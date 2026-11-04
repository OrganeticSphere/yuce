//! `sbgk audit-serve`: the audit layer (contract v0.1) as an MCP server for the swarm, the graph builder and the owner.
//!
//! One durable `AuditState` (the journal is required), the `Dispatcher` (directives to the swarm) and the `Builder` (cards for
//! the graph builder), behind one mutex. Transports as `sbgk mcp-serve`: stdio, or TCP with `--listen` (loopback unless
//! `--allow-remote`), `--max-message-bytes`, `--max-connections`.
//!
//! Contract v0.1 R8, rights on the server: every request is authenticated by a subject token from `--subjects` (in the
//! `initialize` params for the connection, or `_meta.auth_token` / `arguments.auth_token` per call); a request without a valid
//! token gets JSON-RPC error -32001, whatever its method. The subject is a role and an id: the id is the agent's identity in
//! the store (an `agent_id` from the client is never read), and the role decides the tools (`tools/list` shows only those; any
//! other tool gets -32003):
//!
//! - swarm: `audit_acquire` (long poll with `max_wait_ms`), `audit_submit`, `audit_renew`, `audit_release`. Answers keep only
//!   the directive and the repair hint (status, error code, field, message, expected form), not counters of the run.
//! - builder (at most one subject; the store actor is `builder`): `audit_next_card`, `audit_submit_ops`.
//! - owner: `audit_status`, `audit_links`, `audit_link_status`, `audit_concept_status`, `audit_record`, `audit_revoke`,
//!   `audit_terminal_receipt`, `audit_close`, and the
//!   `shutdown` method.
//!
//! `COMPLETE` (and the builder's `IDLE`) means nothing is left to do now: the owner may still withdraw a source and reopen work,
//! so an agent asks again later. `DONE` means the owner closed the run (`audit_close`, only once it is terminal): nothing more
//! is assigned or accepted, and the agent stops. Reads stay open to the owner, and an exact retry of a submission committed
//! before the close is still answered from the acknowledgement cache (its old `COMMITTED`, nothing new is written). The close
//! is held in memory, like the acknowledgements: a restarted server is open again, and the owner closes it again.
//!
//! Start: a non-empty `--wal` is resumed (dispatcher and builder recover from its checkpoints); otherwise a new run is created
//! from `--manifest`, `--repo`, `--select` (one repository path per line) and `--run-id`. `--questions` (the research
//! questions, JSON) is needed in both cases: a changed question set reopens the questions (`question_set_revision`).
//! The section size is bound by an ordinary coordinator checkpoint; an incompatible resume is refused.
//! Successful swarm submissions replay their original ACK across reconnects for the same subject, task and lines while this
//! server process is alive. This response cache is not recovered after a server restart; the underlying effects remain durable.

use super::mcp::{self, LineServer};
use super::{fail, Args};
use sbgk_core::audit::builder::{Builder, BuilderConfig, LINK_RELATIONS};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion, TaskKind};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::{session_root_of, AuditState};
use sbgk_core::audit::{AuditStore, ConceptId, LinkId, LinkStatus, RecordId};
use sbgk_core::hash::{from_hex, sha256, to_hex, Hash};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const PROTOCOL: &str = "2025-06-18";
const UNAUTHORIZED: i64 = -32001;
const FORBIDDEN: i64 = -32003;
/// Longest `max_wait_ms` an `audit_acquire` can ask for.
const MAX_WAIT_CAP_MS: u64 = 30_000;
/// Shortest subject token (a guessable token is no authentication).
const MIN_TOKEN_BYTES: usize = 16;
const COVERAGE_CHECKPOINT: &str = "audit:mcp:coverage";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Swarm,
    Builder,
    Owner,
}

impl Role {
    fn parse(s: &str) -> Option<Role> {
        match s {
            "swarm" => Some(Role::Swarm),
            "builder" => Some(Role::Builder),
            "owner" => Some(Role::Owner),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Role::Swarm => "swarm",
            Role::Builder => "builder",
            Role::Owner => "owner",
        }
    }

    fn tools(self) -> &'static [&'static str] {
        match self {
            Role::Swarm => &["audit_acquire", "audit_submit", "audit_renew", "audit_release"],
            Role::Builder => &["audit_next_card", "audit_submit_ops", "audit_builder_failure"],
            Role::Owner => &[
                "audit_status",
                "audit_links",
                "audit_link_status",
                "audit_concept_status",
                "audit_record",
                "audit_revoke",
                "audit_terminal_receipt",
                "audit_close",
            ],
        }
    }

    fn instructions(self) -> &'static str {
        match self {
            Role::Swarm => {
                "R2R audit swarm agent: call audit_acquire, do exactly what the directive's prompt says, send its JSON lines with audit_submit. \
                 On REPAIR_REQUIRED send only the lines after the accepted ones. On WAIT call audit_acquire again; on COMPLETE call it \
                 again later (the owner may still reopen work); on DONE stop."
            }
            Role::Builder => {
                "R2R graph builder: call audit_next_card, answer the card with operations via audit_submit_ops. On REPAIR_REQUIRED send only \
                 the operations after the committed ones. On IDLE call audit_next_card again later; on DONE stop."
            }
            Role::Owner => {
                "R2R audit owner: the run's status, its links, decisions on links and concepts, the terminal receipt, and audit_close \
                 to end a terminal run (the agents are then told DONE)."
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Subject {
    token: String,
    role: Role,
    id: String,
    /// The kinds of task a swarm agent is given (`None`: any): a link checker next to a single strong reader.
    kinds: Option<Vec<TaskKind>>,
}

/// The subjects file: `{"subjects": [{"token": "...", "role": "swarm|builder|owner", "id": "w1"}, ...]}`. Tokens are unique and at
/// least 16 bytes; ids are unique ASCII identifiers (they are store actors), never `builder` for a swarm agent or the owner, and
/// there is at most one builder. A swarm agent may name the only `kinds` of task it is given (`["VERIFY_LINK", ...]`).
fn parse_subjects(v: &Value) -> Result<Vec<Subject>, String> {
    let list = v.get("subjects").and_then(|x| x.as_array()).ok_or("the subjects file needs a 'subjects' array")?;
    let mut out: Vec<Subject> = Vec::new();
    for s in list {
        let field = |k: &str| s.get(k).and_then(|x| x.as_str()).ok_or(format!("every subject needs a string '{k}'"));
        let (token, id) = (field("token")?, field("id")?);
        let role = Role::parse(field("role")?).ok_or("role is one of swarm, builder, owner")?;
        if token.len() < MIN_TOKEN_BYTES || token.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("the token of '{id}' needs at least {MIN_TOKEN_BYTES} bytes without spaces or control characters"));
        }
        if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(format!("subject id '{id}' must be 1..64 ASCII letters, digits, '_' or '-'"));
        }
        if role != Role::Builder && id == "builder" {
            return Err("'builder' is the graph builder's store actor: give the subject another id".into());
        }
        if out.iter().any(|o| o.id == id) {
            return Err(format!("subject id '{id}' is given twice"));
        }
        if out.iter().any(|o| mcp::same_secret(&o.token, token)) {
            return Err(format!("the token of '{id}' is already another subject's"));
        }
        if role == Role::Builder && out.iter().any(|o| o.role == Role::Builder) {
            return Err("there is one graph builder".into());
        }
        let kinds = match s.get("kinds") {
            None => None,
            Some(Value::Array(a)) if role == Role::Swarm && !a.is_empty() => Some(
                a.iter()
                    .map(|k| k.as_str().and_then(TaskKind::parse).ok_or(format!("subject '{id}': unknown task kind {k}")))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(_) => return Err(format!("subject '{id}': 'kinds' is a non-empty array of task kinds, for a swarm agent")),
        };
        out.push(Subject { token: token.to_string(), role, id: id.to_string(), kinds });
    }
    if out.is_empty() {
        return Err("no subjects: nobody could call the server".into());
    }
    Ok(out)
}

/// The stances a claim may state (records.rs): a question's stance selector names one of them.
const STANCES: [&str; 7] = ["reported", "confirmed", "refuted", "qualified", "superseded", "open", "unknown"];

fn parse_questions(v: &Value) -> Result<Vec<ResearchQuestion>, String> {
    let list = v.as_array().ok_or("the questions file is a JSON array of {id, text, about, stances?, relations?, concept_types?}")?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for q in list {
        let id = q.get("id").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).ok_or("every question needs an 'id'")?;
        let text = q.get("text").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).ok_or(format!("question {id} needs a 'text'"))?;
        // an absent list is empty; a present one is an array of non-empty strings, else the question is refused (Codex review
        // d7d9a49, D11: a wrong type silently dropped a selector and changed the task)
        let list_of = |k: &str| -> Result<Vec<String>, String> {
            match q.get(k) {
                None => Ok(Vec::new()),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|x| {
                        x.as_str().filter(|s| !s.trim().is_empty()).map(str::to_string).ok_or(format!("question {id}: '{k}' holds a non-string or empty entry"))
                    })
                    .collect(),
                Some(_) => Err(format!("question {id}: '{k}' must be an array of strings")),
            }
        };
        let about = list_of("about")?;
        if about.is_empty() || !seen.insert(id.to_string()) {
            return Err(format!("question {id}: a unique id and at least one 'about' term"));
        }
        let (stances, relations) = (list_of("stances")?, list_of("relations")?);
        if let Some(x) = stances.iter().find(|x| !STANCES.contains(&x.as_str())) {
            return Err(format!("question {id}: unknown stance '{x}' (one of {STANCES:?})"));
        }
        if let Some(x) = relations.iter().find(|x| !LINK_RELATIONS.contains(&x.as_str()) && x.as_str() != "duplicate_of") {
            return Err(format!("question {id}: unknown relation '{x}' (one of {LINK_RELATIONS:?} or duplicate_of)"));
        }
        out.push(ResearchQuestion { id: id.into(), text: text.into(), about, stances, relations, concept_types: list_of("concept_types")? });
    }
    if out.is_empty() {
        return Err("no research questions".into());
    }
    Ok(out)
}

/// Reading zones (run S1.2): a JSON array of zones, each a non-empty array of report paths of the run (as --select names them);
/// a report belongs to at most one zone. The zones as the run's document ids.
fn parse_zones(v: &Value, state: &AuditState) -> Result<Vec<Vec<String>>, String> {
    let list = v.as_array().filter(|l| !l.is_empty()).ok_or("the zones file is a non-empty JSON array of arrays of report paths")?;
    let by_path: BTreeMap<String, String> =
        state.docs().into_iter().filter_map(|d| state.source_document(&d).and_then(|s| s["path"].as_str().map(|p| (p.to_string(), d.clone())))).collect();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (n, zone) in list.iter().enumerate() {
        let paths = zone.as_array().filter(|z| !z.is_empty()).ok_or(format!("zone {n} is not a non-empty array of report paths"))?;
        let mut docs = Vec::new();
        for p in paths {
            let p = p.as_str().ok_or(format!("zone {n}: a report path is a string"))?;
            let d = by_path.get(p).ok_or(format!("zone {n}: {p} is not a report of this run"))?;
            if !seen.insert(d.clone()) {
                return Err(format!("zone {n}: {p} is in another zone already"));
            }
            docs.push(d.clone());
        }
        out.push(docs);
    }
    Ok(out)
}

struct SubmitAck {
    subject: String,
    lines_hash: sbgk_core::hash::Hash,
    answer: Value,
}

struct Run {
    state: AuditState,
    dispatch: Dispatcher,
    builder: Builder,
    pool: Option<sbgk_core::audit::builder::parallel::ParallelBuilder>,
    build_backlog: Option<usize>,
    /// `full`, `concepts` (links off), `none` (no graph builder): the owner's control runs of 2026-10-30, or `hints` (as `none`,
    /// with the RELATE turn of a reading task, 2026-10-31). Without a builder the kernel gives no builder work, and the builder is
    /// caught up by definition: there is none to wait for.
    build_scope: &'static str,
    /// Connection retries only: no credentials are cached, and a server restart does not recover these responses.
    acknowledgements: BTreeMap<String, SubmitAck>,
    /// Backpressure liveness: lifts the gate while the builder stands still.
    guard: StallGuard,
    /// The owner closed the terminal run: the agents are told `DONE` and nothing more is accepted. Memory only, like the
    /// acknowledgements: a restarted server is open again.
    closed: bool,
}

/// Backpressure liveness (run 10A-17): when the graph builder's cursor has not moved for the stall time while records wait, the
/// gate lifts, so a stuck builder cannot freeze the reading until the phase deadline; it re-engages as soon as the cursor moves.
/// Wall clock and memory only, like the leases it paces (neither is journaled). Every lift and re-engagement is counted and kept
/// (time, backlog, how long the cursor stood still), so a run shows whether pacing held.
struct StallGuard {
    cursor: u64,
    moved: Instant,
    stall: Duration,
    open: bool,
    lifts: u64,
    reengages: u64,
    events: Vec<Value>,
}

/// Lift and re-engagement events kept for STATUS (the counters go on).
const STALL_EVENTS: usize = 200;

impl StallGuard {
    fn new(stall: Duration, now: Instant) -> StallGuard {
        StallGuard { cursor: 0, moved: now, stall, open: false, lifts: 0, reengages: 0, events: Vec::new() }
    }

    /// The backlog to pace by, or `None` while the guard is open.
    fn backlog(&mut self, cursor: u64, backlog: usize, now: Instant, t_ms: u64) -> Option<usize> {
        if cursor != self.cursor {
            self.cursor = cursor;
            self.moved = now;
        }
        let still = now.duration_since(self.moved);
        let lift = backlog > 0 && still >= self.stall;
        if lift != self.open {
            self.open = lift;
            if lift {
                self.lifts += 1;
            } else {
                self.reengages += 1;
            }
            if self.events.len() < STALL_EVENTS {
                self.events.push(json!({"t_ms": t_ms, "event": if lift { "lift" } else { "reengage" }, "backlog": backlog,
                                        "still_ms": still.as_millis() as u64}));
            }
        }
        (!lift).then_some(backlog)
    }

    fn to_json(&self) -> Value {
        json!({"open": self.open, "lifts": self.lifts, "reengages": self.reengages, "stall_ms": self.stall.as_millis() as u64,
               "events": self.events})
    }
}

struct AuditServer {
    run: Mutex<Run>,
    /// Signalled after every call that can free or create work (long polling of `audit_acquire`).
    changed: Condvar,
    subjects: Vec<Subject>,
    max_message_bytes: usize,
    started: Instant,
}

fn bad_arg(msg: impl Into<String>) -> Value {
    json!({"status": "error", "code": "BAD_ARGUMENT", "message": msg.into()})
}

fn hex_arg<T>(args: &Value, k: &str, wrap: fn(sbgk_core::hash::Hash) -> T) -> Result<T, Value> {
    args.get(k)
        .and_then(|x| x.as_str())
        .map(|s| s.trim_start_matches('@'))
        .and_then(from_hex)
        .map(wrap)
        .ok_or_else(|| bad_arg(format!("'{k}' is a full 64-hex id")))
}

/// What a swarm agent sees of an answer (contract v0.1 R8): the directive and the repair hint, not the run's counters. The hint
/// is the kernel's error as it writes it (`expected_by_kernel`, `obligation`) and the problems of the lines not taken (Codex's
/// review of 8716bf2, F1: the filter kept a key the kernel never writes, so no expected value and no problems reached an agent).
fn for_swarm(out: Value) -> Value {
    // repair_scope says whether any line of the attempt was stored (Codex's e2464d8): the dispatcher wrote it, this filter dropped it,
    // so every live reply of 10A-14 reached the runner without it
    // refused, excluded and extended: what item-wise acceptance stored and left out (the consilium of 10A-17, Gemini's plan step 1)
    const KEEP: [&str; 40] = [
        "unresolved",
        "failures",
        "durable",
        "status",
        "card",
        "card_id",
        "results",
        "committed_ops",
        "proposed_concepts",
        "cursor",
        "replayed",
        "circle",
        "circle_phase",
        "ring_batch",
        "sync_step",
        "link_authors",
        "response_deadline_fixed",
        "repair_scope",
        "code",
        "message",
        "task_id",
        "kind",
        "key",
        "local_id_prefix",
        "expires_at_ms",
        "max_lines",
        "prompt",
        "accepted",
        "failed_index",
        "repair",
        "verdict",
        "waited_ms",
        "accepted_locals",
        "problems",
        "not_stored",
        "refused",
        "excluded",
        "extended",
        "referenced",
        "retained_answer_ids",
    ];
    let mut v = Map::new();
    for k in KEEP {
        if let Some(x) = out.get(k).filter(|x| !x.is_null()) {
            v.insert(k.into(), x.clone());
        }
    }
    if let Some(e) = out.get("error").and_then(|e| e.as_object()) {
        let hint: Map<String, Value> =
            ["code", "field", "message", "expected_by_kernel", "obligation"].iter().filter_map(|k| e.get(*k).map(|x| (k.to_string(), x.clone()))).collect();
        v.insert("error".into(), Value::Object(hint));
    }
    Value::Object(v)
}

fn summary_line(v: &Value) -> String {
    let fields = ["status", "code", "task_id", "kind", "key", "card_id", "message"];
    fields
        .iter()
        .filter_map(|k| match &v[*k] {
            Value::Null => None,
            Value::String(s) => Some(format!("{k}={s}")),
            other => Some(format!("{k}={other}")),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn tool_defs() -> Vec<Value> {
    let s = |d: &str| json!({"type": "string", "description": d});
    let compact = json!({"type": "boolean", "description": "text content is a one-line summary (the full answer stays in structuredContent)"});
    let schema = |props: Value, req: &[&str]| json!({"type": "object", "properties": props, "required": req});
    let t = |name: &str, desc: &str, input: Value| json!({"name": name, "description": desc, "inputSchema": input});
    vec![
        t(
            "audit_acquire",
            "Lease the most urgent free work: DIRECTIVE (task_id, prompt, local_id_prefix), WAIT or COMPLETE.",
            schema(
                json!({"max_wait_ms": {"type": "integer", "minimum": 0, "description": "long poll: wait up to this long (cap 30000) instead of answering WAIT"},
                        "compact": compact}),
                &[],
            ),
        ),
        t(
            "audit_submit",
            "Submit the JSON lines of a directive: COMMITTED, REPAIR_REQUIRED (send only the lines after the accepted ones) or STALE_TASK.",
            schema(
                json!({"task_id": s("task id from audit_acquire"), "lines": {"type": "array", "items": {"type": "object"}}, "compact": compact}),
                &["task_id", "lines"],
            ),
        ),
        t("audit_renew", "Heartbeat: renew a legacy lease; circle response deadlines stay fixed.", schema(json!({"task_id": s("task id")}), &["task_id"])),
        t(
            "audit_release",
            "Give a lease back unfinished; in circles, report an actual model timeout.",
            schema(json!({"task_id": s("task id"),"timed_out":{"type":"boolean"}}), &["task_id"]),
        ),
        t(
            "audit_builder_failure",
            "Report a failed attempt of the authenticated standalone builder; enabled only with --agent-attempts.",
            schema(
                json!({"card_id":s("issued card"),"attempt_id":s("unique physical call id"),"reason":s("failure category")}),
                &["card_id", "attempt_id", "reason"],
            ),
        ),
        t("audit_next_card", "The open card again, or the next one cut from new records; IDLE when the builder has caught up.", schema(json!({}), &[])),
        t(
            "audit_submit_ops",
            "Operations for a card: CARD_DONE, or REPAIR_REQUIRED (send only the operations after the committed ones).",
            schema(json!({"card_id": s("card id"), "ops": {"type": "array", "items": {"type": "object"}}}), &["card_id", "ops"]),
        ),
        t(
            "audit_status",
            "Counters and roots; ontology=true also exports opt-in lifecycle history (owner only).",
            schema(json!({"ontology":{"type":"boolean"},"telemetry":{"type":"boolean"}}), &[]),
        ),
        t(
            "audit_links",
            "Links of the graph with full ids, optionally of one status.",
            schema(json!({"status": {"type": "string", "enum": ["proposed", "accepted", "rejected"]}}), &[]),
        ),
        t(
            "audit_link_status",
            "The owner's decision on a link, resting on records (full ids).",
            schema(
                json!({"link": s("full link id"), "status": {"type": "string", "enum": ["accepted", "rejected"]},
                        "basis": {"type": "array", "items": {"type": "string"}, "description": "full record ids"}}),
                &["link", "status", "basis"],
            ),
        ),
        t(
            "audit_concept_status",
            "The owner's decision on a concept.",
            schema(json!({"concept": s("full concept id"), "status": {"type": "string", "enum": ["accepted", "retired"]}}), &["concept", "status"]),
        ),
        t("audit_record", "One record with its basis and grounding (full or short @id).", schema(json!({"record": s("record id")}), &["record"])),
        t(
            "audit_revoke",
            "Withdraw an observation (its source no longer holds): the answers resting on it are reopened.",
            schema(json!({"record": s("full id of an observe record")}), &["record"]),
        ),
        t("audit_terminal_receipt", "The terminal receipt when the run is complete (contract v0.1 R7), else NOT_COMPLETE.", schema(json!({}), &[])),
        t(
            "audit_close",
            "End a terminal run: the agents are told DONE and nothing more is accepted; reads stay open. NOT_COMPLETE closes nothing.",
            schema(json!({}), &[]),
        ),
    ]
}

impl AuditServer {
    fn lock(&self) -> MutexGuard<'_, Run> {
        self.run.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// The subject a token belongs to (every token is compared, in time independent of the match).
    fn subject_of(&self, token: &str) -> Option<usize> {
        self.subjects.iter().enumerate().fold(None, |found, (i, s)| if mcp::same_secret(&s.token, token) { Some(i) } else { found })
    }

    /// `audit_acquire`, long-polling up to `max_wait_ms` while the answer is `WAIT` (re-checked at least once a second, so an
    /// expiring lease is noticed). A close while it waits answers `DONE`.
    fn acquire<'a>(&'a self, mut g: MutexGuard<'a, Run>, who: &Subject, args: &Value) -> (MutexGuard<'a, Run>, Value) {
        let max_wait = args.get("max_wait_ms").and_then(|x| x.as_u64()).unwrap_or(0).min(MAX_WAIT_CAP_MS);
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_millis(max_wait);
        loop {
            let r = &mut *g;
            if r.closed {
                return (g, json!({"status": "DONE"}));
            }
            if let Err(error) = r.prepare(self.now(), unix_ms()) {
                return (g, json!({"status":"error","code":"CIRCLE_PREPARE_FAILED","error":error}));
            }
            let caught_up = r.caught_up();
            let backlog = r.paced_backlog(Instant::now(), self.now());
            let was_started = r.dispatch.ring_started();
            let mut out = r.dispatch.acquire_for(&r.state, &who.id, caught_up, backlog, who.kinds.as_deref(), self.now());
            // The wrapper also flushes pending expiry/recovery closures on WAIT, and drops any unpublished task on failure.
            let task = out["task_id"].as_str().unwrap_or("");
            if let Err(e) = r.dispatch.persist_change_lease(&mut r.state, task) {
                return (g, json!({"status":"error","code":"CHANGE_LEASE_NOT_DURABLE","error":e.to_json()}));
            }
            if !was_started && r.dispatch.ring_started() {
                self.changed.notify_all();
            }
            let now = Instant::now();
            if out["status"] != "WAIT" || now >= deadline {
                if max_wait > 0 {
                    out["waited_ms"] = json!(now.duration_since(t0).as_millis() as u64);
                }
                return (g, out);
            }
            g = self.changed.wait_timeout(g, (deadline - now).min(Duration::from_secs(1))).unwrap_or_else(|p| p.into_inner()).0;
        }
    }

    fn call(&self, who: &Subject, name: &str, args: &Value) -> Value {
        let mut g = self.lock();
        let now = self.now();
        let task = || args.get("task_id").and_then(|x| x.as_str()).ok_or_else(|| bad_arg("missing 'task_id'"));
        // Check exact successful retries before the dispatcher consults its ephemeral lease. A cache hit changes neither
        // the journal nor the dispatch counters and does not wake long polls. Tool rights were checked before this call.
        if name == "audit_submit" {
            if let (Ok(task), Some(lines)) = (task(), args.get("lines").and_then(Value::as_array)) {
                if let Some(ack) = g.acknowledgements.get(task) {
                    let answer = if ack.subject != who.id {
                        json!({"status": "error", "code": "TASK_NOT_OWNED", "task_id": task})
                    } else if ack.lines_hash != sha256(sbgk_core::jcs::to_jcs(&json!(lines)).as_bytes()) {
                        json!({"status": "error", "code": "SUBMISSION_MISMATCH", "task_id": task,
                               "message": "this task was committed with different lines; only the exact request can replay its acknowledgement"})
                    } else {
                        ack.answer.clone()
                    };
                    return for_swarm(answer);
                }
            }
        }
        // a closed run assigns and accepts nothing more; the owner still reads it
        if g.closed && !matches!(name, "audit_status" | "audit_links" | "audit_record" | "audit_terminal_receipt" | "audit_close") {
            let out = match name {
                "audit_acquire" | "audit_next_card" => json!({"status": "DONE"}),
                _ => json!({"status": "error", "code": "RUN_CLOSED", "message": "the owner closed the run: nothing more is accepted"}),
            };
            return if who.role == Role::Swarm { for_swarm(out) } else { out };
        }
        let mut out = match name {
            "audit_acquire" => {
                let (back, out) = self.acquire(g, who, args);
                g = back;
                out
            }
            "audit_submit" => match (task(), args.get("lines").and_then(|x| x.as_array())) {
                (Ok(t), Some(lines)) => {
                    let r = &mut *g;
                    let out = if r.build_backlog.is_some() && r.dispatch.is_build(t) {
                        if let Some(pool) = &mut r.pool {
                            let card = r.dispatch.build_card_id(t).unwrap_or("").to_string();
                            match pool.worker_mut(&card) {
                                Some(worker) => r.dispatch.submit_build(&mut r.state, worker, t, &who.id, lines, now),
                                None => json!({"status":"STALE_TASK","task_id":t}),
                            }
                        } else {
                            r.dispatch.submit_build(&mut r.state, &mut r.builder, t, &who.id, lines, now)
                        }
                    } else {
                        r.dispatch.submit(&mut r.state, t, &who.id, lines, now)
                    };
                    if out["status"] == "COMMITTED" || out["status"] == "CARD_DONE" {
                        r.acknowledgements.insert(
                            t.to_string(),
                            SubmitAck { subject: who.id.clone(), lines_hash: sha256(sbgk_core::jcs::to_jcs(&json!(lines)).as_bytes()), answer: out.clone() },
                        );
                    }
                    out
                }
                (Err(e), _) => e,
                (_, None) => bad_arg("'lines' is an array of JSON records"),
            },
            "audit_renew" => task().map(|t| g.dispatch.renew(t, &who.id, now)).unwrap_or_else(|e| e),
            "audit_release" => match task() {
                Ok(t) => {
                    let r = &mut *g;
                    match args.get("timed_out") {
                        Some(Value::Bool(true)) => {
                            let card = r.dispatch.build_card_for_task(t, &who.id);
                            let out = r.dispatch.timeout_task(&mut r.state, t, &who.id);
                            if out["status"] == "RELEASED" && r.dispatch.cfg.agent_attempts.is_some() {
                                if let Some(card) = card {
                                    let builder = r.pool.as_mut().and_then(|p| p.worker_mut(&card)).unwrap_or(&mut r.builder);
                                    let reply = builder.agent_failure(&mut r.state, &card, t, &who.id, "MODEL_AGENT_FAILURE");
                                    if reply["status"] == "error" {
                                        return reply;
                                    }
                                }
                            }
                            out
                        }
                        Some(Value::Bool(false)) | None => r.dispatch.release_durable(&mut r.state, t, &who.id),
                        Some(_) => bad_arg("'timed_out' must be a boolean"),
                    }
                }
                Err(e) => e,
            },
            "audit_builder_failure" => {
                let r = &mut *g;
                r.reopen_refiner_card();
                match (args["card_id"].as_str(), args["attempt_id"].as_str(), args["reason"].as_str()) {
                    (Some(card), Some(attempt), Some(reason)) => r.builder.agent_failure(&mut r.state, card, attempt, &who.id, reason),
                    _ => bad_arg("card_id, attempt_id and reason strings required"),
                }
            }
            "audit_next_card" if g.dispatch.cfg.circle_refiner.is_some() => {
                let r = &mut *g;
                if r.dispatch.cfg.circle_refiner.as_deref() != Some(who.id.as_str()) {
                    return json!({"status":"error","code":"NOT_THE_REFINER"});
                }
                if let Err(error) = r.prepare(now, unix_ms()) {
                    return json!({"status":"error","code":"CIRCLE_PREPARE_FAILED","error":error});
                }
                // after the last budget gb still finishes the card it was given (a retry after a timeout or a restart too): the run
                // waits for it
                let issued = r.refiner_issued();
                let finishing = issued.is_some() && r.dispatch.circle_status().is_some_and(|c| c["circle_phase"] == "FINAL");
                if !r.dispatch.circle_is_refining() && !finishing {
                    return json!({"status":"WAIT","circle":r.dispatch.circle_status()});
                }
                let card = match issued {
                    Some((_, to)) if r.builder.open_card_id().is_none() => r.builder.next_card_up_to(&r.state, to),
                    _ => r.builder.next_card(&r.state),
                };
                match card {
                    Some(card) => {
                        if let Err(error) = r.record_refiner_issue(&card) {
                            return json!({"status":"error","code":"REFINER_ISSUE_REFUSED","error":error});
                        }
                        let mut out = card.to_json();
                        out["existing"] = sbgk_core::audit::refine::overlay(&r.state, &card);
                        out["prompt"] = json!(format!("{}{}", sbgk_core::audit::refine::PROMPT, out["prompt"].as_str().unwrap_or("")));
                        if r.dispatch.cfg.agent_attempts.is_some() {
                            out["agent_attempt"] = json!(
                                sbgk_core::audit::agent_failures::entry(&r.state, &format!("build:{}", card.card_id))["failures"].as_u64().unwrap_or(0) + 1
                            );
                        }
                        out = r.dispatch.circle_tag(out);
                        out
                    }
                    None => json!({"status": "IDLE", "cursor": r.builder.cursor(), "caught_up": r.dispatch.refiner_caught_up}),
                }
            }
            "audit_next_card" => {
                let r = &mut *g;
                r.builder.prepare_pairs(&r.state, r.dispatch.reading_done(&r.state));
                match r.builder.next_card(&r.state) {
                    Some(card) => {
                        if let Err(e) = sbgk_core::audit::quality::evolution::issued(&mut r.state, &card) {
                            return json!({"status":"error","code":"EVOLUTION_ISSUE_REFUSED","error":e});
                        }
                        let mut out = card.to_json();
                        if r.dispatch.cfg.agent_attempts.is_some() {
                            out["agent_attempt"] = json!(
                                sbgk_core::audit::agent_failures::entry(&r.state, &format!("build:{}", card.card_id))["failures"].as_u64().unwrap_or(0) + 1
                            );
                        }
                        // the graph builder's typed requests, when the run has them (U1): the board and the forms
                        if let Some(board) = r.dispatch.request_board(&r.state, &card) {
                            out["prompt"] = json!(format!("{}{}", out["prompt"].as_str().unwrap_or(""), Dispatcher::request_rules(&board)));
                            out["requests"] = board;
                        }
                        out
                    }
                    None => json!({"status": "IDLE", "cursor": r.builder.cursor(), "caught_up": r.builder.caught_up(&r.state)}),
                }
            }
            "audit_submit_ops" => match (args.get("card_id").and_then(|x| x.as_str()), args.get("ops").and_then(|x| x.as_array())) {
                (Some(card), Some(ops)) => {
                    let r = &mut *g;
                    r.reopen_refiner_card();
                    {
                        let executor = r.state.ontology_revision_state().is_some().then_some(who.id.as_str());
                        r.dispatch.submit_builder_ops(&mut r.state, &mut r.builder, card, ops, executor)
                    }
                }
                _ => bad_arg("'card_id' and an array 'ops' are required"),
            },
            "audit_status" => {
                let r = &mut *g;
                let telemetry = args.get("telemetry").and_then(Value::as_bool) == Some(true);
                if telemetry { /* snapshot only: no dispatch or phase transition */
                } else if r.pool.is_none() {
                    r.builder.prepare_pairs(&r.state, r.dispatch.reading_done(&r.state));
                } else if let Err(error) = r.prepare(now, unix_ms()) {
                    return json!({"status":"error","code":"CIRCLE_PREPARE_FAILED","error":error});
                }
                if !telemetry {
                    if let Err(e) = r.attest_end() {
                        return json!({"status":"error","code":"ATTESTATION_REFUSED","error":e});
                    }
                }
                let mut out = status(r);
                if r.closed {
                    out["closed"] = json!(true);
                }
                let quality = r.state.graph_quality_metrics();
                if !quality.is_null() {
                    out["graph_quality"] = quality;
                }
                if telemetry {
                    out["circle_telemetry"] = r.state.circle_telemetry();
                }
                if args.get("ontology").and_then(Value::as_bool) == Some(true) {
                    out["ontology_revision"] = r.state.ontology_evolution_snapshot().unwrap_or(Value::Null);
                }
                out
            }
            "audit_links" => {
                let want = args.get("status").and_then(|x| x.as_str());
                let links: Vec<Value> = g
                    .state
                    .links()
                    .iter()
                    .filter(|l| want.is_none_or(|w| l.status.name() == w))
                    .map(|l| {
                        json!({"id": to_hex(&l.id.0), "short": l.id.short(), "from": to_hex(&l.from.0), "rel": l.rel, "to": to_hex(&l.to.0),
                               "status": l.status.name(), "by": l.by})
                    })
                    .collect();
                json!({"status": "LINKS", "links": links})
            }
            "audit_link_status" => link_decision(&mut g.state, &who.id, args),
            "audit_concept_status" => match (hex_arg(args, "concept", ConceptId), args.get("status").and_then(|x| x.as_str())) {
                (Ok(c), Some(st)) => match g.state.set_concept_status(&who.id, &c, st) {
                    Ok(()) => json!({"status": "DECIDED", "concept": c.short(), "concept_status": st}),
                    Err(e) => json!({"status": "error", "code": "REFUSED", "error": e.to_json()}),
                },
                (Err(e), _) => e,
                (_, None) => bad_arg("missing 'status'"),
            },
            "audit_record" => match record_arg(&g.state, args) {
                Ok(r) => record_json(&g.state, &r),
                Err(e) => e,
            },
            "audit_revoke" => match record_arg(&g.state, args) {
                Ok(r) => match g.state.revoke_observation(&who.id, &r) {
                    Ok(()) => json!({"status": "REVOKED", "record": r.short()}),
                    Err(e) => json!({"status": "error", "code": "REFUSED", "error": e.to_json()}),
                },
                Err(e) => e,
            },
            "audit_terminal_receipt" | "audit_close" => {
                let r = &mut *g;
                if r.pool.is_none() {
                    r.builder.prepare_pairs(&r.state, r.dispatch.reading_done(&r.state));
                } else if let Err(error) = r.prepare(now, unix_ms()) {
                    return json!({"status":"error","code":"CIRCLE_PREPARE_FAILED","error":error});
                }
                if let Err(e) = r.attest_end() {
                    return json!({"status":"error","code":"ATTESTATION_REFUSED","error":e});
                }
                let receipt = terminal(r);
                // only a terminal run is closed; NOT_COMPLETE closes nothing
                if name == "audit_close" && receipt["status"] == "TERMINAL" {
                    r.closed = true;
                    // the agents are told DONE without the dispatcher: their waits end here (Codex review 987431f3, WAIT-01)
                    r.dispatch.stats.end_waits(now);
                    json!({"status": "CLOSED", "audit_root": receipt["audit_root"], "wal_head": receipt["wal_head"]})
                } else {
                    receipt
                }
            }
            other => json!({"status": "error", "code": "UNKNOWN_TOOL", "message": format!("unknown tool '{other}'")}),
        };
        // a key given up when a failed lease expired (inside a dispatcher call without the store) is written now (Codex review
        // d7d9a49, D06: otherwise a restart issued it again)
        {
            let r = &mut *g;
            if let Err(e) = r.dispatch.persist_version_closures(&mut r.state) {
                out = json!({"status":"error","code":"CHANGE_CLOSURE_NOT_DURABLE","error":e.to_json(),"prior_reply":out});
            }
            for e in r.dispatch.persist_unresolved(&mut r.state) {
                if r.dispatch.cfg.agent_attempts.is_some() {
                    out = json!({"status":"error","code":"AGENT_FAILURE_CHECKPOINT_REFUSED","error":e,"prior_reply":out});
                    continue;
                }
                eprintln!("{}", json!({"status": "warning", "message": "an unresolved key could not be written yet", "error": e}));
            }
            if let Err(error) = r.dispatch.persist_members(&mut r.state) {
                out = json!({"status":"error","code":"RING_CHECKPOINT_REFUSED","error":error,"prior_reply":out});
            }
        }
        // calls that can free or create work wake the long polls
        if !matches!(name, "audit_acquire" | "audit_status" | "audit_links" | "audit_record" | "audit_terminal_receipt" | "audit_next_card") {
            self.changed.notify_all();
        }
        drop(g);
        if who.role == Role::Swarm {
            for_swarm(out)
        } else {
            out
        }
    }
}

/// `record`: a full 64-hex id or a short `@id` of exactly one record.
fn record_arg(state: &AuditState, args: &Value) -> Result<RecordId, Value> {
    let name = args.get("record").and_then(|x| x.as_str()).ok_or_else(|| bad_arg("missing 'record'"))?;
    if let Some(h) = from_hex(name.trim_start_matches('@')) {
        return Ok(RecordId(h));
    }
    let found: Vec<RecordId> = state.records_since(0).iter().filter(|r| r.id.short() == name).map(|r| r.id).collect();
    match found[..] {
        [id] => Ok(id),
        _ => Err(bad_arg(format!("'{name}' names no single record"))),
    }
}

fn record_json(state: &AuditState, id: &RecordId) -> Value {
    match state.record(id) {
        Some(r) => {
            let mut out = json!({"status": "RECORD", "id": to_hex(&r.id.0), "short": r.id.short(), "kind": r.kind.name(), "author": r.author,
                          "directive": r.directive, "doc_id": r.doc_id, "quote": r.quote, "text": r.text, "terms": r.terms, "stance": r.status,
                          "ends": r.ends.as_ref().map(|(f, rel, t)| json!([to_hex(&f.0), rel, to_hex(&t.0)])), "body": r.body,
                          "based_on": r.based_on.iter().map(|b| to_hex(&b.0)).collect::<Vec<_>>(), "grounded": state.is_grounded(id)});
            let annotation = sbgk_core::audit::quality::annotate(state, *id);
            if !annotation.is_null() {
                out["temporal_status"] = annotation;
            }
            let warnings = sbgk_core::audit::quality::stale::answer_warnings(state, *id);
            // a claim an answer may list, a summary's own or a reader's (ANS-01): what the reader of the answer is told about its
            // time (registry R34a)
            let status = sbgk_core::audit::quality::stale::answer_status(state, *id, !warnings.is_empty());
            if !status.is_null() {
                out["answer_status"] = status;
            }
            if !warnings.is_empty() {
                out["temporal_warnings"] = json!(warnings);
            }
            out
        }
        None => json!({"status": "error", "code": "UNKNOWN_RECORD", "message": "no such record"}),
    }
}

fn link_decision(state: &mut AuditState, by: &str, args: &Value) -> Value {
    let link = match hex_arg(args, "link", LinkId) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let status = match args.get("status").and_then(|x| x.as_str()) {
        Some("accepted") => LinkStatus::Accepted,
        Some("rejected") => LinkStatus::Rejected,
        _ => return bad_arg("'status' is accepted or rejected"),
    };
    let basis: Option<Vec<RecordId>> = args
        .get("basis")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().map(|x| x.as_str().map(|s| s.trim_start_matches('@')).and_then(from_hex).map(RecordId)).collect())
        .and_then(|v: Vec<Option<RecordId>>| v.into_iter().collect());
    let Some(basis) = basis.filter(|b| !b.is_empty()) else { return bad_arg("'basis' is a non-empty array of full record ids") };
    match state.set_link_status(&link, status, by, &basis) {
        Ok(()) => json!({"status": "DECIDED", "link": link.short(), "link_status": status.name()}),
        Err(e) => json!({"status": "error", "code": "REFUSED", "error": e.to_json()}),
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// The card gb was last given (circles +1): its id and range, so the wait for it survives a restart.
const REFINER_ISSUED: &str = "builder:refiner:issued";

impl Run {
    fn cursor(&self) -> u64 {
        if no_builder(self.build_scope) {
            return self.state.head();
        }
        self.pool.as_ref().map_or_else(|| self.builder.cursor(), |p| p.cursor(&self.state))
    }
    /// With circles +1, a card gb was given in REFINE may still be out when the budget moves the circle on: until it comes back
    /// or is left unresolved, the work is not caught up, so neither attested nor terminal (Codex review R02: TERMINAL, then gb's
    /// late card changed the root). The circles themselves move on the pool alone.
    fn caught_up(&self) -> bool {
        if no_builder(self.build_scope) {
            return true;
        }
        match &self.pool {
            None => self.builder.caught_up(&self.state),
            Some(p) => p.caught_up(&self.state) && (self.dispatch.cfg.circle_refiner.is_none() || self.refiner_issued().is_none()),
        }
    }
    /// The range of the card gb was given while its answer has not moved gb's cursor past it. Durable, unlike the open card: a
    /// restart forgot the card and let the run end without it (Codex's check of aeb38ba).
    fn refiner_issued(&self) -> Option<(u64, u64)> {
        if let Some(range) = self.builder.open_range() {
            return Some(range);
        }
        let c = self.state.checkpoint(REFINER_ISSUED)?;
        let (from, to) = (c["context"]["from"].as_u64()?, c["context"]["to"].as_u64()?);
        (self.builder.cursor() <= from).then_some((from, to))
    }
    /// After a restart gb may answer the card it was given without asking for it again: it is cut again first, so the answer
    /// finds it (Gemini's reading of b4edffe).
    fn reopen_refiner_card(&mut self) {
        if self.dispatch.cfg.circle_refiner.is_some() && self.builder.open_card_id().is_none() {
            if let Some((_, to)) = self.refiner_issued() {
                let _ = self.builder.next_card_up_to(&self.state, to);
            }
        }
    }
    fn record_refiner_issue(&mut self, card: &sbgk_core::audit::builder::Card) -> Result<(), Value> {
        if self.state.checkpoint(REFINER_ISSUED).is_some_and(|c| c["context"]["card_id"] == card.card_id.as_str()) {
            return Ok(());
        }
        let ck = json!({"key":REFINER_ISSUED,"from":0,"to":0,"context":{"card_id":card.card_id,"from":card.cursor_from,"to":card.cursor_to}});
        match self.state.submit_operations_id(&format!("refiner-issue:{}", card.card_id), "kernel", &[], Some(ck)) {
            Ok(v) if v["checkpointed"] == true && v["error"].is_null() => Ok(()),
            Ok(v) => Err(v),
            Err(e) => Err(e.to_json()),
        }
    }
    fn backlog(&self) -> usize {
        if no_builder(self.build_scope) {
            return 0;
        }
        self.pool.as_ref().map_or_else(|| self.builder.backlog(&self.state), |p| p.backlog(&self.state))
    }
    fn builder_stats(&self) -> sbgk_core::audit::builder::BuilderStats {
        self.pool.as_ref().map_or_else(|| self.builder.stats.clone(), |p| p.stats())
    }
    fn attest_end(&mut self) -> Result<(), Value> {
        if self.state.checkpoint("audit:mcp:coverage").is_some_and(|c| c["context"]["unattested_at_end"] == true) {
            if let Some(coverage) = self.dispatch.attestation_coverage(&self.state, self.caught_up()) {
                self.state.attest_at_end(coverage).map_err(|e| e.to_json())?;
            }
        }
        Ok(())
    }
    fn prepare(&mut self, now: u64, wall: u64) -> Result<(), Value> {
        self.dispatch.persist_version_closures(&mut self.state).map_err(|e| e.to_json())?;
        if self.dispatch.cfg.agent_attempts.is_some() {
            let errors = self.dispatch.persist_unresolved(&mut self.state);
            if !errors.is_empty() {
                return Err(json!({"code":"AGENT_FAILURE_CHECKPOINT_REFUSED","errors":errors}));
            }
        }
        if self.pool.is_none() {
            self.builder.persist_unresolved_cursor(&mut self.state)?;
        }
        if let Some(pool) = &mut self.pool {
            if self.dispatch.cfg.circle_refiner.is_some() {
                self.builder.persist_unresolved_cursor(&mut self.state)?;
                self.dispatch.refiner_caught_up = self.builder.open_card_id().is_none() && self.builder.cursor() >= self.state.head();
            }
            // no graph builder: the circles keep their reading waves, and a BUILD phase has no cards to wait for
            let caught = no_builder(self.build_scope) || pool.caught_up(&self.state);
            self.dispatch.advance_circles(&mut self.state, caught, now, wall)?;
            let cards = if no_builder(self.build_scope)
                || self.dispatch.circle_is_reading()
                || self.dispatch.circle_is_refining()
                || (pool.open_count(&self.state) == 0 && self.dispatch.ring_readers_busy())
            {
                vec![]
            } else {
                let number = self.dispatch.circle_status().and_then(|v| v["circle"].as_u64()).unwrap_or(1);
                let done = self.dispatch.reading_done(&self.state);
                let phase = self.dispatch.circle_status().and_then(|v| v["circle_phase"].as_str().map(str::to_string)).unwrap_or_else(|| "BUILD".into());
                pool.offers_in_phase(&mut self.state, number, &phase, done)?
            };
            let coverage = self.state.checkpoint("audit:mcp:coverage").unwrap_or(Value::Null);
            let readers = coverage["context"]["circle_readers"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>())
                .unwrap_or_default();
            let circle = self.dispatch.circle_status().and_then(|v| v["circle"].as_u64()).unwrap_or(1);
            for card in &cards {
                sbgk_core::audit::quality::evolution::issued(&mut self.state, card)?;
            }
            self.dispatch.set_ring_order(sbgk_core::audit::quality::ring(&self.state, &readers, circle));
            self.dispatch.offer_ring_builds(pool.batch(), cards);
            self.dispatch.prepare_ring(&mut self.state, now, wall)?;
        } else if !no_builder(self.build_scope) {
            self.builder.prepare_pairs(&self.state, self.dispatch.reading_done(&self.state));
            if let Some(threshold) = self.build_backlog {
                self.dispatch.prepare_build(&self.state, &mut self.builder, threshold);
            }
        }
        self.attest_end()?;
        Ok(())
    }
    /// The builder's backlog for backpressure, or `None` when it is off or the builder stalled: its cursor has not moved for the
    /// stall time while records wait (a stuck builder must not freeze the reading until the phase deadline).
    fn paced_backlog(&mut self, now: Instant, t_ms: u64) -> Option<usize> {
        if self.dispatch.cfg.backpressure_records == 0 {
            return None;
        }
        let (cursor, backlog) = (self.cursor(), self.backlog());
        self.guard.backlog(cursor, backlog, now, t_ms)
    }
}

fn status(r: &Run) -> Value {
    let caught_up = r.caught_up();
    let (proposed, accepted, rejected) = r.state.links().iter().fold((0, 0, 0), |(p, a, x), l| match l.status {
        LinkStatus::Proposed => (p + 1, a, x),
        LinkStatus::Accepted => (p, a + 1, x),
        LinkStatus::Rejected => (p, a, x + 1),
    });
    let d = &r.dispatch.stats;
    let b = r.builder_stats();
    let mut out = json!({"status": "STATUS", "run_id": r.state.run_id(), "records": r.state.head(), "builder_cursor": r.cursor(),
           "builder_caught_up": caught_up, "reading_done": r.dispatch.reading_done(&r.state), "leases": r.dispatch.leases(), "completion": r.dispatch.completion(&r.state, caught_up),
           "dispatch": {"issued": d.issued, "committed": d.committed, "repairs": d.repairs, "expired": d.expired, "confirmed": d.confirmed,
                        "rejected": d.rejected, "waits": d.waits, "requests_accepted": d.requests_accepted, "requests_refused": d.requests_refused,
                        "paced_skips": d.paced_skips, "relate_turns": d.relate_turns, "extend_leases": r.dispatch.extend_leases(),
                        "wait_ms": d.wait_ms},
           "builder_backlog": r.backlog(), "stall_guard": r.guard.to_json(),
           "builder": {"cards": b.cards, "ops_accepted": b.ops_accepted, "ops_refused": b.ops_refused, "concepts_proposed": b.concepts_proposed,
                       "links_proposed": b.links_proposed, "duplicates": b.duplicates, "concepts_reused": b.concepts_reused},
           "links": {"proposed": proposed, "accepted": accepted, "rejected": rejected},
           "audit_ontology_revision": r.state.ontology_version().0, "question_set_revision": r.dispatch.question_set_revision(),
           "audit_root": to_hex(&r.state.audit_root()), "engine_root": to_hex(&r.state.engine_root()),
           "wal_head": r.state.wal_head().map(|h| to_hex(&h)), "transaction_sequence": r.state.transaction_sequence()});
    if r.dispatch.cfg.agent_attempts.is_some() {
        out["agent_failures"] = sbgk_core::audit::agent_failures::state(&r.state);
    }
    if r.build_scope != "full" {
        out["build_scope"] = json!(r.build_scope);
    }
    if let Some(pool) = &r.pool {
        out["circles"] = r.dispatch.circle_status().unwrap_or(Value::Null);
        out["open_builder_cards"] = json!(pool.open_count(&r.state));
        if r.dispatch.cfg.circle_refiner.is_some() {
            out["refiner"] = json!({"cursor": r.builder.cursor(), "open_card": r.builder.open_card_id(), "issued": r.refiner_issued()});
        }
    }
    out
}

/// The terminal receipt with what only the store knows (contract v0.1 R7).
fn terminal(r: &Run) -> Value {
    match r.dispatch.terminal_receipt(&r.state, r.cursor(), r.state.run_id()).filter(|_| r.pool.is_none() || r.caught_up()) {
        Some(mut t) => {
            t["status"] = json!("TERMINAL");
            if r.dispatch.cfg.agent_attempts.is_some() {
                t["agent_failures"] = sbgk_core::audit::agent_failures::state(&r.state);
            }
            t["corpus_manifest_hash"] = json!(to_hex(&r.state.manifest_hash()));
            t["run_namespace"] = json!(to_hex(&r.state.run_namespace()));
            t["engine_root"] = json!(to_hex(&r.state.engine_root()));
            t["session_root"] = json!(to_hex(&r.state.session_root()));
            t["wal_head"] = json!(r.state.wal_head().map(|h| to_hex(&h)));
            if r.build_scope != "full" {
                // a control run's receipt says so: `builder_caught_up` of `none` means there was no builder
                t["build_scope"] = json!(r.build_scope);
            }
            t
        }
        // what is already answered and still holds, so a run stopped before its end keeps its answers (marked partial)
        None => json!({"status": "NOT_COMPLETE", "completion": r.dispatch.completion(&r.state, r.caught_up()),
                       "accepted_outcomes": r.dispatch.accepted_outcomes(&r.state)}),
    }
}

impl LineServer for AuditServer {
    /// The subject a valid `auth_token` in `initialize` authenticated the connection as.
    type Conn = Option<usize>;

    fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    fn connection_admitted(&self, conn: &Self::Conn, line: &str) -> bool {
        conn.is_some()
            || mcp::request(line)
                .ok()
                .flatten()
                .is_some_and(|(_, _, params)| mcp::presented_token(&params).is_some_and(|token| self.subject_of(token).is_some()))
    }

    fn handle(&self, conn: &mut Option<usize>, line: &str) -> (Option<Value>, bool) {
        let (id, method, params) = match mcp::request(line) {
            Ok(Some(r)) => r,
            Ok(None) => return (None, false),
            Err(answer) => return (Some(answer), false),
        };
        let fail = |code: i64, message: String| (Some(mcp::rpc_error(&id, code, message)), false);
        let ok = |result: Value| (Some(mcp::rpc_ok(&id, result)), false);
        // rights on the server (R8): every method, initialize included, needs a subject
        let subject = match mcp::presented_token(&params) {
            Some(t) => match self.subject_of(t) {
                Some(i) => {
                    if method == "initialize" {
                        *conn = Some(i);
                    }
                    i
                }
                None => return fail(UNAUTHORIZED, "Unauthorized: unknown auth_token".into()),
            },
            None => match *conn {
                Some(i) => i,
                None => return fail(UNAUTHORIZED, "Unauthorized: present a subject's auth_token (in initialize params, _meta or tool arguments)".into()),
            },
        };
        let who = &self.subjects[subject];
        match method.as_str() {
            "initialize" => {
                let pv = params.get("protocolVersion").and_then(|x| x.as_str()).unwrap_or(PROTOCOL);
                ok(json!({"protocolVersion": pv, "capabilities": {"tools": {"listChanged": false}},
                          "serverInfo": {"name": "sbgk-audit", "version": env!("CARGO_PKG_VERSION")},
                          "instructions": who.role.instructions(), "subject": {"role": who.role.name(), "id": who.id}}))
            }
            "ping" => ok(json!({})),
            "tools/list" => {
                let retry_enabled = self.run.lock().unwrap_or_else(|e| e.into_inner()).dispatch.cfg.agent_attempts.is_some();
                ok(
                    json!({"tools": tool_defs().into_iter().filter(|t| who.role.tools().iter().any(|n| t["name"] == *n) && (t["name"]!="audit_builder_failure" || retry_enabled)).collect::<Vec<_>>()}),
                )
            }
            "tools/call" => {
                let Some(name) = params.get("name").and_then(|x| x.as_str()) else { return fail(-32602, "tools/call needs 'name'".into()) };
                if !who.role.tools().contains(&name) {
                    return if tool_defs().iter().any(|t| t["name"] == name) {
                        fail(FORBIDDEN, format!("Forbidden: the {} role cannot call {name}", who.role.name()))
                    } else {
                        fail(-32602, format!("unknown tool '{name}'"))
                    };
                }
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let out = self.call(who, name, &args);
                ok(mcp::tool_result(&args, out, summary_line))
            }
            "shutdown" if who.role == Role::Owner => {
                self.changed.notify_all();
                (Some(mcp::rpc_ok(&id, json!({}))), true)
            }
            "shutdown" => fail(FORBIDDEN, "Forbidden: only the owner can shut the server down".into()),
            other => fail(-32601, format!("method not found: {other}")),
        }
    }
}

fn read_json(path: &str, what: &str) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read {what} {path}: {e}")));
    serde_json::from_str(&text).unwrap_or_else(|e| fail(&format!("{what} {path} is not JSON: {e}")))
}

/// A new durable run from the corpus manifest and the selected report paths.
fn create_run(a: &Args, wal: &Path) -> AuditState {
    let manifest = a.req("manifest");
    let repo = a.req("repo");
    let select = std::fs::read_to_string(a.req("select")).unwrap_or_else(|e| fail(&format!("cannot read --select: {e}")));
    let selected: Vec<(String, Vec<u8>)> = select
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|p| (p.to_string(), std::fs::read(Path::new(&repo).join(p)).unwrap_or_else(|e| fail(&format!("cannot read report {p}: {e}")))))
        .collect();
    if selected.is_empty() {
        fail("--select lists no report paths");
    }
    let bytes = std::fs::read(&manifest).unwrap_or_else(|e| fail(&format!("cannot read --manifest {manifest}: {e}")));
    // a base ontology from a file seeds the run's concepts; without it the built-in schema. The genesis keeps either.
    let mut base = a.get("base-ontology").map(|p| read_json(p, "--base-ontology")).unwrap_or_else(AuditOntology::base);
    if a.get("base-ontology").is_some() {
        base["seed_status"] = json!("provisional");
    }
    if a.sw("ontology-revisions") {
        base["revision_policy"] = json!({"rule":"next_nonproposer/1","unmapped_circles":a.num("ontology-unmapped-circles",3usize),
            "catchall_mappings":a.num("ontology-catchall-mappings",8usize),"catchall_reports":a.num("ontology-catchall-reports",2usize)});
    }
    AuditState::create_from_manifest(wal, &base, &a.req("run-id"), &bytes, &selected)
        .unwrap_or_else(|e| fail(&format!("cannot create the run: {}", e.to_json())))
}

/// Bind the section-cut configuration with the existing coordinator checkpoint API. Historical task keys contain only
/// section indices, so a progressed legacy journal without this binding cannot establish compatible coverage safely. Zones and
/// own references are bound with it when given (a `zone:<n>` key means those documents), and only then: the binding of a run
/// without them is the one it always was.
fn graph_quality_args(a: &Args) -> Value {
    let mut q = json!({});
    for k in ["term-hygiene", "ring-rotate", "link-both-sides", "stale-suspect", "evolution-cards", "temporal-summary"] {
        if a.sw(k) {
            q[k.replace('-', "_")] = json!(true);
        }
    }
    if a.sw("term-hygiene") || a.get("term-max-words").is_some() {
        let n = a.num("term-max-words", 4usize);
        if n == 0 || n > 256 {
            fail("--term-max-words must be 1..256");
        }
        q["term_max_words"] = json!(n);
        q["language_pack_sha256"] = json!(to_hex(&sha256(sbgk_core::jcs::to_jcs(&sbgk_core::audit::quality::language_data()).as_bytes())));
    }
    for (k, allowed) in [
        ("candidate-match", vec!["legacy", "strict"]),
        ("jev-mode", vec!["footer", "already-mapped", "inline-flag"]),
        ("known-concepts", vec!["off", "circles", "all"]),
    ] {
        if let Some(v) = a.get(k) {
            if !allowed.contains(&v) {
                fail(&format!("invalid --{k}"));
            }
            q[k.replace('-', "_")] = json!(v);
        }
    }
    if let Some(p) = a.get("evolution-document-order") {
        if !a.sw("evolution-cards") {
            fail("--evolution-document-order requires --evolution-cards");
        }
        let v = read_json(p, "--evolution-document-order");
        if v.as_array().is_none_or(|xs| {
            xs.len() < 2
                || xs.iter().any(|x| x.as_str().is_none_or(|s| s.is_empty()))
                || xs.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() != xs.len()
        }) {
            fail("--evolution-document-order needs a unique array of at least two document ids");
        }
        q["evolution_document_order"] = v;
    }
    if a.sw("evolution-cards") {
        for (k, default) in [("evolution-pairs-per-concept", 16usize), ("evolution-pairs-per-card", 4usize)] {
            let n = a.num(k, default);
            if n == 0 || n > 64 {
                fail(&format!("--{k} must be 1..64"));
            }
            q[k.replace('-', "_")] = json!(n);
        }
    }
    // the strongest graph (31.10): evolution pairs from the claims' own words; dropped here until its pre-flight found it
    if let Some(v) = a.get("evolution-pairing") {
        if !a.sw("evolution-cards") {
            fail("--evolution-pairing requires --evolution-cards");
        }
        if !["concepts", "lexical"].contains(&v) {
            fail("--evolution-pairing must be concepts or lexical");
        }
        q["evolution_pairing"] = json!(v);
    }
    // a summary claim with the later state it is most like by words (31.10): the time component of the temporal summary
    if a.sw("summary-companions") {
        if !a.sw("temporal-summary") {
            fail("--summary-companions requires --temporal-summary");
        }
        q["summary_companions"] = json!(true);
    }
    // the address layer (owner and Gemini, 01.11.2026): a new concept may name its broad function, and lexical evolution pairs also
    // join a claim with the records of change of its function (claims that state a change, or of declared change summaries)
    if a.sw("concept-functions") {
        q["concept_functions"] = json!(true);
        let n = a.num("evolution-pairs-per-function", 3usize);
        if n == 0 || n > 16 {
            fail("--evolution-pairs-per-function must be 1..16");
        }
        q["evolution_pairs_per_function"] = json!(n);
    } else if a.get("evolution-pairs-per-function").is_some() {
        fail("--evolution-pairs-per-function requires --concept-functions");
    }
    if let Some(p) = a.get("change-summary-documents") {
        if !a.sw("concept-functions") || a.get("evolution-pairing") != Some("lexical") {
            fail("--change-summary-documents requires --concept-functions and --evolution-pairing lexical");
        }
        let v = read_json(p, "--change-summary-documents");
        if v.as_array().is_none_or(|xs| xs.is_empty() || xs.iter().any(|x| x.as_str().is_none_or(|s| s.is_empty()))) {
            fail("--change-summary-documents needs a nonempty array of document ids or labels");
        }
        q["change_summary_documents"] = v;
    }
    if q.as_object().expect("object").is_empty() {
        Value::Null
    } else {
        q
    }
}

struct CoverageMode {
    graph_quality: Value,
    circle_refiner: Option<String>,
    resumed: bool,
    agent_attempts: Option<u32>,
    unattested_at_end: bool,
    ontology_review: bool,
    answer_timeout_ms: Option<u64>,
    build_scope: &'static str,
}
fn bind_coverage(
    state: &mut AuditState,
    section_bytes: usize,
    zones: &[Vec<String>],
    own_refs: bool,
    build_backlog: Option<usize>,
    circles: Option<&sbgk_core::audit::directives::circles::CircleConfig>,
    mode: CoverageMode,
) -> Result<(), String> {
    let CoverageMode { resumed, ontology_review, answer_timeout_ms, agent_attempts, unattested_at_end, graph_quality, circle_refiner, build_scope } = mode;
    let mut context = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": section_bytes});
    // durable: a control run's WAL says what was left out, and it cannot be resumed as another kind of run
    if build_scope != "full" {
        context["build_scope"] = json!(build_scope);
    }
    if let Some(n) = agent_attempts {
        context["agent_attempts"] = json!(n);
    }
    if !graph_quality.is_null() {
        context["graph_quality"] = graph_quality;
    }
    if unattested_at_end {
        context["unattested_at_end"] = json!(true);
    }
    if ontology_review {
        context["ontology_review"] = json!(true);
    }
    if let Some(ms) = answer_timeout_ms {
        context["answer_timeout_ms"] = json!(ms);
    }
    if !zones.is_empty() {
        context["zones"] = json!(zones);
    }
    if own_refs {
        context["own_refs"] = json!(true);
    }
    if let Some(n) = build_backlog {
        context["dynamic_roles"] = json!(true);
        context["build_backlog"] = json!(n);
    }
    if let Some(cfg) = circles {
        context["circles"] = json!(true);
        context["wave_sections"] = json!(cfg.wave_sections);
        context["circle_readers"] = json!(cfg.readers);
        context["agent_timeout_ms"] = json!(cfg.agent_timeout_ms);
    }
    if let Some(id) = circle_refiner {
        context["circle_refiner"] = json!(id);
    }
    if let Some(checkpoint) = state.checkpoint(COVERAGE_CHECKPOINT) {
        return if checkpoint["context"] == context {
            Ok(())
        } else {
            // name what differs: a run started with another --profile differs in its switches, not only in --section-bytes
            let stored = checkpoint["context"].as_object().cloned().unwrap_or_default();
            let given = context.as_object().cloned().unwrap_or_default();
            let mut keys: Vec<&String> = stored.keys().chain(given.keys()).filter(|k| stored.get(*k) != given.get(*k)).collect();
            keys.sort();
            keys.dedup();
            Err(format!(
                "cannot resume with --section-bytes {section_bytes}: the stored configuration differs in {keys:?}; start it again with the                  --profile and flags the run was created with"
            ))
        };
    }
    if resumed && state.transaction_sequence().unwrap_or(0) != 0 {
        return Err("cannot resume --section-bytes safely: this progressed WAL has no audit-serve section configuration; start a new WAL".into());
    }
    let checkpoint = json!({"key": COVERAGE_CHECKPOINT, "from": 0, "to": 0, "context": context});
    match state.submit_operations_id("audit-mcp-coverage-config", "kernel", &[], Some(checkpoint)) {
        Ok(result) if result["checkpointed"] == true && result["error"].is_null() => Ok(()),
        Ok(result) => Err(format!("cannot bind audit-serve section configuration: {result}")),
        Err(error) => Err(format!("cannot bind audit-serve section configuration: {}", error.to_json())),
    }
}

/// The measured v0.1 default (the owner, 2026-11-03: "download, run, get what was measured"): no graph builder, reading in circles
/// with dynamic roles, stale suspects and the temporal summary with its companions. An explicit `--build-scope` still applies.
/// `--profile custom` takes every flag as given, the behaviour before v0.1 (the benchmark runner and the tests pass it).
const V01_SWITCHES: [&str; 5] = ["dynamic-roles", "circles", "stale-suspect", "temporal-summary", "summary-companions"];

fn with_profile(a: &Args) -> Args {
    let mut a = a.clone();
    match a.get("profile").unwrap_or("v0.1") {
        "custom" => {}
        "v0.1" => {
            for k in V01_SWITCHES {
                a.sw.insert(k.to_string());
            }
            a.kv.entry("build-scope".to_string()).or_insert_with(|| "none".to_string());
        }
        other => fail(&format!("--profile must be v0.1 or custom, not '{other}'")),
    }
    a
}

/// `sbgk audit-verify --wal <run.wal> [--expect <receipt.json>]`: replays a recorded audit journal without a model, as a resumed
/// server would (frame hashes, source identities, every entry to its committed outcome and roots), and prints the roots and the
/// chain head it reaches. The kernel reads the file once, bounded and read-only: it is never locked, copied or written. With
/// `--expect`, the receipt's `audit_root` (with its `engine_root`, `session_root` and `wal_head` where it has them; a close stamp
/// has no engine root) must name a state the journal passed through, such as a phase receipt or the final one; a `wal_head`
/// binds the chain up to that state, not only the state. Exit 0 when verified, 1 when the journal is refused, the receipt names
/// no state of it, or (without a receipt) bytes after the last complete entry were left unverified: status TORN_TAIL, the crash or
/// the change that this check cannot tell apart. Exit 2 when the file cannot be read: that says nothing about the journal.
pub fn cmd_audit_verify(a: &Args) {
    let wal = a.req("wal");
    if let Err(e) = std::fs::File::open(&wal).and_then(|mut f| std::io::Read::read(&mut f, &mut [0u8; 1])) {
        fail(&format!("cannot read {wal}: {e}"));
    }
    let expect = a.get("expect").map(|p| {
        let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap_or_else(|e| fail(&format!("cannot read {p}: {e}"))))
            .unwrap_or_else(|e| fail(&format!("{p} is not JSON: {e}")));
        let root = |k: &str| {
            let given = v.get(k).filter(|r| !r.is_null());
            let hash = given.and_then(Value::as_str).and_then(from_hex);
            if given.is_some() && hash.is_none() {
                fail(&format!("{p}: {k} must be 64 hex digits"));
            }
            hash
        };
        let audit = root("audit_root").unwrap_or_else(|| fail(&format!("{p} needs an audit_root")));
        (audit, root("engine_root"), root("session_root"), root("wal_head"))
    });
    let mut states: Vec<(usize, Hash, Hash, Hash)> = Vec::new();
    let (state, read) = match AuditState::verify(Path::new(&wal), &mut |n, audit, engine, head| states.push((n, audit, engine, head))) {
        Ok(verified) => verified,
        Err(e) => {
            println!("{}", json!({"status": "REFUSED", "wal": wal, "error": e.to_json()}));
            std::process::exit(1);
        }
    };
    let entries = states.last().map_or(0, |s| s.0);
    let mut out = json!({"status": "VERIFIED", "wal": wal, "wal_bytes": read.bytes, "wal_sha256": to_hex(&read.sha256),
                         "torn_tail_bytes": read.bytes - read.complete_bytes, "run_id": state.run_id(),
                         "corpus_manifest_hash": to_hex(&state.manifest_hash()), "entries": entries, "records": state.head(),
                         "audit_root": to_hex(&state.audit_root()), "engine_root": to_hex(&state.engine_root()),
                         "session_root": to_hex(&state.session_root()), "wal_head": to_hex(&read.wal_head)});
    if let Some((audit, engine, session, head)) = expect {
        let found = states.iter().find(|s| s.1 == audit && engine.is_none_or(|e| s.2 == e) && head.is_none_or(|h| s.3 == h));
        let at = found.map(|s| s.0);
        let session_ok = found.is_some_and(|s| session.is_none_or(|x| x == session_root_of(&s.2, &audit)));
        out["expected"] = json!({"audit_root": to_hex(&audit), "engine_root": engine.map(|e| to_hex(&e)),
                                 "wal_head": head.map(|h| to_hex(&h)), "found_after_entries": at, "at_end": at == Some(entries),
                                 "session_root_matches": session.map(|_| session_ok)});
        if at.is_none() || !session_ok {
            out["status"] = json!("MISMATCH");
            println!("{out}");
            std::process::exit(1);
        }
    } else if read.bytes != read.complete_bytes {
        out["status"] = json!("TORN_TAIL");
        out["note"] = json!("the entries above verify, but the bytes after them are no complete entry: a crash or a change; a receipt tells which");
        println!("{out}");
        std::process::exit(1);
    }
    println!("{out}");
}

pub fn cmd_audit_serve(a: &Args) {
    let profiled_default_scope = a.get("build-scope").is_none();
    let profiled = with_profile(a);
    let a = &profiled;
    let v01 = a.get("profile").unwrap_or("v0.1") == "v0.1";
    // Validate every numeric startup option before creating or opening a durable run.
    let ttl_ms: u64 = a.num("ttl-ms", DispatchConfig::default().ttl_ms);
    let section_bytes: usize = a.num("section-bytes", DispatchConfig::default().section_bytes);
    let max_message_bytes: usize = a.num("max-message-bytes", mcp::DEFAULT_MAX_MESSAGE_BYTES);
    let max_connections: usize = a.num("max-connections", mcp::DEFAULT_MAX_CONNECTIONS);
    if ttl_ms == 0 || ttl_ms > u64::MAX / 2 {
        fail("--ttl-ms must be in 1..=9223372036854775807");
    }
    if section_bytes < 64 {
        fail("--section-bytes must be at least 64");
    }
    if max_message_bytes == 0 || max_message_bytes > isize::MAX as usize {
        fail("--max-message-bytes must be positive and at most isize::MAX");
    }
    if max_connections == 0 {
        fail("--max-connections must be positive");
    }
    // the graph builder's card: a strong model with a fixed cost per call works better on larger cards (Gemini's run-10 plan)
    let bd = BuilderConfig::default();
    let dynamic_roles = a.sw("dynamic-roles");
    let build_backlog: Option<usize> = dynamic_roles.then(|| a.num("build-backlog", 16));
    if build_backlog == Some(0) {
        fail("--build-backlog must be positive");
    }
    // the owner's control runs of 2026-10-30, to see what the graph adds to the answers: `none` runs the swarm and the kernel without
    // the graph builder (no concepts, no term mapping, no links), `concepts` keeps the builder's concepts and term mapping and turns
    // links off; `full` is the ordinary run
    let build_scope: &'static str = match a.get("build-scope").unwrap_or("full") {
        "full" => "full",
        "concepts" => "concepts",
        "none" => "none",
        "hints" => "hints",
        "versions" => "versions",
        other => fail(&format!("--build-scope must be full, concepts, none, hints or versions, not '{other}'")),
    };
    if build_scope != "full" {
        for (flag, set) in [
            ("--evolution-cards", a.sw("evolution-cards")),
            ("--circles-refiner", a.get("circles-refiner").is_some()),
            ("--ontology-review", a.sw("ontology-review")),
            ("--builder-max-links", a.get("builder-max-links").is_some()),
        ] {
            if set {
                fail(&format!("--build-scope {build_scope} has no links to make: {flag} does not go with it"));
            }
        }
    }
    if no_builder(build_scope) {
        for flag in ["builder-max-records", "builder-max-candidates", "builder-max-neighbors", "builder-max-ops", "builder-requests"] {
            if a.get(flag).is_some() {
                fail(&format!("--build-scope {build_scope} has no graph builder: --{flag} does not go with it"));
            }
        }
    }
    let builder_cfg = BuilderConfig {
        max_records: a.num("builder-max-records", bd.max_records),
        max_candidates: a.num("builder-max-candidates", bd.max_candidates),
        max_neighbors: a.num("builder-max-neighbors", bd.max_neighbors),
        max_ops: a.num("builder-max-ops", bd.max_ops),
        max_links: if build_scope == "concepts" { 0 } else { a.num("builder-max-links", bd.max_links) },
        author_runs: dynamic_roles,
    };
    if a.sw("ring-rotate") && !a.sw("circles") {
        fail("--ring-rotate requires --circles");
    }
    if a.sw("evolution-cards") && a.num("evolution-pairs-per-card", 4usize) > builder_cfg.max_links.min(builder_cfg.max_ops) {
        fail("--evolution-pairs-per-card must fit --builder-max-links and --builder-max-ops");
    }
    if builder_cfg.max_records == 0 || builder_cfg.max_ops == 0 || (builder_cfg.max_links == 0 && build_scope != "concepts") {
        fail("--builder-max-records, --builder-max-ops and --builder-max-links must be positive");
    }
    let subjects = parse_subjects(&read_json(&a.req("subjects"), "--subjects")).unwrap_or_else(|e| fail(&format!("--subjects: {e}")));
    if no_builder(build_scope) && subjects.iter().any(|s| s.role == Role::Builder) {
        if v01 && a.get("build-scope") == Some("none") && profiled_default_scope {
            fail("the v0.1 profile has no graph builder: the subjects name a builder; drop it, or pass --profile custom");
        }
        fail(&format!("--build-scope {build_scope} has no graph builder: the subjects name a builder"));
    }
    let circle_mode = a.sw("circles");
    // circles +1 (the owner, 2026-10-27): the swarm's independent graph builder, a fixed role outside the ring, refines every circle
    let refiner = a.get("circles-refiner").map(|id| id.to_string());
    if let Some(id) = &refiner {
        if !circle_mode {
            fail("--circles-refiner requires --circles");
        }
        if !subjects.iter().any(|s| s.role == Role::Builder && &s.id == id) {
            fail("--circles-refiner must name the run's builder subject");
        }
    }
    let refine_budget_ms: Option<u64> = a.get("refine-budget-ms").map(|_| a.num("refine-budget-ms", 300_000u64));
    if refine_budget_ms.is_some() && refiner.is_none() {
        fail("--refine-budget-ms requires --circles-refiner");
    }
    if refine_budget_ms == Some(0) {
        fail("--refine-budget-ms must be positive");
    }
    if dynamic_roles && subjects.iter().any(|s| s.role == Role::Builder && refiner.as_deref() != Some(s.id.as_str())) {
        fail("--dynamic-roles has no dedicated builder subject");
    }
    if circle_mode && !dynamic_roles {
        fail("--circles requires --dynamic-roles");
    }
    if !circle_mode && (a.get("wave-sections").is_some() || a.get("agent-timeout-ms").is_some()) {
        fail("--wave-sections requires --circles");
    }
    let circle_readers = subjects
        .iter()
        .filter(|who| who.role == Role::Swarm && who.kinds.as_ref().is_none_or(|ks| ks.contains(&TaskKind::Extend)))
        .map(|who| who.id.clone())
        .collect::<Vec<_>>();
    let circles = if circle_mode {
        let wave_sections = a.num("wave-sections", circle_readers.len());
        if v01 && circle_readers.len() < 3 {
            fail("the v0.1 profile reads in circles and needs at least three EXTEND readers: pass --profile custom for a smaller team");
        }
        if wave_sections == 0 || circle_readers.len() < 3 {
            fail("--circles needs a positive wave and at least three EXTEND readers");
        }
        let agent_timeout_ms = a.num("agent-timeout-ms", 300_000u64);
        if agent_timeout_ms == 0 {
            fail("--agent-timeout-ms must be positive");
        }
        if subjects.iter().any(|who| circle_readers.contains(&who.id) && who.kinds.as_ref().is_some_and(|ks| !ks.contains(&TaskKind::Build))) {
            fail("each circle reader must also allow BUILD");
        }
        Some(sbgk_core::audit::directives::circles::CircleConfig { wave_sections, readers: circle_readers, agent_timeout_ms })
    } else {
        None
    };
    let questions = parse_questions(&read_json(&a.req("questions"), "--questions")).unwrap_or_else(|e| fail(&format!("--questions: {e}")));
    if let Some(addr) = a.get("listen") {
        // every request carries a subject token, so a remote listener only needs the operator's opt-in
        mcp::check_listen(addr, a.sw("allow-remote"), true, "--allow-remote");
    }
    // before the run exists: a port that is taken must not leave a journal the same command then refuses to create again
    let listener = a.get("listen").map(mcp::bind);
    let wal = a.req("wal");
    let resume = std::fs::metadata(&wal).map(|m| m.len() > 0).unwrap_or(false);
    let mut state = if resume {
        if a.get("manifest").is_some() {
            fail(&format!("{wal} already holds a run: resume it without --manifest, or start a new run with another --wal"));
        }
        if a.get("base-ontology").is_some() {
            fail(&format!("{wal} already holds a run whose genesis fixed its base ontology: resume it without --base-ontology"));
        }
        AuditState::open(Path::new(&wal)).unwrap_or_else(|e| fail(&format!("cannot resume {wal}: {}", e.to_json())))
    } else {
        create_run(a, Path::new(&wal))
    };
    if build_scope == "versions" {
        let lineage = a
            .get("version-lineage")
            .map(|p| read_json(p, "--version-lineage"))
            .or_else(|| state.checkpoint(sbgk_core::audit::versions::KEY).map(|c| c["context"]["lineage"].clone()))
            .unwrap_or_else(|| json!({"lineages":[]}));
        state.enable_versions(&lineage).unwrap_or_else(|e| fail(&format!("--version-lineage: {e}")));
    } else if a.get("version-lineage").is_some() || state.checkpoint(sbgk_core::audit::versions::KEY).is_some() {
        fail("a pinned version map requires --build-scope versions");
    }
    if state.ontology_revision_state().is_some() != a.sw("ontology-revisions") {
        fail("--ontology-revisions must match the pinned genesis policy");
    }
    if a.sw("ontology-revisions") && !circle_mode {
        fail("--ontology-revisions needs --circles and its authenticated roster");
    }
    if let Some(snapshot) = state.ontology_revision_state() {
        let requested = json!({"rule":"next_nonproposer/1","unmapped_circles":a.num("ontology-unmapped-circles",3usize),"catchall_mappings":a.num("ontology-catchall-mappings",8usize),"catchall_reports":a.num("ontology-catchall-reports",2usize)});
        if snapshot["policy"] != requested {
            fail("ontology hint thresholds must match the pinned genesis policy");
        }
    }
    let agent_attempts = a.get("agent-attempts").map(|_| a.num("agent-attempts", 3u32));
    if agent_attempts.is_some_and(|n| n == 0 || n > 1000) {
        fail("--agent-attempts must be 1..1000");
    }
    let ontology_review = a.sw("ontology-review");
    if ontology_review && (!circle_mode || !a.sw("ontology-revisions")) {
        fail("--ontology-review requires --circles --ontology-revisions");
    }
    let answer_timeout_ms = a.get("answer-timeout-ms").map(|_| a.num("answer-timeout-ms", 900000u64));
    if answer_timeout_ms == Some(0) {
        fail("--answer-timeout-ms must be positive");
    }
    // reading zones and own references (run S1.2): off unless given
    let zones = a.get("zones").map(|p| parse_zones(&read_json(p, "--zones"), &state).unwrap_or_else(|e| fail(&format!("--zones: {e}")))).unwrap_or_default();
    let own_refs = a.sw("own-refs");
    bind_coverage(
        &mut state,
        section_bytes,
        &zones,
        own_refs,
        build_backlog,
        circles.as_ref(),
        CoverageMode {
            graph_quality: graph_quality_args(a),
            circle_refiner: refiner.clone(),
            resumed: resume,
            ontology_review,
            answer_timeout_ms,
            agent_attempts,
            unattested_at_end: a.sw("unattested-at-end"),
            build_scope,
        },
    )
    .unwrap_or_else(|error| fail(&error));
    // a concept type a question selects must be one of the run's ontology (Codex review d7d9a49, D11)
    let types = state.concept_types();
    for q in &questions {
        if let Some(t) = q.concept_types.iter().find(|t| !types.contains(t)) {
            fail(&format!("--questions: question {}: unknown concept type '{t}' (one of {types:?})", q.id));
        }
    }
    // the graph builder's typed requests (U1): off unless the run gives a positive bound
    let max_requests: usize = a.num("builder-requests", 0);
    let auto_reread_limit: usize = a.num("auto-rereads", 20);
    // backpressure (run 10A-17): first readings wait for the graph builder's backlog; 0 keeps it off
    let backpressure_records: usize = a.num("backpressure-records", 0);
    let backpressure_per_task: usize = a.num("backpressure-per-task", DispatchConfig::default().backpressure_per_task);
    let stall = Duration::from_millis(a.num("backpressure-stall-ms", 120_000));
    // the lines one answer may hold: a strong reader of a whole report writes more than the swarm's 32 (the owner, 2026-10-25)
    let max_lines: usize = a.num("max-lines", DispatchConfig::default().max_lines);
    // the records a summary is shown (run S1.2: 0, the summary cites its agent's own records only, with --own-refs)
    let summary_records: usize = a.num("summary-records", DispatchConfig::default().summary_records);
    let cfg = DispatchConfig {
        ttl_ms,
        answer_timeout_ms,
        agent_attempts,
        section_bytes,
        max_lines,
        summary_records,
        max_requests,
        auto_reread_limit,
        backpressure_records,
        backpressure_per_task,
        zones,
        own_refs,
        circles: circles.clone(),
        circle_refiner: refiner.clone(),
        refine_budget_ms,
        relation_lines: build_scope == "full",
        relate_hints: build_scope == "hints",
        versions: build_scope == "versions",
        ..DispatchConfig::default()
    };
    // the control profiles have no links by any path, a reader's relation record included (Codex review of 8023910, SCOPE-01)
    state.set_links_off(!matches!(build_scope, "full" | "versions"));
    let mut dispatch = Dispatcher::new(cfg, questions);
    let mut builder = Builder::new(builder_cfg);
    builder.records_only = refiner.is_some();
    dispatch.recover(&state);
    builder.recover(&state);
    let mut pool = circles.as_ref().map(|cfg| sbgk_core::audit::builder::parallel::ParallelBuilder::new(builder_cfg, cfg.readers.clone()));
    if let Some(p) = &mut pool {
        p.recover(&state).unwrap_or_else(|e| fail(&format!("cannot recover card pool: {e}")));
    }
    let mut run = Run {
        state,
        dispatch,
        builder,
        pool,
        build_backlog,
        build_scope,
        acknowledgements: BTreeMap::new(),
        guard: StallGuard::new(stall, Instant::now()),
        closed: false,
    };
    if circle_mode {
        run.prepare(0, unix_ms()).unwrap_or_else(|e| fail(&format!("cannot recover circles: {e}")));
    }
    let mut hello = json!({"run_id": run.state.run_id(), "resumed": resume, "records": run.state.head(), "builder_cursor": run.cursor(),
                           "audit_root": to_hex(&run.state.audit_root()), "subjects": subjects.len()});
    // a recovery that cut the journal's end is said out loud: a crash and a changed last entry look the same from here
    if let Some((bytes, kept)) = run.state.dropped_tail() {
        hello["torn_tail_bytes"] = json!(bytes);
        hello["torn_tail_kept_in"] = json!(kept.display().to_string());
        let message = format!(
            "the journal ended in {bytes} bytes that are no complete entry, from a crash or a change; the run resumes before them; check it against a receipt"
        );
        eprintln!("{}", json!({"status": "warning", "message": message, "kept_in": kept.display().to_string()}));
    }
    let server = Arc::new(AuditServer { run: Mutex::new(run), changed: Condvar::new(), subjects, max_message_bytes, started: Instant::now() });
    let note = json!({"status": "ready", "audit": hello});
    mcp::run_bound(server, listener, max_connections, Some(note), json!({"audit": hello}));
}

/// A build scope without the graph builder: `none`, and `hints` (the owner, 2026-10-31: no build phase; a reading task gets one more
/// turn with the claims of other report dates that share its claims' words).
fn no_builder(scope: &str) -> bool {
    matches!(scope, "none" | "hints" | "versions")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_v01_profile_is_the_measured_default_and_custom_keeps_every_flag_as_given() {
        let parse = |v: &[&str]| super::super::parse_args(v.iter().map(|s| s.to_string()).collect());
        // no profile flag: the measured v0.1 setting
        let a = with_profile(&parse(&["--wal", "x"]));
        assert!(V01_SWITCHES.iter().all(|k| a.sw(k)));
        assert_eq!(a.get("build-scope"), Some("none"));
        // an explicit build scope still applies under the profile
        assert_eq!(with_profile(&parse(&["--build-scope", "versions"])).get("build-scope"), Some("versions"));
        // custom: every flag exactly as given, the old defaults (full graph, no circles) when none is given
        let c = with_profile(&parse(&["--profile", "custom"]));
        assert!(V01_SWITCHES.iter().all(|k| !c.sw(k)) && c.get("build-scope").is_none());
        let c = with_profile(&parse(&["--profile", "custom", "--circles", "--dynamic-roles"]));
        assert!(c.sw("circles") && c.sw("dynamic-roles") && !c.sw("stale-suspect"));
    }

    fn subj(token: &str, role: &str, id: &str) -> Value {
        json!({"token": token, "role": role, "id": id})
    }

    #[test]
    fn the_stall_guard_lifts_while_the_builder_stands_still_and_re_engages_when_it_moves() {
        let t0 = Instant::now();
        let mut g = StallGuard::new(Duration::from_secs(120), t0);
        assert_eq!(g.backlog(8, 50, t0, 0), Some(50));
        assert_eq!(g.backlog(8, 50, t0 + Duration::from_secs(119), 119_000), Some(50), "still within the stall time");
        assert_eq!(g.backlog(8, 50, t0 + Duration::from_secs(121), 121_000), None, "a stuck builder lifts the gate");
        assert_eq!(g.backlog(8, 0, t0 + Duration::from_secs(122), 122_000), Some(0), "nothing waits: nothing to lift");
        assert_eq!(g.backlog(8, 60, t0 + Duration::from_secs(130), 130_000), None);
        assert_eq!(g.backlog(16, 60, t0 + Duration::from_secs(131), 131_000), Some(60), "the cursor moved: paced again");
        let v = g.to_json();
        assert_eq!((v["lifts"].as_u64(), v["reengages"].as_u64(), v["open"].as_bool()), (Some(2), Some(2), Some(false)), "{v}");
        assert_eq!(v["events"][0], json!({"t_ms": 121_000, "event": "lift", "backlog": 50, "still_ms": 121_000}));
    }

    #[test]
    fn subjects_need_long_unique_tokens_unique_ids_and_one_builder() {
        let ok = json!({"subjects": [subj("swarm-token-0001xx", "swarm", "w1"), subj("builder-token-0001", "builder", "gb"), subj("owner-token-00001x", "owner", "own")]});
        assert_eq!(parse_subjects(&ok).unwrap().len(), 3);
        let mut checker = subj("swarm-token-0002xx", "swarm", "w2");
        checker["kinds"] = json!(["VERIFY_LINK", "RESOLVE_CONFLICT"]);
        let parsed = parse_subjects(&json!({"subjects": [checker]})).unwrap();
        assert_eq!(parsed[0].kinds, Some(vec![TaskKind::VerifyLink, TaskKind::ResolveConflict]));
        let mut builder_kinds = subj("builder-token-0001", "builder", "gb");
        builder_kinds["kinds"] = json!(["VERIFY_LINK"]);
        let mut unknown = subj("swarm-token-0002xx", "swarm", "w2");
        unknown["kinds"] = json!(["READ"]);
        for bad in [
            json!({"subjects": [builder_kinds]}),
            json!({"subjects": [unknown]}),
            json!({"subjects": [subj("short", "swarm", "w1")]}),
            json!({"subjects": [subj("swarm-token-0001xx", "swarm", "builder")]}),
            json!({"subjects": [subj("swarm-token-0001xx", "swarm", "w1"), subj("swarm-token-0002xx", "swarm", "w1")]}),
            json!({"subjects": [subj("swarm-token-0001xx", "swarm", "w1"), subj("swarm-token-0001xx", "owner", "own")]}),
            json!({"subjects": [subj("builder-token-0001", "builder", "a"), subj("builder-token-0002", "builder", "b")]}),
            json!({"subjects": [subj("swarm-token-0001xx", "admin", "w1")]}),
            json!({"subjects": [subj("swarm-token 0001xx", "swarm", "w1")]}),
            json!({"subjects": []}),
        ] {
            assert!(parse_subjects(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_swarm_answer_keeps_the_directive_and_the_hint_only() {
        let out = json!({"status": "REPAIR_REQUIRED", "task_id": "T1-x", "failed_index": 1, "accepted": ["@a"], "open_work": 9, "leases": 3,
                         "agent_id": "w1", "problems": [{"line": 1, "exact_quote": "q"}],
                         "error": {"code": "BAD_FIELD", "field": "text", "message": "too long", "expected_by_kernel": {"max": 240},
                                   "obligation": {"action": "shorten"}, "detail": "x"}});
        let v = for_swarm(out);
        assert_eq!(
            v["error"],
            json!({"code": "BAD_FIELD", "field": "text", "message": "too long", "expected_by_kernel": {"max": 240}, "obligation": {"action": "shorten"}})
        );
        assert_eq!(v["problems"], json!([{"line": 1, "exact_quote": "q"}]));
        assert!(v.get("open_work").is_none() && v.get("leases").is_none() && v.get("agent_id").is_none());
        assert_eq!((v["status"].as_str(), v["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)));
    }

    #[test]
    fn a_swarm_answer_says_whether_the_attempt_stored_anything() {
        for scope in ["whole_answer", "accepted_prefix"] {
            let v = for_swarm(json!({"status": "REPAIR_REQUIRED", "task_id": "T1-x", "failed_index": 1, "repair_scope": scope}));
            assert_eq!(v["repair_scope"], scope, "live run 10A-14: the filter dropped the dispatcher's marker");
        }
    }
}
