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
//!   `audit_withdraw_text`, `audit_terminal_receipt`, `audit_close`, and the
//!   `shutdown` method.
//!
//! `COMPLETE` (and the builder's `IDLE`) means nothing is left to do now: the owner may still withdraw a source and reopen work,
//! so an agent asks again later. `DONE` means the owner closed the run (`audit_close`, only once it is terminal): nothing more
//! is assigned or accepted, and the agent stops. Reads stay open to the owner, and an exact retry of a submission committed
//! before the close is still answered from the acknowledgement cache (its old `COMMITTED`, nothing new is written). The close
//! is held in memory, like the acknowledgements: a restarted server is open again, and the owner closes it again.
//!
//! Start: a non-empty `--wal` is resumed (dispatcher and builder recover from its checkpoints); otherwise a new run is created
//! from `--manifest`, `--repo`, `--select` (one repository path per line) and `--run-id`, or from the text files of a folder:
//! `--docs` and `--run-id`, with `--select` to name the files instead of walking the folder. `--questions` (the research
//! questions, JSON) is needed in both cases: a changed question set reopens the questions (`question_set_revision`).
//! The section size is bound by an ordinary coordinator checkpoint; an incompatible resume is refused.
//! Successful swarm submissions replay their original ACK across reconnects for the same subject, task and lines while this
//! server process is alive. This response cache is not recovered after a server restart; the underlying effects remain durable.

use super::mcp::{self, LineServer};
use super::{fail, Args};
use sbgk_core::audit::builder::{Builder, BuilderConfig, LINK_RELATIONS};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, GapProfile, ResearchQuestion, TaskKind, UNIT_STATUSES};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::sign::{self, NoteSigner, NoteVerifier};
use sbgk_core::audit::state::{AuditState, GenesisSpec};
use sbgk_core::audit::{proof, read, AuditStore, ConceptId, LinkId, LinkStatus, RecordId};
use sbgk_core::hash::{from_hex, sha256, to_hex, Hash};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const PROTOCOL: &str = "2025-06-18";
/// The reading tools of 0.2 beyond `audit_status` and `audit_record` (SPEC_V02_STEP3): they never write, and stay open after the
/// run is closed.
const READ_TOOLS: [&str; 5] = ["audit_dependents", "audit_active_claims", "audit_diff", "audit_fallen", "audit_coverage"];
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
                "audit_dependents",
                "audit_active_claims",
                "audit_diff",
                "audit_fallen",
                "audit_coverage",
                "audit_revoke",
                "audit_withdraw_text",
                "audit_seal",
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
    /// `full`, `concepts` (links off), `none` (no graph builder): the control runs, or `hints` (as `none`,
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
    /// The signing failures already told to the operator on stderr (Codex review of 904f1cdb, S4-05).
    sign_failures_told: usize,
    /// The questions whose `about` no document of the run holds (the architect, 11.11.2026).
    about_unmatched: Vec<Value>,
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

pub(crate) struct AuditServer {
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
        t(
            "audit_record",
            "One record with its basis and grounding (full or short @id), its row of the status projection, how many records rest on it, and, when it fell, its first causes. A withdrawn record's text is still shown: a withdrawal is not an erasure.",
            schema(json!({"record": s("record id")}), &["record"]),
        ),
        t(
            "audit_dependents",
            "Every record that rests on a record or on the quotes of a document (in a byte range of its current version), directly or through others, by depth.",
            schema(
                json!({"record": s("record id"), "doc_id": s("document id, instead of a record"), "start": {"type": "integer"}, "end": {"type": "integer"},
                        "limit": {"type": "integer"}}),
                &[],
            ),
        ),
        t(
            "audit_active_claims",
            "The claims that stand now; claims of equal text are one row, with the documents of the standing quotes under them.",
            schema(json!({"doc_id": s("only claims with a standing quote of this document"), "limit": {"type": "integer"}}), &[]),
        ),
        t(
            "audit_diff",
            "What changed between two points of the journal (a point = a number of frames, as a seal's log_size): records added, records that fell or rose, texts withdrawn. Replays the journal up to the earlier point.",
            schema(json!({"from": {"type": "integer"}, "to": {"type": "integer", "description": "default: now"}, "limit": {"type": "integer"}}), &["from"]),
        ),
        t(
            "audit_fallen",
            "The report of what fell: each fallen claim, relation or answer with the grounds that fell, the gone quotes (without their text), the quotes that stand (with their text), twins on other sources (without text) and what to reread. With since (the point a withdrawal answered), only what stood then.",
            schema(json!({"since": {"type": "integer"}, "limit": {"type": "integer"}}), &[]),
        ),
        t(
            "audit_coverage",
            "What each structural unit of the documents (a list item, a paragraph, a table row) came to: quoted and by which records, answered empty and by which pack of the gap pass, left by the budget, without an answer, under withdrawn text or not read yet; with the packs and the totals of the gap pass, which are counts of these rows.",
            schema(
                json!({"doc_id": s("only the units of this document"), "unit_status": s("only the units of this status, such as left_by_budget"),
                        "limit": {"type": "integer"}}),
                &[],
            ),
        ),
        t(
            "audit_revoke",
            "Withdraw an observation (its source no longer holds): its text closes in that document, every stored quote overlapping it goes with it, new ones are refused, and the answers resting on them are reopened.",
            schema(json!({"record": s("full id of an observe record")}), &["record"]),
        ),
        t(
            "audit_withdraw_text",
            "Withdraw text of a document, quoted or not, with the effect of audit_revoke.",
            schema(json!({"doc_id": s("document id"), "exact_quote": s("the text, byte for byte")}), &["doc_id", "exact_quote"]),
        ),
        t(
            "audit_seal",
            "Seal the journal now, for example before a withdrawal, so that a quittance can later show what stood at this point: the frames so far, the roots of the state and the hashes of what stands and what rests on what. A server with a signing key signs it. A seal right after another is not written again.",
            schema(json!({}), &[]),
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
            // a wait for a builder that no subject runs would last for ever: the answer says what it waits for
            if out["status"] == "WAIT" && out["builder_caught_up"] == false && !self.subjects.iter().any(|s| s.role == Role::Builder) {
                out["message"] = json!("waiting for the graph builder to catch up; --subjects names no graph builder: if no agent builds the graph, start the run with --build-scope none");
            }
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
        if g.closed
            && !matches!(name, "audit_status" | "audit_links" | "audit_record" | "audit_terminal_receipt" | "audit_close")
            && !READ_TOOLS.contains(&name)
        {
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
                out["projections"] = read::summary(&r.state);
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
            "audit_dependents" => match target_arg(&g.state, args) {
                Ok(target) => read::dependents(&g.state, &target, limit_arg(args)),
                Err(e) => e,
            },
            "audit_active_claims" => read::active_claims(&g.state, args.get("doc_id").and_then(Value::as_str), limit_arg(args)),
            "audit_coverage" => match args.get("unit_status").and_then(Value::as_str) {
                Some(status) if !UNIT_STATUSES.contains(&status) => bad_arg(format!("'unit_status' is one of {}", UNIT_STATUSES.join(", "))),
                status => read::coverage(&g.state, g.state.entries().unwrap_or(0), args.get("doc_id").and_then(Value::as_str), status, limit_arg(args)),
            },
            "audit_diff" => {
                let now = g.state.entries().unwrap_or(0);
                match points_arg(args, now) {
                    Ok((from, to)) => match read::own_points(&mut g.state, &[from, to]) {
                        Ok(at) => match (at.get(&from), at.get(&to)) {
                            (Some(a), Some(b)) => read::diff(a, b, limit_arg(args)),
                            _ => bad_arg(format!("the journal has {now} frames: give points from 1 to {now}")),
                        },
                        Err(e) => json!({"status": "error", "code": "REPLAY_FAILED", "error": e.to_json()}),
                    },
                    Err(e) => e,
                }
            }
            "audit_fallen" => {
                let now = g.state.entries().unwrap_or(0);
                match args.get("since").map(|v| v.as_u64().map(|n| n as usize)) {
                    None => read::fallen(&g.state, now, None, limit_arg(args)),
                    Some(Some(since)) if (1..=now).contains(&since) => match read::own_points(&mut g.state, &[since]) {
                        Ok(at) => read::fallen(&g.state, now, at.get(&since), limit_arg(args)),
                        Err(e) => json!({"status": "error", "code": "REPLAY_FAILED", "error": e.to_json()}),
                    },
                    Some(_) => bad_arg(format!("'since' is a point of the journal: an integer from 1 to {now}")),
                }
            }
            "audit_revoke" => match record_arg(&g.state, args) {
                Ok(r) => {
                    let before = withdrawal_point(&g.state);
                    match g.state.revoke_observation(&who.id, &r) {
                        Ok(also) => withdrawal_answer(&g.state, json!({"status": "REVOKED", "record": r.short(), "also_revoked": also}), before),
                        Err(e) => json!({"status": "error", "code": "REFUSED", "error": e.to_json()}),
                    }
                }
                Err(e) => e,
            },
            "audit_withdraw_text" => match (args.get("doc_id").and_then(|x| x.as_str()), args.get("exact_quote").and_then(|x| x.as_str())) {
                (Some(doc), Some(text)) => {
                    let before = withdrawal_point(&g.state);
                    match g.state.withdraw_text(&who.id, doc, text) {
                        Ok(also) => withdrawal_answer(&g.state, json!({"status": "REVOKED", "doc_id": doc, "also_revoked": also}), before),
                        Err(e) => json!({"status": "error", "code": "REFUSED", "error": e.to_json()}),
                    }
                }
                _ => bad_arg("give 'doc_id' and 'exact_quote'"),
            },
            // a seal when the owner asks for one, between the seals the server writes by itself: the library's seal, a kernel frame
            // that replay already accepts at any point of a 0.2 journal (no rule changes)
            "audit_seal" => {
                // the library writes no seal right after another and says so: another would seal nothing new
                match g.state.seal() {
                    Ok(v) => {
                        let already = v["already"] == true;
                        let (n, hash) = *g.state.seals().last().expect("the last frame is a seal");
                        let mut sealed = json!({"status": if already { "ALREADY_SEALED" } else { "SEALED" }, "log_size": n,
                            "seal_hash": to_hex(&hash), "wal_head": g.state.wal_head().map(|h| to_hex(&h))});
                        if let Some(failed) = signing_failures(&g.state) {
                            sealed["signing"] = failed;
                        }
                        sealed
                    }
                    Err(e) => json!({"status": "error", "code": "SEAL_REFUSED", "error": e.to_json()}),
                }
            }
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
                // only a terminal run is closed; NOT_COMPLETE closes nothing. The close is an entry of the journal (a seal, then
                // `close`): a restart finds the run closed
                if name == "audit_close" && receipt["status"] == "TERMINAL" {
                    if let Err(e) = r.state.close_run() {
                        return json!({"status":"error","code":"CLOSE_NOT_DURABLE","error":e.to_json()});
                    }
                    r.closed = true;
                    // the agents are told DONE without the dispatcher: their waits end here (Codex review 987431f3, WAIT-01)
                    r.dispatch.stats.end_waits(now);
                    // the roots after the seal and the close entry; the terminal receipt names the state just before them
                    let mut closed =
                        json!({"status": "CLOSED", "audit_root": to_hex(&r.state.audit_root()), "wal_head": r.state.wal_head().map(|h| to_hex(&h))});
                    if let Some(failed) = signing_failures(&r.state) {
                        closed["signing"] = failed;
                    }
                    closed
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
            for (seal, error) in &r.state.sign_failures()[r.sign_failures_told..] {
                eprintln!("{}", json!({"status": "warning", "message": SIGN_FAILURE_NOTE, "seal": seal, "error": error}));
            }
            r.sign_failures_told = r.state.sign_failures().len();
        }
        // calls that can free or create work wake the long polls
        if !matches!(name, "audit_acquire" | "audit_status" | "audit_links" | "audit_record" | "audit_terminal_receipt" | "audit_next_card")
            && !READ_TOOLS.contains(&name)
        {
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

/// The target of `dependents`: a record, or a document with an optional byte range of its current version.
fn target_arg<'a>(state: &AuditState, args: &'a Value) -> Result<read::Target<'a>, Value> {
    match (args.get("record"), args.get("doc_id").and_then(Value::as_str)) {
        (Some(_), None) => record_arg(state, args).map(read::Target::Record),
        (None, Some(doc_id)) => {
            let at = |k: &str| args.get(k).map(|v| v.as_u64().map(|n| n as usize).ok_or_else(|| bad_arg(format!("'{k}' is a byte offset"))));
            match (at("start").transpose()?, at("end").transpose()?) {
                (None, None) => Ok(read::Target::Document { doc_id, range: None }),
                (Some(a), Some(z)) if a < z => Ok(read::Target::Document { doc_id, range: Some((a, z)) }),
                _ => Err(bad_arg("a range needs both 'start' and 'end', start before end")),
            }
        }
        _ => Err(bad_arg("give a 'record' or a 'doc_id'")),
    }
}

fn limit_arg(args: &Value) -> Option<usize> {
    args.get("limit").and_then(Value::as_u64).map(|n| n as usize)
}

/// The two points of a `diff`: `from`, and `to` (default: `now`), both from 1 to `now`, `from` before `to`.
fn points_arg(args: &Value, now: usize) -> Result<(usize, usize), Value> {
    let point = |k: &str| args.get(k).map(|v| v.as_u64().map(|n| n as usize).ok_or_else(|| bad_arg(format!("'{k}' is a point of the journal: an integer"))));
    let from = point("from").transpose()?.ok_or_else(|| bad_arg("missing 'from'"))?;
    let to = point("to").transpose()?.unwrap_or(now);
    if from == 0 || from >= to || to > now {
        return Err(bad_arg(format!("give points from 1 to {now}, 'from' before 'to'")));
    }
    Ok((from, to))
}

/// The point before a withdrawal and the state there, for its answer.
fn withdrawal_point(state: &AuditState) -> (usize, read::Snapshot) {
    let n = state.entries().unwrap_or(0);
    (n, read::Snapshot::of(state, n))
}

/// A withdrawal's answer names the point before it and how many claims, relations and answers fell: the operator asks
/// `audit_fallen` with that point for the report (SPEC_V02_STEP3 section 6).
fn withdrawal_answer(state: &AuditState, mut out: Value, (since, before): (usize, read::Snapshot)) -> Value {
    let report = read::fallen(state, state.entries().unwrap_or(0), Some(&before), Some(1));
    out["since"] = json!(since);
    out["fell"] = report["rows_fallen"].clone();
    out["quotes_gone"] = report["quotes_gone"].clone();
    out["report"] = json!(format!("audit_fallen with since={since}"));
    out
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
            if let Value::Object(more) = read::record_projection(state, id) {
                out.as_object_mut().expect("object").extend(more);
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

const SIGN_FAILURE_NOTE: &str =
    "a seal is in the journal but its signed checkpoint was not written: sbgk audit-sign --wal <run.wal> --signing-key <file> writes it";

/// The seals whose signed checkpoint could not be written (SPEC_V02_STEP4 section 3): the seal stands in the journal and `sbgk
/// audit-sign` writes the checkpoint again (Codex review of 904f1cdb, S4-05). `None` when every seal was signed.
fn signing_failures(state: &AuditState) -> Option<Value> {
    let failed = state.sign_failures();
    (!failed.is_empty()).then(|| {
        json!({"seals_not_signed": failed.iter().map(|(seal, error)| json!({"seal": seal, "error": error})).collect::<Vec<_>>(),
               "note": SIGN_FAILURE_NOTE})
    })
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
    if let Some(failed) = signing_failures(&r.state) {
        out["signing"] = failed;
    }
    if !r.about_unmatched.is_empty() {
        out["about_unmatched"] = json!({"questions": r.about_unmatched, "note": ABOUT_UNMATCHED_NOTE});
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

/// The journal this start has just created, until the run is up. A start that fails after that takes it away again, so the same
/// command can be given again: it holds the corpus and nothing anyone did. A journal that existed before this start is never named.
static NEW_JOURNAL: Mutex<Option<PathBuf>> = Mutex::new(None);

fn remember_new_journal(wal: &Path) {
    *NEW_JOURNAL.lock().unwrap_or_else(|e| e.into_inner()) = Some(wal.to_path_buf());
}

fn keep_new_journal() {
    *NEW_JOURNAL.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Called on the way out of a failed command.
pub fn drop_new_journal() {
    let Some(wal) = NEW_JOURNAL.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
    let mut failure = None;
    // on Windows an indexer or a sync client may hold a new file for a moment
    for pause in [0, 100, 400] {
        std::thread::sleep(Duration::from_millis(pause));
        match std::fs::remove_file(&wal) {
            Ok(()) => return,
            Err(e) => failure = Some(e),
        }
    }
    let message =
        format!("the new journal of this failed start stays behind: {}; remove it before giving the command again", failure.expect("a failed attempt"));
    eprintln!("{}", json!({"status": "warning", "message": message, "journal": wal.display().to_string()}));
}

/// The base ontology of a new run: from a file it seeds the run's concepts, without it the built-in schema. The genesis keeps either.
fn run_base(a: &Args) -> Value {
    let mut base = a.get("base-ontology").map(|p| read_json(p, "--base-ontology")).unwrap_or_else(AuditOntology::base);
    if a.get("base-ontology").is_some() {
        base["seed_status"] = json!("provisional");
    }
    if a.sw("ontology-revisions") {
        base["revision_policy"] = json!({"rule":"next_nonproposer/1","unmapped_circles":a.num("ontology-unmapped-circles",3usize),
            "catchall_mappings":a.num("ontology-catchall-mappings",8usize),"catchall_reports":a.num("ontology-catchall-reports",2usize)});
    }
    base
}

/// A new run on the text files of a folder, prepared without its journal (`start_journal` writes the genesis once every flag is
/// checked). What was taken and what was left stays on the operator's screen, not in the journal: the journal holds the text of
/// what was taken for good, so this is the moment to see it.
fn create_docs_run(a: &Args, folder: &str, wal: &Path) -> AuditState {
    if a.get("manifest").is_some() || a.get("repo").is_some() {
        fail("--docs starts a run on a folder, --manifest and --repo on a pinned corpus: give one of them");
    }
    let select = a.get("select").map(|p| std::fs::read_to_string(p).unwrap_or_else(|e| fail(&format!("cannot read --select: {e}"))));
    // the tokens of --subjects must not become a source of the run they guard
    let inputs: Vec<&str> = [a.get("subjects"), a.get("questions")].into_iter().flatten().collect();
    let own = super::docs_input::Own {
        paths: inputs.iter().copied().chain(wal.to_str()).filter_map(|p| std::fs::canonicalize(p).ok()).collect(),
        texts: inputs.iter().filter_map(|p| std::fs::read(p).ok()).collect(),
    };
    let taken = super::docs_input::collect(Path::new(folder), select.as_deref(), &own).unwrap_or_else(|e| fail(&e));
    let bytes: usize = taken.docs.iter().map(|(_, b)| b.len()).sum();
    let names: Vec<&str> = taken.docs.iter().map(|(id, _)| id.as_str()).collect();
    let left: Vec<Value> = taken.skipped.iter().map(|(path, why)| json!({"path": path, "reason": why})).collect();
    eprintln!("{}", json!({"status": "docs", "folder": folder, "bytes": bytes, "taken": names, "skipped": left}));
    AuditState::prepare_from_docs(&run_base(a), &a.req("run-id"), taken.docs).unwrap_or_else(|e| fail(&format!("cannot create the run: {}", e.to_json())))
}

/// A new run from the corpus manifest and the selected report paths, or from a folder, prepared without its journal.
fn create_run(a: &Args, wal: &Path) -> AuditState {
    if let Some(folder) = a.get("docs") {
        return create_docs_run(a, folder, wal);
    }
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
    AuditState::prepare_from_manifest(&run_base(a), &a.req("run-id"), &bytes, &selected)
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
    for (k, allowed) in [("candidate-match", vec!["legacy", "strict"]), ("known-concepts", vec!["off", "circles", "all"])] {
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
    // the address layer: a new concept may name its broad function, and lexical evolution pairs also
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
    agent_attempts: Option<u32>,
    unattested_at_end: bool,
    ontology_review: bool,
    answer_timeout_ms: Option<u64>,
    build_scope: &'static str,
}
fn coverage_context(
    section_bytes: usize,
    zones: &[Vec<String>],
    own_refs: bool,
    build_backlog: Option<usize>,
    circles: Option<&sbgk_core::audit::directives::circles::CircleConfig>,
    mode: CoverageMode,
) -> Value {
    let CoverageMode { ontology_review, answer_timeout_ms, agent_attempts, unattested_at_end, graph_quality, circle_refiner, build_scope } = mode;
    // the rule the sections are cut by: a run cut by another one is not taken up again (HDR-R01)
    let mut context = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": section_bytes,
                             "section_rule": sbgk_core::audit::directives::SECTION_RULE});
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
    context
}

/// Whether a journal can go on under these settings: read only, so a refused start leaves the journal as it was.
fn check_coverage(state: &AuditState, context: &Value, section_bytes: usize, resumed: bool) -> Result<(), String> {
    // a 0.2 journal names the hash of the canonical settings in its genesis; the checkpoint below still names what differs. A run the
    // library started names the empty settings: nothing is pinned there, and the checkpoint decides as before 0.2
    let unpinned = sbgk_core::audit::state::settings_hash(&json!({}));
    let pinned =
        state.genesis_meta().filter(|meta| meta.settings_hash != unpinned).map(|meta| meta.settings_hash == sbgk_core::audit::state::settings_hash(context));
    if pinned == Some(false) && state.checkpoint(COVERAGE_CHECKPOINT).is_none() {
        return Err(format!(
            "cannot resume with these settings (--section-bytes {section_bytes} and the switches of --profile): the run was started with other settings; start it again with the --profile and flags it was created with"
        ));
    }
    if let Some(checkpoint) = state.checkpoint(COVERAGE_CHECKPOINT) {
        return if checkpoint["context"] == *context && pinned != Some(false) {
            Ok(())
        } else {
            // name what differs: a run started with another --profile differs in its switches, not only in --section-bytes
            let stored = checkpoint["context"].as_object().cloned().unwrap_or_default();
            let given = context.as_object().cloned().unwrap_or_default();
            let mut keys: Vec<&String> = stored.keys().chain(given.keys()).filter(|k| stored.get(*k) != given.get(*k)).collect();
            keys.sort();
            keys.dedup();
            if stored.get("section_rule") != given.get("section_rule") {
                // no flag brings the run back: its task keys number sections that this kernel cuts otherwise (HDR-R01)
                return Err(format!(
                    "cannot resume this run: its documents were cut into sections by another rule (section rule {} here, {} in the run: a `#` line \
                     inside a fenced code block started a section before 0.2), and its section numbers would name other bytes now; start a new run",
                    sbgk_core::audit::directives::SECTION_RULE,
                    stored.get("section_rule").map_or("1".to_string(), Value::to_string)
                ));
            }
            Err(format!(
                "cannot resume with --section-bytes {section_bytes}: the stored configuration differs in {keys:?}; start it again with the                  --profile and flags the run was created with"
            ))
        };
    }
    if resumed && state.transaction_sequence().unwrap_or(0) != 0 {
        return Err("cannot resume --section-bytes safely: this progressed WAL has no audit-serve section configuration; start a new WAL".into());
    }
    Ok(())
}

/// Pins the settings of a new run; a run that has them stays as it is.
fn bind_coverage(state: &mut AuditState, context: Value) -> Result<(), String> {
    // a 0.2 journal also pins their hash in its genesis (`settings_hash`); the checkpoint keeps them readable on resume
    if state.checkpoint(COVERAGE_CHECKPOINT).is_some() {
        return Ok(());
    }
    let checkpoint = json!({"key": COVERAGE_CHECKPOINT, "from": 0, "to": 0, "context": context});
    match state.submit_operations_id("audit-mcp-coverage-config", "kernel", &[], Some(checkpoint)) {
        Ok(result) if result["checkpointed"] == true && result["error"].is_null() => Ok(()),
        Ok(result) => Err(format!("cannot bind audit-serve section configuration: {result}")),
        Err(error) => Err(format!("cannot bind audit-serve section configuration: {}", error.to_json())),
    }
}

/// The measured v0.1 default ("download, run, get what was measured"): no graph builder, reading in circles
/// with dynamic roles, stale suspects and the temporal summary with its companions. An explicit `--build-scope` still applies.
/// `--profile custom` takes every flag as given, the behaviour before v0.1 (the benchmark runner and the tests pass it). `--profile solo`
/// is v0.1 for one reading agent: no circles and no dynamic roles, which need a team of three.
const V01_SWITCHES: [&str; 5] = ["dynamic-roles", "circles", "stale-suspect", "temporal-summary", "summary-companions"];
const TEAM_SWITCHES: [&str; 2] = ["dynamic-roles", "circles"];

fn with_profile(a: &Args) -> Args {
    let mut a = a.clone();
    let chosen = a.get("profile").unwrap_or("v0.1").to_string();
    match chosen.as_str() {
        "custom" => {}
        profile @ ("v0.1" | "solo") => {
            for k in V01_SWITCHES.iter().filter(|k| profile == "v0.1" || !TEAM_SWITCHES.contains(k)) {
                a.sw.insert(k.to_string());
            }
            a.kv.entry("build-scope".to_string()).or_insert_with(|| "none".to_string());
        }
        other => fail(&format!("--profile must be v0.1, solo or custom, not '{other}'")),
    }
    a
}

/// Exit 2, in words, when the journal at `wal` cannot be read because a running server locks the whole file, as a server of 0.2.0
/// or earlier does on Windows: the system's own message (os error 33) names neither the server nor what to do. Any other trouble
/// is the command's to report.
pub(crate) fn refuse_locked_whole(wal: &str) {
    #[cfg(windows)]
    if let Err(e) = std::fs::File::open(wal).and_then(|mut f| std::io::Read::read(&mut f, &mut [0u8; 1])) {
        if e.raw_os_error() == Some(33) {
            fail(&format!("cannot read {wal}: {}", sbgk_core::audit::LOCKED_WHOLE));
        }
    }
    #[cfg(not(windows))]
    let _ = wal;
}

/// What a reading command says of a journal a writer held while it read: how far it read, and that the journal may have
/// grown since. `in_flight` counts the bytes of an entry the server had not finished at that moment, when the command knows them.
pub(crate) fn live_read(frames: usize, in_flight: Option<u64>) -> Value {
    let mut live = json!({"frames_read": frames,
        "note": "a writer held this journal: it was read up to its last complete frame at that moment and may have grown since"});
    if let Some(bytes) = in_flight {
        live["in_flight_bytes"] = json!(bytes);
    }
    live
}

/// `sbgk audit-verify --wal <run.wal> [--expect <receipt.json> [--at-end]]`: replays a recorded audit journal without a model, as a resumed
/// server would (frame hashes, source identities, every entry to its committed outcome and roots), and prints the roots and the
/// chain head it reaches. The kernel reads the file once, bounded and read-only: it is never locked, copied or written. With
/// `--expect`, the receipt's `audit_root` (with its `engine_root`, `session_root` and `wal_head` where it has them; a close stamp
/// has no engine root) must name a state the journal passed through, such as a phase receipt or the final one; a `wal_head`
/// binds the chain up to that state, not only the state; `--at-end` also asks that nothing follows it. Exit 0 when verified, 1 when the journal is refused, the receipt names
/// no state of it, or (without a receipt) bytes after the last complete entry were left unverified: status TORN_TAIL, usually a
/// crash. Exit 2 when the file cannot be read: that says nothing about the journal. A journal cut back to a complete entry is a
/// shorter sound journal: only a receipt shows that anything is missing. A journal a server is writing is checked up to its last
/// complete entry at that moment and the report says so (`live`): an entry the server has not finished is no torn tail.
pub fn cmd_audit_verify(a: &Args) {
    let wal = a.req("wal");
    refuse_locked_whole(&wal);
    if let Err(e) = std::fs::File::open(&wal).and_then(|mut f| std::io::Read::read(&mut f, &mut [0u8; 1])) {
        fail(&format!("cannot read {wal}: {e}"));
    }
    if a.sw("at-end") && a.get("expect").is_none() {
        fail("--at-end needs --expect: it asks that the receipt's state is the journal's last");
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
        // what else a receipt says of its run: a field that does not hold is a receipt of another run, though its roots may match
        let corpus = root("corpus_manifest_hash");
        let run_id =
            v.get("run_id").filter(|r| !r.is_null()).map(|r| r.as_str().map(str::to_string).unwrap_or_else(|| fail(&format!("{p}: run_id must be text"))));
        (audit, root("engine_root"), root("session_root"), root("wal_head"), corpus, run_id)
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
    let checkpoint = checkpoint_check(a, &wal);
    let mut out = json!({"status": "VERIFIED", "wal": wal, "wal_bytes": read.bytes, "wal_sha256": to_hex(&read.sha256),
                         "torn_tail_bytes": read.bytes - read.complete_bytes, "run_id": state.run_id(),
                         "corpus_manifest_hash": to_hex(&state.manifest_hash()), "entries": entries, "records": state.head(),
                         "audit_root": to_hex(&state.audit_root()), "engine_root": to_hex(&state.engine_root()),
                         "session_root": to_hex(&state.session_root()), "wal_head": to_hex(&read.wal_head)});
    if state.source_mode() == "opaque" {
        out["sources"] = json!({"mode": "opaque", "documents": state.source_document_count(), "set_matches_manifest_hash": state.docs_set_matches(),
                                "put_document_entries": read.document_puts});
    }
    if read.live {
        out["live"] = live_read(entries, Some(read.in_flight_bytes));
    }
    if let Some((verdict, refused)) = checkpoint {
        out["checkpoint"] = verdict;
        if refused {
            out["status"] = json!("CHECKPOINT_REFUSED");
            println!("{out}");
            std::process::exit(1);
        }
    }
    // listed whatever the verdict: after a cut, a mismatch is just the case where these files matter
    let earlier = torn_files(&wal);
    if !earlier.is_empty() {
        out["torn_tail_files"] = json!(earlier);
        out["note"] = json!("a recovery cut bytes off this journal's end and kept them in these files; the latest receipt tells whether anything was lost");
    }
    if let Some((audit, engine, session, head, corpus, run_id)) = expect {
        let found = states.iter().find(|s| s.1 == audit && engine.is_none_or(|e| s.2 == e) && head.is_none_or(|h| s.3 == h));
        let at = found.map(|s| s.0);
        // bytes after the last complete entry may be the entry that followed the receipt: the state is the end only with none
        // so may an entry a live server has not finished
        let at_end = at == Some(entries) && read.bytes == read.complete_bytes && read.in_flight_bytes == 0;
        let session_ok = found.is_some_and(|s| session.is_none_or(|x| x == state.session_root_for(&s.2, &audit)));
        let corpus_ok = corpus.is_none_or(|c| c == state.manifest_hash());
        let run_ok = run_id.as_deref().is_none_or(|r| r == state.run_id());
        out["expected"] = json!({"audit_root": to_hex(&audit), "engine_root": engine.map(|e| to_hex(&e)),
                                 "wal_head": head.map(|h| to_hex(&h)), "found_after_entries": at, "at_end": at_end,
                                 "session_root_matches": session.map(|_| session_ok),
                                 "corpus_manifest_hash_matches": corpus.map(|_| corpus_ok), "run_id_matches": run_id.as_ref().map(|_| run_ok)});
        if at.is_none() || !session_ok || !corpus_ok || !run_ok || (a.sw("at-end") && !at_end) {
            out["status"] = json!("MISMATCH");
            println!("{out}");
            std::process::exit(1);
        }
        if read.bytes != read.complete_bytes {
            out["note"] = json!(
                "the receipt's state is there, but bytes after the last complete entry were not read: only the latest receipt shows that nothing was lost"
            );
        }
    } else if read.bytes != read.complete_bytes {
        out["status"] = json!("TORN_TAIL");
        out["note"] = json!("the entries above verify, but the bytes after them are no complete entry, usually from a crash; the latest receipt tells whether anything was lost");
        println!("{out}");
        std::process::exit(1);
    }
    println!("{out}");
}

/// A signed checkpoint checked with its journal (SPEC_V02_STEP4 section 5): the signature against the trusted keys, else against
/// the verifier key given or the one beside the checkpoint (which pins nothing); then that it names a prefix of this journal ending
/// with a seal of the kernel. `None` without `--checkpoint`; else the verdict and whether it refuses.
fn checkpoint_check(a: &Args, wal: &str) -> Option<(Value, bool)> {
    let path = a.get("checkpoint")?;
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read --checkpoint {path}: {e}")));
    let trusted = trusted_keys_arg(a);
    let untrusted = verifier_key_arg(a, std::fs::read_to_string(Path::new(path).with_file_name("verifier.key")).ok());
    let anchored = a.get("anchored-at");
    let note = match sign::open_note(&text) {
        Ok(note) => note,
        Err(e) => return Some((json!({"file": path, "error": e.to_json()}), true)),
    };
    let verdict = sign::signature_verdict(&note, trusted.as_deref().unwrap_or(&[]), untrusted.as_ref(), anchored);
    let mut out = json!({"file": path, "signature": verdict.status, "key": verdict.key, "time": verdict.time});
    let mut refused = verdict.refused;
    let checked = match sign::parse_checkpoint(&note.body) {
        Ok((origin, size, root)) => sign::check_against_journal(Path::new(wal), &origin, size, &root).map(|()| (origin, size, root)),
        Err(e) => Err(e),
    };
    match checked {
        Ok((origin, size, root)) => out["names"] = json!({"origin": origin, "frames": size, "log_root": to_hex(&root)}),
        Err(e) => {
            out["journal"] = e.to_json();
            refused = true;
        }
    }
    Some((out, refused))
}

/// `--trusted-keys <file>`: the keys whose signatures are pinned (SPEC_V02_STEP4 section 4).
fn trusted_keys_arg(a: &Args) -> Option<Vec<sign::TrustedKey>> {
    a.get("trusted-keys").map(|p| {
        let t = std::fs::read_to_string(p).unwrap_or_else(|e| fail(&format!("cannot read --trusted-keys {p}: {e}")));
        sign::parse_trusted_keys(&t).unwrap_or_else(|e| fail(&format!("--trusted-keys {p}: {}", e.to_json())))
    })
}

/// `--key <file or text>`, else `fallback`: a verifier key that pins nothing.
fn verifier_key_arg(a: &Args, fallback: Option<String>) -> Option<NoteVerifier> {
    match a.get("key") {
        Some(k) => Some(std::fs::read_to_string(k).unwrap_or_else(|_| k.to_string())),
        None => fallback,
    }
    .map(|k| NoteVerifier::parse(&k).unwrap_or_else(|e| fail(&format!("verifier key: {}", e.to_json()))))
}

/// `sbgk keygen --name <name> --out <file>`: a new signing key for checkpoints, written to a file that must not exist yet and is never
/// printed; the verifier key, to give to whoever checks, is printed.
pub fn cmd_keygen(a: &Args) {
    let (name, out) = (a.req("name"), a.req("out"));
    let signer = NoteSigner::generate(&name).unwrap_or_else(|e| fail(&e.to_json().to_string()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // readable by its owner only, where the system has such modes (architect, 11.11.2026)
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&out).unwrap_or_else(|e| fail(&format!("cannot create {out}: {e}")));
    std::io::Write::write_all(&mut file, format!("{}\n", signer.text()).as_bytes()).unwrap_or_else(|e| fail(&format!("cannot write {out}: {e}")));
    println!(
        "{}",
        json!({"status": "KEY", "verifier_key": signer.verifier().text(), "signing_key_file": out,
                          "note": "keep the key file to yourself: whoever holds it signs as you; give the verifier key to whoever checks"})
    );
}

/// Refused, exit 1, when `out` names one of `inputs` by its path: the same path written another way, or a link to it (S6-01 for the
/// index, the review of the 0.2.0 release for the quittance). A second name of the same file, a hard link, is no path of it: that
/// one `write_aside` keeps safe.
fn not_over_inputs(wal: &str, out: &Path, inputs: &[(PathBuf, &str)], what: &str) {
    if let Some((_, input)) = inputs.iter().find(|(input, _)| super::audit_index::same_file(out, input)) {
        let error = format!("{what} would be written over {input}: give --out another path");
        println!("{}", json!({"status": "REFUSED", "wal": wal, "out": out.display().to_string(), "error": error}));
        std::process::exit(1)
    }
}

/// `bytes` written to a new file beside `out` and renamed over it: a rename replaces the name `out`, not the file behind it, so a
/// file `out` is a second name of (a hard link to the journal) keeps its bytes, and a failed write leaves `out` as it was (Codex's
/// OUT-01 of 85742398: `audit-proof --out` naming a hard link of the journal replaced the run by the quittance).
fn write_aside(out: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let mut tmp = out.as_os_str().to_owned();
    tmp.push(format!(".{}-{nonce}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    // only a file this call created is removed on failure: a name already taken is someone else's (Codex's third review)
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    let written = std::io::Write::write_all(&mut file, bytes).and_then(|()| file.sync_all());
    drop(file);
    written.and_then(|()| std::fs::rename(&tmp, out)).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// `sbgk audit-sign --wal <run.wal> --signing-key <file> [--out <folder>]`: a checkpoint for every seal of a recorded `/3` journal,
/// checked first as `audit-verify` checks it (SPEC_V02_STEP4 section 3), and the verifier key beside them.
pub fn cmd_audit_sign(a: &Args) {
    let wal = a.req("wal");
    let key = a.req("signing-key");
    let signer = NoteSigner::parse(&std::fs::read_to_string(&key).unwrap_or_else(|e| fail(&format!("cannot read {key}: {e}"))))
        .unwrap_or_else(|e| fail(&format!("--signing-key {key}: {}", e.to_json())));
    refuse_locked_whole(&wal);
    let mut heads = Vec::new();
    let (state, _) = match AuditState::verify_states(Path::new(&wal), &mut |_, _, head| heads.push(head)) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", json!({"status": "REFUSED", "wal": wal, "error": e.to_json()}));
            std::process::exit(1);
        }
    };
    if state.seals().is_empty() {
        println!("{}", json!({"status": "NO_SEALS", "wal": wal}));
        std::process::exit(1);
    }
    let dir = PathBuf::from(a.get("out").map_or(format!("{wal}.checkpoints"), str::to_string));
    // every file it writes is named before the first is written, and none of them is the journal or the signing key (Codex's
    // OUT-02 of 85742398: a journal named verifier.key in the folder of --out was checked, then replaced by the verifier key)
    let files: Vec<PathBuf> = state.seals().iter().map(|(n, _)| dir.join(format!("seal-{n}.txt"))).chain([dir.join("verifier.key")]).collect();
    let inputs = [(PathBuf::from(&wal), "the journal"), (PathBuf::from(&key), "the signing key")];
    for file in &files {
        not_over_inputs(&wal, file, &inputs, "a checkpoint or the verifier key");
    }
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", dir.display())));
    let mut written = Vec::new();
    for ((n, seal_hash), file) in state.seals().iter().zip(&files) {
        let body = sign::checkpoint_body(&sign::origin(state.run_id()), &heads[..=*n]);
        write_aside(file, signer.sign(&body).unwrap_or_else(|e| fail(&e.to_json().to_string())).as_bytes())
            .unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", file.display())));
        written.push(json!({"seal": n, "frames": n + 1, "seal_hash": to_hex(seal_hash), "file": file.display().to_string()}));
    }
    write_aside(&dir.join("verifier.key"), format!("{}\n", signer.verifier().text()).as_bytes())
        .unwrap_or_else(|e| fail(&format!("cannot write the verifier key: {e}")));
    println!("{}", json!({"status": "SIGNED", "wal": wal, "checkpoints": written, "verifier_key": signer.verifier().text()}));
}

/// `sbgk audit-proof --wal <run.wal> --record <id> [--seal <n>] [--checkpoint <file>] [--self-contained] [--with-status] [--out <file>]`:
/// a quittance of one record (SPEC_V02_STEP5 section 5), cut from a recorded journal, checked whole first, and the signed checkpoint
/// of its seal (the journal's last seal by default), with the verifier key beside that checkpoint inside. Exit 1 when refused.
pub fn cmd_audit_proof(a: &Args) {
    let wal = a.req("wal");
    let record = a.req("record");
    let refused = |e: sbgk_core::error::KernelError| -> ! {
        println!("{}", json!({"status": "REFUSED", "wal": wal, "error": e.to_json()}));
        std::process::exit(1)
    };
    refuse_locked_whole(&wal);
    let journal = proof::seals_read(Path::new(&wal)).unwrap_or_else(|e| refused(e));
    let seal = match a.get("seal") {
        Some(v) => v.parse::<usize>().unwrap_or_else(|_| fail(&format!("--seal: a frame number, not '{v}'"))),
        None => *journal.seals.last().unwrap_or_else(|| fail(&format!("{wal} has no seal"))),
    };
    let checkpoint = PathBuf::from(a.get("checkpoint").map_or(format!("{wal}.checkpoints/seal-{seal}.txt"), str::to_string));
    // a quittance is never written over what it is cut from: the journal, the checkpoint of its seal or the verifier key beside it
    // (the review of the 0.2.0 release: `--out` naming the journal wrote the quittance over the run); checked before anything is read
    // for a given --out, and again on the path it is written to, the default one included
    let inputs = [
        (PathBuf::from(&wal), "its journal"),
        (checkpoint.clone(), "the checkpoint of its seal"),
        (checkpoint.with_file_name("verifier.key"), "the verifier key of that checkpoint"),
    ];
    if let Some(out) = a.get("out") {
        not_over_inputs(&wal, Path::new(out), &inputs, "the quittance");
    }
    let text = std::fs::read_to_string(&checkpoint)
        .unwrap_or_else(|e| fail(&format!("cannot read the checkpoint {}: {e}; sbgk audit-sign writes the checkpoints of a journal", checkpoint.display())));
    let key = std::fs::read_to_string(checkpoint.with_file_name("verifier.key")).ok();
    let opts = proof::ProofOptions { self_contained: a.sw("self-contained"), with_status: a.sw("with-status") };
    let made = proof::build(Path::new(&wal), &record, Some(seal), &text, key.as_deref(), opts).unwrap_or_else(|e| refused(e));
    let target = made["target"].as_str().unwrap_or_default();
    let out = PathBuf::from(a.get("out").map_or(format!("{wal}.proofs/{}-seal-{seal}.json", &target[..16.min(target.len())]), str::to_string));
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", dir.display())));
    }
    not_over_inputs(&wal, &out, &inputs, "the quittance");
    let bytes = proof::to_file(&made);
    write_aside(&out, &bytes).unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", out.display())));
    let mut report = json!({"status": "PROOF", "file": out.display().to_string(), "target": target, "seal": seal, "mode": made["mode"],
                            "records": made["records"].as_array().map_or(0, Vec::len), "bytes": bytes.len()});
    if journal.live {
        // a quittance is cut at a seal, which later frames do not change: the note says only that the journal went on
        report["live"] = live_read(journal.frames, None);
    }
    println!("{report}");
}

/// `sbgk audit-proof-verify --proof <file> [--trusted-keys <file>] [--key <verifier>] [--expect-seal <hex>] [--anchored-at YYYY-MM-DD]`:
/// the check of a quittance alone, without its journal and without a model (SPEC_V02_STEP5 section 6). Exit 1 when refused.
pub fn cmd_audit_proof_verify(a: &Args) {
    let file = a.req("proof");
    let bytes = std::fs::read(&file).unwrap_or_else(|e| fail(&format!("cannot read {file}: {e}")));
    let trusted = trusted_keys_arg(a);
    let key = verifier_key_arg(a, None);
    let expect = a.get("expect-seal").map(|h| from_hex(h).filter(|x| to_hex(x) == h).unwrap_or_else(|| fail("--expect-seal: 64 lowercase hex digits")));
    let checked = match proof::parse(&bytes) {
        Ok(p) => proof::verify(&p, trusted.as_deref().unwrap_or(&[]), key.as_ref(), a.get("anchored-at"), expect.as_ref()),
        Err(e) => Err(e),
    };
    match checked {
        Ok(mut out) => {
            out["proof"] = json!(file);
            println!("{out}");
        }
        Err(e) => {
            println!("{}", json!({"status": "PROOF_REFUSED", "proof": file, "error": e.to_json()}));
            std::process::exit(1);
        }
    }
}

/// `sbgk audit-read <tool> --wal <run.wal>`: the reading tools of 0.2 over a recorded journal (SPEC_V02_STEP3). The journal is
/// checked first, as `audit-verify` checks it, and a refused journal is not read (exit 1). The tools answer as the live server's
/// do for the same state: `status`, `dependents` (`--record`, or `--doc-id` with an optional `--start`/`--end`), `active-claims`
/// (`--doc-id`), `diff` (`--from`, `--to`), `record` (`--record`), `fallen` (`--since`) and `coverage` (`--doc-id`, `--unit-status`),
/// each with `--limit`.
pub fn cmd_audit_read(a: &Args) {
    let tool = a.pos(0, "the reading tool: status, dependents, active-claims, diff, record, fallen or coverage");
    if !matches!(tool.as_str(), "status" | "dependents" | "active-claims" | "diff" | "record" | "fallen" | "coverage") {
        fail(&format!("unknown reading tool '{tool}': status, dependents, active-claims, diff, record, fallen or coverage"));
    }
    if let Some(status) = a.get("unit-status").filter(|st| !UNIT_STATUSES.contains(st)) {
        fail(&format!("--unit-status '{status}': one of {}", UNIT_STATUSES.join(", ")));
    }
    let wal = a.req("wal");
    let number = |k: &str| a.get(k).map(|v| v.parse::<usize>().unwrap_or_else(|_| fail(&format!("--{k}: an integer, not '{v}'"))));
    let (from, to, since, limit) = (number("from"), number("to"), number("since"), number("limit"));
    let points: Vec<usize> = [from, to, since].into_iter().flatten().collect();
    refuse_locked_whole(&wal);
    let (state, journal, entries, at) = match read::journal_points(Path::new(&wal), &points) {
        Ok(read) => read,
        Err(e) => {
            println!("{}", json!({"status": "REFUSED", "wal": wal, "error": e.to_json()}));
            std::process::exit(1);
        }
    };
    let snapshot = |n: usize| at.get(&n).unwrap_or_else(|| fail(&format!("the journal has {entries} frames: a point is from 1 to {entries}, not {n}")));
    let mut out = match tool.as_str() {
        "status" => read::status(&state, entries),
        "dependents" => {
            let mut args = json!({});
            for (flag, key) in [("record", "record"), ("doc-id", "doc_id")] {
                if let Some(v) = a.get(flag) {
                    args[key] = json!(v);
                }
            }
            for (flag, key) in [("start", "start"), ("end", "end")] {
                if let Some(v) = number(flag) {
                    args[key] = json!(v);
                }
            }
            match target_arg(&state, &args) {
                Ok(target) => read::dependents(&state, &target, limit),
                Err(e) => fail(&e.to_string()),
            }
        }
        "active-claims" => read::active_claims(&state, a.get("doc-id"), limit),
        "diff" => {
            let from = from.unwrap_or_else(|| fail("diff needs --from"));
            if from >= to.unwrap_or(entries) {
                fail("--from must come before --to");
            }
            // without --to, the end: the state the check replayed to
            let end;
            let to = match to {
                Some(n) => snapshot(n),
                None => {
                    end = read::Snapshot::of(&state, entries);
                    &end
                }
            };
            read::diff(snapshot(from), to, limit)
        }
        "record" => match record_arg(&state, &json!({"record": a.req("record")})) {
            Ok(id) => record_json(&state, &id),
            Err(e) => fail(&e.to_string()),
        },
        "coverage" => read::coverage(&state, entries, a.get("doc-id"), a.get("unit-status"), limit),
        _ => read::fallen(&state, entries, since.map(snapshot), limit),
    };
    if journal.live {
        out["live"] = live_read(entries, Some(journal.in_flight_bytes));
    }
    if a.sw("pretty") {
        println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
    } else {
        println!("{out}");
    }
}

/// The files beside `wal` that keep the tails cut off it by a recovery.
fn torn_files(wal: &str) -> Vec<String> {
    let path = Path::new(wal);
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return Vec::new() };
    let prefix = format!("{name}.torn-");
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| entries.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(&prefix)).map(|e| e.path().display().to_string()).collect())
        .unwrap_or_default();
    found.sort();
    found
}

/// `audit-serve --profile solo` without `--subjects` (the architect, 11.11.2026: one agent on its own folder in one command): the
/// server makes the subjects itself, one reading agent `agent` and the owner `owner`, each with a random token, in
/// `<run.wal>.subjects.json` beside the journal, readable by its owner only where the system has such modes. A resumed run takes
/// the same file. The tokens are never printed: the operator reads them from the file.
fn solo_subjects(wal: &str) -> String {
    let path = format!("{wal}.subjects.json");
    if !Path::new(&path).exists() {
        let token = || sign::random_hex(24).unwrap_or_else(|e| fail(&e.to_json().to_string()));
        let subjects = json!({"subjects": [{"token": token(), "role": "swarm", "id": "agent"}, {"token": token(), "role": "owner", "id": "owner"}]});
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path).unwrap_or_else(|e| fail(&format!("cannot create {path}: {e}")));
        std::io::Write::write_all(&mut file, format!("{subjects:#}\n").as_bytes()).unwrap_or_else(|e| fail(&format!("cannot write {path}: {e}")));
    }
    eprintln!(
        "{}",
        json!({"status": "subjects", "file": path, "agent": "agent", "owner": "owner",
               "note": "--profile solo without --subjects: one reading agent and the owner, with their tokens in this file; give each its own token (SBGK_MCP_TOKEN for mcp-bridge) and keep the file to yourself"})
    );
    path
}

const ABOUT_UNMATCHED_NOTE: &str =
    "no document of the run holds any term of these questions' about: their answers would leave out what the documents call otherwise; give terms the documents use";

/// The tools of the reading agent and of the owner, for `sbgk mcp`, which answers as both.
pub(crate) fn agent_tool_names() -> &'static [&'static str] {
    Role::Swarm.tools()
}

pub(crate) fn owner_tool_names() -> &'static [&'static str] {
    Role::Owner.tools()
}

/// A started audit server, before its transport: `audit-serve` gives it a socket (or stdio with tokens), `sbgk mcp` its own stdio.
pub(crate) struct AuditStart {
    pub(crate) server: Arc<AuditServer>,
    pub(crate) listener: Option<std::net::TcpListener>,
    pub(crate) max_connections: usize,
    pub(crate) hello: Value,
}

pub fn cmd_audit_serve(a: &Args) {
    let start = start_audit_server(a);
    let note = json!({"status": "ready", "audit": start.hello});
    mcp::run_bound(start.server, start.listener, start.max_connections, Some(note), json!({"audit": start.hello}));
}

/// Everything `audit-serve` does before it serves: the flags checked, the run created or resumed, its journal kept.
pub(crate) fn start_audit_server(a: &Args) -> AuditStart {
    let profiled_default_scope = a.get("build-scope").is_none();
    let mut profiled = with_profile(a);
    // a run resumed from the settings file it started with: the flags that started it are the journal's now, not read again
    let resuming = profiled.get("wal").is_some_and(|w| std::fs::metadata(w).is_ok_and(|m| m.len() > 0));
    if resuming {
        let started: Vec<String> = ["base-ontology", "docs", "manifest", "repo", "run-id", "select"]
            .iter()
            .filter(|f| profiled.from_settings.contains(**f))
            .map(|f| f.to_string())
            .collect();
        for flag in &started {
            profiled.kv.remove(flag);
        }
        if !started.is_empty() {
            eprintln!(
                "{}",
                json!({"status": "settings", "message": "resumed: the journal holds what these flags of the settings file started the run with", "not_read": started})
            );
        }
    }
    if profiled.get("subjects").is_none() && profiled.get("profile") == Some("solo") {
        let made = solo_subjects(&profiled.req("wal"));
        profiled.kv.insert("subjects".to_string(), made);
    }
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
    // the control runs, to see what the graph adds to the answers: `none` runs the swarm and the kernel without
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
    // circles +1: the swarm's independent graph builder, a fixed role outside the ring, refines every circle
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
    // links proposed by agents and decided by the owner need no builder, but a summary waits for one: say it before anyone waits
    if !no_builder(build_scope) && !dynamic_roles && !subjects.iter().any(|s| s.role == Role::Builder) {
        let message =
            format!("--build-scope {build_scope}: --subjects names no graph builder: if no agent builds the graph, start the run with --build-scope none");
        eprintln!("{}", json!({"status": "warning", "message": message}));
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
            fail("the v0.1 profile reads in circles and needs at least three EXTEND readers: pass --profile solo for one agent, or --profile custom");
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
    // a new run names its questions in its genesis; a resumed run takes them from there, and --questions, if given, must agree
    let questions_file = a.get("questions").map(|p| read_json(p, "--questions"));
    if let Some(file) = &questions_file {
        parse_questions(file).unwrap_or_else(|e| fail(&format!("--questions: {e}")));
    }
    // every flag that needs no journal is settled here: opening a journal cuts a torn tail, and a mistyped flag must not come after that
    if a.sw("ontology-revisions") && !circle_mode {
        fail("--ontology-revisions needs --circles and its authenticated roster");
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
    let graph_quality = graph_quality_args(a);
    let ontology_policy = json!({"rule":"next_nonproposer/1","unmapped_circles":a.num("ontology-unmapped-circles",3usize),"catchall_mappings":a.num("ontology-catchall-mappings",8usize),"catchall_reports":a.num("ontology-catchall-reports",2usize)});
    // the graph builder's typed requests (U1): off unless the run gives a positive bound
    let max_requests: usize = a.num("builder-requests", 0);
    let auto_reread_limit: usize = a.num("auto-rereads", 20);
    // the gap pass (SPEC_V02_GAP_PASS): a profile file of tiers, its limit and pack size, or the two flags alone; off by default
    let mut gap = a.get("gap-profile").map_or_else(GapProfile::default, |p| {
        GapProfile::from_json(&read_json(p, "--gap-profile")).unwrap_or_else(|e| fail(&format!("--gap-profile: {}", e.to_json())))
    });
    if gap.units_per_task == 0 {
        gap.units_per_task = 8;
    }
    if a.get("gap-pass").is_some() {
        gap.limit = a.num("gap-pass", 0usize);
    }
    if a.get("gap-units").is_some() {
        gap.units_per_task = a.num("gap-units", 8usize);
        if !(4..=8).contains(&gap.units_per_task) {
            fail("--gap-units must be 4..8");
        }
    }
    // a second reader is never the first: without circles (which need three readers) a run of one reading agent could never close
    // such a task (Codex review of 6d2c270, GAP-03)
    if gap.limit > 0 && !gap.second_reader_tiers.is_empty() && !circle_mode {
        let readers = subjects.iter().filter(|s| matches!(s.role, Role::Swarm) && s.kinds.as_ref().is_none_or(|k| k.contains(&TaskKind::Request))).count();
        if readers < 2 {
            fail("--gap-profile names second-reader tiers: the run needs at least two swarm agents that may read");
        }
    }
    // backpressure (run 10A-17): first readings wait for the graph builder's backlog; 0 keeps it off
    let backpressure_records: usize = a.num("backpressure-records", 0);
    let backpressure_per_task: usize = a.num("backpressure-per-task", DispatchConfig::default().backpressure_per_task);
    let stall = Duration::from_millis(a.num("backpressure-stall-ms", 120_000));
    // the lines one answer may hold: a strong reader of a whole report writes more than the swarm's 32
    let max_lines: usize = a.num("max-lines", DispatchConfig::default().max_lines);
    // the records a summary is shown (run S1.2: 0, the summary cites its agent's own records only, with --own-refs)
    let summary_records: usize = a.num("summary-records", DispatchConfig::default().summary_records);
    let zones_file = a.get("zones").map(|p| read_json(p, "--zones"));
    let lineage_file = a.get("version-lineage").map(|p| read_json(p, "--version-lineage"));
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
        if a.get("docs").is_some() {
            fail(&format!("{wal} already holds a run with its documents: resume it without --docs, or start a new run with another --wal"));
        }
        if a.get("base-ontology").is_some() {
            fail(&format!("{wal} already holds a run whose genesis fixed its base ontology: resume it without --base-ontology"));
        }
        let state = AuditState::open(Path::new(&wal)).unwrap_or_else(|e| fail(&format!("cannot resume {wal}: {}", e.to_json())));
        if !state.is_v3() {
            fail(&format!(
                "{wal} is a journal of the 0.1 format (sbgk-session-log/2): `sbgk audit-verify` still checks it, but this server writes only the 0.2 format; finish the run with a 0.1 release, or start a new run with another --wal"
            ));
        }
        state
    } else {
        if questions_file.is_none() {
            fail("--questions is required to start a run: the genesis names the questions of the run");
        }
        create_run(a, Path::new(&wal))
    };
    // a genesis that names no questions (a run the library started) takes them from --questions, as before 0.2
    let named = state.genesis_meta().map(|meta| meta.questions.clone()).filter(|q| q.as_array().is_some_and(|q| !q.is_empty()));
    let questions_value = match (named, &questions_file) {
        (Some(named), Some(file)) if named != *file => {
            fail(&format!("--questions differs from the questions {wal} was started with: resume it without --questions, or with the same file"))
        }
        (Some(named), _) => named,
        (None, Some(file)) => file.clone(),
        (None, None) => fail(&format!("{wal} names no questions in its genesis: give --questions")),
    };
    let questions = parse_questions(&questions_value).unwrap_or_else(|e| fail(&format!("questions of the run: {e}")));
    // a question whose terms no document holds would lose its answer in silence (the architect, 11.11.2026): said at the start and in
    // every status
    let about_unmatched: Vec<Value> =
        questions.iter().filter(|q| state.documents_mentioning(&q.about).is_empty()).map(|q| json!({"question": q.id, "about": q.about})).collect();
    if !about_unmatched.is_empty() {
        eprintln!("{}", json!({"status": "warning", "message": ABOUT_UNMATCHED_NOTE, "questions": about_unmatched}));
    }
    // said here, before any check below can stop the start: the cut has happened, and a later message would be lost with it
    if let Some((bytes, kept)) = state.dropped_tail() {
        let message =
            format!("the journal ended in {bytes} bytes that are no complete entry; the run resumes before them, which can undo what they held; check it against the latest receipt");
        eprintln!("{}", json!({"status": "warning", "message": message, "kept_in": kept.display().to_string()}));
    }
    // what is checked against the journal is only read here: no flag is refused after the first write. A tail cut on opening stays cut,
    // and was said above
    if build_scope != "versions" && (a.get("version-lineage").is_some() || state.checkpoint(sbgk_core::audit::versions::KEY).is_some()) {
        fail("a pinned version map requires --build-scope versions");
    }
    if state.ontology_revision_state().is_some() != a.sw("ontology-revisions") {
        fail("--ontology-revisions must match the pinned genesis policy");
    }
    if let Some(snapshot) = state.ontology_revision_state() {
        if snapshot["policy"] != ontology_policy {
            fail("ontology hint thresholds must match the pinned genesis policy");
        }
    }
    // reading zones and own references (run S1.2): off unless given
    let zones = zones_file.map(|v| parse_zones(&v, &state).unwrap_or_else(|e| fail(&format!("--zones: {e}")))).unwrap_or_default();
    let own_refs = a.sw("own-refs");
    let mut coverage = coverage_context(
        section_bytes,
        &zones,
        own_refs,
        build_backlog,
        circles.as_ref(),
        CoverageMode {
            graph_quality,
            circle_refiner: refiner.clone(),
            ontology_review,
            answer_timeout_ms,
            agent_attempts,
            unattested_at_end: a.sw("unattested-at-end"),
            build_scope,
        },
    );
    // pinned with the run's settings: a run is not resumed with another gap pass (a run without one keeps its coverage bytes)
    if gap.limit > 0 {
        coverage["gap_pass"] = gap.settings();
    }
    check_coverage(&state, &coverage, section_bytes, resume).unwrap_or_else(|error| fail(&error));
    // a concept type a question selects must be one of the run's ontology (Codex review d7d9a49, D11)
    let types = state.concept_types();
    for q in &questions {
        if let Some(t) = q.concept_types.iter().find(|t| !types.contains(t)) {
            fail(&format!("--questions: question {}: unknown concept type '{t}' (one of {types:?})", q.id));
        }
    }
    if !resume {
        let spec = GenesisSpec { questions: questions_value.clone(), settings: coverage.clone(), operator_meta: None };
        state.start_journal(Path::new(&wal), &spec).unwrap_or_else(|e| fail(&format!("cannot create the run: {}", e.to_json())));
        remember_new_journal(Path::new(&wal));
    }
    if build_scope == "versions" {
        let lineage = lineage_file
            .or_else(|| state.checkpoint(sbgk_core::audit::versions::KEY).map(|c| c["context"]["lineage"].clone()))
            .unwrap_or_else(|| json!({"lineages":[]}));
        state.enable_versions(&lineage).unwrap_or_else(|e| fail(&format!("--version-lineage: {e}")));
    }
    bind_coverage(&mut state, coverage).unwrap_or_else(|error| fail(&error));
    let cfg = DispatchConfig {
        corpus: if state.source_mode() == "opaque" { "a source document corpus" } else { DispatchConfig::default().corpus },
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
        gap: gap.clone(),
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
        // a run closed before a restart stays closed (its journal holds the `close` entry)
        closed: false,
        sign_failures_told: 0,
        about_unmatched,
    };
    run.closed = run.state.is_closed();
    // a seal every 256 frames and at each phase of a circle; `audit_close` writes the last one
    run.state.set_seal_every(Some(256));
    // every new seal signed beside the journal (SPEC_V02_STEP4 section 3)
    if let Some(path) = a.get("signing-key") {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read --signing-key {path}: {e}")));
        let signer = NoteSigner::parse(&text).unwrap_or_else(|e| fail(&format!("--signing-key {path}: {}", e.to_json())));
        run.state.set_checkpoint_signer(signer, PathBuf::from(format!("{wal}.checkpoints")));
    }
    if circle_mode {
        run.prepare(0, unix_ms()).unwrap_or_else(|e| fail(&format!("cannot recover circles: {e}")));
    }
    let mut hello = json!({"run_id": run.state.run_id(), "resumed": resume, "records": run.state.head(), "builder_cursor": run.cursor(),
                           "audit_root": to_hex(&run.state.audit_root()), "subjects": subjects.len()});
    // and in the first line, with the files that earlier recoveries kept
    if let Some((bytes, kept)) = run.state.dropped_tail() {
        hello["torn_tail_bytes"] = json!(bytes);
        hello["torn_tail_kept_in"] = json!(kept.display().to_string());
    }
    let earlier = torn_files(&wal);
    if !earlier.is_empty() {
        hello["torn_tail_files"] = json!(earlier);
    }
    let server = Arc::new(AuditServer { run: Mutex::new(run), changed: Condvar::new(), subjects, max_message_bytes, started: Instant::now() });
    keep_new_journal();
    AuditStart { server, listener, max_connections, hello }
}

/// A build scope without the graph builder: `none`, and `hints` (no build phase; a reading task gets one more
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
    fn a_run_cut_into_sections_by_an_earlier_rule_is_not_resumed() {
        // Codex recheck of baa75e5, HDR-R01: a resumed run took its section numbers of the earlier rule with the boundaries of the
        // new one, and 70 bytes were never issued
        let dir = std::env::temp_dir().join(format!("sbgk_section_rule_{}_{}", std::process::id(), unix_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let mode = || CoverageMode {
            graph_quality: Value::Null,
            circle_refiner: None,
            agent_attempts: None,
            unattested_at_end: false,
            ontology_review: false,
            answer_timeout_ms: None,
            build_scope: "full",
        };
        let current = coverage_context(128, &[], false, None, None, mode());
        assert_eq!(current["section_rule"], json!(sbgk_core::audit::directives::SECTION_RULE));
        let mut earlier = current.clone();
        earlier.as_object_mut().unwrap().remove("section_rule");
        let run = |name: &str, settings: &Value| {
            let docs = vec![("a.md".to_string(), b"# A\n\n~~~md\n# in code\n~~~\n\ntext\n".to_vec())];
            let mut state = AuditState::prepare_from_docs(&AuditOntology::base(), name, docs).unwrap();
            let spec = GenesisSpec { questions: json!([]), settings: settings.clone(), operator_meta: None };
            state.start_journal(&dir.join(format!("{name}.wal")), &spec).unwrap();
            bind_coverage(&mut state, settings.clone()).unwrap();
            state
        };
        let refused = check_coverage(&run("earlier", &earlier), &current, 128, true).unwrap_err();
        assert!(refused.contains("another rule") && refused.contains("start a new run"), "{refused}");
        assert_eq!(check_coverage(&run("same", &current), &current, 128, true), Ok(()), "a run of this rule goes on");
        let _ = std::fs::remove_dir_all(&dir);
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
