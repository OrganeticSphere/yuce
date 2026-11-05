//! `sbgk` — command line front end of the SBGK-P0 kernel and its measurement harness.
//!
//! Every command prints one JSON document on stdout so that the Python benchmark driver can
//! consume it without scraping.

use sbgk_core::cdc::CdcParams;
use sbgk_core::container::*;
use sbgk_core::hash::{sha256, to_hex};
use sbgk_core::node::*;
use sbgk_core::*;
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[path = "audit_mcp.rs"]
mod audit_mcp;
#[path = "bridge.rs"]
mod bridge;
#[path = "mcp.rs"] // explicit: `src/bin/yuce.rs` loads this file as a module
mod mcp;

// ------------------------------------------------------------------ allocation accounting

struct Counting;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let c = CUR.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(c, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        CUR.fetch_sub(l.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            if new >= l.size() {
                let c = CUR.fetch_add(new - l.size(), Ordering::Relaxed) + (new - l.size());
                PEAK.fetch_max(c, Ordering::Relaxed);
            } else {
                CUR.fetch_sub(l.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

// ------------------------------------------------------------------ argument parsing

const SWITCHES: &[&str] = &[
    "at-end",
    "timings",
    "oracle",
    "track-roots",
    "continue-on-error",
    "pretty",
    "ids-only",
    "exhaustive",
    "allow-remote",
    "allow-shutdown",
    "own-refs",
    "dynamic-roles",
    "circles",
    "ontology-revisions",
    "ontology-review",
    "unattested-at-end",
    "term-hygiene",
    "ring-rotate",
    "link-both-sides",
    "stale-suspect",
    "evolution-cards",
    "temporal-summary",
    "summary-companions",
    "concept-functions",
];

/// The flags each command reads. `parse_args` takes any `--name value`, so a typo such as `--expct` or `--allow-tool` would
/// otherwise switch a check or a limit off in silence; a flag outside its command's list is refused before the command runs.
/// `known_flags_cover_every_flag_the_code_reads` below keeps this table and the code together.
const CDC_FLAGS: &[&str] = &["cdc-mode", "cdc-min", "cdc-avg", "cdc-max"];
const SESSION_FLAGS: &[&str] = &["base", "docs", "ontology"];
const AUDIT_SERVE_FLAGS: &[&str] = &[
    "agent-attempts",
    "agent-timeout-ms",
    "allow-remote",
    "answer-timeout-ms",
    "auto-rereads",
    "backpressure-per-task",
    "backpressure-records",
    "backpressure-stall-ms",
    "base-ontology",
    "build-backlog",
    "build-scope",
    "builder-max-candidates",
    "builder-max-links",
    "builder-max-neighbors",
    "builder-max-ops",
    "builder-max-records",
    "builder-requests",
    "candidate-match",
    "change-summary-documents",
    "circles",
    "circles-refiner",
    "concept-functions",
    "dynamic-roles",
    "evolution-cards",
    "evolution-document-order",
    "evolution-pairing",
    "evolution-pairs-per-card",
    "evolution-pairs-per-concept",
    "evolution-pairs-per-function",
    "known-concepts",
    "link-both-sides",
    "listen",
    "manifest",
    "max-connections",
    "max-lines",
    "max-message-bytes",
    "ontology-catchall-mappings",
    "ontology-catchall-reports",
    "ontology-review",
    "ontology-revisions",
    "ontology-unmapped-circles",
    "own-refs",
    "profile",
    "questions",
    "refine-budget-ms",
    "repo",
    "ring-rotate",
    "run-id",
    "section-bytes",
    "select",
    "stale-suspect",
    "subjects",
    "summary-companions",
    "summary-records",
    "temporal-summary",
    "term-hygiene",
    "term-max-words",
    "ttl-ms",
    "unattested-at-end",
    "version-lineage",
    "wal",
    "wave-sections",
    "zones",
];

/// How many arguments without a flag name a command takes. A flag written with one dash, or with a dash a document turned into a
/// long one, parses as such an argument: it must not be dropped in silence any more than a mistyped flag.
fn positional_args(cmd: &str) -> usize {
    match cmd {
        "diff" => 2,
        "update-doc" | "root" | "view" | "dump-nodes" | "dump-claims" | "node-table" | "timetravel" | "timetravel-all" | "cone" | "verify" | "tamper" => 1,
        _ => 0,
    }
}

fn known_flags(cmd: &str) -> Option<Vec<&'static str>> {
    let own: &[&str] = match cmd {
        "apply" => &["continue-on-error", "oracle", "out", "pretty", "stream", "timings", "track-roots"],
        "serve" => &["ack", "targets", "wal-path"],
        "mcp-serve" => &["allow-remote", "listen", "max-connections", "max-message-bytes", "targets", "token", "wal-path"],
        "mcp-bridge" => &["agent-id", "allow-shutdown", "allow-tools", "connect", "connect-timeout-ms", "tier", "token"],
        "audit-serve" => AUDIT_SERVE_FLAGS,
        "audit-verify" => &["at-end", "expect", "wal"],
        "update-doc" => &["doc-id", "file", "out", "pretty"],
        "root" | "dump-claims" | "verify" => &["pretty"],
        "dump-nodes" => &["ids-only", "pretty"],
        "node-table" => &["out", "pretty"],
        "diff" => &["reps", "pretty"],
        "timetravel" => &["offset", "reps", "seq", "pretty"],
        "timetravel-all" => &["roots", "pretty"],
        "cone" => &["entity", "full-out", "out", "reps", "pretty"],
        "tamper" => &["exhaustive", "region", "seed", "trials", "pretty"],
        "emit-batch-directives" => &["k", "round", "seats", "state", "targets", "pretty"],
        "emit-directive" => &["k", "round", "seat", "seats", "state", "targets", "pretty"],
        "frontier" => &["state", "targets", "pretty"],
        "view" => &[],
        _ => return None,
    };
    let session: &[&[&str]] = if matches!(cmd, "apply" | "serve" | "mcp-serve") { &[SESSION_FLAGS, CDC_FLAGS] } else { &[] };
    Some(own.iter().chain(session.iter().flat_map(|s| s.iter())).copied().collect())
}

#[derive(Clone)]
struct Args {
    pos: Vec<String>,
    kv: HashMap<String, String>,
    sw: HashSet<String>,
}

fn parse_args(raw: Vec<String>) -> Args {
    let mut a = Args { pos: Vec::new(), kv: HashMap::new(), sw: HashSet::new() };
    let mut i = 0;
    while i < raw.len() {
        if let Some(name) = raw[i].strip_prefix("--") {
            if SWITCHES.contains(&name) {
                a.sw.insert(name.to_string());
            } else {
                i += 1;
                let v = raw.get(i).cloned().unwrap_or_else(|| fail(&format!("--{name} needs a value")));
                // a switch this build does not know would take the next flag as its value and drop both in silence
                if v.starts_with("--") {
                    fail(&format!("--{name} needs a value, not the flag {v}: is --{name} a switch this build does not know?"));
                }
                a.kv.insert(name.to_string(), v);
            }
        } else {
            a.pos.push(raw[i].clone());
        }
        i += 1;
    }
    a
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.kv.get(k).map(|s| s.as_str())
    }

    fn req(&self, k: &str) -> String {
        self.get(k).unwrap_or_else(|| fail(&format!("missing --{k}"))).to_string()
    }

    fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> T {
        match self.get(k) {
            None => default,
            Some(s) => s.parse().unwrap_or_else(|_| fail(&format!("--{k}: bad number '{s}'"))),
        }
    }

    fn pos(&self, i: usize, what: &str) -> String {
        self.pos.get(i).cloned().unwrap_or_else(|| fail(&format!("missing {what}")))
    }

    fn sw(&self, k: &str) -> bool {
        self.sw.contains(k)
    }
}

fn fail(msg: &str) -> ! {
    audit_mcp::drop_new_journal();
    eprintln!("{}", json!({"status": "fatal", "message": msg}));
    std::process::exit(2);
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")))
}

fn read_text(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")))
}

fn write(path: &str, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|e| fail(&format!("cannot write {path}: {e}")))
}

fn cdc_from(a: &Args) -> CdcParams {
    let d = CdcParams::default();
    let mode = match a.get("cdc-mode") {
        None => d.mode,
        Some(m) => sbgk_core::cdc::CdcMode::parse(m).unwrap_or_else(|| fail("--cdc-mode must be fastcdc or localmax")),
    };
    CdcParams { mode, min: a.num("cdc-min", d.min), avg: a.num("cdc-avg", d.avg), max: a.num("cdc-max", d.max) }
}

fn load_session(a: &Args) -> Session {
    if let Some(base) = a.get("base") {
        return open_session(&read(base)).unwrap_or_else(|e| fail(&format!("base container rejected: {e}")));
    }
    let onto = Ontology::from_json_str(&read_text(&a.req("ontology"))).unwrap_or_else(|e| fail(&e.to_string()));
    let mut s = Session::new(onto, cdc_from(a));
    if let Some(dir) = a.get("docs") {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| fail(&format!("cannot list {dir}: {e}")))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        for p in files {
            let id = p.file_stem().and_then(|x| x.to_str()).unwrap_or("doc").to_string();
            if id.len() > sbgk_core::session::MAX_STR {
                fail(&format!("document name too long: {id}"));
            }
            let bytes = std::fs::read(&p).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", p.display())));
            s.put_document(&id, &bytes);
        }
    }
    s
}

fn pct(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx] as f64
}

fn stats_us(mut v: Vec<u64>) -> Value {
    if v.is_empty() {
        return json!({"n": 0});
    }
    v.sort_unstable();
    let mean = v.iter().sum::<u64>() as f64 / v.len() as f64;
    json!({"n": v.len(), "mean": mean / 1e3, "p50": pct(&v, 0.5) / 1e3, "p99": pct(&v, 0.99) / 1e3, "max": *v.last().unwrap() as f64 / 1e3, "min": v[0] as f64 / 1e3})
}

fn session_summary(s: &mut Session) -> Value {
    let (sup, uns, conf) = s.engine.status_counts();
    let k = s.engine.kind_counts();
    json!({
        "state_root": to_hex(&s.engine.root()),
        "nodes": s.engine.node_count(),
        "kinds": {"evidence": k[1], "claims": k[2], "assertions": k[3], "derivations": k[4]},
        "multi_segment_evidence": s.engine.multi_segment_evidence(),
        "claims": {"supported": sup, "unsupported": uns, "conflicting": conf},
        "wal_bytes": s.wal.bytes.len(),
        "last_seq": s.last_seq,
    })
}

// ------------------------------------------------------------------ commands

fn cmd_apply(a: &Args) -> Value {
    let mut s = load_session(a);
    s.track_roots = a.sw("track-roots");
    let text = read_text(&a.req("stream"));
    let timings = a.sw("timings");
    let oracle = a.sw("oracle");
    let cont = a.sw("continue-on-error");
    let mut lat: Vec<u64> = Vec::new();
    let mut ops: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();
    let mut accepted = 0usize;
    let mut lines = 0usize;
    let mut oracle_ok = true;
    let mut overall_peak = 0usize;
    let t_all = Instant::now();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines += 1;
        let base = CUR.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let t0 = Instant::now();
        let r = s.apply_line(line);
        let ns = t0.elapsed().as_nanos() as u64;
        let peak = PEAK.load(Ordering::Relaxed);
        overall_peak = overall_peak.max(peak);
        match r {
            Ok(ap) => {
                accepted += 1;
                lat.push(ns);
                if timings {
                    let mut o = json!({"seq": ap.seq, "op": ap.op, "ns": ns, "peak_delta_bytes": peak.saturating_sub(base)});
                    if let Some(d) = &ap.dred {
                        o["dred"] =
                            json!({"over_deleted": d.over_deleted, "rederived": d.rederived, "net_removed": d.net_removed, "full_recompute": d.full_recompute});
                    }
                    ops.push(o);
                }
                if oracle && ap.op == "revoke_evidence" {
                    oracle_ok &= s.engine.oracle_check();
                }
            }
            Err(e) => {
                let mut j = e.to_json();
                j["line_index"] = json!(lines);
                errors.push(j);
                if !cont {
                    break;
                }
            }
        }
    }
    let total_ns = t_all.elapsed().as_nanos() as u64;
    if oracle {
        oracle_ok &= s.engine.oracle_check();
    }
    let mut rep = session_summary(&mut s);
    rep["lines"] = json!(lines);
    rep["accepted"] = json!(accepted);
    rep["error"] = errors.first().cloned().unwrap_or(Value::Null);
    rep["errors"] = json!(errors);
    rep["latency_us"] = stats_us(lat);
    rep["total_ms"] = json!(total_ns as f64 / 1e6);
    rep["peak_alloc_bytes"] = json!(overall_peak);
    if oracle {
        rep["oracle_ok"] = json!(oracle_ok);
    }
    if timings {
        rep["ops"] = json!(ops);
    }
    if s.track_roots {
        rep["roots"] = json!(s.seq_roots.iter().map(|(q, e, r)| json!({"seq": q, "wal_end": e, "root": to_hex(r)})).collect::<Vec<_>>());
    }
    if let Some(out) = a.get("out") {
        let bytes = build_container(&mut s);
        rep["container_bytes"] = json!(bytes.len());
        write(out, &bytes);
    }
    rep
}

/// `{"op":"directives","targets":{...},"seats":K,"k":4,"round":r}` on the live session (resident compiler): the same batch as
/// `emit-batch-directives` on a snapshot of this state, without building, reopening or verifying a container. The targets
/// may also be given as a file (`"targets_file": path`).
fn serve_directives(s: &Session, cache: &mut sbgk_core::DirectiveCache, v: &Value) -> Value {
    let t = Instant::now();
    let targets = match (v.get("targets"), v.get("targets_file").and_then(|x| x.as_str())) {
        (Some(t), _) => sbgk_core::Targets::from_json(t),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))
            .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| format!("targets: {e}")))
            .and_then(|t| sbgk_core::Targets::from_json(&t)),
        (None, None) => Err("missing 'targets' (or 'targets_file')".to_string()),
    };
    let targets = match targets {
        Ok(t) => t,
        Err(e) => return json!({"status": "error", "code": "BAD_TARGETS", "message": e}),
    };
    let num = |k: &str, d: u64| v.get(k).and_then(|x| x.as_u64()).unwrap_or(d);
    let mut rep = sbgk_core::emit_batch_frames_live(s, cache, &targets, num("seats", 1) as usize, num("k", 4) as usize, num("round", 1));
    rep["total_us"] = json!(t.elapsed().as_nanos() as f64 / 1e3);
    rep["resident"] = json!(true);
    rep["cache"] = cache.stats_json();
    rep["status"] = json!("directives");
    rep
}

/// Resident kernel process: JSONL events in, one JSON answer per line out. Control ops: `snapshot`, `state`, `finish`,
/// `directives` (a synchronous round, EXP-9) and the swarm ops of `SwarmSession::handle` (`set_targets`, `acquire_directive`,
/// `submit_directive`, `renew_lease`, `release_lease`, `put_document` / `post_erratum`, `query_cone`, `swarm_status`,
/// `emit_batch`, `apply_events`). Swarm ops number their events themselves; plain event lines carry their own `seq`.
/// `--wal-path` keeps a persistent session log (`sbgk_core::journal`, resumed when it holds records); `acquire_directive`
/// with `max_wait_ms` sleeps until the earliest lease expiry instead of answering `WAIT_IN_FLIGHT` (a single-stream server has
/// no other caller that could free work meanwhile).
fn cmd_serve(a: &Args) {
    let fresh = || {
        let mut sw = sbgk_core::SwarmSession::new(load_session(a));
        if a.get("targets").is_some() {
            sw.set_targets(read_targets(a));
        }
        Ok(sw)
    };
    let mut sw = match a.get("wal-path") {
        None => fresh().unwrap_or_else(|e: String| fail(&e)),
        Some(p) => {
            let (sw, rep) = sbgk_core::journal::open(std::path::Path::new(p), fresh).unwrap_or_else(|e| fail(&format!("session log: {e}")));
            eprintln!("{}", json!({"status": "wal", "wal": rep}));
            sw
        }
    };
    let terse = a.get("ack").unwrap_or("terse") != "full";
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v.get("op").and_then(|x| x.as_str()) == Some("snapshot") {
                let mut rep = session_summary(&mut sw.session);
                rep["status"] = json!("snapshot");
                if let Err(e) = write_snapshot(&mut sw.session, &v, &mut rep) {
                    rep = e;
                }
                let _ = writeln!(out, "{rep}");
                let _ = out.flush();
                continue;
            }
            if v.get("op").and_then(|x| x.as_str()) == Some("directives") {
                let rep = serve_directives(&sw.session, &mut sw.cache, &v);
                let _ = writeln!(out, "{rep}");
                let _ = out.flush();
                continue;
            }
            if v.get("op").and_then(|x| x.as_str()) == Some("state") {
                let mut rep = session_summary(&mut sw.session);
                rep["status"] = json!("state");
                let _ = writeln!(out, "{rep}");
                let _ = out.flush();
                continue;
            }
            if v.get("op").and_then(|x| x.as_str()) == Some("finish") {
                let mut rep = session_summary(&mut sw.session);
                rep["status"] = json!("finished");
                // a container that cannot be written is reported and the session stays open (retry with another path)
                let failed = write_snapshot(&mut sw.session, &v, &mut rep).err();
                let _ = writeln!(out, "{}", failed.as_ref().unwrap_or(&rep));
                let _ = out.flush();
                if failed.is_none() {
                    return;
                }
                continue;
            }
            if v.get("op").and_then(|x| x.as_str()) == Some("acquire_directive") {
                let rep = serve_acquire(&mut sw, &v);
                let _ = writeln!(out, "{rep}");
                let _ = out.flush();
                continue;
            }
            if let Some(rep) = v.get("op").and_then(|x| x.as_str()).and_then(|op| sw.handle(op, &v)) {
                if rep["code"] == "WAL_WRITE_FAILED" {
                    fail(&format!("session log: {}", rep["message"]));
                }
                let _ = writeln!(out, "{rep}");
                let _ = out.flush();
                continue;
            }
        }
        let resp = match sw.session.apply_line(line) {
            Ok(ap) if terse => json!({"ok": ap.seq}),
            Ok(ap) => ap.to_json(),
            Err(e) => e.to_json(),
        };
        if let Err(e) = sw.sync_wal() {
            fail(&format!("session log: {e}"));
        }
        let _ = writeln!(out, "{resp}");
        let _ = out.flush();
    }
}

/// Write the container to `v.out` when given (`container_bytes` in `rep`); a write error becomes an error answer.
fn write_snapshot(s: &mut Session, v: &Value, rep: &mut Value) -> Result<(), Value> {
    let Some(path) = v.get("out").and_then(|x| x.as_str()) else { return Ok(()) };
    let bytes = build_container(s);
    rep["container_bytes"] = json!(bytes.len());
    std::fs::write(path, &bytes).map_err(|e| json!({"status": "error", "code": "SNAPSHOT_WRITE_FAILED", "message": format!("cannot write {path}: {e}")}))
}

/// `acquire_directive` of `sbgk serve`, waiting up to `max_wait_ms` (cap 30 s) for a lease to expire while the answer is
/// `WAIT_IN_FLIGHT` (only on the server clock: with a virtual `now_ms` nothing expires while the server sleeps).
fn serve_acquire(sw: &mut sbgk_core::SwarmSession, v: &Value) -> Value {
    let max_wait = v.get("max_wait_ms").and_then(|x| x.as_u64()).unwrap_or(0).min(mcp::MAX_WAIT_CAP_MS);
    let t0 = Instant::now();
    loop {
        let mut rep = sw.handle("acquire_directive", v).expect("acquire_directive is a swarm op");
        if rep["code"] == "WAL_WRITE_FAILED" {
            fail(&format!("session log: {}", rep["message"]));
        }
        let waited = t0.elapsed().as_millis() as u64;
        let next = sw.next_expiry_ms().filter(|_| v.get("now_ms").is_none()).map(|e| e.saturating_sub(sw.now(None)).max(1));
        match next {
            Some(ms) if rep["status"] == "WAIT_IN_FLIGHT" && waited < max_wait => {
                std::thread::sleep(std::time::Duration::from_millis(ms.min(max_wait - waited)));
            }
            _ => {
                if max_wait > 0 {
                    rep["waited_ms"] = json!(t0.elapsed().as_secs_f64() * 1e3);
                }
                return rep;
            }
        }
    }
}

fn cmd_update_doc(a: &Args) -> Value {
    let mut s = open_session(&read(&a.pos(0, "container"))).unwrap_or_else(|e| fail(&e.to_string()));
    let before = to_hex(&s.engine.root());
    let doc_id = a.req("doc-id");
    if doc_id.len() > sbgk_core::session::MAX_STR {
        fail("--doc-id is too long");
    }
    if s.arena.doc(&doc_id).is_none() {
        fail(&format!("--doc-id {doc_id}: the container has no such document, and update-doc only replaces one"));
    }
    let bytes = read(&a.req("file"));
    let t0 = Instant::now();
    let rep = s.put_document(&doc_id, &bytes);
    let ns = t0.elapsed().as_nanos() as u64;
    let oracle_ok = s.engine.oracle_check();
    let container = build_container(&mut s);
    if let Some(out) = a.get("out") {
        write(out, &container);
    }
    json!({
        "doc_id": doc_id, "saved_to": a.get("out"), "chunks_before": rep.chunks_before, "chunks_total": rep.chunks_total, "chunks_new": rep.chunks_new, "chunks_reused": rep.chunks_reused,
        "evidence_total_for_doc": rep.evidence_total, "evidence_stale": rep.evidence_stale,
        "rebound_ok": rep.rebound_ok, "rebind_failed": rep.rebind_failed,
        "claims_touched": rep.claims_touched, "claims_net_removed": rep.claims_net_removed,
        "claims_supported_before": rep.claims_supported_before, "claims_supported_after": rep.claims_supported_after,
        "oracle_ok": oracle_ok, "elapsed_us": ns as f64 / 1e3,
        "root_before": before, "root_after": to_hex(&s.engine.root()), "container_bytes": container.len(),
    })
}

fn cmd_root(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let v = ContainerView::parse(&b).unwrap_or_else(|e| fail(&e.to_string()));
    json!({"root": to_hex(&v.root), "nodes": v.node_count(), "bytes": b.len()})
}

fn cmd_dump_nodes(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let v = ContainerView::parse(&b).unwrap_or_else(|e| fail(&e.to_string()));
    let recs = v.records().unwrap_or_else(|e| fail(&e.to_string()));
    if a.sw("ids-only") {
        return json!(recs.iter().map(|r| to_hex(&r.id)).collect::<Vec<_>>());
    }
    json!(recs
        .iter()
        .map(|r| json!({"id": to_hex(&r.id), "kind": kind_name(r.kind), "status": status_name(r.kind, r.status), "rank": r.rank}))
        .collect::<Vec<_>>())
}

fn cmd_dump_claims(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let v = ContainerView::parse(&b).unwrap_or_else(|e| fail(&e.to_string()));
    let recs = v.records().unwrap_or_else(|e| fail(&e.to_string()));
    json!(recs
        .iter()
        .filter(|r| r.kind == KIND_CLAIM)
        .filter_map(|r| Claim::decode(r.payload).ok().map(|c| json!({
            "s": c.s, "p": c.p, "o": c.o, "pol": c.pol.as_str(), "ctx": c.ctx, "t": [c.t_from, c.t_to],
            "status": status_name(KIND_CLAIM, r.status), "rank": r.rank,
        })))
        .collect::<Vec<_>>())
}

fn cmd_node_table(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let v = ContainerView::parse(&b).unwrap_or_else(|e| fail(&e.to_string()));
    if let Some(p) = a.get("out") {
        write(p, v.table);
    }
    json!({"table_bytes": v.table.len(), "table_sha256": to_hex(&sha256(v.table)), "index_bytes": v.index.len(), "index_sha256": to_hex(&sha256(v.index)), "root": to_hex(&v.root)})
}

fn timed<R>(reps: usize, mut f: impl FnMut() -> R) -> (R, Vec<u64>) {
    let mut times = Vec::with_capacity(reps);
    let mut last = f();
    for _ in 0..reps {
        let t = Instant::now();
        last = std::hint::black_box(f());
        times.push(t.elapsed().as_nanos() as u64);
    }
    (last, times)
}

fn cmd_diff(a: &Args) -> Value {
    let (ba, bb) = (read(&a.pos(0, "container A")), read(&a.pos(1, "container B")));
    let reps = a.num("reps", 500usize);
    let (d, times) = timed(reps, || merkle_diff(&ba, &bb).unwrap_or_else(|e| fail(&e.to_string())));
    let entries: Vec<Value> = d
        .entries
        .iter()
        .map(|e| match &e.change {
            DiffKind::OnlyInA => json!({"id": to_hex(&e.id), "kind": kind_name(e.kind), "change": "only_in_a"}),
            DiffKind::OnlyInB => json!({"id": to_hex(&e.id), "kind": kind_name(e.kind), "change": "only_in_b"}),
            DiffKind::StatusChanged { a, b } => json!({"id": to_hex(&e.id), "kind": kind_name(e.kind), "change": "status", "a": a, "b": b}),
        })
        .collect();
    json!({
        "equal": d.root_a == d.root_b, "buckets_differing": d.buckets_differing, "leaves_scanned": d.leaves_scanned,
        "entries": entries, "timing_us": stats_us(times),
    })
}

fn wal_offset_for_seq(buf: &[u8], seq: u64) -> usize {
    let v = ContainerView::parse(buf).unwrap_or_else(|e| fail(&e.to_string()));
    let frames = sbgk_core::wal::parse_frames(v.wal).unwrap_or_else(|e| fail(&e.to_string()));
    for f in &frames {
        if f.seq == seq && matches!(f.op, 1..=4) {
            return f.end;
        }
    }
    fail(&format!("no agent frame with seq {seq}"))
}

fn cmd_timetravel(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let offset = match a.get("offset") {
        Some(o) => o.parse().unwrap_or_else(|_| fail("bad --offset")),
        None => wal_offset_for_seq(&b, a.num("seq", 0u64)),
    };
    let reps = a.num("reps", 50usize);
    let (mut eng, times) = timed(reps, || reconstruct_container_at(&b, offset).unwrap_or_else(|e| fail(&e.to_string())));
    let v = ContainerView::parse(&b).unwrap();
    let (_, full_times) = timed(reps, || reconstruct_container_at(&b, v.wal.len()).unwrap());
    let (sup, uns, conf) = eng.status_counts();
    json!({
        "wal_offset": offset, "wal_total": v.wal.len(), "root": to_hex(&eng.root()), "nodes": eng.node_count(),
        "claims": {"supported": sup, "unsupported": uns, "conflicting": conf},
        "reconstruct_us": stats_us(times), "full_replay_us": stats_us(full_times),
    })
}

fn cmd_timetravel_all(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let report: Value = serde_json::from_str(&read_text(&a.req("roots"))).unwrap_or_else(|e| fail(&format!("bad roots file: {e}")));
    let roots = report.get("roots").and_then(|r| r.as_array()).cloned().unwrap_or_else(|| fail("no 'roots' array"));
    let mut mismatches = 0usize;
    let mut times = Vec::new();
    let mut bytes_read = Vec::new();
    for r in &roots {
        let off = r["wal_end"].as_u64().unwrap() as usize;
        let want = r["root"].as_str().unwrap();
        let t = Instant::now();
        let mut eng = reconstruct_container_at(&b, off).unwrap_or_else(|e| fail(&e.to_string()));
        let got = to_hex(&eng.root());
        times.push(t.elapsed().as_nanos() as u64);
        bytes_read.push(off as u64);
        if got != want {
            mismatches += 1;
        }
    }
    let v = ContainerView::parse(&b).unwrap();
    let (_, full) = timed(20, || reconstruct_container_at(&b, v.wal.len()).unwrap());
    json!({
        "checked": roots.len(), "mismatches": mismatches, "reconstruct_us": stats_us(times),
        "full_replay_us": stats_us(full), "wal_total": v.wal.len(),
    })
}

fn cmd_cone(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let entity = a.req("entity");
    let reps = a.num("reps", 30usize);
    // with --full-out the benchmarks ask for the whole projection and the entity only names a start
    if a.get("full-out").is_none() {
        match sbgk_core::cone::entity_known(&b, &entity) {
            Ok(true) => {}
            Ok(false) => fail(&format!("no claim of this container names the entity '{entity}'")),
            Err(e) => fail(&format!("cannot read the container: {e}")),
        }
    }
    let (cone, t_cone) = timed(reps, || project_minimal_cone(&b, &entity));
    let (full_all, t_full) = timed(reps.clamp(3, 10), || project_full(&b, false));
    let (full_act, t_act) = timed(reps.clamp(3, 10), || project_full(&b, true));
    if let Some(p) = a.get("out") {
        write(p, cone.as_bytes());
    }
    if let Some(p) = a.get("full-out") {
        write(p, full_all.as_bytes());
    }
    let cv: Value = serde_json::from_str(&cone).unwrap_or(Value::Null);
    let n = |k: &str| cv.get(k).and_then(|x| x.as_array()).map_or(0, |x| x.len());
    json!({
        "entity": entity,
        "cone_bytes": cone.len(), "full_all_bytes": full_all.len(), "full_active_bytes": full_act.len(),
        "cone_claims": n("claims"), "cone_steps": n("steps"), "cone_evidence": n("evidence"), "cone_targets": n("targets"),
        "cone_us": stats_us(t_cone), "full_all_us": stats_us(t_full), "full_active_us": stats_us(t_act),
        "container_bytes": b.len(),
    })
}

fn read_targets(a: &Args) -> sbgk_core::Targets {
    let text = read_text(&a.req("targets"));
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| fail(&format!("targets: {e}")));
    sbgk_core::Targets::from_json(&v).unwrap_or_else(|e| fail(&format!("targets: {e}")))
}

/// Frontier analysis + seat partition + one directive frame per seat (Addendum v0.2).
fn cmd_emit_batch(a: &Args) -> Value {
    let bytes = read(&a.req("state"));
    let targets = read_targets(a);
    let t = Instant::now();
    let mut v = sbgk_core::emit_batch_frames(&bytes, &targets, a.num("seats", 1usize), a.num("k", 4usize), a.num("round", 1u64))
        .unwrap_or_else(|e| fail(&format!("emit: {e}")));
    v["total_us"] = json!(t.elapsed().as_nanos() as f64 / 1e3);
    v
}

/// The directive of one seat (the same partition as `emit-batch-directives`, so seats never collide).
fn cmd_emit_directive(a: &Args) -> Value {
    let seat: usize = a.num("seat", 0usize);
    let v = cmd_emit_batch(a);
    let frame = v["frames"].get(seat).cloned().unwrap_or_else(|| fail("--seat is not below --seats"));
    json!({"round": v["round"], "seats": v["seats"], "complete": v["complete"], "analysis_us": v["analysis_us"], "total_us": v["total_us"], "frame": frame})
}

fn cmd_frontier(a: &Args) -> Value {
    let bytes = read(&a.req("state"));
    sbgk_core::frontier_json(&bytes, &read_targets(a)).unwrap_or_else(|e| fail(&format!("frontier: {e}")))
}

fn cmd_verify(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let t = Instant::now();
    match verify_container(&b) {
        Ok(r) => {
            json!({"ok": true, "nodes": r.nodes, "frames": r.frames, "chunks": r.chunks, "anchors_checked": r.anchors_checked, "elapsed_us": t.elapsed().as_nanos() as f64 / 1e3})
        }
        Err(e) => json!({"ok": false, "kind": e.kind, "detail": e.detail}),
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Flip single random bits and count how many are caught by full verification.
fn cmd_tamper(a: &Args) -> Value {
    let b = read(&a.pos(0, "container"));
    let trials: usize = a.num("trials", 1000);
    let region = a.get("region").unwrap_or("all").to_string();
    let mut rng = Rng(a.num("seed", 1u64));
    verify_container(&b).unwrap_or_else(|e| fail(&format!("container must verify before tampering: {e}")));
    let secs = section_ranges(&b).unwrap();
    let frames = wal_frame_ranges(&b).unwrap();
    let chunks: Vec<(usize, usize)> = arena_layout(&b).unwrap().into_iter().filter(|x| x.1 == 0).map(|x| (x.2, x.3)).collect();
    let mut detected = 0usize;
    let mut kinds: HashMap<String, usize> = HashMap::new();
    let mut undetected: Vec<Value> = Vec::new();
    let mut chain_only_detected = 0usize;
    let wal_start = secs[3].1;
    let t = Instant::now();
    let exhaustive = a.sw("exhaustive");
    let (lo, hi) = match region.as_str() {
        "all" => (0, b.len()),
        r => secs.iter().find(|s| s.0 == r).map(|s| (s.1, s.2)).unwrap_or((0, 0)),
    };
    let total = if exhaustive { (hi - lo) * 8 } else { trials };
    for n in 0..total {
        let (pos, label) = if exhaustive {
            let p = lo + n / 8;
            (p, secs.iter().find(|s| p >= s.1 && p < s.2).map(|s| s.0).unwrap_or("?"))
        } else {
            match region.as_str() {
                "wal" => {
                    let f = frames[rng.below(frames.len())];
                    (f.0 + rng.below(f.1 - f.0), "wal")
                }
                "chunk" => {
                    let c = chunks[rng.below(chunks.len())];
                    (c.0 + rng.below(c.1.max(1)), "chunk")
                }
                "all" => {
                    let p = rng.below(b.len());
                    (p, secs.iter().find(|s| p >= s.1 && p < s.2).map(|s| s.0).unwrap_or("?"))
                }
                other => {
                    let s = secs.iter().find(|s| s.0 == other).unwrap_or_else(|| fail("unknown --region"));
                    (s.1 + rng.below(s.2 - s.1), s.0)
                }
            }
        };
        let bit = if exhaustive { n % 8 } else { rng.below(8) };
        let mut m = b.clone();
        m[pos] ^= 1 << bit;
        match verify_container(&m) {
            Err(e) => {
                detected += 1;
                *kinds.entry(format!("{label}:{}", e.kind)).or_default() += 1;
            }
            Ok(_) => undetected.push(json!({"pos": pos, "bit": bit, "region": label})),
        }
        if label == "wal" && pos >= wal_start {
            let wal = &m[wal_start..secs[3].2];
            if sbgk_core::wal::verify_chain(wal).is_err() {
                chain_only_detected += 1;
            }
        }
    }
    json!({
        "region": region, "exhaustive": exhaustive, "trials": total, "detected": detected, "undetected": undetected.len(),
        "undetected_samples": undetected.into_iter().take(5).collect::<Vec<_>>(),
        "detected_by_hash_chain_alone": chain_only_detected, "by_channel": kinds,
        "container_bytes": b.len(), "ms_total": t.elapsed().as_nanos() as f64 / 1e6,
    })
}

const HELP: &str = "usage: sbgk (or yuce) <command> [arguments]

A deterministic evidence control kernel for AI agent teams.

Audit server for a team of agents:
  audit-serve   the shared audit server (newline-delimited JSON-RPC over TCP): --manifest --repo --select --run-id
                --wal --subjects --questions --listen; the measured v0.1 profile unless --profile custom.
                Started again on an existing --wal without --manifest, it resumes that run
  mcp-bridge    joins one MCP client (stdio) to a running audit-serve as one agent: --connect <addr> --agent-id <id>
                --allow-tools <list>; the token comes from SBGK_MCP_TOKEN
  audit-verify  replays a recorded audit journal without a model: --wal <run.wal> [--expect <receipt.json> [--at-end]]; prints the
                audit, engine and session roots, exit 1 if the journal is refused or the receipt names no state of it

Engine and container:
  apply         apply a JSONL stream: --ontology <file> --docs <dir> --stream <file> --out <container>
  verify        check a container (header, chunks, node table, hash chain, quote anchors): verify <container>;
                exit 1 if a check fails
  cone          the support cone of one entity: cone <container> --entity <id> [--out <file>]
  diff          what differs between two containers: diff <a> <b>
  timetravel    the state after a step: timetravel <container> --seq <n>
  root          the state root of a container: root <container>
  view          the full projection of a container: view <container>
  update-doc    replace one document: update-doc <container> --doc-id <id> --file <file> [--out <container>];
                without --out it reports the change and saves nothing

Measurement commands used by the benchmark runners:
  serve, mcp-serve, timetravel-all, dump-nodes, dump-claims, node-table, tamper, emit-directive,
  emit-batch-directives, frontier

Each command prints one JSON document on stdout. A usage or I/O error is one JSON line on stderr with exit code 2, an unknown
flag included; verify and audit-verify exit 1 when the check itself fails, and apply when a step is refused, with their report
on stdout (apply still writes the container of the steps it accepted).
  sbgk --help      this text
  sbgk --version   the version
More: README.md, examples/ and crates/sbgk-core/src/audit/README.md in the repository.";

pub fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        eprintln!("{HELP}");
        std::process::exit(2);
    }
    // `--help` anywhere, also after a command, before the flags are parsed: the parser would read it as a flag with a value
    if raw.iter().any(|r| r == "--help" || r == "-h") || raw[0] == "help" {
        println!("{HELP}");
        return;
    }
    if raw[0] == "--version" || raw[0] == "-V" {
        println!("sbgk {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let cmd = raw[0].clone();
    let a = parse_args(raw[1..].to_vec());
    if let Some(known) = known_flags(&cmd) {
        let mut given: Vec<&str> = a.kv.keys().chain(a.sw.iter()).map(String::as_str).collect();
        given.sort_unstable();
        if let Some(unknown) = given.into_iter().find(|f| !known.contains(f)) {
            fail(&format!("unknown flag --{unknown} for {cmd}: sbgk --help lists the commands"));
        }
        let takes = positional_args(&cmd);
        let stray = a.pos.iter().find(|p| p.starts_with(['-', '\u{2013}', '\u{2014}'])).or(a.pos.get(takes));
        if let Some(stray) = stray {
            fail(&format!("unexpected argument {stray} for {cmd}: sbgk --help lists the commands"));
        }
    }
    let out = match cmd.as_str() {
        "apply" => cmd_apply(&a),
        "serve" => {
            cmd_serve(&a);
            return;
        }
        "mcp-serve" => {
            mcp::cmd_mcp_serve(&a);
            return;
        }
        "mcp-bridge" => {
            bridge::cmd_mcp_bridge(&a);
            return;
        }
        "audit-serve" => {
            audit_mcp::cmd_audit_serve(&a);
            return;
        }
        "audit-verify" => {
            audit_mcp::cmd_audit_verify(&a);
            return;
        }
        "update-doc" => cmd_update_doc(&a),
        "root" => cmd_root(&a),
        "dump-nodes" => cmd_dump_nodes(&a),
        "dump-claims" => cmd_dump_claims(&a),
        "node-table" => cmd_node_table(&a),
        "diff" => cmd_diff(&a),
        "timetravel" => cmd_timetravel(&a),
        "timetravel-all" => cmd_timetravel_all(&a),
        "cone" => cmd_cone(&a),
        "verify" => cmd_verify(&a),
        "tamper" => cmd_tamper(&a),
        "emit-batch-directives" => cmd_emit_batch(&a),
        "emit-directive" => cmd_emit_directive(&a),
        "frontier" => cmd_frontier(&a),
        "view" => {
            let b = read(&a.pos(0, "container"));
            println!("{}", project_full(&b, true));
            return;
        }
        other => fail(&format!("unknown command '{other}': sbgk --help lists the commands")),
    };
    if a.sw("pretty") {
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("{out}");
    }
    // a failed check exits 1, as audit-verify does, so a script or a CI step that reads the exit code cannot take a
    // tampered container for a sound one (it printed "ok": false and exited 0 before)
    if cmd == "verify" && out.get("ok") == Some(&Value::Bool(false)) {
        std::process::exit(1);
    }
    // a refused step exits 1 too: `apply && verify` must not take a refused run for a sound one, as the container of the steps
    // accepted before it is still written and verifies
    if cmd == "apply" && out.get("errors").and_then(Value::as_array).is_some_and(|e| !e.is_empty()) {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod flag_tests {
    use super::*;

    /// every flag read by a literal get, req, num or sw call in the code of the commands (the tests below them are left out)
    fn flags_read(src: &str) -> Vec<String> {
        let src = src.split("#[cfg(test)]").next().unwrap();
        let mut out = Vec::new();
        for call in ["a.get(\"", "a.req(\"", "a.num(\"", "a.sw(\""] {
            for (at, _) in src.match_indices(call) {
                let before = src[..at].chars().next_back().unwrap_or(' ');
                if before.is_alphanumeric() || before == '_' || before == '.' {
                    continue;
                }
                let rest = &src[at + call.len()..];
                let name = &rest[..rest.find('"').unwrap()];
                // a flag is spelled with hyphens; a name with an underscore is a JSON field of a variable also called `a`
                if !name.contains('_') {
                    out.push(name.to_string());
                }
            }
        }
        out
    }

    #[test]
    fn known_flags_cover_every_flag_the_code_reads() {
        let commands = [
            "apply",
            "serve",
            "mcp-serve",
            "mcp-bridge",
            "audit-serve",
            "audit-verify",
            "update-doc",
            "root",
            "dump-claims",
            "verify",
            "dump-nodes",
            "node-table",
            "diff",
            "timetravel",
            "timetravel-all",
            "cone",
            "tamper",
            "emit-batch-directives",
            "emit-directive",
            "frontier",
            "view",
        ];
        let all: Vec<&str> = commands.iter().flat_map(|c| known_flags(c).unwrap()).collect();
        let sources = [include_str!("main.rs"), include_str!("audit_mcp.rs"), include_str!("bridge.rs"), include_str!("mcp.rs")];
        for flag in sources.iter().flat_map(|s| flags_read(s)) {
            assert!(all.contains(&flag.as_str()), "--{flag} is read by the code but no command lists it");
        }
        // the switches and the flags read through a list rather than a literal call
        for flag in SWITCHES.iter().chain(["candidate-match", "known-concepts", "evolution-pairs-per-concept"].iter()) {
            assert!(all.contains(flag), "--{flag} is known to the parser but no command lists it");
        }
    }

    /// The body of `fn name` in a source: from its line to the first line that closes it.
    fn body<'a>(src: &'a str, name: &str) -> &'a str {
        let start = src.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("no fn {name}"));
        let rest = &src[start..];
        &rest[..rest.find("\n}\n").unwrap_or(rest.len())]
    }

    /// Per command, not only over all of them: a flag taken off one command's list must fail here though another command lists it.
    #[test]
    fn each_command_lists_the_flags_of_its_own_function() {
        let main = include_str!("main.rs");
        let audit = include_str!("audit_mcp.rs");
        for (command, src, function) in [
            ("audit-serve", audit, "graph_quality_args"),
            ("audit-serve", audit, "create_run"),
            ("audit-serve", audit, "with_profile"),
            ("apply", main, "cmd_apply"),
            ("update-doc", main, "cmd_update_doc"),
            ("root", main, "cmd_root"),
            ("dump-nodes", main, "cmd_dump_nodes"),
            ("dump-claims", main, "cmd_dump_claims"),
            ("node-table", main, "cmd_node_table"),
            ("diff", main, "cmd_diff"),
            ("timetravel", main, "cmd_timetravel"),
            ("timetravel-all", main, "cmd_timetravel_all"),
            ("cone", main, "cmd_cone"),
            ("verify", main, "cmd_verify"),
            ("tamper", main, "cmd_tamper"),
            ("emit-directive", main, "cmd_emit_directive"),
            ("emit-batch-directives", main, "cmd_emit_batch"),
            ("frontier", main, "cmd_frontier"),
            ("audit-verify", audit, "cmd_audit_verify"),
            ("audit-serve", audit, "cmd_audit_serve"),
        ] {
            let known = known_flags(command).unwrap();
            for flag in flags_read(body(src, function)) {
                assert!(known.contains(&flag.as_str()), "{command} reads --{flag} but does not list it");
            }
        }
    }

    #[test]
    fn an_unknown_command_has_no_list() {
        assert!(known_flags("no-such-command").is_none());
    }
}
