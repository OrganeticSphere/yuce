//! `sbgk mcp-serve`: the swarm dispatcher (`SwarmSession`) as a Model Context Protocol server (JSON-RPC 2.0, one message per
//! line). Transports: stdio (default) or, with `--listen 127.0.0.1:<port>`, TCP with one thread per connection around one
//! `Mutex<SwarmSession>`, so that tens of workers can hold connections and call tools at the same time. With port 0 the
//! chosen address is printed as the first line of stdout: `{"status":"listening","addr":"127.0.0.1:PORT","port":PORT}`.
//!
//! Methods: `initialize`, `notifications/*` (no answer), `ping`, `tools/list`, `tools/call`, and the non-standard `shutdown`
//! (answers, then ends the process). A tool result carries the dispatcher's JSON as `structuredContent` and as text; with
//! `"compact": true` in the arguments the text is a one-line summary instead.
//!
//! Options: `--wal-path` (persistent session log, `sbgk_core::journal`: replayed on start when it holds records),
//! `--token` (every request must present it: `auth_token` in the `initialize` params authenticates the connection, or
//! `_meta.auth_token` / `arguments.auth_token` per call; otherwise JSON-RPC error -32001), `--allow-remote` (required, with a
//! token, to listen on a non-loopback address), `--max-message-bytes` (default 4 MiB; a longer line gets -32600 and is
//! skipped without being buffered) and `--max-connections` (default 256; a connection over the cap gets one error line and is
//! closed). TCP clients have five seconds to send a complete authenticated request (or a first message without `--token`);
//! partial bytes and failed authentication do not renew that deadline. Admitted clients and stdio keep their normal lifetime.
//! `sbgk_acquire_directive` with `max_wait_ms` long-polls: while the answer would be `WAIT_IN_FLIGHT` the call
//! sleeps on a condition variable that every call able to free or create work signals.

use super::{fail, load_session, read_targets, session_summary, Args};
use sbgk_core::cdc::CdcParams;
use sbgk_core::container::build_container;
use sbgk_core::journal;
use sbgk_core::{Ontology, Session, SwarmSession, Targets};
use serde_json::{json, Value};
use std::cell::Cell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const PROTOCOL: &str = "2025-06-18";
/// Longest `max_wait_ms` a call can ask for.
pub const MAX_WAIT_CAP_MS: u64 = 30_000;
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// A TCP client must prove admission within this absolute deadline; partial bytes do not renew it.
const TCP_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
/// JSON-RPC error of a request without the server's token.
const UNAUTHORIZED: i64 = -32001;

#[derive(Default)]
struct State {
    sw: Option<SwarmSession>,
    /// `--wal-path`: the session log `sbgk_init_session` starts when the call names none.
    wal_path: Option<String>,
    /// When the last call that can free or create work signalled the waiters (for `wake_latency_us`).
    signalled_at: Option<Instant>,
    /// Long-polling `sbgk_acquire_directive` calls blocked right now (`sbgk_swarm_status` reports it as `long_polls_waiting`).
    long_polls: usize,
}

struct Server {
    state: Mutex<State>,
    /// Signalled after every call that can free or create work (long polling of `sbgk_acquire_directive`).
    changed: Condvar,
    token: Option<String>,
    max_message_bytes: usize,
}

impl Server {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn num(desc: &str) -> Value {
    json!({"type": "integer", "minimum": 0, "description": desc})
}

fn tools() -> Value {
    let now = num("virtual clock in ms (deterministic runs); default: ms since the server started");
    let agent = json!({"type": "string", "description": "id of the calling worker"});
    let lease = json!({"type": "string", "description": "lease id returned by sbgk_acquire_directive, e.g. \"L7\""});
    let events = json!({"type": "array", "items": {"type": "object"}, "description": "graph events (bind_evidence / assert_fact / derive / revoke_evidence), without seq"});
    let compact = json!({"type": "boolean", "description": "text content is a one-line summary (the full answer stays in structuredContent)"});
    let schema = |props: Value, req: &[&str]| json!({"type": "object", "properties": props, "required": req});
    let t = |name: &str, desc: &str, input: Value| json!({"name": name, "description": desc, "inputSchema": input});
    json!([
        t(
            "sbgk_init_session",
            "Start a new kernel session: ontology (JSON object or path), documents ({doc_id: text} or a directory), optional targets and swarm options.",
            schema(
                json!({"ontology": {"type": ["object", "string"]}, "docs": {"type": ["object", "string"]}, "targets": {"type": "object"},
                        "auto_close_p2a": {"type": "boolean"}, "lock_mode": {"type": "string", "enum": ["shared_premise", "target_only"]},
                        "pack_multi_target": {"type": "boolean"}, "default_ttl_ms": num("lease TTL when acquire gives none"),
                        "default_k": num("event budget when acquire gives none"),
                        "heavy_alive_ms": num("a heavy_reasoner counts as alive this long after its last acquire (default 60000)"),
                        "wal_path": {"type": "string", "description": "persistent session log (default: the server's --wal-path)"},
                        "wal_overwrite": {"type": "boolean", "description": "replace an existing log at wal_path (default: refuse)"}}),
                &["ontology"]
            )
        ),
        t(
            "sbgk_set_targets",
            "Set the goals the swarm must close and the swarm options.",
            schema(
                json!({"targets": {"type": "object"}, "auto_close_p2a": {"type": "boolean"}, "lock_mode": {"type": "string"},
                        "pack_multi_target": {"type": "boolean"}, "default_ttl_ms": num("default lease TTL"), "default_k": num("default event budget"),
                        "heavy_alive_ms": num("heavy_reasoner liveness window")}),
                &["targets"]
            )
        ),
        t(
            "sbgk_acquire_directive",
            "Lease the most urgent free work: returns DIRECTIVE (lease + self-contained frame), WAIT_IN_FLIGHT or COMPLETE.",
            schema(
                json!({"agent_id": agent, "ttl_ms": num("lease time to live"), "k": num("event budget"), "now_ms": now,
                        "tier": {"type": "string", "enum": ["fast_cheap", "standard", "heavy_reasoner"],
                                 "description": "worker class (default standard: any work); fast_cheap leaves amendments and conflicts to a live heavy_reasoner"},
                        "max_wait_ms": num("long poll: wait up to this long (cap 30000) instead of answering WAIT_IN_FLIGHT"), "compact": compact}),
                &["agent_id"]
            )
        ),
        t(
            "sbgk_submit_directive",
            "Submit the events of a lease: COMMITTED, REPAIR_REQUIRED (one repair per lease), LEASE_CLOSED or STALE_LEASE.",
            schema(json!({"lease_id": lease, "agent_id": agent, "events": events, "now_ms": now, "compact": compact}), &["lease_id", "events"])
        ),
        t(
            "sbgk_renew_lease",
            "Heartbeat: extend a live lease.",
            schema(json!({"lease_id": lease, "agent_id": agent, "ttl_ms": num("new TTL from now"), "now_ms": now}), &["lease_id"])
        ),
        t("sbgk_release_lease", "Give a lease back unfinished.", schema(json!({"lease_id": lease, "agent_id": agent, "now_ms": now}), &["lease_id"])),
        t(
            "sbgk_post_erratum",
            "Publish a document (erratum) on the live session; it is routed at once.",
            schema(json!({"doc_id": {"type": "string"}, "erratum_text": {"type": "string"}, "now_ms": now}), &["erratum_text"])
        ),
        t(
            "sbgk_query_cone",
            "Minimal support cone of an entity (claims with their status).",
            schema(json!({"target_entity": {"type": "string"}}), &["target_entity"])
        ),
        t("sbgk_swarm_status", "Counters, active leases, open gaps, goal states and the state root.", schema(json!({"now_ms": now, "compact": compact}), &[])),
        t(
            "sbgk_emit_batch",
            "One synchronous round of directives (round-barrier baseline, as EXP-9).",
            schema(json!({"seats": num("seats of the round"), "k": num("event budget"), "round": num("round number"), "targets": {"type": "object"}}), &[])
        ),
        t(
            "sbgk_apply_events",
            "Apply plain events without a lease (the kernel numbers them); stops at the first rejection.",
            schema(json!({"events": events}), &["events"])
        ),
        t("sbgk_snapshot", "Write the session as a .sbgk container (optional) and return its summary.", schema(json!({"out": {"type": "string"}}), &[])),
    ])
}

fn ontology_from(v: &Value) -> Result<Ontology, String> {
    let text = match v {
        Value::Object(_) => v.to_string(),
        Value::String(s) if s.trim_start().starts_with('{') => s.clone(),
        Value::String(path) => std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?,
        _ => return Err("'ontology' must be an object or a path".into()),
    };
    Ontology::from_json_str(&text).map_err(|e| e.to_string())
}

fn init_session(args: &Value) -> Result<SwarmSession, String> {
    let onto = ontology_from(args.get("ontology").ok_or("missing 'ontology'")?)?;
    let mut s = Session::new(onto, CdcParams::default());
    match args.get("docs") {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            let mut ids: Vec<&String> = m.keys().collect();
            ids.sort();
            for id in ids {
                let text = m[id].as_str().ok_or("document texts must be strings")?;
                if id.is_empty() || id.len() > sbgk_core::session::MAX_STR {
                    return Err(format!("bad document id '{id}'"));
                }
                s.put_document(id, text.as_bytes());
            }
        }
        Some(Value::String(dir)) => {
            let mut files: Vec<_> = std::fs::read_dir(dir)
                .map_err(|e| format!("cannot list {dir}: {e}"))?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            files.sort();
            for p in files {
                let id = p.file_stem().and_then(|x| x.to_str()).unwrap_or("doc").to_string();
                let bytes = std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                s.put_document(&id, &bytes);
            }
        }
        Some(_) => return Err("'docs' must be an object {doc_id: text} or a directory".into()),
    }
    let mut sw = SwarmSession::new(s);
    // the swarm options apply with or without targets
    sw.configure(args).map_err(|e| e["message"].as_str().unwrap_or("bad swarm option").to_string())?;
    if args.get("targets").is_some() {
        let r = sw.handle("set_targets", args).expect("set_targets is a swarm op");
        if r["status"] == "error" {
            return Err(r["message"].as_str().unwrap_or("bad targets").to_string());
        }
    }
    Ok(sw)
}

/// A new session for `sbgk_init_session`, with its session log when the call (or the server) names one.
fn init_tool(st: &mut State, args: &Value) -> Value {
    let sw = match init_session(args) {
        Ok(sw) => sw,
        Err(e) => return json!({"status": "error", "code": "BAD_SESSION", "message": e}),
    };
    let wal = args.get("wal_path").and_then(|x| x.as_str()).map(str::to_string).or_else(|| st.wal_path.clone());
    let (mut sw, wal_rep) = match wal {
        None => (sw, Value::Null),
        Some(p) => {
            let path = Path::new(&p);
            let overwrite = args.get("wal_overwrite").and_then(|x| x.as_bool()).unwrap_or(false);
            if !overwrite && std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false) {
                return json!({"status": "error", "code": "WAL_EXISTS",
                              "message": format!("{p} already holds a session log (restart the server with --wal-path to resume it, or pass wal_overwrite)")});
            }
            // the session being replaced may hold this very log: release it first (a failed init leaves no session)
            if st.sw.as_ref().and_then(|o| o.journal()).is_some() {
                st.sw = None;
            }
            match journal::create(path, sw) {
                Ok(x) => x,
                Err(e) => return json!({"status": "error", "code": "WAL_OPEN_FAILED", "message": e}),
            }
        }
    };
    let mut rep = session_summary(&mut sw.session);
    rep["status"] = json!("SESSION_READY");
    rep["docs"] = json!(sw.session.arena.doc_ids().cloned().collect::<Vec<_>>());
    rep["config"] = sw.cfg.to_json();
    rep["wal"] = wal_rep;
    st.sw = Some(sw);
    rep
}

fn tool_op(name: &str) -> &str {
    match name {
        "sbgk_post_erratum" => "post_erratum",
        other => other.strip_prefix("sbgk_").unwrap_or(other),
    }
}

fn nonempty(v: &Value) -> bool {
    v.as_array().is_some_and(|a| !a.is_empty())
}

/// Whether the answer to `name` may have freed or created work for a waiting worker.
fn frees_work(name: &str, out: &Value) -> bool {
    match name {
        "sbgk_query_cone" | "sbgk_snapshot" | "sbgk_emit_batch" => false,
        "sbgk_acquire_directive" | "sbgk_swarm_status" | "sbgk_renew_lease" => nonempty(&out["expired"]) || nonempty(&out["auto_closed"]),
        _ => true,
    }
}

/// `sbgk_acquire_directive`, long-polling up to `max_wait_ms` while the answer is `WAIT_IN_FLIGHT`. The wait ends early when
/// another call signals a change, or when the earliest lease runs out (on the server clock; a caller's virtual `now_ms`
/// cannot expire anything while it waits).
fn acquire_waiting<'a>(server: &'a Server, mut st: MutexGuard<'a, State>, args: &Value) -> (MutexGuard<'a, State>, Value) {
    let max_wait = args.get("max_wait_ms").and_then(|x| x.as_u64()).unwrap_or(0).min(MAX_WAIT_CAP_MS);
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_millis(max_wait);
    let mut wakeups = 0u64;
    let mut wake_latency: Option<Duration> = None;
    loop {
        let Some(sw) = st.sw.as_mut() else { return (st, json!({"status": "error", "code": "NO_SESSION", "message": "the session is gone"})) };
        let mut out = sw.handle("acquire_directive", args).expect("acquire_directive is a swarm op");
        let now = Instant::now();
        if out["status"] != "WAIT_IN_FLIGHT" || now >= deadline {
            if max_wait > 0 {
                out["waited_ms"] = json!(now.duration_since(t0).as_secs_f64() * 1e3);
                out["wakeups"] = json!(wakeups);
                // signal -> this call running again, measured on the server: what a waiting worker gains over polling
                if let Some(d) = wake_latency {
                    out["wake_latency_us"] = json!(d.as_secs_f64() * 1e6);
                }
            }
            return (st, out);
        }
        let mut timeout = deadline - now;
        if args.get("now_ms").is_none() {
            if let Some(exp) = sw.next_expiry_ms() {
                timeout = timeout.min(Duration::from_millis(exp.saturating_sub(sw.now(None)).max(1)));
            }
        }
        let slept = Instant::now();
        st.long_polls += 1;
        st = server.changed.wait_timeout(st, timeout).unwrap_or_else(|p| p.into_inner()).0;
        st.long_polls -= 1;
        wakeups += 1;
        wake_latency = st.signalled_at.filter(|t| *t >= slept).map(|t| t.elapsed());
    }
}

fn call_tool(server: &Server, name: &str, args: &Value) -> Value {
    let t_wait = Instant::now();
    let mut st = server.lock();
    let wait_us = t_wait.elapsed().as_nanos() as f64 / 1e3;
    let t = Instant::now();
    let mut out = if name == "sbgk_init_session" {
        init_tool(&mut st, args)
    } else if st.sw.is_none() {
        json!({"status": "error", "code": "NO_SESSION", "message": "call sbgk_init_session first (or start the server with --ontology)"})
    } else if name == "sbgk_acquire_directive" {
        let (g, out) = acquire_waiting(server, st, args);
        st = g;
        out
    } else {
        let sw = st.sw.as_mut().expect("checked above");
        match name {
            "sbgk_snapshot" => {
                let mut rep = session_summary(&mut sw.session);
                rep["status"] = json!("SNAPSHOT");
                if let Some(path) = args.get("out").and_then(|x| x.as_str()) {
                    let bytes = build_container(&mut sw.session);
                    rep["container_bytes"] = json!(bytes.len());
                    if let Err(e) = std::fs::write(path, &bytes) {
                        // a bad path is the caller's mistake: answer it, keep serving the swarm
                        rep = json!({"status": "error", "code": "SNAPSHOT_WRITE_FAILED", "message": format!("cannot write {path}: {e}")});
                    }
                }
                if let Some(j) = sw.journal() {
                    rep["wal"] = j.to_json();
                }
                rep
            }
            _ => sw
                .handle(tool_op(name), args)
                .unwrap_or_else(|| json!({"status": "error", "code": "UNKNOWN_TOOL", "message": format!("unknown tool '{name}'")})),
        }
    };
    if name == "sbgk_swarm_status" && out.is_object() {
        out["long_polls_waiting"] = json!(st.long_polls);
    }
    if out["code"] == "WAL_WRITE_FAILED" && name != "sbgk_init_session" {
        // the mutation is in memory but not on disk: stop before anyone builds on an unrecorded state
        fail(&format!("session log: {}", out["message"].as_str().unwrap_or("write failed")));
    }
    if frees_work(name, &out) {
        st.signalled_at = Some(Instant::now());
        server.changed.notify_all();
    }
    drop(st);
    out["server_us"] = json!(t.elapsed().as_nanos() as f64 / 1e3);
    out["lock_wait_us"] = json!(wait_us);
    out
}

/// One-line text of a tool answer in compact mode, e.g. `status=DIRECTIVE lease_id=L3 kind=FORMALIZE target=svc_001`.
fn summary_line(v: &Value) -> String {
    let fields = [
        ("status", &v["status"]),
        ("code", &v["code"]),
        ("lease_id", &v["lease_id"]),
        ("kind", &v["frame"]["kind"]),
        ("target", &v["frame"]["target"]),
        ("accepted", &v["accepted_count"]),
        ("open_gaps", &v["open_gaps"]),
        ("complete", &v["complete"]),
        ("message", &v["message"]),
    ];
    let mut parts = Vec::new();
    for (k, x) in fields {
        match x {
            Value::Null => {}
            Value::String(s) => parts.push(format!("{k}={s}")),
            other => parts.push(format!("{k}={other}")),
        }
    }
    parts.join(" ")
}

/// Byte-wise equal, in time independent of where the strings differ.
pub(crate) fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A JSON-RPC request line as `(id, method, params)`: `Ok(None)` for a notification, `Err(answer)` for a malformed line.
pub(crate) fn request(line: &str) -> Result<Option<(Value, String, Value)>, Value> {
    let msg: Value =
        serde_json::from_str(line).map_err(|e| json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {e}")}}))?;
    let Some(obj) = msg.as_object() else {
        return Err(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "a request must be a JSON object (batches are not supported)"}}));
    };
    let method = obj.get("method").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let params = obj.get("params").cloned().unwrap_or(json!({}));
    // no id: a notification (notifications/initialized, notifications/cancelled, ...)
    Ok(obj.get("id").cloned().map(|id| (id, method, params)))
}

pub(crate) fn rpc_ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub(crate) fn rpc_error(id: &Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// The `auth_token` a request presents: in the `initialize` params, in `_meta` or in the tool arguments.
pub(crate) fn presented_token(params: &Value) -> Option<&str> {
    [params.get("auth_token"), params.get("_meta").and_then(|m| m.get("auth_token")), params.get("arguments").and_then(|a| a.get("auth_token"))]
        .into_iter()
        .flatten()
        .find_map(|x| x.as_str())
}

/// A tool answer as MCP content: the JSON as `structuredContent`, and as text (or the one-line summary with `compact`).
pub(crate) fn tool_result(args: &Value, out: Value, summary: fn(&Value) -> String) -> Value {
    let is_error = out["status"] == "error";
    let text = if args.get("compact").and_then(|x| x.as_bool()) == Some(true) { summary(&out) } else { out.to_string() };
    json!({"content": [{"type": "text", "text": text}], "structuredContent": out, "isError": is_error})
}

impl LineServer for Server {
    /// Whether a valid `auth_token` in `initialize` authenticated the connection.
    type Conn = bool;
    fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }
    fn handle(&self, authed: &mut bool, line: &str) -> (Option<Value>, bool) {
        handle_line(self, authed, line)
    }
    fn connection_admitted(&self, authed: &bool, line: &str) -> bool {
        let Some(token) = &self.token else { return true };
        *authed || request(line).ok().flatten().is_some_and(|(_, _, params)| presented_token(&params).is_some_and(|p| same_secret(p, token)))
    }
}

/// One JSON-RPC message -> its answer (None for notifications). The flag asks the transport to end the process.
/// `authed` is the connection's state: a valid `auth_token` in `initialize` authenticates every later request.
fn handle_line(server: &Server, authed: &mut bool, line: &str) -> (Option<Value>, bool) {
    let (id, method, params) = match request(line) {
        Ok(Some(r)) => r,
        Ok(None) => return (None, false),
        Err(answer) => return (Some(answer), false),
    };
    let method = method.as_str();
    let ok = |result: Value| rpc_ok(&id, result);
    let fail = |code: i64, message: String| rpc_error(&id, code, message);
    if let Some(token) = &server.token {
        match presented_token(&params) {
            Some(p) if same_secret(p, token) => *authed |= method == "initialize",
            Some(_) => return (Some(fail(UNAUTHORIZED, "Unauthorized: wrong auth_token".into())), false),
            None if *authed => {}
            None => {
                return (Some(fail(UNAUTHORIZED, "Unauthorized: this server needs auth_token (in initialize params, _meta or tool arguments)".into())), false);
            }
        }
    }
    match method {
        "initialize" => {
            let pv = params.get("protocolVersion").and_then(|x| x.as_str()).unwrap_or(PROTOCOL);
            (
                Some(ok(json!({"protocolVersion": pv, "capabilities": {"tools": {"listChanged": false}},
                            "serverInfo": {"name": "sbgk-mcp", "version": env!("CARGO_PKG_VERSION")},
                            "instructions": "SBGK swarm dispatcher: init a session, then acquire a directive, do exactly what its frame says, submit the events."}))),
                false,
            )
        }
        "ping" => (Some(ok(json!({}))), false),
        "tools/list" => (Some(ok(json!({"tools": tools()}))), false),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(|x| x.as_str()) else {
                return (Some(fail(-32602, "tools/call needs 'name'".into())), false);
            };
            if !tools().as_array().unwrap().iter().any(|t| t["name"] == name) {
                return (Some(fail(-32602, format!("unknown tool '{name}'"))), false);
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let out = call_tool(server, name, &args);
            (Some(ok(tool_result(&args, out, summary_line))), false)
        }
        "shutdown" => {
            server.changed.notify_all();
            (Some(ok(json!({}))), true)
        }
        other => (Some(fail(-32601, format!("method not found: {other}"))), false),
    }
}

/// Next message of `input` into `buf` (without its line end), reading at most `max + 1` bytes of it. `None` at the end of the
/// input; `Some(false)` when the message is longer than `max`: its remaining bytes are read and dropped, never buffered.
fn read_message(input: &mut impl BufRead, max: usize, buf: &mut Vec<u8>) -> std::io::Result<Option<bool>> {
    buf.clear();
    if input.by_ref().take(max as u64 + 1).read_until(b'\n', buf)? == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        return Ok(Some(true));
    }
    if buf.len() <= max {
        return Ok(Some(true)); // the last message, without a line end
    }
    buf.clear();
    let mut sink = Vec::new();
    loop {
        sink.clear();
        if input.by_ref().take(64 * 1024).read_until(b'\n', &mut sink)? == 0 || sink.last() == Some(&b'\n') {
            return Ok(Some(false));
        }
    }
}

/// A JSON-RPC server the line transport drives: stdio, or TCP with one thread per connection.
pub(crate) trait LineServer: Send + Sync + 'static {
    /// What one connection remembers between its messages (e.g. whom it authenticated as).
    type Conn: Default;
    fn max_message_bytes(&self) -> usize;
    /// TCP admission only: one absolute deadline until a complete request proves authentication. Servers without
    /// authentication admit the first complete message. A valid per-call token may admit a connection without caching identity.
    fn connection_admitted(&self, _conn: &Self::Conn, _line: &str) -> bool {
        true
    }
    fn admission_timeout(&self) -> Duration {
        TCP_ADMISSION_TIMEOUT
    }
    /// One message -> its answer (`None` for a notification); the flag ends the process once the answer is written.
    fn handle(&self, conn: &mut Self::Conn, line: &str) -> (Option<Value>, bool);
}

/// Serve one client over this process's stdin and stdout (`sbgk mcp`).
pub(crate) fn serve_stdio<S: LineServer>(server: &S) {
    serve_stream(server, std::io::stdin().lock(), std::io::stdout().lock());
}

fn serve_stream<S: LineServer>(server: &S, input: impl BufRead, out: impl Write) {
    serve_stream_with_admission(server, input, out, |_, _| true);
}

fn serve_stream_with_admission<S: LineServer>(server: &S, mut input: impl BufRead, mut out: impl Write, mut admit: impl FnMut(&S::Conn, &str) -> bool) {
    let mut conn = S::Conn::default();
    let mut buf = Vec::new();
    let max = server.max_message_bytes();
    loop {
        let resp = match read_message(&mut input, max, &mut buf) {
            Err(_) | Ok(None) => break,
            Ok(Some(false)) => Some((
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600,
                                "message": format!("Invalid Request (message too large: the limit is {max} bytes)")}}),
                false,
            )),
            Ok(Some(true)) => {
                let line = String::from_utf8_lossy(&buf);
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if !admit(&conn, line) {
                    break;
                }
                let (r, stop) = server.handle(&mut conn, line);
                r.map(|r| (r, stop))
            }
        };
        let Some((r, stop)) = resp else { continue };
        // one write per answer: a TCP_NODELAY socket would otherwise send every formatted piece as its own packet
        let mut text = r.to_string();
        text.push('\n');
        if out.write_all(text.as_bytes()).and_then(|_| out.flush()).is_err() {
            break;
        }
        if stop {
            std::process::exit(0);
        }
    }
}

/// Recompute the remaining absolute admission time before every socket read/write. A per-read timeout alone would let
/// clients retain a slot forever by sending one byte just before each timeout, including while an oversized line is drained.
struct AdmissionStream<'a> {
    stream: TcpStream,
    deadline: &'a Cell<Option<Instant>>,
}

impl AdmissionStream<'_> {
    fn remaining(&self) -> std::io::Result<Option<Duration>> {
        match self.deadline.get() {
            None => Ok(None),
            Some(deadline) => deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .map(Some)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP admission deadline expired")),
        }
    }
}

impl Read for AdmissionStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(self.remaining()?)?;
        self.stream.read(bytes)
    }
}

impl Write for AdmissionStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(self.remaining()?)?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.set_write_timeout(self.remaining()?)?;
        self.stream.flush()
    }
}

fn connection<S: LineServer>(server: Arc<S>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let Ok(rd) = stream.try_clone() else { return };
    let deadline = Cell::new(Some(Instant::now() + server.admission_timeout()));
    let input = BufReader::new(AdmissionStream { stream: rd, deadline: &deadline });
    let out = AdmissionStream { stream, deadline: &deadline };
    serve_stream_with_admission(&*server, input, out, |conn, line| {
        if deadline.get().is_some_and(|limit| Instant::now() >= limit) {
            return false;
        }
        if server.connection_admitted(conn, line) {
            deadline.set(None);
        }
        true
    });
}

/// Decrements the live-connection count when a connection thread ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Refuse a non-loopback listen address unless the operator opted in with `--allow-remote` and, where the server takes one, a
/// token (`needs`: what the message names, as the commands differ).
pub(crate) fn check_listen(addr: &str, allow_remote: bool, has_token: bool, needs: &str) {
    let addrs: Vec<_> = addr.to_socket_addrs().unwrap_or_else(|e| fail(&format!("cannot resolve --listen {addr}: {e}"))).collect();
    let remote: Vec<String> = addrs.iter().filter(|a| !a.ip().is_loopback()).map(|a| a.ip().to_string()).collect();
    if !remote.is_empty() && !(allow_remote && has_token) {
        fail(&format!("--listen {addr} is not a loopback address ({}): the server has no TLS, so exposing it needs {needs}", remote.join(", ")));
    }
}

pub fn cmd_mcp_serve(a: &Args) {
    let token = a.get("token").map(str::to_string);
    if token.as_deref() == Some("") {
        fail("--token must not be empty");
    }
    if let Some(addr) = a.get("listen") {
        check_listen(addr, a.sw("allow-remote"), token.is_some(), "both --allow-remote and --token <SECRET>");
    }
    let max_message_bytes: usize = a.num("max-message-bytes", DEFAULT_MAX_MESSAGE_BYTES).max(1);
    let max_connections: usize = a.num("max-connections", DEFAULT_MAX_CONNECTIONS).max(1);
    let mut st = State { wal_path: a.get("wal-path").map(str::to_string), ..State::default() };
    let has_session = a.get("ontology").is_some() || a.get("base").is_some();
    let fresh = || {
        let mut sw = SwarmSession::new(load_session(a));
        if a.get("targets").is_some() {
            let t: Targets = read_targets(a);
            sw.set_targets(t);
        }
        Ok(sw)
    };
    let mut wal_rep = Value::Null;
    match st.wal_path.clone() {
        // a log that holds records is resumed; otherwise a session given on the command line starts a new one
        Some(p) if has_session || std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false) => {
            let (sw, rep) = journal::open(Path::new(&p), fresh).unwrap_or_else(|e| fail(&format!("session log: {e}")));
            st.sw = Some(sw);
            wal_rep = rep;
        }
        Some(_) => {}
        None if has_session => st.sw = Some(fresh().unwrap_or_else(|e: String| fail(&e))),
        None => {}
    }
    let server = Arc::new(Server { state: Mutex::new(st), changed: Condvar::new(), token, max_message_bytes });
    let note = (!wal_rep.is_null()).then(|| json!({"status": "wal", "wal": wal_rep}));
    run(server, a.get("listen"), max_connections, note, json!({"wal": wal_rep}));
}

/// Serve on stdio (`note`, if any, goes to stderr first), or on TCP at `listen`: the first stdout line is
/// `{"status":"listening","addr":..,"port":..}` plus the fields of `hello`; then one thread per connection, at most
/// `max_connections` at a time (a connection over the cap gets one error line and is closed).
pub(crate) fn run<S: LineServer>(server: Arc<S>, listen: Option<&str>, max_connections: usize, note: Option<Value>, hello: Value) {
    run_bound(server, listen.map(bind), max_connections, note, hello)
}

/// The listening socket of `--listen`. A server that creates durable state binds it first, so a taken port leaves nothing behind.
pub(crate) fn bind(addr: &str) -> TcpListener {
    TcpListener::bind(addr).unwrap_or_else(|e| fail(&format!("cannot listen on {addr}: {e}")))
}

/// `run` on a socket already bound (`None`: stdio).
pub(crate) fn run_bound<S: LineServer>(server: Arc<S>, listener: Option<TcpListener>, max_connections: usize, note: Option<Value>, hello: Value) {
    let Some(listener) = listener else {
        if let Some(n) = note {
            eprintln!("{n}");
        }
        return serve_stream(&*server, std::io::stdin().lock(), std::io::stdout().lock());
    };
    let local = listener.local_addr().expect("bound socket has an address");
    let mut first = json!({"status": "listening", "addr": local.to_string(), "port": local.port()});
    if let (Some(f), Some(h)) = (first.as_object_mut(), hello.as_object()) {
        f.extend(h.clone());
    }
    println!("{first}");
    let _ = std::io::stdout().flush();
    let live = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if live.fetch_add(1, Ordering::SeqCst) >= max_connections {
            live.fetch_sub(1, Ordering::SeqCst);
            let msg =
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32000, "message": format!("too many connections (the limit is {max_connections})")}});
            let _ = stream.write_all(format!("{msg}\n").as_bytes());
            continue;
        }
        let slot = Slot(Arc::clone(&live));
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            let _slot = slot;
            connection(server, stream)
        });
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::net::Shutdown;
    use std::sync::mpsc::{self, Receiver};

    const TEST_TIMEOUT: Duration = Duration::from_millis(500);

    struct TestServer {
        max: usize,
    }

    impl LineServer for TestServer {
        type Conn = bool;
        fn max_message_bytes(&self) -> usize {
            self.max
        }
        fn admission_timeout(&self) -> Duration {
            TEST_TIMEOUT
        }
        fn connection_admitted(&self, admitted: &bool, line: &str) -> bool {
            *admitted || line == "auth"
        }
        fn handle(&self, admitted: &mut bool, line: &str) -> (Option<Value>, bool) {
            *admitted |= line == "auth";
            (Some(json!({"admitted": admitted})), false)
        }
    }

    struct Client {
        write: TcpStream,
        read: BufReader<TcpStream>,
        ended: Receiver<()>,
        live: Arc<AtomicUsize>,
    }

    impl Client {
        fn connect(max: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let write = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            write.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            write.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            let (stream, _) = listener.accept().unwrap();
            let read = BufReader::new(write.try_clone().unwrap());
            let live = Arc::new(AtomicUsize::new(1));
            let slot = Slot(Arc::clone(&live));
            let (tx, ended) = mpsc::channel();
            std::thread::spawn(move || {
                connection(Arc::new(TestServer { max }), stream);
                drop(slot);
                let _ = tx.send(());
            });
            Self { write, read, ended, live }
        }

        fn line(&mut self, line: &str) -> Value {
            writeln!(self.write, "{line}").unwrap();
            let mut answer = String::new();
            self.read.read_line(&mut answer).unwrap();
            serde_json::from_str(&answer).unwrap()
        }

        fn assert_closed(&self) {
            self.ended.recv_timeout(Duration::from_secs(2)).expect("unauthenticated connection retained its slot");
            assert_eq!(self.live.load(Ordering::SeqCst), 0);
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            let _ = self.write.shutdown(Shutdown::Both);
        }
    }

    #[test]
    fn idle_connection_releases_its_admission_slot() {
        Client::connect(512).assert_closed();
    }

    #[test]
    fn partial_and_oversized_lines_cannot_renew_the_admission_deadline() {
        for (max, first) in [(512, b"{".as_slice()), (8, b"xxxxxxxxx".as_slice())] {
            let mut client = Client::connect(max);
            client.write.write_all(first).unwrap();
            let started = Instant::now();
            loop {
                if client.ended.try_recv().is_ok() {
                    assert_eq!(client.live.load(Ordering::SeqCst), 0);
                    break;
                }
                assert!(started.elapsed() < Duration::from_secs(2), "partial bytes renewed the deadline with max={max}");
                let _ = client.write.write_all(b"x");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[test]
    fn complete_unauthenticated_messages_cannot_renew_the_deadline() {
        let mut client = Client::connect(512);
        assert_eq!(client.line("ping")["admitted"], false);
        std::thread::sleep(TEST_TIMEOUT + Duration::from_millis(100));
        client.assert_closed();
    }

    #[test]
    fn authenticated_connection_outlives_the_admission_deadline() {
        let mut client = Client::connect(512);
        assert_eq!(client.line("auth")["admitted"], true);
        std::thread::sleep(TEST_TIMEOUT + Duration::from_millis(100));
        assert_eq!(client.line("ping")["admitted"], true);
        assert_eq!(client.live.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn per_call_token_admits_transport_without_caching_identity() {
        let server = Server { state: Mutex::new(State::default()), changed: Condvar::new(), token: Some("secret".into()), max_message_bytes: 512 };
        let line = json!({"jsonrpc":"2.0", "id":1, "method":"ping", "params":{"_meta":{"auth_token":"secret"}}}).to_string();
        let mut authed = false;
        assert!(server.connection_admitted(&authed, &line));
        assert_eq!(server.handle(&mut authed, &line).0.unwrap()["result"], json!({}));
        assert!(!authed, "only initialize caches the subject, even after transport admission");
        let anonymous = json!({"jsonrpc":"2.0", "id":2, "method":"ping", "params":{}}).to_string();
        assert!(!server.connection_admitted(&authed, &anonymous));
        assert_eq!(server.handle(&mut authed, &anonymous).0.unwrap()["error"]["code"], UNAUTHORIZED);
    }
}
