//! `sbgk mcp-serve` over JSON-RPC 2.0 (TCP, one connection per worker, and stdio): parallel leases from concurrent
//! connections, the shared-premise lock on a fan-in clause, kernel auto-closure of P2A, TTL expiry with takeover and a
//! refused zombie, the directive scope guard in Rust, and a lease made stale by an erratum published on the fly. Stage B:
//! crash recovery from the session log (`--wal-path`), long polling (`max_wait_ms`), the TCP guards (loopback by default,
//! `--token`, `--max-message-bytes`, `--max-connections`) and compact answers.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

struct Server {
    child: Child,
    port: u16,
    /// The first stdout line (`listening`, with the session-log report).
    hello: Value,
}

impl Server {
    fn start() -> Server {
        Server::start_with(&[])
    }

    fn start_with(extra: &[&str]) -> Server {
        let mut child =
            Command::new(BIN).args(["mcp-serve", "--listen", "127.0.0.1:0"]).args(extra).stdout(Stdio::piped()).spawn().expect("start sbgk mcp-serve");
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
        let v: Value = serde_json::from_str(&first).expect("first stdout line is the listening address");
        assert_eq!(v["status"], "listening");
        Server { port: v["port"].as_u64().unwrap() as u16, child, hello: v }
    }

    /// Abrupt end: the process is killed, nothing is flushed or snapshotted.
    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
    id: u64,
}

impl Client {
    /// A connection that has not sent `initialize`.
    fn raw(port: u16) -> Client {
        let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        Client { w, r, id: 0 }
    }

    fn connect(port: u16) -> Client {
        let mut c = Client::raw(port);
        let init = c.rpc("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}));
        assert_eq!(init["result"]["serverInfo"]["name"], "sbgk-mcp");
        c.notify("notifications/initialized");
        c
    }

    fn notify(&mut self, method: &str) {
        writeln!(self.w, "{}", json!({"jsonrpc": "2.0", "method": method})).unwrap();
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        writeln!(self.w, "{}", json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})).unwrap();
        self.w.flush().unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], json!(self.id), "answers come in request order");
        v
    }

    fn tool(&mut self, name: &str, args: Value) -> Value {
        let v = self.rpc("tools/call", json!({"name": name, "arguments": args}));
        let r = &v["result"];
        let text: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["status"], r["structuredContent"]["status"]);
        r["structuredContent"].clone()
    }
}

// ------------------------------------------------------------------ fixture: 6 services, 4 of them on one deprecated interface

fn u(k: usize, a: usize) -> String {
    format!("Clause U.{k}: service svc_{k:03} shall call interface api_{a:03} in production from t=100 until t=200.")
}

fn d(a: usize) -> String {
    format!("Clause D.{a}: interface api_{a:03} is deprecated in production from t=150 until t=300.")
}

const R0: &str = "Clause R.0: from t=150 until t=300, production use of interface api_000 is deprecated (this restates clause D.0).";
const ERRATUM: &str = "Erratum E.1: clause D.0 is withdrawn; the same statement stands in clause R.0.\n";
const API_OF: [usize; 6] = [0, 0, 0, 0, 1, 1];

fn init_args(auto: bool) -> Value {
    let mut ents = Vec::new();
    for k in 0..6 {
        ents.push(json!({"id": format!("svc_{k:03}"), "type": "Service", "aliases": [format!("service {k}")]}));
    }
    for a in 0..2 {
        ents.push(json!({"id": format!("api_{a:03}"), "type": "Api", "aliases": [format!("interface {a}")]}));
    }
    let onto = json!({
        "entities": ents,
        "predicates": [{"id": "uses_api", "subject": "Service", "object": "Api"}, {"id": "api_deprecated", "subject": "Api", "object": "@literal"},
                       {"id": "needs_review", "subject": "Service", "object": "@literal"}],
        "rules": [{"id": "R_depr_review@1", "mode": "AND", "body": [{"p": "uses_api"}, {"p": "api_deprecated"}], "join": [["0.o", "1.s"]],
                   "head": {"s": "0.s", "p": "needs_review", "o": {"const": "true"}}}]
    });
    let mut doc = String::from("The operator shall archive the access logs within 3 business days. ");
    for (k, &a) in API_OF.iter().enumerate() {
        doc.push_str(&u(k, a));
        doc.push_str(if k % 2 == 1 { "\n\n" } else { " " });
    }
    doc.push_str(&format!("{} {R0} {}\n", d(0), d(1)));
    let goals: Vec<Value> = (0..6).map(|k| json!({"entity": format!("svc_{k:03}"), "predicate": "needs_review"})).collect();
    json!({"ontology": onto, "docs": {"policy": doc}, "targets": {"goals": goals, "docs": ["policy"]}, "auto_close_p2a": auto, "lock_mode": "shared_premise"})
}

fn facts() -> HashMap<String, (String, String, String)> {
    let mut m = HashMap::new();
    for (k, &a) in API_OF.iter().enumerate() {
        m.insert(u(k, a), (format!("svc_{k:03}"), "uses_api".to_string(), format!("api_{a:03}")));
    }
    for a in 0..2 {
        m.insert(d(a), (format!("api_{a:03}"), "api_deprecated".to_string(), "true".to_string()));
    }
    m.insert(R0.to_string(), ("api_000".into(), "api_deprecated".into(), "true".into()));
    m
}

/// The events a perfect worker writes for a frame.
fn oracle(frame: &Value) -> Vec<Value> {
    let tab = facts();
    let pre = frame["local_id_prefix"].as_str().unwrap();
    let mut out = Vec::new();
    for (n, g) in frame["gaps"].as_array().unwrap().iter().enumerate() {
        match g["kind"].as_str().unwrap() {
            "EMIT_DERIVE_ONLY" => {
                out.push(json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": g["derive"]["rule"], "premises": g["derive"]["premises"]}))
            }
            "REVOKE_WITHDRAWN" | "RESOLVE_CONFLICT" => {
                for e in g["evidence"].as_array().unwrap() {
                    out.push(json!({"op": "revoke_evidence", "target_evidence": e}));
                }
            }
            _ => {
                let mut first = None;
                for (i, t) in g["segment_texts"].as_array().unwrap().iter().enumerate() {
                    let Some((s, p, o)) = tab.get(t.as_str().unwrap()) else { continue };
                    let tt = if p == "uses_api" { [100, 200] } else { [150, 300] };
                    out.push(json!({"op": "bind_evidence", "local_id": format!("{pre}e{n}_{i}"), "doc_id": "policy", "exact_quote": t}));
                    out.push(json!({"op": "assert_fact", "local_id": format!("{pre}f{n}_{i}"), "s": s, "p": p, "o": o, "polarity": "POS", "ctx": "prod",
                                    "t": tt, "evidence": [format!("{pre}e{n}_{i}")]}));
                    first.get_or_insert(format!("{pre}f{n}_{i}"));
                }
                if let (Some(f), Some(p)) = (first, g["partner"].as_object()) {
                    out.push(json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": p["rule"], "premises": [f, p["id"].clone()]}));
                }
            }
        }
    }
    out.truncate(frame["max_events"].as_u64().unwrap() as usize);
    out
}

fn segs(r: &Value) -> Vec<String> {
    r["frame"]["chunk_slice"].as_array().unwrap().iter().filter(|c| c["amendment"] == false).map(|c| c["segment_id"].as_str().unwrap().to_string()).collect()
}

/// `n` workers acquire at the same time, each on its own connection.
fn wave(port: u16, n: usize, now: u64) -> Vec<Value> {
    std::thread::scope(|sc| {
        let hs: Vec<_> = (0..n)
            .map(|i| {
                sc.spawn(move || {
                    Client::connect(port).tool("sbgk_acquire_directive", json!({"agent_id": format!("w{i}"), "ttl_ms": 60_000, "k": 4, "now_ms": now}))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn assert_disjoint(leases: &[&Value]) {
    let mut tg = HashSet::new();
    let mut sg = HashSet::new();
    let mut px = HashSet::new();
    for r in leases {
        for t in r["frame"]["targets"].as_array().unwrap() {
            assert!(tg.insert(t.as_str().unwrap().to_string()), "two leases share target {t}");
        }
        for s in segs(r) {
            assert!(sg.insert(s.clone()), "two leases share sentence {s}");
        }
        assert!(px.insert(r["local_id_prefix"].as_str().unwrap().to_string()));
    }
}

#[test]
fn concurrent_workers_get_disjoint_leases_and_the_kernel_closes_p2a() {
    let srv = Server::start();
    let mut c = Client::connect(srv.port);
    let names: Vec<String> =
        c.rpc("tools/list", json!({}))["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    for t in ["sbgk_init_session", "sbgk_acquire_directive", "sbgk_submit_directive", "sbgk_post_erratum", "sbgk_query_cone", "sbgk_swarm_status"] {
        assert!(names.iter().any(|n| n == t), "missing tool {t}");
    }
    assert_eq!(c.rpc("no/such/method", json!({}))["error"]["code"], -32601);
    assert_eq!(c.tool("sbgk_init_session", init_args(true))["status"], "SESSION_READY");

    // wave 1: six workers at once -> six FORMALIZE leases, pairwise disjoint
    let w1 = wave(srv.port, 6, 0);
    assert!(w1.iter().all(|r| r["status"] == "DIRECTIVE" && r["frame"]["kind"] == "FORMALIZE"), "{w1:?}");
    assert_disjoint(&w1.iter().collect::<Vec<_>>());
    for r in &w1 {
        let s = c.tool("sbgk_submit_directive", json!({"lease_id": r["lease_id"], "agent_id": r["agent_id"], "events": oracle(&r["frame"]), "now_ms": 10}));
        assert_eq!(s["status"], "COMMITTED", "{s}");
    }
    // wave 2: every service waits for its deprecation clause; each shared clause goes to exactly ONE worker
    let w2 = wave(srv.port, 6, 20);
    let got: Vec<&Value> = w2.iter().filter(|r| r["status"] == "DIRECTIVE").collect();
    assert_eq!(got.len(), 2, "one EXTRACT_PARTNER per interface: {w2:?}");
    assert!(got.iter().all(|r| r["frame"]["kind"] == "EXTRACT_PARTNER"));
    assert_eq!(w2.iter().filter(|r| r["status"] == "WAIT_IN_FLIGHT").count(), 4);
    assert_disjoint(&got);
    let mut closed = 0;
    for r in &got {
        let s = c.tool("sbgk_submit_directive", json!({"lease_id": r["lease_id"], "agent_id": r["agent_id"], "events": oracle(&r["frame"]), "now_ms": 30}));
        assert_eq!(s["status"], "COMMITTED");
        closed += s["auto_closed_derivations"].as_array().unwrap().len();
    }
    assert_eq!(closed, 4, "the kernel derives needs_review for the other dependents of both clauses");
    let done = c.tool("sbgk_acquire_directive", json!({"agent_id": "w0", "now_ms": 40}));
    assert_eq!(done["status"], "COMPLETE", "{done}");
    let st = c.tool("sbgk_swarm_status", json!({"now_ms": 40}));
    assert_eq!(st["goal_states"]["CLOSED_POSITIVE"], 6);
    assert_eq!(st["stats"]["auto_closed_total"], 4);
    assert!(st["stats"]["issued_by_kind"].get("EMIT_DERIVE_ONLY").is_none(), "no worker was called for a derive");
    let cone = c.tool("sbgk_query_cone", json!({"target_entity": "svc_002"}));
    assert!(cone["claims"].as_array().unwrap().iter().any(|x| x["p"] == "needs_review" && x["status"] == "SUPPORTED"));
}

#[test]
fn ttl_scope_guard_and_erratum_make_leases_stale() {
    let srv = Server::start();
    let mut c = Client::connect(srv.port);
    assert_eq!(c.tool("sbgk_init_session", init_args(false))["status"], "SESSION_READY");
    let acq =
        |c: &mut Client, agent: &str, ttl: u64, now: u64| c.tool("sbgk_acquire_directive", json!({"agent_id": agent, "ttl_ms": ttl, "k": 4, "now_ms": now}));
    let sub = |c: &mut Client, r: &Value, ev: Vec<Value>, now: u64| {
        c.tool("sbgk_submit_directive", json!({"lease_id": r["lease_id"], "agent_id": r["agent_id"], "events": ev, "now_ms": now}))
    };

    // TTL: the lease of a hung worker expires, another worker takes the same target, the late answer is refused
    let hung = acq(&mut c, "hung", 1000, 0);
    assert_eq!(hung["frame"]["target"], "svc_000");
    let take = acq(&mut c, "w1", 60_000, 1000);
    assert_eq!((take["frame"]["target"].as_str(), take["takeover"].as_bool()), (Some("svc_000"), Some(true)));
    let z = sub(&mut c, &hung, oracle(&hung["frame"]), 1100);
    assert_eq!((z["status"].as_str(), z["code"].as_str()), (Some("STALE_LEASE"), Some("LEASE_EXPIRED_OR_UNKNOWN")));
    // scope guard: a quote from another clause, then a revocation the directive does not list
    let ev = oracle(&take["frame"]);
    let foreign = json!({"op": "bind_evidence", "local_id": "x1", "doc_id": "policy", "exact_quote": u(1, 0)});
    let r1 = sub(&mut c, &take, vec![ev[0].clone(), foreign], 1200);
    assert_eq!(
        (r1["status"].as_str(), r1["error"]["code"].as_str(), r1["accepted_count"].as_u64()),
        (Some("REPAIR_REQUIRED"), Some("DIRECTIVE_VIOLATION"), Some(1))
    );
    let r2 = sub(&mut c, &take, ev[1..].to_vec(), 1300);
    assert_eq!(r2["status"], "COMMITTED", "the repair finishes the lease: {r2}");
    let x = acq(&mut c, "w1", 60_000, 1400);
    assert_eq!(x["frame"]["kind"], "EXTRACT_PARTNER");
    let rv = sub(&mut c, &x, vec![json!({"op": "revoke_evidence", "target_evidence": format!("@{}", r1["results"][0]["node"].as_str().unwrap())})], 1500);
    assert_eq!(rv["error"]["code"], "DIRECTIVE_VIOLATION", "an EXTRACT_PARTNER directive does not allow revocations");
    assert_eq!(sub(&mut c, &x, oracle(&x["frame"]), 1600)["status"], "COMMITTED");
    // a FORMALIZE of svc_001 built on the D.0 fact; the erratum withdraws D.0 and the revocation lands before the answer
    let p = acq(&mut c, "w2", 60_000, 1700);
    assert_eq!((p["frame"]["target"].as_str(), p["frame"]["kind"].as_str()), (Some("svc_001"), Some("FORMALIZE")));
    assert_eq!(p["contract"]["required_premises"].as_array().unwrap().len(), 1);
    let put = c.tool("sbgk_post_erratum", json!({"doc_id": "erratum", "erratum_text": ERRATUM, "now_ms": 1800}));
    assert_eq!(put["visible_docs"], json!(["erratum", "policy"]));
    let rw = acq(&mut c, "w3", 60_000, 1900);
    assert_eq!(rw["frame"]["kind"], "REVOKE_WITHDRAWN");
    let revoke: Vec<Value> = oracle(&rw["frame"]).into_iter().filter(|e| e["op"] == "revoke_evidence").collect();
    assert_eq!(sub(&mut c, &rw, revoke, 2000)["status"], "COMMITTED");
    let s = sub(&mut c, &p, oracle(&p["frame"]), 2100);
    assert_eq!((s["status"].as_str(), s["code"].as_str()), (Some("STALE_LEASE"), Some("STALE_LEASE_PREMISE_REVOKED")), "{s}");
    let st = c.tool("sbgk_swarm_status", json!({"now_ms": 2200}));
    let stats = &st["stats"];
    assert_eq!((stats["leases_expired"].as_u64(), stats["ttl_takeovers"].as_u64(), stats["stale_unknown"].as_u64()), (Some(1), Some(1), Some(1)));
    assert_eq!((stats["stale_premise"].as_u64(), stats["directive_violations"].as_u64()), (Some(1), Some(2)));
}

#[test]
fn stdio_transport_speaks_the_same_protocol() {
    let mut child = Command::new(BIN).args(["mcp-serve"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut w = child.stdin.take().unwrap();
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |msg: Value| -> Option<Value> {
        writeln!(w, "{msg}").unwrap();
        w.flush().unwrap();
        msg.get("id")?;
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        Some(serde_json::from_str(&line).unwrap())
    };
    let init = ask(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(ask(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none());
    let no = ask(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "sbgk_swarm_status", "arguments": {}}})).unwrap();
    assert_eq!(no["result"]["isError"], true, "no session yet");
    let ok = ask(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "sbgk_init_session", "arguments": init_args(true)}})).unwrap();
    assert_eq!(ok["result"]["structuredContent"]["status"], "SESSION_READY");
    let l = ask(
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "sbgk_acquire_directive", "arguments": {"agent_id": "a", "now_ms": 0}}}),
    )
    .unwrap();
    assert_eq!(l["result"]["structuredContent"]["lease_id"], "L1");
    assert_eq!(ask(json!({"jsonrpc": "2.0", "id": 5, "method": "shutdown"})).unwrap()["result"], json!({}));
    assert!(child.wait().unwrap().success());
}

// ------------------------------------------------------------------ Stage B

fn temp_path(tag: &str) -> PathBuf {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    std::env::temp_dir().join(format!("sbgk_{tag}_{}_{nanos}.jsonl", std::process::id()))
}

/// One sequential worker step: acquire, then submit what the frame asks. None once the swarm is complete.
fn step(c: &mut Client, now: u64) -> Option<Value> {
    let r = c.tool("sbgk_acquire_directive", json!({"agent_id": "w", "ttl_ms": 600_000, "k": 4, "now_ms": now}));
    match r["status"].as_str().unwrap() {
        "COMPLETE" => None,
        "DIRECTIVE" => {
            Some(c.tool("sbgk_submit_directive", json!({"lease_id": r["lease_id"], "agent_id": "w", "events": oracle(&r["frame"]), "now_ms": now + 1})))
        }
        other => panic!("{other}: {r}"),
    }
}

/// The first half of the run: two leases, then a lease that is in flight while the erratum is published.
fn first_half(c: &mut Client) {
    for now in [10, 20] {
        assert_eq!(step(c, now).unwrap()["status"], "COMMITTED");
    }
    let x = c.tool("sbgk_acquire_directive", json!({"agent_id": "w", "ttl_ms": 600_000, "k": 4, "now_ms": 30}));
    assert_eq!(x["status"], "DIRECTIVE");
    assert_eq!(c.tool("sbgk_post_erratum", json!({"doc_id": "erratum", "erratum_text": ERRATUM, "now_ms": 31}))["status"], "DOCUMENT_PUT");
    let s = c.tool("sbgk_submit_directive", json!({"lease_id": x["lease_id"], "agent_id": "w", "events": oracle(&x["frame"]), "now_ms": 32}));
    assert!(s["status"] == "COMMITTED" || s["status"] == "STALE_LEASE", "{s}");
}

/// The rest of the run, to completion; returns the final summary.
fn second_half(c: &mut Client) -> Value {
    let mut now = 100;
    while step(c, now).is_some() {
        now += 10;
        assert!(now < 10_000, "no completion");
    }
    c.tool("sbgk_snapshot", json!({}))
}

#[test]
fn wal_crash_recovery_matches_an_uninterrupted_run() {
    // reference: the whole run on one server, no log
    let reference = {
        let srv = Server::start();
        let mut c = Client::connect(srv.port);
        assert_eq!(c.tool("sbgk_init_session", init_args(true))["status"], "SESSION_READY");
        first_half(&mut c);
        second_half(&mut c)
    };
    assert!(reference["claims"]["supported"].as_u64().unwrap() > 6, "{reference}");

    let wal = temp_path("wal");
    let wal_s = wal.to_str().unwrap().to_string();
    let srv = Server::start_with(&["--wal-path", &wal_s]);
    let mut c = Client::connect(srv.port);
    let init = c.tool("sbgk_init_session", init_args(true));
    assert_eq!((init["status"].as_str(), init["wal"]["recovered"].as_bool()), (Some("SESSION_READY"), Some(false)), "{init}");
    first_half(&mut c);
    // a lease in flight at the moment of the crash: it is not persisted, its work is issued again after the restart
    let lost = c.tool("sbgk_acquire_directive", json!({"agent_id": "w", "ttl_ms": 600_000, "k": 4, "now_ms": 40}));
    assert_eq!(lost["status"], "DIRECTIVE");
    let before = c.tool("sbgk_swarm_status", json!({"now_ms": 41}));
    drop(c);
    srv.kill();
    // a torn record: the process died inside a write
    std::fs::OpenOptions::new().append(true).open(&wal).unwrap().write_all(br#"{"wal_op":"event","line":"{\"seq\":9"#).unwrap();
    let srv2 = Server::start_with(&["--wal-path", &wal_s]);
    let w = &srv2.hello["wal"];
    assert_eq!(w["recovered"], true, "{w}");
    assert!(w["torn_bytes_dropped"].as_u64().unwrap() > 0 && w["replayed_events"].as_u64().unwrap() > 0, "{w}");
    assert_eq!(w["state_root"], before["state_root"], "the log reproduces the state of the crash moment");
    assert!(w["lease_seq"].as_u64().unwrap() >= lost["lease_id"].as_str().unwrap()[1..].parse::<u64>().unwrap());
    let mut c = Client::connect(srv2.port);
    // a second session on the same log is refused: the restarted server resumes it
    let again = c.tool("sbgk_init_session", init_args(true));
    assert_eq!(again["code"], "WAL_EXISTS", "{again}");
    let st = c.tool("sbgk_swarm_status", json!({"now_ms": 50}));
    assert_eq!(st["leases"], json!([]), "no lease survives a restart");
    let fin = second_half(&mut c);
    for k in ["state_root", "nodes", "kinds", "claims"] {
        assert_eq!(fin[k], reference[k], "{k}: recovered run vs uninterrupted run");
    }
    srv2.kill();
    // the finished log replays to the final state on its own
    let srv3 = Server::start_with(&["--wal-path", &wal_s]);
    assert_eq!(srv3.hello["wal"]["state_root"], reference["state_root"]);
    srv3.kill();
    let _ = std::fs::remove_file(&wal);
}

#[test]
fn long_poll_wakes_on_the_commit_that_frees_the_premise() {
    let srv = Server::start();
    let mut c = Client::connect(srv.port);
    let mut args = init_args(true);
    args["targets"]["goals"] = json!([{"entity": "svc_000", "predicate": "needs_review"}]);
    assert_eq!(c.tool("sbgk_init_session", args)["status"], "SESSION_READY");
    let acq = |c: &mut Client, agent: &str, wait: u64| c.tool("sbgk_acquire_directive", json!({"agent_id": agent, "ttl_ms": 60_000, "max_wait_ms": wait}));
    let f = acq(&mut c, "w1", 0);
    assert_eq!(f["frame"]["kind"], "FORMALIZE");
    assert_eq!(c.tool("sbgk_submit_directive", json!({"lease_id": f["lease_id"], "events": oracle(&f["frame"])}))["status"], "COMMITTED");
    // worker 1 holds the shared premise (clause D.0); without max_wait_ms worker 2 is told to wait at once
    let x = acq(&mut c, "w1", 0);
    assert_eq!(x["frame"]["kind"], "EXTRACT_PARTNER");
    assert_eq!(acq(&mut c, "w2", 0)["status"], "WAIT_IN_FLIGHT");
    let port = srv.port;
    let waiter = std::thread::spawn(move || {
        let mut c2 = Client::connect(port);
        let r = c2.tool("sbgk_acquire_directive", json!({"agent_id": "w2", "ttl_ms": 60_000, "max_wait_ms": 5000}));
        (r, Instant::now())
    });
    // commit only once worker 2's call is blocked on the server (a fixed 50 ms sleep raced a loaded machine)
    let blocked = Instant::now();
    while c.tool("sbgk_swarm_status", json!({}))["long_polls_waiting"] != 1 {
        assert!(blocked.elapsed() < Duration::from_secs(5), "worker 2 never blocked on the server");
        std::thread::sleep(Duration::from_millis(5));
    }
    let s = c.tool("sbgk_submit_directive", json!({"lease_id": x["lease_id"], "events": oracle(&x["frame"])}));
    let committed = Instant::now();
    assert_eq!(s["status"], "COMMITTED");
    let (r, woke) = waiter.join().unwrap();
    assert_eq!(r["status"], "COMPLETE", "the commit lets the kernel close the target: {r}");
    // the wake-up is measured on the server (signal of the commit -> the waiting call running again); the client clocks only
    // bound it loosely, since a loaded test machine can delay the client threads on their own
    let latency_ms = r["wake_latency_us"].as_f64().unwrap_or_else(|| panic!("woken by a signal: {r}")) / 1e3;
    assert!(latency_ms < 20.0, "woken {latency_ms:.2} ms after the commit's signal");
    let gap = if woke > committed { woke - committed } else { committed - woke };
    assert!(gap < Duration::from_millis(1000), "the client saw the answer {gap:?} away from the commit");
    // it blocked and a signal ended the wait (how long it waited depends on when its own connection got going)
    assert!(r["waited_ms"].as_f64().unwrap() > 0.0 && (1..=2).contains(&r["wakeups"].as_u64().unwrap()), "no polling: {r}");
}

#[test]
fn a_flag_followed_by_another_flag_is_refused_not_taken_as_its_value() {
    // an unknown switch took the next flag as its value and both were dropped in silence
    let out = Command::new(BIN).args(["mcp-serve", "--no-such-switch", "--listen", "127.0.0.1:0"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--no-such-switch needs a value, not the flag --listen"), "{out:?}");
}

#[test]
fn tcp_guards_refuse_remote_listen_unknown_callers_and_oversized_frames() {
    // non-loopback without both --allow-remote and --token: refused before anything is bound
    for extra in [vec![], vec!["--allow-remote"], vec!["--token", "s3cret"]] {
        let out = Command::new(BIN).args(["mcp-serve", "--listen", "0.0.0.0:0"]).args(&extra).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{extra:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-remote"), "{extra:?}");
    }
    // --token
    let srv = Server::start_with(&["--token", "s3cret", "--max-message-bytes", "1024", "--max-connections", "3"]);
    let mut anon = Client::raw(srv.port);
    assert_eq!(anon.rpc("initialize", json!({"protocolVersion": "2025-06-18"}))["error"]["code"], -32001);
    assert_eq!(anon.rpc("tools/list", json!({}))["error"]["code"], -32001);
    assert_eq!(anon.rpc("initialize", json!({"auth_token": "s3cret!"}))["error"]["code"], -32001, "wrong token");
    let ok = anon.rpc("initialize", json!({"protocolVersion": "2025-06-18", "auth_token": "s3cret"}));
    assert_eq!(ok["result"]["serverInfo"]["name"], "sbgk-mcp");
    assert!(anon.rpc("tools/list", json!({}))["result"]["tools"].is_array(), "the connection is authenticated");
    let mut per_call = Client::raw(srv.port);
    assert_eq!(per_call.rpc("ping", json!({"_meta": {"auth_token": "s3cret"}}))["result"], json!({}));
    let st = per_call.rpc("tools/call", json!({"name": "sbgk_swarm_status", "arguments": {"auth_token": "s3cret"}}));
    assert_eq!(st["result"]["structuredContent"]["code"], "NO_SESSION");
    assert_eq!(per_call.rpc("ping", json!({}))["error"]["code"], -32001, "a per-call token does not authenticate the connection");
    // --max-message-bytes: the long line is refused without being buffered, the connection goes on
    let big = format!("{{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}", "x".repeat(200_000));
    writeln!(anon.w, "{big}").unwrap();
    let mut line = String::new();
    anon.r.read_line(&mut line).unwrap();
    let e: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(e["error"]["code"], -32600, "{e}");
    assert!(e["error"]["message"].as_str().unwrap().contains("too large"));
    assert_eq!(anon.rpc("ping", json!({}))["result"], json!({}));
    // --max-connections 3: two are open, the third is accepted, the fourth gets one error line and is closed
    let _third = Client::raw(srv.port);
    std::thread::sleep(Duration::from_millis(100));
    let mut fourth = Client::raw(srv.port);
    let mut rest = String::new();
    fourth.r.read_to_string(&mut rest).unwrap();
    let e: Value = serde_json::from_str(rest.trim()).unwrap();
    assert_eq!(e["error"]["code"], -32000, "{e}");
    // a closed connection frees its slot: the server notices the close asynchronously, so retry until it has (no fixed sleep,
    // which under a loaded parallel test run can be too short and make the next connection hit the cap)
    drop(per_call);
    let t0 = Instant::now();
    loop {
        if let Some(r) = try_ping(srv.port, "s3cret") {
            if r.get("result") == Some(&json!({})) {
                break;
            }
            assert_eq!(r["error"]["code"], -32000, "{r}");
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "the slot of a closed connection was never freed");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One ping on a fresh connection: the answer, or None when the server closed the connection first.
fn try_ping(port: u16, token: &str) -> Option<Value> {
    let mut w = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let mut r = BufReader::new(w.try_clone().ok()?);
    writeln!(w, "{}", json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"auth_token": token}})).ok()?;
    let mut line = String::new();
    r.read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

#[test]
fn compact_answers_keep_the_structure_and_shrink_the_text() {
    let srv = Server::start();
    let mut c = Client::connect(srv.port);
    assert_eq!(c.tool("sbgk_init_session", init_args(true))["status"], "SESSION_READY");
    let call = |c: &mut Client, name: &str, args: Value| c.rpc("tools/call", json!({"name": name, "arguments": args}))["result"].clone();
    let full = call(&mut c, "sbgk_acquire_directive", json!({"agent_id": "a", "now_ms": 0}));
    let small = call(&mut c, "sbgk_acquire_directive", json!({"agent_id": "b", "now_ms": 0, "compact": true}));
    let text = small["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "status=DIRECTIVE lease_id=L2 kind=FORMALIZE target=svc_001 open_gaps=6 complete=false");
    assert_eq!(small["structuredContent"]["frame"]["target"], "svc_001", "the structure is complete");
    let wire = |r: &Value| r.to_string().len();
    assert!(wire(&small) * 10 < wire(&full) * 6, "{} vs {} bytes", wire(&small), wire(&full));
    let l = &full["structuredContent"];
    let s = call(&mut c, "sbgk_submit_directive", json!({"lease_id": l["lease_id"], "events": oracle(&l["frame"]), "now_ms": 1, "compact": true}));
    assert_eq!(s["content"][0]["text"], "status=COMMITTED lease_id=L1");
    let st = call(&mut c, "sbgk_swarm_status", json!({"now_ms": 2, "compact": true}));
    assert!(st["content"][0]["text"].as_str().unwrap().starts_with("status=SWARM_STATUS open_gaps="), "{st}");
}

#[test]
fn init_options_apply_without_targets_and_a_bad_snapshot_path_is_an_answer() {
    let srv = Server::start();
    let mut c = Client::connect(srv.port);
    let mut args = init_args(true);
    args.as_object_mut().unwrap().remove("targets");
    for (k, v) in [
        ("auto_close_p2a", json!(false)),
        ("default_ttl_ms", json!(123)),
        ("default_k", json!(9)),
        ("lock_mode", json!("target_only")),
        ("pack_multi_target", json!(true)),
        ("heavy_alive_ms", json!(5000)),
    ] {
        args[k] = v;
    }
    let init = c.tool("sbgk_init_session", args);
    assert_eq!(init["status"], "SESSION_READY");
    assert_eq!(
        init["config"],
        json!({"auto_close_p2a": false, "default_ttl_ms": 123, "default_k": 9, "lock_mode": "target_only", "pack_multi_target": true,
                                         "heavy_alive_ms": 5000})
    );
    let mut bad = init_args(true);
    bad["lock_mode"] = json!("everything");
    assert_eq!(c.tool("sbgk_init_session", bad)["code"], "BAD_SESSION");
    // the session of the first init is still there
    assert_eq!(c.tool("sbgk_swarm_status", json!({}))["config"]["default_k"], 9);
    let out = temp_path("no_such_dir").join("snap.sbgk");
    let snap = c.tool("sbgk_snapshot", json!({"out": out.to_str().unwrap()}));
    assert_eq!(snap["code"], "SNAPSHOT_WRITE_FAILED", "{snap}");
    assert_eq!(c.rpc("ping", json!({}))["result"], json!({}), "the server keeps serving");
}
