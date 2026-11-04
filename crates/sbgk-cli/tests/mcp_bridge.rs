//! `sbgk mcp-bridge`: stdio MCP clients share ONE `sbgk mcp-serve --listen` session through their own bridge processes. The
//! bridge carries the token (from the environment), fixes the worker identity, keeps `shutdown` away from the shared server
//! and leaves the server running when its client goes away.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const TOKEN: &str = "s3cret-bridge";

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/quickstart").join(name)
}

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start() -> Server {
        let mut child =
            Command::new(BIN).args(["mcp-serve", "--listen", "127.0.0.1:0", "--token", TOKEN]).stdout(Stdio::piped()).spawn().expect("start sbgk mcp-serve");
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
        let v: Value = serde_json::from_str(&first).unwrap();
        Server { port: v["port"].as_u64().unwrap() as u16, child }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A bridge process, driven the way an MCP client drives a stdio server.
struct Bridge {
    child: Child,
    w: Option<ChildStdin>,
    r: BufReader<ChildStdout>,
    id: u64,
}

impl Bridge {
    fn start(port: u16, agent: &str, token: Option<&str>) -> Bridge {
        Bridge::start_with(port, agent, token, &[])
    }

    fn start_with(port: u16, agent: &str, token: Option<&str>, extra: &[&str]) -> Bridge {
        let mut cmd = Command::new(BIN);
        cmd.args(["mcp-bridge", "--connect", &format!("127.0.0.1:{port}"), "--agent-id", agent]).args(extra).env_remove("SBGK_MCP_TOKEN");
        if let Some(t) = token {
            cmd.env("SBGK_MCP_TOKEN", t);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("start sbgk mcp-bridge");
        let w = child.stdin.take();
        let r = BufReader::new(child.stdout.take().unwrap());
        Bridge { child, w, r, id: 0 }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let w = self.w.as_mut().unwrap();
        writeln!(w, "{}", json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})).unwrap();
        w.flush().unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        assert_eq!(v["id"], json!(self.id));
        v
    }

    fn tool(&mut self, name: &str, args: Value) -> Value {
        self.rpc("tools/call", json!({"name": name, "arguments": args}))["result"]["structuredContent"].clone()
    }

    /// The client closes stdin; the bridge must exit on its own.
    fn close(mut self) -> std::process::ExitStatus {
        drop(self.w.take());
        let t0 = Instant::now();
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                return st;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "the bridge did not exit after stdin closed");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn two_clients_share_one_session_through_their_bridges() {
    let srv = Server::start();
    let mut alpha = Bridge::start(srv.port, "alpha", Some(TOKEN));
    // the client sends no token: the bridge adds it
    let init = alpha.rpc("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "client-a", "version": "0"}}));
    assert_eq!(init["result"]["serverInfo"]["name"], "sbgk-mcp", "{init}");
    assert!(alpha.rpc("tools/list", json!({}))["result"]["tools"].as_array().unwrap().len() >= 12);
    let targets: Value = serde_json::from_str(&std::fs::read_to_string(example("targets.json")).unwrap()).unwrap();
    let s = alpha.tool("sbgk_init_session", json!({"ontology": example("ontology.json"), "docs": example("docs"), "targets": targets}));
    assert_eq!(s["status"], "SESSION_READY", "{s}");

    // the model writes no agent_id (or a wrong one): the lease belongs to the bridge's worker
    let l = alpha.tool("sbgk_acquire_directive", json!({"agent_id": "made-up-by-the-model", "now_ms": 0}));
    assert_eq!((l["status"].as_str(), l["agent_id"].as_str()), (Some("DIRECTIVE"), Some("alpha")), "{l}");

    // a second client sees the same session, and cannot submit or release alpha's lease
    let mut beta = Bridge::start(srv.port, "beta", Some(TOKEN));
    beta.rpc("initialize", json!({"protocolVersion": "2025-06-18"}));
    let st = beta.tool("sbgk_swarm_status", json!({"now_ms": 1}));
    assert_eq!(st["leases"].as_array().unwrap().len(), 1, "one shared lease registry: {st}");
    let steal = beta.tool("sbgk_release_lease", json!({"lease_id": l["lease_id"], "now_ms": 2}));
    assert_eq!(steal["code"], "LEASE_NOT_OWNED", "{steal}");
    let b = beta.tool("sbgk_acquire_directive", json!({"now_ms": 3}));
    assert_eq!(b["agent_id"], "beta");
    assert_ne!(b["frame"]["target"], l["frame"]["target"], "disjoint leases across clients");

    // shutdown never reaches the shared server
    assert_eq!(beta.rpc("shutdown", json!({}))["error"]["code"], -32601);
    assert_eq!(alpha.rpc("ping", json!({}))["result"], json!({}));

    // without the token the server refuses the bridge
    let mut anon = Bridge::start(srv.port, "anon", None);
    assert_eq!(anon.rpc("initialize", json!({}))["error"]["code"], -32001);

    // a client that goes away takes only its bridge with it
    assert!(beta.close().success());
    assert_eq!(alpha.tool("sbgk_release_lease", json!({"lease_id": l["lease_id"], "now_ms": 4}))["status"], "RELEASED");
    assert!(alpha.close().success());
    let mut gamma = Bridge::start(srv.port, "gamma", Some(TOKEN));
    gamma.rpc("initialize", json!({}));
    let st = gamma.tool("sbgk_swarm_status", json!({"now_ms": 5}));
    assert_eq!(st["stats"]["leases_released"], 1, "the server and its session are still alive: {st}");
}

#[test]
fn a_bridge_without_a_server_fails_fast() {
    // a port nobody listens on: bind, read the port, close
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let t0 = Instant::now();
    let out = Command::new(BIN).args(["mcp-bridge", "--connect", &format!("127.0.0.1:{port}"), "--connect-timeout-ms", "300"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot connect"));
    assert!(t0.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_worker_bridge_exposes_and_forwards_only_its_allowlist() {
    let srv = Server::start();
    let mut admin = Bridge::start(srv.port, "controller", Some(TOKEN));
    admin.rpc("initialize", json!({}));
    let targets: Value = serde_json::from_str(&std::fs::read_to_string(example("targets.json")).unwrap()).unwrap();
    let s = admin.tool("sbgk_init_session", json!({"ontology": example("ontology.json"), "docs": example("docs"), "targets": targets}));
    assert_eq!(s["status"], "SESSION_READY");
    let allow = "sbgk_acquire_directive,sbgk_submit_directive,sbgk_renew_lease,sbgk_release_lease,sbgk_swarm_status,sbgk_query_cone";
    let mut w = Bridge::start_with(srv.port, "w1", Some(TOKEN), &["--allow-tools", allow]);
    w.rpc("initialize", json!({}));
    let mut names: Vec<String> =
        w.rpc("tools/list", json!({}))["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    names.sort();
    let mut want: Vec<&str> = allow.split(',').collect();
    want.sort();
    assert_eq!(names, want, "the worker sees exactly its role's tools");
    // administrative tools are refused by the bridge and never reach the server
    for (name, args) in [
        ("sbgk_init_session", json!({"ontology": example("ontology.json")})),
        ("sbgk_post_erratum", json!({"erratum_text": "Erratum E.9: clause U.1 is withdrawn.\n"})),
        ("sbgk_apply_events", json!({"events": []})),
        ("sbgk_set_targets", json!({"targets": targets})),
    ] {
        let r = w.rpc("tools/call", json!({"name": name, "arguments": args}));
        assert_eq!(r["error"]["code"], -32602, "{name}: {r}");
    }
    let st = admin.tool("sbgk_swarm_status", json!({"now_ms": 1}));
    assert_eq!((st["doc_epoch"].as_u64(), st["last_seq"].as_u64()), (Some(0), Some(0)), "nothing reached the kernel: {st}");
    // its own work goes through, under the operator's id
    let l = w.tool("sbgk_acquire_directive", json!({"now_ms": 2}));
    assert_eq!((l["status"].as_str(), l["agent_id"].as_str()), (Some("DIRECTIVE"), Some("w1")), "{l}");
}
