//! `sbgk mcp-bridge`: a stdio MCP server that forwards every message to ONE shared `sbgk mcp-serve --listen` over TCP.
//!
//! MCP clients (Claude Code, Codex CLI, ...) start their servers as child processes speaking JSON-RPC over stdio; a stdio
//! `mcp-serve` per client would give every agent its own session. Each client starts this bridge instead, and all bridges
//! talk to the same resident swarm server, so the agents share one session, one lease registry and one graph.
//!
//! On the way to the server the bridge
//! * adds `_meta.auth_token` to every message when a token is configured (`--token`, or the environment variable
//!   `SBGK_MCP_TOKEN` so the secret stays out of the process list and the client's config): the model never sees it;
//! * sets `arguments.agent_id` of every `tools/call` to `--agent-id`, replacing what the model wrote: the operator, not the
//!   model, decides which worker a lease belongs to;
//! * with `--tier fast_cheap|standard|heavy_reasoner`, sets `arguments.tier` of every `sbgk_acquire_directive` call the same
//!   way: the operator decides which class of work the worker's model gets (EXP-12 tier routing);
//! * answers `shutdown` itself with an error (one agent must not stop the server the swarm shares), unless `--allow-shutdown`;
//! * with `--allow-tools a,b,c`, answers a `tools/call` of any other tool itself with an error (it never reaches the server)
//!   and removes the other tools from the server's `tools/list` answer: a worker sees and can call only the tools of its
//!   role, whatever its client allows.
//!
//! Other answers of the server are passed through unchanged. When the client closes stdin the bridge closes its half of the
//! connection and exits; the server keeps running. When the server goes away the bridge exits with status 1.

use super::{fail, Args};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const TOKEN_ENV: &str = "SBGK_MCP_TOKEN";

struct Opts {
    token: Option<String>,
    agent_id: Option<String>,
    /// `--tier`: forced into every `sbgk_acquire_directive` call.
    tier: Option<String>,
    allow_shutdown: bool,
    /// `--allow-tools`: the only tools this bridge exposes (None: all of them).
    allow_tools: Option<Vec<String>>,
}

impl Opts {
    fn tool_allowed(&self, name: &str) -> bool {
        self.allow_tools.as_ref().is_none_or(|a| a.iter().any(|t| t == name))
    }
}

/// A `tools/list` answer of the server with the tools outside `--allow-tools` removed; any other line unchanged.
fn filter_tools_list(line: &str, o: &Opts) -> String {
    if o.allow_tools.is_none() {
        return line.to_string();
    }
    let Ok(mut msg) = serde_json::from_str::<Value>(line) else { return line.to_string() };
    let Some(tools) = msg.pointer_mut("/result/tools").and_then(|t| t.as_array_mut()) else { return line.to_string() };
    tools.retain(|t| t["name"].as_str().is_some_and(|n| o.tool_allowed(n)));
    msg.to_string()
}

/// What the bridge does with one message from the client.
enum Route {
    Forward(String),
    /// The bridge answers itself.
    Answer(Value),
    /// A notification the bridge swallows.
    Drop,
}

fn route(line: &str, o: &Opts) -> Route {
    let Ok(mut msg) = serde_json::from_str::<Value>(line) else {
        return Route::Forward(line.to_string()); // the server answers the parse error
    };
    let Some(obj) = msg.as_object_mut() else { return Route::Forward(line.to_string()) };
    let method = obj.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    if method == "shutdown" && !o.allow_shutdown {
        return match obj.get("id") {
            Some(id) => Route::Answer(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601,
                "message": "shutdown is disabled by the bridge: the server is shared by the swarm"}})),
            None => Route::Drop,
        };
    }
    if method == "tools/call" {
        let name = obj.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
        if !o.tool_allowed(name) {
            return match obj.get("id") {
                Some(id) => Route::Answer(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602,
                    "message": format!("tool '{name}' is not allowed for this worker (bridge --allow-tools)")}})),
                None => Route::Drop,
            };
        }
    }
    let call_agent = o.agent_id.as_ref().filter(|_| method == "tools/call");
    let is_acquire = method == "tools/call" && obj.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str()) == Some("sbgk_acquire_directive");
    let call_tier = o.tier.as_ref().filter(|_| is_acquire);
    if o.token.is_none() && call_agent.is_none() && call_tier.is_none() {
        return Route::Forward(line.to_string());
    }
    let params = obj.entry("params").or_insert_with(|| json!({}));
    if let Some(p) = params.as_object_mut() {
        if let Some(t) = &o.token {
            let meta = p.entry("_meta").or_insert_with(|| json!({}));
            if let Some(m) = meta.as_object_mut() {
                m.insert("auth_token".into(), json!(t));
            }
        }
        if call_agent.is_some() || call_tier.is_some() {
            let args = p.entry("arguments").or_insert_with(|| json!({}));
            if let Some(m) = args.as_object_mut() {
                if let Some(agent) = call_agent {
                    m.insert("agent_id".into(), json!(agent));
                }
                if let Some(tier) = call_tier {
                    m.insert("tier".into(), json!(tier));
                }
            }
        }
    }
    Route::Forward(msg.to_string())
}

fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    if out.write_all(text.as_bytes()).and_then(|_| out.write_all(b"\n")).and_then(|_| out.flush()).is_err() {
        std::process::exit(0); // the client is gone
    }
}

/// Connect, retrying while the server is still starting.
fn connect(addr: &str, timeout: Duration) -> TcpStream {
    let t0 = Instant::now();
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(e) if t0.elapsed() >= timeout => fail(&format!("cannot connect to {addr}: {e}")),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

pub fn cmd_mcp_bridge(a: &Args) {
    let addr = a.req("connect");
    let token = a.get("token").map(str::to_string).or_else(|| std::env::var(TOKEN_ENV).ok()).filter(|t| !t.is_empty());
    let allow_tools = a.get("allow-tools").map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect());
    let tier = a.get("tier").map(str::to_string);
    if let Some(t) = tier.as_deref() {
        if sbgk_core::swarm::WorkerTier::parse(t).is_none() {
            fail(&format!("--tier '{t}' must be fast_cheap, standard or heavy_reasoner"));
        }
    }
    let o = Arc::new(Opts { token, agent_id: a.get("agent-id").map(str::to_string), tier, allow_shutdown: a.sw("allow-shutdown"), allow_tools });
    let stream = connect(&addr, Duration::from_millis(a.num("connect-timeout-ms", 5000)));
    let _ = stream.set_nodelay(true);
    let rd = stream.try_clone().unwrap_or_else(|e| fail(&format!("socket: {e}")));
    let closing = Arc::new(AtomicBool::new(false));
    let closing_rd = Arc::clone(&closing);
    let o_rd = Arc::clone(&o);
    std::thread::spawn(move || {
        for line in BufReader::new(rd).lines() {
            let Ok(line) = line else { break };
            emit(&filter_tools_list(&line, &o_rd));
        }
        if closing_rd.load(Ordering::SeqCst) {
            std::process::exit(0);
        }
        eprintln!("{}", json!({"status": "fatal", "message": "the MCP server closed the connection"}));
        std::process::exit(1);
    });
    let mut w = stream;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match route(&line, &o) {
            Route::Forward(text) => {
                let mut buf = text.into_bytes();
                buf.push(b'\n');
                if w.write_all(&buf).and_then(|_| w.flush()).is_err() {
                    fail("the MCP server closed the connection");
                }
            }
            Route::Answer(v) => emit(&v.to_string()),
            Route::Drop => {}
        }
    }
    // the client is done: close our half, let the last answers arrive, then leave
    closing.store(true, Ordering::SeqCst);
    let _ = w.shutdown(Shutdown::Write);
    std::thread::sleep(Duration::from_secs(5));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(token: Option<&str>, agent: Option<&str>) -> Opts {
        Opts { token: token.map(str::to_string), agent_id: agent.map(str::to_string), tier: None, allow_shutdown: false, allow_tools: None }
    }

    #[test]
    fn allow_tools_hides_and_refuses_the_other_tools() {
        let o = Opts { allow_tools: Some(vec!["sbgk_acquire_directive".into(), "sbgk_submit_directive".into()]), ..opts(Some("t"), Some("w1")) };
        let call = |name: &str| format!(r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"{name}","arguments":{{}}}}}}"#);
        assert!(matches!(route(&call("sbgk_acquire_directive"), &o), Route::Forward(_)));
        for name in ["sbgk_init_session", "sbgk_post_erratum", "sbgk_apply_events", ""] {
            let Route::Answer(v) = route(&call(name), &o) else { panic!("{name} must not reach the server") };
            assert_eq!((v["id"].as_u64(), v["error"]["code"].as_i64()), (Some(4), Some(-32602)), "{name}");
        }
        let listed = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"sbgk_init_session"},{"name":"sbgk_acquire_directive"},{"name":"sbgk_snapshot"},{"name":"sbgk_submit_directive"}]}}"#;
        let v: Value = serde_json::from_str(&filter_tools_list(listed, &o)).unwrap();
        let names: Vec<&str> = v["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["sbgk_acquire_directive", "sbgk_submit_directive"]);
        // other answers (and every answer without an allowlist) pass byte for byte
        let other = r#"{"jsonrpc":"2.0","id":5,"result":{"structuredContent":{"status":"DIRECTIVE"}}}"#;
        assert_eq!(filter_tools_list(other, &o), other);
        assert_eq!(filter_tools_list(listed, &opts(None, None)), listed);
    }

    #[test]
    fn routes_inject_the_token_and_the_operator_agent_id() {
        let o = opts(Some("s3cret"), Some("alpha"));
        let Route::Forward(t) =
            route(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sbgk_acquire_directive","arguments":{"agent_id":"model-made-up"}}}"#, &o)
        else {
            panic!("forward")
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["params"]["_meta"]["auth_token"], "s3cret");
        assert_eq!(v["params"]["arguments"]["agent_id"], "alpha", "the operator's id wins");
        let Route::Forward(t) = route(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &o) else { panic!("forward") };
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!((v["params"]["_meta"]["auth_token"].as_str(), v["params"].get("arguments")), (Some("s3cret"), None));
        // nothing configured: the line goes through byte for byte
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        assert!(matches!(route(raw, &opts(None, None)), Route::Forward(t) if t == raw));
        assert!(matches!(route("not json", &o), Route::Forward(t) if t == "not json"));
    }

    #[test]
    fn the_operator_tier_goes_into_acquire_calls_only() {
        let o = Opts { tier: Some("fast_cheap".into()), ..opts(None, None) };
        let call =
            |name: &str| format!(r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"{name}","arguments":{{"tier":"heavy_reasoner"}}}}}}"#);
        let Route::Forward(t) = route(&call("sbgk_acquire_directive"), &o) else { panic!("forward") };
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["params"]["arguments"]["tier"], "fast_cheap", "the operator's tier wins");
        assert!(matches!(route(&call("sbgk_swarm_status"), &o), Route::Forward(t) if t == call("sbgk_swarm_status")));
    }

    #[test]
    fn shutdown_stays_with_the_bridge() {
        let o = opts(None, None);
        let Route::Answer(v) = route(r#"{"jsonrpc":"2.0","id":9,"method":"shutdown"}"#, &o) else { panic!("answer") };
        assert_eq!((v["id"].as_u64(), v["error"]["code"].as_i64()), (Some(9), Some(-32601)));
        assert!(matches!(route(r#"{"jsonrpc":"2.0","method":"shutdown"}"#, &o), Route::Drop));
        let allow = Opts { allow_shutdown: true, ..o };
        assert!(matches!(route(r#"{"jsonrpc":"2.0","id":9,"method":"shutdown"}"#, &allow), Route::Forward(_)));
    }
}
