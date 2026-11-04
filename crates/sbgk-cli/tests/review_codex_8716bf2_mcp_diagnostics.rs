//! Offline transport probes for 8716bf2: the real CLI, real durable toy WAL,
//! authenticated NDJSON stdio, and no model, corpus or network service.
//!
//! Only the positively owned child process is stopped. The fixture directory is
//! intentionally retained under the isolated test temp directory for evidence.

use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::AuditStore;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const WORKER: &str = "review-worker-token-8716";
const BUILDER: &str = "review-builder-token-8716";
const OWNER: &str = "review-owner-token-8716";
const REPORT: &str = "# Gate\nA precise good quote.\nLine broken\nacross original source.\nDuplicate span here.\nDuplicate span here.\n";

struct Fixture {
    dir: PathBuf,
    wal: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("sbgk_review_mcp_diag_8716_{tag}_{}_{nonce}", std::process::id()));
        std::fs::create_dir(&dir).expect("create a unique, positively owned fixture directory");
        let wal = dir.join("run.wal");
        let docs = vec![("d1".to_string(), REPORT.as_bytes().to_vec())];
        let state = AuditState::create(&wal, &AuditOntology::base(), &docs, "review-mcp-diagnostics-8716", sha256(b"synthetic diagnostics fixture"))
            .expect("create the independent durable toy run");
        assert_eq!(state.head(), 0, "the server must resume a clean genesis, not a progressed legacy WAL");
        assert_eq!(state.transaction_sequence(), Some(0));
        drop(state);
        let subjects = json!({"subjects": [
            {"token": WORKER, "role": "swarm", "id": "review-worker"},
            {"token": BUILDER, "role": "builder", "id": "review-builder"},
            {"token": OWNER, "role": "owner", "id": "review-owner"}
        ]});
        std::fs::write(dir.join("subjects.json"), subjects.to_string()).unwrap();
        let questions = json!([{"id": "RQ1", "text": "What does the toy source establish?", "about": ["topic"]}]);
        std::fs::write(dir.join("questions.json"), questions.to_string()).unwrap();
        eprintln!("retained MCP diagnostics fixture: {}", dir.display());
        Self { dir, wal }
    }
}

struct Server {
    child: Child,
    writer: Option<ChildStdin>,
    replies: Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
    request_id: u64,
}

impl Server {
    fn start(fixture: &Fixture) -> Self {
        let mut command = Command::new(BIN);
        command
            .args(["audit-serve", "--profile", "custom"])
            .arg("--wal")
            .arg(&fixture.wal)
            .arg("--subjects")
            .arg(fixture.dir.join("subjects.json"))
            .arg("--questions")
            .arg(fixture.dir.join("questions.json"))
            .arg("--section-bytes")
            .arg("4000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(File::create(fixture.dir.join("server.stderr")).unwrap()));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let mut child = command.spawn().expect("start only the isolated CLI built for this test");
        let writer = child.stdin.take().expect("owned child stdin");
        let stdout = child.stdout.take().expect("owned child stdout");
        let (sender, replies) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match input.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let reply = serde_json::from_str(&line).map_err(|e| format!("invalid NDJSON reply {line:?}: {e}"));
                        if sender.send(reply).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(format!("reading isolated child stdout: {error}")));
                        break;
                    }
                }
            }
        });
        let mut server = Self { child, writer: Some(writer), replies, reader: Some(reader), request_id: 0 };
        let initialized = server.rpc("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "auth_token": WORKER}));
        assert_eq!(initialized["result"]["serverInfo"]["name"], "sbgk-audit", "{initialized}");
        server
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.request_id += 1;
        let id = self.request_id;
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let writer = self.writer.as_mut().expect("stdio is still open");
        writeln!(writer, "{message}").expect("write to the positively owned child");
        writer.flush().unwrap();
        let reply = self.replies.recv_timeout(Duration::from_secs(10)).expect("isolated CLI reply within 10 seconds").expect("valid NDJSON reply");
        assert_eq!(reply["id"], id, "response binds the exact request: {reply}");
        reply
    }

    fn call(&mut self, tool: &str, mut arguments: Value, token: &str) -> Value {
        arguments["auth_token"] = json!(token);
        let reply = self.rpc("tools/call", json!({"name": tool, "arguments": arguments}));
        assert!(reply.get("error").is_none(), "unexpected JSON-RPC failure: {reply}");
        let out = reply["result"]["structuredContent"].clone();
        assert!(out.is_object(), "the tool reply must expose structuredContent: {reply}");
        out
    }

    fn shutdown(&mut self) {
        let reply = self.rpc("shutdown", json!({"auth_token": OWNER}));
        assert_eq!(reply["result"], json!({}), "the owner ends only this test's child: {reply}");
        self.writer.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "isolated CLI exited unsuccessfully: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "isolated CLI must exit after its owner shutdown");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.writer.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn observe(prefix: &str, suffix: &str, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": format!("{prefix}{suffix}"), "doc_id": "d1", "exact_quote": quote, "terms": ["topic"]})
}

#[test]
fn mcp_swarm_receives_the_unstored_line_problems_and_keeps_the_accepted_prefix_durable() {
    let fixture = Fixture::new("problems");
    let mut server = Server::start(&fixture);
    let task = server.call("audit_acquire", json!({}), WORKER);
    assert_eq!((task["status"].as_str(), task["kind"].as_str()), (Some("DIRECTIVE"), Some("EXTEND")), "{task}");
    assert!(task["prompt"].as_str().unwrap().contains("SECTION doc_id=\"d1\""), "the actual new header reached the client: {task}");
    let prefix = task["local_id_prefix"].as_str().unwrap();
    let answer = vec![
        observe(prefix, "good", "A precise good quote."),
        observe(prefix, "missing", "Line broken across original source."),
        observe(prefix, "ambiguous", "Duplicate span here."),
    ];
    let reply = server.call("audit_submit", json!({"task_id": task["task_id"], "lines": answer}), WORKER);
    assert_eq!((reply["status"].as_str(), reply["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(2)), "{reply}");
    assert_eq!(reply["accepted"].as_array().map(Vec::len), Some(2), "the valid and soft-wrapped observes were accepted: {reply}");
    assert_eq!(reply["error"]["code"], "AMBIGUOUS_QUOTE_SPAN", "the unresolved ambiguity remains refused: {reply}");
    assert!(reply["repair"].as_str().unwrap().contains("problems"), "the dispatcher promised its detailed diagnostics: {reply}");
    let status = server.call("audit_status", json!({}), OWNER);
    assert_eq!(status["records"], 2, "only the valid quote and its exact soft-wrap repair were stored: {status}");
    let stored = server.call("audit_record", json!({"record": reply["accepted"][0]}), OWNER);
    assert_eq!((stored["kind"].as_str(), stored["quote"].as_str()), (Some("observe"), Some("A precise good quote.")), "{stored}");
    server.shutdown();
    drop(server);
    let reopened = AuditState::open(&fixture.wal).expect("reopen only this test's WAL after its child exited");
    let records = reopened.records_since(0);
    assert_eq!(records.len(), 2, "both accepted quotes survive reopening");
    assert_eq!(records[1].quote.as_deref(), Some("Line broken\nacross original source."));
    assert_eq!(reply["extended"][0]["sent"], "Line broken across original source.");
    assert_eq!(reply["extended"][0]["stored"], "Line broken\nacross original source.");
    assert_eq!(records[0].quote.as_deref(), Some("A precise good quote."));
    eprintln!("wire submit reply after independent durable-prefix checks: {reply}");

    let problems = reply["problems"].as_array().expect("MCP must deliver the promised per-line problems, not discard them in for_swarm");
    let at = |line: u64| problems.iter().find(|p| p["line"].as_u64() == Some(line));
    assert!(at(1).is_none(), "a source-exact canonical repair is accepted, not listed as still refused: {reply}");
    assert_eq!(at(2).map(|p| &p["error"]["code"]), Some(&json!("AMBIGUOUS_QUOTE_SPAN")), "{reply}");
}

#[test]
fn mcp_swarm_keeps_the_actual_expected_by_kernel_quote_repair_hint() {
    let fixture = Fixture::new("expected");
    let mut server = Server::start(&fixture);
    let task = server.call("audit_acquire", json!({}), WORKER);
    assert_eq!(task["kind"], "EXTEND", "{task}");
    let prefix = task["local_id_prefix"].as_str().unwrap();
    let reply = server.call("audit_submit", json!({"task_id": task["task_id"], "lines": [observe(prefix, "ambiguous", "Duplicate span here.")]}), WORKER);
    assert_eq!((reply["status"].as_str(), reply["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(0)), "{reply}");
    assert_eq!(reply["error"]["code"], "AMBIGUOUS_QUOTE_SPAN", "the intended error carries the store's two candidate spans: {reply}");
    let status = server.call("audit_status", json!({}), OWNER);
    assert_eq!(status["records"], 0, "neither ambiguous occurrence is accepted: {status}");
    server.shutdown();
    drop(server);
    let reopened = AuditState::open(&fixture.wal).unwrap();
    assert_eq!(reopened.records_since(0).len(), 0);
    eprintln!("wire ambiguous-quote reply after independent zero-record checks: {reply}");

    let spans = reply["error"]["expected_by_kernel"]["candidate_spans"]
        .as_array()
        .expect("MCP must preserve KernelError's expected_by_kernel repair metadata under its real key");
    assert_eq!(spans.len(), 2, "the agent needs the actual two spans to extend its quote: {reply}");
}
