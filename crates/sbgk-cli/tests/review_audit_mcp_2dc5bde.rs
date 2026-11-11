//! Offline loopback review probes for exact revision 2dc5bde99e2b43f607cd80a484462392ae29c587.
//! Synthetic local corpus only: no models, external network, paid calls, or pilot execution.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const W1: &str = "review-swarm-token-0001";
const W2: &str = "review-swarm-token-0002";
const GB: &str = "review-builder-token-01";
const OWN: &str = "review-owner-token-0001";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const TAIL: &str = "UNREAD_TAIL_";

struct Fixture(PathBuf);

impl Fixture {
    fn new(tag: &str) -> Fixture {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("sbgk_audit_mcp_review_{tag}_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("repo/reports")).unwrap();
        // Exactly two 64-byte ASCII sections, without headings or blank-line packing boundaries.
        let text = format!("{}{}{}", "A".repeat(64), TAIL, "B".repeat(64 - TAIL.len()));
        assert_eq!(text.len(), 128);
        std::fs::write(dir.join("repo/reports/report.md"), &text).unwrap();
        let manifest = json!({
            "format": "r2r.tobi_corpus_metadata_manifest.v1",
            "source": {"origin_recorded": "https://example.invalid/local-review.git", "commit": "1".repeat(40), "repository": "C:/local-review"},
            "entries": [{"path": "reports/report.md", "extension": ".md", "corpus_role": "markdown_document_candidate",
                         "size_bytes": text.len(), "raw_sha256": sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(text.as_bytes())),
                         "references": {"commit_candidates": [], "pull_request_candidates": []}}]
        });
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        std::fs::write(dir.join("select.txt"), "reports/report.md\n").unwrap();
        let subjects = json!({"subjects": [
            {"token": W1, "role": "swarm", "id": "w1"},
            {"token": W2, "role": "swarm", "id": "w2"},
            {"token": GB, "role": "builder", "id": "gb"},
            {"token": OWN, "role": "owner", "id": "own"}
        ]});
        std::fs::write(dir.join("subjects.json"), subjects.to_string()).unwrap();
        std::fs::write(dir.join("questions.json"), json!([{"id":"RQ1","text":"What does the report establish?","about":["topic"]}]).to_string()).unwrap();
        Fixture(dir)
    }

    fn p(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }

    fn args(&self, fresh: bool, section_bytes: usize) -> Vec<String> {
        let mut args = vec![
            "--wal".into(),
            self.p("run.wal"),
            "--subjects".into(),
            self.p("subjects.json"),
            "--questions".into(),
            self.p("questions.json"),
            "--section-bytes".into(),
            section_bytes.to_string(),
        ];
        if fresh {
            for (key, value) in [
                ("--manifest", self.p("manifest.json")),
                ("--repo", self.p("repo")),
                ("--select", self.p("select.txt")),
                ("--run-id", "synthetic-mcp-review".into()),
            ] {
                args.push(key.into());
                args.push(value);
            }
        }
        args
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Server {
    _child: ChildGuard,
    port: u16,
}

impl Server {
    /// A startup rejection is returned for the resume test; socket and startup waits are bounded.
    fn try_start(args: &[String]) -> Result<Server, String> {
        let child = Command::new(BIN)
            .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start local audit-serve");
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(result);
        });
        let first = rx.recv_timeout(START_TIMEOUT).expect("audit-serve startup exceeded ten seconds").expect("read startup line");
        if first.is_empty() {
            // EOF on startup: collect the short local diagnostic after stopping the child, so this cannot leave a server behind.
            let deadline = std::time::Instant::now() + IO_TIMEOUT;
            let status = loop {
                if let Some(status) = child.0.try_wait().expect("inspect rejected startup") {
                    break status;
                }
                assert!(std::time::Instant::now() < deadline, "startup closed stdout but did not exit");
                std::thread::sleep(Duration::from_millis(10));
            };
            let exited_with_error = !status.success();
            let _ = child.0.kill();
            let _ = child.0.wait();
            let mut diagnostic = String::new();
            child.0.stderr.take().unwrap().read_to_string(&mut diagnostic).unwrap();
            assert!(exited_with_error, "startup ended without a listening line or an explicit failure: {diagnostic}");
            return Err(diagnostic);
        }
        let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("startup line {first:?}: {e}"));
        assert_eq!(hello["status"], "listening", "{hello}");
        let port = hello["port"].as_u64().unwrap() as u16;
        Ok(Server { _child: child, port })
    }

    fn start(args: &[String]) -> Server {
        Self::try_start(args).unwrap_or_else(|error| panic!("unexpected startup rejection: {error}"))
    }
}

struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
    next_id: u64,
}

impl Client {
    fn connect(port: u16, token: &str) -> Client {
        let w = TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), IO_TIMEOUT).unwrap();
        w.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        w.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        let mut client = Client { w, r, next_id: 0 };
        let init = client.rpc("initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"auth_token":token}));
        assert_eq!(init["result"]["serverInfo"]["name"], "sbgk-audit", "{init}");
        client
    }

    fn exchange(&mut self, request: &Value) -> Value {
        writeln!(self.w, "{request}").unwrap();
        let mut line = String::new();
        assert!(self.r.read_line(&mut line).expect("bounded local RPC read") > 0, "server closed before an RPC answer");
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], request["id"], "RPC correlation: {response}");
        response
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        self.exchange(&json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params}))
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.rpc("tools/call", json!({"name":name,"arguments":arguments}));
        assert!(response.get("error").is_none(), "unexpected JSON-RPC error: {response}");
        response["result"]["structuredContent"].clone()
    }
}

fn section(prompt: &str) -> &str {
    let start = prompt.find("<<<\n").expect("section opening delimiter") + 4;
    let end = prompt[start..].find("\n>>>").expect("section closing delimiter");
    &prompt[start..start + end]
}

#[test]
fn changing_section_size_on_resume_cannot_silently_skip_the_unread_tail() {
    let fixture = Fixture::new("section_resume");
    let server = Server::start(&fixture.args(true, 64));
    let mut worker = Client::connect(server.port, W1);
    let first = worker.call("audit_acquire", json!({}));
    assert_eq!(first["kind"], "EXTEND", "{first}");
    let first_section = section(first["prompt"].as_str().unwrap());
    assert_eq!(first_section.len(), 64, "fixture must lease only the first half");
    assert!(!first_section.contains(TAIL));
    let committed = worker.call("audit_submit", json!({"task_id":first["task_id"],"lines":[]}));
    assert_eq!(committed["status"], "COMMITTED", "{committed}");
    drop(worker);
    drop(server); // The acknowledged checkpoint is durable; the second half has never been issued or submitted.

    let resumed = match Server::try_start(&fixture.args(false, 128)) {
        Ok(server) => server,
        Err(diagnostic) => {
            assert!(diagnostic.to_ascii_lowercase().contains("section"), "a startup refusal must identify incompatible section configuration: {diagnostic}");
            return;
        }
    };
    let mut worker = Client::connect(resumed.port, W1);
    let next = worker.call("audit_acquire", json!({}));
    assert_eq!(next["kind"], "EXTEND", "resume must reject incompatible cuts or still issue the unread tail, never skip directly to summarization: {next}");
    let remaining = section(next["prompt"].as_str().unwrap());
    assert!(remaining.contains(TAIL), "the next issued section must cover the previously unread second half: {remaining:?}");
}

#[test]
fn an_exact_successful_submit_retry_returns_its_ack_without_another_wal_commit() {
    let fixture = Fixture::new("submit_retry");
    let server = Server::start(&fixture.args(true, 64));
    let mut worker = Client::connect(server.port, W1);
    let mut owner = Client::connect(server.port, OWN);
    let task = worker.call("audit_acquire", json!({}));
    assert_eq!(task["kind"], "EXTEND", "{task}");
    let request = json!({"jsonrpc":"2.0","id":77,"method":"tools/call",
                         "params":{"name":"audit_submit","arguments":{"task_id":task["task_id"],"lines":[]}}});
    let first = worker.exchange(&request);
    assert_eq!(first["result"]["structuredContent"]["status"], "COMMITTED", "{first}");
    let before = owner.call("audit_status", json!({}));
    drop(worker); // Simulate retrying an acknowledged commit after the original connection is gone.
    let mut retry_worker = Client::connect(server.port, W1);
    let retry = retry_worker.exchange(&request);
    let after = owner.call("audit_status", json!({}));
    for field in ["audit_root", "engine_root", "wal_head", "transaction_sequence", "records"] {
        assert_eq!(after[field], before[field], "an exact retry must not append or mutate {field}: {retry}");
    }
    assert_eq!(
        retry["result"]["structuredContent"]["status"], "COMMITTED",
        "the authenticated worker must recover its durable acknowledgement after the lease closed: {retry}"
    );
    assert_eq!(retry["result"]["structuredContent"], first["result"]["structuredContent"], "an exact ACK preserves every original response field");
    assert_eq!(after["dispatch"], before["dispatch"], "a retry does not change dispatch counters");
    assert_eq!(after["builder"], before["builder"], "a retry does not change builder counters");
}

#[test]
fn unchanged_section_configuration_resumes_and_still_leases_the_unread_tail() {
    let fixture = Fixture::new("same_section_resume");
    let server = Server::start(&fixture.args(true, 64));
    let mut worker = Client::connect(server.port, W1);
    let first = worker.call("audit_acquire", json!({}));
    assert_eq!(first["kind"], "EXTEND", "{first}");
    assert!(!section(first["prompt"].as_str().unwrap()).contains(TAIL));
    assert_eq!(worker.call("audit_submit", json!({"task_id":first["task_id"],"lines":[]}))["status"], "COMMITTED");
    drop(worker);
    drop(server);

    let server = Server::start(&fixture.args(false, 64));
    let mut worker = Client::connect(server.port, W1);
    let next = worker.call("audit_acquire", json!({}));
    assert_eq!(next["kind"], "EXTEND", "compatible resume must continue coverage: {next}");
    assert!(section(next["prompt"].as_str().unwrap()).contains(TAIL));
}

#[test]
fn a_progressed_legacy_wal_without_section_binding_is_refused_without_rewriting_it() {
    let fixture = Fixture::new("legacy_resume");
    let wal = fixture.0.join("run.wal");
    let docs = vec![("report".to_string(), b"Synthetic legacy report.".to_vec())];
    let mut state = sbgk_core::audit::state::AuditState::create(
        &wal,
        &sbgk_core::audit::onto::AuditOntology::base(),
        &docs,
        "legacy-synthetic-review",
        sbgk_core::hash::sha256(b"synthetic legacy manifest"),
    )
    .unwrap();
    let checkpoint = json!({"key":"task:doc:report#0","from":0,"to":0,"context":{"kind":"EXTEND","task_id":"legacy-task","agent":"w1"}});
    let committed = state.submit_operations_id("legacy-progress", "w1", &[], Some(checkpoint)).unwrap();
    assert_eq!(committed["checkpointed"], true, "{committed}");
    drop(state);
    let before = std::fs::read(&wal).unwrap();
    let diagnostic = match Server::try_start(&fixture.args(false, 64)) {
        Ok(_) => panic!("a progressed legacy journal cannot prove which section configuration its indices used"),
        Err(diagnostic) => diagnostic,
    };
    assert!(diagnostic.contains("section configuration"), "{diagnostic}");
    assert_eq!(std::fs::read(&wal).unwrap(), before, "unsafe resume must not rewrite a valid legacy journal");
}

#[test]
fn cached_submit_ack_is_bound_to_the_authenticated_worker_and_exact_lines() {
    let fixture = Fixture::new("submit_retry_identity");
    let server = Server::start(&fixture.args(true, 64));
    let mut worker = Client::connect(server.port, W1);
    let mut other = Client::connect(server.port, W2);
    let mut owner = Client::connect(server.port, OWN);
    let task = worker.call("audit_acquire", json!({}));
    let doc = task["key"].as_str().unwrap().strip_prefix("doc:").unwrap().split('#').next().unwrap();
    let lines = json!([{"kind":"observe","local_id":format!("{}o1", task["local_id_prefix"].as_str().unwrap()),
                        "doc_id":doc,"exact_quote":section(task["prompt"].as_str().unwrap()),"terms":["alpha"]}]);
    let arguments = json!({"task_id":task["task_id"],"lines":lines});
    let first = worker.call("audit_submit", arguments.clone());
    assert_eq!(first["status"], "COMMITTED", "{first}");
    assert_eq!(first["accepted"].as_array().unwrap().len(), 1);
    let before = owner.call("audit_status", json!({}));
    assert_eq!(other.call("audit_submit", arguments.clone())["code"], "TASK_NOT_OWNED");
    assert_eq!(worker.call("audit_submit", json!({"task_id":task["task_id"],"lines":[]}))["code"], "SUBMISSION_MISMATCH");
    drop(worker);
    let mut reconnected = Client::connect(server.port, W1);
    assert_eq!(reconnected.call("audit_submit", arguments), first, "the original accepted IDs and all ACK fields survive reconnect");
    let after = owner.call("audit_status", json!({}));
    for field in ["audit_root", "engine_root", "wal_head", "transaction_sequence", "records", "dispatch", "builder"] {
        assert_eq!(after[field], before[field], "cache hits and refused mismatches must not change {field}");
    }
}
