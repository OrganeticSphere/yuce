//! `sbgk audit-serve` over JSON-RPC (TCP): rights from subject tokens (contract v0.1 R8) and a whole audit run on the wire -
//! swarm agents, the graph builder and the owner - with a kill and a resume from the journal in the middle.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const A: &str = "# Alpha\nTopic A is reported.\n";
const B: &str = "# Beta\nTopic B is reported.\n";
const W1: &str = "swarm-token-w1-0001";
const W2: &str = "swarm-token-w2-0002";
const GB: &str = "builder-token-00001";
const OWN: &str = "owner-token-0000001";

struct Fixture(PathBuf);

impl Fixture {
    fn new(tag: &str) -> Fixture {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("sbgk_audit_serve_{tag}_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("repo/reports")).unwrap();
        let mut entries = Vec::new();
        for (name, text) in [("a.md", A), ("b.md", B)] {
            std::fs::write(dir.join("repo/reports").join(name), text).unwrap();
            entries.push(json!({"path": format!("reports/{name}"), "extension": ".md", "corpus_role": "markdown_document_candidate",
                                "size_bytes": text.len(), "raw_sha256": sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(text.as_bytes())),
                                "references": {"commit_candidates": [], "pull_request_candidates": []}}));
        }
        let manifest = json!({"format": "r2r.tobi_corpus_metadata_manifest.v1",
                              "source": {"origin_recorded": "https://example.invalid/repo.git", "commit": "1".repeat(40), "repository": "C:/local"},
                              "entries": entries});
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        std::fs::write(dir.join("select.txt"), "# the pilot cut\nreports/a.md\nreports/b.md\n").unwrap();
        let subjects = json!({"subjects": [{"token": W1, "role": "swarm", "id": "w1"}, {"token": W2, "role": "swarm", "id": "w2"},
                                           {"token": GB, "role": "builder", "id": "gb"}, {"token": OWN, "role": "owner", "id": "own"}]});
        std::fs::write(dir.join("subjects.json"), subjects.to_string()).unwrap();
        let questions = json!([{"id": "RQ1", "text": "What do the reports establish about the topic?", "about": ["topic"]}]);
        std::fs::write(dir.join("questions.json"), questions.to_string()).unwrap();
        Fixture(dir)
    }

    fn p(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }

    /// Server arguments: a new run, or (`fresh = false`) a resume of the journal.
    fn args(&self, fresh: bool) -> Vec<String> {
        let mut a: Vec<String> = ["--wal", &self.p("run.wal"), "--subjects", &self.p("subjects.json"), "--questions", &self.p("questions.json")]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if fresh {
            for (k, v) in
                [("--manifest", self.p("manifest.json")), ("--repo", self.p("repo")), ("--select", self.p("select.txt")), ("--run-id", "wire-run".into())]
            {
                a.push(k.into());
                a.push(v);
            }
        }
        a
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server {
    child: Child,
    port: u16,
    hello: Value,
}

impl Server {
    fn start(args: &[String]) -> Server {
        Self::start_with_stderr(args, Stdio::inherit())
    }

    /// A server whose stderr goes where the test says, to read what it told its operator.
    fn start_with_stderr(args: &[String], stderr: Stdio) -> Server {
        let mut child = Command::new(BIN)
            .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("start audit-serve");
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
        let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("first line {first:?}: {e}"));
        assert_eq!(hello["status"], "listening");
        Server { port: hello["port"].as_u64().unwrap() as u16, child, hello }
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
    fn raw(port: u16) -> Client {
        let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        Client { w, r, id: 0 }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        writeln!(self.w, "{}", json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})).unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// A connection authenticated as the subject of `token`.
    fn connect(port: u16, token: &str) -> Client {
        let mut c = Client::raw(port);
        let init = c.rpc("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "auth_token": token}));
        assert_eq!(init["result"]["serverInfo"]["name"], "sbgk-audit", "{init}");
        c
    }

    fn tools(&mut self) -> Vec<String> {
        let r = self.rpc("tools/list", json!({}));
        r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    /// The tool's answer (`structuredContent`), or the JSON-RPC error.
    fn call(&mut self, tool: &str, args: Value) -> Value {
        let r = self.rpc("tools/call", json!({"name": tool, "arguments": args}));
        if r.get("error").is_some() {
            return r["error"].clone();
        }
        r["result"]["structuredContent"].clone()
    }
}

fn section(prompt: &str) -> &str {
    let a = prompt.find("<<<\n").unwrap() + 4;
    &prompt[a..a + prompt[a..].find("\n>>>").unwrap()]
}

fn observes(prompt: &str) -> Vec<String> {
    prompt
        .lines()
        .filter_map(|l| l.trim_start().split_once(' '))
        .filter(|(id, rest)| id.starts_with('@') && rest.starts_with("observe"))
        .map(|(id, _)| id.to_string())
        .collect()
}

/// A deterministic swarm agent: quotes the topic line of an EXTEND section, answers a SUMMARIZE from the quotes shown.
fn answer(t: &Value) -> Vec<Value> {
    let (p, prompt) = (t["local_id_prefix"].as_str().unwrap(), t["prompt"].as_str().unwrap());
    match t["kind"].as_str().unwrap() {
        "EXTEND" => {
            let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap();
            match section(prompt).lines().find(|l| l.starts_with("Topic")) {
                Some(q) => vec![
                    json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": q, "terms": ["topic"]}),
                    json!({"kind": "claim", "local_id": format!("{p}c1"), "text": q, "subject": "topic", "stance": "reported", "based_on": [format!("{p}o1")]}),
                ],
                None => vec![],
            }
        }
        "SUMMARIZE" => {
            let obs = observes(prompt);
            vec![
                json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "Both reports state their topic.", "subject": "topic", "stance": "reported", "based_on": obs}),
                json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": t["task_id"], "outcome": "answered", "answer_ids": [format!("{p}c1")]}),
            ]
        }
        other => panic!("no work of kind {other} in this run: {t}"),
    }
}

fn catch_up(builder: &mut Client) {
    loop {
        let card = builder.call("audit_next_card", json!({}));
        if card["status"] == "IDLE" {
            assert_eq!(card["caught_up"], true, "{card}");
            return;
        }
        assert_eq!(card["status"], "CARD", "{card}");
        let done = builder.call("audit_submit_ops", json!({"card_id": card["card_id"], "ops": []}));
        assert_eq!(done["status"], "CARD_DONE", "{done}");
    }
}

#[test]
fn rights_come_from_the_subject_token_on_every_method() {
    let fx = Fixture::new("rights");
    let server = Server::start(&fx.args(true));
    assert_eq!((server.hello["audit"]["run_id"].as_str(), server.hello["audit"]["resumed"].as_bool()), (Some("wire-run"), Some(false)));

    let mut anon = Client::raw(server.port);
    for (method, params) in [("initialize", json!({"protocolVersion": "2025-06-18"})), ("ping", json!({})), ("tools/list", json!({}))] {
        assert_eq!(anon.rpc(method, params)["error"]["code"], -32001, "{method} needs a subject");
    }
    assert_eq!(anon.rpc("initialize", json!({"auth_token": "not-a-subject-token"}))["error"]["code"], -32001);

    let mut w1 = Client::connect(server.port, W1);
    assert_eq!(w1.tools(), ["audit_acquire", "audit_submit", "audit_renew", "audit_release"]);
    assert_eq!(w1.call("audit_status", json!({}))["code"], -32003, "the swarm sees no run state");
    assert_eq!(w1.call("audit_next_card", json!({}))["code"], -32003);
    assert_eq!(w1.rpc("shutdown", json!({}))["error"]["code"], -32003);
    let mut gb = Client::connect(server.port, GB);
    assert_eq!(gb.tools(), ["audit_next_card", "audit_submit_ops"]);
    assert_eq!(gb.call("audit_acquire", json!({}))["code"], -32003);
    let mut own = Client::connect(server.port, OWN);
    assert_eq!(own.tools().len(), 13, "nine tools of 0.1 and the four reading tools of 0.2");
    assert_eq!(own.call("audit_acquire", json!({}))["code"], -32003, "roles do not stack");

    // the lease belongs to the authenticated subject, whatever agent_id the client claims
    let t = w1.call("audit_acquire", json!({"agent_id": "w2"}));
    assert_eq!(t["status"], "DIRECTIVE", "{t}");
    assert!(t.get("agent_id").is_none(), "{t}");
    let mut w2 = Client::connect(server.port, W2);
    assert_eq!(w2.call("audit_submit", json!({"task_id": t["task_id"], "lines": []}))["code"], "TASK_NOT_OWNED");
    assert_eq!(w2.call("audit_renew", json!({"task_id": t["task_id"]}))["code"], "TASK_NOT_OWNED");
    assert_eq!(w1.call("audit_renew", json!({"task_id": t["task_id"]}))["status"], "RENEWED");
    // a repair hint, without the run's counters
    let bad = w1.call(
        "audit_submit",
        json!({"task_id": t["task_id"], "lines": [{"kind": "observe", "local_id": "x", "doc_id": "nope", "exact_quote": "q", "terms": ["t"]}]}),
    );
    assert_eq!(bad["status"], "REPAIR_REQUIRED", "{bad}");
    assert!(bad["error"]["code"].is_string() && bad.get("open_work").is_none(), "{bad}");
    assert_eq!(w1.call("audit_release", json!({"task_id": t["task_id"]}))["status"], "RELEASED");
    // a per-call token speaks for its own subject only
    assert_eq!(anon.call("audit_status", json!({"auth_token": OWN}))["status"], "STATUS");
    assert_eq!(own.rpc("shutdown", json!({}))["result"], json!({}));
}

#[test]
fn a_run_completes_on_the_wire_and_resumes_from_the_journal_after_a_kill() {
    let fx = Fixture::new("run");
    let server = Server::start(&fx.args(true));
    let mut w1 = Client::connect(server.port, W1);
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!(t["kind"], "EXTEND", "{t}");
    assert!(t["prompt"].as_str().unwrap().contains("over a corpus of engineering reports."), "the words of the measured runs: {t}");
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
    assert_eq!(r["status"], "COMMITTED", "{r}");
    drop(server); // killed: nothing flushed beyond the journal

    let refused = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(fx.args(true)).output().unwrap();
    assert!(!refused.status.success(), "an existing run is resumed, never re-created over");
    let server = Server::start(&fx.args(false));
    assert_eq!((server.hello["audit"]["resumed"].as_bool(), server.hello["audit"]["records"].as_u64()), (Some(true), Some(2)), "{}", server.hello);
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    assert_eq!(own.call("audit_terminal_receipt", json!({}))["status"], "NOT_COMPLETE");
    let mut keys = Vec::new();
    for round in 0..20 {
        catch_up(&mut gb);
        let agent = if round % 2 == 0 { &mut w2 } else { &mut w1 };
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        keys.push(t["key"].as_str().unwrap().to_string());
        let r = agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
        assert_eq!(r["status"], "COMMITTED", "{t} -> {r}");
    }
    assert_eq!(keys.iter().filter(|k| k.starts_with("doc:")).count(), 1, "the section committed before the kill is not issued again: {keys:?}");
    assert!(keys.iter().any(|k| k == "rq:RQ1"), "{keys:?}");
    let status = own.call("audit_status", json!({}));
    assert_eq!((status["completion"]["complete"].as_bool(), status["records"].as_u64()), (Some(true), Some(6)), "{status}");
    let receipt = own.call("audit_terminal_receipt", json!({}));
    assert_eq!(receipt["status"], "TERMINAL", "{receipt}");
    let manifest = std::fs::read(Path::new(&fx.p("manifest.json"))).unwrap();
    assert_eq!(receipt["corpus_manifest_hash"], sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(&manifest)));
    assert_eq!((receipt["outcomes"]["RQ1"]["outcome"].as_str(), receipt["run_id"].as_str()), (Some("answered"), Some("wire-run")));
    assert_eq!(receipt["audit_root"], status["audit_root"]);

    // phase 2: the owner withdraws the quote the answer rests on; only that research question is reopened
    let claim = own.call("audit_record", json!({"record": receipt["outcomes"]["RQ1"]["answer_ids"][0]}));
    assert!(claim.get("answer_status").is_none(), "no time status without stale_suspect: {claim}");
    let observe = own.call("audit_record", json!({"record": claim["based_on"][0]}));
    assert_eq!((observe["kind"].as_str(), observe["grounded"].as_bool()), (Some("observe"), Some(true)), "{observe}");
    assert_eq!(w1.call("audit_revoke", json!({"record": observe["id"]}))["code"], -32003, "only the owner withdraws a source");
    assert_eq!(own.call("audit_revoke", json!({"record": observe["short"]}))["status"], "REVOKED");
    assert_eq!(own.call("audit_record", json!({"record": observe["id"]}))["grounded"], false);
    assert_eq!(own.call("audit_terminal_receipt", json!({}))["status"], "NOT_COMPLETE");
    let again = w1.call("audit_acquire", json!({}));
    assert_eq!((again["kind"].as_str(), again["key"].as_str()), (Some("SUMMARIZE"), Some("rq:RQ1")), "{again}");
    let prompt = again["prompt"].as_str().unwrap();
    assert!(!prompt.contains(observe["short"].as_str().unwrap()) && !prompt.contains(claim["short"].as_str().unwrap()), "withdrawn: {prompt}");
}

#[test]
fn a_closed_run_tells_every_agent_done_accepts_nothing_more_and_stays_closed_after_a_restart() {
    // R27 package 2: COMPLETE is not the end, the owner may still withdraw a source and reopen work, so
    // the agents kept polling; DONE tells them the owner closed the run
    let fx = Fixture::new("close");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    assert_eq!(own.call("audit_close", json!({}))["status"], "NOT_COMPLETE", "a run that is not terminal is not closed");
    let mut complete = false;
    for round in 0..20 {
        catch_up(&mut gb);
        let agent = if round % 2 == 0 { &mut w1 } else { &mut w2 };
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => {
                complete = true;
                break;
            }
            "WAIT" => continue,
            "DIRECTIVE" => {}
            other => panic!("{other}: {t}"),
        }
        assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    assert!(complete, "the run completes before the close");
    let receipt = own.call("audit_terminal_receipt", json!({}));
    assert_eq!(receipt["status"], "TERMINAL", "{receipt}");
    let claim = own.call("audit_record", json!({"record": receipt["outcomes"]["RQ1"]["answer_ids"][0]}));
    let observe = claim["based_on"][0].clone();

    let closed = own.call("audit_close", json!({}));
    // the close is a seal and a `close` entry: the roots move on from the terminal receipt's
    assert_eq!(closed["status"].as_str(), Some("CLOSED"), "{closed}");
    assert_ne!(closed["audit_root"], receipt["audit_root"], "{closed}");
    assert_eq!(w1.call("audit_acquire", json!({}))["status"], "DONE");
    let waited = Instant::now();
    assert_eq!(w2.call("audit_acquire", json!({"max_wait_ms": 5000}))["status"], "DONE");
    assert!(waited.elapsed() < Duration::from_secs(2), "DONE does not wait out the long poll");
    assert_eq!(gb.call("audit_next_card", json!({}))["status"], "DONE");
    let late = w1.call("audit_submit", json!({"task_id": "TX1-late", "lines": []}));
    assert_eq!(late["code"], "RUN_CLOSED", "{late}");
    assert_eq!(own.call("audit_revoke", json!({"record": observe}))["code"], "RUN_CLOSED", "a withdrawal would reopen work nobody takes");
    assert_eq!(own.call("audit_record", json!({"record": observe}))["grounded"], true, "reads stay open; nothing was withdrawn");
    let status = own.call("audit_status", json!({}));
    assert_eq!((status["closed"].as_bool(), &status["audit_root"]), (Some(true), &closed["audit_root"]), "{status}");
    assert_eq!(own.call("audit_terminal_receipt", json!({}))["audit_root"], closed["audit_root"]);
    let again = own.call("audit_close", json!({}));
    assert_eq!((again["status"].as_str(), &again["audit_root"]), (Some("CLOSED"), &closed["audit_root"]), "closing again changes nothing");

    // the close is journaled: a restarted server finds the run closed, with the same root
    drop((w1, w2, gb, own));
    drop(server);
    let server = Server::start(&fx.args(false));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    assert_eq!(w1.call("audit_acquire", json!({}))["status"], "DONE");
    let status = own.call("audit_status", json!({}));
    assert_eq!((status["closed"].as_bool(), &status["audit_root"]), (Some(true), &closed["audit_root"]), "{status}");
}

#[test]
fn a_summary_claim_read_on_the_wire_carries_what_its_reader_is_told_about_time() {
    // registry R34a: the owner's audit_record gives the runner the answer status it writes into the final answer
    let fx = Fixture::new("answer-status");
    let mut args = fx.args(true);
    args.push("--stale-suspect".into());
    let server = Server::start(&args);
    let (mut w1, mut gb, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, GB), Client::connect(server.port, OWN));
    let mut readers = vec![];
    for _ in 0..20 {
        catch_up(&mut gb);
        let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {
                let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
                assert_eq!(r["status"], "COMMITTED", "{r}");
                if t["kind"] == "EXTEND" {
                    readers.extend(r["accepted_locals"].get(format!("{}c1", t["local_id_prefix"].as_str().unwrap())).cloned());
                }
            }
        }
    }
    let receipt = own.call("audit_terminal_receipt", json!({}));
    assert_eq!(receipt["status"], "TERMINAL", "{receipt}");
    let claim = own.call("audit_record", json!({"record": receipt["outcomes"]["RQ1"]["answer_ids"][0]}));
    assert_eq!(claim["answer_status"], json!({"temporal_status": "LATEST_KNOWN", "replaced": [], "earlier_and_later": []}), "{claim}");
    let observe = own.call("audit_record", json!({"record": claim["based_on"][0]}));
    assert!(observe.get("answer_status").is_none(), "only claims: {observe}");
    // ANS-01 (run MCPpair_r1): a summary may list a reader's claim in its answer ids, so a reader's claim carries its status too
    assert!(!readers.is_empty(), "the run had reading work");
    let reader = own.call("audit_record", json!({"record": readers[0]}));
    assert_eq!(reader["answer_status"], json!({"temporal_status": "LATEST_KNOWN", "replaced": [], "earlier_and_later": []}), "{reader}");
}

#[test]
fn a_question_whose_selectors_are_wrong_refuses_the_start_instead_of_changing_the_task() {
    // Codex review d7d9a49, D11: a selector of the wrong type or with an unknown value was silently dropped
    for (selector, needle) in [
        (json!({"stances": "superseded"}), "must be an array of strings"),
        (json!({"stances": ["superseeded"]}), "unknown stance"),
        (json!({"relations": ["replaces"]}), "unknown relation"),
        (json!({"stances": [123]}), "non-string or empty entry"),
        (json!({"concept_types": ["Nonsense"]}), "unknown concept type"),
    ] {
        let fx = Fixture::new("selectors");
        let mut q = json!({"id": "RQ1", "text": "What do the reports establish about the topic?", "about": ["topic"]});
        for (k, v) in selector.as_object().unwrap() {
            q[k] = v.clone();
        }
        std::fs::write(fx.0.join("questions.json"), json!([q]).to_string()).unwrap();
        let out = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(fx.args(true)).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && text.contains(needle), "{selector}: {text}");
    }
}

#[test]
fn dynamic_build_is_a_scoped_swarm_lease_with_repair_ack_and_restart_binding() {
    let fx = Fixture::new("dynamic");
    // No dedicated builder; a third reader is available for pairs with two authors.
    std::fs::write(
        fx.p("subjects.json"),
        json!({"subjects":[
            {"token":W1,"role":"swarm","id":"w1"},{"token":W2,"role":"swarm","id":"w2"},
            {"token":GB,"role":"swarm","id":"w3"},{"token":OWN,"role":"owner","id":"own"}
        ]})
        .to_string(),
    )
    .unwrap();
    let args = |fresh| {
        let mut a = fx.args(fresh);
        a.extend(["--dynamic-roles".into(), "--build-backlog".into(), "1".into()]);
        a
    };
    let server = Server::start(&args(true));
    let (mut w1, mut w2, mut w3) = (Client::connect(server.port, W1), Client::connect(server.port, W2), Client::connect(server.port, GB));
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!(t["kind"], "EXTEND");
    assert_eq!(w1.call("audit_submit", json!({"task_id":t["task_id"],"lines":answer(&t)}))["status"], "COMMITTED");
    let t = w2.call("audit_acquire", json!({}));
    assert_eq!(t["kind"], "BUILD", "{t}");
    assert!(t["card"]["records"].as_array().unwrap().iter().all(|r| r["author"] == "w1"));
    assert!(t["card"]["prompt"].is_string());
    assert_eq!(w2.call("audit_next_card", json!({}))["code"], -32003, "no role escalation");
    assert_eq!(w1.call("audit_submit", json!({"task_id":t["task_id"],"lines":[]}))["code"], "TASK_NOT_OWNED");
    let bad = w2.call("audit_submit", json!({"task_id":t["task_id"],"lines":[{"op":"not-an-operation"}]}));
    assert_eq!(bad["status"], "REPAIR_REQUIRED", "{bad}");
    assert!(bad["results"].is_array(), "repair details survive for_swarm");
    let request = json!({"task_id":t["task_id"],"lines":[]});
    let done = w2.call("audit_submit", request.clone());
    assert_eq!(done["status"], "CARD_DONE", "{done}");
    drop(w2);
    let mut w2 = Client::connect(server.port, W2);
    assert_eq!(w2.call("audit_submit", request), done, "lost ACK replays after reconnect");
    assert_eq!(w2.call("audit_submit", json!({"task_id":t["task_id"],"lines":[{"op":"other"}]}))["code"], "SUBMISSION_MISMATCH");
    let remaining = w1.call("audit_acquire", json!({}));
    assert_eq!(remaining["kind"], "EXTEND", "the author can continue reading");
    assert_eq!(w1.call("audit_submit", json!({"task_id":remaining["task_id"],"lines":answer(&remaining)}))["status"], "COMMITTED");
    let pending = w3.call("audit_acquire", json!({}));
    assert_eq!(pending["kind"], "BUILD");
    let mut own = Client::connect(server.port, OWN);
    let before = own.call("audit_status", json!({}));
    drop(server);
    let server = Server::start(&args(false));
    let mut own = Client::connect(server.port, OWN);
    let after = own.call("audit_status", json!({}));
    assert_eq!(before["audit_root"], after["audit_root"]);
    assert_eq!(before["builder_cursor"], after["builder_cursor"]);
    let mut w2 = Client::connect(server.port, W2);
    let renewed = w2.call("audit_acquire", json!({}));
    assert_eq!(renewed["kind"], "BUILD");
    assert_eq!(renewed["card_id"], pending["card_id"]);
    assert_ne!(renewed["task_id"], pending["task_id"]);
    assert_eq!(w2.call("audit_submit", json!({"task_id":pending["task_id"],"lines":[]}))["status"], "STALE_TASK");
    assert_eq!(w2.call("audit_submit", json!({"task_id":renewed["task_id"],"lines":[]}))["status"], "CARD_DONE");
    drop(server);
    let refused = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(fx.args(false)).output().unwrap();
    assert!(!refused.status.success(), "cannot silently resume a dynamic WAL without its flag");
}

#[test]
fn circles_on_wire_keep_the_shared_barrier_and_timeout_exclusion_across_restart() {
    let fx = Fixture::new("circle-timeout");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(fx.p("manifest.json")).unwrap()).unwrap();
    for i in 0..7 {
        let path = format!("reports/c{i}.md");
        let text = format!("# Topic {i}\nTopic condition {i} is reported.\n");
        std::fs::write(std::path::Path::new(&fx.p("repo")).join(&path), &text).unwrap();
        manifest["entries"].as_array_mut().unwrap().push(json!({"path":path,"extension":".md","corpus_role":"markdown_document_candidate",
            "size_bytes":text.len(),"raw_sha256":sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(text.as_bytes())),
            "references":{"commit_candidates":[],"pull_request_candidates":[]}}));
    }
    std::fs::write(fx.p("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(fx.p("select.txt"), manifest["entries"].as_array().unwrap().iter().map(|v| v["path"].as_str().unwrap()).collect::<Vec<_>>().join("\n"))
        .unwrap();
    std::fs::write(
        fx.p("subjects.json"),
        json!({"subjects":[{"token":W1,"role":"swarm","id":"w1"},
        {"token":W2,"role":"swarm","id":"w2"},{"token":GB,"role":"swarm","id":"w3"},{"token":OWN,"role":"owner","id":"own"}]})
        .to_string(),
    )
    .unwrap();
    let args = |fresh| {
        let mut a = fx.args(fresh);
        a.extend(["--dynamic-roles", "--circles", "--wave-sections", "3", "--builder-max-records", "1", "--agent-timeout-ms", "10000"].map(str::to_string));
        a
    };
    fn batch(cs: &mut [Client; 3]) -> Vec<Value> {
        let mut out = vec![Value::Null; 3];
        for _ in 0..2 {
            for i in 0..3 {
                if !out[i].is_null() {
                    continue;
                }
                let t = cs[i].call("audit_acquire", json!({}));
                if t["kind"] == "BUILD" {
                    out[i] = t;
                } else {
                    assert_eq!(t["status"], "WAIT", "{t}");
                }
            }
        }
        assert!(out.iter().all(|t| t["kind"] == "BUILD"), "{out:?}");
        out
    }
    let server = Server::start(&args(true));
    let mut cs = [Client::connect(server.port, W1), Client::connect(server.port, W2), Client::connect(server.port, GB)];
    let mut own = Client::connect(server.port, OWN);
    for c in &mut cs {
        let t = c.call("audit_acquire", json!({}));
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(t["circle_phase"], "READ");
        assert_eq!(c.call("audit_submit", json!({"task_id":t["task_id"],"lines":answer(&t)}))["status"], "COMMITTED");
    }
    assert_eq!(cs[0].call("audit_acquire", json!({}))["status"], "WAIT", "first reader waits for the shared barrier");
    let tasks = batch(&mut cs);
    assert_eq!(own.call("audit_status", json!({}))["open_builder_cards"], 3);
    let old = tasks[1]["task_id"].clone();
    let card = tasks[1]["card_id"].clone();
    assert_eq!(cs[0].call("audit_release", json!({"task_id":old,"timed_out":true}))["code"], "TASK_NOT_OWNED");
    assert_eq!(cs[1].call("audit_release", json!({"task_id":old,"timed_out":true}))["status"], "RELEASED");
    for i in [0, 2] {
        assert_eq!(cs[i].call("audit_submit", json!({"task_id":tasks[i]["task_id"],"lines":[]}))["status"], "CARD_DONE");
    }
    let replacement = cs[2].call("audit_acquire", json!({}));
    assert_eq!(replacement["card_id"], card);
    assert_ne!(replacement["task_id"], old);
    let before = own.call("audit_status", json!({}));
    assert_eq!(cs[1].call("audit_submit", json!({"task_id":old,"lines":[]}))["status"], "STALE_TASK");
    assert_eq!(own.call("audit_status", json!({}))["audit_root"], before["audit_root"]);
    drop(server);
    let server = Server::start(&args(false));
    cs = [Client::connect(server.port, W1), Client::connect(server.port, W2), Client::connect(server.port, GB)];
    own = Client::connect(server.port, OWN);
    let restored = own.call("audit_status", json!({}));
    assert_eq!(restored["audit_root"], before["audit_root"]);
    assert!(restored["circles"]["excluded"].as_array().unwrap().contains(&json!("w2")));
    assert_eq!(cs[0].call("audit_acquire", json!({}))["status"], "WAIT");
    let retry = cs[2].call("audit_acquire", json!({}));
    assert_eq!(retry["card_id"], card);
    assert_eq!(cs[1].call("audit_acquire", json!({}))["status"], "WAIT", "return is queued while substitute is working");
    let step = own.call("audit_status", json!({}))["circles"]["sync_step"].clone();
    assert_eq!(cs[2].call("audit_submit", json!({"task_id":retry["task_id"],"lines":[]}))["status"], "CARD_DONE");
    let resumed = own.call("audit_status", json!({}));
    assert_eq!(resumed["circles"]["circle_phase"], "BUILD");
    assert!(resumed["circles"]["sync_step"].as_u64() > step.as_u64());
    assert!(!resumed["circles"]["excluded"].as_array().unwrap().contains(&json!("w2")));
    let next = batch(&mut cs);
    assert_eq!(next[1]["kind"], "BUILD", "recovered agent joins the current BUILD phase");
    drop(server);
    let refused = std::process::Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(fx.args(false)).output().unwrap();
    assert!(!refused.status.success(), "circle WAL must not resume without its bound mode");
}

#[test]
fn a_base_ontology_file_seeds_the_genesis_and_a_resume_cannot_swap_it() {
    let fx = Fixture::new("base_ontology");
    let mut base = sbgk_core::audit::onto::AuditOntology::base();
    base["concepts"] = json!([{"type": "Component", "name": "seeded topic engine", "aliases": ["topic engine"]}]);
    std::fs::write(fx.0.join("base.json"), base.to_string()).unwrap();
    let mut args = fx.args(true);
    args.extend(["--base-ontology".to_string(), fx.p("base.json")]);
    let server = Server::start(&args);
    drop(server);
    let journal = String::from_utf8_lossy(&std::fs::read(fx.0.join("run.wal")).unwrap()).to_string();
    assert!(journal.contains("seeded topic engine"), "the genesis keeps the seed concepts");
    let mut resume = fx.args(false);
    resume.extend(["--base-ontology".to_string(), fx.p("base.json")]);
    let refused = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(&resume).output().unwrap();
    let text = String::from_utf8_lossy(&refused.stdout).to_string() + &String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success() && text.contains("resume it without --base-ontology"), "{text}");
}

#[test]
fn revision_policy_is_opt_in_seed_is_provisional_and_snapshot_is_owner_only() {
    let fx = Fixture::new("ontology_revision");
    let subjects = json!({"subjects":[{"token":W1,"role":"swarm","id":"w1"},{"token":W2,"role":"swarm","id":"w2"},{"token":GB,"role":"swarm","id":"w3"},{"token":OWN,"role":"owner","id":"own"}]});
    std::fs::write(fx.p("subjects.json"), subjects.to_string()).unwrap();
    let mut base = sbgk_core::audit::onto::AuditOntology::base();
    base["concepts"] = json!([{"type":"Component","name":"topic engine","aliases":["topic"]}]);
    std::fs::write(fx.p("base.json"), base.to_string()).unwrap();
    let args = |fresh| {
        let mut a = fx.args(fresh);
        a.extend(["--dynamic-roles", "--circles", "--ontology-revisions"].map(str::to_string));
        if fresh {
            a.extend(["--base-ontology".to_string(), fx.p("base.json")]);
        }
        a
    };
    let server = Server::start(&args(true));
    let mut own = Client::connect(server.port, OWN);
    let mut w1 = Client::connect(server.port, W1);
    assert_eq!(w1.call("audit_status", json!({"ontology":true}))["code"], -32003);
    let snapshot = own.call("audit_status", json!({"ontology":true}));
    assert!(snapshot.get("ontology_revision").is_some(), "{snapshot}");
    let ontology = &snapshot["ontology_revision"]["ontology"];
    assert_eq!(ontology["concepts"][0]["status"], "provisional");
    assert_eq!(ontology["base"]["seed_status"], "provisional");
    assert_eq!(snapshot["ontology_revision"]["policy"]["rule"], "next_nonproposer/1");
    let root = snapshot["audit_root"].clone();
    drop(w1);
    drop(own);
    drop(server);
    let server = Server::start(&args(false));
    let mut own = Client::connect(server.port, OWN);
    assert_eq!(own.call("audit_status", json!({}))["audit_root"], root);
    drop(own);
    drop(server);
    let mut mismatch = args(false);
    mismatch.extend(["--ontology-unmapped-circles", "4"].map(str::to_string));
    let result = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(mismatch).output().unwrap();
    assert!(!result.status.success());
    assert!((String::from_utf8_lossy(&result.stdout).to_string() + &String::from_utf8_lossy(&result.stderr)).contains("thresholds must match"));
}

#[test]
fn committed_circle_telemetry_is_owner_only_read_only_and_restored() {
    let fx = Fixture::new("circle_telemetry");
    let server = Server::start(&fx.args(true));
    let mut own = Client::connect(server.port, OWN);
    let mut worker = Client::connect(server.port, W1);
    let denied = worker.call("audit_status", json!({"telemetry":true}));
    assert_eq!(denied["code"], -32003);
    let a = own.call("audit_status", json!({"telemetry":true}));
    let b = own.call("audit_status", json!({"telemetry":true}));
    assert_eq!(a["audit_root"], b["audit_root"]);
    assert_eq!(a["circle_telemetry"], b["circle_telemetry"]);
    assert_eq!(a["circle_telemetry"]["complete"], true);
    #[cfg(windows)]
    {
        let err = std::fs::read(fx.p("run.wal")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(33));
        eprintln!("exclusive WAL owner server pid={}", server.child.id());
    }
    drop(worker);
    drop(own);
    drop(server);
    assert!(!std::fs::read(fx.p("run.wal")).unwrap().is_empty());
    let server = Server::start(&fx.args(false));
    let mut own = Client::connect(server.port, OWN);
    let restored = own.call("audit_status", json!({"telemetry":true}));
    assert_eq!(restored["circle_telemetry"], a["circle_telemetry"]);
}

#[test]
fn opt_in_c0_agent_failures_are_authenticated_and_restart_with_the_same_bound() {
    let f = Fixture::new("c0-failover");
    let mut args = f.args(true);
    args.extend(["--agent-attempts".into(), "2".into()]);
    let server = Server::start(&args);
    let mut w = Client::connect(server.port, W1);
    let mut other = Client::connect(server.port, W2);
    let mut gb = Client::connect(server.port, GB);
    assert!(gb.tools().contains(&"audit_builder_failure".into()));
    let a = w.call("audit_acquire", json!({}));
    assert_eq!(a["kind"], "EXTEND");
    assert_eq!(other.call("audit_release", json!({"task_id":a["task_id"],"timed_out":true}))["code"], "TASK_NOT_OWNED");
    assert_eq!(w.call("audit_release", json!({"task_id":a["task_id"],"timed_out":true}))["failures"], 1);
    drop(w);
    drop(other);
    drop(gb);
    drop(server);
    let mut args = f.args(false);
    args.extend(["--agent-attempts".into(), "2".into()]);
    let server = Server::start(&args);
    let mut w = Client::connect(server.port, W1);
    let b = w.call("audit_acquire", json!({}));
    assert_eq!(b["key"], a["key"]);
    assert_ne!(b["task_id"], a["task_id"]);
    assert_eq!(w.call("audit_release", json!({"task_id":b["task_id"],"timed_out":true}))["unresolved"], true);
    let mut own = Client::connect(server.port, OWN);
    let status = own.call("audit_status", json!({}));
    assert_eq!(status["agent_failures"]["work"][a["key"].as_str().unwrap()]["failures"], 2);
    let next = w.call("audit_acquire", json!({}));
    assert_ne!(next["key"], a["key"]);
    let f = Fixture::new("legacy-tool-list");
    let server = Server::start(&f.args(true));
    let mut gb = Client::connect(server.port, GB);
    assert!(!gb.tools().contains(&"audit_builder_failure".into()));
}

#[test]
fn end_attestation_flag_waits_for_reading_and_builder_then_is_pinned_on_resume() {
    let f = Fixture::new("unattested-end");
    let mut base = sbgk_core::audit::onto::AuditOntology::base();
    base["seed_status"] = json!("provisional");
    base["concepts"] = json!([{"type":"Component","name":"unused synthetic component","aliases":[]}]);
    std::fs::write(f.0.join("base.json"), base.to_string()).unwrap();
    let mut args = f.args(true);
    args.extend(["--base-ontology".into(), f.p("base.json"), "--unattested-at-end".into()]);
    let server = Server::start(&args);
    let mut own = Client::connect(server.port, OWN);
    let mut w = Client::connect(server.port, W1);
    let mut gb = Client::connect(server.port, GB);
    let before = own.call("audit_status", json!({"ontology":true}));
    assert_eq!(before["ontology_revision"]["ontology"]["concepts"][0]["status"], "provisional");
    for _ in 0..20 {
        let t = w.call("audit_acquire", json!({}));
        if t["kind"] == "EXTEND" {
            assert_eq!(w.call("audit_submit", json!({"task_id":t["task_id"],"lines":answer(&t)}))["status"], "COMMITTED");
        } else {
            break;
        }
    }
    let mid = own.call("audit_status", json!({"ontology":true}));
    assert_eq!(mid["ontology_revision"]["ontology"]["concepts"][0]["status"], "provisional");
    catch_up(&mut gb);
    let end = own.call("audit_status", json!({"ontology":true}));
    assert_eq!(end["ontology_revision"]["ontology"]["concepts"][0]["status"], "unattested", "{end}");
    let root = end["audit_root"].clone();
    assert_eq!(own.call("audit_status", json!({"ontology":true}))["audit_root"], root);
    drop(w);
    drop(gb);
    drop(own);
    drop(server);
    let refused = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(f.args(false)).output().unwrap();
    assert!(!refused.status.success());
    let mut resume = f.args(false);
    resume.push("--unattested-at-end".into());
    let server = Server::start(&resume);
    let mut own = Client::connect(server.port, OWN);
    assert_eq!(own.call("audit_status", json!({"ontology":true}))["ontology_revision"]["ontology"]["concepts"][0]["status"], "unattested");
}

#[test]
fn evolution_pairing_is_taken_and_checked() {
    // the strongest graph's pre-flight (31.10): the server dropped --evolution-pairing, and the run would have paired by concepts
    let f = Fixture::new("pairing");
    let mut args = f.args(true);
    args.extend(["--evolution-cards", "--evolution-pairing", "lexical"].map(String::from));
    let server = Server::start(&args);
    let mut owner = Client::connect(server.port, OWN);
    let st = owner.call("audit_status", json!({}));
    assert_eq!(st["graph_quality"]["config"]["evolution_pairing"], "lexical", "{st}");
    drop(owner);
    drop(server);
    for bad in [["--evolution-cards", "--evolution-pairing", "words"].as_slice(), ["--evolution-pairing", "lexical"].as_slice()] {
        let g = Fixture::new("pairing_bad");
        let out = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(g.args(true)).args(bad).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains("--evolution-pairing"), "{bad:?}: {err}");
    }
}

#[test]
fn concept_functions_are_taken_and_their_summaries_need_them() {
    // the address layer (01.11.2026): the server takes the layer, its default pairs per function, and declared change summaries
    let f = Fixture::new("functions");
    let docs = std::env::temp_dir().join(format!("summaries-{}.json", std::process::id()));
    std::fs::write(&docs, "[\"docs/changelog.mdx\"]").unwrap();
    let mut args = f.args(true);
    args.extend(["--evolution-cards", "--evolution-pairing", "lexical", "--concept-functions", "--change-summary-documents"].map(String::from));
    args.push(docs.to_string_lossy().into_owned());
    let server = Server::start(&args);
    let mut owner = Client::connect(server.port, OWN);
    let cfg = owner.call("audit_status", json!({}))["graph_quality"]["config"].clone();
    assert_eq!(
        (&cfg["concept_functions"], &cfg["evolution_pairs_per_function"], &cfg["change_summary_documents"]),
        (&json!(true), &json!(3), &json!(["docs/changelog.mdx"])),
        "{cfg}"
    );
    drop(owner);
    drop(server);
    let path = docs.to_string_lossy().into_owned();
    for (bad, flag) in [
        (vec!["--evolution-cards", "--evolution-pairing", "lexical", "--change-summary-documents", path.as_str()], "--change-summary-documents"),
        (vec!["--evolution-pairs-per-function", "2"], "--evolution-pairs-per-function"),
        (vec!["--concept-functions", "--evolution-pairs-per-function", "0"], "--evolution-pairs-per-function"),
    ] {
        let g = Fixture::new("functions_bad");
        let out = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(g.args(true)).args(&bad).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains(flag), "{bad:?}: {err}");
    }
    let _ = std::fs::remove_file(&docs);
}

#[test]
fn graph_quality_modes_are_pinned_and_legacy_inventory_is_preserved() {
    let f = Fixture::new("graph_quality_modes");
    let extra = vec![
        "--term-hygiene".into(),
        "--candidate-match".into(),
        "strict".into(),
        "--known-concepts".into(),
        "all".into(),
        "--link-both-sides".into(),
        "--stale-suspect".into(),
        "--evolution-cards".into(),
    ];
    let mut args = f.args(true);
    args.extend(extra.clone());
    let server = Server::start(&args);
    let mut owner = Client::connect(server.port, OWN);
    let st = owner.call("audit_status", json!({}));
    assert_eq!(st["graph_quality"]["config"]["candidate_match"], "strict", "{st}");
    assert_eq!(st["graph_quality"]["config"]["known_concepts"], "all", "{st}");
    let root = st["audit_root"].clone();
    let tools = owner.tools();
    drop(owner);
    drop(server);
    let bad = Command::new(BIN).args(["audit-serve", "--profile", "custom"]).args(f.args(false)).output().unwrap();
    assert!(!bad.status.success());
    let mut args = f.args(false);
    args.extend(extra);
    let server = Server::start(&args);
    let mut owner = Client::connect(server.port, OWN);
    assert_eq!(owner.call("audit_status", json!({}))["audit_root"], root);
    assert_eq!(owner.tools(), tools);
}

#[test]
fn without_flags_audit_serve_runs_the_measured_v01_profile() {
    // "download, run, get what was measured": no graph builder, reading in circles with dynamic roles
    let fx = Fixture::new("profile");
    let readers = |n: usize| {
        let mut s: Vec<Value> = [(W1, "w1"), (W2, "w2"), (GB, "w3")][..n].iter().map(|(t, id)| json!({"token":t,"role":"swarm","id":id})).collect();
        s.push(json!({"token":OWN,"role":"owner","id":"own"}));
        std::fs::write(fx.p("subjects.json"), json!({ "subjects": s }).to_string()).unwrap();
    };
    // a dedicated builder has no place in the profile: the refusal names the profile
    std::fs::write(
        fx.p("subjects.json"),
        json!({"subjects":[{"token":W1,"role":"swarm","id":"w1"},{"token":W2,"role":"swarm","id":"w2"},
            {"token":GB,"role":"builder","id":"gb"},{"token":OWN,"role":"owner","id":"own"}]})
        .to_string(),
    )
    .unwrap();
    let out = Command::new(BIN).arg("audit-serve").args(fx.args(true)).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("the v0.1 profile has no graph builder"), "{text}");
    let _ = std::fs::remove_file(fx.p("run.wal"));
    readers(2);
    let out = Command::new(BIN).arg("audit-serve").args(fx.args(true)).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("the v0.1 profile reads in circles"), "{text}");
    let _ = std::fs::remove_file(fx.p("run.wal"));
    readers(3);
    let mut child = Command::new(BIN).args(["audit-serve", "--listen", "127.0.0.1:0"]).args(fx.args(true)).stdout(Stdio::piped()).spawn().unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
    let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("first line {first:?}: {e}"));
    assert_eq!(hello["status"], "listening", "{hello}");
    let mut own = Client::connect(hello["port"].as_u64().unwrap() as u16, OWN);
    let status = own.call("audit_status", json!({}));
    assert_eq!(status["build_scope"], "none", "{status}");
    let mut w1 = Client::connect(hello["port"].as_u64().unwrap() as u16, W1);
    assert_eq!(w1.call("audit_acquire", json!({}))["kind"], "EXTEND", "the circle's first wave reads");
    let _ = child.kill();
    let _ = child.wait();
}

/// A changed last byte makes the final entry a torn tail. Without a receipt that must not read as a clean pass, and a server that
/// resumes on it must say so and keep the bytes: a crash and a change look the same from inside the file.
#[test]
fn a_journal_whose_last_entry_is_damaged_is_not_a_clean_pass_and_recovery_reports_and_keeps_the_tail() {
    let fx = Fixture::new("torn");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    let t = w1.call("audit_acquire", json!({}));
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let end = own.call("audit_status", json!({}));
    drop(server);

    let wal = fx.p("run.wal");
    let mut bytes = std::fs::read(&wal).unwrap();
    let whole = bytes.clone();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&wal, &bytes).unwrap();
    let verify = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-verify").args(args).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap())
    };
    let (code, v) = verify(&["--wal", &wal]);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("TORN_TAIL")), "{v}");
    assert!(v["torn_tail_bytes"].as_u64().unwrap() > 0, "{v}");
    let receipt = fx.p("end.json");
    std::fs::write(&receipt, json!({"audit_root": end["audit_root"], "engine_root": end["engine_root"]}).to_string()).unwrap();
    let (code, m) = verify(&["--wal", &wal, "--expect", &receipt]);
    assert_eq!((code, m["status"].as_str()), (Some(1), Some("MISMATCH")), "{m}");

    let resumed = Server::start(&fx.args(false));
    let hello = resumed.hello.clone();
    drop(resumed);
    let dropped = hello["audit"]["torn_tail_bytes"].as_u64().expect("the hello line reports the cut");
    let kept = hello["audit"]["torn_tail_kept_in"].as_str().expect("and names the file that keeps it");
    assert_eq!(std::fs::read(kept).unwrap(), bytes[bytes.len() - dropped as usize..]);
    assert_eq!(std::fs::read(&wal).unwrap().len(), whole.len() - dropped as usize, "the journal resumes before the tail");
}

/// The warning about a cut tail comes right after the recovery, so a start that a later check stops does not lose it: the cut stays
/// done, and the operator has only this message and the kept file.
#[test]
fn a_start_refused_after_the_recovery_still_says_that_the_tail_was_cut() {
    let fx = Fixture::new("tornstart");
    let server = Server::start(&fx.args(true));
    let mut w1 = Client::connect(server.port, W1);
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    drop(server);
    let wal = fx.p("run.wal");
    let mut bytes = std::fs::read(&wal).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&wal, &bytes).unwrap();
    let out = Command::new(BIN)
        .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0", "--section-bytes", "4096"])
        .args(fx.args(false))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("no complete entry") && said.contains("kept_in"), "{said}");
    assert!(said.contains("the stored configuration differs"), "{said}");
}

/// A flag that needs no journal is settled before the journal is touched: a torn tail stays where it is.
#[test]
fn a_mistyped_flag_leaves_a_torn_journal_as_it_was() {
    let fx = Fixture::new("tornflag");
    let server = Server::start(&fx.args(true));
    let mut w1 = Client::connect(server.port, W1);
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    drop(server);
    let wal = fx.p("run.wal");
    let mut bytes = std::fs::read(&wal).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&wal, &bytes).unwrap();
    let missing = fx.p("no-such-zones.json");
    let bad: Vec<Vec<&str>> = vec![
        vec!["--zones", &missing],
        vec!["--max-lines", "abc"],
        vec!["--summary-records", "abc"],
        vec!["--auto-rereads", "abc"],
        vec!["--builder-requests", "abc"],
        vec!["--backpressure-records", "abc"],
        vec!["--backpressure-per-task", "abc"],
        vec!["--backpressure-stall-ms", "abc"],
        vec!["--ontology-unmapped-circles", "abc"],
        vec!["--ontology-catchall-mappings", "abc"],
        vec!["--ontology-catchall-reports", "abc"],
        vec!["--term-max-words", "0"],
        vec!["--candidate-match", "abc"],
        vec!["--gap-pass", "abc"],
        vec!["--gap-units", "9"],
        vec!["--gap-profile", &missing],
    ];
    for flags in bad {
        let out = Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(&flags).args(fx.args(false)).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{flags:?}");
        assert_eq!(std::fs::read(&wal).unwrap(), bytes, "{flags:?}: not cut, and nothing added");
    }
}

/// A start that fails once the new run exists takes the new journal away: the same command can be given again.
#[test]
fn a_start_refused_after_the_run_was_created_leaves_no_journal() {
    let fx = Fixture::new("newrefused");
    let zones = fx.p("zones.json");
    std::fs::write(&zones, json!([["no/such/report.md"]]).to_string()).unwrap();
    let out =
        Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0", "--zones", &zones]).args(fx.args(true)).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--zones"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!std::path::Path::new(&fx.p("run.wal")).exists(), "the refused start left its journal");
    drop(Server::start(&fx.args(true)));
}

/// A resume that does not fit the stored settings is refused before anything is written: the version map of `--build-scope
/// versions` was written first and the start was refused after it, so a refused start grew the journal.
#[test]
fn a_refused_resume_leaves_the_journal_byte_for_byte() {
    let fx = Fixture::new("refusedresume");
    let file = fx.p("subjects.json");
    let mut subjects: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let list = if subjects.is_array() { &mut subjects } else { &mut subjects["subjects"] };
    list.as_array_mut().unwrap().retain(|s| s["role"] != "builder");
    std::fs::write(&file, subjects.to_string()).unwrap();
    let mut first = fx.args(true);
    first.extend(["--build-scope".to_string(), "none".to_string()]);
    drop(Server::start(&first));
    let wal = fx.p("run.wal");
    let before = std::fs::read(&wal).unwrap();
    for flags in [&["--build-scope", "versions"][..], &["--build-scope", "none", "--section-bytes", "4096"][..]] {
        let out = Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(flags).args(fx.args(false)).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{flags:?}");
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(said.contains("the stored configuration differs"), "{flags:?}: {said}");
        assert_eq!(std::fs::read(&wal).unwrap(), before, "{flags:?} wrote to the journal");
    }
}

/// `--at-end` asks more of a receipt: its state must be the journal's last, so an entry written after it is a mismatch.
#[test]
fn at_end_refuses_a_journal_that_went_on_after_the_receipt() {
    let fx = Fixture::new("atend");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    let t = w1.call("audit_acquire", json!({}));
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let before = own.call("audit_status", json!({}));
    let quote = r["accepted"].as_array().expect("accepted records")[0].clone();
    assert_eq!(own.call("audit_revoke", json!({"record": quote}))["status"], "REVOKED");
    drop(server);
    let receipt = fx.p("before.json");
    std::fs::write(&receipt, json!({"audit_root": before["audit_root"], "engine_root": before["engine_root"]}).to_string()).unwrap();
    let wal = fx.p("run.wal");
    let verify = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-verify").args(args).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let (code, v) = verify(&["--wal", &wal, "--expect", &receipt]);
    assert_eq!((code, v["status"].as_str(), v["expected"]["at_end"].as_bool()), (Some(0), Some("VERIFIED"), Some(false)), "{v}");
    let (code, v) = verify(&["--wal", &wal, "--expect", &receipt, "--at-end"]);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("MISMATCH")), "{v}");
    assert_eq!(verify(&["--wal", &wal, "--at-end"]).0, Some(2), "it needs a receipt");

    // the revocation damaged in its last byte: the receipt's state is now the last whole entry, and what follows it may be what is lost
    let mut bytes = std::fs::read(&wal).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&wal, &bytes).unwrap();
    let (code, v) = verify(&["--wal", &wal, "--expect", &receipt]);
    assert_eq!((code, v["expected"]["at_end"].as_bool()), (Some(0), Some(false)), "{v}");
    let (code, v) = verify(&["--wal", &wal, "--expect", &receipt, "--at-end"]);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("MISMATCH")), "bytes after the state are not the end: {v}");
}

#[test]
fn a_port_that_is_taken_leaves_no_journal_behind() {
    let fx = Fixture::new("port");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();
    let out = Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", &addr]).args(fx.args(true)).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!std::path::Path::new(&fx.p("run.wal")).exists(), "nothing durable before the socket is bound");
}

#[test]
fn audit_verify_of_a_file_it_cannot_read_is_an_error_of_the_call_not_a_refused_journal() {
    let out = Command::new(BIN).args(["audit-verify", "--wal", "no-such-file.wal"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty() && String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}

#[test]
fn audit_verify_replays_a_recorded_journal_without_writing_it_and_finds_the_states_its_receipts_name() {
    let fx = Fixture::new("verify");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    let t = w1.call("audit_acquire", json!({}));
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let phase = own.call("audit_status", json!({}));
    let observe = r["accepted_locals"]
        .as_object()
        .unwrap()
        .values()
        .map(|id| own.call("audit_record", json!({"record": id})))
        .find(|rec| rec["kind"] == "observe")
        .expect("an accepted observe");
    assert_eq!(own.call("audit_revoke", json!({"record": observe["id"]}))["status"], "REVOKED");
    let end = own.call("audit_status", json!({}));
    drop(server);

    let wal = fx.p("run.wal");
    let before = std::fs::read(&wal).unwrap();
    let verify = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-verify").args(args).output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
        (out.status.code(), v)
    };
    let (code, v) = verify(&["--wal", &wal]);
    assert_eq!((code, v["status"].as_str()), (Some(0), Some("VERIFIED")), "{v}");
    assert_eq!((&v["audit_root"], &v["engine_root"], &v["records"]), (&end["audit_root"], &end["engine_root"], &end["records"]), "{v} vs {end}");
    assert_eq!((v["run_id"].as_str(), v["torn_tail_bytes"].as_u64()), (Some("wire-run"), Some(0)));
    assert_eq!(std::fs::read(&wal).unwrap(), before, "the journal is read from a private copy, never written");

    let receipt = |name: &str, body: Value| {
        std::fs::write(fx.0.join(name), body.to_string()).unwrap();
        fx.p(name)
    };
    let at_phase = receipt("phase.json", json!({"audit_root": phase["audit_root"], "engine_root": phase["engine_root"]}));
    let (code, p) = verify(&["--wal", &wal, "--expect", &at_phase]);
    assert_eq!((code, p["status"].as_str(), p["expected"]["at_end"].as_bool()), (Some(0), Some("VERIFIED"), Some(false)), "{p}");
    assert!(p["expected"]["found_after_entries"].as_u64().unwrap() < v["entries"].as_u64().unwrap(), "{p}");
    let at_end = receipt("end.json", json!({"audit_root": v["audit_root"], "engine_root": v["engine_root"], "session_root": v["session_root"]}));
    let (code, e) = verify(&["--wal", &wal, "--expect", &at_end]);
    assert_eq!((code, e["expected"]["at_end"].as_bool(), e["expected"]["session_root_matches"].as_bool()), (Some(0), Some(true), Some(true)), "{e}");

    // a close stamp has no engine root; its wal_head binds the chain, not only the state
    let stamp = receipt("close.json", json!({"audit_root": v["audit_root"], "wal_head": v["wal_head"]}));
    let (code, c) = verify(&["--wal", &wal, "--expect", &stamp]);
    assert_eq!((code, c["expected"]["at_end"].as_bool(), &c["expected"]["session_root_matches"]), (Some(0), Some(true), &Value::Null), "{c}");
    let phase_head = receipt(
        "phase_head.json",
        json!({"audit_root": phase["audit_root"], "engine_root": phase["engine_root"],
                                                        "wal_head": phase["wal_head"]}),
    );
    let (code, h) = verify(&["--wal", &wal, "--expect", &phase_head]);
    assert_eq!((code, h["expected"]["at_end"].as_bool()), (Some(0), Some(false)), "the head after the phase's own frames: {h}");
    let end_head_at_phase = receipt("mixed.json", json!({"audit_root": phase["audit_root"], "wal_head": v["wal_head"]}));
    let (code, m) = verify(&["--wal", &wal, "--expect", &end_head_at_phase]);
    assert_eq!((code, m["status"].as_str()), (Some(1), Some("MISMATCH")), "a head of another prefix: {m}");

    let zero = "0".repeat(64);
    let foreign = receipt("foreign.json", json!({"audit_root": zero, "engine_root": v["engine_root"]}));
    let (code, f) = verify(&["--wal", &wal, "--expect", &foreign]);
    assert_eq!((code, f["status"].as_str()), (Some(1), Some("MISMATCH")), "{f}");
    let foreign_head = receipt("head.json", json!({"audit_root": v["audit_root"], "wal_head": zero}));
    let (code, fh) = verify(&["--wal", &wal, "--expect", &foreign_head]);
    assert_eq!((code, fh["status"].as_str()), (Some(1), Some("MISMATCH")), "{fh}");
    let bad_hex = receipt("bad.json", json!({"audit_root": v["audit_root"], "wal_head": "not a hash"}));
    let out = Command::new(BIN).args(["audit-verify", "--wal", &wal, "--expect", &bad_hex]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "a malformed receipt is a usage error");
    let wrong_session = receipt("session.json", json!({"audit_root": v["audit_root"], "engine_root": v["engine_root"], "session_root": zero}));
    let (code, s) = verify(&["--wal", &wal, "--expect", &wrong_session]);
    assert_eq!((code, s["status"].as_str(), s["expected"]["session_root_matches"].as_bool()), (Some(1), Some("MISMATCH"), Some(false)), "{s}");

    // one byte of the genesis changed, the JSON still valid: the frame hash refuses the copy
    let text = String::from_utf8(before.clone()).unwrap();
    let edited = fx.0.join("edited.wal");
    std::fs::write(&edited, text.replacen("wire-run", "wire-rux", 1)).unwrap();
    let (code, x) = verify(&["--wal", &edited.display().to_string()]);
    assert_eq!((code, x["status"].as_str()), (Some(1), Some("REFUSED")), "{x}");
    assert!(x["error"]["message"].as_str().unwrap().contains("hash mismatch"), "{x}");
}

/// The reading tools of 0.2 on the wire and over the journal (SPEC_V02_STEP3): a withdrawal names the point before it, the report
/// from that point names the claim that fell without the withdrawn text, and `sbgk audit-read` over the stopped journal answers as
/// the live server did.
#[test]
fn the_reading_tools_answer_alike_on_the_wire_and_over_the_journal() {
    let fx = Fixture::new("read");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    let tools = own.tools();
    for tool in ["audit_dependents", "audit_active_claims", "audit_diff", "audit_fallen"] {
        assert!(tools.iter().any(|t| t == tool), "{tool}: {tools:?}");
    }
    assert!(!w1.tools().iter().any(|t| t == "audit_fallen"), "the reading tools are the owner's");
    let t = w1.call("audit_acquire", json!({}));
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let records: Vec<Value> = r["accepted_locals"].as_object().unwrap().values().map(|id| own.call("audit_record", json!({"record": id}))).collect();
    let observe = records.iter().find(|x| x["kind"] == "observe").expect("an observe").clone();
    let claim = records.iter().find(|x| x["kind"] == "claim").expect("a claim").clone();
    assert_eq!((claim["projection"]["fallen_by"].clone(), claim["dependents_direct"].clone()), (json!([]), json!(0)), "{claim}");
    let withdrawn = own.call("audit_revoke", json!({"record": observe["id"]}));
    assert_eq!(
        (withdrawn["status"].as_str(), withdrawn["fell"].as_u64(), withdrawn["quotes_gone"].as_u64()),
        (Some("REVOKED"), Some(1), Some(1)),
        "{withdrawn}"
    );
    let since = withdrawn["since"].as_u64().expect("the point before the withdrawal");
    let status = own.call("audit_status", json!({}));
    assert_eq!((status["projections"]["fallen"].clone(), status["projections"]["quotes_gone"].clone()), (json!(1), json!(1)), "{status}");
    let report = own.call("audit_fallen", json!({"since": since}));
    assert_eq!((report["rows"][0]["id"].clone(), report["rows"][0]["gone"][0]["id"].clone()), (claim["id"].clone(), observe["id"].clone()), "{report}");
    assert!(!report.to_string().contains(observe["quote"].as_str().unwrap()), "the withdrawn text stays out of the report: {report}");
    let diff = own.call("audit_diff", json!({"from": since}));
    assert_eq!(diff["fell"]["count"], 2, "the quote and the claim on it: {diff}");
    let dependents = own.call("audit_dependents", json!({"record": observe["id"]}));
    assert_eq!(dependents["dependents"][0]["id"], claim["id"], "{dependents}");
    let active = own.call("audit_active_claims", json!({}));
    let record = own.call("audit_record", json!({"record": claim["id"]}));
    assert_eq!(record["first_causes"][0]["cause"], "withdrawn", "{record}");
    assert_eq!(own.call("audit_diff", json!({"from": 0}))["code"], "BAD_ARGUMENT");
    assert_eq!(own.call("audit_fallen", json!({"since": 1_000_000}))["code"], "BAD_ARGUMENT");
    drop(server);

    let wal = fx.p("run.wal");
    let read = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-read").args(args).args(["--wal", &wal]).output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!({"stderr": String::from_utf8_lossy(&out.stderr)}));
        (out.status.code(), v)
    };
    let since = since.to_string();
    let observe_id = observe["id"].as_str().unwrap().to_string();
    let claim_id = claim["id"].as_str().unwrap().to_string();
    assert_eq!(read(&["fallen", "--since", &since]), (Some(0), report));
    assert_eq!(read(&["diff", "--from", &since]), (Some(0), diff));
    assert_eq!(read(&["dependents", "--record", &observe_id]), (Some(0), dependents));
    assert_eq!(read(&["active-claims"]), (Some(0), active));
    assert_eq!(read(&["record", "--record", &claim_id]), (Some(0), record));
    let (code, offline) = read(&["status"]);
    assert_eq!((code, offline["projections"].clone()), (Some(0), status["projections"].clone()));
    // a journal changed by one byte is not read; an unknown tool is a usage error
    let edited = fx.0.join("edited.wal");
    std::fs::write(&edited, std::fs::read_to_string(&wal).unwrap().replacen("wire-run", "wire-rux", 1)).unwrap();
    let out = Command::new(BIN).args(["audit-read", "status", "--wal", &edited.display().to_string()]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(Command::new(BIN).args(["audit-read", "everything", "--wal", &wal]).output().unwrap().status.code(), Some(2));
}

/// Signed checkpoints on the wire (SPEC_V02_STEP4): a server with a signing key signs the seal it writes when the run is closed,
/// and `audit-verify` takes the checkpoint with the journal: pinned under the trusted keys, not pinned under the key beside it,
/// refused when the key is revoked or the checkpoint names other frames.
#[test]
fn a_server_with_a_signing_key_signs_its_seals_and_audit_verify_checks_them_with_the_journal() {
    let fx = Fixture::new("sign");
    let key = fx.p("operator.key");
    let made = Command::new(BIN).args(["keygen", "--name", "operator", "--out", &key]).output().unwrap();
    let made: Value = serde_json::from_slice(&made.stdout).unwrap();
    assert_eq!(made["status"], "KEY", "{made}");
    let verifier = made["verifier_key"].as_str().unwrap().to_string();
    assert!(!std::fs::read_to_string(&key).unwrap().contains(&verifier), "the key file holds the signing key, not only the verifier");
    assert_eq!(
        Command::new(BIN).args(["keygen", "--name", "operator", "--out", &key]).output().unwrap().status.code(),
        Some(2),
        "a key file is never overwritten"
    );
    let mut args = fx.args(true);
    args.extend(["--signing-key".to_string(), key.clone()]);
    let server = Server::start(&args);
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    for round in 0..20 {
        catch_up(&mut gb);
        let agent = if round % 2 == 0 { &mut w1 } else { &mut w2 };
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    drop(server);
    let wal = fx.p("run.wal");
    let dir = fx.0.join("run.wal.checkpoints");
    let mut seals: Vec<String> =
        std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.starts_with("seal-")).collect();
    seals.sort_by_key(|n| n[5..n.len() - 4].parse::<usize>().unwrap());
    let last = dir.join(seals.last().expect("a checkpoint for the seal of the close")).display().to_string();
    assert_eq!(std::fs::read_to_string(dir.join("verifier.key")).unwrap().trim(), verifier);
    let verify = |extra: &[&str]| {
        let out = Command::new(BIN).args(["audit-verify", "--wal", &wal, "--checkpoint"]).args(extra).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let (code, v) = verify(&[&last]);
    assert_eq!((code, v["checkpoint"]["signature"].as_str()), (Some(0), Some("signature valid, key not pinned")), "{v}");
    std::fs::write(fx.0.join("trusted.txt"), format!("{verifier} role=operator\n")).unwrap();
    let trusted = fx.p("trusted.txt");
    let (code, v) = verify(&[&last, "--trusted-keys", &trusted]);
    assert_eq!((code, v["checkpoint"]["signature"].as_str()), (Some(0), Some("signature valid, key pinned")), "{v}");
    std::fs::write(fx.0.join("revoked.txt"), format!("{verifier} role=operator revoked=2026-01-01\n")).unwrap();
    let revoked = fx.p("revoked.txt");
    assert_eq!(verify(&[&last, "--trusted-keys", &revoked]).0, Some(1), "a revoked key is refused");
    assert_eq!(verify(&[&last, "--trusted-keys", &revoked, "--anchored-at", "2025-12-31"]).0, Some(0), "kept from before the revocation");
    // the checkpoint of another prefix, signed by the same key, against this journal's first frames: refused
    let first = dir.join(&seals[0]).display().to_string();
    let text = std::fs::read_to_string(&first).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    let other = (lines[1].parse::<usize>().unwrap() + 1).to_string();
    lines[1] = &other;
    std::fs::write(fx.0.join("other.txt"), lines.join("\n") + "\n").unwrap();
    let (code, v) = verify(&[&fx.p("other.txt"), "--trusted-keys", &trusted]);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("CHECKPOINT_REFUSED")), "{v}");

    // a quittance of a standing claim under the checkpoint of the last seal, checked without the journal (SPEC_V02_STEP5)
    let claims = Command::new(BIN).args(["audit-read", "active-claims", "--wal", &wal]).output().unwrap();
    let claims: Value = serde_json::from_slice(&claims.stdout).unwrap();
    let claim = claims["groups"][0]["ids"][0].as_str().expect("a standing claim").to_string();
    let proof_file = fx.p("claim.proof.json");
    let cut =
        Command::new(BIN).args(["audit-proof", "--wal", &wal, "--record", &claim, "--self-contained", "--with-status", "--out", &proof_file]).output().unwrap();
    let stderr = String::from_utf8_lossy(&cut.stderr).to_string();
    let cut: Value = serde_json::from_slice(&cut.stdout).unwrap_or(Value::Null);
    assert_eq!(cut["status"], "PROOF", "{cut} {stderr}");
    // a quittance is never written over its own journal, in any spelling of its path (the review of the 0.2.0 release)
    let before = std::fs::read(&wal).unwrap();
    let folder = std::path::Path::new(&wal).parent().unwrap().display().to_string();
    let file = std::path::Path::new(&wal).file_name().unwrap().to_string_lossy().to_string();
    for out in [wal.clone(), format!("{folder}/./{file}")] {
        let r = Command::new(BIN).args(["audit-proof", "--wal", &wal, "--record", &claim, "--out", &out]).output().unwrap();
        let v: Value = serde_json::from_slice(&r.stdout).unwrap_or(Value::Null);
        assert_eq!((r.status.code(), v["status"].as_str()), (Some(1), Some("REFUSED")), "{out}: {v}");
        assert!(v["error"].as_str().unwrap().contains("its journal"), "{v}");
    }
    assert_eq!(std::fs::read(&wal).unwrap(), before, "the journal is untouched");
    std::fs::rename(&wal, fx.p("away.wal")).unwrap();
    let check = |extra: &[&str]| {
        let out = Command::new(BIN).args(["audit-proof-verify", "--proof", &proof_file]).args(extra).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let (code, v) = check(&["--trusted-keys", &trusted]);
    assert_eq!((code, v["status"].as_str(), v["signature"].as_str()), (Some(0), Some("PROOF_VALID"), Some("signature valid, key pinned")), "{v}");
    assert_eq!(v["standing"]["at_seal"][&claim], true, "{v}");
    assert!(v["quotes_checked_against_documents"].as_u64().unwrap() >= 1, "{v}");
    let seal_hash = v["seal"]["seal_hash"].as_str().unwrap().to_string();
    assert_eq!(check(&["--expect-seal", &seal_hash]).1["anchor"], "the seal is the anchored one");
    assert_eq!(check(&["--expect-seal", &"0".repeat(64)]).0, Some(1), "another anchored seal");
    assert_eq!(check(&["--trusted-keys", &revoked]).0, Some(1), "a revoked key");
    let mut bytes = std::fs::read(&proof_file).unwrap();
    let at = bytes.len() / 2;
    bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
    std::fs::write(&proof_file, bytes).unwrap();
    let (code, v) = check(&[]);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("PROOF_REFUSED")), "a byte changed: {v}");
}

/// A settings file in place of the flags (SPEC_V02_STEP6_7 section 7.4): it gives the run the settings hash the same flags give, its
/// relative paths are taken from its folder, the same file resumes the run, and a key it may not hold is refused.
#[test]
fn a_settings_file_stands_for_the_flags_of_the_server() {
    let fx = Fixture::new("settings");
    let settings = json!({"format": "yuce-settings/1", "wal": "run.wal", "subjects": "subjects.json", "questions": "questions.json",
                          "manifest": "manifest.json", "repo": "repo", "select": "select.txt", "run-id": "wire-run", "section-bytes": 4096});
    std::fs::write(fx.0.join("settings.json"), settings.to_string()).unwrap();
    let file = fx.p("settings.json");
    drop(Server::start(&["--settings".to_string(), file.clone()]));
    let genesis = |wal: &str| -> Value {
        let text = std::fs::read_to_string(wal).unwrap();
        serde_json::from_str::<Value>(text.lines().next().unwrap()).unwrap()["body"].clone()
    };
    let by_file = genesis(&fx.p("run.wal"));
    let fx2 = Fixture::new("settings_flags");
    let mut args = fx2.args(true);
    args.extend(["--section-bytes".to_string(), "4096".to_string()]);
    drop(Server::start(&args));
    let by_flags = genesis(&fx2.p("run.wal"));
    assert!(by_file["settings_hash"].is_string());
    assert_eq!(by_file["settings_hash"], by_flags["settings_hash"], "the file and the same flags give one settings hash");
    // the same file resumes the run: the flags that started it are the journal's now
    drop(Server::start(&["--settings".to_string(), file.clone()]));
    let refused = |bad: Value, extra: &[&str]| {
        std::fs::write(fx.0.join("bad.json"), bad.to_string()).unwrap();
        let out = Command::new(BIN)
            .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0", "--settings", &fx.p("bad.json")])
            .args(extra)
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).to_string())
    };
    for (bad, extra, why) in [
        (json!({"format": "yuce-settings/1", "nope": 1}), vec![], "no flag --nope"),
        (json!({"format": "yuce-settings/1", "circles": "yes"}), vec![], "is true"),
        (json!({"format": "yuce-settings/1", "wal": "x.wal"}), vec!["--wal", "y.wal"], "give it once"),
        (json!({"format": "yuce-settings/2", "wal": "x.wal"}), vec![], "yuce-settings/1"),
        (json!({"format": "yuce-settings/1", "section-bytes": 0.5}), vec![], "whole number"),
    ] {
        let (code, stderr) = refused(bad.clone(), &extra);
        assert_eq!(code, Some(2), "{bad}: {stderr}");
        assert!(stderr.contains(why), "{bad}: {stderr}");
    }
}

/// One agent on its own folder in one command (the architect, 11.11.2026): `--profile solo` without `--subjects` makes the subjects
/// itself, one reading agent and the owner, in a file beside the journal whose tokens are never printed; a question whose `about`
/// no document holds is said at the start and in the status, not lost in silence.
#[test]
fn one_agent_starts_on_its_own_folder_without_a_subjects_file() {
    let fx = Fixture::new("solo");
    let questions = json!([{"id": "RQ1", "text": "What do the reports establish about the topic?", "about": ["topic"]},
                           {"id": "RQ2", "text": "What do they say of zebras?", "about": ["zebra"]}]);
    std::fs::write(fx.0.join("solo_questions.json"), questions.to_string()).unwrap();
    let args: Vec<String> =
        ["--profile", "solo", "--docs", &fx.p("repo/reports"), "--questions", &fx.p("solo_questions.json"), "--wal", &fx.p("solo.wal"), "--run-id", "solo-run"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    let log = fx.0.join("solo.stderr");
    let server = Server::start_with_stderr(&args, Stdio::from(std::fs::File::create(&log).unwrap()));
    let made: Value = serde_json::from_str(&std::fs::read_to_string(fx.p("solo.wal.subjects.json")).unwrap()).unwrap();
    let subjects = made["subjects"].as_array().unwrap();
    assert_eq!(subjects.iter().map(|s| (s["role"].as_str().unwrap(), s["id"].as_str().unwrap())).collect::<Vec<_>>(), [("swarm", "agent"), ("owner", "owner")]);
    let token = |i: usize| subjects[i]["token"].as_str().unwrap().to_string();
    assert!(token(0).len() >= 32 && token(0) != token(1));
    let mut agent = Client::connect(server.port, &token(0));
    let task = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
    assert!(task["status"].is_string() && task["status"] != "error", "{task}");
    let mut owner = Client::connect(server.port, &token(1));
    let status = owner.call("audit_status", json!({}));
    let unmatched: Vec<&str> = status["about_unmatched"]["questions"].as_array().unwrap().iter().map(|q| q["question"].as_str().unwrap()).collect();
    assert_eq!(unmatched, ["RQ2"], "{status}");
    drop(server);
    let stderr = std::fs::read_to_string(&log).unwrap();
    assert!(stderr.contains("\"status\":\"subjects\"") && stderr.contains("no document of the run holds"), "{stderr}");
    assert!(!stderr.contains(&token(0)) && !stderr.contains(&token(1)), "the tokens are never printed");
    // resumed: the same subjects file, the same tokens
    let resume: Vec<String> = ["--profile", "solo", "--wal", &fx.p("solo.wal")].iter().map(|s| s.to_string()).collect();
    let server = Server::start(&resume);
    let mut agent = Client::connect(server.port, &token(0));
    let again = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
    assert!(again["status"].is_string() && again["status"] != "error", "the same token after the resume: {again}");
}

/// The index beside a journal (SPEC_V02_STEP6_7 section 6.5): built on a prefix and brought up to the whole journal it equals one
/// built at once; a row changed in the database is named by the check; what stands answers as the reading tool does; a journal
/// cut below the index is refused.
#[test]
fn the_index_beside_a_journal_is_rebuilt_from_it_and_checked_against_it() {
    let fx = Fixture::new("index");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    for round in 0..20 {
        catch_up(&mut gb);
        let agent = if round % 2 == 0 { &mut w1 } else { &mut w2 };
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    drop(server);
    let wal = fx.p("run.wal");
    let index = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-index").args(args).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    // built at once
    let at_once = fx.p("at_once.sqlite");
    let (code, built) = index(&["--wal", &wal, "--db", &at_once]);
    assert_eq!((code, built["status"].as_str(), built["mode"].as_str()), (Some(0), Some("INDEXED"), Some("built")), "{built}");
    // built on the first half of the frames, then brought up to the whole journal
    let whole = std::fs::read_to_string(&wal).unwrap();
    let lines: Vec<&str> = whole.lines().collect();
    let half = fx.p("half.wal");
    std::fs::write(&half, lines[..lines.len() / 2].iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    let step = fx.p("step.sqlite");
    assert_eq!(index(&["--wal", &half, "--db", &step]).1["status"], "INDEXED");
    std::fs::write(&half, &whole).unwrap();
    let (code, updated) = index(&["--wal", &half, "--db", &step]);
    assert_eq!((code, updated["mode"].as_str()), (Some(0), Some("updated")), "{updated}");
    assert_eq!(updated["frames_added"], lines.len() - lines.len() / 2);
    assert_eq!(updated["index_hash"], built["index_hash"], "an index brought up to date is the index built at once");
    let (code, checked) = index(&["--wal", &wal, "--db", &step, "--check"]);
    assert_eq!((code, checked["status"].as_str()), (Some(0), Some("INDEX_MATCHES")), "{checked}");
    // what stands, from the database, is what the reading tool says
    let conn = rusqlite::Connection::open(&at_once).unwrap();
    let mut standing: Vec<String> = conn
        .prepare("SELECT r.id FROM records r JOIN status s ON s.id = r.id WHERE r.kind = 'claim' AND s.grounded = 1")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    standing.sort();
    let claims = Command::new(BIN).args(["audit-read", "active-claims", "--wal", &wal, "--limit", "100000"]).output().unwrap();
    let claims: Value = serde_json::from_slice(&claims.stdout).unwrap();
    let mut read: Vec<String> =
        claims["groups"].as_array().unwrap().iter().flat_map(|g| g["ids"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string())).collect();
    read.sort();
    assert!(!standing.is_empty());
    assert_eq!(standing, read, "the claims that stand");
    // a row changed in the database: the check names its table and key
    conn.execute("UPDATE records SET text = 'changed' WHERE kind = 'claim' AND rowid = (SELECT MIN(rowid) FROM records WHERE kind = 'claim')", []).unwrap();
    drop(conn);
    let (code, differs) = index(&["--wal", &wal, "--db", &at_once, "--check"]);
    assert_eq!((code, differs["status"].as_str(), differs["differences"].as_u64()), (Some(1), Some("INDEX_DIFFERS"), Some(1)), "{differs}");
    assert_eq!(differs["first_differences"][0]["table"], "records");
    // a journal cut below what the index names is refused, and --rebuild builds it again
    std::fs::write(&half, lines[..lines.len() / 2].iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    assert_eq!(index(&["--wal", &half, "--db", &step]).0, Some(1));
    assert_eq!(index(&["--wal", &half, "--db", &step, "--rebuild"]).1["mode"], "built");

    // Codex review of 11abf6ed. S6-03: an index of the first half, correct for its prefix, is behind the whole journal, not different
    let (code, behind) = index(&["--wal", &wal, "--db", &step, "--check"]);
    assert_eq!((code, behind["status"].as_str(), behind["differences"].as_u64()), (Some(0), Some("INDEX_BEHIND"), Some(0)), "{behind}");
    assert_eq!(behind["index_hash"], behind["journal_index_hash"], "the index is the prefix's");
    let conn = rusqlite::Connection::open(&step).unwrap();
    conn.execute("UPDATE status SET grounded = 1 - grounded WHERE rowid = (SELECT MIN(rowid) FROM status)", []).unwrap();
    drop(conn);
    assert_eq!(index(&["--wal", &wal, "--db", &step, "--check"]).1["status"], "INDEX_DIFFERS", "a changed status of the prefix");
    // S6-02: a record id of the same bytes stored as a BLOB is not the journal's text
    let fresh = fx.p("blob.sqlite");
    assert_eq!(index(&["--wal", &wal, "--db", &fresh]).0, Some(0));
    let conn = rusqlite::Connection::open(&fresh).unwrap();
    let id: String = conn.query_row("SELECT id FROM records LIMIT 1", [], |r| r.get(0)).unwrap();
    let bytes: Vec<u8> = (0..id.len() / 2).map(|i| u8::from_str_radix(&id[2 * i..2 * i + 2], 16).unwrap()).collect();
    conn.execute("UPDATE records SET id = ?1 WHERE id = ?2", rusqlite::params![bytes, id]).unwrap();
    drop(conn);
    let (code, blob) = index(&["--wal", &wal, "--db", &fresh, "--check"]);
    assert_eq!((code, blob["status"].as_str()), (Some(1), Some("INDEX_DIFFERS")), "{blob}");
    // S6-01: the index is never written over its journal, by --db or by its working file, nor over a file that is no index
    let digest = |p: &str| sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(&std::fs::read(p).unwrap()));
    let before = digest(&wal);
    assert_eq!(index(&["--wal", &wal, "--db", &wal, "--rebuild"]).0, Some(1));
    assert_eq!(index(&["--wal", &wal, "--db", &wal]).0, Some(1));
    let named = fx.p("idx.tmp");
    std::fs::copy(&wal, &named).unwrap();
    let target = fx.p("idx");
    assert_eq!(index(&["--wal", &named, "--db", &target]).0, Some(0));
    assert_eq!(index(&["--wal", &named, "--db", &target, "--rebuild"]).0, Some(0));
    assert_eq!(digest(&named), before, "a journal named as the old working file stays");
    let other = fx.p("questions.json");
    let kept = digest(&other);
    assert_eq!(index(&["--wal", &wal, "--db", &other, "--rebuild"]).0, Some(1));
    assert_eq!(index(&["--wal", &wal, "--db", &other]).0, Some(1));
    assert_eq!(digest(&other), kept, "a file that is no index is not replaced");
    assert_eq!(digest(&wal), before, "the journal is untouched");
    // S6-04: a journal that ends in a torn frame is refused, as audit-verify refuses it
    let torn = fx.p("torn.wal");
    std::fs::write(&torn, format!("{whole}{{\"body\":")).unwrap();
    let (code, refused) = index(&["--wal", &torn, "--db", &fx.p("torn.sqlite")]);
    assert_eq!((code, refused["status"].as_str()), (Some(1), Some("REFUSED")), "{refused}");
    assert!(refused["error"]["message"].as_str().unwrap().contains("torn tail"), "{refused}");
    assert_eq!(index(&["--wal", &torn, "--db", &at_once, "--check"]).0, Some(1));
}

/// Codex review of 904f1cdb, S4-05: a seal whose signed checkpoint cannot be written stands in the journal, and the server says so to
/// its operator: in `audit_status`, in the reply of `audit_close` and on stderr, with the seal and what writes it again.
#[test]
fn a_server_tells_its_operator_of_a_seal_it_could_not_sign() {
    let fx = Fixture::new("signfail");
    let key = fx.p("operator.key");
    assert!(Command::new(BIN).args(["keygen", "--name", "operator", "--out", &key]).output().unwrap().status.success());
    // the folder of the checkpoints is taken by a plain file
    std::fs::write(fx.0.join("run.wal.checkpoints"), b"not a folder").unwrap();
    let mut args = fx.args(true);
    args.extend(["--signing-key".to_string(), key.clone()]);
    let log = fx.0.join("server.stderr");
    let server = Server::start_with_stderr(&args, Stdio::from(std::fs::File::create(&log).unwrap()));
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    for round in 0..20 {
        catch_up(&mut gb);
        let agent = if round % 2 == 0 { &mut w1 } else { &mut w2 };
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    let closed = own.call("audit_close", json!({}));
    assert_eq!(closed["status"], "CLOSED", "{closed}");
    let failed = closed["signing"]["seals_not_signed"].as_array().unwrap_or_else(|| panic!("the close names the seal it could not sign: {closed}")).clone();
    assert!(failed.iter().all(|f| f["seal"].is_u64() && f["error"].is_string()), "{closed}");
    assert!(closed["signing"]["note"].as_str().unwrap().contains("sbgk audit-sign"));
    let status = own.call("audit_status", json!({}));
    assert_eq!(status["signing"], closed["signing"], "{status}");
    drop(server);
    let stderr = std::fs::read_to_string(&log).unwrap();
    assert!(stderr.contains("signed checkpoint was not written"), "stderr: {stderr}");
    // the seals are in the journal: audit-sign writes their checkpoints once the folder is free
    std::fs::remove_file(fx.0.join("run.wal.checkpoints")).unwrap();
    let signed = Command::new(BIN).args(["audit-sign", "--wal", &fx.p("run.wal"), "--signing-key", &key]).output().unwrap();
    let signed: Value = serde_json::from_slice(&signed.stdout).unwrap();
    assert_eq!(signed["status"], "SIGNED", "{signed}");
    let last_failed = failed.last().unwrap()["seal"].as_u64().unwrap();
    assert!(signed["checkpoints"].as_array().unwrap().iter().any(|c| c["seal"] == last_failed), "{signed}");
}

/// The gap pass is a setting of the run (SPEC_V02_GAP_PASS section 10): the coverage and the genesis pin it, and the run is not
/// resumed with another one.
#[test]
fn the_gap_pass_is_pinned_with_the_run() {
    let fx = Fixture::new("gappinned");
    let with_gap = |fresh: bool, limit: &str| [fx.args(fresh), vec!["--gap-pass".to_string(), limit.to_string()]].concat();
    drop(Server::start(&with_gap(true, "2")));
    let wal = std::fs::read_to_string(fx.p("run.wal")).unwrap();
    let genesis: Value = serde_json::from_str(wal.lines().next().unwrap()).unwrap();
    assert!(genesis["body"]["settings_hash"].is_string(), "{genesis}");
    assert!(wal.contains("\"gap_pass\":{\"limit\":2"), "the coverage names the gap pass");
    let other = Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(with_gap(false, "3")).output().unwrap();
    assert_eq!(other.status.code(), Some(2), "a run is not resumed with another gap pass: {}", String::from_utf8_lossy(&other.stderr));
    drop(Server::start(&with_gap(false, "2")));
}

/// A second reader is never the first: a run of one reading agent with second-reader tiers is refused before it starts (Codex review
/// of 6d2c270, GAP-03).
#[test]
fn a_second_reader_needs_a_second_agent() {
    let fx = Fixture::new("gaponeagent");
    let one = fx.p("one-subject.json");
    std::fs::write(&one, json!({"subjects": [{"token": "synthetic-solo-token-0123456789abcdef", "id": "w1", "role": "swarm"}]}).to_string()).unwrap();
    let profile = fx.p("gap-profile.json");
    std::fs::write(&profile, json!({"gap_pass": {"limit": 2, "second_reader_tiers": [0]}}).to_string()).unwrap();
    let mut args = fx.args(true);
    let at = args.iter().position(|a| a == "--subjects").unwrap();
    args[at + 1] = one.clone();
    let out =
        Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0", "--gap-profile", &profile]).args(&args).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least two swarm agents"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!Path::new(&fx.p("run.wal")).exists(), "refused before the journal");
}
