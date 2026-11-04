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
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
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
        let mut child = Command::new(BIN)
            .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"])
            .args(args)
            .stdout(Stdio::piped())
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
    assert_eq!(own.tools().len(), 8);
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
fn a_closed_run_tells_every_agent_done_and_accepts_nothing_more_until_a_restart() {
    // R27 package 2 (the owner, 2026-10-28): COMPLETE is not the end, the owner may still withdraw a source and reopen work, so
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
    assert_eq!((closed["status"].as_str(), &closed["audit_root"]), (Some("CLOSED"), &receipt["audit_root"]), "{closed}");
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
    assert_eq!((status["closed"].as_bool(), &status["audit_root"]), (Some(true), &receipt["audit_root"]), "{status}");
    assert_eq!(own.call("audit_terminal_receipt", json!({}))["audit_root"], receipt["audit_root"]);
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED", "closing again changes nothing");

    // the close is not journaled: a restarted server is open again, with the same root
    drop((w1, w2, gb, own));
    drop(server);
    let server = Server::start(&fx.args(false));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    assert_eq!(w1.call("audit_acquire", json!({}))["status"], "COMPLETE");
    let status = own.call("audit_status", json!({}));
    assert_eq!((status.get("closed"), &status["audit_root"]), (None, &receipt["audit_root"]), "{status}");
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
    for mode in ["footer", "already-mapped", "inline-flag"] {
        let f = Fixture::new(mode);
        let extra = vec![
            "--term-hygiene".into(),
            "--candidate-match".into(),
            "strict".into(),
            "--known-concepts".into(),
            "all".into(),
            "--jev-mode".into(),
            mode.into(),
            "--link-both-sides".into(),
            "--stale-suspect".into(),
            "--evolution-cards".into(),
        ];
        let mut args = f.args(true);
        args.extend(extra.clone());
        let server = Server::start(&args);
        let mut owner = Client::connect(server.port, OWN);
        let st = owner.call("audit_status", json!({}));
        assert_eq!(st["graph_quality"]["config"]["jev_mode"], mode, "{st}");
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
}

#[test]
fn without_flags_audit_serve_runs_the_measured_v01_profile() {
    // the owner, 2026-11-03: "download, run, get what was measured" - no graph builder, reading in circles with dynamic roles
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
