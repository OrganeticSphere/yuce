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
        Fixture::with_docs(tag, &[("a.md", A), ("b.md", B)])
    }

    /// A fixture whose two reports have the given text.
    fn with_docs(tag: &str, docs: &[(&str, &str); 2]) -> Fixture {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("sbgk_audit_serve_{tag}_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("repo/reports")).unwrap();
        let mut entries = Vec::new();
        for (name, text) in *docs {
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
    assert_eq!(
        own.tools().len(),
        22,
        "nine tools of 0.1, the four reading tools of 0.2, audit_seal and the coverage of 0.2.1, the preview of 0.2.2, audit_leases, and the five of 0.3.0: audit_key, audit_keys, audit_context, audit_put_document, audit_checkpoint"
    );
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

/// `--corpus-description` names the documents in the directives and is pinned with the run: a run goes on only with its words.
#[test]
fn the_words_a_run_names_its_documents_by_are_its_own_and_stay_with_it() {
    let fx = Fixture::new("corpuswords");
    let words = ["--corpus-description".to_string(), "a set of clinical study reports".to_string()];
    let server = Server::start(&[fx.args(true), words.to_vec()].concat());
    let mut w1 = Client::connect(server.port, W1);
    let t = w1.call("audit_acquire", json!({}));
    assert!(t["prompt"].as_str().unwrap().contains("an audit swarm over a set of clinical study reports."), "{t}");
    drop(server);
    // the run pinned them: it is not resumed without them, nor with other words
    for given in [vec![], vec!["--corpus-description".to_string(), "other words".to_string()]] {
        let out = Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(fx.args(false)).args(&given).output().unwrap();
        assert!(!out.status.success(), "{given:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("corpus_description"), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let server = Server::start(&[fx.args(false), words.to_vec()].concat());
    assert_eq!(server.hello["audit"]["resumed"], true, "{}", server.hello);
    // words that are no single line are refused before a run starts
    let bad = Fixture::new("corpuswordsbad");
    let out = Command::new(BIN)
        .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"])
        .args(bad.args(true))
        .args(["--corpus-description", "two\nlines"])
        .output()
        .unwrap();
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("--corpus-description"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_run_completes_on_the_wire_and_resumes_from_the_journal_after_a_kill() {
    let fx = Fixture::new("run");
    let server = Server::start(&fx.args(true));
    let mut w1 = Client::connect(server.port, W1);
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!(t["kind"], "EXTEND", "{t}");
    // the documents are named neutrally unless the run names them (0.2.3; the runs before said "a corpus of engineering reports")
    assert!(t["prompt"].as_str().unwrap().contains("an audit swarm over the provided source documents."), "{t}");
    assert!(!t["prompt"].as_str().unwrap().contains("engineering reports"), "{t}");
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
    let mut of_w1 = None;
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
        if round % 2 == 0 {
            of_w1.get_or_insert(t["task_id"].clone());
        }
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
    // an answer that differs from one w1 committed is answered from the acknowledgement, and a closed run writes no late
    // answer for it (the root below stays the root of the close)
    let other = w1.call("audit_submit", json!({"task_id": of_w1.expect("a task of w1"), "lines": [{"kind": "claim", "text": "Otherwise."}]}));
    assert_eq!(other["code"], "SUBMISSION_MISMATCH", "{other}");
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
    // the server is the journal's one writer: another process reads the file (0.2.1; its lock stopped that with os error 33) and,
    // on Windows, cannot open it to write
    assert!(!std::fs::read(fx.p("run.wal")).unwrap().is_empty());
    #[cfg(windows)]
    {
        let err = std::fs::OpenOptions::new().append(true).open(fx.p("run.wal")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(32));
        eprintln!("exclusive WAL writer server pid={}", server.child.id());
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

/// `audit_release` with `reason` (0.3.1): an agent's own reason for a failed attempt that is no timeout. The attempt counts, and
/// the journal keeps the reason the agent gave.
#[test]
fn a_task_given_back_with_a_reason_of_the_agents_own_is_a_counted_attempt_with_that_reason() {
    let f = Fixture::new("release-reason");
    let mut args = f.args(true);
    args.extend(["--agent-attempts".into(), "2".into()]);
    let server = Server::start(&args);
    let mut w = Client::connect(server.port, W1);
    let mut other = Client::connect(server.port, W2);
    let a = w.call("audit_acquire", json!({}));
    assert_eq!(a["kind"], "EXTEND");
    let task = a["task_id"].clone();
    // a reason is a code; a mark the kernel writes itself is not an agent's word; a timeout and a reason are two reports
    for bad in [json!("every answer was refused"), json!("MODEL_TIMEOUT"), json!("EXTEND"), json!(7)] {
        let refused = w.call("audit_release", json!({"task_id": task, "reason": bad}));
        assert_eq!(refused["code"], "BAD_ARGUMENT", "{bad}: {refused}");
    }
    assert_eq!(w.call("audit_release", json!({"task_id": task, "reason": "ALL_ANSWERS_REFUSED", "timed_out": true}))["code"], "BAD_ARGUMENT");
    assert_eq!(other.call("audit_release", json!({"task_id": task, "reason": "ALL_ANSWERS_REFUSED"}))["code"], "TASK_NOT_OWNED");
    let released = w.call("audit_release", json!({"task_id": task, "reason": "ALL_ANSWERS_REFUSED"}));
    assert_eq!((released["status"].as_str(), released["failures"].as_u64()), (Some("RELEASED"), Some(1)), "{released}");
    let mut own = Client::connect(server.port, OWN);
    let status = own.call("audit_status", json!({}));
    let attempts = &status["agent_failures"]["work"][a["key"].as_str().unwrap()]["attempts"];
    assert_eq!(attempts[0]["reason"], "ALL_ANSWERS_REFUSED", "{status}");
    assert_eq!(attempts[0]["subject"], "w1", "{status}");
    // the unit is given again, and the second failed attempt gives it up at the bound of the run
    let b = w.call("audit_acquire", json!({}));
    assert_eq!(b["key"], a["key"]);
    let last = w.call("audit_release", json!({"task_id": b["task_id"], "reason": "MODEL_GAVE_NOTHING"}));
    assert_eq!((last["status"].as_str(), last["unresolved"].as_bool()), (Some("RELEASED"), Some(true)), "{last}");
    // the tool says what the field is for
    let tools = w.rpc("tools/list", json!({}));
    let release = tools["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "audit_release").unwrap().clone();
    assert!(release["inputSchema"]["properties"]["reason"]["description"].as_str().unwrap().contains("ALL_ANSWERS_REFUSED"), "{release}");
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

/// The preview of a withdrawal (0.2.2): before the withdrawal, the report its own `since` gives after it, and not a byte written;
/// by the record or by the text; a refusal is the withdrawal's own.
#[test]
fn a_preview_shows_what_a_withdrawal_would_make_fall_and_writes_nothing() {
    let fx = Fixture::new("preview");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    assert!(own.tools().iter().any(|t| t == "audit_withdraw_preview"));
    assert!(!w1.tools().iter().any(|t| t == "audit_withdraw_preview"), "the preview is the owner's");
    let t = w1.call("audit_acquire", json!({}));
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let records: Vec<Value> = r["accepted_locals"].as_object().unwrap().values().map(|id| own.call("audit_record", json!({"record": id}))).collect();
    let observe = records.iter().find(|x| x["kind"] == "observe").expect("an observe").clone();
    let claim = records.iter().find(|x| x["kind"] == "claim").expect("a claim").clone();
    let by_text_args = json!({"doc_id": observe["doc_id"], "exact_quote": observe["quote"]});
    let wal = fx.p("run.wal");
    let bytes = std::fs::read(&wal).unwrap();
    let by_text = own.call("audit_withdraw_preview", by_text_args.clone());
    let by_record = own.call("audit_withdraw_preview", json!({"record": observe["short"]}));
    assert_eq!(std::fs::read(&wal).unwrap(), bytes, "a preview writes nothing");
    assert_eq!(
        (by_text["status"].as_str(), by_text["written"].as_bool(), by_text["fell"].as_u64(), by_text["quotes_gone"].as_u64()),
        (Some("PREVIEW"), Some(false), Some(1), Some(1)),
        "{by_text}"
    );
    assert_eq!(by_text["rows"][0]["id"], claim["id"], "{by_text}");
    assert!(by_text.get("at").is_none() && by_text.get("provable").is_none(), "no frame, no proof yet: {by_text}");
    assert!(!by_text.to_string().contains(observe["quote"].as_str().unwrap()), "the text to withdraw stays out of the report: {by_text}");
    // by the record, the same records fall; the gone quote is then `named`, as audit_revoke names it, and by the text it is not
    let fallen = |v: &Value| v["rows"].as_array().unwrap().iter().map(|r| (r["id"].clone(), r["fallen_by"].clone())).collect::<Vec<_>>();
    assert_eq!((fallen(&by_record), by_record["fell"].clone()), (fallen(&by_text), by_text["fell"].clone()), "{by_record}");
    assert_eq!((by_record["rows"][0]["gone"][0]["named"].clone(), by_text["rows"][0]["gone"][0]["named"].clone()), (json!(true), json!(false)));
    assert_eq!(own.call("audit_status", json!({}))["projections"]["fallen"], 0, "nothing fell yet");
    assert_eq!(own.call("audit_withdraw_preview", json!({}))["code"], "BAD_ARGUMENT");
    let both = json!({"record": observe["id"], "doc_id": observe["doc_id"], "exact_quote": observe["quote"]});
    assert_eq!(own.call("audit_withdraw_preview", both)["code"], "BAD_ARGUMENT");
    // a field sent as null is a field not given; a field of the other form beside a record, or a text that is not a string, is
    // refused (Argon's review of the preview)
    let with_null = own.call("audit_withdraw_preview", json!({"record": null, "doc_id": observe["doc_id"], "exact_quote": observe["quote"]}));
    assert_eq!(with_null["rows"], by_text["rows"], "{with_null}");
    assert_eq!(own.call("audit_withdraw_preview", json!({"record": observe["id"], "doc_id": 7}))["code"], "BAD_ARGUMENT");
    assert_eq!(own.call("audit_withdraw_preview", json!({"doc_id": observe["doc_id"], "exact_quote": 7}))["code"], "BAD_ARGUMENT");

    // the withdrawal is what the preview showed
    let withdrawn = own.call("audit_withdraw_text", by_text_args.clone());
    assert_eq!(withdrawn["status"], "REVOKED", "{withdrawn}");
    for key in ["since", "fell", "quotes_gone", "also_revoked"] {
        assert_eq!(withdrawn[key], by_text[key], "{key}: {withdrawn}");
    }
    let report = own.call("audit_fallen", json!({"since": withdrawn["since"]}));
    for key in ["since", "rows_fallen", "by_kind", "quotes_gone", "questions_to_answer_again", "rows", "truncated", "other_not_standing"] {
        assert_eq!(report[key], by_text[key], "{key}: {report}");
    }
    // the same withdrawal again is refused, and so is its preview, with the same words
    let refused = own.call("audit_withdraw_text", by_text_args.clone());
    assert_eq!(refused["code"], "REFUSED", "{refused}");
    assert_eq!(own.call("audit_withdraw_preview", by_text_args), refused);
}

/// What `audit-verify` did not check, beside its status: without a checkpoint kept apart from the
/// journal, the journal cut back to an earlier frame boundary verifies like the whole one, and the report says so; a signed checkpoint
/// catches that cut and narrows what is left unchecked to the frames after it. The status keeps its values.
#[test]
fn audit_verify_says_that_without_a_checkpoint_a_cut_at_a_frame_boundary_is_not_checked() {
    let fx = Fixture::new("unanchored");
    let key = fx.p("operator.key");
    assert!(Command::new(BIN).args(["keygen", "--name", "operator", "--out", &key]).output().unwrap().status.success());
    let mut args = fx.args(true);
    args.extend(["--signing-key".to_string(), key.clone()]);
    let server = Server::start(&args);
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    let mut sealed = false;
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
        // a seal in the middle of the run, after its first answer: its checkpoint names a prefix of the journal
        if !sealed {
            assert_eq!(own.call("audit_seal", json!({}))["status"], "SEALED");
            sealed = true;
        }
    }
    assert!(sealed, "the run answered at least once");
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    drop(server);
    let wal = fx.p("run.wal");
    let dir = fx.0.join("run.wal.checkpoints");
    let mut seals: Vec<String> =
        std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.starts_with("seal-")).collect();
    seals.sort_by_key(|n| n[5..n.len() - 4].parse::<usize>().unwrap());
    assert!(seals.len() >= 2, "a seal mid-run and the seal of the close: {seals:?}");
    let checkpoint = |n: usize| dir.join(&seals[n]).display().to_string();
    let frames_of = |n: usize| std::fs::read_to_string(checkpoint(n)).unwrap().lines().nth(1).unwrap().parse::<usize>().unwrap();
    let verify = |wal: &str, extra: &[&str]| {
        let out = Command::new(BIN).args(["audit-verify", "--wal", wal]).args(extra).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let unanchored = |v: &Value| v["external_checkpoint"] == false && v["not_checked"].as_str().is_some_and(|t| t.starts_with("frame-boundary truncation:"));

    // the whole journal, no anchor: VERIFIED, and the report says what was not checked
    let (code, whole) = verify(&wal, &[]);
    assert_eq!((code, whole["status"].as_str()), (Some(0), Some("VERIFIED")), "{whole}");
    assert!(unanchored(&whole), "{whole}");
    // the journal cut back to the mid-run seal, a frame boundary: it verifies too, which is exactly what the field says
    let cut = fx.p("cut.wal");
    let text = std::fs::read_to_string(&wal).unwrap();
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    std::fs::write(&cut, lines[..frames_of(0)].concat()).unwrap();
    let (code, v) = verify(&cut, &[]);
    assert_eq!((code, v["status"].as_str()), (Some(0), Some("VERIFIED")), "{v}");
    assert!(unanchored(&v) && v["entries"].as_u64() < whole["entries"].as_u64(), "{v}");
    // the checkpoint of the close's seal, kept apart: the cut is refused, and the whole journal is anchored up to that seal
    let last = checkpoint(seals.len() - 1);
    let (code, v) = verify(&cut, &["--checkpoint", &last]);
    assert_eq!((code, v["status"].as_str(), v["external_checkpoint"].as_bool()), (Some(1), Some("CHECKPOINT_REFUSED"), Some(false)), "{v}");
    let (code, v) = verify(&wal, &["--checkpoint", &last]);
    assert_eq!((code, v["status"].as_str(), v["external_checkpoint"].as_bool()), (Some(0), Some("VERIFIED"), Some(true)), "{v}");
    let after = format!("frame-boundary truncation after frame {}", frames_of(seals.len() - 1));
    assert!(v["not_checked"].as_str().unwrap().starts_with(&after), "{v}");
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
    // a second name of the journal, a hard link, is no path of it: the quittance takes that name and the journal keeps its bytes
    // (Codex's OUT-01 of 85742398)
    let alias = fx.p("alias.wal");
    std::fs::hard_link(&wal, &alias).unwrap();
    let r = Command::new(BIN).args(["audit-proof", "--wal", &wal, "--record", &claim, "--out", &alias]).output().unwrap();
    let v: Value = serde_json::from_slice(&r.stdout).unwrap_or(Value::Null);
    assert_eq!((r.status.code(), v["status"].as_str()), (Some(0), Some("PROOF")), "{v}");
    assert_eq!(std::fs::read(&wal).unwrap(), before, "the journal is untouched by a quittance written to its hard link");
    assert!(serde_json::from_slice::<Value>(&std::fs::read(&alias).unwrap()).is_ok(), "the second name now holds the quittance");
    // nor are the checkpoints written over the journal or the signing key, and a hard link of the journal among them keeps the
    // journal (Codex's OUT-02 of 85742398: a journal named verifier.key in the folder of --out was replaced by the verifier key)
    let sign = |wal: &str, signing: &str, out: &std::path::Path| {
        let r = Command::new(BIN).args(["audit-sign", "--wal", wal, "--signing-key", signing, "--out", &out.display().to_string()]).output().unwrap();
        (r.status.code(), serde_json::from_slice::<Value>(&r.stdout).unwrap_or(Value::Null))
    };
    let (named_key, key_bytes) = (fx.0.join("as_key"), std::fs::read(&key).unwrap());
    std::fs::create_dir_all(&named_key).unwrap();
    std::fs::write(named_key.join("verifier.key"), &before).unwrap();
    let (code, v) = sign(&named_key.join("verifier.key").display().to_string(), &key, &named_key);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("REFUSED")), "{v}");
    assert!(v["error"].as_str().unwrap().contains("the journal"), "{v}");
    assert_eq!(std::fs::read(named_key.join("verifier.key")).unwrap(), before, "a journal named verifier.key is untouched");
    let key_there = fx.0.join("key_there");
    std::fs::create_dir_all(&key_there).unwrap();
    std::fs::write(key_there.join(&seals[0]), &key_bytes).unwrap();
    let (code, v) = sign(&wal, &key_there.join(&seals[0]).display().to_string(), &key_there);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("REFUSED")), "{v}");
    assert!(v["error"].as_str().unwrap().contains("the signing key"), "{v}");
    assert_eq!(std::fs::read(key_there.join(&seals[0])).unwrap(), key_bytes, "the signing key is untouched");
    let linked = fx.0.join("linked");
    std::fs::create_dir_all(&linked).unwrap();
    std::fs::hard_link(&wal, linked.join(&seals[0])).unwrap();
    let (code, v) = sign(&wal, &key, &linked);
    assert_eq!((code, v["status"].as_str()), (Some(0), Some("SIGNED")), "{v}");
    assert_eq!(std::fs::read(&wal).unwrap(), before, "the journal is untouched by a checkpoint written to its hard link");
    assert_eq!(std::fs::read(linked.join(&seals[0])).unwrap(), std::fs::read(dir.join(&seals[0])).unwrap(), "the checkpoint took that name");
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

/// The PROV-O export of a journal (0.2.2): the file names the hash of its own content, a second export gives the same bytes, the
/// claims it says stand are those the reading tool says stand, `--upto` exports the first frames, and a path that names the journal
/// is refused with the journal untouched.
#[test]
fn the_prov_export_of_a_journal_is_the_same_file_every_time_and_stands_what_the_reading_tools_stand() {
    let fx = Fixture::new("prov");
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
    let prov = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-prov").args(["--wal", &wal]).args(args).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let (first, second) = (fx.p("first.prov.jsonld"), fx.p("second.prov.jsonld"));
    let (code, made) = prov(&["--out", &first]);
    assert_eq!((code, made["status"].as_str(), made["format"].as_str()), (Some(0), Some("EXPORTED"), Some("yuce-prov/1")), "{made}");
    assert_eq!(prov(&["--out", &second]).1["content_hash"], made["content_hash"]);
    let text = std::fs::read(&first).unwrap();
    assert_eq!(text, std::fs::read(&second).unwrap(), "the same journal, the same bytes");
    let document: Value = serde_json::from_slice(&text).unwrap();
    let named = sbgk_core::audit::prov::content_hash_of(&document).map(|h| sbgk_core::hash::to_hex(&h));
    assert_eq!(named.as_deref(), made["content_hash"].as_str(), "the file names the hash of its content");
    let frames = std::fs::read_to_string(&wal).unwrap().lines().count();
    assert_eq!(made["frames"].as_u64(), Some(frames as u64));
    // the claims with a period of standing that did not end are the claims the reading tool says stand
    let graph = document["@graph"].as_array().unwrap();
    let claims: std::collections::BTreeSet<&str> = graph.iter().filter(|n| n["yuce:kind"] == "claim").filter_map(|n| n["@id"].as_str()).collect();
    let mut standing: Vec<String> = graph
        .iter()
        .filter(|n| n["@type"].as_array().unwrap().iter().any(|t| t == "yuce:Standing") && n.get("prov:wasInvalidatedBy").is_none())
        .filter_map(|n| n["prov:specializationOf"].as_str().filter(|r| claims.contains(r)))
        .map(|r| r.rsplit(':').next().unwrap().to_string())
        .collect();
    standing.sort();
    let read = Command::new(BIN).args(["audit-read", "active-claims", "--wal", &wal, "--limit", "100000"]).output().unwrap();
    let read: Value = serde_json::from_slice(&read.stdout).unwrap();
    let mut active: Vec<String> =
        read["groups"].as_array().unwrap().iter().flat_map(|g| g["ids"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string())).collect();
    active.sort();
    assert!(!standing.is_empty());
    assert_eq!(standing, active, "the claims that stand");
    // the first frames
    let (code, part) = prov(&["--out", &fx.p("part.prov.jsonld"), "--upto", &(frames / 2).to_string()]);
    assert_eq!((code, part["frames"].as_u64()), (Some(0), Some((frames / 2) as u64)), "{part}");
    assert_eq!(prov(&["--out", &fx.p("none.prov.jsonld"), "--upto", &(frames + 1).to_string()]).0, Some(1));
    // never over the journal
    let before = std::fs::read(&wal).unwrap();
    let (code, refused) = prov(&["--out", &wal]);
    assert_eq!((code, refused["status"].as_str()), (Some(1), Some("REFUSED")), "{refused}");
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    // Codex review of 32aff362, PROV-01: a file beside the output that is another link to the journal is never written, a file
    // someone keeps beside it neither, and an output that is another link to the journal replaces that name, not the journal
    let linked = fx.p("linked.prov.jsonld");
    std::fs::hard_link(&wal, format!("{linked}.partial")).unwrap();
    let kept = fx.p("kept.prov.jsonld");
    std::fs::write(format!("{kept}.partial"), "kept").unwrap();
    let alias = fx.p("alias.prov.jsonld");
    std::fs::hard_link(&wal, &alias).unwrap();
    for out in [&linked, &kept, &alias] {
        let (code, made) = prov(&["--out", out]);
        assert_eq!((code, made["status"].as_str()), (Some(0), Some("EXPORTED")), "{made}");
        assert_eq!(std::fs::read(out).unwrap(), text, "{out} holds the export");
        assert_eq!(std::fs::read(&wal).unwrap(), before, "the journal is untouched after the export to {out}");
    }
    assert_eq!(std::fs::read(format!("{linked}.partial")).unwrap(), before, "the other link to the journal is untouched");
    assert_eq!(std::fs::read_to_string(format!("{kept}.partial")).unwrap(), "kept");
    let left: Vec<String> = std::fs::read_dir(std::path::Path::new(&wal).parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with('.') && n.ends_with(".partial"))
        .collect();
    assert!(left.is_empty(), "no file written beside an export is left: {left:?}");
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

/// 0.2.1: the owner seals the journal before a withdrawal (`audit_seal`), so that a quittance can show an answer's claim as it stood
/// then, after it fell. The seal is signed as the server's own seals are, the journal verifies, and a seal right after a seal is
/// not written again (the finding of the SaneCite run on 0.2.0: no seal fell between the answers and the withdrawal).
#[test]
fn an_owner_seal_before_a_withdrawal_lets_a_quittance_show_what_stood_then() {
    let fx = Fixture::new("ownerseal");
    let key = fx.p("operator.key");
    assert!(Command::new(BIN).args(["keygen", "--name", "operator", "--out", &key]).output().unwrap().status.success());
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
    let receipt = own.call("audit_terminal_receipt", json!({}));
    assert_eq!(receipt["status"], "TERMINAL", "{receipt}");
    assert_eq!(w1.call("audit_seal", json!({}))["code"], -32003, "only the owner seals");
    let sealed = own.call("audit_seal", json!({}));
    assert_eq!(sealed["status"], "SEALED", "{sealed}");
    assert!(sealed.get("signing").is_none(), "the seal was signed: {sealed}");
    let at = sealed["log_size"].as_u64().unwrap();
    let again = own.call("audit_seal", json!({}));
    assert_eq!((again["status"].as_str(), again["log_size"].as_u64()), (Some("ALREADY_SEALED"), Some(at)), "{again}");
    let claim = own.call("audit_record", json!({"record": receipt["outcomes"]["RQ1"]["answer_ids"][0]}));
    let observe = own.call("audit_record", json!({"record": claim["based_on"][0]}));
    assert_eq!(own.call("audit_revoke", json!({"record": observe["short"]}))["status"], "REVOKED");
    assert_eq!(own.call("audit_record", json!({"record": claim["id"]}))["grounded"], false, "the claim fell");
    let after = own.call("audit_seal", json!({}));
    assert_eq!(after["status"], "SEALED", "{after}");
    let later = after["log_size"].as_u64().unwrap();
    assert!(later > at, "{after}");
    drop(server);

    let wal = fx.p("run.wal");
    let verified: Value = serde_json::from_slice(&Command::new(BIN).args(["audit-verify", "--wal", &wal]).output().unwrap().stdout).unwrap();
    assert_eq!(verified["status"], "VERIFIED", "a seal the owner asked for replays as the server's own: {verified}");
    for n in [at, later] {
        assert!(fx.0.join("run.wal.checkpoints").join(format!("seal-{n}.txt")).is_file(), "the seal at {n} is signed");
    }
    let quittance = fx.p("claim.proof.json");
    let cut = |seal: u64| {
        let out = Command::new(BIN)
            .args(["audit-proof", "--wal", &wal, "--record", claim["id"].as_str().unwrap(), "--seal", &seal.to_string(), "--out", &quittance])
            .output()
            .unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let (code, v) = cut(at);
    assert_eq!((code, v["status"].as_str()), (Some(0), Some("PROOF")), "the claim stood at the owner's seal: {v}");
    let check = Command::new(BIN).args(["audit-proof-verify", "--proof", &quittance]).output().unwrap();
    let check: Value = serde_json::from_slice(&check.stdout).unwrap_or(Value::Null);
    assert_eq!(check["status"], "PROOF_VALID", "{check}");
    let (code, v) = cut(later);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("REFUSED")), "the claim fell before the later seal: {v}");
}

/// A reading command over the journal of `fx`: its exit code, what it printed and what it said on stderr.
fn reading(fx: &Fixture, args: &[&str]) -> (Option<i32>, Value, String) {
    let out = Command::new(BIN).args(args).args(["--wal", &fx.p("run.wal")]).output().unwrap();
    (out.status.code(), serde_json::from_slice(&out.stdout).unwrap_or(Value::Null), String::from_utf8_lossy(&out.stderr).to_string())
}

/// A server on the journal of `fx` that must not start: its exit code and what it told its operator. One that started and serves
/// is stopped after a while and has no exit code.
fn refused_server(fx: &Fixture) -> (Option<i32>, String) {
    let mut child = Command::new(BIN)
        .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"])
        .args(fx.args(false))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > until {
            let _ = child.kill();
            let _ = child.wait();
            return (None, "a second server started on the journal and served".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stderr).to_string())
}

/// The journal of a running server is read by another process (0.2.1): `audit-verify` and `audit-read` while the server writes,
/// then `audit-index` and `audit-proof` too while it still holds the journal. Each reads to the last complete frame of that moment
/// and says that the journal was live; an entry in flight is no torn tail. On Windows the server's lock over the whole file
/// stopped every one of them before (os error 33). A second server on the journal is still refused.
#[test]
fn every_reading_command_reads_the_journal_of_a_running_server_and_a_second_server_is_refused() {
    let fx = Fixture::new("live");
    let key = fx.p("operator.key");
    assert_eq!(Command::new(BIN).args(["keygen", "--name", "operator", "--out", &key]).output().unwrap().status.code(), Some(0));
    let mut args = fx.args(true);
    args.extend(["--signing-key".to_string(), key]);
    let server = Server::start(&args);
    // before any agent wrote: the frames of the start, read live
    let (code, first, stderr) = reading(&fx, &["audit-verify"]);
    assert_eq!((code, first["status"].as_str(), first["torn_tail_bytes"].as_u64()), (Some(0), Some("VERIFIED"), Some(0)), "{first} {stderr}");
    let start = first["live"]["frames_read"].as_u64().expect("the report says the journal was live");
    assert_eq!(first["entries"].as_u64(), Some(start), "{first}");
    // while the agents write, another process keeps checking and reading the journal
    let done = std::sync::atomic::AtomicBool::new(false);
    let seen: Vec<(Option<i32>, Value, String)> = std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            let mut seen = Vec::new();
            while !done.load(std::sync::atomic::Ordering::Relaxed) || seen.len() < 6 {
                seen.push(reading(&fx, &["audit-verify"]));
                seen.push(reading(&fx, &["audit-read", "status"]));
            }
            seen
        });
        let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
        let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
        for round in 0..40 {
            catch_up(&mut gb);
            let agent = if round % 2 == 0 { &mut w1 } else { &mut w2 };
            let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
            match t["status"].as_str().unwrap() {
                "COMPLETE" => break,
                "WAIT" => continue,
                _ => {}
            }
            assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        reader.join().unwrap()
    });
    let mut frames = start;
    for (code, v, stderr) in &seen {
        assert_eq!(*code, Some(0), "{v} {stderr}");
        let read = v["live"]["frames_read"].as_u64().unwrap_or_else(|| panic!("a read of a live journal says so: {v}"));
        if v["status"] == "VERIFIED" {
            // a frame in flight is not a torn tail, and a later check never reads fewer frames
            assert_eq!((v["torn_tail_bytes"].as_u64(), v["entries"].as_u64()), (Some(0), Some(read)), "{v}");
            assert!(read >= frames, "{read} frames after {frames}: {v}");
            frames = read;
        }
    }
    // the run is closed and its seal signed; the server still runs and holds the journal
    let (code, last, stderr) = reading(&fx, &["audit-verify"]);
    assert_eq!((code, last["status"].as_str()), (Some(0), Some("VERIFIED")), "{last} {stderr}");
    let end = last["live"]["frames_read"].as_u64().unwrap();
    assert!(end > start && end >= frames, "the journal grew from {start} to {end} frames");
    assert_eq!(last["live"]["in_flight_bytes"], 0, "{last}");
    let (code, status, stderr) = reading(&fx, &["audit-read", "status"]);
    assert_eq!((code, status["live"]["frames_read"].as_u64()), (Some(0), Some(end)), "{status} {stderr}");
    let (code, claims, stderr) = reading(&fx, &["audit-read", "active-claims"]);
    assert_eq!(code, Some(0), "{claims} {stderr}");
    let claim = claims["groups"][0]["ids"][0].as_str().expect("a standing claim").to_string();
    let db = fx.p("live.index.sqlite");
    let (code, indexed, stderr) = reading(&fx, &["audit-index", "--db", &db]);
    assert_eq!((code, indexed["status"].as_str(), indexed["frames"].as_u64()), (Some(0), Some("INDEXED"), Some(end)), "{indexed} {stderr}");
    assert_eq!(indexed["live"]["frames_read"].as_u64(), Some(end), "{indexed}");
    let (code, checked, stderr) = reading(&fx, &["audit-index", "--db", &db, "--check"]);
    assert_eq!((code, checked["status"].as_str()), (Some(0), Some("INDEX_MATCHES")), "{checked} {stderr}");
    let (code, exported, stderr) = reading(&fx, &["audit-prov", "--out", &fx.p("live.prov.jsonld")]);
    assert_eq!((code, exported["status"].as_str(), exported["frames"].as_u64()), (Some(0), Some("EXPORTED"), Some(end)), "{exported} {stderr}");
    assert_eq!(exported["live"]["frames_read"].as_u64(), Some(end), "{exported}");
    let proof = fx.p("live.proof.json");
    let (code, cut, stderr) = reading(&fx, &["audit-proof", "--record", &claim, "--out", &proof]);
    assert_eq!((code, cut["status"].as_str(), cut["live"]["frames_read"].as_u64()), (Some(0), Some("PROOF"), Some(end)), "{cut} {stderr}");
    let check = Command::new(BIN).args(["audit-proof-verify", "--proof", &proof]).output().unwrap();
    assert_eq!(check.status.code(), Some(0), "{}", String::from_utf8_lossy(&check.stdout));
    // one writer still: a second server on the same journal does not start, and the journal is as it was
    let before = std::fs::read(fx.p("run.wal")).unwrap();
    let (code, stderr) = refused_server(&fx);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("in use"), "{stderr}");
    assert_eq!(std::fs::read(fx.p("run.wal")).unwrap(), before);
    drop(server);
    // stopped, the same journal reads the same, and nothing says live
    let (code, stopped, stderr) = reading(&fx, &["audit-verify"]);
    assert_eq!((code, stopped["status"].as_str(), stopped["entries"].as_u64()), (Some(0), Some("VERIFIED"), Some(end)), "{stopped} {stderr}");
    assert!(stopped.get("live").is_none(), "{stopped}");
    assert_eq!((&stopped["wal_sha256"], &stopped["audit_root"]), (&last["wal_sha256"], &last["audit_root"]));
}

/// Beside a server of 0.2.0 or earlier, which opens the journal to read and write and locks the whole file (the handle this test
/// holds): a server of this version does not start, and a reading command is told in words why it cannot read where that lock
/// stops reading (Windows; it said `os error 33`), and reads the journal as live elsewhere.
#[test]
fn a_journal_locked_whole_refuses_a_second_server_and_tells_a_reader_why() {
    let fx = Fixture::new("lockedwhole");
    drop(Server::start(&fx.args(true)));
    let old = std::fs::OpenOptions::new().read(true).write(true).open(fx.p("run.wal")).unwrap();
    old.try_lock().unwrap();
    let (code, stderr) = refused_server(&fx);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("in use"), "{stderr}");
    for command in [&["audit-verify"][..], &["audit-read", "status"], &["audit-index", "--db", &fx.p("locked.index.sqlite")], &["audit-proof", "--record", "0"]]
    {
        let (code, v, stderr) = reading(&fx, command);
        if cfg!(windows) {
            assert_eq!(code, Some(2), "{command:?}: {v} {stderr}");
            assert!(stderr.contains("locked whole by a running server") && !stderr.contains("os error"), "{command:?}: {stderr}");
        } else if command[0] != "audit-proof" {
            assert_eq!(code, Some(0), "{command:?}: {v} {stderr}");
            assert!(v["live"]["frames_read"].as_u64().is_some(), "{command:?}: {v}");
        }
    }
    // unlocked, the journal is served and read again
    drop(old);
    let server = Server::start(&fx.args(false));
    assert_eq!(server.hello["audit"]["resumed"], true, "{}", server.hello);
    assert_eq!(reading(&fx, &["audit-verify"]).0, Some(0));
}

/// The end of a stopped journal that is no complete entry is a torn tail as before, whoever asks and however often: only a
/// writer that holds the journal makes such bytes an entry in flight.
#[test]
fn a_torn_tail_of_a_stopped_journal_is_still_a_torn_tail() {
    let fx = Fixture::new("tornstopped");
    drop(Server::start(&fx.args(true)));
    let mut bytes = std::fs::read(fx.p("run.wal")).unwrap();
    bytes.extend_from_slice(b"{\"body\":{\"actor\":\"w1\"");
    std::fs::write(fx.p("run.wal"), &bytes).unwrap();
    for _ in 0..3 {
        let (code, v, stderr) = reading(&fx, &["audit-verify"]);
        assert_eq!((code, v["status"].as_str(), v["torn_tail_bytes"].as_u64()), (Some(1), Some("TORN_TAIL"), Some(21)), "{v} {stderr}");
        assert!(v.get("live").is_none(), "{v}");
    }
    let (code, v, _) = reading(&fx, &["audit-index", "--db", &fx.p("torn.index.sqlite")]);
    assert_eq!((code, v["status"].as_str()), (Some(1), Some("REFUSED")), "{v}");
    assert_eq!(std::fs::read(fx.p("run.wal")).unwrap(), bytes);
}

/// A report with four structural units: its topic line, two list items and a closing paragraph.
const LIST: &str = "# Alpha\nTopic A is reported.\n\n- The first extra item.\n- The second extra item.\n\nA closing paragraph.\n";

/// The coverage table (0.2.1) on the wire, over the journal and in the index: what each unit came to, with the pack of the gap pass
/// that asked about it. The index takes it up at every update, an index of the earlier format is built again, and a run without a
/// gap pass has the units and no packs.
#[test]
fn the_coverage_table_is_read_on_the_wire_over_the_journal_and_from_the_index() {
    let fx = Fixture::with_docs("coverage", &[("a.md", LIST), ("b.md", B)]);
    let mut args = fx.args(true);
    args.extend(["--gap-pass", "2", "--gap-units", "4"].map(String::from));
    let server = Server::start(&args);
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    assert!(own.tools().iter().any(|t| t == "audit_coverage") && !w1.tools().iter().any(|t| t == "audit_coverage"), "the owner's tool");
    let index = |args: &[&str]| {
        let out = Command::new(BIN).arg("audit-index").args(["--wal", &fx.p("run.wal")]).args(args).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let counts = |db: &str, table: &str, column: &str| -> Vec<(String, i64)> {
        let conn = rusqlite::Connection::open(db).unwrap();
        let mut statement = conn.prepare(&format!("SELECT {column}, COUNT(*) FROM {table} GROUP BY {column} ORDER BY {column}")).unwrap();
        let rows = statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.map(Result::unwrap).collect()
    };
    let step = fx.p("step.sqlite");
    let mut packs = 0;
    for round in 0..40 {
        catch_up(&mut gb);
        let agent = if round % 2 == 0 { &mut w1 } else { &mut w2 };
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        let lines = if t["key"].as_str().is_some_and(|k| k.starts_with("gap:")) {
            packs += 1;
            // the first readings are over and the pack is not answered yet: the index of this moment has the gaps as left
            let (code, built) = index(&["--db", &step]);
            assert_eq!((code, built["status"].as_str(), built["coverage"]["units"].as_u64()), (Some(0), Some("INDEXED"), Some(5)), "{built}");
            assert_eq!(counts(&step, "coverage_units", "status"), [("left_by_budget".to_string(), 3), ("quoted".to_string(), 2)]);
            // the pack asks about the three unquoted units of the list; one of them is quoted, two are answered empty
            let (p, doc) = (t["local_id_prefix"].as_str().unwrap(), t["key"].as_str().unwrap()[4..].rsplit_once('@').unwrap().0);
            vec![json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": "The first extra item.", "terms": ["topic"]})]
        } else {
            answer(&t)
        };
        assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}))["status"], "COMMITTED", "{t}");
    }
    assert_eq!(packs, 1, "the three gaps of one report and one tier are one pack");
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    let live = own.call("audit_coverage", json!({}));
    assert_eq!(own.call("audit_coverage", json!({"unit_status": "everything"}))["code"], "BAD_ARGUMENT");
    drop(server);

    // over the journal the tool answers as on the wire, and its totals are the report of the pass
    let read = |args: &[&str]| {
        let out = Command::new(BIN).args(["audit-read", "coverage", "--wal", &fx.p("run.wal")]).args(args).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    let (code, table) = read(&[]);
    assert_eq!((code, &table), (Some(0), &live));
    assert_eq!((table["status"].as_str(), table["available"].as_bool(), table["units"].as_u64()), (Some("COVERAGE"), Some(true), Some(5)), "{table}");
    assert_eq!(table["by_status"], json!({"empty": 2, "quoted": 3}), "{table}");
    let summary = &table["summary"];
    assert_eq!(
        (&summary["units_read"], &summary["units_quoted"], &summary["gap_units"], &summary["gap_tasks"], &summary["gap_recorded"], &summary["complete"]),
        (&json!(5), &json!(3), &json!(2), &json!(1), &json!(1), &json!(true)),
        "{summary}"
    );
    assert_eq!(table["gap_pass"]["limit"], 2, "{table}");
    let pack = table["packs"][0]["key"].as_str().expect("the pack").to_string();
    assert_eq!(
        (table["packs"].as_array().unwrap().len(), table["packs"][0]["outcome"].as_str(), table["packs"][0]["recorded"].as_u64()),
        (1, Some("answered"), Some(1))
    );
    // the filters: the units answered empty name their pack; the other report has one quoted unit and no pack
    let (_, empty) = read(&["--unit-status", "empty"]);
    assert_eq!(empty["units"], 2, "{empty}");
    assert!(empty["rows"].as_array().unwrap().iter().all(|r| r["status"] == "empty" && r["pack"] == pack.as_str() && r["quoted_by"] == json!([])), "{empty}");
    let quoted = table["rows"].as_array().unwrap().iter().find(|r| r["pack"].is_null()).expect("the unit of the other report");
    assert_eq!((quoted["status"].as_str(), quoted["quoted_by"].as_array().map(Vec::len)), (Some("quoted"), Some(1)), "{quoted}");
    let (_, other) = read(&["--doc-id", quoted["doc_id"].as_str().unwrap()]);
    assert_eq!((other["units"].as_u64(), other["packs"].as_array().map(Vec::len)), (Some(1), Some(0)), "{other}");
    assert_eq!(read(&["--unit-status", "everything"]).0, Some(2), "an unknown status is a usage error");

    // the index: brought up to date it has the table of now, the same as an index built at once; the totals are counts of its rows
    let (code, updated) = index(&["--db", &step]);
    assert_eq!((code, updated["mode"].as_str()), (Some(0), Some("updated")), "{updated}");
    let at_once = fx.p("at_once.sqlite");
    let (_, built) = index(&["--db", &at_once]);
    assert_eq!((built["mode"].as_str(), &built["index_hash"]), (Some("built"), &updated["index_hash"]), "{built}");
    assert_eq!(built["coverage"], json!({"units": 5, "packs": 1}));
    assert_eq!(index(&["--db", &step, "--check"]).1["status"], "INDEX_MATCHES");
    assert_eq!(counts(&step, "coverage_units", "status"), [("empty".to_string(), 2), ("quoted".to_string(), 3)]);
    assert_eq!(counts(&step, "coverage_packs", "outcome"), [("answered".to_string(), 1)]);
    let conn = rusqlite::Connection::open(&step).unwrap();
    let asked: i64 =
        conn.query_row("SELECT COUNT(*) FROM coverage_units u JOIN coverage_packs p ON p.key = u.pack WHERE u.status = 'empty'", [], |r| r.get(0)).unwrap();
    assert_eq!(asked, 2, "each unit answered empty joins the pack that asked");
    // a status changed in the database: the check names the table
    conn.execute("UPDATE coverage_units SET status = 'quoted' WHERE status = 'empty'", []).unwrap();
    drop(conn);
    let (code, differs) = index(&["--db", &step, "--check"]);
    assert_eq!((code, differs["status"].as_str(), differs["differences"].as_u64()), (Some(1), Some("INDEX_DIFFERS"), Some(2)), "{differs}");
    assert_eq!(differs["first_differences"][0]["table"], "coverage_units");

    // an index of the earlier format has no tables of the coverage: it is neither brought up to date nor compared, and is built again
    let conn = rusqlite::Connection::open(&at_once).unwrap();
    conn.execute("UPDATE meta SET value = 'yuce-index/1' WHERE key = 'format'", []).unwrap();
    drop(conn);
    let (code, refused) = index(&["--db", &at_once]);
    assert_eq!((code, refused["status"].as_str()), (Some(1), Some("REFUSED")), "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("earlier format yuce-index/1") && refused["error"].as_str().unwrap().contains("--rebuild"),
        "{refused}"
    );
    let (code, checked) = index(&["--db", &at_once, "--check"]);
    assert_eq!((code, checked["status"].as_str()), (Some(1), Some("INDEX_DIFFERS")), "{checked}");
    assert!(checked["error"].as_str().unwrap().contains("earlier format"), "{checked}");
    let (code, rebuilt) = index(&["--db", &at_once, "--rebuild"]);
    assert_eq!((code, rebuilt["mode"].as_str(), &rebuilt["index_hash"]), (Some(0), Some("built"), &updated["index_hash"]), "{rebuilt}");
    // an index of 0.2.1 or 0.2.2 counted the units of a given-up first reading as read: it is built again too, not compared
    let conn = rusqlite::Connection::open(&at_once).unwrap();
    conn.execute("UPDATE meta SET value = 'yuce-index/2' WHERE key = 'format'", []).unwrap();
    drop(conn);
    let (code, refused) = index(&["--db", &at_once]);
    assert_eq!((code, refused["status"].as_str()), (Some(1), Some("REFUSED")), "{refused}");
    let error = refused["error"].as_str().unwrap();
    assert!(
        error.contains("earlier format yuce-index/2") && error.contains("reading given up with nothing recorded") && error.contains("--rebuild"),
        "{refused}"
    );
    let (code, rebuilt) = index(&["--db", &at_once, "--rebuild"]);
    assert_eq!((code, rebuilt["mode"].as_str(), &rebuilt["index_hash"]), (Some(0), Some("built"), &updated["index_hash"]), "{rebuilt}");

    // a run without a gap pass: the units with what the first readings left of them, no packs, and no claim of a pass
    let plain = Fixture::new("coverageplain");
    drop(Server::start(&plain.args(true)));
    let out = Command::new(BIN).args(["audit-read", "coverage", "--wal", &plain.p("run.wal")]).output().unwrap();
    let none: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (out.status.code(), none["available"].as_bool(), &none["gap_pass"], &none["by_status"]),
        (Some(0), Some(true), &Value::Null, &json!({"unread": 2})),
        "{none}"
    );
    assert_eq!((&none["summary"]["gap_pass"], none["packs"].as_array().map(Vec::len)), (&json!(false), Some(0)), "{none}");
}

/// `audit_leases` shows the owner the tasks out now and nothing else: of each open lease its task id, the kind and the key of its
/// work, the agent that holds it and the milliseconds left, without the text of the task. It is the owner's alone, takes no step
/// of the run and writes no frame; a task handed in is no longer listed, and the list is still read after the run is closed.
#[test]
fn the_owner_reads_the_tasks_out_now_and_the_reading_writes_nothing() {
    let fx = Fixture::new("leases");
    let server = Server::start(&fx.args(true));
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let (mut gb, mut own) = (Client::connect(server.port, GB), Client::connect(server.port, OWN));
    // the owner's alone: no other role lists it, and a call with another token is refused
    assert!(own.tools().iter().any(|t| t == "audit_leases"));
    for other in [&mut w1, &mut gb] {
        assert!(!other.tools().iter().any(|t| t == "audit_leases"));
        let refused = other.call("audit_leases", json!({}));
        assert_eq!(refused["code"], -32003, "{refused}");
    }
    let none = own.call("audit_leases", json!({}));
    assert_eq!((none["status"].as_str(), none["open"].as_u64(), none["leases"].as_array().map(Vec::len)), (Some("LEASES"), Some(0), Some(0)), "{none}");

    // two agents take a task each: both are listed, with exactly the five fields and no text of a task
    let (t1, t2) = (w1.call("audit_acquire", json!({"max_wait_ms": 200})), w2.call("audit_acquire", json!({"max_wait_ms": 200})));
    assert_eq!((t1["status"].as_str(), t2["status"].as_str()), (Some("DIRECTIVE"), Some("DIRECTIVE")), "{t1} {t2}");
    let wal = fx.p("run.wal");
    let before = std::fs::read(&wal).unwrap();
    let out = own.call("audit_leases", json!({}));
    assert_eq!(std::fs::read(&wal).unwrap(), before, "the reading wrote no frame");
    assert_eq!(out["open"], 2, "{out}");
    let leases = out["leases"].as_array().unwrap();
    for (lease, (task, agent)) in leases.iter().zip([(&t1, "w1"), (&t2, "w2")]) {
        let mut fields: Vec<&str> = lease.as_object().unwrap().keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(fields, ["agent", "key", "kind", "ms_left", "task_id"], "{lease}");
        assert_eq!((&lease["task_id"], &lease["kind"], &lease["key"], lease["agent"].as_str()), (&task["task_id"], &task["kind"], &task["key"], Some(agent)));
        let left = lease["ms_left"].as_u64().unwrap();
        assert!(left > 0 && left <= task["expires_at_ms"].as_u64().unwrap(), "{lease}");
    }
    let text = out.to_string();
    assert!(!text.contains("Topic A is reported") && !text.contains("prompt"), "no text of a task: {text}");
    // read again and again, the list is the same but for the time left, and the journal's bytes are as they were
    for _ in 0..5 {
        let again = own.call("audit_leases", json!({}));
        assert_eq!(again["open"], 2, "{again}");
    }
    assert_eq!(own.call("audit_status", json!({"telemetry": true}))["leases"], 2);
    assert_eq!(std::fs::read(&wal).unwrap(), before, "seven readings wrote no frame");

    // a task handed in is no longer listed
    assert_eq!(w1.call("audit_submit", json!({"task_id": t1["task_id"], "lines": answer(&t1)}))["status"], "COMMITTED");
    let out = own.call("audit_leases", json!({}));
    assert_eq!((out["open"].as_u64(), out["leases"][0]["agent"].as_str()), (Some(1), Some("w2")), "{out}");
    assert_eq!(w2.call("audit_submit", json!({"task_id": t2["task_id"], "lines": answer(&t2)}))["status"], "COMMITTED");
    // the run goes to its end and is closed: the list is still read, and it is empty
    for _ in 0..20 {
        catch_up(&mut gb);
        let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    let closed = std::fs::read(&wal).unwrap();
    let out = own.call("audit_leases", json!({}));
    assert_eq!((out["status"].as_str(), out["open"].as_u64()), (Some("LEASES"), Some(0)), "{out}");
    assert_eq!(std::fs::read(&wal).unwrap(), closed);
}

/// The preview writes nothing even while the dispatcher keeps an entry pending (Codex review of e7af1bfc, WPRE-01): an agent's
/// lease expired and its failure waits to be written, its long poll waits, and the owner's preview leaves the journal's bytes as
/// they are; the pending failure is then written by the next call that coordinates, the long poll's own.
#[test]
fn a_preview_leaves_the_dispatchers_pending_entries_to_the_calls_that_write() {
    let fx = Fixture::new("previewpending");
    let mut args = fx.args(true);
    args.extend(["--ttl-ms", "400", "--agent-attempts", "4"].iter().map(|s| s.to_string()));
    let server = Server::start(&args);
    let (mut worker, mut owner) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    let task = worker.call("audit_acquire", json!({"max_wait_ms": 0}));
    assert_eq!(task["status"], "DIRECTIVE", "{task}");
    let doc = task["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
    let quote = section(task["prompt"].as_str().unwrap()).lines().find(|l| l.contains("Topic")).unwrap().to_string();
    // the lease expires unanswered; the agent's next acquire finds it, keeps the failure pending and waits
    std::thread::sleep(Duration::from_millis(450));
    let waiting = std::thread::spawn(move || worker.call("audit_acquire", json!({"max_wait_ms": 3000})));
    std::thread::sleep(Duration::from_millis(80));
    let wal = fx.p("run.wal");
    let before = std::fs::read(&wal).unwrap();
    let started = Instant::now();
    let preview = owner.call("audit_withdraw_preview", json!({"doc_id": doc, "exact_quote": quote}));
    let (elapsed, still_waiting) = (started.elapsed(), !waiting.is_finished());
    assert_eq!((preview["status"].as_str(), preview["written"].as_bool()), (Some("PREVIEW"), Some(false)), "{preview}");
    assert_eq!(std::fs::read(&wal).unwrap(), before, "a preview writes nothing, not even what the dispatcher keeps pending");
    assert!(still_waiting && elapsed < Duration::from_millis(500), "observed while the long poll still waits");
    let waited = waiting.join().unwrap();
    assert_eq!(waited["status"], "DIRECTIVE", "{waited}");
    let added = String::from_utf8_lossy(&std::fs::read(&wal).unwrap()[before.len()..]).to_string();
    assert!(added.contains("audit:agent-failures"), "the pending failure is written by the next call that coordinates: {added}");
}

/// The other reading tools write nothing either, not even what the dispatcher keeps pending (Codex review of cf04d481, READ-01):
/// while an agent's failure waits to be written and its long poll waits, the owner's reads leave the journal's bytes as they are.
/// `audit_status` without `telemetry` coordinates: it moves the run on and writes the pending failure.
#[test]
fn the_reading_tools_leave_the_dispatchers_pending_entries_to_the_calls_that_coordinate() {
    let fx = Fixture::new("readpending");
    let mut args = fx.args(true);
    args.extend(["--ttl-ms", "400", "--agent-attempts", "4"].iter().map(|s| s.to_string()));
    let server = Server::start(&args);
    let (mut worker, mut owner) = (Client::connect(server.port, W1), Client::connect(server.port, OWN));
    let task = worker.call("audit_acquire", json!({"max_wait_ms": 0}));
    assert_eq!(task["status"], "DIRECTIVE", "{task}");
    let doc = task["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
    // the lease expires unanswered; the agent's next acquire finds it, keeps the failure pending and waits
    std::thread::sleep(Duration::from_millis(450));
    let waiting = std::thread::spawn(move || worker.call("audit_acquire", json!({"max_wait_ms": 3000})));
    std::thread::sleep(Duration::from_millis(80));
    let wal = fx.p("run.wal");
    let before = std::fs::read(&wal).unwrap();
    let started = Instant::now();
    let reads = [
        ("audit_status", json!({"telemetry": true})),
        ("audit_leases", json!({})),
        ("audit_links", json!({})),
        ("audit_dependents", json!({"doc_id": doc})),
        ("audit_active_claims", json!({})),
        ("audit_coverage", json!({})),
        ("audit_diff", json!({"from": 1})),
        ("audit_fallen", json!({"since": 1})),
    ];
    for (tool, call) in reads {
        let answer = owner.call(tool, call);
        assert!(answer.get("code").is_none(), "{tool}: {answer}");
        assert_eq!(std::fs::read(&wal).unwrap(), before, "{tool} writes nothing, not even what the dispatcher keeps pending");
    }
    // a refused read writes nothing either
    let unknown = owner.call("audit_record", json!({"record": "nothing"}));
    assert_eq!(unknown["code"], "BAD_ARGUMENT", "{unknown}");
    assert_eq!(std::fs::read(&wal).unwrap(), before, "audit_record writes nothing, not even what the dispatcher keeps pending");
    // the status coordinates: it writes what is pending
    let status = owner.call("audit_status", json!({}));
    let (elapsed, still_waiting) = (started.elapsed(), !waiting.is_finished());
    assert!(still_waiting && elapsed < Duration::from_millis(1500), "observed while the long poll still waits");
    let added = String::from_utf8_lossy(&std::fs::read(&wal).unwrap()[before.len()..]).to_string();
    assert!(added.contains("audit:agent-failures"), "audit_status writes the pending failure: {status} {added}");
    let waited = waiting.join().unwrap();
    assert_eq!(waited["status"], "DIRECTIVE", "{waited}");
}

/// A running `sbgk audit-watch` and requests to it.
struct Watch {
    child: Child,
    /// The address the command printed, as a request names it in `Host`.
    host: String,
    port: u16,
}

impl Watch {
    fn start(wal: &str) -> Watch {
        Watch::start_on(wal, "127.0.0.1:0")
    }

    fn start_on(wal: &str, listen: &str) -> Watch {
        let mut child = Command::new(BIN)
            .args(["audit-watch", "--wal", wal, "--listen", listen, "--every-ms", "20"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("start audit-watch");
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
        let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("first line {first:?}: {e}"));
        assert_eq!(hello["status"], "WATCHING", "{hello}");
        let host = hello["url"].as_str().unwrap().trim_start_matches("http://").trim_end_matches('/').to_string();
        let port = host.rsplit(':').next().unwrap().parse().unwrap();
        Watch { child, host, port }
    }

    /// The status code, the head and the body of the answer to a request given as its first line and its headers. `None` when
    /// the server closed the connection without an answer.
    fn ask(&self, first: &str, headers: &[&str]) -> Option<(u16, String, String)> {
        let mut stream = TcpStream::connect(self.host.as_str()).unwrap();
        let head: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
        write!(stream, "{first}\r\n{head}\r\n").unwrap();
        let mut reply = String::new();
        std::io::Read::read_to_string(&mut stream, &mut reply).ok()?;
        let (head, body) = reply.split_once("\r\n\r\n")?;
        Some((head.split(' ').nth(1)?.parse().ok()?, head.to_string(), body.to_string()))
    }

    /// The status code of a GET with these headers beside `Host`.
    fn code(&self, path: &str, headers: &[&str]) -> u16 {
        let host = format!("Host: {}", self.host);
        let all: Vec<&str> = std::iter::once(host.as_str()).chain(headers.iter().copied()).collect();
        self.ask(&format!("GET {path} HTTP/1.1"), &all).map_or(0, |(code, _, _)| code)
    }

    /// The status code and the body of a GET.
    fn get(&self, path: &str) -> (u16, String) {
        let (code, _, body) = self.ask(&format!("GET {path} HTTP/1.1"), &[&format!("Host: {}", self.host)]).expect("an answer");
        (code, body)
    }

    fn json(&self, path: &str) -> Value {
        let (code, body) = self.get(path);
        assert_eq!(code, 200, "{path}: {body}");
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{path}: {e}: {body}"))
    }

    /// The status once it passes `test`, asked for at most ten seconds.
    fn until(&self, what: &str, test: impl Fn(&Value) -> bool) -> Value {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let status = self.json("/status")["status"].clone();
            if test(&status) {
                return status;
            }
            assert!(Instant::now() < end, "the watch never came to {what}: {status}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `audit-watch` follows the journal of a running server from another process: it has every frame the server wrote, it says a
/// writer holds the journal, and what it shows stands as `audit-prov` and `audit-verify` say of the same frames. It reads only:
/// the journal is byte for byte what the server wrote, and a server stopped and started again on the journal starts while the
/// watch goes on asking for its file. A closed run is shown as closed.
#[test]
fn the_watch_follows_the_journal_of_a_running_server_and_stands_in_no_writers_way() {
    let fx = Fixture::new("watch");
    let wal = fx.p("run.wal");
    // the watch starts before the journal is there, and waits for it
    let watch = Watch::start(&wal);
    assert_eq!(watch.json("/status")["status"]["mode"], "waiting");
    let (code, waiting) = watch.get("/");
    assert!(code == 200 && waiting.contains("Waiting for the first frame"), "{waiting}");
    let frames_of = |fx: &Fixture| reading(fx, &["audit-verify"]).1["entries"].as_u64().unwrap();
    let caught = |watch: &Watch, frames: u64, mode: &str| {
        watch.until(&format!("{frames} frames, {mode}"), |s| s["frames"] == frames && s["mode"] == mode && s["more"] == false && s["pending"] == 0)
    };

    let server = Server::start(&fx.args(true));
    let start = frames_of(&fx);
    caught(&watch, start, "live");
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let mut gb = Client::connect(server.port, GB);
    // the two readings, and after each the watch has the frames written
    let mut first_report = Value::Null;
    for agent in [&mut w1, &mut w2] {
        catch_up(&mut gb);
        let t = agent.call("audit_acquire", json!({"max_wait_ms": 200}));
        assert_eq!(t["kind"], "EXTEND", "{t}");
        let lines = answer(&t);
        if lines[0]["exact_quote"] == "Topic A is reported." {
            first_report = lines[0]["doc_id"].clone();
        }
        assert_eq!(agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}))["status"], "COMMITTED");
        caught(&watch, frames_of(&fx), "live");
    }
    // a page that held the frames of the start is sent the frames since, and the records they made
    let epoch = watch.json("/status")["epoch"].as_u64().unwrap();
    let delta = watch.json(&format!("/delta?epoch={epoch}&frames={start}"))["delta"].clone();
    assert_eq!(delta["from"], start, "{delta}");
    assert_eq!(delta["frames"].as_array().unwrap().len() as u64, frames_of(&fx) - start, "{delta}");
    assert_eq!((delta["quotes"].as_object().unwrap().len(), delta["recs"].as_object().unwrap().len()), (2, 2), "{delta}");
    assert_eq!(delta["status"]["mode"], "live", "{delta}");

    // the server is stopped and started again on the journal while the watch asks for its file every 20 ms: it starts
    drop((w1, w2, gb));
    drop(server);
    let stopped = frames_of(&fx);
    caught(&watch, stopped, "recorded");
    let server = Server::start(&fx.args(false));
    caught(&watch, frames_of(&fx), "live");
    let (mut w1, mut gb, mut own) = (Client::connect(server.port, W1), Client::connect(server.port, GB), Client::connect(server.port, OWN));
    for _ in 0..20 {
        catch_up(&mut gb);
        let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    // the owner withdraws the quote of the first report: what rested on it falls on the page as in the export
    let gone = own.call("audit_withdraw_text", json!({"doc_id": first_report, "exact_quote": "Topic A is reported."}));
    assert_eq!(gone["status"], "REVOKED", "{gone}");
    caught(&watch, frames_of(&fx), "live");
    // the question it reached is answered again from what still stands, and the run is closed
    for _ in 0..20 {
        catch_up(&mut gb);
        let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    let end = frames_of(&fx);
    let status = caught(&watch, end, "closed");
    assert_eq!(status["writer"], true, "the server still holds the journal of the closed run: {status}");

    // what the watch shows of these frames is what audit-verify and audit-prov say of them
    let data = watch.json("/data");
    let (_, verified, _) = reading(&fx, &["audit-verify"]);
    assert_eq!(data["frames"].as_array().unwrap().len() as u64, end);
    for field in ["audit_root", "engine_root", "wal_head", "records"] {
        assert_eq!(data["verify"][field], verified[field], "{field}");
    }
    let (code, exported, stderr) = reading(&fx, &["audit-prov", "--out", &fx.p("watch.prov.jsonld")]);
    assert_eq!((code, exported["frames"].as_u64()), (Some(0), Some(end)), "{exported} {stderr}");
    let export: Value = serde_json::from_slice(&std::fs::read(fx.p("watch.prov.jsonld")).unwrap()).unwrap();
    let graph = export["@graph"].as_array().unwrap();
    let is = |n: &Value, t: &str| n["@type"].as_array().unwrap().iter().any(|x| x == t);
    let short = |iri: &Value| format!("@{}", &iri.as_str().unwrap().rsplit(':').next().unwrap()[..16]);
    let labelled = |n: &&Value| is(n, "yuce:Record") && ["observe", "claim", "hypothesis", "done"].contains(&n["yuce:kind"].as_str().unwrap());
    let mut exported_all: Vec<String> = graph.iter().filter(labelled).map(|n| format!("@{}", &n["yuce:recordId"].as_str().unwrap()[..16])).collect();
    let mut exported_standing: Vec<String> = graph
        .iter()
        .filter(|n| is(n, "yuce:Standing") && n.get("prov:wasInvalidatedBy").is_none())
        .map(|n| short(&n["prov:specializationOf"]))
        .filter(|id| exported_all.contains(id))
        .collect();
    let (mut shown_all, mut shown_standing, mut fell) = (Vec::new(), Vec::new(), 0);
    for group in ["quotes", "recs"] {
        for (label, record) in data[group].as_object().unwrap() {
            let id = record["kid"].as_str().unwrap().to_string();
            let periods = data["periods"][label].as_array().unwrap();
            if periods.iter().any(|p| p[1].is_null()) {
                shown_standing.push(id.clone());
            }
            fell += usize::from(periods.iter().any(|p| p[2] == "basis"));
            shown_all.push(id);
        }
    }
    for list in [&mut exported_all, &mut exported_standing, &mut shown_all, &mut shown_standing] {
        list.sort();
    }
    assert_eq!(shown_all, exported_all, "the records of the page and of the export");
    assert_eq!(shown_standing, exported_standing, "what stands on the page and in the export");
    assert!(fell >= 1 && shown_standing.len() < shown_all.len(), "the withdrawal made records fall: {fell} fell, {} stand", shown_standing.len());
    // the watched page is served for these frames, and the journal is what the server wrote: the watch wrote nothing
    let (code, page) = watch.get("/");
    assert!(code == 200 && page.contains("\"live\":{") && page.contains("connect-src 'self'"), "{}", &page[..page.len().min(400)]);
    drop((w1, gb, own));
    drop(server);
    let after = std::fs::read(&wal).unwrap();
    assert_eq!(after.iter().filter(|b| **b == b'\n').count() as u64, end);
    let (code, last, stderr) = reading(&fx, &["audit-verify"]);
    assert_eq!((code, last["status"].as_str(), last["torn_tail_bytes"].as_u64()), (Some(0), Some("VERIFIED"), Some(0)), "{last} {stderr}");
    assert_eq!(last["wal_head"], verified["wal_head"]);
    // the watch asks for the writer again at its next step: the frames and the mode were the same before the server stopped, so
    // what is waited for is the answer that no writer holds the journal
    let status = watch.until(&format!("{end} frames, closed, no writer"), |s| s["frames"] == end && s["mode"] == "closed" && s["writer"] == false);
    assert_eq!((status["more"].as_bool(), status["pending"].as_u64()), (Some(false), Some(0)), "{status}");
}

/// The server of `audit-watch` answers its own page and no other: a request under another name, one a page of another site
/// makes (the browser says so in `Sec-Fetch-Site` and `Origin`), or one that is no GET gets no data. A request whose head does
/// not come in time is dropped. A journal with a damaged frame is shown up to the frame before it, and a journal whose file is
/// gone says so. The address printed is the one the listener got.
#[test]
fn the_watch_answers_its_own_page_only_and_says_what_is_wrong_with_a_journal() {
    let fx = Fixture::new("watchhttp");
    let wal = fx.p("run.wal");
    {
        let server = Server::start(&fx.args(true));
        let (mut w1, mut gb) = (Client::connect(server.port, W1), Client::connect(server.port, GB));
        for _ in 0..2 {
            catch_up(&mut gb);
            let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
            assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
        }
    }
    let bytes = std::fs::read(&wal).unwrap();
    let frames = bytes.iter().filter(|b| **b == b'\n').count() as u64;
    let watch = Watch::start(&wal);
    watch.until("the whole journal", |s| s["frames"] == frames && s["mode"] == "recorded");

    // its own page: the reader's own navigation and the page's own requests
    let own = format!("Origin: http://{}", watch.host);
    assert_eq!(watch.code("/", &["Sec-Fetch-Site: none"]), 200);
    assert_eq!(watch.code("/delta?epoch=0&frames=1", &["Sec-Fetch-Site: same-origin", &own]), 200);
    assert_eq!(watch.code("/data", &[]), 200);
    // another site's page, by whatever it says of itself, and another name for this port
    for foreign in [&["Sec-Fetch-Site: cross-site"][..], &["Sec-Fetch-Site: same-site"], &["Origin: https://evil.example"], &["Origin: null"]] {
        for path in ["/", "/data", "/delta?epoch=0&frames=1", "/status"] {
            assert_eq!(watch.code(path, foreign), 403, "{path} {foreign:?}");
        }
    }
    let other_name = watch.ask("GET /data HTTP/1.1", &[&format!("Host: evil.example:{}", watch.port)]).unwrap();
    assert_eq!(other_name.0, 403, "{}", other_name.1);
    assert!(!other_name.2.contains("frames"), "no data under another name");
    // GET only, and only the four things it gives
    let host = format!("Host: {}", watch.host);
    assert_eq!(watch.ask("POST / HTTP/1.1", &[&host, "Content-Length: 0"]).unwrap().0, 405);
    assert_eq!(watch.ask("DELETE /data HTTP/1.1", &[&host]).unwrap().0, 405);
    assert_eq!(watch.code("/run.wal", &[]), 404);
    assert_eq!(watch.code("/../run.wal", &[]), 404);
    // every answer forbids a frame of another site and a read as another site's resource
    let (_, head, _) = watch.ask("GET / HTTP/1.1", &[&host]).unwrap();
    for header in ["Content-Security-Policy: frame-ancestors 'none'", "Cross-Origin-Resource-Policy: same-origin", "X-Content-Type-Options: nosniff"] {
        assert!(head.contains(header), "{header} in {head}");
    }
    // a head that does not come in time: the connection is answered with a refusal within a few seconds, not held
    let started = Instant::now();
    let mut slow = TcpStream::connect(watch.host.as_str()).unwrap();
    write!(slow, "GET / HTTP/1.1\r\nHost: {}\r\n", watch.host).unwrap();
    let mut reply = String::new();
    let _ = std::io::Read::read_to_string(&mut slow, &mut reply);
    assert!(reply.starts_with("HTTP/1.1 400") && started.elapsed() < Duration::from_secs(8), "{reply:?} after {:?}", started.elapsed());
    // the same page asked for again is the same bytes
    assert_eq!(watch.get("/").1, watch.get("/").1);

    // a journal with a changed byte in a frame: the frames before it are shown, and the page is told which frame does not pass
    let mut lines: Vec<Vec<u8>> = bytes.split_inclusive(|b| *b == b'\n').map(<[u8]>::to_vec).collect();
    let at = lines.len() / 2;
    let place = lines[at].windows(9).position(|w| w == b"\"actor\":\"").unwrap() + 9;
    lines[at][place] = if lines[at][place] == b'x' { b'y' } else { b'x' };
    std::fs::write(fx.p("damaged.wal"), lines.concat()).unwrap();
    let damaged = Watch::start(&fx.p("damaged.wal"));
    let status = damaged.until("the damaged frame", |s| s["mode"] == "broken");
    assert_eq!((status["frames"].as_u64(), status["broken"]["frame"].as_u64()), (Some(at as u64), Some(at as u64)), "{status}");
    assert_eq!(damaged.json("/data")["frames"].as_array().unwrap().len(), at);
    let delta = damaged.json(&format!("/delta?epoch=0&frames={at}"));
    assert_eq!((delta["delta"]["status"]["mode"].as_str(), delta["delta"]["frames"].as_array().map(Vec::len)), (Some("broken"), Some(0)), "{delta}");
    assert_eq!(damaged.get("/").0, 200);

    // a journal whose file is taken away: the page keeps the frames read and says the file is gone
    std::fs::write(fx.p("gone.wal"), &bytes).unwrap();
    let gone = Watch::start(&fx.p("gone.wal"));
    gone.until("the whole journal", |s| s["frames"] == frames);
    std::fs::remove_file(fx.p("gone.wal")).unwrap();
    let status = gone.until("the missing file", |s| s["unreadable"].is_string());
    assert_eq!((status["frames"].as_u64(), status["unreadable"].as_str()), (Some(frames), Some("the file is no longer there")), "{status}");
    assert_eq!(gone.json("/data")["frames"].as_array().unwrap().len() as u64, frames);

    // `localhost` may be either loopback address: the address printed is the one that answers, under its own name
    let named = Watch::start_on(&wal, "localhost:0");
    let status = named.until("the whole journal", |s| s["frames"] == frames);
    assert_eq!(status["mode"], "recorded");
    assert_eq!(named.code("/status", &[]), 200);
    assert_eq!(named.ask("GET /status HTTP/1.1", &[&format!("Host: localhost:{}", named.port)]).unwrap().0, 200);
}

/// Codex's positive case for PR 61 (7d472d88), as he wrote it: only the owner has `audit_link_status`; a swarm agent and the graph
/// builder are refused it, mark or not. The owner's decision on a link of a claim the owner wrote is refused without the mark and
/// stands with it, and the journal holds the mark.
#[test]
fn codex_only_owner_can_use_arbitration_and_the_wire_marks_it() {
    use sbgk_core::audit::state::AuditState;
    use sbgk_core::audit::{AuditStore, LinkStatus, Scope};
    use sbgk_core::hash::to_hex;
    let fx = Fixture::new("codex-four-eyes-wire");
    let server = Server::start(&fx.args(true));
    for token in [W1, GB] {
        let mut c = Client::connect(server.port, token);
        assert!(!c.tools().iter().any(|t| t == "audit_link_status"));
        assert_eq!(c.call("audit_link_status", json!({"link":"0".repeat(64),"status":"accepted","basis":["0".repeat(64)],"arbitration":true}))["code"], -32003);
    }
    drop(server);
    let wal = PathBuf::from(fx.p("run.wal"));
    let mut s = AuditState::open(&wal).unwrap();
    let docs = AuditStore::docs(&s);
    let da = docs.iter().find(|d| s.doc_text(d).unwrap_or_default().contains("Topic A is reported.")).unwrap().clone();
    let db = docs.iter().find(|d| s.doc_text(d).unwrap_or_default().contains("Topic B is reported.")).unwrap().clone();
    let mut seed = |by: &str, doc: &str, quote: &str| {
        let r = s.submit_records(
            by,
            &format!("seed-{by}"),
            &Scope { docs: vec![doc.into()], ..Default::default() },
            &[
                json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["topic"]}),
                json!({"kind":"claim","local_id":"c","text":quote,"subject":"topic","stance":"reported","based_on":["o"]}),
            ],
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        r.accepted[1]
    };
    let a = seed("own", &da, "Topic A is reported.");
    let b = seed("w1", &db, "Topic B is reported.");
    let link = s.add_link("builder", &a, "supports", &b, &[a]).unwrap().id;
    drop(s);
    let server = Server::start(&fx.args(false));
    let mut own = Client::connect(server.port, OWN);
    let mut args = json!({"link":to_hex(&link.0),"status":"accepted","basis":[to_hex(&a.0)]});
    assert_eq!(own.call("audit_link_status", args.clone())["code"], "REFUSED");
    args["arbitration"] = json!(true);
    assert_eq!(own.call("audit_link_status", args)["status"], "DECIDED");
    drop(server);
    let (s, _) = AuditState::verify_states(&wal, &mut |_, _, _| {}).unwrap();
    assert_eq!(s.link(&link).unwrap().status, LinkStatus::Accepted);
    assert!(std::fs::read_to_string(&wal).unwrap().contains("\"arbitration\":true"));
}

/// `--reading-only` (0.2.3): a shard reads and records, and its summaries are made outside its journal. On the wire it is issued
/// no summary, is terminal once its reading is done, says so in its receipt, closes, and its journal pins the setting.
#[test]
fn a_reading_only_shard_is_issued_no_summary_and_closes_after_its_reading() {
    let fx = Fixture::new("readingonly");
    let server = Server::start(&[fx.args(true), vec!["--reading-only".to_string()]].concat());
    let (mut w1, mut own, mut gb) = (Client::connect(server.port, W1), Client::connect(server.port, OWN), Client::connect(server.port, GB));
    let mut kinds = Vec::new();
    for _ in 0..20 {
        catch_up(&mut gb);
        let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        kinds.push(t["kind"].as_str().unwrap().to_string());
        let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
        assert_eq!(r["status"], "COMMITTED", "{t} -> {r}");
    }
    assert!(kinds.iter().any(|k| k == "EXTEND") && !kinds.iter().any(|k| k == "SUMMARIZE"), "{kinds:?}");
    catch_up(&mut gb);
    let receipt = own.call("audit_terminal_receipt", json!({}));
    assert_eq!(receipt["status"], "TERMINAL", "{receipt}");
    assert_eq!((receipt["summaries"]["in_journal"].as_bool(), receipt["outcomes"].as_object().map(|o| o.len())), (Some(false), Some(0)), "{receipt}");
    assert_eq!(own.call("audit_close", json!({}))["status"], "CLOSED");
    drop(server);
    let s = sbgk_core::audit::state::AuditState::open(&PathBuf::from(fx.p("run.wal"))).unwrap();
    assert_eq!(s.checkpoint("audit:mcp:coverage").unwrap()["context"]["reading_only"], true);
}

/// The arguments of a run with many small sections and no graph builder: enough tasks for a stream of writes.
fn stream_args(fx: &Fixture, fresh: bool) -> Vec<String> {
    [fx.args(fresh), ["--build-scope", "none", "--section-bytes", "64"].map(String::from).to_vec()].concat()
}

/// Readers of the reading tools while two agents write and the owner withdraws (verdict v2 of 20.11.2026, section 3, a condition of
/// the copy-on-write release): no call fails, every answer is taken from one whole state - two answers at one point are the same
/// answer - and the roots only move forward with the transaction sequence. The journal then verifies and resumes at the last roots.
#[test]
fn readers_during_a_stream_of_writes_and_withdrawals_see_whole_states_and_roots_only_move_forward() {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    type Sample = (u64, Value);
    let part = |doc: char, n: usize| format!("# Part {n:02}\nTopic {doc}{n:02} is reported here.\n\n");
    let (a, b): (String, String) = ((0..24).map(|n| part('A', n)).collect(), (0..24).map(|n| part('B', n)).collect());
    let fx = Fixture::with_docs("stream", &[("a.md", &a), ("b.md", &b)]);
    // a run without a graph builder names none
    let subjects = json!({"subjects": [{"token": W1, "role": "swarm", "id": "w1"}, {"token": W2, "role": "swarm", "id": "w2"},
                                       {"token": OWN, "role": "owner", "id": "own"}]});
    std::fs::write(fx.p("subjects.json"), subjects.to_string()).unwrap();
    let log = fx.0.join("server.stderr");
    let server = Server::start_with_stderr(&stream_args(&fx, true), Stdio::from(std::fs::File::create(&log).unwrap()));
    let port = server.port;
    let writing = AtomicBool::new(true);
    let observes: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let (commits, withdrawals, reads) = std::thread::scope(|scope| {
        let writers: Vec<_> = [W1, W2]
            .into_iter()
            .map(|token| {
                let observes = &observes;
                scope.spawn(move || {
                    let mut agent = Client::connect(port, token);
                    let (mut commits, mut waits) = (0, 0);
                    for _ in 0..200 {
                        let t = agent.call("audit_acquire", json!({"max_wait_ms": 20}));
                        match t["status"].as_str() {
                            Some("COMPLETE") => break,
                            Some("WAIT") if waits > 40 => break,
                            Some("WAIT") => {
                                waits += 1;
                                continue;
                            }
                            Some(_) => waits = 0,
                            None => panic!("acquire failed: {t}"),
                        }
                        let r = agent.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
                        assert!(r["status"].is_string() && r["code"].is_null(), "{t} -> {r}");
                        if r["status"] == "COMMITTED" {
                            commits += 1;
                            let locals = r["accepted_locals"].as_object().unwrap();
                            let mut seen = observes.lock().unwrap();
                            seen.extend(locals.iter().filter(|(local, _)| local.ends_with("o1")).map(|(_, id)| id.as_str().unwrap().to_string()));
                        }
                    }
                    commits
                })
            })
            .collect();
        let owner = scope.spawn(|| {
            let mut own = Client::connect(port, OWN);
            let mut withdrawn = 0;
            while writing.load(Ordering::SeqCst) || withdrawn == 0 {
                // every third quote that was committed, as it comes
                let next = observes.lock().unwrap().iter().step_by(3).nth(withdrawn).cloned();
                match next {
                    Some(id) => {
                        let r = own.call("audit_revoke", json!({"record": id}));
                        assert_eq!(r["status"], "REVOKED", "{r}");
                        withdrawn += 1;
                    }
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            withdrawn
        });
        let readers: Vec<_> = (0..3)
            .map(|k| {
                let (writing, observes) = (&writing, &observes);
                scope.spawn(move || {
                    let mut own = Client::connect(port, OWN);
                    let (mut roots, mut fallen): (Vec<Sample>, Vec<Sample>) = (Vec::new(), Vec::new());
                    while writing.load(Ordering::SeqCst) {
                        let s = own.call("audit_status", json!({}));
                        assert!(s["code"].is_null(), "reader {k}: {s}");
                        let point = s["transaction_sequence"].as_u64().expect("a 0.2 journal counts its transactions");
                        roots.push((point, json!([s["audit_root"], s["engine_root"], s["wal_head"], s["records"]])));
                        let f = own.call("audit_fallen", json!({"limit": 1000}));
                        assert!(f["code"].is_null() && f["status"] == "FALLEN", "reader {k}: {f}");
                        fallen.push((f["at"].as_u64().unwrap(), f));
                        let first = observes.lock().unwrap().first().cloned();
                        if let Some(id) = first {
                            let d = own.call("audit_dependents", json!({"record": id}));
                            assert!(d["code"].is_null() && d["status"].is_string(), "reader {k}: {d}");
                        }
                    }
                    (roots, fallen)
                })
            })
            .collect();
        let commits: usize = writers.into_iter().map(|w| w.join().unwrap()).sum();
        writing.store(false, Ordering::SeqCst);
        let withdrawals = owner.join().unwrap();
        let reads: Vec<(Vec<Sample>, Vec<Sample>)> = readers.into_iter().map(|r| r.join().unwrap()).collect();
        (commits, withdrawals, reads)
    });
    assert!(commits >= 40 && withdrawals >= 4, "{commits} answers committed, {withdrawals} withdrawals");
    let (mut at_point, mut report_at): (BTreeMap<u64, Value>, BTreeMap<u64, Value>) = (BTreeMap::new(), BTreeMap::new());
    let mut samples = 0;
    for (k, (roots, fallen)) in reads.iter().enumerate() {
        samples += roots.len();
        for pair in roots.windows(2) {
            assert!(pair[0].0 <= pair[1].0, "reader {k}: the transaction sequence went back: {pair:?}");
            assert!(pair[0].0 < pair[1].0 || pair[0].1 == pair[1].1, "reader {k}: the roots changed at one point: {pair:?}");
        }
        for pair in fallen.windows(2) {
            assert!(pair[0].0 <= pair[1].0, "reader {k}: the report went back from point {} to {}", pair[0].0, pair[1].0);
        }
        for (point, value) in roots {
            assert_eq!(at_point.entry(*point).or_insert_with(|| value.clone()), value, "reader {k}: two states at point {point}");
        }
        for (point, value) in fallen {
            assert_eq!(report_at.entry(*point).or_insert_with(|| value.clone()), value, "reader {k}: two reports at point {point}");
        }
    }
    assert!(samples >= 30 && at_point.len() >= 10, "{samples} reads over {} points", at_point.len());
    let points: Vec<&Value> = at_point.values().collect();
    assert!(points.windows(2).all(|p| p[0][0] != p[1][0]), "every transaction moves the audit root");

    let mut own = Client::connect(port, OWN);
    let end = own.call("audit_status", json!({}));
    drop(own);
    let mut server = server;
    assert!(server.child.try_wait().map(|status| status.is_none()).unwrap_or(false), "the server is still running");
    drop(server);
    let stderr = std::fs::read_to_string(&log).unwrap();
    assert!(!stderr.contains("panicked"), "{stderr}");
    let out = Command::new(BIN).args(["audit-verify", "--wal", &fx.p("run.wal")]).output().unwrap();
    let verified: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((out.status.code(), verified["status"].as_str()), (Some(0), Some("VERIFIED")), "{verified}");
    assert_eq!((verified["audit_root"].clone(), verified["engine_root"].clone()), (end["audit_root"].clone(), end["engine_root"].clone()));
    let resumed = Server::start(&stream_args(&fx, false));
    assert_eq!(resumed.hello["audit"]["audit_root"], end["audit_root"], "{}", resumed.hello);
}

/// A crash in the middle of writing a frame (verdict v2 of 20.11.2026, section 4, point 1). An agent's answer is two frames, its
/// records and then the mark that its task is done; the crash may hit either. Whatever part of the frame reached the disk,
/// `audit-verify` reports a torn tail of exactly that many bytes over the state of the frames before it; a resumed server keeps the
/// cut bytes beside the journal, starts at those roots, and the run goes on to a journal that verifies.
#[test]
fn a_frame_cut_in_the_middle_of_its_write_is_a_torn_tail_and_the_journal_resumes_at_the_frame_before() {
    let fx = Fixture::new("midframe");
    let server = Server::start(&fx.args(true));
    let mut w1 = Client::connect(server.port, W1);
    for _ in 0..2 {
        let t = w1.call("audit_acquire", json!({}));
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}))["status"], "COMMITTED");
    }
    drop(w1);
    drop(server);
    let wal = fx.p("run.wal");
    let whole = std::fs::read(&wal).unwrap();
    let starts: Vec<usize> = std::iter::once(0).chain(whole.iter().enumerate().filter(|(_, b)| **b == b'\n').map(|(i, _)| i + 1)).collect();
    let (records, done, end) = (starts[starts.len() - 3], starts[starts.len() - 2], whole.len());
    let kind = |a: usize, z: usize| serde_json::from_slice::<Value>(&whole[a..z]).unwrap()["body"]["command"]["kind"].clone();
    assert_eq!((kind(records, done), kind(done, end)), (json!("submit"), json!("batch")), "the answer, then its task marked done");
    let verify = |path: &str| {
        let out = Command::new(BIN).args(["audit-verify", "--wal", path]).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap())
    };
    for (start, stop) in [(records, done), (done, end)] {
        let prefix = fx.p(&format!("prefix-{start}.wal"));
        std::fs::write(&prefix, &whole[..start]).unwrap();
        let (code, before) = verify(&prefix);
        assert_eq!(code, Some(0), "{before}");
        let frame = stop - start;
        for cut in [1, frame / 2, frame - 1] {
            let path = fx.p(&format!("cut-{start}-{cut}.wal"));
            std::fs::write(&path, &whole[..start + cut]).unwrap();
            let (code, v) = verify(&path);
            assert_eq!((code, v["status"].as_str(), v["torn_tail_bytes"].as_u64()), (Some(1), Some("TORN_TAIL"), Some(cut as u64)), "cut {cut}: {v}");
            for key in ["entries", "records", "audit_root", "engine_root", "session_root", "wal_head"] {
                assert_eq!(v[key], before[key], "frame at {start}, cut {cut}: {key}");
            }
        }
        // the server resumes from the cut journal, at the frame before, and the run goes on
        std::fs::write(&wal, &whole[..start + frame / 2]).unwrap();
        let resumed = Server::start(&fx.args(false));
        let hello = &resumed.hello["audit"];
        assert_eq!((hello["torn_tail_bytes"].as_u64(), hello["audit_root"].clone()), (Some((frame / 2) as u64), before["audit_root"].clone()), "{hello}");
        assert_eq!(std::fs::read(hello["torn_tail_kept_in"].as_str().unwrap()).unwrap(), whole[start..start + frame / 2]);
        let (mut w1, mut gb) = (Client::connect(resumed.port, W1), Client::connect(resumed.port, GB));
        let mut answers = Vec::new();
        for _ in 0..12 {
            catch_up(&mut gb);
            let t = w1.call("audit_acquire", json!({"max_wait_ms": 200}));
            match t["status"].as_str() {
                Some("COMPLETE") => break,
                Some("WAIT") => continue,
                _ => {}
            }
            let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": answer(&t)}));
            assert!(r["code"].is_null(), "{t} -> {r}");
            answers.push((t["key"].clone(), r["status"].clone()));
        }
        assert!(answers.iter().all(|(_, status)| status == "COMMITTED"), "{answers:?}");
        drop(resumed);
        let (code, v) = verify(&wal);
        assert_eq!((code, v["status"].as_str()), (Some(0), Some("VERIFIED")), "{v}");
        std::fs::write(&wal, &whole).unwrap();
    }
}

/// 0.3.0: a run that starts without a document. The owner puts each source while the run goes on, an agent reads it as any
/// document, and the owner reads a value back by its key, writes a context checkpoint and withdraws a text for a reason.
#[test]
fn a_run_that_starts_without_a_document_takes_its_sources_as_they_come() {
    let fx = Fixture::new("stream");
    // a run without a graph builder names none among its subjects
    let subjects = json!({"subjects": [{"token": W1, "role": "swarm", "id": "w1"}, {"token": OWN, "role": "owner", "id": "own"}]});
    std::fs::write(fx.0.join("readers.json"), subjects.to_string()).unwrap();
    let args: Vec<String> = ["--wal", &fx.p("run.wal"), "--subjects", &fx.p("readers.json"), "--questions", &fx.p("questions.json"), "--run-id", "stream-run"]
        .iter()
        .map(|s| s.to_string())
        .chain(["--empty-start", "--build-scope", "none", "--reading-only"].map(String::from))
        .collect();
    // a start without a document is not a start on a folder too
    let both =
        Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(&args).args(["--docs", &fx.p("repo")]).output().unwrap();
    assert_eq!(both.status.code(), Some(2));
    assert!(!Path::new(&fx.p("run.wal")).exists(), "a refused start leaves no journal");
    // nor of a run that makes its summaries in the journal: it would be asked for them before any source came
    let in_journal: Vec<String> = args.iter().filter(|arg| *arg != "--reading-only").cloned().collect();
    let refused = Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(&in_journal).output().unwrap();
    let said = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(2), "{said}");
    assert!(said.contains("--empty-start needs --reading-only") && said.contains("Start it with --reading-only"), "{said}");
    assert!(!Path::new(&fx.p("run.wal")).exists(), "a refused start leaves no journal");

    let server = Server::start(&args);
    let (mut own, mut w1) = (Client::connect(server.port, OWN), Client::connect(server.port, W1));
    let status = own.call("audit_status", json!({}));
    assert_eq!((status["rules_version"].as_str(), status["context_checkpoints"].as_u64()), (Some("r2r-audit-rules/4"), Some(0)), "{status}");
    // no document yet: the run is not warned that no document holds a term of its questions
    assert_eq!(status.get("about_unmatched"), None, "{status}");
    assert_ne!(w1.call("audit_acquire", json!({}))["status"], "DIRECTIVE", "nothing to read yet");
    assert_eq!(w1.call("audit_put_document", json!({"doc_id": "x", "text": "x"}))["code"], -32003, "a source is the owner's to put");

    let put = own.call("audit_put_document", json!({"doc_id": "context-1", "text": "# Context\n\nTopic A is 10.\n\nTopic B is 5.\n"}));
    assert_eq!((put["status"].as_str(), put["documents"].as_u64()), (Some("PUT"), Some(1)), "{put}");
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!((t["status"].as_str(), t["kind"].as_str()), (Some("DIRECTIVE"), Some("EXTEND")), "{t}");
    assert!(section(t["prompt"].as_str().unwrap()).contains("Topic A is 10."), "{t}");
    let p = t["local_id_prefix"].as_str().unwrap();
    let lines = json!([
        {"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "context-1", "exact_quote": "Topic A is 10.", "terms": ["topic"]},
        {"kind": "observe", "local_id": format!("{p}o2"), "doc_id": "context-1", "exact_quote": "Topic B is 5.", "terms": ["topic"]},
        {"kind": "claim", "local_id": format!("{p}c1"), "text": "A is 10.", "subject": "A", "object": "10", "stance": "reported", "based_on": [format!("{p}o1")]},
        {"kind": "claim", "local_id": format!("{p}c2"), "text": "B is 5.", "subject": "B", "object": "5", "stance": "reported", "based_on": [format!("{p}o2")]},
        // rules 4: a claim on two claims
        {"kind": "claim", "local_id": format!("{p}c3"), "text": "A and B make 15.", "subject": "A+B", "object": "15", "stance": "reported",
         "based_on": [format!("{p}c1"), format!("{p}c2")]},
    ]);
    let stored = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}));
    assert_eq!(stored["status"], "COMMITTED", "{stored}");

    let sum = own.call("audit_key", json!({"key": "A+B"}));
    assert_eq!((sum["state"].as_str(), sum["value"].as_str()), (Some("ACTIVE"), Some("15")), "{sum}");
    assert_eq!(own.call("audit_key", json!({}))["code"], "BAD_ARGUMENT");
    let chains = own.call("audit_status", json!({"telemetry": true}))["claim_chains"].clone();
    assert_eq!((chains["max_depth"].as_u64(), chains["standing_without_own_quote"].as_u64()), (Some(1), Some(1)), "{chains}");
    let written = own.call("audit_checkpoint", json!({"raw_context": "context-1"}));
    assert_eq!((written["status"].as_str(), written["epoch"].as_u64(), written["listed"].as_u64()), (Some("CHECKPOINTED"), Some(1), Some(3)), "{written}");
    assert_eq!(own.call("audit_context", json!({}))["active"].as_array().map(Vec::len), Some(3));

    // B is withdrawn for a reason that is itself a source: B and the sum fall, A stands
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "notice-1", "text": "Notice: the statement of B was an error.\n"}))["documents"], 2);
    let unknown = own.call("audit_withdraw_text", json!({"doc_id": "context-1", "exact_quote": "Topic B is 5.", "reason_source_id": "no-such-notice"}));
    assert_eq!(unknown["error"]["field"], "reason_source_id", "{unknown}");
    let gone = own.call("audit_withdraw_text", json!({"doc_id": "context-1", "exact_quote": "Topic B is 5.", "reason_source_id": "notice-1"}));
    assert_eq!((gone["status"].as_str(), gone["also_revoked"].as_u64(), gone["fell"].as_u64()), (Some("REVOKED"), Some(1), Some(2)), "{gone}");
    let first = own.call("audit_context", json!({"epoch": 1}));
    assert_eq!((first["active"].as_array().map(Vec::len), first["active"][0]["key"].as_str()), (Some(1), Some("A")), "{first}");
    assert_eq!(first["dropped"]["AFFECTED_BY_EVIDENCE_CHANGE"].as_array().map(Vec::len), Some(2), "{first}");
    let table = own.call("audit_keys", json!({"required": ["A", "B", "Z"]}));
    let missing: Vec<&str> = table["missing_required_keys"].as_array().unwrap().iter().map(|m| m["key"].as_str().unwrap()).collect();
    assert_eq!(missing, ["B", "Z"], "{table}");
    assert_eq!(own.call("audit_keys", json!({"required": "A"}))["code"], "BAD_ARGUMENT");
    assert_eq!(own.call("audit_context", json!({"epoch": 2}))["status"], "NO_CONTEXT_CHECKPOINT");

    drop((own, w1, server));
    let out = Command::new(BIN).args(["audit-verify", "--wal", &fx.p("run.wal")]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((out.status.code(), v["status"].as_str(), v["sources"]["put_document_entries"].as_u64()), (Some(0), Some("VERIFIED"), Some(2)), "{v}");
    // and the reads of the journal answer as the server did
    let read = Command::new(BIN).args(["audit-read", "checkpoint", "--epoch", "1", "--wal", &fx.p("run.wal")]).output().unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&read.stdout).unwrap(), first);
}

/// Codex review of b27625da, findings 2 and 3. A source the owner puts again with other bytes is read again: the task of its
/// reading was keyed by the name and the section alone, so the new bytes got no task, live or after a restart. And a name past
/// the bound of a document's name is not put: the task that read it could not be closed.
#[test]
fn a_source_put_again_with_other_bytes_is_read_again_and_a_name_past_the_bound_is_not_put() {
    let fx = Fixture::new("replaced");
    let subjects = json!({"subjects": [{"token": W1, "role": "swarm", "id": "w1"}, {"token": OWN, "role": "owner", "id": "own"}]});
    std::fs::write(fx.0.join("readers.json"), subjects.to_string()).unwrap();
    let resume: Vec<String> = ["--wal", &fx.p("run.wal"), "--subjects", &fx.p("readers.json"), "--questions", &fx.p("questions.json")]
        .iter()
        .map(|s| s.to_string())
        .chain(["--build-scope", "none", "--reading-only"].map(String::from))
        .collect();
    let fresh: Vec<String> = resume.iter().cloned().chain(["--run-id", "replaced-run", "--empty-start"].map(String::from)).collect();
    // one reading: the task of a document's section, answered with a quote and a claim of the key
    let reading = |w1: &mut Client, doc: &str, text: &str, key: &str, value: &str| {
        let t = w1.call("audit_acquire", json!({}));
        assert_eq!((t["status"].as_str(), t["key"].as_str()), (Some("DIRECTIVE"), Some(format!("doc:{doc}#0").as_str())), "{t}");
        assert!(section(t["prompt"].as_str().unwrap()).contains(text), "the task shows the bytes the document has now: {t}");
        let p = t["local_id_prefix"].as_str().unwrap();
        let lines = json!([
            {"kind": "observe", "local_id": format!("{p}o"), "doc_id": doc, "exact_quote": text, "terms": ["value"]},
            {"kind": "claim", "local_id": format!("{p}c"), "text": format!("{key} is {value}."), "subject": key, "object": value, "stance": "reported",
             "based_on": [format!("{p}o")]},
        ]);
        let stored = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}));
        assert_eq!(stored["status"], "COMMITTED", "{stored}");
    };
    let idle = |w1: &mut Client| assert_ne!(w1.call("audit_acquire", json!({}))["status"], "DIRECTIVE", "no reading is open");

    let server = Server::start(&fresh);
    let (mut own, mut w1) = (Client::connect(server.port, OWN), Client::connect(server.port, W1));
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "a", "text": "Alpha is one.\n"}))["status"], "PUT");
    reading(&mut w1, "a", "Alpha is one.", "alpha", "one");
    idle(&mut w1);
    // the same bytes again are no new version
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "a", "text": "Alpha is one.\n"}))["status"], "PUT");
    idle(&mut w1);

    // other bytes under the name: the value fell, and the new bytes get a reading
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "a", "text": "Alpha is two.\n"}))["status"], "PUT");
    assert_eq!(own.call("audit_key", json!({"key": "alpha"}))["state"], "NO_ACTIVE_VALUE");
    // the run is not complete with bytes nobody read, before any agent asks for a task
    let status = own.call("audit_status", json!({}));
    assert_eq!((status["reading_done"].as_bool(), status["completion"]["open_work"].as_u64()), (Some(false), Some(1)), "{status}");
    assert_eq!(status["completion"]["complete"], false, "{status}");
    let open = w1.call("audit_acquire", json!({}));
    assert_eq!((open["status"].as_str(), open["key"].as_str()), (Some("DIRECTIVE"), Some("doc:a#0")), "{open}");
    assert!(section(open["prompt"].as_str().unwrap()).contains("Alpha is two."), "{open}");
    // a restart before the answer: the journal says the reading is of other bytes, and the task is given again
    drop((own, w1, server));
    let server = Server::start(&resume);
    let (mut own, mut w1) = (Client::connect(server.port, OWN), Client::connect(server.port, W1));
    reading(&mut w1, "a", "Alpha is two.", "alpha", "two");
    idle(&mut w1);
    let value = own.call("audit_key", json!({"key": "alpha"}));
    assert_eq!((value["state"].as_str(), value["value"].as_str()), (Some("ACTIVE"), Some("two")), "{value}");
    // a restart after the answer: the reading names the version it read, and stays done
    drop((own, w1, server));
    let server = Server::start(&resume);
    let (mut own, mut w1) = (Client::connect(server.port, OWN), Client::connect(server.port, W1));
    idle(&mut w1);
    // a third version, and a new source beside it: both are read
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "a", "text": "Alpha is three.\n"}))["status"], "PUT");
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "b", "text": "Beta is five.\n"}))["status"], "PUT");
    reading(&mut w1, "a", "Alpha is three.", "alpha", "three");
    reading(&mut w1, "b", "Beta is five.", "beta", "five");
    idle(&mut w1);
    // other bytes come while the task of the earlier ones is out: its answer is stored, it is an answer on the earlier bytes, and
    // the reading is given again for the bytes the document has now
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "c", "text": "Gamma is one.\nDelta is two.\n"}))["status"], "PUT");
    let out = w1.call("audit_acquire", json!({}));
    assert_eq!((out["status"].as_str(), out["key"].as_str()), (Some("DIRECTIVE"), Some("doc:c#0")), "{out}");
    // (bytes of the same length: a quote outside the byte range the task was issued with is refused by the rule of 0.2)
    assert_eq!(own.call("audit_put_document", json!({"doc_id": "c", "text": "Gamma is one.\nDelta is six.\n"}))["status"], "PUT");
    let p = out["local_id_prefix"].as_str().unwrap();
    let kept = json!([{"kind": "observe", "local_id": format!("{p}o"), "doc_id": "c", "exact_quote": "Gamma is one.", "terms": ["value"]}]);
    let stored = w1.call("audit_submit", json!({"task_id": out["task_id"], "lines": kept}));
    assert_eq!(stored["status"], "COMMITTED", "{stored}");
    reading(&mut w1, "c", "Delta is six.", "delta", "six");
    idle(&mut w1);

    // finding 3: a name of 513 bytes is refused where it comes in; one of 512 is put, read and its task closed
    let (fits, long) = ("n".repeat(512), "n".repeat(513));
    let refused = own.call("audit_put_document", json!({"doc_id": long, "text": "Gamma is seven.\n"}));
    assert_eq!((refused["code"].as_str(), refused["error"]["field"].as_str()), (Some("REFUSED"), Some("doc_id")), "{refused}");
    assert_eq!(own.call("audit_put_document", json!({"doc_id": fits, "text": "Gamma is seven.\n"}))["status"], "PUT");
    reading(&mut w1, &fits, "Gamma is seven.", "gamma", "seven");
    idle(&mut w1);

    drop((own, w1, server));
    let out = Command::new(BIN).args(["audit-verify", "--wal", &fx.p("run.wal")]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((out.status.code(), v["status"].as_str(), v["sources"]["documents"].as_u64()), (Some(0), Some("VERIFIED"), Some(4)), "{v}");
}

/// Codex's review of dbb7de2a: an answer that differs from the committed one is a late answer the journal keeps, whether the
/// server still holds the acknowledgement of the task in memory or was started again. The exact request replays its
/// acknowledgement and adds nothing; the same late answer again adds nothing either. After a restart the committed answer
/// sent again is not known to be the committed one (the acknowledgements live in memory) and is recorded once, as late.
#[test]
fn a_late_answer_is_in_the_journal_whether_or_not_the_server_still_holds_the_acknowledgement() {
    use sbgk_core::audit::state::AuditState;
    use sbgk_core::audit::AuditStore;
    let fx = Fixture::new("late-cache");
    let late = |fx: &Fixture| -> Vec<Value> {
        let s = AuditState::open(Path::new(&fx.p("run.wal"))).unwrap();
        let mut keys = s.checkpoint_keys("task-conflict:");
        keys.sort();
        keys.iter().map(|k| s.checkpoint(k).unwrap()["context"].clone()).collect()
    };
    let server = Server::start(&fx.args(true));
    let (mut w1, mut w2) = (Client::connect(server.port, W1), Client::connect(server.port, W2));
    let t = w1.call("audit_acquire", json!({}));
    assert_eq!(t["kind"], "EXTEND", "{t}");
    let lines = answer(&t);
    let committed = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}));
    assert_eq!(committed["status"], "COMMITTED", "{committed}");
    assert_eq!(w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines})), committed, "the exact request");
    let other = vec![json!({"kind": "claim", "local_id": "zz1", "text": "Topic A is otherwise.", "subject": "topic", "stance": "reported"})];
    for _ in 0..2 {
        let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": other}));
        assert_eq!(r["code"], "SUBMISSION_MISMATCH", "{r}");
    }
    let r = w2.call("audit_submit", json!({"task_id": t["task_id"], "lines": other}));
    assert_eq!(r["code"], "TASK_NOT_OWNED", "{r}");
    drop((w1, w2, server));
    let marks = late(&fx);
    assert_eq!(marks.len(), 2, "one record for the answer of w1 sent twice, one for the answer of w2: {marks:?}");
    assert_eq!((marks[0]["agent"].as_str(), marks[0]["closed_as"].as_str(), marks[0]["closed_by"].as_str()), (Some("w1"), Some("completed"), Some("w1")));
    assert_eq!((marks[1]["agent"].as_str(), marks[0]["answer_sha256"] == marks[1]["answer_sha256"]), (Some("w2"), true), "{marks:?}");
    assert!(!marks.iter().any(|m| m.to_string().contains("otherwise")), "no word of the answer: {marks:?}");

    let server = Server::start(&fx.args(false));
    let mut w1 = Client::connect(server.port, W1);
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": other}));
    assert_eq!(r["status"], "STALE_TASK", "{r}");
    let r = w1.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}));
    assert_eq!(r["status"], "STALE_TASK", "{r}");
    drop((w1, server));
    let marks = late(&fx);
    assert_eq!(marks.len(), 3, "the same late answer adds nothing; the committed answer, unknown after a restart, adds one: {marks:?}");
    assert_ne!(marks[2]["answer_sha256"], marks[0]["answer_sha256"]);
}
