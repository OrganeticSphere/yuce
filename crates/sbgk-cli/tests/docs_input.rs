//! `sbgk audit-serve --docs`: a run on the text files of a folder, on the wire and checked from outside.

use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const WORKER: &str = "swarm-token-w1-0001";
const OWNER: &str = "owner-token-0000001";
const SECRET: &str = "KEY=never-in-a-journal\n";
const CONTRACT: &str = "Clause one. The supplier delivers within ten days.\r\n\r\n# not a heading in a text file\r\nClause two. Payment follows.\r\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new(tag: &str, files: &[(&str, &[u8])]) -> Fixture {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("sbgk_docs_serve_{tag}_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        for (name, bytes) in files {
            let path = dir.join("docs").join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let subjects = json!({"subjects": [{"token": WORKER, "role": "swarm", "id": "w1"}, {"token": OWNER, "role": "owner", "id": "own"}]});
        std::fs::write(dir.join("subjects.json"), subjects.to_string()).unwrap();
        let questions = json!([{"id": "RQ1", "text": "What does the supplier owe?", "about": ["supplier"]}]);
        std::fs::write(dir.join("questions.json"), questions.to_string()).unwrap();
        Fixture(dir)
    }

    fn p(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }

    fn args(&self) -> Vec<String> {
        ["--wal", &self.p("run.wal"), "--subjects", &self.p("subjects.json"), "--questions", &self.p("questions.json")].iter().map(|s| s.to_string()).collect()
    }

    fn fresh(&self) -> Vec<String> {
        let mut a = self.args();
        a.extend(["--docs".to_string(), self.p("docs"), "--run-id".to_string(), "docs-run".to_string()]);
        a
    }

    fn refused(&self, args: &[String]) -> Output {
        Command::new(BIN).args(["audit-serve", "--profile", "custom", "--build-scope", "none", "--listen", "127.0.0.1:0"]).args(args).output().unwrap()
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
    note: String,
    /// What the server warned of before it said what it took.
    warnings: Vec<String>,
}

impl Server {
    /// Started as a new run, `note` holds the line that says what was taken; on a resume there is none.
    fn start(args: &[String], fresh: bool) -> Server {
        Server::start_as(&["--profile", "custom", "--build-scope", "none"], args, fresh)
    }

    fn start_as(profile: &[&str], args: &[String], fresh: bool) -> Server {
        let mut child = Command::new(BIN)
            .arg("audit-serve")
            .args(profile)
            .args(["--listen", "127.0.0.1:0"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start audit-serve");
        // stderr is read to its end: a closed pipe would stop the server at its next line
        let mut err = BufReader::new(child.stderr.take().unwrap());
        let (mut note, mut warnings) = (String::new(), Vec::new());
        if fresh {
            loop {
                let mut line = String::new();
                if err.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.contains("\"status\":\"docs\"") {
                    note = line;
                    break;
                }
                warnings.push(line);
            }
        }
        std::thread::spawn(move || {
            let mut sink = String::new();
            while err.read_line(&mut sink).is_ok_and(|n| n > 0) {
                sink.clear();
            }
        });
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
        let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("first line {first:?}: {e}; note {note}"));
        assert_eq!(hello["status"], "listening");
        Server { port: hello["port"].as_u64().unwrap() as u16, child, note, warnings }
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
    fn connect(port: u16, token: &str) -> Client {
        let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        let mut c = Client { w, r, id: 0 };
        let init = c.rpc("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "auth_token": token}));
        assert_eq!(init["result"]["serverInfo"]["name"], "sbgk-audit", "{init}");
        c
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        writeln!(self.w, "{}", json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})).unwrap();
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn call(&mut self, tool: &str, args: Value) -> Value {
        let r = self.rpc("tools/call", json!({"name": tool, "arguments": args}));
        if r.get("error").is_some() {
            return r["error"].clone();
        }
        r["result"]["structuredContent"].clone()
    }
}

fn verify(wal: &str) -> Value {
    let out = Command::new(BIN).args(["audit-verify", "--wal", wal]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn doc_of(task: &Value) -> String {
    let key = task["key"].as_str().unwrap();
    key[4..key.rfind('#').unwrap()].to_string()
}

#[test]
fn a_folder_is_a_run_that_an_outsider_can_check() {
    let name = "\u{414}\u{43e}\u{433}\u{43e}\u{432}\u{43e}\u{440} 1.txt";
    let path = format!("contracts/{name}");
    let fx = Fixture::new("run", &[(path.as_str(), CONTRACT.as_bytes()), (".env", SECRET.as_bytes())]);
    // the operator keeps the tokens beside the documents: they are no source of the run they guard
    let subjects = fx.0.join("docs/subjects.json");
    std::fs::copy(fx.0.join("subjects.json"), &subjects).unwrap();
    let mut args = fx.fresh();
    let at = args.iter().position(|a| a == "--subjects").unwrap();
    args[at + 1] = subjects.display().to_string();

    let server = Server::start(&args, true);
    let note: Value = serde_json::from_str(&server.note).unwrap_or_else(|e| panic!("{}: {e}", server.note));
    assert_eq!(note["status"], "docs");
    assert_eq!(note["taken"], json!([path]), "{note}");
    let left: Vec<&str> = note["skipped"].as_array().unwrap().iter().map(|s| s["path"].as_str().unwrap()).collect();
    assert_eq!(left, [".env", "subjects.json"], "{note}");

    let mut worker = Client::connect(server.port, WORKER);
    let task = worker.call("audit_acquire", json!({}));
    assert_eq!(task["kind"], "EXTEND", "{task}");
    assert_eq!(doc_of(&task), path);
    let prompt = task["prompt"].as_str().unwrap();
    assert!(prompt.contains("a source document corpus") && !prompt.contains("engineering reports"), "{prompt}");
    assert!(prompt.contains("# not a heading"), "the whole contract is one section: {prompt}");
    let (p, quote) = (task["local_id_prefix"].as_str().unwrap(), "The supplier delivers within ten days.");
    let lines = json!([{"kind": "observe", "local_id": format!("{p}o1"), "doc_id": path, "exact_quote": quote, "terms": ["supplier"]}]);
    let done = worker.call("audit_submit", json!({"task_id": task["task_id"], "lines": lines}));
    assert_eq!(done["status"], "COMMITTED", "{done}");
    let mut owner = Client::connect(server.port, OWNER);
    assert_eq!(owner.rpc("shutdown", json!({}))["result"], json!({}));
    drop(server);

    let report = verify(&fx.p("run.wal"));
    assert_eq!(report["status"], "VERIFIED", "{report}");
    assert_eq!(report["sources"], json!({"mode": "opaque", "documents": 1, "set_matches_manifest_hash": true, "put_document_entries": 0}), "{report}");
    let journal = std::fs::read_to_string(fx.p("run.wal")).unwrap();
    assert!(!journal.contains(&to_hex_bytes(SECRET.as_bytes())) && !journal.contains("never-in-a-journal"));
    assert!(!journal.contains(&to_hex_bytes(WORKER.as_bytes())) && !journal.contains(WORKER), "no token in the journal");
    assert!(!journal.contains(fx.0.to_str().unwrap()) && !journal.contains(&fx.0.display().to_string().replace('\\', "\\\\")), "no path of this machine");

    // the run resumes from its journal alone, without the folder
    std::fs::remove_dir_all(fx.0.join("docs")).unwrap();
    let mut resume = fx.args();
    resume[3] = fx.p("subjects.json");
    let server = Server::start(&resume, false);
    let mut owner = Client::connect(server.port, OWNER);
    assert_eq!(owner.call("audit_status", json!({}))["status"], "STATUS");
    drop(server);
    let again = fx.refused(&fx.fresh());
    assert_eq!(again.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&again.stderr).contains("resume it without --docs"), "{again:?}");
}

fn to_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One run's roots from an empty journal: verified at once, with no work done.
fn start_and_stop(fx: &Fixture) -> Value {
    let server = Server::start(&fx.fresh(), true);
    let mut owner = Client::connect(server.port, OWNER);
    assert_eq!(owner.rpc("shutdown", json!({}))["result"], json!({}));
    drop(server);
    verify(&fx.p("run.wal"))
}

#[test]
fn the_same_files_give_the_same_roots_wherever_they_lie() {
    let (a, b): (&[u8], &[u8]) = (b"one\n", b"two\r\n");
    let first = start_and_stop(&Fixture::new("same_a", &[("sub/a.txt", a), ("b.md", b)]));
    let second = start_and_stop(&Fixture::new("same_b", &[("b.md", b), ("sub/a.txt", a), (".ignored", b"x\n")]));
    for key in ["corpus_manifest_hash", "audit_root", "engine_root"] {
        assert_eq!(first[key], second[key], "{key}");
    }
    let third = start_and_stop(&Fixture::new("same_c", &[("sub/a.txt", a), ("b.md", b"two\n")]));
    assert_ne!(first["corpus_manifest_hash"], third["corpus_manifest_hash"], "a line ending is a byte of the document");
    // a value fixed here keeps it the same on every system this test runs on
    let hashes = [to_hex(&sha256(b)), to_hex(&sha256(a))];
    let set = sbgk_core::audit::sources::docs_set_hash([("b.md", hashes[0].as_str()), ("sub/a.txt", hashes[1].as_str())]);
    assert_eq!(first["corpus_manifest_hash"], json!(to_hex(&set)));
    assert_eq!(to_hex(&set), "1b4fcffd5aabee8ebe737ed642c3dea42b0e5a9df8a25f945c159c79a9e11fe5");
}

#[test]
fn a_folder_with_a_file_that_is_no_text_starts_nothing() {
    let fx = Fixture::new("binary", &[("a.txt", b"one\n"), ("contract.docx", b"PK\x03\x04\x00\x00")]);
    let out = fx.refused(&fx.fresh());
    assert_eq!(out.status.code(), Some(2));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("contract.docx") && said.contains("--select"), "{said}");
    assert!(!Path::new(&fx.p("run.wal")).exists(), "no journal is left behind");

    std::fs::write(fx.p("take.txt"), "a.txt\n").unwrap();
    let mut args = fx.fresh();
    args.extend(["--select".to_string(), fx.p("take.txt")]);
    let server = Server::start(&args, true);
    assert!(server.note.contains("a.txt") && !server.note.contains("contract.docx"), "{}", server.note);
}

/// R017-01: a list cannot put the server's own tokens into the journal.
#[test]
fn a_list_that_names_the_tokens_starts_nothing() {
    let fx = Fixture::new("tokens", &[("a.txt", b"one\n")]);
    let subjects = fx.0.join("docs/subjects.json");
    std::fs::copy(fx.0.join("subjects.json"), &subjects).unwrap();
    std::fs::write(fx.p("take.txt"), "a.txt\nsubjects.json\n").unwrap();
    let mut args = fx.fresh();
    let at = args.iter().position(|a| a == "--subjects").unwrap();
    args[at + 1] = subjects.display().to_string();
    args.extend(["--select".to_string(), fx.p("take.txt")]);
    let out = fx.refused(&args);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("own command"), "{out:?}");
    assert!(!Path::new(&fx.p("run.wal")).exists(), "no journal is left behind");
}

/// One reading agent and the owner, with the measured profile made for one agent: the run reads, answers and closes.
#[test]
fn one_agent_finishes_a_run_with_the_solo_profile() {
    let fx = Fixture::new("solo", &[("contract.txt", CONTRACT.as_bytes()), ("policy.md", b"# Policy\n\nThe supplier reports each quarter.\n")]);
    let server = Server::start_as(&["--profile", "solo"], &fx.fresh(), true);
    let (mut worker, mut owner) = (Client::connect(server.port, WORKER), Client::connect(server.port, OWNER));
    let mut kinds = std::collections::BTreeMap::new();
    for _ in 0..60 {
        let t = worker.call("audit_acquire", json!({"max_wait_ms": 200}));
        match t["status"].as_str().unwrap() {
            "COMPLETE" => break,
            "WAIT" => continue,
            _ => {}
        }
        let (p, kind) = (t["local_id_prefix"].as_str().unwrap().to_string(), t["kind"].as_str().unwrap().to_string());
        *kinds.entry(kind.clone()).or_insert(0) += 1;
        let prompt = t["prompt"].as_str().unwrap();
        let lines = match kind.as_str() {
            "EXTEND" => {
                let a = prompt.find("<<<\n").unwrap() + 4;
                let section = &prompt[a..a + prompt[a..].find("\n>>>").unwrap()];
                let quote = section.lines().map(str::trim).find(|l| l.contains("supplier")).map(str::to_string);
                match quote {
                    Some(q) => json!([{"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc_of(&t), "exact_quote": q, "terms": ["supplier"]},
                                      {"kind": "claim", "local_id": format!("{p}c1"), "text": q, "subject": "supplier", "stance": "reported", "based_on": [format!("{p}o1")]}]),
                    None => json!([]),
                }
            }
            "SUMMARIZE" => {
                let shown: Vec<String> = prompt
                    .lines()
                    .filter_map(|l| l.trim_start().split_once(' '))
                    .filter(|(id, rest)| id.starts_with('@') && rest.starts_with("observe"))
                    .map(|(id, _)| id.to_string())
                    .collect();
                json!([{"kind": "claim", "local_id": format!("{p}c1"), "text": "The supplier delivers and reports.", "subject": "supplier", "stance": "reported", "based_on": shown},
                       {"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": t["task_id"], "outcome": "answered", "answer_ids": [format!("{p}c1")]}])
            }
            other => panic!("no work of kind {other} for one agent: {t}"),
        };
        let r = worker.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}));
        assert_eq!(r["status"], "COMMITTED", "{kind}: {r}");
    }
    assert!(kinds.contains_key("EXTEND") && kinds.contains_key("SUMMARIZE"), "{kinds:?}");
    let receipt = owner.call("audit_terminal_receipt", json!({}));
    assert_eq!(receipt["status"], "TERMINAL", "{receipt}");
    assert_eq!(receipt["outcomes"]["RQ1"]["outcome"], "answered", "{receipt}");
}

/// The measured profile needs a team, and the server says what to do with one agent.
#[test]
fn the_team_profile_points_one_agent_to_solo() {
    let fx = Fixture::new("team", &[("a.txt", b"one supplier\n")]);
    let out = Command::new(BIN).args(["audit-serve", "--listen", "127.0.0.1:0"]).args(fx.fresh()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--profile solo"), "{out:?}");
}

/// A graph builder nobody runs left every agent waiting without a word: the wait now says what it waits for and how not to.
#[test]
fn a_wait_for_a_builder_nobody_runs_says_so() {
    let fx = Fixture::new("builder", &[("a.txt", b"one supplier\n")]);
    let server = Server::start_as(&["--profile", "custom"], &fx.fresh(), true);
    assert!(server.warnings.iter().any(|w| w.contains("no graph builder")), "{:?}", server.warnings);
    let mut worker = Client::connect(server.port, WORKER);
    let mut said = Value::Null;
    for _ in 0..10 {
        let t = worker.call("audit_acquire", json!({"max_wait_ms": 100}));
        if t["status"] == "WAIT" {
            said = t;
            break;
        }
        assert_eq!(t["kind"], "EXTEND", "records wait for the builder before any summary: {t}");
        let p = t["local_id_prefix"].as_str().unwrap();
        let lines = json!([{"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc_of(&t), "exact_quote": "one supplier", "terms": ["supplier"]},
                           {"kind": "claim", "local_id": format!("{p}c1"), "text": "There is one supplier.", "subject": "supplier", "stance": "reported", "based_on": [format!("{p}o1")]}]);
        assert_eq!(worker.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}))["status"], "COMMITTED", "{t}");
    }
    assert!(said["message"].as_str().is_some_and(|m| m.contains("--build-scope none")), "{said}");
}

/// A receipt names its run and its corpus as well as its roots, and each of them has to hold.
#[test]
fn a_receipt_of_another_corpus_or_run_is_a_mismatch() {
    let fx = Fixture::new("receipt", &[("a.txt", b"one supplier\n")]);
    let report = start_and_stop(&fx);
    let mut receipt = json!({"audit_root": report["audit_root"], "engine_root": report["engine_root"], "wal_head": report["wal_head"],
                             "corpus_manifest_hash": report["corpus_manifest_hash"], "run_id": "docs-run"});
    let check = |receipt: &Value| {
        std::fs::write(fx.p("receipt.json"), receipt.to_string()).unwrap();
        let out = Command::new(BIN).args(["audit-verify", "--wal", &fx.p("run.wal"), "--expect", &fx.p("receipt.json")]).output().unwrap();
        (out.status.code(), serde_json::from_slice::<Value>(&out.stdout).unwrap())
    };
    let (code, ok) = check(&receipt);
    assert_eq!((code, ok["status"].as_str()), (Some(0), Some("VERIFIED")), "{ok}");
    receipt["corpus_manifest_hash"] = json!("0".repeat(64));
    let (code, other) = check(&receipt);
    assert_eq!((code, other["status"].as_str()), (Some(1), Some("MISMATCH")), "{other}");
    assert_eq!(other["expected"]["corpus_manifest_hash_matches"], false);
    receipt["corpus_manifest_hash"] = report["corpus_manifest_hash"].clone();
    receipt["run_id"] = json!("another-run");
    let (code, other) = check(&receipt);
    assert_eq!((code, other["expected"]["run_id_matches"].as_bool()), (Some(1), Some(false)), "{other}");
}

#[test]
fn two_ways_to_start_a_run_are_refused_together() {
    let fx = Fixture::new("both", &[("a.txt", b"one\n")]);
    let mut args = fx.fresh();
    args.extend(["--manifest".to_string(), fx.p("none.json")]);
    let out = fx.refused(&args);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("give one of them"), "{out:?}");
}
