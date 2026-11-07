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
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
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
        Command::new(BIN).args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"]).args(args).output().unwrap()
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
}

impl Server {
    /// Started as a new run, `note` holds the line that says what was taken; on a resume there is none.
    fn start(args: &[String], fresh: bool) -> Server {
        let mut child = Command::new(BIN)
            .args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start audit-serve");
        let mut note = String::new();
        if fresh {
            BufReader::new(child.stderr.take().unwrap()).read_line(&mut note).unwrap();
        }
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
        let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("first line {first:?}: {e}; note {note}"));
        assert_eq!(hello["status"], "listening");
        Server { port: hello["port"].as_u64().unwrap() as u16, child, note }
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

#[test]
fn two_ways_to_start_a_run_are_refused_together() {
    let fx = Fixture::new("both", &[("a.txt", b"one\n")]);
    let mut args = fx.fresh();
    args.extend(["--manifest".to_string(), fx.p("none.json")]);
    let out = fx.refused(&args);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("give one of them"), "{out:?}");
}
