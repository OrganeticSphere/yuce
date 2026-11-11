//! Codex review of 950f3b7, R02: after the last REFINE budget the kernel gave TERMINAL while gb's card was still open, then accepted
//! that card and changed the root; after a kernel restart the card was forgotten and the run ended without it (Codex's check of
//! aeb38ba). Loopback audit-serve with a synthetic corpus: no models, no external network.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const READERS: [(&str, &str); 3] = [("w1", "refine-swarm-token-0001"), ("w2", "refine-swarm-token-0002"), ("w3", "refine-swarm-token-0003")];
const GB: &str = "refine-builder-token-01";
const OWN: &str = "refine-owner-token-0001";
const BUDGET_MS: u64 = 1000;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Fixture {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("sbgk_refine_terminal_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("repo/reports")).unwrap();
        let mut entries = vec![];
        let mut select = String::new();
        for i in 0..3 {
            let (path, text) = (format!("reports/{i}.md"), format!("# Alpha {i}\nAlpha has reported state number {i}.\n"));
            std::fs::write(dir.join("repo").join(&path), &text).unwrap();
            entries.push(json!({"path": path, "extension": ".md", "corpus_role": "markdown_document_candidate", "size_bytes": text.len(),
                "raw_sha256": sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(text.as_bytes())), "references": {"commit_candidates": [], "pull_request_candidates": []}}));
            select.push_str(&format!("{path}\n"));
        }
        let manifest = json!({"format": "r2r.tobi_corpus_metadata_manifest.v1",
            "source": {"origin_recorded": "https://example.invalid/refine-review.git", "commit": "1".repeat(40), "repository": "local"}, "entries": entries});
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        std::fs::write(dir.join("select.txt"), select).unwrap();
        let mut subjects: Vec<Value> = READERS.iter().map(|(id, token)| json!({"token": token, "role": "swarm", "id": id})).collect();
        subjects.push(json!({"token": GB, "role": "builder", "id": "gb"}));
        subjects.push(json!({"token": OWN, "role": "owner", "id": "own"}));
        std::fs::write(dir.join("subjects.json"), json!({"subjects": subjects}).to_string()).unwrap();
        std::fs::write(dir.join("questions.json"), json!([{"id":"RQX","text":"What is established about omega?","about":["omega"]}]).to_string()).unwrap();
        Fixture(dir)
    }

    fn p(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
        let r = BufReader::new(w.try_clone().unwrap());
        let mut c = Client { w, r, next_id: 0 };
        let init = c.rpc("initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"auth_token":token}));
        assert_eq!(init["result"]["serverInfo"]["name"], "sbgk-audit", "{init}");
        c
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        writeln!(self.w, "{}", json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params})).unwrap();
        let mut line = String::new();
        assert!(self.r.read_line(&mut line).unwrap() > 0, "server closed before an RPC answer");
        serde_json::from_str(&line).unwrap()
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.rpc("tools/call", json!({"name":name,"arguments":arguments}));
        assert!(response.get("error").is_none(), "{response}");
        response["result"]["structuredContent"].clone()
    }
}

/// Every BUILD card the readers are offered comes back empty.
fn build_empty(readers: &mut [Client]) {
    for c in readers.iter_mut() {
        let t = c.call("audit_acquire", json!({}));
        if t["kind"] == "BUILD" {
            assert_eq!(c.call("audit_submit", json!({"task_id": t["task_id"], "lines": []}))["status"], "CARD_DONE");
        }
    }
}

/// The server on the fixture's journal: a new run, or the same run resumed.
fn start(f: &Fixture, fresh: bool) -> (Server, u16) {
    let mut cmd = Command::new(BIN);
    cmd.args(["audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0", "--section-bytes", "6000", "--dynamic-roles", "--build-backlog", "16"])
        .args(["--circles", "--agent-timeout-ms", "60000", "--wave-sections", "3", "--circles-refiner", "gb", "--refine-budget-ms", &BUDGET_MS.to_string()])
        .args(["--builder-max-records", "16"])
        .args(["--wal", &f.p("run.wal"), "--subjects", &f.p("subjects.json"), "--questions", &f.p("questions.json")]);
    if fresh {
        cmd.args(["--manifest", &f.p("manifest.json"), "--repo", &f.p("repo"), "--select", &f.p("select.txt"), "--run-id", "refine-terminal-review"]);
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
    if first.is_empty() {
        let mut err = String::new();
        let _ = std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err);
        panic!("startup failed: {err}");
    }
    let server = Server(child);
    let hello: Value = serde_json::from_str(&first).unwrap_or_else(|e| panic!("startup line {first:?}: {e}"));
    (server, hello["port"].as_u64().unwrap() as u16)
}

struct Clients {
    own: Client,
    gb: Client,
    readers: Vec<Client>,
}

impl Clients {
    fn connect(port: u16) -> Clients {
        Clients {
            own: Client::connect(port, OWN),
            gb: Client::connect(port, GB),
            readers: READERS.iter().map(|(_, token)| Client::connect(port, token)).collect(),
        }
    }
}

/// One circle read and built, gb given a card in REFINE, and the budget run out: the last circle is FINAL with gb's card out.
fn final_with_gb_card(c: &mut Clients) -> Value {
    for r in c.readers.iter_mut() {
        let t = r.call("audit_acquire", json!({}));
        assert_eq!(t["kind"], "EXTEND", "{t}");
        let p = t["local_id_prefix"].as_str().unwrap().to_string();
        let prompt = t["prompt"].as_str().unwrap();
        let section = &prompt[prompt.find("<<<\n").unwrap() + 4..];
        let quote = section.lines().nth(1).unwrap().to_string();
        let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
        let lines = json!([{"kind":"observe","local_id":format!("{p}o"),"doc_id":doc,"exact_quote":quote,"terms":["alpha"]},
                           {"kind":"claim","local_id":format!("{p}c"),"text":quote,"subject":"alpha","stance":"reported","based_on":[format!("{p}o")]}]);
        assert_eq!(r.call("audit_submit", json!({"task_id": t["task_id"], "lines": lines}))["status"], "COMMITTED");
    }
    for _ in 0..12 {
        if c.own.call("audit_status", json!({}))["circles"]["circle_phase"] == "REFINE" {
            break;
        }
        build_empty(&mut c.readers);
    }
    assert_eq!(c.own.call("audit_status", json!({}))["circles"]["circle_phase"], "REFINE");
    let card = c.gb.call("audit_next_card", json!({}));
    assert_eq!(card["status"], "CARD", "{card}");
    std::thread::sleep(Duration::from_millis(BUDGET_MS + 300));
    assert_eq!(c.own.call("audit_status", json!({}))["circles"]["circle_phase"], "FINAL", "the budget moved the last circle on");
    card
}

/// While gb's card is out the answer waits for it and nothing is complete or terminal; in FINAL gb is offered that card again.
fn waits_then_reoffers(c: &mut Clients, card: &Value) {
    for _ in 0..3 {
        build_empty(&mut c.readers);
    }
    let st = c.own.call("audit_status", json!({}));
    assert_eq!(st["completion"]["complete"], false, "gb's card is still out: {st}");
    assert_eq!(st["refiner"]["issued"], json!([card["cursor_from"], card["cursor_to"]]), "{st}");
    assert_ne!(c.own.call("audit_terminal_receipt", json!({}))["status"], "TERMINAL");
    let again = c.gb.call("audit_next_card", json!({}));
    assert_eq!((again["status"].as_str(), again["card_id"].as_str()), (Some("CARD"), card["card_id"].as_str()), "{again}");
}

/// gb's answer to the card is accepted; then the answer, TERMINAL, and no change of the root after it.
fn finishes(c: &mut Clients, card: &Value) {
    let observe = card["records"].as_array().unwrap().iter().find(|r| r["kind"] == "observe").unwrap()["id"].clone();
    let ops = json!([{"op":"propose_concept","type":"Component","name":"alpha","aliases":[],"basis":[observe]}]);
    assert_eq!(c.gb.call("audit_submit_ops", json!({"card_id": card["card_id"], "ops": ops}))["status"], "CARD_DONE");
    let t = c.readers[0].call("audit_acquire", json!({}));
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    let p = t["local_id_prefix"].as_str().unwrap();
    let done = json!([{"kind":"done","local_id":format!("{p}d"),"rq_id":"RQX","directive_id":t["task_id"],"outcome":"unknown","answer_ids":[],
                       "text":"The selected records do not establish omega."}]);
    assert_eq!(c.readers[0].call("audit_submit", json!({"task_id": t["task_id"], "lines": done}))["status"], "COMMITTED");
    for _ in 0..10 {
        build_empty(&mut c.readers);
    }
    let terminal = c.own.call("audit_terminal_receipt", json!({}));
    assert_eq!(terminal["status"], "TERMINAL", "{terminal}");
    let root = c.own.call("audit_status", json!({}))["audit_root"].clone();
    assert_eq!(c.gb.call("audit_next_card", json!({}))["status"], "WAIT");
    assert_eq!(c.own.call("audit_status", json!({}))["audit_root"], root, "nothing changes the root after TERMINAL");
}

#[test]
fn the_run_is_not_terminal_while_gb_still_holds_a_card_after_the_last_refine_budget() {
    let f = Fixture::new();
    let (_server, port) = start(&f, true);
    let mut c = Clients::connect(port);
    let card = final_with_gb_card(&mut c);
    waits_then_reoffers(&mut c, &card);
    finishes(&mut c, &card);
}

#[test]
fn the_card_gb_was_given_outlives_a_kernel_restart_and_keeps_its_id() {
    let f = Fixture::new();
    let (server, port) = start(&f, true);
    let mut c = Clients::connect(port);
    let card = final_with_gb_card(&mut c);
    // once, in a full parallel run, the restarted server did not start: it is stopped before its clients now, and a failed
    // start shows the server's error
    drop(server);
    drop(c);
    let (_server, port) = start(&f, false);
    let mut c = Clients::connect(port);
    assert_eq!(c.own.call("audit_status", json!({}))["refiner"]["open_card"], Value::Null, "the open card itself is memory only");
    waits_then_reoffers(&mut c, &card);
    finishes(&mut c, &card);
}

#[test]
fn after_a_restart_gb_can_answer_its_card_without_asking_for_it_again() {
    // Gemini's reading of b4edffe: the answer to a card given before the restart came back UNKNOWN_CARD
    let f = Fixture::new();
    let (server, port) = start(&f, true);
    let mut c = Clients::connect(port);
    let card = final_with_gb_card(&mut c);
    // once, in a full parallel run, the restarted server did not start: it is stopped before its clients now, and a failed
    // start shows the server's error
    drop(server);
    drop(c);
    let (_server, port) = start(&f, false);
    let mut c = Clients::connect(port);
    finishes(&mut c, &card);
}
