//! `sbgk serve --wal-path`: plain event lines, a document put and the targets are logged before each answer; a killed process
//! restarted on the same log (without `--ontology`) continues from the exact state it acknowledged.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/quickstart").join(name)
}

struct Serve {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Serve {
    fn start(args: &[&str]) -> Serve {
        let mut child = Command::new(BIN).arg("serve").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Serve { child, stdin, stdout }
    }

    fn ask(&mut self, line: &str) -> Value {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        self.stdout.read_line(&mut out).unwrap();
        serde_json::from_str(&out).unwrap()
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const ERRATUM: &str = "Erratum E.1: clause U.2 is withdrawn.\n";

#[test]
fn serve_resumes_from_its_log_after_a_kill() {
    let lines: Vec<String> = std::fs::read_to_string(example("stream.jsonl")).unwrap().lines().map(str::to_string).collect();
    let (onto, docs, targets) = (example("ontology.json"), example("docs"), example("targets.json"));
    let base = ["--ontology", onto.to_str().unwrap(), "--docs", docs.to_str().unwrap(), "--targets", targets.to_str().unwrap()];
    let put = json!({"op": "put_document", "doc_id": "erratum", "text": ERRATUM}).to_string();

    // reference: no log, no crash
    let mut r = Serve::start(&base);
    for l in &lines[..3] {
        assert!(r.ask(l)["ok"].is_u64());
    }
    assert_eq!(r.ask(&put)["status"], "DOCUMENT_PUT");
    for l in &lines[3..] {
        assert!(r.ask(l)["ok"].is_u64());
    }
    let reference = r.ask(r#"{"op":"state"}"#);
    r.kill();

    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = std::env::temp_dir().join(format!("sbgk_serve_wal_{}_{nanos}.jsonl", std::process::id()));
    let wal_s = wal.to_str().unwrap();
    let mut a: Vec<&str> = base.to_vec();
    a.extend(["--wal-path", wal_s]);
    let mut s = Serve::start(&a);
    for l in &lines[..3] {
        assert!(s.ask(l)["ok"].is_u64());
    }
    assert_eq!(s.ask(&put)["status"], "DOCUMENT_PUT");
    let at_crash = s.ask(r#"{"op":"state"}"#);
    s.kill();

    // restart from the log alone
    let mut s = Serve::start(&["--wal-path", wal_s]);
    let st = s.ask(r#"{"op":"state"}"#);
    assert_eq!((&st["state_root"], &st["last_seq"]), (&at_crash["state_root"], &json!(3)));
    // now that this server has answered (it owns the log), a second one on the same path is refused and leaves the log alone
    let len = std::fs::metadata(&wal).unwrap().len();
    let second = Command::new(BIN).args(["serve", "--wal-path", wal_s]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&second.stderr).contains("in use"), "{}", String::from_utf8_lossy(&second.stderr));
    assert_eq!(std::fs::metadata(&wal).unwrap().len(), len);
    for l in &lines[3..] {
        assert!(s.ask(l)["ok"].is_u64(), "{l}");
    }
    let fin = s.ask(r#"{"op":"state"}"#);
    let bad = s.ask(&json!({"op": "snapshot", "out": wal.with_extension("missing").join("x.sbgk")}).to_string());
    assert_eq!(bad["code"], "SNAPSHOT_WRITE_FAILED", "{bad}");
    assert_eq!(fin["state_root"], reference["state_root"]);
    let status = s.ask(r#"{"op":"swarm_status","now_ms":0}"#);
    assert_eq!(status["goal_states"]["CLOSED_POSITIVE"], 1, "the targets came back from the log: {status}");
    // a long poll with nothing in flight answers at once
    let acq = s.ask(r#"{"op":"acquire_directive","agent_id":"a","max_wait_ms":2000}"#);
    assert!(acq["waited_ms"].as_f64().unwrap() < 1000.0, "{acq}");
    s.kill();
    let _ = std::fs::remove_file(&wal);
}
