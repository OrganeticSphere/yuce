//! `sbgk audit-stream`: a journal that starts without a document and takes its sources as they come, written a step at a time by
//! the command line; `audit-read key`, `keys` and `checkpoint` read it back and `audit-verify` checks it. The journal this test
//! writes is the input `valid/stream-context-checkpoints.wal` of the independent verifier (amendment 5, P5-4): the test fails if
//! the kernel no longer writes those bytes, and `YUCE_BLESS_STREAM_INPUT=1` writes the input again.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

struct Folder(PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("sbgk_stream_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Folder(root)
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One command: its exit code and the JSON document it printed.
fn sbgk(args: &[&str]) -> (i32, Value) {
    let out = Command::new(BIN).args(args).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let value = serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{args:?}: {e}: {text} {}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code().unwrap_or(-1), value)
}

fn step(wal: &str, step: &str, args: &[&str]) -> Value {
    let all: Vec<&str> = ["audit-stream", step, "--wal", wal, "--actor", "agent"].into_iter().chain(args.iter().copied()).collect();
    let (code, out) = sbgk(&all);
    assert_eq!(code, 0, "{step} {args:?}: {out}");
    out
}

fn read(wal: &str, tool: &str, args: &[&str]) -> Value {
    let all: Vec<&str> = ["audit-read", tool, "--wal", wal].into_iter().chain(args.iter().copied()).collect();
    let (code, out) = sbgk(&all);
    assert_eq!(code, 0, "{tool} {args:?}: {out}");
    out
}

fn fact(local_id: &str, key: &str, value: &str, based_on: &[&str]) -> Value {
    json!({"kind":"claim","local_id":local_id,"text":format!("{key} is {value}."),"subject":key,"object":value,"stance":"reported","based_on":based_on})
}

fn quote(local_id: &str, doc: &str, text: &str) -> Value {
    json!({"kind":"observe","local_id":local_id,"doc_id":doc,"exact_quote":text,"terms":[]})
}

/// The journal of amendment 5, P5-4, written into `wal`; returns the ids of the claims of the first epoch.
fn write_stream(dir: &Folder, wal: &str) -> Vec<String> {
    let started = step(wal, "start", &["--run-id", "stream-context-checkpoints"]);
    assert_eq!(
        (started["status"].as_str(), started["rules_version"].as_str(), started["entries"].as_u64()),
        (Some("STARTED"), Some("r2r-audit-rules/4"), Some(1))
    );

    // epoch 1
    let put = step(wal, "put", &["--doc-id", "context-1", "--file", &dir.file("c1.txt", "A = 10.\nB = 5.\nC = 7.\n")]);
    assert_eq!((put["status"].as_str(), put["documents"].as_u64(), put["new_version_of_a_known_document"].as_bool()), (Some("PUT"), Some(1), Some(false)));
    let lines = json!([
        quote("oa", "context-1", "A = 10."),
        quote("ob", "context-1", "B = 5."),
        quote("oc", "context-1", "C = 7."),
        fact("a", "A", "10", &["oa"]),
        fact("b", "B", "5", &["ob"]),
        fact("c", "C", "7", &["oc"]),
        fact("ab", "A*B", "50", &["a", "b"]),
        {"kind":"question","local_id":"q","text":"Is A final for the year?","about":["A"],"needed":"the plan of the second quarter","about_record":"a"},
    ]);
    let e1 = step(wal, "submit", &["--task", "epoch-1", "--lines", &dir.file("e1.json", &lines.to_string())]);
    assert_eq!(e1["status"], "COMMITTED");
    let ids: Vec<String> = e1["accepted"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    let first = step(wal, "checkpoint", &["--raw-context", "context-1"]);
    assert_eq!((first["epoch"].as_u64(), first["listed"].as_u64(), first["cursor"].as_u64()), (Some(1), Some(4), Some(8)));

    // epoch 2: A changes by plan, B without one
    step(wal, "put", &["--doc-id", "context-2", "--file", &dir.file("c2.txt", "A = 12, as planned for the second quarter.\nB = 6.\n")]);
    let old_a = format!("@{}", ids[3]);
    let old_quote = format!("@{}", ids[0]);
    let lines = json!([
        quote("oa", "context-2", "A = 12, as planned for the second quarter."),
        quote("ob", "context-2", "B = 6."),
        fact("a", "A", "12", &["oa"]),
        fact("b", "B", "6", &["ob"]),
        {"kind":"relation","local_id":"s","from":"a","rel":"supersedes","to":old_a,"based_on":["oa", old_quote]},
    ]);
    assert_eq!(step(wal, "submit", &["--task", "epoch-2", "--lines", &dir.file("e2.json", &lines.to_string())])["status"], "COMMITTED");
    assert_eq!(step(wal, "checkpoint", &["--raw-context", "context-2"])["epoch"], 2);

    // epoch 3: the first statement of B is withdrawn for a reason that is itself a source
    step(wal, "put", &["--doc-id", "context-3", "--file", &dir.file("c3.txt", "Correction: the earlier statement of B was a typing error.\n")]);
    let withdrawn = step(wal, "withdraw", &["--doc-id", "context-1", "--exact-quote", "B = 5.", "--reason-source-id", "context-3"]);
    assert_eq!((withdrawn["status"].as_str(), withdrawn["also_revoked"].as_u64()), (Some("WITHDRAWN"), Some(1)));
    assert_eq!(step(wal, "checkpoint", &["--raw-context", "context-3"])["epoch"], 3);
    assert_eq!(step(wal, "seal", &[])["status"], "SEALED");
    assert_eq!(step(wal, "close", &[])["status"], "CLOSED");
    ids
}

#[test]
fn a_stream_is_written_a_step_at_a_time_and_read_back_by_key_and_by_checkpoint() {
    let dir = Folder::new("steps");
    let wal = dir.0.join("run.wal").to_str().unwrap().to_string();
    let ids = write_stream(&dir, &wal);

    let (code, verified) = sbgk(&["audit-verify", "--wal", &wal]);
    assert_eq!((code, verified["status"].as_str()), (0, Some("VERIFIED")), "{verified}");
    assert_eq!(verified["sources"], json!({"mode": "opaque", "documents": 3, "set_matches_manifest_hash": false, "put_document_entries": 3}));
    let status = read(&wal, "status", &[]);
    assert_eq!(
        (status["rules_version"].as_str(), status["context_checkpoints"].as_u64(), status["closed"].as_bool()),
        (Some("r2r-audit-rules/4"), Some(3), Some(true))
    );
    assert_eq!(status["claim_chains"], json!({"max_depth": 1, "standing_claims": 4, "standing_without_own_quote": 0, "without_own_quote_per_10000": 0}));

    // by the exact key: the planned change, the value that survived the withdrawal, the untouched one, the one that fell
    let a = read(&wal, "key", &["--key", "A"]);
    assert_eq!((a["state"].as_str(), a["value"].as_str(), a["history"]["superseded"].as_u64()), (Some("ACTIVE"), Some("12"), Some(1)));
    assert_eq!(read(&wal, "key", &["--key", "B"])["value"], "6");
    assert_eq!(read(&wal, "key", &["--key", "C"])["record"]["id"], ids[5].as_str());
    assert_eq!(read(&wal, "key", &["--key", "A*B"])["state"], "NO_ACTIVE_VALUE");
    assert_eq!(read(&wal, "key", &["--key", "c"])["state"], "UNKNOWN_KEY");
    let table = read(&wal, "keys", &["--required", &dir.file("required.json", "[\"C\", \"D\"]")]);
    assert_eq!((table["count"].as_u64(), table["missing_required_keys"][0]["key"].as_str()), (Some(4), Some("D")));

    // the first checkpoint as it reads now: C alone is still active of what it listed
    let first = read(&wal, "checkpoint", &["--epoch", "1"]);
    assert_eq!((first["listed"].as_u64(), first["active"].as_array().map(Vec::len), first["active"][0]["key"].as_str()), (Some(4), Some(1), Some("C")));
    assert_eq!(first["dropped"]["SUPERSEDED"][0]["key"], "A");
    assert_eq!(first["dropped"]["AFFECTED_BY_EVIDENCE_CHANGE"].as_array().map(Vec::len), Some(2));
    let last = read(&wal, "checkpoint", &[]);
    assert_eq!((last["epoch"].as_u64(), last["active"].as_array().map(Vec::len), last["raw_context"].as_str()), (Some(3), Some(3), Some("context-3")));
    let (code, none) = sbgk(&["audit-read", "checkpoint", "--wal", &wal, "--epoch", "9"]);
    assert_eq!((code, none["status"].as_str()), (0, Some("NO_CONTEXT_CHECKPOINT")));

    // a closed run takes no further step
    let (code, refused) = sbgk(&["audit-stream", "put", "--wal", &wal, "--doc-id", "late", "--file", &dir.file("late.txt", "Late.\n")]);
    assert_eq!((code, refused["status"].as_str()), (1, Some("REFUSED")), "{refused}");
}

#[test]
fn a_refused_step_writes_what_it_says_and_exits_1() {
    let dir = Folder::new("refused");
    let wal = dir.0.join("run.wal").to_str().unwrap().to_string();
    step(&wal, "start", &["--run-id", "refusals", "--rules", "r2r-audit-rules/3"]);
    step(&wal, "put", &["--doc-id", "s1", "--file", &dir.file("s1.txt", "A = 10.\n")]);
    // rules 3: a claim on a claim is refused at its line, and the lines before it are stored
    let lines = json!([quote("o", "s1", "A = 10."), fact("a", "A", "10", &["o"]), fact("a2", "2A", "20", &["a"])]);
    let (code, out) = sbgk(&["audit-stream", "submit", "--wal", &wal, "--task", "t1", "--lines", &dir.file("l.json", &lines.to_string())]);
    assert_eq!(
        (code, out["status"].as_str(), out["failed_index"].as_u64(), out["accepted"].as_array().map(Vec::len)),
        (1, Some("REPAIR_REQUIRED"), Some(2), Some(2))
    );
    assert_eq!(out["error"]["code"], "NOT_AN_EVIDENCE");
    // and a journal of rules 3 has no context checkpoint and no reason of a withdrawal
    let (code, out) = sbgk(&["audit-stream", "checkpoint", "--wal", &wal]);
    assert_eq!((code, out["status"].as_str()), (1, Some("REFUSED")), "{out}");
    let (code, out) = sbgk(&["audit-stream", "withdraw", "--wal", &wal, "--doc-id", "s1", "--exact-quote", "A = 10.", "--reason-source-id", "s1"]);
    assert_eq!((code, out["error"]["field"].as_str()), (1, Some("reason_source_id")), "{out}");
    assert_eq!(read(&wal, "status", &[])["rules_version"], "r2r-audit-rules/3");
    // a second start on the same journal is a usage error
    let again = Command::new(BIN).args(["audit-stream", "start", "--wal", &wal, "--run-id", "again"]).output().unwrap();
    assert_eq!(again.status.code(), Some(2));
}

/// The journal the steps write is the verifier's input, byte for byte: the kernel writes no clock and no random value into it.
#[test]
fn the_stream_input_of_the_independent_verifier_is_what_the_kernel_writes() {
    let dir = Folder::new("input");
    let wal = dir.0.join("run.wal").to_str().unwrap().to_string();
    write_stream(&dir, &wal);
    let written = std::fs::read(&wal).unwrap();
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verifier/inputs/valid/stream-context-checkpoints.wal");
    if std::env::var_os("YUCE_BLESS_STREAM_INPUT").is_some() {
        std::fs::write(&input, &written).unwrap();
    }
    let kept = std::fs::read(&input).unwrap_or_default();
    assert!(kept == written, "the input is not this journal: YUCE_BLESS_STREAM_INPUT=1 writes it again (and its entry of expected.json changes with it)");
}

/// Codex review of b27625da, finding 1: after its 257th source a journal took no further quote, as `submit` named every document
/// of the journal in its scope and a scope names at most 256. The scope is now the documents the lines need.
#[test]
fn a_journal_of_more_sources_than_a_scope_names_still_takes_quotes_and_claims() {
    use sbgk_core::audit::onto::AuditOntology;
    use sbgk_core::audit::state::AuditState;
    let dir = Folder::new("many");
    let wal = dir.0.join("run.wal").to_str().unwrap().to_string();
    {
        let mut state = AuditState::create_from_docs(Path::new(&wal), &AuditOntology::base(), "many-sources", Vec::new()).unwrap();
        for n in 0..256usize {
            state.put_document("agent", &format!("d{n:03}"), format!("Value {n} is {}.\n", n * 2).as_bytes()).unwrap();
        }
    }
    let first = json!([quote("o", "d000", "Value 0 is 0."), fact("v", "value/0", "0", &["o"])]);
    let stored = step(&wal, "submit", &["--task", "t0", "--lines", &dir.file("first.json", &first.to_string())]);
    assert_eq!((stored["status"].as_str(), stored["accepted"].as_array().map(Vec::len)), (Some("COMMITTED"), Some(2)), "{stored}");
    // the 257th source, put by the command line, and a submission that quotes it and rests on the claim of the first one
    let put = step(&wal, "put", &["--doc-id", "d256", "--file", &dir.file("d256.txt", "Value 256 is 512.\n")]);
    assert_eq!(put["documents"], 257);
    let claim = format!("@{}", stored["accepted"][1].as_str().unwrap());
    let second = json!([quote("o", "d256", "Value 256 is 512."), fact("v", "value/256", "512", &["o"]), fact("sum", "sum", "512", &[&claim, "v"])]);
    let stored = step(&wal, "submit", &["--task", "t1", "--lines", &dir.file("second.json", &second.to_string())]);
    assert_eq!((stored["status"].as_str(), stored["accepted"].as_array().map(Vec::len)), (Some("COMMITTED"), Some(3)), "{stored}");
    // the frame names the two documents the lines need, and no other of the 257
    let text = std::fs::read_to_string(&wal).unwrap();
    let last: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last["body"]["command"]["scope"]["docs"], json!(["d000", "d256"]));
    assert_eq!(read(&wal, "key", &["--key", "sum"])["value"], "512");
    // a context checkpoint names all 257 sources: its sources are no scope
    let written = step(&wal, "checkpoint", &[]);
    assert_eq!((written["epoch"].as_u64(), written["listed"].as_u64(), written["sources"].as_u64()), (Some(1), Some(3), Some(257)));
    let (code, verified) = sbgk(&["audit-verify", "--wal", &wal]);
    assert_eq!((code, verified["status"].as_str(), verified["sources"]["documents"].as_u64()), (0, Some("VERIFIED"), Some(257)), "{verified}");
}

/// Codex review of b27625da, findings 5 and 6, at the command line: a record that is not active is not listed in a context
/// checkpoint, and a journal of rules 3 has no context checkpoint to read.
#[test]
fn a_context_checkpoint_refuses_a_record_that_fell_and_a_journal_of_rules_3_reads_none() {
    let dir = Folder::new("active");
    let wal = dir.0.join("run.wal").to_str().unwrap().to_string();
    step(&wal, "start", &["--run-id", "active-records"]);
    step(&wal, "put", &["--doc-id", "a", "--file", &dir.file("a1.txt", "Alpha is one.\n")]);
    let lines = json!([quote("o", "a", "Alpha is one."), fact("alpha", "alpha", "one", &["o"])]);
    let stored = step(&wal, "submit", &["--task", "t1", "--lines", &dir.file("l.json", &lines.to_string())]);
    let alpha = stored["accepted"][1].as_str().unwrap().to_string();
    assert_eq!(step(&wal, "checkpoint", &[])["listed"], 1);
    // the source gets other bytes: the claim is affected, and a checkpoint that names it is refused
    let put = step(&wal, "put", &["--doc-id", "a", "--file", &dir.file("a2.txt", "Alpha is two.\n")]);
    assert_eq!(put["new_version_of_a_known_document"], true);
    let named = dir.file("records.json", &json!([alpha]).to_string());
    let (code, out) = sbgk(&["audit-stream", "checkpoint", "--wal", &wal, "--records", &named]);
    assert_eq!((code, out["status"].as_str(), out["error"]["field"].as_str()), (1, Some("REFUSED"), Some("vsc:checkpoint")), "{out}");
    assert!(out["error"]["message"].as_str().unwrap().contains("AFFECTED_BY_EVIDENCE_CHANGE"), "{out}");
    // without a list the checkpoint takes what is active now: nothing
    let second = step(&wal, "checkpoint", &[]);
    assert_eq!((second["epoch"].as_u64(), second["listed"].as_u64()), (Some(2), Some(0)));
    // the first bytes back: the first checkpoint gives the claim again, the second never listed it
    step(&wal, "put", &["--doc-id", "a", "--file", &dir.file("a1.txt", "Alpha is one.\n")]);
    assert_eq!(read(&wal, "checkpoint", &["--epoch", "1"])["active"].as_array().map(Vec::len), Some(1));
    assert_eq!(read(&wal, "checkpoint", &["--epoch", "2"])["active"].as_array().map(Vec::len), Some(0));

    // rules 3: a checkpoint with such a key is any checkpoint, and no read gives it out as a context checkpoint
    let old = dir.0.join("old.wal").to_str().unwrap().to_string();
    {
        use sbgk_core::audit::onto::AuditOntology;
        use sbgk_core::audit::state::{AuditState, GenesisSpec, RULES_VERSION_3};
        let mut state = AuditState::prepare_from_docs(&AuditOntology::base(), "old-rules", Vec::new()).unwrap();
        state.set_rules_version(RULES_VERSION_3).unwrap();
        state.start_journal(Path::new(&old), &GenesisSpec::default()).unwrap();
        let free = json!({"key": "vsc:checkpoint:1", "from": 0, "to": 0, "context": {"anything": true}});
        assert!(state.submit_operations_id("free", "agent", &[], Some(free)).unwrap()["error"].is_null());
    }
    let none = read(&old, "checkpoint", &["--epoch", "1"]);
    assert_eq!(
        (none["status"].as_str(), none["epochs"].as_u64(), none["rules_version"].as_str()),
        (Some("NO_CONTEXT_CHECKPOINT"), Some(0), Some("r2r-audit-rules/3"))
    );
    assert_eq!(read(&old, "status", &[]).get("context_checkpoints"), None);
}
