//! The reading-only shard (`--reading-only`, 0.2.3): a run that reads and records, whose summaries are made outside its journal.
//! No SUMMARIZE is issued; the run is complete once no work is open and no lease is out, its questions answered by nobody here;
//! the terminal receipt says the summaries are outside the journal. Without the setting nothing changes. A withdrawal in an open
//! reading-only run is closed like any other work. No provider or runner calls.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::AuditStore;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const LOG: &str = "# Changes\n\n1. Remove batching support.\n2. Add tool titles.\n\n# Notes\n\nA client MUST retry.\n\nAnother plain note.\n";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn journal(name: &str) -> (Wal, AuditState) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = Wal(std::env::temp_dir().join(format!("reading_only_{name}_{}_{nonce}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
    let s = AuditState::create(&path.0, &AuditOntology::base(), &[("log.md".to_string(), LOG.as_bytes().to_vec())], "reading-only-run", sha256(b"m")).unwrap();
    (path, s)
}

fn dispatcher(reading_only: bool) -> Dispatcher {
    let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
    Dispatcher::new(DispatchConfig { section_bytes: 128, reading_only, ..Default::default() }, vec![q])
}

/// Answers every reading task with a quote of each line of `quotes` its prompt shows; returns the first task that is no reading
/// task, and the kinds of the tasks issued.
fn read_all(d: &mut Dispatcher, s: &mut AuditState, quotes: &[&str]) -> (Value, Vec<String>) {
    let mut kinds = Vec::new();
    loop {
        let t = d.acquire(s, "w1", true, 0);
        if t["status"] != "DIRECTIVE" || t["kind"] != "EXTEND" {
            return (t, kinds);
        }
        kinds.push(t["kind"].as_str().unwrap().to_string());
        let (prefix, prompt) = (t["local_id_prefix"].as_str().unwrap(), t["prompt"].as_str().unwrap());
        let lines: Vec<Value> = quotes
            .iter()
            .filter(|q| prompt.contains(**q))
            .enumerate()
            .map(|(n, q)| json!({"kind": "observe", "local_id": format!("{prefix}o{n}"), "doc_id": "log.md", "exact_quote": q, "terms": ["change"]}))
            .collect();
        assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), "w1", &lines, 0)["status"], "COMMITTED", "{t}");
    }
}

#[test]
fn a_reading_only_run_is_issued_no_summary_and_is_complete_after_its_reading() {
    let (_w, mut s) = journal("on");
    let mut d = dispatcher(true);
    let (last, kinds) = read_all(&mut d, &mut s, &["2. Add tool titles.", "A client MUST retry."]);
    assert!(!kinds.is_empty() && kinds.iter().all(|k| k == "EXTEND"), "only reading tasks: {kinds:?}");
    assert_eq!(last["status"], "COMPLETE", "no summary is issued: {last}");
    let completion = d.completion(&s, true);
    assert_eq!((&completion["complete"], &completion["answered"]), (&json!(true), &json!(0)), "{completion}");
    // the receipt says the summaries are outside the journal: no outcome, no unknown, no question failed
    let receipt = d.terminal_receipt(&s, s.head(), "reading-only-run").expect("a terminal receipt");
    assert_eq!(receipt["summaries"]["in_journal"], false, "{receipt}");
    assert_eq!((receipt["outcomes"].as_object().map(|o| o.len()), &receipt["unknown_outcomes"], &receipt["not_answered"]), (Some(0), &json!([]), &json!([])));
}

#[test]
fn without_the_setting_a_run_still_owes_its_summaries() {
    let (_w, mut s) = journal("off");
    let mut d = dispatcher(false);
    let (last, _) = read_all(&mut d, &mut s, &["2. Add tool titles.", "A client MUST retry."]);
    assert_eq!((last["kind"].as_str(), last["key"].as_str()), (Some("SUMMARIZE"), Some("rq:RQ1")), "{last}");
    assert_eq!(d.completion(&s, true)["complete"], false);
    assert!(d.terminal_receipt(&s, s.head(), "reading-only-run").is_none());
    // and a receipt of a run that summarizes never names the summaries outside the journal
    d.release(last["task_id"].as_str().unwrap(), "w1");
}

#[test]
fn a_withdrawal_in_an_open_reading_only_run_is_closed_like_any_other_work() {
    let (_w, mut s) = journal("withdrawal");
    let mut d = dispatcher(true);
    let (last, _) = read_all(&mut d, &mut s, &["2. Add tool titles.", "A client MUST retry."]);
    assert_eq!(last["status"], "COMPLETE", "{last}");
    // the owner withdraws the text a quote stands on: no answer of this shard falls, since it has none to keep
    assert!(s.withdraw_text("owner", "log.md", "A client MUST retry.").unwrap() >= 1);
    let (after, _) = read_all(&mut d, &mut s, &["Another plain note."]);
    assert_eq!(after["status"], "COMPLETE", "{after}");
    assert_eq!(d.completion(&s, true)["complete"], true);
    let receipt = d.terminal_receipt(&s, s.head(), "reading-only-run").expect("a terminal receipt after the withdrawal");
    assert_eq!(receipt["summaries"]["in_journal"], false, "{receipt}");
}
