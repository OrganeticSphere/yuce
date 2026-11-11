//! Regressions for Codex's review of 77a803e (2026-10-23), his two native probes on the durable store: the exact-bytes hint counts
//! every whitespace-equivalent span of every section of the task (R03), and a question the word search finds no section for is not
//! said to be one the corpus cannot answer (R04).

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{unstored_problems, DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::Scope;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn wal(tag: &str) -> Wal {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    Wal(std::env::temp_dir().join(format!("sbgk_codex77a_{tag}_{}_{nonce}.jsonl", std::process::id())))
}

#[test]
fn no_hint_when_another_section_holds_the_words_twice() {
    // section A holds the words twice, B once with other spacing: three places in the task's sections, so no place is offered
    let text = "# A\nThe gate\nblocks.\nThe gate\nblocks.\n# B\nThe gate  \nblocks.\n";
    let split = text.find("# B").unwrap();
    let w = wal("hint");
    let s = AuditState::create(&w.0, &AuditOntology::base(), &[("d".into(), text.as_bytes().to_vec())], "ambiguity", sha256(b"probe")).unwrap();
    let hint = |ranges: Vec<(String, usize, usize)>| {
        let scope = Scope { docs: vec!["d".into()], topic: None, ranges };
        let line = json!({"kind": "observe", "local_id": "o", "doc_id": "d", "exact_quote": "The gate blocks.", "terms": []});
        let p = unstored_problems(&s, &scope, &BTreeMap::new(), &[], std::slice::from_ref(&line), &[(0, line.clone())]);
        assert_eq!(p[0]["error"]["code"], "QUOTE_NOT_FOUND_IN_BYTES", "{p:?}");
        p[0].get("exact_bytes_in_section").cloned()
    };
    assert_eq!(hint(vec![("d".into(), 0, split), ("d".into(), split, text.len())]), None, "A's two spans count");
    // B alone: one span in the task's sections and unique in the document, so it is offered
    assert_eq!(hint(vec![("d".into(), split, text.len())]), Some(json!("The gate  \nblocks.")));
}

#[test]
fn a_word_search_miss_is_not_said_to_be_absent_from_the_corpus() {
    // the source answers the question, but in other words than its terms: the question is given up as a word search miss and stays
    // open, and the summary is not told that the corpus lacks it
    let source = "# Report\nThe accepted count is forty-two.\n";
    let w = wal("lexical");
    let mut s = AuditState::create(&w.0, &AuditOntology::base(), &[("r".into(), source.as_bytes().to_vec())], "lexical", sha256(b"probe2")).unwrap();
    let q = s.submit_records_id(
        "q",
        "w9",
        "T9-bbbbbbbbbbbbbbbb",
        &Scope::default(),
        &[json!({"kind": "question", "local_id": "q", "text": "What total was approved?", "about": ["authorised quantity"], "needed": "the report's accepted count"})],
    );
    assert!(q.error.is_none(), "{:?}", q.error);
    let rq = ResearchQuestion { id: "RQ1".into(), text: "What count is reported?".into(), about: vec!["count".into()], ..Default::default() };
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![rq]);
    let mut b = Builder::new(BuilderConfig::default());
    let mut summary = Value::Null;
    for _ in 0..12 {
        while let Some(card) = b.next_card(&s) {
            b.submit(&mut s, &card.card_id, &[]);
        }
        let task = d.acquire(&s, "w1", b.caught_up(&s), 1);
        assert_ne!(task["kind"], "INVESTIGATE", "{task}");
        if task["kind"] == "EXTEND" {
            d.submit(&mut s, task["task_id"].as_str().unwrap(), "w1", &[], 1);
        } else if task["kind"] == "SUMMARIZE" {
            summary = task;
            break;
        }
        assert!(d.persist_unresolved(&mut s).is_empty());
    }
    assert!(d.persist_unresolved(&mut s).is_empty());
    let checkpoint = s.checkpoint(&format!("task:question:{}", q.accepted[0].short())).expect("the question given up, durably");
    assert_eq!(checkpoint["context"]["reason"], "no_section_matched_terms", "{checkpoint}");
    let prompt = summary["prompt"].as_str().expect("a summary task");
    assert!(prompt.contains("What total was approved?"), "the question stays open for the summary: {prompt}");
    assert!(!prompt.contains("no section of the corpus speaks to it"), "{prompt}");
    assert!(prompt.contains("a word search found no section on it, which does not show the corpus lacks it"), "{prompt}");
}
