//! Regressions for Codex's analysis of live run 10A-4 (2026-10-23), on the durable store: a question the word search finds no section for
//! is closed without a model call, durably and with its reason (F08); a question about `@id` finds the sections of that record (F08);
//! hypotheses are shown apart from what is recorded (F12); the record formats carry no real date (F07).

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{unstored_problems, DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordKind, Scope};
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

const R1: &str = "# Gate\nThe gate blocks a validator version mismatch.\n";
const R2: &str = "# Notes\nThe release checklist was signed by the owner.\n";

fn fresh(tag: &str) -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_codex10a4_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("r1".to_string(), R1.as_bytes().to_vec()), ("r2".to_string(), R2.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "codex-10a4", sha256(b"toy")).unwrap();
    (wal, state)
}

fn dispatcher() -> Dispatcher {
    let q = ResearchQuestion { id: "RQ1".into(), text: "What does the gate do?".into(), about: vec!["gate".into()], ..Default::default() };
    Dispatcher::new(DispatchConfig::default(), vec![q])
}

/// Every section read empty and the builder caught up: the next directive for `agent` is past the reading.
fn past_reading(d: &mut Dispatcher, s: &mut AuditState, b: &mut Builder, agent: &str) -> Value {
    loop {
        while let Some(c) = b.next_card(s) {
            b.submit(s, &c.card_id, &[]);
        }
        let t = d.acquire(s, agent, b.caught_up(s), 1);
        if t["kind"] != "EXTEND" {
            return t;
        }
        assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), agent, &[], 1)["status"], "COMMITTED");
    }
}

#[test]
fn a_question_no_section_matches_is_closed_without_a_model_call_and_a_named_record_finds_its_section() {
    let (wal, mut s) = fresh("nosource");
    let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
    let seed = s.submit_records(
        "w9",
        "T90-aaaaaaaaaaaaaaaa",
        &scope,
        &[
            json!({"kind": "observe", "local_id": "o1", "doc_id": "r1", "exact_quote": "The gate blocks a validator version mismatch.", "terms": ["gate"]}),
            json!({"kind": "claim", "local_id": "c1", "text": "The gate blocks", "subject": "gate", "stance": "reported", "based_on": ["o1"]}),
            json!({"kind": "hypothesis", "local_id": "h1", "text": "The gate will warn again", "falsifier": "a later report", "subject": "gate", "based_on": ["o1"]}),
        ],
    );
    assert!(seed.error.is_none(), "{:?}", seed.error);
    let claim = seed.accepted[1].short();
    let asked = s.submit_records(
        "w9",
        "T91-bbbbbbbbbbbbbbbb",
        &Scope::default(),
        &[
            json!({"kind": "question", "local_id": "q1", "text": "Is the quantum flux calibrated?", "about": ["quantum flux"], "needed": "a calibration log"}),
            json!({"kind": "question", "local_id": "q2", "text": "Since when does it block?", "about": [claim], "needed": "a dated decision"}),
        ],
    );
    assert!(asked.error.is_none(), "{:?}", asked.error);
    let (q1, q2) = (asked.accepted[0].short(), asked.accepted[1].short());
    let mut d = dispatcher();
    let mut b = Builder::new(BuilderConfig::default());
    let t = past_reading(&mut d, &mut s, &mut b, "w1");
    // the first question has nothing to read: it is passed over, and the second, about a record, gets that record's section
    assert_eq!(t["kind"], "INVESTIGATE", "{t}");
    assert_eq!(t["key"], format!("question:{q2}"), "{t}");
    let prompt = t["prompt"].as_str().unwrap();
    assert!(prompt.contains("SECTION doc_id=\"r1\""), "the record named in about leads to its section: {prompt}");
    // F12: the hypothesis is shown, apart from what is recorded
    assert!(prompt.contains("HYPOTHESES (not established"), "{prompt}");
    let recorded = prompt.split("ALREADY RECORDED:").nth(1).unwrap().split("HYPOTHESES").next().unwrap();
    assert!(!recorded.contains("hypothesis by"), "a hypothesis is not listed as recorded: {recorded}");
    // F07: no real date in the formats
    assert!(prompt.contains("\"as_of\":null") && !prompt.contains("20260810"), "{prompt}");
    // the closure is durable: written with the store at hand, kept by a restarted dispatcher
    assert!(d.persist_unresolved(&mut s).is_empty());
    let key = format!("question:{q1}");
    let checkpoint = s.checkpoint(&format!("task:{key}")).expect("a durable record of the question given up");
    assert_eq!((checkpoint["context"]["unresolved"].as_bool(), checkpoint["context"]["reason"].as_str()), (Some(true), Some("no_section_matched_terms")));
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    let mut d2 = dispatcher();
    d2.recover(&s);
    let status = d2.completion(&s, true);
    assert!(status["unresolved"].as_array().unwrap().iter().any(|k| k == &json!(key)), "{status}");
    assert_eq!(s.records_since(0).iter().filter(|r| r.kind == RecordKind::Question).count(), 2, "the question itself stays for the summaries");
}

#[test]
fn a_question_written_in_a_link_check_is_not_investigated() {
    // F09 (Codex), Gemini's alignment: seven questions of link checks became investigations in 10A-4
    let (_wal, mut s) = fresh("tv-question");
    let r = s.submit_records(
        "w9",
        "TV5-cccccccccccccccc",
        &Scope::default(),
        &[json!({"kind": "question", "local_id": "q1", "text": "Does the gate block?", "about": ["gate"], "needed": "a later report"})],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let mut d = dispatcher();
    let mut b = Builder::new(BuilderConfig::default());
    let t = past_reading(&mut d, &mut s, &mut b, "w1");
    assert_ne!(t["kind"], "INVESTIGATE", "a section speaks to the question, but it came from a link check: {t}");
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    assert!(t["prompt"].as_str().unwrap().contains("Does the gate block?"), "it stays open for the summary: {}", t["prompt"]);
}

#[test]
fn the_exact_bytes_hint_is_only_bytes_the_store_would_take() {
    // Codex on the hint: the candidate passes the store's own quote rule; bytes unique in the section but repeated elsewhere in the
    // document are not offered, and another section is not disclosed
    let text = "# A
alpha beta
gamma here.
# B
alpha beta
gamma again.
";
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_codex10a4_hint_{}_{nonce}.jsonl", std::process::id())));
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), text.as_bytes().to_vec())], "hint", sha256(b"hint")).unwrap();
    let first = text.find("# B").unwrap();
    let hint = |quote: &str, ranges: Vec<(String, usize, usize)>| {
        let scope = Scope { docs: vec!["d".into()], topic: None, ranges };
        let line = json!({"kind": "observe", "local_id": "o", "doc_id": "d", "exact_quote": quote, "terms": []});
        let p = unstored_problems(&s, &scope, &BTreeMap::new(), &[], std::slice::from_ref(&line), &[(0, line.clone())]);
        p[0].get("exact_bytes_in_section").cloned()
    };
    assert_eq!(
        hint("beta gamma here.", vec![("d".into(), 0, first)]),
        Some(json!(
            "beta
gamma here."
        )),
        "unique in the document"
    );
    assert_eq!(hint("alpha beta gamma", vec![("d".into(), 0, first)]), None, "the same bytes stand in another section too");
}
