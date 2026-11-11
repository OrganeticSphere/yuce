//! Regressions for the remaining items of Codex's review of d7d9a49 (D04, D06, D07, F10), on the durable store.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str, text: &str) -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_d7_tails_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), text.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "d7-tails", sha256(b"toy")).unwrap();
    (wal, state)
}

const DOC: &str = "# Topic\nTopic A is reported.\nTopic A was checked again later.\nTopic A holds in the later report.\n";

fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig { section_bytes: 4000, ttl_ms: 100, ..Default::default() },
        vec![ResearchQuestion {
            id: "RQ1".into(),
            text: "What do the reports establish about the topic?".into(),
            about: vec!["topic".into()],
            ..Default::default()
        }],
    )
}

fn observe_and_claim(s: &mut AuditState, actor: &str, quote: &str) -> (RecordId, RecordId) {
    let r = s.submit_records(
        actor,
        &format!("seed-{actor}-{quote}"),
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[
            json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": quote, "terms": ["topic"]}),
            json!({"kind": "claim", "local_id": "c", "text": quote, "subject": "topic", "predicate": "is", "object": "reported", "stance": "reported", "based_on": ["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    (r.accepted[0], r.accepted[1])
}

/// Read the only section with an empty answer; the next directive is returned.
fn past_reading(d: &mut Dispatcher, s: &mut AuditState, agent: &str, now: u64) -> Value {
    let t = d.acquire(s, agent, true, now);
    if t["kind"] != "EXTEND" {
        return t;
    }
    assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), agent, &[], now)["status"], "COMMITTED");
    d.acquire(s, agent, true, now)
}

#[test]
fn d04_a_name_and_aliases_held_by_two_concepts_are_not_reused_by_their_order() {
    let (_wal, mut s) = fresh("ambiguous", "Parser one.\nValidator two.\nPipeline three.\n");
    let scope = Scope { docs: vec!["d1".into()], ..Default::default() };
    let seed = |s: &mut AuditState, quote: &str, term: &str| {
        let r = s.submit_records(
            "reader",
            &format!("seed-{term}"),
            &scope,
            &[json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": quote, "terms": [term]})],
        );
        assert!(r.error.is_none(), "{:?}", r.error);
    };
    seed(&mut s, "Parser one.", "parser");
    seed(&mut s, "Validator two.", "validator");
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&s).unwrap();
    let ops: Vec<Value> = card
        .records
        .iter()
        .map(|r| json!({"op": "propose_concept", "type": "Component", "name": r.terms[0], "aliases": [], "basis": [r.id.short()]}))
        .collect();
    assert_eq!(b.submit(&mut s, &card.card_id, &ops)["status"], "CARD_DONE");
    seed(&mut s, "Pipeline three.", "pipeline");
    let card = b.next_card(&s).unwrap();
    let op =
        json!({"op": "propose_concept", "type": "Component", "name": "pipeline", "aliases": ["parser", "validator"], "basis": [card.records[0].id.short()]});
    let r = b.submit(&mut s, &card.card_id, &[op]);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "two different concepts hold the aliases: no reuse picked by order: {r}");
    assert_eq!(b.stats.concepts_reused, 0);
}

#[test]
fn d06_a_question_given_up_by_expired_failed_leases_stays_given_up_after_a_restart() {
    let (wal, mut s) = fresh("expiry", DOC);
    observe_and_claim(&mut s, "reader", "Topic A is reported.");
    let mut d = dispatcher();
    let mut now = 1_000;
    let mut t = past_reading(&mut d, &mut s, "sum", now);
    for round in 0..3 {
        assert_eq!(t["kind"], "SUMMARIZE", "round {round}: {t}");
        let task = t["task_id"].as_str().unwrap();
        let wrong = json!({"kind": "done", "local_id": "x", "rq_id": "RQ9", "directive_id": task, "outcome": "unknown", "answer_ids": []});
        assert_eq!(d.submit(&mut s, task, "sum", &[wrong], now)["status"], "REPAIR_REQUIRED");
        // the agent never gives the lease back: it expires
        now += 1_000;
        t = d.acquire(&s, "sum", true, now);
        assert!(d.persist_unresolved(&mut s).is_empty(), "the give-up is written");
    }
    assert_eq!(t["status"], "COMPLETE", "{t}");
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher();
    recovered.recover(&s);
    assert_eq!(recovered.acquire(&s, "sum", true, 1).get("status").and_then(Value::as_str), Some("COMPLETE"), "not issued again after a restart");
}

#[test]
fn d07_an_investigation_settles_its_question_only_by_a_standing_claim_or_question() {
    let (_wal, mut s) = fresh("settled", DOC);
    observe_and_claim(&mut s, "reader", "Topic A is reported.");
    let q = json!({"kind": "question", "local_id": "q", "text": "does topic A still hold later?", "about": ["topic"], "needed": "the later report"});
    assert!(s.submit_records("reader", "seed-q", &Scope { docs: vec!["d1".into()], ..Default::default() }, &[q]).error.is_none());
    let mut d = dispatcher();
    let t = past_reading(&mut d, &mut s, "inv", 1);
    assert_eq!(t["kind"], "INVESTIGATE", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap());
    let o = json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "d1", "exact_quote": "Topic A holds in the later report.", "terms": ["topic"]});
    let c = json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "Topic A holds later.", "subject": "topic", "stance": "confirmed", "based_on": [format!("{p}o1")]});
    let r = d.submit(&mut s, task, "inv", &[o, c], 2);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let observe: RecordId = s.records_since(0).iter().find(|x| x.quote.as_deref() == Some("Topic A holds in the later report.")).unwrap().id;
    let open = |d: &mut Dispatcher, s: &AuditState, now: u64| -> String {
        let t = d.acquire(s, "sum", true, now);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        let prompt = t["prompt"].as_str().unwrap().to_string();
        d.release(t["task_id"].as_str().unwrap(), "sum");
        prompt.split("OPEN QUESTIONS (not settled").nth(1).unwrap().to_string()
    };
    assert!(!open(&mut d, &s, 3).contains("does topic A still hold later?"), "a standing claim settles the question");
    s.revoke_observation("owner", &observe).unwrap();
    let prompt_open = open(&mut d, &s, 4);
    assert!(prompt_open.contains("does topic A still hold later?"), "its claim lost its ground: open again: {prompt_open}");
}

#[test]
fn f10_a_summary_shows_the_roles_of_a_claims_terms() {
    let (_wal, mut s) = fresh("roles", DOC);
    observe_and_claim(&mut s, "reader", "Topic A is reported.");
    let mut d = dispatcher();
    let t = past_reading(&mut d, &mut s, "sum", 1);
    let prompt = t["prompt"].as_str().unwrap();
    assert!(prompt.contains("subject: topic") && prompt.contains("object: reported"), "{prompt}");
}
