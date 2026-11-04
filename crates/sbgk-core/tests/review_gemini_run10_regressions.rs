//! Regressions for Gemini's run-9 review and run-10 corrections (2026-10-22), on the durable store.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::json;
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str, text: &str) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_gemini10_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), text.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "gemini-run10", sha256(b"toy")).unwrap();
    (wal, state)
}

fn observe(s: &mut AuditState, directive: &str, quote: &str, term: &str) {
    let r = s.submit_records(
        "reader",
        directive,
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": quote, "terms": [term]})],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
}

#[test]
fn a_later_report_is_stitched_to_the_concept_an_earlier_report_got() {
    let (_wal, mut s) = fresh("stitch", "Report one keeps a self-reference limitation.\nReport two defers the self-reference check to live evidence.\n");
    observe(&mut s, "first", "Report one keeps a self-reference limitation.", "self-reference limitation");
    let mut b = Builder::new(BuilderConfig::default());
    let first = b.next_card(&s).unwrap();
    let o1 = first.records[0].id.short();
    let ops = [
        json!({"op": "propose_concept", "type": "Limitation", "name": "report self-reference limitation", "aliases": [], "basis": [o1]}),
        json!({"op": "map_term", "record": o1, "term": "self-reference limitation", "concept": "report self-reference limitation"}),
    ];
    assert_eq!(b.submit(&mut s, &first.card_id, &ops)["status"], "CARD_DONE");
    let concept = s.candidates("report self-reference limitation", 1)[0].clone();

    let term = "self-reference; deferred to live evidence";
    observe(&mut s, "second", "Report two defers the self-reference check to live evidence.", term);
    let second = b.next_card(&s).unwrap();
    assert!(
        second.candidates[term].iter().any(|c| c.id == concept.id),
        "a concept sharing a significant word is a candidate of the later term: {:?}",
        second.candidates
    );
    let o2 = second.records[0].id.short();
    // what gpt-5.6-sol wrote in run 9: the same name with a new alias, then the existing concept by its full id
    let ops = [
        json!({"op": "propose_concept", "type": "Limitation", "name": "report self-reference limitation", "aliases": ["final commit SHA in report"], "basis": [o2]}),
        json!({"op": "map_term", "record": o2, "term": term, "concept": format!("@{}", to_hex(&concept.id.0))}),
    ];
    let r = b.submit(&mut s, &second.card_id, &ops);
    assert_eq!(r["status"], "CARD_DONE", "no catch-22 between 'already reserved' and 'not a candidate': {r}");
    assert_eq!(r["results"][0]["status"], "existing", "{r}");
    assert_eq!(s.records_of(&concept.id).len(), 2, "both reports' records are mapped to one concept");
    assert_eq!(b.stats.concepts_reused, 1);
}

#[test]
fn a_question_selects_claims_by_their_stance_without_naming_a_topic() {
    let (_wal, mut s) = fresh("stance", "# Rules\nThe old rule was replaced by the gate.\n");
    let r = s.submit_records(
        "reader",
        "seed",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[
            json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": "The old rule was replaced by the gate.", "terms": ["rule"]}),
            json!({"kind": "claim", "local_id": "c", "text": "The old rule no longer holds.", "subject": "rule", "stance": "superseded", "based_on": ["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    // read the only section, then compare the windows of the same question with and without the stance selector
    let mut d0 = Dispatcher::new(DispatchConfig { section_bytes: 4000, ..Default::default() }, vec![]);
    let t = d0.acquire(&s, "w", true, 0);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    assert_eq!(d0.submit(&mut s, t["task_id"].as_str().unwrap(), "w", &[], 1)["status"], "COMMITTED");
    let summary_window = |q: ResearchQuestion| {
        let mut d = Dispatcher::new(DispatchConfig { section_bytes: 4000, ..Default::default() }, vec![q]);
        d.recover(&s);
        let t = d.acquire(&s, "sum", true, 2);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        t["prompt"].as_str().unwrap().lines().find(|l| l.starts_with("WINDOW:")).unwrap().to_string()
    };
    let topic_only = ResearchQuestion { id: "RQ1".into(), text: "Which conclusions changed?".into(), about: vec!["unrelated".into()], ..Default::default() };
    let by_stance = ResearchQuestion { stances: vec!["superseded".into()], ..topic_only.clone() };
    assert!(summary_window(topic_only).starts_with("WINDOW: 0 of 0"));
    assert!(summary_window(by_stance).starts_with("WINDOW: 1 of 1"), "a superseded claim is about a question on superseded conclusions");
}
