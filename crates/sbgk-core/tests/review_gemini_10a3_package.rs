//! Regressions for Gemini's audit of live run 10A-3 (2026-10-22), on the durable store: a builder answer over its operation limit
//! is a repair, and a refused swarm answer names every problem of the lines the store did not take. What is stored is unchanged:
//! the accepted prefix stays, and the diagnostics never decide.

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

fn fresh(tag: &str, text: &str) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_gemini10a3_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), text.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "gemini-10a3", sha256(b"toy")).unwrap();
    (wal, state)
}

fn dispatcher() -> Dispatcher {
    let q = ResearchQuestion { id: "RQ1".into(), text: "Did the gate change?".into(), about: vec!["validator version".into()], ..Default::default() };
    Dispatcher::new(DispatchConfig::default(), vec![q])
}

const REPORT: &str =
    "# Gate\nThe gate blocks a validator\nversion mismatch today.\nThe gate warns.\nLater the gate warns.\nThe validator version difference is now blocking.\n";

fn observe(p: &str, n: u32, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": format!("{p}o{n}"), "doc_id": "d1", "exact_quote": quote, "terms": ["validator version"]})
}

fn claim(p: &str, n: u32, basis: &[String]) -> Value {
    json!({"kind": "claim", "local_id": format!("{p}c{n}"), "text": "The gate blocks a version mismatch", "subject": "validator version",
           "stance": "reported", "based_on": basis})
}

#[test]
fn a_refused_answer_names_every_problem_of_the_lines_not_taken_and_the_accepted_prefix_stays() {
    let (_wal, mut s) = fresh("diagnostics", REPORT);
    let mut d = dispatcher();
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    assert!(t["prompt"].as_str().unwrap().contains("SECTION doc_id=\"d1\" (bytes "), "every section names its doc_id: {}", t["prompt"]);
    let (task, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
    let answer = [
        observe(&p, 1, "The validator version difference is now blocking."),
        // the words of the report, but the report breaks the line inside the phrase
        observe(&p, 2, "The gate blocks a validator version mismatch today."),
        // twice in the document
        observe(&p, 3, "gate warns."),
        claim(&p, 1, &[format!("{p}o1")]),
        // a basis that is a claim, as INVESTIGATE answers wrote in 10A-3
        json!({"kind": "relation", "local_id": format!("{p}r1"), "from": format!("{p}c1"), "rel": "supports", "to": format!("{p}c1"), "based_on": [format!("{p}c1")]}),
    ];
    let r = d.submit(&mut s, &task, "w1", &answer, 1);
    assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(2)), "{r}");
    // A1 accepts the unique soft wrap as exact original bytes; ambiguity and a non-Observe basis stay refused.
    assert_eq!(r["accepted"].as_array().map(Vec::len), Some(3), "the two valid quotes and the independent claim are stored: {r}");
    assert_eq!(s.records_since(0).iter().filter(|x| x.kind == RecordKind::Observe).count(), 2);
    let canonical = "The gate blocks a validator\nversion mismatch today.";
    assert_eq!(s.records_since(0)[1].quote.as_deref(), Some(canonical));
    assert_eq!(r["extended"][0]["stored"], canonical);
    let problems = r["problems"].as_array().expect("the refusal names the problems of the lines not taken");
    let at = |line: u64| problems.iter().filter(|p| p["line"].as_u64() == Some(line)).collect::<Vec<_>>();
    assert!(at(1).is_empty(), "the source-exact canonical repair was accepted: {r}");
    assert_eq!(r["not_stored"], json!([format!("{p}o3"), format!("{p}r1")]), "{r}");
    assert!(r["repair"].as_str().unwrap().contains("Send only the lines of not_stored"), "{r}");
    assert_eq!(at(2)[0]["error"]["code"], "AMBIGUOUS_QUOTE_SPAN", "the store's rule still rejects both spans: {r}");
    assert!(at(3).is_empty(), "a claim resting on an accepted quote has no problem: {r}");
    assert_eq!(at(4)[0]["not_observes"][0], format!("{p}c1 is a claim"), "{r}");
    assert!(r["repair"].as_str().unwrap().contains("problems"), "{r}");

    // Send only the repaired quote and a fresh claim id; the already accepted aliases remain immutable.
    let rest = [observe(&p, 3, "Later the gate warns."), claim(&p, 2, &[format!("{p}o1"), format!("{p}o2")])];
    let r = d.submit(&mut s, &task, "w1", &rest, 2);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    drop(s);
    let reopened = AuditState::open(&_wal.0).unwrap();
    assert_eq!(reopened.records_since(0).len(), 5);
    assert_eq!(reopened.records_since(0)[1].quote.as_deref(), Some(canonical));
}

#[test]
fn diagnostics_follow_the_store_rule_for_documents_and_sections() {
    let (_wal, mut s) = fresh("scope", REPORT);
    let mut d = dispatcher();
    let t = d.acquire(&s, "w1", true, 0);
    let (task, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
    let foreign = json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "foreign_report", "exact_quote": "The gate warns.", "terms": []});
    let r = d.submit(&mut s, &task, "w1", &[foreign], 1);
    assert_eq!(r["error"]["message"], "document is outside the directive", "{r}");
    assert_eq!(r["problems"][0]["choose_one_of"], json!(["d1"]), "{r}");
    assert_eq!(s.records_since(0).len(), 0);
    // the shared rule refuses what the store refuses and finds the span it binds
    let scope = Scope { docs: vec!["d1".into()], topic: None, ranges: vec![("d1".into(), 0, 7)] };
    let span = sbgk_core::audit::state::quote_span(&scope, "d1", Some(REPORT.as_bytes()), "# Gate").unwrap();
    assert_eq!((span.start, span.end), (0, 6));
    let e = sbgk_core::audit::state::quote_span(&scope, "d1", Some(REPORT.as_bytes()), "The gate warns.").unwrap_err();
    assert_eq!(e.message, "quote is outside the issued byte ranges");
    // a done line's text is bound when given (the offline replay of 10A-3 found four summaries' done texts unnamed)
    let done = |text: Option<&str>| {
        let mut v = json!({"kind": "done", "local_id": "d1", "rq_id": "RQ1", "directive_id": "T", "answer_ids": [], "outcome": "unknown"});
        if let Some(t) = text {
            v["text"] = json!(t);
        }
        v
    };
    let named = |line: Value| unstored_problems(&s, &scope, &BTreeMap::new(), &[], std::slice::from_ref(&line), &[(0, line.clone())]).len();
    assert_eq!((named(done(Some(&"x".repeat(241)))), named(done(Some("open: the gate's owner"))), named(done(None))), (1, 0, 0));
}

#[test]
fn a_verdict_without_basis_is_told_what_it_may_cite() {
    let (_wal, mut s) = fresh("verdict", REPORT);
    let mut d = dispatcher();
    let mut b = Builder::new(BuilderConfig::default());
    let t = d.acquire(&s, "w1", true, 0);
    let p = t["local_id_prefix"].as_str().unwrap().to_string();
    let lines = [
        observe(&p, 1, "Later the gate warns."),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "The gate warns", "subject": "validator version", "stance": "reported", "based_on": [format!("{p}o1")]}),
        observe(&p, 2, "The validator version difference is now blocking."),
        json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "The gate blocks", "subject": "validator version", "stance": "reported", "based_on": [format!("{p}o2")]}),
    ];
    assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &lines, 1)["status"], "COMMITTED");
    let recs = s.records_since(0);
    let id = |k: RecordKind, n: usize| recs.iter().filter(|r| r.kind == k).nth(n).unwrap().id.short();
    let card = b.next_card(&s).unwrap();
    let link =
        json!({"op": "link", "from": id(RecordKind::Claim, 1), "rel": "supersedes", "to": id(RecordKind::Claim, 0), "basis": [id(RecordKind::Observe, 1)]});
    assert_eq!(b.submit(&mut s, &card.card_id, &[link])["status"], "CARD_DONE");
    let v = d.acquire(&s, "w2", b.caught_up(&s), 2);
    assert_eq!(v["kind"], "VERIFY_LINK", "{v}");
    let (task, q) = (v["task_id"].as_str().unwrap().to_string(), v["local_id_prefix"].as_str().unwrap().to_string());
    let link_id = s.links()[0].id.short();
    let answer = [observe(&q, 1, "difference is now blocking"), json!({"kind": "verdict", "link": link_id, "verdict": "confirm", "reason": "later"})];
    let r = d.submit(&mut s, &task, "w2", &answer, 3);
    assert_eq!((r["status"].as_str(), r["error"]["code"].as_str()), (Some("REPAIR_REQUIRED"), Some("NO_EVIDENCE")), "{r}");
    let expected = &r["error"]["expected_by_kernel"];
    assert_eq!(expected["verdict"], json!(["confirm", "reject"]), "{r}");
    assert_eq!(expected["based_on"]["your_quotes"], json!([format!("{q}o1")]), "the quote this task already got accepted: {r}");
    assert!(expected["based_on"]["records_shown"].as_array().is_some_and(|a| !a.is_empty()), "{r}");
    let fixed = [json!({"kind": "verdict", "link": link_id, "verdict": "confirm", "reason": "later", "based_on": [format!("{q}o1")]})];
    assert_eq!(d.submit(&mut s, &task, "w2", &fixed, 4)["status"], "COMMITTED", "nothing is chosen for the agent: it names the basis");
}

#[test]
fn a_builder_answer_over_the_operation_limit_is_a_repair_also_after_a_reopen() {
    let (wal, mut s) = fresh("ops", REPORT);
    let r = s.submit_records(
        "reader",
        "seed",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": "Later the gate warns.", "terms": ["gate warning"]})],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let cfg = BuilderConfig { max_ops: 2, ..Default::default() };
    let mut b = Builder::new(cfg);
    let card = b.next_card(&s).unwrap();
    let o = card.records[0].id.short();
    let propose = |name: &str| json!({"op": "propose_concept", "type": "Component", "name": name, "aliases": [], "basis": [o]});
    let over = [propose("gate a"), propose("gate b"), propose("gate c")];
    let head = s.wal_head();
    let r = b.submit(&mut s, &card.card_id, &over);
    assert_eq!((r["status"].as_str(), r["code"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some("TOO_MANY_OPS"), Some(0)), "{r}");
    assert_eq!(s.wal_head(), head, "nothing of the answer was written");
    drop(s);

    let mut s = AuditState::open(&wal.0).unwrap();
    let mut b = Builder::new(cfg);
    b.recover(&s);
    let reopened = b.next_card(&s).unwrap();
    assert_eq!((reopened.card_id.as_str(), reopened.max_ops), (card.card_id.as_str(), 2));
    let r = b.submit(&mut s, &reopened.card_id, &over);
    assert_eq!((r["status"].as_str(), r["committed_ops"].as_u64()), (Some("REPAIR_REQUIRED"), Some(0)), "{r}");
    assert_eq!(s.wal_head(), head, "the same refusal after a reopen writes nothing either");
    let r = b.submit(&mut s, &reopened.card_id, &over[..2]);
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert_eq!(b.stats.ops_accepted, 2);
}
