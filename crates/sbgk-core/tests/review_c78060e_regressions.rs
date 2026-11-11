//! Regressions for Codex's review of c78060e (2026-10-22, "graph -> selection -> context -> answer"), on the durable store.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str, docs: &[(&str, &str)]) -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_c780_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs: Vec<(String, Vec<u8>)> = docs.iter().map(|(d, t)| (d.to_string(), t.as_bytes().to_vec())).collect();
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "c780-regressions", sha256(b"toy")).unwrap();
    (wal, state)
}

const TWO: [(&str, &str); 2] =
    [("d1", "# First\nTopic A is reported.\nTopic A was checked again later.\n"), ("d2", "# Second\nTopic B is reported.\nTopic B was confirmed.\n")];

fn dispatcher(text: &str) -> Dispatcher {
    Dispatcher::new(
        DispatchConfig { section_bytes: 4000, ..Default::default() },
        vec![ResearchQuestion { id: "RQ1".into(), text: text.into(), about: vec!["topic".into()], ..Default::default() }],
    )
}

/// An observe of `quote` in `doc` and a claim on it, by `actor`: (observe, claim).
fn seed(s: &mut AuditState, actor: &str, doc: &str, quote: &str) -> (RecordId, RecordId) {
    let r = s.submit_records(
        actor,
        &format!("seed-{actor}-{quote}"),
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[
            json!({"kind": "observe", "local_id": "o", "doc_id": doc, "exact_quote": quote, "terms": ["topic"]}),
            json!({"kind": "claim", "local_id": "c", "text": quote, "subject": "topic", "stance": "reported", "based_on": ["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    (r.accepted[0], r.accepted[1])
}

/// Read every section with empty answers; the first other directive (leased to `agent`) is returned.
fn past_reading(d: &mut Dispatcher, s: &mut AuditState, agent: &str) -> Value {
    for now in 0..1000 {
        let t = d.acquire(s, agent, true, now);
        if t["kind"] != "EXTEND" {
            return t;
        }
        assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), agent, &[], now)["status"], "COMMITTED");
    }
    panic!("the reading never ended");
}

fn task(t: &Value) -> (&str, &str) {
    (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap())
}

#[test]
fn f01_a_summary_window_fits_the_store_and_shows_every_claim_with_all_its_quotes() {
    let text: String = (0..240).map(|i| format!("Topic line {i:03} is reported here.\n")).collect();
    let (_wal, mut s) = fresh("window", &[("d1", &text)]);
    let scope = Scope { docs: vec!["d1".into()], ..Default::default() };
    for i in 0..120 {
        let o = |k: usize| json!({"kind": "observe", "local_id": format!("o{k}"), "doc_id": "d1", "exact_quote": format!("Topic line {:03} is reported here.", 2 * i + k), "terms": ["topic"]});
        let c =
            json!({"kind": "claim", "local_id": "c", "text": format!("Topic claim {i}."), "subject": "topic", "stance": "reported", "based_on": ["o0", "o1"]});
        let r = s.submit_records("reader", &format!("seed{i}"), &scope, &[o(0), o(1), c]);
        assert!(r.error.is_none(), "{:?}", r.error);
    }
    let mut d = dispatcher("What do the reports establish about the topic?");
    let t = past_reading(&mut d, &mut s, "sum");
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    let prompt = t["prompt"].as_str().unwrap();
    assert!(prompt.contains("of 120 relevant claims shown"), "the window says how much it holds: {prompt}");
    assert!(prompt.contains("(say that the answer may be incomplete)"), "and that some claims did not fit");
    let shown: BTreeSet<&str> = prompt.lines().filter_map(|l| l.split_whitespace().next()).filter(|w| w.starts_with('@')).collect();
    let claims: Vec<&str> = prompt.lines().filter(|l| l.contains(" claim by ")).collect();
    assert!(claims.len() >= 80, "most of the window is used: {} claims", claims.len());
    for c in &claims {
        for b in c.rsplit(" <- ").next().unwrap().split(", ") {
            assert!(shown.contains(b.trim()), "a claim is shown with every quote it rests on: {c} (missing {b})");
        }
    }
    let (id, p) = task(&t);
    let done = json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": id, "outcome": "unknown", "answer_ids": []});
    let r = d.submit(&mut s, id, "sum", &[done], 2000);
    assert_eq!(r["status"], "COMMITTED", "the issued list stays within the store's limit, so an answer can be accepted: {r}");
}

#[test]
fn f03_a_summary_neither_shows_nor_follows_a_link_whose_confirmation_no_longer_stands() {
    let (_wal, mut s) = fresh("usable-link", &TWO);
    let (_, a) = seed(&mut s, "author-a", "d1", "Topic A is reported.");
    let (o2, b) = seed(&mut s, "author-b", "d2", "Topic B is reported.");
    let check = s.submit_records(
        "verifier",
        "check",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": "Topic A was checked again later.", "terms": ["topic"]})],
    );
    assert!(check.error.is_none(), "{:?}", check.error);
    let link = s.add_link("builder", &a, "supports", &b, &[o2]).unwrap().id;
    s.set_link_status(&link, LinkStatus::Accepted, "verifier", &[check.accepted[0]]).unwrap();
    assert!(s.link_usable(&link));
    s.revoke_observation("owner", &check.accepted[0]).unwrap();
    assert_eq!(s.link(&link).unwrap().status, LinkStatus::Accepted, "the raw status stays");
    assert!(!s.link_usable(&link), "but the edge no longer stands");
    let mut d = dispatcher("What do the reports establish about the topic?");
    let t = past_reading(&mut d, &mut s, "sum");
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    assert!(!t["prompt"].as_str().unwrap().contains("(accepted)"), "{}", t["prompt"]);
}

#[test]
fn f04_a_restarted_builder_replays_what_it_committed_after_a_refusal_and_writes_nothing() {
    let (wal, mut s) = fresh(
        "builder-replay",
        &[(
            "d1",
            "Evidence alpha is reported.
Evidence beta is reported.
",
        )],
    );
    let r = s.submit_records(
        "reader",
        "seed",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[
            json!({"kind": "observe", "local_id": "a", "doc_id": "d1", "exact_quote": "Evidence alpha is reported.", "terms": ["alpha"]}),
            json!({"kind": "observe", "local_id": "b", "doc_id": "d1", "exact_quote": "Evidence beta is reported.", "terms": ["beta"]}),
            // a builder link connects claims (block A of the 10A-4 audit)
            json!({"kind": "claim", "local_id": "ca", "text": "Alpha is reported.", "subject": "alpha", "stance": "reported", "based_on": ["a"]}),
            json!({"kind": "claim", "local_id": "cb", "text": "Beta is reported.", "subject": "beta", "stance": "reported", "based_on": ["b"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let (a, b) = (r.accepted[2].short(), r.accepted[3].short());
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let ops = [json!({"op": "no_such_op"}), json!({"op": "link", "from": a, "rel": "supports", "to": b, "basis": [a]})];
    let first = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!((first["status"].as_str(), first["accepted"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{first}");
    let committed = (s.root(), s.transaction_sequence());
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut recovered = Builder::new(BuilderConfig::default());
    recovered.recover(&s);
    assert_eq!(recovered.next_card(&s).unwrap().card_id, card.card_id);
    let again = recovered.submit(&mut s, &card.card_id, &ops);
    assert_eq!((again["status"].as_str(), again["refused"][0]["index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(0)), "{again}");
    assert_eq!(again["results"][0]["link"], first["results"][0]["link"], "the same link, from its receipt");
    assert_eq!(recovered.stats.ops_accepted, 0, "nothing is proposed again");
    assert_eq!((s.root(), s.transaction_sequence()), committed, "an exact resend after a restart writes nothing");
}

#[test]
fn f05_a_question_given_up_is_reported_as_not_answered_and_reopens_when_its_text_changes() {
    let (wal, mut s) = fresh("rq-revision", &TWO);
    seed(&mut s, "reader", "d1", "Topic A is reported.");
    let mut d = dispatcher("What do the reports establish about the topic?");
    let mut t = past_reading(&mut d, &mut s, "sum");
    for round in 0..3 {
        assert_eq!(t["kind"], "SUMMARIZE", "round {round}: {t}");
        let (id, _) = task(&t);
        let wrong = json!({"kind": "done", "local_id": "x", "rq_id": "RQ9", "directive_id": id, "outcome": "unknown", "answer_ids": []});
        assert_eq!(d.submit(&mut s, id, "sum", &[wrong], 3000)["status"], "REPAIR_REQUIRED");
        d.release_durable(&mut s, id, "sum");
        t = d.acquire(&s, "sum", true, 3001 + round);
    }
    assert_eq!(t["status"], "COMPLETE", "{t}");
    let receipt = d.terminal_receipt(&s, s.head(), "c780").expect("complete");
    assert_eq!(receipt["outcomes"]["RQ1"]["outcome"], "not_answered", "a processing failure, not an unknown of the sources: {receipt}");
    assert_eq!(receipt["not_answered"], json!(["RQ1"]));
    assert_eq!(receipt["unknown_outcomes"], json!([]));
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    let mut same = dispatcher("What do the reports establish about the topic?");
    same.recover(&s);
    assert_eq!(same.acquire(&s, "sum", true, 4000)["status"], "COMPLETE", "the give-up survives a restart of the same question set");
    let mut edited = dispatcher("Which conclusions about the topic were later qualified?");
    edited.recover(&s);
    assert_eq!(edited.acquire(&s, "sum", true, 4001)["kind"], "SUMMARIZE", "an edited question is summarized again");
}

#[test]
fn f07_a_verdict_refused_after_its_quote_was_stored_still_reports_the_stored_quote() {
    let (_wal, mut s) = fresh("ack", &TWO);
    let (_, a) = seed(&mut s, "author-a", "d1", "Topic A is reported.");
    let (o2, b) = seed(&mut s, "author-b", "d2", "Topic B is reported.");
    s.add_link("builder", &a, "supports", &b, &[o2]).unwrap();
    let mut d = dispatcher("What do the reports establish about the topic?");
    let t = d.acquire(&s, "verifier", true, 1);
    assert_eq!(t["kind"], "VERIFY_LINK", "{t}");
    let (id, p) = task(&t);
    let observe =
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "d1", "exact_quote": "Topic A was checked again later.", "terms": ["topic"]});
    let verdict =
        json!({"kind": "verdict", "link": t["key"].as_str().unwrap().trim_start_matches("verify:"), "verdict": "confirm", "based_on": ["@0000000000000000"]});
    let r = d.submit(&mut s, id, "verifier", &[observe, verdict], 2);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert!(r["accepted_locals"].get(format!("{p}o1")).is_some(), "the stored quote is reported with the refusal: {r}");
}

#[test]
fn f08_a_card_always_shows_what_its_new_records_rest_on() {
    let (_wal, mut s) = fresh("neighbours", &[("d1", "Evidence alpha is reported.\n")]);
    let scope = Scope { docs: vec!["d1".into()], ..Default::default() };
    let mut lines = vec![json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": "Evidence alpha is reported.", "terms": ["alpha"]})];
    lines.extend((0..9).map(|i| json!({"kind": "claim", "local_id": format!("c{i}"), "text": format!("Alpha claim {i}."), "subject": "alpha", "stance": "reported", "based_on": ["o"]})));
    let first = s.submit_records("reader", "seed", &scope, &lines);
    assert!(first.error.is_none(), "{:?}", first.error);
    let observe = first.accepted[0];
    let mut b = Builder::new(BuilderConfig { max_records: 16, ..Default::default() });
    let card = b.next_card(&s).unwrap();
    let mut ops = vec![json!({"op": "propose_concept", "type": card.concept_types[0], "name": "alpha", "aliases": [], "basis": [observe.short()]})];
    ops.extend(card.records.iter().map(|r| json!({"op": "map_term", "record": r.id.short(), "term": "alpha", "concept": "alpha"})));
    assert_eq!(b.submit(&mut s, &card.card_id, &ops)["status"], "CARD_DONE");
    let later = s.submit_records(
        "reader",
        "later",
        &scope,
        &[json!({"kind": "claim", "local_id": "n", "text": "Alpha holds.", "subject": "alpha", "stance": "reported", "based_on": [observe.short()]})],
    );
    assert!(later.error.is_none(), "{:?}", later.error);
    let next = b.next_card(&s).unwrap();
    assert!(next.neighbors.iter().any(|r| r.id == observe), "the quote the new claim rests on is shown, not cut for newer neighbours");
    assert!(next.neighbors.len() <= BuilderConfig::default().max_neighbors);
}

#[test]
fn f11_a_question_investigated_without_a_record_stays_open_for_the_summary() {
    let (_wal, mut s) = fresh("open-question", &TWO);
    seed(&mut s, "reader", "d1", "Topic A is reported.");
    let q = json!({"kind": "question", "local_id": "q", "text": "is topic B still reported?", "about": ["topic"], "needed": "d2"});
    assert!(s.submit_records("reader", "seed-q", &Scope { docs: vec!["d1".into()], ..Default::default() }, &[q]).error.is_none());
    let mut d = dispatcher("What do the reports establish about the topic?");
    let t = past_reading(&mut d, &mut s, "inv");
    assert_eq!(t["kind"], "INVESTIGATE", "{t}");
    assert_eq!(d.submit(&mut s, task(&t).0, "inv", &[], 10)["status"], "COMMITTED");
    let summary = d.acquire(&s, "sum", true, 11);
    assert_eq!(summary["kind"], "SUMMARIZE", "{summary}");
    let prompt = summary["prompt"].as_str().unwrap();
    let open = prompt.split("OPEN QUESTIONS (not settled").nth(1).unwrap();
    assert!(open.contains("is topic B still reported? (needed: d2)"), "an empty investigation settles nothing: {open}");
}
