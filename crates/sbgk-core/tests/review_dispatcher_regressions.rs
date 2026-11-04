//! Normative regressions for the Dispatcher integration at 256da9b.
//! These tests use the real durable store and deterministic agent answers.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkId, LinkStatus, RecordId, RecordKind, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

const FIRST: &str = "# First\nTopic A is reported.\n";
const SECOND: &str = "# Second\nTopic B is reported.\n";
const OUTSIDE: &str = "# Other\nUnrelated matter is reported.\n";

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str, docs: &[(&str, &str)]) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_dispatch_review_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let owned: Vec<(String, Vec<u8>)> = docs.iter().map(|(id, text)| (id.to_string(), text.as_bytes().to_vec())).collect();
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &owned, "dispatcher-review", sha256(b"toy-manifest")).unwrap();
    (wal, state)
}

fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig { section_bytes: 400, ..Default::default() },
        vec![ResearchQuestion {
            id: "RQ1".into(),
            text: "What do the reports establish about the topic?".into(),
            about: vec!["topic".into()],
            ..Default::default()
        }],
    )
}

fn extend_answer(task: &Value) -> Vec<Value> {
    let prefix = task["local_id_prefix"].as_str().unwrap();
    let doc = task["key"].as_str().unwrap().strip_prefix("doc:").unwrap().split('#').next().unwrap();
    let quote = match doc {
        "d1" => "Topic A is reported.",
        "d2" => "Topic B is reported.",
        _ => panic!("unexpected test document: {doc}"),
    };
    vec![
        json!({"kind":"observe", "local_id":format!("{prefix}o1"), "doc_id":doc, "exact_quote":quote, "terms":["topic"]}),
        json!({"kind":"claim", "local_id":format!("{prefix}c1"), "text":quote, "subject":"topic", "stance":"reported", "based_on":[format!("{prefix}o1")]}),
    ]
}

fn seed_claim(state: &mut AuditState, actor: &str, directive: &str, doc: &str, quote: &str, term: &str) -> (RecordId, RecordId) {
    let report = state.submit_records(
        actor,
        directive,
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[
            json!({"kind":"observe", "local_id":"o", "doc_id":doc, "exact_quote":quote, "terms":[term]}),
            json!({"kind":"claim", "local_id":"c", "text":quote, "subject":term, "stance":"reported", "based_on":["o"]}),
        ],
    );
    assert!(report.error.is_none(), "seed failed: {:?}", report.error);
    assert_eq!(report.accepted.len(), 2);
    (report.accepted[0], report.accepted[1])
}

struct LinkFixture {
    state: AuditState,
    dispatcher: Dispatcher,
    _wal: Wal,
    first_observe: RecordId,
    first_claim: RecordId,
    outside_observe: RecordId,
    link: LinkId,
}

fn link_fixture(tag: &str) -> LinkFixture {
    let (wal, mut state) = fresh(tag, &[("d1", FIRST), ("d2", SECOND), ("outside", OUTSIDE)]);
    let (first_observe, first_claim) = seed_claim(&mut state, "author-a", "seed-a", "d1", "Topic A is reported.", "topic");
    let (_, second_claim) = seed_claim(&mut state, "author-b", "seed-b", "d2", "Topic B is reported.", "topic");
    let (outside_observe, _) = seed_claim(&mut state, "other-author", "seed-other", "outside", "Unrelated matter is reported.", "unrelated");
    let link = state.add_link("builder", &first_claim, "supports", &second_claim, &[first_claim]).unwrap();
    assert_eq!(link.status, LinkStatus::Proposed);
    LinkFixture { state, dispatcher: dispatcher(), _wal: wal, first_observe, first_claim, outside_observe, link: link.id }
}

#[test]
fn the_same_agent_can_complete_new_work_after_dispatcher_recovery() {
    let (wal, mut state) = fresh("recovery", &[("d1", FIRST), ("d2", SECOND)]);
    let mut dispatch = dispatcher();
    let first = dispatch.acquire(&state, "worker", true, 1);
    assert_eq!(first["kind"], "EXTEND", "{first}");
    let accepted = dispatch.submit(&mut state, first["task_id"].as_str().unwrap(), "worker", &extend_answer(&first), 2);
    assert_eq!(accepted["status"], "COMMITTED", "{accepted}");

    drop(state);
    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher();
    recovered.recover(&state);
    let second = recovered.acquire(&state, "worker", true, 3);
    assert_eq!(second["kind"], "EXTEND", "{second}");
    assert_ne!(second["key"], first["key"], "completed work must stay completed");
    let result = recovered.submit(&mut state, second["task_id"].as_str().unwrap(), "worker", &extend_answer(&second), 4);
    assert_eq!(result["status"], "COMMITTED", "new work must not collide with an earlier durable receipt; first={first}; second={second}; result={result}");
    assert_ne!(second["task_id"], first["task_id"], "task identities must not be reused after recovery");
}

#[test]
fn a_verdict_cannot_use_an_unissued_foreign_observation() {
    let mut fixture = link_fixture("issued");
    let task = fixture.dispatcher.acquire(&fixture.state, "verifier", true, 1);
    assert_eq!(task["kind"], "VERIFY_LINK", "{task}");
    assert!(!task["prompt"].as_str().unwrap().contains(&fixture.outside_observe.short()), "the negative fixture must be outside the issued records");
    let result = fixture.dispatcher.submit(
        &mut fixture.state,
        task["task_id"].as_str().unwrap(),
        "verifier",
        &[json!({"kind":"verdict", "link":fixture.link.short(), "verdict":"confirm", "based_on":[fixture.outside_observe.short()]})],
        2,
    );
    assert_eq!(result["status"], "REPAIR_REQUIRED", "a globally valid record is not an issued capability: {result}");
    assert_eq!(fixture.state.link(&fixture.link).unwrap().status, LinkStatus::Proposed, "an unissued basis must not change the link");
}

#[test]
fn a_failed_verdict_can_be_repaired_under_the_same_lease() {
    let mut fixture = link_fixture("verdict-repair");
    let task = fixture.dispatcher.acquire(&fixture.state, "verifier", true, 1);
    assert_eq!(task["kind"], "VERIFY_LINK", "{task}");
    assert!(task["prompt"].as_str().unwrap().contains(&fixture.first_observe.short()));
    let hypothesis = format!("{}h1", task["local_id_prefix"].as_str().unwrap());
    let failed = fixture.dispatcher.submit(
        &mut fixture.state,
        task["task_id"].as_str().unwrap(),
        "verifier",
        &[
            json!({"kind":"hypothesis", "local_id":hypothesis, "text":"The topic may have an additional cause.", "falsifier":"A direct source excludes that cause.", "based_on":[fixture.first_observe.short()]}),
            json!({"kind":"verdict", "link":fixture.link.short(), "verdict":"confirm", "based_on":[hypothesis]}),
        ],
        2,
    );
    assert_eq!(failed["status"], "REPAIR_REQUIRED", "hypotheses cannot establish a verdict: {failed}");
    assert_eq!(fixture.state.link(&fixture.link).unwrap().status, LinkStatus::Proposed);
    assert!(
        fixture.state.records_since(0).iter().any(|record| record.kind == RecordKind::Hypothesis && record.author == "verifier"),
        "the ordinary record prefix must have been accepted before the verdict failed"
    );

    let repaired = fixture.dispatcher.submit(
        &mut fixture.state,
        task["task_id"].as_str().unwrap(),
        "verifier",
        &[json!({"kind":"verdict", "link":fixture.link.short(), "verdict":"confirm", "based_on":[fixture.first_claim.short()]})],
        3,
    );
    assert_eq!(repaired["status"], "COMMITTED", "a previous failed final transaction must not poison the repaired verdict identity: {repaired}");
    assert_eq!(fixture.state.link(&fixture.link).unwrap().status, LinkStatus::Accepted);
}

fn catch_up(builder: &mut Builder, state: &mut AuditState) {
    while let Some(card) = builder.next_card(state) {
        let result = builder.submit(state, &card.card_id, &[]);
        assert_eq!(result["status"], "CARD_DONE", "{result}");
    }
    assert!(builder.caught_up(state));
}

#[test]
fn revoked_answer_evidence_prevents_completion_and_a_terminal_receipt() {
    let (_wal, mut state) = fresh("completion", &[("d1", FIRST)]);
    let (mut dispatch, mut builder) = (dispatcher(), Builder::new(BuilderConfig::default()));
    let extend = dispatch.acquire(&state, "worker", builder.caught_up(&state), 1);
    assert_eq!(extend["kind"], "EXTEND", "{extend}");
    let result = dispatch.submit(&mut state, extend["task_id"].as_str().unwrap(), "worker", &extend_answer(&extend), 2);
    assert_eq!(result["status"], "COMMITTED", "{result}");
    let observation = state.records_since(0).into_iter().find(|record| record.kind == RecordKind::Observe).unwrap().id;
    catch_up(&mut builder, &mut state);

    let summary = dispatch.acquire(&state, "summarizer", builder.caught_up(&state), 3);
    assert_eq!(summary["kind"], "SUMMARIZE", "{summary}");
    let prefix = summary["local_id_prefix"].as_str().unwrap();
    let result = dispatch.submit(
        &mut state,
        summary["task_id"].as_str().unwrap(),
        "summarizer",
        &[
            json!({"kind":"claim", "local_id":format!("{prefix}c1"), "text":"The report establishes topic A.", "subject":"topic", "stance":"reported", "based_on":[observation.short()]}),
            json!({"kind":"done", "local_id":format!("{prefix}d1"), "rq_id":"RQ1", "directive_id":summary["task_id"], "outcome":"answered", "answer_ids":[format!("{prefix}c1")]}),
        ],
        4,
    );
    assert_eq!(result["status"], "COMMITTED", "{result}");
    catch_up(&mut builder, &mut state);
    let terminal = state.records_since(0).into_iter().find(|record| record.kind == RecordKind::Done).unwrap().id;
    assert!(state.is_grounded(&terminal));
    assert_eq!(dispatch.completion(&state, builder.caught_up(&state))["complete"], true);
    assert!(dispatch.terminal_receipt(&state, builder.cursor(), "dispatcher-review").is_some());

    state.revoke_observation("admin", &observation).unwrap();
    assert!(!state.is_grounded(&terminal), "the store must first detect the withdrawn answer proof");
    assert!(builder.caught_up(&state), "revocation changes proof validity without appending an ingest record");
    let completion = dispatch.completion(&state, builder.caught_up(&state));
    let receipt = dispatch.terminal_receipt(&state, builder.cursor(), "dispatcher-review");
    assert!(
        completion["complete"] != true && receipt.is_none(),
        "a stale answered marker must not outlive its evidence; completion={completion}; receipt={receipt:?}"
    );
}
