//! Additional normative Dispatcher regressions for the 4fc99e3 repair.
//! Fixtures use the real durable store and deterministic answers; no models.

use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus, RecordId, RecordKind, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

const FIRST: &str = "# First\nTopic A is reported.\n";
const SECOND: &str = "# Second\nTopic B is reported.\n";

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str, docs: &[(&str, &str)]) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_dispatch_fix_review_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let owned: Vec<(String, Vec<u8>)> = docs.iter().map(|(id, text)| (id.to_string(), text.as_bytes().to_vec())).collect();
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &owned, "dispatcher-fix-review", sha256(b"toy-manifest")).unwrap();
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

fn seed_claim(state: &mut AuditState, actor: &str, directive: &str, doc: &str, quote: &str) -> RecordId {
    let report = state.submit_records(
        actor,
        directive,
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[
            json!({"kind":"observe", "local_id":"o", "doc_id":doc, "exact_quote":quote, "terms":["topic"]}),
            json!({"kind":"claim", "local_id":"c", "text":quote, "subject":"topic", "stance":"reported", "based_on":["o"]}),
        ],
    );
    assert!(report.error.is_none(), "seed failed: {:?}", report.error);
    assert_eq!(report.accepted.len(), 2);
    report.accepted[1]
}

#[test]
fn a_summary_cannot_close_another_research_question() {
    let (_wal, mut state) = fresh("rq-binding", &[("d1", FIRST)]);
    let mut dispatch = dispatcher();
    let extend = dispatch.acquire(&state, "worker", true, 1);
    assert_eq!(extend["kind"], "EXTEND", "{extend}");
    let covered = dispatch.submit(&mut state, extend["task_id"].as_str().unwrap(), "worker", &[], 2);
    assert_eq!(covered["status"], "COMMITTED", "{covered}");
    assert_eq!(state.head(), 0, "empty EXTEND is a checkpoint and appends no records");

    let summary = dispatch.acquire(&state, "summarizer", true, 3);
    assert_eq!(summary["kind"], "SUMMARIZE", "{summary}");
    assert_eq!(summary["key"], "rq:RQ1", "{summary}");
    let prefix = summary["local_id_prefix"].as_str().unwrap();
    let result = dispatch.submit(
        &mut state,
        summary["task_id"].as_str().unwrap(),
        "summarizer",
        &[json!({"kind":"done", "local_id":format!("{prefix}d1"), "rq_id":"RQ2", "directive_id":summary["task_id"],
                  "outcome":"unknown", "answer_ids":[]})],
        4,
    );
    assert_eq!(result["status"], "REPAIR_REQUIRED", "a Done for RQ2 must not close the leased RQ1: {result}");
    assert_ne!(dispatch.completion(&state, true)["complete"], true, "RQ1 has no matching Done");
    assert!(dispatch.terminal_receipt(&state, state.head(), "dispatcher-fix-review").is_none(), "no terminal receipt before RQ1 has its own outcome");
}

#[test]
fn a_verdict_repair_can_name_its_earlier_accepted_observation_by_local_id() {
    let (_wal, mut state) = fresh("prior-local", &[("d1", FIRST), ("d2", SECOND)]);
    let first = seed_claim(&mut state, "author-a", "seed-a", "d1", "Topic A is reported.");
    let second = seed_claim(&mut state, "author-b", "seed-b", "d2", "Topic B is reported.");
    let link = state.add_link("builder", &first, "supports", &second, &[first]).unwrap().id;
    let mut dispatch = dispatcher();
    let task = dispatch.acquire(&state, "verifier", true, 1);
    assert_eq!(task["kind"], "VERIFY_LINK", "{task}");
    let prefix = task["local_id_prefix"].as_str().unwrap();
    let local_observe = format!("{prefix}o1");
    let verdict: Value = json!({"kind":"verdict", "link":link.short(), "verdict":"confirm", "based_on":[local_observe]});
    let failed = dispatch.submit(
        &mut state,
        task["task_id"].as_str().unwrap(),
        "verifier",
        &[
            json!({"kind":"observe", "local_id":local_observe, "doc_id":"d1", "exact_quote":"Topic A is reported.", "terms":["topic"]}),
            json!({"kind":"claim", "local_id":format!("{prefix}c1"), "text":"x".repeat(241), "subject":"topic", "stance":"reported", "based_on":[local_observe]}),
            verdict.clone(),
        ],
        2,
    );
    assert_eq!(failed["status"], "REPAIR_REQUIRED", "the overlong claim must fail after accepting the observation: {failed}");
    assert_eq!(failed["failed_index"], 1, "{failed}");
    assert_eq!(failed["error"]["field"], "text", "{failed}");
    assert_eq!(failed["accepted"].as_array().unwrap().len(), 1, "{failed}");
    assert!(state.records_since(0).iter().any(|r| r.kind == RecordKind::Observe && r.author == "verifier" && r.directive == task["task_id"].as_str().unwrap()));
    assert_eq!(state.link(&link).unwrap().status, LinkStatus::Proposed);

    let repaired = dispatch.submit(&mut state, task["task_id"].as_str().unwrap(), "verifier", &[verdict], 3);
    assert_eq!(repaired["status"], "COMMITTED", "accepted local ids must remain valid for the repair suffix: {repaired}");
    assert_eq!(state.link(&link).unwrap().status, LinkStatus::Accepted);
}
