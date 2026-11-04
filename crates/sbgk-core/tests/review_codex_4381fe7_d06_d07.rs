//! Independent 4381fe7 review probes. These are offline dispatcher/store tests,
//! with a disposable WAL and scripted storage-fault replies; no pilot or model.
//! A failed test remains an expected regression finding, never a product edit.

use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, ConceptId, ConceptView, LinkId, LinkStatus, LinkView, RecordId, RecordView, Scope, SubmitReport};
use sbgk_core::error::{Code, KernelError};
use sbgk_core::hash::{sha256, Hash};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const DOC: &str = "# Topic\nTopic A is reported.\nTopic A was checked again later.\nTopic A holds in the later report.\n";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_438_review_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), DOC.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "438-review", sha256(b"438-fixture")).unwrap();
    (wal, state)
}

fn dispatcher(with_question: bool) -> Dispatcher {
    let questions = if with_question {
        vec![ResearchQuestion {
            id: "RQ1".into(),
            text: "What do the reports establish about topic A?".into(),
            about: vec!["topic".into()],
            ..Default::default()
        }]
    } else {
        Vec::new()
    };
    Dispatcher::new(DispatchConfig { section_bytes: 4000, ttl_ms: 100, ..Default::default() }, questions)
}

#[derive(Clone, Copy)]
enum Fault {
    Error,
    RefusedReply,
}

/// All real operations reach AuditState; one unresolved-checkpoint operation
/// receives the explicitly selected error/reply before any WAL operation.
// The injection is at the documented AuditStore boundary. It does not simulate
// corruption or claim that a real disk failure was performed.
struct FaultStore {
    state: AuditState,
    next_fault: Option<Fault>,
    unresolved_calls: usize,
}

impl FaultStore {
    fn new(state: AuditState, fault: Fault) -> Self {
        Self { state, next_fault: Some(fault), unresolved_calls: 0 }
    }
}

impl AuditStore for FaultStore {
    fn docs(&self) -> Vec<String> {
        AuditStore::docs(&self.state)
    }
    fn doc_text(&self, id: &str) -> Option<String> {
        AuditStore::doc_text(&self.state, id)
    }
    fn submit_records(&mut self, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        AuditStore::submit_records(&mut self.state, agent, directive, scope, lines)
    }
    fn submit_records_id(&mut self, id: &str, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        AuditStore::submit_records_id(&mut self.state, id, agent, directive, scope, lines)
    }
    fn submit_scoped_records_id(&mut self, id: &str, agent: &str, directive: &str, scope: &Scope, issued: &[RecordId], lines: &[Value]) -> SubmitReport {
        AuditStore::submit_scoped_records_id(&mut self.state, id, agent, directive, scope, issued, lines)
    }
    fn records_since(&self, cursor: u64) -> Vec<RecordView> {
        AuditStore::records_since(&self.state, cursor)
    }
    fn record(&self, id: &RecordId) -> Option<RecordView> {
        AuditStore::record(&self.state, id)
    }
    fn is_grounded(&self, id: &RecordId) -> bool {
        AuditStore::is_grounded(&self.state, id)
    }
    fn is_answer_support(&self, id: &RecordId) -> bool {
        AuditStore::is_answer_support(&self.state, id)
    }
    fn head(&self) -> u64 {
        AuditStore::head(&self.state)
    }
    fn ontology_version(&self) -> (u64, Hash) {
        AuditStore::ontology_version(&self.state)
    }
    fn concept_types(&self) -> Vec<String> {
        AuditStore::concept_types(&self.state)
    }
    fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView> {
        AuditStore::candidates(&self.state, term, limit)
    }
    fn concept(&self, id: &ConceptId) -> Option<ConceptView> {
        AuditStore::concept(&self.state, id)
    }
    fn propose_concept(&mut self, by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> Result<ConceptView, KernelError> {
        AuditStore::propose_concept(&mut self.state, by, ty, name, aliases, basis)
    }
    fn map_term(&mut self, by: &str, record: &RecordId, term: &str, concept: &ConceptId) -> Result<(), KernelError> {
        AuditStore::map_term(&mut self.state, by, record, term, concept)
    }
    fn concepts_of(&self, record: &RecordId) -> Vec<ConceptId> {
        AuditStore::concepts_of(&self.state, record)
    }
    fn records_of(&self, concept: &ConceptId) -> Vec<RecordId> {
        AuditStore::records_of(&self.state, concept)
    }
    fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> Result<LinkView, KernelError> {
        AuditStore::add_link(&mut self.state, by, from, rel, to, basis)
    }
    fn set_link_status(&mut self, id: &LinkId, status: LinkStatus, by: &str, basis: &[RecordId]) -> Result<(), KernelError> {
        AuditStore::set_link_status(&mut self.state, id, status, by, basis)
    }
    fn link(&self, id: &LinkId) -> Option<LinkView> {
        AuditStore::link(&self.state, id)
    }
    fn links(&self) -> Vec<LinkView> {
        AuditStore::links(&self.state)
    }
    fn links_of(&self, record: &RecordId) -> Vec<LinkView> {
        AuditStore::links_of(&self.state, record)
    }
    fn link_usable(&self, id: &LinkId) -> bool {
        AuditStore::link_usable(&self.state, id)
    }
    fn usable_links(&self) -> Option<BTreeSet<LinkId>> {
        AuditStore::usable_links(&self.state)
    }
    fn concepts(&self) -> Vec<ConceptView> {
        AuditStore::concepts(&self.state)
    }
    fn submit_operations_id(&mut self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Result<Value, KernelError> {
        if id.ends_with("#unresolved") {
            self.unresolved_calls += 1;
            if let Some(fault) = self.next_fault.take() {
                return match fault {
                    Fault::Error => Err(KernelError::new(Code::BadField, "injected one-shot unresolved checkpoint error")),
                    Fault::RefusedReply => Ok(json!({
                        "checkpointed": false,
                        "error": {"code": "INJECTED_CHECKPOINT_REFUSAL", "message": "injected one-shot noncheckpointed response"}
                    })),
                };
            }
        }
        AuditStore::submit_operations_id(&mut self.state, id, actor, operations, checkpoint)
    }
    fn checkpoint(&self, key: &str) -> Option<Value> {
        AuditStore::checkpoint(&self.state, key)
    }
    fn support_map(&self) -> Option<BTreeMap<RecordId, (bool, bool)>> {
        AuditStore::support_map(&self.state)
    }
    fn run_namespace(&self) -> Hash {
        AuditStore::run_namespace(&self.state)
    }
    fn root(&self) -> Hash {
        AuditStore::root(&self.state)
    }
}

fn fail_release_three<S: AuditStore>(dispatch: &mut Dispatcher, store: &mut S) -> (String, Value) {
    let mut key = String::new();
    let mut last = Value::Null;
    for now in 1..=3 {
        let task = dispatch.acquire(store, "worker", true, now);
        assert_eq!(task["kind"], "EXTEND", "fixture: attempt {now}: {task}");
        let next_key = task["key"].as_str().unwrap();
        if key.is_empty() {
            key = next_key.to_string();
        } else {
            assert_eq!(next_key, key, "fixture: every failed attempt belongs to the same section");
        }
        let invalid = json!({"kind": "done", "local_id": "bad", "rq_id": "RQ9", "directive_id": task["task_id"], "outcome": "unknown", "answer_ids": []});
        assert_eq!(
            dispatch.submit(store, task["task_id"].as_str().unwrap(), "worker", &[invalid], now)["status"],
            "REPAIR_REQUIRED",
            "fixture: an invalid done line marks the EXTEND lease failed before release"
        );
        last = dispatch.release_durable(store, task["task_id"].as_str().unwrap(), "worker");
        assert_eq!(last["status"], "RELEASED", "fixture: attempt {now}: {last}");
        assert_eq!(last["unresolved"], now == 3, "fixture: threshold is exactly three: {last}");
    }
    (format!("task:{key}"), last)
}

#[test]
fn d06_direct_failed_release_keeps_a_failed_checkpoint_queued_for_retry_and_recovery() {
    let (wal, state) = fresh("release-error");
    let mut store = FaultStore::new(state, Fault::Error);
    let mut dispatch = dispatcher(false);
    let (key, last) = fail_release_three(&mut dispatch, &mut store);
    assert_eq!(store.unresolved_calls, 1, "fixture: the only injected error was reached");
    assert_eq!(last["durable"], false, "fixture: caller is told persistence failed");
    assert!(last["error"].is_object(), "fixture: original error is visible");
    assert!(store.checkpoint(&key).is_none(), "fixture: no checkpoint was written by the fault");
    assert_eq!(dispatch.completion(&store, true)["unresolved"].as_array().unwrap().len(), 1);
    assert!(dispatch.persist_unresolved(&mut store).is_empty(), "the store is healthy after its one scripted error");
    // Target assertion: the direct-release path must retain the same retry as
    // the expiration path, rather than forgetting its failed durable write.
    assert!(
        store.checkpoint(&key).is_some(),
        "D06: direct failed release forgot the failed checkpoint; persist_unresolved made {} write attempts in total",
        store.unresolved_calls
    );
    drop(store);
    let state = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher(false);
    recovered.recover(&state);
    assert_eq!(recovered.acquire(&state, "worker", true, 1)["status"], "COMPLETE");
    assert_eq!(recovered.completion(&state, true)["unresolved"].as_array().unwrap().len(), 1);
}

#[test]
fn d06_noncheckpointed_reply_is_not_acknowledged_as_a_durable_give_up() {
    let (_wal, state) = fresh("release-refused");
    let mut store = FaultStore::new(state, Fault::RefusedReply);
    let mut dispatch = dispatcher(false);
    let (key, last) = fail_release_three(&mut dispatch, &mut store);
    assert_eq!(store.unresolved_calls, 1, "fixture: noncheckpointed reply was reached");
    assert!(store.checkpoint(&key).is_none(), "fixture: the response did not persist a checkpoint");
    assert_eq!(dispatch.completion(&store, true)["unresolved"].as_array().unwrap().len(), 1);
    // Target assertion: Ok at the trait boundary is not a checkpoint ACK.
    assert!(last["durable"] == false && last["error"].is_object(), "D06: a checkpointed:false/error reply was converted into an ordinary RELEASED ACK: {last}");
}

#[test]
fn d06_expiry_retry_queue_survives_one_scripted_store_error_then_recovers() {
    let (wal, state) = fresh("expiry-error");
    let mut store = FaultStore::new(state, Fault::Error);
    let mut dispatch = dispatcher(false);
    let mut now = 1;
    let mut key = String::new();
    for round in 0..3 {
        let task = dispatch.acquire(&store, "worker", true, now);
        assert_eq!(task["kind"], "EXTEND", "fixture: round {round}: {task}");
        key = format!("task:{}", task["key"].as_str().unwrap());
        let invalid = json!({"kind": "done", "local_id": "bad", "rq_id": "RQ9", "directive_id": task["task_id"], "outcome": "unknown", "answer_ids": []});
        assert_eq!(
            dispatch.submit(&mut store, task["task_id"].as_str().unwrap(), "worker", &[invalid], now)["status"],
            "REPAIR_REQUIRED",
            "fixture: prevalidation marks the lease failed"
        );
        now += 1000;
    }
    assert_eq!(dispatch.acquire(&store, "worker", true, now)["status"], "COMPLETE", "third failed lease expires");
    assert!(store.checkpoint(&key).is_none());
    let errors = dispatch.persist_unresolved(&mut store);
    assert_eq!(errors.len(), 1, "scripted checkpoint error stays queued");
    assert_eq!(store.unresolved_calls, 1);
    assert!(dispatch.persist_unresolved(&mut store).is_empty());
    assert_eq!(store.unresolved_calls, 2);
    assert!(store.checkpoint(&key).is_some(), "healthy retry wrote the unresolved marker");
    drop(store);
    let state = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher(false);
    recovered.recover(&state);
    assert_eq!(recovered.acquire(&state, "worker", true, 1)["status"], "COMPLETE");
    assert_eq!(recovered.completion(&state, true)["unresolved"].as_array().unwrap().len(), 1);
}

#[test]
fn regular_failed_releases_keep_the_accepted_prefix_and_unresolved_marker_after_reopen() {
    let (wal, mut state) = fresh("accepted-prefix");
    let mut dispatch = dispatcher(false);
    let task = dispatch.acquire(&state, "worker", true, 1);
    assert_eq!(task["kind"], "EXTEND");
    let prefix = task["local_id_prefix"].as_str().unwrap();
    let observe = json!({"kind": "observe", "local_id": format!("{prefix}o"), "doc_id": "d1", "exact_quote": "Topic A is reported.", "terms": ["topic"]});
    let broken = json!({"kind": "claim", "local_id": format!("{prefix}bad"), "text": "unresolved suffix", "subject": "topic", "stance": "reported", "based_on": ["not-accepted"]});
    let partial = dispatch.submit(&mut state, task["task_id"].as_str().unwrap(), "worker", &[observe, broken], 2);
    assert_eq!(partial["status"], "REPAIR_REQUIRED", "fixture: {partial}");
    assert_eq!(partial["failed_index"], 1);
    assert_eq!(partial["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(state.head(), 1);
    let accepted = state.records_since(0)[0].clone();
    let release = dispatch.release_durable(&mut state, task["task_id"].as_str().unwrap(), "worker");
    assert_eq!(release["unresolved"], false);
    for now in 3..=4 {
        let task = dispatch.acquire(&state, "worker", true, now);
        assert_eq!(task["kind"], "EXTEND");
        let invalid = json!({"kind": "done", "local_id": "bad", "rq_id": "RQ9", "directive_id": task["task_id"], "outcome": "unknown", "answer_ids": []});
        assert_eq!(dispatch.submit(&mut state, task["task_id"].as_str().unwrap(), "worker", &[invalid], now)["status"], "REPAIR_REQUIRED");
        let release = dispatch.release_durable(&mut state, task["task_id"].as_str().unwrap(), "worker");
        assert_eq!(release["unresolved"], now == 4, "{release}");
    }
    assert_eq!(state.head(), 1, "abandoning unreadable suffixes does not drop or invent records");
    assert_eq!(state.records_since(0)[0], accepted);
    let checkpoint = format!("task:{}", task["key"].as_str().unwrap());
    assert_eq!(state.checkpoint(&checkpoint).unwrap()["context"]["unresolved"], true);
    let before = state.root();
    drop(state);
    let state = AuditState::open(&wal.0).unwrap();
    assert_eq!(state.root(), before);
    assert_eq!(state.records_since(0), vec![accepted]);
    let mut recovered = dispatcher(false);
    recovered.recover(&state);
    assert_eq!(recovered.acquire(&state, "worker", true, 1)["status"], "COMPLETE");
    assert_eq!(recovered.completion(&state, true)["unresolved"].as_array().unwrap().len(), 1);
}

fn seed_question(state: &mut AuditState, id: &str, text: &str) {
    let q = json!({"kind": "question", "local_id": id, "text": text, "about": ["topic"], "needed": "the later report"});
    assert!(state.submit_records("reader", &format!("seed-{id}"), &Scope { docs: vec!["d1".into()], ..Default::default() }, &[q]).error.is_none());
}

fn past_reading(dispatch: &mut Dispatcher, state: &mut AuditState, now: u64) -> Value {
    let mut task = dispatch.acquire(state, "investigator", true, now);
    if task["kind"] == "EXTEND" {
        assert_eq!(dispatch.submit(state, task["task_id"].as_str().unwrap(), "investigator", &[], now)["status"], "COMMITTED");
        task = dispatch.acquire(state, "investigator", true, now);
    }
    task
}

fn open_questions(dispatch: &mut Dispatcher, state: &AuditState, now: u64) -> String {
    let task = dispatch.acquire(state, "summarizer", true, now);
    assert_eq!(task["kind"], "SUMMARIZE", "fixture: {task}");
    let prompt = task["prompt"].as_str().unwrap();
    let open = prompt.split("OPEN QUESTIONS (not settled").nth(1).expect("fixture: open-questions block").to_string();
    assert_eq!(dispatch.release(task["task_id"].as_str().unwrap(), "summarizer")["status"], "RELEASED");
    open
}

#[test]
fn d07_observe_only_stays_open_and_grounded_claim_settlement_revalidates_after_recovery() {
    let (wal, mut state) = fresh("question-recovery");
    seed_question(&mut state, "q1", "Question with an observation alone?");
    let mut dispatch = dispatcher(true);
    let task = past_reading(&mut dispatch, &mut state, 1);
    assert_eq!(task["kind"], "INVESTIGATE");
    let p = task["local_id_prefix"].as_str().unwrap();
    let observe = json!({"kind": "observe", "local_id": format!("{p}o"), "doc_id": "d1", "exact_quote": "Topic A is reported.", "terms": ["topic"]});
    assert_eq!(dispatch.submit(&mut state, task["task_id"].as_str().unwrap(), "investigator", &[observe], 2)["status"], "COMMITTED");
    assert!(open_questions(&mut dispatch, &state, 3).contains("Question with an observation alone?"));

    seed_question(&mut state, "q2", "Question whose accepted claim loses its source?");
    let task = dispatch.acquire(&state, "investigator", true, 4);
    assert_eq!(task["kind"], "INVESTIGATE");
    let p = task["local_id_prefix"].as_str().unwrap();
    let observe =
        json!({"kind": "observe", "local_id": format!("{p}o"), "doc_id": "d1", "exact_quote": "Topic A holds in the later report.", "terms": ["topic"]});
    let claim = json!({"kind": "claim", "local_id": format!("{p}c"), "text": "Topic A holds later.", "subject": "topic", "stance": "confirmed", "based_on": [format!("{p}o")]});
    let accepted = dispatch.submit(&mut state, task["task_id"].as_str().unwrap(), "investigator", &[observe, claim], 5);
    assert_eq!(accepted["status"], "COMMITTED", "fixture: {accepted}");
    assert_eq!(accepted["accepted"].as_array().unwrap().len(), 2);
    let quote = state.records_since(0).iter().find(|r| r.quote.as_deref() == Some("Topic A holds in the later report.")).unwrap().id;
    assert!(!open_questions(&mut dispatch, &state, 6).contains("Question whose accepted claim loses its source?"));
    drop(state);
    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher(true);
    recovered.recover(&state);
    assert!(!open_questions(&mut recovered, &state, 7).contains("Question whose accepted claim loses its source?"));
    state.revoke_observation("owner", &quote).unwrap();
    let open = open_questions(&mut recovered, &state, 8);
    assert!(open.contains("Question whose accepted claim loses its source?"), "a source lost after recovery reopens the question: {open}");
    assert!(open.contains("Question with an observation alone?"), "observation-only did not settle it after recovery either");
}
