//! Recovery review probes for pinned revision 20952368e60012254aa999dfd44dc43914659830.
//! These assertions describe the required behavior, not the defects observed in that revision.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempWal(PathBuf);

impl TempWal {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!(
            "sbgk_builder_recovery_2095236_{}_{}_{}.jsonl",
            std::process::id(),
            nonce,
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn create(&self, run: &str, text: &str) -> AuditState {
        let docs = vec![("report".to_string(), text.as_bytes().to_vec())];
        AuditState::create(&self.0, &AuditOntology::base(), &docs, run, sha256(text.as_bytes())).unwrap()
    }
}

impl Drop for TempWal {
    fn drop(&mut self) {
        // States are declared after TempWal and dropped first, including on assertion failure.
        let _ = std::fs::remove_file(&self.0);
    }
}

fn seed(state: &mut AuditState, quote: &str) {
    let scope = Scope { docs: vec!["report".into()], ..Default::default() };
    let result = state.submit_records_id(
        "seed",
        "worker",
        "T1",
        &scope,
        &[json!({"kind":"observe","local_id":"o1","doc_id":"report","exact_quote":quote,"terms":["alpha"]})],
    );
    assert!(result.error.is_none(), "seed failed: {:?}", result.error);
    assert_eq!(result.accepted.len(), 1);
}

fn proposal(name: &str, observation: &str) -> Value {
    json!({"op":"propose_concept","type":"Component","name":name,"aliases":[],"basis":[observation]})
}

fn invalid_suffix(observation: &str) -> Value {
    json!({"op":"map_term","record":observation,"term":"not-issued-term","concept":"new component"})
}

#[test]
fn a_recovered_builder_accepts_only_the_repaired_suffix_using_its_prior_proposed_name() {
    let wal = TempWal::new();
    let mut state = wal.create("builder-prefix-name-recovery", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&state).unwrap();
    let observation = card.records[0].id.short();
    let first = builder.submit(&mut state, &card.card_id, &[proposal("new component", &observation), invalid_suffix(&observation)]);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["committed_ops"], 1, "fixture must commit the proposal prefix: {first}");
    assert_eq!(state.candidates("new component", 1).len(), 1);
    assert!(state.candidates("alpha", 1).is_empty(), "the prior concept name is not an alpha candidate");
    drop(state);

    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = Builder::new(BuilderConfig::default());
    recovered.recover(&state);
    let reopened_card = recovered.next_card(&state).unwrap();
    assert_eq!(reopened_card.card_id, card.card_id, "the unfinished card retains its identity");
    let repaired_suffix = json!({"op":"map_term","record":observation,"term":"alpha","concept":"new component"});
    let result = recovered.submit(&mut state, &reopened_card.card_id, &[repaired_suffix]);
    assert_eq!(result["status"], "CARD_DONE", "a restart must preserve accepted-prefix names for suffix-only repair: {result}");
    assert_eq!(state.concepts_of(&reopened_card.records[0].id).len(), 1);
    assert_eq!(state.candidates("new component", 1).len(), 1, "the accepted prefix is not resubmitted");
    assert!(recovered.caught_up(&state));
}

#[test]
fn reopening_an_unfinished_card_does_not_reset_its_committed_operation_budget() {
    let wal = TempWal::new();
    let mut state = wal.create("builder-operation-budget-recovery", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let cfg = BuilderConfig { max_ops: 2, ..BuilderConfig::default() };
    let mut builder = Builder::new(cfg);
    let card = builder.next_card(&state).unwrap();
    let observation = card.records[0].id.short();
    let first = builder.submit(&mut state, &card.card_id, &[proposal("component a", &observation), invalid_suffix(&observation)]);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["committed_ops"], 1, "fixture must spend one of the two card slots: {first}");
    assert_eq!(state.candidates("component a", 1).len(), 1);
    drop(state);

    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = Builder::new(cfg);
    recovered.recover(&state);
    let reopened_card = recovered.next_card(&state).unwrap();
    assert_eq!(reopened_card.card_id, card.card_id);
    assert_eq!(reopened_card.max_ops, 2);
    let result = recovered.submit(&mut state, &reopened_card.card_id, &[proposal("component b", &observation), proposal("component c", &observation)]);
    let accepted = ["component a", "component b", "component c"].iter().map(|name| state.candidates(name, 1).len()).sum::<usize>();
    assert!(
        accepted <= reopened_card.max_ops && result["status"] != "CARD_DONE",
        "the recovered card cannot acknowledge three committed operations under a two-operation limit: accepted={accepted}, result={result}"
    );
}

#[test]
fn an_exact_retry_of_a_refused_whole_batch_replays_without_changing_wal_or_counters() {
    let wal = TempWal::new();
    let mut state = wal.create("builder-failed-batch-exact-retry", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let cfg = BuilderConfig { max_ops: 2, ..BuilderConfig::default() };
    let mut builder = Builder::new(cfg);
    let card = builder.next_card(&state).unwrap();
    let observation = card.records[0].id.short();
    let original_batch = [proposal("new component", &observation), invalid_suffix(&observation)];
    let first = builder.submit(&mut state, &card.card_id, &original_batch);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["committed_ops"], 1, "fixture must preserve a nonempty accepted prefix: {first}");
    let committed = (state.root(), state.wal_head(), state.transaction_sequence());
    let counters = (builder.stats.ops_accepted, builder.stats.ops_refused, builder.stats.concepts_proposed);
    let retry = builder.submit(&mut state, &card.card_id, &original_batch);
    assert_eq!((state.root(), state.wal_head(), state.transaction_sequence()), committed, "an exact transport retry must not append");
    assert_eq!(
        (builder.stats.ops_accepted, builder.stats.ops_refused, builder.stats.concepts_proposed),
        counters,
        "an exact transport retry must not count the accepted prefix or refusal twice"
    );
    assert_eq!(retry["status"], "REPAIR_REQUIRED", "the exact failed batch must replay its prior result: first={first}; retry={retry}");
    assert_eq!(retry["committed_ops"], first["committed_ops"]);
    assert_eq!(retry["failed_index"], first["failed_index"]);
    assert_eq!(retry["accepted"], first["accepted"]);
    assert_eq!(state.candidates("new component", 1).len(), 1);
}
