//! Offline review probes for pinned revision 256da9be25b6de7dedff9c9b5a22e9ee061f45a1.
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
        Self(std::env::temp_dir().join(format!("sbgk_builder_review_{}_{}_{}.jsonl", std::process::id(), nonce, TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed))))
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

#[test]
fn a_completed_card_retry_returns_its_receipt_before_unknown_card_even_after_reopen() {
    let wal = TempWal::new();
    let mut state = wal.create("retry-run", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&state).unwrap();
    let completed = builder.submit(&mut state, &card.card_id, &[]);
    assert_eq!(completed["status"], "CARD_DONE", "{completed}");
    let committed = (state.root(), state.wal_head(), state.transaction_sequence());
    let direct_retry = builder.submit(&mut state, &card.card_id, &[]);
    assert_eq!((state.root(), state.wal_head(), state.transaction_sequence()), committed);
    drop(state);

    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = Builder::new(BuilderConfig::default());
    recovered.recover(&state);
    let replay_retry = recovered.submit(&mut state, &card.card_id, &[]);
    assert_eq!((state.root(), state.wal_head(), state.transaction_sequence()), committed);
    assert_eq!(
        (direct_retry["status"].as_str(), replay_retry["status"].as_str()),
        (Some("CARD_DONE"), Some("CARD_DONE")),
        "a lost CARD_DONE must be recoverable: direct={direct_retry}; reopened={replay_retry}"
    );
}

#[test]
fn a_store_rejection_does_not_poison_the_submission_id_of_the_repaired_suffix() {
    let wal = TempWal::new();
    let mut state = wal.create("repair-run", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&state).unwrap();
    let observation = card.records[0].id.short();
    // The adapter accepts this shape, but the real ontology rejects the alias's UTF-8 byte bound.
    let invalid: Value = json!({"op":"propose_concept","type":"Component","name":"alpha concept","aliases":["x".repeat(121)],"basis":[observation]});
    let failed = builder.submit(&mut state, &card.card_id, &[invalid]);
    assert_eq!(failed["status"], "REPAIR_REQUIRED", "{failed}");
    assert_eq!(failed["committed_ops"], 0, "{failed}");
    assert_eq!(failed["error"]["field"], "aliases", "the rejection must come from the real store: {failed}");

    let repaired = json!({"op":"propose_concept","type":"Component","name":"alpha concept","aliases":[],"basis":[card.records[0].id.short()]});
    let result = builder.submit(&mut state, &card.card_id, &[repaired]);
    assert_eq!(result["status"], "CARD_DONE", "a repaired operation must not collide with the prior refusal receipt: {result}");
    assert_eq!(state.candidates("alpha concept", 1).len(), 1);
    assert!(builder.caught_up(&state));
}

#[test]
fn unrelated_runs_have_distinct_card_identity_and_refuse_a_foreign_empty_ack() {
    let first_wal = TempWal::new();
    let second_wal = TempWal::new();
    let mut first = first_wal.create("run-alpha", "Evidence alpha.");
    let mut second = second_wal.create("run-beta", "Evidence beta.");
    seed(&mut first, "Evidence alpha.");
    seed(&mut second, "Evidence beta.");
    let mut builder_a = Builder::new(BuilderConfig::default());
    let mut builder_b = Builder::new(BuilderConfig::default());
    let card_a = builder_a.next_card(&first).unwrap();
    let card_b = builder_b.next_card(&second).unwrap();
    let before = (second.root(), second.wal_head(), second.transaction_sequence());
    let foreign = builder_b.submit(&mut second, &card_a.card_id, &[]);
    assert!(
        card_a.card_id != card_b.card_id && foreign["status"] != "CARD_DONE",
        "different runs/corpus cuts cannot share an acknowledgement: A={}, B={}, result={foreign}",
        card_a.card_id,
        card_b.card_id
    );
    assert_eq!((second.root(), second.wal_head(), second.transaction_sequence()), before);
    assert!(!builder_b.caught_up(&second));
}
