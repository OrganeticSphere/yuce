//! Follow-up review probes for pinned revision 4fc99e30e8749a6d820e69d0602500650715cb02.
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
            "sbgk_builder_followup_{}_{}_{}.jsonl",
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

#[test]
fn identical_records_in_distinct_runs_do_not_share_a_card_or_foreign_ack() {
    let first_wal = TempWal::new();
    let second_wal = TempWal::new();
    let mut first = first_wal.create("same-corpus-run-alpha", "Evidence alpha.");
    let mut second = second_wal.create("same-corpus-run-beta", "Evidence alpha.");
    seed(&mut first, "Evidence alpha.");
    seed(&mut second, "Evidence alpha.");
    let mut builder_a = Builder::new(BuilderConfig::default());
    let mut builder_b = Builder::new(BuilderConfig::default());
    let card_a = builder_a.next_card(&first).unwrap();
    let card_b = builder_b.next_card(&second).unwrap();
    assert_eq!(card_a.records[0].id, card_b.records[0].id, "fixture must isolate the run namespace");
    assert_eq!(first.ontology_version(), second.ontology_version());
    let before = (second.root(), second.wal_head(), second.transaction_sequence());
    let foreign = builder_b.submit(&mut second, &card_a.card_id, &[]);
    assert!(
        card_a.card_id != card_b.card_id && foreign["status"] != "CARD_DONE",
        "distinct runs need distinct acknowledgements even for identical records: A={}, B={}, result={foreign}",
        card_a.card_id,
        card_b.card_id
    );
    assert_eq!((second.root(), second.wal_head(), second.transaction_sequence()), before);
    assert!(!builder_b.caught_up(&second));
}

#[test]
fn an_older_completed_card_ack_survives_a_later_card_and_reopen() {
    let wal = TempWal::new();
    let mut state = wal.create("older-card-retry-run", "Evidence alpha. Evidence beta.");
    seed(&mut state, "Evidence alpha.");
    let scope = Scope { docs: vec!["report".into()], ..Default::default() };
    let second_seed = state.submit_records_id(
        "seed-second",
        "worker",
        "T1",
        &scope,
        &[json!({"kind":"observe","local_id":"o2","doc_id":"report","exact_quote":"Evidence beta.","terms":["beta"]})],
    );
    assert!(second_seed.error.is_none(), "second seed failed: {:?}", second_seed.error);
    assert_eq!(second_seed.accepted.len(), 1);
    let cfg = BuilderConfig { max_records: 1, ..BuilderConfig::default() };
    let mut builder = Builder::new(cfg);
    let first_card = builder.next_card(&state).unwrap();
    let first_done = builder.submit(&mut state, &first_card.card_id, &[]);
    assert_eq!(first_done["status"], "CARD_DONE", "{first_done}");
    let second_card = builder.next_card(&state).unwrap();
    assert_ne!(first_card.card_id, second_card.card_id);
    let second_done = builder.submit(&mut state, &second_card.card_id, &[]);
    assert_eq!(second_done["status"], "CARD_DONE", "{second_done}");
    let committed = (state.root(), state.wal_head(), state.transaction_sequence());
    let direct_retry = builder.submit(&mut state, &first_card.card_id, &[]);
    assert_eq!((state.root(), state.wal_head(), state.transaction_sequence()), committed);
    drop(state);

    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = Builder::new(cfg);
    recovered.recover(&state);
    let replay_retry = recovered.submit(&mut state, &first_card.card_id, &[]);
    assert_eq!((state.root(), state.wal_head(), state.transaction_sequence()), committed);
    assert_eq!(
        (direct_retry["status"].as_str(), replay_retry["status"].as_str()),
        (Some("CARD_DONE"), Some("CARD_DONE")),
        "an exact old acknowledgement remains recoverable after a later card: direct={direct_retry}; reopened={replay_retry}"
    );
}

#[test]
fn a_changed_payload_for_a_closed_card_cannot_replay_an_unrelated_ack() {
    let wal = TempWal::new();
    let mut state = wal.create("changed-card-payload-run", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&state).unwrap();
    let done = builder.submit(&mut state, &card.card_id, &[]);
    assert_eq!(done["status"], "CARD_DONE", "{done}");
    let committed = (state.root(), state.wal_head(), state.transaction_sequence());
    // This valid operation was never submitted or committed for the closed card.
    let changed = json!({"op":"propose_concept","type":"Component","name":"alpha concept","aliases":[],"basis":[card.records[0].id.short()]});
    let result = builder.submit(&mut state, &card.card_id, &[changed]);
    assert_ne!(result["status"], "CARD_DONE", "only the exact committed request may replay its receipt: {result}");
    assert_eq!((state.root(), state.wal_head(), state.transaction_sequence()), committed);
    assert!(state.candidates("alpha concept", 1).is_empty());
}

#[test]
fn a_refused_operation_can_be_repaired_once_after_reopen_without_id_collision() {
    let wal = TempWal::new();
    let mut state = wal.create("reopened-card-repair-run", "Evidence alpha.");
    seed(&mut state, "Evidence alpha.");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&state).unwrap();
    let ontology_before = state.ontology_version();
    let invalid: Value =
        json!({"op":"propose_concept","type":"Component","name":"alpha concept","aliases":["x".repeat(121)],"basis":[card.records[0].id.short()]});
    let failed = builder.submit(&mut state, &card.card_id, &[invalid]);
    assert_eq!(failed["status"], "REPAIR_REQUIRED", "{failed}");
    assert_eq!(failed["committed_ops"], 0, "{failed}");
    assert_eq!(failed["error"]["field"], "aliases", "fixture needs a durable store refusal: {failed}");
    assert_eq!(state.ontology_version(), ontology_before, "the refused operation must not grow the ontology");
    drop(state);

    let mut state = AuditState::open(&wal.0).unwrap();
    let mut recovered = Builder::new(BuilderConfig::default());
    recovered.recover(&state);
    let reopened_card = recovered.next_card(&state).unwrap();
    assert_eq!(reopened_card.card_id, card.card_id, "this unchanged cut and ontology must reproduce the card");
    let repaired = json!({"op":"propose_concept","type":"Component","name":"alpha concept","aliases":[],"basis":[reopened_card.records[0].id.short()]});
    let result = recovered.submit(&mut state, &reopened_card.card_id, &[repaired]);
    assert_eq!(result["status"], "CARD_DONE", "the first repaired request must not collide with the durable refusal: {result}");
    assert_eq!(state.candidates("alpha concept", 1).len(), 1);
    assert!(recovered.caught_up(&state));
}
