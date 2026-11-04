//! Durable regressions for the assigned D01/D02 fixes. Synthetic inputs only.
use sbgk_core::audit::builder::{Builder, BuilderConfig};
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
fn fresh(tag: &str) -> (Wal, AuditState, [RecordId; 2]) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_d01_d02_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let text = b"First independent evidence.\nSecond independent evidence.\n".to_vec();
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), text)], tag, sha256(tag.as_bytes())).unwrap();
    let r = s.submit_records_id(
        "seed",
        "reader",
        "seed",
        &Scope { docs: vec!["d".into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"o1","doc_id":"d","exact_quote":"First independent evidence.","terms":["frontend"]}),
            json!({"kind":"observe","local_id":"o2","doc_id":"d","exact_quote":"Second independent evidence.","terms":["backend"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let ids = [r.accepted[0], r.accepted[1]];
    (wal, s, ids)
}
fn proposal(ty: &str, name: &str, basis: RecordId) -> Value {
    json!({"op":"propose_concept","type":ty,"name":name,"aliases":[],"basis":[basis.short()]})
}
fn reuse(basis: RecordId) -> Value {
    json!({"op":"propose_concept","type":"Component","name":"frontend","aliases":["core"],"basis":[basis.short()]})
}
fn core(s: &mut AuditState, basis: RecordId) {
    let c = s.propose_concept("owner", "Component", "core", &[], &[basis]).unwrap();
    assert_eq!(c.status, "provisional");
}
fn fingerprint(s: &AuditState) -> Value {
    json!([s.root(), s.engine_root(), s.wal_head(), s.transaction_sequence(), s.head()])
}
fn recovered(s: &AuditState, cfg: BuilderConfig, id: &str) -> Builder {
    let mut b = Builder::new(cfg);
    b.recover(s);
    assert_eq!(b.next_card(s).unwrap().card_id, id);
    b
}

#[test]
fn d01_store_refusal_before_a_later_success_replays_without_writing_or_counting() {
    let (wal, mut s, [a, b]) = fresh("durable-refusal");
    core(&mut s, a);
    // a builder link connects claims (block A of the 10A-4 audit): the fixture's valid second operation links two claims on a and b
    let claims = s.submit_records_id(
        "seed-claims",
        "reader",
        "seed",
        &Scope { docs: vec!["d".into()], ..Default::default() },
        &[
            json!({"kind":"claim","local_id":"c1","text":"First claim.","subject":"frontend","stance":"reported","based_on":[a.short()]}),
            json!({"kind":"claim","local_id":"c2","text":"Second claim.","subject":"backend","stance":"reported","based_on":[b.short()]}),
        ],
    );
    assert!(claims.error.is_none(), "{:?}", claims.error);
    let (c1, c2) = (claims.accepted[0], claims.accepted[1]);
    let cfg = BuilderConfig { max_ops: 2, ..Default::default() };
    let mut builder = Builder::new(cfg);
    let card = builder.next_card(&s).unwrap();
    let ops = [proposal("Rule", "core", a), json!({"op":"link","from":c1.short(),"rel":"supports","to":c2.short(),"basis":[a.short()]})];
    let first = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["refused"][0]["index"], 0);
    assert_eq!(first["refused"][0]["error"]["field"], "name", "fixture needs a durable store rejection: {first}");
    assert_eq!(first["committed_ops"], 1);
    assert_eq!(s.links().len(), 1);
    let before = fingerprint(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, cfg, &card.card_id);
    let again = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(again, first, "the exact durable outcomes must replay");
    assert_eq!(fingerprint(&s), before, "a durable refusal is not a fresh attempt");
    assert_eq!((builder.stats.ops_accepted, builder.stats.ops_refused), (0, 0));
}

#[test]
fn d01_an_original_refusal_does_not_turn_into_reuse_when_a_later_operation_creates_its_name() {
    let (wal, mut s, [a, b]) = fresh("changing-translation");
    s.revoke_observation("owner", &a).unwrap();
    assert!(!s.is_grounded(&a));
    assert!(s.is_grounded(&b));
    let cfg = BuilderConfig { max_ops: 2, ..Default::default() };
    let mut builder = Builder::new(cfg);
    let card = builder.next_card(&s).unwrap();
    let ops = [proposal("Component", "created component", a), proposal("Component", "created component", b)];
    let first = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["refused"].as_array().unwrap().len(), 1);
    assert_eq!(first["refused"][0]["index"], 0);
    assert_eq!(first["results"][0]["status"], "provisional");
    assert_eq!(first["committed_ops"], 1);
    let before = fingerprint(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, cfg, &card.card_id);
    let again = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(again, first, "lookup must precede the live-dependent Reuse interpretation");
    assert_eq!(fingerprint(&s), before);
    assert_eq!((builder.stats.ops_accepted, builder.stats.ops_refused, builder.stats.concepts_reused), (0, 0, 0));
}

#[test]
fn d02_a_reused_local_name_survives_recovery_for_a_suffix_only_map() {
    let (wal, mut s, [a, b]) = fresh("reuse-name");
    core(&mut s, b);
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let invalid = json!({"op":"map_term","record":a.short(),"term":"not-issued","concept":"frontend"});
    let first = builder.submit(&mut s, &card.card_id, &[reuse(a), invalid]);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["accepted"], 1);
    assert_eq!(first["results"][0]["status"], "existing");
    assert!(s.candidates("frontend", 1).is_empty(), "reuse must not add an ontology alias");
    let concept = s.candidates("core", 1)[0].id;
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, BuilderConfig::default(), &card.card_id);
    let fixed = json!({"op":"map_term","record":a.short(),"term":"frontend","concept":"frontend"});
    let result = builder.submit(&mut s, &card.card_id, &[fixed]);
    assert_eq!(result["status"], "CARD_DONE", "an accepted local name survives: {result}");
    assert_eq!(s.concepts_of(&a), vec![concept]);
    assert_eq!(result["results"][0]["status"], "proposed", "reuse is not accepted semantic identity");
}

#[test]
fn d02_exact_reuse_and_durable_refusal_replay_without_wal_or_counter_changes() {
    let (wal, mut s, [a, b]) = fresh("reuse-retry");
    core(&mut s, b);
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let ops = [reuse(a), proposal("Rule", "core", a)];
    let first = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["accepted"], 1);
    let before = fingerprint(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, BuilderConfig::default(), &card.card_id);
    let again = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(again, first);
    assert_eq!(fingerprint(&s), before);
    assert_eq!((builder.stats.ops_accepted, builder.stats.ops_refused, builder.stats.concepts_reused), (0, 0, 0));
}

#[test]
fn d01_legacy_slot_recovery_keeps_budget_and_original_proposal_ack() {
    let (wal, mut s, [a, _]) = fresh("legacy-budget");
    let cfg = BuilderConfig { max_ops: 2, ..Default::default() };
    let mut builder = Builder::new(cfg);
    let card = builder.next_card(&s).unwrap();
    let first = builder.submit(&mut s, &card.card_id, &[proposal("Component", "one", a), json!({"op":"bad"})]);
    assert_eq!(first["committed_ops"], 1);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, cfg, &card.card_id);
    let ops = [proposal("Component", "two", a), proposal("Component", "three", a)];
    let second = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(second["status"], "REPAIR_REQUIRED", "{second}");
    assert_eq!(second["committed_ops"], 2);
    assert!(s.candidates("three", 1).is_empty());
    let before = fingerprint(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, cfg, &card.card_id);
    let again = builder.submit(&mut s, &card.card_id, &ops);
    assert_eq!(again, second, "an existing proposal's ACK is not replaced by Reuse");
    assert_eq!(fingerprint(&s), before);
    assert_eq!(builder.stats.ops_accepted, 0);
}

#[test]
fn d02_a_refused_noop_checkpoint_cannot_ack_or_install_a_name() {
    let (_wal, mut s, [a, b]) = fresh("reuse-checkpoint-failure");
    core(&mut s, b);
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let key = format!("builder:reuse:{}", card.card_id);
    // This valid store checkpoint makes the coordinator's required 0->0 update fail as an Ok(error) batch outcome.
    let context = json!({"format":"r2r-builder-reuse/1","card_id":card.card_id,"names":{},"receipts":{}});
    let planted = s.submit_operations_id("force-checkpoint-refusal", "owner", &[], Some(json!({"key":key,"from":0,"to":1,"context":context}))).unwrap();
    assert_eq!(planted["checkpointed"], true);
    let result = builder.submit(&mut s, &card.card_id, &[reuse(a)]);
    assert_eq!(result["status"], "REPAIR_REQUIRED", "a refused checkpoint is not an accepted Reuse: {result}");
    assert_eq!(result["accepted"], 0);
    assert_eq!((builder.stats.ops_accepted, builder.stats.concepts_reused), (0, 0));
    assert!(s.checkpoint(&key).unwrap()["context"]["names"].as_object().unwrap().is_empty());
    let map = json!({"op":"map_term","record":a.short(),"term":"frontend","concept":"frontend"});
    let result = builder.submit(&mut s, &card.card_id, &[map]);
    assert_eq!(result["status"], "REPAIR_REQUIRED", "a failed Reuse installed no phantom name: {result}");
    assert_eq!(result["accepted"], 0);
    assert!(s.concepts_of(&a).is_empty());
}

#[test]
fn d02_an_older_reuse_retry_preserves_later_bindings_and_exact_ack() {
    let (wal, mut s, [a, b]) = fresh("reuse-growth");
    core(&mut s, a);
    let other = s.propose_concept("owner", "Component", "other", &[], &[b]).unwrap();
    assert_eq!(other.status, "provisional");
    let core_id = s.candidates("core", 1)[0].id;
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let refusal = proposal("Rule", "core", a);
    let older = [reuse(a), refusal.clone()];
    let first = builder.submit(&mut s, &card.card_id, &older);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    assert_eq!(first["accepted"], 1);
    assert_eq!(first["refused"][0]["error"]["field"], "name");
    let newer = json!({"op":"propose_concept","type":"Component","name":"backend","aliases":["other"],"basis":[b.short()]});
    let second = builder.submit(&mut s, &card.card_id, &[newer, refusal]);
    assert_eq!(second["status"], "REPAIR_REQUIRED", "{second}");
    assert_eq!(second["accepted"], 1);
    assert!(s.candidates("frontend", 1).is_empty());
    assert!(s.candidates("backend", 1).is_empty());
    let before = fingerprint(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut builder = recovered(&s, BuilderConfig::default(), &card.card_id);
    let again = builder.submit(&mut s, &card.card_id, &older);
    assert_eq!(again["status"], first["status"]);
    assert_eq!(again["accepted"], first["accepted"]);
    assert_eq!(again["committed_ops"], first["committed_ops"]);
    assert_eq!(again["results"], first["results"], "the exact operation ACK is independent of the growing checkpoint context");
    assert_eq!(again["refused"], first["refused"]);
    assert_eq!(again["proposed_concepts"]["frontend"], core_id.short());
    assert_eq!(again["proposed_concepts"]["backend"], other.id.short());
    assert_eq!(fingerprint(&s), before, "replay must neither write nor replace the newer checkpoint");
    assert_eq!((builder.stats.ops_accepted, builder.stats.ops_refused, builder.stats.concepts_reused), (0, 0, 0));
    let maps = [
        json!({"op":"map_term","record":a.short(),"term":"frontend","concept":"frontend"}),
        json!({"op":"map_term","record":b.short(),"term":"backend","concept":"backend"}),
    ];
    let result = builder.submit(&mut s, &card.card_id, &maps);
    assert_eq!(result["status"], "CARD_DONE", "both bindings survived the old retry: {result}");
    assert_eq!(s.concepts_of(&a), vec![core_id]);
    assert_eq!(s.concepts_of(&b), vec![other.id]);
}
