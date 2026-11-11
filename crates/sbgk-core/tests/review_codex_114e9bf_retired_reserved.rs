//! A retired concept's name stays reserved and must not be rebound through a live alias owner.
use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::json;

#[test]
fn retired_reserved_name_is_not_rebound_through_live_alias_owner() {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = std::env::temp_dir().join(format!("review_114_retired_{}_{nonce}.jsonl", std::process::id()));
    let docs = vec![("d1".to_string(), b"The reserved name denotes the existing component.".to_vec())];
    let mut s = AuditState::create(&wal, &AuditOntology::base(), &docs, "review-114-retired", sha256(b"review-fixture")).unwrap();
    let r = s.submit_records(
        "reader",
        "seed",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[json!({"kind":"observe","local_id":"o","doc_id":"d1","exact_quote":"The reserved name denotes the existing component.","terms":["reserved name"]})],
    );
    assert!(r.error.is_none(), "fixture: {:?}", r.error);
    let observe = r.accepted[0];
    let component = s.propose_concept("seed", "Component", "reserved name", &[], &[observe]).unwrap();
    let rule = s.propose_concept("seed", "Rule", "reserved alias", &[], &[observe]).unwrap();
    s.set_concept_status("owner", &component.id, "retired").unwrap();
    assert_eq!(s.concept(&component.id).unwrap().status, "retired");
    assert!(s.candidates("reserved name", 1).is_empty(), "retired concepts are hidden from candidates");
    assert_eq!(s.candidates("reserved alias", 1)[0].id, rule.id);
    assert!(s.concepts_of(&observe).is_empty());
    let direct = s.propose_concept("kernel-control", "Rule", "reserved name", &["reserved alias".into()], &[observe]);
    assert!(direct.is_err(), "production kernel must reject the still-reserved name");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let answer = builder.submit(
        &mut s,
        &card.card_id,
        &[
            json!({"op":"propose_concept","type":"Rule","name":"reserved name","aliases":["reserved alias"],"basis":[observe.short()]}),
            json!({"op":"map_term","record":observe.short(),"term":"reserved name","concept":"reserved name"}),
        ],
    );
    let mapped = s.concepts_of(&observe);
    assert_eq!(s.concept(&component.id).unwrap().status, "retired");
    drop(s);
    let _ = std::fs::remove_file(&wal);
    assert_eq!(
        answer["status"],
        "REPAIR_REQUIRED",
        "a retired owner's name stays reserved: kernel={direct:?}, retired={}, live={}, mapped={mapped:?}, actual={answer}",
        component.id.short(),
        rule.id.short()
    );
    assert!(mapped.is_empty(), "a refused reserved-name proposal must not route the term to a different concept");
}
