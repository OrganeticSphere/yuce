//! Review-only regression: collisions across concept types must not disappear before ambiguity checking.
use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::json;

#[test]
fn d04_cross_type_reserved_name_is_not_rebound_through_an_alias_of_another_concept() {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = std::env::temp_dir().join(format!("review_final_d04_{}_{nonce}.jsonl", std::process::id()));
    let docs = vec![("d1".to_string(), b"The reserved name denotes the existing component.".to_vec())];
    let mut s = AuditState::create(&wal, &AuditOntology::base(), &docs, "review-final-d04", sha256(b"review-fixture")).unwrap();
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
    assert_ne!(component.id, rule.id);
    assert_eq!(s.candidates("reserved name", 1)[0].id, component.id);
    assert!(s.concepts_of(&observe).is_empty());
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
    assert_eq!(s.candidates("reserved name", 1)[0].id, component.id, "the existing ontology binding remains unchanged");
    drop(s);
    let _ = std::fs::remove_file(&wal);
    assert_eq!(
        answer["status"],
        "REPAIR_REQUIRED",
        "two reserved names belong to different concepts, even across types; component={}, rule={}, mapped={mapped:?}, actual={answer}",
        component.id.short(),
        rule.id.short()
    );
}
