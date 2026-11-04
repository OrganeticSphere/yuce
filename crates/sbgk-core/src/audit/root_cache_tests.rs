//! Cache warmth must not change native relation side effects, JSON bytes, or batch-prefix rules.
use super::*;

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn state() -> (Wal, AuditState, Scope) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = Wal(std::env::temp_dir().join(format!("root-cache-{}-{nonce}.wal", std::process::id())));
    let mut s = AuditState::create(
        &path.0,
        &AuditOntology::base(),
        &[("doc".into(), b"Earlier witness. Later witness.\n".to_vec())],
        "cache-test",
        sha256(b"cache-test"),
    )
    .unwrap();
    let scope = Scope { docs: vec!["doc".into()], ..Default::default() };
    let r = s.submit_records_id(
        "seed",
        "worker",
        "task",
        &scope,
        &[
            json!({"kind":"observe","local_id":"o","doc_id":"doc","exact_quote":"Earlier witness."}),
            json!({"kind":"claim","local_id":"a","text":"Earlier state.","subject":"witness","stance":"reported","based_on":["o"]}),
            json!({"kind":"claim","local_id":"b","text":"Later state.","subject":"witness","stance":"reported","based_on":["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{r:?}");
    (path, s, scope)
}
fn exact(s: &AuditState) {
    assert_eq!(s.core.cached_preimage(), s.core.legacy_preimage());
    assert_eq!(s.audit_root(), sha256_parts(&[b"R2R-AUDIT-STATE/1", s.core.legacy_preimage().as_bytes()]));
}
#[test]
fn a_warm_root_includes_links_materialized_by_relation_ingest_and_unicode_checkpoints() {
    let (wal, mut s, scope) = state();
    exact(&s);
    let r = s.submit_records_id(
        "relation",
        "worker",
        "task",
        &scope,
        &[json!({"kind":"relation","local_id":"r","from":"a","rel":"supports","to":"b","based_on":["o"]})],
    );
    assert!(r.error.is_none(), "{r:?}");
    assert_eq!(s.links().len(), 1);
    exact(&s);
    let c = json!({"key":"unicode-\u{10000}","from":0,"to":0,"context":{"\u{10000}":"supplementary","\u{ffff}":"BMP","quoted":"\"\\\n","valid":null}});
    let v = s.submit_operations_id("unicode", "kernel", &[], Some(c)).unwrap();
    assert!(v["error"].is_null(), "{v}");
    exact(&s);
    let roots = (s.audit_root(), s.engine_root());
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    exact(&s);
    assert_eq!((s.audit_root(), s.engine_root()), roots);
}
#[test]
fn a_warm_support_map_never_leaks_across_mutations_inside_a_batch() {
    let (wal, mut s, scope) = state();
    let observe = s.records_since(0)[0].id;
    assert!(s.support_map()[&observe].0);
    exact(&s);
    let ops = [
        json!({"kind":"revoke","record":to_hex(&observe.0)}),
        json!({"kind":"submit","directive":"after-revoke","scope":scope_value(&scope),"lines":[
            {"kind":"claim","local_id":"must-fail","text":"Unsupported now.","subject":"witness","stance":"reported","based_on":[format!("@{}",to_hex(&observe.0))]}]}),
    ];
    let v = s.submit_operations_id("revoke-and-read", "kernel", &ops, None).unwrap();
    assert_eq!(v["failed_index"], 1, "earlier revoke must affect the later claim: {v}");
    assert_eq!(v["error"]["code"], KernelError::new(Code::EvidenceNotActive, "").to_json()["code"], "must refuse inactive basis, not a malformed claim");
    assert_eq!(s.head(), 3, "no unsupported claim stored");
    assert!(!s.support_map()[&observe].0);
    exact(&s);
    let root = s.audit_root();
    assert_eq!(s.submit_operations_id("revoke-and-read", "kernel", &ops, None).unwrap(), v);
    assert_eq!(s.audit_root(), root, "identical retry is unchanged");
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    exact(&s);
    assert_eq!(s.audit_root(), root);
    assert_eq!(s.submit_operations_id("revoke-and-read", "kernel", &ops, None).unwrap(), v);
}

#[test]
fn committed_audit_state_keeps_send_sync_and_cold_concurrent_reads() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<AuditState>();
    let s = Arc::new(AuditState::new(&AuditOntology::base(), &[]).unwrap());
    let expected = sha256_parts(&[b"R2R-AUDIT-STATE/1", s.core.legacy_preimage().as_bytes()]);
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || (s.audit_root(), s.core.support_flags()))
        })
        .collect();
    let results: Vec<_> = readers.into_iter().map(|r| r.join().unwrap()).collect();
    assert!(results.iter().all(|(root, _)| *root == expected));
    assert!(results.iter().all(|(_, flags)| Arc::ptr_eq(flags, &results[0].1)));
}
