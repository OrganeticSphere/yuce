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
    // the cache serves the `/1` root of the first formats
    let mut s = AuditState::create_v2(
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
fn checkpoint_rows_follow_every_write_in_the_order_of_their_keys_in_utf16() {
    let (wal, mut s, _) = state();
    let checkpoint = |key: &str, n: u64| json!({"key":key,"from":0,"to":0,"context":{"n":n}});
    // bytes and UTF-16 code units disagree on the last two: U+FFFF sorts after U+10000 only as UTF-16
    for (n, key) in ["b", "a", "\u{ffff}", "\u{10000}"].into_iter().enumerate() {
        let v = s.submit_operations_id(&format!("new-{n}"), "kernel", &[], Some(checkpoint(key, 0))).unwrap();
        assert_eq!(v["checkpointed"], true, "{v}");
        exact(&s);
    }
    // the same key written again, by the batch, by an operation, as a command
    let v = s.submit_operations_id("again-1", "kernel", &[], Some(checkpoint("a", 1))).unwrap();
    assert_eq!(v["checkpointed"], true, "{v}");
    exact(&s);
    let mut op = checkpoint("a", 2);
    op["kind"] = json!("checkpoint");
    assert_eq!(s.submit_operations_id("again-2", "kernel", std::slice::from_ref(&op), None).unwrap()["accepted_operations"], 1);
    exact(&s);
    op["context"]["n"] = json!(3);
    assert!(matches!(s.commit("kernel", "again-3", &op), Ok(Outcome::Value(_))));
    assert_eq!(s.checkpoint("a").unwrap()["context"]["n"], 3);
    exact(&s);
    // written in a batch that fails after it: the first operation stays, the one rolled back does not
    op["context"]["n"] = json!(4);
    let mut lost = op.clone();
    lost["key"] = json!("b");
    let v = s.submit_operations_id("rolled-back", "kernel", &[op.clone(), lost, json!({"kind":"no-such-operation"})], None).unwrap();
    assert_eq!(v["failed_index"], 2, "{v}");
    exact(&s);
    // a first operation refused, and a checkpoint refused after its operations: nothing of them is left
    let refused = json!({"kind":"checkpoint","key":"a","from":7,"to":7,"context":{"n":5}});
    let v = s.submit_operations_id("refused-op", "kernel", std::slice::from_ref(&refused), None).unwrap();
    assert_eq!(v["failed_index"], 0, "{v}");
    exact(&s);
    let v = s.submit_operations_id("refused-checkpoint", "kernel", &[], Some(refused)).unwrap();
    assert_eq!(v["checkpointed"], false, "{v}");
    exact(&s);
    let roots = (s.audit_root(), s.engine_root());
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    exact(&s);
    assert_eq!((s.audit_root(), s.engine_root()), roots);
}

#[test]
fn only_a_command_of_checkpoints_keeps_the_support_flags_of_the_state_before_it() {
    let (_wal, mut s, _) = state();
    let observe = s.records_since(0)[0].id;
    let flags = s.core.support_flags();
    let checkpoint = json!({"kind":"checkpoint","key":"k","from":0,"to":0,"context":{}});
    assert!(s.submit_operations_id("alone", "kernel", &[], Some(checkpoint.clone())).unwrap()["error"].is_null());
    assert!(Arc::ptr_eq(&flags, &s.core.support_flags()), "a checkpoint changes nothing the flags read");
    assert!(s.submit_operations_id("as-operation", "kernel", std::slice::from_ref(&checkpoint), None).unwrap()["error"].is_null());
    assert!(Arc::ptr_eq(&flags, &s.core.support_flags()), "nor does the same checkpoint as an operation");
    let revoke = json!({"kind":"revoke","record":to_hex(&observe.0)});
    assert!(s.submit_operations_id("with-revoke", "kernel", &[revoke, checkpoint], None).unwrap()["error"].is_null());
    assert!(!s.core.support_flags()[&observe].0, "a checkpoint beside any other operation keeps nothing");
    exact(&s);
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
