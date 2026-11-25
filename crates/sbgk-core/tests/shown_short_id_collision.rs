//! The dispatcher's reading of a shown record's short id when two shown records share the first eight bytes of their ids: the
//! name stands for the first of them in the order shown, as the walk of the shown records before 0.2.5 found it (the index of
//! short ids of 0.2.5). No pair of real ids is known to share eight bytes, so the second id is made from the first.

use sbgk_core::audit::directives::unstored_problems;
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::collections::BTreeMap;

struct Wal(std::path::PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_short_id_two_shown_records_share_names_the_first_one_shown() {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_shown_short_{}_{nanos}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), b"Prior witness.\nNew witness.\n".to_vec())];
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "short-ids", sha256(b"short ids")).unwrap();
    let scope = Scope { docs: vec!["d1".into()], topic: None, ranges: Vec::new() };
    let stored = s.submit_records_id(
        "s1",
        "w1",
        "t1",
        &scope,
        &[
            json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": "Prior witness.", "terms": ["witness"]}),
            json!({"kind": "claim", "local_id": "c", "text": "A witness came first.", "subject": "witness", "stance": "reported", "based_on": ["o"]}),
        ],
    );
    assert!(stored.error.is_none(), "{:?}", stored.error);
    let claim = stored.accepted[1];
    let mut forged = claim.0;
    forged[8] ^= 0xff;
    let twin = RecordId(forged);
    assert_eq!(twin.short(), claim.short());
    // a claim that rests on a claim: what is said about its basis depends on the record the name stands for
    let line: Value =
        json!({"kind": "claim", "local_id": "x", "text": "Rests on a claim.", "subject": "witness", "stance": "reported", "based_on": [claim.short()]});
    let said = |shown: &[RecordId]| unstored_problems(&s, &scope, &BTreeMap::new(), shown, std::slice::from_ref(&line), &[(0, line.clone())]);
    assert_ne!(said(&[claim]), said(&[twin]), "the test tells the two records apart");
    assert_eq!(said(&[claim, twin]), said(&[claim]));
    assert_eq!(said(&[twin, claim]), said(&[twin]));
}
