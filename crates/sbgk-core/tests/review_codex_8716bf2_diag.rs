//! Independent review of 8716bf2 advisory suffix diagnostics.
//! Scripted records and a disposable production AuditState WAL; no model/pilot.
//! Diagnostics must not reinterpret an earlier valid basis through a later
//! duplicate local_id that the sequential production store rejects.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordKind};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_later_duplicate_local_id_does_not_mislabel_an_earlier_valid_observe_basis() {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("review_diag_8716_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), b"# Topic\nAlpha fact is reported.\nBeta fact is reported.\n".to_vec())];
    let mut state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "review-diag-8716", sha256(b"scripted-fixture")).unwrap();
    let mut dispatch = Dispatcher::new(DispatchConfig::default(), Vec::new());
    let task = dispatch.acquire(&state, "worker", true, 0);
    assert_eq!(task["kind"], "EXTEND", "fixture: {task}");
    let task_id = task["task_id"].as_str().unwrap();
    let p = task["local_id_prefix"].as_str().unwrap();
    let observe = |local: String, quote: &str| {
        json!({
            "kind": "observe", "local_id": local, "doc_id": "d1",
            "exact_quote": quote, "terms": ["topic"]
        })
    };
    let claim = |local: String, text: &str| {
        json!({
            "kind": "claim", "local_id": local, "text": text,
            "subject": "topic", "stance": "reported", "based_on": [format!("{p}o")]
        })
    };
    let answer = [
        observe(format!("{p}bad"), "This quote is absent."),
        observe(format!("{p}o"), "Beta fact is reported."),
        claim(format!("{p}c"), "A supported statement."),
        // The store refuses this duplicate, not the preceding claim's basis.
        claim(format!("{p}o"), "An invalid duplicate local id."),
    ];
    // item by item since the consilium of 10A-17 (Gemini's plan step 1): the malformed first quote and the duplicate are refused,
    // the observe and its claim between them are stored, so the production control of this test is the one submission
    let refused = dispatch.submit(&mut state, task_id, "worker", &answer, 1);
    assert_eq!(refused["status"], "REPAIR_REQUIRED", "fixture: {refused}");
    assert_eq!(refused["failed_index"], 0);
    assert_eq!(refused["error"]["code"], "QUOTE_NOT_FOUND_IN_BYTES");
    assert_eq!(refused["accepted"].as_array().map(Vec::len), Some(2));
    let codes: Vec<(u64, String)> =
        refused["refused"].as_array().unwrap().iter().map(|x| (x["index"].as_u64().unwrap(), x["error"]["code"].as_str().unwrap().to_string())).collect();
    assert_eq!(codes, vec![(0, "QUOTE_NOT_FOUND_IN_BYTES".to_string()), (3, "DUPLICATE_LOCAL_ID".to_string())], "{refused}");
    let problems = refused["problems"].as_array().expect("fixture: diagnostics of the lines not stored").clone();
    assert!(problems.iter().any(|v| v["line"] == 0 && v["error"]["code"] == "QUOTE_NOT_FOUND_IN_BYTES"));
    let accepted = state.records_since(0);
    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[0].kind, RecordKind::Observe);
    assert_eq!(accepted[1].kind, RecordKind::Claim);
    assert_eq!(accepted[1].based_on, vec![accepted[0].id]);
    assert!(state.is_grounded(&accepted[1].id));

    // Target assertion: the original suffix's valid claim (line 2) has an
    // observe basis. A later duplicate cannot change that earlier binding.
    let wrong = problems.iter().filter(|v| v["line"] == 2).collect::<Vec<&Value>>();
    assert!(wrong.is_empty(), "advisory diagnostics mislabel the valid earlier claim using a later rejected duplicate: {wrong:?}; full refusal={refused}");
}
