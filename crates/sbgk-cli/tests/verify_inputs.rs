//! The journals of the independent verifier's inputs (`verifier/inputs`), recorded by earlier kernels, verify as `expected.json`
//! says `sbgk audit-verify` answers them: the same exit and status. A report of a verified or torn journal also says what no check
//! covered without an external checkpoint, in fields of its own beside the status.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

#[test]
fn the_recorded_journals_keep_their_verdicts_and_a_report_says_what_was_not_checked() {
    let inputs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../verifier/inputs");
    let expected: Value = serde_json::from_slice(&std::fs::read(inputs.join("expected.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (group, journals) in expected.as_object().unwrap().iter().filter(|(g, _)| !g.starts_with('_')) {
        for (name, want) in journals.as_object().unwrap() {
            let kernel = &want["kernel"];
            let wal = inputs.join(group).join(name);
            let out = Command::new(BIN).args(["audit-verify", "--wal"]).arg(&wal).output().unwrap();
            let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
            assert_eq!(out.status.code(), kernel["exit"].as_i64().map(|c| c as i32), "{group}/{name}: {v}");
            assert_eq!(v["status"], kernel["status"], "{group}/{name}: {v}");
            if let Some(message) = kernel["message"].as_str() {
                assert!(v["error"]["message"].as_str().is_some_and(|m| m.contains(message)), "{group}/{name}: {v}");
            }
            if matches!(v["status"].as_str(), Some("VERIFIED" | "TORN_TAIL")) {
                assert_eq!(v["external_checkpoint"], false, "{group}/{name}: {v}");
                assert!(v["not_checked"].as_str().is_some_and(|t| t.starts_with("frame-boundary truncation:")), "{group}/{name}: {v}");
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 22, "every recorded journal");
}
