//! `sbgk verify` answers with its exit code as well as its JSON: 0 for a sound container, 1 when a check fails (a
//! tampered container printed "ok": false and exited 0 before), 2 for a usage error.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

/// A refused step is a failed `apply`: the report says which, and the exit code says so to a script.
#[test]
fn apply_exits_1_when_a_step_is_refused_and_reports_it() {
    let dir = std::env::temp_dir().join(format!("sbgk_cli_apply_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let quickstart = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/quickstart");
    let stream = std::fs::read_to_string(quickstart.join("stream.jsonl")).unwrap();
    let bad = dir.join("bad.jsonl");
    std::fs::write(&bad, stream.replace("shall call interface", "must call interface")).unwrap();
    let (ontology, docs) = (quickstart.join("ontology.json"), quickstart.join("docs"));
    let out = dir.join("bad.sbgk");
    let (code, json) = run(&[
        "apply",
        "--ontology",
        ontology.to_str().unwrap(),
        "--docs",
        docs.to_str().unwrap(),
        "--stream",
        bad.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{json}");
    assert!(json.contains("QUOTE_NOT_FOUND_IN_BYTES"), "{json}");
    let good = quickstart.join("stream.jsonl");
    let (code, json) = run(&["apply", "--ontology", ontology.to_str().unwrap(), "--docs", docs.to_str().unwrap(), "--stream", good.to_str().unwrap()]);
    assert_eq!(code, 0, "{json}");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).output().expect("the binary starts");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

/// An entity no claim names is a mistake of the question, not an empty answer: it printed an empty cone and exited 0 before.
#[test]
fn cone_refuses_an_entity_no_claim_names() {
    let dir = std::env::temp_dir().join(format!("sbgk_cli_cone_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let container = quickstart_container(&dir);
    let cone = |entity: &str| Command::new(BIN).args(["cone", container.to_str().unwrap(), "--entity", entity, "--reps", "1"]).output().unwrap();
    assert_eq!(cone("svc_auth").status.code(), Some(0));
    let unknown = cone("no_such_entity");
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no_such_entity"));
    // the whole projection does not depend on the entity
    let full = dir.join("full.json");
    let whole = Command::new(BIN)
        .args(["cone", container.to_str().unwrap(), "--entity", "no_such_entity", "--reps", "1", "--full-out", full.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(whole.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

fn quickstart_container(dir: &Path) -> PathBuf {
    let q = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/quickstart");
    let out = dir.join("graph.sbgk");
    let (code, json) = run(&[
        "apply",
        "--ontology",
        q.join("ontology.json").to_str().unwrap(),
        "--docs",
        q.join("docs").to_str().unwrap(),
        "--stream",
        q.join("stream.jsonl").to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "apply: {json}");
    out
}

#[test]
fn verify_exits_zero_for_a_sound_container_and_one_for_a_tampered_one() {
    let dir = std::env::temp_dir().join(format!("sbgk_cli_verify_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sound = quickstart_container(&dir);
    let (code, json) = run(&["verify", sound.to_str().unwrap()]);
    assert_eq!(code, 0, "{json}");
    assert!(json.contains("\"ok\":true"), "{json}");

    let mut bytes = std::fs::read(&sound).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    let tampered = dir.join("tampered.sbgk");
    std::fs::write(&tampered, &bytes).unwrap();
    let (code, json) = run(&["verify", tampered.to_str().unwrap()]);
    assert_eq!(code, 1, "{json}");
    assert!(json.contains("\"ok\":false"), "{json}");

    let (code, _) = run(&["verify"]);
    assert_eq!(code, 2, "a missing container is a usage error");
    std::fs::remove_dir_all(&dir).ok();
}
