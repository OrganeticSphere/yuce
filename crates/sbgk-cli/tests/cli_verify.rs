//! `sbgk verify` answers with its exit code as well as its JSON: 0 for a sound container, 1 when a check fails (a
//! tampered container printed "ok": false and exited 0 before), 2 for a usage error.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).output().expect("the binary starts");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
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
