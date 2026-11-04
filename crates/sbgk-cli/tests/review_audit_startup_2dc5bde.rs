//! Invalid startup arguments must be rejected before a new durable audit run is created.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("sbgk_review_audit_startup_2dc5bde_{}_{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::create_dir_all(dir.join("repo/reports")).unwrap();
        let text = "# Alpha\nTopic A is reported.\n";
        std::fs::write(dir.join("repo/reports/alpha.md"), text).unwrap();
        let manifest = json!({
            "schema": "r2r.tobi_corpus_metadata_manifest.v1",
            "source": {
                "origin_recorded": "https://example.invalid/synthetic.git",
                "commit": "1".repeat(40),
                "repository": "C:/synthetic"
            },
            "entries": [{
                "path": "reports/alpha.md",
                "extension": ".md",
                "corpus_role": "markdown_document_candidate",
                "size_bytes": text.len(),
                "raw_sha256": sbgk_core::hash::to_hex(&sbgk_core::hash::sha256(text.as_bytes())),
                "references": {"commit_candidates": [], "pull_request_candidates": []}
            }]
        });
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        std::fs::write(dir.join("select.txt"), "reports/alpha.md\n").unwrap();
        let subjects = json!({"subjects": [
            {"token": "synthetic-swarm-token-0001", "role": "swarm", "id": "w1"},
            {"token": "synthetic-builder-token-01", "role": "builder", "id": "gb"},
            {"token": "synthetic-owner-token-0001", "role": "owner", "id": "owner"}
        ]});
        std::fs::write(dir.join("subjects.json"), subjects.to_string()).unwrap();
        let questions = json!([{"id": "RQ1", "text": "What does the report establish about topic A?", "about": ["topic"]}]);
        std::fs::write(dir.join("questions.json"), questions.to_string()).unwrap();
        Self(dir)
    }

    fn p(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn malformed_ttl_is_rejected_before_creating_the_wal() {
    let fx = Fixture::new();
    let wal = fx.0.join("run.wal");
    assert!(!wal.exists(), "this is a fresh synthetic run");
    let output = Command::new(BIN)
        .args(["audit-serve", "--profile", "custom"])
        .args([
            "--wal".to_string(),
            fx.p("run.wal"),
            "--subjects".to_string(),
            fx.p("subjects.json"),
            "--questions".to_string(),
            fx.p("questions.json"),
            "--manifest".to_string(),
            fx.p("manifest.json"),
            "--repo".to_string(),
            fx.p("repo"),
            "--select".to_string(),
            fx.p("select.txt"),
            "--run-id".to_string(),
            "startup-review".to_string(),
            "--ttl-ms".to_string(),
            "nope".to_string(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run audit-serve with a malformed TTL and closed stdin");

    assert!(!output.status.success(), "the malformed TTL must fail");
    assert_eq!(output.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let fatal: Value = serde_json::from_slice(&output.stderr).expect("the argument error is one JSON diagnostic");
    assert_eq!(fatal["status"], "fatal", "{fatal}");
    assert_eq!(fatal["message"], "--ttl-ms: bad number 'nope'", "the fixture must reach numeric argument validation: {fatal}");
    assert!(output.stdout.is_empty(), "a rejected startup must not announce a ready server");
    assert!(!wal.exists(), "invalid --ttl-ms created a durable WAL before startup argument validation: {}", wal.display());
}

#[test]
fn all_numeric_options_and_invalid_ranges_are_checked_before_creating_a_wal() {
    for (option, value) in [
        ("ttl-ms", "0"),
        ("ttl-ms", "18446744073709551615"),
        ("section-bytes", "nope"),
        ("section-bytes", "0"),
        ("section-bytes", "63"),
        ("max-message-bytes", "nope"),
        ("max-message-bytes", "0"),
        ("max-message-bytes", "18446744073709551615"),
        ("max-connections", "nope"),
        ("max-connections", "0"),
    ] {
        let fx = Fixture::new();
        let output = Command::new(BIN)
            .args(["audit-serve", "--profile", "custom"])
            .args([
                "--wal".to_string(),
                fx.p("run.wal"),
                "--subjects".to_string(),
                fx.p("subjects.json"),
                "--questions".to_string(),
                fx.p("questions.json"),
                "--manifest".to_string(),
                fx.p("manifest.json"),
                "--repo".to_string(),
                fx.p("repo"),
                "--select".to_string(),
                fx.p("select.txt"),
                "--run-id".to_string(),
                "startup-review".to_string(),
                format!("--{option}"),
                value.to_string(),
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "--{option} {value}: {}", String::from_utf8_lossy(&output.stderr));
        let fatal: Value = serde_json::from_slice(&output.stderr).expect("one JSON argument error");
        assert_eq!(fatal["status"], "fatal", "{fatal}");
        assert!(fatal["message"].as_str().unwrap().contains(&format!("--{option}")), "the rejected option must be identified: {fatal}");
        assert!(output.stdout.is_empty(), "invalid startup must not announce readiness");
        assert!(!fx.0.join("run.wal").exists(), "--{option} {value} created a WAL before validation");
    }
}
