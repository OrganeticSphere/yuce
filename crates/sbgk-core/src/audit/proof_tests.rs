//! Tests of quittances (SPEC_V02_STEP5 section 7) on journals the kernel writes.

use super::*;
use crate::audit::onto::AuditOntology;
use crate::audit::sign::{checkpoint_body, origin, parse_trusted_keys, NoteSigner};
use crate::audit::state::GenesisSpec;
use crate::audit::Scope;
use std::path::PathBuf;

const DOC: &[u8] = b"The first line names the rule.\nThe second line names its exception.\nA third line is withdrawn later.\n";

struct TempPath(PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp(name: &str) -> TempPath {
    TempPath(std::env::temp_dir().join(format!(
        "r2r_proof_{name}_{}_{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    )))
}

fn scope() -> Scope {
    Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() }
}

fn observe(local: &str, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": local, "doc_id": "d", "exact_quote": quote, "terms": ["t"]})
}

/// A run with two observations in two frames and a claim on both in a third, then whatever `then` does, then a seal; returns the
/// journal, the ids of the claim and the two observations, the seal frame and its signed checkpoint.
struct Run {
    path: TempPath,
    claim: String,
    observations: [String; 2],
    seal: usize,
    checkpoint: String,
    signer: NoteSigner,
}

fn run(name: &str, then: impl FnOnce(&mut AuditState, &[String; 2])) -> Run {
    let path = temp(name);
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &[("d".to_string(), DOC.to_vec())], "proof-run", sha256(b"m"), &spec).unwrap();
    let accepted = |s: &mut AuditState, id: &str, lines: &[Value]| {
        let r = s.submit_records_id(id, "worker", "w", &scope(), lines);
        assert!(r.error.is_none(), "{:?}", r.error);
        to_hex(&r.accepted[0].0)
    };
    let o1 = accepted(&mut s, "a", &[observe("o1", "The first line names the rule.")]);
    let o2 = accepted(&mut s, "b", &[observe("o2", "The second line names its exception.")]);
    let claim = accepted(
        &mut s,
        "c",
        &[json!({"kind": "claim", "local_id": "c1", "text": "The rule has an exception.", "subject": "rule", "stance": "reported", "based_on": ["o1", "o2"]})],
    );
    let observations = [o1, o2];
    then(&mut s, &observations);
    s.seal().unwrap();
    let frames = s.frame_hashes().to_vec();
    let seal = frames.len() - 1;
    drop(s);
    let signer = NoteSigner::generate("operator").unwrap();
    let checkpoint = signer.sign(&checkpoint_body(&origin("proof-run"), &frames)).unwrap();
    Run { path, claim, observations, seal, checkpoint, signer }
}

fn build_of(r: &Run, record: &str, opts: ProofOptions) -> KResult<Value> {
    build(&r.path.0, record, None, &r.checkpoint, Some(&r.signer.verifier().text()), opts)
}

#[test]
fn a_quittance_of_a_claim_on_two_quotes_checks_without_the_journal_in_both_modes() {
    let r = run("both", |_, _| {});
    for opts in [ProofOptions::default(), ProofOptions { self_contained: true, with_status: true }] {
        let proof = build_of(&r, &r.claim, opts).unwrap();
        let bytes = to_file(&proof);
        assert!(bytes.len() < 16 * 1024, "{} bytes", bytes.len());
        let read = parse(&bytes).unwrap();
        let out = verify(&read, &[], None, None, None).unwrap();
        assert_eq!(out["status"], "PROOF_VALID");
        assert_eq!(out["target"], r.claim.as_str());
        assert_eq!(out["records"], 3, "the claim and its two observations");
        assert_eq!(out["frames"], 3, "each record in a frame of its own");
        assert_eq!(out["seal"]["frame"], r.seal);
        assert_eq!(out["signature"], "signature valid, key not pinned");
        assert_eq!(out["anchor"], "the seal is not bound to an anchor");
        if opts.self_contained {
            assert_eq!(out["quotes_checked_against_documents"], 2);
            assert_eq!(out["standing"]["at_seal"][&r.claim], true);
        } else {
            assert!(out["standing"].as_str().unwrap().starts_with("not checked"));
            assert!(read.get("documents").is_none() && read.get("status").is_none());
        }
    }
    // a quittance of an observation alone: one record
    let proof = build_of(&r, &r.observations[0][..12], ProofOptions::default()).unwrap();
    assert_eq!(verify(&proof, &[], None, None, None).unwrap()["records"], 1);
}

/// Every scalar of a quittance, by its path.
fn scalars(v: &Value, at: &mut Vec<Value>, out: &mut Vec<Vec<Value>>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                at.push(json!(k));
                scalars(x, at, out);
                at.pop();
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                at.push(json!(i));
                scalars(x, at, out);
                at.pop();
            }
        }
        _ => out.push(at.clone()),
    }
}

fn at_mut<'a>(v: &'a mut Value, path: &[Value]) -> &'a mut Value {
    path.iter().fold(v, |v, k| match k {
        Value::String(k) => &mut v[k.as_str()],
        k => &mut v[k.as_u64().unwrap() as usize],
    })
}

#[test]
fn every_value_of_a_quittance_changed_is_refused() {
    let r = run("tamper", |_, _| {});
    let proof = build_of(&r, &r.claim, ProofOptions { self_contained: true, with_status: true }).unwrap();
    let mut paths = Vec::new();
    scalars(&proof, &mut Vec::new(), &mut paths);
    assert!(paths.len() > 100, "{} values", paths.len());
    for path in &paths {
        let mut forged = proof.clone();
        let x = at_mut(&mut forged, path);
        *x = match x.clone() {
            Value::String(s) if s.is_empty() => json!("x"),
            Value::String(s) => {
                // the last character changed in kind: a hex digit stays a hex digit, a letter of base64 stays base64
                let mut c: Vec<char> = s.chars().collect();
                let i = c.iter().rposition(|c| c.is_ascii_alphanumeric()).unwrap_or(c.len() - 1);
                c[i] = if c[i] == '0' {
                    '1'
                } else if c[i] == 'a' {
                    'b'
                } else {
                    '0'
                };
                json!(c.into_iter().collect::<String>())
            }
            Value::Number(n) => json!(n.as_u64().unwrap_or(0) + 1),
            Value::Bool(b) => json!(!b),
            Value::Null => json!(0),
            other => other,
        };
        assert!(verify(&forged, &[], None, None, None).is_err(), "a changed value at {path:?} was accepted");
    }
    // the file itself: not its canonical form, and a byte of a chunk
    let mut bytes = to_file(&proof);
    bytes.insert(1, b' ');
    assert!(parse(&bytes).is_err());
    let mut extra = proof.clone();
    extra["note"] = json!("an extra key");
    assert!(check(&extra).is_err());
}

#[test]
fn the_check_weighs_the_key_and_the_anchor() {
    let r = run("keys", |_, _| {});
    let mut proof = build_of(&r, &r.claim, ProofOptions::default()).unwrap();
    let seal_hash = crate::hash::from_hex(verify(&proof, &[], None, None, None).unwrap()["seal"]["seal_hash"].as_str().unwrap()).unwrap();
    let anchored = verify(&proof, &[], None, None, Some(&seal_hash)).unwrap();
    assert_eq!(anchored["anchor"], "the seal is the anchored one");
    assert!(verify(&proof, &[], None, None, Some(&sha256(b"another seal"))).is_err());
    let pinned = parse_trusted_keys(&format!("{} role=operator\n", r.signer.verifier().text())).unwrap();
    assert_eq!(verify(&proof, &pinned, None, None, None).unwrap()["signature"], "signature valid, key pinned");
    let revoked = parse_trusted_keys(&format!("{} role=operator revoked=2026-11-01\n", r.signer.verifier().text())).unwrap();
    assert!(verify(&proof, &revoked, None, None, None).is_err());
    assert!(verify(&proof, &revoked, None, Some("2026-10-31"), None).is_ok(), "kept from before the revocation");
    // another key's verifier key beside the signature: refused; no key at all: refused
    proof["verifier_key"] = json!(NoteSigner::generate("other").unwrap().verifier().text());
    assert!(verify(&proof, &[], None, None, None).is_err());
    proof.as_object_mut().unwrap().remove("verifier_key");
    assert!(verify(&proof, &[], None, None, None).is_err());
    assert!(verify(&proof, &[], Some(&r.signer.verifier()), None, None).is_ok());
}

#[test]
fn a_quittance_is_cut_only_of_records_that_stand_at_a_seal_its_checkpoint_names() {
    // a record whose ground was revoked before the seal: neither it nor the revoked observation
    let r = run("fallen", |s, o| {
        s.revoke_observation("owner", &crate::audit::RecordId(crate::hash::from_hex(&o[1]).unwrap())).unwrap();
    });
    let refused = build_of(&r, &r.claim, ProofOptions::default()).unwrap_err();
    assert!(refused.message.contains("does not stand at this seal"), "{}", refused.message);
    assert!(build_of(&r, &r.observations[1], ProofOptions::default()).is_err());
    assert!(build_of(&r, &r.observations[0], ProofOptions::default()).is_ok(), "the other observation stands");
    // a checkpoint of another prefix, a seal frame that is no seal, a record no one wrote
    let r = run("prefix", |_, _| {});
    let other = r.signer.sign(&checkpoint_body(&origin("proof-run"), &[sha256(b"a"), sha256(b"b")])).unwrap();
    assert!(build(&r.path.0, &r.claim, None, &other, None, ProofOptions::default()).is_err());
    assert!(build(&r.path.0, &r.claim, Some(1), &r.checkpoint, None, ProofOptions::default()).is_err());
    assert!(build_of(&r, &"0".repeat(64), ProofOptions::default()).is_err());
}

#[test]
fn a_record_written_after_the_seal_needs_a_later_seal() {
    let path = temp("after");
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &[("d".to_string(), DOC.to_vec())], "proof-run", sha256(b"m"), &spec).unwrap();
    s.submit_records_id("a", "worker", "w", &scope(), &[observe("o1", "The first line names the rule.")]);
    s.seal().unwrap();
    let first = s.frame_hashes().to_vec();
    let late = s.submit_records_id("b", "worker", "w", &scope(), &[observe("o2", "The second line names its exception.")]);
    let late = to_hex(&late.accepted[0].0);
    s.seal().unwrap();
    drop(s);
    let signer = NoteSigner::generate("operator").unwrap();
    let at_first = signer.sign(&checkpoint_body(&origin("proof-run"), &first)).unwrap();
    let refused = build(&path.0, &late, Some(first.len() - 1), &at_first, None, ProofOptions::default()).unwrap_err();
    assert!(refused.message.contains("needs a later seal"), "{}", refused.message);
}

#[test]
fn a_self_contained_quittance_hands_out_no_chunk_that_holds_withdrawn_text() {
    let r = run("withdrawn", |s, _| {
        s.withdraw_text("owner", "d", "A third line is withdrawn later.").unwrap();
    });
    let refused = build_of(&r, &r.claim, ProofOptions { self_contained: true, with_status: false }).unwrap_err();
    assert!(refused.message.contains("withdrawn text"), "{}", refused.message);
    let proof = build_of(&r, &r.claim, ProofOptions::default()).unwrap();
    assert!(!to_jcs(&proof).contains("A third line"), "an inclusion quittance carries no chunk");
    verify(&proof, &[], None, None, None).unwrap();
}

/// Codex review of 3fda096c, S5-01: a model's hypothesis enters no quittance (SPEC_V02_STEP5 section 0): the build refuses one, and
/// the check refuses a quittance that carries one, even on its true path in the journal.
#[test]
fn a_quittance_carries_no_hypothesis() {
    let path = temp("hypothesis");
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &[("d".to_string(), DOC.to_vec())], "proof-run", sha256(b"m"), &spec).unwrap();
    let lines = [
        observe("o1", "The first line names the rule."),
        json!({"kind": "hypothesis", "local_id": "h1", "text": "The rule may be older.", "falsifier": "A dated source.", "based_on": ["o1"]}),
    ];
    let r = s.submit_records_id("a", "worker", "w", &scope(), &lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    let (o1, h1) = (to_hex(&r.accepted[0].0), to_hex(&r.accepted[1].0));
    s.seal().unwrap();
    let frames = s.frame_hashes().to_vec();
    drop(s);
    let signer = NoteSigner::generate("operator").unwrap();
    let checkpoint = signer.sign(&checkpoint_body(&origin("proof-run"), &frames)).unwrap();
    let key = signer.verifier().text();
    let refused = build(&path.0, &h1, None, &checkpoint, Some(&key), ProofOptions::default()).unwrap_err();
    assert!(refused.message.contains("is a hypothesis"), "{}", refused.message);
    let mut proof = build(&path.0, &o1, None, &checkpoint, Some(&key), ProofOptions::default()).unwrap();
    verify(&proof, &[], None, None, None).unwrap();
    // the hypothesis put in by hand, with its true leaf and path in frame 1: the check refuses it all the same
    let mut values = Vec::new();
    AuditState::verify_states(&path.0, &mut |_, state, _| {
        if state.record_count() == 2 && values.is_empty() {
            values = (0..2).map(|i| state.record_leaf_value_at(i)).collect();
        }
    })
    .unwrap();
    let leaves: Vec<Hash> = values.iter().map(trees::record_leaf).collect();
    assert_eq!(values[1]["kind"], "hypothesis");
    let entry = json!({"value": values[1], "frame": 1, "index": 1, "path": hexes(&trees::records_path(&leaves, 1))});
    proof["records"].as_array_mut().unwrap().push(entry);
    proof["target"] = json!(h1);
    let refused = check(&proof).err().expect("a quittance with a hypothesis was accepted");
    assert!(refused.message.contains("no hypothesis"), "{}", refused.message);
}
