//! Signed checkpoints (SPEC_V02_STEP4): the standard texts of C2SP `signed-note` and the checkpoint of a real journal's seal.

use super::*;
use crate::audit::onto::AuditOntology;
use crate::audit::state::{AuditState, GenesisSpec};
use crate::audit::Scope;
use serde_json::json;

/// The example of the `signed-note` documentation (golang.org/x/mod/sumdb/note): keys, text and the signed note.
const SIGNER: &str = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
const VERIFIER: &str = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
const TEXT: &str = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n";
const SIGNED: &str = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n\n\u{2014} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";

#[test]
fn the_texts_of_signed_note_are_the_standards() {
    let signer = NoteSigner::parse(SIGNER).unwrap();
    assert_eq!(signer.text(), SIGNER);
    assert_eq!(signer.verifier().text(), VERIFIER);
    assert_eq!(NoteVerifier::parse(VERIFIER).unwrap(), signer.verifier());
    assert_eq!(signer.sign(TEXT).unwrap(), SIGNED, "Ed25519 is deterministic: the standard's signature, byte for byte");
    let note = open_note(SIGNED).unwrap();
    assert_eq!(note.body, TEXT);
    assert!(NoteVerifier::parse(VERIFIER).unwrap().signed(&note));
    // one byte of the body changed, or another key: not signed
    assert!(!signer.verifier().signed(&open_note(&SIGNED.replace("cryptography", "cryptographY")).unwrap()));
    let other = NoteSigner::generate("PeterNeumann").unwrap();
    assert!(!other.verifier().signed(&note), "same name, another key and id");
}

/// A weak verifier key, the identity point: under the cofactorless check a "signature" of R = identity and S = 0 verifies any text,
/// so whoever names such a key could deny every signature made with it. The key is refused, and the check of a note is strict.
#[test]
fn a_weak_verifier_key_is_refused_and_a_forged_signature_for_it_does_not_verify() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let name = "Weak";
    let id = key_id(name, &identity);
    let mut data = vec![ED25519];
    data.extend_from_slice(&identity);
    let refused = NoteVerifier::parse(&format!("{name}+{id:08x}+{}", base64(&data))).unwrap_err();
    assert!(refused.message.contains("weak"), "{refused}");
    let key = VerifyingKey::from_bytes(&identity).unwrap();
    let mut forged = [0u8; 64];
    forged[0] = 1;
    assert!(ed25519_dalek::Verifier::verify(&key, TEXT.as_bytes(), &Signature::from_bytes(&forged)).is_ok(), "the cofactorless check takes it");
    let line = base64(&[id.to_be_bytes().as_slice(), &forged].concat());
    let note = open_note(&format!("{TEXT}\n\u{2014} {name} {line}\n")).unwrap();
    assert!(!NoteVerifier { name: name.into(), id, key }.signed(&note), "the strict check refuses it");
}

#[test]
fn base64_has_one_spelling() {
    for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        assert_eq!(unbase64(&base64(bytes)).unwrap(), bytes);
    }
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"fo"), "Zm8=");
    for wrong in ["Zm8", "Zm9=", "Zm==Zm8=", "Zm8*"] {
        assert!(unbase64(wrong).is_none(), "{wrong}");
    }
}

#[test]
fn a_generated_key_round_trips_and_names_have_no_plus_or_space() {
    let signer = NoteSigner::generate("yuce-operator").unwrap();
    let again = NoteSigner::parse(&signer.text()).unwrap();
    assert_eq!(again.verifier(), signer.verifier());
    assert!(NoteSigner::generate("bad name").is_err() && NoteSigner::generate("a+b").is_err() && NoteSigner::generate("").is_err());
    // one character of the key changed, to one it is not (it was drawn at random: compare the character itself)
    let mut text = signer.text();
    let at = text.len() - 6;
    let other = if &text[at..=at] == "A" { "B" } else { "A" };
    text.replace_range(at..=at, other);
    assert_ne!(text, signer.text());
    assert!(NoteSigner::parse(&text).is_err() || NoteSigner::parse(&text).unwrap().verifier() != signer.verifier());
}

struct TempPath(std::path::PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn the_checkpoint_of_a_seal_names_the_journal_up_to_and_with_its_seal_frame() {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = TempPath(std::env::temp_dir().join(format!(
        "r2r_sign_{}_{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )));
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let mut s =
        AuditState::create_with(&path.0, &AuditOntology::base(), &[("d".to_string(), b"One line.\n".to_vec())], "signed-run", sha256(b"m"), &spec).unwrap();
    let scope = Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() };
    let r = s.submit_records_id(
        "a",
        "worker",
        "a",
        &scope,
        &[json!({"kind": "observe", "local_id": "o", "doc_id": "d", "exact_quote": "One line.", "terms": ["t"]})],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    s.seal().unwrap();
    let frames = s.frame_hashes().to_vec();
    s.close_run().unwrap();
    drop(s);
    let signer = NoteSigner::generate("operator").unwrap();
    let body = checkpoint_body(&origin("signed-run"), &frames);
    let note = signer.sign(&body).unwrap();
    let opened = open_note(&note).unwrap();
    assert!(signer.verifier().signed(&opened));
    let (o, size, root) = parse_checkpoint(&opened.body).unwrap();
    assert_eq!((o.as_str(), size), ("yuce/signed-run", 3), "genesis, the reading, the seal");
    check_against_journal(&path.0, &o, size, &root).unwrap();
    // the size of a frame that is no seal, a root of other frames, another run: refused
    assert!(check_against_journal(&path.0, &o, 2, &super::super::trees::log_root(&frames[..2])).is_err());
    assert!(check_against_journal(&path.0, &o, 3, &super::super::trees::log_root(&frames[..2])).is_err());
    assert!(check_against_journal(&path.0, "yuce/another-run", size, &root).is_err());
    assert!(check_against_journal(&path.0, &o, 99, &root).is_err());
}

/// Codex review of 904f1cdb, S4-01: a day compared as text is a day of the calendar first; else the check refuses, and a revoked key
/// is never let through by a day that is no day.
#[test]
fn an_anchored_day_is_a_day_of_the_calendar() {
    for day in ["2026-11-11", "2024-02-29", "2000-02-29", "0001-01-01", "9999-12-31"] {
        assert!(calendar_day(day), "{day}");
    }
    for day in ["!", "", "2026-13-01", "2026-00-10", "2026-02-30", "2025-02-29", "1900-02-29", "0000-01-01", "2026-1-01", "2026/11/11", "2026-11-11 "] {
        assert!(!calendar_day(day), "{day:?}");
    }
    let signer = NoteSigner::parse(SIGNER).unwrap();
    let note = open_note(SIGNED).unwrap();
    let revoked = parse_trusted_keys(&format!("{} role=operator revoked=2026-11-10\n", signer.verifier().text())).unwrap();
    for day in ["!", "2026-02-30", "0000-99-99"] {
        let v = signature_verdict(&note, &revoked, None, Some(day));
        assert!(v.refused, "{day:?}: {v:?}");
        assert_eq!(v.status, "the anchored day is not a calendar day YYYY-MM-DD");
    }
    assert!(!signature_verdict(&note, &revoked, None, Some("2026-11-09")).refused, "a real day before the revocation");
    assert!(signature_verdict(&note, &revoked, None, Some("2026-11-10")).refused, "the day of the revocation");
    assert!(parse_trusted_keys(&format!("{} role=operator revoked=2026-02-30\n", signer.verifier().text())).is_err());
}

/// S4-02: the days a key is valid hold for a revoked key as well; a day before them is refused, before or after the revocation.
#[test]
fn a_revoked_key_is_still_bound_to_the_days_it_was_valid() {
    let signer = NoteSigner::parse(SIGNER).unwrap();
    let note = open_note(SIGNED).unwrap();
    let keys =
        parse_trusted_keys(&format!("{} role=operator valid-after=2026-11-01 valid-before=2026-12-01 revoked=2026-11-10\n", signer.verifier().text())).unwrap();
    let at = |day: &str| signature_verdict(&note, &keys, None, Some(day));
    assert_eq!(at("2026-10-20").status, "key not valid on the anchored day");
    assert!(at("2026-10-20").refused);
    assert_eq!(at("2026-11-05").status, "signature valid, key pinned, signed before its revocation");
    assert!(!at("2026-11-05").refused);
    assert!(at("2026-11-10").refused, "revoked");
    assert!(at("2026-12-02").refused, "after its last day");
    assert!(signature_verdict(&note, &keys, None, None).refused, "revoked, and no day given");
}

/// S4-04: C2SP `signed-note` allows no control character but the line end anywhere in a note; a signature line of an unknown key
/// with one does not ride along with a valid signature.
#[test]
fn a_note_with_a_control_character_is_refused_whole() {
    let signer = NoteSigner::parse(SIGNER).unwrap();
    let with_unknown = format!("{SIGNED}\u{2014} unknown\u{0}key AAAAAAAA\n");
    assert!(open_note(&with_unknown).is_err());
    for c in ['\u{0}', '\t', '\r', '\u{1b}', '\u{1f}'] {
        assert!(open_note(&SIGNED.replacen("problem", &format!("prob{c}lem"), 1)).is_err(), "{c:?} in the body");
        assert!(signer.sign(&TEXT.replacen("problem", &format!("prob{c}lem"), 1)).is_err(), "{c:?} is never signed");
    }
    assert!(NoteSigner::generate("bad\u{0}name").is_err() && NoteSigner::generate("bad\u{7f}name").is_err());
    // what a note may hold still opens: the standard's note and one more valid signature line of another key
    let other = NoteSigner::generate("other").unwrap();
    let two = format!("{}{}", SIGNED, other.sign(TEXT).unwrap().rsplit_once("\n\n").unwrap().1);
    let opened = open_note(&two).unwrap();
    assert!(signer.verifier().signed(&opened) && other.verifier().signed(&opened));
}

/// The vectors of the reference implementation of `signed-note` (golang.org/x/mod/sumdb/note) and of its RFC 6962 tree
/// (golang.org/x/mod/sumdb/tlog), written by `scripts/signed_note_vectors`: keys, signed notes, notes opened with known keys, tree
/// roots. Go is needed only to write the file again.
const VECTORS: &str = include_str!("signed_note_vectors.json");

/// Where the kernel is stricter than the reference on purpose, and why.
const STRICTER: [(&str, &str); 4] = [
    ("name with a control character", "a note holds no control character, so such a key could verify no note"),
    ("weak key, the identity point", "a weak key verifies forged signatures"),
    ("a forged signature for a weak key", "a weak key is refused"),
    ("a signature whose base64 sets the unused padding bits", "base64 has one spelling"),
];

#[test]
fn signed_notes_hold_to_the_reference_implementation() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let stricter = |case: &str| STRICTER.iter().any(|(c, _)| *c == case);
    let cases = |k: &str| v[k].as_array().unwrap().clone();
    let mut checked = 0;
    // keys: their texts are the reference's, both ways
    let mut signers = std::collections::BTreeMap::new();
    for k in cases("keys") {
        let signer = NoteSigner::parse(k["skey"].as_str().unwrap()).unwrap();
        assert_eq!(signer.text(), k["skey"]);
        assert_eq!(signer.verifier().text(), k["vkey"]);
        assert_eq!(NoteVerifier::parse(k["vkey"].as_str().unwrap()).unwrap(), signer.verifier());
        signers.insert(k["name"].as_str().unwrap().to_string(), signer);
    }
    for c in cases("verifier_keys") {
        let case = c["case"].as_str().unwrap();
        let ours = NoteVerifier::parse(c["key"].as_str().unwrap()).is_ok();
        assert_eq!(ours, c["go"] == "ok" && !stricter(case), "verifier key, {case}: the reference says {}", c["go"]);
        checked += 1;
    }
    for c in cases("signer_keys") {
        let case = c["case"].as_str().unwrap();
        let ours = NoteSigner::parse(c["key"].as_str().unwrap()).is_ok();
        assert_eq!(ours, c["go"] == "ok" && !stricter(case), "signer key, {case}: the reference says {}", c["go"]);
        checked += 1;
    }
    // signed notes: one signer signs as the reference does, byte for byte, and every signer's key verifies the note
    for c in cases("signed") {
        let (case, text, note) = (c["case"].as_str().unwrap(), c["text"].as_str().unwrap(), c["note"].as_str().unwrap());
        let names: Vec<&str> = c["signers"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
        if let [one] = names[..] {
            match signers[one].sign(text) {
                Ok(ours) => assert_eq!(ours, note, "{case}"),
                // the kernel signs no body with a blank line: a checkpoint has none
                Err(_) => assert!(text.contains("\n\n"), "{case}: the kernel refused to sign it"),
            }
        }
        let known: Vec<NoteVerifier> = names.iter().map(|n| signers[*n].verifier()).collect();
        let known: Vec<&NoteVerifier> = known.iter().collect();
        assert_eq!(verified_by(&open_note(note).unwrap(), &known).unwrap().len(), names.len(), "{case}");
        checked += 1;
    }
    // notes opened with known keys: the keys that verify are the reference's
    for c in cases("open") {
        let case = c["case"].as_str().unwrap();
        let known: Vec<NoteVerifier> = c["known"].as_array().unwrap().iter().filter_map(|k| NoteVerifier::parse(k.as_str().unwrap()).ok()).collect();
        let known: Vec<&NoteVerifier> = known.iter().collect();
        let ours: Vec<String> = String::from_utf8(unbase64(c["msg_b64"].as_str().unwrap()).unwrap())
            .ok()
            .and_then(|m| open_note(&m).ok())
            .and_then(|n| verified_by(&n, &known).ok())
            .map(|keys| keys.iter().map(|k| k.name.clone()).collect())
            .unwrap_or_default();
        let reference: Vec<String> = c["verified"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect();
        let want = if stricter(case) { Vec::new() } else { reference };
        assert_eq!(ours, want, "open, {case}: the reference says {}", c["go"]);
        checked += 1;
    }
    // RFC 6962 roots over frame hashes
    let frames: Vec<Hash> = (0..1000).map(|i| sha256(format!("frame {i}").as_bytes())).collect();
    for t in cases("trees") {
        let n = t["size"].as_u64().unwrap() as usize;
        assert_eq!(crate::hash::to_hex(&crate::audit::trees::log_root(&frames[..n])), t["root"], "the tree of {n} frames");
        checked += 1;
    }
    assert!(checked > 100, "{checked} cases");
}
