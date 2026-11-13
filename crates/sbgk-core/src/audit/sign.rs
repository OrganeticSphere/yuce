//! Signed checkpoints of 0.2 (SPEC_V02_STEP4): a seal of a `/3` journal signed with Ed25519 in the C2SP `signed-note` format, as
//! a `tlog-checkpoint` whose root is the RFC 6962 tree over the journal's frames up to and with the seal frame. The journal does
//! not change: a checkpoint is a file beside it. The cryptography is `ed25519-dalek`'s; this module only writes and reads the
//! standard texts.
//!
//! A signature says only that the holder of the key claimed that the journal of this size has this root. An anchor out of the
//! writer's reach, and in 0.3 a witness, is what keeps the operator from rewriting it.

use super::persistence::AuditJournal;
use crate::error::{Code, KResult, KernelError};
use crate::hash::{sha256, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::Path;

/// The algorithm byte of an Ed25519 key in C2SP `signed-note`.
const ED25519: u8 = 0x01;
/// The line a signature line begins with: an em dash and a space.
const SIGNATURE_START: &str = "\u{2014} ";

fn bad(field: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field(field)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648), as the C2SP texts write it.
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            out.push(if i <= chunk.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// The bytes of a standard base64 text with padding; `None` for any other text.
pub fn unbase64(text: &str) -> Option<Vec<u8>> {
    let b = text.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (k, quad) in b.chunks(4).enumerate() {
        let last = k + 1 == b.len() / 4;
        let pad = quad.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in quad.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { B64.iter().position(|x| x == c)? as u32 };
            n |= v << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    // one spelling only: the text must be what the bytes encode to
    (base64(&out) == text).then_some(out)
}

/// The key id of C2SP `signed-note`: the first four bytes of SHA-256(name, a line end, the algorithm byte, the public key).
pub fn key_id(name: &str, public: &[u8; 32]) -> u32 {
    let mut data = name.as_bytes().to_vec();
    data.push(b'\n');
    data.push(ED25519);
    data.extend_from_slice(public);
    let h = sha256(&data);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

/// Random bytes from the system as lowercase hex: a token for a subject the server makes itself (`audit-serve --profile solo`).
pub fn random_hex(bytes: usize) -> KResult<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| bad("token", format!("no randomness from the system: {e}")))?;
    Ok(crate::hash::to_hex(&buf))
}

/// A key name of `signed-note`: not empty, no whitespace, no control character and no `+`.
fn key_name(name: &str) -> KResult<&str> {
    if name.is_empty() || name.contains('+') || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad("name", "a key name is not empty and has no whitespace, no control character and no '+'"));
    }
    Ok(name)
}

/// Whether a text holds an ASCII control character other than the line end, which C2SP `signed-note` forbids anywhere in a note
/// (Codex review of 904f1cdb, S4-04).
fn has_control(text: &str) -> bool {
    text.bytes().any(|b| b < 0x20 && b != b'\n')
}

/// Whether `v` is a day `YYYY-MM-DD` of the calendar, from 0001-01-01 on (Codex review of 904f1cdb, S4-01: a day compared as text
/// must be a day first).
pub fn calendar_day(v: &str) -> bool {
    let b = v.as_bytes();
    if !(b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())) {
        return false;
    }
    let number = |r: std::ops::Range<usize>| v[r].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    year >= 1 && (1..=days).contains(&day)
}

/// A signing key with its name. Its text (`PRIVATE+KEY+<name>+<id>+<base64>`) is written to a file and never printed.
pub struct NoteSigner {
    name: String,
    key: SigningKey,
}

impl NoteSigner {
    /// A new key from the system's randomness.
    pub fn generate(name: &str) -> KResult<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| bad("key", format!("no randomness from the system: {e}")))?;
        Ok(Self { name: key_name(name)?.to_string(), key: SigningKey::from_bytes(&seed) })
    }

    /// The text of a signing key file.
    pub fn parse(text: &str) -> KResult<Self> {
        let parts: Vec<&str> = text.trim_end().splitn(5, '+').collect();
        let [priv_, key, name, id, data] = parts[..] else { return Err(bad("signing_key", "expected PRIVATE+KEY+<name>+<id>+<base64>")) };
        let bytes = unbase64(data).filter(|b| priv_ == "PRIVATE" && key == "KEY" && b.len() == 33 && b[0] == ED25519);
        let bytes = bytes.ok_or_else(|| bad("signing_key", "not an Ed25519 signing key of signed-note"))?;
        let signer = Self { name: key_name(name)?.to_string(), key: SigningKey::from_bytes(bytes[1..].try_into().expect("32 bytes")) };
        if format!("{:08x}", signer.id()) != id {
            return Err(bad("signing_key", "the key id does not match the key"));
        }
        Ok(signer)
    }

    pub fn text(&self) -> String {
        let mut data = vec![ED25519];
        data.extend_from_slice(self.key.as_bytes());
        format!("PRIVATE+KEY+{}+{:08x}+{}", self.name, self.id(), base64(&data))
    }

    fn id(&self) -> u32 {
        key_id(&self.name, self.key.verifying_key().as_bytes())
    }

    /// The verifier key of this signer, to give to whoever checks.
    pub fn verifier(&self) -> NoteVerifier {
        NoteVerifier { name: self.name.clone(), id: self.id(), key: self.key.verifying_key() }
    }

    /// A signed note: the body (each line ending in a line end), a blank line and this key's signature line.
    pub fn sign(&self, body: &str) -> KResult<String> {
        if body.is_empty() || !body.ends_with('\n') || body.contains("\n\n") || has_control(body) {
            return Err(bad("body", "a note body is non-empty lines without control characters, each ending in a line end"));
        }
        let mut sig = self.id().to_be_bytes().to_vec();
        sig.extend_from_slice(&self.key.sign(body.as_bytes()).to_bytes());
        Ok(format!("{body}\n{SIGNATURE_START}{} {}\n", self.name, base64(&sig)))
    }
}

/// A verifier key of `signed-note`: `<name>+<id>+<base64(0x01, public key)>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteVerifier {
    pub name: String,
    pub id: u32,
    key: VerifyingKey,
}

impl NoteVerifier {
    pub fn parse(text: &str) -> KResult<Self> {
        let parts: Vec<&str> = text.trim().splitn(3, '+').collect();
        let [name, id, data] = parts[..] else { return Err(bad("verifier_key", "expected <name>+<id>+<base64>")) };
        let bytes = unbase64(data).filter(|b| b.len() == 33 && b[0] == ED25519).ok_or_else(|| bad("verifier_key", "not an Ed25519 verifier key"))?;
        let key = VerifyingKey::from_bytes(bytes[1..].try_into().expect("32 bytes")).map_err(|_| bad("verifier_key", "not a valid Ed25519 public key"))?;
        let v = Self { name: key_name(name)?.to_string(), id: key_id(name, key.as_bytes()), key };
        if format!("{:08x}", v.id) != id {
            return Err(bad("verifier_key", "the key id does not match the key"));
        }
        Ok(v)
    }

    pub fn text(&self) -> String {
        let mut data = vec![ED25519];
        data.extend_from_slice(self.key.as_bytes());
        format!("{}+{:08x}+{}", self.name, self.id, base64(&data))
    }
}

/// A note opened: its body and, for each signature line, the key name and id it names.
#[derive(Debug)]
pub struct OpenedNote {
    pub body: String,
    pub signatures: Vec<(String, u32, Vec<u8>)>,
}

/// The parts of a signed note: the body up to the blank line, then signature lines `— <name> <base64(id, signature)>`.
pub fn open_note(note: &str) -> KResult<OpenedNote> {
    if has_control(note) {
        return Err(bad("checkpoint", "a signed note holds no control character but the line end"));
    }
    let at = note.rfind("\n\n").ok_or_else(|| bad("checkpoint", "a signed note has a blank line before its signatures"))?;
    let (body, rest) = (&note[..=at], &note[at + 2..]);
    if !rest.ends_with('\n') || rest.len() < 2 {
        return Err(bad("checkpoint", "a signed note ends with its signature lines"));
    }
    let mut signatures = Vec::new();
    for line in rest[..rest.len() - 1].split('\n') {
        let line = line.strip_prefix(SIGNATURE_START).ok_or_else(|| bad("checkpoint", "a signature line begins with an em dash and a space"))?;
        let (name, data) = line.split_once(' ').ok_or_else(|| bad("checkpoint", "a signature line names its key and its signature"))?;
        let bytes = unbase64(data).filter(|b| b.len() > 4).ok_or_else(|| bad("checkpoint", "a signature is base64 of a key id and a signature"))?;
        signatures.push((name.to_string(), u32::from_be_bytes(bytes[..4].try_into().expect("4 bytes")), bytes[4..].to_vec()));
    }
    Ok(OpenedNote { body: body.to_string(), signatures })
}

impl NoteVerifier {
    /// Whether this key signed the note's body: a signature line with its name and id whose Ed25519 signature verifies.
    pub fn signed(&self, note: &OpenedNote) -> bool {
        note.signatures.iter().any(|(name, id, sig)| {
            *name == self.name && *id == self.id && Signature::from_slice(sig).is_ok_and(|s| self.key.verify(note.body.as_bytes(), &s).is_ok())
        })
    }
}

/// The body of a `tlog-checkpoint` for the frames `0..size` of a journal (SPEC_V02_STEP4 section 1, option A): its origin, the
/// number of frames, and the RFC 6962 root over their hashes.
pub fn checkpoint_body(origin: &str, frames: &[Hash]) -> String {
    format!("{origin}\n{}\n{}\n", frames.len(), base64(&super::trees::log_root(frames)))
}

/// The origin of a run's checkpoints.
pub fn origin(run_id: &str) -> String {
    format!("yuce/{run_id}")
}

/// A checkpoint's body read back: origin, size, root.
pub fn parse_checkpoint(body: &str) -> KResult<(String, usize, Hash)> {
    let lines: Vec<&str> = body.strip_suffix('\n').unwrap_or(body).split('\n').collect();
    let [origin, size, root] = lines[..] else { return Err(bad("checkpoint", "a checkpoint body here is three lines: origin, size, root")) };
    let size = size.parse::<usize>().ok().filter(|n| *n > 0 && *size == n.to_string()).ok_or_else(|| bad("checkpoint", "the size is a decimal number"))?;
    let root = unbase64(root).filter(|b| b.len() == 32).ok_or_else(|| bad("checkpoint", "the root is base64 of 32 bytes"))?;
    Ok((origin.to_string(), size, root.try_into().expect("32 bytes")))
}

/// Whether a checkpoint names a prefix of the `/3` journal at `path` that ends with a seal of the kernel: its size is a number of
/// frames of the journal, its root the log root over them, its last frame a seal frame and its origin the journal's run.
pub fn check_against_journal(path: &Path, origin_line: &str, size: usize, root: &Hash) -> KResult<()> {
    check_against_scan(&AuditJournal::read(path)?, origin_line, size, root)
}

/// `check_against_journal` over one read of the journal already made.
pub(crate) fn check_against_scan(scan: &super::persistence::JournalScan, origin_line: &str, size: usize, root: &Hash) -> KResult<()> {
    let refuse = |m: &str| Err(KernelError::new(Code::BadField, m.to_string()).field("checkpoint"));
    if scan.payloads.len() < size {
        return refuse("the checkpoint names more frames than the journal holds");
    }
    if super::trees::log_root(&scan.heads[..size]) != *root {
        return refuse("the checkpoint's root is not the log root of this journal's first frames");
    }
    let last = &scan.payloads[size - 1];
    if size < 2 || last["actor"] != "kernel" || last["command"]["kind"] != "seal" || last["outcome"]["kind"] != "value" {
        return refuse("the checkpoint's last frame is not a seal of the kernel");
    }
    if origin_line != origin(scan.payloads[0]["run_id"].as_str().unwrap_or_default()) {
        return refuse("the checkpoint's origin is not this journal's run");
    }
    Ok(())
}

/// One line of a trusted keys file (SPEC_V02_STEP4 section 4): a verifier key, its role, the days it is valid and the day it was
/// revoked, as `YYYY-MM-DD`.
#[derive(Clone, Debug)]
pub struct TrustedKey {
    pub verifier: NoteVerifier,
    pub role: String,
    pub valid_after: Option<String>,
    pub valid_before: Option<String>,
    pub revoked: Option<String>,
}

fn day(v: &str) -> KResult<String> {
    calendar_day(v).then(|| v.to_string()).ok_or_else(|| bad("trusted_keys", format!("a day is a calendar day YYYY-MM-DD, not {v:?}")))
}

/// The lines of a trusted keys file: `<verifier key> role=<role> [valid-after=..] [valid-before=..] [revoked=..]`; blank lines and
/// lines beginning with `#` are skipped.
pub fn parse_trusted_keys(text: &str) -> KResult<Vec<TrustedKey>> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut parts = line.split_whitespace();
        let verifier = NoteVerifier::parse(parts.next().unwrap_or_default())?;
        let mut key = TrustedKey { verifier, role: String::new(), valid_after: None, valid_before: None, revoked: None };
        for attr in parts {
            match attr.split_once('=') {
                Some(("role", v)) if !v.is_empty() => key.role = v.to_string(),
                Some(("valid-after", v)) => key.valid_after = Some(day(v)?),
                Some(("valid-before", v)) => key.valid_before = Some(day(v)?),
                Some(("revoked", v)) => key.revoked = Some(day(v)?),
                _ => return Err(bad("trusted_keys", format!("unknown attribute {attr:?}"))),
            }
        }
        if key.role.is_empty() {
            return Err(bad("trusted_keys", "every trusted key names its role"));
        }
        out.push(key);
    }
    Ok(out)
}

/// What a signed checkpoint's signature is worth (SPEC_V02_STEP4 section 5), and whether the check refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVerdict {
    pub status: &'static str,
    pub key: Option<String>,
    pub refused: bool,
    pub time: &'static str,
}

/// The verdict on a note's signatures: a trusted key that signed it, its dates against the day the checkpoint was anchored when the
/// checker gives one; else an untrusted verifier key the checker gave (`not pinned`); else no signature of a known key.
pub fn signature_verdict(note: &OpenedNote, trusted: &[TrustedKey], untrusted: Option<&NoteVerifier>, anchored_at: Option<&str>) -> SignatureVerdict {
    // the dates compare as text, which holds only for days of the calendar (Codex review of 904f1cdb, S4-01)
    if anchored_at.is_some_and(|a| !calendar_day(a)) {
        return SignatureVerdict { status: "the anchored day is not a calendar day YYYY-MM-DD", key: None, refused: true, time: "not pinned" };
    }
    let time = if anchored_at.is_some() { "anchored" } else { "not pinned" };
    if let Some(k) = trusted.iter().find(|k| k.verifier.signed(note)) {
        let key = Some(k.verifier.text());
        // the days a key is valid hold for a revoked key too (S4-02): before its first day it signed nothing that counts
        let outside = anchored_at.is_some_and(|a| k.valid_after.as_deref().is_some_and(|v| a < v) || k.valid_before.as_deref().is_some_and(|v| a >= v));
        if outside {
            return SignatureVerdict { status: "key not valid on the anchored day", key, refused: true, time };
        }
        if let Some(revoked) = &k.revoked {
            // a key revoked is refused, unless the checker kept the checkpoint from before the revocation (architect, 08.11)
            let before = anchored_at.is_some_and(|a| a < revoked.as_str());
            return SignatureVerdict {
                status: if before { "signature valid, key pinned, signed before its revocation" } else { "key revoked" },
                key,
                refused: !before,
                time,
            };
        }
        return SignatureVerdict { status: "signature valid, key pinned", key, refused: false, time };
    }
    match untrusted {
        Some(v) if v.signed(note) => SignatureVerdict { status: "signature valid, key not pinned", key: Some(v.text()), refused: false, time },
        Some(_) => SignatureVerdict { status: "signature not valid", key: None, refused: true, time },
        None => SignatureVerdict { status: "no signature of a known key", key: None, refused: true, time },
    }
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
