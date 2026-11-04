//! The audit session log: one hash-chained, durable frame per state transaction.
//!
//! `open` checks framing and integrity without changing the file. The caller must
//! replay and validate every returned payload before calling `finish_recovery`.
//! Only that final step may discard an unterminated, unacknowledged last frame.
//! V2 frames use exactly the canonical JSON emitted here, followed by one LF.
//! Noncanonical whitespace or duplicate object fields are rejected, not normalized.

use crate::error::{Code, KResult, KernelError};
use crate::hash::{from_hex, sha256, sha256_parts, to_hex, Hash, ZERO_HASH};
use crate::jcs::to_jcs;
use serde_json::{json, Value};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const FORMAT: &str = "sbgk-session-log/2";
const DOMAIN: &[u8] = b"R2R-AUDIT-WAL/2";
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 1024 * 1024 * 1024;
const FRAME_KEYS: [&str; 6] = ["format", "wal_op", "seq", "previous", "payload", "hash"];

#[derive(Debug)]
pub(crate) struct AuditJournal {
    file: File,
    path: PathBuf,
    dropped_tail: Option<(u64, PathBuf)>,
    seq: u64,
    head: Hash,
    complete_bytes: u64,
    opened_bytes: u64,
    ready: bool,
    poisoned: bool,
    #[cfg(test)]
    fail_sync_once: bool,
}

/// What a bounded read of the journal found: the payloads of its complete frames (genesis first), the chain head after each
/// frame, the bytes read (a torn tail included) and their SHA-256.
#[derive(Debug)]
pub(crate) struct JournalScan {
    pub payloads: Vec<Value>,
    pub heads: Vec<Hash>,
    pub bytes: u64,
    pub complete_bytes: u64,
    pub sha256: Hash,
}

fn error(message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field("audit_wal")
}

fn io_error(operation: &str, e: std::io::Error) -> KernelError {
    error(format!("audit WAL {operation}: {e}"))
}

fn lock(file: &File) -> KResult<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(error("audit WAL is in use by another writer")),
        Err(TryLockError::Error(e)) => Err(io_error("lock", e)),
    }
}

fn frame(seq: u64, previous: &Hash, payload: &Value) -> KResult<(Vec<u8>, Hash)> {
    let mut outer = json!({"format": FORMAT, "wal_op": if seq == 0 { "genesis" } else { "audit" },
        "seq": seq, "previous": to_hex(previous), "payload": payload});
    let canonical = to_jcs(&outer);
    let hash = sha256_parts(&[DOMAIN, canonical.as_bytes()]);
    outer["hash"] = json!(to_hex(&hash));
    let mut bytes = to_jcs(&outer).into_bytes();
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(error("audit WAL frame exceeds 64 MiB"));
    }
    Ok((bytes, hash))
}

impl AuditJournal {
    /// Create a new log. Existing paths, including empty files, are never replaced.
    pub(crate) fn create(path: &Path, genesis: &Value) -> KResult<Self> {
        let (bytes, hash) = frame(0, &ZERO_HASH, genesis)?;
        let file = OpenOptions::new().read(true).write(true).create_new(true).open(path).map_err(|e| io_error("create", e))?;
        lock(&file)?;
        let mut journal = Self {
            file,
            path: path.to_path_buf(),
            dropped_tail: None,
            seq: 0,
            head: ZERO_HASH,
            complete_bytes: 0,
            opened_bytes: 0,
            ready: true,
            poisoned: false,
            #[cfg(test)]
            fail_sync_once: false,
        };
        journal.write_frame(&bytes)?;
        journal.head = hash;
        Ok(journal)
    }

    /// Validate the complete frames, returning their payloads including genesis.
    /// The file stays untouched until the caller validates semantic replay.
    pub(crate) fn open(path: &Path) -> KResult<(Self, Vec<Value>)> {
        let mut file = OpenOptions::new().read(true).write(true).open(path).map_err(|e| io_error("open", e))?;
        lock(&file)?;
        let scan = Self::scan(&mut file)?;
        let journal = Self {
            file,
            path: path.to_path_buf(),
            dropped_tail: None,
            seq: (scan.payloads.len() - 1) as u64,
            head: *scan.heads.last().expect("a genesis frame"),
            complete_bytes: scan.complete_bytes,
            opened_bytes: scan.bytes,
            ready: false,
            poisoned: false,
            #[cfg(test)]
            fail_sync_once: false,
        };
        Ok((journal, scan.payloads))
    }

    /// The checks of `open` on a file opened for reading only and without the writer's lock: nothing can be cut or appended,
    /// and a journal that a live server is writing reads as the frames complete at that moment, or not at all where the server's
    /// lock blocks reading (Windows): check a stopped journal.
    pub(crate) fn read(path: &Path) -> KResult<JournalScan> {
        Self::scan(&mut File::open(path).map_err(|e| io_error("open", e))?)
    }

    /// Read at most `MAX_LOG_BYTES` (one byte more is a refusal, so a file that grows after the length check cannot slip
    /// past it) and validate every complete frame: canonical JSON, sequence, previous hash and frame hash.
    fn scan(file: &mut File) -> KResult<JournalScan> {
        if file.metadata().map_err(|e| io_error("metadata", e))?.len() > MAX_LOG_BYTES {
            return Err(error("audit WAL exceeds 1 GiB"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes).map_err(|e| io_error("read", e))?;
        if bytes.len() as u64 > MAX_LOG_BYTES {
            return Err(error("audit WAL exceeds 1 GiB"));
        }
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        if complete == 0 {
            return Err(error("audit WAL has no complete genesis frame"));
        }
        if bytes.len() - complete > MAX_FRAME_BYTES {
            return Err(error("audit WAL unterminated frame exceeds 64 MiB"));
        }
        let mut payloads = Vec::new();
        let mut heads = Vec::new();
        let mut previous = ZERO_HASH;
        for (index, line) in bytes[..complete - 1].split(|b| *b == b'\n').enumerate() {
            if line.len() + 1 > MAX_FRAME_BYTES {
                return Err(error(format!("audit WAL frame {index} exceeds 64 MiB")));
            }
            let mut value: Value = serde_json::from_slice(line).map_err(|e| error(format!("audit WAL frame {index}: bad JSON: {e}")))?;
            let outer = value.as_object().ok_or_else(|| error(format!("audit WAL frame {index} must be an object")))?;
            if outer.get("format").and_then(Value::as_str) != Some(FORMAT) {
                return Err(error(format!("audit WAL frame {index}: expected {FORMAT}; legacy or unknown format is not accepted")));
            }
            if outer.len() != FRAME_KEYS.len() || FRAME_KEYS.iter().any(|key| !outer.contains_key(*key)) {
                return Err(error(format!("audit WAL frame {index} has missing or unknown fields")));
            }
            if line != to_jcs(&value).as_bytes() {
                return Err(error(format!("audit WAL frame {index}: noncanonical JSON or duplicate fields")));
            }
            let seq = outer["seq"].as_u64().ok_or_else(|| error(format!("audit WAL frame {index}: seq must be a nonnegative integer")))?;
            if seq != index as u64 {
                return Err(error(format!("audit WAL frame {index}: sequence mismatch")));
            }
            let operation = if index == 0 { "genesis" } else { "audit" };
            if outer["wal_op"] != operation {
                return Err(error(format!("audit WAL frame {index}: expected wal_op {operation}")));
            }
            if outer["previous"].as_str().and_then(from_hex) != Some(previous) {
                return Err(error(format!("audit WAL frame {index}: previous hash mismatch")));
            }
            let claimed = outer["hash"].as_str().and_then(from_hex).ok_or_else(|| error(format!("audit WAL frame {index}: invalid hash")))?;
            value.as_object_mut().expect("checked object").remove("hash");
            let canonical = to_jcs(&value);
            let computed = sha256_parts(&[DOMAIN, canonical.as_bytes()]);
            if claimed != computed {
                return Err(error(format!("audit WAL frame {index}: hash mismatch")));
            }
            payloads.push(value["payload"].take());
            heads.push(computed);
            previous = computed;
        }
        Ok(JournalScan { payloads, heads, bytes: bytes.len() as u64, complete_bytes: complete as u64, sha256: sha256(&bytes) })
    }

    /// Called only after the parent has successfully replayed the payloads.
    pub(crate) fn finish_recovery(&mut self) -> KResult<()> {
        if self.poisoned {
            return Err(error("audit WAL writer is poisoned; reopen and replay before continuing"));
        }
        if self.ready {
            return Ok(());
        }
        let finish = (|| -> std::io::Result<()> {
            if self.file.metadata()?.len() != self.opened_bytes {
                return Err(std::io::Error::other("audit WAL length changed during recovery"));
            }
            if self.opened_bytes != self.complete_bytes {
                // usually what a crash left, but a lost line end looks the same: the bytes are kept beside the journal and the
                // caller reports them; a tail that cannot be kept stops the recovery
                self.dropped_tail = Some((self.opened_bytes - self.complete_bytes, self.keep_tail()?));
                self.file.set_len(self.complete_bytes)?;
            }
            self.file.seek(SeekFrom::End(0))?;
            self.file.sync_data()
        })();
        if let Err(e) = finish {
            self.poisoned = true;
            return Err(io_error("finish recovery", e));
        }
        self.opened_bytes = self.complete_bytes;
        self.ready = true;
        Ok(())
    }

    /// Write the bytes after the last complete frame to a new file beside the journal; an existing file is never replaced.
    fn keep_tail(&mut self) -> std::io::Result<PathBuf> {
        self.file.seek(SeekFrom::Start(self.complete_bytes))?;
        let mut tail = Vec::new();
        (&self.file).read_to_end(&mut tail)?;
        for n in 0..1000u32 {
            let suffix = if n == 0 { format!(".torn-{}", self.complete_bytes) } else { format!(".torn-{}-{n}", self.complete_bytes) };
            let mut name = self.path.clone().into_os_string();
            name.push(suffix);
            let path = PathBuf::from(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(&tail)?;
                    file.sync_all()?;
                    // the file's name too must outlive a power loss before the journal is cut (Windows has no such step)
                    #[cfg(unix)]
                    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                        File::open(parent)?.sync_all()?;
                    }
                    return Ok(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("no free name for the torn tail file"))
    }

    /// The tail that recovery cut off the journal: its size and the file that keeps it.
    pub(crate) fn dropped_tail(&self) -> Option<(u64, &Path)> {
        self.dropped_tail.as_ref().map(|(n, p)| (*n, p.as_path()))
    }

    /// Append and synchronize a whole transaction before acknowledging it.
    pub(crate) fn append(&mut self, payload: &Value) -> KResult<()> {
        if self.poisoned {
            return Err(error("audit WAL writer is poisoned; reopen and replay before continuing"));
        }
        if !self.ready {
            return Err(error("audit WAL semantic recovery must finish before append"));
        }
        let seq = self.seq.checked_add(1).ok_or_else(|| error("audit WAL sequence exhausted"))?;
        let (bytes, hash) = frame(seq, &self.head, payload)?;
        self.write_frame(&bytes)?;
        self.seq = seq;
        self.head = hash;
        Ok(())
    }

    fn write_frame(&mut self, bytes: &[u8]) -> KResult<()> {
        let total = self.complete_bytes.checked_add(bytes.len() as u64).filter(|n| *n <= MAX_LOG_BYTES).ok_or_else(|| error("audit WAL exceeds 1 GiB"))?;
        let result = (|| -> std::io::Result<()> {
            if self.file.metadata()?.len() != self.complete_bytes {
                return Err(std::io::Error::other("audit WAL length changed outside this writer"));
            }
            self.file.write_all(bytes)?;
            #[cfg(test)]
            if std::mem::take(&mut self.fail_sync_once) {
                return Err(std::io::Error::other("injected audit WAL sync failure"));
            }
            self.file.sync_data()
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(io_error("append/sync", e));
        }
        self.complete_bytes = total;
        self.opened_bytes = total;
        Ok(())
    }

    pub(crate) fn head(&self) -> Hash {
        self.head
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.seq
    }

    /// Simulate a full write followed by a failed durability barrier. The bytes
    /// may be replayable after reopening, but this writer must return no ACK.
    #[cfg(test)]
    pub(crate) fn inject_sync_failure_once(&mut self) {
        self.fail_sync_once = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempPath(PathBuf);

    impl TempPath {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            Self(std::env::temp_dir().join(format!("r2r_audit_wal_{}_{}_{}.jsonl", std::process::id(), time, NEXT.fetch_add(1, Ordering::Relaxed))))
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn committed() -> (TempPath, Vec<u8>) {
        let path = TempPath::new();
        let mut journal = AuditJournal::create(&path.0, &json!({"engine": "genesis", "audit": {}})).unwrap();
        journal.append(&json!({"command": "first", "receipt": {"accepted": 2}})).unwrap();
        journal.append(&json!({"command": "second", "cursor": 2})).unwrap();
        drop(journal);
        let bytes = std::fs::read(&path.0).unwrap();
        (path, bytes)
    }

    // Windows locks exclude reads through a different handle too. Inspect via
    // the owner and restore its cursor, so the test does not weaken the lock.
    fn snapshot(journal: &mut AuditJournal) -> Vec<u8> {
        let position = journal.file.stream_position().unwrap();
        journal.file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        journal.file.read_to_end(&mut bytes).unwrap();
        journal.file.seek(SeekFrom::Start(position)).unwrap();
        bytes
    }

    #[test]
    fn round_trip_returns_genesis_and_requires_semantic_recovery_before_append() {
        let (path, original) = committed();
        let (mut journal, payloads) = AuditJournal::open(&path.0).unwrap();
        assert_eq!(
            payloads,
            vec![json!({"engine": "genesis", "audit": {}}), json!({"command": "first", "receipt": {"accepted": 2}}), json!({"command": "second", "cursor": 2})]
        );
        assert_eq!(journal.sequence(), 2);
        let old_head = journal.head();
        assert!(journal.append(&json!({"command": "not yet"})).is_err());
        assert_eq!(snapshot(&mut journal), original);
        journal.finish_recovery().unwrap();
        journal.finish_recovery().unwrap();
        journal.append(&json!({"command": "third"})).unwrap();
        assert_eq!(journal.sequence(), 3);
        assert_ne!(journal.head(), old_head);
        let new_head = journal.head();
        drop(journal);
        let (back, payloads) = AuditJournal::open(&path.0).unwrap();
        assert_eq!(back.head(), new_head);
        assert_eq!(payloads.len(), 4);
        assert_eq!(payloads[3], json!({"command": "third"}));
    }

    #[test]
    fn an_existing_file_and_a_locked_log_are_never_replaced() {
        let path = TempPath::new();
        let mut owner = AuditJournal::create(&path.0, &json!({"genesis": true})).unwrap();
        let original = snapshot(&mut owner);
        assert!(AuditJournal::create(&path.0, &Value::Null).is_err());
        assert!(AuditJournal::open(&path.0).unwrap_err().message.contains("in use"));
        assert_eq!(snapshot(&mut owner), original);
        drop(owner);
        assert!(AuditJournal::open(&path.0).is_ok());
        let empty = TempPath::new();
        std::fs::write(&empty.0, []).unwrap();
        assert!(AuditJournal::create(&empty.0, &Value::Null).is_err());
        assert_eq!(std::fs::read(&empty.0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_torn_final_frame_is_untouched_until_successful_semantic_recovery() {
        let (path, original) = committed();
        let mut torn = original.clone();
        torn.extend_from_slice(b"{\"format\":\"sbgk-session-log/2\",\"payload\":\"");
        torn.extend_from_slice(&[0xf0, 0x9f]); // even a half-written UTF-8 code point belongs to the uncommitted tail
        std::fs::write(&path.0, &torn).unwrap();
        let (mut unvalidated, payloads) = AuditJournal::open(&path.0).unwrap();
        assert_eq!(payloads.len(), 3);
        assert_eq!(snapshot(&mut unvalidated), torn);
        assert!(unvalidated.append(&json!({})).is_err());
        drop(unvalidated); // a semantic replay failure must not truncate the original file
        assert_eq!(std::fs::read(&path.0).unwrap(), torn);
        let (mut recovered, _) = AuditJournal::open(&path.0).unwrap();
        recovered.finish_recovery().unwrap();
        assert_eq!(snapshot(&mut recovered), original);
        let (dropped, kept) = recovered.dropped_tail().map(|(n, p)| (n, p.to_path_buf())).expect("the tail is reported");
        assert_eq!(dropped as usize, torn.len() - original.len());
        assert_eq!(std::fs::read(&kept).unwrap(), torn[original.len()..]);
        recovered.append(&json!({"after_recovery": true})).unwrap();
        std::fs::remove_file(kept).unwrap();
    }

    #[test]
    fn a_complete_bad_frame_and_an_incomplete_genesis_fail_without_truncation() {
        let (path, original) = committed();
        for bytes in [b"{\"format\":\"sbgk-session-log/2\"".to_vec(), [original.as_slice(), b"{not JSON}\n"].concat()] {
            std::fs::write(&path.0, &bytes).unwrap();
            assert!(AuditJournal::open(&path.0).is_err());
            assert_eq!(std::fs::read(&path.0).unwrap(), bytes);
        }
    }

    #[test]
    fn hash_tampering_duplicate_removal_and_reordering_are_rejected() {
        let (path, original) = committed();
        let lines: Vec<&[u8]> = original.split_inclusive(|b| *b == b'\n').collect();
        let mut tampered: Value = serde_json::from_slice(lines[1]).unwrap();
        tampered["payload"]["receipt"]["accepted"] = json!(99);
        let changed = format!("{}\n", to_jcs(&tampered)).into_bytes();
        for bytes in [
            [lines[0], changed.as_slice(), lines[2]].concat(),
            [lines[0], lines[1], lines[1], lines[2]].concat(),
            [lines[0], lines[2]].concat(),
            [lines[0], lines[2], lines[1]].concat(),
        ] {
            std::fs::write(&path.0, &bytes).unwrap();
            assert!(AuditJournal::open(&path.0).is_err());
            assert_eq!(std::fs::read(&path.0).unwrap(), bytes);
        }
    }

    #[test]
    fn strict_outer_fields_and_integer_sequences_reject_legacy_or_ambiguous_frames() {
        let path = TempPath::new();
        let (bytes, _) = frame(0, &ZERO_HASH, &json!({})).unwrap();
        let good: Value = serde_json::from_slice(&bytes).unwrap();
        let mut variants = Vec::new();
        for seq in [json!(false), json!(-1), json!(0.0), json!("0")] {
            let mut value = good.clone();
            value["seq"] = seq;
            variants.push((value, "nonnegative integer"));
        }
        let mut unknown = good.clone();
        unknown["extra"] = json!(true);
        variants.push((unknown, "missing or unknown fields"));
        let mut missing_format = good.clone();
        missing_format.as_object_mut().unwrap().remove("format");
        variants.push((missing_format, "legacy or unknown format"));
        let mut missing_payload = good.clone();
        missing_payload.as_object_mut().unwrap().remove("payload");
        variants.push((missing_payload, "missing or unknown fields"));
        let mut wrong_genesis = good.clone();
        wrong_genesis["wal_op"] = json!("audit");
        variants.push((wrong_genesis, "expected wal_op genesis"));
        let mut legacy = good;
        legacy["format"] = json!("sbgk-session-log/1");
        variants.push((legacy, "legacy or unknown format"));
        for (value, expected) in variants {
            let raw = format!("{}\n", to_jcs(&value));
            std::fs::write(&path.0, &raw).unwrap();
            let refused = AuditJournal::open(&path.0).unwrap_err();
            assert!(refused.message.contains(expected), "{refused}");
            assert_eq!(std::fs::read_to_string(&path.0).unwrap(), raw);
        }
        let legacy = "{\"wal_op\":\"genesis\",\"format\":\"sbgk-session-log/1\",\"container_hex\":\"00\"}\n";
        std::fs::write(&path.0, legacy).unwrap();
        assert!(AuditJournal::open(&path.0).unwrap_err().message.contains("legacy or unknown format"));
        assert_eq!(std::fs::read_to_string(&path.0).unwrap(), legacy);
    }

    #[test]
    fn duplicate_fields_and_noncanonical_whitespace_are_rejected_without_rewriting() {
        let path = TempPath::new();
        let (bytes, _) = frame(0, &ZERO_HASH, &json!({"x": 1})).unwrap();
        let canonical = String::from_utf8(bytes).unwrap();
        for raw in
            [canonical.replacen("\"seq\":0", "\"seq\":0,\"seq\":0", 1), canonical.replacen("\"x\":1", "\"x\":0,\"x\":1", 1), canonical.replacen("{", "{ ", 1)]
        {
            std::fs::write(&path.0, &raw).unwrap();
            let refused = AuditJournal::open(&path.0).unwrap_err();
            assert!(refused.message.contains("noncanonical JSON"), "{refused}");
            assert_eq!(std::fs::read_to_string(&path.0).unwrap(), raw);
        }
    }

    #[test]
    fn an_io_failure_poisons_the_writer_and_never_advances_its_receipt_head() {
        let path = TempPath::new();
        let mut journal = AuditJournal::create(&path.0, &json!({"genesis": true})).unwrap();
        let original = snapshot(&mut journal);
        let head = journal.head();
        // A read-only replacement produces a deterministic write error on Windows and Unix.
        journal.file = File::open(&path.0).unwrap();
        assert!(journal.append(&json!({"must_not_ack": true})).is_err());
        assert_eq!(journal.head(), head);
        assert_eq!(journal.sequence(), 0);
        assert!(journal.append(&Value::Null).unwrap_err().message.contains("poisoned"));
        assert!(journal.finish_recovery().unwrap_err().message.contains("poisoned"));
        assert_eq!(std::fs::read(&path.0).unwrap(), original);
        drop(journal);
        let (mut back, payloads) = AuditJournal::open(&path.0).unwrap();
        assert_eq!(payloads.len(), 1);
        back.finish_recovery().unwrap();
        back.append(&json!({"reopened": true})).unwrap();
    }

    #[test]
    fn a_sync_failure_after_the_write_is_unacknowledged_but_replayable() {
        let path = TempPath::new();
        let mut journal = AuditJournal::create(&path.0, &json!({"genesis": true})).unwrap();
        let old_head = journal.head();
        let transaction = json!({"command": "accepted prefix", "receipt": {"submission_id": "once", "accepted": 2}});
        journal.inject_sync_failure_once();
        let failure = journal.append(&transaction).unwrap_err();
        assert!(failure.message.contains("injected audit WAL sync failure"));
        assert_eq!(journal.sequence(), 0, "no acknowledged sequence is published");
        assert_eq!(journal.head(), old_head, "no acknowledged head is published");
        assert_eq!(snapshot(&mut journal).iter().filter(|b| **b == b'\n').count(), 2, "the complete transaction reached write_all");
        assert!(journal.append(&transaction).unwrap_err().message.contains("poisoned"));
        drop(journal);
        // A successful write without a successful sync can survive. Recovery
        // includes its receipt so the parent can deduplicate the caller's retry.
        let (mut recovered, payloads) = AuditJournal::open(&path.0).unwrap();
        assert_eq!(payloads, vec![json!({"genesis": true}), transaction]);
        assert_eq!(recovered.sequence(), 1);
        assert_ne!(recovered.head(), old_head);
        recovered.finish_recovery().unwrap();
    }
}
