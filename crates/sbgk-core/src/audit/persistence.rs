//! The audit session log: one hash-chained, durable frame per state transaction.
//!
//! `open` checks framing and integrity without changing the file. The caller must
//! replay and validate every returned payload before calling `finish_recovery`.
//! Only that final step may discard an unterminated, unacknowledged last frame.
//! V2 frames use exactly the canonical JSON emitted here, followed by one LF.
//! Noncanonical whitespace or duplicate object fields are rejected, not normalized.
//!
//! A journal is written in one frame format from its genesis on. `sbgk-session-log/2` (0.1) hashes the whole frame;
//! `sbgk-session-log/3` (0.2, SPEC_V02_STEP2 section 1) splits it into a header and a body, and the frame hash covers the header,
//! which names the body by its hash and the records the frame accepted by the root of their tree. This layer checks the chain, the
//! body hashes and the frame hashes; the records root is the state's to check on replay.

use crate::error::{Code, KResult, KernelError};
use crate::hash::{from_hex, sha256, sha256_parts, to_hex, Hash, ZERO_HASH};
use crate::jcs::to_jcs;
use serde_json::{json, Value};
#[cfg(not(windows))]
use std::fs::TryLockError;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const FORMAT: &str = "sbgk-session-log/2";
pub(crate) const FORMAT_V3: &str = "sbgk-session-log/3";
const DOMAIN: &[u8] = b"R2R-AUDIT-WAL/2";
const HEADER_DOMAIN: &[u8] = b"R2R-FRAME-HDR/2\0";
const BODY_DOMAIN: &[u8] = b"R2R-FRAME-BODY/2\0";
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 1024 * 1024 * 1024;
const FRAME_KEYS: [&str; 6] = ["format", "wal_op", "seq", "previous", "payload", "hash"];
const FRAME_KEYS_V3: [&str; 3] = ["body", "hash", "header"];
const HEADER_KEYS: [&str; 6] = ["body_hash", "format", "previous", "records_root", "seq", "wal_op"];

/// The frame format of a journal, fixed by its genesis frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameFormat {
    V2,
    V3,
}

#[derive(Debug)]
pub(crate) struct AuditJournal {
    file: File,
    format: FrameFormat,
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
/// frame, the records root each `/3` frame names (empty for `/2`), the bytes read (a torn tail included) and their SHA-256.
///
/// A journal read while its writer held it is `live`: the read stops at the last frame complete at that moment, and the bytes
/// of a frame the writer had not finished (`in_flight`) are not a torn tail and are left out of `bytes` and of the hash.
#[derive(Debug)]
pub(crate) struct JournalScan {
    pub format: FrameFormat,
    pub payloads: Vec<Value>,
    pub heads: Vec<Hash>,
    pub records_roots: Vec<Hash>,
    pub bytes: u64,
    pub complete_bytes: u64,
    pub sha256: Hash,
    pub live: bool,
    pub in_flight: u64,
}

/// A hash as a `/3` journal spells it: 64 lowercase hex digits, nothing else (SPEC_V02_STEP2 section 1).
pub(crate) fn lower_hex(v: &Value) -> Option<Hash> {
    let s = v.as_str()?;
    from_hex(s).filter(|h| to_hex(h) == s)
}

/// The deepest a frame of a `/3` journal nests, its outer object counting one (architect, 11.11.2026): any reader with that much
/// room reads every journal, far under the 128 levels the kernel's own reader allows.
pub(crate) const MAX_FRAME_DEPTH: usize = 64;

/// The depth of a JSON value: a scalar 0, an object or array one more than its deepest member.
pub(crate) fn json_depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(m) => 1 + m.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Whether every number in `v` is an integer from 0 to 2^53-1, the only numbers of a `/3` journal (SPEC_V02_STEP2 section 1): a
/// reader in another language parses them exactly, and RFC 8785 writes them one way.
pub(crate) fn safe_integers(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.as_u64().is_some_and(|n| n < 1 << 53),
        Value::Array(a) => a.iter().all(safe_integers),
        Value::Object(m) => m.values().all(safe_integers),
        _ => true,
    }
}

impl JournalScan {
    /// The first `n` frames only, for a replay up to that point (`AuditState::replay_own`).
    pub(crate) fn keep_first(&mut self, n: usize) {
        self.payloads.truncate(n);
        self.heads.truncate(n);
        self.records_roots.truncate(n);
    }
}

fn error(message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field("audit_wal")
}

fn io_error(operation: &str, e: std::io::Error) -> KernelError {
    error(format!("audit WAL {operation}: {e}"))
}

/// Windows share modes and an error code (winnt.h, winerror.h): what another handle of the file may do, and a read refused by a
/// lock.
#[cfg(windows)]
mod windows {
    pub const FILE_SHARE_READ: u32 = 0x1;
    pub const FILE_SHARE_DELETE: u32 = 0x4;
    pub const ERROR_LOCK_VIOLATION: i32 = 33;
}

/// The Windows error of an open that another handle of the file does not allow (winerror.h).
const ERROR_SHARING_VIOLATION: i32 = 32;

/// How often and how long a writer asks again for a journal that is held: a reading tool asks for a moment whether a writer is
/// there (`writer_present`), and a server that starts in that moment must not be told that another server runs.
const HOLD_RETRIES: u32 = 5;
const HOLD_WAIT: std::time::Duration = std::time::Duration::from_millis(40);

fn in_use() -> KernelError {
    error(if cfg!(windows) {
        "audit WAL is in use by another writer, or by a program that has it open and shares it with no writer"
    } else {
        "audit WAL is in use by another writer"
    })
}

/// The writer's handle of the journal at `path`, a new file with `create`: one writer holds a journal, and no reader waits for it.
///
/// On Windows the writer opens the file sharing it for reading only (and for deletion, as before): every other open that asks to
/// write is refused by the system while this handle lives, and this open is refused while any other handle may write. That
/// excludes a second server of this version and one of 0.2.0 or earlier alike, in either order: the earlier server opens the file
/// to write before it locks it. The file is not locked, since a lock there (`File::try_lock`, LockFileEx over the whole file)
/// is mandatory and stopped every read through another handle too, the reading tools included. Elsewhere the lock is advisory
/// (flock): it excludes writers, the earlier ones too, and stops no reader, so it stays.
fn hold(path: &Path, create: bool) -> KResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, windows::FILE_SHARE_READ | windows::FILE_SHARE_DELETE);
    let mut asked = 0;
    let file = loop {
        match options.open(path) {
            Ok(file) => break file,
            Err(e) if shared_with_no_writer(&e) && asked < HOLD_RETRIES => {
                asked += 1;
                std::thread::sleep(HOLD_WAIT);
            }
            Err(e) if shared_with_no_writer(&e) => return Err(in_use()),
            Err(e) => return Err(io_error(if create { "create" } else { "open" }, e)),
        }
    };
    lock(&file, asked)?;
    Ok(file)
}

/// Whether an open was refused because another handle of the file does not allow it (Windows only).
fn shared_with_no_writer(e: &std::io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
}

/// The writer's advisory lock where the system has one that stops no reader; `asked` counts the retries already spent.
#[cfg(not(windows))]
fn lock(file: &File, mut asked: u32) -> KResult<()> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if asked < HOLD_RETRIES => {
                asked += 1;
                std::thread::sleep(HOLD_WAIT);
            }
            Err(TryLockError::WouldBlock) => return Err(in_use()),
            Err(TryLockError::Error(e)) => return Err(io_error("lock", e)),
        }
    }
}

/// On Windows the share mode of the writer's handle is the exclusion (`hold`).
#[cfg(windows)]
fn lock(_file: &File, _asked: u32) -> KResult<()> {
    Ok(())
}

/// Whether a writer holds the journal at `path` at this moment, asked without waiting and without writing: on Windows by an
/// open for reading that shares the file with no writer, refused exactly while a handle that may write lives; elsewhere by a
/// shared lock, refused exactly while the writer's exclusive lock is held. Either is given up at once. A file that cannot be
/// opened has no writer here: the read that follows says why.
pub(crate) fn writer_present(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, windows::FILE_SHARE_READ | windows::FILE_SHARE_DELETE);
        matches!(options.open(path), Err(e) if shared_with_no_writer(&e))
    }
    #[cfg(not(windows))]
    {
        File::open(path).is_ok_and(|file| matches!(file.try_lock_shared(), Err(TryLockError::WouldBlock)))
    }
}

/// A read refused by a lock over the whole file, which a server of 0.2.0 or earlier holds on Windows: said in words, since the
/// system's own message names neither the server nor what to do.
fn read_error(e: std::io::Error) -> KernelError {
    #[cfg(windows)]
    if e.raw_os_error() == Some(windows::ERROR_LOCK_VIOLATION) {
        return error(LOCKED_WHOLE);
    }
    io_error("read", e)
}

/// What a reader is told of a journal locked whole.
pub const LOCKED_WHOLE: &str = "the journal is locked whole by a running server, as a server of 0.2.0 or earlier locks it on Windows: \
                                it cannot be read while that server runs; stop it, or serve the journal with a later version";

fn frame(seq: u64, previous: &Hash, payload: &Value) -> KResult<(Vec<u8>, Hash)> {
    let mut outer = json!({"format": FORMAT, "wal_op": if seq == 0 { "genesis" } else { "audit" },
        "seq": seq, "previous": to_hex(previous), "payload": payload});
    let canonical = to_jcs(&outer);
    let hash = sha256_parts(&[DOMAIN, canonical.as_bytes()]);
    outer["hash"] = json!(to_hex(&hash));
    sized(to_jcs(&outer).into_bytes(), hash)
}

/// The body hash of a `/3` frame: `H("R2R-FRAME-BODY/2", JCS(body))`.
pub(crate) fn body_hash(body: &Value) -> Hash {
    sha256_parts(&[BODY_DOMAIN, to_jcs(body).as_bytes()])
}

/// The header of a `/3` frame (SPEC_V02_STEP2 section 1); a quittance carries it without the body.
pub(crate) fn header_v3(seq: u64, previous: &Hash, body_hash: &Hash, records_root: &Hash) -> Value {
    json!({"body_hash": to_hex(body_hash), "format": FORMAT_V3, "previous": to_hex(previous),
        "records_root": to_hex(records_root), "seq": seq, "wal_op": if seq == 0 { "genesis" } else { "audit" }})
}

/// The keys of a `/3` frame header, in JCS order.
pub(crate) const HEADER_KEYS_V3: [&str; 6] = HEADER_KEYS;

/// The hash of a `/3` frame: `H("R2R-FRAME-HDR/2", JCS(header))`.
pub(crate) fn header_hash(header: &Value) -> Hash {
    sha256_parts(&[HEADER_DOMAIN, to_jcs(header).as_bytes()])
}

fn frame_v3(seq: u64, previous: &Hash, body: &Value, records_root: &Hash) -> KResult<(Vec<u8>, Hash)> {
    let header = header_v3(seq, previous, &body_hash(body), records_root);
    let hash = header_hash(&header);
    let frame = json!({"body": body, "hash": to_hex(&hash), "header": header});
    // the reader's limits of a `/3` frame hold for every frame the writer makes, the genesis included, which no command check
    // sees (Codex review of 904f1cdb, S4-06): nothing is written that the journal's own check would refuse
    if !safe_integers(&frame) {
        return Err(error("a frame of a 0.2 journal holds only integers from 0 to 2^53-1"));
    }
    if json_depth(&frame) > MAX_FRAME_DEPTH {
        return Err(error("a frame of a 0.2 journal nests at most 64 levels"));
    }
    sized(to_jcs(&frame).into_bytes(), hash)
}

fn sized(mut bytes: Vec<u8>, hash: Hash) -> KResult<(Vec<u8>, Hash)> {
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(error("audit WAL frame exceeds 64 MiB"));
    }
    Ok((bytes, hash))
}

fn encode(format: FrameFormat, seq: u64, previous: &Hash, payload: &Value, records_root: Option<&Hash>) -> KResult<(Vec<u8>, Hash)> {
    match (format, records_root) {
        (FrameFormat::V2, None) => frame(seq, previous, payload),
        (FrameFormat::V3, Some(root)) => frame_v3(seq, previous, payload, root),
        (FrameFormat::V2, Some(_)) => Err(error("a sbgk-session-log/2 frame names no records root")),
        (FrameFormat::V3, None) => Err(error("a sbgk-session-log/3 frame needs its records root")),
    }
}

impl AuditJournal {
    /// Create a new log. Existing paths, including empty files, are never replaced. A `/3` genesis names the records root of its
    /// frame (the empty root); a `/2` genesis names none.
    pub(crate) fn create(path: &Path, genesis: &Value, format: FrameFormat, records_root: Option<&Hash>) -> KResult<Self> {
        let (bytes, hash) = encode(format, 0, &ZERO_HASH, genesis, records_root)?;
        let file = hold(path, true)?;
        let mut journal = Self {
            file,
            format,
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

    /// Validate the complete frames, returning what the scan found, payloads from genesis on.
    /// The file stays untouched until the caller validates semantic replay.
    pub(crate) fn open(path: &Path) -> KResult<(Self, JournalScan)> {
        let mut file = hold(path, false)?;
        let scan = Self::scan(&mut file)?;
        let journal = Self {
            file,
            format: scan.format,
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
        Ok((journal, scan))
    }

    /// The checks of `open` on a file opened for reading only and without the writer's hold: nothing can be cut or appended.
    ///
    /// A journal that a server is writing reads as the frames complete at that moment (`live`). Bytes after the last complete
    /// frame are a frame in flight while a writer holds the journal, and a torn tail when none does: the writer is asked for
    /// before the read and, when such bytes were read with no writer before, once more after it, so the tail of a stopped journal
    /// is always reported as torn. A writer that died between the two leaves a torn tail the next read reports.
    pub(crate) fn read(path: &Path) -> KResult<JournalScan> {
        let held = writer_present(path);
        let mut bytes = Self::slurp(&mut File::open(path).map_err(|e| io_error("open", e))?)?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let live = held || (bytes.len() > complete && writer_present(path));
        let in_flight = if live { bytes.len() - complete } else { 0 };
        if live {
            bytes.truncate(complete);
        }
        let mut scan = Self::check(&bytes)?;
        scan.live = live;
        scan.in_flight = in_flight as u64;
        Ok(scan)
    }

    /// The checks of `read` through the writer's own handle: the frames written so far, for a live server's reading tools
    /// (SPEC_V02_STEP3). The cursor goes back where it was, and the writer appends on.
    pub(crate) fn scan_own(&mut self) -> KResult<JournalScan> {
        let position = self.file.stream_position().map_err(|e| io_error("seek", e))?;
        self.file.seek(SeekFrom::Start(0)).map_err(|e| io_error("seek", e))?;
        let scan = Self::scan(&mut self.file);
        // a writer whose place could not be restored writes nothing more (Codex review of 2c6864f): reopen and replay first
        if let Err(e) = self.file.seek(SeekFrom::Start(position)) {
            self.poisoned = true;
            return Err(io_error("seek", e));
        }
        scan
    }

    /// Read at most `MAX_LOG_BYTES` (one byte more is a refusal, so a file that grows after the length check cannot slip
    /// past it) and validate every complete frame: canonical JSON, sequence, previous hash and frame hash.
    fn scan(file: &mut File) -> KResult<JournalScan> {
        Self::check(&Self::slurp(file)?)
    }

    /// The bytes of the journal, at most `MAX_LOG_BYTES`.
    fn slurp(file: &mut File) -> KResult<Vec<u8>> {
        if file.metadata().map_err(|e| io_error("metadata", e))?.len() > MAX_LOG_BYTES {
            return Err(error("audit WAL exceeds 1 GiB"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes).map_err(read_error)?;
        if bytes.len() as u64 > MAX_LOG_BYTES {
            return Err(error("audit WAL exceeds 1 GiB"));
        }
        Ok(bytes)
    }

    /// The checks of every complete frame among `bytes`.
    fn check(bytes: &[u8]) -> KResult<JournalScan> {
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        if complete == 0 {
            return Err(error("audit WAL has no complete genesis frame"));
        }
        if bytes.len() - complete > MAX_FRAME_BYTES {
            return Err(error("audit WAL unterminated frame exceeds 64 MiB"));
        }
        let mut payloads = Vec::new();
        let mut heads = Vec::new();
        let mut records_roots = Vec::new();
        let mut previous = ZERO_HASH;
        let mut format = None;
        for (index, line) in bytes[..complete - 1].split(|b| *b == b'\n').enumerate() {
            if line.len() + 1 > MAX_FRAME_BYTES {
                return Err(error(format!("audit WAL frame {index} exceeds 64 MiB")));
            }
            let mut value: Value = serde_json::from_slice(line).map_err(|e| error(format!("audit WAL frame {index}: bad JSON: {e}")))?;
            let outer = value.as_object().ok_or_else(|| error(format!("audit WAL frame {index} must be an object")))?;
            // the genesis frame fixes the format of the journal; a frame of the other format later fails that format's checks
            let this = *format.get_or_insert(if outer.contains_key("header") { FrameFormat::V3 } else { FrameFormat::V2 });
            if this == FrameFormat::V3 {
                let (body, head, records_root) = Self::check_v3(index, line, value, &previous)?;
                payloads.push(body);
                heads.push(head);
                records_roots.push(records_root);
                previous = head;
                continue;
            }
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
        Ok(JournalScan {
            format: format.expect("a complete genesis frame"),
            payloads,
            heads,
            records_roots,
            bytes: bytes.len() as u64,
            complete_bytes: complete as u64,
            sha256: sha256(bytes),
            live: false,
            in_flight: 0,
        })
    }

    /// The checks of one `/3` frame: exact fields, canonical bytes, sequence, chain, body hash and frame hash. Returns the body,
    /// the frame hash and the records root its header names.
    fn check_v3(index: usize, line: &[u8], mut value: Value, previous: &Hash) -> KResult<(Value, Hash, Hash)> {
        let at = |message: &str| error(format!("audit WAL frame {index}: {message}"));
        let outer = value.as_object().expect("checked object");
        if outer.len() != FRAME_KEYS_V3.len() || FRAME_KEYS_V3.iter().any(|key| !outer.contains_key(*key)) {
            return Err(error(format!("audit WAL frame {index} has missing or unknown fields")));
        }
        let header = outer["header"].as_object().ok_or_else(|| at("header must be an object"))?;
        if header.get("format").and_then(Value::as_str) != Some(FORMAT_V3) {
            return Err(at(&format!("expected {FORMAT_V3}; a frame of another format is not accepted in this journal")));
        }
        if header.len() != HEADER_KEYS.len() || HEADER_KEYS.iter().any(|key| !header.contains_key(*key)) {
            return Err(error(format!("audit WAL frame {index} header has missing or unknown fields")));
        }
        if line != to_jcs(&value).as_bytes() {
            return Err(at("noncanonical JSON or duplicate fields"));
        }
        // the one form of a number in a `/3` frame (SPEC_V02_STEP2 section 1): another reader parses no float or big integer
        // differently
        if !safe_integers(&value) {
            return Err(at("a number that is not an integer from 0 to 2^53-1"));
        }
        if json_depth(&value) > MAX_FRAME_DEPTH {
            return Err(at("a frame nests deeper than 64 levels"));
        }
        let seq = header["seq"].as_u64().ok_or_else(|| at("seq must be a nonnegative integer"))?;
        if seq != index as u64 {
            return Err(at("sequence mismatch"));
        }
        let operation = if index == 0 { "genesis" } else { "audit" };
        if header["wal_op"] != operation {
            return Err(at(&format!("expected wal_op {operation}")));
        }
        // a hash is spelled one way only, 64 lowercase hex digits: the frame hash is outside every hash, and a capital there
        // would make another file of the same journal
        if lower_hex(&header["previous"]) != Some(*previous) {
            return Err(at("previous hash mismatch"));
        }
        let records_root = lower_hex(&header["records_root"]).ok_or_else(|| at("invalid records root"))?;
        if lower_hex(&header["body_hash"]) != Some(body_hash(&outer["body"])) {
            return Err(at("body hash mismatch"));
        }
        let computed = sha256_parts(&[HEADER_DOMAIN, to_jcs(&outer["header"]).as_bytes()]);
        if lower_hex(&outer["hash"]) != Some(computed) {
            return Err(at("hash mismatch"));
        }
        Ok((value["body"].take(), computed, records_root))
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
                    // a filesystem that cannot sync a folder must not stop a recovery whose file is already synced
                    #[cfg(unix)]
                    let _ = File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))).and_then(|dir| dir.sync_all());
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

    /// Append and synchronize a whole transaction before acknowledging it. A `/3` journal takes the records root of the frame.
    pub(crate) fn append(&mut self, payload: &Value, records_root: Option<&Hash>) -> KResult<()> {
        if self.poisoned {
            return Err(error("audit WAL writer is poisoned; reopen and replay before continuing"));
        }
        if !self.ready {
            return Err(error("audit WAL semantic recovery must finish before append"));
        }
        let seq = self.seq.checked_add(1).ok_or_else(|| error("audit WAL sequence exhausted"))?;
        let (bytes, hash) = encode(self.format, seq, &self.head, payload, records_root)?;
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

    #[cfg(test)]
    pub(crate) fn format(&self) -> FrameFormat {
        self.format
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
        let mut journal = AuditJournal::create(&path.0, &json!({"engine": "genesis", "audit": {}}), FrameFormat::V2, None).unwrap();
        journal.append(&json!({"command": "first", "receipt": {"accepted": 2}}), None).unwrap();
        journal.append(&json!({"command": "second", "cursor": 2}), None).unwrap();
        drop(journal);
        let bytes = std::fs::read(&path.0).unwrap();
        (path, bytes)
    }

    // Inspect via the owner and restore its cursor: what the writer itself sees of its file.
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
        let (mut journal, scan) = AuditJournal::open(&path.0).unwrap();
        let payloads = scan.payloads;
        assert_eq!(
            payloads,
            vec![json!({"engine": "genesis", "audit": {}}), json!({"command": "first", "receipt": {"accepted": 2}}), json!({"command": "second", "cursor": 2})]
        );
        assert_eq!(journal.sequence(), 2);
        let old_head = journal.head();
        assert!(journal.append(&json!({"command": "not yet"}), None).is_err());
        assert_eq!(snapshot(&mut journal), original);
        journal.finish_recovery().unwrap();
        journal.finish_recovery().unwrap();
        journal.append(&json!({"command": "third"}), None).unwrap();
        assert_eq!(journal.sequence(), 3);
        assert_ne!(journal.head(), old_head);
        let new_head = journal.head();
        drop(journal);
        let (back, scan) = AuditJournal::open(&path.0).unwrap();
        let payloads = scan.payloads;
        assert_eq!(back.head(), new_head);
        assert_eq!(payloads.len(), 4);
        assert_eq!(payloads[3], json!({"command": "third"}));
    }

    #[test]
    fn an_existing_file_and_a_locked_log_are_never_replaced() {
        let path = TempPath::new();
        let mut owner = AuditJournal::create(&path.0, &json!({"genesis": true}), FrameFormat::V2, None).unwrap();
        let original = snapshot(&mut owner);
        assert!(AuditJournal::create(&path.0, &Value::Null, FrameFormat::V2, None).is_err());
        assert!(AuditJournal::open(&path.0).unwrap_err().message.contains("in use"));
        assert_eq!(snapshot(&mut owner), original);
        drop(owner);
        assert!(AuditJournal::open(&path.0).is_ok());
        let empty = TempPath::new();
        std::fs::write(&empty.0, []).unwrap();
        assert!(AuditJournal::create(&empty.0, &Value::Null, FrameFormat::V2, None).is_err());
        assert_eq!(std::fs::read(&empty.0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_torn_final_frame_is_untouched_until_successful_semantic_recovery() {
        let (path, original) = committed();
        let mut torn = original.clone();
        torn.extend_from_slice(b"{\"format\":\"sbgk-session-log/2\",\"payload\":\"");
        torn.extend_from_slice(&[0xf0, 0x9f]); // even a half-written UTF-8 code point belongs to the uncommitted tail
        std::fs::write(&path.0, &torn).unwrap();
        let (mut unvalidated, scan) = AuditJournal::open(&path.0).unwrap();
        let payloads = scan.payloads;
        assert_eq!(payloads.len(), 3);
        assert_eq!(snapshot(&mut unvalidated), torn);
        assert!(unvalidated.append(&json!({}), None).is_err());
        drop(unvalidated); // a semantic replay failure must not truncate the original file
        assert_eq!(std::fs::read(&path.0).unwrap(), torn);
        let (mut recovered, _) = AuditJournal::open(&path.0).unwrap();
        recovered.finish_recovery().unwrap();
        assert_eq!(snapshot(&mut recovered), original);
        let (dropped, kept) = recovered.dropped_tail().map(|(n, p)| (n, p.to_path_buf())).expect("the tail is reported");
        assert_eq!(dropped as usize, torn.len() - original.len());
        assert_eq!(std::fs::read(&kept).unwrap(), torn[original.len()..]);
        recovered.append(&json!({"after_recovery": true}), None).unwrap();
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
        let mut journal = AuditJournal::create(&path.0, &json!({"genesis": true}), FrameFormat::V2, None).unwrap();
        let original = snapshot(&mut journal);
        let head = journal.head();
        // A read-only replacement produces a deterministic write error on Windows and Unix.
        journal.file = File::open(&path.0).unwrap();
        assert!(journal.append(&json!({"must_not_ack": true}), None).is_err());
        assert_eq!(journal.head(), head);
        assert_eq!(journal.sequence(), 0);
        assert!(journal.append(&Value::Null, None).unwrap_err().message.contains("poisoned"));
        assert!(journal.finish_recovery().unwrap_err().message.contains("poisoned"));
        assert_eq!(std::fs::read(&path.0).unwrap(), original);
        drop(journal);
        let (mut back, scan) = AuditJournal::open(&path.0).unwrap();
        let payloads = scan.payloads;
        assert_eq!(payloads.len(), 1);
        back.finish_recovery().unwrap();
        back.append(&json!({"reopened": true}), None).unwrap();
    }

    #[test]
    fn a_sync_failure_after_the_write_is_unacknowledged_but_replayable() {
        let path = TempPath::new();
        let mut journal = AuditJournal::create(&path.0, &json!({"genesis": true}), FrameFormat::V2, None).unwrap();
        let old_head = journal.head();
        let transaction = json!({"command": "accepted prefix", "receipt": {"submission_id": "once", "accepted": 2}});
        journal.inject_sync_failure_once();
        let failure = journal.append(&transaction, None).unwrap_err();
        assert!(failure.message.contains("injected audit WAL sync failure"));
        assert_eq!(journal.sequence(), 0, "no acknowledged sequence is published");
        assert_eq!(journal.head(), old_head, "no acknowledged head is published");
        assert_eq!(snapshot(&mut journal).iter().filter(|b| **b == b'\n').count(), 2, "the complete transaction reached write_all");
        assert!(journal.append(&transaction, None).unwrap_err().message.contains("poisoned"));
        drop(journal);
        // A successful write without a successful sync can survive. Recovery
        // includes its receipt so the parent can deduplicate the caller's retry.
        let (mut recovered, scan) = AuditJournal::open(&path.0).unwrap();
        let payloads = scan.payloads;
        assert_eq!(payloads, vec![json!({"genesis": true}), transaction]);
        assert_eq!(recovered.sequence(), 1);
        assert_ne!(recovered.head(), old_head);
        recovered.finish_recovery().unwrap();
    }

    #[test]
    fn a_held_journal_is_read_to_its_last_complete_frame_and_a_frame_in_flight_is_no_torn_tail() {
        let path = TempPath::new();
        let mut writer = AuditJournal::create(&path.0, &json!({"genesis": true}), FrameFormat::V2, None).unwrap();
        writer.append(&json!({"command": "first"}), None).unwrap();
        // another handle reads while the writer holds the journal, and is told so
        let held = AuditJournal::read(&path.0).unwrap();
        assert_eq!((held.payloads.len(), held.live, held.in_flight), (2, true, 0));
        assert_eq!(held.bytes, held.complete_bytes);
        let complete = std::fs::read(&path.0).unwrap();
        assert_eq!(held.sha256, sha256(&complete));
        // half a frame, as a read in the middle of an append finds it: the frames before it, and no torn tail
        writer.file.write_all(b"{\"format\":\"sbgk-session-log/2\",\"payl").unwrap();
        let during = AuditJournal::read(&path.0).unwrap();
        assert_eq!((during.payloads.len(), during.live, during.in_flight), (2, true, 36));
        assert_eq!((during.bytes, during.complete_bytes, during.sha256), (complete.len() as u64, complete.len() as u64, sha256(&complete)));
        assert_eq!(during.heads, held.heads);
        // the same bytes with no writer are a torn tail, as before
        drop(writer);
        let stopped = AuditJournal::read(&path.0).unwrap();
        assert_eq!((stopped.payloads.len(), stopped.live, stopped.in_flight), (2, false, 0));
        assert_eq!(stopped.bytes - stopped.complete_bytes, 36);
        assert!(!writer_present(&path.0));
    }

    /// A server of 0.2.0 or earlier opens the journal to read and write and locks the whole file (`File::try_lock`): the handle
    /// this test holds is that one.
    #[test]
    fn a_writer_of_this_version_and_one_that_locks_the_whole_file_exclude_each_other_in_either_order() {
        let (path, _) = committed();
        let earlier = || OpenOptions::new().read(true).write(true).open(&path.0);
        // the earlier server runs: this version does not open the journal to write
        let old = earlier().unwrap();
        old.try_lock().unwrap();
        assert!(AuditJournal::open(&path.0).unwrap_err().message.contains("in use"));
        assert!(writer_present(&path.0));
        // and a reader is told why it cannot read, where that lock stops reading
        #[cfg(windows)]
        assert_eq!(AuditJournal::read(&path.0).unwrap_err().message, LOCKED_WHOLE);
        #[cfg(not(windows))]
        assert!(AuditJournal::read(&path.0).unwrap().live);
        drop(old);
        // this version runs: the earlier server cannot open the journal to write (Windows), or cannot lock it (elsewhere)
        let (mut new, _) = AuditJournal::open(&path.0).unwrap();
        new.finish_recovery().unwrap();
        #[cfg(windows)]
        assert_eq!(earlier().unwrap_err().raw_os_error(), Some(ERROR_SHARING_VIOLATION));
        #[cfg(not(windows))]
        assert!(matches!(earlier().unwrap().try_lock(), Err(TryLockError::WouldBlock)));
        new.append(&json!({"command": "third"}), None).unwrap();
        assert_eq!(AuditJournal::read(&path.0).unwrap().payloads.len(), 4);
    }

    fn committed_v3() -> (TempPath, Vec<u8>) {
        let path = TempPath::new();
        let empty = crate::audit::trees::records_root(&[]);
        let mut journal = AuditJournal::create(&path.0, &json!({"engine": "genesis", "audit": {}}), FrameFormat::V3, Some(&empty)).unwrap();
        journal.append(&json!({"command": "first", "receipt": {"accepted": 2}}), Some(&sha256(b"two records"))).unwrap();
        journal.append(&json!({"command": "second", "cursor": 2}), Some(&empty)).unwrap();
        drop(journal);
        let bytes = std::fs::read(&path.0).unwrap();
        (path, bytes)
    }

    #[test]
    fn a_v3_journal_round_trips_its_bodies_records_roots_and_header_chain() {
        let (path, original) = committed_v3();
        let line = String::from_utf8(original).unwrap().lines().nth(1).unwrap().to_string();
        let (mut journal, scan) = AuditJournal::open(&path.0).unwrap();
        assert_eq!(scan.format, FrameFormat::V3);
        assert_eq!(journal.format(), FrameFormat::V3);
        assert_eq!(scan.payloads[1], json!({"command": "first", "receipt": {"accepted": 2}}));
        assert_eq!(scan.records_roots[1], sha256(b"two records"));
        assert_eq!(scan.records_roots[2], crate::audit::trees::records_root(&[]));
        // the frame hash covers the header, and the header names the body by its hash
        let frame: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(frame["header"]["body_hash"], json!(to_hex(&body_hash(&frame["body"]))));
        assert_eq!(scan.heads[1], sha256_parts(&[HEADER_DOMAIN, to_jcs(&frame["header"]).as_bytes()]));
        assert_eq!(frame["header"]["previous"], json!(to_hex(&scan.heads[0])));
        assert!(journal.append(&json!({"x": 1}), None).is_err(), "not before recovery");
        journal.finish_recovery().unwrap();
        assert!(journal.append(&json!({"x": 1}), None).unwrap_err().message.contains("needs its records root"));
        journal.append(&json!({"x": 1}), Some(&ZERO_HASH)).unwrap();
        assert_eq!(journal.sequence(), 3);
    }

    #[test]
    fn a_v3_journal_refuses_every_tampered_header_field_body_and_a_v2_frame() {
        let (path, original) = committed_v3();
        let lines: Vec<&[u8]> = original.split_inclusive(|b| *b == b'\n').collect();
        let good: Value = serde_json::from_slice(lines[1]).unwrap();
        let mut variants: Vec<(Value, &str)> = Vec::new();
        for (field, value) in [
            ("body_hash", json!(to_hex(&ZERO_HASH))),
            ("previous", json!(to_hex(&ZERO_HASH))),
            ("records_root", json!(to_hex(&ZERO_HASH))),
            ("seq", json!(7)),
            ("wal_op", json!("genesis")),
            ("format", json!("sbgk-session-log/2")),
        ] {
            let mut changed = good.clone();
            changed["header"][field] = value;
            variants.push((changed, field));
        }
        let mut body = good.clone();
        body["body"]["receipt"]["accepted"] = json!(3);
        variants.push((body, "body"));
        let mut extra = good.clone();
        extra["header"]["extra"] = json!(1);
        variants.push((extra, "extra header field"));
        let mut outer = good.clone();
        outer["payload"] = json!({});
        variants.push((outer, "extra outer field"));
        for (changed, what) in variants {
            let line = format!("{}\n", to_jcs(&changed)).into_bytes();
            let bytes = [lines[0], line.as_slice(), lines[2]].concat();
            std::fs::write(&path.0, &bytes).unwrap();
            assert!(AuditJournal::open(&path.0).is_err(), "{what} was accepted");
            assert_eq!(std::fs::read(&path.0).unwrap(), bytes);
        }
        // a frame of the old format inside a /3 journal
        let (v2, _) = frame(1, &ZERO_HASH, &json!({"command": "first"})).unwrap();
        let bytes = [lines[0], v2.as_slice()].concat();
        std::fs::write(&path.0, &bytes).unwrap();
        assert!(AuditJournal::open(&path.0).is_err());
        // and a /3 frame inside a /2 journal
        let (_old_path, old) = committed();
        let old_lines: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
        std::fs::write(&path.0, [old_lines[0], lines[1]].concat()).unwrap();
        assert!(AuditJournal::open(&path.0).is_err());
    }

    /// The vector of an independent implementation of the specification (SBGK/SPEC_V02_STEP2, sections 0 and 1).
    #[test]
    fn the_frame_hash_matches_the_vector_of_an_independent_implementation() {
        let zero = to_hex(&ZERO_HASH);
        let header = json!({"body_hash": zero, "format": FORMAT_V3, "previous": zero, "records_root": zero, "seq": 0, "wal_op": "genesis"});
        let hash = sha256_parts(&[HEADER_DOMAIN, to_jcs(&header).as_bytes()]);
        assert_eq!(to_hex(&hash), "1310c31dca390da882b78a5209ce0bce9ec5cc21c610682216da72a31569e99b");
    }
}

/// The vectors another session computed from the text of SPEC_V02_STEP2 alone, without this code, for the independent verifier
/// `yuce-verify` (SBGK/VECTORS_INDEPENDENT_VERIFIER_20261110.json, V3): the kernel writes the same frame, byte for byte.
#[cfg(test)]
mod spec_text_vectors {
    use super::*;

    #[test]
    fn a_genesis_frame_gives_the_vector_written_from_the_spec_text() {
        let body = json!({"actor": "kernel", "note": "synthetic vector, not a real frame"});
        assert_eq!(to_hex(&body_hash(&body)), "8cc44deb9e6221a35721f07e0a0d4bebacef06e074fe903c45b58d462d34e98d");
        let (bytes, hash) = frame_v3(0, &ZERO_HASH, &body, &super::super::trees::records_root(&[])).unwrap();
        assert_eq!(to_hex(&hash), "09cdb29cc18bdc6fb6310d325d645bed02107f2e2e453be7b7854d8b0be587dc");
        assert_eq!((bytes.len(), to_hex(&sha256(&bytes))), (453, "3e73136c14bb58c8091442795e0f3cfc2beb7224f907e7bd707afa20d9c8c53f".to_string()));
    }
}
