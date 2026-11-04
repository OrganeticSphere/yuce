//! Persistent session log of a resident server (`sbgk serve` / `sbgk mcp-serve` with `--wal-path`).
//!
//! JSON Lines, one record per committed mutation, in commit order. The server appends the records of a request and calls
//! `sync_data` before it answers, so every acknowledged mutation survives a crash:
//!
//! * `{"wal_op":"genesis","format":"sbgk-session-log/1","container_hex":..}`: the session the server started from, as a
//!   verified `.sbgk` container (ontology, CDC parameters, documents and graph);
//! * `{"wal_op":"put_document","doc_id":..,"text"|"hex":..,"sha256":..}`: a document update (an erratum);
//! * `{"wal_op":"config","config":..}`: the swarm options of a session without targets yet;
//! * `{"wal_op":"set_targets","targets":..,"config":..}`: the goals and the swarm options;
//! * `{"wal_op":"event","line":..}`: an event line exactly as `Session::apply_line` accepted it (agent events of a lease,
//!   plain events, and the kernel's own auto-closure derivations);
//! * `{"wal_op":"lease","seq":n}`: a lease number was issued, so a restarted server never reuses a lease id or a local-id prefix.
//!
//! Leases themselves are not persisted: after a restart no lease is active, and the work that was in flight is issued again.
//! A torn last record (the process died inside a write, so the record was never acknowledged) is cut off on recovery.
//!
//! One process owns a log: it takes an exclusive lock on the file before reading or truncating it and holds the lock while
//! it runs, so a second server started on the same path is refused instead of interleaving its records with the first.

use crate::container::{build_container, open_session};
use crate::directive::Targets;
use crate::hash::{sha256, to_hex};
use crate::swarm::{LockMode, SwarmConfig, SwarmSession};
use serde_json::{json, Value};
use std::fs::TryLockError;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "sbgk-session-log/1";

/// An open session log, positioned at its end.
pub struct Journal {
    file: File,
    pub path: PathBuf,
    pub records: u64,
    pub bytes: u64,
}

impl Journal {
    /// Append `recs` (one JSON text each) and `sync_data` the file.
    pub fn append(&mut self, recs: &[String]) -> std::io::Result<()> {
        if recs.is_empty() {
            return Ok(());
        }
        let mut buf = String::with_capacity(recs.iter().map(|r| r.len() + 1).sum());
        for r in recs {
            buf.push_str(r);
            buf.push('\n');
        }
        self.file.write_all(buf.as_bytes())?;
        self.file.sync_data()?;
        self.records += recs.len() as u64;
        self.bytes += buf.len() as u64;
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({"wal_path": self.path.display().to_string(), "wal_records": self.records, "wal_bytes": self.bytes})
    }
}

// ------------------------------------------------------------------------------------------ records

pub fn doc_record(doc_id: &str, bytes: &[u8]) -> String {
    let mut r = json!({"wal_op": "put_document", "doc_id": doc_id, "sha256": to_hex(&sha256(bytes))});
    match std::str::from_utf8(bytes) {
        Ok(text) => r["text"] = json!(text),
        Err(_) => r["hex"] = json!(to_hex(bytes)),
    }
    r.to_string()
}

pub fn event_record(line: &str) -> String {
    json!({"wal_op": "event", "line": line}).to_string()
}

pub fn lease_record(seq: u64) -> String {
    json!({"wal_op": "lease", "seq": seq}).to_string()
}

pub fn targets_record(t: &Targets, cfg: &SwarmConfig) -> String {
    let goals: Vec<Value> = t.goals.iter().map(|g| json!({"entity": g.entity, "predicate": g.predicate})).collect();
    json!({"wal_op": "set_targets", "targets": {"goals": goals, "docs": t.docs}, "config": cfg.to_json()}).to_string()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2).map(|p| Some((nib(p[0])? << 4) | nib(p[1])?)).collect()
}

fn config_from(v: &Value, cfg: &mut SwarmConfig) {
    if let Some(b) = v["auto_close_p2a"].as_bool() {
        cfg.auto_close_p2a = b;
    }
    if let Some(m) = v["lock_mode"].as_str().and_then(LockMode::parse) {
        cfg.lock = m;
    }
    if let Some(b) = v["pack_multi_target"].as_bool() {
        cfg.pack_multi_target = b;
    }
    if let Some(x) = v["default_ttl_ms"].as_u64() {
        cfg.default_ttl_ms = x;
    }
    if let Some(x) = v["default_k"].as_u64() {
        cfg.default_k = x as usize;
    }
}

// ------------------------------------------------------------------------------------------ open / create / recover

/// Open the log at `path`: replay it when the file holds records, otherwise start a new log from the session `fresh` builds.
/// Returns the swarm (persisting to the log from now on) and a report (`recovered`, record counts, `state_root`).
pub fn open(path: &Path, fresh: impl FnOnce() -> Result<SwarmSession, String>) -> Result<(SwarmSession, Value), String> {
    let mut file = open_locked(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.is_empty() {
        start(path, file, fresh()?)
    } else {
        replay(path, file, &bytes)
    }
}

/// Start a new log at `path` (an existing file is replaced) whose genesis is the current state of `sw`.
pub fn create(path: &Path, sw: SwarmSession) -> Result<(SwarmSession, Value), String> {
    let file = open_locked(path)?;
    start(path, file, sw)
}

/// Open (or create) the file and take its exclusive lock, before anything is read or truncated.
fn open_locked(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(format!("{}: the session log is in use by another server", path.display())),
        Err(TryLockError::Error(e)) => Err(format!("{}: cannot lock the session log: {e}", path.display())),
    }
}

fn start(path: &Path, mut file: File, mut sw: SwarmSession) -> Result<(SwarmSession, Value), String> {
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    let container = build_container(&mut sw.session);
    let mut recs = vec![json!({"wal_op": "genesis", "format": FORMAT, "container_hex": to_hex(&container)}).to_string()];
    match sw.targets.as_ref() {
        Some(t) => recs.push(targets_record(t, &sw.cfg)),
        None => recs.push(json!({"wal_op": "config", "config": sw.cfg.to_json()}).to_string()),
    }
    if sw.lease_seq > 0 {
        recs.push(lease_record(sw.lease_seq));
    }
    file.set_len(0).map_err(io)?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut j = Journal { file, path: path.to_path_buf(), records: 0, bytes: 0 };
    j.append(&recs).map_err(io)?;
    let mut rep = j.to_json();
    rep["recovered"] = json!(false);
    rep["state_root"] = json!(to_hex(&sw.session.engine.root()));
    sw.session.journal = Some(Vec::new());
    sw.journal = Some(j);
    Ok((sw, rep))
}

/// Rebuild the swarm from the records of `bytes` (the content of the locked `file` at `path`) and keep the log for appending.
fn replay(path: &Path, mut file: File, bytes: &[u8]) -> Result<(SwarmSession, Value), String> {
    let at = |i: usize, msg: String| format!("{} record {}: {msg}", path.display(), i + 1);
    // records end with '\n'; anything after the last one is a torn write that was never acknowledged
    let complete = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let text = std::str::from_utf8(&bytes[..complete]).map_err(|e| format!("{}: not UTF-8: {e}", path.display()))?;
    let mut sw: Option<SwarmSession> = None;
    let (mut records, mut events) = (0u64, 0u64);
    for (i, line) in text.lines().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|e| at(i, format!("bad JSON: {e}")))?;
        let op = v["wal_op"].as_str().unwrap_or("");
        records += 1;
        if i == 0 {
            if op != "genesis" || v["format"] != FORMAT {
                return Err(at(i, format!("not a {FORMAT} log (the first record must be its genesis)")));
            }
            let c = v["container_hex"].as_str().and_then(unhex).ok_or_else(|| at(i, "bad container_hex".into()))?;
            let s = open_session(&c).map_err(|e| at(i, format!("genesis container rejected: {e}")))?;
            sw = Some(SwarmSession::new(s));
            continue;
        }
        let sw = sw.as_mut().expect("genesis replayed");
        match op {
            "event" => {
                let l = v["line"].as_str().ok_or_else(|| at(i, "event without 'line'".into()))?;
                sw.session.apply_line(l).map_err(|e| at(i, format!("replay diverged: {e}")))?;
                events += 1;
            }
            "put_document" => {
                let id = v["doc_id"].as_str().ok_or_else(|| at(i, "put_document without 'doc_id'".into()))?;
                let doc = match (v["text"].as_str(), v["hex"].as_str()) {
                    (Some(t), _) => t.as_bytes().to_vec(),
                    (None, Some(h)) => unhex(h).ok_or_else(|| at(i, "bad hex".into()))?,
                    _ => return Err(at(i, "put_document without content".into())),
                };
                if v["sha256"].as_str() != Some(to_hex(&sha256(&doc)).as_str()) {
                    return Err(at(i, format!("document '{id}' does not match its sha256")));
                }
                sw.put_document_raw(id, &doc);
            }
            "set_targets" => {
                let t = Targets::from_json(&v["targets"]).map_err(|e| at(i, e))?;
                config_from(&v["config"], &mut sw.cfg);
                sw.targets = Some(t);
            }
            "config" => config_from(&v["config"], &mut sw.cfg),
            "lease" => sw.lease_seq = sw.lease_seq.max(v["seq"].as_u64().unwrap_or(0)),
            other => return Err(at(i, format!("unknown wal_op '{other}'"))),
        }
    }
    let Some(mut sw) = sw else { return Err(format!("{}: no complete genesis record", path.display())) };
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    file.set_len(complete as u64).map_err(io)?;
    file.seek(SeekFrom::End(0)).map_err(io)?;
    file.sync_data().map_err(io)?;
    let j = Journal { file, path: path.to_path_buf(), records, bytes: complete as u64 };
    let mut rep = j.to_json();
    rep["recovered"] = json!(true);
    rep["replayed_events"] = json!(events);
    rep["torn_bytes_dropped"] = json!(bytes.len() - complete);
    rep["last_seq"] = json!(sw.session.last_seq);
    rep["lease_seq"] = json!(sw.lease_seq);
    rep["state_root"] = json!(to_hex(&sw.session.engine.root()));
    sw.session.journal = Some(Vec::new());
    sw.journal = Some(j);
    Ok((sw, rep))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdc::CdcParams;
    use crate::ontology::Ontology;
    use crate::session::Session;

    fn swarm() -> SwarmSession {
        let onto = r#"{"entities":[{"id":"svc_a","type":"Service"}],"predicates":[{"id":"p","subject":"Service","object":"@literal"}],"rules":[]}"#;
        SwarmSession::new(Session::new(Ontology::from_json_str(onto).unwrap(), CdcParams::default()))
    }

    #[test]
    fn one_log_one_owner_and_options_survive_without_targets() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("sbgk_journal_lock_{}_{nanos}.jsonl", std::process::id()));
        let mut sw = swarm();
        sw.cfg.default_k = 9;
        sw.cfg.lock = LockMode::TargetOnly;
        let (mut owner, rep) = create(&path, sw).unwrap();
        assert_eq!(rep["recovered"], false);
        // a second owner is refused, and neither opening nor creating touches the live log
        let len = std::fs::metadata(&path).unwrap().len();
        let busy = open(&path, || Ok(swarm())).err().expect("a held log is refused");
        assert!(busy.contains("in use"), "{busy}");
        assert!(create(&path, swarm()).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len, "the refused opener did not truncate the log");
        owner.put_document_raw("d", b"svc_a is fine.");
        owner.sync_wal().unwrap();
        drop(owner);
        // released: the next server resumes it, options included
        let (back, rep) = open(&path, || Ok(swarm())).unwrap();
        assert_eq!(rep["recovered"], true, "{rep}");
        assert_eq!((back.cfg.default_k, back.cfg.lock), (9, LockMode::TargetOnly));
        assert!(back.session.arena.doc("d").is_some());
        drop(back);
        let _ = std::fs::remove_file(&path);
    }
}
