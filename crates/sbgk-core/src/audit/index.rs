//! The rows of the index beside a journal (SPEC_V02_STEP6_7, step 6): a SQLite database any tool can read, rebuilt from the
//! journal at any time, every row naming the frame of the journal it comes from. This module builds the rows from a replay of the
//! journal, without SQLite; the CLI writes them. The truth stays in the journal: a row the journal does not give is a row to drop.

use super::persistence::AuditJournal;
use super::state::AuditState;
use super::trees;
use crate::error::{Code, KResult, KernelError};
use crate::hash::{sha256_parts, to_hex, Hash};
use crate::jcs::to_jcs;
use serde_json::{json, Map, Value};
use std::path::Path;

/// The format of an index.
pub const FORMAT: &str = "yuce-index/1";

/// One table: its name, its columns (the key first, `key` of them) and the SQL type of each.
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [(&'static str, &'static str)],
    pub key: usize,
}

/// The tables of the index, in the order `index_hash` reads them (SPEC_V02_STEP6_7 section 6.3). Every table but `status` carries
/// the frame a row comes from; `status` is the state at the last frame indexed and is written again at every update.
pub const TABLES: [Table; 6] = [
    Table {
        name: "frames",
        columns: &[
            ("n", "INTEGER"),
            ("hash", "TEXT"),
            ("actor", "TEXT"),
            ("submission_id", "TEXT"),
            ("command", "TEXT"),
            ("outcome", "TEXT"),
            ("records", "INTEGER"),
        ],
        key: 1,
    },
    Table {
        name: "records",
        columns: &[
            ("id", "TEXT"),
            ("frame", "INTEGER"),
            ("position", "INTEGER"),
            ("seq", "INTEGER"),
            ("kind", "TEXT"),
            ("author", "TEXT"),
            ("directive", "TEXT"),
            ("doc_id", "TEXT"),
            ("quote", "TEXT"),
            ("text", "TEXT"),
            ("stance", "TEXT"),
            ("leaf", "TEXT"),
            ("value", "TEXT"),
        ],
        key: 1,
    },
    Table { name: "grounds", columns: &[("record", "TEXT"), ("position", "INTEGER"), ("ground", "TEXT"), ("frame", "INTEGER")], key: 2 },
    Table {
        name: "quotes",
        columns: &[("record", "TEXT"), ("evidence", "TEXT"), ("version", "TEXT"), ("start", "INTEGER"), ("end", "INTEGER"), ("frame", "INTEGER")],
        key: 1,
    },
    Table {
        name: "seals",
        columns: &[
            ("frame", "INTEGER"),
            ("seal_hash", "TEXT"),
            ("log_root", "TEXT"),
            ("audit_root", "TEXT"),
            ("status_projection", "TEXT"),
            ("dependencies_projection", "TEXT"),
        ],
        key: 1,
    },
    Table {
        name: "status",
        columns: &[("id", "TEXT"), ("kind", "TEXT"), ("grounded", "INTEGER"), ("answer_support", "INTEGER"), ("fallen_by", "TEXT")],
        key: 1,
    },
];

/// The column of each table that names the frame a row comes from, for an update that adds the rows of new frames only.
pub fn frame_column(table: &str) -> Option<&'static str> {
    match table {
        "frames" => Some("n"),
        "records" | "grounds" | "quotes" | "seals" => Some("frame"),
        _ => None,
    }
}

/// The rows of every table, in the order of `TABLES`, with what the index says of its journal.
#[derive(Debug)]
pub struct IndexRows {
    pub run_id: String,
    /// Frames indexed, the genesis included.
    pub frames: usize,
    /// The hash of the last frame indexed.
    pub wal_head: Hash,
    pub tables: Vec<Vec<Vec<Value>>>,
    /// A writer held the journal while it was read: these are the rows of the frames complete at that moment.
    pub live: bool,
}

fn opt(v: &Option<String>) -> Value {
    v.as_ref().map_or(Value::Null, |s| json!(s))
}

/// The rows of the index of the journal at `path`, checked whole first as `audit-verify` checks it.
pub fn rows(path: &Path) -> KResult<IndexRows> {
    rows_at(path, None)
}

/// The rows of the index of the first `upto` frames of the journal at `path` (all of them when `None`), the status that of the state
/// after them: what an index built on that prefix holds (Codex review of 11abf6ed, S6-03: an index behind its journal is compared with
/// the prefix it names, not with the journal's later state). The journal is checked whole first, and a journal that ends in bytes
/// that are no complete frame is refused (S6-04), as `audit-verify` refuses it. The journal is read once: the frames and the
/// states replayed are those of one read, also where a live server appends meanwhile.
pub fn rows_at(path: &Path, upto: Option<usize>) -> KResult<IndexRows> {
    let scan = AuditJournal::read(path)?;
    if scan.bytes != scan.complete_bytes {
        return Err(KernelError::new(
            Code::BadField,
            format!(
                "the journal ends in {} bytes that are no complete frame (a torn tail): an index is built on complete journals only; audit-verify tells more",
                scan.bytes - scan.complete_bytes
            ),
        )
        .field("wal"));
    }
    let all = scan.payloads.len();
    let frames = upto.unwrap_or(all);
    if frames == 0 || frames > all {
        return Err(KernelError::new(Code::BadField, format!("the journal has {all} frames, not {frames}")).field("wal"));
    }
    let mut counts = vec![0usize];
    let mut status_at: Option<Vec<Value>> = None;
    let (state, _) = AuditState::verify_scan(&scan, &mut |m, state, _| {
        counts.push(state.record_count());
        if m == frames {
            status_at = Some(state.projections().0);
        }
    })?;
    let frame_of = |i: usize| (0..counts.len() - 1).find(|&k| counts[k + 1] > i).unwrap_or(0);
    let mut tables: Vec<Vec<Vec<Value>>> = vec![Vec::new(); TABLES.len()];
    for (n, p) in scan.payloads.iter().enumerate().take(frames) {
        let command = if n == 0 { json!("genesis") } else { p["command"]["kind"].clone() };
        let outcome = if n == 0 { Value::Null } else { p["outcome"]["kind"].clone() };
        tables[0].push(vec![
            json!(n),
            json!(to_hex(&scan.heads[n])),
            p.get("actor").cloned().unwrap_or(Value::Null),
            p.get("submission_id").cloned().unwrap_or(Value::Null),
            command,
            outcome,
            json!(counts.get(n + 1).map_or(0, |c| c - counts[n])),
        ]);
    }
    for i in 0..counts[frames] {
        let r = state.record_at(i);
        let (k, id) = (frame_of(i), to_hex(&r.id.0));
        let value = state.record_leaf_value_at(i);
        tables[1].push(vec![
            json!(id),
            json!(k),
            json!(i - counts[k]),
            json!(r.seq),
            json!(r.kind.name()),
            json!(r.author),
            json!(r.directive),
            opt(&r.doc_id),
            opt(&r.quote),
            opt(&r.text),
            opt(&r.status),
            json!(to_hex(&trees::record_leaf(&value))),
            json!(to_jcs(&value)),
        ]);
        for (position, g) in r.based_on.iter().chain(r.ends.iter().flat_map(|(a, _, b)| [a, b])).enumerate() {
            tables[2].push(vec![json!(id), json!(position), json!(to_hex(&g.0)), json!(k)]);
        }
        if let Some((evidence, version, start, end)) = state.evidence_binding(&r.id) {
            tables[3].push(vec![json!(id), json!(to_hex(&evidence)), json!(to_hex(&version)), json!(start), json!(end), json!(k)]);
        }
    }
    for (n, seal_hash) in state.seals().iter().filter(|(n, _)| *n < frames) {
        let p = &scan.payloads[*n]["command"]["seal"];
        tables[4].push(vec![
            json!(n),
            json!(to_hex(seal_hash)),
            p["log_root"].clone(),
            p["audit_root"].clone(),
            p["projections"]["status"].clone(),
            p["projections"]["dependencies"].clone(),
        ]);
    }
    for row in status_at.expect("the prefix was replayed") {
        // [id, kind, grounded, answer_support, fallen_by]
        tables[5].push(vec![row[0].clone(), row[1].clone(), json!(u8::from(row[2] == true)), json!(u8::from(row[3] == true)), json!(to_jcs(&row[4]))]);
    }
    Ok(IndexRows { run_id: state.run_id().to_string(), frames, wal_head: scan.heads[frames - 1], tables, live: scan.live })
}

/// The key of a row: its first `key` values, as one JCS text that sorts the rows of a table the same way everywhere.
pub fn row_key(table: &Table, row: &[Value]) -> String {
    to_jcs(&json!(row[..table.key]))
}

/// `index_hash`: SHA-256 over the canonical content of the tables (SPEC_V02_STEP6_7 section 6.3), each table's rows ordered by key.
/// An index built at once and one built by updates have the same hash; a row changed in the database has another.
pub fn index_hash(tables: &[Vec<Vec<Value>>]) -> Hash {
    let mut content = Map::new();
    for (t, rows) in TABLES.iter().zip(tables) {
        let mut sorted: Vec<&Vec<Value>> = rows.iter().collect();
        sorted.sort_by_key(|r| row_key(t, r));
        content.insert(t.name.to_string(), json!(sorted));
    }
    sha256_parts(&[b"YUCE-INDEX/1\0", to_jcs(&Value::Object(content)).as_bytes()])
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;
