//! `sbgk audit-index`: the SQLite index beside a journal (SPEC_V02_STEP6_7, step 6). The rows come from `sbgk_core::audit::index`,
//! which builds them from a replay of the journal; this module writes them to a database any tool reads, adds the rows of new
//! frames to one already built, and checks a database against its journal. The truth stays in the journal.

use super::{fail, Args};
use rusqlite::types::Value as Sql;
use rusqlite::{params_from_iter, Connection, OpenFlags};
use sbgk_core::audit::index::{self, IndexRows, EARLIER_FORMATS, FORMAT, TABLES};
use sbgk_core::hash::to_hex;
use sbgk_core::jcs::to_jcs;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn sql_error(e: rusqlite::Error) -> ! {
    fail(&format!("index database: {e}"))
}

fn to_sql(v: &Value) -> Sql {
    match v {
        Value::Null => Sql::Null,
        Value::Number(n) => Sql::Integer(n.as_i64().unwrap_or_else(|| fail("an index value is no whole number"))),
        Value::String(s) => Sql::Text(s.clone()),
        Value::Bool(b) => Sql::Integer(i64::from(*b)),
        other => Sql::Text(to_jcs(other)),
    }
}

/// A value read back as the index writes it: text, a whole number or NULL. A value of another SQLite type stays apart, so a row whose
/// type was changed in the database differs from the journal's (Codex review of 11abf6ed, S6-02: a BLOB of the same bytes read as hex
/// passed the check, and a join on it lost the row).
fn from_sql(v: Sql) -> Value {
    match v {
        Sql::Null => Value::Null,
        Sql::Integer(i) => json!(i),
        Sql::Text(s) => json!(s),
        Sql::Real(f) => json!({"sqlite_real": f}),
        Sql::Blob(b) => json!({"sqlite_blob": to_hex(&b)}),
    }
}

/// Whether two paths name one file: by the file's absolute path where it exists, else by its folder's and its name (Codex review of
/// 11abf6ed, S6-01: an index written over its own journal destroyed it).
pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    let absolute = |p: &Path| -> Option<PathBuf> {
        std::fs::canonicalize(p).ok().or_else(|| {
            let folder = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
            Some(std::fs::canonicalize(folder).ok()?.join(p.file_name()?))
        })
    };
    match (absolute(a), absolute(b)) {
        (Some(x), Some(y)) if cfg!(windows) => x.to_string_lossy().to_lowercase() == y.to_string_lossy().to_lowercase(),
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// The format the file at `db` names, when it is a SQLite database with the `meta` table of an index.
fn format_of(db: &Path) -> Option<String> {
    Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .ok()
        .and_then(|conn| conn.query_row("SELECT value FROM meta WHERE key = 'format'", [], |r| r.get::<_, String>(0)).ok())
}

/// Whether the file at `db` is an index of a journal: a SQLite database whose `meta` names this format or an earlier one. Only such
/// a file is replaced.
fn is_index(db: &Path) -> bool {
    format_of(db).is_some_and(|f| f == FORMAT || EARLIER_FORMATS.contains(&f.as_str()))
}

/// What is said of an index of an earlier format: its tables are not this format's, so it is neither updated nor compared.
fn earlier_format(db: &Path) -> Option<String> {
    format_of(db)
        .filter(|f| EARLIER_FORMATS.contains(&f.as_str()))
        .map(|f| format!("the index has the earlier format {f}, without the tables of the coverage: build it again with --rebuild"))
}

fn refuse(db: &Path, wal: &str, error: &str) -> ! {
    println!("{}", json!({"status": "REFUSED", "db": db.display().to_string(), "wal": wal, "error": error}));
    std::process::exit(1)
}

fn create(conn: &Connection) {
    let mut sql = String::from("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);\n");
    for t in &TABLES {
        let columns: Vec<String> = t.columns.iter().map(|(c, ty)| format!("\"{c}\" {ty}")).collect();
        let key: Vec<String> = t.columns[..t.key].iter().map(|(c, _)| format!("\"{c}\"")).collect();
        sql.push_str(&format!("CREATE TABLE {} ({}, PRIMARY KEY ({}));\n", t.name, columns.join(", "), key.join(", ")));
    }
    conn.execute_batch(&sql).unwrap_or_else(|e| sql_error(e));
}

/// Insert the rows of every table, only those of frames from `from` on in the tables that name a frame; `status` is written whole.
fn insert(conn: &Connection, rows: &IndexRows, from: usize) {
    for (t, table) in TABLES.iter().zip(&rows.tables) {
        let frame = index::frame_column(t.name).map(|c| t.columns.iter().position(|(n, _)| *n == c).expect("a frame column"));
        if frame.is_none() {
            conn.execute(&format!("DELETE FROM {}", t.name), []).unwrap_or_else(|e| sql_error(e));
        }
        let marks = vec!["?"; t.columns.len()].join(", ");
        let mut statement = conn.prepare(&format!("INSERT INTO {} VALUES ({marks})", t.name)).unwrap_or_else(|e| sql_error(e));
        for row in table.iter().filter(|r| frame.is_none_or(|at| r[at].as_u64().is_some_and(|n| n as usize >= from))) {
            statement.execute(params_from_iter(row.iter().map(to_sql))).unwrap_or_else(|e| sql_error(e));
        }
    }
    // `coverage` says whether the journal gives the two tables of the coverage, or why it gives none
    let coverage = rows.coverage_unavailable.clone().unwrap_or_else(|| "available".to_string());
    for (key, value) in [
        ("format", FORMAT.to_string()),
        ("run_id", rows.run_id.clone()),
        ("frames", rows.frames.to_string()),
        ("wal_head", to_hex(&rows.wal_head)),
        ("coverage", coverage),
    ] {
        conn.execute("INSERT OR REPLACE INTO meta VALUES (?1, ?2)", [key, value.as_str()]).unwrap_or_else(|e| sql_error(e));
    }
}

fn meta(conn: &Connection) -> BTreeMap<String, String> {
    let mut statement = conn.prepare("SELECT key, value FROM meta").unwrap_or_else(|e| sql_error(e));
    let read = statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap_or_else(|e| sql_error(e));
    read.map(|r| r.unwrap_or_else(|e| sql_error(e))).collect()
}

/// The rows of every table of a database, in the order of `TABLES`.
fn read_rows(conn: &Connection) -> Vec<Vec<Vec<Value>>> {
    TABLES
        .iter()
        .map(|t| {
            let columns: Vec<String> = t.columns.iter().map(|(c, _)| format!("\"{c}\"")).collect();
            let mut statement = conn.prepare(&format!("SELECT {} FROM {}", columns.join(", "), t.name)).unwrap_or_else(|e| sql_error(e));
            let read = statement
                .query_map([], |r| (0..t.columns.len()).map(|i| r.get::<_, Sql>(i).map(from_sql)).collect::<Result<Vec<Value>, _>>())
                .unwrap_or_else(|e| sql_error(e));
            read.map(|r| r.unwrap_or_else(|e| sql_error(e))).collect()
        })
        .collect()
}

/// The rows of a database that differ from the journal's rows of the frames it names: table, key and how, at most `limit`.
fn differences(have: &[Vec<Vec<Value>>], want: &[Vec<Vec<Value>>], limit: usize) -> (usize, Vec<Value>) {
    let mut out = Vec::new();
    let mut count = 0;
    for ((t, h), w) in TABLES.iter().zip(have).zip(want) {
        let h: BTreeMap<String, &Vec<Value>> = h.iter().map(|r| (index::row_key(t, r), r)).collect();
        let w: BTreeMap<String, &Vec<Value>> = w.iter().map(|r| (index::row_key(t, r), r)).collect();
        for key in h.keys().chain(w.keys()).collect::<std::collections::BTreeSet<_>>() {
            let how = match (h.get(key), w.get(key)) {
                (Some(a), Some(b)) if a == b => continue,
                (Some(_), Some(_)) => "differs from the journal",
                (Some(_), None) => "is not in the journal",
                (None, _) => "is missing",
            };
            count += 1;
            if out.len() < limit {
                out.push(json!({"table": t.name, "key": serde_json::from_str::<Value>(key).unwrap_or(Value::Null), "row": how}));
            }
        }
    }
    (count, out)
}

/// `sbgk audit-index --wal <run.wal> [--db <file>] [--rebuild] [--check]` (SPEC_V02_STEP6_7 section 6.2): build the index of a
/// journal, checked whole first, or add the rows of its new frames to an index of the frames before them; with `--check`, compare
/// an index with its journal row by row. Exit 1 when the journal or the index is refused, or the check finds a difference.
pub fn cmd_audit_index(a: &Args) {
    let wal = a.req("wal");
    let db = PathBuf::from(a.get("db").map_or(format!("{wal}.index.sqlite"), str::to_string));
    if same_file(&db, Path::new(&wal)) {
        refuse(&db, &wal, "the index would be written over its own journal: give --db another path");
    }
    super::audit_mcp::refuse_locked_whole(&wal);
    let rows = match index::rows(Path::new(&wal)) {
        Ok(rows) => rows,
        Err(e) => {
            println!("{}", json!({"status": "REFUSED", "wal": wal, "error": e.to_json()}));
            std::process::exit(1);
        }
    };
    let journal_hash = to_hex(&index::index_hash(&rows.tables));
    let head_of = |n: usize| rows.tables[0].get(n.wrapping_sub(1)).map(|r| r[1].clone());
    if a.sw("check") {
        if let Some(error) = earlier_format(&db) {
            println!("{}", json!({"status": "INDEX_DIFFERS", "db": db.display().to_string(), "wal": wal, "error": error}));
            std::process::exit(1);
        }
        let conn = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap_or_else(|e| sql_error(e));
        let m = meta(&conn);
        let frames = m.get("frames").and_then(|f| f.parse::<usize>().ok()).unwrap_or(0);
        let named = m.get("wal_head").map(|h| json!(h));
        if m.get("format").map(String::as_str) != Some(FORMAT) || m.get("run_id") != Some(&rows.run_id) || frames > rows.frames || named != head_of(frames) {
            println!(
                "{}",
                json!({"status": "INDEX_DIFFERS", "db": db.display().to_string(), "wal": wal, "error": "the index names another journal, or more frames than it holds"})
            );
            std::process::exit(1);
        }
        let have = read_rows(&conn);
        // an index behind its journal is compared with the rows of the prefix it names, its status that of the prefix (S6-03)
        let behind = frames < rows.frames;
        let prefix;
        let want = if behind {
            prefix = index::rows_at(Path::new(&wal), Some(frames)).unwrap_or_else(|e| fail(&e.to_json().to_string()));
            &prefix
        } else {
            &rows
        };
        let (count, shown) = differences(&have, &want.tables, 20);
        let status = match (count, behind) {
            (0, false) => "INDEX_MATCHES",
            (0, true) => "INDEX_BEHIND",
            _ => "INDEX_DIFFERS",
        };
        let mut out = json!({"status": status, "db": db.display().to_string(), "wal": wal, "frames_indexed": frames, "frames": rows.frames,
                             "differences": count, "first_differences": shown, "index_hash": to_hex(&index::index_hash(&have)),
                             "journal_index_hash": to_hex(&index::index_hash(&want.tables))});
        if rows.live {
            out["live"] = super::audit_mcp::live_read(rows.frames, None);
        }
        println!("{out}");
        if count > 0 {
            std::process::exit(1);
        }
        return;
    }
    // an index already there is taken up when it names the first frames of this journal, else refused unless --rebuild
    let mut mode = "built";
    let mut from = 0;
    if db.exists() && !a.sw("rebuild") {
        if !is_index(&db) {
            refuse(&db, &wal, "the file at --db is no index of a journal: it is neither updated nor replaced");
        }
        if let Some(error) = earlier_format(&db) {
            refuse(&db, &wal, &error);
        }
        let conn = Connection::open(&db).unwrap_or_else(|e| sql_error(e));
        let m = meta(&conn);
        let frames = m.get("frames").and_then(|f| f.parse::<usize>().ok()).unwrap_or(usize::MAX);
        if m.get("format").map(String::as_str) != Some(FORMAT)
            || m.get("run_id") != Some(&rows.run_id)
            || frames > rows.frames
            || m.get("wal_head").map(|h| json!(h)) != head_of(frames)
        {
            println!(
                "{}",
                json!({"status": "REFUSED", "db": db.display().to_string(), "wal": wal,
                       "error": "the index names another journal or frames this one does not hold (cut?): build it again with --rebuild"})
            );
            std::process::exit(1);
        }
        from = frames;
        mode = if frames == rows.frames { "current" } else { "updated" };
        conn.execute_batch("BEGIN").unwrap_or_else(|e| sql_error(e));
        insert(&conn, &rows, from);
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('index_hash', ?1)", [&journal_hash]).unwrap_or_else(|e| sql_error(e));
        conn.execute_batch("COMMIT").unwrap_or_else(|e| sql_error(e));
        // what was there and what was added is the index the journal gives, or nothing is claimed
        if to_hex(&index::index_hash(&read_rows(&conn))) != journal_hash {
            fail(&format!("the updated index {} is not the journal's: build it again with --rebuild", db.display()));
        }
    } else {
        // only an index is replaced: never the journal or another file that happens to sit at --db (S6-01)
        if db.exists() && !is_index(&db) {
            refuse(&db, &wal, "the file at --db is no index of a journal: it is not replaced");
        }
        // built aside under a name of its own, made new, and put in place in one rename: a reader never sees half an index
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let tmp = PathBuf::from(format!("{}.{}-{nonce}.tmp", db.display(), std::process::id()));
        if same_file(&tmp, Path::new(&wal)) {
            refuse(&db, &wal, "the index's working file would be its own journal: give --db another path");
        }
        std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", tmp.display())));
        let conn = Connection::open(&tmp).unwrap_or_else(|e| sql_error(e));
        create(&conn);
        conn.execute_batch("BEGIN").unwrap_or_else(|e| sql_error(e));
        insert(&conn, &rows, 0);
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('index_hash', ?1)", [&journal_hash]).unwrap_or_else(|e| sql_error(e));
        conn.execute_batch("COMMIT").unwrap_or_else(|e| sql_error(e));
        drop(conn);
        std::fs::rename(&tmp, &db).unwrap_or_else(|e| fail(&format!("cannot put the index in place at {}: {e}", db.display())));
    }
    let mut out = json!({"status": "INDEXED", "mode": mode, "db": db.display().to_string(), "wal": wal, "frames": rows.frames,
    "frames_added": rows.frames - from, "records": rows.tables[1].len(), "index_hash": journal_hash,
    "coverage": match &rows.coverage_unavailable {
        Some(reason) => json!({"unavailable": reason}),
        None => json!({"units": rows.tables[6].len(), "packs": rows.tables[7].len()}),
    }});
    if rows.live {
        out["live"] = super::audit_mcp::live_read(rows.frames, None);
    }
    println!("{out}");
}
