//! Tests of the index rows (SPEC_V02_STEP6_7 section 6.5) on journals the kernel writes.

use super::*;
use crate::audit::onto::AuditOntology;
use crate::audit::state::GenesisSpec;
use crate::audit::Scope;
use crate::hash::sha256;
use std::path::PathBuf;

const DOC: &[u8] = b"The first line names the rule.\nThe second line names its exception.\n";

struct TempPath(PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp(name: &str) -> TempPath {
    TempPath(std::env::temp_dir().join(format!(
        "r2r_index_{name}_{}_{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    )))
}

fn submit(s: &mut AuditState, id: &str, lines: &[Value]) -> String {
    let scope = Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() };
    let r = s.submit_records_id(id, "worker", "w", &scope, lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    to_hex(&r.accepted[0].0)
}

#[test]
fn the_rows_of_a_prefix_are_the_rows_of_the_whole_journal_up_to_it_and_name_their_frames() {
    let path = temp("whole");
    let prefix = temp("prefix");
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &[("d".to_string(), DOC.to_vec())], "index-run", sha256(b"m"), &spec).unwrap();
    let o1 =
        submit(&mut s, "a", &[json!({"kind": "observe", "local_id": "o1", "doc_id": "d", "exact_quote": "The first line names the rule.", "terms": ["t"]})]);
    s.seal().unwrap();
    // the writer locks its journal: the copy is taken with the state closed, and the run goes on from the journal
    drop(s);
    std::fs::copy(&path.0, &prefix.0).unwrap();
    let mut s = AuditState::open(&path.0).unwrap();
    submit(&mut s, "b", &[json!({"kind": "observe", "local_id": "o2", "doc_id": "d", "exact_quote": "The second line names its exception.", "terms": ["t"]})]);
    let claim = submit(
        &mut s,
        "c",
        &[json!({"kind": "claim", "local_id": "c1", "text": "The rule has an exception.", "subject": "rule", "stance": "reported", "based_on": ["o1", "o2"]})],
    );
    s.revoke_observation("owner", &crate::audit::RecordId(crate::hash::from_hex(&o1).unwrap())).unwrap();
    s.seal().unwrap();
    drop(s);

    let whole = rows(&path.0).unwrap();
    let part = rows(&prefix.0).unwrap();
    assert_eq!(whole.run_id, "index-run");
    assert_eq!(whole.frames, std::fs::read_to_string(&path.0).unwrap().lines().count());
    // every table but status: the prefix's rows are the whole journal's rows of the prefix's frames, so an update adds rows only
    for (t, (w, p)) in TABLES.iter().zip(whole.tables.iter().zip(&part.tables)) {
        let Some(column) = frame_column(t.name) else { continue };
        let at = t.columns.iter().position(|(c, _)| *c == column).unwrap();
        let early: Vec<&Vec<Value>> = w.iter().filter(|r| r[at].as_u64().unwrap() < part.frames as u64).collect();
        assert_eq!(early, p.iter().collect::<Vec<_>>(), "table {}", t.name);
    }
    // the rows lead to the journal: a record's frame and leaf, its grounds, its quote, and the claim fallen with its ground
    let record = |id: &str| whole.tables[1].iter().find(|r| r[0] == id).unwrap().clone();
    let c = record(&claim);
    assert_eq!(c[4], "claim");
    let frame = c[1].as_u64().unwrap() as usize;
    assert_eq!(whole.tables[0][frame][6], 1, "the claim's frame accepted one record");
    let grounds: Vec<&Value> = whole.tables[2].iter().filter(|g| g[0] == claim.as_str()).map(|g| &g[2]).collect();
    assert_eq!(grounds.len(), 2);
    assert!(whole.tables[3].iter().any(|q| q[0] == o1.as_str()), "the quote of o1");
    let status = |id: &str| whole.tables[5].iter().find(|r| r[0] == id).unwrap().clone();
    assert_eq!(status(&claim)[2], 0, "the claim fell with o1");
    assert!(status(&claim)[4].as_str().unwrap().contains(&o1));
    assert_eq!(part.tables[5].iter().find(|r| r[0] == o1.as_str()).unwrap()[2], 1, "o1 stood at the first seal");
    assert_eq!(whole.tables[4].len(), 2, "two seals");
    // the same journal gives the same hash; any row changed gives another
    assert_eq!(index_hash(&whole.tables), index_hash(&rows(&path.0).unwrap().tables));
    let mut changed = whole.tables.clone();
    changed[1][0][9] = json!("another text");
    assert_ne!(index_hash(&changed), index_hash(&whole.tables));
    let mut reordered = whole.tables.clone();
    reordered[1].reverse();
    assert_eq!(index_hash(&reordered), index_hash(&whole.tables), "the hash reads rows by key, not in the order given");
    // Codex review of 11abf6ed, S6-03: the rows of the whole journal's prefix, the status that of the prefix, are the prefix's own
    let at_prefix = rows_at(&path.0, Some(part.frames)).unwrap();
    assert_eq!(at_prefix.tables, part.tables);
    assert_eq!((at_prefix.frames, at_prefix.wal_head), (part.frames, part.wal_head));
    assert!(rows_at(&path.0, Some(whole.frames + 1)).is_err() && rows_at(&path.0, Some(0)).is_err());
    // S6-04: a journal that ends in a torn frame gives no rows
    let mut torn = std::fs::read(&path.0).unwrap();
    torn.extend_from_slice(b"{\"body\":");
    std::fs::write(&prefix.0, torn).unwrap();
    assert!(rows(&prefix.0).unwrap_err().message.contains("torn tail"));
}
