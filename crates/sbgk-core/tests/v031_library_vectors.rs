//! The vectors of the independent verifier that only the library can write (0.3.1): the command line writes no batch.
//!
//! - `j4a/set-d/d8-batch-prefix-put-not-applied.wal` (amendment 6, P6-3 and P6-10): a batch whose `submit` keeps an accepted
//!   prefix and whose next operation, a `put_document`, has no result. A reader that applied the put would see the quote of the
//!   prefix on another version of its document, and the claim on it fallen: the seal says both stand.
//! - `cut/V-CUT-25` and `cut/V-CUT-26` (`SPEC_CUT_AND_BUNDLE_v1`, B3.2): a batch brings the exact bytes of an export into the
//!   receiving journal. With no delivery declared the import is undeclared; with its frame declared the delivery is missing,
//!   since a delivery is a `put_document` frame of its own.
//!
//! The test fails if the kernel no longer writes these bytes; `YUCE_BLESS_V031_VECTORS=1` writes the vectors again. The rows of
//! `d8` (`j4a/rows/`) and the entry of `j4a/expected.json` are made from the journal by the tools kept with the vector generators.

use sbgk_core::audit::cut;
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::{AuditState, GenesisSpec};
use sbgk_core::audit::{AuditStore, RecordId};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const BLESS: &str = "YUCE_BLESS_V031_VECTORS";

struct Folder(PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("r2r_v031_vectors_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Folder(root)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn inputs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../verifier/inputs")
}

/// The published file holds these bytes; with the bless variable set, it is written with them.
fn keep(path: &Path, bytes: &[u8]) {
    if std::env::var_os(BLESS).is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        return;
    }
    let published = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e} ({BLESS}=1 writes the vectors)", path.display()));
    assert!(published == bytes, "{}: the kernel no longer writes these bytes ({BLESS}=1 writes the vectors again)", path.display());
}

/// JSON as the expected files of the vectors are written: indented by one space a level, a line feed at the end.
fn pretty(value: &Value) -> Vec<u8> {
    let two = serde_json::to_string_pretty(value).unwrap();
    let mut out = String::new();
    for line in two.lines() {
        let indent = line.len() - line.trim_start_matches(' ').len();
        out.push_str(&" ".repeat(indent / 2));
        out.push_str(&line[indent..]);
        out.push('\n');
    }
    out.into_bytes()
}

/// A journal that starts without a document, under the rules 4, as `audit-stream start` writes it.
fn start(path: &Path, run: &str) -> AuditState {
    let mut s = AuditState::prepare_from_docs(&AuditOntology::base(), run, Vec::new()).unwrap();
    s.start_journal(path, &GenesisSpec::default()).unwrap();
    s
}

/// A submission as `audit-stream submit` writes it: its id by the frames so far, its scope the documents its lines need.
fn submit(s: &mut AuditState, lines: Value) -> Vec<RecordId> {
    let lines = lines.as_array().unwrap().clone();
    let scope = s.scope_of_lines("owner", "read", &lines);
    let id = format!("stream-{}", s.entries().unwrap());
    let report = s.submit_records_id(&id, "owner", "read", &scope, &lines);
    assert!(report.error.is_none(), "{:?}", report.error.map(|e| e.to_json()));
    report.accepted
}

fn observe(local: &str, doc: &str, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": local, "doc_id": doc, "exact_quote": quote, "terms": []})
}

fn claim(local: &str, text: &str, subject: &str, object: &str, based_on: &[&str]) -> Value {
    json!({"kind": "claim", "local_id": local, "text": text, "subject": subject, "object": object, "stance": "reported", "based_on": based_on})
}

fn hex(id: &RecordId) -> String {
    to_hex(&id.0)
}

const D8_FIRST: &str = "Alpha holds in the northern field.\nBeta holds in the southern field.\n";
const D8_SECOND: &str = "Alpha held in the northern field until spring.\nBeta holds in the southern field.\n";

#[test]
fn a_batch_keeps_the_prefix_of_its_submit_and_does_not_apply_the_put_after_the_refused_line() {
    let work = Folder::new("d8");
    let wal = work.0.join("run.wal");
    let mut s = start(&wal, "axis-d8");
    s.put_document("owner", "src", D8_FIRST.as_bytes()).unwrap();
    // operation 0: a quote and a claim on it are accepted, the third line names a ground that does not exist and is refused.
    // operation 1, a new version of the document the quote is bound to, has no result: it is not applied
    let lines = json!([
        observe("o1", "src", "Alpha holds in the northern field."),
        claim("c1", "Alpha holds in the north.", "alpha", "north", &["o1"]),
        claim("c2", "Gamma holds in the east.", "gamma", "east", &["o9"]),
    ]);
    let operations = [
        json!({"kind": "submit", "directive": "read", "scope": {"docs": ["src"], "topic": null, "ranges": []}, "lines": lines}),
        json!({"kind": "put_document", "doc_id": "src", "text": D8_SECOND}),
    ];
    let report = s.submit_operations_id("batch-1", "owner", &operations, None).unwrap();
    let results = report["results"].as_array().unwrap();
    assert_eq!((results.len(), results[0]["accepted"].as_array().map(Vec::len), results[0]["failed_index"].as_u64()), (1, Some(2), Some(2)), "{report}");
    assert!(!report["error"].is_null(), "{report}");
    let accepted: Vec<RecordId> = s.records_since(0).iter().map(|r| r.id).collect();
    assert_eq!(accepted.len(), 2);
    assert!(accepted.iter().all(|id| s.is_grounded(id)), "the put was not applied: the quote is on the current version");
    s.seal().unwrap();
    // the document still has its first bytes: its first line is quoted again, and the line of the put that was not applied is not there
    let later =
        submit(&mut s, json!([observe("o2", "src", "Alpha holds in the northern field."), claim("c3", "The north is held.", "north", "held", &["o2", "o1"])]));
    assert_eq!(later.len(), 2);
    s.seal().unwrap();
    s.close_run().unwrap();
    drop(s);

    let dir = inputs().join("j4a").join("set-d");
    keep(&dir.join("d8-batch-prefix-put-not-applied.wal"), &std::fs::read(&wal).unwrap());
    keep(&dir.join("d8-batch-prefix-put-not-applied.docs").join("src"), D8_FIRST.as_bytes());
}

const NOTICE: &[u8] = b"Party A withdrew the quote under the alpha report.\n";

/// The receiving journal of `V-CUT-25` and `V-CUT-26`: as `b` of `V-CUT-1`, but the export comes in by an operation of a batch.
fn journal_b(wal: &Path, export: &str) -> (RecordId, RecordId) {
    let mut s = start(wal, "cut-b");
    let report = s.submit_operations_id("batch-1", "owner", &[json!({"kind": "put_document", "doc_id": "export-e", "text": export})], None).unwrap();
    assert_eq!((report["accepted_operations"].as_u64(), report["error"].is_null()), (Some(1), true), "{report}");
    let paragraph = export.split("\n\n").nth(1).unwrap();
    let ids = submit(&mut s, json!([observe("o3", "export-e", paragraph), claim("c3", "Party B relies on the alpha report.", "alpha", "relied", &["o3"])]));
    s.put_document("owner", "notice", NOTICE).unwrap();
    s.withdraw_text_for("owner", "export-e", paragraph, "notice").unwrap();
    s.seal().unwrap();
    s.close_run().unwrap();
    (ids[0], ids[1])
}

#[test]
fn a_batch_that_brings_in_the_bytes_of_an_export_is_no_delivery() {
    let cut_dir = inputs().join("cut");
    let source = cut_dir.join("V-CUT-1");
    let export = std::fs::read(source.join("e1.txt")).unwrap();
    let work = Folder::new("cut");
    let wal = work.0.join("run.wal");
    let (o3, c3) = journal_b(&wal, std::str::from_utf8(&export).unwrap());
    let journal = std::fs::read(&wal).unwrap();

    // the cut of the two journals, without the export: the journals as a manifest lists them
    let a = cut::Journal::read(&source.join("a").join("run.wal")).unwrap();
    let b = cut::Journal::read(&wal).unwrap();
    let journals = cut::cut(vec![("a".to_string(), a, None), ("b".to_string(), b, None)], Vec::new(), None).unwrap().manifest["journals"].clone();
    let published: Value = serde_json::from_slice(&std::fs::read(source.join("cut.json")).unwrap()).unwrap();
    assert_eq!(journals[0], published["journals"][0], "journal a is the one of V-CUT-1");
    let entry = published["exports"][0].clone();
    assert_eq!(entry["sha256"], to_hex(&sha256(&export)));

    // the command that makes a cut refuses this bundle: no delivery can declare a batch
    let read = |name: &str, path: &Path| (name.to_string(), cut::Journal::read(path).unwrap(), None);
    let refused = cut::cut(vec![read("a", &source.join("a").join("run.wal")), read("b", &wal)], vec![("e1".to_string(), export.clone())], None).err().unwrap();
    assert!(refused.message.contains("frame 1 of the journal b is a batch"), "{}", refused.message);

    let ids = json!({"o3": hex(&o3), "c3": hex(&c3)});
    let declared = json!({"export": "e1", "journal": "b", "doc_id": "export-e", "frame": 1});
    let vectors = [
        (
            "V-CUT-25",
            json!([]),
            json!({"code": "CUT_UNDECLARED_DELIVERY", "journal": "b", "frame": 1, "doc_id": "export-e", "export": "e1"}),
            "the receiving journal takes the exact bytes of e1 in by an operation of a batch (written by the library), and no delivery is declared",
        ),
        (
            "V-CUT-26",
            json!([declared.clone()]),
            json!({"code": "DELIVERY_MISSING", "export": "e1", "journal": "b", "doc_id": "export-e", "frame": 1}),
            "the journals of V-CUT-25, with a delivery that names the frame of the batch: a delivery is a put_document frame of its own",
        ),
    ];
    for (name, deliveries, failure, notes) in vectors {
        let manifest = json!({"format": cut::CUT_FORMAT, "mode": "observe", "journals": journals.clone(), "exports": [entry.clone()], "deliveries": deliveries,
                              "previous_cut": null});
        let expected = json!({"verdict": "FAIL", "failures": [failure], "notes": notes, "ids": ids, "cut_hash": to_hex(&cut::cut_hash(&manifest))});
        let dir = cut_dir.join(name);
        for file in ["a/run.wal", "a/docs/source", "a/docs/reason", "e1.txt"] {
            keep(&dir.join(file), &std::fs::read(source.join(file)).unwrap());
        }
        keep(&dir.join("b").join("run.wal"), &journal);
        keep(&dir.join("b").join("docs").join("export-e"), &export);
        keep(&dir.join("b").join("docs").join("notice"), NOTICE);
        keep(&dir.join("cut.json"), (sbgk_core::jcs::to_jcs(&manifest) + "\n").as_bytes());
        keep(&dir.join("expected.json"), &pretty(&expected));
    }
}
