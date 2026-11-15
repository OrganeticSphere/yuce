//! Tests of the PROV-O export on journals the kernel writes.

use super::*;
use crate::audit::onto::AuditOntology;
use crate::audit::read;
use crate::audit::state::GenesisSpec;
use crate::audit::Scope;
use crate::hash::from_hex;
use std::path::PathBuf;

const DOC: &[u8] = b"The first line names the rule.\nThe second line names its exception.\n";
const EDITED: &[u8] = b"The first line names the rule.\nThe second line was rewritten.\n";

struct TempPath(PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp(name: &str) -> TempPath {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    TempPath(std::env::temp_dir().join(format!(
        "r2r_prov_{name}_{}_{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )))
}

fn submit(s: &mut AuditState, id: &str, lines: &[Value]) -> String {
    let scope = Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() };
    let r = s.submit_records_id(id, "worker", "w", &scope, lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    to_hex(&r.accepted[0].0)
}

fn id(hex: &str) -> RecordId {
    RecordId(from_hex(hex).unwrap())
}

/// A journal with a quote withdrawn, a claim fallen with it, a document version replaced and then put back, and two seals; the
/// second path holds the same journal cut after the first seal. Returns the record ids (o1, o2, claim) and the cut's frames.
fn journal(path: &Path, prefix: &Path) -> (String, String, String, usize) {
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let mut s = AuditState::create_with(path, &AuditOntology::base(), &[("d".to_string(), DOC.to_vec())], "prov run", sha256(b"m"), &spec).unwrap();
    let o1 =
        submit(&mut s, "a", &[json!({"kind": "observe", "local_id": "o1", "doc_id": "d", "exact_quote": "The first line names the rule.", "terms": ["t"]})]);
    let o2 = submit(
        &mut s,
        "b",
        &[json!({"kind": "observe", "local_id": "o2", "doc_id": "d", "exact_quote": "The second line names its exception.", "terms": ["t"]})],
    );
    let claim = submit(
        &mut s,
        "c",
        &[json!({"kind": "claim", "local_id": "c1", "text": "The rule has an exception.", "subject": "rule", "stance": "reported", "based_on": ["o1", "o2"]})],
    );
    s.seal().unwrap();
    // the writer locks its journal: the copy is taken with the state closed, and the run goes on from the journal
    drop(s);
    std::fs::copy(path, prefix).unwrap();
    let cut = std::fs::read_to_string(prefix).unwrap().lines().count();
    let mut s = AuditState::open(path).unwrap();
    s.revoke_observation("owner", &id(&o1)).unwrap();
    s.put_document("owner", "d", EDITED).unwrap();
    s.put_document("owner", "d", DOC).unwrap();
    s.seal().unwrap();
    drop(s);
    (o1, o2, claim, cut)
}

fn graph(e: &ProvExport) -> Vec<Value> {
    e.document["@graph"].as_array().unwrap().clone()
}

fn by_id(e: &ProvExport) -> BTreeMap<String, Value> {
    graph(e).into_iter().map(|n| (n["@id"].as_str().unwrap().to_string(), n)).collect()
}

fn has_type(n: &Value, t: &str) -> bool {
    n["@type"].as_array().unwrap().iter().any(|x| x == t)
}

fn frame_no(iri: &Value) -> usize {
    iri.as_str().unwrap().rsplit(':').next().unwrap().parse().unwrap()
}

#[test]
fn the_export_says_who_quoted_what_on_which_version_and_what_fell_with_what() {
    let (path, prefix) = (temp("whole"), temp("prefix"));
    let (o1, o2, claim, _) = journal(&path.0, &prefix.0);
    let e = export(&path.0).unwrap();
    let nodes = by_id(&e);
    let base = "urn:yuce:prov%20run:";
    assert_eq!(e.run_id, "prov run");
    assert_eq!(e.frames, std::fs::read_to_string(&path.0).unwrap().lines().count());

    // the observation: its author, its frame, its quote of the genesis version, its bytes
    let r1 = &nodes[&format!("{base}record:{o1}")];
    assert_eq!(r1["yuce:kind"], "observe");
    assert_eq!(r1["prov:wasAttributedTo"], format!("{base}agent:worker"));
    assert_eq!(r1["prov:wasQuotedFrom"], format!("{base}version:d:0"));
    assert_eq!((r1["yuce:start"].as_u64(), r1["yuce:end"].as_u64()), (Some(0), Some(30)));
    assert_eq!(r1["prov:value"], "The first line names the rule.");
    // the claim rests on both observations
    let c = &nodes[&format!("{base}record:{claim}")];
    assert_eq!(c["prov:wasDerivedFrom"], json!(sorted(vec![format!("{base}record:{o1}"), format!("{base}record:{o2}")])));
    assert_eq!((&c["yuce:stance"], &c["prov:value"]), (&json!("reported"), &json!("The rule has an exception.")));

    // three versions of d: the genesis one, the edit, the original put back, each a revision of the one before, no cycle
    let versions: Vec<&Value> = nodes.values().filter(|n| has_type(n, "yuce:DocumentVersion")).collect();
    assert_eq!(versions.len(), 3);
    let v: Vec<usize> = versions.iter().map(|n| frame_no(&n["prov:wasGeneratedBy"])).collect::<BTreeSet<_>>().into_iter().collect();
    let at = |k: usize| &nodes[&format!("{base}version:d:{k}")];
    assert_eq!(at(v[1])["prov:wasRevisionOf"], format!("{base}version:d:{}", v[0]));
    assert_eq!(at(v[2])["prov:wasRevisionOf"], format!("{base}version:d:{}", v[1]));
    assert_eq!(at(v[2])["yuce:versionId"], at(v[0])["yuce:versionId"], "the original bytes put back: the same version id");
    assert!(at(v[0]).get("prov:wasRevisionOf").is_none());

    // the periods: o1 withdrawn; the claim fell with o1; o2 stopped with the edit and stood again when the original came back
    let periods = |r: &str| -> Vec<&Value> {
        nodes.values().filter(|n| has_type(n, "yuce:Standing") && n["prov:specializationOf"] == format!("{base}record:{r}").as_str()).collect()
    };
    let why = |p: &Value| nodes[p["prov:qualifiedInvalidation"].as_str().unwrap()].clone();
    let p1 = periods(&o1);
    assert_eq!(p1.len(), 1);
    assert_eq!(why(p1[0])["yuce:reason"], "withdrawn");
    let pc = periods(&claim);
    assert_eq!(pc.len(), 1);
    let fell = why(pc[0]);
    assert_eq!((&fell["yuce:reason"], &fell["yuce:fallenBy"]), (&json!("basis"), &json!([format!("{base}record:{o1}")])));
    assert_eq!(fell["prov:activity"], why(p1[0])["prov:activity"], "the claim fell in the frame that withdrew o1");
    assert!(has_type(&fell, "prov:Invalidation"));
    let mut p2 = periods(&o2);
    p2.sort_by_key(|p| frame_no(&p["prov:wasGeneratedBy"]));
    assert_eq!(p2.len(), 2);
    assert_eq!(why(p2[0])["yuce:reason"], "new_version");
    assert_eq!(frame_no(&why(p2[0])["prov:activity"]), v[1]);
    assert_eq!(frame_no(&p2[1]["prov:wasGeneratedBy"]), v[2]);
    assert!(p2[1].get("prov:wasInvalidatedBy").is_none(), "o2 stands at the end");
    // a record is never invalidated itself: a withdrawal is not an erasure
    assert!(nodes.values().filter(|n| has_type(n, "yuce:Record")).all(|n| n.get("prov:wasInvalidatedBy").is_none()));

    // every node id is used once, every id a property names is a node of the export
    assert_eq!(nodes.len(), graph(&e).len());
    for n in graph(&e) {
        for (key, value) in n.as_object().unwrap() {
            if LINKS.contains(&key.as_str()) {
                for target in value.as_array().cloned().unwrap_or_else(|| vec![value.clone()]) {
                    assert!(nodes.contains_key(target.as_str().unwrap()), "{key} names {target}, no node of the export");
                }
            }
        }
    }
    // the export names the last frame, its hash and the last seal
    let ex = nodes.values().find(|n| has_type(n, "yuce:Export")).unwrap();
    assert_eq!((ex["yuce:frames"].as_u64(), ex["yuce:walHead"].as_str()), (Some(e.frames as u64), Some(to_hex(&e.wal_head).as_str())));
    assert_eq!(frame_no(&ex["yuce:lastSeal"]), e.frames - 1, "the journal ends in a seal");
}

/// At every point of the journal, the records the export says stand are those the status projection says stand: every fall and
/// every return is where the kernel's own report puts it.
#[test]
fn at_every_frame_the_export_stands_what_the_status_projection_stands() {
    let (path, prefix) = (temp("frames"), temp("frames_prefix"));
    journal(&path.0, &prefix.0);
    let e = export(&path.0).unwrap();
    let periods: Vec<(String, usize, Option<usize>)> = graph(&e)
        .iter()
        .filter(|n| has_type(n, "yuce:Standing"))
        .map(|n| {
            let record = n["prov:specializationOf"].as_str().unwrap().rsplit(':').next().unwrap().to_string();
            (record, frame_no(&n["prov:wasGeneratedBy"]), n.get("prov:wasInvalidatedBy").map(frame_no))
        })
        .collect();
    let points: Vec<usize> = (1..=e.frames).collect();
    let (_, _, _, snaps) = read::journal_points(&path.0, &points).unwrap();
    for (n, snap) in &snaps {
        let k = n - 1;
        let exported: BTreeSet<String> = periods.iter().filter(|(_, from, to)| *from <= k && to.is_none_or(|t| t > k)).map(|(r, _, _)| r.clone()).collect();
        let projected: BTreeSet<String> = snap.rows.iter().filter(|r| r.grounded).map(|r| to_hex(&r.id.0)).collect();
        assert_eq!(exported, projected, "the records standing after frame {k}");
    }
}

#[test]
fn a_journal_always_gives_the_same_bytes_and_the_content_hash_catches_a_change() {
    let (path, prefix) = (temp("bytes"), temp("bytes_prefix"));
    let (_, _, _, cut) = journal(&path.0, &prefix.0);
    let (a, b) = (export(&path.0).unwrap(), export(&path.0).unwrap());
    assert_eq!(a.text(), b.text());
    assert_eq!(content_hash_of(&a.document), Some(a.content_hash));
    let mut changed = a.document.clone();
    let claim = changed["@graph"].as_array_mut().unwrap().iter_mut().find(|n| n["yuce:kind"] == "claim").unwrap();
    claim["prov:value"] = json!("The rule has no exception.");
    assert_ne!(content_hash_of(&changed), Some(a.content_hash));
    // the nodes in the order of their ids, the lists sorted
    let ids: Vec<&str> = a.document["@graph"].as_array().unwrap().iter().map(|n| n["@id"].as_str().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    // the export of a prefix is the export of the journal cut there
    assert_eq!(export_at(&path.0, Some(cut)).unwrap().text(), export(&prefix.0).unwrap().text());
    assert_ne!(export_at(&path.0, Some(cut)).unwrap().text(), a.text());
}

#[test]
fn a_torn_journal_and_a_point_outside_it_are_refused() {
    let (path, prefix) = (temp("torn"), temp("torn_prefix"));
    journal(&path.0, &prefix.0);
    let frames = export(&path.0).unwrap().frames;
    for upto in [0, frames + 1] {
        assert!(export_at(&path.0, Some(upto)).is_err(), "upto {upto}");
    }
    let mut bytes = std::fs::read(&prefix.0).unwrap();
    bytes.extend_from_slice(b"{\"half\":");
    std::fs::write(&prefix.0, bytes).unwrap();
    let error = export(&prefix.0).unwrap_err();
    assert!(error.to_json().to_string().contains("torn tail"), "{}", error.to_json());
}

/// The sample in `examples/prov-export` is the export of the journal above: a change of the export's bytes shows here first.
/// `YUCE_BLESS_PROV=1` writes the sample again, after a change of the format that is meant.
#[test]
fn the_sample_in_the_examples_is_the_export_of_the_fixture_journal() {
    let (path, prefix) = (temp("sample"), temp("sample_prefix"));
    journal(&path.0, &prefix.0);
    let text = export(&path.0).unwrap().text();
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/prov-export/sample.prov.jsonld");
    if std::env::var("YUCE_BLESS_PROV").is_ok_and(|v| v == "1") {
        std::fs::write(&sample, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&sample).unwrap_or_default(), text, "the sample is not this export: YUCE_BLESS_PROV=1 writes it again");
}
