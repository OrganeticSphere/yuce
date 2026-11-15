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
    assert_eq!(r1["prov:wasQuotedFrom"], format!("{base}version:d:0:0"));
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
    let at = |k: usize| &nodes[&format!("{base}version:d:{k}:0")];
    assert_eq!(at(v[1])["prov:wasRevisionOf"], format!("{base}version:d:{}:0", v[0]));
    assert_eq!(at(v[2])["prov:wasRevisionOf"], format!("{base}version:d:{}:0", v[1]));
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

fn ops(s: &mut AuditState, id: &str, operations: &[Value]) -> Value {
    let report = s.submit_operations_id(id, "worker", operations, None).unwrap();
    assert!(report["error"].is_null(), "{report}");
    report
}

fn observe(local: &str, quote: &str) -> Value {
    json!({"kind": "submit", "directive": "w", "scope": {"docs": ["d"], "topic": null, "ranges": []},
           "lines": [{"kind": "observe", "local_id": local, "doc_id": "d", "exact_quote": quote, "terms": ["t"]}]})
}

fn put(text: &str) -> Value {
    json!({"kind": "put_document", "doc_id": "d", "text": text})
}

/// A batch that puts a document twice, with an observation on the version in between: the version is an entity of its own, the
/// observation quotes it, and the chain of revisions holds it (Codex review of 32aff362, PROV-02).
#[test]
fn an_observation_on_a_version_a_batch_put_in_between_quotes_that_version() {
    let path = temp("between");
    let docs = [("d".to_string(), b"Original.\n".to_vec())];
    let mut s = AuditState::create(&path.0, &AuditOntology::base(), &docs, "between", sha256(b"m")).unwrap();
    let report = ops(&mut s, "batch", &[put("Intermediate.\n"), observe("mid", "Intermediate."), put("Final.\n")]);
    assert_eq!(report["accepted_operations"], 3, "{report}");
    let binding = to_hex(&s.evidence_binding(&s.record_at(0).id).unwrap().1);
    drop(s);
    let e = export(&path.0).unwrap();
    let nodes = by_id(&e);
    let base = "urn:yuce:between:";
    let record = nodes.values().find(|n| n["yuce:kind"] == "observe").unwrap();
    assert_eq!(record["prov:wasQuotedFrom"], format!("{base}version:d:1:0"));
    let between = &nodes[&format!("{base}version:d:1:0")];
    assert_eq!(between["yuce:versionId"], binding.as_str());
    assert_eq!(between["prov:wasRevisionOf"], format!("{base}version:d:0:0"));
    assert_eq!(nodes[&format!("{base}version:d:1:2")]["prov:wasRevisionOf"], format!("{base}version:d:1:0"));
    // the observation never stood at the end of a frame: the kernel's projections name no point where it stood
    assert!(!nodes.values().any(|n| has_type(n, "yuce:Standing")));
}

/// A batch that puts other bytes and then the first bytes back, with an observation on each: the first bytes put back are a new
/// version, and the observation accepted after them quotes that one, not the version of the genesis with the same bytes.
#[test]
fn bytes_a_batch_puts_back_are_a_new_version_and_the_observations_on_each_quote_their_own() {
    let path = temp("back");
    let docs = [("d".to_string(), b"Alpha line.\n".to_vec())];
    let mut s = AuditState::create(&path.0, &AuditOntology::base(), &docs, "back", sha256(b"m")).unwrap();
    ops(&mut s, "batch", &[put("Beta line.\n"), observe("b", "Beta line."), put("Alpha line.\n"), observe("a", "Alpha line.")]);
    drop(s);
    let e = export(&path.0).unwrap();
    let nodes = by_id(&e);
    let base = "urn:yuce:back:";
    let quoted = |text: &str| nodes.values().find(|n| n["prov:value"] == text).unwrap()["prov:wasQuotedFrom"].clone();
    assert_eq!(quoted("Beta line."), format!("{base}version:d:1:0"));
    assert_eq!(quoted("Alpha line."), format!("{base}version:d:1:2"));
    assert_eq!(nodes[&format!("{base}version:d:1:2")]["yuce:versionId"], nodes[&format!("{base}version:d:0:0")]["yuce:versionId"]);
    assert_eq!(nodes[&format!("{base}version:d:1:2")]["prov:wasRevisionOf"], format!("{base}version:d:1:0"));
    // the observation on the bytes put back stands at the frame's end; the one on the version in between does not
    let standing: Vec<&Value> = nodes.values().filter(|n| has_type(n, "yuce:Standing")).collect();
    assert_eq!(standing.len(), 1);
    assert_eq!(nodes[standing[0]["prov:specializationOf"].as_str().unwrap()]["prov:value"], "Alpha line.");
}

/// The scenarios of Codex's review of 32aff362, in the formats `/3` and `/2`: a relation that is an answer's support, its link
/// accepted and then rejected (the answer falls with its grounds standing: `answer`), two versions in one batch, a withdrawal.
/// At every frame the export stands what the projection stands, and the export of every prefix is the export of the journal cut there.
fn standing_with_links(legacy: bool) {
    use crate::audit::{AuditStore, LinkStatus};
    let path = temp(if legacy { "legacy" } else { "links" });
    let docs = [("d".to_string(), DOC.to_vec())];
    let spec = GenesisSpec { questions: json!([{"id": "RQ1", "text": "Which claim?"}]), settings: json!({}), operator_meta: None };
    let mut s = if legacy {
        AuditState::create_v2(&path.0, &AuditOntology::base(), &docs, "legacy", sha256(b"m")).unwrap()
    } else {
        AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "links", sha256(b"m"), &spec).unwrap()
    };
    let scope = Scope { docs: vec!["d".into()], topic: None, ranges: vec![] };
    let r = s.submit_records_id(
        "seed",
        "worker",
        "w",
        &scope,
        &[
            json!({"kind": "observe", "local_id": "o1", "doc_id": "d", "exact_quote": "The first line names the rule.", "terms": ["t"]}),
            json!({"kind": "claim", "local_id": "c1", "text": "First.", "subject": "t", "stance": "reported", "based_on": ["o1"]}),
            json!({"kind": "claim", "local_id": "c2", "text": "Second.", "subject": "t", "stance": "reported", "based_on": ["o1"]}),
            json!({"kind": "relation", "local_id": "r1", "from": "c1", "rel": "supports", "to": "c2", "based_on": ["o1"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let (o, c1, c2, rel) = (r.accepted[0], r.accepted[1], r.accepted[2], r.accepted[3]);
    let link = s.add_link("builder", &c1, "supports", &c2, &[o]).unwrap();
    s.set_link_status(&link.id, LinkStatus::Accepted, "checker", &[o]).unwrap();
    if !legacy {
        let answer = json!({"kind": "done", "local_id": "d1", "rq_id": "RQ1", "directive_id": "w",
                            "answer_ids": [format!("@{}", to_hex(&rel.0))], "outcome": "answered"});
        let done = s.submit_records_id("done", "worker", "w", &scope, &[answer]);
        assert!(done.error.is_none(), "{:?}", done.error);
    }
    s.set_link_status(&link.id, LinkStatus::Rejected, "checker", &[o]).unwrap();
    let versions = [put(std::str::from_utf8(EDITED).unwrap()), put(std::str::from_utf8(DOC).unwrap())];
    s.submit_operations_id("versions", "owner", &versions, None).unwrap();
    s.revoke_observation("owner", &o).unwrap();
    if !legacy {
        s.seal().unwrap();
    }
    drop(s);
    let e = export(&path.0).unwrap();
    if !legacy {
        let answer = graph(&e).into_iter().find(|n| n["yuce:kind"] == "done").unwrap();
        let period = graph(&e).into_iter().find(|n| n["prov:specializationOf"] == answer["@id"]).unwrap();
        assert_eq!(by_id(&e)[period["prov:qualifiedInvalidation"].as_str().unwrap()]["yuce:reason"], "answer");
    }
    let lines: Vec<String> = std::fs::read_to_string(&path.0).unwrap().lines().map(|l| format!("{l}\n")).collect();
    let points: Vec<usize> = (1..=e.frames).collect();
    let (_, _, _, snaps) = read::journal_points(&path.0, &points).unwrap();
    for (count, snap) in &snaps {
        let want: BTreeSet<String> = snap.rows.iter().filter(|r| r.grounded).map(|r| to_hex(&r.id.0)).collect();
        let have: BTreeSet<String> = graph(&e)
            .iter()
            .filter(|n| has_type(n, "yuce:Standing") && frame_no(&n["prov:wasGeneratedBy"]) < *count)
            .filter(|n| n.get("prov:wasInvalidatedBy").is_none_or(|v| frame_no(v) >= *count))
            .map(|n| n["prov:specializationOf"].as_str().unwrap().rsplit(':').next().unwrap().to_string())
            .collect();
        assert_eq!(have, want, "standing after {count} frames");
        let prefix = temp("links_prefix");
        std::fs::write(&prefix.0, lines[..*count].concat()).unwrap();
        assert_eq!(export_at(&path.0, Some(*count)).unwrap().text(), export(&prefix.0).unwrap().text(), "the first {count} frames");
    }
}

#[test]
fn standing_follows_link_decisions_batches_and_prefixes() {
    standing_with_links(false);
}

#[test]
fn standing_follows_link_decisions_batches_and_prefixes_in_the_format_2() {
    standing_with_links(true);
}
