//! The reading tools of SPEC_V02_STEP3 on a small run: a review claim rests on its own passage and on the title line of a trial,
//! a twin claim rests on another review, a control claim on another trial, an answer on both claims; then the title line is
//! withdrawn.

use super::*;
use crate::audit::onto::AuditOntology;
use crate::audit::state::GenesisSpec;
use crate::audit::Scope;
use crate::hash::sha256;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct TempPath(PathBuf);

impl TempPath {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("r2r_read_tools_{}_{}_{}.jsonl", std::process::id(), time, NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const TITLE: &str = "Title: Tai chi for knee arthritis.";
const TRIAL: &str = "Title: Tai chi for knee arthritis.\nAuthors: Ni GX.\n";
const REVIEW_A: &str = "Review A includes the Ni 2010 trial in its pooled analysis.\nOther trials: Wang 2009.\n";
const REVIEW_B: &str = "Review B lists Wang 2009 as a trial of tai chi.\n";
const C1: &str = "Review A rests on the Ni 2010 trial of tai chi for knee arthritis";
const TWIN: &str = "Review B rests on the Wang 2009 trial of tai chi for knee arthritis";
const CONTROL: &str = "Review A also cites Wang 2009";

fn observe(local_id: &str, doc: &str, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": local_id, "doc_id": doc, "exact_quote": quote, "terms": ["trial"]})
}

fn claim(local_id: &str, text: &str, based_on: &[&str]) -> Value {
    json!({"kind": "claim", "local_id": local_id, "text": text, "subject": "review", "stance": "reported", "based_on": based_on})
}

struct Run {
    path: TempPath,
    s: AuditState,
    title: RecordId,
    passage: RecordId,
    c1: RecordId,
    twin: RecordId,
    control: RecordId,
    done: RecordId,
    /// The point before the withdrawal.
    before: usize,
    snapshot: Snapshot,
}

fn run() -> Run {
    let path = TempPath::new();
    let docs = [
        ("trial".to_string(), TRIAL.as_bytes().to_vec()),
        ("review_a".into(), REVIEW_A.as_bytes().to_vec()),
        ("review_b".into(), REVIEW_B.as_bytes().to_vec()),
    ];
    let spec = GenesisSpec {
        questions: json!([{"id": "RQ1", "text": "Which reviews rest on the trial?"}]),
        settings: json!({"format": "fixture"}),
        operator_meta: None,
    };
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "read-tools", sha256(b"m"), &spec).unwrap();
    let scope = Scope { docs: vec!["trial".into(), "review_a".into(), "review_b".into()], topic: Some("trials".into()), ranges: Vec::new() };
    let lines = [
        observe("ot", "trial", TITLE),
        observe("oa", "review_a", "Review A includes the Ni 2010 trial in its pooled analysis."),
        claim("c1", C1, &["oa", "ot"]),
        observe("ob", "review_b", "Review B lists Wang 2009 as a trial of tai chi."),
        claim("ct", TWIN, &["ob"]),
        observe("oc", "review_a", "Other trials: Wang 2009."),
        claim("cc", CONTROL, &["oc"]),
        claim("cc2", CONTROL, &["ob"]),
        json!({"kind": "done", "local_id": "d1", "rq_id": "RQ1", "directive_id": "task", "answer_ids": ["c1", "cc"], "outcome": "answered"}),
    ];
    let r = s.submit_records_id("seed", "worker", "task", &scope, &lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    let a = &r.accepted;
    let before = s.entries().unwrap();
    let snapshot = Snapshot::of(&s, before);
    s.withdraw_text("owner", "trial", TITLE).unwrap();
    Run { path, title: a[0], passage: a[1], c1: a[2], twin: a[4], control: a[6], done: a[8], before, snapshot, s }
}

fn hex(id: &RecordId) -> Value {
    json!(to_hex(&id.0))
}

fn ids(rows: &Value) -> Vec<Value> {
    rows.as_array().unwrap().iter().map(|r| r["id"].clone()).collect()
}

#[test]
fn the_report_names_what_fell_and_on_what_it_stood_without_the_withdrawn_text() {
    let r = run();
    let now = r.s.entries().unwrap();
    let report = fallen(&r.s, now, Some(&r.snapshot), None);
    assert_eq!(ids(&report["rows"]), [hex(&r.c1), hex(&r.done)], "the claim on the title line and the answer on it fell; the control and the twin stand");
    assert_eq!((report["rows_fallen"].clone(), report["quotes_gone"].clone()), (json!(2), json!(1)));
    assert_eq!(report["questions_to_answer_again"], json!(["RQ1"]));
    let c1 = &report["rows"][0];
    assert_eq!(c1["fallen_by"], json!([hex(&r.title)]));
    let gone = &c1["gone"][0];
    assert_eq!((gone["id"].clone(), gone["cause"].clone(), gone["doc_id"].clone()), (hex(&r.title), json!("withdrawn"), json!("trial")));
    assert_eq!(
        gone["withdrawal"],
        json!({"doc_id": "trial", "sha256": to_hex(&sha256(TITLE.as_bytes())), "bytes": TITLE.len(), "span": [0, TITLE.len()], "version": gone["version"]})
    );
    assert_eq!(gone["named"], false, "the text was withdrawn, not the quote by its id");
    assert_eq!(c1["standing"].as_array().unwrap().len(), 1);
    assert_eq!(
        (c1["standing"][0]["id"].clone(), c1["standing"][0]["quote"].clone()),
        (hex(&r.passage), json!("Review A includes the Ni 2010 trial in its pooled analysis."))
    );
    assert_eq!(ids(&c1["twins"]), [hex(&r.twin)], "the claim on another review with nearly the same words");
    assert_eq!(c1["twins"][0]["documents"], json!(["review_b"]));
    // what is left of the trial's paragraph once the title line is closed
    assert_eq!(c1["reread"]["passages"], json!([{"doc_id": "trial", "start": TITLE.len(), "end": TRIAL.len() - 1}]));
    let done = &report["rows"][1];
    assert_eq!(
        (done["fallen_by"].clone(), done["gone"][0]["id"].clone()),
        (json!([hex(&r.c1)]), hex(&r.title)),
        "the answer names the claim, its first cause is the title line"
    );
    assert_eq!((done["grounds_standing"].clone(), done["standing"].clone(), done["reread"]["question"].clone()), (json!(1), json!([]), json!("RQ1")));
    // the text of a fallen row, of a gone quote and of a twin is never in the report
    let text = report.to_string();
    for hidden in [TITLE, C1, TWIN] {
        assert!(!text.contains(hidden), "the report gives away {hidden:?}");
    }
    assert!(report["provable"].is_string() && report["heuristic"].is_string() && report["not_erased"].is_string());
}

#[test]
fn without_a_point_the_report_lists_what_lost_a_ground_and_after_the_withdrawal_nothing() {
    let r = run();
    let now = r.s.entries().unwrap();
    let all = fallen(&r.s, now, None, None);
    assert_eq!(ids(&all["rows"]), [hex(&r.c1), hex(&r.done)]);
    assert_eq!(all["rows"], fallen(&r.s, now, Some(&r.snapshot), None)["rows"]);
    let after = Snapshot::of(&r.s, now);
    let none = fallen(&r.s, now, Some(&after), None);
    assert_eq!((none["rows_fallen"].clone(), none["rows"].clone()), (json!(0), json!([])));
    let one = fallen(&r.s, now, None, Some(1));
    assert_eq!((one["rows"].as_array().unwrap().len(), one["truncated"].clone(), one["rows_fallen"].clone()), (1, json!(true), json!(2)));
}

#[test]
fn diff_names_what_fell_between_two_points_and_the_withdrawn_text_by_its_hash() {
    let r = run();
    let after = Snapshot::of(&r.s, r.s.entries().unwrap());
    let d = diff(&r.snapshot, &after, None);
    assert_eq!(ids(&d["fell"]["rows"]), [hex(&r.title), hex(&r.c1), hex(&r.done)]);
    assert_eq!((d["rose"]["count"].clone(), d["records_added"]["total"].clone()), (json!(0), json!(0)));
    assert_eq!(d["withdrawn_added"], json!([{"doc_id": "trial", "sha256": to_hex(&sha256(TITLE.as_bytes())), "bytes": TITLE.len()}]));
    assert_ne!(d["projections"]["from"], d["projections"]["to"]);
    assert!(!d.to_string().contains(TITLE));
}

#[test]
fn dependents_of_a_quote_and_of_a_document_by_depth() {
    let r = run();
    let of_title = dependents(&r.s, &Target::Record(r.title), None);
    assert_eq!(ids(&of_title["dependents"]), [hex(&r.c1), hex(&r.done)]);
    assert_eq!((of_title["dependents"][0]["depth"].clone(), of_title["dependents"][1]["depth"].clone()), (json!(1), json!(2)));
    assert_eq!(of_title["dependents"][1]["fallen_by"], json!([hex(&r.c1)]));
    let of_doc = dependents(&r.s, &Target::Document { doc_id: "trial", range: None }, None);
    assert_eq!((ids(&of_doc["quotes"]), of_doc["count"].clone()), (vec![hex(&r.title)], json!(2)));
    assert_eq!(of_doc["quotes"][0]["stands"], json!(false));
    // the authors line holds no quote
    let authors = dependents(&r.s, &Target::Document { doc_id: "trial", range: Some((TITLE.len() + 1, TRIAL.len())) }, None);
    assert_eq!((authors["count"].clone(), authors["quotes"].clone()), (json!(0), json!([])));
    assert_eq!(of_doc["completeness"], json!(COMPLETENESS));
}

#[test]
fn active_claims_merge_equal_text_and_name_the_documents_under_it() {
    let r = run();
    let a = active_claims(&r.s, None, None);
    assert_eq!((a["claims"].clone(), a["count"].clone()), (json!(3), json!(2)), "the twin and the control twice; the claim on the title line fell");
    let control = a["groups"].as_array().unwrap().iter().find(|g| g["text"] == CONTROL).expect("the control stands");
    assert_eq!((control["sources"].clone(), control["documents"].clone()), (json!(2), json!(["review_a", "review_b"])));
    assert_eq!(control["ids"][0], hex(&r.control));
    let b = active_claims(&r.s, Some("review_a"), None);
    assert_eq!((b["claims"].clone(), b["count"].clone()), (json!(1), json!(1)));
}

#[test]
fn record_gives_its_row_and_first_causes_and_a_quote_its_binding() {
    let r = run();
    let c1 = record_projection(&r.s, &r.c1);
    assert_eq!(c1["projection"], json!({"grounded": false, "answer_support": false, "fallen_by": [hex(&r.title)]}));
    assert_eq!((c1["dependents_direct"].clone(), c1["first_causes"][0]["cause"].clone()), (json!(1), json!("withdrawn")));
    let title = record_projection(&r.s, &r.title);
    assert_eq!((title["quote_binding"]["cause"].clone(), title["dependents_direct"].clone()), (json!("withdrawn"), json!(1)));
    let passage = record_projection(&r.s, &r.passage);
    assert!(passage["quote_binding"].get("cause").is_none(), "a standing quote has no cause");
}

#[test]
fn the_summary_tells_fallen_records_from_records_that_never_stood() {
    let r = run();
    let s = summary(&r.s);
    assert_eq!((s["fallen"].clone(), s["quotes_gone"].clone(), s["other_not_standing"].clone()), (json!(2), json!(1), json!(0)));
    assert_eq!(s["withdrawn"], json!({"texts": 1, "by_document": {"trial": 1}}));
    assert_eq!(s["records"]["claim"], json!({"total": 4, "standing": 3}));
}

#[test]
fn a_live_state_and_its_journal_read_alike() {
    let mut r = run();
    r.s.seal().unwrap();
    let now = r.s.entries().unwrap();
    let live_points = own_points(&mut r.s, &[r.before, now]).unwrap();
    assert_eq!(live_points[&r.before].rows, r.snapshot.rows, "the replay of its own journal reaches the state it had then");
    let live = json!([
        status(&r.s, now),
        fallen(&r.s, now, live_points.get(&r.before), None),
        diff(&live_points[&r.before], &live_points[&now], None),
        dependents(&r.s, &Target::Document { doc_id: "trial", range: None }, None),
        active_claims(&r.s, None, None),
        record_projection(&r.s, &r.c1),
    ]);
    assert_eq!(live[0]["projections"]["seals"].as_array().unwrap().len(), 1);
    let path = r.path.0.clone();
    let (before, _keep) = (r.before, r.path);
    drop(r.s);
    let (s, _, entries, points) = journal_points(&path, &[before, now]).unwrap();
    assert_eq!(entries, now);
    let offline = json!([
        status(&s, entries),
        fallen(&s, entries, points.get(&before), None),
        diff(&points[&before], &points[&now], None),
        dependents(&s, &Target::Document { doc_id: "trial", range: None }, None),
        active_claims(&s, None, None),
        record_projection(&s, &r.c1),
    ]);
    assert_eq!(live, offline);
}

fn one_doc(text: &str) -> (TempPath, AuditState) {
    let path = TempPath::new();
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    let s = AuditState::create_with(&path.0, &AuditOntology::base(), &[("d".to_string(), text.as_bytes().to_vec())], "fates", sha256(b"m"), &spec).unwrap();
    (path, s)
}

fn quote_and_claim(s: &mut AuditState, quote: &str) -> RecordId {
    let scope = Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() };
    let r = s.submit_records_id("seed", "worker", "task", &scope, &[observe("o", "d", quote), claim("c", "A claim on the quote", &["o"])]);
    assert!(r.error.is_none(), "{:?}", r.error);
    r.accepted[0]
}

#[test]
fn a_cause_stays_what_the_withdrawal_recorded_after_a_new_version() {
    // Codex review of 2c6864f, S3-01: the quote went with a withdrawal that overlapped part of it; a new version of the document
    // made the cause read `revoked`, and the withdrawal's hash was lost
    let text = "Before. Alpha bridge Beta Gamma. After.";
    let (path, mut s) = one_doc(text);
    let o = quote_and_claim(&mut s, "Alpha bridge Beta");
    assert_eq!(s.withdraw_text("owner", "d", "Beta Gamma").unwrap(), 1);
    let at = text.find("Beta Gamma").unwrap();
    let want = json!({"doc_id": "d", "sha256": to_hex(&sha256(b"Beta Gamma")), "bytes": 10, "span": [at, at + 10],
                      "version": s.quote_fate(&o).unwrap()["version"]});
    let fate = |s: &AuditState| {
        let f = s.quote_fate(&o).unwrap();
        (f["cause"].clone(), f["withdrawal"].clone())
    };
    assert_eq!(fate(&s), (json!("withdrawn"), want.clone()));
    s.put_document("owner", "d", b"Before. Something else entirely. After.").unwrap();
    assert_eq!(fate(&s), (json!("withdrawn"), want.clone()), "a new version does not rewrite why the quote went");
    let now = s.entries().unwrap();
    assert_eq!(fallen(&s, now, None, None)["rows"][0]["gone"][0]["withdrawal"], want);
    drop(s);
    let (s, _, _, _) = journal_points(&path.0, &[]).unwrap();
    assert_eq!(fate(&s), (json!("withdrawn"), want), "a replay of the journal records it again");
}

#[test]
fn a_later_withdrawal_nearby_does_not_take_over_the_cause() {
    // Codex review of 2c6864f, S3-02: a second withdrawal that took nothing replaced the first cause in the report
    let (path, mut s) = one_doc("Alpha bridge Zulu Finish.");
    let o = quote_and_claim(&mut s, "Alpha bridge Zulu");
    assert_eq!(s.withdraw_text("owner", "d", "Zulu Finish").unwrap(), 1);
    assert_eq!(s.withdraw_text("owner", "d", "Alpha bridge").unwrap(), 0, "the quote went already");
    let cause = |s: &AuditState| {
        let w = &s.quote_fate(&o).unwrap()["withdrawal"];
        (w["span"].clone(), w["sha256"].clone())
    };
    let want = (json!([13, 24]), json!(to_hex(&sha256(b"Zulu Finish"))));
    assert_eq!(cause(&s), want);
    drop(s);
    let (s, _, _, _) = journal_points(&path.0, &[]).unwrap();
    assert_eq!(cause(&s), want);
}

#[test]
fn a_quote_withdrawn_by_its_id_is_named_and_one_on_an_old_version_is_replaced() {
    let (_path, mut s) = one_doc("One line.\nAnother line.\n");
    let o = quote_and_claim(&mut s, "One line.");
    s.revoke_observation("owner", &o).unwrap();
    let f = s.quote_fate(&o).unwrap();
    assert_eq!((f["cause"].clone(), f["named"].clone(), f["withdrawal"]["span"].clone()), (json!("withdrawn"), json!(true), json!([0, 9])));
    let kept = quote_and_claim_as(&mut s, "Another line.", "second");
    s.put_document("owner", "d", b"One line.\nA changed line.\n").unwrap();
    let f = s.quote_fate(&kept).unwrap();
    assert_eq!((f["cause"].clone(), f["current_version"].clone()), (json!("version_replaced"), json!(false)));
}

fn quote_and_claim_as(s: &mut AuditState, quote: &str, task: &str) -> RecordId {
    let scope = Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() };
    let r = s.submit_records_id(task, "worker", task, &scope, &[observe("o", "d", quote), claim("c", "Another claim", &["o"])]);
    assert!(r.error.is_none(), "{:?}", r.error);
    r.accepted[0]
}

#[test]
fn every_quote_on_one_evidence_gets_the_cause_of_its_withdrawal() {
    // Codex recheck of baa75e5, S3-R01: two readers quoted the same bytes, one evidence under two records, and only the first
    // record got the cause; both ways of withdrawing, and the journal replayed
    for by_id in [false, true] {
        let (path, mut s) = one_doc("Alpha bridge Beta Gamma. After.");
        let a = quote_and_claim_as(&mut s, "Alpha bridge Beta", "first");
        let b = quote_and_claim_as(&mut s, "Alpha bridge Beta", "second");
        assert_eq!(s.evidence_id(&a), s.evidence_id(&b), "one evidence under two records");
        if by_id {
            s.revoke_observation("owner", &a).unwrap();
        } else {
            assert_eq!(s.withdraw_text("owner", "d", "Beta Gamma").unwrap(), 2);
        }
        let check = |s: &AuditState| {
            for (id, named) in [(a, by_id), (b, false)] {
                let f = s.quote_fate(&id).unwrap();
                assert_eq!((f["cause"].clone(), f["named"].clone()), (json!("withdrawn"), json!(named)), "by id {by_id}: {f}");
                assert!(f["withdrawal"]["span"].is_array(), "{f}");
            }
            let now = s.entries().unwrap_or(0);
            let report = fallen(s, now, None, None);
            assert!(report["rows"].as_array().unwrap().iter().all(|r| r["gone"][0]["cause"] == "withdrawn"), "{report}");
        };
        check(&s);
        drop(s);
        let (s, _, _, _) = journal_points(&path.0, &[]).unwrap();
        check(&s);
    }
}

#[test]
fn a_quote_on_an_earlier_version_withdrawn_by_its_id_names_no_bytes_of_another_version() {
    // Codex recheck of baa75e5, S3-R01: the span of a withdrawal is an occurrence on the quote's own version
    let (_path, mut s) = one_doc("One line.\nTwo.\n");
    let o = quote_and_claim(&mut s, "One line.");
    s.put_document("owner", "d", b"One line.\nThree.\n").unwrap();
    s.revoke_observation("owner", &o).unwrap();
    let f = s.quote_fate(&o).unwrap();
    assert_eq!((f["cause"].clone(), f["named"].clone(), f["current_version"].clone()), (json!("withdrawn"), json!(true), json!(false)));
    assert!(f["withdrawal"]["span"].is_null(), "{f}");
    assert_ne!(f["withdrawal"]["version"], f["version"], "the text closed in the current version, the quote is bound to the earlier one");
}
