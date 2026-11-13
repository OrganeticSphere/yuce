//! An answer lists each of its records once (0.2.1): the scenarios of Codex's review of 3d994d04, DID-01 (the done record and the
//! report of what fell) and DID-02 (a recovered answer of 0.2.0 written again), and its checks of what must not change.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::read::{self, Target};
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig::default(),
        vec![ResearchQuestion { id: "RQ1".into(), text: "What holds about topic?".into(), about: vec!["topic".into()], ..Default::default() }],
    )
}
fn claim(id: &str, on: &str, text: &str) -> Value {
    json!({"kind":"claim","local_id":id,"text":text,"subject":"topic","stance":"reported","based_on":[on]})
}
fn done(t: &Value, ids: &[&str]) -> Value {
    json!({"kind":"done","local_id":"done","rq_id":"RQ1","directive_id":t["task_id"],"outcome":"answered","answer_ids":ids})
}
fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}
fn assert_unique(v: &Value) {
    let ids = strings(v);
    assert_eq!(ids.len(), ids.iter().collect::<BTreeSet<_>>().len(), "{v}");
}
struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
struct Prepared {
    wal: PathBuf,
    _guard: Wal,
    s: AuditState,
    d: Dispatcher,
    obs: Vec<RecordId>,
    seeds: Vec<RecordId>,
    task: Value,
}
fn prepared() -> Prepared {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = std::env::temp_dir().join(format!("distinct_answer_ids_{}_{nonce}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let docs = vec![("a".into(), b"Topic alpha holds.\n".to_vec()), ("b".into(), b"Topic beta holds.\n".to_vec())];
    let mut s = AuditState::create(&wal, &AuditOntology::base(), &docs, "distinct-review", sha256(b"offline")).unwrap();
    let (mut obs, mut seeds) = (Vec::new(), Vec::new());
    for (doc, quote) in [("a", "Topic alpha holds."), ("b", "Topic beta holds.")] {
        let r = s.submit_records(
            "reader",
            doc,
            &Scope { docs: vec![doc.into()], ..Default::default() },
            &[json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["topic"]}), claim("c", "o", "Topic is reported on this page.")],
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        obs.push(r.accepted[0]);
        seeds.push(r.accepted[1]);
    }
    let mut d = dispatcher();
    for n in 0..2 {
        let t = d.acquire(&s, "reader", true, n);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "reader", &[], n)["status"], "COMMITTED");
    }
    let task = d.acquire(&s, "summary", true, 3);
    assert_eq!(task["kind"], "SUMMARIZE", "{task}");
    Prepared { _guard: Wal(wal.clone()), wal, s, d, obs, seeds, task }
}

#[test]
fn coverage_prefix_resolves_aliases_once_across_attempts_and_physical_recovery() {
    let mut p = prepared();
    let tid = p.task["task_id"].as_str().unwrap().to_string();
    let first = p.d.submit(&mut p.s, &tid, "summary", &[claim("only_a", &p.obs[0].short(), "Topic alpha holds."), done(&p.task, &["only_a", "only_a"])], 4);
    assert_eq!(first["status"], "REPAIR_REQUIRED", "{first}");
    let a = first["accepted_locals"]["only_a"].as_str().unwrap().to_string();
    let prefix = p.s.checkpoint("summary-prefix:RQ1").unwrap();
    assert_unique(&prefix["context"]["answer_ids"]);
    assert_eq!(prefix["context"]["answer_ids"].as_array().unwrap().len(), 1);
    let n = p.s.records_since(0).len();
    // The local alias was accepted earlier. The kernel now also inserts the same record as @id.
    let retry = p.d.submit(&mut p.s, &tid, "summary", &[done(&p.task, &["only_a"])], 5);
    assert_eq!(retry["status"], "REPAIR_REQUIRED", "{retry}");
    assert_eq!(p.s.records_since(0).len(), n);
    assert_eq!(retry["retained_answer_ids"], json!([a]));
    assert_unique(&p.s.checkpoint("summary-prefix:RQ1").unwrap()["context"]["answer_ids"]);
    drop(p.s);
    let mut s = AuditState::open(&p.wal).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    let t = d.acquire(&s, "repair", true, 6);
    assert_eq!(t["retained_answer_ids"], json!([a]));
    let r = d.submit(
        &mut s,
        t["task_id"].as_str().unwrap(),
        "repair",
        &[claim("only_b", &p.obs[1].short(), "Topic beta holds."), done(&t, &["only_b", &a, "only_b", &a])],
        7,
    );
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let b = r["accepted_locals"]["only_b"].as_str().unwrap().to_string();
    let expected = json!([b, a]);
    assert_eq!(d.accepted_outcomes(&s)["RQ1"]["answer_ids"], expected);
    let context = s.checkpoint("task:rq:RQ1").unwrap();
    assert_unique(&context["context"]["answer_ids"]);
    drop(s);
    let s = AuditState::open(&p.wal).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    assert_eq!(d.accepted_outcomes(&s)["RQ1"]["answer_ids"], expected);
    assert_eq!(d.acquire(&s, "next", true, 8)["status"], "COMPLETE");
}

#[test]
fn equal_words_on_different_quotes_keep_both_record_ids() {
    let mut p = prepared();
    assert_ne!(p.seeds[0], p.seeds[1]);
    let (a, b) = (p.seeds[0].short(), p.seeds[1].short());
    let r = p.d.submit(&mut p.s, p.task["task_id"].as_str().unwrap(), "summary", &[done(&p.task, &[&b, &a, &b, &a])], 4);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(p.d.accepted_outcomes(&p.s)["RQ1"]["answer_ids"], json!([b, a]));
}

#[test]
fn a_bad_reference_among_repeats_still_prevents_completion() {
    let mut p = prepared();
    let a = p.seeds[0].short();
    let r = p.d.submit(&mut p.s, p.task["task_id"].as_str().unwrap(), "summary", &[done(&p.task, &[&a, "not_a_record", &a])], 4);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert!(p.s.checkpoint("task:rq:RQ1").is_none());
    assert!(p.d.accepted_outcomes(&p.s).as_object().unwrap().is_empty());
}

#[test]
fn a_done_record_names_each_record_once_and_the_fallen_report_counts_distinct_grounds() {
    let mut p = prepared();
    let (a, b) = (p.seeds[0].short(), p.seeds[1].short());
    let r = p.d.submit(&mut p.s, p.task["task_id"].as_str().unwrap(), "summary", &[done(&p.task, &[&a, &b, &a, &b])], 4);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(p.d.accepted_outcomes(&p.s)["RQ1"]["answer_ids"], json!([a, b]));
    let done_id = p.s.records_since(0).into_iter().find(|r| r.kind == sbgk_core::audit::RecordKind::Done).unwrap().id;
    let done = p.s.record(&done_id).unwrap();
    assert_eq!(done.body["answer_ids"].as_array().unwrap().len(), 2, "the stored done names each record once");
    assert_eq!(done.based_on.len(), 2);
    p.s.revoke_observation("owner", &p.obs[0]).unwrap();
    let report = read::fallen(&p.s, 0, None, None);
    let row = report["rows"].as_array().unwrap().iter().find(|r| r["id"] == to_hex(&done_id.0)).unwrap();
    let active = read::active_claims(&p.s, None, None);
    for group in active["groups"].as_array().unwrap() {
        assert_unique(&group["ids"]);
    }
    let dependents = read::dependents(&p.s, &Target::Record(p.obs[0]), None);
    let ids = dependents["dependents"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(ids.len(), ids.iter().collect::<BTreeSet<_>>().len());
    let distinct_standing = done.based_on.iter().filter(|id| p.s.is_grounded(id)).copied().collect::<BTreeSet<_>>().len();
    // one distinct claim still stands under the done, and the report says one
    assert_eq!(row["grounds_standing"], json!(distinct_standing), "DID-01: the report of what fell counts distinct grounds");
}

#[test]
fn a_recovered_answer_with_repeats_is_written_once_in_a_new_unresolved_checkpoint() {
    let mut p = prepared();
    let (a, b) = (p.seeds[0].short(), p.seeds[1].short());
    let r = p.d.submit(&mut p.s, p.task["task_id"].as_str().unwrap(), "summary", &[done(&p.task, &[&a, &b, &a, &b])], 4);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    // Seed exactly the legacy checkpoint shape observed in both frozen K02 WALs.
    let mut old = p.s.checkpoint("task:rq:RQ1").unwrap();
    old["context"]["answer_ids"] = json!([to_hex(&p.seeds[0].0), to_hex(&p.seeds[1].0), to_hex(&p.seeds[0].0), to_hex(&p.seeds[1].0)]);
    p.s.submit_operations_id("legacy-shape-fixture", "kernel", &[], Some(old)).unwrap();
    drop(p.s);
    let mut s = AuditState::open(&p.wal).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    assert_eq!(d.accepted_outcomes(&s)["RQ1"]["answer_ids"], json!([a, b, a, b]), "legacy replay remains unchanged");
    s.revoke_observation("owner", &p.obs[0]).unwrap();
    for n in 0..3 {
        let t = d.acquire(&s, "fail", true, 100 + n);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "fail", &[], 100 + n)["status"], "REPAIR_REQUIRED");
        d.release_durable(&mut s, t["task_id"].as_str().unwrap(), "fail");
    }
    let cp = s.checkpoint("task:rq:RQ1").unwrap();
    assert_eq!(cp["context"]["unresolved"], true, "{cp}");
    let ids = &cp["context"]["retained_answer"]["answer_ids"];
    assert_unique(ids);
    assert_unique(&cp["context"]["retained_answer"]["fallen_ids"]);
}
