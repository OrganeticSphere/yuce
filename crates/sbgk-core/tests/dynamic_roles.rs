//! Dynamic level 1 on real local WALs: one card, non-author execution, lease lifecycle, recovery, and legacy behavior.
use sbgk_core::audit::builder::{Builder, BuilderConfig, BUILDER_CHECKPOINT};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, TaskKind};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fresh() -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    // Windows clocks are coarse: parallel tests can read the same nanos, so a process-wide counter keeps names unique.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let wal = Wal(std::env::temp_dir().join(format!("dynamic_{}_{nonce}_{n}.wal", std::process::id())));
    let docs = [
        ("old", "OldReport", "2026-07-01", "", "AlphaPort uses former_port."),
        ("new", "NewReport", "2026-08-01", "\"OldReport\"", "AlphaPort replaces former_port."),
    ]
    .into_iter()
    .map(|(id, report, date, refs, body)| {
        (id.to_string(), format!("+++\nreport_id = \"{report}\"\ndate = \"{date}\"\npredecessor_reports = [{refs}]\n+++\n# Facts\n{body}\n").into_bytes())
    })
    .collect::<Vec<_>>();
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "dynamic-toy", sha256(b"toy")).unwrap();
    (wal, s)
}
fn seed(s: &mut AuditState, agent: &str, doc: &str, quote: &str) {
    let r = s.submit_records(
        agent,
        &format!("seed-{}", s.head()),
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["AlphaPort"]}),
            json!({"kind":"claim","local_id":"c","subject":"AlphaPort","text":quote,"stance":"reported","based_on":["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
}
fn builder() -> Builder {
    Builder::new(BuilderConfig { author_runs: true, ..Default::default() })
}
fn dispatcher() -> Dispatcher {
    Dispatcher::new(DispatchConfig { ttl_ms: 10, ..Default::default() }, vec![])
}
fn build(d: &mut Dispatcher, s: &AuditState, b: &mut Builder, who: &str, n: u64) -> Value {
    d.prepare_build(s, b, 1);
    d.acquire_for(s, who, b.caught_up(s), None, Some(&[TaskKind::Build]), n)
}
fn close(d: &mut Dispatcher, s: &mut AuditState, b: &mut Builder, t: &Value, who: &str, ops: &[Value], n: u64) -> Value {
    d.submit_build(s, b, t["task_id"].as_str().unwrap(), who, ops, n)
}

#[test]
fn author_runs_and_threshold_leave_legacy_card_cut_unchanged() {
    let (_w, mut s) = fresh();
    seed(&mut s, "w1", "old", "AlphaPort uses former_port.");
    seed(&mut s, "w2", "new", "AlphaPort replaces former_port.");
    let legacy = Builder::new(BuilderConfig::default()).next_card(&s).unwrap();
    assert_eq!(legacy.records.len(), 4);
    let (mut b, mut d) = (builder(), dispatcher());
    d.prepare_build(&s, &mut b, 5);
    assert_eq!(d.acquire(&s, "w3", false, 0)["kind"], "EXTEND", "below threshold keeps reading");
    let card = b.next_card(&s).unwrap();
    assert_eq!(card.records.len(), 2);
    assert!(card.records.iter().all(|r| r.author == "w1"));
    let t = build(&mut d, &s, &mut b, "w3", 1);
    assert_eq!(t["kind"], "BUILD", "above threshold BUILD precedes remaining EXTEND");
    assert_ne!(t["card"]["prompt"], Value::Null);
    assert_eq!(t["card"]["records"].as_array().unwrap().len(), 2);
    assert_eq!(close(&mut d, &mut s, &mut b, &t, "w3", &[], 2)["status"], "CARD_DONE");
    assert_eq!(s.checkpoint(BUILDER_CHECKPOINT).unwrap()["context"]["build_agent"], "w3");
    assert_eq!(b.next_card(&s).unwrap().records[0].author, "w2");
}

#[test]
fn owner_and_kind_checks_precede_any_operation_and_only_one_card_is_leased() {
    let (_w, mut s) = fresh();
    seed(&mut s, "w1", "old", "AlphaPort uses former_port.");
    let (mut b, mut d) = (builder(), dispatcher());
    assert_eq!(build(&mut d, &s, &mut b, "w1", 0)["status"], "WAIT");
    let t = build(&mut d, &s, &mut b, "w2", 0);
    assert_eq!(t["kind"], "BUILD");
    assert_eq!(build(&mut d, &s, &mut b, "w3", 1)["status"], "WAIT");
    let root = s.root();
    assert_eq!(close(&mut d, &mut s, &mut b, &t, "w1", &[], 1)["code"], "TASK_NOT_OWNED");
    assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w2", &[], 1)["code"], "BUILD_OPERATIONS_REQUIRED");
    assert_eq!(s.root(), root);
    assert_eq!(close(&mut d, &mut s, &mut b, &t, "w2", &[], 2)["status"], "CARD_DONE");
}

#[test]
fn release_and_expiry_allow_a_new_executor_without_advancing_the_cursor() {
    let (_w, mut s) = fresh();
    seed(&mut s, "w1", "old", "AlphaPort uses former_port.");
    let (mut b, mut d) = (builder(), dispatcher());
    let t = build(&mut d, &s, &mut b, "w2", 0);
    assert_eq!(d.release_durable(&mut s, t["task_id"].as_str().unwrap(), "w2")["status"], "RELEASED");
    let again = build(&mut d, &s, &mut b, "w3", 1);
    assert_eq!(again["card_id"], t["card_id"]);
    assert_eq!(b.cursor(), 0);
    let root = s.root();
    assert_eq!(close(&mut d, &mut s, &mut b, &again, "w3", &[], 12)["status"], "STALE_TASK");
    assert_eq!(s.root(), root);
    let last = build(&mut d, &s, &mut b, "w2", 13);
    assert_eq!(last["card_id"], again["card_id"]);
    assert_eq!(close(&mut d, &mut s, &mut b, &last, "w2", &[], 14)["status"], "CARD_DONE");
}

#[test]
fn partial_operations_recover_then_close_atomically_under_the_new_executor() {
    let (w, mut s) = fresh();
    seed(&mut s, "w1", "old", "AlphaPort uses former_port.");
    let (mut b, mut d) = (builder(), dispatcher());
    let t = build(&mut d, &s, &mut b, "w2", 0);
    let ob = t["card"]["records"][0]["id"].as_str().unwrap();
    let proposal = json!({"op":"propose_concept","type":"Component","name":"alpha port","aliases":[],"basis":[ob]});
    let bad = json!({"op":"map_term","record":ob,"term":"not-issued","concept":"alpha port"});
    let r = close(&mut d, &mut s, &mut b, &t, "w2", &[proposal, bad], 1);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["committed_ops"], 1);
    assert_eq!(b.cursor(), 0);
    let root = s.root();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    assert_eq!(s.root(), root);
    let (mut b, mut d) = (builder(), dispatcher());
    b.recover(&s);
    d.recover(&s);
    assert_eq!(close(&mut d, &mut s, &mut b, &t, "w2", &[], 2)["status"], "STALE_TASK");
    let next = build(&mut d, &s, &mut b, "w3", 3);
    assert_eq!(next["card_id"], t["card_id"]);
    assert_ne!(next["task_id"], t["task_id"]);
    let op = json!({"op":"map_term","record":ob,"term":"AlphaPort","concept":"alpha port"});
    let r = close(&mut d, &mut s, &mut b, &next, "w3", &[op], 4);
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert_eq!(s.candidates("alpha port", 10).len(), 1);
    assert_eq!(s.checkpoint(BUILDER_CHECKPOINT).unwrap()["context"]["build_agent"], "w3");
    let closed_root = s.root();
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(s.root(), closed_root);
    let mut b = builder();
    b.recover(&s);
    assert!(b.caught_up(&s));
}

#[test]
fn pair_card_excludes_both_endpoint_authors() {
    let (_w, mut s) = fresh();
    seed(&mut s, "w1", "old", "AlphaPort uses former_port.");
    seed(&mut s, "w2", "new", "AlphaPort replaces former_port.");
    let (mut b, mut d) = (builder(), dispatcher());
    while let Some(c) = b.next_card(&s) {
        assert_eq!(b.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    b.prepare_pairs(&s, true);
    // Complete initial sections, so even a pair with zero record backlog is offered.
    for who in ["w1", "w2"] {
        let t = d.acquire(&s, who, false, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), who, &[], 1)["status"], "COMMITTED");
    }
    d.prepare_build(&s, &mut b, usize::MAX);
    let c = b.next_card(&s).expect("pair");
    assert!(c.pair.is_some());
    for who in ["w1", "w2"] {
        assert_eq!(d.acquire_for(&s, who, false, None, Some(&[TaskKind::Build]), 2)["status"], "WAIT");
    }
    let t = d.acquire_for(&s, "w3", false, None, Some(&[TaskKind::Build]), 2);
    assert_eq!(t["kind"], "BUILD", "{t}");
    assert_eq!(close(&mut d, &mut s, &mut b, &t, "w3", &[], 3)["status"], "CARD_DONE");
    assert_eq!(s.checkpoint(&format!("builder:pair:{}", c.card_id)).unwrap()["context"]["build_agent"], "w3");
}
