//! Assigned C0 durability and retry regressions: real store, no providers.
use sbgk_core::audit::{
    agent_failures,
    builder::{Builder, BuilderConfig},
    directives::{DispatchConfig, Dispatcher},
    onto::AuditOntology,
    state::AuditState,
    AuditStore, LinkStatus, Scope,
};
use sbgk_core::hash::sha256;
use serde_json::json;
use std::path::PathBuf;
struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fresh(tag: &str, limit: u32) -> (Wal, AuditState) {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let w = Wal(std::env::temp_dir().join(format!("c0-failover-{tag}-{}-{n}.wal", std::process::id())));
    let mut s = AuditState::create(
        &w.0,
        &AuditOntology::base(),
        &[("d".into(), b"First independent evidence.\nSecond independent evidence.\n".to_vec())],
        tag,
        sha256(tag.as_bytes()),
    )
    .unwrap();
    let r =
        s.submit_operations_id("policy", "kernel", &[], Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"agent_attempts":limit}}))).unwrap();
    assert_eq!(r["checkpointed"], true);
    (w, s)
}
fn dispatch(limit: u32) -> Dispatcher {
    Dispatcher::new(DispatchConfig { agent_attempts: Some(limit), ttl_ms: 100, ..Default::default() }, vec![])
}
fn seeded(s: &mut AuditState) -> Vec<sbgk_core::audit::RecordId> {
    let r = s.submit_records(
        "writer",
        "seed",
        &Scope { docs: vec!["d".into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"o1","doc_id":"d","exact_quote":"First independent evidence.","terms":["first"]}),
            json!({"kind":"observe","local_id":"o2","doc_id":"d","exact_quote":"Second independent evidence.","terms":["second"]}),
            json!({"kind":"claim","local_id":"c1","text":"First fact","subject":"first","stance":"reported","based_on":["o1"]}),
            json!({"kind":"claim","local_id":"c2","text":"Second fact","subject":"second","stance":"reported","based_on":["o2"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    r.accepted
}
#[test]
fn reader_failure_reissues_unique_lease_and_restores_attempt_limit() {
    let (w, mut s) = fresh("reader", 2);
    let mut d = dispatch(2);
    let a = d.acquire(&s, "w1", true, 1);
    assert_eq!(a["kind"], "EXTEND");
    let task = a["task_id"].as_str().unwrap();
    assert_eq!(d.timeout_task(&mut s, task, "intruder")["code"], "TASK_NOT_OWNED");
    assert!(agent_failures::entry(&s, a["key"].as_str().unwrap()).is_null());
    assert_eq!(d.timeout_task(&mut s, task, "w1")["failures"], 1);
    let root = s.root();
    assert_eq!(d.timeout_task(&mut s, task, "w1")["status"], "STALE_TASK");
    assert_eq!(s.root(), root);
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    assert_eq!(s.root(), root);
    let mut d = dispatch(2);
    d.recover(&s);
    let b = d.acquire(&s, "w2", true, 2);
    assert_eq!(b["key"], a["key"]);
    assert_ne!(b["task_id"], a["task_id"]);
    let out = d.timeout_task(&mut s, b["task_id"].as_str().unwrap(), "w2");
    assert_eq!(out["unresolved"], true, "{out}");
    let key = a["key"].as_str().unwrap();
    assert_eq!(agent_failures::entry(&s, key)["failures"], 2);
    assert!(d.completion(&s, true)["unresolved"].as_array().unwrap().contains(&a["key"]));
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    let mut d = dispatch(2);
    d.recover(&s);
    assert_ne!(d.acquire(&s, "w3", true, 3)["key"], a["key"]);
}
#[test]
fn expired_lease_waits_for_durable_failure_before_reissue() {
    let (_w, mut s) = fresh("expiry", 1);
    let mut d = dispatch(1);
    let a = d.acquire(&s, "w1", true, 1);
    let wait = d.acquire(&s, "w2", true, 102);
    assert_eq!(wait["status"], "WAIT", "{wait}");
    assert!(d.terminal_receipt(&s, s.head(), "expiry").is_none());
    assert!(d.persist_unresolved(&mut s).is_empty());
    assert_eq!(agent_failures::entry(&s, a["key"].as_str().unwrap())["attempts"][0]["reason"], "LEASE_EXPIRED");
    assert_ne!(d.acquire(&s, "w2", true, 103)["key"], a["key"]);
}
#[test]
fn failed_verification_stays_proposed_then_other_work_continues() {
    let (_w, mut s) = fresh("verify", 1);
    let ids = seeded(&mut s);
    let l = s.add_link("gb", &ids[2], "supports", &ids[3], &[ids[0]]).unwrap().id;
    let mut d = dispatch(1);
    let a = d.acquire(&s, "checker", true, 1);
    assert_eq!(a["kind"], "VERIFY_LINK", "{a}");
    assert_eq!(d.timeout_task(&mut s, a["task_id"].as_str().unwrap(), "checker")["unresolved"], true);
    assert_eq!(s.link(&l).unwrap().status, LinkStatus::Proposed);
    let b = d.acquire(&s, "w2", true, 2);
    assert_ne!(b["key"], a["key"]);
    assert_eq!(b["kind"], "EXTEND", "{b}");
}
#[test]
fn standalone_builder_keeps_card_and_committed_prefix_then_skips_only_failed_range() {
    let (w, mut s) = fresh("builder", 2);
    let ids = seeded(&mut s);
    let cfg = BuilderConfig { max_records: 2, ..Default::default() };
    let mut b = Builder::new(cfg);
    let card = b.next_card(&s).unwrap();
    let ops = [
        json!({"op":"propose_concept","type":"Component","name":"first","basis":[ids[0].short()]}),
        json!({"op":"map_term","record":ids[0].short(),"term":"first","concept":"absent"}),
    ];
    let prefix = b.submit(&mut s, &card.card_id, &ops);
    let r = prefix.clone();
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["committed_ops"], 1);
    let r = b.agent_failure(&mut s, &card.card_id, "physical-1", "gb", "AGY_STREAM_FAILURE");
    assert_eq!(r["status"], "CARD_RETRY", "{r}");
    assert_eq!(b.next_card(&s).unwrap().card_id, card.card_id);
    let root = s.root();
    assert_eq!(b.agent_failure(&mut s, &card.card_id, "physical-1", "gb", "AGY_STREAM_FAILURE")["replayed"], true);
    assert_eq!(root, s.root());
    assert_eq!(b.agent_failure(&mut s, &card.card_id, "physical-1", "gb", "other")["error"]["code"], "FAILURE_ATTEMPT_CONFLICT");
    assert_eq!(root, s.root());
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut b = Builder::new(cfg);
    b.recover(&s);
    assert_eq!(b.next_card(&s).unwrap().card_id, card.card_id);
    let root = s.root();
    let replay = b.submit(&mut s, &card.card_id, &ops);
    assert_eq!(replay["results"], prefix["results"]);
    assert_eq!(replay["committed_ops"], prefix["committed_ops"]);
    assert_eq!(root, s.root());
    assert_eq!(s.concepts().len(), 1);
    let out = b.agent_failure(&mut s, &card.card_id, "physical-2", "gb", "AGY_TIMEOUT");
    assert_eq!(out["status"], "CARD_UNRESOLVED", "{out}");
    let next = b.next_card(&s).unwrap();
    assert_ne!(next.card_id, card.card_id);
    assert!(next.cursor_from >= card.cursor_to);
    let range = next.cursor_from;
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    let mut b = Builder::new(cfg);
    b.recover(&s);
    let c = b.next_card(&s).unwrap();
    assert_eq!(c.cursor_from, range);
    let mut s = s;
    assert_eq!(b.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
}
#[test]
fn legacy_c0_timeout_route_is_unchanged_without_opt_in() {
    let (_w, mut s) = fresh("legacy", 2);
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let a = d.acquire(&s, "w", true, 1);
    let root = s.root();
    assert_eq!(d.timeout_task(&mut s, a["task_id"].as_str().unwrap(), "w")["code"], "CIRCLES_REQUIRED");
    assert_eq!(root, s.root());
}

#[test]
fn pool_failure_does_not_jump_over_an_open_prefix_and_survives_restart() {
    use sbgk_core::audit::builder::parallel::ParallelBuilder;
    let (w, mut s) = fresh("pool", 1);
    seeded(&mut s);
    let cfg = BuilderConfig { max_records: 1, ..Default::default() };
    let readers = vec!["w1".into(), "w2".into()];
    let mut p = ParallelBuilder::new(cfg, readers.clone());
    let cards = p.offers(&mut s, 1, false).unwrap();
    assert_eq!(cards.len(), 2);
    let r = p.worker_mut(&cards[1].card_id).unwrap().agent_failure(&mut s, &cards[1].card_id, "b-failed", "w2", "AGY_STREAM_FAILURE");
    assert_eq!(r["status"], "CARD_UNRESOLVED");
    assert_eq!(p.cursor(&s), 0);
    let d = dispatch(1);
    assert!(d.completion(&s, false)["unresolved"].as_array().unwrap().contains(&json!(format!("build:{}", cards[1].card_id))));
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut p = ParallelBuilder::new(cfg, readers);
    p.recover(&s).unwrap();
    assert_eq!(p.cursor(&s), 0);
    assert_eq!(p.worker_mut(&cards[0].card_id).unwrap().submit(&mut s, &cards[0].card_id, &[])["status"], "CARD_DONE");
    assert_eq!(p.cursor(&s), cards[1].cursor_to);
    let next = p.offers(&mut s, 1, false).unwrap();
    assert!(next.iter().all(|c| c.card_id != cards[1].card_id));
}

#[test]
fn crash_between_failure_and_cursor_checkpoint_rolls_forward_before_next_close() {
    let (w, mut s) = fresh("cursor-crash", 1);
    seeded(&mut s);
    let cfg = BuilderConfig { max_records: 2, ..Default::default() };
    let mut b = Builder::new(cfg);
    let c = b.next_card(&s).unwrap();
    agent_failures::record(
        &mut s,
        &format!("build:{}", c.card_id),
        "interrupted",
        "gb",
        "AGY_TIMEOUT",
        Some(json!({"range":[c.cursor_from,c.cursor_to],"pool":false})),
    )
    .unwrap();
    assert!(s.checkpoint(sbgk_core::audit::builder::BUILDER_CHECKPOINT).is_none());
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut b = Builder::new(cfg);
    b.recover(&s);
    let next = b.next_card(&s).unwrap();
    assert_eq!(next.cursor_from, c.cursor_to);
    assert_eq!(b.submit(&mut s, &next.card_id, &[])["status"], "CARD_DONE");
    assert_eq!(s.checkpoint(sbgk_core::audit::builder::BUILDER_CHECKPOINT).unwrap()["to"], next.cursor_to);
}
