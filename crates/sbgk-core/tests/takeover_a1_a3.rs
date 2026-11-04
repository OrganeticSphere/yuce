//! Offline regressions for the stopped consilium implementation; no provider or runner calls.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_WAL: AtomicU64 = AtomicU64::new(0);

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fresh(text: &str) -> (Wal, AuditState, Dispatcher) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("consilium_takeover_{}_{nonce}_{}.wal", std::process::id(), NEXT_WAL.fetch_add(1, Ordering::Relaxed))));
    let docs = vec![("d1".into(), text.as_bytes().to_vec())];
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "takeover", sha256(b"offline")).unwrap();
    let d = Dispatcher::new(
        DispatchConfig { section_bytes: 6000, ..Default::default() },
        vec![ResearchQuestion { id: "RQ1".into(), text: "What is known about topic?".into(), about: vec!["topic".into()], ..Default::default() }],
    );
    (wal, s, d)
}
fn observe(n: &str, quote: &str) -> Value {
    json!({"kind":"observe", "local_id":n, "doc_id":"d1", "exact_quote":quote, "terms":["topic"]})
}
fn claim(n: &str, on: &str, text: &str) -> Value {
    json!({"kind":"claim", "local_id":n, "text":text, "subject":"topic", "stance":"reported", "based_on":[on]})
}
fn done(t: &Value, ids: &[String]) -> Value {
    json!({"kind":"done", "local_id":format!("{}d1",t["local_id_prefix"].as_str().unwrap()), "rq_id":"RQ1", "directive_id":t["task_id"], "outcome":"answered", "answer_ids":ids})
}

#[test]
fn changed_accepted_alias_is_explicitly_refused_without_poisoning_its_dependents() {
    let (_w, mut s, mut d) = fresh("# Facts\nTopic A holds. Topic B holds.\n");
    let t = d.acquire(&s, "w", true, 0);
    let id = t["task_id"].as_str().unwrap();
    let first = d.submit(&mut s, id, "w", &[observe("o", "Topic A holds."), claim("bad", "o", &"x".repeat(241))], 1);
    assert_eq!(first["status"], "REPAIR_REQUIRED");
    assert_eq!(first["audit_persisted"], true, "{first}");
    assert!(s.checkpoint(&format!("task-repair:{id}:1")).is_some());
    let second = d.submit(&mut s, id, "w", &[observe("o", "Topic B holds."), claim("c", "o", "Topic A holds.")], 2);
    assert_eq!(second["status"], "REPAIR_REQUIRED", "changed aliases must never be silently acknowledged: {second}");
    assert_eq!(second["refused"][0]["error"]["field"], "local_id", "{second}");
    assert!(second["accepted_locals"].get("c").is_some(), "references still bind the original accepted o: {second}");
    assert_eq!(s.records_since(0).len(), 2);
}

#[test]
fn forward_dag_and_independent_tail_survive_invalid_and_cyclic_components() {
    let (_w, mut s, mut d) = fresh("# Facts\nTopic A holds.\n");
    let t = d.acquire(&s, "w", true, 0);
    let id = t["task_id"].as_str().unwrap();
    let r = d.submit(
        &mut s,
        id,
        "w",
        &[
            claim("c", "o", "Topic A holds."),
            observe("wrong", "missing bytes"),
            claim("blocked", "wrong", "Topic is missing."),
            claim("cycle1", "cycle2", "Topic cycles."),
            claim("cycle2", "cycle1", "Topic cycles."),
            observe("o", "Topic A holds."),
            claim("tail", "o", "Topic remains known."),
        ],
        1,
    );
    for n in ["o", "c", "tail"] {
        assert!(r["accepted_locals"].get(n).is_some(), "{n}: {r}");
    }
    assert_eq!(s.records_since(0).len(), 3, "only closed valid subgraphs: {r}");
    assert_eq!(r["repair_scope"], "rejected_items_only");
}

#[test]
fn s0_claim_uses_only_whitespace_normalized_exact_quote_including_its_identifiers() {
    let (_w, mut s, mut d) = fresh("# Facts\nTopic changed naturally from\n`4c8a2e19` to `7d3f5b02`.\n");
    let t = d.acquire(&s, "w", true, 0);
    let r = d.submit(
        &mut s,
        t["task_id"].as_str().unwrap(),
        "w",
        &[observe("o", "Topic changed naturally from `4c8a2e19` to `7d3f5b02`."), claim("c", "o", "Topic changed from 4c8a2e19 to 7d3f5b02.")],
        1,
    );
    assert_eq!(r["status"], "COMMITTED", "S0 must inspect the bytes actually stored: {r}");
    assert_eq!(r["extended"].as_array().unwrap().len(), 1);
    assert_eq!(s.records_since(0).len(), 2);
}

#[test]
fn withdrawal_retains_independent_summary_rows_in_delivery_repair_and_restart() {
    let (w, mut s, mut d) = fresh("# Facts\nTopic A holds. Topic B holds.\n");
    let seed = s.submit_records(
        "reader",
        "seed",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[observe("a", "Topic A holds."), claim("ca", "a", "Topic A holds."), observe("b", "Topic B holds."), claim("cb", "b", "Topic B holds.")],
    );
    assert!(seed.error.is_none(), "{:?}", seed.error);
    let read = d.acquire(&s, "r", true, 0);
    assert_eq!(read["kind"], "EXTEND");
    assert_eq!(d.submit(&mut s, read["task_id"].as_str().unwrap(), "r", &[], 1)["status"], "COMMITTED");
    let t = d.acquire(&s, "sum", true, 2);
    assert_eq!(t["kind"], "SUMMARIZE");
    let r = d.submit(
        &mut s,
        t["task_id"].as_str().unwrap(),
        "sum",
        &[
            claim("sa", &seed.accepted[0].short(), "Topic A holds."),
            claim("sb", &seed.accepted[2].short(), "Topic B holds."),
            done(&t, &["sa".into(), "sb".into()]),
        ],
        3,
    );
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let keep = r["accepted_locals"]["sb"].as_str().unwrap().to_string();
    s.revoke_observation("owner", &seed.accepted[0]).unwrap();
    let view = d.accepted_outcomes(&s);
    assert_eq!(view["RQ1"]["answer_ids"], json!([keep]), "independent rows remain visible immediately: {view}");
    assert_eq!(view["RQ1"]["requires_repair"], true, "{view}");
    let mut restored = Dispatcher::new(
        DispatchConfig::default(),
        vec![ResearchQuestion { id: "RQ1".into(), text: "What is known about topic?".into(), about: vec!["topic".into()], ..Default::default() }],
    );
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    restored.recover(&s);
    // A failed delta repair must also retain its independent view durably; its unresolved checkpoint replaces the old task
    // checkpoint, so it must carry that view explicitly.
    let failed_wal = Wal(w.0.with_extension("failed.wal"));
    drop(s); // Release the Windows WAL writer lock before copying this private test file.
    std::fs::copy(&w.0, &failed_wal.0).unwrap();
    let mut s = AuditState::open(&w.0).unwrap();
    let mut failed_state = AuditState::open(&failed_wal.0).unwrap();
    let mut failed_dispatch = dispatcher_like();
    failed_dispatch.recover(&failed_state);
    for n in 0..3 {
        let t = failed_dispatch.acquire(&failed_state, "fail", true, 10 + n);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        assert_eq!(failed_dispatch.submit(&mut failed_state, t["task_id"].as_str().unwrap(), "fail", &[], 10 + n)["status"], "REPAIR_REQUIRED");
        failed_dispatch.release_durable(&mut failed_state, t["task_id"].as_str().unwrap(), "fail");
    }
    drop(failed_state);
    let failed_state = AuditState::open(&failed_wal.0).unwrap();
    let mut failed_dispatch = dispatcher_like();
    failed_dispatch.recover(&failed_state);
    assert_eq!(failed_dispatch.accepted_outcomes(&failed_state)["RQ1"]["answer_ids"], json!([keep]));
    let repair = restored.acquire(&s, "repair", true, 4);
    assert_eq!(repair["kind"], "SUMMARIZE", "{repair}");
    assert_eq!(repair["retained_answer_ids"], json!([keep]), "{repair}");
    // A delta may explicitly remove the invalid row; a caller cannot accidentally erase retained rows by omitting them.
    let mut close = done(&repair, &[]);
    close["outcome"] = json!("unknown");
    let r = restored.submit(&mut s, repair["task_id"].as_str().unwrap(), "repair", &[close], 5);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let view = restored.accepted_outcomes(&s);
    assert_eq!(view["RQ1"]["answer_ids"], json!([keep]), "{view}");
    let done_id = view["RQ1"]["done"].as_str().unwrap();
    let record = s.records_since(0).into_iter().find(|r| r.id.short() == done_id).unwrap();
    assert_eq!(record.based_on.len(), 1, "the new durable done binds retained rows too");
    let mut recovered = dispatcher_like();
    recovered.recover(&s);
    assert_eq!(recovered.accepted_outcomes(&s)["RQ1"]["answer_ids"], json!([keep]));
}
fn dispatcher_like() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig::default(),
        vec![ResearchQuestion { id: "RQ1".into(), text: "What is known about topic?".into(), about: vec!["topic".into()], ..Default::default() }],
    )
}

#[test]
fn soft_wrapped_quote_stores_source_bytes_but_never_crosses_a_list_boundary() {
    let (_w, mut s, mut d) = fresh("# Facts\nTopic has a bounded\n  continuation for 1.99.0.\n\n- Topic one\n- another item.\n");
    let t = d.acquire(&s, "w", true, 0);
    let task = t["task_id"].as_str().unwrap();
    let r = d.submit(
        &mut s,
        task,
        "w",
        &[
            observe("o", "Topic has a bounded continuation for 1.99.0."),
            claim("c", "o", "Topic is bounded for 1.99.0."),
            observe("bad", "Topic one - another item."),
        ],
        1,
    );
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    for n in ["o", "c"] {
        assert!(r["accepted_locals"].get(n).is_some(), "{r}");
    }
    let o = s.records_since(0).into_iter().find(|r| r.kind.name() == "observe").unwrap();
    assert_eq!(o.quote.as_deref(), Some("Topic has a bounded\n  continuation for 1.99.0."));
    assert!(s.is_grounded(&o.id));
    assert_eq!(r["not_stored"], json!(["bad"]), "separate list items cannot be normalized into one quote");
}
