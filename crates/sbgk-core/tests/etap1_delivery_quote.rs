//! Stage 1 regressions: no provider, runner, or shared WAL.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Wal(std::path::PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn questions() -> Vec<ResearchQuestion> {
    vec![ResearchQuestion { id: "RQ1".into(), text: "What holds about topic?".into(), about: vec!["topic".into()], ..Default::default() }]
}
fn state(docs: Vec<(String, Vec<u8>)>) -> (Wal, AuditState, Dispatcher) {
    let wal = Wal(std::env::temp_dir().join(format!("codex_etap1_{}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
    assert!(!wal.0.exists());
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "etap1", sha256(b"toy")).unwrap();
    (wal, s, Dispatcher::new(DispatchConfig::default(), questions()))
}
fn claim(id: &str, on: &str, text: &str) -> Value {
    json!({"kind":"claim","local_id":id,"text":text,"subject":"topic","stance":"reported","based_on":[on]})
}
fn done(t: &Value, ids: &[&str]) -> Value {
    json!({"kind":"done","local_id":"done","rq_id":"RQ1","directive_id":t["task_id"],"outcome":"answered","answer_ids":ids})
}

#[test]
fn missing_window_report_requires_delta_and_retains_prefix_after_physical_reopen() {
    let docs = vec![
        ("a".into(), b"Topic alpha holds.\n".to_vec()),
        ("b".into(), b"Topic beta holds.\n".to_vec()),
        ("outside".into(), b"Unrelated material.\n".to_vec()),
    ];
    let (wal, mut s, mut d) = state(docs);
    let mut obs = vec![];
    for (doc, quote) in [("a", "Topic alpha holds."), ("b", "Topic beta holds.")] {
        let r = s.submit_records(
            "seed",
            doc,
            &Scope { docs: vec![doc.into()], ..Default::default() },
            &[json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["topic"]}), claim("c", "o", quote)],
        );
        assert!(r.error.is_none());
        obs.push(r.accepted[0]);
    }
    for i in 0..3 {
        let t = d.acquire(&s, "reader", true, i);
        assert_eq!(t["kind"], "EXTEND");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "reader", &[], i)["status"], "COMMITTED");
    }
    let t = d.acquire(&s, "sum", true, 4);
    assert_eq!(t["kind"], "SUMMARIZE");
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "sum", &[claim("only_a", &obs[0].short(), "Topic alpha holds."), done(&t, &["only_a"])], 5);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "missing report must not close the question: {r}");
    let kept = r["accepted_locals"]["only_a"].as_str().unwrap().to_string();
    assert!(r["accepted_locals"].get("done").is_none(), "done must wait: {r}");
    assert_eq!(r["refused"][0]["error"]["expected_by_kernel"]["missing_reports"], json!(["b"]), "only the issued window, not outside: {r}");
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut d = Dispatcher::new(DispatchConfig::default(), questions());
    d.recover(&s);
    let delta = d.acquire(&s, "repair", true, 6);
    assert_eq!(delta["kind"], "SUMMARIZE", "no COMPLETE on an incomplete window: {delta}");
    assert_eq!(delta["retained_answer_ids"], json!([kept]), "accepted prefix survives reopen: {delta}");
    let r =
        d.submit(&mut s, delta["task_id"].as_str().unwrap(), "repair", &[claim("only_b", &obs[1].short(), "Topic beta holds."), done(&delta, &["only_b"])], 7);
    assert_eq!(r["status"], "COMMITTED", "the missing report is enough: {r}");
    let out = d.accepted_outcomes(&s);
    assert_eq!(out["RQ1"]["answer_ids"].as_array().unwrap().len(), 2);
    assert!(out["RQ1"]["answer_ids"].as_array().unwrap().contains(&json!(kept)));
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    let mut d = Dispatcher::new(DispatchConfig::default(), questions());
    d.recover(&s);
    assert_eq!(d.acquire(&s, "next", true, 8)["status"], "COMPLETE");
}

#[test]
fn dangling_quote_is_suggested_and_only_explicit_resubmission_stores_more_bytes() {
    let text = "Topic changed naturally from\nold to new.\n";
    let (_wal, mut s, mut d) = state(vec![("a".into(), text.as_bytes().to_vec())]);
    let t = d.acquire(&s, "reader", true, 0);
    let line = json!({"kind":"observe","local_id":"o","doc_id":"a","exact_quote":"Topic changed naturally from","terms":["topic"]});
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "reader", &[line], 1);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "no semantic auto-extension: {r}");
    assert!(r["accepted"].as_array().unwrap().is_empty());
    assert!(!r["problems"][0]["suggested_span"].is_null(), "exact scoped span is returned: {r}");
    assert!(s.records_since(0).is_empty());
    let exact = text.trim_end();
    let r = d.submit(
        &mut s,
        t["task_id"].as_str().unwrap(),
        "reader",
        &[json!({"kind":"observe","local_id":"o","doc_id":"a","exact_quote":exact,"terms":["topic"]})],
        2,
    );
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(s.records_since(0)[0].quote.as_deref(), Some(exact));
}

#[test]
fn negative_list_heading_uses_negation_across_blank_lines_without_leaking_siblings() {
    use sbgk_core::audit::s0::negation_before;
    for heading in
        ["This gate does not authorize:", "It did not establish:", "The current Matrix does **not** establish:", "The implementation does not change:"]
    {
        let doc = format!("{heading}\n\n- PUBLIC_STAGE2;\n\n- RELEASE;\n");
        assert!(negation_before(&doc, doc.find("PUBLIC_STAGE2").unwrap(), "PUBLIC_STAGE2").is_some(), "{doc}");
        assert!(negation_before(&doc, doc.find("RELEASE").unwrap(), "RELEASE").is_some(), "{doc}");
    }
    for doc in [
        "This gate establishes:\n\n- PUBLIC_STAGE2;\n",
        "- No host is added;\n- PUBLIC_STAGE2;\n",
        "This gate does not authorize:\n\n- alpha;\n\nPositive evidence:\n\n- PUBLIC_STAGE2;\n",
    ] {
        assert!(negation_before(doc, doc.find("PUBLIC_STAGE2").unwrap(), "PUBLIC_STAGE2").is_none(), "{doc}");
    }
}
