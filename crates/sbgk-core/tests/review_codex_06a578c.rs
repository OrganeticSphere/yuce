//! Regressions for the owner's three fixes: scoped S0 feedback, whole identifier matches and truthful repair modes.
use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{unstored_problems, DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::s0;
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

fn fresh(doc: &str, tag: &str) -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_codex06_{tag}_{}_{nonce}.wal", std::process::id())));
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), doc.as_bytes().to_vec())], "codex06", sha256(b"fixture")).unwrap();
    (wal, s)
}

#[test]
fn identifier_lookalikes_do_not_count_as_quoted_identifiers() {
    for (claim, quote, want) in [
        ("PR #111 passed", "PR #1110 passed", "#111"),
        ("E003 was raised", "E0031 was raised", "E003"),
        ("version 1.9 passed", "version 1.99 passed", "1.9"),
        ("a.rs changed", "data.rs changed", "a.rs"),
        ("head 1234abc passed", "head a1234abc9 passed", "1234abc"),
        ("MergedGateHold holds", "MergedGateHoldExtra holds", "MergedGateHold"),
        ("SOURCE_ACTIVE holds", "SOURCE_ACTIVE_EXTRA holds", "SOURCE_ACTIVE"),
    ] {
        assert_eq!(s0::missing_identifiers(claim, &[quote]), [want], "{claim} / {quote}");
    }
    for (claim, quote) in [
        ("PR #111 passed", "PR #111 passed"),
        ("head 1234abc passed", "head 1234abcdef passed"),
        ("version 1.9 passed", "version v1.9 passed"),
        ("a.rs changed", "src/a.rs changed"),
    ] {
        assert!(s0::missing_identifiers(claim, &[quote]).is_empty(), "{claim} / {quote}");
    }
}

fn problems(doc: &str, start: usize, quote: &str) -> Vec<Value> {
    let (_wal, s) = fresh(doc, "scope");
    let scope = Scope { docs: vec!["d".into()], ranges: vec![("d".into(), start, doc.len())], ..Default::default() };
    let line = json!({"kind":"observe","local_id":"o1","doc_id":"d","exact_quote":quote,"terms":[]});
    unstored_problems(&s, &scope, &Default::default(), &[], std::slice::from_ref(&line), &[(0, line.clone())])
}

#[test]
fn a_negation_outside_the_issued_range_neither_refuses_nor_discloses_it() {
    let doc = "No PRIVATE_UNISSUED_TOKEN; the gate passed its check.";
    let start = doc.find("the gate").unwrap();
    assert!(problems(doc, start, &doc[start..]).is_empty());
}

#[test]
fn an_in_scope_negation_still_gets_an_in_scope_exact_hint() {
    let doc = "No PRIVATE_UNISSUED_TOKEN; It does not authorize implementation beyond the selected scope.";
    let start = doc.find("It does").unwrap();
    let p = problems(doc, start, "authorize implementation beyond");
    assert_eq!(p.len(), 1);
    assert_eq!(p[0]["negation_before"], "It does not");
    assert_eq!(p[0]["exact_bytes_in_section"], &doc[start..]);
    assert!(!serde_json::to_string(&p).unwrap().contains("PRIVATE_UNISSUED_TOKEN"));
}

fn summary() -> (Wal, AuditState, Dispatcher, String, String, String) {
    let (wal, mut s) = fresh("# Report\nThe gate remains open.\n", "summary");
    let q = ResearchQuestion { id: "RQ1".into(), text: "What stays open?".into(), about: vec!["gate".into()], ..Default::default() };
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![q]);
    let t = d.acquire(&s, "w1", true, 1);
    assert_eq!(t["kind"], "EXTEND");
    let p = t["local_id_prefix"].as_str().unwrap();
    let r = d.submit(
        &mut s,
        t["task_id"].as_str().unwrap(),
        "w1",
        &[
            json!({"kind":"observe","local_id":format!("{p}o1"),"doc_id":"d","exact_quote":"The gate remains open.","terms":["gate"]}),
            json!({"kind":"claim","local_id":format!("{p}c1"),"text":"The gate remains open.","subject":"gate","stance":"open","based_on":[format!("{p}o1")]}),
        ],
        1,
    );
    assert_eq!(r["status"], "COMMITTED");
    let observe = r["accepted_locals"][format!("{p}o1")].as_str().unwrap().to_string();
    let mut b = Builder::new(BuilderConfig::default());
    b.recover(&s);
    while let Some(c) = b.next_card(&s) {
        assert_eq!(b.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    let t = d.acquire(&s, "w2", b.caught_up(&s), 2);
    assert_eq!(t["kind"], "SUMMARIZE");
    (wal, s, d, t["task_id"].as_str().unwrap().into(), t["local_id_prefix"].as_str().unwrap().into(), observe)
}

fn answer(task: &str, p: &str, observe: &str) -> Vec<Value> {
    vec![
        json!({"kind":"claim","local_id":format!("{p}c1"),"text":"The gate remains open.","subject":"gate","stance":"open","based_on":[observe]}),
        json!({"kind":"done","local_id":format!("{p}d1"),"rq_id":"RQ1","directive_id":task,"outcome":"answered","answer_ids":[format!("{p}c1")]}),
    ]
}

#[test]
fn a_preflight_error_reports_whole_answer_and_can_retry_all_unstored_lines() {
    let (_wal, mut s, mut d, task, p, observe) = summary();
    let mut lines = answer(&task, &p, &observe);
    lines[1]["rq_id"] = json!("WRONG_RQ");
    let before = s.records_since(0).len();
    let r = d.submit(&mut s, &task, "w2", &lines, 2);
    assert_eq!(r["failed_index"], 1);
    assert_eq!(r["repair_scope"], "whole_answer");
    assert_eq!(s.records_since(0).len(), before);
    lines[1]["rq_id"] = json!("RQ1");
    let r = d.submit(&mut s, &task, "w2", &lines, 2);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(r["accepted"].as_array().unwrap().len(), 2);
}

#[test]
fn a_bad_done_reference_preserves_the_already_stored_claim_prefix() {
    let (_wal, mut s, mut d, task, p, observe) = summary();
    let mut lines = answer(&task, &p, &observe);
    lines[1]["answer_ids"] = json!(["missing"]);
    let before = s.records_since(0).len();
    let r = d.submit(&mut s, &task, "w2", &lines, 2);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    // item by item since the consilium of 10A-17: the stored claim stays, the refused done line is the item to repair
    assert_eq!(r["repair_scope"], "rejected_items_only", "{r}");
    assert_eq!(r["accepted"].as_array().unwrap().len(), 1, "{r}");
    assert_eq!(s.records_since(0).len(), before + 1);
}

#[test]
fn a_store_refusal_still_reports_the_actual_accepted_prefix() {
    let (_wal, mut s, mut d, task, p, observe) = summary();
    let mut lines = answer(&task, &p, &observe);
    let mut bad = lines[0].clone();
    bad["local_id"] = json!(format!("{p}c2"));
    bad["unknown_field"] = json!(true);
    lines.insert(1, bad);
    let r = d.submit(&mut s, &task, "w2", &lines, 2);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["repair_scope"], "rejected_items_only", "{r}");
    assert_eq!(r["not_stored"], json!([format!("{p}c2"), format!("{p}d1")]), "the done line waits for the refused one: {r}");
    assert_eq!(r["accepted"].as_array().unwrap().len(), 1, "{r}");
}

#[test]
fn a_verdict_error_after_storage_does_not_get_a_whole_answer_marker() {
    let (_wal, mut s, mut d, _task, _p, observe) = summary();
    let from = s.records_since(0).into_iter().find(|r| r.kind == sbgk_core::audit::RecordKind::Claim).unwrap().id;
    let r = s.submit_records(
        "w3",
        "T90-aaaaaaaaaaaaaaaa",
        &Scope { docs: vec!["d".into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"o1","doc_id":"d","exact_quote":"The gate remains open.","terms":["gate"]}),
            json!({"kind":"claim","local_id":"c1","text":"The gate stays open.","subject":"gate","stance":"open","based_on":["o1"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let to = r.accepted[1];
    s.submit_operations_id(
        "link-fixture",
        "builder",
        &[json!({"kind":"add_link","from":sbgk_core::hash::to_hex(&from.0),
        "to":sbgk_core::hash::to_hex(&to.0),"rel":"supports","basis":[sbgk_core::hash::to_hex(&r.accepted[0].0)]})],
        None,
    )
    .unwrap();
    let mut b = Builder::new(BuilderConfig::default());
    b.recover(&s);
    while let Some(c) = b.next_card(&s) {
        assert_eq!(b.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    let t = d.acquire(&s, "verifier", b.caught_up(&s), 3);
    assert_eq!(t["kind"], "VERIFY_LINK", "{t}");
    let p = t["local_id_prefix"].as_str().unwrap();
    let link = t["key"].as_str().unwrap().strip_prefix("verify:").unwrap();
    let lines = [
        json!({"kind":"claim","local_id":format!("{p}c1"),"text":"The gate remains open.","subject":"gate","stance":"reported","based_on":[observe]}),
        json!({"kind":"verdict","link":link,"verdict":"confirm","based_on":["missing"]}),
    ];
    let before = s.records_since(0).len();
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "verifier", &lines, 3);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["error"]["code"], "UNKNOWN_LOCAL_ID", "{r}");
    assert_eq!(r["repair_scope"], "accepted_prefix", "{r}");
    assert_eq!(r["accepted"].as_array().unwrap().len(), 1, "{r}");
    assert_eq!(s.records_since(0).len(), before + 1);
}
