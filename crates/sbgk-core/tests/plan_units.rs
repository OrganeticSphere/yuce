//! Reading units and withdrawn text: a plan of task sections, each
//! with a directive REV_A and a fallback REV_B; a cancelled task is its whole section withdrawn, a changed task its REV_A clause
//! withdrawn. Deterministic stand-ins replace the agents; the journal is the kernel's own.

use sbgk_core::audit::directives::{coverage, DispatchConfig, Dispatcher};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, ConceptId, ConceptView, LinkId, LinkStatus, LinkView, RecordId, RecordView, Scope, SubmitReport};
use sbgk_core::error::{Code, KernelError};
use sbgk_core::hash::{sha256, Hash};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const DOC: &str = "plan.md";
const SECTION_BYTES: usize = 300;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn wal(name: &str) -> Wal {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Wal(std::env::temp_dir().join(format!("plan_units_{name}_{}_{nonce}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
}

fn rev_a(k: usize) -> String {
    format!("Directive REV_A: Task #{k} assigns target cell_{k} operation OP_SET_A with value {k}.5.")
}

fn rev_b(k: usize) -> String {
    format!("Fallback REV_B: If REV_A is withdrawn, Task #{k} assigns target cell_{k} operation OP_SET_B with value {k}0.5.")
}

/// The text of task `k`'s section, without the blank line that ends it: what a cancel withdraws.
fn task(k: usize) -> String {
    format!("## Task #{k}\n\n{}\n\n{}", rev_a(k), rev_b(k))
}

fn plan(n: usize) -> String {
    (1..=n).map(|k| format!("{}\n\n", task(k))).collect()
}

/// A run over a plan of `n` tasks whose journal pins its section size, as `audit-serve` pins it (the coverage table reads it).
fn run(name: &str, n: usize) -> (Wal, AuditState) {
    run_pinning(name, n, json!({}))
}

/// `run`, its pinned settings with `more` (a bound of agent attempts, the plan setting).
fn run_pinning(name: &str, n: usize, more: Value) -> (Wal, AuditState) {
    run_doc(name, &plan(n), more)
}

/// `run_pinning` over a plan of the given text.
fn run_doc(name: &str, text: &str, more: Value) -> (Wal, AuditState) {
    let path = wal(name);
    let mut s = AuditState::create(&path.0, &AuditOntology::base(), &[(DOC.to_string(), text.as_bytes().to_vec())], "plan-units", sha256(b"m")).unwrap();
    let mut context = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": SECTION_BYTES, "section_rule": 2});
    for (k, v) in more.as_object().unwrap() {
        context[k] = v.clone();
    }
    let pinned = json!({"key": "audit:mcp:coverage", "from": 0, "to": 0, "context": context});
    let r = s.submit_operations_id("audit-mcp-coverage-config", "kernel", &[], Some(pinned)).unwrap();
    assert!(r["error"].is_null(), "{r}");
    (path, s)
}

fn config() -> DispatchConfig {
    DispatchConfig { section_bytes: SECTION_BYTES, relation_lines: false, ..Default::default() }
}

/// The plan profile (`--unit-is-task`).
fn plan_config() -> DispatchConfig {
    DispatchConfig { unit_is_task: true, ..config() }
}

/// The task a directive hands out, by the heading of its section.
fn task_of(t: &Value) -> usize {
    let prompt = t["prompt"].as_str().unwrap_or_default();
    let at = prompt.find("## Task #").unwrap_or_else(|| panic!("no task section in {t}")) + "## Task #".len();
    prompt[at..].chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap()
}

/// The stand-in executor's report: the clause quoted and stated.
fn report(t: &Value, clause: &str) -> Vec<Value> {
    let p = t["local_id_prefix"].as_str().unwrap();
    vec![
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": DOC, "exact_quote": clause, "terms": ["task"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": clause, "subject": "task", "stance": "reported", "based_on": [format!("{p}o1")]}),
    ]
}

fn id(t: &Value) -> &str {
    t["task_id"].as_str().unwrap_or_else(|| panic!("no task: {t}"))
}

/// What the coverage table says each unit of task `k`'s section came to.
fn unit_statuses(s: &AuditState, k: usize) -> Vec<String> {
    let text = plan(9);
    let (a, b) = {
        let a = text.find(&task(k)).unwrap();
        (a, a + task(k).len())
    };
    coverage(s)
        .units
        .iter()
        .filter(|r| r[1].as_u64().unwrap() as usize >= a && r[2].as_u64().unwrap() as usize <= b + 2)
        .map(|r| r[5].as_str().unwrap().to_string())
        .collect()
}

// ---- a unit whose every byte is withdrawn is closed, never issued

#[test]
fn a_cancelled_task_is_closed_without_being_issued_and_the_coverage_table_shows_it_withdrawn() {
    let (_w, mut s) = run("cancel", 3);
    let mut d = Dispatcher::new(config(), vec![]);
    s.withdraw_text("owner", DOC, &task(2)).unwrap();
    let mut done = Vec::new();
    loop {
        let t = d.acquire(&s, "w1", true, 0);
        if t["kind"] != "EXTEND" {
            assert_eq!(t["status"], "COMPLETE", "{t}");
            break;
        }
        let k = task_of(&t);
        assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &rev_a(k)), 0)["status"], "COMMITTED");
        done.push(k);
    }
    assert_eq!(done, [1, 3], "the cancelled task was never issued");
    assert_eq!(d.stats.withdrawn_units, 1);
    assert!(d.persist_unresolved(&mut s).is_empty());
    let closed = s.checkpoint(&format!("task:doc:{DOC}#1")).expect("the closure is durable");
    assert_eq!(closed["context"]["reason"], "withdrawn_whole");
    assert!(unit_statuses(&s, 2).iter().all(|st| st == "withdrawn"), "{:?}", unit_statuses(&s, 2));
    assert!(unit_statuses(&s, 1).contains(&"quoted".to_string()));
    // a restarted dispatcher reads the closure and issues nothing
    let mut again = Dispatcher::new(config(), vec![]);
    again.recover(&s);
    assert_eq!(again.acquire(&s, "w2", true, 1)["status"], "COMPLETE");
    assert_eq!(again.stats.withdrawn_units, 0, "closed once, by its durable record");
}

#[test]
fn a_task_whose_clause_alone_is_withdrawn_is_still_issued() {
    let (_w, mut s) = run("change", 1);
    let mut d = Dispatcher::new(config(), vec![]);
    s.withdraw_text("owner", DOC, &rev_a(1)).unwrap();
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!((t["kind"].as_str(), task_of(&t)), (Some("EXTEND"), 1), "{t}");
    assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &rev_b(1)), 0)["status"], "COMMITTED");
    assert_eq!(d.stats.withdrawn_units, 0);
}

#[test]
fn a_task_cancelled_while_leased_is_closed_once_its_lease_is_given_back() {
    let (_w, mut s) = run("leased", 2);
    let mut d = Dispatcher::new(config(), vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!(task_of(&t), 1);
    s.withdraw_text("owner", DOC, &task(1)).unwrap();
    // the executor's report rests on withdrawn text: refused
    assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &rev_a(1)), 0)["status"], "REPAIR_REQUIRED");
    // while the lease is out, the unit is not closed under it
    let u = d.acquire(&s, "w2", true, 0);
    assert_eq!(task_of(&u), 2);
    assert_eq!(d.stats.withdrawn_units, 0);
    assert_eq!(d.submit(&mut s, id(&u), "w2", &report(&u, &rev_a(2)), 0)["status"], "COMMITTED");
    d.release(id(&t), "w1");
    assert_eq!(d.acquire(&s, "w1", true, 0)["status"], "COMPLETE", "given back, the cancelled task is closed, not issued again");
    assert_eq!(d.stats.withdrawn_units, 1);
}

// ---- an issued unit shows its withdrawn bytes as marks, not as text

#[test]
fn a_changed_task_is_issued_with_its_withdrawn_clause_marked_and_its_fallback_quotable() {
    let (_w, mut s) = run("marks", 2);
    let mut d = Dispatcher::new(config(), vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    let p = t["prompt"].as_str().unwrap();
    assert_eq!(task_of(&t), 1);
    assert!(p.contains(&task(1)) && !p.contains("[withdrawn") && !p.contains("WITHDRAWN TEXT"), "nothing withdrawn, nothing marked: {p}");
    assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &rev_a(1)), 0)["status"], "COMMITTED");
    s.withdraw_text("owner", DOC, &rev_a(2)).unwrap();
    let t = d.acquire(&s, "w1", true, 0);
    let p = t["prompt"].as_str().unwrap();
    assert_eq!(task_of(&t), 2);
    assert!(!p.contains(&rev_a(2)), "the withdrawn clause is not shown: {p}");
    assert!(p.contains(&format!("## Task #2\n\n[withdrawn: {} bytes]\n\n{}", rev_a(2).len(), rev_b(2))), "{p}");
    assert!(p.contains("WITHDRAWN TEXT"), "{p}");
    let a = plan(2).find(&task(2)).unwrap();
    assert!(p.contains(&format!("SECTION doc_id=\"{DOC}\" (bytes {a}..")), "the section keeps its bytes: {p}");
    assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &rev_b(2)), 0)["status"], "COMMITTED");
}

// ---- with the plan setting, an answer that leaves its task with nothing accepted does not close it

#[test]
fn without_the_plan_setting_an_empty_answer_closes_its_unit_as_before() {
    let (_w, mut s) = run("reading", 1);
    let mut d = Dispatcher::new(config(), vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!(d.submit(&mut s, id(&t), "w1", &[], 0)["status"], "COMMITTED", "in a reading profile, nothing to record is an answer");
    assert_eq!(d.acquire(&s, "w2", true, 0)["status"], "COMPLETE");
    assert_eq!(d.stats.empty_answers, 0);
}

#[test]
fn with_the_plan_setting_an_empty_answer_gives_the_task_back_and_another_executor_does_it() {
    let (_w, mut s) = run("empty", 1);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    let r = d.submit(&mut s, id(&t), "w1", &[], 0);
    assert_eq!((r["status"].as_str(), r["code"].as_str(), r["unresolved"].as_bool()), (Some("RELEASED"), Some("EMPTY_ANSWER"), Some(false)), "{r}");
    assert_eq!(d.stats.empty_answers, 1);
    assert!(s.checkpoint(&format!("task:doc:{DOC}#0")).is_none(), "the task is not closed");
    assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &rev_a(1)), 0)["status"], "STALE_TASK", "the lease went back with the answer");
    let u = d.acquire(&s, "w2", true, 0);
    assert_eq!(task_of(&u), 1, "the task is issued again");
    assert_eq!(d.submit(&mut s, id(&u), "w2", &report(&u, &rev_a(1)), 0)["status"], "COMMITTED");
    assert_eq!(d.acquire(&s, "w3", true, 0)["status"], "COMPLETE");
}

#[test]
fn with_the_plan_setting_a_task_answered_empty_until_its_leases_run_out_is_unresolved() {
    let (_w, mut s) = run("unresolved", 1);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    let mut last = Value::Null;
    for agent in ["w1", "w2", "w3"] {
        let t = d.acquire(&s, agent, true, 0);
        assert_eq!(task_of(&t), 1);
        last = d.submit(&mut s, id(&t), agent, &[], 0);
    }
    assert_eq!((last["code"].as_str(), last["unresolved"].as_bool()), (Some("EMPTY_ANSWER"), Some(true)), "{last}");
    let given_up = s.checkpoint(&format!("task:doc:{DOC}#0")).expect("durable");
    assert_eq!(given_up["context"]["unresolved"], true);
    assert_eq!(d.acquire(&s, "w4", true, 0)["status"], "COMPLETE", "an unresolved task is no open work");
}

#[test]
fn with_the_plan_setting_and_a_bound_of_attempts_each_empty_answer_is_a_durable_failed_attempt() {
    let (_w, mut s) = run_pinning("attempts", 1, json!({"agent_attempts": 2, "unit_is_task": true}));
    let mut d = Dispatcher::new(DispatchConfig { agent_attempts: Some(2), ..plan_config() }, vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    let r = d.submit(&mut s, id(&t), "w1", &[], 0);
    assert_eq!((r["status"].as_str(), r["failures"].as_u64(), r["unresolved"].as_bool()), (Some("RELEASED"), Some(1), Some(false)), "{r}");
    let t = d.acquire(&s, "w2", true, 0);
    let r = d.submit(&mut s, id(&t), "w2", &[], 0);
    assert_eq!((r["failures"].as_u64(), r["unresolved"].as_bool()), (Some(2), Some(true)), "{r}");
    let record = sbgk_core::audit::agent_failures::entry(&s, &format!("doc:{DOC}#0"));
    assert!(record["attempts"].as_array().unwrap().iter().all(|a| a["reason"] == "EMPTY_ANSWER"), "{record}");
    // a restart reads the attempts back: the task stays given up
    let mut again = Dispatcher::new(DispatchConfig { agent_attempts: Some(2), ..plan_config() }, vec![]);
    again.recover(&s);
    assert_eq!(again.acquire(&s, "w3", true, 0)["status"], "COMPLETE");
}

#[test]
fn with_the_plan_setting_a_task_with_a_line_accepted_earlier_closes_on_an_empty_answer() {
    let (_w, mut s) = run("prefix", 1);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    let p = t["local_id_prefix"].as_str().unwrap();
    // the quote is stored, the claim naming values its quote does not hold is refused
    let lines = [
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": DOC, "exact_quote": rev_a(1), "terms": ["task"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "Task #1 writes 99.9 with receipt code E999.", "subject": "task",
               "stance": "reported", "based_on": [format!("{p}o1")]}),
    ];
    let r = d.submit(&mut s, id(&t), "w1", &lines, 0);
    assert_eq!((r["status"].as_str(), r["accepted"].as_array().map(Vec::len)), (Some("REPAIR_REQUIRED"), Some(1)), "{r}");
    assert_eq!(d.submit(&mut s, id(&t), "w1", &[], 0)["status"], "COMMITTED", "something of it was accepted");
    assert_eq!(d.stats.empty_answers, 0);
}

#[test]
fn with_the_plan_setting_an_empty_answer_on_a_task_cancelled_under_its_lease_closes_it_as_withdrawn_whole() {
    let (_w, mut s) = run("cancel-leased", 1);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    s.withdraw_text("owner", DOC, &task(1)).unwrap();
    assert_eq!(d.submit(&mut s, id(&t), "w1", &[], 0)["status"], "COMMITTED", "nothing is left to do");
    assert_eq!(s.checkpoint(&format!("task:doc:{DOC}#0")).unwrap()["context"]["reason"], "withdrawn_whole");
    assert_eq!(d.stats.empty_answers, 0);
}

// ---- with the plan setting, a task changed after it was done is done again

/// Does every task the dispatcher hands out, each with the first clause its card shows, until it has none.
fn do_all(d: &mut Dispatcher, s: &mut AuditState) -> Vec<(usize, String)> {
    let mut done = Vec::new();
    loop {
        let t = d.acquire(s, "w1", true, 0);
        if t["kind"] != "EXTEND" {
            assert_eq!(t["status"], "COMPLETE", "{t}");
            return done;
        }
        let k = task_of(&t);
        let shown = t["prompt"].as_str().unwrap();
        let clause = [rev_a(k), rev_b(k)].into_iter().find(|c| shown.contains(c.as_str())).expect("a clause to carry out");
        assert_eq!(d.submit(s, id(&t), "w1", &report(&t, &clause), 0)["status"], "COMMITTED");
        done.push((k, clause));
    }
}

#[test]
fn with_the_plan_setting_a_task_changed_after_it_was_done_is_issued_again_and_done_by_its_fallback() {
    let (_w, mut s) = run("reopen", 2);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    assert_eq!(do_all(&mut d, &mut s), [(1, rev_a(1)), (2, rev_a(2))]);
    s.withdraw_text("owner", DOC, &rev_a(1)).unwrap();
    assert_eq!(d.completion(&s, true)["complete"], false, "before any call opens it, the changed task is open work");
    assert_eq!(do_all(&mut d, &mut s), [(1, rev_b(1))], "done again, by REV_B");
    assert_eq!(d.stats.reopened_units, 1);
    let closed = s.checkpoint(&format!("task:doc:{DOC}#0")).unwrap();
    assert_eq!(closed["context"]["reopened"], 1, "{closed}");
    assert_eq!(closed["context"]["unit_records"].as_array().map(Vec::len), Some(2), "the quote of REV_B and its claim: {closed}");
    assert_eq!(d.completion(&s, true)["complete"], true);
}

#[test]
fn without_the_plan_setting_a_task_changed_after_it_was_done_stays_closed_as_before() {
    let (_w, mut s) = run("no-reopen", 2);
    let mut d = Dispatcher::new(config(), vec![]);
    assert_eq!(do_all(&mut d, &mut s).len(), 2);
    s.withdraw_text("owner", DOC, &rev_a(1)).unwrap();
    assert!(do_all(&mut d, &mut s).is_empty(), "a reading profile does not read a section again after a withdrawal");
    assert_eq!(d.stats.reopened_units, 0);
    assert!(s.checkpoint(&format!("task:doc:{DOC}#0")).unwrap()["context"].get("unit_records").is_none(), "nor writes what it would need");
}

#[test]
fn with_the_plan_setting_a_task_cancelled_after_it_was_done_is_not_issued_again() {
    let (_w, mut s) = run("cancel-done", 2);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    assert_eq!(do_all(&mut d, &mut s).len(), 2);
    s.withdraw_text("owner", DOC, &task(2)).unwrap();
    assert!(do_all(&mut d, &mut s).is_empty());
    assert_eq!((d.stats.reopened_units, d.stats.withdrawn_units), (0, 0), "closed already: nothing to close or do");
}

#[test]
fn with_the_plan_setting_a_restarted_dispatcher_opens_a_changed_task_as_the_live_one_does() {
    let (_w, mut s) = run("reopen-recover", 2);
    let mut d = Dispatcher::new(plan_config(), vec![]);
    do_all(&mut d, &mut s);
    s.withdraw_text("owner", DOC, &rev_a(2)).unwrap();
    let mut again = Dispatcher::new(plan_config(), vec![]);
    again.recover(&s);
    assert_eq!(again.stats.reopened_units, 1, "opened on recovery, from the records its checkpoint names");
    assert_eq!(do_all(&mut again, &mut s), [(2, rev_b(2))]);
    // and once more after it was done again: its checkpoint now names the new records, and nothing is open
    let mut third = Dispatcher::new(plan_config(), vec![]);
    third.recover(&s);
    assert!(do_all(&mut third, &mut s).is_empty());
    assert_eq!(third.stats.reopened_units, 0);
}

#[test]
fn with_the_plan_setting_a_task_is_opened_again_at_most_as_often_as_its_attempts_allow() {
    // a task of five lines, each withdrawn once a report rests on it: it could be reopened four times, the bound is three
    let lines: Vec<String> = ["one alpha", "two beta", "three gamma", "four delta", "five epsilon"].iter().map(|w| format!("Line {w} is the rule.")).collect();
    let text = format!(
        "## Task #1

{}
",
        lines.join(
            "

"
        )
    );
    let (_w, mut s) = run_doc("bound", &text, json!({}));
    let mut d = Dispatcher::new(plan_config(), vec![]);
    let mut rounds = 0;
    loop {
        let t = d.acquire(&s, "w1", true, 0);
        if t["kind"] != "EXTEND" {
            assert_eq!(t["status"], "COMPLETE", "{t}");
            break;
        }
        let shown = t["prompt"].as_str().unwrap().to_string();
        let line = lines.iter().find(|l| shown.contains(l.as_str())).unwrap().clone();
        assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, &line), 0)["status"], "COMMITTED");
        s.withdraw_text("owner", DOC, &line).unwrap();
        rounds += 1;
    }
    assert_eq!((rounds, d.stats.reopened_units), (4, 3), "done once and opened again three times");
    // the fourth fall leaves "Line five" standing: past the bound the task is given up as unresolved, not closed in silence
    // (Codex's PR55-R1)
    assert!(d.completion(&s, true)["unresolved"].as_array().unwrap().contains(&json!(format!("doc:{DOC}#0"))));
    assert!(d.persist_unresolved(&mut s).is_empty());
    assert_eq!(s.checkpoint(&format!("task:doc:{DOC}#0")).unwrap()["context"]["reason"], "REOPEN_LIMIT");
}

// ---- Codex review of PR 55 at 4c310b11: his two negative cases (PR55-R1, PR55-R2), kept as regressions as he wrote them
// (2026-11-17_codex_PR55_review_cases.rs, sha256 e7ffecbb...)

#[test]
fn review_exhausted_reopens_must_report_unresolved_before_and_after_restart() {
    let lines = ["Line one alpha is the rule.", "Line two beta is the rule.", "Line three gamma is the rule."];
    let text = format!("## Task #1\n\n{}\n", lines.join("\n\n"));
    let (w, mut s) = run_doc("review-reopen-limit", &text, json!({"agent_attempts": 1, "unit_is_task": true}));
    let cfg = DispatchConfig { agent_attempts: Some(1), ..plan_config() };
    let mut d = Dispatcher::new(cfg.clone(), vec![]);
    for line in lines.iter().take(2) {
        let t = d.acquire(&s, "w1", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(d.submit(&mut s, id(&t), "w1", &report(&t, line), 0)["status"], "COMMITTED");
        s.withdraw_text("owner", DOC, line).unwrap();
    }
    let next = d.acquire(&s, "w2", true, 0);
    let completion = d.completion(&s, true);
    let checkpoint = s.checkpoint(&format!("task:doc:{DOC}#0")).unwrap();
    drop(s);
    let reopened_wal = AuditState::open(&w.0).unwrap();
    let mut again = Dispatcher::new(cfg, vec![]);
    again.recover(&reopened_wal);
    let restarted = again.completion(&reopened_wal, true);
    eprintln!("REOPEN_LIMIT: next={next}; completion={completion}; recovered={restarted}; checkpoint={checkpoint}");
    let key = json!(format!("doc:{DOC}#0"));
    assert!(completion["unresolved"].as_array().unwrap().contains(&key), "remaining live work silently closed: {completion}");
    assert!(restarted["unresolved"].as_array().unwrap().contains(&key), "unresolved result must survive recovery: {restarted}");
}

#[test]
fn review_withdrawn_heading_must_not_return_as_context_of_later_section() {
    let heading = "## OP_SET_A paint cell_1 RED";
    let text = format!("{heading}\n\n{}\n\n{}\n", "A surviving paragraph with ordinary facts about the current task.", "Fallback OP_SET_B paint cell_1 BLUE.");
    let (_w, mut s) = run_doc("review-heading-mask", &text, json!({"section_bytes": 64}));
    s.withdraw_text("owner", DOC, heading).unwrap();
    let mut d = Dispatcher::new(DispatchConfig { section_bytes: 64, ..config() }, vec![]);
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    let prompt = t["prompt"].as_str().unwrap();
    eprintln!("WITHDRAWN_CONTEXT: {prompt}");
    assert!(!prompt.contains(heading), "withdrawn instruction returned as unmarked context: {prompt}");
}

// ---- PR55-R1: a unit given up past its bound of openings is unresolved durably, also when the first write of that fails

/// Every call reaches the kernel's journal, but the first write of the unresolved mark of a unit that ran out of openings is
/// refused once, as a store may refuse a write (the fault of the review of 4381fe7, D06, at the same boundary).
struct OnceRefusing {
    state: AuditState,
    refuse: bool,
    refused: usize,
}

impl AuditStore for OnceRefusing {
    fn docs(&self) -> Vec<String> {
        AuditStore::docs(&self.state)
    }
    fn doc_text(&self, id: &str) -> Option<String> {
        AuditStore::doc_text(&self.state, id)
    }
    fn quoted_spans(&self, doc: &str) -> Vec<(usize, usize)> {
        AuditStore::quoted_spans(&self.state, doc)
    }
    fn quoted_records(&self, doc: &str) -> Vec<(RecordId, usize, usize)> {
        AuditStore::quoted_records(&self.state, doc)
    }
    fn closed_spans(&self, doc: &str) -> Vec<(usize, usize)> {
        AuditStore::closed_spans(&self.state, doc)
    }
    fn submit_records(&mut self, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        AuditStore::submit_records(&mut self.state, agent, directive, scope, lines)
    }
    fn submit_records_id(&mut self, id: &str, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        AuditStore::submit_records_id(&mut self.state, id, agent, directive, scope, lines)
    }
    fn submit_scoped_records_id(&mut self, id: &str, agent: &str, directive: &str, scope: &Scope, issued: &[RecordId], lines: &[Value]) -> SubmitReport {
        AuditStore::submit_scoped_records_id(&mut self.state, id, agent, directive, scope, issued, lines)
    }
    fn records_since(&self, cursor: u64) -> Vec<RecordView> {
        AuditStore::records_since(&self.state, cursor)
    }
    fn record(&self, id: &RecordId) -> Option<RecordView> {
        AuditStore::record(&self.state, id)
    }
    fn is_grounded(&self, id: &RecordId) -> bool {
        AuditStore::is_grounded(&self.state, id)
    }
    fn is_answer_support(&self, id: &RecordId) -> bool {
        AuditStore::is_answer_support(&self.state, id)
    }
    fn head(&self) -> u64 {
        AuditStore::head(&self.state)
    }
    fn ontology_version(&self) -> (u64, Hash) {
        AuditStore::ontology_version(&self.state)
    }
    fn concept_types(&self) -> Vec<String> {
        AuditStore::concept_types(&self.state)
    }
    fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView> {
        AuditStore::candidates(&self.state, term, limit)
    }
    fn concept(&self, id: &ConceptId) -> Option<ConceptView> {
        AuditStore::concept(&self.state, id)
    }
    fn propose_concept(&mut self, by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> Result<ConceptView, KernelError> {
        AuditStore::propose_concept(&mut self.state, by, ty, name, aliases, basis)
    }
    fn map_term(&mut self, by: &str, record: &RecordId, term: &str, concept: &ConceptId) -> Result<(), KernelError> {
        AuditStore::map_term(&mut self.state, by, record, term, concept)
    }
    fn concepts_of(&self, record: &RecordId) -> Vec<ConceptId> {
        AuditStore::concepts_of(&self.state, record)
    }
    fn records_of(&self, concept: &ConceptId) -> Vec<RecordId> {
        AuditStore::records_of(&self.state, concept)
    }
    fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> Result<LinkView, KernelError> {
        AuditStore::add_link(&mut self.state, by, from, rel, to, basis)
    }
    fn set_link_status(&mut self, id: &LinkId, status: LinkStatus, by: &str, basis: &[RecordId]) -> Result<(), KernelError> {
        AuditStore::set_link_status(&mut self.state, id, status, by, basis)
    }
    fn link(&self, id: &LinkId) -> Option<LinkView> {
        AuditStore::link(&self.state, id)
    }
    fn links(&self) -> Vec<LinkView> {
        AuditStore::links(&self.state)
    }
    fn links_of(&self, record: &RecordId) -> Vec<LinkView> {
        AuditStore::links_of(&self.state, record)
    }
    fn link_usable(&self, id: &LinkId) -> bool {
        AuditStore::link_usable(&self.state, id)
    }
    fn usable_links(&self) -> Option<BTreeSet<LinkId>> {
        AuditStore::usable_links(&self.state)
    }
    fn concepts(&self) -> Vec<ConceptView> {
        AuditStore::concepts(&self.state)
    }
    fn submit_operations_id(&mut self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Result<Value, KernelError> {
        if self.refuse && id.starts_with("reopen-limit-") {
            self.refuse = false;
            self.refused += 1;
            return Err(KernelError::new(Code::BadField, "the store refused this write once"));
        }
        AuditStore::submit_operations_id(&mut self.state, id, actor, operations, checkpoint)
    }
    fn checkpoint(&self, key: &str) -> Option<Value> {
        AuditStore::checkpoint(&self.state, key)
    }
    fn checkpoint_keys(&self, prefix: &str) -> Vec<String> {
        AuditStore::checkpoint_keys(&self.state, prefix)
    }
    fn support_map(&self) -> Option<BTreeMap<RecordId, (bool, bool)>> {
        AuditStore::support_map(&self.state)
    }
    fn run_namespace(&self) -> Hash {
        AuditStore::run_namespace(&self.state)
    }
    fn root(&self) -> Hash {
        AuditStore::root(&self.state)
    }
    fn epoch(&self) -> Hash {
        AuditStore::epoch(&self.state)
    }
}

#[test]
fn a_task_fallen_again_past_its_openings_is_written_unresolved_and_a_refused_write_is_retried() {
    let lines = ["Line one alpha is the rule.", "Line two beta is the rule.", "Line three gamma is the rule."];
    let text = format!("## Task #1\n\n{}\n", lines.join("\n\n"));
    let (w, s) = run_doc("reopen-limit-write", &text, json!({"agent_attempts": 1, "unit_is_task": true}));
    let cfg = DispatchConfig { agent_attempts: Some(1), ..plan_config() };
    let mut fs = OnceRefusing { state: s, refuse: true, refused: 0 };
    let mut d = Dispatcher::new(cfg.clone(), vec![]);
    for line in lines.iter().take(2) {
        let t = d.acquire(&fs, "w1", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(d.submit(&mut fs, id(&t), "w1", &report(&t, line), 0)["status"], "COMMITTED");
        fs.state.withdraw_text("owner", DOC, line).unwrap();
    }
    let key = json!(format!("doc:{DOC}#0"));
    let task = format!("task:doc:{DOC}#0");
    // before any call gives it up, the completion already names it
    assert!(d.completion(&fs, true)["unresolved"].as_array().unwrap().contains(&key));
    assert_eq!(d.acquire(&fs, "w2", true, 0)["status"], "COMPLETE", "not issued again past its bound");
    // the first write is refused: the mark stays queued, and the dispatcher still reports the unit as unresolved
    assert_eq!(d.persist_unresolved(&mut fs).len(), 1);
    assert_eq!(fs.refused, 1);
    assert_ne!(fs.checkpoint(&task).unwrap()["context"]["unresolved"], true, "not written yet");
    assert!(d.completion(&fs, true)["unresolved"].as_array().unwrap().contains(&key));
    // the next call with the store writes it
    assert!(d.persist_unresolved(&mut fs).is_empty());
    let mark = fs.checkpoint(&task).unwrap()["context"].clone();
    assert_eq!((mark["unresolved"].as_bool(), mark["reason"].as_str(), mark["reopened"].as_u64()), (Some(true), Some("REOPEN_LIMIT"), Some(1)), "{mark}");
    // and a restart on the journal reads it back
    drop(fs);
    let reopened = AuditState::open(&w.0).unwrap();
    let mut again = Dispatcher::new(cfg, vec![]);
    again.recover(&reopened);
    let completion = again.completion(&reopened, true);
    assert!(completion["unresolved"].as_array().unwrap().contains(&key), "{completion}");
    assert_eq!(again.acquire(&reopened, "w3", true, 0)["status"], "COMPLETE");
    assert_eq!(again.stats.reopened_units, 0, "given up, not opened again");
}

// ---- PR55-R2: withdrawn bytes of the CONTEXT above a section are marks, as in the section

#[test]
fn a_heading_withdrawn_in_part_is_shown_as_context_with_its_withdrawn_bytes_marked() {
    let text = "## Paint cell_1 RED now\n\nA surviving paragraph with ordinary facts about the current task.\n\nFallback: paint cell_1 BLUE.\n";
    let (_w, mut s) = run_doc("context-mark", text, json!({"section_bytes": 64}));
    let mut d = Dispatcher::new(DispatchConfig { section_bytes: 64, ..config() }, vec![]);
    // nothing withdrawn: the heading is the context of the later sections, and there is no note
    let mut seen = Vec::new();
    for agent in ["w1", "w2", "w3"] {
        let t = d.acquire(&s, agent, true, 0);
        if t["kind"] == "EXTEND" {
            seen.push((agent, t));
        }
    }
    let plain: Vec<&str> = seen.iter().map(|(_, t)| t["prompt"].as_str().unwrap()).filter(|p| p.contains("CONTEXT above this section")).collect();
    assert!(!plain.is_empty() && plain.iter().all(|p| p.contains("section heading: ## Paint cell_1 RED now") && !p.contains("WITHDRAWN TEXT")));
    for (agent, t) in &seen {
        d.release(id(t), agent);
    }
    // the owner withdraws one word of the heading: a later section shows it as a mark, with the note
    s.withdraw_text("owner", DOC, "RED").unwrap();
    let mut later = None;
    for agent in ["w4", "w5", "w6"] {
        let t = d.acquire(&s, agent, true, 0);
        if t["prompt"].as_str().unwrap_or_default().contains("CONTEXT above this section") {
            later = Some(t);
            break;
        }
    }
    let later = later.expect("a card with context");
    let p = later["prompt"].as_str().unwrap();
    assert!(p.contains("section heading: ## Paint cell_1 [withdrawn: 3 bytes] now"), "{p}");
    assert!(!p.contains("RED") && p.contains("WITHDRAWN TEXT"), "{p}");
}
