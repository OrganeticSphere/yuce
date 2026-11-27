//! A lease given back for a reason of the agent's own (`Dispatcher::fail_task`, 0.3.1): the attempt counts, and the journal keeps
//! the reason the agent gave, never a timeout that did not happen. Whether a reader of a ring is left out until the next shift
//! is the server's setting, not the agent's choice.
use sbgk_core::audit::builder::parallel::ParallelBuilder;
use sbgk_core::audit::builder::BuilderConfig;
use sbgk_core::audit::directives::circles::{failure_reason, CircleConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, TaskKind};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::AuditStore;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

const REASON: &str = "ALL_ANSWERS_REFUSED";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh() -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let w = Wal(std::env::temp_dir().join(format!("release_reason_{}_{n}.wal", std::process::id())));
    let docs = (0..9).map(|i| (format!("d{i}"), format!("# Topic {i}\nThe topic has condition {i}.\n").into_bytes())).collect::<Vec<_>>();
    let s = AuditState::create(&w.0, &AuditOntology::base(), &docs, "release-reason", sha256(b"toy")).unwrap();
    (w, s)
}

fn id(task: &Value) -> &str {
    task["task_id"].as_str().unwrap_or_else(|| panic!("no task: {task}"))
}

#[test]
fn a_reason_is_a_code_and_never_a_mark_of_the_kernel() {
    for good in [REASON, "A", "MODEL_GAVE_NOTHING_2", &"X".repeat(64)] {
        assert_eq!(failure_reason(good), Ok(()), "{good}");
    }
    for bad in ["", "all answers refused", "lower_case", "1ST", "_X", "WITH-DASH", "\u{410}", &"X".repeat(65)] {
        assert!(failure_reason(bad).is_err(), "{bad}");
    }
    // what the kernel writes itself for a lease that ended: the timeouts, its own failure marks and the kind of a task
    for kernel in ["MODEL_TIMEOUT", "READINESS_TIMEOUT", "MODEL_AGENT_FAILURE", "FAILED_LEASE_RELEASED", "LEASE_EXPIRED", "EXTEND", "BUILD", "SUMMARIZE"] {
        assert!(failure_reason(kernel).is_err(), "{kernel}");
    }
}

#[test]
fn a_task_given_back_for_a_reason_counts_as_a_failed_attempt_and_the_journal_keeps_the_reason() {
    let (_w, mut s) = fresh();
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let first = d.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), 1);
    assert_eq!(first["kind"], "EXTEND", "{first}");
    let key = first["key"].as_str().unwrap().to_string();
    // no subject reports for another, and a task nobody holds is stale: nothing is written for either
    let root = s.root();
    assert_eq!(d.fail_task(&mut s, id(&first), "w2", REASON)["code"], "TASK_NOT_OWNED");
    assert_eq!(d.fail_task(&mut s, "no-such-task", "w1", REASON)["status"], "STALE_TASK");
    assert_eq!(s.root(), root);

    let released = d.fail_task(&mut s, id(&first), "w1", REASON);
    assert_eq!(
        (released["status"].as_str(), released["reason"].as_str(), released["unresolved"].as_bool()),
        (Some("RELEASED"), Some(REASON), Some(false)),
        "{released}"
    );
    let written = s.checkpoint(&format!("task-failed:{}", id(&first))).expect("the reason is in the journal")["context"].clone();
    assert_eq!(
        (written["reason"].as_str(), written["agent"].as_str(), written["kind"].as_str(), written["work_key"].as_str()),
        (Some(REASON), Some("w1"), Some("EXTEND"), Some(key.as_str()))
    );
    // the unit is open again, and the third failed attempt at it gives it up, as three failed leases do
    let mut last = Value::Null;
    for n in 0..2 {
        let again = (2..40).map(|t| d.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), t + n * 40)).find(|t| t["key"] == key.as_str());
        let again = again.expect("the unit is given again");
        last = d.fail_task(&mut s, id(&again), "w1", REASON);
        assert_eq!(last["status"], "RELEASED", "{last}");
    }
    assert_eq!(last["unresolved"], true, "{last}");
    // a recovered dispatcher keeps the unit given up
    let mut recovered = Dispatcher::new(DispatchConfig::default(), vec![]);
    recovered.recover(&s);
    let given: Vec<Value> = (0..12).map(|t| recovered.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), 200 + t)).collect();
    assert_eq!(given.iter().filter(|t| t["kind"] == "EXTEND").count(), 8, "the eight other units are given");
    assert!(!given.iter().any(|t| t["key"] == key.as_str()), "the unit given up is not given again");
}

fn ring(exclude_on_failure: bool) -> Dispatcher {
    let circles = Some(CircleConfig { wave_sections: 3, readers: vec!["w1".into(), "w2".into(), "w3".into()], agent_timeout_ms: 600_000 });
    Dispatcher::new(DispatchConfig { circles, exclude_on_failure, ..Default::default() }, vec![])
}

fn pool() -> ParallelBuilder {
    ParallelBuilder::new(BuilderConfig { author_runs: true, max_records: 16, ..Default::default() }, vec!["w1".into(), "w2".into(), "w3".into()])
}

fn acquire(d: &mut Dispatcher, s: &mut AuditState, p: &ParallelBuilder, who: &str, t: u64) -> Value {
    d.prepare_ring(s, t, 10000 + t).unwrap();
    d.acquire_for(s, who, p.caught_up(s), None, Some(&[TaskKind::Extend]), t)
}

fn ring_events(s: &AuditState) -> Vec<Value> {
    s.checkpoint("audit:ring-members").map(|c| c["context"]["events"].as_array().cloned().unwrap_or_default()).unwrap_or_default()
}

#[test]
fn a_reader_of_a_ring_is_left_in_or_out_by_the_servers_setting_and_the_ring_mark_names_the_reason() {
    for exclude in [false, true] {
        let (_w, mut s) = fresh();
        let (mut d, p) = (ring(exclude), pool());
        let caught_up = p.caught_up(&s);
        d.advance_circles(&mut s, caught_up, 0, 10000).unwrap();
        let task = acquire(&mut d, &mut s, &p, "w1", 1);
        assert_eq!(task["kind"], "EXTEND", "{task}");
        assert_eq!(d.fail_task(&mut s, id(&task), "w2", REASON)["code"], "TASK_NOT_OWNED");
        let released = d.fail_task(&mut s, id(&task), "w1", REASON);
        assert_eq!((released["status"].as_str(), released["reason"].as_str()), (Some("RELEASED"), Some(REASON)), "{released}");
        assert_eq!(released.get("excluded_until_next_shift").and_then(Value::as_bool), exclude.then_some(true), "{released}");
        // the mark of the ring names what the agent reported, and no timeout
        let events = ring_events(&s);
        let mark = events.iter().find(|e| e["agent"] == "w1" && e["task"] == id(&task)).unwrap_or_else(|| panic!("no mark: {events:?}"));
        assert_eq!((mark["kind"].as_str(), mark["reason"].as_str()), (Some(if exclude { "EXCLUDED" } else { "ATTEMPT_FAILED" }), Some(REASON)), "{mark}");
        assert!(!events.iter().any(|e| e["reason"] == "MODEL_TIMEOUT"), "{events:?}");
        let excluded = s.checkpoint("audit:ring-members").unwrap()["context"]["excluded"].clone();
        assert_eq!(excluded, if exclude { json!(["w1"]) } else { json!([]) });
        // left in, the reader gets its unit again; left out, it waits for the next shift
        let again = acquire(&mut d, &mut s, &p, "w1", 2);
        assert_eq!(again["kind"] == "EXTEND", !exclude, "{again}");
        if !exclude {
            assert_eq!(again["key"], task["key"]);
        }
    }
}
