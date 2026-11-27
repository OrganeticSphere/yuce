//! A late answer in every way a task ends (0.3.1; Codex's review of dbb7de2a).
//!
//! A task ends in several places of the kernel, and each leaves its own trace in the journal. An answer sent to a task the
//! journal shows ended gets one checkpoint `task-conflict:<task>:<n>`, whichever trace it is, and whether the dispatcher that
//! ended the task still runs or another was started on the same journal. An answer sent again, line for line by the same
//! agent, adds nothing. A task that left no trace is not ended in the journal, and an answer to it leaves none either.
//!
//! | how the task ended                                        | its trace in the journal       | `closed_as`  |
//! |-----------------------------------------------------------|--------------------------------|--------------|
//! | its answer was committed                                  | `task:<key>`                   | `completed`  |
//! | failed leases gave its work up (attempts not counted)     | `task:<key>`, unresolved       | `unresolved` |
//! | given back with a reason, attempts counted                | `audit:agent-failures`         | `failed`, or `unresolved` at the bound |
//! | timed out, attempts counted                               | `audit:agent-failures`         | the same     |
//! | its lease ran out, attempts counted                       | `audit:agent-failures`         | the same     |
//! | the same, the dispatcher started again before it ran out  | none (the lease was in memory) | no record    |
//! | released after a refused answer, attempts counted         | `audit:agent-failures`         | the same     |
//! | given back with a reason, no count and no ring            | `task-failed:<task>`           | `failed`     |
//! | a reader of a ring gave it back with a reason             | the mark of the ring, not read | no record    |
//! | a reader of a ring timed out on it                        | the mark of the ring, not read | no record    |
//! | given back plainly                                        | none                           | no record    |
//! | its lease ran out, no count, the work still open          | none                           | no record    |
//! | a task nobody was given                                   | none                           | no record    |
//!
//! The mark of a ring names a task without its kind, and a reader of a ring takes cards of the builder too: it is not read,
//! as a card of the builder is no task of this rule. The cells of the server's cache of acknowledgements are in
//! `crates/sbgk-cli/tests/audit_serve.rs`.
use sbgk_core::audit::builder::parallel::ParallelBuilder;
use sbgk_core::audit::builder::BuilderConfig;
use sbgk_core::audit::directives::circles::CircleConfig;
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, TaskKind};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::AuditStore;
use sbgk_core::hash::{sha256, to_hex};
use sbgk_core::jcs::to_jcs;
use serde_json::{json, Value};
use std::path::PathBuf;

const REASON: &str = "ALL_ANSWERS_REFUSED";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A journal of nine short documents; with `attempts`, the journal's own setting of the count of attempts, as a server writes
/// it at the start of a run.
fn fresh(attempts: Option<u32>) -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let w = Wal(std::env::temp_dir().join(format!("late_cells_{}_{n}.wal", std::process::id())));
    let docs = (0..9).map(|i| (format!("d{i}"), format!("# Topic {i}\nThe topic has condition {i}.\n").into_bytes())).collect::<Vec<_>>();
    let mut s = AuditState::create(&w.0, &AuditOntology::base(), &docs, "late-cells", sha256(b"toy")).unwrap();
    if let Some(limit) = attempts {
        let policy = json!({"key": "audit:mcp:coverage", "from": 0, "to": 0, "context": {"agent_attempts": limit}});
        assert_eq!(s.submit_operations_id("policy", "kernel", &[], Some(policy)).unwrap()["checkpointed"], true);
    }
    (w, s)
}

fn id(task: &Value) -> String {
    task["task_id"].as_str().unwrap_or_else(|| panic!("no task: {task}")).to_string()
}

fn digest(lines: &[Value]) -> String {
    to_hex(&sha256(to_jcs(&json!(lines)).as_bytes()))
}

/// The contexts of the late answers the journal holds for a task, in their order.
fn late(s: &AuditState, task: &str) -> Vec<Value> {
    let mut marks: Vec<(u64, Value)> = s
        .checkpoint_keys(&format!("task-conflict:{task}:"))
        .iter()
        .map(|key| (key.rsplit(':').next().unwrap().parse().unwrap(), s.checkpoint(key).unwrap()["context"].clone()))
        .collect();
    marks.sort_by_key(|(n, _)| *n);
    marks.into_iter().map(|(_, context)| context).collect()
}

/// The lines of a reading that the store takes: a quote of the task's document and a claim on it.
fn reading(task: &Value) -> Vec<Value> {
    let p = task["local_id_prefix"].as_str().unwrap();
    let doc = task["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
    let n = &doc[1..];
    vec![
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": format!("The topic has condition {n}."), "terms": ["topic"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": format!("Topic {n} has condition {n}."), "subject": "topic", "stance": "reported",
               "based_on": [format!("{p}o1")]}),
    ]
}

/// A line the store refuses: a quote that is not in the task's document.
fn refused(task: &Value) -> Vec<Value> {
    let doc = task["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
    vec![json!({"kind": "observe", "local_id": "x", "doc_id": doc, "exact_quote": "No such sentence is in the document.", "terms": ["topic"]})]
}

/// A dispatcher that never ran this journal, started on it: what a restarted server has.
fn started_again(cfg: &DispatchConfig, s: &AuditState) -> Dispatcher {
    let mut d = Dispatcher::new(cfg.clone(), vec![]);
    d.recover(s);
    d.recover_members(s).unwrap();
    d
}

fn ring_config(exclude_on_failure: bool, attempts: Option<u32>) -> DispatchConfig {
    let circles = Some(CircleConfig { wave_sections: 3, readers: vec!["w1".into(), "w2".into(), "w3".into()], agent_timeout_ms: 600_000 });
    DispatchConfig { circles, exclude_on_failure, agent_attempts: attempts, ..Default::default() }
}

fn pool() -> ParallelBuilder {
    ParallelBuilder::new(BuilderConfig { author_runs: true, max_records: 16, ..Default::default() }, vec!["w1".into(), "w2".into(), "w3".into()])
}

/// One way a task ends. The setup ends a task of `w1` and gives its id back, with a task that ended without a trace when the
/// way leaves one behind.
struct Way {
    name: &'static str,
    cfg: DispatchConfig,
    attempts: Option<u32>,
    /// `Some(how)`: the journal shows the task ended so; `None`: it left no trace.
    closed_as: Option<&'static str>,
    /// Whether the trace names the key of the work.
    names_the_work: bool,
    /// Whether the trace names the agent whose task it was (a work given up by failed leases that were not counted does not).
    names_the_agent: bool,
    /// Whether the end is only in the memory of the dispatcher when it is started again: a lease still held lives there, and a
    /// restart before it ran out leaves no trace of the task.
    lost_on_restart: bool,
    end: fn(&mut Dispatcher, &mut AuditState) -> (String, Value),
}

fn extend(d: &mut Dispatcher, s: &mut AuditState, now: u64) -> Value {
    let task = d.acquire_for(s, "w1", true, None, Some(&[TaskKind::Extend]), now);
    assert_eq!(task["kind"], "EXTEND", "{task}");
    task
}

fn ring_task(d: &mut Dispatcher, s: &mut AuditState) -> Value {
    let p = pool();
    let caught_up = p.caught_up(s);
    d.advance_circles(s, caught_up, 0, 10000).unwrap();
    d.prepare_ring(s, 1, 10001).unwrap();
    let task = d.acquire_for(s, "w1", p.caught_up(s), None, Some(&[TaskKind::Extend]), 1);
    assert_eq!(task["kind"], "EXTEND", "{task}");
    task
}

fn ways() -> Vec<Way> {
    let plain = DispatchConfig::default;
    let counted = |limit: u32| DispatchConfig { agent_attempts: Some(limit), ttl_ms: 100, ..Default::default() };
    vec![
        Way {
            name: "its answer was committed",
            cfg: plain(),
            attempts: None,
            closed_as: Some("completed"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                let done = d.submit(s, &id(&task), "w1", &reading(&task), 2);
                assert_eq!(done["status"], "COMMITTED", "{done}");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "failed leases gave its work up, attempts not counted",
            cfg: plain(),
            attempts: None,
            closed_as: Some("unresolved"),
            names_the_work: true,
            names_the_agent: false,
            lost_on_restart: false,
            end: |d, s| {
                let first = extend(d, s, 1);
                let key = first["key"].clone();
                let mut task = first;
                let mut out = Value::Null;
                for n in 0..3u64 {
                    if n > 0 {
                        task = (0..40)
                            .map(|t| d.acquire_for(s, "w1", true, None, Some(&[TaskKind::Extend]), 10 + n * 50 + t))
                            .find(|t| t["key"] == key)
                            .expect("the unit again");
                    }
                    // an answer the kernel refuses marks the lease failed; released, it is a failed attempt
                    let refused = d.submit(s, &id(&task), "w1", &refused(&task), 10 + n * 50);
                    assert_eq!(refused["status"], "REPAIR_REQUIRED", "{refused}");
                    out = d.release_durable(s, &id(&task), "w1");
                    assert_eq!(out["status"], "RELEASED", "{out}");
                }
                assert_eq!(out["unresolved"], true, "{out}");
                (id(&task), key)
            },
        },
        Way {
            name: "given back with a reason, attempts counted, the work still open",
            cfg: counted(3),
            attempts: Some(3),
            closed_as: Some("failed"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                let out = d.fail_task(s, &id(&task), "w1", REASON);
                assert_eq!((out["status"].as_str(), out["unresolved"].as_bool()), (Some("RELEASED"), Some(false)), "{out}");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "given back with a reason at the bound of attempts",
            cfg: counted(1),
            attempts: Some(1),
            closed_as: Some("unresolved"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                let out = d.fail_task(s, &id(&task), "w1", REASON);
                assert_eq!((out["status"].as_str(), out["unresolved"].as_bool()), (Some("RELEASED"), Some(true)), "{out}");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "timed out, attempts counted",
            cfg: counted(3),
            attempts: Some(3),
            closed_as: Some("failed"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                assert_eq!(d.timeout_task(s, &id(&task), "w1")["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "its lease ran out, attempts counted",
            cfg: counted(3),
            attempts: Some(3),
            closed_as: Some("failed"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: true,
            // the lease is still held: the late answer itself, sent after its time, ends it
            end: |d, s| {
                let task = extend(d, s, 1);
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "released after a refused answer, attempts counted",
            cfg: counted(3),
            attempts: Some(3),
            closed_as: Some("failed"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                let refused = d.submit(s, &id(&task), "w1", &refused(&task), 2);
                assert_eq!(refused["status"], "REPAIR_REQUIRED", "{refused}");
                assert_eq!(d.release_durable(s, &id(&task), "w1")["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "given back with a reason, no count and no ring",
            cfg: plain(),
            attempts: None,
            closed_as: Some("failed"),
            names_the_work: true,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                assert_eq!(d.fail_task(s, &id(&task), "w1", REASON)["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "a reader of a ring gave it back with a reason and stays in",
            cfg: ring_config(false, None),
            attempts: None,
            closed_as: None,
            names_the_work: false,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = ring_task(d, s);
                assert_eq!(d.fail_task(s, &id(&task), "w1", REASON)["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "a reader of a ring gave it back with a reason and is left out",
            cfg: ring_config(true, None),
            attempts: None,
            closed_as: None,
            names_the_work: false,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = ring_task(d, s);
                assert_eq!(d.fail_task(s, &id(&task), "w1", REASON)["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "a reader of a ring timed out on it",
            cfg: ring_config(false, None),
            attempts: None,
            closed_as: None,
            names_the_work: false,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = ring_task(d, s);
                assert_eq!(d.timeout_task(s, &id(&task), "w1")["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "given back plainly",
            cfg: plain(),
            attempts: None,
            closed_as: None,
            names_the_work: false,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                assert_eq!(d.release_durable(s, &id(&task), "w1")["status"], "RELEASED");
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "its lease ran out, no count, the work still open",
            cfg: DispatchConfig { ttl_ms: 100, ..Default::default() },
            attempts: None,
            closed_as: None,
            names_the_work: false,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                (id(&task), task["key"].clone())
            },
        },
        Way {
            name: "a task nobody was given",
            cfg: plain(),
            attempts: None,
            closed_as: None,
            names_the_work: false,
            names_the_agent: true,
            lost_on_restart: false,
            end: |d, s| {
                let task = extend(d, s, 1);
                let _ = d.release_durable(s, &id(&task), "w1");
                ("T999-no-such-task".to_string(), Value::Null)
            },
        },
    ]
}

/// Every way a task ends, with the dispatcher that ended it and with one started again on the journal: an answer that differs
/// leaves one record, the same answer again none, the next that differs one more, and the same lines of another agent one more.
#[test]
fn an_answer_to_an_ended_task_leaves_one_record_however_the_task_ended_and_whoever_runs() {
    // long after any lease of the cells has run out
    const LATER: u64 = 100_000;
    let (first, second) = (vec![json!({"kind": "claim", "text": "It is otherwise."})], vec![json!({"kind": "claim", "text": "It is otherwise again."})]);
    for way in ways() {
        for restart in [false, true] {
            let what = format!("{} ({})", way.name, if restart { "a dispatcher started again" } else { "the same dispatcher" });
            let (wal, mut s) = fresh(way.attempts);
            let mut d = Dispatcher::new(way.cfg.clone(), vec![]);
            let (task, key) = (way.end)(&mut d, &mut s);
            if restart {
                // what the server writes after every call, then the journal is opened again by another dispatcher
                let _ = d.persist_unresolved(&mut s);
                let _ = d.persist_members(&mut s);
                drop(s);
                s = AuditState::open(&wal.0).unwrap();
                d = started_again(&way.cfg, &s);
            }
            assert!(late(&s, &task).is_empty(), "{what}");
            let send = |d: &mut Dispatcher, s: &mut AuditState, agent: &str, lines: &[Value], now: u64| {
                let out = d.submit(s, &task, agent, lines, now);
                assert_eq!(out["status"], "STALE_TASK", "{what}: {out}");
                late(s, &task)
            };
            let marks = send(&mut d, &mut s, "w1", &first, LATER);
            let closed_as = if restart && way.lost_on_restart { None } else { way.closed_as };
            let Some(closed_as) = closed_as else {
                // no trace of the task, no record of the answer: and none after a restart either
                assert!(marks.is_empty(), "{what}: {marks:?}");
                assert!(send(&mut d, &mut s, "w2", &second, LATER + 1).is_empty(), "{what}");
                assert!(s.checkpoint_keys("task-conflict:").is_empty(), "{what}");
                continue;
            };
            assert_eq!(marks.len(), 1, "{what}: {marks:?}");
            let mark = &marks[0];
            assert_eq!(
                (mark["task_id"].as_str(), mark["agent"].as_str(), mark["closed_as"].as_str(), mark["closed_by"].as_str()),
                (Some(task.as_str()), Some("w1"), Some(closed_as), way.names_the_agent.then_some("w1")),
                "{what}: {mark}"
            );
            assert_eq!((mark["lines"].as_u64(), mark["answer_sha256"].as_str()), (Some(1), Some(digest(&first).as_str())), "{what}: {mark}");
            assert_eq!(mark["work_key"], if way.names_the_work { key.clone() } else { Value::Null }, "{what}: {mark}");
            // the mark holds what the kernel computed and no word of the answer
            assert_eq!(mark.as_object().unwrap().len(), 7, "{what}: {mark}");
            assert!(!mark.to_string().contains("otherwise"), "{what}: {mark}");
            // the same answer again is the same late answer; one that differs is another; so are the same lines of another agent
            assert_eq!(send(&mut d, &mut s, "w1", &first, LATER + 1).len(), 1, "{what}: an exact repeat");
            assert_eq!(send(&mut d, &mut s, "w1", &second, LATER + 2).len(), 2, "{what}");
            let marks = send(&mut d, &mut s, "w2", &first, LATER + 3);
            assert_eq!(
                (marks.len(), marks[2]["agent"].as_str(), marks[2]["closed_by"].as_str()),
                (3, Some("w2"), way.names_the_agent.then_some("w1")),
                "{what}: {marks:?}"
            );
            assert_eq!(send(&mut d, &mut s, "w2", &first, LATER + 4).len(), 3, "{what}: an exact repeat of another agent");
            // the journal with the records replays to the same state
            let root = s.audit_root();
            drop(s);
            assert_eq!(AuditState::open(&wal.0).unwrap().audit_root(), root, "{what}");
        }
    }
}

/// The bound of late answers of one task holds for answers that all differ, and an exact repeat does not use it up.
#[test]
fn the_bound_of_late_answers_counts_answers_that_differ() {
    let (_wal, mut s) = fresh(None);
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let task = extend(&mut d, &mut s, 1);
    assert_eq!(d.submit(&mut s, &id(&task), "w1", &reading(&task), 2)["status"], "COMMITTED");
    for n in 0..10 {
        for _ in 0..3 {
            d.submit(&mut s, &id(&task), "w1", &[json!({"n": n})], 10 + n);
        }
    }
    assert_eq!(late(&s, &id(&task)).len(), 10);
    for n in 10..30 {
        d.submit(&mut s, &id(&task), "w1", &[json!({"n": n})], 10 + n);
    }
    assert_eq!(late(&s, &id(&task)).len(), 16);
}

/// The outcome a late answer names is the outcome of its own attempt: an earlier failed attempt stays `failed` after a later
/// attempt gave the work up, and the attempt that gave it up is `unresolved` (Codex's recheck of 4e8b3748, P3).
#[test]
fn a_late_answer_names_how_its_own_attempt_ended() {
    let (_wal, mut s) = fresh(Some(2));
    let mut d = Dispatcher::new(DispatchConfig { agent_attempts: Some(2), ttl_ms: 100, ..Default::default() }, vec![]);
    let first = extend(&mut d, &mut s, 1);
    let out = d.fail_task(&mut s, &id(&first), "w1", REASON);
    assert_eq!(out["unresolved"], false, "{out}");
    d.submit(&mut s, &id(&first), "w1", &[json!({"n": 1})], 2);
    let second =
        (0..40).map(|t| d.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), 3 + t)).find(|t| t["key"] == first["key"]).expect("the work again");
    let out = d.fail_task(&mut s, &id(&second), "w1", REASON);
    assert_eq!(out["unresolved"], true, "{out}");
    d.submit(&mut s, &id(&first), "w1", &[json!({"n": 2})], 50);
    d.submit(&mut s, &id(&second), "w1", &[json!({"n": 3})], 51);
    let earlier = late(&s, &id(&first));
    assert_eq!(earlier.iter().map(|c| c["closed_as"].as_str().unwrap()).collect::<Vec<_>>(), ["failed", "failed"], "{earlier:?}");
    let last = late(&s, &id(&second));
    assert_eq!((last.len(), last[0]["closed_as"].as_str()), (1, Some("unresolved")), "{last:?}");
}
