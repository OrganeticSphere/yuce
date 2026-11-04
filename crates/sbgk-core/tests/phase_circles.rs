//! Real-WAL phase barriers, maximum non-author matching, out-of-order prefix, and recovery.
use sbgk_core::audit::builder::parallel::ParallelBuilder;
use sbgk_core::audit::builder::BuilderConfig;
use sbgk_core::audit::directives::circles::CircleConfig;
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, TaskKind};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::AuditStore;
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
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let w = Wal(std::env::temp_dir().join(format!("circle_{}_{n}.wal", std::process::id())));
    let docs = (0..9).map(|i| (format!("d{i}"), format!("# Topic {i}\nThe topic has condition {i}.\n").into_bytes())).collect::<Vec<_>>();
    let s = AuditState::create(&w.0, &AuditOntology::base(), &docs, "circles-toy", sha256(b"toy")).unwrap();
    (w, s)
}
fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig {
            circles: Some(CircleConfig { wave_sections: 3, readers: vec!["w1".into(), "w2".into(), "w3".into()], agent_timeout_ms: 600_000 }),
            ..Default::default()
        },
        vec![],
    )
}
fn pool() -> ParallelBuilder {
    ParallelBuilder::new(BuilderConfig { author_runs: true, max_records: 16, ..Default::default() }, vec!["w1".into(), "w2".into(), "w3".into()])
}
fn tick(d: &mut Dispatcher, s: &mut AuditState, p: &ParallelBuilder, t: u64) {
    d.advance_circles(s, p.caught_up(s), t, 10000 + t).unwrap();
}
fn acquire(d: &mut Dispatcher, s: &mut AuditState, p: &ParallelBuilder, who: &str, kinds: &[TaskKind], t: u64) -> Value {
    d.prepare_ring(s, t, 10000 + t).unwrap();
    d.acquire_for(s, who, p.caught_up(s), None, Some(kinds), t)
}
fn answer(t: &Value, s: &AuditState) -> Vec<Value> {
    let doc = t["key"].as_str().unwrap().strip_prefix("doc:").unwrap().split('#').next().unwrap();
    let q = s.doc_text(doc).unwrap().lines().nth(1).unwrap().to_string();
    vec![
        json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":q,"terms":["topic"]}),
        json!({"kind":"claim","local_id":"c","subject":"topic","text":q,"stance":"reported","based_on":["o"]}),
    ]
}
fn start_build(d: &mut Dispatcher, s: &mut AuditState, p: &mut ParallelBuilder, t: u64) -> Vec<Value> {
    tick(d, s, p, t);
    let mut tasks = vec![];
    for who in ["w1", "w2", "w3"] {
        let task = acquire(d, s, p, who, &[TaskKind::Extend], t + 1);
        assert_eq!(task["kind"], "EXTEND", "{task}");
        assert_eq!(task["circle_phase"], "READ");
        let lines = answer(&task, s);
        assert_eq!(d.submit(s, task["task_id"].as_str().unwrap(), who, &lines, t + 2)["status"], "COMMITTED");
        tasks.push(task);
    }
    tick(d, s, p, t + 3);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "BUILD");
    let done = d.reading_done(s);
    let number = d.circle_status().unwrap()["circle"].as_u64().unwrap();
    let cards = p.offers(s, number, done).unwrap();
    d.offer_ring_builds(p.batch(), cards);
    tasks
}
fn build_tasks(d: &mut Dispatcher, s: &mut AuditState, p: &ParallelBuilder, t: u64) -> Vec<(String, Value)> {
    let mut tasks = vec![];
    for pass in 0..2 {
        for who in ["w1", "w2", "w3"] {
            if tasks.iter().any(|(a, _): &(String, Value)| a == who) {
                continue;
            }
            let task = acquire(d, s, p, who, &[TaskKind::Build], t + pass);
            if task["kind"] == "BUILD" {
                if pass == 0 {
                    assert_eq!(who, "w3", "no model task before all three readers arrive");
                }
                assert!(task["card"]["records"].as_array().unwrap().iter().all(|r| r["author"] != who));
                let author = task["card"]["records"][0]["author"].as_str().unwrap();
                let recipient = match author {
                    "w1" => "w2",
                    "w2" => "w3",
                    "w3" => "w1",
                    _ => panic!("unexpected author"),
                };
                assert_eq!(who, recipient, "strict clockwise destination");
                tasks.push((who.to_string(), task));
            } else {
                assert_eq!(task["status"], "WAIT", "{task}");
            }
        }
    }
    assert_eq!(tasks.len(), p.open_count(s), "each active slot has exactly its fixed reader");
    tasks
}

fn submit(d: &mut Dispatcher, s: &mut AuditState, p: &mut ParallelBuilder, who: &str, t: &Value, ops: &[Value], now: u64) -> Value {
    let worker = p.worker_mut(t["card_id"].as_str().unwrap()).unwrap();
    let r = d.submit_build(s, worker, t["task_id"].as_str().unwrap(), who, ops, now);
    assert_ne!(r["status"], "error", "{r}");
    r
}

#[test]
fn three_circles_separate_reading_building_and_reach_terminal() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (dispatcher(), pool());
    for n in 1..=3 {
        start_build(&mut d, &mut s, &mut p, n * 100);
        assert_eq!(d.circle_status().unwrap()["circle"], n);
        assert_eq!(acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Extend], n * 100 + 4)["status"], "WAIT", "no next-wave reading during BUILD");
        let tasks = build_tasks(&mut d, &mut s, &p, n * 100 + 5);
        assert_eq!(p.open_count(&s), 3);
        let mut ids = std::collections::BTreeSet::new();
        for (_, t) in &tasks {
            for r in t["card"]["records"].as_array().unwrap() {
                assert!(ids.insert(r["id"].as_str().unwrap().to_string()));
            }
        }
        assert_eq!(ids.len(), 6, "three disjoint cards");
        let start = p.cursor(&s);
        let mut ordered = tasks;
        ordered.sort_by_key(|(_, t)| t["card"]["cursor_from"].as_u64().unwrap());
        for (i, (who, t)) in ordered.iter().rev().enumerate() {
            assert_eq!(submit(&mut d, &mut s, &mut p, who, t, &[], n * 100 + 6)["status"], "CARD_DONE");
            assert_eq!(p.cursor(&s), if i < 2 { start } else { s.head() }, "only the longest closed prefix moves");
        }
        assert!(p.caught_up(&s));
        tick(&mut d, &mut s, &p, n * 100 + 7);
        assert_eq!(d.circle_status().unwrap()["circle_phase"], if n == 3 { "FINAL" } else { "READ" });
    }
    assert!(d.terminal_receipt(&s, p.cursor(&s), "circles-toy").is_some());
}

#[test]
fn reading_waits_for_every_lease_and_repair_and_restart_keeps_its_wave() {
    let (w, mut s) = fresh();
    let (mut d, mut p) = (dispatcher(), pool());
    tick(&mut d, &mut s, &p, 0);
    let first = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Extend], 1);
    let second = acquire(&mut d, &mut s, &p, "w2", &[TaskKind::Extend], 1);
    assert_eq!(acquire(&mut d, &mut s, &p, "w3", &[TaskKind::Build], 1)["status"], "WAIT");
    let mut bad = answer(&first, &s);
    bad[0]["exact_quote"] = json!("not present in any source");
    assert_eq!(d.submit(&mut s, first["task_id"].as_str().unwrap(), "w1", &bad, 2)["status"], "REPAIR_REQUIRED");
    tick(&mut d, &mut s, &p, 3);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "READ");
    let good = answer(&second, &s);
    assert_eq!(d.submit(&mut s, second["task_id"].as_str().unwrap(), "w2", &good, 4)["status"], "COMMITTED");
    assert_eq!(acquire(&mut d, &mut s, &p, "w2", &[TaskKind::Extend], 5)["status"], "WAIT", "a fast reader cannot consume another reader's section");
    let state = d.circle_status().unwrap();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    d = dispatcher();
    d.recover(&s);
    p = pool();
    p.recover(&s).unwrap();
    tick(&mut d, &mut s, &p, 10);
    assert_eq!(d.circle_status().unwrap(), state);
    let again = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Extend], 11);
    assert_eq!(again["key"], first["key"]);
    assert_ne!(again["task_id"], first["task_id"]);
    let root = s.root();
    assert_eq!(d.submit(&mut s, first["task_id"].as_str().unwrap(), "w1", &[], 12)["status"], "STALE_TASK");
    assert_eq!(s.root(), root);
    for (who, t) in [("w1", again), ("w3", acquire(&mut d, &mut s, &p, "w3", &[TaskKind::Extend], 11))] {
        let lines = answer(&t, &s);
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), who, &lines, 13)["status"], "COMMITTED");
    }
    tick(&mut d, &mut s, &p, 14);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "BUILD");
}

#[test]
fn restart_preserves_out_of_order_close_and_partial_operations_then_reissues_only_open_cards() {
    let (w, mut s) = fresh();
    let (mut d, mut p) = (dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    let mut tasks = build_tasks(&mut d, &mut s, &p, 5);
    tasks.sort_by_key(|(_, t)| t["card"]["cursor_from"].as_u64().unwrap());
    let (who, mid) = &tasks[1];
    assert_eq!(submit(&mut d, &mut s, &mut p, who, mid, &[], 6)["status"], "CARD_DONE");
    let (who, first) = &tasks[0];
    let ob = first["card"]["records"][0]["id"].as_str().unwrap();
    let ops = [
        json!({"op":"propose_concept","type":"Component","name":"topic shared","aliases":[],"basis":[ob]}),
        json!({"op":"map_term","record":ob,"term":"not issued","concept":"topic shared"}),
    ];
    assert_eq!(submit(&mut d, &mut s, &mut p, who, first, &ops, 7)["status"], "REPAIR_REQUIRED");
    assert_eq!(p.cursor(&s), 0);
    let root = s.root();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    d = dispatcher();
    d.recover(&s);
    p = pool();
    p.recover(&s).unwrap();
    assert_eq!(s.root(), root);
    tick(&mut d, &mut s, &p, 10);
    let cards = p.offers(&mut s, 1, false).unwrap();
    assert_eq!(cards.len(), 2);
    assert!(cards.iter().all(|c| c.card_id != mid["card_id"]));
    d.offer_ring_builds(p.batch(), cards);
    assert_eq!(d.submit(&mut s, first["task_id"].as_str().unwrap(), who, &[], 11)["status"], "STALE_TASK");
    let reopened = build_tasks(&mut d, &mut s, &p, 12);
    for (agent, t) in reopened {
        let ops = if t["card_id"] == first["card_id"] { vec![json!({"op":"map_term","record":ob,"term":"topic","concept":"topic shared"})] } else { vec![] };
        assert_eq!(submit(&mut d, &mut s, &mut p, &agent, &t, &ops, 15)["status"], "CARD_DONE");
    }
    assert_eq!(p.cursor(&s), s.head());
    assert_eq!(s.candidates("topic shared", 10).len(), 1);
}

#[test]
fn next_wave_sees_bounded_relevant_concepts_as_vocabulary_not_evidence() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    let tasks = build_tasks(&mut d, &mut s, &p, 5);
    for (i, (who, t)) in tasks.iter().enumerate() {
        let ob = t["card"]["records"][0]["id"].as_str().unwrap();
        let ops = if i == 0 {
            (0..45).map(|k|json!({"op":"propose_concept","type":"Component","name":format!("topic concept {k}"),"aliases":[format!("topic alias {k}")],"basis":[ob]})).collect::<Vec<_>>()
        } else {
            vec![]
        };
        assert_eq!(submit(&mut d, &mut s, &mut p, who, t, &ops, 6)["status"], "CARD_DONE");
    }
    tick(&mut d, &mut s, &p, 7);
    let t = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Extend], 8);
    let prompt = t["prompt"].as_str().unwrap();
    let known = prompt.split("KNOWN CONCEPTS").nth(1).unwrap();
    assert!(known.contains("shared vocabulary only, not evidence"));
    assert_eq!(known.lines().skip(1).take_while(|l| l.starts_with("  @")).count(), 40);
    assert!(known.contains("topic alias"));
}

fn short_dispatcher() -> Dispatcher {
    let mut d = dispatcher();
    d.cfg.circles.as_mut().unwrap().agent_timeout_ms = 20;
    d
}
fn refresh(d: &mut Dispatcher, s: &mut AuditState, p: &mut ParallelBuilder, t: u64) {
    tick(d, s, p, t);
    let number = d.circle_status().unwrap()["circle"].as_u64().unwrap();
    let cards = if d.circle_is_reading() {
        vec![]
    } else {
        let done = d.reading_done(s);
        p.offers(s, number, done).unwrap()
    };
    d.offer_ring_builds(p.batch(), cards);
    d.prepare_ring(s, t, 10000 + t).unwrap();
}

#[test]
fn expired_build_is_durably_excluded_and_reassigned_without_accepting_its_late_response() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (short_dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    let tasks = build_tasks(&mut d, &mut s, &p, 5);
    let late = tasks.iter().find(|(a, _)| a == "w2").unwrap().1.clone();
    for (a, t) in &tasks {
        if a != "w2" {
            assert_eq!(submit(&mut d, &mut s, &mut p, a, t, &[], 7)["status"], "CARD_DONE");
        }
    }
    refresh(&mut d, &mut s, &mut p, 30);
    assert!(d.circle_status().unwrap()["excluded"].as_array().unwrap().contains(&json!("w2")));
    let replacement = acquire(&mut d, &mut s, &p, "w3", &[TaskKind::Build], 31);
    assert_eq!(replacement["kind"], "BUILD", "{replacement}");
    assert_eq!(replacement["card_id"], late["card_id"]);
    assert_ne!(replacement["task_id"], late["task_id"]);
    let root = s.root();
    assert_eq!(d.submit(&mut s, late["task_id"].as_str().unwrap(), "w2", &[], 32)["status"], "STALE_TASK");
    assert_eq!(s.root(), root, "late response writes nothing");
    assert_eq!(submit(&mut d, &mut s, &mut p, "w3", &replacement, &[], 33)["status"], "CARD_DONE");
}

#[test]
fn recovered_agent_joins_next_shift_in_build_and_cannot_join_mid_shift() {
    let (_w, mut s) = fresh();
    let mut d = short_dispatcher();
    let mut p = ParallelBuilder::new(BuilderConfig { author_runs: true, max_records: 1, ..Default::default() }, vec!["w1".into(), "w2".into(), "w3".into()]);
    start_build(&mut d, &mut s, &mut p, 0);
    let tasks = build_tasks(&mut d, &mut s, &p, 5);
    let late = tasks.iter().find(|(a, _)| a == "w2").unwrap().1.clone();
    for (a, t) in &tasks {
        if a != "w2" {
            assert_eq!(submit(&mut d, &mut s, &mut p, a, t, &[], 7)["status"], "CARD_DONE");
        }
    }
    refresh(&mut d, &mut s, &mut p, 30);
    let substitute = acquire(&mut d, &mut s, &p, "w3", &[TaskKind::Build], 31);
    assert_eq!(substitute["kind"], "BUILD");
    let step = d.circle_status().unwrap()["sync_step"].clone();
    assert_eq!(acquire(&mut d, &mut s, &p, "w2", &[TaskKind::Build], 32)["status"], "WAIT");
    d.prepare_ring(&mut s, 33, 10033).unwrap();
    assert_eq!(d.circle_status().unwrap()["sync_step"], step, "live substitute prevents mid-step rejoin");
    assert_eq!(submit(&mut d, &mut s, &mut p, "w3", &substitute, &[], 34)["status"], "CARD_DONE");
    refresh(&mut d, &mut s, &mut p, 35);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "BUILD");
    assert!(d.circle_status().unwrap()["sync_step"].as_u64() > step.as_u64());
    assert!(!d.circle_status().unwrap()["excluded"].as_array().unwrap().contains(&json!("w2")));
    let tasks = build_tasks(&mut d, &mut s, &p, 36);
    assert!(tasks.iter().any(|(a, t)| a == "w2" && t["kind"] == "BUILD"));
    let root = s.root();
    assert_eq!(d.submit(&mut s, late["task_id"].as_str().unwrap(), "w2", &[], 37)["status"], "STALE_TASK");
    assert_eq!(s.root(), root);
}

#[test]
fn read_timeout_keeps_the_wave_open_then_an_available_reader_finishes_it() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (short_dispatcher(), pool());
    tick(&mut d, &mut s, &p, 0);
    let mut reads = vec![];
    for a in ["w1", "w2", "w3"] {
        reads.push((a, acquire(&mut d, &mut s, &p, a, &[TaskKind::Extend], 1)));
    }
    let late = reads.iter().find(|(a, _)| *a == "w2").unwrap().1.clone();
    for (a, t) in reads {
        if a != "w2" {
            let lines = answer(&t, &s);
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), a, &lines, 2)["status"], "COMMITTED");
        }
    }
    refresh(&mut d, &mut s, &mut p, 25);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "READ");
    let retry = acquire(&mut d, &mut s, &p, "w3", &[TaskKind::Extend], 26);
    assert_eq!(retry["key"], late["key"]);
    let lines = answer(&retry, &s);
    assert_eq!(d.submit(&mut s, retry["task_id"].as_str().unwrap(), "w3", &lines, 27)["status"], "COMMITTED");
    refresh(&mut d, &mut s, &mut p, 28);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "BUILD");
}

#[test]
fn exclusion_and_prefix_survive_restart_but_readiness_must_be_fresh() {
    let (w, mut s) = fresh();
    let (mut d, mut p) = (short_dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    let tasks = build_tasks(&mut d, &mut s, &p, 5);
    let late = tasks.iter().find(|(a, _)| a == "w2").unwrap().1.clone();
    let ob = late["card"]["records"][0]["id"].as_str().unwrap();
    assert_eq!(
        submit(
            &mut d,
            &mut s,
            &mut p,
            "w2",
            &late,
            &[
                json!({"op":"propose_concept","type":"Component","name":"timeout concept","aliases":[],"basis":[ob]}),
                json!({"op":"map_term","record":ob,"term":"wrong","concept":"timeout concept"})
            ],
            7
        )["status"],
        "REPAIR_REQUIRED"
    );
    for (a, t) in tasks {
        if a != "w2" {
            assert_eq!(submit(&mut d, &mut s, &mut p, &a, &t, &[], 8)["status"], "CARD_DONE");
        }
    }
    refresh(&mut d, &mut s, &mut p, 30);
    let root = s.root();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    d = short_dispatcher();
    d.recover(&s);
    p = pool();
    p.recover(&s).unwrap();
    refresh(&mut d, &mut s, &mut p, 40);
    assert_eq!(s.root(), root, "restart reads durable membership, no assumed readiness");
    assert_eq!(acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Build], 41)["status"], "WAIT");
    let retry = acquire(&mut d, &mut s, &p, "w3", &[TaskKind::Build], 42);
    assert_eq!(retry["card_id"], late["card_id"]);
    let op = json!({"op":"map_term","record":ob,"term":"topic","concept":"timeout concept"});
    assert_eq!(submit(&mut d, &mut s, &mut p, "w3", &retry, &[op], 43)["status"], "CARD_DONE");
    assert_eq!(s.candidates("timeout concept", 10).len(), 1, "accepted prefix retained");
}

#[test]
fn timeout_self_report_cannot_evict_another_subject_and_no_author_fallback_is_allowed() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (short_dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    let tasks = build_tasks(&mut d, &mut s, &p, 5);
    let w2 = &tasks.iter().find(|(a, _)| a == "w2").unwrap().1;
    let root = s.root();
    assert_eq!(d.timeout_task(&mut s, w2["task_id"].as_str().unwrap(), "w1")["code"], "TASK_NOT_OWNED");
    assert_eq!(s.root(), root);
    for (a, t) in &tasks {
        if a == "w1" {
            assert_eq!(submit(&mut d, &mut s, &mut p, a, t, &[], 7)["status"], "CARD_DONE");
        } else {
            assert_eq!(d.timeout_task(&mut s, t["task_id"].as_str().unwrap(), a)["status"], "RELEASED");
        }
    }
    let first = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Build], 8);
    assert_eq!(first["kind"], "BUILD");
    assert_eq!(submit(&mut d, &mut s, &mut p, "w1", &first, &[], 9)["status"], "CARD_DONE");
    let remaining = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Build], 10);
    assert_eq!(remaining["status"], "WAIT", "the remaining card is its own, so no self-build");
    assert!(!p.caught_up(&s));
}

#[test]
fn heartbeat_cannot_extend_the_circle_response_deadline() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (short_dispatcher(), pool());
    tick(&mut d, &mut s, &p, 0);
    let t = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Extend], 1);
    let renewed = d.renew(t["task_id"].as_str().unwrap(), "w1", 15);
    assert_eq!(renewed["expires_at_ms"], t["expires_at_ms"]);
    assert_eq!(renewed["response_deadline_fixed"], true);
    assert_eq!(d.renew(t["task_id"].as_str().unwrap(), "w1", 22)["status"], "STALE_TASK");
    refresh(&mut d, &mut s, &mut p, 23);
    assert!(d.circle_status().unwrap()["excluded"].as_array().unwrap().contains(&json!("w1")));
}

#[test]
fn missing_reader_at_build_barrier_times_out_without_self_build() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (short_dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    assert_eq!(acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Build], 5)["status"], "WAIT");
    assert_eq!(acquire(&mut d, &mut s, &p, "w2", &[TaskKind::Build], 5)["status"], "WAIT");
    refresh(&mut d, &mut s, &mut p, 30);
    assert!(d.circle_status().unwrap()["excluded"].as_array().unwrap().contains(&json!("w3")));
    let t = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Build], 31);
    assert_eq!(t["kind"], "BUILD");
    assert!(t["card"]["records"].as_array().unwrap().iter().all(|r| r["author"] != "w1"));
}

#[test]
fn unknown_concept_repair_can_propose_and_map_in_one_submission() {
    let (_w, mut s) = fresh();
    let (mut d, mut p) = (dispatcher(), pool());
    start_build(&mut d, &mut s, &mut p, 0);
    let tasks = build_tasks(&mut d, &mut s, &p, 5);
    let (who, t) = &tasks[0];
    let record = t["card"]["records"].as_array().unwrap().iter().find(|r| r["kind"] == "observe").unwrap()["id"].as_str().unwrap();
    let mapping = json!({"op":"map_term","record":record,"term":"topic","concept":"scoped topic"});
    let before = s.root();
    let refused = submit(&mut d, &mut s, &mut p, who, t, std::slice::from_ref(&mapping), 6);
    assert_eq!(refused["status"], "REPAIR_REQUIRED");
    assert_eq!(s.root(), before, "unresolved concept creates no mapping or concept");
    assert_eq!(refused["error"]["code"], "UNKNOWN_ENTITY");
    assert_eq!(refused["error"]["expected_by_kernel"]["unresolved_concept"], "scoped topic");
    assert!(refused["error"]["expected_by_kernel"]["repair"].as_str().unwrap().contains("propose_concept BEFORE"));
    assert!(refused["repair"].as_str().unwrap().contains("prerequisites"));
    let proposal = json!({"op":"propose_concept","type":"Component","name":"scoped topic","aliases":[],"basis":[record]});
    let fixed = submit(&mut d, &mut s, &mut p, who, t, &[proposal, mapping], 7);
    assert_eq!(fixed["status"], "CARD_DONE");
    assert_eq!(fixed["accepted"], 2);
    let concepts = s.candidates("scoped topic", 10);
    assert_eq!(concepts.len(), 1);
    assert!(!s.records_of(&concepts[0].id).is_empty(), "the repaired mapping was actually stored");
}

#[test]
fn answer_lease_has_900_seconds_while_read_build_keep_300_and_renewal_is_fixed() {
    use sbgk_core::audit::directives::ResearchQuestion;
    let (_w, mut s) = fresh();
    let mut cfg = dispatcher().cfg;
    cfg.circles.as_mut().unwrap().agent_timeout_ms = 300_000;
    cfg.answer_timeout_ms = Some(900_000);
    let mut d =
        Dispatcher::new(cfg, vec![ResearchQuestion { id: "RQ1".into(), text: "What is known?".into(), about: vec!["topic".into()], ..Default::default() }]);
    let mut p = pool();
    for n in 1..=3 {
        let t = n * 100;
        start_build(&mut d, &mut s, &mut p, t);
        let tasks = build_tasks(&mut d, &mut s, &p, t + 5);
        for (who, task) in tasks {
            assert!([t + 5 + 300_000, t + 6 + 300_000].contains(&task["expires_at_ms"].as_u64().unwrap()));
            submit(&mut d, &mut s, &mut p, &who, &task, &[], t + 6);
        }
        tick(&mut d, &mut s, &p, t + 7);
    }
    let answer = acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Summarize], 1000);
    assert_eq!(answer["kind"], "SUMMARIZE", "{answer}");
    assert_eq!(answer["expires_at_ms"], 901000);
    let task = answer["task_id"].as_str().unwrap();
    assert_eq!(d.renew(task, "w1", 500_000)["expires_at_ms"], 901000);
    assert_eq!(d.renew(task, "w1", 901_000)["status"], "STALE_TASK");
}

/// Circles +1 (the owner, 2026-10-27): the swarm's independent graph builder, a fixed role outside the ring, refines every circle
/// between the swarm's BUILD and the next reading.
#[test]
fn refiner_refines_each_circle_between_build_and_the_next_reading_and_survives_restart() {
    use sbgk_core::audit::builder::Builder;
    let refining = || {
        Dispatcher::new(
            DispatchConfig {
                circles: Some(CircleConfig { wave_sections: 3, readers: vec!["w1".into(), "w2".into(), "w3".into()], agent_timeout_ms: 600_000 }),
                circle_refiner: Some("gb".into()),
                ..Default::default()
            },
            vec![],
        )
    };
    let refiner = || {
        let mut b = Builder::new(BuilderConfig { max_records: 16, ..Default::default() });
        b.records_only = true;
        b
    };
    let (w, mut s) = fresh();
    let (mut d, mut p, mut gb) = (refining(), pool(), refiner());
    start_build(&mut d, &mut s, &mut p, 100);
    for (who, t) in build_tasks(&mut d, &mut s, &p, 105) {
        assert_eq!(submit(&mut d, &mut s, &mut p, &who, &t, &[], 106)["status"], "CARD_DONE");
    }
    assert!(p.caught_up(&s));
    tick(&mut d, &mut s, &p, 107);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "REFINE", "the swarm's BUILD is followed by the refiner");
    assert_eq!(acquire(&mut d, &mut s, &p, "w1", &[TaskKind::Extend], 108)["status"], "WAIT", "no reading while the refiner works");
    let card = gb.next_card(&s).unwrap();
    assert!(!card.records.is_empty());
    let shown = sbgk_core::audit::refine::overlay(&s, &card);
    assert_eq!(shown.as_array().unwrap().len(), card.records.len());
    d.refiner_caught_up = gb.open_card_id().is_none() && gb.cursor() >= s.head();
    tick(&mut d, &mut s, &p, 109);
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "REFINE", "an open refiner card holds the barrier");
    let state = d.circle_status().unwrap();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    (d, p, gb) = (refining(), pool(), refiner());
    d.recover(&s);
    p.recover(&s).unwrap();
    gb.recover(&s);
    tick(&mut d, &mut s, &p, 110);
    let durable = |v: &Value| (v["circle"].clone(), v["circle_phase"].clone(), v["wave"].clone(), v["started_unix_ms"].clone());
    assert_eq!(durable(&d.circle_status().unwrap()), durable(&state), "REFINE survives a restart");
    while let Some(c) = gb.next_card(&s) {
        assert_eq!(gb.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    d.refiner_caught_up = gb.open_card_id().is_none() && gb.cursor() >= s.head();
    assert!(d.refiner_caught_up);
    tick(&mut d, &mut s, &p, 111);
    assert_eq!((d.circle_status().unwrap()["circle_phase"].as_str(), d.circle_status().unwrap()["circle"].as_u64()), (Some("READ"), Some(2)));
}

#[test]
fn refine_budget_lets_the_swarm_go_on_while_the_refiner_keeps_its_cursor() {
    let (_w, mut s) = fresh();
    let mut d = Dispatcher::new(
        DispatchConfig {
            circles: Some(CircleConfig { wave_sections: 3, readers: vec!["w1".into(), "w2".into(), "w3".into()], agent_timeout_ms: 600_000 }),
            circle_refiner: Some("gb".into()),
            refine_budget_ms: Some(1_000),
            ..Default::default()
        },
        vec![],
    );
    let mut p = pool();
    start_build(&mut d, &mut s, &mut p, 100);
    for (who, t) in build_tasks(&mut d, &mut s, &p, 105) {
        assert_eq!(submit(&mut d, &mut s, &mut p, &who, &t, &[], 106)["status"], "CARD_DONE");
    }
    tick(&mut d, &mut s, &p, 107);
    let refine = d.circle_status().unwrap();
    assert_eq!(refine["circle_phase"], "REFINE");
    let started = refine["started_unix_ms"].as_u64().unwrap();
    let caught = p.caught_up(&s);
    d.advance_circles(&mut s, caught, 108, started + 999).unwrap();
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "REFINE", "within the budget the swarm waits for the refiner");
    d.advance_circles(&mut s, caught, 109, started + 1_000).unwrap();
    assert_eq!((d.circle_status().unwrap()["circle_phase"].as_str(), d.circle_status().unwrap()["circle"].as_u64()), (Some("READ"), Some(2)));
}
