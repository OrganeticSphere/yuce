//! Regressions from the live model runs of the A/C pilot (2026-10-22), on the durable store: what a real model did that the
//! deterministic stand-ins never did.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::json;
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh(tag: &str) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_live_regr_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), b"# First\nTopic A is reported.\n".to_vec()), ("d2".to_string(), b"# Second\nTopic B is reported.\n".to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "live-regressions", sha256(b"toy")).unwrap();
    (wal, state)
}

fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig { section_bytes: 400, ..Default::default() },
        vec![ResearchQuestion {
            id: "RQ1".into(),
            text: "What do the reports establish about the topic?".into(),
            about: vec!["topic".into()],
            ..Default::default()
        }],
    )
}

#[test]
fn a_repair_that_resends_its_accepted_lines_is_not_refused_as_a_duplicate() {
    let (_wal, mut state) = fresh("resend");
    let mut d = dispatcher();
    let t = d.acquire(&state, "w1", true, 1);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap());
    let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
    let quote = if doc == "d1" { "Topic A is reported." } else { "Topic B is reported." };
    let observe = json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": quote, "terms": ["topic"]});
    let claim = |text: String| json!({"kind": "claim", "local_id": format!("{p}c1"), "text": text, "subject": "topic", "stance": "reported", "based_on": [format!("{p}o1")]});
    let failed = d.submit(&mut state, task, "w1", &[observe.clone(), claim("x".repeat(241))], 2);
    assert_eq!((failed["status"].as_str(), failed["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{failed}");
    // the model repairs the claim but sends its accepted observation again, byte for byte
    let repaired = d.submit(&mut state, task, "w1", &[observe, claim(quote.to_string())], 3);
    assert_eq!(repaired["status"], "COMMITTED", "an exact resend of an accepted line is a no-op: {repaired}");
    assert_eq!(state.records_since(0).len(), 2, "the observation is stored once");
}

#[test]
fn a_check_that_keeps_failing_is_given_up_as_unresolved_instead_of_looping() {
    let (_wal, mut state) = fresh("unresolved");
    let mut seed = |actor: &str, doc: &str, quote: &str| {
        let r = state.submit_records(
            actor,
            &format!("seed-{actor}"),
            &Scope { docs: vec![doc.into()], ..Default::default() },
            &[
                json!({"kind": "observe", "local_id": "o", "doc_id": doc, "exact_quote": quote, "terms": ["topic"]}),
                json!({"kind": "claim", "local_id": "c", "text": quote, "subject": "topic", "stance": "reported", "based_on": ["o"]}),
            ],
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        r.accepted[1]
    };
    let (a, b) = (seed("author-a", "d1", "Topic A is reported."), seed("author-b", "d2", "Topic B is reported."));
    let link = state.add_link("builder", &a, "supports", &b, &[a]).unwrap().id;
    let mut d = dispatcher();
    for round in 0..3 {
        let t = d.acquire(&state, "verifier", true, 10 + round);
        assert_eq!(t["kind"], "VERIFY_LINK", "round {round}: {t}");
        let task = t["task_id"].as_str().unwrap();
        // a verdict the dispatcher refuses (it names another link), then the agent gives the lease back
        let r = d.submit(
            &mut state,
            task,
            "verifier",
            &[json!({"kind": "verdict", "link": "@0000000000000000", "verdict": "confirm", "based_on": [a.short()]})],
            20,
        );
        assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
        d.release(task, "verifier");
    }
    let next = d.acquire(&state, "verifier", true, 30);
    assert_ne!(next["kind"], "VERIFY_LINK", "the failed check is not issued a fourth time: {next}");
    let unresolved = d.completion(&state, true)["unresolved"].clone();
    assert_eq!(unresolved, json!([format!("verify:{}", link.short())]), "and it is reported");
}

/// The store with a seeded claim about the topic (shown to a summary) and every section covered, so the next task is SUMMARIZE.
fn ready_for_summary(state: &mut AuditState, d: &mut Dispatcher) -> RecordId {
    let r = state.submit_records(
        "reader",
        "seed",
        &Scope { docs: vec!["d1".into()], ..Default::default() },
        &[
            json!({"kind": "observe", "local_id": "o", "doc_id": "d1", "exact_quote": "Topic A is reported.", "terms": ["topic"]}),
            json!({"kind": "claim", "local_id": "c", "text": "Topic A is reported.", "subject": "topic", "stance": "reported", "based_on": ["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    for now in 0..4 {
        let t = d.acquire(state, "w1", true, now);
        if t["kind"] != "EXTEND" {
            d.release(t["task_id"].as_str().unwrap(), "w1");
            break;
        }
        assert_eq!(d.submit(state, t["task_id"].as_str().unwrap(), "w1", &[], now)["status"], "COMMITTED");
    }
    r.accepted[0]
}

#[test]
fn an_exact_resend_of_an_accepted_done_line_commits_instead_of_panicking() {
    let (_wal, mut state) = fresh("done-resend");
    let mut d = dispatcher();
    let observe = ready_for_summary(&mut state, &mut d);
    let t = d.acquire(&state, "sum", true, 10);
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap());
    let done =
        json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": task, "outcome": "answered", "answer_ids": [format!("{p}c1")]});
    let first = d.submit(
        &mut state,
        task,
        "sum",
        &[
            json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "Topic A is reported.", "subject": "topic", "stance": "reported", "based_on": [observe.short()]}),
            done.clone(),
            // refused by the store after the done line was accepted (a long text is now refused before anything is stored)
            json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "Topic B is reported.", "subject": "topic", "stance": "reported", "based_on": ["@0000000000000000"]}),
        ],
        11,
    );
    // item by item since the consilium of 10A-17: the done line waits while a line of the summary is refused, so it is the first line
    // not stored; sent again alone it commits
    assert_eq!((first["status"].as_str(), first["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{first}");
    let again = d.submit(&mut state, task, "sum", &[done], 12);
    assert_eq!(again["status"], "COMMITTED", "the accepted done is found by its local id: {again}");
    assert_eq!(d.completion(&state, true)["answered"], 1);
}

#[test]
fn a_question_given_up_after_failed_summaries_ends_as_not_answered_also_after_a_restart() {
    let (wal, mut state) = fresh("rq-given-up");
    let mut d = dispatcher();
    ready_for_summary(&mut state, &mut d);
    for round in 0..3 {
        let t = d.acquire(&state, "sum", true, 20 + round);
        assert_eq!(t["kind"], "SUMMARIZE", "round {round}: {t}");
        let task = t["task_id"].as_str().unwrap();
        let wrong = json!({"kind": "done", "local_id": "x", "rq_id": "RQ9", "directive_id": task, "outcome": "unknown", "answer_ids": []});
        assert_eq!(d.submit(&mut state, task, "sum", &[wrong], 30)["status"], "REPAIR_REQUIRED");
        d.release_durable(&mut state, task, "sum");
    }
    assert_eq!(d.acquire(&state, "sum", true, 40)["status"], "COMPLETE", "the run ends instead of waiting forever");
    let receipt = d.terminal_receipt(&state, state.head(), "live-regressions").expect("complete");
    assert_eq!(receipt["outcomes"]["RQ1"]["outcome"], "not_answered", "a processing failure, not an unknown (Codex review c78060e, F05)");
    assert_eq!(receipt["outcomes"]["RQ1"]["unresolved"], true);
    drop(state);
    let state = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher();
    recovered.recover(&state);
    assert_eq!(recovered.acquire(&state, "sum", true, 50)["status"], "COMPLETE", "the give-up survives a restart");
}

#[test]
fn a_question_raised_while_investigating_stays_a_follow_up_after_a_restart() {
    let (wal, mut state) = fresh("follow-up");
    let q = json!({"kind": "question", "local_id": "q", "text": "is topic A still reported?", "about": ["topic"], "needed": "d2"});
    assert!(state.submit_records("reader", "seed", &Scope { docs: vec!["d1".into()], ..Default::default() }, &[q]).error.is_none());
    let mut d = dispatcher();
    // variant D: every section is read before the question is investigated
    let t = loop {
        let t = d.acquire(&state, "inv", true, 1);
        if t["kind"] != "EXTEND" {
            break t;
        }
        assert_eq!(d.submit(&mut state, t["task_id"].as_str().unwrap(), "inv", &[], 1)["status"], "COMMITTED");
    };
    assert_eq!(t["kind"], "INVESTIGATE", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap());
    let follow = json!({"kind": "question", "local_id": format!("{p}q1"), "text": "and topic B?", "about": ["topic"], "needed": "d2"});
    let bad = json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "x".repeat(241), "subject": "topic", "stance": "reported", "based_on": []});
    assert_eq!(d.submit(&mut state, task, "inv", &[follow, bad], 2)["status"], "REPAIR_REQUIRED", "the follow-up question is stored, the task is not complete");
    d.release(task, "inv");
    drop(state);
    let state = AuditState::open(&wal.0).unwrap();
    let mut recovered = dispatcher();
    recovered.recover(&state);
    for now in 3..8 {
        let t = recovered.acquire(&state, "w", true, now);
        assert!(!(t["kind"] == "INVESTIGATE" && !t["key"].as_str().unwrap().ends_with(&state.records_since(0)[0].id.short())), "a follow-up was issued: {t}");
        if let Some(task) = t["task_id"].as_str() {
            recovered.release(task, "w");
        }
    }
}

#[test]
fn what_a_link_check_records_is_not_material_for_the_graph_builder() {
    // live run 10A: link checks wrote 70% of the records; the builder linked them in turn and never caught up
    let (_wal, mut state) = fresh("link-evidence");
    let mut seed = |actor: &str, doc: &str, quote: &str| {
        let r = state.submit_records(
            actor,
            &format!("seed-{actor}"),
            &Scope { docs: vec![doc.into()], ..Default::default() },
            &[
                json!({"kind": "observe", "local_id": "o", "doc_id": doc, "exact_quote": quote, "terms": ["topic"]}),
                json!({"kind": "claim", "local_id": "c", "text": quote, "subject": "topic", "stance": "reported", "based_on": ["o"]}),
            ],
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        r.accepted[1]
    };
    let (a, b) = (seed("author-a", "d1", "Topic A is reported."), seed("author-b", "d2", "Topic B is reported."));
    let mut builder = Builder::new(BuilderConfig::default());
    let first = builder.next_card(&state).unwrap();
    assert_eq!(first.records.len(), 4);
    assert_eq!(builder.submit(&mut state, &first.card_id, &[])["status"], "CARD_DONE");
    state.add_link("builder", &a, "supports", &b, &[a]).unwrap();
    let mut d = dispatcher();
    let t = d.acquire(&state, "verifier", true, 1);
    assert_eq!(t["kind"], "VERIFY_LINK", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap());
    assert!(task.starts_with("TV"), "a link task says so in its id: {task}");
    let observe = json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "d1", "exact_quote": "Topic A is reported.", "terms": ["topic"]});
    let link = t["key"].as_str().unwrap().trim_start_matches("verify:").to_string();
    let verdict = json!({"kind": "verdict", "link": link, "verdict": "confirm", "based_on": [format!("{p}o1")]});
    assert_eq!(d.submit(&mut state, task, "verifier", &[observe, verdict], 2)["status"], "COMMITTED");
    let next = builder.next_card(&state).unwrap();
    assert!(next.records.is_empty(), "the check's evidence is not shown to the builder: {:?}", next.records);
    assert_eq!(next.cursor_to, state.head(), "but the card covers it, so the cursor moves on");
    assert_eq!(builder.submit(&mut state, &next.card_id, &[])["status"], "CARD_DONE");
    assert!(builder.caught_up(&state));
}

#[test]
fn a_summary_is_checked_whole_before_anything_is_stored() {
    // live run 10A-3: a 248-character claim and a 906-character done text were refused one at a time after a partial acceptance;
    // the model, repairing a suffix, resent accepted lines changed and the answer was lost; 43 lines were read as "40 accepted"
    let (_wal, mut state) = fresh("summary-whole");
    let mut d = dispatcher();
    let observe = ready_for_summary(&mut state, &mut d);
    let t = d.acquire(&state, "sum", true, 10);
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap(), t["local_id_prefix"].as_str().unwrap());
    let before = state.head();
    let claim = |n: usize, text: String, based: Vec<String>| json!({"kind": "claim", "local_id": format!("{p}c{n}"), "text": text, "subject": "topic", "stance": "reported", "based_on": based});
    let done = |text: String| json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": task, "outcome": "answered", "answer_ids": [format!("{p}c1")], "text": text});
    // one line over the summary bound (48 since live run 10A-4)
    let too_many: Vec<_> = (0..49).map(|n| claim(n, "Topic A is reported.".into(), vec![observe.short()])).collect();
    let r = d.submit(&mut state, task, "sum", &too_many, 11);
    assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(0)), "nothing was accepted: {r}");
    let bad = [
        claim(1, "Topic A is reported.".into(), vec![observe.short()]),
        claim(2, "x".repeat(248), vec![observe.short()]),
        claim(3, "Not settled.".into(), vec![]),
        done("y".repeat(300)),
    ];
    // item by item since the consilium of 10A-17 (Gemini's plan step 1): the valid claim is stored, each refused line is named with
    // its own problem, the done line with its own and it waits for the others
    let r = d.submit(&mut state, task, "sum", &bad, 12);
    assert_eq!(
        (r["status"].as_str(), r["failed_index"].as_u64(), r["repair_scope"].as_str()),
        (Some("REPAIR_REQUIRED"), Some(1), Some("rejected_items_only")),
        "{r}"
    );
    let refused = r["refused"].as_array().unwrap();
    assert_eq!(refused.iter().map(|x| x["index"].as_u64().unwrap()).collect::<Vec<_>>(), vec![1, 2, 3], "every problem at once: {r}");
    // live run 10A-14: told only "1..240 characters", the model resent claims of 243..246 characters unchanged five times
    let chars = |n: usize| refused[n]["error"]["expected_by_kernel"]["characters"].as_u64();
    assert_eq!((chars(0), chars(2)), (Some(248), Some(300)), "{r}");
    assert!(refused[0]["error"]["message"].as_str().unwrap().ends_with("this one has 248: shorten it by at least 8"), "{r}");
    assert!(chars(1).is_none(), "a missing quote is no length problem: {r}");
    assert_eq!(state.head(), before + 1, "the valid claim is stored, nothing else");
    let good = [claim(1, "Topic A is reported.".into(), vec![observe.short()]), done("The other reports are not covered.".into())];
    assert_eq!(d.submit(&mut state, task, "sum", &good, 13)["status"], "COMMITTED");
    // an accepted answer is there for an export before the run is terminal, marked partial (Codex's analysis of 10A-4, F01)
    let held = d.accepted_outcomes(&state);
    assert_eq!((held["RQ1"]["outcome"].as_str(), held["RQ1"]["partial"].as_bool()), (Some("answered"), Some(true)), "{held}");
    assert_eq!(held["RQ1"]["answer_ids"].as_array().map(Vec::len), Some(1), "{held}");
}
