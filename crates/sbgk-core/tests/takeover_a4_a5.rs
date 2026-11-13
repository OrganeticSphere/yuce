use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{pairs, AuditStore, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_WAL: AtomicU64 = AtomicU64::new(0);
struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fresh(docs: &[(&str, String)]) -> (Wal, AuditState) {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let w = Wal(std::env::temp_dir().join(format!("pair_fair_{}_{n}_{}.wal", std::process::id(), NEXT_WAL.fetch_add(1, Ordering::Relaxed))));
    let ds = docs.iter().map(|(d, t)| (d.to_string(), t.as_bytes().to_vec())).collect::<Vec<_>>();
    let s = AuditState::create(&w.0, &AuditOntology::base(), &ds, "offline", sha256(b"toy")).unwrap();
    (w, s)
}
fn doc(id: &str, date: &str, refs: &str, body: &str) -> String {
    format!("+++\nreport_id = \"{id}\"\ndate = \"{date}\"\npredecessor_reports = [{refs}]\n+++\n# Facts\n{body}\n")
}
fn seed(s: &mut AuditState, doc: &str, quote: &str, text: &str) -> Vec<RecordId> {
    let r = s.submit_records(
        doc,
        &format!("seed-{doc}-{}", s.head()),
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["topic"]}),
            json!({"kind":"claim","local_id":"c","text":text,"subject":"topic","stance":"reported","based_on":["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    r.accepted
}
#[test]
fn pair_card_and_its_plan_recover_without_advancing_the_record_cursor() {
    let (w, mut s) = fresh(&[
        ("old", doc("old-report", "2026-07-29", "", "FrontendPhase2ReleasePort uses private_port.")),
        ("new", doc("new-report", "2026-08-10", "\"old-report\"", "FrontendPhase2ReleasePort replaces former private_port.")),
    ]);
    let a = seed(&mut s, "old", "FrontendPhase2ReleasePort uses private_port.", "FrontendPhase2ReleasePort uses private_port.");
    let b = seed(&mut s, "new", "FrontendPhase2ReleasePort replaces former private_port.", "FrontendPhase2ReleasePort replaces former private_port.");
    s.add_link("builder", &a[1], "supports", &b[1], &[a[0]]).unwrap();
    let candidates = pairs::detect(&s);
    assert_eq!(candidates.len(), 1);
    assert_eq!((candidates[0].old, candidates[0].new), (a[1], b[1]));
    let mut builder = Builder::new(BuilderConfig { max_links: 1, ..Default::default() });
    while let Some(c) = builder.next_card(&s) {
        assert_eq!(builder.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    let cursor = builder.cursor();
    builder.prepare_pairs(&s, true);
    assert!(!builder.caught_up(&s));
    let card = builder.next_card(&s).unwrap();
    assert_eq!(card.to_json()["kind"], "PAIR_CARD");
    assert_eq!(card.records.len(), 2);
    assert_eq!(card.neighbors.len(), 2);
    // A refused pair answer still persists its catalog, so restarting cannot choose a different pair plan.
    let op = json!({"op":"link","from":b[1].short(),"rel":"supersedes","to":a[1].short(),"basis":[b[0].short()]});
    let bad = json!({"op":"link","from":b[0].short(),"rel":"supersedes","to":a[1].short(),"basis":[b[0].short()]});
    let r = builder.submit(&mut s, &card.card_id, &[bad]);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    let r = builder.submit(&mut s, &card.card_id, &[op.clone(), json!({"op":"map_term"})]);
    assert_eq!(r["status"], "REPAIR_REQUIRED");
    // Reopen before success, then exercise the fresh pair budget beside an earlier card's link.
    assert_eq!(s.links().len(), 1);
    assert_eq!(s.links()[0].status.name(), "proposed");
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut restarted = Builder::new(BuilderConfig { max_links: 1, ..Default::default() });
    restarted.recover(&s);
    restarted.prepare_pairs(&s, true);
    let again = restarted.next_card(&s).unwrap();
    assert_eq!(again.card_id, card.card_id);
    let r = restarted.submit(&mut s, &again.card_id, std::slice::from_ref(&op));
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert_eq!(restarted.cursor(), cursor);
    assert_eq!(s.links().len(), 2);
    let head = s.head();
    let r = restarted.submit(&mut s, &again.card_id, &[op]);
    assert_eq!(r["replayed"], true, "{r}");
    assert_eq!(s.head(), head);
    assert!(restarted.next_card(&s).is_none());
}
#[test]
fn procedural_report_scope_is_guarded_and_an_explicit_quoted_bridge_can_pass() {
    let (_w, mut s) = fresh(&[
        ("old", doc("old-report", "2026-07-29", "", "Exact-head validation is pending for head 9e4b1d73.")),
        (
            "new",
            doc(
                "new-report",
                "2026-08-10",
                "\"old-report\"",
                "Exact-head validation is required for head 2c6e0a85. Unlike old-report, this worktree has a fresh head.",
            ),
        ),
    ]);
    let a = seed(&mut s, "old", "Exact-head validation is pending for head 9e4b1d73.", "Exact-head validation is pending for head 9e4b1d73.");
    let b = seed(&mut s, "new", "Exact-head validation is required for head 2c6e0a85.", "Exact-head validation is required for head 2c6e0a85.");
    assert!(pairs::scope_violation(&s, b[1], "qualifies", a[1], &[a[0], b[0]]).is_some());
    let link = s.add_link("builder", &b[1], "qualifies", &a[1], &[b[0]]).unwrap();
    let mut d = Dispatcher::default();
    let t = d.acquire(&s, "verify", true, 0);
    assert_eq!(t["kind"], "VERIFY_LINK");
    let verdict = |v: &str| json!({"kind":"verdict","link":link.id.short(),"verdict":v,"based_on":[b[0].short()]});
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "verify", &[verdict("confirm")], 1);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["error"]["expected_by_kernel"]["scope_guard"]["rule"], "report_head_scope");
    assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "verify", &[verdict("reject")], 2)["status"], "COMMITTED");
    let bridge = seed(&mut s, "new", "Unlike old-report, this worktree has a fresh head.", "The worktree differs.");
    assert!(pairs::scope_violation(&s, b[1], "qualifies", a[1], &[bridge[0]]).is_none(), "passing a scope guard still does not confirm semantics");
}
#[test]
fn automatic_loss_rereads_are_fair_durable_bounded_and_precede_summary() {
    let docs = (0..3)
        .map(|i| (format!("d{i}"), (0..3).map(|k| format!("# Section {k}\nTopic {i} {k} holds with a separate report-local condition.\n")).collect::<String>()))
        .collect::<Vec<_>>();
    let borrowed = docs.iter().map(|(d, t)| (d.as_str(), t.clone())).collect::<Vec<_>>();
    let (w, mut s) = fresh(&borrowed);
    let mut d = Dispatcher::new(DispatchConfig { section_bytes: 80, ..Default::default() }, vec![]);
    for _ in 0..9 {
        let t = d.acquire(&s, "reader", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        let id = t["task_id"].as_str().unwrap();
        let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap();
        let r =
            d.submit(&mut s, id, "reader", &[json!({"kind":"observe","local_id":"bad","doc_id":doc,"exact_quote":"not in any report","terms":["topic"]})], 1);
        assert_eq!(r["status"], "REPAIR_REQUIRED");
        assert_eq!(d.submit(&mut s, id, "reader", &[], 2)["status"], "COMMITTED");
    }
    d.cfg.auto_reread_limit = 20;
    let mut seen = Vec::new();
    for i in 0..9 {
        if i == 2 {
            drop(s);
            s = AuditState::open(&w.0).unwrap();
            d = Dispatcher::new(DispatchConfig { section_bytes: 80, auto_reread_limit: 20, ..Default::default() }, vec![]);
            d.recover(&s);
        }
        assert!(!d.reading_done(&s));
        let t = d.acquire(&s, "retry", true, 3 + i);
        assert_eq!(t["kind"], "REQUEST", "{t}");
        let key = t["key"].as_str().unwrap().to_string();
        assert!(key.starts_with("reread:"));
        seen.push(key.clone());
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "retry", &[], 3 + i)["status"], "COMMITTED");
        let ck = s.checkpoint(&format!("task:{key}")).unwrap();
        assert_eq!(ck["context"]["origin"]["generation"], 1);
    }
    assert_eq!(
        seen.iter().map(|k| k.split('#').next().unwrap()).collect::<Vec<_>>(),
        ["reread:d0", "reread:d1", "reread:d2", "reread:d0", "reread:d1", "reread:d2", "reread:d0", "reread:d1", "reread:d2"]
    );
    assert!(d.reading_done(&s));
    assert_eq!(d.acquire(&s, "retry", true, 20)["status"], "COMPLETE");
}

#[test]
fn a_negated_parent_heading_still_governs_its_list_items() {
    let doc = "This slice does not authorize:\n- public release;\n- production activation.\n";
    for q in ["public release", "production activation"] {
        assert!(sbgk_core::audit::s0::negation_before(doc, doc.find(q).unwrap(), q).is_some(), "{q}");
    }
}

#[test]
fn a_new_positive_heading_and_unrelated_sentence_do_not_inherit_a_list_prohibition() {
    for doc in ["This does not authorize:\n- release.\nThe next gate passes.", "This does not authorize:\n- release.\nResults:\n- the gate passes."] {
        let q = "passes";
        assert!(sbgk_core::audit::s0::negation_before(doc, doc.find(q).unwrap(), q).is_none(), "{doc}");
    }
}

#[test]
fn evolution_selection_admits_reported_change_markers_without_widening_rq2() {
    let (_w, mut s) = fresh(&[("d", doc("report", "2026-08-10", "", "The former crate_parser is replaced by a scoped seam."))]);
    let records = seed(&mut s, "d", "The former crate_parser is replaced by a scoped seam.", "The former crate_parser is replaced by a scoped seam.");
    let d = Dispatcher::new(
        DispatchConfig::default(),
        vec![
            ResearchQuestion {
                id: "RQ1".into(),
                text: "Evolution".into(),
                about: vec!["stale".into()],
                relations: vec!["supersedes".into()],
                ..Default::default()
            },
            ResearchQuestion { id: "RQ2".into(), text: "Future work".into(), about: vec!["deferred".into()], ..Default::default() },
        ],
    );
    assert!(d.summary_candidates(&s, "RQ1", false).unwrap().1.contains(&records[1]));
    assert!(!d.summary_candidates(&s, "RQ2", false).unwrap().1.contains(&records[1]));
}

#[test]
fn evolution_selection_admits_reported_changelog_words_and_not_plain_reports() {
    // 0.2.1, step A8 (the A2A corpus): a changelog states a change as "removed" or "renamed", and its readers kept the stance
    // `reported`; such a claim answers an evolution question, a report of something else does not, nor a removal its sentence negates
    let lines = [
        "The redundant final field was removed from TaskStatusUpdateEvent.",
        "supportsAuthenticatedExtendedCard was renamed to supportsExtendedAgentCard.",
        "Blocking calls are clarified to return on interrupted states.",
        "No features have been removed under the lifecycle policy yet.",
        "The fallback guidance stays in the specification and is not removed.",
        // a deprecation alone is not taken: on the first control run of 0.2 it made about 50 more claims eligible
        "The kind field of streaming events is deprecated.",
        // the word inside an identifier reports no renaming (Codex's review of e25b4efd, WIN-02)
        "The RenamedOptions message has an optional parameter.",
    ];
    let (_w, mut s) = fresh(&[("d", doc("changelog", "2026-05-28", "", &lines.join("\n")))]);
    let ids: Vec<RecordId> = lines.iter().map(|l| seed(&mut s, "d", l, l)[1]).collect();
    let d = Dispatcher::new(
        DispatchConfig::default(),
        vec![
            ResearchQuestion {
                id: "RQ1".into(),
                text: "Evolution".into(),
                about: vec!["stale".into()],
                relations: vec!["supersedes".into()],
                ..Default::default()
            },
            ResearchQuestion { id: "RQ2".into(), text: "Future work".into(), about: vec!["deferred".into()], ..Default::default() },
        ],
    );
    let rq1 = d.summary_candidates(&s, "RQ1", false).unwrap().1;
    let rq2 = d.summary_candidates(&s, "RQ2", false).unwrap().1;
    for (line, id) in lines.iter().zip(&ids).take(2) {
        assert!(rq1.contains(id), "a change stated as in a changelog answers the evolution question: {line}");
        assert!(!rq2.contains(id), "and only that question: {line}");
    }
    for (line, id) in lines.iter().zip(&ids).skip(2) {
        assert!(!rq1.contains(id), "no change, a negated one, a deprecation alone or an identifier stays out: {line}");
    }
}

#[test]
fn evolution_selection_reads_a_changelog_word_in_the_text_first_then_in_the_subject_predicate_object() {
    // Codex's review of e25b4efd, WIN-01: a claim's object is among its terms, and "is not" and "removed" read apart turned a
    // negated removal into one. The text decides; the triple, read as one sentence, only where the text does not use the word.
    let rows = [
        ("The fallback feature is not removed.", "fallback feature", "is not", "removed", false),
        ("The final field of TaskStatusUpdateEvent is gone.", "final field", "was", "removed", true),
        ("The legacy flow is not removed.", "legacy flow", "was", "removed", false),
    ];
    let body = rows.iter().map(|r| r.0).collect::<Vec<_>>().join("\n");
    let (_w, mut s) = fresh(&[("d", doc("changelog", "2026-05-28", "", &body))]);
    let ids: Vec<RecordId> = rows
        .iter()
        .map(|(text, subject, predicate, object, _)| {
            let r = s.submit_records(
                "reader",
                &format!("triple-{}", s.head()),
                &Scope { docs: vec!["d".into()], ..Default::default() },
                &[
                    json!({"kind":"observe","local_id":"o","doc_id":"d","exact_quote":text}),
                    json!({"kind":"claim","local_id":"c","text":text,"subject":subject,"predicate":predicate,"object":object,
                           "stance":"reported","based_on":["o"]}),
                ],
            );
            assert!(r.error.is_none(), "{:?}", r.error);
            r.accepted[1]
        })
        .collect();
    let d = Dispatcher::new(
        DispatchConfig::default(),
        vec![ResearchQuestion {
            id: "RQ1".into(),
            text: "Evolution".into(),
            about: vec!["stale".into()],
            relations: vec!["supersedes".into()],
            ..Default::default()
        }],
    );
    let rq1 = d.summary_candidates(&s, "RQ1", false).unwrap().1;
    for (row, id) in rows.iter().zip(&ids) {
        assert_eq!(rq1.contains(id), row.4, "{row:?}");
    }
}

#[test]
fn a_report_title_prefix_is_not_an_explicit_scope_bridge() {
    let old = doc("old-report", "2026-07-29", "", "Exact-head validation is pending.").replace("report_id = ", "title = \"Release gate\"\nreport_id = ");
    let new = doc("new-report", "2026-08-10", "\"old-report\"", "Exact-head validation is required. Release gatekeeper worktree is pending.");
    let (_w, mut s) = fresh(&[("old", old), ("new", new)]);
    let a = seed(&mut s, "old", "Exact-head validation is pending.", "Exact-head validation is pending.");
    let b = seed(&mut s, "new", "Release gatekeeper worktree is pending.", "Exact-head validation is required.");
    assert!(pairs::scope_violation(&s, b[1], "qualifies", a[1], &[b[0]]).is_some());
}

#[test]
fn semicolon_does_not_transfer_a_negation_to_the_next_positive_clause() {
    let doc = "The report cannot embed its own final SHA without self-reference;\n  exact final head/tree and no-PR state belong in the handoff.";
    let q = "exact final head/tree and no-PR state belong in the handoff.";
    assert!(sbgk_core::audit::s0::negation_before(doc, doc.find(q).unwrap(), q).is_none());
    let doc = "The first gate passed; the second gate cannot authorize release.";
    assert!(sbgk_core::audit::s0::negation_before(doc, doc.find("authorize").unwrap(), "authorize release").is_some());
}

#[test]
fn second_reading_wave_uses_the_remainder_after_late_primary_reading() {
    let a = (0..3).map(|k| format!("# Section {k}\nTopic a {k} holds with a separate report-local condition.\n")).collect::<String>();
    let b = "# Section 0\nTopic b holds with a separate report-local condition.\n".to_string();
    let (_w, mut s) = fresh(&[("a", a), ("b", b)]);
    let mut d = Dispatcher::new(DispatchConfig { section_bytes: 80, auto_reread_limit: 20, ..Default::default() }, vec![]);
    for k in 0..3 {
        let t = d.acquire(&s, "reader", true, 0);
        assert_eq!(t["key"], format!("doc:a#{k}"));
        let id = t["task_id"].as_str().unwrap();
        let bad = json!({"kind":"observe","local_id":"bad","doc_id":"a","exact_quote":"missing bytes","terms":["topic"]});
        assert_eq!(d.submit(&mut s, id, "reader", &[bad], 1)["status"], "REPAIR_REQUIRED");
        assert_eq!(d.submit(&mut s, id, "reader", &[], 2)["status"], "COMMITTED");
        if k < 2 {
            let t = d.acquire(&s, "rereader", true, 3);
            assert_eq!(t["kind"], "REQUEST");
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "rereader", &[], 4)["status"], "COMMITTED");
        }
    }
    let t = d.acquire(&s, "late-reader", true, 5);
    assert_eq!(t["key"], "doc:b#0", "a cannot consume a third slot before late b is read: {t}");
    assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "late-reader", &[], 6)["status"], "COMMITTED");
    let t = d.acquire(&s, "rereader", true, 7);
    assert_eq!(t["key"], "reread:a#2", "the first wave is a reservation, not a permanent loss: {t}");
}

#[test]
fn change_marker_join_does_not_drop_plain_language_claims_beside_metadata_matches() {
    let oldmain = "The actual frontend port is test-only; no runtime dependency or product adapter is selected.";
    let newmain = "The former direct acme_frontend dependency was replaced by CapabilityPhase2ReleasePort.";
    let meta = "Verdict not_applicable and supersedes list empty.";
    let (_w, mut s) = fresh(&[
        ("old", doc("old-report", "2026-07-29", "", &format!("{oldmain}\n{meta}\nCurrent focused checks overrode stale ownership."))),
        ("new", doc("new-report", "2026-08-10", "\"old-report\"", &format!("{newmain}\n{meta}\nFocused runs replaced a stale digest."))),
    ]);
    let a = seed(&mut s, "old", oldmain, oldmain);
    seed(&mut s, "old", meta, meta);
    let b = seed(&mut s, "new", newmain, newmain);
    seed(&mut s, "new", meta, meta);
    let old_noise = seed(&mut s, "old", "Current focused checks overrode stale ownership.", "Current focused checks overrode stale ownership.");
    let new_noise = seed(&mut s, "new", "Focused runs replaced a stale digest.", "Focused runs replaced a stale digest.");
    let pairs = pairs::detect(&s);
    assert!(pairs.iter().any(|p| p.old == a[1] && p.new == b[1]), "plain words in a referenced report still participate in a change-marker join");
    assert!(!pairs.iter().any(|p| p.old == old_noise[1] && p.new == new_noise[1]), "a shared change marker is not a second entity anchor");
    assert!(!pairs.iter().any(|p| p.old == a[1] && p.new != b[1]), "an unrelated metadata match is not a reason to pair every old claim");
}

#[test]
fn plain_entity_and_compound_identifier_meet_despite_repeated_test_outcomes() {
    let a = "The actual frontend port is test-only; no runtime dependency is selected.";
    let b = "The former direct dependency was replaced by FrontendPhase2ReleasePort.";
    let old_noise = "The test passed after a failed test.";
    let new_noise = "The failed test was replaced and the test passed.";
    let (_w, mut s) = fresh(&[
        ("old", doc("old-report", "2026-07-29", "", &format!("{a}\n{old_noise}"))),
        ("new", doc("new-report", "2026-08-10", "\"old-report\"", &format!("{b}\n{new_noise}"))),
    ]);
    let old = seed(&mut s, "old", a, a);
    let new = seed(&mut s, "new", b, b);
    for _ in 0..4 {
        seed(&mut s, "old", old_noise, old_noise);
        seed(&mut s, "new", new_noise, new_noise);
    }
    let pairs = pairs::detect(&s);
    assert!(
        pairs.iter().any(|p| p.old == old[1] && p.new == new[1]),
        "plain frontend/port and the compound code name identify a retrieval subject before repeated pass/fail outcomes"
    );
    assert!(pairs.len() <= pairs::MAX_PAIR_CARDS);
}
