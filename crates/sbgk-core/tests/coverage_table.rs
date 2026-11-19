//! The coverage table (0.2.1) on journals the kernel writes: what each unit came to, drawn from the journal alone; its totals are
//! the report of the gap pass; a withdrawal changes it; the index carries it at every prefix; a journal that pins no sections gives
//! none and says why. No provider or runner calls.
use sbgk_core::audit::directives::{coverage, DispatchConfig, Dispatcher, GapProfile, ResearchQuestion};
use sbgk_core::audit::index;
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const LOG: &str = "# Changes\n\n1. Remove batching support.\n2. Add tool titles.\n3. Clarify the error text.\n4. Remove sessions.\n5. Add icons.\n\n# Notes\n\nA client MUST retry.\n\nAnother plain note.\n";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn wal(name: &str) -> Wal {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Wal(std::env::temp_dir().join(format!("coverage_{name}_{}_{nonce}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
}

fn gap() -> GapProfile {
    GapProfile { limit: 2, units_per_task: 4, ..Default::default() }
}

/// A journal of one document whose run pins `settings` as `audit-serve` pins them, when it pins any.
fn journal(name: &str, settings: Option<Value>) -> (Wal, AuditState) {
    let path = wal(name);
    let mut s = AuditState::create(&path.0, &AuditOntology::base(), &[("log.md".to_string(), LOG.as_bytes().to_vec())], "coverage-run", sha256(b"m")).unwrap();
    if let Some(context) = settings {
        let pinned = json!({"key": "audit:mcp:coverage", "from": 0, "to": 0, "context": context});
        let r = s.submit_operations_id("audit-mcp-coverage-config", "kernel", &[], Some(pinned)).unwrap();
        assert!(r["error"].is_null(), "{r}");
    }
    (path, s)
}

fn settings() -> Value {
    json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": 6000, "section_rule": 2, "gap_pass": gap().settings()})
}

fn dispatcher() -> Dispatcher {
    let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
    Dispatcher::new(DispatchConfig { gap: gap(), ..Default::default() }, vec![q])
}

fn observe(prefix: &str, n: usize, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": format!("{prefix}o{n}"), "doc_id": "log.md", "exact_quote": quote, "terms": ["change"]})
}

/// Answers the task `t` with a quote of each of `quotes` its prompt shows.
fn answer(d: &mut Dispatcher, s: &mut AuditState, t: &Value, agent: &str, quotes: &[&str]) {
    let (prefix, prompt) = (t["local_id_prefix"].as_str().unwrap(), t["prompt"].as_str().unwrap());
    let lines: Vec<Value> = quotes.iter().filter(|q| prompt.contains(**q)).enumerate().map(|(n, q)| observe(prefix, n, q)).collect();
    assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), agent, &lines, 0)["status"], "COMMITTED", "{t}");
}

/// The units of LOG with their status, in byte order.
fn statuses(s: &AuditState) -> Vec<(String, String)> {
    let at = |v: &Value| v.as_u64().unwrap() as usize;
    coverage(s).units.iter().map(|r| (LOG[at(&r[1])..at(&r[2])].to_string(), r[5].as_str().unwrap().to_string())).collect()
}

fn with_status<'a>(units: &'a [(String, String)], status: &str) -> Vec<&'a str> {
    units.iter().filter(|(_, st)| st == status).map(|(text, _)| text.as_str()).collect()
}

/// The first readings, then the two packs of the gap pass: the first quotes one of its four units, the second answers empty.
/// Returns the number of frames before the pass began.
fn read_and_pass(d: &mut Dispatcher, s: &mut AuditState) -> usize {
    let mut t = d.acquire(s, "w1", true, 0);
    while t["kind"] == "EXTEND" {
        answer(d, s, &t, "w1", &["3. Clarify the error text."]);
        t = d.acquire(s, "w1", true, 0);
    }
    let before = s.entries().unwrap();
    assert_eq!(t["kind"], "REQUEST", "{t}");
    answer(d, s, &t, "w1", &["1. Remove batching support."]);
    let t = d.acquire(s, "w1", true, 0);
    assert_eq!(t["kind"], "REQUEST", "{t}");
    answer(d, s, &t, "w1", &[]);
    before
}

#[test]
fn the_table_is_drawn_from_the_journal_alone_and_its_totals_are_the_report_of_the_pass() {
    let (path, mut s) = journal("totals", Some(settings()));
    let mut d = dispatcher();
    assert!(statuses(&s).iter().all(|(_, st)| st == "unread"), "nothing is read yet");
    let before = read_and_pass(&mut d, &mut s);
    let units = statuses(&s);
    assert_eq!(with_status(&units, "quoted"), ["1. Remove batching support.", "3. Clarify the error text."]);
    assert_eq!(with_status(&units, "empty"), ["2. Add tool titles.", "4. Remove sessions.", "5. Add icons.", "A client MUST retry.", "Another plain note."]);
    let table = coverage(&s);
    assert_eq!((table.section_bytes, table.gap_pass.clone(), table.packs.len()), (Some(6000), Some(gap().settings()), 2));
    assert_eq!(table.summary, d.gap_pass_report(&s), "the totals of the table are the report of the pass");
    assert_eq!((&table.summary["units_read"], &table.summary["units_quoted"], &table.summary["gap_empty"]), (&json!(7), &json!(2), &json!(1)));
    // no first reading was given up: the totals are those of 0.2.2, without the field that would count such units
    assert!(table.summary.get("units_reading_given_up").is_none(), "{}", table.summary);
    // a dispatcher recovered on the journal, as after a restart, gives the same report: nothing of the table lives outside the journal
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    let mut recovered = dispatcher();
    recovered.recover(&s);
    assert_eq!(coverage(&s).summary, recovered.gap_pass_report(&s));
    assert_eq!(coverage(&s).units, table.units);
    // the index carries the two tables as they are, and at a prefix the table of that prefix: before the pass the gaps were not asked about
    drop(s);
    let rows = index::rows(&path.0).unwrap();
    assert_eq!((&rows.tables[6], &rows.tables[7], &rows.coverage_unavailable), (&table.units, &table.packs, &None));
    let earlier = index::rows_at(&path.0, Some(before)).unwrap();
    let then: Vec<&str> = earlier.tables[6].iter().map(|r| r[5].as_str().unwrap()).collect();
    assert_eq!(then.iter().filter(|st| **st == "left_by_budget").count(), 6, "{then:?}");
    assert!(earlier.tables[7].is_empty());
    assert_ne!(index::index_hash(&earlier.tables), index::index_hash(&rows.tables));
}

#[test]
fn a_withdrawal_changes_what_a_unit_came_to() {
    let (_path, mut s) = journal("withdrawn", Some(settings()));
    let mut d = dispatcher();
    read_and_pass(&mut d, &mut s);
    // the quoted text of a unit is withdrawn: its quote goes, and the unit is under withdrawn text, not a gap again
    assert!(s.withdraw_text("owner", "log.md", "3. Clarify the error text.").unwrap() >= 1);
    let units = statuses(&s);
    assert_eq!(with_status(&units, "withdrawn"), ["3. Clarify the error text."]);
    assert_eq!(with_status(&units, "quoted"), ["1. Remove batching support."]);
    let table = coverage(&s);
    assert_eq!(table.summary, d.gap_pass_report(&s));
    assert_eq!((&table.summary["units_read"], &table.summary["units_quoted"], &table.summary["gap_units"]), (&json!(7), &json!(1), &json!(5)));
    // the text of a unit that was answered empty is withdrawn too: no gap is left there
    assert!(s.withdraw_text("owner", "log.md", "Another plain note.").unwrap() == 0, "no quote stood on it");
    let units = statuses(&s);
    assert_eq!(with_status(&units, "withdrawn"), ["3. Clarify the error text.", "Another plain note."]);
    assert_eq!(coverage(&s).summary, d.gap_pass_report(&s));
}

#[test]
fn a_run_without_a_gap_pass_gives_the_units_and_no_packs() {
    let (path, mut s) = journal("nopass", Some(json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": 6000, "section_rule": 2})));
    let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![q]);
    let mut t = d.acquire(&s, "w1", true, 0);
    while t["kind"] == "EXTEND" {
        answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
        t = d.acquire(&s, "w1", true, 0);
    }
    let table = coverage(&s);
    assert_eq!((table.unavailable.clone(), table.gap_pass.clone(), table.packs.len()), (None, None, 0));
    let units = statuses(&s);
    assert_eq!((with_status(&units, "quoted").len(), with_status(&units, "left_by_budget").len()), (1, 6));
    assert_eq!((&table.summary["gap_pass"], &table.summary["units_read"], &table.summary["gap_units"]), (&json!(false), &json!(7), &json!(6)));
    drop(s);
    assert_eq!(index::rows(&path.0).unwrap().tables[6].len(), 7);
}

#[test]
fn a_journal_that_pins_no_sections_or_another_rule_of_them_gives_no_table_and_says_why() {
    // started by the library alone: no section size is pinned
    let (path, s) = journal("unpinned", None);
    let table = coverage(&s);
    assert!(table.unavailable.as_deref().is_some_and(|r| r.contains("pins no section size")), "{:?}", table.unavailable);
    assert!(table.units.is_empty() && table.packs.is_empty() && table.summary.is_null());
    drop(s);
    let rows = index::rows(&path.0).unwrap();
    assert!(rows.tables[6].is_empty() && rows.tables[7].is_empty());
    assert!(rows.coverage_unavailable.is_some());
    // a run of 0.1: its sections were cut by the earlier rule, and its coverage settings name no rule
    let (_path, s) = journal("rule1", Some(json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": 6000})));
    assert!(coverage(&s).unavailable.as_deref().is_some_and(|r| r.contains("earlier rule")));
}

/// The size that cuts LOG into two sections: the list of changes, and the notes.
const TWO_SECTIONS: usize = 128;

fn question() -> ResearchQuestion {
    ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() }
}

/// Hands in, for the reading task `t`, a quote the text does not hold: the line is refused and the lease fails; its release is
/// a failed attempt. Returns what the release says.
fn fail(d: &mut Dispatcher, s: &mut AuditState, t: &Value, agent: &str) -> Value {
    let id = t["task_id"].as_str().unwrap();
    let r = d.submit(s, id, agent, &[observe(t["local_id_prefix"].as_str().unwrap(), 0, "A client MAY retry.")], 0);
    assert_ne!(r["status"], "COMMITTED", "{r}");
    d.release_durable(s, id, agent)
}

/// The reading tasks of LOG, in two sections: the reader of the notes fails every attempt, until `agents` have failed it, the
/// other quotes "3. Clarify the error text.". Returns the first task that is no reading task.
fn read_failing_the_notes(d: &mut Dispatcher, s: &mut AuditState, agents: &[&str]) -> Value {
    let (mut keys, mut failed) = (BTreeSet::new(), 0);
    loop {
        let agent = agents[failed.min(agents.len() - 1)];
        let t = d.acquire(s, agent, true, 0);
        if t["kind"] != "EXTEND" {
            assert_eq!(keys.len(), 2, "two sections: {keys:?}");
            assert_eq!(failed, agents.len(), "every agent failed the notes once");
            return t;
        }
        keys.insert(t["key"].as_str().unwrap().to_string());
        if t["prompt"].as_str().unwrap().contains("A client MUST retry.") {
            let r = fail(d, s, &t, agent);
            failed += 1;
            assert_eq!(r["unresolved"] == true, failed == agents.len(), "given up after the last attempt only: {r}");
        } else {
            answer(d, s, &t, agent, &["3. Clarify the error text."]);
        }
    }
}

/// A first reading given up is no reading (the dispatch table check of 18.11.2026: the units of a section whose reading was given
/// up came out `left_by_budget`, or `empty` under a pack of the gap pass, all counted as read). Here the run's bound is one
/// attempt and the reader of the notes hands in a quote the text does not hold: the section is given up, unresolved. The gap pass
/// still spans its units with a pack, as it did; that pack quotes one of them, which is then `quoted`, and the other stays
/// `reading_given_up`, with the pack named. The units read leave both out, the coverage is not complete and says why; the report of
/// the pass says the same, also after a restart, and the index carries the rows.
#[test]
fn the_units_of_a_section_whose_first_reading_was_given_up_are_not_read() {
    let profile = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": TWO_SECTIONS, "section_rule": 2, "agent_attempts": 1,
                         "gap_pass": gap().settings()});
    let (path, mut s) = journal("given-up", Some(profile));
    let config = || DispatchConfig { gap: gap(), section_bytes: TWO_SECTIONS, agent_attempts: Some(1), ..Default::default() };
    let mut d = Dispatcher::new(config(), vec![question()]);
    let mut t = read_failing_the_notes(&mut d, &mut s, &["w1"]);
    // the two packs of the pass: the list of changes, answered empty, and the notes, where the reader of the pack quotes one unit
    while t["kind"] == "REQUEST" {
        let agent = t["agent_id"].as_str().unwrap().to_string();
        answer(&mut d, &mut s, &t, &agent, &["A client MUST retry."]);
        t = d.acquire(&s, &agent, true, 0);
    }
    let table = coverage(&s);
    assert_eq!(table.packs.len(), 2, "{:?}", table.packs);
    let units = statuses(&s);
    assert_eq!(with_status(&units, "quoted"), ["3. Clarify the error text.", "A client MUST retry."]);
    assert_eq!(with_status(&units, "empty"), ["1. Remove batching support.", "2. Add tool titles.", "4. Remove sessions.", "5. Add icons."]);
    assert_eq!(with_status(&units, "reading_given_up"), ["Another plain note."]);
    let row = table.units.iter().find(|r| r[5] == "reading_given_up").unwrap();
    assert!(row[7].as_str().is_some_and(|p| p.starts_with("gap:log.md@")), "the pack that spans it is named: {row:?}");
    let sum = &table.summary;
    assert_eq!(
        (&sum["units_read"], &sum["units_quoted"], &sum["gap_units"], &sum["units_reading_given_up"]),
        (&json!(6), &json!(2), &json!(4), &json!(1)),
        "{sum}"
    );
    assert_eq!(sum["complete"], false, "{sum}");
    assert!(
        sum["meaning"]
            .as_str()
            .unwrap()
            .ends_with("1 more units lie in sections whose reading was given up with nothing recorded, and are not counted as read"),
        "{sum}"
    );
    assert_eq!(&d.gap_pass_report(&s), sum, "the report of the pass says the same");
    // after a restart: the journal gives the same table and a recovered dispatcher the same report
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    let mut recovered = Dispatcher::new(config(), vec![question()]);
    recovered.recover(&s);
    assert_eq!((coverage(&s).units, recovered.gap_pass_report(&s)), (table.units.clone(), sum.clone()));
    drop(s);
    assert_eq!(index::rows(&path.0).unwrap().tables[6], table.units, "the index carries the rows");
}

/// Without a gap pass and without a bound of attempts pinned, a first reading is given up after three failed leases and closed
/// unresolved by its checkpoint: its units are `reading_given_up`, not `left_by_budget`, and the totals name them.
#[test]
fn without_a_gap_pass_a_given_up_first_reading_is_not_left_by_the_budget() {
    let profile = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": TWO_SECTIONS, "section_rule": 2});
    let (path, mut s) = journal("given-up-nopass", Some(profile));
    let config = || DispatchConfig { section_bytes: TWO_SECTIONS, ..Default::default() };
    let mut d = Dispatcher::new(config(), vec![question()]);
    read_failing_the_notes(&mut d, &mut s, &["w1", "w2", "w3"]);
    let units = statuses(&s);
    assert_eq!(with_status(&units, "reading_given_up"), ["A client MUST retry.", "Another plain note."]);
    assert_eq!((with_status(&units, "quoted").len(), with_status(&units, "left_by_budget").len()), (1, 4));
    let sum = coverage(&s).summary;
    assert_eq!(
        (&sum["gap_pass"], &sum["units_read"], &sum["gap_units"], &sum["units_reading_given_up"]),
        (&json!(false), &json!(5), &json!(4), &json!(2)),
        "{sum}"
    );
    assert!(
        sum["meaning"]
            .as_str()
            .unwrap()
            .ends_with("; 2 more units lie in sections whose reading was given up with nothing recorded, and are not counted as read"),
        "{sum}"
    );
    // a dispatcher recovered on the journal counts the same
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    let mut recovered = Dispatcher::new(config(), vec![question()]);
    recovered.recover(&s);
    let report = recovered.gap_pass_report(&s);
    for key in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
        assert_eq!(report[key], sum[key], "{key}: {report}");
    }
}

/// What the two recorded runs of the check held (Co_r1b and Co_r2 of the Tobi rerun): a first reading closed by an answer abandoned
/// after refused ones (`abandoned` in its checkpoint, the reading closed as done) with nothing stored. A loss reread of the section
/// follows. When the reread records nothing, the section's units are `reading_given_up`; when it records something, it read the
/// section: the quoted unit is `quoted` and the other is read with no quote, as before.
#[test]
fn a_reading_abandoned_after_refusals_is_given_up_unless_its_reread_records_something() {
    for reread_records in [false, true] {
        let profile = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": TWO_SECTIONS, "section_rule": 2});
        let (path, mut s) = journal(if reread_records { "abandoned-reread" } else { "abandoned" }, Some(profile));
        let config = || DispatchConfig { section_bytes: TWO_SECTIONS, auto_reread_limit: 1, ..Default::default() };
        let mut d = Dispatcher::new(config(), vec![question()]);
        let mut t = d.acquire(&s, "w1", true, 0);
        while t["kind"] == "EXTEND" {
            if t["prompt"].as_str().unwrap().contains("A client MUST retry.") {
                // a refused answer, then an empty one that closes the reading: abandoned, with nothing stored
                let id = t["task_id"].as_str().unwrap();
                let refused = d.submit(&mut s, id, "w1", &[observe(t["local_id_prefix"].as_str().unwrap(), 0, "A client MAY retry.")], 0);
                assert_ne!(refused["status"], "COMMITTED", "{refused}");
                assert_eq!(d.submit(&mut s, id, "w1", &[], 0)["status"], "COMMITTED");
                let closed = s.checkpoint(&format!("task:{}", t["key"].as_str().unwrap())).unwrap();
                let context = &closed["context"];
                assert_eq!(
                    (context["abandoned"].as_bool(), context["stored"].as_u64(), context["unresolved"].as_bool()),
                    (Some(true), Some(0), None),
                    "{closed}"
                );
            } else {
                answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
            }
            t = d.acquire(&s, "w1", true, 0);
        }
        // closed as done, the abandoned reading is no reading until its reread says otherwise
        assert_eq!(with_status(&statuses(&s), "reading_given_up"), ["A client MUST retry.", "Another plain note."]);
        // the loss reread of the notes
        let reread = if t["kind"] == "REQUEST" { t } else { d.acquire(&s, "w2", true, 0) };
        assert!(reread["key"].as_str().is_some_and(|k| k == "reread:log.md#1"), "{reread}");
        let agent = reread["agent_id"].as_str().unwrap().to_string();
        answer(&mut d, &mut s, &reread, &agent, if reread_records { &["A client MUST retry."] } else { &[] });
        let units = statuses(&s);
        if reread_records {
            assert!(with_status(&units, "reading_given_up").is_empty(), "{units:?}");
            assert_eq!(with_status(&units, "quoted"), ["3. Clarify the error text.", "A client MUST retry."]);
            assert_eq!(with_status(&units, "left_by_budget").len(), 5, "{units:?}");
        } else {
            assert_eq!(with_status(&units, "reading_given_up"), ["A client MUST retry.", "Another plain note."]);
        }
        let sum = coverage(&s).summary;
        assert_eq!(sum.get("units_reading_given_up").cloned(), (!reread_records).then(|| json!(2)), "{sum}");
        // a dispatcher recovered on the journal counts the same
        drop(s);
        let s = AuditState::open(&path.0).unwrap();
        let mut recovered = Dispatcher::new(config(), vec![question()]);
        recovered.recover(&s);
        let report = recovered.gap_pass_report(&s);
        for key in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
            assert_eq!(report.get(key), sum.get(key), "{key}: {report}");
        }
    }
}

/// An owed second reading is no complete coverage (Codex's COV-01 of fe0ac7af, its scenario): the table and the report of the pass
/// say so before the second answer and after a restart, with the number owed, and say complete once the second reader answers
/// empty. A second reading that runs out of attempts stays `second_reading_failed` (the unit tests of the pass).
#[test]
fn an_owed_second_reading_is_no_complete_coverage_until_it_is_answered() {
    let profile = || GapProfile { limit: 1, units_per_task: 8, second_reader_tiers: vec![0], ..Default::default() };
    let pinned = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": 6000, "section_rule": 2, "gap_pass": profile().settings()});
    let (path, mut s) = journal("owed", Some(pinned));
    let question = || ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
    let mut d = Dispatcher::new(DispatchConfig { gap: profile(), ..Default::default() }, vec![question()]);
    let mut t = d.acquire(&s, "w1", true, 0);
    while t["kind"] == "EXTEND" {
        answer(&mut d, &mut s, &t, "w1", &[]);
        t = d.acquire(&s, "w1", true, 0);
    }
    assert_eq!(t["kind"], "REQUEST", "{t}");
    answer(&mut d, &mut s, &t, "w1", &[]);
    let owed = coverage(&s);
    let pending = owed.units.iter().filter(|r| r[5] == "second_reading_pending").count();
    assert_eq!(pending, 7, "{:?}", owed.units);
    assert_eq!((&owed.summary["complete"], &owed.summary["gap_units_second_reading_pending"]), (&json!(false), &json!(7)), "{}", owed.summary);
    assert!(owed.summary["meaning"].as_str().unwrap().contains("7 whose second reading is still owed"), "{}", owed.summary);
    assert_eq!(d.gap_pass_report(&s), owed.summary, "the report of the pass says the same");
    // after a restart: the journal gives the same table, a recovered dispatcher the same report and the reading still owed
    drop(s);
    let mut s = AuditState::open(&path.0).unwrap();
    assert_eq!(coverage(&s).summary, owed.summary);
    let mut recovered = Dispatcher::new(DispatchConfig { gap: profile(), ..Default::default() }, vec![question()]);
    recovered.recover(&s);
    assert_eq!(recovered.gap_pass_report(&s), owed.summary);
    let second = recovered.acquire(&s, "w2", true, 0);
    assert!(second["key"].as_str().is_some_and(|k| k.starts_with("gap2:")), "{second}");
    // the second reader answers empty: the units are answered empty, and the coverage is complete
    answer(&mut recovered, &mut s, &second, "w2", &[]);
    let done = coverage(&s);
    assert_eq!(done.units.iter().filter(|r| r[5] == "empty").count(), 7, "{:?}", done.units);
    assert_eq!((&done.summary["complete"], &done.summary["gap_units_second_reading_pending"]), (&json!(true), &json!(0)), "{}", done.summary);
    assert_eq!(recovered.gap_pass_report(&s), done.summary);
}

/// Codex's PR59-R1 of bbea393e, his case as he wrote it: under a bound of attempts, the reading of the notes stores one quote and
/// hands in another the text does not hold; its one attempt runs out and is recorded only in the record of failed attempts, with no
/// task checkpoint. The reading stored a record, so its section is read: the other unit of it is not `reading_given_up`.
#[test]
fn codex_partial_first_reading_with_explicit_attempt_limit_still_counts_as_read() {
    let pinned = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2,"agent_attempts":1});
    let (path, mut s) = journal("codex-partial-bounded", Some(pinned));
    let cfg = DispatchConfig { section_bytes: TWO_SECTIONS, agent_attempts: Some(1), auto_reread_limit: 0, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    loop {
        let t = d.acquire(&s, "w1", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        if t["prompt"].as_str().unwrap().contains("A client MUST retry.") {
            let prefix = t["local_id_prefix"].as_str().unwrap();
            let response = d.submit(
                &mut s,
                t["task_id"].as_str().unwrap(),
                "w1",
                &[observe(prefix, 0, "A client MUST retry."), observe(prefix, 1, "This quote never occurred.")],
                0,
            );
            assert_eq!(response["status"], "REPAIR_REQUIRED", "{response}");
            assert_eq!(response["accepted"].as_array().unwrap().len(), 1, "{response}");
            let released = d.release_durable(&mut s, t["task_id"].as_str().unwrap(), "w1");
            assert_eq!(released["unresolved"], true, "{released}");
            assert!(d.persist_unresolved(&mut s).is_empty());
            break;
        }
        answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
    }
    let first = coverage(&s);
    eprintln!("PARTIAL_BOUNDED: summary={}; rows={:?}; checkpoint={:?}", first.summary, statuses(&s), s.checkpoint("task:doc:log.md#1"));
    // the report of a dispatcher on the live state counts the same (no gap pass: the totals it shares with the table)
    for key in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
        assert_eq!(d.gap_pass_report(&s).get(key), first.summary.get(key), "{key}");
    }
    drop(s);
    let recovered = AuditState::open(&path.0).unwrap();
    let after = coverage(&recovered);
    assert_eq!(first.units, after.units);
    assert!(
        with_status(&statuses(&recovered), "reading_given_up").is_empty(),
        "a first reading stored a real record; another unit of its section must remain read: {}",
        after.summary
    );
    assert_eq!(after.summary["units_read"], 7);
    let mut again = Dispatcher::new(cfg, vec![question()]);
    again.recover(&recovered);
    for key in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
        assert_eq!(again.gap_pass_report(&recovered).get(key), after.summary.get(key), "{key} after a restart");
    }
}

// Codex's PR59-R3 of 2490c346, his two cases as he wrote them: a first reading stores part of its answer and the journal is cut
// off before the lease is given back; after a restart the section's attempts run out. The stored quote ties the reading to its
// section only through the repair checkpoint of its task, and the section is read.
use sbgk_core::audit::AuditStore;
fn codex_prefix_recovery_case(attempt_limit: Option<u32>) {
    let mut pinned = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2});
    if let Some(n) = attempt_limit {
        pinned["agent_attempts"] = json!(n);
    }
    let (path, mut s) = journal("codex-prefix-before-crash", Some(pinned));
    let cfg = DispatchConfig { section_bytes: TWO_SECTIONS, agent_attempts: attempt_limit, auto_reread_limit: 0, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    let original_task;
    loop {
        let t = d.acquire(&s, "w1", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        if t["prompt"].as_str().unwrap().contains("A client MUST retry.") {
            let prefix = t["local_id_prefix"].as_str().unwrap();
            original_task = t["task_id"].as_str().unwrap().to_string();
            let r = d.submit(&mut s, &original_task, "w1", &[observe(prefix, 0, "A client MUST retry."), observe(prefix, 1, "This quote never occurred.")], 0);
            assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
            assert_eq!(r["accepted"].as_array().unwrap().len(), 1);
            break;
        }
        answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
    }
    // Crash with an accepted prefix, before releasing the failed lease. The repair checkpoint and accepted record are durable.
    assert!(s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"] == original_task));
    drop(d);
    drop(s);
    let mut s = AuditState::open(&path.0).unwrap();
    let mut d = Dispatcher::new(cfg, vec![question()]);
    d.recover(&s);
    for n in 0..attempt_limit.unwrap_or(3) {
        let agent = format!("w{}", n + 2);
        let t = d.acquire(&s, &agent, true, 0);
        assert_eq!(t["key"], "doc:log.md#1", "{t}");
        let r =
            d.submit(&mut s, t["task_id"].as_str().unwrap(), &agent, &[observe(t["local_id_prefix"].as_str().unwrap(), 0, "Another quote never occurred.")], 0);
        assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
        let released = d.release_durable(&mut s, t["task_id"].as_str().unwrap(), &agent);
        if n + 1 == attempt_limit.unwrap_or(3) {
            assert_eq!(released["unresolved"], true, "{released}");
        }
    }
    assert!(d.persist_unresolved(&mut s).is_empty());
    let table = coverage(&s);
    let repair_points: Vec<Value> = s.checkpoint_keys("task-repair:").into_iter().map(|k| json!({"key": k, "checkpoint": s.checkpoint(&k)})).collect();
    let original_records: Vec<String> = s.records_since(0).into_iter().map(|r| r.directive).collect();
    let evidence = json!({"attempt_limit":attempt_limit,"original_task":original_task,"summary":table.summary,"rows":statuses(&s),"gap_report":d.gap_pass_report(&s),"record_directives":original_records,"repairs":repair_points,"task_checkpoint":s.checkpoint("task:doc:log.md#1"),"failures":s.checkpoint("audit:agent-failures")});
    if let Some(dir) = std::env::var_os("CODEX_REPRO_DIR") {
        let name = attempt_limit.map_or("default".into(), |n| format!("explicit-{n}"));
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join(format!("prefix-recovery-{name}.json")), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
        std::fs::copy(&path.0, dir.join(format!("prefix-recovery-{name}.wal"))).unwrap();
    }
    eprintln!("PREFIX_RECOVERY: limit={attempt_limit:?}; original_task={original_task}; summary={}; rows={:?}", table.summary, statuses(&s));
    assert!(with_status(&statuses(&s), "quoted").contains(&"A client MUST retry."));
    // the report of the live dispatcher counts the same (no gap pass: the totals it shares with the table)
    for key in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
        assert_eq!(evidence["gap_report"].get(key), table.summary.get(key), "{key}");
    }
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    assert!(
        with_status(&statuses(&s), "reading_given_up").is_empty(),
        "a durable prefix from the same first reading was stored before restart: {}",
        coverage(&s).summary
    );
    assert_eq!(coverage(&s).summary["units_read"], 7);
}

#[test]
fn codex_prefix_before_crash_counts_with_explicit_attempt_limit() {
    codex_prefix_recovery_case(Some(1));
}

#[test]
fn codex_prefix_before_crash_counts_with_default_attempt_limit() {
    codex_prefix_recovery_case(None);
}

// Codex's PR59-R4 of 6c9f567b, his five cases as he wrote them: a part answer cut off before its repair checkpoint (with an
// explicit bound and the default one), and three boundaries: a refusal alone, a quote of another section and a quote of a gap
// pack credit no first reading.
fn codex_r3_before_repair_checkpoint_case(attempt_limit: Option<u32>) {
    let mut pinned = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2});
    if let Some(n) = attempt_limit {
        pinned["agent_attempts"] = json!(n);
    }
    let (path, mut s) = journal("codex-prefix-before-crash", Some(pinned));
    let cfg = DispatchConfig { section_bytes: TWO_SECTIONS, agent_attempts: attempt_limit, auto_reread_limit: 0, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    let original_task;
    loop {
        let t = d.acquire(&s, "w1", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        if t["prompt"].as_str().unwrap().contains("A client MUST retry.") {
            let prefix = t["local_id_prefix"].as_str().unwrap();
            original_task = t["task_id"].as_str().unwrap().to_string();
            let r = d.submit(&mut s, &original_task, "w1", &[observe(prefix, 0, "A client MUST retry."), observe(prefix, 1, "This quote never occurred.")], 0);
            assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
            assert_eq!(r["accepted"].as_array().unwrap().len(), 1);
            break;
        }
        answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
    }
    // Crash with an accepted prefix, before releasing the failed lease. The repair checkpoint and accepted record are durable.
    assert!(s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"] == original_task));
    drop(d);
    drop(s);
    // Preserve exact complete frames before the repair checkpoint: a process can stop after store_items committed but before
    // Dispatcher::submit writes task-repair. No frame body, hash or sequence is changed.
    let full = std::fs::read(&path.0).unwrap();
    let marker = format!("task-repair:{original_task}:");
    let mut cut = 0;
    let mut found = false;
    for line in full.split_inclusive(|b| *b == b'\n') {
        if std::str::from_utf8(line).unwrap().contains(&marker) {
            found = true;
            break;
        }
        cut += line.len();
    }
    assert!(found && cut > 0 && cut < full.len());
    if let Some(dir) = std::env::var_os("CODEX_REPRO_DIR") {
        let name = if attempt_limit.is_some() { "explicit-1" } else { "default" };
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join(format!("before-repair-{name}-complete.wal")), &full).unwrap();
        std::fs::write(dir.join(format!("before-repair-{name}-prefix.wal")), &full[..cut]).unwrap();
    }
    std::fs::write(&path.0, &full[..cut]).unwrap();
    eprintln!("PRE_REPAIR_CUT: limit={attempt_limit:?}; exact_prefix_bytes={cut}; complete_bytes={}", full.len());
    let mut s = AuditState::open(&path.0).unwrap();
    assert!(s.records_since(0).iter().any(|r| r.directive == original_task), "prefix must retain committed record");
    assert!(
        !s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"] == original_task),
        "cut is before the repair frame"
    );

    let mut d = Dispatcher::new(cfg, vec![question()]);
    d.recover(&s);
    for n in 0..attempt_limit.unwrap_or(3) {
        let agent = format!("w{}", n + 2);
        let t = d.acquire(&s, &agent, true, 0);
        assert_eq!(t["key"], "doc:log.md#1", "{t}");
        let r =
            d.submit(&mut s, t["task_id"].as_str().unwrap(), &agent, &[observe(t["local_id_prefix"].as_str().unwrap(), 0, "Another quote never occurred.")], 0);
        assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
        let released = d.release_durable(&mut s, t["task_id"].as_str().unwrap(), &agent);
        if n + 1 == attempt_limit.unwrap_or(3) {
            assert_eq!(released["unresolved"], true, "{released}");
        }
    }
    assert!(d.persist_unresolved(&mut s).is_empty());
    let table = coverage(&s);
    let repair_points: Vec<Value> = s.checkpoint_keys("task-repair:").into_iter().map(|k| json!({"key": k, "checkpoint": s.checkpoint(&k)})).collect();
    let original_records: Vec<String> = s.records_since(0).into_iter().map(|r| r.directive).collect();
    let evidence = json!({"attempt_limit":attempt_limit,"original_task":original_task,"summary":table.summary,"rows":statuses(&s),"gap_report":d.gap_pass_report(&s),"record_directives":original_records,"repairs":repair_points,"task_checkpoint":s.checkpoint("task:doc:log.md#1"),"failures":s.checkpoint("audit:agent-failures")});
    if let Some(dir) = std::env::var_os("CODEX_REPRO_DIR") {
        let name = attempt_limit.map_or("default".into(), |n| format!("explicit-{n}"));
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join(format!("prefix-recovery-{name}.json")), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
        std::fs::copy(&path.0, dir.join(format!("prefix-recovery-{name}.wal"))).unwrap();
    }
    eprintln!("PREFIX_RECOVERY: limit={attempt_limit:?}; original_task={original_task}; summary={}; rows={:?}", table.summary, statuses(&s));
    assert!(with_status(&statuses(&s), "quoted").contains(&"A client MUST retry."));
    // the report of the live dispatcher counts the same (no gap pass: the totals it shares with the table)
    for key in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
        assert_eq!(evidence["gap_report"].get(key), table.summary.get(key), "{key}");
    }
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    assert!(
        with_status(&statuses(&s), "reading_given_up").is_empty(),
        "a durable prefix from the same first reading was stored before restart: {}",
        coverage(&s).summary
    );
    assert_eq!(coverage(&s).summary["units_read"], 7);
}

#[test]
fn codex_r3_before_repair_checkpoint_explicit_limit_still_counts() {
    codex_r3_before_repair_checkpoint_case(Some(1));
}
#[test]
fn codex_r3_before_repair_checkpoint_default_limit_still_counts() {
    codex_r3_before_repair_checkpoint_case(None);
}

#[test]
fn codex_r3_refusal_only_before_crash_does_not_count_as_read() {
    for limit in [Some(1u32), None] {
        let mut settings = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2});
        if let Some(n) = limit {
            settings["agent_attempts"] = json!(n);
        }
        let (path, mut s) = journal("codex-refusal-only-crash", Some(settings));
        let cfg = DispatchConfig { section_bytes: TWO_SECTIONS, agent_attempts: limit, auto_reread_limit: 0, ..Default::default() };
        let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
        let failed_task;
        loop {
            let t = d.acquire(&s, "w1", true, 0);
            assert_eq!(t["kind"], "EXTEND", "{t}");
            if t["key"] == "doc:log.md#1" {
                failed_task = t["task_id"].as_str().unwrap().to_string();
                let r = d.submit(&mut s, &failed_task, "w1", &[observe(t["local_id_prefix"].as_str().unwrap(), 0, "A client MAY retry.")], 0);
                assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
                assert_eq!(r["accepted"], json!([]));
                break;
            }
            answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
        }
        assert!(s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"] == failed_task));
        assert!(!s.records_since(0).iter().any(|r| r.directive == failed_task));
        drop(d);
        drop(s);
        let mut s = AuditState::open(&path.0).unwrap();
        let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
        d.recover(&s);
        for n in 0..limit.unwrap_or(3) {
            let agent = format!("w{}", n + 2);
            let t = d.acquire(&s, &agent, true, 0);
            assert_eq!(t["key"], "doc:log.md#1", "{t}");
            let r = fail(&mut d, &mut s, &t, &agent);
            if n + 1 == limit.unwrap_or(3) {
                assert_eq!(r["unresolved"], true, "{r}");
            }
        }
        assert!(d.persist_unresolved(&mut s).is_empty());
        drop(s);
        let s = AuditState::open(&path.0).unwrap();
        assert_eq!(with_status(&statuses(&s), "reading_given_up"), ["A client MUST retry.", "Another plain note."]);
        assert_eq!(coverage(&s).summary["units_read"], 5);
        let mut d = Dispatcher::new(cfg, vec![question()]);
        d.recover(&s);
        assert_eq!(d.gap_pass_report(&s)["units_read"], 5);
    }
}

#[test]
fn codex_r3_other_section_repair_does_not_credit_unread_notes() {
    let settings = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2,"agent_attempts":1});
    let (path, mut s) = journal("codex-other-section-repair", Some(settings));
    let cfg = DispatchConfig { section_bytes: TWO_SECTIONS, agent_attempts: Some(1), auto_reread_limit: 0, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!(t["key"], "doc:log.md#0", "{t}");
    let id = t["task_id"].as_str().unwrap();
    let prefix = t["local_id_prefix"].as_str().unwrap();
    let r = d.submit(&mut s, id, "w1", &[observe(prefix, 0, "3. Clarify the error text."), observe(prefix, 1, "This quote never occurred.")], 0);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(d.submit(&mut s, id, "w1", &[], 0)["status"], "COMMITTED");
    let t = d.acquire(&s, "w2", true, 0);
    assert_eq!(t["key"], "doc:log.md#1", "{t}");
    assert_eq!(fail(&mut d, &mut s, &t, "w2")["unresolved"], true);
    assert!(d.persist_unresolved(&mut s).is_empty());
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    assert_eq!(with_status(&statuses(&s), "reading_given_up"), ["A client MUST retry.", "Another plain note."]);
    assert_eq!(coverage(&s).summary["units_read"], 5);
}

#[test]
fn codex_r3_gap_repair_prefix_does_not_credit_the_first_reading() {
    let settings = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2,"agent_attempts":1,"gap_pass":gap().settings()});
    let (path, mut s) = journal("codex-gap-repair", Some(settings));
    let cfg = DispatchConfig { gap: gap(), section_bytes: TWO_SECTIONS, agent_attempts: Some(1), auto_reread_limit: 0, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    let mut t = read_failing_the_notes(&mut d, &mut s, &["w1"]);
    let mut checked = false;
    while t["kind"] == "REQUEST" {
        let agent = t["agent_id"].as_str().unwrap().to_string();
        if t["prompt"].as_str().unwrap().contains("A client MUST retry.") {
            assert!(t["key"].as_str().unwrap().starts_with("gap:"), "{t}");
            let prefix = t["local_id_prefix"].as_str().unwrap();
            let r = d.submit(
                &mut s,
                t["task_id"].as_str().unwrap(),
                &agent,
                &[observe(prefix, 0, "A client MUST retry."), observe(prefix, 1, "This quote never occurred.")],
                0,
            );
            assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
            assert_eq!(r["accepted"].as_array().unwrap().len(), 1);
            assert_eq!(d.release_durable(&mut s, t["task_id"].as_str().unwrap(), &agent)["unresolved"], true);
            checked = true;
        } else {
            answer(&mut d, &mut s, &t, &agent, &[]);
        }
        t = d.acquire(&s, &agent, true, 0);
    }
    assert!(checked, "must exercise gap repair");
    assert!(d.persist_unresolved(&mut s).is_empty());
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    assert_eq!(with_status(&statuses(&s), "reading_given_up"), ["Another plain note."]);
    assert_eq!(with_status(&statuses(&s), "quoted"), ["3. Clarify the error text.", "A client MUST retry."]);
    assert_eq!(coverage(&s).summary["units_read"], 6);
    let mut d = Dispatcher::new(cfg, vec![question()]);
    d.recover(&s);
    assert_eq!(d.gap_pass_report(&s), coverage(&s).summary);
}

// Codex's PR59-R4 of 0e655b47, his four cases as he wrote them: a first reading stores a question (no quote of its own) and is
// cut off before its repair checkpoint, with an explicit bound and the default one; the same with the repair checkpoint written
// (control); and a quote stored before the cut and withdrawn later. Each section read stays read.
fn codex_r4_nonquote_or_withdrawn_case(limit: Option<u32>, cut_before_repair: bool, withdraw: bool) {
    let label = format!(
        "{}-{}-{}",
        if withdraw { "withdraw" } else { "question" },
        if cut_before_repair { "cut" } else { "full" },
        if limit.is_some() { "explicit" } else { "default" }
    );
    let mut settings = json!({"format":"r2r-audit-mcp-coverage/1","section_bytes":TWO_SECTIONS,"section_rule":2});
    if let Some(n) = limit {
        settings["agent_attempts"] = json!(n);
    }
    let (path, mut s) = journal(&label, Some(settings));
    let cfg = DispatchConfig { section_bytes: TWO_SECTIONS, agent_attempts: limit, auto_reread_limit: 0, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    let original_task;
    let original_id;
    loop {
        let t = d.acquire(&s, "w1", true, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        if t["key"] == "doc:log.md#1" {
            let p = t["local_id_prefix"].as_str().unwrap();
            original_task = t["task_id"].as_str().unwrap().to_string();
            let accepted = if withdraw {
                observe(p, 0, "A client MUST retry.")
            } else {
                json!({"kind":"question","local_id":format!("{p}q0"),"text":"What error text changed?","about":["change"],"needed":"Clarify which change affects error text."})
            };
            let r = d.submit(&mut s, &original_task, "w1", &[accepted, observe(p, 1, "This quote never occurred.")], 0);
            assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
            assert_eq!(r["accepted"].as_array().unwrap().len(), 1, "legal prefix must be stored: {r}");
            original_id = s.records_since(0).into_iter().find(|r| r.directive == original_task).unwrap().id;
            if !withdraw {
                assert!(s.record(&original_id).unwrap().quote.is_none());
                assert!(!s.bound_quotes("log.md").iter().any(|(id, _, _)| *id == original_id), "question has no bound quote of its own");
            }
            break;
        }
        answer(&mut d, &mut s, &t, "w1", &["3. Clarify the error text."]);
    }
    assert!(s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"] == original_task));
    drop(d);
    drop(s);
    let full = std::fs::read(&path.0).unwrap();
    let mut cut = full.len();
    if cut_before_repair {
        let marker = format!("task-repair:{original_task}:");
        cut = 0;
        let mut found = false;
        for line in full.split_inclusive(|b| *b == b'\n') {
            if std::str::from_utf8(line).unwrap().contains(&marker) {
                found = true;
                break;
            }
            cut += line.len();
        }
        assert!(found && cut > 0 && cut < full.len());
        std::fs::write(&path.0, &full[..cut]).unwrap();
    }
    if let Some(dir) = std::env::var_os("CODEX_REPRO_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join(format!("{label}-complete.wal")), &full).unwrap();
        std::fs::write(dir.join(format!("{label}-prefix.wal")), &full[..cut]).unwrap();
    }
    let mut s = AuditState::open(&path.0).unwrap();
    assert_eq!(s.record(&original_id).unwrap().directive, original_task, "accepted prefix must replay");
    assert_eq!(s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"] == original_task), !cut_before_repair);
    if withdraw {
        assert!(s.withdraw_text("owner", "log.md", "A client MUST retry.").unwrap() >= 1);
        assert!(s.bound_quotes("log.md").iter().any(|(id, _, _)| *id == original_id), "revoked binding is still durable");
        assert!(!s.quoted_records("log.md").iter().any(|(id, _, _)| *id == original_id), "withdrawn quote is not standing");
    }
    let mut d = Dispatcher::new(cfg.clone(), vec![question()]);
    d.recover(&s);
    for n in 0..limit.unwrap_or(3) {
        let agent = format!("w{}", n + 2);
        let t = d.acquire(&s, &agent, true, 0);
        assert_eq!(t["key"], "doc:log.md#1", "{t}");
        let r = fail(&mut d, &mut s, &t, &agent);
        if n + 1 == limit.unwrap_or(3) {
            assert_eq!(r["unresolved"], true, "{r}");
        }
    }
    assert!(d.persist_unresolved(&mut s).is_empty());
    drop(d);
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    let mut recovered = Dispatcher::new(cfg, vec![question()]);
    recovered.recover(&s);
    let table = coverage(&s);
    let report = recovered.gap_pass_report(&s);
    for k in ["units_read", "units_quoted", "gap_units", "units_reading_given_up"] {
        assert_eq!(table.summary.get(k), report.get(k), "{k}");
    }
    let original = s.record(&original_id).unwrap();
    let evidence = json!({"label":label,"limit":limit,"cut_before_repair":cut_before_repair,"withdraw":withdraw,
        "prefix_bytes":cut,"complete_bytes":full.len(),"original_task":original_task,"original_record":{"id":original_id.short(),"kind":format!("{:?}",original.kind),"quote":original.quote,"directive":original.directive},
        "has_original_repair":s.checkpoint_keys("task-repair:").iter().any(|k| s.checkpoint(k).unwrap()["context"]["task_id"]==original_task),
        "bound_quotes":s.bound_quotes("log.md").into_iter().map(|(id,a,b)|json!([id.short(),a,b])).collect::<Vec<_>>(),
        "summary":table.summary,"rows":statuses(&s),"gap_report":report});
    if let Some(dir) = std::env::var_os("CODEX_REPRO_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join(format!("{label}.json")), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
        std::fs::copy(&path.0, dir.join(format!("{label}-after-retries.wal"))).unwrap();
    }
    eprintln!("R4_EXTRA: {evidence}");
    assert_eq!(table.summary["units_read"], 7, "any legal saved first-reading record counts, including a question without its own quote: {evidence}");
    assert!(with_status(&statuses(&s), "reading_given_up").is_empty(), "{evidence}");
    if withdraw {
        assert_eq!(with_status(&statuses(&s), "withdrawn"), ["A client MUST retry."]);
        assert_eq!(table.summary["gap_units"], 5);
    } else {
        assert_eq!(table.summary["gap_units"], 6);
    }
}

#[test]
fn codex_r4_question_before_repair_explicit_limit_counts_as_read() {
    codex_r4_nonquote_or_withdrawn_case(Some(1), true, false);
}
#[test]
fn codex_r4_question_before_repair_default_limit_counts_as_read() {
    codex_r4_nonquote_or_withdrawn_case(None, true, false);
}
#[test]
fn codex_r4_question_after_repair_counts_as_read_control() {
    codex_r4_nonquote_or_withdrawn_case(Some(1), false, false);
}
#[test]
fn codex_r4_withdrawn_quote_before_repair_still_counts_as_read() {
    codex_r4_nonquote_or_withdrawn_case(Some(1), true, true);
}
