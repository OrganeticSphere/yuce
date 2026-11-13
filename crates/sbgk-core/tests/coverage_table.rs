//! The coverage table (0.2.1) on journals the kernel writes: what each unit came to, drawn from the journal alone; its totals are
//! the report of the gap pass; a withdrawal changes it; the index carries it at every prefix; a journal that pins no sections gives
//! none and says why. No provider or runner calls.
use sbgk_core::audit::directives::{coverage, DispatchConfig, Dispatcher, GapProfile, ResearchQuestion};
use sbgk_core::audit::index;
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
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
