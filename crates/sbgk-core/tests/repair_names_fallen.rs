//! A repair after a withdrawal: it names what fell by id, shows what stands under it, keeps the fallen text out, and the kernel
//! leaves copies of the kept rows out of the answer. No provider or runner calls.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_WAL: AtomicU64 = AtomicU64::new(0);

const FALLEN_TEXT: &str = "Topics A and B both hold.";
const KEPT_TEXT: &str = "Topic C holds.";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig { section_bytes: 6000, ..Default::default() },
        vec![ResearchQuestion { id: "RQ1".into(), text: "What is known about topic?".into(), about: vec!["topic".into()], ..Default::default() }],
    )
}
fn observe(n: &str, doc: &str, quote: &str) -> Value {
    json!({"kind":"observe", "local_id":n, "doc_id":doc, "exact_quote":quote, "terms":["topic"]})
}
fn claim(n: &str, on: &[&str], text: &str) -> Value {
    json!({"kind":"claim", "local_id":n, "text":text, "subject":"topic", "stance":"reported", "based_on":on})
}
fn done(t: &Value, ids: &[&str]) -> Value {
    json!({"kind":"done", "local_id":format!("{}d1",t["local_id_prefix"].as_str().unwrap()), "rq_id":"RQ1", "directive_id":t["task_id"], "outcome":"answered", "answer_ids":ids})
}

struct Answered {
    wal: Wal,
    s: AuditState,
    d: Dispatcher,
    /// The quotes of topics A, B and C.
    quotes: Vec<RecordId>,
    fallen: String,
    kept: String,
}

/// An answer of two rows, the first on the quotes named by `row` and the second on the quote of topic C, with topic A withdrawn
/// afterwards. Topic D is a second document's line: reports names the documents the first row reads.
fn withdrawn_under(row: &[usize], second_doc: bool) -> Answered {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("repair_fallen_{}_{nonce}_{}.wal", std::process::id(), NEXT_WAL.fetch_add(1, Ordering::Relaxed))));
    let mut docs = vec![("d1".to_string(), b"# Facts\nTopic A holds. Topic B holds. Topic C holds.\n".to_vec())];
    if second_doc {
        docs.push(("d2".to_string(), b"# More\nTopic D holds.\n".to_vec()));
    }
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "repair", sha256(b"offline")).unwrap();
    let mut d = dispatcher();
    let names: Vec<String> = docs.iter().map(|(n, _)| n.clone()).collect();
    let mut lines = vec![
        observe("a", "d1", "Topic A holds."),
        claim("ca", &["a"], "Topic A holds."),
        observe("b", "d1", "Topic B holds."),
        claim("cb", &["b"], "Topic B holds."),
        observe("c", "d1", "Topic C holds."),
        claim("cc", &["c"], "Topic C seen."),
    ];
    if second_doc {
        lines.push(observe("e", "d2", "Topic D holds."));
        lines.push(claim("ce", &["e"], "Topic D holds."));
    }
    let seed = s.submit_records("reader", "seed", &Scope { docs: names, ..Default::default() }, &lines);
    assert!(seed.error.is_none(), "{:?}", seed.error);
    let mut quotes = vec![seed.accepted[0], seed.accepted[2], seed.accepted[4]];
    if second_doc {
        quotes.push(seed.accepted[6]);
    }
    let mut now = 0;
    let t = loop {
        let t = d.acquire(&s, "worker", true, now);
        now += 1;
        if t["kind"] == "SUMMARIZE" {
            break t;
        }
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "worker", &[], now)["status"], "COMMITTED");
    };
    let on: Vec<String> = row.iter().map(|i| quotes[*i].short()).collect();
    let on: Vec<&str> = on.iter().map(String::as_str).collect();
    let answer = [claim("row", &on, FALLEN_TEXT), claim("other", &[&quotes[2].short()], KEPT_TEXT), done(&t, &["row", "other"])];
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "worker", &answer, now);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let (fallen, kept) = (r["accepted_locals"]["row"].as_str().unwrap().to_string(), r["accepted_locals"]["other"].as_str().unwrap().to_string());
    s.revoke_observation("owner", &quotes[0]).unwrap();
    Answered { wal, s, d, quotes, fallen, kept }
}

#[test]
fn a_repair_names_the_fallen_row_by_id_and_keeps_its_text_out() {
    let mut a = withdrawn_under(&[0, 1], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    assert_eq!(t["retained_answer_ids"], json!([a.kept]), "{t}");
    let p = t["prompt"].as_str().unwrap();
    assert!(p.contains(&format!("{} (1 of its quotes gone): {} \"Topic B holds.\"", a.fallen, a.quotes[1].short())), "{p}");
    assert!(!p.contains(FALLEN_TEXT), "the text of the fallen row may state what was withdrawn: {p}");
    assert!(!p.contains("Topic A holds."), "the withdrawn bytes: {p}");
    assert!(p.contains("Write at most 4 claim lines"), "{p}");
    assert!(p.contains("Answer with at most 5 JSON lines"), "{p}");
    assert_eq!(t["max_lines"], 5, "{t}");
    for full_answer in ["Condense", "do not restate every record", "Cover every report", "say that the answer may be incomplete"] {
        assert!(!p.contains(full_answer), "{full_answer}: {p}");
    }
}

#[test]
fn a_copy_of_a_kept_row_is_left_out_and_counted() {
    let mut a = withdrawn_under(&[0, 1], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let task = t["task_id"].as_str().unwrap().to_string();
    let (b, c) = (a.quotes[1].short(), a.quotes[2].short());
    let before = a.s.records_since(0).len();
    let lines = [claim("copy", &[&c], "  topic c   HOLDS. "), claim("new", &[&b], "Topic B holds on its own."), done(&t, &["copy", "new"])];
    let r = a.d.submit(&mut a.s, &task, "repair", &lines, 101);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(r["dropped_copies"], json!(["copy"]), "{r}");
    assert!(r["accepted_locals"].get("copy").is_none(), "{r}");
    let new = r["accepted_locals"]["new"].as_str().unwrap().to_string();
    assert_eq!(a.s.records_since(0).len(), before + 2, "the new row and the done line: {r}");
    let view = a.d.accepted_outcomes(&a.s);
    let ids: Vec<&str> = view["RQ1"]["answer_ids"].as_array().unwrap().iter().filter_map(|x| x.as_str()).collect();
    assert!(ids.len() == 2 && ids.contains(&a.kept.as_str()) && ids.contains(&new.as_str()), "{view}");
    let context = a.s.checkpoint("task:rq:RQ1").expect("the answer's checkpoint")["context"].clone();
    assert_eq!(context["composition"]["dropped_copies"], json!(["copy"]), "{context}");
    assert_eq!(context["composition"]["fallen_answer_ids"], json!([a.fallen]), "{context}");
}

/// R017-02: the same sentence on another quote or with another date is another claim, and the repair keeps it.
#[test]
fn the_words_of_a_kept_row_on_other_grounds_or_another_date_are_no_copy() {
    let mut a = withdrawn_under(&[0, 1], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let task = t["task_id"].as_str().unwrap().to_string();
    let (b, c) = (a.quotes[1].short(), a.quotes[2].short());
    let mut dated = claim("dated", &[&c], KEPT_TEXT);
    dated["as_of"] = json!(20260101);
    let lines = [claim("other", &[&b], KEPT_TEXT), dated, done(&t, &["other", "dated"])];
    let r = a.d.submit(&mut a.s, &task, "repair", &lines, 101);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert!(r.get("dropped_copies").is_none_or(|d| d.as_array().is_some_and(|d| d.is_empty())), "{r}");
    let view = a.d.accepted_outcomes(&a.s);
    let ids: Vec<&str> = view["RQ1"]["answer_ids"].as_array().unwrap().iter().filter_map(|x| x.as_str()).collect();
    for name in ["other", "dated"] {
        assert!(ids.contains(&r["accepted_locals"][name].as_str().unwrap()), "{name}: {view}");
    }
}

/// The grounds of a line read as the store reads a reference: a full id in either case is the quote, a near miss is no quote at all.
#[test]
fn a_copy_may_name_its_grounds_in_full_and_a_wrong_id_is_refused() {
    for (name, full) in [("lower", false), ("upper", true)] {
        let mut a = withdrawn_under(&[0, 1], false);
        let t = a.d.acquire(&a.s, "repair", true, 100);
        let task = t["task_id"].as_str().unwrap().to_string();
        let hex = sbgk_core::hash::to_hex(&a.quotes[2].0);
        let id = format!("@{}", if full { hex.to_uppercase() } else { hex });
        let r = a.d.submit(&mut a.s, &task, "repair", &[claim("copy", &[&id], KEPT_TEXT), done(&t, &["copy"])], 101);
        assert_eq!(r["dropped_copies"], json!(["copy"]), "{name}: {r}");
    }
    let mut a = withdrawn_under(&[0, 1], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let task = t["task_id"].as_str().unwrap().to_string();
    let mut hex = sbgk_core::hash::to_hex(&a.quotes[2].0);
    let last = if hex.ends_with('0') { "1" } else { "0" };
    hex.replace_range(63.., last);
    let wrong = format!("@{hex}");
    let r = a.d.submit(&mut a.s, &task, "repair", &[claim("copy", &[&wrong], KEPT_TEXT), done(&t, &["copy"])], 101);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["error"]["code"], "UNKNOWN_LOCAL_ID", "{r}");
}

#[test]
fn a_repair_takes_no_more_lines_than_it_was_told() {
    let mut a = withdrawn_under(&[0, 1], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let task = t["task_id"].as_str().unwrap().to_string();
    let b = a.quotes[1].short();
    let before = a.s.records_since(0).len();
    let mut lines: Vec<Value> = (0..5).map(|n| claim(&format!("n{n}"), &[&b], &format!("Topic B holds, reading {n}."))).collect();
    lines.push(done(&t, &["n0"]));
    let r = a.d.submit(&mut a.s, &task, "repair", &lines, 101);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert_eq!(r["error"]["expected_by_kernel"]["max_lines"], 5, "{r}");
    assert_eq!(a.s.records_since(0).len(), before, "nothing was stored: {r}");
}

#[test]
fn a_row_with_nothing_standing_closes_on_the_done_line_alone() {
    let mut a = withdrawn_under(&[0], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let p = t["prompt"].as_str().unwrap();
    assert!(p.contains("No quote of theirs stands"), "{p}");
    assert!(!p.contains(FALLEN_TEXT) && !p.contains("Topic A holds."), "{p}");
    assert_eq!(t["max_lines"], 3, "{t}");
    let r = a.d.submit(&mut a.s, t["task_id"].as_str().unwrap(), "repair", &[done(&t, &[])], 101);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(a.d.accepted_outcomes(&a.s)["RQ1"]["answer_ids"], json!([a.kept]));
}

#[test]
fn with_nothing_standing_other_records_may_still_say_where_the_point_stands() {
    // a withdrawn newest state: its row has no quote left, and the older state stands in a record of its own
    let mut a = withdrawn_under(&[0], false);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let b = a.quotes[1].short();
    let lines = [claim("older", &[&b], "Topic B holds; the later state is unconfirmed."), done(&t, &["older"])];
    let r = a.d.submit(&mut a.s, t["task_id"].as_str().unwrap(), "repair", &lines, 101);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    assert_eq!(a.d.accepted_outcomes(&a.s)["RQ1"]["answer_ids"].as_array().unwrap().len(), 2);
}

#[test]
fn a_report_whose_only_row_fell_need_not_come_back() {
    // the fallen row was the only one on the second document, whose quote stands: closing the repair without it is an answer
    let mut a = withdrawn_under(&[0, 3], true);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    assert!(t["prompt"].as_str().unwrap().contains(&a.quotes[3].short()), "{t}");
    let r = a.d.submit(&mut a.s, t["task_id"].as_str().unwrap(), "repair", &[done(&t, &[])], 101);
    assert_eq!(r["status"], "COMMITTED", "{r}");
}

#[test]
fn a_restart_still_knows_what_fell_also_after_the_repair_was_given_up() {
    let a = withdrawn_under(&[0, 1], false);
    let (wal, fallen, s) = (a.wal, a.fallen, a.s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    for n in 0..3 {
        let t = d.acquire(&s, "fail", true, 200 + n);
        assert!(t["prompt"].as_str().unwrap().contains(&fallen), "{t}");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "fail", &[], 200 + n)["status"], "REPAIR_REQUIRED");
        d.release_durable(&mut s, t["task_id"].as_str().unwrap(), "fail");
    }
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    let view = d.offline_diagnostics(&s);
    let p = view["summary_windows"]["RQ1"]["prompt"].as_str().unwrap();
    assert!(p.contains(&fallen) && !p.contains(FALLEN_TEXT), "{p}");
}
