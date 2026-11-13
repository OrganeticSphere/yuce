//! A repair after a withdrawal shows the live support of what fell (the owner's decision of 11.11.2026 on run K02_1_r1): the
//! standing claims most like the fallen rows by words, after the kept rows and before the claims chosen by the question, in the
//! same budget. A journal replays from the window each of its frames carries. No provider or runner calls.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_WAL: AtomicU64 = AtomicU64::new(0);

/// The changelog line withdrawn later.
const WITHDRAWN: &str = "Remove protocol-level sessions from the streamable transport.";
const FALLEN_TEXT: &str = "Protocol-level sessions were removed from the streamable transport.";
/// The same change stated on another page: the live support of the fallen conclusion.
const TWIN_QUOTE: &str = "Removal of protocol-level sessions.";
const TWIN_TEXT: &str = "The streamable transport removed protocol-level sessions.";
/// Claims of the question's topic on the transport page, read before its twin: more than the window takes.
const FILLERS: usize = 110;
/// The window's budget of records in these tests: the claims by the question do not all fit.
const RECORDS: usize = 150;
/// What every repair after a withdrawal is told the withdrawal took (0.2.1, step A9: the control run 1 of 0.2 read the withdrawal of
/// one changelog line as the withdrawal, and the refutation, of the whole revision).
const SCOPE: &str = "A withdrawal takes away only the quoted bytes it names, not the document they come from, its revision, or what other \
                     quotes say: every quote shown in this task stands. It says nothing about whether what those bytes stated is \
                     true: do not write that a document, a revision or a change was withdrawn, reverted or is no longer confirmed \
                     unless a quote shown here says so.";

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig { section_bytes: 6000, summary_records: RECORDS, ..Default::default() },
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

struct Run {
    wal: Wal,
    s: AuditState,
    d: Dispatcher,
    /// Seed records by local id.
    seed: std::collections::BTreeMap<String, RecordId>,
    fallen: String,
    kept: String,
}
impl Run {
    fn id(&self, n: &str) -> RecordId {
        self.seed[n]
    }
}

/// The lines of the page `side`: each is read by two readers, and a wide answer row rests on all of them.
const SIDE: [&str; 4] = [
    "Gateway nodes batch outgoing frames every forty milliseconds.",
    "Relay caches expire idle tokens after ninety seconds.",
    "Ledger shards rotate signing keys each quarter.",
    "Probe timers back off exponentially under sustained load.",
];
const WIDE_TEXT: &str =
    "Sessions were removed from the streamable transport; gateways batch frames, relays expire tokens, shards rotate keys, timers back off.";

/// The first answer has one row on the withdrawn line alone.
fn withdrawn(twins: usize) -> Run {
    answered(twins, &[("row", &["w"], FALLEN_TEXT)], false)
}

/// The changelog `log` states the change, withdrawn after the first answer, and a line that stays; the transport page `page` has
/// FILLERS claims of the topic and then the twin of the change; `twins` more pages `t<k>` state the twin again. Readers also rest
/// claims on the withdrawn line (`cw`), on a quote inside it (`cwp`), and on it and the twin's quote together (`mixed`). With
/// `side`, a page `side` of SIDE lines `s<k>`, each with the claims `cs<k>a` and `cs<k>b` of two readers. The first answer has
/// `rows` (local id, the seed quotes it rests on, text), the first of them on the withdrawn line, and a kept row on the line that
/// stays, and reads every other page by one quote.
fn answered(twins: usize, rows: &[(&str, &[&str], &str)], side: bool) -> Run {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("repair_live_{}_{nonce}_{}.wal", std::process::id(), NEXT_WAL.fetch_add(1, Ordering::Relaxed))));
    let mut page = String::from("# Transport\n");
    for n in 0..FILLERS {
        page.push_str(&format!("Topic item {n} holds.\n"));
    }
    page.push_str(&format!("{TWIN_QUOTE}\n"));
    let mut docs = vec![("log".to_string(), format!("# Changes\n{WITHDRAWN}\nTopic C holds.\n").into_bytes()), ("page".to_string(), page.into_bytes())];
    for k in 0..twins {
        docs.push((format!("t{k}"), format!("# Twin {k}\n{TWIN_QUOTE}\n").into_bytes()));
    }
    if side {
        docs.push(("side".to_string(), format!("# Side\n{}\n", SIDE.join("\n")).into_bytes()));
    }
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "repair-live", sha256(b"offline")).unwrap();
    let mut lines = vec![
        observe("w", "log", WITHDRAWN),
        claim("cw", &["w"], "Protocol-level sessions are gone from the streamable transport."),
        observe("wpart", "log", "protocol-level sessions from the streamable"),
        claim("cwp", &["wpart"], "Protocol-level sessions left the streamable transport."),
        observe("c", "log", "Topic C holds."),
        claim("cc", &["c"], "Topic C seen."),
    ];
    for n in 0..FILLERS {
        lines.push(observe(&format!("f{n}"), "page", &format!("Topic item {n} holds.")));
        lines.push(claim(&format!("cf{n}"), &[&format!("f{n}")], &format!("Topic item {n} holds.")));
    }
    lines.push(observe("tq", "page", TWIN_QUOTE));
    lines.push(claim("twin", &["tq"], TWIN_TEXT));
    lines.push(claim("mixed", &["w", "tq"], "Sessions were removed, on both quotes."));
    for k in 0..twins {
        lines.push(observe(&format!("tq{k}"), &format!("t{k}"), TWIN_QUOTE));
        lines.push(claim(&format!("twin{k}"), &[&format!("tq{k}")], TWIN_TEXT));
    }
    for (k, text) in SIDE.iter().enumerate().filter(|_| side) {
        lines.push(observe(&format!("s{k}"), "side", text));
        lines.push(claim(&format!("cs{k}a"), &[&format!("s{k}")], text));
        lines.push(claim(&format!("cs{k}b"), &[&format!("s{k}")], &format!("The side page states: {text}")));
    }
    let names: Vec<String> = docs.iter().map(|(n, _)| n.clone()).collect();
    let r = s.submit_records("reader", "seed", &Scope { docs: names, ..Default::default() }, &lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    let seed: std::collections::BTreeMap<String, RecordId> =
        lines.iter().zip(&r.accepted).map(|(l, id)| (l["local_id"].as_str().unwrap().to_string(), *id)).collect();
    let mut d = dispatcher();
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
    let mut other: Vec<String> = vec![seed["c"].short(), seed["f0"].short()];
    other.extend((0..twins).map(|k| seed[&format!("tq{k}")].short()));
    let other: Vec<&str> = other.iter().map(String::as_str).collect();
    let mut answer: Vec<Value> = rows
        .iter()
        .map(|(n, on, text)| {
            let on: Vec<String> = on.iter().map(|q| seed[*q].short()).collect();
            claim(n, &on.iter().map(String::as_str).collect::<Vec<_>>(), text)
        })
        .collect();
    answer.push(claim("other", &other, "Topic C holds, and the other pages hold."));
    let mut ids: Vec<&str> = rows.iter().map(|r| r.0).collect();
    ids.push("other");
    answer.push(done(&t, &ids));
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "worker", &answer, now);
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let (fallen, kept) = (r["accepted_locals"][rows[0].0].as_str().unwrap().to_string(), r["accepted_locals"]["other"].as_str().unwrap().to_string());
    assert!(s.withdraw_text("owner", "log", WITHDRAWN).unwrap() >= 1);
    Run { wal, s, d, seed, fallen, kept }
}

/// The line of a prompt that starts so.
fn line<'a>(p: &'a str, head: &str) -> &'a str {
    p.lines().find(|l| l.starts_with(head)).unwrap_or_else(|| panic!("no {head} line: {p}"))
}

#[test]
fn a_live_twin_past_the_window_by_the_question_comes_in_through_the_live_support() {
    let mut a = withdrawn(0);
    let (twin, tq) = (a.id("twin"), a.id("tq"));
    // by the question alone the twin is past the window: more than a hundred relevant claims, and it was read last
    let (by_question, relevant) = a.d.summary_candidates(&a.s, "RQ1", true).unwrap();
    assert!(relevant.len() > 100 && relevant.contains(&twin) && !by_question.contains(&twin), "{} relevant", relevant.len());
    let t = a.d.acquire(&a.s, "repair", true, 100);
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    assert_eq!(t["retained_answer_ids"], json!([a.kept]), "{t}");
    let p = t["prompt"].as_str().unwrap();
    assert_eq!(
        line(p, "LIVE SUPPORT"),
        format!(
            "LIVE SUPPORT (kernel, a retrieval by the words of the records that fell, not a verdict): 1 standing claim shown whatever their place \
         by the question, each with all it rests on, none on withdrawn text: {}.",
            twin.short()
        )
    );
    assert!(p.contains(&format!("{} observe by reader: [page] \"{TWIN_QUOTE}\"", tq.short())), "{p}");
    assert!(p.contains("The claims of LIVE SUPPORT below stand on quotes that were not withdrawn"), "{p}");
    // the budget does not grow: the twin's unit takes the place of one claim by the question, so as many relevant claims are shown
    // as without it, and the twin, relevant and past the cap of claims, is counted among them, not among those not shown
    assert_eq!(line(p, "WINDOW:"), "WINDOW: 75 of 113 relevant claims shown, each with all it rests on; 38 not shown. Documents with no quote shown: none.");
    let records = p.lines().skip_while(|l| *l != "RECORDS:").skip(1).take_while(|l| *l != "ACCEPTED LINKS:").count();
    let by_question = p.matches(" claim by reader: Topic item ").count();
    assert!(records <= RECORDS && by_question == 72, "{records} records, {by_question} claims of the page by the question");
    // the repair rests the fallen point on the twin's quote: the store takes it, as the window was issued
    let task = t["task_id"].as_str().unwrap().to_string();
    let r = a.d.submit(
        &mut a.s,
        &task,
        "repair",
        &[claim("again", &[&tq.short()], "Protocol-level sessions were removed (transport page)."), done(&t, &["again"])],
        101,
    );
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let again = r["accepted_locals"]["again"].as_str().unwrap().to_string();
    let wal = a.wal;
    drop(a.s);
    // the window is in the frame of that answer: its allowed records hold the twin's quote
    let text = std::fs::read_to_string(&wal.0).unwrap();
    let frame: Value = text
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|f| f["body"]["command"]["kind"] == "submit" && f["body"]["command"]["directive"] == json!(task))
        .expect("the repair's frame");
    let allowed: BTreeSet<&str> = frame["body"]["command"]["allowed_records"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(allowed.contains(to_hex(&tq.0).as_str()) && allowed.len() <= RECORDS, "{} allowed", allowed.len());
    // and the journal replays: a reopened store and a recovered dispatcher have the repaired answer
    let s = AuditState::open(&wal.0).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    let view = d.accepted_outcomes(&s);
    let got: BTreeSet<&str> = view["RQ1"]["answer_ids"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert_eq!(got, [a.kept.as_str(), again.as_str()].into_iter().collect(), "{view}");
}

#[test]
fn what_was_withdrawn_and_what_rests_on_it_stay_out_of_the_live_support() {
    let mut a = withdrawn(0);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let p = t["prompt"].as_str().unwrap();
    assert!(line(p, "LIVE SUPPORT").ends_with(&format!(": {}.", a.id("twin").short())), "{p}");
    // the claim on the withdrawn line, the one on a quote inside it and the one on it and the twin's quote are nearer by words than
    // the twin, and none of them is shown; nor are the withdrawn quotes, nor the fallen row's text
    for n in ["cw", "cwp", "mixed", "w", "wpart"] {
        assert!(!p.contains(&a.id(n).short()), "{n}: {p}");
    }
    assert!(!p.contains(WITHDRAWN) && !p.contains(FALLEN_TEXT) && !p.contains(&a.fallen), "{p}");
    assert!(p.contains("\nINCREMENTAL REPAIR: 1 of the answer records of this question no longer stand"), "{p}");
    // a row with no quote standing, a live support shown: the task says what the withdrawal took
    assert!(p.contains(SCOPE), "{p}");
}

#[test]
fn one_state_gives_one_window_and_equal_twins_keep_reading_order_four_at_most() {
    let a = withdrawn(5);
    // six claims with the same words: the page's twin, then the twins of pages t0..t4, read in that order
    let shorts: Vec<String> = ["twin", "twin0", "twin1", "twin2"].iter().map(|n| a.id(n).short()).collect();
    let wal = a.wal;
    drop(a.s);
    let windows: Vec<(String, Value)> = (0..2)
        .map(|_| {
            let s = AuditState::open(&wal.0).unwrap();
            let mut d = dispatcher();
            d.recover(&s);
            let w = d.offline_diagnostics(&s)["summary_windows"]["RQ1"].clone();
            (w["prompt"].as_str().unwrap().to_string(), w["issued"].clone())
        })
        .collect();
    assert_eq!(windows[0], windows[1]);
    let p = &windows[0].0;
    assert!(
        line(p, "LIVE SUPPORT").ends_with(&format!(
            "4 standing claims shown whatever their place by the question, each with all it rests on, none on withdrawn text: {}.",
            shorts.join(", ")
        )),
        "{p}"
    );
    // a live task over the same state shows the same records
    let s = AuditState::open(&wal.0).unwrap();
    let mut d = dispatcher();
    d.recover(&s);
    let t = d.acquire(&s, "repair", true, 300);
    assert_eq!(line(t["prompt"].as_str().unwrap(), "LIVE SUPPORT"), line(p, "LIVE SUPPORT"));
    assert_eq!(line(t["prompt"].as_str().unwrap(), "WINDOW:"), line(p, "WINDOW:"));
}

#[test]
fn a_journal_replays_from_the_window_its_frames_carry_whatever_the_window_rule_now() {
    let mut a = withdrawn(0);
    let (tq, far) = (a.id("tq"), a.id(&format!("f{}", FILLERS - 1)));
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let now: BTreeSet<String> =
        a.d.offline_diagnostics(&a.s)["summary_windows"]["RQ1"]["issued"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    assert!(now.contains(&tq.short()) && !now.contains(&far.short()), "the rule now shows the twin, not the last filler");
    assert!(t["prompt"].as_str().unwrap().contains(&tq.short()));
    // a window as an earlier rule chose it: without the twin, with the last filler's quote; recorded in the frames of two answers
    let mut earlier: Vec<RecordId> = a.s.records_since(0).into_iter().filter(|r| now.contains(&r.id.short()) && r.id != tq).map(|r| r.id).collect();
    earlier.push(far);
    let on_far = a.s.submit_scoped_records_id(
        "old-1",
        "old",
        "TS900-0",
        &Scope::default(),
        &earlier,
        &[claim("x", &[&format!("@{}", to_hex(&far.0))], "Topic item holds.")],
    );
    assert!(on_far.error.is_none(), "{:?}", on_far.error);
    let on_twin = a.s.submit_scoped_records_id(
        "old-2",
        "old",
        "TS900-0",
        &Scope::default(),
        &earlier,
        &[claim("y", &[&format!("@{}", to_hex(&tq.0))], "Sessions were removed.")],
    );
    assert_eq!(on_twin.accepted.len(), 0, "the twin was not issued in that frame");
    let (records, root) = (a.s.records_since(0).len(), a.s.audit_root());
    let wal = a.wal;
    drop(a.s);
    // the replay takes each frame's own window: the same records, the same root
    let s = AuditState::open(&wal.0).unwrap();
    assert_eq!((s.records_since(0).len(), s.audit_root()), (records, root));
    assert!(s.is_grounded(&on_far.accepted[0]));
}

#[test]
fn a_row_that_fell_with_quotes_still_standing_gets_the_support_of_what_it_lost_not_the_claims_on_those_quotes() {
    // a wide row on the withdrawn line and the four lines of the side page, each of them read by two readers
    let mut a = answered(0, &[("wide", &["w", "s0", "s1", "s2", "s3"], WIDE_TEXT)], true);
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let p = t["prompt"].as_str().unwrap();
    // its standing quotes are named with it...
    assert!(p.contains("STILL STANDING UNDER THE FALLEN RECORDS"), "{p}");
    for (k, text) in SIDE.iter().enumerate() {
        assert!(p.contains(&format!("{} \"{text}\"", a.id(&format!("s{k}")).short())), "{p}");
    }
    // ...so the live support is the twin of the line it lost, and no place of it goes to a claim on those same quotes
    let live = line(p, "LIVE SUPPORT");
    assert!(live.contains(&a.id("twin").short()), "{live}");
    for k in 0..SIDE.len() {
        for reader in ["a", "b"] {
            assert!(!live.contains(&a.id(&format!("cs{k}{reader}")).short()), "cs{k}{reader}: {live}");
        }
    }
    assert!(p.contains("with the quotes of the claims of LIVE SUPPORT below"), "{p}");
    // a row named with its standing quotes: the task says what the withdrawal took, once
    assert_eq!(p.matches(SCOPE).count(), 1, "{p}");
}

#[test]
fn a_row_that_fell_with_no_quote_standing_beside_a_named_one_may_still_rest_on_the_live_support() {
    // two rows fall: one on the withdrawn line alone, one on it and a line of the page that stands
    let mut a = answered(0, &[("row", &["w"], FALLEN_TEXT), ("part", &["w", "f1"], "Topic item 1 holds, and sessions were removed.")], false);
    let (tq, f1) = (a.id("tq"), a.id("f1"));
    let t = a.d.acquire(&a.s, "repair", true, 100);
    let p = t["prompt"].as_str().unwrap();
    assert!(p.contains("INCREMENTAL REPAIR: 2 of the answer records of this question no longer stand"), "{p}");
    assert!(p.contains(SCOPE), "{p}");
    assert!(p.contains("STILL STANDING UNDER THE FALLEN RECORDS") && line(p, "LIVE SUPPORT").contains(&a.id("twin").short()), "{p}");
    // the row without a quote is not written off: the task lets it rest on the live support
    assert!(!p.contains("write nothing for them"), "{p}");
    assert!(p.contains("1 more fell, not named above: write a claim for them only where the quotes of the claims of LIVE SUPPORT below"), "{p}");
    assert!(p.contains("Write no claim beyond these: the answer needs no other change."), "{p}");
    // and the repair that does so is taken: a claim on the twin's quote and one on the standing quote of the named row
    let task = t["task_id"].as_str().unwrap().to_string();
    let lines = [
        claim("again", &[&tq.short()], "Protocol-level sessions were removed (transport page)."),
        claim("item", &[&f1.short()], "Topic item 1 holds."),
        done(&t, &["again", "item"]),
    ];
    let r = a.d.submit(&mut a.s, &task, "repair", &lines, 101);
    assert_eq!(r["status"], "COMMITTED", "{r}");
}
