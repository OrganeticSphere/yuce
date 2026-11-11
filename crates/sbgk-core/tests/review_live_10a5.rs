//! Regressions for live run 10A-5 (Sonnet 5.5, 2026-10-23), on the durable store: a question whose `about` names a line of its own
//! answer by local id is investigated in that line's section, not given up as a word-search miss; the builder is told which records
//! it may map and link, and it proposes links by the same criteria the check confirms them by.

use sbgk_core::audit::builder::{Builder, BuilderConfig, LINK_CRITERIA};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const R1: &str = "# Gate\nThe gate blocks a validator version mismatch.\n";
const R2: &str = "# Notes\nThe release checklist was signed by the owner.\n";

fn fresh(tag: &str) -> (Wal, AuditState) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_live10a5_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("r1".to_string(), R1.as_bytes().to_vec()), ("r2".to_string(), R2.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "live-10a5", sha256(b"toy")).unwrap();
    (wal, state)
}

fn dispatcher() -> Dispatcher {
    let q = ResearchQuestion { id: "RQ1".into(), text: "What does the gate do?".into(), about: vec!["gate".into()], ..Default::default() };
    Dispatcher::new(DispatchConfig::default(), vec![q])
}

/// Every section read empty and the builder caught up: the next directive for `agent` is past the reading.
fn past_reading(d: &mut Dispatcher, s: &mut AuditState, b: &mut Builder, agent: &str) -> Value {
    loop {
        while let Some(c) = b.next_card(s) {
            b.submit(s, &c.card_id, &[]);
        }
        let t = d.acquire(s, agent, b.caught_up(s), 1);
        if t["kind"] != "EXTEND" {
            return t;
        }
        assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), agent, &[], 1)["status"], "COMMITTED");
    }
}

#[test]
fn a_question_about_a_line_of_its_own_answer_is_investigated_in_that_lines_section() {
    let (_wal, mut s) = fresh("about-local");
    let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
    let r = s.submit_records(
        "w9",
        "T90-aaaaaaaaaaaaaaaa",
        &scope,
        &[
            json!({"kind": "observe", "local_id": "t90_o1", "doc_id": "r1", "exact_quote": "The gate blocks a validator version mismatch.", "terms": ["gate"]}),
            json!({"kind": "claim", "local_id": "t90_c1", "text": "A version mismatch is blocked", "subject": "validator", "stance": "reported", "based_on": ["t90_o1"]}),
            json!({"kind": "question", "local_id": "t90_q1", "text": "Does this still hold after the later refactor?", "about": ["t90_c1"], "needed": "a later report"}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let question = r.accepted[2].short();
    assert_eq!(s.local_record("w9", "T90-aaaaaaaaaaaaaaaa", "t90_c1"), Some(r.accepted[1]));
    assert_eq!(s.local_record("w8", "T90-aaaaaaaaaaaaaaaa", "t90_c1"), None, "a local id is the agent's own");
    let mut d = dispatcher();
    let mut b = Builder::new(BuilderConfig::default());
    let t = past_reading(&mut d, &mut s, &mut b, "w1");
    assert_eq!((t["kind"].as_str(), t["key"].as_str()), (Some("INVESTIGATE"), Some(format!("question:{question}").as_str())), "{t}");
    assert!(t["prompt"].as_str().unwrap().contains("SECTION doc_id=\"r1\""), "{}", t["prompt"]);
    assert!(d.persist_unresolved(&mut s).is_empty());
    assert!(s.checkpoint(&format!("task:question:{question}")).is_none(), "not given up as a word-search miss");
}

#[test]
fn the_builder_and_the_check_share_the_link_criteria_and_the_card_says_what_may_be_mapped() {
    let (_wal, mut s) = fresh("criteria");
    let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
    let r = s.submit_records(
        "w9",
        "T90-aaaaaaaaaaaaaaaa",
        &scope,
        &[
            json!({"kind": "observe", "local_id": "o1", "doc_id": "r1", "exact_quote": "The gate blocks a validator version mismatch.", "terms": ["gate"]}),
            json!({"kind": "claim", "local_id": "c1", "text": "A version mismatch is blocked", "subject": "gate", "stance": "reported", "based_on": ["o1"]}),
            json!({"kind": "claim", "local_id": "c2", "text": "The gate is a validator check", "subject": "gate", "stance": "reported", "based_on": ["o1"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&s).expect("a card");
    let prompt = card.prompt();
    assert!(prompt.contains(LINK_CRITERIA), "{prompt}");
    assert!(prompt.contains("Its neighbors are earlier records shown for context"), "{prompt}");
    let (c1, c2) = (r.accepted[1].short(), r.accepted[2].short());
    let ops = [json!({"op": "link", "from": c1, "rel": "qualifies", "to": c2, "basis": [r.accepted[0].short()]})];
    let done = b.submit(&mut s, &card.card_id, &ops);
    assert_eq!(done["status"], "CARD_DONE", "{done}");
    let mut d = dispatcher();
    let t = d.acquire(&s, "w1", b.caught_up(&s), 1);
    assert_eq!(t["kind"], "VERIFY_LINK", "{t}");
    assert!(t["prompt"].as_str().unwrap().contains(LINK_CRITERIA), "{}", t["prompt"]);
}

#[test]
fn an_ambiguous_quote_gets_the_shortest_unique_extension_inside_its_section() {
    // live run 10A-6: a report repeats a block; the quote and its one-line extensions occur twice and the answer's other lines were lost
    let text =
        "# A\nintro words here\nArchitect disposition:\nCOMPATIBLE ONLY.\nalpha end\n# B\nother words\nArchitect disposition:\nCOMPATIBLE ONLY.\nbeta end\n";
    let split = text.find("# B").unwrap();
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_live10a6_ext_{}_{nonce}.jsonl", std::process::id())));
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), text.as_bytes().to_vec())], "ext", sha256(b"ext")).unwrap();
    let hint = |s: &AuditState, quote: &str, ranges: Vec<(String, usize, usize)>| {
        let scope = Scope { docs: vec!["d".into()], topic: None, ranges };
        let line = json!({"kind": "observe", "local_id": "o", "doc_id": "d", "exact_quote": quote, "terms": []});
        let p = sbgk_core::audit::directives::unstored_problems(s, &scope, &Default::default(), &[], std::slice::from_ref(&line), &[(0, line.clone())]);
        assert_eq!(p[0]["error"]["code"], "AMBIGUOUS_QUOTE_SPAN", "{p:?}");
        p[0].get("exact_bytes_in_section").cloned()
    };
    let longer = hint(&s, "Architect disposition:\nCOMPATIBLE ONLY.", vec![("d".into(), 0, split)]);
    // the shortest unique extension: one word to the left (44 bytes) before one to the right (45)
    assert_eq!(longer, Some(json!("here\nArchitect disposition:\nCOMPATIBLE ONLY.")));
    let scope = Scope { docs: vec!["d".into()], topic: None, ranges: vec![("d".into(), 0, split)] };
    let line = json!({"kind": "observe", "local_id": "o2", "doc_id": "d", "exact_quote": longer.unwrap(), "terms": []});
    let r = s.submit_records_id("ext-1", "w1", "T1-aaaaaaaaaaaaaaaa", &scope, &[line]);
    assert!(r.error.is_none(), "the store takes the extension: {:?}", r.error);
    // a section that is the repeated block itself has no unique extension: no hint
    let block = text.find("Architect").unwrap();
    let end = block + "Architect disposition:\nCOMPATIBLE ONLY.\n".len();
    assert_eq!(hint(&s, "COMPATIBLE ONLY.", vec![("d".into(), block, end)]), None);
}

#[test]
fn a_reading_task_tells_relation_lines_the_link_criteria() {
    let (_wal, s) = fresh("formats");
    let mut d = dispatcher();
    let t = d.acquire(&s, "w1", true, 1);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    assert!(t["prompt"].as_str().unwrap().contains(LINK_CRITERIA), "{}", t["prompt"]);
}

#[test]
fn the_repair_says_to_send_the_exact_bytes_shown() {
    // live run 10A-7: shown the unique extension of an ambiguous quote, the model extended the quote its own way, ambiguous again
    let (_wal, mut s) = fresh("repair-text");
    let mut d = dispatcher();
    let t = d.acquire(&s, "w1", true, 1);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    let (task, prefix) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
    let doc = t["prompt"].as_str().unwrap().split("doc_id=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let line = json!({"kind": "observe", "local_id": format!("{prefix}o1"), "doc_id": doc, "exact_quote": "words that are nowhere in it", "terms": []});
    let r = d.submit(&mut s, &task, "w1", &[line], 1);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
    assert!(r["repair"].as_str().unwrap().contains("Where a problem has exact_bytes_in_section, send those bytes"), "{r}");
}

#[test]
fn a_swarm_relation_with_an_observe_end_is_refused_and_the_lines_before_it_stay() {
    // Gemini's audit of 10A-9: a worker linked a quote to the claim resting on it, a path rule A1 did not cover
    let (_wal, mut s) = fresh("relation-ends");
    let mut d = dispatcher();
    let t = d.acquire(&s, "w1", true, 1);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    let (task, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
    let doc = t["prompt"].as_str().unwrap().split("doc_id=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let quote = if doc == "r1" { "The gate blocks a validator version mismatch." } else { "The release checklist was signed by the owner." };
    let lines = [
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": quote, "terms": ["x"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "It is stated", "subject": "x", "stance": "reported", "based_on": [format!("{p}o1")]}),
        json!({"kind": "relation", "local_id": format!("{p}r1"), "from": format!("{p}o1"), "rel": "qualifies", "to": format!("{p}c1"), "based_on": [format!("{p}o1")]}),
        json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "It holds", "subject": "x", "stance": "reported", "based_on": [format!("{p}o1")]}),
    ];
    let r = d.submit(&mut s, &task, "w1", &lines, 1);
    assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(2)), "{r}");
    // item by item since the consilium of 10A-17: only the relation is refused, the claim after it is stored
    assert_eq!(r["accepted"].as_array().unwrap().len(), 3, "the observe and both claims stay: {r}");
    assert_eq!(r["not_stored"], json!([format!("{p}r1")]), "{r}");
    assert!(r["problems"].as_array().unwrap().iter().any(|x| x["observe_ends"] == json!([format!("{p}o1")])), "{r}");
    // the repair: a relation between claims is stored
    let fixed = [
        json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "It holds", "subject": "x", "stance": "reported", "based_on": [format!("{p}o1")]}),
        json!({"kind": "relation", "local_id": format!("{p}r2"), "from": format!("{p}c2"), "rel": "supports", "to": format!("{p}c1"), "based_on": [format!("{p}o1")]}),
    ];
    let r = d.submit(&mut s, &task, "w1", &fixed, 1);
    assert_eq!(r["status"], "COMMITTED", "{r}");
}

#[test]
fn a_unique_extension_on_the_left_is_found_past_a_long_word_on_the_right() {
    // Codex's review of d1f2474: growing right and left in turn, a 400-byte word on the right hid a 17-byte extension on the left
    let long = "x".repeat(400);
    let text = format!("# A\nuniqueLeft SHARED {long}\n# B\nother SHARED tail\n");
    let split = text.find("# B").unwrap();
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_codexd1f_left_{}_{nonce}.jsonl", std::process::id())));
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), text.as_bytes().to_vec())], "left", sha256(b"left")).unwrap();
    let scope = Scope { docs: vec!["d".into()], topic: None, ranges: vec![("d".into(), 0, split)] };
    let line = json!({"kind": "observe", "local_id": "o", "doc_id": "d", "exact_quote": "SHARED", "terms": []});
    let p = sbgk_core::audit::directives::unstored_problems(&s, &scope, &Default::default(), &[], std::slice::from_ref(&line), &[(0, line.clone())]);
    assert_eq!(p[0].get("exact_bytes_in_section"), Some(&json!("uniqueLeft SHARED")), "{p:?}");
}
