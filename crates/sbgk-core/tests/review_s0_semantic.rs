//! S0, the deterministic semantic checks of the research of 2026-10-23, on the durable store through the dispatcher: a claim that
//! names an identifier none of its quotes holds is refused with the identifier named, the lines before it stay; a quote cut off a
//! negation or in the middle of its clause is refused with the whole clause to quote instead.

use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const DOC: &str = "# Sync\nThe base moved to 5b2d8e476f1a3c9e0b4d7f2a8c5e1b3d6f9a0c4e after PR #125.\nIt does not authorize implementation beyond the documentation scope. The gate stays open.\n";

fn task(tag: &str) -> (Wal, AuditState, Dispatcher, String, String) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_s0_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), DOC.as_bytes().to_vec())], "s0", sha256(b"s0")).unwrap();
    let q = ResearchQuestion { id: "RQ1".into(), text: "What moved?".into(), about: vec!["base".into()], ..Default::default() };
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![q]);
    let t = d.acquire(&s, "w1", true, 1);
    assert_eq!(t["kind"], "EXTEND", "{t}");
    let (id, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
    (wal, s, d, id, p)
}

fn problem<'a>(r: &'a Value, key: &str) -> &'a Value {
    r["problems"].as_array().unwrap().iter().find(|p| p.get(key).is_some()).unwrap_or_else(|| panic!("no {key} problem: {r}"))
}

#[test]
fn a_claim_naming_a_hash_its_quotes_do_not_hold_is_refused_and_the_lines_before_it_stay() {
    let (_wal, mut s, mut d, task, p) = task("ids");
    let lines = [
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "d", "exact_quote": "The base moved to 5b2d8e476f1a3c9e0b4d7f2a8c5e1b3d6f9a0c4e after PR #125.", "terms": ["base"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "The base moved from 3a7e9c21 to 5b2d8e47 after PR #125", "subject": "base", "stance": "reported", "based_on": [format!("{p}o1")]}),
        json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "The base moved to 5b2d8e47 after PR #125", "subject": "base", "stance": "reported", "based_on": [format!("{p}o1")]}),
    ];
    let r = d.submit(&mut s, &task, "w1", &lines, 1);
    assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{r}");
    assert_eq!(r["accepted"].as_array().unwrap().len(), 2, "the quote and the narrowed claim after the refused one stay: {r}");
    assert_eq!(problem(&r, "missing_identifiers")["missing_identifiers"], json!(["3a7e9c21"]), "{r}");
    assert_eq!(r["error"]["code"], "NO_EVIDENCE", "{r}");
    // the hash prefix of a quoted full hash, and #125 quoted: the narrowed claim is taken
    let r = d.submit(&mut s, &task, "w1", &lines[2..], 1);
    assert_eq!(r["status"], "COMMITTED", "{r}");
}

#[test]
fn a_quote_cut_off_its_negation_and_mid_clause_is_refused_with_the_whole_clause() {
    let (_wal, mut s, mut d, task, p) = task("clause");
    let lines = [json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "d", "exact_quote": "authorize implementation beyond", "terms": ["scope"]})];
    let r = d.submit(&mut s, &task, "w1", &lines, 1);
    assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(0)), "{r}");
    let c = problem(&r, "negation_before");
    assert_eq!(c["ends_mid_clause"], true, "{r}");
    let whole = c["exact_bytes_in_section"].as_str().expect("the whole clause");
    assert_eq!(whole, "It does not authorize implementation beyond the documentation scope.");
    let fixed = [json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "d", "exact_quote": whole, "terms": ["scope"]})];
    assert_eq!(d.submit(&mut s, &task, "w1", &fixed, 1)["status"], "COMMITTED");
}

#[test]
fn the_builder_does_not_map_a_term_to_a_concept_of_another_commit() {
    // Codex's 10A-6 analysis: validations of different commits were mapped to one concept
    use sbgk_core::audit::builder::{Builder, BuilderConfig};
    use sbgk_core::audit::{AuditStore, Scope};
    let doc = "# Heads\nThe validation of head 9e4b1d73 is stale after the correction.\nThe validation of head 2c6e0a85 is stale for the commit.\n";
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_s0_map_{}_{nonce}.jsonl", std::process::id())));
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &[("d".into(), doc.as_bytes().to_vec())], "s0map", sha256(b"s0map")).unwrap();
    let r = s.submit_records(
        "w1",
        "T1-aaaaaaaaaaaaaaaa",
        &Scope { docs: vec!["d".into()], ..Default::default() },
        &[
            json!({"kind": "observe", "local_id": "o1", "doc_id": "d", "exact_quote": "The validation of head 9e4b1d73 is stale after the correction.", "terms": ["validation of head 9e4b1d73"]}),
            json!({"kind": "observe", "local_id": "o2", "doc_id": "d", "exact_quote": "The validation of head 2c6e0a85 is stale for the commit.", "terms": ["validation of head 2c6e0a85"]}),
        ],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let (o1, o2) = (r.accepted[0].short(), r.accepted[1].short());
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&s).expect("a card");
    let ty = card.concept_types[0].clone();
    let ops = [
        json!({"op": "propose_concept", "type": ty, "name": "validation of head 9e4b1d73", "aliases": [], "basis": [o1]}),
        json!({"op": "map_term", "record": o1, "term": "validation of head 9e4b1d73", "concept": "validation of head 9e4b1d73"}),
        json!({"op": "map_term", "record": o2, "term": "validation of head 2c6e0a85", "concept": "validation of head 9e4b1d73"}),
    ];
    let out = b.submit(&mut s, &card.card_id, &ops);
    let refused = out["refused"].as_array().unwrap_or_else(|| panic!("{out}"));
    assert_eq!(refused.len(), 1, "{out}");
    assert_eq!(refused[0]["index"], 2, "{out}");
    assert!(refused[0]["error"]["message"].as_str().unwrap().contains("2c6e0a85"), "{out}");
}
