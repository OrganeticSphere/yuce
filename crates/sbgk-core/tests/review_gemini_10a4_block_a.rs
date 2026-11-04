//! Regressions for block A of the 10A-4 audit (Gemini, 2026-10-23), on the durable store: a builder link connects assertions while a
//! pair keeps its different relations, a card adds a bounded number of links (also after a restart), and a summary's records are not
//! material for the builder.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{is_link_directive, is_summary_directive};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordKind, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const REPORT: &str = "# Gate\nThe gate warns on a version mismatch.\nThe gate now blocks a version mismatch.\nThe gate logs every mismatch.\n";

fn fresh(tag: &str) -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_gemini10a4_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), REPORT.as_bytes().to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "gemini-10a4", sha256(b"toy")).unwrap();
    (wal, state)
}

/// Three quotes and a claim on each, written by one task.
fn seed(s: &mut AuditState, directive: &str) {
    let mut lines = Vec::new();
    for (i, q) in ["The gate warns on a version mismatch.", "The gate now blocks a version mismatch.", "The gate logs every mismatch."].iter().enumerate() {
        lines.push(json!({"kind": "observe", "local_id": format!("o{i}"), "doc_id": "d1", "exact_quote": q, "terms": ["gate"]}));
        lines.push(json!({"kind": "claim", "local_id": format!("c{i}"), "text": format!("gate claim {i}"), "subject": "gate", "stance": "reported",
                          "based_on": [format!("o{i}")]}));
    }
    let r = s.submit_records("w1", directive, &Scope { docs: vec!["d1".into()], ..Default::default() }, &lines);
    assert!(r.error.is_none(), "{:?}", r.error);
}

fn ids(s: &AuditState, kind: RecordKind) -> Vec<String> {
    s.records_since(0).into_iter().filter(|r| r.kind == kind).map(|r| r.id.short()).collect()
}

fn link(from: &str, rel: &str, to: &str, basis: &str) -> Value {
    json!({"op": "link", "from": from, "rel": rel, "to": to, "basis": [basis]})
}

#[test]
fn a_link_connects_assertions_and_a_pair_keeps_its_different_relations() {
    let (_wal, mut s) = fresh("ends");
    seed(&mut s, "T1-aaaaaaaaaaaaaaaa");
    let (o, c) = (ids(&s, RecordKind::Observe), ids(&s, RecordKind::Claim));
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&s).unwrap();
    // a claim and its own quote: refused, the quote belongs in basis
    let r = b.submit(&mut s, &card.card_id, &[link(&c[0], "depends_on", &o[0], &o[0])]);
    assert_eq!((r["status"].as_str(), r["error"]["code"].as_str()), (Some("REPAIR_REQUIRED"), Some("BAD_FIELD")), "{r}");
    assert!(r["error"]["message"].as_str().unwrap().contains("is a observe"), "{r}");
    assert_eq!(r["error"]["expected_by_kernel"]["endpoint_kinds"], json!(["claim", "hypothesis", "relation"]));
    // different relations of one pair carry different meanings and all stay (Codex's review of block A: no unordered-pair dedupe)
    let r = b.submit(
        &mut s,
        &card.card_id,
        &[
            link(&c[1], "qualifies", &c[0], &o[1]),
            link(&c[1], "supersedes", &c[0], &o[1]),
            json!({"op": "flag_conflict", "a": c[0], "b": c[1], "basis": [o[0], o[1]]}),
        ],
    );
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert_eq!(s.links().len(), 3, "qualifies, supersedes and contradicts");
}

#[test]
fn a_card_adds_a_bounded_number_of_links_also_after_a_restart() {
    let (wal, mut s) = fresh("cap");
    seed(&mut s, "T1-bbbbbbbbbbbbbbbb");
    let (o, c) = (ids(&s, RecordKind::Observe), ids(&s, RecordKind::Claim));
    let cfg = BuilderConfig { max_links: 2, ..Default::default() };
    let mut b = Builder::new(cfg);
    let card = b.next_card(&s).unwrap();
    assert_eq!(card.max_links, 2);
    assert!(card.to_json()["prompt"].as_str().unwrap().contains("at most 2 link, mark_duplicate and flag_conflict lines"));
    let third = link(&c[2], "depends_on", &c[0], &o[2]);
    let r = b.submit(&mut s, &card.card_id, &[link(&c[1], "qualifies", &c[0], &o[1]), link(&c[2], "supports", &c[1], &o[2]), third.clone()]);
    assert_eq!((r["status"].as_str(), r["failed_index"].as_u64(), r["accepted"].as_u64()), (Some("REPAIR_REQUIRED"), Some(2), Some(2)), "{r}");
    assert_eq!(r["error"]["expected_by_kernel"]["max_links"], 2, "{r}");
    assert_eq!(s.links().len(), 2);
    // a restart counts the links the open card already made from the store
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    let mut b = Builder::new(cfg);
    b.recover(&s);
    let reopened = b.next_card(&s).unwrap();
    assert_eq!(reopened.card_id, card.card_id);
    let r = b.submit(&mut s, &reopened.card_id, &[third]);
    assert_eq!((r["status"].as_str(), r["error"]["expected_by_kernel"]["max_links"].as_u64()), (Some("REPAIR_REQUIRED"), Some(2)), "{r}");
    assert_eq!(s.links().len(), 2, "nothing over the bound after the restart either");
    assert_eq!(b.submit(&mut s, &reopened.card_id, &[])["status"], "CARD_DONE");
}

#[test]
fn a_summary_is_not_material_for_the_builder() {
    assert!(is_summary_directive("TS12-0123456789abcdef") && !is_summary_directive("T12-0123456789abcdef"));
    assert!(!is_link_directive("TS12-0123456789abcdef") && !is_summary_directive("TV3-0123456789abcdef"));
    let (_wal, mut s) = fresh("summary");
    seed(&mut s, "TS7-cccccccccccccccc");
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&s).expect("the cursor still moves over the summary");
    assert!(card.records.is_empty(), "the summary's records are not shown as new: {:?}", card.records.iter().map(|r| r.id.short()).collect::<Vec<_>>());
    assert_eq!(b.submit(&mut s, &card.card_id, &[])["status"], "CARD_DONE");
    assert!(b.caught_up(&s));
}
