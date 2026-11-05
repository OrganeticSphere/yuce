//! Reading zones and own references (run S1.2), on the durable store: it creates the links
//! of relation lines and enforces the records a directive allows (MemStore does neither).
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::hash::sha256;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

const R1: &str = "# Classifier MVP\nDiffering validator versions -> warning only.\nSame canonical/hash remains a candidate only.\n\n# Limits\nVersion negotiation is future work.\n";
const R2: &str = "# Compatibility gate\nA validator version difference is now blocking.\n";

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Wal(std::path::PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run(cfg: DispatchConfig) -> (Wal, AuditState, Dispatcher) {
    let wal = Wal(std::env::temp_dir().join(format!("claude_zones_{}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
    assert!(!wal.0.exists());
    let docs = vec![("r1".to_string(), R1.as_bytes().to_vec()), ("r2".to_string(), R2.as_bytes().to_vec())];
    let s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "zones", sha256(b"toy")).unwrap();
    let q = ResearchQuestion { id: "RQ1".into(), text: "How did the severity change?".into(), about: vec!["validator version".into()], ..Default::default() };
    (wal, s, Dispatcher::new(cfg, vec![q]))
}

#[test]
fn a_zone_is_read_whole_by_one_task_and_its_claims_relate_across_reports() {
    let cfg = DispatchConfig { section_bytes: 80, zones: vec![vec!["r1".into(), "r2".into()]], ..Default::default() };
    let (_wal, mut s, mut d) = run(cfg);
    let t = d.acquire(&s, "w1", true, 0);
    assert_eq!((t["kind"].as_str(), t["key"].as_str()), (Some("EXTEND"), Some("zone:0")), "{t}");
    let prompt = t["prompt"].as_str().unwrap();
    assert!(prompt.contains("SECTION doc_id=\"r1\"") && prompt.contains("SECTION doc_id=\"r2\""), "both reports in one directive");
    assert!(prompt.contains("Version negotiation is future work."), "whole, past the 80-byte section cut");
    let p = t["local_id_prefix"].as_str().unwrap();
    let lines = [
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "r1", "exact_quote": "Differing validator versions -> warning only.", "terms": ["validator version"]}),
        json!({"kind": "observe", "local_id": format!("{p}o2"), "doc_id": "r2", "exact_quote": "A validator version difference is now blocking.", "terms": ["validator version"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "A validator version difference was a warning only.", "subject": "validator version",
               "stance": "reported", "based_on": [format!("{p}o1")]}),
        json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "A validator version difference is now blocking.", "subject": "validator version",
               "stance": "reported", "based_on": [format!("{p}o2")]}),
        json!({"kind": "relation", "local_id": format!("{p}r1"), "from": format!("{p}c2"), "rel": "supersedes", "to": format!("{p}c1"),
               "based_on": [format!("{p}o1"), format!("{p}o2")]}),
    ];
    let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &lines, 0);
    assert_eq!((r["status"].as_str(), r["accepted"].as_array().map(Vec::len)), (Some("COMMITTED"), Some(5)), "{r}");
    // no section task is left for a zoned report; the reader may not check its own link, another agent gets it
    assert_eq!(d.acquire(&s, "w1", true, 1)["status"], "WAIT");
    assert_eq!(d.acquire(&s, "w2", true, 2)["kind"], "VERIFY_LINK");
}

#[test]
fn own_refs_let_an_answer_cite_its_agents_earlier_records_but_no_unshown_record_of_another_agent() {
    // contract v0.1 R5 widened to "shown or own": a summary shown no record cites the observe its own agent recorded in its zone;
    // the observe of another agent stays out of reach, and without own_refs so does its own
    for own_refs in [false, true] {
        let zones = vec![vec!["r1".to_string()], vec!["r2".to_string()]];
        let cfg = DispatchConfig { section_bytes: 80, zones, summary_records: 0, summary_claims: 0, own_refs, ..Default::default() };
        let (_wal, mut s, mut d) = run(cfg);
        let mut observed = BTreeMap::new();
        for (agent, doc, quote) in
            [("w1", "r1", "Differing validator versions -> warning only."), ("w2", "r2", "A validator version difference is now blocking.")]
        {
            let t = d.acquire(&s, agent, true, 0);
            let p = t["local_id_prefix"].as_str().unwrap();
            let line = json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": quote, "terms": ["validator version"]});
            let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), agent, &[line], 0);
            assert_eq!(r["status"], "COMMITTED", "{r}");
            observed.insert(agent, r["accepted"][0].as_str().unwrap().to_string());
        }
        let t = d.acquire(&s, "w1", true, 1);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        let (id, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
        let cite = |observe: &str| {
            [
                json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "The severity changed.", "subject": "validator version", "stance": "reported",
                       "based_on": [observe]}),
                json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": id, "outcome": "answered", "answer_ids": [format!("{p}c1")]}),
            ]
        };
        let foreign = d.submit(&mut s, &id, "w1", &cite(&observed["w2"]), 2);
        assert_eq!(foreign["status"], "REPAIR_REQUIRED", "own_refs {own_refs}: another agent's unshown observe: {foreign}");
        let own = d.submit(&mut s, &id, "w1", &cite(&observed["w1"]), 3);
        assert_eq!(own["status"], if own_refs { "COMMITTED" } else { "REPAIR_REQUIRED" }, "own_refs {own_refs}: its own observe: {own}");
    }
}
