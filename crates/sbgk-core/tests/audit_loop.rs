//! The audit loop on the kernel store (contract v0.1): the dispatcher hands out sections, swarm agents answer with records, the
//! graph builder links them, a non-author verifies the link, the research question is summarized, and a restart in the middle
//! loses nothing and repeats nothing. Deterministic stand-ins replace the models.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus, RecordKind};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

const APRIL: &str = "# Classifier MVP\nDiffering validator versions are reported as a warning only.\n";
const AUGUST: &str = "# Compatibility gate\nA differing validator version now blocks the comparison.\n";

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn wal(tag: &str) -> Wal {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    Wal(std::env::temp_dir().join(format!("sbgk_audit_loop_{tag}_{}_{nonce}.jsonl", std::process::id())))
}

fn questions() -> Vec<ResearchQuestion> {
    vec![ResearchQuestion {
        id: "RQ1".into(),
        text: "How did the treatment of differing validator versions change?".into(),
        about: vec!["validator version".into()],
        ..Default::default()
    }]
}

fn dispatcher() -> Dispatcher {
    Dispatcher::new(DispatchConfig { section_bytes: 400, ..Default::default() }, questions())
}

/// The stand-in swarm agent: quotes the one sentence of its section and states it.
fn answer_extend(t: &Value, docs: &[(&str, &str)]) -> Vec<Value> {
    let p = t["local_id_prefix"].as_str().unwrap();
    let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap();
    let text = docs.iter().find(|d| d.0 == doc).unwrap().1;
    let sentence = text.lines().nth(1).unwrap();
    vec![
        json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": sentence, "terms": ["validator version"]}),
        json!({"kind": "claim", "local_id": format!("{p}c1"), "text": format!("{doc}: {sentence}"), "subject": "validator version",
               "stance": "reported", "based_on": [format!("{p}o1")]}),
    ]
}

#[test]
fn the_audit_loop_closes_on_the_kernel_store_and_survives_a_restart() {
    let w = wal("main");
    let docs = [("april", APRIL), ("august", AUGUST)];
    let owned: Vec<(String, Vec<u8>)> = docs.iter().map(|(a, b)| (a.to_string(), b.as_bytes().to_vec())).collect();
    let mut s = AuditState::create(&w.0, &AuditOntology::base(), &owned, "loop", sha256(b"manifest")).unwrap();
    let (mut d, mut b) = (dispatcher(), Builder::new(BuilderConfig::default()));

    // 1. two agents cover the two reports
    for agent in ["w1", "w2"] {
        let t = d.acquire(&s, agent, b.caught_up(&s), 1);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), agent, &answer_extend(&t, &docs), 2);
        assert_eq!(r["status"], "COMMITTED", "{r}");
    }
    let claims: Vec<_> = s.records_since(0).into_iter().filter(|r| r.kind == RecordKind::Claim).collect();
    let observes: Vec<_> = s.records_since(0).into_iter().filter(|r| r.kind == RecordKind::Observe).collect();
    let (april, august) = if claims[0].text.as_deref().unwrap().starts_with("april") { (&claims[0], &claims[1]) } else { (&claims[1], &claims[0]) };

    // 2. the builder names the concept and proposes that August supersedes April
    let card = b.next_card(&s).unwrap();
    let ops = [
        json!({"op": "propose_concept", "type": "Rule", "name": "validator version difference", "aliases": ["validator version"],
               "basis": [observes[0].id.short()]}),
        json!({"op": "link", "from": august.id.short(), "rel": "supersedes", "to": april.id.short(), "basis": [august.id.short()]}),
    ];
    let r = b.submit(&mut s, &card.card_id, &ops);
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    let link = s.links().into_iter().find(|l| l.rel == "supersedes").unwrap();
    assert_eq!(link.status, LinkStatus::Proposed, "the builder's word is a proposal");

    // 3. restart: everything is reopened from the durable journal
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let (mut d, mut b) = (dispatcher(), Builder::new(BuilderConfig::default()));
    d.recover(&s);
    b.recover(&s);
    assert!(b.caught_up(&s), "the builder's cursor came back from its checkpoint");

    // 4. the authors never verify their own link; a third agent does
    let w1 = d.acquire(&s, "w1", b.caught_up(&s), 10);
    assert_ne!(w1["kind"], "VERIFY_LINK", "{w1}");
    d.release(w1["task_id"].as_str().unwrap_or(""), "w1");
    let v = d.acquire(&s, "w3", b.caught_up(&s), 11);
    assert_eq!(v["kind"], "VERIFY_LINK", "the completed EXTEND tasks were not issued again: {v}");
    let r = d.submit(
        &mut s,
        v["task_id"].as_str().unwrap(),
        "w3",
        &[json!({"kind": "verdict", "link": link.id.short(), "verdict": "confirm", "based_on": [august.id.short()]})],
        12,
    );
    assert_eq!(r["verdict"]["status"], "accepted", "{r}");
    assert!(s.link_usable(&link.id));

    // 5. the summary, then completion of all three parts
    let t = d.acquire(&s, "w4", b.caught_up(&s), 13);
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    let p = t["local_id_prefix"].as_str().unwrap();
    let r = d.submit(
        &mut s,
        t["task_id"].as_str().unwrap(),
        "w4",
        &[
            json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "August made a version difference blocking; it supersedes April's warning",
               "subject": "validator version", "stance": "superseded", "based_on": [august.based_on[0].short(), april.based_on[0].short()]}),
            json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": t["task_id"], "outcome": "answered", "answer_ids": [format!("{p}c1")]}),
        ],
        14,
    );
    assert_eq!(r["status"], "COMMITTED", "{r}");
    while let Some(c) = b.next_card(&s) {
        assert_eq!(b.submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    assert_eq!(d.acquire(&s, "w5", b.caught_up(&s), 15)["status"], "COMPLETE");
    assert_eq!(d.completion(&s, b.caught_up(&s))["complete"], true);
    let receipt = d.terminal_receipt(&s, b.cursor(), "loop").expect("complete: a terminal receipt");
    assert_eq!((receipt["ingest_watermark"].as_u64(), receipt["builder_cursor"].as_u64()), (Some(s.head()), Some(s.head())));
    assert_eq!(receipt["audit_root"], sbgk_core::hash::to_hex(&s.audit_root()));
}
