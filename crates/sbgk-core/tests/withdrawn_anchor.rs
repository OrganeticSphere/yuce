//! The withdrawn-name notice (16.11.2026): after a withdrawal, a standing claim whose words name a token that only the withdrawn
//! bytes held, and none of its own quotes, gets a notice; nothing falls by it. The kernel's extractor reads structural anchors;
//! another extractor plugs into the same mechanism.
use sbgk_core::audit::quality::withdrawn_anchor::{self, Extractor};
use sbgk_core::audit::{onto::AuditOntology, state::AuditState, AuditStore, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const DOC: &str = "Release 0.4.1 fixed E017. Release 0.4.2 broke the cache in store.rs again. Release 0.4.3 restored it.";
const WITHDRAWN: &str = "Release 0.4.2 broke the cache in store.rs again.";

/// A run of one document with the notice on or off. The claims: c1 names 0.4.1, 0.4.2 and 0.4.3 on the sentences of 0.4.1 and
/// 0.4.3 (recorded directly, so S0 at the agents' intake does not stand in the way); c2 rests on the withdrawn sentence; c3 names
/// 0.4.1 on its own sentence.
fn run(on: bool) -> (Wal, AuditState, [RecordId; 3]) {
    run_on(DOC, on)
}

fn run_on(doc: &str, on: bool) -> (Wal, AuditState, [RecordId; 3]) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!("{}-{}", std::process::id(), UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let w = Wal(std::env::temp_dir().join(format!("withdrawn-anchor-{nonce}.wal")));
    let _ = std::fs::remove_file(&w.0);
    let docs = vec![("d0".to_string(), doc.as_bytes().to_vec())];
    let mut s = AuditState::create(&w.0, &AuditOntology::base(), &docs, "wa-test", sha256(b"wa")).unwrap();
    let q: Value = if on { json!({"withdrawn_anchor": true}) } else { json!({}) };
    s.submit_operations_id(
        "config",
        "kernel",
        &[],
        Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":q,"section_bytes":6000}})),
    )
    .unwrap();
    let scope = Scope { docs: vec!["d0".into()], ..Default::default() };
    let r = s.submit_records("w1", "read0", &scope, &[
        json!({"kind":"observe","local_id":"o1","doc_id":"d0","exact_quote":"Release 0.4.1 fixed E017.","terms":["release"]}),
        json!({"kind":"observe","local_id":"o2","doc_id":"d0","exact_quote":WITHDRAWN,"terms":["release"]}),
        json!({"kind":"observe","local_id":"o3","doc_id":"d0","exact_quote":"Release 0.4.3 restored it.","terms":["release"]}),
        json!({"kind":"claim","local_id":"c1","text":"Releases 0.4.1, 0.4.2 and 0.4.3 changed the cache.","subject":"release","stance":"reported","based_on":["o1","o3"]}),
        json!({"kind":"claim","local_id":"c2","text":"0.4.2 broke the cache.","subject":"release","stance":"reported","based_on":["o2"]}),
        json!({"kind":"claim","local_id":"c3","text":"0.4.1 fixed E017.","subject":"release","stance":"reported","based_on":["o1"]}),
    ]);
    assert!(r.error.is_none(), "{r:?}");
    let ids = [r.accepted[3], r.accepted[4], r.accepted[5]];
    (w, s, ids)
}

#[test]
fn a_claim_naming_a_withdrawn_version_its_quotes_do_not_hold_gets_the_notice_and_stands() {
    let (w, mut s, [c1, c2, c3]) = run(true);
    assert!(withdrawn_anchor::flagged(&s).is_empty(), "nothing withdrawn yet");
    s.withdraw_text("owner", "d0", WITHDRAWN).unwrap();
    assert!(s.is_grounded(&c1) && !s.is_grounded(&c2) && s.is_grounded(&c3), "the withdrawal itself does what it did before");
    let found = withdrawn_anchor::flagged(&s);
    assert_eq!(found.iter().map(|(id, names, _)| (*id, names.clone())).collect::<Vec<_>>(), vec![(c1, vec!["0.4.2".to_string()])]);
    assert_eq!(withdrawn_anchor::annotation(&s, c1)["names"], json!(["0.4.2"]));
    assert!(withdrawn_anchor::annotation(&s, c3).is_null());
    let prompt = withdrawn_anchor::prompt(&s);
    assert!(prompt.contains("WITHDRAWN NAME WARNINGS") && prompt.contains(&c1.short()) && prompt.contains("0.4.2"), "{prompt}");
    // a projection of the journal: the state read again gives the same notice
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(withdrawn_anchor::flagged(&s).len(), 1);
}

#[test]
fn off_by_default_the_prompt_says_nothing_and_the_reading_tool_still_sees_it() {
    let (_w, mut s, [c1, _, _]) = run(false);
    s.withdraw_text("owner", "d0", WITHDRAWN).unwrap();
    assert!(withdrawn_anchor::flagged(&s).is_empty());
    assert!(withdrawn_anchor::prompt(&s).is_empty());
    assert_eq!(withdrawn_anchor::flagged_any(&s).iter().map(|(id, _, _)| *id).collect::<Vec<_>>(), vec![c1]);
}

#[test]
fn a_name_that_standing_text_still_holds_is_no_withdrawn_name() {
    // 0.4.2 is named again in a sentence that stands: the claim may be under-quoted, but the name is not only withdrawn text's
    let doc = format!("{DOC} Release 0.4.2 is listed in the notes.");
    let (_w, mut s, _) = run_on(&doc, true);
    s.withdraw_text("owner", "d0", WITHDRAWN).unwrap();
    assert!(withdrawn_anchor::flagged(&s).is_empty(), "{:?}", withdrawn_anchor::withdrawn_with(&s, &withdrawn_anchor::Anchors));
    assert_eq!(withdrawn_anchor::withdrawn_with(&s, &withdrawn_anchor::Anchors).into_iter().map(|(t, _)| t).collect::<Vec<_>>(), ["store.rs"]);
}

/// Another extractor through the same mechanism: here, words of a closed list.
struct Words(&'static [&'static str]);

impl Extractor for Words {
    fn tokens(&self, text: &str) -> Vec<(usize, usize, String)> {
        let mut out = Vec::new();
        for w in self.0 {
            let mut from = 0;
            while let Some(at) = text[from..].find(w) {
                out.push((from + at, from + at + w.len(), w.to_string()));
                from += at + w.len();
            }
        }
        out
    }
}

#[test]
fn another_extractor_plugs_into_the_same_overlap_of_bytes() {
    let (_w, mut s, [c1, _, _]) = run(false);
    s.withdraw_text("owner", "d0", WITHDRAWN).unwrap();
    let words = Words(&["cache", "broke", "restored"]);
    let gone: Vec<String> = withdrawn_anchor::withdrawn_with(&s, &words).into_iter().map(|(t, _)| t).collect();
    assert_eq!(gone, ["cache", "broke"], "only the words whose bytes the withdrawal covers");
    let found = withdrawn_anchor::flagged_with(&s, &words);
    assert_eq!(found.iter().map(|(id, names, _)| (*id, names.clone())).collect::<Vec<_>>(), vec![(c1, vec!["cache".to_string()])]);
}
