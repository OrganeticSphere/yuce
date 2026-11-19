//! Four eyes at the acceptance of a link (0.2.3, the architect's decision of 18.11.2026, part I, A). In a run that pins it in its
//! settings, the kernel refuses a verdict on a link from the author of either end; the owner may decide one anyway, and the journal
//! marks it as an arbitration. A run that does not pin it is judged as every run before, and the settings of a run that pins it
//! cannot drop it. A replay of the journal gives the same outcomes and the same root. No provider or runner calls.
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::{AuditState, SETTINGS_CHECKPOINT};
use sbgk_core::audit::{AuditStore, LinkId, LinkStatus, RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The settings a run pins: those of `audit-serve`, with `four_eyes` as given (absent with `None`).
fn settings(four_eyes: Option<bool>) -> Value {
    let mut context = json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": 400, "section_rule": 2});
    if let Some(on) = four_eyes {
        context["four_eyes"] = json!(on);
    }
    context
}

/// Writes the settings checkpoint: what the kernel answered, or its error.
fn pin(s: &mut AuditState, id: &str, context: Value) -> Result<Value, Value> {
    s.submit_operations_id(id, "kernel", &[], Some(json!({"key": SETTINGS_CHECKPOINT, "from": 0, "to": 0, "context": context}))).map_err(|e| e.to_json())
}

/// A run of two documents whose settings pin `four_eyes` (or not), a claim of each of two authors, and two links between them the
/// graph builder proposed.
fn run(tag: &str, four_eyes: Option<bool>) -> (Wal, AuditState, [RecordId; 2], [LinkId; 2]) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_four_eyes_{tag}_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), b"# First\nTopic A is reported.\n".to_vec()), ("d2".to_string(), b"# Second\nTopic B is reported.\n".to_vec())];
    let mut s = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "four-eyes", sha256(b"toy")).unwrap();
    if four_eyes.is_some() {
        let r = pin(&mut s, "audit-mcp-coverage-config", settings(four_eyes)).unwrap();
        assert!(r["error"].is_null(), "{r}");
    }
    let mut seed = |actor: &str, doc: &str, quote: &str| {
        let r = s.submit_records(
            actor,
            &format!("seed-{actor}"),
            &Scope { docs: vec![doc.into()], ..Default::default() },
            &[
                json!({"kind": "observe", "local_id": "o", "doc_id": doc, "exact_quote": quote, "terms": ["topic"]}),
                json!({"kind": "claim", "local_id": "c", "text": quote, "subject": "topic", "stance": "reported", "based_on": ["o"]}),
            ],
        );
        assert!(r.error.is_none(), "{:?}", r.error);
        r.accepted[1]
    };
    let (a, b) = (seed("author-a", "d1", "Topic A is reported."), seed("author-b", "d2", "Topic B is reported."));
    let supports = s.add_link("builder", &a, "supports", &b, &[a]).unwrap().id;
    let qualifies = s.add_link("builder", &b, "qualifies", &a, &[b]).unwrap().id;
    (wal, s, [a, b], [supports, qualifies])
}

fn status(s: &AuditState, link: &LinkId) -> LinkStatus {
    s.link(link).unwrap().status
}

/// The journal replayed from its start, as `audit-verify` reads it, gives the state the live run had: the same links and root.
fn replays_the_same(wal: &Wal, live: &AuditState) {
    let (again, _) = AuditState::verify_states(&wal.0, &mut |_, _, _| {}).unwrap_or_else(|e| panic!("{}", e.to_json()));
    assert_eq!(again.audit_root(), live.audit_root(), "the replay gives the same root");
    let statuses = |s: &AuditState| s.links().into_iter().map(|l| (l.id, l.status)).collect::<Vec<_>>();
    assert_eq!(statuses(&again), statuses(live));
}

#[test]
fn in_a_run_that_pins_four_eyes_the_author_of_an_end_does_not_judge_the_link() {
    let (wal, mut s, [a, b], [supports, qualifies]) = run("pinned", Some(true));
    // the author of either end is refused, accepting or rejecting
    let refused = s.set_link_status(&supports, LinkStatus::Accepted, "author-a", &[a]).unwrap_err();
    assert!(refused.to_json().to_string().contains("four eyes"), "{}", refused.to_json());
    assert!(s.set_link_status(&supports, LinkStatus::Rejected, "author-b", &[b]).is_err());
    assert_eq!(status(&s, &supports), LinkStatus::Proposed);
    // a subject that wrote neither end judges it
    s.set_link_status(&supports, LinkStatus::Accepted, "verifier", &[a]).unwrap();
    assert_eq!(status(&s, &supports), LinkStatus::Accepted);
    // the owner's decision without the mark is held to the rule like any other; with it, it stands, marked in the journal
    assert!(s.decide_link(&qualifies, LinkStatus::Accepted, "author-b", &[b], false).is_err());
    s.decide_link(&qualifies, LinkStatus::Accepted, "author-b", &[b], true).unwrap();
    assert_eq!(status(&s, &qualifies), LinkStatus::Accepted);
    let journal = std::fs::read_to_string(&wal.0).unwrap();
    let arbitrated: Vec<&str> = journal.lines().filter(|l| l.contains("\"arbitration\":true")).collect();
    assert_eq!(arbitrated.len(), 1, "the arbitration is marked once in the journal");
    // the mark is true or absent
    let mut bad = json!({"kind": "set_link_status", "link": sbgk_core::hash::to_hex(&supports.0), "status": "rejected",
                         "expected_status": "accepted", "basis": [sbgk_core::hash::to_hex(&a.0)], "arbitration": false});
    let r = s.submit_operations_id("bad-mark", "verifier", &[bad.take()], None).unwrap();
    assert!(!r["error"].is_null(), "{r}");
    replays_the_same(&wal, &s);
    assert_eq!((status(&s, &supports), status(&s, &qualifies)), (LinkStatus::Accepted, LinkStatus::Accepted));
}

#[test]
fn a_run_that_does_not_pin_four_eyes_is_judged_as_before() {
    for (tag, pinned) in [("unpinned", None), ("off", Some(false))] {
        let (wal, mut s, [a, _b], [supports, qualifies]) = run(tag, pinned);
        // an author judges a link of its own claim, as every run before 0.2.3 allowed
        s.set_link_status(&supports, LinkStatus::Accepted, "author-a", &[a]).unwrap();
        assert_eq!(status(&s, &supports), LinkStatus::Accepted, "{tag}");
        // and a command with a mark these runs never had is refused, as it always was
        assert!(s.decide_link(&qualifies, LinkStatus::Accepted, "owner", &[a], true).is_err(), "{tag}");
        assert_eq!(status(&s, &qualifies), LinkStatus::Proposed, "{tag}");
        replays_the_same(&wal, &s);
    }
}

#[test]
fn the_settings_of_a_run_that_pins_four_eyes_cannot_drop_it() {
    let (wal, mut s, [a, _b], [supports, _]) = run("drop", Some(true));
    for (n, context) in [settings(None), settings(Some(false))].into_iter().enumerate() {
        let r = pin(&mut s, &format!("drop-{n}"), context);
        let refused = match r {
            Ok(v) => !v["error"].is_null(),
            Err(_) => true,
        };
        assert!(refused, "a later checkpoint of the settings without the rule is refused");
    }
    // the same settings may be written again
    let r = pin(&mut s, "again", settings(Some(true))).unwrap();
    assert!(r["error"].is_null(), "{r}");
    assert!(s.set_link_status(&supports, LinkStatus::Accepted, "author-a", &[a]).is_err(), "the rule still holds");
    replays_the_same(&wal, &s);
}
