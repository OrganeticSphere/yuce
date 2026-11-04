//! Regression for preserving the verifier-depth boundary after durable recovery.

use sbgk_core::audit::directives::{DispatchConfig, Dispatcher};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus, RecordId, RecordKind, Scope};
use sbgk_core::hash::sha256;
use serde_json::json;
use std::path::PathBuf;

struct Wal(PathBuf);

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fresh() -> (Wal, AuditState) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let wal = Wal(std::env::temp_dir().join(format!("sbgk_dispatch_recovery_review_{}_{nonce}.jsonl", std::process::id())));
    let docs = vec![("d1".to_string(), b"# First\nTopic A is reported.\n".to_vec()), ("d2".to_string(), b"# Second\nTopic B is reported.\n".to_vec())];
    let state = AuditState::create(&wal.0, &AuditOntology::base(), &docs, "dispatcher-recovery-review", sha256(b"toy-manifest")).unwrap();
    (wal, state)
}

fn seed_claim(state: &mut AuditState, actor: &str, directive: &str, doc: &str, quote: &str) -> (RecordId, RecordId) {
    let report = state.submit_records(
        actor,
        directive,
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[
            json!({"kind":"observe", "local_id":"o", "doc_id":doc, "exact_quote":quote, "terms":["topic"]}),
            json!({"kind":"claim", "local_id":"c", "text":quote, "subject":"topic", "stance":"reported", "based_on":["o"]}),
        ],
    );
    assert!(report.error.is_none(), "seed must succeed: {:?}", report.error);
    assert_eq!(report.accepted.len(), 2);
    (report.accepted[0], report.accepted[1])
}

fn dispatcher() -> Dispatcher {
    Dispatcher::new(DispatchConfig { section_bytes: 400, ..Default::default() }, Vec::new())
}

#[test]
fn recovery_preserves_the_depth_boundary_for_records_created_by_a_verifier() {
    let (wal, mut state) = fresh();
    let (first_observe, first_claim) = seed_claim(&mut state, "author-a", "seed-a", "d1", "Topic A is reported.");
    let (_, second_claim) = seed_claim(&mut state, "author-b", "seed-b", "d2", "Topic B is reported.");
    let first_link = state.add_link("builder", &first_claim, "supports", &second_claim, &[first_claim]).unwrap().id;
    let mut dispatch = dispatcher();
    let task = dispatch.acquire(&state, "verifier-one", true, 1);
    assert_eq!(task["kind"], "VERIFY_LINK", "{task}");
    assert_eq!(task["key"], format!("verify:{}", first_link.short()), "{task}");
    assert!(task["prompt"].as_str().unwrap().contains(&first_observe.short()), "the verifier's claim must cite an issued observation");
    let task_id = task["task_id"].as_str().unwrap();
    let prefix = task["local_id_prefix"].as_str().unwrap();
    let committed = dispatch.submit(
        &mut state,
        task_id,
        "verifier-one",
        &[
            json!({"kind":"claim", "local_id":format!("{prefix}judgement"), "text":"The first report establishes topic A.",
                  "subject":"topic", "stance":"reported", "based_on":[first_observe.short()]}),
            json!({"kind":"verdict", "link":first_link.short(), "verdict":"confirm", "based_on":[first_claim.short()]}),
        ],
        2,
    );
    assert_eq!(committed["status"], "COMMITTED", "the original verifier task must finish: {committed}");
    assert_eq!(state.link(&first_link).unwrap().status, LinkStatus::Accepted);
    let checkpoint_key = format!("task:verify:{}", first_link.short());
    let checkpoint = state.checkpoint(&checkpoint_key).expect("the verifier task must have a durable completion checkpoint");
    assert_eq!(checkpoint["context"]["link_task"], task["task_id"], "{checkpoint}");
    let judgement = state
        .records_since(0)
        .into_iter()
        .find(|r| r.kind == RecordKind::Claim && r.author == "verifier-one" && r.directive == task_id)
        .expect("the verifier must have created a claim in its completed task")
        .id;

    let later_link = state.add_link("builder", &judgement, "supports", &first_claim, &[judgement]).unwrap().id;
    let later_key = format!("verify:{}", later_link.short());
    assert_eq!(state.link(&later_link).unwrap().status, LinkStatus::Proposed, "the new link must remain a builder proposal");
    let before = dispatch.acquire(&state, "verifier-two", true, 3);
    assert_ne!(before["key"], later_key, "the current dispatcher must exclude links touching a verifier's records: {before}");
    assert_ne!(before["kind"], "VERIFY_LINK", "there are no other proposed links in this fixture: {before}");

    drop(dispatch);
    drop(state);
    let state = AuditState::open(&wal.0).unwrap();
    assert_eq!(state.link(&first_link).unwrap().status, LinkStatus::Accepted);
    assert_eq!(state.link(&later_link).unwrap().status, LinkStatus::Proposed);
    let checkpoint = state.checkpoint(&checkpoint_key).expect("the verifier checkpoint must survive WAL replay");
    assert_eq!(checkpoint["context"]["link_task"], task["task_id"]);
    let mut recovered = dispatcher();
    recovered.recover(&state);
    let after = recovered.acquire(&state, "verifier-two", true, 4);
    assert_ne!(
        after["key"], later_key,
        "recovery must retain the same verifier-depth boundary, instead of reissuing the excluded link; before={before}; after={after}"
    );
}
