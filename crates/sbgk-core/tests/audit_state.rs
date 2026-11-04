//! Audit-state integration: durable receipts, source grounding, ontology growth and coordinated checkpoints.
//! The temporary journal is always unlocked before another reader inspects its bytes (Windows file locking).

use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus, RecordId, Scope, SubmitReport};
use sbgk_core::hash::{sha256, to_hex, Hash};
use sbgk_core::{journal, verify_container, Code};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const DOC: &str = "Evidence A. Evidence B. Component alpha is reported.";

struct TempWal(PathBuf);

impl TempWal {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("sbgk_audit_state_{}_{}_{}.jsonl", std::process::id(), nonce, TEMP_SEQ.fetch_add(1, Ordering::Relaxed))))
    }

    fn create(&self, docs: &[(String, Vec<u8>)]) -> AuditState {
        AuditState::create(&self.0, &AuditOntology::base(), docs, "audit-integration", sha256(b"test manifest")).unwrap()
    }
}

impl Drop for TempWal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn docs(text: &str) -> Vec<(String, Vec<u8>)> {
    vec![("report".into(), text.as_bytes().to_vec())]
}

fn scope() -> Scope {
    Scope { docs: vec!["report".into()], ..Default::default() }
}

fn observe(local: &str, quote: &str) -> Value {
    json!({"kind":"observe","local_id":local,"doc_id":"report","exact_quote":quote,"terms":["component alpha"]})
}

fn claim(local: &str, basis: &str, text: &str) -> Value {
    json!({"kind":"claim","local_id":local,"text":text,"subject":"component alpha","stance":"reported","based_on":[basis]})
}

fn done(local: &str, directive: &str, answer: &str) -> Value {
    json!({"kind":"done","local_id":local,"rq_id":"RQ1","directive_id":directive,"answer_ids":[answer],"outcome":"answered"})
}

fn ok(report: SubmitReport) -> Vec<RecordId> {
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(report.failed_index.is_none());
    report.accepted
}

fn identity(s: &AuditState) -> (Hash, Hash, Hash, Option<Hash>, Option<u64>, u64) {
    (s.audit_root(), s.engine_root(), s.session_root(), s.wal_head(), s.transaction_sequence(), s.head())
}

#[test]
fn accepted_prefix_survives_reopen_and_local_reference_repair_and_receipt_retries() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let failed = vec![observe("o", "Evidence A."), claim("c", "missing", "An assertion.")];
    let report = s.submit_records_id("initial", "w1", "T1", &scope(), &failed);
    assert_eq!((report.accepted.len(), report.failed_index), (1, Some(1)));
    assert_eq!(report.error.as_ref().unwrap().code, Code::UnknownLocalId);
    let observation = report.accepted[0];
    let before = identity(&s);
    drop(s);

    let mut s = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&s), before);
    let repaired = ok(s.submit_records_id("repair", "w1", "T1", &scope(), &[claim("c", "o", "An assertion.")]));
    assert_eq!(s.record(&repaired[0]).unwrap().based_on, [observation]);
    assert_eq!(s.head(), 2);
    s.put_document("owner", "report", b"The old evidence was withdrawn.").unwrap();
    assert!(!s.is_grounded(&observation));
    let before_retry = identity(&s);
    let retry = s.submit_records_id("initial", "w1", "T1", &scope(), &failed);
    assert_eq!((retry.accepted, retry.failed_index), (report.accepted, report.failed_index));
    assert_eq!(retry.error.unwrap().code, report.error.unwrap().code);
    assert_eq!(identity(&s), before_retry, "receipt retry precedes a now-stale quote/context check");
    let conflict = s.submit_records_id("initial", "w1", "T1", &scope(), &[observe("other", "The old evidence was withdrawn.")]);
    assert_eq!(conflict.error.unwrap().field.as_deref(), Some("submission_id"));
    assert_eq!(identity(&s), before_retry, "reusing an id for different content does not write another receipt");
}

#[test]
fn a_state_without_a_journal_refuses_every_mutation_without_changing_roots() {
    let mut s = AuditState::new(&AuditOntology::base(), &docs(DOC)).unwrap();
    let original = identity(&s);
    let report = s.submit_records_id("r", "w1", "T1", &scope(), &[observe("o", "Evidence A.")]);
    assert_eq!(report.error.unwrap().field.as_deref(), Some("wal_path"));
    assert!(s.put_document("owner", "report", b"changed").is_err());
    assert!(s.propose_concept("builder", "Component", "alpha", &[], &[]).is_err());
    assert!(s.submit_operations_id("batch", "builder", &[], Some(json!({"key":"builder","from":0,"to":0,"context":{}}))).is_err());
    assert_eq!(identity(&s), original);
    assert!(s.records_since(0).is_empty() && s.wal_head().is_none());
}

#[test]
fn unicode_quotes_use_byte_ranges_any_of_scope_and_ambiguity_does_not_touch_the_engine() {
    let wal = TempWal::new();
    let text = "\u{41f}\u{440}\u{43e}\u{43b}\u{43e}\u{433}. \u{423}\u{43d}\u{438}\u{43a}\u{430}\u{43b}\u{44c}\u{43d}\u{430}\u{44f} \u{446}\u{438}\u{442}\u{430}\u{442}\u{430}. \u{41a}\u{43e}\u{43d}\u{435}\u{446}. \u{41f}\u{43e}\u{432}\u{442}\u{43e}\u{440}. \u{41f}\u{43e}\u{432}\u{442}\u{43e}\u{440}.";
    let mut s = wal.create(&docs(text));
    let quote = "\u{423}\u{43d}\u{438}\u{43a}\u{430}\u{43b}\u{44c}\u{43d}\u{430}\u{44f} \u{446}\u{438}\u{442}\u{430}\u{442}\u{430}.";
    let start = text.find(quote).unwrap();
    let issued = Scope {
        docs: vec!["report".into()],
        topic: None,
        ranges: vec![("report".into(), 0, "\u{41f}\u{440}\u{43e}\u{43b}\u{43e}\u{433}.".len()), ("report".into(), start, start + quote.len())],
    };
    let id = ok(s.submit_records_id("unicode", "w1", "T1", &issued, &[observe("o", quote)]))[0];
    assert!(s.is_grounded(&id) && s.evidence_id(&id).is_some());
    let engine = s.engine_root();
    let ingest = s.head();
    let duplicate = s.submit_records_id("ambiguous", "w2", "T2", &scope(), &[observe("o", "\u{41f}\u{43e}\u{432}\u{442}\u{43e}\u{440}.")]);
    assert_eq!(duplicate.error.unwrap().code, Code::AmbiguousQuoteSpan);
    let wrong = Scope { docs: vec!["report".into()], topic: None, ranges: vec![("report".into(), 0, "\u{41f}\u{440}\u{43e}\u{43b}\u{43e}\u{433}.".len())] };
    assert!(s.submit_records_id("outside", "w3", "T3", &wrong, &[observe("o", quote)]).error.is_some());
    assert_eq!((s.engine_root(), s.head()), (engine, ingest), "rejected observations leave no partial engine nodes");
    assert!(verify_container(&s.engine_container()).is_ok());
    let expected = identity(&s);
    drop(s);
    assert_eq!(identity(&AuditState::open(&wal.0).unwrap()), expected);
}

#[test]
fn record_ids_keep_authorship_but_ignore_local_renaming_key_order_and_other_directives() {
    let a = TempWal::new();
    let b = TempWal::new();
    let mut first = a.create(&docs(DOC));
    let mut second = b.create(&docs(DOC));
    // A different directive adds an unrelated question without advancing this author's T1 ordinal.
    ok(second.submit_records_id(
        "unrelated",
        "other",
        "X",
        &scope(),
        &[json!({"kind":"question","local_id":"q","text":"What changed?","about":["alpha"],"needed":"Another report."})],
    ));
    let left = ok(first.submit_records_id("left", "w1", "T1", &scope(), &[observe("o1", "Evidence A."), claim("c1", "o1", "Alpha is reported.")]));
    let renamed: Value =
        serde_json::from_str(r#"{"terms":["component alpha"],"exact_quote":"Evidence A.","doc_id":"report","local_id":"renamed","kind":"observe"}"#).unwrap();
    let right = ok(second.submit_records_id("right", "w1", "T1", &scope(), &[renamed, claim("other-name", "renamed", "Alpha is reported.")]));
    assert_eq!(left, right, "server stream seq and transport local names are not identity");
    let other_author = ok(first.submit_records_id("other-author", "w2", "T1", &scope(), &[observe("o1", "Evidence A.")]));
    assert_ne!(left[0], other_author[0]);
}

#[test]
fn concepts_are_provisional_immutable_and_replayed_and_mapping_does_not_advance_ingest() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let id = ok(s.submit_records_id("records", "w1", "T1", &scope(), &[observe("o", "Evidence A.")]))[0];
    let ingest = s.head();
    let original_version = s.ontology_version();
    let concept = s.propose_concept("builder", "Component", "Alpha", &["component alpha".into()], &[id]).unwrap();
    assert_eq!(concept.status, "provisional");
    assert_ne!(s.ontology_version(), original_version);
    assert_eq!(s.head(), ingest);
    let version = s.ontology_version();
    let retry = s.propose_concept("builder", "Component", "Alpha", &["component alpha".into()], &[id]).unwrap();
    assert_eq!(retry, concept);
    assert_eq!(s.ontology_version(), version);
    assert!(s.propose_concept("builder", "Rule", "Alpha", &["component alpha".into()], &[id]).is_err());
    assert_eq!(s.concept(&concept.id).unwrap(), concept);
    let before_map = s.audit_root();
    s.map_term("builder", &id, "component alpha", &concept.id).unwrap();
    assert_ne!(s.audit_root(), before_map);
    assert_eq!(s.head(), ingest);
    assert_eq!(s.concepts_of(&id), [concept.id]);
    s.set_concept_status("owner", &concept.id, "accepted").unwrap();
    assert!(s.ontology_version().0 > version.0);
    s.set_concept_status("owner", &concept.id, "retired").unwrap();
    assert!(s.set_concept_status("owner", &concept.id, "accepted").is_err());
    let expected = identity(&s);
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&s), expected);
    let restored = s.concept(&concept.id).unwrap();
    assert_eq!(
        (restored.id, restored.ty, restored.name, restored.aliases, restored.status),
        (concept.id, concept.ty, concept.name, concept.aliases, "retired".into())
    );
    assert_eq!(s.records_of(&concept.id), [id]);
}

#[test]
fn relations_stay_proposed_three_edge_supersedes_cycles_and_unsupported_acceptance_are_refused() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let ids = ok(s.submit_records_id(
        "records",
        "w1",
        "T1",
        &scope(),
        &[
            observe("o1", "Evidence A."),
            observe("o2", "Evidence B."),
            claim("a", "o1", "First."),
            claim("b", "o1", "Second."),
            claim("c", "o1", "Third."),
            json!({"kind":"relation","local_id":"r","from":"a","rel":"supports","to":"b","based_on":["o1"]}),
        ],
    ));
    assert_eq!(s.links().len(), 1);
    assert_eq!(s.links()[0].status, LinkStatus::Proposed);
    let ab = s.add_link("builder", &ids[2], "supersedes", &ids[3], &[ids[0]]).unwrap();
    s.add_link("builder", &ids[3], "supersedes", &ids[4], &[ids[0]]).unwrap();
    let links = s.links();
    assert!(s.add_link("builder", &ids[4], "supersedes", &ids[2], &[ids[0]]).is_err());
    assert_eq!(s.links(), links);
    assert!(s.set_link_status(&ab.id, LinkStatus::Accepted, "builder", &[ids[0]]).is_err());
    s.revoke_observation("owner", &ids[0]).unwrap();
    assert!(s.is_grounded(&ids[1]) && !s.is_grounded(&ids[2]));
    assert!(s.set_link_status(&ab.id, LinkStatus::Accepted, "verifier", &[ids[1]]).is_err(), "a live but unrelated basis does not revive withdrawn endpoints");
    assert_eq!(s.link(&ab.id).unwrap().status, LinkStatus::Proposed);
}

#[test]
fn revocation_and_source_version_changes_invalidate_grounding_and_done_support_after_reopen() {
    let wal = TempWal::new();
    let mut documents = docs(DOC);
    documents.push(("second".into(), b"Other evidence.".to_vec()));
    let mut s = wal.create(&documents);
    let invalid = s.submit_records_id(
        "initial",
        "w1",
        "T1",
        &scope(),
        &[
            observe("o", "Evidence A."),
            claim("c", "o", "A grounded report."),
            json!({"kind":"hypothesis","local_id":"h","text":"An explanation.","falsifier":"Counter-evidence.","based_on":["o"]}),
            done("bad-done", "T1", "h"),
        ],
    );
    assert_eq!((invalid.accepted.len(), invalid.failed_index), (3, Some(3)));
    let terminal = ok(s.submit_records_id("answer", "w1", "T1", &scope(), &[done("done", "T1", "c")]))[0];
    assert!(s.is_grounded(&terminal));
    let other_scope = Scope { docs: vec!["second".into()], ..Default::default() };
    let other = ok(s.submit_records_id(
        "second",
        "w2",
        "T2",
        &other_scope,
        &[json!({"kind":"observe","local_id":"o","doc_id":"second","exact_quote":"Other evidence."})],
    ))[0];
    s.revoke_observation("owner", &invalid.accepted[0]).unwrap();
    assert!(!s.is_grounded(&invalid.accepted[1]) && !s.is_grounded(&terminal));
    // The quote still exists, but its recorded source version was replaced: it needs a fresh observation.
    s.put_document("owner", "second", b"Preface. Other evidence.").unwrap();
    assert!(!s.is_grounded(&other));
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    assert!(!s.is_grounded(&terminal) && !s.is_grounded(&other));
    let stale = s.submit_records_id("stale-answer", "w1", "T1", &scope(), &[done("later", "T1", "c")]);
    assert!(stale.error.is_some() && stale.accepted.is_empty());
    let unsupported = s.submit_records_id("stale-claim", "w1", "T1", &scope(), &[claim("later-claim", "o", "Another assertion.")]);
    assert_eq!(unsupported.error.unwrap().code, Code::EvidenceNotActive);
}

#[test]
fn operation_prefix_and_checkpoint_share_a_receipt_and_empty_operations_can_ack_a_card() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let observation = ok(s.submit_records_id("records", "w1", "T1", &scope(), &[observe("o", "Evidence A.")]))[0];
    let operations = vec![
        json!({"kind":"propose_concept","type":"Component","name":"alpha","aliases":["component alpha"],"basis":[to_hex(&observation.0)]}),
        json!({"kind":"not-an-operation"}),
    ];
    let checkpoint = json!({"key":"builder","from":0,"to":s.head(),"context":{"card":"C1"}});
    let result = s.submit_operations_id("prefix", "builder", &operations, Some(checkpoint.clone())).unwrap();
    assert_eq!(result["accepted_operations"], 1);
    assert_eq!(result["failed_index"], 1);
    assert_eq!(result["checkpointed"], false);
    assert!(s.checkpoint("builder").is_none());
    let concept = s.candidates("alpha", 1)[0].clone();
    let before = identity(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&s), before);
    assert_eq!(s.submit_operations_id("prefix", "builder", &operations, Some(checkpoint.clone())).unwrap(), result);
    assert_eq!(identity(&s), before, "the accepted prefix and refusal are a durable replay receipt");
    let before_map = s.audit_root();
    let mapping = json!({"kind":"map_term","record":to_hex(&observation.0),"term":"component alpha","concept":to_hex(&concept.id.0)});
    let bad_checkpoint = json!({"key":"builder","from":1,"to":s.head(),"context":{"card":"C1"}});
    let partial = s.submit_operations_id("map-prefix", "builder", &[mapping], Some(bad_checkpoint)).unwrap();
    assert_eq!(partial["accepted_operations"], 1);
    assert_eq!(partial["failed_index"], 1);
    assert_eq!(partial["checkpointed"], false);
    assert_ne!(s.audit_root(), before_map);
    assert_eq!(s.concepts_of(&observation), [concept.id]);
    assert!(s.checkpoint("builder").is_none());
    let ack = s.submit_operations_id("empty-ack", "builder", &[], Some(checkpoint.clone())).unwrap();
    assert_eq!(ack["accepted_operations"], 0);
    assert_eq!(ack["checkpointed"], true);
    assert_eq!(s.checkpoint("builder").unwrap()["to"], s.head());
    let expected = identity(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&s), expected);
    assert_eq!(s.submit_operations_id("empty-ack", "builder", &[], Some(checkpoint)).unwrap(), ack);
    assert_eq!(identity(&s), expected);
}

#[test]
fn the_legacy_v1_journal_reader_rejects_v2_without_rewriting_it() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    ok(s.submit_records_id("records", "w1", "T1", &scope(), &[observe("o", "Evidence A.")]));
    let expected = identity(&s);
    drop(s);
    let original = std::fs::read(&wal.0).unwrap();
    assert!(journal::open(&wal.0, || Err("the v2 log must never invoke fresh v1 initialization".into())).is_err());
    assert_eq!(std::fs::read(&wal.0).unwrap(), original);
    assert_eq!(identity(&AuditState::open(&wal.0).unwrap()), expected);
}

#[test]
fn a_document_can_return_to_earlier_bytes_without_reusing_an_old_mutation_receipt() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs("Version A."));
    s.put_document("owner", "report", b"Version B.").unwrap();
    let after_b = s.transaction_sequence().unwrap();
    s.put_document("owner", "report", b"Version A.").unwrap();
    assert_eq!(s.doc_text("report").as_deref(), Some("Version A."));
    assert!(s.transaction_sequence().unwrap() > after_b);
    // Repeat the whole A->B->A cycle: a convenience mutation is a fresh invocation, not an RPC receipt retry.
    s.put_document("owner", "report", b"Version B.").unwrap();
    assert_eq!(s.doc_text("report").as_deref(), Some("Version B."));
    s.put_document("owner", "report", b"Version A.").unwrap();
    assert_eq!(s.doc_text("report").as_deref(), Some("Version A."));
    let expected = identity(&s);
    drop(s);
    let s = AuditState::open(&wal.0).unwrap();
    assert_eq!(s.doc_text("report").as_deref(), Some("Version A."));
    assert_eq!(identity(&s), expected);
}

#[test]
fn relation_answers_lose_grounding_when_an_endpoint_is_revoked_or_the_link_is_later_rejected() {
    for revoke_endpoint in [true, false] {
        let wal = TempWal::new();
        let mut s = wal.create(&docs("Evidence A. Evidence B. Evidence C."));
        let ids = ok(s.submit_records_id(
            "records",
            "w1",
            "T1",
            &scope(),
            &[
                observe("oa", "Evidence A."),
                observe("ob", "Evidence B."),
                observe("independent", "Evidence C."),
                claim("a", "oa", "First claim."),
                claim("b", "ob", "Second claim."),
                json!({"kind":"relation","local_id":"relation","from":"a","rel":"qualifies","to":"b","based_on":["independent"]}),
            ],
        ));
        let link = s.links()[0].id;
        s.set_link_status(&link, LinkStatus::Accepted, "verifier", &[ids[2]]).unwrap();
        let answer = ok(s.submit_records_id("answer", "w1", "T1", &scope(), &[done("done", "T1", "relation")]))[0];
        assert!(s.is_grounded(&ids[5]) && s.is_grounded(&answer));
        if revoke_endpoint {
            s.revoke_observation("owner", &ids[0]).unwrap();
            assert!(!s.is_grounded(&ids[3]));
            assert!(!s.is_grounded(&ids[5]));
        } else {
            s.set_link_status(&link, LinkStatus::Rejected, "owner", &[ids[2]]).unwrap();
            assert!(s.is_grounded(&ids[5]), "a rejected relation can retain its structural source grounding");
        }
        assert!(s.is_grounded(&ids[2]), "the relation's independent evidence is deliberately still active");
        assert!(!s.is_answer_support(&ids[5]) && !s.link_usable(&link), "structural grounding alone is not accepted answer support");
        assert!(!s.is_grounded(&answer), "endpoint/link validity is part of the answer proof");
        drop(s);
        let mut s = AuditState::open(&wal.0).unwrap();
        assert!(!s.is_grounded(&answer));
        let refused = s.submit_records_id("later-answer", "w1", "T1", &scope(), &[done("later", "T1", "relation")]);
        assert!(refused.error.is_some() && refused.accepted.is_empty(), "withdrawn relation proof cannot support another done");
    }
}

#[test]
fn reactivating_a_rejected_supersedes_link_cannot_close_a_cycle() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let ids = ok(s.submit_records_id(
        "records",
        "w1",
        "T1",
        &scope(),
        &[observe("o", "Evidence A."), claim("a", "o", "First claim."), claim("b", "o", "Second claim.")],
    ));
    let ab = s.add_link("builder", &ids[1], "supersedes", &ids[2], &[ids[0]]).unwrap();
    s.set_link_status(&ab.id, LinkStatus::Rejected, "verifier", &[ids[0]]).unwrap();
    let ba = s.add_link("builder", &ids[2], "supersedes", &ids[1], &[ids[0]]).unwrap();
    s.set_link_status(&ba.id, LinkStatus::Accepted, "verifier", &[ids[0]]).unwrap();
    assert!(s.set_link_status(&ab.id, LinkStatus::Accepted, "owner", &[ids[0]]).is_err());
    assert_eq!(s.link(&ab.id).unwrap().status, LinkStatus::Rejected);
    assert_eq!(s.link(&ba.id).unwrap().status, LinkStatus::Accepted);
    let expected = identity(&s);
    drop(s);
    assert_eq!(identity(&AuditState::open(&wal.0).unwrap()), expected);
}

#[test]
fn relation_answer_proof_includes_original_proposal_and_verifier_basis_independently_of_record_basis() {
    for revoke_proposal in [true, false] {
        let wal = TempWal::new();
        let mut s = wal.create(&docs("Evidence A. Evidence B. Proposal evidence C. Relation evidence D. Verifier evidence V."));
        let ids = ok(s.submit_records_id(
            "records",
            "w1",
            "T1",
            &scope(),
            &[
                observe("oa", "Evidence A."),
                observe("ob", "Evidence B."),
                observe("proposal", "Proposal evidence C."),
                observe("relation-basis", "Relation evidence D."),
                observe("verification", "Verifier evidence V."),
                claim("a", "oa", "First claim."),
                claim("b", "ob", "Second claim."),
            ],
        ));
        // C justifies the original link. A later record for the same link has its own independent D evidence.
        let link = s.add_link("builder", &ids[5], "qualifies", &ids[6], &[ids[2]]).unwrap().id;
        let relation = ok(s.submit_records_id(
            "relation",
            "w1",
            "T1",
            &scope(),
            &[json!({"kind":"relation","local_id":"relation","from":"a","rel":"qualifies","to":"b","based_on":["relation-basis"]})],
        ))[0];
        s.set_link_status(&link, LinkStatus::Accepted, "verifier", &[ids[4]]).unwrap();
        assert!(s.link_usable(&link) && s.is_answer_support(&relation));
        let answer = ok(s.submit_records_id("answer", "w1", "T1", &scope(), &[done("done", "T1", "relation")]))[0];
        assert!(s.is_grounded(&answer));
        s.revoke_observation("owner", &ids[if revoke_proposal { 2 } else { 4 }]).unwrap();
        assert!(s.is_grounded(&ids[3]) && s.is_grounded(&ids[5]) && s.is_grounded(&ids[6]), "D and both endpoint proofs remain live");
        assert!(s.is_grounded(&relation), "structural record evidence remains live after C or V is withdrawn");
        assert!(!s.link_usable(&link) && !s.is_answer_support(&relation), "the effective link also requires C and V");
        assert!(!s.is_grounded(&answer));
        drop(s);
        let mut s = AuditState::open(&wal.0).unwrap();
        assert!(!s.link_usable(&link) && !s.is_answer_support(&relation) && !s.is_grounded(&answer));
        let refused = s.submit_records_id("later-answer", "w1", "T1", &scope(), &[done("later", "T1", "relation")]);
        assert!(refused.error.is_some() && refused.accepted.is_empty());
    }
}

#[test]
fn a_malformed_checkpoint_keeps_the_accepted_operation_prefix_and_durable_receipt() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let observation = ok(s.submit_records_id("records", "w1", "T1", &scope(), &[observe("o", "Evidence A.")]))[0];
    let operations = vec![json!({"kind":"propose_concept","type":"Component","name":"alpha","aliases":[],"basis":[to_hex(&observation.0)]})];
    let result = s.submit_operations_id("malformed-checkpoint", "builder", &operations, Some(json!(17))).unwrap();
    assert_eq!(result["accepted_operations"], 1);
    assert_eq!(result["failed_index"], operations.len());
    assert!(!result["error"].is_null());
    assert_eq!(result["checkpointed"], false);
    assert_eq!(s.candidates("alpha", 1).len(), 1, "checkpoint shape failure must not discard the accepted concept");
    assert!(s.checkpoint("builder").is_none());
    let expected = identity(&s);
    drop(s);
    let mut s = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&s), expected);
    assert_eq!(s.candidates("alpha", 1).len(), 1);
    assert_eq!(s.submit_operations_id("malformed-checkpoint", "builder", &operations, Some(json!(17))).unwrap(), result);
    assert_eq!(identity(&s), expected, "retry returns the same prefix/error receipt without another transaction");
}

#[test]
fn a_structurally_grounded_relation_with_a_hypothesis_endpoint_cannot_launder_verifier_evidence() {
    let wal = TempWal::new();
    let mut s = wal.create(&docs(DOC));
    let ids = ok(s.submit_records_id(
        "records",
        "w1",
        "T1",
        &scope(),
        &[
            observe("o", "Evidence A."),
            json!({"kind":"hypothesis","local_id":"h","text":"A possible explanation.","falsifier":"Counter-evidence.","based_on":["o"]}),
            claim("a", "o", "First claim."),
            claim("b", "o", "Second claim."),
            json!({"kind":"relation","local_id":"bad-relation","from":"h","rel":"supports","to":"a","based_on":["o"]}),
        ],
    ));
    assert!(s.is_grounded(&ids[1]) && s.is_grounded(&ids[4]));
    assert!(!s.is_answer_support(&ids[4]), "an active quote does not turn a hypothesis endpoint into established proof");
    let link = s.add_link("builder", &ids[2], "supports", &ids[3], &[ids[0]]).unwrap().id;
    ok(s.submit_records_id(
        "good-relation",
        "w1",
        "T1",
        &scope(),
        &[json!({"kind":"relation","local_id":"good-relation","from":"a","rel":"supports","to":"b","based_on":["o"]})],
    ));
    assert!(s.set_link_status(&link, LinkStatus::Accepted, "verifier", &[ids[4]]).is_err());
    assert_eq!(s.link(&link).unwrap().status, LinkStatus::Proposed);
    let refused = s.submit_records_id("answer", "w1", "T1", &scope(), &[done("done", "T1", "good-relation")]);
    assert!(refused.error.is_some() && refused.accepted.is_empty(), "a rejected verifier proof cannot promote a proposed relation into an answer");
    let links = s.links();
    assert!(s.add_link("builder", &ids[2], "qualifies", &ids[3], &[ids[4]]).is_err());
    assert_eq!(s.links(), links, "the builder cannot use the same hypothesis-bearing relation as proposal evidence");
}
