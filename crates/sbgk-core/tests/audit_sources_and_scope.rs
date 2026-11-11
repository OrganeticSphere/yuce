//! Source identity and issued-reference scope at the durable State boundary.
//! All fixtures are local toy data; a locked journal is dropped before any file read.

use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::quality::evolution;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus, RecordId, Scope, SubmitReport};
use sbgk_core::hash::{sha256, to_hex, Hash};
use sbgk_core::jcs::to_jcs;
use sbgk_core::Code;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const REPO: &str = "https://example.invalid/audit-fixture.git";
const REPORT_PATH: &str = "reports/2026-10-20_audit.md";
const REPORT: &str = "# Audit\nEvidence alpha. Evidence beta.\nSee a123456 and PR #7.\n";
const README: &str = "# Report index\n";
const SUMMARY: &str = "{}\n";

struct TempWal(PathBuf);

impl TempWal {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("r2r_sources_scope_{}_{}_{}.jsonl", std::process::id(), nonce, NEXT.fetch_add(1, Ordering::Relaxed))))
    }

    fn opaque(&self, documents: &[(String, Vec<u8>)]) -> AuditState {
        AuditState::create(&self.0, &AuditOntology::base(), documents, "scope-fixture", sha256(b"opaque fixture")).unwrap()
    }
}

impl Drop for TempWal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn entry(path: &str, text: &str, extension: &str, role: &str) -> Value {
    json!({"path":path,"extension":extension,"corpus_role":role,"size_bytes":text.len(),"raw_sha256":to_hex(&sha256(text.as_bytes()))})
}

fn manifest() -> Value {
    let mut report = entry(REPORT_PATH, REPORT, ".md", "markdown_document_candidate");
    report["references"] = json!({
        "commit_candidates":[{"hex":"a123456","line_1based":3,"column_1based":5,"syntax":["bare"],"resolution":"not_resolved"}],
        "pull_request_candidates":[{"number":7,"line_1based":3,"column_1based":20,"syntax":["hash_number"],"resolution":"not_resolved"}]
    });
    json!({"format":"r2r.tobi_corpus_metadata_manifest.v1",
        "source":{"origin_recorded":REPO,"commit":"1".repeat(40),"repository":"C:/toy-checkout"},
        "entries":[report,entry("reports/README.md",README,".md","readme_or_index_auxiliary"),
            entry("reports/summary.json",SUMMARY,".json","json_artifact")]})
}

fn identity(state: &AuditState) -> (Hash, Hash, Hash, Option<Hash>, Option<u64>, u64) {
    (state.engine_root(), state.audit_root(), state.session_root(), state.wal_head(), state.transaction_sequence(), state.head())
}

fn scope(document: &str) -> Scope {
    Scope { docs: vec![document.into()], ..Default::default() }
}

fn observe(local_id: &str, document: &str, quote: &str) -> Value {
    json!({"kind":"observe","local_id":local_id,"doc_id":document,"exact_quote":quote,"terms":["alpha"]})
}

fn claim(local_id: &str, basis: &str, text: &str) -> Value {
    json!({"kind":"claim","local_id":local_id,"text":text,"subject":"alpha","stance":"reported","based_on":[basis]})
}

fn relation(local_id: &str, from: &str, to: &str, basis: &str) -> Value {
    json!({"kind":"relation","local_id":local_id,"from":from,"rel":"supports","to":to,"based_on":[basis]})
}

fn reference(id: RecordId) -> String {
    format!("@{}", to_hex(&id.0))
}

fn accepted(report: SubmitReport) -> Vec<RecordId> {
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(report.failed_index.is_none());
    report.accepted
}

#[test]
fn a_manifest_source_persists_its_exact_tuple_unresolved_metadata_and_roots_and_cannot_be_rewritten() {
    let wal = TempWal::new();
    // Raw manifest serialization has its own identity, separate from the tuple's canonical encoding.
    let manifest_bytes = serde_json::to_vec_pretty(&manifest()).unwrap();
    let selected = [(REPORT_PATH.into(), REPORT.as_bytes().to_vec())];
    let mut state = AuditState::create_from_manifest(&wal.0, &AuditOntology::base(), "manifest-fixture", &manifest_bytes, &selected).unwrap();
    let expected_id = format!(
        "d_{}",
        to_hex(&sha256(to_jcs(&json!(["R2R-AUDIT-GIT-DOCUMENT/1", REPO, "1".repeat(40), REPORT_PATH, to_hex(&sha256(REPORT.as_bytes()))])).as_bytes()))
    );
    assert_eq!(state.docs(), std::slice::from_ref(&expected_id), "auxiliary and JSON entries were not loaded");
    let descriptor = state.source_document(&expected_id).unwrap();
    assert_eq!(descriptor["kind"], "git_manifest");
    assert_eq!(descriptor["repo"], REPO);
    assert_eq!(descriptor["commit"], "1".repeat(40));
    assert_eq!(descriptor["path"], REPORT_PATH);
    assert_eq!(descriptor["raw_sha256"], to_hex(&sha256(REPORT.as_bytes())));
    assert_eq!(descriptor["size_bytes"], REPORT.len());
    assert_eq!(descriptor["revision_refs"]["classification"], "unresolved_lexical");
    assert_eq!(descriptor["revision_refs"]["commit_candidates"][0]["resolution"], "not_resolved");
    assert_eq!(descriptor["revision_refs"]["pull_request_candidates"][0]["resolution"], "not_resolved");
    assert!(state.candidates("a123456", 10).is_empty(), "a lexical reference did not create a Revision concept");
    let observation =
        accepted(state.submit_records_id("observation", "worker", "task", &scope(&expected_id), &[observe("o", &expected_id, "Evidence alpha.")]))[0];
    let original_engine = state.engine_root();
    let original_ingest = state.head();
    let refused = state.put_document("owner", &expected_id, b"The pinned source was changed.").unwrap_err();
    assert_eq!(refused.field.as_deref(), Some("doc_id"));
    assert!(refused.message.contains("immutable"));
    assert_eq!(state.engine_root(), original_engine);
    assert_eq!(state.head(), original_ingest);
    assert_eq!(state.doc_text(&expected_id).as_deref(), Some(REPORT));
    assert_eq!(state.source_document(&expected_id), Some(descriptor.clone()));
    assert!(state.is_grounded(&observation));
    let refused_extra = state.put_document("owner", "extra", b"A document outside the selected manifest.").unwrap_err();
    assert_eq!(refused_extra.field.as_deref(), Some("doc_id"));
    assert_eq!(state.docs(), std::slice::from_ref(&expected_id), "an unselected opaque document cannot bypass the manifest boundary");
    assert!(state.doc_text("extra").is_none() && state.source_document("extra").is_none());
    assert_eq!((state.engine_root(), state.head()), (original_engine, original_ingest));
    // Refusals may themselves have durable receipts; capture the final root after the refusal.
    let expected_roots = identity(&state);
    drop(state);
    let log = std::fs::read_to_string(&wal.0).unwrap();
    let genesis: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    // a 0.2 frame holds its entry in `body`
    assert_eq!(genesis["body"]["manifest_hash"], to_hex(&sha256(&manifest_bytes)));
    assert_eq!(genesis["body"]["source_documents"][&expected_id], descriptor);
    let recovered = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&recovered), expected_roots);
    assert_eq!(recovered.docs(), std::slice::from_ref(&expected_id));
    assert_eq!(recovered.source_document(&expected_id), Some(descriptor));
    assert_eq!(recovered.doc_text(&expected_id).as_deref(), Some(REPORT));
    assert!(recovered.is_grounded(&observation));
}

#[test]
fn an_undated_manifest_keeps_its_roots_and_a_declared_date_changes_only_the_descriptor() {
    // the roots of this fixture: the engine root at 17769a8, before a manifest entry could declare a date, and the audit root of
    // the 0.2 format (`r2r-state-root/2`; the `/1` root of 0.1 was eb317f32...). An undated manifest keeps them, and the second pins
    // the bytes of the new root
    const ENGINE_ROOT: &str = "61eb4cb329a5d3a8b3bd43fdd1103c0172b6f1d0d57280002faf36661d1eef0c";
    const AUDIT_ROOT: &str = "67b1466a30c5d65a649af0df20d1f1e82b8ab16e7ff09ef87ebaa9a20f83c4c0";
    let create = |m: &Value| {
        let wal = TempWal::new();
        let selected = [(REPORT_PATH.into(), REPORT.as_bytes().to_vec())];
        let state =
            AuditState::create_from_manifest(&wal.0, &AuditOntology::base(), "manifest-fixture", &serde_json::to_vec_pretty(m).unwrap(), &selected).unwrap();
        (wal, state)
    };
    let (_undated_wal, undated) = create(&manifest());
    assert_eq!((to_hex(&undated.engine_root()), to_hex(&undated.audit_root())), (ENGINE_ROOT.to_string(), AUDIT_ROOT.to_string()));
    let id = undated.docs()[0].clone();
    assert_eq!(undated.document_date(&id), None);
    let mut m = manifest();
    m["entries"][0]["date"] = json!("2026-10-20");
    let (wal, dated) = create(&m);
    assert_eq!(dated.docs(), undated.docs(), "a date names no other document");
    assert_eq!(dated.engine_root(), undated.engine_root());
    assert_ne!(dated.audit_root(), undated.audit_root(), "the descriptor, and so the audit root, carries the date");
    assert_eq!(dated.document_date(&id).as_deref(), Some("2026-10-20"));
    let roots = identity(&dated);
    drop(dated);
    let recovered = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&recovered), roots);
    assert_eq!(recovered.document_date(&id).as_deref(), Some("2026-10-20"));
}

#[test]
fn a_front_matter_date_wins_over_the_manifest_date_and_an_undated_page_has_none() {
    let pages = [
        ("reports/a.md", "+++\ndate = \"2026-10-20\"\n+++\nAlpha.\n", Some("2025-01-01")),
        ("reports/b.md", "Beta.\n", Some("2025-01-02")),
        ("reports/c.md", "Gamma.\n", None),
    ];
    let entries = pages
        .iter()
        .map(|(p, t, d)| {
            let mut e = entry(p, t, ".md", "markdown_document_candidate");
            if let Some(d) = d {
                e["date"] = json!(d);
            }
            e
        })
        .collect::<Vec<_>>();
    let m = json!({"format":"r2r.tobi_corpus_metadata_manifest.v1","source":{"origin_recorded":REPO,"commit":"1".repeat(40)},"entries":entries});
    let wal = TempWal::new();
    let selected = pages.map(|(p, t, _)| (p.to_string(), t.as_bytes().to_vec()));
    let state = AuditState::create_from_manifest(&wal.0, &AuditOntology::base(), "dates-fixture", &serde_json::to_vec(&m).unwrap(), &selected).unwrap();
    let date = |p: &str| evolution::date(&state, &state.docs().into_iter().find(|d| state.document_label(d) == p).unwrap());
    assert_eq!(date("reports/a.md"), "2026-10-20", "the report's own front matter wins");
    assert_eq!(date("reports/b.md"), "2025-01-02");
    assert_eq!(date("reports/c.md"), "");
}

#[test]
fn mismatched_bytes_auxiliary_entries_and_unlisted_paths_refuse_before_creating_a_journal() {
    let manifest_bytes = serde_json::to_vec(&manifest()).unwrap();
    let mut changed = REPORT.as_bytes().to_vec();
    changed[0] = b'!'; // same size: the raw digest, rather than just length, must reject it
    let cases = [
        (REPORT_PATH, changed, "raw_sha256"),
        (REPORT_PATH, REPORT.as_bytes()[1..].to_vec(), "size_bytes"),
        ("reports/README.md", README.as_bytes().to_vec(), "selected"),
        ("reports/summary.json", SUMMARY.as_bytes().to_vec(), "selected"),
        ("reports/unlisted.md", REPORT.as_bytes().to_vec(), "selected"),
    ];
    for (path, bytes, field) in cases {
        let wal = TempWal::new();
        let error = AuditState::create_from_manifest(&wal.0, &AuditOntology::base(), "refused-fixture", &manifest_bytes, &[(path.into(), bytes)])
            .err()
            .expect("an invalid selected source must be refused");
        assert_eq!(error.field.as_deref(), Some(field), "{path}: {error}");
        assert!(!wal.0.exists(), "failed source preparation must not create a partial WAL");
    }
}

#[test]
fn a_foreign_record_in_the_same_document_requires_explicit_issuance() {
    let wal = TempWal::new();
    let mut state = wal.opaque(&[("report".into(), b"Evidence alpha. Evidence beta.".to_vec())]);
    let document_scope = scope("report");
    let shown = accepted(state.submit_records_id(
        "shown",
        "producer",
        "first",
        &document_scope,
        &[observe("o", "report", "Evidence alpha."), claim("a", "o", "Visible assertion.")],
    ));
    let hidden = accepted(state.submit_records_id(
        "hidden",
        "other-producer",
        "second",
        &document_scope,
        &[observe("o", "report", "Evidence beta."), claim("b", "o", "Unissued assertion.")],
    ));
    let report = state.submit_scoped_records_id(
        "limited",
        "consumer",
        "task",
        &document_scope,
        &shown,
        &[claim("c", &reference(shown[0]), "A new supported assertion."), relation("r", "c", &reference(hidden[1]), &reference(shown[0]))],
    );
    assert_eq!((report.accepted.len(), report.failed_index), (1, Some(1)));
    assert_eq!(report.error.as_ref().unwrap().field.as_deref(), Some("reference"));
    assert!(report.error.as_ref().unwrap().message.contains("not issued"));
    assert!(state.links().is_empty(), "the rejected relation must not leave a link behind");
    let prefix = report.accepted[0];
    let granted = [shown[0], shown[1], hidden[1]];
    let repaired = accepted(state.submit_scoped_records_id(
        "grant",
        "consumer",
        "task",
        &document_scope,
        &granted,
        &[relation("r", "c", &reference(hidden[1]), &reference(shown[0]))],
    ));
    assert_eq!(repaired.len(), 1);
    assert_eq!(state.record(&repaired[0]).unwrap().ends, Some((prefix, "supports".into(), hidden[1])));
    assert_eq!(state.links().len(), 1);
    assert_eq!(state.links()[0].status, LinkStatus::Proposed);
    let expected = identity(&state);
    drop(state);
    assert_eq!(identity(&AuditState::open(&wal.0).unwrap()), expected);
}

#[test]
fn an_accepted_own_prefix_can_be_repaired_with_an_issued_cone_and_no_document_scope() {
    let wal = TempWal::new();
    let mut state = wal.opaque(&[("report".into(), b"Evidence alpha.".to_vec())]);
    let issued = accepted(state.submit_records_id(
        "seed",
        "producer",
        "seed-task",
        &scope("report"),
        &[observe("o", "report", "Evidence alpha."), claim("a", "o", "An issued assertion.")],
    ));
    let prefix = state.submit_scoped_records_id(
        "prefix",
        "consumer",
        "context-only",
        &Scope::default(),
        &issued,
        &[claim("c", &reference(issued[0]), "Own accepted assertion."), claim("bad", "missing", "Refused suffix.")],
    );
    assert_eq!((prefix.accepted.len(), prefix.failed_index), (1, Some(1)));
    assert_eq!(prefix.error.unwrap().code, Code::UnknownLocalId);
    let own_claim = prefix.accepted[0];
    let expected = identity(&state);
    drop(state);
    let mut recovered = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&recovered), expected);
    let repaired = accepted(recovered.submit_scoped_records_id(
        "repair",
        "consumer",
        "context-only",
        &Scope::default(),
        &issued,
        &[relation("r", "c", &reference(issued[1]), &reference(issued[0]))],
    ));
    assert_eq!(repaired.len(), 1);
    assert_eq!(recovered.record(&repaired[0]).unwrap().ends, Some((own_claim, "supports".into(), issued[1])));
    assert_eq!(recovered.links()[0].status, LinkStatus::Proposed);
    assert_eq!(recovered.head(), 4, "the repair did not resubmit the accepted claim");
}

#[test]
fn the_legacy_document_scope_refuses_an_other_document_even_for_the_same_author_and_task() {
    let wal = TempWal::new();
    let mut state = wal.opaque(&[("visible".into(), b"Visible evidence.".to_vec()), ("other".into(), b"Other evidence.".to_vec())]);
    let other = accepted(state.submit_records_id("seed", "worker", "task", &scope("other"), &[observe("o", "other", "Other evidence.")]))[0];
    let original_ingest = state.head();
    let original_engine = state.engine_root();
    let refused = state.submit_records_id("narrow", "worker", "task", &scope("visible"), &[claim("c", &reference(other), "Outside the issued document.")]);
    assert!(refused.accepted.is_empty());
    assert_eq!(refused.failed_index, Some(0));
    assert_eq!(refused.error.unwrap().field.as_deref(), Some("reference"));
    assert_eq!((state.head(), state.engine_root()), (original_ingest, original_engine));
    let expected = identity(&state);
    drop(state);
    let recovered = AuditState::open(&wal.0).unwrap();
    assert_eq!(identity(&recovered), expected);
    assert!(recovered.is_grounded(&other));
}
