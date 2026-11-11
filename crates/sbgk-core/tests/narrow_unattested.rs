use sbgk_core::audit::{
    builder::{Builder, BuilderConfig},
    directives::{DispatchConfig, Dispatcher},
    onto::AuditOntology,
    state::AuditState,
    AuditStore, ConceptId, RecordId, Scope,
};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::path::PathBuf;
struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fresh(revisions: bool, attest: bool) -> (Wal, AuditState, ConceptId, ConceptId, Vec<RecordId>) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let w = Wal(std::env::temp_dir().join(format!("narrow-{n}-{}.wal", std::process::id())));
    let mut o = AuditOntology::base();
    o["seed_status"] = json!("provisional");
    o["concepts"] = json!([{"type":"Component","name":"mechanism","aliases":["runtime","machine"]},{"type":"Component","name":"unused module","aliases":[]},{"type":"Component","name":"specific engine","aliases":[]}]);
    if revisions {
        o["revision_policy"] = json!({"rule":"next_nonproposer/1","unmapped_circles":3,"catchall_mappings":2,"catchall_reports":2});
    }
    let mut s = AuditState::create(
        &w.0,
        &o,
        &[("a".into(), b"Alpha engine evidence.\nUnused alpha note.\nThe machine runs.".to_vec()), ("b".into(), b"Beta engine evidence.".to_vec())],
        "narrow-test",
        sha256(b"test"),
    )
    .unwrap();
    let mut coverage = json!({"section_bytes":6000});
    if revisions {
        coverage["circle_readers"] = json!(["w1", "w2", "w3"]);
    }
    if attest {
        coverage["unattested_at_end"] = json!(true);
    }
    checkpoint(&mut s, "policy", "audit:mcp:coverage", coverage);
    let r = s.submit_records(
        "w1",
        "seed",
        &Scope { docs: vec!["a".into(), "b".into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"a","doc_id":"a","exact_quote":"Alpha engine evidence.","terms":["runtime","machine","unused module"]}),
            json!({"kind":"observe","local_id":"b","doc_id":"b","exact_quote":"Beta engine evidence.","terms":["machine"]}),
        ],
    );
    assert!(r.error.is_none(), "{r:?}");
    let broad = s.candidates("mechanism", 1)[0].id;
    let unused = s.candidates("unused module", 1)[0].id;
    (w, s, broad, unused, r.accepted)
}
fn checkpoint(s: &mut AuditState, id: &str, key: &str, context: Value) {
    let r = s.submit_operations_id(id, "kernel", &[], Some(json!({"key":key,"from":0,"to":0,"context":context}))).unwrap();
    assert_eq!(r["checkpointed"], true, "{r}");
}
fn op(s: &mut AuditState, id: &str, v: Value) -> Value {
    s.submit_operations_id(id, "builder", &[v], None).unwrap()
}
fn map(s: &mut AuditState, id: &str, r: RecordId, c: ConceptId, t: &str) {
    let v = op(s, id, json!({"kind":"map_term","record":to_hex(&r.0),"concept":to_hex(&c.0),"term":t}));
    assert!(v["error"].is_null(), "{v}");
}
fn plan(c: ConceptId, r: RecordId) -> Value {
    json!({"kind":"revise_concept","subject":"w1","concept":to_hex(&c.0),"action":"narrow","into":[{"type":"Component","name":"alpha engine mechanism","aliases":[],"basis":[to_hex(&r.0)]}],"move":[{"record":to_hex(&r.0),"term":"runtime","to":"alpha engine mechanism"}],"basis":[to_hex(&r.0)],"reason":"Separate mechanisms using shown evidence."})
}
fn confirm(p: &Value, r: RecordId, subject: &str, action: &str) -> Value {
    json!({"kind":"revise_concept","subject":subject,"proposal":p["results"][0]["proposal"],"action":action,"basis":[to_hex(&r.0)],"reason":"Independent source check."})
}
#[test]
fn narrow_waits_for_independent_confirmation_moves_only_selected_association_and_replays() {
    let (w, mut s, b, _, r) = fresh(true, false);
    map(&mut s, "map1", r[0], b, "runtime");
    map(&mut s, "map2", r[1], b, "machine");
    let p = op(&mut s, "plan", plan(b, r[0]));
    assert!(p["error"].is_null(), "{p}");
    assert_eq!(s.concept(&b).unwrap().status, "provisional");
    assert!(s.candidates("alpha engine mechanism", 1).is_empty());
    assert_eq!(s.mapped_terms_of(&b).unwrap().len(), 2);
    let wrong = op(&mut s, "self", confirm(&p, r[0], "w1", "confirm"));
    assert!(wrong["error"].is_object());
    let done = op(&mut s, "confirm", confirm(&p, r[0], "w2", "confirm"));
    assert!(done["error"].is_null(), "{done}");
    let new = s.candidates("alpha engine mechanism", 1)[0].clone();
    assert_eq!(new.status, "provisional");
    assert_eq!(s.concept(&b).unwrap().status, "narrowed");
    assert!(s.candidates("runtime", 1).is_empty());
    assert_eq!(s.mapped_terms_of(&new.id).unwrap(), vec![(r[0], "runtime".into())]);
    assert_eq!(s.mapped_terms_of(&b).unwrap(), vec![(r[1], "machine".into())]);
    let blocked = op(&mut s, "blocked", json!({"kind":"map_term","record":to_hex(&r[0].0),"concept":to_hex(&b.0),"term":"machine"}));
    assert!(blocked["error"]["expected_by_kernel"]["narrowed_into"].is_array(), "{blocked}");
    let root = s.root();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    assert_eq!(root, s.root());
    assert_eq!(op(&mut s, "confirm", confirm(&p, r[0], "w2", "confirm")), done);
    assert_eq!(root, s.root());
    let snap = s.ontology_evolution_snapshot().unwrap();
    assert!(snap["current_mappings"].as_array().unwrap().iter().any(|m| m["on_narrowed_concept"] == true));
    assert_eq!(snap["events"].as_array().unwrap().iter().find(|e| e["status"] == "confirmed").unwrap()["proposer"], "w1");
}
#[test]
fn rejection_and_invalid_plan_never_apply_partial_concepts_or_moves() {
    let (_w, mut s, b, _, r) = fresh(true, false);
    map(&mut s, "map", r[0], b, "runtime");
    let count = s.concepts().len();
    let mut v = plan(b, r[0]);
    v["move"].as_array_mut().unwrap().push(json!({"record":to_hex(&r[1].0),"term":"machine","to":"alpha engine mechanism"}));
    assert!(op(&mut s, "invalid", v)["error"].is_object());
    assert_eq!(s.concepts().len(), count);
    let mut v = plan(b, r[0]);
    v["into"][0]["basis"] = json!([]);
    assert!(op(&mut s, "no-basis", v)["error"].is_object());
    let p = op(&mut s, "plan", plan(b, r[0]));
    assert!(op(&mut s, "reject", confirm(&p, r[0], "w2", "reject"))["error"].is_null());
    assert_eq!(s.concepts().len(), count);
    assert_eq!(s.concept(&b).unwrap().status, "provisional");
    assert_eq!(s.mapped_terms_of(&b).unwrap().len(), 1);
}
#[test]
fn withdrawal_of_nested_basis_invalidates_pending_narrow() {
    let (_w, mut s, b, _, r) = fresh(true, false);
    map(&mut s, "map", r[0], b, "runtime");
    let mut v = plan(b, r[0]);
    v["into"][0]["basis"] = json!([to_hex(&r[1].0)]);
    let p = op(&mut s, "plan", v);
    assert!(p["error"].is_null(), "{p}");
    s.revoke_observation("owner", &r[1]).unwrap();
    assert!(op(&mut s, "confirm", confirm(&p, r[0], "w2", "confirm"))["error"].is_object());
    assert_eq!(s.concept(&b).unwrap().status, "provisional");
    assert!(s.candidates("alpha engine mechanism", 1).is_empty());
    assert_eq!(s.ontology_revision_state().unwrap()["invalidated"].as_array().unwrap().len(), 1);
}
#[test]
fn builder_requires_shown_move_and_nested_evidence_then_issues_a_complete_review() {
    let (_w, mut s, b, _unused, r) = fresh(true, false);
    map(&mut s, "map", r[0], b, "runtime");
    let mut builder = Builder::new(BuilderConfig::default());
    let card = builder.next_card(&s).unwrap();
    let mut v = plan(b, r[0]);
    let m = v.as_object_mut().unwrap();
    m.remove("kind");
    m.remove("subject");
    m.insert("op".into(), json!("revise_concept"));
    v["concept"] = json!(b.short());
    v["basis"] = json!([r[0].short()]);
    v["into"][0]["basis"] = json!([r[0].short()]);
    v["move"][0]["record"] = json!(r[0].short());
    let mut bad = v.clone();
    let unseen = s.candidates("specific engine", 1)[0].id;
    assert!(!card.candidates.values().flatten().any(|c| c.id == unseen));
    bad["move"][0]["to"] = json!(to_hex(&unseen.0));
    bad["into"] = json!([]);
    let out = builder.submit_as(&mut s, &card.card_id, &[bad], Some("w1"));
    assert_eq!(out["status"], "REPAIR_REQUIRED", "{out}");
    assert!(s.candidates("alpha engine mechanism", 1).is_empty());
    let out = builder.submit_as(&mut s, &card.card_id, &[v], Some("w1"));
    assert_eq!(out["status"], "CARD_DONE", "{out}");
    let review = builder.next_card(&s).unwrap();
    assert!(review.review.is_some());
    assert!(review.neighbors.iter().any(|x| x.id == r[0]));
    let p = s.ontology_revision_state().unwrap()["pending"][0]["proposal"].clone();
    let out = builder.submit_as(
        &mut s,
        &review.card_id,
        &[json!({"op":"revise_concept","action":"confirm","proposal":p,"basis":[r[0].short()],"reason":"Independent shown quote check."})],
        Some("w2"),
    );
    assert_eq!(out["status"], "CARD_DONE", "{out}");
    assert_eq!(s.concept(&b).unwrap().status, "narrowed");
}
fn drain(s: &mut AuditState, d: &mut Dispatcher) {
    for n in 1..10 {
        let t = d.acquire(s, "reader", true, n);
        if t["kind"] != "EXTEND" {
            break;
        }
        assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), "reader", &[], n)["status"], "COMMITTED");
    }
}
#[test]
fn end_attestation_counts_stored_provisional_mappings_waits_and_reactivates_after_replay() {
    let (w, mut s, b, u, r) = fresh(false, true);
    map(&mut s, "map", r[0], b, "runtime");
    let dynamic = s.propose_concept("builder", "Component", "runtime introduced", &[], &[r[0]]).unwrap().id;
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    assert!(d.attestation_coverage(&s, true).is_none());
    drain(&mut s, &mut d);
    assert!(d.attestation_coverage(&s, false).is_none());
    let coverage = d.attestation_coverage(&s, true).unwrap();
    s.attest_at_end(coverage.clone()).unwrap();
    assert_eq!(s.concept(&b).unwrap().status, "provisional");
    assert_eq!(s.concept(&u).unwrap().status, "unattested");
    assert_eq!(s.concept(&dynamic).unwrap().status, "provisional");
    assert!(s.candidates("unused module", 1).is_empty());
    let root = s.root();
    s.attest_at_end(coverage).unwrap();
    assert_eq!(root, s.root());
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    assert_eq!(root, s.root());
    map(&mut s, "reactivate", r[0], u, "unused module");
    assert_eq!(s.concept(&u).unwrap().status, "provisional");
    assert!(!s.candidates("unused module", 1).is_empty());
    let snap = s.ontology_evolution_snapshot().unwrap();
    assert!(snap["events"].as_array().unwrap().iter().any(|e| e["status"] == "unattested"));
    let root = s.root();
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(root, s.root());
    assert_eq!(s.concept(&u).unwrap().status, "provisional");
}
#[test]
fn end_attestation_needs_the_name_in_a_report_not_a_mapping() {
    // run C0n_r1: 'database migration', named in no report, got three mappings through a shared word
    let (_w, mut s, b, _, r) = fresh(false, true);
    let specific = s.candidates("specific engine", 1)[0].id;
    map(&mut s, "shared-word", r[1], specific, "machine");
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    drain(&mut s, &mut d);
    let coverage = d.attestation_coverage(&s, true).unwrap();
    s.attest_at_end(coverage).unwrap();
    assert_eq!(s.concept(&specific).unwrap().status, "unattested", "a mapping does not attest a name no report uses");
    assert_eq!(s.concept(&b).unwrap().status, "provisional", "an alias in the text attests it");
    let snap = s.ontology_evolution_snapshot().unwrap();
    let e = snap["events"].as_array().unwrap().iter().find(|e| e["status"] == "unattested" && e["concept"] == json!(to_hex(&specific.0))).unwrap().clone();
    assert_eq!((e["reason"]["rule"].as_str(), e["reason"]["mapping_count"].as_u64()), (Some("name_or_alias_in_report_text/1"), Some(1)), "{e}");
}
#[test]
fn an_end_attestation_written_before_the_text_rule_replays_by_its_mappings() {
    // Codex review R01: by 3592a94, a seed the report names but nothing was mapped to; the rule then made it unattested
    let bytes = include_bytes!("data/unattested_3592a94.wal");
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let w = Wal(std::env::temp_dir().join(format!("legacy-attestation-{n}-{}.wal", std::process::id())));
    std::fs::write(&w.0, bytes).unwrap();
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(to_hex(&s.audit_root()), "552f9d7754faa44d3e866d5695ee9914f7107c8e951220c47095cc550d4e9118");
    assert_eq!(s.concepts()[0].status, "unattested");
    drop(s);
    assert_eq!(std::fs::read(&w.0).unwrap(), bytes, "opening does not rewrite the journal");
}
#[test]
fn disabled_attestation_does_not_write_or_change_status() {
    let (_w, mut s, _, u, _) = fresh(false, false);
    let root = s.root();
    assert!(s.attest_at_end(json!({})).unwrap().is_null());
    assert_eq!(root, s.root());
    assert_eq!(s.concept(&u).unwrap().status, "provisional");
}
#[test]
fn unread_failed_units_cannot_authorize_unattested() {
    let (_w, mut s, _, _, _) = fresh(false, true);
    let mut ck = s.checkpoint("audit:mcp:coverage").unwrap();
    ck["context"]["agent_attempts"] = json!(1);
    s.submit_operations_id("retry-policy", "kernel", &[], Some(ck)).unwrap();
    let mut d = Dispatcher::new(DispatchConfig { agent_attempts: Some(1), ..Default::default() }, vec![]);
    let t = d.acquire(&s, "reader", true, 1);
    d.timeout_task(&mut s, t["task_id"].as_str().unwrap(), "reader");
    drain(&mut s, &mut d);
    assert!(d.reading_done(&s));
    assert!(d.attestation_coverage(&s, true).is_none());
}

#[test]
fn narrowed_target_waits_for_its_own_pending_revision_and_missing_move_basis_refuses() {
    let (_w, mut s, b, target, r) = fresh(true, false);
    map(&mut s, "map", r[0], b, "runtime");
    let mut v = plan(b, r[0]);
    v["basis"] = json!([to_hex(&r[1].0)]);
    assert!(op(&mut s, "unrelated-basis", v)["error"].is_object());
    let pending = op(
        &mut s,
        "target-review",
        json!({"kind":"revise_concept","subject":"w1","concept":to_hex(&target.0),"action":"retire","basis":[to_hex(&r[0].0)],"reason":"Independent review needed."}),
    );
    assert!(pending["error"].is_null());
    let mut v = plan(b, r[0]);
    v["into"] = json!([]);
    v["move"][0]["to"] = json!(to_hex(&target.0));
    assert!(op(&mut s, "target-locked", v)["error"].is_object());
    assert_eq!(s.concept(&b).unwrap().status, "provisional");
}
#[test]
fn review_distribution_counts_all_mappings_but_limits_quote_groups_and_drops_unmapped_hints() {
    use sbgk_core::audit::builder::parallel::ParallelBuilder;
    let (_w, mut s, b, _, r) = fresh(true, false);
    let mut ck = s.checkpoint("audit:mcp:coverage").unwrap();
    ck["context"]["ontology_review"] = json!(true);
    s.submit_operations_id("reviews", "kernel", &[], Some(ck)).unwrap();
    checkpoint(&mut s, "circle", "audit:circles", json!({"circle":3,"circle_phase":"BUILD"}));
    for (i, rid) in r.iter().enumerate() {
        let term = if i == 0 { "runtime" } else { "machine" };
        let v = op(&mut s, &format!("map-{i}"), json!({"kind":"map_term","subject":"w1","record":to_hex(&rid.0),"term":term,"concept":to_hex(&b.0)}));
        assert!(v["error"].is_null(), "{v}");
    }
    let terms = (0..10).map(|n| format!("term{n}")).collect::<Vec<_>>();
    let extra = s.submit_records(
        "w1",
        "distribution-extra",
        &Scope { docs: vec!["a".into()], ..Default::default() },
        &[json!({"kind":"observe","local_id":"distribution","doc_id":"a","exact_quote":"Unused alpha note.","terms":terms})],
    );
    assert!(extra.error.is_none());
    for term in &terms {
        let v = op(
            &mut s,
            &format!("map-{term}"),
            json!({"kind":"map_term","subject":"w1","record":to_hex(&extra.accepted[0].0),"term":term,"concept":to_hex(&b.0)}),
        );
        assert!(v["error"].is_null());
    }
    let mut pool = ParallelBuilder::new(BuilderConfig::default(), vec!["w1".into(), "w2".into(), "w3".into()]);
    let mut found = None;
    for _ in 0..10 {
        let cards = pool.offers(&mut s, 3, false).unwrap();
        if let Some(c) = cards.iter().find(|c| c.to_json()["kind"] == "ONTOLOGY_REVIEW_CARD") {
            found = Some(c.clone());
            break;
        }
        for c in cards {
            let who = sbgk_core::audit::directives::circles::ring_recipient(&c, &["w1".into(), "w2".into(), "w3".into()]).unwrap();
            assert_eq!(pool.worker_mut(&c.card_id).unwrap().submit_as(&mut s, &c.card_id, &[], Some(&who))["status"], "CARD_DONE");
        }
    }
    let c = found.unwrap();
    assert_eq!(c.to_json()["prompt"].as_str().unwrap().matches("narrow requires").count(), 1);
    let spec = &c.ontology.as_ref().unwrap()["review_task"];
    let d = &spec["mapping_distribution"];
    assert_eq!(d["total_mappings"], 12);
    assert_eq!(d["by_report"].as_object().unwrap().len(), 2);
    assert!(d["term_groups"].as_array().unwrap().len() <= 8);
    assert_eq!(d["term_groups"].as_array().unwrap().len(), 8);
    assert_eq!(d["omitted_term_groups"], 4);
    assert!(!c.to_json().to_string().contains("unmapped_seed"));
    for group in d["term_groups"].as_array().unwrap() {
        let sample = group["sample"]["mapped_record"].as_str().unwrap();
        assert!(c.neighbors.iter().any(|r| r.id.short() == sample));
        let quote = group["sample"]["observe"].as_str().unwrap();
        assert!(c.neighbors.iter().any(|r| r.id.short() == quote));
    }
}

#[test]
fn attestation_with_circle_roster_requires_the_final_phase() {
    let (_w, mut s, _, u, _) = fresh(true, true);
    let coverage = json!({"reading_done":true,"waves_closed":true,"builder_caught_up":true,"unread_units":0,"read_units":2,"reports":2,"read_bytes":s.docs().iter().filter_map(|d|s.doc_text(d)).map(|s|s.len()).sum::<usize>()});
    assert!(s.attest_at_end(coverage.clone()).is_err());
    assert_eq!(s.concept(&u).unwrap().status, "provisional");
    checkpoint(&mut s, "build-phase", "audit:circles", json!({"circle":1,"circle_phase":"BUILD"}));
    assert!(s.attest_at_end(coverage.clone()).is_err());
    assert_eq!(s.concept(&u).unwrap().status, "provisional");
    checkpoint(&mut s, "final-phase", "audit:circles", json!({"circle":1,"circle_phase":"FINAL"}));
    assert!(s.attest_at_end(coverage).is_ok());
    assert_eq!(s.concept(&u).unwrap().status, "unattested");
}

#[test]
fn narrow_move_keeps_existing_identifier_scope_guards() {
    let (_w, mut s, b, _, _) = fresh(true, false);
    let term = format!("commit {}", "abcd1234".repeat(5));
    let other = format!("commit {}", "ffff5678".repeat(5));
    let got = s.submit_records(
        "w1",
        "identifier-scope",
        &Scope { docs: vec!["a".into()], ..Default::default() },
        &[json!({"kind":"observe","local_id":"o","doc_id":"a","exact_quote":"Alpha engine evidence.","terms":[term]})],
    );
    assert!(got.error.is_none());
    let r = got.accepted[0];
    map(&mut s, "map", r, b, &term);
    let mut v = plan(b, r);
    v["into"][0]["name"] = json!(other);
    v["move"][0]["term"] = json!(term);
    v["move"][0]["to"] = v["into"][0]["name"].clone();
    let out = op(&mut s, "cross-identifier", v);
    assert!(out["error"].is_object(), "{out}");
    assert_eq!(s.concept(&b).unwrap().status, "provisional");
    assert_eq!(s.concepts().len(), 3);
}

#[test]
fn narrowing_a_grounded_hypothesis_mapping_never_promotes_it_to_fact() {
    let (_w, mut s, b, _, r) = fresh(true, false);
    let got=s.submit_records("w1","hypothesis",&Scope{docs:vec!["a".into()],..Default::default()},&[json!({"kind":"hypothesis","local_id":"h","text":"A possible runtime mechanism.","subject":"runtime","stance":"open","falsifier":"A later check rules it out.","based_on":[r[0].short()]})]);
    assert!(got.error.is_none(), "{got:?}");
    let h = got.accepted[0];
    assert!(s.is_grounded(&h));
    assert!(!s.is_answer_support(&h));
    map(&mut s, "map-h", h, b, "runtime");
    let mut v = plan(b, r[0]);
    v["move"][0]["record"] = json!(to_hex(&h.0));
    let p = op(&mut s, "hypothesis-plan", v);
    assert!(p["error"].is_null(), "{p}");
    let result = op(&mut s, "hypothesis-confirm", confirm(&p, r[0], "w2", "confirm"));
    assert!(result["error"].is_null(), "{result}");
    let target = s.candidates("alpha engine mechanism", 1)[0].id;
    assert_eq!(s.mapped_terms_of(&target).unwrap(), vec![(h, "runtime".into())]);
    assert!(s.is_grounded(&h));
    assert!(!s.is_answer_support(&h));
    assert_eq!(s.record(&h).unwrap().kind, sbgk_core::audit::RecordKind::Hypothesis);
}
