//! Owner-authorized ontology lifecycle regressions. No models or external services.
use sbgk_core::audit::builder::{parallel::ParallelBuilder, Builder, BuilderConfig};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::{AuditState, REFINER_MAP_RULE};
use sbgk_core::audit::{AuditStore, ConceptId, RecordId, Scope};
use sbgk_core::hash::{from_hex, sha256, to_hex};
use serde_json::{json, Value};
use std::path::PathBuf;
struct Fixture {
    path: PathBuf,
    s: AuditState,
    observe: RecordId,
    concept: ConceptId,
}
impl Fixture {
    fn new() -> Self {
        Self::with_concepts(json!([{"type":"Component","name":"engine","aliases":["runtime","machine"]},{"type":"Component","name":"kernel","aliases":[]}]))
    }
    fn with_concepts(concepts: Value) -> Self {
        // parallel tests can read the same clock value on Windows: a counter keeps their journals apart
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ontology_revision_{}_{}_{}.wal",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut base = AuditOntology::base();
        base["concepts"] = concepts;
        base["seed_status"] = json!("provisional");
        base["revision_policy"] = json!({"rule":"next_nonproposer/1","unmapped_circles":3,"catchall_mappings":8,"catchall_reports":2});
        let mut s =
            AuditState::create(&path, &base, &[("doc".into(), b"The engine passed validation.".to_vec())], "revision-test", sha256(b"manifest")).unwrap();
        let ck = json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"circle_readers":["w1","w2","w3"]}});
        s.submit_operations_id("roster", "kernel", &[], Some(ck)).unwrap();
        let scope = Scope { docs: vec!["doc".into()], ..Default::default() };
        let r = s.submit_records(
            "w3",
            "T1",
            &scope,
            &[json!({"kind":"observe","local_id":"o","doc_id":"doc","exact_quote":"The engine passed validation.","terms":["engine","runtime","machine"]})],
        );
        assert!(r.error.is_none(), "{r:?}");
        let observe = r.accepted[0];
        let concept = s.candidates("engine", 1)[0].id;
        Self { path, s, observe, concept }
    }
    fn reopen(&mut self) {
        let placeholder = std::env::temp_dir().join(format!(
            "replacement_{}_{}.wal",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let temporary = AuditState::create(&placeholder, &AuditOntology::base(), &[], "placeholder", sha256(b"m")).unwrap();
        let old = std::mem::replace(&mut self.s, temporary);
        drop(old);
        let old = std::mem::replace(&mut self.s, AuditState::open(&self.path).unwrap());
        drop(old);
        let _ = std::fs::remove_file(placeholder);
    }
    fn command(&mut self, id: &str, mut op: Value, subject: &str) -> Value {
        op["kind"] = json!("revise_concept");
        op["subject"] = json!(subject);
        op["basis"] = json!([to_hex(&self.observe.0)]);
        op["reason"] = json!("The shown quote distinguishes the scope.");
        self.s.submit_operations_id(id, "builder", &[op], None).unwrap()
    }
    fn proposal(&mut self, action: &str, extra: Value) -> Value {
        let mut op = json!({"concept":to_hex(&self.concept.0),"action":action});
        op.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let r = self.command("proposal", op, "w1");
        assert!(r["error"].is_null(), "{r}");
        r["results"][0].clone()
    }
}
// AuditState owns an open Windows journal. Fixture tests leave only their own temp path to process cleanup.
#[test]
fn pending_is_durable_and_self_or_wrong_neighbor_cannot_confirm() {
    let mut f = Fixture::new();
    let p = f.proposal("retire", json!({}));
    assert_eq!(p["status"], "pending");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "provisional");
    let root = f.s.audit_root();
    f.reopen();
    assert_eq!(f.s.audit_root(), root);
    for (id, who) in [("self", "w1"), ("wrong", "w3")] {
        let r = f.command(id, json!({"action":"confirm","proposal":p["proposal"]}), who);
        assert!(r["error"].is_object(), "{r}");
        assert_eq!(f.s.concept(&f.concept).unwrap().status, "provisional");
    }
    let r = f.command("confirm", json!({"action":"confirm","proposal":p["proposal"]}), "w2");
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "retired");
    let root = f.s.audit_root();
    f.reopen();
    assert_eq!(f.s.audit_root(), root);
    assert!(f.s.ontology_revision_state().unwrap()["pending"].as_array().unwrap().is_empty());
}
#[test]
fn rejection_preserves_definition_and_records_reason() {
    let mut f = Fixture::new();
    let p = f.proposal("retire", json!({}));
    let r = f.command("reject", json!({"action":"reject","proposal":p["proposal"]}), "w2");
    assert_eq!(r["results"][0]["status"], "rejected");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "provisional");
    assert!(f.s.ontology_revision_state().unwrap()["pending"].as_array().unwrap().is_empty());
}
#[test]
fn removing_alias_keeps_immutable_id_and_reservation_after_replay() {
    let mut f = Fixture::new();
    let p = f.proposal("remove_alias", json!({"alias":"runtime"}));
    let r = f.command("confirm", json!({"action":"confirm","proposal":p["proposal"]}), "w2");
    assert!(r["error"].is_null(), "{r}");
    assert!(f.s.candidates("runtime", 1).is_empty());
    assert_eq!(f.s.concept(&f.concept).unwrap().id, f.concept);
    assert!(f.s.propose_concept("w2", "Rule", "runtime", &[], &[f.observe]).is_err());
    f.reopen();
    assert!(f.s.candidates("runtime", 1).is_empty());
}
#[test]
fn merge_and_retype_preserve_old_mapping_and_name_replacement_in_refusal() {
    for retype in [false, true] {
        let mut f = Fixture::new();
        f.s.map_term("builder", &f.observe, "engine", &f.concept).unwrap();
        let extra =
            if retype { json!({"new_type":"Rule","new_name":"scoped engine rule"}) } else { json!({"target":to_hex(&f.s.candidates("kernel",1)[0].id.0)}) };
        let p = f.proposal(if retype { "retype" } else { "merge_into" }, extra);
        let r = f.command("confirm", json!({"action":"confirm","proposal":p["proposal"]}), "w2");
        assert!(r["error"].is_null(), "{r}");
        let target = ConceptId(from_hex(r["results"][0]["result"]["replacement"].as_str().unwrap()).unwrap());
        assert_ne!(f.concept, target);
        assert_eq!(f.s.concepts_of(&f.observe), vec![f.concept]);
        let err = f.s.map_term("builder", &f.observe, "runtime", &f.concept).unwrap_err().to_json();
        assert!(err.to_string().contains(&to_hex(&target.0)), "{err}");
        f.s.map_term("builder", &f.observe, "runtime", &target).unwrap();
        f.reopen();
        assert_eq!(f.s.concept(&f.concept).unwrap().status, "retired");
    }
}
#[test]
fn retype_requires_new_unique_name() {
    let mut f = Fixture::new();
    for (id, name) in [("same", "engine"), ("alias", "runtime"), ("existing", "kernel")] {
        let r = f.command(id, json!({"concept":to_hex(&f.concept.0),"action":"retype","new_type":"Rule","new_name":name}), "w1");
        assert!(r["error"].is_object(), "{r}");
    }
    let r = f.command("missing", json!({"concept":to_hex(&f.concept.0),"action":"retype","new_type":"Rule"}), "w1");
    assert!(r["error"].is_object());
}
#[test]
fn builder_scope_subject_and_oversized_review_are_refused() {
    let mut f = Fixture::new();
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&f.s).unwrap();
    assert!(card.to_json()["allowed_ops"].as_array().unwrap().contains(&json!("revise_concept")));
    let op = json!({"op":"revise_concept","concept":f.concept.short(),"action":"retire","basis":[f.observe.short()],"reason":"Shown basis."});
    let mut forged = op.clone();
    forged["subject"] = json!("w3");
    assert_eq!(b.submit_as(&mut f.s, &card.card_id, &[forged], Some("w1"))["status"], "REPAIR_REQUIRED");
    let mut bad = op.clone();
    bad["basis"] = json!(["@0000000000000000"]);
    assert_eq!(b.submit_as(&mut f.s, &card.card_id, &[bad], Some("w1"))["status"], "REPAIR_REQUIRED");
    let r = b.submit_as(&mut f.s, &card.card_id, &[op], Some("w1"));
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    let card = b.next_card(&f.s).unwrap();
    assert_eq!(card.to_json()["kind"], "REVISION_CARD");
    let pid = card.review.clone().unwrap();
    let op = json!({"op":"revise_concept","action":"confirm","proposal":pid,"basis":[f.observe.short()],"reason":"I checked the quote."});
    // An oversized review stores nothing; one authenticated explicit decision is still required.
    let r = b.submit_as(&mut f.s, &card.card_id, &[op.clone(), json!({"op":"nope"})], Some("w2"));
    assert_eq!(r["status"], "REPAIR_REQUIRED"); // max_ops rejects whole answer, nothing committed
    let r = f.command("direct-confirm", json!({"action":"confirm","proposal":pid}), "w2");
    assert!(r["error"].is_null(), "{r}");
    f.reopen();
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "retired");
}
#[test]
fn parallel_pool_issues_review_to_next_neighbor_after_tail_and_recovers() {
    let mut f = Fixture::new();
    let readers = vec!["w1".into(), "w2".into(), "w3".into()];
    let mut pool = ParallelBuilder::new(BuilderConfig { author_runs: true, ..Default::default() }, readers.clone());
    let cards = pool.offers(&mut f.s, 1, false).unwrap();
    let c = &cards[0];
    let r = pool.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[], Some("w1"));
    assert_eq!(r["status"], "CARD_DONE");
    let p = f.proposal("retire", json!({}));
    let cards = pool.offers(&mut f.s, 1, false).unwrap();
    let c = cards.iter().find(|c| c.review.is_some()).unwrap();
    assert_eq!(sbgk_core::audit::directives::circles::ring_recipient(c, &readers), Some("w2".into()));
    let id = c.card_id.clone();
    let op = json!({"op":"revise_concept","action":"confirm","proposal":p["proposal"],"basis":[f.observe.short()],"reason":"Checked the source."});
    f.reopen();
    let mut recovered = ParallelBuilder::new(BuilderConfig { author_runs: true, ..Default::default() }, readers);
    recovered.recover(&f.s).unwrap();
    use sbgk_core::jcs::to_jcs;
    let spec = f.s.checkpoint("builder:pool").unwrap()["context"]["cards"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap().clone();
    let request = to_hex(&sha256(to_jcs(&json!([op])).as_bytes()));
    let checkpoint = json!({"key":format!("builder:pool:closed:{id}"),"from":0,"to":0,"context":{"card_id":id,"request":request,"range_from":spec["from"],"range_to":spec["to"],"circle":spec["circle"],"circle_phase":spec["circle_phase"],"ring_batch":spec["batch"],"build_agent":"w2"}});
    let digest = to_hex(&sha256(to_jcs(&json!([[op], checkpoint])).as_bytes()));
    let close_id = format!("{id}:ck:{}", &digest[..16]);
    f.s.submit_operations_id(&close_id, "builder", &[], None).unwrap(); // owned fault: close id conflicts, prefix must survive
    let r = recovered.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, &[op], Some("w2"));
    assert_eq!(r["code"], "CHECKPOINT_REFUSED", "{r}");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "retired");
    f.reopen();
    let mut recovered = ParallelBuilder::new(BuilderConfig { author_runs: true, ..Default::default() }, vec!["w1".into(), "w2".into(), "w3".into()]);
    recovered.recover(&f.s).unwrap();
    let r = recovered.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, &[], Some("w2"));
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert!(recovered.caught_up(&f.s));
}
#[test]
fn legacy_schema_snapshot_has_no_new_fields_or_policy() {
    let ontology = AuditOntology::from_value(&AuditOntology::base()).unwrap();
    assert!(ontology.revision_policy().is_none());
    let v = ontology.to_value();
    assert_eq!(v.as_object().unwrap().len(), 5);
    assert_eq!(v["base"], AuditOntology::from_value(&AuditOntology::base()).unwrap().to_value()["base"]);
}

#[test]
fn pending_prevents_stale_selector_mappings_and_withdrawal_invalidates_it() {
    let mut f = Fixture::new();
    let p = f.proposal("retire", json!({}));
    let err = f.s.map_term("builder", &f.observe, "engine", &f.concept).unwrap_err();
    assert!(err.to_json().to_string().contains("pending revision"));
    f.s.revoke_observation("owner", &f.observe).unwrap();
    let snapshot = f.s.ontology_revision_state().unwrap();
    assert!(snapshot["pending"].as_array().unwrap().is_empty());
    assert_eq!(snapshot["invalidated"][0]["proposal"], p["proposal"]);
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "provisional");
    f.reopen();
    assert_eq!(f.s.ontology_revision_state().unwrap()["invalidated"].as_array().unwrap().len(), 1);
}
#[test]
fn review_failover_requires_durable_exclusion_and_still_rejects_author() {
    let mut f = Fixture::new();
    let p = f.proposal("retire", json!({}));
    let ck = json!({"key":"audit:ring-members","from":0,"to":0,"context":{"excluded":["w2"]}});
    f.s.submit_operations_id("excluded", "kernel", &[], Some(ck)).unwrap();
    let r = f.command("author", json!({"action":"confirm","proposal":p["proposal"]}), "w1");
    assert!(r["error"].is_object());
    let r = f.command("fallback", json!({"action":"confirm","proposal":p["proposal"]}), "w3");
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(r["results"][0]["reviewer_failed_over"], true);
}

#[test]
#[ignore = "explicit closed WAL copy required; no provider or live run"]
fn legacy_wal_roots_are_verified_without_reinterpreting_genesis() {
    let path = PathBuf::from(std::env::var("R2R_CLOSED_WAL").expect("closed copied WAL path"));
    let bytes = std::fs::read(&path).unwrap();
    let before = sha256(&bytes);
    let last: Value = serde_json::from_str(std::str::from_utf8(&bytes).unwrap().lines().last().unwrap()).unwrap();
    let s = AuditState::open(&path).unwrap();
    assert_eq!(to_hex(&s.audit_root()), last["payload"]["audit_root"]);
    assert!(s.ontology_revision_state().is_none());
    assert!(s.head() > 0);
    drop(s);
    assert_eq!(sha256(&std::fs::read(path).unwrap()), before);
}

#[test]
fn proposed_concept_retry_after_restart_reuses_its_original_slot_and_subject() {
    let mut f = Fixture::new();
    let cfg = BuilderConfig { max_ops: 2, ..Default::default() };
    let mut b = Builder::new(cfg);
    let c = b.next_card(&f.s).unwrap();
    let op = json!({"op":"propose_concept","type":"Rule","name":"validation invariant","aliases":[],"basis":[f.observe.short()]});
    let r = b.submit_as(&mut f.s, &c.card_id, &[op.clone(), json!({"op":"missing"})], Some("w1"));
    assert_eq!(r["status"], "REPAIR_REQUIRED");
    assert_eq!(r["committed_ops"], 1);
    f.reopen();
    let mut b = Builder::new(cfg);
    b.recover(&f.s);
    let c2 = b.next_card(&f.s).unwrap();
    assert_eq!(c2.card_id, c.card_id);
    let r = b.submit_as(&mut f.s, &c2.card_id, &[op], Some("w1"));
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert_eq!(r["results"][0]["status"], "provisional", "a stored proposal is replayed, not recategorized as new reuse");
    let state = f.s.ontology_revision_state().unwrap();
    let origin = state["ontology"]["concepts"].as_array().unwrap().iter().find(|c| c["definition"]["name"] == "validation invariant").unwrap();
    assert_eq!(origin["proposed_by"], "w1");
}

#[test]
fn mapping_inventory_counts_associations_not_calls_or_all_lexical_terms() {
    let mut f = Fixture::new();
    assert_eq!(f.s.record(&f.observe).unwrap().terms.len(), 3);
    f.s.map_term("builder", &f.observe, "engine", &f.concept).unwrap();
    f.s.map_term("builder", &f.observe, "engine", &f.concept).unwrap();
    assert_eq!(f.s.mapped_terms_of(&f.concept).unwrap(), vec![(f.observe, "engine".into())]);
    f.s.map_term("builder", &f.observe, "runtime", &f.concept).unwrap();
    assert_eq!(f.s.mapped_terms_of(&f.concept).unwrap().len(), 2);
    assert_eq!(f.s.records_of(&f.concept), vec![f.observe]);
    f.reopen();
    assert_eq!(f.s.mapped_terms_of(&f.concept).unwrap().len(), 2);
}

#[test]
fn false_merge_hint_requires_distinct_actually_mapped_aliases() {
    let mut f = Fixture::new();
    let scope = Scope { docs: vec!["doc".into()], ..Default::default() };
    let rows = [
        json!({"kind":"claim","local_id":"older","text":"An older report position.","stance":"superseded","based_on":[f.observe.short()],"subject":"runtime","object":"machine"}),
        json!({"kind":"claim","local_id":"newer","text":"A newer report position.","stance":"confirmed","based_on":[f.observe.short()],"subject":"runtime","object":"machine"}),
    ];
    let report = f.s.submit_records("w3", "T2", &scope, &rows);
    assert!(report.error.is_none(), "{report:?}");
    let a = report.accepted[0];
    let b = report.accepted[1];
    f.s.add_link("builder", &b, "supersedes", &a, &[f.observe]).unwrap();
    f.s.map_term("builder", &a, "runtime", &f.concept).unwrap();
    f.s.map_term("builder", &b, "runtime", &f.concept).unwrap();
    let card = Builder::new(BuilderConfig::default()).next_card(&f.s).unwrap();
    assert!(
        !card.ontology.unwrap()["hints"].as_array().unwrap().iter().any(|h| h["kind"] == "possible_false_merge"),
        "unmapped lexical terms are not mapping edges"
    );
    f.s.map_term("builder", &b, "machine", &f.concept).unwrap();
    let card = Builder::new(BuilderConfig::default()).next_card(&f.s).unwrap();
    assert!(card.ontology.unwrap()["hints"].as_array().unwrap().iter().any(|h| h["kind"] == "possible_false_merge"));
}

fn enable_reviews(f: &mut Fixture, circle: u64) {
    let ck = json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"circle_readers":["w1","w2","w3"],"ontology_review":true}});
    f.s.submit_operations_id(&format!("review-mode-{circle}"), "kernel", &[], Some(ck)).unwrap();
    let ck = json!({"key":"audit:circles","from":0,"to":0,"context":{"format":"r2r-circles/1","circle":circle,"circle_phase":"BUILD"}});
    f.s.submit_operations_id(&format!("review-circle-{circle}"), "kernel", &[], Some(ck)).unwrap();
}
fn review_pool() -> ParallelBuilder {
    ParallelBuilder::new(BuilderConfig { author_runs: true, ..Default::default() }, vec!["w1".into(), "w2".into(), "w3".into()])
}
fn map_as(f: &mut Fixture, key: &str, record: RecordId, term: &str, who: &str) {
    let op = json!({"kind":"map_term","record":to_hex(&record.0),"term":term,"concept":to_hex(&f.concept.0),"subject":who});
    let r = f.s.submit_operations_id(key, "builder", &[op], None).unwrap();
    assert!(r["error"].is_null(), "{r}");
}
fn false_merge_mappings(f: &mut Fixture) {
    let rows = [
        json!({"kind":"claim","local_id":"older","text":"Older position.","stance":"superseded","based_on":[f.observe.short()],"subject":"runtime","object":"machine"}),
        json!({"kind":"claim","local_id":"newer","text":"Newer position.","stance":"confirmed","based_on":[f.observe.short()],"subject":"runtime","object":"machine"}),
    ];
    let r = f.s.submit_records("w3", "claims", &Scope { docs: vec!["doc".into()], ..Default::default() }, &rows);
    assert!(r.error.is_none());
    let (a, b) = (r.accepted[0], r.accepted[1]);
    f.s.add_link("builder", &b, "supersedes", &a, &[f.observe]).unwrap();
    map_as(f, "m1", a, "runtime", "w1");
    map_as(f, "m2", b, "runtime", "w1");
    map_as(f, "m3", b, "machine", "w2");
    map_as(f, "retry-m1", a, "runtime", "w2");
    assert_eq!(f.s.mapping_authors_of(&f.concept).unwrap(), vec![("w1".into(), 2), ("w2".into(), 1)]);
}
fn first_mandatory(f: &mut Fixture, p: &mut ParallelBuilder) -> Vec<sbgk_core::audit::builder::Card> {
    for _ in 0..20 {
        let cards = p.offers(&mut f.s, 3, false).unwrap();
        if cards.iter().any(|c| c.to_json()["kind"] == "ONTOLOGY_REVIEW_CARD") {
            return cards;
        }
        for c in cards {
            let who = sbgk_core::audit::directives::circles::ring_recipient(&c, &["w1".into(), "w2".into(), "w3".into()]).unwrap();
            let r = p.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[], Some(&who));
            assert_eq!(r["status"], "CARD_DONE", "{r}");
        }
    }
    panic!("mandatory review not issued");
}
#[test]
fn review_card_shows_the_concepts_its_records_are_also_mapped_to() {
    let mut f = Fixture::with_concepts(
        json!([{"type":"Component","name":"engine","aliases":["runtime","machine"]},{"type":"Component","name":"kernel","aliases":[]},{"type":"Limitation","name":"quota","aliases":[]}]),
    );
    enable_reviews(&mut f, 3);
    false_merge_mappings(&mut f);
    // a record of the reviewed concept is also mapped to a concept of another type with no shared word
    let quota = f.s.candidates("quota", 1)[0].id;
    let mapped = f.s.mapped_terms_of(&f.concept).unwrap();
    let record = f.s.records_of(&f.concept).into_iter().find(|r| !mapped.iter().any(|(m, t)| m == r && t == "machine")).unwrap();
    let op = json!({"kind":"map_term","record":to_hex(&record.0),"term":"machine","concept":to_hex(&quota.0),"subject":"w2"});
    let r = f.s.submit_operations_id("quota-map", "builder", &[op], None).unwrap();
    assert!(r["error"].is_null(), "{r}");
    let mut p = review_pool();
    let card = first_mandatory(&mut f, &mut p).into_iter().find(|c| c.to_json()["kind"] == "ONTOLOGY_REVIEW_CARD").unwrap();
    let ids = card.ontology.as_ref().unwrap()["review_task"]["candidate_ids"].clone();
    assert_eq!(ids[1], json!(to_hex(&quota.0)), "the shared concept follows the reviewed one: {ids}");
}
#[test]
fn review_card_asks_for_a_decision_and_ordinary_cards_do_not() {
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    false_merge_mappings(&mut f);
    let mut p = review_pool();
    for c in first_mandatory(&mut f, &mut p) {
        let v = c.to_json();
        let prompt = v["prompt"].as_str().unwrap();
        let rule = prompt.contains("DECISION RULE") && prompt.contains("That a hint is not proof does not mean keep");
        assert_eq!(rule, v["kind"] == "ONTOLOGY_REVIEW_CARD", "{}", v["kind"]);
        if rule {
            assert!(prompt.find("DECISION RULE").unwrap() > prompt.find("Ontology candidates have").unwrap(), "the rule follows the cautions");
        }
    }
}
#[test]
fn mandatory_reviews_reject_empty_spoofed_or_unshown_basis_and_survive_restart() {
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    false_merge_mappings(&mut f);
    let mut p = review_pool();
    let cards = first_mandatory(&mut f, &mut p);
    let c = cards.iter().find(|c| c.ontology.as_ref().unwrap()["review_task"]["concept"] == to_hex(&f.concept.0)).unwrap().clone();
    let task = &c.ontology.as_ref().unwrap()["review_task"];
    assert_eq!(task["excluded_mappers"], json!(["w1"]));
    assert_eq!(task["reviewer"], "w2");
    let id = c.card_id.clone();
    let op = json!({"op":"keep","concept":f.concept.short(),"basis":[f.observe.short()],"reason":"Keep provisional: the shown evidence is insufficient for a change."});
    let r = p.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, &[], Some("w2"));
    assert_eq!(r["status"], "REPAIR_REQUIRED");
    assert_eq!(r["error"]["code"], "REVIEW_REQUIRED");
    let r = p.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, std::slice::from_ref(&op), Some("w1"));
    assert_eq!(r["status"], "REPAIR_REQUIRED");
    for key in ["subject", "review_id"] {
        let mut bad = op.clone();
        bad[key] = json!("forged");
        assert_eq!(p.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, &[bad], Some("w2"))["status"], "REPAIR_REQUIRED");
    }
    let mut bad = op.clone();
    bad["basis"] = json!(["@ffffffffffffffff"]);
    assert_eq!(p.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, &[bad], Some("w2"))["status"], "REPAIR_REQUIRED");
    f.reopen();
    let mut restored = review_pool();
    restored.recover(&f.s).unwrap();
    let r = restored.worker_mut(&id).unwrap().submit_as(&mut f.s, &id, &[op], Some("w2"));
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "provisional");
    let root = f.s.audit_root();
    let telemetry = f.s.circle_telemetry();
    assert!(telemetry["frames"].to_string().contains("Keep provisional"));
    assert_eq!(f.s.audit_root(), root);
    f.reopen();
    assert_eq!(f.s.circle_telemetry(), telemetry);
    assert_eq!(f.s.audit_root(), root);
    assert_eq!(f.s.mapping_authors_of(&f.concept).unwrap(), vec![("w1".into(), 2), ("w2".into(), 1)]);
    let mut restored = review_pool();
    restored.recover(&f.s).unwrap();
    for _ in 0..10 {
        let cards = restored.offers(&mut f.s, 3, false).unwrap();
        if cards.is_empty() {
            break;
        }
        for card in cards {
            let spec = &card.ontology.as_ref().unwrap()["review_task"];
            let who = spec["reviewer"].as_str().unwrap();
            let op = json!({"op":"keep","concept":spec["concept_short"],"basis":[f.observe.short()],"reason":"Keep provisional."});
            assert_eq!(restored.worker_mut(&card.card_id).unwrap().submit_as(&mut f.s, &card.card_id, &[op], Some(who))["status"], "CARD_DONE");
        }
    }
    assert!(restored.caught_up(&f.s));
    assert!(restored.offers(&mut f.s, 3, false).unwrap().is_empty());
    f.reopen();
    let mut restored = review_pool();
    restored.recover(&f.s).unwrap();
    assert!(restored.offers(&mut f.s, 3, false).unwrap().is_empty());
    enable_reviews(&mut f, 4);
    assert!(!restored.caught_up(&f.s));
    assert!(!restored.offers(&mut f.s, 4, false).unwrap().is_empty());
}
#[test]
fn mandatory_revise_creates_pending_change_for_next_nonproposer() {
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    false_merge_mappings(&mut f);
    let mut p = review_pool();
    let cards = first_mandatory(&mut f, &mut p);
    let c = cards[0].clone();
    let spec = &c.ontology.as_ref().unwrap()["review_task"];
    let who = spec["reviewer"].as_str().unwrap();
    let op = json!({"op":"revise_concept","concept":spec["concept_short"],"action":"retire","basis":[f.observe.short()],"reason":"The evidence warrants retiring this definition."});
    let r = p.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[op], Some(who));
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    let cid = ConceptId(from_hex(spec["concept"].as_str().unwrap()).unwrap());
    assert_eq!(f.s.concept(&cid).unwrap().status, "provisional");
    let pending = f.s.ontology_revision_state().unwrap()["pending"][0].clone();
    assert_ne!(pending["reviewer"], who);
    assert_eq!(f.s.ontology_revision_state().unwrap()["events"].as_array().unwrap().iter().filter(|v| v["op"] == "ontology_review").count(), 1);
    let r = f.command("self-confirm-review", json!({"action":"confirm","proposal":pending["proposal"]}), who);
    assert!(r["error"].is_object());
    f.reopen();
    let reviewer = pending["reviewer"].as_str().unwrap();
    let r = f.command("confirm-review", json!({"action":"confirm","proposal":pending["proposal"]}), reviewer);
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(f.s.concept(&cid).unwrap().status, "retired");
}
#[test]
fn disabled_reviews_keep_historical_mapping_shape_and_windows_owner_lock() {
    let mut f = Fixture::new();
    let root = f.s.audit_root();
    let before = f.s.circle_telemetry();
    assert_eq!(f.s.audit_root(), root);
    assert_eq!(before["complete"], true);
    #[cfg(windows)]
    {
        let err = std::fs::read(&f.path).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(33));
        eprintln!("WAL read blocked by this AuditState process pid={}", std::process::id());
    }
    f.s.map_term("builder", &f.observe, "engine", &f.concept).unwrap();
    assert!(f.s.mapping_authors_of(&f.concept).is_none());
    let mut op = json!({"kind":"revise_concept","subject":"w1","concept":to_hex(&f.concept.0),"action":"retire","basis":[to_hex(&f.observe.0)],"reason":"fixture","review_id":true});
    let r = f.s.submit_operations_id("bad-review-type", "builder", &[op.clone()], None).unwrap();
    assert!(r["error"].is_object());
    op["review_id"] = json!("unknown");
    let r = f.s.submit_operations_id("disabled-review", "builder", &[op], None).unwrap();
    assert!(r["error"].is_object());
}

#[test]
#[ignore = "explicit closed C1r copy required; no provider or pilot"]
fn closed_revision_wal_preserves_roots_and_telemetry_after_replay() {
    let path = PathBuf::from(std::env::var("R2R_CLOSED_WAL").unwrap());
    let raw = std::fs::read(&path).unwrap();
    let hash = sha256(&raw);
    let last: Value = serde_json::from_str(std::str::from_utf8(&raw).unwrap().lines().last().unwrap()).unwrap();
    let s = AuditState::open(&path).unwrap();
    assert_eq!(to_hex(&s.audit_root()), last["payload"]["audit_root"]);
    assert!(s.ontology_revision_state().is_some());
    assert!(!s.circle_telemetry()["frames"].as_array().unwrap().is_empty());
    eprintln!("closed C1r replay: head={} frames={}", s.head(), s.circle_telemetry()["frames"].as_array().unwrap().len());
    drop(s);
    assert_eq!(sha256(&std::fs::read(path).unwrap()), hash);
}

#[test]
fn accepted_mandatory_decision_survives_a_refused_close_checkpoint() {
    for revise in [false, true] {
        let mut f = Fixture::new();
        enable_reviews(&mut f, 3);
        false_merge_mappings(&mut f);
        let mut p = review_pool();
        let cards = first_mandatory(&mut f, &mut p);
        let c = &cards[0];
        let task = &c.ontology.as_ref().unwrap()["review_task"];
        let who = task["reviewer"].as_str().unwrap();
        let mut op = json!({"op":if revise {"revise_concept"} else {"keep"},"concept":task["concept_short"],"basis":[f.observe.short()],"reason":"Check the evidence before changing the provisional definition."});
        if revise {
            op["action"] = json!("retire");
        }
        let spec = f.s.checkpoint("builder:pool").unwrap()["context"]["cards"].as_array().unwrap().iter().find(|v| v["id"] == c.card_id).unwrap().clone();
        let request = to_hex(&sha256(sbgk_core::jcs::to_jcs(&json!([op])).as_bytes()));
        let checkpoint = json!({"key":format!("builder:pool:closed:{}",c.card_id),"from":0,"to":0,"context":{"card_id":c.card_id,"request":request,"range_from":spec["from"],"range_to":spec["to"],"circle":spec["circle"],"circle_phase":spec["circle_phase"],"ring_batch":spec["batch"],"build_agent":who}});
        let hash = to_hex(&sha256(sbgk_core::jcs::to_jcs(&json!([[op], checkpoint])).as_bytes()));
        let close_id = format!("{}:ck:{}", c.card_id, &hash[..16]);
        f.s.submit_operations_id(&close_id, "builder", &[], None).unwrap();
        let r = p.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[op], Some(who));
        assert_eq!(r["code"], "CHECKPOINT_REFUSED", "{r}");
        f.reopen();
        let mut p = review_pool();
        p.recover(&f.s).unwrap();
        assert_eq!(p.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[], Some(who))["status"], "CARD_DONE");
        assert_eq!(f.s.ontology_revision_state().unwrap()["events"].as_array().unwrap().iter().filter(|v| v["op"] == "ontology_review").count(), 1);
    }
}

#[test]
fn tied_maximum_mappers_are_all_excluded_and_no_reviewer_is_never_silently_self_assigned() {
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    false_merge_mappings(&mut f);
    let ob = f.observe;
    map_as(&mut f, "tie", ob, "engine", "w2");
    let mut p = review_pool();
    let cards = first_mandatory(&mut f, &mut p);
    let spec = &cards[0].ontology.as_ref().unwrap()["review_task"];
    assert_eq!(spec["reviewer"], "w3");
    let excluded = spec["excluded_mappers"].as_array().unwrap();
    assert!(excluded.contains(&json!("w1")) && excluded.contains(&json!("w2")));
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    false_merge_mappings(&mut f);
    let ob = f.observe;
    map_as(&mut f, "tie1", ob, "engine", "w2");
    map_as(&mut f, "tie2", ob, "runtime", "w3");
    map_as(&mut f, "tie3", ob, "machine", "w3");
    let mut p = review_pool();
    let cards = p.offers(&mut f.s, 3, false).unwrap();
    for c in cards {
        assert_eq!(p.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[], Some("w1"))["status"], "CARD_DONE");
    }
    // Every reader is a maximum mapper: the review is still issued by the circle's rotation and marked weak, not refused.
    let cards = p.offers(&mut f.s, 3, false).unwrap();
    let spec = &cards[0].ontology.as_ref().unwrap()["review_task"];
    assert_eq!(spec["reviewer_independence"], "weak_all_readers_mapped");
    let reviewer = spec["reviewer"].as_str().unwrap().to_string();
    let excluded = spec["excluded_mappers"].as_array().unwrap();
    assert_eq!(excluded.len(), 2);
    assert!(!excluded.contains(&json!(reviewer)));
    assert!(!p.caught_up(&f.s));
}
#[test]
fn circles_refiner_maps_terms_and_its_mappings_neither_block_nor_steer_the_review() {
    // Run H1p1_r2 (circles +1 with ontology reviews): every one of gb's 991 map_term was refused, "mapper must be an
    // authenticated ring subject"; a mapping by gb would also have stopped the review plan with MAPPER_OUTSIDE_RING.
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    let ck = json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"circle_readers":["w1","w2","w3"],"ontology_review":true,"circle_refiner":"gb"}});
    f.s.submit_operations_id("refiner-review-mode", "kernel", &[], Some(ck)).unwrap();
    false_merge_mappings(&mut f);
    let ob = f.observe;
    let op = |term: &str, who: &str, rule: Option<&str>| {
        let mut op = json!({"kind":"map_term","record":to_hex(&ob.0),"term":term,"concept":to_hex(&f.concept.0),"subject":who});
        if let Some(rule) = rule {
            op["rule"] = json!(rule);
        }
        op
    };
    // without the rule a map by gb is judged as before the rule, with the same refusal (Codex's consilium 28.10, D02)
    let r = f.s.submit_operations_id("gb-unruled", "builder", &[op("engine", "gb", None)], None).unwrap();
    assert_eq!(r["error"]["message"], "mapper must be an authenticated ring subject", "{r}");
    for (key, term) in [("gb-1", "engine"), ("gb-2", "runtime"), ("gb-3", "machine")] {
        let r = f.s.submit_operations_id(key, "builder", &[op(term, "gb", Some(REFINER_MAP_RULE))], None).unwrap();
        assert!(r["error"].is_null(), "{r}");
    }
    // the rule does not make anyone the refiner, and an unknown rule is refused
    for (key, who, rule) in [("outsider-map", "zz", REFINER_MAP_RULE), ("other-rule", "gb", "anything/1")] {
        let r = f.s.submit_operations_id(key, "builder", &[op("engine", who, Some(rule))], None).unwrap();
        assert_eq!(r["error"]["code"], "BAD_FIELD", "{r}");
    }
    assert_eq!(f.s.mapping_authors_of(&f.concept).unwrap(), vec![("gb".into(), 3), ("w1".into(), 2), ("w2".into(), 1)]);
    let mut p = review_pool();
    let cards = first_mandatory(&mut f, &mut p);
    let c = cards.iter().find(|c| c.ontology.as_ref().unwrap()["review_task"]["concept"] == to_hex(&f.concept.0)).unwrap();
    let task = &c.ontology.as_ref().unwrap()["review_task"];
    // the same reviewer as without gb: w1 is the readers' maximum mapper, w2 its next neighbor
    assert_eq!(task["excluded_mappers"], json!(["w1"]));
    assert_eq!(task["reviewer"], "w2");
}
#[test]
fn the_builder_names_the_refiner_rule_and_the_mapping_survives_a_restart() {
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    let ck = json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"circle_readers":["w1","w2","w3"],"ontology_review":true,"circle_refiner":"gb"}});
    f.s.submit_operations_id("refiner-review-mode", "kernel", &[], Some(ck)).unwrap();
    let mut b = Builder::new(BuilderConfig::default());
    let card = b.next_card(&f.s).unwrap();
    let map = json!({"op":"map_term","record":f.observe.short(),"term":"engine","concept":f.concept.short()});
    let r = b.submit_as(&mut f.s, &card.card_id, &[map], Some("gb"));
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(f.s.mapping_authors_of(&f.concept).unwrap(), vec![("gb".into(), 1)]);
    let root = f.s.audit_root();
    f.reopen();
    assert_eq!(f.s.audit_root(), root);
    assert_eq!(f.s.mapping_authors_of(&f.concept).unwrap(), vec![("gb".into(), 1)]);
}
#[test]
fn review_mode_refuses_an_unattributed_mapping_without_mutating_the_graph() {
    let mut f = Fixture::new();
    enable_reviews(&mut f, 3);
    let r = f.s.map_term("builder", &f.observe, "engine", &f.concept);
    assert!(r.is_err());
    assert!(f.s.records_of(&f.concept).is_empty());
}

#[test]
fn failed_review_is_durably_unresolved_and_does_not_confirm_or_block_the_pool() {
    let mut f = Fixture::new();
    let mut ck = f.s.checkpoint("audit:mcp:coverage").unwrap();
    ck["context"]["agent_attempts"] = json!(1);
    let r = f.s.submit_operations_id("failure-policy", "kernel", &[], Some(ck)).unwrap();
    assert_eq!(r["checkpointed"], true);
    let readers = vec!["w1".into(), "w2".into(), "w3".into()];
    let cfg = BuilderConfig { author_runs: true, ..Default::default() };
    let mut p = ParallelBuilder::new(cfg, readers.clone());
    for c in p.offers(&mut f.s, 1, false).unwrap() {
        assert_eq!(p.worker_mut(&c.card_id).unwrap().submit_as(&mut f.s, &c.card_id, &[], Some("w1"))["status"], "CARD_DONE");
    }
    let proposal = f.proposal("retire", json!({}));
    let c = p.offers(&mut f.s, 1, false).unwrap().into_iter().find(|c| c.review.is_some()).unwrap();
    assert_eq!(p.worker_mut(&c.card_id).unwrap().agent_failure(&mut f.s, &c.card_id, "review-timeout", "w2", "AGY_TIMEOUT")["status"], "CARD_UNRESOLVED");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "provisional");
    assert_eq!(f.s.ontology_revision_state().unwrap()["pending"][0]["proposal"], proposal["proposal"]);
    assert!(p.caught_up(&f.s));
    f.reopen();
    let mut p = ParallelBuilder::new(cfg, readers);
    p.recover(&f.s).unwrap();
    assert!(p.caught_up(&f.s));
    assert!(p.offers(&mut f.s, 1, false).unwrap().is_empty());
}
#[test]
fn circles_refiner_proposal_goes_to_the_reader_of_its_circle_and_the_refiner_cannot_confirm() {
    let mut f = Fixture::new();
    let ck = json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"circle_readers":["w1","w2","w3"],"circle_refiner":"gb"}});
    f.s.submit_operations_id("refiner-roster", "kernel", &[], Some(ck)).unwrap();
    f.s.submit_operations_id("circle-2", "kernel", &[], Some(json!({"key":"audit:circles","from":0,"to":0,"context":{"circle":2}}))).unwrap();
    let kernel = f.s.candidates("kernel", 1)[0].id;
    let outsider = f.command("outsider", json!({"concept":to_hex(&kernel.0),"action":"retire"}), "zz");
    assert!(outsider["error"].is_object(), "a subject outside the ring and not the refiner cannot propose: {outsider}");
    let r = f.command("refiner-proposal", json!({"concept":to_hex(&f.concept.0),"action":"retire"}), "gb");
    assert!(r["error"].is_null(), "{r}");
    let p = r["results"][0].clone();
    assert_eq!((p["status"].as_str(), p["reviewer"].as_str()), (Some("pending"), Some("w2")), "{p}");
    let own = f.command("refiner-self", json!({"action":"confirm","proposal":p["proposal"]}), "gb");
    assert!(own["error"].is_object(), "{own}");
    let r = f.command("confirm", json!({"action":"confirm","proposal":p["proposal"]}), "w2");
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(f.s.concept(&f.concept).unwrap().status, "retired");
}
