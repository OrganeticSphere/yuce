use sbgk_core::audit::{
    directives::{circles::CircleConfig, DispatchConfig, Dispatcher, ResearchQuestion, TaskKind},
    onto::AuditOntology,
    state::AuditState,
    versions, AuditStore, LinkStatus, Scope,
};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const OLD: &str = "# Rule\nThe version mismatch is warning only.\n";
const NEW: &str = "# Rule\nThe version mismatch is now blocking.\n";
const LOG: &str = "The blocking rule supersedes the warning rule.\n";

struct Fixture {
    path: PathBuf,
    state: Option<AuditState>,
    map: Value,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.state.take();
        let _ = std::fs::remove_file(&self.path);
    }
}
impl Fixture {
    fn new() -> Self {
        let f = Self::with_new(NEW);
        assert_eq!(f.map["cards"].as_array().unwrap().len(), 1);
        f
    }
    fn with_new(new: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("r2r_versions_{}_{}.wal", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut state = AuditState::create(
            &path,
            &AuditOntology::base(),
            &[
                ("old".into(), OLD.as_bytes().into()),
                ("new".into(), new.as_bytes().into()),
                ("log".into(), LOG.as_bytes().into()),
                ("outside".into(), b"Unrelated witness outside the card.".into()),
            ],
            "versions",
            sha256(b"fixture"),
        )
        .unwrap();
        let doc = |id: &str, text: &str| json!({"doc_id":id,"raw_sha256":to_hex(&sha256(text.as_bytes()))});
        let lineage = json!({"lineages":[{"id":"product","snapshots":[
            {"id":"v1","docs":[doc("old",OLD)],"changelog":[]}, {"id":"v2","docs":[doc("new",new)],"changelog":[doc("log",LOG)]}]}]});
        let map = state.enable_versions(&lineage).unwrap();
        Self { path, state: Some(state), map }
    }
    fn s(&mut self) -> &mut AuditState {
        self.state.as_mut().unwrap()
    }
    fn authorize(&mut self, task: &str) -> Scope {
        self.authorize_card(task, 0)
    }
    fn authorize_card(&mut self, task: &str, index: usize) -> Scope {
        let card = self.map["cards"][index].clone();
        let r = self
            .s()
            .submit_operations_id(
                &format!("issue-{task}"),
                "kernel",
                &[],
                Some(json!({"key":format!("version:lease:{task}"),"from":0,"to":0,
            "context":{"agent":"a","card":card["id"]}})),
            )
            .unwrap();
        assert_eq!(r["checkpointed"], true, "{r}");
        versions::card_scope(&card)
    }
}
fn records(prefix: &str) -> Vec<Value> {
    vec![
        json!({"kind":"observe","local_id":format!("{prefix}o"),"doc_id":"old","exact_quote":"The version mismatch is warning only.","terms":["version mismatch"]}),
        json!({"kind":"observe","local_id":format!("{prefix}n"),"doc_id":"new","exact_quote":"The version mismatch is now blocking.","terms":["version mismatch"]}),
        json!({"kind":"claim","local_id":format!("{prefix}oc"),"text":"The version mismatch is warning only.","subject":"version mismatch","stance":"reported","based_on":[format!("{prefix}o")]}),
        json!({"kind":"claim","local_id":format!("{prefix}nc"),"text":"The version mismatch is now blocking.","subject":"version mismatch","stance":"reported","based_on":[format!("{prefix}n")]}),
        json!({"kind":"relation","local_id":format!("{prefix}r"),"from":format!("{prefix}nc"),"rel":"supersedes","to":format!("{prefix}oc"),"based_on":[format!("{prefix}o"),format!("{prefix}n")]}),
    ]
}

#[test]
fn change_is_authenticated_then_independently_verified_and_replayed() {
    let mut f = Fixture::new();
    let mut d = Dispatcher::new(DispatchConfig { versions: true, relation_lines: false, ..Default::default() }, vec![]);
    let task = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 0);
    assert_eq!(task["kind"], "CHANGE", "{task}");
    assert!(task["prompt"].as_str().unwrap().contains(LOG.trim()));
    let id = task["task_id"].as_str().unwrap();
    d.persist_change_lease(f.s(), id).unwrap();
    let answer = d.submit(f.s(), id, "a", &records(task["local_id_prefix"].as_str().unwrap()), 1);
    assert_eq!(answer["status"], "COMMITTED", "{answer}");
    let l = f.s().links().pop().unwrap();
    assert_eq!(l.status, LinkStatus::Proposed);
    let own = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::VerifyLink]), 2);
    assert_ne!(own["kind"], "VERIFY_LINK");
    let check = d.acquire_for(f.s(), "b", true, None, Some(&[TaskKind::VerifyLink]), 2);
    assert_eq!(check["kind"], "VERIFY_LINK", "{check}");
    let result = d.submit(
        f.s(),
        check["task_id"].as_str().unwrap(),
        "b",
        &[json!({"kind":"verdict","link":l.id.short(),"verdict":"confirm","based_on":[l.from.short()]})],
        3,
    );
    assert_eq!(result["status"], "COMMITTED", "{result}");
    assert_eq!(f.s().links()[0].status, LinkStatus::Accepted);
    assert_eq!(sbgk_core::audit::quality::stale::answer_status(f.s(), l.to, false)["temporal_status"], "CITES_REPLACED");
    let roots = (f.s().audit_root(), f.s().engine_root(), f.s().session_root(), f.s().wal_head());
    f.state.take();
    let recovered = AuditState::open(&f.path).unwrap();
    assert_eq!((recovered.audit_root(), recovered.engine_root(), recovered.session_root(), recovered.wal_head()), roots);
    assert_eq!(recovered.checkpoint(versions::KEY).unwrap()["context"], f.map);
    f.state = Some(recovered);
    let mut resumed_dispatch = Dispatcher::new(DispatchConfig { versions: true, relation_lines: false, ..Default::default() }, vec![]);
    resumed_dispatch.recover(f.s());
    assert_ne!(
        resumed_dispatch.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 10)["kind"],
        "CHANGE",
        "closed card must not be reissued after restart"
    );
    let new_quote = l.basis.iter().find(|id| f.s().record(id).unwrap().doc_id.as_deref() == Some("new")).copied().unwrap();
    f.s().revoke_observation("owner", &new_quote).unwrap();
    assert_eq!(sbgk_core::audit::quality::stale::answer_status(f.s(), l.to, false)["temporal_status"], "CURRENT_UNCERTAIN");
    assert!(versions::uncertainty(f.s()).contains("replacement_support_unavailable"));
}

#[test]
fn reverse_one_sided_out_of_card_and_forged_origin_are_refused_even_inside_batch() {
    for case in ["reverse", "one-sided", "same-snapshot", "outside", "forged", "scope", "batch", "nested-batch"] {
        let mut f = Fixture::new();
        let mut scope = f.authorize("change");
        let mut lines = records("");
        match case {
            "reverse" => {
                lines[4]["from"] = json!("oc");
                lines[4]["to"] = json!("nc");
            }
            "one-sided" => lines[4]["based_on"] = json!(["o"]),
            "same-snapshot" => lines[3]["based_on"] = json!(["o"]),
            "outside" => {
                scope.docs.push("outside".into());
                scope.ranges.push(("outside".into(), 0, 34));
                lines[1]["doc_id"] = json!("outside");
                lines[1]["exact_quote"] = json!("Unrelated witness outside the card.");
            }
            "scope" => scope.ranges.clear(),
            _ => (),
        }
        if case == "nested-batch" {
            let result = f.s().submit_operations_id("bad", "a", &[json!({"kind":"batch","operations":[],"checkpoint":null})], None).unwrap();
            assert!(!result["error"].is_null(), "{result}");
        } else if case == "batch" {
            lines[4]["based_on"] = json!(["o"]);
            let operation = json!({"kind":"submit","directive":"change","scope":{"docs":scope.docs,"topic":scope.topic,"ranges":scope.ranges},"lines":lines});
            let result = f.s().submit_operations_id("bad", "a", &[operation], None).unwrap_err();
            assert!(result.message.contains("BOTH"), "{result}");
        } else {
            let report = f.s().submit_records_id("bad", "a", if case == "forged" { "TD-forged" } else { "change" }, &scope, &lines);
            assert!(report.error.is_some(), "{case}: {report:?}");
        }
        assert!(f.s().links().is_empty(), "{case}");
    }
}

#[test]
fn foreign_endpoint_cannot_bypass_card_guard_with_issued_reference_capability() {
    let mut f = Fixture::new();
    let outside = Scope { docs: vec!["outside".into()], ..Default::default() };
    let report = f.s().submit_records_id(
        "outside-seed",
        "a",
        "ordinary",
        &outside,
        &[
            json!({"kind":"observe","local_id":"o","doc_id":"outside","exact_quote":"Unrelated witness outside the card.","terms":["witness"]}),
            json!({"kind":"claim","local_id":"c","text":"An unrelated witness.","subject":"witness","stance":"reported","based_on":["o"]}),
        ],
    );
    assert!(report.error.is_none(), "{report:?}");
    let scope = f.authorize("change");
    let mut lines = records("");
    lines[4]["from"] = json!(report.accepted[1].short());
    let result = f.s().submit_scoped_records_id("outside-relation", "a", "change", &scope, &report.accepted, &lines);
    assert!(result.error.is_some(), "{result:?}");
    assert!(f.s().links().is_empty());
}

#[test]
fn map_recomputation_rejects_tampering_and_changed_source_and_has_no_date_inference() {
    let mut f = Fixture::new();
    let mut changed = f.map.clone();
    changed["cards"][0]["old"][0][1] = json!(0);
    let result = f.s().submit_operations_id("tamper", "kernel", &[], Some(json!({"key":versions::KEY,"from":0,"to":0,"context":changed}))).unwrap();
    assert_ne!(result["checkpointed"], true);
    assert!(f.s().put_document("owner", "old", b"other bytes").is_err());
    let mut docs: std::collections::BTreeMap<String, (String, String)> = std::collections::BTreeMap::new();
    docs.insert("2024-01-01/policy".into(), ("2024-01-01/policy".into(), OLD.into()));
    docs.insert("2025-01-01/policy".into(), ("2025-01-01/policy".into(), NEW.into()));
    let empty = versions::compute(&docs, &json!({"lineages":[]})).unwrap();
    assert!(empty["cards"].as_array().unwrap().is_empty());
    let mut lineage = f.map["lineage"].clone();
    lineage["lineages"][0]["snapshots"][0]["docs"][0]["raw_sha256"] = json!("0".repeat(64));
    assert!(f.s().enable_versions(&lineage).is_err());
}

#[test]
fn a_forged_first_map_is_recomputed_and_its_refusal_replays() {
    let mut original = Fixture::new();
    let docs = original
        .s()
        .docs()
        .into_iter()
        .map(|id| {
            let bytes = original.s().doc_text(&id).unwrap().into_bytes();
            (id, bytes)
        })
        .collect::<Vec<_>>();
    let path = original.path.with_extension("forged.wal");
    let state = AuditState::create(&path, &AuditOntology::base(), &docs, "forged", sha256(b"fixture")).unwrap();
    let mut f = Fixture { path, state: Some(state), map: original.map.clone() };
    let mut forged = f.map.clone();
    forged["cards"][0]["old"][0][1] = json!(0);
    let result = f.s().submit_operations_id("forged-first-map", "kernel", &[], Some(json!({"key":versions::KEY,"from":0,"to":0,"context":forged}))).unwrap();
    assert_eq!(result["checkpointed"], false, "{result}");
    assert!(result.to_string().contains("recomputation"), "{result}");
    assert!(!f.s().has_checkpoint(versions::KEY));
    let roots = (f.s().audit_root(), f.s().engine_root(), f.s().wal_head());
    f.state.take();
    let mut reopened = AuditState::open(&f.path).unwrap();
    assert_eq!((reopened.audit_root(), reopened.engine_root(), reopened.wal_head()), roots);
    assert!(!reopened.has_checkpoint(versions::KEY));
    assert!(reopened.enable_versions(&f.map["lineage"]).is_err(), "map cannot be installed after a prior transaction");
    f.state = Some(reopened);
}

#[test]
fn unmatched_is_metadata_and_never_revokes_an_old_fact() {
    let mut f = Fixture::with_new("# Different\nQuantum sockets activated.\n");
    let scope = Scope { docs: vec!["old".into()], ..Default::default() };
    let lines = records("");
    let report = f.s().submit_records_id("old-fact", "reader", "extend", &scope, &[lines[0].clone(), lines[2].clone()]);
    assert!(report.error.is_none());
    let map = f.map.clone();
    assert_eq!(map["cards"].as_array().unwrap().len(), 2);
    assert!(map["cards"].as_array().unwrap().iter().all(|c| c["parts"][0]["status"] == "unmatched_by_version_map"));
    assert!(versions::uncertainty(f.s()).contains("unmatched_by_version_map"));
    assert!(f.s().is_answer_support(&report.accepted[1]));
    assert!(f.s().links().is_empty());
}

#[test]
fn unmatched_old_section_can_use_an_explicit_new_changelog_quote() {
    let mut f = Fixture::with_new("# Different\nQuantum sockets activated.\n");
    let index = f.map["cards"].as_array().unwrap().iter().position(|c| !c["old"].as_array().unwrap().is_empty()).unwrap();
    let scope = f.authorize_card("removal", index);
    let mut lines = records("");
    lines[1]["doc_id"] = json!("log");
    lines[1]["exact_quote"] = json!(LOG.trim());
    let report = f.s().submit_records_id("removal-answer", "a", "removal", &scope, &lines);
    assert!(report.error.is_none(), "{report:?}");
    assert_eq!(f.s().links()[0].status, LinkStatus::Proposed);
    let link = f.s().links()[0].clone();
    assert!(f.s().set_link_status(&link.id, LinkStatus::Accepted, "a", &link.basis).is_err(), "author cannot self-accept");
}

#[test]
fn argon_v01_acceptance_never_overwrites_two_snapshot_proposal_basis() {
    for path in ["verdict", "direct", "batch"] {
        let mut f = Fixture::new();
        let scope = f.authorize("change");
        assert!(f.s().submit_records_id("proposal", "a", "change", &scope, &records("")).error.is_none());
        let proposal = f.s().links()[0].clone();
        let outside = Scope { docs: vec!["outside".into()], ..Default::default() };
        let witness = f.s().submit_records_id(
            "review-witness",
            "b",
            "review",
            &outside,
            &[json!({"kind":"observe","local_id":"w","doc_id":"outside","exact_quote":"Unrelated witness outside the card.","terms":["witness"]})],
        );
        assert!(witness.error.is_none());
        match path {
            "verdict" => {
                let mut d = Dispatcher::new(DispatchConfig { versions: true, relation_lines: false, ..Default::default() }, vec![]);
                let t = d.acquire_for(f.s(), "b", true, None, Some(&[TaskKind::VerifyLink]), 0);
                assert_eq!(t["kind"], "VERIFY_LINK");
                let r = d.submit(
                    f.s(),
                    t["task_id"].as_str().unwrap(),
                    "b",
                    &[json!({"kind":"verdict","link":proposal.id.short(),"verdict":"confirm","based_on":[proposal.from.short()]})],
                    1,
                );
                assert_eq!(r["status"], "COMMITTED", "{r}");
            }
            "direct" => f.s().set_link_status(&proposal.id, LinkStatus::Accepted, "b", &witness.accepted).unwrap(),
            _ => {
                let r = f
                    .s()
                    .submit_operations_id(
                        "accept-batch",
                        "b",
                        &[json!({"kind":"set_link_status","link":to_hex(&proposal.id.0),"status":"accepted","basis":[to_hex(&witness.accepted[0].0)]})],
                        None,
                    )
                    .unwrap();
                assert!(r["error"].is_null(), "{r}");
            }
        }
        assert_eq!(f.s().links()[0].basis, proposal.basis, "{path}");
        let old = proposal.basis.iter().copied().find(|id| f.s().record(id).unwrap().doc_id.as_deref() == Some("old")).unwrap();
        f.s().revoke_observation("owner", &old).unwrap();
        assert!(!f.s().link_usable(&proposal.id), "{path}: original old support remains required");
        assert!(f.s().set_link_status(&proposal.id, LinkStatus::Accepted, "b", &witness.accepted).is_err());
        println!("V01 {path}: proposal basis unchanged; revoked old observation disables the link");
    }
}

#[test]
fn argon_v02_explicit_reuse_inside_card_retains_independent_verifier_exclusions() {
    for author in ["a", "b"] {
        let mut f = Fixture::new();
        let scope = versions::card_scope(&f.map["cards"][0]);
        let seed = f.s().submit_records_id("prior-reading", author, "ordinary-reading", &scope, &records("")[..4]);
        assert!(seed.error.is_none(), "{seed:?}");
        let mut d = Dispatcher::new(DispatchConfig { versions: true, relation_lines: false, own_refs: true, ..Default::default() }, vec![]);
        let t = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 0);
        let task = t["task_id"].as_str().unwrap();
        d.persist_change_lease(f.s(), task).unwrap();
        let line = json!({"kind":"relation","local_id":format!("{}r",t["local_id_prefix"].as_str().unwrap()),"from":seed.accepted[3].short(),"rel":"supersedes","to":seed.accepted[2].short(),"based_on":[seed.accepted[0].short(),seed.accepted[1].short()]});
        if author == "a" {
            let r = d.submit(f.s(), task, "a", &[line], 1);
            assert_eq!(r["status"], "COMMITTED", "{r}");
        } else {
            let r = f.s().submit_scoped_records_id("explicit-reuse", "a", task, &scope, &seed.accepted, &[line]);
            assert!(r.error.is_none(), "{r:?}");
        }
        assert_eq!(f.s().links().len(), 1);
        assert_ne!(d.acquire_for(f.s(), author, true, None, Some(&[TaskKind::VerifyLink]), 2)["kind"], "VERIFY_LINK");
        assert_ne!(
            d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::VerifyLink]), 2)["kind"],
            "VERIFY_LINK",
            "relation proposer must not be assigned its own verification"
        );
        assert_eq!(d.acquire_for(f.s(), "c", true, None, Some(&[TaskKind::VerifyLink]), 2)["kind"], "VERIFY_LINK");
        println!("V02 author {author}: in-card reuse accepted; endpoint author excluded, independent c eligible");
    }
}

#[test]
fn argon_v03_last_wave_summary_waits_for_open_and_leased_verification() {
    let original = Fixture::new();
    let path = original.path.with_extension("last-wave.wal");
    let mut state = AuditState::create(
        &path,
        &AuditOntology::base(),
        &[("old".into(), OLD.as_bytes().into()), ("new".into(), NEW.as_bytes().into())],
        "last-wave",
        sha256(b"fixture"),
    )
    .unwrap();
    let doc = |id: &str, t: &str| json!({"doc_id":id,"raw_sha256":to_hex(&sha256(t.as_bytes()))});
    let map=state.enable_versions(&json!({"lineages":[{"id":"l","snapshots":[{"id":"v1","docs":[doc("old",OLD)],"changelog":[]},{"id":"v2","docs":[doc("new",NEW)],"changelog":[]}]}]})).unwrap();
    let mut f = Fixture { path, state: Some(state), map };
    let cfg = DispatchConfig {
        versions: true,
        relation_lines: false,
        circles: Some(CircleConfig { readers: vec!["a".into(), "b".into(), "c".into()], wave_sections: 3, agent_timeout_ms: 10000 }),
        ..Default::default()
    };
    let mut d = Dispatcher::new(
        cfg,
        vec![ResearchQuestion { id: "RQ1".into(), text: "Version mismatch rule?".into(), about: vec!["version mismatch".into()], ..Default::default() }],
    );
    d.advance_circles(f.s(), true, 0, 1000).unwrap();
    let change = d.acquire_for(f.s(), "a", true, None, None, 0);
    assert_eq!(change["kind"], "CHANGE");
    for who in ["b", "c"] {
        let t = d.acquire_for(f.s(), who, true, None, None, 0);
        assert_eq!(t["kind"], "EXTEND", "{t}");
        assert_eq!(d.submit(f.s(), t["task_id"].as_str().unwrap(), who, &[], 1)["status"], "COMMITTED");
    }
    assert_eq!(d.submit(f.s(), change["task_id"].as_str().unwrap(), "a", &records(change["local_id_prefix"].as_str().unwrap()), 2)["status"], "COMMITTED");
    d.advance_circles(f.s(), true, 3, 1003).unwrap();
    assert_eq!(d.circle_status().unwrap()["circle_phase"], "FINAL");
    assert_ne!(d.acquire_for(f.s(), "c", true, None, Some(&[TaskKind::Summarize]), 4)["kind"], "SUMMARIZE");
    let check = d.acquire_for(f.s(), "b", true, None, Some(&[TaskKind::VerifyLink]), 4);
    assert_eq!(check["kind"], "VERIFY_LINK", "{check}");
    assert_ne!(d.acquire_for(f.s(), "c", true, None, Some(&[TaskKind::Summarize]), 5)["kind"], "SUMMARIZE");
    let link = f.s().links()[0].clone();
    let r = d.submit(
        f.s(),
        check["task_id"].as_str().unwrap(),
        "b",
        &[json!({"kind":"verdict","link":link.id.short(),"verdict":"confirm","based_on":[link.from.short()]})],
        6,
    );
    assert_eq!(r["status"], "COMMITTED", "{r}");
    let summary = d.acquire_for(f.s(), "c", true, None, Some(&[TaskKind::Summarize]), 7);
    assert_eq!(summary["kind"], "SUMMARIZE", "{summary}");
    assert!(summary["prompt"].as_str().unwrap().contains("accepted_replacements_total\":1"), "{summary}");
    println!("V03: final READ -> FINAL; summary blocked with an open or leased check; accepted replacement shown afterward");
}

#[test]
fn argon_v04_restart_before_submit_has_distinct_task_id() {
    let mut f = Fixture::new();
    let cfg = DispatchConfig { versions: true, relation_lines: false, ..Default::default() };
    let mut a = Dispatcher::new(cfg.clone(), vec![]);
    let old = a.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 0);
    a.persist_change_lease(f.s(), old["task_id"].as_str().unwrap()).unwrap();
    f.state.take();
    f.state = Some(AuditState::open(&f.path).unwrap());
    let mut b = Dispatcher::new(cfg, vec![]);
    b.recover(f.s());
    let new = b.acquire_for(f.s(), "b", true, None, Some(&[TaskKind::Change]), 0);
    assert_eq!(new["kind"], "CHANGE");
    assert_ne!(old["task_id"], new["task_id"]);
    b.persist_change_lease(f.s(), new["task_id"].as_str().unwrap()).unwrap();
    assert_eq!(b.submit(f.s(), old["task_id"].as_str().unwrap(), "a", &[], 1)["status"], "STALE_TASK");
    println!("V04 restart: old {} != new {}; stale public submit refused", old["task_id"], new["task_id"]);
}

#[test]
fn argon_v04_core_grants_do_not_survive_release_expiry_completion_or_restart() {
    let mut surviving = Vec::new();
    for how in ["release", "expiry", "completion", "restart"] {
        let mut f = Fixture::new();
        let cfg = DispatchConfig { versions: true, relation_lines: false, ttl_ms: 10, ..Default::default() };
        let mut d = Dispatcher::new(cfg.clone(), vec![]);
        let t = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 0);
        let task = t["task_id"].as_str().unwrap();
        d.persist_change_lease(f.s(), task).unwrap();
        let scope = versions::card_scope(&f.map["cards"][0]);
        match how {
            "release" => {
                assert_eq!(d.release_durable(f.s(), task, "a")["status"], "RELEASED");
                assert_eq!(d.submit(f.s(), task, "a", &[], 1)["status"], "STALE_TASK");
            }
            "expiry" => {
                assert_eq!(d.submit(f.s(), task, "a", &[], 11)["status"], "STALE_TASK");
            }
            "completion" => {
                assert_eq!(d.submit(f.s(), task, "a", &[], 1)["status"], "COMMITTED");
            }
            _ => {
                f.state.take();
                f.state = Some(AuditState::open(&f.path).unwrap());
                let mut next = Dispatcher::new(cfg, vec![]);
                next.recover(f.s());
                let n = next.acquire_for(f.s(), "b", true, None, Some(&[TaskKind::Change]), 0);
                next.persist_change_lease(f.s(), n["task_id"].as_str().unwrap()).unwrap();
            }
        }
        let result = f.s().submit_records_id("stale-direct-core", "a", task, &scope, &records("late_"));
        println!("V04 {how}: public lease gone, direct Core accepted {}", result.error.is_none());
        if result.error.is_none() {
            surviving.push(how);
        }
        let roots = (f.s().audit_root(), f.s().engine_root(), f.s().session_root(), f.s().wal_head());
        f.state.take();
        let recovered = AuditState::open(&f.path).unwrap();
        assert_eq!(
            (recovered.audit_root(), recovered.engine_root(), recovered.session_root(), recovered.wal_head()),
            roots,
            "{how}: closure and refused late write must replay"
        );
        f.state = Some(recovered);
    }
    assert!(surviving.is_empty(), "persisted origin grants still active after {surviving:?}");
}

#[test]
fn argon_v04_failed_publication_does_not_strand_a_lease() {
    let mut f = Fixture::new();
    let mut d = Dispatcher::new(DispatchConfig { versions: true, relation_lines: false, ..Default::default() }, vec![]);
    let t = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 0);
    let task = t["task_id"].as_str().unwrap();
    let card = f.map["cards"][0]["id"].clone();
    let r = f
        .s()
        .submit_operations_id(
            "injected-publication-conflict",
            "kernel",
            &[],
            Some(json!({"key":format!("version:lease:{task}"),"from":0,"to":0,"context":{"agent":"b","card":card}})),
        )
        .unwrap();
    assert_eq!(r["checkpointed"], true);
    assert!(d.persist_change_lease(f.s(), task).is_err());
    let next = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 1);
    assert_eq!(next["kind"], "CHANGE", "publication failure must release unpublished work: {next}");
}

#[test]
fn change_refusal_names_only_the_bad_relation_and_keeps_independent_lines() {
    let mut f = Fixture::new();
    let mut d = Dispatcher::new(DispatchConfig { versions: true, ..Default::default() }, vec![]);
    let t = d.acquire_for(f.s(), "a", true, None, Some(&[TaskKind::Change]), 0);
    let task = t["task_id"].as_str().unwrap();
    d.persist_change_lease(f.s(), task).unwrap();
    let p = t["local_id_prefix"].as_str().unwrap();
    let mut lines = records(p);
    lines[4]["from"] = json!(format!("{p}oc"));
    lines[4]["to"] = json!(format!("{p}nc"));
    lines.push(json!({"kind":"claim","local_id":format!("{p}dependent"),"text":"A dependent assertion.","subject":"version mismatch","stance":"reported","based_on":[format!("{p}r")]}));
    lines.push(json!({"kind":"claim","local_id":format!("{p}independent"),"text":"The new rule blocks.","subject":"version mismatch","stance":"reported","based_on":[format!("{p}n")]}));
    let mut good = records(p).pop().unwrap();
    good["local_id"] = json!(format!("{p}good"));
    lines.push(good);
    let out = d.submit(f.s(), task, "a", &lines, 1);
    println!("change refusal receipt: {out}");
    assert_eq!(out["failed_index"], 4, "{out}");
    assert_eq!(out["refused"].as_array().unwrap().len(), 1, "{out}");
    assert_eq!(out["refused"][0]["local_id"], format!("{p}r"));
    assert_eq!(out["error"]["expected_by_kernel"]["condition"], "supersedes_new_to_old");
    assert!(out["error"]["expected_by_kernel"]["from"].as_str().unwrap().starts_with('@'));
    let prompt = t["prompt"].as_str().unwrap();
    assert!(prompt.contains("cross-snapshot only") && prompt.contains("\"from\":\"new_c\"") && prompt.contains("\"based_on\":[\"old_o\",\"new_o\"]"));
    assert_eq!(out["excluded"][0]["local_id"], format!("{p}dependent"));
    assert_eq!(out["accepted"].as_array().unwrap().len(), 6, "{out}");
    assert_eq!(f.s().links().len(), 1);
    assert_eq!(out["not_stored"], json!([format!("{p}r"), format!("{p}dependent")]));
    let saved = out["accepted_locals"].clone();
    let mut repaired = records(p).pop().unwrap();
    repaired["rel"] = json!("qualifies");
    let done = d.submit(f.s(), task, "a", &[repaired], 2);
    assert_eq!(done["status"], "COMMITTED", "{done}");
    for (name, id) in saved.as_object().unwrap() {
        assert_eq!(f.s().local_record("a", task, name).unwrap().short(), id.as_str().unwrap());
    }
    let roots = (f.s().audit_root(), f.s().engine_root(), f.s().wal_head());
    f.state.take();
    let recovered = AuditState::open(&f.path).unwrap();
    assert_eq!((recovered.audit_root(), recovered.engine_root(), recovered.wal_head()), roots);
    f.state = Some(recovered);
}

#[test]
fn change_relation_diagnostics_distinguish_snapshot_and_basis_errors_without_losing_prefix() {
    for (case, condition) in [
        ("reverse", "supersedes_new_to_old"),
        ("same-new", "different_snapshots"),
        ("mixed", "one_snapshot_per_endpoint"),
        ("basis", "observe_basis_both_snapshots"),
        ("forged", "authenticated_change_grant"),
    ] {
        let mut f = Fixture::new();
        let scope = f.authorize("change");
        let mut lines = records("");
        match case {
            "reverse" => {
                lines[4]["from"] = json!("oc");
                lines[4]["to"] = json!("nc");
            }
            "same-new" => lines[2]["based_on"] = json!(["n"]),
            "mixed" => lines[2]["based_on"] = json!(["o", "n"]),
            "basis" => lines[4]["based_on"] = json!(["n"]),
            _ => (),
        }
        let task = if case == "forged" { "forged" } else { "change" };
        let report = f.s().submit_records_id("attempt", "a", task, &scope, &lines);
        assert_eq!(report.accepted.len(), 4, "{case}: {report:?}");
        assert_eq!(report.failed_index, Some(4));
        assert_eq!(report.error.as_ref().unwrap().expected_by_kernel["condition"], condition);
        assert!(f.s().links().is_empty());
        let roots = (f.s().audit_root(), f.s().engine_root(), f.s().wal_head());
        let retry = f.s().submit_records_id("attempt", "a", task, &scope, &lines);
        assert_eq!(report.accepted, retry.accepted);
        assert_eq!(report.error.as_ref().unwrap().to_json(), retry.error.unwrap().to_json());
        assert_eq!((f.s().audit_root(), f.s().engine_root(), f.s().wal_head()), roots, "retry appends nothing");
        f.state.take();
        let reopened = AuditState::open(&f.path).unwrap();
        assert_eq!((reopened.audit_root(), reopened.engine_root(), reopened.wal_head()), roots);
        f.state = Some(reopened);
    }
}
