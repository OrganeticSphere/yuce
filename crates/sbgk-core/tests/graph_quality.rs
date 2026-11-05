use sbgk_core::audit::{
    builder::{
        parallel::{plan_key, ParallelBuilder},
        Builder, BuilderConfig,
    },
    directives::{DispatchConfig, Dispatcher, ResearchQuestion, TaskKind},
    onto::AuditOntology,
    quality,
    state::AuditState,
    AuditStore, LinkId, LinkStatus, RecordId, Scope,
};
use sbgk_core::hash::{from_hex, sha256, to_hex};
use serde_json::{json, Value};
use std::path::PathBuf;
struct Wal(PathBuf);
impl Drop for Wal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn fresh(q: Value) -> (Wal, AuditState, Vec<RecordId>, Vec<RecordId>) {
    fresh_with(q, &["w1", "w2", "w3"])
}
fn fresh_with(q: Value, readers: &[&str]) -> (Wal, AuditState, Vec<RecordId>, Vec<RecordId>) {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let w = Wal(std::env::temp_dir().join(format!("quality-{nonce}-{}.wal", std::process::id())));
    let mut o = AuditOntology::base();
    o["concepts"] = json!([{"type":"Component","name":"reactor","aliases":["unit"]},{"type":"Limitation","name":"out of scope","aliases":["excluded area"]},{"type":"Component","name":"neutron gate","aliases":[]}]);
    let docs = (0..4)
        .map(|i| {
            (
                format!("d{i}"),
                format!("+++\ndate = \"2026-10-0{}\"\n+++\nscope common. Reactor state {i}. {}", i + 1, if i == 0 { "neutron" } else { "common" }).into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let mut s = AuditState::create(&w.0, &o, &docs, "quality-test", sha256(b"quality")).unwrap();
    let r = s
        .submit_operations_id(
            "config",
            "kernel",
            &[],
            Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":q,"section_bytes":6000,"circle_readers":readers}})),
        )
        .unwrap();
    assert_eq!(r["checkpointed"], true);
    let (mut obs, mut claims) = (vec![], vec![]);
    for i in 0..4 {
        let a = readers[i % readers.len()].to_string();
        let doc = format!("d{i}");
        let r=s.submit_records(&a,&format!("read{i}"),&Scope{docs:vec![doc.clone()],..Default::default()},&[
 json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":format!("Reactor state {i}."),"terms":["reactor","false","conformance_not_efficacy","a very long phrase of six words"]}),
 json!({"kind":"claim","local_id":"c","text":format!("Reactor has state {i}."),"subject":"reactor","predicate":"has_state","object":"false","stance":"reported","as_of":20261001+i,"based_on":["o"]}),
 json!({"kind":"question","local_id":"q","text":"What is the next state?","about":["reactor"],"needed":"Read later reactor reports."})]);
        assert!(r.error.is_none(), "{r:?}");
        obs.push(r.accepted[0]);
        claims.push(r.accepted[1]);
    }
    (w, s, obs, claims)
}
fn map(s: &mut AuditState, ids: &[RecordId]) {
    let c = s.candidates("reactor", 1)[0].id;
    for (i, id) in ids.iter().enumerate() {
        let r = s
            .submit_operations_id(
                &format!("mapping{i}"),
                "builder",
                &[json!({"kind":"map_term","record":to_hex(&id.0),"term":"reactor","concept":to_hex(&c.0)})],
                None,
            )
            .unwrap();
        assert!(r["error"].is_null(), "{r}");
    }
}
fn link(s: &mut AuditState, obs: &[RecordId], cs: &[RecordId]) -> LinkId {
    let r=s.submit_operations_id("proposal","builder",&[json!({"kind":"add_link","from":to_hex(&cs[1].0),"rel":"supersedes","to":to_hex(&cs[0].0),"basis":obs[..2].iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()})],None).unwrap();
    assert!(r["error"].is_null(), "{r}");
    LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap())
}
#[test]
fn hygiene_filters_presentation_not_frozen_records_and_survives_restart() {
    let (w, s, _, _) = fresh(json!({"term_hygiene":true,"term_max_words":4}));
    let original = s.root();
    let mut b = Builder::new(BuilderConfig { max_records: 16, ..Default::default() });
    let c = b.next_card(&s).unwrap();
    assert!(c.records.iter().filter(|r| r.kind.name() == "question").all(|r| r.terms.is_empty()));
    assert!(c.records.iter().flat_map(|r| &r.terms).all(|t| !t.contains("false") && !t.contains("not") && !t.starts_with("a very")));
    assert!(s.records_since(0).iter().any(|r| r.terms.contains(&"false".to_string())));
    assert_eq!(original, s.root());
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(original, s.root());
    assert_eq!(Builder::new(BuilderConfig { max_records: 16, ..Default::default() }).next_card(&s).unwrap().to_json(), c.to_json());
}
#[test]
fn strict_uses_corpus_frequency_and_phrase_boundaries() {
    let (_w, s, _, _) = fresh(json!({"candidate_match":"strict"}));
    assert!(quality::strict_candidates(&s, "scope", 8).is_empty());
    assert_eq!(quality::strict_candidates(&s, "out_of_scope", 8)[0].name, "out of scope");
    assert_eq!(quality::strict_candidates(&s, "neutron", 8)[0].name, "neutron gate");
    assert!(quality::strict_candidates(&s, "common", 8).is_empty());
    assert!(quality::strict_candidates(&s, "react", 8).is_empty());
}
#[test]
fn known_concepts_modes_are_independent_of_circles() {
    for (mode, yes) in [("off", false), ("circles", false), ("all", true)] {
        let (_w, s, _, _) = fresh(json!({"known_concepts":mode}));
        let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
        let t = d.acquire(&s, "reader", true, 0);
        assert_eq!(t["kind"], "EXTEND");
        assert_eq!(t["prompt"].as_str().unwrap().contains("KNOWN CONCEPTS"), yes, "{t}");
    }
}
#[test]
fn rotation_changes_neighbors_and_is_durable() {
    let (w, s, _, _) = fresh(json!({"ring_rotate":true}));
    let rs = vec!["w1".into(), "w2".into(), "w3".into()];
    assert_ne!(quality::ring(&s, &rs, 1), quality::ring(&s, &rs, 2));
    let expected = quality::ring(&s, &rs, 2);
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(quality::ring(&s, &rs, 2), expected);
}
#[test]
fn checker_sees_both_complete_cones_even_with_small_generic_cone_limit() {
    let (_w, mut s, obs, cs) = fresh(json!({"link_both_sides":true}));
    let l = link(&mut s, &obs, &cs);
    let mut d = Dispatcher::new(DispatchConfig { max_cone: 1, ..Default::default() }, vec![]);
    let t = d.acquire_for(&s, "checker", true, None, Some(&[TaskKind::VerifyLink]), 0);
    assert_eq!(t["kind"], "VERIFY_LINK", "{t}");
    let p = t["prompt"].as_str().unwrap();
    assert!(p.contains(&obs[0].short()) && p.contains(&obs[1].short()), "{t}");
    assert_eq!(s.link(&l).unwrap().basis, obs[..2]);
}
#[test]
fn a_link_checker_sees_the_report_date_of_every_quote_and_the_partial_replacement_rule() {
    // step 3a of 31.10: no check of MCPpair2_r2 showed a date, and checkers refused true supersedes as "no quote shows it is newer"
    let (_w, mut s, obs, cs) = fresh(json!({}));
    link(&mut s, &obs, &cs);
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let t = d.acquire_for(&s, "checker", true, None, Some(&[TaskKind::VerifyLink]), 0);
    assert_eq!(t["kind"], "VERIFY_LINK", "{t}");
    let p = t["prompt"].as_str().unwrap();
    for (o, date) in [(obs[0], "2026-10-01"), (obs[1], "2026-10-02")] {
        let line = p.lines().find(|l| l.contains(&o.short()) && l.contains(" observe by ")).unwrap_or_else(|| panic!("{p}"));
        assert!(line.contains(&format!("report date {date}")), "{line}");
    }
    assert!(p.contains("the relation is qualifies, not supersedes") && p.contains("write that observe line first"), "{p}");
}
#[test]
fn stale_survives_revoke_and_restart_without_resurrecting_old_state() {
    let (w, mut s, obs, cs) = fresh(json!({"stale_suspect":true}));
    let l = link(&mut s, &obs, &cs);
    s.set_link_status(&l, LinkStatus::Accepted, "checker", &obs[..2]).unwrap();
    assert_eq!(quality::annotate(&s, cs[0])["stale_suspect"], false);
    s.revoke_observation("owner", &obs[1]).unwrap();
    let a = quality::annotate(&s, cs[0]);
    assert_eq!(a["stale_suspect"], true);
    assert!(s.is_grounded(&cs[0]));
    assert!(!s.is_grounded(&cs[1]));
    let mut d = Dispatcher::new(
        DispatchConfig::default(),
        vec![ResearchQuestion {
            id: "RQ1".into(),
            text: "What changed?".into(),
            about: vec!["reactor".into()],
            stances: vec![],
            relations: vec!["supersedes".into()],
            concept_types: vec![],
        }],
    );
    let t = d.acquire(&s, "reader", true, 0);
    assert_eq!(t["kind"], "INVESTIGATE", "{t}");
    let p = t["prompt"].as_str().unwrap();
    assert!(p.contains("priority reread") && p.to_lowercase().contains("current state is unconfirmed") && !p.contains("doc_id=\"d0\""), "{p}");
    assert!(d.offline_diagnostics(&s).to_string().contains("TEMPORAL WARNINGS"));
    let root = s.root();
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(root, s.root());
    assert_eq!(quality::annotate(&s, cs[0]), a);
}
fn evolution(s: &mut AuditState) -> (Builder, sbgk_core::audit::builder::Card) {
    let mut b = Builder::new(BuilderConfig { max_records: 16, ..Default::default() });
    while let Some(c) = b.next_card(s) {
        assert_eq!(b.submit(s, &c.card_id, &[])["status"], "CARD_DONE");
    }
    b.prepare_pairs(s, true);
    let c = b.next_card(s).unwrap();
    (b, c)
}
#[test]
fn evolution_requires_mapping_and_different_dated_reports() {
    let (_w, mut s, _, cs) = fresh(json!({"evolution_cards":true,"evolution_pairs_per_concept":3,"evolution_pairs_per_card":2}));
    assert!(quality::evolution::detect(&s).is_empty());
    map(&mut s, &cs);
    let p = quality::evolution::detect(&s);
    // every card's pairs share a reader who wrote none of their ends (K06, the fix of EVO-01), and no pair is lost
    let pairs = p.iter().flat_map(|c| c.metadata["pairs"].as_array().unwrap().clone()).collect::<Vec<_>>();
    assert_eq!(pairs.len(), 3, "{p:?}");
    for c in &p {
        assert_eq!(c.metadata["kind"], "evolution", "{c:?}");
        let rows = c.metadata["pairs"].as_array().unwrap();
        assert!(rows.len() <= 2, "{c:?}");
        let authors = rows.iter().flat_map(|r| ["old", "new"].map(|k| s.record(&quality::evolution::id(&r[k]).unwrap()).unwrap().author)).collect::<Vec<_>>();
        assert!(["w1", "w2", "w3"].iter().any(|w| !authors.iter().any(|a| a == w)), "a card no reader may take: {c:?}");
    }
    let (_, c) = evolution(&mut s);
    assert_eq!(c.to_json()["kind"], "EVOLUTION_LINK_CARD");
    // each end of the card's pairs comes with the quote it rests on
    assert!(c.neighbors.iter().filter(|r| r.kind.name() == "observe").count() >= c.records.len(), "{c:?}");
}
#[test]
fn explicit_order_pairs_undated_reports_against_their_id_order_and_no_order_pairs_nothing() {
    // Codex review R03: undated 'z' comes before 'a' by the explicit order only
    let detect = |order: Value| {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let w = Wal(std::env::temp_dir().join(format!("quality-order-{nonce}-{}.wal", std::process::id())));
        let mut o = AuditOntology::base();
        o["concepts"] = json!([{"type":"Component","name":"alpha","aliases":[]}]);
        let docs = vec![("a".to_string(), b"Alpha state is new.".to_vec()), ("z".to_string(), b"Alpha state was old.".to_vec())];
        let mut s = AuditState::create(&w.0, &o, &docs, "order-test", sha256(b"order")).unwrap();
        let q = json!({"evolution_cards":true,"evolution_document_order":order});
        let r =
            s.submit_operations_id("config", "kernel", &[], Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":q}}))).unwrap();
        assert_eq!(r["checkpointed"], true);
        let mut claims = vec![];
        for (doc, state) in [("z", "old"), ("a", "new")] {
            let text = s.doc_text(doc).unwrap();
            let r = s.submit_records(&format!("w{}", claims.len() + 1), "read", &Scope { docs: vec![doc.into()], ..Default::default() }, &[
                json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":text,"terms":["alpha"]}),
                json!({"kind":"claim","local_id":"c","text":text,"subject":"alpha","predicate":"state","object":state,"stance":"reported","based_on":["o"]}),
            ]);
            assert!(r.error.is_none(), "{r:?}");
            claims.push(r.accepted[1]);
        }
        let c = s.candidates("alpha", 1)[0].id;
        for (i, r) in claims.iter().enumerate() {
            let v = s
                .submit_operations_id(
                    &format!("map{i}"),
                    "builder",
                    &[json!({"kind":"map_term","record":to_hex(&r.0),"term":"alpha","concept":to_hex(&c.0)})],
                    None,
                )
                .unwrap();
            assert!(v["error"].is_null(), "{v}");
        }
        quality::evolution::detect(&s).iter().flat_map(|p| p.metadata["pairs"].as_array().cloned().unwrap_or_default()).collect::<Vec<_>>()
    };
    let pairs = detect(json!(["z", "a"]));
    assert_eq!(pairs.len(), 1, "{pairs:?}");
    assert_eq!(
        (pairs[0]["old_doc"].as_str(), pairs[0]["new_doc"].as_str(), pairs[0]["ordering"].as_str()),
        (Some("z"), Some("a"), Some("explicit_manifest_order"))
    );
    assert!(detect(json!([])).is_empty(), "no date and no place: no order is guessed from ids");
}
#[test]
fn manifest_dates_order_pages_without_front_matter_and_pages_of_one_date_pair_nothing() {
    // run smoke2 on MCP: pages without front matter had no date, so the explicit order alone paired pages of one release
    let pages = [
        ("docs/specification/2025-03-26/changelog.mdx", "2025-03-26", "Alpha state was old."),
        ("docs/specification/2025-06-18/changelog.mdx", "2025-06-18", "Alpha state is new."),
        ("docs/specification/2025-06-18/deprecated.mdx", "2025-06-18", "Alpha state is listed."),
    ];
    let detect = |dated: bool, reopen: bool| {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let w = Wal(std::env::temp_dir().join(format!("quality-dates-{nonce}-{}.wal", std::process::id())));
        let entries = pages
            .iter()
            .map(|(p, d, t)| {
                let mut e = json!({"path":p,"extension":".mdx","corpus_role":"markdown_document_candidate","size_bytes":t.len(),"raw_sha256":to_hex(&sha256(t.as_bytes()))});
                if dated {
                    e["date"] = json!(d);
                }
                e
            })
            .collect::<Vec<_>>();
        let manifest = json!({"schema":"r2r.tobi_corpus_metadata_manifest.v1","source":{"origin_recorded":"https://example.invalid/spec.git","commit":"1".repeat(40)},"entries":entries});
        let selected = pages.iter().map(|(p, _, t)| (p.to_string(), t.as_bytes().to_vec())).collect::<Vec<_>>();
        let mut o = AuditOntology::base();
        o["concepts"] = json!([{"type":"Component","name":"alpha","aliases":[]}]);
        let mut s = AuditState::create_from_manifest(&w.0, &o, "dates-test", &serde_json::to_vec(&manifest).unwrap(), &selected).unwrap();
        let ids = pages.iter().map(|(p, _, _)| s.docs().into_iter().find(|d| s.document_label(d) == *p).unwrap()).collect::<Vec<_>>();
        let q = json!({"evolution_cards":true,"evolution_document_order":ids});
        let r =
            s.submit_operations_id("config", "kernel", &[], Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":q}}))).unwrap();
        assert_eq!(r["checkpointed"], true);
        let mut claims = vec![];
        for (i, doc) in ids.iter().enumerate() {
            let text = s.doc_text(doc).unwrap();
            let r = s.submit_records(&format!("w{}", i + 1), "read", &Scope { docs: vec![doc.clone()], ..Default::default() }, &[
                json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":text,"terms":["alpha"]}),
                json!({"kind":"claim","local_id":"c","text":text,"subject":"alpha","predicate":"state","object":i.to_string(),"stance":"reported","based_on":["o"]}),
            ]);
            assert!(r.error.is_none(), "{r:?}");
            claims.push(r.accepted[1]);
        }
        let c = s.candidates("alpha", 1)[0].id;
        for (i, r) in claims.iter().enumerate() {
            let v = s
                .submit_operations_id(
                    &format!("map{i}"),
                    "builder",
                    &[json!({"kind":"map_term","record":to_hex(&r.0),"term":"alpha","concept":to_hex(&c.0)})],
                    None,
                )
                .unwrap();
            assert!(v["error"].is_null(), "{v}");
        }
        if reopen {
            let root = s.root();
            drop(s);
            s = AuditState::open(&w.0).unwrap();
            assert_eq!(root, s.root());
        }
        let label = |d: &Value| s.document_label(d.as_str().unwrap());
        let mut pairs = quality::evolution::detect(&s)
            .iter()
            .flat_map(|p| p.metadata["pairs"].as_array().cloned().unwrap_or_default())
            .map(|p| {
                (
                    label(&p["old_doc"]),
                    label(&p["new_doc"]),
                    p["old_date"].as_str().unwrap().to_string(),
                    p["new_date"].as_str().unwrap().to_string(),
                    p["ordering"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>();
        pairs.sort();
        pairs
    };
    let (v1, v2, v2d) = (pages[0].0.to_string(), pages[1].0.to_string(), pages[2].0.to_string());
    let undated = detect(false, false);
    assert_eq!(undated.len(), 3, "the explicit order alone pairs the two pages of 2025-06-18 too: {undated:?}");
    assert!(undated.iter().any(|p| (&p.0, &p.1, p.4.as_str()) == (&v2, &v2d, "explicit_manifest_order")), "{undated:?}");
    for reopen in [false, true] {
        let dated = detect(true, reopen);
        let expected = [&v2, &v2d].map(|new| (v1.clone(), new.clone(), "2025-03-26".to_string(), "2025-06-18".to_string(), "report_date".to_string()));
        assert_eq!(dated, expected.to_vec(), "dated pages pair across dates only, also after a restart");
    }
}
#[test]
fn a_withdrawn_replacement_rereads_its_page_also_when_both_pages_carry_one_date() {
    // Codex review MDATE-01 of c8c13a4: two pages of one release; an accepted supersedes loses its new quote, and the reread of the
    // replacement's page was dropped by the date filter although the page holds another quote of the later state
    let pages = [
        ("reports/history.mdx", "Before release V the port was 8080."),
        ("reports/release.mdx", "In release V the port became 9090. Another notice confirms port 9090."),
    ];
    let reread = |dates: Option<[&str; 2]>, reopen: bool| {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let w = Wal(std::env::temp_dir().join(format!("quality-mdate-{nonce}-{}.wal", std::process::id())));
        let entries = pages
            .iter()
            .enumerate()
            .map(|(i, (p, t))| {
                let mut e = json!({"path":p,"extension":".mdx","corpus_role":"markdown_document_candidate","size_bytes":t.len(),"raw_sha256":to_hex(&sha256(t.as_bytes()))});
                if let Some(d) = dates {
                    e["date"] = json!(d[i]);
                }
                e
            })
            .collect::<Vec<_>>();
        let manifest = json!({"schema":"r2r.tobi_corpus_metadata_manifest.v1","source":{"origin_recorded":"https://example.invalid/spec.git","commit":"1".repeat(40)},"entries":entries});
        let selected = pages.iter().map(|(p, t)| (p.to_string(), t.as_bytes().to_vec())).collect::<Vec<_>>();
        let mut s = AuditState::create_from_manifest(&w.0, &AuditOntology::base(), "mdate-test", &serde_json::to_vec(&manifest).unwrap(), &selected).unwrap();
        let ids = pages.iter().map(|(p, _)| s.docs().into_iter().find(|d| s.document_label(d) == *p).unwrap()).collect::<Vec<_>>();
        let q = json!({"stale_suspect":true,"evolution_document_order":ids});
        let r =
            s.submit_operations_id("config", "kernel", &[], Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":q}}))).unwrap();
        assert_eq!(r["checkpointed"], true);
        let (mut obs, mut claims) = (vec![], vec![]);
        for (i, (doc, quote, port)) in
            [(&ids[0], "Before release V the port was 8080.", "8080"), (&ids[1], "In release V the port became 9090.", "9090")].into_iter().enumerate()
        {
            let r = s.submit_records(
                &format!("w{}", i + 1),
                "read",
                &Scope { docs: vec![doc.clone()], ..Default::default() },
                &[
                    json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["port"]}),
                    json!({"kind":"claim","local_id":"c","text":quote,"subject":"port","predicate":"is","object":port,"stance":"reported","based_on":["o"]}),
                ],
            );
            assert!(r.error.is_none(), "{r:?}");
            obs.push(r.accepted[0]);
            claims.push(r.accepted[1]);
        }
        let l = link(&mut s, &obs, &claims);
        s.set_link_status(&l, LinkStatus::Accepted, "checker", &obs[..2]).unwrap();
        s.revoke_observation("owner", &obs[1]).unwrap();
        if reopen {
            let root = s.root();
            drop(s);
            s = AuditState::open(&w.0).unwrap();
            assert_eq!(root, s.root());
        }
        assert_eq!(quality::annotate(&s, claims[0])["stale_suspect"], true);
        let sections = quality::stale::later_sections(&s, claims[0], 6000);
        sections.iter().map(|(d, _, _)| s.document_label(d)).collect::<Vec<_>>()
    };
    for reopen in [false, true] {
        for dates in [None, Some(["2026-07-28", "2026-07-28"]), Some(["2026-07-28", "2026-07-29"])] {
            assert_eq!(reread(dates, reopen), ["reports/release.mdx"], "dates {dates:?}, reopen {reopen}");
        }
        // a page dated earlier than the old state is not a later one, even when the replacement came from it
        assert!(reread(Some(["2026-07-28", "2026-07-27"]), reopen).is_empty());
    }
}
#[test]
fn evolution_rejects_single_basis_reverse_direction_and_requires_none_per_pair() {
    let (w, mut s, _, cs) = fresh(json!({"evolution_cards":true,"evolution_pairs_per_concept":2,"evolution_pairs_per_card":2}));
    map(&mut s, &cs);
    let (mut b, c) = evolution(&mut s);
    let rows = quality::evolution::rows(&c);
    assert_eq!(b.submit(&mut s, &c.card_id, &[])["status"], "REPAIR_REQUIRED");
    let old = quality::evolution::id(&rows[0]["old"]).unwrap();
    let new = quality::evolution::id(&rows[0]["new"]).unwrap();
    let ob = s.record(&old).unwrap().based_on[0];
    let bad = json!({"op":"link","from":new.short(),"to":old.short(),"rel":"supersedes","basis":[ob.short()]});
    assert_eq!(b.submit(&mut s, &c.card_id, &[bad])["status"], "REPAIR_REQUIRED");
    let ops = rows.iter().map(|r| json!({"op":"none","pair":r["pair"],"reason":"No proven update of the same state."})).collect::<Vec<_>>();
    let r = b.submit(&mut s, &c.card_id, &ops);
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    let root = s.root();
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut b = Builder::new(BuilderConfig::default());
    b.recover(&s);
    assert_eq!(b.submit(&mut s, &c.card_id, &ops)["replayed"], true);
    assert_eq!(root, s.root());
}

#[test]
fn rotated_pool_assignments_recover_from_same_circle() {
    let (w, mut s, _, _) = fresh(json!({"ring_rotate":true}));
    let readers = vec!["w1".into(), "w2".into(), "w3".into()];
    let cfg = BuilderConfig { max_records: 3, author_runs: true, ..Default::default() };
    let mut p = ParallelBuilder::new(cfg, readers.clone());
    let first = p.offers(&mut s, 2, false).unwrap();
    assert!(!first.is_empty());
    let ids = first.iter().map(|c| c.card_id.clone()).collect::<Vec<_>>();
    drop(p);
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut p = ParallelBuilder::new(cfg, readers);
    p.recover(&s).unwrap();
    assert_eq!(p.offers(&mut s, 2, false).unwrap().iter().map(|c| c.card_id.clone()).collect::<Vec<_>>(), ids);
}
#[test]
fn evolution_link_is_proposed_and_confirmed_by_separate_checker() {
    let (_w, mut s, _, cs) = fresh(json!({"evolution_cards":true,"evolution_pairs_per_concept":1,"evolution_pairs_per_card":1}));
    map(&mut s, &cs);
    let (mut b, c) = evolution(&mut s);
    let p = quality::evolution::rows(&c)[0].clone();
    let a = quality::evolution::id(&p["old"]).unwrap();
    let n = quality::evolution::id(&p["new"]).unwrap();
    let basis = [s.record(&a).unwrap().based_on[0], s.record(&n).unwrap().based_on[0]];
    let reverse = json!({"op":"link","from":a.short(),"rel":"supersedes","to":n.short(),"basis":basis.iter().map(|r|r.short()).collect::<Vec<_>>()});
    assert_eq!(b.submit(&mut s, &c.card_id, &[reverse])["status"], "REPAIR_REQUIRED");
    let op = json!({"op":"link","from":n.short(),"rel":"supersedes","to":a.short(),"basis":basis.iter().map(|r|r.short()).collect::<Vec<_>>()});
    let r = b.submit(&mut s, &c.card_id, &[op]);
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    let l = s.links()[0].clone();
    assert_eq!(l.status, LinkStatus::Proposed);
    assert!(s.set_link_status(&l.id, LinkStatus::Accepted, "builder", &basis).is_err());
    s.set_link_status(&l.id, LinkStatus::Accepted, "independent", &basis).unwrap();
}
/// An answer across the first and the last report (2026-10-01 and 2026-10-04) on the reactor's state.
fn spanning_claim(s: &mut AuditState, obs: &[RecordId]) -> RecordId {
    let based_on = [obs[0], obs[3]].iter().map(|o| format!("@{}", to_hex(&o.0))).collect::<Vec<_>>();
    let r = s.submit_records(
        "w1",
        "summary",
        &Scope { docs: vec!["d0".into(), "d3".into()], ..Default::default() },
        &[json!({"kind":"claim","local_id":"x","text":"The reactor moved to state 3.","subject":"reactor","predicate":"has_state","object":"3","stance":"reported","based_on":based_on})],
    );
    assert!(r.error.is_none(), "{r:?}");
    r.accepted[0]
}
#[test]
fn withdrawn_newest_evidence_leaves_the_state_after_the_standing_date_unconfirmed() {
    let (w, mut s, obs, _) = fresh(json!({"stale_suspect":true}));
    let x = spanning_claim(&mut s, &obs);
    assert!(quality::annotate(&s, x).is_null());
    s.revoke_observation("owner", &obs[3]).unwrap();
    let a = quality::annotate(&s, x);
    assert_eq!(
        (a["support_status"].as_str(), a["temporal_status"].as_str(), a["stale_suspect"].as_bool()),
        (Some("WITHDRAWN"), Some("CURRENT_UNCERTAIN"), Some(true)),
        "{a}"
    );
    assert_eq!(a["evidence_gap"], json!({"evidence_until":"2026-10-01","withdrawn_after":"2026-10-04"}));
    assert!(quality::stale::suspects(&s).contains(&x));
    assert!(quality::stale::warning(&s, x).contains("the state after 2026-10-01 is unconfirmed"));
    assert!(quality::stale::prompt(&s).contains("TEMPORAL WARNINGS"));
    // the reread goes to the report that held the withdrawn evidence only
    let sections = quality::stale::later_sections(&s, x, 6000);
    assert!(!sections.is_empty() && sections.iter().all(|sec| sec.0 == "d3"), "{sections:?}");
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let t = d.acquire(&s, "reader", true, 0);
    assert_eq!(t["kind"], "INVESTIGATE", "{t}");
    assert!(t["prompt"].as_str().unwrap().contains("doc_id=\"d3\""), "{t}");
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(quality::annotate(&s, x), a);
}
/// The claim-by-claim definition of `suspects` before its one-pass support (2026-10-28): the fix must not change the result.
fn suspects_claim_by_claim(s: &AuditState) -> Vec<RecordId> {
    let mut ids = s.supersession_history().into_iter().map(|l| l.to).collect::<std::collections::BTreeSet<_>>();
    ids.extend(s.records_since(0).into_iter().filter(|r| r.kind.name() == "claim" && !s.is_grounded(&r.id)).map(|r| r.id));
    ids.into_iter().filter(|id| quality::stale::annotation(s, *id)["stale_suspect"] == true).collect()
}
#[test]
fn one_pass_suspects_equal_the_claim_by_claim_definition() {
    let (_w, mut s, obs, cs) = fresh(json!({"stale_suspect":true}));
    let x = spanning_claim(&mut s, &obs);
    map(&mut s, &cs);
    let l = link(&mut s, &obs, &cs);
    s.set_link_status(&l, LinkStatus::Accepted, "w2", &obs[..2]).unwrap();
    assert_eq!(quality::stale::suspects(&s), suspects_claim_by_claim(&s));
    for o in [obs[3], obs[1]] {
        s.revoke_observation("owner", &o).unwrap();
        let (fast, slow) = (quality::stale::suspects(&s), suspects_claim_by_claim(&s));
        assert_eq!(fast, slow);
        assert!(!fast.is_empty());
    }
    assert!(quality::stale::suspects(&s).contains(&x));
}
#[test]
fn kept_suspects_equal_suspects_computed_again_after_every_kind_of_command() {
    // 01.11.2026 measurement: each task acquire computed the suspects again (69-103 ms at the end of a live run); the store now
    // keeps them for an unchanged state and drops them at every command, like its support flags
    let (w, mut s, obs, cs) = fresh(json!({"stale_suspect":true}));
    let same = |s: &AuditState| {
        let kept = quality::stale::suspects(s);
        assert_eq!(kept, quality::stale::suspects_fresh(s));
        assert_eq!(quality::stale::suspects(s), kept, "asked again on the same state");
        kept
    };
    assert!(same(&s).is_empty());
    let x = spanning_claim(&mut s, &obs);
    map(&mut s, &cs);
    let l = link(&mut s, &obs, &cs);
    same(&s);
    s.set_link_status(&l, LinkStatus::Accepted, "w2", &obs[..2]).unwrap();
    same(&s);
    s.revoke_observation("owner", &obs[3]).unwrap();
    let before = same(&s);
    assert!(before.contains(&x), "a revocation makes a suspect");
    // a refused line changes nothing, and the kept suspects stay those of the unchanged state
    let r = s.submit_records(
        "w1",
        "refused",
        &Scope { docs: vec!["d0".into()], ..Default::default() },
        &[json!({"kind":"claim","local_id":"c","text":"Unsupported.","subject":"reactor","stance":"reported","based_on":["missing"]})],
    );
    assert!(r.accepted.is_empty(), "{r:?}");
    assert_eq!(same(&s), before);
    // a changed source and a restart
    s.put_document("owner", "d2", b"+++\ndate = \"2026-10-03\"\n+++\nscope common. Nothing else.").unwrap();
    let changed = same(&s);
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    assert_eq!(same(&s), changed, "after a restart");
    // a checkpoint that turns the policy off
    let r = s
        .submit_operations_id(
            "config-off",
            "kernel",
            &[],
            Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":{},"section_bytes":6000,"circle_readers":["w1","w2","w3"]}})),
        )
        .unwrap();
    assert_eq!(r["checkpointed"], true, "{r}");
    assert!(same(&s).is_empty(), "the policy is off");
}
#[test]
fn the_records_of_one_kind_are_every_record_filtered_by_kind_in_order() {
    let (_w, mut s, obs, cs) = fresh(json!({"stale_suspect":true}));
    spanning_claim(&mut s, &obs);
    map(&mut s, &cs);
    let l = link(&mut s, &obs, &cs);
    s.set_link_status(&l, LinkStatus::Accepted, "w2", &obs[..2]).unwrap();
    let all = s.records_since(0);
    for kind in ["observe", "claim", "relation", "hypothesis", "question", "done"].map(|k| sbgk_core::audit::RecordKind::parse(k).unwrap()) {
        let filtered: Vec<RecordId> = all.iter().filter(|r| r.kind == kind).map(|r| r.id).collect();
        assert_eq!(s.records_of_kind(kind).iter().map(|r| r.id).collect::<Vec<_>>(), filtered, "{kind:?}");
    }
    assert!(!s.records_of_kind(sbgk_core::audit::RecordKind::parse("question").unwrap()).is_empty());
}
#[test]
fn withdrawn_older_evidence_or_policy_off_leaves_no_gap() {
    let (_w, mut s, obs, _) = fresh(json!({"stale_suspect":true}));
    let x = spanning_claim(&mut s, &obs);
    s.revoke_observation("owner", &obs[0]).unwrap();
    assert!(quality::annotate(&s, x).is_null());
    assert!(quality::stale::suspects(&s).is_empty());
    let (_w, mut s, obs, _) = fresh(json!({}));
    let x = spanning_claim(&mut s, &obs);
    s.revoke_observation("owner", &obs[3]).unwrap();
    assert!(quality::annotate(&s, x).is_null());
    assert!(quality::stale::prompt(&s).is_empty());
}

/// The SUMMARIZE prompt of a window of four records: the reading-order cut that shows d0's claim without the d3 claim
/// superseding it, against registry R30 step 2 (`temporal_summary`).
fn summary_of_superseded_pair(q: Value) -> (Value, RecordId, RecordId) {
    let (_w, mut s, obs, cs) = fresh(q);
    let basis = [obs[0], obs[3]];
    let r = s
        .submit_operations_id(
            "late-supersedes",
            "builder",
            &[json!({"kind":"add_link","from":to_hex(&cs[3].0),"rel":"supersedes","to":to_hex(&cs[0].0),"basis":basis.iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()})],
            None,
        )
        .unwrap();
    assert!(r["error"].is_null(), "{r}");
    let l = LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap());
    s.set_link_status(&l, LinkStatus::Accepted, "checker", &basis).unwrap();
    let question = ResearchQuestion {
        id: "RQ1".into(),
        text: "What changed?".into(),
        about: vec!["reactor".into()],
        stances: vec![],
        relations: vec!["supersedes".into()],
        concept_types: vec![],
    };
    let d = Dispatcher::new(DispatchConfig { summary_records: 4, ..Default::default() }, vec![question]);
    (d.offline_diagnostics(&s)["summary_windows"]["RQ1"].clone(), cs[0], cs[3])
}
#[test]
fn temporal_summary_shows_a_superseded_claim_with_its_later_state_and_report_dates() {
    let records = |p: &str| p.split("\nRECORDS:\n").nth(1).expect("record window").split("\nACCEPTED LINKS:").next().unwrap().to_string();
    let common_guidance = |p: &str| {
        let block = p.split("COMMON ANSWER GUIDANCE:\n").nth(1).expect("shared answer instructions").split("\nEND COMMON ANSWER GUIDANCE").next().unwrap();
        assert!(block.contains("A report date says when the report stated something, not when it took effect."), "{block}");
        assert!(block.contains("A later report date alone does not prove replacement."), "{block}");
        assert!(block.contains("Never present an earlier state as current when later evidence supplied here replaces it."), "{block}");
        assert!(block.contains("When later evidence only qualifies an earlier state by adding a scope or condition, both stand"), "{block}");
    };
    // reading order alone: the window fills with d0 and d1, the earlier state is shown and its supersession is not
    let (w, old, new) = summary_of_superseded_pair(json!({}));
    let p = w["prompt"].as_str().unwrap();
    assert!(p.contains(&old.short()) && !p.contains(&new.short()), "{p}");
    assert_eq!(w["superseded_old_shown"][0]["new_shown"], false, "{w}");
    common_guidance(p);
    // Generic chronology guidance is always shared with A; only the record annotations depend on this retrieval policy.
    let window = records(p);
    assert!(window.contains("[d0] \"Reactor state 0.\"") && window.contains("[d1] \"Reactor state 1.\""), "{window}");
    assert!(!window.contains(", report date ") && !p.contains("SUPERSEDED (kernel"), "{p}");
    // R30 step 2: the pair is one unit, quotes carry their report dates in date order, and the supersession is spelled out
    let (w, old, new) = summary_of_superseded_pair(json!({"temporal_summary":true}));
    let p = w["prompt"].as_str().unwrap();
    assert_eq!(w["superseded_old_shown"][0]["new_shown"], true, "{w}");
    assert!(p.contains(&format!("{} supersedes {} (accepted)", new.short(), old.short())), "{p}");
    let window = records(p);
    let (first, last) = (
        window.find("[d0, report date 2026-10-01] \"Reactor state 0.\"").expect("d0 quote dated"),
        window.find("[d3, report date 2026-10-04] \"Reactor state 3.\"").expect("d3 quote dated"),
    );
    assert!(first < last, "records in report-date order: {p}");
    let warning = p.split("SUPERSEDED (kernel, from accepted links):").nth(1).expect("supersession spelled out");
    assert!(
        warning.contains(&format!(
            "{} (report date 2026-10-01) is superseded by {} (report date 2026-10-04) by the swarm's accepted link",
            old.short(),
            new.short()
        )),
        "{p}"
    );
    common_guidance(p);
}

#[test]
fn a_state_on_quotes_of_several_reports_is_dated_by_the_latest_of_them() {
    // run MCPpair_r1: the later end of a pair an answer cites rested on quotes of two pages, and the answer read "report date unknown"
    let (_w, mut s, obs, cs) = fresh(json!({"stale_suspect":true}));
    let later = answer_claim(&mut s, "l", &[obs[2], obs[3]]);
    let basis = [obs[0], obs[2], obs[3]];
    let op = json!({"kind":"add_link","from":to_hex(&later.0),"rel":"supersedes","to":to_hex(&cs[0].0),"basis":basis.iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()});
    let r = s.submit_operations_id("two-page-later", "builder", &[op], None).unwrap();
    assert!(r["error"].is_null(), "{r}");
    let l = LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap());
    s.set_link_status(&l, LinkStatus::Accepted, "checker", &basis).unwrap();
    let old = answer_claim(&mut s, "a", &[obs[0]]);
    let status = quality::stale::answer_status(&s, old, false);
    let pair = json!([{"earlier":cs[0].short(),"earlier_date":"2026-10-01","later":later.short(),"later_date":"2026-10-04"}]);
    assert_eq!(status["replaced"], pair, "{status}");
}
/// A summary's claim resting on `on` (directive `TS1-`: an answer to a research question).
fn answer_claim(s: &mut AuditState, local: &str, on: &[RecordId]) -> RecordId {
    answer_claim_text(s, local, "The reactor state.", "reactor", on)
}
fn answer_claim_text(s: &mut AuditState, local: &str, text: &str, subject: &str, on: &[RecordId]) -> RecordId {
    let based_on = on.iter().map(|r| format!("@{}", to_hex(&r.0))).collect::<Vec<_>>();
    let scope = Scope { docs: (0..4).map(|i| format!("d{i}")).collect(), ..Default::default() };
    let r = s.submit_records(
        "w1",
        &format!("TS1-{local}"),
        &scope,
        &[json!({"kind":"claim","local_id":local,"text":text,"subject":subject,"stance":"reported","based_on":based_on})],
    );
    assert!(r.error.is_none(), "{r:?}");
    r.accepted[0]
}
#[test]
fn an_answer_is_told_the_replaced_states_its_quotes_hold_not_a_verdict_on_its_text() {
    // registry R34a, Codex's check of bc7cf23: an earlier row kept in the final answer next to the later one had no mark.
    // Codex review of 40f97e0 (R34-01/02): a shared quote does not make another statement superseded, and quotes of both states
    // do not prove the text states the change, so the status names the evidence under the claim
    let (w, mut s, obs, cs) = fresh(json!({"stale_suspect":true}));
    let basis = [obs[0], obs[3]];
    let op = json!({"kind":"add_link","from":to_hex(&cs[3].0),"rel":"supersedes","to":to_hex(&cs[0].0),"basis":basis.iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()});
    let r = s.submit_operations_id("late-supersedes", "builder", &[op], None).unwrap();
    assert!(r["error"].is_null(), "{r}");
    let l = LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap());
    s.set_link_status(&l, LinkStatus::Accepted, "checker", &basis).unwrap();
    // a summary's claim rests on quotes: d0's quote is the earlier state's, d3's the later one's
    let (old, new, change) = (answer_claim(&mut s, "a", &[obs[0]]), answer_claim(&mut s, "b", &[obs[3]]), answer_claim(&mut s, "c", &[obs[0], obs[3]]));
    let status = |s: &AuditState, id| quality::stale::answer_status(s, id, false);
    let pair = json!([{"earlier":cs[0].short(),"earlier_date":"2026-10-01","later":cs[3].short(),"later_date":"2026-10-04"}]);
    assert_eq!(status(&s, old), json!({"temporal_status":"CITES_REPLACED","replaced":pair,"earlier_and_later":[]}));
    assert_eq!(status(&s, new)["temporal_status"], "LATEST_KNOWN", "the later state itself");
    assert_eq!(status(&s, change), json!({"temporal_status":"CITES_EARLIER_AND_LATER","replaced":[],"earlier_and_later":pair}));
    // R34-01: another statement on the shared quote is told the same evidence, and nothing is said about its own subject
    let other = answer_claim_text(&mut s, "v", "The neutron gate is open.", "neutron gate", &[obs[0]]);
    assert_eq!(status(&s, other), status(&s, old));
    // R34-02: a text that states only the earlier state on quotes of both is not told it is the latest known
    let only_old = answer_claim_text(&mut s, "w", "The reactor has state 0.", "reactor", &[obs[0], obs[3]]);
    assert_eq!(status(&s, only_old), status(&s, change));
    // ANS-01 (run MCPpair_r1): a summary lists readers' claims in its answer ids too; the replaced state itself is told so
    assert_eq!(status(&s, cs[0]), status(&s, old), "a reader's claim, the replaced state itself");
    assert_eq!(status(&s, cs[3])["temporal_status"], "LATEST_KNOWN", "a reader's claim, the later state");
    assert!(status(&s, obs[0]).is_null(), "only claims");
    assert_eq!(quality::stale::answer_status(&s, new, true)["temporal_status"], "CURRENT_UNCERTAIN");
    let before = status(&s, old);
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    assert_eq!(status(&s, old), before, "a projection: the same after a restart");
    // the later state loses its quote: the link no longer stands, and the earlier state is uncertain, not superseded
    s.revoke_observation("owner", &obs[3]).unwrap();
    for id in [old, cs[0]] {
        let warnings = quality::stale::answer_warnings(&s, id);
        assert!(!warnings.is_empty());
        assert_eq!(
            quality::stale::answer_status(&s, id, !warnings.is_empty()),
            json!({"temporal_status":"CURRENT_UNCERTAIN","replaced":[],"earlier_and_later":[]})
        );
    }
    assert!(quality::stale::answer_warnings(&s, obs[0]).is_empty(), "only claims");
    // off without stale_suspect
    let (_w, mut s, obs, _) = fresh(json!({}));
    let old = answer_claim(&mut s, "a", &[obs[0]]);
    assert!(status(&s, old).is_null());
}

/// A chain d0 <- d1 <- d2 (each later claim supersedes the one before) in a window of `budget` records (Codex 28.10, D05).
fn summary_of_chain(budget: usize) -> (Value, Vec<RecordId>) {
    let (_w, mut s, obs, cs) = fresh(json!({"temporal_summary":true}));
    for (k, (new, old)) in [(1usize, 0usize), (2, 1)].into_iter().enumerate() {
        let basis = [obs[old], obs[new]];
        let op = json!({"kind":"add_link","from":to_hex(&cs[new].0),"rel":"supersedes","to":to_hex(&cs[old].0),"basis":basis.iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()});
        let r = s.submit_operations_id(&format!("chain-{k}"), "builder", &[op], None).unwrap();
        assert!(r["error"].is_null(), "{r}");
        let l = LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap());
        s.set_link_status(&l, LinkStatus::Accepted, "checker", &basis).unwrap();
    }
    let question = ResearchQuestion {
        id: "RQ1".into(),
        text: "What changed?".into(),
        about: vec!["reactor".into()],
        stances: vec![],
        relations: vec!["supersedes".into()],
        concept_types: vec![],
    };
    let d = Dispatcher::new(DispatchConfig { summary_records: budget, ..Default::default() }, vec![question]);
    (d.offline_diagnostics(&s)["summary_windows"]["RQ1"].clone(), cs[..3].to_vec())
}
#[test]
fn temporal_summary_keeps_a_whole_chain_of_states_together_or_leaves_it_out() {
    // room for two of the three states: one hop showed d0 and d1, d1 as the later state with d2 hidden; now no shown state
    // has a hidden superseder, and the chain is left out whole
    let (w, cs) = summary_of_chain(4);
    let p = w["prompt"].as_str().unwrap();
    assert!(w["superseded_old_shown"].as_array().unwrap().iter().all(|x| x["new_shown"] == true), "{w}");
    assert!(cs.iter().all(|c| !p.contains(&c.short())), "the chain does not fit and is left out whole: {p}");
    assert!(p.contains("(say that the answer may be incomplete)"), "{p}");
    // room for the whole chain: all three states with both links, in report-date order
    let (w, cs) = summary_of_chain(6);
    let p = w["prompt"].as_str().unwrap();
    assert!(cs.iter().all(|c| p.contains(&c.short())), "{p}");
    assert_eq!(w["superseded_old_shown"].as_array().unwrap().len(), 2, "{w}");
    assert!(w["superseded_old_shown"].as_array().unwrap().iter().all(|x| x["new_shown"] == true), "{w}");
    let at = |c: &RecordId| p.find(&format!("{} claim", c.short())).unwrap();
    assert!(at(&cs[0]) < at(&cs[1]) && at(&cs[1]) < at(&cs[2]), "{p}");
    assert!(p.starts_with("TASK SUMMARIZE") && p.contains("WINDOW: 3 of"), "the relevant claims of the chain are counted: {p}");
}

/// No link at all: the neutron gate in reports 1 and 4, a turbine in report 2, one quote each, in a window of four records.
fn summary_by_words(q: Value) -> (Value, [RecordId; 3]) {
    let (_w, mut s, obs, _) = fresh(q);
    let early = reader_claim(&mut s, "w1", "n0", "The neutron gate is open.", obs[0], "d0");
    let turbine = reader_claim(&mut s, "w2", "t1", "The turbine is checked.", obs[1], "d1");
    let late = reader_claim(&mut s, "w3", "n3", "The neutron gate is removed.", obs[3], "d3");
    let question =
        ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["neutron gate".into(), "turbine".into()], ..Default::default() };
    let d = Dispatcher::new(DispatchConfig { summary_records: 4, ..Default::default() }, vec![question]);
    (d.offline_diagnostics(&s)["summary_windows"]["RQ1"].clone(), [early, turbine, late])
}
#[test]
fn a_summary_claim_brings_the_later_claim_most_like_it_by_words_only_when_asked() {
    // 31.10, MCPhints_r1 and MCPctl_none_r1/_r3: the later state was read, the swarm linked nothing, the window showed the earlier
    let (w, [early, turbine, late]) = summary_by_words(json!({"temporal_summary":true}));
    let p = w["prompt"].as_str().unwrap();
    assert!(p.contains(&early.short()) && p.contains(&turbine.short()) && !p.contains(&late.short()), "reading order fills the window: {p}");
    assert!(!p.contains("LATER ON THE SAME WORDS"), "{p}");
    // with the option the earlier gate state comes with the later one, named as a retrieval by words
    let (w, [early, turbine, late]) = summary_by_words(json!({"temporal_summary":true,"summary_companions":true}));
    let p = w["prompt"].as_str().unwrap();
    assert!(p.contains(&early.short()) && p.contains(&late.short()) && !p.contains(&turbine.short()), "{p}");
    let block = p.split("LATER ON THE SAME WORDS (kernel, a retrieval by words, not a link)").nth(1).expect("the pair named");
    assert!(block.contains(&format!("{} (report date 2026-10-01) and the later {} (report date 2026-10-04)", early.short(), late.short())), "{p}");
    // the option needs the temporal summary: without report dates there is no later state to bring
    let (w, [_, _, late]) = summary_by_words(json!({"summary_companions":true}));
    assert!(!w["prompt"].as_str().unwrap().contains(&late.short()), "{w}");
}

/// Codex's probe of e463b2f (28.10, D07): a summary prefix retained from an earlier answer holds the oldest state of a chain that
/// the swarm accepted later. The retained row must not stand in the window without the later states that supersede it.
fn retained_chain_window(prefix_by_checkpoint: bool) -> (Value, Vec<RecordId>) {
    let (w, mut s, obs, cs) = fresh(json!({"temporal_summary":true,"stale_suspect":true}));
    let q = ResearchQuestion {
        id: "RQ1".into(),
        text: "What changed?".into(),
        about: vec!["reactor".into()],
        stances: vec![],
        relations: vec!["supersedes".into()],
        concept_types: vec![],
    };
    let cfg = DispatchConfig { summary_records: 4, ..Default::default() };
    let mut d = Dispatcher::new(cfg.clone(), vec![q.clone()]);
    if prefix_by_checkpoint {
        let ck =
            json!({"key":"summary-prefix:RQ1","from":0,"to":0,"context":{"question_set_revision":d.question_set_revision(),"answer_ids":[to_hex(&cs[0].0)]}});
        let r = s.submit_operations_id("retained-prefix", "kernel", &[], Some(ck)).unwrap();
        assert!(r["error"].is_null() && r["checkpointed"] == true, "{r}");
    } else {
        // the native way: a summary answers with the d0 claim only, its coverage repair retains it
        let mut task = Value::Null;
        for now in 0..40 {
            let t = d.acquire(&s, "reader", true, now);
            if t["kind"] == "SUMMARIZE" {
                task = t;
                break;
            }
            let id = t["task_id"].as_str().expect("work before the summary");
            assert_eq!(d.submit(&mut s, id, "reader", &[], now)["status"], "COMMITTED");
        }
        let id = task["task_id"].as_str().expect("a summary task").to_string();
        let done = json!({"kind":"done","local_id":"done","rq_id":"RQ1","directive_id":id,"outcome":"answered","answer_ids":[cs[0].short()]});
        let r = d.submit(&mut s, &id, "reader", &[done], 41);
        assert_eq!((r["status"].as_str(), &r["retained_answer_ids"]), (Some("REPAIR_REQUIRED"), &json!([cs[0].short()])), "{r}");
    }
    for (k, (new, old)) in [(1usize, 0usize), (2, 1)].into_iter().enumerate() {
        let basis = [obs[new], obs[old]];
        let op = json!({"kind":"add_link","from":to_hex(&cs[new].0),"rel":"supersedes","to":to_hex(&cs[old].0),"basis":basis.iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()});
        let r = s.submit_operations_id(&format!("late-chain-{k}"), "builder", &[op], None).unwrap();
        assert!(r["error"].is_null(), "{r}");
        let l = LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap());
        s.set_link_status(&l, LinkStatus::Accepted, "checker", &basis).unwrap();
    }
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    let mut d = Dispatcher::new(cfg, vec![q]);
    d.recover(&s);
    (d.offline_diagnostics(&s)["summary_windows"]["RQ1"].clone(), cs[..3].to_vec())
}
#[test]
fn a_retained_old_state_comes_with_its_later_states_after_a_restart() {
    for by_checkpoint in [true, false] {
        let (w, cs) = retained_chain_window(by_checkpoint);
        let p = w["prompt"].as_str().unwrap();
        // the retained row is kept (the next done keeps it) and comes with the whole chain, even past the window of four
        assert!(cs.iter().all(|c| p.contains(&c.short())), "{p}");
        assert!(w["superseded_old_shown"].as_array().unwrap().iter().all(|x| x["new_shown"] == true), "{w}");
        assert!(p.contains(&format!("INCREMENTAL REPAIR: retain these independent answer records unchanged: {}", cs[0].short())), "{p}");
        assert!(!p.contains("RETAINED WITHOUT ROOM"), "{p}");
    }
}

#[test]
fn a_readers_claim_is_not_told_the_suspicion_of_another_claim_on_its_quote() {
    // Codex review of 729eda8, BATCH-02: a reader's two claims rest on one quote, "Pump A is OFF. Valve B is OPEN."; a later pump
    // state replaces the old one and then loses its quote. The old pump claim is a stale suspect; the valve claim beside it is not,
    // and its answer must not call it historical or uncertain
    const OLD: &str = "Pump A is OFF. Valve B is OPEN.";
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let w = Wal(std::env::temp_dir().join(format!("quality-neighbour-{nonce}-{}.wal", std::process::id())));
    let docs = [("old", "2024-01-01", OLD), ("new", "2025-01-01", "Pump A is ON."), ("confirm", "2026-01-01", "Pump A was OFF in 2024.")]
        .map(|(id, date, text)| (id.to_string(), format!("+++\ndate = \"{date}\"\n+++\n{text}\n").into_bytes()));
    let mut s = AuditState::create(&w.0, &AuditOntology::base(), &docs, "quality-test", sha256(b"quality")).unwrap();
    let r = s
        .submit_operations_id(
            "config",
            "kernel",
            &[],
            Some(json!({"key":"audit:mcp:coverage","from":0,"to":0,"context":{"graph_quality":{"stale_suspect":true}}})),
        )
        .unwrap();
    assert_eq!(r["checkpointed"], true);
    let mut obs = vec![];
    for (i, (doc, quote)) in [("old", OLD), ("new", "Pump A is ON."), ("confirm", "Pump A was OFF in 2024.")].into_iter().enumerate() {
        let scope = Scope { docs: vec![doc.into()], ..Default::default() };
        let r = s.submit_records(
            if i == 1 { "w2" } else { "w1" },
            &format!("read{i}"),
            &scope,
            &[json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["pump","valve"]})],
        );
        assert!(r.error.is_none(), "{r:?}");
        obs.push(r.accepted[0]);
    }
    let all = Scope { docs: vec!["old".into(), "new".into(), "confirm".into()], ..Default::default() };
    let mut claim = |local: &str, text: &str, subject: &str, as_of: u32, on: &[RecordId], actor: &str| {
        let based_on = on.iter().map(|b| format!("@{}", to_hex(&b.0))).collect::<Vec<_>>();
        let r = s.submit_records(
            actor,
            "reader-claims",
            &all,
            &[json!({"kind":"claim","local_id":local,"text":text,"subject":subject,"as_of":as_of,"stance":"reported","based_on":based_on})],
        );
        assert!(r.error.is_none(), "{r:?}");
        r.accepted[0]
    };
    let pump = claim("pump", "In 2024 Pump A was OFF.", "pump-a", 20240101, &[obs[0], obs[2]], "w1");
    let valve = claim("valve", "Valve B is OPEN.", "valve-b", 20240101, &[obs[0]], "w1");
    let new = claim("new", "In 2025 Pump A is ON.", "pump-a", 20250101, &[obs[1]], "w2");
    let op =
        json!({"kind":"add_link","from":to_hex(&new.0),"rel":"supersedes","to":to_hex(&pump.0),"basis":obs.iter().map(|b|to_hex(&b.0)).collect::<Vec<_>>()});
    let r = s.submit_operations_id("proposal", "builder", &[op], None).unwrap();
    assert!(r["error"].is_null(), "{r}");
    let link = LinkId(from_hex(r["results"][0]["id"].as_str().unwrap()).unwrap());
    s.set_link_status(&link, LinkStatus::Accepted, "checker", &obs).unwrap();
    s.revoke_observation("owner", &obs[1]).unwrap();
    let told = |s: &AuditState, id: RecordId| {
        let warnings = quality::stale::answer_warnings(s, id);
        (warnings.len(), quality::stale::answer_status(s, id, !warnings.is_empty())["temporal_status"].clone())
    };
    assert_eq!(told(&s, valve), (0, json!("LATEST_KNOWN")), "the valve fact is no stale suspect");
    let (warned, status) = told(&s, pump);
    assert!(warned > 0 && status == "CURRENT_UNCERTAIN", "the old pump state itself is: {warned} {status}");
    drop(s);
    let s = AuditState::open(&w.0).unwrap();
    assert_eq!(told(&s, valve), (0, json!("LATEST_KNOWN")), "the same after a restart");
}
fn reader_claim(s: &mut AuditState, author: &str, local: &str, text: &str, on: RecordId, doc: &str) -> RecordId {
    let r = s.submit_records(
        author,
        &format!("T7-{local}"),
        &Scope { docs: vec![doc.into()], ..Default::default() },
        &[json!({"kind":"claim","local_id":local,"text":text,"subject":"gate","stance":"reported","based_on":[format!("@{}", to_hex(&on.0))]})],
    );
    assert!(r.error.is_none(), "{r:?}");
    r.accepted[0]
}
#[test]
fn lexical_pairing_joins_claims_by_their_own_words_without_a_concept() {
    // step 3a of 31.10: pairs by the claims' own words joined the two sides of 7 to 11 of the 13 stale facts offline, pairs by a
    // shared concept 2 to 4; no concept is mapped here
    let (_w, mut s, obs, _) = fresh(json!({"evolution_cards":true,"evolution_pairing":"lexical","evolution_pairs_per_card":4}));
    let old = reader_claim(&mut s, "w1", "g0", "The neutron gate interlock is mandatory for every start.", obs[0], "d0");
    let new = reader_claim(&mut s, "w2", "g3", "The neutron gate interlock is withdrawn from the start sequence.", obs[3], "d3");
    reader_claim(&mut s, "w3", "k1", "Coolant pressure stays nominal during tests.", obs[1], "d1");
    let rows = quality::evolution::detect(&s).iter().flat_map(|c| c.metadata["pairs"].as_array().unwrap().clone()).collect::<Vec<_>>();
    let pair = rows.iter().find(|r| quality::evolution::id(&r["new"]) == Some(new)).unwrap_or_else(|| panic!("the later claim is paired: {rows:?}"));
    assert_eq!(quality::evolution::id(&pair["old"]), Some(old), "{pair}");
    assert_eq!((&pair["channel"], pair.get("shared_concept")), (&json!("corpus"), None), "{pair}");
    // an earlier claim is never the new end
    assert!(rows.iter().all(|r| quality::evolution::id(&r["new"]) != Some(old) || r["old_date"].as_str() < r["new_date"].as_str()), "{rows:?}");
}
#[test]
fn a_pair_no_reader_may_take_stays_in_the_plan_named_and_never_stops_the_offer() {
    // Codex's EVO-01 (review of a4a7fea): with two configured readers a pair of both their claims found no recipient, and
    // NO_NONAUTHOR_RECIPIENT stopped the whole offer; now that pair stays in the frozen plan, named, and the others are offered
    let (_w, mut s, _, cs) = fresh_with(json!({"evolution_cards":true,"evolution_pairs_per_concept":6,"evolution_pairs_per_card":4}), &["w1", "w2"]);
    map(&mut s, &cs);
    let plan = quality::evolution::detect(&s);
    let nobody = plan.iter().filter(|c| c.metadata["kind"] == quality::evolution::UNASSIGNABLE).collect::<Vec<_>>();
    assert_eq!(nobody.len(), 1, "{plan:?}");
    assert_eq!(nobody[0].metadata["reason"], "NO_NONAUTHOR");
    for c in plan.iter().filter(|c| c.metadata["kind"] == "evolution") {
        let authors = c.metadata["pairs"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| ["old", "new"].map(|k| s.record(&quality::evolution::id(&r[k]).unwrap()).unwrap().author))
            .collect::<Vec<_>>();
        assert!(["w1", "w2"].iter().any(|w| !authors.iter().any(|a| a == w)), "{c:?}");
    }
    let mut p = ParallelBuilder::new(BuilderConfig { max_records: 16, author_runs: true, ..Default::default() }, vec!["w1".into(), "w2".into()]);
    let mut pair_cards = vec![];
    for _ in 0..20 {
        let offered = p.offers(&mut s, 1, true).expect("the offer never stops on a pair no reader may take");
        if offered.iter().any(quality::evolution::is_card) {
            pair_cards = offered.iter().filter(|c| quality::evolution::is_card(c)).map(|c| c.card_id.clone()).collect();
            break;
        }
        for c in offered {
            assert_eq!(p.worker_mut(&c.card_id).unwrap().submit(&mut s, &c.card_id, &[])["status"], "CARD_DONE");
        }
    }
    assert!(!pair_cards.is_empty(), "the pairs a reader may take are offered");
    assert!(pair_cards.iter().all(|id| *id != nobody[0].id()), "{pair_cards:?}");
    assert_eq!(s.graph_quality_metrics()["evolution"]["pairs_without_a_taker"], nobody[0].metadata["pairs"].as_array().unwrap().len(), "named in the status");
    // once every card a reader may take is decided, the pool has caught up: the pair nobody may take does not hold it, also after a
    // recovery (claude-reviewer on a8d94c7, RV-01: it kept the circles' pool from catching up, and the run would wait to its deadline)
    for _ in 0..20 {
        let offered = p.offers(&mut s, 1, true).unwrap();
        if offered.is_empty() {
            break;
        }
        for c in offered {
            let ops = quality::evolution::rows(&c).iter().map(|r| json!({"op":"none","pair":r["pair"],"reason":"no relation is proved"})).collect::<Vec<_>>();
            assert_eq!(p.worker_mut(&c.card_id).unwrap().submit(&mut s, &c.card_id, &ops)["status"], "CARD_DONE", "{c:?}");
        }
    }
    assert!(p.caught_up(&s), "decided cards and a pair nobody may take: caught up");
    let mut again = ParallelBuilder::new(BuilderConfig { max_records: 16, author_runs: true, ..Default::default() }, vec!["w1".into(), "w2".into()]);
    again.recover(&s).unwrap();
    assert!(again.caught_up(&s), "the same after a recovery");
    // only the plan the pool names is counted (Gemini on 0b9d30cc): not a plan a save wrote before it stopped short of the pool,
    // nor, in a pool of format 1, a plan of format 2 left beside it
    let named = s.graph_quality_metrics()["evolution"]["pairs_without_a_taker"].clone();
    let plan = pool_plan(&s).unwrap();
    let put = |s: &mut AuditState, id: &str, key: String, context: Value| {
        let r = s.submit_operations_id(id, "kernel", &[], Some(json!({"key":key,"from":0,"to":0,"context":context}))).unwrap();
        assert_eq!(r["checkpointed"], true, "{r}");
    };
    put(&mut s, "unnamed-plan", plan_key(&to_hex(&sha256(b"unnamed"))), plan.clone());
    assert_eq!(s.graph_quality_metrics()["evolution"]["pairs_without_a_taker"], named, "a plan the pool does not name");
    let batch = s.checkpoint("builder:pool").unwrap()["context"]["batch"].clone();
    put(&mut s, "pool-of-format-one", "builder:pool".into(), json!({"format":"r2r-builder-pool/1","cards":[],"batch":batch,"pairs":plan["pairs"]}));
    assert_eq!(s.graph_quality_metrics()["evolution"]["pairs_without_a_taker"], named, "a pool of format 1 beside a plan of format 2");
}
#[test]
fn a_claim_on_quotes_of_two_report_dates_leads_the_answer_window() {
    // Gemini 31.10: a change across versions written as a claim on the quotes of both (the hint profile's RELATE) must not be
    // cut by the claim budget; with the time option it goes first, without it the window is as before
    let window = |q: Value| {
        let (_w, mut s, obs, _) = fresh(q);
        let change = spanning_claim(&mut s, &obs);
        let question = ResearchQuestion {
            id: "RQ1".into(),
            text: "What changed?".into(),
            about: vec!["reactor".into()],
            stances: vec![],
            relations: vec!["supersedes".into()],
            concept_types: vec![],
        };
        let d = Dispatcher::new(DispatchConfig { summary_claims: 1, ..Default::default() }, vec![question]);
        (d.offline_diagnostics(&s)["summary_windows"]["RQ1"]["prompt"].as_str().unwrap().to_string(), change)
    };
    let (p, change) = window(json!({"temporal_summary":true}));
    assert!(p.contains(&change.short()), "{p}");
    let (p, change) = window(json!({}));
    assert!(!p.contains(&change.short()), "{p}");
}
/// A concept on `on` under `function`, through the builder's kernel command, and `on` mapped to it.
fn placed(s: &mut AuditState, name: &str, function: &str, on: RecordId) -> Value {
    let r = s
        .submit_operations_id(
            &format!("place-{name}"),
            "builder",
            &[json!({"kind":"propose_concept","type":"Component","name":name,"aliases":[],"basis":[to_hex(&on.0)],"function":function})],
            None,
        )
        .unwrap();
    assert!(r["error"].is_null(), "{r}");
    let c = r["results"][0].clone();
    let m = s
        .submit_operations_id(&format!("map-{name}"), "builder", &[json!({"kind":"map_term","record":to_hex(&on.0),"term":"reactor","concept":c["id"]})], None)
        .unwrap();
    assert!(m["error"].is_null(), "{m}");
    c
}
/// The later claim's pair rows, with an earlier claim that states a change ("Added ...") or not, and the function layer on or off.
fn function_pairs(q: Value, states_change: bool) -> (Vec<Value>, RecordId, RecordId) {
    let (_w, mut s, obs, _) = fresh(q);
    let old_text = if states_change { "Added the gizmo framework for remote handling." } else { "The gizmo framework serves remote handling." };
    let old = reader_claim(&mut s, "w1", "f0", old_text, obs[0], "d0");
    // no word in common with the earlier claim: words alone never pair them
    let new = reader_claim(&mut s, "w2", "f3", "Clients present a widget badge on every call.", obs[3], "d3");
    let a = placed(&mut s, "gizmo framework", "remote handling", obs[0]);
    let b = placed(&mut s, "widget badge", "Remote  Handlings", obs[3]);
    assert_eq!((&a["function"], &b["function"]), (&json!("remote handling"), &json!("remote handling")), "one name for one function");
    let rows = quality::evolution::detect(&s).iter().flat_map(|c| c.metadata["pairs"].as_array().unwrap().clone()).collect::<Vec<_>>();
    (rows.into_iter().filter(|r| quality::evolution::id(&r["new"]) == Some(new)).collect(), old, new)
}
#[test]
fn a_claim_meets_the_records_of_change_of_its_function_only_when_asked() {
    // the address layer: a later detail meets the earlier record of change of its whole
    let on = json!({"evolution_cards":true,"evolution_pairing":"lexical","evolution_pairs_per_card":4,"concept_functions":true});
    let (rows, old, _) = function_pairs(on.clone(), true);
    let pair = rows.iter().find(|r| quality::evolution::id(&r["old"]) == Some(old)).unwrap_or_else(|| panic!("paired through the function: {rows:?}"));
    assert_eq!(pair["channel"], "function", "{pair}");
    // off, or an earlier claim that states no change: no such pair
    let off = json!({"evolution_cards":true,"evolution_pairing":"lexical","evolution_pairs_per_card":4});
    let (rows, old, _) = function_pairs(off, true);
    assert!(rows.iter().all(|r| quality::evolution::id(&r["old"]) != Some(old)), "{rows:?}");
    let (rows, old, _) = function_pairs(on.clone(), false);
    assert!(rows.iter().all(|r| quality::evolution::id(&r["old"]) != Some(old)), "a claim that states no change is no record of change: {rows:?}");
    // a declared change summary makes every claim of it a record of change
    let mut declared = on;
    declared["change_summary_documents"] = json!(["d0"]);
    let (rows, old, _) = function_pairs(declared, false);
    assert!(rows.iter().any(|r| quality::evolution::id(&r["old"]) == Some(old) && r["channel"] == "function"), "{rows:?}");
}
#[test]
fn a_builder_card_shows_known_functions_by_use_and_an_evolution_card_hides_the_function_channel() {
    let (_w, mut s, obs, _) = fresh(json!({"concept_functions":true}));
    placed(&mut s, "gizmo framework", "remote handling", obs[0]);
    placed(&mut s, "widget badge", "remote handling", obs[1]);
    placed(&mut s, "coolant loop", "cooling", obs[2]);
    let mut b = Builder::new(BuilderConfig { max_records: 16, ..Default::default() });
    let card = b.next_card(&s).unwrap().to_json();
    let known = card["known_functions"].as_array().unwrap();
    assert_eq!((&known[0]["function"], &known[0]["concepts"], &known[1]["function"]), (&json!("remote handling"), &json!(2), &json!("cooling")), "{known:?}");
    assert!(card["prompt"].as_str().unwrap().contains("FUNCTIONS:"), "{}", card["prompt"]);
    // off: neither the list nor the rule
    let (_w2, s2, _, _) = fresh(json!({}));
    let card = Builder::new(BuilderConfig { max_records: 16, ..Default::default() }).next_card(&s2).unwrap().to_json();
    assert!(card.get("known_functions").is_none() && !card["prompt"].as_str().unwrap().contains("FUNCTIONS:"), "{card}");
    // an evolution card shows a pair found through a function without its channel: the function is no evidence
    let row = |channel: &str| json!({"pair":format!("E{channel}"),"old":to_hex(&obs[0].0),"new":to_hex(&obs[3].0),"channel":channel,"similarity_per_mille":5});
    let c = sbgk_core::audit::builder::Card {
        card_id: "Ctest".into(),
        cursor_from: 0,
        cursor_to: 0,
        records: vec![],
        candidates: Default::default(),
        neighbors: vec![],
        concept_types: vec![],
        max_ops: 4,
        max_links: 4,
        pair: Some(json!({"old":to_hex(&obs[0].0),"new":to_hex(&obs[3].0),"metadata":{"kind":"evolution","pairs":[row("function"),row("corpus")]}})),
        ontology: None,
        review: None,
        functions: None,
    };
    let shown = c.to_json()["pair_metadata"]["metadata"]["pairs"].clone();
    assert_eq!((shown[0].get("channel"), shown[0].get("similarity_per_mille")), (None, None), "{shown}");
    assert_eq!(shown[1]["channel"], "corpus", "other channels stay as they were: {shown}");
}
#[test]
fn a_builder_places_a_new_concept_under_a_function_or_none_and_a_catchall_goes_back_to_repair() {
    let (_w, mut s, _, _) = fresh(json!({"concept_functions":true}));
    let mut b = Builder::new(BuilderConfig { max_records: 16, ..Default::default() });
    let c = b.next_card(&s).unwrap();
    let o = c.records.iter().find(|r| r.kind.name() == "observe").unwrap().id;
    let propose = |name: &str, function: Option<&str>| {
        let mut op = json!({"op":"propose_concept","type":"Component","name":name,"aliases":[],"basis":[o.short()]});
        if let Some(f) = function {
            op["function"] = json!(f);
        }
        op
    };
    let r = b.submit(&mut s, &c.card_id, &[propose("idle pump", Some("General"))]);
    assert_eq!(r["status"], "REPAIR_REQUIRED", "a catch-all function is refused: {r}");
    let r = b.submit(&mut s, &c.card_id, &[propose("idle pump", Some("Cooling Loops")), propose("spare valve", None)]);
    assert_eq!(r["status"], "CARD_DONE", "{r}");
    let by_name = |n: &str| s.concepts().into_iter().find(|c| c.name == n).unwrap().function;
    assert_eq!((by_name("idle pump").as_deref(), by_name("spare valve")), (Some("cooling loop"), None), "the function is optional");
}
#[test]
fn a_function_named_on_a_later_proposal_places_an_existing_concept_once_and_says_so() {
    // claude-reviewer's RV-01 of 8dfff576: the rule asks to leave the function out when unsure, and the reuse path dropped a later one
    let (_w, mut s, _, _) = fresh(json!({"concept_functions":true}));
    let mut b = Builder::new(BuilderConfig { max_records: 3, ..Default::default() });
    let mut propose_on_next_card = |s: &mut AuditState, function: Option<&str>| {
        let c = b.next_card(&*s).unwrap();
        let o = c.records.iter().find(|r| r.kind.name() == "observe").unwrap().id;
        let mut op = json!({"op":"propose_concept","type":"Component","name":"spare valve","aliases":[],"basis":[o.short()]});
        if let Some(f) = function {
            op["function"] = json!(f);
        }
        let r = b.submit(s, &c.card_id, &[op]);
        assert_eq!(r["status"], "CARD_DONE", "{r}");
        r
    };
    propose_on_next_card(&mut s, None);
    let valve = |s: &AuditState| s.concepts().into_iter().find(|c| c.name == "spare valve").unwrap();
    assert_eq!(valve(&s).function, None);
    let r = propose_on_next_card(&mut s, Some("Cooling Loops"));
    assert_eq!(valve(&s).function.as_deref(), Some("cooling loop"), "{r}");
    assert!(r.to_string().contains("now placed under"), "the agent is told: {r}");
    let r = propose_on_next_card(&mut s, Some("ventilation"));
    assert_eq!(valve(&s).function.as_deref(), Some("cooling loop"), "the first placement stays");
    assert!(r.to_string().contains("stays under its function"), "{r}");
}

/// Closes every open card of the pool's batch as its builder's close marker does, so the next offer saves a new batch.
fn close_batch(s: &mut AuditState) {
    let pool = s.checkpoint("builder:pool").unwrap()["context"].clone();
    let batch = pool["batch"].clone();
    for spec in pool["cards"].as_array().unwrap().iter().filter(|v| v["batch"] == batch) {
        let id = spec["id"].as_str().unwrap();
        let ck = json!({"key":format!("builder:pool:closed:{id}"),"from":0,"to":0,"context":{"card_id":id,"range_from":spec["from"],"range_to":spec["to"]}});
        let r = s.submit_operations_id(&format!("close-{id}"), "kernel", &[], Some(ck)).unwrap();
        assert_eq!(r["checkpointed"], true, "{r}");
    }
}

/// The pair plan the pool (format 2) names.
fn pool_plan<S: AuditStore>(s: &S) -> Option<Value> {
    let pool = s.checkpoint("builder:pool")?["context"].clone();
    s.checkpoint(&plan_key(pool["plan"].as_str()?)).map(|c| c["context"].clone())
}

/// The key of the n-th chunk of pairs the pool (format 2) names.
fn chunk_key(s: &AuditState, n: usize) -> String {
    format!("builder:pool:pairs:{}", s.checkpoint("builder:pool").unwrap()["context"]["pair_chunks"][n].as_str().unwrap())
}

/// A pool past the freeze of its pair plan: record cards closed batch by batch until the frozen plan holds pairs.
fn pool_with_pairs() -> (Wal, AuditState, ParallelBuilder, BuilderConfig, Vec<String>) {
    let (w, mut s, _, cs) = fresh(json!({"evolution_cards":true,"evolution_pairs_per_concept":1,"evolution_pairs_per_card":1}));
    map(&mut s, &cs);
    let readers: Vec<String> = vec!["w1".into(), "w2".into(), "w3".into()];
    let cfg = BuilderConfig { max_records: 3, author_runs: true, ..Default::default() };
    let mut p = ParallelBuilder::new(cfg, readers.clone());
    let frozen = |s: &AuditState| pool_plan(s).is_some_and(|c| c["pairs"].as_array().is_some_and(|ps| !ps.is_empty()));
    for _ in 0..20 {
        p.offers(&mut s, 2, true).unwrap();
        if frozen(&s) {
            break;
        }
        close_batch(&mut s);
    }
    assert!(frozen(&s), "the plan froze with pairs");
    (w, s, p, cfg, readers)
}

fn ids(cards: Vec<sbgk_core::audit::builder::Card>) -> Vec<String> {
    cards.iter().map(|c| c.card_id.clone()).collect()
}

#[test]
fn the_pool_writes_its_pair_plan_once_and_a_restart_reads_the_same_cards() {
    // 01.11.2026 measurement: 96-98% of a live run's journal was the pool rewritten at every batch with the plan in it twice
    let (w, mut s, mut p, cfg, readers) = pool_with_pairs();
    let pool = s.checkpoint("builder:pool").unwrap()["context"].clone();
    assert_eq!(pool["format"], "r2r-builder-pool/2");
    assert!(pool.get("pairs").is_none(), "the plan is not in the pool: {pool}");
    let pair_cards: Vec<Value> = pool["cards"].as_array().unwrap().iter().filter(|c| !c["pair"].is_null()).cloned().collect();
    assert!(!pair_cards.is_empty());
    assert!(pair_cards.iter().all(|c| c["pair"] == json!({"chunk":0})), "the pool names the chunk, not the pair: {pool}");
    let chunk = s.checkpoint(&chunk_key(&s, 0)).unwrap()["context"].clone();
    assert!(pair_cards.iter().all(|c| chunk["pairs"][c["id"].as_str().unwrap()].is_object()), "{chunk}");
    let open = ids(p.offers(&mut s, 2, true).unwrap());
    assert!(!open.is_empty());
    drop(p);
    drop(s);
    let mut s = AuditState::open(&w.0).unwrap();
    let mut p = ParallelBuilder::new(cfg, readers);
    p.recover(&s).unwrap();
    assert_eq!(ids(p.offers(&mut s, 2, true).unwrap()), open, "a restart offers the same cards");
    // a later batch writes neither the plan nor the pairs again: at most the pool itself
    let before = s.transaction_sequence().unwrap_or(0);
    close_batch(&mut s);
    let closed = s.transaction_sequence().unwrap_or(0);
    assert_eq!(closed - before, open.len() as u64);
    p.offers(&mut s, 2, true).unwrap();
    assert!(s.transaction_sequence().unwrap_or(0) <= closed + 1);
    assert_eq!(s.checkpoint("builder:pool").unwrap()["context"]["pair_chunks"].as_array().unwrap().len(), 1);
}

#[test]
fn a_pool_of_format_one_is_read_and_its_next_save_writes_format_two_and_a_changed_pair_is_refused() {
    let (_w, mut s, mut p, cfg, readers) = pool_with_pairs();
    let open = ids(p.offers(&mut s, 2, true).unwrap());
    // the same catalog as format 1 wrote it: every pair in its card and the plan in the pool
    let mut pool = s.checkpoint("builder:pool").unwrap()["context"].clone();
    let chunk = s.checkpoint(&chunk_key(&s, 0)).unwrap()["context"].clone();
    for c in pool["cards"].as_array_mut().unwrap() {
        if !c["pair"].is_null() {
            c["pair"] = chunk["pairs"][c["id"].as_str().unwrap()].clone();
        }
    }
    let v1 = json!({"format":"r2r-builder-pool/1","cards":pool["cards"],"batch":pool["batch"],"pairs":pool_plan(&s).unwrap()["pairs"]});
    let r = s.submit_operations_id("old-pool", "kernel", &[], Some(json!({"key":"builder:pool","from":0,"to":0,"context":v1}))).unwrap();
    assert_eq!(r["checkpointed"], true, "{r}");
    let mut old = ParallelBuilder::new(cfg, readers.clone());
    old.recover(&s).unwrap();
    assert_eq!(ids(old.offers(&mut s, 2, true).unwrap()), open, "format 1 reads the same cards");
    // its first save writes format 2 with every pair card's pair: a later reading gives the pool a new card to save
    close_batch(&mut s);
    let r = s.submit_records(
        "w1",
        "late",
        &Scope { docs: vec!["d0".into()], ..Default::default() },
        &[
            json!({"kind":"observe","local_id":"o","doc_id":"d0","exact_quote":"neutron","terms":["neutron gate"]}),
            json!({"kind":"claim","local_id":"c","text":"The neutron gate is named.","subject":"neutron gate","stance":"reported","based_on":["o"]}),
        ],
    );
    assert!(r.error.is_none(), "{r:?}");
    old.offers(&mut s, 2, true).unwrap();
    let pool = s.checkpoint("builder:pool").unwrap()["context"].clone();
    assert_eq!(pool["format"], "r2r-builder-pool/2", "{pool}");
    let key = chunk_key(&s, 0);
    let chunk = s.checkpoint(&key).unwrap()["context"].clone();
    assert!(pool["cards"].as_array().unwrap().iter().filter(|c| !c["pair"].is_null()).all(|c| chunk["pairs"][c["id"].as_str().unwrap()].is_object()));
    // a pair changed in its chunk no longer matches the digest the pool names
    let mut changed = chunk;
    let id = changed["pairs"].as_object().unwrap().keys().next().unwrap().clone();
    changed["pairs"][&id]["metadata"]["note"] = json!("changed");
    let r = s.submit_operations_id("changed-pairs", "kernel", &[], Some(json!({"key":key,"from":0,"to":0,"context":changed}))).unwrap();
    assert_eq!(r["checkpointed"], true, "{r}");
    assert_eq!(ParallelBuilder::new(cfg, readers).recover(&s).unwrap_err()["code"], "BAD_POOL_PAIRS");
}

/// Codex's review of 0b9d30cc (POOL-B01), after his reproduction: two saves of the frozen plan stopped before the pool itself was
/// written, the sources changed between them and changed back, and the pool then named plan A while the plan's key held plan B
/// (the retried write of A found its earlier receipt and wrote nothing); a restart refused the pool with BAD_POOL_PAIRS.
mod pool_saves_stopped_before_the_pool {
    use super::*;
    use sbgk_core::audit::{ConceptId, ConceptView, LinkView, Prior, RecordView, SubmitReport};
    use sbgk_core::error::{Code, KernelError};
    use sbgk_core::hash::Hash;

    /// AuditState, except that the next write of the pool itself is refused before it reaches the store.
    struct FaultStore {
        inner: AuditState,
        refuse_pool: bool,
    }
    impl AuditStore for FaultStore {
        fn docs(&self) -> Vec<String> {
            AuditStore::docs(&self.inner)
        }
        fn document_label(&self, id: &str) -> String {
            AuditStore::document_label(&self.inner, id)
        }
        fn document_date(&self, _id: &str) -> Option<String> {
            AuditStore::document_date(&self.inner, _id)
        }
        fn doc_text(&self, doc_id: &str) -> Option<String> {
            AuditStore::doc_text(&self.inner, doc_id)
        }
        fn submit_records(&mut self, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
            AuditStore::submit_records(&mut self.inner, agent, directive, scope, lines)
        }
        fn submit_records_id(&mut self, _submission_id: &str, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
            AuditStore::submit_records_id(&mut self.inner, _submission_id, agent, directive, scope, lines)
        }
        fn submit_scoped_records_id(&mut self, id: &str, agent: &str, directive: &str, scope: &Scope, _issued: &[RecordId], lines: &[Value]) -> SubmitReport {
            AuditStore::submit_scoped_records_id(&mut self.inner, id, agent, directive, scope, _issued, lines)
        }
        fn records_since(&self, cursor: u64) -> Vec<RecordView> {
            AuditStore::records_since(&self.inner, cursor)
        }
        fn record(&self, id: &RecordId) -> Option<RecordView> {
            AuditStore::record(&self.inner, id)
        }
        fn local_record(&self, _agent: &str, _directive: &str, _local_id: &str) -> Option<RecordId> {
            AuditStore::local_record(&self.inner, _agent, _directive, _local_id)
        }
        fn is_grounded(&self, id: &RecordId) -> bool {
            AuditStore::is_grounded(&self.inner, id)
        }
        fn is_answer_support(&self, id: &RecordId) -> bool {
            AuditStore::is_answer_support(&self.inner, id)
        }
        fn head(&self) -> u64 {
            AuditStore::head(&self.inner)
        }
        fn ontology_version(&self) -> (u64, Hash) {
            AuditStore::ontology_version(&self.inner)
        }
        fn concept_types(&self) -> Vec<String> {
            AuditStore::concept_types(&self.inner)
        }
        fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView> {
            AuditStore::candidates(&self.inner, term, limit)
        }
        fn concept(&self, id: &ConceptId) -> Option<ConceptView> {
            AuditStore::concept(&self.inner, id)
        }
        fn propose_concept(&mut self, by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> Result<ConceptView, KernelError> {
            AuditStore::propose_concept(&mut self.inner, by, ty, name, aliases, basis)
        }
        fn map_term(&mut self, by: &str, rec: &RecordId, term: &str, concept: &ConceptId) -> Result<(), KernelError> {
            AuditStore::map_term(&mut self.inner, by, rec, term, concept)
        }
        fn concepts_of(&self, rec: &RecordId) -> Vec<ConceptId> {
            AuditStore::concepts_of(&self.inner, rec)
        }
        fn mapping_authors_of(&self, _concept: &ConceptId) -> Option<Vec<(String, usize)>> {
            AuditStore::mapping_authors_of(&self.inner, _concept)
        }
        fn mapped_terms_of(&self, _concept: &ConceptId) -> Option<Vec<(RecordId, String)>> {
            AuditStore::mapped_terms_of(&self.inner, _concept)
        }
        fn records_of(&self, concept: &ConceptId) -> Vec<RecordId> {
            AuditStore::records_of(&self.inner, concept)
        }
        fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> Result<LinkView, KernelError> {
            AuditStore::add_link(&mut self.inner, by, from, rel, to, basis)
        }
        fn set_link_status(&mut self, id: &LinkId, status: LinkStatus, by: &str, basis: &[RecordId]) -> Result<(), KernelError> {
            AuditStore::set_link_status(&mut self.inner, id, status, by, basis)
        }
        fn link(&self, id: &LinkId) -> Option<LinkView> {
            AuditStore::link(&self.inner, id)
        }
        fn links(&self) -> Vec<LinkView> {
            AuditStore::links(&self.inner)
        }
        fn links_of(&self, rec: &RecordId) -> Vec<LinkView> {
            AuditStore::links_of(&self.inner, rec)
        }
        fn link_usable(&self, id: &LinkId) -> bool {
            AuditStore::link_usable(&self.inner, id)
        }
        fn supersession_history(&self) -> Vec<LinkView> {
            AuditStore::supersession_history(&self.inner)
        }
        fn usable_links(&self) -> Option<std::collections::BTreeSet<LinkId>> {
            AuditStore::usable_links(&self.inner)
        }
        fn ontology_revision_state(&self) -> Option<Value> {
            AuditStore::ontology_revision_state(&self.inner)
        }
        fn concepts(&self) -> Vec<ConceptView> {
            AuditStore::concepts(&self.inner)
        }
        fn checkpoint(&self, _key: &str) -> Option<Value> {
            AuditStore::checkpoint(&self.inner, _key)
        }
        fn operations_receipt(&self, _submission_id: &str, _actor: &str, _operations: &[Value], _checkpoint: Option<Value>) -> Prior {
            AuditStore::operations_receipt(&self.inner, _submission_id, _actor, _operations, _checkpoint)
        }
        fn receipt_outcome(&self, _submission_id: &str, _actor: &str) -> Option<Value> {
            AuditStore::receipt_outcome(&self.inner, _submission_id, _actor)
        }
        fn support_map(&self) -> Option<std::collections::BTreeMap<RecordId, (bool, bool)>> {
            AuditStore::support_map(&self.inner)
        }
        fn run_namespace(&self) -> Hash {
            AuditStore::run_namespace(&self.inner)
        }
        fn root(&self) -> Hash {
            AuditStore::root(&self.inner)
        }
        fn submit_operations_id(&mut self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Result<Value, KernelError> {
            if self.refuse_pool && checkpoint.as_ref().is_some_and(|c| c["key"] == "builder:pool") {
                self.refuse_pool = false;
                return Err(KernelError::new(Code::BadField, "REFUSED_BEFORE_THE_POOL"));
            }
            self.inner.submit_operations_id(id, actor, operations, checkpoint)
        }
    }

    /// The journal, the store, the pool, its config and readers, and the texts of the sources.
    type Fixture = (Wal, FaultStore, ParallelBuilder, BuilderConfig, Vec<String>, Vec<(String, String)>);

    /// Record cards closed until the pool has caught up, its pair plan not frozen yet.
    fn before_freeze() -> Fixture {
        let (w, mut s, _, claims) = fresh(json!({"evolution_cards":true,"evolution_pairs_per_concept":1,"evolution_pairs_per_card":1}));
        map(&mut s, &claims);
        let docs = s.docs().into_iter().map(|d| (d.clone(), s.doc_text(&d).unwrap())).collect();
        let readers: Vec<String> = vec!["w1".into(), "w2".into(), "w3".into()];
        let cfg = BuilderConfig { max_records: 3, author_runs: true, ..Default::default() };
        let mut p = ParallelBuilder::new(cfg, readers.clone());
        for _ in 0..20 {
            if p.offers(&mut s, 2, false).unwrap().is_empty() {
                break;
            }
            close_batch(&mut s);
        }
        assert!(p.caught_up(&s));
        assert!(s.checkpoint("builder:pool").unwrap()["context"]["plan"].is_null());
        assert!(!quality::pair_candidates(&s).is_empty());
        (w, FaultStore { inner: s, refuse_pool: false }, p, cfg, readers, docs)
    }

    /// A restart: the journal reopens with the same roots and the pool is read back from it.
    fn reopen(w: &Wal, s: FaultStore, cfg: BuilderConfig, readers: &[String]) -> (FaultStore, ParallelBuilder) {
        let roots = (s.inner.engine_root(), s.inner.audit_root());
        drop(s);
        let inner = AuditState::open(&w.0).unwrap();
        assert_eq!((inner.engine_root(), inner.audit_root()), roots);
        let mut p = ParallelBuilder::new(cfg, readers.to_vec());
        p.recover(&inner).unwrap();
        (FaultStore { inner, refuse_pool: false }, p)
    }

    fn freeze_stopped_before_the_pool(p: &mut ParallelBuilder, s: &mut FaultStore) {
        s.refuse_pool = true;
        let err = p.offers(s, 2, true).unwrap_err();
        assert!(err.to_string().contains("REFUSED_BEFORE_THE_POOL"), "{err}");
        assert!(s.inner.checkpoint("builder:pool").unwrap()["context"]["plan"].is_null());
    }

    #[test]
    fn a_freeze_stopped_before_the_pool_is_saved_again_and_read_after_a_restart() {
        let (w, mut s, mut p, cfg, readers, _) = before_freeze();
        freeze_stopped_before_the_pool(&mut p, &mut s);
        (s, p) = reopen(&w, s, cfg, &readers);
        let open = ids(p.offers(&mut s, 2, true).unwrap());
        assert!(!open.is_empty());
        let (mut s, mut p) = reopen(&w, s, cfg, &readers);
        assert_eq!(ids(p.offers(&mut s, 2, true).unwrap()), open);
    }

    #[test]
    fn a_plan_written_then_another_and_then_the_first_again_is_read_back_as_the_pool_names_it() {
        let (w, mut s, mut p, cfg, readers, docs) = before_freeze();
        let a: Vec<String> = quality::pair_candidates(&s).iter().map(|x| x.id()).collect();
        freeze_stopped_before_the_pool(&mut p, &mut s);
        (s, p) = reopen(&w, s, cfg, &readers);
        // the sources change and no pair is left: the save of the empty plan B stops before the pool too
        for (d, _) in &docs {
            s.inner.put_document("owner", d, b"Evidence unavailable.").unwrap();
        }
        assert!(quality::pair_candidates(&s).is_empty());
        freeze_stopped_before_the_pool(&mut p, &mut s);
        (s, p) = reopen(&w, s, cfg, &readers);
        // the same sources come back, and plan A with them
        for (d, text) in &docs {
            s.inner.put_document("owner", d, text.as_bytes()).unwrap();
        }
        assert_eq!(quality::pair_candidates(&s).iter().map(|x| x.id()).collect::<Vec<_>>(), a);
        let open = ids(p.offers(&mut s, 2, true).unwrap());
        assert!(!open.is_empty());
        assert!(pool_plan(&s).unwrap()["pairs"].as_array().is_some_and(|ps| !ps.is_empty()), "the pool names plan A and its key holds A");
        drop(p);
        let (mut s, mut p) = reopen(&w, s, cfg, &readers);
        assert_eq!(ids(p.offers(&mut s, 2, true).unwrap()), open, "the published pool is read after a restart");
    }
}
