//! Literal domains apply to computed rule heads, including claim-free automatic derivation.

use sbgk_core::hash::{sha256, to_hex};
use sbgk_core::node::{Claim, Polarity, ST_SUPPORTED};
use sbgk_core::{build_container, open_session, verify_container, CdcParams, Code, Ontology, Session, SwarmSession, Targets};
use serde_json::{json, Value};

fn ontology_value(mode: &str, restricted: bool) -> Value {
    let mut v = json!({
        "entities": [{"id": "x", "type": "X"}],
        "predicates": [
            {"id": "raw", "subject": "X", "object": "@literal"},
            {"id": "flag", "subject": "X", "object": "@literal"}
        ],
        "rules": [{"id": "R", "mode": mode, "body": [{"p": "raw"}],
            "head": {"s": "0.s", "p": "flag", "o": "0.o"}}]
    });
    if restricted {
        v["predicates"][1]["allowed_values"] = json!(["true"]);
    }
    v
}

fn session(ontology: Value, literal: &str) -> Session {
    let mut s = Session::new(Ontology::from_value(&ontology).unwrap(), CdcParams::default());
    let quote = format!("x has {literal}.");
    s.put_document("policy", format!("{quote}\n").as_bytes());
    s.apply_line(&json!({"seq": 1, "op": "bind_evidence", "local_id": "e", "doc_id": "policy", "exact_quote": quote}).to_string()).unwrap();
    s.apply_line(
        &json!({"seq": 2, "op": "assert_fact", "local_id": "f", "s": "x", "p": "raw", "o": literal,
            "polarity": "POS", "ctx": "prod", "t": [0, 1], "evidence": ["e"]})
        .to_string(),
    )
    .unwrap();
    s
}

fn flag(literal: &str) -> Claim {
    Claim { s: "x".into(), p: "flag".into(), o: literal.into(), pol: Polarity::Pos, ctx: "prod".into(), t_from: 0, t_to: 1 }
}

fn derive(literal: &str, explicit: bool) -> String {
    let mut event = json!({"seq": 3, "op": "derive", "local_id": "d", "rule": "R", "premises": ["f"]});
    if explicit {
        event["claim"] = json!({"s": "x", "p": "flag", "o": literal, "polarity": "POS", "ctx": "prod", "t": [0, 1]});
    }
    event.to_string()
}

fn rejects_disallowed_head(mode: &str) {
    for explicit in [false, true] {
        let mut s = session(ontology_value(mode, true), "false");
        let root = s.state_root();
        let wal = s.wal.bytes.clone();
        let nodes = s.engine.node_count();
        let error = s.apply_line(&derive("false", explicit)).unwrap_err();
        assert_eq!(error.code, Code::LiteralNotAllowed, "{mode}, explicit={explicit}");
        assert_eq!(error.field.as_deref(), Some("claim.o"));
        assert_eq!(error.expected_by_kernel, json!({"predicate": "flag", "allowed_values": ["true"]}));
        assert_eq!(error.obligation["action"], "resubmit_with_allowed_literal");
        assert_eq!(s.last_seq, 2);
        assert_eq!(s.state_root(), root, "a rejected head must not change support");
        assert_eq!(s.wal.bytes, wal, "a rejected head must not enter the WAL");
        assert_eq!(s.engine.node_count(), nodes);
        assert!(!s.engine.contains(&flag("false").id()));
        assert!(s.engine.oracle_check());
    }
}

#[test]
fn and_copy_rule_rejects_disallowed_implicit_and_explicit_heads() {
    rejects_disallowed_head("AND");
}

#[test]
fn or_copy_rule_rejects_disallowed_implicit_and_explicit_heads() {
    rejects_disallowed_head("OR");
}

#[test]
fn allowed_heads_have_identical_canonical_output_with_or_without_claim() {
    for mode in ["AND", "OR"] {
        let mut containers = Vec::new();
        for explicit in [false, true] {
            let mut s = session(ontology_value(mode, true), "true");
            s.apply_line(&derive("true", explicit)).unwrap();
            assert_eq!(s.engine.status_of(&flag("true").id()), Some(ST_SUPPORTED));
            assert!(s.engine.oracle_check());
            let bytes = build_container(&mut s);
            verify_container(&bytes).unwrap();
            let mut reopened = open_session(&bytes).unwrap();
            assert_eq!(reopened.state_root(), s.state_root());
            containers.push(bytes);
        }
        assert_eq!(containers[0], containers[1], "{mode}");
    }
}

#[test]
fn auto_closure_skips_invalid_head_without_looping_or_blocking_valid_derivation() {
    // The frontier's automatic rule enumeration currently supports AND rules only.
    let mode = "AND";
    let mut ontology = ontology_value(mode, true);
    ontology["entities"].as_array_mut().unwrap().push(json!({"id": "y", "type": "X"}));
    ontology["predicates"].as_array_mut().unwrap().push(json!({"id": "approved", "subject": "X", "object": "@literal", "allowed_values": ["true"]}));
    ontology["rules"].as_array_mut().unwrap().push(json!({"id": "R_good", "mode": mode, "body": [{"p": "raw"}],
            "head": {"s": {"const": "y"}, "p": "approved", "o": {"const": "true"}}}));
    let mut sw = SwarmSession::new(session(ontology, "false"));
    sw.set_targets(Targets::from_json(&json!({"goals": [{"entity": "x", "predicate": "flag"}, {"entity": "y", "predicate": "approved"}]})).unwrap());
    let response = sw.acquire_directive("worker", None, None, Some(0));
    assert_ne!(response["status"], "COMPLETE", "the invalid goal remains unclosed");
    assert_eq!(sw.stats.auto_close_errors, 1, "{mode}: retrying the same bad head must terminate");
    assert_eq!(sw.stats.auto_closed_total, 1, "the valid sibling rule still fires");
    assert!(!sw.session.engine.contains(&flag("false").id()));
    let approved = Claim { s: "y".into(), p: "approved".into(), ..flag("true") };
    assert_eq!(sw.session.engine.status_of(&approved.id()), Some(ST_SUPPORTED));
    assert_eq!(sw.session.last_seq, 3, "only the valid derivation is committed");
    verify_container(&build_container(&mut sw.session)).unwrap();
}

#[test]
fn absent_enum_preserves_legacy_computed_constant_domain() {
    for mode in ["AND", "OR"] {
        // Existing ontologies allow an unrestricted constant head, including an empty one.
        // The enum fix must not add unrelated validation to that claim-free legacy path.
        for literal in ["", "arbitrary"] {
            let mut ontology = ontology_value(mode, false);
            ontology["rules"][0]["head"]["o"] = json!({"const": literal});
            let mut s = session(ontology, "false");
            s.apply_line(&derive(literal, false)).unwrap();
            assert_eq!(s.engine.status_of(&flag(literal).id()), Some(ST_SUPPORTED));
            verify_container(&build_container(&mut s)).unwrap();
        }
    }
}

#[test]
fn absent_enum_preserves_legacy_false_literal_and_frozen_hashes() {
    // Frozen using the unmodified c68dc8c CLI (binary SHA256 7439901e4b64dfddc5578bdcac3b60737f9fb099580296617c6144f4c930500f).
    let baselines = [
        (
            "AND",
            "26b4d300fb407bb81301ddbeaf016d3b1c894c2b02b836926b1ca40f4a07e458",
            "21b5ceec51ab19d82f31775ad3b9ec0b46e5db7f2c3f91dbc1c596b64182af3a",
            "590f92ae98069792ca5e131897f702557e74f188b1466a36e1b039be98a02014",
        ),
        (
            "OR",
            "386bd026740e4e177d1ea164d6a1ac2413a92e196723994211637a7ff973b452",
            "846319981bd8c7fb013f64d60721492e7c6f84bf487c1266d2eece66b88ba698",
            "620ac5a89db953c76e6e5c1587cdcad63cbedf69abdfd147ab1944a42f5f4bb1",
        ),
    ];
    for (mode, ontology_hash, state_root, container_hash) in baselines {
        for explicit in [false, true] {
            let mut s = session(ontology_value(mode, false), "false");
            s.apply_line(&derive("false", explicit)).unwrap();
            assert_eq!(s.engine.status_of(&flag("false").id()), Some(ST_SUPPORTED));
            assert_eq!(to_hex(&s.ontology.hash), ontology_hash);
            assert_eq!(s.root_hex(), state_root);
            let bytes = build_container(&mut s);
            verify_container(&bytes).unwrap();
            assert_eq!(to_hex(&sha256(&bytes)), container_hash, "{mode}, explicit={explicit}");
        }
    }
}
