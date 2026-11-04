//! Integration test of the directive emitter through the public API and the container bytes: several parallel rounds are
//! played by a scripted executor that does exactly what each frame asks; the batch must never give two seats the same
//! target or the same source sentence, frames must stay small, and the run must end in P4 (no work left) with every
//! eligible target concluded.

use sbgk_core::cdc::CdcParams;
use sbgk_core::container::build_container;
use sbgk_core::{emit_batch_frames, Ontology, Session, Targets};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

fn onto(n: usize, apis: usize) -> String {
    let mut ents = Vec::new();
    for i in 0..n {
        ents.push(json!({"id": format!("svc_{i:03}"), "type": "Service", "aliases": [format!("service {i}")]}));
    }
    for a in 0..apis {
        ents.push(json!({"id": format!("api_{a:03}"), "type": "Api", "aliases": [format!("interface {a}")]}));
    }
    json!({
        "entities": ents,
        "predicates": [
            {"id": "uses_api", "subject": "Service", "object": "Api"},
            {"id": "api_deprecated", "subject": "Api", "object": "@literal"},
            {"id": "needs_review", "subject": "Service", "object": "@literal"}],
        "rules": [{"id": "R_depr_review@1", "mode": "AND", "body": [{"p": "uses_api"}, {"p": "api_deprecated"}],
                   "join": [["0.o", "1.s"]], "head": {"s": "0.s", "p": "needs_review", "o": {"const": "true"}}}]
    })
    .to_string()
}

/// 10 services over 4 APIs; APIs 0 and 1 are deprecated in an overlapping window, API 2 only later, API 3 never.
fn world() -> (String, HashMap<String, Value>, HashSet<String>) {
    let mut facts = HashMap::new();
    let mut gold = HashSet::new();
    let mut sents = vec!["The operator shall archive the access logs within 3 business days.".to_string()];
    for i in 0..10usize {
        let a = i % 4;
        let (lo, hi) = (100 + 2 * i as i64, 200 + 4 * i as i64);
        let s = format!("Clause U.{i}: service svc_{i:03} shall call interface api_{a:03} in production from t={lo} until t={hi}.");
        facts.insert(s.clone(), json!({"s": format!("svc_{i:03}"), "p": "uses_api", "o": format!("api_{a:03}"), "t": [lo, hi]}));
        sents.push(s);
        if a < 2 {
            gold.insert(format!("svc_{i:03}"));
        }
    }
    for (a, (lo, hi)) in [(0usize, (150i64, 300i64)), (1, (150, 300)), (2, (300, 400))] {
        let s = format!("Clause D.{a}: interface api_{a:03} is deprecated in production from t={lo} until t={hi}.");
        facts.insert(s.clone(), json!({"s": format!("api_{a:03}"), "p": "api_deprecated", "o": "true", "t": [lo, hi]}));
        sents.push(s);
    }
    sents.push("The custodian must review all change requests before the next audit window.".into());
    (sents.join(" ") + "\n", facts, gold)
}

fn overlap(a: &Value, b: &Value) -> bool {
    a["t"][0].as_i64().unwrap().max(b["t"][0].as_i64().unwrap()) < a["t"][1].as_i64().unwrap().min(b["t"][1].as_i64().unwrap())
}

#[test]
fn parallel_rounds_are_collision_free_small_and_complete() {
    let (doc, facts, gold) = world();
    let mut s = Session::new(Ontology::from_json_str(&onto(10, 4)).unwrap(), CdcParams::default());
    s.put_document("policy", doc.as_bytes());
    let targets =
        Targets::from_json(&json!({"entities": (0..10).map(|i| format!("svc_{i:03}")).collect::<Vec<_>>(), "predicate": "needs_review", "docs": ["policy"]}))
            .unwrap();
    let mut seq = 0u64;
    let mut send = |s: &mut Session, mut ev: Value| -> bool {
        seq += 1;
        ev["seq"] = json!(seq);
        match s.apply_line(&ev.to_string()) {
            Ok(_) => true,
            Err(_) => {
                seq -= 1;
                false
            }
        }
    };
    let dep_of = |api: &str| facts.values().find(|f| f["p"] == "api_deprecated" && f["s"] == api).cloned();
    let mut rounds = 0;
    let mut rejected = 0;
    loop {
        rounds += 1;
        assert!(rounds < 20, "did not converge");
        let bytes = build_container(&mut s);
        let batch = emit_batch_frames(&bytes, &targets, 4, 4, rounds).unwrap();
        if batch["complete"] == json!(true) {
            break;
        }
        let frames = batch["frames"].as_array().unwrap().clone();
        // invariant: no target and no source sentence is given to two seats
        let mut tg = HashSet::new();
        let mut sg = HashSet::new();
        for f in frames.iter().filter(|f| f["noop"] == json!(false)) {
            for t in f["targets"].as_array().unwrap() {
                assert!(tg.insert(t.as_str().unwrap().to_string()), "target {t} given twice in round {rounds}");
            }
            for g in f["gaps"].as_array().unwrap() {
                for seg in g["segments"].as_array().unwrap() {
                    assert!(sg.insert(seg.as_str().unwrap().to_string()), "segment {seg} given twice in round {rounds}");
                }
            }
            let n = f["prompt_chars"].as_u64().unwrap();
            assert!(n < 4500, "frame of {n} chars");
            assert!(!f["prompt"].as_str().unwrap().contains("custodian"), "filler leaked into a frame");
        }
        // the scripted executor does what each frame says
        for f in frames.iter().filter(|f| f["noop"] == json!(false)) {
            let pre = f["local_id_prefix"].as_str().unwrap().to_string();
            let mut n = 0;
            for g in f["gaps"].as_array().unwrap() {
                match g["kind"].as_str().unwrap() {
                    "FORMALIZE" | "EXTRACT_PARTNER" => {
                        for text in g["segment_texts"].as_array().unwrap() {
                            let fact = &facts[text.as_str().unwrap()];
                            n += 1;
                            let (e, fl) = (format!("{pre}e{n}"), format!("{pre}f{n}"));
                            rejected += usize::from(!send(&mut s, json!({"op": "bind_evidence", "local_id": e, "doc_id": "policy", "exact_quote": text})));
                            rejected += usize::from(!send(
                                &mut s,
                                json!({"op": "assert_fact", "local_id": fl, "s": fact["s"], "p": fact["p"], "o": fact["o"],
                                "polarity": "POS", "ctx": "prod", "t": fact["t"], "evidence": [e]}),
                            ));
                            if let Some(p) = g["partner"].as_object() {
                                let (use_f, dep_f) = if fact["p"] == "uses_api" {
                                    (fact.clone(), dep_of(fact["o"].as_str().unwrap()))
                                } else {
                                    (Value::Null, Some(fact.clone()))
                                };
                                let ok = match (&use_f, &dep_f) {
                                    (Value::Null, _) => true, // partner is the use fact; the kernel decides on overlap below
                                    (u, Some(d)) => overlap(u, d),
                                    _ => false,
                                };
                                if ok {
                                    n += 1;
                                    // a derive that the windows do not allow is rejected by the kernel - count it but it is not a failure of the emitter
                                    let _ =
                                        send(&mut s, json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": p["rule"], "premises": [fl, p["id"]]}));
                                }
                            }
                        }
                    }
                    "EMIT_DERIVE_ONLY" => {
                        n += 1;
                        rejected += usize::from(!send(
                            &mut s,
                            json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": g["derive"]["rule"], "premises": g["derive"]["premises"]}),
                        ));
                    }
                    k => panic!("unexpected gap kind {k}"),
                }
            }
        }
    }
    assert_eq!(rejected, 0, "every event the frames asked for was accepted");
    let bytes = build_container(&mut s);
    let fin = emit_batch_frames(&bytes, &targets, 4, 4, 99).unwrap();
    for t in &gold {
        assert_eq!(fin["goal_state"][t], json!("CLOSED_POSITIVE"), "{t}");
    }
    for i in 0..10 {
        let t = format!("svc_{i:03}");
        if !gold.contains(&t) {
            let st = fin["goal_state"][&t].as_str().unwrap();
            // API 2 has a later deprecation clause (formalized, then closed), API 3 none at all (closed without formalization)
            let want = if i % 4 == 3 { "CLOSED_NEGATIVE_UNREACHABLE" } else { "CLOSED_NEGATIVE" };
            assert_eq!(st, want, "{t}");
        }
    }
    assert!(rounds <= 6, "rounds {rounds}");
}
