//! End-to-end checks over the public API: container round-trips, tamper evidence,
//! time travel, permutation invariance, Merkle diff, minimal cone, and a randomized
//! incremental-vs-oracle equivalence test for the DRed engine.

use sbgk_core::cdc::CdcParams;
use sbgk_core::container::*;
use sbgk_core::engine::{CanonOp, Engine};
use sbgk_core::hash::sha256;
use sbgk_core::node::*;
use sbgk_core::*;
use serde_json::{json, Value};

const ONTO: &str = r#"{
  "entities":[
    {"id":"n0","type":"Node","aliases":["root"]},{"id":"n1","type":"Node"},{"id":"n2","type":"Node"},
    {"id":"n3","type":"Node"},{"id":"n4","type":"Node"},{"id":"n5","type":"Node"}],
  "predicates":[
    {"id":"edge","subject":"Node","object":"Node"},
    {"id":"reach","subject":"Node","object":"Node"}],
  "rules":[
    {"id":"R_seed@1","mode":"AND","body":[{"p":"edge"}],"head":{"s":"0.s","p":"reach","o":"0.o"}},
    {"id":"R_step@1","mode":"AND","body":[{"p":"reach"},{"p":"edge"}],"join":[["0.o","1.s"]],
     "head":{"s":"0.s","p":"reach","o":"1.o"}}]}"#;

fn doc_text() -> String {
    let mut s = String::new();
    for (i, (a, b)) in [(0, 1), (0, 2), (1, 3), (2, 3), (3, 4), (4, 5)].iter().enumerate() {
        s.push_str(&format!("Link L{i}: node n{a} connects to node n{b} in production.\n"));
        s.push_str("Filler sentence about unrelated operational procedures and staffing.\n");
    }
    s
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn edges() -> Vec<(usize, usize)> {
    vec![(0, 1), (0, 2), (1, 3), (2, 3), (3, 4), (4, 5)]
}

/// Build a session over the diamond graph. `order` permutes the evidence/edge sequence and
/// `tag` changes every local name.
fn build(order: &[usize], tag: &str, extra_edge_t: Option<(i64, i64)>) -> Session {
    let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), CdcParams::default());
    s.put_document("net", doc_text().as_bytes());
    let mut seq = 1u64;
    let mut line = |s: &mut Session, v: Value| {
        let mut v = v;
        v["seq"] = json!(seq);
        seq += 1;
        s.apply_line(&v.to_string()).unwrap_or_else(|e| panic!("{}", e.to_json()));
    };
    for &i in order {
        let (a, b) = edges()[i];
        let q = format!("Link L{i}: node n{a} connects to node n{b} in production.");
        line(&mut s, json!({"op":"bind_evidence","local_id":format!("{tag}e{i}"),"doc_id":"net","exact_quote":q}));
        let t = if i == 5 { extra_edge_t.unwrap_or((0, 100)) } else { (0, 100) };
        line(
            &mut s,
            json!({"op":"assert_fact","local_id":format!("{tag}f{i}"),"s":format!("n{a}"),"p":"edge","o":format!("n{b}"),
                   "polarity":"POS","ctx":"prod","t":[t.0,t.1],"evidence":[format!("{tag}e{i}")]}),
        );
    }
    // derivations: seed from first-level edges, then steps in dependency order
    let d = |s: &mut Session, line: &mut dyn FnMut(&mut Session, Value), name: &str, rule: &str, prem: Vec<String>, claim: Value| {
        line(s, json!({"op":"derive","local_id":name,"rule":rule,"premises":prem,"claim":claim}));
    };
    let t5 = extra_edge_t.unwrap_or((0, 100));
    let cl = |a: usize, b: usize, t: (i64, i64)| json!({"s":format!("n{a}"),"p":"reach","o":format!("n{b}"),"polarity":"POS","ctx":"prod","t":[t.0,t.1]});
    d(&mut s, &mut line, &format!("{tag}r01"), "R_seed@1", vec![format!("{tag}f0")], cl(0, 1, (0, 100)));
    d(&mut s, &mut line, &format!("{tag}r02"), "R_seed@1", vec![format!("{tag}f1")], cl(0, 2, (0, 100)));
    d(&mut s, &mut line, &format!("{tag}r03a"), "R_step@1", vec![format!("{tag}f2"), format!("{tag}r01")], cl(0, 3, (0, 100)));
    d(&mut s, &mut line, &format!("{tag}r03b"), "R_step@1", vec![format!("{tag}r02"), format!("{tag}f3")], cl(0, 3, (0, 100)));
    d(&mut s, &mut line, &format!("{tag}r04"), "R_step@1", vec![format!("{tag}r03a"), format!("{tag}f4")], cl(0, 4, (0, 100)));
    d(&mut s, &mut line, &format!("{tag}r05"), "R_step@1", vec![format!("{tag}r04"), format!("{tag}f5")], cl(0, 5, (0, t5.1.min(100))));
    s
}

fn natural() -> Vec<usize> {
    vec![0, 1, 2, 3, 4, 5]
}

#[test]
fn container_roundtrip_verify_reopen_and_continue() {
    let mut s = build(&natural(), "a", None);
    s.engine.oracle_check();
    let bytes = build_container(&mut s);
    let rep = verify_container(&bytes).unwrap();
    assert!(rep.nodes > 20 && rep.anchors_checked == 6);
    assert_eq!(&bytes[..6], b"SBGK\x00\x01");

    let mut re = open_session(&bytes).unwrap();
    assert_eq!(re.state_root(), s.state_root());
    // local names are gone: address an existing node by its id prefix instead
    let ev = s.engine.evidence(&{
        let q = format!("Link L{}: node n{} connects to node n{} in production.", 3, 2, 3);
        let ar = s.arena.doc("net").unwrap();
        let occ = sbgk_core::arena::find_all(&ar.bytes, q.as_bytes());
        let anchor = s.arena.anchor_for_span("net", occ[0].start, occ[0].end).unwrap();
        Arena::evidence_node(&anchor, q.len()).id()
    });
    assert!(ev.is_some());
    let eid = Arena::evidence_node(
        &{
            let q = "Link L3: node n2 connects to node n3 in production.";
            let ar = re.arena.doc("net").unwrap();
            let occ = sbgk_core::arena::find_all(&ar.bytes, q.as_bytes());
            re.arena.anchor_for_span("net", occ[0].start, occ[0].end).unwrap()
        },
        "Link L3: node n2 connects to node n3 in production.".len(),
    )
    .id();
    let line = json!({"seq": re.last_seq + 1, "op": "revoke_evidence", "target_evidence": format!("@{}", &sbgk_core::hash::to_hex(&eid)[..16])});
    let r = re.apply_line(&line.to_string()).unwrap();
    assert!(r.dred.unwrap().over_deleted > 0);
    assert!(re.engine.oracle_check());
    let bytes2 = build_container(&mut re);
    verify_container(&bytes2).unwrap();
    assert_ne!(ContainerView::parse(&bytes).unwrap().root, ContainerView::parse(&bytes2).unwrap().root);
}

#[test]
fn every_single_bit_flip_is_detected() {
    // tiny graph so the exhaustive sweep stays cheap
    let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), CdcParams::default());
    s.put_document("net", b"Link L0: node n0 connects to node n1 in production.\n");
    s.apply_line(r#"{"seq":1,"op":"bind_evidence","local_id":"e","doc_id":"net","exact_quote":"Link L0: node n0 connects to node n1 in production."}"#)
        .unwrap();
    s.apply_line(r#"{"seq":2,"op":"assert_fact","local_id":"f","s":"n0","p":"edge","o":"n1","polarity":"POS","ctx":"p","t":[0,9],"evidence":["e"]}"#).unwrap();
    s.apply_line(r#"{"seq":3,"op":"derive","local_id":"r","rule":"R_seed@1","premises":["f"]}"#).unwrap();
    let bytes = build_container(&mut s);
    verify_container(&bytes).unwrap();
    let mut undetected = Vec::new();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            if verify_container(&b).is_ok() {
                undetected.push((i, bit));
            }
        }
    }
    assert!(undetected.is_empty(), "{} of {} flips undetected, first {:?}", undetected.len(), bytes.len() * 8, &undetected[..undetected.len().min(5)]);
    // truncation and extension
    assert!(verify_container(&bytes[..bytes.len() - 1]).is_err());
    let mut ext = bytes.clone();
    ext.push(0);
    assert!(verify_container(&ext).is_err());
}

#[test]
fn time_travel_equals_live_history() {
    let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), CdcParams::default());
    s.track_roots = true;
    s.put_document("net", doc_text().as_bytes());
    let mut seq = 0;
    let mut send = |s: &mut Session, mut v: Value| {
        seq += 1;
        v["seq"] = json!(seq);
        s.apply_line(&v.to_string()).unwrap_or_else(|e| panic!("{}", e.to_json()));
    };
    for i in 0..3 {
        let (a, b) = edges()[i];
        let q = format!("Link L{i}: node n{a} connects to node n{b} in production.");
        send(&mut s, json!({"op":"bind_evidence","local_id":format!("e{i}"),"doc_id":"net","exact_quote":q}));
        send(
            &mut s,
            json!({"op":"assert_fact","local_id":format!("f{i}"),"s":format!("n{a}"),"p":"edge","o":format!("n{b}"),"polarity":"POS","ctx":"p","t":[0,9],"evidence":[format!("e{i}")]}),
        );
    }
    send(&mut s, json!({"op":"derive","local_id":"r","rule":"R_seed@1","premises":["f0"]}));
    send(&mut s, json!({"op":"revoke_evidence","target_evidence":"e0"}));
    let history = s.seq_roots.clone();
    let bytes = build_container(&mut s);
    let v = ContainerView::parse(&bytes).unwrap();
    let wal_base = v.wal.as_ptr() as usize - bytes.as_ptr() as usize;
    for (seq, wal_end, root) in history {
        let mut e = reconstruct_container_at(&bytes, wal_end).unwrap();
        assert_eq!(e.root(), root, "root mismatch at seq {seq} (wal offset {wal_end}, base {wal_base})");
    }
    // a slice that ends inside a frame is refused
    assert!(reconstruct_container_at(&bytes, s.wal.frame_ends[2] - 3).is_err());
}

#[test]
fn permutation_and_naming_noise_vanish_bit_for_bit() {
    let mut a = build(&natural(), "alpha_", None);
    let mut b = build(&[3, 1, 5, 0, 4, 2], "node99_", None);
    // different order of base facts changes the WAL but must not change table or index bytes
    let ba = build_container(&mut a);
    let bb = build_container(&mut b);
    let (va, vb) = (ContainerView::parse(&ba).unwrap(), ContainerView::parse(&bb).unwrap());
    assert_eq!(va.table, vb.table);
    assert_eq!(va.index, vb.index);
    assert_eq!(va.root, vb.root);
    assert_ne!(va.wal, vb.wal);
    assert!(merkle_diff(&ba, &bb).unwrap().entries.is_empty());
}

#[test]
fn merkle_diff_reports_exactly_the_symmetric_difference() {
    let mut a = build(&natural(), "a", None);
    let mut b = build(&natural(), "b", Some((0, 50)));
    let (ba, bb) = (build_container(&mut a), build_container(&mut b));
    let d = merkle_diff(&ba, &bb).unwrap();
    assert!(!d.entries.is_empty());
    let ids = |bytes: &[u8]| -> std::collections::BTreeSet<[u8; 32]> { ContainerView::parse(bytes).unwrap().records().unwrap().iter().map(|r| r.id).collect() };
    let (ia, ib) = (ids(&ba), ids(&bb));
    let expected: std::collections::BTreeSet<[u8; 32]> = ia.symmetric_difference(&ib).copied().collect();
    let got: std::collections::BTreeSet<[u8; 32]> = d.entries.iter().map(|e| e.id).collect();
    assert_eq!(got, expected);
    assert!(d.buckets_differing < 256);
    assert!(d.leaves_scanned < ia.len() + ib.len());
}

#[test]
fn minimal_cone_is_self_contained_and_skips_revoked_branches() {
    let mut s = build(&natural(), "a", None);
    let bytes = build_container(&mut s);
    let cone: Value = serde_json::from_str(&project_minimal_cone(&bytes, "n3")).unwrap();
    assert_eq!(cone["entity"], "n3");
    let claims = cone["claims"].as_array().unwrap();
    let steps = cone["steps"].as_array().unwrap();
    let ids: std::collections::HashSet<&str> = claims.iter().map(|c| c["id"].as_str().unwrap()).collect();
    // every chosen step has all premises inside the cone and every leaf has evidence
    for st in steps {
        assert!(ids.contains(st["claim"].as_str().unwrap()));
        if let Some(p) = st["premises"].as_array() {
            for x in p {
                assert!(ids.contains(x.as_str().unwrap()));
            }
        }
    }
    assert!(!cone["evidence"].as_array().unwrap().is_empty());
    assert!(project_minimal_cone(&bytes, "n3").len() < project_full(&bytes, false).len());
    // alias resolution goes through the stored ontology
    let by_alias: Value = serde_json::from_str(&project_minimal_cone(&bytes, "root")).unwrap();
    assert_eq!(by_alias["entity"], "n0");

    // revoke the only evidence of the last edge: reach(n0,n5) disappears from the cone
    let mut re = open_session(&bytes).unwrap();
    let q = "Link L5: node n4 connects to node n5 in production.";
    let occ = sbgk_core::arena::find_all(&re.arena.doc("net").unwrap().bytes, q.as_bytes());
    let anchor = re.arena.anchor_for_span("net", occ[0].start, occ[0].end).unwrap();
    let eid = Arena::evidence_node(&anchor, q.len()).id();
    let line = json!({"seq": re.last_seq + 1, "op": "revoke_evidence", "target_evidence": format!("@{}", &sbgk_core::hash::to_hex(&eid)[..16])});
    re.apply_line(&line.to_string()).unwrap();
    let bytes2 = build_container(&mut re);
    let cone2: Value = serde_json::from_str(&project_minimal_cone(&bytes2, "n5")).unwrap();
    assert!(cone2["claims"].as_array().unwrap().is_empty());
}

#[test]
fn find_node_binary_search_hits_every_record() {
    let mut s = build(&natural(), "a", None);
    let bytes = build_container(&mut s);
    let v = ContainerView::parse(&bytes).unwrap();
    for r in v.records().unwrap() {
        let f = v.find_node(&r.id).expect("indexed");
        assert_eq!(f.payload, r.payload);
        assert_eq!(sha256(f.payload), r.id);
    }
    assert!(v.find_node(&[0xAB; 32]).is_none());
}

#[test]
fn incremental_engine_equals_batch_oracle_on_random_graphs() {
    let mut saw_conflict = false;
    let mut max_supported = 0;
    for seed in 0..60u64 {
        let mut rng = Rng(seed * 7919 + 1);
        let mut e = Engine::new();
        let nchunks = 6u8;
        let chunks: Vec<[u8; 32]> = (0..nchunks).map(|i| [i + 1; 32]).collect();
        e.apply(&CanonOp::DocPut { doc_id: "d".into(), version: [0; 32], chunks: chunks[..4].to_vec() }).unwrap();
        let mut evs = Vec::new();
        for i in 0..nchunks {
            let ev = EvidenceNode { doc_id: "d".into(), quote_hash: [100 + i; 32], quote_len: 4, segs: vec![Seg { chunk: [i + 1; 32], start: 0, end: 4 }] };
            e.apply(&CanonOp::BindEvidence { doc_version: [0; 32], ev: ev.clone() }).unwrap();
            evs.push(ev.id());
        }
        let mut claims: Vec<Claim> = Vec::new();
        for step in 0..60 {
            match rng.below(10) {
                0..=2 => {
                    let c = Claim {
                        s: format!("e{}", rng.below(6)),
                        p: "p".into(),
                        o: format!("v{}", rng.below(2)),
                        pol: if rng.below(4) == 0 { Polarity::Neg } else { Polarity::Pos },
                        ctx: "c".into(),
                        t_from: (rng.below(4) * 10) as i64,
                        t_to: (rng.below(4) * 10 + 40) as i64,
                    };
                    let k = 1 + rng.below(2);
                    let mut ev: Vec<[u8; 32]> = (0..k).map(|_| evs[rng.below(evs.len())]).collect();
                    ev.sort();
                    ev.dedup();
                    e.apply(&CanonOp::Assert { claim: c.clone(), evidence: ev }).unwrap();
                    claims.push(c);
                }
                3..=6 if !claims.is_empty() => {
                    let head = Claim {
                        s: format!("e{}", rng.below(6)),
                        p: "q".into(),
                        o: format!("v{}", rng.below(2)),
                        pol: Polarity::Pos,
                        ctx: "c".into(),
                        t_from: 0,
                        t_to: 40,
                    };
                    // allow premises that create cycles on purpose (heads may feed older claims)
                    let np = 1 + rng.below(2);
                    let mut ps: Vec<[u8; 32]> = (0..np).map(|_| claims[rng.below(claims.len())].id()).collect();
                    ps.sort();
                    ps.dedup();
                    e.apply(&CanonOp::Derive { claim: head.clone(), justs: vec![("R".into(), ps)] }).unwrap();
                    claims.push(head);
                }
                7 => {
                    let ev = evs[rng.below(evs.len())];
                    if e.status_of(&ev) != Some(EV_REVOKED) {
                        e.apply(&CanonOp::Revoke { evidence: ev }).unwrap();
                    }
                }
                8 => {
                    let n = 2 + rng.below((nchunks - 1) as usize);
                    let start = rng.below((nchunks as usize - n) + 1);
                    e.apply(&CanonOp::DocPut { doc_id: "d".into(), version: [0; 32], chunks: chunks[start..start + n].to_vec() }).unwrap();
                }
                _ => {}
            }
            assert!(e.oracle_check(), "seed {seed} step {step}: incremental state diverged from batch recomputation");
            let (sup, _, conf) = e.status_counts();
            saw_conflict |= conf > 0;
            max_supported = max_supported.max(sup);
        }
    }
    // the generator must actually exercise the interesting regimes
    assert!(saw_conflict, "random graphs never produced a conflicting pair");
    assert!(max_supported >= 5);
}
