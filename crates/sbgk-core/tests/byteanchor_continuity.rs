//! ByteAnchor validity is independent of the support oracle: current document bytes
//! must contain the complete quote, with ordered, adjacent chunk occurrences.

use sbgk_core::arena::version_id_of;
use sbgk_core::cdc::{CdcMode, CdcParams};
use sbgk_core::container::{build_container, open_session, reconstruct_container_at, verify_container};
use sbgk_core::engine::{CanonOp, Engine};
use sbgk_core::hash::{sha256, Hash};
use sbgk_core::node::*;
use sbgk_core::{reconstruct_at_byte_offset, Arena, Ontology, Session};
use serde_json::{json, Value};

const ONTO: &str = r#"{"entities":[{"id":"a","type":"Node"},{"id":"b","type":"Node"}],
"predicates":[{"id":"edge","subject":"Node","object":"Node"},{"id":"reach","subject":"Node","object":"Node"}],
"rules":[{"id":"R_seed@1","mode":"AND","body":[{"p":"edge"}],"head":{"s":"0.s","p":"reach","o":"0.o"}}]}"#;

fn params() -> CdcParams {
    CdcParams { mode: CdcMode::FastCdc, min: 4, avg: 4, max: 4 }
}

fn chunks(parts: &[&[u8]]) -> Vec<Hash> {
    parts.iter().map(|p| sha256(p)).collect()
}

fn put(engine: &mut Engine, hashes: &[Hash]) -> Hash {
    let version = version_id_of(hashes);
    engine.apply(&CanonOp::DocPut { doc_id: "d".into(), version, chunks: hashes.to_vec() }).unwrap();
    version
}

fn evidence(parts: &[&[u8]]) -> EvidenceNode {
    let quote: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    EvidenceNode {
        doc_id: "d".into(),
        quote_hash: sha256(&quote),
        quote_len: quote.len() as u32,
        segs: parts.iter().map(|p| Seg { chunk: sha256(p), start: 0, end: p.len() as u32 }).collect(),
    }
}

fn claim(predicate: &str) -> Claim {
    Claim { s: "a".into(), p: predicate.into(), o: "b".into(), pol: Polarity::Pos, ctx: "prod".into(), t_from: 0, t_to: 10 }
}

fn assert_and_derive(engine: &mut Engine, ev: Hash) -> (Hash, Hash) {
    let fact = claim("edge");
    let derived = claim("reach");
    engine.apply(&CanonOp::Assert { claim: fact.clone(), evidence: vec![ev] }).unwrap();
    engine.apply(&CanonOp::Derive { claim: derived.clone(), justs: vec![("R_seed@1".into(), vec![fact.id()])] }).unwrap();
    (fact.id(), derived.id())
}

fn send(session: &mut Session, mut event: Value) -> Hash {
    event["seq"] = json!(session.last_seq + 1);
    session.apply_line(&event.to_string()).unwrap().node.unwrap()
}

fn session_graph() -> (Session, Hash, Hash, Hash) {
    let mut session = Session::new(Ontology::from_json_str(ONTO).unwrap(), params());
    session.put_document("d", b"AAAABBBBCCCC");
    assert_eq!(session.arena.doc("d").unwrap().chunk_hashes, chunks(&[b"AAAA", b"BBBB", b"CCCC"]));
    let ev = send(&mut session, json!({"op":"bind_evidence","local_id":"e","doc_id":"d","exact_quote":"AAAABBBB"}));
    assert_eq!(session.engine.evidence(&ev).unwrap().segs.len(), 2);
    let fact = send(
        &mut session,
        json!({"op":"assert_fact","local_id":"f","s":"a","p":"edge","o":"b",
        "polarity":"POS","ctx":"prod","t":[0,10],"evidence":["e"]}),
    );
    let derived = send(
        &mut session,
        json!({"op":"derive","local_id":"r","rule":"R_seed@1","premises":["f"],
        "claim":{"s":"a","p":"reach","o":"b","polarity":"POS","ctx":"prod","t":[0,10]}}),
    );
    (session, ev, fact, derived)
}

#[test]
fn bind_and_docput_reject_reordered_and_separated_windows() {
    let ev = evidence(&[b"AAAA", b"BBBB"]);
    for invalid in [chunks(&[b"BBBB", b"AAAA"]), chunks(&[b"AAAA", b"XXXX", b"BBBB"])] {
        let mut engine = Engine::new();
        let version = put(&mut engine, &invalid);
        engine.apply(&CanonOp::BindEvidence { doc_version: version, ev: ev.clone() }).unwrap();
        let (fact, derived) = assert_and_derive(&mut engine, ev.id());
        assert_eq!(engine.status_of(&ev.id()), Some(EV_STALE));
        assert_eq!(engine.status_of(&fact), Some(ST_UNSUPPORTED));
        assert_eq!(engine.status_of(&derived), Some(ST_UNSUPPORTED));

        put(&mut engine, &chunks(&[b"AAAA", b"BBBB"]));
        assert_eq!(engine.status_of(&ev.id()), Some(EV_ACTIVE));
        assert_eq!(engine.status_of(&fact), Some(ST_SUPPORTED));
        assert_eq!(engine.status_of(&derived), Some(ST_SUPPORTED));
        put(&mut engine, &invalid);
        assert_eq!(engine.status_of(&ev.id()), Some(EV_STALE));
        assert_eq!(engine.status_of(&fact), Some(ST_UNSUPPORTED));
        assert_eq!(engine.status_of(&derived), Some(ST_UNSUPPORTED));
        assert!(engine.oracle_check());
    }
}

#[test]
fn repeated_hashes_require_multiplicity_and_search_every_start() {
    for (parts, before, after) in [
        (vec![b"AAAA".as_slice(), b"BBBB"], chunks(&[b"AAAA", b"BBBB"]), chunks(&[b"AAAA", b"XXXX", b"AAAA", b"BBBB"])),
        (vec![b"AAAA".as_slice(), b"AAAA"], chunks(&[b"AAAA", b"AAAA"]), chunks(&[b"AAAA"])),
    ] {
        let ev = evidence(&parts);
        let mut engine = Engine::new();
        let version = put(&mut engine, &before);
        engine.apply(&CanonOp::BindEvidence { doc_version: version, ev: ev.clone() }).unwrap();
        let (fact, derived) = assert_and_derive(&mut engine, ev.id());
        put(&mut engine, &after);
        let active = parts[0] != parts[1];
        assert_eq!(engine.status_of(&ev.id()), Some(if active { EV_ACTIVE } else { EV_STALE }));
        for id in [fact, derived] {
            assert_eq!(engine.status_of(&id), Some(if active { ST_SUPPORTED } else { ST_UNSUPPORTED }));
        }
        let mut bound_after = Engine::new();
        let version = put(&mut bound_after, &after);
        bound_after.apply(&CanonOp::BindEvidence { doc_version: version, ev: ev.clone() }).unwrap();
        assert_eq!(bound_after.status_of(&ev.id()), Some(if active { EV_ACTIVE } else { EV_STALE }));
    }
}

#[test]
fn source_free_validation_rejects_impossible_spans_and_quote_lengths() {
    let good = evidence(&[b"AAAA", b"BBBB"]);
    let mut malformed = Vec::new();
    let mut empty = good.clone();
    empty.segs.clear();
    malformed.push(empty);
    let mut reversed = good.clone();
    reversed.segs[0].start = 5;
    malformed.push(reversed);
    let mut discontinuous = good.clone();
    discontinuous.segs[1].start = 1;
    discontinuous.quote_len -= 1;
    malformed.push(discontinuous);
    let mut wrong_length = good;
    wrong_length.quote_len += 1;
    malformed.push(wrong_length);
    for ev in malformed {
        let mut engine = Engine::new();
        let version = put(&mut engine, &chunks(&[b"AAAA", b"BBBB"]));
        engine.apply(&CanonOp::BindEvidence { doc_version: version, ev: ev.clone() }).unwrap();
        assert_eq!(engine.status_of(&ev.id()), Some(EV_STALE));
        put(&mut engine, &chunks(&[b"CCCC", b"AAAA", b"BBBB"]));
        assert_eq!(engine.status_of(&ev.id()), Some(EV_STALE));
    }
}

#[test]
fn relocation_and_restoration_preserve_support_but_revocation_is_final() {
    let ev = evidence(&[b"AAAA", b"BBBB"]);
    let mut engine = Engine::new();
    let version = put(&mut engine, &chunks(&[b"AAAA", b"BBBB", b"CCCC"]));
    engine.apply(&CanonOp::BindEvidence { doc_version: version, ev: ev.clone() }).unwrap();
    let (fact, derived) = assert_and_derive(&mut engine, ev.id());
    put(&mut engine, &chunks(&[b"CCCC", b"AAAA", b"BBBB"]));
    assert_eq!(engine.status_of(&ev.id()), Some(EV_ACTIVE));
    put(&mut engine, &[]);
    assert_eq!(engine.status_of(&fact), Some(ST_UNSUPPORTED));
    put(&mut engine, &chunks(&[b"AAAA", b"BBBB"]));
    assert_eq!(engine.status_of(&derived), Some(ST_SUPPORTED));
    engine.apply(&CanonOp::Revoke { evidence: ev.id() }).unwrap();
    put(&mut engine, &chunks(&[b"CCCC", b"AAAA", b"BBBB"]));
    assert_eq!(engine.status_of(&ev.id()), Some(EV_REVOKED));
    assert_eq!(engine.status_of(&fact), Some(ST_UNSUPPORTED));
    assert_eq!(engine.status_of(&derived), Some(ST_UNSUPPORTED));
}

#[test]
fn alternative_evidence_keeps_the_same_fact_and_derived_claim_supported() {
    let mut engine = Engine::new();
    let version = put(&mut engine, &chunks(&[b"AAAA", b"BBBB", b"CCCC"]));
    let ev = evidence(&[b"AAAA", b"BBBB"]);
    let alternative = evidence(&[b"CCCC"]);
    for e in [&ev, &alternative] {
        engine.apply(&CanonOp::BindEvidence { doc_version: version, ev: e.clone() }).unwrap();
    }
    let (fact, derived) = assert_and_derive(&mut engine, ev.id());
    engine.apply(&CanonOp::Assert { claim: claim("edge"), evidence: vec![alternative.id()] }).unwrap();
    put(&mut engine, &chunks(&[b"BBBB", b"AAAA", b"CCCC"]));
    assert_eq!(engine.status_of(&ev.id()), Some(EV_STALE));
    assert_eq!(engine.status_of(&alternative.id()), Some(EV_ACTIVE));
    assert_eq!(engine.status_of(&fact), Some(ST_SUPPORTED));
    assert_eq!(engine.status_of(&derived), Some(ST_SUPPORTED));
    assert!(engine.oracle_check());
}

#[test]
fn session_drops_support_when_current_bytes_no_longer_contain_the_quote() {
    for edited in [b"BBBBAAAACCCC".as_slice(), b"AAAAXXXXBBBBCCCC"] {
        let (mut session, ev, fact, derived) = session_graph();
        let report = session.put_document("d", edited);
        assert!(session.arena.find_occurrences("d", b"AAAABBBB").unwrap().is_empty());
        assert_eq!(report.rebound_ok, 0);
        assert_eq!(report.rebind_failed, 1);
        assert_eq!(session.engine.status_of(&ev), Some(EV_STALE));
        assert_eq!(session.engine.status_of(&fact), Some(ST_UNSUPPORTED));
        assert_eq!(session.engine.status_of(&derived), Some(ST_UNSUPPORTED));
    }
}

#[test]
fn session_rebinds_a_unique_rechunked_quote_and_restores_its_exact_claims() {
    let (mut session, old, fact, derived) = session_graph();
    let report = session.put_document("d", b"XAAAABBBBCCCC");
    assert_eq!(session.arena.find_occurrences("d", b"AAAABBBB").unwrap().len(), 1);
    assert_eq!(report.evidence_stale, 1);
    assert_eq!(report.rebound_ok, 1);
    assert_eq!(session.engine.status_of(&old), Some(EV_STALE));
    assert_eq!(session.engine.status_of(&fact), Some(ST_SUPPORTED));
    assert_eq!(session.engine.status_of(&derived), Some(ST_SUPPORTED));
    let active: Vec<_> = session
        .engine
        .node_views()
        .filter_map(|(id, status, view)| if matches!(view, sbgk_core::engine::NodeView::Evidence(_)) && status == EV_ACTIVE { Some(*id) } else { None })
        .collect();
    assert_eq!(active.len(), 1);
    assert_ne!(active[0], old);
    let rebound = session.engine.evidence(&active[0]).unwrap();
    assert_eq!(session.arena.quote_bytes(rebound).unwrap(), b"AAAABBBB");
    assert_eq!(session.engine.claims_asserted_by(&active[0]), vec![claim("edge")]);
}

#[test]
fn session_keeps_an_intact_relocated_anchor_without_imposing_global_uniqueness() {
    let (mut session, ev, fact, derived) = session_graph();
    let report = session.put_document("d", b"CCCCAAAABBBBAAAABBBB");
    assert_eq!(session.arena.find_occurrences("d", b"AAAABBBB").unwrap().len(), 2);
    assert_eq!(report.evidence_stale, 0);
    assert_eq!(report.rebound_ok, 0);
    assert_eq!(session.engine.status_of(&ev), Some(EV_ACTIVE));
    assert_eq!(session.engine.status_of(&fact), Some(ST_SUPPORTED));
    assert_eq!(session.engine.status_of(&derived), Some(ST_SUPPORTED));
}

#[test]
fn session_does_not_rebind_an_ambiguous_quote_or_revive_revoked_evidence() {
    let (mut session, ev, fact, derived) = session_graph();
    let report = session.put_document("d", b"XAAAABBBBXAAAABBBB");
    assert_eq!(session.arena.find_occurrences("d", b"AAAABBBB").unwrap().len(), 2);
    assert_eq!(report.rebound_ok, 0);
    assert_eq!(report.rebind_failed, 1);
    assert_eq!(session.engine.status_of(&ev), Some(EV_STALE));
    assert_eq!(session.engine.status_of(&fact), Some(ST_UNSUPPORTED));
    assert_eq!(session.engine.status_of(&derived), Some(ST_UNSUPPORTED));

    let (mut session, ev, fact, _) = session_graph();
    send(&mut session, json!({"op":"revoke_evidence","target_evidence":"e"}));
    let report = session.put_document("d", b"XAAAABBBBCCCC");
    assert_eq!(report.rebound_ok, 0);
    assert_eq!(session.engine.status_of(&ev), Some(EV_REVOKED));
    assert_eq!(session.engine.status_of(&fact), Some(ST_UNSUPPORTED));
}

#[test]
fn wal_replay_container_reopen_and_time_travel_agree_on_exact_statuses() {
    let (mut session, ev, fact, derived) = session_graph();
    let before = session.wal.bytes.len();
    let before_root = session.engine.root();
    session.put_document("d", b"BBBBAAAACCCC");
    let after_root = session.engine.root();
    assert_ne!(before_root, after_root);
    let mut replay = reconstruct_at_byte_offset(&session.wal.bytes).unwrap().engine;
    assert_eq!(replay.root(), after_root);
    for (id, expected) in [(ev, EV_STALE), (fact, ST_UNSUPPORTED), (derived, ST_UNSUPPORTED)] {
        assert_eq!(replay.status_of(&id), Some(expected));
    }
    let bytes = build_container(&mut session);
    verify_container(&bytes).unwrap();
    let mut opened = open_session(&bytes).unwrap();
    assert_eq!(opened.engine.root(), after_root);
    let mut historical = reconstruct_container_at(&bytes, before).unwrap();
    assert_eq!(historical.root(), before_root);
    assert_eq!(historical.status_of(&ev), Some(EV_ACTIVE));
    assert_eq!(historical.status_of(&fact), Some(ST_SUPPORTED));
    assert_eq!(historical.status_of(&derived), Some(ST_SUPPORTED));
}

#[test]
fn arena_rejects_noncontiguous_spans_bad_bounds_length_and_hash() {
    let mut arena = Arena::new(params());
    arena.put_document("d", b"AAAABBBBCCCC");
    let anchor = arena.anchor_for_span("d", 2, 10).unwrap();
    let valid = Arena::evidence_node(&anchor, 8);
    assert!(arena.verify_evidence(&valid));
    let mut bad = Vec::new();
    let mut gap = valid.clone();
    gap.segs[0].end = 3;
    gap.quote_len -= 1;
    gap.quote_hash = sha256(&arena.quote_bytes(&gap).unwrap());
    bad.push(gap);
    let mut interior = valid.clone();
    interior.segs[1].end = 3;
    interior.quote_len -= 1;
    interior.quote_hash = sha256(&arena.quote_bytes(&interior).unwrap());
    bad.push(interior);
    let mut prefix = valid.clone();
    prefix.segs[2].start = 1;
    prefix.quote_len -= 1;
    prefix.quote_hash = sha256(&arena.quote_bytes(&prefix).unwrap());
    bad.push(prefix);
    let mut bounds = valid.clone();
    bounds.segs[0].end = 5;
    bad.push(bounds);
    let mut empty = valid.clone();
    empty.segs[0].start = empty.segs[0].end;
    bad.push(empty);
    let mut length = valid.clone();
    length.quote_len += 1;
    bad.push(length);
    let mut hash = valid;
    hash.quote_hash = sha256(b"wrong");
    bad.push(hash);
    for ev in bad {
        assert!(!arena.verify_evidence(&ev), "accepted malformed evidence: {ev:?}");
    }
}

#[test]
fn container_rejects_malformed_spans_quote_lengths_and_hashes() {
    // The WAL-only engine cannot know that the first chunk has four bytes. These
    // slices hash correctly, but omit two bytes between their source ranges.
    let gap = EvidenceNode {
        doc_id: "d".into(),
        quote_hash: sha256(b"AABBBB"),
        quote_len: 6,
        segs: vec![Seg { chunk: sha256(b"AAAA"), start: 0, end: 2 }, Seg { chunk: sha256(b"BBBB"), start: 0, end: 4 }],
    };
    let mut wrong_length = evidence(&[b"AAAA", b"BBBB"]);
    wrong_length.quote_len += 1;
    let mut wrong_hash = evidence(&[b"AAAA", b"BBBB"]);
    wrong_hash.quote_hash = sha256(b"wrong");
    let mut out_of_bounds = evidence(&[b"AAAA", b"BBBB"]);
    out_of_bounds.segs[1].end = 5;
    out_of_bounds.quote_len += 1;
    for ev in [gap, wrong_length, wrong_hash, out_of_bounds] {
        let mut session = Session::new(Ontology::from_json_str(ONTO).unwrap(), params());
        session.put_document("d", b"AAAABBBB");
        let op = CanonOp::BindEvidence { doc_version: session.arena.doc("d").unwrap().version_id, ev };
        session.engine.apply(&op).unwrap();
        session.wal.append(1, &op, false);
        session.last_seq = 1;
        let bytes = build_container(&mut session);
        assert_eq!(verify_container(&bytes).unwrap_err().kind, "anchor_broken");
    }
}
