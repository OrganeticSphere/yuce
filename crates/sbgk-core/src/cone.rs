//! Projections of a container into compact RFC 8785 JSON: the *minimal support cone* of one
//! entity (read through the byte index, never touching unrelated nodes) and, as a baseline, the
//! full graph.

use crate::container::{ContainerView, NodeRec};
use crate::hash::{short, to_hex, Hash};
use crate::jcs::to_jcs;
use crate::node::*;
use crate::ontology::Ontology;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn claim_value(r: &NodeRec, c: &Claim, alt: Option<usize>, via: Option<&Hash>) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), json!(short(&r.id)));
    m.insert("s".into(), json!(c.s));
    m.insert("p".into(), json!(c.p));
    m.insert("o".into(), json!(c.o));
    m.insert("pol".into(), json!(c.pol.as_str()));
    m.insert("ctx".into(), json!(c.ctx));
    m.insert("t".into(), json!([c.t_from, c.t_to]));
    m.insert("st".into(), json!(status_name(KIND_CLAIM, r.status)));
    if let Some(a) = alt {
        m.insert("alt".into(), json!(a));
    }
    if let Some(v) = via {
        m.insert("via".into(), json!(short(v)));
    }
    Value::Object(m)
}

fn step_value(r: &NodeRec, j: &Justification, with_active: bool) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), json!(short(&r.id)));
    match j {
        Justification::Assertion { claim, evidence } => {
            m.insert("kind".into(), json!("assertion"));
            m.insert("claim".into(), json!(short(claim)));
            m.insert("evidence".into(), json!(short(evidence)));
        }
        Justification::Derivation { rule, claim, premises } => {
            m.insert("kind".into(), json!("derivation"));
            m.insert("claim".into(), json!(short(claim)));
            m.insert("rule".into(), json!(rule));
            m.insert("premises".into(), json!(premises.iter().map(short).collect::<Vec<_>>()));
        }
    }
    if with_active {
        m.insert("active".into(), json!(r.status == J_ACTIVE));
    }
    Value::Object(m)
}

fn evidence_value(v: &ContainerView, r: &NodeRec, ev: &EvidenceNode, with_status: bool) -> Value {
    let quote = v.quote_of(ev).map(|q| String::from_utf8_lossy(&q).into_owned()).unwrap_or_default();
    let mut m = Map::new();
    m.insert("id".into(), json!(short(&r.id)));
    m.insert("doc".into(), json!(ev.doc_id));
    m.insert("quote".into(), json!(quote));
    let first = ev.segs.first();
    m.insert("chunk".into(), json!(first.map(|s| short(&s.chunk)).unwrap_or_default()));
    m.insert("span".into(), json!(first.map(|s| vec![s.start, s.end]).unwrap_or_default()));
    if ev.segs.len() > 1 {
        m.insert("segs".into(), json!(ev.segs.len()));
    }
    if with_status {
        m.insert("st".into(), json!(status_name(KIND_EVIDENCE, r.status)));
    }
    Value::Object(m)
}

fn resolve_entity_records(v: &ContainerView, entity: &str) -> (String, Vec<u32>) {
    let direct = v.entity_records(entity);
    if !direct.is_empty() {
        return (entity.to_string(), direct);
    }
    // Fall back to the alias registry stored in the arena.
    if let Some(g) = crate::wal::parse_frames(v.wal).ok().and_then(|f| f.first().map(|x| x.payload.to_vec())) {
        if g.len() >= 32 {
            let h: Hash = g[..32].try_into().unwrap();
            if let Some(Ok(onto)) = v.arena_find(&h).and_then(|b| std::str::from_utf8(b).ok()).map(Ontology::from_json_str) {
                if let Ok(e) = onto.resolve_entity(entity) {
                    return (e.id.clone(), v.entity_records(&e.id));
                }
            }
        }
    }
    (entity.to_string(), Vec::new())
}

/// Minimal support cone of `query_entity`: every SUPPORTED / CONFLICTING claim whose subject or
/// object is the entity, plus — for each of them and recursively for their premises — one
/// canonical active justification (lowest rank, then lowest id) and the evidence behind it.
/// Revoked, stale and unsupported branches are not read at all.
pub fn project_minimal_cone(bytes: &[u8], query_entity: &str) -> String {
    match minimal_cone_value(bytes, query_entity) {
        Ok(v) => to_jcs(&v),
        Err(e) => to_jcs(&json!({"error": e.to_string()})),
    }
}

pub fn minimal_cone_value(bytes: &[u8], query_entity: &str) -> Result<Value, crate::container::ContainerError> {
    let v = ContainerView::parse(bytes)?;
    let (entity, offs) = resolve_entity_records(&v, query_entity);
    let mut claims: BTreeMap<Hash, Value> = BTreeMap::new();
    let mut steps: BTreeMap<Hash, Value> = BTreeMap::new();
    let mut evid: BTreeMap<Hash, Value> = BTreeMap::new();
    let mut targets: BTreeSet<Hash> = BTreeSet::new();
    let mut stack: Vec<Hash> = Vec::new();
    for o in offs {
        let r = v.record_at(o)?;
        if r.status == ST_SUPPORTED || r.status == ST_CONFLICTING {
            targets.insert(r.id);
            stack.push(r.id);
        }
    }
    while let Some(cid) = stack.pop() {
        if claims.contains_key(&cid) {
            continue;
        }
        let r = match v.find_node(&cid) {
            Some(r) => r,
            None => continue,
        };
        let c = Claim::decode(r.payload)?;
        // choose the canonical active justification
        let mut best: Option<NodeRec> = None;
        let mut active = 0usize;
        for jid in r.adj_ids() {
            if let Some(jr) = v.find_node(&jid) {
                if jr.status == J_ACTIVE {
                    active += 1;
                    if best.is_none_or(|b| (jr.rank, jr.id) < (b.rank, b.id)) {
                        best = Some(jr);
                    }
                }
            }
        }
        let via = best.map(|b| b.id);
        claims.insert(cid, claim_value(&r, &c, Some(active.saturating_sub(1)), via.as_ref()));
        if let Some(jr) = best {
            let j = Justification::decode(jr.payload)?;
            steps.insert(jr.id, step_value(&jr, &j, false));
            match &j {
                Justification::Assertion { evidence, .. } => {
                    if !evid.contains_key(evidence) {
                        if let Some(er) = v.find_node(evidence) {
                            let ev = EvidenceNode::decode(er.payload)?;
                            evid.insert(*evidence, evidence_value(&v, &er, &ev, false));
                        }
                    }
                }
                Justification::Derivation { premises, .. } => stack.extend(premises.iter().copied()),
            }
        }
    }
    Ok(json!({
        "format": "sbgk-cone/1",
        "entity": entity,
        "state_root": to_hex(&v.root),
        "targets": targets.iter().map(short).collect::<Vec<_>>(),
        "claims": claims.into_values().collect::<Vec<_>>(),
        "steps": steps.into_values().collect::<Vec<_>>(),
        "evidence": evid.into_values().collect::<Vec<_>>(),
    }))
}

/// Whole-graph projection used as the hand-off baseline. With `active_only` the revoked,
/// stale and unsupported nodes are dropped; otherwise every node is serialised with its status.
pub fn project_full(bytes: &[u8], active_only: bool) -> String {
    match full_value(bytes, active_only) {
        Ok(v) => to_jcs(&v),
        Err(e) => to_jcs(&json!({"error": e.to_string()})),
    }
}

pub fn full_value(bytes: &[u8], active_only: bool) -> Result<Value, crate::container::ContainerError> {
    let v = ContainerView::parse(bytes)?;
    let mut claims: BTreeMap<Hash, Value> = BTreeMap::new();
    let mut steps: BTreeMap<Hash, Value> = BTreeMap::new();
    let mut evid: BTreeMap<Hash, Value> = BTreeMap::new();
    for r in v.records()? {
        match r.kind {
            KIND_CLAIM => {
                if active_only && r.status == ST_UNSUPPORTED {
                    continue;
                }
                let c = Claim::decode(r.payload)?;
                claims.insert(r.id, claim_value(&r, &c, None, None));
            }
            KIND_ASSERTION | KIND_DERIVATION => {
                if active_only && r.status != J_ACTIVE {
                    continue;
                }
                let j = Justification::decode(r.payload)?;
                steps.insert(r.id, step_value(&r, &j, !active_only));
            }
            KIND_EVIDENCE => {
                if active_only && r.status != EV_ACTIVE {
                    continue;
                }
                let ev = EvidenceNode::decode(r.payload)?;
                evid.insert(r.id, evidence_value(&v, &r, &ev, !active_only));
            }
            _ => {}
        }
    }
    Ok(json!({
        "format": if active_only { "sbgk-full-active/1" } else { "sbgk-full/1" },
        "state_root": to_hex(&v.root),
        "claims": claims.into_values().collect::<Vec<_>>(),
        "steps": steps.into_values().collect::<Vec<_>>(),
        "evidence": evid.into_values().collect::<Vec<_>>(),
    }))
}
