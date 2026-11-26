//! The reads of 0.3.0 over a journal that takes its sources as they come: the value of a key, the table of keys, a context
//! checkpoint as it reads now, and what the claim chains come to.
//!
//! All four are projections over the journal and never write. The key of a claim is its `subject`, compared as the exact
//! string, and its value is its `object`. A key has a current value while exactly one value is said by its active claims: the
//! claims that stand and that no standing `supersedes` relation replaced. The kernel refuses no record for what these reads find:
//! two active claims of one key with different values are a `VALUE_CONFLICT` to read, not a record to refuse, and a key the
//! caller requires and no active claim says is a `MISSING_REQUIRED_KEY`.
//!
//! A live server and `sbgk audit-read` over a journal call the same functions, as the reading tools of 0.2 do.

use super::read::{DEFAULT_LIMIT, MAX_LIMIT};
use super::state::{AuditState, RecordState};
use super::{AuditStore, RecordId, RecordKind, RecordView};
use crate::hash::{from_hex, to_hex};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const KEY_MEANING: &str = "the key of a claim is its subject, compared as the exact string, and its value is its object; a value is current while \
                               the claim stands and no standing supersedes relation replaced it";
pub const NOT_A_REFUSAL: &str = "a projection over the journal: the kernel refused no record for it";

type Claim = (Arc<RecordView>, RecordState);

fn value_of(r: &RecordView) -> Value {
    r.body.get("object").cloned().unwrap_or(Value::Null)
}

fn claim_row(r: &RecordView, state: RecordState) -> Value {
    let mut row = json!({"id": to_hex(&r.id.0), "short": r.id.short(), "key": r.body["subject"], "value": value_of(r), "text": r.text,
        "stance": r.status, "author": r.author, "state": state.name()});
    if let Some(as_of) = r.body.get("as_of").filter(|v| !v.is_null()) {
        row["as_of"] = as_of.clone();
    }
    if let RecordState::Superseded(by) = state {
        row["superseded_by"] = json!(to_hex(&by.0));
    }
    row
}

fn record_row(r: &RecordView, state: RecordState) -> Value {
    match r.kind {
        RecordKind::Claim => {
            let mut row = claim_row(r, state);
            row["kind"] = json!("claim");
            row
        }
        RecordKind::Observe => {
            json!({"id": to_hex(&r.id.0), "short": r.id.short(), "kind": "observe", "doc_id": r.doc_id, "quote": r.quote, "state": state.name()})
        }
        kind => json!({"id": to_hex(&r.id.0), "short": r.id.short(), "kind": kind.name(), "text": r.text, "state": state.name()}),
    }
}

/// The state of a key from its claims: `ACTIVE` with one value said by its active claims, `VALUE_CONFLICT` with more than one,
/// `NO_ACTIVE_VALUE` when it has claims and none is active, `UNKNOWN_KEY` without a claim.
fn key_state(claims: &[Claim]) -> (&'static str, Option<Value>) {
    let values: BTreeSet<String> = claims.iter().filter(|(_, state)| *state == RecordState::Active).map(|(r, _)| value_of(r).to_string()).collect();
    match (claims.is_empty(), values.len()) {
        (true, _) => ("UNKNOWN_KEY", None),
        (false, 0) => ("NO_ACTIVE_VALUE", None),
        (false, 1) => ("ACTIVE", claims.iter().rev().find(|(_, state)| *state == RecordState::Active).map(|(r, _)| value_of(r))),
        (false, _) => ("VALUE_CONFLICT", None),
    }
}

fn history(claims: &[Claim]) -> Value {
    let count = |name: &str| claims.iter().filter(|(_, state)| state.name() == name).count();
    json!({"claims": claims.len(), "active": count("ACTIVE"), "superseded": count("SUPERSEDED"),
           "affected_by_evidence_change": count("AFFECTED_BY_EVIDENCE_CHANGE")})
}

/// `key`: the value a key has now, read by the exact key. `ACTIVE` gives the value and the last active claim that says it;
/// `VALUE_CONFLICT` gives every active claim of the key; the claims that are active no more are counted, not listed.
pub fn key(s: &AuditState, key: &str) -> Value {
    let claims = s.claims_of_key(key);
    let (state, value) = key_state(&claims);
    let active: Vec<Value> = claims.iter().filter(|(_, state)| *state == RecordState::Active).map(|(r, state)| claim_row(r, *state)).collect();
    let mut out = json!({"status": "KEY", "key": key, "state": state, "history": history(&claims), "meaning": KEY_MEANING});
    match state {
        "ACTIVE" => {
            out["value"] = value.unwrap_or(Value::Null);
            out["record"] = active.last().cloned().unwrap_or(Value::Null);
            out["agreeing_claims"] = json!(active.len());
        }
        "VALUE_CONFLICT" => {
            out["active"] = json!(active);
            out["note"] = json!(NOT_A_REFUSAL);
        }
        _ => {}
    }
    out
}

/// The claims of a journal by key, in the order of the keys.
fn by_key(s: &AuditState) -> BTreeMap<String, Vec<Claim>> {
    let mut out: BTreeMap<String, Vec<Claim>> = BTreeMap::new();
    for (record, state) in s.claims_with_states() {
        if let Some(key) = record.body["subject"].as_str() {
            out.entry(key.to_string()).or_default().push((record, state));
        }
    }
    out
}

/// `keys`: every key with its state and, when it has one, its current value; then the keys in conflict, and the keys of
/// `required` that no active claim says (`MISSING_REQUIRED_KEY`).
pub fn keys(s: &AuditState, required: &[String], limit: Option<usize>) -> Value {
    let table = by_key(s);
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut rows = Vec::new();
    let mut conflicts = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (key, claims) in &table {
        let (state, value) = key_state(claims);
        *counts.entry(state).or_default() += 1;
        if state == "VALUE_CONFLICT" {
            let active: Vec<Value> = claims.iter().filter(|(_, state)| *state == RecordState::Active).map(|(r, state)| claim_row(r, *state)).collect();
            conflicts.push(json!({"key": key, "active": active}));
        }
        if rows.len() < limit {
            let mut row = json!({"key": key, "state": state, "history": history(claims)});
            if let Some(value) = value {
                row["value"] = value;
            }
            rows.push(row);
        }
    }
    let missing: Vec<Value> = required
        .iter()
        .filter(|key| table.get(*key).is_none_or(|claims| !claims.iter().any(|(_, state)| *state == RecordState::Active)))
        .map(|key| json!({"key": key, "state": "MISSING_REQUIRED_KEY", "known": table.contains_key(key)}))
        .collect();
    json!({"status": "KEYS", "count": table.len(), "by_state": counts, "keys": rows, "truncated": table.len() > limit,
           "value_conflicts": conflicts, "required": required.len(), "missing_required_keys": missing,
           "meaning": KEY_MEANING, "note": NOT_A_REFUSAL})
}

/// The keys of the claims a manifest lists.
fn manifest_keys(s: &AuditState, context: &Value) -> BTreeSet<String> {
    let ids = context["records"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(from_hex)).map(RecordId);
    ids.filter_map(|id| s.record(&id)).filter(|r| r.kind == RecordKind::Claim).filter_map(|r| r.body["subject"].as_str().map(str::to_string)).collect()
}

/// `checkpoint`: a context checkpoint as it reads now (the last one when no epoch is named). Only the records of its manifest
/// that are active now are given back; those withdrawn, affected by a change of evidence or replaced since are named with
/// their state. Each source says whether its bytes are still the bytes the checkpoint named. `keys_not_carried` are the keys
/// the checkpoint before listed and this one does not: one of them that still has an active claim is a `MISSING_REQUIRED_KEY`.
pub fn checkpoint(s: &AuditState, epoch: Option<u64>) -> Value {
    let epochs = s.context_epochs();
    let epoch = epoch.unwrap_or(epochs);
    let read = match s.read_active_checkpoint(epoch) {
        Ok(read) => read,
        // under rules 3 there is none to read: a checkpoint with such a key is any checkpoint there, and is not read as a manifest
        Err(_) if s.rules_version() == super::state::RULES_VERSION_3 => {
            return json!({"status": "NO_CONTEXT_CHECKPOINT", "epoch": epoch, "epochs": 0, "rules_version": s.rules_version(),
                          "message": "a context checkpoint is of rules 4: this journal names rules 3"})
        }
        Err(_) => {
            return json!({"status": "NO_CONTEXT_CHECKPOINT", "epoch": epoch, "epochs": epochs,
                          "message": "this journal has no context checkpoint of that epoch"})
        }
    };
    let active: Vec<Value> = read.active.iter().map(|r| record_row(r, RecordState::Active)).collect();
    let mut dropped: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for (id, state) in &read.dropped {
        let mut row = json!({"id": to_hex(&id.0), "short": id.short()});
        if let Some(key) = s.record(id).and_then(|r| r.body["subject"].as_str().map(str::to_string)) {
            row["key"] = json!(key);
        }
        if let RecordState::Superseded(by) = state {
            row["superseded_by"] = json!(to_hex(&by.0));
        }
        dropped.entry(state.name()).or_default().push(row);
    }
    let sources: BTreeMap<String, Value> = read.context["sources"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(doc, hash)| (doc.clone(), json!({"raw_sha256": hash, "current": s.source_document(doc).is_some_and(|d| d["raw_sha256"] == *hash)})))
        .collect();
    let mut not_carried = Vec::new();
    if epoch > 1 {
        if let Some((before, _)) = s.context_checkpoint_of(epoch - 1) {
            let carried = manifest_keys(s, &read.context);
            for key in manifest_keys(s, &before).difference(&carried) {
                let (state, _) = key_state(&s.claims_of_key(key));
                let state = if state == "ACTIVE" || state == "VALUE_CONFLICT" { "MISSING_REQUIRED_KEY" } else { state };
                not_carried.push(json!({"key": key, "state": state}));
            }
        }
    }
    json!({"status": "CONTEXT_CHECKPOINT", "epoch": epoch, "epochs": epochs, "key": format!("{}{epoch}", super::state::CONTEXT_CHECKPOINT_PREFIX),
           "cursor": read.cursor, "raw_context": read.context["raw_context"], "sources": sources, "manifest": read.context["manifest"],
           "listed": read.active.len() + read.dropped.len(), "active": active, "dropped": dropped, "keys_not_carried": not_carried,
           "meaning": "only the records of the checkpoint that are active now; nothing is erased: the journal keeps every record"})
}

/// `claim_chains`: the longest chain of claims resting on claims, and the share of the standing claims without a quote of their
/// own among their grounds (in parts of ten thousand, a whole number).
pub fn claim_chains(s: &AuditState) -> Value {
    let chains = s.claim_chains();
    let share = (chains.standing_without_own_quote * 10_000).checked_div(chains.standing_claims).unwrap_or(0);
    json!({"max_depth": chains.max_depth, "standing_claims": chains.standing_claims,
           "standing_without_own_quote": chains.standing_without_own_quote, "without_own_quote_per_10000": share})
}
