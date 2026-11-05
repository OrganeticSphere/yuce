//! Streaming JSONL ingestion with fail-fast validation and structured repair obligations.
//!
//! The agent is an untrusted proposer: it names things with throw-away `local_id`s and quotes
//! text; the kernel binds quotes to bytes, resolves entities, checks rule applications,
//! computes intervals and erases every local name before anything is committed.

use crate::arena::{find_all, nearest_segments, unique_extension, Arena};
use crate::cdc::CdcParams;
use crate::engine::{Applied, CanonOp, DredReport, Engine};
use crate::error::{Code, KResult, KernelError};
use crate::hash::{short, to_hex, Hash};
use crate::node::*;
use crate::ontology::*;
use crate::wal::Wal;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AppliedLine {
    pub seq: u64,
    pub op: &'static str,
    pub node: Option<Hash>,
    pub created: usize,
    /// `Some(true)` when the node this event names (evidence or claim) already existed, i.e. the event
    /// repeated a step that is already in the graph; `None` for events without such a node.
    pub existed: Option<bool>,
    pub claim_status: Option<u8>,
    pub dred: Option<DredReport>,
    pub wal_end: usize,
}

impl AppliedLine {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("status".into(), json!("ok"));
        m.insert("seq".into(), json!(self.seq));
        m.insert("op".into(), json!(self.op));
        if let Some(n) = &self.node {
            m.insert("node".into(), json!(short(n)));
        }
        if let Some(cs) = self.claim_status {
            m.insert("claim_status".into(), json!(status_name(KIND_CLAIM, cs)));
        }
        m.insert("created".into(), json!(self.created));
        if let Some(e) = self.existed {
            m.insert("existed".into(), json!(e));
        }
        if let Some(d) = &self.dred {
            m.insert("dred".into(), json!({"over_deleted": d.over_deleted, "rederived": d.rederived, "net_removed": d.net_removed}));
        }
        Value::Object(m)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DocUpdateReport {
    pub chunks_before: usize,
    pub chunks_total: usize,
    pub chunks_new: usize,
    pub chunks_reused: usize,
    pub evidence_total: usize,
    pub evidence_stale: usize,
    pub rebound_ok: usize,
    pub rebind_failed: usize,
    pub claims_touched: usize,
    pub claims_net_removed: usize,
    pub claims_restored: usize,
    pub claims_supported_before: usize,
    pub claims_supported_after: usize,
}

pub struct Session {
    pub ontology: Ontology,
    pub arena: Arena,
    pub engine: Engine,
    pub wal: Wal,
    locals: HashMap<String, Hash>,
    locals_rev: HashMap<Hash, String>,
    pub last_seq: u64,
    /// Record `(seq, wal_end, root)` after every agent line (used by time-travel experiments).
    pub track_roots: bool,
    pub seq_roots: Vec<(u64, usize, Hash)>,
    /// When set, every committed mutation (accepted event line, document put) is queued here as a session-log record
    /// (`crate::journal`) in commit order, for the owner to persist.
    pub journal: Option<Vec<String>>,
}

fn s_field<'a>(o: &'a Map<String, Value>, k: &str) -> KResult<&'a str> {
    match o.get(k) {
        None => Err(KernelError::new(Code::MissingField, format!("missing field '{k}'")).field(k)),
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(KernelError::new(Code::BadField, format!("field '{k}' must be a string")).field(k)),
    }
}

/// Hard bounds that keep every canonical encoding inside its fixed-width length fields.
pub const MAX_STR: usize = 1024;
pub const MAX_REFS: usize = 256;
pub const MAX_QUOTE: usize = 16 * 1024;

fn too_long(field: &str, len: usize, max: usize) -> KernelError {
    KernelError::new(Code::BadField, format!("'{field}' is {len} bytes, the limit is {max}")).field(field)
}

fn str_list(o: &Map<String, Value>, k: &str) -> KResult<Vec<String>> {
    if let Some(Value::Array(a)) = o.get(k) {
        if a.len() > MAX_REFS {
            return Err(too_long(k, a.len(), MAX_REFS));
        }
    }
    match o.get(k) {
        None => Err(KernelError::new(Code::MissingField, format!("missing field '{k}'")).field(k)),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().map(|s| s.to_string()).ok_or_else(|| KernelError::new(Code::BadField, format!("'{k}' must be an array of strings")).field(k)))
            .collect(),
        Some(_) => Err(KernelError::new(Code::BadField, format!("field '{k}' must be an array")).field(k)),
    }
}

fn interval(v: Option<&Value>, field: &str) -> KResult<(i64, i64)> {
    let a = match v {
        None => return Err(KernelError::new(Code::MissingField, format!("missing field '{field}'")).field(field)),
        Some(Value::Array(a)) if a.len() == 2 => a,
        _ => return Err(KernelError::new(Code::BadInterval, "t must be [t_from, t_to)").field(field)),
    };
    match (a[0].as_i64(), a[1].as_i64()) {
        (Some(x), Some(y)) if x < y => Ok((x, y)),
        _ => Err(KernelError::new(Code::BadInterval, "t must be two integers with t_from < t_to").field(field)),
    }
}

fn claim_json(c: &Claim) -> Value {
    json!({"s": c.s, "p": c.p, "o": c.o, "polarity": c.pol.as_str(), "ctx": c.ctx, "t": [c.t_from, c.t_to]})
}

impl Session {
    pub fn new(ontology: Ontology, cdc: CdcParams) -> Session {
        let mut arena = Arena::new(cdc);
        arena.blobs.insert(ontology.hash, ontology.canonical_json.clone().into_bytes());
        let mut s = Session {
            ontology,
            arena,
            engine: Engine::new(),
            wal: Wal::new(),
            locals: HashMap::new(),
            locals_rev: HashMap::new(),
            last_seq: 0,
            track_roots: false,
            seq_roots: Vec::new(),
            journal: None,
        };
        let g = CanonOp::Genesis { ontology_hash: s.ontology.hash, cdc: cdc.to_tuple() };
        s.commit_with_seq(0, &g).expect("genesis cannot fail");
        s
    }

    /// Resume a session from already verified parts (local names are not persisted, so
    /// existing nodes are addressed as `@<hex id prefix>`).
    pub fn from_parts(ontology: Ontology, arena: Arena, engine: Engine, wal: Wal) -> Session {
        let last_seq = wal.last_seq;
        Session {
            ontology,
            arena,
            engine,
            wal,
            locals: HashMap::new(),
            locals_rev: HashMap::new(),
            last_seq,
            track_roots: false,
            seq_roots: Vec::new(),
            journal: None,
        }
    }

    /// What `from_parts` resets, on this session itself: for a caller that goes on with it where it would otherwise rebuild it from
    /// copies of its parts.
    pub(crate) fn reset_transients(&mut self) {
        self.locals.clear();
        self.locals_rev.clear();
        self.last_seq = self.wal.last_seq;
        self.track_roots = false;
        self.seq_roots.clear();
        self.journal = None;
    }

    fn commit_with_seq(&mut self, seq: u64, op: &CanonOp) -> Result<(Applied, usize), KernelError> {
        self.commit_flagged(seq, op, false)
    }

    fn commit_flagged(&mut self, seq: u64, op: &CanonOp, kernel: bool) -> Result<(Applied, usize), KernelError> {
        if let CanonOp::BindEvidence { ev, .. } = op {
            if !self.arena.verify_evidence(ev) {
                return Err(KernelError::new(Code::BadField, "evidence does not describe a continuous byte range"));
            }
        }
        let ap = self.engine.apply(op).map_err(|e| KernelError::new(Code::BadField, format!("internal engine error: {}", e.0)))?;
        let end = self.wal.append(seq, op, kernel);
        Ok((ap, end))
    }

    // ------------------------------------------------------------------ documents

    /// Insert or update a source document. Evidence whose ordered contiguous chunk window
    /// disappeared goes STALE (DRed cascade); each stale quote is then re-located in the new
    /// bytes and re-bound when it occurs exactly once.
    pub fn put_document(&mut self, doc_id: &str, bytes: &[u8]) -> DocUpdateReport {
        assert!(doc_id.len() <= MAX_STR, "doc_id longer than {MAX_STR} bytes");
        let before = self.engine.status_counts().0;
        let chunks_before = self.arena.doc(doc_id).map_or(0, |d| d.chunk_hashes.len());
        if let Some(j) = self.journal.as_mut() {
            j.push(crate::journal::doc_record(doc_id, bytes));
        }
        let put = self.arena.put_document(doc_id, bytes);
        let mut rep = DocUpdateReport {
            chunks_before,
            chunks_total: put.chunks_total,
            chunks_new: put.chunks_new,
            chunks_reused: put.chunks_reused_from_prev,
            claims_supported_before: before,
            ..Default::default()
        };
        let op = CanonOp::DocPut { doc_id: doc_id.to_string(), version: put.version_id, chunks: put.chunk_hashes.clone() };
        let (ap, _) = self.commit_with_seq(self.last_seq, &op).expect("docput cannot fail");
        if let Some(d) = ap.dred {
            rep.claims_touched = d.over_deleted;
            rep.claims_net_removed = d.net_removed;
        }
        let stale = self.engine.stale_evidence_of_doc(doc_id);
        rep.evidence_stale = stale.len();
        for (old_id, old_ev) in stale {
            let new_bytes = &self.arena.doc(doc_id).expect("just inserted").bytes;
            let quote = match self.arena.quote_bytes(&old_ev) {
                Some(q) => q,
                None => {
                    rep.rebind_failed += 1;
                    continue;
                }
            };
            let occ = find_all(new_bytes, &quote);
            if occ.len() != 1 {
                rep.rebind_failed += 1;
                continue;
            }
            let anchor = self.arena.anchor_for_span(doc_id, occ[0].start, occ[0].end).expect("span in range");
            if anchor.segs.len() > MAX_EVIDENCE_SEGMENTS {
                rep.rebind_failed += 1;
                continue;
            }
            let new_ev = Arena::evidence_node(&anchor, quote.len());
            let new_id = new_ev.id();
            let claims = self.engine.claims_asserted_by(&old_id);
            self.commit_flagged(self.last_seq, &CanonOp::BindEvidence { doc_version: anchor.doc_version_id, ev: new_ev }, true).expect("rebind bind");
            for c in claims {
                self.commit_flagged(self.last_seq, &CanonOp::Assert { claim: c, evidence: vec![new_id] }, true).expect("rebind assert");
            }
            // Keep the agent's local names valid across the rebind.
            for v in self.locals.values_mut() {
                if *v == old_id {
                    *v = new_id;
                }
            }
            if let Some(name) = self.locals_rev.remove(&old_id) {
                self.locals_rev.insert(new_id, name);
            }
            rep.rebound_ok += 1;
        }
        rep.evidence_total = self.evidence_count_of(doc_id);
        rep.claims_supported_after = self.engine.status_counts().0;
        rep.claims_restored = rep.claims_supported_after.saturating_sub(rep.claims_supported_before.saturating_sub(rep.claims_net_removed));
        rep
    }

    fn evidence_count_of(&self, doc_id: &str) -> usize {
        self.engine.evidence_count_of_doc(doc_id)
    }

    // ------------------------------------------------------------------ line ingestion

    pub fn apply_line(&mut self, line: &str) -> KResult<AppliedLine> {
        let v: Value = serde_json::from_str(line).map_err(|e| KernelError::new(Code::BadJson, format!("invalid JSON: {e}")))?;
        let obj = match v {
            Value::Object(m) => m,
            _ => return Err(KernelError::new(Code::BadJson, "each line must be a JSON object")),
        };
        let seq = match obj.get("seq") {
            None => return Err(KernelError::new(Code::MissingField, "missing field 'seq'").field("seq")),
            Some(x) => x.as_u64().ok_or_else(|| KernelError::new(Code::BadField, "seq must be a positive integer").field("seq"))?,
        };
        let r = self.apply_obj(seq, &obj);
        match r {
            Ok(a) => {
                self.last_seq = seq;
                if let Some(j) = self.journal.as_mut() {
                    j.push(crate::journal::event_record(line));
                }
                if self.track_roots {
                    let root = self.engine.root();
                    self.seq_roots.push((seq, a.wal_end, root));
                }
                Ok(a)
            }
            Err(e) => Err(e.with_seq(seq)),
        }
    }

    fn apply_obj(&mut self, seq: u64, obj: &Map<String, Value>) -> KResult<AppliedLine> {
        if seq != self.last_seq + 1 {
            return Err(KernelError::new(Code::SeqMismatch, format!("expected seq {}, got {seq}", self.last_seq + 1))
                .field("seq")
                .expected(json!({"seq": self.last_seq + 1}))
                .obligation(json!({"action": "resubmit_with_expected_seq"})));
        }
        let op = s_field(obj, "op")?;
        match op {
            "bind_evidence" => self.op_bind(seq, obj),
            "assert_fact" => self.op_assert(seq, obj),
            "derive" => self.op_derive(seq, obj),
            "revoke_evidence" => self.op_revoke(seq, obj),
            other => Err(KernelError::new(Code::UnknownOp, format!("unknown op '{other}'"))
                .field("op")
                .expected(json!({"ops": ["bind_evidence", "assert_fact", "derive", "revoke_evidence"]}))),
        }
    }

    fn new_local(&self, obj: &Map<String, Value>) -> KResult<String> {
        let id = s_field(obj, "local_id")?.to_string();
        if self.locals.contains_key(&id) {
            return Err(KernelError::new(Code::DuplicateLocalId, format!("local_id '{id}' already used")).field("local_id"));
        }
        Ok(id)
    }

    fn resolve_local(&self, name: &str, field: &str) -> KResult<Hash> {
        if let Some(h) = self.locals.get(name) {
            return Ok(*h);
        }
        if let Some(hex) = name.strip_prefix('@') {
            if hex.len() >= 8 {
                if let Some(h) = self.engine.find_by_prefix(hex) {
                    return Ok(h);
                }
            }
        }
        Err(KernelError::new(Code::UnknownLocalId, format!("unknown local id '{name}'"))
            .field(field)
            .obligation(json!({"action": "reference_a_previously_defined_local_id_or_@node_id"})))
    }

    fn bind_local(&mut self, name: String, id: Hash) {
        self.locals_rev.entry(id).or_insert_with(|| name.clone());
        self.locals.insert(name, id);
    }

    fn finish(&mut self, seq: u64, op: &'static str, cop: CanonOp) -> KResult<AppliedLine> {
        let existed = match &cop {
            CanonOp::BindEvidence { ev, .. } => Some(self.engine.contains(&ev.id())),
            CanonOp::Assert { claim, .. } | CanonOp::Derive { claim, .. } => Some(self.engine.contains(&claim.id())),
            _ => None,
        };
        let (ap, end) = self.commit_with_seq(seq, &cop)?;
        Ok(AppliedLine { seq, op, node: ap.node, created: ap.created, existed, claim_status: ap.claim_status, dred: ap.dred, wal_end: end })
    }

    // -- bind_evidence --------------------------------------------------------------

    fn op_bind(&mut self, seq: u64, obj: &Map<String, Value>) -> KResult<AppliedLine> {
        let local = self.new_local(obj)?;
        let doc_id = s_field(obj, "doc_id")?;
        let quote = s_field(obj, "exact_quote")?;
        if quote.is_empty() {
            return Err(KernelError::new(Code::BadField, "exact_quote must not be empty").field("exact_quote"));
        }
        if quote.len() > MAX_QUOTE {
            return Err(too_long("exact_quote", quote.len(), MAX_QUOTE));
        }
        let doc = match self.arena.doc(doc_id) {
            Some(d) => d,
            None => {
                let ids: Vec<&String> = self.arena.doc_ids().collect();
                return Err(KernelError::new(Code::UnknownDoc, format!("unknown doc_id '{doc_id}'")).field("doc_id").expected(json!({"doc_ids": ids})));
            }
        };
        let occ = find_all(&doc.bytes, quote.as_bytes());
        if occ.is_empty() {
            let cands: Vec<Value> = nearest_segments(&doc.bytes, quote.as_bytes(), 3)
                .into_iter()
                .map(|(sim, s, e)| json!({"exact_quote": String::from_utf8_lossy(&doc.bytes[s..e]), "similarity_permille": (sim * 1000.0) as u64}))
                .collect();
            return Err(KernelError::new(Code::QuoteNotFoundInBytes, "quote has no byte-exact occurrence in the document")
                .field("exact_quote")
                .expected(json!({"candidates": cands}))
                .obligation(json!({"action": "resubmit_with_exact_quote", "choose_one_of": "expected_by_kernel.candidates"})));
        }
        if occ.len() > 1 {
            let exts: Vec<Value> = occ
                .iter()
                .take(8)
                .filter_map(|o| unique_extension(&doc.bytes, o, 160))
                .map(|(s, e)| json!(String::from_utf8_lossy(&doc.bytes[s..e])))
                .collect();
            return Err(KernelError::new(Code::AmbiguousQuoteSpan, format!("quote occurs {} times", occ.len()))
                .field("exact_quote")
                .expected(json!({"occurrences": occ.len(), "unique_extensions": exts}))
                .obligation(json!({"action": "resubmit_with_longer_quote", "choose_one_of": "expected_by_kernel.unique_extensions"})));
        }
        let anchor = self.arena.anchor_for_span(doc_id, occ[0].start, occ[0].end).expect("occurrence in range");
        if anchor.segs.len() > MAX_EVIDENCE_SEGMENTS {
            return Err(KernelError::new(
                Code::QuoteTooFragmented,
                format!("the quote spans {} chunks; one evidence node holds at most {MAX_EVIDENCE_SEGMENTS}", anchor.segs.len()),
            )
            .field("exact_quote")
            .expected(json!({"max_segments": MAX_EVIDENCE_SEGMENTS, "segments": anchor.segs.len()}))
            .obligation(json!({"action": "resubmit_with_shorter_quote"})));
        }
        let ev = Arena::evidence_node(&anchor, quote.len());
        let id = ev.id();
        if self.engine.status_of(&id) == Some(EV_REVOKED) {
            return Err(KernelError::new(Code::EvidenceRevoked, "this exact evidence was revoked earlier").field("exact_quote"));
        }
        let r = self.finish(seq, "bind_evidence", CanonOp::BindEvidence { doc_version: anchor.doc_version_id, ev })?;
        self.bind_local(local, id);
        Ok(r)
    }

    // -- shared helpers --------------------------------------------------------------

    fn resolve_subject(&self, pred: &Predicate, name: &str, field: &str) -> KResult<String> {
        self.resolve_typed(name, &pred.subject, field)
    }

    fn resolve_typed(&self, name: &str, want_type: &str, field: &str) -> KResult<String> {
        match self.ontology.resolve_entity(name) {
            Ok(e) if e.ty == want_type => Ok(e.id.clone()),
            Ok(e) => Err(KernelError::new(Code::TypeMismatch, format!("'{name}' is a {} but a {want_type} is required", e.ty))
                .field(field)
                .expected(json!({"required_type": want_type, "actual_type": e.ty, "entity": e.id}))),
            Err(ResolveErr::Ambiguous { candidates }) => Err(KernelError::new(Code::AmbiguousEntity, format!("alias '{name}' maps to several entities"))
                .field(field)
                .expected(json!({"candidates": candidates}))
                .obligation(json!({"action": "resubmit_with_canonical_entity_id", "choose_one_of": "expected_by_kernel.candidates"}))),
            Err(ResolveErr::Unknown { suggestions }) => {
                Err(KernelError::new(Code::UnknownEntity, format!("unknown entity '{name}'")).field(field).expected(json!({"suggestions": suggestions})))
            }
        }
    }

    fn resolve_object(&self, pred: &Predicate, name: &str, field: &str) -> KResult<String> {
        match &pred.object {
            ObjType::Literal => {
                if name.is_empty() {
                    Err(KernelError::new(Code::BadField, "literal object must not be empty").field(field))
                } else if name.len() > MAX_STR {
                    Err(too_long(field, name.len(), MAX_STR))
                } else if pred.allowed_values.as_ref().is_some_and(|v| !v.iter().any(|x| x == name)) {
                    Err(KernelError::new(Code::LiteralNotAllowed, format!("'{name}' is not an allowed value of '{}'", pred.id))
                        .field(field)
                        .expected(json!({"predicate": pred.id, "allowed_values": pred.allowed_values}))
                        .obligation(json!({"action": "resubmit_with_allowed_literal", "choose_one_of": "expected_by_kernel.allowed_values"})))
                } else {
                    Ok(name.to_string())
                }
            }
            ObjType::Entity(t) => self.resolve_typed(name, t, field),
        }
    }

    fn predicate(&self, name: &str, field: &str) -> KResult<&Predicate> {
        self.ontology.predicates.get(name).ok_or_else(|| {
            let mut sugg: Vec<&String> = self.ontology.predicates.keys().filter(|k| k.contains(name) || name.contains(k.as_str())).collect();
            sugg.truncate(5);
            KernelError::new(Code::UnknownPredicate, format!("unknown predicate '{name}'")).field(field).expected(json!({"suggestions": sugg}))
        })
    }

    fn pol(obj: &Map<String, Value>) -> KResult<Polarity> {
        let s = s_field(obj, "polarity")?;
        Polarity::parse(s).ok_or_else(|| {
            KernelError::new(Code::BadPolarity, format!("polarity '{s}' is not POS/NEG")).field("polarity").expected(json!({"polarity": ["POS", "NEG"]}))
        })
    }

    // -- assert_fact ------------------------------------------------------------------

    fn op_assert(&mut self, seq: u64, obj: &Map<String, Value>) -> KResult<AppliedLine> {
        let local = self.new_local(obj)?;
        let p = s_field(obj, "p")?;
        let pred = self.predicate(p, "p")?.clone();
        let s = self.resolve_subject(&pred, s_field(obj, "s")?, "s")?;
        let o = self.resolve_object(&pred, s_field(obj, "o")?, "o")?;
        let pol = Self::pol(obj)?;
        let ctx = s_field(obj, "ctx")?;
        if ctx.is_empty() {
            return Err(KernelError::new(Code::BadField, "ctx must not be empty").field("ctx"));
        }
        if ctx.len() > MAX_STR {
            return Err(too_long("ctx", ctx.len(), MAX_STR));
        }
        let (t_from, t_to) = interval(obj.get("t"), "t")?;
        let ev_names = str_list(obj, "evidence")?;
        if ev_names.is_empty() {
            return Err(KernelError::new(Code::NoEvidence, "a fact needs at least one evidence reference").field("evidence"));
        }
        let mut ev_ids = Vec::new();
        for n in &ev_names {
            let id = self.resolve_local(n, "evidence")?;
            match self.engine.kind_of(&id) {
                Some(KIND_EVIDENCE) => {}
                _ => return Err(KernelError::new(Code::NotAnEvidence, format!("'{n}' is not an evidence reference")).field("evidence")),
            }
            let st = self.engine.status_of(&id).unwrap_or(EV_REVOKED);
            if st != EV_ACTIVE {
                return Err(KernelError::new(Code::EvidenceNotActive, format!("evidence '{n}' is {}", status_name(KIND_EVIDENCE, st)))
                    .field("evidence")
                    .expected(json!({"evidence_status": status_name(KIND_EVIDENCE, st)}))
                    .obligation(json!({"action": "bind_fresh_evidence_or_drop_reference"})));
            }
            ev_ids.push(id);
        }
        ev_ids.sort();
        ev_ids.dedup();
        let claim = Claim { s, p: p.to_string(), o, pol, ctx: ctx.to_string(), t_from, t_to };
        let id = claim.id();
        let r = self.finish(seq, "assert_fact", CanonOp::Assert { claim, evidence: ev_ids })?;
        self.bind_local(local, id);
        Ok(r)
    }

    // -- derive ------------------------------------------------------------------------

    fn op_derive(&mut self, seq: u64, obj: &Map<String, Value>) -> KResult<AppliedLine> {
        let local = self.new_local(obj)?;
        let rule_name = s_field(obj, "rule")?;
        let rule = match self.ontology.rules.get(rule_name) {
            Some(r) => r.clone(),
            None => {
                let ids: Vec<&String> = self.ontology.rules.keys().collect();
                return Err(KernelError::new(Code::UnknownRule, format!("unknown rule '{rule_name}'")).field("rule").expected(json!({"rules": ids})));
            }
        };
        let names = str_list(obj, "premises")?;
        let mut premises: Vec<(String, Hash, Claim)> = Vec::new();
        for n in &names {
            let id = self.resolve_local(n, "premises")?;
            let c = match self.engine.claim(&id) {
                Some(c) => c.clone(),
                None => return Err(KernelError::new(Code::NotAClaim, format!("'{n}' is not a claim")).field("premises")),
            };
            match self.engine.status_of(&id) {
                Some(ST_SUPPORTED) => {}
                Some(ST_CONFLICTING) => {
                    return Err(KernelError::new(Code::PremiseConflicting, format!("premise '{n}' is in a conflicting pair and blocked"))
                        .field("premises")
                        .expected(json!({"premise": n, "claim": claim_json(&c)}))
                        .obligation(json!({"action": "resolve_conflict_by_revoking_one_side_or_choose_another_premise"})))
                }
                _ => {
                    let cands = self.supported_alternatives(&c, &id);
                    return Err(KernelError::new(Code::PremiseUnsupported, format!("premise '{n}' is not supported in the current graph"))
                        .field("premises")
                        .expected(json!({"premise": n, "claim": claim_json(&c), "candidates": cands}))
                        .obligation(json!({"action": "replace_premise", "premise": n, "with_one_of": "expected_by_kernel.candidates"})));
                }
            }
            premises.push((n.clone(), id, c));
        }

        let agent_claim = obj.get("claim").and_then(|c| c.as_object());
        if obj.contains_key("claim") && agent_claim.is_none() {
            return Err(KernelError::new(Code::BadField, "claim must be an object").field("claim"));
        }

        let (expected, justs) = match rule.mode {
            Mode::And => self.derive_and(&rule, &premises, agent_claim)?,
            Mode::Or => self.derive_or(&rule, &premises, agent_claim)?,
        };
        // A rule can copy a literal from a less restrictive predicate. Validate the
        // selected computed head even when the caller omitted `claim` (as auto-closure does).
        let pred = self.predicate(&expected.p, "claim.p")?;
        if pred.allowed_values.is_some() {
            self.resolve_object(pred, &expected.o, "claim.o")?;
        }
        let id = expected.id();
        let r = self.finish(seq, "derive", CanonOp::Derive { claim: expected, justs })?;
        self.bind_local(local, id);
        Ok(r)
    }

    fn supported_alternatives(&self, like: &Claim, exclude: &Hash) -> Vec<Value> {
        let mut out = Vec::new();
        for id in self.engine.claim_ids() {
            if &id == exclude || self.engine.status_of(&id) != Some(ST_SUPPORTED) {
                continue;
            }
            let c = self.engine.claim(&id).unwrap();
            if c.p == like.p && c.pol == like.pol && c.ctx == like.ctx && c.overlaps(like) {
                out.push((self.locals_rev.get(&id).cloned().unwrap_or_else(|| format!("@{}", short(&id))), c.clone()));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.truncate(5);
        out.into_iter().map(|(n, c)| json!({"local_id": n, "claim": claim_json(&c)})).collect()
    }

    fn eval_term(t: &Term, prem: &[&Claim]) -> String {
        match t {
            Term::Const(c) => c.clone(),
            Term::Ref(i, Field::S) => prem[*i].s.clone(),
            Term::Ref(i, Field::O) => prem[*i].o.clone(),
        }
    }

    fn field_of(c: &Claim, f: Field) -> &str {
        match f {
            Field::S => &c.s,
            Field::O => &c.o,
        }
    }

    fn derive_and(&self, rule: &Rule, premises: &[(String, Hash, Claim)], agent: Option<&Map<String, Value>>) -> KResult<(Claim, Vec<(String, Vec<Hash>)>)> {
        let n = rule.body.len();
        if premises.len() != n {
            return Err(KernelError::new(Code::ArityMismatch, format!("rule {} takes {n} premises, got {}", rule.id, premises.len()))
                .field("premises")
                .expected(json!({"arity": n, "body": rule.body.iter().map(|a| json!({"p": a.p, "polarity": a.pol.as_str()})).collect::<Vec<_>>()})));
        }
        // Enumerate assignments of premises to body atoms (premise order is irrelevant to the
        // kernel: the agent's ordering noise must not change the committed node).
        let mut valid: Vec<Vec<usize>> = Vec::new();
        let mut pred_ok = false;
        let mut perm: Vec<usize> = (0..n).collect();
        permute(&mut perm, 0, &mut |p| {
            // body atom i takes premise p[i]
            if (0..n).all(|i| premises[p[i]].2.p == rule.body[i].p && premises[p[i]].2.pol == rule.body[i].pol) {
                pred_ok = true;
                let cl: Vec<&Claim> = (0..n).map(|i| &premises[p[i]].2).collect();
                if rule.join.iter().all(|((ai, af), (bi, bf))| Self::field_of(cl[*ai], *af) == Self::field_of(cl[*bi], *bf)) {
                    valid.push(p.to_vec());
                }
            }
        });
        if !pred_ok {
            return Err(KernelError::new(Code::PremisePredicateMismatch, format!("premises do not match the body of {}", rule.id))
                .field("premises")
                .expected(json!({"body": rule.body.iter().map(|a| json!({"p": a.p, "polarity": a.pol.as_str()})).collect::<Vec<_>>(),
                                  "given": premises.iter().map(|p| json!({"local_id": p.0, "p": p.2.p, "polarity": p.2.pol.as_str()})).collect::<Vec<_>>()})));
        }
        if valid.is_empty() {
            return Err(KernelError::new(Code::JoinViolation, format!("premises violate the join conditions of {}", rule.id)).field("premises").expected(
                json!({"join": rule.join.iter().map(|((ai, af), (bi, bf))| format!("{ai}.{} == {bi}.{}", af.as_str(), bf.as_str())).collect::<Vec<_>>()}),
            ));
        }
        // ctx must agree across premises.
        let ctx = premises[0].2.ctx.clone();
        if premises.iter().any(|p| p.2.ctx != ctx) {
            let ctxs: Vec<&str> = premises.iter().map(|p| p.2.ctx.as_str()).collect();
            return Err(KernelError::new(Code::CtxMismatch, "premises live in different contexts").field("premises").expected(json!({"contexts": ctxs})));
        }
        let t_from = premises.iter().map(|p| p.2.t_from).max().unwrap();
        let t_to = premises.iter().map(|p| p.2.t_to).min().unwrap();
        if t_from >= t_to {
            return Err(KernelError::new(Code::EmptyIntervalIntersection, "premise intervals do not intersect")
                .field("premises")
                .expected(json!({"intervals": premises.iter().map(|p| json!([p.2.t_from, p.2.t_to])).collect::<Vec<_>>()})));
        }
        // Candidate heads (one per valid assignment).
        let mut heads: Vec<Claim> = Vec::new();
        for p in &valid {
            let cl: Vec<&Claim> = (0..n).map(|i| &premises[p[i]].2).collect();
            let h = Claim {
                s: Self::eval_term(&rule.head.s, &cl),
                p: rule.head.p.clone(),
                o: Self::eval_term(&rule.head.o, &cl),
                pol: rule.head.pol,
                ctx: ctx.clone(),
                t_from,
                t_to,
            };
            if !heads.contains(&h) {
                heads.push(h);
            }
        }
        let expected = self.match_agent_head(&heads, agent)?;
        let mut ids: Vec<Hash> = premises.iter().map(|p| p.1).collect();
        ids.sort();
        ids.dedup();
        Ok((expected, vec![(rule.id.clone(), ids)]))
    }

    fn derive_or(&self, rule: &Rule, premises: &[(String, Hash, Claim)], agent: Option<&Map<String, Value>>) -> KResult<(Claim, Vec<(String, Vec<Hash>)>)> {
        if premises.is_empty() {
            return Err(KernelError::new(Code::ArityMismatch, "an OR rule needs at least one premise").field("premises"));
        }
        for (n, _, c) in premises {
            if !rule.body.iter().any(|a| a.p == c.p && a.pol == c.pol) {
                return Err(KernelError::new(Code::PremisePredicateMismatch, format!("premise '{n}' matches no alternative of {}", rule.id))
                    .field("premises")
                    .expected(json!({"alternatives": rule.body.iter().map(|a| json!({"p": a.p, "polarity": a.pol.as_str()})).collect::<Vec<_>>()})));
            }
        }
        let mut heads: Vec<Claim> = Vec::new();
        for (_, _, c) in premises {
            let cl = [c];
            let h = Claim {
                s: Self::eval_term(&rule.head.s, &cl),
                p: rule.head.p.clone(),
                o: Self::eval_term(&rule.head.o, &cl),
                pol: rule.head.pol,
                ctx: c.ctx.clone(),
                t_from: c.t_from,
                t_to: c.t_to,
            };
            if !heads.contains(&h) {
                heads.push(h);
            }
        }
        if heads.len() != 1 {
            return Err(KernelError::new(Code::OrPremisesInconsistent, "alternative premises yield different conclusions; derive them separately")
                .field("premises")
                .expected(json!({"conclusions": heads.iter().map(claim_json).collect::<Vec<_>>()})));
        }
        let expected = self.match_agent_head(&heads, agent)?;
        let mut justs: Vec<(String, Vec<Hash>)> = premises.iter().map(|p| (rule.id.clone(), vec![p.1])).collect();
        justs.sort();
        justs.dedup();
        Ok((expected, justs))
    }

    /// Compare the agent's claimed conclusion with the kernel's computed candidates.
    fn match_agent_head(&self, heads: &[Claim], agent: Option<&Map<String, Value>>) -> KResult<Claim> {
        let a = match agent {
            None => {
                return if heads.len() == 1 {
                    Ok(heads[0].clone())
                } else {
                    Err(KernelError::new(Code::HeadMismatch, "several conclusions are possible; state the claim")
                        .field("claim")
                        .expected(json!({"claims": heads.iter().map(claim_json).collect::<Vec<_>>()})))
                };
            }
            Some(a) => a,
        };
        let pred_name = s_field(a, "p").map_err(|e| e.field("claim.p"))?;
        let pred = self.predicate(pred_name, "claim.p")?.clone();
        let s = self.resolve_subject(&pred, s_field(a, "s").map_err(|e| e.field("claim.s"))?, "claim.s")?;
        let o = self.resolve_object(&pred, s_field(a, "o").map_err(|e| e.field("claim.o"))?, "claim.o")?;
        let pol = Self::pol(a).map_err(|e| e.field("claim.polarity"))?;
        let ctx = s_field(a, "ctx").map_err(|e| e.field("claim.ctx"))?;
        let (tf, tt) = interval(a.get("t"), "claim.t")?;
        let head = heads.iter().find(|h| h.s == s && h.p == pred_name && h.o == o && h.pol == pol);
        let head = match head {
            Some(h) => h,
            None => {
                let e0 = &heads[0];
                return Err(KernelError::new(Code::HeadMismatch, "claim (s,p,o,polarity) differs from what the rule concludes")
                    .field("claim")
                    .expected(json!({"claim": claim_json(e0)}))
                    .obligation(json!({"action": "replace_claim_with_expected_by_kernel"})));
            }
        };
        if ctx != head.ctx {
            return Err(KernelError::new(Code::CtxMismatch, "claim ctx differs from the ctx of the premises")
                .field("claim.ctx")
                .expected(json!({"ctx": head.ctx}))
                .obligation(json!({"action": "replace_claim_ctx_with_expected_by_kernel"})));
        }
        if (tf, tt) != (head.t_from, head.t_to) {
            return Err(KernelError::new(Code::IntervalMismatch, "claim interval is not the intersection of the premise intervals")
                .field("claim.t")
                .expected(json!({"t": [head.t_from, head.t_to]}))
                .obligation(json!({"action": "replace_claim_t_with_expected_by_kernel"})));
        }
        Ok(head.clone())
    }

    // -- revoke_evidence ----------------------------------------------------------------

    fn op_revoke(&mut self, seq: u64, obj: &Map<String, Value>) -> KResult<AppliedLine> {
        let name = s_field(obj, "target_evidence")?;
        let id = self.resolve_local(name, "target_evidence")?;
        match self.engine.kind_of(&id) {
            Some(KIND_EVIDENCE) => {}
            _ => return Err(KernelError::new(Code::NotAnEvidence, format!("'{name}' is not an evidence reference")).field("target_evidence")),
        }
        if self.engine.status_of(&id) == Some(EV_REVOKED) {
            return Err(KernelError::new(Code::AlreadyRevoked, format!("evidence '{name}' is already revoked")).field("target_evidence"));
        }
        self.finish(seq, "revoke_evidence", CanonOp::Revoke { evidence: id })
    }

    pub fn state_root(&mut self) -> Hash {
        self.engine.root()
    }

    pub fn root_hex(&mut self) -> String {
        to_hex(&self.engine.root())
    }
}

fn permute(a: &mut Vec<usize>, k: usize, f: &mut dyn FnMut(&[usize])) {
    if k == a.len() {
        f(a);
        return;
    }
    for i in k..a.len() {
        a.swap(k, i);
        permute(a, k + 1, f);
        a.swap(k, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONTO: &str = r#"{
      "entities":[
        {"id":"svc_auth","type":"Service","aliases":["auth","gateway"]},
        {"id":"svc_pay","type":"Service","aliases":["gateway"]},
        {"id":"api_v1","type":"Api","aliases":["v1"]}],
      "predicates":[
        {"id":"uses_api","subject":"Service","object":"Api"},
        {"id":"api_deprecated","subject":"Api","object":"@literal"},
        {"id":"needs_review","subject":"Service","object":"@literal"}],
      "rules":[{"id":"R_depr_review@1","mode":"AND",
        "body":[{"p":"uses_api"},{"p":"api_deprecated"}],
        "join":[["0.o","1.s"]],
        "head":{"s":"0.s","p":"needs_review","o":{"const":"true"}}}]}"#;

    const DOC: &str = "Policy 1. The auth service calls API v1 in production.\nPolicy 2. API v1 is deprecated since 2024.\nPolicy 3. The beta flag is on.\nThe beta flag is on.\n";

    fn session() -> Session {
        let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), CdcParams::default());
        s.put_document("policy", DOC.as_bytes());
        s
    }

    fn run(s: &mut Session, line: &str) -> KResult<AppliedLine> {
        s.apply_line(line)
    }

    fn happy(s: &mut Session) {
        run(s, r#"{"seq":1,"op":"bind_evidence","local_id":"e1","doc_id":"policy","exact_quote":"The auth service calls API v1 in production."}"#).unwrap();
        run(s, r#"{"seq":2,"op":"bind_evidence","local_id":"e2","doc_id":"policy","exact_quote":"API v1 is deprecated since 2024."}"#).unwrap();
        run(
            s,
            r#"{"seq":3,"op":"assert_fact","local_id":"f1","s":"auth","p":"uses_api","o":"v1","polarity":"POS","ctx":"prod","t":[100,200],"evidence":["e1"]}"#,
        )
        .unwrap();
        run(s, r#"{"seq":4,"op":"assert_fact","local_id":"f2","s":"api_v1","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["e2"]}"#).unwrap();
    }

    #[test]
    fn evidence_over_255_chunks_is_refused_and_containers_stay_readable() {
        // one-byte chunks: a quote of n bytes spans n segments, and the node encoding counts segments in one byte
        let cdc = CdcParams { mode: crate::cdc::CdcMode::FastCdc, min: 1, avg: 1, max: 1 };
        let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), cdc);
        let doc = format!("y{}x", "z".repeat(255));
        s.put_document("d", doc.as_bytes());
        let line = |seq: u64, id: &str, q: &str| json!({"seq": seq, "op": "bind_evidence", "local_id": id, "doc_id": "d", "exact_quote": q}).to_string();
        let e = s.apply_line(&line(1, "e1", &doc[..256])).unwrap_err();
        assert_eq!(e.code, Code::QuoteTooFragmented, "{}", e.to_json());
        s.apply_line(&line(1, "e1", &doc[..255])).unwrap();
        let c = crate::container::build_container(&mut s);
        let mut back = crate::container::open_session(&c).expect("a container with a 255-segment evidence opens");
        assert_eq!(back.engine.root(), s.engine.root());
    }

    #[test]
    fn full_flow_and_revocation() {
        let mut s = session();
        happy(&mut s);
        let a = run(&mut s, r#"{"seq":5,"op":"derive","local_id":"d1","rule":"R_depr_review@1","premises":["f2","f1"],"claim":{"s":"svc_auth","p":"needs_review","o":"true","polarity":"POS","ctx":"prod","t":[150,200]}}"#).unwrap();
        assert_eq!(a.claim_status, Some(ST_SUPPORTED));
        let r = run(&mut s, r#"{"seq":6,"op":"revoke_evidence","target_evidence":"e2"}"#).unwrap();
        assert_eq!(r.dred.unwrap().net_removed, 2);
        assert!(s.engine.oracle_check());
    }

    #[test]
    fn fail_fast_returns_kernel_computed_value_and_keeps_prefix() {
        let mut s = session();
        happy(&mut s);
        let e = run(&mut s, r#"{"seq":5,"op":"derive","local_id":"d1","rule":"R_depr_review@1","premises":["f1","f2"],"claim":{"s":"svc_auth","p":"needs_review","o":"true","polarity":"POS","ctx":"prod","t":[100,300]}}"#).unwrap_err();
        assert_eq!(e.code, Code::IntervalMismatch);
        assert_eq!(e.seq, Some(5));
        assert_eq!(e.expected_by_kernel["t"], json!([150, 200]));
        let n = s.engine.node_count();
        // the prefix survives; only seq 5 is re-sent with the kernel's value
        let ok = run(&mut s, r#"{"seq":5,"op":"derive","local_id":"d1","rule":"R_depr_review@1","premises":["f1","f2"],"claim":{"s":"svc_auth","p":"needs_review","o":"true","polarity":"POS","ctx":"prod","t":[150,200]}}"#).unwrap();
        assert_eq!(ok.seq, 5);
        assert!(s.engine.node_count() > n);
    }

    #[test]
    fn quote_errors() {
        let mut s = session();
        let nf =
            run(&mut s, r#"{"seq":1,"op":"bind_evidence","local_id":"e1","doc_id":"policy","exact_quote":"The auth service calls API v2 in production."}"#)
                .unwrap_err();
        assert_eq!(nf.code, Code::QuoteNotFoundInBytes);
        let cands = nf.expected_by_kernel["candidates"].as_array().unwrap();
        assert_eq!(cands[0]["exact_quote"], "The auth service calls API v1 in production.");
        let amb = run(&mut s, r#"{"seq":1,"op":"bind_evidence","local_id":"e1","doc_id":"policy","exact_quote":"The beta flag is on."}"#).unwrap_err();
        assert_eq!(amb.code, Code::AmbiguousQuoteSpan);
        let ext = amb.expected_by_kernel["unique_extensions"].as_array().unwrap();
        assert!(!ext.is_empty());
        // resubmitting a unique extension succeeds
        let q = ext[0].as_str().unwrap();
        let line = json!({"seq":1,"op":"bind_evidence","local_id":"e1","doc_id":"policy","exact_quote":q}).to_string();
        run(&mut s, &line).unwrap();
    }

    #[test]
    fn allowed_values_refuse_a_wrong_literal_and_name_the_allowed_ones() {
        let assert_o = |o: &str| {
            format!(
                r#"{{"seq":3,"op":"assert_fact","local_id":"f2","s":"api_v1","p":"api_deprecated","o":"{o}","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["e2"]}}"#
            )
        };
        let bind = r#"{"seq":2,"op":"bind_evidence","local_id":"e2","doc_id":"policy","exact_quote":"API v1 is deprecated since 2024."}"#;
        // without the field the literal is free, as before
        let mut s = session();
        run(&mut s, &bind.replace(r#""seq":2"#, r#""seq":1"#)).unwrap();
        run(&mut s, &assert_o("api_v1").replace(r#""seq":3"#, r#""seq":2"#)).unwrap();
        // with it, the kernel refuses the API id as the object and names the allowed values
        let onto = ONTO.replace(r#""object":"@literal"},"#, r#""object":"@literal","allowed_values":["true"]},"#);
        assert_ne!(onto, ONTO);
        let mut s = Session::new(Ontology::from_json_str(&onto).unwrap(), CdcParams::default());
        s.put_document("policy", DOC.as_bytes());
        run(&mut s, &bind.replace(r#""seq":2"#, r#""seq":1"#)).unwrap();
        let e = run(&mut s, &assert_o("api_v1").replace(r#""seq":3"#, r#""seq":2"#)).unwrap_err();
        assert_eq!((e.code, e.field.as_deref()), (Code::LiteralNotAllowed, Some("o")));
        assert_eq!(e.expected_by_kernel, json!({"predicate": "api_deprecated", "allowed_values": ["true"]}));
        assert_eq!(e.obligation["choose_one_of"], "expected_by_kernel.allowed_values");
        run(&mut s, &assert_o("true").replace(r#""seq":3"#, r#""seq":2"#)).unwrap();
    }

    #[test]
    fn ambiguous_alias_and_type_errors() {
        let mut s = session();
        happy(&mut s);
        let e = run(
            &mut s,
            r#"{"seq":5,"op":"assert_fact","local_id":"f3","s":"gateway","p":"uses_api","o":"v1","polarity":"POS","ctx":"prod","t":[1,2],"evidence":["e1"]}"#,
        )
        .unwrap_err();
        assert_eq!(e.code, Code::AmbiguousEntity);
        assert_eq!(e.expected_by_kernel["candidates"], json!(["svc_auth", "svc_pay"]));
        let e = run(
            &mut s,
            r#"{"seq":5,"op":"assert_fact","local_id":"f3","s":"api_v1","p":"uses_api","o":"v1","polarity":"POS","ctx":"prod","t":[1,2],"evidence":["e1"]}"#,
        )
        .unwrap_err();
        assert_eq!(e.code, Code::TypeMismatch);
    }

    #[test]
    fn unsupported_premise_has_candidates() {
        let mut s = session();
        happy(&mut s);
        run(&mut s, r#"{"seq":5,"op":"revoke_evidence","target_evidence":"e2"}"#).unwrap();
        let e = run(&mut s, r#"{"seq":6,"op":"derive","local_id":"d1","rule":"R_depr_review@1","premises":["f1","f2"]}"#).unwrap_err();
        assert_eq!(e.code, Code::PremiseUnsupported);
    }

    #[test]
    fn repeated_steps_are_reported_as_existing_whatever_their_names() {
        let mut s = session();
        let a = run(&mut s, r#"{"seq":1,"op":"bind_evidence","local_id":"e1","doc_id":"policy","exact_quote":"The auth service calls API v1 in production."}"#)
            .unwrap();
        assert_eq!(a.existed, Some(false));
        let b = run(
            &mut s,
            r#"{"seq":2,"op":"bind_evidence","local_id":"other_name","doc_id":"policy","exact_quote":"The auth service calls API v1 in production."}"#,
        )
        .unwrap();
        assert_eq!(b.existed, Some(true), "same quote under another name is the same evidence node");
        let f1 = run(
            &mut s,
            r#"{"seq":3,"op":"assert_fact","local_id":"f1","s":"auth","p":"uses_api","o":"v1","polarity":"POS","ctx":"prod","t":[100,200],"evidence":["e1"]}"#,
        )
        .unwrap();
        assert_eq!(f1.existed, Some(false));
        let f2 = run(&mut s, r#"{"seq":4,"op":"assert_fact","local_id":"f_again","s":"svc_auth","p":"uses_api","o":"api_v1","polarity":"POS","ctx":"prod","t":[100,200],"evidence":["other_name"]}"#).unwrap();
        assert_eq!(f2.existed, Some(true), "aliases and local names do not hide a repeated step");
        assert_eq!(f2.to_json()["existed"], true);
    }

    #[test]
    fn oversize_inputs_are_rejected_not_truncated() {
        let mut s = session();
        happy(&mut s);
        let long = "x".repeat(MAX_STR + 1);
        let line = json!({"seq":5,"op":"assert_fact","local_id":"g","s":"svc_auth","p":"needs_review","o":long,"polarity":"POS","ctx":"prod","t":[1,2],"evidence":["e1"]}).to_string();
        assert_eq!(run(&mut s, &line).unwrap_err().code, Code::BadField);
        let many: Vec<String> = (0..MAX_REFS + 1).map(|_| "e1".to_string()).collect();
        let line = json!({"seq":5,"op":"assert_fact","local_id":"g","s":"svc_auth","p":"needs_review","o":"true","polarity":"POS","ctx":"prod","t":[1,2],"evidence":many}).to_string();
        assert_eq!(run(&mut s, &line).unwrap_err().code, Code::BadField);
        let q = "a".repeat(MAX_QUOTE + 1);
        let line = json!({"seq":5,"op":"bind_evidence","local_id":"h","doc_id":"policy","exact_quote":q}).to_string();
        assert_eq!(run(&mut s, &line).unwrap_err().code, Code::BadField);
        // a rejected line leaves the sequence open for the corrected one
        assert_eq!(s.last_seq, 4);
    }

    #[test]
    fn local_names_do_not_affect_node_ids() {
        let mut a = session();
        happy(&mut a);
        let mut b = session();
        run(&mut b, r#"{"seq":1,"op":"bind_evidence","local_id":"zz","doc_id":"policy","exact_quote":"API v1 is deprecated since 2024."}"#).unwrap();
        run(&mut b, r#"{"seq":2,"op":"bind_evidence","local_id":"yy","doc_id":"policy","exact_quote":"The auth service calls API v1 in production."}"#)
            .unwrap();
        run(&mut b, r#"{"seq":3,"op":"assert_fact","local_id":"q","s":"api_v1","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["zz"]}"#).unwrap();
        run(&mut b, r#"{ "seq" : 4, "op":"assert_fact", "evidence":["yy"], "t":[100,200], "ctx":"prod","polarity":"POS","o":"api_v1","p":"uses_api","s":"svc_auth","local_id":"r"}"#).unwrap();
        assert_eq!(a.state_root(), b.state_root());
    }

    #[test]
    fn document_update_rebinds_only_stale_evidence() {
        let mut s = session();
        happy(&mut s);
        run(&mut s, r#"{"seq":5,"op":"derive","local_id":"d1","rule":"R_depr_review@1","premises":["f1","f2"],"claim":{"s":"svc_auth","p":"needs_review","o":"true","polarity":"POS","ctx":"prod","t":[150,200]}}"#).unwrap();
        let mut new_doc = String::from("PREAMBLE ADDED LATER.\n");
        new_doc.push_str(DOC);
        let rep = s.put_document("policy", new_doc.as_bytes());
        assert!(s.engine.oracle_check());
        // the document is tiny (one chunk), so the chunk changed: both quotes are re-bound
        assert_eq!(rep.evidence_stale, rep.rebound_ok + rep.rebind_failed);
        assert_eq!(s.engine.status_counts().0, 3, "all three claims are supported again after re-binding");
    }
}
