//! A small in-memory `AuditStore` for the tests of `builder` and `directives` (no journal, no byte anchors: quotes are matched
//! as substrings). The kernel implementation is `state::AuditState`.

use super::*;
use crate::error::Code;
use crate::hash::{from_hex, sha256_parts, to_hex};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct MemStore {
    pub docs: Vec<(String, String)>,
    pub types: Vec<String>,
    pub records: Vec<RecordView>,
    pub concepts: Vec<ConceptView>,
    pub mapped: BTreeMap<RecordId, Vec<ConceptId>>,
    pub links: Vec<LinkView>,
    /// submission id -> (request, result): an exact retry returns the stored result, another request under the id is refused
    pub receipts: BTreeMap<String, (Value, Value)>,
    pub checkpoints: BTreeMap<String, Value>,
    /// (agent, directive, local id) -> record, over every submission of a directive, as the kernel store keeps them (a later
    /// submission of a task may rest on a line an earlier one stored)
    pub locals: BTreeMap<(String, String, String), RecordId>,
}

fn err(msg: &str) -> KernelError {
    KernelError::new(Code::BadField, msg.to_string())
}

pub(crate) fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

impl MemStore {
    pub fn new(docs: &[(&str, &str)], types: &[&str]) -> MemStore {
        MemStore {
            docs: docs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            types: types.iter().map(|t| t.to_string()).collect(),
            ..Default::default()
        }
    }

    fn resolve(&self, r: &str, local: &BTreeMap<String, RecordId>) -> Option<RecordId> {
        local.get(r).copied().or_else(|| self.records.iter().find(|x| x.id.short() == r).map(|x| x.id))
    }

    fn line(&self, agent: &str, scope: &Scope, v: &Value, local: &BTreeMap<String, RecordId>) -> Result<RecordView, KernelError> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let list = |k: &str| v.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        let kind = s("kind").and_then(|k| RecordKind::parse(&k)).ok_or_else(|| err("unknown kind"))?;
        let mut based_on = Vec::new();
        for b in list("based_on") as Vec<String> {
            based_on.push(self.resolve(&b, local).ok_or_else(|| err("unknown based_on"))?);
        }
        let mut terms: Vec<String> = list("terms");
        for k in ["subject", "object"] {
            terms.extend(s(k));
        }
        terms.extend(list("about") as Vec<String>);
        let (mut doc_id, mut quote, mut ends) = (None, None, None);
        match kind {
            RecordKind::Observe => {
                let d = s("doc_id").ok_or_else(|| err("observe needs doc_id"))?;
                let q = s("exact_quote").ok_or_else(|| err("observe needs exact_quote"))?;
                if !scope.docs.contains(&d) {
                    return Err(err("document outside the directive"));
                }
                let text = &self.docs.iter().find(|x| x.0 == d).ok_or_else(|| err("unknown doc"))?.1;
                let at = text.find(&q).ok_or_else(|| err("quote not found"))?;
                let inside = scope.ranges.iter().filter(|r| r.0 == d).all(|r| at >= r.1 && at + q.len() <= r.2);
                if !inside {
                    return Err(err("quote outside the directive's section"));
                }
                doc_id = Some(d);
                quote = Some(q);
            }
            RecordKind::Claim | RecordKind::Hypothesis | RecordKind::Relation if based_on.is_empty() => return Err(err("based_on required")),
            RecordKind::Relation => {
                let f = self.resolve(&s("from").unwrap_or_default(), local).ok_or_else(|| err("unknown from"))?;
                let t = self.resolve(&s("to").unwrap_or_default(), local).ok_or_else(|| err("unknown to"))?;
                ends = Some((f, s("rel").unwrap_or_default(), t));
            }
            _ => {}
        }
        let seq = self.records.len() as u64 + 1;
        let id = RecordId(sha256_parts(&[v.to_string().as_bytes(), agent.as_bytes(), &seq.to_le_bytes()]));
        Ok(RecordView {
            id,
            seq,
            kind,
            author: agent.to_string(),
            directive: String::new(),
            doc_id,
            quote,
            terms,
            text: s("text"),
            status: s("stance"),
            based_on,
            ends,
            body: v.clone(),
        })
    }
}

impl MemStore {
    fn op(&mut self, actor: &str, op: &Value) -> Result<Value, KernelError> {
        let s = |k: &str| op.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let ids = |k: &str| -> Vec<RecordId> {
            op.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().and_then(from_hex)).map(RecordId).collect()).unwrap_or_default()
        };
        let rid = |k: &str| from_hex(&s(k)).map(RecordId).ok_or_else(|| err("bad record id"));
        match s("kind").as_str() {
            "propose_concept" => {
                let aliases: Vec<String> =
                    op.get("aliases").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let c = self.propose_concept(actor, &s("type"), &s("name"), &aliases, &ids("basis"))?;
                // the first proposal that names a function places the concept, as in the kernel store
                let function = op.get("function").and_then(Value::as_str).map(|f| f.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase());
                let stored = self.concepts.iter_mut().find(|x| x.id == c.id).expect("proposed concept");
                if stored.function.is_none() {
                    stored.function = function;
                }
                let mut out = json!({"id": to_hex(&c.id.0), "status": c.status});
                if let Some(f) = &stored.function {
                    out["function"] = json!(f);
                }
                Ok(out)
            }
            "map_term" => {
                let c = from_hex(&s("concept")).map(ConceptId).ok_or_else(|| err("bad concept id"))?;
                self.map_term(actor, &rid("record")?, &s("term"), &c)?;
                Ok(json!({"status": "proposed"}))
            }
            "add_link" => {
                let l = self.add_link(actor, &rid("from")?, &s("rel"), &rid("to")?, &ids("basis"))?;
                Ok(json!({"id": to_hex(&l.id.0), "status": l.status.name()}))
            }
            "set_link_status" => {
                let id = from_hex(&s("link")).map(LinkId).ok_or_else(|| err("bad link id"))?;
                let st = match s("status").as_str() {
                    "accepted" => LinkStatus::Accepted,
                    "rejected" => LinkStatus::Rejected,
                    _ => LinkStatus::Proposed,
                };
                let cur = self.link(&id).ok_or_else(|| err("unknown link"))?.status;
                if op.get("expected_status").and_then(|x| x.as_str()).is_some_and(|e| e != cur.name()) {
                    return Err(err("link status changed since the task was issued"));
                }
                self.set_link_status(&id, st, actor, &ids("basis"))?;
                Ok(json!({"id": s("link"), "status": st.name()}))
            }
            _ => Err(err("unknown operation")),
        }
    }
}

impl AuditStore for MemStore {
    fn docs(&self) -> Vec<String> {
        self.docs.iter().map(|d| d.0.clone()).collect()
    }
    fn doc_text(&self, doc_id: &str) -> Option<String> {
        self.docs.iter().find(|d| d.0 == doc_id).map(|d| d.1.clone())
    }
    fn submit_records(&mut self, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        let mut rep = SubmitReport::default();
        let mut local: BTreeMap<String, RecordId> =
            self.locals.iter().filter(|((a, d, _), _)| a == agent && d == directive).map(|((_, _, n), id)| (n.clone(), *id)).collect();
        for (i, v) in lines.iter().enumerate() {
            match self.line(agent, scope, v, &local) {
                Ok(mut r) => {
                    r.directive = directive.to_string();
                    if let Some(l) = v.get("local_id").and_then(|x| x.as_str()) {
                        local.insert(l.to_string(), r.id);
                        self.locals.insert((agent.to_string(), directive.to_string(), l.to_string()), r.id);
                    }
                    rep.accepted.push(r.id);
                    self.records.push(r);
                }
                Err(e) => {
                    rep.failed_index = Some(i);
                    rep.error = Some(e);
                    break;
                }
            }
        }
        rep
    }
    fn records_since(&self, cursor: u64) -> Vec<RecordView> {
        self.records.iter().filter(|r| r.seq > cursor).cloned().collect()
    }
    fn local_record(&self, agent: &str, directive: &str, local_id: &str) -> Option<RecordId> {
        self.locals.get(&(agent.to_string(), directive.to_string(), local_id.to_string())).copied()
    }
    fn record(&self, id: &RecordId) -> Option<RecordView> {
        self.records.iter().find(|r| r.id == *id).cloned()
    }
    fn head(&self) -> u64 {
        self.records.len() as u64
    }
    fn ontology_version(&self) -> (u64, Hash) {
        (self.concepts.len() as u64, [0; 32])
    }
    fn concept_types(&self) -> Vec<String> {
        self.types.clone()
    }
    fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView> {
        let t = norm(term);
        self.concepts.iter().filter(|c| norm(&c.name) == t || c.aliases.iter().any(|a| norm(a) == t)).take(limit).cloned().collect()
    }
    fn concept(&self, id: &ConceptId) -> Option<ConceptView> {
        self.concepts.iter().find(|c| c.id == *id).cloned()
    }
    fn propose_concept(&mut self, _by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> Result<ConceptView, KernelError> {
        if !self.types.iter().any(|t| t == ty) {
            return Err(err("unknown concept type"));
        }
        if let Some(c) = self.concepts.iter().find(|c| c.ty == ty && norm(&c.name) == norm(name) && c.aliases == aliases) {
            return Ok(c.clone()); // the same definition again: idempotent, as in the kernel store
        }
        if basis.is_empty() || !self.candidates(name, 1).is_empty() {
            return Err(err("no basis or name clash"));
        }
        let c = ConceptView {
            id: ConceptId(sha256_parts(&[ty.as_bytes(), norm(name).as_bytes()])),
            ty: ty.to_string(),
            name: name.to_string(),
            aliases: aliases.to_vec(),
            status: "accepted".into(),
            function: None,
        };
        self.concepts.push(c.clone());
        Ok(c)
    }
    fn map_term(&mut self, _by: &str, rec: &RecordId, _term: &str, concept: &ConceptId) -> Result<(), KernelError> {
        let m = self.mapped.entry(*rec).or_default();
        if !m.contains(concept) {
            m.push(*concept);
        }
        Ok(())
    }
    fn concepts(&self) -> Vec<ConceptView> {
        self.concepts.clone()
    }
    fn concepts_of(&self, rec: &RecordId) -> Vec<ConceptId> {
        self.mapped.get(rec).cloned().unwrap_or_default()
    }
    fn records_of(&self, concept: &ConceptId) -> Vec<RecordId> {
        self.mapped.iter().filter(|(_, c)| c.contains(concept)).map(|(r, _)| *r).collect()
    }
    fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> Result<LinkView, KernelError> {
        let id = LinkId(sha256_parts(&[&from.0, rel.as_bytes(), &to.0]));
        if let Some(l) = self.link(&id) {
            return Ok(l);
        }
        if rel == "supersedes" && self.links.iter().any(|l| l.rel == "supersedes" && l.status != LinkStatus::Rejected && l.from == *to && l.to == *from) {
            return Err(err("supersedes would form a cycle"));
        }
        let l = LinkView { id, from: *from, rel: rel.to_string(), to: *to, status: LinkStatus::Proposed, by: by.to_string(), basis: basis.to_vec() };
        self.links.push(l.clone());
        Ok(l)
    }
    fn set_link_status(&mut self, id: &LinkId, status: LinkStatus, _by: &str, _basis: &[RecordId]) -> Result<(), KernelError> {
        let l = self.links.iter_mut().find(|l| l.id == *id).ok_or_else(|| err("unknown link"))?;
        l.status = status;
        Ok(())
    }
    fn link(&self, id: &LinkId) -> Option<LinkView> {
        self.links.iter().find(|l| l.id == *id).cloned()
    }
    fn links(&self) -> Vec<LinkView> {
        self.links.clone()
    }
    fn links_of(&self, rec: &RecordId) -> Vec<LinkView> {
        self.links.iter().filter(|l| l.from == *rec || l.to == *rec).cloned().collect()
    }
    fn root(&self) -> Hash {
        [0; 32]
    }
    fn submit_operations_id(&mut self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Result<Value, KernelError> {
        let request = json!([actor, operations, checkpoint]);
        if let Some((req, res)) = self.receipts.get(id) {
            return if *req == request { Ok(res.clone()) } else { Err(err("submission id reused with other content")) };
        }
        let (mut results, mut error, mut failed) = (Vec::new(), Value::Null, Value::Null);
        for (i, op) in operations.iter().enumerate() {
            match self.op(actor, op) {
                Ok(v) => results.push(v),
                Err(e) => {
                    error = e.to_json();
                    failed = json!(i);
                    break;
                }
            }
        }
        let mut checkpointed = false;
        if let (true, Some(c)) = (error.is_null(), checkpoint) {
            let key = c["key"].as_str().unwrap_or("").to_string();
            let old = self.checkpoints.get(&key).and_then(|x| x["to"].as_u64()).unwrap_or(0);
            if c["from"].as_u64() == Some(old) && c["to"].as_u64().is_some_and(|t| t >= old && t <= self.head()) {
                self.checkpoints.insert(key, c);
                checkpointed = true;
            } else {
                error = err("checkpoint must extend the current cursor").to_json();
                failed = json!(operations.len());
            }
        }
        let res = json!({"accepted_operations": results.len(), "results": results, "failed_index": failed, "error": error, "checkpointed": checkpointed});
        self.receipts.insert(id.to_string(), (request, res.clone()));
        Ok(res)
    }
    fn checkpoint(&self, key: &str) -> Option<Value> {
        self.checkpoints.get(key).cloned()
    }
    fn receipt_outcome(&self, id: &str, actor: &str) -> Option<Value> {
        self.receipts.get(id).filter(|(req, _)| req[0] == actor).map(|(_, res)| res.clone())
    }
    fn operations_receipt(&self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Prior {
        match self.receipts.get(id) {
            None => Prior::Free,
            Some((req, res)) if *req == json!([actor, operations, checkpoint]) => Prior::Same(Ok(res.clone())),
            Some(_) => Prior::Other,
        }
    }
}
