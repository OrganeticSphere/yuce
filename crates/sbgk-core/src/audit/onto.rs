//! The audit ontology is independent of the engine's immutable genesis ontology.
//!
//! Genesis declarations are strictly validated and normalized before hashing. Runtime proposals introduce only concepts of
//! known types, initially provisional. Definitions and ids never change; names stay reserved after retirement. The caller
//! validates basis records and authorization. This module validates immutable definitions and lifecycle, and keeps provenance.
//! Kernel end-attestation is a reversible suspension; narrowed/retired names remain reserved.
//! Replay starts from `base` and reapplies commands; `to_value` is a commitment snapshot, not a restore protocol.

use super::{ConceptId, ConceptView, RecordId};
use crate::error::{Code, KResult, KernelError};
use crate::hash::{sha256_parts, to_hex, Hash};
use crate::jcs::to_jcs;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const BASE_FORMAT: &str = "r2r-audit-ontology/1";
const STATE_FORMAT: &str = "r2r-audit-ontology-state/1";
const MAX_TYPES: usize = 256;
const MAX_RELATIONS: usize = 128;
const MAX_STANCES: usize = 32;
const MAX_CONCEPTS: usize = 100_000;
const MAX_ALIASES: usize = 32;
const MAX_BASIS: usize = 256;
const MAX_NAME_BYTES: usize = 120;
const MAX_ACTOR_BYTES: usize = 1024;
/// A function is the name of a broad part of the system ("authorization", "streamable http transport"), not a statement.
const MAX_FUNCTION_BYTES: usize = 60;
const MAX_FUNCTION_WORDS: usize = 5;
/// Words that name everything: a function made only of them is refused (Fable 5.1's consultation of 01.11: such functions draw
/// every concept a builder is unsure of).
const CATCHALL_FUNCTION_WORDS: [&str; 15] = [
    "general",
    "misc",
    "miscellaneous",
    "other",
    "others",
    "core",
    "protocol",
    "spec",
    "specification",
    "system",
    "overview",
    "generic",
    "common",
    "basic",
    "basics",
];

fn bad(field: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field(field)
}

fn object<'a>(v: &'a Value, field: &str, keys: &[&str]) -> KResult<&'a Map<String, Value>> {
    let m = v.as_object().ok_or_else(|| bad(field, "expected an object"))?;
    if let Some(k) = m.keys().find(|k| !keys.contains(&k.as_str())) {
        return Err(bad(field, format!("unknown field '{k}'")));
    }
    Ok(m)
}

fn string<'a>(m: &'a Map<String, Value>, key: &str) -> KResult<&'a str> {
    m.get(key).and_then(Value::as_str).ok_or_else(|| bad(key, "expected a string"))
}

fn array<'a>(m: &'a Map<String, Value>, key: &str, max: usize) -> KResult<&'a [Value]> {
    let a = m.get(key).and_then(Value::as_array).ok_or_else(|| bad(key, "expected an array"))?;
    if a.len() > max {
        return Err(bad(key, format!("at most {max} entries are allowed")));
    }
    Ok(a)
}

fn identifier(s: &str, field: &str) -> KResult<String> {
    let mut b = s.bytes();
    if s.len() > 64 || !b.next().is_some_and(|c| c.is_ascii_alphabetic()) || !b.all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err(bad(field, "expected an ASCII identifier of at most 64 bytes"));
    }
    Ok(s.to_string())
}

fn identifiers(m: &Map<String, Value>, key: &str, max: usize, nonempty: bool) -> KResult<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for v in array(m, key, max)? {
        let s = identifier(v.as_str().ok_or_else(|| bad(key, "all entries must be strings"))?, key)?;
        if !out.insert(s) {
            return Err(bad(key, "duplicate identifier"));
        }
    }
    if nonempty && out.is_empty() {
        return Err(bad(key, "at least one entry is required"));
    }
    Ok(out)
}

fn normalized_name(s: &str, field: &str) -> KResult<String> {
    let n = s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    if n.is_empty() || n.len() > MAX_NAME_BYTES || n.chars().any(char::is_control) {
        return Err(bad(field, format!("normalized names must contain 1..{MAX_NAME_BYTES} UTF-8 bytes, without control characters")));
    }
    Ok(n)
}

/// Singular words that end in -s and take -es in the plural (claude-reviewer's RV-03 of 376d8d14: an -es rule after -us or -as broke
/// "cases" and "releases"; the few such words a function's name meets are listed instead).
const S_SINGULARS: [&str; 15] =
    ["alias", "atlas", "bias", "bonus", "bus", "campus", "canvas", "census", "corpus", "focus", "gas", "lens", "radius", "status", "virus"];
/// Words in -che whose plural is a plain -s ("caches" is "cache", not "cach").
const CHE_SINGULARS: [&str; 3] = ["cache", "cliche", "niche"];

/// The singular of an English plural, for one word (claude-reviewer's RV-02 and RV-03): -ies after a consonant to -y; -es dropped
/// after ch, sh, x and ss, and after a listed singular in -s; else one -s dropped, except after ss, us, is and as. "cookies" still
/// gives "cooky" and "quizzes" "quizze": rare in a function's name.
fn singular(w: &str) -> String {
    let l = w.len();
    let consonant_before = |n: usize| w.as_bytes().get(l.wrapping_sub(n + 1)).is_some_and(|c| c.is_ascii_alphabetic() && !b"aeiou".contains(c));
    let stem = w.get(..l.saturating_sub(2)).unwrap_or("");
    if l > 4 && w.ends_with("ies") && consonant_before(3) {
        format!("{}y", &w[..l - 3])
    } else if l > 4 && w.ends_with("es") && CHE_SINGULARS.iter().any(|x| x.strip_suffix('e') == Some(stem)) {
        w[..l - 1].to_string()
    } else if l > 4 && w.ends_with("es") && (["ch", "sh", "x", "ss"].iter().any(|e| stem.ends_with(e)) || S_SINGULARS.contains(&stem)) {
        stem.to_string()
    } else if l > 3 && w.ends_with('s') && !["ss", "us", "is", "as"].iter().any(|e| w.ends_with(e)) {
        w[..l - 1].to_string()
    } else {
        w.to_string()
    }
}

/// One name for one function: the normalized name without a leading article, its last word in the singular ("the transports" and
/// "transport" are one function), at most 5 words and 60 bytes, and not a catch-all.
fn function_name(s: &str) -> KResult<String> {
    let n = normalized_name(s, "function")?;
    let mut words = n.split(' ').collect::<Vec<_>>();
    if words.len() > 1 && matches!(words[0], "the" | "a" | "an") {
        words.remove(0);
    }
    let last = words.pop().unwrap_or("");
    let singular = singular(last);
    // a catch-all in either form ("basics" and "basic")
    if words.iter().all(|w| CATCHALL_FUNCTION_WORDS.contains(w))
        && (CATCHALL_FUNCTION_WORDS.contains(&last) || CATCHALL_FUNCTION_WORDS.contains(&singular.as_str()))
    {
        return Err(bad("function", "a function names one part of the system, not everything: use a known function or leave it out"));
    }
    words.push(&singular);
    if words.iter().all(|w| CATCHALL_FUNCTION_WORDS.contains(w)) {
        return Err(bad("function", "a function names one part of the system, not everything: use a known function or leave it out"));
    }
    let f = words.join(" ");
    if f.len() > MAX_FUNCTION_BYTES || words.len() > MAX_FUNCTION_WORDS {
        return Err(bad("function", format!("a function is a short name: at most {MAX_FUNCTION_WORDS} words and {MAX_FUNCTION_BYTES} bytes")));
    }
    Ok(f)
}

fn actor(by: &str) -> KResult<()> {
    if by.trim().is_empty() || by.len() > MAX_ACTOR_BYTES || by.chars().any(char::is_control) {
        return Err(bad("by", "a nonempty actor id of at most 1024 bytes is required"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Definition {
    ty: String,
    name: String,
    aliases: Vec<String>,
}

impl Definition {
    fn new(ty: &str, name: &str, aliases: &[String], types: &BTreeSet<String>) -> KResult<Self> {
        if !types.contains(ty) {
            return Err(KernelError::new(Code::TypeMismatch, format!("unknown audit concept type '{ty}'")).field("type").expected(json!({"types": types})));
        }
        if aliases.len() > MAX_ALIASES {
            return Err(bad("aliases", format!("at most {MAX_ALIASES} aliases are allowed")));
        }
        let name = normalized_name(name, "name")?;
        let mut normalized = BTreeSet::new();
        for alias in aliases {
            let a = normalized_name(alias, "aliases")?;
            if a != name {
                normalized.insert(a);
            }
        }
        Ok(Self { ty: ty.to_string(), name, aliases: normalized.into_iter().collect() })
    }

    fn from_value(v: &Value, types: &BTreeSet<String>) -> KResult<Self> {
        let m = object(v, "concepts", &["type", "name", "aliases"])?;
        let mut aliases = Vec::new();
        if m.contains_key("aliases") {
            for a in array(m, "aliases", MAX_ALIASES)? {
                aliases.push(a.as_str().ok_or_else(|| bad("aliases", "all aliases must be strings"))?.to_string());
            }
        }
        Self::new(string(m, "type")?, string(m, "name")?, &aliases, types)
    }

    fn names(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.name).chain(&self.aliases)
    }

    fn to_value(&self) -> Value {
        json!({"type": self.ty, "name": self.name, "aliases": self.aliases})
    }

    fn id(&self, base_hash: &Hash) -> ConceptId {
        ConceptId(sha256_parts(&[b"R2R-AUDIT-CONCEPT/1\0", base_hash, to_jcs(&self.to_value()).as_bytes()]))
    }
}

#[derive(Debug, Clone)]
struct StatusChange {
    revision: u64,
    status: String,
    by: String,
}

#[derive(Debug, Clone)]
struct Concept {
    id: ConceptId,
    definition: Definition,
    proposed_by: String,
    basis: Vec<RecordId>,
    status: String,
    history: Vec<StatusChange>,
    removed_aliases: BTreeSet<String>,
    replacement: Option<ConceptId>,
    narrowed_into: Vec<ConceptId>,
    unattested_prior: Option<String>,
    attestation_reason: Option<Value>,
    function: Option<String>,
}

impl Concept {
    fn view(&self) -> ConceptView {
        ConceptView {
            id: self.id,
            ty: self.definition.ty.clone(),
            name: self.definition.name.clone(),
            aliases: self.definition.aliases.iter().filter(|a| !self.removed_aliases.contains(*a)).cloned().collect(),
            status: self.status.clone(),
            function: self.function.clone(),
        }
    }

    fn to_value(&self) -> Value {
        let mut v = json!({"id": to_hex(&self.id.0), "definition": self.definition.to_value(), "proposed_by": self.proposed_by,
            "basis": self.basis.iter().map(|b| to_hex(&b.0)).collect::<Vec<_>>(), "status": self.status,
            "history": self.history.iter().map(|h| json!({"revision": h.revision, "status": h.status, "by": h.by})).collect::<Vec<_>>()});
        if !self.removed_aliases.is_empty() {
            v["removed_aliases"] = json!(self.removed_aliases);
        }
        if let Some(id) = self.replacement {
            v["replaced_by"] = json!(to_hex(&id.0));
        }
        if !self.narrowed_into.is_empty() {
            v["narrowed_into"] = json!(self.narrowed_into.iter().map(|id| to_hex(&id.0)).collect::<Vec<_>>());
        }
        if let Some(prior) = &self.unattested_prior {
            v["unattested_prior"] = json!(prior);
        }
        if let Some(reason) = &self.attestation_reason {
            v["attestation_reason"] = reason.clone();
        }
        // only when set: a state without functions keeps its bytes, so older journals replay to the same roots
        if let Some(function) = &self.function {
            v["function"] = json!(function);
        }
        v
    }
}

/// An additive audit ontology. `set_status` is an internal operation; its caller enforces the admin role.
#[derive(Debug, Clone)]
pub struct AuditOntology {
    base: Value,
    base_hash: Hash,
    revision: u64,
    types: BTreeSet<String>,
    concepts: BTreeMap<ConceptId, Concept>,
    reserved: BTreeMap<String, ConceptId>,
}

impl AuditOntology {
    /// Built-in schema only; no corpus findings, revisions, or seed concepts are embedded.
    pub fn base() -> Value {
        serde_json::from_str(include_str!("base_ontology.json")).expect("the built-in audit ontology must be valid JSON")
    }

    /// Load a strict genesis declaration. Runtime snapshots are not accepted as genesis declarations.
    pub fn from_value(v: &Value) -> KResult<Self> {
        let m = object(v, "ontology", &["format", "types", "relations", "stances", "concepts", "seed_status", "revision_policy"])?;
        if string(m, "format")? != BASE_FORMAT {
            return Err(bad("format", format!("expected {BASE_FORMAT}")));
        }
        let types = identifiers(m, "types", MAX_TYPES, true)?;
        let stances = identifiers(m, "stances", MAX_STANCES, true)?;
        let mut relations = BTreeMap::new();
        for relation in array(m, "relations", MAX_RELATIONS)? {
            let r = object(relation, "relations", &["id", "from", "to"])?;
            let id = identifier(string(r, "id")?, "relations.id")?;
            let endpoint = |key| -> KResult<String> {
                let s = string(r, key)?;
                if s == "record" || s == "concept" || s.strip_prefix("concept:").is_some_and(|ty| types.contains(ty)) {
                    Ok(s.to_string())
                } else {
                    Err(bad(key, "expected record, concept, or concept:<known type>"))
                }
            };
            let signature = json!({"id": id, "from": endpoint("from")?, "to": endpoint("to")?});
            if relations.insert(id, signature).is_some() {
                return Err(bad("relations", "duplicate relation id"));
            }
        }
        let mut seeds = Vec::new();
        let mut seed_names = BTreeSet::new();
        for seed in array(m, "concepts", MAX_CONCEPTS)? {
            let d = Definition::from_value(seed, &types)?;
            for name in d.names() {
                if !seed_names.insert(name.clone()) {
                    return Err(bad("concepts", format!("seed name or alias '{name}' is already reserved")));
                }
            }
            seeds.push(d);
        }
        seeds.sort();
        let seed_status = m.get("seed_status").and_then(Value::as_str).unwrap_or("accepted");
        if m.contains_key("seed_status") && !matches!(m["seed_status"].as_str(), Some("provisional" | "accepted")) {
            return Err(bad("seed_status", "expected provisional or accepted"));
        }
        if let Some(policy) = m.get("revision_policy") {
            let p = object(policy, "revision_policy", &["rule", "unmapped_circles", "catchall_mappings", "catchall_reports"])?;
            if string(p, "rule")? != "next_nonproposer/1" {
                return Err(bad("revision_policy", "unknown revision rule"));
            }
            for key in ["unmapped_circles", "catchall_mappings", "catchall_reports"] {
                if p.get(key).and_then(Value::as_u64).is_none_or(|n| n == 0 || n > 100_000) {
                    return Err(bad(key, "expected integer 1..100000"));
                }
            }
        }
        let mut base = json!({"format": BASE_FORMAT, "types": types, "relations": relations.into_values().collect::<Vec<_>>(),
            "stances": stances, "concepts": seeds.iter().map(Definition::to_value).collect::<Vec<_>>()});
        for key in ["seed_status", "revision_policy"] {
            if let Some(v) = m.get(key) {
                base[key] = v.clone();
            }
        }
        let base_hash = sha256_parts(&[b"R2R-AUDIT-ONTOLOGY-BASE/1\0", to_jcs(&base).as_bytes()]);
        let mut result = Self { base, base_hash, revision: 0, types, concepts: BTreeMap::new(), reserved: BTreeMap::new() };
        for seed in seeds {
            result.insert(seed, "base", Vec::new(), seed_status, 0);
        }
        Ok(result)
    }

    fn insert(&mut self, definition: Definition, by: &str, basis: Vec<RecordId>, status: &str, revision: u64) -> ConceptView {
        let id = definition.id(&self.base_hash);
        for name in definition.names() {
            self.reserved.insert(name.clone(), id);
        }
        let c = Concept {
            id,
            definition,
            proposed_by: by.to_string(),
            basis,
            status: status.to_string(),
            history: vec![StatusChange { revision, status: status.to_string(), by: by.to_string() }],
            removed_aliases: BTreeSet::new(),
            replacement: None,
            narrowed_into: vec![],
            unattested_prior: None,
            attestation_reason: None,
            function: None,
        };
        let view = c.view();
        self.concepts.insert(id, c);
        view
    }

    /// Place a concept under a broad function of the system. The first placement stays: a later
    /// proposal of the same concept naming another function changes nothing and gets the standing one back. A placement is a new
    /// ontology revision, as any change of the state (claude-reviewer's observation 1 on 8dfff576).
    pub fn place(&mut self, id: &ConceptId, function: &str) -> KResult<String> {
        let f = function_name(function)?;
        let next = self.next_revision()?;
        let c = self.concepts.get_mut(id).ok_or_else(|| KernelError::new(Code::UnknownEntity, "unknown audit concept").field("concept"))?;
        if let Some(standing) = &c.function {
            return Ok(standing.clone());
        }
        c.function = Some(f.clone());
        self.revision = next;
        Ok(f)
    }

    fn next_revision(&self) -> KResult<u64> {
        self.revision.checked_add(1).ok_or_else(|| bad("revision", "audit ontology revision exhausted"))
    }

    pub fn revision(&self) -> (u64, Hash) {
        (self.revision, sha256_parts(&[b"R2R-AUDIT-ONTOLOGY-STATE/1\0", to_jcs(&self.to_value()).as_bytes()]))
    }

    pub fn types(&self) -> Vec<String> {
        self.types.iter().cloned().collect()
    }

    /// Whether the immutable genesis schema declares this relation specifically between two records.
    pub fn record_relation(&self, id: &str) -> bool {
        self.base["relations"].as_array().expect("validated base relations").iter().any(|r| r["id"] == id && r["from"] == "record" && r["to"] == "record")
    }

    /// All concepts, including retired ones, ordered by immutable id.
    pub fn concepts(&self) -> Vec<ConceptView> {
        self.concepts.values().map(Concept::view).collect()
    }

    pub fn concept(&self, id: &ConceptId) -> Option<ConceptView> {
        self.concepts.get(id).map(Concept::view)
    }

    /// Exact normalized name/alias matches only. Retired names stay reserved but are not offered as candidates.
    pub fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(term) = normalized_name(term, "term") else { return Vec::new() };
        self.reserved
            .get(&term)
            .and_then(|id| self.concepts.get(id))
            .filter(|c| c.view().selectable() && !c.removed_aliases.contains(&term))
            .map(|c| vec![c.view()])
            .unwrap_or_default()
    }

    /// Validate shape here; the caller verifies that every basis id is an active observe record.
    /// Repeated normalized definitions preserve the first provenance and return the existing status, even after retirement.
    pub fn propose(&mut self, by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> KResult<ConceptView> {
        actor(by)?;
        if basis.is_empty() || basis.len() > MAX_BASIS {
            return Err(KernelError::new(Code::NoEvidence, "a concept needs 1..256 basis record ids").field("basis"));
        }
        let d = Definition::new(ty, name, aliases, &self.types)?;
        if let Some(existing) = self.reserved.get(&d.name).and_then(|id| self.concepts.get(id)) {
            if existing.definition == d {
                return Ok(existing.view());
            }
        }
        for n in d.names() {
            if let Some(id) = self.reserved.get(n) {
                return Err(bad("name", format!("name or alias '{n}' is already reserved"))
                    .expected(json!({"existing_concept": to_hex(&id.0)}))
                    .obligation(json!({"action": "use_existing_concept_or_choose_unreserved_names"})));
            }
        }
        if self.concepts.len() >= MAX_CONCEPTS {
            return Err(bad("concepts", format!("at most {MAX_CONCEPTS} concepts are allowed")));
        }
        let revision = self.next_revision()?;
        let basis: Vec<RecordId> = basis.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();
        let view = self.insert(d, by, basis, "provisional", revision);
        self.revision = revision;
        Ok(view)
    }

    /// Allowed transitions: provisional -> accepted/retired, accepted -> retired. Same-state retries do not add history.
    pub fn set_status(&mut self, id: &ConceptId, status: &str, by: &str) -> KResult<ConceptView> {
        actor(by)?;
        if !matches!(status, "provisional" | "accepted" | "retired") {
            return Err(bad("status", "expected provisional, accepted, or retired"));
        }
        let c = self.concepts.get(id).ok_or_else(|| KernelError::new(Code::UnknownEntity, "unknown audit concept").field("concept"))?;
        if c.status == status {
            return Ok(c.view());
        }
        if !matches!((c.status.as_str(), status), ("provisional", "accepted" | "retired") | ("accepted", "retired")) {
            return Err(bad("status", "concept lifecycle is irreversible"));
        }
        let revision = self.next_revision()?;
        let c = self.concepts.get_mut(id).expect("concept checked above");
        c.status = status.to_string();
        c.history.push(StatusChange { revision, status: status.to_string(), by: by.to_string() });
        let view = c.view();
        self.revision = revision;
        Ok(view)
    }

    pub fn revision_policy(&self) -> Option<Value> {
        self.base.get("revision_policy").cloned()
    }

    pub fn replacement(&self, id: &ConceptId) -> Option<ConceptView> {
        let mut next = self.concepts.get(id)?.replacement?;
        for _ in 0..self.concepts.len() {
            let c = self.concepts.get(&next)?;
            if let Some(id) = c.replacement {
                next = id;
            } else {
                return Some(c.view());
            }
        }
        None
    }

    /// Stage on a clone: a refused revision never partly changes definitions or lifecycle.
    pub fn revise(&mut self, change: &Value, by: &str, basis: &[RecordId]) -> KResult<Value> {
        let mut staged = self.clone();
        let id = ConceptId(crate::hash::from_hex(change["concept"].as_str().unwrap_or("")).ok_or_else(|| bad("concept", "expected full concept id"))?);
        let old = staged.concept(&id).filter(ConceptView::selectable).ok_or_else(|| bad("concept", "revision needs a live concept"))?;
        let mut replacement = None;
        match change["action"].as_str().unwrap_or("") {
            "retire" => {
                staged.set_status(&id, "retired", by)?;
            }
            "merge_into" => {
                let target = ConceptId(crate::hash::from_hex(change["target"].as_str().unwrap_or("")).ok_or_else(|| bad("target", "expected full target id"))?);
                if target == id || staged.concept(&target).is_none_or(|c| !c.selectable()) {
                    return Err(bad("target", "replacement must be a different live concept"));
                }
                staged.set_status(&id, "retired", by)?;
                replacement = Some(target);
            }
            "retype" => {
                let ty = change["new_type"].as_str().ok_or_else(|| bad("new_type", "required"))?;
                if ty == old.ty {
                    return Err(bad("new_type", "retype needs a different type"));
                }
                let name = normalized_name(change["new_name"].as_str().ok_or_else(|| bad("new_name", "a new unique name is required"))?, "new_name")?;
                if staged.reserved.contains_key(&name) {
                    return Err(bad("new_name", "retype requires a new unreserved unique name"));
                }
                let new = staged.propose(by, ty, &name, &[], basis)?;
                staged.set_status(&id, "retired", by)?;
                replacement = Some(new.id);
            }
            "remove_alias" => {
                let alias = normalized_name(change["alias"].as_str().ok_or_else(|| bad("alias", "required"))?, "alias")?;
                if !old.aliases.contains(&alias) {
                    return Err(bad("alias", "alias must currently belong to the concept"));
                }
                let revision = staged.next_revision()?;
                let c = staged.concepts.get_mut(&id).expect("checked concept");
                c.removed_aliases.insert(alias);
                c.history.push(StatusChange { revision, status: c.status.clone(), by: by.to_string() });
                staged.revision = revision;
            }
            _ => return Err(bad("action", "expected retire, merge_into, remove_alias or retype")),
        }
        if let Some(target) = replacement {
            staged.concepts.get_mut(&id).expect("checked concept").replacement = Some(target);
        }
        let out = json!({"concept":to_hex(&id.0),"status":staged.concept(&id).expect("checked concept").status,
            "replacement":replacement.map(|id|to_hex(&id.0)),"ontology_revision":staged.revision});
        *self = staged;
        Ok(out)
    }

    pub fn to_value(&self) -> Value {
        json!({"format": STATE_FORMAT, "base": self.base, "base_hash": to_hex(&self.base_hash), "revision": self.revision,
            "concepts": self.concepts.values().map(Concept::to_value).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ontology() -> AuditOntology {
        AuditOntology::from_value(&AuditOntology::base()).unwrap()
    }

    fn basis() -> Vec<RecordId> {
        vec![RecordId([1; 32]), RecordId([2; 32])]
    }

    #[test]
    fn a_concept_is_placed_once_under_one_normalized_function_and_a_catchall_is_refused() {
        let mut o = ontology();
        let engine = o.propose("builder", "Component", "engine", &[], &basis()).unwrap();
        let unplaced = o.revision().1;
        assert!(!to_jcs(&o.to_value()).contains("\"function\""), "a state without functions keeps its bytes");
        assert_eq!(o.place(&engine.id, "The  Braking Systems").unwrap(), "braking system");
        assert_eq!(o.place(&engine.id, "ventilation").unwrap(), "braking system", "the first placement stays");
        assert_eq!(o.concept(&engine.id).unwrap().function.as_deref(), Some("braking system"));
        assert_ne!(o.revision().1, unplaced, "a placement is part of the ontology state");
        let placed = o.revision().0;
        o.place(&engine.id, "cooling").unwrap();
        assert_eq!(o.revision().0, placed, "a placement that changes nothing is no new revision");
        let pump = o.propose("builder", "Component", "pump", &[], &basis()).unwrap();
        for bad in ["General", "core  Protocol", "the system", "one two three four five six", &"x".repeat(61)] {
            assert!(o.place(&pump.id, bad).is_err(), "{bad}");
        }
        assert_eq!(o.concept(&pump.id).unwrap().function, None, "a refused placement places nothing");
        // one singular for the last word, and nothing else changed (claude-reviewer's RV-02 of 8dfff576 for the -es forms, RV-03 of
        // 376d8d14 for the words in -se, -ze and -che that the first fix broke)
        for (name, want) in [
            ("batches", "batch"),
            ("processes", "process"),
            ("indexes", "index"),
            ("statuses", "status"),
            ("aliases", "alias"),
            ("alias", "alias"),
            ("cases", "case"),
            ("sizes", "size"),
            ("releases", "release"),
            ("databases", "database"),
            ("causes", "cause"),
            ("caches", "cache"),
            ("buses", "bus"),
        ] {
            assert_eq!(function_name(name).unwrap(), want, "{name}");
        }
        assert!(function_name("Basics").is_err() && function_name("the basic").is_err(), "a catch-all in either form");
        for (name, want) in [
            ("access", "access"),
            ("status", "status"),
            ("analysis", "analysis"),
            ("capabilities", "capability"),
            ("Request Headers", "request header"),
            ("mcp protocol", "mcp protocol"),
        ] {
            assert_eq!(function_name(name).unwrap(), want, "{name}");
        }
    }

    #[test]
    fn built_in_schema_has_explicit_domains_and_no_corpus_findings() {
        let o = ontology();
        assert_eq!(o.types().len(), 11);
        assert!(o.concepts().is_empty());
        assert_eq!(o.revision().0, 0);
        assert!(o.base["relations"].as_array().unwrap().iter().any(|r| r == &json!({"id": "validated_by", "from": "concept:Check", "to": "concept:Revision"})));
        assert!(AuditOntology::from_value(&o.to_value()).is_err(), "snapshots are not genesis declarations");
    }

    #[test]
    fn record_relations_follow_the_declared_genesis_domains() {
        let o = ontology();
        assert!(o.record_relation("supports"));
        assert!(!o.record_relation("validated_by"));
        assert!(!o.record_relation("unknown"));
        let mut base = AuditOntology::base();
        base["relations"].as_array_mut().unwrap().retain(|r| r["id"] != "supports");
        assert!(!AuditOntology::from_value(&base).unwrap().record_relation("supports"));
        base["relations"].as_array_mut().unwrap().push(json!({"id":"supports", "from":"concept:Check", "to":"concept:Revision"}));
        assert!(!AuditOntology::from_value(&base).unwrap().record_relation("supports"));
    }

    #[test]
    fn proposals_are_provisional_and_normalized_retries_preserve_identity_and_provenance() {
        let mut o = ontology();
        let a = o.propose("builder", "Component", "  Core   Engine  ", &[" Runtime ".into(), "RUNTIME".into(), "core engine".into()], &basis()).unwrap();
        assert_eq!((a.name.as_str(), a.aliases.as_slice(), a.status.as_str()), ("core engine", &["runtime".to_string()][..], "provisional"));
        let before = o.to_value();
        let rev = o.revision();
        let b = o.propose("another", "Component", "CORE ENGINE", &["runtime".into()], &[RecordId([9; 32])]).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(o.revision(), rev);
        assert_eq!(o.to_value(), before);
        assert_eq!(o.candidates("  RUNTIME ", 5), vec![a]);
        assert!(o.candidates("engine", 5).is_empty(), "no fuzzy equivalence is invented");
        assert!(o.candidates("runtime", 0).is_empty());
    }

    #[test]
    fn aliases_names_and_types_cannot_redefine_an_existing_concept() {
        let mut o = ontology();
        o.propose("builder", "Component", "engine", &["kernel".into()], &basis()).unwrap();
        let before = o.revision();
        for (ty, name, aliases) in [
            ("Rule", "ENGINE", vec![]),
            ("Component", "kernel", vec![]),
            ("Component", "other", vec!["engine".into()]),
            ("Component", "engine", vec!["changed".into()]),
        ] {
            assert!(o.propose("builder", ty, name, &aliases, &basis()).is_err());
            assert_eq!(o.revision(), before);
        }
    }

    #[test]
    fn lifecycle_keeps_history_and_retired_names_reserved() {
        let mut o = ontology();
        let c = o.propose("builder", "Component", "engine", &["kernel".into()], &basis()).unwrap();
        let original_id = c.id;
        assert_eq!(o.set_status(&c.id, "accepted", "owner").unwrap().status, "accepted");
        assert_eq!(o.revision().0, 2);
        let accepted = o.revision();
        o.set_status(&c.id, "accepted", "owner").unwrap();
        assert_eq!(o.revision(), accepted);
        assert!(o.set_status(&c.id, "provisional", "owner").is_err());
        assert_eq!(o.set_status(&c.id, "retired", "owner").unwrap().id, original_id);
        assert_eq!(o.revision().0, 3);
        assert!(o.set_status(&c.id, "accepted", "owner").is_err());
        assert!(o.candidates("engine", 5).is_empty());
        assert!(o.propose("builder", "Issue", "kernel", &[], &basis()).is_err());
        assert_eq!(o.propose("builder", "Component", "engine", &["kernel".into()], &basis()).unwrap().status, "retired");
        assert_eq!(o.to_value()["concepts"][0]["history"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn normalized_sets_and_replayed_commands_have_deterministic_hashes() {
        let mut base = AuditOntology::base();
        let mut reordered = base.clone();
        for key in ["types", "relations", "stances"] {
            reordered[key].as_array_mut().unwrap().reverse();
        }
        let seed = json!({"type": "Report", "name": "  Manifest  ", "aliases": ["Index", " INDEX "]});
        base["concepts"] = json!([seed]);
        reordered["concepts"] = json!([{"type":"Report", "name":"manifest", "aliases":["index"]}]);
        let mut a = AuditOntology::from_value(&base).unwrap();
        let mut b = AuditOntology::from_value(&reordered).unwrap();
        assert_eq!(a.revision(), b.revision());
        assert_eq!(a.concepts()[0].status, "accepted", "trusted seeds are accepted");
        let ca = a.propose("builder", "Component", "engine", &["rt".into(), "kernel".into()], &basis()).unwrap();
        let cb = b.propose("builder", "Component", "ENGINE", &["KERNEL".into(), "rt".into()], &[RecordId([2; 32]), RecordId([1; 32])]).unwrap();
        assert_eq!(ca.id, cb.id);
        a.set_status(&ca.id, "retired", "owner").unwrap();
        b.set_status(&cb.id, "retired", "owner").unwrap();
        assert_eq!(a.revision(), b.revision());
        assert_eq!(to_jcs(&a.to_value()), to_jcs(&b.to_value()));
    }

    #[test]
    fn commitment_covers_provenance_status_and_base_identity() {
        let mut a = ontology();
        let mut b = ontology();
        let ca = a.propose("builder-a", "Component", "engine", &[], &basis()).unwrap();
        let cb = b.propose("builder-b", "Component", "engine", &[], &basis()).unwrap();
        assert_eq!(ca.id, cb.id, "provenance is not concept identity");
        assert_ne!(a.revision().1, b.revision().1);
        let before = a.revision().1;
        a.set_status(&ca.id, "accepted", "owner").unwrap();
        assert_ne!(a.revision().1, before);
        let mut changed_base = AuditOntology::base();
        changed_base["types"].as_array_mut().unwrap().push(json!("Extra"));
        let mut c = AuditOntology::from_value(&changed_base).unwrap();
        let cc = c.propose("builder-a", "Component", "engine", &[], &basis()).unwrap();
        assert_ne!(ca.id, cc.id, "concept ids are scoped to the genesis audit ontology");
    }

    #[test]
    fn malformed_bases_are_rejected_without_silently_dropping_fields() {
        for (key, replacement) in [
            ("types", json!(["Component", 1])),
            ("types", json!(["Component", "Component"])),
            ("stances", json!([true])),
            ("relations", json!([{"id":"about", "from":"record", "to":"concept:Missing"}])),
            ("relations", json!([{"id":"about", "from":"record", "to":"concept", "unexpected":true}])),
            ("concepts", json!([{"type":"Component", "name":"x", "aliases":[false]}])),
            ("concepts", json!([{"type":"Missing", "name":"x"}])),
            ("concepts", json!([{"type":"Component", "name":"x"}, {"type":"Issue", "name":"X"}])),
        ] {
            let mut v = AuditOntology::base();
            v[key] = replacement;
            assert!(AuditOntology::from_value(&v).is_err(), "{v}");
        }
        let mut v = AuditOntology::base();
        v["revision"] = json!(true);
        assert!(AuditOntology::from_value(&v).is_err(), "genesis does not accept a spoofed revision");
    }

    #[test]
    fn bounds_and_revision_exhaustion_do_not_partially_mutate() {
        let mut o = ontology();
        let before = o.to_value();
        assert!(o.propose("builder", "Component", "x", &[], &[]).is_err());
        assert!(o.propose("builder", "Component", &"x".repeat(MAX_NAME_BYTES + 1), &[], &basis()).is_err());
        assert!(o.propose("builder", "Component", "x", &vec!["alias".into(); MAX_ALIASES + 1], &basis()).is_err());
        assert_eq!(o.to_value(), before);
        o.revision = u64::MAX;
        let before = o.to_value();
        assert!(o.propose("builder", "Component", "x", &[], &basis()).is_err());
        assert_eq!(o.to_value(), before);
    }
}

mod lifecycle;
