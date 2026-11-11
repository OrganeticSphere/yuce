//! Durable audit storage, independent of the engine's ontology and binary formats.
//!
//! A transaction is prepared on a private engine/audit state, written and synced as one outer WAL frame, then published.
//! Recovery repeats commands from the committed genesis and checks both post-roots before permitting any tail repair.
//! `AuditStore` is an in-process kernel interface; the dispatcher must authenticate subjects and authorize role methods.
//! The explicit submission/checkpoint APIs let it keep receipts independently of ephemeral leases and cards.

use super::onto::AuditOntology;
use super::persistence::{AuditJournal, FrameFormat};
use super::records;
use super::*;
use crate::arena::{find_all, Occurrence};
use crate::cdc::CdcParams;
use crate::container::{build_container, open_session};
use crate::error::{Code, KResult};
use crate::hash::{from_hex, sha256, sha256_parts, sha256_stream, ZERO_HASH};
use crate::jcs::to_jcs;
use crate::merkle::KeyedIdBuild;
use crate::node::{EV_ACTIVE, EV_REVOKED};
use crate::ontology::Ontology;
use crate::session::{Session, MAX_REFS, MAX_STR};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[path = "root_cache.rs"]
mod root_cache;
#[path = "state_root.rs"]
mod state_root;

#[path = "attestation.rs"]
mod attestation;
#[path = "narrow.rs"]
mod narrow;
#[path = "ontology_review.rs"]
mod ontology_review;
#[path = "revisions.rs"]
mod revisions;
mod versions;

/// Format 2: a withdrawal closes text of a document, wherever those bytes stand in it, in any version. Every stored quote overlapping
/// them loses its support with it and a new quote overlapping them is refused. Format 1 refused only the exact span, so a wider quote
/// brought the text back as a new record (series of 06.11.2026): its journals keep that rule, because a recorded outcome has to
/// replay as it was recorded.
const GENESIS_FORMAT: &str = "r2r-audit-genesis/2";
const GENESIS_FORMAT_EXACT_SPAN: &str = "r2r-audit-genesis/1";
/// Format 3 (0.2, SPEC_V02_STEP2 section 4): `/3` frames, the `r2r-state-root/2` root, the rules of format 2, and a strict list of
/// fields that names the rules, the formats of the root and the seal, the questions and the hash of the settings.
const GENESIS_FORMAT_V3: &str = "r2r-audit-genesis/3";
pub const RULES_VERSION: &str = "r2r-audit-rules/3";
const SEAL_FORMAT: &str = "r2r-seal/2";
const GENESIS_V3_KEYS: [&str; 15] = [
    "audit_root",
    "base_ontology",
    "engine_container_hex",
    "engine_root",
    "format",
    "manifest_hash",
    "operator_meta",
    "questions",
    "rules_version",
    "run_id",
    "seal_format",
    "settings_hash",
    "source_documents",
    "source_mode",
    "state_root_format",
];
const MAX_OPERATOR_META_BYTES: usize = 4096;

/// What a new `/3` journal names in its genesis besides its sources: the questions of the run, the canonical settings it runs
/// under (hashed, `settings_hash`), and an object of the operator's that the kernel never reads.
#[derive(Clone, Debug)]
pub struct GenesisSpec {
    pub questions: Value,
    pub settings: Value,
    pub operator_meta: Option<Value>,
}

impl Default for GenesisSpec {
    fn default() -> Self {
        Self { questions: json!([]), settings: json!({}), operator_meta: None }
    }
}

/// `H("R2R-SETTINGS/2", JCS(settings))`.
pub fn settings_hash(settings: &Value) -> Hash {
    sha256_parts(&[b"R2R-SETTINGS/2\0", to_jcs(settings).as_bytes()])
}

/// What a `/3` genesis named, kept for the server: the questions, the settings hash, the operator's object.
#[derive(Clone, Debug)]
pub struct GenesisMeta {
    pub questions: Value,
    pub settings_hash: Hash,
    pub operator_meta: Option<Value>,
}
pub const MAX_DOC_BYTES: usize = 16 * 1024 * 1024;
/// The longest name of a supplied document: the keys of its tasks hold the name and have the limit of any identifier, so a longer name
/// could be read and its reading never closed.
pub const MAX_DOC_NAME_BYTES: usize = 512;
/// The rule a map_term names when the circles +1 refiner maps a term under ontology reviews; the builder sets it, not the model.
pub const REFINER_MAP_RULE: &str = "refiner_map_term/1";

fn bad(field: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field(field)
}

/// The quote rule of an observe record: the document is one of the directive's, the whole document holds the quote byte for byte
/// exactly once, and that occurrence lies inside the issued byte ranges. One rule for the commit path and for the dispatcher's
/// read-only diagnostics of a refused answer, which never decide what is stored; the commit path also refuses withdrawn text.
/// The occurrences of `text` near `span`, among them every one that overlaps it: such an occurrence lies within one length of `text`
/// on either side. Every new quote asks this of every closed text, so it must not cost a search of the whole document.
fn occurrences_around(doc: &[u8], text: &[u8], span: &Occurrence) -> Vec<Occurrence> {
    let (from, to) = (span.start.saturating_sub(text.len()), span.end.saturating_add(text.len()).min(doc.len()));
    find_all(&doc[from..to], text).into_iter().map(|o| Occurrence { start: o.start + from, end: o.end + from }).collect()
}

pub fn quote_span(scope: &Scope, doc_id: &str, doc: Option<&[u8]>, quote: &str) -> KResult<Occurrence> {
    if !scope.docs.iter().any(|d| d == doc_id) {
        return Err(bad("doc_id", "document is outside the directive"));
    }
    let bytes = doc.ok_or_else(|| KernelError::new(Code::UnknownDoc, "document was not loaded").field("doc_id"))?;
    let occurrences = find_all(bytes, quote.as_bytes());
    if occurrences.is_empty() {
        return Err(KernelError::new(Code::QuoteNotFoundInBytes, "quote has no byte-exact occurrence").field("exact_quote"));
    }
    // Legacy bind_evidence itself requires global uniqueness, so preserve that stronger constraint and never
    // select the first match outside or inside a section silently.
    if occurrences.len() != 1 {
        return Err(KernelError::new(Code::AmbiguousQuoteSpan, "quote is ambiguous; submit a unique extension")
            .field("exact_quote")
            .expected(json!({"candidate_spans":occurrences.iter().take(8).map(|r|json!([r.start,r.end])).collect::<Vec<_>>()})));
    }
    let span = occurrences.into_iter().next().expect("one occurrence");
    let inside =
        scope.ranges.is_empty() || scope.ranges.iter().any(|(d, s, e)| d == doc_id && *s <= span.start && span.end <= *e && *s < *e && *e <= bytes.len());
    if !inside {
        return Err(bad("exact_quote", "quote is outside the issued byte ranges"));
    }
    Ok(span)
}

fn string<'a>(v: &'a Value, key: &str) -> KResult<&'a str> {
    let s = v.get(key).and_then(Value::as_str).ok_or_else(|| bad(key, "expected a string"))?;
    identifier(s, key)?;
    Ok(s)
}

fn identifier(s: &str, key: &str) -> KResult<()> {
    if s.trim().is_empty() || s.len() > MAX_STR || s.chars().any(char::is_control) {
        return Err(bad(key, "expected 1..1024 UTF-8 bytes without control characters"));
    }
    Ok(())
}

/// Whether a committed command changed a circle's phase: the dispatcher's `audit:circles` checkpoint, accepted (Codex recheck of
/// db57a93: a refused one is no boundary). One rule for the write and for the replay, on the journaled outcome.
fn phase_changed(command: &Value, outcome: &Value) -> bool {
    let result = &outcome["result"];
    (command["checkpoint"]["key"] == "audit:circles" && result["checkpointed"] == true)
        || (command["kind"] == "checkpoint" && command["key"] == "audit:circles" && result["checkpoint"] == "audit:circles")
}

/// The kernel's own ids in a `/3` journal (Codex review of 43447f4, S2-02): `seal-<n>` is the seal of the first n frames and
/// nothing else, and `audit-close` the close. No other command takes them first and turns the kernel's own frame into a refusal.
/// A seal and a close are the kernel's alone, under any id: a frame of another actor with one would be a seal or a close nobody
/// counts (GAP-14 of the independent verifier).
fn kernel_id(actor: &str, id: &str, command: &Value) -> KResult<()> {
    let kind = command["kind"].as_str().unwrap_or("");
    if actor != "kernel" {
        if kind == "seal" || kind == "close" {
            return Err(bad("actor", "a seal and a close are the kernel's: no other actor writes one"));
        }
        return Ok(());
    }
    if id.starts_with("seal-") || kind == "seal" {
        let own = command["seal"]["log_size"].as_u64().map(|n| format!("seal-{n}"));
        if kind != "seal" || own.as_deref() != Some(id) {
            return Err(bad("submission_id", "the ids seal-<n> belong to the kernel's seal of the first n frames"));
        }
    }
    if (id == "audit-close") != (kind == "close") {
        return Err(bad("submission_id", "the id audit-close belongs to the kernel's close, and the close to it"));
    }
    Ok(())
}

fn strings(v: &Value, key: &str) -> KResult<Vec<String>> {
    let values = v.get(key).and_then(Value::as_array).ok_or_else(|| bad(key, "expected an array"))?;
    if values.len() > MAX_REFS {
        return Err(bad(key, "too many references"));
    }
    values.iter().map(|x| x.as_str().map(str::to_string).ok_or_else(|| bad(key, "all entries must be strings"))).collect()
}

/// A hash the kernel wrote into a journal: in a `/3` journal 64 lowercase hex digits and no other spelling (SPEC_V02_STEP2
/// section 1), as the journals of the first formats also took capitals.
fn kernel_hash(v: &Value, key: &str, v3: bool) -> KResult<Hash> {
    let h = hash_field(v, key)?;
    if v3 && v[key] != json!(to_hex(&h)) {
        return Err(bad(key, "a hash of a 0.2 journal is 64 lowercase hex digits"));
    }
    Ok(h)
}

fn hash_field(v: &Value, key: &str) -> KResult<Hash> {
    v.get(key).and_then(Value::as_str).and_then(from_hex).ok_or_else(|| bad(key, "expected a full 64-digit hash"))
}

fn record_value(r: &RecordView) -> Value {
    json!({"id":to_hex(&r.id.0),"seq":r.seq,"kind":r.kind.name(),"author":r.author,"directive":r.directive,
        "doc_id":r.doc_id,"quote":r.quote,"terms":r.terms,"text":r.text,"stance":r.status,
        "based_on":r.based_on.iter().map(|x|to_hex(&x.0)).collect::<Vec<_>>(),
        "ends":r.ends.as_ref().map(|(a,rel,b)|json!([to_hex(&a.0),rel,to_hex(&b.0)])),"body":r.body})
}

fn concept_value(c: &ConceptView) -> Value {
    let mut v = json!({"id":to_hex(&c.id.0),"type":c.ty,"name":c.name,"aliases":c.aliases,"status":c.status});
    // only when placed: results of concepts without a function keep their bytes
    if let Some(f) = &c.function {
        v["function"] = json!(f);
    }
    v
}

fn link_value(l: &LinkView) -> Value {
    json!({"id":to_hex(&l.id.0),"from":to_hex(&l.from.0),"rel":l.rel,"to":to_hex(&l.to.0),
        "status":l.status.name(),"by":l.by,"basis":l.basis.iter().map(|r|to_hex(&r.0)).collect::<Vec<_>>()})
}

fn report_value(r: &SubmitReport) -> Value {
    json!({"accepted":r.accepted.iter().map(|x|to_hex(&x.0)).collect::<Vec<_>>(),
        "failed_index":r.failed_index,"error":r.error.as_ref().map(KernelError::to_json)})
}

#[derive(Debug, Clone)]
enum Outcome {
    Records(SubmitReport),
    Value(Value),
    Error(KernelError),
}

impl Outcome {
    fn value(&self) -> Value {
        match self {
            Self::Records(r) => json!({"kind":"records","result":report_value(r)}),
            Self::Value(v) => json!({"kind":"value","result":v}),
            Self::Error(e) => json!({"kind":"error","error":e.to_json()}),
        }
    }
}

#[derive(Debug, Clone)]
struct Receipt {
    request_hash: Hash,
    outcome: Outcome,
}

#[derive(Debug, Clone)]
struct EvidenceBinding {
    evidence: Hash,
    version: Hash,
    start: usize,
    end: usize,
}

/// What a pass over the records keeps of each one. Record ids are digests and nothing reads these maps in order; an ordered map
/// cost a pass several times what it derives, and a command makes several passes.
///
/// Its key is drawn per process, so its order changes from run to run, and an order that reached a root would make two runs of one
/// journal differ. So it cannot be walked: `sorted` is the way out.
#[derive(Clone, Debug, PartialEq)]
struct ById<T>(HashMap<RecordId, T, KeyedIdBuild>);

impl<T> Default for ById<T> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<T> ById<T> {
    fn with_capacity(n: usize) -> Self {
        Self(HashMap::with_capacity_and_hasher(n, KeyedIdBuild::default()))
    }

    fn get(&self, id: &RecordId) -> Option<&T> {
        self.0.get(id)
    }

    fn insert(&mut self, id: RecordId, value: T) -> Option<T> {
        self.0.insert(id, value)
    }

    fn sorted(&self) -> BTreeMap<RecordId, T>
    where
        T: Clone,
    {
        self.0.iter().map(|(id, value)| (*id, value.clone())).collect()
    }
}

impl<T> std::ops::Index<&RecordId> for ById<T> {
    type Output = T;

    fn index(&self, id: &RecordId) -> &T {
        &self.0[id]
    }
}

#[derive(Debug, Clone)]
struct Data {
    run_id: String,
    manifest_hash: Hash,
    source_mode: String,
    source_documents: BTreeMap<String, Value>,
    ontology: AuditOntology,
    records: Vec<RecordView>,
    locals: BTreeMap<(String, String, String), RecordId>,
    task_ordinals: BTreeMap<(String, String), u64>,
    evidence: ById<EvidenceBinding>,
    mappings: BTreeMap<(RecordId, String, ConceptId), String>,
    links: BTreeMap<LinkId, LinkView>,
    acceptance_basis: BTreeMap<LinkId, Vec<RecordId>>,
    decisions: Vec<Value>,
    receipts: BTreeMap<(String, String), Receipt>,
    checkpoints: BTreeMap<String, Value>,
    /// The journal's rule, from its genesis; neither this nor `withdrawn` enters `audit_root`: both follow from the genesis and the commands.
    withdrawal_closes_bytes: bool,
    /// The text withdrawn under that rule, by document.
    withdrawn: BTreeMap<String, BTreeSet<Vec<u8>>>,
    /// Why each quote that went went, written once, by the command that revoked its evidence (SPEC_V02_STEP3 section 6): a later
    /// version of the document or a later withdrawal nearby never rewrites it (Codex review of 2c6864f, S3-01, S3-02). A replay of
    /// the commands writes it again; it enters no root, no frame and no projection.
    fates: BTreeMap<RecordId, Value>,
    /// The run was closed by a `close` entry of a `/3` journal (`audit_close`): it stays closed after a restart.
    closed: bool,
}

struct Core {
    session: Session,
    engine_root: Hash,
    data: Data,
    root_cache: Mutex<root_cache::Cache>,
    /// The `r2r-state-root/2` tree of a `/3` journal; `None` for a journal of the first formats, whose root is `/1`.
    state_tree: Mutex<Option<state_root::StateTree>>,
    /// Set while `replay_in_place` runs a command: no step of it keeps a copy to go back to. Never set on a fork.
    in_place: bool,
}

impl Core {
    fn fork(&self) -> KResult<Self> {
        #[cfg(test)]
        FORKS.with(|n| n.set(n.get() + 1));
        Ok(Self {
            session: self.fork_session()?,
            engine_root: self.engine_root,
            data: self.data.clone(),
            root_cache: Mutex::new(self.cache().clone()),
            state_tree: Mutex::new(self.state_tree.lock().expect("state tree poisoned").clone()),
            in_place: false,
        })
    }

    /// The keys a command changes, for the `/2` root; `None` for a journal of the first formats.
    fn dirty(&mut self) -> Option<&mut state_root::Dirty> {
        self.state_tree.get_mut().expect("state tree poisoned").as_mut().map(|t| &mut t.dirty)
    }

    /// The status projection, one row per record in record order (`[id, kind, grounded, answer_support, fallen_by]`, `fallen_by` the
    /// sorted grounds that no longer stand), and the dependency projection, the sorted pairs `[record, ground]` of `based_on` and of
    /// relation ends, each hashed in its own domain. Complete as to the kernel's rule, not as to the world: a dependency an agent
    /// did not declare is in neither.
    fn projection_hashes(&self) -> (Hash, Hash) {
        let (status, pairs) = self.projection_rows();
        projection_hashes_of(&status, &pairs)
    }

    /// The rows of the two projections. `fallen_by` names the direct grounds that no longer stand (for a done that rests on a claim
    /// on a withdrawn quote, the claim, not the quote): the first cause is found by following `fallen_by` down to a withdrawn
    /// observation (Codex review of 43447f4, S2-03; SPEC_V02_STEP2 section 6).
    fn projection_rows(&self) -> (Vec<Value>, Vec<Value>) {
        let support = self.support_flags();
        let stands = |id: &RecordId| support.get(id).is_some_and(|v| v.0);
        let mut status = Vec::with_capacity(self.data.records.len());
        let mut pairs = BTreeSet::new();
        for r in &self.data.records {
            let (grounded, established) = support.get(&r.id).copied().unwrap_or((false, false));
            let mut grounds = r.based_on.clone();
            if let Some((a, _, b)) = &r.ends {
                grounds.extend([*a, *b]);
            }
            let mut fallen: Vec<String> = grounds.iter().filter(|g| !stands(g)).map(|g| to_hex(&g.0)).collect();
            fallen.sort();
            fallen.dedup();
            status.push(json!([to_hex(&r.id.0), r.kind.name(), grounded, established, fallen]));
            for g in grounds {
                pairs.insert((to_hex(&r.id.0), to_hex(&g.0)));
            }
        }
        let pairs: Vec<Value> = pairs.into_iter().map(|(a, b)| json!([a, b])).collect();
        (status, pairs)
    }

    /// What a command begins with for both roots: the `/1` cache drops what it may change, the `/2` tree marks the ontology.
    fn begin_roots(&mut self, command: &Value) {
        self.root_cache.get_mut().expect("audit root cache poisoned").begin(command);
        if let Some(tree) = self.state_tree.get_mut().expect("state tree poisoned").as_mut() {
            tree.begin(command);
        }
    }

    /// The session of `fork` alone: an observation binds its evidence on a staged engine and keeps it only when the record is
    /// accepted, and needs no copy of the rest (01.11.2026 measurement: a whole fork per observe line, 16 per agent answer, cloned
    /// every record of the state and threw the copy away).
    ///
    /// The engine is copied, not rebuilt by a replay of the session WAL (01.11.2026: the replay, a conservative prototype's way
    /// around an engine without `Clone`, cost O(WAL) per fork). This state is trusted: its WAL bytes were checked when the journal
    /// was opened (`open_session`, `recover`) and are written by this kernel alone since; `from_parts` still resets what a fork
    /// resets (session locals, root tracking, the session journal; `last_seq` from the WAL). Codex's conditions of 01.11.2026.
    fn fork_session(&self) -> KResult<Session> {
        #[cfg(test)]
        if REPLAY_FORK.with(std::cell::Cell::get) {
            let rec = crate::wal::reconstruct_at_byte_offset(&self.session.wal.bytes).map_err(|e| bad("wal", e.to_string()))?;
            return Ok(Session::from_parts(self.session.ontology.clone(), self.session.arena.clone(), rec.engine, self.session.wal.clone()));
        }
        Ok(Session::from_parts(self.session.ontology.clone(), self.session.arena.clone(), self.session.engine.clone(), self.session.wal.clone()))
    }

    /// The state after `command`, executed on a fork of this one, with its receipt; a failed command leaves a fresh fork of this
    /// state with the failure's receipt. This state is not changed.
    fn stage(&self, actor: &str, id: &str, command: &Value) -> KResult<(Self, Outcome)> {
        let mut next = self.fork()?;
        next.begin_roots(command);
        // a batch, the store's form of every builder operation, rolls a refused first operation back to this state: a successful
        // operation then costs one copy of the state, not two (02.11.2026, Argon's review of the builder card transaction)
        let base = Some(self);
        #[cfg(test)]
        let base = base.filter(|_| !TWO_COPY_BATCH.with(std::cell::Cell::get));
        let executed = if command["kind"] == "batch" { next.batch(actor, command, base) } else { next.execute(actor, command) };
        let executed = executed.and_then(|outcome| {
            next.version_effects(self, actor)?;
            Ok(outcome)
        });
        let outcome = match executed {
            Ok(outcome) => outcome,
            Err(error) => {
                next = self.fork()?;
                Outcome::Error(error)
            }
        };
        next.seal(actor, id, command, &outcome);
        Ok((next, outcome))
    }

    /// `stage` on this state itself, for a replayed command whose journal entry reports no failure (`AuditState::prepare_recorded`).
    /// `stage` copies this state to have a way back from a failure, and a copy costs as much as the state is long. A command that
    /// does not fail runs the same code on the same state here and leaves the same state. One that fails all the same has an outcome
    /// other than the recorded one: the caller refuses the journal as it refuses any divergence, and nothing reads the half-changed
    /// state after `seal` has written its receipt into it.
    fn replay_in_place(&mut self, actor: &str, id: &str, command: &Value) -> Outcome {
        self.begin_roots(command);
        self.session.reset_transients();
        self.in_place = true;
        let executed = if command["kind"] == "batch" { self.batch(actor, command, None) } else { self.execute(actor, command) };
        self.in_place = false;
        let outcome = executed.unwrap_or_else(Outcome::Error);
        self.seal(actor, id, command, &outcome);
        outcome
    }

    /// What every staged command ends with, failed or not: the engine root, the receipt, an audit root to compute.
    fn seal(&mut self, actor: &str, id: &str, command: &Value, outcome: &Outcome) {
        self.engine_root = self.session.engine.root();
        self.data.receipts.insert((actor.into(), id.into()), Receipt { request_hash: request_hash(actor, command), outcome: outcome.clone() });
        if let Some(d) = self.dirty() {
            d.receipts.insert((actor.into(), id.into()));
        }
        self.root_cache.get_mut().expect("audit root cache poisoned").finish();
    }

    fn record(&self, id: &RecordId) -> Option<&RecordView> {
        self.data.records.iter().find(|r| r.id == *id)
    }

    fn resolve(&self, name: &str, actor: &str, directive: &str) -> KResult<RecordId> {
        if let Some(id) = self.data.locals.get(&(actor.into(), directive.into(), name.into())) {
            return Ok(*id);
        }
        let prefix = name.strip_prefix('@').ok_or_else(|| KernelError::new(Code::UnknownLocalId, "expected an issued local id or @hash").field("reference"))?;
        if prefix.len() < 16 || prefix.len() > 64 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("reference", "@ references require 16..64 hexadecimal digits"));
        }
        let prefix = prefix.to_ascii_lowercase();
        let ids: Vec<_> = self.data.records.iter().filter(|r| to_hex(&r.id.0).starts_with(&prefix)).map(|r| r.id).collect();
        match ids.as_slice() {
            [id] => Ok(*id),
            [] => Err(KernelError::new(Code::UnknownLocalId, "record reference was not found").field("reference")),
            _ => Err(bad("reference", "ambiguous record prefix; use the full id").expected(json!({"full_id_required":true}))),
        }
    }

    /// An observation is grounded while its evidence is bound, active in the engine, and its document still has the version
    /// the evidence was bound to: its `structural_grounding`, which `support_flags_fresh` takes as its grounding, read without a
    /// pass over every record.
    fn observe_grounded(&self, r: &RecordView) -> bool {
        self.data.evidence.get(&r.id).is_some_and(|b| {
            self.session.engine.status_of(&b.evidence) == Some(EV_ACTIVE)
                && r.doc_id.as_ref().and_then(|d| self.session.arena.doc(d)).is_some_and(|d| d.version_id == b.version)
        })
    }

    fn by_record<T>(&self) -> ById<T> {
        ById::with_capacity(self.data.records.len())
    }

    fn structural_grounding(&self) -> ById<bool> {
        let mut flags = self.by_record();
        for r in &self.data.records {
            let active = if r.kind == RecordKind::Observe {
                self.observe_grounded(r)
            } else {
                r.kind != RecordKind::Done
                    && !r.based_on.is_empty()
                    && r.based_on.iter().all(|b| flags.get(b) == Some(&true))
                    && r.ends.as_ref().is_none_or(|(a, _, b)| flags.get(a) == Some(&true) && flags.get(b) == Some(&true))
            };
            flags.insert(r.id, active);
        }
        flags
    }

    fn effective_links(&self, structural: &ById<bool>) -> BTreeSet<(RecordId, String, RecordId)> {
        let proof = self.proof_admissibility(structural);
        self.data
            .links
            .values()
            .filter(|l| {
                l.status == LinkStatus::Accepted
                    && proof.get(&l.from) == Some(&true)
                    && proof.get(&l.to) == Some(&true)
                    && !l.basis.is_empty()
                    && l.basis.iter().all(|id| proof.get(id) == Some(&true))
                    && self.data.acceptance_basis.get(&l.id).is_some_and(|basis| !basis.is_empty() && basis.iter().all(|id| proof.get(id) == Some(&true)))
            })
            .map(|l| (l.from, l.rel.clone(), l.to))
            .collect()
    }

    fn proof_admissibility(&self, structural: &ById<bool>) -> ById<bool> {
        // A verifier may cite its own structurally grounded judgement without recursively verifying that judgement.
        // However, a hypothesis must not become proof through a relation endpoint or an indirect basis chain.
        let mut proof = self.by_record();
        for r in &self.data.records {
            let allowed = structural.get(&r.id) == Some(&true)
                && !matches!(r.kind, RecordKind::Hypothesis | RecordKind::Question | RecordKind::Done)
                && r.based_on.iter().all(|id| proof.get(id) == Some(&true))
                && r.ends.as_ref().is_none_or(|(a, _, b)| proof.get(a) == Some(&true) && proof.get(b) == Some(&true));
            proof.insert(r.id, allowed);
        }
        proof
    }

    fn cache(&self) -> MutexGuard<'_, root_cache::Cache> {
        self.root_cache.lock().expect("audit root cache poisoned")
    }

    fn support_flags(&self) -> Arc<root_cache::Support> {
        let mut cache = self.cache();
        if !cache.readable {
            drop(cache);
            return Arc::new(self.support_flags_fresh());
        }
        cache.support.get_or_insert_with(|| Arc::new(self.support_flags_fresh())).clone()
    }

    fn support_flags_fresh(&self) -> root_cache::Support {
        // References only point backwards in the immutable ingest stream. One ordered pass avoids recursion and
        // exponential walks through shared premises, even for adversarially deep relation records.
        let mut flags = self.by_record::<(bool, bool)>();
        let structural = self.structural_grounding();
        let accepted = self.effective_links(&structural);
        for r in &self.data.records {
            let (grounded, established) = if r.kind == RecordKind::Observe {
                let active = structural.get(&r.id) == Some(&true);
                (active, active)
            } else {
                let basis = !r.based_on.is_empty() && r.based_on.iter().all(|b| flags.get(b).is_some_and(|v| v.0));
                let endpoints = r.ends.as_ref().is_none_or(|(a, _, b)| flags.get(a).is_some_and(|v| v.0) && flags.get(b).is_some_and(|v| v.0));
                let established_ends = r.ends.as_ref().is_none_or(|(a, rel, b)| {
                    accepted.contains(&(*a, rel.clone(), *b)) && flags.get(a).is_some_and(|v| v.1) && flags.get(b).is_some_and(|v| v.1)
                });
                let answer = r.kind != RecordKind::Done || r.based_on.iter().all(|b| flags.get(b).is_some_and(|v| v.1));
                let grounded = basis && endpoints && answer;
                (grounded, grounded && established_ends && !matches!(r.kind, RecordKind::Hypothesis | RecordKind::Question | RecordKind::Done))
            };
            flags.insert(r.id, (grounded, established));
        }
        flags
    }

    fn grounded(&self, id: &RecordId) -> bool {
        self.support_flags().get(id).is_some_and(|v| v.0)
    }
    fn answer_support(&self, id: &RecordId) -> bool {
        self.support_flags().get(id).is_some_and(|v| v.1)
    }

    fn basis(&self, names: &[String], actor: &str, directive: &str, observes_only: bool) -> KResult<Vec<RecordId>> {
        if names.is_empty() || names.len() > MAX_REFS {
            return Err(KernelError::new(Code::NoEvidence, "at least one bounded basis reference is required").field("based_on"));
        }
        names
            .iter()
            .map(|n| {
                let id = self.resolve(n, actor, directive)?;
                let record = self.record(&id).expect("resolved");
                if observes_only && record.kind != RecordKind::Observe {
                    return Err(KernelError::new(Code::NotAnEvidence, "basis must name observe records").field("based_on"));
                }
                // an observation directly (Gemini, 01.11.2026: inside a command the support cache is closed, and this check paid a
                // pass over every record per reference, 16 per agent answer)
                let grounded = if record.kind == RecordKind::Observe { self.observe_grounded(record) } else { self.grounded(&id) };
                if !grounded || record.kind == RecordKind::Hypothesis {
                    return Err(KernelError::new(Code::EvidenceNotActive, "basis is not currently grounded").field("based_on"));
                }
                Ok(id)
            })
            .collect()
    }

    #[cfg(any(test, feature = "audit-root-profile", feature = "audit-root-verify"))]
    fn legacy_preimage(&self) -> String {
        let support = self.support_flags_fresh();
        let records: Vec<_> = self
            .data
            .records
            .iter()
            .map(|r| {
                let mut v = record_value(r);
                v["grounded"] = json!(support.get(&r.id).is_some_and(|v| v.0));
                if let Some(b) = self.data.evidence.get(&r.id) {
                    v["evidence"] = json!({"id":to_hex(&b.evidence),"version":to_hex(&b.version),"span":[b.start,b.end]});
                }
                v
            })
            .collect();
        let locals: Vec<_> = self.data.locals.iter().map(|((a, d, l), r)| json!([a, d, l, to_hex(&r.0)])).collect();
        let mappings: Vec<_> = self.data.mappings.iter().map(|((r, t, c), s)| json!([to_hex(&r.0), t, to_hex(&c.0), s])).collect();
        let receipts: Vec<_> = self.data.receipts.iter().map(|((a, id), r)| json!([a, id, to_hex(&r.request_hash), r.outcome.value()])).collect();
        let ordinals: Vec<_> = self.data.task_ordinals.iter().map(|((a, d), n)| json!([a, d, n])).collect();
        let acceptance: Vec<_> =
            self.data.acceptance_basis.iter().map(|(id, proof)| json!([to_hex(&id.0), proof.iter().map(|r| to_hex(&r.0)).collect::<Vec<_>>()])).collect();
        let value = json!({"format":"r2r-audit-state/1","run_id":self.data.run_id,"manifest_hash":to_hex(&self.data.manifest_hash),"source_mode":self.data.source_mode,
            "source_documents":self.data.source_documents,"ontology":self.data.ontology.to_value(),"records":records,"locals":locals,"ordinals":ordinals,"mappings":mappings,
            "links":self.data.links.values().map(link_value).collect::<Vec<_>>(),"decisions":self.data.decisions,"acceptance_basis":acceptance,
            "receipts":receipts,"checkpoints":self.data.checkpoints});
        to_jcs(&value)
    }

    fn visible_in_scope(&self, id: &RecordId, scope: &Scope) -> bool {
        let mut visible = self.by_record();
        for record in &self.data.records {
            let allowed = if record.kind == RecordKind::Observe {
                record.doc_id.as_ref().is_some_and(|doc| {
                    scope.docs.contains(doc)
                        && self
                            .data
                            .evidence
                            .get(&record.id)
                            .is_some_and(|b| scope.ranges.is_empty() || scope.ranges.iter().any(|(d, a, z)| d == doc && *a <= b.start && b.end <= *z))
                })
            } else {
                !record.based_on.is_empty()
                    && record.based_on.iter().all(|b| visible.get(b) == Some(&true))
                    && record.ends.as_ref().is_none_or(|(a, _, b)| visible.get(a) == Some(&true) && visible.get(b) == Some(&true))
            };
            visible.insert(record.id, allowed);
        }
        visible.get(id) == Some(&true)
    }

    fn add_record(
        &mut self,
        actor: &str,
        directive: &str,
        scope: &Scope,
        allowed_records: Option<&BTreeSet<RecordId>>,
        value: &Value,
        version_rule: bool,
    ) -> KResult<RecordId> {
        let parsed = records::parse(value)?;
        let local_key = (actor.to_string(), directive.to_string(), parsed.local_id.clone());
        if self.data.locals.contains_key(&local_key) {
            return Err(
                KernelError::new(Code::DuplicateLocalId, "local id already belongs to an accepted record; repair only the unaccepted suffix").field("local_id")
            );
        }
        let mut body = parsed.body;
        body.as_object_mut().expect("parser object").remove("local_id");
        let mut based_on = if parsed.based_on.is_empty() { Vec::new() } else { self.basis(&parsed.based_on, actor, directive, true)? };
        if !based_on.is_empty() {
            body["based_on"] = json!(based_on.iter().map(|x| format!("@{}", to_hex(&x.0))).collect::<Vec<_>>());
        }
        let ends = match parsed.ends {
            Some((f, rel, t)) => {
                let from = self.resolve(&f, actor, directive)?;
                let to = self.resolve(&t, actor, directive)?;
                self.validate_link_ends(&from, &rel, &to)?;
                body["from"] = json!(format!("@{}", to_hex(&from.0)));
                body["to"] = json!(format!("@{}", to_hex(&to.0)));
                Some((from, rel, to))
            }
            None => None,
        };
        if parsed.kind == RecordKind::Done {
            if string(&body, "directive_id")? != directive {
                return Err(bad("directive_id", "done must name its current directive"));
            }
            let answers = strings(&body, "answer_ids")?;
            if answers.is_empty() && body["outcome"] != "unknown" {
                return Err(bad("answer_ids", "an answered outcome requires an answer; unknown may explicitly have none"));
            }
            based_on = answers.iter().map(|n| self.resolve(n, actor, directive)).collect::<KResult<Vec<_>>>()?;
            for id in &based_on {
                let r = self.record(id).expect("resolved");
                if !self.answer_support(id) {
                    return Err(bad("answer_ids", "answer support must be grounded and cannot be a hypothesis, question or done"));
                }
                if let Some((from, rel, to)) = &r.ends {
                    let link = self.data.links.values().find(|l| l.from == *from && l.to == *to && l.rel == *rel);
                    if !link.is_some_and(|l| l.status == LinkStatus::Accepted) {
                        return Err(bad("answer_ids", "a proposed relation is not accepted answer support"));
                    }
                }
            }
            body["answer_ids"] = json!(based_on.iter().map(|x| format!("@{}", to_hex(&x.0))).collect::<Vec<_>>());
        }
        let mut references = based_on.clone();
        if let Some((a, _, b)) = &ends {
            references.extend([*a, *b]);
        }
        for reference in references {
            let prior = self.record(&reference).expect("resolved reference");
            let own_prefix = prior.author == actor && prior.directive == directive;
            let allowed = match allowed_records {
                Some(issued) => issued.contains(&reference) || own_prefix,
                None => self.visible_in_scope(&reference, scope),
            };
            if !allowed {
                return Err(bad("reference", "record was not issued in this context or allowed document scope"));
            }
        }
        let ordinal_key = (actor.to_string(), directive.to_string());
        let ordinal = self.data.task_ordinals.get(&ordinal_key).copied().unwrap_or(0).checked_add(1).ok_or_else(|| bad("index", "ordinal exhausted"))?;
        let seq = self.data.records.len() as u64 + 1;
        let mut binding = None;
        let (doc_id, quote) = if parsed.kind == RecordKind::Observe {
            let doc_id = string(&body, "doc_id")?.to_string();
            let quote = body["exact_quote"].as_str().expect("parser quote").to_string();
            let span = quote_span(scope, &doc_id, self.session.arena.doc(&doc_id).map(|d| d.bytes.as_slice()), &quote)?;
            let doc = self.session.arena.doc(&doc_id).expect("quote_span found the document");
            let version = doc.version_id;
            if let Some(hit) = self
                .data
                .withdrawn
                .get(&doc_id)
                .into_iter()
                .flatten()
                .flat_map(|text| occurrences_around(&doc.bytes, text, &span))
                .find(|o| o.start < span.end && span.start < o.end)
            {
                return Err(KernelError::new(Code::EvidenceRevoked, "this quote overlaps withdrawn text: quote other text or drop the line")
                    .field("exact_quote")
                    .expected(json!({"withdrawn_span":[hit.start,hit.end]}))
                    .obligation(json!({"action":"quote_other_text_or_drop_the_line"})));
            }
            let mut fork = None;
            if self.in_place {
                self.session.reset_transients();
            } else {
                fork = Some(self.fork_session()?);
            }
            let staged = fork.as_mut().unwrap_or(&mut self.session);
            let event = json!({"seq":staged.last_seq+1,"op":"bind_evidence","local_id":format!("audit_observe_{seq}"),"doc_id":doc_id,"exact_quote":quote});
            let applied = staged.apply_line(&to_jcs(&event))?;
            let evidence = applied.node.ok_or_else(|| bad("evidence", "engine did not return an evidence id"))?;
            let bound = EvidenceBinding { evidence, version, start: span.start, end: span.end };
            body["evidence_id"] = json!(to_hex(&evidence));
            body["document_version"] = json!(to_hex(&version));
            binding = Some((fork, bound));
            (Some(doc_id), Some(quote))
        } else {
            (None, None)
        };
        let id = records::record_id(&body, actor, directive, ordinal);
        if self.record(&id).is_some() {
            return Err(bad("record_id", "record identity collision"));
        }
        if let Some((from, rel, to)) = &ends {
            if version_rule {
                self.version_relation_line(actor, directive, &parsed.local_id, *from, rel, *to, &based_on)?;
            }
            self.add_link(actor, from, rel, to, &based_on)?;
        }
        if let Some((fork, bound)) = binding {
            if let Some(session) = fork {
                self.session = session;
            }
            self.data.evidence.insert(id, bound);
        }
        self.data.records.push(RecordView {
            id,
            seq,
            kind: parsed.kind,
            author: actor.into(),
            directive: directive.into(),
            doc_id,
            quote,
            terms: parsed.terms,
            text: parsed.text,
            status: parsed.stance,
            based_on,
            ends,
            body,
        });
        if let Some(d) = self.dirty() {
            d.locals.insert(local_key.clone());
            d.ordinals.insert(ordinal_key.clone());
        }
        self.data.locals.insert(local_key, id);
        self.data.task_ordinals.insert(ordinal_key, ordinal);
        Ok(id)
    }

    fn submit(&mut self, actor: &str, command: &Value) -> KResult<Outcome> {
        let version_rule = match command.get("version_rule") {
            None => false,
            Some(rule) if rule == super::versions::RELATION_RULE => true,
            Some(_) => return Err(bad("version_rule", "unknown version relation admission rule")),
        };
        let directive = string(command, "directive")?;
        let scope = scope_from_value(&command["scope"])?;
        self.version_scope(actor, directive, &scope)?;
        let allowed_records = match command.get("allowed_records").filter(|v| !v.is_null()) {
            None => None,
            Some(_) => Some(
                strings(command, "allowed_records")?
                    .iter()
                    .map(|n| {
                        let id = RecordId(from_hex(n).ok_or_else(|| bad("allowed_records", "issued references must use full ids"))?);
                        if self.record(&id).is_none() {
                            return Err(bad("allowed_records", "issued record does not exist"));
                        }
                        Ok(id)
                    })
                    .collect::<KResult<BTreeSet<_>>>()?,
            ),
        };
        let lines = command["lines"].as_array().ok_or_else(|| bad("lines", "expected an array"))?;
        if lines.len() > MAX_REFS {
            return Err(bad("lines", "batch exceeds 256 records"));
        }
        let mut report = SubmitReport::default();
        for (i, line) in lines.iter().enumerate() {
            match self.add_record(actor, directive, &scope, allowed_records.as_ref(), line, version_rule) {
                Ok(id) => report.accepted.push(id),
                Err(error) => {
                    report.failed_index = Some(i);
                    report.error = Some(error);
                    break;
                }
            }
        }
        Ok(Outcome::Records(report))
    }

    fn validate_link_ends(&self, from: &RecordId, rel: &str, to: &RecordId) -> KResult<()> {
        if !RELATIONS.contains(&rel) || !self.data.ontology.record_relation(rel) {
            return Err(bad("rel", "relation is not declared with record-to-record domains in the audit ontology"));
        }
        let a = self.record(from).ok_or_else(|| bad("from", "unknown record"))?;
        let b = self.record(to).ok_or_else(|| bad("to", "unknown record"))?;
        if from == to {
            return Err(bad("to", "self links are not permitted"));
        }
        if matches!(a.kind, RecordKind::Question | RecordKind::Done) || matches!(b.kind, RecordKind::Question | RecordKind::Done) {
            return Err(bad("rel", "questions and terminal answers are not assertion endpoints"));
        }
        if rel == "supersedes" {
            let mut stack = vec![*to];
            let mut seen = BTreeSet::new();
            while let Some(id) = stack.pop() {
                if id == *from {
                    return Err(bad("rel", "supersedes would form a cycle"));
                }
                if seen.insert(id) {
                    stack.extend(self.data.links.values().filter(|l| l.from == id && l.rel == "supersedes" && l.status != LinkStatus::Rejected).map(|l| l.to));
                }
            }
        }
        Ok(())
    }

    fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> KResult<LinkView> {
        self.validate_link_ends(from, rel, to)?;
        let proof = self.proof_admissibility(&self.structural_grounding());
        if basis.is_empty() || basis.iter().any(|b| proof.get(b) != Some(&true)) {
            return Err(bad("basis", "link basis must be nonempty and currently grounded"));
        }
        let id = LinkId(sha256_parts(&[b"R2R-AUDIT-LINK/1", to_jcs(&json!([to_hex(&from.0), rel, to_hex(&to.0)])).as_bytes()]));
        if let Some(old) = self.data.links.get(&id) {
            return Ok(old.clone());
        }
        let link = LinkView { id, from: *from, rel: rel.into(), to: *to, status: LinkStatus::Proposed, by: by.into(), basis: basis.to_vec() };
        self.data.links.insert(id, link.clone());
        if let Some(d) = self.dirty() {
            d.links.insert(id);
        }
        Ok(link)
    }
}

fn scope_value(scope: &Scope) -> Value {
    json!({"docs":scope.docs,"topic":scope.topic,"ranges":scope.ranges})
}

fn scope_from_value(v: &Value) -> KResult<Scope> {
    let docs = strings(v, "docs")?;
    let topic = match &v["topic"] {
        Value::Null => None,
        Value::String(s) => {
            identifier(s, "topic")?;
            Some(s.clone())
        }
        _ => return Err(bad("topic", "expected string or null")),
    };
    let ranges = v["ranges"].as_array().ok_or_else(|| bad("ranges", "expected an array"))?;
    if ranges.len() > MAX_REFS {
        return Err(bad("ranges", "too many ranges"));
    }
    let mut out = Vec::new();
    for r in ranges {
        let a = r.as_array().filter(|a| a.len() == 3).ok_or_else(|| bad("ranges", "expected [doc_id,start,end]"))?;
        let d = a[0].as_str().ok_or_else(|| bad("ranges", "expected doc id"))?;
        let start = a[1].as_u64().and_then(|n| usize::try_from(n).ok()).ok_or_else(|| bad("ranges", "expected integer byte offset"))?;
        let end = a[2].as_u64().and_then(|n| usize::try_from(n).ok()).ok_or_else(|| bad("ranges", "expected integer byte offset"))?;
        if start >= end || !docs.iter().any(|x| x == d) {
            return Err(bad("ranges", "range must be nonempty and belong to a scoped document"));
        }
        out.push((d.into(), start, end));
    }
    Ok(Scope { docs, topic, ranges: out })
}

/// A durable audit session. `new` is read-only until a v2 journal has been attached with `create`/`open`.
pub struct AuditState {
    core: Core,
    journal: Option<AuditJournal>,
    // Read-only projection of committed checkpoint frames; not part of the audit root or WAL format.
    telemetry_frames: Vec<Value>,
    // The control profiles `--build-scope concepts|none`: no link between records is created by any path.
    // A run policy set by the server from its bound coverage configuration; not part of the audit root or WAL format.
    links_off: bool,
    /// What the genesis of a `/3` journal named besides its sources; `None` for a journal of the first formats.
    genesis: Option<GenesisMeta>,
    /// The base ontology of a run prepared without a journal yet (`prepare_from_docs`, `prepare_from_manifest`), for its genesis.
    pending_base: Option<Value>,
    /// The hash of every frame of a `/3` journal, genesis first: a seal names the log tree over them.
    frames: Vec<Hash>,
    /// The frames up to and with the last seal (0: none yet; the genesis counts then), and the interval of automatic seals
    /// (`set_seal_every`): a seal is due once `k` frames follow the last one.
    sealed_at: usize,
    seal_every: Option<usize>,
    /// A seal was due and not written (its commit failed, or a restart came between a circle's phase change and its seal): the
    /// next command writes it. Never part of a root or of a frame (Codex review of 43447f4, S2-02).
    seal_pending: bool,
    /// The seals in the journal so far: the frames each names (`log_size`) and its hash, for the reading tools (SPEC_V02_STEP3).
    /// Read from the journal, never part of a root.
    seals: Vec<(usize, Hash)>,
    /// The key that signs each new seal and the folder its checkpoints go to (SPEC_V02_STEP4), and the seals left unsigned.
    signer: Option<(super::sign::NoteSigner, PathBuf)>,
    sign_failures: Vec<(usize, String)>,
}

/// What `AuditState::verify` read: the bytes (a torn tail included), the complete frames among them, their SHA-256 and the
/// chain head after the last complete frame.
#[derive(Clone, Debug)]
pub struct VerifiedJournal {
    pub bytes: u64,
    pub complete_bytes: u64,
    pub sha256: Hash,
    pub wal_head: Hash,
    /// Entries that put a document after the start: only a journal of supplied documents can hold one.
    pub document_puts: usize,
}

/// The documents a committed command put: a batch stops at a failed operation, and what follows it was not applied.
fn document_puts(command: &Value, result: &Value) -> usize {
    match command["kind"].as_str() {
        Some("put_document") => 1,
        Some("batch") => {
            let (operations, results) = (command["operations"].as_array().into_iter().flatten(), result["results"].as_array().into_iter().flatten());
            operations.zip(results).take(result["accepted_operations"].as_u64().unwrap_or(0) as usize).map(|(o, r)| document_puts(o, r)).sum()
        }
        _ => 0,
    }
}

/// The hashes of the two projections' rows, each in its own domain (SPEC_V02_STEP2 section 6).
fn projection_hashes_of(status: &[Value], pairs: &[Value]) -> (Hash, Hash) {
    (sha256_parts(&[b"R2R-PROJ-STATUS/2\0", to_jcs(&json!(status)).as_bytes()]), sha256_parts(&[b"R2R-PROJ-DEPS/2\0", to_jcs(&json!(pairs)).as_bytes()]))
}

/// The session root that binds an engine root and an audit root (the `session_root` of a state and of a terminal receipt) in a
/// journal of the first formats.
pub fn session_root_of(engine_root: &Hash, audit_root: &Hash) -> Hash {
    sha256_parts(&[b"R2R-AUDIT-SESSION/1", engine_root, audit_root])
}

/// The session root of a `/3` journal, whose audit root is `r2r-state-root/2`.
pub fn session_root_v2(engine_root: &Hash, audit_root: &Hash) -> Hash {
    sha256_parts(&[b"R2R-AUDIT-SESSION/2\0", engine_root, audit_root])
}

const SEAL_KEYS: [&str; 8] = ["audit_root", "engine_root", "format", "log_root", "log_size", "projections", "run_id", "wal_head"];

/// `H("R2R-SEAL/2", JCS(P))`: the hash a signature and the third line of a `tlog-checkpoint` will name (step 4).
pub fn seal_hash(seal: &Value) -> Hash {
    sha256_parts(&[b"R2R-SEAL/2\0", to_jcs(seal).as_bytes()])
}

/// The part of a seal only the journal knows: it names the frames before it, their log tree and the last of them.
fn check_seal_log(seal: &Value, frames: &[Hash]) -> KResult<()> {
    let size = seal["log_size"].as_u64();
    if size != Some(frames.len() as u64)
        || seal["wal_head"] != json!(to_hex(frames.last().expect("the genesis frame")))
        || seal["log_root"] != json!(to_hex(&super::trees::log_root(frames)))
    {
        return Err(bad("seal", "a seal names the frames before it: their number, their log tree and the last of them"));
    }
    Ok(())
}

/// The checks of a `/3` genesis beyond the fields both formats share: the exact list of fields, the formats and rules it names,
/// the questions, the settings hash and the size of the operator's object. Returns what it named.
fn genesis_v3_meta(genesis: &Value) -> KResult<GenesisMeta> {
    let object = genesis.as_object().ok_or_else(|| bad("wal", "the genesis must be an object"))?;
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != GENESIS_V3_KEYS {
        return Err(bad("wal", "a r2r-audit-genesis/3 names exactly its fields; this one has missing or unknown fields"));
    }
    for (key, want) in [("rules_version", RULES_VERSION), ("state_root_format", state_root::ROOT_FORMAT), ("seal_format", SEAL_FORMAT)] {
        if genesis[key] != want {
            return Err(bad(key, format!("this kernel replays {want}; the journal names another")));
        }
    }
    if !genesis["questions"].is_array() {
        return Err(bad("questions", "the genesis names the questions of the run as an array"));
    }
    let operator_meta = match &genesis["operator_meta"] {
        Value::Null => None,
        meta @ Value::Object(_) if to_jcs(meta).len() <= MAX_OPERATOR_META_BYTES => Some(meta.clone()),
        _ => return Err(bad("operator_meta", format!("operator_meta is an object of at most {MAX_OPERATOR_META_BYTES} bytes, or null"))),
    };
    Ok(GenesisMeta { questions: genesis["questions"].clone(), settings_hash: kernel_hash(genesis, "settings_hash", true)?, operator_meta })
}

impl AuditState {
    /// Turn links off for this run (the control profiles `--build-scope concepts|none`): every command that would create a link
    /// is refused before it is journaled.
    pub fn set_links_off(&mut self, off: bool) {
        self.links_off = off;
    }

    pub fn new(base_ontology: &Value, docs: &[(String, Vec<u8>)]) -> KResult<Self> {
        let ontology = AuditOntology::from_value(base_ontology)?;
        let engine_ontology = Ontology::from_value(&json!({"entities":[],"predicates":[],"rules":[]})).map_err(|e| bad("engine_ontology", e.to_string()))?;
        let mut session = Session::new(engine_ontology, CdcParams::default());
        let mut names = BTreeSet::new();
        for (id, bytes) in docs {
            identifier(id, "doc_id")?;
            if !names.insert(id) {
                return Err(bad("docs", "duplicate doc_id"));
            }
            if bytes.len() > MAX_DOC_BYTES || std::str::from_utf8(bytes).is_err() {
                return Err(bad("docs", "documents must be UTF-8 and at most 16 MiB"));
            }
            session.put_document(id, bytes);
        }
        let engine_root = session.engine.root();
        Ok(Self {
            core: Core {
                session,
                engine_root,
                root_cache: Mutex::default(),
                state_tree: Mutex::new(None),
                in_place: false,
                data: Data {
                    run_id: "unbound".into(),
                    manifest_hash: ZERO_HASH,
                    source_mode: "opaque".into(),
                    source_documents: docs
                        .iter()
                        .map(|(id, bytes)| (id.clone(), json!({"kind":"opaque","doc_id":id,"raw_sha256":to_hex(&sha256(bytes))})))
                        .collect(),
                    ontology,
                    records: Vec::new(),
                    locals: BTreeMap::new(),
                    task_ordinals: BTreeMap::new(),
                    evidence: ById::default(),
                    mappings: BTreeMap::new(),
                    links: BTreeMap::new(),
                    acceptance_basis: BTreeMap::new(),
                    decisions: Vec::new(),
                    receipts: BTreeMap::new(),
                    checkpoints: BTreeMap::new(),
                    withdrawal_closes_bytes: true,
                    withdrawn: BTreeMap::new(),
                    fates: BTreeMap::new(),
                    closed: false,
                },
            },
            journal: None,
            telemetry_frames: Vec::new(),
            links_off: false,
            genesis: None,
            pending_base: None,
            frames: Vec::new(),
            sealed_at: 0,
            seal_pending: false,
            seal_every: None,
            seals: Vec::new(),
            signer: None,
            sign_failures: Vec::new(),
        })
    }

    /// A new run with a `/3` journal and the default genesis (no questions, empty settings): the library's form.
    pub fn create(path: &Path, base_ontology: &Value, docs: &[(String, Vec<u8>)], run_id: &str, manifest_hash: Hash) -> KResult<Self> {
        Self::create_with(path, base_ontology, docs, run_id, manifest_hash, &GenesisSpec::default())
    }

    /// A new run with a `/3` journal whose genesis names `spec`.
    pub fn create_with(path: &Path, base_ontology: &Value, docs: &[(String, Vec<u8>)], run_id: &str, manifest_hash: Hash, spec: &GenesisSpec) -> KResult<Self> {
        let mut state = Self::prepare_run(base_ontology, docs, run_id, manifest_hash)?;
        state.start_journal(path, spec)?;
        Ok(state)
    }

    /// A new run without a journal yet: everything the server checks before the genesis is written (`start_journal`).
    fn prepare_run(base_ontology: &Value, docs: &[(String, Vec<u8>)], run_id: &str, manifest_hash: Hash) -> KResult<Self> {
        identifier(run_id, "run_id")?;
        let mut state = Self::new(base_ontology, docs)?;
        state.core.data.run_id = run_id.into();
        state.core.data.manifest_hash = manifest_hash;
        state.pending_base = Some(base_ontology.clone());
        Ok(state)
    }

    /// Write the genesis of a prepared run: a `/3` journal at `path` that names `spec`. Only a prepared run without a journal
    /// starts one, once.
    pub fn start_journal(&mut self, path: &Path, spec: &GenesisSpec) -> KResult<()> {
        let base = self.pending_base.clone().ok_or_else(|| bad("wal", "only a prepared run without a journal starts one"))?;
        self.begin_v3(spec)?;
        self.attach_new_journal(path, &base)?;
        self.pending_base = None;
        Ok(())
    }

    /// Make this new state one of a `/3` journal: its genesis names `spec`, its root is `r2r-state-root/2`.
    fn begin_v3(&mut self, spec: &GenesisSpec) -> KResult<()> {
        if !spec.questions.is_array() {
            return Err(bad("questions", "the questions of a run are an array"));
        }
        if spec.operator_meta.as_ref().is_some_and(|m| !m.is_object() || to_jcs(m).len() > MAX_OPERATOR_META_BYTES) {
            return Err(bad("operator_meta", format!("operator_meta is an object of at most {MAX_OPERATOR_META_BYTES} bytes")));
        }
        self.genesis =
            Some(GenesisMeta { questions: spec.questions.clone(), settings_hash: settings_hash(&spec.settings), operator_meta: spec.operator_meta.clone() });
        *self.core.state_tree.get_mut().expect("state tree poisoned") = Some(state_root::StateTree::build(&self.core.data));
        self.core.root_cache = Mutex::default();
        Ok(())
    }

    /// A run on supplied files, each named by its path inside the set. They are bound by their bytes alone: no repository stands behind
    /// them. In order of the names, so that the same files give the same roots however they were found.
    pub fn create_from_docs(path: &Path, base_ontology: &Value, run_id: &str, docs: Vec<(String, Vec<u8>)>) -> KResult<Self> {
        Self::create_from_docs_with(path, base_ontology, run_id, docs, &GenesisSpec::default())
    }

    pub fn create_from_docs_with(path: &Path, base_ontology: &Value, run_id: &str, docs: Vec<(String, Vec<u8>)>, spec: &GenesisSpec) -> KResult<Self> {
        let mut state = Self::prepare_from_docs(base_ontology, run_id, docs)?;
        state.start_journal(path, spec)?;
        Ok(state)
    }

    /// `create_from_docs` without the journal: `start_journal` writes it.
    pub fn prepare_from_docs(base_ontology: &Value, run_id: &str, mut docs: Vec<(String, Vec<u8>)>) -> KResult<Self> {
        if let Some((id, _)) = docs.iter().find(|(id, _)| id.len() > MAX_DOC_NAME_BYTES) {
            return Err(bad("doc_id", format!("a document name takes at most {MAX_DOC_NAME_BYTES} bytes: {id}")));
        }
        docs.sort_by(|a, b| a.0.cmp(&b.0));
        let hashes: Vec<String> = docs.iter().map(|(_, bytes)| to_hex(&sha256(bytes))).collect();
        let set = super::sources::docs_set_hash(docs.iter().zip(&hashes).map(|((id, _), hash)| (id.as_str(), hash.as_str())));
        Self::prepare_run(base_ontology, &docs, run_id, set)
    }

    /// The genesis of this state's journal: `/3` with the fields of `GENESIS_V3_KEYS` when the state is of that format, else the
    /// first formats' (a scratch copy of an old journal's state, `replay_prefixes`).
    fn attach_new_journal(&mut self, path: &Path, base_ontology: &Value) -> KResult<()> {
        let container = build_container(&mut self.core.session);
        let mut genesis = json!({"run_id":self.core.data.run_id,"manifest_hash":to_hex(&self.core.data.manifest_hash),"source_mode":self.core.data.source_mode,"base_ontology":base_ontology,
            "source_documents":self.core.data.source_documents,
            "engine_container_hex":to_hex(&container),"engine_root":to_hex(&self.engine_root()),"audit_root":to_hex(&self.audit_root())});
        self.journal = Some(match &self.genesis {
            Some(meta) => {
                genesis["format"] = json!(GENESIS_FORMAT_V3);
                genesis["rules_version"] = json!(RULES_VERSION);
                genesis["state_root_format"] = json!(state_root::ROOT_FORMAT);
                genesis["seal_format"] = json!(SEAL_FORMAT);
                genesis["questions"] = meta.questions.clone();
                genesis["settings_hash"] = json!(to_hex(&meta.settings_hash));
                genesis["operator_meta"] = meta.operator_meta.clone().unwrap_or(Value::Null);
                AuditJournal::create(path, &genesis, FrameFormat::V3, Some(&super::trees::records_root(&[])))?
            }
            None => {
                genesis["format"] = json!(if self.core.data.withdrawal_closes_bytes { GENESIS_FORMAT } else { GENESIS_FORMAT_EXACT_SPAN });
                AuditJournal::create(path, &genesis, FrameFormat::V2, None)?
            }
        });
        self.frames = self.journal.as_ref().map(|j| vec![j.head()]).unwrap_or_default();
        Ok(())
    }

    /// Prepare only explicitly selected, byte-verified report documents. Lexical SHA/PR references remain unresolved.
    pub fn create_from_manifest(path: &Path, base_ontology: &Value, run_id: &str, manifest_bytes: &[u8], selected: &[(String, Vec<u8>)]) -> KResult<Self> {
        Self::create_from_manifest_with(path, base_ontology, run_id, manifest_bytes, selected, &GenesisSpec::default())
    }

    pub fn create_from_manifest_with(
        path: &Path,
        base_ontology: &Value,
        run_id: &str,
        manifest_bytes: &[u8],
        selected: &[(String, Vec<u8>)],
        spec: &GenesisSpec,
    ) -> KResult<Self> {
        let mut state = Self::prepare_from_manifest(base_ontology, run_id, manifest_bytes, selected)?;
        state.start_journal(path, spec)?;
        Ok(state)
    }

    /// `create_from_manifest` without the journal: `start_journal` writes it.
    pub fn prepare_from_manifest(base_ontology: &Value, run_id: &str, manifest_bytes: &[u8], selected: &[(String, Vec<u8>)]) -> KResult<Self> {
        let sources = super::sources::prepare(manifest_bytes, selected)?;
        let mut state = Self::prepare_run(base_ontology, &sources.docs, run_id, sources.manifest_hash)?;
        state.core.data.source_mode = "git_manifest".into();
        state.core.data.source_documents = sources.identities;
        Ok(state)
    }

    /// A run with a journal of the first formats, as 0.1 wrote them: the tests of the `/1` root and of those frames.
    #[cfg(test)]
    pub(crate) fn create_v2(path: &Path, base_ontology: &Value, docs: &[(String, Vec<u8>)], run_id: &str, manifest_hash: Hash) -> KResult<Self> {
        let mut state = Self::prepare_run(base_ontology, docs, run_id, manifest_hash)?;
        state.pending_base = None;
        state.attach_new_journal(path, base_ontology)?;
        Ok(state)
    }

    /// Offline measurement only (`examples/v02_rewrite.rs`), never a migration a server does: the commands of the recorded journal at
    /// `old` run again, in order and under their actors and ids, into a new journal at `new`, of the `/3` format when `v3` and of
    /// the first formats otherwise. Every outcome must equal the recorded one, so only a journal under the rule of closed bytes
    /// (`r2r-audit-genesis/2`) can be written as `/3`. Returns the entries written.
    #[doc(hidden)]
    pub fn rewrite_recorded(old: &Path, new: &Path, v3: bool) -> KResult<usize> {
        Self::rewrite_recorded_sealed(old, new, v3, false)
    }

    /// `rewrite_recorded`, and with `sealed` a `/3` journal written as a 0.2 server writes one: a seal every 256 frames and at each
    /// phase of a circle, and a seal and a close at the end. The reference journals of the independent verifier come from it
    /// (`examples/v02_reference_journals.rs`).
    #[doc(hidden)]
    pub fn rewrite_recorded_sealed(old: &Path, new: &Path, v3: bool, sealed: bool) -> KResult<usize> {
        let scan = AuditJournal::read(old)?;
        let genesis = scan.payloads.first().ok_or_else(|| bad("wal", "genesis is required"))?;
        if v3 && genesis["format"] != GENESIS_FORMAT {
            return Err(bad("wal", "only a journal under the rule of closed bytes (r2r-audit-genesis/2) runs again as /3"));
        }
        let first = super::persistence::JournalScan {
            format: scan.format,
            payloads: scan.payloads[..1].to_vec(),
            heads: scan.heads[..1].to_vec(),
            records_roots: scan.records_roots.iter().take(1).copied().collect(),
            bytes: 0,
            complete_bytes: 0,
            sha256: ZERO_HASH,
        };
        let mut copy = Self::replay(&first, &mut |_, _, _| Ok(()))?;
        if v3 {
            copy.begin_v3(&GenesisSpec::default())?;
        }
        copy.attach_new_journal(new, &genesis["base_ontology"])?;
        if v3 && sealed {
            copy.set_seal_every(Some(256));
        }
        for (n, payload) in scan.payloads.iter().enumerate().skip(1) {
            let outcome = copy.commit(string(payload, "actor")?, string(payload, "submission_id")?, &payload["command"])?;
            if outcome.value() != payload["outcome"] {
                return Err(bad("wal", format!("entry {n} ran again to another outcome")));
            }
        }
        if v3 && sealed {
            copy.close_run()?;
        }
        Ok(scan.payloads.len() - 1)
    }

    /// What the genesis of a `/3` journal named; `None` for a journal of the first formats.
    pub fn genesis_meta(&self) -> Option<&GenesisMeta> {
        self.genesis.as_ref()
    }

    /// Whether this state's journal is of the `/3` format.
    pub fn is_v3(&self) -> bool {
        self.genesis.is_some()
    }

    /// Write a seal after every `k` frames of a `/3` journal (`None`: only when asked, `seal`); the server seals every 256.
    pub fn set_seal_every(&mut self, k: Option<usize>) {
        self.seal_every = k.filter(|k| *k > 0);
    }

    /// Write a seal (SPEC_V02_STEP2 section 7): the frames so far, the roots of this state and the hashes of its two projections.
    /// Its outcome holds the seal and its hash. A seal right after another changes nothing and is not written again.
    pub fn seal(&mut self) -> KResult<Value> {
        if !self.is_v3() || self.journal.is_none() {
            return Err(bad("seal", "only a 0.2 journal is sealed"));
        }
        #[cfg(test)]
        if FAIL_SEALS.with(|n| n.replace(n.get().saturating_sub(1)) > 0) {
            return Err(bad("seal", "a seal failed (test)"));
        }
        let n = self.frames.len();
        let (status, dependencies) = self.core.projection_hashes();
        let seal = json!({"format": SEAL_FORMAT, "run_id": self.core.data.run_id, "log_size": n, "log_root": to_hex(&super::trees::log_root(&self.frames)),
            "wal_head": to_hex(&self.frames[n - 1]), "audit_root": to_hex(&self.audit_root()), "engine_root": to_hex(&self.engine_root()),
            "projections": {"status": to_hex(&status), "dependencies": to_hex(&dependencies)}});
        let id = format!("seal-{n}");
        let hash = seal_hash(&seal);
        match self.commit("kernel", &id, &json!({"kind": "seal", "seal": seal}))? {
            Outcome::Value(v) => {
                self.seals.push((n, hash));
                self.write_checkpoint(n);
                self.sealed_at = self.frames.len();
                // a seal written by hand settles a seal that was due, as the replay finds it settled
                self.seal_pending = false;
                Ok(v)
            }
            Outcome::Error(e) => Err(e),
            Outcome::Records(_) => Err(bad("seal", "unexpected records outcome")),
        }
    }

    /// Close the run (`audit_close`): a seal, then a `close` entry, so the run stays closed after a restart.
    pub fn close_run(&mut self) -> KResult<Value> {
        if self.is_closed() {
            return Ok(json!({"closed": true, "already": true}));
        }
        self.seal()?;
        match self.commit("kernel", "audit-close", &json!({"kind": "close"}))? {
            Outcome::Value(v) => Ok(v),
            Outcome::Error(e) => Err(e),
            Outcome::Records(_) => Err(bad("close", "unexpected records outcome")),
        }
    }

    /// Whether a seal was due and is not written yet (the next command writes it).
    pub fn seal_pending(&self) -> bool {
        self.seal_pending
    }

    /// Whether a `close` entry closed the run.
    pub fn is_closed(&self) -> bool {
        self.core.data.closed
    }

    /// The hashes of the status and dependency projections of this state (SPEC_V02_STEP2 section 6).
    pub fn projection_hashes(&self) -> (Hash, Hash) {
        self.core.projection_hashes()
    }

    /// The rows of the status and dependency projections, as their hashes take them (SPEC_V02_STEP2 section 6).
    pub fn projection_rows(&self) -> (Vec<Value>, Vec<Value>) {
        self.core.projection_rows()
    }

    /// The rows of both projections and their hashes, from one pass over the records.
    pub fn projections(&self) -> (Vec<Value>, Vec<Value>, (Hash, Hash)) {
        let (status, pairs) = self.core.projection_rows();
        let hashes = projection_hashes_of(&status, &pairs);
        (status, pairs, hashes)
    }

    /// The seals in the journal so far: the frames each names and its hash.
    pub fn seals(&self) -> &[(usize, Hash)] {
        &self.seals
    }

    /// Sign every seal written from now on (SPEC_V02_STEP4 section 3): into `dir`, `seal-<n>.txt`, the C2SP checkpoint over the
    /// frames up to and with the seal frame, and `verifier.key` beside them, a key the writer puts there and so pins nothing. A
    /// failed write never undoes the seal: it is kept in `sign_failures`, and `sbgk audit-sign` writes it again from the journal.
    pub fn set_checkpoint_signer(&mut self, signer: super::sign::NoteSigner, dir: PathBuf) {
        self.signer = Some((signer, dir));
    }

    /// The seals whose checkpoint could not be written: the frame of each seal and why. The seal stands in the journal either way.
    pub fn sign_failures(&self) -> &[(usize, String)] {
        &self.sign_failures
    }

    fn write_checkpoint(&mut self, n: usize) {
        let Some((signer, dir)) = &self.signer else { return };
        let result = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(dir)?;
            let body = super::sign::checkpoint_body(&super::sign::origin(&self.core.data.run_id), &self.frames[..=n]);
            let note = signer.sign(&body).map_err(|e| std::io::Error::other(e.message))?;
            std::fs::write(dir.join(format!("seal-{n}.txt")), note)?;
            let key = dir.join("verifier.key");
            if !key.exists() {
                std::fs::write(key, format!("{}\n", signer.verifier().text()))?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.sign_failures.push((n, e.to_string()));
        }
    }

    /// The hash of every frame of the `/3` journal this state writes, the genesis first: a signed checkpoint names the log tree
    /// over a prefix of them (SPEC_V02_STEP4). Empty for a state without a journal of that format.
    pub fn frame_hashes(&self) -> &[Hash] {
        &self.frames
    }

    // What a quittance reads of a state (SPEC_V02_STEP5, `proof.rs`).

    /// The records accepted so far, in the order the frames accepted them: a quittance finds a record's frame by counting.
    pub(super) fn record_count(&self) -> usize {
        self.core.data.records.len()
    }

    pub(super) fn record_at(&self, i: usize) -> &RecordView {
        &self.core.data.records[i]
    }

    /// The leaf value `L` of record `i` (SPEC_V02_STEP2 section 2), as the records tree of its frame hashes it.
    pub(super) fn record_leaf_value_at(&self, i: usize) -> Value {
        state_root::record_leaf_value(&self.core.data, &self.core.data.records[i])
    }

    /// An observation's evidence binding: the engine's evidence id, the document version and the bytes `[start, end)`.
    pub(super) fn evidence_binding(&self, id: &RecordId) -> Option<(Hash, Hash, usize, usize)> {
        self.core.data.evidence.get(id).map(|b| (b.evidence, b.version, b.start, b.end))
    }

    /// The canonical bytes of an evidence node of the engine, whose SHA-256 is its id.
    pub(super) fn evidence_node_bytes(&self, evidence: &Hash) -> Option<Vec<u8>> {
        self.core.session.engine.evidence(evidence).map(crate::node::EvidenceNode::encode)
    }

    /// The current version of a document: its id, its chunks and their bytes.
    pub(super) fn current_document(&self, doc_id: &str) -> Option<&crate::arena::DocEntry> {
        self.core.session.arena.doc(doc_id)
    }

    /// The texts withdrawn from a document: a quittance never hands them out.
    pub(super) fn withdrawn_of(&self, doc_id: &str) -> Vec<&[u8]> {
        self.core.data.withdrawn.get(doc_id).into_iter().flatten().map(Vec::as_slice).collect()
    }

    /// The documents whose current text holds one of `terms`, case aside: whether the `about` of a question names anything in the
    /// run's documents. A question whose terms no document holds loses its answer in silence (the architect, 11.11.2026), so the
    /// server says so; a document whose text the run does not hold counts as not holding them.
    pub fn documents_mentioning(&self, terms: &[String]) -> Vec<String> {
        let terms: Vec<String> = terms.iter().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).collect();
        let arena = &self.core.session.arena;
        arena
            .doc_ids()
            .filter(|id| {
                arena.doc(id).is_some_and(|d| {
                    let text = String::from_utf8_lossy(&d.bytes).to_lowercase();
                    terms.iter().any(|t| text.contains(t.as_str()))
                })
            })
            .cloned()
            .collect()
    }

    /// The frames of the journal this state writes, the genesis included; `None` for a state without one (a replay).
    pub fn entries(&self) -> Option<usize> {
        self.journal.as_ref().map(|j| j.sequence() as usize + 1)
    }

    /// The withdrawn texts: document, SHA-256 and length of each, never the text (the reading tools name a withdrawal by these).
    pub fn withdrawn_texts(&self) -> Vec<(String, Hash, usize)> {
        self.core.data.withdrawn.iter().flat_map(|(doc, texts)| texts.iter().map(move |t| (doc.clone(), sha256(t), t.len()))).collect()
    }

    /// Where an observation's quote is bound (document, version, bytes, whether that version is the document's current one) and,
    /// when the quote no longer stands, why (SPEC_V02_STEP3 section 6), as the command that revoked it recorded it: `withdrawn`
    /// (a withdrawal of text took it, named by the withdrawn text's hash and length and the bytes that overlapped the quote then;
    /// `named` when the record itself was the one withdrawn) or `revoked` (the record was revoked, and no text closed with it, the
    /// rule of the first journals). A quote whose evidence stands on an older version of its document is `version_replaced`. Never
    /// the text of the quote: when it fell, that text is what was withdrawn. `None` for a record that is not an observation.
    pub fn quote_fate(&self, id: &RecordId) -> Option<Value> {
        let b = self.core.data.evidence.get(id)?;
        let r = self.core.record(id)?;
        let doc = r.doc_id.clone()?;
        let on_current = self.core.session.arena.doc(&doc).is_some_and(|d| d.version_id == b.version);
        let mut out = json!({"doc_id": doc, "version": to_hex(&b.version), "start": b.start, "end": b.end, "current_version": on_current});
        if self.core.observe_grounded(r) {
            return Some(out);
        }
        match self.core.data.fates.get(id) {
            // what the revoking command found, never what a later state suggests (Codex review of 2c6864f, S3-01, S3-02)
            Some(Value::Object(fate)) => out.as_object_mut().expect("object").extend(fate.clone()),
            _ if self.core.session.engine.status_of(&b.evidence) != Some(EV_REVOKED) => out["cause"] = json!("version_replaced"),
            _ => out["cause"] = json!("revoked"),
        }
        Some(out)
    }

    pub fn open(path: &Path) -> KResult<Self> {
        Self::recover(path, &mut |_, _, _| Ok(()), true)
    }

    /// A replay of the first `upto` frames this state's own journal holds, read through the writer's handle and never written:
    /// `visit(n, state)` sees the state of the first `n` entries, up to `n = upto`. A live server's `diff` and report `since` take
    /// their earlier point from it (SPEC_V02_STEP3 section 4); the frames after it are not replayed.
    pub fn replay_own(&mut self, upto: usize, visit: &mut dyn FnMut(usize, &AuditState)) -> KResult<()> {
        let mut scan = self.journal.as_mut().ok_or_else(|| bad("wal", "this state writes no journal"))?.scan_own()?;
        scan.keep_first(upto.max(1));
        Self::replay(&scan, &mut |n, state, _| {
            visit(n, state);
            Ok(())
        })
        .map(drop)
    }

    /// Check of a recorded journal (`sbgk audit-verify`): the checks of `open` (frame hashes, genesis sources, every entry
    /// replayed to its committed outcome and roots) on a bounded read-only read of the file, which is never opened for writing
    /// or locked. `visit(n, audit_root, engine_root, wal_head)` sees the state of the first `n` entries and the chain head after
    /// them, for each `n` from the genesis alone to all.
    pub fn verify(path: &Path, visit: &mut dyn FnMut(usize, Hash, Hash, Hash)) -> KResult<(Self, VerifiedJournal)> {
        Self::verify_states(path, &mut |n, state, head| visit(n, state.audit_root(), state.engine_root(), head))
    }

    /// `verify` that hands `visit` the state of the first `n` entries itself, read only, with the chain head after them: the
    /// reading tools take a point of the journal from it (`sbgk audit-read`, SPEC_V02_STEP3).
    pub fn verify_states(path: &Path, visit: &mut dyn FnMut(usize, &AuditState, Hash)) -> KResult<(Self, VerifiedJournal)> {
        let scan = AuditJournal::read(path)?;
        let heads = &scan.heads;
        let state = Self::replay(&scan, &mut |n, state, _| {
            visit(n, state, heads[n - 1]);
            Ok(())
        })?;
        let document_puts =
            scan.payloads.iter().skip(1).filter(|p| p["outcome"]["kind"] != "error").map(|p| document_puts(&p["command"], &p["outcome"]["result"])).sum();
        let read =
            VerifiedJournal { bytes: scan.bytes, complete_bytes: scan.complete_bytes, sha256: scan.sha256, wal_head: heads[heads.len() - 1], document_puts };
        Ok((state, read))
    }

    /// Offline replay of a recorded run only (examples/replay_step1.rs), never a live one: one recovery pass over the WAL at `path`,
    /// checked as `open` checks it, that hands `visit` a writable copy of the state before entry `n` (the WAL's first `n` entries)
    /// for each `n` of `at`, in the order of the WAL and once per occurrence. The k-th copy at `n` writes to a new journal at
    /// `scratch(n, k)`; the file at `path` is never written. A pass costs one recovery, not one per copy.
    #[doc(hidden)]
    pub fn replay_prefixes(path: &Path, at: &[usize], scratch: impl Fn(usize, usize) -> PathBuf, mut visit: impl FnMut(usize, AuditState)) -> KResult<()> {
        let mut want: BTreeMap<usize, usize> = BTreeMap::new();
        for n in at {
            *want.entry(*n).or_default() += 1;
        }
        let mut copies = |n: usize, state: &mut AuditState, genesis: &Value| -> KResult<()> {
            for k in 0..want.get(&n).copied().unwrap_or(0) {
                let mut copy = AuditState {
                    core: state.core.fork()?,
                    journal: None,
                    telemetry_frames: Vec::new(),
                    links_off: false,
                    genesis: state.genesis.clone(),
                    pending_base: None,
                    frames: Vec::new(),
                    sealed_at: 0,
                    seal_pending: false,
                    seal_every: None,
                    seals: Vec::new(),
                    signer: None,
                    sign_failures: Vec::new(),
                };
                copy.attach_new_journal(&scratch(n, k), &genesis["base_ontology"])?;
                visit(n, copy);
            }
            Ok(())
        };
        Self::recover(path, &mut copies, false).map(drop)
    }

    /// Recovery from the WAL at `path`: `visit(n, state, genesis)` before entry `n` is applied and once more after the last; `finish`
    /// readies the journal for writing (a torn tail is cut off), as `open` does.
    fn recover(path: &Path, visit: &mut dyn FnMut(usize, &mut AuditState, &Value) -> KResult<()>, finish: bool) -> KResult<Self> {
        if !finish {
            return Self::replay(&AuditJournal::read(path)?, visit);
        }
        let (mut journal, scan) = AuditJournal::open(path)?;
        let mut state = Self::replay(&scan, visit)?;
        journal.finish_recovery()?;
        state.journal = Some(journal);
        if state.is_v3() {
            state.frames = scan.heads.clone();
        }
        Ok(state)
    }

    /// The records root of the records `self` accepted beyond the first `before`: the frame's tree of SPEC_V02_STEP2 section 2.
    fn records_root_since(&self, before: usize) -> Hash {
        let data = &self.core.data;
        let leaves: Vec<Hash> =
            data.records[before.min(data.records.len())..].iter().map(|r| super::trees::record_leaf(&state_root::record_leaf_value(data, r))).collect();
        super::trees::records_root(&leaves)
    }

    /// Semantic replay of the journal's payloads (genesis first) into a state with no journal attached. A `/3` journal's frames
    /// must carry a `/3` genesis and the records root of what each frame accepted; a `/2` journal a genesis of the first formats.
    fn replay(scan: &super::persistence::JournalScan, visit: &mut dyn FnMut(usize, &mut AuditState, &Value) -> KResult<()>) -> KResult<Self> {
        let payloads = &scan.payloads;
        let genesis = payloads.first().ok_or_else(|| bad("wal", "genesis is required"))?;
        let v3 = scan.format == FrameFormat::V3;
        let known =
            if v3 { genesis["format"] == GENESIS_FORMAT_V3 } else { genesis["format"] == GENESIS_FORMAT || genesis["format"] == GENESIS_FORMAT_EXACT_SPAN };
        if !known {
            return Err(bad("wal", "unsupported audit genesis, or a genesis of another format than its frames"));
        }
        let meta = if v3 { Some(genesis_v3_meta(genesis)?) } else { None };
        let mut state = Self::new(&genesis["base_ontology"], &[])?;
        state.core.data.withdrawal_closes_bytes = genesis["format"] != GENESIS_FORMAT_EXACT_SPAN;
        state.core.data.run_id = string(genesis, "run_id")?.into();
        state.core.data.manifest_hash = kernel_hash(genesis, "manifest_hash", v3)?;
        state.core.data.source_mode = string(genesis, "source_mode")?.into();
        if !matches!(state.core.data.source_mode.as_str(), "opaque" | "git_manifest") {
            return Err(bad("source_mode", "unsupported source identity mode"));
        }
        state.core.data.source_documents = genesis["source_documents"]
            .as_object()
            .ok_or_else(|| bad("source_documents", "genesis must bind source identities"))?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let hex = genesis["engine_container_hex"].as_str().ok_or_else(|| bad("wal", "missing engine genesis"))?;
        let container = decode_hex(hex)?;
        state.core.session = open_session(&container).map_err(|e| bad("wal", e.to_string()))?;
        if state.core.session.arena.doc_ids().count() != state.core.data.source_documents.len() {
            return Err(bad("source_documents", "genesis document identities do not cover the engine documents"));
        }
        for id in state.core.session.arena.doc_ids() {
            let doc = state.core.session.arena.doc(id).expect("listed document");
            let identity = state.core.data.source_documents.get(id).ok_or_else(|| bad("source_documents", "missing document identity"))?;
            if identity["kind"] != state.core.data.source_mode {
                return Err(bad("source_documents", "source identity disagrees with the session mode"));
            }
            if identity["kind"] == "git_manifest" {
                super::sources::verify_identity(id, identity, &doc.bytes)?;
            } else if identity["kind"] != "opaque" || identity["doc_id"] != *id || identity["raw_sha256"] != to_hex(&sha256(&doc.bytes)) {
                return Err(bad("source_documents", "invalid opaque source identity"));
            }
        }
        state.core.engine_root = state.core.session.engine.root();
        if let Some(meta) = meta {
            state.genesis = Some(meta);
            *state.core.state_tree.get_mut().expect("state tree poisoned") = Some(state_root::StateTree::build(&state.core.data));
            if scan.records_roots[0] != super::trees::records_root(&[]) {
                return Err(bad("wal", "the genesis frame accepts no record; its records root must be the empty root"));
            }
        }
        if kernel_hash(genesis, "engine_root", v3)? != state.engine_root() || kernel_hash(genesis, "audit_root", v3)? != state.audit_root() {
            return Err(bad("wal", "genesis roots do not match the recovered state"));
        }
        for (n, payload) in payloads.iter().enumerate().skip(1) {
            visit(n, &mut state, genesis)?;
            let before = state.core.data.records.len();
            let actor = string(payload, "actor")?;
            let request_id = string(payload, "submission_id")?;
            let request_hash = request_hash(actor, &payload["command"]);
            if request_hash != kernel_hash(payload, "request_hash", v3)? {
                return Err(bad("wal", "request hash mismatch"));
            }
            if state.core.data.receipts.contains_key(&(actor.into(), request_id.into())) {
                return Err(bad("wal", "duplicate persisted submission"));
            }
            if v3 {
                kernel_id(actor, request_id, &payload["command"]).map_err(|e| bad("wal", format!("a frame takes an id of the kernel's own: {}", e.message)))?;
                if state.is_closed() {
                    return Err(bad("wal", "a frame after the close: the close is the last frame of a journal"));
                }
            }
            if v3 && payload["command"]["kind"] == "seal" {
                check_seal_log(&payload["command"]["seal"], &scan.heads[..n])?;
                // the frames up to and with the seal itself: the next one is due `k` frames after it
                state.sealed_at = n + 1;
                state.seal_pending = false;
            } else if v3 && phase_changed(&payload["command"], &payload["outcome"]) {
                // a circle's phase changed and no seal follows yet: the next command after the restart writes it
                state.seal_pending = true;
            }
            let outcome = state.prepare_recorded(actor, request_id, payload)?;
            if outcome.value() != payload["outcome"]
                || state.engine_root() != kernel_hash(payload, "engine_root", v3)?
                || state.audit_root() != kernel_hash(payload, "audit_root", v3)?
            {
                return Err(bad("wal", "semantic replay diverged from the committed outcome/roots"));
            }
            if v3 && state.records_root_since(before) != scan.records_roots[n] {
                return Err(bad("wal", "the records root of a frame does not match the records it accepted"));
            }
            if v3 && payload["command"]["kind"] == "seal" && payload["outcome"]["kind"] != "error" {
                state.seals.push((n, seal_hash(&payload["command"]["seal"])));
            }
            state.project_telemetry(payload);
        }
        visit(payloads.len(), &mut state, genesis)?;
        Ok(state)
    }

    fn project_telemetry(&mut self, payload: &Value) {
        let ck = &payload["command"]["checkpoint"];
        let key = ck["key"].as_str().unwrap_or("");
        let result = &payload["outcome"]["result"];
        let reviews = result["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| v["op"] == "ontology_review" || v["review_decision"] == "revise")
            .cloned()
            .collect::<Vec<_>>();
        let checkpoint =
            result["checkpointed"] == true && (key == "audit:circles" || key.starts_with("builder:pool:closed:") || key.starts_with("builder:reuse:"));
        if checkpoint || !reviews.is_empty() {
            self.telemetry_frames.push(json!({"payload":{"command":{"checkpoint":if checkpoint {ck.clone()} else {Value::Null}},"outcome":{"result":{"checkpointed":checkpoint,"results":reviews}},"audit_root":payload["audit_root"]}}));
        }
    }
    /// Snapshot from already committed/replayed state. Never opens the writer-locked WAL through a second reader.
    pub fn circle_telemetry(&self) -> Value {
        json!({"format":"r2r-circle-telemetry/1","frames":self.telemetry_frames,"through_sequence":self.transaction_sequence(),
            "wal_head":self.wal_head().map(|h|to_hex(&h)),"audit_root":to_hex(&self.audit_root()),"complete":true})
    }

    pub fn audit_root(&self) -> Hash {
        self.core.root()
    }
    pub fn engine_root(&self) -> Hash {
        self.core.engine_root
    }
    pub fn session_root(&self) -> Hash {
        self.session_root_for(&self.engine_root(), &self.audit_root())
    }
    /// The session root of these roots under this journal's format (`session_root_v2` for `/3`, else `session_root_of`).
    pub fn session_root_for(&self, engine_root: &Hash, audit_root: &Hash) -> Hash {
        if self.is_v3() {
            session_root_v2(engine_root, audit_root)
        } else {
            session_root_of(engine_root, audit_root)
        }
    }
    pub fn wal_head(&self) -> Option<Hash> {
        self.journal.as_ref().map(AuditJournal::head)
    }
    pub fn transaction_sequence(&self) -> Option<u64> {
        self.journal.as_ref().map(AuditJournal::sequence)
    }
    /// The bytes that recovery cut off the journal's end, and the file beside it that keeps them.
    pub fn dropped_tail(&self) -> Option<(u64, &Path)> {
        self.journal.as_ref().and_then(AuditJournal::dropped_tail)
    }
    pub fn is_grounded(&self, id: &RecordId) -> bool {
        self.core.grounded(id)
    }
    /// Grounded provenance is separate from established answer support (in particular for rejected/proposed relations).
    pub fn is_answer_support(&self, id: &RecordId) -> bool {
        self.core.answer_support(id)
    }
    pub fn source_document(&self, id: &str) -> Option<Value> {
        self.core.data.source_documents.get(id).cloned()
    }
    /// Publication is not inferred from a filename. The ingest order and agent-supplied valid time are separately labeled.
    pub fn record_metadata(&self, id: &RecordId) -> Option<Value> {
        let record = self.core.record(id)?;
        let mut value = record_value(record);
        value["grounded"] = json!(self.is_grounded(id));
        value["answer_support"] = json!(self.is_answer_support(id));
        value["times"] = json!({"observed":{"value":record.seq,"provenance":"kernel_ingest_sequence"},
            "valid":{"value":record.body.get("as_of").cloned().unwrap_or(Value::Null),"provenance":"agent"},
            "published":{"value":Value::Null,"provenance":"not_independently_verified"}});
        Some(value)
    }
    pub fn link_usable(&self, id: &LinkId) -> bool {
        self.core.data.links.get(id).is_some_and(|l| self.core.effective_links(&self.core.structural_grounding()).contains(&(l.from, l.rel.clone(), l.to)))
    }
    /// Actual durable evolution offers and successful builder operations, distinct from semantic correctness.
    pub fn graph_quality_metrics(&self) -> Value {
        let cfg = super::quality::config(self);
        if cfg.is_null() {
            return Value::Null;
        }
        let issued = self
            .core
            .data
            .checkpoints
            .iter()
            .filter(|(k, _)| k.starts_with("builder:evolution:issued:"))
            .map(|(_, v)| v["context"].clone())
            .collect::<Vec<_>>();
        let mut ids = BTreeSet::new();
        let mut operations = 0;
        for card in &issued {
            if let Some(id) = card["card_id"].as_str() {
                for slot in 0..64 {
                    for attempt in 0..256 {
                        let Some(v) = self.receipt_outcome(&format!("{id}:{slot}:{attempt}"), "builder") else { break };
                        if v["error"].is_null() && v["accepted_operations"] == 1 {
                            if let Some(l) = v["results"][0]["id"].as_str().and_then(from_hex).map(LinkId).filter(|l| self.link(l).is_some()) {
                                ids.insert(l);
                                operations += 1;
                            }
                        }
                    }
                }
            }
        }
        let mut proposed = BTreeMap::<String, usize>::new();
        let mut accepted = BTreeMap::<String, usize>::new();
        for l in ids.iter().filter_map(|id| self.link(id)) {
            *proposed.entry(l.rel.clone()).or_default() += 1;
            if l.status == LinkStatus::Accepted && self.link_usable(&l.id) {
                *accepted.entry(l.rel).or_default() += 1;
            }
        }
        // pairs of the frozen plan no reader may take (EVO-01): kept in the plan, never offered, counted here
        // (the plan of the single builder, "builder:pair-plan", or of the circles' pool: in "builder:pool" in its format 1, in format
        // 2 the plan the pool names, never a plan written by a save that did not reach the pool)
        let pool_plan = self.core.data.checkpoints.get("builder:pool").and_then(|c| c["context"]["plan"].as_str().map(super::builder::parallel::plan_key));
        let without_taker = ["builder:pair-plan".to_string(), "builder:pool".to_string()]
            .into_iter()
            .chain(pool_plan)
            .filter_map(|k| self.core.data.checkpoints.get(&k).and_then(|c| c["context"]["pairs"].as_array().cloned()))
            .flatten()
            .filter(|p| p["metadata"]["kind"] == super::quality::evolution::UNASSIGNABLE)
            .filter_map(|p| p["metadata"]["pairs"].as_array().map(Vec::len))
            .sum::<usize>();
        json!({"config":cfg,"evolution":{"cards_issued":issued.len(),"pairs_issued":issued.iter().filter_map(|c|c["pairs"].as_array()).map(Vec::len).sum::<usize>(),
            "pairs_without_a_taker":without_taker,"link_operations":operations,"unique_links":ids.len(),"links_proposed_by_type":proposed,"links_accepted_and_usable_by_type":accepted,
            "explicit_none":self.core.data.checkpoints.keys().filter(|k|k.starts_with("builder:evolution:none:")).count()},
            "stale_suspect":super::quality::stale::suspects(self).iter().map(|id|super::quality::annotate(self,*id)).collect::<Vec<_>>()})
    }
    pub fn evidence_id(&self, id: &RecordId) -> Option<Hash> {
        self.core.data.evidence.get(id).map(|b| b.evidence)
    }
    pub fn checkpoint(&self, key: &str) -> Option<Value> {
        self.core.data.checkpoints.get(key).cloned()
    }
    /// Read-only receipt lookup for `submit_operations_id`: the same request finds its stored outcome, nothing is appended.
    pub fn operations_receipt(&self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Prior {
        let Some(receipt) = self.core.data.receipts.get(&(actor.into(), id.into())) else { return Prior::Free };
        let command = json!({"kind":"batch","operations":operations,"checkpoint":checkpoint});
        if receipt.request_hash != request_hash(actor, &command) {
            return Prior::Other;
        }
        Prior::Same(match &receipt.outcome {
            Outcome::Value(v) => Ok(v.clone()),
            Outcome::Error(e) => Err(e.clone()),
            Outcome::Records(_) => Err(bad("command", "unexpected outcome")),
        })
    }
    /// The run id and the corpus manifest hash, from the genesis.
    pub fn run_id(&self) -> &str {
        &self.core.data.run_id
    }
    pub fn manifest_hash(&self) -> Hash {
        self.core.data.manifest_hash
    }

    /// `git_manifest` (pinned sources) or `opaque` (supplied documents).
    pub fn source_mode(&self) -> &str {
        &self.core.data.source_mode
    }

    pub fn source_document_count(&self) -> usize {
        self.core.data.source_documents.len()
    }

    /// Whether the documents as they stand now are the set this run's `manifest_hash` names. Computed here, not read: a run started on
    /// a folder says yes while its documents are those of the start, also when one changed and came back. A run of the library may
    /// hold any value there, and then says no from the start.
    pub fn docs_set_matches(&self) -> bool {
        let documents = &self.core.data.source_documents;
        let pairs = documents.iter().map(|(id, identity)| (id.as_str(), identity["raw_sha256"].as_str().unwrap_or_default()));
        self.core.data.manifest_hash == super::sources::docs_set_hash(pairs)
    }
    /// Read-only: `link_usable` of every link, computed in one pass.
    pub fn usable_links(&self) -> BTreeSet<LinkId> {
        let edges = self.core.effective_links(&self.core.structural_grounding());
        self.core.data.links.values().filter(|l| edges.contains(&(l.from, l.rel.clone(), l.to))).map(|l| l.id).collect()
    }
    /// Read-only: every record's (grounded, answer support) flags, computed in one ordered pass.
    pub fn support_map(&self) -> BTreeMap<RecordId, (bool, bool)> {
        self.core.support_flags().sorted()
    }
    /// Read-only: `quality::stale::suspects`, kept like the support flags until the next command (01.11.2026 measurement: 69-103 ms
    /// of each 80-120 ms task acquire at the end of a live run, computed again by every poll of a waiting agent on an unchanged state).
    pub fn stale_suspects(&self) -> Vec<RecordId> {
        let readable = {
            let cache = self.core.cache();
            if let Some(ids) = cache.stale.as_ref().filter(|_| cache.readable) {
                return ids.to_vec();
            }
            cache.readable
        };
        // computed with the cache unlocked: it reads the support flags through the same cache
        let ids = super::quality::stale::suspects_fresh(self);
        if readable {
            self.core.cache().stale = Some(Arc::new(ids.clone()));
        }
        ids
    }
    /// Read-only: the stored outcome under `(actor, id)`, whatever request produced it, as `submit_operations_id` returned it
    /// (an error outcome as `{"error": ...}`).
    pub fn receipt_outcome(&self, id: &str, actor: &str) -> Option<Value> {
        self.core.data.receipts.get(&(actor.into(), id.into())).map(|r| match &r.outcome {
            Outcome::Value(v) => v.clone(),
            Outcome::Error(e) => json!({"error": e.to_json()}),
            other => other.value(),
        })
    }
    /// The run's namespace, fixed by the genesis: run id, corpus manifest hash and source mode.
    pub fn run_namespace(&self) -> Hash {
        let d = &self.core.data;
        sha256(to_jcs(&json!(["r2r-audit-run/1", d.run_id, to_hex(&d.manifest_hash), d.source_mode])).as_bytes())
    }
    pub fn engine_container(&mut self) -> Vec<u8> {
        build_container(&mut self.core.session)
    }

    fn prepare(&mut self, actor: &str, id: &str, command: &Value) -> KResult<Outcome> {
        let (next, outcome) = self.core.stage(actor, id, command)?;
        self.core = next;
        Ok(outcome)
    }

    /// `prepare` of a journal entry. An entry that reports no failure runs on the state itself; the check of its outcome and roots
    /// against what the replay computes is the caller's, whichever way it ran. The report only spares the copy: if it is false,
    /// either way the outcome differs and the journal is refused. The version guard compares a command with the state before it,
    /// so a run with a version map keeps the copy; only the first entry can install a map (`version_checkpoint`).
    fn prepare_recorded(&mut self, actor: &str, id: &str, entry: &Value) -> KResult<Outcome> {
        let recorded = &entry["outcome"];
        let failed = recorded["kind"] == "error" || !recorded["result"]["error"].is_null();
        let map = self.core.data.receipts.is_empty() || self.core.data.checkpoints.contains_key(super::versions::KEY);
        #[cfg(test)]
        let failed = failed || COPY_REPLAY.with(std::cell::Cell::get);
        if failed || map {
            return self.prepare(actor, id, &entry["command"]);
        }
        Ok(self.core.replay_in_place(actor, id, &entry["command"]))
    }

    fn commit(&mut self, actor: &str, id: &str, command: &Value) -> KResult<Outcome> {
        identifier(actor, "actor")?;
        identifier(id, "submission_id")?;
        if self.is_v3() {
            kernel_id(actor, id, command)?;
            // nothing is written that a `/3` journal refuses on replay (SPEC_V02_STEP2 section 1)
            if !super::persistence::safe_integers(command) {
                return Err(bad("command", "a number of a 0.2 journal is an integer from 0 to 2^53-1"));
            }
        }
        let hash = request_hash(actor, command);
        if let Some(receipt) = self.core.data.receipts.get(&(actor.into(), id.into())) {
            return if receipt.request_hash == hash {
                Ok(receipt.outcome.clone())
            } else {
                Err(bad("submission_id", "the same id was already used for different content"))
            };
        }
        if self.journal.is_none() {
            return Err(bad("wal_path", "audit mutations require a durable v2 journal").expected(json!({"wal_path":"required"})));
        }
        // the close is the journal's last frame: a retry above still has its receipt, nothing new is written (GAP-15 of the
        // independent verifier)
        if self.is_v3() && self.core.data.closed {
            return Err(bad("kind", "the run is closed: nothing more is written to its journal"));
        }
        // staged on one fork; the state is replaced only once the journal holds the command (01.11.2026 measurement: a fork to stage
        // on, forked again inside, cost a whole copy of the state per command)
        let (next_core, outcome) = self.core.stage(actor, id, command)?;
        let next = Self {
            core: next_core,
            journal: None,
            telemetry_frames: Vec::new(),
            links_off: false,
            genesis: self.genesis.clone(),
            pending_base: None,
            frames: Vec::new(),
            sealed_at: 0,
            seal_pending: false,
            seal_every: None,
            seals: Vec::new(),
            signer: None,
            sign_failures: Vec::new(),
        };
        // the storage invariant of the control profiles, judged by what the staged command did and not by its shape, so no
        // composition carries a link past it: a relation record of the swarm, a link operation of the builder, or either inside a
        // batch (Codex reviews of 8023910, SCOPE-01, and of 3ee34e9, SCOPE-03: a submit inside a batch stored a relation)
        if self.links_off && next.core.data.links.keys().any(|link| !self.core.data.links.contains_key(link)) {
            return Err(bad("kind", "links are off in this run (build scope concepts or none): a command that creates a link is not stored")
                .expected(json!({"links": "off"})));
        }
        let payload = json!({"actor":actor,"submission_id":id,"request_hash":to_hex(&hash),"command":command,"outcome":outcome.value(),
            "engine_root":to_hex(&next.engine_root()),"audit_root":to_hex(&next.audit_root())});
        // the frame is the body and the header in one object: one level over the body (SPEC_V02_STEP2 section 11)
        if self.is_v3() && 1 + super::persistence::json_depth(&payload) > super::persistence::MAX_FRAME_DEPTH {
            return Err(bad("command", "a frame of a 0.2 journal nests at most 64 levels"));
        }
        let records_root = self.is_v3().then(|| next.records_root_since(self.core.data.records.len()));
        self.journal.as_mut().expect("checked journal").append(&payload, records_root.as_ref())?;
        self.core = next.core;
        self.project_telemetry(&payload);
        if self.is_v3() {
            self.frames.push(self.journal.as_ref().expect("checked journal").head());
            let due = self.seal_every.is_some_and(|k| self.frames.len() >= self.sealed_at.max(1) + k);
            // a circle's phase changed (the dispatcher's `audit:circles` checkpoint): a boundary of the run worth a seal
            let phase = self.seal_every.is_some() && phase_changed(command, &outcome.value());
            let pending = self.seal_every.is_some() && self.seal_pending;
            if (due || phase || pending) && command["kind"] != "seal" && command["kind"] != "close" {
                // the command is in the journal: its receipt stands whatever becomes of the seal, and a seal that fails stays due
                // for the next command (Codex review of 43447f4, S2-02)
                self.seal_pending = self.seal().is_err();
            }
        }
        Ok(outcome)
    }

    fn value_command(&mut self, actor: &str, command: Value) -> KResult<Value> {
        // This in-process method is a fresh invocation, not an RPC retry token. In particular A -> B -> A document
        // updates must not reuse the first A's historical receipt. Remote retry semantics use explicit submission ids.
        let sequence = self.journal.as_ref().map_or(0, AuditJournal::sequence);
        let id = format!("auto_{sequence}_{}", to_hex(&request_hash(actor, &command)));
        match self.commit(actor, &id, &command)? {
            Outcome::Value(v) => Ok(v),
            Outcome::Error(e) => Err(e),
            Outcome::Records(_) => Err(bad("command", "unexpected records outcome")),
        }
    }

    pub fn submit_records_id(&mut self, id: &str, actor: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        let command = json!({"kind":"submit","directive":directive,"scope":scope_value(scope),"lines":lines});
        let command = self.version_submit_command(id, actor, command);
        match self.commit(actor, id, &command) {
            Ok(Outcome::Records(r)) => r,
            Ok(Outcome::Error(e)) | Err(e) => SubmitReport { accepted: Vec::new(), failed_index: Some(0), error: Some(e) },
            Ok(Outcome::Value(_)) => SubmitReport { accepted: Vec::new(), failed_index: Some(0), error: Some(bad("command", "unexpected outcome")) },
        }
    }

    /// Restrict references to the exact records issued by a trusted dispatcher, plus the actor's own accepted prefix.
    pub fn submit_scoped_records_id(&mut self, id: &str, actor: &str, directive: &str, scope: &Scope, issued: &[RecordId], lines: &[Value]) -> SubmitReport {
        let issued: Vec<_> = issued.iter().copied().collect::<BTreeSet<_>>().into_iter().map(|r| to_hex(&r.0)).collect();
        let command = json!({"kind":"submit","directive":directive,"scope":scope_value(scope),"allowed_records":issued,"lines":lines});
        let command = self.version_submit_command(id, actor, command);
        match self.commit(actor, id, &command) {
            Ok(Outcome::Records(r)) => r,
            Ok(Outcome::Error(e)) | Err(e) => SubmitReport { accepted: Vec::new(), failed_index: Some(0), error: Some(e) },
            _ => SubmitReport { accepted: Vec::new(), failed_index: Some(0), error: Some(bad("command", "unexpected outcome")) },
        }
    }

    // Name the new refusal semantics in the committed command. Old WAL commands keep their whole-command refusal and roots;
    // an exact retry of an old receipt also keeps its original command hash. The final effect guard remains mandatory for both.
    fn version_submit_command(&self, id: &str, actor: &str, mut command: Value) -> Value {
        if self.core.data.checkpoints.contains_key(super::versions::KEY)
            && !self.core.data.receipts.get(&(actor.into(), id.into())).is_some_and(|r| r.request_hash == request_hash(actor, &command))
        {
            command["version_rule"] = json!(super::versions::RELATION_RULE);
        }
        command
    }

    /// Trusted coordinator API: operations, their prefix receipt and an optional cursor checkpoint share one WAL frame.
    /// The dispatcher must validate the issued card/scope/subject before calling this, including at replay boundaries.
    pub fn submit_operations_id(&mut self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> KResult<Value> {
        let command = json!({"kind":"batch","operations":operations,"checkpoint":checkpoint});
        match self.commit(actor, id, &command)? {
            Outcome::Value(v) => Ok(v),
            Outcome::Error(e) => Err(e),
            _ => Err(bad("command", "unexpected outcome")),
        }
    }

    pub fn put_document(&mut self, actor: &str, doc_id: &str, bytes: &[u8]) -> KResult<()> {
        if bytes.len() > MAX_DOC_BYTES {
            return Err(bad("document", "document exceeds 16 MiB"));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| bad("document", "document must be UTF-8"))?;
        self.value_command(actor, json!({"kind":"put_document","doc_id":doc_id,"text":text}))?;
        Ok(())
    }

    /// Withdraws text of a document, quoted or not; the count is of the stored quotes that went with it.
    pub fn withdraw_text(&mut self, actor: &str, doc_id: &str, text: &str) -> KResult<u64> {
        let value = self.value_command(actor, json!({"kind":"revoke_text","doc_id":doc_id,"exact_quote":text}))?;
        Ok(value["also_revoked"].as_u64().unwrap_or(0))
    }

    /// Withdraws the quote of an observation; the count is of the other stored quotes that went with it.
    pub fn revoke_observation(&mut self, actor: &str, record: &RecordId) -> KResult<u64> {
        let value = self.value_command(actor, json!({"kind":"revoke","record":to_hex(&record.0)}))?;
        Ok(value["also_revoked"].as_u64().unwrap_or(0))
    }

    /// Administrative in-process API; the server must authorize the caller before exposing it.
    pub fn set_concept_status(&mut self, actor: &str, id: &ConceptId, status: &str) -> KResult<()> {
        self.value_command(actor, json!({"kind":"concept_status","concept":to_hex(&id.0),"status":status}))?;
        Ok(())
    }
}

fn request_hash(actor: &str, command: &Value) -> Hash {
    sha256(to_jcs(&json!(["r2r-audit-request/1", actor, command])).as_bytes())
}

fn check_keys(v: &Value, allowed: &[&str]) -> KResult<()> {
    let object = v.as_object().ok_or_else(|| bad("command", "expected an object"))?;
    if let Some(key) = object.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(bad(key, "unknown command field"));
    }
    Ok(())
}

fn status(value: &str) -> KResult<LinkStatus> {
    match value {
        "proposed" => Ok(LinkStatus::Proposed),
        "accepted" => Ok(LinkStatus::Accepted),
        "rejected" => Ok(LinkStatus::Rejected),
        _ => Err(bad("status", "invalid link status")),
    }
}

impl Core {
    fn record_ref(&self, name: &str) -> KResult<RecordId> {
        if let Some(hash) = from_hex(name) {
            let id = RecordId(hash);
            return if self.record(&id).is_some() { Ok(id) } else { Err(bad("record", "unknown full record id")) };
        }
        self.resolve(name, "", "")
    }

    fn command_basis(&self, v: &Value) -> KResult<Vec<RecordId>> {
        let names = strings(v, "basis")?;
        if names.is_empty() {
            return Err(bad("basis", "at least one basis record is required"));
        }
        let proof = self.proof_admissibility(&self.structural_grounding());
        names
            .iter()
            .map(|n| {
                let id = self.record_ref(n)?;
                if proof.get(&id) != Some(&true) {
                    return Err(bad("basis", "basis must be grounded without a hypothesis, question or terminal answer in its provenance"));
                }
                Ok(id)
            })
            .collect()
    }

    /// A command that succeeds may not rest on a way back: an error caught after a change, with a success returned on the strength of
    /// the copy, would run differently on the state itself (`replay_in_place`), and an honest journal would be refused.
    fn execute(&mut self, actor: &str, command: &Value) -> KResult<Outcome> {
        let kind = string(command, "kind")?;
        let value = match kind {
            "submit" => {
                check_keys(command, &["kind", "directive", "scope", "allowed_records", "lines", "version_rule"])?;
                return self.submit(actor, command);
            }
            "batch" => return self.batch(actor, command, None),
            "propose_concept" => {
                check_keys(
                    command,
                    if self.data.ontology.revision_policy().is_some() {
                        &["kind", "type", "name", "aliases", "basis", "subject", "function"]
                    } else {
                        &["kind", "type", "name", "aliases", "basis", "function"]
                    },
                )?;
                let basis = self.command_basis(command)?;
                if basis.iter().any(|id| self.record(id).is_none_or(|r| r.kind != RecordKind::Observe)) {
                    return Err(bad("basis", "concept proposals require observe records"));
                }
                let by = command.get("subject").and_then(Value::as_str).unwrap_or(actor);
                let mut view = self.data.ontology.propose(by, string(command, "type")?, string(command, "name")?, &strings(command, "aliases")?, &basis)?;
                // the address layer: the first proposal that names a function places the concept
                if command.get("function").is_some() {
                    self.data.ontology.place(&view.id, string(command, "function")?)?;
                    view = self.data.ontology.concept(&view.id).expect("proposed concept");
                }
                let result = concept_value(&view);
                if self.data.ontology.revision_policy().is_some() {
                    self.data.decisions.push(json!({"op":"concept_proposed","concept":result["id"],"subject":by,"basis":basis.iter().map(|id|to_hex(&id.0)).collect::<Vec<_>>(),"circle":self.data.checkpoints.get("audit:circles").map(|v|v["context"]["circle"].clone())}));
                }
                result
            }
            "concept_status" => {
                check_keys(command, &["kind", "concept", "status"])?;
                let result = concept_value(&self.data.ontology.set_status(&ConceptId(hash_field(command, "concept")?), string(command, "status")?, actor)?);
                if self.data.ontology.revision_policy().is_some() {
                    self.data.decisions.push(json!({"op":"concept_status","concept":result["id"],"status":result["status"],"subject":actor,"circle":self.data.checkpoints.get("audit:circles").map(|v|v["context"]["circle"].clone())}));
                }
                result
            }
            "ontology_unattested" => self.mark_unattested(actor, command)?,
            "ontology_review_keep" => self.keep_ontology_review(command)?,
            "revise_concept" => self.revise_concept(command)?,
            "map_term" => {
                check_keys(
                    command,
                    if self.ontology_review_enabled() {
                        &["kind", "record", "term", "concept", "subject", "rule"]
                    } else {
                        &["kind", "record", "term", "concept"]
                    },
                )?;
                let rule = command
                    .get("rule")
                    .map(|v| v.as_str().filter(|r| *r == REFINER_MAP_RULE).ok_or_else(|| bad("rule", "unknown map_term rule")))
                    .transpose()?;
                let id = self.record_ref(string(command, "record")?)?;
                let term = string(command, "term")?;
                let concept_id = ConceptId(hash_field(command, "concept")?);
                let concept = self.data.ontology.concept(&concept_id).filter(|c| !matches!(c.status.as_str(), "retired" | "narrowed")).ok_or_else(|| {
                    let error = bad("concept", "unknown or retired concept");
                    if self.data.ontology.revision_policy().is_some() {
                        let mut expected = json!({"replacement":self.data.ontology.replacement(&concept_id).map(|c|concept_value(&c))});
                        let narrowed = self.data.ontology.narrowed_replacements(&concept_id);
                        if !narrowed.is_empty() {
                            expected["narrowed_into"] = json!(narrowed.iter().map(concept_value).collect::<Vec<_>>());
                        }
                        error.expected(expected)
                    } else {
                        error
                    }
                })?;
                if let Some(snapshot) = self.revision_state() {
                    if let Some(proposal) = snapshot["pending"].as_array().into_iter().flatten().find(|p| p["change"]["concept"] == to_hex(&concept_id.0)) {
                        return Err(bad("concept", "concept has a pending revision; wait for explicit review before adding mappings")
                            .expected(json!({"proposal":proposal["proposal"],"reviewer":proposal["reviewer"]})));
                    }
                }
                let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
                let term = normalize(term);
                let record = self.record(&id).expect("resolved record");
                if !record.terms.iter().any(|t| normalize(t) == term) {
                    return Err(bad("term", "term was not present in the issued record"));
                }
                if self.data.mappings.keys().any(|(r, t, c)| *r == id && *t == term && *c != concept_id) {
                    return Err(bad("concept", "term already has a different mapping"));
                }
                let map_subject = if self.ontology_review_enabled() {
                    let subject = string(command, "subject")?;
                    let context = self.data.checkpoints.get("audit:mcp:coverage").map(|v| &v["context"]);
                    let reader = context.and_then(|c| c["circle_readers"].as_array()).is_some_and(|xs| xs.iter().any(|v| v == subject));
                    // circles +1: the pinned refiner maps terms too (run H1p1_r2 refused all 991 of gb's map_term here), but only by
                    // a command naming the rule: a command without it is judged as it always was, so a refusal recorded before the
                    // rule replays with the same outcome and roots (Codex's consilium 28.10, D02: H1p1_r2 seq 98)
                    let refiner = rule.is_some() && context.is_some_and(|c| c["circle_refiner"] == subject);
                    if !reader && !refiner {
                        return Err(bad("subject", "mapper must be an authenticated ring subject"));
                    }
                    identifier(subject, "subject")?;
                    Some(subject.to_string())
                } else {
                    None
                };
                let concept = if self.data.ontology.attest_mapping(&concept_id)? {
                    self.data.decisions.push(json!({"op":"ontology_attestation","concept":to_hex(&concept_id.0),"status":self.data.ontology.concept(&concept_id).expect("known").status,"subject":"kernel","reason":{"mapping_record":to_hex(&id.0),"term":term,"meaning":"mapping observed again; prior status restored"}}));
                    self.data.ontology.concept(&concept_id).expect("known")
                } else {
                    concept
                };
                let accepted_name = normalize(&concept.name) == term || concept.aliases.iter().any(|a| normalize(a) == term);
                let state = if concept.status == "accepted" && accepted_name { "accepted" } else { "proposed" };
                self.data.mappings.insert((id, term.clone(), concept_id), state.into());
                if let Some(d) = self.dirty() {
                    d.mappings.insert((id, term.clone(), concept_id));
                }
                let mut decision = json!({"op":"map_term","by":actor,"record":to_hex(&id.0),"concept":to_hex(&concept_id.0),"status":state});
                if let Some(subject) = map_subject {
                    decision["subject"] = json!(subject);
                    decision["term"] = json!(term);
                }
                self.data.decisions.push(decision);
                json!({"status":state})
            }
            "add_link" => {
                check_keys(command, &["kind", "from", "rel", "to", "basis"])?;
                let from = self.record_ref(string(command, "from")?)?;
                let to = self.record_ref(string(command, "to")?)?;
                let basis = self.command_basis(command)?;
                link_value(&self.add_link(actor, &from, string(command, "rel")?, &to, &basis)?)
            }
            "set_link_status" => {
                check_keys(command, &["kind", "link", "status", "expected_status", "basis"])?;
                let id = LinkId(hash_field(command, "link")?);
                let next = status(string(command, "status")?)?;
                let basis = self.command_basis(command)?;
                let link = self.data.links.get(&id).ok_or_else(|| bad("link", "unknown link"))?;
                if let Some(expected) = command.get("expected_status") {
                    if expected.as_str() != Some(link.status.name()) {
                        return Err(bad("expected_status", "link status changed since the task was issued"));
                    }
                }
                if next != LinkStatus::Rejected {
                    self.validate_link_ends(&link.from, &link.rel, &link.to)?;
                }
                if actor == "builder" && next != LinkStatus::Proposed {
                    return Err(bad("actor", "the graph builder cannot accept or reject its own proposal"));
                }
                if actor == "kernel" && next == LinkStatus::Accepted && matches!(link.rel.as_str(), "same_as" | "duplicate_of") {
                    return Err(bad("status", "identity and duplicates require a verifier or owner"));
                }
                let proof = self.proof_admissibility(&self.structural_grounding());
                if next == LinkStatus::Accepted && (proof.get(&link.from) != Some(&true) || proof.get(&link.to) != Some(&true)) {
                    return Err(bad("link", "link endpoints are no longer admissible proof"));
                }
                if next == LinkStatus::Accepted && link.basis.iter().any(|id| proof.get(id) != Some(&true)) {
                    return Err(bad("link", "the proposal basis is no longer admissible proof"));
                }
                self.data.links.get_mut(&id).expect("checked link").status = next;
                if next == LinkStatus::Accepted {
                    self.data.acceptance_basis.insert(id, basis.clone());
                }
                if let Some(d) = self.dirty() {
                    d.links.insert(id);
                    d.acceptance.insert(id);
                }
                self.data.decisions.push(json!({"op":"link_status","link":to_hex(&id.0),"status":next.name(),"by":actor,
                    "basis":basis.iter().map(|x|to_hex(&x.0)).collect::<Vec<_>>()}));
                link_value(&self.data.links[&id])
            }
            "put_document" => {
                check_keys(command, &["kind", "doc_id", "text"])?;
                let id = string(command, "doc_id")?;
                let text = command["text"].as_str().ok_or_else(|| bad("text", "expected UTF-8 text"))?;
                if self.data.checkpoints.contains_key(crate::audit::versions::KEY) && self.session.arena.doc(id).is_none_or(|d| d.bytes != text.as_bytes()) {
                    return Err(bad("doc_id", "version-map inputs are frozen; start a new run for new source bytes"));
                }
                if text.len() > MAX_DOC_BYTES {
                    return Err(bad("text", "document exceeds 16 MiB"));
                }
                if self.data.source_mode == "git_manifest" && !self.data.source_documents.contains_key(id) {
                    return Err(bad("doc_id", "document is outside this session's frozen manifest selection"));
                }
                if self.data.source_documents.get(id).is_some_and(|d| d["kind"] == "git_manifest" && d["raw_sha256"] != to_hex(&sha256(text.as_bytes()))) {
                    return Err(bad("doc_id", "manifest DocumentId is immutable; load a new version under its new identity"));
                }
                self.session.put_document(id, text.as_bytes());
                // quotes of an earlier version come back with that version: what was withdrawn meanwhile stays withdrawn
                for closed in self.data.withdrawn.get(id).cloned().unwrap_or_default() {
                    let hit = self.quotes_on(id, &closed);
                    self.close_text(id, closed, hit, None)?;
                }
                if self.data.source_documents.get(id).is_none_or(|d| d["kind"] == "opaque") {
                    self.data.source_documents.insert(id.into(), json!({"kind":"opaque","doc_id":id,"raw_sha256":to_hex(&sha256(text.as_bytes()))}));
                    if let Some(d) = self.dirty() {
                        d.sources.insert(id.into());
                    }
                }
                json!({"document_version":to_hex(&self.session.arena.doc(id).expect("inserted document").version_id)})
            }
            "revoke" => {
                check_keys(command, &["kind", "record"])?;
                let record = RecordId(hash_field(command, "record")?);
                let evidence = self.data.evidence.get(&record).ok_or_else(|| bad("record", "record is not an observe"))?.evidence;
                let quoted = self.record(&record).and_then(|r| Some((r.doc_id.clone()?, r.quote.clone()?)));
                let closing = quoted.filter(|(doc, text)| self.data.withdrawal_closes_bytes && !self.is_withdrawn(doc, text.as_bytes()));
                // a quote that went with a withdrawal can still be withdrawn itself: the rest of its text closes now
                let went_with_another = closing.is_some() && self.session.engine.status_of(&evidence) == Some(EV_REVOKED);
                let hit = closing.as_ref().map(|(doc, text)| self.quotes_on(doc, text.as_bytes())).unwrap_or_default();
                if !went_with_another {
                    if self.session.engine.status_of(&evidence) != Some(EV_REVOKED) {
                        // the record named, and every other record on the same evidence: its own text closes with it under the
                        // rule of closed bytes; under the first rule nothing else does
                        let fate = |s: &Self, id: &RecordId| match &closing {
                            Some((doc, text)) => json!({"cause": "withdrawn", "named": *id == record, "withdrawal": s.withdrawal(doc, text.as_bytes(), id)}),
                            None => json!({"cause": "revoked", "named": *id == record}),
                        };
                        self.revoke_with_fates(evidence, &fate)?;
                    } else {
                        self.revoke_evidence(evidence)?;
                    }
                }
                match closing {
                    Some((doc, text)) => json!({"revoked":true,"also_revoked":self.close_text(&doc, text.into_bytes(), hit, Some(record))?}),
                    None if self.data.withdrawal_closes_bytes => json!({"revoked":true,"also_revoked":0}),
                    None => json!({"revoked":true}),
                }
            }
            // a journal of the first format has no such command, and answers as it always did
            "revoke_text" if self.data.withdrawal_closes_bytes => {
                check_keys(command, &["kind", "doc_id", "exact_quote"])?;
                let doc = string(command, "doc_id")?.to_string();
                // the text of a quote, not an identifier: soft line breaks and long sentences belong to it
                let text =
                    command["exact_quote"].as_str().filter(|t| t.len() <= MAX_DOC_BYTES).ok_or_else(|| bad("exact_quote", "expected UTF-8 text"))?.to_string();
                let bytes = self.session.arena.doc(&doc).ok_or_else(|| KernelError::new(Code::UnknownDoc, "document was not loaded").field("doc_id"))?;
                if find_all(&bytes.bytes, text.as_bytes()).is_empty() {
                    return Err(KernelError::new(Code::QuoteNotFoundInBytes, "the text has no byte-exact occurrence").field("exact_quote"));
                }
                if self.is_withdrawn(&doc, text.as_bytes()) {
                    return Err(KernelError::new(Code::AlreadyRevoked, "this text is already withdrawn").field("exact_quote"));
                }
                let hit = self.quotes_on(&doc, text.as_bytes());
                json!({"revoked":true,"also_revoked":self.close_text(&doc, text.into_bytes(), hit, None)?})
            }
            "checkpoint" => {
                check_keys(command, &["kind", "key", "from", "to", "context"])?;
                self.version_checkpoint(actor, command)?;
                let key = string(command, "key")?;
                let from = command["from"].as_u64().ok_or_else(|| bad("from", "checkpoint requires an integer"))?;
                let to = command["to"].as_u64().ok_or_else(|| bad("to", "checkpoint requires an integer"))?;
                let old = self.data.checkpoints.get(key).and_then(|c| c["to"].as_u64()).unwrap_or(0);
                if from != old || to < from || to > self.data.records.len() as u64 {
                    return Err(bad("to", "checkpoint must extend the current contiguous cursor within the ingest stream"));
                }
                self.data.checkpoints.insert(key.into(), command.clone());
                if let Some(d) = self.dirty() {
                    d.checkpoints.insert(key.into());
                }
                json!({"checkpoint":key,"cursor":to})
            }
            // a 0.2 journal only: the run closed by `audit_close`, and the seals (SPEC_V02_STEP2 sections 5 and 7)
            "close" if self.dirty().is_some() => {
                check_keys(command, &["kind"])?;
                if actor != "kernel" {
                    return Err(bad("actor", "only the kernel closes a run"));
                }
                if self.data.closed {
                    return Err(bad("kind", "the run is already closed"));
                }
                self.data.closed = true;
                if let Some(d) = self.dirty() {
                    d.meta = true;
                }
                json!({"closed": true})
            }
            "seal" if self.dirty().is_some() => {
                check_keys(command, &["kind", "seal"])?;
                if actor != "kernel" {
                    return Err(bad("actor", "only the kernel writes a seal"));
                }
                let seal = &command["seal"];
                let mut keys: Vec<&str> = seal.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
                keys.sort_unstable();
                let (status, dependencies) = self.projection_hashes();
                // the kernel's part of the seal, read on the state before it; the journal's part is the caller's (`check_seal_log`)
                if keys != SEAL_KEYS
                    || seal["format"] != SEAL_FORMAT
                    || seal["run_id"] != json!(self.data.run_id)
                    || seal["audit_root"] != json!(to_hex(&self.root()))
                    || seal["engine_root"] != json!(to_hex(&self.engine_root))
                    || seal["projections"] != json!({"status": to_hex(&status), "dependencies": to_hex(&dependencies)})
                {
                    return Err(bad("seal", "a seal names this state: its run, its roots and the hashes of its projections"));
                }
                json!({"seal": seal, "seal_hash": to_hex(&seal_hash(seal))})
            }
            _ => return Err(KernelError::new(Code::UnknownOp, "unknown audit operation").field("kind")),
        };
        Ok(Outcome::Value(value))
    }

    fn revoke_evidence(&mut self, evidence: Hash) -> KResult<()> {
        let event = json!({"seq":self.session.last_seq+1,"op":"revoke_evidence","target_evidence":format!("@{}",to_hex(&evidence))});
        self.session.apply_line(&to_jcs(&event)).map(|_| ())
    }

    fn is_withdrawn(&self, doc_id: &str, text: &[u8]) -> bool {
        self.data.withdrawn.get(doc_id).is_some_and(|closed| closed.contains(text))
    }

    /// The live quotes of the document's present version that overlap an occurrence of `text`, in span order: a replay repeats the
    /// engine's operations. Records are walked, as evidence is keyed by a digest and two documents can have the same version.
    fn quotes_on(&self, doc_id: &str, text: &[u8]) -> Vec<(usize, usize, Hash, RecordId)> {
        let Some(doc) = self.session.arena.doc(doc_id) else { return Vec::new() };
        let occurrences = find_all(&doc.bytes, text);
        let mut hit: Vec<_> = self
            .data
            .records
            .iter()
            .filter(|r| r.doc_id.as_deref() == Some(doc_id))
            .filter_map(|r| self.data.evidence.get(&r.id).map(|b| (b, r.id)))
            .filter(|(b, _)| b.version == doc.version_id && self.session.engine.status_of(&b.evidence) != Some(EV_REVOKED))
            .filter(|(b, _)| occurrences.iter().any(|o| b.start < o.end && o.start < b.end))
            .map(|(b, id)| (b.start, b.end, b.evidence, id))
            .collect();
        hit.sort_unstable();
        hit
    }

    /// A withdrawal as the report of what fell names it for one quote it took: the document, the hash and length of the withdrawn
    /// text, the version and the bytes of the occurrence that overlapped the quote, as they were when it went.
    /// `span` is an occurrence on the quote's own version: for a quote bound to an earlier version than the one the text closed in,
    /// bytes of two versions do not compare, and it is null (Codex recheck of baa75e5, S3-R01).
    fn withdrawal(&self, doc_id: &str, text: &[u8], quote: &RecordId) -> Value {
        let doc = self.session.arena.doc(doc_id);
        let binding = self.data.evidence.get(quote);
        let span = doc
            .zip(binding)
            .filter(|(d, b)| d.version_id == b.version)
            .and_then(|(d, b)| find_all(&d.bytes, text).into_iter().find(|o| o.start < b.end && b.start < o.end))
            .map(|o| json!([o.start, o.end]));
        json!({"doc_id": doc_id, "sha256": to_hex(&sha256(text)), "bytes": text.len(), "version": doc.map(|d| to_hex(&d.version_id)), "span": span})
    }

    /// Revoke an evidence and write why for every record bound to it that has no cause yet: two readers may quote the same bytes,
    /// one evidence under two records (Codex recheck of baa75e5, S3-R01).
    fn revoke_with_fates(&mut self, evidence: Hash, fate: &dyn Fn(&Self, &RecordId) -> Value) -> KResult<()> {
        self.revoke_evidence(evidence)?;
        let bound: Vec<RecordId> = self
            .data
            .records
            .iter()
            .filter(|r| !self.data.fates.contains_key(&r.id) && self.data.evidence.get(&r.id).is_some_and(|b| b.evidence == evidence))
            .map(|r| r.id)
            .collect();
        let fates: Vec<(RecordId, Value)> = bound.into_iter().map(|id| (id, fate(self, &id))).collect();
        self.data.fates.extend(fates);
        Ok(())
    }

    /// The rest of a withdrawal: the quotes found before it go, and the text stays closed. The count leaves out the record named.
    fn close_text(&mut self, doc_id: &str, text: Vec<u8>, hit: Vec<(usize, usize, Hash, RecordId)>, named: Option<RecordId>) -> KResult<u64> {
        let also = hit.iter().filter(|(_, _, _, id)| Some(*id) != named).count() as u64;
        for (_, _, evidence, _) in hit {
            if self.session.engine.status_of(&evidence) != Some(EV_REVOKED) {
                // this withdrawal is why the quotes on this evidence went: a later one cannot claim them (S3-02)
                let fate = |s: &Self, id: &RecordId| json!({"cause": "withdrawn", "named": Some(*id) == named, "withdrawal": s.withdrawal(doc_id, &text, id)});
                self.revoke_with_fates(evidence, &fate)?;
            }
        }
        if let Some(d) = self.dirty() {
            d.withdrawn.insert((doc_id.to_string(), sha256(&text)));
        }
        self.data.withdrawn.entry(doc_id.to_string()).or_default().insert(text);
        Ok(also)
    }

    /// `base`: the state the batch is staged on, when it is the staged command itself (`stage`). A refused first operation rolls
    /// back to a fork of it, taken only then; any other operation to the copy taken before it.
    fn batch(&mut self, actor: &str, command: &Value, base: Option<&Core>) -> KResult<Outcome> {
        check_keys(command, &["kind", "operations", "checkpoint"])?;
        let operations = command["operations"].as_array().ok_or_else(|| bad("operations", "expected an array"))?;
        if operations.len() > MAX_REFS {
            return Err(bad("operations", "at most 256 operations are allowed"));
        }
        let mut results = Vec::new();
        let mut failure = None;
        let mut failed_index = None;
        for (index, operation) in operations.iter().enumerate() {
            if operation["kind"] == "batch" {
                failure = Some(bad("kind", "nested batches are not permitted"));
                failed_index = Some(index);
                break;
            }
            // a seal names the prefix of the journal and is checked as a frame of its own; a close ends the run after its seal
            // (Codex review of 43447f4, S2-01: a seal inside a batch named a prefix no check compared)
            #[cfg(test)]
            let nested = NESTED_FRAMES.with(std::cell::Cell::get);
            #[cfg(not(test))]
            let nested = false;
            if (operation["kind"] == "seal" || operation["kind"] == "close") && !nested {
                failure = Some(bad("kind", "a seal or a close is a frame of its own, never an operation of a batch"));
                failed_index = Some(index);
                break;
            }
            let previous = if self.in_place || (index == 0 && base.is_some()) { None } else { Some(self.fork()?) };
            match self.execute(actor, operation) {
                Ok(Outcome::Records(report)) => {
                    results.push(report_value(&report));
                    if let Some(error) = report.error {
                        failure = Some(error);
                        failed_index = Some(index);
                        break;
                    }
                }
                Ok(Outcome::Value(value)) => results.push(value),
                Ok(Outcome::Error(error)) | Err(error) => {
                    if !self.in_place {
                        *self = match previous {
                            Some(previous) => previous,
                            // the state as `stage` began the batch on it
                            None => {
                                let mut fresh = base.expect("the base of a staged batch").fork()?;
                                fresh.begin_roots(command);
                                fresh
                            }
                        };
                    }
                    failure = Some(error);
                    failed_index = Some(index);
                    break;
                }
            }
        }
        let mut checkpointed = false;
        if failure.is_none() && !command["checkpoint"].is_null() {
            let mut checkpoint = command["checkpoint"].clone();
            let result = match checkpoint.as_object_mut() {
                Some(object) => {
                    object.insert("kind".into(), json!("checkpoint"));
                    self.execute(actor, &checkpoint)
                }
                None => Err(bad("checkpoint", "expected an object")),
            };
            match result {
                Ok(_) => checkpointed = true,
                Err(error) => {
                    failure = Some(error);
                    failed_index = Some(operations.len());
                }
            }
        }
        Ok(Outcome::Value(json!({"accepted_operations":results.len(),"results":results,"failed_index":failed_index,
            "error":failure.as_ref().map(KernelError::to_json),"checkpointed":checkpointed})))
    }
}

impl AuditStore for AuditState {
    fn local_record(&self, agent: &str, directive: &str, local_id: &str) -> Option<RecordId> {
        self.core.data.locals.get(&(agent.into(), directive.into(), local_id.into())).copied()
    }
    fn document_label(&self, id: &str) -> String {
        self.source_document(id).and_then(|v| v["path"].as_str().map(str::to_string)).unwrap_or_else(|| id.to_string())
    }
    fn document_date(&self, id: &str) -> Option<String> {
        self.source_document(id).and_then(|v| v["date"].as_str().map(str::to_string))
    }
    fn docs(&self) -> Vec<String> {
        self.core.session.arena.doc_ids().cloned().collect()
    }
    fn doc_text(&self, doc_id: &str) -> Option<String> {
        self.core.session.arena.doc(doc_id).and_then(|d| String::from_utf8(d.bytes.clone()).ok())
    }
    fn quoted_spans(&self, doc_id: &str) -> Vec<(usize, usize)> {
        let Some(doc) = self.core.session.arena.doc(doc_id) else { return Vec::new() };
        // the bytes the kernel bound each quote to, in the document's present version, while its evidence stands
        self.core
            .data
            .records
            .iter()
            .filter(|r| r.doc_id.as_deref() == Some(doc_id))
            .filter_map(|r| self.core.data.evidence.get(&r.id))
            .filter(|b| b.version == doc.version_id && self.core.session.engine.status_of(&b.evidence) != Some(EV_REVOKED))
            .map(|b| (b.start, b.end))
            .collect()
    }
    fn closed_spans(&self, doc_id: &str) -> Vec<(usize, usize)> {
        let (Some(doc), Some(closed)) = (self.core.session.arena.doc(doc_id), self.core.data.withdrawn.get(doc_id)) else { return Vec::new() };
        closed.iter().flat_map(|text| find_all(&doc.bytes, text)).map(|o| (o.start, o.end)).collect()
    }
    fn submit_records(&mut self, actor: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        // Compatibility entry point for the first builder/dispatcher skeleton. Production transports should supply the
        // explicit id to submit_records_id, rather than treating changed content as the same RPC attempt.
        let id = format!("compat_{}", to_hex(&request_hash(actor, &json!([directive, scope_value(scope), lines]))));
        self.submit_records_id(&id, actor, directive, scope, lines)
    }
    fn records_since(&self, cursor: u64) -> Vec<RecordView> {
        self.core.data.records.iter().filter(|r| r.seq > cursor).cloned().collect()
    }
    fn records_of_kind(&self, kind: RecordKind) -> Vec<RecordView> {
        self.core.data.records.iter().filter(|r| r.kind == kind).cloned().collect()
    }
    fn record(&self, id: &RecordId) -> Option<RecordView> {
        self.core.record(id).cloned()
    }
    fn submit_records_id(&mut self, id: &str, actor: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        AuditState::submit_records_id(self, id, actor, directive, scope, lines)
    }
    fn submit_scoped_records_id(&mut self, id: &str, actor: &str, directive: &str, scope: &Scope, issued: &[RecordId], lines: &[Value]) -> SubmitReport {
        AuditState::submit_scoped_records_id(self, id, actor, directive, scope, issued, lines)
    }
    fn is_grounded(&self, id: &RecordId) -> bool {
        AuditState::is_grounded(self, id)
    }
    fn is_answer_support(&self, id: &RecordId) -> bool {
        AuditState::is_answer_support(self, id)
    }
    fn link_usable(&self, id: &LinkId) -> bool {
        AuditState::link_usable(self, id)
    }
    fn submit_operations_id(&mut self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> KResult<Value> {
        AuditState::submit_operations_id(self, id, actor, operations, checkpoint)
    }
    fn checkpoint(&self, key: &str) -> Option<Value> {
        AuditState::checkpoint(self, key)
    }
    fn has_checkpoint(&self, key: &str) -> bool {
        self.core.data.checkpoints.contains_key(key)
    }
    fn checkpoint_keys(&self, prefix: &str) -> Vec<String> {
        self.core.data.checkpoints.keys().filter(|k| k.starts_with(prefix)).cloned().collect()
    }
    fn operations_receipt(&self, id: &str, actor: &str, operations: &[Value], checkpoint: Option<Value>) -> Prior {
        AuditState::operations_receipt(self, id, actor, operations, checkpoint)
    }
    fn receipt_outcome(&self, id: &str, actor: &str) -> Option<Value> {
        AuditState::receipt_outcome(self, id, actor)
    }
    fn support_map(&self) -> Option<BTreeMap<RecordId, (bool, bool)>> {
        Some(AuditState::support_map(self))
    }
    fn stale_suspects(&self) -> Option<Vec<RecordId>> {
        Some(AuditState::stale_suspects(self))
    }
    fn supersession_history(&self) -> Vec<LinkView> {
        self.core
            .data
            .links
            .values()
            .filter(|l| {
                l.rel == "supersedes"
                    && self.core.data.decisions.iter().any(|d| d["op"] == "link_status" && d["status"] == "accepted" && d["link"] == to_hex(&l.id.0))
            })
            .cloned()
            .collect()
    }
    fn usable_links(&self) -> Option<BTreeSet<LinkId>> {
        Some(AuditState::usable_links(self))
    }
    fn ontology_revision_state(&self) -> Option<Value> {
        self.core.revision_state()
    }
    fn concepts(&self) -> Vec<ConceptView> {
        self.core.data.ontology.concepts()
    }
    fn run_namespace(&self) -> Hash {
        AuditState::run_namespace(self)
    }
    fn head(&self) -> u64 {
        self.core.data.records.len() as u64
    }
    fn ontology_version(&self) -> (u64, Hash) {
        self.core.data.ontology.revision()
    }
    fn concept_types(&self) -> Vec<String> {
        self.core.data.ontology.types()
    }
    fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView> {
        self.core.data.ontology.candidates(term, limit)
    }
    fn concept(&self, id: &ConceptId) -> Option<ConceptView> {
        self.core.data.ontology.concept(id)
    }
    fn propose_concept(&mut self, by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> KResult<ConceptView> {
        let value = self.value_command(
            by,
            json!({"kind":"propose_concept","type":ty,"name":name,"aliases":aliases,
            "basis":basis.iter().map(|x|to_hex(&x.0)).collect::<Vec<_>>()}),
        )?;
        self.concept(&ConceptId(hash_field(&value, "id")?)).ok_or_else(|| bad("concept", "committed concept was not found"))
    }
    fn map_term(&mut self, by: &str, record: &RecordId, term: &str, concept: &ConceptId) -> KResult<()> {
        self.value_command(by, json!({"kind":"map_term","record":to_hex(&record.0),"term":term,"concept":to_hex(&concept.0)}))?;
        Ok(())
    }
    fn concepts_of(&self, record: &RecordId) -> Vec<ConceptId> {
        self.core.data.mappings.keys().filter(|(r, _, _)| r == record).map(|(_, _, c)| *c).collect::<BTreeSet<_>>().into_iter().collect()
    }
    fn mapping_authors_of(&self, concept: &ConceptId) -> Option<Vec<(String, usize)>> {
        let mut seen = BTreeSet::new();
        let mut counts = BTreeMap::new();
        let cid = to_hex(&concept.0);
        for event in &self.core.data.decisions {
            if event["op"] == "map_term" && event["concept"] == cid {
                let record = event["record"].as_str()?;
                let term = event["term"].as_str()?;
                let current = from_hex(record).map(RecordId).is_some_and(|r| self.core.data.mappings.contains_key(&(r, term.to_string(), *concept)));
                if current && seen.insert((record.to_string(), term.to_string())) {
                    let subject = event["subject"].as_str()?;
                    *counts.entry(subject.to_string()).or_insert(0) += 1;
                }
            }
        }
        Some(counts.into_iter().collect())
    }
    fn mapped_terms_of(&self, concept: &ConceptId) -> Option<Vec<(RecordId, String)>> {
        Some(self.core.data.mappings.keys().filter(|(_, _, c)| c == concept).map(|(r, t, _)| (*r, t.clone())).collect())
    }
    fn records_of(&self, concept: &ConceptId) -> Vec<RecordId> {
        self.core.data.mappings.keys().filter(|(_, _, c)| c == concept).map(|(r, _, _)| *r).collect::<BTreeSet<_>>().into_iter().collect()
    }
    fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> KResult<LinkView> {
        let value = self.value_command(
            by,
            json!({"kind":"add_link","from":to_hex(&from.0),"rel":rel,"to":to_hex(&to.0),
            "basis":basis.iter().map(|x|to_hex(&x.0)).collect::<Vec<_>>()}),
        )?;
        self.link(&LinkId(hash_field(&value, "id")?)).ok_or_else(|| bad("link", "committed link was not found"))
    }
    fn set_link_status(&mut self, id: &LinkId, next: LinkStatus, by: &str, basis: &[RecordId]) -> KResult<()> {
        let old = self.link(id).ok_or_else(|| bad("link", "unknown link"))?;
        self.value_command(
            by,
            json!({"kind":"set_link_status","link":to_hex(&id.0),"status":next.name(),"expected_status":old.status.name(),
            "basis":basis.iter().map(|x|to_hex(&x.0)).collect::<Vec<_>>()}),
        )?;
        Ok(())
    }
    fn link(&self, id: &LinkId) -> Option<LinkView> {
        self.core.data.links.get(id).cloned()
    }
    fn links(&self) -> Vec<LinkView> {
        self.core.data.links.values().cloned().collect()
    }
    fn links_of(&self, record: &RecordId) -> Vec<LinkView> {
        self.core.data.links.values().filter(|l| l.from == *record || l.to == *record).cloned().collect()
    }
    fn root(&self) -> Hash {
        self.audit_root()
    }
    fn epoch(&self) -> Hash {
        // a 0.2 journal: the chain head, read at no cost; the first formats keep the audit root
        if self.is_v3() {
            self.frames.last().copied().unwrap_or(ZERO_HASH)
        } else {
            self.audit_root()
        }
    }
}

fn decode_hex(hex: &str) -> KResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("container_hex", "invalid hexadecimal bytes"));
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let s = std::str::from_utf8(p).expect("ascii hex");
            u8::from_str_radix(s, 16).map_err(|_| bad("container_hex", "invalid hexadecimal bytes"))
        })
        .collect()
}

#[cfg(test)]
thread_local! {
    /// Tests only: fork the session engine by a replay of its WAL, the way before 01.11.2026, as the oracle of the copy.
    static REPLAY_FORK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests only: a staged batch copies the state before its first operation too, the way before 02.11.2026, as the oracle.
    static TWO_COPY_BATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests only: every replayed command is staged on a copy, as a live command is, as the oracle of the replay on the state itself.
    static COPY_REPLAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests only: the copies of the state made on this thread.
    static FORKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Tests only: a batch takes a seal or a close as an operation, the way before 09.11.2026, to write the journal a replay refuses.
    static NESTED_FRAMES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests only: the next n seals fail before they reach the journal.
    static FAIL_SEALS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
