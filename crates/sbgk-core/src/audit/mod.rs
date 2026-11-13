//! The swarm audit layer (contract v0, `R2R_SWARM_CONTRACT_v0_RU.md`): three roles around one kernel.
//!
//! * **Swarm agents** (outside, stateless) do the main work and stream atomic records: `observe` (an exact quote, bound to the
//!   source bytes by the engine's `bind_evidence`), `claim`, `relation`, `hypothesis`, `question`, `done`. They never see the
//!   graph or `bytes[]`; they get short directives (`directives`).
//! * **The kernel** validates every record, keeps records, the audit ontology (base + accepted growth, versioned), the links
//!   between records and their statuses, and is the only trusted checker. The engine's own ontology stays fixed: swarm records are
//!   not engine claims, so its genesis, container v1 and WAL are unchanged.
//! * **The graph builder** (one agent, weak model, inside) reads cards (`builder`) and proposes: term -> concept mappings, new
//!   concepts of known types, links between records of different agents, duplicates, conflicts. Every link is born `Proposed`;
//!   it becomes `Accepted` by a kernel rule, by a targeted `VERIFY_LINK` directive answered by one swarm agent, or by the owner.
//!
//! Ownership: `state` (the `AuditStore` implementation, its journal records and root) - Codex; `builder` and `directives` -
//! Claude. Both sides code against the `AuditStore` trait below.

mod answer_guidance;
pub mod builder;
pub mod directives;
pub mod index;
#[cfg(test)]
pub(crate) mod mem;
pub mod onto;
pub(crate) mod persistence;
pub use persistence::LOCKED_WHOLE;
pub mod proof;
pub mod read;
pub mod records;
pub mod s0;
pub mod sign;
pub mod sources;
pub mod state;
pub mod trees;
pub mod versions;

use crate::error::KernelError;
use crate::hash::{to_hex, Hash};
use serde_json::Value;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Hash);

        impl $name {
            /// `@` + the first 16 hex digits, the form agents see and write.
            pub fn short(&self) -> String {
                format!("@{}", &to_hex(&self.0)[..16])
            }
        }
    };
}
id_type!(RecordId);
id_type!(ConceptId);
id_type!(LinkId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordKind {
    Observe,
    Claim,
    Relation,
    Hypothesis,
    Question,
    Done,
}

impl RecordKind {
    pub fn name(self) -> &'static str {
        match self {
            RecordKind::Observe => "observe",
            RecordKind::Claim => "claim",
            RecordKind::Relation => "relation",
            RecordKind::Hypothesis => "hypothesis",
            RecordKind::Question => "question",
            RecordKind::Done => "done",
        }
    }

    pub fn parse(s: &str) -> Option<RecordKind> {
        Some(match s {
            "observe" => RecordKind::Observe,
            "claim" => RecordKind::Claim,
            "relation" => RecordKind::Relation,
            "hypothesis" => RecordKind::Hypothesis,
            "question" => RecordKind::Question,
            "done" => RecordKind::Done,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkStatus {
    Proposed,
    Accepted,
    Rejected,
}

impl LinkStatus {
    pub fn name(self) -> &'static str {
        match self {
            LinkStatus::Proposed => "proposed",
            LinkStatus::Accepted => "accepted",
            LinkStatus::Rejected => "rejected",
        }
    }
}

/// Relations between records (contract §2, §4.2). `duplicate_of` is the builder's `mark_duplicate`.
pub const RELATIONS: [&str; 7] = ["supports", "contradicts", "qualifies", "supersedes", "depends_on", "same_as", "duplicate_of"];

/// A record as the kernel stores it (agent-local ids already resolved to record ids).
#[derive(Debug, Clone, PartialEq)]
pub struct RecordView {
    pub id: RecordId,
    /// Position in the audit stream (the builder's cursor counts these).
    pub seq: u64,
    pub kind: RecordKind,
    pub author: String,
    pub directive: String,
    /// `observe`: the bound document and quote.
    pub doc_id: Option<String>,
    pub quote: Option<String>,
    /// The agent's own words for what the record is about (`terms`, `subject`/`object` of a claim, `about` of a question).
    pub terms: Vec<String>,
    /// `claim`/`hypothesis`/`question` text.
    pub text: Option<String>,
    /// The agent's stance on the source (`stance`: reported/confirmed/refuted/...). An interpretation, never an acceptance
    /// (contract v0.1 R3).
    pub status: Option<String>,
    /// Records this one rests on (`based_on`), and for a `relation` record its two ends.
    pub based_on: Vec<RecordId>,
    pub ends: Option<(RecordId, String, RecordId)>,
    /// The canonical record as stored (for directives and audits).
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConceptView {
    pub id: ConceptId,
    pub ty: String,
    pub name: String,
    pub aliases: Vec<String>,
    /// `accepted` / `proposed` / `retired`.
    pub status: String,
    /// The broad function of the system the concept belongs to (the graph's "address" layer). An
    /// address, never an identity: two concepts of one function are not the same thing, and ending one ends neither the other nor
    /// the function. Set once, by the first proposal that names it.
    pub function: Option<String>,
}

impl ConceptView {
    pub fn selectable(&self) -> bool {
        !matches!(self.status.as_str(), "retired" | "narrowed" | "unattested")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkView {
    pub id: LinkId,
    pub from: RecordId,
    pub rel: String,
    pub to: RecordId,
    pub status: LinkStatus,
    /// Who proposed it (`builder`, an agent id, `kernel`, `owner`) and on what records.
    pub by: String,
    pub basis: Vec<RecordId>,
}

/// What a directive allows a swarm agent to touch: documents (optionally a byte range of one) and a topic key.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scope {
    pub docs: Vec<String>,
    pub topic: Option<String>,
    /// `(doc_id, byte_start, byte_end)`: an `observe` quote must lie inside one of these (empty = the whole of `docs`).
    pub ranges: Vec<(String, usize, usize)>,
}

/// Outcome of a record batch: the accepted prefix and the first refused line (fail-fast, one-step repair).
#[derive(Debug, Clone, Default)]
pub struct SubmitReport {
    pub accepted: Vec<RecordId>,
    pub failed_index: Option<usize>,
    pub error: Option<KernelError>,
}

/// What a coordinator submission id already holds (read without writing).
#[derive(Debug, Clone)]
pub enum Prior {
    /// The id was never used.
    Free,
    /// The id holds exactly this request: its stored result.
    Same(Result<Value, KernelError>),
    /// The id holds another request.
    Other,
}

/// The storage side of the audit layer. `state::AuditState` implements it on the kernel (journal, root, byte-bound quotes);
/// tests may use an in-memory implementation.
pub trait AuditStore {
    /// Documents known to the session (`doc_id`s, in load order).
    fn docs(&self) -> Vec<String>;
    fn document_label(&self, id: &str) -> String {
        id.to_string()
    }
    /// The report date (`YYYY-MM-DD`) a document's pinned manifest entry declares, when it declares one.
    fn document_date(&self, _id: &str) -> Option<String> {
        None
    }
    /// The UTF-8 text of a document (directives hand agents the section they must read).
    fn doc_text(&self, doc_id: &str) -> Option<String>;
    /// The bytes of a document that standing accepted quotes are bound to, for the gap pass (SPEC_V02_GAP_PASS section 3). The
    /// default places each standing quote at its first occurrence, as a store without bound spans can.
    fn quoted_spans(&self, doc_id: &str) -> Vec<(usize, usize)> {
        let text = self.doc_text(doc_id).unwrap_or_default();
        self.records_of_kind(RecordKind::Observe)
            .into_iter()
            .filter(|r| r.doc_id.as_deref() == Some(doc_id) && self.is_grounded(&r.id))
            .filter_map(|r| r.quote.filter(|q| !q.is_empty()).and_then(|q| text.find(&q).map(|a| (a, a + q.len()))))
            .collect()
    }
    /// The standing quotes of a document with the bytes they are bound to: the spans of `quoted_spans`, each with its record, for
    /// the coverage table. The default places each standing quote at its first occurrence, as `quoted_spans` does.
    fn quoted_records(&self, doc_id: &str) -> Vec<(RecordId, usize, usize)> {
        let text = self.doc_text(doc_id).unwrap_or_default();
        self.records_of_kind(RecordKind::Observe)
            .into_iter()
            .filter(|r| r.doc_id.as_deref() == Some(doc_id) && self.is_grounded(&r.id))
            .filter_map(|r| r.quote.filter(|q| !q.is_empty()).and_then(|q| text.find(&q).map(|a| (r.id, a, a + q.len()))))
            .collect()
    }
    /// The byte ranges of a document closed by a withdrawal of its text (every occurrence of each closed text). Default: none.
    fn closed_spans(&self, _doc_id: &str) -> Vec<(usize, usize)> {
        Vec::new()
    }
    /// Validate and store swarm records (contract §2, v0.1 R1-R5), stopping at the first refused line. A `relation` record also
    /// creates its link through `add_link` (status `Proposed`, the same path as the builder's links: v0.1 R3).
    fn submit_records(&mut self, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport;
    /// Explicit transport retry identity. Simple in-memory test stores may keep the compatibility implementation;
    /// durable stores override it and persist the request hash/accepted-prefix receipt before acknowledging.
    fn submit_records_id(&mut self, _submission_id: &str, agent: &str, directive: &str, scope: &Scope, lines: &[Value]) -> SubmitReport {
        self.submit_records(agent, directive, scope, lines)
    }
    /// Issued reference capabilities, separate from document ranges. Real transports should use the durable override.
    fn submit_scoped_records_id(&mut self, id: &str, agent: &str, directive: &str, scope: &Scope, _issued: &[RecordId], lines: &[Value]) -> SubmitReport {
        self.submit_records_id(id, agent, directive, scope, lines)
    }
    /// Records with `seq > cursor`, in order.
    fn records_since(&self, cursor: u64) -> Vec<RecordView>;
    /// The records of one kind, in order: `records_since(0)` filtered, which a store can give without copying the others.
    fn records_of_kind(&self, kind: RecordKind) -> Vec<RecordView> {
        self.records_since(0).into_iter().filter(|r| r.kind == kind).collect()
    }
    fn record(&self, id: &RecordId) -> Option<RecordView>;
    /// The record `agent` stored under `local_id` in `directive`, read only: a question's `about` may name a line of its own answer
    /// (live run 10A-5). A store that keeps no local ids answers None.
    fn local_record(&self, _agent: &str, _directive: &str, _local_id: &str) -> Option<RecordId> {
        None
    }
    /// Structural provenance and established answer support are separate axes. Production orchestration must consult
    /// these after mutations/recovery, rather than treating the continued existence of a `done` record as completion.
    fn is_grounded(&self, id: &RecordId) -> bool {
        self.record(id).is_some()
    }
    fn is_answer_support(&self, id: &RecordId) -> bool {
        self.record(id).is_some_and(|r| !matches!(r.kind, RecordKind::Hypothesis | RecordKind::Question | RecordKind::Done))
    }
    /// The last record seq (0 when empty).
    fn head(&self) -> u64;

    /// (version, hash) of the audit ontology.
    fn ontology_version(&self) -> (u64, Hash);
    /// Concept types of the audit ontology.
    fn concept_types(&self) -> Vec<String>;
    /// Concepts whose normalized name or alias matches `term` (deterministic), best first.
    fn candidates(&self, term: &str, limit: usize) -> Vec<ConceptView>;
    fn concept(&self, id: &ConceptId) -> Option<ConceptView>;
    /// A provisional concept of a known type. A separate authorized decision accepts it; a name match is not identity proof.
    fn propose_concept(&mut self, by: &str, ty: &str, name: &str, aliases: &[String], basis: &[RecordId]) -> Result<ConceptView, KernelError>;
    fn map_term(&mut self, by: &str, rec: &RecordId, term: &str, concept: &ConceptId) -> Result<(), KernelError>;
    /// Concepts a record is mapped to.
    fn concepts_of(&self, rec: &RecordId) -> Vec<ConceptId>;
    /// Distinct stored record-term associations, not map calls or every lexical term of a mapped record.
    /// Compatibility stores may omit this inventory; anomaly hints then abstain on mapping-dependent conditions.
    /// First authenticated mapper of each distinct association; telemetry for independent review selection.
    fn mapping_authors_of(&self, _concept: &ConceptId) -> Option<Vec<(String, usize)>> {
        None
    }
    fn mapped_terms_of(&self, _concept: &ConceptId) -> Option<Vec<(RecordId, String)>> {
        None
    }
    /// Records mapped to a concept.
    fn records_of(&self, concept: &ConceptId) -> Vec<RecordId>;

    /// A link between two records; always stored `Proposed` (idempotent: the same link returns the same id).
    fn add_link(&mut self, by: &str, from: &RecordId, rel: &str, to: &RecordId, basis: &[RecordId]) -> Result<LinkView, KernelError>;
    fn set_link_status(&mut self, id: &LinkId, status: LinkStatus, by: &str, basis: &[RecordId]) -> Result<(), KernelError>;
    fn link(&self, id: &LinkId) -> Option<LinkView>;
    fn links(&self) -> Vec<LinkView>;
    fn links_of(&self, rec: &RecordId) -> Vec<LinkView>;
    fn link_usable(&self, id: &LinkId) -> bool {
        self.link(id).is_some_and(|l| l.status == LinkStatus::Accepted)
    }
    /// `link_usable` of every link at once, when the store can give it in one pass (`None`: ask link by link).
    /// Accepted supersession history survives later rejection or loss of proof; it is not current link usability.
    fn supersession_history(&self) -> Vec<LinkView> {
        self.links().into_iter().filter(|l| l.rel == "supersedes" && l.status == LinkStatus::Accepted).collect()
    }
    fn usable_links(&self) -> Option<std::collections::BTreeSet<LinkId>> {
        None
    }
    /// Every concept of the audit ontology (retrieval by a topic inside a name or alias: a candidate, never an identity).
    /// Opt-in revision state; absent on historical sessions and compatibility stores.
    fn ontology_revision_state(&self) -> Option<Value> {
        None
    }

    fn concepts(&self) -> Vec<ConceptView> {
        Vec::new()
    }

    /// One trusted coordinator transaction: operation prefix, receipt and optional processed-cursor checkpoint.
    /// Stateless test stores do not promise durability. A transport must not silently fall back to individual calls.
    fn submit_operations_id(&mut self, _submission_id: &str, _actor: &str, _operations: &[Value], _checkpoint: Option<Value>) -> Result<Value, KernelError> {
        Err(KernelError::new(crate::error::Code::BadField, "this audit store does not provide durable coordinator transactions"))
    }
    fn checkpoint(&self, _key: &str) -> Option<Value> {
        None
    }
    /// Presence checks must not copy a large derived map merely to inspect its policy bit.
    fn has_checkpoint(&self, key: &str) -> bool {
        self.checkpoint(key).is_some()
    }
    /// Startup inventory, without copying checkpoint bodies. Durable stores override this for lifecycle recovery.
    fn checkpoint_keys(&self, _prefix: &str) -> Vec<String> {
        Vec::new()
    }
    /// The stored outcome of exactly this coordinator transaction, read without writing anything: `None` when the id was never
    /// used, an error when the id holds other content. A coordinator answers a lost acknowledgement or picks a fresh repair id
    /// from it, also after a restart.
    fn operations_receipt(&self, _submission_id: &str, _actor: &str, _operations: &[Value], _checkpoint: Option<Value>) -> Prior {
        Prior::Free
    }
    /// The stored outcome under a coordinator submission id, whatever its request (read without writing): a coordinator rebuilds
    /// what it had committed before a restart from it.
    fn receipt_outcome(&self, _submission_id: &str, _actor: &str) -> Option<Value> {
        None
    }
    /// Every record's (grounded, answer support) flags in one pass, when the store can give them at once (a coordinator asking
    /// record by record would make each of its calls quadratic in the records).
    fn support_map(&self) -> Option<std::collections::BTreeMap<RecordId, (bool, bool)>> {
        None
    }
    /// `quality::stale::suspects`, when the store keeps it for an unchanged state (`None`: computed at each call).
    fn stale_suspects(&self) -> Option<Vec<RecordId>> {
        None
    }
    /// A fixed identity of the run (run id and corpus manifest, from the genesis): the namespace of coordinator identities.
    fn run_namespace(&self) -> Hash {
        [0; 32]
    }

    /// Commitment over records, audit ontology, links and statuses (combined with the engine root by the session).
    fn root(&self) -> Hash;

    /// The epoch the dispatcher's task numbers are drawn under: the audit root by default; a 0.2 journal answers its chain head,
    /// which costs nothing to read (SPEC_V02_STEP2 section 8).
    fn epoch(&self) -> Hash {
        self.root()
    }
}

/// Bounded deterministic pair retrieval and procedural scope checks (consilium A4).
pub mod pairs;
pub mod quality;
pub mod refine;

/// Optional durable bounded retries of failed agents.
pub mod agent_failures;
