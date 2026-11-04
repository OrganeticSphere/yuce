//! Compiler-driven directive emitter (Addendum v0.2).
//!
//! The kernel stops being a passive notice board. From the verified state of a container and a list of target goals it
//!
//! 1. computes the *frontier* of unfinished work (`FrontierGapAnalyzer`), ordered by priority
//!    `P0 resolve a polar conflict / apply an amendment` < `P1 repair a target that lost its support` <
//!    `P2 complete a Horn derivation` (2A: every premise is already supported, 2B: one premise is missing and the
//!    source segment that can state it is known) < `P3 formalise an uncovered segment that mentions a target` <
//!    `P4 nothing left`;
//! 2. partitions that frontier over the agent seats of one parallel round so that two seats never receive the same
//!    target entity or the same source segment (`emit_batch`), and leaves surplus seats idle (no model call at all);
//! 3. packs one self-contained `DirectiveFrame` per seat: 1-3 source sentences instead of the document, the minimal
//!    support cone of the target instead of the graph, an ontology slice instead of the ontology, and an instruction text
//!    written by the kernel with precomputed premise ids and intervals.
//!
//! A worker that receives a frame needs nothing else; after its events are committed its context is discarded.
//!
//! Source segments are sentences of the visible documents. Mentions of entities are found through the ontology's
//! canonical ids and aliases (whole-word, ASCII case-insensitive). Amendments are recognised by keywords
//! ("erratum", "withdrawn", "supersedes", ...); inside an amendment sentence a clause label that precedes the
//! withdrawal keyword is the withdrawn clause and a label after "stands in" / "restated in" / "replaced by" is its
//! replacement. These are deterministic heuristics, documented as such; the kernel still verifies every event.
//!
//! Everything the analysis derives from immutable inputs - the ontology's name index, the sentences of a document version
//! with their mentions, labels and type signatures, the byte span and quote of an evidence node - lives in a
//! `DirectiveCache`. A resident compiler (`sbgk serve`, op `directives`) keeps one for the whole session, so a round only
//! pays for the graph; a one-shot call (`emit-batch-directives`) starts from an empty one. The output does not depend on
//! the cache.

use crate::arena::DocEntry;
use crate::engine::{ConeReader, NodeView};
use crate::hash::{sha256, short, to_hex, Hash};
use crate::merkle::{FxMap, FxSet, IdMap, IdSet};
use crate::node::*;
use crate::ontology::{Field, Mode, ObjType, Ontology, Rule, Term};
use crate::session::Session;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

// ------------------------------------------------------------------------------------------ types

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    P0ResolvePolarConflict = 0,
    P1RepairRevokedTarget = 1,
    P2CompleteHornDerivation = 2,
    P3FormalizeUncoveredChunk = 3,
    P4NoOpComplete = 4,
}

impl Priority {
    pub fn name(self) -> &'static str {
        match self {
            Priority::P0ResolvePolarConflict => "P0_ResolvePolarConflict",
            Priority::P1RepairRevokedTarget => "P1_RepairRevokedTarget",
            Priority::P2CompleteHornDerivation => "P2_CompleteHornDerivation",
            Priority::P3FormalizeUncoveredChunk => "P3_FormalizeUncoveredChunk",
            Priority::P4NoOpComplete => "P4_NoOpComplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Goal {
    pub entity: String,
    pub predicate: String,
}

/// What the team must close: one goal per (entity, goal predicate), and the documents the compiler may route work to.
#[derive(Debug, Clone, Default)]
pub struct Targets {
    pub goals: Vec<Goal>,
    pub docs: Option<Vec<String>>,
}

impl Targets {
    /// `{"goals":[{"entity":"svc_001","predicate":"needs_review"},...], "docs":["policy"]}`
    /// (`"entities":[...]` + `"predicate":"..."` is accepted as a shorthand).
    pub fn from_json(v: &Value) -> Result<Targets, String> {
        let mut goals = Vec::new();
        if let Some(a) = v.get("goals").and_then(|x| x.as_array()) {
            for g in a {
                let e = g.get("entity").and_then(|x| x.as_str()).ok_or("goal without entity")?;
                let p = g.get("predicate").and_then(|x| x.as_str()).ok_or("goal without predicate")?;
                goals.push(Goal { entity: e.to_string(), predicate: p.to_string() });
            }
        }
        if let (Some(a), Some(p)) = (v.get("entities").and_then(|x| x.as_array()), v.get("predicate").and_then(|x| x.as_str())) {
            for e in a.iter().filter_map(|x| x.as_str()) {
                goals.push(Goal { entity: e.to_string(), predicate: p.to_string() });
            }
        }
        let docs = v.get("docs").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        Ok(Targets { goals, docs })
    }
}

/// What a sentence states independently of the graph; computed once per document version and shared by every analysis.
#[derive(Debug)]
pub struct SegText {
    pub id: String,
    pub doc_id: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub mentions: Vec<String>,
    pub labels: Vec<(usize, String)>,
    pub own_label: Option<String>,
    pub amendment: bool,
    /// Entity types of the mentions (the sentence's type signature).
    pub types: BTreeSet<String>,
    /// Entity type of each mention (parallel to `mentions`).
    mention_types: Vec<Option<String>>,
    /// Amendment sentences: first withdrawal / replacement keyword in the lower-cased text.
    withdraw_at: Option<usize>,
    replace_at: Option<usize>,
}

/// A sentence of a visible document in one analysis: its text facts plus what the graph says about it.
#[derive(Debug, Clone)]
pub struct Segment {
    pub idx: usize,
    pub facts: Arc<SegText>,
    pub covered_active: Vec<Hash>,
    pub covered_revoked: Vec<Hash>,
    /// Some active evidence on this sentence is referenced by an active assertion.
    pub asserted: bool,
    pub withdrawn: bool,
}

impl Deref for Segment {
    type Target = SegText;
    fn deref(&self) -> &SegText {
        &self.facts
    }
}

impl SegText {
    fn typed_mentions(&self) -> impl Iterator<Item = (&str, Option<&str>)> + '_ {
        self.mentions.iter().zip(&self.mention_types).map(|(m, t)| (m.as_str(), t.as_deref()))
    }
}

impl Segment {
    /// Formalized: an active assertion rests on an evidence span of this sentence, or the sentence's evidence was revoked.
    /// Evidence that is bound but carries no assertion (a lease that closed between `bind_evidence` and `assert_fact`)
    /// does not cover the sentence, so the sentence is handed out again instead of being lost.
    pub fn covered(&self) -> bool {
        self.asserted || !self.covered_revoked.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ClaimInfo<'s> {
    pub id: Hash,
    pub claim: &'s Claim,
    pub status: u8,
    /// (evidence id, assertion active)
    pub asserted_by: Vec<(Hash, bool)>,
}

#[derive(Debug, Clone)]
pub struct EvInfo<'s> {
    pub id: Hash,
    pub ev: &'s EvidenceNode,
    pub status: u8,
    pub span: Option<(usize, usize)>,
    pub quote: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct ReadyDerivation {
    pub rule: String,
    pub premises: Vec<Hash>,
    pub head: Claim,
}

#[derive(Debug, Clone)]
pub struct FrontierGap {
    pub gap_id: String,
    pub priority: Priority,
    pub kind: &'static str,
    pub target: String,
    pub segments: Vec<usize>,
    pub nodes: Vec<Hash>,
    pub derive: Option<ReadyDerivation>,
    pub resupport: Option<Claim>,
    /// For EXTRACT_PARTNER / FORMALIZE: the supported premise the new fact will join with (to derive in the same step).
    pub partner: Option<(String, Hash)>,
    pub est_events: usize,
    pub note: String,
    /// FORMALIZE only: the clauses may contradict each other or the existing conclusion (no same-step derive is offered).
    pub may_conflict: bool,
}

/// The frontier of one state. Claims and evidence are borrowed from the session it was computed from.
#[derive(Debug, Clone)]
pub struct Analysis<'s> {
    pub segments: Vec<Segment>,
    pub claims: Vec<ClaimInfo<'s>>,
    pub evidence: Vec<EvInfo<'s>>,
    pub gaps: Vec<FrontierGap>,
    pub goal_state: BTreeMap<String, &'static str>,
    pub analysis_us: f64,
    claim_ix: IdMap<usize>,
    ev_ix: IdMap<usize>,
}

impl<'s> Analysis<'s> {
    pub fn complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub(crate) fn claim(&self, id: &Hash) -> Option<&ClaimInfo<'s>> {
        self.claim_ix.get(id).map(|&i| &self.claims[i])
    }

    pub(crate) fn ev(&self, id: &Hash) -> Option<&EvInfo<'s>> {
        self.ev_ix.get(id).map(|&i| &self.evidence[i])
    }
}

// ------------------------------------------------------------------------------------------ cache

/// One atom `i` of a two-atom AND rule (the atom a sentence's fact would fill) and what the partner atom `j` needs.
struct Side {
    slots_i: BTreeSet<String>,
    pj_p: String,
    pj_pol: Polarity,
    want: BTreeSet<String>,
    /// per join condition: entity type of atom i's field (None if it is not entity-typed), joined field of atom j
    joins: Vec<(Option<String>, Field)>,
}

/// A two-atom AND rule that concludes some goal predicate, both atoms as `Side`s (i = 0, 1).
struct RulePlan {
    rule_id: String,
    sides: Vec<Side>,
}

/// Name index, aliases, predicate slot types and rule plans of one ontology.
struct OntoCache {
    hash: Hash,
    names: FxMap<String, Vec<String>>,
    maxn: usize,
    aliases: FxMap<String, Vec<String>>,
    slots: FxMap<String, BTreeSet<String>>,
    /// head predicate -> its two-atom AND rules, in rule-id order
    plans: FxMap<String, Vec<RulePlan>>,
}

static NO_TYPES: BTreeSet<String> = BTreeSet::new();

impl OntoCache {
    fn build(onto: &Ontology) -> OntoCache {
        let (names, maxn) = name_index(onto);
        let mut aliases: FxMap<String, Vec<String>> = FxMap::default();
        for n in onto.entity_names() {
            if let Ok(e) = onto.resolve_entity(n) {
                if n.as_str() != e.id {
                    aliases.entry(e.id.clone()).or_default().push(n.clone());
                }
            }
        }
        for v in aliases.values_mut() {
            v.sort();
        }
        let slots = onto.predicates.keys().map(|p| (p.clone(), slot_types(onto, p))).collect();
        let field_ty = |p: &str, f: Field| -> Option<String> {
            let pr = onto.predicates.get(p)?;
            match f {
                Field::S => Some(pr.subject.clone()),
                Field::O => match &pr.object {
                    ObjType::Entity(t) => Some(t.clone()),
                    ObjType::Literal => None,
                },
            }
        };
        let mut plans: FxMap<String, Vec<RulePlan>> = FxMap::default();
        for rule in onto.rules.values().filter(|r| r.mode == Mode::And && r.body.len() == 2) {
            let sides = (0..2)
                .map(|i| {
                    let j = 1 - i;
                    Side {
                        slots_i: slot_types(onto, &rule.body[i].p),
                        pj_p: rule.body[j].p.clone(),
                        pj_pol: rule.body[j].pol,
                        want: slot_types(onto, &rule.body[j].p),
                        joins: joins_between(rule, i, j).into_iter().map(|(fi, fj)| (field_ty(&rule.body[i].p, fi), fj)).collect(),
                    }
                })
                .collect();
            plans.entry(rule.head.p.clone()).or_default().push(RulePlan { rule_id: rule.id.clone(), sides });
        }
        OntoCache { hash: onto.hash, names, maxn, aliases, slots, plans }
    }

    fn plans(&self, head_p: &str) -> &[RulePlan] {
        self.plans.get(head_p).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Entity-typed slot types of a predicate (empty for an unknown predicate).
    fn slots(&self, p: &str) -> &BTreeSet<String> {
        self.slots.get(p).unwrap_or(&NO_TYPES)
    }

    /// Every other name (alias) that resolves to `entity`, sorted.
    fn aliases(&self, entity: &str) -> &[String] {
        self.aliases.get(entity).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

struct DocCache {
    version: Hash,
    segs: Vec<Arc<SegText>>,
    /// entity -> positions (ascending) of the sentences that mention it
    by_entity: Arc<FxMap<String, Vec<usize>>>,
}

struct EvCache {
    /// Version of the evidence's document the span was computed against (spans are positions in the current version).
    version: Option<Hash>,
    span: Option<(usize, usize)>,
    quote: Arc<str>,
}

/// How much of the last analyses was served from the cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    pub analyses: u64,
    pub docs_built: u64,
    pub docs_reused: u64,
    pub evidence_built: u64,
    pub evidence_reused: u64,
}

/// Memo of everything the frontier analysis derives from immutable inputs (see the module docs). Keyed by content: the
/// ontology hash, the document version id, the evidence node id (+ the version its span refers to).
#[derive(Default)]
pub struct DirectiveCache {
    onto: Option<OntoCache>,
    docs: FxMap<String, DocCache>,
    evidence: IdMap<EvCache>,
    derivations: DeriveMemo,
    pub stats: CacheStats,
}

/// Rule applications by (sha256(rule id), premise ids in body order) -> (head id, derivation), or None when the premises do
/// not combine (join, context or interval). Claims are immutable, so an entry never goes stale.
type DeriveMemo = FxMap<Vec<Hash>, Option<(Hash, ReadyDerivation)>>;

impl DirectiveCache {
    pub fn new() -> DirectiveCache {
        DirectiveCache::default()
    }

    fn prepare(&mut self, onto: &Ontology) {
        if self.onto.as_ref().map(|o| o.hash) != Some(onto.hash) {
            // mentions, type signatures and rule heads depend on the ontology: a different one invalidates them all
            self.docs.clear();
            self.derivations.clear();
            self.onto = Some(OntoCache::build(onto));
        }
    }

    fn onto(&self) -> &OntoCache {
        self.onto.as_ref().expect("the analysis prepares the cache before frames are packed")
    }

    pub fn stats_json(&self) -> Value {
        let st = &self.stats;
        json!({"analyses": st.analyses, "docs_built": st.docs_built, "docs_reused": st.docs_reused,
               "evidence_built": st.evidence_built, "evidence_reused": st.evidence_reused,
               "docs_cached": self.docs.len(), "evidence_cached": self.evidence.len(), "derivations_cached": self.derivations.len()})
    }
}

/// Sentences of one document version with their text facts (cached per version).
fn doc_facts<'c>(docs: &'c mut FxMap<String, DocCache>, st: &mut CacheStats, oc: &OntoCache, onto: &Ontology, d: &str, entry: &DocEntry) -> &'c DocCache {
    if docs.get(d).map(|c| c.version == entry.version_id).unwrap_or(false) {
        st.docs_reused += 1;
    } else {
        st.docs_built += 1;
        let bytes = &entry.bytes;
        // one tokenization of the whole document: a sentence's tokens are the ones that start inside it (no token crosses a
        // sentence boundary, which is always a '.', a line break or whitespace)
        let toks = tokenize(bytes);
        let segs = split_sentences(bytes)
            .into_iter()
            .map(|(a, b)| {
                let text_b = &bytes[a..b];
                let (lo, hi) = (toks.at.partition_point(|&p| p < a), toks.at.partition_point(|&p| p < b));
                let mentions: Vec<String> = mentions_in(&toks, lo, hi, &oc.names, oc.maxn).into_iter().collect();
                let labels = find_labels(text_b);
                let own_label = labels.iter().find(|(p, l)| text_b.get(p + l.len()) == Some(&b':')).map(|x| x.1.clone());
                let text = String::from_utf8_lossy(text_b).into_owned();
                let lower = text.to_lowercase();
                let amendment = AMENDMENT_WORDS.iter().any(|w| lower.contains(w));
                let (withdraw_at, replace_at) = if amendment { (first_pos(&lower, WITHDRAW_WORDS), first_pos(&lower, REPLACE_WORDS)) } else { (None, None) };
                let mention_types: Vec<Option<String>> = mentions.iter().map(|m| entity_type(onto, m).map(String::from)).collect();
                let types = mention_types.iter().flatten().cloned().collect();
                Arc::new(SegText {
                    id: format!("{d}:{a}"),
                    doc_id: d.to_string(),
                    start: a,
                    end: b,
                    text,
                    mentions,
                    labels,
                    own_label,
                    amendment,
                    types,
                    mention_types,
                    withdraw_at,
                    replace_at,
                })
            })
            .collect::<Vec<Arc<SegText>>>();
        let mut by_entity: FxMap<String, Vec<usize>> = FxMap::default();
        for (i, g) in segs.iter().enumerate() {
            for m in &g.mentions {
                by_entity.entry(m.clone()).or_default().push(i);
            }
        }
        docs.insert(d.to_string(), DocCache { version: entry.version_id, segs, by_entity: Arc::new(by_entity) });
    }
    &docs[d]
}

/// Byte span of an evidence node in the current version of its document, and its quote (cached per node and version).
fn evidence_facts(cache: &mut IdMap<EvCache>, st: &mut CacheStats, s: &Session, id: &Hash, ev: &EvidenceNode) -> (Option<(usize, usize)>, Arc<str>) {
    let doc = s.arena.doc(&ev.doc_id);
    let version = doc.map(|d| d.version_id);
    if let Some(c) = cache.get(id) {
        if c.version == version {
            st.evidence_reused += 1;
            return (c.span, c.quote.clone());
        }
    }
    st.evidence_built += 1;
    let span = doc.and_then(|d| {
        let first = ev.segs.first()?;
        let last = ev.segs.last()?;
        let i0 = d.chunk_hashes.iter().position(|h| *h == first.chunk)?;
        let i1 = d.chunk_hashes.iter().skip(i0).position(|h| *h == last.chunk)? + i0;
        Some((d.chunk_starts[i0] + first.start as usize, d.chunk_starts[i1] + last.end as usize))
    });
    let quote: Arc<str> = s.arena.quote_bytes(ev).map(|q| String::from_utf8_lossy(&q).into_owned()).unwrap_or_default().into();
    cache.insert(*id, EvCache { version, span, quote: quote.clone() });
    (span, quote)
}

// ------------------------------------------------------------------------------------------ text helpers

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Sentences of a document: split after ". " / ".\n" and at line breaks; trimmed; empty pieces dropped.
pub fn split_sentences(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let n = bytes.len();
    let push = |s: usize, e: usize, out: &mut Vec<(usize, usize)>| {
        let (mut a, mut b) = (s, e);
        while a < b && bytes[a].is_ascii_whitespace() {
            a += 1;
        }
        while b > a && bytes[b - 1].is_ascii_whitespace() {
            b -= 1;
        }
        if a < b {
            out.push((a, b));
        }
    };
    let mut i = 0;
    while i < n {
        let b = bytes[i];
        if b == b'\n' {
            push(start, i, &mut out);
            start = i + 1;
        } else if b == b'.' && (i + 1 == n || bytes[i + 1] == b' ' || bytes[i + 1] == b'\r') {
            push(start, i + 1, &mut out);
            start = i + 1;
        }
        i += 1;
    }
    push(start, n, &mut out);
    out
}

/// Whole-word, ASCII-case-insensitive occurrences of `needle` in `hay`.
#[cfg(test)]
fn find_words(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > hay.len() {
        return out;
    }
    for i in 0..=hay.len() - needle.len() {
        if hay[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            let before = i == 0 || !is_word(hay[i - 1]);
            let after = i + needle.len() == hay.len() || !is_word(hay[i + needle.len()]);
            if before && after {
                out.push(i);
            }
        }
    }
    out
}

/// Clause labels such as `U.12`, `D.3`, `E.1`: one uppercase letter, a dot, digits; not part of a longer token.
fn find_labels(text: &[u8]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let n = text.len();
    let mut i = 0;
    while i < n {
        let ok_before = i == 0 || !(is_word(text[i - 1]) || text[i - 1] == b'.');
        if ok_before && text[i].is_ascii_uppercase() && i + 2 < n && text[i + 1] == b'.' && text[i + 2].is_ascii_digit() {
            let mut j = i + 2;
            while j < n && text[j].is_ascii_digit() {
                j += 1;
            }
            let ok_after = j == n || !(is_word(text[j]) || (text[j] == b'.' && j + 1 < n && text[j + 1].is_ascii_digit()));
            if ok_after {
                out.push((i, String::from_utf8_lossy(&text[i..j]).into_owned()));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

const AMENDMENT_WORDS: &[&str] = &["erratum", "amendment", "supersede", "exception", "revocation", "withdrawn", "revoked", "repealed", "recorded in error"];
const WITHDRAW_WORDS: &[&str] = &["withdrawn", "revoked", "repealed", "recorded in error", "no longer in force"];
const REPLACE_WORDS: &[&str] = &["stands in", "restated in", "replaced by", "superseded by", "now stated in"];

fn first_pos(lower: &str, words: &[&str]) -> Option<usize> {
    words.iter().filter_map(|w| lower.find(w)).min()
}

// ------------------------------------------------------------------------------------------ analysis

/// Lower-cased word tokens (runs of ASCII alphanumerics and '_') joined by single spaces, with the span of every token in
/// the joined text and its byte offset in the input: an n-gram of consecutive tokens is a slice of `joined`.
struct Tokens {
    joined: String,
    spans: Vec<(usize, usize)>,
    at: Vec<usize>,
}

fn tokenize(text: &[u8]) -> Tokens {
    let mut joined: Vec<u8> = Vec::with_capacity(text.len());
    let mut spans: Vec<(usize, usize)> = Vec::with_capacity(text.len() / 4);
    let mut at: Vec<usize> = Vec::with_capacity(text.len() / 4);
    let mut in_tok = false;
    for (pos, &b) in text.iter().enumerate() {
        if is_word(b) {
            if !in_tok {
                if !joined.is_empty() {
                    joined.push(b' ');
                }
                spans.push((joined.len(), 0));
                at.push(pos);
                in_tok = true;
            }
            joined.push(b.to_ascii_lowercase());
        } else if in_tok {
            spans.last_mut().unwrap().1 = joined.len();
            in_tok = false;
        }
    }
    if in_tok {
        spans.last_mut().unwrap().1 = joined.len();
    }
    // word bytes are ASCII, so the joined text is always valid UTF-8
    Tokens { joined: String::from_utf8(joined).expect("ASCII tokens"), spans, at }
}

/// Name index: token sequence of every canonical id and alias -> entity ids (sorted); plus the longest name in tokens.
fn name_index(onto: &Ontology) -> (FxMap<String, Vec<String>>, usize) {
    let mut idx: FxMap<String, Vec<String>> = FxMap::default();
    let mut maxn = 1;
    for name in onto.entity_names() {
        let ids: Vec<String> = match onto.resolve_entity(name) {
            Ok(e) => vec![e.id.clone()],
            Err(crate::ontology::ResolveErr::Ambiguous { candidates }) => candidates,
            Err(_) => continue,
        };
        let t = tokenize(name.as_bytes());
        if t.spans.is_empty() {
            continue;
        }
        maxn = maxn.max(t.spans.len());
        idx.entry(t.joined).or_default().extend(ids);
    }
    for ids in idx.values_mut() {
        ids.sort();
        ids.dedup();
    }
    (idx, maxn)
}

/// Entities named by tokens `lo..hi` of a tokenized text (every n-gram up to the longest name).
fn mentions_in(t: &Tokens, lo: usize, hi: usize, idx: &FxMap<String, Vec<String>>, maxn: usize) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for i in lo..hi {
        for n in 1..=maxn.min(hi - i) {
            if let Some(ids) = idx.get(&t.joined[t.spans[i].0..t.spans[i + n - 1].1]) {
                out.extend(ids.iter().cloned());
            }
        }
    }
    out
}

fn entity_type<'o>(onto: &'o Ontology, id: &str) -> Option<&'o str> {
    onto.entities.get(id).map(|e| e.ty.as_str())
}

pub(crate) fn field_of(c: &Claim, f: Field) -> &str {
    match f {
        Field::S => &c.s,
        Field::O => &c.o,
    }
}

fn eval_term(t: &Term, prem: &[&Claim]) -> String {
    match t {
        Term::Const(c) => c.clone(),
        Term::Ref(i, Field::S) => prem[*i].s.clone(),
        Term::Ref(i, Field::O) => prem[*i].o.clone(),
    }
}

/// Entity-typed slot types of a predicate (as a sorted set), e.g. uses_api -> {Api, Service}, api_deprecated -> {Api}.
fn slot_types(onto: &Ontology, p: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(pr) = onto.predicates.get(p) {
        out.insert(pr.subject.clone());
        if let ObjType::Entity(t) = &pr.object {
            out.insert(t.clone());
        }
    }
    out
}

/// Join conditions of a two-atom rule seen from atom `i`: (field of atom i, field of atom j) pairs.
pub(crate) fn joins_between(rule: &Rule, i: usize, j: usize) -> Vec<(Field, Field)> {
    rule.join
        .iter()
        .filter_map(|((a, af), (b, bf))| {
            if *a == i && *b == j {
                Some((*af, *bf))
            } else if *a == j && *b == i {
                Some((*bf, *af))
            } else {
                None
            }
        })
        .collect()
}

fn gap_id(kind: &str, target: &str, parts: &[String]) -> String {
    let mut s = format!("{kind}|{target}");
    for p in parts {
        s.push('|');
        s.push_str(p);
    }
    to_hex(&sha256(s.as_bytes())[..6])
}

/// Lookup structures of one analysis (built once, shared by the P2/P3 passes).
struct Ix<'a> {
    oc: &'a OntoCache,
    segments: &'a [Segment],
    /// per visible document: index of its first segment, entity -> positions of its sentences that mention it
    doc_ix: Vec<(usize, Arc<FxMap<String, Vec<usize>>>)>,
    claims: &'a [ClaimInfo<'a>],
    /// predicate -> indices of its claims (in claim order)
    by_p: FxMap<&'a str, Vec<usize>>,
    /// (predicate, field is the object, value) of every claim that is not UNSUPPORTED
    live: FxSet<(&'a str, bool, &'a str)>,
}

impl<'a> Ix<'a> {
    /// Indices (ascending) of the segments that mention entity `e`.
    fn mentioning<'b>(&'b self, e: &'b str) -> impl Iterator<Item = usize> + 'b {
        self.doc_ix.iter().flat_map(move |(base, m)| m.get(e).map(|v| v.as_slice()).unwrap_or(&[]).iter().map(move |&i| base + i))
    }

    fn of_pred(&self, p: &str) -> &[usize] {
        self.by_p.get(p).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Deterministic frontier of unfinished work for the given targets (one-shot: builds its caches from scratch).
pub fn analyze<'s>(s: &'s Session, t: &Targets) -> Analysis<'s> {
    analyze_cached(s, t, &mut DirectiveCache::new())
}

/// The same frontier, reusing (and refreshing) `cache`; the result does not depend on what the cache held before.
pub fn analyze_cached<'s>(s: &'s Session, t: &Targets, cache: &mut DirectiveCache) -> Analysis<'s> {
    let t0 = Instant::now();
    let onto = &s.ontology;
    cache.prepare(onto);
    let DirectiveCache { onto: oc, docs: doc_cache, evidence: ev_cache, derivations: memo, stats } = cache;
    let oc = oc.as_ref().expect("prepared above");
    stats.analyses += 1;
    // ---- nodes
    let mut claims: Vec<ClaimInfo<'s>> = Vec::new();
    let mut evidence: Vec<EvInfo<'s>> = Vec::new();
    let mut assertions: Vec<(Hash, Hash, bool)> = Vec::new(); // (claim, evidence, active)
    for (id, status, v) in s.engine.node_views() {
        match v {
            NodeView::Evidence(ev) => {
                let (span, quote) = evidence_facts(ev_cache, stats, s, id, ev);
                evidence.push(EvInfo { id: *id, ev, status, span, quote });
            }
            NodeView::Claim(c) => claims.push(ClaimInfo { id: *id, claim: c, status, asserted_by: Vec::new() }),
            NodeView::Assertion { claim, evidence: e } => assertions.push((*claim, *e, status == J_ACTIVE)),
            NodeView::Derivation { .. } => {}
        }
    }
    let claim_ix: IdMap<usize> = claims.iter().enumerate().map(|(i, c)| (c.id, i)).collect();
    for (c, e, act) in &assertions {
        if let Some(&i) = claim_ix.get(c) {
            claims[i].asserted_by.push((*e, *act));
        }
    }
    let ev_ix: IdMap<usize> = evidence.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
    let asserted_ev: IdSet = assertions.iter().filter(|(_, _, act)| *act).map(|(_, e, _)| *e).collect();

    // ---- segments of the visible documents
    let mut docs: Vec<String> = match &t.docs {
        Some(d) => d.clone(),
        None => s.arena.doc_ids().cloned().collect(),
    };
    docs.sort();
    docs.dedup();
    let mut segments: Vec<Segment> = Vec::new();
    let mut doc_ix: Vec<(usize, Arc<FxMap<String, Vec<usize>>>)> = Vec::new();
    for d in &docs {
        let Some(entry) = s.arena.doc(d) else { continue };
        let base = segments.len();
        let dc = doc_facts(doc_cache, stats, oc, onto, d, entry);
        doc_ix.push((base, Arc::clone(&dc.by_entity)));
        segments.reserve(dc.segs.len());
        for f in &dc.segs {
            segments.push(Segment {
                idx: segments.len(),
                facts: Arc::clone(f),
                covered_active: Vec::new(),
                covered_revoked: Vec::new(),
                asserted: false,
                withdrawn: false,
            });
        }
        // sentences are disjoint and in byte order: the ones an evidence span overlaps form one run
        let local = &mut segments[base..];
        for e in &evidence {
            if e.ev.doc_id != *d {
                continue;
            }
            let Some((es, ee)) = e.span else { continue };
            let mut i = local.partition_point(|g| g.end <= es);
            while i < local.len() && local[i].start < ee {
                match e.status {
                    EV_ACTIVE => {
                        local[i].covered_active.push(e.id);
                        local[i].asserted |= asserted_ev.contains(&e.id);
                    }
                    EV_REVOKED => local[i].covered_revoked.push(e.id),
                    _ => {}
                }
                i += 1;
            }
        }
    }
    // ---- amendments: which clause labels are withdrawn, and what replaces them
    let plain_labels: FxMap<&str, usize> = segments.iter().filter(|g| !g.amendment).filter_map(|g| g.own_label.as_deref().map(|l| (l, g.idx))).collect();
    let mut withdrawals: Vec<(usize, usize, Option<usize>)> = Vec::new(); // (amendment seg, withdrawn seg, replacement seg)
    for g in segments.iter().filter(|g| g.amendment) {
        let Some(kw) = g.withdraw_at else { continue };
        let rp = g.replace_at;
        let mut withdrawn = Vec::new();
        let mut repl = None;
        for (pos, lab) in &g.labels {
            if Some(lab) == g.own_label.as_ref() {
                continue;
            }
            let Some(&target) = plain_labels.get(lab.as_str()) else { continue };
            match rp {
                Some(r) if *pos > r => repl = repl.or(Some(target)),
                _ if *pos < kw => withdrawn.push(target),
                _ => {}
            }
        }
        for w in withdrawn {
            withdrawals.push((g.idx, w, repl));
        }
    }
    for (_, w, _) in &withdrawals {
        segments[*w].withdrawn = true;
    }

    // ---- gaps
    let goal_entities: FxSet<&str> = t.goals.iter().map(|g| g.entity.as_str()).collect();
    let mut gaps: Vec<FrontierGap> = Vec::new();
    let first_entity = |g: &Segment| g.mentions.first().cloned().unwrap_or_else(|| g.own_label.clone().unwrap_or_else(|| g.id.clone()));
    let claims_of_ev = |e: &Hash| -> Vec<Hash> { assertions.iter().filter(|(_, ev, _)| ev == e).map(|(c, _, _)| *c).collect() };

    // P0 / P1: apply amendments
    let mut resupported = IdSet::default();
    for (am, w, repl) in &withdrawals {
        let ws = &segments[*w];
        let affected: Vec<Hash> = ws.covered_active.iter().flat_map(&claims_of_ev).collect();
        let withdrawn_claims: Vec<Hash> = ws.covered_active.iter().chain(ws.covered_revoked.iter()).flat_map(&claims_of_ev).collect();
        if !ws.covered_active.is_empty() {
            let conflict = affected.iter().any(|c| claim_ix.get(c).map(|&i| claims[i].status == ST_CONFLICTING).unwrap_or(false));
            let kind = if conflict { "RESOLVE_CONFLICT" } else { "REVOKE_WITHDRAWN" };
            let target = first_entity(ws);
            let mut nodes = ws.covered_active.clone();
            nodes.extend(affected.iter().copied());
            gaps.push(FrontierGap {
                gap_id: gap_id(kind, &target, std::slice::from_ref(&ws.id)),
                priority: Priority::P0ResolvePolarConflict,
                kind,
                target,
                segments: vec![*am, *w],
                nodes,
                derive: None,
                resupport: None,
                partner: None,
                est_events: ws.covered_active.len(),
                may_conflict: false,
                note: format!("clause {} is withdrawn by the amendment", ws.own_label.clone().unwrap_or_default()),
            });
        }
        if let Some(r) = repl {
            let rs = &segments[*r];
            // the withdrawn clause stated these claims; the replacement must state them again (once the withdrawn evidence is gone)
            for c in withdrawn_claims.iter().filter_map(|c| claim_ix.get(c).map(|&i| &claims[i])) {
                let still_from_other = c
                    .asserted_by
                    .iter()
                    .any(|(e, act)| *act && !ws.covered_active.contains(e) && ev_ix.get(e).map(|&i| evidence[i].status == EV_ACTIVE).unwrap_or(false));
                if still_from_other || rs.covered() && c.status == ST_SUPPORTED {
                    continue;
                }
                if rs.covered_active.iter().any(|e| c.asserted_by.iter().any(|(x, a)| x == e && *a)) {
                    continue;
                }
                resupported.insert(c.id);
                let target = first_entity(rs);
                gaps.push(FrontierGap {
                    gap_id: gap_id("RESUPPORT_FROM_RESTATEMENT", &target, &[rs.id.clone(), short(&c.id)]),
                    priority: Priority::P1RepairRevokedTarget,
                    kind: "RESUPPORT_FROM_RESTATEMENT",
                    target,
                    segments: vec![*am, *r],
                    nodes: vec![c.id],
                    derive: None,
                    resupport: Some(c.claim.clone()),
                    partner: None,
                    est_events: if rs.covered_active.is_empty() { 2 } else { 1 },
                    may_conflict: false,
                    note: format!(
                        "clause {} is withdrawn; the same statement stands in clause {}",
                        ws.own_label.clone().unwrap_or_default(),
                        rs.own_label.clone().unwrap_or_default()
                    ),
                });
            }
        }
    }

    let resupport_segs: FxSet<usize> = gaps.iter().filter(|g| g.kind == "RESUPPORT_FROM_RESTATEMENT").flat_map(|g| g.segments.iter().copied()).collect();

    // P1: a claim of a target lost its support and an uncovered clause mentions its entities
    for c in claims.iter().filter(|c| c.status == ST_UNSUPPORTED && !resupported.contains(&c.id)) {
        if !goal_entities.contains(c.claim.s.as_str()) || c.asserted_by.is_empty() {
            continue;
        }
        let ents: Vec<&str> = [c.claim.s.as_str(), c.claim.o.as_str()].into_iter().filter(|e| onto.entities.contains_key(*e)).collect();
        let cand: Vec<usize> = segments
            .iter()
            .filter(|g| !g.covered() && !g.withdrawn && !g.amendment && ents.iter().all(|e| g.mentions.iter().any(|m| m == e)))
            .map(|g| g.idx)
            .collect();
        if let Some(&g) = cand.first() {
            gaps.push(FrontierGap {
                gap_id: gap_id("REPAIR_UNSUPPORTED", &c.claim.s, &[short(&c.id)]),
                priority: Priority::P1RepairRevokedTarget,
                kind: "REPAIR_UNSUPPORTED",
                target: c.claim.s.clone(),
                segments: vec![g],
                nodes: vec![c.id],
                derive: None,
                resupport: Some(c.claim.clone()),
                partner: None,
                est_events: 2,
                may_conflict: false,
                note: "the claim lost its support".into(),
            });
        }
    }

    // lookup structures for the P2 / P3 passes
    let mut by_p: FxMap<&str, Vec<usize>> = FxMap::default();
    let mut live: FxSet<(&str, bool, &str)> = FxSet::default();
    for (i, c) in claims.iter().enumerate() {
        by_p.entry(c.claim.p.as_str()).or_default().push(i);
        if c.status != ST_UNSUPPORTED {
            live.insert((c.claim.p.as_str(), false, c.claim.s.as_str()));
            live.insert((c.claim.p.as_str(), true, c.claim.o.as_str()));
        }
    }
    let ix = Ix { oc, segments: &segments, doc_ix, claims: &claims, by_p, live };

    // P2A: ready derivations; P2B: one premise supported, the partner premise missing
    let supported: Vec<&ClaimInfo> = claims.iter().filter(|c| c.status == ST_SUPPORTED).collect();
    let mut ready_heads = IdSet::default();
    let closed = |hid: &Hash| claim_ix.get(hid).map(|&i| claims[i].status == ST_SUPPORTED || claims[i].status == ST_CONFLICTING).unwrap_or(false);
    for rule in onto.rules.values().filter(|r| r.mode == Mode::And) {
        for (hid, d) in ready_derivations(rule, &supported, memo, &closed) {
            if !ready_heads.insert(hid) {
                continue;
            }
            let target = d.head.s.clone();
            gaps.push(FrontierGap {
                gap_id: gap_id("EMIT_DERIVE_ONLY", &target, &d.premises.iter().map(short).collect::<Vec<_>>()),
                priority: Priority::P2CompleteHornDerivation,
                kind: "EMIT_DERIVE_ONLY",
                target,
                segments: Vec::new(),
                nodes: d.premises.clone(),
                derive: Some(d),
                resupport: None,
                partner: None,
                est_events: 1,
                may_conflict: false,
                note: "every premise is supported".into(),
            });
        }
        if rule.body.len() != 2 {
            continue;
        }
        for i in 0..2 {
            let j = 1 - i;
            // the head subject must be fixed by atom i alone
            let head_from_i = match &rule.head.s {
                Term::Ref(k, _) => *k == i,
                Term::Const(_) => true,
            };
            if !head_from_i {
                continue;
            }
            let joins = joins_between(rule, i, j);
            if joins.is_empty() {
                continue;
            }
            let pj = &rule.body[j];
            let want_types = oc.slots(&pj.p);
            for c in supported.iter().filter(|c| c.claim.p == rule.body[i].p && c.claim.pol == rule.body[i].pol) {
                let vals: Vec<(Field, &str)> = joins.iter().map(|(fi, fj)| (*fj, field_of(c.claim, *fi))).collect();
                let partner_exists = ix
                    .of_pred(&pj.p)
                    .iter()
                    .map(|&xi| &claims[xi])
                    .any(|x| x.claim.pol == pj.pol && x.status != ST_UNSUPPORTED && vals.iter().all(|(f, v)| field_of(x.claim, *f) == *v));
                if partner_exists {
                    continue;
                }
                let join_ents: Vec<&str> = vals.iter().map(|(_, v)| *v).filter(|v| onto.entities.contains_key(*v)).collect();
                if join_ents.is_empty() {
                    continue;
                }
                let cand = ix
                    .mentioning(join_ents[0])
                    .map(|gi| &segments[gi])
                    .filter(|g| !g.covered() && !g.withdrawn && !g.amendment && !resupport_segs.contains(&g.idx))
                    .filter(|g| join_ents.iter().all(|e| g.mentions.iter().any(|m| m == e)))
                    .find(|g| g.types == *want_types)
                    .map(|g| g.idx);
                let Some(g) = cand else { continue };
                let prem: Vec<&Claim> = vec![c.claim, c.claim];
                let target = match &rule.head.s {
                    Term::Const(k) => k.clone(),
                    t => eval_term(t, &prem),
                };
                gaps.push(FrontierGap {
                    gap_id: gap_id("EXTRACT_PARTNER", &target, &[segments[g].id.clone(), short(&c.id)]),
                    priority: Priority::P2CompleteHornDerivation,
                    kind: "EXTRACT_PARTNER",
                    target,
                    segments: vec![g],
                    nodes: vec![c.id],
                    derive: None,
                    resupport: None,
                    partner: Some((rule.id.clone(), c.id)),
                    est_events: 3,
                    may_conflict: false,
                    note: format!("{} is supported; the {} premise of {} is missing", c.claim.p, pj.p, rule.id),
                });
            }
        }
    }

    // P3: uncovered segments that mention a target entity which has no supported goal claim yet
    let done_goals: FxSet<(&str, &str)> =
        claims.iter().filter(|c| c.claim.pol == Polarity::Pos && c.status == ST_SUPPORTED).map(|c| (c.claim.s.as_str(), c.claim.p.as_str())).collect();
    let mut unreachable: FxSet<&str> = FxSet::default();
    for g in &t.goals {
        let concluded = done_goals.contains(&(g.entity.as_str(), g.predicate.as_str()));
        let segs: Vec<usize> = ix
            .mentioning(&g.entity)
            .filter(|&i| {
                let x = &segments[i];
                !x.covered() && !x.withdrawn && !x.amendment
            })
            .collect();
        if segs.is_empty() {
            continue;
        }
        if !segs.iter().any(|i| reachable(&ix, &g.predicate, &segments[*i])) {
            unreachable.insert(g.entity.as_str());
            continue;
        }
        // two or more sentences with the same entity-type signature may contradict each other (POS / NEG): then no same-step
        // derive is offered - the facts go in first and the compiler routes the derivation only if the kernel allows it
        let sigs: Vec<&BTreeSet<String>> = segs.iter().map(|i| &segments[*i].types).collect();
        let may_conflict = (0..sigs.len()).any(|i| (i + 1..sigs.len()).any(|j| sigs[i] == sigs[j])) || (concluded && !segs.is_empty());
        // a supported partner premise that the new fact could join with right away (e.g. the deprecation fact of the API)
        let partner = if may_conflict { None } else { partner_for(&ix, &g.predicate, &segs) };
        gaps.push(FrontierGap {
            gap_id: gap_id("FORMALIZE", &g.entity, &segs.iter().map(|i| segments[*i].id.clone()).collect::<Vec<_>>()),
            priority: Priority::P3FormalizeUncoveredChunk,
            kind: "FORMALIZE",
            target: g.entity.clone(),
            segments: segs.clone(),
            nodes: Vec::new(),
            derive: None,
            resupport: None,
            est_events: 2 * segs.len().min(2) + usize::from(partner.is_some()),
            may_conflict,
            partner,
            note: if may_conflict {
                format!("{} clause(s) mention {} and are not formalized yet; they may contradict each other or the existing conclusion", segs.len(), g.entity)
            } else {
                format!("{} clause(s) mention {} and are not formalized yet", segs.len(), g.entity)
            },
        });
    }
    gaps.sort_by(|a, b| (a.priority, &a.target, &a.gap_id).cmp(&(b.priority, &b.target, &b.gap_id)));
    gaps.dedup_by(|a, b| a.gap_id == b.gap_id);

    // ---- goal states
    let mut goal_state = BTreeMap::new();
    let open_targets: FxSet<&str> = gaps.iter().map(|x| x.target.as_str()).collect();
    let conflicted: FxSet<&str> = claims.iter().filter(|c| c.status == ST_CONFLICTING).map(|c| c.claim.s.as_str()).collect();
    for g in &t.goals {
        let st = if done_goals.contains(&(g.entity.as_str(), g.predicate.as_str())) {
            "CLOSED_POSITIVE"
        } else if open_targets.contains(g.entity.as_str()) {
            "OPEN"
        } else if conflicted.contains(g.entity.as_str()) {
            "CLOSED_BLOCKED_BY_CONFLICT"
        } else if unreachable.contains(g.entity.as_str()) {
            "CLOSED_NEGATIVE_UNREACHABLE"
        } else {
            "CLOSED_NEGATIVE"
        };
        goal_state.insert(g.entity.clone(), st);
    }
    let analysis_us = t0.elapsed().as_nanos() as f64 / 1e3;
    Analysis { segments, claims, evidence, gaps, goal_state, analysis_us, claim_ix, ev_ix }
}

/// Can a fact stated by segment `seg` ever take part in concluding `goal_pred`? For every two-atom AND rule that concludes it:
/// the segment's entity types must match the slot types of one atom, and the other atom must be satisfiable for the joined
/// entity - either a claim of that predicate about it is already in the kernel, or some non-withdrawn sentence mentions it with
/// exactly that predicate's slot types. A target whose sentences can reach no rule is closed without being formalized.
fn reachable(ix: &Ix, goal_pred: &str, seg: &Segment) -> bool {
    let plans = ix.oc.plans(goal_pred);
    if plans.is_empty() {
        return true;
    }
    for plan in plans {
        for side in &plan.sides {
            if side.slots_i != seg.types {
                continue;
            }
            if side.joins.is_empty() {
                return true;
            }
            let ok = side.joins.iter().all(|(ty, fj)| {
                let Some(ty) = ty else { return true };
                seg.typed_mentions().filter(|(_, t)| *t == Some(ty.as_str())).any(|(e, _)| {
                    ix.live.contains(&(side.pj_p.as_str(), *fj == Field::O, e))
                        || ix.mentioning(e).map(|gi| &ix.segments[gi]).any(|g| !g.withdrawn && !g.amendment && g.types == side.want)
                })
            });
            if ok {
                return true;
            }
        }
    }
    false
}

/// A supported claim that a fact stated by one of `segs` would join with to conclude `goal_pred` (for the same-step derive hint).
fn partner_for(ix: &Ix, goal_pred: &str, segs: &[usize]) -> Option<(String, Hash)> {
    for plan in ix.oc.plans(goal_pred) {
        for &si in segs {
            let g = &ix.segments[si];
            for side in &plan.sides {
                if side.slots_i != g.types {
                    continue;
                }
                // the partner premise mentions one of the segment's entities through the join
                for c in ix.of_pred(&side.pj_p).iter().map(|&ci| &ix.claims[ci]) {
                    if c.status != ST_SUPPORTED || c.claim.pol != side.pj_pol {
                        continue;
                    }
                    if g.mentions.iter().any(|m| *m == c.claim.s || *m == c.claim.o) {
                        return Some((plan.rule_id.clone(), c.id));
                    }
                }
            }
        }
    }
    None
}

/// Every application of `rule` to supported premises whose head is not SUPPORTED / CONFLICTING yet (`closed`), in body order.
fn ready_derivations(rule: &Rule, supported: &[&ClaimInfo], memo: &mut DeriveMemo, closed: &dyn Fn(&Hash) -> bool) -> Vec<(Hash, ReadyDerivation)> {
    struct Walk<'r, 'm> {
        rule: &'r Rule,
        rule_key: Hash,
        memo: &'m mut DeriveMemo,
        closed: &'m dyn Fn(&Hash) -> bool,
        key: Vec<Hash>,
        out: Vec<(Hash, ReadyDerivation)>,
    }
    fn head_of(rule: &Rule, pick: &[&ClaimInfo]) -> Option<(Hash, ReadyDerivation)> {
        let cl: Vec<&Claim> = pick.iter().map(|c| c.claim).collect();
        if !rule.join.iter().all(|((a, af), (b, bf))| field_of(cl[*a], *af) == field_of(cl[*b], *bf)) {
            return None;
        }
        let ctx = &cl[0].ctx;
        if cl.iter().any(|c| &c.ctx != ctx) {
            return None;
        }
        let t_from = cl.iter().map(|c| c.t_from).max().unwrap();
        let t_to = cl.iter().map(|c| c.t_to).min().unwrap();
        if t_from >= t_to {
            return None;
        }
        let head = Claim {
            s: eval_term(&rule.head.s, &cl),
            p: rule.head.p.clone(),
            o: eval_term(&rule.head.o, &cl),
            pol: rule.head.pol,
            ctx: ctx.clone(),
            t_from,
            t_to,
        };
        let mut premises: Vec<Hash> = pick.iter().map(|c| c.id).collect();
        premises.sort();
        premises.dedup();
        Some((head.id(), ReadyDerivation { rule: rule.id.clone(), premises, head }))
    }
    fn rec<'a>(w: &mut Walk, cands: &[Vec<&'a ClaimInfo<'a>>], pick: &mut Vec<&'a ClaimInfo<'a>>) {
        let k = pick.len();
        if k == cands.len() {
            w.key.clear();
            w.key.push(w.rule_key);
            w.key.extend(pick.iter().map(|c| c.id));
            if !w.memo.contains_key(w.key.as_slice()) {
                w.memo.insert(w.key.clone(), head_of(w.rule, pick));
            }
            if let Some((hid, d)) = &w.memo[w.key.as_slice()] {
                if !(w.closed)(hid) {
                    w.out.push((*hid, d.clone()));
                }
            }
            return;
        }
        for c in &cands[k] {
            // prune on joins that only involve already picked atoms and this one
            pick.push(c);
            let ok = w.rule.join.iter().all(
                |((a, af), (b, bf))| {
                    if *a <= k && *b <= k {
                        field_of(pick[*a].claim, *af) == field_of(pick[*b].claim, *bf)
                    } else {
                        true
                    }
                },
            );
            if ok {
                rec(w, cands, pick);
            }
            pick.pop();
        }
    }
    let cands: Vec<Vec<&ClaimInfo>> =
        rule.body.iter().map(|a| supported.iter().copied().filter(|c| c.claim.p == a.p && c.claim.pol == a.pol).collect()).collect();
    let mut w = Walk { rule, rule_key: sha256(rule.id.as_bytes()), memo, closed, key: Vec::with_capacity(rule.body.len() + 1), out: Vec::new() };
    let mut pick: Vec<&ClaimInfo> = Vec::with_capacity(rule.body.len());
    rec(&mut w, &cands, &mut pick);
    w.out
}

// ------------------------------------------------------------------------------------------ seat partition

/// One seat's share of a round: the gaps of ONE target entity, never sharing a target or a source segment with another seat.
#[derive(Debug, Clone)]
pub struct Assignment {
    pub seat: usize,
    pub target: Option<String>,
    pub targets: Vec<String>,
    pub gaps: Vec<usize>,
}

/// Canonical order `(priority, target, gap_id)`; greedy, deterministic, collision-free by construction.
/// Pass 1 gives every seat one target (the most urgent ones first); pass 2 tops busy seats up with further whole targets while
/// their event budget `k` lasts. A target, a source segment (amendment sentences excepted) and a gap node never go to two seats.
pub fn emit_batch(a: &Analysis<'_>, seats: usize, k: usize) -> Vec<Assignment> {
    let mut best: HashMap<String, Priority> = HashMap::new();
    for g in &a.gaps {
        let e = best.entry(g.target.clone()).or_insert(g.priority);
        if g.priority < *e {
            *e = g.priority;
        }
    }
    let mut by_target: BTreeMap<(Priority, String), Vec<usize>> = BTreeMap::new();
    for (i, g) in a.gaps.iter().enumerate() {
        by_target.entry((best[&g.target], g.target.clone())).or_default().push(i);
    }
    let order: Vec<(String, Vec<usize>)> = by_target.into_iter().map(|((_, t), l)| (t, l)).collect();
    let mut used_segments: HashSet<usize> = HashSet::new();
    let mut used_nodes: HashSet<Hash> = HashSet::new();
    let mut taken: HashSet<String> = HashSet::new();
    let mut out: Vec<Assignment> = (0..seats).map(|s| Assignment { seat: s, target: None, targets: Vec::new(), gaps: Vec::new() }).collect();
    let mut budget: Vec<usize> = vec![0; seats];

    let try_take = |list: &[usize], room: usize, first: bool, used_segments: &HashSet<usize>, used_nodes: &HashSet<Hash>| -> (Vec<usize>, usize) {
        let mut chosen = Vec::new();
        let mut spent = 0usize;
        for &gi in list {
            let g = &a.gaps[gi];
            if g.segments.iter().any(|s| used_segments.contains(s) && !a.segments[*s].amendment)
                || g.nodes.iter().any(|n| used_nodes.contains(n) && g.kind != "EMIT_DERIVE_ONLY")
            {
                continue;
            }
            let over = spent + g.est_events > room;
            if over && !(first && chosen.is_empty()) {
                continue;
            }
            spent += g.est_events;
            chosen.push(gi);
        }
        (chosen, spent)
    };
    let commit = |seat: usize,
                  target: &str,
                  chosen: Vec<usize>,
                  spent: usize,
                  out: &mut Vec<Assignment>,
                  budget: &mut Vec<usize>,
                  used_segments: &mut HashSet<usize>,
                  used_nodes: &mut HashSet<Hash>| {
        for &gi in &chosen {
            let g = &a.gaps[gi];
            used_segments.extend(g.segments.iter().copied());
            used_nodes.extend(g.nodes.iter().copied());
            if let Some(d) = &g.derive {
                used_nodes.insert(d.head.id());
            }
        }
        let asg = &mut out[seat];
        if asg.target.is_none() {
            asg.target = Some(target.to_string());
        }
        asg.targets.push(target.to_string());
        asg.gaps.extend(chosen);
        budget[seat] += spent;
    };
    // pass 1: one target per seat
    let mut seat = 0usize;
    for (target, list) in &order {
        if seat == seats {
            break;
        }
        let (chosen, spent) = try_take(list, k, true, &used_segments, &used_nodes);
        if chosen.is_empty() {
            continue;
        }
        taken.insert(target.clone());
        commit(seat, target, chosen, spent, &mut out, &mut budget, &mut used_segments, &mut used_nodes);
        seat += 1;
    }
    // pass 2: top up busy seats with whole further targets while the budget lasts
    for s in 0..seats {
        if out[s].target.is_none() {
            continue;
        }
        for (target, list) in &order {
            if taken.contains(target) {
                continue;
            }
            let room = k.saturating_sub(budget[s]);
            if room == 0 {
                break;
            }
            let (chosen, spent) = try_take(list, room, false, &used_segments, &used_nodes);
            // only whole targets: every gap of the target must fit, otherwise it waits for a later step
            if chosen.is_empty() || chosen.len() != list.len() {
                continue;
            }
            taken.insert(target.clone());
            commit(s, target, chosen, spent, &mut out, &mut budget, &mut used_segments, &mut used_nodes);
        }
    }
    out
}

// ------------------------------------------------------------------------------------------ frames

pub const SEAT_TAGS: &[&str] = &["a", "b", "c", "d", "e", "f", "g", "h"];

/// Local-id prefix of a seat in a synchronous round. Up to 8 seats keep the historical `a1_ .. h1_` form (the EXP-9 frames
/// stay byte-identical); wider rounds add the seat block, `a0r1_ .. h0r1_, a1r1_ ..`, so no two seats share a prefix.
pub fn seat_prefix(seat: usize, seats: usize, round: u64) -> String {
    let tag = SEAT_TAGS[seat % SEAT_TAGS.len()];
    if seats <= SEAT_TAGS.len() {
        format!("{tag}{round}_")
    } else {
        format!("{tag}{}r{round}_", seat / SEAT_TAGS.len())
    }
}

fn claim_line(c: &Claim, id: &Hash, status: u8) -> String {
    let pol = if c.pol == Polarity::Neg { " [NEG]" } else { "" };
    format!("@{}  {}({}, {}){} t=[{},{}) {}", short(id), c.p, c.s, c.o, pol, c.t_from, c.t_to, status_name(KIND_CLAIM, status))
}

fn rule_text(rule: &Rule) -> String {
    let atom = |p: &str| p.to_string();
    let body: Vec<String> = rule.body.iter().map(|b| atom(&b.p)).collect();
    let joins: Vec<String> = rule.join.iter().map(|((a, af), (b, bf))| format!("{}.{} = {}.{}", body[*a], af.as_str(), body[*b], bf.as_str())).collect();
    let term = |t: &Term| match t {
        Term::Const(c) => format!("\"{c}\""),
        Term::Ref(i, f) => format!("{}.{}", body[*i], f.as_str()),
    };
    format!(
        "{}: {} where {} => {}(s={}, o={}); the conclusion's interval is the intersection [max(t_from), min(t_to)) of the premises",
        rule.id,
        body.join(" AND "),
        joins.join(", "),
        rule.head.p,
        term(&rule.head.s),
        term(&rule.head.o)
    )
}

/// Claim ids of the minimal support cone of `e` on the live engine. An entity no claim is about is looked up through the
/// alias registry, as the container projection (`cone::minimal_cone_value`) does.
pub(crate) fn cone_claim_ids(cone: &ConeReader, onto: &Ontology, e: &str) -> Vec<Hash> {
    if cone.about(e) {
        return cone.claim_ids(e);
    }
    onto.resolve_entity(e).map(|x| cone.claim_ids(&x.id)).unwrap_or_default()
}

/// Who a frame is for: a seat of a synchronous round (`emit_batch`) or one lease of the asynchronous swarm (`swarm`).
/// Only the directive id, the local-id prefix, the header line and the slot fields differ; the work packed is the same.
pub(crate) enum FrameSlot<'x> {
    Seat { round: u64, seats: usize },
    Lease { seq: u64, lease_id: &'x str },
}

/// The kernel's frame for one seat. `cone` reads the minimal support cone from the state the analysis was computed from
/// (the same selection `cone::minimal_cone_value` makes on that state's container); `cache` is the one the analysis used.
fn build_frame(cone: &ConeReader, cache: &DirectiveCache, onto: &Ontology, a: &Analysis<'_>, asg: &Assignment, round: u64, seats: usize, k: usize) -> Value {
    if asg.target.is_none() {
        return json!({"directive_id": format!("D-r{round}-s{}-noop", asg.seat), "seat": asg.seat, "seats": seats, "round": round,
                      "priority": Priority::P4NoOpComplete.name(), "kind": "NO_OP", "noop": true, "target": Value::Null,
                      "prompt": "", "prompt_chars": 0});
    }
    frame_for(cone, cache, onto, a, asg, k, &FrameSlot::Seat { round, seats })
}

/// The frame of a non-empty assignment (`asg.target` is set).
pub(crate) fn frame_for(cone: &ConeReader, cache: &DirectiveCache, onto: &Ontology, a: &Analysis<'_>, asg: &Assignment, k: usize, slot: &FrameSlot) -> Value {
    let oc = cache.onto();
    let target = asg.target.as_ref().expect("frame_for needs an assignment with a target");
    let gaps: Vec<&FrontierGap> = asg.gaps.iter().map(|&i| &a.gaps[i]).collect();
    let top = gaps[0];
    let (directive_id, prefix, slot_text) = match slot {
        FrameSlot::Seat { round, seats } => (
            format!("D-r{round}-s{}-{}", asg.seat, top.gap_id),
            seat_prefix(asg.seat, *seats, *round),
            format!("seat {} of {seats}, round {round}", asg.seat + 1),
        ),
        FrameSlot::Lease { seq, .. } => (format!("D-L{seq}-{}", top.gap_id), format!("l{seq}_"), format!("lease L{seq} of the asynchronous swarm")),
    };
    // ---- source slice (amendment sentences first), at most 3 sentences
    let mut seg_ids: Vec<usize> = Vec::new();
    for g in &gaps {
        for s in &g.segments {
            if !seg_ids.contains(s) {
                seg_ids.push(*s);
            }
        }
    }
    // every sentence a packed gap needs is shown (the event budget already bounds how many gaps share a frame)
    seg_ids.sort_by_key(|s| (!a.segments[*s].amendment, *s));
    // ---- entities this directive is about
    let mut ents: BTreeSet<String> = BTreeSet::new();
    ents.extend(asg.targets.iter().cloned());
    for s in &seg_ids {
        ents.extend(a.segments[*s].mentions.iter().cloned());
    }
    let mut node_ids: Vec<Hash> = Vec::new();
    for g in &gaps {
        node_ids.extend(g.nodes.iter().copied());
        if let Some((_, p)) = &g.partner {
            node_ids.push(*p);
        }
        if let Some(d) = &g.derive {
            node_ids.extend(d.premises.iter().copied());
        }
    }
    for n in &node_ids {
        if let Some(c) = a.claim(n) {
            if onto.entities.contains_key(&c.claim.o) {
                ents.insert(c.claim.o.clone());
            }
            ents.insert(c.claim.s.clone());
        }
    }
    // ---- minimal support cone: the kernel's own projection for the target and its related entities, plus the nodes the gaps name
    // (short id -> id, in short-id order)
    let mut cone_claims: BTreeMap<String, Hash> = BTreeMap::new();
    for e in &ents {
        for id in cone_claim_ids(cone, onto, e) {
            cone_claims.entry(short(&id)).or_insert(id);
        }
    }
    let mut cone_lines: Vec<String> = Vec::new();
    let mut listed: HashSet<String> = HashSet::new();
    let mut add_claim = |ci: &ClaimInfo, lines: &mut Vec<String>| {
        let sid = short(&ci.id);
        if !listed.insert(sid) {
            return;
        }
        let evs: Vec<String> = ci
            .asserted_by
            .iter()
            .map(|(e, act)| {
                let lab = a.ev(e).map(|x| x.quote.split(':').next().unwrap_or("").to_string()).unwrap_or_default();
                let st = a.ev(e).map(|x| status_name(KIND_EVIDENCE, x.status)).unwrap_or("?");
                format!("evidence @{} ({lab}, {st}{})", short(e), if *act { "" } else { ", inactive" })
            })
            .collect();
        let why = if evs.is_empty() { "derived".to_string() } else { evs.join(" | ") };
        lines.push(format!("  {}  <- {}", claim_line(ci.claim, &ci.id, ci.status), why));
    };
    // gap nodes first, then the kernel's cone, then other claims about the target (e.g. lost ones the cone omits)
    for n in &node_ids {
        if let Some(ci) = a.claim(n) {
            add_claim(ci, &mut cone_lines);
        }
    }
    for id in cone_claims.values() {
        if let Some(ci) = a.claim(id) {
            if ents.contains(&ci.claim.s) || ents.contains(&ci.claim.o) {
                add_claim(ci, &mut cone_lines);
            }
        }
    }
    for ci in a.claims.iter().filter(|c| asg.targets.contains(&c.claim.s) && c.status != ST_SUPPORTED) {
        add_claim(ci, &mut cone_lines);
    }
    let cone_truncated = cone_lines.len() > 10;
    cone_lines.truncate(10);
    // evidence that the gaps name directly (to revoke)
    let mut ev_lines: Vec<String> = Vec::new();
    for g in &gaps {
        for n in &g.nodes {
            if let Some(e) = a.ev(n) {
                ev_lines.push(format!("  @{} [{}] \"{}\"", short(&e.id), status_name(KIND_EVIDENCE, e.status), e.quote));
            }
        }
    }
    // ---- ontology slice
    let mut onto_lines: Vec<String> = Vec::new();
    for e in &ents {
        if let Some(en) = onto.entities.get(e) {
            let al = oc.aliases(e);
            onto_lines.push(format!("  entity {} : {}{}", en.id, en.ty, if al.is_empty() { String::new() } else { format!(" (alias: {})", al.join(", ")) }));
        }
    }
    let mut rules: Vec<&Rule> = Vec::new();
    for g in &gaps {
        if let Some(d) = &g.derive {
            if let Some(r) = onto.rules.get(&d.rule) {
                rules.push(r);
            }
        }
        if let Some((r, _)) = &g.partner {
            if let Some(r) = onto.rules.get(r) {
                rules.push(r);
            }
        }
    }
    let goal_rules: Vec<&Rule> = onto
        .rules
        .values()
        .filter(|r| r.body.iter().any(|b| ents.iter().any(|e| entity_type(onto, e).map(|t| oc.slots(&b.p).contains(t)).unwrap_or(false))))
        .collect();
    if rules.is_empty() {
        rules.extend(goal_rules.iter().take(2));
    }
    rules.sort_by(|x, y| x.id.cmp(&y.id));
    rules.dedup_by(|x, y| x.id == y.id);
    let mut preds: BTreeSet<String> = BTreeSet::new();
    for r in &rules {
        preds.extend(r.body.iter().map(|b| b.p.clone()));
        preds.insert(r.head.p.clone());
    }
    for p in &preds {
        if let Some(pr) = onto.predicates.get(p) {
            let o = match (&pr.object, &pr.allowed_values) {
                (ObjType::Entity(t), _) => t.clone(),
                (ObjType::Literal, None) => "literal".into(),
                (ObjType::Literal, Some(v)) => format!("literal, one of: {}", v.join(", ")),
            };
            onto_lines.push(format!("  predicate {p}({} -> {o})", pr.subject));
        }
    }
    for r in &rules {
        onto_lines.push(format!("  rule {}", rule_text(r)));
    }
    // ---- instruction text
    let mut steps: Vec<String> = Vec::new();
    let mut est = 0usize;
    for g in &gaps {
        est += g.est_events;
        let seg_label = |i: usize| a.segments[i].own_label.clone().unwrap_or_else(|| format!("sentence {}", a.segments[i].id));
        let plain: Vec<usize> = g.segments.iter().copied().filter(|s| !a.segments[*s].amendment).collect();
        let txt = match g.kind {
            "FORMALIZE" => {
                let labels: Vec<String> = plain.iter().map(|s| seg_label(*s)).collect();
                let mut t = format!(
                    "Formalize clause(s) {} for {}: for each, bind the whole sentence as evidence (exact_quote = the sentence, byte-exact) and assert the fact it states \
                     (use a predicate from the ontology slice, the exact time window, polarity POS - or NEG if the sentence says the service does NOT call the interface).",
                    labels.join(", "),
                    g.target
                );
                if g.note.contains("may contradict") {
                    t.push_str(
                        " These sentences may contradict each other (or a conclusion already in the kernel): assert each exactly as it is stated \
                                (POS or NEG) and do NOT derive in this step - if the facts allow a conclusion, the compiler will ask for it next.",
                    );
                }
                if let Some((rule, p)) = &g.partner {
                    if let Some(pc) = a.claim(p) {
                        t.push_str(&format!(
                            " The partner premise is already in the kernel: @{} {}({}, {}) t=[{},{}). If your new fact's window overlaps it, also derive {} with premises \
                             [<your new fact's local_id>, \"@{}\"]: the conclusion interval will be [max(t_from), min(t_to)) = [max(your_from, {}), min(your_to, {})). \
                             If the windows do not overlap, do not derive.",
                            short(p), pc.claim.p, pc.claim.s, pc.claim.o, pc.claim.t_from, pc.claim.t_to, rule, short(p), pc.claim.t_from, pc.claim.t_to
                        ));
                    }
                }
                t
            }
            "EXTRACT_PARTNER" => {
                let (rule, p) = g.partner.clone().unwrap_or_default();
                let pc = a.claim(&p).map(|c| c.claim.clone());
                let lab = plain.first().map(|s| seg_label(*s)).unwrap_or_default();
                match pc {
                    Some(pc) => format!(
                        "The kernel holds @{} {}({}, {}) t=[{},{}) but the other premise of {} is missing. Clause {} in the slice states it: bind that sentence and assert the fact. \
                         Then, if the two windows overlap, derive {} with premises [\"@{}\", <your new fact's local_id>]; the kernel will conclude for {} on \
                         [max({}, new_from), min({}, new_to)). If they do not overlap, stop after the assertion.",
                        short(&p), pc.p, pc.s, pc.o, pc.t_from, pc.t_to, rule, lab, rule, short(&p), g.target, pc.t_from, pc.t_to
                    ),
                    None => format!("Bind clause {lab} and assert the fact it states."),
                }
            }
            "EMIT_DERIVE_ONLY" => {
                let d = g.derive.as_ref().unwrap();
                let prem: Vec<String> = d.premises.iter().map(|p| format!("\"@{}\"", short(p))).collect();
                format!(
                    "All premises are supported in the kernel. Emit exactly one derive event: rule {} with premises [{}]. Precomputed by the kernel: \
                     {}({}, {}) t=[{},{}) (the interval is [max(t_from), min(t_to)) of the premises). Do not bind or assert anything.",
                    d.rule,
                    prem.join(", "),
                    d.head.p,
                    d.head.s,
                    d.head.o,
                    d.head.t_from,
                    d.head.t_to
                )
            }
            "REVOKE_WITHDRAWN" | "RESOLVE_CONFLICT" => {
                let evs: Vec<String> = g.nodes.iter().filter(|n| a.ev(n).is_some()).map(|n| format!("\"@{}\"", short(n))).collect();
                let lab = plain.first().map(|s| seg_label(*s)).unwrap_or_default();
                let mut t = format!(
                    "The amendment in the slice withdraws clause {}. Its evidence {} is still ACTIVE in the kernel. Emit revoke_evidence for it (one event per evidence id); \
                     the kernel then removes everything that rested only on it.",
                    lab,
                    evs.join(", ")
                );
                if g.kind == "RESOLVE_CONFLICT" {
                    t.push_str(" This also resolves the CONFLICTING_SOURCES pair it takes part in: the old evidence was withdrawn, use the amendment to decide the current status.");
                }
                t
            }
            "RESUPPORT_FROM_RESTATEMENT" | "REPAIR_UNSUPPORTED" => {
                let c = g.resupport.as_ref().unwrap();
                let lab = plain.first().map(|s| seg_label(*s)).unwrap_or_default();
                format!(
                    "The kernel's claim @{} {}({}, {}){} t=[{},{}) lost (or is losing) its evidence. Clause {} in the slice states the same fact: bind that sentence and assert \
                     exactly this fact with it (s={}, p={}, o={}, polarity {}, t=[{},{})). Every conclusion that rested on the claim is restored by the kernel - do NOT derive again.",
                    short(&c.id()), c.p, c.s, c.o, if c.pol == Polarity::Neg { " [NEG]" } else { "" }, c.t_from, c.t_to, lab, c.s, c.p, c.o, c.pol.as_str(), c.t_from, c.t_to
                )
            }
            _ => g.note.clone(),
        };
        steps.push(format!("  {}. [{} / {}] {}", steps.len() + 1, g.priority.name(), g.kind, txt));
    }
    let mut slice_lines: Vec<String> = Vec::new();
    let mut slice_json: Vec<Value> = Vec::new();
    for s in &seg_ids {
        let g = &a.segments[*s];
        slice_lines.push(format!("  [{}{}] {}", g.doc_id, if g.amendment { ", AMENDMENT" } else { "" }, g.text));
        slice_json.push(json!({"segment_id": g.id, "doc_id": g.doc_id, "amendment": g.amendment, "text": g.text}));
    }
    let k_here = est.clamp(1, k);
    let prompt = format!(
        "SBGK DIRECTIVE {directive_id} | {pri} | {kind} | target {tlist} | {slot_text}\n\
         You are a stateless graph-builder. You see only this directive (no document, no history). Write {k_here} or fewer strict JSON events, one per line, \
         no code fences, no commentary. The kernel checks every event and stops at the first rejected one. Do only what the task says: an event outside it \
         (a quote that is not in the slice, a revoke of evidence the task does not list) is refused.\n\
         \nTASK (written by the compiler):\n{steps}\n\
         \nSOURCE SLICE (exact sentences; doc_id in brackets; quote them byte-exactly):\n{slice}\n\
         \nSUPPORT CONE (accepted nodes in the kernel; reference them as \"@id\"){trunc}:\n{cone}{evs}\n\
         \nONTOLOGY SLICE:\n{onto}\n\
         \nEVENT FORMAT (context is always \"prod\"; start every local_id with \"{prefix}\"):\n\
         {{\"op\":\"bind_evidence\",\"local_id\":\"{prefix}e1\",\"doc_id\":\"policy\",\"exact_quote\":\"<one whole sentence from the slice>\"}}\n\
         {{\"op\":\"assert_fact\",\"local_id\":\"{prefix}f1\",\"s\":\"svc_003\",\"p\":\"uses_api\",\"o\":\"api_002\",\"polarity\":\"POS\",\"ctx\":\"prod\",\"t\":[100,200],\"evidence\":[\"{prefix}e1\"]}}\n\
         {{\"op\":\"derive\",\"local_id\":\"{prefix}r1\",\"rule\":\"R_depr_review@1\",\"premises\":[\"{prefix}f1\",\"@0123456789abcdef\"]}}\n\
         {{\"op\":\"revoke_evidence\",\"target_evidence\":\"@0123456789abcdef\"}}\n\
         (derive: the kernel computes the conclusion itself. A fact's object for api_deprecated is \"true\".)\n",
        pri = top.priority.name(),
        tlist = asg.targets.join(", "),
        kind = top.kind,
        steps = steps.join("\n"),
        slice = if slice_lines.is_empty() { "  (none needed)".to_string() } else { slice_lines.join("\n") },
        trunc = if cone_truncated { " - truncated to the 10 most relevant" } else { "" },
        cone = if cone_lines.is_empty() { "  (nothing about this target yet)".to_string() } else { cone_lines.join("\n") },
        evs = if ev_lines.is_empty() { String::new() } else { format!("\n  evidence to act on:\n{}", ev_lines.join("\n")) },
        onto = onto_lines.join("\n"),
    );
    let mut m = Map::new();
    m.insert("directive_id".into(), json!(directive_id));
    match slot {
        FrameSlot::Seat { round, seats } => {
            m.insert("seat".into(), json!(asg.seat));
            m.insert("seats".into(), json!(seats));
            m.insert("round".into(), json!(round));
        }
        FrameSlot::Lease { seq, lease_id } => {
            m.insert("lease_id".into(), json!(lease_id));
            m.insert("lease_seq".into(), json!(seq));
        }
    }
    m.insert("priority".into(), json!(top.priority.name()));
    m.insert("kind".into(), json!(top.kind));
    m.insert("noop".into(), json!(false));
    m.insert("target".into(), json!(target));
    m.insert("targets".into(), json!(asg.targets));
    m.insert("local_id_prefix".into(), json!(prefix));
    m.insert("max_events".into(), json!(k_here));
    m.insert("gaps".into(), json!(gaps.iter().map(|g| gap_json(a, g)).collect::<Vec<_>>()));
    m.insert("chunk_slice".into(), json!(slice_json));
    m.insert("minimal_support_cone".into(), json!({"claims": cone_lines, "evidence_to_act_on": ev_lines}));
    m.insert("ontology_slice".into(), json!(onto_lines));
    m.insert("compiler_instruction_text".into(), json!(steps));
    m.insert("prompt_chars".into(), json!(prompt.chars().count()));
    m.insert("prompt".into(), json!(prompt));
    Value::Object(m)
}

fn claim_json(c: &Claim) -> Value {
    json!({"s": c.s, "p": c.p, "o": c.o, "polarity": c.pol.as_str(), "ctx": c.ctx, "t": [c.t_from, c.t_to]})
}

/// Machine-readable part of a gap (the harness and the report use it; the worker reads the prompt).
fn gap_json(a: &Analysis<'_>, g: &FrontierGap) -> Value {
    json!({
        "gap_id": g.gap_id, "priority": g.priority.name(), "kind": g.kind, "target": g.target,
        "segments": g.segments.iter().map(|s| a.segments[*s].id.clone()).collect::<Vec<_>>(),
        "segment_texts": g.segments.iter().filter(|s| !a.segments[**s].amendment).map(|s| a.segments[*s].text.clone()).collect::<Vec<_>>(),
        "est_events": g.est_events, "note": g.note,
        "partner": g.partner.as_ref().map(|(r, id)| json!({"rule": r, "id": format!("@{}", short(id))})),
        "derive": g.derive.as_ref().map(|d| json!({"rule": d.rule, "premises": d.premises.iter().map(|p| format!("@{}", short(p))).collect::<Vec<_>>(), "head": claim_json(&d.head)})),
        "evidence": g.nodes.iter().filter(|n| a.ev(n).is_some()).map(|n| format!("@{}", short(n))).collect::<Vec<_>>(),
        "resupport": g.resupport.as_ref().map(claim_json),
    })
}

/// Everything a round needs: frontier analysis, the seat partition and one frame per seat; plus the ready derivations the
/// kernel could close by itself (`auto_close`, as derive events with @ids - the caller decides whether to submit them).
/// One-shot path: opens (and verifies) the container, analyses with a fresh cache.
pub fn emit_batch_frames(bytes: &[u8], targets: &Targets, seats: usize, k: usize, round: u64) -> Result<Value, String> {
    let t_open = Instant::now();
    let s = crate::container::open_session(bytes).map_err(|e| e.to_string())?;
    let open_us = t_open.elapsed().as_nanos() as f64 / 1e3;
    let mut cache = DirectiveCache::new();
    let a = analyze_cached(&s, targets, &mut cache);
    // the first analysis in a fresh process builds the caches and pays one-off costs (allocator warm-up, hash-seed
    // initialisation); a second analysis of the same state gives the steady-state cost of a resident compiler
    let warm_us = analyze_cached(&s, targets, &mut cache).analysis_us;
    let mut v = batch_json(&s, &cache, &a, seats, k, round);
    v["open_us"] = json!(open_us);
    v["analysis_warm_us"] = json!(warm_us);
    Ok(v)
}

/// The same batch from a live session (resident compiler, `sbgk serve` op `directives`): no container is built, reopened or
/// verified, and `cache` carries the text facts of the documents and evidence across rounds. For the same state the
/// output equals `emit_batch_frames` on that state's container (apart from the timing fields).
pub fn emit_batch_frames_live(s: &Session, cache: &mut DirectiveCache, targets: &Targets, seats: usize, k: usize, round: u64) -> Value {
    let a = analyze_cached(s, targets, cache);
    let mut v = batch_json(s, cache, &a, seats, k, round);
    v["open_us"] = json!(0.0);
    v
}

fn batch_json(s: &Session, cache: &DirectiveCache, a: &Analysis<'_>, seats: usize, k: usize, round: u64) -> Value {
    let t_pack = Instant::now();
    let asg = emit_batch(a, seats.max(1), k.max(1));
    let cone = s.engine.cone_reader();
    let frames: Vec<Value> = asg.iter().map(|x| build_frame(&cone, cache, &s.ontology, a, x, round, seats.max(1), k.max(1))).collect();
    let pack_us = t_pack.elapsed().as_nanos() as f64 / 1e3;
    let auto: Vec<Value> = a
        .gaps
        .iter()
        .filter_map(|g| g.derive.as_ref())
        .enumerate()
        .map(|(i, d)| json!({"op": "derive", "local_id": format!("k{round}_{i}"), "rule": d.rule, "premises": d.premises.iter().map(|p| format!("@{}", short(p))).collect::<Vec<_>>()}))
        .collect();
    let mut states: BTreeMap<&str, usize> = BTreeMap::new();
    for st in a.goal_state.values() {
        *states.entry(st).or_default() += 1;
    }
    json!({
        "round": round, "seats": seats, "k": k, "complete": a.complete(),
        "gaps_total": a.gaps.len(),
        "gaps_by_priority": {
            "P0": a.gaps.iter().filter(|g| g.priority == Priority::P0ResolvePolarConflict).count(),
            "P1": a.gaps.iter().filter(|g| g.priority == Priority::P1RepairRevokedTarget).count(),
            "P2": a.gaps.iter().filter(|g| g.priority == Priority::P2CompleteHornDerivation).count(),
            "P3": a.gaps.iter().filter(|g| g.priority == Priority::P3FormalizeUncoveredChunk).count(),
        },
        "goal_states": states, "goal_state": a.goal_state,
        "segments": a.segments.len(), "segments_covered": a.segments.iter().filter(|g| g.covered()).count(),
        "analysis_us": a.analysis_us, "pack_us": pack_us,
        "frames": frames, "auto_close": auto,
    })
}

/// Debug view of the frontier (all gaps, segment coverage).
pub fn frontier_json(bytes: &[u8], targets: &Targets) -> Result<Value, String> {
    let s = crate::container::open_session(bytes).map_err(|e| e.to_string())?;
    let a = analyze(&s, targets);
    Ok(json!({
        "complete": a.complete(), "analysis_us": a.analysis_us, "goal_state": a.goal_state,
        "gaps": a.gaps.iter().map(|g| json!({"gap_id": g.gap_id, "priority": g.priority.name(), "kind": g.kind, "target": g.target,
            "segments": g.segments.iter().map(|s| a.segments[*s].text.clone()).collect::<Vec<_>>(), "nodes": g.nodes.iter().map(short).collect::<Vec<_>>(),
            "est_events": g.est_events, "note": g.note})).collect::<Vec<_>>(),
        "segments": a.segments.iter().map(|g| json!({"id": g.id, "text": g.text, "mentions": g.mentions, "label": g.own_label, "amendment": g.amendment,
            "covered": g.covered(), "withdrawn": g.withdrawn})).collect::<Vec<_>>(),
    }))
}

// ------------------------------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdc::CdcParams;
    use crate::container::build_container;

    const ONTO: &str = r#"{
      "entities":[
        {"id":"svc_001","type":"Service","aliases":["service 1"]},
        {"id":"svc_002","type":"Service","aliases":["service 2"]},
        {"id":"svc_003","type":"Service","aliases":["service 3"]},
        {"id":"svc_010","type":"Service","aliases":["service 10"]},
        {"id":"api_001","type":"Api","aliases":["interface 1"]},
        {"id":"api_002","type":"Api","aliases":["interface 2"]},
        {"id":"api_003","type":"Api","aliases":["interface 3"]}],
      "predicates":[
        {"id":"uses_api","subject":"Service","object":"Api"},
        {"id":"api_deprecated","subject":"Api","object":"@literal"},
        {"id":"needs_review","subject":"Service","object":"@literal"}],
      "rules":[{"id":"R_depr_review@1","mode":"AND",
        "body":[{"p":"uses_api"},{"p":"api_deprecated"}],
        "join":[["0.o","1.s"]],
        "head":{"s":"0.s","p":"needs_review","o":{"const":"true"}}}]}"#;

    const U1: &str = "Clause U.1: service svc_001 shall call interface api_001 in production from t=100 until t=200.";
    const U2: &str = "Clause U.2: service 2 shall call interface 1 in production from t=110 until t=210.";
    const U3: &str = "Clause U.3: service svc_003 shall call interface api_002 in production from t=100 until t=140.";
    const N3: &str = "Clause N.3: service svc_003 does not call interface api_002 in production from t=120 until t=150.";
    const D1: &str = "Clause D.1: interface api_001 is deprecated in production from t=150 until t=300.";
    const R1: &str = "Clause R.1: from t=150 until t=300, production use of interface api_001 is deprecated (this restates clause D.1).";
    const D2: &str = "Clause D.2: interface api_002 is deprecated in production from t=150 until t=300.";
    const U10: &str = "Clause U.10: service 10 shall call interface 3 in production from t=100 until t=220.";

    fn doc() -> String {
        format!("The operator shall archive the access logs within 3 business days. {U1} {U2} {U10}\n\nThe custodian must review all change requests. {U3} {N3} {D1} {R1} {D2}\n")
    }

    fn targets(docs: &[&str]) -> Targets {
        Targets {
            goals: ["svc_001", "svc_002", "svc_003", "svc_010"].iter().map(|e| Goal { entity: e.to_string(), predicate: "needs_review".into() }).collect(),
            docs: Some(docs.iter().map(|d| d.to_string()).collect()),
        }
    }

    fn session() -> Session {
        let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), CdcParams::default());
        s.put_document("policy", doc().as_bytes());
        s.put_document("erratum", b"Erratum E.1: clause D.1 is withdrawn; the same statement stands in clause R.1. Erratum E.2: clause U.2 is withdrawn.\n");
        s
    }

    struct Feed {
        seq: u64,
    }

    impl Feed {
        fn line(&mut self, s: &mut Session, body: Value) {
            self.seq += 1;
            let mut m = body.as_object().unwrap().clone();
            m.insert("seq".into(), json!(self.seq));
            s.apply_line(&Value::Object(m).to_string()).unwrap_or_else(|e| panic!("{e}"));
        }
        fn fact(&mut self, s: &mut Session, n: &str, quote: &str, subj: &str, p: &str, o: &str, pol: &str, t: (i64, i64)) {
            self.line(s, json!({"op":"bind_evidence","local_id":format!("e{n}"),"doc_id":"policy","exact_quote":quote}));
            self.line(s, json!({"op":"assert_fact","local_id":format!("f{n}"),"s":subj,"p":p,"o":o,"polarity":pol,"ctx":"prod","t":[t.0,t.1],"evidence":[format!("e{n}")]}));
        }
    }

    fn kinds(a: &Analysis) -> Vec<(String, &'static str)> {
        a.gaps.iter().map(|g| (g.target.clone(), g.kind)).collect()
    }

    #[test]
    fn sentences_labels_and_mentions() {
        let d = doc();
        let parts = split_sentences(d.as_bytes());
        let texts: Vec<&str> = parts.iter().map(|(a, b)| &d[*a..*b]).collect();
        assert!(texts.contains(&U1) && texts.contains(&U2) && texts.contains(&R1), "{texts:?}");
        assert_eq!(find_labels(U1.as_bytes())[0].1, "U.1");
        assert_eq!(find_labels(b"see U.10: and E.2").iter().map(|x| x.1.as_str()).collect::<Vec<_>>(), vec!["U.10", "E.2"]);
        assert!(find_words(b"service 10 shall", b"service 1").is_empty());
        assert_eq!(find_words(b"service 1 shall", b"service 1"), vec![0]);
        let s = session();
        let a = analyze(&s, &targets(&["policy"]));
        let u2 = a.segments.iter().find(|g| g.text == U2).unwrap();
        assert_eq!(u2.mentions, vec!["api_001".to_string(), "svc_002".to_string()], "aliases resolve to canonical ids");
        assert_eq!(u2.own_label.as_deref(), Some("U.2"));
    }

    #[test]
    fn empty_state_formalizes_each_target_and_ignores_filler() {
        let s = session();
        let a = analyze(&s, &targets(&["policy"]));
        let k = kinds(&a);
        assert_eq!(k.iter().filter(|x| x.1 == "FORMALIZE").count(), 3, "{k:?}");
        let g3 = a.gaps.iter().find(|g| g.target == "svc_003").unwrap();
        assert_eq!(g3.segments.len(), 2, "both the POS and the NEG clause of svc_003");
        assert_eq!(a.goal_state["svc_010"], "CLOSED_NEGATIVE_UNREACHABLE", "interface 3 has no deprecation clause: nothing to formalize");
        assert!(a.gaps.iter().all(|g| g.priority == Priority::P3FormalizeUncoveredChunk));
    }

    #[test]
    fn partner_extraction_points_at_the_deprecation_clause_only() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        let a = analyze(&s, &targets(&["policy"]));
        let g = a.gaps.iter().find(|g| g.kind == "EXTRACT_PARTNER").expect("P2B gap");
        assert_eq!(g.target, "svc_001");
        assert_eq!(a.segments[g.segments[0]].text, D1, "the type signature {{Api}} selects D.1, not the other use clauses");
        assert_eq!(g.priority, Priority::P2CompleteHornDerivation);
    }

    #[test]
    fn ready_derivation_has_precomputed_interval_and_premises() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        f.fact(&mut s, "2", D1, "api_001", "api_deprecated", "true", "POS", (150, 300));
        let a = analyze(&s, &targets(&["policy"]));
        let g = a.gaps.iter().find(|g| g.kind == "EMIT_DERIVE_ONLY").expect("P2A gap");
        let d = g.derive.as_ref().unwrap();
        assert_eq!((d.head.s.as_str(), d.head.t_from, d.head.t_to), ("svc_001", 150, 200));
        assert_eq!(d.premises.len(), 2);
        // svc_002 now gets a same-step derive hint against the supported deprecation fact
        let f2 = a.gaps.iter().find(|g| g.target == "svc_002").unwrap();
        assert!(f2.partner.is_some(), "partner premise offered for the same-step derive");
        // and the kernel accepts exactly the derive the directive asks for
        f.line(&mut s, json!({"op":"derive","local_id":"r1","rule":d.rule,"premises":d.premises.iter().map(|p| format!("@{}", short(p))).collect::<Vec<_>>()}));
        let a2 = analyze(&s, &targets(&["policy"]));
        assert_eq!(a2.goal_state["svc_001"], "CLOSED_POSITIVE");
        assert!(a2.gaps.iter().all(|g| g.kind != "EMIT_DERIVE_ONLY"));
    }

    #[test]
    fn possibly_contradicting_sentences_get_no_same_step_derive() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        f.fact(&mut s, "5", D2, "api_002", "api_deprecated", "true", "POS", (150, 300));
        let a = analyze(&s, &targets(&["policy"]));
        let g3 = a.gaps.iter().find(|g| g.target == "svc_003" && g.kind == "FORMALIZE").unwrap();
        assert_eq!(g3.segments.len(), 2);
        assert!(g3.partner.is_none() && g3.note.contains("may contradict"), "{:?}", g3.note);
        // a concluded target whose other sentence was never formalized is routed again
        f.fact(&mut s, "3", U3, "svc_003", "uses_api", "api_002", "POS", (100, 160));
        f.line(&mut s, json!({"op":"derive","local_id":"r3","rule":"R_depr_review@1","premises":["f3","f5"]}));
        let b = analyze(&s, &targets(&["policy"]));
        assert_eq!(b.goal_state["svc_003"], "CLOSED_POSITIVE");
        let g = b.gaps.iter().find(|g| g.target == "svc_003").expect("N.3 still routed");
        assert_eq!(b.segments[g.segments[0]].text, N3);
    }

    #[test]
    fn conflict_without_amendment_is_closed_as_blocked() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        f.fact(&mut s, "3", U3, "svc_003", "uses_api", "api_002", "POS", (100, 140));
        f.fact(&mut s, "4", N3, "svc_003", "uses_api", "api_002", "NEG", (120, 150));
        f.fact(&mut s, "5", D2, "api_002", "api_deprecated", "true", "POS", (150, 300));
        let a = analyze(&s, &targets(&["policy"]));
        assert_eq!(a.goal_state["svc_003"], "CLOSED_BLOCKED_BY_CONFLICT", "{:?}", kinds(&a));
    }

    #[test]
    fn amendment_revokes_then_resupports_from_the_restatement() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        f.fact(&mut s, "2", D1, "api_001", "api_deprecated", "true", "POS", (150, 300));
        f.line(&mut s, json!({"op":"derive","local_id":"r1","rule":"R_depr_review@1","premises":["f1","f2"]}));
        let t = targets(&["policy", "erratum"]);
        let a = analyze(&s, &t);
        assert_eq!(a.gaps[0].priority, Priority::P0ResolvePolarConflict, "{:?}", kinds(&a));
        assert_eq!(a.gaps[0].kind, "REVOKE_WITHDRAWN");
        let rs = a.gaps.iter().find(|g| g.kind == "RESUPPORT_FROM_RESTATEMENT").expect("P1 resupport");
        assert_eq!(rs.resupport.as_ref().unwrap().p, "api_deprecated");
        assert!(a.segments.iter().any(|g| g.text == U2 && g.withdrawn), "U.2 is withdrawn before anyone formalized it");
        assert!(a.gaps.iter().all(|g| g.target != "svc_002"), "a withdrawn clause is never routed for formalization");
        // one seat gets revoke + resupport for api_001 in one frame
        let asg = emit_batch(&a, 1, 4);
        let kinds0: Vec<&str> = asg[0].gaps.iter().map(|&i| a.gaps[i].kind).collect();
        assert_eq!(kinds0, vec!["REVOKE_WITHDRAWN", "RESUPPORT_FROM_RESTATEMENT"]);
        // apply: revoke D.1, bind R.1 and re-assert -> conclusion restored without a new derive
        f.line(&mut s, json!({"op":"revoke_evidence","target_evidence":"e2"}));
        let mid = analyze(&s, &t);
        assert!(mid.gaps.iter().any(|g| g.kind == "RESUPPORT_FROM_RESTATEMENT"));
        f.line(&mut s, json!({"op":"bind_evidence","local_id":"eR","doc_id":"policy","exact_quote":R1}));
        f.line(&mut s, json!({"op":"assert_fact","local_id":"fR","s":"api_001","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["eR"]}));
        let end = analyze(&s, &t);
        assert_eq!(end.goal_state["svc_001"], "CLOSED_POSITIVE", "{:?}", kinds(&end));
        assert!(end.gaps.iter().all(|g| g.kind != "RESUPPORT_FROM_RESTATEMENT" && g.kind != "REVOKE_WITHDRAWN"), "{:?}", kinds(&end));
    }

    #[test]
    fn parallel_batch_never_shares_a_target_or_a_segment_and_idles_surplus_seats() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        let bytes0 = build_container(&mut s);
        for seats in 1..=6 {
            let a = analyze(&s, &targets(&["policy"]));
            let asg = emit_batch(&a, seats, 4);
            assert_eq!(asg.len(), seats);
            let mut tg = HashSet::new();
            let mut sg = HashSet::new();
            for x in &asg {
                if let Some(t) = &x.target {
                    assert!(tg.insert(t.clone()), "two seats share target {t}");
                    for &gi in &x.gaps {
                        for s in &a.gaps[gi].segments {
                            assert!(sg.insert(*s), "two seats share segment {s}");
                        }
                    }
                }
            }
            let busy = asg.iter().filter(|x| x.target.is_some()).count();
            assert!(busy <= 3, "only three targets have work");
        }
        // shared partner: svc_001 and svc_002 both use api_001 -> only one of them may take D.1 in a round
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        f.fact(&mut s, "2", U2, "svc_002", "uses_api", "api_001", "POS", (110, 210));
        let a = analyze(&s, &targets(&["policy"]));
        assert_eq!(a.gaps.iter().filter(|g| g.kind == "EXTRACT_PARTNER").count(), 2);
        let asg = emit_batch(&a, 4, 4);
        let d1_takers = asg.iter().filter(|x| x.gaps.iter().any(|&gi| a.gaps[gi].kind == "EXTRACT_PARTNER")).count();
        assert_eq!(d1_takers, 1, "the shared deprecation clause goes to exactly one seat");
        // frames are small and self-contained
        let bytes = build_container(&mut s);
        let v = emit_batch_frames(&bytes, &targets(&["policy"]), 4, 4, 3).unwrap();
        for fr in v["frames"].as_array().unwrap() {
            let n = fr["prompt_chars"].as_u64().unwrap();
            assert!(n == 0 || (n > 500 && n < 4500), "frame size {n}");
            if !fr["noop"].as_bool().unwrap() {
                assert!(!fr["prompt"].as_str().unwrap().contains("The custodian must review"), "filler never reaches the worker");
            }
        }
        assert!(emit_batch_frames(&bytes0, &targets(&["policy"]), 2, 4, 1).is_ok());
    }

    #[test]
    fn complete_state_is_p4_no_op() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        f.fact(&mut s, "2", D1, "api_001", "api_deprecated", "true", "POS", (150, 300));
        f.fact(&mut s, "3", U2, "svc_002", "uses_api", "api_001", "POS", (110, 210));
        f.line(&mut s, json!({"op":"derive","local_id":"r1","rule":"R_depr_review@1","premises":["f1","f2"]}));
        f.line(&mut s, json!({"op":"derive","local_id":"r2","rule":"R_depr_review@1","premises":["f3","f2"]}));
        f.fact(&mut s, "4", U3, "svc_003", "uses_api", "api_002", "POS", (100, 140));
        f.fact(&mut s, "5", N3, "svc_003", "uses_api", "api_002", "NEG", (120, 150));
        f.fact(&mut s, "6", D2, "api_002", "api_deprecated", "true", "POS", (150, 300));
        // R.1 restates D.1: binding it is not required, but it is an uncovered sentence only about api_001 (no target) -> no work
        let a = analyze(&s, &targets(&["policy"]));
        assert!(a.complete(), "{:?}", kinds(&a));
        let bytes = build_container(&mut s);
        let v = emit_batch_frames(&bytes, &targets(&["policy"]), 3, 4, 9).unwrap();
        assert_eq!(v["complete"], json!(true));
        assert!(v["frames"].as_array().unwrap().iter().all(|f| f["noop"] == json!(true)));
        assert!(v["analysis_us"].as_f64().unwrap() < 50_000.0);
    }

    /// The cone the resident path reads from the live engine is the one the container projection reads from the bytes.
    fn check_cones(s: &mut Session) {
        let bytes = build_container(s);
        let cone = s.engine.cone_reader();
        let mut names: Vec<String> = s.ontology.entities.keys().cloned().collect();
        names.extend(["service 1", "interface 1", "true", "nobody"].map(String::from));
        for e in &names {
            let v = crate::cone::minimal_cone_value(&bytes, e).unwrap();
            let want: BTreeSet<String> = v["claims"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect();
            let got: BTreeSet<String> = cone_claim_ids(&cone, &s.ontology, e).iter().map(short).collect();
            assert_eq!(got, want, "cone of {e}");
        }
    }

    #[test]
    fn engine_cone_selects_exactly_what_the_container_projection_reads() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        check_cones(&mut s);
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        f.fact(&mut s, "2", D1, "api_001", "api_deprecated", "true", "POS", (150, 300));
        f.fact(&mut s, "3", U2, "svc_002", "uses_api", "api_001", "POS", (110, 210));
        f.line(&mut s, json!({"op":"derive","local_id":"r1","rule":"R_depr_review@1","premises":["f1","f2"]}));
        f.line(&mut s, json!({"op":"derive","local_id":"r2","rule":"R_depr_review@1","premises":["f3","f2"]}));
        check_cones(&mut s);
        // a conclusion that also has a direct assertion: the canonical justification is the lower-ranked assertion
        f.line(&mut s, json!({"op":"assert_fact","local_id":"g1","s":"svc_001","p":"needs_review","o":"true","polarity":"POS","ctx":"prod","t":[150,200],"evidence":["e1"]}));
        // a second source for the deprecation fact (two active assertions, rank tie broken by id) and a polar conflict
        f.line(&mut s, json!({"op":"bind_evidence","local_id":"eR","doc_id":"policy","exact_quote":R1}));
        f.line(&mut s, json!({"op":"assert_fact","local_id":"fR","s":"api_001","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["eR"]}));
        f.fact(&mut s, "4", U3, "svc_003", "uses_api", "api_002", "POS", (100, 140));
        f.fact(&mut s, "5", N3, "svc_003", "uses_api", "api_002", "NEG", (120, 150));
        check_cones(&mut s);
        // revocations: the cone follows the remaining support only
        f.line(&mut s, json!({"op":"revoke_evidence","target_evidence":"e2"}));
        check_cones(&mut s);
        f.line(&mut s, json!({"op":"revoke_evidence","target_evidence":"eR"}));
        check_cones(&mut s);
    }

    /// Timing fields differ between runs; everything else of a batch must be byte-identical.
    fn without_timings(mut v: Value) -> String {
        for k in ["open_us", "analysis_us", "analysis_warm_us", "pack_us"] {
            v.as_object_mut().unwrap().remove(k);
        }
        v.to_string()
    }

    /// The resident batch (live session, cache kept across rounds) against the one-shot batch on the container of the same state.
    fn same_batch(s: &mut Session, cache: &mut DirectiveCache, t: &Targets, round: u64) {
        let bytes = build_container(s);
        for seats in [1, 3] {
            let one_shot = emit_batch_frames(&bytes, t, seats, 4, round).unwrap();
            let live = emit_batch_frames_live(s, cache, t, seats, 4, round);
            assert_eq!(without_timings(live), without_timings(one_shot), "round {round}, {seats} seat(s)");
        }
        let a = analyze_cached(s, t, cache);
        let b = analyze(s, t);
        assert_eq!(kinds(&a), kinds(&b));
        assert_eq!(a.goal_state, b.goal_state);
    }

    #[test]
    fn resident_batches_equal_container_batches_across_rounds_and_document_updates() {
        let mut s = session();
        let mut f = Feed { seq: 0 };
        let mut cache = DirectiveCache::new();
        let plain = targets(&["policy"]);
        let all = targets(&["policy", "erratum"]);
        same_batch(&mut s, &mut cache, &plain, 1);
        f.fact(&mut s, "1", U1, "svc_001", "uses_api", "api_001", "POS", (100, 200));
        same_batch(&mut s, &mut cache, &plain, 2);
        f.fact(&mut s, "2", D1, "api_001", "api_deprecated", "true", "POS", (150, 300));
        same_batch(&mut s, &mut cache, &plain, 3);
        f.line(&mut s, json!({"op":"derive","local_id":"r1","rule":"R_depr_review@1","premises":["f1","f2"]}));
        f.fact(&mut s, "4", U3, "svc_003", "uses_api", "api_002", "POS", (100, 140));
        f.fact(&mut s, "5", N3, "svc_003", "uses_api", "api_002", "NEG", (120, 150));
        same_batch(&mut s, &mut cache, &plain, 4);
        // the erratum becomes visible: P0 revoke + P1 resupport
        same_batch(&mut s, &mut cache, &all, 5);
        f.line(&mut s, json!({"op":"revoke_evidence","target_evidence":"e2"}));
        same_batch(&mut s, &mut cache, &all, 6);
        f.line(&mut s, json!({"op":"bind_evidence","local_id":"eR","doc_id":"policy","exact_quote":R1}));
        f.line(&mut s, json!({"op":"assert_fact","local_id":"fR","s":"api_001","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["eR"]}));
        same_batch(&mut s, &mut cache, &all, 7);
        // a new document version shifts every sentence and every evidence span: the cache must rebuild both
        let built = cache.stats.docs_built;
        s.put_document("policy", format!("Preamble: this register is binding. {}", doc()).as_bytes());
        same_batch(&mut s, &mut cache, &all, 8);
        assert!(cache.stats.docs_built > built, "the new version was segmented again");
        s.put_document("policy", doc().as_bytes());
        same_batch(&mut s, &mut cache, &all, 9);
        assert!(cache.stats.docs_reused > 0 && cache.stats.evidence_reused > 0);
    }

    #[test]
    fn wide_rounds_give_every_seat_its_own_prefix() {
        // up to 8 seats: the historical prefixes
        assert_eq!((0..8).map(|i| seat_prefix(i, 8, 3)).collect::<Vec<_>>(), ["a3_", "b3_", "c3_", "d3_", "e3_", "f3_", "g3_", "h3_"]);
        assert_eq!(seat_prefix(1, 2, 1), "b1_");
        // 100 seats, 100 targets: one FORMALIZE per seat, 100 distinct prefixes, and every seat's events are accepted
        let n = 100;
        let ents: Vec<Value> =
            (0..n).map(|i| json!({"id": format!("svc_{i:03}"), "type": "Service"})).chain([json!({"id": "api_001", "type": "Api"})]).collect();
        let onto = json!({"entities": ents, "predicates": [{"id": "uses_api", "subject": "Service", "object": "Api"},
                          {"id": "needs_review", "subject": "Service", "object": "@literal"}], "rules": []});
        let mut s = Session::new(Ontology::from_json_str(&onto.to_string()).unwrap(), CdcParams::default());
        let clauses: Vec<String> =
            (0..n).map(|i| format!("Clause U.{i}: service svc_{i:03} shall call interface api_001 in production from t=100 until t=200.")).collect();
        s.put_document("policy", clauses.join(" ").as_bytes());
        let t = Targets { goals: (0..n).map(|i| Goal { entity: format!("svc_{i:03}"), predicate: "needs_review".into() }).collect(), docs: None };
        let b = emit_batch_frames_live(&s, &mut DirectiveCache::new(), &t, n, 4, 1);
        let frames: Vec<&Value> = b["frames"].as_array().unwrap().iter().filter(|f| !f["noop"].as_bool().unwrap_or(false)).collect();
        assert_eq!(frames.len(), n);
        let prefixes: HashSet<&str> = frames.iter().map(|f| f["local_id_prefix"].as_str().unwrap()).collect();
        assert_eq!(prefixes.len(), n, "no two seats of a round share a prefix");
        assert!(prefixes.contains("a0r1_") && prefixes.contains("d12r1_"));
        let mut seq = 0;
        for f in &frames {
            let pre = f["local_id_prefix"].as_str().unwrap();
            let text = f["gaps"][0]["segment_texts"][0].as_str().unwrap();
            let svc = &text[text.find("svc_").unwrap()..][..7];
            for ev in [
                json!({"op": "bind_evidence", "local_id": format!("{pre}e1"), "doc_id": "policy", "exact_quote": text}),
                json!({"op": "assert_fact", "local_id": format!("{pre}f1"), "s": svc, "p": "uses_api", "o": "api_001", "polarity": "POS",
                       "ctx": "prod", "t": [100, 200], "evidence": [format!("{pre}e1")]}),
            ] {
                seq += 1;
                let mut m = ev.as_object().unwrap().clone();
                m.insert("seq".into(), json!(seq));
                s.apply_line(&Value::Object(m).to_string()).unwrap_or_else(|e| panic!("{pre}: {e}"));
            }
        }
    }
}
