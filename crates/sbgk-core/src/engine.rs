//! Deterministic graph engine: node store, least-fixed-point support, DRed
//! (delete-and-rederive) maintenance, conflict blocking and state snapshots.
//!
//! Semantics
//! * An `Assertion` justification fires iff its evidence is ACTIVE.
//! * A `Derivation` fires iff every premise claim is *usable*.
//! * `S0` is the least fixed point of the firing relation (plain support).
//! * If an opposite-polarity pair (same s,p,o,ctx; overlapping `[from,to)`) is inside `S0`,
//!   both members form the conflict set `C`. `S2` is the least fixed point in which members of
//!   `C` do not fire as premises. Final status: `S2 \ C` = SUPPORTED, `S2 ∩ C` = CONFLICTING,
//!   everything else UNSUPPORTED.
//! * Without conflicts `S2 = S0`, which is maintained incrementally (forward semi-naive on
//!   additions, DRed on deletions). When conflicts exist the engine recomputes `S2` in full.

use crate::hash::{sha256, Hash};
use crate::merkle::{bucket_hash, root_from_buckets, FxMap, FxSet, IdMap, BUCKETS};
use crate::node::*;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub enum CanonOp {
    Genesis { ontology_hash: Hash, cdc: (u32, u32, u32, u32) },
    BindEvidence { doc_version: Hash, ev: EvidenceNode },
    Assert { claim: Claim, evidence: Vec<Hash> },
    Derive { claim: Claim, justs: Vec<(String, Vec<Hash>)> },
    Revoke { evidence: Hash },
    DocPut { doc_id: String, version: Hash, chunks: Vec<Hash> },
}

#[derive(Debug, Clone)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "engine error: {}", self.0)
    }
}

impl std::error::Error for EngineError {}

#[derive(Debug, Clone, Default)]
pub struct DredReport {
    pub over_deleted: usize,
    pub rederived: usize,
    pub net_removed: usize,
    pub restored_by_forward: usize,
    pub full_recompute: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Applied {
    pub node: Option<Hash>,
    pub created: usize,
    pub claim_status: Option<u8>,
    pub dred: Option<DredReport>,
}

#[derive(Debug, Clone)]
enum Body {
    Evidence(EvidenceNode),
    Claim(Claim),
    Assertion { claim: u32, ev: u32 },
    Derivation { rule: String, claim: u32, premises: Vec<u32> },
}

#[derive(Debug, Clone)]
struct Entry {
    id: Hash,
    body: Body,
    status: u8,
    /// Justifications consuming this node (evidence -> assertions, claim -> derivations).
    used_by: Vec<u32>,
    /// For claims: justifications concluding this claim.
    supports: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
struct DocState {
    version: Option<Hash>,
    /// Current document order and multiplicity are part of anchor validity.
    chunks: Vec<Hash>,
    evidence: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub id: Hash,
    pub kind: u8,
    pub status: u8,
    pub rank: u32,
    pub payload: Vec<u8>,
    /// For claims: ids of justifications concluding it. Empty for other kinds.
    pub adj: Vec<Hash>,
}

/// Borrowed view of one node (see `Engine::node_views`).
#[derive(Debug, Clone, Copy)]
pub enum NodeView<'a> {
    Evidence(&'a EvidenceNode),
    Claim(&'a Claim),
    Assertion { claim: &'a Hash, evidence: &'a Hash },
    Derivation { rule: &'a str, claim: &'a Hash },
}

/// The selection of `cone::minimal_cone_value`, read from the live engine instead of container bytes: the SUPPORTED /
/// CONFLICTING claims whose subject or object is the entity, then recursively the premises of each claim's canonical active
/// justification (lowest `(rank, id)`, ranks as written into the node table).
pub struct ConeReader<'a> {
    eng: &'a Engine,
    ranks: Vec<u32>,
    by_entity: FxMap<&'a str, Vec<u32>>,
}

impl ConeReader<'_> {
    /// Does any claim (whatever its status) have `entity` as subject or object?
    pub fn about(&self, entity: &str) -> bool {
        self.by_entity.contains_key(entity)
    }

    /// Claim ids of the minimal support cone of `entity` (exact canonical id).
    pub fn claim_ids(&self, entity: &str) -> Vec<Hash> {
        let ents = &self.eng.entries;
        let mut seen: FxSet<u32> = FxSet::default();
        let mut stack: Vec<u32> = self
            .by_entity
            .get(entity)
            .map(|v| v.iter().copied().filter(|&i| matches!(ents[i as usize].status, ST_SUPPORTED | ST_CONFLICTING)).collect())
            .unwrap_or_default();
        while let Some(c) = stack.pop() {
            if !seen.insert(c) {
                continue;
            }
            let best = ents[c as usize]
                .supports
                .iter()
                .copied()
                .filter(|&j| ents[j as usize].status == J_ACTIVE)
                .min_by_key(|&j| (self.ranks[j as usize], ents[j as usize].id));
            if let Some(j) = best {
                if let Body::Derivation { premises, .. } = &ents[j as usize].body {
                    stack.extend(premises.iter().copied());
                }
            }
        }
        let mut out: Vec<Hash> = seen.into_iter().map(|i| ents[i as usize].id).collect();
        out.sort();
        out
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Sorted by `(rank, node_id)` — topological by derivation depth, then lexicographic.
    pub records: Vec<Record>,
    pub bucket_hashes: Vec<Hash>,
    pub root: Hash,
}

/// `Clone` is a deep copy of every field, the derived indices and caches included: a staged transaction forks the engine of a
/// trusted in-memory state by it (the audit layer's `Core::fork_session`).
#[derive(Debug, Clone)]
pub struct Engine {
    entries: Vec<Entry>,
    index: IdMap<u32>,
    s0: Vec<bool>,
    docs: HashMap<String, DocState>,
    groups: IdMap<Vec<u32>>,
    risky: HashSet<Hash>,
    blocked_mode: bool,
    buckets: Vec<Vec<u32>>,
    bucket_hashes: Vec<Hash>,
    dirty: Vec<bool>,
    flip_log: Vec<u32>,
    pub genesis: Option<(Hash, (u32, u32, u32, u32))>,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new()
    }
}

/// Conflict group of a claim: `(s, p, o, ctx)`. Each component is length-prefixed, so no two different tuples share a key
/// (names may contain any character, NUL included).
fn group_id(c: &Claim) -> Hash {
    let mut buf = Vec::new();
    for s in [&c.s, &c.p, &c.o, &c.ctx] {
        buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
    }
    sha256(&buf)
}

impl Engine {
    pub fn new() -> Engine {
        Engine {
            entries: Vec::new(),
            index: IdMap::default(),
            s0: Vec::new(),
            docs: HashMap::new(),
            groups: IdMap::default(),
            risky: HashSet::new(),
            blocked_mode: false,
            buckets: vec![Vec::new(); BUCKETS],
            bucket_hashes: vec![[0u8; 32]; BUCKETS],
            dirty: vec![false; BUCKETS],
            flip_log: Vec::new(),
            genesis: None,
        }
    }

    // ------------------------------------------------------------------ queries

    pub fn node_count(&self) -> usize {
        self.entries.len()
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.index.contains_key(id)
    }

    pub fn kind_of(&self, id: &Hash) -> Option<u8> {
        self.index.get(id).map(|&i| match self.entries[i as usize].body {
            Body::Evidence(_) => KIND_EVIDENCE,
            Body::Claim(_) => KIND_CLAIM,
            Body::Assertion { .. } => KIND_ASSERTION,
            Body::Derivation { .. } => KIND_DERIVATION,
        })
    }

    pub fn status_of(&self, id: &Hash) -> Option<u8> {
        self.index.get(id).map(|&i| self.entries[i as usize].status)
    }

    pub fn claim(&self, id: &Hash) -> Option<&Claim> {
        match self.index.get(id).map(|&i| &self.entries[i as usize].body) {
            Some(Body::Claim(c)) => Some(c),
            _ => None,
        }
    }

    pub fn evidence(&self, id: &Hash) -> Option<&EvidenceNode> {
        match self.index.get(id).map(|&i| &self.entries[i as usize].body) {
            Some(Body::Evidence(e)) => Some(e),
            _ => None,
        }
    }

    pub fn claim_ids(&self) -> Vec<Hash> {
        self.entries.iter().filter(|e| matches!(e.body, Body::Claim(_))).map(|e| e.id).collect()
    }

    /// Supported-or-conflicting claims whose subject or object equals `entity`.
    pub fn claims_of_entity(&self, entity: &str) -> Vec<Hash> {
        let mut v: Vec<Hash> = self
            .entries
            .iter()
            .filter_map(|e| match &e.body {
                Body::Claim(c) if c.s == entity || c.o == entity => Some(e.id),
                _ => None,
            })
            .collect();
        v.sort();
        v
    }

    pub fn stale_evidence_of_doc(&self, doc_id: &str) -> Vec<(Hash, EvidenceNode)> {
        let mut out = Vec::new();
        if let Some(d) = self.docs.get(doc_id) {
            for &i in &d.evidence {
                let e = &self.entries[i as usize];
                if e.status == EV_STALE {
                    if let Body::Evidence(ev) = &e.body {
                        out.push((e.id, ev.clone()));
                    }
                }
            }
        }
        out.sort_by_key(|a| a.0);
        out
    }

    /// Claims asserted directly from `evidence` (via assertion justifications).
    pub fn claims_asserted_by(&self, evidence: &Hash) -> Vec<Claim> {
        let mut out = Vec::new();
        if let Some(&i) = self.index.get(evidence) {
            for &j in &self.entries[i as usize].used_by {
                if let Body::Assertion { claim, .. } = &self.entries[j as usize].body {
                    if let Body::Claim(c) = &self.entries[*claim as usize].body {
                        out.push(c.clone());
                    }
                }
            }
        }
        out.sort_by_key(|c| c.id());
        out
    }

    pub fn doc_version(&self, doc_id: &str) -> Option<Hash> {
        self.docs.get(doc_id).and_then(|d| d.version)
    }

    pub fn evidence_count_of_doc(&self, doc_id: &str) -> usize {
        self.docs.get(doc_id).map_or(0, |d| d.evidence.len())
    }

    /// Unique node whose hex id starts with `hex_prefix` (used for `@<id>` references).
    pub fn find_by_prefix(&self, hex_prefix: &str) -> Option<Hash> {
        let p = hex_prefix.to_ascii_lowercase();
        let mut found: Option<Hash> = None;
        for e in &self.entries {
            if crate::hash::to_hex(&e.id).starts_with(&p) {
                if found.is_some() {
                    return None;
                }
                found = Some(e.id);
            }
        }
        found
    }

    pub fn status_counts(&self) -> (usize, usize, usize) {
        let (mut s, mut u, mut c) = (0, 0, 0);
        for e in &self.entries {
            if matches!(e.body, Body::Claim(_)) {
                match e.status {
                    ST_SUPPORTED => s += 1,
                    ST_CONFLICTING => c += 1,
                    _ => u += 1,
                }
            }
        }
        (s, u, c)
    }

    /// Number of evidence nodes whose quote straddles a chunk boundary (more than one segment).
    pub fn multi_segment_evidence(&self) -> usize {
        self.entries.iter().filter(|e| matches!(&e.body, Body::Evidence(ev) if ev.segs.len() > 1)).count()
    }

    pub fn kind_counts(&self) -> [usize; 5] {
        let mut k = [0usize; 5];
        for e in &self.entries {
            let i = match e.body {
                Body::Evidence(_) => 1,
                Body::Claim(_) => 2,
                Body::Assertion { .. } => 3,
                Body::Derivation { .. } => 4,
            };
            k[i] += 1;
        }
        k
    }

    // ------------------------------------------------------------------ mutation helpers

    fn insert(&mut self, id: Hash, body: Body, status: u8) -> (u32, bool) {
        if let Some(&i) = self.index.get(&id) {
            return (i, false);
        }
        let i = self.entries.len() as u32;
        if let Body::Claim(c) = &body {
            let g = group_id(c);
            let members = self.groups.entry(g).or_default();
            members.push(i);
            let mut has_pos = false;
            let mut has_neg = false;
            for &m in members.iter() {
                if m == i {
                    match c.pol {
                        Polarity::Pos => has_pos = true,
                        Polarity::Neg => has_neg = true,
                    }
                } else if let Body::Claim(o) = &self.entries[m as usize].body {
                    match o.pol {
                        Polarity::Pos => has_pos = true,
                        Polarity::Neg => has_neg = true,
                    }
                }
            }
            if has_pos && has_neg {
                self.risky.insert(g);
            }
        }
        self.entries.push(Entry { id, body, status, used_by: Vec::new(), supports: Vec::new() });
        self.s0.push(false);
        self.index.insert(id, i);
        self.buckets[id[0] as usize].push(i);
        self.dirty[id[0] as usize] = true;
        (i, true)
    }

    fn set_status_raw(&mut self, i: u32, st: u8) -> bool {
        let e = &mut self.entries[i as usize];
        if e.status == st {
            return false;
        }
        e.status = st;
        let b = e.id[0] as usize;
        self.dirty[b] = true;
        true
    }

    /// Recompute the ACTIVE/INACTIVE flag of one justification from final statuses.
    fn refresh_j(&mut self, j: u32) {
        let active = match &self.entries[j as usize].body {
            Body::Assertion { ev, .. } => self.entries[*ev as usize].status == EV_ACTIVE,
            Body::Derivation { premises, .. } => premises.iter().all(|&p| self.entries[p as usize].status == ST_SUPPORTED),
            _ => return,
        };
        self.set_status_raw(j, if active { J_ACTIVE } else { J_INACTIVE });
    }

    fn set_claim_status(&mut self, c: u32, st: u8) {
        let old = self.entries[c as usize].status;
        if old == st {
            return;
        }
        self.set_status_raw(c, st);
        if (old == ST_SUPPORTED) != (st == ST_SUPPORTED) {
            let users = self.entries[c as usize].used_by.clone();
            for j in users {
                self.refresh_j(j);
            }
        }
    }

    fn set_ev_status(&mut self, e: u32, st: u8) {
        if self.set_status_raw(e, st) {
            let users = self.entries[e as usize].used_by.clone();
            for j in users {
                self.refresh_j(j);
            }
        }
    }

    fn set_s0(&mut self, c: u32, v: bool) {
        if self.s0[c as usize] != v {
            self.s0[c as usize] = v;
            self.flip_log.push(c);
        }
    }

    fn fires_s0(&self, j: u32) -> bool {
        match &self.entries[j as usize].body {
            Body::Assertion { ev, .. } => self.entries[*ev as usize].status == EV_ACTIVE,
            Body::Derivation { premises, .. } => premises.iter().all(|&p| self.s0[p as usize]),
            _ => false,
        }
    }

    fn concl(&self, j: u32) -> u32 {
        match &self.entries[j as usize].body {
            Body::Assertion { claim, .. } | Body::Derivation { claim, .. } => *claim,
            _ => unreachable!("not a justification"),
        }
    }

    // ------------------------------------------------------------------ fixed point

    /// Semi-naive forward closure starting from the given justifications.
    fn forward(&mut self, seeds: Vec<u32>) -> usize {
        let mut q: VecDeque<u32> = seeds.into();
        let mut added = 0;
        while let Some(j) = q.pop_front() {
            let c = self.concl(j);
            if self.s0[c as usize] || !self.fires_s0(j) {
                continue;
            }
            self.set_s0(c, true);
            added += 1;
            for &j2 in &self.entries[c as usize].used_by {
                q.push_back(j2);
            }
        }
        added
    }

    fn has_s0_support(&self, c: u32) -> bool {
        self.entries[c as usize].supports.iter().any(|&j| self.fires_s0(j))
    }

    /// Delete-and-Rederive after the given evidence nodes became inactive.
    fn dred(&mut self, lost: &[u32]) -> DredReport {
        let mut over: Vec<u32> = Vec::new();
        let mut in_over: HashSet<u32> = HashSet::new();
        let mut stack: Vec<u32> = Vec::new();
        for &ev in lost {
            for &j in &self.entries[ev as usize].used_by {
                let c = self.concl(j);
                if self.s0[c as usize] && in_over.insert(c) {
                    over.push(c);
                    stack.push(c);
                }
            }
        }
        while let Some(c) = stack.pop() {
            for &j in &self.entries[c as usize].used_by {
                let c2 = self.concl(j);
                if self.s0[c2 as usize] && in_over.insert(c2) {
                    over.push(c2);
                    stack.push(c2);
                }
            }
        }
        for &c in &over {
            self.set_s0(c, false);
        }
        let mut work: VecDeque<u32> = over.iter().copied().collect();
        let mut rederived = 0;
        while let Some(c) = work.pop_front() {
            if self.s0[c as usize] || !self.has_s0_support(c) {
                continue;
            }
            self.set_s0(c, true);
            rederived += 1;
            for &j in &self.entries[c as usize].used_by {
                let c2 = self.concl(j);
                if in_over.contains(&c2) && !self.s0[c2 as usize] {
                    work.push_back(c2);
                }
            }
        }
        DredReport { over_deleted: over.len(), rederived, net_removed: over.len() - rederived, restored_by_forward: 0, full_recompute: false }
    }

    fn any_conflict_s0(&self) -> bool {
        for g in &self.risky {
            let m = &self.groups[g];
            for (ai, &a) in m.iter().enumerate() {
                if !self.s0[a as usize] {
                    continue;
                }
                for &b in &m[ai + 1..] {
                    if self.s0[b as usize] && self.conflicting_pair(a, b) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn conflicting_pair(&self, a: u32, b: u32) -> bool {
        match (&self.entries[a as usize].body, &self.entries[b as usize].body) {
            (Body::Claim(x), Body::Claim(y)) => x.pol != y.pol && x.overlaps(y) && (&x.s, &x.p, &x.o, &x.ctx) == (&y.s, &y.p, &y.o, &y.ctx),
            _ => false,
        }
    }

    /// From-scratch computation of `(S0, final claim statuses)`. Also the correctness oracle.
    pub fn compute_batch(&self) -> (Vec<bool>, Vec<u8>) {
        let n = self.entries.len();
        let closure = |blocked: &[bool]| -> Vec<bool> {
            let mut val = vec![false; n];
            let mut need: Vec<u32> = vec![0; n];
            let mut q: VecDeque<u32> = VecDeque::new();
            for (j, e) in self.entries.iter().enumerate() {
                match &e.body {
                    Body::Assertion { claim, ev } => {
                        if self.entries[*ev as usize].status == EV_ACTIVE && !val[*claim as usize] {
                            val[*claim as usize] = true;
                            q.push_back(*claim);
                        }
                    }
                    Body::Derivation { premises, .. } => need[j] = premises.len() as u32,
                    _ => {}
                }
            }
            while let Some(c) = q.pop_front() {
                if blocked[c as usize] {
                    continue;
                }
                for &j in &self.entries[c as usize].used_by {
                    if let Body::Derivation { claim, .. } = &self.entries[j as usize].body {
                        need[j as usize] -= 1;
                        if need[j as usize] == 0 && !val[*claim as usize] {
                            val[*claim as usize] = true;
                            q.push_back(*claim);
                        }
                    }
                }
            }
            val
        };
        let none = vec![false; n];
        let s0 = closure(&none);
        let mut in_c = vec![false; n];
        let mut any = false;
        for g in &self.risky {
            let m = &self.groups[g];
            for (ai, &a) in m.iter().enumerate() {
                for &b in &m[ai + 1..] {
                    if s0[a as usize] && s0[b as usize] && self.conflicting_pair(a, b) {
                        in_c[a as usize] = true;
                        in_c[b as usize] = true;
                        any = true;
                    }
                }
            }
        }
        let s2 = if any { closure(&in_c) } else { s0.clone() };
        let mut status = vec![ST_UNSUPPORTED; n];
        for (i, e) in self.entries.iter().enumerate() {
            if matches!(e.body, Body::Claim(_)) && s2[i] {
                status[i] = if in_c[i] { ST_CONFLICTING } else { ST_SUPPORTED };
            }
        }
        (s0, status)
    }

    /// True iff incrementally maintained state equals a from-scratch recomputation.
    pub fn oracle_check(&self) -> bool {
        let (s0, status) = self.compute_batch();
        for (i, e) in self.entries.iter().enumerate() {
            if matches!(e.body, Body::Claim(_)) && (s0[i] != self.s0[i] || status[i] != e.status) {
                return false;
            }
        }
        true
    }

    /// Settle final statuses after `flip_log` accumulated S0 changes.
    fn finalize(&mut self) -> bool {
        let flips = std::mem::take(&mut self.flip_log);
        let conflict = !self.risky.is_empty() && self.any_conflict_s0();
        if !conflict && !self.blocked_mode {
            let mut seen = HashSet::new();
            for c in flips {
                if seen.insert(c) {
                    let st = if self.s0[c as usize] { ST_SUPPORTED } else { ST_UNSUPPORTED };
                    self.set_claim_status(c, st);
                }
            }
            return false;
        }
        let (s0, status) = self.compute_batch();
        for i in 0..self.entries.len() {
            if matches!(self.entries[i].body, Body::Claim(_)) {
                self.s0[i] = s0[i];
                self.set_claim_status(i as u32, status[i]);
            }
        }
        self.blocked_mode = conflict;
        true
    }

    // ------------------------------------------------------------------ ops

    fn lookup(&self, id: &Hash, what: &str) -> Result<u32, EngineError> {
        self.index.get(id).copied().ok_or_else(|| EngineError(format!("missing {what} node {}", crate::hash::short(id))))
    }

    pub fn apply(&mut self, op: &CanonOp) -> Result<Applied, EngineError> {
        match op {
            CanonOp::Genesis { ontology_hash, cdc } => {
                self.genesis = Some((*ontology_hash, *cdc));
                Ok(Applied::default())
            }
            CanonOp::BindEvidence { doc_version, ev } => {
                if let Some(Some(cur)) = self.docs.get(&ev.doc_id).map(|d| d.version) {
                    if cur != *doc_version {
                        return Err(EngineError("evidence is anchored to a document version that is not current".into()));
                    }
                }
                let id = ev.id();
                let active = self.docs.get(&ev.doc_id).is_some_and(|d| ev.has_contiguous_chunks(&d.chunks));
                let st = if active { EV_ACTIVE } else { EV_STALE };
                let (i, created) = self.insert(id, Body::Evidence(ev.clone()), st);
                if created {
                    self.docs.entry(ev.doc_id.clone()).or_default().evidence.push(i);
                }
                Ok(Applied { node: Some(id), created: created as usize, ..Default::default() })
            }
            CanonOp::Assert { claim, evidence } => {
                let cid = claim.id();
                let (ci, created) = self.insert(cid, Body::Claim(claim.clone()), ST_UNSUPPORTED);
                let mut made = created as usize;
                let mut new_js = Vec::new();
                for ev in evidence {
                    let ei = self.lookup(ev, "evidence")?;
                    if !matches!(self.entries[ei as usize].body, Body::Evidence(_)) {
                        return Err(EngineError("assert references a non-evidence node".into()));
                    }
                    let jid = sha256(&encode_assertion(&cid, ev));
                    let (ji, jc) = self.insert(jid, Body::Assertion { claim: ci, ev: ei }, J_INACTIVE);
                    if jc {
                        made += 1;
                        self.entries[ei as usize].used_by.push(ji);
                        self.entries[ci as usize].supports.push(ji);
                        self.refresh_j(ji);
                    }
                    new_js.push(ji);
                }
                self.forward(new_js);
                self.finalize();
                Ok(Applied { node: Some(cid), created: made, claim_status: Some(self.entries[ci as usize].status), ..Default::default() })
            }
            CanonOp::Derive { claim, justs } => {
                let cid = claim.id();
                let (ci, created) = self.insert(cid, Body::Claim(claim.clone()), ST_UNSUPPORTED);
                let mut made = created as usize;
                let mut new_js = Vec::new();
                for (rule, premises) in justs {
                    let mut pidx = Vec::with_capacity(premises.len());
                    for p in premises {
                        let pi = self.lookup(p, "premise")?;
                        if !matches!(self.entries[pi as usize].body, Body::Claim(_)) {
                            return Err(EngineError("derive premise is not a claim".into()));
                        }
                        pidx.push(pi);
                    }
                    let jid = sha256(&encode_derivation(rule, &cid, premises));
                    let mut sorted_idx = pidx.clone();
                    sorted_idx.sort_by_key(|&i| self.entries[i as usize].id);
                    sorted_idx.dedup();
                    let (ji, jc) = self.insert(jid, Body::Derivation { rule: rule.clone(), claim: ci, premises: sorted_idx.clone() }, J_INACTIVE);
                    if jc {
                        made += 1;
                        for &p in &sorted_idx {
                            self.entries[p as usize].used_by.push(ji);
                        }
                        self.entries[ci as usize].supports.push(ji);
                        self.refresh_j(ji);
                    }
                    new_js.push(ji);
                }
                self.forward(new_js);
                self.finalize();
                Ok(Applied { node: Some(cid), created: made, claim_status: Some(self.entries[ci as usize].status), ..Default::default() })
            }
            CanonOp::Revoke { evidence } => {
                let ei = self.lookup(evidence, "evidence")?;
                if !matches!(self.entries[ei as usize].body, Body::Evidence(_)) {
                    return Err(EngineError("revoke target is not evidence".into()));
                }
                let was_active = self.entries[ei as usize].status == EV_ACTIVE;
                self.set_ev_status(ei, EV_REVOKED);
                let mut rep = DredReport::default();
                if was_active {
                    rep = self.dred(&[ei]);
                }
                rep.full_recompute = self.finalize();
                Ok(Applied { node: Some(*evidence), dred: Some(rep), ..Default::default() })
            }
            CanonOp::DocPut { doc_id, chunks, version } => {
                let st = self.docs.entry(doc_id.clone()).or_default();
                st.version = Some(*version);
                st.chunks = chunks.clone();
                let evs = st.evidence.clone();
                let mut lost = Vec::new();
                let mut gained = Vec::new();
                for e in evs {
                    let old = self.entries[e as usize].status;
                    if old == EV_REVOKED {
                        continue;
                    }
                    let contiguous = match &self.entries[e as usize].body {
                        Body::Evidence(ev) => ev.has_contiguous_chunks(&self.docs[doc_id].chunks),
                        _ => true,
                    };
                    let new = if contiguous { EV_ACTIVE } else { EV_STALE };
                    if new != old {
                        self.set_ev_status(e, new);
                        if new == EV_STALE {
                            lost.push(e);
                        } else {
                            gained.push(e);
                        }
                    }
                }
                let mut rep = if lost.is_empty() { DredReport::default() } else { self.dred(&lost) };
                let mut seeds = Vec::new();
                for &e in &gained {
                    seeds.extend(self.entries[e as usize].used_by.iter().copied());
                }
                rep.restored_by_forward = self.forward(seeds);
                rep.full_recompute = self.finalize();
                Ok(Applied { dred: Some(rep), ..Default::default() })
            }
        }
    }

    // ------------------------------------------------------------------ commitments

    pub fn root(&mut self) -> Hash {
        for b in 0..BUCKETS {
            if self.dirty[b] {
                let mut leaves: Vec<(Hash, u8)> = self.buckets[b].iter().map(|&i| (self.entries[i as usize].id, self.entries[i as usize].status)).collect();
                leaves.sort();
                self.bucket_hashes[b] = bucket_hash(&leaves);
                self.dirty[b] = false;
            }
        }
        root_from_buckets(&self.bucket_hashes, &self.genesis_meta())
    }

    /// Bytes of the genesis commitment folded into the state root.
    pub fn genesis_meta(&self) -> Vec<u8> {
        match &self.genesis {
            None => Vec::new(),
            Some((h, c)) => {
                let mut m = h.to_vec();
                for v in [c.0, c.1, c.2, c.3] {
                    m.extend_from_slice(&v.to_le_bytes());
                }
                m
            }
        }
    }

    pub fn bucket_hashes(&mut self) -> Vec<Hash> {
        let _ = self.root();
        self.bucket_hashes.clone()
    }

    /// LFP stage ranks: 0 for active evidence, 1 for assertions, `1 + max(premise rank)` for
    /// derivations; a claim takes the minimum over its active justifications.
    fn ranks(&self) -> Vec<u32> {
        let n = self.entries.len();
        let mut rank = vec![u32::MAX; n];
        let mut need: Vec<u32> = vec![0; n];
        let mut q: VecDeque<u32> = VecDeque::new();
        for (i, e) in self.entries.iter().enumerate() {
            match &e.body {
                Body::Evidence(_) if e.status == EV_ACTIVE => rank[i] = 0,
                Body::Derivation { premises, .. } => need[i] = premises.len() as u32,
                _ => {}
            }
        }
        for (i, e) in self.entries.iter().enumerate() {
            if let Body::Assertion { claim, ev } = &e.body {
                if self.entries[*ev as usize].status == EV_ACTIVE {
                    rank[i] = 1;
                    if rank[*claim as usize] == u32::MAX && self.entries[*claim as usize].status != ST_UNSUPPORTED {
                        rank[*claim as usize] = 1;
                        if self.entries[*claim as usize].status == ST_SUPPORTED {
                            q.push_back(*claim);
                        }
                    }
                }
            }
        }
        while let Some(c) = q.pop_front() {
            let rc = rank[c as usize];
            for &j in &self.entries[c as usize].used_by {
                need[j as usize] -= 1;
                if need[j as usize] == 0 {
                    if let Body::Derivation { claim, .. } = &self.entries[j as usize].body {
                        if self.entries[j as usize].status != J_ACTIVE {
                            continue;
                        }
                        rank[j as usize] = rc + 1;
                        let cl = *claim as usize;
                        if rank[cl] == u32::MAX && self.entries[cl].status != ST_UNSUPPORTED {
                            rank[cl] = rc + 1;
                            if self.entries[cl].status == ST_SUPPORTED {
                                q.push_back(*claim);
                            }
                        }
                    }
                }
            }
        }
        rank
    }

    /// Every node with its kind, status and canonical payload, in insertion order, without computing the Merkle root
    /// or the LFP ranks (read-only view for the directive emitter; `rank` is 0 and `adj` is empty).
    pub fn records_unranked(&self) -> Vec<Record> {
        self.entries
            .iter()
            .map(|e| {
                let (kind, payload) = match &e.body {
                    Body::Evidence(ev) => (KIND_EVIDENCE, ev.encode()),
                    Body::Claim(c) => (KIND_CLAIM, c.encode()),
                    Body::Assertion { claim, ev } => (KIND_ASSERTION, encode_assertion(&self.entries[*claim as usize].id, &self.entries[*ev as usize].id)),
                    Body::Derivation { rule, claim, premises } => {
                        let ps: Vec<Hash> = premises.iter().map(|&p| self.entries[p as usize].id).collect();
                        (KIND_DERIVATION, encode_derivation(rule, &self.entries[*claim as usize].id, &ps))
                    }
                };
                Record { id: e.id, kind, status: e.status, rank: 0, payload, adj: Vec::new() }
            })
            .collect()
    }

    /// Every node with its status, borrowed, in insertion order (no payload encoding, no Merkle root, no ranks): what the
    /// resident directive compiler reads every round.
    pub fn node_views(&self) -> impl Iterator<Item = (&Hash, u8, NodeView<'_>)> + '_ {
        self.entries.iter().map(move |e| {
            let v = match &e.body {
                Body::Evidence(ev) => NodeView::Evidence(ev),
                Body::Claim(c) => NodeView::Claim(c),
                Body::Assertion { claim, ev } => NodeView::Assertion { claim: &self.entries[*claim as usize].id, evidence: &self.entries[*ev as usize].id },
                Body::Derivation { rule, claim, .. } => NodeView::Derivation { rule, claim: &self.entries[*claim as usize].id },
            };
            (&e.id, e.status, v)
        })
    }

    /// Minimal-support-cone reader over the live engine (ranks and the entity index are computed once per state).
    pub fn cone_reader(&self) -> ConeReader<'_> {
        let mut by_entity: FxMap<&str, Vec<u32>> = FxMap::default();
        for (i, e) in self.entries.iter().enumerate() {
            if let Body::Claim(c) = &e.body {
                by_entity.entry(c.s.as_str()).or_default().push(i as u32);
                if c.o != c.s {
                    by_entity.entry(c.o.as_str()).or_default().push(i as u32);
                }
            }
        }
        ConeReader { eng: self, ranks: self.ranks(), by_entity }
    }

    pub fn snapshot(&mut self) -> Snapshot {
        let root = self.root();
        let rank = self.ranks();
        let mut records: Vec<Record> = Vec::with_capacity(self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            let (kind, payload, adj) = match &e.body {
                Body::Evidence(ev) => (KIND_EVIDENCE, ev.encode(), Vec::new()),
                Body::Claim(c) => {
                    let mut adj: Vec<Hash> = e.supports.iter().map(|&j| self.entries[j as usize].id).collect();
                    adj.sort();
                    (KIND_CLAIM, c.encode(), adj)
                }
                Body::Assertion { claim, ev } => {
                    (KIND_ASSERTION, encode_assertion(&self.entries[*claim as usize].id, &self.entries[*ev as usize].id), Vec::new())
                }
                Body::Derivation { rule, claim, premises } => {
                    let ps: Vec<Hash> = premises.iter().map(|&p| self.entries[p as usize].id).collect();
                    (KIND_DERIVATION, encode_derivation(rule, &self.entries[*claim as usize].id, &ps), Vec::new())
                }
            };
            records.push(Record { id: e.id, kind, status: e.status, rank: rank[i], payload, adj });
        }
        records.sort_by_key(|a| (a.rank, a.id));
        Snapshot { records, bucket_hashes: self.bucket_hashes.clone(), root }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Seg;

    fn ev(doc: &str, n: u8) -> EvidenceNode {
        EvidenceNode { doc_id: doc.into(), quote_hash: [n; 32], quote_len: 4, segs: vec![Seg { chunk: [n; 32], start: 0, end: 4 }] }
    }

    fn claim(s: &str, p: &str, o: &str, pol: Polarity, t: (i64, i64)) -> Claim {
        Claim { s: s.into(), p: p.into(), o: o.into(), pol, ctx: "prod".into(), t_from: t.0, t_to: t.1 }
    }

    fn bind(e: &mut Engine, ev: EvidenceNode) {
        let v = e.doc_version(&ev.doc_id).unwrap_or([0; 32]);
        e.apply(&CanonOp::BindEvidence { doc_version: v, ev }).unwrap();
    }

    fn put(e: &mut Engine, doc: &str, chunks: &[u8]) {
        let chunks: Vec<[u8; 32]> = chunks.iter().map(|n| [*n; 32]).collect();
        e.apply(&CanonOp::DocPut { doc_id: doc.into(), version: crate::arena::version_id_of(&chunks), chunks }).unwrap();
    }

    #[test]
    fn dred_keeps_alternative_support_and_drops_cycles() {
        let mut e = Engine::new();
        put(&mut e, "d", &[1, 2]);
        let e1 = ev("d", 1);
        let e2 = ev("d", 2);
        bind(&mut e, e1.clone());
        bind(&mut e, e2.clone());
        let a = claim("a", "p", "x", Polarity::Pos, (0, 10));
        let b = claim("b", "p", "x", Polarity::Pos, (0, 10));
        let c = claim("c", "p", "x", Polarity::Pos, (0, 10));
        e.apply(&CanonOp::Assert { claim: a.clone(), evidence: vec![e1.id()] }).unwrap();
        // b <- a ; c <- b ; and a <- c (cycle), plus c also asserted by e2 (backup)
        e.apply(&CanonOp::Derive { claim: b.clone(), justs: vec![("R".into(), vec![a.id()])] }).unwrap();
        e.apply(&CanonOp::Derive { claim: c.clone(), justs: vec![("R".into(), vec![b.id()])] }).unwrap();
        e.apply(&CanonOp::Derive { claim: a.clone(), justs: vec![("R".into(), vec![c.id()])] }).unwrap();
        e.apply(&CanonOp::Assert { claim: c.clone(), evidence: vec![e2.id()] }).unwrap();
        assert!(e.oracle_check());
        assert_eq!(e.status_of(&c.id()), Some(ST_SUPPORTED));
        // revoke primary: a is still supported via cycle a<-c<-e2 (c has backup), everything stays
        e.apply(&CanonOp::Revoke { evidence: e1.id() }).unwrap();
        assert!(e.oracle_check());
        assert_eq!(e.status_of(&a.id()), Some(ST_SUPPORTED));
        assert_eq!(e.status_of(&b.id()), Some(ST_SUPPORTED));
        // revoke backup: the cycle must not sustain itself
        let r = e.apply(&CanonOp::Revoke { evidence: e2.id() }).unwrap();
        assert!(e.oracle_check());
        for x in [&a, &b, &c] {
            assert_eq!(e.status_of(&x.id()), Some(ST_UNSUPPORTED));
        }
        assert!(r.dred.unwrap().net_removed >= 3);
    }

    #[test]
    fn evidence_of_an_unknown_document_waits_for_its_chunk_window() {
        // without the document's ordered chunks the engine cannot confirm continuity: the evidence is kept, but STALE
        let mut e = Engine::new();
        let x = ev("d", 1);
        bind(&mut e, x.clone());
        assert_eq!(e.status_of(&x.id()), Some(EV_STALE));
        let c = claim("svc", "ok", "yes", Polarity::Pos, (0, 10));
        e.apply(&CanonOp::Assert { claim: c.clone(), evidence: vec![x.id()] }).unwrap();
        assert_eq!(e.status_of(&c.id()), Some(ST_UNSUPPORTED));
        // a document whose chunks contain the window activates it, and the assertion gains support
        put(&mut e, "d", &[7, 1, 9]);
        assert_eq!(e.status_of(&x.id()), Some(EV_ACTIVE));
        assert_eq!(e.status_of(&c.id()), Some(ST_SUPPORTED));
        assert!(e.oracle_check());
    }

    #[test]
    fn names_with_nul_do_not_share_a_conflict_group() {
        let mut e = Engine::new();
        put(&mut e, "d", &[1, 2]);
        let evs: Vec<_> = (1..=2).map(|n| ev("d", n)).collect();
        for x in &evs {
            bind(&mut e, x.clone());
        }
        // ("a\0b", "c") and ("a", "b\0c") joined with NUL separators give the same bytes; they are different claims
        let pos = Claim { s: "a\0b".into(), p: "c".into(), o: "d".into(), pol: Polarity::Pos, ctx: "e".into(), t_from: 0, t_to: 10 };
        let neg = Claim { s: "a".into(), p: "b\0c".into(), o: "d".into(), pol: Polarity::Neg, ctx: "e".into(), t_from: 0, t_to: 10 };
        e.apply(&CanonOp::Assert { claim: pos.clone(), evidence: vec![evs[0].id()] }).unwrap();
        e.apply(&CanonOp::Assert { claim: neg.clone(), evidence: vec![evs[1].id()] }).unwrap();
        assert!(e.oracle_check());
        assert_eq!((e.status_of(&pos.id()), e.status_of(&neg.id())), (Some(ST_SUPPORTED), Some(ST_SUPPORTED)));
    }

    #[test]
    fn conflicts_block_downstream() {
        let mut e = Engine::new();
        put(&mut e, "d", &[1, 2, 3]);
        let evs: Vec<_> = (1..=3).map(|n| ev("d", n)).collect();
        for x in &evs {
            bind(&mut e, x.clone());
        }
        let pos = claim("svc", "ok", "yes", Polarity::Pos, (0, 100));
        let neg = claim("svc", "ok", "yes", Polarity::Neg, (50, 150));
        let down = claim("svc", "flag", "yes", Polarity::Pos, (0, 100));
        e.apply(&CanonOp::Assert { claim: pos.clone(), evidence: vec![evs[0].id()] }).unwrap();
        e.apply(&CanonOp::Derive { claim: down.clone(), justs: vec![("R".into(), vec![pos.id()])] }).unwrap();
        assert_eq!(e.status_of(&down.id()), Some(ST_SUPPORTED));
        e.apply(&CanonOp::Assert { claim: neg.clone(), evidence: vec![evs[1].id()] }).unwrap();
        assert!(e.oracle_check());
        assert_eq!(e.status_of(&pos.id()), Some(ST_CONFLICTING));
        assert_eq!(e.status_of(&neg.id()), Some(ST_CONFLICTING));
        assert_eq!(e.status_of(&down.id()), Some(ST_UNSUPPORTED), "derivations from a conflicting pair are blocked");
        // revoking the NEG evidence resolves the conflict and restores the consequence
        e.apply(&CanonOp::Revoke { evidence: evs[1].id() }).unwrap();
        assert!(e.oracle_check());
        assert_eq!(e.status_of(&pos.id()), Some(ST_SUPPORTED));
        assert_eq!(e.status_of(&down.id()), Some(ST_SUPPORTED));
    }

    #[test]
    fn root_is_order_independent() {
        let build = |order: &[usize]| {
            let mut e = Engine::new();
            put(&mut e, "d", &[1, 2, 3]);
            let evs: Vec<_> = (1..=3).map(|n| ev("d", n)).collect();
            for x in &evs {
                bind(&mut e, x.clone());
            }
            let cs = [claim("a", "p", "1", Polarity::Pos, (0, 9)), claim("b", "p", "1", Polarity::Pos, (0, 9)), claim("c", "p", "1", Polarity::Pos, (0, 9))];
            for &i in order {
                e.apply(&CanonOp::Assert { claim: cs[i].clone(), evidence: vec![evs[i].id()] }).unwrap();
            }
            e.root()
        };
        assert_eq!(build(&[0, 1, 2]), build(&[2, 0, 1]));
    }

    #[test]
    fn doc_update_marks_evidence_stale_and_recovers() {
        let mut e = Engine::new();
        put(&mut e, "d", &[1, 2]);
        let e1 = ev("d", 1);
        bind(&mut e, e1.clone());
        let a = claim("a", "p", "1", Polarity::Pos, (0, 9));
        e.apply(&CanonOp::Assert { claim: a.clone(), evidence: vec![e1.id()] }).unwrap();
        put(&mut e, "d", &[2, 9]);
        assert_eq!(e.status_of(&e1.id()), Some(EV_STALE));
        assert_eq!(e.status_of(&a.id()), Some(ST_UNSUPPORTED));
        put(&mut e, "d", &[1, 2]);
        assert_eq!(e.status_of(&a.id()), Some(ST_SUPPORTED));
        assert!(e.oracle_check());
    }
}
