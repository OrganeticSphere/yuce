//! Asynchronous swarm dispatcher (Addendum v0.3.1, EXP-10).
//!
//! `emit_batch` hands out the work of one synchronous round: every seat gets its frame from the same state and the next round
//! starts only when the slowest seat has answered. `SwarmSession` replaces the round barrier with individual TTL leases on a
//! live session:
//!
//! * `acquire_directive` analyses the current state (`analyze_cached`, the resident `DirectiveCache`), drops every gap whose
//!   resources are held by an active lease and packs the most urgent free target into one frame (`frame_for`, the same
//!   packing as a round's frame, with the local-id prefix `l{lease_seq}_`). The lease locks the gap's target, its source
//!   sentences (amendment sentences excepted, as in `emit_batch`), its nodes and - the shared-premise lock - the premise it
//!   will establish, e.g. `(api_000, api_deprecated)` for an `EXTRACT_PARTNER` on the shared clause `D.0`. Two leases never
//!   hold the same target, sentence or premise; a worker that finds every open gap locked gets `WAIT_IN_FLIGHT`.
//! * `submit_directive` checks that the lease is still alive (TTL, `expire_stale`), that the premises it was issued against are
//!   still SUPPORTED and that no fresh erratum withdrew its sentences (`STALE_LEASE`), then runs the events through the
//!   lease's `ScopeContract` (the directive scope guard of the EXP-9 harness, now in the kernel) and `Session::apply_line`,
//!   fail-fast with the accepted prefix kept and one repair attempt per lease.
//! * with `auto_close_p2a` the kernel itself applies every ready Horn derivation (`EMIT_DERIVE_ONLY`, P2A) after each commit,
//!   document update and before each acquire, so no worker is ever called for a derive the kernel can compute; a derivation
//!   whose conclusion belongs to a target held by an active lease waits until that lease closes.
//!
//! Time is the caller's `now_ms` when given (deterministic simulations), else milliseconds since the session was created.
//! Every decision is deterministic for a given sequence of calls.

use crate::directive::{
    analyze_cached, cone_claim_ids, emit_batch_frames_live, field_of, frame_for, joins_between, Analysis, Assignment, DirectiveCache, FrameSlot, FrontierGap,
    Priority, ReadyDerivation, Targets,
};
use crate::hash::{short, to_hex, Hash};
use crate::journal::{self, Journal};
use crate::merkle::{FxSet, IdSet};
use crate::node::*;
use crate::session::{Session, MAX_STR};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::time::Instant;

const FACT_KINDS: [&str; 4] = ["FORMALIZE", "EXTRACT_PARTNER", "RESUPPORT_FROM_RESTATEMENT", "REPAIR_UNSUPPORTED"];
const VALID_OPS: [&str; 4] = ["bind_evidence", "assert_fact", "derive", "revoke_evidence"];

fn us(t: Instant) -> f64 {
    t.elapsed().as_nanos() as f64 / 1e3
}

// ------------------------------------------------------------------------------------------ configuration

/// What a lease locks besides its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Only the target entity (sharding by target, as a naive dispatcher would do).
    TargetOnly,
    /// Target + non-amendment source sentences + gap nodes + the premise a gap establishes (`LockedSegment + LockedPremiseKey`).
    SharedPremise,
}

impl LockMode {
    pub fn name(self) -> &'static str {
        match self {
            LockMode::TargetOnly => "target_only",
            LockMode::SharedPremise => "shared_premise",
        }
    }

    pub fn parse(s: &str) -> Option<LockMode> {
        match s {
            "target_only" | "target" => Some(LockMode::TargetOnly),
            "shared_premise" | "premise" | "full" => Some(LockMode::SharedPremise),
            _ => None,
        }
    }
}

/// The model class of the worker asking for work (EXP-12 tier routing). `Standard`, the default, takes any work as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkerTier {
    FastCheap,
    Standard,
    HeavyReasoner,
}

impl WorkerTier {
    pub fn name(self) -> &'static str {
        match self {
            WorkerTier::FastCheap => "fast_cheap",
            WorkerTier::Standard => "standard",
            WorkerTier::HeavyReasoner => "heavy_reasoner",
        }
    }

    pub fn parse(s: &str) -> Option<WorkerTier> {
        match s {
            "fast_cheap" | "fast" => Some(WorkerTier::FastCheap),
            "standard" => Some(WorkerTier::Standard),
            "heavy_reasoner" | "heavy" => Some(WorkerTier::HeavyReasoner),
            _ => None,
        }
    }
}

/// Work a `fast_cheap` worker leaves to a live `heavy_reasoner`: document amendments and conflicts (P0, revocation, re-support,
/// repair of an unsupported conclusion) and clauses that may contradict each other. Repairs inside a lease stay with its holder.
pub fn heavy_work(g: &FrontierGap) -> bool {
    g.priority == Priority::P0ResolvePolarConflict
        || matches!(g.kind, "REVOKE_WITHDRAWN" | "RESOLVE_CONFLICT" | "RESUPPORT_FROM_RESTATEMENT" | "REPAIR_UNSUPPORTED")
        || (g.kind == "FORMALIZE" && g.may_conflict)
}

#[derive(Debug, Clone)]
pub struct SwarmConfig {
    pub auto_close_p2a: bool,
    pub lock: LockMode,
    /// Top a lease up with further whole free targets while its event budget lasts (pass 2 of `emit_batch`).
    pub pack_multi_target: bool,
    pub default_ttl_ms: u64,
    pub default_k: usize,
    /// A `heavy_reasoner` counts as alive while it holds a lease or asked for work within this many ms; only then do
    /// `fast_cheap` workers skip `heavy_work` (otherwise the swarm would stall when the reasoner is gone).
    pub heavy_alive_ms: u64,
}

impl Default for SwarmConfig {
    fn default() -> SwarmConfig {
        SwarmConfig {
            auto_close_p2a: true,
            lock: LockMode::SharedPremise,
            pack_multi_target: false,
            default_ttl_ms: 30_000,
            default_k: 4,
            heavy_alive_ms: 60_000,
        }
    }
}

impl SwarmConfig {
    pub fn to_json(&self) -> Value {
        json!({"auto_close_p2a": self.auto_close_p2a, "lock_mode": self.lock.name(), "pack_multi_target": self.pack_multi_target,
               "default_ttl_ms": self.default_ttl_ms, "default_k": self.default_k, "heavy_alive_ms": self.heavy_alive_ms})
    }
}

// ------------------------------------------------------------------------------------------ scope contract

/// What a lease allows (the directive scope guard of the EXP-9 harness, `contract_of` / `contract_violation`).
#[derive(Debug, Clone, Default)]
pub struct ScopeContract {
    pub allowed_ops: FxSet<String>,
    /// Non-amendment sentences of the frame's source slice: a quote must be taken from one of them.
    pub allowed_quotes: Vec<String>,
    /// Short ids of the evidence the gaps list for revocation.
    pub allowed_revokes: FxSet<String>,
    /// Supported premises the directive builds on (partner premises, premises of a ready derivation).
    pub required_premises: Vec<Hash>,
}

impl ScopeContract {
    fn of(a: &Analysis<'_>, gaps: &[&FrontierGap]) -> ScopeContract {
        let mut c = ScopeContract::default();
        let mut seen: Vec<usize> = Vec::new();
        for g in gaps {
            if FACT_KINDS.contains(&g.kind) {
                c.allowed_ops.extend(["bind_evidence", "assert_fact", "derive"].map(String::from));
            } else if g.kind == "EMIT_DERIVE_ONLY" {
                c.allowed_ops.insert("derive".into());
            } else if g.kind == "REVOKE_WITHDRAWN" || g.kind == "RESOLVE_CONFLICT" {
                c.allowed_ops.insert("revoke_evidence".into());
                c.allowed_revokes.extend(g.nodes.iter().filter(|n| a.ev(n).is_some()).map(short));
            }
            if let Some((_, p)) = &g.partner {
                c.required_premises.push(*p);
            }
            if let Some(d) = &g.derive {
                c.required_premises.extend(d.premises.iter().copied());
            }
            for s in &g.segments {
                if !seen.contains(s) {
                    seen.push(*s);
                    if !a.segments[*s].amendment {
                        c.allowed_quotes.push(a.segments[*s].text.clone());
                    }
                }
            }
        }
        c.required_premises.sort();
        c.required_premises.dedup();
        c
    }

    /// Why the event is outside the directive (None: allowed). Unknown ops are left to the kernel (UNKNOWN_OP).
    pub fn violation(&self, ev: &Map<String, Value>) -> Option<String> {
        let op = ev.get("op").and_then(|x| x.as_str()).unwrap_or("");
        if !VALID_OPS.contains(&op) {
            return None;
        }
        if !self.allowed_ops.contains(op) {
            return Some(format!("this directive does not ask for '{op}' events"));
        }
        if op == "bind_evidence" {
            let q = ev.get("exact_quote").and_then(|x| x.as_str()).unwrap_or("");
            if q.is_empty() || !self.allowed_quotes.iter().any(|t| t.contains(q)) {
                return Some("the quote is not taken from the directive's source slice".into());
            }
        }
        if op == "revoke_evidence" {
            let t = ev.get("target_evidence").and_then(|x| x.as_str()).unwrap_or("").trim_start_matches('@');
            if t.len() < 8 || !self.allowed_revokes.iter().any(|r| r.starts_with(t) || t.starts_with(r.as_str())) {
                return Some("this evidence is not listed for revocation by the directive".into());
            }
        }
        None
    }

    pub fn to_json(&self) -> Value {
        let mut ops: Vec<&String> = self.allowed_ops.iter().collect();
        ops.sort();
        let mut rev: Vec<&String> = self.allowed_revokes.iter().collect();
        rev.sort();
        json!({"allowed_ops": ops, "allowed_quotes": self.allowed_quotes, "allowed_revokes": rev,
               "required_premises": self.required_premises.iter().map(|p| format!("@{}", short(p))).collect::<Vec<_>>()})
    }
}

// ------------------------------------------------------------------------------------------ leases

/// Resources held by a lease (or needed by a gap).
#[derive(Debug, Clone, Default)]
pub struct Locks {
    pub targets: FxSet<String>,
    pub segments: FxSet<String>,
    pub nodes: IdSet,
    pub premises: FxSet<(String, String)>,
}

impl Locks {
    fn absorb(&mut self, o: &Locks) {
        self.targets.extend(o.targets.iter().cloned());
        self.segments.extend(o.segments.iter().cloned());
        self.nodes.extend(o.nodes.iter().copied());
        self.premises.extend(o.premises.iter().cloned());
    }

    /// Would a gap needing `need` collide with these locks? (`derive_only`: a ready derivation shares its premise nodes freely.)
    fn blocks(&self, need: &Locks, mode: LockMode, derive_only: bool) -> bool {
        if need.targets.iter().any(|t| self.targets.contains(t)) {
            return true;
        }
        if mode == LockMode::TargetOnly {
            return false;
        }
        need.segments.iter().any(|s| self.segments.contains(s))
            || (!derive_only && need.nodes.iter().any(|n| self.nodes.contains(n)))
            || need.premises.iter().any(|p| self.premises.contains(p))
    }
}

#[derive(Debug, Clone)]
pub struct ActiveLease {
    pub lease_id: String,
    pub seq: u64,
    pub local_id_prefix: String,
    pub directive_id: String,
    pub agent_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub k: usize,
    pub max_events: usize,
    pub targets: Vec<String>,
    pub gaps: Vec<FrontierGap>,
    pub frame: Value,
    pub locks: Locks,
    /// Source sentences the lease states facts from: a fresh erratum that withdraws one makes the lease stale.
    pub fact_segments: Vec<String>,
    pub contract: ScopeContract,
    pub repair_used: bool,
    pub accepted_events: usize,
    pub doc_epoch: u64,
    pub tier: WorkerTier,
}

impl ActiveLease {
    fn brief(&self) -> Value {
        let mut segs: Vec<&String> = self.locks.segments.iter().collect();
        segs.sort();
        let mut prem: Vec<String> = self.locks.premises.iter().map(|(e, p)| format!("{p}({e})")).collect();
        prem.sort();
        json!({"lease_id": self.lease_id, "agent_id": self.agent_id, "directive_id": self.directive_id, "kind": self.frame["kind"],
               "targets": self.targets, "issued_at_ms": self.issued_at_ms, "expires_at_ms": self.expires_at_ms,
               "locked_segments": segs, "locked_premises": prem, "repair_used": self.repair_used, "accepted_events": self.accepted_events,
               "tier": self.tier.name()})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SwarmStats {
    pub leases_issued: u64,
    pub leases_committed: u64,
    pub leases_expired: u64,
    pub leases_failed: u64,
    pub leases_released: u64,
    pub stale_unknown: u64,
    pub stale_premise: u64,
    pub stale_segment: u64,
    pub repair_required: u64,
    pub directive_violations: u64,
    pub events_accepted: u64,
    pub events_rejected: u64,
    pub auto_closed_total: u64,
    pub auto_close_errors: u64,
    pub ttl_takeovers: u64,
    pub renewals: u64,
    pub wait_responses: u64,
    pub complete_responses: u64,
    pub issued_by_kind: BTreeMap<String, u64>,
    pub issued_by_tier: BTreeMap<String, u64>,
    /// `tier/kind` of the first gap of each lease issued.
    pub issued_by_tier_kind: BTreeMap<String, u64>,
    /// Acquire calls of a `fast_cheap` worker that left at least one `heavy_work` gap to a live `heavy_reasoner`.
    pub tier_skips: u64,
}

impl SwarmStats {
    pub fn to_json(&self) -> Value {
        json!({
            "leases_issued": self.leases_issued, "leases_committed": self.leases_committed, "leases_expired": self.leases_expired,
            "leases_failed": self.leases_failed, "leases_released": self.leases_released,
            "stale_unknown": self.stale_unknown, "stale_premise": self.stale_premise, "stale_segment": self.stale_segment,
            "repair_required": self.repair_required, "directive_violations": self.directive_violations,
            "events_accepted": self.events_accepted, "events_rejected": self.events_rejected,
            "auto_closed_total": self.auto_closed_total, "auto_close_errors": self.auto_close_errors,
            "ttl_takeovers": self.ttl_takeovers, "renewals": self.renewals,
            "wait_responses": self.wait_responses, "complete_responses": self.complete_responses,
            "issued_by_kind": self.issued_by_kind, "issued_by_tier": self.issued_by_tier, "tier_skips": self.tier_skips,
            "issued_by_tier_kind": self.issued_by_tier_kind,
        })
    }
}

// ------------------------------------------------------------------------------------------ auto-closure (P2A)

fn ready_of(a: &Analysis<'_>, skip_targets: &FxSet<String>, bad: &IdSet) -> Vec<ReadyDerivation> {
    a.gaps
        .iter()
        .filter(|g| g.kind == "EMIT_DERIVE_ONLY" && !skip_targets.contains(&g.target))
        .filter_map(|g| g.derive.clone())
        .filter(|d| !bad.contains(&d.head.id()))
        .collect()
}

fn apply_ready(s: &mut Session, ready: Vec<ReadyDerivation>, out: &mut Vec<Value>, bad: &mut IdSet, stats: &mut SwarmStats) {
    for d in ready {
        let seq = s.last_seq + 1;
        let premises: Vec<String> = d.premises.iter().map(|p| format!("@{}", short(p))).collect();
        let line = json!({"seq": seq, "op": "derive", "local_id": format!("k{seq}_auto"), "rule": d.rule, "premises": premises});
        match s.apply_line(&line.to_string()) {
            Ok(_) => {
                stats.auto_closed_total += 1;
                let h = &d.head;
                out.push(json!({"target": h.s, "rule": d.rule, "claim_id": format!("@{}", short(&h.id())), "seq": seq,
                                "claim": {"s": h.s, "p": h.p, "o": h.o, "polarity": h.pol.as_str(), "ctx": h.ctx}, "t": [h.t_from, h.t_to],
                                "premises": premises}));
            }
            Err(_) => {
                stats.auto_close_errors += 1;
                bad.insert(d.head.id());
            }
        }
    }
}

fn auto_close_with(s: &mut Session, cache: &mut DirectiveCache, targets: &Targets, skip_targets: &FxSet<String>, stats: &mut SwarmStats) -> Vec<Value> {
    let mut out = Vec::new();
    let mut bad = IdSet::default();
    // a derived conclusion can be the premise of another rule: repeat until nothing is ready
    for _ in 0..64 {
        let ready = ready_of(&analyze_cached(s, targets, cache), skip_targets, &bad);
        if ready.is_empty() {
            break;
        }
        apply_ready(s, ready, &mut out, &mut bad, stats);
    }
    out
}

/// Kernel auto-closure of P2A: apply every ready Horn derivation (`EMIT_DERIVE_ONLY`) of `targets` to `s` through
/// `Session::apply_line`, until none is left. Returns the closed derivations (`target`, `rule`, `claim_id`, `t`, ...).
pub fn auto_close_ready(s: &mut Session, cache: &mut DirectiveCache, targets: &Targets) -> Vec<Value> {
    auto_close_with(s, cache, targets, &FxSet::default(), &mut SwarmStats::default())
}

/// The premise a gap establishes, as (entity, predicate): the missing partner premise of an `EXTRACT_PARTNER`, the claim a
/// resupport / repair states again.
fn premise_key(a: &Analysis<'_>, s: &Session, g: &FrontierGap) -> Option<(String, String)> {
    match g.kind {
        "EXTRACT_PARTNER" => {
            let (rule_id, cid) = g.partner.as_ref()?;
            let rule = s.ontology.rules.get(rule_id)?;
            let c = a.claim(cid)?.claim;
            let i = (0..rule.body.len().min(2)).find(|&i| rule.body[i].p == c.p && rule.body[i].pol == c.pol)?;
            let j = 1 - i;
            let (fi, _) = *joins_between(rule, i, j).first()?;
            Some((field_of(c, fi).to_string(), rule.body[j].p.clone()))
        }
        "RESUPPORT_FROM_RESTATEMENT" | "REPAIR_UNSUPPORTED" => g.resupport.as_ref().map(|c| (c.s.clone(), c.p.clone())),
        _ => None,
    }
}

fn gap_locks(a: &Analysis<'_>, s: &Session, g: &FrontierGap) -> Locks {
    let mut l = Locks::default();
    l.targets.insert(g.target.clone());
    for &i in &g.segments {
        if !a.segments[i].amendment {
            l.segments.insert(a.segments[i].id.clone());
        }
    }
    l.nodes.extend(g.nodes.iter().copied());
    if let Some(d) = &g.derive {
        l.nodes.insert(d.head.id());
    }
    if let Some(k) = premise_key(a, s, g) {
        l.premises.insert(k);
    }
    l
}

// ------------------------------------------------------------------------------------------ the swarm session

pub struct SwarmSession {
    pub session: Session,
    pub cache: DirectiveCache,
    pub targets: Option<Targets>,
    pub cfg: SwarmConfig,
    pub stats: SwarmStats,
    leases: BTreeMap<u64, ActiveLease>,
    pub(crate) lease_seq: u64,
    pub(crate) doc_epoch: u64,
    /// Targets of expired leases not issued again yet (to count TTL takeovers).
    expired_targets: FxSet<String>,
    started: Instant,
    /// Persistent session log (`--wal-path`); see `crate::journal`.
    pub(crate) journal: Option<Journal>,
    /// The last COMPLETE this server answered: which document epoch and root it was for, and its number (a server-side witness
    /// that a worker asked and was told COMPLETE after a given document update).
    last_complete: Option<Value>,
    /// When each `heavy_reasoner` last asked for work (server ms).
    heavy_seen_ms: BTreeMap<String, u64>,
}

fn parse_lease(id: &str) -> Option<u64> {
    id.strip_prefix('L')?.parse().ok()
}

fn err(code: &str, message: impl Into<String>) -> Value {
    json!({"status": "error", "code": code, "message": message.into()})
}

impl SwarmSession {
    pub fn new(session: Session) -> SwarmSession {
        SwarmSession {
            session,
            cache: DirectiveCache::new(),
            targets: None,
            cfg: SwarmConfig::default(),
            stats: SwarmStats::default(),
            leases: BTreeMap::new(),
            lease_seq: 0,
            doc_epoch: 0,
            expired_targets: FxSet::default(),
            started: Instant::now(),
            journal: None,
            last_complete: None,
            heavy_seen_ms: BTreeMap::new(),
        }
    }

    pub fn now(&self, now_ms: Option<u64>) -> u64 {
        now_ms.unwrap_or_else(|| self.started.elapsed().as_millis() as u64)
    }

    pub fn active_leases(&self) -> impl Iterator<Item = &ActiveLease> {
        self.leases.values()
    }

    /// Expiry time (the session clock, ms) of the lease that runs out first: when nothing else happens, work comes free then.
    pub fn next_expiry_ms(&self) -> Option<u64> {
        self.leases.values().map(|l| l.expires_at_ms).min()
    }

    pub fn set_targets(&mut self, targets: Targets) {
        self.targets = Some(targets);
        self.log_targets();
    }

    fn log_targets(&mut self) {
        if let (Some(j), Some(t)) = (self.session.journal.as_mut(), self.targets.as_ref()) {
            j.push(journal::targets_record(t, &self.cfg));
        }
    }

    /// Apply the swarm options present in `v` (`auto_close_p2a`, `lock_mode`, `pack_multi_target`, `default_ttl_ms`,
    /// `default_k`); absent ones keep their value. Nothing changes when an option is invalid.
    pub fn configure(&mut self, v: &Value) -> Result<(), Value> {
        let mut cfg = self.cfg.clone();
        if let Some(b) = v.get("auto_close_p2a").and_then(|x| x.as_bool()) {
            cfg.auto_close_p2a = b;
        }
        if let Some(m) = v.get("lock_mode").and_then(|x| x.as_str()) {
            cfg.lock = LockMode::parse(m).ok_or_else(|| err("BAD_LOCK_MODE", "lock_mode must be shared_premise or target_only"))?;
        }
        if let Some(b) = v.get("pack_multi_target").and_then(|x| x.as_bool()) {
            cfg.pack_multi_target = b;
        }
        if let Some(x) = v.get("default_ttl_ms").and_then(|x| x.as_u64()) {
            cfg.default_ttl_ms = x.max(1);
        }
        if let Some(x) = v.get("default_k").and_then(|x| x.as_u64()) {
            cfg.default_k = (x as usize).max(1);
        }
        if let Some(x) = v.get("heavy_alive_ms").and_then(|x| x.as_u64()) {
            cfg.heavy_alive_ms = x;
        }
        self.cfg = cfg;
        Ok(())
    }

    /// The session log this swarm persists to, if any.
    pub fn journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    /// Append the queued session-log records and `sync_data` them (a no-op without a log). A resident server calls this
    /// before it answers, so an acknowledged mutation survives a crash.
    pub fn sync_wal(&mut self) -> std::io::Result<()> {
        let (Some(j), Some(q)) = (self.journal.as_mut(), self.session.journal.as_mut()) else { return Ok(()) };
        let recs = std::mem::take(q);
        j.append(&recs)
    }

    /// Drop every lease whose TTL ran out; its resources return to the pool at once. Returns the expired lease ids.
    pub fn expire_stale(&mut self, now_ms: u64) -> Vec<String> {
        let dead: Vec<u64> = self.leases.iter().filter(|(_, l)| now_ms >= l.expires_at_ms).map(|(q, _)| *q).collect();
        let mut out = Vec::new();
        for q in dead {
            if let Some(l) = self.leases.remove(&q) {
                self.stats.leases_expired += 1;
                self.expired_targets.extend(l.targets.iter().cloned());
                out.push(l.lease_id);
            }
        }
        out
    }

    fn locks(&self) -> Locks {
        let mut l = Locks::default();
        for x in self.leases.values() {
            l.absorb(&x.locks);
        }
        l
    }

    fn run_auto_close(&mut self) -> Vec<Value> {
        if !self.cfg.auto_close_p2a {
            return Vec::new();
        }
        let Some(t) = self.targets.as_ref() else { return Vec::new() };
        let held = self.locks().targets;
        auto_close_with(&mut self.session, &mut self.cache, t, &held, &mut self.stats)
    }

    // -------------------------------------------------------------------------------------- acquire

    /// Lease the most urgent free work to `agent_id` (see the module docs).
    pub fn acquire_directive(&mut self, agent_id: &str, ttl_ms: Option<u64>, k: Option<usize>, now_ms: Option<u64>) -> Value {
        self.acquire_directive_tier(agent_id, WorkerTier::Standard, ttl_ms, k, now_ms)
    }

    /// Whether a `heavy_reasoner` holds a lease or asked for work within `heavy_alive_ms`.
    pub fn heavy_alive(&self, now: u64) -> bool {
        self.leases.values().any(|l| l.tier == WorkerTier::HeavyReasoner)
            || self.heavy_seen_ms.values().any(|&t| now.saturating_sub(t) <= self.cfg.heavy_alive_ms)
    }

    /// `acquire_directive` for a worker of a given tier: a `fast_cheap` worker skips `heavy_work` while a `heavy_reasoner` is
    /// alive, and a `heavy_reasoner` gets targets with `heavy_work` first (then helps with the rest).
    pub fn acquire_directive_tier(&mut self, agent_id: &str, tier: WorkerTier, ttl_ms: Option<u64>, k: Option<usize>, now_ms: Option<u64>) -> Value {
        let t0 = Instant::now();
        let now = self.now(now_ms);
        let expired = self.expire_stale(now);
        if tier == WorkerTier::HeavyReasoner {
            self.heavy_seen_ms.insert(agent_id.to_string(), now);
        }
        let leave_heavy = tier == WorkerTier::FastCheap && self.heavy_alive(now);
        let ttl = ttl_ms.unwrap_or(self.cfg.default_ttl_ms).max(1);
        let k = k.unwrap_or(self.cfg.default_k).max(1);
        let (auto, mode, pack) = (self.cfg.auto_close_p2a, self.cfg.lock, self.cfg.pack_multi_target);
        let locks = self.locks();
        let Some(targets) = self.targets.as_ref() else { return err("NO_TARGETS", "set_targets first") };
        let mut auto_closed: Vec<Value> = Vec::new();
        let mut bad = IdSet::default();
        // auto-closure first; the analysis that finds nothing more to close is the one the lease is cut from
        let a = loop {
            let a = analyze_cached(&self.session, targets, &mut self.cache);
            if !auto {
                break a;
            }
            let ready = ready_of(&a, &locks.targets, &bad);
            if ready.is_empty() {
                break a;
            }
            drop(a);
            apply_ready(&mut self.session, ready, &mut auto_closed, &mut bad, &mut self.stats);
        };
        let analysis_us = a.analysis_us;
        let open_gaps = a.gaps.len();
        if a.gaps.is_empty() && self.leases.is_empty() {
            drop(a);
            self.stats.complete_responses += 1;
            let root = to_hex(&self.session.engine.root());
            self.last_complete = Some(json!({"n": self.stats.complete_responses, "doc_epoch": self.doc_epoch, "state_root": root,
                                             "agent_id": agent_id, "at_ms": now}));
            return json!({"status": "COMPLETE", "complete": true, "state_root": root, "auto_closed": auto_closed,
                          "expired": expired, "analysis_us": analysis_us, "total_us": us(t0)});
        }
        // gaps a worker may get, grouped by target in the canonical order of `emit_batch`
        let need: Vec<Locks> = a.gaps.iter().map(|g| gap_locks(&a, &self.session, g)).collect();
        let issuable = |g: &FrontierGap| !(auto && g.kind == "EMIT_DERIVE_ONLY") && !(leave_heavy && heavy_work(g));
        let left_to_heavy = leave_heavy && a.gaps.iter().any(heavy_work);
        // the rank of a target: a heavy reasoner takes targets with heavy work first, everyone else ranks by priority alone
        let rank = |g: &FrontierGap| (!(tier == WorkerTier::HeavyReasoner && heavy_work(g)), g.priority);
        let mut best: BTreeMap<&str, (bool, Priority)> = BTreeMap::new();
        for g in a.gaps.iter().filter(|g| issuable(g)) {
            let e = best.entry(g.target.as_str()).or_insert(rank(g));
            if rank(g) < *e {
                *e = rank(g);
            }
        }
        let mut by_target: BTreeMap<((bool, Priority), &str), Vec<usize>> = BTreeMap::new();
        for (i, g) in a.gaps.iter().enumerate().filter(|(_, g)| issuable(g)) {
            by_target.entry((best[g.target.as_str()], g.target.as_str())).or_default().push(i);
        }
        let take = |list: &[usize], room: usize, first: bool, held: &Locks| -> (Vec<usize>, usize) {
            let mut chosen = Vec::new();
            let mut spent = 0usize;
            for &gi in list {
                let g = &a.gaps[gi];
                if held.blocks(&need[gi], mode, g.kind == "EMIT_DERIVE_ONLY") {
                    continue;
                }
                if spent + g.est_events > room && !(first && chosen.is_empty()) {
                    continue;
                }
                spent += g.est_events;
                chosen.push(gi);
            }
            (chosen, spent)
        };
        let mut held = locks.clone();
        let mut lease_locks = Locks::default();
        let mut chosen: Vec<usize> = Vec::new();
        let mut taken: Vec<String> = Vec::new();
        let mut spent = 0usize;
        for ((_, target), list) in &by_target {
            if chosen.is_empty() {
                let (c, sp) = take(list, k, true, &held);
                if c.is_empty() {
                    continue;
                }
                spent = sp;
                chosen = c;
            } else {
                let room = k.saturating_sub(spent);
                if room == 0 {
                    break;
                }
                let (c, sp) = take(list, room, false, &held);
                // only whole targets, as in pass 2 of `emit_batch`
                if c.is_empty() || c.len() != list.len() {
                    continue;
                }
                spent += sp;
                chosen.extend(c);
            }
            taken.push(target.to_string());
            for &gi in &chosen {
                lease_locks.absorb(&need[gi]);
            }
            held.absorb(&lease_locks);
            if !pack {
                break;
            }
        }
        if left_to_heavy {
            self.stats.tier_skips += 1;
        }
        if chosen.is_empty() {
            // work left to a live heavy reasoner is not a stall: the fast worker waits for it
            let stalled = self.leases.is_empty() && !left_to_heavy;
            self.stats.wait_responses += 1;
            return json!({"status": if stalled { "STALLED" } else { "WAIT_IN_FLIGHT" }, "complete": false,
                          "in_flight_leases": self.leases.len(), "open_gaps": open_gaps, "auto_closed": auto_closed, "expired": expired,
                          "analysis_us": analysis_us, "total_us": us(t0)});
        }
        // ---- the lease
        self.lease_seq += 1;
        let seq = self.lease_seq;
        let lease_id = format!("L{seq}");
        let asg = Assignment { seat: 0, target: Some(taken[0].clone()), targets: taken.clone(), gaps: chosen.clone() };
        let frame = {
            let cone = self.session.engine.cone_reader();
            frame_for(&cone, &self.cache, &self.session.ontology, &a, &asg, k, &FrameSlot::Lease { seq, lease_id: &lease_id })
        };
        let gaps: Vec<&FrontierGap> = chosen.iter().map(|&i| &a.gaps[i]).collect();
        let contract = ScopeContract::of(&a, &gaps);
        let fact_segments: Vec<String> = gaps
            .iter()
            .filter(|g| FACT_KINDS.contains(&g.kind))
            .flat_map(|g| g.segments.iter().filter(|&&s| !a.segments[s].amendment).map(|&s| a.segments[s].id.clone()))
            .collect();
        let owned_gaps: Vec<FrontierGap> = gaps.iter().map(|g| (*g).clone()).collect();
        let kind = gaps[0].kind.to_string();
        drop(a);
        let takeover = taken.iter().any(|t| self.expired_targets.contains(t));
        if takeover {
            self.stats.ttl_takeovers += 1;
        }
        for t in &taken {
            self.expired_targets.remove(t);
        }
        self.stats.leases_issued += 1;
        *self.stats.issued_by_tier_kind.entry(format!("{}/{kind}", tier.name())).or_default() += 1;
        *self.stats.issued_by_kind.entry(kind).or_default() += 1;
        *self.stats.issued_by_tier.entry(tier.name().to_string()).or_default() += 1;
        let lease = ActiveLease {
            lease_id: lease_id.clone(),
            seq,
            local_id_prefix: format!("l{seq}_"),
            directive_id: frame["directive_id"].as_str().unwrap_or("").to_string(),
            agent_id: agent_id.to_string(),
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(ttl),
            k,
            max_events: frame["max_events"].as_u64().unwrap_or(k as u64) as usize,
            targets: taken,
            gaps: owned_gaps,
            frame,
            locks: lease_locks,
            fact_segments,
            contract,
            repair_used: false,
            accepted_events: 0,
            doc_epoch: self.doc_epoch,
            tier,
        };
        let rep = json!({"status": "DIRECTIVE", "complete": false, "lease_id": lease.lease_id, "agent_id": lease.agent_id,
                         "directive_id": lease.directive_id, "local_id_prefix": lease.local_id_prefix, "tier": tier.name(),
                         "issued_at_ms": lease.issued_at_ms, "expires_at_ms": lease.expires_at_ms, "takeover": takeover,
                         "frame": lease.frame, "contract": lease.contract.to_json(), "auto_closed": auto_closed, "expired": expired,
                         "in_flight_leases": self.leases.len() + 1, "open_gaps": open_gaps, "analysis_us": analysis_us, "total_us": us(t0)});
        if let Some(j) = self.session.journal.as_mut() {
            j.push(journal::lease_record(seq));
        }
        self.leases.insert(seq, lease);
        rep
    }

    // -------------------------------------------------------------------------------------- submit

    /// Commit the events of a lease (see the module docs).
    pub fn submit_directive(&mut self, lease_id: &str, agent_id: Option<&str>, events: &[Value], now_ms: Option<u64>) -> Value {
        let t0 = Instant::now();
        let now = self.now(now_ms);
        let expired = self.expire_stale(now);
        let Some(seq) = parse_lease(lease_id).filter(|q| self.leases.contains_key(q)) else {
            self.stats.stale_unknown += 1;
            return json!({"status": "STALE_LEASE", "code": "LEASE_EXPIRED_OR_UNKNOWN", "lease_id": lease_id, "expired": expired,
                          "message": "the lease expired (TTL) or was already closed; nothing was applied - acquire a new directive",
                          "total_us": us(t0)});
        };
        if let Some(ag) = agent_id {
            if self.leases[&seq].agent_id != ag {
                return err("LEASE_NOT_OWNED", format!("lease {lease_id} belongs to agent '{}'", self.leases[&seq].agent_id));
            }
        }
        let mut lease = self.leases.remove(&seq).expect("checked above");
        // optimistic check against changes made since the lease was issued
        let lost: Vec<String> = lease
            .contract
            .required_premises
            .iter()
            .filter(|p| self.session.engine.status_of(p) != Some(ST_SUPPORTED))
            .map(|p| format!("@{}", short(p)))
            .collect();
        if !lost.is_empty() {
            self.stats.stale_premise += 1;
            let auto = self.run_auto_close();
            return json!({"status": "STALE_LEASE", "code": "STALE_LEASE_PREMISE_REVOKED", "lease_id": lease_id, "premises": lost,
                          "message": "a premise this directive builds on is no longer SUPPORTED (revoked or in conflict); nothing was applied - acquire a new directive",
                          "auto_closed_derivations": auto, "expired": expired, "total_us": us(t0)});
        }
        if lease.doc_epoch != self.doc_epoch && !lease.fact_segments.is_empty() {
            let withdrawn: Vec<String> = match self.targets.as_ref() {
                Some(t) => {
                    let a = analyze_cached(&self.session, t, &mut self.cache);
                    a.segments.iter().filter(|g| g.withdrawn && lease.fact_segments.contains(&g.id)).map(|g| g.id.clone()).collect()
                }
                None => Vec::new(),
            };
            if !withdrawn.is_empty() {
                self.stats.stale_segment += 1;
                return json!({"status": "STALE_LEASE", "code": "STALE_LEASE_SEGMENT_WITHDRAWN", "lease_id": lease_id, "segments": withdrawn,
                              "message": "an erratum published after the lease was issued withdraws a clause of this directive; nothing was applied",
                              "expired": expired, "total_us": us(t0)});
            }
            lease.doc_epoch = self.doc_epoch;
        }
        let limit = if lease.repair_used { lease.max_events.saturating_sub(lease.accepted_events).max(1) } else { lease.max_events };
        let over_budget = events.len().saturating_sub(limit);
        let mut results: Vec<Value> = Vec::new();
        let mut accepted = 0usize;
        let mut fail: Option<(usize, Value)> = None;
        for (i, ev) in events.iter().take(limit).enumerate() {
            let Some(obj) = ev.as_object() else {
                fail = Some((i, err("BAD_JSON", "each event must be a JSON object")));
                break;
            };
            let mut m = obj.clone();
            m.remove("seq");
            if let Some(why) = lease.contract.violation(&m) {
                self.stats.directive_violations += 1;
                let mut e = err("DIRECTIVE_VIOLATION", why);
                e["obligation"] = json!({"action": "emit only the events the directive asks for"});
                fail = Some((i, e));
                break;
            }
            m.insert("seq".into(), json!(self.session.last_seq + 1));
            match self.session.apply_line(&Value::Object(m).to_string()) {
                Ok(ap) => {
                    accepted += 1;
                    results.push(ap.to_json());
                }
                Err(e) => {
                    fail = Some((i, e.to_json()));
                    break;
                }
            }
        }
        lease.accepted_events += accepted;
        self.stats.events_accepted += accepted as u64;
        if let Some((idx, error)) = fail {
            self.stats.events_rejected += 1;
            let unsent = events.len().min(limit).saturating_sub(idx + 1);
            if lease.repair_used {
                self.stats.leases_failed += 1;
                let auto = self.run_auto_close();
                return json!({"status": "LEASE_CLOSED", "code": "REPAIR_EXHAUSTED", "lease_id": lease_id, "accepted_count": accepted,
                              "failed_index": idx, "error": error, "results": results, "unsent": unsent, "over_budget": over_budget,
                              "auto_closed_derivations": auto, "state_root": to_hex(&self.session.engine.root()), "expired": expired, "total_us": us(t0)});
            }
            lease.repair_used = true;
            self.stats.repair_required += 1;
            let remaining = lease.max_events.saturating_sub(lease.accepted_events).max(1);
            let expires = lease.expires_at_ms;
            self.leases.insert(seq, lease);
            return json!({"status": "REPAIR_REQUIRED", "lease_id": lease_id, "accepted_count": accepted, "failed_index": idx, "error": error,
                          "results": results, "unsent": unsent, "over_budget": over_budget, "max_events_repair": remaining,
                          "expires_at_ms": expires, "expired": expired, "total_us": us(t0)});
        }
        self.stats.leases_committed += 1;
        let t_ac = Instant::now();
        let auto = self.run_auto_close();
        let auto_us = us(t_ac);
        json!({"status": "COMMITTED", "lease_id": lease_id, "accepted": accepted, "results": results, "over_budget": over_budget,
               "auto_closed_derivations": auto, "auto_close_us": auto_us, "state_root": to_hex(&self.session.engine.root()),
               "expired": expired, "total_us": us(t0)})
    }

    /// Extend a live lease (heartbeat of a worker that is still working on it).
    pub fn renew_lease(&mut self, lease_id: &str, agent_id: Option<&str>, ttl_ms: Option<u64>, now_ms: Option<u64>) -> Value {
        let t0 = Instant::now();
        let now = self.now(now_ms);
        let expired = self.expire_stale(now);
        let ttl = ttl_ms.unwrap_or(self.cfg.default_ttl_ms).max(1);
        match parse_lease(lease_id).and_then(|q| self.leases.get_mut(&q)) {
            Some(l) if agent_id.is_none_or(|a| a == l.agent_id) => {
                l.expires_at_ms = now.saturating_add(ttl);
                self.stats.renewals += 1;
                json!({"status": "RENEWED", "lease_id": lease_id, "expires_at_ms": l.expires_at_ms, "expired": expired, "total_us": us(t0)})
            }
            Some(l) => err("LEASE_NOT_OWNED", format!("lease {lease_id} belongs to agent '{}'", l.agent_id)),
            None => json!({"status": "STALE_LEASE", "code": "LEASE_EXPIRED_OR_UNKNOWN", "lease_id": lease_id, "expired": expired, "total_us": us(t0)}),
        }
    }

    /// Give a lease back unfinished (its work returns to the pool at once).
    pub fn release_lease(&mut self, lease_id: &str, agent_id: Option<&str>, now_ms: Option<u64>) -> Value {
        let t0 = Instant::now();
        let now = self.now(now_ms);
        let expired = self.expire_stale(now);
        match parse_lease(lease_id).and_then(|q| self.leases.get(&q).map(|l| (q, l))) {
            Some((q, l)) if agent_id.is_none_or(|a| a == l.agent_id) => {
                self.leases.remove(&q);
                self.stats.leases_released += 1;
                let auto = self.run_auto_close();
                json!({"status": "RELEASED", "lease_id": lease_id, "auto_closed_derivations": auto, "expired": expired, "total_us": us(t0)})
            }
            Some((_, l)) => err("LEASE_NOT_OWNED", format!("lease {lease_id} belongs to agent '{}'", l.agent_id)),
            None => json!({"status": "STALE_LEASE", "code": "LEASE_EXPIRED_OR_UNKNOWN", "lease_id": lease_id, "expired": expired, "total_us": us(t0)}),
        }
    }

    // -------------------------------------------------------------------------------------- documents, views

    /// Publish a document (an erratum) on the live session; it becomes visible to the compiler at once.
    pub fn put_document(&mut self, doc_id: &str, bytes: &[u8], now_ms: Option<u64>) -> Value {
        let t0 = Instant::now();
        let now = self.now(now_ms);
        let expired = self.expire_stale(now);
        if doc_id.is_empty() || doc_id.len() > MAX_STR {
            return err("BAD_DOC_ID", "doc_id must be 1..1024 bytes");
        }
        let root_before = to_hex(&self.session.engine.root());
        let t = Instant::now();
        let rep = self.put_document_raw(doc_id, bytes);
        let elapsed_us = us(t);
        let auto = self.run_auto_close();
        json!({"status": "DOCUMENT_PUT", "doc_id": doc_id, "root_before": root_before, "root_after": to_hex(&self.session.engine.root()),
               "chunks_total": rep.chunks_total, "evidence_stale": rep.evidence_stale, "rebound_ok": rep.rebound_ok, "rebind_failed": rep.rebind_failed,
               "claims_net_removed": rep.claims_net_removed, "elapsed_us": elapsed_us, "visible_docs": self.targets.as_ref().and_then(|t| t.docs.clone()),
               "auto_closed_derivations": auto, "expired": expired, "total_us": us(t0)})
    }

    /// The document update itself, without auto-closure (also the replay of a session-log record).
    pub(crate) fn put_document_raw(&mut self, doc_id: &str, bytes: &[u8]) -> crate::session::DocUpdateReport {
        let rep = self.session.put_document(doc_id, bytes);
        self.doc_epoch += 1;
        if let Some(d) = self.targets.as_mut().and_then(|t| t.docs.as_mut()) {
            if !d.iter().any(|x| x == doc_id) {
                d.insert(0, doc_id.to_string());
            }
        }
        rep
    }

    /// The minimal support cone of an entity on the live engine (claims with their status).
    pub fn query_cone(&self, entity: &str) -> Value {
        let t0 = Instant::now();
        let eng = &self.session.engine;
        let ids = cone_claim_ids(&eng.cone_reader(), &self.session.ontology, entity);
        let claims: Vec<Value> = ids
            .iter()
            .filter_map(|id| {
                let c = eng.claim(id)?;
                let st = eng.status_of(id).unwrap_or(ST_UNSUPPORTED);
                Some(json!({"id": format!("@{}", short(id)), "s": c.s, "p": c.p, "o": c.o, "polarity": c.pol.as_str(), "ctx": c.ctx,
                            "t": [c.t_from, c.t_to], "status": status_name(KIND_CLAIM, st)}))
            })
            .collect();
        json!({"status": "CONE", "entity": entity, "claims": claims, "total_us": us(t0)})
    }

    pub fn status(&mut self, now_ms: Option<u64>) -> Value {
        let t0 = Instant::now();
        let now = self.now(now_ms);
        let expired = self.expire_stale(now);
        let mut rep = json!({"status": "SWARM_STATUS", "now_ms": now, "config": self.cfg.to_json(), "stats": self.stats.to_json(),
                             "leases": self.leases.values().map(|l| l.brief()).collect::<Vec<_>>(), "expired": expired,
                             "doc_epoch": self.doc_epoch, "last_seq": self.session.last_seq,
                             "last_complete": self.last_complete});
        if let Some(t) = self.targets.as_ref() {
            let a = analyze_cached(&self.session, t, &mut self.cache);
            let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
            for g in &a.gaps {
                *kinds.entry(g.kind).or_default() += 1;
            }
            let mut states: BTreeMap<&str, usize> = BTreeMap::new();
            for st in a.goal_state.values() {
                *states.entry(st).or_default() += 1;
            }
            rep["open_gaps"] = json!(a.gaps.len());
            rep["gaps_by_kind"] = json!(kinds);
            rep["goal_states"] = json!(states);
            rep["complete"] = json!(a.gaps.is_empty() && self.leases.is_empty());
            rep["analysis_us"] = json!(a.analysis_us);
        }
        rep["state_root"] = json!(to_hex(&self.session.engine.root()));
        rep["nodes"] = json!(self.session.engine.node_count());
        rep["total_us"] = json!(us(t0));
        rep
    }

    /// A synchronous round on the live session (`emit_batch_frames_live`), for the round-barrier baseline.
    pub fn emit_batch(&mut self, targets: Option<Targets>, seats: usize, k: usize, round: u64) -> Value {
        let t0 = Instant::now();
        let t = match targets.as_ref().or(self.targets.as_ref()) {
            Some(t) => t,
            None => return err("NO_TARGETS", "set_targets first (or pass 'targets')"),
        };
        let mut rep = emit_batch_frames_live(&self.session, &mut self.cache, t, seats.max(1), k.max(1), round);
        rep["status"] = json!("directives");
        rep["resident"] = json!(true);
        rep["total_us"] = json!(us(t0));
        rep
    }

    /// Plain events without a lease (the kernel numbers them), fail-fast: stops at the first rejected event.
    pub fn apply_events(&mut self, events: &[Value]) -> Value {
        let t0 = Instant::now();
        let mut results = Vec::new();
        let mut error = Value::Null;
        let mut failed = Value::Null;
        for (i, ev) in events.iter().enumerate() {
            let Some(obj) = ev.as_object() else {
                error = err("BAD_JSON", "each event must be a JSON object");
                failed = json!(i);
                break;
            };
            let mut m = obj.clone();
            m.insert("seq".into(), json!(self.session.last_seq + 1));
            match self.session.apply_line(&Value::Object(m).to_string()) {
                Ok(ap) => results.push(ap.to_json()),
                Err(e) => {
                    error = e.to_json();
                    failed = json!(i);
                    break;
                }
            }
        }
        json!({"status": "APPLIED", "accepted": results.len(), "results": results, "error": error, "failed_index": failed, "total_us": us(t0)})
    }

    // -------------------------------------------------------------------------------------- JSON front end

    /// One JSON request of `sbgk serve` / `sbgk mcp-serve`. None: `op` is not a swarm op.
    pub fn handle(&mut self, op: &str, v: &Value) -> Option<Value> {
        let t0 = Instant::now();
        let s = |k: &str| v.get(k).and_then(|x| x.as_str());
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64());
        let empty: Vec<Value> = Vec::new();
        let events = v.get("events").and_then(|x| x.as_array()).unwrap_or(&empty);
        let mut rep = match op {
            "set_targets" => {
                let Some(tv) = v.get("targets") else { return Some(err("BAD_TARGETS", "missing 'targets'")) };
                let t = match Targets::from_json(tv) {
                    Ok(t) => t,
                    Err(e) => return Some(err("BAD_TARGETS", e)),
                };
                if let Err(e) = self.configure(v) {
                    return Some(e);
                }
                let goals = t.goals.len();
                let docs = t.docs.clone();
                self.set_targets(t);
                json!({"status": "TARGETS_SET", "goals": goals, "docs": docs, "config": self.cfg.to_json()})
            }
            "acquire_directive" => match s("tier").map(|t| WorkerTier::parse(t).ok_or(t)).unwrap_or(Ok(WorkerTier::Standard)) {
                Ok(tier) => self.acquire_directive_tier(s("agent_id").unwrap_or("anonymous"), tier, n("ttl_ms"), n("k").map(|x| x as usize), n("now_ms")),
                Err(t) => err("BAD_TIER", format!("tier '{t}' must be fast_cheap, standard or heavy_reasoner")),
            },
            "submit_directive" => match s("lease_id") {
                Some(l) => self.submit_directive(l, s("agent_id"), events, n("now_ms")),
                None => err("MISSING_FIELD", "missing 'lease_id'"),
            },
            "renew_lease" => match s("lease_id") {
                Some(l) => self.renew_lease(l, s("agent_id"), n("ttl_ms"), n("now_ms")),
                None => err("MISSING_FIELD", "missing 'lease_id'"),
            },
            "release_lease" => match s("lease_id") {
                Some(l) => self.release_lease(l, s("agent_id"), n("now_ms")),
                None => err("MISSING_FIELD", "missing 'lease_id'"),
            },
            "put_document" | "post_erratum" => match s("text").or(s("erratum_text")) {
                Some(text) => self.put_document(s("doc_id").unwrap_or("erratum"), text.as_bytes(), n("now_ms")),
                None => err("MISSING_FIELD", "missing 'text'"),
            },
            "query_cone" => match s("entity").or(s("target_entity")) {
                Some(e) => self.query_cone(e),
                None => err("MISSING_FIELD", "missing 'entity'"),
            },
            "swarm_status" => self.status(n("now_ms")),
            "emit_batch" => {
                let t = match v.get("targets").map(Targets::from_json) {
                    Some(Ok(t)) => Some(t),
                    Some(Err(e)) => return Some(err("BAD_TARGETS", e)),
                    None => None,
                };
                self.emit_batch(t, n("seats").unwrap_or(1) as usize, n("k").unwrap_or(4) as usize, n("round").unwrap_or(1))
            }
            "apply_events" => self.apply_events(events),
            _ => return None,
        };
        if let Err(e) = self.sync_wal() {
            return Some(err("WAL_WRITE_FAILED", format!("the session log could not be written: {e}")));
        }
        if rep.get("total_us").is_none() {
            rep["total_us"] = json!(us(t0));
        }
        Some(rep)
    }
}

// ------------------------------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdc::CdcParams;
    use crate::ontology::Ontology;
    use std::collections::HashMap;

    const ONTO: &str = r#"{
      "entities":[
        {"id":"svc_001","type":"Service","aliases":["service 1"]},
        {"id":"svc_002","type":"Service","aliases":["service 2"]},
        {"id":"svc_003","type":"Service","aliases":["service 3"]},
        {"id":"svc_004","type":"Service","aliases":["service 4"]},
        {"id":"api_001","type":"Api","aliases":["interface 1"]},
        {"id":"api_002","type":"Api","aliases":["interface 2"]}],
      "predicates":[
        {"id":"uses_api","subject":"Service","object":"Api"},
        {"id":"api_deprecated","subject":"Api","object":"@literal"},
        {"id":"needs_review","subject":"Service","object":"@literal"}],
      "rules":[{"id":"R_depr_review@1","mode":"AND",
        "body":[{"p":"uses_api"},{"p":"api_deprecated"}],
        "join":[["0.o","1.s"]],
        "head":{"s":"0.s","p":"needs_review","o":{"const":"true"}}}]}"#;

    const U1: &str = "Clause U.1: service svc_001 shall call interface api_001 in production from t=100 until t=200.";
    const U2: &str = "Clause U.2: service svc_002 shall call interface api_001 in production from t=110 until t=210.";
    const U3: &str = "Clause U.3: service svc_003 shall call interface api_001 in production from t=100 until t=220.";
    const U4: &str = "Clause U.4: service svc_004 shall call interface api_002 in production from t=100 until t=200.";
    const D1: &str = "Clause D.1: interface api_001 is deprecated in production from t=150 until t=300.";
    const D2: &str = "Clause D.2: interface api_002 is deprecated in production from t=150 until t=300.";
    const R1: &str = "Clause R.1: from t=150 until t=300, production use of interface api_001 is deprecated (this restates clause D.1).";
    const ERRATUM: &str = "Erratum E.1: clause D.1 is withdrawn; the same statement stands in clause R.1. Erratum E.2: clause U.3 is withdrawn.\n";

    /// sentence -> the fact it states (s, p, o, t)
    fn table() -> HashMap<&'static str, (&'static str, &'static str, &'static str, (i64, i64))> {
        HashMap::from([
            (U1, ("svc_001", "uses_api", "api_001", (100, 200))),
            (U2, ("svc_002", "uses_api", "api_001", (110, 210))),
            (U3, ("svc_003", "uses_api", "api_001", (100, 220))),
            (U4, ("svc_004", "uses_api", "api_002", (100, 200))),
            (D1, ("api_001", "api_deprecated", "true", (150, 300))),
            (D2, ("api_002", "api_deprecated", "true", (150, 300))),
            (R1, ("api_001", "api_deprecated", "true", (150, 300))),
        ])
    }

    fn swarm(auto: bool, lock: LockMode) -> SwarmSession {
        let mut s = Session::new(Ontology::from_json_str(ONTO).unwrap(), CdcParams::default());
        let doc = format!("The operator shall archive the access logs within 3 business days. {U1} {U2}\n\n{U3} {U4} The custodian must review all change requests.\n\n{D1} {R1} {D2}\n");
        s.put_document("policy", doc.as_bytes());
        let mut sw = SwarmSession::new(s);
        let goals: Vec<Value> = ["svc_001", "svc_002", "svc_003", "svc_004"].iter().map(|e| json!({"entity": e, "predicate": "needs_review"})).collect();
        let t = json!({"goals": goals, "docs": ["policy"]});
        let r = sw.handle("set_targets", &json!({"targets": t, "auto_close_p2a": auto, "lock_mode": lock.name()})).unwrap();
        assert_eq!(r["status"], "TARGETS_SET");
        sw
    }

    /// Executes a frame exactly as the compiler asks (no model): the events a perfect worker would write.
    fn oracle(frame: &Value) -> Vec<Value> {
        let tab = table();
        let pre = frame["local_id_prefix"].as_str().unwrap();
        let mut out = Vec::new();
        let mut n = 0;
        for g in frame["gaps"].as_array().unwrap() {
            match g["kind"].as_str().unwrap() {
                "FORMALIZE" | "EXTRACT_PARTNER" | "RESUPPORT_FROM_RESTATEMENT" | "REPAIR_UNSUPPORTED" => {
                    let mut first: Option<(String, (i64, i64))> = None;
                    for t in g["segment_texts"].as_array().unwrap() {
                        let text = t.as_str().unwrap();
                        let Some((s, p, o, tt)) = tab.get(text).copied() else { continue };
                        n += 1;
                        out.push(json!({"op": "bind_evidence", "local_id": format!("{pre}e{n}"), "doc_id": "policy", "exact_quote": text}));
                        out.push(json!({"op": "assert_fact", "local_id": format!("{pre}f{n}"), "s": s, "p": p, "o": o, "polarity": "POS", "ctx": "prod",
                                        "t": [tt.0, tt.1], "evidence": [format!("{pre}e{n}")]}));
                        first.get_or_insert((format!("{pre}f{n}"), tt));
                    }
                    if let (Some((lid, _)), Some(p)) = (first, g["partner"].as_object()) {
                        // every window in this fixture overlaps its partner's
                        n += 1;
                        out.push(json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": p["rule"], "premises": [lid, p["id"].clone()]}));
                    }
                }
                "EMIT_DERIVE_ONLY" => {
                    n += 1;
                    out.push(json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": g["derive"]["rule"], "premises": g["derive"]["premises"]}));
                }
                _ => {
                    for e in g["evidence"].as_array().unwrap() {
                        out.push(json!({"op": "revoke_evidence", "target_evidence": e}));
                    }
                }
            }
        }
        out.truncate(frame["max_events"].as_u64().unwrap() as usize);
        out
    }

    fn acquire(sw: &mut SwarmSession, agent: &str, now: u64) -> Value {
        sw.handle("acquire_directive", &json!({"agent_id": agent, "ttl_ms": 30_000, "k": 4, "now_ms": now})).unwrap()
    }

    fn submit(sw: &mut SwarmSession, r: &Value, events: Vec<Value>, now: u64) -> Value {
        sw.handle("submit_directive", &json!({"lease_id": r["lease_id"], "agent_id": r["agent_id"], "events": events, "now_ms": now})).unwrap()
    }

    fn work(sw: &mut SwarmSession, r: &Value, now: u64) -> Value {
        let ev = oracle(&r["frame"]);
        submit(sw, r, ev, now)
    }

    fn segments_of(r: &Value) -> Vec<String> {
        r["frame"]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["segment_texts"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()))
            .collect()
    }

    /// Plays the swarm to the end in waves: up to `agents` workers take leases from the same state, then all of them answer.
    /// Returns the final root and the kinds issued.
    fn play(sw: &mut SwarmSession, agents: usize) -> (String, Vec<String>) {
        let mut kinds = Vec::new();
        let mut now = 100_000u64;
        for _ in 0..100 {
            let mut wave = Vec::new();
            for i in 0..agents {
                now += 1;
                let r = acquire(sw, &format!("a{i}"), now);
                match r["status"].as_str().unwrap() {
                    "COMPLETE" => return (r["state_root"].as_str().unwrap().to_string(), kinds),
                    "DIRECTIVE" => {
                        kinds.push(r["frame"]["kind"].as_str().unwrap().to_string());
                        wave.push(r);
                    }
                    "WAIT_IN_FLIGHT" => break,
                    other => panic!("{other}: {r}"),
                }
            }
            for r in &wave {
                now += 1;
                assert_eq!(work(sw, r, now)["status"], "COMMITTED");
            }
        }
        panic!("no completion")
    }

    #[test]
    fn parallel_leases_lock_the_shared_premise_and_target_only_duplicates_it() {
        let mut sw = swarm(false, LockMode::SharedPremise);
        let first: Vec<Value> = (1..=4).map(|i| acquire(&mut sw, &format!("a{i}"), 0)).collect();
        let tg: Vec<&str> = first.iter().map(|r| r["frame"]["target"].as_str().unwrap()).collect();
        assert_eq!(tg, vec!["svc_001", "svc_002", "svc_003", "svc_004"], "four FORMALIZE leases, one target each");
        let prefixes: FxSet<&str> = first.iter().map(|r| r["local_id_prefix"].as_str().unwrap()).collect();
        assert_eq!(prefixes.len(), 4);
        assert_eq!(acquire(&mut sw, "a5", 0)["status"], "WAIT_IN_FLIGHT");
        // svc_001 formalized: D.1 is the missing partner premise
        assert_eq!(work(&mut sw, &first[0], 10)["status"], "COMMITTED");
        let x = acquire(&mut sw, "a1", 10);
        assert_eq!(x["frame"]["kind"], "EXTRACT_PARTNER");
        assert_eq!(segments_of(&x), vec![D1.to_string()]);
        assert_eq!(x["contract"]["required_premises"].as_array().unwrap().len(), 1);
        // svc_002 formalized while D.1 is in flight: its EXTRACT_PARTNER needs the same clause / premise -> no duplicate
        assert_eq!(work(&mut sw, &first[1], 11)["status"], "COMMITTED");
        let y = acquire(&mut sw, "a2", 11);
        assert_eq!(y["status"], "WAIT_IN_FLIGHT", "{y}");
        // the same moment with target-only sharding: the shared clause goes to a second worker
        let mut naive = swarm(false, LockMode::TargetOnly);
        let f: Vec<Value> = (1..=4).map(|i| acquire(&mut naive, &format!("a{i}"), 0)).collect();
        work(&mut naive, &f[0], 10);
        let x2 = acquire(&mut naive, "a1", 10);
        work(&mut naive, &f[1], 11);
        let y2 = acquire(&mut naive, "a2", 11);
        assert_eq!((x2["frame"]["kind"].as_str(), y2["frame"]["kind"].as_str()), (Some("EXTRACT_PARTNER"), Some("EXTRACT_PARTNER")));
        assert_eq!(segments_of(&y2), segments_of(&x2), "target-only sharding hands the same clause out twice");
        // finishing the extraction: the premise lock is released and svc_002 can be closed
        assert_eq!(work(&mut sw, &x, 20)["status"], "COMMITTED");
        let z = acquire(&mut sw, "a2", 20);
        assert_eq!(z["frame"]["kind"], "EMIT_DERIVE_ONLY", "without auto-closure a worker is called for the derive");
    }

    #[test]
    fn auto_closure_derives_for_dependents_and_reaches_the_same_root() {
        let mut manual = swarm(false, LockMode::SharedPremise);
        let (root_manual, kinds_manual) = play(&mut manual, 4);
        let mut auto = swarm(true, LockMode::SharedPremise);
        let (root_auto, kinds_auto) = play(&mut auto, 4);
        assert!(kinds_manual.iter().any(|k| k == "EMIT_DERIVE_ONLY"), "{kinds_manual:?}");
        assert!(!kinds_auto.iter().any(|k| k == "EMIT_DERIVE_ONLY"), "{kinds_auto:?}");
        assert!(auto.stats.auto_closed_total >= 1);
        assert!(kinds_auto.len() < kinds_manual.len());
        assert_eq!(root_auto, root_manual, "the kernel's derive is the derive a worker would have written");
        let st = auto.status(Some(1000));
        assert_eq!(st["goal_states"]["CLOSED_POSITIVE"], 4);
        // the free function closes nothing more on a closed state
        let t = auto.targets.clone().unwrap();
        assert!(auto_close_ready(&mut auto.session, &mut auto.cache, &t).is_empty());
    }

    #[test]
    fn ttl_expiry_returns_the_work_and_refuses_the_zombie() {
        let mut sw = swarm(true, LockMode::SharedPremise);
        let l1 = sw.handle("acquire_directive", &json!({"agent_id": "slow", "ttl_ms": 1000, "now_ms": 0})).unwrap();
        assert_eq!(l1["frame"]["target"], "svc_001");
        let renewed = sw.handle("renew_lease", &json!({"lease_id": l1["lease_id"], "agent_id": "slow", "ttl_ms": 1000, "now_ms": 500})).unwrap();
        assert_eq!(renewed["expires_at_ms"], 1500);
        assert_ne!(acquire(&mut sw, "b", 1200)["frame"]["target"], "svc_001", "a renewed lease keeps its target");
        let t = acquire(&mut sw, "c", 1500);
        assert_eq!(t["frame"]["target"], "svc_001");
        assert_eq!(t["takeover"], true);
        assert_eq!(t["expired"], json!(["L1"]));
        assert_eq!((sw.stats.leases_expired, sw.stats.ttl_takeovers), (1, 1));
        let seq = sw.session.last_seq;
        let z = work(&mut sw, &l1, 1600);
        assert_eq!((z["status"].as_str(), z["code"].as_str()), (Some("STALE_LEASE"), Some("LEASE_EXPIRED_OR_UNKNOWN")));
        assert_eq!(sw.session.last_seq, seq, "nothing of the zombie's answer reaches the kernel");
        assert_eq!(work(&mut sw, &t, 1700)["status"], "COMMITTED");
    }

    #[test]
    fn scope_guard_keeps_the_prefix_refuses_foreign_quotes_and_closes_after_one_repair() {
        let mut sw = swarm(true, LockMode::SharedPremise);
        let l = acquire(&mut sw, "a", 0);
        let ev = oracle(&l["frame"]);
        let foreign = json!({"op": "bind_evidence", "local_id": "l1_x", "doc_id": "policy", "exact_quote": U2});
        let r = submit(&mut sw, &l, vec![ev[0].clone(), foreign.clone()], 1);
        assert_eq!(r["status"], "REPAIR_REQUIRED");
        assert_eq!((r["accepted_count"].as_u64(), r["failed_index"].as_u64()), (Some(1), Some(1)));
        assert_eq!(r["error"]["code"], "DIRECTIVE_VIOLATION");
        let revoke = json!({"op": "revoke_evidence", "target_evidence": r["results"][0]["node"].as_str().map(|n| format!("@{n}"))});
        let r2 = submit(&mut sw, &l, vec![revoke], 2);
        assert_eq!((r2["status"].as_str(), r2["code"].as_str()), (Some("LEASE_CLOSED"), Some("REPAIR_EXHAUSTED")));
        assert_eq!(r2["error"]["code"], "DIRECTIVE_VIOLATION", "a FORMALIZE directive does not allow revocations");
        assert_eq!(sw.stats.directive_violations, 2);
        // the accepted prefix stays in the kernel; the closed lease holds nothing any more
        assert_eq!(sw.stats.events_accepted, 1);
        assert_eq!(sw.active_leases().count(), 0);
        assert_eq!(acquire(&mut sw, "b", 3)["status"], "DIRECTIVE");
    }

    #[test]
    fn last_complete_witnesses_the_document_epoch_and_root() {
        let mut sw = swarm(true, LockMode::SharedPremise);
        assert_eq!(sw.status(Some(0))["last_complete"], Value::Null);
        let (root, _) = play(&mut sw, 4);
        let lc = sw.status(Some(200_000))["last_complete"].clone();
        assert_eq!((lc["doc_epoch"].as_u64(), lc["state_root"].as_str()), (Some(0), Some(root.as_str())));
        // a document update raises the epoch; a later COMPLETE carries the new epoch and the new root
        sw.handle("post_erratum", &json!({"doc_id": "erratum", "erratum_text": ERRATUM, "now_ms": 200_001})).unwrap();
        assert_eq!(sw.status(Some(200_002))["last_complete"]["doc_epoch"], 0, "no COMPLETE has been answered since the erratum");
        let (root2, _) = play(&mut sw, 4);
        let lc2 = sw.status(Some(300_000))["last_complete"].clone();
        assert_eq!((lc2["doc_epoch"].as_u64(), lc2["state_root"].as_str()), (Some(1), Some(root2.as_str())));
        assert!(lc2["n"].as_u64() > lc["n"].as_u64());
    }

    #[test]
    fn partial_bind_without_assert_is_reissued_and_reaches_completeness() {
        let (reference, _) = play(&mut swarm(true, LockMode::SharedPremise), 4);
        let mut sw = swarm(true, LockMode::SharedPremise);
        let l = acquire(&mut sw, "a", 0);
        assert_eq!((l["frame"]["target"].as_str(), segments_of(&l)), (Some("svc_001"), vec![U1.to_string()]));
        let ev = oracle(&l["frame"]);
        // U.1 is bound, the fact is refused (a service is not an Api), and the repair is refused as well
        let mut bad = ev[1].clone();
        bad["s"] = json!("api_002");
        let r = submit(&mut sw, &l, vec![ev[0].clone(), bad.clone()], 1);
        assert_eq!((r["status"].as_str(), r["accepted_count"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{r}");
        let r2 = submit(&mut sw, &l, vec![bad], 2);
        assert_eq!((r2["status"].as_str(), r2["code"].as_str()), (Some("LEASE_CLOSED"), Some("REPAIR_EXHAUSTED")));
        // the bound evidence alone does not cover U.1: svc_001 is handed out again
        let st = sw.status(Some(3));
        assert_eq!(st["goal_states"]["OPEN"], 4, "{st}");
        let again = acquire(&mut sw, "b", 3);
        assert_eq!((again["frame"]["target"].as_str(), again["frame"]["kind"].as_str()), (Some("svc_001"), Some("FORMALIZE")), "{again}");
        assert_eq!(segments_of(&again), vec![U1.to_string()]);
        // the second worker binds the same quote under its own prefix (the kernel keeps one evidence node) and asserts
        let c = work(&mut sw, &again, 4);
        assert_eq!(c["status"], "COMMITTED", "{c}");
        let (root, _) = play(&mut sw, 4);
        assert_eq!(root, reference, "the abandoned binding leaves no trace in the final state");
        let st = sw.status(Some(10_000));
        assert_eq!(st["goal_states"]["CLOSED_POSITIVE"], 4, "{st}");
    }

    #[test]
    fn fuzz_partial_lease_failures_never_lose_targets() {
        let (reference, _) = play(&mut swarm(true, LockMode::SharedPremise), 4);
        for seed in 0..20u64 {
            let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut roll = move || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng % 100
            };
            let mut sw = swarm(true, LockMode::SharedPremise);
            let (mut now, mut closed, mut done) = (0u64, 0usize, None);
            for _ in 0..400 {
                let agents = 1 + (roll() % 4) as usize;
                let mut wave = Vec::new();
                for i in 0..agents {
                    now += 1;
                    let r = acquire(&mut sw, &format!("w{i}"), now);
                    match r["status"].as_str().unwrap() {
                        "COMPLETE" => {
                            done = Some(r["state_root"].as_str().unwrap().to_string());
                            break;
                        }
                        "DIRECTIVE" => wave.push(r),
                        "WAIT_IN_FLIGHT" => break,
                        other => panic!("seed {seed}: {other}: {r}"),
                    }
                }
                if done.is_some() {
                    break;
                }
                for r in &wave {
                    now += 1;
                    let ev = oracle(&r["frame"]);
                    let poison = ev.iter().position(|e| e["op"] == "assert_fact");
                    match poison.filter(|_| roll() < 30) {
                        // the lease binds its evidence, then fails twice on the fact and closes
                        Some(at) => {
                            let mut bad = ev[at].clone();
                            bad["p"] = json!("no_such_predicate");
                            let mut first = ev[..at].to_vec();
                            first.push(bad.clone());
                            assert_eq!(submit(&mut sw, r, first, now)["status"], "REPAIR_REQUIRED", "seed {seed}");
                            now += 1;
                            let x = submit(&mut sw, r, vec![bad], now);
                            assert_eq!(x["code"], "REPAIR_EXHAUSTED", "seed {seed}: {x}");
                            closed += 1;
                        }
                        None => assert_eq!(submit(&mut sw, r, ev, now)["status"], "COMMITTED", "seed {seed}"),
                    }
                }
            }
            let root = done.unwrap_or_else(|| panic!("seed {seed}: no completion"));
            let st = sw.status(Some(now + 1));
            assert_eq!(st["goal_states"]["CLOSED_POSITIVE"], 4, "seed {seed}: {st}");
            assert_eq!(root, reference, "seed {seed}: {closed} closed leases");
        }
    }

    fn acquire_as(sw: &mut SwarmSession, agent: &str, tier: &str, now: u64) -> Value {
        sw.handle("acquire_directive", &json!({"agent_id": agent, "tier": tier, "ttl_ms": 30_000, "k": 4, "now_ms": now})).unwrap()
    }

    fn lease_has_heavy_work(sw: &SwarmSession, r: &Value) -> bool {
        let seq = parse_lease(r["lease_id"].as_str().unwrap()).unwrap();
        sw.leases[&seq].gaps.iter().any(heavy_work)
    }

    /// The fixture after U.1 and its partner D.1 are formalized and the erratum (withdraws D.1 and U.3) is posted.
    fn swarm_after_erratum(now: u64) -> SwarmSession {
        let mut sw = swarm(false, LockMode::SharedPremise);
        let l1 = acquire(&mut sw, "a", now);
        work(&mut sw, &l1, now + 1);
        let x = acquire(&mut sw, "a", now + 2);
        work(&mut sw, &x, now + 3);
        sw.handle("post_erratum", &json!({"doc_id": "erratum", "erratum_text": ERRATUM, "now_ms": now + 4})).unwrap();
        sw
    }

    #[test]
    fn fast_workers_leave_heavy_work_to_a_live_reasoner() {
        let mut sw = swarm_after_erratum(0);
        assert!(!sw.heavy_alive(5));
        // the reasoner registers by asking; it gets the amendment (P0) first
        let h = acquire_as(&mut sw, "h", "heavy_reasoner", 5);
        assert_eq!((h["frame"]["kind"].as_str(), h["tier"].as_str()), (Some("REVOKE_WITHDRAWN"), Some("heavy_reasoner")));
        // while it is alive, fast workers take only routine work, never heavy work
        let mut fast = Vec::new();
        for (i, now) in (6..9).enumerate() {
            let f = acquire_as(&mut sw, &format!("f{i}"), "fast_cheap", now);
            if f["status"] == "DIRECTIVE" {
                assert!(!lease_has_heavy_work(&sw, &f), "{f}");
                fast.push(f);
            } else {
                assert_eq!(f["status"], "WAIT_IN_FLIGHT", "work left to a live reasoner is not a stall: {f}");
            }
        }
        assert!(sw.stats.tier_skips > 0);
        assert_eq!(sw.stats.issued_by_tier["heavy_reasoner"], 1);
        assert_eq!(sw.stats.issued_by_tier_kind["heavy_reasoner/REVOKE_WITHDRAWN"], 1);
        // a standard worker still takes anything (the default, as before)
        assert_eq!(WorkerTier::parse("standard"), Some(WorkerTier::Standard));
        let bad = sw.handle("acquire_directive", &json!({"agent_id": "x", "tier": "turbo", "now_ms": 9})).unwrap();
        assert_eq!(bad["code"], "BAD_TIER");
    }

    #[test]
    fn fast_workers_take_heavy_work_when_no_reasoner_is_alive() {
        // never registered: fast_cheap behaves as standard
        let mut sw = swarm_after_erratum(0);
        let f = acquire_as(&mut sw, "f", "fast_cheap", 5);
        assert_eq!(f["frame"]["kind"], "REVOKE_WITHDRAWN");
        // registered, then silent for longer than heavy_alive_ms without a lease: gone
        let mut sw = swarm_after_erratum(0);
        let h = acquire_as(&mut sw, "h", "heavy_reasoner", 5);
        sw.handle("release_lease", &json!({"lease_id": h["lease_id"], "agent_id": "h", "now_ms": 6})).unwrap();
        let late = 5 + sw.cfg.heavy_alive_ms + 1;
        assert!(!sw.heavy_alive(late));
        let f = acquire_as(&mut sw, "f", "fast_cheap", late);
        assert_eq!(f["status"], "DIRECTIVE");
        assert!(lease_has_heavy_work(&sw, &f), "{f}");
    }

    #[test]
    fn a_tiered_swarm_reaches_the_root_of_an_untiered_one() {
        let finish = |sw: &mut SwarmSession, tiers: &[&str]| -> String {
            sw.cfg.auto_close_p2a = true;
            let mut now = 100_000u64;
            for _ in 0..100 {
                let mut wave = Vec::new();
                for (i, t) in tiers.iter().enumerate() {
                    now += 1;
                    let r = acquire_as(sw, &format!("a{i}"), t, now);
                    match r["status"].as_str().unwrap() {
                        "COMPLETE" => return r["state_root"].as_str().unwrap().to_string(),
                        "DIRECTIVE" => wave.push(r),
                        "WAIT_IN_FLIGHT" => {}
                        other => panic!("{other}: {r}"),
                    }
                }
                for r in &wave {
                    now += 1;
                    assert_eq!(work(sw, r, now)["status"], "COMMITTED");
                }
            }
            panic!("no completion")
        };
        let plain = finish(&mut swarm_after_erratum(0), &["standard", "standard", "standard"]);
        let mut sw = swarm_after_erratum(0);
        let tiered = finish(&mut sw, &["heavy_reasoner", "fast_cheap", "fast_cheap"]);
        assert_eq!(tiered, plain);
        let by_tier = &sw.stats.issued_by_tier;
        assert!(by_tier.contains_key("heavy_reasoner") && by_tier.contains_key("fast_cheap"), "{by_tier:?}");
    }

    #[test]
    fn erratum_makes_in_flight_leases_stale_and_guards_revocations() {
        let mut sw = swarm(false, LockMode::SharedPremise);
        let l1 = acquire(&mut sw, "a", 0);
        let c1 = work(&mut sw, &l1, 1);
        let u1_ev = format!("@{}", c1["results"][0]["node"].as_str().unwrap());
        let x = acquire(&mut sw, "a", 2);
        assert_eq!(x["frame"]["kind"], "EXTRACT_PARTNER");
        work(&mut sw, &x, 3);
        // svc_002 now gets a FORMALIZE with the D.1 fact as its partner premise; svc_003 a FORMALIZE of U.3
        let p = acquire(&mut sw, "b", 4);
        assert_eq!((p["frame"]["target"].as_str(), p["frame"]["kind"].as_str()), (Some("svc_002"), Some("FORMALIZE")));
        assert_eq!(p["contract"]["required_premises"].as_array().unwrap().len(), 1);
        let u3 = acquire(&mut sw, "c", 4);
        assert_eq!(u3["frame"]["target"], "svc_003");
        let put = sw.handle("post_erratum", &json!({"doc_id": "erratum", "erratum_text": ERRATUM, "now_ms": 5})).unwrap();
        assert_eq!(put["visible_docs"], json!(["erratum", "policy"]));
        // the erratum withdrew U.3 under the svc_003 lease
        let s3 = work(&mut sw, &u3, 6);
        assert_eq!((s3["status"].as_str(), s3["code"].as_str()), (Some("STALE_LEASE"), Some("STALE_LEASE_SEGMENT_WITHDRAWN")));
        // P0: revoke the D.1 evidence. A revocation the directive does not list is refused.
        let rv = acquire(&mut sw, "d", 7);
        assert_eq!(rv["frame"]["kind"], "REVOKE_WITHDRAWN");
        let listed: Vec<Value> = oracle(&rv["frame"]).into_iter().filter(|e| e["op"] == "revoke_evidence").collect();
        assert_eq!(listed.len(), 1);
        let bad = submit(&mut sw, &rv, vec![json!({"op": "revoke_evidence", "target_evidence": u1_ev})], 8);
        assert_eq!(bad["error"]["code"], "DIRECTIVE_VIOLATION");
        assert_eq!(submit(&mut sw, &rv, listed, 9)["status"], "COMMITTED");
        // the svc_002 lease was cut against the D.1 fact, which has just lost its support
        let s2 = work(&mut sw, &p, 10);
        assert_eq!((s2["status"].as_str(), s2["code"].as_str()), (Some("STALE_LEASE"), Some("STALE_LEASE_PREMISE_REVOKED")));
        // the swarm still converges: R.1 restates the premise, U.3 stays withdrawn
        sw.cfg.auto_close_p2a = true;
        let (_, _) = play(&mut sw, 2);
        let st = sw.status(Some(10_000));
        assert_eq!(st["goal_states"]["CLOSED_POSITIVE"], 3, "{st}");
    }
}
