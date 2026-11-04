//! Durable opt-in wave barrier. Ordinary dispatch and threshold BUILD remain unchanged when disabled.
use super::{Dispatcher, Flags, TaskKind};
use crate::audit::{pairs, AuditStore, LinkStatus};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub mod members;

const CHECKPOINT: &str = "audit:circles";
#[derive(Debug, Clone)]
pub struct CircleConfig {
    pub wave_sections: usize,
    pub readers: Vec<String>,
    pub agent_timeout_ms: u64,
}
#[derive(Debug, Clone)]
pub struct CircleState {
    pub number: u64,
    pub phase: String,
    pub wave: BTreeMap<String, String>,
    pub started_unix_ms: u64,
}
impl CircleState {
    fn json(&self) -> Value {
        json!({"format":"r2r-circles/1","circle":self.number,"circle_phase":self.phase,
        "wave":self.wave,"started_unix_ms":self.started_unix_ms})
    }
}
fn snapshot<S: AuditStore>(s: &S) -> Value {
    let concepts = s.concepts().into_iter().filter(|c| c.selectable()).collect::<Vec<_>>();
    let cross =
        concepts.iter().filter(|c| pairs::cone(s, &s.records_of(&c.id)).into_iter().filter_map(|r| r.doc_id).collect::<BTreeSet<_>>().len() >= 2).count();
    let links = s.links();
    json!({"records":s.head(),"concepts":concepts.len(),"concepts_across_reports":cross,
        "links_proposed":links.iter().filter(|l|l.status==LinkStatus::Proposed).count(),
        "links_accepted":links.iter().filter(|l|l.status==LinkStatus::Accepted).count(),
        "links_rejected":links.iter().filter(|l|l.status==LinkStatus::Rejected).count(),"links_total":links.len()})
}
/// Fixed clockwise destination; only authors are skipped, never busy recipients.
pub fn ring_recipient(card: &crate::audit::builder::Card, readers: &[String]) -> Option<String> {
    if let Some(task) = card.ontology.as_ref().and_then(|v| v.get("review_task")) {
        return task["reviewer"].as_str().map(str::to_string);
    }
    if let Some(proposal) = &card.review {
        return card.ontology.as_ref()?["pending"].as_array()?.iter().find(|p| p["proposal"] == *proposal)?["reviewer"].as_str().map(str::to_string);
    }
    if readers.is_empty() {
        return None;
    }
    let origin = card.records.first().and_then(|r| readers.iter().position(|a| a == &r.author));
    let start = origin.map_or((card.cursor_from as usize) % readers.len(), |i| (i + 1) % readers.len());
    (0..readers.len()).map(|k| &readers[(start + k) % readers.len()]).find(|a| card.records.iter().all(|r| r.author != **a)).cloned()
}
impl Dispatcher {
    pub fn circle_status(&self) -> Option<Value> {
        self.circle.as_ref().map(|c| {
            let mut v = c.json();
            v["ring_batch"] = json!(self.ring_batch);
            v["ring_ready"] = json!(self.ring_ready);
            v["ring_started"] = json!(self.ring_started);
            v["sync_step"] = json!(self.members.epoch);
            v["excluded"] = json!(self.members.excluded);
            v["pending_rejoin"] = json!(self.members.returned);
            v
        })
    }
    pub fn circle_is_reading(&self) -> bool {
        self.circle.as_ref().is_some_and(|c| c.phase == "READ")
    }
    pub fn circle_is_refining(&self) -> bool {
        self.circle.as_ref().is_some_and(|c| c.phase == "REFINE")
    }
    pub(super) fn circles_final(&self) -> bool {
        self.cfg.circles.is_none() || self.circle.as_ref().is_some_and(|c| c.phase == "FINAL")
    }
    pub fn circle_tag(&self, mut out: Value) -> Value {
        if let Some(c) = &self.circle {
            out["circle"] = json!(c.number);
            out["circle_phase"] = json!(c.phase);
            out["sync_step"] = json!(self.members.epoch);
        }
        out
    }
    pub(super) fn circle_allows(&self, kind: TaskKind, key: &str, agent: &str) -> bool {
        if self.cfg.circles.is_none() {
            return true;
        }
        let Some(c) = &self.circle else { return false };
        if self.members.excluded.contains(agent) {
            return false;
        }
        match c.phase.as_str() {
            "READ" => {
                kind == TaskKind::Request
                    || (self.cfg.versions && matches!(kind, TaskKind::VerifyLink | TaskKind::ResolveConflict))
                    || (matches!(kind, TaskKind::Extend | TaskKind::Change)
                        && c.wave.get(key).is_some_and(|owner| self.replacement(owner, None).as_deref() == Some(agent)))
            }
            "BUILD" => {
                if kind == TaskKind::Build {
                    self.assigned_build(key, agent)
                } else {
                    matches!(kind, TaskKind::VerifyLink | TaskKind::ResolveConflict)
                        && (self.build_offer.is_empty() || !self.cfg.circles.as_ref().expect("circle config").readers.iter().any(|a| a == agent))
                }
            }
            // only the checks of the refiner's links run while it refines; the swarm waits at the barrier
            "REFINE" => matches!(kind, TaskKind::VerifyLink | TaskKind::ResolveConflict),
            "FINAL" => {
                if !self.build_offer.is_empty() && self.cfg.circles.as_ref().expect("circle config").readers.iter().any(|a| a == agent) {
                    kind == TaskKind::Build && self.assigned_build(key, agent)
                } else {
                    true
                }
            }
            _ => false,
        }
    }
    pub fn offer_ring_builds(&mut self, batch: u64, cards: Vec<crate::audit::builder::Card>) {
        if self.ring_batch != Some(batch) {
            self.ring_batch = Some(batch);
            self.ring_ready.clear();
            self.ring_started = false;
        }
        self.build_offer = cards;
    }
    pub fn set_ring_order(&mut self, order: Vec<String>) {
        self.ring_order = Some(order);
    }
    pub fn ring_started(&self) -> bool {
        self.ring_started
    }
    pub(super) fn arrive_at_ring(&mut self, agent: &str) -> bool {
        let Some(cfg) = &self.cfg.circles else { return true };
        if self.circle_is_reading() || self.build_offer.is_empty() || !cfg.readers.iter().any(|a| a == agent) {
            return true;
        }
        if self.members.excluded.contains(agent) {
            self.members.returned.insert(agent.to_string());
            return false;
        }
        self.ring_ready.insert(agent.to_string());
        if cfg.readers.iter().filter(|a| !self.members.excluded.contains(*a)).all(|a| self.ring_ready.contains(a)) {
            self.ring_started = true;
        }
        self.ring_started
    }
    fn assigned_build(&self, key: &str, agent: &str) -> bool {
        self.ring_started
            && self
                .build_offer
                .iter()
                .find(|c| key == format!("build:{}", c.card_id))
                .and_then(|c| {
                    let primary = ring_recipient(c, self.ring_order.as_ref().unwrap_or(&self.cfg.circles.as_ref().expect("circle config").readers))?;
                    self.replacement(&primary, Some(c)).filter(|who| !crate::audit::builder::review_exclusions(c).contains(who))
                })
                .as_deref()
                == Some(agent)
    }
    /// A healthy fixed neighbor is never bypassed. Only excluded destinations can fail over to a free non-author.
    fn replacement(&self, primary: &str, card: Option<&crate::audit::builder::Card>) -> Option<String> {
        if !self.members.excluded.contains(primary) {
            return Some(primary.to_string());
        }
        let cfg = self.cfg.circles.as_ref()?;
        let readers = self.ring_order.as_ref().unwrap_or(&cfg.readers);
        let start = readers.iter().position(|a| a == primary).unwrap_or(0);
        (1..=readers.len())
            .map(|i| &readers[(start + i) % readers.len()])
            .find(|a| {
                !self.members.excluded.contains(*a)
                    && !self.leases.values().any(|l| &l.agent == *a)
                    && card.is_none_or(|c| c.records.iter().all(|r| r.author != **a) && !crate::audit::builder::review_exclusions(c).contains(*a))
            })
            .cloned()
    }
    fn wave<S: AuditStore>(&self, s: &S, number: u64) -> BTreeMap<String, String> {
        let cfg = self.cfg.circles.as_ref().expect("circle config");
        self.open_work(s, &Flags::of(s))
            .into_iter()
            .filter(|w| matches!(w.0, TaskKind::Extend | TaskKind::Change))
            .take(cfg.wave_sections)
            .enumerate()
            .map(|(i, w)| (w.1, cfg.readers[(i + (number as usize - 1)) % cfg.readers.len()].clone()))
            .collect()
    }
    fn save_circle<S: AuditStore>(&mut self, s: &mut S, next: CircleState) -> Result<(), Value> {
        let mut context = next.json();
        context["snapshot"] = snapshot(s);
        let id = format!("circle:{}", crate::hash::to_hex(&crate::hash::sha256(crate::jcs::to_jcs(&context).as_bytes())));
        let ck = json!({"key":CHECKPOINT,"from":0,"to":0,"context":context});
        match s.submit_operations_id(&id, "kernel", &[], Some(ck)) {
            Ok(r) if r["checkpointed"] == true && r["error"].is_null() => {
                self.circle = Some(next);
                Ok(())
            }
            Ok(r) => Err(json!({"code":"CIRCLE_CHECKPOINT_REFUSED","store":r})),
            Err(e) => Err(e.to_json()),
        }
    }
    /// Called under the server lock. It expires leases first; a repaired or expired unclosed reading stays in its wave.
    pub fn advance_circles<S: AuditStore>(&mut self, s: &mut S, builder_caught_up: bool, now: u64, unix_ms: u64) -> Result<(), Value> {
        let Some(cfg) = self.cfg.circles.clone() else { return Ok(()) };
        if cfg.wave_sections == 0 || cfg.readers.is_empty() || cfg.agent_timeout_ms == 0 {
            return Err(json!({"code":"BAD_CIRCLE_CONFIG"}));
        }
        self.recover_members(s)?;
        self.expire(now);
        self.revalidate(s, &Flags::of(s));
        let errors = self.persist_unresolved(s);
        if !errors.is_empty() {
            return Err(json!({"code":"CIRCLE_OUTCOMES_NOT_DURABLE","errors":errors}));
        }
        if self.circle.is_none() {
            if let Some(ck) = s.checkpoint(CHECKPOINT) {
                let v = &ck["context"];
                let phase = v["circle_phase"]
                    .as_str()
                    .filter(|x| matches!(*x, "READ" | "BUILD" | "REFINE" | "FINAL"))
                    .ok_or_else(|| json!({"code":"BAD_CIRCLE_PHASE"}))?;
                if v["format"] != "r2r-circles/1" {
                    return Err(json!({"code":"BAD_CIRCLE_FORMAT"}));
                }
                let wave = v["wave"]
                    .as_object()
                    .ok_or_else(|| json!({"code":"BAD_CIRCLE_WAVE"}))?
                    .iter()
                    .map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect::<Option<BTreeMap<_, _>>>()
                    .ok_or_else(|| json!({"code":"BAD_CIRCLE_WAVE"}))?;
                if wave.values().any(|a| !cfg.readers.contains(a)) {
                    return Err(json!({"code":"CIRCLE_READERS_CHANGED"}));
                }
                self.circle = Some(CircleState {
                    number: v["circle"].as_u64().filter(|n| *n > 0).ok_or_else(|| json!({"code":"BAD_CIRCLE_NUMBER"}))?,
                    phase: phase.into(),
                    wave,
                    started_unix_ms: v["started_unix_ms"].as_u64().ok_or_else(|| json!({"code":"BAD_CIRCLE_TIME"}))?,
                });
            } else {
                return self.save_circle(s, CircleState { number: 1, phase: "READ".into(), wave: self.wave(s, 1), started_unix_ms: unix_ms });
            }
        }
        let c = self.circle.clone().expect("circle restored");
        let work = self.open_work(s, &Flags::of(s));
        let checks_done = !work.iter().any(|w| matches!(w.0, TaskKind::VerifyLink | TaskKind::ResolveConflict))
            && !self.leases.values().any(|l| matches!(l.kind, TaskKind::VerifyLink | TaskKind::ResolveConflict));
        let after_build = |d: &Self, c: CircleState| {
            let wave = d.wave(s, c.number + 1);
            let phase = if wave.is_empty() && !work.iter().any(|w| w.0 == TaskKind::Request) { "FINAL" } else { "READ" };
            CircleState { number: if phase == "FINAL" { c.number } else { c.number + 1 }, phase: phase.into(), wave, started_unix_ms: unix_ms }
        };
        let next = match c.phase.as_str() {
            "READ"
                if !work.iter().any(|w| c.wave.contains_key(&w.1) || w.0 == TaskKind::Request)
                    && !self.leases.values().any(|l| matches!(l.kind, TaskKind::Extend | TaskKind::Change | TaskKind::Request)) =>
            {
                if self.cfg.versions {
                    Some(after_build(self, c))
                } else {
                    Some(CircleState { phase: "BUILD".into(), started_unix_ms: unix_ms, ..c })
                }
            }
            "BUILD" if builder_caught_up && checks_done && !self.leases.values().any(|l| l.kind == TaskKind::Build) => {
                if self.cfg.circle_refiner.is_some() {
                    Some(CircleState { phase: "REFINE".into(), started_unix_ms: unix_ms, ..c })
                } else {
                    Some(after_build(self, c))
                }
            }
            "REFINE"
                if (self.refiner_caught_up && checks_done)
                    || self.cfg.refine_budget_ms.is_some_and(|budget| unix_ms.saturating_sub(c.started_unix_ms) >= budget) =>
            {
                Some(after_build(self, c))
            }
            _ => None,
        };
        if let Some(next) = next {
            self.save_circle(s, next)?;
        }
        Ok(())
    }
    /// Vocabulary, never evidence or a semantic assertion. Fixed bound and deterministic relevance/order.
    pub(super) fn known_concepts<S: AuditStore>(&self, s: &S, section: &str) -> String {
        let query = format!("{} {}", section, self.questions.iter().flat_map(|q| q.about.iter()).cloned().collect::<Vec<_>>().join(" ")).to_lowercase();
        let tokens = |v: &str| v.split(|c: char| !c.is_alphanumeric()).filter(|w| w.chars().count() >= 3).map(str::to_lowercase).collect::<BTreeSet<_>>();
        let want = tokens(&query);
        let mut cs = s
            .concepts()
            .into_iter()
            .filter(|c| c.selectable())
            .filter_map(|c| {
                let names = std::iter::once(&c.name).chain(&c.aliases).collect::<Vec<_>>();
                let hits = names.iter().map(|n| tokens(n).intersection(&want).count()).sum::<usize>();
                (hits > 0).then_some((hits, c))
            })
            .collect::<Vec<_>>();
        cs.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.id.cmp(&b.1.id)));
        cs.truncate(40);
        let lines = cs
            .iter()
            .map(|(_, c)| {
                if s.ontology_revision_state().is_some() {
                    format!("  {} {} status={} aliases={}", c.id.short(), c.name, c.status, serde_json::to_string(&c.aliases).expect("string aliases"))
                } else {
                    format!("  {} {} aliases={}", c.id.short(), c.name, serde_json::to_string(&c.aliases).expect("string aliases"))
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "KNOWN CONCEPTS (shared vocabulary only, not evidence; use a name only for the same thing and scope):\n{}\n",
            if lines.is_empty() { "  (none)" } else { &lines }
        )
    }
}
