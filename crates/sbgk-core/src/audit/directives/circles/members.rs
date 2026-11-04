//! Timeout is the sole exception to the fixed ring. Durable exclusion precedes failover; fresh readiness joins at a new epoch.
use crate::audit::{
    directives::{Dispatcher, TaskKind},
    AuditStore,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
const KEY: &str = "audit:ring-members";
#[derive(Debug, Default)]
pub struct Membership {
    pub epoch: u64,
    pub excluded: BTreeSet<String>,
    pub returned: BTreeSet<String>,
    loaded: bool,
    dirty: bool,
    binding: Value,
    started_unix_ms: u64,
    readiness_since: Option<u64>,
    contacts: BTreeMap<String, u64>,
    events: Vec<Value>,
}
impl Dispatcher {
    pub fn ring_readers_busy(&self) -> bool {
        self.cfg.circles.as_ref().is_some_and(|cfg| self.leases.values().any(|l| cfg.readers.contains(&l.agent)))
    }
    pub(in crate::audit::directives) fn received_response(&mut self, task: &str, now: u64) {
        if self.cfg.circles.is_some() {
            let until = now.saturating_add(self.leases.get(task).map(|l| self.lease_ms_for(l.kind)).unwrap_or_else(|| self.lease_ms()));
            if let Some(l) = self.leases.get_mut(task) {
                l.expires_ms = until;
            }
        }
    }
    pub(in crate::audit::directives) fn lease_ms_for(&self, kind: TaskKind) -> u64 {
        if kind == TaskKind::Summarize {
            self.cfg.answer_timeout_ms.unwrap_or_else(|| self.lease_ms())
        } else {
            self.lease_ms()
        }
    }
    pub(in crate::audit::directives) fn lease_ms(&self) -> u64 {
        self.cfg.circles.as_ref().map_or(self.cfg.ttl_ms, |c| c.agent_timeout_ms)
    }
    pub fn recover_members<S: AuditStore>(&mut self, s: &S) -> Result<(), Value> {
        if self.cfg.circles.is_none() || self.members.loaded {
            return Ok(());
        }
        if let Some(ck) = s.checkpoint(KEY) {
            let c = &ck["context"];
            if c["format"] != "r2r-ring-members/1" {
                return Err(json!({"code":"BAD_RING_MEMBERS"}));
            }
            self.members.epoch = c["epoch"].as_u64().ok_or_else(|| json!({"code":"BAD_RING_EPOCH"}))?;
            self.members.excluded = c["excluded"]
                .as_array()
                .and_then(|xs| xs.iter().map(|v| v.as_str().map(str::to_string)).collect())
                .ok_or_else(|| json!({"code":"BAD_RING_MEMBERS"}))?;
            let cfg = self.cfg.circles.as_ref().expect("circle config");
            if self.members.excluded.iter().any(|a| !cfg.readers.contains(a)) {
                return Err(json!({"code":"BAD_RING_MEMBER_ID"}));
            }
            self.members.binding = c["binding"].clone();
            self.members.started_unix_ms = c["started_unix_ms"].as_u64().ok_or_else(|| json!({"code":"BAD_RING_TIME"}))?;
            self.members.events = c["events"].as_array().ok_or_else(|| json!({"code":"BAD_RING_EVENTS"}))?.clone();
        }
        self.members.loaded = true;
        Ok(())
    }
    pub fn persist_members<S: AuditStore>(&mut self, s: &mut S) -> Result<(), Value> {
        if self.cfg.circles.is_none() || !self.members.dirty {
            return Ok(());
        }
        let c = json!({"format":"r2r-ring-members/1","epoch":self.members.epoch,"excluded":self.members.excluded,
            "binding":self.members.binding,"started_unix_ms":self.members.started_unix_ms,"events":self.members.events});
        let hash = crate::hash::to_hex(&crate::hash::sha256(crate::jcs::to_jcs(&c).as_bytes()));
        let ck = json!({"key":KEY,"from":0,"to":0,"context":c});
        match s.submit_operations_id(&format!("ring-members:{hash}"), "kernel", &[], Some(ck)) {
            Ok(r) if r["checkpointed"] == true && r["error"].is_null() => {
                self.members.dirty = false;
                Ok(())
            }
            Ok(r) => Err(json!({"code":"RING_CHECKPOINT_REFUSED","store":r})),
            Err(e) => Err(e.to_json()),
        }
    }
    pub(in crate::audit::directives) fn exclude_member(&mut self, agent: &str, task: &str, reason: &str) {
        let Some(cfg) = &self.cfg.circles else { return };
        if !cfg.readers.iter().any(|a| a == agent) || !self.members.excluded.insert(agent.to_string()) {
            return;
        }
        self.members.returned.remove(agent);
        self.members.events.push(json!({"kind":"EXCLUDED","agent":agent,"task":task,"reason":reason,"sync_step":self.members.epoch}));
        self.members.dirty = true;
    }
    pub(in crate::audit::directives) fn member_contact(&mut self, agent: &str, now: u64) {
        if self.cfg.circles.is_some() {
            self.members.contacts.insert(agent.to_string(), now);
        }
    }
    pub(in crate::audit::directives) fn membership_pending(&self) -> bool {
        self.cfg.circles.is_some() && self.members.dirty
    }
    /// A shift boundary is durable. Recovered agents are admitted only after old active leases finish, never mid-step.
    pub fn prepare_ring<S: AuditStore>(&mut self, s: &mut S, now: u64, unix_ms: u64) -> Result<(), Value> {
        let Some(cfg) = self.cfg.circles.clone() else { return Ok(()) };
        self.recover_members(s)?;
        let Some(circle) = &self.circle else { return Ok(()) };
        let binding = json!([circle.number, circle.phase, self.ring_batch]);
        let changed = binding != self.members.binding;
        let readiness_since = *self.members.readiness_since.get_or_insert(unix_ms);
        let can_rejoin = !self.members.returned.is_empty() && self.leases.is_empty();
        if changed || can_rejoin {
            self.members.epoch = self.members.epoch.checked_add(1).ok_or_else(|| json!({"code":"RING_EPOCH_OVERFLOW"}))?;
            self.members.binding = binding;
            self.members.started_unix_ms = unix_ms;
            self.members.readiness_since = Some(unix_ms);
            self.ring_ready.clear();
            self.ring_started = false;
            for agent in std::mem::take(&mut self.members.returned) {
                if self.members.excluded.remove(&agent) {
                    self.members.events.push(json!({"kind":"REJOINED","agent":agent,"sync_step":self.members.epoch}));
                }
            }
            self.members.contacts.clear();
            self.members.events.push(json!({"kind":"SHIFT_BEGIN","sync_step":self.members.epoch,"binding":self.members.binding}));
            self.members.dirty = true;
        }
        let active = cfg.readers.iter().filter(|a| !self.members.excluded.contains(*a)).cloned().collect::<Vec<_>>();
        let reading = self.circle_is_reading();
        let open = self.open_work(s, &super::super::Flags::of(s));
        for agent in active {
            if self.leases.values().any(|l| l.agent == agent) {
                continue;
            }
            let absent = if reading {
                self.circle.as_ref().is_some_and(|c| c.wave.iter().any(|(key, owner)| owner == &agent && open.iter().any(|w| &w.1 == key)))
            } else {
                !self.build_offer.is_empty() && !self.ring_started && !self.ring_ready.contains(&agent)
            };
            let elapsed = self
                .members
                .contacts
                .get(&agent)
                .map_or_else(|| unix_ms.saturating_sub(if changed || can_rejoin { unix_ms } else { readiness_since }), |t| now.saturating_sub(*t));
            if absent && elapsed >= cfg.agent_timeout_ms {
                self.exclude_member(&agent, "", "READINESS_TIMEOUT");
            }
        }
        self.persist_members(s)
    }
    /// Authenticated self-report of a transport/model timeout. No subject can evict another subject.
    pub fn timeout_task<S: AuditStore>(&mut self, s: &mut S, task: &str, agent: &str) -> Value {
        if self.cfg.circles.is_none() && self.cfg.agent_attempts.is_none() {
            return json!({"status":"error","code":"CIRCLES_REQUIRED"});
        }
        let Some(l) = self.leases.get(task).cloned() else {
            return json!({"status":"STALE_TASK","task_id":task});
        };
        if l.agent != agent {
            return json!({"status":"error","code":"TASK_NOT_OWNED","task_id":task});
        }
        // a RELATE turn's reading is stored: its timeout records no failure of the reading's key (claude-reviewer's RV-02 of 8509eb18)
        if self.cfg.agent_attempts.is_some() && !l.relate {
            if let Err(error) = self.agent_failure_record(s, &l.key, task, agent, "MODEL_AGENT_FAILURE") {
                return json!({"status":"error","code":"AGENT_FAILURE_CHECKPOINT_REFUSED","error":error});
            }
            if self.cfg.circles.is_none() {
                self.leases.remove(task);
                return json!({"status":"RELEASED","task_id":task,"timed_out":true,"unresolved":self.unresolved.contains(&l.key),"failures":self.failures.get(&l.key)});
            }
        }
        let reader = self.cfg.circles.as_ref().is_some_and(|c| c.readers.iter().any(|a| a == agent));
        if !reader {
            if self.cfg.agent_attempts.is_some() {
                self.leases.remove(task);
                return json!({"status":"RELEASED","task_id":task,"unresolved":self.unresolved.contains(&l.key)});
            }
            self.mark_failed(task);
            return self.release_durable(s, task, agent);
        }
        self.exclude_member(agent, task, "MODEL_TIMEOUT");
        if let Err(e) = self.persist_members(s) {
            return json!({"status":"error","code":"RING_CHECKPOINT_REFUSED","error":e});
        }
        self.leases.remove(task);
        json!({"status":"RELEASED","task_id":task,"timed_out":true,"excluded_until_next_shift":true})
    }
    pub(in crate::audit::directives) fn expire_circle_lease(&mut self, agent: &str, task: &str, kind: TaskKind) -> bool {
        let reader = self.cfg.circles.as_ref().is_some_and(|c| c.readers.iter().any(|a| a == agent));
        if reader {
            self.exclude_member(agent, task, kind.name());
        }
        reader
    }
}
