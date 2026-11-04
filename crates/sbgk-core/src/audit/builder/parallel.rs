//! Durable disjoint card queue with synchronous ring batches. A batch never bypasses a busy recipient.
//! Allocation and batch membership are persisted before issue; independent close markers define the longest closed prefix.
use super::{digest, Builder, BuilderConfig, BuilderStats, Card};
use crate::audit::{directives::circles::ring_recipient, pairs::PairCandidate, AuditStore};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
const CATALOG: &str = "builder:pool";
/// The pool's frozen pair plan (pool format 2), under a key named by its digest. A checkpoint key can be written again, and a
/// write retried under its earlier submission returns the earlier receipt without writing (Codex review of 0b9d30cc, POOL-B01:
/// plan A, then plan B under one key, then A again left B in place); a key named by its content holds only that content.
pub fn plan_key(digest: &str) -> String {
    format!("builder:pool:plan:{digest}")
}
fn closed_key(id: &str) -> String {
    format!("builder:pool:closed:{id}")
}
/// A chunk of pair-card pairs (pool format 2), under a key named by its digest like the plan.
fn pairs_key(digest: &str) -> String {
    format!("builder:pool:pairs:{digest}")
}
#[derive(Debug)]
pub struct ParallelBuilder {
    cfg: BuilderConfig,
    readers: Vec<String>,
    catalog: Vec<Value>,
    pairs: Option<Vec<PairCandidate>>,
    batch: u64,
    workers: BTreeMap<String, Builder>,
    review_planned: BTreeSet<u64>,
    /// Pool format 2: the digest of the written plan, the digests of the written pair chunks in order, and for each pair card
    /// whose pair is written the chunk that holds it.
    plan_written: Option<String>,
    pair_chunks: Vec<String>,
    pairs_written: BTreeMap<String, usize>,
}
impl ParallelBuilder {
    pub fn new(cfg: BuilderConfig, readers: Vec<String>) -> Self {
        Self {
            cfg,
            readers,
            catalog: vec![],
            pairs: None,
            batch: 0,
            workers: BTreeMap::new(),
            review_planned: BTreeSet::new(),
            plan_written: None,
            pair_chunks: vec![],
            pairs_written: BTreeMap::new(),
        }
    }
    pub fn batch(&self) -> u64 {
        self.batch
    }
    fn closed<S: AuditStore>(s: &S, spec: &Value) -> bool {
        Self::closed_with(s, Self::failures(s).as_ref(), spec)
    }
    /// The agent-failure state a closure check reads, once per call (`None` with the policy off): read per entry, every check of a
    /// catalog of 1 000 cards cloned it again (01.11.2026 measurement: `caught_up` took 1.4-3.8 s at the end of a live run).
    fn failures<S: AuditStore>(s: &S) -> Option<Value> {
        super::super::agent_failures::limit(s).map(|_| super::super::agent_failures::state(s))
    }
    /// `closed` on an agent-failure state read once: `agent_failures::unresolved_card` on the same state, then the close marker.
    fn closed_with<S: AuditStore>(s: &S, failures: Option<&Value>, spec: &Value) -> bool {
        let Some(id) = spec["id"].as_str() else { return false };
        if let Some(f) = failures {
            let e = &f["work"][format!("build:{id}")];
            if e["unresolved"] == true && e["range"] == json!([spec["from"].as_u64().unwrap_or(0), spec["to"].as_u64().unwrap_or(0)]) {
                return true;
            }
        }
        s.checkpoint(&closed_key(id))
            .is_some_and(|c| c["context"]["card_id"] == id && c["context"]["range_from"] == spec["from"] && c["context"]["range_to"] == spec["to"])
    }
    /// `closed` of every catalog entry, by position, on one read of the agent-failure state.
    fn closed_flags<S: AuditStore>(&self, s: &S) -> Vec<bool> {
        let failures = Self::failures(s);
        self.catalog.iter().map(|v| Self::closed_with(s, failures.as_ref(), v)).collect()
    }
    fn worker<S: AuditStore>(&self, s: &S, spec: &Value) -> Result<Builder, Value> {
        let from = spec["from"].as_u64().ok_or_else(|| json!({"code":"BAD_POOL_RANGE"}))?;
        let to = spec["to"].as_u64().ok_or_else(|| json!({"code":"BAD_POOL_RANGE"}))?;
        let id = spec["id"].as_str().ok_or_else(|| json!({"code":"BAD_POOL_ID"}))?;
        let mut b = Builder::new(self.cfg);
        let card = if spec["ontology_review"].is_object() {
            b.cursor = from;
            b.ontology_review_card(s, &spec["ontology_review"])
        } else if let Some(proposal) = spec["revision"].as_str() {
            b.cursor = from;
            b.revision_card(s, Some(proposal))
        } else if spec["pair"].is_null() {
            b.cursor = from;
            b.cut_to = Some(to);
            b.next_card(s)
        } else {
            let pair = PairCandidate::from_json(&spec["pair"]).ok_or_else(|| json!({"code":"BAD_POOL_PAIR"}))?;
            b.pairs = Some(vec![pair]);
            b.pairs_ready = true;
            b.pair_card(s)
        }
        .ok_or_else(|| json!({"code":"MISSING_POOL_CARD","card":id}))?;
        if card.card_id != id
            || card.cursor_from != from
            || card.cursor_to != to
            || ring_recipient(&card, &crate::audit::quality::ring(s, &self.readers, spec["circle"].as_u64().unwrap_or(1))).as_deref()
                != spec["recipient"].as_str()
        {
            return Err(json!({"code":"POOL_CARD_CHANGED","card":id}));
        }
        b.close_scope = Some((closed_key(id), json!({"circle":spec["circle"],"circle_phase":spec["circle_phase"],"ring_batch":spec["batch"]})));
        Ok(b)
    }
    pub fn recover<S: AuditStore>(&mut self, s: &S) -> Result<(), Value> {
        self.catalog.clear();
        self.workers.clear();
        self.pairs = None;
        self.review_planned.clear();
        self.batch = 0;
        self.plan_written = None;
        self.pair_chunks.clear();
        self.pairs_written.clear();
        if let Some(c) = s.checkpoint(CATALOG) {
            let v = &c["context"];
            let compact = match v["format"].as_str() {
                Some("r2r-builder-pool/1") => false,
                Some("r2r-builder-pool/2") => true,
                _ => return Err(json!({"code":"BAD_POOL_FORMAT"})),
            };
            if let Some(planned) = v.get("ontology_review_circles") {
                self.review_planned =
                    planned.as_array().and_then(|xs| xs.iter().map(Value::as_u64).collect()).ok_or_else(|| json!({"code":"BAD_REVIEW_PLAN"}))?;
            }
            self.catalog = v["cards"].as_array().ok_or_else(|| json!({"code":"BAD_POOL_CATALOG"}))?.clone();
            self.batch = v["batch"].as_u64().ok_or_else(|| json!({"code":"BAD_POOL_BATCH"}))?;
            let plan = if compact { self.read_written(s, v)? } else { v["pairs"].clone() };
            if !plan.is_null() {
                self.pairs =
                    Some(plan.as_array().and_then(|ps| ps.iter().map(PairCandidate::from_json).collect()).ok_or_else(|| json!({"code":"BAD_POOL_PAIRS"}))?);
            }
        }
        let mut ids = BTreeSet::new();
        let mut end = 0;
        let mut recipients = BTreeSet::new();
        let failures = Self::failures(s);
        for spec in &self.catalog {
            let id = spec["id"].as_str().ok_or_else(|| json!({"code":"BAD_POOL_ID"}))?;
            if !ids.insert(id)
                || spec["circle"].as_u64().is_none()
                || !matches!(spec["circle_phase"].as_str(), Some("BUILD" | "FINAL"))
                || !spec["recipient"].as_str().is_some_and(|v| self.readers.iter().any(|r| r == v))
            {
                return Err(json!({"code":"BAD_POOL_CATALOG"}));
            }
            if spec["pair"].is_null() && spec["revision"].is_null() && spec["ontology_review"].is_null() {
                if spec["from"].as_u64() != Some(end) || spec["to"].as_u64().is_none_or(|to| to <= end || to > s.head()) {
                    return Err(json!({"code":"BAD_POOL_RANGE"}));
                }
                end = spec["to"].as_u64().expect("validated range");
            }
            if let Some(batch) = spec["batch"].as_u64() {
                if batch > self.batch || (batch < self.batch && !Self::closed_with(s, failures.as_ref(), spec)) {
                    return Err(json!({"code":"UNCLOSED_OLDER_BATCH"}));
                }
                if batch == self.batch && !Self::closed_with(s, failures.as_ref(), spec) {
                    if !recipients.insert(spec["recipient"].as_str().expect("validated recipient")) {
                        return Err(json!({"code":"DUPLICATE_BATCH_RECIPIENT"}));
                    }
                    self.workers.insert(id.to_string(), self.worker(s, spec)?);
                }
            } else if !spec["batch"].is_null() {
                return Err(json!({"code":"BAD_POOL_BATCH"}));
            }
        }
        Ok(())
    }
    /// Format 2: the pair of every pair card back into the catalog from the written chunks, each checked against the digest
    /// the pool names, and the frozen plan (`null` before it froze), checked the same way.
    fn read_written<S: AuditStore>(&mut self, s: &S, v: &Value) -> Result<Value, Value> {
        let bad = || json!({"code":"BAD_POOL_PAIRS"});
        let chunks: Vec<String> = v["pair_chunks"].as_array().and_then(|xs| xs.iter().map(|x| x.as_str().map(String::from)).collect()).ok_or_else(bad)?;
        let mut pair_of = BTreeMap::new();
        for (n, want) in chunks.iter().enumerate() {
            let c = s.checkpoint(&pairs_key(want)).map(|c| c["context"].clone()).ok_or_else(bad)?;
            if digest(&c) != *want {
                return Err(bad());
            }
            for (id, pair) in c["pairs"].as_object().ok_or_else(bad)? {
                pair_of.insert(id.clone(), (n, pair.clone()));
            }
        }
        for card in &mut self.catalog {
            if !card["pair"].is_null() {
                let id = card["id"].as_str().ok_or_else(|| json!({"code":"BAD_POOL_ID"}))?;
                card["pair"] = pair_of.get(id).map(|(_, p)| p.clone()).ok_or_else(bad)?;
            }
        }
        self.pairs_written = pair_of.into_iter().map(|(id, (n, _))| (id, n)).collect();
        self.pair_chunks = chunks;
        let Some(want) = v["plan"].as_str() else { return Ok(Value::Null) };
        let plan = s.checkpoint(&plan_key(want)).map(|c| c["context"].clone()).ok_or_else(bad)?;
        if digest(&plan) != want {
            return Err(bad());
        }
        self.plan_written = Some(want.to_string());
        Ok(plan["pairs"].clone())
    }
    fn write<S: AuditStore>(s: &mut S, key: &str, context: &Value) -> Result<(), Value> {
        let ck = json!({"key":key,"from":0,"to":0,"context":context});
        match s.submit_operations_id(&format!("pool:{}", digest(&ck)), "kernel", &[], Some(ck)) {
            // a receipt says the write was once made, the key says what it holds now: the pool names only what the key holds
            Ok(r) if r["checkpointed"] == true && r["error"].is_null() => {
                if s.checkpoint(key).is_some_and(|c| c["context"] == *context) {
                    Ok(())
                } else {
                    Err(json!({"code":"POOL_CHECKPOINT_NOT_HELD","key":key}))
                }
            }
            Ok(r) => Err(json!({"code":"POOL_CHECKPOINT_REFUSED","store":r})),
            Err(e) => Err(e.to_json()),
        }
    }
    /// Pool format 2 (01.11.2026 measurement: 96-98% of a live run's journal was this checkpoint, rewritten whole at every
    /// batch with the frozen pair plan in it twice, as the plan and in each pair card): the plan and the pair of each pair card
    /// are written once, in their own checkpoints, before the pool that names them by digest. A pool read from format 1 writes
    /// them all at its first save.
    fn save<S: AuditStore>(
        &mut self,
        s: &mut S,
        cards: &[Value],
        pairs: &Option<Vec<PairCandidate>>,
        batch: u64,
        planned: &BTreeSet<u64>,
    ) -> Result<(), Value> {
        let mut plan = self.plan_written.clone();
        if let (None, Some(ps)) = (&plan, pairs) {
            let context = json!({"format":"r2r-builder-pool-plan/1","pairs":ps.iter().map(PairCandidate::to_json).collect::<Vec<_>>()});
            let d = digest(&context);
            Self::write(s, &plan_key(&d), &context)?;
            plan = Some(d);
        }
        let chunk = self.pair_chunks.len();
        let fresh: BTreeMap<&str, &Value> = cards
            .iter()
            .filter(|v| !v["pair"].is_null())
            .filter_map(|v| v["id"].as_str().filter(|id| !self.pairs_written.contains_key(*id)).map(|id| (id, &v["pair"])))
            .collect();
        let mut chunks = self.pair_chunks.clone();
        if !fresh.is_empty() {
            let context = json!({"format":"r2r-builder-pool-pairs/1","pairs":fresh});
            let d = digest(&context);
            Self::write(s, &pairs_key(&d), &context)?;
            chunks.push(d);
        }
        let compact: Vec<Value> = cards
            .iter()
            .map(|v| {
                let mut c = v.clone();
                if !c["pair"].is_null() {
                    let id = c["id"].as_str().unwrap_or_default();
                    c["pair"] = json!({"chunk": self.pairs_written.get(id).copied().unwrap_or(chunk)});
                }
                c
            })
            .collect();
        let mut context = json!({"format":"r2r-builder-pool/2","cards":compact,"batch":batch,"plan":plan,"pair_chunks":chunks});
        if super::ontology_review::enabled(s) {
            context["ontology_review_circles"] = json!(planned);
        }
        Self::write(s, CATALOG, &context)?;
        let fresh: Vec<String> = fresh.into_keys().map(String::from).collect();
        self.pairs_written.extend(fresh.into_iter().map(|id| (id, chunk)));
        self.pair_chunks = chunks;
        self.plan_written = plan;
        Ok(())
    }
    pub fn offers<S: AuditStore>(&mut self, s: &mut S, circle: u64, reading_done: bool) -> Result<Vec<Card>, Value> {
        self.offers_in_phase(s, circle, "BUILD", reading_done)
    }
    pub fn offers_in_phase<S: AuditStore>(&mut self, s: &mut S, circle: u64, phase: &str, reading_done: bool) -> Result<Vec<Card>, Value> {
        if self.readers.is_empty() {
            return Err(json!({"code":"NO_RING_READERS"}));
        }
        // Complete the current shift as a whole before planning or opening the next one.
        if self.open_count(s) > 0 {
            return Ok(self.open_cards(s));
        }
        let mut catalog = self.catalog.clone();
        let mut planned = self.review_planned.clone();
        // links off (`max_links` 0, the build scope `concepts`): no pair cards, which only link
        let pairs = if self.cfg.max_links == 0 {
            Some(vec![])
        } else if reading_done && self.pairs.is_none() && (!crate::audit::quality::enabled(s, "evolution_cards") || self.caught_up(s)) {
            Some(crate::audit::quality::pair_candidates(s))
        } else {
            self.pairs.clone()
        };
        let mut from = catalog
            .iter()
            .filter(|v| v["pair"].is_null() && v["revision"].is_null() && v["ontology_review"].is_null())
            .filter_map(|v| v["to"].as_u64())
            .max()
            .unwrap_or(0);
        while from < s.head() {
            let mut b = Builder::new(self.cfg);
            b.cursor = from;
            let card = b.next_card(s).ok_or_else(|| json!({"code":"POOL_CUT_MISSING"}))?;
            let recipient =
                ring_recipient(&card, &crate::audit::quality::ring(s, &self.readers, circle)).ok_or_else(|| json!({"code":"NO_NONAUTHOR_RECIPIENT"}))?;
            from = card.cursor_to;
            catalog.push(json!({"id":card.card_id,"from":card.cursor_from,"to":card.cursor_to,"pair":null,
                "circle":circle,"circle_phase":phase,"recipient":recipient,"batch":null}));
        }
        for p in super::revisions::pending(s) {
            if super::super::agent_failures::unresolved_review(s, &p["proposal"]) {
                continue;
            }
            let pid = p["proposal"].as_str().expect("proposal id");
            if catalog.iter().any(|v| v["revision"] == pid) {
                continue;
            }
            let mut b = Builder::new(self.cfg);
            b.cursor = from;
            let card = b.revision_card(s, Some(pid)).ok_or_else(|| json!({"code":"REVISION_CARD_MISSING"}))?;
            catalog.push(json!({"id":card.card_id,"from":from,"to":from,"pair":null,"revision":pid,"circle":circle,"circle_phase":phase,"recipient":p["reviewer"],"batch":null}));
        }
        if let Some(ps) = &pairs {
            // a pair's id is a SHA-256 of its JCS metadata: computed once per pair and looked up, not once per catalog entry
            let mut ids: BTreeSet<String> = catalog.iter().filter_map(|v| v["id"].as_str().map(String::from)).collect();
            for pair in ps {
                // pairs no reader may take stay in the frozen plan, named, and are never offered (EVO-01)
                if pair.metadata["kind"] == crate::audit::quality::evolution::UNASSIGNABLE || ids.contains(&pair.id()) {
                    continue;
                }
                let mut b = Builder::new(self.cfg);
                b.pairs = Some(vec![pair.clone()]);
                b.pairs_ready = true;
                let card = b.pair_card(s).ok_or_else(|| json!({"code":"POOL_PAIR_MISSING"}))?;
                let recipient =
                    ring_recipient(&card, &crate::audit::quality::ring(s, &self.readers, circle)).ok_or_else(|| json!({"code":"NO_NONAUTHOR_RECIPIENT"}))?;
                ids.insert(card.card_id.clone());
                catalog.push(json!({"id":card.card_id,"from":0,"to":0,"pair":card.pair,
                    "circle":circle,"circle_phase":phase,"recipient":recipient,"batch":null}));
            }
        }
        // One card per fixed recipient: a second card for that recipient stays queued, even if another agent is idle.
        let mut recipients = BTreeSet::new();
        let mut chosen = vec![];
        let next = self.batch + 1;
        let mut order = (0..catalog.len()).collect::<Vec<_>>();
        order.sort_by_key(|i| catalog[*i]["revision"].is_null());
        // nothing is written before the pool is saved below: one read of the agent-failure state serves every check
        let failures = Self::failures(s);
        for i in order {
            let spec = &mut catalog[i];
            if spec["batch"].is_null()
                && !Self::closed_with(s, failures.as_ref(), spec)
                && recipients.insert(spec["recipient"].as_str().expect("recipient").to_string())
            {
                spec["batch"] = json!(next);
                chosen.push(spec.clone());
            }
        }
        if chosen.is_empty() && phase == "BUILD" && super::ontology_review::enabled(s) && !planned.contains(&circle) {
            for spec in super::ontology_review::plan(s, circle, &self.readers)? {
                let mut b = Builder::new(self.cfg);
                b.cursor = from;
                let card = b.ontology_review_card(s, &spec).ok_or_else(|| json!({"code":"BAD_ONTOLOGY_REVIEW_CARD"}))?;
                catalog.push(json!({"id":card.card_id,"from":from,"to":from,"pair":null,"ontology_review":spec,"circle":circle,"circle_phase":phase,"recipient":spec["reviewer"],"batch":null}));
            }
            planned.insert(circle);
            for spec in &mut catalog {
                if spec["batch"].is_null()
                    && !Self::closed_with(s, failures.as_ref(), spec)
                    && recipients.insert(spec["recipient"].as_str().expect("recipient").to_string())
                {
                    spec["batch"] = json!(next);
                    chosen.push(spec.clone());
                }
            }
        }
        let batch = if chosen.is_empty() { self.batch } else { next };
        let pairs_changed = self.pairs.is_none() && pairs.is_some();
        if catalog != self.catalog || pairs_changed || planned != self.review_planned {
            self.save(s, &catalog, &pairs, batch, &planned)?;
            self.catalog = catalog;
            self.pairs = pairs;
            self.batch = batch;
            self.review_planned = planned;
        }
        for spec in chosen {
            self.workers.insert(spec["id"].as_str().expect("card id").to_string(), self.worker(s, &spec)?);
        }
        Ok(self.open_cards(s))
    }
    fn open_cards<S: AuditStore>(&self, s: &S) -> Vec<Card> {
        self.catalog
            .iter()
            .filter(|v| v["batch"].as_u64() == Some(self.batch) && !Self::closed(s, v))
            .filter_map(|v| self.workers.get(v["id"].as_str()?))
            .filter_map(|b| b.open.clone())
            .collect()
    }
    pub fn worker_mut(&mut self, id: &str) -> Option<&mut Builder> {
        self.workers.get_mut(id)
    }
    pub fn open_count<S: AuditStore>(&self, s: &S) -> usize {
        self.catalog.iter().filter(|v| v["batch"].as_u64() == Some(self.batch) && !Self::closed(s, v)).count()
    }
    pub fn cursor<S: AuditStore>(&self, s: &S) -> u64 {
        self.cursor_in(&self.closed_flags(s))
    }
    fn cursor_in(&self, closed: &[bool]) -> u64 {
        let mut cursor = 0;
        for (v, closed) in self.catalog.iter().zip(closed).filter(|(v, _)| v["pair"].is_null() && v["revision"].is_null() && v["ontology_review"].is_null()) {
            if v["from"].as_u64() != Some(cursor) || !closed {
                break;
            }
            cursor = v["to"].as_u64().expect("validated range");
        }
        cursor
    }
    pub fn caught_up<S: AuditStore>(&self, s: &S) -> bool {
        if super::ontology_review::enabled(s) {
            if let Some(circle) = s.checkpoint("audit:circles") {
                if circle["context"]["circle_phase"] == "BUILD" && circle["context"]["circle"].as_u64().is_some_and(|n| !self.review_planned.contains(&n)) {
                    return false;
                }
            }
        }
        if !super::revisions::pending(s).iter().all(|p| super::super::agent_failures::unresolved_review(s, &p["proposal"])) {
            return false;
        }
        // the closed entries once, and each pair's id once (01.11.2026 measurement: comparing every pair's id, recomputed, with
        // every catalog entry took 1.4-3.8 s per call at the end of a live run, and every prepare calls this)
        let closed = self.closed_flags(s);
        let closed_ids: BTreeSet<&str> = self.catalog.iter().zip(&closed).filter(|(_, c)| **c).filter_map(|(v, _)| v["id"].as_str()).collect();
        self.cursor_in(&closed) >= s.head()
            && closed.iter().all(|c| *c)
            // a pair no reader may take is never offered, so it never waits to be closed (claude-reviewer on a8d94c7, RV-01)
            && self.pairs.as_ref().is_none_or(|ps| {
                ps.iter().filter(|p| p.metadata["kind"] != crate::audit::quality::evolution::UNASSIGNABLE).all(|p| closed_ids.contains(p.id().as_str()))
            })
    }
    pub fn backlog<S: AuditStore>(&self, s: &S) -> usize {
        let closed = self.closed_flags(s);
        s.records_since(self.cursor_in(&closed))
            .iter()
            .filter(|r| {
                !crate::audit::directives::is_link_directive(&r.directive)
                    && !crate::audit::directives::is_summary_directive(&r.directive)
                    && !self.catalog.iter().zip(&closed).any(|(v, closed)| {
                        v["pair"].is_null() && v["from"].as_u64().is_some_and(|n| n < r.seq) && v["to"].as_u64().is_some_and(|n| r.seq <= n) && *closed
                    })
            })
            .count()
    }
    pub fn stats(&self) -> BuilderStats {
        let mut out = BuilderStats::default();
        for b in self.workers.values() {
            out.cards += b.stats.cards;
            out.ops_accepted += b.stats.ops_accepted;
            out.ops_refused += b.stats.ops_refused;
            out.concepts_proposed += b.stats.concepts_proposed;
            out.links_proposed += b.stats.links_proposed;
            out.duplicates += b.stats.duplicates;
            out.concepts_reused += b.stats.concepts_reused;
        }
        out
    }
}
