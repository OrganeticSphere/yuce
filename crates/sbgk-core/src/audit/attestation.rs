//! Optional reversible end-of-reading observations, never a claim that a concept is false.
use super::*;
/// The rule a new end attestation is decided by; its command carries it. A command without a rule was written before it (by
/// 3592a94 or 950f3b7) and replays by the stored mappings it was decided by, so an old journal keeps its roots (Codex review R01).
const NAMED_IN_TEXT: &str = "name_or_alias_in_report_text/1";
impl Core {
    fn unattested_enabled(&self) -> bool {
        self.data.checkpoints.get("audit:mcp:coverage").is_some_and(|c| c["context"]["unattested_at_end"] == true)
    }
    /// Seeds the reports never name. A seed is attested when its name or an alias stands in the text of a loaded report as whole
    /// words. A stored mapping does not attest it: a shared word maps terms to a concept the reports never
    /// name (run C0n_r1: 'database migration' got three mappings, 'unrelated migration requirements' among them, so nothing was
    /// ever unattested). Offline on that run the text names 22 of its 24 seeds: of the other two, one is a planted absent
    /// concept and one a planted stance; one correct seed, 'out of scope', is named nowhere either. Without the rule: seeds nothing
    /// was mapped to.
    fn unattested_ids(&self, named_in_text: bool) -> Vec<ConceptId> {
        let seeds = self.data.ontology.seed_ids().into_iter().filter(|id| self.data.ontology.concept(id).is_some_and(|c| c.selectable()));
        if !named_in_text {
            return seeds.filter(|id| !self.data.mappings.keys().any(|(_, _, c)| c == id)).collect();
        }
        let words = |t: &str| super::quality::tokens(t).join(" ");
        let text = self
            .session
            .arena
            .doc_ids()
            .filter_map(|id| self.session.arena.doc(id))
            .map(|d| format!(" {} ", words(&String::from_utf8_lossy(&d.bytes))))
            .collect::<String>();
        let named = |c: &ConceptView| std::iter::once(&c.name).chain(&c.aliases).map(|n| words(n)).any(|p| !p.is_empty() && text.contains(&format!(" {p} ")));
        seeds.filter(|id| self.data.ontology.concept(id).is_some_and(|c| !named(&c))).collect()
    }
    pub(super) fn mark_unattested(&mut self, actor: &str, command: &Value) -> KResult<Value> {
        check_keys(command, &["kind", "coverage", "watermark", "rule"])?;
        let named_in_text = match command.get("rule") {
            None => false,
            Some(rule) if rule == NAMED_IN_TEXT => true,
            Some(_) => return Err(bad("rule", "unknown end attestation rule").expected(json!({"rule": NAMED_IN_TEXT}))),
        };
        if actor != "kernel" || !self.unattested_enabled() {
            return Err(bad("kind", "end attestation requires enabled kernel coordinator"));
        }
        let coverage = &command["coverage"];
        if command["watermark"].as_u64() != Some(self.data.records.len() as u64)
            || coverage["reading_done"] != true
            || coverage["waves_closed"] != true
            || coverage["builder_caught_up"] != true
            || coverage["unread_units"] != 0
        {
            return Err(bad("coverage", "a stable complete reading and builder boundary is required"));
        }
        if self.data.checkpoints.get("audit:mcp:coverage").is_some_and(|c| !c["context"]["circle_readers"].is_null())
            && self.data.checkpoints.get("audit:circles").is_none_or(|c| c["context"]["circle_phase"] != "FINAL")
        {
            return Err(bad("coverage", "all circles must be closed"));
        }
        let bytes = self.session.arena.doc_ids().filter_map(|id| self.session.arena.doc(id)).map(|d| d.bytes.len()).sum::<usize>();
        if coverage["reports"].as_u64() != Some(self.session.arena.doc_ids().count() as u64)
            || coverage["read_bytes"].as_u64() != Some(bytes as u64)
            || coverage["read_units"].as_u64().is_none()
        {
            return Err(bad("coverage", "reading volume must match the loaded corpus"));
        }
        let ids = self.unattested_ids(named_in_text);
        let mut events = vec![];
        for id in ids {
            let mappings = self.data.mappings.keys().filter(|(_, _, c)| *c == id).count();
            let mut reason = if !named_in_text {
                json!({"mapping_count":0,"count_unit":"stored_record_term_concept_associations","coverage":coverage,"watermark":command["watermark"],"previous_ontology_revision":self.data.ontology.revision().0,"meaning":"not attested by this corpus reading; not false or retired"})
            } else {
                json!({"rule":NAMED_IN_TEXT,"mapping_count":mappings,"count_unit":"stored_record_term_concept_associations","coverage":coverage,"watermark":command["watermark"],"previous_ontology_revision":self.data.ontology.revision().0,"meaning":"no report names it; not false or retired, and a later mapping reactivates it"})
            };
            self.data.ontology.mark_unattested(&id, &reason)?;
            reason["ontology_revision"] = json!(self.data.ontology.revision().0);
            let e = json!({"op":"ontology_attestation","concept":to_hex(&id.0),"status":"unattested","subject":"kernel","reason":reason});
            self.data.decisions.push(e.clone());
            events.push(e);
        }
        Ok(json!({"events":events,"ontology_revision":self.data.ontology.revision().0}))
    }
    fn evolution_snapshot(&self) -> Option<Value> {
        let mut out = self.revision_state().or_else(|| {
            self.unattested_enabled().then(|| json!({"policy":null,"pending":[],"invalidated":[],"events":[],"ontology":self.data.ontology.to_value()}))
        })?;
        out["events"] = json!(self
            .data
            .decisions
            .iter()
            .filter(|e| matches!(e["op"].as_str(), Some("revise_concept" | "concept_proposed" | "concept_status" | "ontology_review" | "ontology_attestation")))
            .collect::<Vec<_>>());
        out["current_mappings"]=json!(self.data.mappings.iter().map(|((r,t,c),state)|json!({"record":to_hex(&r.0),"term":t,"concept":to_hex(&c.0),"status":state,"on_narrowed_concept":self.data.ontology.concept(c).is_some_and(|c|c.status=="narrowed")})).collect::<Vec<_>>());
        out["seed_ids"] = json!(self.data.ontology.seed_ids().iter().map(|id| to_hex(&id.0)).collect::<Vec<_>>());
        Some(out)
    }
}
impl AuditState {
    pub fn attest_at_end(&mut self, coverage: Value) -> KResult<Value> {
        if !self.core.unattested_enabled() || self.core.unattested_ids(true).is_empty() {
            return Ok(Value::Null);
        }
        let command = json!({"kind":"ontology_unattested","rule":NAMED_IN_TEXT,"coverage":coverage,"watermark":self.head()});
        let id = format!("unattested:{}", to_hex(&sha256(to_jcs(&json!([command, to_hex(&self.audit_root())])).as_bytes())));
        match self.commit("kernel", &id, &command)? {
            Outcome::Value(v) => Ok(v),
            Outcome::Error(e) => Err(e),
            _ => Err(bad("kind", "unexpected attestation outcome")),
        }
    }
    pub fn ontology_evolution_snapshot(&self) -> Option<Value> {
        self.core.evolution_snapshot()
    }
}
