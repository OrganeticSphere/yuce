use super::*;
impl AuditOntology {
    pub fn seed_ids(&self) -> Vec<ConceptId> {
        self.concepts.values().filter(|c| c.history.first().is_some_and(|h| h.revision == 0 && h.by == "base")).map(|c| c.id).collect()
    }
    pub fn narrowed_replacements(&self, id: &ConceptId) -> Vec<ConceptView> {
        self.concepts.get(id).into_iter().flat_map(|c| c.narrowed_into.iter()).filter_map(|id| self.concept(id)).collect()
    }
    pub fn mark_narrowed(&mut self, id: &ConceptId, targets: &[ConceptId], by: &str) -> KResult<()> {
        actor(by)?;
        if targets.is_empty() || targets.contains(id) || targets.iter().any(|id| self.concept(id).is_none_or(|c| !c.selectable())) {
            return Err(bad("into", "narrow needs distinct selectable replacements"));
        }
        let rev = self.next_revision()?;
        let c = self.concepts.get_mut(id).ok_or_else(|| bad("concept", "unknown concept"))?;
        if !c.view().selectable() {
            return Err(bad("concept", "narrow needs a selectable source"));
        }
        c.status = "narrowed".into();
        c.narrowed_into = targets.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();
        c.history.push(StatusChange { revision: rev, status: c.status.clone(), by: by.into() });
        self.revision = rev;
        Ok(())
    }
    pub fn mark_unattested(&mut self, id: &ConceptId, reason: &Value) -> KResult<bool> {
        let c = self.concepts.get(id).ok_or_else(|| bad("concept", "unknown concept"))?;
        if !c.view().selectable() {
            return Ok(false);
        }
        let rev = self.next_revision()?;
        let c = self.concepts.get_mut(id).expect("known");
        c.unattested_prior = Some(c.status.clone());
        c.status = "unattested".into();
        let mut applied = reason.clone();
        applied["ontology_revision"] = json!(rev);
        c.attestation_reason = Some(applied);
        c.history.push(StatusChange { revision: rev, status: c.status.clone(), by: "kernel".into() });
        self.revision = rev;
        Ok(true)
    }
    pub fn attest_mapping(&mut self, id: &ConceptId) -> KResult<bool> {
        let c = self.concepts.get(id).ok_or_else(|| bad("concept", "unknown concept"))?;
        if c.status != "unattested" {
            return Ok(false);
        }
        let prior = c.unattested_prior.clone().ok_or_else(|| bad("status", "missing prior attested status"))?;
        let rev = self.next_revision()?;
        let c = self.concepts.get_mut(id).expect("known");
        c.status = prior;
        c.unattested_prior = None;
        c.history.push(StatusChange { revision: rev, status: c.status.clone(), by: "kernel".into() });
        self.revision = rev;
        Ok(true)
    }
}
