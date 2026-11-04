//! A staged narrowing plan. Nested evidence and every source mapping are revalidated on confirmation.
use super::*;
pub(super) struct NarrowPlan {
    ontology: AuditOntology,
    moves: Vec<Value>,
    result: Value,
}
impl Core {
    pub(super) fn prepare_narrow(&self, change: &Value, proposer: &str, confirmer: &str, basis: &[RecordId]) -> KResult<NarrowPlan> {
        check_keys(change, &["concept", "action", "into", "move"])?;
        let broad = ConceptId(hash_field(change, "concept")?);
        if self.data.ontology.concept(&broad).is_none_or(|c| !c.selectable()) {
            return Err(bad("concept", "narrow needs a selectable source"));
        }
        let mut ontology = self.data.ontology.clone();
        let mut names = BTreeMap::new();
        let mut created = vec![];
        let mut replacements = BTreeSet::new();
        let into = change["into"].as_array().filter(|v| v.len() <= MAX_REFS).ok_or_else(|| bad("into", "expected bounded array"))?;
        for v in into {
            check_keys(v, &["type", "name", "aliases", "basis"])?;
            let evidence = self.revision_basis(v)?;
            if evidence.iter().any(|id| self.record(id).is_none_or(|r| r.kind != RecordKind::Observe)) {
                return Err(bad("basis", "new narrow concepts require observes"));
            }
            let before = ontology.concepts();
            let c = ontology.propose(proposer, string(v, "type")?, string(v, "name")?, &strings(v, "aliases")?, &evidence)?;
            if before.iter().any(|v| v.id == c.id) {
                return Err(bad("name", "into names must be new; use an existing target in move instead"));
            }
            names.insert(c.name.clone(), c.id);
            replacements.insert(c.id);
            created.push(concept_value(&c));
        }
        let moves = change["move"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= MAX_REFS)
            .ok_or_else(|| bad("move", "narrow needs a nonempty bounded list of existing mappings"))?;
        let mut seen = BTreeSet::new();
        let mut rows = vec![];
        for v in moves {
            check_keys(v, &["record", "term", "to"])?;
            let rid = RecordId(hash_field(v, "record")?);
            let term = string(v, "term")?.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
            if !seen.insert((rid, term.clone())) || !self.data.mappings.contains_key(&(rid, term.clone(), broad)) {
                return Err(bad("move", "each move must name a distinct existing mapping of the broad concept"));
            }
            if !self.grounded(&rid) {
                return Err(bad("record", "move record must remain active and grounded"));
            }
            let mut todo = vec![rid];
            let mut cone = BTreeSet::new();
            while let Some(id) = todo.pop() {
                if cone.insert(id) {
                    if let Some(r) = self.record(&id) {
                        todo.extend(r.based_on.iter().copied());
                        if let Some((a, _, b)) = &r.ends {
                            todo.extend([*a, *b]);
                        }
                    }
                }
            }
            if !basis.iter().any(|id| cone.contains(id)) {
                return Err(bad("basis", "every move must be grounded in its shown record or evidence cone"));
            }
            let to = string(v, "to")?;
            let target = names
                .get(&to.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase())
                .copied()
                .or_else(|| from_hex(to.trim_start_matches('@')).map(ConceptId))
                .ok_or_else(|| bad("to", "expected new name or full existing concept id"))?;
            let target_hex = to_hex(&target.0);
            if self.data.decisions.iter().any(|p| {
                p["op"] == "revise_concept"
                    && p["status"] == "pending"
                    && p["change"]["concept"] == target_hex
                    && self.revision_basis(p).is_ok()
                    && !self.data.decisions.iter().any(|e| e["proposal"] == p["proposal"] && matches!(e["status"].as_str(), Some("confirmed" | "rejected")))
            }) {
                return Err(bad("to", "target has a pending revision"));
            }
            let c = ontology
                .concept(&target)
                .filter(ConceptView::selectable)
                .filter(|c| c.id != broad)
                .ok_or_else(|| bad("to", "target must be a different selectable concept"))?;
            let names = std::iter::once(c.name.clone()).chain(c.aliases.iter().cloned()).collect::<Vec<_>>().join(" ");
            if let Some((ours, theirs)) = crate::audit::s0::conflicting_identifiers(&term, &names) {
                return Err(bad("to", format!("the term names {ours}, target names {theirs}: they are different things")));
            }
            let status = if c.status == "accepted" && (c.name == term || c.aliases.contains(&term)) { "accepted" } else { "proposed" };
            replacements.insert(target);
            rows.push(json!({"record":to_hex(&rid.0),"term":term,"from":to_hex(&broad.0),"to":to_hex(&target.0),"status":status}));
        }
        ontology.mark_narrowed(&broad, &replacements.into_iter().collect::<Vec<_>>(), confirmer)?;
        let result = json!({"concept":to_hex(&broad.0),"status":"narrowed","into":created,"moves":rows,"moved_mappings":rows.len(),"replacements":ontology.narrowed_replacements(&broad).iter().map(concept_value).collect::<Vec<_>>(),"ontology_revision":ontology.revision().0});
        Ok(NarrowPlan { ontology, moves: rows, result })
    }
    pub(super) fn apply_narrow(&mut self, change: &Value, proposer: &str, confirmer: &str, basis: &[RecordId]) -> KResult<Value> {
        let plan = self.prepare_narrow(change, proposer, confirmer, basis)?;
        for row in &plan.moves {
            let rid = RecordId(hash_field(row, "record")?);
            let term = string(row, "term")?.to_string();
            let broad = ConceptId(hash_field(row, "from")?);
            let target = ConceptId(hash_field(row, "to")?);
            self.data.mappings.remove(&(rid, term.clone(), broad));
            self.data.mappings.insert((rid, term.clone(), target), string(row, "status")?.into());
            self.data.decisions.push(json!({"op":"map_term","by":"builder","subject":proposer,"confirmed_by":confirmer,"record":row["record"],"term":term,"concept":row["to"],"moved_from":row["from"],"status":row["status"]}));
        }
        self.data.ontology = plan.ontology;
        Ok(plan.result)
    }
}
