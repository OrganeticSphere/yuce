//! Persistent version-map policy and effect guard. Agent-supplied record fields grant no authority.
use super::*;
use crate::audit::versions;

impl Core {
    pub(super) fn compute_version_map(&self, lineage: &Value) -> KResult<Value> {
        let docs = self
            .session
            .arena
            .doc_ids()
            .map(|id| {
                let text = String::from_utf8(self.session.arena.doc(id).expect("listed").bytes.clone()).expect("UTF-8 genesis");
                let label = self.data.source_documents[id]["path"].as_str().unwrap_or(id).to_string();
                (id.to_string(), (label, text))
            })
            .collect::<BTreeMap<_, _>>();
        versions::compute(&docs, lineage)
    }

    pub(super) fn version_checkpoint(&self, actor: &str, command: &Value) -> KResult<()> {
        let key = string(command, "key")?;
        if key == versions::KEY {
            if actor != "kernel"
                || self.data.checkpoints.contains_key(key)
                || !self.data.receipts.is_empty()
                || !self.data.records.is_empty()
                || !self.data.links.is_empty()
            {
                return Err(bad("version:map", "the kernel installs an immutable version map as the first transaction after genesis"));
            }
            if command["context"] != self.compute_version_map(&command["context"]["lineage"])? {
                return Err(bad("version:map", "version map differs from recomputation over frozen inputs"));
            }
        } else if key.starts_with("version:lease:") {
            let context = &command["context"];
            let card = self.version_card(context["card"].as_str().unwrap_or(""));
            if actor != "kernel" || card.is_none() || self.data.checkpoints.get(key).is_some_and(|c| c != command) {
                return Err(bad("version:lease", "only the dispatcher binds an immutable CHANGE lease to a map card"));
            }
            identifier(string(context, "agent")?, "agent")?;
        } else if let Some(task) = key.strip_prefix("version:closed:") {
            let grant = self.data.checkpoints.get(&format!("version:lease:{task}")).ok_or_else(|| bad("version:closed", "unknown CHANGE grant"))?;
            if (actor != "kernel" && grant["context"]["agent"] != actor)
                || self.data.checkpoints.get(key).is_some_and(|c| c != command)
                || !matches!(command["context"]["reason"].as_str(), Some("completed" | "released" | "expired" | "recovery"))
            {
                return Err(bad("version:closed", "only the dispatcher or grant owner may permanently close a CHANGE grant"));
            }
        }
        Ok(())
    }

    fn version_card(&self, id: &str) -> Option<&Value> {
        self.data.checkpoints.get(versions::KEY)?["context"]["cards"].as_array()?.iter().find(|c| c["id"] == id)
    }

    pub(super) fn version_scope(&self, actor: &str, directive: &str, scope: &Scope) -> KResult<()> {
        if let Some(lease) = self.data.checkpoints.get(&format!("version:lease:{directive}")) {
            if self.data.checkpoints.contains_key(&format!("version:closed:{directive}")) {
                return Err(bad("directive", "CHANGE grant is closed; acquire a fresh task"));
            }
            let card = self.version_card(lease["context"]["card"].as_str().unwrap_or(""));
            if lease["context"]["agent"] != actor || card.is_none_or(|c| versions::card_scope(c) != *scope) {
                return Err(bad("scope", "CHANGE scope and agent must match the dispatcher-issued card"));
            }
        }
        Ok(())
    }

    fn version_observes(&self, id: RecordId, ranges: &[Value]) -> bool {
        let mut todo = vec![id];
        let mut seen = BTreeSet::new();
        let mut found = false;
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(r) = self.record(&id) else { return false };
            if r.kind == RecordKind::Observe {
                let Some(bound) = self.data.evidence.get(&id) else { return false };
                if !self.observe_grounded(r)
                    || !ranges.iter().any(|v| {
                        r.doc_id.as_deref() == v[0].as_str()
                            && v[1].as_u64().is_some_and(|a| a <= bound.start as u64)
                            && v[2].as_u64().is_some_and(|b| bound.end as u64 <= b)
                    })
                {
                    return false;
                }
                found = true;
            } else {
                if r.kind != RecordKind::Claim || r.based_on.is_empty() {
                    return false;
                }
                todo.extend(&r.based_on);
            }
        }
        found
    }

    /// Refuse before add_link mutates state, so submit retains its accepted prefix and the dispatcher can store independent
    /// suffix lines. Only commands naming RELATION_RULE use these diagnostics; old recorded refusals replay unchanged.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn version_relation_line(
        &self,
        actor: &str,
        directive: &str,
        local: &str,
        from: RecordId,
        rel: &str,
        to: RecordId,
        basis: &[RecordId],
    ) -> KResult<()> {
        if !self.data.checkpoints.contains_key(versions::KEY) {
            return Ok(());
        }
        let diagnostic = |condition: &str, message: &str, card: Value| {
            bad("relation", message).expected(json!({"rule":versions::RELATION_RULE,"condition":condition,"local_id":local,
                "from":from.short(),"to":to.short(),"rel":rel,"card":card}))
        };
        let grant = self.data.checkpoints.get(&format!("version:lease:{directive}"));
        let Some(context) = grant.map(|c| &c["context"]).filter(|c| c["agent"] == actor) else {
            return Err(diagnostic("authenticated_change_grant", "a version relation requires an authenticated CHANGE task", Value::Null));
        };
        let card = self
            .version_card(context["card"].as_str().unwrap_or(""))
            .ok_or_else(|| diagnostic("known_card", "unknown version card", context["card"].clone()))?;
        let old = card["old"].as_array().expect("computed ranges");
        let new =
            card["new"].as_array().expect("computed ranges").iter().chain(card["changelog"].as_array().expect("computed logs")).cloned().collect::<Vec<_>>();
        let both = old.iter().chain(&new).cloned().collect::<Vec<_>>();
        let side = |id| {
            if self.version_observes(id, old) {
                "old"
            } else if self.version_observes(id, &new) {
                "new"
            } else if self.version_observes(id, &both) {
                "mixed"
            } else {
                "outside_card_or_ungrounded"
            }
        };
        let (a, b) = (side(from), side(to));
        let refuse = |condition: &str, message: &str| {
            let mut error = diagnostic(condition, message, card["id"].clone());
            error.expected_by_kernel = json!({"rule":versions::RELATION_RULE,"condition":condition,"local_id":local,
                "from":from.short(),"to":to.short(),"rel":rel,"card":card["id"],"from_snapshot":a,"to_snapshot":b,
                "basis":basis.iter().map(RecordId::short).collect::<Vec<_>>(),"required":"one endpoint per snapshot inside this card; supersedes from NEW to OLD; based_on includes Observe from OLD and NEW"});
            error
        };
        if [a, b].contains(&"outside_card_or_ungrounded") {
            return Err(refuse("endpoints_inside_card", "each endpoint must rest on grounded quotes inside this CHANGE card"));
        }
        if [a, b].contains(&"mixed") {
            return Err(refuse("one_snapshot_per_endpoint", "split a claim resting on both snapshots into separate OLD and NEW claims"));
        }
        if a == b {
            return Err(refuse("different_snapshots", "CHANGE accepts cross-snapshot relations only; these endpoints come from the same snapshot"));
        }
        if rel == "supersedes" && a != "new" {
            return Err(refuse("supersedes_new_to_old", "supersedes.from must be the NEW claim and supersedes.to the OLD claim"));
        }
        if basis.is_empty()
            || !basis.iter().all(|id| self.version_observes(*id, &both))
            || !basis.iter().any(|id| self.version_observes(*id, old))
            || !basis.iter().any(|id| self.version_observes(*id, &new))
        {
            return Err(refuse("observe_basis_both_snapshots", "based_on must include grounded Observe support from BOTH OLD and NEW inside this card"));
        }
        Ok(())
    }

    /// Check the staged effects, including a submit embedded in a coordinator batch. A forged directive label is insufficient:
    /// a trusted dispatcher checkpoint binds (task, authenticated agent, exact card), and the evidence must fit that card.
    pub(super) fn version_effects(&self, previous: &Self, actor: &str) -> KResult<()> {
        if !self.data.checkpoints.contains_key(versions::KEY) {
            return Ok(());
        }
        if !previous.data.checkpoints.contains_key(versions::KEY)
            && (!previous.data.receipts.is_empty() || previous.data.source_documents != self.data.source_documents || !self.data.records.is_empty())
        {
            return Err(bad("version:map", "map installation must use unchanged genesis sources before ingest"));
        }
        for l in self.data.links.values() {
            if !previous.data.links.contains_key(&l.id) {
                let origin = self
                    .data
                    .records
                    .iter()
                    .skip(previous.data.records.len())
                    .find(|r| r.ends.as_ref().is_some_and(|(a, rel, b)| *a == l.from && *b == l.to && *rel == l.rel) && r.author == actor);
                let Some(origin) = origin else {
                    return Err(bad("relation", "versions accepts only relations of an issued CHANGE task"));
                };
                let lease = self.data.checkpoints.get(&format!("version:lease:{}", origin.directive));
                let Some(context) = lease.map(|c| &c["context"]).filter(|c| c["agent"] == actor) else {
                    return Err(bad("relation", "relation has no authenticated CHANGE lease"));
                };
                let card = self.version_card(context["card"].as_str().unwrap_or("")).ok_or_else(|| bad("relation", "unknown version card"))?;
                let old = card["old"].as_array().expect("computed ranges");
                let new = card["new"]
                    .as_array()
                    .expect("computed ranges")
                    .iter()
                    .chain(card["changelog"].as_array().expect("computed logs"))
                    .cloned()
                    .collect::<Vec<_>>();
                let forward = self.version_observes(l.from, &new) && self.version_observes(l.to, old);
                let backward = self.version_observes(l.to, &new) && self.version_observes(l.from, old);
                if (!forward && (l.rel == "supersedes" || !backward)) || l.basis.is_empty() {
                    return Err(bad("relation", "link endpoints need different snapshots within the card; supersedes runs NEW to OLD"));
                }
                let both = old.iter().chain(&new).cloned().collect::<Vec<_>>();
                if !l.basis.iter().all(|id| self.version_observes(*id, &both))
                    || !l.basis.iter().any(|id| self.version_observes(*id, old))
                    || !l.basis.iter().any(|id| self.version_observes(*id, &new))
                {
                    return Err(bad("basis", "a version link needs Observe support from BOTH snapshots inside its card"));
                }
            }
            if l.status == LinkStatus::Accepted
                && previous.data.links.get(&l.id).is_none_or(|p| p.status != LinkStatus::Accepted)
                && (l.by == actor || [l.from, l.to].iter().any(|id| self.record(id).is_some_and(|r| r.author == actor)))
            {
                return Err(bad("actor", "a version link requires an independent nonauthor verifier"));
            }
        }
        Ok(())
    }
}

impl AuditState {
    /// Install once, before reading. The complete derived map is stored once; recovery recomputes it from lineage and genesis.
    pub fn enable_versions(&mut self, lineage: &Value) -> KResult<Value> {
        let map = self.core.compute_version_map(lineage)?;
        if let Some(old) = self.checkpoint(versions::KEY) {
            return if old["context"] == map { Ok(map) } else { Err(bad("version:map", "lineage/map changed on resume")) };
        }
        let result =
            self.submit_operations_id("version-map", "kernel", &[], Some(json!({"kind":"checkpoint","key":versions::KEY,"from":0,"to":0,"context":map})))?;
        if result["checkpointed"] != true || !result["error"].is_null() {
            return Err(bad("version:map", format!("map checkpoint refused: {result}")));
        }
        Ok(map)
    }
}
