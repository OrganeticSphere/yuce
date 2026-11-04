//! Grounded, explicit nonproposer review. Subject is sealed by the authenticated coordinator.
use super::*;
impl Core {
    pub(super) fn revision_basis(&self, value: &Value) -> KResult<Vec<RecordId>> {
        let basis = self.command_basis(value)?;
        if basis.iter().any(|id| !self.answer_support(id)) {
            return Err(bad("basis", "ontology revision basis must remain established and active; proposed relations are not support"));
        }
        Ok(basis)
    }

    pub(super) fn revision_state(&self) -> Option<Value> {
        let policy = self.data.ontology.revision_policy()?;
        let events: Vec<Value> = self
            .data
            .decisions
            .iter()
            .filter(|d| matches!(d["op"].as_str(), Some("revise_concept" | "concept_proposed" | "concept_status" | "ontology_review")))
            .cloned()
            .collect();
        let candidates: Vec<Value> = events
            .iter()
            .filter(|e| {
                e["status"] == "pending"
                    && !events.iter().any(|v| v["proposal"] == e["proposal"] && matches!(v["status"].as_str(), Some("confirmed" | "rejected")))
            })
            .cloned()
            .collect();
        let mut pending = Vec::new();
        let mut invalidated = Vec::new();
        for mut p in candidates {
            let live = p["change"]["concept"]
                .as_str()
                .and_then(from_hex)
                .map(ConceptId)
                .and_then(|id| self.data.ontology.concept(&id))
                .is_some_and(|c| c.selectable());
            let narrow_live = p["change"]["action"] != "narrow"
                || self
                    .revision_basis(&p)
                    .is_ok_and(|b| self.prepare_narrow(&p["change"], p["subject"].as_str().unwrap_or(""), p["subject"].as_str().unwrap_or(""), &b).is_ok());
            if live && narrow_live && self.revision_basis(&p).is_ok() {
                pending.push(p);
            } else {
                p["status"] = json!("invalidated");
                p["invalidation_reason"] = if p["change"]["action"] == "narrow" {
                    json!("narrow plan no longer applicable: evidence, mapping, target or reserved name changed")
                } else {
                    json!("original support withdrawn or source concept retired")
                };
                invalidated.push(p);
            }
        }
        Some(json!({"invalidated":invalidated,"policy":policy,"ontology":self.data.ontology.to_value(),"events":events,"pending":pending}))
    }
    pub(super) fn revise_concept(&mut self, command: &Value) -> KResult<Value> {
        let snapshot = self.revision_state().ok_or_else(|| bad("op", "ontology revisions are disabled for this genesis"))?;
        check_keys(
            command,
            &["kind", "concept", "action", "target", "alias", "new_type", "new_name", "proposal", "basis", "reason", "subject", "review_id", "into", "move"],
        )?;
        let subject = string(command, "subject")?;
        let reason = string(command, "reason")?;
        if subject.trim().is_empty() || subject.len() > 1024 || reason.trim().is_empty() || reason.len() > 4096 {
            return Err(bad("reason", "nonempty subject and reason (at most 4096 bytes) required"));
        }
        let basis = self.revision_basis(command)?;
        let review = if command.get("review_id").is_some() { Some(self.validate_ontology_review(string(command, "review_id")?, subject)?) } else { None };
        if let Some(spec) = &review {
            if matches!(command["action"].as_str(), Some("confirm" | "reject")) || command["concept"] != spec["concept"] {
                return Err(bad("concept", "mandatory review must propose a change of its own concept"));
            }
        }
        let circle = self.data.checkpoints.get("audit:circles").map(|v| v["context"]["circle"].clone()).unwrap_or(Value::Null);
        let action = string(command, "action")?;
        let event = if matches!(action, "confirm" | "reject") {
            let proposal = string(command, "proposal")?;
            let pending = snapshot["pending"]
                .as_array()
                .expect("pending array")
                .iter()
                .find(|p| p["proposal"] == proposal)
                .ok_or_else(|| bad("proposal", "no open proposal with this id"))?;
            let primary = pending["reviewer"].as_str().unwrap_or("");
            let excluded = self.data.checkpoints.get("audit:ring-members").and_then(|v| v["context"]["excluded"].as_array());
            let primary_excluded = excluded.is_some_and(|xs| xs.iter().any(|v| v == primary));
            let roster = self.data.checkpoints.get("audit:mcp:coverage").and_then(|v| v["context"]["circle_readers"].as_array());
            let fallback_allowed =
                primary_excluded && roster.is_some_and(|xs| xs.iter().any(|v| v == subject)) && !excluded.is_some_and(|xs| xs.iter().any(|v| v == subject));
            if (pending["reviewer"] != subject && !fallback_allowed) || pending["subject"] == subject {
                return Err(bad("subject", "only the fixed next nonproposer may confirm or reject"));
            }
            let mut result = Value::Null;
            if action == "confirm" {
                self.revision_basis(pending)?; // withdrawn original support cannot authorize application
                let change = &pending["change"];
                let mut observe_basis = BTreeSet::new();
                let mut visited = BTreeSet::new();
                let mut queue = basis.clone();
                while let Some(id) = queue.pop() {
                    if !visited.insert(id) {
                        continue;
                    }
                    let r = self.record(&id).ok_or_else(|| bad("basis", "missing record"))?;
                    if r.kind == RecordKind::Observe {
                        observe_basis.insert(id);
                    } else {
                        queue.extend(r.based_on.iter().copied());
                    }
                }
                result = if change["action"] == "narrow" {
                    self.apply_narrow(change, pending["subject"].as_str().unwrap_or(""), subject, &self.revision_basis(pending)?)?
                } else {
                    self.data.ontology.revise(change, subject, &observe_basis.into_iter().collect::<Vec<_>>())?
                };
            }
            json!({"op":"revise_concept","proposal":proposal,"change":pending["change"],"subject":subject,"proposer":pending["subject"],"initial_reviewer":pending["reviewer"],"reviewer_failed_over":pending["reviewer"]!=subject,
                "basis":basis.iter().map(|id|to_hex(&id.0)).collect::<Vec<_>>(),"reason":reason,"circle":circle,"status":if action=="confirm" {"confirmed"} else {"rejected"},"result":result})
        } else {
            let keys: &[&str] = match action {
                "retire" => &["concept", "action"],
                "merge_into" => &["concept", "action", "target"],
                "remove_alias" => &["concept", "action", "alias"],
                "retype" => &["concept", "action", "new_type", "new_name"],
                "narrow" => &["concept", "action"],
                _ => return Err(bad("action", "unknown revision action")),
            };
            let mut change = serde_json::Map::new();
            for key in keys {
                change.insert((*key).to_string(), json!(string(command, key)?));
            }
            let mut change = Value::Object(change);
            if action == "narrow" {
                change["into"] = command["into"].clone();
                change["move"] = command["move"].clone();
                self.prepare_narrow(&change, subject, subject, &basis)?;
            } else {
                let mut trial = self.data.ontology.clone();
                trial.revise(&change, subject, &basis)?;
            }
            if snapshot["pending"].as_array().expect("pending array").iter().any(|p| p["change"]["concept"] == change["concept"]) {
                return Err(bad("concept", "already has a pending revision: confirm or reject that proposal"));
            }
            let readers = self
                .data
                .checkpoints
                .get("audit:mcp:coverage")
                .and_then(|v| v["context"]["circle_readers"].as_array())
                .ok_or_else(|| bad("subject", "revision proposals need a pinned circle roster"))?;
            let refiner = self.data.checkpoints.get("audit:mcp:coverage").and_then(|v| v["context"]["circle_refiner"].as_str());
            let reviewer = if refiner == Some(subject) {
                // circles +1: the refiner is outside the ring; a swarm reader chosen by the circle number confirms its proposal
                let n = circle.as_u64().unwrap_or(1).max(1) as usize;
                readers.get((n - 1) % readers.len().max(1)).ok_or_else(|| bad("subject", "a distinct next circle participant is required"))?
            } else {
                let index = readers.iter().position(|v| v == subject).ok_or_else(|| bad("subject", "proposer must be an authenticated circle participant"))?;
                (1..readers.len())
                    .map(|k| &readers[(index + k) % readers.len()])
                    .find(|v| *v != subject)
                    .ok_or_else(|| bad("subject", "a distinct next circle participant is required"))?
            };
            let proposal = to_hex(&sha256(to_jcs(&json!([change, subject, self.data.decisions.len()])).as_bytes()));
            json!({"op":"revise_concept","proposal":proposal,"change":change,"subject":subject,"reviewer":reviewer,
                "basis":basis.iter().map(|id|to_hex(&id.0)).collect::<Vec<_>>(),"reason":reason,"circle":circle,"status":"pending"})
        };
        let mut event = event;
        if let Some(spec) = review {
            if matches!(action, "confirm" | "reject") || event["change"]["concept"] != spec["concept"] {
                return Err(bad("concept", "mandatory review must propose a change of its own concept"));
            }
            event["review_id"] = spec["id"].clone();
            event["review_decision"] = json!("revise");
            self.record_ontology_review(&spec, subject, "revise", &basis, reason, event.get("proposal").cloned());
        }
        self.data.decisions.push(event.clone());
        Ok(event)
    }
}
