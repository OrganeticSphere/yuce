//! Opt-in, once-per-circle review decisions. Definitions are never accepted by a keep decision.
use super::*;
impl Core {
    pub(super) fn ontology_review_enabled(&self) -> bool {
        self.data.checkpoints.get("audit:mcp:coverage").is_some_and(|v| v["context"]["ontology_review"] == true)
    }
    pub(super) fn validate_ontology_review(&self, id: &str, subject: &str) -> KResult<Value> {
        if !self.ontology_review_enabled() {
            return Err(bad("review_id", "mandatory ontology review is disabled"));
        }
        let spec = self
            .data
            .checkpoints
            .get("builder:pool")
            .and_then(|v| v["context"]["cards"].as_array())
            .into_iter()
            .flatten()
            .find_map(|v| (v["ontology_review"]["id"] == id).then(|| v["ontology_review"].clone()))
            .ok_or_else(|| bad("review_id", "no issued durable ontology review"))?;
        if self.data.decisions.iter().any(|v| v["op"] == "ontology_review" && v["review_id"] == id) {
            return Err(bad("review_id", "this review already has a durable decision"));
        }
        let circle = self.data.checkpoints.get("audit:circles").map(|v| v["context"].clone()).unwrap_or(Value::Null);
        if circle["circle"] != spec["circle"] || circle["circle_phase"] != "BUILD" {
            return Err(bad("review_id", "ontology review belongs to another circle/phase"));
        }
        let excluded = spec["excluded_mappers"].as_array().ok_or_else(|| bad("review_id", "invalid review exclusions"))?;
        if excluded.iter().any(|v| v == subject) {
            return Err(bad("subject", "the largest mapper cannot review this concept"));
        }
        let members = self.data.checkpoints.get("audit:ring-members").and_then(|v| v["context"]["excluded"].as_array());
        if members.is_some_and(|xs| xs.iter().any(|v| v == subject)) {
            return Err(bad("subject", "timed-out subject cannot review before rejoin"));
        }
        let primary = spec["reviewer"].as_str().unwrap_or("");
        let fallback = members.is_some_and(|xs| xs.iter().any(|v| v == primary));
        let in_roster = self
            .data
            .checkpoints
            .get("audit:mcp:coverage")
            .and_then(|v| v["context"]["circle_readers"].as_array())
            .is_some_and(|xs| xs.iter().any(|v| v == subject));
        if !in_roster || (subject != primary && !fallback) {
            return Err(bad("subject", "only the assigned independent ring reviewer may decide"));
        }
        Ok(spec)
    }
    pub(super) fn record_ontology_review(
        &mut self,
        spec: &Value,
        subject: &str,
        decision: &str,
        basis: &[RecordId],
        reason: &str,
        proposal: Option<Value>,
    ) -> Value {
        let result = json!({"op":"ontology_review","review_id":spec["id"],"concept":spec["concept"],"circle":spec["circle"],
            "subject":subject,"decision":decision,"basis":basis.iter().map(|id|to_hex(&id.0)).collect::<Vec<_>>(),"reason":reason,"proposal":proposal});
        self.data.decisions.push(result.clone());
        result
    }
    pub(super) fn keep_ontology_review(&mut self, command: &Value) -> KResult<Value> {
        check_keys(command, &["kind", "concept", "review_id", "subject", "basis", "reason"])?;
        let subject = string(command, "subject")?;
        let spec = self.validate_ontology_review(string(command, "review_id")?, subject)?;
        if command["concept"] != spec["concept"] {
            return Err(bad("concept", "keep must name this review's concept"));
        }
        let reason = string(command, "reason")?;
        if reason.trim().is_empty() || reason.len() > 4096 {
            return Err(bad("reason", "nonempty reason up to 4096 bytes required"));
        }
        let basis = self.revision_basis(command)?;
        Ok(self.record_ontology_review(&spec, subject, "keep", &basis, reason, None))
    }
}
