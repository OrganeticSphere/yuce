use super::*;
impl Dispatcher {
    pub(super) fn reported_unresolved<S: AuditStore>(&self, s: &S) -> BTreeSet<String> {
        let mut keys = self.unresolved.clone();
        if self.cfg.agent_attempts.is_some() {
            for (key, e) in super::agent_failures::state(s)["work"].as_object().into_iter().flat_map(|m| m.iter()) {
                if e["unresolved"] == true && (!key.starts_with("rq:") || e["question_set_revision"] == self.question_set_revision()) {
                    keys.insert(key.clone());
                }
            }
        }
        keys
    }
    pub(super) fn agent_failure_record<S: AuditStore>(&mut self, s: &mut S, key: &str, attempt: &str, who: &str, reason: &str) -> Result<Value, Value> {
        let e = super::agent_failures::record(
            s,
            key,
            attempt,
            who,
            reason,
            Some({
                let mut meta = json!({"question_set_revision":self.question_set_revision()});
                if let Some(c) = self.build_offer.iter().find(|c| key == format!("build:{}", c.card_id)) {
                    meta["range"] = json!([c.cursor_from, c.cursor_to]);
                    meta["pool"] = json!(self.cfg.circles.is_some());
                    meta["review"] = json!(c.review);
                }
                meta
            }),
        )?;
        let count = e["failures"].as_u64().unwrap_or(0) as u32;
        self.failures.insert(key.into(), count.saturating_sub(1));
        self.note_failure(key);
        Ok(e)
    }
    pub fn build_card_for_task(&self, task: &str, who: &str) -> Option<String> {
        let l = self.leases.get(task)?;
        (l.agent == who && l.kind == TaskKind::Build).then(|| l.key.strip_prefix("build:").unwrap_or("").to_string())
    }
}
