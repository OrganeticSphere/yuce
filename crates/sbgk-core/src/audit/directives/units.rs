//! Reading units and withdrawn text. What the owner withdrew is never handed out
//! as work: a unit whose every byte is withdrawn is closed, not issued, and an issued unit shows its withdrawn bytes as
//! marks, not as text. In the plan profile (`unit_is_task`) a unit is a task: an answer that leaves it with nothing
//! accepted does not close it, and a closed unit whose records all fell to a withdrawal is done again.
//!
//! These are decisions of the dispatcher only. The rules of the journal (`r2r-audit-rules/3`) check every submission against the
//! scope its own frame records and never replay what the dispatcher chose to issue or to close.

use super::*;

/// The reason a unit was closed without a reading: every byte of it is withdrawn. Its units show as `withdrawn` in the coverage
/// table, as those of a unit read before the withdrawal do.
pub(super) const WITHDRAWN_WHOLE: &str = "withdrawn_whole";

/// The code of an answer given back because it left its task with nothing accepted (`unit_is_task`).
pub(super) const EMPTY_ANSWER: &str = "EMPTY_ANSWER";

/// The reason a unit was given up as unresolved because it fell again after it was opened as often as its bound allows (Codex's
/// PR55-R1): text of it stands, so its task is not done.
pub(super) const REOPEN_LIMIT: &str = "REOPEN_LIMIT";

/// The withdrawn bytes of a document inside `a..b`: its closed spans cut to the range, merged, in order.
pub(super) fn withdrawn_in(closed: &[(usize, usize)], a: usize, b: usize) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = closed.iter().filter(|(x, y)| x < y && *x < b && a < *y).map(|(x, y)| ((*x).max(a), (*y).min(b))).collect();
    spans.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (x, y) in spans {
        match out.last_mut() {
            Some(last) if x <= last.1 => last.1 = last.1.max(y),
            _ => out.push((x, y)),
        }
    }
    out
}

/// Whether some byte of `text[a..b]` is withdrawn and nothing but whitespace lies outside the withdrawn bytes: nothing of the range
/// is left to quote. Whitespace is allowed because a withdrawal names a text, and the text of a whole section is named without the
/// blank line that ends it.
pub(super) fn withdrawn_whole(text: &str, a: usize, b: usize, closed: &[(usize, usize)]) -> bool {
    let spans = withdrawn_in(closed, a, b);
    if spans.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let blank = |x: usize, y: usize| bytes.get(x..y).is_some_and(|r| r.iter().all(u8::is_ascii_whitespace));
    let mut from = a;
    for (x, y) in spans {
        if !blank(from, x) {
            return false;
        }
        from = y;
    }
    blank(from, b)
}

/// Said before a section, and its context, that show withdrawn bytes as marks. Only such a card has it: a prompt over
/// text with nothing withdrawn is what it was.
pub(super) const WITHDRAWN_NOTE: &str = "WITHDRAWN TEXT: the owner withdrew the bytes marked [withdrawn: N bytes] below. \
                                         They are not shown and no longer stand: do not act on them, and a quote of them is refused.\n";

/// `text[a..b]` as an agent is shown it: each run of withdrawn bytes replaced by a mark of its length (a section
/// issued again showed its withdrawn clause as live text, so the executor carried it out and quoted it, and only the refusal told
/// it). A quote of withdrawn bytes is refused anyway, so the mark hides nothing an answer could use. Returns the text and whether it
/// marks anything; with nothing withdrawn in the range it is the range's text, byte for byte.
pub(super) fn shown_section(text: &str, a: usize, b: usize, closed: &[(usize, usize)]) -> (String, bool) {
    let spans = withdrawn_in(closed, a, b);
    if spans.is_empty() {
        return (text[a..b].to_string(), false);
    }
    // a withdrawn text is whole characters wherever it occurs; the bounds are kept on characters all the same
    let floor = |mut i: usize| {
        while !text.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let ceil = |mut i: usize| {
        while !text.is_char_boundary(i) {
            i += 1;
        }
        i
    };
    let mut out = String::new();
    let mut from = a;
    for (x, y) in spans {
        let (x, y) = (floor(x).max(from), ceil(y).min(b));
        if y <= from {
            continue;
        }
        out.push_str(&text[from..x]);
        out.push_str(&format!("[withdrawn: {} bytes]", y - x));
        from = y;
    }
    out.push_str(&text[from..b]);
    (out, true)
}

/// The text and the closed spans of the documents one dispatcher call looks at, each read once (a document without withdrawn text
/// costs no copy of its text).
#[derive(Default)]
pub(super) struct WithdrawnDocs(BTreeMap<String, Option<(String, Vec<(usize, usize)>)>>);

impl WithdrawnDocs {
    pub(super) fn of<S: AuditStore>(&mut self, s: &S, doc: &str) -> Option<&(String, Vec<(usize, usize)>)> {
        self.0
            .entry(doc.to_string())
            .or_insert_with(|| {
                let closed = s.closed_spans(doc);
                if closed.is_empty() {
                    None
                } else {
                    s.doc_text(doc).map(|text| (text, closed))
                }
            })
            .as_ref()
    }

    pub(super) fn whole<S: AuditStore>(&mut self, s: &S, doc: &str, a: usize, b: usize) -> bool {
        self.of(s, doc).is_some_and(|(text, closed)| withdrawn_whole(text, a, b, closed))
    }
}

impl Dispatcher {
    /// The byte ranges an EXTEND unit reads: its section, or every document of its zone whole.
    pub(super) fn unit_ranges<S: AuditStore>(&self, s: &S, key: &str) -> Vec<(String, usize, usize)> {
        if let Some(n) = key.strip_prefix("zone:").and_then(|n| n.parse::<usize>().ok()) {
            return self.cfg.zones.get(n).into_iter().flatten().map(|d| (d.clone(), 0, s.doc_text(d).map_or(0, |t| t.len()))).collect();
        }
        let Some((doc, k)) = key.strip_prefix("doc:").and_then(|k| k.rsplit_once('#')) else { return Vec::new() };
        let (Some(k), Some(text)) = (k.parse::<usize>().ok(), s.doc_text(doc)) else { return Vec::new() };
        sections(doc, &text, self.cfg.section_bytes).get(k).map(|(a, b)| vec![(doc.to_string(), *a, *b)]).unwrap_or_default()
    }

    /// Closes, without issuing them, the open EXTEND units of `work` whose every byte is withdrawn and that no lease holds (a
    /// cancelled task was issued again and again until its failed leases gave it up). Each counts as read; its durable
    /// record, reason WITHDRAWN_WHOLE, is written at the next call that has the store (`persist_unresolved`). Returns their keys.
    pub(super) fn close_withdrawn_units<S: AuditStore>(&mut self, s: &S, work: &[Work]) -> BTreeSet<String> {
        let mut docs = WithdrawnDocs::default();
        let mut out = BTreeSet::new();
        for (kind, key, _, _, section) in work {
            if *kind != TaskKind::Extend || self.taken(key) {
                continue;
            }
            let ranges = match section {
                Some((doc, a, b)) if !doc.starts_with("zone:") => vec![(doc.clone(), *a, *b)],
                _ => self.unit_ranges(s, key),
            };
            if !ranges.is_empty() && ranges.iter().all(|(doc, a, b)| docs.whole(s, doc, *a, *b)) {
                out.insert(key.clone());
            }
        }
        for key in &out {
            self.handled.insert(key.clone());
            self.pending_withdrawn.push((key.clone(), 0));
            self.stats.withdrawn_units += 1;
        }
        out
    }

    /// Whether every range a lease's scope reads is withdrawn whole.
    pub(super) fn scope_withdrawn_whole<S: AuditStore>(&self, s: &S, scope: &Scope) -> bool {
        let mut docs = WithdrawnDocs::default();
        !scope.ranges.is_empty() && scope.ranges.iter().all(|(doc, a, b)| docs.whole(s, doc, *a, *b))
    }

    /// The plan profile (`unit_is_task`): an answer that left its unit with nothing accepted gives its lease back as a
    /// failed attempt, as a refused answer given back does. With a bound of agent attempts the attempt is recorded durably with the
    /// reason EMPTY_ANSWER; without one it counts toward MAX_FAILED_LEASES. Past the bound the unit is unresolved; before it, it is
    /// issued again.
    pub(super) fn give_back_empty<S: AuditStore>(&mut self, s: &mut S, task_id: &str, agent: &str) -> Value {
        self.mark_failed(task_id);
        self.stats.empty_answers += 1;
        let key = self.leases.get(task_id).map(|l| l.key.clone()).unwrap_or_default();
        let told = |mut v: Value| {
            if v["status"] == "RELEASED" {
                v["code"] = json!(EMPTY_ANSWER);
                v["accepted"] = json!([]);
                v["message"] = json!("an answer with nothing accepted does not close a task: the task was given back as a failed attempt");
            }
            v
        };
        if self.cfg.agent_attempts.is_some() {
            return match self.agent_failure_record(s, &key, task_id, agent, EMPTY_ANSWER) {
                Ok(e) => {
                    self.leases.remove(task_id);
                    told(json!({"status": "RELEASED", "task_id": task_id, "unresolved": e["unresolved"], "failures": e["failures"]}))
                }
                Err(error) => json!({"status": "error", "code": "AGENT_FAILURE_CHECKPOINT_REFUSED", "error": error}),
            };
        }
        told(self.release_durable(s, task_id, agent))
    }

    /// The plan profile: what a closing unit's completion checkpoint says of it, for `recover_unit`: the records it is closed with
    /// and, once it was opened again, how often.
    pub(super) fn unit_context(&self, key: &str, own: &[RecordId], context: &mut Value) {
        if !own.is_empty() {
            context["unit_records"] = json!(own.iter().map(|r| crate::hash::to_hex(&r.0)).collect::<Vec<_>>());
        }
        if let Some(n) = self.reopened.get(key).filter(|n| **n > 0) {
            context["reopened"] = json!(n);
        }
    }

    /// The plan profile: a unit closed with these records (none: closed as withdrawn whole).
    pub(super) fn close_unit(&mut self, key: &str, own: &[RecordId]) {
        if own.is_empty() {
            self.unit_records.remove(key);
        } else {
            self.unit_records.insert(key.to_string(), own.to_vec());
        }
    }

    /// The plan profile: a unit's records and reopenings, from its completion checkpoint.
    pub(super) fn recover_unit(&mut self, key: &str, context: &Value) {
        let ids: Vec<RecordId> =
            context["unit_records"].as_array().into_iter().flatten().filter_map(|x| x.as_str().and_then(crate::hash::from_hex).map(RecordId)).collect();
        self.close_unit(key, &ids);
        match context["reopened"].as_u64().and_then(|n| u32::try_from(n).ok()) {
            Some(n) => self.reopened.insert(key.to_string(), n),
            None => self.reopened.remove(key),
        };
    }

    /// The plan profile (`unit_is_task`): the closed units that are tasks to do again. Every record a unit was closed
    /// with has fallen, withdrawn text touches it, and text of it stands: its task was changed after it was done (a directive
    /// withdrawn after acceptance took its element away, and nobody carried out its fallback). A unit is opened again at most as often as the
    /// bound of attempts (`agent_attempts`, else MAX_FAILED_LEASES), so text withdrawn piece by piece cannot hold the run for ever;
    /// one that falls again past the bound still has a task to do, and is given up as unresolved, not closed in silence (Codex's
    /// PR55-R1).
    /// The records a unit stands on are those its last lease was closed with. A unit no withdrawn text touches is not opened (its
    /// records fell for another cause, such as a document's new version), nor one withdrawn whole (nothing is left to do).
    /// Returns the units to open again and those given up.
    pub(super) fn fallen_units<S: AuditStore>(&self, s: &S, f: &Flags) -> (BTreeSet<String>, BTreeSet<String>) {
        let (mut reopen, mut exhausted) = (BTreeSet::new(), BTreeSet::new());
        if !self.cfg.unit_is_task {
            return (reopen, exhausted);
        }
        let bound = self.cfg.agent_attempts.unwrap_or(MAX_FAILED_LEASES);
        let mut docs = WithdrawnDocs::default();
        for (key, ids) in &self.unit_records {
            if !self.handled.contains(key) || self.unresolved.contains(key) || ids.is_empty() || ids.iter().any(|id| f.grounded(s, id)) {
                continue;
            }
            let ranges = self.unit_ranges(s, key);
            let touched = ranges.iter().any(|(doc, a, b)| docs.of(s, doc).is_some_and(|(_, closed)| !withdrawn_in(closed, *a, *b).is_empty()));
            if touched && !ranges.iter().all(|(doc, a, b)| docs.whole(s, doc, *a, *b)) {
                if self.reopened.get(key).copied().unwrap_or(0) < bound {
                    reopen.insert(key.clone());
                } else {
                    exhausted.insert(key.clone());
                }
            }
        }
        (reopen, exhausted)
    }

    /// Opens the fallen units again (`fallen_units`): each is open work once more, and counts one opening. Those past the bound are
    /// given up as unresolved, written durably at the next call that has the store (`persist_unresolved`, retried while it fails),
    /// with the reason REOPEN_LIMIT; a recovery before that write finds them fallen past the bound again.
    pub(super) fn reopen_fallen_units<S: AuditStore>(&mut self, s: &S, f: &Flags) {
        let (reopen, exhausted) = self.fallen_units(s, f);
        for key in reopen {
            self.handled.remove(&key);
            *self.reopened.entry(key).or_default() += 1;
            self.stats.reopened_units += 1;
        }
        for key in exhausted {
            self.handled.remove(&key);
            self.unresolved.insert(key.clone());
            self.reopen_exhausted.insert(key.clone());
            self.pending_unresolved.push((key.clone(), format!("reopen-limit-{key}"), 0));
        }
    }

    /// The durable record of a unit closed because every byte of it is withdrawn: its completion checkpoint, which `recover` reads
    /// as a closed task and the coverage table as a read unit. A retry is a new submission (a refused one keeps its receipt).
    pub(super) fn write_withdrawn<S: AuditStore>(&self, s: &mut S, key: &str, attempt: u32) -> Result<(), Value> {
        let checkpoint = json!({"key": task_checkpoint(key), "from": 0, "to": 0, "context": {"kind": "EXTEND", "reason": WITHDRAWN_WHOLE}});
        let id = if attempt == 0 { format!("withdrawn:{key}") } else { format!("withdrawn:{key}#retry{attempt}") };
        match s.submit_operations_id(&id, "kernel", &[], Some(checkpoint)) {
            Ok(r) if r["checkpointed"] == true && r["error"].is_null() => Ok(()),
            Ok(r) => Err(if r["error"].is_null() { json!({"code": "NOT_CHECKPOINTED", "reply": r}) } else { r["error"].clone() }),
            Err(e) => Err(e.to_json()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawn_spans_are_cut_to_the_range_and_merged() {
        assert_eq!(withdrawn_in(&[(5, 9), (0, 3), (8, 12), (20, 30)], 2, 22), vec![(2, 3), (5, 12), (20, 22)]);
        assert!(withdrawn_in(&[(0, 2), (9, 9)], 2, 9).is_empty(), "a span ending at the range's start, or empty, touches nothing");
    }

    #[test]
    fn a_range_is_withdrawn_whole_when_only_whitespace_lies_outside_its_withdrawn_bytes() {
        let text = "## A\n\none two\n\n## B\n";
        let at = |q: &str| {
            let i = text.find(q).unwrap();
            (i, i + q.len())
        };
        let section = (0, text.find("## B").unwrap());
        assert!(withdrawn_whole(text, section.0, section.1, &[at("## A\n\none two")]), "the blank line after it carries nothing");
        assert!(withdrawn_whole(text, section.0, section.1, &[at("## A"), at("one two")]));
        assert!(!withdrawn_whole(text, section.0, section.1, &[at("one two")]), "the heading is left");
        assert!(!withdrawn_whole(text, section.0, section.1, &[]), "nothing withdrawn is not withdrawn whole");
        assert!(!withdrawn_whole("\n\n", 0, 2, &[]), "nor is a blank range");
    }

    #[test]
    fn a_shown_section_marks_each_withdrawn_run_by_its_length_and_is_the_text_itself_without_one() {
        let text = "## A\n\nRule one.\n\nRule twö.\n\n## B\n";
        let at = |q: &str| {
            let i = text.find(q).unwrap();
            (i, i + q.len())
        };
        let end = text.find("## B").unwrap();
        assert_eq!(shown_section(text, 0, end, &[]), (text[..end].to_string(), false));
        assert_eq!(shown_section(text, 0, end, &[at("## B")]), (text[..end].to_string(), false), "withdrawn text of another section");
        let (shown, marked) = shown_section(text, 0, end, &[at("Rule one."), at("twö")]);
        assert!(marked);
        assert_eq!(shown, "## A\n\n[withdrawn: 9 bytes]\n\nRule [withdrawn: 4 bytes].\n\n");
        // a run that crosses the range's end is cut to it
        let (shown, _) = shown_section(text, 0, at("Rule one.").0 + 4, &[at("Rule one.")]);
        assert_eq!(shown, "## A\n\n[withdrawn: 4 bytes]");
    }
}
