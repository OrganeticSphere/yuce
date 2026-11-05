//! Typed requests of the graph builder (U1): on a sign its card shows, the builder asks for
//! more reading, never with words of its own for the swarm. A request is one of a closed set of types in two families, a report
//! section and two records with their link, and is checked as strictly as a swarm answer. The kernel writes the task from its own
//! neutral template and leases it like any other. Records written under such a task carry its `TR<n>-` directive; a request never
//! rests on them (no chains), and the analysis tells them apart.
//!
//! The control group of the same run: for every accepted `reread_gap` the kernel itself picks
//! another saturated section, deterministically, and leases one second reading of it with the same template and no focus terms
//! (`TC<n>-`, key `control:<n>`). Builder-chosen and kernel-chosen second readings are then compared.

use super::*;

/// The request types, each with the reason codes it may give (a closed list: a human explanation goes to the journal, never into a
/// prompt). `split_concept` of the specification is not in v1.
pub const REQUEST_TYPES: [&str; 3] = ["reread_gap", "check_coverage", "find_link_basis"];
/// `section_refused` (tuning before 10A-17): a section whose first reading had refused answers, shown on the builder's board; the
/// builder never sees its bytes, so such a request may come without focus terms.
const REREAD_REASONS: [&str; 4] = ["section_refused", "section_saturated", "concept_single_report", "rq_topic_missing"];
const COVERAGE_REASONS: [&str; 1] = ["report_no_claims_for_rq"];
const LINK_BASIS_REASONS: [&str; 1] = ["link_without_bridge"];
const MAX_FOCUS: usize = 5;
const MAX_FOCUS_CHARS: usize = 120;
const MAX_BASED_ON: usize = 8;
const MAX_LOCAL_ID_CHARS: usize = 40;
/// A section whose first reading stored this many records counts as saturated for the control group (the swarm's answers stop
/// near 22 lines, live runs 10A-13 and 10A-14).
const SATURATED_RECORDS: usize = 20;

/// A request about a section or a whole report.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum SectionRequest {
    /// A second reading of one section, about these terms (each one occurs in its bytes).
    RereadGap { section: usize, focus: Vec<String> },
    /// What a report says about a research question it has no claims for yet.
    CheckCoverage { rq: String },
}

/// A request about records already in the graph.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum RecordRequest {
    /// What the sources say about a proposed link between two records: a quote for it, one against it, or nothing.
    FindLinkBasis { link: LinkId },
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Target {
    Section { doc: String, kind: SectionRequest },
    Records { records: [RecordId; 2], kind: RecordRequest },
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Request {
    pub card_id: String,
    pub local_id: String,
    pub reason: String,
    pub based_on: Vec<RecordId>,
    pub target: Target,
    /// The section the kernel chose for this request's control reading (`reread_gap` only; none when no read section is free).
    pub control: Option<(String, usize)>,
}

pub(super) fn request_key(n: usize) -> String {
    format!("request:{n}")
}

pub(super) fn control_key(n: usize) -> String {
    format!("control:{n}")
}

/// The request number of a `request:<n>` or `control:<n>` key.
pub(super) fn request_number(key: &str) -> Option<usize> {
    key.strip_prefix("request:").or_else(|| key.strip_prefix("control:")).and_then(|n| n.parse().ok()).filter(|n| *n > 0)
}

/// Whether a record was written under a request or a control task: a request never rests on it.
pub(super) fn from_request(directive: &str) -> bool {
    marked(directive, "TR") || marked(directive, "TC")
}

fn bad(code: Code, msg: impl Into<String>, field: &str) -> KernelError {
    KernelError::new(code, msg).field(field)
}

fn hex_ids(ids: &[RecordId]) -> Vec<String> {
    ids.iter().map(|r| crate::hash::to_hex(&r.0)).collect()
}

fn norm(t: &str) -> String {
    t.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

impl Request {
    pub(super) fn ty(&self) -> &'static str {
        match &self.target {
            Target::Section { kind: SectionRequest::RereadGap { .. }, .. } => "reread_gap",
            Target::Section { kind: SectionRequest::CheckCoverage { .. }, .. } => "check_coverage",
            Target::Records { kind: RecordRequest::FindLinkBasis { .. }, .. } => "find_link_basis",
        }
    }

    /// Two requests asking for the same work: type, target and normalized focus.
    fn dedup_key(&self) -> String {
        match &self.target {
            Target::Section { doc, kind: SectionRequest::RereadGap { section, focus } } => {
                let mut f: Vec<String> = focus.iter().map(|t| norm(t)).collect();
                f.sort();
                f.dedup();
                format!("reread_gap|{doc}|{section}|{}", f.join("|"))
            }
            Target::Section { doc, kind: SectionRequest::CheckCoverage { rq } } => format!("check_coverage|{doc}|{rq}"),
            Target::Records { kind: RecordRequest::FindLinkBasis { link }, .. } => format!("find_link_basis|{}", crate::hash::to_hex(&link.0)),
        }
    }

    /// The same ask as `other` (its control section is the kernel's choice, not part of the ask).
    fn same_ask(&self, other: &Request) -> bool {
        (&self.card_id, &self.local_id, &self.reason, &self.based_on, &self.target)
            == (&other.card_id, &other.local_id, &other.reason, &other.based_on, &other.target)
    }

    pub(super) fn link(&self) -> Option<LinkId> {
        match &self.target {
            Target::Records { kind: RecordRequest::FindLinkBasis { link }, .. } => Some(*link),
            Target::Section { .. } => None,
        }
    }

    /// The durable form (full ids), read back by `from_json` after a restart.
    fn to_json(&self) -> Value {
        let mut v = json!({"type": self.ty(), "card_id": self.card_id, "local_id": self.local_id, "reason": self.reason,
                           "based_on": hex_ids(&self.based_on),
                           "control": self.control.as_ref().map(|(d, k)| json!({"doc_id": d, "section": k}))});
        match &self.target {
            Target::Section { doc, kind } => {
                v["doc_id"] = json!(doc);
                match kind {
                    SectionRequest::RereadGap { section, focus } => {
                        v["section"] = json!(section);
                        v["focus"] = json!(focus);
                    }
                    SectionRequest::CheckCoverage { rq } => v["rq_id"] = json!(rq),
                }
            }
            Target::Records { records, kind: RecordRequest::FindLinkBasis { link } } => {
                v["records"] = json!(hex_ids(records));
                v["link"] = json!(crate::hash::to_hex(&link.0));
            }
        }
        v
    }

    fn from_json(v: &Value) -> Option<Request> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let ids =
            |k: &str| -> Option<Vec<RecordId>> { v.get(k)?.as_array()?.iter().map(|x| x.as_str().and_then(crate::hash::from_hex).map(RecordId)).collect() };
        let doc = s("doc_id");
        let target = match v.get("type")?.as_str()? {
            "reread_gap" => Target::Section {
                doc: doc?,
                kind: SectionRequest::RereadGap {
                    section: v.get("section")?.as_u64()? as usize,
                    focus: v.get("focus")?.as_array()?.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<_>>()?,
                },
            },
            "check_coverage" => Target::Section { doc: doc?, kind: SectionRequest::CheckCoverage { rq: s("rq_id")? } },
            "find_link_basis" => {
                let r = ids("records")?;
                Target::Records {
                    records: [*r.first()?, *r.get(1)?],
                    kind: RecordRequest::FindLinkBasis { link: s("link").and_then(|x| crate::hash::from_hex(&x)).map(LinkId)? },
                }
            }
            _ => return None,
        };
        let control = match v.get("control") {
            Some(Value::Null) | None => None,
            Some(c) => Some((c.get("doc_id")?.as_str()?.to_string(), c.get("section")?.as_u64()? as usize)),
        };
        Some(Request { card_id: s("card_id")?, local_id: s("local_id")?, reason: s("reason")?, based_on: ids("based_on")?, target, control })
    }
}

/// A record by its short `@id` or its full id.
fn find_record<S: AuditStore>(s: &S, id: &str) -> Option<RecordView> {
    if let Some(r) = crate::hash::from_hex(id.strip_prefix('@').unwrap_or(id)).map(RecordId).and_then(|r| s.record(&r)) {
        return Some(r);
    }
    id.starts_with('@').then(|| s.records_since(0).into_iter().find(|r| r.id.short() == id)).flatten()
}

fn find_link<S: AuditStore>(s: &S, id: &str) -> Option<LinkView> {
    if let Some(l) = crate::hash::from_hex(id.strip_prefix('@').unwrap_or(id)).map(LinkId).and_then(|l| s.link(&l)) {
        return Some(l);
    }
    id.starts_with('@').then(|| s.links().into_iter().find(|l| l.id.short() == id)).flatten()
}

/// The byte offset of an observe in its document (the store keeps each accepted quote unique within its section; the first
/// occurrence places it).
fn observe_at(text: &str, r: &RecordView) -> Option<usize> {
    r.quote.as_deref().filter(|q| !q.is_empty()).and_then(|q| text.find(q))
}

impl Dispatcher {
    /// A5: the kernel does not wait for a builder card or spend its content-request quota on damaged first readings. Each
    /// reread costs one slot: least-served report first, then highest loss_score within it, with stable document/section ties.
    /// Two slots per report bound the first wave and reserve room for late reports. Later waves share the bounded remainder.
    /// A reread never schedules another reread.
    pub(super) fn auto_reread_work<S: AuditStore>(&self, s: &S) -> Vec<Work> {
        if self.cfg.auto_reread_limit == 0 {
            return vec![];
        }
        let mut served: BTreeMap<String, usize> = BTreeMap::new();
        let used: BTreeSet<String> = self
            .handled
            .iter()
            .chain(&self.unresolved)
            .cloned()
            .chain(self.leases.values().map(|l| l.key.clone()))
            .filter(|k| k.starts_with("reread:"))
            .collect();
        for key in &used {
            if let Some((doc, _)) = key[7..].rsplit_once('#') {
                *served.entry(doc.to_string()).or_default() += 1;
            }
        }
        let mut remaining = self.cfg.auto_reread_limit.saturating_sub(used.len());
        let mut per_doc: BTreeMap<String, Vec<(usize, usize, usize, usize)>> = BTreeMap::new();
        for (key, loss) in &self.strained {
            let Some((doc, k)) = key.strip_prefix("doc:").and_then(|x| x.rsplit_once('#')) else { continue };
            let Ok(k) = k.parse::<usize>() else { continue };
            let reread = format!("reread:{doc}#{k}");
            if used.contains(&reread) {
                continue;
            }
            let text = s.doc_text(doc).unwrap_or_default();
            if let Some((a, b)) = sections(&text, self.cfg.section_bytes).get(k) {
                per_doc.entry(doc.to_string()).or_default().push((loss.score(), k, *a, *b));
            }
        }
        for rows in per_doc.values_mut() {
            rows.sort_by_key(|(score, k, _, _)| (std::cmp::Reverse(*score), *k));
        }
        let first_readings_done = s.docs().iter().all(|doc| {
            sections(&s.doc_text(doc).unwrap_or_default(), self.cfg.section_bytes)
                .iter()
                .enumerate()
                .all(|(k, _)| self.handled.contains(&format!("doc:{doc}#{k}")) || self.unresolved.contains(&format!("doc:{doc}#{k}")))
        });
        let mut out = Vec::new();
        while remaining > 0 {
            // Reserve room for reports whose primary readings have not yet revealed their losses. Once the first wave has
            // served every currently damaged report (or exhausted its losses), further unit-cost fair rounds use the remainder.
            let needs_first_wave = per_doc.iter().any(|(doc, rows)| !rows.is_empty() && served.get(doc).copied().unwrap_or(0) < 2);
            let next = per_doc
                .iter()
                .filter(|(doc, rows)| !rows.is_empty() && (served.get(*doc).copied().unwrap_or(0) < 2 || (first_readings_done && !needs_first_wave)))
                .min_by_key(|(doc, rows)| (served.get(*doc).copied().unwrap_or(0), std::cmp::Reverse(rows[0].0), (*doc).clone()))
                .map(|(doc, _)| doc.clone());
            let Some(doc) = next else { break };
            let (_, k, a, b) = per_doc.get_mut(&doc).expect("selected report").remove(0);
            *served.entry(doc.clone()).or_default() += 1;
            remaining -= 1;
            out.push((TaskKind::Request, format!("reread:{doc}#{k}"), None, None, Some((doc, a, b))));
        }
        out
    }

    pub(super) fn auto_reread_prompt<S: AuditStore>(&self, s: &S, f: &Flags, key: &str) -> (String, Scope, Vec<RecordId>) {
        let (doc, k) = key[7..].rsplit_once('#').expect("a reread section key");
        let text = s.doc_text(doc).unwrap_or_default();
        let (a, b) = sections(&text, self.cfg.section_bytes)[k.parse::<usize>().expect("section number")];
        let (base, scope, issued) = self.extend_prompt(s, f, &(doc.to_string(), a, b));
        (
            format!(
                "KERNEL LOSS REREAD (generation 1): retain already accepted records; record only independent missing facts. \
            The first reading had refusals; this is not evidence that its source says less. Do not duplicate known claims.\n{base}"
            ),
            scope,
            issued,
        )
    }

    /// The builder's request lines of one answer for the open card `card_id` (`(index in the answer, line)`): each checked,
    /// deduplicated, bounded and, when accepted, written durably as the checkpoint `request:<n>`. A refusal comes back as an
    /// operation's refusal does and leaves the card's operations alone; an exact resend of an accepted request (a retried answer)
    /// gets its acceptance again.
    pub fn builder_requests<S: AuditStore>(&mut self, s: &mut S, card_id: &str, lines: &[(usize, Value)]) -> Vec<Value> {
        lines
            .iter()
            .map(|(i, line)| match self.builder_request(s, card_id, line) {
                Ok((n, replayed)) => {
                    let r = &self.requests[n - 1];
                    json!({"index": i, "local_id": line.get("local_id"), "status": "accepted", "request": request_key(n), "type": r.ty(),
                           "replayed": replayed})
                }
                Err(e) => {
                    self.stats.requests_refused += 1;
                    json!({"index": i, "local_id": line.get("local_id"), "status": "refused", "error": e.to_json()})
                }
            })
            .collect()
    }

    fn builder_request<S: AuditStore>(&mut self, s: &mut S, card_id: &str, line: &Value) -> Result<(usize, bool), KernelError> {
        if self.cfg.max_requests == 0 {
            return Err(bad(Code::UnknownOp, "requests are off in this run", "op"));
        }
        // an exact resend of an accepted request keeps its acceptance whatever its work changed since (a report covered, a link
        // checked): it is recognised by its form and ids before the conditions the graph may have changed are checked (Codex's C17-02)
        let asked = self.check_request(s, card_id, line, false)?;
        if let Some(n) = self.requests.iter().position(|x| x.card_id == asked.card_id && x.local_id == asked.local_id) {
            return if self.requests[n].same_ask(&asked) {
                Ok((n + 1, true))
            } else {
                Err(bad(Code::DuplicateLocalId, "this local_id already names another request of this card", "local_id"))
            };
        }
        let mut r = self.check_request(s, card_id, line, true)?;
        let key = r.dedup_key();
        if let Some(n) = self.requests.iter().position(|x| x.dedup_key() == key) {
            return Err(bad(Code::BadField, format!("the same work was already requested as {}", request_key(n + 1)), "type"));
        }
        let per_card = self.requests.iter().filter(|x| x.card_id == card_id).count();
        if per_card >= self.cfg.requests_per_card {
            return Err(bad(Code::BadField, format!("at most {} requests per card", self.cfg.requests_per_card), "op")
                .expected(json!({"requests_per_card": self.cfg.requests_per_card})));
        }
        if self.requests.len() >= self.cfg.max_requests {
            return Err(bad(Code::BadField, format!("the run's {} requests are used up", self.cfg.max_requests), "op")
                .expected(json!({"max_requests": self.cfg.max_requests})));
        }
        let n = self.requests.len() + 1;
        if matches!(r.target, Target::Section { kind: SectionRequest::RereadGap { .. }, .. }) {
            r.control = self.control_section(s, n, &r);
        }
        let checkpoint = json!({"key": request_key(n), "from": 0, "to": 0, "context": r.to_json()});
        match s.submit_operations_id(&request_key(n), "builder", &[], Some(checkpoint)) {
            Ok(v) if v["error"].is_null() && v["checkpointed"] == true => {}
            Ok(v) => return Err(bad(Code::BadField, format!("the store refused the request: {}", v["error"]), "op")),
            Err(e) => return Err(e),
        }
        self.requests.push(r);
        self.stats.requests_accepted += 1;
        Ok((n, false))
    }

    /// The acknowledgement of a request line that repeats an accepted request exactly: a retried answer of a card already closed
    /// gets the acceptance its requests had (Codex's C17-02); `None` when no accepted request is this one.
    pub fn replay_request<S: AuditStore>(&self, s: &S, card_id: &str, line: &Value) -> Option<Value> {
        let asked = self.check_request(s, card_id, line, false).ok()?;
        let n = self.requests.iter().position(|x| x.same_ask(&asked))?;
        Some(json!({"local_id": line.get("local_id"), "status": "accepted", "request": request_key(n + 1), "type": asked.ty(), "replayed": true}))
    }

    /// One request line checked against the closed type set, its own fields and the graph; nothing is written. Without
    /// `conditions` only its form and the ids it names are checked, not what the graph may change (a section read, a report's
    /// claims, a link's status).
    fn check_request<S: AuditStore>(&self, s: &S, card_id: &str, line: &Value, conditions: bool) -> Result<Request, KernelError> {
        let obj = line.as_object().ok_or_else(|| bad(Code::BadField, "a request is a JSON object", "op"))?;
        let field = |k: &str| obj.get(k).ok_or_else(|| bad(Code::MissingField, format!("missing '{k}'"), k));
        let text = |k: &str| field(k)?.as_str().filter(|x| !x.trim().is_empty()).ok_or_else(|| bad(Code::BadField, format!("'{k}' is a non-empty string"), k));
        let ty = text("type")?;
        let (own, reasons): (&[&str], &[&str]) = match ty {
            "reread_gap" => (&["doc_id", "section", "focus"], &REREAD_REASONS),
            "check_coverage" => (&["doc_id", "rq_id"], &COVERAGE_REASONS),
            "find_link_basis" => (&["records", "link"], &LINK_BASIS_REASONS),
            other => {
                return Err(bad(Code::BadField, format!("unknown request type '{other}'"), "type").expected(json!({"type": REQUEST_TYPES})));
            }
        };
        let allowed: Vec<&str> = ["op", "type", "local_id", "reason", "based_on"].into_iter().chain(own.iter().copied()).collect();
        if let Some(k) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
            return Err(bad(Code::BadField, format!("a {ty} request has no field '{k}'"), k).expected(json!({"fields": allowed})));
        }
        for k in &allowed {
            field(k)?;
        }
        let local_id = text("local_id")?;
        if local_id.chars().count() > MAX_LOCAL_ID_CHARS {
            return Err(bad(Code::BadField, format!("local_id of at most {MAX_LOCAL_ID_CHARS} characters"), "local_id"));
        }
        let reason = text("reason")?;
        if !reasons.contains(&reason) {
            return Err(bad(Code::BadField, format!("a {ty} request gives one of its reasons"), "reason").expected(json!({"reason": reasons})));
        }
        let based_on: Vec<RecordId> = {
            let ids = field("based_on")?
                .as_array()
                .filter(|a| (1..=MAX_BASED_ON).contains(&a.len()))
                .ok_or_else(|| bad(Code::NoEvidence, format!("based_on names 1..{MAX_BASED_ON} accepted records"), "based_on"))?;
            let mut out = Vec::new();
            for x in ids {
                let id = x.as_str().unwrap_or("");
                let r = find_record(s, id).ok_or_else(|| bad(Code::UnknownLocalId, format!("{id} is not an accepted record"), "based_on"))?;
                // no chains: what a request or a control reading wrote does not ground another request (generation 1 at most)
                if from_request(&r.directive) {
                    return Err(bad(Code::BadField, format!("{id} was written under a request: a request rests on no such record"), "based_on"));
                }
                out.push(r.id);
            }
            out
        };
        let doc = |k: &str| -> Result<(String, String), KernelError> {
            let d = text(k)?;
            let t = s.doc_text(d).filter(|_| s.docs().iter().any(|x| x == d));
            t.map(|t| (d.to_string(), t)).ok_or_else(|| bad(Code::UnknownDoc, format!("{d} is not a document of this run"), k))
        };
        let target = match ty {
            "reread_gap" => {
                let (d, t) = doc("doc_id")?;
                let secs = sections(&t, self.cfg.section_bytes);
                let section = field("section")?
                    .as_u64()
                    .map(|n| n as usize)
                    .filter(|n| *n < secs.len())
                    .ok_or_else(|| bad(Code::BadField, format!("section is a section number of {d}: 0..{}", secs.len().saturating_sub(1)), "section"))?;
                // a section whose reading was given up after failed leases was read too, at a loss (Codex's C17-01)
                let key = format!("doc:{d}#{section}");
                if conditions && !self.handled.contains(&key) && !self.unresolved.contains(&key) {
                    return Err(bad(Code::BadField, "a second reading needs a section the swarm has read", "section"));
                }
                let (a, b) = secs[section];
                let refused = reason == "section_refused";
                if conditions && refused && !self.strained.contains_key(&key) {
                    return Err(bad(Code::BadField, "section_refused names a section of requests.losses", "reason"));
                }
                let least = usize::from(!refused || self.cfg.auto_reread_limit > 0);
                let focus: Vec<String> = field("focus")?
                    .as_array()
                    .filter(|f| (least..=MAX_FOCUS).contains(&f.len()))
                    .and_then(|f| f.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
                    .ok_or_else(|| bad(Code::BadField, format!("focus is {least}..{MAX_FOCUS} terms"), "focus"))?;
                if let Some(term) = focus.iter().find(|x| x.trim().is_empty() || x.chars().count() > MAX_FOCUS_CHARS || !t[a..b].contains(x.as_str())) {
                    return Err(bad(Code::BadField, format!("'{term}' does not occur in the section: a focus term is copied from its bytes"), "focus"));
                }
                Target::Section { doc: d, kind: SectionRequest::RereadGap { section, focus } }
            }
            "check_coverage" => {
                let (d, _) = doc("doc_id")?;
                let rq = text("rq_id")?;
                let q = self.questions.iter().find(|q| q.id == rq).ok_or_else(|| {
                    bad(Code::BadField, format!("unknown research question '{rq}'"), "rq_id")
                        .expected(json!({"rq_id": self.questions.iter().map(|q| &q.id).collect::<Vec<_>>()}))
                })?;
                let n = if conditions { self.claims_for(s, &Flags::of(s), &d, q) } else { 0 };
                if n > 0 {
                    return Err(bad(Code::BadField, format!("{d} already has {n} claims for {rq}"), "rq_id"));
                }
                Target::Section { doc: d, kind: SectionRequest::CheckCoverage { rq: rq.to_string() } }
            }
            _ => {
                let recs =
                    field("records")?.as_array().filter(|a| a.len() == 2).ok_or_else(|| bad(Code::BadField, "records names the link's two ends", "records"))?;
                let mut ends = Vec::new();
                for x in recs {
                    let id = x.as_str().unwrap_or("");
                    ends.push(find_record(s, id).ok_or_else(|| bad(Code::UnknownLocalId, format!("{id} is not an accepted record"), "records"))?.id);
                }
                let lid = text("link")?;
                let l = find_link(s, lid).ok_or_else(|| bad(Code::UnknownEntity, format!("{lid} is not a link of this run"), "link"))?;
                if conditions && l.status != LinkStatus::Proposed {
                    return Err(bad(Code::BadField, format!("{lid} is {}: only a proposed link waits for its basis", l.status.name()), "link"));
                }
                if ![l.from, l.to].iter().all(|e| ends.contains(e)) {
                    return Err(
                        bad(Code::BadField, "records are the two ends of the link", "records").expected(json!({"records": [l.from.short(), l.to.short()]}))
                    );
                }
                let check = format!("verify:{}", l.id.short());
                if conditions && self.taken(&check) {
                    return Err(bad(Code::BadField, format!("{lid} is being checked already"), "link"));
                }
                Target::Records { records: [l.from, l.to], kind: RecordRequest::FindLinkBasis { link: l.id } }
            }
        };
        Ok(Request { card_id: card_id.to_string(), local_id: local_id.to_string(), reason: reason.to_string(), based_on, target, control: None })
    }

    /// The claims a report already holds for a research question: grounded claims resting on its quotes that name the question's
    /// topics or carry one of its stances (summaries and link checks excluded).
    fn claims_for<S: AuditStore>(&self, s: &S, f: &Flags, doc: &str, q: &ResearchQuestion) -> usize {
        let all = s.records_since(0);
        let quotes: BTreeSet<RecordId> = all.iter().filter(|r| r.doc_id.as_deref() == Some(doc)).map(|r| r.id).collect();
        let topics = Topics::new(&q.about);
        all.iter()
            .filter(|r| r.kind == RecordKind::Claim && !is_summary_directive(&r.directive) && !is_link_directive(&r.directive))
            .filter(|r| r.based_on.iter().any(|b| quotes.contains(b)) && f.grounded(s, &r.id))
            .filter(|r| {
                r.status.as_ref().is_some_and(|st| q.stances.contains(st))
                    || r.text.as_deref().is_some_and(|t| topics.named(t))
                    || r.terms.iter().any(|t| topics.named(t))
            })
            .count()
    }

    /// Records of a section's first reading: its observes and the records resting directly on them (second readings, link
    /// checks and summaries excluded).
    fn section_records<S: AuditStore>(&self, s: &S, doc: &str, text: &str, (a, b): (usize, usize)) -> Vec<RecordView> {
        let first = |r: &RecordView| !from_request(&r.directive) && !is_link_directive(&r.directive) && !is_summary_directive(&r.directive);
        let all = s.records_since(0);
        let quotes: BTreeSet<RecordId> = all
            .iter()
            .filter(|r| r.kind == RecordKind::Observe && r.doc_id.as_deref() == Some(doc) && first(r))
            .filter(|r| observe_at(text, r).is_some_and(|p| a <= p && p < b))
            .map(|r| r.id)
            .collect();
        all.into_iter().filter(|r| first(r) && (quotes.contains(&r.id) || r.based_on.iter().any(|x| quotes.contains(x)))).collect()
    }

    /// The kernel's own section for the control reading of request `n`: a deterministic choice among saturated sections the swarm
    /// has read that no builder request names and no other control took; else among any such read section.
    fn control_section<S: AuditStore>(&self, s: &S, n: usize, r: &Request) -> Option<(String, usize)> {
        let mut requested: BTreeSet<(String, usize)> = self
            .requests
            .iter()
            .filter_map(|x| match &x.target {
                Target::Section { doc, kind: SectionRequest::RereadGap { section, .. } } => Some((doc.clone(), *section)),
                _ => None,
            })
            .collect();
        if let Target::Section { doc, kind: SectionRequest::RereadGap { section, .. } } = &r.target {
            requested.insert((doc.clone(), *section));
        }
        let controlled: BTreeSet<(String, usize)> = self.requests.iter().filter_map(|x| x.control.clone()).collect();
        let (mut saturated, mut read) = (Vec::new(), Vec::new());
        let mut docs = s.docs();
        docs.sort();
        for d in docs {
            let text = s.doc_text(&d).unwrap_or_default();
            for (k, range) in sections(&text, self.cfg.section_bytes).into_iter().enumerate() {
                let at = (d.clone(), k);
                if !self.handled.contains(&format!("doc:{d}#{k}")) || requested.contains(&at) || controlled.contains(&at) {
                    continue;
                }
                if self.section_records(s, &d, &text, range).len() >= SATURATED_RECORDS {
                    saturated.push(at.clone());
                }
                read.push(at);
            }
        }
        let pool = if saturated.is_empty() { read } else { saturated };
        let h = crate::hash::sha256(crate::jcs::to_jcs(&json!(["r2r-control/1", request_key(n), r.card_id, r.local_id])).as_bytes());
        let pick = u64::from_be_bytes(h[..8].try_into().expect("a sha256 has 8 bytes")) as usize;
        (!pool.is_empty()).then(|| pool[pick % pool.len()].clone())
    }

    /// After a restart: the accepted requests come back from their checkpoints `request:1`, `request:2`, ...
    pub(super) fn load_requests<S: AuditStore>(&mut self, s: &S) {
        self.requests = (1..).map_while(|n| s.checkpoint(&request_key(n)).and_then(|c| Request::from_json(&c["context"]))).collect();
    }

    /// The open work of the requests and of their control readings.
    pub(super) fn request_work<S: AuditStore>(&self, s: &S) -> Vec<Work> {
        let at = |doc: &String, k: usize| {
            let text = s.doc_text(doc).unwrap_or_default();
            sections(&text, self.cfg.section_bytes).get(k).map(|(a, b)| (doc.clone(), *a, *b))
        };
        let mut out = Vec::new();
        for (i, r) in self.requests.iter().enumerate() {
            let n = i + 1;
            match &r.target {
                Target::Section { doc, kind: SectionRequest::RereadGap { section, .. } } => {
                    out.push((TaskKind::Request, request_key(n), None, None, at(doc, *section)));
                    if let Some((d, k)) = &r.control {
                        out.push((TaskKind::Request, control_key(n), None, None, at(d, *k)));
                    }
                }
                Target::Section { .. } => out.push((TaskKind::Request, request_key(n), None, None, None)),
                Target::Records { kind: RecordRequest::FindLinkBasis { link }, .. } => out.push((TaskKind::Request, request_key(n), Some(*link), None, None)),
            }
        }
        out
    }

    /// Links whose check waits for an open request about them.
    pub(super) fn links_awaiting_requests(&self) -> BTreeSet<LinkId> {
        self.requests
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let k = request_key(i + 1);
                !self.handled.contains(&k) && !self.unresolved.contains(&k)
            })
            .filter_map(|(_, r)| r.link())
            .collect()
    }

    /// What a request task of a link wrote: shown to the link's check next to the link's own records.
    pub(super) fn request_records_of_link<S: AuditStore>(&self, s: &S, f: &Flags, link: LinkId) -> Vec<RecordView> {
        let asked: BTreeSet<usize> = self.requests.iter().enumerate().filter(|(_, r)| r.link() == Some(link)).map(|(i, _)| i + 1).collect();
        let tasks: BTreeSet<&String> = self.request_tasks.iter().filter(|(_, n)| asked.contains(n)).map(|(t, _)| t).collect();
        s.records_since(0).into_iter().filter(|r| tasks.contains(&r.directive) && f.grounded(s, &r.id)).collect()
    }

    /// The directive of a request or control task, from the kernel's own templates.
    pub(super) fn request_prompt<S: AuditStore>(&self, s: &S, f: &Flags, key: &str) -> (String, Scope, Vec<RecordId>) {
        let n = request_number(key).expect("a request task has a request number");
        let r = &self.requests[n - 1];
        let control = key.starts_with("control:");
        match (&r.target, control) {
            (Target::Section { doc, kind: SectionRequest::RereadGap { section, focus } }, _) => {
                let (doc, section) = if control { r.control.clone().expect("a control task has its section") } else { (doc.clone(), *section) };
                let text = s.doc_text(&doc).unwrap_or_default();
                let (a, b) = sections(&text, self.cfg.section_bytes)[section];
                let mut known: Vec<RecordView> =
                    self.section_records(s, &doc, &text, (a, b)).into_iter().filter(|r| matches!(r.kind, RecordKind::Claim | RecordKind::Hypothesis)).collect();
                known.truncate(2 * self.cfg.max_known);
                // the control reading has no focus: the same template, the same section list, nothing the builder chose
                let about = if control || focus.is_empty() { String::new() } else { format!(", in particular about: {}", focus.join("; ")) };
                let prompt = format!(
                    "TASK REREAD: a second reading of this section of report {doc}. The claims below were already recorded from it. Record only \
                     what they miss that matters for the research questions{about}. Quote only from the section. If they miss nothing, answer \
                     [].\nRESEARCH QUESTIONS:\n{}\n{}\nSECTION doc_id=\"{doc}\" (bytes {a}..{b}):\n<<<\n{}\n>>>",
                    self.questions_text(),
                    known_block(&known, "ALREADY RECORDED FROM THIS SECTION (do not repeat; relate to these @ids instead)"),
                    &text[a..b]
                );
                let issued = known.iter().map(|r| r.id).collect();
                (prompt, Scope { docs: vec![doc.clone()], topic: None, ranges: vec![(doc, a, b)] }, issued)
            }
            (Target::Section { doc, kind: SectionRequest::CheckCoverage { rq } }, _) => {
                let q = self.questions.iter().find(|q| &q.id == rq).expect("a checked request names a question");
                let text = s.doc_text(doc).unwrap_or_default();
                let topics: Vec<String> = q.about.iter().map(|t| t.to_lowercase()).collect();
                let mut secs: Vec<(usize, usize, usize)> = sections(&text, self.cfg.section_bytes)
                    .into_iter()
                    .map(|(a, b)| {
                        let low = text[a..b].to_lowercase();
                        (topics.iter().filter(|t| !t.is_empty() && low.contains(t.as_str())).count(), a, b)
                    })
                    .collect();
                // the sections that name most of the question's topics; with none, the report's first sections
                secs.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
                let chosen: Vec<(String, usize, usize, String)> =
                    secs.into_iter().take(2).map(|(_, a, b)| (doc.clone(), a, b, text[a..b].to_string())).collect();
                let known = self.known(s, f, &q.about, Some(doc));
                let base = format!(
                    "TASK CHECK_COVERAGE: read these sections of report {doc} for research question {}: {}\nRecord what they establish, \
                     qualify, revoke or leave open that bears on this question, quoting only from them. If they say nothing that bears on it, \
                     answer [].\n{}",
                    q.id,
                    q.text,
                    known_block(&known, "ALREADY RECORDED (do not repeat; relate to these @ids instead)")
                );
                self.with_sections(base, &chosen, known.iter().map(|r| r.id).collect())
            }
            (Target::Records { records, kind: RecordRequest::FindLinkBasis { link } }, _) => {
                let rel = s.link(link).map(|l| l.rel).unwrap_or_default();
                let cone_recs = self.cone(s, f, records);
                let cone: Vec<String> = cone_recs.iter().map(rec_line).collect();
                let terms: Vec<String> =
                    records.iter().filter_map(|r| s.record(r)).flat_map(|r| r.terms).chain(cone_recs.iter().filter_map(|r| r.quote.clone())).collect();
                let ask = format!(
                    "TASK FIND_LINK_BASIS: what do the sources below say about whether {} {rel} {}? Quote only from the sections below. Write \
                     the observe lines that bear on it, for it or against it, then at most two claim lines saying what those quotes show \
                     about these two records. If the sections say nothing about it, answer []. Write no relation, verdict or question \
                     lines: a separate check decides the link.",
                    records[0].short(),
                    records[1].short()
                );
                let issued = cone_recs.iter().map(|x| x.id).collect();
                self.with_sections(format!("{ask}\nRECORDS:\n{}", cone.join("\n")), &self.sections_about(s, &terms), issued)
            }
        }
    }

    /// What the graph builder's card shows for requests (None when they are off): the budget, the section of each observe it
    /// shows, the claims each report holds per research question, and the proposed links among the records it shows.
    pub fn request_board<S: AuditStore>(&self, s: &S, card: &super::super::builder::Card) -> Option<Value> {
        if self.cfg.max_requests == 0 {
            return None;
        }
        let used = self.requests.iter().filter(|x| x.card_id == card.card_id).count();
        let shown: Vec<&RecordView> = card.records.iter().chain(&card.neighbors).collect();
        let mut texts: BTreeMap<String, String> = BTreeMap::new();
        let mut at: BTreeMap<String, Value> = BTreeMap::new();
        for r in shown.iter().filter(|r| r.kind == RecordKind::Observe) {
            let Some(d) = r.doc_id.clone() else { continue };
            let text = texts.entry(d.clone()).or_insert_with(|| s.doc_text(&d).unwrap_or_default());
            if let Some(p) = observe_at(text, r) {
                if let Some(k) = sections(text, self.cfg.section_bytes).iter().position(|(a, b)| *a <= p && p < *b) {
                    at.insert(r.id.short(), json!([d, k]));
                }
            }
        }
        let mut coverage = Vec::new();
        let f = Flags::of(s);
        let mut docs = s.docs();
        docs.sort();
        for d in &docs {
            for q in &self.questions {
                coverage.push(json!({"doc_id": d, "rq_id": q.id, "claims": self.claims_for(s, &f, d, q)}));
            }
        }
        // the sections read with losses that no request names yet, fewest records stored first
        let asked: BTreeSet<String> = self
            .requests
            .iter()
            .filter_map(|x| match &x.target {
                Target::Section { doc, kind: SectionRequest::RereadGap { section, .. } } => Some(format!("doc:{doc}#{section}")),
                _ => None,
            })
            .collect();
        let mut losses: Vec<(&String, &Loss)> = self.strained.iter().filter(|(k, _)| !asked.contains(*k)).collect();
        // the most damaged first: a reading given up, then lines offered but not stored, then refusals (Gemini's ranking)
        losses.sort_by_key(|(k, l)| (std::cmp::Reverse(l.score()), (*k).clone()));
        let losses: Vec<Value> = losses
            .into_iter()
            .take(10)
            .filter_map(|(k, l)| {
                let (doc, n) = k.strip_prefix("doc:")?.rsplit_once('#')?;
                Some(json!({"doc_id": doc, "section": n.parse::<usize>().ok()?, "stored": l.stored, "offered": l.offered, "refused_answers": l.refusals,
                            "abandoned": l.abandoned, "loss_score": l.score()}))
            })
            .collect();
        let ids: BTreeSet<RecordId> = shown.iter().map(|r| r.id).collect();
        let awaiting = self.links_awaiting_requests();
        let links: Vec<Value> = s
            .links()
            .into_iter()
            .filter(|l| l.status == LinkStatus::Proposed && ids.contains(&l.from) && ids.contains(&l.to))
            .filter(|l| !awaiting.contains(&l.id) && !self.taken(&format!("verify:{}", l.id.short())))
            .map(|l| json!({"link": l.id.short(), "from": l.from.short(), "rel": l.rel, "to": l.to.short()}))
            .collect();
        Some(json!({"types": REQUEST_TYPES, "card_left": self.cfg.requests_per_card.saturating_sub(used),
                    "run_left": self.cfg.max_requests.saturating_sub(self.requests.len()), "losses": losses, "sections": at, "coverage": coverage,
                    "links": links}))
    }

    /// The rules of requests for the builder's prompt (with the board of `request_board`).
    pub fn request_rules(board: &Value) -> String {
        format!(
            "\nREQUESTS. Besides operations you ask the kernel for more reading of the reports, at most {} request lines in this answer \
             ({} left in the run). Write a request for each of these signs on this card's requests board, most important first: a section \
             of requests.losses (its reading had refused answers: reread_gap with reason section_refused, focus may be []); a report with \
             claims 0 for a research question in requests.coverage (check_coverage); a proposed link of requests.links whose quotes show \
             no bridge (find_link_basis); a section of requests.sections whose records stop short of what it covers (reread_gap with \
             1-5 focus terms). With none of these signs, write no request. The kernel checks every request and writes the swarm's task \
             itself: you never write words for the swarm. Exactly these forms, nothing more:\n\
             - {{\"op\":\"request\",\"type\":\"reread_gap\",\"local_id\":\"q1\",\"doc_id\":\"<doc_id>\",\"section\":<its number in requests.losses or requests.sections>,\
             \"focus\":[\"0-5 terms copied exactly from quotes of that section; [] only with section_refused\"],\
             \"reason\":\"section_refused|section_saturated|concept_single_report|rq_topic_missing\",\"based_on\":[\"@record shown\"]}}\n\
             - {{\"op\":\"request\",\"type\":\"check_coverage\",\"local_id\":\"q2\",\"doc_id\":\"<doc_id with claims 0 in requests.coverage>\",\
             \"rq_id\":\"<that rq_id>\",\"reason\":\"report_no_claims_for_rq\",\"based_on\":[\"@record shown\"]}}\n\
             - {{\"op\":\"request\",\"type\":\"find_link_basis\",\"local_id\":\"q3\",\"records\":[\"@from\",\"@to\"],\"link\":\"@link of requests.links\",\
             \"reason\":\"link_without_bridge\",\"based_on\":[\"@from\",\"@to\"]}}\n\
             Write request lines after all operations.",
            board["card_left"], board["run_left"]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::builder::{Builder, BuilderConfig};
    use super::super::super::mem::MemStore;
    use super::*;

    const R1: &str = "# Classifier MVP\nDiffering validator versions -> warning only.\nSame canonical/hash remains a candidate only.\n\n# Limits\nVersion negotiation is future work.\n";
    const R2: &str = "# Compatibility gate\nA validator version difference is now blocking.\n";

    fn setup(max_requests: usize) -> (MemStore, Dispatcher, Builder) {
        let s = MemStore::new(&[("r1", R1), ("r2", R2)], &["Rule", "Component"]);
        let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["validator version".into()], ..Default::default() };
        let cfg = DispatchConfig { section_bytes: 80, max_requests, ..Default::default() };
        (s, Dispatcher::new(cfg, vec![q]), Builder::new(BuilderConfig::default()))
    }

    /// Every section read: the first one gets an observe and a claim (by agent w1), the others are answered empty.
    fn read_all(d: &mut Dispatcher, s: &mut MemStore, b: &mut Builder) -> RecordId {
        read_all_with(d, s, b, false)
    }

    /// As `read_all`; with `refuse_first`, the first section's first answer quotes what the section does not hold (a refused answer)
    /// before the right one.
    fn read_all_with(d: &mut Dispatcher, s: &mut MemStore, b: &mut Builder, refuse_first: bool) -> RecordId {
        loop {
            let t = d.acquire(s, "w1", b.caught_up(s), 0);
            if t["kind"] != "EXTEND" {
                break;
            }
            let id = t["task_id"].as_str().unwrap().to_string();
            let key = t["key"].as_str().unwrap();
            let lines = if key == "doc:r1#0" {
                let p = t["local_id_prefix"].as_str().unwrap();
                vec![
                    json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "r1", "exact_quote": "Differing validator versions -> warning only.", "terms": ["validator version"]}),
                    json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "Differing validator versions only warn.", "subject": "validator version", "stance": "reported", "based_on": [format!("{p}o1")]}),
                ]
            } else {
                vec![]
            };
            if refuse_first && key == "doc:r1#0" {
                let p = t["local_id_prefix"].as_str().unwrap();
                let wrong =
                    [json!({"kind": "observe", "local_id": format!("{p}o9"), "doc_id": "r1", "exact_quote": "not in this section at all", "terms": ["x"]})];
                assert_eq!(d.submit(s, &id, "w1", &wrong, 0)["status"], "REPAIR_REQUIRED");
            }
            let r = d.submit(s, &id, "w1", &lines, 0);
            assert_eq!(r["status"], "COMMITTED", "{r}");
            while let Some(c) = b.next_card(s) {
                b.submit(s, &c.card_id, &[]);
            }
        }
        s.records_since(0).into_iter().find(|r| r.kind == RecordKind::Claim).expect("the first section was read").id
    }

    fn reread(basis: &RecordId, focus: &str, local: &str) -> (usize, Value) {
        (
            0,
            json!({"op": "request", "type": "reread_gap", "local_id": local, "doc_id": "r1", "section": 0, "focus": [focus],
                   "reason": "section_saturated", "based_on": [basis.short()]}),
        )
    }

    #[test]
    fn requests_are_off_unless_the_run_turns_them_on() {
        let (mut s, mut d, mut b) = setup(0);
        let c = read_all(&mut d, &mut s, &mut b);
        let out = d.builder_requests(&mut s, "C1-1-0", &[reread(&c, "validator versions", "q1")]);
        assert_eq!(out[0]["status"], "refused", "{out:?}");
        assert_eq!(out[0]["error"]["code"], "UNKNOWN_OP");
    }

    #[test]
    fn a_reread_request_becomes_a_kernel_task_and_its_records_ground_no_further_request() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all(&mut d, &mut s, &mut b);
        // the second section of r1 (sections of 80 bytes), about a term of its own bytes
        let ask = (
            0,
            json!({"op": "request", "type": "reread_gap", "local_id": "q1", "doc_id": "r1", "section": 1, "focus": ["candidate only"],
                             "reason": "section_saturated", "based_on": [c.short()]}),
        );
        let out = d.builder_requests(&mut s, "C9-9-0", std::slice::from_ref(&ask));
        assert_eq!(out[0]["status"], "accepted", "{out:?}");
        assert!(s.checkpoint("request:1").is_some(), "durable");
        // an exact resend is the same acceptance, nothing new
        let again = d.builder_requests(&mut s, "C9-9-0", &[ask]);
        assert_eq!((again[0]["status"].as_str(), again[0]["replayed"].as_bool()), (Some("accepted"), Some(true)));
        let t = d.acquire(&s, "w2", b.caught_up(&s), 0);
        assert_eq!((t["kind"].as_str(), t["key"].as_str()), (Some("REQUEST"), Some("request:1")), "{t}");
        let task = t["task_id"].as_str().unwrap().to_string();
        assert!(task.starts_with("TR"), "{task}");
        let prompt = t["prompt"].as_str().unwrap();
        assert!(
            prompt.contains("TASK REREAD") && prompt.contains("in particular about: candidate only") && prompt.contains("remains a candidate only."),
            "{prompt}"
        );
        let p = t["local_id_prefix"].as_str().unwrap();
        let lines =
            [json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "r1", "exact_quote": "remains a candidate only.", "terms": ["candidate"]})];
        assert_eq!(d.submit(&mut s, &task, "w2", &lines, 0)["status"], "COMMITTED");
        let new = s.records_since(0).into_iter().find(|r| r.directive == task).expect("a record of the request");
        let chained = d.builder_requests(
            &mut s,
            "C10-10-0",
            &[(
                0,
                json!({"op": "request", "type": "reread_gap", "local_id": "q1", "doc_id": "r1",
            "section": 1, "focus": ["candidate"], "reason": "section_saturated", "based_on": [new.id.short()]}),
            )],
        );
        assert_eq!(chained[0]["status"], "refused", "{chained:?}");
        assert!(chained[0]["error"]["message"].as_str().unwrap().contains("written under a request"), "{chained:?}");
    }

    #[test]
    fn a_request_outside_its_closed_form_is_refused_and_the_limits_hold() {
        let (mut s, mut d, mut b) = setup(2);
        let c = read_all(&mut d, &mut s, &mut b);
        let base = reread(&c, "validator versions", "q1").1;
        let mut cases = Vec::new();
        for (k, v) in [
            ("type", json!("split_concept")),
            ("reason", json!("curious")),
            ("focus", json!(["not in the section"])),
            ("section", json!(99)),
            ("hint", json!("read harder")),
        ] {
            let mut x = base.clone();
            x[k] = v;
            cases.push((0, x));
        }
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("based_on");
        cases.push((0, missing));
        for (i, out) in d.builder_requests(&mut s, "C9-9-0", &cases).iter().enumerate() {
            assert_eq!(out["status"], "refused", "case {i}: {out}");
        }
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[reread(&c, "validator versions", "q1")])[0]["status"], "accepted");
        // the same work under another local id, then the card's and the run's bounds
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[reread(&c, "Validator  versions", "q2")])[0]["status"], "refused");
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[reread(&c, "warning only", "q3")])[0]["status"], "accepted");
        let third = d.builder_requests(&mut s, "C9-9-0", &[reread(&c, "Differing", "q4")]);
        assert!(third[0]["error"]["message"].as_str().unwrap().contains("per card"), "{third:?}");
        let over = d.builder_requests(&mut s, "C11-11-0", &[reread(&c, "Differing", "q1")]);
        assert!(over[0]["error"]["message"].as_str().unwrap().contains("used up"), "{over:?}");
    }

    #[test]
    fn a_coverage_request_needs_a_report_without_claims_for_the_question() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all(&mut d, &mut s, &mut b);
        let ask = |doc: &str| {
            (
                0,
                json!({"op": "request", "type": "check_coverage", "local_id": "q1", "doc_id": doc, "rq_id": "RQ1",
                                          "reason": "report_no_claims_for_rq", "based_on": [c.short()]}),
            )
        };
        let held = d.builder_requests(&mut s, "C9-9-0", &[ask("r1")]);
        assert!(held[0]["error"]["message"].as_str().unwrap().contains("already has 1 claims"), "{held:?}");
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[ask("r2")])[0]["status"], "accepted");
        let t = d.acquire(&s, "w2", b.caught_up(&s), 0);
        let prompt = t["prompt"].as_str().unwrap();
        assert!(prompt.contains("TASK CHECK_COVERAGE") && prompt.contains("is now blocking"), "{prompt}");
    }

    #[test]
    fn a_link_check_waits_for_the_basis_request_and_then_sees_what_it_found() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all(&mut d, &mut s, &mut b);
        // a second claim by another agent in r2, and a builder's proposed link between the two
        let scope = Scope { docs: vec!["r2".into()], ..Default::default() };
        let r2 = s.submit_records("w3", "T99-x", &scope, &[
            json!({"kind": "observe", "local_id": "o", "doc_id": "r2", "exact_quote": "A validator version difference is now blocking.", "terms": ["validator version"]}),
            json!({"kind": "claim", "local_id": "c", "text": "A validator version difference now blocks.", "subject": "validator version", "stance": "reported", "based_on": ["o"]}),
        ]);
        let other = r2.accepted[1];
        let l = s.add_link("builder", &other, "supersedes", &c, &[other]).unwrap();
        let ask = (
            0,
            json!({"op": "request", "type": "find_link_basis", "local_id": "q1", "records": [c.short(), other.short()],
                             "link": l.id.short(), "reason": "link_without_bridge", "based_on": [c.short(), other.short()]}),
        );
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[ask])[0]["status"], "accepted");
        let t = d.acquire(&s, "w2", true, 0);
        assert_eq!(t["key"], "request:1", "the check waits: {t}");
        let task = t["task_id"].as_str().unwrap().to_string();
        let p = t["local_id_prefix"].as_str().unwrap();
        let found = [
            json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "r2", "exact_quote": "A validator version difference is now blocking.", "terms": ["blocking"]}),
        ];
        assert_eq!(d.submit(&mut s, &task, "w2", &found, 0)["status"], "COMMITTED");
        let new = s.records_since(0).into_iter().find(|r| r.directive == task).expect("the request's record");
        let v = d.acquire(&s, "w2", true, 0);
        assert_eq!(v["kind"], "VERIFY_LINK", "{v}");
        assert!(v["prompt"].as_str().unwrap().contains(&new.id.short()), "the check shows the request's quote: {v}");
    }

    #[test]
    fn a_basis_request_given_up_after_failed_leases_no_longer_holds_the_link_check() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all(&mut d, &mut s, &mut b);
        let scope = Scope { docs: vec!["r2".into()], ..Default::default() };
        let r2 = s.submit_records("w3", "T99-x", &scope, &[
            json!({"kind": "observe", "local_id": "o", "doc_id": "r2", "exact_quote": "A validator version difference is now blocking.", "terms": ["validator version"]}),
            json!({"kind": "claim", "local_id": "c", "text": "A validator version difference now blocks.", "subject": "validator version", "stance": "reported", "based_on": ["o"]}),
        ]);
        let other = r2.accepted[1];
        let l = s.add_link("builder", &other, "supersedes", &c, &[other]).unwrap();
        let ask = (
            0,
            json!({"op": "request", "type": "find_link_basis", "local_id": "q1", "records": [c.short(), other.short()],
                             "link": l.id.short(), "reason": "link_without_bridge", "based_on": [c.short(), other.short()]}),
        );
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[ask])[0]["status"], "accepted");
        // three refused answers, each lease given back: the request is given up and the link's check is issued after all
        for _ in 0..MAX_FAILED_LEASES {
            let t = d.acquire(&s, "w2", true, 0);
            assert_eq!(t["key"], "request:1", "{t}");
            let task = t["task_id"].as_str().unwrap().to_string();
            let bad = [json!({"kind": "verdict", "link": l.id.short(), "verdict": "confirm", "based_on": [c.short()]})];
            assert_eq!(d.submit(&mut s, &task, "w2", &bad, 0)["status"], "REPAIR_REQUIRED");
            d.release(&task, "w2");
        }
        assert!(d.unresolved.contains("request:1"));
        let v = d.acquire(&s, "w2", true, 0);
        assert_eq!((v["kind"].as_str(), v["key"].as_str()), (Some("VERIFY_LINK"), Some(format!("verify:{}", l.id.short()).as_str())), "{v}");
    }

    fn empty_card(id: &str) -> super::super::super::builder::Card {
        super::super::super::builder::Card {
            card_id: id.into(),
            cursor_from: 0,
            cursor_to: 0,
            records: vec![],
            candidates: BTreeMap::new(),
            neighbors: vec![],
            concept_types: vec![],
            max_ops: 64,
            max_links: 8,
            pair: None,
            ontology: None,
            review: None,
            functions: None,
        }
    }

    #[test]
    fn a_section_read_with_losses_is_on_the_board_and_may_be_reread_without_focus() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all_with(&mut d, &mut s, &mut b, true);
        let board = d.request_board(&s, &empty_card("C9-9-0")).expect("requests are on");
        assert_eq!(
            board["losses"],
            json!([{"doc_id": "r1", "section": 0, "stored": 2, "offered": 2, "refused_answers": 1, "abandoned": false, "loss_score": 5}]),
            "{board}"
        );
        let ask = |doc: &str| {
            (
                0,
                json!({"op": "request", "type": "reread_gap", "local_id": "q1", "doc_id": doc, "section": 0, "focus": [],
                                          "reason": "section_refused", "based_on": [c.short()]}),
            )
        };
        let other = d.builder_requests(&mut s, "C9-9-0", &[ask("r2")]);
        assert!(other[0]["error"]["message"].as_str().unwrap().contains("requests.losses"), "{other:?}");
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[ask("r1")])[0]["status"], "accepted");
        assert_eq!(d.request_board(&s, &empty_card("C10-10-0")).unwrap()["losses"], json!([]), "a requested loss leaves the board");
        let t = d.acquire(&s, "w2", true, 0);
        assert_eq!(t["key"], "request:1", "{t}");
        assert!(!t["prompt"].as_str().unwrap().contains("in particular about"), "{t}");
        // after a restart the loss comes back from the reading's checkpoint
        let mut d2 = Dispatcher::new(DispatchConfig { section_bytes: 80, max_requests: 20, ..Default::default() }, d.questions.clone());
        d2.recover(&s);
        assert_eq!(d2.strained, d.strained);
    }

    #[test]
    fn backpressure_holds_first_readings_only_and_never_the_first_reader_of_an_idle_builder() {
        let (s, mut d, _) = setup(0);
        d.cfg.backpressure_records = 30;
        d.cfg.backpressure_per_task = 20;
        // an idle builder: the first reading is issued, the second would exceed the bound with one in flight
        let first = d.acquire_paced(&s, "w1", true, Some(0), 0);
        assert_eq!(first["kind"], "EXTEND", "{first}");
        let held = d.acquire_paced(&s, "w2", true, Some(0), 0);
        assert_eq!(held["status"], "WAIT", "{held}");
        assert_eq!(d.stats.paced_skips, 1);
        // a backlog alone holds a reading; off (None) holds nothing
        let mut d2 = Dispatcher::new(DispatchConfig { section_bytes: 80, backpressure_records: 30, ..Default::default() }, vec![]);
        assert_eq!(d2.acquire_paced(&s, "w1", false, Some(40), 0)["status"], "WAIT");
        assert_eq!(d2.acquire_paced(&s, "w1", false, None, 0)["kind"], "EXTEND");
    }

    #[test]
    fn a_control_reading_takes_another_read_section_without_focus_and_requests_survive_a_restart() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all(&mut d, &mut s, &mut b);
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[reread(&c, "validator versions", "q1")])[0]["status"], "accepted");
        let control = d.requests[0].control.clone().expect("a read section is free");
        assert_ne!(control, ("r1".to_string(), 0), "never the requested section");
        let keys: Vec<String> = (0..2).map(|_| d.acquire(&s, "w2", true, 0)).map(|t| t["key"].as_str().unwrap_or("").to_string()).collect();
        assert_eq!(keys, ["request:1", "control:1"]);
        let mut d2 = Dispatcher::new(DispatchConfig { section_bytes: 80, max_requests: 20, ..Default::default() }, d.questions.clone());
        d2.recover(&s);
        assert_eq!(d2.requests, d.requests);
        let t = d2.acquire(&s, "w4", true, 0);
        assert!(t["task_id"].as_str().unwrap().starts_with('T') && ["request:1", "control:1"].contains(&t["key"].as_str().unwrap()), "{t}");
        let p = t["prompt"].as_str().unwrap();
        if t["key"] == "control:1" {
            assert!(t["task_id"].as_str().unwrap().starts_with("TC") && !p.contains("in particular about"), "{t}");
        }
    }

    // Codex's regression tests of the consilium of 10A-17 (CODEX_CONSILIUM_10A15_17_20261024_EVIDENCE.json, offline_probe_source),
    // added verbatim: C17-01, C17-02, C17-03.

    #[test]
    fn codex_consilium_abandoned_sections_are_recoverable_losses() {
        let mut s = MemStore::new(&[("r1", "Alpha is ready.\n")], &["Rule"]);
        let mut d = Dispatcher::new(DispatchConfig { section_bytes: 80, max_requests: 20, ..Default::default() }, vec![]);
        let mut basis = None;
        for _ in 0..MAX_FAILED_LEASES {
            let t = d.acquire(&s, "w1", false, 0);
            assert_eq!(t["kind"], "EXTEND");
            let id = t["task_id"].as_str().unwrap();
            let p = t["local_id_prefix"].as_str().unwrap();
            let lines = [
                json!({"kind":"observe","local_id":format!("{p}o1"),"doc_id":"r1","exact_quote":"Alpha is ready.","terms":["Alpha"]}),
                json!({"kind":"observe","local_id":format!("{p}o2"),"doc_id":"r1","exact_quote":"This is absent.","terms":["absent"]}),
            ];
            assert_eq!(d.submit(&mut s, id, "w1", &lines, 0)["status"], "REPAIR_REQUIRED");
            basis = Some(s.records_since(0).into_iter().find(|r| r.directive == id).unwrap().id);
            d.release_durable(&mut s, id, "w1");
        }
        assert!(d.unresolved.contains("doc:r1#0"));
        let board = d.request_board(&s, &empty_card("C9-9-0")).unwrap();
        let ask = json!({"op":"request","type":"reread_gap","local_id":"q1","doc_id":"r1","section":0,"focus":[],
                        "reason":"section_refused","based_on":[basis.unwrap().short()]});
        let out = d.builder_requests(&mut s, "C9-9-0", &[(0, ask)]);
        println!("CODEX_LOSS board={} request={}", board["losses"], json!(out));
        assert!(!board["losses"].as_array().unwrap().is_empty(), "abandoned first reading has stored data and refused tails, but is absent from losses");
        assert_eq!(out[0]["status"], "accepted");
    }

    #[test]
    fn codex_consilium_exact_request_retry_keeps_its_acceptance_after_work() {
        let (mut s, mut d, mut b) = setup(20);
        let c = read_all(&mut d, &mut s, &mut b);
        let ask = json!({"op":"request","type":"check_coverage","local_id":"q1","doc_id":"r2","rq_id":"RQ1",
                         "reason":"report_no_claims_for_rq","based_on":[c.short()]});
        assert_eq!(d.builder_requests(&mut s, "C9-9-0", &[(0, ask.clone())])[0]["status"], "accepted");
        let t = d.acquire(&s, "w2", true, 0);
        assert_eq!(t["key"], "request:1");
        let id = t["task_id"].as_str().unwrap();
        let p = t["local_id_prefix"].as_str().unwrap();
        let lines = [
            json!({"kind":"observe","local_id":format!("{p}o1"),"doc_id":"r2","exact_quote":"A validator version difference is now blocking.","terms":["validator version"]}),
            json!({"kind":"claim","local_id":format!("{p}c1"),"text":"A validator version difference now blocks.","subject":"validator version","stance":"reported","based_on":[format!("{p}o1")]}),
        ];
        assert_eq!(d.submit(&mut s, id, "w2", &lines, 0)["status"], "COMMITTED");
        let again = d.builder_requests(&mut s, "C9-9-0", &[(0, ask)]);
        println!("CODEX_RETRY {}", json!(again));
        assert_eq!(again[0]["status"], "accepted", "an exact accepted request must retain its ACK after its work changes coverage");
        assert_eq!(again[0]["replayed"], true);
    }

    #[test]
    fn codex_consilium_no_fail_fast_is_not_a_negated_test_result() {
        let doc =
            "cargo test --workspace --no-fail-fast:\n  1199 passed, 1 failed\nknown failure:\n  status_doc_keeps_operational_path_separate_from_planning_path";
        let q = "known failure:\n  status_doc_keeps_operational_path_separate_from_planning_path";
        let got = super::super::super::s0::negation_before(doc, doc.find(q).unwrap(), q);
        println!("CODEX_NEGATION {got:?}");
        assert_eq!(got, None, "the --no-fail-fast option does not negate the known failure on a later log line");
    }
}
