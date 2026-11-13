//! The gap pass of 0.2 (SPEC_V02_GAP_PASS): after the first readings, the structural units of the read sections that no accepted
//! quote touches are handed out as narrow tasks ("write what this unit states, with an exact quote, or answer that there is nothing
//! to record"). This file holds the pure parts: the units of a document and the gaps among them. Which unit means what (a changelog,
//! a MUST) is the profile's data, never this code's.

/// A Markdown fence line: at least three backticks or three tildes after up to three spaces, as `(char, length, rest)`.
fn fence(line: &str) -> Option<(char, usize, &str)> {
    let t = line.trim_start_matches(' ');
    let c = t.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let n = t.chars().take_while(|x| *x == c).count();
    (line.len() - t.len() <= 3 && n >= 3).then(|| (c, n, &t[n..]))
}

/// The lines of a text, each with its first byte and whether it is code: a fence line, or a line inside a fenced block. Only a
/// fence of the same character, as long or longer and with nothing after it, closes a block (Codex review of 6d2c270, GAP-04).
/// The one rule of fences for the units, the sections of the first reading and the context shown with a piece (Codex review of
/// 320a04e, HDR-01: a `#` line inside a block was taken for a heading).
pub(crate) fn code_lines(text: &str) -> Vec<(usize, &str, bool)> {
    let mut out = Vec::new();
    let mut in_fence: Option<(char, usize)> = None;
    let mut at = 0;
    for raw in text.split_inclusive('\n') {
        let (start, line) = (at, raw.trim_end_matches(['\n', '\r']));
        at += raw.len();
        let code = match (in_fence, fence(line)) {
            (None, Some((c, n, _))) => {
                in_fence = Some((c, n));
                true
            }
            (Some((c, n)), Some((d, m, rest))) if d == c && m >= n && rest.trim().is_empty() => {
                in_fence = None;
                true
            }
            (Some(_), _) => true,
            (None, None) => false,
        };
        out.push((start, line, code));
    }
    out
}

/// A list item's first line: `-`, `*` or `+`, or a number with `.` or `)`, then a space, after any indentation.
fn item(line: &str) -> bool {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix(['-', '*', '+']) {
        return rest.starts_with(' ') || rest.starts_with('\t');
    }
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    (1..=9).contains(&digits) && {
        let rest = &t[digits..];
        rest.starts_with(". ") || rest.starts_with(") ") || rest.starts_with(".\t") || rest.starts_with(")\t")
    }
}

/// The structural units of a document, as ordered, disjoint, half-open byte ranges that never end inside a character
/// (SPEC_V02_GAP_PASS section 2):
/// - in a Markdown document (`super::has_headings`): a list item with its continuation lines, a paragraph, a table row. A heading is
///   not a unit (it is context), a fenced code block is skipped whole, and so is a line of markup (`<...>`) or a table rule
///   (`|---`). The unit of an item with a nested list ends before the first nested item, so a quote of a sub-item does not hide
///   the rest;
/// - in any other text: a paragraph, up to a blank line.
///
/// A range covers the unit's lines without the line break after its last line.
pub(crate) fn units(doc: &str, text: &str) -> Vec<(usize, usize)> {
    let markdown = super::has_headings(doc);
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut open: Option<(usize, usize)> = None;
    for (start, line, code) in code_lines(text) {
        let end = start + line.len();
        let blank = line.trim().is_empty();
        let close = |open: &mut Option<(usize, usize)>, out: &mut Vec<(usize, usize)>| {
            if let Some(u) = open.take() {
                out.push(u);
            }
        };
        if markdown {
            // a fenced block is skipped whole: its first line ends the unit before it
            if code {
                close(&mut open, &mut out);
                continue;
            }
            let t = line.trim_start();
            if blank || t.starts_with('#') || t.starts_with('<') || t.starts_with("|-") || t.starts_with("| -") || t.starts_with("|:") {
                close(&mut open, &mut out);
                continue;
            }
            if t.starts_with('|') {
                // a table row is a unit of its own
                close(&mut open, &mut out);
                out.push((start, end));
                continue;
            }
            if item(line) {
                close(&mut open, &mut out);
                open = Some((start, end));
                continue;
            }
        } else if blank {
            close(&mut open, &mut out);
            continue;
        }
        match open.as_mut() {
            Some(u) => u.1 = end,
            None => open = Some((start, end)),
        }
    }
    if let Some(u) = open {
        out.push(u);
    }
    out
}

/// A table row: in Markdown a line that begins with `|`, in other text a line of at least three cells split by ` | `.
fn table_row(markdown: bool, line: &str) -> bool {
    let t = line.trim();
    if markdown {
        t.starts_with('|')
    } else {
        t.matches(" | ").count() >= 2
    }
}

/// Read-only context for a piece of a document that begins at byte `start` (a section of a first reading, a gap pack): the
/// nearest heading above it in a Markdown document, and the header row of the table it begins inside (with the rule under it in
/// Markdown). A reader of a piece cut from the middle sees what the rows and lines are about; the scope stays the piece, so the
/// context cannot be quoted (SPEC_V02 roadmap: section and table header at the first reading).
pub(crate) fn reading_context(doc: &str, text: &str, start: usize) -> Vec<String> {
    let markdown = super::has_headings(doc);
    let start = start.min(text.len());
    let mut out = Vec::new();
    // a piece may begin inside a line (a section cut where a table has no blank line): the whole line it begins in counts
    let start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    // in Markdown a line of code is neither a heading nor a table row (Codex review of 320a04e, HDR-01)
    let lines: Vec<(usize, &str, bool)> = code_lines(text).into_iter().map(|(at, l, code)| (at, l, markdown && code)).collect();
    let (before, after) = lines.split_at(lines.partition_point(|(at, _, _)| *at < start));
    let first = after.iter().find(|(_, l, _)| !l.trim().is_empty()).map_or(("", false), |(_, l, code)| (*l, *code));
    let heading = |l: &str, code: bool| !code && l.trim_start().starts_with('#');
    if markdown && !heading(first.0, first.1) {
        if let Some((_, h, _)) = before.iter().rev().find(|(_, l, code)| heading(l, *code)) {
            out.push(format!("section heading: {}", h.trim()));
        }
    }
    if !first.1 && table_row(markdown, first.0) {
        // walk back over the rows of the same table (blank lines between rows in plain text, the rule in Markdown) to its first
        // row; a line of code ends the table
        let mut header = None;
        for (_, line, code) in before.iter().rev() {
            let t = line.trim();
            if !code && table_row(markdown, line) {
                header = Some(t);
            } else if *code || !(t.is_empty() && !markdown) {
                break;
            }
        }
        if let Some(h) = header {
            out.push(format!("table header: {h}"));
        }
    }
    out
}

fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// The gaps of one document (SPEC_V02_GAP_PASS section 3): the units that lie wholly in sections whose first reading is over
/// (`done(k)` for every section `k` the unit touches), that no accepted quote overlaps (`quoted`: the bytes the kernel bound the
/// quotes to) and that no withdrawn text overlaps (`closed`). Derived from the state alone, never stored.
pub(crate) fn gaps(
    units: &[(usize, usize)],
    sections: &[(usize, usize)],
    done: impl Fn(usize) -> bool,
    quoted: &[(usize, usize)],
    closed: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    units
        .iter()
        .copied()
        .filter(|u| {
            let touched: Vec<usize> = sections.iter().enumerate().filter(|(_, s)| overlaps(*u, **s)).map(|(k, _)| k).collect();
            !touched.is_empty() && touched.iter().all(|k| done(*k))
        })
        .filter(|u| !quoted.iter().any(|q| overlaps(*u, *q)))
        .filter(|u| !closed.iter().any(|c| overlaps(*u, *c)))
        .collect()
}

use super::*;

/// The gap pass of a run (SPEC_V02_GAP_PASS sections 4 and 6), data of the profile: off with `limit` 0.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GapProfile {
    /// At most this many primary packs (`gap:`) in a run; the second reader's (`gap2:`) are not counted.
    pub limit: usize,
    /// Units per pack, 4..8.
    pub units_per_task: usize,
    /// A unit takes the first tier whose rule it matches, else the last; without tiers all are one.
    pub tiers: Vec<GapTier>,
    /// The tiers whose empty packs a second reader checks.
    pub second_reader_tiers: Vec<usize>,
}

/// A tier's rule: the document's path contains one of `path_contains`, or the unit contains one of `words` (as written).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GapTier {
    pub path_contains: Vec<String>,
    pub words: Vec<String>,
}

fn bad_field(field: &str, message: &str) -> KernelError {
    KernelError::new(Code::BadField, message.to_string()).field(field)
}

impl GapProfile {
    /// The profile file `{"gap_pass": {"limit", "units_per_task", "tiers": [{"path_contains": [], "words": []}],
    /// "second_reader_tiers": []}}`, or its inner object.
    pub fn from_json(v: &Value) -> Result<GapProfile, KernelError> {
        let v = if v.get("gap_pass").is_some() { &v["gap_pass"] } else { v };
        let strings = |x: &Value, key: &str| -> Result<Vec<String>, KernelError> {
            match &x[key] {
                Value::Null => Ok(Vec::new()),
                Value::Array(a) => a.iter().map(|s| s.as_str().map(str::to_string).ok_or_else(|| bad_field(key, "expected strings"))).collect(),
                _ => Err(bad_field(key, "expected an array of strings")),
            }
        };
        let tiers = match &v["tiers"] {
            Value::Null => Vec::new(),
            Value::Array(a) => a
                .iter()
                .map(|t| Ok(GapTier { path_contains: strings(t, "path_contains")?, words: strings(t, "words")? }))
                .collect::<Result<_, KernelError>>()?,
            _ => return Err(bad_field("tiers", "expected an array")),
        };
        let units_per_task = v["units_per_task"].as_u64().unwrap_or(8) as usize;
        if !(4..=8).contains(&units_per_task) {
            return Err(bad_field("units_per_task", "a pack holds 4 to 8 units"));
        }
        let second_reader_tiers =
            v["second_reader_tiers"].as_array().map_or_else(Vec::new, |a| a.iter().filter_map(Value::as_u64).map(|t| t as usize).collect());
        Ok(GapProfile { limit: v["limit"].as_u64().unwrap_or(0) as usize, units_per_task, tiers, second_reader_tiers })
    }

    /// The tier of a unit of document `path` with text `unit`: the first rule it matches, else the last tier (rules plus one).
    pub fn tier(&self, path: &str, unit: &str) -> usize {
        self.tiers
            .iter()
            .position(|t| t.path_contains.iter().any(|p| path.contains(p.as_str())) || t.words.iter().any(|w| unit.contains(w.as_str())))
            .unwrap_or(self.tiers.len())
    }

    /// The last tier: the one of the units no rule matches.
    fn last_tier(&self) -> usize {
        self.tiers.len()
    }

    /// The settings the genesis pins (SPEC_V02_GAP_PASS section 10).
    pub fn settings(&self) -> Value {
        json!({"limit": self.limit, "units_per_task": self.units_per_task, "second_reader_tiers": self.second_reader_tiers,
               "tiers": self.tiers.iter().map(|t| json!({"path_contains": t.path_contains, "words": t.words})).collect::<Vec<_>>()})
    }
}

/// A pack's key: `gap:{doc}@{lo}-{hi}` (or `gap2:`), the bytes from its first unit's start to its last unit's end.
pub(super) fn pack_key(second: bool, doc: &str, lo: usize, hi: usize) -> String {
    format!("{}:{doc}@{lo}-{hi}", if second { "gap2" } else { "gap" })
}

/// `(second, doc, lo, hi)` of a pack key.
pub(super) fn parse_pack(key: &str) -> Option<(bool, &str, usize, usize)> {
    let (second, rest) = key.strip_prefix("gap2:").map(|r| (true, r)).or_else(|| key.strip_prefix("gap:").map(|r| (false, r)))?;
    let (doc, range) = rest.rsplit_once('@')?;
    let (lo, hi) = range.split_once('-')?;
    Some((second, doc, lo.parse().ok()?, hi.parse().ok()?))
}

impl Dispatcher {
    fn gap_keys_used(&self) -> BTreeSet<String> {
        self.handled.iter().chain(&self.unresolved).cloned().chain(self.leases.values().map(|l| l.key.clone())).filter(|k| k.starts_with("gap")).collect()
    }

    /// Every first reading is over and no loss reread is open: the gap pass may begin (SPEC_V02_GAP_PASS section 7).
    fn gap_pass_may_begin<S: AuditStore>(&self, s: &S) -> bool {
        let first_readings_done = s.docs().iter().all(|doc| {
            (0..sections(doc, &s.doc_text(doc).unwrap_or_default(), self.cfg.section_bytes).len())
                .all(|k| self.handled.contains(&format!("doc:{doc}#{k}")) || self.unresolved.contains(&format!("doc:{doc}#{k}")))
        });
        first_readings_done
            && !self.auto_reread_work(s).iter().any(|w| !self.handled.contains(&w.1) && !self.unresolved.contains(&w.1))
            && !self.leases.values().any(|l| l.key.starts_with("reread:") || l.kind == TaskKind::Extend)
    }

    /// The gap units of a document now: of finished sections, under no standing quote and no withdrawn text.
    fn gap_units<S: AuditStore>(&self, s: &S, doc: &str) -> Vec<(usize, usize)> {
        let text = s.doc_text(doc).unwrap_or_default();
        let secs = sections(doc, &text, self.cfg.section_bytes);
        let done = |k: usize| self.handled.contains(&format!("doc:{doc}#{k}")) || self.unresolved.contains(&format!("doc:{doc}#{k}"));
        gaps(&units(doc, &text), &secs, done, &s.quoted_spans(doc), &s.closed_spans(doc))
    }

    /// The gap units of the pack's tier inside its bytes now: the targets of its task, primary or second reader. A pack's bytes
    /// may span units of another tier; those are another pack's.
    pub(super) fn pack_targets<S: AuditStore>(&self, s: &S, doc: &str, lo: usize, hi: usize) -> Vec<(usize, usize)> {
        let text = s.doc_text(doc).unwrap_or_default();
        let (label, tier) = (s.document_label(doc), self.pack_tier(s, doc, lo));
        self.gap_units(s, doc).into_iter().filter(|(a, b)| lo <= *a && *b <= hi && self.cfg.gap.tier(&label, &text[*a..*b]) == tier).collect()
    }

    /// The tier of the pack that begins at byte `lo` of `doc`: its first unit's.
    fn pack_tier<S: AuditStore>(&self, s: &S, doc: &str, lo: usize) -> usize {
        let text = s.doc_text(doc).unwrap_or_default();
        let end = units(doc, &text).into_iter().find(|u| u.0 == lo).map_or(lo, |u| u.1);
        self.cfg.gap.tier(&s.document_label(doc), &text[lo.min(text.len())..end.min(text.len())])
    }

    /// The completion of a gap task the journal took (an answer was stored): its order and whether it recorded anything. A key
    /// given up after its attempts ran out has none.
    fn gap_completion<S: AuditStore>(&self, s: &S, key: &str) -> Option<(u64, bool)> {
        if !self.handled.contains(key) {
            return None;
        }
        let c = s.checkpoint(&task_checkpoint(key))?;
        Some((c["context"]["gap"]["order"].as_u64().unwrap_or(0), c["context"]["gap"]["recorded"].as_u64().unwrap_or(0) > 0))
    }

    /// Per tier, the events of the tier rule in the order the journal took them (Codex review of 6d2c270, GAP-01 and GAP-02): a
    /// pack that recorded counts as recorded at the answer that recorded (its first reader's, else its second reader's); an empty
    /// pack counts once it is closed for good, at the answer that closed it (in a tier with a second reader, the second's). A pack
    /// or second reader whose attempts ran out answered nothing and is no event.
    fn gap_tier_runs<S: AuditStore>(&self, s: &S) -> BTreeMap<usize, Vec<bool>> {
        let mut events: Vec<(u64, usize, bool)> = Vec::new();
        for key in self.handled.iter().filter(|k| k.starts_with("gap:")) {
            let Some((_, doc, lo, hi)) = parse_pack(key) else { continue };
            let Some((first, recorded)) = self.gap_completion(s, key) else { continue };
            let tier = self.pack_tier(s, doc, lo);
            if recorded {
                events.push((first, tier, true));
            } else if !self.cfg.gap.second_reader_tiers.contains(&tier) {
                events.push((first, tier, false));
            } else if let Some((second, recorded)) = self.gap_completion(s, &pack_key(true, doc, lo, hi)) {
                events.push((second, tier, recorded));
            } else if !self.unresolved.contains(&pack_key(true, doc, lo, hi)) && self.pack_targets(s, doc, lo, hi).is_empty() {
                // nothing left for a second reader: the pack closed with its first answer
                events.push((first, tier, false));
            }
        }
        events.sort_unstable();
        let mut runs: BTreeMap<usize, Vec<bool>> = BTreeMap::new();
        for (_, tier, recorded) in events {
            runs.entry(tier).or_default().push(recorded);
        }
        runs
    }

    /// The gap pass's open work (SPEC_V02_GAP_PASS sections 4 to 7): the second readers' packs, then the primary packs of the
    /// tiers that are not closed, in tier, document and byte order, within the budget. A pure function of the state and the profile.
    pub(super) fn gap_work<S: AuditStore>(&self, s: &S) -> Vec<Work> {
        let g = &self.cfg.gap;
        if g.limit == 0 || !self.gap_pass_may_begin(s) {
            return Vec::new();
        }
        let used = self.gap_keys_used();
        let mut out: Vec<Work> = Vec::new();
        // a second reader follows a stored first answer, whose author is known; a pack whose attempts ran out stays a gap on the
        // record and gets none (Codex recheck of 789b440d, GAP-03)
        for key in self.handled.iter().filter(|k| k.starts_with("gap:")) {
            let Some((_, doc, lo, hi)) = parse_pack(key) else { continue };
            let second = pack_key(true, doc, lo, hi);
            if !used.contains(&second) && g.second_reader_tiers.contains(&self.pack_tier(s, doc, lo)) && !self.pack_targets(s, doc, lo, hi).is_empty() {
                out.push((TaskKind::Request, second, None, None, Some((doc.to_string(), lo, hi))));
            }
        }
        let mut budget = g.limit.saturating_sub(used.iter().filter(|k| k.starts_with("gap:")).count());
        // a tier closes after three empty packs in a row; once the last tier closes, the pass stops
        let closed: BTreeSet<usize> =
            self.gap_tier_runs(s).into_iter().filter(|(_, run)| run.len() >= 3 && run[run.len() - 3..].iter().all(|r| !r)).map(|(t, _)| t).collect();
        if budget == 0 || closed.contains(&g.last_tier()) {
            return out;
        }
        // a unit is taken once a pack of its tier spans it
        let taken: Vec<(String, usize, usize, usize)> =
            used.iter().filter_map(|k| parse_pack(k)).map(|(_, d, lo, hi)| (d.to_string(), lo, hi, self.pack_tier(s, d, lo))).collect();
        let mut queue: Vec<(usize, String, usize, usize)> = Vec::new();
        for doc in s.docs() {
            let text = s.doc_text(&doc).unwrap_or_default();
            let label = s.document_label(&doc);
            for (a, b) in self.gap_units(s, &doc) {
                let tier = g.tier(&label, &text[a..b]);
                if taken.iter().any(|(d, lo, hi, t)| *d == doc && *lo <= a && b <= *hi && *t == tier) {
                    continue;
                }
                if !closed.contains(&tier) {
                    queue.push((tier, doc.clone(), a, b));
                }
            }
        }
        queue.sort();
        let mut i = 0;
        while i < queue.len() && budget > 0 {
            let (tier, doc) = (queue[i].0, queue[i].1.clone());
            let mut j = i;
            while j < queue.len() && j - i < g.units_per_task.max(1) && queue[j].0 == tier && queue[j].1 == doc {
                j += 1;
            }
            let (lo, hi) = (queue[i].2, queue[j - 1].3);
            out.push((TaskKind::Request, pack_key(false, &doc, lo, hi), None, None, Some((doc, lo, hi))));
            budget -= 1;
            i = j;
        }
        out
    }

    /// Whether `agent` may take this gap task: a second reader is never the pack's first reader; with circles it is the ring's
    /// next reader after it, or the one after that when it is excluded (SPEC_V02_GAP_PASS section 6).
    pub(super) fn gap_allows<S: AuditStore>(&self, s: &S, key: &str, agent: &str) -> bool {
        let Some((true, doc, lo, hi)) = parse_pack(key) else { return true };
        let Some(first) = self.gap_first_reader(s, doc, lo, hi) else { return false };
        if agent == first {
            return false;
        }
        let Some(cfg) = self.cfg.circles.as_ref() else { return true };
        // the ring as it stands now (the server's order from quality::ring), as the BUILD cards use it (Codex review of 6d2c270,
        // GAP-05): the reader after the first; when it is excluded, a free reader after it that is neither the first nor busy
        let readers = self.ring_order.as_ref().unwrap_or(&cfg.readers);
        let start = readers.iter().position(|r| *r == first).map_or(0, |i| i + 1);
        let ring = || (0..readers.len()).map(|k| &readers[(start + k) % readers.len()]).filter(|r| **r != first);
        match ring().next() {
            Some(next) if !self.members.excluded.contains(next) => next == agent,
            _ => ring().find(|r| !self.members.excluded.contains(*r) && !self.leases.values().any(|l| l.agent == **r)).is_some_and(|r| r == agent),
        }
    }

    /// The first reader of a pack: the agent whose answer closed its primary task.
    fn gap_first_reader<S: AuditStore>(&self, s: &S, doc: &str, lo: usize, hi: usize) -> Option<String> {
        s.checkpoint(&task_checkpoint(&pack_key(false, doc, lo, hi))).and_then(|c| c["context"]["agent"].as_str().map(str::to_string))
    }

    /// A second reader's task that no reader may ever take: with circles, every reader of the ring but the first is excluded
    /// (Codex review of 6d2c270, GAP-03). It is given up as unresolved, the need of an independent reader kept on the record. Without
    /// circles the server refuses a second reader to a run of fewer than two swarm agents before it starts.
    pub(super) fn gap_without_reader<S: AuditStore>(&self, s: &S, key: &str) -> bool {
        let (Some((true, doc, lo, hi)), Some(cfg)) = (parse_pack(key), self.cfg.circles.as_ref()) else { return false };
        let Some(first) = self.gap_first_reader(s, doc, lo, hi) else { return false };
        self.ring_order.as_ref().unwrap_or(&cfg.readers).iter().all(|r| *r == first || self.members.excluded.contains(r))
    }

    /// What the gap pass did, for the coverage report (SPEC_V02_GAP_PASS section 9): the units of the read sections, those a
    /// standing quote covers, the gaps left, the packs and what they recorded, the second readers and the empty answers they
    /// overturned, and the gaps no pack of their tier spans (the budget or a closed tier left them).
    pub(super) fn gap_report<S: AuditStore>(&self, s: &S) -> Value {
        // the primary packs whose answer was stored, and those whose attempts ran out (Codex review of 6d2c270, GAP-02): only a
        // stored answer is an explicit empty one
        let spans = |keys: &BTreeSet<String>| -> Vec<(String, usize, usize, usize)> {
            keys.iter().filter_map(|k| parse_pack(k)).filter(|p| !p.0).map(|(_, d, lo, hi)| (d.to_string(), lo, hi, self.pack_tier(s, d, lo))).collect()
        };
        let (answered, exhausted) = (spans(&self.handled), spans(&self.unresolved));
        let (mut read, mut quoted, mut gaps_now, mut left) = (0usize, 0usize, 0usize, 0usize);
        // units without a final answer: of a pack whose attempts ran out, or left unquoted by a stored first answer in a tier with a
        // second reader whose reading did not happen (its attempts ran out or no independent reader was left; Codex recheck of
        // 789b440d, GAP-02)
        let (mut pack_failed, mut second_failed) = (0usize, 0usize);
        for doc in s.docs() {
            let text = s.doc_text(&doc).unwrap_or_default();
            let secs = sections(&doc, &text, self.cfg.section_bytes);
            let done = |k: usize| self.handled.contains(&format!("doc:{doc}#{k}")) || self.unresolved.contains(&format!("doc:{doc}#{k}"));
            let read_units = gaps(&units(&doc, &text), &secs, done, &[], &[]);
            let quotes = s.quoted_spans(&doc);
            read += read_units.len();
            quoted += read_units.iter().filter(|u| quotes.iter().any(|q| u.0 < q.1 && q.0 < u.1)).count();
            let label = s.document_label(&doc);
            for (a, b) in self.gap_units(s, &doc) {
                gaps_now += 1;
                let tier = self.cfg.gap.tier(&label, &text[a..b]);
                let spanning =
                    |packs: &[(String, usize, usize, usize)]| packs.iter().find(|(d, lo, hi, t)| *d == doc && *lo <= a && b <= *hi && *t == tier).cloned();
                if let Some((d, lo, hi, _)) = spanning(&answered) {
                    if self.cfg.gap.second_reader_tiers.contains(&tier) && self.unresolved.contains(&pack_key(true, &d, lo, hi)) {
                        second_failed += 1;
                    }
                } else if spanning(&exhausted).is_some() {
                    pack_failed += 1;
                } else {
                    left += 1;
                }
            }
        }
        let recorded = |k: &String| self.gap_completion(s, k).is_some_and(|c| c.1);
        let count = |set: &BTreeSet<String>, prefix: &str| set.iter().filter(|k| k.starts_with(prefix)).count();
        let primary: Vec<&String> = self.handled.iter().filter(|k| k.starts_with("gap:")).collect();
        let second: Vec<&String> = self.handled.iter().filter(|k| k.starts_with("gap2:")).collect();
        let gap_recorded = primary.iter().filter(|k| recorded(k)).count();
        json!({"units_read": read, "units_quoted": quoted, "gap_units": gaps_now, "gap_tasks": primary.len(), "gap_recorded": gap_recorded,
        "gap_empty": primary.len() - gap_recorded, "gap_exhausted": count(&self.unresolved, "gap:"),
        "second_reader_tasks": second.len(), "empty_overturned": second.iter().filter(|k| recorded(k)).count(),
        "second_reader_exhausted": count(&self.unresolved, "gap2:"),
        "gap_left_by_budget": left, "gap_units_unanswered": pack_failed + second_failed,
        "gap_units_pack_failed": pack_failed, "gap_units_second_reading_failed": second_failed,
        "complete": left + pack_failed + second_failed == 0,
        "meaning": if left + pack_failed + second_failed == 0 {
            "every read unit is quoted or answered empty".to_string()
        } else {
            format!(
                "incomplete coverage: every read unit is quoted or answered empty, except {left} the budget left, {pack_failed} whose pack \
                 ran out of attempts and {second_failed} whose second reading did not happen"
            )
        }})
    }

    /// `gap_report` for a check from outside this crate (`examples/coverage_check.rs`): the totals a recovered dispatcher gives
    /// for a recorded run, to hold the coverage table against.
    #[doc(hidden)]
    pub fn gap_pass_report<S: AuditStore>(&self, s: &S) -> Value {
        self.gap_report(s)
    }

    /// The task of a gap pack: its target units, numbered, and read-only context (the section's heading, the parent item of a
    /// nested unit) that is never quoted. The scope is the targets alone, so a quote from the context is refused.
    pub(super) fn gap_prompt<S: AuditStore>(&self, s: &S, key: &str) -> (String, Scope, Vec<RecordId>) {
        let (second, doc, lo, hi) = parse_pack(key).expect("a gap key");
        let text = s.doc_text(doc).unwrap_or_default();
        let targets = self.pack_targets(s, doc, lo, hi);
        let mut context: Vec<String> = reading_context(doc, &text, lo).into_iter().map(|c| format!("  {c}")).collect();
        let all = units(doc, &text);
        let mut body = String::new();
        for (n, (a, b)) in targets.iter().enumerate() {
            let unit = &text[*a..*b];
            let first_line = unit.lines().next().unwrap_or("");
            let indent = first_line.len() - first_line.trim_start().len();
            if indent > 0 && item(first_line) {
                let parent = all
                    .iter()
                    .rev()
                    .filter(|u| u.1 <= *a)
                    .map(|u| text[u.0..u.1].lines().next().unwrap_or(""))
                    .find(|p| p.len() - p.trim_start().len() < indent);
                if let Some(p) = parent {
                    context.push(format!("  parent of unit {}: {}", n + 1, p.trim()));
                }
            }
            body.push_str(&format!("[{}] (bytes {a}..{b})\n<<<\n{unit}\n>>>\n", n + 1));
        }
        let prompt = format!(
            "TASK GAP{}: the reading of report {doc} recorded nothing from the units below. For each unit, record what it states that \
             matters for the research questions, with an exact quote from that unit. If a unit states nothing worth recording, write \
             nothing for it; if none does, answer with no lines. Quote only from the UNITS; the CONTEXT is shown only to understand \
             them and is never quoted.\nRESEARCH QUESTIONS:\n{}\nCONTEXT (do not quote):\n{}\nUNITS doc_id=\"{doc}\":\n{body}",
            if second { " (second reader)" } else { "" },
            self.questions_text(),
            if context.is_empty() { "  (none)".to_string() } else { context.join("\n") },
        );
        let ranges = targets.iter().map(|(a, b)| (doc.to_string(), *a, *b)).collect();
        (prompt, Scope { docs: vec![doc.to_string()], topic: None, ranges }, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts<'a>(text: &'a str, units: &[(usize, usize)]) -> Vec<&'a str> {
        units.iter().map(|(a, b)| &text[*a..*b]).collect()
    }

    #[test]
    fn a_list_item_keeps_its_continuation_lines_and_a_nested_item_is_a_unit_of_its_own() {
        let text =
            "# Changes\n\n1. Remove batching\n   (PR #416)\n2. Add tools:\n   - `title`\n     for display\n   - `icons`\n\nA paragraph\nover two lines.\n";
        let u = units("changelog.mdx", text);
        assert_eq!(
            texts(text, &u),
            ["1. Remove batching\n   (PR #416)", "2. Add tools:", "   - `title`\n     for display", "   - `icons`", "A paragraph\nover two lines."]
        );
        // ordered and disjoint
        assert!(u.windows(2).all(|w| w[0].1 <= w[1].0), "{u:?}");
    }

    #[test]
    fn a_table_row_is_a_unit_and_rules_markup_headings_and_fenced_code_are_not() {
        let text = "## Table\n\n| Trial | Year |\n|---|---|\n| Ni 2010 | 2010 |\n| Lee 2009 | 2009 |\n\n<Note>\n\n```json\n{\"a\": 1}\n- not an item\n```\n\nAfter the code.\n";
        let u = units("page.md", text);
        assert_eq!(texts(text, &u), ["| Trial | Year |", "| Ni 2010 | 2010 |", "| Lee 2009 | 2009 |", "After the code."]);
    }

    #[test]
    fn a_fence_closes_only_on_its_own_character_and_length() {
        // Codex review of 6d2c270, GAP-04: a shorter or other fence inside a block does not end it
        for text in [
            "Before.

````
```
- Fake change.
````

After.
",
            "Before.

```
~~~
- Fake change.
```

After.
",
        ] {
            let u = units("doc.md", text);
            assert_eq!(texts(text, &u), ["Before.", "After."], "{text:?}");
        }
    }

    #[test]
    fn a_piece_cut_from_the_middle_gets_its_heading_and_its_table_header_as_context() {
        let md = "# Trials

Intro.

| Study | Year |
|---|---|
| Lee 2009 | 2009 |
| Ni 2010 | 2010 |
";
        let at = md.find("| Ni 2010").unwrap();
        assert_eq!(reading_context("t.md", md, at), ["section heading: # Trials", "table header: | Study | Year |"]);
        assert!(reading_context("t.md", md, 0).is_empty(), "a piece that begins with its heading needs none");
        assert_eq!(reading_context("t.md", md, at + 5), ["section heading: # Trials", "table header: | Study | Year |"], "cut inside a row");
        let txt = "Included trials

Study | Country | Arms

Lee 2009 | Korea | 2

Ni 2010 | China | 2
";
        let at = txt.find("Ni 2010").unwrap();
        assert_eq!(reading_context("review.txt", txt, at), ["table header: Study | Country | Arms"], "plain text: rows of three cells or more");
        assert!(reading_context("review.txt", txt, txt.find("Included").unwrap()).is_empty());
    }

    #[test]
    fn a_heading_or_a_table_row_inside_a_code_block_is_code() {
        // Codex review of 320a04e, HDR-01: a `#` line inside a `~~~md` block became the heading of the text after the block, and
        // the first reading cut a section there
        let long = "After the block the text goes on for a while. ".repeat(6);
        let md = format!("# Real heading\n\nIntro line.\n\n~~~md\n# Fabricated heading\n| Not | A | Table |\n~~~\n\n{long}\n");
        let after = md.find("After the block").unwrap();
        assert_eq!(reading_context("notes.md", &md, after), ["section heading: # Real heading"]);
        let fabricated = md.find("# Fabricated").unwrap();
        assert!(super::super::sections("notes.md", &md, 64).iter().all(|(a, _)| *a != fabricated), "no section starts at a line of code");
        assert_eq!(super::super::sections("notes.md", &md, 4096), [(0, md.len())], "one heading, one section");
        // a piece that begins inside the block is code: no table header from it, and the heading above the block
        let row = md.find("| Not").unwrap();
        assert_eq!(reading_context("notes.md", &md, row), ["section heading: # Real heading"]);
        // a code block between a table and the piece ends the table
        let table = "# T\n\n| A | B |\n|---|---|\n| 1 | 2 |\n```\nx\n```\n| 3 | 4 |\n";
        assert_eq!(reading_context("t.md", table, table.find("| 3").unwrap()), ["section heading: # T"]);
        assert_eq!(code_lines(table).iter().filter(|(_, _, code)| *code).count(), 3);
    }

    #[test]
    fn plain_text_has_paragraphs_only_and_windows_line_ends_stay_out_of_a_unit() {
        let text = "Title: Tai chi improves function.\r\n\r\n- not a list in plain text\r\n# not a heading\r\n\r\nLast.";
        let u = units("retracted-trial.txt", text);
        assert_eq!(texts(text, &u), ["Title: Tai chi improves function.", "- not a list in plain text\r\n# not a heading", "Last."]);
    }

    #[test]
    fn units_never_end_inside_a_character() {
        let text = "1. R\u{e9}sum\u{e9} \u{2014} first\n2. \u{7b2c}\u{4e8c}\u{9805}\u{76ee}\n\n\u{da}ltimo p\u{e1}rrafo \u{2713}\n";
        let u = units("notes.md", text);
        assert_eq!(texts(text, &u), ["1. R\u{e9}sum\u{e9} \u{2014} first", "2. \u{7b2c}\u{4e8c}\u{9805}\u{76ee}", "\u{da}ltimo p\u{e1}rrafo \u{2713}"]);
        assert!(u.iter().all(|(a, b)| text.is_char_boundary(*a) && text.is_char_boundary(*b)));
    }

    #[test]
    fn a_gap_is_a_unit_of_finished_sections_that_no_quote_and_no_withdrawn_text_touches() {
        let text = "# A\n\n1. one\n2. two\n3. three\n\n# B\n\n4. four\n";
        let u = units("c.md", text);
        let sections = vec![(0, text.find("# B").unwrap()), (text.find("# B").unwrap(), text.len())];
        let at = |s: &str| {
            let i = text.find(s).unwrap();
            (i, i + s.len())
        };
        // section A is done, section B is not; "one" is quoted, "three" is withdrawn text
        let g = gaps(&u, &sections, |k| k == 0, &[at("one")], &[at("three")]);
        assert_eq!(texts(text, &g), ["2. two"]);
        // a quote that only touches a unit's edge still covers it; nothing is a gap before any section is done
        assert_eq!(texts(text, &gaps(&u, &sections, |k| k == 0, &[at("2.")], &[])), ["1. one", "3. three"]);
        assert!(gaps(&u, &sections, |_| false, &[], &[]).is_empty());
    }

    // ---- the dispatcher's part (SPEC_V02_GAP_PASS section 11, checks 3 to 9)

    use super::super::super::mem::MemStore;

    const LOG: &str = "# Changes\n\n1. Remove batching support.\n2. Add tool titles.\n3. Clarify the error text.\n4. Remove sessions.\n5. Add icons.\n\n# Notes\n\nA client MUST retry.\n\nAnother plain note.\n";

    fn dispatcher(gap: GapProfile) -> Dispatcher {
        let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
        Dispatcher::new(DispatchConfig { gap, ..Default::default() }, vec![q])
    }

    fn observe(p: &str, n: usize, quote: &str) -> Value {
        json!({"kind": "observe", "local_id": format!("{p}o{n}"), "doc_id": "log.md", "exact_quote": quote, "terms": ["change"]})
    }

    /// Reads every section, quoting `quoted` where its section holds it, and returns the first task that is no reading.
    fn read_all(d: &mut Dispatcher, s: &mut MemStore, quoted: &[&str]) -> Value {
        loop {
            let t = d.acquire(s, "w1", true, 0);
            if t["kind"] != "EXTEND" {
                return t;
            }
            let p = t["local_id_prefix"].as_str().unwrap();
            let prompt = t["prompt"].as_str().unwrap();
            let lines: Vec<Value> = quoted.iter().filter(|q| prompt.contains(**q)).enumerate().map(|(n, q)| observe(p, n, q)).collect();
            assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), "w1", &lines, 0)["status"], "COMMITTED", "{t}");
        }
    }

    fn span(q: &str) -> (usize, usize) {
        let i = LOG.find(q).unwrap();
        (i, i + q.len())
    }

    /// The report of the pass, held against the coverage table drawn from the store alone: the totals of the table are the report.
    fn report(d: &Dispatcher, s: &MemStore) -> Value {
        let r = d.gap_report(s);
        let table = super::super::coverage::coverage_with(s, d.cfg.section_bytes, &d.cfg.gap);
        assert_eq!(table.summary, r, "the totals of the coverage table are not the report");
        r
    }

    /// The units of LOG with what the coverage table says each came to, and its packs.
    fn table(d: &Dispatcher, s: &MemStore) -> (Vec<(String, String)>, Vec<Vec<Value>>) {
        let table = super::super::coverage::coverage_with(s, d.cfg.section_bytes, &d.cfg.gap);
        let at = |v: &Value| v.as_u64().unwrap() as usize;
        (table.units.iter().map(|r| (LOG[at(&r[1])..at(&r[2])].to_string(), r[5].as_str().unwrap().to_string())).collect(), table.packs)
    }

    fn with_status<'a>(units: &'a [(String, String)], status: &str) -> Vec<&'a str> {
        units.iter().filter(|(_, st)| st == status).map(|(text, _)| text.as_str()).collect()
    }

    #[test]
    fn the_coverage_table_says_what_each_unit_came_to_and_its_totals_are_the_report() {
        let mut s = MemStore::new(&[("log.md", LOG)], &[]);
        let mut d = dispatcher(GapProfile { limit: 1, units_per_task: 8, second_reader_tiers: vec![0], ..Default::default() });
        // before any reading no unit is read
        let (units, packs) = table(&d, &s);
        assert_eq!((units.len(), with_status(&units, "unread").len(), packs.len()), (7, 7, 0), "{units:?}");
        // read, one unit quoted: the others are gaps no pack has asked about yet
        let t = read_all(&mut d, &mut s, &["3. Clarify the error text."]);
        let (units, _) = table(&d, &s);
        assert_eq!(with_status(&units, "quoted"), ["3. Clarify the error text."]);
        assert_eq!(with_status(&units, "left_by_budget").len(), 6, "{units:?}");
        report(&d, &s);
        // the first reader quotes one unit of the pack: the rest wait for the second reader
        let key = t["key"].as_str().unwrap().to_string();
        let p = t["local_id_prefix"].as_str().unwrap().to_string();
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[observe(&p, 1, "1. Remove batching support.")], 0)["status"], "COMMITTED");
        let (units, packs) = table(&d, &s);
        assert_eq!(with_status(&units, "quoted"), ["1. Remove batching support.", "3. Clarify the error text."]);
        assert_eq!(with_status(&units, "second_reading_pending").len(), 5, "{units:?}");
        assert_eq!(packs.len(), 1);
        report(&d, &s);
        // the second reader quotes one more and leaves the others: an explicit empty answer of two readers
        let second = d.acquire(&s, "w2", true, 0);
        let p2 = second["local_id_prefix"].as_str().unwrap().to_string();
        assert_eq!(d.submit(&mut s, second["task_id"].as_str().unwrap(), "w2", &[observe(&p2, 1, "5. Add icons.")], 0)["status"], "COMMITTED");
        let (units, packs) = table(&d, &s);
        assert_eq!(with_status(&units, "quoted"), ["1. Remove batching support.", "3. Clarify the error text.", "5. Add icons."]);
        assert_eq!(with_status(&units, "empty"), ["2. Add tool titles.", "4. Remove sessions.", "A client MUST retry.", "Another plain note."]);
        // every row of a unit the pack spans names it, and its second reading; a quoted unit names its quote
        let rows = super::super::coverage::coverage_with(&s, d.cfg.section_bytes, &d.cfg.gap).units;
        let second_key = key.replacen("gap:", "gap2:", 1);
        assert!(rows.iter().all(|r| r[7] == json!(key) && r[8] == json!(second_key)), "{rows:?}");
        let quoted_by: Vec<Value> = serde_json::from_str(rows[0][6].as_str().unwrap()).unwrap();
        assert_eq!(quoted_by.len(), 1, "{rows:?}");
        assert_eq!(rows[1][6], json!("[]"));
        // the packs: the first reader's and the second's, each with what it recorded, in the order they closed
        let pack = |n: usize| (packs[n][0].clone(), packs[n][4].clone(), packs[n][6].clone(), packs[n][7].clone(), packs[n][8].clone(), packs[n][9].clone());
        assert_eq!(pack(0), (json!(key), json!(0), json!("answered"), json!(1), json!(0), json!("w1")));
        assert_eq!(pack(1), (json!(second_key), json!(1), json!("answered"), json!(1), json!(1), json!("w2")));
        let r = report(&d, &s);
        assert_eq!((&r["units_quoted"], &r["gap_units"], &r["complete"]), (&json!(3), &json!(4), &json!(true)), "{r}");
    }

    #[test]
    fn packs_follow_the_tiers_of_the_profile_within_the_budget_and_carry_their_targets_only() {
        let profile =
            GapProfile { limit: 2, units_per_task: 4, tiers: vec![GapTier { words: vec!["Remove".into()], ..Default::default() }], ..Default::default() };
        let mut s = MemStore::new(&[("log.md", LOG)], &[]);
        let mut d = dispatcher(profile);
        let first = read_all(&mut d, &mut s, &["3. Clarify the error text."]);
        // tier 0 first: the two units with "Remove", one pack, nothing else in it
        assert_eq!(first["kind"], "REQUEST", "{first}");
        assert!(first["task_id"].as_str().unwrap().starts_with("TG"), "{first}");
        let (a, _) = span("1. Remove batching support.");
        let (_, b) = span("4. Remove sessions.");
        assert_eq!(first["key"], format!("gap:log.md@{a}-{b}"));
        let prompt = first["prompt"].as_str().unwrap();
        assert!(prompt.contains("[1] (bytes") && prompt.contains("1. Remove batching support.") && prompt.contains("4. Remove sessions."), "{prompt}");
        assert!(!prompt.contains("2. Add tool titles.") && !prompt.contains("3. Clarify"), "a pack holds its tier's gaps only: {prompt}");
        assert!(prompt.contains("section heading: # Changes"), "{prompt}");
        // tier 1 next, from another agent at the same time; the budget of two packs is then spent
        let second = d.acquire(&s, "w2", true, 0);
        assert_eq!(second["kind"], "REQUEST", "{second}");
        let (c, _) = span("2. Add tool titles.");
        assert!(second["key"].as_str().unwrap().starts_with(&format!("gap:log.md@{c}-")), "{second}");
        assert!(!d.reading_done(&s), "the reading waits for the gap pass");
        let third = d.acquire(&s, "w3", true, 0);
        assert_ne!(third["kind"], "REQUEST", "the budget counts primary packs: {third}");
    }

    #[test]
    fn a_quote_from_the_context_is_refused_and_an_empty_answer_closes_the_pack_for_good() {
        let mut s = MemStore::new(&[("log.md", LOG)], &[]);
        let mut d = dispatcher(GapProfile { limit: 4, units_per_task: 4, ..Default::default() });
        let t = read_all(&mut d, &mut s, &[]);
        assert_eq!(t["kind"], "REQUEST", "{t}");
        let (id, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
        let heading = json!({"kind": "observe", "local_id": format!("{p}o9"), "doc_id": "log.md", "exact_quote": "# Changes", "terms": ["x"]});
        assert_ne!(d.submit(&mut s, &id, "w1", &[heading], 0)["status"], "COMMITTED", "the heading is context, never a target");
        assert_eq!(d.submit(&mut s, &id, "w1", &[observe(&p, 1, "2. Add tool titles.")], 0)["status"], "COMMITTED");
        // what stays unquoted of that pack is not handed out again; the rest of the document is
        let key = t["key"].as_str().unwrap().to_string();
        let next = d.acquire(&s, "w1", true, 0);
        assert_eq!(next["kind"], "REQUEST", "{next}");
        let (_, _, lo, hi) = parse_pack(next["key"].as_str().unwrap()).unwrap();
        let (_, _, klo, khi) = parse_pack(&key).unwrap();
        assert!(hi <= klo || khi <= lo, "packs of one tier do not overlap: {key} {next}");
        assert!(!d.reading_done(&s));
        assert_eq!(d.submit(&mut s, next["task_id"].as_str().unwrap(), "w1", &[], 0)["status"], "COMMITTED", "an empty answer closes it");
        assert!(d.reading_done(&s));
        assert_eq!(d.acquire(&s, "w1", true, 0)["kind"], "SUMMARIZE");
    }

    #[test]
    fn three_empty_packs_in_a_row_close_the_last_tier_and_a_restart_keeps_the_order() {
        let items: String = (1..=20).map(|n| format!("{n}. Item number {n} states a rule.\n")).collect();
        let doc = format!("# List\n\n{items}");
        let mut s = MemStore::new(&[("log.md", doc.as_str())], &[]);
        let profile = GapProfile { limit: 10, units_per_task: 4, ..Default::default() };
        let mut d = dispatcher(profile.clone());
        let mut t = read_all(&mut d, &mut s, &[]);
        for n in 0..3 {
            assert_eq!(t["kind"], "REQUEST", "pack {n}: {t}");
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[], 0)["status"], "COMMITTED");
            if n == 1 {
                // a restart between packs: the completed ones stay done and their order stays known
                let mut fresh = dispatcher(profile.clone());
                fresh.recover(&s);
                d = fresh;
            }
            t = d.acquire(&s, "w1", true, 0);
        }
        assert_ne!(t["kind"], "REQUEST", "three empty packs closed the only tier: {t}");
        assert_eq!(d.gap_order, 3);
    }

    #[test]
    fn a_second_reader_gets_only_the_unquoted_units_and_is_never_the_first_reader() {
        let mut s = MemStore::new(&[("log.md", LOG)], &[]);
        let profile = GapProfile { limit: 1, units_per_task: 8, second_reader_tiers: vec![0], ..Default::default() };
        let mut d = dispatcher(profile);
        let t = read_all(&mut d, &mut s, &[]);
        assert_eq!(t["kind"], "REQUEST", "{t}");
        let key = t["key"].as_str().unwrap().to_string();
        let p = t["local_id_prefix"].as_str().unwrap().to_string();
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[observe(&p, 1, "1. Remove batching support.")], 0)["status"], "COMMITTED");
        assert_eq!(d.acquire(&s, "w1", true, 0)["status"], "WAIT", "the first reader never checks its own pack");
        let second = d.acquire(&s, "w2", true, 0);
        assert_eq!(second["key"], json!(key.replacen("gap:", "gap2:", 1)), "{second}");
        let prompt = second["prompt"].as_str().unwrap();
        assert!(prompt.contains("TASK GAP (second reader)") && prompt.contains("2. Add tool titles."), "{prompt}");
        assert!(!prompt.contains("1. Remove batching support."), "a quoted unit is no target of the second reader: {prompt}");
        let p2 = second["local_id_prefix"].as_str().unwrap().to_string();
        assert_eq!(d.submit(&mut s, second["task_id"].as_str().unwrap(), "w2", &[observe(&p2, 1, "5. Add icons.")], 0)["status"], "COMMITTED");
        assert_eq!(s.checkpoint(&task_checkpoint(&key.replacen("gap:", "gap2:", 1))).unwrap()["context"]["gap"]["recorded"], json!(1));
        // the limit of one primary pack is spent; the second reader did not count against it
        assert_eq!(d.acquire(&s, "w3", true, 0)["kind"], "SUMMARIZE");
        let r = report(&d, &s);
        assert_eq!(
            (
                &r["units_read"],
                &r["units_quoted"],
                &r["gap_tasks"],
                &r["gap_recorded"],
                &r["second_reader_tasks"],
                &r["empty_overturned"],
                &r["gap_left_by_budget"]
            ),
            (&json!(7), &json!(2), &json!(1), &json!(1), &json!(1), &json!(1), &json!(0)),
            "{r}"
        );
    }

    #[test]
    fn a_pack_whose_units_were_all_quoted_gets_no_second_reader_and_the_pass_is_off_without_a_limit() {
        let mut s = MemStore::new(&[("log.md", "# A\n\n1. One rule.\n2. Two rules.\n")], &[]);
        let mut d = dispatcher(GapProfile { limit: 3, units_per_task: 4, second_reader_tiers: vec![0], ..Default::default() });
        let t = read_all(&mut d, &mut s, &[]);
        let p = t["local_id_prefix"].as_str().unwrap().to_string();
        let lines = [observe(&p, 1, "1. One rule."), observe(&p, 2, "2. Two rules.")];
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &lines, 0)["status"], "COMMITTED");
        assert_eq!(d.acquire(&s, "w2", true, 0)["kind"], "SUMMARIZE", "nothing is left for a second reader");
        // limit 0: the reading goes straight to the summaries, as before 0.2
        let mut s = MemStore::new(&[("log.md", LOG)], &[]);
        let mut d = dispatcher(GapProfile::default());
        assert_eq!(read_all(&mut d, &mut s, &[])["kind"], "SUMMARIZE");
    }

    #[test]
    fn a_profile_file_reads_its_tiers_and_refuses_a_pack_size_out_of_range() {
        let v = json!({"gap_pass": {"limit": 12, "units_per_task": 8, "second_reader_tiers": [0],
            "tiers": [{"path_contains": ["changelog"]}, {"words": ["MUST", "Deprecat"]}]}});
        let g = GapProfile::from_json(&v).unwrap();
        assert_eq!((g.limit, g.units_per_task, g.second_reader_tiers.clone(), g.tiers.len()), (12, 8, vec![0], 2));
        assert_eq!((g.tier("docs/changelog.mdx", "x"), g.tier("page.md", "A client MUST"), g.tier("page.md", "plain")), (0, 1, 2));
        assert_eq!(GapProfile::from_json(&g.settings()).unwrap(), g);
        assert!(GapProfile::from_json(&json!({"limit": 1, "units_per_task": 9})).is_err());
        let _ = span("A client MUST retry.");
    }

    // ---- Codex review of 6d2c270

    #[test]
    fn a_tier_counts_packs_in_the_order_they_closed_not_the_order_of_their_first_answers() {
        // GAP-01: four packs answered empty; their second readers close D with a record, then A, B, C empty: the tier closes
        let items: String = (1..=32).map(|n| format!("{n}. Item number {n} states a rule.\n")).collect();
        let doc = format!("# List\n\n{items}");
        let mut s = MemStore::new(&[("log.md", doc.as_str())], &[]);
        let mut d = dispatcher(GapProfile { limit: 10, units_per_task: 4, second_reader_tiers: vec![0], ..Default::default() });
        let first = read_all(&mut d, &mut s, &[]);
        let mut primaries = vec![first];
        for agent in ["w2", "w3", "w4"] {
            primaries.push(d.acquire(&s, agent, true, 0));
        }
        for (t, agent) in primaries.iter().zip(["w1", "w2", "w3", "w4"]) {
            assert!(t["key"].as_str().unwrap().starts_with("gap:"), "{t}");
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), agent, &[], 0)["status"], "COMMITTED");
        }
        let seconds: Vec<(Value, &str)> = ["w2", "w3", "w4", "w1"].into_iter().map(|a| (d.acquire(&s, a, true, 0), a)).collect();
        for (t, _) in &seconds {
            assert!(t["key"].as_str().unwrap().starts_with("gap2:"), "{t}");
        }
        // D's second reader (w1) records first, then A, B and C close empty
        let (td, ad) = &seconds[3];
        let p = td["local_id_prefix"].as_str().unwrap();
        let quote =
            json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "log.md", "exact_quote": "13. Item number 13 states a rule.", "terms": ["rule"]});
        assert_eq!(d.submit(&mut s, td["task_id"].as_str().unwrap(), ad, &[quote], 0)["status"], "COMMITTED", "{td}");
        for (t, a) in &seconds[..3] {
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), a, &[], 0)["status"], "COMMITTED");
        }
        assert!(d.reading_done(&s), "recorded, then three empty: the only tier is closed");
        assert_eq!(d.acquire(&s, "w2", true, 0)["kind"], "SUMMARIZE");
        // and so after a restart
        let mut fresh = dispatcher(GapProfile { limit: 10, units_per_task: 4, second_reader_tiers: vec![0], ..Default::default() });
        fresh.recover(&s);
        assert!(fresh.reading_done(&s));
    }

    #[test]
    fn a_pack_whose_attempts_ran_out_is_no_empty_answer_in_the_report() {
        // GAP-02: the pack expires with agent_attempts 1; nothing was answered, so the report says so and claims no empty answer
        let mut s = MemStore::new(&[("log.md", "# A\n\n1. One rule.\n2. Two rules.\n")], &[]);
        // the run's policy of attempts, as the server pins it with the coverage
        s.checkpoints.insert("audit:mcp:coverage".into(), json!({"context": {"agent_attempts": 1}}));
        let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
        let gap = GapProfile { limit: 1, units_per_task: 4, ..Default::default() };
        let mut d = Dispatcher::new(DispatchConfig { gap: gap.clone(), agent_attempts: Some(1), ..Default::default() }, vec![q.clone()]);
        let t = read_all(&mut d, &mut s, &[]);
        assert!(t["key"].as_str().unwrap().starts_with("gap:"), "{t}");
        let later = d.acquire(&s, "w2", true, 10_000_000);
        assert_ne!(later["kind"], "REQUEST", "the expired pack is given up, not handed out again: {later}");
        let errors = d.persist_unresolved(&mut s);
        assert!(errors.is_empty(), "{errors:?}");
        let mut d = Dispatcher::new(DispatchConfig { gap, agent_attempts: Some(1), ..Default::default() }, vec![q]);
        d.recover(&s);
        let r = report(&d, &s);
        assert_eq!(
            (&r["gap_empty"], &r["gap_exhausted"], &r["gap_units_unanswered"], &r["gap_left_by_budget"]),
            (&json!(0), &json!(1), &json!(2), &json!(0)),
            "{r}"
        );
        assert!(
            r["meaning"].as_str().unwrap().contains("incomplete coverage") && r["meaning"].as_str().unwrap().contains("2 whose pack ran out of attempts"),
            "{r}"
        );
        assert_eq!(r["complete"], json!(false));
    }

    #[test]
    fn the_second_reader_follows_the_ring_as_it_stands_and_is_given_up_when_none_is_left() {
        // GAP-05 and GAP-03: the ring now [w1, w3, w4, w2], the first reader w1
        let mut s = MemStore::new(&[("log.md", LOG)], &[]);
        let readers: Vec<String> = ["w1", "w2", "w3", "w4"].iter().map(|r| r.to_string()).collect();
        let circles = Some(circles::CircleConfig { wave_sections: 4, readers, agent_timeout_ms: 60_000 });
        let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), ..Default::default() };
        let mut d = Dispatcher::new(
            DispatchConfig {
                circles,
                gap: GapProfile { limit: 1, units_per_task: 4, second_reader_tiers: vec![0], ..Default::default() },
                ..Default::default()
            },
            vec![q],
        );
        d.set_ring_order(["w1", "w3", "w4", "w2"].iter().map(|r| r.to_string()).collect());
        s.checkpoints.insert(
            "task:gap:log.md@0-10".into(),
            json!({"key": "task:gap:log.md@0-10", "from": 0, "to": 0, "context": {"agent": "w1", "gap": {"order": 0, "recorded": 0}}}),
        );
        let key = "gap2:log.md@0-10";
        let allowed = |d: &Dispatcher| ["w1", "w2", "w3", "w4"].into_iter().filter(|a| d.gap_allows(&s, key, a)).collect::<Vec<_>>();
        assert_eq!(allowed(&d), ["w3"], "the reader after the first in the ring as it stands");
        d.members.excluded.insert("w3".into());
        assert_eq!(allowed(&d), ["w4"], "w3 excluded: the free reader after it");
        assert!(!d.gap_without_reader(&s, key));
        d.members.excluded.insert("w4".into());
        d.members.excluded.insert("w2".into());
        assert!(d.gap_without_reader(&s, key), "only the first reader is left: no independent reader");
    }

    // ---- Codex recheck of 789b440d

    fn one_attempt() -> (MemStore, Dispatcher) {
        let mut s = MemStore::new(&[("log.md", "# A\n\n1. One rule.\n2. Two rules.\n")], &[]);
        s.checkpoints.insert("audit:mcp:coverage".into(), json!({"context": {"agent_attempts": 1}}));
        let q = ResearchQuestion { id: "RQ1".into(), text: "What changed?".into(), about: vec!["change".into()], ..Default::default() };
        let gap = GapProfile { limit: 1, units_per_task: 4, second_reader_tiers: vec![0], ..Default::default() };
        (s, Dispatcher::new(DispatchConfig { gap, agent_attempts: Some(1), ..Default::default() }, vec![q]))
    }

    #[test]
    fn a_pack_whose_first_reader_ran_out_of_attempts_gets_no_second_reader() {
        // GAP-03: no stored first answer, no known author: no second reading, and the pass does not hang
        let (mut s, mut d) = one_attempt();
        let t = read_all(&mut d, &mut s, &[]);
        assert!(t["key"].as_str().unwrap().starts_with("gap:"), "{t}");
        // the lease runs out; the kernel waits until the give-up is on the record, then goes on
        assert_eq!(d.acquire(&s, "w2", true, 10_000_000)["status"], "WAIT");
        assert!(d.persist_unresolved(&mut s).is_empty());
        let next = d.acquire(&s, "w2", true, 10_000_000);
        assert_eq!(next["kind"], "SUMMARIZE", "the exhausted pack opened no second reading: {next}");
        assert!(d.reading_done(&s));
        let r = report(&d, &s);
        assert_eq!((&r["gap_units_pack_failed"], &r["second_reader_tasks"], &r["complete"]), (&json!(2), &json!(0), &json!(false)), "{r}");
        let rows = super::super::coverage::coverage_with(&s, d.cfg.section_bytes, &d.cfg.gap);
        assert!(rows.units.iter().all(|u| u[5] == "pack_failed"), "{:?}", rows.units);
        assert_eq!((rows.packs.len(), &rows.packs[0][6], &rows.packs[0][7]), (1, &json!("exhausted"), &Value::Null), "{:?}", rows.packs);
    }

    #[test]
    fn units_whose_second_reading_did_not_happen_are_reported_without_an_answer() {
        // GAP-02: the first reader quotes one unit of two; the second reader of the other runs out of attempts
        let (mut s, mut d) = one_attempt();
        let t = read_all(&mut d, &mut s, &[]);
        let p = t["local_id_prefix"].as_str().unwrap().to_string();
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[observe(&p, 1, "1. One rule.")], 0)["status"], "COMMITTED");
        let second = d.acquire(&s, "w2", true, 0);
        assert!(second["key"].as_str().unwrap().starts_with("gap2:"), "{second}");
        assert_eq!(d.acquire(&s, "w3", true, 10_000_000)["status"], "WAIT");
        assert!(d.persist_unresolved(&mut s).is_empty());
        let next = d.acquire(&s, "w3", true, 10_000_000);
        assert_eq!(next["kind"], "SUMMARIZE", "{next}");
        let r = report(&d, &s);
        assert_eq!(
            (
                &r["units_read"],
                &r["units_quoted"],
                &r["gap_units"],
                &r["second_reader_exhausted"],
                &r["gap_units_unanswered"],
                &r["gap_units_second_reading_failed"]
            ),
            (&json!(2), &json!(1), &json!(1), &json!(1), &json!(1), &json!(1)),
            "{r}"
        );
        assert_eq!(r["complete"], json!(false));
        assert!(r["meaning"].as_str().unwrap().contains("1 whose second reading did not happen"), "{r}");
        let rows = super::super::coverage::coverage_with(&s, d.cfg.section_bytes, &d.cfg.gap);
        let statuses: Vec<&str> = rows.units.iter().map(|u| u[5].as_str().unwrap()).collect();
        assert_eq!(statuses, ["quoted", "second_reading_failed"]);
    }
}
