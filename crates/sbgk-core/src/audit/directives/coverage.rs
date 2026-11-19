//! The coverage table (0.2.1): what each structural unit of the documents came to, and each pack of the gap pass, drawn from the
//! state of a journal alone. The gap pass reports totals (`Dispatcher::gap_report`, SPEC_V02_GAP_PASS section 9); this is the same
//! account unit by unit, and its totals are those: every number of the report is a count of rows here.
//!
//! Nothing is stored and no rule of the kernel reads it. The settings come from what the run pinned in its journal (the checkpoint
//! `audit:mcp:coverage`: the size its sections were cut by, its gap pass and its bound of attempts), the tasks from their completion
//! checkpoints and from the record of failed attempts, the quotes and the withdrawn text from the state, as a dispatcher recovered
//! on the journal reads them.

use super::gaps::{gaps, parse_pack, units, GapProfile};
use super::*;
use crate::jcs::to_jcs;

/// What a unit came to, in the order of the questions asked of it:
/// - `unread`: it does not lie wholly in sections whose first reading is over;
/// - `quoted`: a standing quote touches it;
/// - `withdrawn`: no standing quote, and withdrawn text touches it;
/// - `reading_given_up`: no standing quote and no withdrawn text, and the reading of a section it lies in was given up with
///   nothing recorded (`FirstReadings::given_up`): it is not read, whatever a pack of the gap pass answered for it, and `pack`
///   still names that pack. Only a quote that stands on it later, of a pack or of any other task, makes it `quoted`. Until 0.2.2
///   such a unit was counted as read, as a gap (the dispatch table check of 18.11.2026);
/// - then the gaps (read, no standing quote, no withdrawn text):
///   - `empty`: a pack of its tier that was answered spans it, and no second reading is owed: an explicit empty answer;
///   - `second_reading_pending`: such a pack spans it in a tier with a second reader, whose pack is not closed yet;
///   - `second_reading_failed`: the second reader's pack was given up (its attempts ran out, or no independent reader was left);
///   - `pack_failed`: the only pack of its tier that spans it was given up: nobody answered;
///   - `left_by_budget`: no pack of its tier spans it: the budget, a closed tier or a run without a gap pass left it.
pub const UNIT_STATUSES: [&str; 9] =
    ["unread", "quoted", "withdrawn", "reading_given_up", "empty", "second_reading_pending", "second_reading_failed", "pack_failed", "left_by_budget"];

/// The columns of a unit's row, and of a pack's row: the index names its columns so (`audit::index::TABLES`).
pub const UNIT_COLUMNS: [&str; 9] = ["doc_id", "start", "end", "section", "tier", "status", "quoted_by", "pack", "second_pack"];
pub const PACK_COLUMNS: [&str; 11] = ["key", "doc_id", "start", "end", "second", "tier", "outcome", "recorded", "closed_order", "agent", "reason"];

/// The coverage of a journal's state: a row per unit of every document and a row per pack of the gap pass, with the totals.
#[derive(Debug, Clone)]
pub struct Coverage {
    /// Why this journal gives no table, when it gives none: the rows are then empty.
    pub unavailable: Option<String>,
    /// The size the sections of the run were cut by.
    pub section_bytes: Option<usize>,
    /// The gap pass the run pinned, when it had one.
    pub gap_pass: Option<Value>,
    /// One row per unit, in document and byte order: the values of `UNIT_COLUMNS`. `quoted_by` is the JCS text of the ids of the
    /// standing quotes that touch the unit.
    pub units: Vec<Vec<Value>>,
    /// One row per pack whose task was closed, answered or given up: the values of `PACK_COLUMNS`.
    pub packs: Vec<Vec<Value>>,
    /// The totals: with a gap pass the fields of its report, equal to it; without one the units read, quoted and left. Both name
    /// `units_reading_given_up` when some units are `reading_given_up`, and not otherwise.
    pub summary: Value,
}

impl Coverage {
    fn none(reason: &str) -> Coverage {
        Coverage { unavailable: Some(reason.to_string()), section_bytes: None, gap_pass: None, units: Vec::new(), packs: Vec::new(), summary: Value::Null }
    }
}

/// The coverage of the state `s`, by the settings its journal pins. A journal that pins no section size, or whose sections were cut
/// by another rule than this kernel's, gives no table: the sections its tasks number cannot be told from it.
pub fn coverage<S: AuditStore>(s: &S) -> Coverage {
    let Some(pinned) = s.checkpoint("audit:mcp:coverage") else {
        return Coverage::none("the journal pins no section size: its run was not started by audit-serve, and its sections cannot be told");
    };
    let context = &pinned["context"];
    let Some(section_bytes) = context["section_bytes"].as_u64() else {
        return Coverage::none("the journal pins no section size: its sections cannot be told");
    };
    if context["section_rule"].as_u64() != Some(SECTION_RULE) {
        return Coverage::none(
            "the documents of this run were cut into sections by an earlier rule (before 0.2): the sections its tasks number cannot be told by this kernel",
        );
    }
    let gap = match &context["gap_pass"] {
        Value::Null => GapProfile::default(),
        settings => match GapProfile::from_json(settings) {
            Ok(gap) => gap,
            Err(_) => return Coverage::none("the gap pass this journal pins is not one this kernel reads"),
        },
    };
    let mut out = coverage_with(s, section_bytes as usize, &gap);
    out.section_bytes = Some(section_bytes as usize);
    out.gap_pass = (gap.limit > 0).then(|| gap.settings());
    out
}

/// A pack's task as its checkpoint closed it.
struct Pack {
    key: String,
    second: bool,
    doc: String,
    lo: usize,
    hi: usize,
    tier: usize,
    answered: bool,
    recorded: u64,
    order: Option<u64>,
    agent: Option<String>,
    reason: Option<String>,
}

/// Whether the reading of a section was given up with nothing recorded, as its journal says. The coverage table and the report of
/// the gap pass ask it of every section whose first reading is over.
pub(crate) struct FirstReadings<'a, S: AuditStore> {
    s: &'a S,
    /// The task that stored each record (its `directive`), read once and only when a given-up reading is asked about.
    recorded: std::cell::OnceCell<BTreeMap<RecordId, String>>,
    /// The scope ranges each task stored records under (`AuditStore::stored_scopes`), read likewise.
    scoped: std::cell::OnceCell<Vec<(String, String, usize, usize)>>,
    /// The tasks each work key had an answer of refused in part (`task-repair:<task>:<attempt>`, `work_key`), read likewise.
    repaired: std::cell::OnceCell<BTreeMap<String, Vec<String>>>,
}

impl<'a, S: AuditStore> FirstReadings<'a, S> {
    pub(crate) fn new(s: &'a S) -> Self {
        FirstReadings { s, recorded: std::cell::OnceCell::new(), scoped: std::cell::OnceCell::new(), repaired: std::cell::OnceCell::new() }
    }

    /// The first reading of `key` (`doc:{doc}#{k}`), over, was given up with nothing recorded when:
    /// - it was given up: closed unresolved or out of attempts (`unresolved`, as the caller reads it), or closed by an answer
    ///   abandoned after refused ones (`abandoned` in its checkpoint, the kernel's own word for a reading given up: `Loss`);
    /// - it stored no record. Above all, no first reading (an EXTEND task, `T<n>-`; a reread is `TR`, a pack of the gap pass `TG`)
    ///   stored a record of any kind under a scope inside the section's bytes (`AuditStore::stored_scopes`), nor bound a quote
    ///   there (`AuditStore::bound_quotes`), standing or not: both are written in the transaction that stores the record, so the
    ///   tie holds at every frame (Codex's PR59-R4 of 6c9f567b and of 0e655b47: the ties of the earlier fixes are written later and
    ///   miss a journal cut off between, and a question has no quote of its own). Then, for a store that keeps neither, no record
    ///   of a task of the reading: the one its checkpoint names (and its `stored` count), those of its failed attempts (PR59-R1 of
    ///   bbea393e), those its repair checkpoints tie to the section (`task-repair:`, `work_key`; PR59-R3 of 2490c346). A refusal
    ///   alone is no record, and a record of another section or task kind is not one of the reading. A reading that stored records
    ///   read its section, whatever it lost;
    /// - and no loss reread of the section (`reread:{doc}#{k}`) was answered with a record: one that recorded anything read it.
    ///
    /// The dispatch table check of 18.11.2026 found such sections on two recorded runs counted as read: 5 and 7 of 21 first
    /// readings closed by an abandoned answer with nothing stored, of which 1 and 2 had no record after their reread either.
    pub(crate) fn given_up(&self, key: &str, section: (usize, usize), unresolved: bool) -> bool {
        let context = self.s.checkpoint(&task_checkpoint(key)).map_or(Value::Null, |c| c["context"].clone());
        if !(unresolved || context["abandoned"] == true) || context["stored"].as_u64().unwrap_or(0) > 0 {
            return false;
        }
        let recorded = self.recorded.get_or_init(|| self.s.records_since(0).into_iter().map(|r| (r.id, r.directive)).collect());
        // a quote of a first reading bound inside the section
        let first_reading =
            |id: &RecordId| recorded.get(id).and_then(|task| task.strip_prefix('T')).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
        let doc = key.strip_prefix("doc:").and_then(|rest| rest.rsplit_once('#')).map(|(doc, _)| doc);
        if doc.is_some_and(|doc| self.s.bound_quotes(doc).iter().any(|(id, a, b)| section.0 <= *a && *b <= section.1 && first_reading(id))) {
            return false;
        }
        // a record of any kind a first reading stored under a scope inside the section
        let first_reading_task = |task: &str| task.strip_prefix('T').is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
        let scoped = self.scoped.get_or_init(|| self.s.stored_scopes());
        if doc.is_some_and(|doc| scoped.iter().any(|(task, d, a, b)| d == doc && section.0 <= *a && *b <= section.1 && *a < *b && first_reading_task(task))) {
            return false;
        }
        // the tasks of the first reading, and an answered loss reread of the section
        let mut tasks: Vec<String> = context["task_id"].as_str().map(str::to_string).into_iter().collect();
        let failed = crate::audit::agent_failures::entry(self.s, key);
        tasks.extend(failed["attempts"].as_array().into_iter().flatten().filter_map(|a| a["id"].as_str()).map(str::to_string));
        let repaired = self.repaired.get_or_init(|| {
            let mut by_key: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for name in self.s.checkpoint_keys("task-repair:") {
                let context = self.s.checkpoint(&name).map_or(Value::Null, |c| c["context"].clone());
                if let (Some(work), Some(task)) = (context["work_key"].as_str(), context["task_id"].as_str()) {
                    by_key.entry(work.to_string()).or_default().push(task.to_string());
                }
            }
            by_key
        });
        tasks.extend(repaired.get(key).into_iter().flatten().cloned());
        if let Some(section) = key.strip_prefix("doc:") {
            let reread = self.s.checkpoint(&task_checkpoint(&format!("reread:{section}"))).map_or(Value::Null, |c| c["context"].clone());
            tasks.extend(reread["task_id"].as_str().filter(|_| reread["unresolved"] != true).map(str::to_string));
        }
        let stored_by: BTreeSet<&String> = recorded.values().collect();
        !tasks.iter().any(|task| stored_by.contains(task))
    }
}

/// `coverage` under given settings: the units and packs as the dispatcher of a run with these settings counts them.
pub(crate) fn coverage_with<S: AuditStore>(s: &S, section_bytes: usize, gap: &GapProfile) -> Coverage {
    // A task is over once the journal says so, as `Dispatcher::recover` reads it: answered when its completion checkpoint is there;
    // given up when that checkpoint says `unresolved`, or when the record of failed attempts holds as many as the run's bound.
    let bound = crate::audit::agent_failures::limit(s);
    let failed = crate::audit::agent_failures::state(s)["work"].clone();
    let given_up = |key: &str| bound.is_some_and(|max| failed[key]["failures"].as_u64().is_some_and(|n| n >= u64::from(max)));
    let closed_task = |key: &str| match s.checkpoint(&task_checkpoint(key)) {
        Some(c) => Some(c["context"]["unresolved"] != true),
        None => given_up(key).then_some(false),
    };
    struct Document {
        id: String,
        label: String,
        text: String,
        units: Vec<(usize, usize)>,
    }
    let documents: Vec<Document> = s
        .docs()
        .into_iter()
        .map(|id| {
            let text = s.doc_text(&id).unwrap_or_default();
            Document { label: s.document_label(&id), units: units(&id, &text), text, id }
        })
        .collect();
    // the tier of a pack: its first unit's (`Dispatcher::pack_tier`)
    let pack_tier = |doc: &str, lo: usize| {
        let Some(d) = documents.iter().find(|d| d.id == doc) else { return gap.tier(&s.document_label(doc), "") };
        let end = d.units.iter().find(|u| u.0 == lo).map_or(lo, |u| u.1);
        gap.tier(&d.label, &d.text[lo.min(d.text.len())..end.min(d.text.len())])
    };
    // the packs whose task is over: those with a completion checkpoint, and those given up after their attempts ran out
    let mut keys: BTreeSet<String> = s.checkpoint_keys("task:gap").into_iter().map(|name| name["task:".len()..].to_string()).collect();
    keys.extend(failed.as_object().into_iter().flat_map(|work| work.keys()).filter(|k| k.starts_with("gap") && given_up(k)).cloned());
    let mut packs: Vec<Pack> = Vec::new();
    for key in keys {
        let (Some((second, doc, lo, hi)), Some(answered)) = (parse_pack(&key), closed_task(&key)) else { continue };
        let context = s.checkpoint(&task_checkpoint(&key)).map_or(Value::Null, |c| c["context"].clone());
        // why it was given up: what its checkpoint says, else what its last failed attempt said
        let reason = context["reason"].as_str().or_else(|| failed[&key]["attempts"].as_array().and_then(|a| a.last()).and_then(|a| a["reason"].as_str()));
        packs.push(Pack {
            second,
            doc: doc.to_string(),
            lo,
            hi,
            tier: pack_tier(doc, lo),
            answered,
            recorded: context["gap"]["recorded"].as_u64().unwrap_or(0),
            order: context["gap"]["order"].as_u64().filter(|_| answered),
            agent: context["agent"].as_str().map(str::to_string),
            reason: reason.map(str::to_string),
            key: key.clone(),
        });
    }
    packs.sort_by(|a, b| (&a.doc, a.lo, a.hi, a.second).cmp(&(&b.doc, b.lo, b.hi, b.second)));
    let primary = |answered: bool, doc: &str, a: usize, b: usize, tier: usize| {
        packs.iter().find(|p| !p.second && p.answered == answered && p.doc == doc && p.lo <= a && b <= p.hi && p.tier == tier)
    };
    let mut rows: Vec<Vec<Value>> = Vec::new();
    let mut count: BTreeMap<&str, usize> = BTreeMap::new();
    let readings = FirstReadings::new(s);
    for d in &documents {
        let sections = sections(&d.id, &d.text, section_bytes);
        // the first reading of each section: over when answered or given up (`Some(false)`), and whether it was given up with
        // nothing recorded
        let first: Vec<Option<bool>> = (0..sections.len()).map(|k| closed_task(&format!("doc:{}#{k}", d.id))).collect();
        let done = |k: usize| first.get(k).is_some_and(Option::is_some);
        let gave_up: Vec<bool> =
            first.iter().enumerate().map(|(k, f)| f.is_some() && readings.given_up(&format!("doc:{}#{k}", d.id), sections[k], *f == Some(false))).collect();
        let read: BTreeSet<(usize, usize)> = gaps(&d.units, &sections, done, &[], &[]).into_iter().collect();
        // the dispatcher's own account of the gaps: the units the kernel's quoted and withdrawn bytes leave
        let gap_units: BTreeSet<(usize, usize)> = gaps(&d.units, &sections, done, &s.quoted_spans(&d.id), &s.closed_spans(&d.id)).into_iter().collect();
        let (quoted, withdrawn) = (s.quoted_spans(&d.id), s.closed_spans(&d.id));
        let quotes = s.quoted_records(&d.id);
        let touches = |u: (usize, usize), span: &(usize, usize)| u.0 < span.1 && span.0 < u.1;
        let abandoned = |u: (usize, usize)| sections.iter().zip(&gave_up).any(|(sec, g)| *g && touches(u, sec));
        for u in &d.units {
            let (a, b) = *u;
            let tier = gap.tier(&d.label, &d.text[a..b]);
            let pack = primary(true, &d.id, a, b, tier).or_else(|| primary(false, &d.id, a, b, tier)).filter(|_| read.contains(u));
            let second = pack.and_then(|p| packs.iter().find(|q| q.second && q.doc == p.doc && q.lo == p.lo && q.hi == p.hi));
            let status = if !read.contains(u) {
                "unread"
            } else if quoted.iter().any(|q| touches(*u, q)) {
                "quoted"
            } else if !gap_units.contains(u) || withdrawn.iter().any(|w| touches(*u, w)) {
                "withdrawn"
            } else if abandoned(*u) {
                "reading_given_up"
            } else {
                match pack {
                    Some(p) if p.answered => match second {
                        Some(q) if !q.answered && gap.second_reader_tiers.contains(&tier) => "second_reading_failed",
                        None if gap.second_reader_tiers.contains(&tier) => "second_reading_pending",
                        _ => "empty",
                    },
                    Some(_) => "pack_failed",
                    None => "left_by_budget",
                }
            };
            *count.entry(status).or_default() += 1;
            let by: Vec<String> = quotes.iter().filter(|(_, x, y)| touches(*u, &(*x, *y))).map(|(id, _, _)| to_hex(&id.0)).collect();
            rows.push(vec![
                json!(d.id),
                json!(a),
                json!(b),
                sections.iter().position(|sec| touches(*u, sec)).map_or(Value::Null, |k| json!(k)),
                json!(tier),
                json!(status),
                json!(to_jcs(&json!(by))),
                pack.map_or(Value::Null, |p| json!(p.key)),
                second.map_or(Value::Null, |q| json!(q.key)),
            ]);
        }
    }
    let n = |status: &str| count.get(status).copied().unwrap_or(0);
    let (left, pack_failed, second_failed) = (n("left_by_budget"), n("pack_failed"), n("second_reading_failed"));
    let (second_pending, given_up) = (n("second_reading_pending"), n("reading_given_up"));
    let gap_units = n("empty") + second_pending + second_failed + pack_failed + left;
    let units_read = rows.len() - n("unread") - given_up;
    let of = |second: bool, answered: bool| packs.iter().filter(move |p| p.second == second && p.answered == answered);
    let mut summary = if gap.limit == 0 {
        let mut meaning = format!("the run had no gap pass: {gap_units} read units have no standing quote, and nobody was asked about them again");
        if given_up > 0 {
            meaning = format!("{meaning}; {}", super::gaps::given_up_meaning(given_up));
        }
        json!({"units_read": units_read, "units_quoted": n("quoted"), "gap_units": gap_units, "gap_pass": false, "meaning": meaning})
    } else {
        let gap_recorded = of(false, true).filter(|p| p.recorded > 0).count();
        // the fields and the words of `Dispatcher::gap_report`
        json!({"units_read": units_read, "units_quoted": n("quoted"), "gap_units": gap_units, "gap_tasks": of(false, true).count(),
        "gap_recorded": gap_recorded, "gap_empty": of(false, true).count() - gap_recorded, "gap_exhausted": of(false, false).count(),
        "second_reader_tasks": of(true, true).count(), "empty_overturned": of(true, true).filter(|p| p.recorded > 0).count(),
        "second_reader_exhausted": of(true, false).count(),
        "gap_left_by_budget": left, "gap_units_unanswered": pack_failed + second_failed,
        "gap_units_pack_failed": pack_failed, "gap_units_second_reading_failed": second_failed,
        "gap_units_second_reading_pending": second_pending,
        "complete": super::gaps::coverage_complete(left, pack_failed, second_failed, second_pending, given_up),
        "meaning": super::gaps::coverage_meaning(left, pack_failed, second_failed, second_pending, given_up)})
    };
    // as the report of the pass names them: only when there are any
    if given_up > 0 {
        summary["units_reading_given_up"] = json!(given_up);
    }
    let packs = packs
        .iter()
        .map(|p| {
            vec![
                json!(p.key),
                json!(p.doc),
                json!(p.lo),
                json!(p.hi),
                json!(u8::from(p.second)),
                json!(p.tier),
                json!(if p.answered { "answered" } else { "exhausted" }),
                if p.answered { json!(p.recorded) } else { Value::Null },
                p.order.map_or(Value::Null, |n| json!(n)),
                p.agent.as_ref().map_or(Value::Null, |a| json!(a)),
                p.reason.as_ref().filter(|_| !p.answered).map_or(Value::Null, |r| json!(r)),
            ]
        })
        .collect();
    Coverage { unavailable: None, section_bytes: Some(section_bytes), gap_pass: None, units: rows, packs, summary }
}

/// How many units have each status, the statuses with none left out.
pub fn by_status(units: &[Vec<Value>]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for row in units {
        *out.entry(row[5].as_str().unwrap_or_default().to_string()).or_default() += 1;
    }
    out
}
