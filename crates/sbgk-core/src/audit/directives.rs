//! Directives to the swarm (contract v0 §5): what a stateless agent does next, cut from the growing graph.
//!
//! Every directive is a lease on one key (a report section, a question record, a link, a research question) with a TTL, so two
//! agents never get the same work. Priorities: resolve a conflict between agents, verify a builder's proposed link, investigate an
//! open question, extend coverage section by section, and summarize a research question once the rest is done and the builder has
//! caught up. A directive carries everything the agent may use (the section text, the records and quotes it rests on) and what is
//! already established, so the agent neither re-reads nor re-checks what the swarm knows. A link is verified by one agent that
//! wrote neither of its ends: that single targeted check replaces everybody re-checking everything.

use super::*;
use crate::error::Code;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

mod requests;
// the gap pass (SPEC_V02_GAP_PASS)
pub(crate) mod gaps;
pub use gaps::{GapProfile, GapTier};
pub use requests::REQUEST_TYPES;

#[derive(Debug, Clone, Default)]
pub struct ResearchQuestion {
    pub id: String,
    pub text: String,
    /// Terms the answer is about (used to collect its support from the graph).
    pub about: Vec<String>,
    /// Structure that makes a claim about the question too (Gemini's run-10 corrections): one of these stances, an end of a
    /// standing link of one of these relations, or a mapping to a concept of one of these types. Empty: the topics alone.
    pub stances: Vec<String>,
    pub relations: Vec<String>,
    pub concept_types: Vec<String>,
}

pub mod circles;

#[derive(Debug, Clone)]
pub struct DispatchConfig {
    pub ttl_ms: u64,
    /// None retains legacy behavior; Some bounds failed agent leases.
    pub agent_attempts: Option<u32>,
    /// Explicit transport deadline of SUMMARY/ANSWER only; None preserves historical leases.
    pub answer_timeout_ms: Option<u64>,
    /// What the agents are told they read. A run on pinned reports keeps the words its measured runs had.
    pub corpus: &'static str,
    /// Upper bound of one report section handed to an agent (UTF-8 bytes).
    pub section_bytes: usize,
    /// Records shown as support (cone) or as already established.
    pub max_cone: usize,
    pub max_known: usize,
    /// Lines one answer may carry.
    pub max_lines: usize,
    /// A summary sees up to this many claims about its question, spread over the documents, and up to this many records of
    /// their support, and may answer with this many lines (Gemini's run-9 spec: the 12-record window of run 8 hid most of the
    /// graph from the summaries). `summary_records` is capped at the store's MAX_REFS: the store refuses a longer issued list
    /// (Codex review c78060e, F01).
    pub summary_claims: usize,
    pub summary_records: usize,
    /// Live run 10A-2: shown 76..85 claims, the summaries restated them in 70+ lines and ran into the model's output limit (8192
    /// tokens) mid-line, three times, so the answer was lost. A summary condenses: 40 lines of about 120 tokens fit.
    pub summary_lines: usize,
    /// The graph builder's typed requests (U1): at most this many in a run (0: off) and this
    /// many per card.
    pub max_requests: usize,
    pub requests_per_card: usize,
    /// Independent kernel loss rereads (A5), unit-cost fair queue: at most two per report in this bounded first wave. Zero: off.
    pub auto_reread_limit: usize,
    /// Backpressure (the owner's run 10A-17, agreed with the side session): a first reading is not issued while the records the
    /// graph builder has not carded yet, plus `backpressure_per_task` for every first reading in flight and the one asked for,
    /// exceed `backpressure_records` (0: off). Link checks, conflicts and requests are never held.
    pub backpressure_records: usize,
    pub backpressure_per_task: usize,
    /// Reading zones (run S1.2): each a set of documents one EXTEND task reads whole, every section of
    /// them in one directive, so its records may be related across them. A document of no zone is read section by section as
    /// before. Empty: no zones.
    pub zones: Vec<Vec<String>>,
    /// An answer may also cite the grounded records its own agent got accepted earlier in the run, besides those its directive
    /// shows (contract v0.1 R5 widened from "shown" to "shown or own"; a record of another agent still has to be shown). Off:
    /// shown only.
    pub own_refs: bool,
    /// Explicit read/build waves, off for both historical modes.
    pub circles: Option<circles::CircleConfig>,
    /// Circles +1: the subject of the swarm's independent graph builder with a fixed role. It refines the
    /// swarm's graph in a REFINE phase after the swarm's BUILD of every circle; None keeps circles as they were.
    pub circle_refiner: Option<String>,
    /// The longest REFINE of a circle: past it the swarm goes on and the refiner keeps its cursor for the next circle (one
    /// slow refiner call must not hold a circle). None waits for the refiner.
    pub refine_budget_ms: Option<u64>,
    /// The swarm may write relation lines, which become links the swarm checks. Off in the owner's control profiles
    /// `--build-scope concepts|none` (2026-10-30): records are not connected, the prompts offer no relation line, and one is
    /// refused before the store.
    pub relation_lines: bool,
    /// The hint profile `--build-scope hints` (no build phase; the reader gets related records with its
    /// directive): once a reading task's answer is stored, the task has one more turn, RELATE, which shows each of its claims with
    /// claims of other report dates that share its words (hints, not evidence) and takes only claims of a change on both quotes.
    pub relate_hints: bool,
    /// Explicit map candidates in the reading queue; links belong only to authenticated CHANGE leases.
    pub versions: bool,
    /// The gap pass after the first readings (SPEC_V02_GAP_PASS); off while its `limit` is 0.
    pub gap: GapProfile,
}

impl Default for DispatchConfig {
    fn default() -> DispatchConfig {
        DispatchConfig {
            ttl_ms: 600_000,
            agent_attempts: None,
            answer_timeout_ms: None,
            corpus: "a corpus of engineering reports",
            section_bytes: 6000,
            max_cone: 12,
            max_known: 12,
            max_lines: 32,
            summary_claims: 100,
            summary_records: crate::session::MAX_REFS,
            summary_lines: 48,
            max_requests: 0,
            requests_per_card: 2,
            auto_reread_limit: 0,
            backpressure_records: 0,
            backpressure_per_task: 20,
            zones: Vec::new(),
            own_refs: false,
            circles: None,
            circle_refiner: None,
            refine_budget_ms: None,
            relation_lines: true,
            relate_hints: false,
            versions: false,
            gap: GapProfile::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskKind {
    ResolveConflict,
    VerifyLink,
    /// A graph builder's request or its control reading (`request:<n>`, `control:<n>`).
    Request,
    Investigate,
    Change,
    Extend,
    Summarize,
    /// A sequential builder card leased to a non-author swarm agent.
    Build,
}

impl TaskKind {
    pub fn name(self) -> &'static str {
        match self {
            TaskKind::ResolveConflict => "RESOLVE_CONFLICT",
            TaskKind::VerifyLink => "VERIFY_LINK",
            TaskKind::Request => "REQUEST",
            TaskKind::Investigate => "INVESTIGATE",
            TaskKind::Change => "CHANGE",
            TaskKind::Extend => "EXTEND",
            TaskKind::Summarize => "SUMMARIZE",
            TaskKind::Build => "BUILD",
        }
    }

    /// The kind a name gives (`name`'s inverse).
    pub fn parse(name: &str) -> Option<TaskKind> {
        [
            TaskKind::ResolveConflict,
            TaskKind::VerifyLink,
            TaskKind::Request,
            TaskKind::Investigate,
            TaskKind::Change,
            TaskKind::Extend,
            TaskKind::Summarize,
            TaskKind::Build,
        ]
        .into_iter()
        .find(|k| k.name() == name)
    }
}

#[derive(Debug, Clone)]
struct Lease {
    agent: String,
    kind: TaskKind,
    key: String,
    scope: Scope,
    expires_ms: u64,
    link: Option<LinkId>,
    /// The link's status when the task was issued (the verdict is refused if it changed meanwhile).
    link_status: Option<LinkStatus>,
    question: Option<String>,
    /// Records shown in the directive: the only foreign records the answer may reference (contract v0.1 R5).
    issued: Vec<RecordId>,
    /// With `own_refs`: the grounded records its agent got accepted earlier in the run, which the answer may cite as well. Not
    /// part of the directive's window (a summary's report coverage is still that of `issued`).
    own_run: Vec<RecordId>,
    /// Submissions so far: every store submission of the task gets a fresh id `<task>#<attempt>` / `<task>#done<attempt>`
    /// (a refused attempt keeps its receipt; the repaired one is a new submission).
    attempt: u32,
    /// Records this agent already got accepted under the task, and their local ids (a repair may reference them by either).
    own: Vec<RecordId>,
    locals: BTreeMap<String, RecordId>,
    /// The digest of each accepted line by local id: an exact resend of it is a no-op (models repairing an answer repeat it).
    line_digests: BTreeMap<String, String>,
    /// An answer of this lease was refused: giving the lease back then counts as a failed attempt at its key.
    failed: bool,
    /// Refused answers of this lease (a section read with losses is shown to the graph builder).
    refusals: u32,
    /// A reading task in its RELATE turn (`relate_hints`): its answer is stored, and it now takes only claims of a change.
    relate: bool,
    /// A repair that names fallen answer rows: the most lines it takes. The report coverage of a new answer does not apply to it:
    /// the rows kept were covered when they were accepted, and a report whose only row fell need not come back.
    repair_lines: Option<usize>,
}

/// Hints per claim in a RELATE turn (offline on four runs: the best three held the other side of 8 to 9 of 11 to 12 stale facts).
const RELATE_HINTS: usize = 3;
/// The nearest claims by words in which a summary's claim looks for its later state (`summary_companions`), as for a hint.
const COMPANION_POOL: usize = 3;

/// Leases of one key given back after a refused answer before the key is recorded as unresolved and no longer issued (live run 3:
/// a link check whose verifier kept failing looped until the runner stopped the run).
const MAX_FAILED_LEASES: u32 = 3;

/// The durable reason of a question given up because the word search of `sections_about` found no section for it: what was checked,
/// not a finding that the corpus lacks the answer (Codex's review of 77a803e, R04).
const NO_SECTION_MATCHED: &str = "no_section_matched_terms";

fn line_digest(v: &Value) -> String {
    crate::hash::to_hex(&crate::hash::sha256(crate::jcs::to_jcs(v).as_bytes()))
}

/// The outcomes a summary's `done` line may state (contract v0.1 R7: an honest unknown is an outcome, not a gap).
const OUTCOMES: [&str; 3] = ["answered", "unknown", "unresolved_conflict"];

/// The store's bound of a claim's or a done line's text (records.rs MAX_TEXT_CHARS), checked for a whole summary before it is stored.
const SUMMARY_TEXT_CHARS: usize = 240;
/// The claims a summary is asked for: below its line bound with room to spare (live run 10A-3: asked for at most 39, it wrote 42;
/// live run 10A-4: RQ2 needed 40 claims and its 41 lines were over the bound of 40).
const SUMMARY_CLAIMS: usize = 40;

/// A research question's accepted outcome: its `done` record, the stated outcome and the answer records.
#[derive(Debug, Clone)]
struct Answer {
    done: RecordId,
    outcome: String,
    ids: Vec<RecordId>,
    /// Rows of this answer that stopped standing: its repair names them.
    fallen: Vec<RecordId>,
}

impl Answer {
    /// Keep the rows that stand and remember the others.
    fn settle<S: AuditStore>(&mut self, s: &S, f: &Flags) {
        let (kept, fallen): (Vec<RecordId>, Vec<RecordId>) = self.ids.iter().copied().partition(|id| f.support(s, id));
        self.ids = kept;
        self.fallen.extend(fallen);
    }
}

/// An answer row that fell: the quotes under it that stand, and how many do not.
struct Fallen {
    id: RecordId,
    standing: Vec<RecordView>,
    gone: usize,
}

/// The fallen rows a repair names one by one. The others are only counted.
const FALLEN_NAMED: usize = 20;

/// The rows a repair names: those with a quote left to answer from.
fn named_rows(fallen: &[Fallen]) -> Vec<&Fallen> {
    fallen.iter().filter(|r| !r.standing.is_empty()).take(FALLEN_NAMED).collect()
}

/// The claim lines a repair takes: a merged row may come back as two, and a little room. The room stays when no quote stands: the
/// state before a withdrawn one may stand in other records, and the answer may say so.
fn repair_claims(fallen: &[Fallen]) -> usize {
    (2 * named_rows(fallen).len() + 2).min(SUMMARY_CLAIMS)
}

/// The head of a repair. A fallen row is named by id with the quotes that stand: its text may state what was withdrawn (run K016:
/// the row said what the withdrawn sentence said, and the header it named stood in no other quote), so the kernel does not hand it
/// back. Without this the repair could not tell what fell: it wrote the answer again, 34 lines, 23 of them copies, and not the row.
/// With a live support shown (`live`), the repair may also rest what fell on its quotes.
fn fallen_repair(fallen: &[Fallen], kept: &[RecordId], live: &[RecordId]) -> String {
    let named = named_rows(fallen);
    let mut out = format!(
        "INCREMENTAL REPAIR: {} of the answer records of this question no longer stand: evidence under them was withdrawn or changed. The kernel \
         keeps the other {} and adds them to your done line itself: {}. Do not write them again: a line repeating one of them is dropped.\n",
        fallen.len(),
        kept.len(),
        short_list(kept).join(", ")
    );
    if named.is_empty() && !live.is_empty() {
        out.push_str(&format!(
            "No quote of theirs stands, and their text is left out, as it may state what was withdrawn. The claims of LIVE SUPPORT below stand on \
             quotes that were not withdrawn and are the records most like them by words: where their quotes state on their own a point of this \
             question, write it as a claim based_on those quotes, saying nothing they do not say. Write a claim only there or where the records \
             below show that a point of this question now stands differently, at most {} claim lines; otherwise only the done line.\n",
            repair_claims(fallen)
        ));
        return out;
    }
    if named.is_empty() {
        out.push_str(&format!(
            "No quote of theirs stands, and their text is left out, as it may state what was withdrawn. Write a claim only where the records below \
             show that a point of this question now stands differently, at most {} claim lines; otherwise only the done line.\n",
            repair_claims(fallen)
        ));
        return out;
    }
    out.push_str("STILL STANDING UNDER THE FALLEN RECORDS (their text is left out, as it may state what was withdrawn):\n");
    for r in &named {
        let quotes: Vec<String> = r.standing.iter().map(|o| format!("{} \"{}\"", o.id.short(), o.quote.as_deref().unwrap_or_default())).collect();
        let gone = if r.gone > 0 { format!(" ({} of its quotes gone)", r.gone) } else { String::new() };
        out.push_str(&format!("  {}{gone}: {}\n", r.id.short(), quotes.join(", ")));
    }
    // the rows not named have no quote to answer from, or are past FALLEN_NAMED: without a live support nothing is written for
    // them; with one, what they stated may stand on its quotes (two rows fell, one of them with a quote left: the other was
    // written off while its live support was in the window)
    let more = fallen.len() - named.len();
    if more > 0 && live.is_empty() {
        out.push_str(&format!("{more} more fell: write nothing for them.\n"));
    } else if more > 0 {
        out.push_str(&format!(
            "{more} more fell, not named above: write a claim for them only where the quotes of the claims of LIVE SUPPORT below state on their \
             own a point of this question, based_on those quotes and saying nothing they do not say.\n"
        ));
    }
    let with_live = if live.is_empty() { "" } else { ", with the quotes of the claims of LIVE SUPPORT below," };
    let no_other = if more > 0 && !live.is_empty() { "Write no claim beyond these" } else { "Write no other claim" };
    out.push_str(&format!(
        "Write at most {} claim lines: for each fallen record above, what its standing quotes{with_live} state on their own, based_on those quotes only and \
         saying nothing they do not say, or no claim where they state too little. {no_other}: the answer needs no other change.\n",
        repair_claims(fallen)
    ));
    out
}

/// What a claim says: its text, case and spacing aside, and its other fields.
fn claim_stated(text: &str, claim: &Value) -> (String, Vec<String>) {
    let fields = ["subject", "predicate", "object", "stance", "as_of"]
        .iter()
        .map(|k| claim.get(*k).filter(|v| !v.is_null()).map(Value::to_string).unwrap_or_default())
        .collect();
    (text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase(), fields)
}

/// Whether references name exactly these grounds, ids in hex. A reference reads as in the store: `@` and at least 16 digits of an id, in
/// either case, or the same digits without the `@` when no line of the answer has that name, as the dispatcher adds the `@` before the
/// store reads it. Whatever else a line names is no ground of a kept row, and the store's own check answers for it.
fn names_grounds(references: &[Value], grounds: &BTreeSet<String>, names: &BTreeSet<&str>) -> bool {
    let named: Option<BTreeSet<&String>> = references
        .iter()
        .map(|r| {
            let r = r.as_str()?;
            let digits = r.strip_prefix('@').or_else(|| (!names.contains(r)).then_some(r)).filter(|d| d.len() >= 16)?.to_ascii_lowercase();
            grounds.iter().find(|g| g.starts_with(&digits))
        })
        .collect();
    named.is_some_and(|n| n.len() == grounds.len())
}

/// The claim lines that only repeat a row the answer keeps: the same statement on the same grounds. Words alone do not make a copy: the
/// same sentence with another date or on another quote is another claim. A copy would be a new record beside the kept row (a record's
/// id holds its directive): runs K015 and K016 got answers of 80 and 71 rows, 47 and 48 of them distinct. A line another line rests on
/// stays. Done here and not in the store: a journal holding such copies must replay.
/// The records of an answer, each once, in the order first named. The kernel adds a kept row by its short id, and the model may name
/// the same record again in another spelling: its own local id, or the id of a claim equal to a kept row, which the store gives the
/// kept row's id (control run K02_1_r2 of 0.2: a repair in several attempts listed 11 of 54 records twice).
fn distinct_ids(ids: Vec<RecordId>) -> Vec<RecordId> {
    let mut seen = BTreeSet::new();
    ids.into_iter().filter(|id| seen.insert(*id)).collect()
}

fn copies_of_kept<S: AuditStore>(s: &S, kept: &[RecordId], lines: &[Value]) -> BTreeSet<String> {
    let rows: Vec<_> = kept
        .iter()
        .filter_map(|id| s.record(id))
        .filter_map(|r| r.text.as_deref().map(|t| (claim_stated(t, &r.body), r.based_on.iter().map(|g| to_hex(&g.0)).collect::<BTreeSet<_>>())))
        .collect();
    let names: BTreeSet<&str> = lines.iter().filter_map(|v| v["local_id"].as_str()).collect();
    let repeats = |v: &Value, text: &str| {
        let (stated, references) = (claim_stated(text, v), v["based_on"].as_array().map_or(&[][..], Vec::as_slice));
        rows.iter().any(|(row, grounds)| *row == stated && names_grounds(references, grounds, &names))
    };
    let used: BTreeSet<String> = lines.iter().filter(|v| v["kind"] != "done").flat_map(references).collect();
    lines
        .iter()
        .filter(|v| v["kind"] == "claim" && v["text"].as_str().is_some_and(|t| repeats(v, t)))
        .filter_map(|v| v["local_id"].as_str())
        .filter(|n| !used.contains(*n))
        .map(str::to_string)
        .collect()
}

/// What a section's first reading lost: records stored, the most lines one answer offered, refused answers, and whether the reading
/// was given up (closed by an empty answer after refusals, or by failed leases: Codex's C17-01). The graph builder's board ranks
/// losses by `score`; the reading's checkpoint keeps them over a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Loss {
    stored: usize,
    offered: usize,
    refusals: u32,
    abandoned: bool,
}

impl Loss {
    /// Gemini's ranking (the consilium of 10A-17): a reading given up first, then the lines offered but not stored, then refusals.
    fn score(&self) -> usize {
        100 * usize::from(self.abandoned) + self.offered.saturating_sub(self.stored) + 5 * self.refusals as usize
    }

    fn context(&self, ctx: &mut Value) {
        ctx["refusals"] = json!(self.refusals);
        ctx["stored"] = json!(self.stored);
        ctx["offered"] = json!(self.offered);
        ctx["abandoned"] = json!(self.abandoned);
    }

    fn from_context(ctx: &Value) -> Option<Loss> {
        let refusals = ctx["refusals"].as_u64().filter(|r| *r > 0)? as u32;
        Some(Loss {
            stored: ctx["stored"].as_u64().unwrap_or(0) as usize,
            offered: ctx["offered"].as_u64().unwrap_or(0) as usize,
            refusals,
            abandoned: ctx["abandoned"] == true,
        })
    }
}

/// What a store submission of an answer stored and left out, item by item: stored lines (index in the answer, record), refused lines
/// (index, the error) and lines left out because they rest on a refused one (index, the local id they rest on); `parts` counts the
/// store submissions of the attempt.
#[derive(Debug, Default)]
struct Items {
    stored: Vec<(usize, RecordId)>,
    refused: Vec<(usize, Value)>,
    excluded: Vec<(usize, String)>,
    parts: usize,
}

impl Items {
    fn absorb(&mut self, more: Items) {
        self.stored.extend(more.stored);
        self.refused.extend(more.refused);
        self.excluded.extend(more.excluded);
        self.parts = more.parts;
    }
}

/// The foreign records the store may let these lines reference: the directive's shown records; with `own_refs` (a lease with
/// own records) the shown and own records these lines name, since the shown ones alone may fill the store's bound of MAX_REFS.
fn allowed_records(lease: &Lease, lines: &[Value]) -> Vec<RecordId> {
    if lease.own_run.is_empty() {
        return lease.issued.clone();
    }
    let named: BTreeSet<String> = lines.iter().flat_map(references).collect();
    let mut out: Vec<RecordId> = lease.issued.iter().chain(&lease.own_run).filter(|id| named.contains(&id.short())).copied().collect();
    out.sort();
    out.dedup();
    out
}

/// The names a line rests on or connects: its based_on, a relation's ends, a done line's answer_ids.
fn references(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = ["based_on", "answer_ids"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(|x| x.as_array()))
        .flatten()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    out.extend(["from", "to"].iter().filter_map(|k| v.get(*k).and_then(|x| x.as_str()).map(str::to_string)));
    out
}

/// The refusal of a line by the dispatcher's own rules, worded as the store words its own, with what the line needs in
/// `expected_by_kernel` (Gemini's plan step 1: an agent told only the rule's text repaired blind and failed three times).
fn rule_error(p: &Value) -> Value {
    if let Some(e) = p.get("error") {
        let mut error = e.clone();
        let mut expected = error["expected_by_kernel"].as_object().cloned().map(Value::Object).unwrap_or_else(|| json!({}));
        expected["rule"] = json!("byte_quote");
        for k in ["hint", "exact_bytes_in_section", "suggested_span"] {
            if let Some(v) = p.get(k) {
                expected[k] = v.clone();
            }
        }
        if let Some(v) = p.get("exact_bytes_in_section") {
            expected["suggested_exact_quote"] = v.clone();
        }
        error["expected_by_kernel"] = expected;
        return error;
    }
    let e = if p.get("local_id_rebound").is_some() {
        KernelError::new(Code::BadField, "an accepted local_id cannot be rebound: keep its accepted value or use a fresh id")
            .field("local_id")
            .expected(json!({"rule": "immutable_local_id", "accepted": p["local_id_rebound"]}))
    } else if p.get("relations_off").is_some() {
        KernelError::new(Code::BadField, RELATIONS_OFF).field("kind").expected(json!({"kinds_not_allowed": ["relation"]}))
    } else if p.get("observe_ends").is_some() {
        KernelError::new(Code::BadField, RELATION_ENDS).field("from").expected(json!({"endpoint_kinds": ["claim", "hypothesis", "relation"]}))
    } else if let Some(ids) = p.get("missing_identifiers") {
        KernelError::new(Code::NoEvidence, MISSING_IDENTIFIERS).field("based_on").expected(json!({"missing_identifiers": ids}))
    } else if p.get("negation_before").is_some() || p.get("ends_mid_clause").is_some() {
        let rule = if p.get("negation_before").is_some() { "negation_before" } else { "ends_mid_clause" };
        let mut expected = json!({"rule": rule});
        for k in ["negation_before", "trailing_word", "exact_bytes_in_section", "suggested_span"] {
            if let Some(x) = p.get(k) {
                expected[k] = x.clone();
            }
        }
        if let Some(v) = p.get("exact_bytes_in_section") {
            expected["suggested_exact_quote"] = v.clone();
        }
        KernelError::new(Code::BadField, CLAUSE_NEEDS).field("exact_quote").expected(expected)
    } else {
        let mut e = KernelError::new(Code::BadField, p["needs"].as_str().unwrap_or("refused by the dispatcher")).field("text");
        if let Some(n) = p.get("characters") {
            e = e.expected(json!({"characters": n, "max_characters": SUMMARY_TEXT_CHARS}));
        }
        e
    };
    e.to_json()
}

/// Durable completion of a task: one checkpoint per task key, written with the task's last operations (contract v0.1 R5).
fn task_checkpoint(key: &str) -> String {
    format!("task:{key}")
}

#[derive(Debug, Default, Clone)]
pub struct DispatchStats {
    pub issued: BTreeMap<String, u64>,
    pub committed: u64,
    pub repairs: u64,
    pub expired: u64,
    pub confirmed: u64,
    pub rejected: u64,
    pub waits: u64,
    pub requests_accepted: u64,
    pub requests_refused: u64,
    /// Acquire calls that held back a first reading for the builder's backlog.
    pub paced_skips: u64,
    /// Reading tasks that went on to a RELATE turn (`relate_hints`).
    pub relate_turns: u64,
    /// Per agent, the milliseconds it waited for a task, by why the kernel had none for it: the next task in line for it was
    /// taken, of a kind it does not do, another agent's ring card, closed by the circle phase, an investigation waiting for the
    /// builder, paced, or the check of its own link; no open work at all (others' leases out, the builder behind); a checkpoint,
    /// its exclusion, its own lease, the ring barrier. Never shown to the swarm (02.11.2026: the idle half of the final phase,
    /// explained by its causes). A reason is the first one met, not proven the only one. Closed waits only: a wait counts once
    /// the kernel answers the agent a task or `COMPLETE`, or the run is closed; one still open at a status is not in it.
    pub wait_ms: BTreeMap<String, BTreeMap<String, u64>>,
    /// Per agent, the reason of its open wait and when the kernel answered it.
    waiting: BTreeMap<String, (&'static str, u64)>,
}

impl DispatchStats {
    /// The agent got no task at `now` for `why`: the wait it was in until now counts for its own reason.
    fn wait(&mut self, agent: &str, why: &'static str, now: u64) {
        self.end_wait(agent, now);
        self.waiting.insert(agent.to_string(), (why, now));
    }
    /// The agent got a task or `COMPLETE` at `now`.
    fn end_wait(&mut self, agent: &str, now: u64) {
        if let Some((why, since)) = self.waiting.remove(agent) {
            *self.wait_ms.entry(agent.to_string()).or_default().entry(why.to_string()).or_default() += now.saturating_sub(since);
        }
    }
    /// The run is closed at `now`: no agent is answered again (Codex review 987431f3, WAIT-01).
    pub fn end_waits(&mut self, now: u64) {
        for agent in self.waiting.keys().cloned().collect::<Vec<_>>() {
            self.end_wait(&agent, now);
        }
    }
}

type Work = (TaskKind, String, Option<LinkId>, Option<RecordId>, Option<(String, usize, usize)>);

#[derive(Debug)]
pub struct Dispatcher {
    pub cfg: DispatchConfig,
    build_offer: Vec<super::builder::Card>,
    ring_order: Option<Vec<String>>,
    circle: Option<circles::CircleState>,
    /// Set by the coordinator before it advances the circles: the refiner's cursor reached the head with no open card.
    pub refiner_caught_up: bool,
    ring_batch: Option<u64>,
    ring_ready: BTreeSet<String>,
    ring_started: bool,
    members: circles::members::Membership,
    questions: Vec<ResearchQuestion>,
    leases: BTreeMap<String, Lease>,
    handled: BTreeSet<String>,
    /// Research question -> its accepted outcome.
    answered: BTreeMap<String, Answer>,
    /// Independent rows of an invalidated answer. Derived from the existing answer checkpoint on recovery; never regenerated.
    retained: BTreeMap<String, Answer>,
    /// Distinguishes this dispatcher's task ids from those of another dispatcher on the same state.
    nonce: String,
    /// The store root when this dispatcher issued its first task (or recovered). The root changes with every committed
    /// submission, refusals included (they are receipts), and never repeats; so task ids cut from it differ from every id an
    /// earlier process got a receipt under (contract v0.1 R5).
    epoch: String,
    /// Tasks that checked a link: links touching their records spawn no further checks (contract v0.1 R7, bounded depth).
    link_tasks: BTreeSet<String>,
    /// Tasks that investigated a question: the questions they raise are not investigated in turn (the same bounded depth for
    /// questions; live run 2 spent the swarm on questions about questions before the reports were read).
    followup_tasks: BTreeSet<String>,
    /// Failed leases per key, and the keys given up after MAX_FAILED_LEASES (reported in completion and the terminal receipt).
    failures: BTreeMap<String, u32>,
    pending_agent_failures: Vec<(String, String, String)>,
    unresolved: BTreeSet<String>,
    /// Questions an investigation answered with a claim or a sharper question, and those records: the question stays open for the
    /// summaries while none of them stands (Codex review c78060e, F11; d7d9a49, D07: an observe alone settles nothing, and a
    /// settlement whose records lost their ground no longer holds).
    settled: BTreeMap<String, Vec<RecordId>>,
    /// Keys given up whose durable record is not written yet: given up when a failed lease expired (no store at hand), or whose
    /// write failed; retried at the next call that has the store, each attempt under a new submission id (Codex review d7d9a49,
    /// D06; review of 4381fe7: a failed write on a direct release was forgotten). (key, task id, attempt)
    pending_unresolved: Vec<(String, String, u32)>,
    /// Immutable grant history is separate from live authority. Closures are retried until durable.
    pending_version_closures: BTreeMap<String, (String, u32)>,
    /// Questions the word search of `sections_about` found no section for: given up without a model call, durably, with the reason
    /// NO_SECTION_MATCHED (Codex's analysis of 10A-4, F08: 21 of 41 investigations got nothing to read and 27 calls produced 12
    /// questions). A word search that misses is not proof the corpus lacks the answer (his review of 77a803e, R04).
    no_source: BTreeSet<String>,
    /// The graph builder's accepted requests, `request:<n>` at index n-1, and the tasks issued for them (task id -> n).
    requests: Vec<requests::Request>,
    request_tasks: BTreeMap<String, usize>,
    /// Sections whose first reading lost lines (refused answers, given up), and per first-reading key the records stored over all
    /// its leases and the most lines one answer offered.
    strained: BTreeMap<String, Loss>,
    key_stored: BTreeMap<String, usize>,
    key_offered: BTreeMap<String, usize>,
    seq: u64,
    /// Gap packs completed so far: the order the tier rule reads back (SPEC_V02_GAP_PASS section 4).
    gap_order: u64,
    pub stats: DispatchStats,
}

impl Default for Dispatcher {
    /// A dispatcher without research questions, with its own nonce like any other.
    fn default() -> Dispatcher {
        Dispatcher::new(DispatchConfig::default(), Vec::new())
    }
}

/// Whether `#` opens a section of this document. A Markdown file: yes, and so a name that does not say what it is, as a pinned
/// source's id (`d_<hash>`) does not. In any other text or code file such a line is a comment or an attribute.
fn has_headings(doc: &str) -> bool {
    let name = doc.rsplit('/').next().unwrap_or(doc);
    match name.rsplit_once('.') {
        Some((stem, kind)) if !stem.is_empty() => kind.eq_ignore_ascii_case("md") || kind.eq_ignore_ascii_case("mdx"),
        _ => true,
    }
}

/// Where a piece of plain text ends: after its last blank line, else after its last line. Text from Windows ends a line in `\r\n`.
fn plain_break(piece: &str) -> Option<usize> {
    let blank = piece.rfind("\n\n").map(|p| p + 2).max(piece.rfind("\n\r\n").map(|p| p + 3));
    blank.or_else(|| piece.rfind('\n').map(|p| p + 1))
}

/// The rule `sections` cuts by, pinned with a server's run: 1, a `#` line at a line's start opens a section; 2, not inside a fenced
/// code block (Codex review of 320a04e, HDR-01). A task key names a section by its number, so a run cut by one rule cannot be taken
/// up again by another: its numbers would name other bytes (Codex recheck of baa75e5, HDR-R01).
pub const SECTION_RULE: u64 = 2;

/// Byte ranges of a document cut at headings where it has them, then packed (or split at blank lines / char boundaries) to at most
/// `max`. Task keys hold these section numbers, so every reader of a document's sections comes here, with its name.
pub(crate) fn sections(doc: &str, text: &str, max: usize) -> Vec<(usize, usize)> {
    let max = max.max(64);
    let headings = has_headings(doc);
    let mut starts = vec![0usize];
    // a `#` line inside a fenced block is code, not a heading (Codex review of 320a04e, HDR-01)
    for (at, line, code) in gaps::code_lines(text) {
        if headings && at > 0 && !code && line.starts_with('#') {
            starts.push(at);
        }
    }
    starts.push(text.len());
    let mut raw: Vec<(usize, usize)> = Vec::new();
    for w in starts.windows(2) {
        let (mut a, b) = (w[0], w[1]);
        while b - a > max {
            let mut cut = a + max;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            let end = if headings { text[a..cut].rfind("\n\n").filter(|p| *p > 0).map(|p| p + 2) } else { plain_break(&text[a..cut]) };
            if let Some(end) = end {
                cut = a + end;
            }
            raw.push((a, cut));
            a = cut;
        }
        if b > a {
            raw.push((a, b));
        }
    }
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (a, b) in raw {
        match out.last_mut() {
            Some(last) if b - last.0 <= max => last.1 = b,
            _ => out.push((a, b)),
        }
    }
    out
}

/// The store's (grounded, answer support) flags, read once per dispatcher call: the store derives them from every record, so
/// asking it record by record made each call quadratic (live run 7: a call took over 120 s at about 1200 records).
struct Flags(Option<BTreeMap<RecordId, (bool, bool)>>);

impl Flags {
    fn of<S: AuditStore>(s: &S) -> Flags {
        Flags(s.support_map())
    }
    fn grounded<S: AuditStore>(&self, s: &S, id: &RecordId) -> bool {
        self.0.as_ref().map_or_else(|| s.is_grounded(id), |m| m.get(id).is_some_and(|v| v.0))
    }
    fn support<S: AuditStore>(&self, s: &S, id: &RecordId) -> bool {
        self.0.as_ref().map_or_else(|| s.is_answer_support(id), |m| m.get(id).is_some_and(|v| v.1))
    }
}

/// Whether a record can stand as proof, as the store requires of a link's ends and basis before it accepts the link: grounded,
/// not a hypothesis, question or done, and so is everything it rests on or connects.
fn admissible<S: AuditStore>(s: &S, f: &Flags, id: &RecordId, memo: &mut BTreeMap<RecordId, bool>) -> bool {
    if let Some(v) = memo.get(id) {
        return *v;
    }
    memo.insert(*id, false);
    let ok = s.record(id).is_some_and(|r| {
        f.grounded(s, id)
            && !matches!(r.kind, RecordKind::Hypothesis | RecordKind::Question | RecordKind::Done)
            && r.based_on.iter().all(|b| admissible(s, f, b, memo))
            && r.ends.as_ref().is_none_or(|(a, _, b)| admissible(s, f, a, memo) && admissible(s, f, b, memo))
    });
    memo.insert(*id, ok);
    ok
}

/// The topics of a research question: a text names one when it contains it (whitespace collapsed, any case: agents write topics
/// in their own words, "stale provenance" for the topic "stale").
struct Topics(Vec<String>);

impl Topics {
    fn norm(t: &str) -> String {
        t.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
    }
    fn new(about: &[String]) -> Topics {
        Topics(about.iter().map(|t| Topics::norm(t)).filter(|t| !t.is_empty()).collect())
    }
    fn named(&self, x: &str) -> bool {
        let x = Topics::norm(x);
        self.0.iter().any(|w| x.contains(w.as_str()))
    }
}

/// Whether a directive is a link task (`TV<n>-`: VERIFY_LINK or RESOLVE_CONFLICT). What it records is the evidence of a verdict,
/// not new material: the graph builder does not take it up (live run 10A: link checks wrote 70% of the records, and the builder,
/// linking them in turn, never caught up), and links touching it spawn no checks (contract v0.1 R7).
pub fn is_link_directive(directive: &str) -> bool {
    marked(directive, "TV")
}

/// Whether a directive is a summary (`TS<n>-`): its records answer a research question from what the swarm found; the graph builder
/// does not take them up as new material (live run 10A-4).
pub fn is_summary_directive(directive: &str) -> bool {
    marked(directive, "TS")
}

fn marked(directive: &str, mark: &str) -> bool {
    directive.strip_prefix(mark).and_then(|r| r.split_once('-')).is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A grounded record and every grounded record it rests on or connects (based_on and relation ends, transitively).
fn closure<S: AuditStore>(s: &S, f: &Flags, root: &RecordId) -> BTreeSet<RecordId> {
    let mut out = BTreeSet::new();
    let mut stack = vec![*root];
    while let Some(id) = stack.pop() {
        if out.contains(&id) || !f.grounded(s, &id) {
            continue;
        }
        let Some(r) = s.record(&id) else { continue };
        out.insert(id);
        stack.extend(r.based_on.iter().copied());
        if let Some((a, _, b)) = r.ends {
            stack.extend([a, b]);
        }
    }
    out
}

fn short_list(ids: &[RecordId]) -> Vec<String> {
    ids.iter().map(|i| i.short()).collect()
}

/// The records a SUMMARIZE window shows: retained rows first, then ordinary claims, each unit all or nothing. Without the time
/// option (registry R30 step 2) this is the window as it always was: the retained ids, their units where they fit the configured
/// budget, then ordinary units. With it, the retained rows' whole units (cones and time components) come first and may take the
/// configured budget up to the store's hard bound: a retained old state was shown while its later state did not fit, and a
/// retained row cannot be dropped, since the next done keeps it (Codex 28.10, D07). A retained row whose unit is beyond even that
/// bound is returned as partial, for the task to mark. The units of a repair's live support (`live_support`) come next, each where
/// it fits the same budget, then the ordinary units. Returns the shown records, the ordinary units placed, the partial rows and the
/// indices of the live support placed.
fn place(
    retained: &[(RecordId, BTreeSet<RecordId>)],
    live: &[BTreeSet<RecordId>],
    support: &[BTreeSet<RecordId>],
    soft: usize,
    hard: usize,
    temporal: bool,
) -> (BTreeSet<RecordId>, usize, Vec<RecordId>, Vec<usize>) {
    let mut shown: BTreeSet<RecordId> = retained.iter().map(|(c, _)| *c).collect();
    let mut budget = soft.max(shown.len());
    if temporal {
        let need = retained.iter().flat_map(|(_, u)| u.iter().copied()).chain(shown.iter().copied()).collect::<BTreeSet<_>>().len();
        if need <= hard {
            budget = budget.max(need);
        }
    }
    for (_, whole) in retained {
        if shown.len() + whole.difference(&shown).count() <= budget {
            shown.extend(whole.iter().copied());
        }
    }
    let mut placed = Vec::new();
    for (i, whole) in live.iter().enumerate() {
        if shown.len() + whole.difference(&shown).count() <= budget {
            shown.extend(whole.iter().copied());
            placed.push(i);
        }
    }
    let mut fit = 0usize;
    for whole in support {
        if shown.len() + whole.difference(&shown).count() <= budget {
            shown.extend(whole.iter().copied());
            fit += 1;
        }
    }
    let partial = if temporal { retained.iter().filter(|(_, u)| !u.is_subset(&shown)).map(|(c, _)| *c).collect() } else { vec![] };
    (shown, fit, partial, placed)
}

/// The claims of a repair's live support (`live_support`): at most this many in its window, within the same budget...
const LIVE_SUPPORT: usize = 12;
/// ...and at most this many for one fallen row.
const LIVE_SUPPORT_PER_ROW: usize = 4;

/// The live support of a repair after a withdrawal (the owner's decision of 11.11.2026 on run K02_1_r1: the window chosen by the
/// question alone left out all 12 standing quotes of another page that still carried a fallen conclusion, and the repair dropped
/// it): for each fallen row, the standing claims of the readers most like what it lost by words (`quality::evolution::nearest`,
/// the retrieval of LATER ON THE SAME WORDS, by the row's text and the quotes of it that are gone), taken in turns over the rows,
/// best first, each row at most LIVE_SUPPORT_PER_ROW and all of them at most LIVE_SUPPORT, none twice. A claim on nothing but
/// the standing quotes the repair names under the rows (`named`) takes no place: those quotes are shown anyway. The rows run in
/// id order and each row's claims in its retrieval order, so one state gives one list. Not the near twins of
/// `audit-read fallen`: on K02_1_r1 they pointed to the next passage of the same changelog.
fn live_support<S: AuditStore>(s: &S, fallen: &[Fallen], named: &BTreeSet<RecordId>) -> Vec<RecordId> {
    let rows: Vec<RecordId> = fallen.iter().map(|r| r.id).collect();
    take_in_turns(&super::quality::evolution::nearest(s, &rows, named), LIVE_SUPPORT_PER_ROW, LIVE_SUPPORT)
}

/// From ranked lists, the best of each list in turns: list order within a turn, at most `per` of each list, at most `all`, none twice.
fn take_in_turns(ranked: &[Vec<RecordId>], per: usize, all: usize) -> Vec<RecordId> {
    let mut next = vec![0usize; ranked.len()];
    let mut out: Vec<RecordId> = Vec::new();
    for _ in 0..per {
        for (i, list) in ranked.iter().enumerate() {
            if out.len() == all {
                return out;
            }
            while let Some(c) = list.get(next[i]) {
                next[i] += 1;
                if !out.contains(c) {
                    out.push(*c);
                    break;
                }
            }
        }
    }
    out
}

/// Words by which a claim says that something ended or was replaced (wider than `pairs::change_marker`: the MCP changelogs say
/// "removed" and "deprecated").
const ENDING: &[&str] = &["deprecat", "remov", "replac", "no longer", "supersed", "retire", "dropped", "obsolete", "withdrawn", "eliminat", "moved to"];

/// For each claim a summary may show, the claim of a later report it is most like by words among its nearest (the retrieval of the
/// hint profile, `quality::evolution::related`) that says something ended or was replaced, when there is one: a retrieval, not a
/// relation the swarm accepted. Offline on 31.10, any later claim cost the window 10 to 21 of its 100 claims.
fn later_on_the_same_words<S: AuditStore>(s: &S) -> BTreeMap<RecordId, RecordId> {
    let date = |id: &RecordId| super::quality::evolution::document(s, *id).map(|d| super::quality::evolution::date(s, &d)).unwrap_or_default();
    let ends = |id: &RecordId| s.record(id).and_then(|r| r.text).is_some_and(|t| ENDING.iter().any(|m| t.to_ascii_lowercase().contains(m)));
    let claims: Vec<RecordId> = s.records_since(0).into_iter().filter(|r| r.kind == RecordKind::Claim).map(|r| r.id).collect();
    super::quality::evolution::related(s, &claims, COMPANION_POOL)
        .into_iter()
        .filter_map(|(id, near)| {
            let d = date(&id);
            near.into_iter().find(|n| !d.is_empty() && date(n) > d && ends(n)).map(|n| (id, n))
        })
        .collect()
}

fn rec_line(r: &RecordView) -> String {
    rec_line_dated(r, "")
}

/// A record line whose quote names its report's date (registry R30, step 2): the date of the report's front matter, not an
/// agent's `as_of`. Empty for an undated report.
fn rec_line_dated(r: &RecordView, date: &str) -> String {
    // what an agent stated in its own fields (a date is the agent's `as_of`, not a verified publication date; Codex review c78060e,
    // F10: two decisions dated only there looked alike)
    let extra: String =
        [("subject", "subject"), ("predicate", "predicate"), ("object", "object"), ("as_of", "as of"), ("falsifier", "falsifier"), ("needed", "needed")]
            .iter()
            .filter_map(|(k, label)| {
                r.body.get(*k).filter(|v| !v.is_null()).map(|v| format!("; {label}: {}", v.as_str().map_or_else(|| v.to_string(), str::to_string)))
            })
            .collect();
    let body = match r.kind {
        RecordKind::Observe if !date.is_empty() => {
            format!("[{}, report date {date}] \"{}\"", r.doc_id.as_deref().unwrap_or(""), r.quote.as_deref().unwrap_or(""))
        }
        RecordKind::Observe => format!("[{}] \"{}\"", r.doc_id.as_deref().unwrap_or(""), r.quote.as_deref().unwrap_or("")),
        RecordKind::Relation => r.ends.as_ref().map(|(f, rel, t)| format!("{} {rel} {}", f.short(), t.short())).unwrap_or_default(),
        _ => format!("{}{}{extra}", r.text.as_deref().unwrap_or(""), r.status.as_deref().map(|s| format!(" (stance: {s})")).unwrap_or_default()),
    };
    let basis = if r.based_on.is_empty() { String::new() } else { format!(" <- {}", short_list(&r.based_on).join(", ")) };
    format!("  {} {} by {}: {body}{basis}", r.id.short(), r.kind.name(), r.author)
}

/// Read-only diagnostics of an observe line by the store's own quote rule (`state::quote_span`): the store's refusal with the quote
/// itself, and a hint where it helps. A quote that misses the section only on spacing (a line break inside the phrase) is still
/// refused: nothing is normalized; a multi-line quote whose bytes match is fine.
fn quote_problem<S: AuditStore>(s: &S, scope: &Scope, doc: &str, quote: &str) -> Option<Value> {
    let text = s.doc_text(doc);
    let e = super::state::quote_span(scope, doc, text.as_deref().map(str::as_bytes), quote).err()?;
    let mut p = json!({"doc_id": doc, "exact_quote": quote.chars().take(160).collect::<String>(), "error": e.to_json()});
    match e.code {
        Code::BadField if e.field.as_deref() == Some("doc_id") => {
            p["needs"] = json!(
                "the doc_id of a section of this task: quote only from those sections; a record shown above is cited by \
                                its @id in based_on, not quoted again"
            );
            p["choose_one_of"] = json!(scope.docs);
        }
        Code::QuoteNotFoundInBytes => {
            let squash = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
            let text = text.unwrap_or_default();
            let sections: Vec<&str> = if scope.ranges.is_empty() {
                vec![text.as_str()]
            } else {
                scope.ranges.iter().filter(|(d, _, _)| d == doc).filter_map(|(_, a, b)| text.get(*a..*b)).collect()
            };
            // the one span of the task's sections with the quote's characters, only the spacing between its words other (a line
            // break inside the phrase), shown to be copied and sent again: only when the store's own rule takes those bytes (unique
            // in the whole document, inside the task's ranges; Codex), never accepted in the agent's place (Gemini's 10A-4 audit:
            // blind repeats on line breaks). Every span of every section counts: a section with two is not dropped from the count
            // (Codex's review of 77a803e, R03: one span left in B while A held two is no unique place)
            let candidates: Vec<String> = sections.iter().flat_map(|sec| spaced_matches(sec, quote)).collect();
            if let [exact] = candidates.as_slice() {
                if super::state::quote_span(scope, doc, Some(text.as_bytes()), exact).is_ok() {
                    p["exact_bytes_in_section"] = json!(exact);
                }
            }
            if !quote.trim().is_empty() && sections.iter().any(|sec| squash(sec).contains(&squash(quote))) {
                p["hint"] = json!(
                    "the section has these words with other spacing (a line break inside the phrase): copy the bytes \
                                   exactly, line break included, or quote a part that stands on one line"
                );
            }
        }
        Code::AmbiguousQuoteSpan => {
            p["hint"] = json!(
                "the whole document holds this quote more than once: extend it with neighbouring words, across a line break when \
                               the line itself repeats"
            );
            // live run 10A-6: a report repeats a 139-byte block; extended twice by a line, the quote stayed ambiguous and its 11
            // other lines were lost. The shortest extension inside the task's section that the store's rule takes is shown, to be
            // copied and sent again; the line stays refused
            let text = text.unwrap_or_default();
            let ranges: Vec<(usize, usize)> = if scope.ranges.is_empty() {
                vec![(0, text.len())]
            } else {
                scope.ranges.iter().filter(|(d, _, _)| d == doc).map(|(_, a, b)| (*a, *b)).collect()
            };
            if let Some(longer) = unique_extension(&text, &ranges, quote) {
                if super::state::quote_span(scope, doc, Some(text.as_bytes()), &longer).is_ok() {
                    p["exact_bytes_in_section"] = json!(longer);
                }
            }
        }
        _ => {}
    }
    if let (Some(exact), Some(text)) = (p["exact_bytes_in_section"].as_str(), s.doc_text(doc)) {
        if let Ok(span) = super::state::quote_span(scope, doc, Some(text.as_bytes()), exact) {
            p["suggested_span"] = json!({"doc_id":doc,"start_byte":span.start,"end_byte":span.end});
        }
    }
    Some(p)
}

/// S0 for a quote the store takes: one that cuts a negation off its sentence or ends in the middle of a clause says, alone, other
/// than its source. The whole clause is shown when the store's own rule takes it.
fn clause_problem<S: AuditStore>(s: &S, scope: &Scope, doc: &str, quote: &str) -> Option<Value> {
    let text = s.doc_text(doc)?;
    let at = super::state::quote_span(scope, doc, Some(text.as_bytes()), quote).ok()?;
    // Diagnostics have the same scope as the task: even the negation's lead must not disclose unissued source bytes.
    let (a, b) = scope.ranges.iter().find(|(d, a, b)| d == doc && *a <= at.start && at.end <= *b).map_or((0, text.len()), |(_, a, b)| (*a, *b));
    let section = text.get(a..b)?;
    let negation = super::s0::negation_before(section, at.start - a, quote);
    let cut = super::s0::ends_mid_clause(quote);
    if negation.is_none() && !cut {
        return None;
    }
    let mut p = json!({"doc_id": doc, "exact_quote": quote.chars().take(160).collect::<String>(), "needs": CLAUSE_NEEDS});
    if let Some(lead) = negation {
        p["negation_before"] = json!(lead);
    }
    if cut {
        p["ends_mid_clause"] = json!(true);
        p["trailing_word"] = json!(quote.split_whitespace().last().unwrap_or(""));
    }
    if let Some(whole) = super::s0::whole_clause(section, at.start - a, at.end - a, 0, section.len(), EXTENSION_MAX_BYTES) {
        if super::state::quote_span(scope, doc, Some(text.as_bytes()), &whole).is_ok() {
            let span = super::state::quote_span(scope, doc, Some(text.as_bytes()), &whole).expect("checked suggestion");
            p["exact_bytes_in_section"] = json!(whole);
            p["suggested_span"] = json!({"doc_id":doc,"start_byte":span.start,"end_byte":span.end});
        }
    }
    Some(p)
}

/// What the store would refuse in lines it has not taken, named before they are sent again: each observe's document and quote (by the
/// store's own rule, `quote_problem`), each basis that is not an observe, and each text over its bound. `locals` are the task's
/// accepted local ids, `shown` the records it may cite by @id. Read only: the store still decides what is stored.
pub fn unstored_problems<S: AuditStore>(
    s: &S,
    scope: &Scope,
    locals: &BTreeMap<String, RecordId>,
    shown: &[RecordId],
    lines: &[Value],
    unstored: &[(usize, Value)],
) -> Vec<Value> {
    // Accepted aliases take precedence. Within a batch the first definition binds the name, including a forward reference:
    // store_items topologically orders the DAG and refuses later duplicate definitions without rebinding the first one.
    let kind_of = |n: &str, _before: usize| -> Option<String> {
        if let Some(id) = locals.get(n) {
            return s.record(id).map(|r| r.kind.name().to_string());
        }
        if let Some(l) = lines.iter().find(|l| l.get("local_id").and_then(|x| x.as_str()) == Some(n)) {
            return Some(l.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string());
        }
        shown.iter().find(|r| r.short() == n).and_then(|r| s.record(r)).map(|r| r.kind.name().to_string())
    };
    // the quote a basis name stands for, bound the same way
    let quote_of = |n: &str, _before: usize| -> Option<String> {
        if let Some(id) = locals.get(n) {
            return s.record(id).and_then(|r| r.quote);
        }
        if let Some(l) = lines.iter().find(|l| l.get("local_id").and_then(|x| x.as_str()) == Some(n)) {
            return l.get("exact_quote").and_then(|x| x.as_str()).map(str::to_string);
        }
        shown.iter().find(|r| r.short() == n).and_then(|r| s.record(r)).and_then(|r| r.quote)
    };
    let mut out = Vec::new();
    for (j, v) in unstored {
        let field = |k: &str| v.get(k).and_then(|x| x.as_str());
        let kind = field("kind").unwrap_or("");
        let mut found = Vec::new();
        if kind == "observe" {
            if let (Some(doc), Some(quote)) = (field("doc_id"), field("exact_quote")) {
                match quote_problem(s, scope, doc, quote) {
                    Some(p) => found.push(p),
                    None => found.extend(clause_problem(s, scope, doc, quote)),
                }
            }
        }
        // S0: what a claim names by identifier, its quotes hold (the semantic-verification research, 2026-10-23; Codex's 10A-6
        // analysis: a commit hash named in a claim was in none of its quotes)
        if kind == "claim" {
            let names: Vec<&str> = v.get("based_on").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
            let quotes: Vec<String> = names.iter().filter_map(|n| quote_of(n, *j)).collect();
            let said = ["text", "subject", "object"].into_iter().filter_map(field).collect::<Vec<_>>().join("\n");
            let missing = super::s0::missing_identifiers(&said, &quotes.iter().map(String::as_str).collect::<Vec<_>>());
            if !names.is_empty() && !missing.is_empty() {
                found.push(json!({"needs": MISSING_IDENTIFIERS, "missing_identifiers": missing}));
            }
        }
        if matches!(kind, "claim" | "hypothesis" | "relation") {
            let names: Vec<&str> = v.get("based_on").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
            if names.is_empty() {
                found.push(json!({"needs": "based_on: at least one quote, an observe local_id of this answer or an observe @id shown; if the \
                                            sections do not show it, write a question line instead"}));
            }
            let not_observes: Vec<String> = names.iter().filter_map(|n| kind_of(n, *j).filter(|k| k != "observe").map(|k| format!("{n} is a {k}"))).collect();
            if !not_observes.is_empty() {
                found.push(json!({"needs": "based_on names observe records (quotes) only; records are connected by a relation line's from and to",
                                  "not_observes": not_observes}));
            }
        }
        // the builder's rule A1 for the swarm's relation lines too (Gemini's audit of 10A-9: a worker linked a quote to the claim
        // resting on it, and the check confirmed it)
        if kind == "relation" {
            let ends: Vec<&str> = ["from", "to"].into_iter().filter_map(field).filter(|n| kind_of(n, *j).as_deref() == Some("observe")).collect();
            if !ends.is_empty() {
                found.push(json!({"needs": RELATION_ENDS, "observe_ends": ends}));
            }
        }
        // a done line's text is optional, but bound like the others when given (the offline replay of 10A-3 found it unnamed)
        let bounded = matches!(kind, "claim" | "hypothesis" | "question") || (kind == "done" && v.get("text").is_some());
        if bounded {
            let n = field("text").map_or(0, |t| t.chars().count());
            if n == 0 || n > records::MAX_TEXT_CHARS {
                found.push(json!({"needs": format!("text of 1..{} characters", records::MAX_TEXT_CHARS), "characters": n}));
            }
        }
        for mut p in found {
            p["line"] = json!(j);
            p["local_id"] = v.get("local_id").cloned().unwrap_or(Value::Null);
            out.push(p);
        }
    }
    out
}

/// The bytes of `section` with the words of `quote` in their order, any ASCII spacing between them (space, tab, CR, LF: a line break
/// inside the phrase): every such span. Every other character is the quote's own; the first word may end a longer token and the last
/// begin one, as a quote may cut a word, but no word is extended or corrected. Offsets are the section's UTF-8 bytes.
fn spaced_matches(section: &str, quote: &str) -> Vec<String> {
    let words: Vec<&str> = quote.split_ascii_whitespace().collect();
    if words.len() < 2 {
        return Vec::new();
    }
    let base = section.as_ptr() as usize;
    let tokens: Vec<(usize, &str)> = section.split_ascii_whitespace().map(|w| (w.as_ptr() as usize - base, w)).collect();
    let n = words.len();
    let mut spans = Vec::new();
    for i in 0..tokens.len().saturating_sub(n - 1) {
        let window = &tokens[i..i + n];
        let inner = window[1..n - 1].iter().zip(&words[1..n - 1]).all(|((_, t), w)| t == w);
        if inner && window[0].1.ends_with(words[0]) && window[n - 1].1.starts_with(words[n - 1]) {
            let start = window[0].0 + window[0].1.len() - words[0].len();
            let end = window[n - 1].0 + words[n - 1].len();
            spans.push((start, end));
        }
    }
    spans.iter().filter_map(|(a, b)| section.get(*a..*b).map(str::to_string)).collect()
}

/// Only a single soft newline inside one paragraph/list item is canonicalized automatically. All other whitespace repairs
/// remain explicit hints. Candidate bytes must be unique in the document and inside this lease's issued section ranges.
fn soft_wrap_quote<S: AuditStore>(s: &S, scope: &Scope, doc: &str, quote: &str) -> Option<String> {
    let text = s.doc_text(doc)?;
    if super::state::quote_span(scope, doc, Some(text.as_bytes()), quote).is_ok() {
        return None;
    }
    let fold = |raw: &str| -> Option<String> {
        let mut lines = raw.split('\n');
        let mut out = lines.next()?.trim_end_matches([' ', '\r']).to_string();
        for line in lines {
            let l = line.trim_start_matches([' ', '\t']);
            let n = l.bytes().take_while(u8::is_ascii_digit).count();
            if l.is_empty() || ["#", "- ", "* ", "```", "+++", "|"].iter().any(|p| l.starts_with(p)) || (n > 0 && l[n..].starts_with(". ")) {
                return None;
            }
            out.push(' ');
            out.push_str(l.trim_end_matches([' ', '\r']));
        }
        Some(out)
    };
    let ranges = if scope.ranges.is_empty() { vec![(doc.to_string(), 0, text.len())] } else { scope.ranges.clone() };
    let candidates: Vec<String> = ranges
        .iter()
        .filter(|(d, _, _)| d == doc)
        .filter_map(|(_, a, b)| text.get(*a..*b))
        .flat_map(|sec| spaced_matches(sec, quote))
        .filter(|raw| raw.contains('\n') && fold(raw).as_deref() == Some(quote))
        .filter(|raw| super::state::quote_span(scope, doc, Some(text.as_bytes()), raw).is_ok())
        .collect();
    if let [one] = candidates.as_slice() {
        Some(one.clone())
    } else {
        None
    }
}

/// S0 refusals, each with what the line needs.
const MISSING_IDENTIFIERS: &str = "a claim names only identifiers its quotes hold: add a quote of this section that holds each one listed, \
                                   or leave it out of the claim";
const CLAUSE_NEEDS: &str = "a quote keeps the clause it belongs to: quote from the start of the sentence when it negates what follows, \
                            and to the end of the clause when the quote ends on a word like 'from' or 'with'";

/// What a relation line connects, the builder's rule A1 (builder.rs) for the swarm as well.
const RELATION_ENDS: &str = "a relation connects two claims, hypotheses or relations, never an observe: a quote goes in based_on";

/// The longest extension of an ambiguous quote that is offered (a quote is best one line of at most 200 characters).
const EXTENSION_MAX_BYTES: usize = 300;

/// The shortest extension of `quote` by whole words to the left, the right or both, only inside `ranges` and at most
/// EXTENSION_MAX_BYTES, that occurs once in `text`, when the quote occurs exactly once inside the ranges. Every combination is tried
/// shortest first (Codex's review of d1f2474: growing right and left in turn, a 400-byte word on the right hid a 17-byte unique
/// extension on the left). Words are cut at ASCII spacing, so the bytes stay whole characters.
fn unique_extension(text: &str, ranges: &[(usize, usize)], quote: &str) -> Option<String> {
    if quote.is_empty() {
        return None;
    }
    let inside: Vec<(usize, usize, usize, usize)> = text
        .match_indices(quote)
        .filter_map(|(s, _)| ranges.iter().find(|(a, b)| *a <= s && s + quote.len() <= *b).map(|(a, b)| (s, s + quote.len(), *a, *b)))
        .collect();
    let &[(s, e, a, b)] = inside.as_slice() else { return None };
    let bytes = text.as_bytes();
    let space = |i: usize| bytes[i].is_ascii_whitespace();
    // where the extension may start (word by word to the left) and end (to the right), within the bound
    let mut starts = vec![s];
    let mut x = s;
    while x > a && e - x <= EXTENSION_MAX_BYTES {
        while x > a && space(x - 1) {
            x -= 1;
        }
        while x > a && !space(x - 1) {
            x -= 1;
        }
        starts.push(x);
    }
    let mut ends = vec![e];
    let mut y = e;
    while y < b && y - s <= EXTENSION_MAX_BYTES {
        while y < b && space(y) {
            y += 1;
        }
        while y < b && !space(y) {
            y += 1;
        }
        ends.push(y);
    }
    let mut spans: Vec<(usize, usize)> =
        starts.iter().flat_map(|&l| ends.iter().map(move |&r| (l, r))).filter(|&(l, r)| (l, r) != (s, e) && r - l <= EXTENSION_MAX_BYTES).collect();
    spans.sort_by_key(|&(l, r)| (r - l, l));
    spans.into_iter().filter_map(|(l, r)| text.get(l..r)).find(|longer| text.match_indices(*longer).nth(1).is_none()).map(str::to_string)
}

/// What the swarm already recorded, for a task: claims under `heading`, hypotheses apart (Codex's analysis of 10A-4, F12: hypotheses
/// were shown as established, and "do not repeat" kept agents from testing them).
fn known_block(known: &[RecordView], heading: &str) -> String {
    let (hypotheses, claims): (Vec<&RecordView>, Vec<&RecordView>) = known.iter().partition(|r| r.kind == RecordKind::Hypothesis);
    let lines = |rs: &[&RecordView]| if rs.is_empty() { "  (nothing yet)".to_string() } else { rs.iter().map(|r| rec_line(r)).collect::<Vec<_>>().join("\n") };
    let mut out = format!("{heading}:\n{}", lines(&claims));
    if !hypotheses.is_empty() {
        out.push_str(&format!("\nHYPOTHESES (not established: confirm or refute them only with quotes):\n{}", lines(&hypotheses)));
    }
    out
}

const FORMATS: &str = "Record formats (one JSON object per line, no code fences, nothing else):\n\
  {\"kind\":\"observe\",\"local_id\":\"<prefix>o1\",\"doc_id\":\"...\",\"exact_quote\":\"<copied byte-exactly from the text shown, best a span of ONE line \
  (15..200 characters, long enough to occur once in the section); cross a line break only when the meaning needs it>\",\"terms\":[\"what it is about, your words\"]}\n\
  {\"kind\":\"claim\",\"local_id\":\"<prefix>c1\",\"text\":\"<= 240 chars\",\"subject\":\"...\",\"predicate\":\"...\",\"object\":\"...\",\"stance\":\"reported|confirmed|refuted|qualified|superseded|open|unknown\",\"as_of\":null,\"based_on\":[\"<prefix>o1\"]}\n\
  {\"kind\":\"relation\",\"local_id\":\"<prefix>r1\",\"from\":\"<id>\",\"rel\":\"supports|contradicts|qualifies|supersedes|depends_on\",\"to\":\"<id>\",\"based_on\":[\"...\"]}\n\
  {\"kind\":\"hypothesis\",\"local_id\":\"<prefix>h1\",\"text\":\"...\",\"falsifier\":\"what would refute it\",\"based_on\":[\"...\"]}\n\
  {\"kind\":\"question\",\"local_id\":\"<prefix>q1\",\"text\":\"...\",\"about\":[\"...\"],\"needed\":\"what to check and where\"}\n\
  based_on names observe records (quotes) only: your observe lines of this answer or observe @ids shown here, never a claim, \
  question or hypothesis. A relation connects two claims, hypotheses or relations by from and to, never an observe (a quote goes \
  in based_on); its based_on are the quotes that show the connection. \
  The quotes a claim rests on together name its subject, what is stated of it and its qualifications (a table row with its header \
  if need be); when they do not, narrow the claim or use unknown. \
  as_of is the YYYYMMDD date from which the claim holds as the source states it (a number), or null when the source does not date it. \
  \"Not checked\" is not \"refuted\": use unknown or a question.";
/// What a link check weighs besides the relation's criteria (step 3a of 31.10, Gemini's partial replacement and Claude's basis
/// rule): checkers refused true supersedes when the older claim also gave details of the ended mechanism, and when a claim stood
/// on a weak quote although the section shown held the deciding text.
const VERIFY_SCOPE_RULES: &str = "Each quote shows its report date: the newer conclusion is the one of the later report. supersedes \
  holds when the newer conclusion ends, removes, replaces or deprecates the mechanism the older conclusion states, even when the older \
  one also gives details of that mechanism; when the older conclusion joins two separate mechanisms and the newer ends only one of \
  them, the relation is qualifies, not supersedes. When an end's own quote does not show what decides the link but a section shown \
  here does, write that observe line first and rest the verdict on it.";
/// The sentence of FORMATS about relation lines.
const RELATION_RULE: &str = "A relation connects two claims, hypotheses or relations by from and to, never an observe (a quote goes in \
    based_on); its based_on are the quotes that show the connection. ";
/// Why a relation line is refused in the control profiles.
const RELATIONS_OFF: &str = "relation lines are off in this run (build scope concepts or none): records are not connected; write claims only";

/// The record formats of a task: FORMATS, or without the relation line and its rule when relation lines are off.
fn formats(relation_lines: bool) -> String {
    if relation_lines {
        return format!("{FORMATS} A relation line holds only when its quotes prove it: {}", super::builder::LINK_CRITERIA);
    }
    let lines: Vec<&str> = FORMATS.split('\n').filter(|l| !l.contains("\"kind\":\"relation\"")).collect();
    format!("{} Relation lines are off in this run: write none.", lines.join("\n").replace(RELATION_RULE, ""))
}

impl Dispatcher {
    pub fn new(cfg: DispatchConfig, questions: Vec<ResearchQuestion>) -> Dispatcher {
        static INSTANCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let n = INSTANCES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let seed = format!("{t}:{}:{n}", std::process::id());
        let nonce = crate::hash::to_hex(&crate::hash::sha256(seed.as_bytes()))[..16].to_string();
        Dispatcher {
            cfg,
            build_offer: Vec::new(),
            ring_order: None,
            circle: None,
            refiner_caught_up: false,
            ring_batch: None,
            ring_ready: BTreeSet::new(),
            ring_started: false,
            members: circles::members::Membership::default(),
            questions,
            leases: BTreeMap::new(),
            handled: BTreeSet::new(),
            answered: BTreeMap::new(),
            retained: BTreeMap::new(),
            nonce,
            epoch: String::new(),
            link_tasks: BTreeSet::new(),
            followup_tasks: BTreeSet::new(),
            failures: BTreeMap::new(),
            pending_agent_failures: Vec::new(),
            unresolved: BTreeSet::new(),
            settled: BTreeMap::new(),
            pending_unresolved: Vec::new(),
            pending_version_closures: BTreeMap::new(),
            no_source: BTreeSet::new(),
            requests: Vec::new(),
            request_tasks: BTreeMap::new(),
            strained: BTreeMap::new(),
            key_stored: BTreeMap::new(),
            key_offered: BTreeMap::new(),
            seq: 0,
            gap_order: 0,
            stats: DispatchStats::default(),
        }
    }

    fn expire(&mut self, now: u64) {
        let dead: Vec<String> = self.leases.iter().filter(|(_, l)| now >= l.expires_ms).map(|(k, _)| k.clone()).collect();
        for k in dead {
            if let Some(l) = self.leases.remove(&k) {
                if self.cfg.versions && l.kind == TaskKind::Change {
                    self.pending_version_closures.insert(k.clone(), ("expired".into(), 0));
                }
                let excluded = self.expire_circle_lease(&l.agent, &k, l.kind);
                // a RELATE turn that runs out gives up only the turn: its reading answer is stored
                if l.relate {
                } else if self.cfg.agent_attempts.is_some() {
                    self.pending_agent_failures.push((l.key.clone(), k.clone(), l.agent.clone()));
                } else if l.failed && !excluded {
                    let was = self.unresolved.contains(&l.key);
                    self.note_failure(&l.key);
                    if !was && self.unresolved.contains(&l.key) {
                        self.pending_unresolved.push((l.key.clone(), k.clone(), 0));
                    }
                }
            }
            self.stats.expired += 1;
        }
    }

    /// A lease given back after a refused answer; after MAX_FAILED_LEASES of them its key is unresolved: no longer issued, and
    /// what it would have settled stays unsettled (a link stays proposed and never supports an answer).
    fn note_failure(&mut self, key: &str) {
        let n = self.failures.entry(key.to_string()).or_default();
        *n += 1;
        if *n >= self.cfg.agent_attempts.unwrap_or(MAX_FAILED_LEASES) {
            self.unresolved.insert(key.to_string());
            // a first reading given up after failed leases keeps what it stored and lost: the most damaged sections stay visible
            // to the builder and may be read again (Codex's C17-01)
            if key.starts_with("doc:") {
                let loss = Loss {
                    stored: self.key_stored.get(key).copied().unwrap_or(0),
                    offered: self.key_offered.get(key).copied().unwrap_or(0),
                    refusals: *n,
                    abandoned: true,
                };
                self.strained.insert(key.to_string(), loss);
            }
        }
    }

    /// A question raised under an INVESTIGATE task: its directive carries the `TQ<n>-` mark (or this process issued the task).
    /// A question raised in a link task is not investigated either (F09): it stays open for the summaries.
    fn is_followup(&self, directive: &str) -> bool {
        // nor one raised under a request or its control reading: a request does not spawn work in turn
        self.followup_tasks.contains(directive) || marked(directive, "TQ") || is_link_directive(directive) || requests::from_request(directive)
    }

    /// A research question given up after failed summaries no longer holds the run (Codex review 6d6bcf9, P1: otherwise no summary
    /// is issued and the run waits forever); the terminal receipt reports it as not answered, not as unknown (c78060e, F05).
    fn given_up(&self, q: &ResearchQuestion) -> bool {
        self.unresolved.contains(&format!("rq:{}", q.id))
    }

    fn mark_failed(&mut self, task_id: &str) {
        if let Some(l) = self.leases.get_mut(task_id) {
            // a refused RELATE answer gives nothing of the reading up (its answer is stored)
            l.failed |= !l.relate;
            l.refusals += 1;
        }
    }

    fn taken(&self, key: &str) -> bool {
        self.handled.contains(key) || self.unresolved.contains(key) || self.leases.values().any(|l| l.key == key)
    }

    /// The open work of kinds 1-4 (conflicts, proposed links, questions, uncovered sections), in priority order; keys given up as
    /// unresolved are not open work.
    fn open_work<S: AuditStore>(&self, s: &S, f: &Flags) -> Vec<Work> {
        self.all_work(s, f).into_iter().filter(|w| !self.handled.contains(&w.1) && !self.unresolved.contains(&w.1)).collect()
    }

    /// After a restart: tasks whose completion checkpoint is durable are done; leases are not restored, their work is issued
    /// again (contract v0.1 R5). A research question counts as answered only when its checkpoint binds this question set, the
    /// question, its `done` record and an explicit outcome; anything else (an older format, another question set) reopens it.
    pub fn recover<S: AuditStore>(&mut self, s: &S) {
        self.leases.clear();
        self.pending_version_closures.clear();
        if self.cfg.versions {
            for key in s.checkpoint_keys("version:lease:") {
                let task = key.strip_prefix("version:lease:").expect("filtered prefix");
                if !s.has_checkpoint(&format!("version:closed:{task}")) {
                    self.pending_version_closures.insert(task.into(), ("recovery".into(), 0));
                }
            }
        }
        self.pending_agent_failures.clear();
        if self.cfg.agent_attempts.is_some() {
            self.failures.clear();
            self.unresolved.clear();
            for (key, e) in super::agent_failures::state(s)["work"].as_object().into_iter().flat_map(|m| m.iter()) {
                if key.starts_with("rq:") && e["question_set_revision"] != self.question_set_revision() {
                    continue;
                }
                if let Some(count) = e["failures"].as_u64() {
                    self.failures.insert(key.clone(), (count as u32).saturating_sub(1));
                    self.note_failure(key);
                }
            }
        }
        self.build_offer.clear();
        self.circle = None;
        self.ring_batch = None;
        self.ring_ready.clear();
        self.ring_started = false;
        self.members = circles::members::Membership::default();
        self.answered.clear();
        self.retained.clear();
        self.epoch = crate::hash::to_hex(&s.epoch());
        // the accepted requests first: their keys are work keys too
        self.load_requests(s);
        // every key a task may have completed: the open work, the research questions and every link (a checked link is no
        // longer open work, but its task's records must keep their R7 depth boundary)
        let f = Flags::of(s);
        let mut keys: BTreeSet<String> = self.all_work(s, &f).into_iter().map(|w| w.1).collect();
        // Recover every possible reread key, including completed keys no longer in the open queue.
        for doc in s.docs() {
            for k in 0..sections(&doc, &s.doc_text(&doc).unwrap_or_default(), self.cfg.section_bytes).len() {
                keys.insert(format!("reread:{doc}#{k}"));
            }
        }
        // and every gap pack that completed, with the order of the last one
        keys.extend(s.checkpoint_keys("task:gap").into_iter().map(|k| k["task:".len()..].to_string()));
        self.gap_order =
            s.checkpoint_keys("task:gap").iter().filter_map(|k| s.checkpoint(k).and_then(|c| c["context"]["gap"]["order"].as_u64())).max().map_or(0, |n| n + 1);
        keys.extend(self.questions.iter().map(|q| format!("rq:{}", q.id)));
        keys.extend(s.links().iter().flat_map(|l| [format!("verify:{}", l.id.short()), format!("conflict:{}", l.id.short())]));
        let revision = self.question_set_revision();
        for key in keys {
            let Some(c) = s.checkpoint(&task_checkpoint(&key)) else { continue };
            let ctx = &c["context"];
            if ctx["unresolved"] == true {
                if let Some(loss) = Loss::from_context(ctx).filter(|_| key.starts_with("doc:")) {
                    self.strained.insert(key.clone(), loss);
                }
                // a research question given up under another question set (an edited text or topics) is open again (Codex review
                // c78060e, F05)
                if key.starts_with("rq:") && ctx["question_set_revision"] != revision.as_str() {
                    continue;
                }
                if ctx["reason"] == NO_SECTION_MATCHED {
                    self.no_source.insert(key.clone());
                }
                if let Some(q) = key.strip_prefix("rq:") {
                    let a = &ctx["retained_answer"];
                    if let (Some(done), Some(outcome), Some(ids)) = (
                        a["done"].as_str().and_then(crate::hash::from_hex).map(RecordId),
                        a["outcome"].as_str().filter(|o| OUTCOMES.contains(o)),
                        a["answer_ids"].as_array(),
                    ) {
                        if s.record(&done).is_some_and(|r| r.kind == RecordKind::Done && r.body["rq_id"] == q) {
                            let ids =
                                ids.iter().filter_map(|x| x.as_str().and_then(crate::hash::from_hex).map(RecordId)).filter(|id| f.support(s, id)).collect();
                            let fallen = a["fallen_ids"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|x| x.as_str().and_then(crate::hash::from_hex).map(RecordId))
                                .collect();
                            self.retained.insert(q.to_string(), Answer { done, outcome: outcome.to_string(), ids, fallen });
                        }
                    }
                }
                self.unresolved.insert(key);
                continue;
            }
            if let Some(q) = key.strip_prefix("rq:") {
                let id = |x: &Value| x.as_str().and_then(crate::hash::from_hex).map(RecordId);
                let ids: Option<Vec<RecordId>> = ctx["answer_ids"].as_array().and_then(|a| a.iter().map(id).collect());
                let outcome = ctx["outcome"].as_str().filter(|o| OUTCOMES.contains(o));
                match (ids, outcome, id(&ctx["done"])) {
                    (Some(ids), Some(outcome), Some(done)) if ctx["rq_id"] == q && ctx["question_set_revision"] == revision.as_str() => {
                        self.answered.insert(q.to_string(), Answer { done, outcome: outcome.to_string(), ids, fallen: Vec::new() });
                    }
                    _ => continue,
                }
            }
            if let Some(t) = ctx["link_task"].as_str() {
                self.link_tasks.insert(t.to_string());
            }
            if let (Some("INVESTIGATE"), Some(t)) = (ctx["kind"].as_str(), ctx["task_id"].as_str()) {
                self.followup_tasks.insert(t.to_string());
            }
            if let (Some("REQUEST"), Some(t), Some(n)) = (ctx["kind"].as_str(), ctx["task_id"].as_str(), requests::request_number(&key)) {
                self.request_tasks.insert(t.to_string(), n);
            }
            if let Some(loss) = Loss::from_context(ctx).filter(|_| ctx["kind"] == "EXTEND") {
                self.strained.insert(key.clone(), loss);
            }
            if let Some(ids) = ctx["settled"].as_array() {
                let ids: Vec<RecordId> = ids.iter().filter_map(|x| x.as_str().and_then(crate::hash::from_hex).map(RecordId)).collect();
                if !ids.is_empty() {
                    self.settled.insert(key.clone(), ids);
                }
            }
            self.handled.insert(key);
        }
        self.revalidate(s, &f);
    }

    fn all_work<S: AuditStore>(&self, s: &S, f: &Flags) -> Vec<Work> {
        let mut out: Vec<Work> = Vec::new();
        let from_check = |r: &RecordId| s.record(r).is_some_and(|x| self.link_tasks.contains(&x.directive) || is_link_directive(&x.directive));
        let mut memo = BTreeMap::new();
        // a link whose basis a request is looking for is checked once the request is done, with what it found
        let awaiting = self.links_awaiting_requests();
        for l in s.links() {
            if l.status == LinkStatus::Rejected || from_check(&l.from) || from_check(&l.to) {
                continue;
            }
            // a link whose ends or basis cannot stand as proof can never be accepted: checking it would loop (live run 2)
            if ![l.from, l.to].iter().chain(&l.basis).all(|r| admissible(s, f, r, &mut memo)) {
                continue;
            }
            if l.rel == "contradicts" {
                out.push((TaskKind::ResolveConflict, format!("conflict:{}", l.id.short()), Some(l.id), None, None));
            } else if l.status == LinkStatus::Proposed && !awaiting.contains(&l.id) {
                out.push((TaskKind::VerifyLink, format!("verify:{}", l.id.short()), Some(l.id), None, None));
            }
        }
        for id in super::quality::stale::suspects(s) {
            let a = super::quality::annotate(s, id);
            let hash = crate::hash::to_hex(&crate::hash::sha256(crate::jcs::to_jcs(&a).as_bytes()));
            for section in super::quality::stale::later_sections(s, id, self.cfg.section_bytes) {
                let key = format!("stale:{}:{}:{}#{}", id.short(), &hash[..16], section.0, section.1);
                out.push((TaskKind::Investigate, key, None, Some(id), Some(section)));
            }
        }
        out.extend(self.request_work(s));
        if self.cfg.versions {
            out.extend(
                super::versions::cards(s).iter().map(|c| (TaskKind::Change, format!("change:{}", c["id"].as_str().expect("computed card")), None, None, None)),
            );
        }
        out.extend(self.auto_reread_work(s));
        out.extend(self.gap_work(s));
        // the questions alone (01.11.2026 scaling stand: a copy of every record to find them was 5.9 ms of each of the four
        // computations of the work per task acquire at 4 600 records)
        for r in s.records_of_kind(RecordKind::Question).into_iter().filter(|r| !self.is_followup(&r.directive)) {
            out.push((TaskKind::Investigate, format!("question:{}", r.id.short()), None, Some(r.id), None));
        }
        // a zone is read whole by one task, and its documents get no section tasks (run S1.2)
        for n in 0..self.cfg.zones.len() {
            out.push((TaskKind::Extend, format!("zone:{n}"), None, None, Some((format!("zone:{n}"), 0, 0))));
        }
        for d in s.docs() {
            if self.cfg.zones.iter().flatten().any(|z| *z == d) {
                continue;
            }
            let text = s.doc_text(&d).unwrap_or_default();
            for (k, (a, b)) in sections(&d, &text, self.cfg.section_bytes).into_iter().enumerate() {
                out.push((TaskKind::Extend, format!("doc:{d}#{k}"), None, None, Some((d.clone(), a, b))));
            }
        }
        out.sort_by_key(|w| (!w.1.starts_with("stale:"), w.0));
        out
    }

    /// An answer holds on the current state while its `done` record names this question and each answer record is still answer
    /// support (a revoked quote, a changed source or a rejected link takes it away). `unknown` without records is an honest outcome.
    fn answer_holds<S: AuditStore>(s: &S, f: &Flags, q: &str, a: &Answer) -> bool {
        s.record(&a.done).is_some_and(|d| d.kind == RecordKind::Done && d.body["rq_id"] == q) && a.ids.iter().all(|i| f.support(s, i))
    }

    /// Reopen research questions whose answer no longer holds (contract v0.1 R7).
    fn revalidate<S: AuditStore>(&mut self, s: &S, f: &Flags) {
        let stale: Vec<String> = self.answered.iter().filter(|(q, a)| !Self::answer_holds(s, f, q, a)).map(|(q, _)| q.clone()).collect();
        for q in stale {
            if let Some(mut a) = self.answered.remove(&q) {
                a.settle(s, f);
                if !a.ids.is_empty() {
                    self.retained.insert(q.clone(), a);
                }
            }
            self.handled.remove(&format!("rq:{q}"));
        }
        for a in self.retained.values_mut() {
            a.settle(s, f);
        }
    }

    /// The rows of a question's answer that no longer stand, with what stands under each.
    fn fallen_rows<S: AuditStore>(&self, s: &S, f: &Flags, q: &str) -> Vec<Fallen> {
        let Some(a) = self.retained.get(q).or_else(|| self.answered.get(q)) else { return Vec::new() };
        let ids: BTreeSet<RecordId> = a.fallen.iter().chain(&a.ids).filter(|id| !f.support(s, id)).copied().collect();
        ids.into_iter()
            .map(|id| {
                let quotes = super::pairs::cone(s, &[id]).into_iter().filter(|r| r.kind == RecordKind::Observe);
                let (standing, gone): (Vec<RecordView>, Vec<RecordView>) = quotes.partition(|o| f.grounded(s, &o.id));
                Fallen { id, standing, gone: gone.len() }
            })
            .collect()
    }

    /// The most lines a repair naming fallen rows takes: its claims and the done line. None for any other summary.
    fn repair_lines<S: AuditStore>(&self, s: &S, f: &Flags, q: &str) -> Option<usize> {
        if self.retained_ids(s, q).is_empty() {
            return None;
        }
        let fallen = self.fallen_rows(s, f, q);
        (!fallen.is_empty()).then(|| repair_claims(&fallen) + 1)
    }

    fn retained_ids<S: AuditStore>(&self, s: &S, q: &str) -> Vec<RecordId> {
        let f = Flags::of(s);
        if self.answered.get(q).is_some_and(|a| Self::answer_holds(s, &f, q, a)) && !self.retained.contains_key(q) {
            return Vec::new();
        }
        let mut ids: Vec<RecordId> = self
            .retained
            .get(q)
            .or_else(|| self.answered.get(q).filter(|a| !Self::answer_holds(s, &f, q, a)))
            .map(|a| a.ids.iter().copied().filter(|id| f.support(s, id)).collect())
            .unwrap_or_default();
        // A coverage repair has no accepted done record yet. Its prefix is retained by an ordinary coordinator checkpoint,
        // bound to this question set, so reopening the WAL can issue only the missing part without inventing a terminal answer.
        if let Some(c) = s.checkpoint(&format!("summary-prefix:{q}")) {
            let ctx = &c["context"];
            if ctx["question_set_revision"] == self.question_set_revision() {
                for id in ctx["answer_ids"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(RecordId)) {
                    if !ids.contains(&id) && f.support(s, &id) && s.record(&id).is_some_and(|r| matches!(r.kind, RecordKind::Claim | RecordKind::Relation)) {
                        ids.push(id);
                    }
                }
            }
        }
        ids
    }

    fn missing_summary_reports<S: AuditStore>(s: &S, issued: &[RecordId], answers: &[RecordId]) -> Vec<String> {
        let f = Flags::of(s);
        let required: BTreeSet<String> = issued
            .iter()
            .filter(|id| f.support(s, id))
            .filter_map(|id| s.record(id))
            .filter(|r| r.kind == RecordKind::Observe)
            .filter_map(|r| r.doc_id)
            .collect();
        let covered: BTreeSet<String> = super::pairs::cone(s, answers).into_iter().filter_map(|r| r.doc_id).collect();
        required.difference(&covered).cloned().collect()
    }

    /// The server offers the one open builder card only when the dynamic-role queue policy permits it.
    /// Nothing is offered in the legacy mode; offers and leases are deliberately ephemeral.
    pub fn prepare_build<S: AuditStore>(&mut self, s: &S, builder: &mut super::builder::Builder, threshold: usize) {
        let ready = builder.backlog(s) >= threshold || self.reading_done(s);
        self.build_offer = if ready { builder.next_card(s).into_iter().collect() } else { Vec::new() };
    }

    /// Route requests and operations identically for both builder modes; preserve indexes of the complete answer.
    pub fn submit_builder_ops<S: AuditStore>(
        &mut self,
        s: &mut S,
        builder: &mut super::builder::Builder,
        card: &str,
        ops: &[Value],
        executor: Option<&str>,
    ) -> Value {
        let (asks, rest): (Vec<(usize, Value)>, Vec<(usize, Value)>) = ops.iter().cloned().enumerate().partition(|(_, o)| o["op"] == "request");
        if asks.is_empty() {
            return builder.submit_as(s, card, ops, executor);
        }
        let requests = if builder.open_card_id() == Some(card) {
            self.builder_requests(s, card, &asks)
        } else {
            // a retried answer of a closed card: its requests accepted before get their acceptance again (Codex's C17-02)
            asks.iter()
                .map(|(i, o)| match self.replay_request(s, card, o) {
                    Some(mut ack) => {
                        ack["index"] = json!(i);
                        ack
                    }
                    None => json!({"index": i, "local_id": o.get("local_id"), "status": "refused",
                               "error": {"code": "UNKNOWN_CARD", "message": format!("'{card}' is not the open card")}}),
                })
                .collect()
        };
        let index: Vec<usize> = rest.iter().map(|(i, _)| *i).collect();
        let operations: Vec<Value> = rest.into_iter().map(|(_, o)| o).collect();
        let mut out = builder.submit_as(s, card, &operations, executor);
        let at = |v: &Value| v.as_u64().and_then(|i| index.get(i as usize)).map(|j| json!(j));
        if out["code"] != "TOO_MANY_OPS" {
            if let Some(j) = at(&out["failed_index"]) {
                out["failed_index"] = j;
            }
        }
        if let Some(refused) = out["refused"].as_array_mut() {
            for x in refused {
                if let Some(j) = at(&x["index"]) {
                    x["index"] = j;
                }
            }
        }
        out["requests"] = json!(requests);
        out
    }

    pub fn offer_builds(&mut self, cards: Vec<super::builder::Card>) {
        self.build_offer = cards;
    }

    pub fn build_card_id(&self, task: &str) -> Option<&str> {
        self.leases.get(task).filter(|l| l.kind == TaskKind::Build).and_then(|l| l.key.strip_prefix("build:"))
    }

    pub fn is_build(&self, task_id: &str) -> bool {
        self.leases.get(task_id).is_some_and(|l| l.kind == TaskKind::Build)
    }

    /// Apply only operations of the authenticated agent's live BUILD lease. The builder keeps its existing
    /// durable operation slots and cursor; its atomic close checkpoint names this agent.
    pub fn submit_build<S: AuditStore>(
        &mut self,
        s: &mut S,
        builder: &mut super::builder::Builder,
        task_id: &str,
        agent: &str,
        ops: &[Value],
        now: u64,
    ) -> Value {
        self.expire(now);
        let Some(lease) = self.leases.get(task_id).cloned() else {
            return json!({"status":"STALE_TASK","task_id":task_id});
        };
        if lease.agent != agent {
            return json!({"status":"error","code":"TASK_NOT_OWNED","task_id":task_id});
        }
        if lease.kind != TaskKind::Build {
            return json!({"status":"error","code":"NOT_BUILD_TASK","task_id":task_id});
        }
        let card_id = lease.key.strip_prefix("build:").expect("build work key");
        let Some(card) = builder.next_card(s).filter(|c| c.card_id == card_id) else {
            return json!({"status":"STALE_TASK","task_id":task_id});
        };
        if card.records.iter().any(|r| r.author == agent) {
            return json!({"status":"error","code":"BUILD_AUTHOR","task_id":task_id});
        }
        self.received_response(task_id, now);
        if self.cfg.circles.is_some() {
            builder.execution_step(self.members.epoch);
        }
        let mut out = self.submit_builder_ops(s, builder, card_id, ops, Some(agent));
        out["task_id"] = json!(task_id);
        if out["status"] == "CARD_DONE" {
            self.leases.remove(task_id);
            self.handled.insert(lease.key.clone());
            self.build_offer.retain(|c| c.card_id != card_id);
            self.stats.committed += 1;
        } else if out["status"] == "REPAIR_REQUIRED" {
            self.stats.repairs += 1;
        }
        out
    }

    /// Lease the most urgent free work to `agent`: `DIRECTIVE`, `WAIT` (work exists but is leased, or a summary waits for the
    /// builder) or `COMPLETE`.
    pub fn acquire<S: AuditStore>(&mut self, s: &S, agent: &str, builder_caught_up: bool, now: u64) -> Value {
        self.acquire_paced(s, agent, builder_caught_up, None, now)
    }

    /// `acquire` with the graph builder's backlog (records after its cursor it has not carded yet), when backpressure is on: a first
    /// reading waits while the backlog and the readings in flight would exceed the bound. `None` holds nothing back (off, or the
    /// builder stalled).
    pub fn acquire_paced<S: AuditStore>(&mut self, s: &S, agent: &str, builder_caught_up: bool, backlog: Option<usize>, now: u64) -> Value {
        self.acquire_for(s, agent, builder_caught_up, backlog, None, now)
    }

    /// `acquire_paced` for an agent that does only the given kinds of task (`None`: any). A single strong reader writes every
    /// claim, so it can check no link between them: a second agent checks the links and does nothing else (one
    /// strong model in place of the swarm).
    pub fn acquire_for<S: AuditStore>(
        &mut self,
        s: &S,
        agent: &str,
        builder_caught_up: bool,
        backlog: Option<usize>,
        kinds: Option<&[TaskKind]>,
        now: u64,
    ) -> Value {
        let allowed = |k: TaskKind| kinds.is_none_or(|ks| ks.contains(&k));
        self.expire(now);
        if self.membership_pending() {
            self.stats.wait(agent, "membership_checkpoint", now);
            return json!({"status":"WAIT","message":"membership checkpoint pending"});
        }
        if !self.pending_agent_failures.is_empty() {
            self.stats.wait(agent, "agent_failure_checkpoint", now);
            return json!({"status":"WAIT","message":"agent failure checkpoint pending"});
        }
        self.member_contact(agent, now);
        if self.members.excluded.contains(agent) {
            self.members.returned.insert(agent.to_string());
            self.stats.wait(agent, "excluded", now);
            return json!({"status":"WAIT","message":"excluded: fresh readiness queued for next shift"});
        }
        if self.cfg.circles.is_some() && self.leases.values().any(|l| l.agent == agent) {
            self.stats.wait(agent, "own_lease", now);
            return json!({"status":"WAIT","message":"one active lease per circle agent"});
        }
        if !self.arrive_at_ring(agent) {
            self.stats.wait(agent, "ring_barrier", now);
            return json!({"status":"WAIT","message":"waiting for every ring reader at the shift barrier"});
        }
        let f = Flags::of(s);
        self.revalidate(s, &f);
        let mut work = self.open_work(s, &f);
        for card in self.build_offer.iter().filter(|c| c.records.iter().all(|r| r.author != agent)) {
            let key = format!("build:{}", card.card_id);
            let at = work.iter().position(|w| w.0 == TaskKind::Extend).unwrap_or(work.len());
            work.insert(at, (TaskKind::Build, key, None, None, None));
        }
        let mut pick = None;
        // variant D: questions are investigated once every section is read and the builder has
        // caught up, so an investigation sees the whole corpus in the graph
        let reading = work.iter().any(|w| w.0 == TaskKind::Extend);
        // the first reader of an idle builder is never held, so a misconfigured bound cannot stop the run
        let (bound, per) = (self.cfg.backpressure_records, self.cfg.backpressure_per_task);
        let in_flight = self.leases.values().filter(|l| l.kind == TaskKind::Extend).count();
        let held = backlog.filter(|_| bound > 0).is_some_and(|b| (b > 0 || in_flight > 0) && b + per * (in_flight + 1) > bound);
        let mut paced = false;
        // why the first task in line for this agent was not its own
        let mut blocked = None;
        for (kind, key, link, question, section) in &work {
            // a second reader no reader may ever be is given up, the need of an independent reader on the record (GAP-03)
            if *kind == TaskKind::Request && !self.taken(key) && self.gap_without_reader(s, key) {
                self.unresolved.insert(key.clone());
                self.pending_unresolved.push((key.clone(), format!("noreader-{key}"), 0));
                continue;
            }
            let skip = if self.taken(key) {
                Some("taken")
            } else if !allowed(*kind) {
                Some("kind_not_its_own")
            } else if !self.circle_allows(*kind, key, agent) {
                Some(if *kind == TaskKind::Build { "ring_card_of_another" } else { "circle_phase" })
            } else if !self.gap_allows(s, key, agent) {
                Some("gap_second_reader_of_another")
            } else if *kind == TaskKind::Investigate && !key.starts_with("stale:") && (reading || !builder_caught_up) {
                Some("investigation_waits_for_builder")
            } else if *kind == TaskKind::Extend && held {
                paced = true;
                Some("paced")
            } else {
                None
            };
            if let Some(why) = skip {
                blocked.get_or_insert(why);
                continue;
            }
            // a question the word search finds no section for is an honest outcome, not a task (it stays open for the summaries)
            if let Some(q) = question.filter(|_| *kind == TaskKind::Investigate && !key.starts_with("stale:")) {
                if s.record(&q).is_some_and(|r| self.sections_about(s, &self.question_terms(s, &r)).is_empty()) {
                    self.no_source.insert(key.clone());
                    self.unresolved.insert(key.clone());
                    self.pending_unresolved.push((key.clone(), format!("nosource-{key}"), 0));
                    continue;
                }
            }
            // a link is checked by an agent that wrote neither end
            if let Some(l) = link.and_then(|l| s.link(&l)) {
                let authors: Vec<String> = [l.from, l.to].iter().filter_map(|r| s.record(r)).map(|r| r.author).collect();
                if authors.iter().any(|a| a == agent) || (self.cfg.versions && l.by == agent) {
                    blocked.get_or_insert("own_link");
                    continue;
                }
            }
            pick = Some((*kind, key.clone(), *link, *question, section.clone()));
            break;
        }
        if pick.is_none() && work.is_empty() && builder_caught_up && allowed(TaskKind::Summarize) && self.circles_final() {
            pick = self
                .questions
                .iter()
                .find(|q| !self.answered.contains_key(&q.id) && !self.taken(&format!("rq:{}", q.id)))
                .map(|q| (TaskKind::Summarize, format!("rq:{}", q.id), None, None, None));
        }
        if paced && pick.is_none() {
            self.stats.paced_skips += 1;
        }
        let Some((kind, key, link, question, section)) = pick else {
            let complete = self.circles_final()
                && work.is_empty()
                && builder_caught_up
                && self.leases.is_empty()
                && self.questions.iter().all(|q| self.answered.contains_key(&q.id) || self.given_up(q));
            if complete {
                // work reopened later is a new wait, not this one (Codex review 987431f3, WAIT-01)
                self.stats.end_wait(agent, now);
                return json!({"status": "COMPLETE"});
            }
            self.stats.waits += 1;
            let why = blocked.unwrap_or(if !self.leases.is_empty() {
                "others_working"
            } else if !builder_caught_up {
                "builder_behind"
            } else {
                "no_open_work"
            });
            self.stats.wait(agent, why, now);
            return json!({"status": "WAIT", "open_work": work.len(), "leases": self.leases.len(), "builder_caught_up": builder_caught_up});
        };
        self.stats.end_wait(agent, now);
        self.seq += 1;
        if self.epoch.is_empty() {
            self.epoch = crate::hash::to_hex(&s.epoch());
        }
        let h = crate::hash::sha256(crate::jcs::to_jcs(&json!(["r2r-task/1", self.nonce, self.epoch, self.seq])).as_bytes());
        // an INVESTIGATE task id says so (`TQ<n>-`): the questions it raises are follow-ups by their own directive, also after a
        // restart and when the task never completed (Codex review 6d6bcf9, P2); a link task id too (`TV<n>-`): what it records is
        // the evidence of a verdict, not material for the graph builder
        // a request task `TR<n>-`, its control reading `TC<n>-`: what they write is told apart from the first reading
        let mark = match kind {
            TaskKind::Investigate => "TQ",
            TaskKind::VerifyLink | TaskKind::ResolveConflict => "TV",
            TaskKind::Summarize => "TS",
            TaskKind::Build => "TB",
            TaskKind::Change => "TD",
            TaskKind::Request if key.starts_with("control:") => "TC",
            TaskKind::Request if key.starts_with("gap") => "TG",
            TaskKind::Request => "TR",
            _ => "T",
        };
        let task_id = format!("{mark}{}-{}", self.seq, &crate::hash::to_hex(&h)[..16]);
        let prefix = format!("t{}_", self.seq);
        let (prompt, scope, issued) = match kind {
            TaskKind::Change => {
                let card = super::versions::cards(s).into_iter().find(|c| c["id"] == key[7..]).expect("mapped CHANGE");
                super::versions::prompt(s, &card)
            }
            TaskKind::Build => {
                let card = self.build_offer.iter().find(|c| key == format!("build:{}", c.card_id)).expect("offered build card");
                (card.prompt(), Scope::default(), card.records.iter().chain(&card.neighbors).map(|r| r.id).collect())
            }
            TaskKind::Extend => self.extend_prompt(s, &f, section.as_ref().expect("an EXTEND task has a section")),
            TaskKind::Investigate if key.starts_with("stale:") => {
                super::quality::stale::investigation_section(s, question.expect("stale target"), section.as_ref().expect("stale section"))
            }
            TaskKind::Investigate => self.investigate_prompt(s, &f, question.expect("an INVESTIGATE task has a question")),
            TaskKind::VerifyLink | TaskKind::ResolveConflict => self.link_prompt(s, &f, kind, link.expect("a link task has a link")),
            TaskKind::Request if key.starts_with("reread:") => self.auto_reread_prompt(s, &f, &key),
            TaskKind::Request if key.starts_with("gap") => self.gap_prompt(s, &key),
            TaskKind::Request => self.request_prompt(s, &f, &key),
            TaskKind::Summarize => self.summarize_prompt(s, &f, &key[3..], &task_id),
        };
        if let Some(n) = requests::request_number(&key).filter(|_| kind == TaskKind::Request) {
            self.request_tasks.insert(task_id.clone(), n);
        }
        let own_run = if self.cfg.own_refs {
            s.records_since(0)
                .into_iter()
                .filter(|r| r.author == agent && matches!(r.kind, RecordKind::Observe | RecordKind::Claim | RecordKind::Hypothesis) && f.grounded(s, &r.id))
                .map(|r| r.id)
                .collect()
        } else {
            Vec::new()
        };
        let repair_lines = key.strip_prefix("rq:").filter(|_| kind == TaskKind::Summarize).and_then(|q| self.repair_lines(s, &f, q));
        let lease = Lease {
            agent: agent.to_string(),
            kind,
            key: key.clone(),
            scope,
            expires_ms: now + self.lease_ms_for(kind),
            link,
            link_status: link.and_then(|l| s.link(&l)).map(|l| l.status),
            question: key.strip_prefix("rq:").map(str::to_string),
            issued,
            own_run,
            attempt: 0,
            own: Vec::new(),
            locals: BTreeMap::new(),
            line_digests: BTreeMap::new(),
            failed: false,
            refusals: 0,
            relate: false,
            repair_lines,
        };
        *self.stats.issued.entry(kind.name().to_string()).or_default() += 1;
        if kind == TaskKind::Investigate {
            // from the moment it is issued: its questions are follow-ups even if the task never completes
            self.followup_tasks.insert(task_id.clone());
        }
        self.leases.insert(task_id.clone(), lease);
        if kind == TaskKind::Build {
            let card = self.build_offer.iter().find(|c| key == format!("build:{}", c.card_id)).expect("offered build card");
            return self.circle_tag(json!({"status":"DIRECTIVE","task_id":task_id,"kind":"BUILD","key":key,"agent_id":agent,
                "expires_at_ms":now+self.lease_ms(),"prompt":prompt,"card_id":card.card_id,"card":card.to_json(),"ring_batch":self.ring_batch}));
        }
        let max_lines = repair_lines.unwrap_or_else(|| self.max_lines(kind));
        // a relation line becomes a link the swarm checks, by the builder's criteria (live run 10A-6: 10 of 28 checked links came
        // from relation lines, which were not told them)
        let link_authors = if self.cfg.circles.is_some() {
            link.and_then(|id| s.link(&id)).map(|l| [l.from, l.to].iter().filter_map(|id| s.record(id)).map(|r| r.author).collect::<BTreeSet<_>>())
        } else {
            None
        };
        let mut out =
            self.circle_tag(json!({"status": "DIRECTIVE", "task_id": task_id, "kind": kind.name(), "key": key, "agent_id": agent, "local_id_prefix": prefix,
               "expires_at_ms": now + self.lease_ms_for(kind), "max_lines": max_lines,
               "retained_answer_ids": if kind == TaskKind::Summarize { short_list(&self.retained_ids(s, &key[3..])) } else { vec![] },
               "prompt": format!("You are one agent of an audit swarm over {corpus}. You are stateless: this directive is all \
                                 you get. Answer with at most {max_lines} JSON lines; every local_id starts with {prefix}.\n\n{prompt}\n\n{}",
                                 formats(self.cfg.relation_lines || (self.cfg.versions && kind == TaskKind::Change)), corpus = self.cfg.corpus)}));
        if self.cfg.versions && kind == TaskKind::Summarize {
            let prompt = out["prompt"].as_str().unwrap_or_default().to_string();
            out["prompt"] = json!(prompt + &super::versions::uncertainty(s));
        }
        if let Some(authors) = link_authors {
            out["link_authors"] = json!(authors);
        }
        out
    }

    /// Called before publishing a CHANGE directive. The agent receives only a task id, never a writable origin capability.
    pub fn persist_change_lease<S: AuditStore>(&mut self, s: &mut S, task: &str) -> Result<(), KernelError> {
        let result = self.persist_version_closures(s).and_then(|_| self.persist_change_lease_inner(s, task));
        if result.is_err() {
            // Nothing was published to the caller: do not strand the work under an invisible lease.
            self.leases.remove(task);
        }
        result
    }

    pub fn persist_version_closures<S: AuditStore>(&mut self, s: &mut S) -> Result<(), KernelError> {
        let pending = self.pending_version_closures.clone();
        for (task, (reason, attempt)) in pending {
            let key = format!("version:closed:{task}");
            if !s.has_checkpoint(&key) && s.has_checkpoint(&format!("version:lease:{task}")) {
                // A refused coordinator submission has a receipt too: retry under a fresh id.
                self.pending_version_closures.insert(task.clone(), (reason.clone(), attempt + 1));
                let result =
                    s.submit_operations_id(&format!("{key}#{attempt}"), "kernel", &[], Some(json!({"key":key,"from":0,"to":0,"context":{"reason":reason}})))?;
                if result["checkpointed"] != true || !result["error"].is_null() {
                    return Err(KernelError::new(Code::BadField, format!("CHANGE grant closure is not durable: {result}")));
                }
            }
            self.pending_version_closures.remove(&task);
        }
        Ok(())
    }

    fn persist_change_lease_inner<S: AuditStore>(&self, s: &mut S, task: &str) -> Result<(), KernelError> {
        let Some(lease) = self.leases.get(task).filter(|l| l.kind == TaskKind::Change && self.cfg.versions) else { return Ok(()) };
        let card = super::versions::cards(s)
            .into_iter()
            .find(|c| c["id"] == lease.key[7..])
            .ok_or_else(|| KernelError::new(Code::BadField, "CHANGE card is absent from the pinned map"))?;
        if lease.scope != super::versions::card_scope(&card) {
            return Err(KernelError::new(Code::BadField, "CHANGE scope differs from its pinned card"));
        }
        let key = format!("version:lease:{task}");
        if s.has_checkpoint(&format!("version:closed:{task}")) {
            return Err(KernelError::new(Code::BadField, "CHANGE grant is already closed"));
        }
        let context = json!({"agent":lease.agent,"card":card["id"]});
        if let Some(old) = s.checkpoint(&key) {
            return if old["context"] == context { Ok(()) } else { Err(KernelError::new(Code::BadField, "CHANGE lease changed")) };
        }
        let result = s.submit_operations_id(&key, "kernel", &[], Some(json!({"key":key,"from":0,"to":0,"context":context})))?;
        if result["checkpointed"] != true || !result["error"].is_null() {
            return Err(KernelError::new(Code::BadField, format!("CHANGE lease could not be persisted: {result}")));
        }
        Ok(())
    }

    fn max_lines(&self, kind: TaskKind) -> usize {
        if kind == TaskKind::Summarize {
            self.cfg.summary_lines
        } else {
            self.cfg.max_lines
        }
    }

    /// Claims the swarm already holds about these terms or this document (shown so nobody repeats them).
    fn known<S: AuditStore>(&self, s: &S, f: &Flags, terms: &[String], doc: Option<&str>) -> Vec<RecordView> {
        let mut ids: BTreeSet<RecordId> = BTreeSet::new();
        for t in terms {
            for c in s.candidates(t, 4) {
                ids.extend(s.records_of(&c.id));
            }
        }
        let all = s.records_since(0);
        // records whose own terms or text name the topic, and the ends of accepted links among them (before or without a
        // mapping). Agents write terms in their own words ("stale provenance" for the topic "stale"): a topic matches inside them.
        let norm = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        let wanted: BTreeSet<String> = terms.iter().map(|t| norm(t)).filter(|t| !t.is_empty()).collect();
        let names = |x: &str| {
            let x = norm(x);
            wanted.iter().any(|w| x.contains(w.as_str()))
        };
        ids.extend(all.iter().filter(|r| r.terms.iter().any(|t| names(t)) || r.text.as_deref().is_some_and(names)).map(|r| r.id));
        for l in s.links().into_iter().filter(|l| l.status == LinkStatus::Accepted) {
            if ids.contains(&l.from) || ids.contains(&l.to) {
                ids.extend([l.from, l.to]);
            }
        }
        if let Some(d) = doc {
            let obs: BTreeSet<RecordId> = all.iter().filter(|r| r.doc_id.as_deref() == Some(d)).map(|r| r.id).collect();
            ids.extend(all.iter().filter(|r| r.based_on.iter().any(|b| obs.contains(b))).map(|r| r.id));
        }
        // a withdrawn source takes its records out of what is shown as established (and so out of what may be cited)
        let mut out: Vec<RecordView> =
            all.into_iter().filter(|r| ids.contains(&r.id) && matches!(r.kind, RecordKind::Claim | RecordKind::Hypothesis) && f.grounded(s, &r.id)).collect();
        out.truncate(self.cfg.max_known);
        out
    }

    fn questions_text(&self) -> String {
        self.questions.iter().map(|q| format!("  {}: {}", q.id, q.text)).collect::<Vec<_>>().join("\n")
    }

    fn extend_prompt<S: AuditStore>(&self, s: &S, f: &Flags, (doc, a, b): &(String, usize, usize)) -> (String, Scope, Vec<RecordId>) {
        if let Some(n) = doc.strip_prefix("zone:").and_then(|n| n.parse::<usize>().ok()) {
            return self.zone_prompt(s, f, n);
        }
        let text = s.doc_text(doc).unwrap_or_default();
        let terms: Vec<String> = self.questions.iter().flat_map(|q| q.about.clone()).collect();
        let known_recs = self.known(s, f, &terms, Some(doc));
        let issued: Vec<RecordId> = known_recs.iter().map(|r| r.id).collect();
        // a section cut from the middle of a document: its heading and the header of the table it begins inside, shown to read it
        // by and never quoted (the scope stays the section)
        let context = gaps::reading_context(doc, &text, *a);
        let context = if context.is_empty() {
            String::new()
        } else {
            format!(
                "CONTEXT above this section (to understand it; never quote it):\n{}\n",
                context.iter().map(|c| format!("  {c}")).collect::<Vec<_>>().join("\n")
            )
        };
        let prompt = format!(
            "TASK EXTEND: read this section of report {doc} and record what it establishes, qualifies, revokes or leaves open that \
             matters for the research questions. Quote only from the section.\nRESEARCH QUESTIONS:\n{}\n{}\n{context}SECTION doc_id=\"{doc}\" \
             (bytes {a}..{b}):\n<<<\n{}\n>>>",
            self.questions_text(),
            known_block(&known_recs, "ALREADY RECORDED (do not repeat; relate to these @ids instead)"),
            &text[*a..*b]
        );
        let prompt =
            if super::quality::show_concepts(s, self.cfg.circles.is_some()) { format!("{prompt}\n{}", self.known_concepts(s, &text[*a..*b])) } else { prompt };
        (prompt, Scope { docs: vec![doc.clone()], topic: None, ranges: vec![(doc.clone(), *a, *b)] }, issued)
    }

    /// A zone read whole (run S1.2): every document of it in one directive, quoted from any of them, its records related across
    /// them by relation lines between the answer's own claims.
    fn zone_prompt<S: AuditStore>(&self, s: &S, f: &Flags, n: usize) -> (String, Scope, Vec<RecordId>) {
        let docs = &self.cfg.zones[n];
        let terms: Vec<String> = self.questions.iter().flat_map(|q| q.about.clone()).collect();
        let known_recs = self.known(s, f, &terms, None);
        let issued: Vec<RecordId> = known_recs.iter().map(|r| r.id).collect();
        let mut ranges = Vec::new();
        let mut sections = String::new();
        for d in docs {
            let text = s.doc_text(d).unwrap_or_default();
            ranges.push((d.clone(), 0, text.len()));
            sections.push_str(&format!("SECTION doc_id=\"{d}\" (bytes 0..{}):\n<<<\n{text}\n>>>\n", text.len()));
        }
        let prompt = format!(
            "TASK EXTEND: read these {} reports whole and record what they establish, qualify, revoke or leave open that matters for \
             the research questions{}. Quote only from the sections, each observe naming its own doc_id.\nRESEARCH QUESTIONS:\n{}\n{}\n{sections}",
            docs.len(),
            if self.cfg.relation_lines { ", and how your claims relate across the reports (relation lines between them)" } else { "" },
            self.questions_text(),
            known_block(&known_recs, "ALREADY RECORDED (do not repeat; relate to these @ids instead)"),
        );
        let prompt =
            if super::quality::show_concepts(s, self.cfg.circles.is_some()) { format!("{prompt}\n{}", self.known_concepts(s, &sections)) } else { prompt };
        (prompt, Scope { docs: docs.clone(), topic: None, ranges }, issued)
    }

    /// The sections (of any document) that mention the most of `terms`, up to two.
    fn sections_about<S: AuditStore>(&self, s: &S, terms: &[String]) -> Vec<(String, usize, usize, String)> {
        let mut scored = Vec::new();
        for d in s.docs() {
            let text = s.doc_text(&d).unwrap_or_default();
            for (a, b) in sections(&d, &text, self.cfg.section_bytes) {
                let low = text[a..b].to_lowercase();
                let hits = terms.iter().filter(|t| !t.is_empty() && low.contains(&t.to_lowercase())).count();
                if hits > 0 {
                    scored.push((hits, d.clone(), a, b, text[a..b].to_string()));
                }
            }
        }
        scored.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)).then(x.2.cmp(&y.2)));
        scored.into_iter().take(2).map(|(_, d, a, b, t)| (d, a, b, t)).collect()
    }

    fn cone<S: AuditStore>(&self, s: &S, f: &Flags, roots: &[RecordId]) -> Vec<RecordView> {
        self.cone_within(s, f, roots, self.cfg.max_cone)
    }

    fn cone_within<S: AuditStore>(&self, s: &S, f: &Flags, roots: &[RecordId], limit: usize) -> Vec<RecordView> {
        let mut seen: BTreeSet<RecordId> = BTreeSet::new();
        let mut out = Vec::new();
        let mut stack: Vec<RecordId> = roots.to_vec();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) || out.len() >= limit {
                continue;
            }
            if let Some(r) = s.record(&id) {
                stack.extend(r.based_on.iter().copied());
                if f.grounded(s, &id) {
                    out.push(r);
                }
            }
        }
        out.sort_by_key(|r| r.seq);
        out
    }

    fn with_sections(&self, base: String, secs: &[(String, usize, usize, String)], issued: Vec<RecordId>) -> (String, Scope, Vec<RecordId>) {
        let mut p = base;
        for (d, a, b, t) in secs {
            // the doc_id an observe names, as in EXTEND (live run 10A-3: INVESTIGATE answers named reports by title or @id)
            p.push_str(&format!("\nSECTION doc_id=\"{d}\" (bytes {a}..{b}):\n<<<\n{t}\n>>>"));
        }
        let scope = Scope {
            docs: secs.iter().map(|x| x.0.clone()).collect::<BTreeSet<_>>().into_iter().collect(),
            topic: None,
            ranges: secs.iter().map(|(d, a, b, _)| (d.clone(), *a, *b)).collect(),
        };
        (p, scope, issued)
    }

    /// What a question is about, for finding its sections: its terms, and for a term that names a record (`@id`, live run 10A-4,
    /// F08) that record's terms, text and the quotes it rests on.
    fn question_terms<S: AuditStore>(&self, s: &S, r: &RecordView) -> Vec<String> {
        let mut out = Vec::new();
        for t in &r.terms {
            // `about` names a record by @id, or by the local id of a line of the question's own answer (live run 10A-5: a question
            // about "t24_c1" matched no section and was given up uninvestigated)
            let named = if t.starts_with('@') {
                s.records_since(0).into_iter().find(|x| x.id.short() == *t)
            } else {
                s.local_record(&r.author, &r.directive, t).and_then(|id| s.record(&id))
            };
            match named {
                Some(x) => {
                    out.extend(x.terms.iter().cloned());
                    out.extend(x.text.clone());
                    out.extend(x.quote.clone());
                    out.extend(x.based_on.iter().filter_map(|b| s.record(b)).filter_map(|b| b.quote));
                }
                None => out.push(t.clone()),
            }
        }
        out
    }

    fn investigate_prompt<S: AuditStore>(&self, s: &S, f: &Flags, q: RecordId) -> (String, Scope, Vec<RecordId>) {
        let r = s.record(&q).expect("a question record exists");
        let terms = self.question_terms(s, &r);
        let cone_recs = self.cone(s, f, &[q]);
        let known_recs = self.known(s, f, &terms, None);
        let issued: Vec<RecordId> = cone_recs.iter().chain(&known_recs).map(|x| x.id).collect();
        let cone: Vec<String> = cone_recs.iter().map(rec_line).collect();
        let base = format!(
            "TASK INVESTIGATE: answer this open question of another agent from the sections below, quoting only from them. If they do \
             not settle it, write a sharper question line (it needs no quote) or answer []: a claim, even with stance unknown, rests on \
             quotes from these sections.\nQUESTION {}: {}\nNEEDED: {}\nSUPPORT:\n{}\n{}",
            r.id.short(),
            r.text.clone().unwrap_or_default(),
            r.body.get("needed").and_then(|x| x.as_str()).unwrap_or(""),
            cone.join("\n"),
            known_block(&known_recs, "ALREADY RECORDED")
        );
        self.with_sections(base, &self.sections_about(s, &terms), issued)
    }

    fn link_prompt<S: AuditStore>(&self, s: &S, f: &Flags, kind: TaskKind, l: LinkId) -> (String, Scope, Vec<RecordId>) {
        let l = s.link(&l).expect("a leased link exists");
        let mut cone_recs = self.cone(s, f, &[l.from, l.to]);
        // what a request about this link found, for or against it
        for r in self.request_records_of_link(s, f, l.id) {
            if !cone_recs.iter().any(|x| x.id == r.id) {
                cone_recs.push(r);
            }
        }
        if super::quality::enabled(s, "link_both_sides") {
            let mut all = super::pairs::cone(s, &[l.from, l.to]);
            for r in all.drain(..) {
                if !cone_recs.iter().any(|x| x.id == r.id) {
                    cone_recs.push(r);
                }
            }
        }
        // every quote names its report's date: supersedes runs from the newer conclusion to the older, and without dates a checker
        // refused true ones as "no quote shows it is newer" (step 3a of 31.10: none of the 487 checks of MCPpair2_r2 showed a date)
        let cone: Vec<String> = cone_recs
            .iter()
            .map(|r| match (r.kind, r.doc_id.as_deref()) {
                (RecordKind::Observe, Some(doc)) => rec_line_dated(r, &super::quality::evolution::date(s, doc)),
                _ => rec_line(r),
            })
            .collect();
        let terms: Vec<String> =
            [l.from, l.to].iter().filter_map(|r| s.record(r)).flat_map(|r| r.terms).chain(cone_recs.iter().filter_map(|r| r.quote.clone())).collect();
        // a check rests on the quotes it is shown (live run 10A-4: link checks wrote eight times the quotes of all reading)
        let ask = if kind == TaskKind::VerifyLink {
            format!(
                "TASK VERIFY_LINK: the graph builder proposed {} {} {}. Check it against the quotes and sections. Answer with one verdict line \
                 {{\"kind\":\"verdict\",\"link\":\"{}\",\"verdict\":\"confirm|reject\",\"reason\":\"...\",\"based_on\":[\"@id or your observe\"]}}. \
                 Rest it on the observe @ids shown in RECORDS; write an observe line first only when they do not show what decides the \
                 link, and no claim, hypothesis, relation or question lines. Confirm only when the quotes prove exactly this relation: {} \
                 {VERIFY_SCOPE_RULES} Otherwise reject.",
                l.from.short(),
                l.rel,
                l.to.short(),
                l.id.short(),
                super::builder::LINK_CRITERIA
            )
        } else {
            format!(
                "TASK RESOLVE_CONFLICT: {} and {} were flagged as contradicting. Find out why: a later decision (supersedes), a different \
                 version, date or context (qualifies), or a real unresolved conflict. Record it with relation/claim lines, then one verdict \
                 line {{\"kind\":\"verdict\",\"link\":\"{}\",\"verdict\":\"confirm|reject\",\"reason\":\"...\",\"based_on\":[\"@id or your observe\"]}}: \
                 confirm if the conflict is real and unresolved, reject if it is not a conflict.",
                l.from.short(),
                l.to.short(),
                l.id.short()
            )
        };
        let guard = super::pairs::scope_violation(s, l.from, &l.rel, l.to, &l.basis);
        let ask = if let Some(v) = guard {
            format!("{ask}\nREPORT/HEAD SCOPE GUARD: {v}. Reject unless a shown/new basis quote explicitly names the other report/head; shared procedural wording is not a bridge.")
        } else {
            ask
        };
        let issued: Vec<RecordId> = cone_recs.iter().map(|x| x.id).collect();
        self.with_sections(format!("{ask}\nRECORDS:\n{}", cone.join("\n")), &self.sections_about(s, &terms), issued)
    }

    /// The claims a summary of `rq` would answer from now, with or without the concepts the builder mapped: the window and every
    /// claim chosen before the cap. A measurement for the quarantine of proposed mappings (the owner's decision of 2026-10-23).
    pub fn summary_candidates<S: AuditStore>(&self, s: &S, rq: &str, mappings: bool) -> Option<(Vec<RecordId>, BTreeSet<RecordId>)> {
        let q = self.questions.iter().find(|q| q.id == rq)?;
        let f = Flags::of(s);
        let usable = s.usable_links();
        let links_now: Vec<LinkView> = s
            .links()
            .into_iter()
            .filter(|l| l.status == LinkStatus::Accepted && usable.as_ref().map_or_else(|| s.link_usable(&l.id), |u| u.contains(&l.id)))
            .collect();
        Some(self.summary_support(s, &f, q, &links_now, mappings))
    }

    fn summarize_prompt<S: AuditStore>(&self, s: &S, f: &Flags, rq: &str, task_id: &str) -> (String, Scope, Vec<RecordId>) {
        let q = self.questions.iter().find(|q| q.id == rq).expect("a research question exists");
        // only links that stand now (their ends, basis and confirmation still hold) widen or show anything (Codex review c78060e, F03)
        let usable = s.usable_links();
        let links_now: Vec<LinkView> = s
            .links()
            .into_iter()
            .filter(|l| l.status == LinkStatus::Accepted && usable.as_ref().map_or_else(|| s.link_usable(&l.id), |u| u.contains(&l.id)))
            .collect();
        let (support, chosen) = self.summary_support(s, f, q, &links_now, true);
        let eligible = chosen.len();
        // each claim with everything it rests on, best first, until the window is full: a claim is shown whole or not at all, and
        // the prompt says how much did not fit (Codex review c78060e, F01/F14: the store takes at most MAX_REFS issued records, and
        // a shared depth-first budget dropped the first claims and cut quotes off the others)
        let budget = self.cfg.summary_records.min(crate::session::MAX_REFS);
        let retained = self.retained_ids(s, rq);
        // Registry R30, step 2 (opt-in): every answer of the Claude series gave an earlier report's state as current where a later
        // report had changed it (blind grading, 28.10). A claim joins the window with its whole time component: every claim its
        // standing supersedes or contradicts links reach, transitively, each with all it rests on, so the window never shows an
        // older or middle state without the later one (offline on H1c_r3: 1 to 3 such pairs cut per answer). One hop was not
        // enough: in A <- B <- C with room for A and B only, B stood shown as the later state with C hidden (Codex 28.10, D05).
        let temporal = super::quality::enabled(s, "temporal_summary");
        let timed: Vec<&LinkView> = links_now.iter().filter(|l| temporal && matches!(l.rel.as_str(), "supersedes" | "contradicts")).collect();
        // The same time component by words (opt-in, `summary_companions`): a claim also brings the claim of a later report it is
        // most like among its nearest by words, with all it rests on, transitively. 31.10: MCPhints_r1, MCPctl_none_r1 and _r3 had
        // read the later state of a stale fact, the swarm linked nothing, and the window showed only the older state.
        let companions = temporal && super::quality::enabled(s, "summary_companions");
        let companion: BTreeMap<RecordId, RecordId> = if companions { later_on_the_same_words(s) } else { BTreeMap::new() };
        let unit = |c: &RecordId| {
            let mut whole = closure(s, f, c);
            let mut seen = BTreeSet::new();
            loop {
                let open: Vec<RecordId> = whole.iter().filter(|x| !seen.contains(*x)).copied().collect();
                if open.is_empty() {
                    break;
                }
                for x in open {
                    seen.insert(x);
                    for l in timed.iter().filter(|l| l.from == x || l.to == x) {
                        let other = if l.from == x { l.to } else { l.from };
                        if !whole.contains(&other) {
                            whole.extend(closure(s, f, &other));
                        }
                    }
                    if let Some(later) = companion.get(&x).filter(|n| !whole.contains(*n)) {
                        whole.extend(closure(s, f, later));
                    }
                }
            }
            whole
        };
        // Retained rows are already grounded records. Issue their ids first so a delta done can name them; add their cones
        // where they fit, then ordinary source claims. The store's issued-reference bound still applies.
        let retained_units: Vec<(RecordId, BTreeSet<RecordId>)> = retained.iter().map(|c| (*c, unit(c))).collect();
        let support_units: Vec<BTreeSet<RecordId>> = support.iter().map(unit).collect();
        // what a repair answers from stands in the window whatever else fits there
        let fallen = if retained.is_empty() { Vec::new() } else { self.fallen_rows(s, f, rq) };
        let named: BTreeSet<RecordId> = named_rows(&fallen).iter().flat_map(|r| r.standing.iter().map(|o| o.id)).collect();
        let hard = crate::session::MAX_REFS.saturating_sub(named.len());
        // and the claims still standing that are most like what fell by words, before the claims chosen by the question, in the
        // same budget: the live support of a fallen conclusion need not be near the question (run K02_1_r1)
        let live = if fallen.is_empty() { Vec::new() } else { live_support(s, &fallen, &named) };
        let live_units: Vec<BTreeSet<RecordId>> = live.iter().map(unit).collect();
        let (mut shown, mut fit, partial, placed) = place(&retained_units, &live_units, &support_units, budget.min(hard), hard, temporal);
        let live: Vec<RecordId> = placed.iter().map(|i| live[*i]).collect();
        shown.extend(named.iter().copied());
        if temporal {
            // a component brings in relevant claims of its own: count the relevant claims shown, not the units placed (D05)
            fit = chosen.iter().filter(|c| shown.contains(c)).count();
        } else {
            // a claim of the live support that is relevant to the question and past the cap of claims is shown too: the units
            // placed do not count it, and WINDOW would name it among the claims not shown
            fit += live.iter().filter(|c| chosen.contains(*c) && !support.contains(*c)).count();
        }
        // the date of a record's report: its own document, or the one document its quotes come from; empty when undated
        let dated = |id: &RecordId| -> String {
            let doc = s.record(id).and_then(|r| r.doc_id).or_else(|| super::quality::evolution::document(s, *id));
            doc.map(|d| super::quality::evolution::date(s, &d)).unwrap_or_default()
        };
        let mut recs: Vec<RecordView> = shown.iter().filter_map(|i| s.record(i)).collect();
        if temporal {
            // report-date order (undated last), reading order within a report
            recs.sort_by_cached_key(|r| {
                let d = dated(&r.id);
                (d.is_empty(), d, r.seq)
            });
        } else {
            recs.sort_by_key(|r| r.seq);
        }
        let issued: Vec<RecordId> = recs.iter().map(|x| x.id).collect();
        let cone: Vec<String> =
            recs.iter().map(|r| if temporal && r.kind == RecordKind::Observe { rec_line_dated(r, &dated(&r.id)) } else { rec_line(r) }).collect();
        let links: Vec<String> = links_now
            .iter()
            .filter(|l| shown.contains(&l.from) && shown.contains(&l.to))
            .map(|l| format!("  {} {} {} (accepted)", l.from.short(), l.rel, l.to.short()))
            .collect();
        let later: Vec<String> = links_now
            .iter()
            .filter(|l| temporal && l.rel == "supersedes" && shown.contains(&l.from) && shown.contains(&l.to))
            .map(|l| {
                let (old, new) = (dated(&l.to), dated(&l.from));
                let when = |d: &str| if d.is_empty() { "undated report".to_string() } else { format!("report date {d}") };
                // the swarm's accepted relation, not a truth: Codex's consilium (28.10, D04) found accepted supersedes whose two ends
                // describe one and the same change
                format!(
                    "  {} ({}) is superseded by {} ({}) by the swarm's accepted link: unless the records shown say otherwise, give {} as the \
                     earlier state as its report states it and {} as the later state.",
                    l.to.short(),
                    when(&old),
                    l.from.short(),
                    when(&new),
                    l.to.short(),
                    l.from.short()
                )
            })
            // a qualifies across two report dates marks a partial change (Gemini 31.10: an older claim that joins two mechanisms
            // of which the later report ends one): the earlier record stands, with the later one's change
            .chain(links_now.iter().filter(|l| temporal && l.rel == "qualifies" && shown.contains(&l.from) && shown.contains(&l.to)).filter_map(|l| {
                let (a, b) = (dated(&l.from), dated(&l.to));
                let (old, new) = if a < b { (l.from, l.to) } else { (l.to, l.from) };
                (!a.is_empty() && !b.is_empty() && a != b).then(|| {
                    format!(
                        "  {} (report date {}) is partly replaced or qualified by {} (report date {}) by the swarm's accepted link: unless the \
                         records shown say otherwise, give {} with the later change {} states.",
                        old.short(),
                        a.clone().min(b.clone()),
                        new.short(),
                        a.max(b),
                        old.short(),
                        new.short()
                    )
                })
            }))
            .collect();
        // a qualification keeps the earlier statement standing with a new scope or condition; only a replacement makes it history;
        // a report date says when a report stated something, not when it took effect (Codex 28.10, D06)
        let time_metadata = if temporal { "Each quote shows its report date; RECORDS run in report-date order (undated reports last).\n" } else { "" };
        let mut later = if later.is_empty() { String::new() } else { format!("\nSUPERSEDED (kernel, from accepted links):\n{}", later.join("\n")) };
        if !partial.is_empty() {
            later.push_str(&format!(
                "\nRETAINED WITHOUT ROOM (kernel): {} kept from this task's earlier answer, but what they rest on or their later states do \
                 not all fit this window: do not give them as the latest known state.",
                short_list(&partial).join(", ")
            ));
        }
        // the pairs by words the window shows whole, named as what they are, so the summary judges the change itself
        let by_words: Vec<String> = companion
            .iter()
            .filter(|(a, b)| shown.contains(*a) && shown.contains(*b))
            .map(|(a, b)| format!("  {} (report date {}) and the later {} (report date {})", a.short(), dated(a), b.short(), dated(b)))
            .collect();
        if !by_words.is_empty() {
            later.push_str(&format!(
                "\nLATER ON THE SAME WORDS (kernel, a retrieval by words, not a link): where the later record replaces or changes what the \
                 earlier one states, give the earlier as historical and the later as the latest known; where it states something else or \
                 only adds a condition, both stand.\n{}",
                by_words.join("\n")
            ));
        }
        let quoted: BTreeSet<String> = recs.iter().filter_map(|r| r.doc_id.clone()).collect();
        let unquoted: Vec<String> = s.docs().into_iter().filter(|d| !quoted.contains(d)).collect();
        let mut window = format!(
            "WINDOW: {fit} of {eligible} relevant claims shown, each with all it rests on{}; {} not shown{}. Documents with no quote shown: {}.",
            if partial.is_empty() { String::new() } else { format!(" except the retained {}", short_list(&partial).join(", ")) },
            eligible - fit,
            if (eligible > fit || !partial.is_empty()) && fallen.is_empty() { " (say that the answer may be incomplete)" } else { "" },
            if unquoted.is_empty() { "none".to_string() } else { unquoted.join(", ") }
        );
        if !live.is_empty() {
            window.push_str(&format!(
                "\nLIVE SUPPORT (kernel, a retrieval by the words of the records that fell, not a verdict): {} standing claim{} shown whatever \
                 their place by the question, each with all it rests on, none on withdrawn text: {}.",
                live.len(),
                if live.len() == 1 { "" } else { "s" },
                short_list(&live).join(", ")
            ));
        }
        let open = self.open_questions(s, f, &q.about);
        let repair = if retained.is_empty() {
            String::new()
        } else if !fallen.is_empty() {
            fallen_repair(&fallen, &retained, &live)
        } else {
            format!(
                "INCREMENTAL REPAIR: retain these independent answer records unchanged: {}. Write only replacement/additional \
                claims for the invalidated part, or exclude it if unsupported. Do not paraphrase or regenerate retained rows. \
                The kernel unions their ids into the new done and records this composition in the task checkpoint.\n",
                short_list(&retained).join(", ")
            )
        };
        let guidance = super::answer_guidance::text();
        let target_text_chars = super::answer_guidance::target_claim_characters();
        // a repair is no new answer: telling it to condense and to cover every report made it write the whole answer again
        let (shape, cover) = if fallen.is_empty() {
            let most = SUMMARY_CLAIMS.min(self.cfg.summary_lines.saturating_sub(1));
            (
                format!(
                    "Condense: at most {most} claim lines, each a short text (at most {target_text_chars} characters; more than {SUMMARY_TEXT_CHARS} is refused) that \
                     merges related records and rests on all their quotes; do not restate every record."
                ),
                " Cover every report the records come from.",
            )
        } else {
            (format!("Each claim is a short text (at most {target_text_chars} characters; more than {SUMMARY_TEXT_CHARS} is refused)."), "")
        };
        let prompt = format!(
            "{repair}TASK SUMMARIZE research question {}: {}\nAnswer only from the records below: write final claim lines based_on the observe @ids shown (the quotes), \
             and write no observe lines (no document is open to a summary: cite the quotes shown by their @ids). {shape} End with {{\"kind\":\"done\",\"local_id\":\"<prefix>d1\",\"rq_id\":\"{}\",\"directive_id\":\"{task_id}\",\
             \"outcome\":\"answered|unknown|unresolved_conflict\",\"answer_ids\":[\"your claims\"],\"text\":\"what the records do not settle\"}}. The done text names \
             the main points the records do not settle, the OPEN QUESTIONS below included, in at most {target_text_chars} characters; they are not claims (a claim always rests \
             on quotes). If the records settle nothing, the outcome is unknown with no answer_ids.{cover} \
             {guidance}\n{time_metadata}{window}\n\
             RECORDS:\n{}\nACCEPTED LINKS:\n{}{later}\nOPEN QUESTIONS (not settled by the swarm):\n{}",
            q.id,
            q.text,
            q.id,
            cone.join("\n"),
            links.join("\n"),
            if open.is_empty() { "  (none)".to_string() } else { open.join("\n") }
        );
        (format!("{prompt}{}", super::quality::stale::prompt(s)), Scope::default(), issued)
    }

    /// The claims a summary answers from, best first, and how many there were before the cap. A claim is about the question when
    /// its own terms, text, predicate or stance name a topic, when an observe it rests on does (terms or quote), or when it is
    /// mapped to a concept whose name or alias names a topic (a retrieval candidate, not an identity; Codex review c78060e, F09);
    /// also when its structure says so: a stance, a standing link or a concept type the question selects (Gemini's run-10
    /// corrections). The claims that links standing now connect to them join. They are spread over the documents (round robin by
    /// the document of their first quote).
    fn summary_support<S: AuditStore>(
        &self,
        s: &S,
        f: &Flags,
        q: &ResearchQuestion,
        links: &[LinkView],
        mappings: bool,
    ) -> (Vec<RecordId>, BTreeSet<RecordId>) {
        let topics = Topics::new(&q.about);
        let all = s.records_since(0);
        let by_id: BTreeMap<RecordId, &RecordView> = all.iter().map(|r| (r.id, r)).collect();
        let claim = |r: &RecordView| r.kind == RecordKind::Claim && f.support(s, &r.id);
        let mapped: BTreeSet<RecordId> = s
            .concepts()
            .iter()
            .filter(|c| {
                mappings && c.status != "retired" && (topics.named(&c.name) || c.aliases.iter().any(|a| topics.named(a)) || q.concept_types.contains(&c.ty))
            })
            .flat_map(|c| s.records_of(&c.id))
            .collect();
        let linked_by: BTreeSet<RecordId> = links.iter().filter(|l| q.relations.contains(&l.rel)).flat_map(|l| [l.from, l.to]).collect();
        let topical = |r: &RecordView| {
            // P2 applies to an evolution question (selected by supersedes/contradicts or lifecycle stances), not every RQ.
            let evolution = q.relations.iter().any(|r| matches!(r.as_str(), "supersedes" | "contradicts"))
                || q.stances.iter().any(|r| matches!(r.as_str(), "superseded" | "refuted"));
            (evolution
                && matches!(r.status.as_deref(), Some("reported" | "confirmed"))
                && super::pairs::change_marker(
                    &r.terms
                        .iter()
                        .cloned()
                        .chain([
                            r.text.clone().unwrap_or_default(),
                            r.body["predicate"].as_str().unwrap_or("").to_string(),
                            r.body["object"].as_str().unwrap_or("").to_string(),
                        ])
                        .collect::<Vec<_>>()
                        .join(" "),
                ))
                || mapped.contains(&r.id)
                || linked_by.contains(&r.id)
                || r.status.as_deref().is_some_and(|x| q.stances.iter().any(|w| w == x))
                || r.terms.iter().any(|t| topics.named(t))
                || [r.text.as_deref(), r.status.as_deref(), r.quote.as_deref(), r.body.get("predicate").and_then(|x| x.as_str())]
                    .into_iter()
                    .flatten()
                    .any(|t| topics.named(t))
        };
        let mut chosen: BTreeSet<RecordId> =
            all.iter().filter(|r| claim(r) && (topical(r) || r.based_on.iter().any(|b| by_id.get(b).is_some_and(|o| topical(o))))).map(|r| r.id).collect();
        let linked: Vec<RecordId> = links.iter().filter(|l| chosen.contains(&l.from) || chosen.contains(&l.to)).flat_map(|l| [l.from, l.to]).collect();
        chosen.extend(linked.into_iter().filter(|id| by_id.get(id).is_some_and(|r| claim(r))));
        let mut by_doc: BTreeMap<String, Vec<RecordId>> = BTreeMap::new();
        for r in all.iter().filter(|r| chosen.contains(&r.id)) {
            let doc = r.based_on.iter().find_map(|b| by_id.get(b).and_then(|o| o.doc_id.clone())).unwrap_or_default();
            by_doc.entry(doc).or_default().push(r.id);
        }
        let mut out = Vec::new();
        for round in 0.. {
            let before = out.len();
            for ids in by_doc.values() {
                if let Some(id) = ids.get(round) {
                    out.push(*id);
                }
            }
            if out.len() == before {
                break;
            }
        }
        // changes across versions first, within the same claim budget (step 3a of 31.10: MCPpair2_r2 had read and linked the claims
        // that Roots and Sampling were deprecated, none of them reached the window, and its answers gave both as current): the ends of
        // a standing supersedes or contradicts, of a qualifies between reports of two dates, and a claim whose quotes come from
        // reports of two or more dates. Without the time option (registry R30), or without such links or claims, the order is the one above.
        let temporal = super::quality::enabled(s, "temporal_summary");
        let date_of = |id: &RecordId| super::quality::evolution::document(s, *id).map(|d| super::quality::evolution::date(s, &d)).unwrap_or_default();
        let mut first: BTreeSet<RecordId> = links
            .iter()
            .filter(|l| match l.rel.as_str() {
                "supersedes" | "contradicts" => true,
                "qualifies" => {
                    let (a, b) = (date_of(&l.from), date_of(&l.to));
                    !a.is_empty() && !b.is_empty() && a != b
                }
                _ => false,
            })
            .flat_map(|l| [l.from, l.to])
            .filter(|id| temporal && chosen.contains(id))
            .collect();
        for id in out.iter().filter(|_| temporal) {
            let dates = super::pairs::cone(s, &[*id])
                .into_iter()
                .filter(|r| r.kind == RecordKind::Observe)
                .filter_map(|r| r.doc_id.map(|d| super::quality::evolution::date(s, &d)))
                .filter(|d| !d.is_empty())
                .collect::<BTreeSet<_>>();
            if dates.len() >= 2 {
                first.insert(*id);
            }
        }
        let (mut out, rest): (Vec<RecordId>, Vec<RecordId>) = out.into_iter().partition(|id| first.contains(id));
        out.extend(rest);
        out.truncate(self.cfg.summary_claims);
        (out, chosen)
    }

    /// What the swarm left open, for a summary: follow-up questions and the questions not investigated, given up or investigated
    /// without a record (Codex review c78060e, F11), those about the question's topics first, with what each needs; at most 30, and
    /// how many more there are.
    fn open_questions<S: AuditStore>(&self, s: &S, f: &Flags, about: &[String]) -> Vec<String> {
        let topics = Topics::new(about);
        // settled while a claim or sharper question the investigation recorded still stands (Codex review d7d9a49, D07)
        let settled = |r: &RecordView| self.settled.get(&format!("question:{}", r.id.short())).is_some_and(|ids| ids.iter().any(|id| f.grounded(s, id)));
        let mut open: Vec<RecordView> =
            s.records_since(0).into_iter().filter(|r| r.kind == RecordKind::Question).filter(|r| self.is_followup(&r.directive) || !settled(r)).collect();
        open.sort_by_key(|r| !(r.terms.iter().any(|t| topics.named(t)) || r.text.as_deref().is_some_and(|t| topics.named(t))));
        let more = open.len().saturating_sub(30);
        let mut lines: Vec<String> = open
            .iter()
            .take(30)
            .map(|r| {
                // a question the word search found no section for says so, and only that: a missed word is no proof the corpus
                // lacks the answer (F08; Codex's review of 77a803e, R04)
                let why = if self.no_source.contains(&format!("question:{}", r.id.short())) {
                    "; a word search found no section on it, which does not show the corpus lacks it"
                } else {
                    ""
                };
                format!(
                    "  {} {} (needed: {}{why})",
                    r.id.short(),
                    r.text.clone().unwrap_or_default(),
                    r.body.get("needed").and_then(|x| x.as_str()).unwrap_or("")
                )
            })
            .collect();
        if more > 0 {
            lines.push(format!("  ... and {more} more open questions not shown"));
        }
        lines
    }

    fn answer_problems<S: AuditStore>(&self, s: &S, lease: &Lease, lines: &[Value], unstored: &[(usize, Value)]) -> Vec<Value> {
        let shown: Vec<RecordId> = lease.own.iter().chain(&lease.issued).chain(&lease.own_run).copied().collect();
        let mut out = unstored_problems(s, &lease.scope, &lease.locals, &shown, lines, unstored);
        if !self.cfg.relation_lines && !(self.cfg.versions && lease.kind == TaskKind::Change) {
            // the control profiles: a relation line would become a link (Codex review of 8023910, SCOPE-01)
            for (j, v) in unstored.iter().filter(|(_, v)| v.get("kind").and_then(|x| x.as_str()) == Some("relation")) {
                out.push(json!({"needs": RELATIONS_OFF, "relations_off": true, "line": j, "local_id": v.get("local_id").cloned().unwrap_or(Value::Null)}));
            }
        }
        out
    }

    /// Resolve only whitespace and soft wraps to the source's exact bytes. Clause repair is an explicit suggestion, never a
    /// replacement of the agent's selected evidence. Record every whitespace normalization in the response metadata.
    fn normalize_soft_wrap_quotes<S: AuditStore>(&self, s: &S, lease: &Lease, kept: Vec<(usize, Value)>) -> (Vec<(usize, Value)>, Vec<Value>) {
        let mut extended = Vec::new();
        let kept = kept
            .into_iter()
            .map(|(i, mut v)| {
                if v.get("kind").and_then(|x| x.as_str()) == Some("observe") {
                    let doc = v.get("doc_id").and_then(|x| x.as_str()).map(str::to_string);
                    let quote = v.get("exact_quote").and_then(|x| x.as_str()).map(str::to_string);
                    if let (Some(d), Some(q)) = (doc, quote) {
                        let normalized = soft_wrap_quote(s, &lease.scope, &d, &q).unwrap_or_else(|| q.clone());
                        if normalized != q {
                            extended.push(json!({"local_id":v.get("local_id"),"sent":q,"stored":normalized}));
                            v["exact_quote"] = json!(normalized);
                        }
                    }
                }
                (i, v)
            })
            .collect();
        (kept, extended)
    }

    /// A reference written as the bare hex of a record shown to this lease is that record. Live summaries cited the quotes shown
    /// without the "@" (MCPctl_none_r1, MCPctl_none_r2, MCPstrong_r1: 100-123 references, 25-34 of 31-40 lines refused as
    /// UNKNOWN_LOCAL_ID), and the repair then left most of those lines out. Only a reference that is no local id of this answer
    /// or of this lease and names one record shown gets its "@"; the store still decides the line. Reported as `referenced`.
    fn normalize_bare_references(&self, lease: &Lease, lines: &[Value], kept: Vec<(usize, Value)>) -> (Vec<(usize, Value)>, Vec<Value>) {
        let shown: BTreeSet<String> = lease.issued.iter().chain(&lease.own).chain(&lease.own_run).map(RecordId::short).collect();
        let names: BTreeSet<&str> = lines.iter().filter_map(|v| v.get("local_id").and_then(|x| x.as_str())).collect();
        let full = |x: &Value| -> Option<String> {
            let r = x.as_str()?;
            let at = format!("@{r}");
            (!r.starts_with('@') && !names.contains(r) && !lease.locals.contains_key(r) && shown.contains(&at)).then_some(at)
        };
        let mut referenced = Vec::new();
        let kept = kept
            .into_iter()
            .map(|(i, mut v)| {
                let local = v.get("local_id").cloned().unwrap_or(Value::Null);
                if let Some(a) = v.get_mut("based_on").and_then(|x| x.as_array_mut()) {
                    for x in a.iter_mut() {
                        if let Some(at) = full(x) {
                            referenced.push(json!({"local_id": local, "field": "based_on", "sent": x, "stored": at}));
                            *x = json!(at);
                        }
                    }
                }
                for k in ["from", "to"] {
                    if let Some(x) = v.get_mut(k) {
                        if let Some(at) = full(x) {
                            referenced.push(json!({"local_id": local, "field": k, "sent": x, "stored": at}));
                            *x = json!(at);
                        }
                    }
                }
                (i, v)
            })
            .collect();
        (kept, referenced)
    }

    /// Store an answer's lines item by item (`lines` with their index in the answer, in order): a line the dispatcher's rules refuse
    /// (`ruled`, by index) is left out, and so is every line resting on a line left out; the store decides the others one by one, and
    /// after a line it refuses the rest goes in as the next part of the attempt (`<task>#<attempt>.<part>`).
    #[allow(clippy::too_many_arguments)]
    fn store_items<S: AuditStore>(
        &self,
        s: &mut S,
        task_id: &str,
        agent: &str,
        lease: &Lease,
        attempt: u32,
        lines: &[(usize, Value)],
        ruled: &BTreeMap<usize, Value>,
        first_part: usize,
    ) -> Items {
        let mut items = Items { parts: first_part, ..Default::default() };
        let mut out: BTreeSet<String> = BTreeSet::new();
        let name = |v: &Value| v.get("local_id").and_then(|x| x.as_str()).map(str::to_string);
        let mut definitions: BTreeMap<String, usize> = BTreeMap::new();
        for (i, v) in lines {
            if let Some(n) = name(v) {
                definitions.entry(n).or_insert(*i);
            }
        }
        let leave_out = |i: usize, v: &Value, out: &mut BTreeSet<String>, items: &mut Items| -> bool {
            match references(v).into_iter().find(|r| out.contains(r) && !lease.locals.contains_key(r)) {
                Some(on) => {
                    items.excluded.push((i, on));
                    if let Some(n) = name(v).filter(|n| definitions.get(n) == Some(&i)) {
                        out.insert(n);
                    }
                    true
                }
                None => false,
            }
        };
        let mut pending = Vec::new();
        for (i, v) in lines {
            let duplicate = name(v).is_some_and(|n| definitions.get(&n) != Some(i));
            if let Some(p) = ruled.get(i) {
                items.refused.push((*i, rule_error(p)));
                if let Some(n) = name(v).filter(|n| definitions.get(n) == Some(i) && !lease.locals.contains_key(n)) {
                    out.insert(n);
                }
            } else if duplicate {
                items.refused.push((
                    *i,
                    KernelError::new(Code::DuplicateLocalId, "a local_id has exactly one definition in an answer")
                        .field("local_id")
                        .expected(json!({"rule": "unique_local_id"}))
                        .to_json(),
                ));
            } else {
                pending.push((*i, v.clone()));
            }
        }
        // Stable Kahn ordering. Unknown external references still go to the store for its normal scoped refusal. A refused
        // definition blocks its dependent subgraph; independent components keep their original relative order.
        let mut queue = Vec::new();
        while !pending.is_empty() {
            pending.retain(|(i, v)| !leave_out(*i, v, &mut out, &mut items));
            if pending.is_empty() {
                break;
            }
            let names: BTreeSet<String> = pending.iter().filter_map(|(_, v)| name(v)).collect();
            let ready = pending.iter().position(|(_, v)| references(v).iter().all(|r| !names.contains(r) || lease.locals.contains_key(r)));
            let Some(k) = ready else {
                for (i, _) in pending.drain(..) {
                    items.refused.push((
                        i,
                        KernelError::new(Code::BadField, "local references must form an acyclic graph")
                            .field("based_on")
                            .expected(json!({"rule": "acyclic_local_references"}))
                            .to_json(),
                    ));
                }
                break;
            };
            queue.push(pending.remove(k));
        }
        while !queue.is_empty() {
            let records: Vec<Value> = queue.iter().map(|(_, v)| v.clone()).collect();
            let id = if items.parts == 0 { format!("{task_id}#{attempt}") } else { format!("{task_id}#{attempt}.{}", items.parts) };
            items.parts += 1;
            let rep = s.submit_scoped_records_id(&id, agent, task_id, &lease.scope, &allowed_records(lease, &records), &records);
            items.stored.extend(queue.iter().zip(&rep.accepted).map(|((i, _), r)| (*i, *r)));
            let Some(e) = rep.error else { break };
            let k = rep.failed_index.filter(|k| *k < queue.len() && *k >= rep.accepted.len()).unwrap_or(rep.accepted.len());
            if k >= queue.len() {
                break;
            }
            let rest = queue.split_off(k + 1);
            let (ri, rv) = queue.pop().expect("the refused line");
            items.refused.push((ri, e.to_json()));
            if let Some(n) = name(&rv).filter(|n| !lease.locals.contains_key(n)) {
                out.insert(n);
            }
            queue = rest.into_iter().filter(|(i, v)| !leave_out(*i, v, &mut out, &mut items)).collect();
        }
        items
    }

    fn repair(&mut self, task_id: &str, i: usize, e: KernelError) -> Value {
        self.stats.repairs += 1;
        self.mark_failed(task_id);
        // Before a store submission no line of this attempt was committed. A post-submit caller wraps this with `ack`, which
        // supplies the real accepted prefix and overrides this marker. This is response metadata, not a WAL or admission change.
        json!({"status": "REPAIR_REQUIRED", "task_id": task_id, "failed_index": i, "repair_scope": "whole_answer", "error": e.to_json()})
    }

    /// Store an agent's answer to its lease. `verdict` lines (link tasks only) are applied by the dispatcher; the rest go to the
    /// store under the lease's scope (fail-fast; the lease stays open for a repair).
    pub fn submit<S: AuditStore>(&mut self, s: &mut S, task_id: &str, agent: &str, lines: &[Value], now: u64) -> Value {
        self.expire(now);
        if let Err(e) = self.persist_version_closures(s) {
            return json!({"status":"error","code":"CHANGE_CLOSURE_NOT_DURABLE","error":e.to_json()});
        }
        let Some(lease) = self.leases.get(task_id).cloned() else {
            return json!({"status": "STALE_TASK", "task_id": task_id, "message": "unknown or expired task: acquire again"});
        };
        if lease.agent != agent {
            return json!({"status": "error", "code": "TASK_NOT_OWNED", "task_id": task_id});
        }
        if lease.kind == TaskKind::Build {
            return json!({"status":"error","code":"BUILD_OPERATIONS_REQUIRED","task_id":task_id});
        }
        if let Err(e) = self.persist_change_lease(s, task_id) {
            return self.repair(task_id, 0, e);
        }
        self.received_response(task_id, now);
        // A3: compose the current independent view into a delta completion without rewriting any accepted claim. Original
        // answer checkpoints and records remain immutable; the new checkpoint explicitly attributes the union to the kernel.
        let retained = lease.question.as_ref().filter(|_| lease.kind == TaskKind::Summarize).map(|q| self.retained_ids(s, q)).unwrap_or_default();
        let copies = copies_of_kept(s, &retained, lines);
        let mut composed: Vec<Value> =
            lines.iter().filter(|v| v["kind"] != "claim" || !v["local_id"].as_str().is_some_and(|n| copies.contains(n))).cloned().collect();
        for v in &mut composed {
            if !retained.is_empty() && v["kind"] == "done" && v["rq_id"] == lease.question.as_deref().unwrap_or("") {
                if let Some(ids) = v.get_mut("answer_ids").and_then(|x| x.as_array_mut()) {
                    ids.retain(|x| !x.as_str().is_some_and(|n| copies.contains(n)));
                    for id in &retained {
                        let n = json!(id.short());
                        if !ids.contains(&n) {
                            ids.push(n);
                        }
                    }
                    if v["outcome"] == "unknown" {
                        v["outcome"] = json!("answered");
                    }
                }
            }
        }
        let lines = composed.as_slice();
        // what a reading offered and stored is its own: the claims of its RELATE turn are not lines of the section
        if lease.kind == TaskKind::Extend && !lease.relate {
            let offered = self.key_offered.entry(lease.key.clone()).or_default();
            *offered = (*offered).max(lines.len());
        }
        let max_lines = lease.repair_lines.unwrap_or_else(|| self.max_lines(lease.kind));
        if lines.len() > max_lines {
            // a repair, not a lost section (run 8 lost four sections to answers of 25..27 lines). Nothing is stored, so the failed
            // index is 0: live run 10A-3 read index 40 as "40 lines accepted" and sent only its last three
            let e = KernelError::new(
                Code::BadField,
                format!("{} lines, at most {max_lines} per answer: nothing was stored; send the whole answer again, at most {max_lines} lines", lines.len()),
            )
            .field("lines")
            .expected(json!({"max_lines": max_lines}));
            return self.repair(task_id, 0, e);
        }
        if lease.relate {
            // the RELATE turn takes claims of a change only: the reading answer is stored, and the quotes are those shown
            if let Some(i) = lines.iter().position(|v| v["kind"] != "claim") {
                let e = KernelError::new(Code::BadField, "a RELATE turn takes claim lines only: a claim of a change on the quotes shown, or []")
                    .field("kind")
                    .expected(json!({"kinds": ["claim"]}));
                return self.repair(task_id, i, e);
            }
        }
        let is_verdict = |v: &Value| v.get("kind").and_then(|x| x.as_str()) == Some("verdict");
        // an exact resend of a line this lease already got accepted is a no-op; the rest keeps its index in the answer
        let kept: Vec<(usize, Value)> = lines
            .iter()
            .enumerate()
            .filter(|(_, v)| !is_verdict(v))
            .filter(|(_, v)| !v.get("local_id").and_then(|x| x.as_str()).is_some_and(|n| lease.line_digests.get(n) == Some(&line_digest(v))))
            .map(|(i, v)| (i, v.clone()))
            .collect();
        let verdicts: Vec<(usize, Value)> = lines.iter().enumerate().filter(|(_, v)| is_verdict(v)).map(|(i, v)| (i, v.clone())).collect();
        let link_task = matches!(lease.kind, TaskKind::VerifyLink | TaskKind::ResolveConflict);
        if !link_task && !verdicts.is_empty() {
            return self.repair(task_id, verdicts[0].0, KernelError::new(Code::BadField, "verdict lines belong to link tasks only").field("kind"));
        }
        if link_task && verdicts.len() != 1 {
            return self.repair(task_id, lines.len(), KernelError::new(Code::MissingField, "a link task needs exactly one verdict line").field("kind"));
        }
        // a done line closes the leased research question and nothing else: checked before anything is stored
        let is_done = |v: &Value| v.get("kind").and_then(|x| x.as_str()) == Some("done");
        let dones: Vec<usize> = lines.iter().enumerate().filter(|(_, v)| is_done(v)).map(|(i, _)| i).collect();
        let mut outcome = None;
        let mut summary_refused: BTreeMap<usize, Value> = BTreeMap::new();
        if lease.kind != TaskKind::Summarize {
            if let Some(i) = dones.first() {
                return self.repair(task_id, *i, KernelError::new(Code::BadField, "done lines belong to SUMMARIZE tasks only").field("kind"));
            }
        } else {
            // live run 5: summarizers quoted the reports again and got "document is outside the directive" three times over
            if let Some(i) = lines.iter().position(|v| v.get("kind").and_then(|x| x.as_str()) == Some("observe")) {
                let e = KernelError::new(Code::BadField, "a summary writes no observe lines: cite the observe @ids shown in RECORDS in based_on")
                    .field("kind")
                    .expected(json!({"kinds": if self.cfg.relation_lines { json!(["claim", "relation", "done"]) } else { json!(["claim", "done"]) },
                                     "based_on": "observe @ids shown in RECORDS"}));
                return self.repair(task_id, i, e);
            }
            if dones.len() != 1 {
                let e = KernelError::new(Code::MissingField, "a SUMMARIZE answer ends with exactly one done line").field("kind");
                return self.repair(task_id, dones.get(1).copied().unwrap_or(lines.len()), e);
            }
            let (i, done) = (dones[0], &lines[dones[0]]);
            let q = lease.question.clone().expect("a summary has a research question");
            let field = |k: &str, want: &str| -> Option<KernelError> {
                (done.get(k).and_then(|x| x.as_str()) != Some(want))
                    .then(|| KernelError::new(Code::BadField, format!("the done line must name {k} {want}")).field(k).expected(json!({ k: want })))
            };
            if let Some(e) = field("rq_id", &q).or_else(|| field("directive_id", task_id)) {
                return self.repair(task_id, i, e);
            }
            let Some(o) = done.get("outcome").and_then(|x| x.as_str()).filter(|o| OUTCOMES.contains(o)) else {
                let e = KernelError::new(Code::BadField, "the done line states its outcome").field("outcome").expected(json!({"outcome": OUTCOMES}));
                return self.repair(task_id, i, e);
            };
            if o != "unknown" && done.get("answer_ids").and_then(|x| x.as_array()).is_none_or(|a| a.is_empty()) {
                let e = KernelError::new(Code::NoEvidence, format!("an outcome '{o}' names its answer records; with none it is unknown")).field("answer_ids");
                return self.repair(task_id, i, e);
            }
            // what the store would refuse in a summary's lines is found in all of them at once (live run 10A-3); each such line is
            // left out with what depends on it and the others are stored, item by item (the consilium of 10A-17, Gemini's plan step
            // 1: one claim of 249 characters cost a summary of 48 lines). The done line is stored only when no line was refused
            let new_lines: Vec<(usize, &Value)> =
                lines.iter().enumerate().filter(|(_, v)| !v.get("local_id").and_then(|x| x.as_str()).is_some_and(|n| lease.locals.contains_key(n))).collect();
            let problems: Vec<Value> = new_lines
                .iter()
                .filter_map(|(j, v)| {
                    let text = v.get("text").and_then(|x| x.as_str()).map(|t| t.chars().count());
                    let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
                    let based = v.get("based_on").and_then(|x| x.as_array()).map_or(0, |a| a.len());
                    // a text over the bound says by how much: told only "1..240 characters", the model resent claims of 243..246
                    // characters unchanged five times and both summaries ended unknown (live run 10A-14)
                    let over = |n: usize| format!("; this one has {n}: shorten it by at least {}", n.saturating_sub(SUMMARY_TEXT_CHARS));
                    let problem = match kind {
                        "claim" if text.is_none_or(|n| n == 0 || n > SUMMARY_TEXT_CHARS) => {
                            Some(format!("text of 1..{SUMMARY_TEXT_CHARS} characters{}", text.filter(|n| *n > 0).map(over).unwrap_or_default()))
                        }
                        "claim" if based == 0 => Some("a claim rests on the quotes shown (based_on): put what is not settled into the done text".into()),
                        "done" if text.is_some_and(|n| n > SUMMARY_TEXT_CHARS) => {
                            Some(format!("done text of at most {SUMMARY_TEXT_CHARS} characters{}", text.map(over).unwrap_or_default()))
                        }
                        _ => None,
                    }?;
                    let mut p = json!({"line": j, "local_id": v.get("local_id"), "needs": problem});
                    if let Some(n) = text.filter(|n| *n > SUMMARY_TEXT_CHARS) {
                        p["characters"] = json!(n);
                    }
                    Some(p)
                })
                .collect();
            for p in problems {
                if let Some(j) = p["line"].as_u64() {
                    summary_refused.entry(j as usize).or_insert(p);
                }
            }
            outcome = Some(o.to_string());
        }
        // a verdict is checked before anything is stored
        let link_status = match verdicts.first() {
            Some((i, v)) => {
                let link = lease.link.expect("a link task has a link");
                if v.get("link").and_then(|x| x.as_str()) != Some(link.short().as_str()) {
                    let e = KernelError::new(Code::BadField, "the verdict names another link").field("link").expected(json!({"link": link.short()}));
                    return self.repair(task_id, *i, e);
                }
                match v.get("verdict").and_then(|x| x.as_str()) {
                    Some("confirm") => Some((*i, link, LinkStatus::Accepted)),
                    Some("reject") => Some((*i, link, LinkStatus::Rejected)),
                    _ => return self.repair(task_id, *i, KernelError::new(Code::BadField, "verdict is confirm or reject").field("verdict")),
                }
            }
            None => None,
        };
        // the dispatcher's own rules refuse a line as the store does: a relation line with an observe end (A1 for the swarm, Gemini's
        // audit of 10A-9) and S0, a claim naming identifiers its quotes do not hold, a quote cut from its clause. A refused line is left
        // out with the lines resting on it, every other line is stored, item by item (the consilium of 10A-17, Gemini's plan step 1:
        // 40% of the lines lost in 10A-16/17 were valid lines after one refused line). Clause boundaries produce repair hints;
        // only whitespace may be normalized to source bytes without another submission.
        let (kept, extended) = self.normalize_soft_wrap_quotes(s, &lease, kept);
        let (kept, referenced) = self.normalize_bare_references(&lease, lines, kept);
        let mut canonical = lines.to_vec();
        for (i, v) in &kept {
            canonical[*i] = v.clone();
        }
        let mut ruled = summary_refused;
        for (i, v) in &kept {
            if let Some(id) = v.get("local_id").and_then(|x| x.as_str()).and_then(|n| lease.locals.get(n)) {
                ruled.insert(*i, json!({"local_id_rebound": id.short()}));
            }
        }
        for p in self.answer_problems(s, &lease, &canonical, &kept) {
            if ["observe_ends", "missing_identifiers", "negation_before", "ends_mid_clause", "relations_off", "error"].iter().any(|k| p.get(*k).is_some()) {
                if let Some(j) = p["line"].as_u64() {
                    ruled.entry(j as usize).or_insert(p);
                }
            }
        }
        let attempt = self.next_attempt(task_id);
        // a summary's done line is stored only once every other line of it is
        let done_at = dones.first().copied().filter(|_| lease.kind == TaskKind::Summarize);
        let body: Vec<(usize, Value)> = kept.iter().filter(|(i, _)| Some(*i) != done_at).cloned().collect();
        let mut items = self.store_items(s, task_id, agent, &lease, attempt, &body, &ruled, 0);
        let mut coverage_prefix = None;
        if let Some((d, done)) = done_at.and_then(|d| kept.iter().find(|(i, _)| *i == d)) {
            if let Some(p) = ruled.get(d) {
                items.refused.push((*d, rule_error(p)));
            } else if items.refused.is_empty() && items.excluded.is_empty() {
                let mut names = lease.locals.clone();
                for (i, id) in &items.stored {
                    if let Some(name) = lines[*i]["local_id"].as_str() {
                        names.insert(name.to_string(), *id);
                    }
                }
                let ids: Option<Vec<RecordId>> = done["answer_ids"].as_array().and_then(|a| {
                    a.iter()
                        .map(|v| {
                            let name = v.as_str()?;
                            names
                                .get(name)
                                .copied()
                                .or_else(|| lease.own.iter().chain(&lease.issued).chain(&lease.own_run).find(|id| id.short() == name).copied())
                        })
                        .collect::<Option<Vec<_>>>()
                        .map(distinct_ids)
                });
                // An explicit unknown with no assertions is still an honest terminal outcome of the existing contract.
                // Coverage guards delivered assertions; it must not force the agent to invent them to fill its window.
                let missing = ids
                    .as_ref()
                    .filter(|ids| !ids.is_empty() || outcome.as_deref() != Some("unknown"))
                    .filter(|_| lease.repair_lines.is_none())
                    .map(|ids| Self::missing_summary_reports(s, &lease.issued, ids))
                    .unwrap_or_default();
                if !missing.is_empty() {
                    let ids = ids.expect("resolved coverage roots");
                    let e = KernelError::new(
                        Code::NoEvidence,
                        "the answer omits a report of its issued window; retain accepted rows and add only the missing coverage",
                    )
                    .field("answer_ids")
                    .expected(json!({"rule":"summary_window_report_coverage","missing_reports":missing,"retained_answer_ids":short_list(&ids)}));
                    coverage_prefix = Some(ids);
                    items.refused.push((*d, e.to_json()));
                } else {
                    let more = self.store_items(s, task_id, agent, &lease, attempt, &[(*d, done.clone())], &BTreeMap::new(), items.parts);
                    items.absorb(more);
                }
            } else {
                // the done line waits for the refused lines: named with them, so the repair sends it again
                items.excluded.push((*d, "a line refused in this answer".into()));
            }
        }
        items.refused.sort_by_key(|(i, _)| *i);
        items.excluded.sort_by_key(|(i, _)| *i);
        let stored_ids: Vec<RecordId> = items.stored.iter().map(|(_, id)| *id).collect();
        // which local id each stored record of this attempt had (resent lines are filtered out, so `accepted` is not positional)
        let accepted_locals: BTreeMap<String, String> =
            items.stored.iter().filter_map(|(i, id)| lines[*i].get("local_id").and_then(|x| x.as_str()).map(|n| (n.to_string(), id.short()))).collect();
        // from here on every answer says what the store already accepted, refusals included: the runner tracks accepted quotes
        // from these acknowledgements (Codex review c78060e, F07)
        let acked = short_list(&stored_ids);
        let ack = |mut v: Value| {
            v["accepted"] = json!(acked);
            v["accepted_locals"] = json!(accepted_locals);
            if v["status"] == "REPAIR_REQUIRED" {
                v["repair_scope"] = json!("accepted_prefix");
            }
            v
        };
        // the stored lines stay with the lease, by record id and by local id, for this answer and for a repair of it; a line is known
        // by what the agent sent (an extended quote too), so an exact resend of it is a no-op
        let (own, locals) = {
            let l = self.leases.get_mut(task_id).expect("checked lease");
            l.own.extend(stored_ids.iter().copied());
            for (i, id) in &items.stored {
                if let Some(name) = lines[*i].get("local_id").and_then(|x| x.as_str()) {
                    l.locals.insert(name.to_string(), *id);
                    l.line_digests.insert(name.to_string(), line_digest(&lines[*i]));
                }
            }
            (l.own.clone(), l.locals.clone())
        };
        if lease.kind == TaskKind::Extend && !lease.relate {
            *self.key_stored.entry(lease.key.clone()).or_default() += items.stored.len();
        }
        if !items.refused.is_empty() || !items.excluded.is_empty() {
            // what the store would refuse in the lines not stored is named at once, with each quote (live run 10A-3: a refusal named
            // only its index, and at temperature 0 the model sent the same lines again). Diagnostics only: the store still decides
            let mut out_idx: Vec<usize> = items.refused.iter().map(|(i, _)| *i).chain(items.excluded.iter().map(|(i, _)| *i)).collect();
            out_idx.sort_unstable();
            // as the store saw them: a reference given its "@" finds its quote here too (claude-reviewer RV-01 of 2e99ddc: on the line
            // as sent, S0 named identifiers its quote holds as missing, against the refusal itself)
            let unstored: Vec<(usize, Value)> = out_idx.iter().map(|i| (*i, canonical[*i].clone())).collect();
            let problems = self.answer_problems(s, self.leases.get(task_id).expect("checked lease"), &canonical, &unstored);
            self.stats.repairs += 1;
            self.mark_failed(task_id);
            let refused: Vec<Value> = items.refused.iter().map(|(i, e)| json!({"index": i, "local_id": lines[*i].get("local_id"), "error": e})).collect();
            let excluded: Vec<Value> =
                items.excluded.iter().map(|(i, on)| json!({"index": i, "local_id": lines[*i].get("local_id"), "rests_on": on})).collect();
            let not_stored: Vec<Value> = out_idx.iter().filter_map(|i| lines[*i].get("local_id").cloned()).collect();
            let first = items.refused.iter().min_by_key(|(i, _)| *i).map(|(_, e)| e.clone()).unwrap_or(Value::Null);
            let done = if done_at.is_some() { " The done line goes with them: it is stored once no line of the answer is refused." } else { "" };
            let mut answer = json!({"status": "REPAIR_REQUIRED", "task_id": task_id, "failed_index": out_idx.first(), "repair_scope": "rejected_items_only",
                                    "accepted": acked, "accepted_locals": accepted_locals, "refused": refused, "excluded": excluded,
                                    "not_stored": not_stored, "error": first,
                                    "repair": format!("Every other line was stored and keeps its local id. Send only the lines of not_stored: correct \
                                                       each refused line or leave it out together with the lines resting on it, and send the \
                                                       excluded lines again as they were. problems names what the store refuses in them. Where a \
                                                       problem has exact_bytes_in_section, send those bytes as the line's exact_quote, unchanged: \
                                                       they occur once and the store takes them.{done}")});
            if !problems.is_empty() {
                answer["problems"] = json!(problems);
            }
            if !extended.is_empty() {
                answer["extended"] = json!(extended);
            }
            if !referenced.is_empty() {
                answer["referenced"] = json!(referenced);
            }
            // A2 dead-letter audit: dispatcher refusals (including pre-store S0) must survive a crash as well as accepted rows.
            // Reuse the existing coordinator checkpoint transaction; no WAL framing or record admission rule changes.
            let audit_key = format!("task-repair:{task_id}:{attempt}");
            let mut checkpoint = json!({"key":audit_key,"from":0,"to":0,"context":{"task_id":task_id,"work_key":lease.key,
                "kind":lease.kind.name(),"attempt":attempt,"accepted":answer["accepted"],"refused":answer["refused"],"excluded":answer["excluded"]}});
            // the lines of this attempt whose references got their "@", stored or not (RV-02: the task checkpoint names only the last)
            if !referenced.is_empty() {
                checkpoint["context"]["referenced_bare_ids"] = json!(referenced.iter().filter_map(|x| x["local_id"].as_str()).collect::<BTreeSet<_>>());
            }
            match s.submit_operations_id(&format!("{task_id}#repair{attempt}"), "kernel", &[], Some(checkpoint)) {
                Ok(v) if v["checkpointed"] == true && v["error"].is_null() => answer["audit_persisted"] = json!(true),
                Ok(v) => {
                    answer["audit_persisted"] = json!(false);
                    answer["audit_error"] = v["error"].clone();
                }
                Err(e) => {
                    answer["audit_persisted"] = json!(false);
                    answer["audit_error"] = e.to_json();
                }
            }
            if let Some(ids) = coverage_prefix {
                let q = lease.question.as_deref().expect("summary question");
                let checkpoint = json!({"key":format!("summary-prefix:{q}"),"from":0,"to":0,"context":{
                    "question_set_revision":self.question_set_revision(),"rq_id":q,"source_task":task_id,
                    "answer_ids":ids.iter().map(|id|crate::hash::to_hex(&id.0)).collect::<Vec<_>>()}});
                match s.submit_operations_id(&format!("{task_id}#coverage{attempt}"), "kernel", &[], Some(checkpoint)) {
                    Ok(v) if v["checkpointed"] == true && v["error"].is_null() => answer["retained_answer_ids"] = json!(short_list(&ids)),
                    Ok(v) => {
                        answer["audit_persisted"] = json!(false);
                        answer["audit_error"] = v["error"].clone();
                    }
                    Err(e) => {
                        answer["audit_persisted"] = json!(false);
                        answer["audit_error"] = e.to_json();
                    }
                }
            }
            return answer;
        }
        // what this answer may cite: its own records (this attempt or an earlier accepted one, with own_refs any of the run) and the
        // records the directive showed
        let citable = |name: &str| -> Option<RecordId> {
            locals.get(name).copied().or_else(|| own.iter().chain(&lease.issued).chain(&lease.own_run).find(|r| r.short() == name).copied())
        };
        let resolve_all = |v: &Value, key: &str| -> Result<Vec<RecordId>, String> {
            v.get(key)
                .and_then(|x| x.as_array())
                .map(|a| a.iter().map(|x| x.as_str().and_then(citable).ok_or_else(|| x.to_string())).collect())
                .unwrap_or(Ok(vec![]))
        };
        // the verdict and the completion of the task: one durable transaction
        let mut ops = Vec::new();
        let mut verdict_out = Value::Null;
        if let Some((i, link, st)) = link_status {
            // what the verdict may cite: the quotes this task already got accepted (by local id) and the records shown (live run
            // 10A-3: RESOLVE_CONFLICT verdicts without basis were refused three times over without being told what to name)
            let choices = || {
                let observes = locals.iter().filter(|(_, id)| s.record(id).is_some_and(|r| r.kind == RecordKind::Observe)).map(|(n, _)| n.clone());
                json!({"based_on": {"your_quotes": observes.collect::<Vec<_>>(), "records_shown": short_list(&lease.issued)}, "verdict": ["confirm", "reject"]})
            };
            let basis = match resolve_all(&verdicts[0].1, "based_on") {
                Ok(b) => b,
                Err(bad_ref) => {
                    let e = KernelError::new(Code::UnknownLocalId, format!("{bad_ref} is neither a record of this answer nor one the directive showed"))
                        .field("based_on")
                        .expected(choices());
                    return ack(self.repair(task_id, i, e));
                }
            };
            if basis.is_empty() {
                let e = KernelError::new(Code::NoEvidence, "a verdict rests on at least one record: name it in based_on").field("based_on").expected(choices());
                return ack(self.repair(task_id, i, e));
            }
            if st == LinkStatus::Accepted {
                let l = s.link(&link).expect("leased link");
                let mut all_basis = l.basis.clone();
                all_basis.extend(&basis);
                if let Some(v) = super::pairs::scope_violation(s, l.from, &l.rel, l.to, &all_basis) {
                    let e = KernelError::new(Code::NoEvidence, "procedural assertions from different reports/heads need an explicit quoted bridge")
                        .field("verdict")
                        .expected(json!({"scope_guard":v,"verdict":"reject"}));
                    return ack(self.repair(task_id, i, e));
                }
            }
            ops.push(json!({"kind": "set_link_status", "link": crate::hash::to_hex(&link.0), "status": st.name(),
                            "expected_status": lease.link_status.map(LinkStatus::name), "basis": basis.iter().map(|b| crate::hash::to_hex(&b.0)).collect::<Vec<_>>()}));
            verdict_out = json!({"link": link.short(), "status": st.name()});
        }
        // a summary's answer: its stored done record, the stated outcome and the records it names (all of them citable)
        let mut answer = None;
        let mut context = json!({"task_id": task_id, "kind": lease.kind.name(), "agent": agent, "link_task": if link_task { Some(task_id) } else { None }});
        if !retained.is_empty() {
            context["composition"] = json!({"by": "kernel", "mode": "incremental_repair", "retained_answer_ids": short_list(&retained),
                "source_done": lease.question.as_ref().and_then(|q| self.retained.get(q)).map(|a| a.done.short())});
            // what the kernel left out of the answer is on the record, and which rows this answer replaces
            if !copies.is_empty() {
                context["composition"]["dropped_copies"] = json!(copies);
            }
            if let Some(a) = lease.question.as_ref().and_then(|q| self.retained.get(q)).filter(|a| !a.fallen.is_empty()) {
                context["composition"]["fallen_answer_ids"] = json!(short_list(&a.fallen));
            }
        }
        if !extended.is_empty() {
            context["extended_quotes"] = json!(extended.iter().map(|x| x["local_id"].clone()).collect::<Vec<_>>());
        }
        if !referenced.is_empty() {
            context["referenced_bare_ids"] = json!(referenced.iter().filter_map(|x| x["local_id"].as_str()).collect::<BTreeSet<_>>());
        }
        if let Some(source) = lease.key.strip_prefix("reread:") {
            context["origin"] = json!({"kind": "kernel_loss_reread", "generation": 1, "source_key": format!("doc:{source}"),
                "loss_score": self.strained.get(&format!("doc:{source}")).map(Loss::score), "policy": "unit_cost_round_robin_max2_per_report_first_wave"});
        }
        // a first reading with refused answers, in this lease or in leases given back before: a loss the builder's board shows
        let refusals = self.leases.get(task_id).map_or(0, |l| l.refusals) + self.failures.get(&lease.key).copied().unwrap_or(0);
        // an empty answer closing a reading after refusals gives the rest up (the runner's closure of an abandoned task)
        let loss = Loss {
            stored: self.key_stored.get(&lease.key).copied().unwrap_or(0),
            offered: self.key_offered.get(&lease.key).copied().unwrap_or(0),
            refusals,
            abandoned: lines.is_empty(),
        };
        // (the loss of a reading is taken when its answer is stored: an empty RELATE answer is no abandoned reading)
        if lease.kind == TaskKind::Extend && refusals > 0 && !lease.relate {
            loss.context(&mut context);
        }
        // an investigation that recorded nothing leaves its question open for the summaries (Codex review c78060e, F11)
        let settled: Vec<RecordId> = if lease.kind == TaskKind::Investigate {
            own.iter().filter(|r| s.record(r).is_some_and(|x| matches!(x.kind, RecordKind::Claim | RecordKind::Question))).copied().collect()
        } else {
            Vec::new()
        };
        if !settled.is_empty() {
            context["settled"] = json!(settled.iter().map(|r| crate::hash::to_hex(&r.0)).collect::<Vec<_>>());
        }
        if let Some(outcome) = outcome {
            context["delivery_audit"] = json!({"repair_count":refusals,"had_refusals":refusals>0,"retained_rows":retained.len(),
                "partial_declared":lines[dones[0]]["text"].as_str().is_some_and(|t|t.starts_with("Partial answer:"))});
            let done_line = &lines[dones[0]];
            let Some(done) = done_line.get("local_id").and_then(|x| x.as_str()).and_then(|n| locals.get(n).copied()) else {
                let e = KernelError::new(Code::MissingField, "the done line needs its local_id").field("local_id");
                return ack(self.repair(task_id, dones[0], e));
            };
            let ids = match resolve_all(done_line, "answer_ids") {
                Ok(ids) => distinct_ids(ids),
                Err(bad_ref) => {
                    let e = KernelError::new(Code::UnknownLocalId, format!("{bad_ref} in answer_ids is not a record of this answer")).field("answer_ids");
                    return ack(self.repair(task_id, lines.len(), e));
                }
            };
            context["rq_id"] = json!(lease.question);
            context["question_set_revision"] = json!(self.question_set_revision());
            context["done"] = json!(crate::hash::to_hex(&done.0));
            context["outcome"] = json!(outcome);
            context["answer_ids"] = json!(ids.iter().map(|r| crate::hash::to_hex(&r.0)).collect::<Vec<_>>());
            answer = Some(Answer { done, outcome, ids, fallen: Vec::new() });
        }
        context = self.circle_tag(context);
        if lease.key.starts_with("gap") {
            // the order of completion and what the pack recorded: the tier rule reads them back (SPEC_V02_GAP_PASS section 4)
            context["gap"] = json!({"order": self.gap_order, "recorded": own.len()});
        }
        if lease.relate {
            // the reading's checkpoint stays what it was (its loss, its origin) and the turn only adds its mark: a recovery sees the
            // reading as the live dispatcher does (claude-reviewer's RV-01 of 8509eb18: the close wrote over it)
            if let Some(reading) = s.checkpoint(&task_checkpoint(&lease.key)) {
                context = reading["context"].clone();
            }
            context["relate"] = json!({"task_id": task_id, "agent": agent, "lines": lines.len()});
        }
        let checkpoint = json!({"key": task_checkpoint(&lease.key), "from": 0, "to": 0, "context": context});
        if self.cfg.versions && lease.kind == TaskKind::Change {
            ops.push(json!({"kind":"checkpoint","key":format!("version:closed:{task_id}"),"from":0,"to":0,"context":{"reason":"completed"}}));
        }
        let done_attempt = self.next_attempt(task_id);
        match s.submit_operations_id(&format!("{task_id}#done{done_attempt}"), agent, &ops, Some(checkpoint)) {
            Ok(r) if r["error"].is_null() && r["checkpointed"] == true => {}
            Ok(r) => {
                self.stats.repairs += 1;
                self.mark_failed(task_id);
                return json!({"status": "REPAIR_REQUIRED", "task_id": task_id, "failed_index": lines.len(), "repair_scope": "accepted_prefix", "accepted": acked,
                              "accepted_locals": accepted_locals, "error": r["error"]});
            }
            Err(e) => return ack(self.repair(task_id, lines.len(), e)),
        }
        if let Some((_, _, st)) = link_status {
            if st == LinkStatus::Accepted {
                self.stats.confirmed += 1;
            } else {
                self.stats.rejected += 1;
            }
        }
        if link_task {
            self.link_tasks.insert(task_id.to_string());
        }
        if let (Some(q), Some(a)) = (lease.question.clone(), answer) {
            self.retained.remove(&q);
            self.answered.insert(q, a);
        }
        if !settled.is_empty() {
            self.settled.insert(lease.key.clone(), settled);
        }
        if lease.kind == TaskKind::Extend && refusals > 0 && !lease.relate {
            self.strained.insert(lease.key.clone(), loss);
        }
        // the hint profile: a stored reading answer opens the task's RELATE turn instead of closing it
        if self.cfg.relate_hints && lease.kind == TaskKind::Extend && !lease.relate {
            let own: Vec<RecordId> = self.leases.get(task_id).map(|l| l.own.clone()).unwrap_or_default();
            let claims: Vec<RecordId> = own.into_iter().filter(|id| s.record(id).is_some_and(|r| r.kind == RecordKind::Claim)).collect();
            if let Some((prompt, shown)) = self.relate_prompt(s, task_id, &claims) {
                let ttl = self.lease_ms_for(TaskKind::Extend);
                // the reading is stored and checkpointed, as a recovery sees it: a RELATE turn given back, refused or run out gives
                // up only the turn, and the section is not issued again
                self.handled.insert(lease.key.clone());
                self.stats.committed += 1;
                let l = self.leases.get_mut(task_id).expect("checked lease");
                l.relate = true;
                l.failed = false;
                l.refusals = 0;
                l.issued.extend(shown);
                // one more model call: the turn gets a reading task's full time again
                l.expires_ms = now + ttl;
                self.stats.relate_turns += 1;
                return json!({"status": "RELATE", "task_id": task_id, "accepted": acked, "accepted_locals": accepted_locals, "prompt": prompt});
            }
        }
        if lease.key.starts_with("gap") {
            self.gap_order += 1;
        }
        self.handled.insert(lease.key.clone());
        self.leases.remove(task_id);
        if !lease.relate {
            self.stats.committed += 1;
        }
        let mut done = json!({"status": "COMMITTED", "task_id": task_id, "accepted": acked, "accepted_locals": accepted_locals, "verdict": verdict_out});
        if !extended.is_empty() {
            done["extended"] = json!(extended);
        }
        if !referenced.is_empty() {
            done["referenced"] = json!(referenced);
        }
        if !copies.is_empty() {
            done["dropped_copies"] = json!(copies);
        }
        done
    }

    /// The RELATE turn of a reading task (`relate_hints`): each of its claims with the claims of other report dates that share its
    /// words and the quotes they rest on, all dated; None when no claim has one. Returns the prompt and the records it shows.
    fn relate_prompt<S: AuditStore>(&self, s: &S, task_id: &str, claims: &[RecordId]) -> Option<(String, Vec<RecordId>)> {
        let related = super::quality::evolution::related(s, claims, RELATE_HINTS);
        if related.iter().all(|(_, hints)| hints.is_empty()) {
            return None;
        }
        let dated = |r: &RecordView| match (r.kind, r.doc_id.as_deref()) {
            (RecordKind::Observe, Some(doc)) => rec_line_dated(r, &super::quality::evolution::date(s, doc)),
            _ => rec_line(r),
        };
        let mut shown = Vec::new();
        let mut blocks = Vec::new();
        for (claim, hints) in related.iter().filter(|(_, hints)| !hints.is_empty()) {
            let mut lines: Vec<String> = super::pairs::cone(s, &[*claim]).iter().map(dated).collect();
            lines.push("    related (hints chosen by shared words, not evidence):".into());
            for hint in hints {
                for r in super::pairs::cone(s, &[*hint]) {
                    if !shown.contains(&r.id) {
                        shown.push(r.id);
                    }
                    lines.push(format!("    {}", dated(&r)));
                }
            }
            blocks.push(lines.join("\n"));
        }
        let prefix = format!("{}_", task_id.split('-').next().unwrap_or("t").to_lowercase());
        let max_lines = self.max_lines(TaskKind::Extend);
        let prompt = format!(
            "You are one agent of an audit swarm over {corpus}. Your answer to this reading task is stored. \
             TASK RELATE: below, each of your claims comes with claims of reports of other dates that share its words: hints chosen by \
             words, not evidence. When a hint states an earlier or a later state of the same thing and scope as your claim, write one \
             claim of the change: what held at the earlier report date and what the later report date replaced, removed, deprecated or \
             only qualified. Decide the direction by the report dates shown, not by which report you read first. Its based_on names \
             the observe @ids of both sides, and only when their quotes show the change; its stance is superseded when the later state \
             replaces the earlier one, qualified when it only limits or conditions it. Write only claim lines, at most {max_lines}, each \
             with a new local_id that starts with {prefix}r; no observe, question, hypothesis or relation lines. If no hint is a change \
             of the same thing, reply exactly [].\nYOUR CLAIMS, EACH WITH RELATED RECORDS:\n{}\n\nRecord format (one JSON object per \
             line, no code fences, nothing else):\n  {{\"kind\":\"claim\",\"local_id\":\"{prefix}r1\",\"text\":\"<= 240 chars\",\"subject\":\"...\",\
             \"predicate\":\"...\",\"object\":\"...\",\"stance\":\"superseded|qualified\",\"as_of\":null,\"based_on\":[\"@observe of the earlier \
             report\",\"@observe of the later report\"]}}",
            blocks.join("\n\n"),
            corpus = self.cfg.corpus
        );
        Some((prompt, shown))
    }

    fn next_attempt(&mut self, task_id: &str) -> u32 {
        let l = self.leases.get_mut(task_id).expect("checked lease");
        l.attempt += 1;
        l.attempt
    }

    /// Heartbeat: a live lease of `agent` runs one more TTL from `now` (the agent cannot choose a longer one).
    pub fn renew(&mut self, task_id: &str, agent: &str, now: u64) -> Value {
        self.expire(now);
        let ttl = self.leases.get(task_id).map(|l| self.lease_ms_for(l.kind)).unwrap_or_else(|| self.lease_ms());
        let fixed = self.cfg.circles.is_some();
        match self.leases.get_mut(task_id) {
            Some(l) if l.agent == agent => {
                if !fixed {
                    l.expires_ms = now + ttl;
                }
                let mut out = json!({"status": "RENEWED", "task_id": task_id, "expires_at_ms": l.expires_ms});
                if fixed {
                    out["response_deadline_fixed"] = json!(true);
                }
                out
            }
            Some(_) => json!({"status": "error", "code": "TASK_NOT_OWNED", "task_id": task_id}),
            None => json!({"status": "STALE_TASK", "task_id": task_id, "message": "unknown or expired task: acquire again"}),
        }
    }

    /// The initial reading and its bounded automatic repair wave have finished. Requests and pair verification may follow.
    pub fn reading_done<S: AuditStore>(&self, s: &S) -> bool {
        !self
            .open_work(s, &Flags::of(s))
            .iter()
            .any(|w| matches!(w.0, TaskKind::Extend | TaskKind::Change) || w.1.starts_with("reread:") || w.1.starts_with("gap"))
            && !self.leases.values().any(|l| matches!(l.kind, TaskKind::Extend | TaskKind::Change) || l.key.starts_with("reread:") || l.key.starts_with("gap"))
    }

    pub fn attestation_coverage<S: AuditStore>(&self, s: &S, builder_caught_up: bool) -> Option<Value> {
        if !builder_caught_up
            || !self.reading_done(s)
            || !self.circles_final()
            || self.leases.values().any(|l| matches!(l.kind, TaskKind::Extend | TaskKind::Request | TaskKind::Build))
        {
            return None;
        }
        if self.reported_unresolved(s).iter().any(|k| k.starts_with("build:") || k.starts_with("reread:")) {
            return None;
        }
        let keys = if self.cfg.zones.is_empty() {
            s.docs()
                .iter()
                .flat_map(|d| {
                    sections(d, &s.doc_text(d).unwrap_or_default(), self.cfg.section_bytes)
                        .iter()
                        .enumerate()
                        .map(|(k, _)| format!("doc:{d}#{k}"))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        } else {
            (0..self.cfg.zones.len()).map(|n| format!("zone:{n}")).collect()
        };
        let unread =
            keys.iter().filter(|k| !self.handled.contains(*k) || s.checkpoint(&task_checkpoint(k)).is_none_or(|c| c["context"]["unresolved"] == true)).count();
        if unread > 0 {
            return None;
        }
        let mut out = json!({"reading_done":true,"waves_closed":true,"builder_caught_up":true,"unread_units":0,"read_units":keys.len(),"reports":s.docs().len(),"read_bytes":s.docs().iter().filter_map(|d|s.doc_text(d)).map(|s|s.len()).sum::<usize>(),"meaning":"all initial read units committed; not a guarantee of semantic extraction completeness"});
        // the gap pass, when the run has one: what each read unit came to (SPEC_V02_GAP_PASS section 9)
        if self.cfg.gap.limit > 0 {
            out["gap_pass"] = self.gap_report(s);
        }
        Some(out)
    }

    /// Read-only offline diagnostics for the consilium gates. Uses the exact production queue and summary window, without
    /// issuing a lease, storing a record, or calling a provider.
    #[doc(hidden)]
    pub fn offline_diagnostics<S: AuditStore>(&self, s: &S) -> Value {
        let f = Flags::of(s);
        let rereads: Vec<Value> = self
            .auto_reread_work(s)
            .iter()
            .map(|w| {
                json!({"key":w.1,
            "score":w.1.strip_prefix("reread:").and_then(|x|self.strained.get(&format!("doc:{x}"))).map(Loss::score)})
            })
            .collect();
        let windows: BTreeMap<String, Value> = self
            .questions
            .iter()
            .map(|q| {
                let usable = s.usable_links();
                let links: Vec<LinkView> = s
                    .links()
                    .into_iter()
                    .filter(|l| l.status == LinkStatus::Accepted && usable.as_ref().map_or_else(|| s.link_usable(&l.id), |u| u.contains(&l.id)))
                    .collect();
                let (_, chosen) = self.summary_support(s, &f, q, &links, true);
                let (prompt, _, issued) = self.summarize_prompt(s, &f, &q.id, "offline-summary");
                let shown: BTreeSet<RecordId> = issued.iter().copied().collect();
                let relevant: BTreeSet<String> =
                    super::pairs::cone(s, &chosen.iter().copied().collect::<Vec<_>>()).into_iter().filter_map(|r| r.doc_id).collect();
                let quoted: BTreeSet<String> = issued.iter().filter_map(|id| s.record(id)).filter_map(|r| r.doc_id).collect();
                let one_sided: Vec<Value> = links
                    .iter()
                    .filter(|l| l.rel == "contradicts" && (shown.contains(&l.from) != shown.contains(&l.to)))
                    .map(|l| json!({"from":l.from.short(),"to":l.to.short()}))
                    .collect();
                let superseded: Vec<Value> = links
                    .iter()
                    .filter(|l| l.rel == "supersedes" && shown.contains(&l.to))
                    .map(|l| json!({"old":l.to.short(),"new":l.from.short(),"new_shown":shown.contains(&l.from)}))
                    .collect();
                (
                    q.id.clone(),
                    json!({"eligible":short_list(&chosen.iter().copied().collect::<Vec<_>>()),"issued":short_list(&issued),"prompt":prompt,
                    "reports_relevant":relevant,"reports_quoted":quoted,"one_sided_conflicts":one_sided,"superseded_old_shown":superseded}),
                )
            })
            .collect();
        json!({"rereads":rereads,"summary_windows":windows})
    }

    /// First readings in flight (the permits backpressure counts).
    pub fn extend_leases(&self) -> usize {
        self.leases.values().filter(|l| l.kind == TaskKind::Extend).count()
    }

    /// Open leases (the kernel is idle when there are none).
    pub fn leases(&self) -> usize {
        self.leases.len()
    }

    /// Offline replay of a recorded run only (examples/replay_step1.rs), never a live one: the lease a recorded task had, with the
    /// records it had stored under its local ids, so a recorded answer goes through `submit` as it would now. Its store submissions
    /// are numbered from 1001 on, apart from the recorded ones of the same task.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn replay_lease(
        &mut self,
        task_id: &str,
        agent: &str,
        kind: TaskKind,
        key: &str,
        scope: Scope,
        issued: Vec<RecordId>,
        locals: BTreeMap<String, RecordId>,
        accepted_lines: &[Value],
    ) {
        let lease = Lease {
            agent: agent.to_string(),
            kind,
            key: key.to_string(),
            scope,
            expires_ms: u64::MAX,
            link: None,
            link_status: None,
            question: key.strip_prefix("rq:").map(str::to_string),
            issued,
            own_run: Vec::new(),
            attempt: 1000,
            own: locals.values().copied().collect(),
            locals,
            line_digests: accepted_lines.iter().filter_map(|v| v["local_id"].as_str().map(|n| (n.to_string(), line_digest(v)))).collect(),
            failed: false,
            refusals: 0,
            relate: false,
            repair_lines: None,
        };
        self.leases.insert(task_id.to_string(), lease);
    }

    /// `release`, and when the key is given up as unresolved, a durable record of that (a `task:<key>` checkpoint marked
    /// unresolved, restored by `recover`), so a restart does not issue it again (Codex review 6d6bcf9, P2).
    pub fn release_durable<S: AuditStore>(&mut self, s: &mut S, task_id: &str, agent: &str) -> Value {
        if self.cfg.versions && self.leases.get(task_id).is_some_and(|l| l.agent == agent && l.kind == TaskKind::Change) {
            self.pending_version_closures.insert(task_id.into(), ("released".into(), 0));
            if let Err(e) = self.persist_version_closures(s) {
                return json!({"status":"error","code":"CHANGE_CLOSURE_NOT_DURABLE","error":e.to_json()});
            }
        }
        if self.cfg.agent_attempts.is_some() {
            if let Some(l) = self.leases.get(task_id).filter(|l| l.agent == agent && l.failed).cloned() {
                match self.agent_failure_record(s, &l.key, task_id, agent, "FAILED_LEASE_RELEASED") {
                    Ok(e) => {
                        self.leases.remove(task_id);
                        return json!({"status":"RELEASED","task_id":task_id,"unresolved":e["unresolved"],"failures":e["failures"]});
                    }
                    Err(error) => return json!({"status":"error","code":"AGENT_FAILURE_CHECKPOINT_REFUSED","error":error}),
                }
            }
        }
        let key = self.leases.get(task_id).map(|l| l.key.clone());
        let was = key.as_ref().is_some_and(|k| self.unresolved.contains(k));
        let out = self.release(task_id, agent);
        if let Some(key) = key.filter(|k| !was && self.unresolved.contains(k)) {
            if let Err(e) = self.write_unresolved(s, &key, task_id, 0) {
                // kept for a retry at the next call with the store (review of 4381fe7)
                self.pending_unresolved.push((key, task_id.to_string(), 1));
                return json!({"status": "RELEASED", "task_id": task_id, "unresolved": true, "durable": false, "error": e});
            }
        }
        out
    }

    /// Write the keys given up when failed leases expired (Codex review d7d9a49, D06); the server calls it after every call with the
    /// store at hand. A key whose record could not be written stays queued.
    pub fn persist_unresolved<S: AuditStore>(&mut self, s: &mut S) -> Vec<Value> {
        let mut errors = Vec::new();
        for (key, attempt, who) in std::mem::take(&mut self.pending_agent_failures) {
            match self.agent_failure_record(s, &key, &attempt, &who, "LEASE_EXPIRED") {
                Ok(_) => (),
                Err(e) => {
                    errors.push(e);
                    self.pending_agent_failures.push((key, attempt, who));
                }
            }
        }
        for (key, task_id, attempt) in std::mem::take(&mut self.pending_unresolved) {
            if let Err(e) = self.write_unresolved(s, &key, &task_id, attempt) {
                errors.push(e);
                self.pending_unresolved.push((key, task_id, attempt + 1));
            }
        }
        errors
    }

    /// The durable record of a key given up as unresolved; a research question's is bound to its question set (Codex review
    /// c78060e, F05).
    fn write_unresolved<S: AuditStore>(&self, s: &mut S, key: &str, task_id: &str, attempt: u32) -> Result<(), Value> {
        let mut context = json!({"task_id": task_id, "unresolved": true, "failures": self.failures.get(key)});
        if let Some(loss) = self.strained.get(key) {
            loss.context(&mut context);
        }
        if self.no_source.contains(key) {
            context["reason"] = json!(NO_SECTION_MATCHED);
        }
        if task_id.starts_with("noreader-") {
            context["reason"] = json!("NO_INDEPENDENT_READER");
        }
        if let Some(q) = key.strip_prefix("rq:") {
            context["rq_id"] = json!(q);
            context["question_set_revision"] = json!(self.question_set_revision());
            if let Some(a) = self.retained.get(q) {
                context["retained_answer"] = json!({"done":crate::hash::to_hex(&a.done.0),"outcome":a.outcome,
                    "answer_ids":a.ids.iter().map(|id|crate::hash::to_hex(&id.0)).collect::<Vec<_>>(),
                    "fallen_ids":a.fallen.iter().map(|id|crate::hash::to_hex(&id.0)).collect::<Vec<_>>()});
            }
        }
        let checkpoint = json!({"key": task_checkpoint(key), "from": 0, "to": 0, "context": context});
        // a retry is a new submission: a refused one keeps its receipt and would answer the same request with the same refusal
        let id = if attempt == 0 { format!("{task_id}#unresolved") } else { format!("{task_id}#retry{attempt}#unresolved") };
        match s.submit_operations_id(&id, "kernel", &[], Some(checkpoint)) {
            // only a written checkpoint counts (review of 4381fe7: a checkpointed:false reply was taken for one)
            Ok(r) if r["checkpointed"] == true && r["error"].is_null() => Ok(()),
            Ok(r) => Err(if r["error"].is_null() { json!({"code": "NOT_CHECKPOINTED", "reply": r}) } else { r["error"].clone() }),
            Err(e) => Err(e.to_json()),
        }
    }

    pub fn release(&mut self, task_id: &str, agent: &str) -> Value {
        match self.leases.get(task_id) {
            Some(l) if l.agent == agent => {
                let (key, failed) = (l.key.clone(), l.failed);
                if self.cfg.versions && l.kind == TaskKind::Change {
                    self.pending_version_closures.entry(task_id.into()).or_insert(("released".into(), 0));
                }
                self.leases.remove(task_id);
                if failed {
                    self.note_failure(&key);
                }
                json!({"status": "RELEASED", "task_id": task_id, "unresolved": self.unresolved.contains(&key)})
            }
            Some(_) => json!({"status": "error", "code": "TASK_NOT_OWNED"}),
            None => json!({"status": "STALE_TASK", "task_id": task_id}),
        }
    }

    /// The research questions as one revision (part of the terminal receipt).
    pub fn question_set_revision(&self) -> String {
        // the structural selectors join the revision only when a question has them (earlier questions keep their revision)
        let qs: Vec<Value> = self
            .questions
            .iter()
            .map(|q| {
                let mut v = json!([q.id, q.text, q.about]);
                if !(q.stances.is_empty() && q.relations.is_empty() && q.concept_types.is_empty()) {
                    v.as_array_mut().expect("an array").push(json!({"stances": q.stances, "relations": q.relations, "concept_types": q.concept_types}));
                }
                v
            })
            .collect();
        crate::hash::to_hex(&crate::hash::sha256(crate::jcs::to_jcs(&json!(qs)).as_bytes()))
    }

    fn delivery_audit<S: AuditStore>(s: &S, q: &str, done: RecordId) -> Value {
        s.checkpoint(&task_checkpoint(&format!("rq:{q}")))
            .filter(|c| c["context"]["done"] == crate::hash::to_hex(&done.0))
            .map(|c| c["context"]["delivery_audit"].clone())
            .unwrap_or(Value::Null)
    }

    /// Contract v0.1 R7: the terminal receipt, cut on one state - only when the run is complete. The caller adds what only the
    /// kernel store knows (engine root, session root, WAL head, corpus manifest hash).
    pub fn terminal_receipt<S: AuditStore>(&self, s: &S, builder_cursor: u64, run_id: &str) -> Option<Value> {
        if !self.pending_agent_failures.is_empty() {
            return None;
        }
        if !self.circles_final() {
            return None;
        }

        let c = self.completion(s, builder_cursor >= s.head());
        if c["complete"] != true || builder_cursor != s.head() {
            return None;
        }
        let unknown: Vec<&String> = self.answered.iter().filter(|(_, a)| a.outcome == "unknown").map(|(q, _)| q).collect();
        let mut outcomes: BTreeMap<&String, Value> = self
            .answered
            .iter()
            .map(|(q, a)| {
                (
                    q,
                    json!({"outcome": a.outcome, "done": a.done.short(), "answer_ids": short_list(&a.ids),
                "delivery_audit":Self::delivery_audit(s,q,a.done)}),
                )
            })
            .collect();
        // every summary of the question was refused: the run produced no answer to it. A processing failure, not an unknown of the
        // sources (Codex review c78060e, F05)
        let mut failed: Vec<&String> = Vec::new();
        for q in self.questions.iter().filter(|q| !self.answered.contains_key(&q.id) && self.given_up(q)) {
            failed.push(&q.id);
            let retained = self.accepted_outcomes(s).get(&q.id).cloned();
            outcomes.insert(
                &q.id,
                retained
                    .map(|mut v| {
                        v["unresolved"] = json!(true);
                        v["reason"] = json!("incremental repair failed; independent rows retained");
                        v
                    })
                    .unwrap_or_else(|| {
                        json!({"outcome": "not_answered", "done": null, "answer_ids": [], "unresolved": true,
                "reason": if self.cfg.agent_attempts.is_some() {"agent attempt limit reached; summary not completed"} else {"every summary of this question was refused"}})
                    }),
            );
        }
        let (rev, hash) = s.ontology_version();
        Some(json!({"run_id": run_id, "question_set_revision": self.question_set_revision(), "audit_ontology_revision": rev,
                    "audit_ontology_hash": crate::hash::to_hex(&hash), "ingest_watermark": s.head(), "builder_cursor": builder_cursor,
                    "audit_root": crate::hash::to_hex(&s.root()), "answered": self.answered.keys().collect::<Vec<_>>(),
                    "outcomes": outcomes, "unknown_outcomes": unknown, "not_answered": failed, "unresolved": self.reported_unresolved(s)}))
    }

    /// The research questions answered so far whose answers still hold, for a run that stops before it is terminal (Codex's analysis
    /// of 10A-4, F01: an accepted RQ1 was lost to the export because only a terminal receipt carried outcomes). Not a terminal receipt.
    pub fn accepted_outcomes<S: AuditStore>(&self, s: &S) -> Value {
        let f = Flags::of(s);
        let held: BTreeMap<&String, Value> = self
            .answered
            .iter()
            .chain(&self.retained)
            .filter_map(|(q, a)| {
                if Self::answer_holds(s, &f, q, a) && !self.retained.contains_key(q) {
                    Some((
                        q,
                        json!({"outcome": a.outcome, "done": a.done.short(), "answer_ids": short_list(&a.ids), "partial": true,
                    "delivery_audit":Self::delivery_audit(s,q,a.done)}),
                    ))
                } else {
                    let ids: Vec<RecordId> = a.ids.iter().copied().filter(|id| f.support(s, id)).collect();
                    (!ids.is_empty()).then(|| {
                        (
                            q,
                            json!({"outcome": a.outcome, "done": null, "source_done": a.done.short(),
                    "answer_ids": short_list(&ids), "partial": true, "requires_repair": true}),
                        )
                    })
                }
            })
            .collect();
        json!(held)
    }

    /// Contract §6: the run is complete only when the swarm, the builder and the kernel are all done.
    pub fn completion<S: AuditStore>(&self, s: &S, builder_caught_up: bool) -> Value {
        let f = Flags::of(s);
        let open = self.open_work(s, &f).len();
        let holds = |q: &ResearchQuestion| self.answered.get(&q.id).is_some_and(|a| Self::answer_holds(s, &f, &q.id, a)) || self.given_up(q);
        let swarm = open == 0 && self.questions.iter().all(holds);
        let kernel = self.leases.is_empty();
        json!({"swarm_done": swarm, "builder_caught_up": builder_caught_up, "kernel_idle": kernel, "complete": swarm && builder_caught_up && kernel && self.circles_final(),
               "open_work": open, "answered": self.answered.len(), "questions": self.questions.len(), "unresolved": self.reported_unresolved(s)})
    }
}

#[cfg(test)]
mod tests {
    use super::super::builder::{Builder, BuilderConfig};
    use super::super::mem::MemStore;
    use super::*;

    #[test]
    fn a_retained_row_takes_its_whole_unit_first_and_is_marked_only_beyond_the_hard_bound() {
        // Codex 28.10, D07: retained old state A, its unit A <- B <- C with their quotes (6 records), a window of 4
        let id = |n: u8| RecordId(crate::hash::sha256(&[n]));
        let unit: BTreeSet<RecordId> = (1..=6).map(id).collect();
        let retained = vec![(id(1), unit.clone())];
        let other = vec![[id(7), id(8)].into_iter().collect::<BTreeSet<_>>()];
        // the time option: the retained row's whole unit goes in before the configured window; nothing is marked
        let (shown, fit, partial, _) = place(&retained, &[], &other, 4, 256, true);
        assert!(unit.is_subset(&shown) && partial.is_empty() && fit == 0, "{shown:?}");
        // beyond the store's hard bound the retained row stays (the next done keeps it) and is returned as partial
        let (shown, _, partial, _) = place(&retained, &[], &other, 4, 5, true);
        assert!(shown.contains(&id(1)) && !shown.contains(&id(6)) && partial == vec![id(1)], "{shown:?}");
        // without the option the window is as it always was: the retained id, its unit only where it fits, no marks
        let (shown, fit, partial, _) = place(&retained, &[], &other, 4, 256, false);
        assert_eq!((shown.len(), fit, partial.len()), (3, 1, 0), "{shown:?}");
    }

    #[test]
    fn a_live_support_goes_in_after_the_retained_rows_and_before_the_claims_by_the_question_in_the_same_budget() {
        let id = |n: u8| RecordId(crate::hash::sha256(&[n]));
        let set = |ns: &[u8]| ns.iter().map(|n| id(*n)).collect::<BTreeSet<_>>();
        let retained = vec![(id(1), set(&[1, 2]))];
        let live = vec![set(&[3, 4]), set(&[5, 6, 7]), set(&[8, 9])];
        let other = vec![set(&[10, 11]), set(&[3, 4])];
        // a budget of 6: the retained unit (2), the first live unit (2), the third (2); the second (3) does not fit, nor any other
        // unit but the one already shown, which the window counts as a claim by the question
        let (shown, fit, partial, placed) = place(&retained, &live, &other, 6, 256, false);
        assert_eq!(placed, vec![0, 2], "{shown:?}");
        assert_eq!(shown, set(&[1, 2, 3, 4, 8, 9]));
        assert_eq!((fit, partial.len()), (1, 0));
        // the budget does not grow: with no live support the same budget takes the claims by the question
        let (shown, fit, _, placed) = place(&retained, &[], &other, 6, 256, false);
        assert!(placed.is_empty() && fit == 2 && shown == set(&[1, 2, 3, 4, 10, 11]), "{shown:?}");
    }

    #[test]
    fn the_live_support_takes_the_best_of_each_fallen_row_in_turns_with_caps_and_no_copies() {
        let id = |n: u8| RecordId(crate::hash::sha256(&[n]));
        let ids = |ns: std::ops::Range<u8>| ns.map(id).collect::<Vec<_>>();
        // one row: its best four
        assert_eq!(take_in_turns(&[ids(1..9)], LIVE_SUPPORT_PER_ROW, LIVE_SUPPORT), ids(1..5));
        // two rows sharing their best claim: in turns, the shared one once, and the second row takes its next
        let ranked = vec![vec![id(1), id(2), id(3)], vec![id(1), id(9), id(8)]];
        assert_eq!(take_in_turns(&ranked, LIVE_SUPPORT_PER_ROW, LIVE_SUPPORT), vec![id(1), id(9), id(2), id(8), id(3)]);
        // five rows of five claims each: four turns would give twenty, the cap keeps twelve, the first turns first
        let ranked: Vec<Vec<RecordId>> = (0..5u8).map(|r| ids(10 * r + 10..10 * r + 15)).collect();
        let out = take_in_turns(&ranked, LIVE_SUPPORT_PER_ROW, LIVE_SUPPORT);
        assert_eq!(out.len(), LIVE_SUPPORT);
        assert_eq!(out[..5].to_vec(), vec![id(10), id(20), id(30), id(40), id(50)]);
        assert_eq!(out[10..].to_vec(), vec![id(12), id(22)]);
        // the same lists give the same support
        assert_eq!(take_in_turns(&ranked, LIVE_SUPPORT_PER_ROW, LIVE_SUPPORT), out);
    }

    const R1: &str = "# Classifier MVP\nDiffering validator versions -> warning only.\nSame canonical/hash remains a candidate only.\n\n# Limits\nVersion negotiation is future work.\n";
    const R2: &str = "# Compatibility gate\nA validator version difference is now blocking.\n";

    fn setup() -> (MemStore, Dispatcher, Builder) {
        let s = MemStore::new(&[("r1", R1), ("r2", R2)], &["Rule", "Component"]);
        let q = ResearchQuestion {
            id: "RQ1".into(),
            text: "How did the severity of validator version differences change?".into(),
            about: vec!["validator version".into()],
            ..Default::default()
        };
        (s, Dispatcher::new(DispatchConfig { section_bytes: 80, ..Default::default() }, vec![q]), Builder::new(BuilderConfig::default()))
    }

    #[test]
    fn common_answer_guidance_is_present_with_or_without_temporal_window_metadata() {
        for temporal in [false, true] {
            let (mut s, mut d, mut b) = setup();
            d.questions[0].about = vec!["ABOUT_ONLY_SENTINEL".into()];
            s.checkpoints.insert("audit:mcp:coverage".into(), json!({"context":{"graph_quality":{"temporal_summary":temporal}}}));
            let task = after_reading(&mut d, &mut s, &mut b, "w1", 0);
            assert_eq!(task["kind"], "SUMMARIZE", "{task}");
            let prompt = task["prompt"].as_str().unwrap();
            assert_eq!(prompt.matches(super::super::answer_guidance::text()).count(), 1);
            assert!(!prompt.contains("ABOUT_ONLY_SENTINEL"));
            assert!(prompt.contains("at most 200 characters; more than 240 is refused"));
            assert_eq!(prompt.contains("RECORDS run in report-date order"), temporal);
            assert!(prompt.contains("WINDOW:") && prompt.contains("ACCEPTED LINKS:") && prompt.contains("OPEN QUESTIONS"));
        }
    }

    /// Variant D: answer every section empty and let the builder catch up; the first other directive (leased to `agent`) is returned.
    fn after_reading(d: &mut Dispatcher, s: &mut MemStore, b: &mut Builder, agent: &str, now: u64) -> Value {
        loop {
            while let Some(c) = b.next_card(s) {
                b.submit(s, &c.card_id, &[]);
            }
            let t = d.acquire(s, agent, b.caught_up(s), now);
            if t["kind"] != "EXTEND" {
                return t;
            }
            assert_eq!(d.submit(s, t["task_id"].as_str().unwrap(), agent, &[], now)["status"], "COMMITTED");
        }
    }

    #[test]
    fn an_agent_limited_to_link_checks_gets_no_reading_and_no_summary() {
        // one strong reader in place of the swarm: a second agent only checks the links between its claims
        let (mut s, mut d, mut b) = setup();
        let checker = [TaskKind::VerifyLink, TaskKind::ResolveConflict];
        assert_eq!(d.acquire_for(&s, "w2", true, None, Some(&checker), 0)["status"], "WAIT", "no reading for the checker");
        let first = d.acquire_for(&s, "w1", true, None, None, 0);
        assert_eq!(first["kind"], "EXTEND", "the reader reads");
        d.release(first["task_id"].as_str().unwrap(), "w1");
        let t = after_reading(&mut d, &mut s, &mut b, "w1", 0);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        d.release(t["task_id"].as_str().unwrap(), "w1");
        assert_eq!(d.acquire_for(&s, "w2", b.caught_up(&s), None, Some(&checker), 0)["status"], "WAIT", "no summary for the checker");
        assert_eq!(TaskKind::parse("VERIFY_LINK"), Some(TaskKind::VerifyLink));
        assert_eq!(TaskKind::parse("verify_link"), None);
    }

    fn claim_on(d: &mut Dispatcher, s: &mut MemStore, t: &Value, agent: &str, quote: &str, text: &str, now: u64) -> Value {
        let p = t["local_id_prefix"].as_str().unwrap();
        let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
        d.submit(
            s,
            t["task_id"].as_str().unwrap(),
            agent,
            &[
                json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": doc, "exact_quote": quote, "terms": ["validator version"]}),
                json!({"kind": "claim", "local_id": format!("{p}c1"), "text": text, "subject": "validator version", "stance": "reported", "based_on": [format!("{p}o1")]}),
            ],
            now,
        )
    }

    #[test]
    fn an_answer_is_stored_item_by_item_and_explicit_quote_bytes_are_preserved() {
        // the consilium of 10A-17 (Gemini's plan step 1): a report wrapped at 80 columns, quoted one line as the directive asks
        const DOC: &str = "# Run-set\nThe accepted run-set expected identity changed naturally from\n`4c8a2e19` to `7d3f5b02` because the version counts.\n";
        let mut s = MemStore::new(&[("r1", DOC)], &["Rule"]);
        let mut d = Dispatcher::new(DispatchConfig { section_bytes: 4000, ..Default::default() }, vec![]);
        let t = d.acquire(&s, "w1", true, 0);
        let (id, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
        let whole = "The accepted run-set expected identity changed naturally from\n`4c8a2e19` to `7d3f5b02` because the version counts.";
        let lines = [
            json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "r1", "exact_quote": whole, "terms": ["run-set identity"]}),
            json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "The expected run-set identity changed.", "subject": "run-set identity", "stance": "reported", "based_on": [format!("{p}o1")]}),
            json!({"kind": "observe", "local_id": format!("{p}o2"), "doc_id": "r1", "exact_quote": "words that are nowhere in it", "terms": ["x"]}),
            json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "Something else holds.", "subject": "x", "stance": "reported", "based_on": [format!("{p}o2")]}),
            json!({"kind": "claim", "local_id": format!("{p}c3"), "text": "The version counts.", "subject": "version", "stance": "reported", "based_on": [format!("{p}o1")]}),
        ];
        let r = d.submit(&mut s, &id, "w1", &lines, 0);
        assert_eq!(
            (r["status"].as_str(), r["repair_scope"].as_str(), r["failed_index"].as_u64()),
            (Some("REPAIR_REQUIRED"), Some("rejected_items_only"), Some(2)),
            "{r}"
        );
        assert_eq!(r["accepted"].as_array().map(Vec::len), Some(3), "o1, c1 and c3 are stored: {r}");
        assert_eq!(r["refused"][0]["index"], 2, "{r}");
        assert_eq!(r["excluded"], json!([{"index": 3, "local_id": format!("{p}c2"), "rests_on": format!("{p}o2")}]), "{r}");
        assert_eq!(r["not_stored"], json!([format!("{p}o2"), format!("{p}c2")]), "{r}");
        assert!(r.get("extended").is_none(), "no byte replacement: {r}");
        let stored = s.records_since(0).into_iter().find(|x| x.kind == RecordKind::Observe).unwrap();
        assert_eq!(stored.quote.as_deref(), Some(whole), "the store holds the whole clause");
        // the repair sends only what was not stored; an exact resend of the accepted quote is a no-op
        let repair = [
            lines[0].clone(),
            json!({"kind": "observe", "local_id": format!("{p}o2"), "doc_id": "r1", "exact_quote": "because the version counts.", "terms": ["x"]}),
            lines[3].clone(),
        ];
        assert_eq!(d.submit(&mut s, &id, "w1", &repair, 0)["status"], "COMMITTED");
        assert_eq!(s.records_since(0).len(), 5);
    }

    #[test]
    fn with_relation_lines_off_the_prompt_offers_none_and_one_is_refused_before_the_store() {
        // the control profiles --build-scope concepts|none (Codex review of 8023910, SCOPE-01: a reader's relation became a link)
        assert_eq!(formats(true), format!("{FORMATS} A relation line holds only when its quotes prove it: {}", super::super::builder::LINK_CRITERIA));
        assert!(!formats(false).to_lowercase().contains("relation line holds"), "{}", formats(false));
        assert!(!formats(false).contains("\"kind\":\"relation\"") && !formats(false).contains(RELATION_RULE.trim()), "{}", formats(false));
        const DOC: &str = "# Rule\nThe validator rejects a version mismatch.\nA mismatch blocks the release.\n";
        let mut s = MemStore::new(&[("r1", DOC)], &["Rule"]);
        let mut d = Dispatcher::new(DispatchConfig { relation_lines: false, ..Default::default() }, vec![]);
        let t = d.acquire(&s, "w1", true, 0);
        assert!(!t["prompt"].as_str().unwrap().contains("\"kind\":\"relation\""), "{}", t["prompt"]);
        let (id, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
        let lines = [
            json!({"kind": "observe", "local_id": format!("{p}o1"), "doc_id": "r1", "exact_quote": "The validator rejects a version mismatch.", "terms": ["mismatch"]}),
            json!({"kind": "observe", "local_id": format!("{p}o2"), "doc_id": "r1", "exact_quote": "A mismatch blocks the release.", "terms": ["release"]}),
            json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "A version mismatch is rejected.", "subject": "mismatch", "stance": "reported", "based_on": [format!("{p}o1")]}),
            json!({"kind": "claim", "local_id": format!("{p}c2"), "text": "A mismatch blocks the release.", "subject": "release", "stance": "reported", "based_on": [format!("{p}o2")]}),
            json!({"kind": "relation", "local_id": format!("{p}r1"), "from": format!("{p}c2"), "rel": "depends_on", "to": format!("{p}c1"), "based_on": [format!("{p}o1"), format!("{p}o2")]}),
        ];
        let r = d.submit(&mut s, &id, "w1", &lines, 0);
        assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(4)), "{r}");
        assert_eq!(r["accepted"].as_array().map(Vec::len), Some(4), "the observes and claims are stored: {r}");
        assert_eq!(r["refused"][0]["error"]["message"], RELATIONS_OFF, "{r}");
        assert!(s.links().is_empty(), "no link was made");
    }

    #[test]
    fn hash_lines_open_sections_in_markdown_and_in_a_name_that_says_nothing() {
        let text = "# one\nfirst line of text\n# two\nsecond line of text\n";
        for doc in ["a.md", "reports/a.MD", "a.mdx", "policy", "d_0123", ".notes", "dir.v2/policy"] {
            assert!(has_headings(doc), "{doc}");
            assert_eq!(sections(doc, text, 64).len(), sections("a.md", text, 64).len(), "{doc}");
        }
        for doc in ["a.txt", "app/orders.py", "src/lib.RS", "contract.v2"] {
            assert!(!has_headings(doc), "{doc}");
        }
    }

    #[test]
    fn a_comment_does_not_cut_a_code_file_and_plain_text_ends_at_a_line() {
        let line = "x = compute(value)\n";
        let code = format!("{}# a comment, not a heading\n{}", line.repeat(3), line.repeat(3));
        assert_eq!(sections("a.py", &code, 1000), vec![(0, code.len())]);
        // a comment line at the top of a window opens no section either
        let many = format!("{}# comment\n{}", line.repeat(4), line.repeat(4));
        assert!(sections("a.py", &many, 64).iter().all(|(a, _)| !many[*a..].starts_with('#')), "cut by size, not at the comment");
        // no blank line in the window: the cut falls at the end of a line, never inside one
        let long = line.repeat(12);
        let cut = sections("a.py", &long, 64);
        assert!(cut.len() > 1);
        assert!(cut.iter().all(|(a, b)| long[*a..*b].ends_with('\n') && b - a <= 64), "{cut:?}");
        assert_eq!((cut[0].0, cut[cut.len() - 1].1), (0, long.len()));
        // one line longer than a section is still cut, on a character
        let wide = "\u{44f}".repeat(100);
        let parts = sections("a.txt", &wide, 64);
        assert_eq!(parts.iter().map(|(a, b)| b - a).sum::<usize>(), wide.len());
    }

    #[test]
    fn a_blank_line_ends_a_piece_of_plain_text_in_either_line_ending() {
        for end in ["\n", "\r\n"] {
            let para = format!("A paragraph of words.{end}Its second line.{end}{end}");
            let text = para.repeat(6);
            let cut = sections("contract.txt", &text, 2 * para.len() + 10);
            assert!(cut.len() > 1);
            assert!(cut.iter().all(|(_, b)| b % para.len() == 0), "{cut:?} at {} with {end:?}", para.len());
            assert_eq!(cut[cut.len() - 1].1, text.len());
        }
    }

    #[test]
    fn a_markdown_document_is_cut_as_it_always_was() {
        // the cut a measured run read: blank lines of `\n` only, whatever the line ending of the file
        let crlf = "word word word word\r\n\r\n".repeat(12);
        let cut = sections("d_0123", &crlf, 64);
        assert_eq!(cut[0], (0, 64));
    }

    #[test]
    fn sections_cut_at_headings_and_respect_the_size_bound() {
        let secs = sections("r1", R1, 80);
        assert!(secs.len() >= 2 && secs.iter().all(|(a, b)| b - a <= 80 && R1.is_char_boundary(*a) && R1.is_char_boundary(*b)), "{secs:?}");
        assert_eq!((secs[0].0, secs.last().unwrap().1), (0, R1.len()));
        assert!(secs.windows(2).all(|w| w[0].1 == w[1].0), "contiguous");
    }

    #[test]
    fn extend_leases_one_section_per_agent_and_refuses_quotes_outside_it() {
        let (mut s, mut d, b) = setup();
        let t1 = d.acquire(&s, "w1", b.caught_up(&s), 0);
        let t2 = d.acquire(&s, "w2", b.caught_up(&s), 0);
        assert_eq!((t1["kind"].as_str(), t2["kind"].as_str()), (Some("EXTEND"), Some("EXTEND")));
        assert_ne!(t1["key"], t2["key"], "two agents never get the same section");
        assert!(t1["prompt"].as_str().unwrap().contains("Differing validator versions"));
        // a quote from another section is refused, the lease survives for the repair
        let r = claim_on(&mut d, &mut s, &t1, "w1", "Version negotiation is future work.", "x", 1);
        assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
        let r = claim_on(&mut d, &mut s, &t1, "w1", "Differing validator versions -> warning only.", "Version differences were a warning", 2);
        assert_eq!(r["status"], "COMMITTED", "{r}");
        assert_eq!(claim_on(&mut d, &mut s, &t1, "w1", "x", "x", 3)["status"], "STALE_TASK");
        assert_eq!(d.submit(&mut s, t2["task_id"].as_str().unwrap(), "w1", &[], 3)["code"], "TASK_NOT_OWNED");
        // what the swarm already holds about the document is shown to the next agent on it
        d.release(t2["task_id"].as_str().unwrap(), "w2");
        let t3 = d.acquire(&s, "w3", b.caught_up(&s), 4);
        assert_eq!(t3["key"], t2["key"], "a released section is the first free work again");
        assert!(t3["prompt"].as_str().unwrap().contains("Version differences were a warning"), "{}", t3["prompt"]);
    }

    #[test]
    fn proposed_links_are_verified_by_a_non_author_and_conflicts_come_first() {
        let (mut s, mut d, mut b) = setup();
        for (i, (doc, q, text)) in [
            ("r1", "Differing validator versions -> warning only.", "A version difference is a warning"),
            ("r2", "A validator version difference is now blocking.", "A version difference is blocking"),
        ]
        .iter()
        .enumerate()
        {
            let agent = format!("w{}", i + 1);
            let mut t = d.acquire(&s, &agent, true, 10);
            while !t["key"].as_str().unwrap().starts_with(&format!("doc:{doc}")) {
                let key = t["key"].as_str().unwrap().to_string();
                d.release(t["task_id"].as_str().unwrap(), &agent);
                d.handled.insert(key); // covered elsewhere in this test
                t = d.acquire(&s, &agent, true, 10);
            }
            assert_eq!(claim_on(&mut d, &mut s, &t, &agent, q, text, 11)["status"], "COMMITTED");
        }
        let claims: Vec<RecordId> = s.records.iter().filter(|r| r.kind == RecordKind::Claim).map(|r| r.id).collect();
        // the builder flags the conflict and proposes a supersedes link
        let card = b.next_card(&s).unwrap();
        let ops = [
            json!({"op": "flag_conflict", "a": claims[0].short(), "b": claims[1].short()}),
            json!({"op": "link", "from": claims[1].short(), "rel": "supersedes", "to": claims[0].short(), "basis": [claims[1].short()]}),
        ];
        assert_eq!(b.submit(&mut s, &card.card_id, &ops)["status"], "CARD_DONE");
        // the authors never get the link tasks; another agent gets the conflict first
        let w1 = d.acquire(&s, "w1", b.caught_up(&s), 20);
        assert!(!matches!(w1["kind"].as_str(), Some("RESOLVE_CONFLICT") | Some("VERIFY_LINK")), "{w1}");
        let w3 = d.acquire(&s, "w3", b.caught_up(&s), 20);
        assert_eq!(w3["kind"], "RESOLVE_CONFLICT");
        let link = s.links.iter().find(|l| l.rel == "contradicts").unwrap().id.short();
        let ok = d.submit(
            &mut s,
            w3["task_id"].as_str().unwrap(),
            "w3",
            &[json!({"kind": "verdict", "link": link, "verdict": "reject", "based_on": [claims[1].short()]})],
            21,
        );
        assert_eq!(ok["verdict"]["status"], "rejected", "{ok}");
        let w4 = d.acquire(&s, "w4", b.caught_up(&s), 22);
        assert_eq!(w4["kind"], "VERIFY_LINK");
        let sup = s.links.iter().find(|l| l.rel == "supersedes").unwrap().id.short();
        assert_eq!(d.submit(&mut s, w4["task_id"].as_str().unwrap(), "w4", &[], 23)["status"], "REPAIR_REQUIRED", "a verdict is required");
        let ok = d.submit(
            &mut s,
            w4["task_id"].as_str().unwrap(),
            "w4",
            &[json!({"kind": "verdict", "link": sup, "verdict": "confirm", "based_on": [claims[1].short()]})],
            24,
        );
        assert_eq!(ok["verdict"]["status"], "accepted", "{ok}");
        assert_eq!((d.stats.confirmed, d.stats.rejected), (1, 1));
    }

    #[test]
    fn summary_waits_for_the_builder_and_the_run_completes_only_when_all_three_are_done() {
        let (mut s, mut d, mut b) = setup();
        let mut now = 0;
        // cover every section without findings
        loop {
            now += 1;
            let t = d.acquire(&s, "w1", b.caught_up(&s), now);
            if t["kind"] != "EXTEND" {
                assert_eq!(t["kind"], "SUMMARIZE", "nothing else is open: {t}");
                d.release(t["task_id"].as_str().unwrap(), "w1");
                break;
            }
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[], now)["status"], "COMMITTED");
        }
        // one record arrives late: the builder has not seen it, so no summary yet
        let scope = Scope { docs: vec!["r2".into()], ..Default::default() };
        s.submit_records(
            "w9",
            "X",
            &scope,
            &[json!({"kind": "observe", "local_id": "o", "doc_id": "r2", "exact_quote": "now blocking", "terms": ["validator version"]})],
        );
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), now)["status"], "WAIT");
        let c = b.next_card(&s).unwrap();
        b.submit(&mut s, &c.card_id, &[]);
        let t = d.acquire(&s, "w1", b.caught_up(&s), now);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        assert!(!d.completion(&s, b.caught_up(&s))["complete"].as_bool().unwrap());
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[], now)["status"], "REPAIR_REQUIRED", "a summary ends with done");
        let p = t["local_id_prefix"].as_str().unwrap();
        let done = json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": t["task_id"], "answer_ids": []});
        let mut wrong = done.clone();
        wrong["outcome"] = json!("answered");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[wrong], now)["error"]["field"], "answer_ids", "no records: unknown");
        let mut done = done;
        done["outcome"] = json!("unknown");
        let r = d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[done], now);
        assert_eq!(r["status"], "COMMITTED", "{r}");
        // the done record is new to the builder: not complete until it has caught up
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), now)["status"], "WAIT");
        let c = b.next_card(&s).unwrap();
        b.submit(&mut s, &c.card_id, &[]);
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), now)["status"], "COMPLETE");
        assert_eq!(d.completion(&s, b.caught_up(&s))["complete"], true);
        let receipt = d.terminal_receipt(&s, b.cursor(), "run").unwrap();
        assert_eq!((receipt["unknown_outcomes"][0].as_str(), receipt["outcomes"]["RQ1"]["outcome"].as_str()), (Some("RQ1"), Some("unknown")));
    }

    #[test]
    fn an_agent_wait_counts_for_why_the_kernel_had_no_task_for_it() {
        let (mut s, mut d, mut b) = setup();
        let mut now = 0;
        loop {
            now += 1;
            let t = d.acquire(&s, "w1", b.caught_up(&s), now);
            if t["kind"] != "EXTEND" {
                d.release(t["task_id"].as_str().unwrap(), "w1");
                break;
            }
            assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[], now)["status"], "COMMITTED");
        }
        // w1 holds the only task: w2 waits while another agent works
        let held = d.acquire(&s, "w1", b.caught_up(&s), 100);
        assert_eq!(held["kind"], "SUMMARIZE", "{held}");
        assert_eq!(d.acquire(&s, "w2", b.caught_up(&s), 100)["status"], "WAIT");
        d.release(held["task_id"].as_str().unwrap(), "w1");
        // a late record: the summary waits for the builder
        let scope = Scope { docs: vec!["r2".into()], ..Default::default() };
        s.submit_records(
            "w9",
            "X",
            &scope,
            &[json!({"kind": "observe", "local_id": "o", "doc_id": "r2", "exact_quote": "now blocking", "terms": ["validator version"]})],
        );
        assert_eq!(d.acquire(&s, "w2", b.caught_up(&s), 400)["status"], "WAIT");
        let c = b.next_card(&s).unwrap();
        b.submit(&mut s, &c.card_id, &[]);
        let t = d.acquire(&s, "w2", b.caught_up(&s), 1000);
        assert_eq!(t["kind"], "SUMMARIZE");
        let waited = &d.stats.wait_ms["w2"];
        assert_eq!((waited.get("others_working"), waited.get("builder_behind")), (Some(&300), Some(&600)), "{waited:?}");
        assert!(!d.stats.wait_ms.contains_key("w1"), "an agent that never waited has no wait");
        // the answer is new to the builder: w1 waits for it, then the run is complete
        let p = t["local_id_prefix"].as_str().unwrap();
        let done = json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": t["task_id"], "answer_ids": [], "outcome": "unknown"});
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w2", &[done], 1000)["status"], "COMMITTED");
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), 1100)["status"], "WAIT");
        let c = b.next_card(&s).unwrap();
        b.submit(&mut s, &c.card_id, &[]);
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), 1200)["status"], "COMPLETE");
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), 1300)["status"], "COMPLETE");
        // work reopens long after COMPLETE: the pause after it counts for no reason
        s.submit_records(
            "w9",
            "X",
            &scope,
            &[json!({"kind": "observe", "local_id": "o2", "doc_id": "r2", "exact_quote": "now blocking", "terms": ["validator version"]})],
        );
        assert_eq!(d.acquire(&s, "w1", b.caught_up(&s), 10_000)["status"], "WAIT");
        assert_eq!(d.stats.wait_ms["w1"].get("builder_behind"), Some(&100));
        // a closed run ends every open wait
        d.stats.end_waits(10_500);
        assert_eq!(d.stats.wait_ms["w1"].get("builder_behind"), Some(&600));
        d.stats.end_waits(11_000);
        assert_eq!(d.stats.wait_ms["w1"].get("builder_behind"), Some(&600), "a second close counts nothing");
    }

    #[test]
    fn a_restarted_dispatcher_keeps_completed_tasks_and_reissues_open_leases() {
        let (mut s, mut d, b) = setup();
        let t1 = d.acquire(&s, "w1", b.caught_up(&s), 0);
        let t2 = d.acquire(&s, "w2", b.caught_up(&s), 0);
        assert_eq!(claim_on(&mut d, &mut s, &t1, "w1", "Differing validator versions -> warning only.", "a warning", 1)["status"], "COMMITTED");
        // crash: t2 was leased but never answered
        let q = ResearchQuestion { id: "RQ1".into(), text: "x".into(), about: vec!["validator version".into()], ..Default::default() };
        let mut d2 = Dispatcher::new(DispatchConfig { section_bytes: 80, ..Default::default() }, vec![q]);
        d2.recover(&s);
        let again = d2.acquire(&s, "w3", b.caught_up(&s), 2);
        assert_eq!(again["key"], t2["key"], "the unanswered lease is issued again");
        assert_ne!(again["key"], t1["key"], "the committed task is not");
    }

    #[test]
    fn an_expired_lease_is_issued_again() {
        let (s, mut d, b) = setup();
        let t = d.acquire(&s, "w1", b.caught_up(&s), 0);
        let again = d.acquire(&s, "w2", b.caught_up(&s), d.cfg.ttl_ms + 1);
        assert_eq!(again["key"], t["key"]);
        assert_eq!(d.stats.expired, 1);
    }

    #[test]
    fn a_summary_sees_every_document_and_more_than_the_small_task_window() {
        let (mut s, mut d, mut b) = setup();
        for (doc, quote) in [("r1", "warning only"), ("r2", "now blocking")] {
            for i in 0..9 {
                let scope = Scope { docs: vec![doc.into()], ..Default::default() };
                let lines = [
                    json!({"kind": "observe", "local_id": "o", "doc_id": doc, "exact_quote": quote, "terms": ["validator version"]}),
                    json!({"kind": "claim", "local_id": "c", "text": format!("{doc} finding {i}"), "subject": "validator version", "stance": "reported", "based_on": ["o"]}),
                ];
                assert!(s.submit_records(&format!("a{doc}{i}"), "seed", &scope, &lines).error.is_none());
            }
        }
        let t = after_reading(&mut d, &mut s, &mut b, "w1", 1);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        let prompt = t["prompt"].as_str().unwrap();
        let shown = prompt.matches(" claim by ").count();
        assert_eq!(shown, 18, "all 18 claims, not the 12 of a small task (Gemini's run-9 spec)");
        assert!(prompt.contains("r1 finding 8") && prompt.contains("r2 finding 8"), "both documents");
        assert_eq!(t["max_lines"], 48);
    }

    #[test]
    fn a_summary_that_quotes_the_reports_again_gets_a_clear_repair_hint() {
        let (mut s, mut d, b) = setup();
        for now in 1..20 {
            let t = d.acquire(&s, "w1", b.caught_up(&s), now);
            let task = t["task_id"].as_str().unwrap().to_string();
            if t["kind"] == "EXTEND" {
                assert_eq!(d.submit(&mut s, &task, "w1", &[], now)["status"], "COMMITTED");
                continue;
            }
            assert_eq!(t["kind"], "SUMMARIZE", "{t}");
            assert!(t["prompt"].as_str().unwrap().contains("write no observe lines"));
            let quote = json!({"kind": "observe", "local_id": "x", "doc_id": "r1", "exact_quote": "warning only", "terms": ["t"]});
            let r = d.submit(&mut s, &task, "w1", &[quote], now);
            assert_eq!((r["status"].as_str(), r["error"]["field"].as_str()), (Some("REPAIR_REQUIRED"), Some("kind")), "{r}");
            assert!(r["error"]["message"].as_str().unwrap().contains("no observe lines"), "{r}");
            return;
        }
        panic!("no summary was issued");
    }

    #[test]
    fn a_summary_citing_a_shown_quote_without_its_at_sign_is_stored_and_says_so() {
        // MCPctl_none_r1, MCPctl_none_r2, MCPstrong_r1: summaries cited the quotes shown as bare hex and lost 25-34 lines each
        let (mut s, mut d, mut b) = setup();
        let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
        let seed = [
            json!({"kind": "observe", "local_id": "o", "doc_id": "r1", "exact_quote": "warning only", "terms": ["validator version"]}),
            json!({"kind": "claim", "local_id": "c", "text": "The validator gives a warning only.", "subject": "validator version", "stance": "reported", "based_on": ["o"]}),
        ];
        assert!(s.submit_records("seed1", "seed", &scope, &seed).error.is_none());
        let t = after_reading(&mut d, &mut s, &mut b, "w1", 1);
        assert_eq!(t["kind"], "SUMMARIZE", "{t}");
        let (task, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
        let observe = t["prompt"]
            .as_str()
            .unwrap()
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with('@') && l.contains(" observe by "))
            .and_then(|l| l.split(' ').next())
            .map(|id| id.trim_start_matches('@').to_string())
            .expect("an observe shown");
        let answer = |based: &str| {
            [
                json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "The validator gives a warning only.", "subject": "validator version",
                       "stance": "reported", "based_on": [based]}),
                json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": task, "outcome": "answered", "answer_ids": [format!("{p}c1")]}),
            ]
        };
        // a bare hex that names no record shown is left as sent: the store refuses it
        let r = d.submit(&mut s, &task, "w1", &answer("0123456789abcdef"), 2);
        assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
        assert_eq!(r["refused"][0]["local_id"], format!("{p}c1"), "{r}");
        assert!(r.get("referenced").is_none(), "{r}");
        let r = d.submit(&mut s, &task, "w1", &answer(&observe), 3);
        assert_eq!(r["status"], "COMMITTED", "{r}");
        assert_eq!(r["referenced"], json!([{"local_id": format!("{p}c1"), "field": "based_on", "sent": observe, "stored": format!("@{observe}")}]), "{r}");
        let claim = s
            .records_since(0)
            .into_iter()
            .find(|x| x.kind == RecordKind::Claim && x.text.as_deref() == Some("The validator gives a warning only.") && x.directive == task);
        assert!(claim.is_some_and(|c| c.based_on.iter().any(|o| o.short() == format!("@{observe}"))), "the claim rests on the quote shown");
    }

    #[test]
    fn a_repair_hint_names_the_identifiers_missing_from_the_line_the_store_saw() {
        // claude-reviewer's RV-01 of 2e99ddc: with a bare reference the hint was built on the line as sent, found no quote and named
        // v2.3.1 missing too, which the quote holds, beside the refusal's own v9.9.9
        for bare in [true, false] {
            let mut s = MemStore::new(&[("r1", "Validator v2.3.1 gives a warning only.\n")], &["Rule", "Component"]);
            let q = ResearchQuestion {
                id: "RQ1".into(),
                text: "What does the validator do?".into(),
                about: vec!["validator version".into()],
                ..Default::default()
            };
            let mut d = Dispatcher::new(DispatchConfig { section_bytes: 80, ..Default::default() }, vec![q]);
            let mut b = Builder::new(BuilderConfig::default());
            let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
            let seed = [
                json!({"kind": "observe", "local_id": "o", "doc_id": "r1", "exact_quote": "Validator v2.3.1 gives a warning only.", "terms": ["validator version"]}),
                json!({"kind": "claim", "local_id": "c", "text": "The validator gives a warning only.", "subject": "validator version", "stance": "reported", "based_on": ["o"]}),
            ];
            assert!(s.submit_records("seed1", "seed", &scope, &seed).error.is_none());
            let t = after_reading(&mut d, &mut s, &mut b, "w1", 1);
            assert_eq!(t["kind"], "SUMMARIZE", "{t}");
            let (task, p) = (t["task_id"].as_str().unwrap().to_string(), t["local_id_prefix"].as_str().unwrap().to_string());
            let observe = t["prompt"]
                .as_str()
                .unwrap()
                .lines()
                .map(str::trim)
                .find(|l| l.starts_with('@') && l.contains(" observe by "))
                .and_then(|l| l.split(' ').next())
                .map(|id| id.trim_start_matches('@').to_string())
                .expect("an observe shown");
            let based = if bare { observe.clone() } else { format!("@{observe}") };
            let lines = [
                json!({"kind": "claim", "local_id": format!("{p}c1"), "text": "Validator v2.3.1 gives a warning only; v9.9.9 blocks.",
                       "subject": "validator version", "stance": "reported", "based_on": [based]}),
                json!({"kind": "done", "local_id": format!("{p}d1"), "rq_id": "RQ1", "directive_id": task, "outcome": "answered", "answer_ids": [format!("{p}c1")]}),
            ];
            let r = d.submit(&mut s, &task, "w1", &lines, 2);
            assert_eq!(r["status"], "REPAIR_REQUIRED", "{r}");
            let hint = r["problems"].as_array().unwrap().iter().find(|x| x.get("missing_identifiers").is_some()).expect("an S0 hint");
            assert_eq!(hint["missing_identifiers"], json!(["v9.9.9"]), "bare {bare}: {r}");
        }
    }

    #[test]
    fn questions_raised_while_investigating_are_recorded_not_investigated_again() {
        let (mut s, mut d, mut b) = setup();
        let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
        let q = json!({"kind": "question", "local_id": "q", "text": "is it blocking now?", "about": ["validator version"], "needed": "r2"});
        assert!(s.submit_records("w9", "X", &scope, &[q]).error.is_none());
        // variant D: the question waits until every section is read and the builder has caught up
        let first = d.acquire(&s, "w1", false, 1);
        assert_eq!(first["kind"], "EXTEND", "{first}");
        d.release(first["task_id"].as_str().unwrap(), "w1");
        let t = after_reading(&mut d, &mut s, &mut b, "w1", 1);
        assert_eq!(t["kind"], "INVESTIGATE", "{t}");
        let p = t["local_id_prefix"].as_str().unwrap();
        let follow = json!({"kind": "question", "local_id": format!("{p}q1"), "text": "and the profiles?", "about": ["profile"], "needed": "r1"});
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), "w1", &[follow], 2)["status"], "COMMITTED");
        let next = d.acquire(&s, "w2", b.caught_up(&s), 3);
        assert_ne!(next["kind"], "INVESTIGATE", "a follow-up question is kept as a record, not investigated: {next}");
    }

    #[test]
    fn a_link_that_could_never_be_accepted_is_not_sent_for_verification() {
        let (mut s, mut d, b) = setup();
        let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
        let rep = s.submit_records(
            "w1",
            "T1",
            &scope,
            &[
                json!({"kind": "observe", "local_id": "o", "doc_id": "r1", "exact_quote": "warning only", "terms": ["severity"]}),
                json!({"kind": "hypothesis", "local_id": "h", "text": "it may block later", "falsifier": "a later gate", "based_on": ["o"]}),
                json!({"kind": "claim", "local_id": "c", "text": "a warning", "subject": "severity", "stance": "reported", "based_on": ["o"]}),
            ],
        );
        assert!(rep.error.is_none(), "{:?}", rep.error);
        s.add_link("builder", &rep.accepted[1], "supports", &rep.accepted[2], &[rep.accepted[2]]).unwrap();
        // a verify task would outrank every section; a hypothesis end can never be accepted, so none is issued
        let t = d.acquire(&s, "w9", b.caught_up(&s), 1);
        assert_eq!(t["kind"], "EXTEND", "{t}");
    }

    /// Three dated reports, two about one feature that the later one removes, each read with one claim. With `relate_hints` the
    /// second batching claim opens a RELATE turn: its task, the reply, its agent and its document.
    #[allow(clippy::type_complexity)]
    fn hint_reading(relate_hints: bool) -> (MemStore, Dispatcher, Option<(Value, Value, &'static str, String)>) {
        hint_reading_with(DispatchConfig { section_bytes: 4000, relate_hints, ..Default::default() }, false)
    }

    /// `hint_reading` with a config of its own; `refuse_first`: each reading first sends a quote its section does not hold, a loss.
    #[allow(clippy::type_complexity)]
    fn hint_reading_with(cfg: DispatchConfig, refuse_first: bool) -> (MemStore, Dispatcher, Option<(Value, Value, &'static str, String)>) {
        let docs = [
            ("old", "+++\ndate = \"2025-01-01\"\n+++\nEvery server MUST support the legacy batching feature.\n"),
            ("mid", "+++\ndate = \"2025-06-01\"\n+++\nLogging levels follow the syslog severities.\n"),
            ("new", "+++\ndate = \"2026-01-01\"\n+++\nThe legacy batching feature is removed from every server.\n"),
        ];
        let said: BTreeMap<&str, (&str, &str)> = [
            ("old", ("Every server MUST support the legacy batching feature.", "Servers must support legacy batching.")),
            ("mid", ("Logging levels follow the syslog severities.", "Logging levels follow syslog.")),
            ("new", ("The legacy batching feature is removed from every server.", "Legacy batching is removed from servers.")),
        ]
        .into_iter()
        .collect();
        let mut s = MemStore::new(&docs, &["Rule"]);
        let mut d = Dispatcher::new(cfg, vec![]);
        let mut relate = None;
        for (n, agent) in ["w1", "w2", "w3"].into_iter().enumerate() {
            let t = d.acquire(&s, agent, true, n as u64);
            assert_eq!(t["kind"], "EXTEND", "{t}");
            let doc = t["key"].as_str().unwrap()[4..].split('#').next().unwrap().to_string();
            if refuse_first {
                let p = t["local_id_prefix"].as_str().unwrap();
                let bad = json!({"kind": "observe", "local_id": format!("{p}o9"), "doc_id": doc, "exact_quote": "Nothing like this is written here.", "terms": ["x"]});
                assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), agent, &[bad], n as u64)["status"], "REPAIR_REQUIRED");
            }
            let (quote, text) = said[doc.as_str()];
            let r = claim_on(&mut d, &mut s, &t, agent, quote, text, n as u64);
            match r["status"].as_str() {
                Some("COMMITTED") => {}
                Some("RELATE") => relate = Some((t.clone(), r, agent, doc)),
                _ => panic!("{r}"),
            }
        }
        (s, d, relate)
    }

    #[test]
    fn with_hints_a_stored_reading_answer_opens_a_relate_turn_that_takes_only_a_claim_of_the_change() {
        // the hint profile: a reader is shown the claims of other report dates that share its claim's words, and
        // writes the change itself on both quotes
        let (mut s, mut d, relate) = hint_reading(true);
        let (t, r, agent, doc) = relate.expect("the second batching claim opens a RELATE turn");
        let p = r["prompt"].as_str().unwrap();
        let other = if doc == "new" { "2025-01-01" } else { "2026-01-01" };
        assert!(p.contains("TASK RELATE") && p.contains(&format!("report date {other}")) && p.contains("not evidence"), "{p}");
        assert!(!p.contains("syslog"), "a claim of no shared subject is no hint: {p}");
        let task = t["task_id"].as_str().unwrap();
        let bad = d.submit(&mut s, task, agent, &[json!({"kind": "question", "local_id": "x1", "text": "?", "about": ["x"], "needed": "y"})], 9);
        assert_eq!((bad["status"].as_str(), bad["error"]["field"].as_str()), (Some("REPAIR_REQUIRED"), Some("kind")), "{bad}");
        // the change, on the quote of each report
        let obs: Vec<String> = s
            .records_since(0)
            .into_iter()
            .filter(|r| r.kind == RecordKind::Observe && r.quote.as_deref().is_some_and(|q| q.contains("batching")))
            .map(|r| r.id.short())
            .collect();
        assert_eq!(obs.len(), 2);
        let p = t["local_id_prefix"].as_str().unwrap();
        let change = json!({"kind": "claim", "local_id": format!("{p}r1"), "text": "Legacy batching, required in 2025-01-01, is removed in 2026-01-01.",
            "subject": "legacy batching", "stance": "superseded", "as_of": null, "based_on": obs});
        let done = d.submit(&mut s, task, agent, &[change], 10);
        assert_eq!(done["status"], "COMMITTED", "{done}");
        assert!(d.leases.is_empty(), "the task is closed");
        assert_eq!((d.stats.relate_turns, d.stats.committed), (1, 3));
        // without the profile the same answers close their tasks at once
        let (_, d, relate) = hint_reading(false);
        assert!(relate.is_none() && d.leases.is_empty() && d.stats.committed == 3);
    }

    #[test]
    fn a_relate_turn_keeps_its_readings_checkpoint_so_a_recovery_sees_the_reading_as_the_live_dispatcher_does() {
        // claude-reviewer's RV-01 of 8509eb18: the close of the turn wrote over the reading's checkpoint, and a restart lost its loss
        let (mut s, mut d, relate) = hint_reading_with(DispatchConfig { section_bytes: 4000, relate_hints: true, ..Default::default() }, true);
        let (t, _, agent, _) = relate.expect("a RELATE turn");
        let key = t["key"].as_str().unwrap().to_string();
        let before = s.checkpoint(&task_checkpoint(&key)).expect("the reading's checkpoint")["context"].clone();
        assert!(before["refusals"].as_u64().unwrap_or(0) > 0, "the reading's loss is in its checkpoint: {before}");
        assert_eq!(d.submit(&mut s, t["task_id"].as_str().unwrap(), agent, &[], 10)["status"], "COMMITTED");
        let mut after = s.checkpoint(&task_checkpoint(&key)).expect("the checkpoint")["context"].clone();
        assert_eq!(after["relate"]["task_id"], t["task_id"], "the turn adds its mark: {after}");
        after.as_object_mut().unwrap().remove("relate");
        assert_eq!(after, before, "the reading's checkpoint is kept");
        let mut again = Dispatcher::new(DispatchConfig { section_bytes: 4000, relate_hints: true, ..Default::default() }, vec![]);
        again.recover(&s);
        let losses = |d: &Dispatcher| d.strained.iter().map(|(k, l)| (k.clone(), l.stored, l.offered, l.refusals, l.abandoned)).collect::<Vec<_>>();
        assert!(d.strained.contains_key(&key));
        assert_eq!(losses(&again), losses(&d), "a recovery has the live dispatcher's losses");
    }

    #[test]
    fn a_relate_turn_the_runner_times_out_gives_up_only_the_turn() {
        // claude-reviewer's RV-02 of 8509eb18: with --agent-attempts, the runner's timeout of the turn recorded an agent failure on
        // the key of the stored reading
        let (mut s, mut d, relate) =
            hint_reading_with(DispatchConfig { section_bytes: 4000, relate_hints: true, agent_attempts: Some(4), ..Default::default() }, false);
        let (t, _, agent, _) = relate.expect("a RELATE turn");
        let key = t["key"].as_str().unwrap().to_string();
        let r = d.timeout_task(&mut s, t["task_id"].as_str().unwrap(), agent);
        assert_eq!(r["status"], "RELEASED", "{r}");
        assert!(d.leases.is_empty() && d.taken(&key), "the stored reading stays handled");
        assert!(!d.failures.contains_key(&key) && !d.unresolved.contains(&key), "no agent failure of the reading: {r}");
    }

    #[test]
    fn a_relate_turn_refused_answered_empty_or_run_out_gives_up_nothing_of_its_stored_reading() {
        // review of the hint profile: the reading answer is stored when the turn opens, so an empty RELATE answer after a refusal is
        // no abandoned reading (no loss for a reread), and a turn that runs out does not issue its section again
        for run_out in [false, true] {
            let (mut s, mut d, relate) = hint_reading(true);
            let (t, _, agent, _) = relate.expect("a RELATE turn");
            let (task, key) = (t["task_id"].as_str().unwrap(), t["key"].as_str().unwrap().to_string());
            assert!(d.taken(&key), "the stored reading is handled while its RELATE turn runs");
            let bad = d.submit(&mut s, task, agent, &[json!({"kind": "question", "local_id": "x1", "text": "?", "about": ["x"], "needed": "y"})], 9);
            assert_eq!(bad["status"], "REPAIR_REQUIRED", "{bad}");
            if run_out {
                d.expire(u64::MAX);
                assert!(d.leases.is_empty());
            } else {
                assert_eq!(d.submit(&mut s, task, agent, &[], 10)["status"], "COMMITTED");
            }
            assert!(d.taken(&key) && !d.unresolved.contains(&key) && !d.failures.contains_key(&key), "run out {run_out}");
            assert!(d.strained.get(&key).is_none_or(|l| !l.abandoned), "run out {run_out}: no abandoned reading");
            assert_eq!(d.stats.committed, 3, "the reading counts once");
        }
    }
}

mod agent_failure;
