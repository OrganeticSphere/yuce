//! The reading tools of 0.2 (SPEC_V02_STEP3): a run's summary, what rests on a record or a document, the claims that stand, what
//! changed between two points of the journal, one record with its grounds, and the report of what fell after a withdrawal.
//!
//! They read the two projections of SPEC_V02_STEP2 section 6 and never write. A live server and `sbgk audit-read` over a journal
//! call the same functions, so both answer alike for one state. A point of the journal is a number of frames `n`, as the
//! `log_size` of a seal: the state after frames `0..n-1`.

use super::directives::gaps;
use super::state::AuditState;
use super::{pairs, quality, AuditStore, RecordId, RecordKind, RecordView};
use crate::hash::{from_hex, to_hex, Hash};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The two sentences that go together wherever a projection is said to be complete (DESIGN_V02 correction 12).
pub const COMPLETENESS: [&str; 2] = [
    "complete as to the kernel's rule: every based_on and relation end the records declare",
    "not as to the world: a dependency an agent did not declare is in no projection",
];

/// What the report says it proves, and what it only suggests (DESIGN_V02 section 3.3).
pub const PROVABLE: &str = "provable from the journal: what stands, what fell, which quote went";
pub const HEURISTIC: &str = "twins are found by comparing text, a heuristic; reread is advice";
pub const NOT_ERASED: &str = "a withdrawal is not an erasure: the journal keeps the withdrawn text, and record shows it";

/// The most rows a list of a tool gives when its caller names no limit, and the most it ever gives.
pub const DEFAULT_LIMIT: usize = 500;
pub const DEFAULT_REPORT_LIMIT: usize = 200;
pub const MAX_LIMIT: usize = 5000;

/// The most twins a fallen row names, and the share of words a twin shares with it at least (as `TWIN_NUM / TWIN_DEN`).
const TWINS: usize = 5;
const TWIN_NUM: usize = 1;
const TWIN_DEN: usize = 2;

/// One row of the status projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub id: RecordId,
    pub kind: String,
    pub grounded: bool,
    pub answer_support: bool,
    pub fallen_by: Vec<RecordId>,
}

/// What the tools take of a state at one point of its journal: the status projection, the withdrawn texts, the projection
/// hashes and the seals so far.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub at: usize,
    pub rows: Vec<Row>,
    index: HashMap<RecordId, usize>,
    pub withdrawn: BTreeSet<(String, Hash, usize)>,
    pub projections: (Hash, Hash),
    pub seals: Vec<(usize, Hash)>,
}

fn id_of(v: &Value) -> RecordId {
    RecordId(v.as_str().and_then(from_hex).expect("a projection names records by 64 hex digits"))
}

impl Snapshot {
    /// The snapshot of `s` at point `at`.
    pub fn of(s: &AuditState, at: usize) -> Self {
        let (status, _, hashes) = s.projections();
        let rows: Vec<Row> = status
            .iter()
            .map(|r| Row {
                id: id_of(&r[0]),
                kind: r[1].as_str().unwrap_or_default().to_string(),
                grounded: r[2] == true,
                answer_support: r[3] == true,
                fallen_by: r[4].as_array().into_iter().flatten().map(id_of).collect(),
            })
            .collect();
        let index = rows.iter().enumerate().map(|(i, r)| (r.id, i)).collect();
        Self { at, rows, index, withdrawn: s.withdrawn_texts().into_iter().collect(), projections: hashes, seals: s.seals().to_vec() }
    }

    pub fn row(&self, id: &RecordId) -> Option<&Row> {
        self.index.get(id).map(|i| &self.rows[*i])
    }

    fn stands(&self, id: &RecordId) -> bool {
        self.row(id).is_some_and(|r| r.grounded)
    }
}

fn hexes(ids: &[RecordId]) -> Vec<String> {
    ids.iter().map(|g| to_hex(&g.0)).collect()
}

fn projections_json(p: &(Hash, Hash)) -> Value {
    json!({"status": to_hex(&p.0), "dependencies": to_hex(&p.1)})
}

fn seals_json<'a>(seals: impl Iterator<Item = &'a (usize, Hash)>) -> Vec<Value> {
    seals.map(|(n, h)| json!({"log_size": n, "seal_hash": to_hex(h)})).collect()
}

fn limit_of(limit: Option<usize>, default: usize) -> usize {
    limit.unwrap_or(default).clamp(1, MAX_LIMIT)
}

/// The records by kind, as the tools count them: total and standing.
fn by_kind(rows: &[&Row]) -> Value {
    let mut out: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for r in rows {
        let e = out.entry(r.kind.as_str()).or_default();
        e.0 += 1;
        e.1 += usize::from(r.grounded);
    }
    json!(out.into_iter().map(|(k, (total, standing))| (k, json!({"total": total, "standing": standing}))).collect::<BTreeMap<_, _>>())
}

/// A record that fell: it does not stand, and a ground of its own no longer stands. A record that does not stand with all its
/// grounds standing never stood on them: a question or a hypothesis without grounds, or an answer whose grounds stand but cannot
/// all support an answer.
fn lost_a_ground(r: &Row) -> bool {
    !r.grounded && r.kind != "observe" && !r.fallen_by.is_empty()
}

/// What the projections say of a state: records by kind, standing, fallen (a ground of theirs went) and otherwise not standing,
/// the withdrawn texts and gone quotes, the seals and the projection hashes. The live `audit_status` carries it as its
/// `projections` block.
pub fn summary(s: &AuditState) -> Value {
    let snap = Snapshot::of(s, 0);
    let rows: Vec<&Row> = snap.rows.iter().collect();
    let standing = rows.iter().filter(|r| r.grounded).count();
    let fallen = rows.iter().filter(|r| lost_a_ground(r)).count();
    let gone = rows.iter().filter(|r| !r.grounded && r.kind == "observe").count();
    let mut by_document: BTreeMap<&str, usize> = BTreeMap::new();
    for (doc, _, _) in &snap.withdrawn {
        *by_document.entry(doc.as_str()).or_default() += 1;
    }
    json!({"records": by_kind(&rows), "standing": standing, "fallen": fallen, "quotes_gone": gone, "other_not_standing": rows.len() - standing - fallen - gone,
           "withdrawn": {"texts": snap.withdrawn.len(), "by_document": by_document},
           "seals": seals_json(snap.seals.iter()), "hashes": projections_json(&snap.projections), "completeness": COMPLETENESS})
}

/// `status`: the summary of a run read from its journal (`entries` frames).
pub fn status(s: &AuditState, entries: usize) -> Value {
    let mut out = json!({"status": "READ_STATUS", "run_id": s.run_id(), "journal_format": if s.is_v3() { "sbgk-session-log/3" } else { "sbgk-session-log/2" },
                         "entries": entries, "closed": s.is_closed(), "projections": summary(s)});
    if let Some(meta) = s.genesis_meta() {
        out["rules_version"] = json!(super::state::RULES_VERSION);
        out["questions"] = json!(meta.questions.as_array().map_or(0, Vec::len));
    }
    out
}

/// What a `dependents` call starts from: a record, or the quotes of a document (in a byte range of its current version).
pub enum Target<'a> {
    Record(RecordId),
    Document { doc_id: &'a str, range: Option<(usize, usize)> },
}

/// The records that rest on each record, from the dependency projection.
fn resting_on(s: &AuditState) -> HashMap<RecordId, Vec<RecordId>> {
    let (_, pairs) = s.projection_rows();
    let mut out: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
    for p in &pairs {
        out.entry(id_of(&p[1])).or_default().push(id_of(&p[0]));
    }
    out
}

/// `dependents`: every record that rests on the target, directly (depth 1) or through others, by depth and then in record order.
pub fn dependents(s: &AuditState, target: &Target, limit: Option<usize>) -> Value {
    let snap = Snapshot::of(s, 0);
    let (roots, target_json, quotes): (Vec<RecordId>, Value, Option<Vec<Value>>) = match target {
        Target::Record(id) => (vec![*id], json!({"record": to_hex(&id.0)}), None),
        Target::Document { doc_id, range } => {
            let mut roots = Vec::new();
            let mut quotes = Vec::new();
            for r in snap.rows.iter().filter(|r| r.kind == "observe") {
                let Some(fate) = s.quote_fate(&r.id) else { continue };
                let inside = range.is_none_or(|(a, z)| {
                    fate["current_version"] == true
                        && fate["start"].as_u64().is_some_and(|x| (x as usize) < z)
                        && fate["end"].as_u64().is_some_and(|x| (x as usize) > a)
                });
                if fate["doc_id"] == *doc_id && inside {
                    roots.push(r.id);
                    quotes.push(json!({"id": to_hex(&r.id.0), "short": r.id.short(), "start": fate["start"], "end": fate["end"], "stands": r.grounded}));
                }
            }
            (roots, json!({"doc_id": doc_id, "range": range.map(|(a, z)| json!([a, z]))}), Some(quotes))
        }
    };
    let on = resting_on(s);
    let mut depth: HashMap<RecordId, usize> = roots.iter().map(|id| (*id, 0)).collect();
    let mut level = roots.clone();
    let mut found: Vec<(usize, usize, RecordId)> = Vec::new();
    let mut d = 0;
    while !level.is_empty() {
        d += 1;
        let mut next = Vec::new();
        for id in &level {
            for up in on.get(id).into_iter().flatten() {
                if !depth.contains_key(up) {
                    depth.insert(*up, d);
                    next.push(*up);
                    found.push((d, snap.index.get(up).copied().unwrap_or(usize::MAX), *up));
                }
            }
        }
        level = next;
    }
    found.sort_unstable();
    let limit = limit_of(limit, DEFAULT_LIMIT);
    let rows: Vec<Value> = found
        .iter()
        .take(limit)
        .filter_map(|(d, _, id)| snap.row(id).map(|r| (d, r)))
        .map(|(d, r)| json!({"id": to_hex(&r.id.0), "short": r.id.short(), "kind": r.kind, "depth": d, "stands": r.grounded, "fallen_by": hexes(&r.fallen_by)}))
        .collect();
    let mut out = json!({"status": "DEPENDENTS", "target": target_json, "count": found.len(), "dependents": rows, "truncated": found.len() > limit,
                         "completeness": COMPLETENESS});
    if let Some(q) = quotes {
        out["quotes"] = json!(q);
    }
    out
}

/// The standing quotes under a record, in record order: its cone's observations that stand.
fn standing_quotes(s: &AuditState, snap: &Snapshot, id: RecordId) -> Vec<RecordView> {
    let mut quotes: Vec<RecordView> = pairs::cone(s, &[id]).into_iter().filter(|r| r.kind == RecordKind::Observe && snap.stands(&r.id)).collect();
    quotes.sort_by_key(|r| r.seq);
    quotes
}

fn documents(quotes: &[RecordView]) -> BTreeSet<String> {
    quotes.iter().filter_map(|q| q.doc_id.clone()).collect()
}

/// A claim's text as `active_claims` merges it: case and spacing aside.
fn merged_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// `active_claims`: the claims that stand, those of equal text (case and spacing aside) merged into one row that names the
/// documents of the standing quotes under them; only those with a standing quote of `doc` when it is given.
pub fn active_claims(s: &AuditState, doc: Option<&str>, limit: Option<usize>) -> Value {
    let snap = Snapshot::of(s, 0);
    let mut groups: Vec<(String, Vec<RecordId>, BTreeSet<String>, bool)> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut claims = 0;
    for r in s.records_of_kind(RecordKind::Claim) {
        let Some(row) = snap.row(&r.id).filter(|row| row.grounded) else { continue };
        let docs = documents(&standing_quotes(s, &snap, r.id));
        if doc.is_some_and(|d| !docs.contains(d)) {
            continue;
        }
        claims += 1;
        let text = r.text.clone().unwrap_or_default();
        let key = merged_text(&text);
        let i = *at.entry(key).or_insert_with(|| {
            groups.push((text, Vec::new(), BTreeSet::new(), false));
            groups.len() - 1
        });
        groups[i].1.push(r.id);
        groups[i].2.extend(docs);
        groups[i].3 |= row.answer_support;
    }
    let limit = limit_of(limit, DEFAULT_LIMIT);
    let rows: Vec<Value> = groups
        .iter()
        .take(limit)
        .map(|(text, ids, docs, support)| json!({"text": text, "ids": hexes(ids), "documents": docs, "sources": docs.len(), "answer_support": support}))
        .collect();
    json!({"status": "ACTIVE_CLAIMS", "doc_id": doc, "claims": claims, "count": groups.len(), "groups": rows, "truncated": groups.len() > limit})
}

/// `diff`: what changed between two points of one journal, `from` before `to`. Records are never erased, so those added are the
/// rows of `to` past the rows of `from`.
pub fn diff(from: &Snapshot, to: &Snapshot, limit: Option<usize>) -> Value {
    let limit = limit_of(limit, DEFAULT_LIMIT);
    let common = from.rows.len().min(to.rows.len());
    let added: Vec<&Row> = to.rows[common..].iter().collect();
    let row = |r: &Row| json!({"id": to_hex(&r.id.0), "short": r.id.short(), "kind": r.kind, "fallen_by": hexes(&r.fallen_by)});
    let fell: Vec<&Row> = (0..common).filter(|i| from.rows[*i].grounded && !to.rows[*i].grounded).map(|i| &to.rows[i]).collect();
    let rose: Vec<&Row> = (0..common).filter(|i| !from.rows[*i].grounded && to.rows[*i].grounded).map(|i| &to.rows[i]).collect();
    let withdrawn: Vec<Value> =
        to.withdrawn.difference(&from.withdrawn).map(|(doc, h, len)| json!({"doc_id": doc, "sha256": to_hex(h), "bytes": len})).collect();
    json!({"status": "DIFF", "from": from.at, "to": to.at,
           "records_added": {"total": added.len(), "by_kind": by_kind(&added)},
           "fell": {"count": fell.len(), "rows": fell.iter().take(limit).map(|r| row(r)).collect::<Vec<_>>()},
           "rose": {"count": rose.len(), "rows": rose.iter().take(limit).map(|r| row(r)).collect::<Vec<_>>()},
           "withdrawn_added": withdrawn,
           "projections": {"from": projections_json(&from.projections), "to": projections_json(&to.projections)},
           "seals_between": seals_json(to.seals.iter().filter(|(n, _)| *n >= from.at && *n < to.at)),
           "truncated": fell.len() > limit || rose.len() > limit})
}

/// The first causes of a row that does not stand: following `fallen_by` down to the observations that do not stand, in record order.
fn first_causes(snap: &Snapshot, id: RecordId) -> Vec<RecordId> {
    let mut todo = vec![id];
    let mut seen = BTreeSet::new();
    let mut out = BTreeSet::new();
    while let Some(id) = todo.pop() {
        let Some(r) = snap.row(&id) else { continue };
        for g in &r.fallen_by {
            if !seen.insert(*g) {
                continue;
            }
            match snap.row(g) {
                Some(row) if row.kind == "observe" => {
                    out.insert((snap.index[g], *g));
                }
                Some(_) => todo.push(*g),
                None => {}
            }
        }
    }
    out.into_iter().map(|(_, g)| g).collect()
}

fn gone_json(s: &AuditState, id: RecordId) -> Value {
    let mut out = json!({"id": to_hex(&id.0), "short": id.short()});
    if let Some(Value::Object(fate)) = s.quote_fate(&id) {
        out.as_object_mut().expect("object").extend(fate);
    }
    out
}

/// `record`'s additions to a record (SPEC_V02_STEP3 section 5): its row of the status projection, how many records rest on it
/// directly, and, when it does not stand, its first causes; for an observation, where its quote is bound.
pub fn record_projection(s: &AuditState, id: &RecordId) -> Value {
    let snap = Snapshot::of(s, 0);
    let Some(r) = snap.row(id) else { return Value::Null };
    let direct = resting_on(s).get(id).map_or(0, |v| v.iter().collect::<BTreeSet<_>>().len());
    let mut out = json!({"projection": {"grounded": r.grounded, "answer_support": r.answer_support, "fallen_by": hexes(&r.fallen_by)},
                         "dependents_direct": direct});
    if r.kind == "observe" {
        out["quote_binding"] = s.quote_fate(id).unwrap_or(Value::Null);
    } else if !r.grounded {
        out["first_causes"] = json!(first_causes(&snap, *id).into_iter().map(|g| gone_json(s, g)).collect::<Vec<_>>());
    }
    out
}

/// The words a twin is compared by: three letters or more, case aside.
fn words(text: &str) -> BTreeSet<String> {
    quality::tokens(text).into_iter().filter(|t| t.chars().count() >= 3).collect()
}

/// The standing claims a twin is drawn from, with an index of their words.
struct Standing {
    claims: Vec<(RecordId, BTreeSet<String>, BTreeSet<String>, Vec<RecordId>)>,
    by_word: HashMap<String, Vec<usize>>,
}

impl Standing {
    fn of(s: &AuditState, snap: &Snapshot) -> Self {
        let mut claims = Vec::new();
        let mut by_word: HashMap<String, Vec<usize>> = HashMap::new();
        for r in s.records_of_kind(RecordKind::Claim).into_iter().filter(|r| snap.stands(&r.id)) {
            let w = words(r.text.as_deref().unwrap_or_default());
            let docs = documents(&standing_quotes(s, snap, r.id));
            if w.is_empty() || docs.is_empty() {
                continue;
            }
            for word in &w {
                by_word.entry(word.clone()).or_default().push(claims.len());
            }
            claims.push((r.id, w, docs, r.based_on.clone()));
        }
        Self { claims, by_word }
    }

    /// The standing claims whose words overlap `w` by at least half of their union and none of whose standing quotes is from `away`.
    fn twins(&self, w: &BTreeSet<String>, away: &BTreeSet<String>) -> Vec<Value> {
        let mut shared: HashMap<usize, usize> = HashMap::new();
        for word in w {
            for i in self.by_word.get(word).into_iter().flatten() {
                *shared.entry(*i).or_default() += 1;
            }
        }
        let mut found: Vec<(usize, usize, usize)> = shared
            .into_iter()
            .map(|(i, n)| (i, n, w.len() + self.claims[i].1.len() - n))
            .filter(|(i, n, union)| n * TWIN_DEN >= union * TWIN_NUM && self.claims[*i].2.is_disjoint(away))
            .collect();
        // by share of words, the larger first (compared as fractions, without floating point), then in record order
        found.sort_by(|a, b| (b.1 * a.2).cmp(&(a.1 * b.2)).then(a.0.cmp(&b.0)));
        found
            .into_iter()
            .take(TWINS)
            .map(|(i, n, union)| {
                let (id, _, docs, based_on) = &self.claims[i];
                json!({"id": to_hex(&id.0), "short": id.short(), "based_on": hexes(based_on), "documents": docs, "shared_words": n, "union_words": union})
            })
            .collect()
    }
}

/// The structural unit of a document around a gone quote, without the withdrawn text: what to reread there. Only for a quote on
/// the document's current version; nothing when no word of the unit is left.
fn reread_passages(s: &AuditState, fate: &Value) -> Vec<Value> {
    let (Some(doc), Some(start)) = (fate["doc_id"].as_str(), fate["start"].as_u64()) else { return Vec::new() };
    if fate["current_version"] != true {
        return Vec::new();
    }
    let Some(text) = s.doc_text(doc) else { return Vec::new() };
    let start = start as usize;
    let end = fate["end"].as_u64().map_or(start, |e| e as usize);
    let Some((a, z)) = gaps::units(doc, &text).into_iter().find(|(a, z)| *a < end.max(start + 1) && start < *z) else { return Vec::new() };
    let mut closed = s.closed_spans(doc);
    closed.sort_unstable();
    let mut pieces = Vec::new();
    let mut from = a;
    for (c0, c1) in closed.into_iter().filter(|(c0, c1)| *c0 < z && a < *c1) {
        if c0 > from {
            pieces.push((from, c0));
        }
        from = from.max(c1);
    }
    if from < z {
        pieces.push((from, z));
    }
    pieces
        .into_iter()
        .filter(|(p0, p1)| text.get(*p0..*p1).is_some_and(|t| t.chars().filter(|c| c.is_alphanumeric()).count() >= 3))
        .map(|(p0, p1)| json!({"doc_id": doc, "start": p0, "end": p1}))
        .collect()
}

/// A standing quote's text without the bytes of quotes that went in the same version of its document, each run of them replaced
/// by `[withheld]`, and those runs: under the rule of the first journals a wider quote stands over a narrower one that went, and
/// its text would repeat what went (Codex review of 2c6864f, S3-03). `record` and the journal still give the whole quote.
fn without_gone(quote: &str, fate: &Value, gone: &HashMap<(String, String), Vec<(usize, usize)>>) -> (String, Vec<(usize, usize)>) {
    let (Some(doc), Some(version), Some(start)) = (fate["doc_id"].as_str(), fate["version"].as_str(), fate["start"].as_u64()) else {
        return (quote.to_string(), Vec::new());
    };
    let (start, end) = (start as usize, start as usize + quote.len());
    let mut cut: Vec<(usize, usize)> = gone
        .get(&(doc.to_string(), version.to_string()))
        .into_iter()
        .flatten()
        .filter(|(a, z)| *a < end && start < *z)
        .map(|(a, z)| ((*a).max(start), (*z).min(end)))
        .collect();
    cut.sort_unstable();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (a, z) in cut {
        match runs.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(z),
            _ => runs.push((a, z)),
        }
    }
    let mut text = String::new();
    let mut at = start;
    for (a, z) in &runs {
        // a run that does not end on a character's edge takes the text around it too: it withholds more, never less
        text.push_str(quote.get(at - start..a - start).unwrap_or_default());
        text.push_str("[withheld]");
        at = *z;
    }
    text.push_str(quote.get(at - start..).unwrap_or_default());
    (text, runs)
}

/// The report of what fell (SPEC_V02_STEP3 section 6): the claims, relations, hypotheses and answers that lost a ground, and,
/// with `since`, those that stood at that point and do not stand now. A row names its direct grounds that fell, its first causes
/// (the gone quotes, without their text), the quotes under it that stand (with their text; an answer names how many of its
/// grounds stand instead), its twins on other sources (without their text) and what to reread. The text of a fallen row is never
/// given: it may state what was withdrawn.
pub fn fallen(s: &AuditState, at: usize, since: Option<&Snapshot>, limit: Option<usize>) -> Value {
    let now = Snapshot::of(s, at);
    let fell = |i: usize| match since {
        Some(p) => !now.rows[i].grounded && p.rows.get(i).is_some_and(|r| r.grounded),
        None => !now.rows[i].grounded && (now.rows[i].kind == "observe" || lost_a_ground(&now.rows[i])),
    };
    let fell: Vec<usize> = (0..now.rows.len()).filter(|i| fell(*i)).collect();
    let (gone, rows): (Vec<usize>, Vec<usize>) = fell.into_iter().partition(|i| now.rows[*i].kind == "observe");
    let other: Vec<&Row> =
        if since.is_none() { now.rows.iter().filter(|r| !r.grounded && r.kind != "observe" && r.fallen_by.is_empty()).collect() } else { Vec::new() };
    let fallen_rows: Vec<&Row> = rows.iter().map(|i| &now.rows[*i]).collect();
    let records: HashMap<RecordId, RecordView> = s
        .records_since(0)
        .into_iter()
        .filter(|r| r.kind != RecordKind::Observe && now.row(&r.id).is_some_and(|row| !row.grounded))
        .map(|r| (r.id, r))
        .collect();
    let standing = fallen_rows.iter().any(|r| r.kind == "claim").then(|| Standing::of(s, &now));
    // the bytes of every quote that went, by document and version: no text the report gives may repeat them
    let mut gone_spans: HashMap<(String, String), Vec<(usize, usize)>> = HashMap::new();
    for r in now.rows.iter().filter(|r| r.kind == "observe" && !r.grounded) {
        let Some(f) = s.quote_fate(&r.id) else { continue };
        if let (Some(doc), Some(version), Some(a), Some(z)) = (f["doc_id"].as_str(), f["version"].as_str(), f["start"].as_u64(), f["end"].as_u64()) {
            gone_spans.entry((doc.to_string(), version.to_string())).or_default().push((a as usize, z as usize));
        }
    }
    let limit = limit_of(limit, DEFAULT_REPORT_LIMIT);
    let mut questions = BTreeSet::new();
    let mut out_rows = Vec::new();
    for (k, r) in fallen_rows.iter().enumerate() {
        let record = records.get(&r.id);
        let question = record.filter(|v| v.kind == RecordKind::Done).and_then(|v| v.body["rq_id"].as_str().map(str::to_string));
        if let Some(q) = &question {
            questions.insert(q.clone());
        }
        if k >= limit {
            continue;
        }
        let causes = first_causes(&now, r.id);
        let gone_quotes: Vec<Value> = causes.iter().map(|g| gone_json(s, *g)).collect();
        let away: BTreeSet<String> = gone_quotes.iter().filter_map(|g| g["doc_id"].as_str().map(str::to_string)).collect();
        let kept = if r.kind == "done" { Vec::new() } else { standing_quotes(s, &now, r.id) };
        let standing_json: Vec<Value> = kept
            .iter()
            .map(|q| {
                let fate = s.quote_fate(&q.id).unwrap_or(Value::Null);
                let mut out = json!({"id": to_hex(&q.id.0), "short": q.id.short(), "doc_id": q.doc_id, "start": fate["start"], "end": fate["end"]});
                let (text, cut) = without_gone(q.quote.as_deref().unwrap_or_default(), &fate, &gone_spans);
                out["quote"] = json!(text);
                if !cut.is_empty() {
                    out["withheld"] = json!(cut.iter().map(|(a, z)| json!([a, z])).collect::<Vec<_>>());
                }
                out
            })
            .collect();
        let twins = match (&standing, record) {
            (Some(st), Some(v)) if r.kind == "claim" => st.twins(&words(v.text.as_deref().unwrap_or_default()), &away),
            _ => Vec::new(),
        };
        let mut passages: Vec<Value> = gone_quotes.iter().flat_map(|g| reread_passages(s, g)).collect();
        passages.dedup();
        let mut reread = json!({"passages": passages});
        if let Some(q) = &question {
            reread["question"] = json!(q);
        }
        let mut row = json!({"id": to_hex(&r.id.0), "short": r.id.short(), "kind": r.kind, "fallen_by": hexes(&r.fallen_by),
                             "gone": gone_quotes, "standing": standing_json, "twins": twins, "reread": reread});
        if let Some(v) = record.filter(|_| r.kind == "done") {
            // an answer rests on many claims: how many of them stand, not every quote under them
            row["grounds_standing"] = json!(v.based_on.iter().filter(|g| now.stands(g)).count());
        }
        if causes.is_empty() {
            row["note"] = json!("no quote under it went: its grounds stand, but not all of them can support an answer");
        }
        out_rows.push(row);
    }
    json!({"status": "FALLEN", "since": since.map(|p| p.at), "at": at, "rows_fallen": fallen_rows.len(), "by_kind": by_kind(&fallen_rows),
           "quotes_gone": gone.len(), "questions_to_answer_again": questions, "rows": out_rows, "truncated": fallen_rows.len() > limit,
           "other_not_standing": {"by_kind": by_kind(&other),
                                  "meaning": "not standing, though no ground of theirs fell: a question or hypothesis without grounds, or an answer whose grounds stand but cannot all support it"},
           "provable": PROVABLE, "heuristic": HEURISTIC, "not_erased": NOT_ERASED})
}

/// `coverage`: what each structural unit of the documents came to and each pack of the gap pass, at the state `s` of `at` frames
/// (`directives::coverage`): the totals, the units of `doc` with `status` (all of them without the filters) and the packs. A
/// journal that gives no coverage says why and has no rows.
pub fn coverage(s: &AuditState, at: usize, doc: Option<&str>, status: Option<&str>, limit: Option<usize>) -> Value {
    use super::directives::{by_status, PACK_COLUMNS, UNIT_COLUMNS};
    let table = super::directives::coverage(s);
    let limit = limit_of(limit, DEFAULT_LIMIT);
    let object = |columns: &[&str], row: &[Value]| -> Value {
        let mut out = serde_json::Map::new();
        for (name, value) in columns.iter().zip(row) {
            // the ids of the quotes are a list here; the index keeps them as one text
            let value = if *name == "quoted_by" { value.as_str().and_then(|t| serde_json::from_str(t).ok()).unwrap_or(Value::Null) } else { value.clone() };
            out.insert(name.to_string(), value);
        }
        Value::Object(out)
    };
    let units: Vec<&Vec<Value>> = table.units.iter().filter(|r| doc.is_none_or(|d| r[0] == d)).filter(|r| status.is_none_or(|st| r[5] == st)).collect();
    let packs: Vec<&Vec<Value>> = table.packs.iter().filter(|r| doc.is_none_or(|d| r[1] == d)).collect();
    let mut out = json!({"status": "COVERAGE", "at": at, "doc_id": doc, "unit_status": status, "available": table.unavailable.is_none(),
        "section_bytes": table.section_bytes, "gap_pass": table.gap_pass, "summary": table.summary, "by_status": by_status(&table.units),
        "units": units.len(), "rows": units.iter().take(limit).map(|r| object(&UNIT_COLUMNS, r)).collect::<Vec<_>>(),
        "truncated": units.len() > limit,
        "packs": packs.iter().take(limit).map(|r| object(&PACK_COLUMNS, r)).collect::<Vec<_>>(), "packs_truncated": packs.len() > limit,
        "meaning": "a unit is a list item, a paragraph or a table row of a document, by its bytes; the totals are counts of these rows, drawn from the journal alone"});
    if let Some(reason) = table.unavailable {
        out["reason"] = json!(reason);
    }
    out
}

/// The snapshots of a journal at the points `at`, with the state at its end and what the check read: one verified replay of the
/// file, which is never written (`sbgk audit-read`, and a live server's `diff` and report `since`). A point past the end, or
/// before the genesis, has no snapshot.
pub fn journal_points(
    path: &std::path::Path,
    at: &[usize],
) -> crate::error::KResult<(AuditState, super::state::VerifiedJournal, usize, BTreeMap<usize, Snapshot>)> {
    let want: BTreeSet<usize> = at.iter().copied().collect();
    let mut found = BTreeMap::new();
    let mut entries = 0;
    let (state, read) = AuditState::verify_states(path, &mut |n, state, _| {
        entries = n;
        if want.contains(&n) {
            found.insert(n, Snapshot::of(state, n));
        }
    })?;
    Ok((state, read, entries, found))
}

/// The snapshots at the points `at` of the journal a live state writes: the point of its last frame is the state itself, and an
/// earlier one comes from a replay of its frames up to the latest earlier point asked, read through the writer's own handle
/// (`AuditState::replay_own`) and never written; the caller holds the state the while (the server, its lock). A point past the
/// frames written, or before the genesis, has no snapshot.
pub fn own_points(s: &mut AuditState, at: &[usize]) -> crate::error::KResult<BTreeMap<usize, Snapshot>> {
    let now = s.entries().unwrap_or(0);
    let want: BTreeSet<usize> = at.iter().copied().filter(|n| (1..=now).contains(n)).collect();
    let mut found = BTreeMap::new();
    if want.contains(&now) {
        found.insert(now, Snapshot::of(s, now));
    }
    if let Some(upto) = want.iter().copied().filter(|n| *n < now).max() {
        s.replay_own(upto, &mut |n, state| {
            if want.contains(&n) {
                found.insert(n, Snapshot::of(state, n));
            }
        })?;
    }
    Ok(found)
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
