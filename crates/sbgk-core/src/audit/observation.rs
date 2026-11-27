//! The observation report (`yuce-observation-report/1`), as `verifier/spec/SPEC_OBSERVATION_REPORT_v1.md` fixes it: for every
//! claim of one sealed journal, or of the journals of a cut, three independent axes and the map around them.
//!
//! - support: does the claim stand on its evidence now, and if not, on which withdrawn or replaced quotes it fell;
//! - dispute: is it contradicted by a standing claim;
//! - time: has a standing later claim replaced it.
//!
//! The axes are never merged into one status and the debt counters are never summed into one number. The report holds no
//! judgement of meaning: every value is read from the state the journal replays to. The independent verifier recomputes the
//! report from the same files and compares it byte for byte.

use super::cut::{utf16_order, Cut, Part};
use super::read::{first_causes, Row, Snapshot};
use super::state::RecordState;
use super::{AuditStore, LinkId, LinkStatus, LinkView, RecordId, RecordKind};
use crate::hash::{from_hex, sha256_parts, to_hex, Hash};
use crate::jcs::to_jcs;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The format a report names.
pub const REPORT_FORMAT: &str = "yuce-observation-report/1";

/// The debt counters of a journal, in the order the specification lists them (section 6). The last two count frames of the
/// journal's part, not claims: the answers the kernel refused, wholly or in part, and the answers sent to a task that was
/// already closed.
const DEBT: [&str; 8] =
    ["affected", "contested", "resting_on_contested", "stale", "questions_about_claims", "key_conflicts", "rejected_submissions", "late_submissions"];

/// What the report reads of one journal's part.
struct View<'a> {
    name: &'a str,
    part: &'a Part,
    rows: Vec<Row>,
    index: HashMap<RecordId, usize>,
    links: Vec<LinkView>,
    usable: BTreeSet<LinkId>,
    /// The ends of every relation record: a link of such ends is declared by the journal itself (section 5).
    declared: BTreeSet<(RecordId, String, RecordId)>,
}

impl<'a> View<'a> {
    fn of(name: &'a str, part: &'a Part) -> Self {
        let rows = Snapshot::of(&part.state, part.log_size).rows;
        let index = rows.iter().enumerate().map(|(i, row)| (row.id, i)).collect();
        let mut links = AuditStore::links(&part.state);
        links.sort_by_key(|link| link.id);
        let declared = part.state.records_of_kind(RecordKind::Relation).into_iter().filter_map(|r| r.ends).collect();
        View { name, part, rows, index, links, usable: part.state.usable_links(), declared }
    }

    fn stands(&self, id: &RecordId) -> bool {
        self.index.get(id).is_some_and(|i| self.rows[*i].grounded)
    }

    fn kind(&self, id: &RecordId) -> Option<&str> {
        self.index.get(id).map(|i| self.rows[*i].kind.as_str())
    }

    /// A link as an axis lists it; `other` is the end the axis reads.
    fn link(&self, link: &LinkView, other: &RecordId) -> Value {
        json!({"link": to_hex(&link.id.0), "rel": link.rel, "from": to_hex(&link.from.0), "to": to_hex(&link.to.0), "status": link.status.name(),
               "other_grounded": self.stands(other), "usable": self.usable.contains(&link.id)})
    }

    /// The root causes of a claim that does not stand (section 3): the observations that do not stand under it, in record order,
    /// each with the reason the first command that revoked its anchor fixed, or `version_replaced` when none did.
    fn root_causes(&self, claim: RecordId) -> Vec<Value> {
        first_causes(&self.rows, &self.index, claim)
            .into_iter()
            .map(|cause| {
                let fate = self.part.state.quote_fate(&cause).unwrap_or(Value::Null);
                json!({"record": to_hex(&cause.0), "reason": fate["cause"]})
            })
            .collect()
    }

    /// The dispute axis of a claim (section 4) and every `contradicts` link the claim is an end of, by link id.
    fn dispute(&self, claim: &RecordId) -> (&'static str, Vec<Value>) {
        let links: Vec<(&LinkView, RecordId)> = self
            .links
            .iter()
            .filter(|link| link.rel == "contradicts" && (link.from == *claim || link.to == *claim))
            .map(|link| (link, if link.from == *claim { link.to } else { link.from }))
            .collect();
        let accepted = |status: LinkStatus| status == LinkStatus::Accepted;
        let axis = if links.iter().any(|(link, other)| accepted(link.status) && self.stands(other)) {
            "contested"
        } else if links.iter().any(|(link, other)| link.status == LinkStatus::Proposed || (accepted(link.status) && !self.stands(other))) {
            "unknown"
        } else {
            "uncontested"
        };
        (axis, links.iter().map(|(link, other)| self.link(link, other)).collect())
    }

    /// The time axis of a claim (section 5) and every `supersedes` link to the claim, by link id.
    fn time(&self, claim: &RecordId) -> (&'static str, Vec<Value>) {
        let to_claim: Vec<&LinkView> = self.links.iter().filter(|link| link.rel == "supersedes" && link.to == *claim).collect();
        let kept: Vec<&&LinkView> = to_claim.iter().filter(|link| link.status != LinkStatus::Rejected).collect();
        let declared = |link: &LinkView| self.declared.contains(&(link.from, link.rel.clone(), link.to));
        let axis = if kept.iter().any(|link| self.stands(&link.from) && (link.status == LinkStatus::Accepted || declared(link))) {
            "stale"
        } else if !kept.is_empty() {
            "unknown"
        } else {
            "current"
        };
        (axis, to_claim.iter().map(|link| self.link(link, &link.from)).collect())
    }

    /// The record a question is about (`about_record`, rules 4), when it names one.
    fn about(&self, question: &RecordId) -> Option<RecordId> {
        let position = self.part.position(question)?;
        let about = self.part.state.record_at(position).body["about_record"].as_str()?;
        from_hex(about.trim_start_matches('@')).map(RecordId)
    }

    /// The conflicting values of exact keys (section 6), as the kernel's exact-key reads find them: a key is the `subject` of a
    /// claim, its value the `object` (`null` without one), and a key is in conflict while its active claims say two values or more.
    fn key_conflicts(&self) -> Vec<Value> {
        let mut values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (claim, state) in self.part.state.claims_with_states() {
            if let (RecordState::Active, Some(subject)) = (state, claim.body["subject"].as_str()) {
                values.entry(subject.to_string()).or_default().insert(to_jcs(claim.body.get("object").unwrap_or(&Value::Null)));
            }
        }
        let mut conflicts: Vec<(String, Vec<String>)> = values.into_iter().filter(|(_, v)| v.len() > 1).map(|(k, v)| (k, v.into_iter().collect())).collect();
        conflicts.sort_by(|a, b| utf16_order(&a.0, &b.0));
        conflicts
            .into_iter()
            .map(|(subject, mut values)| {
                values.sort_by(|a, b| utf16_order(a, b));
                let values: Vec<Value> = values.iter().map(|v| serde_json::from_str(v).expect("canonical JSON")).collect();
                json!({"journal": self.name, "subject": subject, "values": values})
            })
            .collect()
    }
}

/// The report of one sealed journal alone: its name in the report is its run id, and `cut_hash` is null.
pub fn of_journal(part: &Part) -> Value {
    report(&[(part.state.run_id(), part)], None, &BTreeMap::new())
}

/// The report of the journals of a cut: `rests_on_across` names, for a claim that rests on a quote of a delivered export, the
/// journal the export was made from and the record of the paragraph quoted.
pub fn of_cut(cut: &Cut) -> Value {
    let mut across: BTreeMap<(usize, RecordId), BTreeSet<(usize, RecordId)>> = BTreeMap::new();
    for hit in cut.across() {
        let delivery = &cut.deliveries[hit.delivery];
        across.entry((delivery.journal, hit.observation)).or_default().insert((cut.exports[delivery.export].journal, hit.record));
    }
    let parts: Vec<(&str, &Part)> = cut.parts.iter().map(|(name, part)| (name.as_str(), part)).collect();
    report(&parts, Some(cut.cut_hash), &across)
}

/// `report_hash = H("YUCE-OBS-REPORT/1", JCS(report without "report_hash"))` (section 7).
pub fn report_hash(body: &Value) -> Hash {
    sha256_parts(&[b"YUCE-OBS-REPORT/1\0", to_jcs(body).as_bytes()])
}

/// The bytes of a report file: canonical JSON, without a line feed after it.
pub fn report_bytes(report: &Value) -> Vec<u8> {
    to_jcs(report).into_bytes()
}

/// `across`: for a quote of a journal (its place in `parts`, the observation), the journals and records it quotes across.
fn report(parts: &[(&str, &Part)], cut_hash: Option<Hash>, across: &BTreeMap<(usize, RecordId), BTreeSet<(usize, RecordId)>>) -> Value {
    let views: Vec<View> = parts.iter().map(|(name, part)| View::of(name, part)).collect();
    let mut claims = Vec::new();
    // per journal, the claims with their dispute axis, and the claim grounds of each claim: within the journal and across
    let mut contested: BTreeSet<(usize, RecordId)> = BTreeSet::new();
    let mut claim_grounds: Vec<Vec<Vec<(usize, RecordId)>>> = Vec::new();
    let mut counters: Vec<BTreeMap<&str, usize>> = Vec::new();
    for (j, view) in views.iter().enumerate() {
        let mut debt: BTreeMap<&str, usize> = DEBT.iter().map(|name| (*name, 0)).collect();
        let mut grounds_of_claims = Vec::new();
        let mut questions: BTreeMap<RecordId, BTreeSet<String>> = BTreeMap::new();
        for row in view.rows.iter().filter(|row| row.kind == "question") {
            let Some(about) = view.about(&row.id) else { continue };
            if view.kind(&about) == Some("claim") {
                debt.entry("questions_about_claims").and_modify(|n| *n += 1);
                questions.entry(about).or_default().insert(to_hex(&row.id.0));
            }
        }
        for (position, row) in view.rows.iter().enumerate().filter(|(_, row)| row.kind == "claim") {
            let record = view.part.state.record_at(position);
            let (frame, author) = view.part.accepted_by(position);
            let mut seen = BTreeSet::new();
            let based_on: Vec<RecordId> = record.based_on.iter().filter(|g| seen.insert(**g)).copied().collect();
            // two observations of the same bytes of the same version are two grounds and one entry: no array of the report holds
            // a duplicate (section 6)
            let mut quoted = BTreeSet::new();
            let quotes: Vec<Value> = based_on
                .iter()
                .filter(|g| view.kind(g) == Some("observe"))
                .filter_map(|g| view.part.state.evidence_binding(g).map(|b| (g, b)))
                .filter_map(|(g, (_, version, start, end))| {
                    let doc_id = view.part.position(g).and_then(|p| view.part.state.record_at(p).doc_id.clone());
                    quoted
                        .insert((doc_id.clone(), version, start, end))
                        .then(|| json!({"doc_id": doc_id, "version": to_hex(&version), "start": start, "end": end}))
                })
                .collect();
            let rests_on: Vec<RecordId> = based_on.iter().filter(|g| view.kind(g) == Some("claim")).copied().collect();
            let mut far: Vec<(usize, RecordId)> = based_on.iter().filter_map(|g| across.get(&(j, *g))).flatten().copied().collect();
            far.sort_by(|a, b| utf16_order(views[a.0].name, views[b.0].name).then(a.1.cmp(&b.1)));
            far.dedup();
            let (dispute, dispute_links) = view.dispute(&row.id);
            let (time, time_links) = view.time(&row.id);
            let root_causes = if row.grounded { Vec::new() } else { view.root_causes(row.id) };
            if !row.grounded {
                debt.entry("affected").and_modify(|n| *n += 1);
            }
            if dispute == "contested" {
                debt.entry("contested").and_modify(|n| *n += 1);
                contested.insert((j, row.id));
            }
            if time == "stale" {
                debt.entry("stale").and_modify(|n| *n += 1);
            }
            claims.push(json!({
                "journal": view.name,
                "id": to_hex(&row.id.0),
                "author": author,
                "frame": frame,
                "quotes": quotes,
                "rests_on": rests_on.iter().map(|g| to_hex(&g.0)).collect::<Vec<_>>(),
                "rests_on_across": far.iter().map(|(source, record)| json!({"journal": views[*source].name, "record": to_hex(&record.0)})).collect::<Vec<_>>(),
                "questions": questions.get(&row.id).map(|q| q.iter().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "support": if row.grounded { "grounded" } else { "affected" },
                "root_causes": root_causes,
                "dispute": dispute,
                "dispute_links": dispute_links,
                "time": time,
                "time_links": time_links,
            }));
            grounds_of_claims.push(rests_on.into_iter().map(|g| (j, g)).chain(far).collect::<Vec<_>>());
        }
        claim_grounds.push(grounds_of_claims);
        counters.push(debt);
    }
    let mut key_conflicts = Vec::new();
    for (j, view) in views.iter().enumerate() {
        let found = view.key_conflicts();
        counters[j].insert("key_conflicts", found.len());
        counters[j].insert("rejected_submissions", view.part.rejected_submissions);
        counters[j].insert("late_submissions", view.part.late_submissions);
        counters[j].insert("resting_on_contested", claim_grounds[j].iter().filter(|grounds| grounds.iter().any(|g| contested.contains(g))).count());
        key_conflicts.extend(found);
    }
    key_conflicts.sort_by(|a, b| {
        let text = |v: &Value, key: &str| v[key].as_str().unwrap_or_default().to_string();
        utf16_order(&text(a, "journal"), &text(b, "journal")).then(utf16_order(&text(a, "subject"), &text(b, "subject")))
    });
    let total: Map<String, Value> = DEBT.iter().map(|name| (name.to_string(), json!(counters.iter().map(|c| c[name]).sum::<usize>()))).collect();
    let by_journal: Map<String, Value> = views.iter().zip(&counters).map(|(view, debt)| (view.name.to_string(), json!(debt))).collect();
    let mut body = json!({
        "format": REPORT_FORMAT,
        "mode": "observe",
        "cut_hash": cut_hash.map(|hash| to_hex(&hash)),
        "journals": views.iter().map(|v| json!({"name": v.name, "seal_hash": to_hex(&v.part.seal_hash), "log_size": v.part.log_size})).collect::<Vec<_>>(),
        "claims": claims,
        "key_conflicts": key_conflicts,
        "debt": {"total": total, "by_journal": by_journal},
    });
    body["report_hash"] = json!(to_hex(&report_hash(&body)));
    body
}
