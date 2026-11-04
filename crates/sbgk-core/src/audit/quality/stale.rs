//! A projection of durable acceptance history, not a revival of invalid evidence.
use super::evolution::{date, document};
use super::*;
/// A claim that lost support with its newest evidence withdrawn while older evidence stands: the date of its latest standing
/// quote, the date of its latest withdrawn one, and the reports of the withdrawn quotes after the standing date. Run C1r_r1,
/// withdrawal 2B, as in the four runs before it: both 08-10 quotes on the replaced port were withdrawn, the 07-29 and 07-31 ones
/// stood, and the restated answer gave the old state as current. No supersedes link was accepted, so the history above saw
/// nothing. Undated reports give no time order.
fn evidence_gap<S: AuditStore>(s: &S, id: RecordId) -> Option<(String, String, BTreeSet<String>)> {
    if s.is_grounded(&id) || s.record(&id)?.kind != RecordKind::Claim {
        return None;
    }
    let (mut kept, mut lost) = (String::new(), Vec::new());
    for o in super::super::pairs::cone(s, &[id]).into_iter().filter(|r| r.kind == RecordKind::Observe) {
        let Some(d) = o.doc_id else { continue };
        let dt = date(s, &d);
        if dt.is_empty() {
            continue;
        }
        if s.is_grounded(&o.id) {
            kept = kept.max(dt);
        } else {
            lost.push((dt, d));
        }
    }
    let latest = lost.iter().map(|(dt, _)| dt.clone()).max()?;
    if kept.is_empty() || latest <= kept {
        return None;
    }
    let reports = lost.into_iter().filter(|(dt, _)| *dt > kept).map(|(_, d)| d).collect();
    Some((kept, latest, reports))
}
/// Support and time are separate (registry R30): a withdrawn claim may still mark that a later state existed, and a standing
/// claim may be superseded. `LATEST_KNOWN` means no later state is known to the graph, not that the state is current.
pub fn annotation<S: AuditStore>(s: &S, id: RecordId) -> Value {
    if !enabled(s, "stale_suspect") {
        return Value::Null;
    }
    let hs = s.supersession_history().into_iter().filter(|l| l.to == id).collect::<Vec<_>>();
    let gap = evidence_gap(s, id);
    if hs.is_empty() && gap.is_none() {
        return Value::Null;
    }
    let broken = hs.iter().filter(|l| !s.is_grounded(&l.from)).collect::<Vec<_>>();
    let current = hs.iter().any(|l| l.status == LinkStatus::Accepted && s.link_usable(&l.id));
    let stale = !current && (!broken.is_empty() || gap.is_some());
    let d = document(s, id).unwrap_or_default();
    let mut reports = broken.iter().flat_map(|l| super::super::pairs::cone(s, &[l.from])).filter_map(|r| r.doc_id).collect::<BTreeSet<_>>();
    let mut a = json!({"superseded_by":hs.iter().map(|l|l.from.short()).collect::<BTreeSet<_>>(),
        "stale_suspect":stale,"historical_date":date(s,&d),
        "support_status":if s.is_grounded(&id) {"GROUNDED"} else {"WITHDRAWN"},
        "temporal_status":if current {"SUPERSEDED"} else if stale {"CURRENT_UNCERTAIN"} else {"LATEST_KNOWN"}});
    if let Some((kept, latest, docs)) = gap {
        reports.extend(docs);
        a["historical_date"] = json!(kept);
        a["evidence_gap"] = json!({"evidence_until":kept,"withdrawn_after":latest});
    }
    a["withdrawn_update_reports"] = json!(reports);
    a
}
/// The stale suspects of the current state, as the store keeps them for an unchanged state (`suspects_fresh` when it does not).
pub fn suspects<S: AuditStore>(s: &S) -> Vec<RecordId> {
    s.stale_suspects().unwrap_or_else(|| suspects_fresh(s))
}
pub fn suspects_fresh<S: AuditStore>(s: &S) -> Vec<RecordId> {
    if !enabled(s, "stale_suspect") {
        return vec![];
    }
    let mut ids = s.supersession_history().into_iter().map(|l| l.to).collect::<BTreeSet<_>>();
    // one support pass for every claim: `is_grounded` claim by claim redid the whole pass each time, 1 s per call at 1 500 records
    // and three calls per poll of a waiting agent (perf on audit-serve, 2026-10-28: 99% of an idle server's CPU)
    let support = s.support_map();
    let grounded = |id: &RecordId| support.as_ref().map_or_else(|| s.is_grounded(id), |m| m.get(id).is_some_and(|v| v.0));
    ids.extend(s.records_of_kind(RecordKind::Claim).into_iter().filter(|r| !grounded(&r.id)).map(|r| r.id));
    ids.into_iter().filter(|id| annotation(s, *id)["stale_suspect"] == true).collect()
}
pub fn warning<S: AuditStore>(s: &S, id: RecordId) -> String {
    let a = annotation(s, id);
    if a["stale_suspect"] != true {
        return String::new();
    }
    let date = a["historical_date"].as_str().unwrap_or("unknown date");
    if let Some(after) = a["evidence_gap"]["withdrawn_after"].as_str() {
        return format!("{} stale_suspect: its evidence dated up to {date} stands; its later evidence dated {after} was withdrawn. As of {date} the earlier state was recorded; the state after {date} is unconfirmed. Do not present the earlier state as current. superseded_by={}",id.short(),a["superseded_by"]);
    }
    format!("{} stale_suspect: as of {date} the earlier claim was recorded; a later update lost support after withdrawal. Current state is unconfirmed. Do not present the older state as current. superseded_by={}",id.short(),a["superseded_by"])
}
pub fn prompt<S: AuditStore>(s: &S) -> String {
    let rows = suspects(s).into_iter().map(|id| warning(s, id)).collect::<Vec<_>>();
    if rows.is_empty() {
        String::new()
    } else {
        format!("\nTEMPORAL WARNINGS (kernel, retained from accepted supersession history and from the dates of withdrawn evidence):\n{}\nState these items historically with the date; say the later update was withdrawn and current state is unconfirmed, unless another record shown confirms the later state from standing evidence dated after that date. Never infer a new state.\n",rows.join("\n"))
    }
}
/// Sections to reread for a stale claim: only the later reports that held the withdrawn evidence, when they are known. Another
/// quote there may carry the same later state (run S1.3, withdrawal 2B: arm A found other support in the 08-10 report); the
/// other later reports were read before. Offline on run C1r_r1, withdrawal 2B: four claims superseded by one withdrawn update
/// asked 17 to 19 sections each over every later report, 72 tasks for one step.
pub fn later_sections<S: AuditStore>(s: &S, id: RecordId, size: usize) -> Vec<(String, usize, usize)> {
    let a = annotation(s, id);
    let old = document(s, id).unwrap_or_default();
    let old_date = a["historical_date"].as_str().unwrap_or_default().to_string();
    let only_withdrawn = a["withdrawn_update_reports"].as_array().is_some_and(|r| !r.is_empty());
    let cfg = config(s);
    let order = cfg["evolution_document_order"].as_array().cloned().unwrap_or_default();
    let preferred = a["withdrawn_update_reports"].as_array().cloned().unwrap_or_default();
    let mut docs = s
        .docs()
        .into_iter()
        .filter(|d| {
            let dt = date(s, d);
            if !old_date.is_empty() && !dt.is_empty() {
                // one date orders nothing, but another report of that date which held the withdrawn evidence of the replacement is
                // reread all the same (Codex review MDATE-01 of c8c13a4: with two pages of one release dated, the later state's
                // page was dropped here, before the filter on the withdrawn reports below)
                dt > old_date || (dt == old_date && *d != old && preferred.contains(&json!(d)))
            } else {
                order.iter().position(|x| x == &old).zip(order.iter().position(|x| x == d)).is_some_and(|(a, b)| a < b)
            }
        })
        .collect::<Vec<_>>();
    if only_withdrawn {
        docs.retain(|d| preferred.contains(&json!(d)));
    }
    docs.sort_by_key(|d| (!preferred.contains(&json!(d)), date(s, d), d.clone()));
    docs.into_iter()
        .flat_map(|d| super::super::directives::sections(&s.doc_text(&d).unwrap_or_default(), size).into_iter().map(move |(a, b)| (d.clone(), a, b)))
        .collect()
}
pub fn investigation_section<S: AuditStore>(s: &S, id: RecordId, section: &(String, usize, usize)) -> (String, Scope, Vec<RecordId>) {
    let (d, a, b) = section;
    let doc = s.doc_text(d).unwrap_or_default();
    let scope = Scope { docs: vec![d.clone()], ranges: vec![(d.clone(), *a, *b)], ..Default::default() };
    let text=format!("TASK INVESTIGATE: priority reread after a withdrawal. {}\nFind independent later confirmation of the same subject/version/scope. Do not reuse withdrawn evidence; absence of confirmation leaves current state unconfirmed.\nSECTION doc_id=\"{d}\" (bytes {a}..{b}):\n<<<\n{}\n>>>\n",warning(s,id),&doc[*a..*b]);
    (text, scope, vec![])
}

/// Answer projections retain the author's text and attach the kernel's temporal qualification, for any claim an answer lists: a
/// summary's own and a reader's claim it names in its answer ids (ANS-01, run MCPpair_r1: 46 of the RQ1 answer's claims were
/// readers', four of them superseded by an accepted link and one a stale suspect, and none was marked). A summary's claim is told
/// every stale suspect its quotes reach; a reader's claim only its own suspicion: a suspect it merely shares a quote with is
/// another claim and may be another subject, and the answer would call the reader's fact historical (Codex review of 729eda8,
/// BATCH-02: the old pump state's suspicion marked the valve fact beside it on the same quote).
pub fn answer_warnings<S: AuditStore>(s: &S, id: RecordId) -> Vec<String> {
    let Some(r) = s.record(&id).filter(|r| r.kind == RecordKind::Claim) else {
        return vec![];
    };
    if !super::super::directives::is_summary_directive(&r.directive) {
        return suspects(s).into_iter().filter(|old| *old == id).map(|old| warning(s, old)).collect();
    }
    let bases = super::super::pairs::cone(s, &r.based_on).into_iter().filter(|r| r.kind == RecordKind::Observe).map(|r| r.id).collect::<BTreeSet<_>>();
    suspects(s).into_iter().filter(|old| super::super::pairs::cone(s, &[*old]).iter().any(|r| bases.contains(&r.id))).map(|old| warning(s, old)).collect()
}

/// The temporal status of a claim for the reader of an answer that lists it (registry R34a): a summary's own claim, or a reader's
/// claim the summary names in its answer ids (ANS-01, as in `answer_warnings`). A claim rests on observes only, so a
/// state is reached by its quotes, as in `answer_warnings`; one quote may hold several states, and two quotes do not say which
/// state the text states (Codex review of 40f97e0, R34-01/02). So the status names the evidence under the claim, not the truth
/// of its text: `CITES_REPLACED` when it rests on a quote of a record that a standing accepted `supersedes` link replaces and on
/// no quote of the record replacing it (it may state the earlier state), `CITES_EARLIER_AND_LATER` when it rests on quotes of
/// both (it may state the change, or either state), `CURRENT_UNCERTAIN` when `answer_warnings` found a stale suspect under it
/// (`uncertain`), else `LATEST_KNOWN`: no replaced state is among its grounds, which is not proof that the state is current.
/// Codex's check of bc7cf23: a retained earlier row stood in the final answer next to the later one with no mark. A reader's claim
/// that is itself the replaced state rests on its own quotes, so it is told `CITES_REPLACED`. `Value::Null` for any record that is
/// not a claim, or without `stale_suspect`.
pub fn answer_status<S: AuditStore>(s: &S, id: RecordId, uncertain: bool) -> Value {
    let versions = s.has_checkpoint(super::super::versions::KEY);
    if !enabled(s, "stale_suspect") && !versions {
        return Value::Null;
    }
    let Some(r) = s.record(&id).filter(|r| r.kind == RecordKind::Claim) else {
        return Value::Null;
    };
    let quotes = super::super::pairs::cone(s, &r.based_on).into_iter().filter(|r| r.kind == RecordKind::Observe).map(|r| r.id).collect::<BTreeSet<_>>();
    let rests_on = |state: RecordId| super::super::pairs::cone(s, &[state]).iter().any(|r| quotes.contains(&r.id));
    let usable = s.usable_links();
    let standing = |l: &LinkView| l.status == LinkStatus::Accepted && usable.as_ref().map_or_else(|| s.link_usable(&l.id), |u| u.contains(&l.id));
    // a state is dated by the latest report it rests on: `document` names a report only when there is one, and a later state on
    // quotes of two pages read "report date unknown" in the answer (run MCPpair_r1). The latest known supporting report date,
    // not the time of the state, nor the order of the link (Codex review of 729eda8, N1)
    let dated = |r: RecordId| super::super::pairs::cone(s, &[r]).into_iter().filter_map(|x| x.doc_id).map(|d| date(s, &d)).max().unwrap_or_default();
    let (mut replaced, mut earlier_and_later, mut unavailable) = (vec![], vec![], vec![]);
    for l in s.supersession_history().into_iter().filter(|l| rests_on(l.to)) {
        let pair = json!({"earlier": l.to.short(), "earlier_date": dated(l.to), "later": l.from.short(), "later_date": dated(l.from)});
        if !standing(&l) {
            if versions {
                unavailable.push(pair);
            }
            continue;
        }
        if rests_on(l.from) { &mut earlier_and_later } else { &mut replaced }.push(pair);
    }
    let status = if !replaced.is_empty() {
        "CITES_REPLACED"
    } else if !earlier_and_later.is_empty() {
        "CITES_EARLIER_AND_LATER"
    } else if uncertain || !unavailable.is_empty() {
        "CURRENT_UNCERTAIN"
    } else {
        "LATEST_KNOWN"
    };
    let mut result = json!({"temporal_status": status, "replaced": replaced, "earlier_and_later": earlier_and_later});
    if versions && !unavailable.is_empty() {
        result["unavailable_replacements"] = json!(unavailable);
    }
    result
}
