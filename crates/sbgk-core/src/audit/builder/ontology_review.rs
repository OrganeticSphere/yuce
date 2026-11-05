//! Durable once-per-circle anomaly reviews. The frozen catalog owns identity, reviewer and shown capabilities.
use super::*;
/// The decision a review card asks for. The cautions of the revision prompt alone let a reviewer keep a
/// catch-all whose shown records it saw were about different things: offline on the 26 live review prompts of runs C1n_r2 and
/// H1c_r1, Sonnet 5.5 narrowed 0 of 15 catch-all reviews; with this rule Sonnet 15 of 15 (and narrowed one of 11 correct
/// concepts), Haiku 5.5 15 of 15 (none of the 11).
pub(super) const DECISION_RULE: &str = "DECISION RULE (it overrides the cautions above for this review): read every shown mapped \
record and its quote. If they describe two or more different things (different mechanisms, components, artefacts, subjects or scopes), \
the concept is too broad: propose revise_concept narrow into the specific concepts these records name and move each shown mapping to \
the concept it belongs to. If the concept's aliases join a replaced thing and its replacement, or two different things, propose narrow \
as well. Keep only when every shown record is about the same thing in the same scope. That a hint is not proof does not mean keep: the \
shown records are the evidence; decide from them.";
pub(super) fn enabled<S: AuditStore>(s: &S) -> bool {
    s.checkpoint("audit:mcp:coverage").is_some_and(|v| v["context"]["ontology_review"] == true)
}
pub(super) fn task(card: &Card) -> Option<&Value> {
    card.ontology.as_ref()?.get("review_task")
}
pub(super) fn decided<S: AuditStore>(s: &S, id: &str) -> bool {
    s.ontology_revision_state().is_some_and(|v| v["events"].as_array().into_iter().flatten().any(|e| e["op"] == "ontology_review" && e["review_id"] == id))
}
pub(super) fn exclusions(card: &Card) -> Vec<String> {
    if let Some(t) = task(card) {
        return t["excluded_mappers"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
    }
    card.review
        .as_ref()
        .and_then(|id| card.ontology.as_ref()?["pending"].as_array()?.iter().find(|p| p["proposal"] == *id)?["subject"].as_str().map(|v| vec![v.to_string()]))
        .unwrap_or_default()
}
pub(super) fn plan<S: AuditStore>(s: &S, circle: u64, readers: &[String]) -> Result<Vec<Value>, Value> {
    let mut by = BTreeMap::<ConceptId, Vec<Value>>::new();
    let pending = revisions::pending(s);
    for hint in revisions::all_hints(s).into_iter().filter(|h| h["kind"] != "unmapped_seed") {
        if let Some(c) = s.concepts().into_iter().find(|c| hint["concept"] == c.id.short()) {
            if !pending.iter().any(|p| p["change"]["concept"] == hex(&c.id.0)) {
                by.entry(c.id).or_default().push(hint);
            }
        }
    }
    let refiner = s.checkpoint("audit:mcp:coverage").and_then(|v| v["context"]["circle_refiner"].as_str().map(str::to_string));
    let mut out = Vec::new();
    for (id, hints) in by {
        let authors = s.mapping_authors_of(&id).ok_or_else(|| json!({"code":"MAPPER_ATTRIBUTION_UNAVAILABLE","concept":id.short()}))?;
        if authors.iter().any(|(a, _)| !readers.contains(a) && refiner.as_ref() != Some(a)) {
            return Err(json!({"code":"MAPPER_OUTSIDE_RING","concept":id.short()}));
        }
        // The circles +1 refiner never reviews, so its mappings do not move the choice among the readers.
        let counts = authors.into_iter().filter(|(a, _)| readers.contains(a)).collect::<BTreeMap<_, _>>();
        let max = counts.values().copied().max().unwrap_or(0);
        let rotated = (0..readers.len()).map(|i| &readers[((circle.saturating_sub(1) as usize) + i) % readers.len()]).collect::<Vec<_>>();
        // Exclude every maximum mapper, including ties. Start at its next clockwise neighbor.
        let mut excluded = rotated.iter().filter(|a| max > 0 && counts.get(**a) == Some(&max)).map(|a| (*a).clone()).collect::<Vec<_>>();
        let start = excluded
            .first()
            .and_then(|who| readers.iter().position(|a| a == who))
            .map_or((circle.saturating_sub(1) as usize) % readers.len(), |i| (i + 1) % readers.len());
        let mut independence = "non_maximum_mapper";
        let reviewer = match (0..readers.len()).map(|i| &readers[(start + i) % readers.len()]).find(|a| !excluded.contains(a)) {
            Some(r) => r,
            // Every reader tied as a maximum mapper (a broad concept everyone used): the review still happens, by the circle's
            // rotation, and the card says its independence is weak. Stopping here would leave exactly such concepts unreviewed.
            None => {
                independence = "weak_all_readers_mapped";
                let r = &readers[(circle.saturating_sub(1) as usize) % readers.len()];
                excluded = readers.iter().filter(|a| *a != r).cloned().collect();
                r
            }
        };
        let concept = s.concept(&id).ok_or_else(|| json!({"code":"UNKNOWN_REVIEW_CONCEPT"}))?;
        let (mut distribution, distributed_roots) = super::distribution::distribution(s, &id);
        let chosen = if hints.iter().any(|h| h["kind"] == "possible_catchall") {
            distributed_roots
        } else {
            distribution = json!({"available":false,"reason":"not a catchall review"});
            s.records_of(&id)
        };
        let mut roots = chosen.iter().filter_map(|id| s.record(id)).collect::<Vec<_>>();
        roots.sort_by_key(|r| std::cmp::Reverse(r.seq));
        roots.truncate(8);
        let mut basis = super::super::pairs::cone(s, &roots.iter().map(|r| r.id).collect::<Vec<_>>());
        let rendered = distribution["term_groups"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|g| [&g["sample"]["mapped_record"], &g["sample"]["observe"]])
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<BTreeSet<_>>();
        let protected = basis.iter().filter(|r| rendered.contains(&r.id.short())).cloned().collect::<Vec<_>>();
        basis.sort_by_key(|r| std::cmp::Reverse(r.seq));
        basis.truncate(64);
        for r in protected {
            if !basis.iter().any(|v| v.id == r.id) {
                basis.push(r);
            }
        }
        if !basis.iter().any(|r| r.kind == RecordKind::Observe && s.is_answer_support(&r.id)) {
            basis.extend(s.records_since(0).into_iter().rev().filter(|r| r.kind == RecordKind::Observe && s.is_answer_support(&r.id)).take(8));
        }
        if basis.is_empty() {
            return Err(json!({"code":"NO_ONTOLOGY_REVIEW_BASIS","concept":id.short()}));
        }
        let want = std::iter::once(&concept.name).chain(&concept.aliases).flat_map(|v| words(v)).collect::<BTreeSet<_>>();
        let mut candidates = s
            .concepts()
            .into_iter()
            .filter(|c| c.id != id && c.selectable())
            .map(|c| {
                let overlap = std::iter::once(&c.name).chain(&c.aliases).flat_map(|v| words(v)).collect::<BTreeSet<_>>().intersection(&want).count();
                (overlap + usize::from(c.ty == concept.ty), c.id)
            })
            .filter(|(score, _)| *score > 0)
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        // the concepts the same records are already mapped to come first, so a narrow can move a mapping to the concept it belongs
        // to instead of proposing a near duplicate (offline on run C1n_r2, 2026-10-27: 9 of 103 and 4 of 122 proposed moves went
        // to existing concepts; the review showed only concepts of the same type or with shared words)
        let mut shared = BTreeMap::<ConceptId, usize>::new();
        for r in s.records_of(&id) {
            for c in s.concepts_of(&r) {
                if c != id && s.concept(&c).is_some_and(|v| v.selectable()) {
                    *shared.entry(c).or_default() += 1;
                }
            }
        }
        let mut shared = shared.into_iter().collect::<Vec<_>>();
        shared.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        shared.truncate(16);
        let mut candidates =
            shared.into_iter().map(|(c, n)| (n, c)).chain(std::mem::take(&mut candidates)).fold(Vec::<(usize, ConceptId)>::new(), |mut out, (n, c)| {
                if !out.iter().any(|(_, x)| *x == c) {
                    out.push((n, c));
                }
                out
            });
        candidates.truncate(32);
        let review_id = format!("O{}", digest(&json!(["r2r-ontology-review/1", hex(&s.run_namespace()), circle, hex(&id.0)])));
        out.push(json!({"id":review_id,"circle":circle,"concept":hex(&id.0),"concept_short":id.short(),"hints":hints,"reviewer":reviewer,
            "reviewer_independence":independence,"excluded_mappers":excluded,"mapping_counts":counts,"tie_break":"exclude_all_maximum_mappers_clockwise",
            "records":basis.iter().map(|r|hex(&r.id.0)).collect::<BTreeSet<_>>(),"candidate_ids":std::iter::once(hex(&id.0)).chain(candidates.into_iter().map(|(_,id)|hex(&id.0))).collect::<Vec<_>>(),"basis_scope_limited":true,"mapping_distribution":distribution}));
    }
    Ok(out)
}
impl Builder {
    pub(super) fn ontology_review_card<S: AuditStore>(&mut self, s: &S, spec: &Value) -> Option<Card> {
        let mut candidates = BTreeMap::new();
        candidates.insert(
            "review".into(),
            spec["candidate_ids"]
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(ConceptId).and_then(|id| s.concept(&id)))
                .collect(),
        );
        let neighbors =
            spec["records"].as_array()?.iter().filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(RecordId).and_then(|id| s.record(&id))).collect();
        let mut shown_spec = spec.clone();
        shown_spec["hints"] = json!(spec["hints"].as_array().into_iter().flatten().filter(|h| h["kind"] != "unmapped_seed").collect::<Vec<_>>());
        let card = Card {
            card_id: format!("R{}-{}-{}", self.cursor, self.cursor, spec["id"].as_str()?),
            cursor_from: self.cursor,
            cursor_to: self.cursor,
            records: vec![],
            candidates,
            neighbors,
            concept_types: s.concept_types(),
            max_ops: 1,
            max_links: 0,
            pair: None,
            ontology: Some(json!({"pending":[],"hints":shown_spec["hints"],"review_task":shown_spec})),
            review: Some(spec["id"].as_str()?.to_string()),
            functions: None,
        };
        self.done_ops = 0;
        self.proposed.clear();
        self.last = None;
        self.restore(s, &card);
        self.open = Some(card.clone());
        Some(card)
    }
}
