use super::*;
pub(super) fn distribution<S: AuditStore>(s: &S, id: &ConceptId) -> (Value, Vec<RecordId>) {
    let Some(maps) = s.mapped_terms_of(id) else {
        return (json!({"available":false,"reason":"mapping inventory unavailable"}), vec![]);
    };
    let mut reports = BTreeMap::<String, usize>::new();
    let mut terms = BTreeMap::<String, Vec<RecordId>>::new();
    for (r, t) in &maps {
        terms.entry(t.clone()).or_default().push(*r);
        for d in super::super::pairs::cone(s, &[*r]).iter().filter_map(|r| r.doc_id.as_ref()).collect::<BTreeSet<_>>() {
            *reports.entry(d.clone()).or_default() += 1;
        }
    }
    let total_groups = terms.len();
    let mut sorted = terms.into_iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    sorted.truncate(8);
    let mut groups = vec![];
    let mut shown = vec![];
    let mut shown_mappings = 0;
    for (term, mut ids) in sorted {
        ids.sort();
        shown_mappings += ids.len();
        let sample = ids.iter().find_map(|rid| {
            super::super::pairs::cone(s, &[*rid]).into_iter().find(|r| r.kind == RecordKind::Observe && s.is_answer_support(&r.id)).map(|quote| (*rid, quote))
        });
        let mut g = json!({"term":term,"mappings":ids.len()});
        if let Some((rid, q)) = sample {
            shown.push(rid);
            g["sample"] = json!({"mapped_record":rid.short(),"observe":q.id.short(),"report":q.doc_id,"quote_excerpt":q.quote.as_deref().unwrap_or("").chars().take(240).collect::<String>()});
        }
        groups.push(g);
    }
    (
        json!({"available":true,"total_mappings":maps.len(),"count_unit":"stored_record_term_concept_associations","by_report":reports,"report_counts_may_overlap":true,"term_groups":groups,"omitted_term_groups":total_groups.saturating_sub(8),"omitted_mappings":maps.len().saturating_sub(shown_mappings),"interpretation":"retrieval distribution, not evidence that any named concept is wrong"}),
        shown,
    )
}
