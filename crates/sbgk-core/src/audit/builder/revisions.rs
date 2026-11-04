//! Bounded, grounded revision context. Heuristics flag review opportunities, never semantic verdicts.
use super::*;
pub(super) const PROMPT: &str = "Ontology candidates have provisional/accepted/retired/narrowed/unattested status; provisional is a hypothesis, not established identity. You may doubt a concept. Propose {\"op\":\"revise_concept\",\"concept\":\"@shown concept\",\"action\":\"retire|merge_into|remove_alias|retype|narrow\",\"basis\":[\"@shown grounded record\"],\"reason\":\"...\"}. merge_into requires target; remove_alias requires alias; retype requires new_type and NEW UNIQUE new_name. narrow requires into:[{type,name,aliases,basis:[shown Observe]}] and move:[{record:shown mapped record,term,to:new name or shown @existing}]. Put every moved record or its shown evidence in the outer basis. It proposes new provisional concepts and explicit mapping moves; nothing applies until independent confirm. The broad concept becomes narrowed, not retired; unmoved mappings remain historical on it. Inspect mapping_distribution: a catch-all may collect different mechanisms from different reports, but distribution is not proof of error. Definitions and reserved names never change. PENDING REVISION requires the fixed next nonproposer to answer {\"op\":\"revise_concept\",\"action\":\"confirm|reject\",\"proposal\":\"full proposal id\",\"basis\":[\"@shown grounded record\"],\"reason\":\"...\"}. Read the proposal and its quotes critically, never rubber-stamp. Hints are retrieval signals, not proof. Retired mappings remain historical; map future terms only to a live replacement.";
pub(super) fn pending<S: AuditStore>(s: &S) -> Vec<Value> {
    s.ontology_revision_state().and_then(|v| v["pending"].as_array().cloned()).unwrap_or_default()
}
pub(super) fn context<S: AuditStore>(s: &S, candidates: &mut BTreeMap<String, Vec<ConceptView>>, neighbors: &mut Vec<RecordView>) -> Option<Value> {
    let state = s.ontology_revision_state()?;
    let pending = state["pending"].as_array().expect("pending array").iter().take(16).cloned().collect::<Vec<_>>();
    for p in &pending {
        for key in ["concept", "target"] {
            if let Some(id) = p["change"][key].as_str().and_then(crate::hash::from_hex).map(ConceptId) {
                if let Some(c) = s.concept(&id) {
                    candidates.entry(format!("revision:{}", c.id.short())).or_default().push(c);
                }
            }
        }
        for m in p["change"]["move"].as_array().into_iter().flatten() {
            if let Some(c) = m["to"].as_str().and_then(crate::hash::from_hex).map(ConceptId).and_then(|id| s.concept(&id)) {
                candidates.entry(format!("review:{}", c.id.short())).or_default().push(c);
            }
        }
        let mut queue =
            p["basis"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(RecordId)).collect::<Vec<_>>();
        for v in p["change"]["into"].as_array().into_iter().flatten() {
            queue.extend(v["basis"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(RecordId)));
        }
        queue.extend(p["change"]["move"].as_array().into_iter().flatten().filter_map(|v| v["record"].as_str().and_then(crate::hash::from_hex).map(RecordId)));
        let mut visited = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if !visited.insert(id) {
                continue;
            }
            if let Some(r) = s.record(&id) {
                queue.extend(r.based_on.iter().copied());
                if !neighbors.iter().any(|n| n.id == id) {
                    neighbors.push(r);
                }
            }
        }
    }
    let all = s.concepts();
    let hints = all_hints(s).into_iter().filter(|h| h["kind"] != "unmapped_seed").take(32).collect::<Vec<_>>();
    let policy = &state["policy"];
    // Show referenced hint concepts, including retired historical matches, within a deterministic bound.
    for c in all.iter().filter(|c| hints.iter().any(|h| h["concept"] == c.id.short())).take(32) {
        candidates.entry(format!("hint:{}", c.id.short())).or_default().push(c.clone());
    }
    for (term, cs) in candidates.iter_mut() {
        for c in all.iter().filter(|c| c.status == "retired" && (norm(term) == c.name || c.aliases.contains(&norm(term)))).take(4) {
            if !cs.iter().any(|x| x.id == c.id) {
                cs.push(c.clone());
            }
        }
    }
    Some(json!({"pending":pending,"hints":hints,"policy":policy,"ontology_revision":s.ontology_version().0}))
}
pub(super) fn all_hints<S: AuditStore>(s: &S) -> Vec<Value> {
    let Some(state) = s.ontology_revision_state() else {
        return vec![];
    };
    let mut hints = Vec::new();
    let all = s.concepts();
    let ck = s.checkpoint("audit:circles");
    let current = ck.as_ref().and_then(|v| v["context"]["circle"].as_u64()).unwrap_or(0);
    let circle = if ck.as_ref().is_some_and(|v| v["context"]["circle_phase"] == "FINAL") { current } else { current.saturating_sub(1) };
    let policy = &state["policy"];
    let mapped_min = policy["catchall_mappings"].as_u64().unwrap_or(8) as usize;
    let reports_min = policy["catchall_reports"].as_u64().unwrap_or(2) as usize;
    let unmapped = policy["unmapped_circles"].as_u64().unwrap_or(3);
    for c in all.iter().filter(|c| c.selectable()) {
        let records = s.records_of(&c.id).iter().filter_map(|id| s.record(id)).collect::<Vec<_>>();
        let mappings = s.mapped_terms_of(&c.id);
        let ids = records.iter().map(|r| r.id).collect::<BTreeSet<_>>();
        let reports =
            super::super::pairs::cone(s, &records.iter().map(|r| r.id).collect::<Vec<_>>()).into_iter().filter_map(|r| r.doc_id).collect::<BTreeSet<_>>().len();
        let linked = s.links().iter().any(|l| matches!(l.rel.as_str(), "supersedes" | "contradicts") && ids.contains(&l.from) && ids.contains(&l.to));
        let opposing = records.iter().any(|r| matches!(r.status.as_deref(), Some("superseded" | "refuted")))
            && records.iter().any(|r| matches!(r.status.as_deref(), Some("confirmed" | "reported")));
        let diverse = mappings
            .as_ref()
            .is_some_and(|edges| edges.iter().map(|(_, term)| norm(term)).filter(|term| c.aliases.contains(term)).collect::<BTreeSet<_>>().len() > 1);
        if (linked || opposing) && diverse {
            hints.push(json!({"concept":c.id.short(),"kind":"possible_false_merge","proof":false}));
        }
        if mappings.as_ref().is_some_and(|edges| edges.len() >= mapped_min)
            && reports >= reports_min
            && c.aliases.iter().any(|a| a.split_whitespace().count() == 1)
            && all.iter().any(|n| n.id != c.id && n.selectable() && n.ty == c.ty && n.name.split_whitespace().count() > 1)
        {
            hints.push(json!({"concept":c.id.short(),"kind":"possible_catchall","mappings":mappings.as_ref().map(Vec::len),"mapped_records":records.len(),"count_unit":"distinct_record_term_concept_associations","reports":reports,"proof":false}));
        }
        let born = state["ontology"]["concepts"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|v| v["id"] == hex(&c.id.0))
            .and_then(|v| v["proposed_by"].as_str())
            .unwrap_or("");
        if records.is_empty() && born == "base" && circle >= unmapped {
            hints.push(json!({"concept":c.id.short(),"kind":"unmapped_seed","circles":circle,"proof":false}));
        }
    }
    hints
}
pub(super) fn translate<S: AuditStore>(s: &S, card: &Card, op: &Value) -> Result<Value, Value> {
    if card.ontology.is_none() {
        return Err(bad(Code::UnknownOp, "ontology revisions disabled", "op").to_json());
    }
    let object = op.as_object().ok_or_else(|| bad(Code::BadField, "expected object", "op").to_json())?;
    if object
        .keys()
        .any(|k| !["op", "concept", "action", "target", "alias", "new_type", "new_name", "proposal", "basis", "reason", "into", "move"].contains(&k.as_str()))
    {
        return Err(bad(Code::BadField, "unknown revision field (subject is server-controlled)", "op").to_json());
    }
    let action = op["action"].as_str().unwrap_or("");
    let mut out = op.clone();
    out.as_object_mut().expect("object").remove("op");
    out["kind"] = json!(if op["op"] == "keep" { "ontology_review_keep" } else { "revise_concept" });
    if let Some(spec) = super::ontology_review::task(card) {
        if op["concept"] != spec["concept_short"] || matches!(action, "confirm" | "reject") {
            return Err(bad(Code::BadField, "review must keep or propose a change of its own concept", "concept").to_json());
        }
        out["review_id"] = spec["id"].clone();
    }
    let seen: BTreeMap<String, RecordView> = card.records.iter().chain(&card.neighbors).map(|r| (r.id.short(), r.clone())).collect();
    let basis = op["basis"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 256)
        .ok_or_else(|| bad(Code::NoEvidence, "basis needs 1..256 shown grounded records", "basis").to_json())?;
    let mut full = Vec::new();
    for b in basis {
        let r = b
            .as_str()
            .and_then(|v| seen.get(v))
            .filter(|r| s.is_answer_support(&r.id) && s.is_grounded(&r.id))
            .ok_or_else(|| bad(Code::NoEvidence, "basis must be a shown active grounded record, never a hypothesis/question/done", "basis").to_json())?;
        full.push(hex(&r.id.0));
    }
    out["basis"] = json!(full);
    if action == "narrow" {
        let into = op["into"].as_array().ok_or_else(|| bad(Code::BadField, "into must be an array", "into").to_json())?;
        let mut normalized = vec![];
        for entry in into {
            let mut v = entry.clone();
            let basis =
                entry["basis"].as_array().filter(|v| !v.is_empty()).ok_or_else(|| bad(Code::NoEvidence, "into basis is required", "basis").to_json())?;
            let mut ids = vec![];
            for b in basis {
                let r = b
                    .as_str()
                    .and_then(|id| seen.get(id))
                    .filter(|r| r.kind == RecordKind::Observe && s.is_answer_support(&r.id))
                    .ok_or_else(|| bad(Code::NoEvidence, "into basis must be shown active observes", "basis").to_json())?;
                ids.push(hex(&r.id.0));
            }
            v["basis"] = json!(ids);
            normalized.push(v);
        }
        out["into"] = json!(normalized);
        let moves = op["move"].as_array().ok_or_else(|| bad(Code::BadField, "move must be an array", "move").to_json())?;
        let mut normalized = vec![];
        for m in moves {
            let mut v = m.clone();
            let r = m["record"]
                .as_str()
                .and_then(|id| seen.get(id))
                .filter(|r| s.is_grounded(&r.id))
                .ok_or_else(|| bad(Code::NoEvidence, "move must name a shown active grounded record", "record").to_json())?;
            v["record"] = json!(hex(&r.id.0));
            let to = m["to"].as_str().ok_or_else(|| bad(Code::BadField, "move target required", "to").to_json())?;
            if !into.iter().any(|v| v["name"].as_str().is_some_and(|n| norm(n) == norm(to))) {
                let c = card
                    .candidates
                    .values()
                    .flatten()
                    .find(|c| (c.id.short() == to || hex(&c.id.0) == to.trim_start_matches('@')) && c.selectable())
                    .ok_or_else(|| bad(Code::UnknownEntity, "existing narrow target must be shown and selectable", "to").to_json())?;
                v["to"] = json!(hex(&c.id.0));
            }
            normalized.push(v);
        }
        out["move"] = json!(normalized);
    }
    if matches!(action, "confirm" | "reject") {
        if !card.ontology.as_ref().expect("context")["pending"].as_array().into_iter().flatten().any(|p| p["proposal"] == op["proposal"]) {
            return Err(bad(Code::UnknownEntity, "proposal was not shown in this card", "proposal").to_json());
        }
    } else {
        for key in ["concept", "target"] {
            if key == "target" && action != "merge_into" {
                continue;
            }
            let id = op[key]
                .as_str()
                .and_then(|v| card.candidates.values().flatten().find(|c| c.id.short() == v))
                .ok_or_else(|| bad(Code::UnknownEntity, "revision concept/target must be shown", "concept").to_json())?;
            out[key] = json!(hex(&id.id.0));
        }
    }
    Ok(out)
}
impl Builder {
    pub(super) fn revision_card<S: AuditStore>(&mut self, s: &S, proposal: Option<&str>) -> Option<Card> {
        let p = if let Some(pid) = proposal {
            s.ontology_revision_state()?["events"].as_array()?.iter().find(|p| p["status"] == "pending" && p["proposal"] == pid)?.clone()
        } else {
            pending(s).into_iter().find(|p| !super::super::agent_failures::unresolved_review(s, &p["proposal"]))?
        };
        let pid = p["proposal"].as_str()?.to_string();
        let mut candidates = BTreeMap::new();
        let mut neighbors = Vec::new();
        let mut ontology = context(s, &mut candidates, &mut neighbors)?;
        // A selected review beyond the ordinary 16-item display bound still carries its own complete shown basis.
        for key in ["concept", "target"] {
            if let Some(c) = p["change"][key].as_str().and_then(crate::hash::from_hex).map(ConceptId).and_then(|id| s.concept(&id)) {
                candidates.entry(format!("review:{}", c.id.short())).or_default().push(c);
            }
        }
        for m in p["change"]["move"].as_array().into_iter().flatten() {
            if let Some(c) = m["to"].as_str().and_then(crate::hash::from_hex).map(ConceptId).and_then(|id| s.concept(&id)) {
                candidates.entry(format!("review:{}", c.id.short())).or_default().push(c);
            }
        }
        let mut queue =
            p["basis"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(RecordId)).collect::<Vec<_>>();
        for v in p["change"]["into"].as_array().into_iter().flatten() {
            queue.extend(v["basis"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(crate::hash::from_hex).map(RecordId)));
        }
        queue.extend(p["change"]["move"].as_array().into_iter().flatten().filter_map(|v| v["record"].as_str().and_then(crate::hash::from_hex).map(RecordId)));
        let mut visited = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if !visited.insert(id) {
                continue;
            }
            if let Some(r) = s.record(&id) {
                queue.extend(r.based_on.iter().copied());
                if !neighbors.iter().any(|n| n.id == id) {
                    neighbors.push(r);
                }
            }
        }
        ontology["pending"] = json!([p.clone()]);
        let card = Card {
            card_id: format!("R{}-{}-{}", self.cursor, self.cursor, pid),
            cursor_from: self.cursor,
            cursor_to: self.cursor,
            records: vec![],
            candidates,
            neighbors,
            concept_types: s.concept_types(),
            max_ops: 1,
            max_links: 0,
            pair: None,
            ontology: Some(ontology),
            review: Some(pid),
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
