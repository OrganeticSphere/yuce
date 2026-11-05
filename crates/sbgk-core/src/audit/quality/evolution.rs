//! Bounded cross-report claim pairs: by a shared stored concept, or by the claims' own words. Retrieval is not a relation verdict.
use super::super::pairs::{cone, PairCandidate};
use super::*;
pub fn document<S: AuditStore>(s: &S, id: RecordId) -> Option<String> {
    let ds = cone(s, &[id]).into_iter().filter_map(|r| r.doc_id).collect::<BTreeSet<_>>();
    if ds.len() == 1 {
        ds.into_iter().next()
    } else {
        None
    }
}
/// A report's date: `date` in its `+++` front matter (dated reports), else the date its pinned manifest entry declares (pages
/// without front matter, such as the MCP specification's); empty when neither gives one.
pub fn date<S: AuditStore>(s: &S, doc: &str) -> String {
    let text = s.doc_text(doc).unwrap_or_default();
    let front = text.strip_prefix("+++\n").or_else(|| text.strip_prefix("+++\r\n")).and_then(|rest| {
        rest.split("+++").next().unwrap_or("").lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == "date").then(|| v.trim().trim_matches('"').to_string())
        })
    });
    front.filter(|d| !d.is_empty()).or_else(|| s.document_date(doc)).unwrap_or_default()
}
/// Shared and total significant words of two claim texts: a word of three or more characters that is not in every report.
/// A retrieval rank, never a relation verdict (offline C3 on run C0a_r2: in concept order the first ten cards held no
/// evolution pair, while the real ones, such as a dependency later replaced, waited at cards 36 to 83 of 104).
fn overlap(a: &str, b: &str, n: usize, df: &BTreeMap<String, usize>) -> (u64, u64) {
    let words = |t: &str| tokens(t).into_iter().filter(|w| w.chars().count() >= 3 && df.get(w).copied().unwrap_or(0) < n).collect::<BTreeSet<_>>();
    let (a, b) = (words(a), words(b));
    (a.intersection(&b).count() as u64, a.union(&b).count() as u64)
}
/// Higher overlap first; ties keep their order (the sort is stable).
fn by_overlap<T>(xs: &mut [((u64, u64), T)]) {
    xs.sort_by(|((s1, u1), _), ((s2, u2), _)| (s2 * (*u1).max(1)).cmp(&(s1 * (*u2).max(1))));
}
/// Words a lexical pair ignores: grammar, not subject matter.
const STOP: [&str; 63] = [
    "the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "is", "are", "be", "by", "with", "as", "that", "this", "it", "its", "from", "at", "which",
    "when", "must", "should", "may", "can", "not", "no", "any", "all", "each", "if", "than", "then", "into", "only", "also", "more", "such", "these", "those",
    "other", "their", "there", "has", "have", "was", "were", "will", "would", "do", "does", "so", "but", "they", "them", "we", "you", "our", "your", "been",
];
/// A pair below this cosine shares no subject worth a card.
const MIN_SIMILARITY: f64 = 0.05;
/// A report's page without its version: the label with every `YYYY-MM-DD` path segment taken out, so one page of two versions
/// compares equal (docs/specification/2025-06-18/basic/transports.mdx and its 2026-07-28 twin).
fn logical_page(label: &str) -> String {
    let date = |seg: &str| seg.len() == 10 && seg.bytes().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == b'-' } else { c.is_ascii_digit() });
    label.split('/').filter(|seg| !date(seg)).collect::<Vec<_>>().join("/")
}
/// Unit-length TF-IDF vectors of claims over their text and the quotes they rest on.
fn tfidf(texts: &[String]) -> Vec<BTreeMap<String, f64>> {
    let toks: Vec<Vec<String>> =
        texts.iter().map(|t| tokens(t).into_iter().filter(|w| w.chars().count() >= 2 && !STOP.contains(&w.as_str())).collect()).collect();
    let mut df: BTreeMap<String, usize> = BTreeMap::new();
    for ts in &toks {
        for w in ts.iter().collect::<BTreeSet<_>>() {
            *df.entry(w.clone()).or_default() += 1;
        }
    }
    let n = toks.len() as f64;
    toks.iter()
        .map(|ts| {
            let mut tf: BTreeMap<String, f64> = BTreeMap::new();
            for w in ts {
                *tf.entry(w.clone()).or_default() += 1.0;
            }
            let mut v: BTreeMap<String, f64> = tf
                .into_iter()
                .map(|(w, c)| {
                    let x = (1.0 + c.ln()) * (n / df[&w] as f64).ln();
                    (w, x)
                })
                .collect();
            let norm = v.values().map(|x| x * x).sum::<f64>().sqrt();
            if norm > 0.0 {
                v.values_mut().for_each(|x| *x /= norm);
            }
            v
        })
        .collect()
}
fn cosine(a: &BTreeMap<String, f64>, b: &BTreeMap<String, f64>) -> f64 {
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().filter_map(|(w, x)| large.get(w).map(|y| x * y)).sum()
}
/// Whether `old_doc` comes before `new_doc`: by report date, else by the explicit order. Earlier is the reports' order alone: an
/// undated report placed by the explicit order may sort after the later one by id (Codex review R03: 'z' before 'a' lost its pair),
/// and without a date or a place there is no order.
fn ordered<S: AuditStore>(s: &S, old_doc: &str, new_doc: &str, explicit: &[Value]) -> bool {
    let (od, nd) = (date(s, old_doc), date(s, new_doc));
    if !od.is_empty() && !nd.is_empty() {
        od < nd
    } else {
        explicit.iter().position(|d| d == old_doc).zip(explicit.iter().position(|d| d == new_doc)).is_some_and(|(a, b)| a < b)
    }
}
/// A claim a pair may hold: a reader's own conclusion of one report, not a summary's or a link check's.
fn pairable<S: AuditStore>(s: &S, r: &RecordView) -> bool {
    r.kind == RecordKind::Claim
        && !super::super::directives::is_summary_directive(&r.directive)
        && !super::super::directives::is_link_directive(&r.directive)
        && s.is_answer_support(&r.id)
}
fn row<S: AuditStore>(s: &S, old_doc: &str, old: &RecordView, new_doc: &str, new: &RecordView, how: Value) -> Value {
    let h = crate::hash::sha256(crate::jcs::to_jcs(&json!([old.id.short(), new.id.short()])).as_bytes());
    let mut v = json!({"pair":format!("E{}",&crate::hash::to_hex(&h)[..16]),"old":hex_id(old.id),"new":hex_id(new.id),
        "old_doc":old_doc,"new_doc":new_doc,"old_report":s.document_label(old_doc),"new_report":s.document_label(new_doc),"old_date":date(s,old_doc),"new_date":date(s,new_doc),
        "ordering":if date(s,old_doc).is_empty()||date(s,new_doc).is_empty(){"explicit_manifest_order"}else{"report_date"}});
    for (k, x) in how.as_object().into_iter().flatten() {
        v[k] = x.clone();
    }
    v
}
/// What a lexical match reads of a claim: its text and the quotes it rests on.
fn claim_text<S: AuditStore>(s: &S, r: &RecordView) -> String {
    let quotes = cone(s, &[r.id]).into_iter().filter_map(|x| x.quote).collect::<Vec<_>>().join(" ");
    format!("{} {quotes}", r.text.as_deref().unwrap_or(""))
}
/// For each of `of`, at most `k` claims of reports of another date that share its words, best first (the hint profile of 31.10:
/// offline, the best three of these held the other side of 8 to 9 of the 11 to 12 stale facts both sides of which were read). Hints,
/// not evidence: the reader decides on the quotes whether one is an earlier or a later state of the same thing. A claim without a
/// dated report of its own gets none.
pub fn related<S: AuditStore>(s: &S, of: &[RecordId], k: usize) -> Vec<(RecordId, Vec<RecordId>)> {
    let claims = s.records_since(0).into_iter().filter(|r| pairable(s, r)).filter_map(|r| document(s, r.id).map(|d| (d, r))).collect::<Vec<_>>();
    let texts = claims.iter().map(|(_, r)| claim_text(s, r)).collect::<Vec<_>>();
    let vecs = tfidf(&texts);
    let dates = claims.iter().map(|(d, _)| date(s, d)).collect::<Vec<_>>();
    of.iter()
        .filter_map(|id| {
            let i = claims.iter().position(|(_, r)| r.id == *id)?;
            let mut best = claims
                .iter()
                .enumerate()
                .filter(|(j, (doc, _))| *j != i && *doc != claims[i].0 && !dates[i].is_empty() && !dates[*j].is_empty() && dates[*j] != dates[i])
                .map(|(j, (_, r))| (cosine(&vecs[i], &vecs[j]), r.seq, r.id))
                .filter(|x| x.0 > MIN_SIMILARITY)
                .collect::<Vec<_>>();
            best.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
            Some((*id, best.into_iter().take(k).map(|x| x.2).collect()))
        })
        .collect()
}
/// Pairs by the words of the claims themselves, not by a shared concept (step 3a of 31.10: concept-shared pairs joined the two
/// sides of 2 to 4 of the 13 stale facts of the MCP oracle; this pairing joined 7 to 11 offline). Per new claim, its best earlier
/// claim of the same page in another version and its best earlier claim anywhere else, by TF-IDF cosine over its text and quotes.
fn lexical_rows<S: AuditStore>(s: &S, cfg: &Value, explicit: &[Value]) -> Vec<Value> {
    let per_page = cfg["evolution_pairs_per_page"].as_u64().unwrap_or(1) as usize;
    let per_corpus = cfg["evolution_pairs_per_corpus"].as_u64().unwrap_or(1) as usize;
    let claims = s.records_since(0).into_iter().filter(|r| pairable(s, r)).filter_map(|r| document(s, r.id).map(|d| (d, r))).collect::<Vec<_>>();
    let texts = claims.iter().map(|(_, r)| claim_text(s, r)).collect::<Vec<_>>();
    let vecs = tfidf(&texts);
    let pages = claims.iter().map(|(d, _)| logical_page(&s.document_label(d))).collect::<Vec<_>>();
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, (new_doc, new)) in claims.iter().enumerate() {
        let mut olds = claims
            .iter()
            .enumerate()
            .filter(|(j, (old_doc, _))| *j != i && old_doc != new_doc && ordered(s, old_doc, new_doc, explicit))
            .map(|(j, (_, old))| (cosine(&vecs[i], &vecs[j]), old.seq, j))
            .filter(|(x, _, _)| *x > MIN_SIMILARITY)
            .collect::<Vec<_>>();
        olds.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        let same = olds.iter().filter(|(_, _, j)| pages[*j] == pages[i]).take(per_page).map(|x| (x.0, x.2, "page")).collect::<Vec<_>>();
        let rest = olds.iter().filter(|(_, _, j)| !same.iter().any(|y| y.1 == *j)).take(per_corpus).map(|x| (x.0, x.2, "corpus")).collect::<Vec<_>>();
        for (sim, j, channel) in same.into_iter().chain(rest) {
            let (old_doc, old) = &claims[j];
            if seen.insert((old.id, new.id)) {
                rows.push(row(s, old_doc, old, new_doc, new, json!({"channel":channel,"similarity_per_mille":(sim * 1000.0).round() as u64})));
            }
        }
    }
    rows.extend(function_rows(s, cfg, explicit, &claims, &vecs, &mut seen));
    rows
}
/// Words that state a change, matched whole ("add" is not "address").
const CHANGE_WORDS: [&str; 12] = ["add", "added", "adds", "adding", "moved", "drop", "dropped", "drops", "previously", "instead", "longer", "now"];
/// Word beginnings that state a change ("removed", "replaces", "deprecation", "introduced", "renamed", "superseded", "changed").
const CHANGE_STEMS: [&str; 7] = ["remov", "replac", "deprecat", "introduc", "renam", "supersed", "chang"];
/// Whether a claim states a change: a record of change, in whatever document (Fable 5.1's consultation of 01.11: the general form of
/// a declared change summary; offline on MCPstrong_r1 it paired 9 of 21 read gold changes within a function, declared summaries 10).
/// "longer" and "now" count only in "no longer" and "now requires"-like phrases, "instead" only in "instead of".
fn states_change(text: &str) -> bool {
    let words = tokens(text);
    words.iter().enumerate().any(|(i, w)| {
        let next = words.get(i + 1).map(String::as_str).unwrap_or("");
        let prev = if i > 0 { words[i - 1].as_str() } else { "" };
        match w.as_str() {
            "longer" => prev == "no",
            "now" => next.starts_with("requir") || next == "must",
            "instead" => next == "of",
            w => CHANGE_WORDS.contains(&w) || CHANGE_STEMS.iter().any(|st| w.starts_with(st)),
        }
    })
}
/// The address layer's channel: per new claim and per function of the concepts mapped in its cone,
/// the best `evolution_pairs_per_function` earlier claims of the same function that are records of change: claims that state a
/// change, or claims of the documents the corpus declares as change summaries. A later detail meets the item that introduced or
/// changed its whole (offline on MCPstrong_r1: 9 to 10 of 21 read gold changes paired, against 1 by words alone; with the function
/// labels shuffled 7, Fable's control). The function selects candidates only; it proves no relation.
fn function_rows<S: AuditStore>(
    s: &S,
    cfg: &Value,
    explicit: &[Value],
    claims: &[(String, RecordView)],
    vecs: &[BTreeMap<String, f64>],
    seen: &mut BTreeSet<(RecordId, RecordId)>,
) -> Vec<Value> {
    if cfg["concept_functions"] != true {
        return vec![];
    }
    let summaries = cfg["change_summary_documents"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<BTreeSet<_>>();
    let k = cfg["evolution_pairs_per_function"].as_u64().unwrap_or(3) as usize;
    let placed = s.concepts().into_iter().filter_map(|c| c.function.map(|f| (c.id, f))).collect::<BTreeMap<_, _>>();
    let functions = claims
        .iter()
        .map(|(_, r)| cone(s, &[r.id]).iter().flat_map(|x| s.concepts_of(&x.id)).filter_map(|c| placed.get(&c).cloned()).collect::<BTreeSet<_>>())
        .collect::<Vec<_>>();
    // a record of change: a claim that states one, or a claim of a declared summary, named by its document id or its label (the path
    // the manifest gives it)
    let change = claims
        .iter()
        .map(|(d, r)| states_change(r.text.as_deref().unwrap_or("")) || summaries.contains(d.as_str()) || summaries.contains(s.document_label(d).as_str()))
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for (i, (new_doc, new)) in claims.iter().enumerate() {
        for f in &functions[i] {
            let mut olds = claims
                .iter()
                .enumerate()
                .filter(|(j, (old_doc, _))| change[*j] && *j != i && old_doc != new_doc && functions[*j].contains(f) && ordered(s, old_doc, new_doc, explicit))
                .map(|(j, (_, old))| (cosine(&vecs[i], &vecs[j]), old.seq, j))
                .collect::<Vec<_>>();
            olds.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
            for (sim, _, j) in olds.into_iter().take(k) {
                let (old_doc, old) = &claims[j];
                if seen.insert((old.id, new.id)) {
                    rows.push(row(s, old_doc, old, new_doc, new, json!({"channel":"function","similarity_per_mille":(sim * 1000.0).round() as u64})));
                }
            }
        }
    }
    rows
}
/// Bounded cross-report pairs of claims that share a stored concept (the default pairing).
fn concept_rows<S: AuditStore>(s: &S, cfg: &Value, explicit: &[Value]) -> Vec<Value> {
    let limit = cfg["evolution_pairs_per_concept"].as_u64().unwrap_or(16) as usize;
    let per_claim = cfg["evolution_pairs_per_claim"].as_u64().unwrap_or(3) as usize;
    let (n, df) = super::document_frequency(s);
    let mut pairs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut docs = s.docs();
    docs.sort_by_key(|d| (date(s, d), d.clone()));
    for c in s.concepts().into_iter().filter(|c| c.selectable()) {
        let mapped = s.records_of(&c.id).into_iter().collect::<BTreeSet<_>>();
        let mut claims = s
            .records_since(0)
            .into_iter()
            .filter(|r| pairable(s, r) && cone(s, &[r.id]).iter().any(|r| mapped.contains(&r.id)))
            .filter_map(|r| document(s, r.id).map(|d| (d, r)))
            .collect::<Vec<_>>();
        claims.sort_by_key(|(d, r)| (docs.iter().position(|x| x == d), r.seq));
        // per new claim its best earlier claims, then the concept's best pairs; a pair seen under an earlier concept is not offered again
        let mut ranked = Vec::new();
        for (new_doc, new) in &claims {
            let mut olds = Vec::new();
            for (old_doc, old) in &claims {
                if old_doc == new_doc || seen.contains(&(old.id, new.id)) {
                    continue;
                }
                if ordered(s, old_doc, new_doc, explicit) {
                    olds.push((overlap(old.text.as_deref().unwrap_or(""), new.text.as_deref().unwrap_or(""), n, &df), (old_doc, old, new_doc, new)));
                }
            }
            by_overlap(&mut olds);
            ranked.extend(olds.into_iter().take(per_claim));
        }
        by_overlap(&mut ranked);
        for ((shared, words), (old_doc, old, new_doc, new)) in ranked.into_iter().take(limit) {
            if !seen.insert((old.id, new.id)) {
                continue;
            }
            pairs.push((
                (shared, words),
                row(s, old_doc, old, new_doc, new, json!({"shared_concept":{"id":c.id.short(),"name":c.name,"status":c.status},"word_overlap":[shared,words]})),
            ));
        }
    }
    by_overlap(&mut pairs);
    pairs.into_iter().map(|(_, p)| p).collect()
}
pub fn detect<S: AuditStore>(s: &S) -> Vec<PairCandidate> {
    let cfg = config(s);
    let k = cfg["evolution_pairs_per_card"].as_u64().unwrap_or(4) as usize;
    let explicit = cfg["evolution_document_order"].as_array().cloned().unwrap_or_default();
    let rows = if cfg["evolution_pairing"] == "lexical" { lexical_rows(s, &cfg, &explicit) } else { concept_rows(s, &cfg, &explicit) };
    pack(s, rows, k)
}
/// The pairs of a frozen plan that no circle reader may take: every reader wrote one of its ends. Never offered as a card.
pub const UNASSIGNABLE: &str = "evolution_unassignable";
/// Cards of up to `k` pairs, each card's pairs sharing a circle reader who wrote none of their ends (K06, and the fix of Codex's
/// EVO-01: chunks in rank order joined the authors of several pairs, a card whose ends had every reader as an author found no
/// recipient, and that stopped the whole offer). A pair only one reader may take goes to that reader first, the others to the
/// reader with the fewest; cards keep rank order. A pair no reader may take stays in the plan, named and never offered.
fn pack<S: AuditStore>(s: &S, rows: Vec<Value>, k: usize) -> Vec<PairCandidate> {
    if rows.is_empty() {
        return vec![];
    }
    let card = |ps: &[Value], kind: &str, reason: Option<&str>| {
        let mut metadata = json!({"kind":kind,"pairs":ps});
        if let Some(r) = reason {
            metadata["reason"] = json!(r);
        }
        PairCandidate {
            old: id(&ps[0]["old"]).unwrap(),
            new: id(&ps[0]["new"]).unwrap(),
            old_doc: ps[0]["old_doc"].as_str().unwrap().into(),
            new_doc: ps[0]["new_doc"].as_str().unwrap().into(),
            score: ps.len(),
            metadata,
        }
    };
    let readers = s
        .checkpoint("audit:mcp:coverage")
        .and_then(|c| c["context"]["circle_readers"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    if readers.is_empty() {
        return rows.chunks(k.max(1)).map(|ps| card(ps, "evolution", None)).collect();
    }
    let author = |v: &Value| id(v).and_then(|i| s.record(&i)).map(|r| r.author);
    let takers = rows
        .iter()
        .map(|r| {
            let ends = [author(&r["old"]), author(&r["new"])];
            (0..readers.len()).filter(|i| ends.iter().all(|a| a.as_deref() != Some(readers[*i].as_str()))).collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut groups: Vec<Vec<usize>> = vec![vec![]; readers.len()];
    let mut nobody = vec![];
    // first the pairs one reader alone may take, then the others to the reader with the fewest; a pair nobody may take is set aside
    for forced in [true, false] {
        for (i, t) in takers.iter().enumerate() {
            if (t.len() <= 1) != forced {
                continue;
            }
            match t.iter().min_by_key(|r| (groups[**r].len(), **r)) {
                Some(&r) => groups[r].push(i),
                None => nobody.push(i),
            }
        }
    }
    let mut cards = groups.iter().flat_map(|g| g.chunks(k.max(1)).map(<[usize]>::to_vec)).collect::<Vec<_>>();
    cards.sort_by_key(|c| c[0]);
    let mut out = cards.iter().map(|c| card(&c.iter().map(|i| rows[*i].clone()).collect::<Vec<_>>(), "evolution", None)).collect::<Vec<_>>();
    if !nobody.is_empty() {
        out.push(card(&nobody.iter().map(|i| rows[*i].clone()).collect::<Vec<_>>(), UNASSIGNABLE, Some("NO_NONAUTHOR")));
    }
    out
}
fn hex_id(id: RecordId) -> String {
    crate::hash::to_hex(&id.0)
}
pub fn id(v: &Value) -> Option<RecordId> {
    Some(RecordId(crate::hash::from_hex(v.as_str()?)?))
}
pub fn is_card(card: &super::super::builder::Card) -> bool {
    card.pair.as_ref().is_some_and(|p| p["metadata"]["kind"] == "evolution")
}
pub fn rows(card: &super::super::builder::Card) -> Vec<Value> {
    card.pair.as_ref().and_then(|p| p["metadata"]["pairs"].as_array()).cloned().unwrap_or_default()
}
pub fn ends(p: &PairCandidate) -> Vec<RecordId> {
    if p.metadata["kind"] != "evolution" {
        return vec![p.old, p.new];
    }
    p.metadata["pairs"].as_array().into_iter().flatten().flat_map(|r| [id(&r["old"]), id(&r["new"])]).flatten().collect::<BTreeSet<_>>().into_iter().collect()
}
pub fn none_key(card: &str, pair: &str) -> String {
    format!("builder:evolution:none:{card}:{pair}")
}
pub fn decided<S: AuditStore>(s: &S, card: &super::super::builder::Card, row: &Value) -> bool {
    if s.checkpoint(&none_key(&card.card_id, row["pair"].as_str().unwrap_or(""))).is_some() {
        return true;
    }
    let a = id(&row["old"]);
    let b = id(&row["new"]);
    (0..card.max_ops).any(|slot| {
        (0..super::super::builder::MAX_ATTEMPTS)
            .filter_map(|n| s.receipt_outcome(&format!("{}:{slot}:{n}", card.card_id), "builder"))
            .filter(|r| r["accepted_operations"] == 1 && r["error"].is_null())
            .filter_map(|r| r["results"][0]["id"].as_str().and_then(crate::hash::from_hex).map(LinkId).and_then(|l| s.link(&l)))
            .any(|l| (Some(l.from) == a && Some(l.to) == b) || (Some(l.from) == b && Some(l.to) == a))
    })
}

pub fn issued<S: AuditStore>(s: &mut S, card: &super::super::builder::Card) -> Result<(), Value> {
    if !is_card(card) {
        return Ok(());
    }
    let key = format!("builder:evolution:issued:{}", card.card_id);
    if s.checkpoint(&key).is_some() {
        return Ok(());
    }
    let ck = json!({"key":key,"from":0,"to":0,"context":{"card_id":card.card_id,"pairs":rows(card)}});
    match s.submit_operations_id(&format!("quality-issue:{}", card.card_id), "kernel", &[], Some(ck)) {
        Ok(v) if v["checkpointed"] == true && v["error"].is_null() => Ok(()),
        Ok(v) => Err(v),
        Err(e) => Err(e.to_json()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_ranks_shared_significant_words_first() {
        // "the" and "report" are in both reports, so they are not significant
        let df: BTreeMap<String, usize> = [("the", 2), ("report", 2), ("frontend", 1)].into_iter().map(|(w, f)| (w.to_string(), f)).collect();
        let near = overlap("The frontend dependency remains dev-only.", "The frontend dependency was superseded.", 2, &df);
        let far = overlap("The frontend dependency remains dev-only.", "The report adds no release surface.", 2, &df);
        assert_eq!((near, far), ((2, 7), (0, 8)));
        let mut xs = vec![(far, "far"), (near, "near"), ((0, 0), "empty")];
        by_overlap(&mut xs);
        assert_eq!(xs.iter().map(|x| x.1).collect::<Vec<_>>(), ["near", "far", "empty"]);
    }
}
