//! Opt-in graph retrieval policy. The coverage checkpoint pins it across restart.
use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub mod evolution;
pub mod stale;
pub fn config<S: AuditStore>(s: &S) -> Value {
    s.checkpoint("audit:mcp:coverage").map(|c| c["context"]["graph_quality"].clone()).unwrap_or(Value::Null)
}
pub fn enabled<S: AuditStore>(s: &S, k: &str) -> bool {
    config(s)[k] == true || (k == "temporal_summary" && s.has_checkpoint(super::versions::KEY))
}
/// The functions concepts are placed under (the address layer), the most used first, each with its
/// number of live concepts and the names of up to `examples` of them, the most mapped first: what a builder card shows so that a new
/// concept reuses a function (Fable 5.1, 01.11: sorted by use, with counts).
pub fn known_functions<S: AuditStore>(s: &S, examples: usize) -> Vec<(String, usize, Vec<String>)> {
    let mut by: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    for c in s.concepts().into_iter().filter(ConceptView::selectable) {
        if let Some(f) = c.function {
            by.entry(f).or_default().push((s.records_of(&c.id).len(), c.name));
        }
    }
    let mut out = by
        .into_iter()
        .map(|(f, mut cs)| {
            cs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            let n = cs.len();
            (f, n, cs.into_iter().take(examples).map(|(_, name)| name).collect::<Vec<_>>())
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}
pub fn tokens(t: &str) -> Vec<String> {
    t.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).map(str::to_lowercase).collect()
}
pub fn clean_term(t: &str, max_words: usize) -> bool {
    let language: Value = serde_json::from_str(include_str!("quality/english.json")).expect("language data");
    let ts = tokens(t);
    !ts.is_empty()
        && ts.len() <= max_words
        && !language["literals"].as_array().unwrap().iter().any(|v| tokens(v.as_str().unwrap()) == ts)
        && !language["clause_connectors"].as_array().unwrap().iter().any(|v| {
            let phrase = tokens(v.as_str().unwrap());
            ts.windows(phrase.len()).any(|w| w == phrase)
        })
}
pub fn terms<S: AuditStore>(s: &S, r: &RecordView) -> Vec<String> {
    let cfg = config(s);
    if cfg["term_hygiene"] != true {
        return r.terms.clone();
    }
    if r.kind == RecordKind::Question {
        return vec![];
    }
    r.terms.iter().filter(|t| clean_term(t, cfg["term_max_words"].as_u64().unwrap_or(4) as usize)).cloned().collect()
}
/// Unsmoothed IDF is monotone in document frequency. df < N/2 is the pinned significance boundary
/// (IDF > ln(2), without floating point). Count words once per full frozen report, not per card.
pub fn document_frequency<S: AuditStore>(s: &S) -> (usize, BTreeMap<String, usize>) {
    let docs = s.docs();
    let mut df = BTreeMap::new();
    for d in &docs {
        for w in tokens(&s.doc_text(d).unwrap_or_default()).into_iter().collect::<BTreeSet<_>>() {
            *df.entry(w).or_default() += 1;
        }
    }
    (docs.len(), df)
}
pub fn strict_match(term: &str, c: &ConceptView, n: usize, df: &BTreeMap<String, usize>) -> bool {
    let want = tokens(term);
    if want.is_empty() {
        return false;
    }
    std::iter::once(&c.name).chain(&c.aliases).any(|name| {
        let phrase = tokens(name);
        (!phrase.is_empty() && want.windows(phrase.len().min(want.len())).any(|w| w == phrase))
            || phrase.iter().any(|w| want.contains(w) && df.get(w).is_some_and(|f| 2 * f < n))
    })
}
pub fn strict_candidates<S: AuditStore>(s: &S, term: &str, cap: usize) -> Vec<ConceptView> {
    let (n, df) = document_frequency(s);
    let mut cs = s.concepts().into_iter().filter(|c| c.selectable() && strict_match(term, c, n, &df)).collect::<Vec<_>>();
    cs.sort_by_key(|c| (!std::iter::once(&c.name).chain(&c.aliases).any(|x| tokens(x) == tokens(term)), c.id));
    cs.truncate(cap);
    cs
}
pub fn show_concepts<S: AuditStore>(s: &S, circles: bool) -> bool {
    match config(s)["known_concepts"].as_str() {
        Some("off") => false,
        Some("all") => true,
        _ => circles,
    }
}
/// Keep the first member anchored and permute the others. Rotating the whole array would leave
/// every neighbor unchanged. Persisted circle number defines the same order after recovery.
pub fn ring<S: AuditStore>(s: &S, readers: &[String], circle: u64) -> Vec<String> {
    let mut order = readers.to_vec();
    if enabled(s, "ring_rotate") && order.len() > 2 {
        let n = order.len() - 1;
        order[1..].rotate_left(circle.saturating_sub(1) as usize % n);
    }
    order
}
pub fn pair_candidates<S: AuditStore>(s: &S) -> Vec<super::pairs::PairCandidate> {
    if enabled(s, "evolution_cards") {
        evolution::detect(s)
    } else {
        super::pairs::detect(s)
    }
}
pub fn annotate<S: AuditStore>(s: &S, id: RecordId) -> Value {
    stale::annotation(s, id)
}
pub fn language_data() -> Value {
    serde_json::from_str(include_str!("quality/english.json")).expect("language data")
}
