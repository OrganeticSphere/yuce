//! A4 retrieval only: metadata blocks and an inverted technical-token index bring assertions together. A candidate is never
//! an accepted relation. The frozen first-wave plan is bounded and survives restart through ordinary coordinator checkpoints.
use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PAIR_CARDS: usize = 25;

#[derive(Debug, Clone)]
pub struct PairCandidate {
    pub old: RecordId,
    pub new: RecordId,
    pub old_doc: String,
    pub new_doc: String,
    pub score: usize,
    pub metadata: Value,
}

impl PairCandidate {
    pub fn id(&self) -> String {
        // a plan entry of several pairs is named by all of them (an evolution card, or the pairs no reader may take)
        let payload = if self.metadata["kind"] == "evolution" || self.metadata["kind"] == crate::audit::quality::evolution::UNASSIGNABLE {
            json!(["r2r-evolution/1", self.metadata])
        } else {
            json!(["r2r-pair/1", self.old.short(), self.new.short()])
        };
        let h = crate::hash::sha256(crate::jcs::to_jcs(&payload).as_bytes());
        format!("P0-0-{}", &crate::hash::to_hex(&h)[..16])
    }
    pub fn to_json(&self) -> Value {
        json!({"old":crate::hash::to_hex(&self.old.0),"new":crate::hash::to_hex(&self.new.0),"old_doc":self.old_doc,
            "new_doc":self.new_doc,"score":self.score,"metadata":self.metadata})
    }
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            old: RecordId(crate::hash::from_hex(v["old"].as_str()?)?),
            new: RecordId(crate::hash::from_hex(v["new"].as_str()?)?),
            old_doc: v["old_doc"].as_str()?.into(),
            new_doc: v["new_doc"].as_str()?.into(),
            score: v["score"].as_u64()? as usize,
            metadata: v["metadata"].clone(),
        })
    }
}

#[derive(Clone, Default)]
struct Meta {
    report: String,
    date: String,
    title: String,
    sha: String,
    refs: BTreeSet<String>,
}
fn quoted(s: &str) -> Vec<String> {
    s.split('"').enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, s)| s.to_string()).collect()
}
fn metadata(text: &str) -> Meta {
    let Some(rest) = text.strip_prefix("+++\n").or_else(|| text.strip_prefix("+++\r\n")) else { return Meta::default() };
    let block = rest.split("+++").next().unwrap_or("");
    let mut m = Meta::default();
    let mut refs = false;
    for line in block.lines() {
        let l = line.trim();
        if let Some((k, v)) = l.split_once('=') {
            refs = matches!(k.trim(), "predecessor_reports" | "referenced_reports" | "supersedes");
            let values = quoted(v);
            let first = values.first().cloned().unwrap_or_default();
            match k.trim() {
                "report_id" => m.report = first,
                "date" => m.date = first,
                "title" => m.title = first,
                "base_sha" => m.sha = first,
                _ => (),
            }
            if refs {
                m.refs.extend(values);
            }
        } else if refs {
            m.refs.extend(quoted(l));
        }
        if l.ends_with(']') {
            refs = false;
        }
    }
    m
}

pub fn change_marker(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    ["replaced", "replaces", "supersed", "stale", "obsolete", "no longer", "invalidat", "former", "reverted", "unsupported", "only where consistent"]
        .iter()
        .any(|m| s.contains(m))
}

fn technical(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for t in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
        let t = t.trim_matches('-');
        let camel = t.bytes().zip(t.bytes().skip(1)).any(|(a, b)| a.is_ascii_lowercase() && b.is_ascii_uppercase());
        let snake = t.contains('_') && t.len() > 4;
        let sha = t.len() >= 7 && t.len() <= 40 && t.bytes().all(|b| b.is_ascii_hexdigit()) && t.bytes().any(|b| b.is_ascii_digit());
        if camel || snake || sha {
            out.insert(t.to_ascii_lowercase());
        }
    }
    for row in ['a', 'b', 'c', 'd'] {
        let t = format!("row {row}");
        if s.to_ascii_lowercase().contains(&t) {
            out.insert(t);
        }
    }
    out
}

// Content words supplement code identifiers; this is bounded retrieval, never semantic acceptance.
fn lexical(s: &str) -> BTreeSet<String> {
    const STOP: &[&str] = &[
        "about", "after", "also", "before", "been", "both", "does", "from", "have", "into", "only", "other", "same", "that", "their", "then", "there", "these",
        "this", "those", "through", "under", "were", "when", "where", "which", "while", "with", "without",
    ];
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4 && t.bytes().any(|b| b.is_ascii_alphabetic()))
        .map(str::to_ascii_lowercase)
        // A lifecycle marker chooses which new rows to inspect; it does not identify their shared subject.
        .filter(|t| !STOP.contains(&t.as_str()) && !change_marker(t))
        .collect()
}

/// Transitive source cone, with duplicates removed. This is record provenance, not proof that the claim follows from it.
pub fn cone<S: AuditStore>(s: &S, ids: &[RecordId]) -> Vec<RecordView> {
    let mut todo = ids.to_vec();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(r) = s.record(&id) {
            todo.extend(&r.based_on);
            out.push(r);
        }
    }
    out.sort_by_key(|r| r.seq);
    out
}
fn source_doc<S: AuditStore>(s: &S, r: &RecordView) -> Option<String> {
    let docs: BTreeSet<String> = cone(s, &[r.id]).into_iter().filter_map(|r| r.doc_id).collect();
    (docs.len() == 1).then(|| docs.into_iter().next()).flatten()
}
fn assertion_text<S: AuditStore>(s: &S, r: &RecordView) -> String {
    std::iter::once(r.text.clone().unwrap_or_default())
        .chain(r.terms.iter().cloned())
        .chain(cone(s, &r.based_on).into_iter().filter_map(|r| r.quote))
        .collect::<Vec<_>>()
        .join("\n")
}

// Match plain subjects to the parts of an explicit code name. This is lexical candidate retrieval, not an alias assertion.
fn compound_words(s: &str) -> Vec<BTreeSet<String>> {
    let mut out = Vec::new();
    for raw in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        let b = raw.as_bytes();
        let camel = b.windows(2).any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());
        if !raw.contains('_') && !camel {
            continue;
        }
        let mut expanded = String::new();
        for (i, &c) in b.iter().enumerate() {
            if i > 0
                && c.is_ascii_uppercase()
                && (b[i - 1].is_ascii_lowercase()
                    || b[i - 1].is_ascii_digit()
                    || (b[i - 1].is_ascii_uppercase() && b.get(i + 1).is_some_and(u8::is_ascii_lowercase)))
            {
                expanded.push(' ');
            }
            expanded.push(if c == b'_' { ' ' } else { c as char });
        }
        let parts = lexical(&expanded);
        if parts.len() >= 2 {
            out.push(parts);
        }
    }
    out
}

// Free-form labels alone do not establish shared content. Anchor plain words in assertion text or actual source quotes.
fn content_words<S: AuditStore>(s: &S, r: &RecordView) -> BTreeSet<String> {
    lexical(&std::iter::once(r.text.clone().unwrap_or_default()).chain(cone(s, &r.based_on).into_iter().filter_map(|r| r.quote)).collect::<Vec<_>>().join("\n"))
}

/// Sort/merge over metadata blocks and sorted postings. At most three claim pairs per metadata edge; one representative of
/// every edge is selected before extra pairs, so a long report cannot spend all 25 cards. Undated reports are not ordered.
pub fn detect<S: AuditStore>(s: &S) -> Vec<PairCandidate> {
    let docs: BTreeMap<String, Meta> = s
        .docs()
        .into_iter()
        .map(|d| {
            let m = metadata(&s.doc_text(&d).unwrap_or_default());
            (d, m)
        })
        .collect();
    let flags = s.support_map();
    let mut claims: BTreeMap<String, Vec<(RecordView, BTreeSet<String>, bool)>> = BTreeMap::new();
    for r in s.records_since(0).into_iter().filter(|r| {
        r.kind == RecordKind::Claim && !super::directives::is_summary_directive(&r.directive) && !super::directives::is_link_directive(&r.directive)
    }) {
        if !flags.as_ref().map_or_else(|| s.is_answer_support(&r.id), |m| m.get(&r.id).is_some_and(|x| x.1)) {
            continue;
        }
        let Some(doc) = source_doc(s, &r) else { continue };
        let text = assertion_text(s, &r);
        claims.entry(doc).or_default().push((r, technical(&text), change_marker(&text)));
    }
    let mut edges = Vec::new();
    for (new, nm) in &docs {
        for (old, om) in &docs {
            if om.date.is_empty() || nm.date.is_empty() || om.date >= nm.date {
                continue;
            }
            let named = nm.refs.contains(&om.report) || (!om.report.is_empty() && s.doc_text(new).unwrap_or_default().contains(&om.report));
            if !named {
                continue;
            }
            let (Some(a), Some(b)) = (claims.get(old), claims.get(new)) else { continue };
            let mut index: BTreeMap<String, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
            for (i, (_, tokens, _)) in a.iter().enumerate() {
                for t in tokens {
                    index.entry(t.clone()).or_default().0.push(i);
                }
            }
            for (i, (_, tokens, _)) in b.iter().enumerate() {
                for t in tokens {
                    index.entry(t.clone()).or_default().1.push(i);
                }
            }
            let mut scores: BTreeMap<(usize, usize), usize> = BTreeMap::new();
            for (left, right) in index.values() {
                for i in left {
                    for j in right {
                        *scores.entry((*i, *j)).or_default() += 1;
                    }
                }
            }
            let plain_a: Vec<_> = a.iter().map(|(r, _, _)| content_words(s, r)).collect();
            let plain_b: Vec<_> = b.iter().map(|(r, _, _)| content_words(s, r)).collect();
            let mut plain_index: BTreeMap<&str, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
            for (i, tokens) in plain_a.iter().enumerate() {
                for t in tokens {
                    plain_index.entry(t).or_default().0.push(i);
                }
            }
            for (j, tokens) in plain_b.iter().enumerate().filter(|(j, _)| b[*j].2) {
                for t in tokens {
                    plain_index.entry(t).or_default().1.push(j);
                }
            }
            let mut shared_words: BTreeMap<(usize, usize), usize> = BTreeMap::new();
            for (left, right) in plain_index.values() {
                for i in left {
                    for j in right {
                        *shared_words.entry((*i, *j)).or_default() += 1;
                    }
                }
            }
            for (pair, count) in shared_words.into_iter().filter(|(_, n)| *n >= 2) {
                *scores.entry(pair).or_default() += count;
            }
            let mut compound_overlap: BTreeMap<(usize, usize), usize> = BTreeMap::new();
            let mut join_compounds = |new_side: bool| {
                for (i, (r, _, changed)) in (if new_side { b } else { a }).iter().enumerate() {
                    if new_side && !changed {
                        continue;
                    }
                    for parts in compound_words(&assertion_text(s, r)) {
                        let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
                        for part in parts {
                            if let Some((old, new)) = plain_index.get(part.as_str()) {
                                for j in if new_side { old } else { new } {
                                    *counts.entry(*j).or_default() += 1;
                                }
                            }
                        }
                        for (j, n) in counts.into_iter().filter(|(_, n)| *n >= 2) {
                            let pair = if new_side { (j, i) } else { (i, j) };
                            let v = compound_overlap.entry(pair).or_default();
                            *v = (*v).max(n);
                        }
                    }
                }
            };
            join_compounds(true);
            join_compounds(false);
            for (pair, n) in &compound_overlap {
                *scores.entry(*pair).or_default() += 8 * n;
            }
            // A metadata edge remains a retrieval candidate when extraction changed the wording. Prefer a change-bearing new row;
            // this fallback never gives it semantic acceptance.
            if scores.is_empty() {
                for i in 0..a.len() {
                    for (j, (_, _, changed)) in b.iter().enumerate().filter(|(_, x)| x.2).take(3) {
                        scores.insert((i, j), usize::from(*changed));
                    }
                }
            }
            let mut rows: Vec<PairCandidate> = scores
                .into_iter()
                .map(|((i, j), common)| {
                    let score = common + 10 * usize::from(b[j].2) + 2 * usize::from(a[i].2);
                    PairCandidate {
                        old: a[i].0.id,
                        new: b[j].0.id,
                        old_doc: old.clone(),
                        new_doc: new.clone(),
                        score,
                        metadata: json!({"old_report":om.report,"old_date":om.date,"new_report":nm.report,"new_date":nm.date,
                    "blocking":"explicit_report_reference","shared_technical_tokens":a[i].1.intersection(&b[j].1).collect::<Vec<_>>(),"shared_content_words":plain_a[i].intersection(&plain_b[j]).collect::<Vec<_>>(),"compound_part_overlap":compound_overlap.get(&(i,j)).copied().unwrap_or(0)}),
                    }
                })
                .collect();
            rows.sort_by_key(|p| (std::cmp::Reverse(p.score), p.old, p.new));
            rows.truncate(3);
            if !rows.is_empty() {
                edges.push(rows);
            }
        }
    }
    let mut out = Vec::new();
    for k in 0..3 {
        for rows in &edges {
            if let Some(p) = rows.get(k) {
                if out.len() < MAX_PAIR_CARDS {
                    out.push(p.clone());
                }
            }
        }
    }
    out
}

/// A conservative scope boundary for procedural claims: separate heads/reports need an explicit bridge in the actual basis
/// quotes. Mere predecessor navigation in front matter does not satisfy it. Passing this guard never confirms a relation.
pub fn scope_violation<S: AuditStore>(s: &S, from: RecordId, rel: &str, to: RecordId, basis: &[RecordId]) -> Option<Value> {
    if !["qualifies", "supersedes", "same_as", "duplicate_of", "contradicts"].contains(&rel) {
        return None;
    }
    let (a, b) = (s.record(&from)?, s.record(&to)?);
    let (ad, bd) = (source_doc(s, &a)?, source_doc(s, &b)?);
    if ad == bd {
        return None;
    }
    let procedural = |r: &RecordView| {
        let t = assertion_text(s, r).to_ascii_lowercase();
        ["exact-head", "exact head", "fresh head", "head validation", "cargo test", "clippy", "worktree"].iter().any(|w| t.contains(w))
    };
    if !procedural(&a) || !procedural(&b) {
        return None;
    }
    let am = metadata(&s.doc_text(&ad).unwrap_or_default());
    let bm = metadata(&s.doc_text(&bd).unwrap_or_default());
    let quoted = cone(s, basis).into_iter().filter_map(|r| r.quote).collect::<Vec<_>>().join("\n");
    let names = |doc: &str, m: &Meta, r: &RecordView| {
        let hashes = technical(&assertion_text(s, r)).into_iter().filter(|t| t.len() >= 7 && t.bytes().all(|b| b.is_ascii_hexdigit())).collect::<Vec<_>>();
        std::iter::once(doc.to_string())
            .chain(doc.rsplit('/').next().map(str::to_string))
            .chain([m.report.clone(), m.title.clone()])
            .chain(hashes)
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    };
    // A bridge identifies the OTHER report/head inside a quote from one endpoint's source (not two independent local quotes).
    let bridge = cone(s, basis).into_iter().filter(|r| r.quote.is_some()).any(|r| {
        let opposite = if r.doc_id.as_deref() == Some(&ad) {
            names(&bd, &bm, &b)
        } else if r.doc_id.as_deref() == Some(&bd) {
            names(&ad, &am, &a)
        } else {
            return false;
        };
        let q = r.quote.as_deref().unwrap();
        opposite.iter().any(|n| {
            q.split(['`', '"']).any(|part| part == n)
                || q.split_whitespace().any(|word| word.trim_matches(['.', ',', ';', ':', '(', ')']) == n)
                || (n.contains(' ')
                    && q.match_indices(n).any(|(i, _)| {
                        let boundary = |c: char| !c.is_ascii_alphanumeric() && !matches!(c, '_' | '-');
                        q[..i].chars().next_back().is_none_or(boundary) && q[i + n.len()..].chars().next().is_none_or(boundary)
                    }))
        })
    });
    (!bridge).then(|| {
        json!({"rule":"report_head_scope","from_doc":ad,"to_doc":bd,"rel":rel,
        "expected":"a basis quote explicitly naming the other report or its assertion's SHA","basis_quote_bytes":quoted.len()})
    })
}
