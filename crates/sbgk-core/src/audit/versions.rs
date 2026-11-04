//! Version-map candidates. Explicit lineage is input; text similarity is retrieval, never evidence of replacement.
use super::{AuditStore, Scope};
use crate::error::{Code, KResult, KernelError};
use crate::hash::{sha256, to_hex};
use crate::jcs::to_jcs;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const ALGORITHM: &str = "r2r-version-map/1";
pub const KEY: &str = "version:map";
/// Explicit command rule: old WAL commands retain their original whole-command refusal semantics.
pub const RELATION_RULE: &str = "version_relations/1";
const BUDGET: usize = 9000;

pub trait SourceBytes {
    fn text(&self, id: &str) -> Option<String>;
    fn label(&self, id: &str) -> String;
}

impl SourceBytes for std::collections::BTreeMap<String, (String, String)> {
    fn text(&self, id: &str) -> Option<String> {
        self.get(id).map(|(_, t)| t.clone())
    }
    fn label(&self, id: &str) -> String {
        self.get(id).map_or_else(|| id.into(), |(l, _)| l.clone())
    }
}

fn bad(message: &str) -> KernelError {
    KernelError::new(Code::BadField, message).field(KEY)
}

pub fn digest(value: &Value) -> String {
    to_hex(&sha256(to_jcs(value).as_bytes()))
}

fn array<'a>(value: &'a Value, key: &str) -> KResult<&'a [Value]> {
    value[key].as_array().map(Vec::as_slice).ok_or_else(|| bad("lineage needs arrays of lineages, snapshots, docs and changelog"))
}

fn label<'a>(value: &'a Value, key: &str) -> KResult<&'a str> {
    value[key].as_str().filter(|s| !s.is_empty() && s.len() <= 4096).ok_or_else(|| bad("lineage ids must be bounded nonempty strings"))
}

/// The reference normalizes only specification version URLs and whitespace; it does not interpret dates as lineage.
fn norm(text: &str) -> String {
    let mut s = text.to_string();
    let prefix = "/specification/";
    let mut pos = 0;
    while let Some(i) = s[pos..].find(prefix) {
        let a = pos + i + prefix.len();
        let bytes = s.as_bytes();
        let dated = bytes
            .get(a..a + 11)
            .is_some_and(|b| b[4] == b'-' && b[7] == b'-' && b[10] == b'/' && b[..10].iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()));
        if dated {
            s.replace_range(a..a + 10, "V");
        }
        pos = a;
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn words(text: &str) -> BTreeSet<String> {
    const STOP: &str = "the a an and or of to in is are be for with by on as that this from its it at not no if any all may must should will can";
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| w.len() > 2 && !STOP.split_whitespace().any(|s| s == *w))
        .map(str::to_string)
        .collect()
}

struct Section {
    doc: String,
    head: String,
    text: String,
    start: usize,
    end: usize,
    words: BTreeSet<String>,
}

impl Section {
    fn range(&self) -> Value {
        json!([self.doc, self.start, self.end])
    }
    fn score(&self, other: &Self) -> (usize, usize) {
        let union = self.words.union(&other.words).count().max(1);
        let same = usize::from(norm(&self.head).to_lowercase() == norm(&other.head).to_lowercase());
        (same * union + self.words.intersection(&other.words).count(), union)
    }
}

fn sections(doc: &str, text: &str, title: &str) -> Vec<Section> {
    let mut begin = 0;
    if text.starts_with("---\n") || text.starts_with("---\r\n") {
        let first = text.find('\n').unwrap() + 1;
        if let Some(end) = text[first..].find("\n---") {
            let marker = first + end + 4;
            begin = text[marker..].find('\n').map_or(text.len(), |i| marker + i + 1);
        }
    }
    let mut head = title.to_string();
    // Match the prephase's front-matter title, used only for the section preceding the first heading.
    for line in text[..begin].lines() {
        if let Some(t) = line.strip_prefix("title:") {
            head = t.trim().trim_matches('"').to_string();
        }
    }
    let mut out = Vec::new();
    let mut start = begin;
    let push = |out: &mut Vec<Section>, head: &str, a: usize, b: usize| {
        let raw = &text[a..b];
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let a = a + raw.len() - raw.trim_start().len();
        let b = a + trimmed.len();
        let body = trimmed.to_string();
        out.push(Section { doc: doc.into(), head: head.into(), words: words(&format!("{head} {body}")), text: body, start: a, end: b });
    };
    let mut offset = begin;
    for line in text[begin..].split_inclusive('\n') {
        let n = line.bytes().take_while(|b| *b == b'#').count();
        if (1..=6).contains(&n) && line.as_bytes().get(n).is_some_and(u8::is_ascii_whitespace) {
            push(&mut out, &head, start, offset);
            head = line[n..].trim().to_string();
            start = offset + line.len();
        }
        offset += line.len();
    }
    push(&mut out, &head, start, text.len());
    out
}

fn snapshot<S: SourceBytes>(s: &S, snap: &Value, seen: &mut BTreeSet<String>) -> KResult<Vec<Section>> {
    label(snap, "id")?;
    let mut out = Vec::new();
    for (key, reading) in [("docs", true), ("changelog", false)] {
        for doc in array(snap, key)? {
            let id = label(doc, "doc_id")?;
            let hash = label(doc, "raw_sha256")?;
            if !seen.insert(id.into()) {
                return Err(bad("a document may belong to only one explicit snapshot"));
            }
            let text = s.text(id).ok_or_else(|| bad("lineage document is outside genesis"))?;
            if to_hex(&sha256(text.as_bytes())) != hash {
                return Err(bad("snapshot hash does not match genesis document bytes"));
            }
            if reading {
                out.extend(sections(id, &text, &s.label(id)));
            }
        }
    }
    Ok(out)
}

/// Explicit ordered snapshots: {lineages:[{id, snapshots:[{id, docs:[{doc_id,raw_sha256}], changelog:[...]}]}]}.
/// Array order is the tie break, not a source of inferred lineage. Every document is byte-bound to genesis.
pub fn compute<S: SourceBytes>(s: &S, lineage: &Value) -> KResult<Value> {
    let mut cards = Vec::<Value>::new();
    let mut seen = BTreeSet::new();
    let mut lineages = BTreeSet::new();
    for lin in array(lineage, "lineages")? {
        let lid = label(lin, "id")?;
        if !lineages.insert(lid) {
            return Err(bad("duplicate lineage id"));
        }
        let snaps = array(lin, "snapshots")?;
        let mut versions = BTreeSet::new();
        let mut all = Vec::new();
        for snap in snaps {
            if !versions.insert(label(snap, "id")?) {
                return Err(bad("duplicate snapshot id"));
            }
            all.push(snapshot(s, snap, &mut seen)?);
        }
        for i in 1..all.len() {
            let (old, new) = (&all[i - 1], &all[i]);
            let mut used = BTreeSet::new();
            let mut parts = Vec::new();
            let part = |o: Option<&Section>, n: Option<&Section>| {
                json!({"old":o.map(Section::range),"new":n.map(Section::range),
                    "head":n.or(o).expect("section").head,
                    "status":if o.is_none() || n.is_none() {"unmatched_by_version_map"} else {"changed_text_candidate"}})
            };
            for n in new {
                let mut best: Option<(usize, usize, usize)> = None;
                for (j, o) in old.iter().enumerate() {
                    let (num, den) = n.score(o);
                    if best.is_none_or(|(_, a, b)| num * b > a * den) {
                        best = Some((j, num, den));
                    }
                }
                if let Some((j, _, _)) = best.filter(|(_, num, den)| 100 * num >= 35 * den) {
                    // The reference counts (doc, heading) as used, even when the heading occurs twice.
                    used.insert((old[j].doc.clone(), old[j].head.clone()));
                    if norm(&old[j].text) != norm(&n.text) {
                        parts.push(part(Some(&old[j]), Some(n)));
                    }
                } else {
                    parts.push(part(None, Some(n)));
                }
            }
            for o in old {
                if !used.contains(&(o.doc.clone(), o.head.clone())) {
                    parts.push(part(Some(o), None));
                }
            }
            let logs = array(&snaps[i], "changelog")?
                .iter()
                .map(|d| {
                    let id = d["doc_id"].as_str().expect("checked doc");
                    json!([id, 0, s.text(id).expect("checked text").len()])
                })
                .collect::<Vec<_>>();
            let mut packed: Vec<(String, usize, Vec<Value>)> = Vec::new();
            for p in parts {
                let primary = p["new"][0].as_str().or_else(|| p["old"][0].as_str()).expect("part range").to_string();
                let size = ["old", "new"].iter().map(|k| p[k][2].as_u64().unwrap_or(0) - p[k][1].as_u64().unwrap_or(0)).sum::<u64>() as usize;
                if let Some((key, bytes, group)) = packed.last_mut().filter(|(key, bytes, _)| *key == primary && *bytes + size <= BUDGET) {
                    let _ = key;
                    *bytes += size;
                    group.push(p);
                } else {
                    packed.push((primary, size, vec![p]));
                }
            }
            for (_, _, parts) in packed {
                let ranges = |key: &str| parts.iter().filter_map(|p| (!p[key].is_null()).then_some(p[key].clone())).collect::<Vec<_>>();
                let mut card = json!({"lineage":lid,"from":snaps[i-1]["id"],"to":snaps[i]["id"],
                    "old":ranges("old"),"new":ranges("new"),"changelog":logs,"parts":parts});
                card["id"] = json!(digest(&card));
                cards.push(card);
            }
        }
    }
    let mut map = json!({"algorithm":ALGORITHM,"threshold":{"numerator":35,"denominator":100},
        "tie_break":"explicit_snapshot_document_order_then_section_offset_first_max",
        "budget_utf8_bytes":BUDGET,"lineage":lineage,"cards":cards});
    map["digest"] = json!(digest(&map));
    Ok(map)
}

pub fn card_scope(card: &Value) -> Scope {
    let ranges: Vec<(String, usize, usize)> = ["old", "new", "changelog"]
        .iter()
        .flat_map(|k| card[k].as_array().into_iter().flatten())
        .map(|r| {
            (r[0].as_str().expect("computed range").into(), r[1].as_u64().expect("computed range") as usize, r[2].as_u64().expect("computed range") as usize)
        })
        .collect();
    let docs = ranges.iter().map(|(d, _, _)| d.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    Scope { docs, ranges, topic: Some(format!("version:{}", card["id"].as_str().expect("computed id"))) }
}

pub fn cards<S: AuditStore>(s: &S) -> Vec<Value> {
    s.checkpoint(KEY).and_then(|c| c["context"]["cards"].as_array().cloned()).unwrap_or_default()
}

pub fn prompt<S: AuditStore>(s: &S, card: &Value) -> (String, Scope, Vec<super::RecordId>) {
    let scope = card_scope(card);
    let mut prompt = format!("TASK CHANGE\nCandidate {} -> {}. Similarity and unmatched_by_version_map are retrieval metadata, NOT proof of removal or replacement. Quote both versions. A removal needs an explicit NEW changelog statement; absence alone proves nothing. Write ordinary observe/claim/relation lines. supersedes runs NEW to OLD, only for the same fact and scope. A separate nonauthor verifies links.\nCARD:\n{}\n", card["from"], card["to"], to_jcs(card));
    prompt.push_str("CHANGE relations are cross-snapshot only: each endpoint claim rests on quotes from exactly ONE snapshot, the other claim from the OTHER snapshot. Do not submit relations between two NEW claims or two OLD claims. Keep OLD and NEW findings in separate claims, even when they agree. Every relation based_on includes an Observe from EACH snapshot. Example after writing old_o (OLD quote), new_o (NEW quote), old_c based_on [old_o] and new_c based_on [new_o]: {\"kind\":\"relation\",\"local_id\":\"<prefix>r1\",\"from\":\"new_c\",\"rel\":\"supersedes\",\"to\":\"old_c\",\"based_on\":[\"old_o\",\"new_o\"]}. Use your actual local_ids with the issued prefix. Propose a relation only if the quotes prove it; otherwise keep the grounded observations and claims without a relation.\n");
    let texts = ["old", "new", "changelog"]
        .iter()
        .flat_map(|side| card[*side].as_array().into_iter().flatten().map(move |r| (*side, r)))
        .map(|(side, r)| {
            let doc = r[0].as_str().expect("range doc");
            let a = r[1].as_u64().expect("range start") as usize;
            let b = r[2].as_u64().expect("range end") as usize;
            json!({"side":side,"doc_id":doc,"start":a,"end":b,"text":&s.doc_text(doc).expect("mapped document")[a..b]})
        })
        .collect::<Vec<_>>();
    prompt.push_str(&format!("\nVERSION TEXTS:\n{}\nEND VERSION TEXTS\n", to_jcs(&json!(texts))));
    (prompt, scope, vec![])
}

pub fn uncertainty<S: AuditStore>(s: &S) -> String {
    let mut out = Vec::new();
    for card in cards(s) {
        for p in card["parts"].as_array().into_iter().flatten().filter(|p| p["status"] == "unmatched_by_version_map") {
            out.push(json!({"algorithm":ALGORITHM,"card":card["id"],"from":card["from"],"to":card["to"],"old":p["old"],"new":p["new"],"status":"unmatched_by_version_map"}));
        }
    }
    let total = out.len();
    out.truncate(32);
    let (active, unavailable): (Vec<_>, Vec<_>) = s.supersession_history().into_iter().partition(|l| s.link_usable(&l.id));
    let rows = |links: &[super::LinkView]| {
        links.iter().take(32).map(|l| json!({"earlier":l.to.short(),"later":l.from.short(),"link":l.id.short()})).collect::<Vec<_>>()
    };
    let view = json!({"unmatched_total":total,"unmatched_shown":out,"map_digest":s.checkpoint(KEY).map(|c|c["context"]["digest"].clone()),
        "accepted_replacements_total":active.len(),"accepted_replacements":rows(&active),
        "replacement_support_unavailable_total":unavailable.len(),"replacement_support_unavailable":rows(&unavailable)});
    format!("\nVERSION MAP UNCERTAINTY (metadata, not evidence; no fact is revoked by unmatched; at most 32 rows per category shown): {}\nEstablished replacement is separate: only accepted supersedes with active two-sided evidence. A replacement whose support is unavailable leaves the current state unconfirmed; do not revive the old state as current. Cite only evidence issued in RECORDS.\n", to_jcs(&view))
}
