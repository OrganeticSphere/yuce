//! A name only withdrawn text held (the architect's directive of 16.11.2026, task 1A, by the boundary of Argon's second opinion).
//! A withdrawal makes fall what rests on the withdrawn bytes; a claim whose own quotes are other sentences stands, even when its
//! words carry a token that only the withdrawn bytes held. The kernel does not judge meaning; it can see that much in bytes, and
//! says so. A notice, not a fall: nothing is refused, withdrawn or reopened by it.
//!
//! The mechanism is the same for any kind of token. A token is withdrawn when an occurrence of it in a document's whole text
//! overlaps withdrawn bytes (a withdrawal of "4.1" inside "v1.4.12" withdraws the version 1.4.12, never 4.1) and no occurrence
//! outside withdrawn bytes, in any document, holds it: text still standing elsewhere is no withdrawn name. A standing claim that
//! names a withdrawn token, while none of its own quotes holds it, gets the notice. What a token is, an extractor says: the open
//! kernel's reads structural anchors (hashes, versions, `#124`-style numbers, error codes and file paths, `s0::anchors`); a
//! build may plug in another through [`Extractor`]. A claim recorded through the agents' intake already names no anchor its
//! quotes lack (S0 refuses it), so with the open extractor the notice speaks for claims recorded without S0, and for extractors
//! plugged in.
use super::*;

/// What the notice compares: the tokens of a text with their bytes, and whether some tokens hold one.
pub trait Extractor {
    /// The tokens of a text, each with its bytes in the text and the spelling it is compared by.
    fn tokens(&self, text: &str) -> Vec<(usize, usize, String)>;
    /// Whether `among` holds `token`: by default the same spelling.
    fn held(&self, token: &str, among: &[String]) -> bool {
        among.iter().any(|t| t == token)
    }
}

/// The open kernel's extractor: the structural anchors of S0, compared as S0 compares them.
pub struct Anchors;

impl Extractor for Anchors {
    fn tokens(&self, text: &str) -> Vec<(usize, usize, String)> {
        super::super::s0::anchors(text)
    }
    fn held(&self, token: &str, among: &[String]) -> bool {
        super::super::s0::identifier_held(token, among)
    }
}

/// A claim with the notice: its id, the tokens it names that only withdrawn text held, and the documents they were withdrawn from.
pub type Notice = (RecordId, Vec<String>, BTreeSet<String>);

/// The tokens only withdrawn text held, each with its document: an occurrence overlaps withdrawn bytes, and no occurrence outside
/// them, in any document, holds the token.
pub fn withdrawn_with<S: AuditStore, E: Extractor>(s: &S, e: &E) -> Vec<(String, String)> {
    let docs = s.docs();
    let spans: Vec<(String, Vec<(usize, usize)>)> = docs.iter().map(|d| (d.clone(), s.closed_spans(d))).collect();
    if spans.iter().all(|(_, sp)| sp.is_empty()) {
        return Vec::new();
    }
    let (mut gone, mut standing): (Vec<(String, String)>, Vec<String>) = (Vec::new(), Vec::new());
    for (doc, sp) in &spans {
        let Some(text) = s.doc_text(doc) else { continue };
        for (a, b, t) in e.tokens(&text) {
            if sp.iter().any(|(x, y)| a < *y && *x < b) {
                if !gone.iter().any(|(g, d)| *g == t && d == doc) {
                    gone.push((t, doc.clone()));
                }
            } else {
                standing.push(t);
            }
        }
    }
    standing.sort_unstable();
    standing.dedup();
    gone.retain(|(t, _)| !e.held(t, &standing));
    gone
}

/// The notice on one claim, given the withdrawn tokens: the tokens it names that they hold and its own quotes do not, when it
/// stands.
fn notice_of<S: AuditStore, E: Extractor>(s: &S, e: &E, gone: &[(String, String)], r: &RecordView, grounded: bool) -> Option<Notice> {
    let text = r.text.as_deref()?;
    let all: Vec<String> = gone.iter().map(|(t, _)| t.clone()).collect();
    let mut named: Vec<String> = Vec::new();
    for (_, _, t) in e.tokens(text) {
        if e.held(&t, &all) && !named.contains(&t) {
            named.push(t);
        }
    }
    if named.is_empty() || !grounded {
        return None;
    }
    let held: Vec<String> = super::super::pairs::cone(s, &[r.id])
        .into_iter()
        .filter(|o| o.kind == RecordKind::Observe)
        .filter_map(|o| o.quote)
        .flat_map(|q| e.tokens(&q).into_iter().map(|(_, _, t)| t))
        .collect();
    named.retain(|t| !e.held(t, &held));
    if named.is_empty() {
        return None;
    }
    let docs = gone.iter().filter(|(w, _)| named.iter().any(|t| e.held(t, std::slice::from_ref(w)))).map(|(_, d)| d.clone()).collect();
    Some((r.id, named, docs))
}

/// The standing claims that name a withdrawn token none of their own quotes holds, by the extractor given. Computed whether the
/// run turned the notice on or not (the reading tool over any journal).
pub fn flagged_with<S: AuditStore, E: Extractor>(s: &S, e: &E) -> Vec<Notice> {
    let gone = withdrawn_with(s, e);
    if gone.is_empty() {
        return Vec::new();
    }
    let support = s.support_map();
    let grounded = |id: &RecordId| support.as_ref().map_or_else(|| s.is_grounded(id), |m| m.get(id).is_some_and(|v| v.0));
    s.records_of_kind(RecordKind::Claim).iter().filter_map(|r| notice_of(s, e, &gone, r, grounded(&r.id))).collect()
}

/// `flagged_with` the open kernel's extractor, whether the run turned the notice on or not.
pub fn flagged_any<S: AuditStore>(s: &S) -> Vec<Notice> {
    flagged_with(s, &Anchors)
}

/// `flagged_any`, when the run turned the notice on (`withdrawn_anchor` of the graph quality settings).
pub fn flagged<S: AuditStore>(s: &S) -> Vec<Notice> {
    if !enabled(s, "withdrawn_anchor") {
        return Vec::new();
    }
    flagged_any(s)
}

/// The notice on one record, or null: checked for that record alone, and only for a claim of a run that turned the notice on.
pub fn annotation<S: AuditStore>(s: &S, id: RecordId) -> Value {
    if !enabled(s, "withdrawn_anchor") {
        return Value::Null;
    }
    let Some(r) = s.record(&id).filter(|r| r.kind == RecordKind::Claim) else {
        return Value::Null;
    };
    let gone = withdrawn_with(s, &Anchors);
    if gone.is_empty() {
        return Value::Null;
    }
    notice_of(s, &Anchors, &gone, &r, s.is_grounded(&id))
        .map_or(Value::Null, |(_, names, docs)| json!({"names": names, "withdrawn_from": docs.iter().map(|d| s.document_label(d)).collect::<Vec<_>>()}))
}

/// The rows of the notice in JSON, for a report: id, short id, text, names, documents.
pub fn rows<S: AuditStore>(s: &S, found: &[Notice]) -> Value {
    json!(found
        .iter()
        .map(|(id, names, docs)| json!({"id": to_hex(&id.0), "short": id.short(), "text": s.record(id).and_then(|r| r.text),
            "names": names, "withdrawn_from": docs.iter().map(|d| s.document_label(d)).collect::<Vec<_>>()}))
        .collect::<Vec<_>>())
}

/// The lines a summary's prompt gets: each standing claim that names what only withdrawn text held.
pub fn prompt<S: AuditStore>(s: &S) -> String {
    let rows = flagged(s)
        .into_iter()
        .map(|(id, names, docs)| {
            let from = docs.iter().map(|d| s.document_label(d)).collect::<Vec<_>>().join(", ");
            format!("  {} names {}, which withdrawn text of {from} held; none of its own quotes holds it.", id.short(), names.join(", "))
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        String::new()
    } else {
        format!(
            "\nWITHDRAWN NAME WARNINGS (kernel: a standing claim names what only withdrawn text held):\n{}\nDo not repeat such a name \
             unless a standing quote shown above holds it.\n",
            rows.join("\n")
        )
    }
}
