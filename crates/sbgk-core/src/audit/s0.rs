//! S0: deterministic semantic checks of the swarm's lines, without a model (the semantic-verification research of 2026-10-23, its
//! first stage; Gemini's analysis of it). They read only the line, the quotes it rests on and the document bytes, so a refusal they
//! cause is the same on every run. Measured offline on the claims of live runs 10A-5..10A-9 before they were turned on: every
//! negation cut off and every clause cut on a dangling word was real, and an identifier missing from the quotes is by construction a
//! claim that says more than its quotes.

/// The identifiers a claim names that none of its quotes holds byte for byte: commit hashes (7..40 hex digits with a letter and a
/// digit), versions (`1.99.0`, `v0.1`), `#124`-style numbers, error codes (`E003`), file paths with a known extension, CamelCase names
/// of three humps or more and SCREAMING_SNAKE names. Compare whole identifiers: #1110 is no evidence of #111, nor data.rs of a.rs.
/// A hash may be the prefix of a quoted hash; a version may omit the quoted v marker and a path may omit parent components.
pub fn missing_identifiers(claim: &str, quotes: &[&str]) -> Vec<String> {
    let quoted: Vec<String> = quotes.iter().flat_map(|q| identifiers(q)).collect();
    let mut out: Vec<String> = Vec::new();
    for id in identifiers(claim) {
        let held = quoted.iter().any(|q| {
            q == &id
                || match id_class(&id) {
                    Some("hash") => id_class(q) == Some("hash") && q.starts_with(&id),
                    Some("version") => q.strip_prefix('v') == Some(id.as_str()),
                    Some("path") => id_class(q) == Some("path") && q.strip_suffix(id.as_str()).is_some_and(|parent| parent.ends_with('/')),
                    _ => false,
                }
        });
        if !held && !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// A term and a concept that name different identifiers of one class, as `(term's, concept's)`: a mapping between them joins two
/// things (the research of 2026-10-23 on concept linking; Codex's 10A-6 analysis: validations of different commits mapped to one
/// concept). A hash may be the other's prefix.
pub fn conflicting_identifiers(term: &str, concept: &str) -> Option<(String, String)> {
    let (ours, theirs) = (identifiers(term), identifiers(concept));
    let same = |a: &str, b: &str| a == b || (id_class(a) == Some("hash") && (a.starts_with(b) || b.starts_with(a)));
    for class in ["hash", "version", "number", "code", "path", "camel", "screaming"] {
        let mine: Vec<&String> = ours.iter().filter(|t| id_class(t) == Some(class)).collect();
        let other: Vec<&String> = theirs.iter().filter(|t| id_class(t) == Some(class)).collect();
        if let (Some(a), Some(b)) = (mine.first(), other.first()) {
            if !mine.iter().any(|m| other.iter().any(|o| same(m, o))) {
                return Some(((*a).clone(), (*b).clone()));
            }
        }
    }
    None
}

fn identifiers(text: &str) -> Vec<String> {
    let token_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '#');
    let trim = |t: &str| t.trim_matches(|c: char| matches!(c, '.' | '-' | '/')).to_string();
    let mut out = Vec::new();
    for t in text.split(|c: char| !token_char(c)).map(trim).filter(|t| !t.is_empty()) {
        if id_class(&t).is_some() {
            out.push(t);
        } else if t.contains('/') {
            // names joined by a slash that are no path ("SameCodeDifferentDetails/DifferentIdentity", 10A-10): each part counts
            out.extend(t.split('/').map(trim).filter(|p| id_class(p).is_some()));
        }
    }
    out
}

fn id_class(t: &str) -> Option<&'static str> {
    let hex = t.len() >= 7 && t.len() <= 40 && t.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let sha = hex && t.bytes().any(|b| b.is_ascii_digit()) && t.bytes().any(|b| b.is_ascii_alphabetic());
    let v = t.strip_prefix('v').unwrap_or(t);
    let version = v.contains('.') && v.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) && v.split('.').count() >= 2;
    let number = t.strip_prefix('#').is_some_and(|n| n.len() >= 2 && n.bytes().all(|b| b.is_ascii_digit()));
    let ecode = t.len() >= 4 && t.len() <= 5 && t.starts_with('E') && t[1..].bytes().all(|b| b.is_ascii_digit());
    const EXT: [&str; 10] = [".rs", ".md", ".toml", ".json", ".py", ".yml", ".yaml", ".lock", ".txt", ".sh"];
    let path = EXT.iter().any(|e| t.len() > e.len() && t.ends_with(e)) && t.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
    let humps = t.bytes().zip(t.bytes().skip(1)).filter(|(a, b)| (a.is_ascii_lowercase() || a.is_ascii_digit()) && b.is_ascii_uppercase()).count();
    let camel = t.bytes().all(|b| b.is_ascii_alphanumeric()) && t.bytes().next().is_some_and(|b| b.is_ascii_uppercase()) && humps >= 2;
    let screaming = t.contains('_')
        && t.split('_').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
        && t.bytes().any(|b| b.is_ascii_uppercase());
    [(sha, "hash"), (version, "version"), (number, "number"), (ecode, "code"), (path, "path"), (camel, "camel"), (screaming, "screaming")]
        .into_iter()
        .find_map(|(is, class)| is.then_some(class))
}

/// Words a clause does not end on: a quote ending on one was cut in the middle of what it says ("changed naturally from").
const DANGLING: [&str; 19] = ["from", "to", "by", "with", "that", "and", "or", "of", "the", "a", "an", "for", "in", "on", "at", "as", "than", "beyond", "into"];

/// A quote that ends on a word no clause ends on.
pub fn ends_mid_clause(quote: &str) -> bool {
    let last = quote.split_whitespace().last().unwrap_or("").trim_matches(|c: char| matches!(c, '`' | '*' | ',' | ';' | ':' | '(' | ')'));
    DANGLING.contains(&last.to_ascii_lowercase().as_str())
}

/// The part of the sentence before a quote that starts at `start` in `doc`: back to the last sentence end, blank line, table cell,
/// label, list item or line of a fenced code block, at most 300 bytes.
fn sentence_lead(doc: &str, start: usize) -> &str {
    let mut from = start.saturating_sub(300);
    while !doc.is_char_boundary(from) {
        from += 1;
    }
    let head = &doc[from..start];
    // a label ending its line ("known failure:" after a command's output, the consilium of 10A-17) starts a new statement too
    let cut = [". ", ".\n", ";", "\n\n", "|", ": ", ":\n"].iter().filter_map(|m| head.rfind(m).map(|i| i + m.len())).max().unwrap_or(0);
    // A negative governing heading scopes its list, unlike a sibling item's negation. Keep this bounded lexical control:
    // layout alone cannot turn "does not authorize: - release" into affirmative release evidence.
    let list_item = |line: &str| {
        let l = line.trim_start();
        let n = l.bytes().take_while(u8::is_ascii_digit).count();
        l.starts_with("- ") || l.starts_with("* ") || (n > 0 && l[n..].starts_with(". "))
    };
    let mut at = 0;
    let mut parent = None;
    for line in head.split_inclusive('\n') {
        let low = line.trim().to_ascii_lowercase();
        if low.ends_with(':') {
            parent = negates(&low).then_some(at);
        } else if !low.is_empty() && !list_item(line) && !line.starts_with([' ', '\t']) {
            parent = None;
        }
        at += line.len();
    }
    let current = &doc[doc[..start].rfind('\n').map_or(0, |i| i + 1)..];
    if list_item(current) || current.starts_with([' ', '\t']) {
        if let Some(at) = parent {
            return &head[at..];
        }
    }
    &head[cut.max(line_statement(doc, from, start))..]
}

/// Where the statement holding `start` begins by the layout of its lines, as an offset from `from`: at the list item holding it (a
/// line starting with `- `, `* ` or `1. `, its wrapped lines included) and, inside a fenced code block, at its own line. The negation
/// of the item or line before negates nothing in it (the offline replay of 10A-17's answers, step 1: a third of the negation_before
/// refusals left were "- protected corpus bytes remain unchanged;" after "- ... contains no host ...;" and the like).
fn line_statement(doc: &str, from: usize, start: usize) -> usize {
    let head = &doc[from..start];
    let mut cut = 0;
    for (i, _) in head.match_indices('\n') {
        let line = doc[from + i + 1..].trim_start_matches([' ', '\t']);
        let digits = line.bytes().take_while(u8::is_ascii_digit).count();
        if line.starts_with("- ") || line.starts_with("* ") || (digits > 0 && line[digits..].starts_with(". ")) {
            cut = i + 1;
        }
    }
    if doc[..start].matches("```").count() % 2 == 1 {
        cut = cut.max(head.rfind('\n').map_or(0, |i| i + 1));
    }
    cut
}

/// A negation word, not a part of a snake-case or hyphenated name: front matter's `merge_recommendation = "not_applicable"`, a field
/// value `NOT_AUTHORIZED` and a command's `--no-fail-fast` negate nothing that follows (check run 10A-12 lost
/// `supersedes = []` to the first; run 10A-17 lost a section's 27 lines to the last, Codex's C17-03).
fn negates(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("n't")
        || lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .any(|w| matches!(w, "not" | "no" | "never" | "neither" | "nor" | "without" | "cannot"))
}

/// The negation the quote's own sentence states before it, when the quote holds none: quoted alone, the words say the opposite
/// ("does not create product truth ... or authorize implementation beyond" quoted as "authorize implementation beyond").
pub fn negation_before(doc: &str, start: usize, quote: &str) -> Option<String> {
    let lead = sentence_lead(doc, start);
    (negates(lead) && !negates(quote)).then(|| lead.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The quote extended to the end of its clause when it ends on a dangling word exactly where a line of the source ends, its clause
/// running on in the next line (a report wrapped at 80 columns, quoted one line as the directive asks: the consilium of 10A-17 found
/// 40% of the lost lines on this rule), and no negation is cut off before it. The bytes to store instead, at most `max`, inside
/// `[a, b)`; the caller checks them by the store's quote rule. A negation cut off is never extended in the agent's place: the claim
/// resting on the quote may say the opposite of its source.
pub fn line_end_clause(doc: &str, start: usize, end: usize, a: usize, b: usize, max: usize) -> Option<String> {
    let quote = doc.get(start..end)?;
    if !ends_mid_clause(quote) || negation_before(doc, start, quote).is_some() {
        return None;
    }
    let rest = doc.get(end..b.min(doc.len()))?;
    let after = rest.trim_start_matches([' ', '\t', '\r']);
    if !after.starts_with('\n') || after[1..].trim_start_matches([' ', '\t', '\r']).starts_with('\n') {
        return None;
    }
    whole_clause(doc, start, end, a, b, max).filter(|whole| whole.len() > quote.len() && !ends_mid_clause(whole))
}

/// The quote extended to the start of its sentence (when a negation is cut off) or to the end of its clause (when it ends mid-clause):
/// the bytes to quote instead, at most `max` bytes, inside `[a, b)`. The caller checks them by the store's quote rule.
pub fn whole_clause(doc: &str, start: usize, end: usize, a: usize, b: usize, max: usize) -> Option<String> {
    let mut s = start;
    if negation_before(doc, start, &doc[start..end]).is_some() {
        s = start - sentence_lead(doc, start).len();
    }
    let mut e = end;
    if ends_mid_clause(&doc[start..end]) {
        let tail = &doc[end..b.min(doc.len())];
        let stop = [". ", ".\n", ";", ": ", ":\n", "\n\n", "|"].iter().filter_map(|m| tail.find(m).map(|i| i + 1)).min().unwrap_or(tail.len());
        e = end + stop.min(tail.len());
    }
    while s < start && doc.as_bytes()[s].is_ascii_whitespace() {
        s += 1;
    }
    while e > end && doc.as_bytes()[e - 1].is_ascii_whitespace() {
        e -= 1;
    }
    (s >= a && e <= b && (s, e) != (start, end) && e - s <= max && doc.is_char_boundary(s) && doc.is_char_boundary(e)).then(|| doc[s..e].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_hashes_versions_numbers_codes_paths_and_code_names() {
        let ids = identifiers("Base 3a7e9c21 moved to 5b2d8e47 after PR #125; pin 1.99.0 (was v1.97.1), E003 in conformance.rs, MergedGateHold and CARGO_PKG_VERSION; 27 fixes in Rust 2024.");
        assert_eq!(ids, ["3a7e9c21", "5b2d8e47", "#125", "1.99.0", "v1.97.1", "E003", "conformance.rs", "MergedGateHold", "CARGO_PKG_VERSION"]);
        assert!(identifiers("deadline accepted decade").is_empty(), "words of hex letters only are no hash");
        assert_eq!(identifiers("Row D for SameCodeDifferentDetails/DifferentIdentity in docs/reports/a.md"), ["SameCodeDifferentDetails", "docs/reports/a.md"]);
    }

    #[test]
    fn a_term_and_a_concept_naming_different_identifiers_of_one_class_conflict() {
        assert_eq!(conflicting_identifiers("validation of head 2c6e0a85", "claude validation of head 9e4b1d73"), Some(("2c6e0a85".into(), "9e4b1d73".into())));
        assert_eq!(conflicting_identifiers("PR #111 correction", "PR #124 result"), Some(("#111".into(), "#124".into())));
        assert_eq!(conflicting_identifiers("head 9e4b1d73", "validation of 9e4b1d73a5c2f806"), None, "a hash prefix is the same hash");
        assert_eq!(conflicting_identifiers("stale validation", "claude validation of head 9e4b1d73"), None, "nothing to compare");
    }

    #[test]
    fn an_identifier_is_missing_unless_a_quote_holds_it() {
        let quotes = ["Current live origin/dev after PR #125 | 5b2d8e476f1a3c9e0b4d7f2a8c5e1b3d6f9a0c4e |"];
        assert_eq!(missing_identifiers("The base 3a7e9c21 was superseded by 5b2d8e47 after PR #125.", &quotes), ["3a7e9c21"]);
    }

    #[test]
    fn a_negation_cut_off_and_a_clause_cut_on_a_dangling_word_are_found_with_the_whole_clause() {
        let doc = "It does not create product truth, perform activation, or authorize implementation beyond the selected scope. Next.";
        let q = "authorize implementation beyond";
        let start = doc.find(q).unwrap();
        assert!(negation_before(doc, start, q).is_some());
        assert!(ends_mid_clause(q));
        let whole = whole_clause(doc, start, start + q.len(), 0, doc.len(), 300).unwrap();
        assert_eq!(whole, "It does not create product truth, perform activation, or authorize implementation beyond the selected scope.");
        assert!(negation_before(doc, doc.find("Next").unwrap(), "Next").is_none(), "a new sentence starts clean");
    }

    #[test]
    fn a_hyphenated_option_or_a_label_line_is_no_negation_of_what_follows() {
        let doc = "cargo test --workspace --no-fail-fast:\n  1199 passed, 1 failed\nknown failure:\n  status_doc_keeps_operational_path";
        let q = "known failure:\n  status_doc_keeps_operational_path";
        assert_eq!(negation_before(doc, doc.find(q).unwrap(), q), None);
        let doc = "The run used non-blocking reads: the gate holds.";
        assert_eq!(negation_before(doc, doc.find("the gate").unwrap(), "the gate holds."), None);
        let doc = "It is not reproduced on main and passes";
        assert!(negation_before(doc, doc.find("passes").unwrap(), "passes").is_some(), "a plain negation still counts");
    }

    #[test]
    fn a_line_cut_on_a_dangling_word_at_the_end_of_a_wrapped_line_extends_to_its_clause() {
        let doc = "The accepted run-set expected identity changed naturally from\n`4c8a2e19` to\n`7d3f5b02`\nbecause validator version \
                   participates in run-set framing. The old digest was not preserved.";
        let q = "The accepted run-set expected identity changed naturally from";
        let at = doc.find(q).unwrap();
        let whole = line_end_clause(doc, at, at + q.len(), 0, doc.len(), 300).unwrap();
        assert_eq!(whole, "The accepted run-set expected identity changed naturally from\n`4c8a2e19` to\n`7d3f5b02`\nbecause validator version participates in run-set framing.");
        // cut mid-line, or a negation cut off before it: the agent quotes again
        let mid = "changed naturally";
        let doc2 = "It changed naturally from a to b.";
        let at2 = doc2.find("changed naturally from").unwrap();
        assert_eq!(line_end_clause(doc2, at2, at2 + "changed naturally from".len(), 0, doc2.len(), 300), None, "{mid}");
        let doc3 = "It does not authorize implementation beyond\nthe selected scope.";
        let q3 = "authorize implementation beyond";
        let at3 = doc3.find(q3).unwrap();
        assert_eq!(line_end_clause(doc3, at3, at3 + q3.len(), 0, doc3.len(), 300), None, "a negation cut off is never extended");
        let doc4 = "A list item ends with\n\nNext paragraph.";
        let at4 = doc4.find("A list").unwrap();
        assert_eq!(line_end_clause(doc4, at4, at4 + "A list item ends with".len(), 0, doc4.len(), 300), None, "a blank line ends the clause");
    }

    #[test]
    fn a_list_item_and_a_line_of_a_code_block_start_their_own_statement() {
        let doc = "Checks:\n- the capability closure contains no host or other\n  Stage 2 crate;\n- protected corpus bytes remain unchanged;\n\
                   16. actual source probe is checkout-hermetic.\n";
        for q in ["protected corpus bytes remain unchanged;", "- protected corpus bytes remain unchanged;", "actual source probe is checkout-hermetic."] {
            assert_eq!(negation_before(doc, doc.find(q).unwrap(), q), None, "{q}");
        }
        let doc = "```text\nMATRIX = CONFORMANCE CHARACTERIZATION, NOT EFFICACY BENCHMARK\nSTAGE2_RELEASE_PENDING\n```\n";
        assert_eq!(negation_before(doc, doc.find("STAGE2").unwrap(), "STAGE2_RELEASE_PENDING"), None);
        // controls: a negation in the quote's own item, a wrapped line of it included, or in its own sentence still counts
        let doc = "Checks:\n- the capability closure contains no host or other\n  Stage 2 crate;\n";
        assert!(negation_before(doc, doc.find("Stage 2 crate").unwrap(), "Stage 2 crate;").is_some(), "a wrapped line of the item");
        let doc = "It is not Project Sources, architecture\nauthority, or merge authorization.";
        assert!(negation_before(doc, doc.find("authority").unwrap(), "authority, or merge authorization.").is_some(), "a wrapped sentence");
        let doc = "```text\nThe gate does not authorize release\n```\n";
        assert!(negation_before(doc, doc.find("authorize").unwrap(), "authorize release").is_some(), "its own line in a code block");
    }

    #[test]
    fn a_snake_case_name_is_no_negation() {
        let doc = "verdict = \"passed_with_limitations\"\nmerge_recommendation = \"not_applicable\"\ntarget_branch = \"dev\"\nsupersedes = []\n";
        assert!(negation_before(doc, doc.find("supersedes").unwrap(), "supersedes = []").is_none());
        let doc = "STATUS: NOT_AUTHORIZED\nSNAPSHOT_ELIGIBILITY: REQUIRED";
        assert!(negation_before(doc, doc.find("SNAPSHOT").unwrap(), "SNAPSHOT_ELIGIBILITY: REQUIRED").is_none());
        let doc = "The gate is not passed; status no_go.";
        assert!(negation_before(doc, doc.find("passed").unwrap(), "passed").is_some(), "a negation word still counts");
    }
}
