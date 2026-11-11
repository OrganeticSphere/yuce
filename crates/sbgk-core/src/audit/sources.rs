//! Bind an explicitly selected set of supplied Markdown bytes to a pinned metadata manifest.
//!
//! This module does not read a repository, resolve a revision reference, or extract a finding. Lexical reference metadata is
//! retained only as unresolved metadata. Manifest identity hashes its raw bytes; document identity hashes the pinned tuple.
//! An entry may declare its report's `date`: it joins the document's descriptor (and so the audit root), never its id.

use crate::error::{Code, KResult, KernelError};
use crate::hash::{from_hex, sha256, to_hex, Hash};
use crate::jcs::to_jcs;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const MANIFEST_FORMAT: &str = "r2r.tobi_corpus_metadata_manifest.v1";
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_REFERENCES: usize = 100_000;

pub struct PreparedSources {
    pub manifest_hash: Hash,
    pub docs: Vec<(String, Vec<u8>)>,
    pub identities: BTreeMap<String, Value>,
}

fn bad(field: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field(field)
}

fn object<'a>(v: &'a Value, field: &str) -> KResult<&'a Map<String, Value>> {
    v.as_object().ok_or_else(|| bad(field, "expected an object"))
}

fn string<'a>(m: &'a Map<String, Value>, key: &str) -> KResult<&'a str> {
    let s = m.get(key).and_then(Value::as_str).ok_or_else(|| bad(key, "expected a string"))?;
    if s.trim().is_empty() || s.len() > MAX_TEXT_BYTES || s.chars().any(char::is_control) {
        return Err(bad(key, "expected a bounded, nonempty string without control characters"));
    }
    Ok(s)
}

fn integer(m: &Map<String, Value>, key: &str, positive: bool) -> KResult<u64> {
    m.get(key).and_then(Value::as_u64).filter(|n| !positive || *n > 0).ok_or_else(|| bad(key, "expected a bounded unsigned integer"))
}

fn array<'a>(m: &'a Map<String, Value>, key: &str) -> KResult<&'a [Value]> {
    let a = m.get(key).and_then(Value::as_array).ok_or_else(|| bad(key, "expected an array"))?;
    if a.len() > MAX_REFERENCES {
        return Err(bad(key, "too many metadata entries"));
    }
    Ok(a)
}

fn pin(s: &str) -> KResult<String> {
    if s.len() != 40 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("commit", "the source pin must be a full 40-digit hexadecimal commit"));
    }
    Ok(s.to_ascii_lowercase())
}

fn path(s: &str) -> KResult<()> {
    if s.is_empty()
        || s.len() > MAX_TEXT_BYTES
        || s.contains('\\')
        || s.chars().any(char::is_control)
        || s.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || s.split('/').next().is_some_and(|part| part.contains(':'))
    {
        return Err(bad("path", "expected a canonical repository-relative path with forward slashes"));
    }
    Ok(())
}

fn digest(m: &Map<String, Value>) -> KResult<Hash> {
    string(m, "raw_sha256").and_then(|s| from_hex(s).ok_or_else(|| bad("raw_sha256", "expected a full 64-digit SHA-256")))
}

/// The report date an entry declares, if any: an ISO calendar date `YYYY-MM-DD`. Reports are ordered by comparing these strings,
/// so only this fixed shape of a real calendar day is accepted. Pages without date front matter, such as the MCP specification's,
/// are dated here (run smoke2 on MCP: every evolution pair carried two empty dates, and pages of one release were paired as if
/// one were later).
fn report_date(m: &Map<String, Value>) -> KResult<Option<&str>> {
    if !m.contains_key("date") {
        return Ok(None);
    }
    let refused = || bad("date", "expected a calendar date YYYY-MM-DD");
    let s = m.get("date").and_then(Value::as_str).ok_or_else(refused)?;
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || !digits(0..4) || !digits(5..7) || !digits(8..10) {
        return Err(refused());
    }
    let n = |r: std::ops::Range<usize>| s[r].parse::<u32>().expect("checked digits");
    let (y, mo, d) = (n(0..4), n(5..7), n(8..10));
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d == 0 || d > days[mo as usize - 1] {
        return Err(refused());
    }
    Ok(Some(s))
}

fn syntax(m: &Map<String, Value>) -> KResult<()> {
    for v in array(m, "syntax")? {
        let s = v.as_str().ok_or_else(|| bad("syntax", "syntax entries must be strings"))?;
        if s.is_empty() || s.len() > MAX_TEXT_BYTES || s.chars().any(char::is_control) {
            return Err(bad("syntax", "expected bounded syntax labels"));
        }
    }
    Ok(())
}

fn references(v: Option<&Value>) -> KResult<Value> {
    let Some(v) = v else {
        return Ok(json!({"classification":"unresolved_lexical", "commit_candidates":[], "pull_request_candidates":[]}));
    };
    let m = object(v, "references")?;
    for (key, is_commit) in [("commit_candidates", true), ("pull_request_candidates", false)] {
        for candidate in array(m, key)? {
            let c = object(candidate, key)?;
            if string(c, "resolution")? != "not_resolved" {
                return Err(bad("resolution", "lexical references must remain not_resolved"));
            }
            integer(c, "line_1based", true)?;
            integer(c, "column_1based", true)?;
            syntax(c)?;
            if is_commit {
                let h = string(c, "hex")?;
                if !(7..=40).contains(&h.len()) || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("hex", "a lexical commit candidate must contain 7..40 hexadecimal digits"));
                }
            } else {
                integer(c, "number", true)?;
            }
            for optional in ["repository_from_url", "matched_url_prefix", "matched_url"] {
                if c.contains_key(optional) {
                    string(c, optional)?;
                }
            }
        }
    }
    let mut result = v.clone();
    result.as_object_mut().expect("checked reference object").insert("classification".into(), json!("unresolved_lexical"));
    Ok(result)
}

/// The Markdown extension of a source path: `.md`, or `.mdx` (Markdown with embedded components, as documentation sites such as
/// the MCP specification publish it), so that a pinned path names the upstream file itself.
fn markdown_extension(p: &str) -> Option<&'static str> {
    let lower = p.to_ascii_lowercase();
    [".md", ".mdx"].into_iter().find(|e| lower.ends_with(e))
}

/// The identity of a set of supplied files: their names and content hashes, in the order of the names. It holds nothing of the
/// machine, so the same files give the same value anywhere, and it can be computed again from a journal's own list.
pub fn docs_set_hash<'a>(docs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Hash {
    let mut pairs: Vec<(&str, &str)> = docs.into_iter().collect();
    pairs.sort_unstable();
    sha256(to_jcs(&json!(["r2r-audit-docs/1", pairs])).as_bytes())
}

fn document_id(repo: &str, commit: &str, path: &str, raw_hash: &Hash) -> String {
    let tuple = json!(["R2R-AUDIT-GIT-DOCUMENT/1", repo, commit, path, to_hex(raw_hash)]);
    format!("d_{}", to_hex(&sha256(to_jcs(&tuple).as_bytes())))
}

fn check_bytes(m: &Map<String, Value>, bytes: &[u8]) -> KResult<Hash> {
    if integer(m, "size_bytes", false)? != bytes.len() as u64 {
        return Err(bad("size_bytes", "supplied bytes do not match the manifest size"));
    }
    let hash = digest(m)?;
    if sha256(bytes) != hash {
        return Err(bad("raw_sha256", "supplied raw bytes do not match the pinned digest"));
    }
    Ok(hash)
}

/// Verify a persisted git-manifest descriptor against the bytes recovered from its engine container.
/// Opaque legacy document descriptors belong to their separate caller-owned compatibility path.
pub fn verify_identity(id: &str, descriptor: &Value, bytes: &[u8]) -> KResult<()> {
    let m = object(descriptor, "source_identity")?;
    if string(m, "kind")? != "git_manifest" {
        return Err(bad("kind", "expected a git_manifest source identity"));
    }
    let repo = string(m, "repo")?;
    let commit = pin(string(m, "commit")?)?;
    let p = string(m, "path")?;
    path(p)?;
    if markdown_extension(p).is_none() {
        return Err(bad("path", "only selected Markdown sources are supported"));
    }
    let hash = check_bytes(m, bytes)?;
    if id != document_id(repo, &commit, p, &hash) {
        return Err(bad("document_id", "document id does not match its pinned source tuple"));
    }
    let refs = m.get("revision_refs").ok_or_else(|| bad("revision_refs", "unresolved lexical metadata is required"))?;
    if refs.get("classification").and_then(Value::as_str) != Some("unresolved_lexical") {
        return Err(bad("revision_refs", "references must be classified as unresolved_lexical"));
    }
    references(Some(refs))?;
    report_date(m)?;
    Ok(())
}

/// Prepare only explicitly selected `(repo_relative_path, raw_bytes)` pairs. Manifest and path ordering do not rename a
/// document; changing the repo, pin, path, or raw digest does. The returned docs are sorted by their immutable ids.
pub fn prepare(manifest_bytes: &[u8], selected: &[(String, Vec<u8>)]) -> KResult<PreparedSources> {
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(bad("manifest", "manifest exceeds 16 MiB"));
    }
    let manifest: Value = serde_json::from_slice(manifest_bytes).map_err(|e| KernelError::new(Code::BadJson, format!("invalid metadata manifest: {e}")))?;
    let m = object(&manifest, "manifest")?;
    // The published metadata manifest declares `schema`; older fixtures use `format`.
    // Validate every declaration without rewriting the original bytes or their commitment.
    let mut declared = false;
    for field in ["schema", "format"] {
        if m.contains_key(field) {
            declared = true;
            if string(m, field)? != MANIFEST_FORMAT {
                return Err(bad(field, format!("unsupported metadata manifest {field}")));
            }
        }
    }
    if !declared {
        return Err(bad("schema", "metadata manifest requires schema or legacy format"));
    }
    let source = object(m.get("source").ok_or_else(|| bad("source", "source metadata is required"))?, "source")?;
    let repo = string(source, "origin_recorded")?;
    let commit = pin(string(source, "commit")?)?;
    let mut entries = BTreeMap::new();
    for entry in array(m, "entries")? {
        let e = object(entry, "entries")?;
        let p = string(e, "path")?;
        path(p)?;
        integer(e, "size_bytes", false)?;
        digest(e)?;
        string(e, "extension")?;
        string(e, "corpus_role")?;
        report_date(e)?;
        let refs = references(e.get("references"))?;
        if entries.insert(p, (e, refs)).is_some() {
            return Err(bad("entries", "duplicate repository-relative path in manifest"));
        }
    }
    let mut prepared = BTreeMap::new();
    let mut seen = BTreeMap::new();
    for (p, bytes) in selected {
        path(p)?;
        if seen.insert(p, ()).is_some() {
            return Err(bad("selected", "duplicate selected repository-relative path"));
        }
        let (e, refs) = entries.get(p.as_str()).ok_or_else(|| bad("selected", "selected path is absent from the pinned manifest"))?;
        if markdown_extension(p) != Some(string(e, "extension")?) || string(e, "corpus_role")? != "markdown_document_candidate" {
            return Err(bad(
                "selected",
                format!("{p}: only Markdown document candidates may be selected from a manifest; for other text files start the run with --docs"),
            ));
        }
        let hash = check_bytes(e, bytes)?;
        let id = document_id(repo, &commit, p, &hash);
        let mut descriptor = json!({"kind":"git_manifest", "repo":repo, "commit":commit, "path":p, "raw_sha256":to_hex(&hash),
            "size_bytes":bytes.len() as u64,"revision_refs":refs});
        // only a declared date is written: an undated entry keeps the descriptor, and the root, it had before dates existed
        if let Some(date) = report_date(e)? {
            descriptor["date"] = json!(date);
        }
        prepared.insert(id, (bytes.clone(), descriptor));
    }
    let mut docs = Vec::new();
    let mut identities = BTreeMap::new();
    for (id, (bytes, descriptor)) in prepared {
        docs.push((id.clone(), bytes));
        identities.insert(id, descriptor);
    }
    Ok(PreparedSources { manifest_hash: sha256(manifest_bytes), docs, identities })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Value {
        json!({"format":MANIFEST_FORMAT,"source":{"origin_recorded":"https://example.invalid/repo.git","commit":"1".repeat(40),
            "repository":"C:/local/checkout"},"entries":[{"path":"reports/a.md","extension":".md","corpus_role":"markdown_document_candidate",
                "size_bytes":2,"raw_sha256":to_hex(&sha256(b"A\n")),"references":{"commit_candidates":[{"hex":"a123456","line_1based":1,
                    "column_1based":2,"syntax":["bare"],"resolution":"not_resolved"}],"pull_request_candidates":[{"number":7,"line_1based":1,
                    "column_1based":4,"syntax":["hash_number"],"resolution":"not_resolved"}]}}]})
    }

    fn selected() -> Vec<(String, Vec<u8>)> {
        vec![("reports/a.md".into(), b"A\n".to_vec())]
    }

    fn prepared(v: &Value) -> KResult<PreparedSources> {
        prepare(to_jcs(v).as_bytes(), &selected())
    }

    #[test]
    fn identities_bind_repo_pin_path_and_raw_bytes_not_the_local_checkout() {
        let original = manifest();
        let base = prepared(&original).unwrap();
        let id = &base.docs[0].0;
        assert!(id.starts_with("d_") && id.len() == 66);
        let descriptor = &base.identities[id];
        verify_identity(id, descriptor, &base.docs[0].1).unwrap();
        assert_eq!(descriptor["revision_refs"]["classification"], "unresolved_lexical");
        assert_eq!(descriptor["revision_refs"]["commit_candidates"][0]["resolution"], "not_resolved");
        let mut changed = original.clone();
        changed["source"]["repository"] = json!("D:/another-checkout");
        assert_eq!(&prepared(&changed).unwrap().docs[0].0, id);
        changed["source"]["origin_recorded"] = json!("https://example.invalid/another.git");
        assert_ne!(&prepared(&changed).unwrap().docs[0].0, id);
        changed = original.clone();
        changed["source"]["commit"] = json!("2".repeat(40));
        assert_ne!(&prepared(&changed).unwrap().docs[0].0, id);
        changed = original;
        changed["entries"][0]["path"] = json!("reports/b.md");
        let renamed = prepare(to_jcs(&changed).as_bytes(), &[("reports/b.md".into(), b"A\n".to_vec())]).unwrap();
        assert_ne!(&renamed.docs[0].0, id);
        assert!(verify_identity(id, &renamed.identities[&renamed.docs[0].0], b"A\n").is_err());
    }

    #[test]
    fn raw_manifest_hash_tracks_serialization_but_document_ids_do_not() {
        let v = manifest();
        let compact = to_jcs(&v).into_bytes();
        let pretty = serde_json::to_vec_pretty(&v).unwrap();
        let a = prepare(&compact, &selected()).unwrap();
        let b = prepare(&pretty, &selected()).unwrap();
        assert_eq!(a.manifest_hash, sha256(&compact));
        assert_eq!(b.manifest_hash, sha256(&pretty));
        assert_ne!(a.manifest_hash, b.manifest_hash);
        assert_eq!(a.docs, b.docs);
        assert_eq!(a.identities, b.identities);
    }

    #[test]
    fn schema_only_manifest_preserves_original_raw_hash_and_legacy_document_identities() {
        let legacy = prepared(&manifest()).unwrap();
        let mut schema_only = manifest();
        let object = schema_only.as_object_mut().unwrap();
        let declaration = object.remove("format").unwrap();
        object.insert("schema".into(), declaration);
        // Deliberately noncanonical whitespace must remain part of the raw manifest commitment.
        let raw = format!(" \r\n{}\r\n", serde_json::to_string_pretty(&schema_only).unwrap()).into_bytes();
        let accepted = prepare(&raw, &selected()).unwrap();
        assert_eq!(accepted.manifest_hash, sha256(&raw));
        assert_ne!(accepted.manifest_hash, sha256(to_jcs(&schema_only).as_bytes()));
        assert_ne!(accepted.manifest_hash, legacy.manifest_hash);
        assert_eq!(accepted.docs, legacy.docs);
        assert_eq!(accepted.identities, legacy.identities);
        let (id, bytes) = &accepted.docs[0];
        verify_identity(id, &accepted.identities[id], bytes).unwrap();
    }

    #[test]
    fn schema_and_format_declarations_must_both_match_when_present() {
        let legacy = prepared(&manifest()).unwrap();
        let mut both = manifest();
        both["schema"] = json!(MANIFEST_FORMAT);
        let bytes = serde_json::to_vec_pretty(&both).unwrap();
        let accepted = prepare(&bytes, &selected()).unwrap();
        assert_eq!(accepted.manifest_hash, sha256(&bytes));
        assert_eq!(accepted.docs, legacy.docs);
        assert_eq!(accepted.identities, legacy.identities);
        for field in ["schema", "format"] {
            let mut conflicting = both.clone();
            conflicting[field] = json!("other/1");
            let refused = prepared(&conflicting).err().expect("a conflicting declaration must not fall back to its valid sibling");
            assert_eq!(refused.field.as_deref(), Some(field));
        }
    }

    #[test]
    fn missing_or_nonstring_declarations_are_rejected_even_with_a_valid_sibling() {
        let mut missing = manifest();
        missing.as_object_mut().unwrap().remove("format");
        assert!(prepared(&missing).is_err());
        for field in ["schema", "format"] {
            for invalid in [Value::Null, json!(true), json!(1), json!([]), json!({})] {
                let mut single = missing.clone();
                single[field] = invalid.clone();
                let refused = prepared(&single).err().expect("a declaration must be a string");
                assert_eq!(refused.field.as_deref(), Some(field));
                let mut both = manifest();
                both["schema"] = json!(MANIFEST_FORMAT);
                both[field] = invalid;
                let refused = prepared(&both).err().expect("an invalid declaration must not be ignored");
                assert_eq!(refused.field.as_deref(), Some(field));
            }
        }
    }

    #[test]
    fn supplied_size_and_raw_digest_are_both_checked() {
        assert!(prepare(to_jcs(&manifest()).as_bytes(), &[("reports/a.md".into(), b"B\n".to_vec())]).is_err());
        assert!(prepare(to_jcs(&manifest()).as_bytes(), &[("reports/a.md".into(), b"A".to_vec())]).is_err());
        let mut v = manifest();
        v["entries"][0]["size_bytes"] = json!(true);
        assert!(prepared(&v).is_err());
        v["entries"][0]["size_bytes"] = json!(2.0);
        assert!(prepared(&v).is_err());
        let p = prepared(&manifest()).unwrap();
        assert!(verify_identity(&p.docs[0].0, &p.identities[&p.docs[0].0], b"B\n").is_err());
    }

    #[test]
    fn only_explicit_markdown_candidates_are_eligible() {
        let mut v = manifest();
        v["entries"][0]["corpus_role"] = json!("readme_or_index_auxiliary");
        assert!(prepared(&v).is_err());
        v["entries"][0]["corpus_role"] = json!("markdown_document_candidate");
        v["entries"][0]["extension"] = json!(".json");
        assert!(prepared(&v).is_err());
        let none = prepare(to_jcs(&manifest()).as_bytes(), &[]).unwrap();
        assert!(none.docs.is_empty() && none.identities.is_empty());
    }

    #[test]
    fn an_mdx_source_is_markdown_pinned_at_its_own_path_and_its_extension_must_name_it() {
        let mut v = manifest();
        v["entries"][0]["path"] = json!("docs/a.mdx");
        v["entries"][0]["extension"] = json!(".mdx");
        let mdx = |v: &Value| prepare(to_jcs(v).as_bytes(), &[("docs/a.mdx".into(), b"A\n".to_vec())]);
        let p = mdx(&v).unwrap();
        let (id, bytes) = &p.docs[0];
        assert_eq!(p.identities[id]["path"], "docs/a.mdx");
        verify_identity(id, &p.identities[id], bytes).unwrap();
        v["entries"][0]["extension"] = json!(".md");
        assert!(mdx(&v).is_err(), "the extension field names the path's own extension");
    }

    #[test]
    fn a_declared_date_joins_the_descriptor_not_the_document_id_and_must_be_a_calendar_day() {
        let undated = prepared(&manifest()).unwrap();
        let id = &undated.docs[0].0;
        assert!(undated.identities[id].get("date").is_none(), "an undated entry keeps the descriptor it had");
        let mut v = manifest();
        v["entries"][0]["date"] = json!("2024-02-29");
        let dated = prepared(&v).unwrap();
        assert_eq!(&dated.docs[0].0, id, "a date names no other document");
        assert_eq!(dated.identities[id]["date"], "2024-02-29");
        verify_identity(id, &dated.identities[id], &dated.docs[0].1).unwrap();
        for wrong in [
            json!("2025-02-29"),
            json!("2025-13-01"),
            json!("2025-00-10"),
            json!("2025-04-31"),
            json!("2025-04-00"),
            json!("2025-3-26"),
            json!("2025/03/26"),
            json!("2025-03-26T00:00:00Z"),
            json!(" 2025-03-26"),
            json!(""),
            json!(20250326),
            Value::Null,
        ] {
            let mut v = manifest();
            v["entries"][0]["date"] = wrong.clone();
            assert_eq!(prepared(&v).err().expect("a malformed date is refused").field.as_deref(), Some("date"), "{wrong}");
            let mut forged = dated.identities[id].clone();
            forged["date"] = wrong.clone();
            assert!(verify_identity(id, &forged, &dated.docs[0].1).is_err(), "{wrong}");
        }
    }

    #[test]
    fn relative_paths_and_duplicates_are_checked_without_filesystem_access() {
        let bytes = to_jcs(&manifest()).into_bytes();
        for p in ["/reports/a.md", "../a.md", "reports/../a.md", "C:/a.md", "reports\\a.md", "reports//a.md", "missing.md"] {
            assert!(prepare(&bytes, &[(p.into(), b"A\n".to_vec())]).is_err(), "{p}");
        }
        let mut duplicate = selected();
        duplicate.extend(selected());
        assert!(prepare(&bytes, &duplicate).is_err());
        let mut v = manifest();
        let entry = v["entries"][0].clone();
        v["entries"].as_array_mut().unwrap().push(entry);
        assert!(prepared(&v).is_err());
    }

    #[test]
    fn malformed_reference_metadata_is_rejected_instead_of_silently_dropped() {
        for (key, value) in [("line_1based", json!(true)), ("column_1based", json!(0)), ("resolution", json!("resolved")), ("syntax", json!([1]))] {
            let mut v = manifest();
            v["entries"][0]["references"]["commit_candidates"][0][key] = value;
            assert!(prepared(&v).is_err());
        }
        let mut v = manifest();
        v["entries"][0]["references"]["pull_request_candidates"][0]["number"] = json!(7.0);
        assert!(prepared(&v).is_err());
        v = manifest();
        v["entries"][0]["references"] = json!(false);
        assert!(prepared(&v).is_err());
        v = manifest();
        v["entries"][0].as_object_mut().unwrap().remove("references");
        assert_eq!(prepared(&v).unwrap().identities.values().next().unwrap()["revision_refs"]["commit_candidates"], json!([]));
    }

    #[test]
    fn format_pin_and_manifest_byte_limit_are_strict() {
        for (key, value) in [("commit", json!("a123456")), ("commit", json!(true)), ("origin_recorded", Value::Null)] {
            let mut v = manifest();
            v["source"][key] = value;
            assert!(prepared(&v).is_err());
        }
        let mut v = manifest();
        v["format"] = json!("other/1");
        assert!(prepared(&v).is_err());
        assert!(prepare(&vec![b' '; MAX_MANIFEST_BYTES + 1], &[]).is_err());
    }
}
