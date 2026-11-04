//! Strict, stateless shapes for swarm records. Reference resolution, source dates, quote binding and `done` proof belong
//! to `AuditState`. The schema's `x-maxUtf8Bytes` and `x-calendar` annotations describe checks the kernel also enforces.

use super::{RecordId, RecordKind};
use crate::error::{Code, KResult, KernelError};
use crate::hash::sha256;
use crate::jcs::to_jcs;
use crate::session::{MAX_QUOTE, MAX_REFS, MAX_STR};
use serde_json::{json, Map, Value};

pub(crate) const MAX_TEXT_CHARS: usize = 240;
const STANCES: [&str; 7] = ["reported", "confirmed", "refuted", "qualified", "superseded", "open", "unknown"];
// Identity/duplicate proposals belong to the builder's operations, not a swarm relation record.
const SWARM_RELATIONS: [&str; 5] = ["supports", "contradicts", "qualifies", "supersedes", "depends_on"];

#[derive(Debug, Clone)]
pub(crate) struct ParsedRecord {
    pub kind: RecordKind,
    pub local_id: String,
    pub body: Value,
    pub terms: Vec<String>,
    pub text: Option<String>,
    pub stance: Option<String>,
    pub based_on: Vec<String>,
    pub ends: Option<(String, String, String)>,
}

fn bad(field: &str, message: impl Into<String>, expected: Value) -> KernelError {
    KernelError::new(Code::BadField, message).field(field).expected(expected)
}

fn required<'a>(m: &'a Map<String, Value>, field: &str) -> KResult<&'a Value> {
    m.get(field).ok_or_else(|| KernelError::new(Code::MissingField, format!("missing '{field}'")).field(field).expected(json!({"required": field})))
}

fn string(v: &Value, field: &str, max_bytes: usize, max_chars: usize) -> KResult<String> {
    let expected = json!({"type": "string", "minLength": 1, "maxLength": max_chars, "x-maxUtf8Bytes": max_bytes});
    let s = v.as_str().ok_or_else(|| bad(field, format!("'{field}' must be a string"), expected.clone()))?;
    if s.is_empty() || s.len() > max_bytes || s.chars().count() > max_chars {
        return Err(bad(field, format!("'{field}' is empty or exceeds its character/UTF-8 byte bound"), expected));
    }
    Ok(s.to_string())
}

fn str_field(m: &Map<String, Value>, field: &str) -> KResult<String> {
    string(required(m, field)?, field, MAX_STR, MAX_STR)
}

fn optional_str(m: &Map<String, Value>, field: &str) -> KResult<Option<String>> {
    m.get(field).map(|v| string(v, field, MAX_STR, MAX_STR)).transpose()
}

fn text_field(m: &Map<String, Value>, field: &str) -> KResult<String> {
    string(required(m, field)?, field, MAX_STR, MAX_TEXT_CHARS)
}

fn strings(m: &Map<String, Value>, field: &str, min: usize, required_field: bool) -> KResult<Vec<String>> {
    let Some(v) = m.get(field) else {
        if required_field {
            required(m, field)?;
        }
        return Ok(Vec::new());
    };
    let expected = json!({"type": "array", "minItems": min, "maxItems": MAX_REFS, "items": {"type": "string"}});
    let a = v.as_array().ok_or_else(|| bad(field, format!("'{field}' must be an array of strings"), expected.clone()))?;
    if a.len() < min || a.len() > MAX_REFS {
        return Err(bad(field, format!("'{field}' must contain {min}..{MAX_REFS} items"), expected));
    }
    a.iter().enumerate().map(|(i, v)| string(v, &format!("{field}[{i}]"), MAX_STR, MAX_STR)).collect()
}

fn enum_field(m: &Map<String, Value>, field: &str, allowed: &[&str]) -> KResult<String> {
    let s = str_field(m, field)?;
    if !allowed.contains(&s.as_str()) {
        return Err(bad(field, format!("'{field}' is not an allowed value"), json!({"enum": allowed})));
    }
    Ok(s)
}

fn check_date(m: &Map<String, Value>) -> KResult<()> {
    let Some(v) = m.get("as_of").filter(|v| !v.is_null()) else { return Ok(()) };
    let n = v.as_u64().filter(|_| v.is_u64() || v.is_i64());
    let valid = n.is_some_and(|n| {
        let year = n / 10_000;
        let month = n / 100 % 100;
        let day = n % 100;
        let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 0,
        };
        (1..=9999).contains(&year) && day >= 1 && day <= days
    });
    if !valid {
        return Err(bad(
            "as_of",
            "as_of must be null or an integer encoding a valid Gregorian date YYYYMMDD",
            json!({"type": ["integer", "null"], "x-calendar": "YYYYMMDD"}),
        ));
    }
    Ok(())
}

/// Parse six strict record shapes without resolving a reference or changing any state.
pub(crate) fn parse(v: &Value) -> KResult<ParsedRecord> {
    let m = v.as_object().ok_or_else(|| KernelError::new(Code::BadJson, "a record must be a JSON object"))?;
    let k = str_field(m, "kind")?;
    let kind = RecordKind::parse(&k)
        .ok_or_else(|| bad("kind", "unknown record kind", json!({"enum": ["observe", "claim", "relation", "hypothesis", "question", "done"]})))?;
    let allowed: &[&str] = match kind {
        RecordKind::Observe => &["kind", "local_id", "doc_id", "exact_quote", "terms"],
        RecordKind::Claim => &["kind", "local_id", "text", "subject", "predicate", "object", "stance", "as_of", "based_on"],
        RecordKind::Relation => &["kind", "local_id", "from", "rel", "to", "based_on"],
        RecordKind::Hypothesis => &["kind", "local_id", "text", "falsifier", "subject", "stance", "based_on"],
        RecordKind::Question => &["kind", "local_id", "text", "about", "needed"],
        RecordKind::Done => &["kind", "local_id", "rq_id", "directive_id", "answer_ids", "outcome", "text"],
    };
    if let Some(field) = m.keys().find(|f| !allowed.contains(&f.as_str())) {
        return Err(bad(field, format!("unknown field '{field}' for {k}"), json!({"allowed_fields": allowed})));
    }
    let local_id = str_field(m, "local_id")?;
    let mut terms = Vec::new();
    let mut text = None;
    let mut stance = None;
    let mut based_on = Vec::new();
    let mut ends = None;
    match kind {
        RecordKind::Observe => {
            str_field(m, "doc_id")?;
            string(required(m, "exact_quote")?, "exact_quote", MAX_QUOTE, MAX_QUOTE)?;
            terms = strings(m, "terms", 0, false)?;
        }
        RecordKind::Claim => {
            text = Some(text_field(m, "text")?);
            terms.push(str_field(m, "subject")?);
            optional_str(m, "predicate")?;
            terms.extend(optional_str(m, "object")?);
            stance = Some(enum_field(m, "stance", &STANCES)?);
            check_date(m)?;
            based_on = strings(m, "based_on", 1, true)?;
        }
        RecordKind::Relation => {
            ends = Some((str_field(m, "from")?, enum_field(m, "rel", &SWARM_RELATIONS)?, str_field(m, "to")?));
            based_on = strings(m, "based_on", 1, true)?;
        }
        RecordKind::Hypothesis => {
            text = Some(text_field(m, "text")?);
            str_field(m, "falsifier")?;
            terms.extend(optional_str(m, "subject")?);
            stance = m.get("stance").map(|_| enum_field(m, "stance", &STANCES)).transpose()?;
            based_on = strings(m, "based_on", 1, true)?;
        }
        RecordKind::Question => {
            text = Some(text_field(m, "text")?);
            terms = strings(m, "about", 1, true)?;
            str_field(m, "needed")?;
        }
        RecordKind::Done => {
            str_field(m, "rq_id")?;
            str_field(m, "directive_id")?;
            strings(m, "answer_ids", 0, true)?;
            if m.contains_key("outcome") {
                enum_field(m, "outcome", &["answered", "unknown", "unresolved_conflict"])?;
            }
            text = m.get("text").map(|v| string(v, "text", MAX_STR, MAX_TEXT_CHARS)).transpose()?;
        }
    }
    let mut unique_terms = Vec::new();
    for term in terms {
        if !unique_terms.contains(&term) {
            unique_terms.push(term);
        }
    }
    Ok(ParsedRecord { kind, local_id, body: v.clone(), terms: unique_terms, text, stance, based_on, ends })
}

/// Machine-readable shapes. `x-maxUtf8Bytes` and `x-calendar` are kernel checks, not standard JSON Schema assertions.
pub fn schema() -> Value {
    serde_json::from_str(include_str!("schema.json")).expect("the embedded audit record schema is valid JSON")
}

/// Stable record identity after State has resolved references. Local naming is transport-only; provenance includes the
/// per-directive ordinal, not the global stream position. Inserting unrelated directives therefore does not rename a record.
pub fn record_id(content: &Value, author: &str, directive: &str, index: u64) -> RecordId {
    let mut body = content.clone();
    if let Some(m) = body.as_object_mut() {
        m.remove("local_id");
    }
    let envelope = json!(["r2r.audit.record.v1", author, directive, index, body]);
    RecordId(sha256(to_jcs(&envelope).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> Vec<Value> {
        vec![
            json!({"kind":"observe","local_id":"o1","doc_id":"r1","exact_quote":"A source.","terms":["component"]}),
            json!({"kind":"claim","local_id":"c1","text":"It is reported.","subject":"component","stance":"reported","as_of":20260228,"based_on":["o1"]}),
            json!({"kind":"relation","local_id":"r1","from":"c1","rel":"supports","to":"@0123456789abcdef","based_on":["o1"]}),
            json!({"kind":"hypothesis","local_id":"h1","text":"A possible explanation.","falsifier":"An opposite observation.","based_on":["o1"]}),
            json!({"kind":"question","local_id":"q1","text":"What changed?","about":["component"],"needed":"A dated source."}),
            json!({"kind":"done","local_id":"d1","rq_id":"RQ1","directive_id":"T1","answer_ids":["c1"],"outcome":"answered"}),
        ]
    }

    #[test]
    fn all_six_shapes_parse_without_rewriting_source_fields() {
        for v in examples() {
            let parsed = parse(&v).unwrap();
            assert_eq!(parsed.kind.name(), v["kind"].as_str().unwrap());
            assert_eq!(parsed.local_id, v["local_id"].as_str().unwrap());
            assert_eq!(parsed.body, v);
        }
        let h = parse(&examples()[3]).unwrap();
        assert!(h.stance.is_none() && h.terms.is_empty());
        let c = parse(&examples()[1]).unwrap();
        assert_eq!(c.terms, ["component"]);
        assert_eq!(c.stance.as_deref(), Some("reported"));
        assert_eq!(c.text.as_deref(), Some("It is reported."));
        assert_eq!(c.based_on, ["o1"]);
        assert_eq!(parse(&examples()[2]).unwrap().ends.unwrap().1, "supports");
    }

    #[test]
    fn claim_character_limit_counts_unicode_characters_not_utf8_bytes() {
        let mut v = examples()[1].clone();
        v["text"] = json!("🦀".repeat(240));
        assert!(parse(&v).is_ok());
        v["text"] = json!("🦀".repeat(241));
        assert_eq!(parse(&v).unwrap_err().field.as_deref(), Some("text"));
    }

    #[test]
    fn date_is_null_or_an_actual_calendar_integer() {
        let mut v = examples()[1].clone();
        for date in [Value::Null, json!(20000229), json!(20240229), json!(20261231)] {
            v["as_of"] = date;
            assert!(parse(&v).is_ok(), "{v}");
        }
        for date in [
            json!(true),
            json!(20260229),
            json!(19000229),
            json!(20260431),
            json!(20261301),
            json!(20260100),
            json!(-1),
            json!(0),
            json!(100000101u64),
            json!(20260101.0),
            json!("20260101"),
        ] {
            v["as_of"] = date;
            assert_eq!(parse(&v).unwrap_err().field.as_deref(), Some("as_of"), "{v}");
        }
    }

    #[test]
    fn rejects_unknown_missing_and_wrongly_typed_fields() {
        for mut v in examples() {
            v["server_seq"] = json!(1);
            assert_eq!(parse(&v).unwrap_err().field.as_deref(), Some("server_seq"));
            v.as_object_mut().unwrap().remove("server_seq");
            v.as_object_mut().unwrap().remove("local_id");
            assert_eq!(parse(&v).unwrap_err().code, Code::MissingField);
            v["local_id"] = json!("");
            assert!(parse(&v).is_err());
            v["local_id"] = json!(true);
            assert!(parse(&v).is_err());
        }
        assert_eq!(parse(&json!([])).unwrap_err().code, Code::BadJson);
        let mut v = examples()[1].clone();
        v["status"] = v["stance"].clone();
        assert!(parse(&v).is_err(), "the legacy status field is not an acceptance escape hatch");
        v.as_object_mut().unwrap().remove("status");
        v["stance"] = json!("accepted");
        assert!(parse(&v).is_err());
    }

    #[test]
    fn arrays_are_bounded_and_every_element_is_checked() {
        for (mut v, field) in
            [(examples()[0].clone(), "terms"), (examples()[1].clone(), "based_on"), (examples()[4].clone(), "about"), (examples()[5].clone(), "answer_ids")]
        {
            for invalid in [json!(false), json!(["valid", 1]), json!([null]), json!([""]), json!(vec!["x"; MAX_REFS + 1])] {
                v[field] = invalid;
                assert!(parse(&v).is_err(), "{v}");
            }
        }
        let mut v = examples()[1].clone();
        v["based_on"] = json!([]);
        assert!(parse(&v).is_err());
        let mut done = examples()[5].clone();
        done["answer_ids"] = json!([]);
        done["outcome"] = json!("unknown");
        assert!(parse(&done).is_ok(), "State checks whether an unknown completion has the required proof");
    }

    #[test]
    fn strings_obey_utf8_byte_bounds_and_builder_relations_are_not_swarm_records() {
        let mut v = examples()[0].clone();
        v["exact_quote"] = json!("x".repeat(MAX_QUOTE));
        assert!(parse(&v).is_ok());
        v["exact_quote"] = json!("\u{44f}".repeat(MAX_QUOTE / 2 + 1));
        assert!(parse(&v).is_err());
        v["exact_quote"] = json!("A source.");
        v["doc_id"] = json!("\u{44f}".repeat(MAX_STR / 2 + 1));
        assert!(parse(&v).is_err());
        let mut relation = examples()[2].clone();
        for rel in ["same_as", "duplicate_of", "causes"] {
            relation["rel"] = json!(rel);
            assert!(parse(&relation).is_err());
        }
    }

    #[test]
    fn record_identity_ignores_local_renaming_and_json_key_order_but_keeps_provenance() {
        let a: Value = serde_json::from_str(r#"{"kind":"claim","local_id":"a","based_on":["@resolved"],"text":"x"}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"text":"x","based_on":["@resolved"],"local_id":"b","kind":"claim"}"#).unwrap();
        let id = record_id(&a, "agent", "T1", 2);
        assert_eq!(id, record_id(&b, "agent", "T1", 2));
        assert_ne!(id, record_id(&a, "agent", "T1", 3));
        assert_ne!(id, record_id(&a, "other", "T1", 2));
        assert_ne!(id, record_id(&a, "agent", "T2", 2));
        assert_ne!(record_id(&a, "ab", "c", 2), record_id(&a, "a", "bc", 2), "the envelope frames adjacent provenance fields");
    }

    #[test]
    fn embedded_schema_has_six_closed_shapes_and_documents_kernel_constraints() {
        let schema = schema();
        let shapes = schema["oneOf"].as_array().unwrap();
        assert_eq!(shapes.len(), 6);
        for v in examples() {
            let shape = shapes.iter().find(|s| s["properties"]["kind"]["const"] == v["kind"]).unwrap();
            assert_eq!(shape["additionalProperties"], false);
            for required in shape["required"].as_array().unwrap() {
                assert!(v.get(required.as_str().unwrap()).is_some());
            }
            assert!(v.as_object().unwrap().keys().all(|k| shape["properties"].get(k).is_some()));
        }
        assert_eq!(schema["$defs"]["string"]["x-maxUtf8Bytes"], MAX_STR);
        assert_eq!(schema["$defs"]["quote"]["x-maxUtf8Bytes"], MAX_QUOTE);
        assert_eq!(schema["$defs"]["date"]["x-calendar"], "YYYYMMDD");
    }
}
