//! Entity & alias registry, predicate signatures and Horn rules (AND / OR).
//!
//! The ontology is plain JSON data, not a DSL:
//!
//! ```json
//! {"entities":[{"id":"svc_auth","type":"Service","aliases":["auth"]}],
//!  "predicates":[{"id":"uses_api","subject":"Service","object":"Api"},
//!                {"id":"needs_review","subject":"Service","object":"@literal","allowed_values":["true"]}],
//!  "rules":[{"id":"R_depr_review@1","mode":"AND",
//!            "body":[{"p":"uses_api"},{"p":"api_deprecated"}],
//!            "join":[["0.o","1.s"]],
//!            "head":{"s":"0.s","p":"needs_review","o":{"const":"true"}}}]}
//! ```

use crate::hash::{sha256, Hash};
use crate::jcs::to_jcs;
use crate::node::Polarity;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    pub id: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjType {
    Entity(String),
    Literal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    pub id: String,
    pub subject: String,
    pub object: ObjType,
    /// `@literal` objects only: when set, the only literals the kernel accepts (`"allowed_values": [...]`). Absent = any literal,
    /// and the ontology JSON (so its hash) is unchanged.
    pub allowed_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    S,
    O,
}

impl Field {
    pub fn as_str(self) -> &'static str {
        match self {
            Field::S => "s",
            Field::O => "o",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Ref(usize, Field),
    Const(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyAtom {
    pub p: String,
    pub pol: Polarity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub s: Term,
    pub p: String,
    pub o: Term,
    pub pol: Polarity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub mode: Mode,
    pub body: Vec<BodyAtom>,
    pub join: Vec<((usize, Field), (usize, Field))>,
    pub head: Head,
}

#[derive(Debug, Clone)]
pub enum ResolveErr {
    Unknown { suggestions: Vec<String> },
    Ambiguous { candidates: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct Ontology {
    pub entities: BTreeMap<String, Entity>,
    names: HashMap<String, Vec<String>>,
    pub predicates: BTreeMap<String, Predicate>,
    pub rules: BTreeMap<String, Rule>,
    pub canonical_json: String,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyError(pub String);

impl std::fmt::Display for OntologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ontology error: {}", self.0)
    }
}

impl std::error::Error for OntologyError {}

fn oe<T>(msg: impl Into<String>) -> Result<T, OntologyError> {
    Err(OntologyError(msg.into()))
}

fn str_field<'a>(v: &'a Value, k: &str, ctx: &str) -> Result<&'a str, OntologyError> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| OntologyError(format!("{ctx}: missing string field '{k}'")))
}

fn parse_ref(s: &str, nbody: usize) -> Result<(usize, Field), OntologyError> {
    let (i, f) = s.split_once('.').ok_or_else(|| OntologyError(format!("bad field reference '{s}'")))?;
    let idx: usize = i.parse().map_err(|_| OntologyError(format!("bad premise index in '{s}'")))?;
    if idx >= nbody {
        return oe(format!("premise index out of range in '{s}'"));
    }
    let f = match f {
        "s" => Field::S,
        "o" => Field::O,
        _ => return oe(format!("bad field in reference '{s}'")),
    };
    Ok((idx, f))
}

fn parse_term(v: &Value, nbody: usize) -> Result<Term, OntologyError> {
    if let Some(s) = v.as_str() {
        let (i, f) = parse_ref(s, nbody)?;
        return Ok(Term::Ref(i, f));
    }
    if let Some(c) = v.get("const").and_then(|c| c.as_str()) {
        return Ok(Term::Const(c.to_string()));
    }
    oe("head term must be \"i.s\"/\"i.o\" or {\"const\": ...}")
}

impl Ontology {
    pub fn from_json_str(text: &str) -> Result<Ontology, OntologyError> {
        let v: Value = serde_json::from_str(text).map_err(|e| OntologyError(format!("invalid JSON: {e}")))?;
        Ontology::from_value(&v)
    }

    pub fn from_value(v: &Value) -> Result<Ontology, OntologyError> {
        // Every name ends up in a u16-length-prefixed canonical field.
        fn check_names(v: &Value, depth: usize) -> Result<(), OntologyError> {
            match v {
                Value::String(s) if s.len() > 1024 => oe("ontology strings are limited to 1024 bytes"),
                Value::Array(a) if depth < 8 => a.iter().try_for_each(|x| check_names(x, depth + 1)),
                Value::Object(m) if depth < 8 => m.values().try_for_each(|x| check_names(x, depth + 1)),
                _ => Ok(()),
            }
        }
        check_names(v, 0)?;
        let canonical_json = to_jcs(v);
        let hash = sha256(canonical_json.as_bytes());

        let mut entities = BTreeMap::new();
        let mut names: HashMap<String, Vec<String>> = HashMap::new();
        for e in v.get("entities").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let id = str_field(e, "id", "entity")?.to_string();
            let ty = str_field(e, "type", "entity")?.to_string();
            if entities.insert(id.clone(), Entity { id: id.clone(), ty }).is_some() {
                return oe(format!("duplicate entity '{id}'"));
            }
            let mut all = vec![id.clone()];
            for a in e.get("aliases").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
                if let Some(s) = a.as_str() {
                    all.push(s.trim().to_string());
                }
            }
            all.sort();
            all.dedup();
            for n in all {
                let slot = names.entry(n).or_default();
                if !slot.contains(&id) {
                    slot.push(id.clone());
                }
            }
        }
        for slot in names.values_mut() {
            slot.sort();
        }

        let mut predicates = BTreeMap::new();
        for p in v.get("predicates").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let id = str_field(p, "id", "predicate")?.to_string();
            let subject = str_field(p, "subject", "predicate")?.to_string();
            let obj = str_field(p, "object", "predicate")?;
            let object = if obj == "@literal" { ObjType::Literal } else { ObjType::Entity(obj.to_string()) };
            let allowed_values = match p.get("allowed_values") {
                None => None,
                Some(_) if object != ObjType::Literal => return oe(format!("predicate '{id}': allowed_values needs an @literal object")),
                Some(Value::Array(a)) if !a.is_empty() => {
                    let mut vals = Vec::with_capacity(a.len());
                    for x in a {
                        match x.as_str() {
                            Some(s) if !s.is_empty() => vals.push(s.to_string()),
                            _ => return oe(format!("predicate '{id}': allowed_values must be non-empty strings")),
                        }
                    }
                    Some(vals)
                }
                Some(_) => return oe(format!("predicate '{id}': allowed_values must be a non-empty array of strings")),
            };
            if predicates.insert(id.clone(), Predicate { id: id.clone(), subject, object, allowed_values }).is_some() {
                return oe(format!("duplicate predicate '{id}'"));
            }
        }

        let mut ont = Ontology { entities, names, predicates, rules: BTreeMap::new(), canonical_json, hash };

        let mut rules = BTreeMap::new();
        for r in v.get("rules").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let rule = ont.parse_rule(r)?;
            if rules.insert(rule.id.clone(), rule.clone()).is_some() {
                return oe(format!("duplicate rule '{}'", rule.id));
            }
        }
        ont.rules = rules;
        Ok(ont)
    }

    fn parse_rule(&self, r: &Value) -> Result<Rule, OntologyError> {
        let id = str_field(r, "id", "rule")?.to_string();
        let mode = match r.get("mode").and_then(|m| m.as_str()).unwrap_or("AND") {
            "AND" => Mode::And,
            "OR" => Mode::Or,
            m => return oe(format!("rule {id}: unknown mode '{m}'")),
        };
        let body_v = r.get("body").and_then(|b| b.as_array()).ok_or_else(|| OntologyError(format!("rule {id}: missing body")))?;
        if body_v.is_empty() || body_v.len() > 6 {
            return oe(format!("rule {id}: body must have 1..=6 atoms"));
        }
        let mut body = Vec::new();
        for b in body_v {
            let p = str_field(b, "p", &id)?.to_string();
            if !self.predicates.contains_key(&p) {
                return oe(format!("rule {id}: unknown body predicate '{p}'"));
            }
            let pol = match b.get("pol").and_then(|x| x.as_str()) {
                None => Polarity::Pos,
                Some(s) => Polarity::parse(s).ok_or_else(|| OntologyError(format!("rule {id}: bad polarity")))?,
            };
            body.push(BodyAtom { p, pol });
        }
        let nref = if mode == Mode::Or { 1 } else { body.len() };
        let mut join = Vec::new();
        for j in r.get("join").and_then(|j| j.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let pair = j.as_array().filter(|a| a.len() == 2).ok_or_else(|| OntologyError(format!("rule {id}: join entries are pairs")))?;
            let a = parse_ref(pair[0].as_str().unwrap_or(""), nref)?;
            let b = parse_ref(pair[1].as_str().unwrap_or(""), nref)?;
            join.push((a, b));
        }
        let h = r.get("head").ok_or_else(|| OntologyError(format!("rule {id}: missing head")))?;
        let hp = str_field(h, "p", &id)?.to_string();
        let hpred = self.predicates.get(&hp).ok_or_else(|| OntologyError(format!("rule {id}: unknown head predicate '{hp}'")))?;
        let hpol = match h.get("pol").and_then(|x| x.as_str()) {
            None => Polarity::Pos,
            Some(s) => Polarity::parse(s).ok_or_else(|| OntologyError(format!("rule {id}: bad head polarity")))?,
        };
        let hs = parse_term(h.get("s").ok_or_else(|| OntologyError(format!("rule {id}: head.s missing")))?, nref)?;
        let ho = parse_term(h.get("o").ok_or_else(|| OntologyError(format!("rule {id}: head.o missing")))?, nref)?;
        let rule = Rule { id: id.clone(), mode, body, join, head: Head { s: hs, p: hp, o: ho, pol: hpol } };

        // Type-check head terms and joins.
        let ty_of = |t: &Term, want_subject: bool| -> Result<Option<ObjType>, OntologyError> {
            match t {
                Term::Const(_) => Ok(None),
                Term::Ref(i, f) => {
                    let tys: Vec<ObjType> = if rule.mode == Mode::Or {
                        rule.body.iter().map(|a| self.field_type(&a.p, *f)).collect()
                    } else {
                        vec![self.field_type(&rule.body[*i].p, *f)]
                    };
                    if tys.windows(2).any(|w| w[0] != w[1]) {
                        return oe(format!("rule {id}: OR alternatives disagree on the type of '{}'", f.as_str()));
                    }
                    let _ = want_subject;
                    Ok(Some(tys[0].clone()))
                }
            }
        };
        if let Some(t) = ty_of(&rule.head.s, true)? {
            if t != ObjType::Entity(hpred.subject.clone()) {
                return oe(format!("rule {id}: head subject type mismatch"));
            }
        }
        if let Some(t) = ty_of(&rule.head.o, false)? {
            if t != hpred.object {
                return oe(format!("rule {id}: head object type mismatch"));
            }
        }
        if let Term::Const(c) = &rule.head.s {
            match self.entities.get(c) {
                Some(e) if e.ty == hpred.subject => {}
                _ => return oe(format!("rule {id}: head subject constant '{c}' is not a {} entity", hpred.subject)),
            }
        }
        if let (Term::Const(c), ObjType::Entity(t)) = (&rule.head.o, &hpred.object) {
            match self.entities.get(c) {
                Some(e) if &e.ty == t => {}
                _ => return oe(format!("rule {id}: head object constant '{c}' is not a {t} entity")),
            }
        }
        if let (Term::Const(c), Some(vals)) = (&rule.head.o, &hpred.allowed_values) {
            if !vals.contains(c) {
                return oe(format!("rule {id}: head object constant '{c}' is not one of the allowed values of '{}'", hpred.id));
            }
        }
        if rule.mode == Mode::And {
            for ((ai, af), (bi, bf)) in &rule.join {
                if self.field_type(&rule.body[*ai].p, *af) != self.field_type(&rule.body[*bi].p, *bf) {
                    return oe(format!("rule {id}: join between incompatible types"));
                }
            }
        }
        Ok(rule)
    }

    /// Declared type of the `s` or `o` slot of predicate `p`.
    pub fn field_type(&self, p: &str, f: Field) -> ObjType {
        let pr = &self.predicates[p];
        match f {
            Field::S => ObjType::Entity(pr.subject.clone()),
            Field::O => pr.object.clone(),
        }
    }

    pub fn resolve_entity(&self, name: &str) -> Result<&Entity, ResolveErr> {
        let key = name.trim();
        match self.names.get(key) {
            Some(ids) if ids.len() == 1 => Ok(&self.entities[&ids[0]]),
            Some(ids) => Err(ResolveErr::Ambiguous { candidates: ids.clone() }),
            None => {
                let lower = key.to_lowercase();
                let mut sugg: Vec<String> = self
                    .names
                    .iter()
                    .filter(|(n, _)| {
                        let nl = n.to_lowercase();
                        !lower.is_empty() && (nl.contains(&lower) || lower.contains(&nl))
                    })
                    .flat_map(|(_, ids)| ids.iter().cloned())
                    .collect();
                sugg.sort();
                sugg.dedup();
                sugg.truncate(5);
                Err(ResolveErr::Unknown { suggestions: sugg })
            }
        }
    }

    pub fn entity_names(&self) -> impl Iterator<Item = &String> {
        self.names.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> Ontology {
        Ontology::from_json_str(
            r#"{
            "entities":[
              {"id":"svc_auth","type":"Service","aliases":["auth","gateway"]},
              {"id":"svc_pay","type":"Service","aliases":["payments","gateway"]},
              {"id":"api_v1","type":"Api","aliases":["v1"]}],
            "predicates":[
              {"id":"uses_api","subject":"Service","object":"Api"},
              {"id":"api_deprecated","subject":"Api","object":"@literal"},
              {"id":"needs_review","subject":"Service","object":"@literal"}],
            "rules":[{"id":"R_depr_review@1","mode":"AND",
              "body":[{"p":"uses_api"},{"p":"api_deprecated"}],
              "join":[["0.o","1.s"]],
              "head":{"s":"0.s","p":"needs_review","o":{"const":"true"}}}]
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn alias_resolution() {
        let o = sample();
        assert_eq!(o.resolve_entity("auth").unwrap().id, "svc_auth");
        assert_eq!(o.resolve_entity("svc_pay").unwrap().id, "svc_pay");
        match o.resolve_entity("gateway") {
            Err(ResolveErr::Ambiguous { candidates }) => assert_eq!(candidates, vec!["svc_auth", "svc_pay"]),
            _ => panic!("expected ambiguity"),
        }
        assert!(matches!(o.resolve_entity("nope"), Err(ResolveErr::Unknown { .. })));
    }

    #[test]
    fn rule_type_errors_are_rejected() {
        let bad = r#"{"entities":[],"predicates":[
            {"id":"a","subject":"X","object":"Y"},{"id":"b","subject":"Z","object":"@literal"}],
            "rules":[{"id":"R","body":[{"p":"a"}],"head":{"s":"0.s","p":"b","o":{"const":"1"}}}]}"#;
        assert!(Ontology::from_json_str(bad).is_err());
    }

    #[test]
    fn allowed_values_are_checked_when_the_ontology_loads() {
        let onto = |pred: &str, head_o: &str| {
            format!(
                r#"{{"entities":[],"predicates":[{{"id":"a","subject":"X","object":"Y"}},{pred}],
                    "rules":[{{"id":"R","body":[{{"p":"a"}}],"head":{{"s":"0.s","p":"b","o":{head_o}}}}}]}}"#
            )
        };
        let ok = Ontology::from_json_str(&onto(r#"{"id":"b","subject":"X","object":"@literal","allowed_values":["true"]}"#, r#"{"const":"true"}"#)).unwrap();
        assert_eq!(ok.predicates["b"].allowed_values, Some(vec!["true".to_string()]));
        assert_eq!(ok.predicates["a"].allowed_values, None);
        for (pred, why) in [
            (r#"{"id":"b","subject":"X","object":"Y","allowed_values":["true"]}"#, "needs an @literal object"),
            (r#"{"id":"b","subject":"X","object":"@literal","allowed_values":[]}"#, "non-empty array"),
            (r#"{"id":"b","subject":"X","object":"@literal","allowed_values":[""]}"#, "non-empty strings"),
            (r#"{"id":"b","subject":"X","object":"@literal","allowed_values":"true"}"#, "non-empty array"),
            (r#"{"id":"b","subject":"X","object":"@literal","allowed_values":["false"]}"#, "not one of the allowed values"),
        ] {
            let e = Ontology::from_json_str(&onto(pred, r#"{"const":"true"}"#)).unwrap_err();
            assert!(e.0.contains(why), "{pred}: {}", e.0);
        }
    }

    #[test]
    fn hash_ignores_formatting() {
        let a = Ontology::from_json_str(r#"{"entities":[],"predicates":[]}"#).unwrap();
        let b = Ontology::from_json_str("{ \"predicates\" : [ ], \"entities\":[] }").unwrap();
        assert_eq!(a.hash, b.hash);
    }
}
