//! The graph builder's side of the audit layer (contract v0 §4): cards in, proposals out.
//!
//! The builder is one agent on a weak model inside the hidden contour. It never reads `bytes[]`: the kernel cuts a card from the
//! records it has not seen yet (cursor), adds the concepts whose names match their terms (deterministic lookup) and the records
//! already mapped to those concepts (neighbours, for duplicates and conflicts). The builder answers with operations; the kernel
//! checks each one (fail-fast, one-step repair), stores mappings and concepts, and stores every link as `Proposed`. Only a targeted
//! `VERIFY_LINK` directive or the owner makes a link `Accepted` (contract v0.1 R6: not even an identical-text duplicate).

use super::*;
use crate::error::Code;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub mod parallel;
pub(crate) fn review_exclusions(card: &Card) -> Vec<String> {
    ontology_review::exclusions(card)
}
mod ontology_review;
mod revisions;

pub const BUILDER_OPS: [&str; 5] = ["map_term", "propose_concept", "link", "mark_duplicate", "flag_conflict"];
/// The operations of a record card when links are off (`max_links` 0).
pub const CONCEPT_OPS: [&str; 2] = ["map_term", "propose_concept"];
/// Relations the builder may propose with `link` (`duplicate_of` and `contradicts` also come from their own ops).
pub const LINK_RELATIONS: [&str; 6] = ["supports", "contradicts", "qualifies", "supersedes", "depends_on", "same_as"];
/// When the quotes prove a relation: one text for the builder that proposes a link and the agent that checks it (live run 10A-5:
/// the checks rejected 46 of 55 proposed links, 30 of 32 qualifies, mostly as two facts stated side by side).
pub const LINK_CRITERIA: &str = "qualifies needs a quote that one record limits, conditions or scopes the other (across reports: that \
    the one report's rule applies to the other's scope); supports needs a quote that gives the other's reason or evidence; depends_on \
    needs a quote that one holds only because the other does; supersedes runs from a newer conclusion to the older conclusion it \
    replaces, never to its own quote; same_as needs the same meaning about the same subject; contradicts needs that both cannot hold. \
    Two facts stated side by side (in one report, section or episode) are no relation.";
/// The address layer (owner and Gemini, 01.11.2026; offline the same rule put both sides of 14 to 15 of 22 read version changes under
/// one function, where 5 shared a concept). The example comes from an unrelated domain, so that no term of a corpus is suggested.
/// The function is optional (Fable 5.1's consultation of 01.11: a forced choice breeds catch-all functions).
pub const FUNCTION_RULE: &str = "FUNCTIONS: in this run a propose_concept also names \"function\":\"<name>\", the broad part of the \
    system the concept belongs to, when the concept clearly belongs to one; leave it out when unsure. A function is one mechanism, \
    subsystem, transport, message family or procedure, under which several concepts sit \
    as its parts, fields, options, rules or changes. Reuse a function of known_functions whenever the concept is a part, rule, option, \
    field or change of it, and place a sub-procedure under the broad subsystem it serves. Name a new function only for a separate \
    subsystem: a short noun of 1-4 words, never a statement, a version, a date, a document name or one word for everything. A concept \
    that is itself a broad part of the system may get a function of its own name. Example from an unrelated domain (a car manual): \
    \"ABS sensor\", \"brake pad wear limit\", \"brake fluid replaced every 2 years\" and \"brake bleeding procedure\" all go under \
    \"braking system\"; \"cabin air filter\" goes under \"ventilation\". known_functions lists the functions in use, the most used \
    first. A function is an address, not an identity: concepts of one function are different things, and a shared function proves \
    no relation between records.";

#[derive(Debug, Clone, Copy)]
pub struct BuilderConfig {
    pub max_records: usize,
    pub max_candidates: usize,
    pub max_neighbors: usize,
    pub max_ops: usize,
    /// Links (`link`, `mark_duplicate`, `flag_conflict`) a card may add: each one costs a verification task of the swarm. 0 turns
    /// links off (the build scope `concepts`, the owner's control run of 2026-10-30): record cards only name concepts and map
    /// terms, there are no pair cards, and a link operation is refused.
    pub max_links: usize,
    /// Keep each record card within one author's consecutive run (dynamic roles only).
    pub author_runs: bool,
}

impl Default for BuilderConfig {
    fn default() -> BuilderConfig {
        // 64 operations: eight records with several terms each needed more than 32 in live run 10A-3
        // 8 links: live run 10A-4 cards proposed up to 65 links among eight records, and their checks took 892 of 1198 calls
        BuilderConfig { max_records: 8, max_candidates: 4, max_neighbors: 8, max_ops: 64, max_links: 8, author_runs: false }
    }
}

#[derive(Debug, Clone)]
pub struct Card {
    pub card_id: String,
    pub cursor_from: u64,
    pub cursor_to: u64,
    pub records: Vec<RecordView>,
    /// term -> matching concepts
    pub candidates: BTreeMap<String, Vec<ConceptView>>,
    pub neighbors: Vec<RecordView>,
    pub concept_types: Vec<String>,
    pub max_ops: usize,
    pub max_links: usize,
    /// A pair card carries report metadata and its two assertions; it does not advance the ordinary ingestion cursor.
    pub pair: Option<Value>,
    pub ontology: Option<Value>,
    pub review: Option<String>,
    /// With the address layer on (owner and Gemini, 01.11.2026): the known functions, each with examples of its concepts. Every
    /// propose_concept of this card then names the function its concept belongs to.
    pub functions: Option<Vec<(String, usize, Vec<String>)>>,
}

fn record_json(r: &RecordView) -> Value {
    let mut v = json!({"id": r.id.short(), "kind": r.kind.name(), "author": r.author, "text": r.text, "quote": r.quote, "doc_id": r.doc_id,
           "terms": r.terms, "stance": r.status,
           "based_on": r.based_on.iter().map(|b| b.short()).collect::<Vec<_>>(),
           "ends": r.ends.as_ref().map(|(f, rel, t)| json!([f.short(), rel, t.short()]))});
    // what the agent stated in its own fields (Codex review c78060e, F10): the date is the agent's as_of, not a verified one
    for k in ["subject", "predicate", "object", "as_of", "falsifier", "needed"] {
        if let Some(x) = r.body.get(k).filter(|x| !x.is_null()) {
            v[k] = x.clone();
        }
    }
    v
}

impl Card {
    pub fn to_json(&self) -> Value {
        let cands: BTreeMap<&String, Vec<Value>> = self
            .candidates
            .iter()
            .map(|(t, cs)| {
                (t, cs.iter().map(|c| json!({"id": c.id.short(), "type": c.ty, "name": c.name, "aliases": c.aliases, "status": c.status})).collect())
            })
            .collect();
        let mut out = json!({"status": "CARD", "card_id": self.card_id, "cursor_from": self.cursor_from, "cursor_to": self.cursor_to,
               "kind": if super::quality::evolution::is_card(self) {"EVOLUTION_LINK_CARD"} else if ontology_review::task(self).is_some() {"ONTOLOGY_REVIEW_CARD"} else if self.review.is_some() { "REVISION_CARD" } else if self.pair.is_some() { "PAIR_CARD" } else { "RECORD_CARD" }, "pair_metadata": self.pair,
               "records": self.records.iter().map(record_json).collect::<Vec<_>>(), "candidates": cands,
               "neighbors": self.neighbors.iter().map(record_json).collect::<Vec<_>>(), "concept_types": self.concept_types,
               "allowed_ops": if self.pair.is_some() { vec!["link","mark_duplicate","flag_conflict"] } else if self.max_links == 0 { CONCEPT_OPS.to_vec() } else { BUILDER_OPS.to_vec() },
               "link_relations": if self.max_links == 0 { &[][..] } else { &LINK_RELATIONS[..] }, "max_ops": self.max_ops, "max_links": self.max_links, "prompt": self.prompt()});
        if super::quality::evolution::is_card(self) {
            // a pair found through a shared function shows no channel: the function selects candidates, it is no evidence, and the
            // agent must not read it as one (Fable 5.1's consultation of 01.11); the frozen plan in the journal keeps the channel
            for row in out["pair_metadata"]["metadata"]["pairs"].as_array_mut().into_iter().flatten() {
                if row["channel"] == "function" {
                    if let Some(o) = row.as_object_mut() {
                        o.remove("channel");
                        o.remove("similarity_per_mille");
                    }
                }
            }
            out["allowed_ops"] = json!(["link", "none"]);
            out["link_relations"] = json!(["supersedes", "qualifies", "contradicts", "same_as"]);
        }
        if let Some(ontology) = &self.ontology {
            out["ontology_revision"] = ontology.clone();
            out["allowed_ops"].as_array_mut().expect("ops array").push(json!("revise_concept"));
            out["prompt"] = json!(format!("{}\n{}", self.prompt(), revisions::PROMPT));
            if ontology_review::task(self).is_some() {
                out["prompt"] = json!(format!("{}\n{}", out["prompt"].as_str().unwrap_or(""), ontology_review::DECISION_RULE));
            }
        }
        if let Some(functions) = &self.functions {
            out["known_functions"] = json!(functions.iter().map(|(f, n, e)| json!({"function": f, "concepts": n, "examples": e})).collect::<Vec<_>>());
            out["prompt"] = json!(format!("{}\n{}", out["prompt"].as_str().unwrap_or(""), FUNCTION_RULE));
        }
        if let Some(proposal) = &self.review {
            out["review_proposal"] = json!(proposal);
            out["allowed_ops"] = if ontology_review::task(self).is_some() { json!(["keep", "revise_concept"]) } else { json!(["revise_concept"]) };
        }
        out
    }

    /// The short instruction for the weak model (the card itself carries the data).
    pub fn prompt(&self) -> String {
        if ontology_review::task(self).is_some() {
            return "ONTOLOGY_REVIEW_CARD: decide the single marked concept. Submit {\"op\":\"keep\",\"concept\":\"@shown concept\",\"basis\":[\"@shown grounded record\"],\"reason\":\"...\"}, or propose revise_concept for that concept. [] cannot close the task. Keep retains its current status, never promotes a provisional concept to truth. Unmapped is not proof of absence; keep provisional when evidence is insufficient.".into();
        }
        if self.review.is_some() {
            return "REVISION_CARD: explicitly confirm or reject the shown pending proposal using shown grounded records. Only revise_concept is allowed. [] does not close an unresolved review.".to_string();
        }
        if super::quality::evolution::is_card(self) {
            return "EVOLUTION_LINK_CARD: decide EVERY listed pair explicitly. For a justified relation submit {\"op\":\"link\",\"from\":\"@claim\",\"rel\":\"supersedes|qualifies|contradicts|same_as\",\"to\":\"@claim\",\"basis\":[\"@observe from each end\"]}; otherwise {\"op\":\"none\",\"pair\":\"E...\",\"reason\":\"why no relation is proved\"}. supersedes runs NEW to OLD. Shared concepts (including provisional) select candidates only, never prove identity, same scope, or a relation. Compare both quotes, report dates, subjects, versions and scope. A later state supersedes an earlier one only for the same thing and scope; it need not name the earlier report. qualifies requires an actual boundary applying to the other claim; same_as requires the same fact. Do not link merely related topics. Every link needs a shown grounded Observe from EACH endpoint cone. A separate nonauthor verifies proposals. [] leaves undecided pairs open. Write one JSON object per line, with no array, prose or code fence; a none reason is at most 240 characters.".into();
        }
        if self.pair.is_some() {
            return format!(
                "PAIR_CARD: compare the OLD and NEW assertions in records, their exact Observe cone in neighbors, and \
                report metadata. Metadata and shared tokens are retrieval signals, not evidence of a semantic relation. Propose \
                only a link/mark_duplicate/flag_conflict between these two assertions, using basis ids shown. Otherwise answer []. \
                Supersedes runs NEW -> OLD. At most {} operations and {} links. {}",
                self.max_ops, self.max_links, LINK_CRITERIA
            );
        }
        if self.max_links == 0 {
            // links off: the concept part of the record card below, without links, duplicates and conflicts
            return format!(
                "You are the concept builder of an audit swarm. You do not judge the audit; you name what the agents wrote.\n\
                 For the NEW records of this card (and only for them) write JSON operations, one per line, at most {}. The card's \
                 records are the new ones: map_term names one of them. Its neighbors are earlier records shown for context; their \
                 terms are never mapped here. Links between records are off in this run: write no link, mark_duplicate or \
                 flag_conflict.\n\
                 - {{\"op\":\"map_term\",\"record\":\"@id\",\"term\":\"<a term of that record>\",\"concept\":\"@concept id or the name of a concept you propose in this batch\"}}\n\
                 - {{\"op\":\"propose_concept\",\"type\":\"<one of: {}>\",\"name\":\"<the thing itself in 1-4 words: a term, feature or mechanism; no verb, no must/should/may - the rule goes into claims>\",\"aliases\":[...],\"basis\":[\"@observe record\"]}} only when no candidate fits; its basis are observe records (quotes) only, never a question, hypothesis or claim\n\
                 Write propose_concept before map_term. Use only the ids shown in this card. map_term names a candidate @id shown \
                 above or a concept proposed for this card: earlier in this answer (write its propose_concept line first) or accepted \
                 from an earlier answer, by its exact name; never map to a name that is neither. Map a term only to a concept of the \
                 same thing in the same scope (the same commit, version, report or subsystem): a term that no candidate names exactly \
                 stays unmapped, or gets a concept you propose; a near name is not the same thing. \
                 Before each map_term, resolve its concept: copy a shown candidate @id, or use a concept already accepted for this card. \
                 If no scoped concept fits and the shown observes ground one, write propose_concept FIRST, then map_term using its exact \
                 name in the SAME submission. A term string does not create a concept. On an UNKNOWN_ENTITY repair, add the needed \
                 propose_concept before the refused map_term, or select a shown candidate; leave the term unmapped if unsupported. \
                 Consider grounded concept operations before deliberately answering []. Write nothing else.",
                self.max_ops,
                self.concept_types.join(", ")
            );
        }
        format!(
            "You are the graph builder of an audit swarm. You do not judge the audit; you connect what the agents wrote.\n\
             For the NEW records of this card (and only for them) write JSON operations, one per line, at most {} (of them at most {} \
             link, mark_duplicate and flag_conflict lines). The card's records are the new ones: map_term names one of them, and every \
             link, duplicate or conflict has one of them as an end. Its neighbors are earlier records shown for context: one may be the \
             other end of a link, but their terms are never mapped here.\n\
             - {{\"op\":\"map_term\",\"record\":\"@id\",\"term\":\"<a term of that record>\",\"concept\":\"@concept id or the name of a concept you propose in this batch\"}}\n\
             - {{\"op\":\"propose_concept\",\"type\":\"<one of: {}>\",\"name\":\"<the thing itself in 1-4 words: a term, feature or mechanism; no verb, no must/should/may - the rule goes into claims>\",\"aliases\":[...],\"basis\":[\"@observe record\"]}} only when no candidate fits; its basis are observe records (quotes) only, never a question, hypothesis or claim\n\
             - {{\"op\":\"link\",\"from\":\"@id\",\"rel\":\"<one of: {}>\",\"to\":\"@id\",\"basis\":[\"@record\"]}}\n\
             - {{\"op\":\"mark_duplicate\",\"record\":\"@new\",\"of\":\"@earlier\"}} when a new record says what an earlier one already says\n\
             - {{\"op\":\"flag_conflict\",\"a\":\"@id\",\"b\":\"@id\",\"basis\":[\"@record\"]}} when two records cannot both hold\n\
             A link, a duplicate or a conflict connects two claims, hypotheses or relations, never an observe: a quote is evidence and goes \
             in basis. Link records only where it matters for the audit (a later decision, a qualification, a contradiction, a \
             dependency across sections or reports) and the basis quotes prove the relation: {} A separate check rejects any \
             other link, at a cost. \
             Write them in this order: first link, mark_duplicate and flag_conflict, then propose_concept, then map_term. \
             Use only the ids shown in this card. map_term names a candidate @id shown above or a concept proposed for this card: earlier \
             in this answer (write its propose_concept line first) or accepted from an earlier answer, by its exact name; never map to \
             a name that is neither. Map a term only to a concept of the same thing in the same scope (the same commit, version, report \
             or subsystem): a term that no candidate names exactly stays unmapped, or gets a concept you propose; a near name is not \
             the same thing. \
             Concept mapping and links are independent: no justified link does not prevent grounded concept operations. \
             Before each map_term, resolve its concept: copy a shown candidate @id, or use a concept already accepted for this card. \
             If no scoped concept fits and the shown observes ground one, write propose_concept FIRST, then map_term using its exact \
             name in the SAME submission. A term string does not create a concept. On an UNKNOWN_ENTITY repair, add the needed \
             propose_concept before the refused map_term, or select a shown candidate; leave the term unmapped if unsupported. \
             Consider both grounded concept operations and links before deliberately answering []. \
             Links are proposals: a separate check confirms them. Write nothing else.",
            self.max_ops,
            self.max_links,
            self.concept_types.join(", "),
            LINK_RELATIONS.join(", "),
            LINK_CRITERIA
        )
    }
}

fn bad(code: Code, msg: impl Into<String>, field: &str) -> KernelError {
    KernelError::new(code, msg).field(field)
}

#[derive(Debug, Default)]
pub struct Builder {
    pub cfg: BuilderConfig,
    /// Circles +1: the refiner cards records only; the swarm's revision reviews and pair cards are not its work.
    pub records_only: bool,
    cursor: u64,
    /// Only pooled workers use a fixed range and their own durable close marker.
    cut_to: Option<u64>,
    close_scope: Option<(String, Value)>,
    open: Option<Card>,
    /// Operations of the open card already committed. The store id of an operation is `<card>:<n>:<attempt>`, the attempt read
    /// from the durable receipts: an exact retry finds its receipt, a repaired payload is a new submission (also after a restart).
    done_ops: usize,
    /// Concepts proposed for the open card, by normalized name (a later `map_term` of the card may name them).
    proposed: BTreeMap<String, ConceptId>,
    /// The last answer for the open card and the digest of its request: an exact retry gets it again, with no side effect.
    last: Option<(String, Value)>,
    pub stats: BuilderStats,
    pairs: Option<Vec<super::pairs::PairCandidate>>,
    pairs_ready: bool,
}

/// What a builder operation becomes once checked: the answer it gives after its store operation is committed.
enum Kind {
    Map(ConceptId),
    None,
    Revise,
    Keep,
    Propose(String),
    /// A proposal whose name or alias the ontology holds for a concept of the same type: that concept, nothing written.
    Reuse(String, ConceptId),
    Link(&'static str, &'static str),
}

/// A concept name as the ontology keys it (whitespace collapsed, lower case).
fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// A live concept named by its short `@id`, its full id (with or without `@`) or an exact name or alias.
fn existing_concept<S: AuditStore>(s: &S, name: &str) -> Option<ConceptId> {
    let live = |c: &ConceptView| !matches!(c.status.as_str(), "retired" | "narrowed");
    if let Some(c) = crate::hash::from_hex(name.strip_prefix('@').unwrap_or(name)).map(ConceptId).and_then(|id| s.concept(&id)).filter(live) {
        return Some(c.id);
    }
    if name.starts_with('@') {
        return s.concepts().into_iter().find(|c| live(c) && c.id.short() == name).map(|c| c.id);
    }
    s.candidates(name, 1).into_iter().find(live).map(|c| c.id)
}

/// Significant words of a name: lower case letters and digits, longer than four characters, not a corpus-wide word.
fn words(s: &str) -> BTreeSet<String> {
    const COMMON: [&str; 6] = ["report", "reports", "which", "their", "there", "about"];
    s.split(|c: char| !c.is_alphanumeric()).map(str::to_lowercase).filter(|w| w.chars().count() > 4 && !COMMON.contains(&w.as_str())).collect()
}

/// The durable cursor key of the graph builder (contract v0.1 R5).
pub const BUILDER_CHECKPOINT: &str = "builder";
/// Refused attempts of one operation slot before the builder must stop repairing it. Every refusal before the slot's next success
/// shares it (Codex review c78060e: 16 could run out inside one 32-operation answer).
pub(crate) const MAX_ATTEMPTS: u32 = 256;

fn hex(h: &Hash) -> String {
    crate::hash::to_hex(h)
}

fn digest(v: &Value) -> String {
    hex(&crate::hash::sha256(crate::jcs::to_jcs(v).as_bytes()))
}

#[derive(Debug, Default, Clone)]
pub struct BuilderStats {
    pub cards: u64,
    pub ops_accepted: u64,
    pub ops_refused: u64,
    pub concepts_proposed: u64,
    pub links_proposed: u64,
    pub duplicates: u64,
    /// `propose_concept` answered with the concept the ontology already holds under that name or alias.
    pub concepts_reused: u64,
}

impl Builder {
    pub fn new(cfg: BuilderConfig) -> Builder {
        Builder { cfg, ..Default::default() }
    }

    /// Complete a durable failure's serial cursor transition, including after a crash between the two checkpoints.
    pub fn persist_unresolved_cursor<S: AuditStore>(&mut self, s: &mut S) -> Result<(), Value> {
        if self.close_scope.is_some() {
            return Ok(());
        }
        let (from, to, ids) = super::agent_failures::serial_progress(s);
        if to == from {
            return Ok(());
        }
        let ck = json!({"key":BUILDER_CHECKPOINT,"from":from,"to":to,"context":{"reason":"agent_attempt_limit","unresolved_cards":ids}});
        match s.submit_operations_id(&format!("builder-unresolved:{}", digest(&ck)), "kernel", &[], Some(ck)) {
            Ok(r) if r["checkpointed"] == true && r["error"].is_null() => {
                self.cursor = self.cursor.max(to);
                Ok(())
            }
            Ok(r) => Err(r),
            Err(e) => Err(e.to_json()),
        }
    }
    /// Report a failed model attempt without discarding already committed operations.
    pub fn agent_failure<S: AuditStore>(&mut self, s: &mut S, card_id: &str, attempt: &str, who: &str, reason: &str) -> Value {
        let key = format!("build:{card_id}");
        let prior = super::agent_failures::entry(s, &key);
        if prior["attempts"].as_array().is_some_and(|xs| xs.iter().any(|v| v["id"] == attempt)) {
            if let Err(error) = super::agent_failures::record(s, &key, attempt, who, reason, None) {
                return json!({"status":"error","code":"AGENT_FAILURE_CHECKPOINT_REFUSED","error":error});
            }
            if prior["unresolved"] == true {
                if let Err(error) = self.persist_unresolved_cursor(s) {
                    return json!({"status":"error","code":"AGENT_FAILURE_CURSOR_REFUSED","error":error});
                }
                if let Some(card) = self.open.as_ref().filter(|c| c.card_id == card_id) {
                    self.cursor = self.cursor.max(card.cursor_to);
                    self.open = None;
                }
            }
            return json!({"status":if prior["unresolved"]==true {"CARD_UNRESOLVED"} else {"CARD_RETRY"},"card_id":card_id,"failures":prior["failures"],"replayed":true});
        }
        let Some(card) = self.open.as_ref().filter(|c| c.card_id == card_id).cloned() else {
            return json!({"status":"error","code":"STALE_CARD"});
        };
        match super::agent_failures::record(
            s,
            &key,
            attempt,
            who,
            reason,
            Some(json!({"range":[card.cursor_from,card.cursor_to],"pool":self.close_scope.is_some(),"review":card.review})),
        ) {
            Ok(e) => {
                if e["unresolved"] == true {
                    if let Err(error) = self.persist_unresolved_cursor(s) {
                        return json!({"status":"error","code":"AGENT_FAILURE_CURSOR_REFUSED","error":error});
                    }
                    self.cursor = self.cursor.max(card.cursor_to);
                    self.open = None;
                }
                json!({"status":if e["unresolved"]==true {"CARD_UNRESOLVED"} else {"CARD_RETRY"},"card_id":card_id,"failures":e["failures"],"unresolved":e["unresolved"]})
            }
            Err(error) => json!({"status":"error","code":"AGENT_FAILURE_CHECKPOINT_REFUSED","error":error}),
        }
    }
    /// Records the builder has processed or explicitly left unresolved after its attempt limit.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// After a restart: the cursor comes back from the store's durable checkpoint; an open card is cut again with the same id
    /// (its committed operations replay from their receipts, so redoing them adds nothing).
    pub fn recover<S: AuditStore>(&mut self, s: &S) {
        self.cursor = s.checkpoint(BUILDER_CHECKPOINT).and_then(|c| c["to"].as_u64()).unwrap_or(0);
        self.cursor = self.cursor.max(super::agent_failures::serial_progress(s).1);
        self.open = None;
        self.done_ops = 0;
        self.proposed.clear();
        self.last = None;
        self.pairs = s
            .checkpoint("builder:pair-plan")
            .and_then(|c| c["context"]["pairs"].as_array().and_then(|a| a.iter().map(super::pairs::PairCandidate::from_json).collect()));
        self.pairs_ready = false;
    }

    /// Freeze the bounded A4 first wave once initial extraction and automatic rereads finish. The first pair submission
    /// persists this catalog before any pair operation; recovery uses that same catalog, not a new ranking over changed data.
    pub fn prepare_pairs<S: AuditStore>(&mut self, s: &S, reading_done: bool) {
        self.pairs_ready = reading_done;
        if self.cfg.max_links == 0 {
            // links off: no pair cards, which only link
            self.pairs = Some(vec![]);
        } else if reading_done && self.pairs.is_none() && (!super::quality::enabled(s, "evolution_cards") || (self.cursor >= s.head() && self.open.is_none())) {
            self.pairs = Some(super::quality::pair_candidates(s));
        }
    }

    fn pending_pair<S: AuditStore>(&self, s: &S) -> Option<&super::pairs::PairCandidate> {
        if !self.pairs_ready {
            return None;
        }
        self.pairs
            .as_ref()?
            .iter()
            .filter(|p| p.metadata["kind"] != super::quality::evolution::UNASSIGNABLE)
            .find(|p| s.checkpoint(&format!("builder:pair:{}", p.id())).is_none() && !super::agent_failures::unresolved_card(s, &p.id(), 0, 0))
    }

    fn pair_card<S: AuditStore>(&mut self, s: &S) -> Option<Card> {
        let p = self.pending_pair(s)?.clone();
        let ends = super::quality::evolution::ends(&p);
        let records: Vec<RecordView> = ends.iter().filter_map(|id| s.record(id)).collect();
        let neighbors = super::pairs::cone(s, &ends).into_iter().filter(|r| !ends.contains(&r.id)).collect();
        let card = Card {
            card_id: p.id(),
            cursor_from: 0,
            cursor_to: 0,
            records,
            candidates: BTreeMap::new(),
            neighbors,
            concept_types: vec![],
            max_ops: if p.metadata["kind"] == "evolution" { self.cfg.max_ops } else { self.cfg.max_links },
            max_links: self.cfg.max_links,
            pair: Some(p.to_json()),
            ontology: None,
            review: None,
            functions: None,
        };
        self.done_ops = 0;
        self.proposed.clear();
        self.last = None;
        self.stats.cards += 1;
        self.restore(s, &card);
        self.open = Some(card.clone());
        Some(card)
    }

    /// Records after the cursor the builder will card: what a link check or a summary wrote is not material (as in `next_card`).
    pub fn backlog<S: AuditStore>(&self, s: &S) -> usize {
        s.records_since(self.cursor)
            .iter()
            .filter(|r| !super::directives::is_link_directive(&r.directive) && !super::directives::is_summary_directive(&r.directive))
            .count()
    }

    /// The range of the card waiting for its answer, if any.
    pub fn open_range(&self) -> Option<(u64, u64)> {
        self.open.as_ref().map(|c| (c.cursor_from, c.cursor_to))
    }

    /// The id of the card waiting for its answer, if any.
    pub fn open_card_id(&self) -> Option<&str> {
        self.open.as_ref().map(|c| c.card_id.as_str())
    }

    pub fn caught_up<S: AuditStore>(&self, s: &S) -> bool {
        self.open.is_none()
            && self.cursor >= s.head()
            && self.pending_pair(s).is_none()
            && revisions::pending(s).iter().all(|p| super::agent_failures::unresolved_review(s, &p["proposal"]))
    }

    /// The open card again (idempotent), or a new one from the records after the cursor; `None` when there is nothing new.
    /// The next card cut no further than record `end`: a card given before a restart is cut again over its range, so it keeps
    /// its id and its answer is still accepted.
    pub fn next_card_up_to<S: AuditStore>(&mut self, s: &S, end: u64) -> Option<Card> {
        let cut = self.cut_to.replace(self.cut_to.map_or(end, |c| c.min(end)));
        let card = self.next_card(s);
        self.cut_to = cut;
        card
    }

    pub fn next_card<S: AuditStore>(&mut self, s: &S) -> Option<Card> {
        if self.open.as_ref().is_some_and(|c| super::agent_failures::unresolved_card(s, &c.card_id, c.cursor_from, c.cursor_to)) {
            self.cursor = self.cursor.max(self.open.as_ref().unwrap().cursor_to);
            self.open = None;
        }
        if let Some(c) = &self.open {
            return Some(c.clone());
        }
        // what a link check records is the evidence of its verdict, not new material: the card does not show it, but its range
        // covers it and the cursor moves on (live run 10A: link checks wrote 70% of the records and the builder never caught up).
        // A stretch of such records only is a card without records.
        let (mut records, mut last) = (Vec::new(), None);
        for r in s.records_since(self.cursor) {
            if self.cut_to.is_some_and(|end| r.seq > end) {
                break;
            }
            if records.len() >= self.cfg.max_records {
                break;
            }
            let material = !super::directives::is_link_directive(&r.directive) && !super::directives::is_summary_directive(&r.directive);
            if material && self.cfg.author_runs && records.first().is_some_and(|old: &RecordView| old.author != r.author) {
                break;
            }
            last = Some(r.seq);
            // a summary is an answer, not material either (live run 10A-4: the builder linked the RQ1 summary's claims to their quotes)
            if !super::directives::is_link_directive(&r.directive) && !super::directives::is_summary_directive(&r.directive) {
                records.push(r);
            }
        }
        let Some(last) = last else {
            if self.records_only {
                return None;
            }
            return self.revision_card(s, None).or_else(|| self.pair_card(s));
        };
        if super::quality::enabled(s, "term_hygiene") {
            for r in &mut records {
                r.terms = super::quality::terms(s, r);
            }
        }
        // the significant words of every live concept: a term with too few exact matches gets the concepts that share most of its
        // words as candidates too (Gemini, run 9: one limitation in two reports got two concepts, so the builder never saw the
        // earlier report's records next to the later ones). A retrieval candidate, never an identity.
        let indexed: Vec<(BTreeSet<String>, ConceptView)> = s
            .concepts()
            .into_iter()
            .filter(|c| c.selectable())
            .map(|c| (std::iter::once(&c.name).chain(&c.aliases).flat_map(|x| words(x)).collect(), c))
            .collect();
        let mut candidates: BTreeMap<String, Vec<ConceptView>> = BTreeMap::new();
        let (mut required, mut optional): (BTreeSet<RecordId>, BTreeSet<RecordId>) = (BTreeSet::new(), BTreeSet::new());
        let new_ids: BTreeSet<RecordId> = records.iter().map(|r| r.id).collect();
        for r in &records {
            for t in &r.terms {
                if candidates.contains_key(t) {
                    continue;
                }
                let strict = super::quality::config(s)["candidate_match"] == "strict";
                let mut cs = if strict { super::quality::strict_candidates(s, t, self.cfg.max_candidates) } else { s.candidates(t, self.cfg.max_candidates) };
                let want = words(t);
                if !strict && cs.len() < self.cfg.max_candidates && !want.is_empty() {
                    let mut scored: Vec<(usize, &ConceptView)> = indexed
                        .iter()
                        .filter(|(_, c)| !cs.iter().any(|h| h.id == c.id))
                        .map(|(w, c)| (w.intersection(&want).count(), c))
                        .filter(|(k, _)| *k > 0)
                        .collect();
                    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.id.cmp(&b.1.id)));
                    let room = self.cfg.max_candidates - cs.len();
                    cs.extend(scored.into_iter().take(room).map(|(_, c)| c.clone()));
                }
                for c in &cs {
                    optional.extend(s.records_of(&c.id).into_iter().filter(|x| !new_ids.contains(x)));
                }
                candidates.insert(t.clone(), cs);
            }
            // what the new record rests on or points to is context the builder may link against
            required.extend(r.based_on.iter().copied().filter(|x| !new_ids.contains(x)));
            if let Some((f, _, t)) = &r.ends {
                required.extend([*f, *t].into_iter().filter(|x| !new_ids.contains(x)));
            }
        }
        // what the new records rest on is always shown (a basis cut off is a record the builder must use but cannot see; Codex
        // review c78060e, F08); the latest records of their concepts fill the rest of the neighbour budget
        let mut neighbors: Vec<RecordView> = required.iter().filter_map(|i| s.record(i)).collect();
        let mut extra: Vec<RecordView> = optional.difference(&required).filter_map(|i| s.record(i)).collect();
        extra.sort_by_key(|r| std::cmp::Reverse(r.seq));
        extra.truncate(self.cfg.max_neighbors.saturating_sub(neighbors.len()));
        neighbors.extend(extra);
        neighbors.sort_by_key(|r| r.seq);
        self.stats.cards += 1;
        self.done_ops = 0;
        self.proposed.clear();
        self.last = None;
        // deterministic and unambiguous: the run (run id and manifest), the cut and its record ids. Not the ontology: the
        // builder's own committed operations change it, and a card cut again after a restart keeps its id.
        let ids: Vec<String> = records.iter().map(|r| hex(&r.id.0)).collect();
        let seed = digest(&json!(["r2r-builder-card/1", hex(&s.run_namespace()), self.cursor, last, ids]));
        let ontology = revisions::context(s, &mut candidates, &mut neighbors);
        let card = Card {
            card_id: format!("C{}-{}-{}", self.cursor, last, &seed[..16]),
            cursor_from: self.cursor,
            cursor_to: last,
            records,
            candidates,
            neighbors,
            concept_types: s.concept_types(),
            max_ops: self.cfg.max_ops,
            max_links: self.cfg.max_links,
            pair: None,
            ontology,
            review: None,
            functions: super::quality::enabled(s, "concept_functions").then(|| super::quality::known_functions(s, 3)),
        };
        self.restore(s, &card);
        self.open = Some(card.clone());
        Some(card)
    }

    /// A card cut again after a restart: how many of its operations were committed and the names of the concepts they proposed,
    /// rebuilt from the durable receipts, so a suffix-only repair and the operation budget go on from there.
    fn restore<S: AuditStore>(&mut self, s: &S, card: &Card) {
        'slot: loop {
            for a in 0..MAX_ATTEMPTS {
                let Some(v) = s.receipt_outcome(&format!("{}:{}:{a}", card.card_id, self.done_ops), "builder") else { break 'slot };
                if v["accepted_operations"] == 1 && v["error"].is_null() {
                    if let Some(c) = v["results"][0]["id"].as_str().and_then(crate::hash::from_hex).map(ConceptId).and_then(|c| s.concept(&c)) {
                        self.proposed.insert(norm(&c.name), c.id);
                    }
                    self.done_ops += 1;
                    continue 'slot;
                }
            }
            break;
        }
        // Old journals have no reuse checkpoint: the operation-slot recovery above still applies.
        if let Ok(context) = Self::reuse_context(s, card) {
            if let Some(names) = context["names"].as_object() {
                for (name, id) in names {
                    if let Some(cid) = id.as_str().and_then(crate::hash::from_hex).map(ConceptId).filter(|id| s.concept(id).is_some()) {
                        self.proposed.insert(name.clone(), cid);
                    }
                }
            }
        }
    }

    /// Reuse bindings are coordinator metadata, not ontology aliases or the builder ingest cursor.
    fn reuse_key(card: &Card) -> String {
        format!("builder:reuse:{}", card.card_id)
    }

    fn reuse_context<S: AuditStore>(s: &S, card: &Card) -> Result<Value, Value> {
        let Some(checkpoint) = s.checkpoint(&Self::reuse_key(card)) else {
            return Ok(json!({"format":"r2r-builder-reuse/1", "card_id":card.card_id, "names":{}, "receipts":{}}));
        };
        let context = &checkpoint["context"];
        if context["format"] != "r2r-builder-reuse/1" || context["card_id"] != card.card_id || !context["names"].is_object() || !context["receipts"].is_object()
        {
            return Err(bad(Code::BadField, "invalid builder reuse checkpoint", "checkpoint").to_json());
        }
        Ok(context.clone())
    }

    /// Read the first accepted reuse ACK before live-dependent translation; an exact retry installs nothing again.
    fn prior_reuse<S: AuditStore>(s: &S, card: &Card, op: &Value) -> Result<Option<Value>, (Value, bool)> {
        let context = Self::reuse_context(s, card).map_err(|e| (e, false))?;
        let hash = digest(op);
        if let Some(receipt) = context["receipts"].get(&hash) {
            let valid = receipt["name"].as_str().is_some()
                && receipt["concept"].as_str().and_then(crate::hash::from_hex).is_some()
                && receipt["answer"].is_object()
                && receipt["answer"]["op"] == "propose_concept"
                && receipt["answer"]["status"] == "existing";
            return if valid {
                Ok(Some(receipt["answer"].clone()))
            } else {
                Err((bad(Code::BadField, "invalid builder reuse receipt", "checkpoint").to_json(), false))
            };
        }
        // A failed checkpoint also has a durable receipt. Do not reinterpret its exact request as a fresh reuse.
        if let Some(outcome) = s.receipt_outcome(&format!("{}:reuse:{hash}", card.card_id), "builder") {
            let error = if outcome["error"].is_null() {
                bad(Code::BadField, "reuse receipt has no accepted binding checkpoint", "checkpoint").to_json()
            } else {
                outcome["error"].clone()
            };
            return Err((error, true));
        }
        Ok(None)
    }

    /// Persist the binding and its exact ACK in an existing empty-operation/checkpoint transaction before acknowledging it.
    fn reuse<S: AuditStore>(
        &mut self,
        s: &mut S,
        card: &Card,
        op: &Value,
        store_op: &Value,
        name: String,
        cid: ConceptId,
    ) -> Result<(Value, bool), (Value, bool)> {
        let mut context = Self::reuse_context(&*s, card).map_err(|e| (e, false))?;
        let hash = digest(op);
        let mut note = "the ontology already holds this name or alias for a concept of this type: that concept is used, its aliases unchanged".to_string();
        // the address layer (claude-reviewer's RV-01 of 8dfff576): the rule asks to leave the function out when unsure, so a concept
        // proposed first without one gets it from a later proposal; the kernel places it under the concept's own stored definition, and
        // a refusal (a definition changed since) leaves the card's answer as it was; the agent is told which
        if let (Some(function), Some(concept)) = (store_op.get("function"), s.concept(&cid)) {
            note = match concept.function {
                Some(standing) => format!("{note}; it stays under its function \"{standing}\""),
                None => {
                    let mut place = json!({"kind":"propose_concept","type":concept.ty,"name":concept.name,"aliases":concept.aliases,
                        "basis":store_op["basis"],"function":function});
                    if let Some(subject) = store_op.get("subject") {
                        place["subject"] = subject.clone();
                    }
                    match s.submit_operations_id(&format!("{}:place:{hash}", card.card_id), "builder", &[place], None) {
                        Ok(r) if r["error"].is_null() => format!("{note}; it is now placed under \"{}\"", r["results"][0]["function"].as_str().unwrap_or("")),
                        _ => format!("{note}; the function was not taken"),
                    }
                }
            };
        }
        let answer = json!({"op":"propose_concept", "concept":cid.short(), "status":"existing", "note":note});
        context["names"][&name] = json!(hex(&cid.0));
        context["receipts"][&hash] = json!({"name":name, "concept":hex(&cid.0), "answer":answer});
        let checkpoint = json!({"key":Self::reuse_key(card), "from":0, "to":0, "context":context});
        let id = format!("{}:reuse:{hash}", card.card_id);
        match s.submit_operations_id(&id, "builder", &[], Some(checkpoint)) {
            Ok(outcome) if outcome["checkpointed"] == true && outcome["error"].is_null() => {}
            Ok(outcome) => {
                let error = if outcome["error"].is_null() {
                    bad(Code::BadField, "reuse binding was not checkpointed", "checkpoint").to_json()
                } else {
                    outcome["error"].clone()
                };
                return Err((error, false));
            }
            Err(error) => return Err((error.to_json(), false)),
        }
        self.proposed.insert(name, cid);
        self.stats.concepts_reused += 1;
        Ok((answer, false))
    }

    /// Apply the builder's operations for the open card, one durable store submission per operation (`<card>:<n>:<attempt>`),
    /// then move the cursor with a checkpoint submission that names the closing request (`<card>:ck:<request>`). Every valid
    /// operation is committed; refused ones come back with `REPAIR_REQUIRED` and the builder sends only them, corrected.
    /// An exact retry gets the same answer and writes nothing: the open card keeps its last answer, and an operation the card
    /// already committed (in any slot, as part of any earlier request) is replayed from its receipt, also after a restart.
    pub fn submit<S: AuditStore>(&mut self, s: &mut S, card_id: &str, ops: &[Value]) -> Value {
        self.submit_as(s, card_id, ops, None)
    }

    /// Dynamic-role execution keeps the logical builder's operation receipts, while the atomic close checkpoint
    /// names the authenticated executor. Without an executor the historical bytes and receipts are unchanged.
    pub fn submit_as<S: AuditStore>(&mut self, s: &mut S, card_id: &str, ops: &[Value], executor: Option<&str>) -> Value {
        if let Err(error) = self.persist_unresolved_cursor(s) {
            return json!({"status":"error","code":"AGENT_FAILURE_CURSOR_REFUSED","error":error});
        }
        let Some(card) = self.open.clone().filter(|c| c.card_id == card_id) else {
            return Self::replay(s, card_id, ops, executor, self.close_scope.as_ref());
        };
        if let Err(e) = super::quality::evolution::issued(s, &card) {
            return json!({"status":"error","code":"EVOLUTION_ISSUE_REFUSED","error":e});
        }
        if card.pair.is_some() && s.checkpoint("builder:pair-plan").is_none() {
            let plan = json!({"key":"builder:pair-plan","from":0,"to":0,"context":{"pairs":self.pairs.as_ref().map(|ps|ps.iter().map(|p|p.to_json()).collect::<Vec<_>>())}});
            match s.submit_operations_id("builder:pair-plan", "builder", &[], Some(plan)) {
                Ok(r) if r["checkpointed"] == true && r["error"].is_null() => (),
                Ok(r) => return json!({"status":"error","code":"PAIR_PLAN_REFUSED","store":r}),
                Err(e) => return json!({"status":"error","code":"PAIR_PLAN_REFUSED","error":e.to_json()}),
            }
        }
        if card.pair.is_some() && !super::quality::evolution::is_card(&card) {
            if let Some(i) = ops.iter().position(|o| !matches!(o["op"].as_str(), Some("link" | "mark_duplicate" | "flag_conflict"))) {
                return json!({"status":"REPAIR_REQUIRED","card_id":card_id,"failed_index":i,"accepted":0,
                    "error":bad(Code::BadField,"PAIR_CARD permits only relations between its two assertions","op")
                        .expected(json!({"ops":["link","mark_duplicate","flag_conflict"]})).to_json()});
            }
        }
        let request = if card.ontology.is_some() && ops.iter().any(|o| matches!(o["op"].as_str(), Some("revise_concept" | "keep"))) {
            digest(&json!([ops, executor]))
        } else {
            digest(&json!(ops))
        };
        if let Some((_, answer)) = self.last.as_ref().filter(|(d, _)| *d == request) {
            return answer.clone();
        }
        if ops.len() > card.max_ops {
            // a repair, not a lost card: live run 10A-3 closed 19 of 53 cards empty on this refusal, without one repair. Nothing of
            // the answer is stored, so the failed index is 0, as for the swarm's answer over its line limit; taking the first
            // `max_ops` operations would drop the rest silently
            let e = bad(
                Code::BadField,
                format!(
                    "{} operations, at most {} per answer: nothing of this answer was stored; send it again with at most {} operations",
                    ops.len(),
                    card.max_ops,
                    card.max_ops
                ),
                "ops",
            )
            .expected(json!({"max_ops": card.max_ops}));
            return json!({"status": "REPAIR_REQUIRED", "card_id": card_id, "failed_index": 0, "code": "TOO_MANY_OPS", "accepted": 0,
                          "committed_ops": self.done_ops, "error": e.to_json()});
        }
        // every valid operation of the request is committed; a refused one no longer drops the operations after it (run 8 lost
        // two thirds of its links: the model writes links last, and the first refused mapping cut them off)
        let (mut results, mut refused) = (Vec::new(), Vec::new());
        for (i, op) in ops.iter().enumerate() {
            match self.apply(s, &card, op, executor) {
                Ok((r, replayed)) => {
                    if !replayed {
                        self.stats.ops_accepted += 1;
                    }
                    results.push(r);
                }
                Err((e, replayed)) => {
                    if !replayed {
                        self.stats.ops_refused += 1;
                    }
                    refused.push(json!({"index": i, "error": e}));
                }
            }
        }
        if let Some(first) = refused.first() {
            // the concepts proposed for this card so far: a corrected map_term may name them (Codex review c78060e)
            let proposed: BTreeMap<&String, String> = self.proposed.iter().map(|(n, c)| (n, c.short())).collect();
            let answer = json!({"status": "REPAIR_REQUIRED", "card_id": card_id, "failed_index": first["index"], "refused": refused,
                                "accepted": results.len(), "committed_ops": self.done_ops, "results": results, "error": first["error"],
                                "proposed_concepts": proposed,
                                "repair": "every valid operation was committed: resend refused operations, corrected, plus any needed \
                                           propose_concept prerequisites before their map_term; do not resend accepted operations. \
                                           map_term may name a concept of proposed_concepts by its exact name"});
            self.last = Some((request, answer.clone()));
            return answer;
        }
        if super::quality::evolution::is_card(&card) && super::quality::evolution::rows(&card).iter().any(|p| !super::quality::evolution::decided(s, &card, p))
        {
            return json!({"status":"REPAIR_REQUIRED","accepted":results.len(),"results":results,"error":{"code":"EVOLUTION_DECISIONS_REQUIRED","message":"Decide every pair with a justified link or explicit none and reason."}});
        }
        if let Some(proposal) = &card.review {
            let unresolved = if ontology_review::task(&card).is_some() {
                !ontology_review::decided(s, proposal)
            } else {
                revisions::pending(s).iter().any(|p| p["proposal"] == *proposal)
            };
            if unresolved {
                return json!({"status":"REPAIR_REQUIRED","failed_index":0,"accepted":results.len(),"results":results,
                    "error":{"code":"REVIEW_REQUIRED","message":"Explicitly answer this review with shown grounded basis; mandatory reviews need keep/revise_concept, pending revisions need confirm/reject. [] leaves it open."}});
            }
        }
        let (close_id, checkpoint) = Self::close_request(card_id, card.cursor_from, card.cursor_to, ops, executor, self.close_scope.as_ref());
        match s.submit_operations_id(&close_id, "builder", &[], Some(checkpoint)) {
            Ok(r) if r["checkpointed"] == true => {}
            Ok(r) => return json!({"status": "error", "code": "CHECKPOINT_REFUSED", "card_id": card_id, "store": r}),
            Err(e) => return json!({"status": "error", "code": "CHECKPOINT_REFUSED", "card_id": card_id, "error": e.to_json()}),
        }
        if card.pair.is_none() {
            self.cursor = card.cursor_to;
        }
        self.open = None;
        json!({"status": "CARD_DONE", "card_id": card_id, "accepted": results.len(), "results": results, "cursor": self.cursor})
    }

    pub fn execution_step(&mut self, step: u64) {
        if let Some((_, context)) = &mut self.close_scope {
            context["sync_step"] = json!(step);
        }
    }

    /// The submission that closes a card: its id and its checkpoint name the exact request that closed it.
    fn close_request(card_id: &str, from: u64, to: u64, ops: &[Value], executor: Option<&str>, scope: Option<&(String, Value)>) -> (String, Value) {
        let request = digest(&json!(ops));
        let id = format!("{card_id}:ck:{}", &request[..16]);
        let key = if card_id.starts_with('P') { format!("builder:pair:{card_id}") } else { BUILDER_CHECKPOINT.to_string() };
        let mut checkpoint = json!({"key": key, "from": from, "to": to, "context": {"card_id": card_id, "request": request}});
        if let Some((key, context)) = scope {
            checkpoint["key"] = json!(key);
            checkpoint["from"] = json!(0);
            checkpoint["to"] = json!(0);
            checkpoint["context"]["range_from"] = json!(from);
            checkpoint["context"]["range_to"] = json!(to);
            checkpoint["context"].as_object_mut().expect("close context").extend(context.as_object().expect("pool context").clone());
        }
        if let Some(agent) = executor {
            checkpoint["context"]["build_agent"] = json!(agent);
        }
        let id = if scope.is_some() { format!("{card_id}:ck:{}", &digest(&json!([ops, checkpoint]))[..16]) } else { id };
        (id, checkpoint)
    }

    /// A card that is not open: the exact request that closed it gets its acknowledgement again (a lost `CARD_DONE`, also of an
    /// older card and after a restart, read from the durable receipt); any other request is refused and nothing is written.
    fn replay<S: AuditStore>(s: &S, card_id: &str, ops: &[Value], executor: Option<&str>, scope: Option<&(String, Value)>) -> Value {
        let mut parts = card_id.strip_prefix(['C', 'P', 'R']).unwrap_or("").splitn(3, '-').map(|p| p.parse::<u64>().ok());
        if let (Some(Some(from)), Some(Some(to))) = (parts.next(), parts.next()) {
            let (id, checkpoint) = Self::close_request(card_id, from, to, ops, executor, scope);
            if let Prior::Same(Ok(r)) = s.operations_receipt(&id, "builder", &[], Some(checkpoint)) {
                if r["checkpointed"] == true {
                    return json!({"status": "CARD_DONE", "card_id": card_id, "cursor": to, "replayed": true});
                }
            }
        }
        json!({"status": "error", "code": "UNKNOWN_CARD",
               "message": format!("'{card_id}' is not the open card, and no close of it by exactly this request is on record")})
    }

    /// One store operation as its own durable submission `<card>:<slot>:<attempt>`: the first attempt whose id is free or holds
    /// exactly this operation (an exact retry finds its receipt and is reported as replayed; a repair after a refusal, also one
    /// from before a restart, gets the next attempt). The store's error comes back as is.
    fn commit<S: AuditStore>(&self, s: &mut S, card: &Card, slot: usize, op: Value) -> Result<(Value, bool), (Value, bool)> {
        let ops = [op];
        let mut replayed = false;
        let id = (0..MAX_ATTEMPTS)
            .map(|a| format!("{}:{slot}:{a}", card.card_id))
            .find(|id| match s.operations_receipt(id, "builder", &ops, None) {
                Prior::Other => false,
                Prior::Same(_) => {
                    replayed = true;
                    true
                }
                Prior::Free => true,
            })
            .ok_or_else(|| (bad(Code::BadField, format!("operation {slot} was refused {MAX_ATTEMPTS} times"), "op").to_json(), false))?;
        match s.submit_operations_id(&id, "builder", &ops, None) {
            Ok(r) if r["accepted_operations"] == 1 && r["error"].is_null() => Ok((r["results"][0].clone(), replayed)),
            Ok(r) => Err((r["error"].clone(), replayed)),
            Err(e) => Err((e.to_json(), replayed)),
        }
    }

    /// Whether a slot holds this exact operation's durable success or refusal.
    fn prior<S: AuditStore>(s: &S, card: &Card, slot: usize, op: Value) -> bool {
        let ops = [op];
        (0..MAX_ATTEMPTS)
            .map(|a| s.operations_receipt(&format!("{}:{slot}:{a}", card.card_id), "builder", &ops, None))
            .take_while(|p| !matches!(p, Prior::Free))
            .any(|p| matches!(p, Prior::Same(_)))
    }

    /// Check one operation and commit it: in the slot that already holds it (a replay from its receipt, nothing written) or in the
    /// next free slot. Its answer, and whether it was replayed.
    fn apply<S: AuditStore>(&mut self, s: &mut S, card: &Card, op: &Value, executor: Option<&str>) -> Result<(Value, bool), (Value, bool)> {
        if op["op"] == "propose_concept" {
            if let Some(answer) = Self::prior_reuse(&*s, card, op)? {
                return Ok((answer, true));
            }
        }
        let (mut store_op, kind) = self.translate(&*s, card, op).map_err(|e| (e, false))?;
        if matches!(kind, Kind::Revise | Kind::Keep) {
            store_op["subject"] = json!(executor.ok_or_else(|| (bad(Code::BadField, "authenticated executor required", "subject").to_json(), false))?);
        }
        if card.ontology.is_some() && matches!(kind, Kind::Propose(_) | Kind::Reuse(..)) {
            store_op["subject"] = json!(executor.ok_or_else(|| (bad(Code::BadField, "authenticated executor required", "subject").to_json(), false))?);
        }
        if ontology_review::enabled(s) && matches!(kind, Kind::Map(_)) {
            let mapper = executor.ok_or_else(|| (bad(Code::BadField, "authenticated mapper required", "subject").to_json(), false))?;
            store_op["subject"] = json!(mapper);
            // the pinned circles +1 refiner maps under its own rule, so mappings recorded before the rule replay unchanged
            if s.checkpoint("audit:mcp:coverage").is_some_and(|c| c["context"]["circle_refiner"] == mapper) {
                store_op["rule"] = json!(crate::audit::state::REFINER_MAP_RULE);
            }
        }
        // A refusal before a later success remains in that occupied slot. Look up every durable outcome before deciding
        // whether this proposal is now an existing concept or whether a new operation would spend another card slot.
        let held = (0..=self.done_ops).find(|&k| Self::prior(&*s, card, k, store_op.clone()));
        if held.is_none() && super::quality::evolution::is_card(card) {
            let rows = super::quality::evolution::rows(card);
            let selected = rows.iter().find(|p| {
                if op["op"] == "none" {
                    p["pair"] == op["pair"]
                } else {
                    let old = super::quality::evolution::id(&p["old"]).unwrap().short();
                    let new = super::quality::evolution::id(&p["new"]).unwrap().short();
                    (op["from"] == old && op["to"] == new) || (op["from"] == new && op["to"] == old)
                }
            });
            if selected.is_some_and(|p| super::quality::evolution::decided(s, card, p)) {
                return Err((bad(Code::BadField, "this pair already has a durable decision; do not submit a second decision", "pair").to_json(), false));
            }
        }
        let kind = match kind {
            Kind::Reuse(name, cid) if held.is_none() => return self.reuse(s, card, op, &store_op, name, cid),
            Kind::Reuse(name, _) => Kind::Propose(name),
            other => other,
        };
        if held.is_none() && matches!(kind, Kind::Link(..)) {
            // Pair cards deliberately revisit old endpoints. Count this card's durable successful receipts, not all links
            // touching its endpoints: an earlier record card must not consume a later pair card's budget.
            let store = &*s;
            let made: BTreeSet<LinkId> = (0..self.done_ops)
                .flat_map(|slot| (0..MAX_ATTEMPTS).filter_map(move |a| store.receipt_outcome(&format!("{}:{slot}:{a}", card.card_id), "builder")))
                .filter(|v| v["accepted_operations"] == 1 && v["error"].is_null() && v["results"][0]["rel"].is_string())
                .filter_map(|v| v["results"][0]["id"].as_str().and_then(crate::hash::from_hex).map(LinkId))
                .collect();
            if made.len() >= card.max_links {
                let e = bad(Code::BadField, format!("the card's {} links are used up", card.max_links), "op").expected(json!({"max_links": card.max_links}));
                return Err((e.to_json(), false));
            }
        }
        if held.is_none() && self.done_ops >= card.max_ops {
            let e = bad(Code::BadField, format!("the card's {} operations are used up", card.max_ops), "op").expected(json!({"max_ops": card.max_ops}));
            return Err((e.to_json(), false));
        }
        let (res, replayed) = self.commit(s, card, held.unwrap_or(self.done_ops), store_op)?;
        if held.is_none() {
            self.done_ops += 1;
        }
        let answer = match kind {
            Kind::None => json!({"op":"none","pair":op["pair"],"reason":op["reason"]}),
            Kind::Keep => {
                let mut value = res;
                value["op"] = json!("keep");
                value
            }
            Kind::Revise => {
                let mut value = res;
                value["op"] = json!("revise_concept");
                value
            }
            Kind::Map(cid) => json!({"op": "map_term", "concept": cid.short(), "status": res["status"]}),
            Kind::Propose(name) => {
                let cid = res["id"]
                    .as_str()
                    .and_then(crate::hash::from_hex)
                    .map(ConceptId)
                    .ok_or((json!({"code": "STORE", "message": "no concept id"}), replayed))?;
                if !replayed {
                    self.stats.concepts_proposed += 1;
                }
                self.proposed.insert(name, cid);
                json!({"op": "propose_concept", "concept": cid.short(), "status": res["status"]})
            }
            Kind::Reuse(..) => unreachable!("a reused concept writes nothing"),
            Kind::Link(o, rel) => {
                if !replayed {
                    self.stats.links_proposed += 1;
                    self.stats.duplicates += u64::from(rel == "duplicate_of");
                }
                // contract v0.1 R6: no link is accepted on the builder's word, duplicates included (VERIFY_LINK or the owner)
                let lid = res["id"].as_str().and_then(crate::hash::from_hex).map(|h| LinkId(h).short());
                json!({"op": o, "link": lid, "rel": rel, "status": res["status"]})
            }
        };
        Ok((answer, replayed))
    }

    /// Check one builder operation against the card and turn it into the store operation (nothing is written).
    fn translate<S: AuditStore>(&self, s: &S, card: &Card, op: &Value) -> Result<(Value, Kind), Value> {
        let f = |k: &str| op.get(k).and_then(|x| x.as_str());
        let new: BTreeMap<String, &RecordView> = card.records.iter().map(|r| (r.id.short(), r)).collect();
        let seen: BTreeMap<String, &RecordView> = card.records.iter().chain(&card.neighbors).map(|r| (r.id.short(), r)).collect();
        let rec = |k: &str, only_new: bool| -> Result<&RecordView, Value> {
            let id = f(k).ok_or_else(|| bad(Code::MissingField, format!("missing '{k}'"), k).to_json())?;
            let pool = if only_new { &new } else { &seen };
            pool.get(id).copied().ok_or_else(|| {
                bad(Code::UnknownLocalId, format!("{id} is not a {} record of this card", if only_new { "new" } else { "shown" }), k)
                    .expected(json!({"choose_one_of": pool.keys().collect::<Vec<_>>()}))
                    .to_json()
            })
        };
        let basis = |k: &str| -> Result<Vec<&RecordView>, Value> {
            let ids: Vec<&str> = op.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
            if ids.is_empty() {
                return Err(bad(Code::NoEvidence, format!("'{k}' needs at least one record"), k).to_json());
            }
            ids.iter().map(|i| seen.get(*i).copied().ok_or_else(|| bad(Code::UnknownLocalId, format!("{i} is not shown in this card"), k).to_json())).collect()
        };
        let ids = |rs: &[&RecordView]| rs.iter().map(|r| hex(&r.id.0)).collect::<Vec<_>>();
        if card.review.is_some() && f("op") != Some("revise_concept") && !(ontology_review::task(card).is_some() && f("op") == Some("keep")) {
            return Err(bad(Code::BadField, "REVISION_CARD permits only confirm/reject", "op").to_json());
        }
        match f("op").unwrap_or("") {
            "none" if super::quality::evolution::is_card(card) => {
                let pair = f("pair").ok_or_else(|| bad(Code::MissingField, "missing pair", "pair").to_json())?;
                // the card asks for at most 240 characters and the store takes 400: an overlong reason cost a repair round (K21)
                let reason = f("reason")
                    .filter(|v| !v.trim().is_empty() && v.chars().count() <= 400)
                    .ok_or_else(|| bad(Code::BadField, "none needs a reason of 1..400 characters", "reason").to_json())?;
                if !super::quality::evolution::rows(card).iter().any(|r| r["pair"] == pair) {
                    return Err(bad(Code::BadField, "unknown pair", "pair").to_json());
                }
                Ok((
                    json!({"kind":"checkpoint","key":super::quality::evolution::none_key(&card.card_id,pair),"from":0,"to":0,"context":{"pair":pair,"reason":reason}}),
                    Kind::None,
                ))
            }
            "revise_concept" => revisions::translate(s, card, op).map(|v| (v, Kind::Revise)),
            "keep" if ontology_review::task(card).is_some() => revisions::translate(s, card, op).map(|v| (v, Kind::Keep)),
            "map_term" => {
                let r = rec("record", true)?;
                let term = f("term").ok_or_else(|| bad(Code::MissingField, "missing 'term'", "term").to_json())?;
                if !r.terms.iter().any(|t| t == term) {
                    return Err(bad(Code::BadField, "a term must be one of the record's own terms", "term").expected(json!({"terms": r.terms})).to_json());
                }
                let c = f("concept").ok_or_else(|| bad(Code::MissingField, "missing 'concept'", "concept").to_json())?;
                let shown: Vec<&ConceptView> = card.candidates.values().flatten().collect();
                // a candidate shown, a concept proposed for this card, or any live concept of the ontology by its id or exact name or
                // alias (Gemini, run 9: the kernel answered "already reserved: use the existing concept", and that concept was refused
                // here because the card did not show it, so the builder had to invent a duplicate under another name)
                let cid = shown
                    .iter()
                    .find(|x| x.id.short() == c)
                    .map(|x| x.id)
                    .or_else(|| self.proposed.get(&norm(c)).copied())
                    .or_else(|| existing_concept(s, c))
                    .or_else(||card.ontology.as_ref().and_then(|_|s.concepts().into_iter().find(|cv|!cv.selectable() && (cv.id.short()==c || hex(&cv.id.0)==c.trim_start_matches('@') || norm(c)==cv.name || cv.aliases.contains(&norm(c)))).map(|cv|cv.id)))
                    .ok_or_else(|| {
                        bad(Code::UnknownEntity, format!("cannot resolve concept {c} for this card; a term string does not create a concept"), "concept")
                        .expected(
                            json!({"unresolved_concept":c,
                                "repair":"Choose a shown candidate @id, or submit a grounded propose_concept BEFORE this map_term in the SAME repair, using the exact proposed name. Use shown observe ids as proposal basis; leave unsupported terms unmapped.",
                                "candidates": shown.iter().map(|x| x.id.short()).collect::<Vec<_>>(), "proposed": self.proposed.keys().collect::<Vec<_>>()}),
                        )
                        .to_json()
                    })?;
                // a term and a concept that name different identifiers of one class are two things (Codex's 10A-6 analysis: validations
                // of different commits mapped to one concept; the research of 2026-10-23 on concept linking)
                if let Some(cv) = s.concept(&cid) {
                    let named = std::iter::once(cv.name.clone()).chain(cv.aliases.iter().cloned()).collect::<Vec<_>>().join("\n");
                    if let Some((ours, theirs)) = super::s0::conflicting_identifiers(term, &named) {
                        return Err(bad(Code::BadField, format!("the term names {ours}, the concept {theirs}: they are different things"), "concept")
                            .expected(json!({"leave_unmapped": true, "or": "a concept of the same thing, or propose one"}))
                            .to_json());
                    }
                }
                Ok((json!({"kind": "map_term", "record": hex(&r.id.0), "term": term, "concept": hex(&cid.0)}), Kind::Map(cid)))
            }
            "propose_concept" => {
                let ty = f("type").ok_or_else(|| bad(Code::MissingField, "missing 'type'", "type").to_json())?;
                if !card.concept_types.iter().any(|t| t == ty) {
                    return Err(bad(Code::BadField, format!("unknown concept type '{ty}' (new types need the owner)"), "type")
                        .expected(json!({"types": card.concept_types}))
                        .to_json());
                }
                let name =
                    f("name").filter(|n| !n.trim().is_empty() && n.len() <= 120).ok_or_else(|| bad(Code::BadField, "name: 1..120 chars", "name").to_json())?;
                let aliases: Vec<String> =
                    op.get("aliases").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let b = basis("basis")?;
                if let Some(x) = b.iter().find(|r| r.kind != RecordKind::Observe) {
                    return Err(
                        bad(Code::BadField, format!("{} is a {}: a concept rests on observe records (quotes)", x.id.short(), x.kind.name()), "basis").to_json()
                    );
                }
                // a name or alias the ontology already holds for a concept of this type: that concept is used, as the kernel's refusal
                // would demand ("already reserved: use the existing concept"); its aliases stay as they are
                // only an unambiguous match: a name and aliases held by two different concepts are not routed to one of them by
                // their order (Codex review d7d9a49, D04), whatever their types (review of 4381fe7: a name held by a Component was
                // routed to a Rule through an alias); the kernel then refuses the proposal and names what holds each name
                // every owner of a requested name counts, a retired one too: its names stay reserved though candidates() hides it
                // (Codex's review of 114e9bf)
                let wanted: BTreeSet<String> = std::iter::once(norm(name)).chain(aliases.iter().map(|a| norm(a))).collect();
                let held: BTreeMap<ConceptId, ConceptView> = s
                    .concepts()
                    .into_iter()
                    .filter(|c| std::iter::once(&c.name).chain(&c.aliases).any(|n| wanted.contains(&norm(n))))
                    .map(|c| (c.id, c))
                    .collect();
                // the address layer: with functions on the card, a new concept may name the function it belongs to; the kernel
                // refuses a catch-all name or one of more than 5 words
                let function = match (&card.functions, op.get("function")) {
                    (Some(_), Some(x)) => {
                        Some(x.as_str().map(str::trim).filter(|x| !x.is_empty() && x.split_whitespace().collect::<Vec<_>>().join(" ").len() <= 60).ok_or_else(
                            || {
                                bad(
                                    Code::BadField,
                                    "FUNCTIONS: \"function\" is a short name of 1-4 words, a known function or a new one; or leave it out",
                                    "function",
                                )
                                .to_json()
                            },
                        )?)
                    }
                    // functions off: a stray field changes nothing, as before the layer
                    _ => None,
                };
                let mut command = json!({"kind": "propose_concept", "type": ty, "name": name, "aliases": aliases, "basis": ids(&b)});
                if let Some(x) = function {
                    command["function"] = json!(x);
                }
                if let (1, Some(c)) = (held.len(), held.values().next().filter(|c| c.ty == ty && c.selectable())) {
                    return Ok((command, Kind::Reuse(norm(name), c.id)));
                }
                Ok((command, Kind::Propose(norm(name))))
            }
            o @ ("link" | "mark_duplicate" | "flag_conflict") if card.max_links == 0 => {
                Err(bad(Code::UnknownOp, format!("links are off in this run (build scope concepts): '{o}' is not allowed"), "op")
                    .expected(json!({"ops": CONCEPT_OPS}))
                    .to_json())
            }
            o @ ("link" | "mark_duplicate" | "flag_conflict") => {
                let o = BUILDER_OPS.into_iter().find(|x| *x == o).expect("a builder op");
                let (from, rel, to, b) = match o {
                    "link" => {
                        let rel = f("rel")
                            .and_then(|r| LINK_RELATIONS.into_iter().find(|x| *x == r))
                            .ok_or_else(|| bad(Code::BadField, "unknown relation", "rel").expected(json!({"rel": LINK_RELATIONS})).to_json())?;
                        (rec("from", false)?, rel, rec("to", false)?, basis("basis")?)
                    }
                    "mark_duplicate" => {
                        let (a, b) = (rec("record", true)?, rec("of", false)?);
                        if a.kind != b.kind {
                            return Err(bad(Code::BadField, "a duplicate must be a record of the same kind", "of").to_json());
                        }
                        (a, "duplicate_of", b, vec![a, b])
                    }
                    _ => {
                        let (a, b) = (rec("a", false)?, rec("b", false)?);
                        let mut bs = vec![a, b];
                        if op.get("basis").is_some() {
                            bs.extend(basis("basis")?);
                        }
                        (a, "contradicts", b, bs)
                    }
                };
                if card.pair.is_some() && (![from.id, to.id].iter().all(|id| card.records.iter().any(|r| r.id == *id))) {
                    return Err(bad(Code::BadField, "a pair link connects exactly its OLD and NEW assertions", "from").to_json());
                }
                if super::quality::evolution::is_card(card) {
                    if !matches!(rel, "supersedes" | "qualifies" | "contradicts" | "same_as") || o != "link" {
                        return Err(bad(Code::BadField, "evolution permits four relation types or none", "rel").to_json());
                    }
                    let pair = super::quality::evolution::rows(card)
                        .into_iter()
                        .find(|p| {
                            let old = super::quality::evolution::id(&p["old"]);
                            let new = super::quality::evolution::id(&p["new"]);
                            (Some(from.id) == old && Some(to.id) == new) || (Some(from.id) == new && Some(to.id) == old)
                        })
                        .ok_or_else(|| bad(Code::BadField, "endpoints must be one listed pair", "from").to_json())?;
                    if rel == "supersedes" && Some(from.id) != super::quality::evolution::id(&pair["new"]) {
                        return Err(bad(Code::BadField, "supersedes must run NEW to OLD", "from").to_json());
                    }
                    for end in [from.id, to.id] {
                        let cone = super::pairs::cone(s, &[end]);
                        if !b.iter().any(|r| r.kind == RecordKind::Observe && s.is_grounded(&r.id) && cone.iter().any(|x| x.id == r.id)) {
                            return Err(bad(Code::NoEvidence, "include a shown grounded Observe from each endpoint cone", "basis").to_json());
                        }
                    }
                }
                if from.id == to.id {
                    return Err(bad(Code::BadField, "a link needs two different records", "to").to_json());
                }
                // a link connects assertions; a quote is evidence and is named in basis (live run 10A-4: 493 of 605 links had an
                // observe end, mostly a claim and its own quote, and each one cost a verification task)
                if let Some(x) = [from, to].into_iter().find(|r| !matches!(r.kind, RecordKind::Claim | RecordKind::Hypothesis | RecordKind::Relation)) {
                    let e = bad(
                        Code::BadField,
                        format!("{} is a {}: links connect claims, hypotheses or relations; a quote goes in basis", x.id.short(), x.kind.name()),
                        "from",
                    )
                    .expected(json!({"endpoint_kinds": ["claim", "hypothesis", "relation"]}));
                    return Err(e.to_json());
                }
                if !new.contains_key(&from.id.short()) && !new.contains_key(&to.id.short()) {
                    return Err(bad(Code::BadField, "a link must touch a new record of this card", "from").to_json());
                }
                Ok((json!({"kind": "add_link", "from": hex(&from.id.0), "rel": rel, "to": hex(&to.id.0), "basis": ids(&b)}), Kind::Link(o, rel)))
            }
            other => Err(bad(Code::UnknownOp, format!("unknown op '{other}'"), "op").expected(json!({"ops": BUILDER_OPS})).to_json()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::mem::MemStore;
    use super::*;

    const DOC: &str = "The classifier treats differing validator versions as a warning. Same canonical/hash remains a candidate only.";

    fn store_with_records() -> (MemStore, Vec<RecordId>) {
        let mut s = MemStore::new(&[("r1", DOC)], &["Component", "Rule"]);
        let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
        let a = s.submit_records(
            "w1",
            "T1",
            &scope,
            &[
                json!({"kind": "observe", "local_id": "o1", "doc_id": "r1", "exact_quote": "differing validator versions as a warning", "terms": ["validator version"]}),
                json!({"kind": "claim", "local_id": "c1", "text": "Version differences are only a warning", "subject": "validator version", "predicate": "severity", "object": "warning", "stance": "reported", "based_on": ["o1"]}),
            ],
        );
        let b = s.submit_records(
            "w2",
            "T2",
            &scope,
            &[
                json!({"kind": "observe", "local_id": "o1", "doc_id": "r1", "exact_quote": "treats differing validator versions as a warning", "terms": ["validator versions"]}),
                json!({"kind": "claim", "local_id": "c1", "text": "version differences are only a  warning", "subject": "validator version", "predicate": "severity", "object": "warning", "stance": "reported", "based_on": ["o1"]}),
            ],
        );
        assert!(a.error.is_none() && b.error.is_none());
        (s, [a.accepted, b.accepted].concat())
    }

    #[test]
    fn a_card_shows_new_records_and_the_builder_maps_proposes_and_links() {
        let (mut s, ids) = store_with_records();
        let mut b = Builder::new(BuilderConfig::default());
        let card = b.next_card(&s).unwrap();
        assert_eq!((card.cursor_from, card.cursor_to, card.records.len()), (0, 4, 4));
        assert_eq!(b.next_card(&s).unwrap().card_id, card.card_id, "the open card is handed out again");
        let [o1, c1, o2, c2] = [ids[0], ids[1], ids[2], ids[3]].map(|i| i.short());
        let ops = vec![
            json!({"op": "propose_concept", "type": "Rule", "name": "validator version difference", "aliases": ["validator version", "validator versions"], "basis": [o1]}),
            json!({"op": "map_term", "record": c1, "term": "validator version", "concept": "validator version difference"}),
            json!({"op": "map_term", "record": o2, "term": "validator versions", "concept": "validator version difference"}),
            json!({"op": "mark_duplicate", "record": c2, "of": c1}),
        ];
        let r = b.submit(&mut s, &card.card_id, &ops);
        assert_eq!(r["status"], "CARD_DONE", "{r}");
        assert_eq!(r["results"][3]["status"], "proposed", "a duplicate is never accepted on the builder's word (v0.1 R6)");
        assert!(b.caught_up(&s) && b.next_card(&s).is_none());
        assert_eq!(s.concepts.len(), 1);
        assert_eq!(b.stats.duplicates, 1);
    }

    #[test]
    fn a_restarted_builder_resumes_from_the_durable_checkpoint_and_redoes_nothing() {
        let (mut s, ids) = store_with_records();
        let o1 = ids[0].short();
        let op = json!({"op": "propose_concept", "type": "Rule", "name": "validator version difference", "basis": [o1]});
        // crash after the first operation was committed but before the card closed
        let mut b = Builder::new(BuilderConfig::default());
        let card = b.next_card(&s).unwrap();
        let r = b.submit(&mut s, &card.card_id, &[op.clone(), json!({"op": "map_term", "record": ids[1].short(), "term": "nope", "concept": "x"})]);
        assert_eq!((r["status"].as_str(), r["committed_ops"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{r}");
        let mut b2 = Builder::new(BuilderConfig::default());
        b2.recover(&s);
        assert_eq!(b2.cursor(), 0, "the card never closed");
        let card2 = b2.next_card(&s).unwrap();
        assert_eq!(b2.submit(&mut s, &card2.card_id, &[op])["status"], "CARD_DONE", "the same proposal is idempotent");
        assert_eq!(s.concepts.len(), 1, "nothing was created twice");
        // a third builder after the close starts behind the closed card
        let mut b3 = Builder::new(BuilderConfig::default());
        b3.recover(&s);
        assert_eq!(b3.cursor(), 4);
        assert!(b3.next_card(&s).is_none());
    }

    #[test]
    fn refused_operations_name_the_repair_and_keep_the_card_open() {
        let (mut s, ids) = store_with_records();
        let mut b = Builder::new(BuilderConfig::default());
        let card = b.next_card(&s).unwrap();
        let c1 = ids[1].short();
        for (op, code) in [
            (json!({"op": "map_term", "record": c1, "term": "made up", "concept": "@x"}), "BAD_FIELD"),
            (json!({"op": "map_term", "record": "@0000000000000000", "term": "t", "concept": "@x"}), "UNKNOWN_LOCAL_ID"),
            (json!({"op": "propose_concept", "type": "Person", "name": "x", "basis": [c1]}), "BAD_FIELD"),
            (json!({"op": "propose_concept", "type": "Rule", "name": "x", "basis": []}), "NO_EVIDENCE"),
            (json!({"op": "link", "from": c1, "rel": "causes", "to": c1, "basis": [c1]}), "BAD_FIELD"),
            (json!({"op": "link", "from": c1, "rel": "supports", "to": c1, "basis": [c1]}), "BAD_FIELD"),
            (json!({"op": "rewrite"}), "UNKNOWN_OP"),
        ] {
            let r = b.submit(&mut s, &card.card_id, std::slice::from_ref(&op));
            assert_eq!((r["status"].as_str(), r["error"]["code"].as_str()), (Some("REPAIR_REQUIRED"), Some(code)), "{op}: {r}");
        }
        assert_eq!(b.cursor(), 0, "nothing was closed");
        assert_eq!(b.submit(&mut s, "C9", &[])["code"], "UNKNOWN_CARD");
    }

    #[test]
    fn with_links_off_a_card_only_names_concepts_and_a_link_is_refused() {
        // the build scope `concepts` (the owner's control run of 2026-10-30): `max_links` 0
        let (mut s, ids) = store_with_records();
        let mut b = Builder::new(BuilderConfig { max_links: 0, ..BuilderConfig::default() });
        let card = b.next_card(&s).unwrap();
        let shown = card.to_json();
        assert_eq!((&shown["allowed_ops"], &shown["link_relations"]), (&json!(CONCEPT_OPS), &json!([])));
        let prompt = shown["prompt"].as_str().unwrap();
        for op in ["\"op\":\"link\"", "\"op\":\"mark_duplicate\"", "\"op\":\"flag_conflict\""] {
            assert!(!prompt.contains(op), "{op} in the prompt: {prompt}");
        }
        let [o1, c1, _, c2] = [ids[0], ids[1], ids[2], ids[3]].map(|i| i.short());
        for op in [
            json!({"op": "link", "from": c2, "rel": "supports", "to": c1, "basis": [o1]}),
            json!({"op": "mark_duplicate", "record": c2, "of": c1}),
            json!({"op": "flag_conflict", "a": c1, "b": c2}),
        ] {
            let r = b.submit(&mut s, &card.card_id, std::slice::from_ref(&op));
            assert_eq!((r["status"].as_str(), r["error"]["code"].as_str()), (Some("REPAIR_REQUIRED"), Some("UNKNOWN_OP")), "{op}: {r}");
            assert_eq!(r["error"]["expected_by_kernel"]["ops"], json!(CONCEPT_OPS), "{r}");
        }
        assert!(s.links().is_empty(), "no link was made");
        let ops = [
            json!({"op": "propose_concept", "type": "Rule", "name": "validator version difference", "aliases": ["validator version"], "basis": [o1]}),
            json!({"op": "map_term", "record": c1, "term": "validator version", "concept": "validator version difference"}),
        ];
        assert_eq!(b.submit(&mut s, &card.card_id, &ops)["status"], "CARD_DONE");
        b.prepare_pairs(&s, true);
        assert!(b.pairs.as_ref().is_some_and(Vec::is_empty), "no pair cards: they only link");
        assert!(b.caught_up(&s) && b.next_card(&s).is_none());
    }

    #[test]
    fn an_answer_over_the_operation_limit_is_a_repair_and_stores_nothing() {
        let (mut s, ids) = store_with_records();
        let mut b = Builder::new(BuilderConfig { max_ops: 2, ..Default::default() });
        let card = b.next_card(&s).unwrap();
        let [o1, c1, o2] = [ids[0], ids[1], ids[2]].map(|i| i.short());
        let propose = json!({"op": "propose_concept", "type": "Rule", "name": "validator version difference", "aliases": ["validator version"], "basis": [o1]});
        let map = json!({"op": "map_term", "record": c1, "term": "validator version", "concept": "validator version difference"});
        let over =
            [propose.clone(), map.clone(), json!({"op": "map_term", "record": o2, "term": "validator versions", "concept": "validator version difference"})];
        let head = s.head();
        let r = b.submit(&mut s, &card.card_id, &over);
        assert_eq!((r["status"].as_str(), r["code"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some("TOO_MANY_OPS"), Some(0)), "{r}");
        assert_eq!(
            (r["accepted"].as_u64(), r["committed_ops"].as_u64(), r["error"]["expected_by_kernel"]["max_ops"].as_u64()),
            (Some(0), Some(0), Some(2)),
            "{r}"
        );
        assert_eq!((s.head(), s.concepts.len(), b.cursor()), (head, 0, 0), "nothing was stored and the card stays open");
        assert_eq!(b.next_card(&s).unwrap().card_id, card.card_id);
        let r = b.submit(&mut s, &card.card_id, &[propose, map]);
        assert_eq!(r["status"], "CARD_DONE", "the shorter answer closes the same card: {r}");
        assert!(b.caught_up(&s));
    }

    #[test]
    fn a_link_with_different_words_stays_proposed_and_a_cycle_of_supersedes_is_refused() {
        let (mut s, ids) = store_with_records();
        let mut b = Builder::new(BuilderConfig::default());
        let card = b.next_card(&s).unwrap();
        let (c1, c2) = (ids[1].short(), ids[3].short());
        let back = json!({"op": "link", "from": c1, "rel": "supersedes", "to": c2, "basis": [c1]});
        let r = b.submit(&mut s, &card.card_id, &[json!({"op": "link", "from": c2, "rel": "supersedes", "to": c1, "basis": [c2]}), back.clone()]);
        assert_eq!((r["status"].as_str(), r["failed_index"].as_u64()), (Some("REPAIR_REQUIRED"), Some(1)), "{r}");
        assert_eq!(r["results"][0]["status"], "proposed", "different words: a separate check must confirm it");
        // the builder only touches what its card shows: a later card cannot reach these records
        let r = b.submit(&mut s, &card.card_id, &[]);
        assert_eq!(r["status"], "CARD_DONE");
        let scope = Scope { docs: vec!["r1".into()], ..Default::default() };
        s.submit_records("w3", "T3", &scope, &[json!({"kind": "question", "text": "is it a candidate only?", "about": ["canonical hash"]})]);
        let card2 = b.next_card(&s).unwrap();
        assert_eq!((card2.records.len(), card2.neighbors.len()), (1, 0));
        assert_eq!(b.submit(&mut s, &card2.card_id, &[back])["error"]["code"], "UNKNOWN_LOCAL_ID");
    }
}

mod distribution;
