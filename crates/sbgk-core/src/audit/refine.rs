//! Circles +1: after the swarm's BUILD of every circle, the swarm's independent graph builder, a fixed
//! role outside the ring, refines the one graph. Its card is an ordinary record card from its own cursor, shown with what the
//! swarm already mapped and linked for those records, so it adds and corrects instead of building again.
use super::builder::Card;
use super::AuditStore;
use serde_json::{json, Value};

pub const PROMPT: &str = "REFINE_CARD: you are the swarm's independent graph builder with a fixed role. The swarm has already built the graph for \
these records: EXISTING lists, for every record, the concepts its terms are mapped to and the links that touch it. Do not repeat them. \
Add what is missing and correct what is wrong: map a term the swarm left unmapped or that also names another shown concept, propose a \
concept only when no candidate fits, link records across reports (neighbors include earlier circles), mark duplicates, flag conflicts, \
and where the shown records ground it propose revise_concept. Answer [] when nothing is missing.\n";

/// What the swarm built for the card's records: every mapping of their terms and every link touching them.
pub fn overlay<S: AuditStore>(s: &S, card: &Card) -> Value {
    json!(card
        .records
        .iter()
        .map(|r| {
            let mapped = s
                .concepts_of(&r.id)
                .into_iter()
                .flat_map(|c| {
                    let name = s.concept(&c).map(|v| v.name).unwrap_or_default();
                    s.mapped_terms_of(&c)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|(id, _)| *id == r.id)
                        .map(move |(_, term)| json!({"term":term,"concept":format!("{} {}", c.short(), name)}))
                })
                .collect::<Vec<_>>();
            let links = s
                .links_of(&r.id)
                .into_iter()
                .map(|l| json!({"from":l.from.short(),"rel":l.rel,"to":l.to.short(),"status":l.status.name()}))
                .collect::<Vec<_>>();
            json!({"record":r.id.short(),"mapped":mapped,"links":links})
        })
        .collect::<Vec<_>>())
}
