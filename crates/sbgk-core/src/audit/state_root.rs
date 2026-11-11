//! `r2r-state-root/2`: the root of the primary audit state of a `/3` journal (SPEC_V02_STEP2 section 3).
//!
//! Every value of the state is one leaf, `H("R2R-STATE-LEAF/2", lp(section), lp(key), value)`, in one of thirteen named sections.
//! A section spreads its leaves over 256 buckets by the first byte of the key hash; a bucket hashes its leaves in key-hash order,
//! a section its 256 buckets, the root its sections in a fixed order. A command rehashes the leaves it changed, their buckets and
//! their sections, not the state: what `r2r-audit-state/1` cost per command grew with the run.
//!
//! Derived values are not leaves: whether a record still stands is the status projection's, so one withdrawal does not touch the
//! leaves of every record that rested on it. The withdrawn text is a leaf, by its hash: it decides whether a new quote is taken.
//!
//! Records, receipts, local names and decisions are only ever appended; the other sections are keyed and change in place. Every
//! place that changes a keyed value names its key in `Dirty`, and the ontology, which changes through many methods, is rebuilt
//! after any command that may change it. Tests and the `audit-root-verify` build compare the incremental root with one built
//! from the whole state at every step, so a change that names no key fails there.

use super::*;
use std::sync::Arc;

pub(super) const ROOT_FORMAT: &str = "r2r-state-root/2";

pub(super) const SECTIONS: [&str; 13] = [
    "meta",
    "source_documents",
    "ontology",
    "records",
    "locals",
    "ordinals",
    "mappings",
    "links",
    "acceptance_basis",
    "decisions",
    "receipts",
    "checkpoints",
    "withdrawn",
];

const META: usize = 0;
const SOURCES: usize = 1;
const ONTOLOGY: usize = 2;
const RECORDS: usize = 3;
const LOCALS: usize = 4;
const ORDINALS: usize = 5;
const MAPPINGS: usize = 6;
const LINKS: usize = 7;
const ACCEPTANCE: usize = 8;
const DECISIONS: usize = 9;
const RECEIPTS: usize = 10;
const CHECKPOINTS: usize = 11;
const WITHDRAWN: usize = 12;

/// The command kinds that never change the ontology (`root_cache::Cache::invalidate` reads them the same way); any other kind may.
const LEAVES_ONTOLOGY: [&str; 6] = ["submit", "checkpoint", "put_document", "revoke", "add_link", "set_link_status"];

/// The keys of the keyed sections changed since the tree last saw the state.
#[derive(Clone, Debug, Default)]
pub(super) struct Dirty {
    pub(super) sources: BTreeSet<String>,
    pub(super) locals: BTreeSet<(String, String, String)>,
    pub(super) ordinals: BTreeSet<(String, String)>,
    pub(super) mappings: BTreeSet<(RecordId, String, ConceptId)>,
    pub(super) links: BTreeSet<LinkId>,
    pub(super) acceptance: BTreeSet<LinkId>,
    pub(super) receipts: BTreeSet<(String, String)>,
    pub(super) checkpoints: BTreeSet<String>,
    pub(super) withdrawn: BTreeSet<(String, Hash)>,
    pub(super) ontology: bool,
    /// The members of `meta` that can change after the genesis: `closed`.
    pub(super) meta: bool,
}

#[derive(Clone)]
struct Section {
    buckets: Vec<Arc<BTreeMap<Hash, Hash>>>,
    hashes: Vec<Hash>,
    stale: BTreeSet<u8>,
    root: Hash,
}

/// The tree of one state, kept beside it and copied with it; the copy shares the buckets it does not change.
#[derive(Clone)]
pub(super) struct StateTree {
    sections: Vec<Section>,
    records_seen: usize,
    decisions_seen: usize,
    pub(super) dirty: Dirty,
    root: Option<Hash>,
}

fn lp(bytes: &[u8]) -> [u8; 4] {
    u32::try_from(bytes.len()).expect("a part of a state leaf under 4 GiB").to_be_bytes()
}

fn key_hash(section: usize, key: &str) -> Hash {
    let name = SECTIONS[section].as_bytes();
    sha256_parts(&[b"R2R-STATE-KEY/2\0", &lp(name), name, key.as_bytes()])
}

fn leaf(section: usize, key: &str, value: &str) -> Hash {
    let name = SECTIONS[section].as_bytes();
    sha256_parts(&[b"R2R-STATE-LEAF/2\0", &lp(name), name, &lp(key.as_bytes()), key.as_bytes(), value.as_bytes()])
}

fn bucket_hash(section: usize, index: u8, leaves: &BTreeMap<Hash, Hash>) -> Hash {
    let name = SECTIONS[section].as_bytes();
    sha256_stream(|out| {
        out(b"R2R-STATE-BUCKET/2\0");
        out(&lp(name));
        out(name);
        out(&[index]);
        for (kh, leaf) in leaves {
            out(kh);
            out(leaf);
        }
    })
}

fn section_root(section: usize, hashes: &[Hash]) -> Hash {
    let name = SECTIONS[section].as_bytes();
    sha256_stream(|out| {
        out(b"R2R-STATE-SECTION/2\0");
        out(&lp(name));
        out(name);
        for hash in hashes {
            out(hash);
        }
    })
}

impl Section {
    fn empty(section: usize) -> Self {
        let empty = Arc::new(BTreeMap::new());
        let hashes: Vec<Hash> = (0..=255u8).map(|b| bucket_hash(section, b, &empty)).collect();
        Self { root: section_root(section, &hashes), buckets: vec![empty; 256], hashes, stale: BTreeSet::new() }
    }
}

/// The bindings of a record's evidence, as the records tree and the records section both write them.
fn evidence_value(b: &EvidenceBinding) -> Value {
    json!({"id": to_hex(&b.evidence), "version": to_hex(&b.version), "span": [b.start, b.end]})
}

/// `L` of SPEC_V02_STEP2 section 2: the record as `/1` wrote it, without `grounded`, with its own evidence binding and the
/// binding of every ground, in the order of `based_on`. One such value names a claim with all it rests on.
pub(super) fn record_leaf_value(data: &Data, r: &RecordView) -> Value {
    let mut value = record_value(r);
    if let Some(b) = data.evidence.get(&r.id) {
        value["evidence"] = evidence_value(b);
    }
    if !r.based_on.is_empty() {
        value["grounds"] = json!(r
            .based_on
            .iter()
            .map(|g| match data.evidence.get(g) {
                Some(b) => json!({"id": to_hex(&g.0), "evidence": evidence_value(b)}),
                None => json!({"id": to_hex(&g.0)}),
            })
            .collect::<Vec<_>>());
    }
    value
}

/// Whether `command` may change the ontology: a kind outside `LEAVES_ONTOLOGY`, or a batch holding one.
pub(super) fn may_change_ontology(command: &Value) -> bool {
    match command["kind"].as_str() {
        Some("batch") => command["operations"].as_array().into_iter().flatten().any(may_change_ontology),
        Some(kind) => !LEAVES_ONTOLOGY.contains(&kind),
        None => true,
    }
}

impl StateTree {
    /// The tree of `data`, built from every value.
    pub(super) fn build(data: &Data) -> Self {
        let mut tree =
            Self { sections: (0..SECTIONS.len()).map(Section::empty).collect(), records_seen: 0, decisions_seen: 0, dirty: Dirty::default(), root: None };
        tree.put(META, &to_jcs(&json!("manifest_hash")), Some(&to_jcs(&json!(to_hex(&data.manifest_hash)))));
        tree.put(META, &to_jcs(&json!("run_id")), Some(&to_jcs(&json!(data.run_id))));
        tree.put(META, &to_jcs(&json!("source_mode")), Some(&to_jcs(&json!(data.source_mode))));
        tree.dirty.meta = true;
        tree.dirty.sources = data.source_documents.keys().cloned().collect();
        tree.dirty.locals = data.locals.keys().cloned().collect();
        tree.dirty.ordinals = data.task_ordinals.keys().cloned().collect();
        tree.dirty.mappings = data.mappings.keys().cloned().collect();
        tree.dirty.links = data.links.keys().copied().collect();
        tree.dirty.acceptance = data.acceptance_basis.keys().copied().collect();
        tree.dirty.receipts = data.receipts.keys().cloned().collect();
        tree.dirty.checkpoints = data.checkpoints.keys().cloned().collect();
        tree.dirty.withdrawn = data.withdrawn.iter().flat_map(|(d, texts)| texts.iter().map(move |t| (d.clone(), sha256(t)))).collect();
        tree.dirty.ontology = true;
        tree.sync(data);
        tree
    }

    fn put(&mut self, section: usize, key: &str, value: Option<&str>) {
        let kh = key_hash(section, key);
        let s = &mut self.sections[section];
        let bucket = Arc::make_mut(&mut s.buckets[kh[0] as usize]);
        match value {
            Some(value) => bucket.insert(kh, leaf(section, key, value)),
            None => bucket.remove(&kh),
        };
        s.stale.insert(kh[0]);
        self.root = None;
    }

    /// Mark a command that may change the ontology (`may_change_ontology`) before it runs.
    pub(super) fn begin(&mut self, command: &Value) {
        if may_change_ontology(command) {
            self.dirty.ontology = true;
        }
    }

    /// Bring the tree to `data`: the appended records and decisions, the keys `dirty` names, the ontology when marked.
    pub(super) fn sync(&mut self, data: &Data) {
        for r in &data.records[self.records_seen.min(data.records.len())..] {
            self.put(RECORDS, &to_jcs(&json!(to_hex(&r.id.0))), Some(&to_jcs(&record_leaf_value(data, r))));
        }
        self.records_seen = data.records.len();
        for (n, d) in data.decisions.iter().enumerate().skip(self.decisions_seen) {
            self.put(DECISIONS, &to_jcs(&json!(n)), Some(&to_jcs(d)));
        }
        self.decisions_seen = data.decisions.len();
        let dirty = std::mem::take(&mut self.dirty);
        for id in &dirty.sources {
            self.put(SOURCES, &to_jcs(&json!(id)), data.source_documents.get(id).map(to_jcs).as_deref());
        }
        for key @ (a, d, l) in &dirty.locals {
            self.put(LOCALS, &to_jcs(&json!([a, d, l])), data.locals.get(key).map(|id| to_jcs(&json!(to_hex(&id.0)))).as_deref());
        }
        for key @ (a, d) in &dirty.ordinals {
            self.put(ORDINALS, &to_jcs(&json!([a, d])), data.task_ordinals.get(key).map(|n| to_jcs(&json!(n))).as_deref());
        }
        for key @ (r, t, c) in &dirty.mappings {
            self.put(MAPPINGS, &to_jcs(&json!([to_hex(&r.0), t, to_hex(&c.0)])), data.mappings.get(key).map(|s| to_jcs(&json!(s))).as_deref());
        }
        for id in &dirty.links {
            self.put(LINKS, &to_jcs(&json!(to_hex(&id.0))), data.links.get(id).map(|l| to_jcs(&link_value(l))).as_deref());
        }
        for id in &dirty.acceptance {
            let value = data.acceptance_basis.get(id).map(|basis| to_jcs(&json!(basis.iter().map(|r| to_hex(&r.0)).collect::<Vec<_>>())));
            self.put(ACCEPTANCE, &to_jcs(&json!(to_hex(&id.0))), value.as_deref());
        }
        for key @ (a, id) in &dirty.receipts {
            let value = data.receipts.get(key).map(|r| to_jcs(&json!([to_hex(&r.request_hash), r.outcome.value()])));
            self.put(RECEIPTS, &to_jcs(&json!([a, id])), value.as_deref());
        }
        for key in &dirty.checkpoints {
            self.put(CHECKPOINTS, &to_jcs(&json!(key)), data.checkpoints.get(key).map(to_jcs).as_deref());
        }
        for (doc, text_hash) in &dirty.withdrawn {
            let present = data.withdrawn.get(doc).is_some_and(|texts| texts.iter().any(|t| sha256(t) == *text_hash));
            self.put(WITHDRAWN, &to_jcs(&json!([doc, to_hex(text_hash)])), present.then_some("1"));
        }
        if dirty.meta {
            // a run closed by a `close` entry; an open run has no such leaf
            self.put(META, &to_jcs(&json!("closed")), data.closed.then_some("true"));
        }
        if dirty.ontology {
            self.rebuild_ontology(data);
        }
    }

    /// The ontology section anew: its scalar members by name, its concepts by id.
    fn rebuild_ontology(&mut self, data: &Data) {
        let fresh = Section::empty(ONTOLOGY);
        self.sections[ONTOLOGY] = fresh;
        let value = data.ontology.to_value();
        if let Some(members) = value.as_object() {
            for (name, member) in members {
                if name == "concepts" {
                    for concept in member.as_array().into_iter().flatten() {
                        let id = concept["id"].as_str().unwrap_or_default();
                        self.put(ONTOLOGY, &to_jcs(&json!(["concept", id])), Some(&to_jcs(concept)));
                    }
                } else {
                    self.put(ONTOLOGY, &to_jcs(&json!(name)), Some(&to_jcs(member)));
                }
            }
        }
        self.root = None;
    }

    /// The root over the sections, rehashing the stale buckets first.
    pub(super) fn root(&mut self) -> Hash {
        if let Some(root) = self.root {
            return root;
        }
        for (n, s) in self.sections.iter_mut().enumerate() {
            if s.stale.is_empty() {
                continue;
            }
            for b in std::mem::take(&mut s.stale) {
                s.hashes[b as usize] = bucket_hash(n, b, &s.buckets[b as usize]);
            }
            s.root = section_root(n, &s.hashes);
        }
        let roots: Vec<Hash> = self.sections.iter().map(|s| s.root).collect();
        let root = root_over(&roots);
        self.root = Some(root);
        root
    }
}

/// The state root over the roots of the sections, in their order: `H("R2R-STATE-ROOT/2", (lp(name), name, root)...)`.
fn root_over(section_roots: &[Hash]) -> Hash {
    sha256_stream(|out| {
        out(b"R2R-STATE-ROOT/2\0");
        for (n, root) in section_roots.iter().enumerate() {
            let name = SECTIONS[n].as_bytes();
            out(&lp(name));
            out(name);
            out(root);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_section_differs_by_name_and_a_leaf_moves_its_bucket_only() {
        let a = Section::empty(META);
        let b = Section::empty(RECORDS);
        assert_ne!(a.root, b.root);
        let mut tree =
            StateTree { sections: (0..SECTIONS.len()).map(Section::empty).collect(), records_seen: 0, decisions_seen: 0, dirty: Dirty::default(), root: None };
        let before = tree.root();
        let copy = tree.clone();
        tree.put(CHECKPOINTS, "\"k\"", Some("1"));
        let one = tree.root();
        assert_ne!(one, before);
        tree.put(CHECKPOINTS, "\"k\"", Some("2"));
        assert_ne!(tree.root(), one);
        tree.put(CHECKPOINTS, "\"k\"", None);
        assert_eq!(tree.root(), before, "removing the only leaf restores the empty section");
        let mut other = copy;
        assert_eq!(other.root(), before, "a copy keeps its own buckets");
        // the same key and value in another section is another leaf
        other.put(LINKS, "\"k\"", Some("1"));
        let mut third =
            StateTree { sections: (0..SECTIONS.len()).map(Section::empty).collect(), records_seen: 0, decisions_seen: 0, dirty: Dirty::default(), root: None };
        third.put(CHECKPOINTS, "\"k\"", Some("1"));
        assert_ne!(other.root(), third.root());
    }

    /// The vectors of an independent implementation of the specification (SBGK/SPEC_V02_STEP2, sections 0 and 3).
    #[test]
    fn the_state_root_matches_the_vectors_of_an_independent_implementation() {
        let mut tree =
            StateTree { sections: (0..SECTIONS.len()).map(Section::empty).collect(), records_seen: 0, decisions_seen: 0, dirty: Dirty::default(), root: None };
        assert_eq!(to_hex(&tree.root()), "b556e673e5dbadeb5200567af4cabbe567b5df849e56a5855059c861a9b15e99");
        tree.put(CHECKPOINTS, "\"k\"", Some("1"));
        assert_eq!(to_hex(&tree.root()), "f15a3ea89a48027f9efdab09899119438855dac1163714f384a1a7af757ed054");
        assert_eq!(to_hex(&super::settings_hash(&json!({}))), "6b3606913caec5aaa55cef68c181172fc5a8ce84ba9a3574311b1c6f5a03a73e");
    }
}

/// The vectors another session computed from the text of SPEC_V02_STEP2 alone, without this code, for the independent verifier
/// `yuce-verify` (SBGK/VECTORS_INDEPENDENT_VERIFIER_20261110.json, V5 and V6): the kernel's own functions must give them.
#[cfg(test)]
mod spec_text_vectors {
    use super::*;
    use crate::hash::to_hex;

    #[test]
    fn the_state_root_gives_the_vectors_written_from_the_spec_text() {
        let withdrawn = SECTIONS.iter().position(|s| *s == "withdrawn").unwrap();
        let empty: Vec<Section> = (0..SECTIONS.len()).map(Section::empty).collect();
        assert_eq!(to_hex(&bucket_hash(META, 0, &BTreeMap::new())), "1c6cdbb266d0260bd4b04ce1e9eadbd16494e40891adf3ad162fa5a9828d5cb6");
        assert_eq!(to_hex(&empty[META].root), "4a7b45a454c3180a968b4f38966412ba22ebbf53499e033b9d97b66afcdfa2ba");
        assert_eq!(to_hex(&empty[withdrawn].root), "e85d6d838983ee31cf9e31d7d7441938a9fb9ef27df8b0b152e047793d78a78d");
        let mut roots: Vec<Hash> = empty.iter().map(|s| s.root).collect();
        assert_eq!(to_hex(&root_over(&roots)), "b556e673e5dbadeb5200567af4cabbe567b5df849e56a5855059c861a9b15e99");
        // one leaf in `meta`, its key and value as JCS texts
        let (key, value) = ("\"run_id\"", "\"vector-run\"");
        let kh = key_hash(META, key);
        assert_eq!((to_hex(&kh).as_str(), kh[0]), ("ec29e20c74d605ecabc16e1d26973e4990a130bb8f2757cf05d7019cd3630ca2", 236));
        let one = leaf(META, key, value);
        assert_eq!(to_hex(&one), "179ee8c007329c42e5e5eca7e239e29b9270110676d658930440dc4adc14c6ce");
        let mut hashes = empty[META].hashes.clone();
        hashes[kh[0] as usize] = bucket_hash(META, kh[0], &BTreeMap::from([(kh, one)]));
        roots[META] = section_root(META, &hashes);
        assert_eq!(to_hex(&roots[META]), "2d43f69bb24904fa5b04b35be09496074658a1e5dfaab1266fdc5026464403c3");
        assert_eq!(to_hex(&root_over(&roots)), "6102326a854af6dbcd524b7d0f8b0834ee9f3e79c0dded78925323c092a34741");
    }
}
