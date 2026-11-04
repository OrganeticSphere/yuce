//! Ephemeral serialization cache for the unchanged r2r-audit-state/1 preimage.
//! Never persisted. Staged cores share immutable fragments, not mutable cache state.

use super::*;
use std::sync::Arc;

pub(super) type Support = BTreeMap<RecordId, (bool, bool)>;

#[derive(Clone)]
pub(super) struct Cache {
    pub(super) readable: bool,
    pub(super) support: Option<Arc<Support>>,
    /// `quality::stale::suspects` of this state, like the support flags dropped at every command.
    pub(super) stale: Option<Arc<Vec<RecordId>>>,
    hash: Option<Hash>,
    fragments: Arc<Fragments>,
    sections: BTreeMap<&'static str, Arc<str>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self { readable: true, support: None, stale: None, hash: None, fragments: Arc::default(), sections: BTreeMap::new() }
    }
}

#[derive(Clone, Default)]
struct Fragments {
    records: Vec<(RecordId, bool, Arc<str>)>,
    locals: BTreeMap<(String, String, String), Arc<str>>,
    receipts: BTreeMap<(String, String), Arc<str>>,
    decisions: Vec<Arc<str>>,
}

impl Cache {
    // No cached support is consulted while executing a transaction: later lines/operations
    // must see earlier mutations in that same batch, including accepted prefixes.
    pub(super) fn begin(&mut self, command: &Value) {
        self.readable = false;
        self.support = None;
        self.stale = None;
        self.hash = None;
        self.invalidate(command);
    }

    pub(super) fn finish(&mut self) {
        self.readable = true;
        // A new receipt changes the root even if execute failed and its state was rolled back.
        self.hash = None;
    }

    fn invalidate(&mut self, command: &Value) {
        let sections: &[&str] = match command["kind"].as_str() {
            Some("batch") => {
                for op in command["operations"].as_array().into_iter().flatten() {
                    self.invalidate(op);
                }
                if !command["checkpoint"].is_null() {
                    self.sections.remove("checkpoints");
                }
                return;
            }
            Some("submit") => &["ordinals", "links"], // relation records also materialize native links
            Some("checkpoint") => &["checkpoints"],
            Some("put_document") => &["source_documents"],
            Some("revoke") => &[], // record fragments compare newly derived grounding below
            Some("add_link") => &["links"],
            Some("set_link_status") => &["links", "acceptance_basis"],
            Some("map_term") => &["mappings", "ontology"], // a mapping can reattest a concept
            _ => {
                // Ontology operations, including narrowing/mapping moves, and future commands
                // conservatively invalidate every mutable section. Append-only rows are separate.
                self.sections.clear();
                return;
            }
        };
        for section in sections {
            self.sections.remove(section);
        }
    }
}

fn array(out: &mut String, rows: impl IntoIterator<Item = impl AsRef<str>>) {
    out.push('[');
    for (n, row) in rows.into_iter().enumerate() {
        if n != 0 {
            out.push(',');
        }
        out.push_str(row.as_ref());
    }
    out.push(']');
}

impl Core {
    fn cached_preimage(&self) -> String {
        let support = self.support_flags();
        let mut cache = self.cache();
        let Cache { fragments, sections, .. } = &mut *cache;
        let rows = Arc::make_mut(fragments);
        for (n, record) in self.data.records.iter().enumerate() {
            let grounded = support.get(&record.id).is_some_and(|v| v.0);
            let cached = rows.records.get(n);
            if cached.is_some_and(|(id, flag, _)| *id == record.id && *flag == grounded) {
                continue;
            }
            let mut value = record_value(record);
            value["grounded"] = json!(grounded);
            if let Some(b) = self.data.evidence.get(&record.id) {
                value["evidence"] = json!({"id":to_hex(&b.evidence),"version":to_hex(&b.version),"span":[b.start,b.end]});
            }
            let row = (record.id, grounded, Arc::from(to_jcs(&value)));
            if n < rows.records.len() {
                rows.records[n] = row;
            } else {
                rows.records.push(row);
            }
        }
        rows.records.truncate(self.data.records.len());
        // These keys/values and the ingest/decision rows are immutable once committed.
        // In particular a duplicate submission never replaces its historical receipt.
        for (key @ (a, d, l), id) in &self.data.locals {
            rows.locals.entry(key.clone()).or_insert_with(|| Arc::from(to_jcs(&json!([a, d, l, to_hex(&id.0)]))));
        }
        for (key @ (a, id), receipt) in &self.data.receipts {
            rows.receipts.entry(key.clone()).or_insert_with(|| Arc::from(to_jcs(&json!([a, id, to_hex(&receipt.request_hash), receipt.outcome.value()]))));
        }
        for decision in &self.data.decisions[rows.decisions.len()..] {
            rows.decisions.push(Arc::from(to_jcs(decision)));
        }

        // Top-level member order is the UTF-16/JCS order of the unchanged /1 projection.
        // Every nested value still goes through the existing canonical serializer.
        let keys = [
            "acceptance_basis",
            "checkpoints",
            "decisions",
            "format",
            "links",
            "locals",
            "manifest_hash",
            "mappings",
            "ontology",
            "ordinals",
            "receipts",
            "records",
            "run_id",
            "source_documents",
            "source_mode",
        ];
        let mut out = String::new();
        out.push('{');
        for (n, key) in keys.into_iter().enumerate() {
            if n != 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(key);
            out.push_str("\":");
            match key {
                "records" => array(&mut out, rows.records.iter().map(|(_, _, v)| v)),
                "locals" => array(&mut out, rows.locals.values()),
                "receipts" => array(&mut out, rows.receipts.values()),
                "decisions" => array(&mut out, &rows.decisions),
                _ => {
                    let part = sections.entry(key).or_insert_with(|| {
                        let value = match key {
                            "format" => json!("r2r-audit-state/1"),
                            "run_id" => json!(self.data.run_id),
                            "manifest_hash" => json!(to_hex(&self.data.manifest_hash)),
                            "source_mode" => json!(self.data.source_mode),
                            "source_documents" => json!(self.data.source_documents),
                            "ontology" => self.data.ontology.to_value(),
                            "mappings" => json!(self.data.mappings.iter().map(|((r, t, c), s)| json!([to_hex(&r.0), t, to_hex(&c.0), s])).collect::<Vec<_>>()),
                            "links" => json!(self.data.links.values().map(link_value).collect::<Vec<_>>()),
                            "ordinals" => json!(self.data.task_ordinals.iter().map(|((a, d), n)| json!([a, d, n])).collect::<Vec<_>>()),
                            "acceptance_basis" => json!(self
                                .data
                                .acceptance_basis
                                .iter()
                                .map(|(id, p)| json!([to_hex(&id.0), p.iter().map(|r| to_hex(&r.0)).collect::<Vec<_>>()]))
                                .collect::<Vec<_>>()),
                            "checkpoints" => json!(self.data.checkpoints),
                            _ => unreachable!("fixed /1 member"),
                        };
                        Arc::from(to_jcs(&value))
                    });
                    out.push_str(part);
                }
            }
        }
        out.push('}');
        out
    }

    pub(super) fn root(&self) -> Hash {
        #[cfg(feature = "audit-root-profile")]
        let started = std::time::Instant::now();
        #[cfg(feature = "audit-root-profile")]
        let legacy = profile::LEGACY.load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(feature = "audit-root-profile"))]
        let legacy = false;
        let cached = self.cache().hash;
        let root = if legacy {
            #[cfg(feature = "audit-root-profile")]
            {
                sha256_parts(&[b"R2R-AUDIT-STATE/1", self.legacy_preimage().as_bytes()])
            }
            #[cfg(not(feature = "audit-root-profile"))]
            {
                unreachable!()
            }
        } else if let Some(root) = cached {
            root
        } else {
            let preimage = self.cached_preimage();
            #[cfg(any(test, feature = "audit-root-verify"))]
            {
                let expected = self.legacy_preimage();
                if preimage != expected {
                    let actual: Value = serde_json::from_str(&preimage).expect("cached JSON");
                    let legacy: Value = serde_json::from_str(&expected).expect("legacy JSON");
                    let fields: Vec<_> = legacy.as_object().expect("object").keys().filter(|k| actual[*k] != legacy[*k]).collect();
                    panic!("audit /1 preimage diverged in {fields:?}; cached {} B, legacy {} B", preimage.len(), expected.len());
                }
            }
            let root = sha256_parts(&[b"R2R-AUDIT-STATE/1", preimage.as_bytes()]);
            self.cache().hash = Some(root);
            root
        };
        #[cfg(any(test, feature = "audit-root-verify"))]
        assert_eq!(root, sha256_parts(&[b"R2R-AUDIT-STATE/1", self.legacy_preimage().as_bytes()]), "audit /1 root diverged");
        #[cfg(feature = "audit-root-profile")]
        profile::record(started.elapsed());
        root
    }
}

#[cfg(feature = "audit-root-profile")]
mod profile {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    pub(super) static LEGACY: AtomicBool = AtomicBool::new(false);
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static NANOS: AtomicU64 = AtomicU64::new(0);
    pub(super) fn record(elapsed: std::time::Duration) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        NANOS.fetch_add(elapsed.as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
    }
    impl super::AuditState {
        /// Offline profiling only. Set before opening an isolated archive in a fresh process.
        #[doc(hidden)]
        pub fn root_profile_begin(legacy: bool) {
            LEGACY.store(legacy, Ordering::Relaxed);
            CALLS.store(0, Ordering::Relaxed);
            NANOS.store(0, Ordering::Relaxed);
        }
        #[doc(hidden)]
        pub fn root_profile_snapshot() -> (u64, u64) {
            (CALLS.load(Ordering::Relaxed), NANOS.load(Ordering::Relaxed))
        }
    }
}

#[cfg(test)]
#[path = "root_cache_tests.rs"]
mod tests;
