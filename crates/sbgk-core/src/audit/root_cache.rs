//! Ephemeral serialization cache for the unchanged r2r-audit-state/1 preimage.
//! Never persisted. Staged cores share immutable fragments, not mutable cache state.

use super::*;
use std::sync::Arc;

pub(super) type Support = ById<(bool, bool)>;

#[derive(Clone)]
pub(super) struct Cache {
    pub(super) readable: bool,
    pub(super) support: Option<Arc<Support>>,
    /// `quality::stale::suspects` of this state, dropped at every command: unlike the support flags it reads the checkpoints.
    pub(super) stale: Option<Arc<Vec<RecordId>>>,
    hash: Option<Hash>,
    fragments: Arc<Fragments>,
    /// The `"key":value` member of each checkpoint, dropped when that key is written: most commands of a run write one checkpoint,
    /// and the others stay as they were.
    checkpoints: Arc<BTreeMap<String, Arc<str>>>,
    sections: BTreeMap<&'static str, Arc<str>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self { readable: true, support: None, stale: None, hash: None, fragments: Arc::default(), checkpoints: Arc::default(), sections: BTreeMap::new() }
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
    // must see earlier mutations in that same batch, including accepted prefixes. The flags of a state
    // are kept for its successor only by a command of checkpoints, which changes nothing they read.
    pub(super) fn begin(&mut self, command: &Value) {
        self.readable = false;
        if !checkpoints_alone(command) {
            self.support = None;
        }
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
                    self.checkpoint_written(&command["checkpoint"]);
                }
                return;
            }
            Some("submit") => &["ordinals", "links"], // relation records also materialize native links
            Some("checkpoint") => {
                self.checkpoint_written(command);
                return;
            }
            Some("put_document") => &["source_documents"],
            Some("revoke") => &[], // record fragments compare newly derived grounding below
            Some("add_link") => &["links"],
            Some("set_link_status") => &["links", "acceptance_basis"],
            Some("map_term") => &["mappings", "ontology"], // a mapping can reattest a concept
            _ => {
                // Ontology operations, including narrowing/mapping moves, and future commands
                // conservatively invalidate every mutable section. Append-only rows are separate.
                self.sections.clear();
                self.checkpoints = Arc::default();
                return;
            }
        };
        for section in sections {
            self.sections.remove(section);
        }
    }

    fn checkpoint_written(&mut self, checkpoint: &Value) {
        self.sections.remove("checkpoints");
        match checkpoint["key"].as_str() {
            Some(key) => {
                Arc::make_mut(&mut self.checkpoints).remove(key);
            }
            None => self.checkpoints = Arc::default(),
        }
    }
}

/// A command that can change only `Data::checkpoints` (and its own receipt) when it succeeds, and nothing when it fails.
fn checkpoints_alone(command: &Value) -> bool {
    match command["kind"].as_str() {
        Some("checkpoint") => true,
        Some("batch") => command["operations"].as_array().is_some_and(|operations| operations.iter().all(|op| op["kind"] == "checkpoint")),
        _ => false,
    }
}

/// Add the rows of the keys of `data` that `rows` lacks. `rows` holds no other key, and both maps are in key order: one walk finds
/// them, and a map of equal length has none to add.
fn fill<K: Ord + Clone, V>(rows: &mut BTreeMap<K, Arc<str>>, data: &BTreeMap<K, V>, row: impl Fn(&K, &V) -> Arc<str>) {
    if rows.len() == data.len() {
        return;
    }
    let mut known = rows.keys().peekable();
    let missing: Vec<_> = data.iter().filter(|(key, _)| known.next_if_eq(key).is_none()).map(|(key, value)| (key.clone(), row(key, value))).collect();
    rows.extend(missing);
}

/// The JSON object of the checkpoints, from their rows. JCS orders members by UTF-16 code units, the map by bytes.
fn checkpoints_object(rows: &BTreeMap<String, Arc<str>>) -> Arc<str> {
    let mut members: Vec<_> = rows.iter().collect();
    members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    let mut object = String::with_capacity(rows.values().map(|row| row.len() + 1).sum::<usize>() + 2);
    object.push('{');
    for (n, (_, row)) in members.into_iter().enumerate() {
        if n != 0 {
            object.push(',');
        }
        object.push_str(row);
    }
    object.push('}');
    Arc::from(object)
}

fn array(out: &mut dyn FnMut(&[u8]), rows: impl IntoIterator<Item = impl AsRef<str>>) {
    out(b"[");
    for (n, row) in rows.into_iter().enumerate() {
        if n != 0 {
            out(b",");
        }
        out(row.as_ref().as_bytes());
    }
    out(b"]");
}

impl Core {
    /// The r2r-audit-state/1 preimage, handed to `out` piece by piece and in order: a root hashes the pieces as they come, and the
    /// megabytes of a long run are not put together in a string first.
    fn write_preimage(&self, out: &mut dyn FnMut(&[u8])) {
        let support = self.support_flags();
        let mut cache = self.cache();
        let Cache { fragments, checkpoints, sections, .. } = &mut *cache;
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
        fill(&mut rows.locals, &self.data.locals, |(a, d, l), id| Arc::from(to_jcs(&json!([a, d, l, to_hex(&id.0)]))));
        fill(&mut rows.receipts, &self.data.receipts, |(a, id), receipt| {
            Arc::from(to_jcs(&json!([a, id, to_hex(&receipt.request_hash), receipt.outcome.value()])))
        });
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
        out(b"{");
        for (n, key) in keys.into_iter().enumerate() {
            if n != 0 {
                out(b",");
            }
            out(b"\"");
            out(key.as_bytes());
            out(b"\":");
            match key {
                "records" => array(out, rows.records.iter().map(|(_, _, v)| v)),
                "locals" => array(out, rows.locals.values()),
                "receipts" => array(out, rows.receipts.values()),
                "decisions" => array(out, &rows.decisions),
                "checkpoints" => {
                    let part = sections.entry(key).or_insert_with(|| {
                        let rows = Arc::make_mut(checkpoints);
                        fill(rows, &self.data.checkpoints, |key, value| Arc::from(format!("{}:{}", to_jcs(&json!(key)), to_jcs(value))));
                        checkpoints_object(rows)
                    });
                    out(part.as_bytes());
                }
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
                            _ => unreachable!("fixed /1 member"),
                        };
                        Arc::from(to_jcs(&value))
                    });
                    out(part.as_bytes());
                }
            }
        }
        out(b"}");
    }

    #[cfg(any(test, feature = "audit-root-verify"))]
    fn cached_preimage(&self) -> String {
        let mut preimage = Vec::new();
        self.write_preimage(&mut |piece| preimage.extend_from_slice(piece));
        String::from_utf8(preimage).expect("pieces of a UTF-8 preimage")
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
            #[cfg(any(test, feature = "audit-root-verify"))]
            {
                let preimage = self.cached_preimage();
                let expected = self.legacy_preimage();
                if preimage != expected {
                    let actual: Value = serde_json::from_str(&preimage).expect("cached JSON");
                    let legacy: Value = serde_json::from_str(&expected).expect("legacy JSON");
                    let fields: Vec<_> = legacy.as_object().expect("object").keys().filter(|k| actual[*k] != legacy[*k]).collect();
                    panic!("audit /1 preimage diverged in {fields:?}; cached {} B, legacy {} B", preimage.len(), expected.len());
                }
            }
            let root = sha256_stream(|out| {
                out(b"R2R-AUDIT-STATE/1");
                self.write_preimage(out);
            });
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
