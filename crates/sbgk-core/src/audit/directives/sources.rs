//! A source that gets other bytes while the run goes on (0.3.0: a journal that takes its sources as they come puts a new version
//! of a document under the name it has). The work of reading is keyed by the document and the number of its section, and a key
//! done once was done for ever: the new bytes got no reading (Codex review of b27625da, finding 2).
//!
//! The reading of a document that was ever given other bytes names the version it was issued on, in its completion checkpoint
//! (`source_version`), and is over for that version alone. A live dispatcher and one recovered from the journal read the same
//! checkpoint, so they agree on what is open; and a reading of other bytes is open work for every reader of the open work, the
//! completion of the run among them, before any agent asks for a task. A document that keeps the bytes it came with has no such
//! mark: its checkpoints are what 0.2 wrote, byte for byte.
//!
//! Not given again: a reading given up as unresolved before the new bytes came, and the packs of the gap pass over the earlier
//! bytes.
//!
//! A decision of the dispatcher only, as the reading units are (`units.rs`): no rule of the journal replays it.

use super::*;

/// In the completion checkpoint of a reading: the version of the bytes it was issued on, in hex (`AuditStore::doc_stamp`; of a
/// zone, the hash of the versions of its documents in their order).
pub(crate) const SOURCE_VERSION: &str = "source_version";

/// The documents the reading of `key` reads: the document of a first reading `doc:<doc>#<k>` and of its loss reread
/// `reread:<doc>#<k>`, the documents of `zone:<n>`. No other key is a reading of documents by their bytes.
fn reading_docs(zones: &[Vec<String>], key: &str) -> Vec<String> {
    if let Some(n) = key.strip_prefix("zone:").and_then(|n| n.parse::<usize>().ok()) {
        return zones.get(n).cloned().unwrap_or_default();
    }
    let section = key.strip_prefix("doc:").or_else(|| key.strip_prefix("reread:"));
    section.and_then(|rest| rest.rsplit_once('#')).map(|(doc, _)| vec![doc.to_string()]).unwrap_or_default()
}

/// The version of the bytes these documents have now; `None` from a store that stamps none, and for no document.
fn version_of<S: AuditStore>(s: &S, docs: &[String]) -> Option<String> {
    let stamps: Vec<Hash> = docs.iter().map(|d| s.doc_stamp(d)).collect::<Option<_>>()?;
    match stamps.as_slice() {
        [] => None,
        [one] => Some(crate::hash::to_hex(one)),
        many => Some(crate::hash::to_hex(&crate::hash::sha256_parts(&many.iter().map(|h| h.as_slice()).collect::<Vec<_>>()))),
    }
}

/// Whether the completion checkpoint of the reading `key`, whose context is `context`, is of the bytes its documents have now.
/// Always for documents that were never given other bytes; else only when the checkpoint names the present version.
pub(crate) fn reading_current<S: AuditStore>(s: &S, zones: &[Vec<String>], key: &str, context: &Value) -> bool {
    let docs = reading_docs(zones, key);
    if !docs.iter().any(|d| s.doc_replaced(d)) {
        return true;
    }
    context[SOURCE_VERSION].as_str().map(str::to_string) == version_of(s, &docs)
}

impl Dispatcher {
    /// The version of the bytes a reading is issued on, kept in its lease: its answer is of those bytes, whatever the document
    /// has when the answer comes.
    pub(super) fn source_version<S: AuditStore>(&self, s: &S, key: &str) -> Option<String> {
        version_of(s, &reading_docs(&self.cfg.zones, key))
    }

    /// What the completion checkpoint of a reading says of its source: the version `issued_on`, when a document of it was ever
    /// given other bytes.
    pub(super) fn source_context<S: AuditStore>(&self, s: &S, key: &str, issued_on: Option<&str>, context: &mut Value) {
        if let Some(version) = issued_on.filter(|_| reading_docs(&self.cfg.zones, key).iter().any(|d| s.doc_replaced(d))) {
            context[SOURCE_VERSION] = json!(version);
        }
    }

    /// Whether the reading `key` is closed for the bytes its documents have now, by its completion checkpoint in the journal.
    pub(super) fn reading_is_current<S: AuditStore>(&self, s: &S, key: &str) -> bool {
        let context = s.checkpoint(&task_checkpoint(key)).map_or(Value::Null, |c| c["context"].clone());
        reading_current(s, &self.cfg.zones, key, &context)
    }

    /// A reading that just closed on a lease issued before its document got other bytes read the earlier bytes: it is not done
    /// for the present ones, and is open work again.
    pub(super) fn reopen_if_stale<S: AuditStore>(&mut self, s: &S, key: &str) {
        if self.handled.contains(key) && !self.reading_is_current(s, key) {
            self.reopen_reading(key);
        }
    }

    /// The readings closed for bytes their documents no longer have: open work, whoever reads the open work (the next task, the
    /// completion of the run, its terminal receipt). Only the documents that were ever given other bytes are looked at.
    pub(super) fn stale_readings<S: AuditStore>(&self, s: &S) -> BTreeSet<String> {
        let mut stale = BTreeSet::new();
        for doc in s.replaced_docs() {
            let keys: Vec<String> = match self.cfg.zones.iter().position(|zone| zone.contains(&doc)) {
                Some(n) => vec![format!("zone:{n}")],
                None => (0..self.sections_of(s, &doc).len()).flat_map(|k| [format!("doc:{doc}#{k}"), format!("reread:{doc}#{k}")]).collect(),
            };
            stale.extend(keys.into_iter().filter(|key| self.handled.contains(key) && !self.reading_is_current(s, key)));
        }
        stale
    }

    /// Those readings are no longer done: a task of each can be given (`taken` reads what is done).
    pub(super) fn reopen_replaced_sources<S: AuditStore>(&mut self, s: &S) {
        for key in self.stale_readings(s) {
            self.reopen_reading(&key);
        }
    }

    /// What the dispatcher kept of a reading that is to be done again goes with it: a recovery from the journal keeps none of
    /// it either (`recover` passes a reading that is not current).
    fn reopen_reading(&mut self, key: &str) {
        self.handled.remove(key);
        self.strained.remove(key);
        self.key_stored.remove(key);
        self.key_offered.remove(key);
        self.unit_records.remove(key);
        self.reopened.remove(key);
    }
}
