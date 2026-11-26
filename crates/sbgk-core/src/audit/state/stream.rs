//! Rules 4 (0.3.0): what a journal that takes its sources as they come adds to rules 3, and the reads that go with it.
//!
//! - A claim may rest on a claim. The rule stays AND: a claim stands while every ground of it stands.
//! - A context checkpoint is the checkpoint command with a key `vsc:checkpoint:<epoch>`: the records and the sources an agent
//!   keeps across a compaction of its context. Its epochs count from 1 by one, and what it lists exists.
//! - A withdrawal may name the document that is its reason.
//! - A claim's `subject` is its key and its `object` its value: the reads by exact key and the checks of values and of required
//!   keys are projections over the journal. The kernel refuses no record for them.
//! - A relation `supersedes` (from the new record to the old) is a planned change of version: the old record stays as it stands,
//!   and is no longer the current one. Only a withdrawal makes what rested on a quote fall.
//!
//! A journal under rules 3 has none of this: the same commands are judged as 0.2 judged them.

use super::*;

/// The keys of the context checkpoints: `vsc:checkpoint:<epoch>`, epochs from 1.
pub const CONTEXT_CHECKPOINT_PREFIX: &str = "vsc:checkpoint:";
/// The form of a context checkpoint's manifest (the `context` of its command).
pub const CONTEXT_CHECKPOINT_FORMAT: &str = "r2r-context-checkpoint/1";
const CONTEXT_KEYS: [&str; 6] = ["epoch", "format", "manifest", "raw_context", "records", "sources"];
/// The most records a context checkpoint lists, and the most bytes of the manifest an agent adds to it (JCS).
pub const MAX_CHECKPOINT_RECORDS: usize = 65_536;
pub const MAX_CHECKPOINT_MANIFEST_BYTES: usize = 65_536;

/// A fate with the reason of its withdrawal, when the command named one.
pub(super) fn with_reason(mut fate: Value, reason: Option<&str>) -> Value {
    if let Some(reason) = reason {
        fate["reason_source_id"] = json!(reason);
    }
    fate
}

fn link_id(from: &RecordId, rel: &str, to: &RecordId) -> LinkId {
    LinkId(sha256_parts(&[b"R2R-AUDIT-LINK/1", to_jcs(&json!([to_hex(&from.0), rel, to_hex(&to.0)])).as_bytes()]))
}

/// The epoch a context checkpoint key names: digits without a sign or a leading zero, from 1.
fn epoch_of(key: &str) -> Option<u64> {
    let digits = key.strip_prefix(CONTEXT_CHECKPOINT_PREFIX)?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The refusal of a context checkpoint written as the checkpoint or as an operation of a batch.
pub(super) fn not_in_a_batch() -> KernelError {
    bad("vsc:checkpoint", "a context checkpoint is a command of its own, never the checkpoint or an operation of a batch")
}

#[cfg(test)]
thread_local! {
    /// The records `stands_now` looked at, counted in the tests: a chain of new claims is walked once, not once for each claim.
    pub(super) static STANDS_VISITS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl Core {
    /// Rules 4: whether a checkpoint command, or the checkpoint of a batch, has a key of the context checkpoints.
    pub(super) fn context_checkpoint_key(&self, checkpoint: &Value) -> bool {
        self.data.rules >= 4 && checkpoint["key"].as_str().is_some_and(|key| key.starts_with(CONTEXT_CHECKPOINT_PREFIX))
    }

    /// Whether a record stands in the state a command has made so far, by its own grounds: `grounded` reads the support flags,
    /// which are closed while a command runs, and paid a pass over every record for each claim a new claim rests on. Only the cone
    /// of `id` is walked, with an explicit stack. A record the command found is read from the flags the command began with: only
    /// a submit asks (`basis`), and a submit changes no flag of an earlier record. For the same reason what one walk found holds
    /// for the rest of the submit (`Cache::stands`, emptied at every command and operation): a chain of claims that one submit
    /// brings is walked once, and not from its end to its start again for each claim of it (Codex review of b27625da).
    pub(super) fn stands_now(&self, id: &RecordId) -> bool {
        let (before, mut known) = {
            let mut cache = self.cache();
            (cache.support_before.clone(), std::mem::take(&mut cache.stands))
        };
        let mut stack = vec![*id];
        while let Some(&top) = stack.last() {
            if known.contains_key(&top) {
                stack.pop();
                continue;
            }
            #[cfg(test)]
            STANDS_VISITS.with(|n| n.set(n.get() + 1));
            let Some(&position) = self.data.record_positions.get(&top) else {
                known.insert(top, false);
                stack.pop();
                continue;
            };
            let record = &self.data.records[position];
            if record.kind == RecordKind::Observe {
                known.insert(top, self.observe_grounded(record));
                stack.pop();
                continue;
            }
            if let Some(flags) = before.as_ref().and_then(|flags| flags.get(&top)) {
                known.insert(top, flags.0);
                stack.pop();
                continue;
            }
            let grounds = || record.based_on.iter().chain(record.ends.iter().flat_map(|(a, _, b)| [a, b]));
            let pending: Vec<RecordId> = grounds().filter(|g| !known.contains_key(g)).copied().collect();
            if pending.is_empty() {
                // the rule of `record_flags` for a record that is no answer: its grounds and its ends stand
                let stands = record.kind != RecordKind::Done && !record.based_on.is_empty() && grounds().all(|g| known.get(g) == Some(&true));
                known.insert(top, stands);
                stack.pop();
            } else {
                stack.extend(pending);
            }
        }
        let stands = known[id];
        #[cfg(test)]
        assert_eq!(stands, self.support_flags_fresh().get(id).is_some_and(|v| v.0), "a record's own grounds and a whole pass disagree");
        self.cache().stands = known;
        stands
    }

    /// Rules 4: the document a withdrawal names as its reason (`reason_source_id`), which must be a document of the journal.
    /// Under rules 3 the command has no such field, and one that carries it is refused as before.
    pub(super) fn withdrawal_reason(&self, command: &Value, keys: &[&str]) -> KResult<Option<String>> {
        if self.data.rules < 4 {
            check_keys(command, keys)?;
            return Ok(None);
        }
        let mut allowed = keys.to_vec();
        allowed.push("reason_source_id");
        check_keys(command, &allowed)?;
        match command.get("reason_source_id") {
            None => Ok(None),
            Some(Value::String(doc)) if self.session.arena.doc(doc).is_some() => Ok(Some(doc.clone())),
            Some(_) => Err(bad("reason_source_id", "the reason of a withdrawal is a document of this journal: put it first")),
        }
    }

    /// Rules 4: a checkpoint whose key begins `vsc:checkpoint:` is a context checkpoint. Its epoch follows the last one by one,
    /// its cursor is the number of records now, and its manifest lists records that are active now and sources that exist: each
    /// record by its whole id, each source by its name and the SHA-256 of the bytes it has now. A record that fell or was replaced
    /// is not listed: its checkpoint would give it back as kept when its ground came back, though it was not kept. Any other
    /// key, and every key under rules 3, is judged as before. The command is a frame of its own (`batch` refuses the key), so
    /// the state it reads is the state the frame before it left.
    pub(super) fn context_checkpoint_rule(&self, command: &Value) -> KResult<()> {
        let key = string(command, "key")?;
        if self.data.rules < 4 || !key.starts_with(CONTEXT_CHECKPOINT_PREFIX) {
            return Ok(());
        }
        let refuse = |message: &str| bad("vsc:checkpoint", message);
        let epoch = epoch_of(key).ok_or_else(|| refuse("a context checkpoint is named vsc:checkpoint:<epoch>, the epoch in digits from 1"))?;
        if self.data.checkpoints.contains_key(key) {
            return Err(refuse("this epoch has its checkpoint: a context checkpoint is written once"));
        }
        if epoch > 1 && !self.data.checkpoints.contains_key(&format!("{CONTEXT_CHECKPOINT_PREFIX}{}", epoch - 1)) {
            return Err(refuse("the epochs of the context checkpoints follow one another by one"));
        }
        if command["from"] != 0 || command["to"].as_u64() != Some(self.data.records.len() as u64) {
            return Err(refuse("a context checkpoint covers the records from the first to the last one now: from 0, to their number"));
        }
        let context = &command["context"];
        let mut keys: Vec<&str> = context.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        keys.sort_unstable();
        if keys != CONTEXT_KEYS || context["format"] != CONTEXT_CHECKPOINT_FORMAT || context["epoch"].as_u64() != Some(epoch) {
            return Err(refuse("the manifest of a context checkpoint names its format, its epoch, its records, its sources, raw_context and manifest"));
        }
        let listed = context["records"].as_array().ok_or_else(|| refuse("records is an array of record ids"))?;
        if listed.len() > MAX_CHECKPOINT_RECORDS {
            return Err(refuse("a context checkpoint lists at most 65536 records"));
        }
        let mut seen = BTreeSet::new();
        // read once, and only for a checkpoint that lists a record
        let mut standing: Option<Arc<Vec<bool>>> = None;
        for id in listed {
            let record = id
                .as_str()
                .and_then(from_hex)
                .filter(|hash| *id == json!(to_hex(hash)))
                .and_then(|hash| self.record(&RecordId(hash)))
                .ok_or_else(|| refuse("a context checkpoint lists records of this journal by their whole ids in lowercase"))?;
            if matches!(record.kind, RecordKind::Question | RecordKind::Done) {
                return Err(refuse("a context checkpoint lists observations, claims, relations and hypotheses: a question or an answer of a task is none"));
            }
            if !seen.insert(record.id) {
                return Err(refuse("a context checkpoint lists a record once"));
            }
            let position = *self.data.record_positions.get(&record.id).expect("a record of the journal");
            let state = self.state_at(position, standing.get_or_insert_with(|| self.standing_in_command()));
            if state != RecordState::Active {
                return Err(refuse(&format!("a context checkpoint lists records that are active now: {} is {}", record.id.short(), state.name())));
            }
        }
        let sources = context["sources"].as_object().ok_or_else(|| refuse("sources is an object of document names and the SHA-256 of their bytes"))?;
        for (doc, hash) in sources {
            if self.data.source_documents.get(doc).is_none_or(|identity| identity["raw_sha256"] != *hash) {
                return Err(refuse("a context checkpoint names each source by the SHA-256 of the bytes it has now"));
            }
        }
        match &context["raw_context"] {
            Value::Null => {}
            Value::String(doc) if sources.contains_key(doc) => {}
            _ => return Err(refuse("raw_context is null or one of the sources of the checkpoint")),
        }
        match &context["manifest"] {
            Value::Null => {}
            manifest @ Value::Object(_) if to_jcs(manifest).len() <= MAX_CHECKPOINT_MANIFEST_BYTES => {}
            _ => return Err(refuse("manifest is null or an object of at most 65536 bytes")),
        }
        Ok(())
    }

    /// Whether each record stands, for a command that is a frame of its own and has changed nothing yet. The flags of the state
    /// before a command of checkpoints are kept for the state after it (`Cache::begin`): they are read when they are there, and a
    /// whole pass computes them when they are not.
    fn standing_in_command(&self) -> Arc<Vec<bool>> {
        let kept = self.cache().standing.clone();
        let fresh = || {
            let flags = self.support_flags_fresh();
            Arc::new(self.data.records.iter().map(|r| flags.get(&r.id).is_some_and(|v| v.0)).collect::<Vec<bool>>())
        };
        #[cfg(test)]
        if let Some(kept) = &kept {
            assert_eq!(*kept, fresh(), "the flags kept across a command of checkpoints and a whole pass disagree");
        }
        kept.unwrap_or_else(fresh)
    }

    /// The standing relation `supersedes` that names the record at `position` as the old one, when its link was not rejected: the
    /// record that replaced it. A relation stands while its grounds and both its ends stand, so a replacement that fell replaces
    /// nothing, and the old record is the current one again.
    fn superseded_by(&self, position: usize, standing: &[bool]) -> Option<RecordId> {
        let old = self.data.records[position].id;
        self.data.dependents.get(&old).into_iter().flatten().find_map(|&p| {
            let relation = &self.data.records[p];
            let (from, rel, to) = relation.ends.as_ref()?;
            let stands = standing.get(p).copied().unwrap_or(false);
            let kept = self.data.links.get(&link_id(from, rel, to)).is_some_and(|link| link.status != LinkStatus::Rejected);
            (rel == "supersedes" && *to == old && stands && kept).then_some(*from)
        })
    }

    fn state_at(&self, position: usize, standing: &[bool]) -> RecordState {
        let record = &self.data.records[position];
        let stands = standing.get(position).copied().unwrap_or(false);
        match (record.kind, stands) {
            (RecordKind::Observe, true) => RecordState::Active,
            (RecordKind::Observe, false) if self.data.fates.contains_key(&record.id) => RecordState::Withdrawn,
            (RecordKind::Observe, false) => RecordState::AffectedByEvidenceChange,
            (_, true) => match self.superseded_by(position, standing) {
                Some(by) => RecordState::Superseded(by),
                None => RecordState::Active,
            },
            (_, false) if record.based_on.is_empty() && record.ends.is_none() => RecordState::Ungrounded,
            (_, false) => RecordState::AffectedByEvidenceChange,
        }
    }
}

/// What a record is now, for the reads of 0.3.0. The kernel keeps `grounded` alone; the rest is read off the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordState {
    /// It stands, and no standing record replaced it.
    Active,
    /// It stands as it was said, and a standing `supersedes` relation names the record that replaced it.
    Superseded(RecordId),
    /// An observation whose quote was withdrawn, by name or with the text it overlapped.
    Withdrawn,
    /// A ground of it no longer stands, or the document of an observation has other bytes now.
    AffectedByEvidenceChange,
    /// It never rested on anything: a question.
    Ungrounded,
}

impl RecordState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Superseded(_) => "SUPERSEDED",
            Self::Withdrawn => "WITHDRAWN",
            Self::AffectedByEvidenceChange => "AFFECTED_BY_EVIDENCE_CHANGE",
            Self::Ungrounded => "UNGROUNDED",
        }
    }
}

/// What the claim chains of a journal come to (rules 4): the longest chain of claims resting on claims, and how many of the
/// standing claims have no quote of their own among their grounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClaimChains {
    /// A claim on observations alone has depth 0; a claim on a claim of depth `d`, at least `d + 1`. Of all claims, standing or not.
    pub max_depth: usize,
    pub standing_claims: usize,
    pub standing_without_own_quote: usize,
}

impl AuditState {
    /// What a record is now (`RecordState`); `None` for an id that names no record.
    pub fn record_state(&self, id: &RecordId) -> Option<RecordState> {
        let position = *self.core.data.record_positions.get(id)?;
        Some(self.core.state_at(position, &self.core.standing_flags()))
    }

    /// The states of several records, read off one copy of the flags.
    pub fn record_states(&self, ids: &[RecordId]) -> Vec<Option<RecordState>> {
        let standing = self.core.standing_flags();
        ids.iter().map(|id| self.core.data.record_positions.get(id).map(|p| self.core.state_at(*p, &standing))).collect()
    }

    /// The claims whose subject is exactly `key`, in record order, each with its state. The subject of a claim is its key and
    /// its object its value: found by an index of the subjects, not by a walk of the records.
    pub fn claims_of_key(&self, key: &str) -> Vec<(Arc<RecordView>, RecordState)> {
        let standing = self.core.standing_flags();
        let positions = self.core.data.claims_by_key.get(&sha256(key.as_bytes())).map(Vec::as_slice).unwrap_or_default();
        positions
            .iter()
            .map(|p| (Arc::clone(&self.core.data.records[*p]), self.core.state_at(*p, &standing)))
            .filter(|(record, _)| record.body["subject"] == key)
            .collect()
    }

    /// Every claim with its state, in record order: the table of keys is made of them.
    pub fn claims_with_states(&self) -> Vec<(Arc<RecordView>, RecordState)> {
        let standing = self.core.standing_flags();
        let records = &self.core.data.records;
        (0..records.len()).filter(|p| records[*p].kind == RecordKind::Claim).map(|p| (Arc::clone(&records[p]), self.core.state_at(p, &standing))).collect()
    }

    /// The scope of whole documents under which these lines can be judged, for a writer that keeps one journal and has no task
    /// of a dispatcher to take a scope from (`audit-stream submit`): the documents the lines quote, and the documents under every
    /// earlier record they name, as a ground is visible in a scope only when every quote under it is of a document of the scope
    /// (`visible_in_scope`). In the order of the names. A name that resolves to nothing adds nothing: the kernel refuses its line.
    /// A scope names a bounded number of documents (`MAX_REFS`): lines that quote and rest on more than that are refused by the
    /// kernel as any scope too wide is.
    pub fn scope_of_lines(&self, actor: &str, directive: &str, lines: &[Value]) -> Scope {
        let mut docs: BTreeSet<String> = BTreeSet::new();
        let mut local: BTreeSet<&str> = BTreeSet::new();
        let mut stack: Vec<RecordId> = Vec::new();
        for line in lines {
            docs.extend(line["doc_id"].as_str().map(str::to_string));
            let single = ["from", "to", "about_record"].into_iter().filter_map(|field| line[field].as_str());
            let listed = ["based_on", "answer_ids"].into_iter().flat_map(|field| line[field].as_array().into_iter().flatten()).filter_map(Value::as_str);
            // a name an earlier line of these gave is a record of these lines: what it rests on is named by its own line
            stack.extend(single.chain(listed).filter(|name| !local.contains(name)).filter_map(|name| self.core.resolve(name, actor, directive).ok()));
            local.extend(line["local_id"].as_str());
        }
        let mut walked: BTreeSet<RecordId> = BTreeSet::new();
        while let Some(id) = stack.pop() {
            let Some(record) = self.core.record(&id).filter(|_| walked.insert(id)) else { continue };
            docs.extend(record.doc_id.iter().filter(|_| record.kind == RecordKind::Observe).cloned());
            stack.extend(record.based_on.iter().chain(record.ends.iter().flat_map(|(a, _, b)| [a, b])));
        }
        Scope { docs: docs.into_iter().collect(), topic: None, ranges: Vec::new() }
    }

    /// The number of context checkpoints written: their epochs are 1 to this number. None under rules 3: a checkpoint with such a
    /// key is there any checkpoint, which no rule compared with the form of a manifest (Codex review of b27625da, finding 5).
    pub fn context_epochs(&self) -> u64 {
        if self.core.data.rules < 4 {
            return 0;
        }
        let mut n = 0;
        while self.core.data.checkpoints.contains_key(&format!("{CONTEXT_CHECKPOINT_PREFIX}{}", n + 1)) {
            n += 1;
        }
        n
    }

    /// The manifest of the context checkpoint of an epoch, and the number of records it covers. None under rules 3.
    pub fn context_checkpoint_of(&self, epoch: u64) -> Option<(Value, u64)> {
        if self.core.data.rules < 4 {
            return None;
        }
        let command = self.core.data.checkpoints.get(&format!("{CONTEXT_CHECKPOINT_PREFIX}{epoch}"))?;
        Some((command["context"].clone(), command["to"].as_u64().unwrap_or(0)))
    }

    /// Write the context checkpoint of the next epoch (rules 4): the records an agent keeps across a compaction of its context,
    /// the sources they rest on, each with the SHA-256 of its bytes now, the source that holds the raw context when there is one,
    /// and an object of the agent's that the kernel does not read. One command of its own, never a line of a submit. Answers with
    /// the key, the epoch and the cursor.
    pub fn context_checkpoint(
        &mut self,
        actor: &str,
        records: &[RecordId],
        sources: &[String],
        raw_context: Option<&str>,
        manifest: Option<Value>,
    ) -> KResult<Value> {
        if self.core.data.rules < 4 {
            return Err(bad("vsc:checkpoint", "a context checkpoint is of rules 4: this journal names rules 3"));
        }
        let epoch = self.context_epochs() + 1;
        let mut named = BTreeMap::new();
        for doc in sources.iter().map(String::as_str).chain(raw_context) {
            let identity = self.core.data.source_documents.get(doc).ok_or_else(|| bad("sources", format!("{doc} is no document of this journal")))?;
            named.insert(doc.to_string(), identity["raw_sha256"].clone());
        }
        let context = json!({"format": CONTEXT_CHECKPOINT_FORMAT, "epoch": epoch, "records": records.iter().map(|r| to_hex(&r.0)).collect::<Vec<_>>(),
            "sources": named, "raw_context": raw_context, "manifest": manifest});
        let key = format!("{CONTEXT_CHECKPOINT_PREFIX}{epoch}");
        let command = json!({"kind": "checkpoint", "key": key, "from": 0, "to": self.core.data.records.len(), "context": context});
        let value = self.value_command(actor, command)?;
        Ok(json!({"checkpoint": key, "epoch": epoch, "cursor": value["cursor"], "records": records.len()}))
    }

    /// The records of a context checkpoint that are active now, in the order it lists them: what an agent takes back after a
    /// compaction of its context. A record that was withdrawn, lost a ground or was replaced since is left out; `dropped` names
    /// each of those with its state. Nothing is erased: the journal keeps every record.
    pub fn read_active_checkpoint(&self, epoch: u64) -> KResult<ActiveCheckpoint> {
        if self.core.data.rules < 4 {
            return Err(bad("epoch", "a context checkpoint is of rules 4: this journal names rules 3"));
        }
        let (context, cursor) = self.context_checkpoint_of(epoch).ok_or_else(|| bad("epoch", "no context checkpoint of this epoch"))?;
        let ids: Vec<RecordId> = context["records"].as_array().into_iter().flatten().filter_map(|v| v.as_str().and_then(from_hex)).map(RecordId).collect();
        let standing = self.core.standing_flags();
        let (mut active, mut dropped) = (Vec::new(), Vec::new());
        for id in ids {
            let Some(&position) = self.core.data.record_positions.get(&id) else { continue };
            match self.core.state_at(position, &standing) {
                RecordState::Active => active.push(Arc::clone(&self.core.data.records[position])),
                state => dropped.push((id, state)),
            }
        }
        Ok(ActiveCheckpoint { epoch, cursor, context, active, dropped })
    }

    /// Withdraw text of a document and name the document that is the reason (rules 4), as `withdraw_text` without one.
    pub fn withdraw_text_for(&mut self, actor: &str, doc_id: &str, text: &str, reason_source_id: &str) -> KResult<u64> {
        let command = json!({"kind": "revoke_text", "doc_id": doc_id, "exact_quote": text, "reason_source_id": reason_source_id});
        Ok(self.value_command(actor, command)?["also_revoked"].as_u64().unwrap_or(0))
    }

    /// Withdraw the quote of an observation and name the document that is the reason (rules 4), as `revoke_observation` without one.
    pub fn revoke_observation_for(&mut self, actor: &str, record: &RecordId, reason_source_id: &str) -> KResult<u64> {
        let command = json!({"kind": "revoke", "record": to_hex(&record.0), "reason_source_id": reason_source_id});
        Ok(self.value_command(actor, command)?["also_revoked"].as_u64().unwrap_or(0))
    }

    /// The claim chains of the journal, from one pass over its records.
    pub fn claim_chains(&self) -> ClaimChains {
        let standing = self.core.standing_flags();
        let records = &self.core.data.records;
        let mut depth = vec![0usize; records.len()];
        let mut out = ClaimChains::default();
        for (position, record) in records.iter().enumerate() {
            if record.kind != RecordKind::Claim {
                continue;
            }
            let grounds = || record.based_on.iter().filter_map(|g| self.core.data.record_positions.get(g).copied());
            depth[position] = grounds().filter(|g| records[*g].kind == RecordKind::Claim).map(|g| depth[g] + 1).max().unwrap_or(0);
            out.max_depth = out.max_depth.max(depth[position]);
            if standing.get(position).copied().unwrap_or(false) {
                out.standing_claims += 1;
                out.standing_without_own_quote += usize::from(!grounds().any(|g| records[g].kind == RecordKind::Observe));
            }
        }
        out
    }
}

/// What `read_active_checkpoint` gives: the active records of a context checkpoint, and the listed records that are active no more.
#[derive(Clone, Debug)]
pub struct ActiveCheckpoint {
    pub epoch: u64,
    /// The number of records the journal had when the checkpoint was written.
    pub cursor: u64,
    /// The manifest as it was written.
    pub context: Value,
    pub active: Vec<Arc<RecordView>>,
    pub dropped: Vec<(RecordId, RecordState)>,
}
