//! Durability failures must not publish staged state or repair an unvalidated log.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct TempPath(PathBuf);

impl TempPath {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("r2r_audit_state_failure_{}_{}_{}.jsonl", std::process::id(), time, NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        // and the tails a recovery kept beside the journal
        let name = format!("{}.torn-", self.0.file_name().unwrap().to_string_lossy());
        for kept in std::fs::read_dir(std::env::temp_dir()).into_iter().flatten().flatten() {
            if kept.file_name().to_string_lossy().starts_with(&name) {
                let _ = std::fs::remove_file(kept.path());
            }
        }
    }
}

fn state(path: &Path) -> AuditState {
    AuditState::create(
        path,
        &AuditOntology::base(),
        &[("policy".into(), b"Prior witness.\nNew witness.\n".to_vec())],
        "failure-regression",
        sha256(b"frozen manifest fixture"),
    )
    .unwrap()
}

fn observation(local_id: &str, quote: &str) -> Value {
    json!({"kind":"observe","local_id":local_id,"doc_id":"policy","exact_quote":quote,"terms":["witness"]})
}

fn scope() -> Scope {
    Scope { docs: vec!["policy".into()], topic: Some("witnesses".into()), ranges: Vec::new() }
}

#[test]
fn a_sync_failure_never_publishes_staged_state_and_recovery_deduplicates_the_unacked_request() {
    let path = TempPath::new();
    let mut state = state(&path.0);
    let scope = scope();
    let seed = state.submit_records_id("seed", "worker", "task", &scope, &[observation("seed_e", "Prior witness.")]);
    assert!(seed.error.is_none(), "{:?}", seed.error);
    assert_eq!(seed.accepted.len(), 1);
    let seed_record = state.record(&seed.accepted[0]).unwrap();
    let seed_receipt = state.core.data.receipts[&("worker".into(), "seed".into())].outcome.value();
    let before = (state.engine_root(), state.audit_root(), state.session_root(), state.wal_head(), state.transaction_sequence(), state.head());
    let engine_wal = state.core.session.wal.bytes.clone();
    let engine_nodes = state.core.session.engine.node_count();
    let engine_seq = state.core.session.last_seq;
    let receipts = state.core.data.receipts.len();
    let lines = [observation("new_e", "New witness.")];

    state.journal.as_mut().unwrap().inject_sync_failure_once();
    let refused = state.submit_records_id("attempt-1", "worker", "task", &scope, &lines);
    assert!(refused.accepted.is_empty(), "an undurable operation must return no accepted ids");
    assert_eq!(refused.failed_index, Some(0));
    assert!(refused.error.unwrap().message.contains("injected audit WAL sync failure"));
    assert_eq!((state.engine_root(), state.audit_root(), state.session_root(), state.wal_head(), state.transaction_sequence(), state.head()), before);
    assert_eq!(state.core.session.wal.bytes, engine_wal);
    assert_eq!(state.core.session.engine.node_count(), engine_nodes);
    assert_eq!(state.core.session.last_seq, engine_seq);
    assert_eq!(state.core.data.receipts.len(), receipts);
    assert!(!state.core.data.receipts.contains_key(&("worker".into(), "attempt-1".into())));
    assert!(!state.core.data.locals.contains_key(&("worker".into(), "task".into(), "new_e".into())));
    assert!(state.is_grounded(&seed_record.id), "the already durable evidence remains available");

    let blocked = state.submit_records_id("attempt-after-poison", "worker", "task", &scope, &lines);
    assert!(blocked.accepted.is_empty());
    assert!(blocked.error.unwrap().message.contains("poisoned"));
    assert_eq!((state.engine_root(), state.audit_root(), state.session_root(), state.wal_head(), state.transaction_sequence(), state.head()), before);
    drop(state);

    // The complete, unacknowledged write may survive a failed durability barrier.
    // Its stored receipt must resolve the retry without a second state effect.
    let mut recovered = AuditState::open(&path.0).unwrap();
    assert_eq!(recovered.head(), before.5 + 1);
    assert_eq!(recovered.transaction_sequence(), before.4.map(|n| n + 1));
    assert_ne!(recovered.engine_root(), before.0);
    assert_ne!(recovered.audit_root(), before.1);
    assert_eq!(recovered.record(&seed_record.id), Some(seed_record.clone()));
    assert!(recovered.is_grounded(&seed_record.id));
    assert_eq!(recovered.core.data.receipts[&("worker".into(), "seed".into())].outcome.value(), seed_receipt);
    let stored = recovered.core.data.receipts[&("worker".into(), "attempt-1".into())].outcome.value();
    let after_recovery =
        (recovered.engine_root(), recovered.audit_root(), recovered.session_root(), recovered.wal_head(), recovered.transaction_sequence(), recovered.head());
    let retry = recovered.submit_records_id("attempt-1", "worker", "task", &scope, &lines);
    assert!(retry.error.is_none(), "{:?}", retry.error);
    assert_eq!(retry.accepted.len(), 1);
    assert_eq!(json!({"kind":"records","result":report_value(&retry)}), stored);
    assert_eq!(recovered.core.resolve("new_e", "worker", "task").unwrap(), retry.accepted[0]);
    assert_eq!(
        (recovered.engine_root(), recovered.audit_root(), recovered.session_root(), recovered.wal_head(), recovered.transaction_sequence(), recovered.head()),
        after_recovery
    );
    assert!(!recovered.core.data.receipts.contains_key(&("worker".into(), "attempt-after-poison".into())));
    drop(recovered);
    assert_eq!(std::fs::read(&path.0).unwrap().iter().filter(|b| **b == b'\n').count(), 3, "genesis, seed and the single recovered attempt");
}

#[test]
fn semantic_replay_failure_preserves_the_unterminated_tail_even_when_frame_hashes_are_valid() {
    let path = TempPath::new();
    let mut state = state(&path.0);
    let report = state.submit_records_id("accepted", "worker", "task", &scope(), &[observation("e", "Prior witness.")]);
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.accepted.len(), 1);
    drop(state);

    let original = std::fs::read_to_string(&path.0).unwrap();
    let mut frames: Vec<Value> = original.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(frames.len(), 2);
    let transaction = &mut frames[1];
    assert_ne!(transaction["payload"]["audit_root"], json!(to_hex(&ZERO_HASH)));
    transaction["payload"]["audit_root"] = json!(to_hex(&ZERO_HASH));
    transaction.as_object_mut().unwrap().remove("hash");
    let hash = sha256_parts(&[b"R2R-AUDIT-WAL/2", to_jcs(transaction).as_bytes()]);
    transaction["hash"] = json!(to_hex(&hash));
    let mut changed = frames.iter().map(|frame| format!("{}\n", to_jcs(frame))).collect::<String>().into_bytes();
    changed.extend_from_slice(b"{\"format\":\"sbgk-session-log/2\",\"wal_op\":\"audit\"");
    std::fs::write(&path.0, &changed).unwrap();

    // Prove this is not a framing/hash rejection. Do not finish recovery here:
    // the State layer has not yet accepted the command's claimed post-roots.
    let (journal, payloads) = AuditJournal::open(&path.0).unwrap();
    assert_eq!(payloads.len(), 2);
    assert_eq!(payloads[1]["audit_root"], json!(to_hex(&ZERO_HASH)));
    drop(journal);
    assert_eq!(std::fs::read(&path.0).unwrap(), changed);

    let failure = AuditState::open(&path.0).err().expect("semantic replay must reject an incorrect committed audit root");
    assert!(failure.message.contains("semantic replay diverged"), "{failure}");
    assert_eq!(std::fs::read(&path.0).unwrap(), changed, "failed semantic replay must preserve every original byte, including the torn tail");
}

#[test]
fn with_links_off_no_path_stores_a_link_and_nothing_is_journaled_for_it() {
    // the control profiles --build-scope concepts|none (Codex review of 8023910, SCOPE-01): neither a relation record of the swarm
    // nor a link operation of the builder becomes a link
    let path = TempPath::new();
    let mut state = state(&path.0);
    let scope = scope();
    let lines = [
        observation("w_o1", "Prior witness."),
        observation("w_o2", "New witness."),
        json!({"kind":"claim","local_id":"w_c1","text":"A prior witness exists.","subject":"witness","stance":"reported","based_on":["w_o1"]}),
        json!({"kind":"claim","local_id":"w_c2","text":"A new witness exists.","subject":"witness","stance":"reported","based_on":["w_o2"]}),
    ];
    let seed = state.submit_records_id("seed", "worker", "task", &scope, &lines);
    assert!(seed.error.is_none(), "{:?}", seed.error);
    let (c1, c2, o1) = (seed.accepted[2], seed.accepted[3], seed.accepted[0]);
    state.set_links_off(true);
    let before = (state.audit_root(), state.transaction_sequence());
    let relation = json!({"kind":"relation","local_id":"w_r1","from":"w_c2","rel":"supersedes","to":"w_c1","based_on":["w_o1","w_o2"]});
    let refused = state.submit_records_id("relation", "worker", "task", &scope, std::slice::from_ref(&relation));
    assert!(refused.accepted.is_empty() && refused.error.as_ref().is_some_and(|e| e.message.contains("links are off")), "{:?}", refused.error);
    let op = json!({"kind":"add_link","from":to_hex(&c2.0),"rel":"supersedes","to":to_hex(&c1.0),"basis":[to_hex(&o1.0)]});
    let batch = state.submit_operations_id("builder-op", "builder", std::slice::from_ref(&op), None);
    assert!(batch.as_ref().err().is_some_and(|e| e.message.contains("links are off")), "{batch:?}");
    // a relation record in a submit inside a batch of operations (Codex review of 3ee34e9, SCOPE-03)
    let wrapped = json!({"kind":"submit","directive":"task","scope":scope_value(&scope),"lines":[relation]});
    let refused = state.submit_operations_id("wrapped-relation", "worker", std::slice::from_ref(&wrapped), None);
    assert!(refused.as_ref().err().is_some_and(|e| e.message.contains("links are off")), "{refused:?}");
    assert!(state.links().is_empty(), "no link was stored");
    assert_eq!((state.audit_root(), state.transaction_sequence()), before, "nothing was journaled for a refused link");
    let path_on_disk = path.0.clone();
    drop(state);
    let mut state = AuditState::open(&path_on_disk).unwrap();
    assert!(state.links().is_empty(), "no link after recovery from the journal");
    assert_eq!((state.audit_root(), state.transaction_sequence()), before);
    // the same records may link in an ordinary run, by either path
    let wrapped_ok = state.submit_operations_id("wrapped-relation-full", "worker", &[wrapped], None).unwrap();
    assert!(wrapped_ok["error"].is_null(), "{wrapped_ok}");
    assert_eq!(state.links().len(), 1);
    assert!(state.submit_operations_id("builder-op-full", "builder", &[op], None).is_ok());
    assert_eq!(state.links().len(), 1, "the builder's link is the same link");
}

/// One scenario over the transaction paths a fork serves: observations staged one by one, a refused line after an accepted
/// prefix, duplicate evidence, relation records, builder links and their statuses, a batch whose second operation fails, a retried
/// submission, a revoked observation, a source changed and changed back, a restart, more work after it. Each command's engine and
/// audit roots are returned; the journal is at `path`.
fn fork_scenario(path: &Path) -> Vec<(Hash, Hash)> {
    let docs = [("a".to_string(), b"Alpha one.\nAlpha two.\nAlpha three.\n".to_vec()), ("b".to_string(), b"Beta one.\nBeta two.\n".to_vec())];
    let mut s = AuditState::create(path, &AuditOntology::base(), &docs, "fork-differential", sha256(b"fork differential manifest")).unwrap();
    let mut roots = Vec::new();
    let mut step = |s: &AuditState| {
        // the direct grounding of an observation is the grounding of the pass over every record, after every command
        let flags = s.core.support_flags_fresh();
        for r in s.core.data.records.iter().filter(|r| r.kind == RecordKind::Observe) {
            assert_eq!(s.core.observe_grounded(r), flags[&r.id].0, "observation {}", to_hex(&r.id.0));
        }
        roots.push((s.engine_root(), s.audit_root()))
    };
    let scope = |d: &str| Scope { docs: vec![d.into()], topic: None, ranges: Vec::new() };
    let obs = |l: &str, d: &str, q: &str| json!({"kind":"observe","local_id":l,"doc_id":d,"exact_quote":q,"terms":["alpha"]});
    let claim = |l: &str, o: &str| json!({"kind":"claim","local_id":l,"text":format!("Claim {l}."),"subject":"alpha","stance":"reported","based_on":[o]});
    let first = [obs("o1", "a", "Alpha one."), obs("o2", "a", "Alpha two."), claim("c1", "o1"), claim("c2", "o2")];
    let r = s.submit_records_id("s1", "w1", "t1", &scope("a"), &first);
    assert_eq!(r.accepted.len(), 4, "{:?}", r.error);
    let (o1, o2, c1, c2) = (r.accepted[0], r.accepted[1], r.accepted[2], r.accepted[3]);
    step(&s);
    let r = s.submit_records_id(
        "s2",
        "w2",
        "t2",
        &scope("b"),
        &[
            obs("o3", "b", "Beta one."),
            claim("c3", "o3"),
            obs("o4", "b", "Beta two."),
            claim("c4", "o4"),
            json!({"kind":"relation","local_id":"r1","from":"c4","rel":"supports","to":"c3","based_on":["o3","o4"]}),
        ],
    );
    assert_eq!(r.accepted.len(), 5, "{:?}", r.error);
    let c3 = r.accepted[1];
    step(&s);
    // the same quote again, then a refused line after an accepted prefix
    let r = s.submit_records_id("s3", "w3", "t3", &scope("a"), &[obs("o5", "a", "Alpha one."), claim("c5", "o5"), claim("bad", "missing")]);
    assert_eq!((r.accepted.len(), r.failed_index), (2, Some(2)), "{:?}", r.error);
    step(&s);
    // an observation whose quote is not in its document, and a command refused as a whole: the error branch of Core::stage
    // (Argon's review of D and E, 01.11.2026)
    let r = s.submit_records_id("s3b", "w3", "t3b", &scope("a"), &[obs("o7", "a", "No such quote."), claim("c7", "o7")]);
    assert_eq!((r.accepted.len(), r.failed_index), (0, Some(0)), "{:?}", r.error);
    step(&s);
    assert!(s.revoke_observation("owner", &c1).is_err(), "a claim is not an observation to revoke");
    step(&s);
    let l1 = s.add_link("builder", &c2, "supersedes", &c1, &[o1, o2]).unwrap();
    step(&s);
    s.set_link_status(&l1.id, LinkStatus::Accepted, "checker", &[o1, o2]).unwrap();
    step(&s);
    let l2 = s.add_link("builder", &c2, "contradicts", &c3, &[o2]).unwrap();
    s.set_link_status(&l2.id, LinkStatus::Rejected, "checker", &[o2]).unwrap();
    step(&s);
    let good = json!({"kind":"propose_concept","type":"Component","name":"alpha unit","aliases":[],"basis":[to_hex(&o1.0)]});
    let v = s.submit_operations_id("b1", "builder", &[good, json!({"kind":"no-such-operation"})], None).unwrap();
    assert_eq!((v["accepted_operations"].as_u64(), v["failed_index"].as_u64()), (Some(1), Some(1)), "{v}");
    step(&s);
    // one-operation batches, the store's form of every builder operation: refused after a partial change (the concept is proposed,
    // then its catch-all function refused), accepted, refused before any change, a decision checkpoint, and a close alone
    let mut one = |id: &str, op: Value| s.submit_operations_id(id, "builder", &[op], None).unwrap();
    let proposal = json!({"kind":"propose_concept","type":"Component","name":"beta unit","aliases":[],"basis":[to_hex(&o1.0)]});
    let mut misplaced = proposal.clone();
    misplaced["function"] = json!("misc");
    let v = one("b2", misplaced);
    assert_eq!((v["accepted_operations"].as_u64(), v["failed_index"].as_u64()), (Some(0), Some(0)), "{v}");
    let v = one("b3", proposal);
    assert_eq!(v["accepted_operations"].as_u64(), Some(1), "the refused proposal left no concept behind: {v}");
    let v = one("b4", json!({"kind":"no-such-operation"}));
    assert_eq!(v["failed_index"].as_u64(), Some(0), "{v}");
    let v = one("b5", json!({"kind":"checkpoint","key":"builder:pair:P1","from":0,"to":0,"context":{"pair":"E1","reason":"none"}}));
    assert_eq!(v["accepted_operations"].as_u64(), Some(1), "{v}");
    step(&s);
    let v = s.submit_operations_id("b6", "builder", &[], Some(json!({"key":"builder:test","from":0,"to":0,"context":{}}))).unwrap();
    assert_eq!(v["checkpointed"], true, "{v}");
    step(&s);
    let again = s.submit_records_id("s1", "w1", "t1", &scope("a"), &first);
    assert_eq!(again.accepted, vec![o1, o2, c1, c2], "a retry returns its receipt");
    step(&s);
    s.revoke_observation("owner", &o2).unwrap();
    step(&s);
    // the same observation again reaches the engine; whatever it answers, both forks must journal the same
    let _ = s.revoke_observation("owner", &o2);
    step(&s);
    s.put_document("owner", "b", b"Beta two.\n").unwrap();
    step(&s);
    s.put_document("owner", "b", b"Beta one.\nBeta two.\n").unwrap();
    step(&s);
    drop(s);
    let mut s = AuditState::open(path).unwrap();
    step(&s);
    let r = s.submit_records_id("s4", "w1", "t4", &scope("a"), &[obs("o6", "a", "Alpha three."), claim("c6", "o6")]);
    assert_eq!(r.accepted.len(), 2, "{:?}", r.error);
    step(&s);
    roots
}

#[test]
fn forking_by_a_copy_of_the_engine_journals_the_same_bytes_as_forking_by_replay() {
    // Codex's conditions for Engine: Clone (01.11.2026): the replay stays as the oracle, and the copy must lead to the same
    // continuation, not only to the same root at the fork
    let (replayed, copied) = (TempPath::new(), TempPath::new());
    REPLAY_FORK.with(|r| r.set(true));
    let by_replay = fork_scenario(&replayed.0);
    REPLAY_FORK.with(|r| r.set(false));
    let by_copy = fork_scenario(&copied.0);
    assert_eq!(by_copy, by_replay, "the same roots after every command");
    assert_eq!(std::fs::read(&copied.0).unwrap(), std::fs::read(&replayed.0).unwrap(), "the same journal, byte for byte");
}

#[test]
fn a_batch_rolled_back_to_its_base_journals_the_same_bytes_as_one_copied_before_its_first_operation() {
    // the copy before a staged batch's first operation is the oracle (02.11.2026): a refused first operation, also after a partial
    // change, must leave the same state and receipt, at the commit and in the recovery that replays it
    let (copied, based) = (TempPath::new(), TempPath::new());
    TWO_COPY_BATCH.with(|r| r.set(true));
    let by_copy = fork_scenario(&copied.0);
    TWO_COPY_BATCH.with(|r| r.set(false));
    let by_base = fork_scenario(&based.0);
    assert_eq!(by_base, by_copy, "the same roots after every command");
    assert_eq!(std::fs::read(&based.0).unwrap(), std::fs::read(&copied.0).unwrap(), "the same journal, byte for byte");
}

#[test]
fn an_accepted_builder_operation_is_staged_on_one_copy_of_the_state() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    let r = s.submit_records_id("seed", "worker", "task", &scope(), &[observation("seed_o", "Prior witness.")]);
    assert!(r.error.is_none(), "{:?}", r.error);
    let op = json!({"kind":"propose_concept","type":"Component","name":"seed unit","aliases":[],"basis":[to_hex(&r.accepted[0].0)]});
    let before = FORKS.with(std::cell::Cell::get);
    let v = s.submit_operations_id("one", "builder", &[op], None).unwrap();
    assert_eq!(v["accepted_operations"].as_u64(), Some(1), "{v}");
    assert_eq!(FORKS.with(std::cell::Cell::get) - before, 1, "stage copies the state once; the batch adds no second copy");
}

#[test]
fn a_copied_engine_changes_alone_and_equals_the_replay_of_its_wal() {
    let path = TempPath::new();
    let mut state = state(&path.0);
    let r = state.submit_records_id("seed", "worker", "task", &scope(), &[observation("seed_e", "Prior witness.")]);
    assert!(r.error.is_none(), "{:?}", r.error);
    let replay = |wal: &[u8]| crate::wal::reconstruct_at_byte_offset(wal).unwrap().engine;
    let bind = |s: &mut Session, local: &str| {
        let event = json!({"seq":s.last_seq+1,"op":"bind_evidence","local_id":local,"doc_id":"policy","exact_quote":"New witness."});
        s.apply_line(&to_jcs(&event)).unwrap();
    };
    // a warm engine (its root computed at the commit) copied, the copy changed: the original stays as it was
    let core = &state.core;
    let (root, nodes, wal) = (core.engine_root, core.session.engine.node_count(), core.session.wal.bytes.clone());
    let mut copy = core.fork_session().unwrap();
    bind(&mut copy, "probe");
    assert_ne!(copy.engine.root(), root);
    assert_eq!(copy.engine.root(), replay(&copy.wal.bytes).root(), "the changed copy equals the replay of its own WAL");
    let mut original = core.session.engine.clone();
    assert_eq!((original.root(), core.session.engine.node_count(), &core.session.wal.bytes), (root, nodes, &wal), "the original is unchanged");
    assert_eq!(replay(&wal).root(), root);
    // a cold engine (changed, its root not computed yet) copied: both continue alike
    let mut cold = core.fork_session().unwrap();
    bind(&mut cold, "cold");
    let mut twin = Session::from_parts(cold.ontology.clone(), cold.arena.clone(), cold.engine.clone(), cold.wal.clone());
    for s in [&mut cold, &mut twin] {
        let event = json!({"seq":s.last_seq+1,"op":"bind_evidence","local_id":"next","doc_id":"policy","exact_quote":"Prior witness."});
        s.apply_line(&to_jcs(&event)).unwrap();
    }
    assert_eq!(cold.wal.bytes, twin.wal.bytes);
    assert_eq!(cold.engine.root(), twin.engine.root());
    assert_eq!(cold.engine.root(), replay(&cold.wal.bytes).root());
}

#[test]
fn verify_replays_like_open_but_leaves_every_byte_of_the_journal_including_a_torn_tail() {
    let path = TempPath::new();
    let mut state = state(&path.0);
    let genesis = (state.audit_root(), state.engine_root());
    let report = state.submit_records_id("accepted", "worker", "task", &scope(), &[observation("e", "Prior witness.")]);
    assert!(report.error.is_none(), "{:?}", report.error);
    let end = (state.audit_root(), state.engine_root(), state.session_root(), state.head(), state.wal_head());
    drop(state);
    let mut bytes = std::fs::read(&path.0).unwrap();
    bytes.extend_from_slice(b"{\"format\":\"sbgk-session-log/2\",\"wal_op\":\"audit\"");
    std::fs::write(&path.0, &bytes).unwrap();

    let mut seen = Vec::new();
    let (verified, read) = AuditState::verify(&path.0, &mut |n, audit, engine, head| seen.push((n, audit, engine, head))).unwrap();
    assert_eq!((verified.audit_root(), verified.engine_root(), verified.session_root(), verified.head()), (end.0, end.1, end.2, end.3));
    assert_eq!(seen.iter().map(|s| (s.0, s.1, s.2)).collect::<Vec<_>>(), vec![(1, genesis.0, genesis.1), (2, end.0, end.1)]);
    assert_eq!((Some(read.wal_head), read.bytes, read.sha256), (end.4, bytes.len() as u64, sha256(&bytes)));
    assert_eq!(seen[1].3, read.wal_head, "the head after the last complete frame");
    assert_ne!(seen[0].3, seen[1].3, "each state has the chain head after its own frames");
    assert_eq!(read.bytes - read.complete_bytes, 47, "the torn tail is read, not cut");
    assert_eq!(session_root_of(&end.1, &end.0), end.2);
    assert!(verified.wal_head().is_none(), "no journal is readied for writing");
    drop(verified);
    assert_eq!(std::fs::read(&path.0).unwrap(), bytes, "verify cuts nothing: the torn tail stays");

    drop(AuditState::open(&path.0).unwrap());
    assert!(std::fs::read(&path.0).unwrap().len() < bytes.len(), "open readies the journal for writing and cuts the torn tail");
}

/// What a resumed server goes on from, roots aside: the preimage of the state, the session's engine log and sequence, the telemetry.
fn replayed(s: &AuditState) -> (String, Vec<u8>, u64, Hash, Vec<Value>) {
    let session = &s.core.session;
    (s.core.legacy_preimage(), session.wal.bytes.clone(), session.last_seq, session.engine.clone().root(), s.telemetry_frames.clone())
}

/// `AuditState::verify` of the journal at `path`, on copies of the state or on the state itself: the states it visited, then what it
/// reached or how it refused the journal.
#[allow(clippy::type_complexity)]
fn verified(path: &Path, copies: bool) -> (Vec<(usize, Hash, Hash, Hash)>, Result<(String, Vec<u8>, u64, Hash, Vec<Value>), Value>) {
    COPY_REPLAY.with(|c| c.set(copies));
    let mut seen = Vec::new();
    let result = AuditState::verify(path, &mut |n, audit, engine, head| seen.push((n, audit, engine, head)));
    COPY_REPLAY.with(|c| c.set(false));
    (seen, result.map(|(state, _)| replayed(&state)).map_err(|e| e.to_json()))
}

/// Writes `frames` with a valid hash chain: only the replay can tell what is wrong with them.
fn chained(path: &Path, mut frames: Vec<Value>) {
    let mut previous = ZERO_HASH;
    let mut bytes = String::new();
    for frame in &mut frames {
        frame["previous"] = json!(to_hex(&previous));
        frame.as_object_mut().unwrap().remove("hash");
        previous = sha256_parts(&[b"R2R-AUDIT-WAL/2", to_jcs(frame).as_bytes()]);
        frame["hash"] = json!(to_hex(&previous));
        bytes.push_str(&to_jcs(frame));
        bytes.push('\n');
    }
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_replay_on_the_state_itself_reaches_what_a_replay_on_copies_reaches_and_goes_on_alike() {
    let path = TempPath::new();
    fork_scenario(&path.0);
    let (on_copies, in_place) = (verified(&path.0, true), verified(&path.0, false));
    assert!(on_copies.1.is_ok(), "{:?}", on_copies.1.err());
    assert_eq!(in_place.0, on_copies.0, "the same roots and chain head after every entry");
    assert_eq!(in_place.1, on_copies.1, "the same state, engine log and telemetry");

    // a resumed server: the same commands after each recovery journal the same bytes
    let mut resumes = Vec::new();
    for copies in [true, false] {
        let resumed = TempPath::new();
        std::fs::copy(&path.0, &resumed.0).unwrap();
        COPY_REPLAY.with(|c| c.set(copies));
        let mut s = AuditState::open(&resumed.0).unwrap();
        COPY_REPLAY.with(|c| c.set(false));
        let scope = Scope { docs: vec!["a".into()], topic: None, ranges: Vec::new() };
        let lines = [
            json!({"kind":"observe","local_id":"o8","doc_id":"a","exact_quote":"Alpha one.","terms":["alpha"]}),
            json!({"kind":"claim","local_id":"c8","text":"Claim c8.","subject":"alpha","stance":"reported","based_on":["o8"]}),
        ];
        let r = s.submit_records_id("after-1", "w4", "t5", &scope, &lines);
        assert_eq!(r.accepted.len(), 2, "{:?}", r.error);
        let v = s.submit_operations_id("after-2", "kernel", &[], Some(json!({"key":"after:resume","from":0,"to":0,"context":{"n":1}}))).unwrap();
        assert_eq!(v["checkpointed"], true, "{v}");
        s.revoke_observation("owner", &r.accepted[0]).unwrap();
        let v = s.submit_operations_id("after-3", "builder", &[json!({"kind":"no-such-operation"})], None).unwrap();
        assert_eq!(v["failed_index"], 0, "{v}");
        let reached = (replayed(&s), s.audit_root(), s.engine_root(), s.wal_head());
        drop(s);
        resumes.push((reached, std::fs::read(&resumed.0).unwrap()));
    }
    assert_eq!(resumes[1].0, resumes[0].0, "the same state after the same commands");
    assert_eq!(resumes[1].1, resumes[0].1, "the same journal, byte for byte");
}

#[test]
fn an_entry_that_reports_no_failure_replays_without_a_copy_of_the_state() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    let lines = [observation("o1", "Prior witness.")];
    assert!(s.submit_records_id("first", "worker", "task", &scope(), &lines).error.is_none());
    assert!(s.submit_records_id("second", "worker", "task-2", &scope(), &[observation("o2", "New witness.")]).error.is_none());
    let v = s.submit_operations_id("third", "kernel", &[], Some(json!({"key":"k","from":0,"to":0,"context":{}}))).unwrap();
    assert_eq!(v["checkpointed"], true, "{v}");
    let refused = s.submit_records_id("fourth", "worker", "task-3", &scope(), &[observation("o3", "No such quote.")]);
    assert_eq!(refused.failed_index, Some(0));
    drop(s);
    let before = FORKS.with(std::cell::Cell::get);
    drop(AuditState::open(&path.0).unwrap());
    assert_eq!(FORKS.with(std::cell::Cell::get) - before, 2, "one for the first entry, which may install a version map, one for the refused line");
}

#[test]
fn a_journal_that_misreports_an_entry_is_refused_as_a_replay_on_copies_refuses_it() {
    let path = TempPath::new();
    fork_scenario(&path.0);
    let frames: Vec<Value> = std::fs::read_to_string(&path.0).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let mut clean = 0;
    let mut refused = 0;
    for n in 1..frames.len() {
        let original = &frames[n]["payload"];
        let failed = original["outcome"]["kind"] == "error" || !original["outcome"]["result"]["error"].is_null();
        (clean, refused) = if failed { (clean, refused + 1) } else { (clean + 1, refused) };
        let mut forgeries = vec![
            ("audit_root", json!(to_hex(&ZERO_HASH))),
            ("engine_root", json!(to_hex(&ZERO_HASH))),
            ("outcome", json!({"kind":"error","error":KernelError::new(Code::BadField, "never happened").to_json()})),
        ];
        if failed {
            // the entry of a failed command, written as a success: the replay on the state itself runs it with no way back
            let mut success = original["outcome"].clone();
            if success["kind"] == "error" {
                success = json!({"kind":"value","result":{}});
            } else {
                success["result"]["error"] = Value::Null;
                success["result"]["failed_index"] = Value::Null;
            }
            forgeries.push(("outcome", success));
        }
        for (field, forged) in forgeries {
            let mut changed = frames.clone();
            changed[n]["payload"][field] = forged;
            chained(&path.0, changed);
            let (on_copies, in_place) = (verified(&path.0, true), verified(&path.0, false));
            assert_eq!(in_place.0, on_copies.0, "entry {n}, {field}: the same states before the refusal");
            let refusal = on_copies.1.err().unwrap_or_else(|| panic!("entry {n}, {field}: a forged entry was accepted"));
            assert_eq!(in_place.1.err(), Some(refusal.clone()), "entry {n}, {field}: the same refusal");
            assert!(refusal["message"].as_str().unwrap().contains("semantic replay diverged"), "entry {n}, {field}: {refusal}");
        }
    }
    assert!(clean > 8 && refused > 4, "the scenario keeps both kinds of entry: {clean} clean, {refused} refused");
}

fn frames_of(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

/// An attacker who knows the replay runs on the state: the entry carries the roots that very path computes, not those of a copy.
#[test]
fn forged_entries_with_the_roots_of_the_run_on_the_state_are_judged_as_on_copies() {
    let path = TempPath::new();
    fork_scenario(&path.0);
    let frames = frames_of(&path.0);
    let work = TempPath::new();
    let bad_claim = json!({"kind":"claim","local_id":"zz","text":"Claim zz.","subject":"alpha","stance":"reported","based_on":["missing"]});
    let good_obs = json!({"kind":"observe","local_id":"zo","doc_id":"a","exact_quote":"Alpha three.","terms":["alpha"]});
    let ok_ck = |key: &str| json!({"kind":"checkpoint","key":key,"from":0,"to":0,"context":{"n":1}});
    let (mut accepted_in_place, mut accepted_copies, mut tried) = (0, 0, 0);
    for n in 2..frames.len() {
        chained(&work.0, frames[..n].to_vec());
        let observes: Vec<String> = {
            let (s, _) = AuditState::verify(&work.0, &mut |_, _, _, _| {}).unwrap();
            s.records_since(0).iter().filter(|r| r.kind == RecordKind::Observe).map(|r| to_hex(&r.id.0)).collect()
        };
        let revoke = observes.first().map(|r| json!({"kind":"revoke","record":r})).unwrap_or(json!({"kind":"no-such"}));
        let submit = |lines: Vec<Value>| json!({"kind":"submit","directive":format!("zd{n}"),"scope":{"docs":["a"],"topic":null,"ranges":[]},"lines":lines});
        let commands = vec![
            ("kernel", json!({"kind":"batch","operations":[ok_ck("za"),{"kind":"no-such"}],"checkpoint":null})),
            ("kernel", json!({"kind":"batch","operations":[revoke.clone(),{"kind":"no-such"}],"checkpoint":null})),
            ("kernel", json!({"kind":"batch","operations":[revoke.clone(),ok_ck("zb")],"checkpoint":{"key":"zc","from":5,"to":5,"context":{}}})),
            ("zw", submit(vec![good_obs.clone(), bad_claim.clone()])),
            ("kernel", json!({"kind":"batch","operations":[submit(vec![good_obs.clone(), bad_claim.clone()]),ok_ck("zd")],"checkpoint":null})),
            ("zw", submit(vec![json!({"kind":"observe","local_id":"zq","doc_id":"a","exact_quote":"Not there.","terms":["alpha"]})])),
            ("kernel", json!({"kind":"checkpoint","key":crate::audit::versions::KEY,"from":0,"to":0,"context":{}})),
            ("kernel", json!({"kind":"checkpoint","key":"version:lease:zt","from":0,"to":0,"context":{"agent":"zw","card":"x"}})),
            ("kernel", json!({"kind":"batch","operations":[{"kind":"batch","operations":[],"checkpoint":null}],"checkpoint":null})),
            ("kernel", frames[n]["payload"]["command"].clone()),
        ];
        for (k, (actor, command)) in commands.into_iter().enumerate() {
            let (mut s, _) = AuditState::verify(&work.0, &mut |_, _, _, _| {}).unwrap();
            let id = format!("forged-{n}-{k}");
            let outcome = s.core.replay_in_place(actor, &id, &command).value();
            let (audit, engine) = (s.audit_root(), s.engine_root());
            drop(s);
            let mut said_success = outcome.clone();
            if said_success["kind"] == "error" {
                said_success = json!({"kind":"value","result":{}});
            } else {
                said_success["result"]["error"] = Value::Null;
                said_success["result"]["failed_index"] = Value::Null;
            }
            for told in [outcome, said_success] {
                let mut forged = frames[..=n].to_vec();
                let payload = &mut forged[n]["payload"];
                payload["actor"] = json!(actor);
                payload["submission_id"] = json!(id);
                payload["command"] = command.clone();
                payload["request_hash"] = json!(to_hex(&request_hash(actor, &command)));
                payload["outcome"] = told;
                payload["audit_root"] = json!(to_hex(&audit));
                payload["engine_root"] = json!(to_hex(&engine));
                let journal = TempPath::new();
                chained(&journal.0, forged);
                let (copies, in_place) = (verified(&journal.0, true), verified(&journal.0, false));
                tried += 1;
                accepted_in_place += usize::from(in_place.1.is_ok());
                accepted_copies += usize::from(copies.1.is_ok());
                assert_eq!(in_place.0, copies.0, "entry {n} command {k}: states seen");
                assert_eq!(in_place.1, copies.1, "entry {n} command {k}: verdict and state");
            }
        }
    }
    assert_eq!(accepted_in_place, accepted_copies, "the two ways accept the same entries");
    assert!(tried > 100, "{tried} forgeries");
}

/// Random honest runs with every kind of failure in them: after each command the kept flags equal fresh ones, and the two replays,
/// a torn tail and a resumed server end alike.
#[test]
fn random_runs_replay_alike_on_the_state_and_on_copies() {
    let keys = ["a", "b", "\u{ffff}", "\u{10000}", "\u{e000}", "\u{10ffff}", "k\"q", "k\\b", "k\u{1}", "\u{2028}", ""];
    let quotes = ["Alpha one.", "Alpha two.", "Alpha three.", "Beta one.", "Beta two.", "Not there."];
    let (mut ok_commands, mut failed_commands, mut concepts) = (0, 0, 0);
    for seed in 0..12u64 {
        let mut rng = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut next = move |n: u64| {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (rng >> 33) % n
        };
        let path = TempPath::new();
        let docs = [("a".to_string(), b"Alpha one.\nAlpha two.\nAlpha three.\n".to_vec()), ("b".to_string(), b"Beta one.\nBeta two.\n".to_vec())];
        let mut s = AuditState::create(&path.0, &AuditOntology::base(), &docs, "review", sha256(b"review")).unwrap();
        let mut cursors: BTreeMap<String, u64> = BTreeMap::new();
        for step in 0..36u64 {
            let id = format!("c{step}");
            let observes: Vec<RecordId> = s.records_since(0).iter().filter(|r| r.kind == RecordKind::Observe).map(|r| r.id).collect();
            let head = s.head();
            let mut checkpoint = || {
                let key = keys[next(keys.len() as u64) as usize].to_string();
                let from = cursors.get(&key).copied().unwrap_or(0);
                json!({"kind":"checkpoint","key":key,"from":from,"to":head.max(from),"context":{"step":step}})
            };
            let (a, b, c) = (checkpoint(), checkpoint(), checkpoint());
            let pick = next(9);
            let doc = if next(2) == 0 { "a" } else { "b" };
            let quote = match (doc, next(8)) {
                (_, 0) => "Not there.",
                ("a", n) => quotes[(n % 3) as usize],
                (_, n) => quotes[3 + (n % 2) as usize],
            };
            let scope = Scope { docs: vec![doc.into()], topic: None, ranges: Vec::new() };
            let observe = json!({"kind":"observe","local_id":"o","doc_id":doc,"exact_quote":quote,"terms":["alpha"]});
            let claim = json!({"kind":"claim","local_id":"c","text":format!("Claim {step}."),"subject":"alpha","stance":"reported","based_on":["o"]});
            let other = json!({"kind":"claim","local_id":"d","text":format!("Other {step}."),"subject":"alpha","stance":"reported","based_on":["o"]});
            let relation = json!({"kind":"relation","local_id":"r","from":"d","rel":"supports","to":"c","based_on":["o"]});
            let broken = json!({"kind":"claim","local_id":"x","text":"Broken.","subject":"alpha","stance":"reported","based_on":["missing"]});
            let any = observes.get(next(observes.len().max(1) as u64) as usize).map(|r| to_hex(&r.0));
            let revoke = any.as_ref().map(|r| json!({"kind":"revoke","record":r})).unwrap_or(json!({"kind":"no-such"}));
            let concept = any
                .as_ref()
                .map(|r| json!({"kind":"propose_concept","type":"Component","name":format!("name {seed} {step}"),"aliases":[],"basis":[r]}))
                .unwrap_or(json!({"kind":"no-such"}));
            let failed = match pick {
                0 => s.submit_records_id(&id, "w1", &format!("t{step}"), &scope, &[observe, claim]).error.is_some(),
                1 => s.submit_records_id(&id, "w2", &format!("t{step}"), &scope, &[observe, claim, other, relation]).error.is_some(),
                2 => s.submit_records_id(&id, "w3", &format!("t{step}"), &scope, &[observe, claim, broken]).error.is_some(),
                3 => !s.submit_operations_id(&id, "kernel", &[], Some(a)).unwrap()["error"].is_null(),
                4 => !s.submit_operations_id(&id, "kernel", &[a, b], Some(c)).unwrap()["error"].is_null(),
                5 => !s.submit_operations_id(&id, "kernel", &[a, json!({"kind":"no-such"}), b], None).unwrap()["error"].is_null(),
                6 => !s.submit_operations_id(&id, "kernel", &[revoke, a], None).unwrap()["error"].is_null(),
                7 => {
                    let v = s.submit_operations_id(&id, "kernel", &[concept], None).unwrap();
                    concepts += usize::from(v["error"].is_null());
                    !v["error"].is_null()
                }
                _ => match observes.first() {
                    Some(r) => s.revoke_observation("owner", r).is_err(),
                    None => true,
                },
            };
            if failed {
                failed_commands += 1;
            } else {
                ok_commands += 1;
            }
            for (key, value) in s.core.data.checkpoints.iter() {
                cursors.insert(key.clone(), value["to"].as_u64().unwrap_or(0));
            }
            assert_eq!(*s.core.support_flags(), s.core.support_flags_fresh(), "seed {seed} step {step}: kept flags");
            let _ = s.audit_root();
        }
        drop(s);
        let (copies, in_place) = (verified(&path.0, true), verified(&path.0, false));
        assert!(copies.1.is_ok(), "seed {seed}: {:?}", copies.1.err());
        assert_eq!(in_place, copies, "seed {seed}");
        // a torn tail, then a resumed server
        let mut bytes = std::fs::read(&path.0).unwrap();
        bytes.extend_from_slice(b"{\"format\":\"torn");
        let mut after = Vec::new();
        for copy in [true, false] {
            let resumed = TempPath::new();
            std::fs::write(&resumed.0, &bytes).unwrap();
            COPY_REPLAY.with(|c| c.set(copy));
            let mut r = AuditState::open(&resumed.0).unwrap();
            COPY_REPLAY.with(|c| c.set(false));
            assert_eq!(*r.core.support_flags(), r.core.support_flags_fresh(), "seed {seed}: flags after recovery");
            let scope = Scope { docs: vec!["a".into()], topic: None, ranges: Vec::new() };
            r.submit_records_id(
                "after-1",
                "w9",
                "t9",
                &scope,
                &[json!({"kind":"observe","local_id":"o","doc_id":"a","exact_quote":"Alpha one.","terms":["alpha"]})],
            );
            let v = r.submit_operations_id("after-2", "kernel", &[], Some(json!({"key":"after","from":0,"to":0,"context":{}}))).unwrap();
            assert!(v["error"].is_null());
            let reached = (replayed(&r), r.audit_root(), r.engine_root(), r.wal_head());
            drop(r);
            after.push((reached, std::fs::read(&resumed.0).unwrap()));
            for kept in std::fs::read_dir(std::env::temp_dir()).into_iter().flatten().flatten() {
                if kept.file_name().to_string_lossy().starts_with(&format!("{}.torn-", resumed.0.file_name().unwrap().to_string_lossy())) {
                    let _ = std::fs::remove_file(kept.path());
                }
            }
        }
        assert_eq!(after[0], after[1], "seed {seed}: resumed alike");
    }
    assert!(ok_commands > 80 && failed_commands > 100 && concepts > 0, "{ok_commands} clean, {failed_commands} failed, {concepts} concepts");
}

/// A claim of `withdrawal` tests, on the observation `on`.
fn resting_on(local_id: &str, on: &str) -> Value {
    json!({"kind":"claim","local_id":local_id,"text":"A witness stands.","subject":"witness","stance":"reported","based_on":[on]})
}

fn refused_as_withdrawn(s: &mut AuditState, id: &str, quote: &str) -> bool {
    let r = s.submit_records_id(id, "worker", id, &scope(), &[observation("q", quote)]);
    r.accepted.is_empty() && r.error.is_some_and(|e| e.to_json()["code"] == "EVIDENCE_REVOKED")
}

/// Series of 06.11.2026: a reader went back to the page after the withdrawal and stored the sentence with its list number, three
/// bytes wider. The kernel refused only the exact span, so the withdrawn text came back as a new record with its support.
#[test]
fn a_wider_quote_does_not_bring_withdrawn_text_back() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    let r = s.submit_records_id("seed", "worker", "seed", &scope(), &[observation("o1", "Prior witness."), resting_on("c1", "o1")]);
    assert_eq!(r.accepted.len(), 2, "{:?}", r.error);
    let (o1, c1) = (r.accepted[0], r.accepted[1]);
    assert_eq!(s.revoke_observation("owner", &o1).unwrap(), 0);
    assert!(!s.is_grounded(&c1));
    for (id, quote) in [("exact", "Prior witness."), ("wider", "Prior witness.\nNew"), ("narrower", "Prior wit"), ("across", "witness.\nNew witness.")] {
        assert!(refused_as_withdrawn(&mut s, id, quote), "{id}");
    }
    let other = s.submit_records_id("other", "worker", "other", &scope(), &[observation("o2", "New witness."), resting_on("c2", "o2")]);
    assert_eq!(other.accepted.len(), 2, "text beside the withdrawn span stays open: {:?}", other.error);
    assert!(s.is_grounded(&other.accepted[1]));
    let roots = (s.engine_root(), s.audit_root(), s.wal_head());
    drop(s);
    let mut s = AuditState::open(&path.0).unwrap();
    assert_eq!((s.engine_root(), s.audit_root(), s.wal_head()), roots);
    assert!(refused_as_withdrawn(&mut s, "after-restart", "Prior witness.\nNew"), "a restart keeps the span closed");
}

#[test]
fn a_withdrawal_takes_every_stored_quote_that_overlaps_it() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    let lines = [
        observation("o1", "Prior witness."),
        observation("o2", "witness.\nNew"),
        observation("o3", "New witness."),
        resting_on("c2", "o2"),
        resting_on("c3", "o3"),
    ];
    let r = s.submit_records_id("seed", "worker", "seed", &scope(), &lines);
    assert_eq!(r.accepted.len(), 5, "{:?}", r.error);
    let (o1, o2, o3, c2, c3) = (r.accepted[0], r.accepted[1], r.accepted[2], r.accepted[3], r.accepted[4]);
    assert_eq!(s.revoke_observation("owner", &o1).unwrap(), 1, "the quote that overlaps it, and not the one that overlaps only that quote");
    assert!(!s.is_grounded(&o2) && !s.is_grounded(&c2));
    assert!(s.is_grounded(&o3) && s.is_grounded(&c3));
    let roots = (s.engine_root(), s.audit_root(), s.wal_head());
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    assert_eq!((s.engine_root(), s.audit_root(), s.wal_head()), roots, "a replay repeats the withdrawal");
}

/// A recorded outcome has to replay as it was recorded: a journal of the first format, such as the published ones, keeps its rule.
#[test]
fn a_journal_of_the_first_format_keeps_the_exact_span_rule() {
    let path = TempPath::new();
    let base = AuditOntology::base();
    let mut s = AuditState::new(&base, &[("policy".into(), b"Prior witness.\nNew witness.\n".to_vec())]).unwrap();
    s.core.data.run_id = "first-format".into();
    s.core.data.withdrawal_closes_bytes = false;
    s.attach_new_journal(&path.0, &base).unwrap();
    let r = s.submit_records_id("seed", "worker", "seed", &scope(), &[observation("o1", "Prior witness.")]);
    assert_eq!(s.revoke_observation("owner", &r.accepted[0]).unwrap(), 0);
    assert!(refused_as_withdrawn(&mut s, "exact", "Prior witness."));
    assert!(s.withdraw_text("owner", "policy", "New witness.").is_err(), "the rule of its release has no such command");
    let wider = s.submit_records_id("wider", "worker", "wider", &scope(), &[observation("o2", "Prior witness.\nNew")]);
    assert_eq!(wider.accepted.len(), 1, "{:?}", wider.error);
    let roots = (s.engine_root(), s.audit_root(), s.wal_head());
    drop(s);
    assert!(std::fs::read_to_string(&path.0).unwrap().lines().next().unwrap().contains(GENESIS_FORMAT_EXACT_SPAN));
    let s = AuditState::open(&path.0).unwrap();
    assert_eq!((s.engine_root(), s.audit_root(), s.wal_head()), roots);
}

#[test]
fn a_new_journal_records_the_rule_of_closed_bytes() {
    let path = TempPath::new();
    drop(state(&path.0));
    assert!(std::fs::read_to_string(&path.0).unwrap().lines().next().unwrap().contains(GENESIS_FORMAT));
}

/// The order of two withdrawals does not decide what stays open: a quote that went with a narrower one can still be withdrawn, and the
/// rest of its text closes then (review of 06.11.2026, D02).
#[test]
fn a_quote_that_went_with_another_can_still_close_its_own_text() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    let r = s.submit_records_id("seed", "worker", "seed", &scope(), &[observation("o1", "Prior w"), observation("o2", "Prior witness.")]);
    assert_eq!(r.accepted.len(), 2, "{:?}", r.error);
    assert_eq!(s.revoke_observation("owner", &r.accepted[0]).unwrap(), 1);
    assert_eq!(s.revoke_observation("owner", &r.accepted[1]).unwrap(), 0);
    assert!(refused_as_withdrawn(&mut s, "rest", "itness.\nNew"));
    assert!(s.revoke_observation("owner", &r.accepted[1]).is_err(), "nothing is left to close");
}

/// A step of a withdrawal plan on text nobody quoted closed nothing (D01), and a new version of the document opened it again (D03).
#[test]
fn a_text_nobody_quoted_can_be_withdrawn_and_stays_closed_in_a_new_version() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    assert_eq!(s.withdraw_text("owner", "policy", "Prior witness.").unwrap(), 0);
    assert!(s.withdraw_text("owner", "policy", "Prior witness.").is_err(), "already withdrawn");
    assert!(s.withdraw_text("owner", "policy", "No such text.").is_err());
    assert!(s.withdraw_text("owner", "no-such-document", "Prior witness.").is_err());
    assert!(refused_as_withdrawn(&mut s, "wider", "Prior witness.\nNew"));
    s.put_document("owner", "policy", b"Added line.\nPrior witness.\nNew witness.\n").unwrap();
    assert!(refused_as_withdrawn(&mut s, "exact-in-new", "Prior witness."));
    assert!(refused_as_withdrawn(&mut s, "wider-in-new", "line.\nPrior"));
    let open = s.submit_records_id("open", "worker", "open", &scope(), &[observation("o", "Added line.")]);
    assert_eq!(open.accepted.len(), 1, "{:?}", open.error);
    let roots = (s.engine_root(), s.audit_root(), s.wal_head());
    drop(s);
    let mut s = AuditState::open(&path.0).unwrap();
    assert_eq!((s.engine_root(), s.audit_root(), s.wal_head()), roots);
    assert!(refused_as_withdrawn(&mut s, "after-restart", "Prior witness."));
}

/// Two documents can have the same bytes and so the same version id: a withdrawal stays in its document (D04) and reaches every place
/// of the text in it (D03).
#[test]
fn a_withdrawal_stays_in_its_document_and_reaches_every_place_in_it() {
    let path = TempPath::new();
    let bytes = b"One same.\nTwo same.\nThree.\n".to_vec();
    let mut s =
        AuditState::create(&path.0, &AuditOntology::base(), &[("a".into(), bytes.clone()), ("b".into(), bytes)], "two-documents", sha256(b"fixture")).unwrap();
    let both = Scope { docs: vec!["a".into(), "b".into()], topic: Some("witnesses".into()), ranges: Vec::new() };
    let quote = |id: &str, doc: &str, text: &str| json!({"kind":"observe","local_id":id,"doc_id":doc,"exact_quote":text,"terms":["witness"]});
    let lines = [quote("o1", "a", "One same."), quote("o2", "a", "Two same."), quote("o3", "a", "Three."), quote("o4", "b", "One same.")];
    let r = s.submit_records_id("seed", "worker", "seed", &both, &lines);
    assert_eq!(r.accepted.len(), 4, "{:?}", r.error);
    assert_eq!(s.withdraw_text("owner", "a", "same.").unwrap(), 2);
    assert!(!s.is_grounded(&r.accepted[0]) && !s.is_grounded(&r.accepted[1]));
    assert!(s.is_grounded(&r.accepted[2]) && s.is_grounded(&r.accepted[3]));
    let other = s.submit_records_id("other", "worker", "other", &both, &[quote("o5", "b", "Two same."), quote("o6", "a", "One")]);
    assert_eq!(other.accepted.len(), 2, "{:?}", other.error);
}

/// A quote of an earlier version comes back with that version, and what was withdrawn meanwhile must not come back with it (D08).
#[test]
fn a_document_that_returns_to_an_earlier_version_keeps_the_text_closed() {
    let path = TempPath::new();
    let mut s = state(&path.0);
    let lines = [observation("o1", "Prior witness."), observation("o2", "witness.\nNew"), resting_on("c1", "o1"), resting_on("c2", "o2")];
    let r = s.submit_records_id("seed", "worker", "seed", &scope(), &lines);
    assert_eq!(r.accepted.len(), 4, "{:?}", r.error);
    s.put_document("owner", "policy", b"Added line.\nPrior witness.\nNew witness.\n").unwrap();
    assert_eq!(s.withdraw_text("owner", "policy", "Prior witness.").unwrap(), 0, "no quote of this version");
    s.put_document("owner", "policy", b"Prior witness.\nNew witness.\n").unwrap();
    for id in &r.accepted {
        assert!(!s.is_grounded(id));
    }
    let roots = (s.engine_root(), s.audit_root(), s.wal_head());
    drop(s);
    let s = AuditState::open(&path.0).unwrap();
    assert_eq!((s.engine_root(), s.audit_root(), s.wal_head()), roots);
}

/// The text of a quote, not an identifier (D09).
#[test]
fn a_text_with_a_line_break_and_a_long_text_can_be_withdrawn() {
    let path = TempPath::new();
    let long = "Long line. ".repeat(200);
    let bytes = format!("Prior witness.\nNew witness.\n{long}\n");
    let mut s = AuditState::create(&path.0, &AuditOntology::base(), &[("policy".into(), bytes.into_bytes())], "text", sha256(b"fixture")).unwrap();
    assert_eq!(s.withdraw_text("owner", "policy", "witness.\nNew").unwrap(), 0);
    assert_eq!(s.withdraw_text("owner", "policy", long.trim_end()).unwrap(), 0);
    assert!(refused_as_withdrawn(&mut s, "broken", "Prior witness."));
}

#[test]
fn a_journal_of_a_folder_says_when_its_documents_are_not_the_set_it_started_on() {
    let wal = TempPath::new();
    let docs = vec![("b.txt".to_string(), b"Beta.\n".to_vec()), ("a.txt".to_string(), b"Alpha.\n".to_vec())];
    let mut s = AuditState::create_from_docs(&wal.0, &AuditOntology::base(), "folder", docs).unwrap();
    assert!(s.docs_set_matches());
    assert_eq!(s.source_document_count(), 2);
    s.put_document("owner", "a.txt", b"Alpha, changed.\n").unwrap();
    assert!(!s.docs_set_matches());
    drop(s);
    let (replayed, read) = AuditState::verify(&wal.0, &mut |_, _, _, _| {}).unwrap();
    assert_eq!((replayed.docs_set_matches(), read.document_puts), (false, 1));
    drop(replayed);
    // R017-04: a document put inside a batch counts, and a document that came back matches again with the count showing it
    let mut s = AuditState::open(&wal.0).unwrap();
    let put = json!({"kind":"put_document","doc_id":"a.txt","text":"Alpha.\n"});
    s.submit_operations_id("back", "owner", &[put], None).unwrap();
    assert!(s.docs_set_matches());
    drop(s);
    let (replayed, read) = AuditState::verify(&wal.0, &mut |_, _, _, _| {}).unwrap();
    assert_eq!((replayed.docs_set_matches(), read.document_puts), (true, 2));
    // the library's own value says no from the start: nothing in such a journal claims to be a folder's set
    let other = TempPath::new();
    let library = AuditState::create(&other.0, &AuditOntology::base(), &[("a".to_string(), b"Alpha.\n".to_vec())], "library", sha256(b"own")).unwrap();
    assert!(!library.docs_set_matches());
}

/// R017-03: the keys of a document's tasks hold its name, so a name that fits an identifier can give a key that does not.
#[test]
fn a_document_name_leaves_room_for_the_keys_of_its_tasks() {
    let wal = TempPath::new();
    let long = |n: usize| vec![(format!("{}.txt", "a".repeat(n - 4)), b"Alpha.\n".to_vec())];
    let refused = AuditState::create_from_docs(&wal.0, &AuditOntology::base(), "names", long(MAX_DOC_NAME_BYTES + 1));
    assert!(refused.is_err());
    assert!(!wal.0.exists(), "no journal is left behind");
    let mut s = AuditState::create_from_docs(&wal.0, &AuditOntology::base(), "names", long(MAX_DOC_NAME_BYTES)).unwrap();
    let id = long(MAX_DOC_NAME_BYTES)[0].0.clone();
    let key = format!("task:reread:{id}#99999");
    let check = json!({"kind":"checkpoint","key":key,"from":0,"to":0,"context":{}});
    s.submit_operations_id("key", "kernel", &[check], None).unwrap();
}
