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
