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

fn state_v2(path: &Path) -> AuditState {
    AuditState::create_v2(
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
    let mut state = state_v2(&path.0);
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
    let (journal, scan) = AuditJournal::open(&path.0).unwrap();
    let payloads = scan.payloads;
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
    // the frames of the first formats: the forgery tests below rewrite them (the /3 ones have their own)
    let mut s = AuditState::create_v2(path, &AuditOntology::base(), &docs, "fork-differential", sha256(b"fork differential manifest")).unwrap();
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
    assert_eq!(session_root_v2(&end.1, &end.0), end.2);
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
    let genesis = std::fs::read_to_string(&path.0).unwrap().lines().next().unwrap().to_string();
    assert!(genesis.contains(GENESIS_FORMAT_V3) && genesis.contains(RULES_VERSION), "{genesis}");
    let old = TempPath::new();
    drop(state_v2(&old.0));
    assert!(std::fs::read_to_string(&old.0).unwrap().lines().next().unwrap().contains(GENESIS_FORMAT));
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
    drop(replayed);
    // a batch stops at a failed operation: what follows it was not applied, and it is not counted
    let mut s = AuditState::open(&wal.0).unwrap();
    let put = |text: &str| json!({"kind":"put_document","doc_id":"a.txt","text":text});
    s.submit_operations_id("tail", "owner", &[put("Second.\n"), json!({"kind":"no-such"}), put("Third.\n")], None).unwrap();
    assert_eq!(s.doc_text("a.txt").as_deref(), Some("Second.\n"));
    drop(s);
    assert_eq!(AuditState::verify(&wal.0, &mut |_, _, _, _| {}).unwrap().1.document_puts, 3);
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

// ---- the 0.2 journal (SPEC_V02_STEP2) ----

fn claim(local_id: &str, text: &str, based_on: &[&str]) -> Value {
    json!({"kind":"claim","local_id":local_id,"text":text,"subject":"witness","stance":"reported","based_on":based_on})
}

fn v3_spec() -> GenesisSpec {
    GenesisSpec {
        questions: json!([{"id": "RQ1", "text": "What is witnessed?"}]),
        settings: json!({"format": "r2r-audit-mcp-coverage/1", "section_bytes": 4096}),
        operator_meta: Some(json!({"team": "fixture"})),
    }
}

fn v3_run(path: &Path) -> AuditState {
    let docs = [("policy".to_string(), b"Prior witness.\nNew witness.\n".to_vec())];
    let mut s = AuditState::create_with(path, &AuditOntology::base(), &docs, "v3-run", sha256(b"v3 manifest"), &v3_spec()).unwrap();
    let r = s.submit_records_id(
        "seed",
        "worker",
        "task",
        &scope(),
        &[observation("o1", "Prior witness."), observation("o2", "New witness."), claim("c1", "Witnessed twice.", &["o1", "o2"])],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    s.submit_operations_id("ck", "kernel", &[], Some(json!({"key":"k","from":0,"to":1,"context":{}}))).unwrap();
    assert_eq!(s.revoke_observation("owner", &r.accepted[0]).unwrap(), 0);
    s
}

/// Writes `/3` frames with a valid header chain and body hashes: only the replay can tell what is wrong with them.
fn chained_v3(path: &Path, mut frames: Vec<Value>) {
    let mut previous = ZERO_HASH;
    let mut bytes = String::new();
    for frame in &mut frames {
        frame["header"]["previous"] = json!(to_hex(&previous));
        frame["header"]["body_hash"] = json!(to_hex(&crate::audit::persistence::body_hash(&frame["body"])));
        previous = sha256_parts(&[b"R2R-FRAME-HDR/2\0", to_jcs(&frame["header"]).as_bytes()]);
        frame["hash"] = json!(to_hex(&previous));
        bytes.push_str(&to_jcs(frame));
        bytes.push('\n');
    }
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_v3_journal_names_its_genesis_and_reopens_and_verifies_to_the_same_roots() {
    let path = TempPath::new();
    let s = v3_run(&path.0);
    let end = (s.audit_root(), s.engine_root(), s.session_root(), s.wal_head());
    assert_eq!(end.2, session_root_v2(&end.1, &end.0));
    drop(s);
    let text = std::fs::read_to_string(&path.0).unwrap();
    let genesis: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(genesis["header"]["format"], "sbgk-session-log/3");
    let g = &genesis["body"];
    assert_eq!(
        (g["format"].as_str(), g["rules_version"].as_str(), g["state_root_format"].as_str(), g["seal_format"].as_str()),
        (Some(GENESIS_FORMAT_V3), Some(RULES_VERSION), Some("r2r-state-root/2"), Some(SEAL_FORMAT))
    );
    assert_eq!(g["questions"], v3_spec().questions);
    assert_eq!(g["settings_hash"], json!(to_hex(&settings_hash(&v3_spec().settings))));
    assert_eq!(g["operator_meta"], json!({"team": "fixture"}));
    let reopened = AuditState::open(&path.0).unwrap();
    assert_eq!((reopened.audit_root(), reopened.engine_root(), reopened.session_root(), reopened.wal_head()), end);
    let meta = reopened.genesis_meta().expect("a /3 genesis");
    assert_eq!((meta.questions.clone(), meta.settings_hash), (v3_spec().questions, settings_hash(&v3_spec().settings)));
    drop(reopened);
    let (verified, read) = AuditState::verify(&path.0, &mut |_, _, _, _| {}).unwrap();
    assert_eq!((verified.audit_root(), Some(read.wal_head)), (end.0, end.3));
    // the seed frame accepted three records: its records root is their tree; the checkpoint frame accepted none
    let frames: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_ne!(frames[1]["header"]["records_root"], json!(to_hex(&crate::audit::trees::records_root(&[]))));
    assert_eq!(frames[2]["header"]["records_root"], json!(to_hex(&crate::audit::trees::records_root(&[]))));
}

#[test]
fn every_forged_body_records_root_and_genesis_field_of_a_v3_journal_is_refused() {
    let path = TempPath::new();
    drop(v3_run(&path.0));
    let frames: Vec<Value> = std::fs::read_to_string(&path.0).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let work = TempPath::new();
    chained_v3(&work.0, frames.clone());
    AuditState::verify(&work.0, &mut |_, _, _, _| {}).expect("a faithful rechain verifies");
    for n in 1..frames.len() {
        for (field, forged) in
            [("audit_root", json!(to_hex(&ZERO_HASH))), ("engine_root", json!(to_hex(&ZERO_HASH))), ("outcome", json!({"kind":"value","result":{}}))]
        {
            let mut changed = frames.clone();
            changed[n]["body"][field] = forged;
            chained_v3(&work.0, changed);
            assert!(AuditState::verify(&work.0, &mut |_, _, _, _| {}).is_err(), "entry {n}: forged {field} was accepted");
        }
        let mut changed = frames.clone();
        changed[n]["header"]["records_root"] = json!(to_hex(&sha256(b"other records")));
        chained_v3(&work.0, changed);
        let refusal = AuditState::verify(&work.0, &mut |_, _, _, _| {}).err().unwrap_or_else(|| panic!("entry {n}: a forged records root was accepted"));
        assert!(refusal.message.contains("records root"), "{refusal}");
    }
    for (field, forged, expected) in [
        ("rules_version", json!("r2r-audit-rules/9"), "this kernel replays"),
        ("state_root_format", json!("r2r-state-root/1"), "this kernel replays"),
        ("operator_meta", json!({"blob": "x".repeat(5000)}), "operator_meta"),
        ("questions", json!("not a list"), "questions"),
        ("extra", json!(1), "missing or unknown fields"),
    ] {
        let mut changed = frames.clone();
        changed[0]["body"][field] = forged;
        chained_v3(&work.0, changed);
        let refusal = AuditState::verify(&work.0, &mut |_, _, _, _| {}).err().unwrap_or_else(|| panic!("genesis {field} was accepted"));
        assert!(refusal.message.contains(expected), "{field}: {refusal}");
    }
    // a /3 frame chain with a genesis of the first formats
    let mut changed = frames.clone();
    changed[0]["body"]["format"] = json!(GENESIS_FORMAT);
    chained_v3(&work.0, changed);
    assert!(AuditState::verify(&work.0, &mut |_, _, _, _| {}).is_err());
}

/// The library writes no seal right after another, as its doc says (the architect's decision of 13.11 on step 4 of 0.2.1): a second
/// seal says `already`, and the close of a run whose last frame is a seal writes the close only. A seal after a new frame is written.
#[test]
fn a_seal_right_after_a_seal_is_not_written_again() {
    let path = TempPath::new();
    let mut s = v3_run(&path.0);
    let first = s.seal().unwrap();
    let entries = s.entries();
    let again = s.seal().unwrap();
    assert_eq!(again["already"], true, "{again}");
    assert_eq!(again["seal_hash"], first["seal_hash"]);
    assert_eq!(again["log_size"], first["seal"]["log_size"]);
    assert_eq!(s.entries(), entries, "no frame written");
    assert_eq!(s.seals().len(), 1);
    s.close_run().unwrap();
    assert_eq!(s.entries(), entries.map(|n| n + 1), "the close only");
    assert_eq!(s.seals().len(), 1);
    drop(s);
    assert_eq!(AuditState::open(&path.0).unwrap().seals().len(), 1);
    let verified = AuditState::verify(&path.0, &mut |_, _, _, _| {});
    assert!(verified.is_ok(), "{:?}", verified.err());
}

#[test]
fn a_seal_names_the_frames_the_roots_and_the_projections_and_a_forged_seal_is_refused() {
    let path = TempPath::new();
    let mut s = v3_run(&path.0);
    let frames_before = s.transaction_sequence().unwrap() as usize + 1;
    let (status, deps) = s.projection_hashes();
    let out = s.seal().unwrap();
    let seal = &out["seal"];
    assert_eq!(seal["log_size"], json!(frames_before));
    assert_eq!(seal["projections"], json!({"status": to_hex(&status), "dependencies": to_hex(&deps)}));
    assert_eq!(out["seal_hash"], json!(to_hex(&seal_hash(seal))));
    let end = s.audit_root();
    drop(s);
    assert_eq!(AuditState::open(&path.0).unwrap().audit_root(), end);
    let frames: Vec<Value> = std::fs::read_to_string(&path.0).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let n = frames.len() - 1;
    let work = TempPath::new();
    for (field, forged) in [
        ("log_root", json!(to_hex(&ZERO_HASH))),
        ("log_size", json!(1)),
        ("wal_head", json!(to_hex(&ZERO_HASH))),
        ("audit_root", json!(to_hex(&ZERO_HASH))),
        ("projections", json!({"status": to_hex(&ZERO_HASH), "dependencies": to_hex(&deps)})),
    ] {
        let mut changed = frames.clone();
        changed[n]["body"]["command"]["seal"][field] = forged.clone();
        changed[n]["body"]["outcome"]["result"]["seal"][field] = forged;
        changed[n]["body"]["request_hash"] = json!(to_hex(&request_hash("kernel", &changed[n]["body"]["command"])));
        chained_v3(&work.0, changed);
        assert!(AuditState::verify(&work.0, &mut |_, _, _, _| {}).is_err(), "a seal with a forged {field} was accepted");
    }
}

#[test]
fn a_closed_run_stays_closed_after_a_restart_and_seals_before_it_closes() {
    let path = TempPath::new();
    let mut s = v3_run(&path.0);
    assert!(!s.is_closed());
    let open_root = s.audit_root();
    s.close_run().unwrap();
    assert!(s.is_closed());
    assert_ne!(s.audit_root(), open_root, "closed is a leaf of the state");
    assert_eq!(s.close_run().unwrap()["already"], json!(true));
    let end = s.audit_root();
    drop(s);
    let reopened = AuditState::open(&path.0).unwrap();
    assert!(reopened.is_closed());
    assert_eq!(reopened.audit_root(), end);
    drop(reopened);
    let text = std::fs::read_to_string(&path.0).unwrap();
    let kinds: Vec<String> =
        text.lines().skip(1).map(|l| serde_json::from_str::<Value>(l).unwrap()["body"]["command"]["kind"].as_str().unwrap_or("").to_string()).collect();
    assert_eq!(kinds[kinds.len() - 2..], ["seal".to_string(), "close".to_string()]);
    // a journal of the first formats has no such entry
    let old = TempPath::new();
    let mut v2 = state_v2(&old.0);
    assert!(v2.close_run().is_err());
    assert!(v2.seal().is_err());
}

#[test]
fn seals_come_every_k_frames_and_the_epoch_of_a_v3_journal_is_its_chain_head() {
    let path = TempPath::new();
    let docs = [("policy".to_string(), b"Prior witness.\nNew witness.\n".to_vec())];
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "v3-seals", sha256(b"m"), &v3_spec()).unwrap();
    s.set_seal_every(Some(3));
    for i in 0..7 {
        s.submit_operations_id(&format!("ck{i}"), "kernel", &[], Some(json!({"key":format!("k{i}"),"from":0,"to":0,"context":{}}))).unwrap();
    }
    assert_eq!(AuditStore::epoch(&s), s.wal_head().unwrap());
    drop(s);
    let text = std::fs::read_to_string(&path.0).unwrap();
    let seals: Vec<usize> =
        text.lines().enumerate().filter(|(_, l)| serde_json::from_str::<Value>(l).unwrap()["body"]["command"]["kind"] == "seal").map(|(n, _)| n).collect();
    assert_eq!(seals, vec![4, 8], "a seal once three frames follow the genesis or the last seal");
    let reopened = AuditState::open(&path.0).unwrap();
    assert_eq!(AuditStore::epoch(&reopened), reopened.wal_head().unwrap());
}

#[test]
fn the_incremental_state_root_is_the_full_build_after_every_kind_of_change() {
    // `root()` compares the two at every call in a test build; this run touches every keyed section
    let path = TempPath::new();
    let mut s = v3_run(&path.0);
    s.withdraw_text("owner", "policy", "New witness.").unwrap();
    s.put_document("owner", "extra", b"Extra witness.\n").unwrap();
    let r = s.submit_records_id(
        "more",
        "worker2",
        "task2",
        &Scope { docs: vec!["extra".into()], ..Default::default() },
        &[json!({"kind":"observe","local_id":"x","doc_id":"extra","exact_quote":"Extra witness.","terms":["witness"]})],
    );
    assert!(r.error.is_none(), "{:?}", r.error);
    let root = s.audit_root();
    drop(s);
    assert_eq!(AuditState::open(&path.0).unwrap().audit_root(), root);
}

fn command_kinds(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["body"]["command"]["kind"].as_str().unwrap_or("").to_string())
        .collect()
}

fn forged_prefix_seal(s: &AuditState) -> Value {
    let (status, deps) = s.projection_hashes();
    json!({"kind": "seal", "seal": {"format": SEAL_FORMAT, "run_id": s.core.data.run_id, "log_size": 0, "log_root": to_hex(&ZERO_HASH),
        "wal_head": to_hex(&ZERO_HASH), "audit_root": to_hex(&s.audit_root()), "engine_root": to_hex(&s.engine_root()),
        "projections": {"status": to_hex(&status), "dependencies": to_hex(&deps)}}})
}

#[test]
fn a_seal_or_a_close_is_never_an_operation_of_a_batch_and_a_journal_with_one_does_not_verify() {
    // Codex review of 43447f4, S2-01: a seal inside a batch named a journal prefix that no check compared, and the journal verified
    let path = TempPath::new();
    let mut s = v3_run(&path.0);
    s.seal().unwrap();
    for (id, op) in [("nested-seal", forged_prefix_seal(&s)), ("nested-close", json!({"kind": "close"}))] {
        let out = s.submit_operations_id(id, "kernel", &[op], None).unwrap();
        assert_eq!((&out["accepted_operations"], &out["failed_index"]), (&json!(0), &json!(0)), "{out}");
        assert!(out["error"].to_string().contains("frame of its own"), "{out}");
    }
    assert!(!s.is_closed());
    drop(s);
    AuditState::verify(&path.0, &mut |_, _, _, _| {}).expect("refused batches verify");
    // the journal of a kernel that took the nested seal, as before the fix: the replay refuses it
    let old = TempPath::new();
    let mut w = v3_run(&old.0);
    w.seal().unwrap();
    let forged = forged_prefix_seal(&w);
    NESTED_FRAMES.with(|n| n.set(true));
    let out = w.submit_operations_id("nested-seal", "kernel", &[forged], None);
    NESTED_FRAMES.with(|n| n.set(false));
    assert_eq!(out.unwrap()["accepted_operations"], json!(1));
    drop(w);
    let refusal = AuditState::verify(&old.0, &mut |_, _, _, _| {}).err().expect("a journal with a seal inside a batch was verified");
    assert!(refusal.message.contains("diverged"), "{refusal}");
    assert!(AuditState::open(&old.0).is_err());
}

#[test]
fn the_ids_of_the_seal_and_the_close_are_the_kernels_and_a_failed_seal_leaves_its_command_standing() {
    // Codex review of 43447f4, S2-02: a batch took the id of the next seal, the automatic seal was refused, and the command it
    // followed came back as an error though the journal held it
    let path = TempPath::new();
    let docs = [("policy".to_string(), b"Prior witness.\n".to_vec())];
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "v3-pending", sha256(b"m"), &v3_spec()).unwrap();
    let ck = |k: &str| json!({"key": k, "from": 0, "to": 0, "context": {}});
    for id in ["seal-3", "audit-close"] {
        let refusal = s.submit_operations_id(id, "kernel", &[], Some(ck("k"))).err().unwrap_or_else(|| panic!("a batch took the id {id}"));
        assert!(refusal.message.contains("belong"), "{refusal}");
    }
    s.set_seal_every(Some(256));
    FAIL_SEALS.with(|n| n.set(1));
    let phase = json!({"key": "audit:circles", "from": 0, "to": 0, "context": {"circle": 1}});
    let out = s.submit_operations_id("phase-1", "kernel", &[], Some(phase.clone())).expect("the command stands though its seal failed");
    assert_eq!(out["checkpointed"], json!(true));
    assert!(s.seal_pending());
    assert_eq!(s.submit_operations_id("phase-1", "kernel", &[], Some(phase)).unwrap(), out, "a retry gets the receipt of the command");
    s.submit_operations_id("next", "kernel", &[], Some(ck("k1"))).unwrap();
    assert!(!s.seal_pending(), "the next command wrote the seal");
    drop(s);
    assert_eq!(command_kinds(&path.0), ["batch", "batch", "seal"]);
    AuditState::verify(&path.0, &mut |_, _, _, _| {}).unwrap();
    // a restart between a circle's phase change and its seal: the first command after it writes the seal
    let mut r = AuditState::open(&path.0).unwrap();
    assert!(!r.seal_pending());
    r.submit_operations_id("phase-2", "kernel", &[], Some(json!({"key": "audit:circles", "from": 0, "to": 0, "context": {"circle": 2}}))).unwrap();
    drop(r);
    let mut r = AuditState::open(&path.0).unwrap();
    assert!(r.seal_pending());
    r.set_seal_every(Some(256));
    r.submit_operations_id("after", "kernel", &[], Some(ck("k2"))).unwrap();
    assert!(!r.seal_pending());
    drop(r);
    let kinds = command_kinds(&path.0);
    assert_eq!(kinds[kinds.len() - 3..], ["batch", "batch", "seal"]);
    AuditState::verify(&path.0, &mut |_, _, _, _| {}).unwrap();
    // Codex recheck of db57a93: a refused phase change is no boundary, live or after a restart
    let mut r = AuditState::open(&path.0).unwrap();
    r.set_seal_every(Some(256));
    let refused = r.submit_operations_id("phase-bad", "kernel", &[], Some(json!({"key": "audit:circles", "from": 7, "to": 7, "context": {}}))).unwrap();
    assert_eq!(refused["checkpointed"], json!(false), "{refused}");
    assert!(!r.seal_pending());
    drop(r);
    let mut r = AuditState::open(&path.0).unwrap();
    assert!(!r.seal_pending(), "a refused phase change left no seal due");
    // and a seal written by hand settles one that was due
    r.set_seal_every(Some(256));
    FAIL_SEALS.with(|n| n.set(1));
    r.submit_operations_id("phase-3", "kernel", &[], Some(json!({"key": "audit:circles", "from": 0, "to": 0, "context": {"circle": 3}}))).unwrap();
    assert!(r.seal_pending());
    r.seal().unwrap();
    assert!(!r.seal_pending(), "the seal by hand settled the due one");
    r.submit_operations_id("plain", "kernel", &[], Some(ck("k3"))).unwrap();
    drop(r);
    let kinds = command_kinds(&path.0);
    assert_eq!(kinds[kinds.len() - 4..], ["batch", "batch", "seal", "batch"], "no second seal after the one by hand");
    AuditState::verify(&path.0, &mut |_, _, _, _| {}).unwrap();
}

#[test]
fn fallen_by_names_the_direct_grounds_that_no_longer_stand() {
    // Codex review of 43447f4, S2-03: observe -> claim -> done, the observe withdrawn. The claim names the observe and the done
    // names the claim; the first cause is the end of the chain (SPEC_V02_STEP2 section 6)
    let path = TempPath::new();
    let docs = [("policy".to_string(), b"Prior witness.\n".to_vec())];
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "v3-fallen", sha256(b"m"), &v3_spec()).unwrap();
    let done = json!({"kind": "done", "local_id": "d1", "rq_id": "RQ1", "directive_id": "task", "answer_ids": ["c1"], "outcome": "answered"});
    let r = s.submit_records_id("seed", "worker", "task", &scope(), &[observation("o1", "Prior witness."), claim("c1", "Witnessed.", &["o1"]), done]);
    assert!(r.error.is_none(), "{:?}", r.error);
    let (o, c, d) = (r.accepted[0], r.accepted[1], r.accepted[2]);
    let (before, _) = s.core.projection_rows();
    assert!(before.iter().all(|row| row[4] == json!([])), "nothing has fallen yet");
    s.revoke_observation("owner", &o).unwrap();
    let (rows, _) = s.core.projection_rows();
    let fallen = |id: &RecordId| rows.iter().find(|row| row[0] == json!(to_hex(&id.0))).expect("a row per record")[4].clone();
    assert_eq!((fallen(&o), fallen(&c), fallen(&d)), (json!([]), json!([to_hex(&o.0)]), json!([to_hex(&c.0)])));
}

#[test]
fn the_store_gives_the_gap_pass_the_bytes_of_standing_quotes_and_of_withdrawn_text() {
    // SPEC_V02_GAP_PASS section 3: a unit is no gap when a standing quote or withdrawn text overlaps it
    let path = TempPath::new();
    let mut s = v3_run(&path.0); // "Prior witness." was quoted and its quote withdrawn; "New witness." stands
    let text = "Prior witness.\nNew witness.\n";
    let at = |q: &str| {
        let i = text.find(q).unwrap();
        (i, i + q.len())
    };
    // a withdrawn quote closes its text too
    assert_eq!(AuditStore::quoted_spans(&s, "policy"), vec![at("New witness.")]);
    assert_eq!(AuditStore::closed_spans(&s, "policy"), vec![at("Prior witness.")]);
    s.withdraw_text("owner", "policy", "New witness.").unwrap();
    assert!(AuditStore::quoted_spans(&s, "policy").is_empty(), "the withdrawal took the quote with it");
    let mut closed = AuditStore::closed_spans(&s, "policy");
    closed.sort_unstable();
    assert_eq!(closed, vec![at("Prior witness."), at("New witness.")]);
}

#[test]
fn the_report_withholds_the_bytes_of_a_gone_quote_inside_a_wider_quote_that_stands() {
    // Codex review of 2c6864f, S3-03: under the rule of the first journals a wider quote stands over a narrower one that went;
    // the report gave the wider quote's whole text, the gone quote's bytes with it
    let path = TempPath::new();
    let base = AuditOntology::base();
    let mut s = AuditState::new(&base, &[("policy".into(), b"Prior witness.\nNew witness.\n".to_vec())]).unwrap();
    s.core.data.run_id = "first-format".into();
    s.core.data.withdrawal_closes_bytes = false;
    s.attach_new_journal(&path.0, &base).unwrap();
    let lines = [observation("o1", "Prior witness."), observation("o2", "Prior witness.\nNew"), claim("c1", "Witnessed.", &["o1", "o2"])];
    let r = s.submit_records_id("seed", "worker", "seed", &scope(), &lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    let (o1, o2, c1) = (r.accepted[0], r.accepted[1], r.accepted[2]);
    s.revoke_observation("owner", &o1).unwrap();
    assert!(s.is_grounded(&o2) && !s.is_grounded(&c1), "the wider quote stands by the exact-span rule, the claim fell");
    let entries = s.entries().unwrap();
    let report = crate::audit::read::fallen(&s, entries, None, None);
    let row = &report["rows"][0];
    assert_eq!((row["id"].clone(), row["gone"][0]["cause"].clone(), row["gone"][0]["named"].clone()), (json!(to_hex(&c1.0)), json!("revoked"), json!(true)));
    let standing = &row["standing"][0];
    assert_eq!(
        (standing["id"].clone(), standing["quote"].clone(), standing["withheld"].clone()),
        (json!(to_hex(&o2.0)), json!("[withheld]\nNew"), json!([[0, 14]]))
    );
    assert!(!report.to_string().contains("Prior witness"), "{report}");
    drop(s);
    let (s, _, entries, _) = crate::audit::read::journal_points(&path.0, &[]).unwrap();
    assert_eq!(crate::audit::read::fallen(&s, entries, None, None), report, "the journal reads alike");
}

#[test]
fn the_seal_and_projection_hashes_give_the_vectors_written_from_the_spec_text() {
    // computed by another session from the text of SPEC_V02_STEP2 alone, for the independent verifier `yuce-verify`
    // (SBGK/VECTORS_INDEPENDENT_VERIFIER_20261110.json, V7 and V8)
    let (status, dependencies) = projection_hashes_of(&[], &[]);
    assert_eq!(to_hex(&status), "88f19ee44d285b626e63507ebd361e8ce71ccc967e93d303dad85d908ac5a875");
    assert_eq!(to_hex(&dependencies), "65ec2af34b368787092fa5d7b6e498b243c7b7eaedf11eb45f3033fd5ba49133");
    let state_root = "6102326a854af6dbcd524b7d0f8b0834ee9f3e79c0dded78925323c092a34741";
    let seal = json!({"format": "r2r-seal/2", "run_id": "vector-run", "log_size": 3,
                      "log_root": "3e68089e94499e6df51727b8b615320676ff1e203d8b77551e28502e685da147",
                      "wal_head": "c9609d57fb2cffdcebc4c3834042f827576269e1556438ab854c8acf694cfed9",
                      "audit_root": state_root, "engine_root": "11".repeat(32),
                      "projections": {"status": to_hex(&status), "dependencies": to_hex(&dependencies)}});
    assert_eq!(to_hex(&seal_hash(&seal)), "30f2caab8a2e00b324a3c42993822f7318be44dfd2068b8557427e44b68c6f72");
    let session = session_root_v2(&[0x11; 32], &from_hex(state_root).unwrap());
    assert_eq!(to_hex(&session), "92bd027e0f65b39feac22b7ce1ddf60aafaa5955b7700056afa614811e917d79");
    assert_eq!(to_hex(&settings_hash(&json!({}))), "6b3606913caec5aaa55cef68c181172fc5a8ce84ba9a3574311b1c6f5a03a73e");
}

#[test]
fn a_real_record_leaf_and_its_frame_records_root() {
    // the vector V2 of the independent verifier with a real record: an observation and a claim on it, as one frame accepts them
    let path = TempPath::new();
    let docs = [("policy".to_string(), b"Prior witness.\n".to_vec())];
    let mut s = AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "vector-record", sha256(b"m"), &v3_spec()).unwrap();
    let r = s.submit_records_id("seed", "worker", "task", &scope(), &[observation("o1", "Prior witness."), claim("c1", "Witnessed.", &["o1"])]);
    assert!(r.error.is_none(), "{:?}", r.error);
    let values: Vec<Value> = s.core.data.records.iter().map(|r| state_root::record_leaf_value(&s.core.data, r)).collect();
    let leaves: Vec<Hash> = values.iter().map(super::super::trees::record_leaf).collect();
    drop(s); // the writer's lock keeps other readers out on Windows
    let frames = frames_of(&path.0);
    let last = frames.last().unwrap();
    assert_eq!(last["header"]["records_root"], json!(to_hex(&super::super::trees::records_root(&leaves))), "the frame names the root of its two records");
    // pinned in VECTORS_INDEPENDENT_VERIFIER_20261110.json as V2_real (the leaf values' JCS are there too)
    assert_eq!(
        leaves.iter().map(|l| to_hex(l)).collect::<Vec<_>>(),
        ["b635f5edec501dc2abee35d22ffd97d64978faec23dc11fc54fb0ebc0621fb50", "2a2317d6c6cfca54d42dfb6da4c3d5ca04b6cc1fca50bc31841aef9dfef3cfc2"]
    );
    assert_eq!(last["header"]["records_root"], "6f99214ff9e8891fd0945b8394b24ee522d1eb9c45f3e5c5aaf4e0276020edcf");
    if std::env::var("PRINT_VECTORS").is_ok() {
        for v in &values {
            println!("leaf_value_jcs {}", to_jcs(v));
        }
    }
}

/// Frames of a `/3` journal with their hashes made whole again after a change: each request hash, body hash, header hash and the
/// next `previous`, as a forger would, so only the rule under test can refuse the copy.
fn rechained_v3(mut frames: Vec<Value>) -> String {
    let mut previous = to_hex(&ZERO_HASH);
    for f in frames.iter_mut() {
        if let (Some(actor), true) = (f["body"]["actor"].as_str().map(str::to_string), f["body"].get("request_hash").is_some()) {
            f["body"]["request_hash"] = json!(to_hex(&request_hash(&actor, &f["body"]["command"])));
        }
        f["header"]["body_hash"] = json!(to_hex(&super::persistence::body_hash(&f["body"])));
        f["header"]["previous"] = json!(previous);
        let hash = sha256_parts(&[b"R2R-FRAME-HDR/2\0", to_jcs(&f["header"]).as_bytes()]);
        f["hash"] = json!(to_hex(&hash));
        previous = to_hex(&hash);
    }
    frames.iter().map(|f| format!("{}\n", to_jcs(f))).collect()
}

fn refusal(text: &str) -> String {
    let copy = TempPath::new();
    std::fs::write(&copy.0, text).unwrap();
    AuditState::verify(&copy.0, &mut |_, _, _, _| {}).err().map(|e| e.message).unwrap_or_default()
}

#[test]
fn a_0_2_journal_spells_a_hash_one_way_and_holds_only_safe_integers() {
    // rules of SPEC_V02_STEP2 section 1 for the independent verifier (GAP-01, GAP-12): another reader parses the journal alike
    let path = TempPath::new();
    let mut s =
        AuditState::create_with(&path.0, &AuditOntology::base(), &[("policy".to_string(), b"Prior witness.\n".to_vec())], "rules", sha256(b"m"), &v3_spec())
            .unwrap();
    let r = s.submit_records_id("seed", "worker", "task", &scope(), &[observation("o1", "Prior witness.")]);
    assert!(r.error.is_none(), "{:?}", r.error);
    // a command with a number that is not a safe integer is refused and not written
    let entries = s.entries().unwrap();
    let float = s.submit_operations_id("float", "kernel", &[], Some(json!({"key": "k", "from": 0, "to": 0, "context": {"share": 0.5}})));
    assert!(float.unwrap_err().message.contains("integer"));
    let big = s.submit_operations_id("big", "kernel", &[], Some(json!({"key": "k", "from": 0, "to": 0, "context": {"n": 1u64 << 53}})));
    assert!(big.unwrap_err().message.contains("integer"));
    assert_eq!(s.entries().unwrap(), entries, "nothing was written");
    drop(s);
    let frames = frames_of(&path.0);
    assert_eq!(refusal(&rechained_v3(frames.clone())), "", "the copy made whole again verifies");
    // the frame hash in capitals: same meaning, another file
    let mut upper = frames.clone();
    let last = upper.len() - 1;
    upper[last]["hash"] = json!(upper[last]["hash"].as_str().unwrap().to_uppercase());
    let text: String = upper.iter().map(|f| format!("{}\n", to_jcs(f))).collect();
    assert!(refusal(&text).contains("hash mismatch"), "{}", refusal(&text));
    // a root the kernel wrote, in capitals, with every hash made whole again
    let mut root = frames.clone();
    root[last]["body"]["audit_root"] = json!(root[last]["body"]["audit_root"].as_str().unwrap().to_uppercase());
    assert!(refusal(&rechained_v3(root)).contains("lowercase"));
    // a float in a body, every hash made whole again
    let mut float = frames.clone();
    float[last]["body"]["command"]["share"] = json!(0.5);
    assert!(refusal(&rechained_v3(float)).contains("integer"));
}

#[test]
fn a_seal_names_the_roots_of_the_frame_before_it_and_a_close_follows_the_last_seal() {
    // SPEC_V02_STEP2 section 7 for the independent verifier (GAP-10): P.audit_root and P.engine_root are the roots in the body of
    // frame n-1; the seal frame's own body names the state with the seal's receipt; a closed run ends with seal, close
    let path = TempPath::new();
    let mut s = AuditState::create_with(
        &path.0,
        &AuditOntology::base(),
        &[("policy".to_string(), b"Prior witness.\nNew witness.\n".to_vec())],
        "seals",
        sha256(b"m"),
        &v3_spec(),
    )
    .unwrap();
    s.submit_records_id("a", "worker", "a", &scope(), &[observation("o1", "Prior witness.")]);
    s.seal().unwrap();
    s.submit_records_id("b", "worker", "b", &scope(), &[observation("o1", "New witness.")]);
    s.close_run().unwrap();
    drop(s);
    let frames = frames_of(&path.0);
    let seals: Vec<usize> = (0..frames.len()).filter(|i| frames[*i]["body"]["command"]["kind"] == "seal").collect();
    assert_eq!(seals.len(), 2);
    for n in seals {
        let (body, before) = (&frames[n]["body"], &frames[n - 1]["body"]);
        let p = &body["command"]["seal"];
        assert_eq!((&p["audit_root"], &p["engine_root"]), (&before["audit_root"], &before["engine_root"]), "frame {n}");
        assert_ne!(body["audit_root"], p["audit_root"], "the seal frame's own state has the seal's receipt");
        assert_eq!((p["log_size"].as_u64(), &p["wal_head"]), (Some(n as u64), &frames[n - 1]["hash"]));
        assert_eq!((body["actor"].as_str(), body["submission_id"].as_str()), (Some("kernel"), Some(format!("seal-{n}").as_str())));
        assert_eq!(body["outcome"], json!({"kind": "value", "result": {"seal": p, "seal_hash": to_hex(&seal_hash(p))}}));
    }
    let close = frames.last().unwrap();
    assert_eq!((close["body"]["command"].clone(), close["body"]["submission_id"].as_str()), (json!({"kind": "close"}), Some("audit-close")));
    assert_eq!(frames[frames.len() - 2]["body"]["command"]["kind"], "seal", "one close frame after the last seal");
}

#[test]
fn a_seal_and_a_close_are_the_kernels_and_nothing_follows_the_close() {
    // GAP-14 and GAP-15 of the independent verifier: no other actor writes a seal or a close, and the close is the last frame,
    // when the kernel writes and when it replays
    let path = TempPath::new();
    let mut s = AuditState::create_with(
        &path.0,
        &AuditOntology::base(),
        &[("policy".to_string(), b"Prior witness.\nNew witness.\n".to_vec())],
        "closing",
        sha256(b"m"),
        &v3_spec(),
    )
    .unwrap();
    s.submit_records_id("a", "worker", "a", &scope(), &[observation("o1", "Prior witness.")]);
    let entries = s.entries().unwrap();
    for kind in ["seal", "close"] {
        let refused = s.commit("owner", &format!("my-{kind}"), &json!({"kind": kind})).unwrap_err();
        assert!(refused.message.contains("the kernel's"), "{kind}: {}", refused.message);
    }
    assert_eq!(s.entries().unwrap(), entries, "nothing was written");
    s.close_run().unwrap();
    let closed = s.entries().unwrap();
    let late = s.submit_records_id("b", "worker", "b", &scope(), &[observation("o1", "New witness.")]);
    assert!(late.error.is_some() && late.accepted.is_empty(), "nothing is accepted after the close");
    assert!(s.seal().is_err() && s.withdraw_text("owner", "policy", "New witness.").is_err());
    assert_eq!(s.close_run().unwrap()["already"], true);
    assert_eq!(s.entries().unwrap(), closed, "the close is the last frame");
    drop(s);
    let frames = frames_of(&path.0);
    assert_eq!(refusal(&rechained_v3(frames.clone())), "", "the journal as written verifies");
    // a frame after the close, every hash made whole
    let mut after = frames.clone();
    let mut extra = frames[1].clone();
    extra["body"]["submission_id"] = json!("late");
    extra["header"]["seq"] = json!(frames.len());
    after.push(extra);
    assert!(refusal(&rechained_v3(after)).contains("after the close"));
    // a seal frame of another actor, every hash made whole
    let mut foreign = frames.clone();
    let seal = foreign.iter().position(|f| f["body"]["command"]["kind"] == "seal").unwrap();
    foreign[seal]["body"]["actor"] = json!("owner");
    assert!(refusal(&rechained_v3(foreign)).contains("the kernel's"));
}

#[test]
fn a_frame_of_a_0_2_journal_nests_at_most_64_levels() {
    // architect, 11.11.2026: a rule of the format, so any reader with 64 levels of room reads every journal
    let path = TempPath::new();
    let mut s =
        AuditState::create_with(&path.0, &AuditOntology::base(), &[("policy".to_string(), b"Prior witness.\n".to_vec())], "depth", sha256(b"m"), &v3_spec())
            .unwrap();
    s.submit_records_id("a", "worker", "a", &scope(), &[observation("o1", "Prior witness.")]);
    let entries = s.entries().unwrap();
    let nested = |depth: usize| (0..depth).fold(json!(1), |inner, _| json!({"n": inner}));
    // the checkpoint frame is the frame, the body, the command and the checkpoint over the nesting: four levels
    let deep = s.submit_operations_id("deep", "kernel", &[], Some(json!({"key": "k", "from": 0, "to": 0, "context": nested(62)})));
    assert!(deep.unwrap_err().message.contains("64 levels"));
    assert_eq!(s.entries().unwrap(), entries, "nothing was written");
    s.submit_operations_id("fits", "kernel", &[], Some(json!({"key": "k", "from": 0, "to": 0, "context": nested(50)}))).unwrap();
    drop(s);
    let frames = frames_of(&path.0);
    assert!(frames.iter().all(|f| super::persistence::json_depth(f) <= 64));
    let mut forged = frames.clone();
    let last = forged.len() - 1;
    forged[last]["body"]["command"]["checkpoint"]["context"] = nested(70);
    assert!(refusal(&rechained_v3(forged)).contains("64 levels"));
}

/// Codex review of 904f1cdb, S4-06: the genesis frame passes no command check, and the limits of a `/3` frame held only on reading
/// it back. A run is not created with a genesis its own check would refuse, and no journal is left behind.
#[test]
fn a_0_2_genesis_holds_the_limits_of_a_frame_before_anything_is_written() {
    let docs = [("policy".to_string(), b"Prior witness.\n".to_vec())];
    let deep = (0..80).fold(json!(0), |inner, _| json!([inner]));
    for (meta, why) in
        [(json!({"deep": deep}), "64 levels"), (json!({"x": 0.5}), "integers"), (json!({"x": -1}), "integers"), (json!({"x": 1u64 << 53}), "integers")]
    {
        let path = TempPath::new();
        let spec = GenesisSpec { operator_meta: Some(meta.clone()), ..v3_spec() };
        let refused = AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "genesis-limits", sha256(b"m"), &spec)
            .err()
            .unwrap_or_else(|| panic!("{meta} was accepted"));
        assert!(refused.message.contains(why), "{meta}: {}", refused.message);
        assert!(!path.0.exists(), "{meta}: no journal is left");
    }
    // within the limits the run is created, and its journal checks
    let path = TempPath::new();
    let fits = (0..40).fold(json!(0), |inner, _| json!([inner]));
    let spec = GenesisSpec { operator_meta: Some(json!({"fits": fits, "n": (1u64 << 53) - 1})), ..v3_spec() };
    drop(AuditState::create_with(&path.0, &AuditOntology::base(), &docs, "genesis-limits", sha256(b"m"), &spec).unwrap());
    AuditState::verify(&path.0, &mut |_, _, _, _| {}).unwrap();
}
