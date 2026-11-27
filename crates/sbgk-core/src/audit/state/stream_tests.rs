//! Tests of rules 4 (0.3.0): a journal that starts without a document and takes its sources as they come, claims that rest on
//! claims, context checkpoints, a planned change of version beside a withdrawal, and the reads by exact key.

use super::*;
use crate::audit::state::{ClaimChains, RecordState, CONTEXT_CHECKPOINT_PREFIX, MAX_DOC_NAME_BYTES, RULES_VERSION, RULES_VERSION_3};
use crate::audit::{read, vsc};

/// A submission id no other call of a test took.
fn fresh_id(what: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("{what}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A journal of rules 4 that starts without a document.
fn stream(path: &Path) -> AuditState {
    AuditState::create_from_docs(path, &AuditOntology::base(), "stream", Vec::new()).unwrap()
}

/// The same start under rules 3: what 0.2 wrote.
fn stream_under_rules_3(path: &Path) -> AuditState {
    let mut s = AuditState::prepare_from_docs(&AuditOntology::base(), "stream", Vec::new()).unwrap();
    s.set_rules_version(RULES_VERSION_3).unwrap();
    s.start_journal(path, &GenesisSpec::default()).unwrap();
    s
}

fn all_docs(s: &AuditState) -> Scope {
    Scope { docs: s.docs(), topic: None, ranges: Vec::new() }
}

fn quote(local_id: &str, doc: &str, text: &str) -> Value {
    json!({"kind":"observe","local_id":local_id,"doc_id":doc,"exact_quote":text,"terms":[]})
}

/// A claim whose subject is the key and whose object is the value.
fn fact(local_id: &str, key: &str, value: &str, based_on: &[&str]) -> Value {
    json!({"kind":"claim","local_id":local_id,"text":format!("{key} is {value}."),"subject":key,"object":value,"stance":"reported","based_on":based_on})
}

fn supersedes(local_id: &str, new: &str, old: &str, based_on: &[&str]) -> Value {
    json!({"kind":"relation","local_id":local_id,"from":new,"rel":"supersedes","to":old,"based_on":based_on})
}

fn submit(s: &mut AuditState, task: &str, lines: &[Value]) -> Vec<RecordId> {
    let scope = all_docs(s);
    let report = s.submit_records_id(&fresh_id("submit"), "agent", task, &scope, lines);
    assert!(report.error.is_none(), "{task}: {:?}", report.error.map(|e| e.to_json()));
    report.accepted
}

fn refused(s: &mut AuditState, task: &str, lines: &[Value]) -> KernelError {
    let scope = all_docs(s);
    s.submit_records_id(&fresh_id("refused"), "agent", task, &scope, lines).error.expect("a refusal")
}

fn at(id: &RecordId) -> String {
    format!("@{}", to_hex(&id.0))
}

fn state_of(s: &AuditState, id: &RecordId) -> &'static str {
    s.record_state(id).unwrap().name()
}

fn genesis_of(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str::<Value>(text.lines().next().unwrap()).unwrap()["body"].clone()
}

// ---- the rules a journal names ----

#[test]
fn a_new_journal_names_rules_4_and_a_journal_of_rules_3_is_written_and_replayed_under_them() {
    let (new, old) = (TempPath::new(), TempPath::new());
    let mut s = stream(&new.0);
    assert_eq!((s.rules_version(), genesis_of(&new.0)["rules_version"].as_str()), (RULES_VERSION, Some(RULES_VERSION)));
    assert!(s.set_rules_version(RULES_VERSION_3).is_err(), "the rules are chosen before the journal is started");
    let mut prepared = AuditState::prepare_from_docs(&AuditOntology::base(), "stream", Vec::new()).unwrap();
    assert!(prepared.set_rules_version("r2r-audit-rules/5").is_err());

    let mut t = stream_under_rules_3(&old.0);
    assert_eq!((t.rules_version(), genesis_of(&old.0)["rules_version"].as_str()), (RULES_VERSION_3, Some(RULES_VERSION_3)));
    for state in [&mut s, &mut t] {
        state.put_document("owner", "s1", b"A = 10.\nB = 5.\n").unwrap();
        submit(state, "t1", &[quote("o", "s1", "A = 10."), fact("a", "A", "10", &["o"])]);
    }
    // a claim on a claim, a question that names a record, a reason of a withdrawal: rules 4 take them, rules 3 refuse each as 0.2 did
    let on_claim = fact("a2", "A2", "20", &["a"]);
    let about = json!({"kind":"question","local_id":"q","text":"Is A final?","about":["A"],"needed":"a later source","about_record":"a"});
    let error = refused(&mut t, "t1", std::slice::from_ref(&on_claim));
    assert_eq!((error.code, error.message.as_str()), (Code::NotAnEvidence, "basis must name observe records"));
    assert_eq!(refused(&mut t, "t1", std::slice::from_ref(&about)).field.as_deref(), Some("about_record"));
    let o = t.records_since(0)[0].id;
    assert_eq!(t.revoke_observation_for("owner", &o, "s1").unwrap_err().field.as_deref(), Some("reason_source_id"));
    assert!(t.context_checkpoint("agent", &[], &[], None, None).is_err());
    // a key of the context checkpoints is any key under rules 3, as before
    let free = json!({"key": format!("{CONTEXT_CHECKPOINT_PREFIX}7"), "from": 0, "to": 0, "context": {"anything": true}});
    assert!(t.submit_operations_id("free", "agent", &[], Some(free)).unwrap()["error"].is_null());
    assert_eq!(read::status(&t, 0).get("claim_chains"), None, "the status of a journal of rules 3 reads as it did");

    let accepted = submit(&mut s, "t1", &[on_claim, about]);
    assert_eq!(s.record(&accepted[1]).unwrap().body["about_record"], json!(at(&s.records_since(0)[1].id)));
    assert!(s.record(&accepted[1]).unwrap().based_on.is_empty(), "the record a question is about is an address, not a ground");
    let (held_new, held_old) = (told(&s), told(&t));
    drop((s, t));
    let (s, t) = (AuditState::open(&new.0).unwrap(), AuditState::open(&old.0).unwrap());
    assert_eq!((told(&s), s.rules_version()), (held_new, RULES_VERSION));
    assert_eq!((told(&t), t.rules_version()), (held_old, RULES_VERSION_3));
}

#[test]
fn a_claim_rests_on_observations_and_claims_and_on_no_other_record() {
    let path = TempPath::new();
    let mut s = stream(&path.0);
    s.put_document("owner", "s1", b"A = 10.\nB = 5.\nC = 7.\n").unwrap();
    let ids = submit(
        &mut s,
        "t1",
        &[
            quote("oa", "s1", "A = 10."),
            quote("ob", "s1", "B = 5."),
            fact("a", "A", "10", &["oa"]),
            fact("b", "B", "5", &["ob"]),
            json!({"kind":"relation","local_id":"r","from":"a","rel":"supports","to":"b","based_on":["oa"]}),
            json!({"kind":"hypothesis","local_id":"h","text":"A may grow.","falsifier":"A stays.","based_on":["oa"]}),
            json!({"kind":"question","local_id":"q","text":"What is D?","about":["D"],"needed":"a source"}),
        ],
    );
    for (name, ground) in [("a relation", "r"), ("a hypothesis", "h"), ("a question", "q")] {
        let error = refused(&mut s, "t1", &[fact("x", "X", "1", &[ground])]);
        assert_eq!((error.code, error.message.as_str()), (Code::NotAnEvidence, "basis must name observe or claim records"), "{name}");
    }
    // the grounds of a relation and of a hypothesis stay observations
    let error = refused(&mut s, "t1", &[json!({"kind":"relation","local_id":"r2","from":"b","rel":"supports","to":"a","based_on":["a"]})]);
    assert_eq!(error.message, "basis must name observe records");
    let error = refused(&mut s, "t1", &[json!({"kind":"hypothesis","local_id":"h2","text":"B may fall.","falsifier":"B stays.","based_on":["b"]})]);
    assert_eq!(error.message, "basis must name observe records");
    // a chain: the sum rests on both claims, a claim on the sum, and the rule is AND
    let chain = submit(&mut s, "t2", &[fact("sum", "A+B", "15", &[&at(&ids[2]), &at(&ids[3])]), fact("twice", "2(A+B)", "30", &["sum"])]);
    assert!(chain.iter().all(|id| s.is_grounded(id)));
    assert_eq!(s.claim_chains(), ClaimChains { max_depth: 2, standing_claims: 4, standing_without_own_quote: 2 });
    assert_eq!(vsc::claim_chains(&s)["without_own_quote_per_10000"], 5000);
    // one ground of the sum goes: the sum and what rests on it fall, the other claim stands
    s.revoke_observation("owner", &ids[1]).unwrap();
    assert_eq!([&ids[2], &ids[3], &chain[0], &chain[1]].map(|id| s.is_grounded(id)), [true, false, false, false]);
    assert_eq!(state_of(&s, &ids[1]), "WITHDRAWN");
    assert_eq!([&ids[3], &chain[0], &chain[1]].map(|id| state_of(&s, id)), ["AFFECTED_BY_EVIDENCE_CHANGE"; 3]);
    // and a claim cannot be put on a claim that fell
    assert_eq!(refused(&mut s, "t3", &[fact("late", "L", "1", &[&at(&chain[0])])]).code, Code::EvidenceNotActive);
    assert_eq!(s.claim_chains(), ClaimChains { max_depth: 2, standing_claims: 1, standing_without_own_quote: 0 });
    let held = told(&s);
    drop(s);
    assert_eq!(told(&AuditState::open(&path.0).unwrap()), held);
}

// ---- STREAM ----

/// A hundred sources come into an open journal that started without one; conclusions of several steps are drawn over them; the
/// withdrawal of a source in the middle, for a reason that is itself a source, makes every record that rested on it fall and no
/// other; the journal reopens at the same roots.
#[test]
fn a_hundred_sources_come_into_an_open_journal_and_a_withdrawal_in_the_middle_takes_what_rested_on_it() {
    let path = TempPath::new();
    let mut s = stream(&path.0);
    assert_eq!((s.source_mode(), s.source_document_count(), genesis_of(&path.0)["source_documents"].clone()), ("opaque", 0, json!({})));
    let mut values: Vec<RecordId> = Vec::new();
    let mut totals: Vec<RecordId> = Vec::new();
    for n in 0..100usize {
        let doc = format!("source-{n:03}");
        s.put_document("feed", &doc, format!("Reading {n} is {}.\nNote {n}: taken at the gate.\n", n * 3).as_bytes()).unwrap();
        let mut lines = vec![quote("o", &doc, &format!("Reading {n} is {}.", n * 3)), fact("v", &format!("reading/{n}"), &(n * 3).to_string(), &["o"])];
        // a running total: a claim on the claim before it and on the new value
        let before = totals.last().map(at);
        let grounds: Vec<&str> = before.as_deref().into_iter().chain(["v"]).collect();
        lines.push(fact("t", &format!("total/{n}"), &((0..=n).map(|k| k * 3).sum::<usize>()).to_string(), &grounds));
        let ids = submit(&mut s, &format!("t{n}"), &lines);
        values.push(ids[1]);
        totals.push(ids[2]);
    }
    assert_eq!((s.source_document_count(), s.head()), (100, 300));
    assert!(totals.iter().all(|id| s.is_grounded(id)));
    // the first total rests on a claim, and each total after it on the total before
    assert_eq!(s.claim_chains().max_depth, 100);
    assert_eq!(vsc::key(&s, "total/99")["value"], "14850");

    // source 40 is withdrawn for a reason: the notice is the 101st source
    s.put_document("feed", "notice-1", b"Notice: reading 40 was taken with a faulty gauge and is withdrawn.\n").unwrap();
    let also = s.withdraw_text_for("owner", "source-040", "Reading 40 is 120.", "notice-1").unwrap();
    assert_eq!(also, 1);
    assert_eq!(s.withdraw_text_for("owner", "source-041", "Reading 41 is 123.", "no-such-notice").unwrap_err().field.as_deref(), Some("reason_source_id"));
    for (n, (value, total)) in values.iter().zip(&totals).enumerate() {
        // the values of the other sources stand; every total from the withdrawn one on fell
        assert_eq!((s.is_grounded(value), s.is_grounded(total)), (n != 40, n < 40), "source {n}");
    }
    assert_eq!(vsc::key(&s, "total/39")["state"], "ACTIVE");
    assert_eq!(vsc::key(&s, "total/99")["state"], "NO_ACTIVE_VALUE");
    assert_eq!(vsc::key(&s, "reading/40")["history"]["affected_by_evidence_change"], 1);
    let observation = s.records_since(0)[40 * 3].id;
    let fate = s.quote_fate(&observation).unwrap();
    assert_eq!((fate["cause"].as_str(), fate["reason_source_id"].as_str()), (Some("withdrawn"), Some("notice-1")));
    // a new quote of the withdrawn text is refused, and the rest of the source can still be quoted
    assert_eq!(refused(&mut s, "again", &[quote("o", "source-040", "Reading 40 is 120.")]).code, Code::EvidenceRevoked);
    submit(&mut s, "note", &[quote("o", "source-040", "Note 40: taken at the gate.")]);

    let held = (told(&s), vsc::keys(&s, &[], Some(5000)), s.claim_chains());
    drop(s);
    let (reopened, read) = AuditState::verify(&path.0, &mut |_, _, _, _| {}).unwrap();
    assert_eq!((told(&reopened).0, told(&reopened).1), (held.0 .0, held.0 .1));
    assert_eq!(read.document_puts, 101);
    let reopened = AuditState::open(&path.0).unwrap();
    assert_eq!((told(&reopened), vsc::keys(&reopened, &[], Some(5000)), reopened.claim_chains()), held);
}

// ---- VSC: three epochs ----

/// Three compactions of a context in a row. (a) A value kept before a compaction is read back exactly. (b) A changed value
/// without a planned change is a conflict to read, not a record to refuse. (c) A key the next checkpoint left out while it is
/// still current is reported. (d) A planned change of version makes the old claim superseded and takes nothing that rested on it.
/// (e) A withdrawal of a source of the first epoch takes what rested on it, in every checkpoint that listed it. (f) What did not
/// rest on it is untouched.
#[test]
fn three_epochs_of_context_checkpoints_keep_values_and_tell_a_planned_change_from_a_withdrawal() {
    let path = TempPath::new();
    let mut s = stream(&path.0);

    // epoch 1
    s.put_document("agent", "context-1", b"A = 10.\nB = 5.\nC = 7.\n").unwrap();
    let e1 = submit(
        &mut s,
        "e1",
        &[
            quote("oa", "context-1", "A = 10."),
            quote("ob", "context-1", "B = 5."),
            quote("oc", "context-1", "C = 7."),
            fact("a", "A", "10", &["oa"]),
            fact("b", "B", "5", &["ob"]),
            fact("c", "C", "7", &["oc"]),
            fact("ab", "A*B", "50", &["a", "b"]),
            fact("a1", "A+1", "11", &["a"]),
        ],
    );
    let (a, b, c, ab, a1) = (e1[3], e1[4], e1[5], e1[6], e1[7]);
    let first = s.context_checkpoint("agent", &[a, b, c, ab, a1], &[], Some("context-1"), Some(json!({"note": "before the first compaction"}))).unwrap();
    assert_eq!((first["checkpoint"].as_str(), first["epoch"].as_u64(), first["cursor"].as_u64()), (Some("vsc:checkpoint:1"), Some(1), Some(8)));
    // (a) the value is read back exactly, by the checkpoint and by the key
    let read = s.read_active_checkpoint(1).unwrap();
    assert_eq!(read.active.iter().map(|r| r.id).collect::<Vec<_>>(), [a, b, c, ab, a1]);
    assert!(read.dropped.is_empty());
    let key = vsc::key(&s, "A");
    assert_eq!((key["state"].as_str(), key["value"].as_str(), key["record"]["id"].as_str()), (Some("ACTIVE"), Some("10"), Some(to_hex(&a.0).as_str())));
    assert_eq!(vsc::key(&s, "a")["state"], "UNKNOWN_KEY", "a key is compared as the exact string");

    // epoch 2: A changes by plan, B changes without one, C is left out of the checkpoint
    s.put_document("agent", "context-2", b"A = 12, as planned for the second quarter.\nB = 6.\n").unwrap();
    let e2 = submit(
        &mut s,
        "e2",
        &[
            quote("oa", "context-2", "A = 12, as planned for the second quarter."),
            quote("ob", "context-2", "B = 6."),
            fact("a", "A", "12", &["oa"]),
            fact("b", "B", "6", &["ob"]),
            supersedes("s", "a", &at(&a), &["oa", &at(&e1[0])]),
        ],
    );
    let (a2, b2) = (e2[2], e2[3]);
    // (d) the old claim stands as it was said and is no longer the current one; what rested on it did not fall
    assert_eq!(s.record_state(&a), Some(RecordState::Superseded(a2)));
    assert_eq!([&a, &ab, &a1].map(|id| s.is_grounded(id)), [true; 3]);
    assert_eq!((state_of(&s, &ab), state_of(&s, &a1)), ("ACTIVE", "ACTIVE"));
    assert_eq!(vsc::key(&s, "A")["value"], "12");
    assert_eq!(vsc::key(&s, "A")["history"], json!({"claims": 2, "active": 1, "superseded": 1, "affected_by_evidence_change": 0}));
    // (b) two active claims of one key with different values and no planned change between them
    let conflict = vsc::key(&s, "B");
    assert_eq!((conflict["state"].as_str(), conflict["active"].as_array().map(Vec::len)), (Some("VALUE_CONFLICT"), Some(2)));
    let second = s.context_checkpoint("agent", &[a2, b2, ab, a1], &["context-1".to_string()], Some("context-2"), None).unwrap();
    assert_eq!(second["epoch"], 2);
    // (c) C is current and the second checkpoint does not carry it; D was required and never said
    let table = vsc::keys(&s, &["C".to_string(), "D".to_string()], None);
    assert_eq!(table["missing_required_keys"], json!([{"key": "D", "state": "MISSING_REQUIRED_KEY", "known": false}]));
    assert_eq!(table["value_conflicts"].as_array().unwrap().len(), 1);
    let now = vsc::checkpoint(&s, None);
    assert_eq!((now["epoch"].as_u64(), now["keys_not_carried"].clone()), (Some(2), json!([{"key": "C", "state": "MISSING_REQUIRED_KEY"}])));
    // the first checkpoint read now leaves the superseded claim out, and names it
    let then = vsc::checkpoint(&s, Some(1));
    assert_eq!(then["active"].as_array().unwrap().len(), 4);
    assert_eq!(then["dropped"], json!({"SUPERSEDED": [{"id": to_hex(&a.0), "short": a.short(), "key": "A", "superseded_by": to_hex(&a2.0)}]}));

    // epoch 3: the first statement of B is withdrawn for a reason
    s.put_document("agent", "context-3", b"Correction: the earlier statement of B was a typing error.\n").unwrap();
    let before_root = s.audit_root();
    assert_eq!(s.withdraw_text_for("agent", "context-1", "B = 5.", "context-3").unwrap(), 1);
    assert_ne!(s.audit_root(), before_root);
    // (e) the quote is withdrawn, the claim on it and the claim on that claim are affected, in the checkpoints that listed them
    assert_eq!((state_of(&s, &e1[1]), state_of(&s, &b), state_of(&s, &ab)), ("WITHDRAWN", "AFFECTED_BY_EVIDENCE_CHANGE", "AFFECTED_BY_EVIDENCE_CHANGE"));
    let first_now = s.read_active_checkpoint(1).unwrap();
    assert_eq!(first_now.active.iter().map(|r| r.id).collect::<Vec<_>>(), [c, a1]);
    assert_eq!(first_now.dropped, [(a, RecordState::Superseded(a2)), (b, RecordState::AffectedByEvidenceChange), (ab, RecordState::AffectedByEvidenceChange)]);
    assert_eq!(s.read_active_checkpoint(2).unwrap().active.iter().map(|r| r.id).collect::<Vec<_>>(), [a2, b2, a1]);
    // the conflict of B is gone with the withdrawn value
    assert_eq!((vsc::key(&s, "B")["state"].as_str(), vsc::key(&s, "B")["value"].as_str()), (Some("ACTIVE"), Some("6")));
    // (f) C never rested on B
    assert_eq!((state_of(&s, &c), s.is_grounded(&c), vsc::key(&s, "C")["value"].as_str()), ("ACTIVE", true, Some("7")));
    let third = s.context_checkpoint("agent", &[a2, b2, c, a1], &["context-1".to_string(), "context-2".to_string()], Some("context-3"), None).unwrap();
    assert_eq!((third["epoch"].as_u64(), s.context_epochs()), (Some(3), 3));
    assert_eq!(vsc::checkpoint(&s, None)["keys_not_carried"], json!([{"key": "A*B", "state": "NO_ACTIVE_VALUE"}]));
    // the checkpoint of the first epoch says that its source has the bytes it named
    assert_eq!(vsc::checkpoint(&s, Some(1))["sources"]["context-1"]["current"], true);

    // the replacement falls: it replaces nothing, and the old value is the current one again
    assert_eq!(s.withdraw_text_for("agent", "context-2", "A = 12, as planned for the second quarter.", "context-3").unwrap(), 1);
    assert_eq!((state_of(&s, &a), state_of(&s, &a2)), ("ACTIVE", "AFFECTED_BY_EVIDENCE_CHANGE"));
    assert_eq!(vsc::key(&s, "A")["value"], "10");

    let held = (told(&s), vsc::keys(&s, &[], None), vsc::checkpoint(&s, Some(1)), vsc::checkpoint(&s, Some(3)), read::status(&s, 0));
    assert_eq!(held.4["context_checkpoints"], 3);
    drop(s);
    let r = AuditState::open(&path.0).unwrap();
    assert_eq!((told(&r), vsc::keys(&r, &[], None), vsc::checkpoint(&r, Some(1)), vsc::checkpoint(&r, Some(3)), read::status(&r, 0)), held);
    assert_eq!(vsc::checkpoint(&r, Some(4))["status"], "NO_CONTEXT_CHECKPOINT");
}

#[test]
fn a_context_checkpoint_is_refused_unless_it_follows_the_last_one_and_lists_what_exists() {
    let path = TempPath::new();
    let mut s = stream(&path.0);
    s.put_document("agent", "s1", b"A = 10.\nB = 5.\n").unwrap();
    let ids = submit(
        &mut s,
        "t1",
        &[
            quote("oa", "s1", "A = 10."),
            fact("a", "A", "10", &["oa"]),
            json!({"kind":"question","local_id":"q","text":"What is D?","about":["D"],"needed":"a source"}),
        ],
    );
    let sha = s.source_document("s1").unwrap()["raw_sha256"].clone();
    let manifest = |epoch: u64, records: Value, sources: Value, raw: Value| {
        json!({"kind":"checkpoint","key":format!("{CONTEXT_CHECKPOINT_PREFIX}{epoch}"),"from":0,"to":3,
               "context":{"format":"r2r-context-checkpoint/1","epoch":epoch,"records":records,"sources":sources,"raw_context":raw,"manifest":null}})
    };
    let good = manifest(1, json!([to_hex(&ids[1].0)]), json!({"s1": sha}), json!("s1"));
    let mut wrong: Vec<(&str, Value)> = vec![
        ("the second epoch first", manifest(2, json!([]), json!({}), Value::Null)),
        ("a record that does not exist", manifest(1, json!(["00".repeat(32)]), json!({}), Value::Null)),
        ("a short id", manifest(1, json!([ids[1].short()]), json!({}), Value::Null)),
        ("an id in capitals", manifest(1, json!([to_hex(&ids[1].0).to_uppercase()]), json!({}), Value::Null)),
        ("a record twice", manifest(1, json!([to_hex(&ids[1].0), to_hex(&ids[1].0)]), json!({}), Value::Null)),
        ("a question", manifest(1, json!([to_hex(&ids[2].0)]), json!({}), Value::Null)),
        ("a source with other bytes", manifest(1, json!([]), json!({"s1": "00".repeat(32)}), Value::Null)),
        ("an unknown source", manifest(1, json!([]), json!({"s9": sha}), Value::Null)),
        ("a raw context that is no source of it", manifest(1, json!([]), json!({}), json!("s1"))),
    ];
    let mut edited = |name: &'static str, edit: &dyn Fn(&mut Value)| {
        let mut command = good.clone();
        edit(&mut command);
        wrong.push((name, command));
    };
    edited("a cursor short of the records", &|c| c["to"] = json!(2));
    edited("an epoch other than its key", &|c| c["context"]["epoch"] = json!(2));
    edited("another format", &|c| c["context"]["format"] = json!("r2r-context-checkpoint/2"));
    edited("an unknown field", &|c| c["context"]["extra"] = json!(true));
    edited("a manifest that is no object", &|c| c["context"]["manifest"] = json!("text"));
    edited("a key with a leading zero", &|c| c["key"] = json!(format!("{CONTEXT_CHECKPOINT_PREFIX}01")));
    edited("a key without an epoch", &|c| c["key"] = json!(CONTEXT_CHECKPOINT_PREFIX));
    for (name, command) in &wrong {
        // as a command of its own and as the checkpoint of a batch
        let alone = s.commit("agent", &format!("alone {name}"), command).unwrap();
        assert!(matches!(&alone, Outcome::Error(e) if e.field.as_deref() == Some("vsc:checkpoint")), "{name}: {:?}", alone.value());
        let mut inner = command.clone();
        inner.as_object_mut().unwrap().remove("kind");
        let batch = s.submit_operations_id(&format!("batch {name}"), "agent", &[], Some(inner)).unwrap();
        assert_eq!((batch["checkpointed"].as_bool(), batch["error"]["field"].as_str()), (Some(false), Some("vsc:checkpoint")), "{name}");
    }
    assert_eq!(s.context_epochs(), 0);
    assert!(matches!(s.commit("agent", "good", &good).unwrap(), Outcome::Value(_)));
    // written once
    let again = s.commit("agent", "again", &good).unwrap();
    assert!(matches!(&again, Outcome::Error(e) if e.message.contains("written once")), "{:?}", again.value());
    assert_eq!((s.context_epochs(), s.context_checkpoint_of(1).unwrap().1), (1, 3));
    // a checkpoint does not move the flags or the records
    assert!(s.is_grounded(&ids[1]));
    // the source changes: the checkpoint says its bytes are no longer the ones it named, and the claim on them is affected
    s.put_document("agent", "s1", b"A = 11.\nB = 5.\n").unwrap();
    let read = vsc::checkpoint(&s, Some(1));
    assert_eq!((read["sources"]["s1"]["current"].as_bool(), read["active"].as_array().map(Vec::len)), (Some(false), Some(0)));
    assert_eq!(read["dropped"]["AFFECTED_BY_EVIDENCE_CHANGE"][0]["key"], "A");
    assert_eq!(state_of(&s, &ids[0]), "AFFECTED_BY_EVIDENCE_CHANGE", "an observation of other bytes is not a withdrawn one");
    // the bytes come back, and so does the claim
    s.put_document("agent", "s1", b"A = 10.\nB = 5.\n").unwrap();
    assert_eq!(vsc::checkpoint(&s, Some(1))["active"].as_array().map(Vec::len), Some(1));
    let held = told(&s);
    drop(s);
    assert_eq!(told(&AuditState::open(&path.0).unwrap()), held);
}

// ---- the flags after a put document ----

/// Random histories of a journal that takes its sources as they come: new documents, new versions of a document and its earlier
/// bytes again, quotes, claims on claims, planned changes, withdrawals by record and by text, and a put document inside a batch.
/// After every command the flags kept from the state before equal a whole pass (`support_flags` checks it too, in every test), the
/// index of the claims by key equals a walk of the records, and a replay of the journal ends at the same roots.
///
/// The same histories pin the rule the independent verifier is given for an observation (its specification, amendment 6,
/// P6-4): an observation stands exactly when its anchor is not revoked and its document is at the version the quote was bound
/// to. The kernel asks three things of it (an evidence node that is active, a binding, an equal version). After every command
/// the two rules agree on every observation; a binding never changes; and an anchor once revoked stays revoked, also when the
/// bytes of its version come back.
#[test]
fn a_put_document_keeps_the_flags_and_the_indices_a_whole_pass_computes() {
    let versions = [
        "Alpha one.\nAlpha two.\nAlpha three.\n",
        "Alpha one.\nAlpha two, as amended.\nAlpha three.\n",
        "Alpha one.\nAlpha three.\nAlpha four.\n",
        "Alpha zero.\nAlpha one.\nAlpha two.\nAlpha three.\n",
    ];
    let lines = ["Alpha one.", "Alpha two.", "Alpha three.", "Alpha four.", "Alpha two, as amended.", "Alpha zero."];
    let (mut puts, mut chained, mut withdrawn, mut replaced, mut checkpoints) = (0, 0, 0, 0, 0);
    // what the rule of P6-4 met: quotes that came back with their version, quotes off the current version whose anchor is not
    // revoked, and quotes of the current version whose anchor is
    let (mut came_back, mut off_version, mut revoked_on_version) = (0usize, 0usize, 0usize);
    for seed in 0..10u64 {
        let mut rng = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut next = move |n: u64| {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (rng >> 33) % n
        };
        let path = TempPath::new();
        let mut s = stream(&path.0);
        s.put_document("feed", "a", versions[0].as_bytes()).unwrap();
        // the verifier's side of P6-4, kept by the test: the anchors seen revoked, the binding of each observation as first
        // seen, and whether it stood after the command before
        let mut revoked: BTreeSet<Hash> = BTreeSet::new();
        let mut bindings: HashMap<RecordId, (Hash, Hash, usize, usize)> = HashMap::new();
        let mut stood: HashMap<RecordId, bool> = HashMap::new();
        for step in 0..60u64 {
            let claims: Vec<RecordId> = s.records_since(0).iter().filter(|r| r.kind == RecordKind::Claim).map(|r| r.id).collect();
            let observes: Vec<RecordId> = s.records_since(0).iter().filter(|r| r.kind == RecordKind::Observe).map(|r| r.id).collect();
            let any = |ids: &[RecordId], n: u64| ids.get((n % ids.len().max(1) as u64) as usize).copied();
            let standing = |ids: &[RecordId]| ids.iter().copied().filter(|id| s.is_grounded(id)).collect::<Vec<_>>();
            let (standing_claims, standing_observes) = (standing(&claims), standing(&observes));
            let scope = all_docs(&s);
            // mostly a line the document has now, sometimes one it has not
            let text = s.doc_text("a").unwrap();
            let present: Vec<&str> = text.lines().collect();
            let line = if next(5) == 0 { lines[next(lines.len() as u64) as usize] } else { present[next(present.len() as u64) as usize] };
            match next(12) {
                0 | 1 => {
                    puts += usize::from(s.put_document("feed", "a", versions[next(versions.len() as u64) as usize].as_bytes()).is_ok());
                }
                2 => {
                    puts += usize::from(s.put_document("feed", &format!("n{step}"), format!("Line {step} one.\nLine {step} two.\n").as_bytes()).is_ok());
                }
                3 => {
                    let put = json!({"kind":"put_document","doc_id":"a","text":versions[next(versions.len() as u64) as usize]});
                    let _ = s.submit_operations_id(&format!("b{step}"), "kernel", &[put], None).unwrap();
                }
                4 | 5 | 10 => {
                    // a quote, a claim on it, and a claim on that claim and on an earlier one
                    let earlier = if next(4) == 0 { any(&claims, next(64)) } else { any(&standing_claims, next(64)) }.map(|id| at(&id));
                    let grounds: Vec<&str> = ["c"].into_iter().chain(earlier.as_deref()).collect();
                    let records = [
                        quote("o", "a", line),
                        fact("c", &format!("k{}", next(4)), &format!("v{}", next(3)), &["o"]),
                        fact("d", &format!("k{}", next(4)), &format!("v{}", next(3)), &grounds),
                        fact("e", "deep", &step.to_string(), &["d"]),
                    ];
                    let report = s.submit_records_id(&format!("s{step}"), "agent", &format!("t{step}"), &scope, &records);
                    chained += usize::from(report.accepted.len() == 4);
                }
                6 | 11 => {
                    // a planned change between two earlier claims, resting on any quote
                    let basis = if next(4) == 0 { any(&observes, next(64)) } else { any(&standing_observes, next(64)) };
                    if let (Some(new), Some(old), Some(o)) = (any(&claims, next(64)), any(&claims, next(64)), basis) {
                        let report = s.submit_records_id(
                            &format!("r{step}"),
                            "agent",
                            &format!("t{step}"),
                            &scope,
                            &[supersedes("r", &at(&new), &at(&old), &[&at(&o)])],
                        );
                        replaced += usize::from(report.error.is_none());
                    }
                }
                7 => {
                    if let Some(o) = any(&observes, next(64)) {
                        withdrawn += usize::from(s.revoke_observation("owner", &o).is_ok());
                    }
                }
                8 => {
                    let text = if next(2) == 0 { line.to_string() } else { line.split(' ').nth(1).unwrap().to_string() };
                    withdrawn += usize::from(s.withdraw_text("owner", "a", &text).is_ok());
                }
                _ => {
                    // some of the claims active now, and at times one that is not: a checkpoint with it is refused
                    let active = |id: &RecordId| s.record_state(id) == Some(RecordState::Active);
                    let fallen = claims.iter().copied().find(|id| !active(id)).filter(|_| next(4) == 0);
                    let listed: Vec<RecordId> = claims.iter().copied().filter(|id| active(id) && next(2) == 0).chain(fallen).collect();
                    let written = s.context_checkpoint("agent", &listed, &[], None, None);
                    assert_eq!(written.is_ok(), fallen.is_none(), "seed {seed} step {step}: {written:?}");
                    checkpoints += usize::from(written.is_ok());
                }
            }
            let fresh = s.core.support_flags_fresh();
            assert_eq!(*s.core.support_flags(), fresh, "seed {seed} step {step}: kept flags");
            let standing: Vec<bool> = s.core.data.records.iter().map(|r| fresh.get(&r.id).is_some_and(|v| v.0)).collect();
            assert_eq!(*s.core.standing_flags(), standing, "seed {seed} step {step}: standing by position");
            assert_eq!(s.core.projection_hashes(), s.core.projection_hashes_of_rows(), "seed {seed} step {step}: projections");
            // the index of the claims by key is a walk of the records
            let mut by_key: HashMap<String, Vec<RecordId>> = HashMap::new();
            for r in s.core.data.records.iter().filter(|r| r.kind == RecordKind::Claim) {
                by_key.entry(r.body["subject"].as_str().unwrap().to_string()).or_default().push(r.id);
            }
            for (key, ids) in &by_key {
                assert_eq!(&s.claims_of_key(key).iter().map(|(r, _)| r.id).collect::<Vec<_>>(), ids, "seed {seed} step {step}: key {key}");
            }
            assert!(s.claims_of_key("no such key").is_empty());
            // a record is superseded exactly when a standing supersedes relation whose link was not rejected names it as the old one
            for (position, r) in s.core.data.records.iter().enumerate() {
                let by_walk = s
                    .core
                    .data
                    .records
                    .iter()
                    .enumerate()
                    .any(|(p, x)| standing[p] && x.ends.as_ref().is_some_and(|(_, rel, to)| rel == "supersedes" && *to == r.id));
                let state = s.record_state(&r.id).unwrap();
                assert_eq!(
                    matches!(state, RecordState::Superseded(_)),
                    standing[position] && r.kind != RecordKind::Observe && by_walk,
                    "seed {seed} step {step}"
                );
                assert_eq!(matches!(state, RecordState::Active | RecordState::Superseded(_)), standing[position], "seed {seed} step {step}");
            }
            for r in s.core.data.records.iter().filter(|r| r.kind == RecordKind::Observe) {
                let b = s.core.data.evidence.get(&r.id).expect("an observation is bound when it is accepted");
                let bound = (b.evidence, b.version, b.start, b.end);
                assert_eq!(*bindings.entry(r.id).or_insert(bound), bound, "seed {seed} step {step}: a binding never changes");
                if s.core.session.engine.status_of(&b.evidence) == Some(crate::node::EV_REVOKED) {
                    revoked.insert(b.evidence);
                }
                let on_version = s.core.session.arena.doc(r.doc_id.as_deref().expect("a quote names its document")).map(|d| d.version_id) == Some(b.version);
                let by_two = !revoked.contains(&b.evidence) && on_version;
                assert_eq!(s.core.observe_grounded(r), by_two, "seed {seed} step {step}: {} by the kernel's rule and by P6-4", r.id.short());
                assert_eq!(fresh.get(&r.id).map(|v| v.0), Some(by_two), "seed {seed} step {step}: {} in the flags", r.id.short());
                came_back += usize::from(stood.insert(r.id, by_two) == Some(false) && by_two);
                off_version += usize::from(!on_version && !revoked.contains(&b.evidence));
                revoked_on_version += usize::from(on_version && revoked.contains(&b.evidence));
            }
            let _ = s.audit_root();
        }
        let held = (told(&s), s.claim_chains(), vsc::keys(&s, &[], Some(5000)));
        drop(s);
        let r = AuditState::open(&path.0).unwrap();
        assert_eq!((told(&r), r.claim_chains(), vsc::keys(&r, &[], Some(5000))), held, "seed {seed}: replay");
    }
    assert!(
        puts > 100 && chained > 40 && withdrawn > 30 && replaced > 10 && checkpoints > 20,
        "{puts} puts, {chained} chains, {withdrawn} withdrawals, {replaced} planned changes, {checkpoints} context checkpoints"
    );
    assert!(
        came_back > 5 && off_version > 100 && revoked_on_version > 100,
        "{came_back} quotes came back with their version, {off_version} looks at a quote off the current version, {revoked_on_version} at a revoked one on it"
    );
}

// ---- the review of b27625da (Codex, 26.11.2026) ----

/// Finding 1. A journal that takes its sources as they come soon has more documents than a scope names, and a scope of every
/// document was refused for every submission after the 257th source. The writer names the documents its lines need; the kernel
/// refuses a scope too wide as it did.
#[test]
fn the_scope_of_lines_names_the_documents_they_need_and_a_scope_too_wide_is_refused_as_before() {
    let path = TempPath::new();
    let mut s = stream(&path.0);
    for n in 0..257usize {
        s.put_document("feed", &format!("d{n:03}"), format!("Value {n} is {}.\n", n * 2).as_bytes()).unwrap();
    }
    let lines = [quote("o", "d000", "Value 0 is 0."), fact("v", "value/0", "0", &["o"])];
    let wide = all_docs(&s);
    let error = s.submit_records_id(&fresh_id("wide"), "agent", "t0", &wide, &lines).error.expect("a refusal");
    assert_eq!((error.field.as_deref(), error.message.as_str()), (Some("docs"), "too many references"));
    assert_eq!(s.head(), 0);

    let scope = s.scope_of_lines("agent", "t0", &lines);
    assert_eq!(scope.docs, ["d000"]);
    let first = s.submit_records_id(&fresh_id("narrow"), "agent", "t0", &scope, &lines);
    assert!(first.error.is_none(), "{:?}", first.error.map(|e| e.to_json()));
    // another task rests on the claim by its id and quotes the last source: the documents of both
    let lines = [quote("o", "d256", "Value 256 is 512."), fact("v", "value/256", "512", &["o"]), fact("sum", "sum", "512", &[&at(&first.accepted[1]), "v"])];
    let scope = s.scope_of_lines("agent", "t1", &lines);
    assert_eq!(scope.docs, ["d000", "d256"]);
    let second = s.submit_records_id(&fresh_id("narrow"), "agent", "t1", &scope, &lines);
    assert_eq!((second.accepted.len(), second.error.is_none()), (3, true));
    // a name an earlier submission of the task gave is found as the kernel finds it, and the documents under it are named
    let lines = [fact("twice", "twice", "1024", &["sum"])];
    let scope = s.scope_of_lines("agent", "t1", &lines);
    assert_eq!(scope.docs, ["d000", "d256"]);
    assert!(s.submit_records_id(&fresh_id("narrow"), "agent", "t1", &scope, &lines).error.is_none());
    // a scope narrower than the grounds is refused by the kernel: the writer's scope is no rule of its own
    let narrow = Scope { docs: vec!["d256".to_string()], topic: None, ranges: Vec::new() };
    assert!(s.submit_records_id(&fresh_id("narrow"), "agent", "t1", &narrow, &[fact("thrice", "thrice", "1536", &["sum"])]).error.is_some());
    // a name that is nothing adds nothing, and the kernel refuses its line
    assert!(s.scope_of_lines("agent", "t1", &[fact("x", "x", "1", &["nothing"])]).docs.is_empty());
    let held = told(&s);
    drop(s);
    assert_eq!(told(&AuditState::open(&path.0).unwrap()), held);
}

/// Finding 3. A source put while the run goes on took a name of any length an identifier has, and the task that read it could
/// not be closed: its key holds the name. The bound of a name the journal starts with holds for a source that comes later.
#[test]
fn a_source_that_comes_later_has_the_bound_of_a_name_the_journal_starts_with() {
    let (new, old) = (TempPath::new(), TempPath::new());
    let (mut s, mut t) = (stream(&new.0), stream_under_rules_3(&old.0));
    let (fits, long) = ("n".repeat(MAX_DOC_NAME_BYTES), "n".repeat(MAX_DOC_NAME_BYTES + 1));
    for state in [&mut s, &mut t] {
        state.put_document("owner", &fits, b"A = 10.\n").unwrap();
        let error = state.put_document("owner", &long, b"A = 10.\n").unwrap_err();
        assert_eq!((error.code, error.field.as_deref()), (Code::BadField, Some("doc_id")));
        assert_eq!(state.source_document_count(), 1);
    }
    // the rule of a journal of rules 4 refuses the command itself; a journal of rules 3 is judged, and replayed, as 0.2 judged it
    let put = json!({"kind":"put_document","doc_id":long,"text":"A = 10.\n"});
    let refused = s.commit("owner", "long-name", &put).unwrap();
    assert!(matches!(&refused, Outcome::Error(e) if e.field.as_deref() == Some("doc_id")), "{:?}", refused.value());
    assert!(matches!(t.commit("owner", "long-name", &put).unwrap(), Outcome::Value(_)));
    assert_eq!((s.source_document_count(), t.source_document_count()), (1, 2));
    let (held_new, held_old) = (told(&s), told(&t));
    drop((s, t));
    assert_eq!(told(&AuditState::open(&new.0).unwrap()), held_new);
    assert_eq!(told(&AuditState::open(&old.0).unwrap()), held_old);
}

/// Finding 4. A context checkpoint is a frame of its own: neither the checkpoint of a batch nor an operation of one. The cursor
/// checkpoints of the tasks are written by a batch as before.
#[test]
fn a_context_checkpoint_is_a_frame_of_its_own_and_never_part_of_a_batch() {
    let path = TempPath::new();
    let mut s = stream(&path.0);
    s.put_document("agent", "s1", b"A = 10.\n").unwrap();
    let ids = submit(&mut s, "t1", &[quote("oa", "s1", "A = 10."), fact("a", "A", "10", &["oa"])]);
    let sha = s.source_document("s1").unwrap()["raw_sha256"].clone();
    let manifest = |to: u64| {
        json!({"key":format!("{CONTEXT_CHECKPOINT_PREFIX}1"),"from":0,"to":to,
               "context":{"format":"r2r-context-checkpoint/1","epoch":1,"records":[to_hex(&ids[1].0)],"sources":{"s1":sha},"raw_context":null,"manifest":null}})
    };
    // as the checkpoint of a batch whose one operation stores a record: the operation is stored, the checkpoint is not written
    let line = fact("a2", "2A", "20", &[&at(&ids[1])]);
    let operation = json!({"kind":"submit","directive":"t2","scope":{"docs":["s1"],"topic":null,"ranges":[]},"lines":[line]});
    let batch = s.submit_operations_id("with-a-record", "agent", &[operation], Some(manifest(3))).unwrap();
    assert_eq!(
        (batch["checkpointed"].as_bool(), batch["failed_index"].as_u64(), batch["error"]["field"].as_str()),
        (Some(false), Some(1), Some("vsc:checkpoint"))
    );
    assert!(batch["error"]["message"].as_str().unwrap().contains("a command of its own"), "{batch}");
    assert_eq!((s.head(), s.context_epochs()), (3, 0));
    // as the checkpoint of a batch without an operation, and as an operation
    let alone = s.submit_operations_id("alone", "agent", &[], Some(manifest(3))).unwrap();
    assert_eq!((alone["checkpointed"].as_bool(), alone["error"]["field"].as_str()), (Some(false), Some("vsc:checkpoint")));
    let mut operation = manifest(3);
    operation["kind"] = json!("checkpoint");
    let inside = s.submit_operations_id("inside", "agent", std::slice::from_ref(&operation), None).unwrap();
    assert_eq!((inside["failed_index"].as_u64(), inside["error"]["field"].as_str()), (Some(0), Some("vsc:checkpoint")));
    assert_eq!(s.context_epochs(), 0);
    // a cursor checkpoint of a task is the checkpoint of a batch as before
    let task = json!({"key":"task:t2","from":0,"to":0,"context":{"task_id":"t2"}});
    assert_eq!(s.submit_operations_id("task", "agent", &[], Some(task)).unwrap()["checkpointed"], true);
    // and the command of its own is written: its frame holds the checkpoint alone, with the records root of a frame without a record
    assert!(matches!(s.commit("agent", "own-frame", &operation).unwrap(), Outcome::Value(_)));
    assert_eq!(s.context_epochs(), 1);
    let text = std::fs::read_to_string(&path.0).unwrap();
    let frames: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let last = frames.last().unwrap();
    assert_eq!(last["body"]["command"]["kind"], "checkpoint");
    assert_eq!(frames[1]["body"]["command"]["kind"], "put_document");
    assert_eq!(last["header"]["records_root"], frames[1]["header"]["records_root"]);
    assert_ne!(last["header"]["records_root"], frames[2]["header"]["records_root"], "the frame of a submit has the root of its records");
    let held = told(&s);
    drop(s);
    let r = AuditState::open(&path.0).unwrap();
    assert_eq!((told(&r), r.context_epochs()), (held, 1));
}

/// Finding 5. Under rules 3 a checkpoint with a key of the context checkpoints is any checkpoint: no rule compared it with the
/// form of a manifest, and the reads of 0.3 do not give it out as one.
#[test]
fn a_journal_of_rules_3_has_no_context_checkpoint_to_read_whatever_its_keys() {
    let path = TempPath::new();
    let mut t = stream_under_rules_3(&path.0);
    let key = format!("{CONTEXT_CHECKPOINT_PREFIX}1");
    let free = json!({"key": key, "from": 0, "to": 0, "context": {"anything": true}});
    assert!(t.submit_operations_id("free", "agent", &[], Some(free.clone())).unwrap()["error"].is_null());
    let check = |t: &AuditState| {
        assert_eq!(t.checkpoint(&key).map(|c| c["context"].clone()), Some(json!({"anything": true})), "kept as the checkpoint it is");
        assert_eq!(t.context_epochs(), 0);
        assert!(t.context_checkpoint_of(1).is_none());
        assert_eq!(t.read_active_checkpoint(1).unwrap_err().field.as_deref(), Some("epoch"));
        for epoch in [Some(1), None] {
            let read = vsc::checkpoint(t, epoch);
            assert_eq!(
                (read["status"].as_str(), read["epochs"].as_u64(), read["rules_version"].as_str()),
                (Some("NO_CONTEXT_CHECKPOINT"), Some(0), Some(RULES_VERSION_3))
            );
            assert!(read.get("active").is_none() && read.get("listed").is_none(), "{read}");
        }
    };
    check(&t);
    drop(t);
    check(&AuditState::open(&path.0).unwrap());
}

/// Finding 6. A context checkpoint lists what is active when it is written. A record that fell, was withdrawn or was replaced
/// is refused by name: its checkpoint would give it back as kept once its ground came back, though it was not kept.
#[test]
fn a_context_checkpoint_lists_records_that_are_active_when_it_is_written() {
    let path = TempPath::new();
    let mut s = stream(&path.0);
    s.put_document("agent", "a", b"Alpha is one.\n").unwrap();
    s.put_document("agent", "b", b"Beta is two.\n").unwrap();
    let ids = submit(
        &mut s,
        "t1",
        &[quote("oa", "a", "Alpha is one."), quote("ob", "b", "Beta is two."), fact("alpha", "alpha", "one", &["oa"]), fact("beta", "beta", "two", &["ob"])],
    );
    let (oa, ob, alpha, beta) = (ids[0], ids[1], ids[2], ids[3]);
    let refused = |s: &mut AuditState, listed: &[RecordId], state: &str, who: &RecordId| {
        let error = s.context_checkpoint("agent", listed, &[], None, None).unwrap_err();
        assert_eq!(error.field.as_deref(), Some("vsc:checkpoint"), "{state}");
        assert!(error.message.contains("active now") && error.message.contains(&who.short()) && error.message.contains(state), "{state}: {}", error.message);
        assert_eq!(s.context_epochs(), 0, "{state}");
    };
    // a document gets other bytes: the claim on its quote is affected, the claim on the other document stands
    s.put_document("agent", "a", b"Alpha is uno.\n").unwrap();
    assert_eq!((state_of(&s, &alpha), state_of(&s, &beta)), ("AFFECTED_BY_EVIDENCE_CHANGE", "ACTIVE"));
    refused(&mut s, &[beta, alpha], "AFFECTED_BY_EVIDENCE_CHANGE", &alpha);
    // a planned change: the old claim stands and is replaced
    let later = submit(&mut s, "t2", &[fact("b2", "beta", "2", &[&at(&ob)]), supersedes("s", "b2", &at(&beta), &[&at(&ob)])]);
    refused(&mut s, &[beta], "SUPERSEDED", &beta);
    // the first bytes come back, and the quote under alpha is withdrawn
    s.put_document("agent", "a", b"Alpha is one.\n").unwrap();
    assert_eq!(state_of(&s, &alpha), "ACTIVE");
    assert_eq!(s.withdraw_text("owner", "a", "Alpha is one.").unwrap(), 1);
    refused(&mut s, &[oa], "WITHDRAWN", &oa);
    refused(&mut s, &[later[0], alpha], "AFFECTED_BY_EVIDENCE_CHANGE", &alpha);
    // what is active is listed, and read back
    let written = s.context_checkpoint("agent", &[later[0], ob], &[], None, None).unwrap();
    assert_eq!((written["epoch"].as_u64(), written["records"].as_u64()), (Some(1), Some(2)));
    assert_eq!(s.read_active_checkpoint(1).unwrap().active.iter().map(|r| r.id).collect::<Vec<_>>(), [later[0], ob]);
    let held = (told(&s), vsc::checkpoint(&s, Some(1)));
    drop(s);
    let r = AuditState::open(&path.0).unwrap();
    assert_eq!((told(&r), vsc::checkpoint(&r, Some(1))), held);
}

/// The observation of the review beside its findings: a chain of claims that one submission brings was walked from its end to its
/// start again for each claim of it, a number of looks that grew as the square of the chain. What a walk found is kept for the
/// rest of the submission; a later submission reads the flags the journal kept.
#[test]
fn a_chain_of_claims_that_one_submission_brings_is_walked_once() {
    use super::super::stream::STANDS_VISITS;
    let path = TempPath::new();
    let mut s = stream(&path.0);
    s.put_document("agent", "s1", b"A = 1.\n").unwrap();
    let mut lines = vec![quote("o", "s1", "A = 1."), fact("c0", "k0", "1", &["o"])];
    for n in 1..200usize {
        lines.push(fact(&format!("c{n}"), &format!("k{n}"), "1", &[&format!("c{}", n - 1)]));
    }
    STANDS_VISITS.with(|n| n.set(0));
    let ids = submit(&mut s, "chain", &lines);
    let looks = STANDS_VISITS.with(std::cell::Cell::get);
    // 199 claims rest on a claim: about one look for each, where a walk of the whole chain for each claim took 39 999 looks
    assert!(looks <= lines.len() as u64 + 2, "{looks} looks at {} lines", lines.len());
    assert!(ids.iter().all(|id| s.is_grounded(id)));
    assert_eq!(s.claim_chains().max_depth, 199);
    // the next submission reads the end of the chain from the flags kept: one look
    STANDS_VISITS.with(|n| n.set(0));
    submit(&mut s, "next", &[fact("next", "next", "1", &[&at(ids.last().unwrap())])]);
    assert_eq!(STANDS_VISITS.with(std::cell::Cell::get), 1);
    // inside a batch no flags are kept: the chain is walked once for the operation, not once for each of its lines
    let scope = json!({"docs":["s1"],"topic":null,"ranges":[]});
    let tail = |n: usize, on: String| fact(&format!("t{n}"), &format!("tail{n}"), "1", &[&on]);
    let operation =
        json!({"kind":"submit","directive":"batch","scope":scope,"lines":[tail(0, at(ids.last().unwrap())), tail(1, "t0".into()), tail(2, "t1".into())]});
    STANDS_VISITS.with(|n| n.set(0));
    let batch = s.submit_operations_id("in-a-batch", "agent", &[operation], None).unwrap();
    assert!(batch["error"].is_null(), "{batch}");
    let looks = STANDS_VISITS.with(std::cell::Cell::get);
    assert!((200..=3 * 204).contains(&looks), "{looks} looks");
    // a fallen ground is found fallen by the same walk: the quote goes, and no claim can be put on the chain
    s.revoke_observation("owner", &ids[0]).unwrap();
    assert_eq!(refused(&mut s, "late", &[fact("late", "late", "1", &[&at(ids.last().unwrap())])]).code, Code::EvidenceNotActive);
    let held = told(&s);
    drop(s);
    assert_eq!(told(&AuditState::open(&path.0).unwrap()), held);
}
