//! A refused answer and a late one in the journal (0.3.1; findings 7 and 10 of the plan probe, the architect's choice of
//! 27.11.2026): the checkpoints `task-repair:<task>:<attempt>` and `task-conflict:<task>:<n>` of a batch of the kernel.
//!
//! - Of a line that was not stored the journal keeps its place, the SHA-256 of its canonical JSON, the code of the refusal, the
//!   field when its name is the kernel's own and the rule; never the text of the line or the message of the refusal.
//! - An answer refused whole leaves the same record as one refused in part.
//! - An answer sent to a task that is closed leaves the hash of the answer; one sent to a task the journal does not show
//!   closed leaves nothing.
//!
//! The journal this test writes is the vector `j4a/set-d/d9-refused-and-late-answers.wal` of the independent verifier, with two
//! frames of each kind for the counters `rejected_submissions` and `late_submissions` of the observation report. The test fails
//! if the kernel no longer writes those bytes; `YUCE_BLESS_V031_VECTORS=1` writes the vector again.

use sbgk_core::audit::cut::Journal;
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, TaskKind};
use sbgk_core::audit::observation;
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::AuditStore;
use sbgk_core::hash::{sha256, to_hex};
use sbgk_core::jcs::to_jcs;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const BLESS: &str = "YUCE_BLESS_V031_VECTORS";
const DOC: &str = "Alpha holds in the northern field.\nBeta holds in the southern field.\n";
/// Words of a refused line that must not reach the journal: its text, and the name of a field the kernel does not know.
const PRIVATE_TEXT: &str = "PRIVATE-WORDS-OF-THE-REFUSED-LINE";
const PRIVATE_FIELD: &str = "zzz_private_field";
/// The text of a line refused before the store: it reaches no frame.
const WHOLE_TEXT: &str = "WORDS-OF-A-LINE-REFUSED-BEFORE-THE-STORE";

struct Folder(PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("r2r_refused_late_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Folder(root)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn digest(value: &Value) -> String {
    to_hex(&sha256(to_jcs(value).as_bytes()))
}

#[allow(dead_code)]
fn keep(path: &Path, bytes: &[u8]) {
    if std::env::var_os(BLESS).is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        return;
    }
    let published = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e} ({BLESS}=1 writes the vectors)", path.display()));
    assert!(published == bytes, "{}: the kernel no longer writes these bytes ({BLESS}=1 writes the vectors again)", path.display());
}

/// The frames of a journal file, as JSON.
fn frames(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

#[test]
fn a_refused_answer_and_a_late_one_are_in_the_journal_without_the_text_of_a_line() {
    let work = Folder::new("d9");
    let wal = work.0.join("run.wal");
    let mut s = AuditState::create_from_docs(&wal, &AuditOntology::base(), "axis-d9", vec![("src".to_string(), DOC.as_bytes().to_vec())]).unwrap();
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let task = d.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), 1);
    assert_eq!(task["kind"], "EXTEND", "{task}");
    let id = task["task_id"].as_str().unwrap().to_string();
    let key = task["key"].as_str().unwrap().to_string();
    let p = task["local_id_prefix"].as_str().unwrap().to_string();
    let local = |name: &str| format!("{p}{name}");

    // 1. an answer refused in part: two lines are stored, the third has a field the kernel does not know
    let quote = json!({"kind": "observe", "local_id": local("o1"), "doc_id": "src", "exact_quote": "Alpha holds in the northern field.", "terms": ["alpha"]});
    let claim = json!({"kind": "claim", "local_id": local("c1"), "text": "Alpha holds in the north.", "subject": "alpha", "object": "north", "stance": "reported",
                       "based_on": [local("o1")]});
    let unknown = json!({"kind": "claim", "local_id": local("c2"), "text": PRIVATE_TEXT, "subject": "alpha", "stance": "reported", "based_on": [local("o1")],
                         PRIVATE_FIELD: "x"});
    let part = d.submit(&mut s, &id, "w1", &[quote.clone(), claim.clone(), unknown.clone()], 2);
    assert_eq!(
        (part["status"].as_str(), part["repair_scope"].as_str(), part["audit_persisted"].as_bool()),
        (Some("REPAIR_REQUIRED"), Some("rejected_items_only"), Some(true)),
        "{part}"
    );
    // the agent is told all of it, as before: the message names the field
    assert!(part["refused"][0]["error"]["message"].as_str().unwrap().contains(PRIVATE_FIELD), "{part}");
    let repairs = s.checkpoint_keys("task-repair:");
    assert_eq!(repairs.len(), 1);
    let first = s.checkpoint(&repairs[0]).unwrap()["context"].clone();
    assert_eq!(
        (first["task_id"].as_str(), first["work_key"].as_str(), first["kind"].as_str(), first["agent"].as_str()),
        (Some(id.as_str()), Some(key.as_str()), Some("EXTEND"), Some("w1"))
    );
    // the field of the refusal is the agent's own word, so the mark has none: the place, the hash and the code
    assert_eq!(first["refused"], json!([{"index": 2, "line_sha256": digest(&unknown), "code": part["refused"][0]["error"]["code"]}]), "{first}");
    assert_eq!(first["excluded"], json!([]));

    // 2. a line that is refused for a field of the kernel's own vocabulary names it, and a line that rests on it is left out by its hash
    let dangling = json!({"kind": "claim", "local_id": local("c3"), "text": "Beta holds in the south.", "subject": "beta", "stance": "reported", "based_on": ["no-such-line"]});
    let resting =
        json!({"kind": "claim", "local_id": local("c4"), "text": "The south is held.", "subject": "south", "stance": "reported", "based_on": [local("c3")]});
    // a third line cites the stored quote by the bare hex of its id: the kernel gives the reference its "@" and tells the agent
    // (`referenced`). Until 0.3.0 the checkpoint named such lines by their local ids, names the agent chose; it no longer does
    let bare = part["accepted_locals"][local("o1")].as_str().unwrap().trim_start_matches('@').to_string();
    let cited = json!({"kind": "claim", "local_id": local("c5"), "text": "The north is held.", "subject": "north", "stance": "reported", "based_on": [bare]});
    let second = d.submit(&mut s, &id, "w1", &[dangling.clone(), resting.clone(), cited], 3);
    assert_eq!(second["status"], "REPAIR_REQUIRED", "{second}");
    assert_eq!(second["referenced"].as_array().map(Vec::len), Some(1), "{second}");
    assert_eq!(second["referenced"][0]["local_id"], local("c5"), "{second}");
    let repairs = s.checkpoint_keys("task-repair:");
    assert_eq!(repairs.len(), 2);
    let context = repairs.iter().map(|k| s.checkpoint(k).unwrap()["context"].clone()).find(|c| c["attempt"] != first["attempt"]).unwrap();
    assert_eq!(context["refused"][0]["line_sha256"], digest(&dangling), "{context}");
    assert_eq!(context["refused"][0]["field"], second["refused"][0]["error"]["field"], "{context}");
    assert!(context["refused"][0]["field"].is_string(), "{context}");
    assert_eq!(context["excluded"], json!([{"index": 1, "line_sha256": digest(&resting)}]), "{context}");
    assert_eq!(context.get("referenced_bare_ids"), None, "{context}");
    assert!(!context.to_string().contains(&local("c5")), "{context}");

    // 3. an answer refused whole: a reading takes no done line, and nothing of the answer is stored
    let done = json!({"kind": "done", "local_id": local("d"), "rq_id": "q", "directive_id": id, "answer_ids": [], "outcome": "unknown", "text": WHOLE_TEXT});
    let whole = d.submit(&mut s, &id, "w1", std::slice::from_ref(&done), 4);
    assert_eq!(
        (whole["status"].as_str(), whole["repair_scope"].as_str(), whole["audit_persisted"].as_bool()),
        (Some("REPAIR_REQUIRED"), Some("whole_answer"), Some(true)),
        "{whole}"
    );
    let repairs = s.checkpoint_keys("task-repair:");
    assert_eq!(repairs.len(), 3);
    let whole_mark = repairs.iter().map(|k| s.checkpoint(k).unwrap()["context"].clone()).find(|c| c["whole_answer"] == true).unwrap();
    assert_eq!((whole_mark["lines"].as_u64(), whole_mark["answer_sha256"].as_str()), (Some(1), Some(digest(&json!([done])).as_str())), "{whole_mark}");
    assert_eq!(whole_mark["refused"], json!([{"index": 0, "line_sha256": digest(&done), "code": whole["error"]["code"], "field": "kind"}]), "{whole_mark}");

    // What the journal holds of the refused lines.
    // - No checkpoint of a refusal repeats a line: neither its text nor the name of a field the kernel does not know.
    // - A line refused before the store (here the done line of the answer refused whole) is in no frame at all.
    // - A line the store itself refused is in the frame of its submit, whole, as in every journal before: the frame is the
    //   command the store ran, and a replay runs it again to the same refusal. Only the checkpoint stopped repeating it.
    let marks: Vec<String> = s.checkpoint_keys("task-repair:").iter().map(|k| s.checkpoint(k).unwrap().to_string()).collect();
    assert!(marks.iter().all(|m| !m.contains(PRIVATE_FIELD) && !m.contains(PRIVATE_TEXT) && !m.contains(WHOLE_TEXT) && !m.contains("message")), "{marks:?}");
    drop(s);
    let journal = std::fs::read_to_string(&wal).unwrap();
    assert!(!journal.contains(WHOLE_TEXT), "a line refused before the store is in the journal");
    let with_the_line: Vec<Value> = frames(&wal).into_iter().filter(|f| f["body"].to_string().contains(PRIVATE_FIELD)).collect();
    assert_eq!(with_the_line.len(), 1);
    assert_eq!(with_the_line[0]["body"]["command"]["kind"], "submit");
    // the checkpoints are read back after a restart as they were written, and a replay of the journal ends at the same root
    let reopened = AuditState::open(&wal).unwrap();
    assert_eq!(reopened.checkpoint_keys("task-repair:").len(), 3);
    let _ = (quote, claim, d);
}

/// The vector: one reading with an answer refused in part, an answer refused whole, the answer that closes the task, and two
/// answers sent after it; then a seal and the close.
/// What the dispatcher writes for each is checked on a journal of this run; the published vector is checked as it is.
#[test]
fn the_vector_of_refused_and_late_answers_is_what_the_kernel_writes_and_the_report_counts_them() {
    let work = Folder::new("vector");
    let wal = work.0.join("run.wal");
    let mut s = AuditState::create_from_docs(&wal, &AuditOntology::base(), "axis-d9", vec![("src".to_string(), DOC.as_bytes().to_vec())]).unwrap();
    let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
    let task = d.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), 1);
    let id = task["task_id"].as_str().unwrap().to_string();
    let p = task["local_id_prefix"].as_str().unwrap().to_string();
    let local = |name: &str| format!("{p}{name}");
    let quote = json!({"kind": "observe", "local_id": local("o1"), "doc_id": "src", "exact_quote": "Alpha holds in the northern field.", "terms": ["alpha"]});
    let claim = json!({"kind": "claim", "local_id": local("c1"), "text": "Alpha holds in the north.", "subject": "alpha", "object": "north", "stance": "reported",
                       "based_on": [local("o1")]});
    let dangling = json!({"kind": "claim", "local_id": local("c2"), "text": "Beta holds in the south.", "subject": "beta", "object": "south", "stance": "reported",
                          "based_on": ["no-such-line"]});
    let done = json!({"kind": "done", "local_id": local("d"), "rq_id": "q", "directive_id": id, "answer_ids": [], "outcome": "unknown"});
    let root = s.root();
    // an answer to a task nobody was given leaves nothing
    assert_eq!(d.submit(&mut s, "T999-no-such-task", "w1", std::slice::from_ref(&claim), 2)["status"], "STALE_TASK");
    assert_eq!(s.root(), root);
    assert_eq!(d.submit(&mut s, &id, "w1", &[quote.clone(), claim.clone(), dangling.clone()], 2)["status"], "REPAIR_REQUIRED");
    assert_eq!(d.submit(&mut s, &id, "w1", std::slice::from_ref(&done), 3)["status"], "REPAIR_REQUIRED");
    let second_quote =
        json!({"kind": "observe", "local_id": local("o2"), "doc_id": "src", "exact_quote": "Beta holds in the southern field.", "terms": ["beta"]});
    let repaired = json!({"kind": "claim", "local_id": local("c2"), "text": "Beta holds in the south.", "subject": "beta", "object": "south", "stance": "reported",
                          "based_on": [local("o2")]});
    // the answer that closes the task cites a stored quote by the bare hex of its id: the agent is told, and the checkpoint of
    // the task no longer names the line (`referenced_bare_ids`, written until 0.3.0 and read by nothing)
    let stored = s.records_since(0)[0].id.short().trim_start_matches('@').to_string();
    let cited = json!({"kind": "claim", "local_id": local("c5"), "text": "The north is held.", "subject": "north", "object": "held", "stance": "reported",
                       "based_on": [stored]});
    let closed = d.submit(&mut s, &id, "w1", &[second_quote, repaired, cited], 4);
    assert_eq!(closed["status"], "COMMITTED", "{closed}");
    assert_eq!(closed["referenced"].as_array().map(Vec::len), Some(1), "{closed}");
    let closing = s.checkpoint(&format!("task:{}", task["key"].as_str().unwrap())).unwrap();
    assert_eq!(closing["context"]["task_id"], id.as_str());
    assert_eq!(closing["context"].get("referenced_bare_ids"), None, "{closing}");
    assert!(s.checkpoint_keys("").iter().all(|k| !s.checkpoint(k).unwrap().to_string().contains("referenced_bare_ids")));
    // the task is closed: an answer of its reader that says otherwise, and an answer of another agent, are late
    let other = json!({"kind": "claim", "local_id": local("c9"), "text": "Alpha does not hold in the north.", "subject": "alpha", "object": "nowhere", "stance": "refuted",
                       "based_on": [local("o1")]});
    assert_eq!(d.submit(&mut s, &id, "w1", std::slice::from_ref(&other), 5)["status"], "STALE_TASK");
    assert_eq!(d.submit(&mut s, &id, "w2", &[], 6)["status"], "STALE_TASK");
    let late: Vec<Value> = s.checkpoint_keys("task-conflict:").iter().map(|k| s.checkpoint(k).unwrap()).collect();
    assert_eq!(
        late.iter().map(|c| c["key"].as_str().unwrap().to_string()).collect::<Vec<_>>(),
        [format!("task-conflict:{id}:1"), format!("task-conflict:{id}:2")]
    );
    let (first, second) = (&late[0]["context"], &late[1]["context"]);
    assert_eq!(
        (first["agent"].as_str(), first["closed_as"].as_str(), first["closed_by"].as_str(), first["lines"].as_u64(), first["answer_sha256"].as_str()),
        (Some("w1"), Some("completed"), Some("w1"), Some(1), Some(digest(&json!([other])).as_str())),
        "{first}"
    );
    assert_eq!(
        (second["agent"].as_str(), second["lines"].as_u64(), second["answer_sha256"].as_str()),
        (Some("w2"), Some(0), Some(digest(&json!([])).as_str())),
        "{second}"
    );
    assert_eq!(first["work_key"], task["key"]);
    // no more than a bound of late answers to one task is recorded
    for n in 0..20 {
        d.submit(&mut s, &id, "w2", &[json!({"n": n})], 7 + n);
    }
    assert_eq!(s.checkpoint_keys(&format!("task-conflict:{id}:")).len(), 16);
    drop(s);

    // The vector has two frames of each kind: the same steps without the flood, sealed and closed. A task id holds a nonce of
    // its dispatcher, so the journal is not written twice with the same bytes: the vector is written once, and what is checked
    // from then on is the published file.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../verifier/inputs/j4a/set-d");
    let published = dir.join("d9-refused-and-late-answers.wal");
    if std::env::var_os(BLESS).is_some() {
        let wal = work.0.join("vector.wal");
        let mut s = AuditState::create_from_docs(&wal, &AuditOntology::base(), "axis-d9", vec![("src".to_string(), DOC.as_bytes().to_vec())]).unwrap();
        let mut d = Dispatcher::new(DispatchConfig::default(), vec![]);
        let task = d.acquire_for(&s, "w1", true, None, Some(&[TaskKind::Extend]), 1);
        let id = task["task_id"].as_str().unwrap().to_string();
        // the lines again, under the names of this task
        let renamed = |line: &Value| -> Value { serde_json::from_str(&line.to_string().replace(&p, task["local_id_prefix"].as_str().unwrap())).unwrap() };
        d.submit(&mut s, &id, "w1", &[renamed(&quote), renamed(&claim), renamed(&dangling)], 2);
        let mut done = renamed(&done);
        done["directive_id"] = json!(id);
        d.submit(&mut s, &id, "w1", &[done], 3);
        let second_quote =
            json!({"kind": "observe", "local_id": local("o2"), "doc_id": "src", "exact_quote": "Beta holds in the southern field.", "terms": ["beta"]});
        let repaired = json!({"kind": "claim", "local_id": local("c2"), "text": "Beta holds in the south.", "subject": "beta", "object": "south",
                              "stance": "reported", "based_on": [local("o2")]});
        assert_eq!(d.submit(&mut s, &id, "w1", &[renamed(&second_quote), renamed(&repaired)], 4)["status"], "COMMITTED");
        d.submit(&mut s, &id, "w1", &[renamed(&other)], 5);
        d.submit(&mut s, &id, "w2", &[], 6);
        s.seal().unwrap();
        s.close_run().unwrap();
        drop(s);
        std::fs::create_dir_all(dir.join("d9-refused-and-late-answers.docs")).unwrap();
        std::fs::write(&published, std::fs::read(&wal).unwrap()).unwrap();
        std::fs::write(dir.join("d9-refused-and-late-answers.docs").join("src"), DOC).unwrap();
    }
    assert_eq!(std::fs::read(dir.join("d9-refused-and-late-answers.docs").join("src")).unwrap(), DOC.as_bytes());

    // the published journal is one the kernel replays, and its frames of the two kinds have the form the observation report
    // counts: a batch of the kernel with outcome value whose checkpoint was written under the key
    let counted = |prefix: &str| {
        let hits: Vec<Value> = frames(&published)
            .into_iter()
            .map(|f| f["body"].clone())
            .filter(|b| b["command"]["kind"] == "batch" && b["outcome"]["kind"] == "value" && b["outcome"]["result"]["checkpointed"] == true)
            .filter(|b| b["command"]["checkpoint"]["key"].as_str().is_some_and(|k| k.starts_with(prefix)))
            .collect();
        assert!(hits.iter().all(|b| b["actor"] == "kernel" && b["command"]["operations"] == json!([])), "{hits:?}");
        // a mark holds no message of a refusal and no line
        assert!(hits.iter().all(|b| !b["command"]["checkpoint"].to_string().contains("message")), "{hits:?}");
        hits.len()
    };
    assert_eq!((counted("task-repair:"), counted("task-conflict:")), (2, 2));
    let journal = Journal::read(&published).unwrap();
    let part = journal.part(journal.last_seal().unwrap(), None, &BTreeSet::new()).unwrap();
    assert!(part.closed);
    let report = observation::of_journal(&part);
    let debt = &report["debt"]["total"];
    assert_eq!((debt["rejected_submissions"].as_u64(), debt["late_submissions"].as_u64()), (Some(2), Some(2)), "{debt}");
    assert_eq!(report["claims"].as_array().map(Vec::len), Some(2));
    assert_eq!((debt["affected"].as_u64(), debt["contested"].as_u64(), debt["stale"].as_u64()), (Some(0), Some(0), Some(0)), "{debt}");
}
