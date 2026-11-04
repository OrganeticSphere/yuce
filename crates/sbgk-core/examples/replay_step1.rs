//! Offline replay of step 1 of Gemini's plan after the consilium of 10A-17 ($0, no models): every answer the swarm sent in a
//! recorded live run goes through the current dispatcher (item-wise acceptance, the S0 fixes, a quote cut where its line ends
//! extended to its clause) on a recorded WAL boundary: the answer's own store submission when matched,
//! otherwise the task's next submission/closure (an upper bound, explicitly labeled per row), with the lease the task had (its scope and issued records from the WAL, a summary's from its directive)
//! and the records it had stored under their local ids. One row per answer: what the recorded kernel stored and lost, line by line,
//! and what the current one does with the same lines. The states come from one recovery pass over a copy of the WAL
//! (`AuditState::replay_prefixes`), not one recovery per answer.
//!
//! cargo run --release --example replay_step1 -- <run dir with arm_c/run.wal, arm_c/questions.json, journal.jsonl> <out.jsonl>
//!
//! Each answer is replayed on its own: the run's repairs answered the recorded kernel's replies, not the current one's. A summary
//! whose replayed answer still has refused lines is closed as the runner closes it when its repairs are used up, by a partial answer
//! naming the lines stored. Link checks are not replayed (a verdict needs the link's state when it was issued), nor answers the
//! runner refused before the kernel saw them.

use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion, TaskKind};
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::from_hex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

fn id(hex: &Value) -> RecordId {
    RecordId(from_hex(hex.as_str().expect("hex id")).expect("64 hex digits"))
}

fn scope_of(v: &Value) -> Scope {
    let ranges = v["ranges"].as_array().map_or_else(Vec::new, |a| {
        a.iter().map(|r| (r[0].as_str().unwrap().to_string(), r[1].as_u64().unwrap() as usize, r[2].as_u64().unwrap() as usize)).collect()
    });
    let docs = v["docs"].as_array().map_or_else(Vec::new, |a| a.iter().map(|d| d.as_str().unwrap().to_string()).collect());
    Scope { docs, topic: v["topic"].as_str().map(str::to_string), ranges }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map_or_else(Vec::new, |a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
}

/// One store submission of a task in the WAL: its entry, the local ids of its lines and the records it accepted, in order.
struct Sub {
    n: usize,
    locals: Vec<Option<String>>,
    lines: Vec<Value>,
    accepted: Vec<RecordId>,
    scope: Scope,
    issued: Vec<RecordId>,
}

/// The lines the runner submits for an answer (`submission_lines`): every nonblank line a JSON object, `[]` an empty answer.
fn answer_lines(text: &str) -> Option<Vec<Value>> {
    if text.trim() == "[]" {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match serde_json::from_str::<Value>(l) {
            Ok(v) if v.is_object() => out.push(v),
            _ => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// An answer to replay: its row so far, the state it needs (the WAL's first `n` entries) and its lease.
struct Job {
    row: Value,
    n: usize,
    kind: TaskKind,
    key: String,
    task: String,
    agent: String,
    lines: Vec<Value>,
    prior: BTreeMap<String, RecordId>,
    accepted_lines: Vec<Value>,
    lease: Option<(Scope, Vec<RecordId>)>,
    prompt: String,
    reply: Value,
    last: bool,
}

fn kind_of(name: &str) -> Option<TaskKind> {
    Some(match name {
        "EXTEND" => TaskKind::Extend,
        "INVESTIGATE" => TaskKind::Investigate,
        "REQUEST" => TaskKind::Request,
        "SUMMARIZE" => TaskKind::Summarize,
        _ => return None,
    })
}

/// The rules a recorded diagnostic names for a line, and the negation it cut off.
fn rules_of(p: &Value) -> (Vec<&'static str>, Option<String>) {
    let mut rules = Vec::new();
    for k in ["negation_before", "ends_mid_clause", "missing_identifiers", "observe_ends", "exact_bytes_in_section", "characters"] {
        if p.get(k).is_some() {
            rules.push(k);
        }
    }
    (rules, p["negation_before"].as_str().map(str::to_string))
}

/// What the current kernel did with each line of an answer, by index: stored, a no-op resend, refused (with its code and rule), left
/// out with a refused line it rests on, or refused with the whole answer.
fn new_outcomes(r: &Value, lines: &[Value], prior: &BTreeMap<String, RecordId>) -> Vec<Value> {
    let stored: BTreeSet<String> = r["accepted_locals"].as_object().map_or_else(BTreeSet::new, |m| m.keys().cloned().collect());
    let refused: BTreeMap<u64, &Value> =
        r["refused"].as_array().map_or_else(BTreeMap::new, |a| a.iter().filter_map(|x| Some((x["index"].as_u64()?, x))).collect());
    let excluded: BTreeSet<u64> = r["excluded"].as_array().map_or_else(BTreeSet::new, |a| a.iter().filter_map(|x| x["index"].as_u64()).collect());
    let whole = r["status"] == "REPAIR_REQUIRED" && r["repair_scope"] != "rejected_items_only";
    lines
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let local = v["local_id"].as_str().unwrap_or("");
            if stored.contains(local) {
                json!({"outcome": "stored"})
            } else if let Some(x) = refused.get(&(i as u64)) {
                json!({"outcome": "refused", "code": x["error"]["code"], "rule": x["error"]["expected_by_kernel"]["rule"], "message": x["error"]["message"]})
            } else if excluded.contains(&(i as u64)) {
                json!({"outcome": "excluded"})
            } else if whole {
                json!({"outcome": "refused_whole", "code": r["error"]["code"]})
            } else if prior.contains_key(local) {
                json!({"outcome": "resent"})
            } else if r["status"] == "COMMITTED" {
                json!({"outcome": "stored"})
            } else {
                json!({"outcome": "not_stored"})
            }
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (run, out_path) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let wal: Vec<String> = std::fs::read_to_string(run.join("arm_c").join("run.wal")).unwrap().lines().map(str::to_string).collect();
    let questions: Vec<ResearchQuestion> = serde_json::from_str::<Value>(&std::fs::read_to_string(run.join("arm_c").join("questions.json")).unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|q| ResearchQuestion {
            id: q["id"].as_str().unwrap().to_string(),
            text: q["text"].as_str().unwrap_or("").to_string(),
            about: strings(&q["about"]),
            stances: strings(&q["stances"]),
            relations: strings(&q["relations"]),
            concept_types: strings(&q["concept_types"]),
        })
        .collect();

    // each task's store submissions in the WAL, and the entry closing it
    let mut subs: BTreeMap<String, Vec<Sub>> = BTreeMap::new();
    let mut closed: BTreeMap<String, usize> = BTreeMap::new();
    for (n, raw) in wal.iter().enumerate() {
        let e: Value = serde_json::from_str(raw).unwrap();
        let p = &e["payload"];
        let cmd = &p["command"];
        if cmd["kind"] == "submit" {
            let lines = cmd["lines"].as_array().unwrap();
            subs.entry(cmd["directive"].as_str().unwrap().to_string()).or_default().push(Sub {
                n,
                lines: lines.clone(),
                locals: lines.iter().map(|v| v["local_id"].as_str().map(str::to_string)).collect(),
                accepted: p["outcome"]["result"]["accepted"].as_array().unwrap().iter().map(id).collect(),
                scope: scope_of(&cmd["scope"]),
                issued: cmd["allowed_records"].as_array().unwrap().iter().map(id).collect(),
            });
        } else if let Some((task, _)) = p["submission_id"].as_str().and_then(|s| s.split_once("#done")) {
            closed.entry(task.to_string()).or_insert(n);
        }
    }

    let (mut contexts, mut texts, mut replies) = (BTreeMap::new(), BTreeMap::new(), Vec::new());
    for raw in std::fs::read_to_string(run.join("journal.jsonl")).unwrap().lines() {
        let e: Value = serde_json::from_str(raw).unwrap();
        let r = e["record"].clone();
        let call = r["call_id"].as_str().unwrap_or("").to_string();
        match e["kind"].as_str() {
            Some("context") => {
                contexts.insert(call, r);
            }
            Some("call") => {
                texts.insert(call, r["text"].as_str().unwrap_or("").to_string());
            }
            Some("reply") => replies.push(r),
            _ => {}
        }
    }

    // the runner's own closure of a task whose repairs are used up is a reply without a model call: not an answer
    replies.retain(|r| r["call_id"].is_string());
    let last_reply: BTreeMap<String, String> =
        replies.iter().map(|r| (r["task"].as_str().unwrap_or("").to_string(), r["call_id"].as_str().unwrap_or("").to_string())).collect();
    // per answer: a row (skipped) or a job; per task the next of its WAL submissions not yet matched to an answer
    let mut rows: Vec<(usize, Value)> = Vec::new();
    let mut jobs: Vec<(usize, Job)> = Vec::new();
    let mut cursor: BTreeMap<String, usize> = BTreeMap::new();
    for (order, rec) in replies.iter().enumerate() {
        let (call, task, agent) = (rec["call_id"].as_str().unwrap(), rec["task"].as_str().unwrap_or(""), rec["agent"].as_str().unwrap_or(""));
        let ctx = contexts.get(call).cloned().unwrap_or(Value::Null);
        let key = ctx["key"].as_str().unwrap_or("").to_string();
        let mut row = json!({"call_id": call, "task": task, "kind": rec["kind"], "key": key, "phase": rec["phase"]});
        let mut skip = |mut row: Value, why: &str| {
            row["skipped"] = json!(why);
            rows.push((order, row));
        };
        let Some(kind) = rec["kind"].as_str().and_then(kind_of) else {
            skip(row, "not replayed: a link check");
            continue;
        };
        if rec["local"] == true || rec["lines_submitted"].is_null() {
            skip(row, "refused by the runner before the kernel");
            continue;
        }
        let Some(lines) = texts.get(call).map(String::as_str).and_then(answer_lines) else {
            skip(row, "the answer does not parse as submitted");
            continue;
        };
        if Some(lines.len() as u64) != rec["lines_submitted"].as_u64() {
            row["parsed"] = json!(lines.len());
            skip(row, "parsed lines differ from lines_submitted");
            continue;
        }
        // the state: up to this answer's own store submission, else up to the task's next one (or its closing, or the end)
        let task_subs = subs.get(task).map(Vec::as_slice).unwrap_or(&[]);
        let c = cursor.entry(task.to_string()).or_default();
        let old_accepted: Vec<String> = strings(&rec["reply"]["accepted"]);
        let n = if !old_accepted.is_empty() {
            let Some(j) = (*c..task_subs.len()).find(|j| task_subs[*j].accepted.iter().map(RecordId::short).collect::<Vec<_>>() == old_accepted) else {
                skip(row, "no WAL submission accepted these records");
                continue;
            };
            *c = j + 1;
            task_subs[j].n
        } else if let Some(sub) = task_subs.get(*c) {
            if sub.accepted.is_empty() {
                *c += 1;
            }
            sub.n
        } else {
            closed.get(task).copied().unwrap_or(wal.len())
        };
        if task_subs.is_empty() && kind != TaskKind::Summarize {
            skip(row, "the task has no store submission to take its lease from");
            continue;
        }
        // the records the task had stored by then, by local id
        let mut prior: BTreeMap<String, RecordId> = BTreeMap::new();
        let mut accepted_lines = Vec::new();
        row["state_boundary"] = json!(if old_accepted.is_empty() { "next_task_submission_or_close_upper_bound" } else { "matching_accepted_receipt" });
        for sub in task_subs.iter().filter(|x| x.n < n) {
            accepted_lines.extend(sub.lines.iter().take(sub.accepted.len()).cloned());
            for (l, r) in sub.locals.iter().zip(&sub.accepted) {
                if let Some(l) = l {
                    prior.insert(l.clone(), *r);
                }
            }
        }
        let job = Job {
            row,
            n,
            kind,
            key,
            task: task.to_string(),
            agent: agent.to_string(),
            lines,
            prior,
            accepted_lines,
            lease: task_subs.first().map(|sub| (sub.scope.clone(), sub.issued.clone())),
            prompt: ctx["prompt"].as_str().unwrap_or("").to_string(),
            reply: rec.clone(),
            last: last_reply.get(task).map(String::as_str) == Some(call),
        };
        jobs.push((order, job));
    }

    // one recovery pass over a copy of the WAL (the run's own file is never opened for writing), a state for each job in WAL order
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let scratch = std::env::temp_dir().join(format!("sbgk_step1_{}_{nonce}", std::process::id()));
    std::fs::create_dir(&scratch).unwrap();
    let copy = scratch.join("run.wal");
    std::fs::write(&copy, wal.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    jobs.sort_by_key(|(order, j)| (j.n, *order));
    let at: Vec<usize> = jobs.iter().map(|(_, j)| j.n).collect();
    let mut queue = jobs.into_iter();
    AuditState::replay_prefixes(
        &copy,
        &at,
        |n, k| scratch.join(format!("p{n}_{k}.wal")),
        |n, mut s| {
            let (order, job) = queue.next().expect("a job for each state");
            assert_eq!(job.n, n, "states come in the order of the jobs");
            rows.push((order, replay(job, &mut s, &questions)));
        },
    )
    .unwrap_or_else(|e| panic!("WAL: {e:?}"));

    rows.sort_by_key(|(order, _)| *order);
    let mut out = std::io::BufWriter::new(std::fs::File::create(&out_path).unwrap());
    writeln!(
        out,
        "{}",
        json!({"meta": {"run": run.file_name().map(|x| x.to_string_lossy().to_string()), "wal_entries": wal.len(),
                                         "answers": replies.len(), "revision": option_env!("SBGK_REVISION")}})
    )
    .unwrap();
    for (_, row) in rows {
        writeln!(out, "{row}").unwrap();
    }
    out.flush().unwrap();
    // Preserve private replay snapshots as evidence. Never recursively delete a computed TEMP path.
}

/// One answer through the current dispatcher on its state: the row of what the recorded kernel and the current one did with it.
fn replay(job: Job, s: &mut AuditState, questions: &[ResearchQuestion]) -> Value {
    let Job { mut row, n, kind, key, task, agent, lines, prior, accepted_lines, lease, prompt, reply: rec, last } = job;
    let (scope, issued) = lease.unwrap_or_else(|| {
        // a summary that never reached the store: the records its directive showed
        let block = prompt.split_once("RECORDS:\n").map_or("", |x| x.1);
        let block = block.split_once("\nACCEPTED LINKS:").map_or(block, |x| x.0);
        let shown: BTreeSet<&str> = block.split(|c: char| !(c.is_ascii_hexdigit() || c == '@')).filter(|t| t.len() == 17 && t.starts_with('@')).collect();
        let all: Vec<RecordId> = s.records_since(0).iter().map(|r| r.id).filter(|r| shown.contains(r.short().as_str())).collect();
        row["issued_from_prompt"] = json!(all.len());
        (Scope::default(), all)
    });
    let mut d = Dispatcher::new(DispatchConfig::default(), questions.to_vec());
    d.replay_lease(&task, &agent, kind, &key, scope, issued, prior.clone(), &accepted_lines);
    let r = d.submit(s, &task, &agent, &lines, 0);

    // the recorded outcome, line by line
    let old_accepted: Vec<String> = strings(&rec["reply"]["accepted"]);
    let old_stored: BTreeSet<String> = rec["reply"]["accepted_locals"].as_object().map_or_else(BTreeSet::new, |m| m.keys().cloned().collect());
    let mut problems: BTreeMap<u64, (Vec<&'static str>, Option<String>)> = BTreeMap::new();
    for p in rec["reply"]["problems"].as_array().into_iter().flatten() {
        if let Some(i) = p["line"].as_u64() {
            let (rules, lead) = rules_of(p);
            let e = problems.entry(i).or_default();
            e.0.extend(rules);
            e.1 = e.1.take().or(lead);
        }
    }
    let new = new_outcomes(&r, &lines, &prior);
    let per_line: Vec<Value> = lines
        .iter()
        .enumerate()
        .zip(&new)
        .map(|((i, v), now)| {
            let local = v["local_id"].as_str().unwrap_or("");
            let old = if prior.contains_key(local) {
                "resent"
            } else if old_stored.contains(local) {
                "stored"
            } else {
                "lost"
            };
            let (rules, lead) = problems.get(&(i as u64)).cloned().unwrap_or_default();
            let mut x = json!({"i": i, "local_id": local, "line_kind": v["kind"], "old": old, "new": now});
            if !rules.is_empty() {
                x["old_rules"] = json!(rules);
            }
            if let Some(lead) = lead {
                x["old_negation_lead"] = json!(lead);
            }
            if v["kind"] == "observe" {
                x["doc_id"] = v["doc_id"].clone();
                x["quote"] = v["exact_quote"].clone();
            }
            x
        })
        .collect();
    row["wal_index"] = json!(n);
    row["lines"] = json!(lines.len());
    row["old"] = json!({"status": rec["status"], "accepted": old_accepted.len(), "failed_index": rec["failed_index"], "code": rec["code"],
                        "message": rec["message"]});
    row["new"] = json!({"status": r["status"], "repair_scope": r["repair_scope"], "stored": r["accepted"].as_array().map_or(0, Vec::len),
                        "refused": r["refused"].as_array().map_or(0, Vec::len), "excluded": r["excluded"].as_array().map_or(0, Vec::len),
                        "extended": r["extended"], "error": r["error"]["code"]});
    row["per_line"] = json!(per_line);

    // a summary whose lines are still refused when the run's repairs were used up: the runner's partial delivery
    if kind == TaskKind::Summarize && r["status"] == "REPAIR_REQUIRED" && last {
        let mut stored: Vec<String> = r["accepted_locals"].as_object().map_or_else(Vec::new, |m| m.keys().cloned().collect());
        stored.extend(prior.keys().cloned());
        stored.sort();
        stored.dedup();
        let prefix = lines.iter().find_map(|v| v["local_id"].as_str().and_then(|l| l.split_once('_')).map(|(p, _)| format!("{p}_"))).unwrap_or_default();
        let done = if stored.is_empty() {
            json!({"kind": "done", "local_id": format!("{prefix}d9"), "rq_id": &key[3..], "directive_id": task, "outcome": "unknown", "answer_ids": []})
        } else {
            json!({"kind": "done", "local_id": format!("{prefix}d9"), "rq_id": &key[3..], "directive_id": task, "outcome": "answered",
                   "answer_ids": stored,
                   "text": format!("Partial answer: {} lines were stored; the lines still refused after the repairs are left out.", stored.len())})
        };
        let f = d.submit(s, &task, &agent, &[done], 0);
        row["fallback"] = json!({"status": f["status"], "answer_ids": stored.len(), "error": f["error"]["code"]});
    }
    row
}
