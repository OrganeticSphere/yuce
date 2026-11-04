//! Offline replay of a recorded live run through the current kernel ($0, no models): the state at each recorded answer is the
//! run's own WAL up to that answer, so every record id is the run's. For each swarm submission the store's outcome is compared with
//! the recorded one, and for a refused one the read-only diagnostics of the lines not taken are checked line by line against the
//! store (each line submitted alone, in order). For each builder card the recorded first answer is submitted to a builder with the
//! run's operation limit and with the current one.
//!
//! cargo run --release --example replay_wal -- <run dir with arm_c/run.wal and journal.jsonl> <out.jsonl> [all|builder|swarm FROM TO]
//!
//! Each prefix replays the journal from its start, so both parts can run in shards of WAL entries [FROM, TO) side by side (a card
//! belongs to the shard of its first submission). The first output row names the shard and the revision the tool was built from
//! (`SBGK_REVISION` at build time). A swarm row compares the store's outcome (accepted ids, failed index, the whole error) and the
//! audit and engine roots after the submission with the recorded ones. The builder's parser keeps the answer's JSON lines and drops
//! the rest: it is not an oracle of the runner's strict answer parsing.

use sbgk_core::audit::builder::{Builder, BuilderConfig};
use sbgk_core::audit::directives::unstored_problems;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::from_hex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The run's WAL up to (not including) entry `n`, opened as a store of its own.
fn prefix(wal: &[String], n: usize, scratch: &Path) -> AuditState {
    let path = scratch.join(format!("prefix_{n}.wal"));
    std::fs::write(&path, wal[..n].iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    AuditState::open(&path).unwrap_or_else(|e| panic!("prefix {n}: {e:?}"))
}

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

/// What the store said to one submission: accepted ids, failed index, error code and message.
fn outcome(accepted: &[String], failed: Option<u64>, code: Option<&str>, message: Option<&str>) -> Value {
    json!({"accepted": accepted, "failed_index": failed, "code": code, "message": message})
}

/// Whether a diagnostic names the reason the store gave: the store's own quote error, a basis that is no quote, or a bound.
fn same_reason(diagnostic: &Value, code: &str, message: &str) -> bool {
    if let Some(e) = diagnostic.get("error") {
        return e["code"] == code && e["message"] == message;
    }
    if diagnostic.get("not_observes").is_some() {
        return code == "NOT_AN_EVIDENCE";
    }
    let needs = diagnostic["needs"].as_str().unwrap_or("");
    (needs.starts_with("based_on:") && message.starts_with("'based_on' must contain"))
        || (needs.starts_with("text of") && message.starts_with("'text' is empty or exceeds"))
}

/// A refusal of a kind the diagnostics name: a quote or its document, a basis that is no quote, a bound the parser checks.
fn named_class(code: &str, message: &str) -> bool {
    matches!(code, "QUOTE_NOT_FOUND_IN_BYTES" | "AMBIGUOUS_QUOTE_SPAN" | "NOT_AN_EVIDENCE")
        || (code == "BAD_FIELD"
            && (message == "document is outside the directive"
                || message == "quote is outside the issued byte ranges"
                || message.starts_with("'based_on' must contain")
                || message.starts_with("'text' is empty or exceeds")))
}

fn swarm(wal: &[String], range: std::ops::Range<usize>, scratch: &Path, out: &mut impl Write) {
    // the local ids each task got accepted so far, by (actor, directive)
    let mut locals: BTreeMap<(String, String), BTreeMap<String, RecordId>> = BTreeMap::new();
    for (n, raw) in wal.iter().enumerate() {
        let e: Value = serde_json::from_str(raw).unwrap();
        let p = &e["payload"];
        let cmd = &p["command"];
        if cmd["kind"] != "submit" {
            continue;
        }
        let (sid, actor, directive) = (p["submission_id"].as_str().unwrap(), p["actor"].as_str().unwrap(), cmd["directive"].as_str().unwrap());
        let lines: Vec<Value> = cmd["lines"].as_array().unwrap().clone();
        let scope = scope_of(&cmd["scope"]);
        let issued: Vec<RecordId> = cmd["allowed_records"].as_array().unwrap().iter().map(id).collect();
        let res = &p["outcome"]["result"];
        let rec_accepted: Vec<String> = res["accepted"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let recorded = outcome(&rec_accepted, res["failed_index"].as_u64(), res["error"]["code"].as_str(), res["error"]["message"].as_str());
        if n >= range.end {
            break;
        }
        if n < range.start {
            // before this shard: what the task got accepted is read from the record, not replayed
            let task = locals.entry((actor.to_string(), directive.to_string())).or_default();
            for (v, r) in lines.iter().zip(&rec_accepted) {
                if let Some(name) = v["local_id"].as_str() {
                    task.insert(name.to_string(), id(&json!(r)));
                }
            }
            continue;
        }

        let mut s = prefix(wal, n, scratch);
        let rep = s.submit_scoped_records_id(sid, actor, directive, &scope, &issued, &lines);
        let accepted: Vec<String> = rep.accepted.iter().map(|r| sbgk_core::hash::to_hex(&r.0)).collect();
        let err = rep.error.as_ref().map(|e| e.to_json());
        let replayed = outcome(
            &accepted,
            rep.failed_index.map(|i| i as u64),
            err.as_ref().and_then(|e| e["code"].as_str()),
            err.as_ref().and_then(|e| e["message"].as_str()),
        );
        let task = locals.entry((actor.to_string(), directive.to_string())).or_default();
        for (v, r) in lines.iter().zip(&rep.accepted) {
            if let Some(name) = v["local_id"].as_str() {
                task.insert(name.to_string(), *r);
            }
        }
        // the whole error and the roots after the submission, not only the projected outcome
        let same_error = res["error"] == err.clone().unwrap_or(Value::Null);
        let roots = [sbgk_core::hash::to_hex(&s.root()), sbgk_core::hash::to_hex(&s.engine_root())];
        let same_roots = p["audit_root"] == roots[0] && p["engine_root"] == roots[1];
        let mut row = json!({"wal_index": n, "submission": sid, "actor": actor, "directive": directive, "lines": lines.len(),
                             "recorded": recorded, "replayed": replayed, "same": recorded == replayed, "same_error": same_error,
                             "same_roots": same_roots});
        if let Some(f) = rep.failed_index {
            let unstored: Vec<(usize, Value)> = lines.iter().cloned().enumerate().skip(f).collect();
            let shown: Vec<RecordId> = task.values().copied().chain(issued.iter().copied()).collect();
            let problems = unstored_problems(&s, &scope, task, &shown, &lines, &unstored);
            // the store's own verdict on each line not taken, each submitted alone and in order
            let mut per_line = Vec::new();
            for (j, line) in &unstored {
                let r = s.submit_scoped_records_id(&format!("{sid}#replay{j}"), actor, directive, &scope, &issued, std::slice::from_ref(line));
                let store = r.error.as_ref().map(|e| e.to_json());
                let flagged: Vec<&Value> = problems.iter().filter(|p| p["line"].as_u64() == Some(*j as u64)).collect();
                let (code, message) = store.as_ref().map_or(("", ""), |e| (e["code"].as_str().unwrap_or(""), e["message"].as_str().unwrap_or("")));
                let verdict = match (flagged.is_empty(), store.is_none()) {
                    (false, true) => "FALSE_ALARM",
                    (false, false) => "NAMED",
                    (true, false) if named_class(code, message) => "MISSED",
                    (true, false) => "OTHER_REFUSAL",
                    (true, true) => "ACCEPTED",
                };
                let reason = (verdict == "NAMED").then(|| flagged.iter().any(|d| same_reason(d, code, message)));
                per_line.push(json!({"line": j, "kind": line["kind"], "local_id": line["local_id"], "verdict": verdict, "same_reason": reason,
                                     "store": store.map(|e| json!({"code": e["code"], "message": e["message"]})),
                                     "diagnostics": flagged}));
            }
            row["per_line"] = json!(per_line);
        }
        writeln!(out, "{row}").unwrap();
        drop(s);
        let _ = std::fs::remove_file(scratch.join(format!("prefix_{n}.wal")));
    }
}

/// `B<phase>-<card id>-<attempt>` → the card id and the attempt.
fn card_of(call_id: &str) -> Option<(String, u64)> {
    let rest = call_id.strip_prefix('B')?.split_once('-')?.1;
    let (card, attempt) = rest.rsplit_once('-')?;
    Some((card.to_string(), attempt.parse().ok()?))
}

fn builder(wal: &[String], range: std::ops::Range<usize>, journal: &Path, scratch: &Path, out: &mut impl Write) {
    let mut first: BTreeMap<String, String> = BTreeMap::new();
    for raw in std::fs::read_to_string(journal).unwrap().lines() {
        let e: Value = serde_json::from_str(raw).unwrap();
        if e["kind"] != "call" {
            continue;
        }
        let c = &e["record"];
        if let Some((card, 0)) = c["call_id"].as_str().and_then(card_of) {
            first.insert(card, c["text"].as_str().unwrap_or("").to_string());
        }
    }
    for (card_id, text) in &first {
        let Some(n) = wal.iter().position(|raw| {
            let e: Value = serde_json::from_str(raw).unwrap();
            e["payload"]["submission_id"].as_str().is_some_and(|s| s.starts_with(&format!("{card_id}:")))
        }) else {
            if range.start == 0 {
                writeln!(out, "{}", json!({"card": card_id, "error": "no submission of this card in the WAL"})).unwrap();
            }
            continue;
        };
        if !range.contains(&n) {
            continue;
        }
        let ops: Vec<Value> = text.lines().map(str::trim).filter(|l| l.starts_with('{')).filter_map(|l| serde_json::from_str(l).ok()).collect();
        let mut row = json!({"card": card_id, "wal_index": n, "ops": ops.len()});
        let mut s = prefix(wal, n, scratch);
        for max_ops in [32usize, 64] {
            // an answer within both limits gets the same answer from both; one over the run's limit wrote nothing, so the same
            // prefix serves the current limit too
            if max_ops == 64 && ops.len() <= 32 {
                row["max_ops_64"] = row["max_ops_32"].clone();
                row["max_ops_64"]["copied_from_32"] = json!(true);
                continue;
            }
            let mut b = Builder::new(BuilderConfig { max_ops, ..Default::default() });
            b.recover(&s);
            let card = b.next_card(&s).expect("the card is open again");
            // the links the answer adds: each one is a verification task of the swarm
            let before = s.links().len();
            let r = b.submit(&mut s, &card.card_id, &ops);
            let link_ops = ops.iter().filter(|o| matches!(o["op"].as_str(), Some("link" | "mark_duplicate" | "flag_conflict"))).count();
            row[format!("max_ops_{max_ops}")] = json!({"same_card": &card.card_id == card_id, "records": card.records.len(), "status": r["status"],
                "code": r["code"].as_str().or(r["error"]["code"].as_str()), "accepted": r["accepted"], "refused": r["refused"].as_array().map(Vec::len),
                "committed_ops": r["committed_ops"], "link_ops": link_ops, "links_made": s.links().len() - before});
        }
        drop(s);
        let _ = std::fs::remove_file(scratch.join(format!("prefix_{n}.wal")));
        writeln!(out, "{row}").unwrap();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (run, out_path) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let wal: Vec<String> = std::fs::read_to_string(run.join("arm_c").join("run.wal")).unwrap().lines().map(str::to_string).collect();
    let scratch = std::env::temp_dir().join(format!("sbgk_replay_{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let mut out = std::io::BufWriter::new(std::fs::File::create(&out_path).unwrap());
    let what = args.get(3).map_or("all", String::as_str);
    let bound = |i: usize, default: usize| args.get(i).map_or(default, |x| x.parse().expect("a WAL entry index"));
    let range = bound(4, 0)..bound(5, wal.len());
    let meta = json!({"mode": what, "range": [range.start, range.end], "wal_entries": wal.len(), "revision": option_env!("SBGK_REVISION")});
    writeln!(out, "{}", json!({ "meta": meta })).unwrap();
    if what != "builder" {
        swarm(&wal, range.clone(), &scratch, &mut out);
    }
    if what != "swarm" {
        builder(&wal, range, &run.join("journal.jsonl"), &scratch, &mut out);
    }
    out.flush().unwrap();
    let _ = std::fs::remove_dir_all(&scratch);
}
