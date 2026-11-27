//! `sbgk audit-stream`: a journal that takes its sources as they come (0.3.0, rules 4), written one step at a time without a
//! server. One agent keeps one journal: `start` writes a genesis without a document, `put` adds a source or a new version of
//! one, `submit` adds records over the sources its lines quote, `checkpoint` writes a context checkpoint before the agent's context is
//! compacted, `withdraw` takes back a quote or a text for a reason that is itself a source, `seal` and `close` end the run as
//! the server's do. Each step opens the journal as a resumed server would (every frame checked), writes one entry and prints one
//! JSON document. `audit-read key`, `keys` and `checkpoint` read the journal back; `audit-verify` checks it.

use super::{fail, read, Args};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::{AuditState, GenesisSpec, RecordState};
use sbgk_core::audit::{AuditStore, RecordId};
use sbgk_core::error::KernelError;
use sbgk_core::hash::{from_hex, sha256, to_hex};
use serde_json::{json, Value};
use std::path::Path;

const STEPS: &str = "start, put, submit, checkpoint, withdraw, seal or close";

fn refused(wal: &str, step: &str, error: &KernelError) -> ! {
    println!("{}", json!({"status": "REFUSED", "step": step, "wal": wal, "error": error.to_json()}));
    std::process::exit(1)
}

/// A file of JSON values: one array, or one value a line.
pub(super) fn json_lines(path: &str, flag: &str) -> Vec<Value> {
    let text = String::from_utf8(read(path)).unwrap_or_else(|_| fail(&format!("--{flag} {path}: not UTF-8")));
    if let Ok(Value::Array(values)) = serde_json::from_str::<Value>(&text) {
        return values;
    }
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(n, line)| serde_json::from_str(line).unwrap_or_else(|e| fail(&format!("--{flag} {path}: line {} is not JSON: {e}", n + 1))))
        .collect()
}

/// A record named by its whole id or by its short form `@` and sixteen digits.
pub(super) fn record_named(state: &AuditState, name: &str) -> RecordId {
    let whole = from_hex(name.trim_start_matches('@')).map(RecordId).filter(|id| state.record(id).is_some());
    whole.or_else(|| state.record_by_short(name)).unwrap_or_else(|| fail(&format!("{name} names no record of this journal")))
}

pub fn cmd_audit_stream(a: &Args) {
    let step = a.pos(0, &format!("the step: {STEPS}"));
    let wal = a.req("wal");
    let actor = a.get("actor").unwrap_or("owner").to_string();
    if step == "start" {
        if std::fs::metadata(&wal).map(|m| m.len() > 0).unwrap_or(false) {
            fail(&format!("{wal} already holds a run: its sources are added with `audit-stream put`"));
        }
        let base = match a.get("base-ontology") {
            Some(path) => serde_json::from_slice(&read(path)).unwrap_or_else(|e| fail(&format!("--base-ontology {path}: not JSON: {e}"))),
            None => AuditOntology::base(),
        };
        let mut state = AuditState::prepare_from_docs(&base, &a.req("run-id"), Vec::new()).unwrap_or_else(|e| refused(&wal, &step, &e));
        if let Some(rules) = a.get("rules") {
            state.set_rules_version(rules).unwrap_or_else(|e| refused(&wal, &step, &e));
        }
        state.start_journal(Path::new(&wal), &GenesisSpec::default()).unwrap_or_else(|e| refused(&wal, &step, &e));
        return finish(a, &state, json!({"status": "STARTED", "run_id": state.run_id(), "rules_version": state.rules_version(), "documents": 0}));
    }
    super::audit_mcp::refuse_locked_whole(&wal);
    let mut state = AuditState::open(Path::new(&wal)).unwrap_or_else(|e| refused(&wal, &step, &e));
    if !state.is_v3() {
        fail(&format!("{wal} is a journal of the 0.1 format: audit-stream writes the 0.2 format only"));
    }
    let out = match step.as_str() {
        "put" => {
            let (doc, bytes) = (a.req("doc-id"), read(&a.req("file")));
            let known = state.source_document(&doc).is_some();
            state.put_document(&actor, &doc, &bytes).unwrap_or_else(|e| refused(&wal, &step, &e));
            json!({"status": "PUT", "doc_id": doc, "bytes": bytes.len(), "raw_sha256": to_hex(&sha256(&bytes)), "new_version_of_a_known_document": known,
                   "documents": state.source_document_count()})
        }
        "submit" => {
            let lines = json_lines(&a.req("lines"), "lines");
            // the documents the lines need and no other (`scope_of_lines`): a scope takes a bounded number of documents, and a
            // journal that takes its sources as they come soon has more than that (Codex review of b27625da, finding 1)
            let task = a.req("task");
            let scope = state.scope_of_lines(&actor, &task, &lines);
            let id = format!("stream-{}", state.entries().unwrap_or(0));
            let report = state.submit_records_id(&id, &actor, &task, &scope, &lines);
            let accepted: Vec<String> = report.accepted.iter().map(|r| to_hex(&r.0)).collect();
            match &report.error {
                None => json!({"status": "COMMITTED", "accepted": accepted}),
                // the lines before the refused one are stored: only the lines from it on are sent again
                Some(error) => {
                    json!({"status": "REPAIR_REQUIRED", "accepted": accepted, "failed_index": report.failed_index, "error": error.to_json()})
                }
            }
        }
        "checkpoint" => {
            let records: Vec<RecordId> = match a.get("records") {
                Some(path) => json_lines(path, "records")
                    .iter()
                    .map(|v| record_named(&state, v.as_str().unwrap_or_else(|| fail("--records: a file of record ids, each a JSON string"))))
                    .collect(),
                // without a list: every claim that is active now
                None => state.claims_with_states().into_iter().filter(|(_, s)| *s == RecordState::Active).map(|(r, _)| r.id).collect(),
            };
            let sources: Vec<String> = match a.get("sources") {
                Some(list) => list.split(',').map(str::trim).filter(|d| !d.is_empty()).map(str::to_string).collect(),
                None => state.docs(),
            };
            let manifest =
                a.get("manifest").map(|path| serde_json::from_slice(&read(path)).unwrap_or_else(|e| fail(&format!("--manifest {path}: not JSON: {e}"))));
            let written = state.context_checkpoint(&actor, &records, &sources, a.get("raw-context"), manifest).unwrap_or_else(|e| refused(&wal, &step, &e));
            json!({"status": "CHECKPOINTED", "checkpoint": written["checkpoint"], "epoch": written["epoch"], "cursor": written["cursor"],
                   "listed": records.len(), "sources": sources.len()})
        }
        "withdraw" => {
            let reason = a.req("reason-source-id");
            let also = match (a.get("record"), a.get("doc-id")) {
                (Some(record), None) => state.revoke_observation_for(&actor, &record_named(&state, record), &reason),
                (None, Some(doc)) => {
                    let text = match (a.get("exact-quote"), a.get("file")) {
                        (Some(text), None) => text.to_string(),
                        (None, Some(path)) => String::from_utf8(read(path)).unwrap_or_else(|_| fail(&format!("--file {path}: not UTF-8"))),
                        _ => fail("withdraw --doc-id takes the text as --exact-quote, or as the bytes of --file"),
                    };
                    state.withdraw_text_for(&actor, doc, &text, &reason)
                }
                _ => fail("withdraw takes --record <id> of an observation, or --doc-id <id> with the text"),
            };
            json!({"status": "WITHDRAWN", "also_revoked": also.unwrap_or_else(|e| refused(&wal, &step, &e)), "reason_source_id": reason})
        }
        "seal" => state.seal().map(|seal| json!({"status": "SEALED", "seal": seal})).unwrap_or_else(|e| refused(&wal, &step, &e)),
        "close" => state.close_run().map(|closed| json!({"status": "CLOSED", "close": closed})).unwrap_or_else(|e| refused(&wal, &step, &e)),
        other => fail(&format!("unknown step '{other}': {STEPS}")),
    };
    let repair = out["status"] == "REPAIR_REQUIRED";
    finish(a, &state, out);
    if repair {
        std::process::exit(1);
    }
}

/// The answer of a step with where the journal stands after it.
fn finish(a: &Args, state: &AuditState, mut out: Value) {
    out["entries"] = json!(state.entries());
    out["records"] = json!(state.head());
    out["audit_root"] = json!(to_hex(&state.audit_root()));
    out["wal_head"] = json!(state.wal_head().map(|h| to_hex(&h)));
    if a.sw("pretty") {
        println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
    } else {
        println!("{out}");
    }
}
