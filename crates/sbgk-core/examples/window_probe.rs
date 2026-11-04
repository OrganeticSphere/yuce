//! What the quarantine of proposed mappings would take out of the summary windows of a recorded run (the owner's decision of
//! 2026-10-23: measure before turning it on). Reads a WAL up to its first summary, never calls a model.
//!
//!     cargo run --release -p sbgk-core --example window_probe -- <run.wal> <questions.json>

use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId};
use serde_json::{json, Value};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (wal, questions) = (&args[1], &args[2]);
    // the state the first summary saw: every frame before the first summary task's
    let lines: Vec<String> = std::fs::read_to_string(wal).expect("the WAL").lines().map(str::to_string).collect();
    let first_summary = lines
        .iter()
        .position(|l| {
            let v: Value = serde_json::from_str(l).unwrap_or(Value::Null);
            v["payload"]["command"]["directive"].as_str().is_some_and(|d| d.starts_with("TS"))
        })
        .unwrap_or(lines.len());
    let prefix = std::env::temp_dir().join(format!("sbgk_window_probe_{}.jsonl", std::process::id()));
    std::fs::write(&prefix, lines[..first_summary].join("\n") + "\n").expect("a prefix copy");
    let s = AuditState::open(&prefix).expect("the prefix opens");
    let _ = std::fs::remove_file(&prefix);
    let qs: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(questions).expect("the questions")).expect("json");
    let strings =
        |v: &Value, k: &str| -> Vec<String> { v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default() };
    let rqs: Vec<ResearchQuestion> = qs
        .iter()
        .map(|q| ResearchQuestion {
            id: q["id"].as_str().unwrap_or_default().into(),
            text: q["text"].as_str().unwrap_or_default().into(),
            about: strings(q, "about"),
            stances: strings(q, "stances"),
            relations: strings(q, "relations"),
            concept_types: strings(q, "concept_types"),
        })
        .collect();
    let d = Dispatcher::new(DispatchConfig::default(), rqs.clone());
    let doc_of = |id: &RecordId| -> Option<String> {
        let r = s.record(id)?;
        r.based_on.iter().find_map(|b| s.record(b).and_then(|o| o.doc_id))
    };
    let mut out = Vec::new();
    for q in &rqs {
        let (window, chosen) = d.summary_candidates(&s, &q.id, true).expect("the question");
        let (window_q, chosen_q) = d.summary_candidates(&s, &q.id, false).expect("the question");
        let only_mapped: Vec<Value> = chosen
            .difference(&chosen_q)
            .map(|id| {
                let r = s.record(id).expect("a record");
                json!({"id": id.short(), "in_window": window.contains(id), "doc": doc_of(id), "text": r.text.unwrap_or_default().chars().take(140).collect::<String>()})
            })
            .collect();
        let docs = |ids: &[RecordId]| ids.iter().filter_map(doc_of).collect::<std::collections::BTreeSet<String>>().len();
        out.push(json!({"rq": q.id, "frames_before_first_summary": first_summary, "chosen": chosen.len(), "chosen_without_mappings": chosen_q.len(),
                        "window": window.len(), "window_without_mappings": window_q.len(), "window_docs": docs(&window), "window_docs_without_mappings": docs(&window_q),
                        "only_via_mappings": only_mapped}));
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
