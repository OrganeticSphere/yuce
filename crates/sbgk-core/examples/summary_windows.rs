//! What the SUMMARIZE task of a closed run shows, offline (registry R30, step 2). Read-only on the archive: the journal is
//! copied (whole, or up to the first revoke with --phase1) into a fresh scratch directory and opened there. With --answer-status,
//! also what the reader of the answers is told about the time of every summary claim (registry R34a), in answer_status.json.
//! With --companions (and --temporal), a summary claim also brings the later claim it is most like by words (summary_companions).
//! usage: summary_windows <run dir> <out dir> [--phase1 | --frames N] [--temporal [--companions]] [--answer-status]
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, LinkStatus};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn questions(run: &std::path::Path) -> Vec<ResearchQuestion> {
    let q: Value = serde_json::from_slice(&std::fs::read(run.join("arm_c/questions.json")).unwrap()).unwrap();
    let rows = q.as_array().or_else(|| q["questions"].as_array()).expect("question array");
    let strings = |v: &Value| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    rows.iter()
        .map(|q| ResearchQuestion {
            id: q["id"].as_str().unwrap().into(),
            text: q["text"].as_str().unwrap().into(),
            about: strings(&q["about"]),
            stances: strings(&q["stances"]),
            relations: strings(&q["relations"]),
            concept_types: strings(&q["concept_types"]),
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (run, out) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let phase1 = args.iter().any(|a| a == "--phase1");
    std::fs::create_dir_all(&out).unwrap();
    let raw = std::fs::read(run.join("arm_c/run.wal")).unwrap();
    let lines: Vec<&[u8]> = raw.split_inclusive(|b| *b == b'\n').collect();
    let first_revoke = lines
        .iter()
        .position(|l| serde_json::from_slice::<Value>(l).is_ok_and(|e| matches!(e["payload"]["command"]["kind"].as_str(), Some("revoke" | "revoke_text"))));
    // --frames N: the first N frames, e.g. the state before a summary's first answer line was stored
    let frames = args.iter().position(|a| a == "--frames").map(|i| args[i + 1].parse::<usize>().expect("--frames N"));
    let take = frames.unwrap_or(if phase1 { first_revoke.unwrap_or(lines.len()) } else { lines.len() }).min(lines.len());
    let copy = std::env::temp_dir().join(format!("summary_windows_{}_{}.wal", std::process::id(), out.file_name().unwrap().to_string_lossy()));
    std::fs::write(&copy, lines[..take].concat()).unwrap();
    let started = std::time::Instant::now();
    let mut state = AuditState::open(&copy).expect("recovery of the copied journal");
    let opened_s = started.elapsed().as_secs_f64();
    if args.iter().any(|a| a == "--temporal") {
        // the copy only: the same state with registry R30 step 2 switched on in its pinned graph-quality policy
        let mut ck = state.checkpoint("audit:mcp:coverage").expect("a coverage checkpoint");
        ck["context"]["graph_quality"]["temporal_summary"] = json!(true);
        if args.iter().any(|a| a == "--companions") {
            ck["context"]["graph_quality"]["summary_companions"] = json!(true);
        }
        let r = state
            .submit_operations_id(
                "offline-temporal-summary",
                "kernel",
                &[],
                Some(json!({"key":"audit:mcp:coverage","from":ck["from"],"to":ck["to"],"context":ck["context"]})),
            )
            .unwrap();
        assert_eq!(r["checkpointed"], true, "{r}");
    }
    let mut d = Dispatcher::new(DispatchConfig { section_bytes: 6000, ..Default::default() }, questions(&run));
    d.recover(&state);
    let usable = state.usable_links();
    let mut rels = BTreeMap::<String, usize>::new();
    for l in state.links().into_iter().filter(|l| l.status == LinkStatus::Accepted && usable.contains(&l.id)) {
        *rels.entry(l.rel).or_default() += 1;
    }
    let diag = d.offline_diagnostics(&state);
    let mut rows = serde_json::Map::new();
    for (rq, w) in diag["summary_windows"].as_object().unwrap() {
        std::fs::write(out.join(format!("{rq}_prompt.txt")), w["prompt"].as_str().unwrap()).unwrap();
        let sup = w["superseded_old_shown"].as_array().unwrap();
        rows.insert(
            rq.clone(),
            json!({"eligible":w["eligible"].as_array().unwrap().len(),"issued":w["issued"].as_array().unwrap().len(),
            "superseded_old_shown":sup.len(),"superseded_new_not_shown":sup.iter().filter(|x|x["new_shown"]==false).count(),
            "one_sided_conflicts":w["one_sided_conflicts"].as_array().unwrap().len(),
            "temporal_warnings":w["prompt"].as_str().unwrap().contains("TEMPORAL WARNINGS"),"prompt_chars":w["prompt"].as_str().unwrap().len()}),
        );
    }
    let summary = json!({"run":run.file_name().unwrap().to_string_lossy(),"phase1":phase1,"temporal":args.iter().any(|a| a == "--temporal"),"frames":take,"records":state.head(),
        "opened_s":opened_s,"accepted_usable_links_by_rel":rels,"windows":rows});
    std::fs::write(out.join("summary.json"), serde_json::to_string_pretty(&summary).unwrap()).unwrap();
    println!("{summary}");
    if args.iter().any(|a| a == "--answer-status") {
        let records = state.records_since(0);
        let text = records.iter().map(|r| (r.id.short(), r.text.clone())).collect::<BTreeMap<_, _>>();
        let claims = records
            .iter()
            .filter(|r| r.kind.name() == "claim" && sbgk_core::audit::directives::is_summary_directive(&r.directive))
            .map(|r| {
                let warnings = sbgk_core::audit::quality::stale::answer_warnings(&state, r.id);
                let mut status = sbgk_core::audit::quality::stale::answer_status(&state, r.id, !warnings.is_empty());
                // the two states in words, for whoever checks the mark
                for key in ["replaced", "earlier_and_later"] {
                    for x in status[key].as_array_mut().into_iter().flatten() {
                        for side in ["earlier", "later"] {
                            x[format!("{side}_text")] = json!(x[side].as_str().and_then(|s| text.get(s)));
                        }
                    }
                }
                json!({"short":r.id.short(),"directive":r.directive,"grounded":state.is_grounded(&r.id),"text":r.text,"answer_status":status})
            })
            .collect::<Vec<_>>();
        std::fs::write(out.join("answer_status.json"), serde_json::to_string_pretty(&claims).unwrap()).unwrap();
    }
    drop(state);
    let _ = std::fs::remove_file(&copy);
}
