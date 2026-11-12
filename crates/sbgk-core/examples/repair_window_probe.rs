//! The repair window of a recorded run after a withdrawal, offline ($0, no model). The journal is read and never written: every
//! frame is replayed by the current kernel (the check of `sbgk audit-verify`), and on the state of its first N frames the
//! dispatcher is recovered and builds the SUMMARIZE window of a question as a repair task would get it now. The probe names the
//! quotes of that window from reports whose label holds a given text and, given the frame of the recorded repair's first answer,
//! the same of the window recorded there (that frame's `allowed_records`).
//!
//!     cargo run --release -p sbgk-core --example repair_window_probe -- <run.wal> <questions.json> <N> <RQ> <label text> [<answer frame>]
//!         [--quote-has <text>] [--prompt <file>]
//!
//! Frames count the journal's lines from 1, the genesis included: N is the withdrawal's own line. With --quote-has only the quotes
//! holding that text (any case) count, and every standing quote of the named reports that holds it is listed with the windows
//! that show it.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordKind, RecordView};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn questions(path: &str) -> Vec<ResearchQuestion> {
    let q: Value = serde_json::from_slice(&std::fs::read(path).expect("the questions")).expect("json");
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

/// The ids a frame's submit command allowed its answer to cite, short.
fn recorded_window(wal: &PathBuf, frame: usize) -> BTreeSet<String> {
    let text = std::fs::read_to_string(wal).expect("the journal");
    let line = text.lines().nth(frame - 1).expect("the answer frame");
    let v: Value = serde_json::from_str(line).expect("a frame");
    let cmd = &v["body"]["command"];
    assert_eq!(cmd["kind"], "submit", "frame {frame} is no submission");
    cmd["allowed_records"].as_array().expect("an issued window").iter().map(|x| format!("@{}", &x.as_str().unwrap()[..16])).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let wal = PathBuf::from(&args[1]);
    let qs = questions(&args[2]);
    let at: usize = args[3].parse().expect("N");
    let (rq, label) = (args[4].clone(), args[5].clone());
    let answer_frame: Option<usize> = args.get(6).filter(|a| !a.starts_with("--")).map(|a| a.parse().expect("the answer frame"));
    let prompt_out = args.iter().position(|a| a == "--prompt").map(|i| PathBuf::from(&args[i + 1]));
    let has = args.iter().position(|a| a == "--quote-has").map(|i| args[i + 1].to_lowercase()).unwrap_or_default();
    let recorded = answer_frame.map(|f| recorded_window(&wal, f));
    let mut out = Value::Null;
    let (_, read) = AuditState::verify_states(&wal, &mut |n, s, _| {
        if n != at {
            return;
        }
        let mut d = Dispatcher::new(DispatchConfig::default(), qs.clone());
        d.recover(s);
        let w = d.offline_diagnostics(s)["summary_windows"][&rq].clone();
        let prompt = w["prompt"].as_str().expect("a window").to_string();
        let records: BTreeMap<String, RecordView> = s.records_since(0).into_iter().map(|r| (r.id.short(), r)).collect();
        let named = |r: &RecordView| {
            r.kind == RecordKind::Observe
                && r.doc_id.as_deref().is_some_and(|d| s.document_label(d).contains(&label))
                && r.quote.as_deref().is_some_and(|q| q.to_lowercase().contains(&has))
        };
        // the quotes of a window from the named reports, and the claims of the window resting on them
        let from_reports = |window: &BTreeSet<String>| -> Value {
            let quotes: Vec<&RecordView> = window.iter().filter_map(|x| records.get(x)).filter(|r| named(r)).collect();
            let ids: BTreeSet<_> = quotes.iter().map(|r| r.id).collect();
            let claims: Vec<Value> = window
                .iter()
                .filter_map(|x| records.get(x))
                .filter(|r| r.kind == RecordKind::Claim && r.based_on.iter().any(|b| ids.contains(b)))
                .map(|r| json!({"id": r.id.short(), "text": r.text}))
                .collect();
            json!({"quotes": quotes.iter().map(|r| json!({"id": r.id.short(), "grounded": s.is_grounded(&r.id), "report": r.doc_id.as_deref().map(|d| s.document_label(d)),
                    "quote": r.quote})).collect::<Vec<_>>(), "claims": claims})
        };
        let now: BTreeSet<String> = w["issued"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let line = |head: &str| prompt.lines().find(|l| l.starts_with(head)).map(str::to_string);
        // every standing quote of the named reports with the text, and which window shows it
        let standing: Vec<Value> = records
            .values()
            .filter(|r| named(r) && s.is_grounded(&r.id))
            .map(|r| {
                json!({"id": r.id.short(), "in_window_now": now.contains(&r.id.short()),
                       "in_window_recorded": recorded.as_ref().map(|w| w.contains(&r.id.short())), "quote": r.quote})
            })
            .collect();
        let mut o = json!({"frame": n, "rq": rq, "label": label, "quote_has": has, "standing_quotes": standing,
            "window_now": {"issued": now.len(), "window_line": line("WINDOW:"), "live_support_line": line("LIVE SUPPORT"),
            "repair_line": line("INCREMENTAL REPAIR"), "from_reports": from_reports(&now)}});
        if let Some(rec) = &recorded {
            o["window_recorded"] =
                json!({"frame": answer_frame, "issued": rec.len(), "from_reports": from_reports(rec), "same_as_now": *rec == now,
                       "only_now": now.difference(rec).count(), "only_recorded": rec.difference(&now).count()});
        }
        if let Some(p) = &prompt_out {
            std::fs::write(p, &prompt).expect("the prompt file");
        }
        out = o;
    })
    .expect("the journal verifies under this kernel");
    out["journal"] = json!({"verified": true, "bytes": read.bytes, "sha256": sbgk_core::hash::to_hex(&read.sha256)});
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
