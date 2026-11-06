//! Read-only archive inputs; all recovery and withdrawal writes use fresh files under the isolated TEMP directory.
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{pairs, AuditStore, RecordId};
use sbgk_core::hash::{from_hex, sha256, to_hex};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn questions(run: &Path) -> Vec<ResearchQuestion> {
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
fn dispatcher(run: &Path) -> Dispatcher {
    Dispatcher::new(DispatchConfig { section_bytes: 3000, auto_reread_limit: 20, ..Default::default() }, questions(run))
}
fn short(s: &str) -> RecordId {
    RecordId(from_hex(s.trim_start_matches('@')).expect("full record id"))
}

fn main() {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let scratch = std::env::temp_dir().join(format!("consilium_gates_{}_{nonce}", std::process::id()));
    std::fs::create_dir(&scratch).unwrap();
    for (i, arg) in std::env::args().skip(1).enumerate() {
        let run = PathBuf::from(arg);
        let input = run.join("arm_c/run.wal");
        let raw = std::fs::read(&input).unwrap();
        let frames = String::from_utf8(raw.clone()).unwrap().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).collect::<Vec<_>>();
        let first = frames.iter().position(|e| matches!(e["payload"]["command"]["kind"].as_str(), Some("revoke" | "revoke_text")));
        let phase1_frames = first.unwrap_or(frames.len());
        let prefix_bytes = raw.split_inclusive(|b| *b == b'\n').take(phase1_frames).flatten().copied().collect::<Vec<_>>();
        let copy = scratch.join(format!("{i}_phase1.wal"));
        std::fs::write(&copy, &prefix_bytes).unwrap();
        let started = std::time::Instant::now();
        eprintln!("archive {}: semantic recovery of phase 1 ({} frames)", run.display(), phase1_frames);
        let mut state = AuditState::open(&copy).expect("semantic WAL prefix recovery");
        eprintln!("archive {}: recovered in {:.3}s", run.display(), started.elapsed().as_secs_f64());
        let candidates = pairs::detect(&state);
        let mut d = dispatcher(&run);
        d.recover(&state);
        let scope: Vec<Value> = state
            .links()
            .into_iter()
            .filter_map(|l| {
                pairs::scope_violation(&state, l.from, &l.rel, l.to, &l.basis)
                    .map(|guard| json!({"link":l.id.short(),"status":l.status.name(),"from":l.from.short(),"rel":l.rel,"to":l.to.short(),"guard":guard}))
            })
            .collect();
        let reports: Vec<_> = state
            .docs()
            .into_iter()
            .map(|doc| {
                let text = state.doc_text(&doc).unwrap_or_default();
                json!({"doc_id":doc,"front_matter":text.split("+++").nth(1).unwrap_or("")})
            })
            .collect();
        let mut row = json!({"run":run.file_name().unwrap().to_string_lossy(),"input_sha256":to_hex(&sha256(&raw)),"semantic_replay":"PASS",
            "slice":"phase1_before_first_revoke_or_complete_archive_if_none","phase1_frames":phase1_frames,
            "phase1_sha256":to_hex(&sha256(&prefix_bytes)),"reports":reports,
            "records":state.head(),"pairs":candidates.iter().map(|p|json!({"card_id":p.id(),"old":p.old.short(),"new":p.new.short(),
                "old_doc":p.old_doc,"new_doc":p.new_doc,"score":p.score,"metadata":p.metadata,
                "old_text":state.record(&p.old).and_then(|r|r.text),"new_text":state.record(&p.new).and_then(|r|r.text)})).collect::<Vec<_>>(),
            "scope_blocked":scope,"diagnostics":d.offline_diagnostics(&state),"scratch":scratch});
        if let Some(n) = first {
            let rid = short(frames[n]["payload"]["command"]["record"].as_str().unwrap());
            let mut withdrawal = Value::Null;
            eprintln!("archive {}: withdrawal through ordinary WAL prefix", run.display());
            let mut test_withdrawal = |s: &mut AuditState| {
                let mut before = dispatcher(&run);
                before.recover(s);
                let prior = before.accepted_outcomes(s);
                let ids = |v: &Value| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>()).unwrap_or_default();
                let prior_ids = prior.as_object().map(|m| m.iter().map(|(q, v)| (q.clone(), ids(&v["answer_ids"]))).collect::<Vec<_>>()).unwrap_or_default();
                s.revoke_observation("offline-owner", &rid).unwrap();
                let after = before.accepted_outcomes(s);
                let mut expected = serde_json::Map::new();
                let mut ok = true;
                let all = s.records_since(0);
                for (q, old_ids) in &prior_ids {
                    let kept = old_ids
                        .iter()
                        .filter(|id| all.iter().find(|r| r.id.short() == id.as_str()).is_some_and(|r| s.is_answer_support(&r.id)))
                        .cloned()
                        .collect::<Vec<_>>();
                    ok &= ids(&after[q]["answer_ids"]) == kept;
                    expected.insert(q.clone(), json!({"before":old_ids.len(),"independent":kept.len(),"ids":kept}));
                }
                withdrawal = json!({"record":rid.short(),"expected":expected,"delivered":after,"all_independent_retained":ok});
            };
            test_withdrawal(&mut state);
            drop(state);
            let reopened = AuditState::open(&copy).unwrap();
            let mut recovered = dispatcher(&run);
            recovered.recover(&reopened);
            let restarted = recovered.accepted_outcomes(&reopened);
            let same = withdrawal["delivered"].as_object().unwrap().iter().all(|(q, v)| v["answer_ids"] == restarted[q]["answer_ids"]);
            withdrawal["dispatcher_recovery_same"] = json!(same);
            row["withdrawal"] = withdrawal;
        }
        assert_eq!(std::fs::read(&input).unwrap(), raw, "archive input changed during analysis");
        row["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        println!("{row}");
    }
}
