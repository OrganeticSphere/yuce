//! The storage side of `benchmarks/run_limits.py`, which runs it and reports the numbers of BENCHMARKS.md, section 4.
//!
//! `limits populate <dir> <records>` builds a journal of that many records from nothing on a fixed synthetic corpus: half quotes,
//! half claims on one quote each, 32 records per durable transaction. At the exact size it closes its writer, keeps a copy of the
//! journal with its roots, reopens the working file, and times 32 single quotes, one transaction each, on top of it.
//!
//! `limits seed <wal> <records>` adds the same records to a journal a server has just created.
//!
//! `limits recover <wal> <out.jsonl>` opens a journal in this new process and reports the time and the roots.
//!
//! Each writes one JSON line per stage to stdout or to the named file. No model, no provider, no network.
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

const QUOTE: &str = "The synthetic history item is a reported condition.";
const BATCH: u64 = 32;
const PROBES: usize = 32;
const SUPPORT_CHECKS: usize = 64;

fn roots(s: &AuditState) -> Value {
    json!({"audit_root": to_hex(&s.audit_root()), "engine_root": to_hex(&s.engine_root()), "session_root": to_hex(&s.session_root())})
}

fn emit(out: Option<&Path>, row: &Value) {
    if let Some(path) = out {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(path).expect("open the output");
        writeln!(f, "{row}").expect("write the output");
        f.sync_data().expect("sync the output");
    }
    println!("{row}");
}

/// The sample at sorted index ceil((n-1) * q).
fn percentile(v: &[f64], q: f64) -> f64 {
    let mut a = v.to_vec();
    a.sort_by(f64::total_cmp);
    a[((a.len() - 1) as f64 * q).ceil() as usize]
}

fn stats(v: &[f64]) -> Value {
    json!({"n": v.len(), "p50_us": percentile(v, 0.5), "p95_us": percentile(v, 0.95), "samples_us": v})
}

fn micros(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e6
}

fn observe(id: &str) -> Value {
    json!({"kind": "observe", "local_id": id, "doc_id": "seed", "exact_quote": QUOTE, "terms": ["history"]})
}

fn scope() -> Scope {
    Scope { docs: vec!["seed".into()], ..Default::default() }
}

/// Adds quotes and claims until the journal holds `target` records; the claims' ids are returned.
fn fill(s: &mut AuditState, target: u64) -> Vec<RecordId> {
    let (mut batch, mut claims) = (0u64, Vec::new());
    while s.head() < target {
        let count = (target - s.head()).min(BATCH);
        assert_eq!(count % 2, 0, "records come in pairs");
        let mut lines = Vec::new();
        for i in 0..count / 2 {
            let o = format!("o{i:03}");
            lines.push(observe(&o));
            lines.push(json!({"kind": "claim", "local_id": format!("c{i:03}"), "subject": "history", "text": QUOTE, "stance": "reported", "based_on": [o]}));
        }
        let id = format!("seed_{batch:08}");
        let r = s.submit_records_id(&id, "seeder", &id, &scope(), &lines);
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.accepted.len(), lines.len());
        claims.extend(r.accepted.iter().skip(1).step_by(2).copied());
        batch += 1;
    }
    claims
}

fn populate(dir: &Path, target: u64) {
    let wal = dir.join("population.wal");
    assert!(!wal.exists(), "each point starts from nothing");
    let started = Instant::now();
    let mut docs = vec![("seed".to_string(), format!("# History\n{QUOTE}\n").into_bytes())];
    for i in 0..96 {
        docs.push((format!("d{i:03}"), format!("# Status {i:03}\nThe status of component {i:03} is reported ready.\n").into_bytes()));
    }
    let mut s = AuditState::create(&wal, &AuditOntology::base(), &docs, "limits", sha256(b"fixed-synthetic-corpus-v1")).expect("create the journal");
    s.set_links_off(true);
    let claims = fill(&mut s, target);
    let expected = roots(&s);
    let transactions = s.transaction_sequence();
    // a writer holds its file locked on Windows: close it before the copy
    drop(s);
    let saved = dir.join(format!("base_{target}.wal"));
    fs::copy(&wal, &saved).expect("keep the journal");
    let mut s = AuditState::open(&wal).expect("reopen the journal");
    s.set_links_off(true);
    assert_eq!(s.head(), target);
    assert_eq!(roots(&s), expected);
    let mut support = Vec::new();
    for i in 0..SUPPORT_CHECKS {
        let id = if i % 2 == 0 { claims.first() } else { claims.last() }.expect("a claim");
        let t = Instant::now();
        assert!(s.is_answer_support(id));
        support.push(micros(t));
    }
    let mut single = Vec::new();
    for i in 0..PROBES {
        let id = format!("probe_{target}_{i:03}");
        let t = Instant::now();
        let r = s.submit_records_id(&id, "probe", &id, &scope(), &[observe("o")]);
        single.push(micros(t));
        assert!(r.error.is_none(), "{:?}", r.error);
    }
    let journal_bytes = fs::metadata(&saved).expect("the kept journal").len();
    emit(
        Some(&dir.join("storage.jsonl")),
        &json!({"stage": "point", "records": target, "transactions": transactions, "journal_bytes": journal_bytes, "journal": saved.file_name().map(|n| n.to_string_lossy()),
                "single_quote_commit": stats(&single), "support_check": stats(&support), "roots": expected, "elapsed_s": started.elapsed().as_secs_f64()}),
    );
}

fn seed(wal: &Path, target: u64) {
    let mut s = AuditState::open(wal).expect("open the journal");
    assert_eq!(s.head(), 0, "the journal of a new run");
    s.set_links_off(true);
    fill(&mut s, target);
    let ids: Vec<String> = s.records_since(0).iter().map(|r| to_hex(&r.id.0)).collect();
    let digest = to_hex(&sha256(serde_json::to_string(&ids).expect("ids").as_bytes()));
    emit(None, &json!({"stage": "seed", "records": s.head(), "record_ids_sha256": digest, "roots": roots(&s)}));
}

fn recover(wal: &Path, out: &Path) {
    let t = Instant::now();
    let s = AuditState::open(wal).expect("open the journal");
    let open_us = micros(t);
    emit(Some(out), &json!({"stage": "recovery", "records": s.head(), "open_us": open_us, "roots": roots(&s), "transactions": s.transaction_sequence()}));
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match (a.get(1).map(String::as_str), a.len()) {
        (Some("populate"), 4) => populate(Path::new(&a[2]), a[3].parse().expect("records")),
        (Some("seed"), 4) => seed(Path::new(&a[2]), a[3].parse().expect("records")),
        (Some("recover"), 4) => recover(Path::new(&a[2]), Path::new(&a[3])),
        _ => {
            eprintln!("usage: limits populate <dir> <records> | seed <wal> <records> | recover <wal> <out.jsonl>");
            std::process::exit(2);
        }
    }
}
