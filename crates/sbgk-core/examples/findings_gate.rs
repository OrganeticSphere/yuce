//! A security review's findings through the kernel, on the library, with no model: `examples/findings-gate/README.md`.
//! A findings file names a file and a line for each step. A check of its shape can tell that the file and the line exist, not that
//! the line says what the finding claims. The script plays the agents itself.
//! usage: cargo run --release -p sbgk-core --example findings_gate [-- --keep]
use sbgk_core::audit::directives::{DispatchConfig, Dispatcher, ResearchQuestion};
use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{AuditStore, RecordId, Scope};
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How long a reader holds a task without a sign of life, on the example's own clock.
const LEASE_MS: u64 = 1_000;
const FILES: [&str; 2] = ["app/orders.py", "app/session.py"];

fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    FILES.iter().map(|f| (f.to_string(), std::fs::read(root.join(f)).expect("a file of the example"))).collect()
}

/// The quotes of a finding, each once, in the order the finding gives them.
fn quotes(f: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for step in f["trace"].as_array().into_iter().chain(f["evidence"].as_array()).flatten() {
        let q = step["quote"].as_str().expect("a quote").to_string();
        if !out.contains(&q) {
            out.push(q);
        }
    }
    out
}

fn file_of(f: &Value) -> &str {
    f["evidence"][0]["file"].as_str().expect("the finding's file")
}

/// A finding as lines of the kernel: each quote a record, and one claim that rests on all of them.
fn lines_of(f: &Value, prefix: &str) -> Vec<Value> {
    let name = f["fingerprint"].as_str().expect("a fingerprint");
    let mut lines = Vec::new();
    let mut on = Vec::new();
    for (k, quote) in quotes(f).iter().enumerate() {
        let local = format!("{prefix}{name}-o{k}");
        lines.push(json!({"kind":"observe","local_id":local,"doc_id":file_of(f),"exact_quote":quote,"terms":["finding"]}));
        on.push(local);
    }
    lines.push(json!({"kind":"claim","local_id":format!("{prefix}{name}"),"text":f["title"],"subject":"finding","stance":"reported","based_on":on}));
    lines
}

/// The line of a file a quote starts on, as a reader would count it.
fn line_of(bytes: &[u8], quote: &str) -> Option<usize> {
    let at = bytes.windows(quote.len()).position(|w| w == quote.as_bytes())?;
    Some(1 + bytes[..at].iter().filter(|b| **b == b'\n').count())
}

struct Steps(bool);
impl Steps {
    fn step(&mut self, n: u32, text: String, ok: bool) {
        println!("  [{}] {n}. {text}", if ok { "ok" } else { "FAILED" });
        self.0 &= ok;
    }
}

fn main() {
    let keep = std::env::args().any(|a| a == "--keep");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/findings-gate");
    let findings: Vec<Value> = serde_json::from_slice(&std::fs::read(dir.join("findings.json")).expect("findings.json")).expect("a findings file");
    let before = tree(&dir.join("before"));
    let after = tree(&dir.join("after"));
    let mut steps = Steps(true);
    println!("YuCe findings gate: {} findings, {} files, no model", findings.len(), before.len());

    // 1. What a check of the shape sees: the file and the line of every step exist
    let bytes_of = |docs: &[(String, Vec<u8>)], file: &str| docs.iter().find(|(n, _)| n == file).map(|(_, b)| b.clone());
    let shape_ok = findings.iter().all(|f| {
        f["trace"].as_array().into_iter().chain(f["evidence"].as_array()).flatten().all(|s| {
            let lines = bytes_of(&before, s["file"].as_str().unwrap_or("")).map_or(0, |b| b.iter().filter(|x| **x == b'\n').count() as u64);
            s["line"].as_u64().is_some_and(|l| l >= 1 && l <= lines)
        })
    });
    steps.step(1, format!("a check of the shape: every step of all {} findings names a file and a line that exist -> passed", findings.len()), shape_ok);

    let wal = std::env::temp_dir().join(format!("yuce_findings_gate_{}.wal", std::process::id()));
    let mut s = AuditState::create(&wal, &AuditOntology::base(), &before, "findings-gate", sha256(b"findings-gate")).expect("a new journal");
    let question =
        ResearchQuestion { id: "RQ1".into(), text: "Which findings of this review hold?".into(), about: vec!["finding".into()], ..Default::default() };
    let mut d = Dispatcher::new(DispatchConfig { ttl_ms: LEASE_MS, ..Default::default() }, vec![question]);
    let mut now = 0u64;

    // 2. The first reader hands in the findings on its file: the made-up one has no bytes to stand on
    let t = d.acquire(&s, "reader-1", true, now);
    let task = t["task_id"].as_str().expect("a task").to_string();
    let file = t["key"].as_str().unwrap_or("").trim_start_matches("doc:").split('#').next().unwrap_or("").to_string();
    let mine: Vec<&Value> = findings.iter().filter(|f| file_of(f) == file).collect();
    let lines: Vec<Value> = mine.iter().flat_map(|f| lines_of(f, "")).collect();
    let r = d.submit(&mut s, &task, "reader-1", &lines, now);
    let refused: Vec<String> = r["refused"].as_array().into_iter().flatten().filter_map(|x| x["error"]["code"].as_str().map(str::to_string)).collect();
    let stored: BTreeMap<String, String> = serde_json::from_value(r["accepted_locals"].clone()).unwrap_or_default();
    let made_up = findings.iter().find(|f| f["fingerprint"] == "orders-path-traversal").expect("the made-up finding");
    let real = findings.iter().find(|f| f["fingerprint"] == "orders-sql-injection").expect("the first real finding");
    let name = |f: &Value| f["fingerprint"].as_str().unwrap_or("").to_string();
    steps.step(
        2,
        format!(
            "{file}: finding {} stored, finding {} refused ({}), and nothing of it stored",
            name(real),
            name(made_up),
            refused.first().map_or("no refusal", String::as_str)
        ),
        stored.contains_key(&name(real)) && !stored.keys().any(|k| k.starts_with(&name(made_up))) && refused.iter().any(|c| c == "QUOTE_NOT_FOUND_IN_BYTES"),
    );
    let closing: Vec<Value> = lines_of(real, "");
    let r = d.submit(&mut s, &task, "reader-1", &closing, now);
    assert_eq!(r["status"], "COMMITTED", "{r}");

    // 3. The second reader takes the other file and is never heard of again
    now += 1;
    let lost = d.acquire(&s, "reader-2", true, now);
    let lost_task = lost["task_id"].as_str().expect("a task").to_string();
    let waiting = d.acquire(&s, "reader-3", true, now);
    now += LEASE_MS + 1;
    let taken = d.acquire(&s, "reader-3", true, now);
    let late = d.submit(&mut s, &lost_task, "reader-2", &[], now);
    let same = lost["key"] == taken["key"];
    steps.step(
        3,
        format!(
            "reader-2 took {} and went silent: while its lease ran the task was held ({}), after it reader-3 got the same task, and a late answer of reader-2 is {}",
            lost["key"].as_str().unwrap_or(""),
            waiting["status"].as_str().unwrap_or(""),
            late["status"].as_str().unwrap_or("")
        ),
        same && taken["task_id"] != lost["task_id"] && late["status"] == "STALE_TASK",
    );
    let second = findings.iter().find(|f| f["fingerprint"] == "session-hardcoded-key").expect("the second real finding");
    let taken_task = taken["task_id"].as_str().expect("a task").to_string();
    let r = d.submit(&mut s, &taken_task, "reader-3", &lines_of(second, ""), now);
    assert_eq!(r["status"], "COMMITTED", "{r}");

    // 4. The review ends with an answer on the two findings
    let claims = s.records_since(0);
    let id_of = |text: &Value| claims.iter().find(|x| x.text.as_deref() == text.as_str() && x.kind.name() == "claim").map(|x| x.id).expect("a stored finding");
    let (first_claim, second_claim) = (id_of(&real["title"]), id_of(&second["title"]));
    let quotes_of = |id: RecordId| claims.iter().find(|x| x.id == id).expect("a record").based_on.iter().map(|q| q.short()).collect::<Vec<_>>();
    let t = d.acquire(&s, "reader-1", true, now);
    assert_eq!(t["kind"], "SUMMARIZE", "{t}");
    let task = t["task_id"].as_str().expect("a task");
    let prefix = t["local_id_prefix"].as_str().unwrap_or("");
    let row = |n: &str, f: &Value, on: Vec<String>| json!({"kind":"claim","local_id":format!("{prefix}{n}"),"text":f["title"],"subject":"finding","stance":"reported","based_on":on});
    let answer = [
        row("r1", real, quotes_of(first_claim)),
        row("r2", second, quotes_of(second_claim)),
        json!({"kind":"done","local_id":format!("{prefix}d1"),"rq_id":"RQ1","directive_id":task,"outcome":"answered","answer_ids":[format!("{prefix}r1"),format!("{prefix}r2")]}),
    ];
    let r = d.submit(&mut s, task, "reader-1", &answer, now);
    let next = d.acquire(&s, "reader-1", true, now);
    steps.step(
        4,
        format!("the review closes: answer {} on 2 findings, work left: {}", r["status"].as_str().unwrap_or(""), next["status"].as_str().unwrap_or("")),
        r["status"] == "COMMITTED" && next["status"] == "COMPLETE" && d.completion(&s, true)["complete"] == true,
    );
    let grounded = |s: &AuditState| (s.is_grounded(&first_claim), s.is_grounded(&second_claim));
    let was = grounded(&s);

    // 5. The code changes: one finding is fixed, and a comment moves the other down by a line
    for (file, bytes) in &after {
        s.put_document("owner", file, bytes).expect("a new version of the file");
    }
    let now_grounded = grounded(&s);
    let open_again = d.completion(&s, true)["complete"] == false;
    steps.step(
        5,
        format!("both files changed: the findings on them were grounded {was:?}, now {now_grounded:?}, and the review is open again: {open_again}"),
        was == (true, true) && now_grounded == (false, false) && open_again,
    );

    // 6. Each finding is checked again on the new bytes, by what it quotes
    let recheck = |s: &mut AuditState, f: &Value| {
        let scope = Scope { docs: vec![file_of(f).to_string()], ..Default::default() };
        s.submit_records("reader-1", &format!("recheck-{}", name(f)), &scope, &lines_of(f, "recheck-"))
    };
    let fixed = recheck(&mut s, real);
    let moved = recheck(&mut s, second);
    let new_bytes = bytes_of(&after, file_of(second)).expect("the new file");
    let key = second["evidence"][0]["quote"].as_str().expect("a quote");
    let (cited, found) = (second["evidence"][0]["line"].as_u64().unwrap_or(0) as usize, line_of(&new_bytes, key).unwrap_or(0));
    let stands = moved.error.is_none() && moved.accepted.last().is_some_and(|id| s.is_grounded(id));
    let code = fixed.error.as_ref().map(|e| e.to_json()["code"].as_str().unwrap_or("").to_string()).unwrap_or_default();
    steps.step(
        6,
        format!(
            "checked again: {} no longer has its bytes ({code}) and goes back to open; {} stands on the new version, at line {found} and not {cited}",
            name(real),
            name(second)
        ),
        fixed.error.is_some() && code == "QUOTE_NOT_FOUND_IN_BYTES" && stands && found == cited + 1,
    );

    // 7. All of it is one journal, checked without a model and without the server
    let (audit, engine) = (s.audit_root(), s.engine_root());
    drop(s);
    let (replayed, _) = AuditState::verify(&wal, &mut |_, _, _, _| {}).expect("the journal replays");
    steps.step(
        7,
        format!("the journal replays to the same roots: audit {}..., engine {}...", &to_hex(&audit)[..16], &to_hex(&engine)[..16]),
        replayed.audit_root() == audit && replayed.engine_root() == engine,
    );
    finish(&wal, keep, steps.0);
}

fn finish(wal: &PathBuf, keep: bool, good: bool) {
    println!("{}", if good { "All steps behaved as described." } else { "Some step did not behave as described." });
    if keep {
        println!("  journal {}", wal.display());
    } else {
        let _ = std::fs::remove_file(wal);
    }
    std::process::exit(if good { 0 } else { 1 });
}
