//! `sbgk mcp`: one agent on its own folder as ONE MCP server over stdio. The run is the one `audit-serve --profile solo` starts;
//! the command keeps the two tokens to itself, routes each tool to its subject, closes the owner's writing tools unless asked,
//! resumes from the journal in `<folder>/.yuce/`, and gives a long answer in parts.

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const POLICY: &str = "# Refund policy\n\nRefunds are accepted within 30 days of purchase.\n\nThe refund window was 14 days before 2026.\n";

struct Folder(PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("sbgk_one_command_{tag}_{}_{nonce}", std::process::id()));
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(dir.join("docs/policy.md"), POLICY).unwrap();
        Folder(dir)
    }

    fn docs(&self) -> String {
        self.0.join("docs").display().to_string()
    }

    /// One client session: initialize, tools/list, then the given tool calls; stdin closes after them.
    fn session(&self, flags: &[&str], calls: &[Value]) -> (Vec<Value>, Vec<Value>, Output) {
        let mut child =
            Command::new(BIN).arg("mcp").args(flags).current_dir(&self.0).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut messages = vec![
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ];
        for (i, call) in calls.iter().enumerate() {
            let mut call = call.clone();
            call["jsonrpc"] = json!("2.0");
            call["id"] = json!(10 + i);
            messages.push(call);
        }
        let text: String = messages.iter().map(|m| format!("{m}\n")).collect();
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let lines = |b: &[u8]| String::from_utf8_lossy(b).lines().filter_map(|l| serde_json::from_str(l).ok()).collect::<Vec<Value>>();
        (lines(&out.stdout), lines(&out.stderr), out)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn call(name: &str, args: Value) -> Value {
    json!({"method": "tools/call", "params": {"name": name, "arguments": args}})
}

fn tool_names(answers: &[Value]) -> Vec<String> {
    answers[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
}

fn structured(answer: &Value) -> Value {
    answer["result"]["structuredContent"].clone()
}

#[test]
fn one_command_starts_a_run_on_a_folder_and_answers_as_the_agent_and_the_owner() {
    let f = Folder::new("start");
    let (answers, notes, out) = f.session(
        &["--docs", &f.docs(), "--ask", "What is the refund window?"],
        &[call("audit_acquire", json!({"max_wait_ms": 0})), call("audit_status", json!({}))],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(answers[0]["result"]["serverInfo"]["name"], "yuce");
    assert_eq!(
        tool_names(&answers),
        [
            "audit_acquire",
            "audit_submit",
            "audit_renew",
            "audit_release",
            "audit_status",
            "audit_record",
            "audit_dependents",
            "audit_active_claims",
            "audit_diff",
            "audit_fallen",
            "audit_coverage",
            "audit_more"
        ]
    );
    let directive = structured(&answers[2]);
    assert_eq!(directive["status"], "DIRECTIVE");
    assert_eq!(directive["kind"], "EXTEND");
    assert!(structured(&answers[3])["completion"].is_object(), "the owner's status answers");
    // the journal sits in the folder's hidden .yuce, and the folder scan took only the document
    let wal = f.0.join("docs/.yuce/run.wal");
    assert!(wal.metadata().unwrap().len() > 0);
    let docs = notes.iter().find(|n| n["status"] == "docs").unwrap();
    assert_eq!(docs["taken"], json!(["policy.md"]));
    let question = notes.iter().find(|n| n["status"] == "question").unwrap();
    assert_eq!(question["about"], json!(["refund", "window"]));
}

#[test]
fn the_owners_writing_tools_are_closed_unless_the_command_opens_them() {
    let f = Folder::new("owner");
    let withdraw = call("audit_withdraw_text", json!({"doc_id": "policy.md", "exact_quote": "30 days"}));
    let (answers, _, _) = f.session(&["--docs", &f.docs(), "--ask", "What is the refund window?"], std::slice::from_ref(&withdraw));
    assert!(!tool_names(&answers).contains(&"audit_withdraw_text".to_string()));
    assert_eq!(answers[2]["error"]["code"], -32003, "{}", answers[2]);
    // a token the client sends chooses nothing: the tool's name decides the subject
    let forged = json!({"method": "tools/call", "params": {"name": "audit_withdraw_text", "auth_token": "x",
                        "arguments": {"doc_id": "policy.md", "exact_quote": "30 days", "auth_token": "y"}}});
    let (answers, _, _) = f.session(&["--docs", &f.docs()], &[forged]);
    assert_eq!(answers[2]["error"]["code"], -32003);
    let (answers, _, _) = f.session(&["--docs", &f.docs(), "--owner-tools", "all"], &[withdraw]);
    assert!(tool_names(&answers).contains(&"audit_close".to_string()));
    assert_eq!(structured(&answers[2])["status"], "REVOKED", "{}", answers[2]);
    let (answers, _, _) = f.session(&["--docs", &f.docs(), "--owner-tools", "none"], &[]);
    assert_eq!(tool_names(&answers), ["audit_acquire", "audit_submit", "audit_renew", "audit_release", "audit_more"]);
}

#[test]
fn started_again_it_resumes_the_run_of_its_journal() {
    let f = Folder::new("resume");
    let flags = ["--docs", &f.docs(), "--ask", "What is the refund window?"];
    let (_, first, _) = f.session(&flags, &[]);
    let ready = |notes: &[Value]| notes.iter().find(|n| n["status"] == "ready").cloned().unwrap();
    assert_eq!(ready(&first)["audit"]["resumed"], false);
    let (answers, again, out) = f.session(&flags, &[call("audit_acquire", json!({"max_wait_ms": 0}))]);
    assert!(out.status.success());
    assert_eq!(ready(&again)["audit"]["resumed"], true);
    assert_eq!(ready(&again)["audit"]["run_id"], ready(&first)["audit"]["run_id"]);
    let resuming = again.iter().find(|n| n["status"] == "resuming").unwrap();
    assert_eq!(resuming["not_read"], json!(["docs", "ask"]));
    assert_eq!(structured(&answers[2])["status"], "DIRECTIVE");
}

#[test]
fn a_long_answer_comes_in_parts_and_the_parts_rebuild_it() {
    let f = Folder::new("parts");
    let (first, _, _) = f.session(
        &["--docs", &f.docs(), "--ask", "What is the refund window?", "--max-result-chars", "1000"],
        &[call("audit_acquire", json!({"max_wait_ms": 0}))],
    );
    let text = first[2]["result"]["content"][0]["text"].as_str().unwrap().to_string();
    assert!(first[2]["result"].get("structuredContent").is_none(), "a paged answer carries no second, whole copy");
    let (header, _) = text.split_once('\n').unwrap();
    let header: Value = serde_json::from_str(header).unwrap();
    let parts = header["parts"].as_u64().unwrap() as usize;
    assert!(parts >= 2);
    assert_eq!(header["about"]["status"], "DIRECTIVE");
    // the parts live in the process that cut them: ask for them in the same session
    let more: Vec<Value> = (2..=parts).map(|n| call("audit_more", json!({"handle": header["answer_in_parts"], "part": n}))).collect();
    let mut calls = vec![call("audit_acquire", json!({"max_wait_ms": 0}))];
    calls.extend(more);
    let (answers, _, _) = f.session(&["--docs", &f.docs(), "--max-result-chars", "1000"], &calls);
    let first_text = answers[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(first_text.chars().count() <= 1000, "the first part, its header included, fits the limit");
    let (header, body) = first_text.split_once('\n').unwrap();
    let header: Value = serde_json::from_str(header).unwrap();
    let mut whole = body.to_string();
    for n in 2..=header["parts"].as_u64().unwrap() as usize {
        let t = answers[1 + n]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(t.chars().count() <= 1000);
        let (h, b) = t.split_once('\n').unwrap();
        assert_eq!(serde_json::from_str::<Value>(h).unwrap()["part"], n);
        whole.push_str(b);
    }
    let directive: Value = serde_json::from_str(&whole).expect("the parts put together are the whole answer");
    assert_eq!(directive["task_id"], header["about"]["task_id"]);
    assert!(directive["prompt"].as_str().unwrap().contains("Refunds are accepted within 30 days of purchase."));
    // a part that does not exist is an error, not a silence
    let (answers, _, _) = f.session(&["--docs", &f.docs()], &[call("audit_more", json!({"handle": "r999", "part": 2}))]);
    assert_eq!(answers[2]["result"]["isError"], true);
}

#[test]
fn a_run_cannot_start_without_its_question() {
    let f = Folder::new("question");
    let (_, _, out) = f.session(&["--docs", &f.docs()], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--ask"));
    let (_, _, out) = f.session(&["--docs", &f.docs(), "--ask", "Why so?"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--about"));
    assert!(!f.0.join("docs/.yuce/run.wal").exists(), "a refused start leaves no journal");
}

#[test]
fn the_asked_question_replaces_no_file_beside_the_journal() {
    // Codex's review of e13e2802, OCMCP-01: with --wal, a questions.json beside the journal was overwritten
    let f = Folder::new("sibling");
    let theirs = f.0.join("questions.json");
    let original = b"[{\"id\":\"owner-question\",\"text\":\"Keep this file\",\"about\":[\"refund\"]}]\n";
    std::fs::write(&theirs, original).unwrap();
    let wal = f.0.join("custom.wal").display().to_string();
    let (answers, notes, out) =
        f.session(&["--docs", &f.docs(), "--wal", &wal, "--ask", "What is the refund window?"], &[call("audit_acquire", json!({"max_wait_ms": 0}))]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(&theirs).unwrap(), original);
    let question = notes.iter().find(|n| n["status"] == "question").unwrap();
    assert_eq!(question["text"], "What is the refund window?");
    assert!(question.get("file").is_none(), "the question goes to the run without a file");
    // the run took the asked question, not the file beside its journal
    assert!(structured(&answers[2])["prompt"].as_str().unwrap().contains("What is the refund window?"));
    // and the default journal folder holds no question file either
    let g = Folder::new("nofile");
    let (_, _, out) = g.session(&["--docs", &g.docs(), "--ask", "What is the refund window?"], &[]);
    assert!(out.status.success());
    assert!(!g.0.join("docs/.yuce/questions.json").exists());
}

#[test]
fn metadata_that_is_not_an_object_is_refused_and_the_session_goes_on() {
    // Codex's review of e13e2802, OCMCP-02: a _meta that was not an object ended the process
    let f = Folder::new("meta");
    let mut calls = Vec::new();
    for meta in [json!([]), json!("text"), json!(42), json!(false)] {
        calls.push(json!({"method": "tools/call", "params": {"name": "audit_status", "arguments": {}, "_meta": meta}}));
    }
    calls.push(json!({"method": "tools/call", "params": {"name": "audit_status", "arguments": {}, "_meta": null}}));
    calls.push(json!({"method": "tools/call", "params": {"name": "audit_status", "arguments": {}, "_meta": {"trace": "kept", "auth_token": "x"}}}));
    calls.push(json!({"method": "ping"}));
    let (answers, _, out) = f.session(&["--docs", &f.docs(), "--ask", "What is the refund window?"], &calls);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for a in &answers[2..6] {
        assert_eq!(a["error"]["code"], -32602, "{a}");
    }
    assert!(structured(&answers[6])["completion"].is_object(), "a null _meta is no _meta: {}", answers[6]);
    assert!(structured(&answers[7])["completion"].is_object(), "{}", answers[7]);
    assert_eq!(answers[8]["result"], json!({}));
}

#[test]
fn every_part_fits_the_limit_even_with_a_long_document_name() {
    // Codex's review of e13e2802, OCMCP-03: the task's key (it holds the document's name) made the first part 1099 of 1000
    let f = Folder::new("longkey");
    let mut deep = f.0.join("docs");
    for _ in 0..8 {
        deep.push("a".repeat(55));
    }
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("refund.md"), POLICY).unwrap();
    std::fs::remove_file(f.0.join("docs/policy.md")).unwrap();
    let flags = ["--docs", &f.docs(), "--ask", "What is the refund window?", "--max-result-chars", "1000"];
    let (first, _, out) = f.session(&flags, &[call("audit_acquire", json!({"max_wait_ms": 0}))]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = first[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.chars().count() <= 1000, "{} characters", text.chars().count());
    let header: Value = serde_json::from_str(text.split_once('\n').unwrap().0).unwrap();
    let parts = header["parts"].as_u64().unwrap() as usize;
    // the long key did not fit beside half a part and was left out of the header; the task's id and status stay
    assert!(header["about"].get("key").is_none());
    assert_eq!(header["about"]["status"], "DIRECTIVE");
    let mut calls = vec![call("audit_acquire", json!({"max_wait_ms": 0}))];
    calls.extend((2..=parts).map(|n| call("audit_more", json!({"handle": header["answer_in_parts"], "part": n}))));
    let (answers, _, _) = f.session(&["--docs", &f.docs(), "--max-result-chars", "1000"], &calls);
    let header: Value = serde_json::from_str(answers[2]["result"]["content"][0]["text"].as_str().unwrap().split_once('\n').unwrap().0).unwrap();
    assert_eq!(header["parts"].as_u64().unwrap() as usize, parts);
    let mut whole = String::new();
    for a in &answers[2..] {
        let t = a["result"]["content"][0]["text"].as_str().unwrap();
        assert!(t.chars().count() <= 1000, "{} characters", t.chars().count());
        whole.push_str(t.split_once('\n').unwrap().1);
    }
    let directive: Value = serde_json::from_str(&whole).expect("the parts put together are the whole answer");
    assert_eq!(directive["task_id"], header["about"]["task_id"]);
    assert!(directive["key"].as_str().unwrap().contains(&"a".repeat(55)), "the whole answer still holds the key");
}
