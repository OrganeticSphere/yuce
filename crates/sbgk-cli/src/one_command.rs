//! `sbgk mcp` (and `yuce mcp`): the audit server for one agent on its own folder, as ONE MCP server over stdio.
//!
//! An MCP client (Claude Code, Claude Desktop, Cursor, ...) starts it from one line of its configuration: no listener, no bridge,
//! no token to copy. The command starts, or resumes, the run `audit-serve --profile solo` would start on the folder, with its
//! journal in `<folder>/.yuce/` (a hidden folder, which the folder scan leaves out), keeps the run's two tokens to itself and
//! answers the client as both subjects: the reading agent's four tools, and the owner's reading tools (all the owner's tools with
//! `--owner-tools all`, none with `--owner-tools none`). Each call goes to the subject whose tool it is; the kernel's rules, the
//! journal and every answer are those of `audit-serve`.
//!
//! A tool answer longer than `--max-result-chars` comes in parts: the first names a handle and the number of parts, and
//! `audit_more` gives the others. In the probe of 14.11.2026 a summary's directive was 70 to 85 KB, more than Claude Code takes
//! in one tool result: it kept the first 2 KB and the reader could not answer.

use super::audit_mcp::{self, AuditServer};
use super::mcp::{self, LineServer};
use super::{fail, Args};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The owner's tools that only read the run.
const OWNER_READ: &[&str] = &["audit_status", "audit_record", "audit_dependents", "audit_active_claims", "audit_diff", "audit_fallen", "audit_coverage"];
const MORE: &str = "audit_more";
const DEFAULT_MAX_RESULT_CHARS: usize = 16_000;
/// The fields of a paged answer's first header, in the order they are dropped when the header would take more than half a part:
/// the whole answer, put together from the parts, still holds them all. `key` goes first: it grows with the document names.
const ABOUT_FIELDS: &[&str] = &["status", "task_id", "kind", "max_lines", "local_id_prefix", "key"];
/// Answers in parts kept for `audit_more`: the newest ones.
const KEPT_PAGED: usize = 8;
const INVALID_PARAMS: i64 = -32602;
const FORBIDDEN: i64 = -32003;

const INSTRUCTIONS: &str = "YuCe audit of the documents of one folder. As its reading agent: call audit_acquire, do exactly what the directive's \
prompt says, and send its JSON lines with audit_submit. On REPAIR_REQUIRED send only the lines after the accepted ones; on WAIT call audit_acquire \
again; on COMPLETE the questions of the run are answered; on DONE stop. A long answer comes in parts: its first part names a handle and the number \
of parts, and audit_more with that handle gives each other part; read every part before you act. The owner's reading tools show what stands \
(audit_active_claims, audit_record), what fell and why (audit_fallen), what each part of the documents came to (audit_coverage), and the run's \
status (audit_status).";

/// Words that name no topic: left out of the terms taken from a question.
const STOP_WORDS: &[&str] = &[
    "about",
    "after",
    "before",
    "could",
    "does",
    "document",
    "documents",
    "from",
    "have",
    "into",
    "said",
    "says",
    "should",
    "that",
    "their",
    "them",
    "there",
    "these",
    "they",
    "this",
    "those",
    "what",
    "when",
    "where",
    "which",
    "while",
    "will",
    "with",
    "would",
];

pub fn cmd_mcp(a: &Args) {
    let owner_tools: Vec<&'static str> = match a.get("owner-tools").unwrap_or("read") {
        "read" => OWNER_READ.to_vec(),
        "all" => audit_mcp::owner_tool_names().to_vec(),
        "none" => Vec::new(),
        other => fail(&format!("--owner-tools must be read, all or none, not '{other}'")),
    };
    let max_chars: usize = a.num("max-result-chars", DEFAULT_MAX_RESULT_CHARS);
    if max_chars < 1000 {
        fail("--max-result-chars must be at least 1000");
    }
    let wal = match a.get("wal") {
        Some(w) => PathBuf::from(w),
        None => Path::new(a.get("docs").unwrap_or_else(|| fail("give --docs <folder>, or --wal <journal> of a run to resume"))).join(".yuce").join("run.wal"),
    };
    let resuming = wal.metadata().is_ok_and(|m| m.len() > 0);
    let dir = wal.parent().map(Path::to_path_buf).filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", dir.display())));
    let mut kv: HashMap<String, String> = HashMap::new();
    kv.insert("profile".into(), "solo".into());
    kv.insert("wal".into(), wal.display().to_string());
    // the question of --ask goes to the run as JSON: no file is written, so no file beside the journal is replaced
    let mut asked: Option<Value> = None;
    if resuming {
        // the journal holds the documents and the questions the run started with
        let given: Vec<&str> = ["docs", "select", "run-id", "questions", "ask", "about"].into_iter().filter(|f| a.get(f).is_some()).collect();
        if !given.is_empty() {
            eprintln!(
                "{}",
                json!({"status": "resuming", "journal": wal.display().to_string(), "not_read": given,
                       "message": "the journal holds the documents and the questions this run started with"})
            );
        }
    } else {
        let docs = a.get("docs").unwrap_or_else(|| fail(&format!("{} holds no run yet: give --docs <folder> to start one", wal.display())));
        kv.insert("docs".into(), docs.into());
        if let Some(select) = a.get("select") {
            kv.insert("select".into(), select.into());
        }
        let folder = Path::new(docs).canonicalize().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        kv.insert("run-id".into(), a.get("run-id").map(str::to_string).or(folder).unwrap_or_else(|| "yuce".into()));
        match (a.get("questions"), a.get("ask")) {
            (Some(_), Some(_)) => fail("give --questions <file> or --ask <question>, not both"),
            (Some(file), None) => {
                kv.insert("questions".into(), file.to_string());
            }
            (None, Some(ask)) => {
                let about: Vec<String> = match a.get("about") {
                    Some(list) => list.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
                    None => terms_of(ask),
                };
                if about.is_empty() {
                    fail("--ask: give --about <term,term>: the words the documents use for the topic");
                }
                eprintln!("{}", json!({"status": "question", "id": "q1", "text": ask, "about": about}));
                asked = Some(json!([{"id": "q1", "text": ask, "about": about}]));
            }
            (None, None) => fail("give the run its question: --ask <question> (and --about <term,term>), or --questions <file>"),
        }
    }
    let args = Args { pos: Vec::new(), kv, sw: HashSet::new(), from_settings: HashSet::new() };
    let start = audit_mcp::start_audit_server(&args, asked);
    let subjects_file = format!("{}.subjects.json", wal.display());
    let (agent, owner) = tokens(&subjects_file);
    eprintln!("{}", json!({"status": "ready", "transport": "stdio", "audit": start.hello, "owner_tools": owner_tools, "max_result_chars": max_chars}));
    let server = OneCommand { inner: start.server, agent, owner, owner_tools, max_chars, paged: Mutex::new(Paged::default()) };
    mcp::serve_stdio(&server);
}

/// The words of a question that may name its topic: four letters or more, not a stop word, the first eight. A script written
/// without spaces between words (Chinese, Japanese) gives no words here: the whole question would be one "word" no document
/// holds, so such text is left out and the start asks for `--about`.
fn terms_of(question: &str) -> Vec<String> {
    let unspaced = |c: char| matches!(c as u32, 0x3040..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xAC00..=0xD7AF | 0xF900..=0xFAFF | 0xFF66..=0xFF9F);
    let mut out: Vec<String> = Vec::new();
    for word in question.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
        let word = word.trim_matches(|c| c == '-' || c == '_').to_lowercase();
        if word.chars().any(unspaced) {
            continue;
        }
        if word.chars().count() >= 4 && !STOP_WORDS.contains(&word.as_str()) && !out.contains(&word) {
            out.push(word);
        }
        if out.len() == 8 {
            break;
        }
    }
    out
}

/// The tokens of the run's agent and owner, from the subjects file the solo profile wrote beside the journal.
fn tokens(path: &str) -> (String, String) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")));
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| fail(&format!("{path} is not JSON: {e}")));
    let find = |id: &str| {
        v["subjects"]
            .as_array()
            .and_then(|s| s.iter().find(|x| x["id"] == id))
            .and_then(|x| x["token"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| fail(&format!("{path} names no subject '{id}': the solo profile writes 'agent' and 'owner'")))
    };
    (find("agent"), find("owner"))
}

#[derive(Default)]
struct Paged {
    next: u64,
    kept: VecDeque<(String, Vec<String>)>,
}

struct OneCommand {
    inner: Arc<AuditServer>,
    agent: String,
    owner: String,
    owner_tools: Vec<&'static str>,
    max_chars: usize,
    paged: Mutex<Paged>,
}

impl OneCommand {
    /// One request to the audit server as `token`'s subject; whatever token the client sent is dropped first.
    fn forward(&self, id: &Value, token: &str, method: &str, mut params: Value) -> Value {
        if !params.is_object() {
            params = json!({});
        }
        if let Some(p) = params.as_object_mut() {
            p.remove("auth_token");
        }
        if let Some(args) = params.get_mut("arguments").and_then(Value::as_object_mut) {
            args.remove("auth_token");
        }
        // MCP's _meta is an object; any other value is refused here, before the token goes in, and the session goes on
        match params.get("_meta") {
            None | Some(Value::Null) | Some(Value::Object(_)) => {}
            Some(_) => return mcp::rpc_error(id, INVALID_PARAMS, "params._meta must be an object".into()),
        }
        params["_meta"]["auth_token"] = json!(token);
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        let (answer, _) = LineServer::handle(&*self.inner, &mut None, &line);
        answer.unwrap_or_else(|| mcp::rpc_error(id, -32603, "the audit server gave no answer".into()))
    }

    fn tools(&self) -> Vec<Value> {
        let listed = |token: &str| self.forward(&json!(0), token, "tools/list", json!({}))["result"]["tools"].as_array().cloned().unwrap_or_default();
        let mut tools = listed(&self.agent);
        tools.extend(listed(&self.owner).into_iter().filter(|t| t["name"].as_str().is_some_and(|n| self.owner_tools.contains(&n))));
        tools.push(json!({
            "name": MORE,
            "description": "The next part of a tool answer that came in parts: the handle and the part number its first part named.",
            "inputSchema": {"type": "object", "properties": {"handle": {"type": "string"}, "part": {"type": "integer", "minimum": 2}},
                            "required": ["handle", "part"]}
        }));
        tools
    }

    fn call(&self, id: &Value, params: Value) -> Value {
        let name = params.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        if name == MORE {
            return mcp::rpc_ok(id, self.more(&params["arguments"]));
        }
        let token = if audit_mcp::agent_tool_names().contains(&name.as_str()) {
            &self.agent
        } else if self.owner_tools.contains(&name.as_str()) {
            &self.owner
        } else if audit_mcp::owner_tool_names().contains(&name.as_str()) {
            return mcp::rpc_error(id, FORBIDDEN, format!("the owner's tool {name} is not open here: start the server with --owner-tools all"));
        } else {
            return mcp::rpc_error(id, INVALID_PARAMS, format!("unknown tool '{name}'"));
        };
        let mut answer = self.forward(id, token, "tools/call", params);
        self.page(&mut answer);
        answer
    }

    /// A tool answer whose text is longer than `max_chars` is replaced by its first part; the parts are kept for `audit_more`.
    /// Every part, its header included, is at most `max_chars` characters.
    fn page(&self, answer: &mut Value) {
        let Some(text) = answer["result"]["content"][0]["text"].as_str() else { return };
        let length = text.chars().count();
        if length <= self.max_chars {
            return;
        }
        let mut about = json!({});
        for key in ABOUT_FIELDS {
            if let Some(v) = answer["result"]["structuredContent"].get(*key) {
                about[*key] = v.clone();
            }
        }
        let mut paged = self.paged.lock().unwrap_or_else(|e| e.into_inner());
        paged.next += 1;
        let handle = format!("r{}", paged.next);
        // the longest header a part of this answer can carry: the first part's, with part numbers as wide as the number of
        // characters (no answer has more parts than that), plus its line break
        let widest = 10usize.pow(length.ilog10() + 1) - 1;
        let room = |about: &Value| part_header(&handle, widest - 1, widest, Some(about)).chars().count() + 1;
        while room(&about) > self.max_chars / 2 {
            let Some(field) = ABOUT_FIELDS.iter().rev().find(|f| about.get(**f).is_some()) else { break };
            if let Some(fields) = about.as_object_mut() {
                fields.remove(*field);
            }
        }
        let parts = split(text, self.max_chars.saturating_sub(room(&about)).max(1));
        let first = part_text(&handle, 1, parts.len(), Some(&about), &parts[0]);
        paged.kept.push_back((handle, parts));
        while paged.kept.len() > KEPT_PAGED {
            paged.kept.pop_front();
        }
        drop(paged);
        let is_error = answer["result"]["isError"].clone();
        answer["result"] = json!({"content": [{"type": "text", "text": first}], "isError": is_error});
    }

    fn more(&self, args: &Value) -> Value {
        let handle = args["handle"].as_str().unwrap_or_default();
        let part = args["part"].as_u64().unwrap_or(0) as usize;
        let paged = self.paged.lock().unwrap_or_else(|e| e.into_inner());
        let Some((_, parts)) = paged.kept.iter().find(|(h, _)| h == handle) else {
            let text = format!("no answer in parts under the handle '{handle}' (only the newest {KEPT_PAGED} are kept)");
            return json!({"content": [{"type": "text", "text": text}], "isError": true});
        };
        if part < 1 || part > parts.len() {
            let text = format!("the answer {handle} has parts 1 to {}", parts.len());
            return json!({"content": [{"type": "text", "text": text}], "isError": true});
        }
        json!({"content": [{"type": "text", "text": part_text(handle, part, parts.len(), None, &parts[part - 1])}], "isError": false})
    }
}

/// The header line of one part of an answer.
fn part_header(handle: &str, part: usize, parts: usize, about: Option<&Value>) -> String {
    let mut header = json!({"answer_in_parts": handle, "part": part, "parts": parts});
    if part < parts {
        header["next"] = json!(format!("call {MORE} with {{\"handle\": \"{handle}\", \"part\": {}}}", part + 1));
    } else {
        header["next"] = json!("this is the last part");
    }
    if let Some(about) = about {
        header["about"] = about.clone();
    }
    header.to_string()
}

/// One part of an answer: a header line, then the text.
fn part_text(handle: &str, part: usize, parts: usize, about: Option<&Value>, text: &str) -> String {
    format!("{}\n{text}", part_header(handle, part, parts, about))
}

/// `text` cut into pieces of at most `size` characters, on character boundaries.
fn split(text: &str, size: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut piece = String::new();
    let mut count = 0;
    for c in text.chars() {
        piece.push(c);
        count += 1;
        if count == size {
            out.push(std::mem::take(&mut piece));
            count = 0;
        }
    }
    if !piece.is_empty() || out.is_empty() {
        out.push(piece);
    }
    out
}

impl LineServer for OneCommand {
    type Conn = ();
    fn max_message_bytes(&self) -> usize {
        LineServer::max_message_bytes(&*self.inner)
    }
    fn handle(&self, _conn: &mut (), line: &str) -> (Option<Value>, bool) {
        let (id, method, params) = match mcp::request(line) {
            Ok(Some(r)) => r,
            Ok(None) => return (None, false),
            Err(answer) => return (Some(answer), false),
        };
        let answer = match method.as_str() {
            "initialize" => {
                let protocol = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2025-06-18");
                mcp::rpc_ok(
                    &id,
                    json!({"protocolVersion": protocol, "capabilities": {"tools": {"listChanged": false}},
                           "serverInfo": {"name": "yuce", "version": env!("CARGO_PKG_VERSION")}, "instructions": INSTRUCTIONS}),
                )
            }
            "ping" => mcp::rpc_ok(&id, json!({})),
            "tools/list" => mcp::rpc_ok(&id, json!({"tools": self.tools()})),
            "tools/call" => self.call(&id, params),
            "shutdown" => mcp::rpc_error(&id, FORBIDDEN, "close the client to stop this server; the run stays in its journal".into()),
            other => mcp::rpc_error(&id, -32601, format!("method not found: {other}")),
        };
        (Some(answer), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_text_is_cut_on_character_boundaries_and_nothing_is_lost() {
        // two-byte letters (Greek): a cut inside a character would not be valid UTF-8
        let text = "αβγδε".repeat(1000);
        let parts = split(&text, 333);
        assert!(parts.iter().all(|p| p.chars().count() <= 333));
        assert_eq!(parts.concat(), text);
        assert_eq!(split("", 10), vec![String::new()]);
    }

    #[test]
    fn the_terms_of_a_question_leave_out_short_and_stop_words() {
        assert_eq!(terms_of("What do these documents say about refunds and the refund window?"), vec!["refunds", "refund", "window"]);
        // a script with spaces between words gives its words, lower-cased
        assert_eq!(terms_of("Ποιες αποφάσεις για το HYP-03;"), vec!["ποιες", "αποφάσεις", "hyp-03"]);
        // written without spaces, a question gives no terms: the start asks for --about
        assert!(terms_of("这些文档关于退款说了什么？").is_empty());
        assert!(terms_of("返金の期限はいつですか").is_empty());
        assert_eq!(terms_of("退款 policy window"), vec!["policy", "window"]);
    }
}
