//! `sbgk audit-watch` (also `watch`): the YuCe Live page of a journal while a server writes it, served on this computer.
//!
//! The command reads the journal and nothing else: no token, no call to the server that writes it. It replays the journal from its
//! genesis once and then reads only the frames written since (`sbgk_core::audit::follow`), each checked as `audit-verify` checks it.
//! What the page shows comes from the export `audit-prov` gives for the frames read (`prov::Tracker`, the same code), from the
//! kernel's coverage table at a frame, and from the frames themselves (who wrote a frame, and the task the kernel closed with it).
//! The page data has the format of `examples/live-journal/make_page.py`, and the page is that example's `page.html`: a journal
//! watched to its end shows what its recorded page shows.
//!
//! The server listens on a loopback address only, answers GET only, and gives four things: `/` the page with the data of the frames
//! read so far, `/delta` what changed since the frames a page already has, `/data` the whole data, `/status` how far the reading is.
//! The journal is never written, locked or copied.

use super::{fail, program, Args};
use sbgk_core::audit::directives;
use sbgk_core::audit::follow::{Follower, Stop, Tail};
use sbgk_core::audit::prov::Tracker;
use sbgk_core::audit::AuditStore;
use sbgk_core::hash::{sha256, to_hex};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The page: the template of the recorded page, one file for both.
const TEMPLATE: &str = include_str!("../../../examples/live-journal/page.html");
/// The script a watched page gets after the template's own: it asks this server for what changed and hands it to the page.
const CLIENT: &str = include_str!("audit_watch_client.js");
const PLACE: &str = "/*DATA*/null";
const POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
/// The policy of a watched page: the template's, and requests to the server that gave the page.
const POLICY_LIVE: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";
const FORMAT: &str = "yuce-live-journal/1";
/// Up to this many frames and records a journal is short: its coverage is kept at every frame (`make_page.py`).
const SMALL: usize = 200;
const DEFAULT_LISTEN: &str = "127.0.0.1:7117";
/// The longest document `--docs` reads to show quotes in their lines.
const MAX_DOC_BYTES: u64 = 64 * 1024 * 1024;
/// How long a request may take to send its head.
const REQUEST_TIME: Duration = Duration::from_secs(3);
/// How long a step of the reading goes before the page data is made again, while a long journal is caught up with.
const STEP: Duration = Duration::from_millis(400);
/// How often a page asks for what changed, in milliseconds.
const PAGE_EVERY_MS: u64 = 700;

// ------------------------------------------------------------------ small helpers

/// Python's truth of a JSON value, as `make_page.py` tests fields.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// The last part of an id of the export, percent-decoded.
fn tail(iri: &str) -> String {
    unquote(iri.rsplit(':').next().unwrap_or_default())
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn frame_of(iri: &Value) -> usize {
    tail(iri.as_str().unwrap_or_default()).parse().unwrap_or(0)
}

fn has_type(n: &Value, t: &str) -> bool {
    n["@type"].as_array().is_some_and(|a| a.iter().any(|x| x == t))
}

/// The valid UTF-8 of `bytes`, what is not left out.
fn utf8_ignore(bytes: &[u8]) -> String {
    bytes.utf8_chunks().map(|c| c.valid()).collect()
}

/// A JSON text in ASCII, with no `<`: it stands inside a script of the page and cannot end it.
fn ascii(json: &str) -> String {
    let mut out = String::with_capacity(json.len() + json.len() / 8);
    let mut units = [0u16; 2];
    for c in json.chars() {
        if c == '<' || !(' '..='~').contains(&c) {
            for u in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A label of the page: `q` a quote, `c` a claim, `h` a hypothesis, `A` an answer, numbered in the order of the journal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Label(char, usize);

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.0, self.1)
    }
}

fn labels(mut list: Vec<Label>) -> Value {
    list.sort();
    json!(list.iter().map(Label::to_string).collect::<Vec<_>>())
}

// ------------------------------------------------------------------ what is kept of a frame

/// The task the kernel closed with a frame.
enum Task {
    Read(String, Value),
    Answer(String, Value, Vec<String>),
    Other(String, Value),
}

/// What the page shows of a frame beyond the export: who wrote it, its command and the task the kernel closed with it; and what
/// places a record among the lines handed in with it.
struct Note {
    actor: Value,
    kind: String,
    task: Option<Task>,
    /// The kind of each line handed in and its quote or text.
    lines: Vec<(String, Option<String>)>,
    /// The question of the one `done` line of the frame, when it has exactly one.
    asked: Option<Value>,
}

impl Note {
    fn of(number: usize, body: &Value) -> Note {
        if number == 0 {
            return Note { actor: json!("kernel"), kind: "genesis".into(), task: None, lines: Vec::new(), asked: None };
        }
        let command = &body["command"];
        let mut kind = match command["kind"].as_str().filter(|k| !k.is_empty()) {
            Some(kind) => kind.to_string(),
            None if command.get("checkpoint").is_some() => "checkpoint".to_string(),
            None => "entry".to_string(),
        };
        let checkpoint = &command["checkpoint"];
        let key = checkpoint["key"].as_str().unwrap_or_default();
        let context = &checkpoint["context"];
        let by = context.get("agent").cloned().unwrap_or(Value::Null);
        let mut task = None;
        if let Some(what) = key.strip_prefix("task:").filter(|_| truthy(checkpoint)) {
            task = Some(if let Some(doc) = what.strip_prefix("doc:") {
                Task::Read(doc.split('#').next().unwrap_or_default().to_string(), by)
            } else if let Some(question) = what.strip_prefix("rq:") {
                let kept = context["composition"]["retained_answer_ids"].as_array().map(Vec::as_slice).unwrap_or_default();
                Task::Answer(question.to_string(), by, kept.iter().filter_map(Value::as_str).map(str::to_string).collect())
            } else {
                Task::Other(what.split(':').next().unwrap_or_default().to_string(), by)
            });
        } else if key == "audit:mcp:coverage" {
            kind = "open".to_string();
        }
        let handed = command["lines"].as_array().map(Vec::as_slice).unwrap_or_default();
        let lines = handed
            .iter()
            .map(|line| {
                let value = line.get("exact_quote").unwrap_or(&line["text"]);
                (line["kind"].as_str().unwrap_or_default().to_string(), value.as_str().map(str::to_string))
            })
            .collect();
        let done: Vec<&Value> = handed.iter().filter(|line| line["kind"] == "done").collect();
        let asked = (done.len() == 1).then(|| done[0].get("rq_id").cloned().unwrap_or(Value::Null));
        Note { actor: body.get("actor").cloned().unwrap_or(Value::Null), kind, task, lines, asked }
    }

    /// The place of a record among the lines of the frame that made it, as `make_page.py` places it.
    fn place(&self, kind: &str, value: Option<&str>) -> usize {
        self.lines.iter().position(|(k, v)| k == kind && (kind == "done" || v.as_deref() == value)).unwrap_or(1 << 20)
    }
}

/// A period in which a record stood, as the page takes it: from a frame, to a frame or null, why it ended, the labels it fell by.
type Period = (usize, Option<usize>, Value, Value);

/// The cells of the coverage table at a frame: for each document, one letter a unit in the order of its bytes.
type Cells = BTreeMap<String, String>;

/// The kernel's nine coverage statuses, folded into seven cells on the page (`make_page.py`).
fn cell(status: &str) -> char {
    match status {
        "quoted" => 'q',
        "empty" => 'e',
        "left_by_budget" => 'b',
        "withdrawn" => 'w',
        "unread" => 'n',
        "reading_given_up" => 'g',
        _ => 'p',
    }
}

/// The kernel's coverage table of a state as cells, or why the journal gives none.
fn cells_of(state: &sbgk_core::audit::state::AuditState) -> Result<Cells, String> {
    let table = directives::coverage(state);
    if let Some(reason) = table.unavailable {
        return Err(reason);
    }
    let mut rows: Vec<(&str, u64, &str)> =
        table.units.iter().map(|r| (r[0].as_str().unwrap_or_default(), r[1].as_u64().unwrap_or(0), r[5].as_str().unwrap_or_default())).collect();
    rows.sort_by_key(|r| (r.0, r.1));
    let mut cells = Cells::new();
    for (doc, _, status) in rows {
        cells.entry(doc.to_string()).or_default().push(cell(status));
    }
    Ok(cells)
}

// ------------------------------------------------------------------ the page data

/// The page data of the frames read, in pieces that are already JSON: a piece is sent to a page again only after it changed.
struct Model {
    /// The frames read.
    frames: usize,
    /// The members of the data that are small and sent whole each time, without the braces.
    head: String,
    /// One JSON object a frame.
    entries: Vec<String>,
    /// Label, JSON, and the last frame of the reading in which the JSON changed; in the order of the labels.
    quotes: Vec<(String, String, usize)>,
    recs: Vec<(String, String, usize)>,
    periods: Vec<(String, String, usize)>,
    /// Frame and JSON of each coverage entry.
    coverage: Vec<(usize, String)>,
    /// The last frame of the reading at which the coverage entries were not only added to.
    coverage_whole: usize,
    /// The whole data and the page made of this model last, with what they were made for: asked for again, they are not made again.
    whole: std::sync::OnceLock<Arc<String>>,
    page: Mutex<Option<(String, Arc<String>)>>,
}

fn object(items: impl Iterator<Item = (impl AsRef<str>, impl AsRef<str>)>) -> String {
    let members: Vec<String> = items.map(|(k, v)| format!("{}:{}", Value::String(k.as_ref().to_string()), v.as_ref())).collect();
    format!("{{{}}}", members.join(","))
}

impl Model {
    /// The whole data as `/data` gives it, made once.
    fn whole(&self) -> Arc<String> {
        self.whole.get_or_init(|| Arc::new(self.data(None))).clone()
    }

    /// The page of this model for `epoch` and `status`, made once for each.
    fn page(&self, epoch: u64, status: &str) -> Arc<String> {
        let key = format!("{epoch} {status}");
        let mut kept = self.page.lock().unwrap_or_else(|p| p.into_inner());
        match kept.as_ref() {
            Some((made_for, page)) if *made_for == key => page.clone(),
            _ => {
                let page = Arc::new(page(self, epoch, status));
                *kept = Some((key, page.clone()));
                page
            }
        }
    }

    /// The whole data, with `live` (a JSON object) when the page is a watched one.
    fn data(&self, live: Option<&str>) -> String {
        format!(
            "{{{},\"frames\":[{}],\"quotes\":{},\"recs\":{},\"periods\":{},\"coverage\":[{}]{}}}",
            self.head,
            self.entries.join(","),
            object(self.quotes.iter().map(|(k, v, _)| (k, v))),
            object(self.recs.iter().map(|(k, v, _)| (k, v))),
            object(self.periods.iter().map(|(k, v, _)| (k, v))),
            self.coverage.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(","),
            live.map(|l| format!(",\"live\":{l}")).unwrap_or_default()
        )
    }

    /// What changed for a page that has the data of the first `have` frames.
    fn delta(&self, have: usize, status: &str) -> String {
        let since = |list: &[(String, String, usize)]| object(list.iter().filter(|(_, _, stamp)| *stamp >= have).map(|(k, v, _)| (k, v)));
        // the entry at the page's last frame was that frame's own; entries before it stand, unless the list was made again since
        let from = if self.coverage_whole >= have { 0 } else { have - 1 };
        format!(
            "{{{},\"from\":{have},\"frames\":[{}],\"quotes\":{},\"recs\":{},\"periods\":{},\"coverage_from\":{from},\"coverage\":[{}],\"status\":{status}}}",
            self.head,
            self.entries[have.min(self.entries.len())..].join(","),
            since(&self.quotes),
            since(&self.recs),
            since(&self.periods),
            self.coverage.iter().filter(|(at, _)| *at >= from).map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(",")
        )
    }
}

/// The reading of one journal: the follower, the export built beside it, and what the page needs of each frame.
struct Reader {
    docs: Option<PathBuf>,
    note: String,
    follower: Follower,
    tracker: Tracker,
    /// The run's id, its questions and the identities of its documents, from the genesis frame.
    genesis: Value,
    notes: Vec<Note>,
    /// Record id -> the question the kernel named when it closed the answer task.
    asked: HashMap<String, Value>,
    /// The coverage cells at the first frames, at every seal and at every frame where a record stopped standing; no cells where
    /// the kernel had no table at that frame.
    coverage: BTreeMap<usize, Cells>,
    /// The bytes of each document given with `--docs`, once its SHA-256 was found in the journal; `None` when it was not.
    texts: HashMap<String, Option<Vec<u8>>>,
    /// Each piece of the data as it was sent last, and the last frame of the reading at which it changed.
    pieces: HashMap<String, (String, usize)>,
    /// The documents in the order of their names, and whether the journal was long, at the data made last.
    order: Vec<String>,
    big: bool,
    coverage_whole: usize,
}

impl Reader {
    fn new(wal: &Path, docs: Option<PathBuf>, note: String) -> Self {
        Self {
            docs,
            note,
            follower: Follower::new(wal),
            tracker: Tracker::new(),
            genesis: Value::Null,
            notes: Vec::new(),
            asked: HashMap::new(),
            coverage: BTreeMap::new(),
            texts: HashMap::new(),
            pieces: HashMap::new(),
            order: Vec::new(),
            big: false,
            coverage_whole: 0,
        }
    }

    /// One step along the journal, for at most `budget`: the frames it reads go to the export and to the notes.
    fn step(&mut self, budget: Duration) -> Result<Tail, Stop> {
        let started = Instant::now();
        let Reader { follower, tracker, genesis, notes, asked, coverage, .. } = self;
        follower.advance(&mut |f| {
            if f.number == 0 {
                *genesis = json!({"run_id": f.payload["run_id"], "questions": f.payload["questions"], "source_documents": f.payload["source_documents"]});
            }
            let ended = tracker.ended();
            tracker.frame(f.state, f.payload, f.head);
            let note = Note::of(f.number, f.payload);
            let context = &f.payload["command"]["checkpoint"]["context"];
            if let (Some(done), true) = (context["done"].as_str().filter(|d| !d.is_empty()), truthy(&context["rq_id"])) {
                asked.insert(done.to_string(), context["rq_id"].clone());
            }
            let seal = note.kind == "seal" && f.payload["outcome"]["kind"] != "error";
            if f.number < SMALL || seal || tracker.ended() > ended {
                coverage.insert(f.number, cells_of(f.state).unwrap_or_default());
            }
            notes.push(note);
            started.elapsed() < budget
        })
    }

    /// The page data of the frames read so far. `Ok(true)` with it when the documents or the size class of the journal changed
    /// since the data made last: a page that holds the earlier data takes this one whole.
    fn model(&mut self, version: &str) -> Result<(Model, bool), String> {
        let state = self.follower.state().ok_or("the journal has no frame yet")?;
        let export = self.tracker.document(state, true).map_err(|e| e.message)?;
        let graph = export.document["@graph"].as_array().ok_or("the export has no graph")?;
        let last = export.frames - 1;
        let nodes: HashMap<&str, &Value> = graph.iter().filter_map(|n| n["@id"].as_str().map(|id| (id, n))).collect();
        let records: Vec<&Value> = graph.iter().filter(|n| has_type(n, "yuce:Record")).collect();

        // the documents: every document of the export (those put during the run included), in the order of their names
        // the table at the last frame says whether the journal gives one at all, as `make_page.py` takes it
        let (head_cells, no_coverage) = match cells_of(state) {
            Ok(cells) => (Some(cells), String::new()),
            Err(reason) => (None, reason),
        };
        let no_sources = Map::new();
        let sources = self.genesis["source_documents"].as_object().unwrap_or(&no_sources);
        let mut doc_ids: BTreeSet<String> = sources.keys().cloned().collect();
        doc_ids.extend(graph.iter().filter(|n| has_type(n, "yuce:Document")).filter_map(|n| n["yuce:docId"].as_str().map(str::to_string)));
        let name_of = |d: &str| sources.get(d).and_then(|s| s["path"].as_str()).filter(|p| !p.is_empty()).unwrap_or(d).to_string();
        let mut order: Vec<String> = doc_ids.into_iter().collect();
        order.sort_by_key(|d| (name_of(d), d.clone()));
        let did: HashMap<&str, String> = order.iter().enumerate().map(|(i, d)| (d.as_str(), format!("D{}", i + 1))).collect();
        let units = |d: &str| head_cells.as_ref().and_then(|c| c.get(d)).map_or(0, |cells| cells.len());
        let mut unchecked = Vec::new();
        if let Some(folder) = &self.docs {
            for d in &order {
                let text = self.texts.entry(d.clone()).or_insert_with(|| {
                    // the name comes from the journal, not from the operator: it is followed only to a regular file inside the folder
                    let data = super::docs_input::read_inside(folder, &name_of(d), MAX_DOC_BYTES).ok()?;
                    (sources.get(d.as_str()).and_then(|s| s["raw_sha256"].as_str()) == Some(to_hex(&sha256(&data)).as_str())).then_some(data)
                });
                if text.is_none() {
                    unchecked.push(name_of(d));
                }
            }
        }
        let shown = self.texts.values().any(Option::is_some);

        // labels in the order the records were handed in: frame, then their place among the frame's lines
        let label_of = |kind: &str| match kind {
            "observe" => Some('q'),
            "claim" => Some('c'),
            "hypothesis" => Some('h'),
            "done" => Some('A'),
            _ => None,
        };
        let id_of = |n: &Value| n["yuce:recordId"].as_str().unwrap_or_default().to_string();
        let mut ordered: Vec<(usize, usize, String, &Value)> = records
            .iter()
            .filter(|n| label_of(n["yuce:kind"].as_str().unwrap_or_default()).is_some())
            .map(|n| {
                let f = frame_of(&n["prov:wasGeneratedBy"]);
                let place = self.notes.get(f).map_or(1 << 20, |note| note.place(n["yuce:kind"].as_str().unwrap_or_default(), n["prov:value"].as_str()));
                (f, place, id_of(n), *n)
            })
            .collect();
        ordered.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
        let mut label: HashMap<String, Label> = HashMap::new();
        let mut count: HashMap<char, usize> = HashMap::new();
        for (_, _, id, n) in &ordered {
            let prefix = label_of(n["yuce:kind"].as_str().unwrap_or_default()).expect("a labelled kind");
            let number = count.entry(prefix).or_default();
            *number += 1;
            label.insert(id.clone(), Label(prefix, *number));
        }
        let short: HashMap<String, Label> = label.iter().map(|(id, lab)| (format!("@{}", &id[..id.len().min(16)]), *lab)).collect();
        let set_of = |v: &Value| -> Vec<Label> {
            v.as_array().into_iter().flatten().filter_map(|x| label.get(&tail(x.as_str().unwrap_or_default())).copied()).collect()
        };

        let mut quotes: Vec<(Label, Value)> = Vec::new();
        let mut recs: Vec<(Label, Value)> = Vec::new();
        let mut answer_parts: HashMap<Label, Vec<Label>> = HashMap::new();
        for (f, _, id, n) in &ordered {
            let (lab, kind) = (label[id], n["yuce:kind"].as_str().unwrap_or_default());
            let by = tail(n["prov:wasAttributedTo"].as_str().unwrap_or_default());
            let value = n["prov:value"].as_str().unwrap_or_default();
            let kid = format!("@{}", &id[..id.len().min(16)]);
            if kind == "observe" {
                let from = n["prov:wasQuotedFrom"].as_str().unwrap_or_default();
                let version = from.split_once(":version:").map_or("", |x| x.1);
                let doc = unquote(version.rsplitn(3, ':').nth(2).unwrap_or_default());
                let (a, b) = (n["yuce:start"].as_u64().unwrap_or(0) as usize, n["yuce:end"].as_u64().unwrap_or(0) as usize);
                let mut q = json!({"d": did.get(doc.as_str()), "a": a, "b": b, "by": by, "f": f, "kid": kid, "hit": value});
                if let Some(Some(data)) = self.texts.get(&doc) {
                    if a <= b && b <= data.len() && String::from_utf8_lossy(&data[a..b]) == value {
                        let start = data[..a].iter().rposition(|c| *c == b'\n').map_or(0, |i| i + 1).max(a.saturating_sub(240));
                        let end = data[b..].iter().position(|c| *c == b'\n').map_or(data.len(), |i| b + i).min(b + 240);
                        q["pre"] = json!(utf8_ignore(&data[start..a]));
                        q["post"] = json!(utf8_ignore(&data[b..end]));
                    }
                }
                quotes.push((lab, q));
            } else {
                // a record rests on what the export derives it from, in the order of the ids there
                let mut on = set_of(&n["prov:wasDerivedFrom"]);
                let word = if kind == "done" { "answer" } else { kind };
                let mut r = json!({"k": word, "f": f, "by": by, "kid": kid});
                if kind == "done" {
                    let question = self.asked.get(id).cloned().or_else(|| self.notes.get(*f).and_then(|note| note.asked.clone())).unwrap_or(json!("?"));
                    r["q"] = question;
                    r["note"] = json!(value);
                    for c in &on {
                        answer_parts.entry(*c).or_default().push(lab);
                    }
                    on.sort_by_key(|c| c.1);
                } else {
                    r["t"] = json!(value);
                }
                r["on"] = json!(on.iter().map(Label::to_string).collect::<Vec<_>>());
                recs.push((lab, r));
            }
        }
        for (lab, r) in &mut recs {
            if let (Some(parts), true) = (answer_parts.get(lab), r["k"] != "answer") {
                r["part"] = json!(parts.iter().map(Label::to_string).collect::<Vec<_>>());
            }
        }

        // periods: [from, to or null, reason or null, [labels it fell by]]; a record the kernel gave no period has none
        let mut periods: BTreeMap<Label, Vec<Period>> = label.values().map(|lab| (*lab, Vec::new())).collect();
        for n in graph.iter().filter(|n| has_type(n, "yuce:Standing")) {
            let Some(lab) = label.get(&tail(n["prov:specializationOf"].as_str().unwrap_or_default())) else { continue };
            let end = n.get("prov:wasInvalidatedBy").map(frame_of);
            let why = n["prov:qualifiedInvalidation"].as_str().and_then(|id| nodes.get(id));
            let reason = why.map_or(Value::Null, |w| w["yuce:reason"].clone());
            let by = labels(why.map(|w| set_of(&w["yuce:fallenBy"])).unwrap_or_default());
            periods.get_mut(lab).expect("a labelled record").push((frame_of(&n["prov:wasGeneratedBy"]), end, reason, by));
        }
        for list in periods.values_mut() {
            list.sort_by_key(|p| (p.0, p.1.unwrap_or(usize::MAX)));
        }

        // frames: who wrote it, what kind, the task the kernel closed, what it made and what it ended
        let mut made: BTreeMap<usize, Vec<Label>> = BTreeMap::new();
        let mut ended: BTreeMap<usize, Vec<Label>> = BTreeMap::new();
        for (f, _, id, _) in &ordered {
            made.entry(*f).or_default().push(label[id]);
        }
        for (lab, list) in &periods {
            for end in list.iter().filter_map(|p| p.1) {
                ended.entry(end).or_default().push(*lab);
            }
        }
        let seals: BTreeMap<usize, &Value> = graph.iter().filter(|n| has_type(n, "yuce:Seal")).map(|n| (frame_of(&n["prov:wasGeneratedBy"]), n)).collect();
        let sealed: BTreeMap<usize, usize> = seals.keys().enumerate().map(|(i, f)| (*f, i + 1)).collect();
        let mut entries = Vec::with_capacity(last + 1);
        for (f, note) in self.notes.iter().enumerate().take(last + 1) {
            let mut e = json!({"a": note.actor, "k": note.kind});
            match &note.task {
                Some(Task::Read(doc, by)) => e["task"] = json!({"read": did.get(doc.as_str()).unwrap_or(doc), "by": by}),
                Some(Task::Answer(question, by, kept)) => {
                    let kept: Vec<String> = kept.iter().filter_map(|x| short.get(x)).map(Label::to_string).collect();
                    e["task"] = json!({"answer": question, "by": by, "kept": kept});
                }
                Some(Task::Other(what, by)) => e["task"] = json!({"other": what, "by": by}),
                None => {}
            }
            if let Some(list) = made.get(&f) {
                e["made"] = labels(list.clone());
            }
            if let Some(list) = ended.get(&f) {
                e["ended"] = labels(list.clone());
            }
            if let Some(number) = sealed.get(&f) {
                let root = seals[&f]["yuce:auditRoot"].as_str().unwrap_or_default();
                e["seal"] = json!(number);
                e["root"] = json!(&root[..root.len().min(16)]);
            }
            entries.push(e.to_string());
        }

        // the kernel's coverage table at the frames the page shows it: every frame of a short journal; in a long one the seals,
        // the frames where records stopped standing, and the last frame
        let small = last < SMALL && label.len() <= SMALL;
        let mut coverage = Vec::new();
        if let Some(head_cells) = &head_cells {
            let at: BTreeSet<usize> =
                if small { (0..=last).collect() } else { [0, last].into_iter().chain(sealed.keys().copied()).chain(ended.keys().copied()).collect() };
            for f in at {
                let Some(cells) = (if f == last { Some(head_cells) } else { self.coverage.get(&f) }) else { continue };
                let row: Map<String, Value> =
                    order.iter().map(|d| (did[d.as_str()].clone(), json!(cells.get(d).cloned().unwrap_or_else(|| "n".repeat(units(d)))))).collect();
                coverage.push((f, json!({"at": f, "cells": row}).to_string()));
            }
        }

        // a page that holds earlier data keeps what did not change; when the documents changed their order, nothing is kept
        let whole = !self.order.is_empty() && self.order != order;
        if whole {
            self.pieces.clear();
        }
        if whole || self.big != !small {
            self.coverage_whole = last;
        }
        self.big = !small;
        let pieces = &mut self.pieces;
        let mut stamped = |prefix: char, lab: Label, json: String| -> (String, String, usize) {
            let piece = pieces.entry(format!("{prefix}{lab}")).or_insert_with(|| (String::new(), last));
            if piece.0 != json {
                *piece = (json.clone(), last);
            }
            (lab.to_string(), json, piece.1)
        };
        let quotes: Vec<_> = quotes.into_iter().map(|(lab, q)| stamped('Q', lab, q.to_string())).collect();
        let recs: Vec<_> = recs.into_iter().map(|(lab, r)| stamped('R', lab, r.to_string())).collect();
        let mut by_label: Vec<(Label, String)> = periods.into_iter().map(|(lab, list)| (lab, json!(list).to_string())).collect();
        // the periods in the order of the records, as the quotes and the records come
        let position: HashMap<Label, usize> = ordered.iter().enumerate().map(|(i, (_, _, id, _))| (label[id], i)).collect();
        by_label.sort_by_key(|(lab, _)| position[lab]);
        let periods: Vec<_> = by_label.into_iter().map(|(lab, list)| stamped('P', lab, list)).collect();
        self.order = order.clone();

        let questions: Vec<Value> = self.genesis["questions"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|q| json!({"id": q["id"], "text": q.get("text").cloned().unwrap_or(json!(""))}))
            .collect();
        let open = records.iter().filter(|n| n["yuce:kind"] == "question").count();
        let not_shown = if open > 0 { json!({"question": open}) } else { json!({}) };
        let head = json!({
            "format": FORMAT, "run": self.genesis["run_id"], "kernel": version, "note": self.note, "big": !small,
            "verify": {"status": "VERIFIED", "entries": last + 1, "records": state.head(), "audit_root": to_hex(&state.audit_root()),
                       "engine_root": to_hex(&state.engine_root()), "wal_head": to_hex(&export.wal_head)},
            "docs": order.iter().map(|d| json!({"id": did[d.as_str()], "name": name_of(d), "units": units(d)})).collect::<Vec<_>>(),
            "docs_shown": shown, "docs_unchecked": unchecked, "questions": questions,
            "coverage_note": no_coverage,
            "checked": {"frames": 0, "all": false}, "not_shown": not_shown,
        })
        .to_string();
        let head = head[1..head.len() - 1].to_string();
        let model = Model {
            frames: last + 1,
            head,
            entries,
            quotes,
            recs,
            periods,
            coverage,
            coverage_whole: self.coverage_whole,
            whole: std::sync::OnceLock::new(),
            page: Mutex::new(None),
        };
        Ok((model, whole))
    }
}

// ------------------------------------------------------------------ the reading and what the server gives of it

/// How far the reading is, as a page and `/status` are told.
#[derive(Clone, Default)]
struct Status {
    /// `waiting` (no frame read yet), `live` (a writer holds the journal), `recorded` (none does), `closed` (the run was closed),
    /// `broken` (a frame does not pass the checks).
    mode: &'static str,
    frames: usize,
    writer: bool,
    pending: u64,
    more: bool,
    broken: Option<(usize, String)>,
    /// Why the file cannot be read at this moment.
    unreadable: Option<String>,
}

impl Status {
    fn json(&self) -> String {
        let mut out = json!({"mode": self.mode, "frames": self.frames, "writer": self.writer, "pending": self.pending, "more": self.more});
        if let Some((frame, message)) = &self.broken {
            out["broken"] = json!({"frame": frame, "message": message});
        }
        if let Some(message) = &self.unreadable {
            out["unreadable"] = json!(message);
        }
        out.to_string()
    }
}

#[derive(Default)]
struct Shared {
    /// Goes up when a page must take the data whole again: the file became another journal, or its documents changed.
    epoch: u64,
    model: Option<Arc<Model>>,
    status: Status,
}

/// The lock of the watch state, also after a thread stopped while it held it: what it holds is whole values, set at once.
fn locked(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|p| p.into_inner())
}

/// Says so on the pages if the reading thread stops: they must not go on showing a journal as followed that no one reads.
struct Reading(Arc<Mutex<Shared>>);

impl Drop for Reading {
    fn drop(&mut self) {
        let mut shared = locked(&self.0);
        let frames = shared.status.frames;
        shared.status.mode = "broken";
        shared.status.more = false;
        shared.status.broken = Some((frames, "the reading of the journal stopped on an error of the command itself: start it again".to_string()));
    }
}

/// The reading thread: steps along the journal for as long as the command runs, and makes the page data again after new frames.
fn follow(wal: PathBuf, docs: Option<PathBuf>, note: String, every: Duration, shared: Arc<Mutex<Shared>>) {
    let _reading = Reading(shared.clone());
    let version = format!("{} {}", program(), env!("CARGO_PKG_VERSION"));
    let mut reader = Reader::new(&wal, docs.clone(), note.clone());
    let mut made = 0;
    let mut budget = STEP;
    loop {
        let step = reader.step(budget);
        let mut status = Status { frames: reader.follower.frames(), ..Status::default() };
        let mut wait = true;
        match step {
            Ok(tail) => {
                (status.writer, status.pending, status.more) = (tail.writer, tail.pending, tail.more);
                wait = !tail.more;
            }
            // a journal that is not there yet is waited for; one that cannot be read, or that was there and is gone, says so
            Err(Stop::Unreadable(e)) if wal.exists() => status.unreadable = Some(e.message),
            Err(Stop::Unreadable(_)) if status.frames > 0 => status.unreadable = Some("the file is no longer there".to_string()),
            Err(Stop::Unreadable(_)) => {}
            Err(Stop::Broken { frame, error }) => status.broken = Some((frame, error.message)),
            Err(Stop::Replaced(_)) => {
                // another journal at this path: read it from its start, and tell the pages to take it whole
                reader = Reader::new(&wal, docs.clone(), note.clone());
                made = 0;
                let mut shared = locked(&shared);
                shared.epoch += 1;
                shared.model = None;
                shared.status = Status { mode: "waiting", ..Status::default() };
                continue;
            }
        }
        let closed = reader.follower.state().is_some_and(|s| s.is_closed());
        status.mode = match () {
            _ if status.broken.is_some() => "broken",
            _ if status.frames == 0 => "waiting",
            _ if closed => "closed",
            _ if status.writer => "live",
            _ => "recorded",
        };
        let mut model = None;
        if status.frames != made && status.frames > 0 {
            let started = Instant::now();
            match reader.model(&version) {
                Ok(new) => {
                    made = status.frames;
                    model = Some(new);
                }
                Err(message) => status.broken = Some((status.frames, format!("the page data could not be made: {message}"))),
            }
            // a long journal is caught up with in steps a few times longer than the making of the data
            budget = STEP.max(started.elapsed() * 4);
        }
        {
            let mut shared = locked(&shared);
            if let Some((model, whole)) = model {
                shared.epoch += u64::from(whole);
                shared.model = Some(Arc::new(model));
            }
            shared.status = status;
        }
        if wait {
            std::thread::sleep(every);
        }
    }
}

/// The page of the frames read: the template with its data, the policy that lets it ask this server, and the script that asks.
fn page(model: &Model, epoch: u64, status: &str) -> String {
    let live = format!("{{\"epoch\":{epoch},\"every\":{PAGE_EVERY_MS},\"status\":{status}}}");
    let data = ascii(&model.data(Some(&live)));
    TEMPLATE.replacen(POLICY, POLICY_LIVE, 1).replacen("</body>", &format!("<script>\n{CLIENT}</script>\n</body>"), 1).replacen(PLACE, &data, 1)
}

/// The page while no frame is read yet: it asks again by itself.
fn waiting(wal: &Path, status: &Status) -> String {
    let what = match (&status.broken, &status.unreadable) {
        // a file whose first frame does not pass is no journal the kernel reads: there is no frame to show
        (Some((frame, message)), _) => format!("Frame {frame} of this file does not pass the checks of a journal: {}", escape_html(message)),
        (None, Some(message)) => format!("The journal cannot be read yet: {}", escape_html(message)),
        (None, None) => "Waiting for the first frame of the journal.".to_string(),
    };
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>YuCe Live</title>\
         <style>body{{font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:44rem;padding:0 1rem;color:#17142a;background:#f6f5fb}}\
         code{{font:14px ui-monospace,Consolas,monospace}}@media (prefers-color-scheme:dark){{body{{color:#ece9f7;background:#0c0a13}}}}</style></head>\
         <body><h1>YuCe Live</h1><p>{what}</p><p><code>{}</code></p><p>The page appears with the first frame of a journal.</p></body></html>\n",
        escape_html(&wal.display().to_string())
    )
}

fn respond(stream: &mut TcpStream, code: &str, kind: &str, body: &[u8]) {
    // no other site may put the page in a frame of its own or read an answer of this server as a resource of its own
    let head = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nContent-Security-Policy: frame-ancestors 'none'\r\nX-Frame-Options: DENY\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body)).and_then(|()| stream.flush());
}

/// The head of one request: its method, its target, and its `Host`, `Origin` and `Sec-Fetch-Site` where it has them. `None` when
/// the bytes are no request this server answers, or the whole head did not come within `REQUEST_TIME`.
struct Request {
    method: String,
    target: String,
    host: String,
    origin: Option<String>,
    fetch_site: Option<String>,
}

fn request(stream: &mut TcpStream) -> Option<Request> {
    let until = Instant::now() + REQUEST_TIME;
    let mut head = Vec::new();
    let mut buffer = [0u8; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        // the time is for the whole head: a sender of a byte now and then does not hold a thread for long
        let left = until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        stream.set_read_timeout(Some(left)).ok()?;
        let n = stream.read(&mut buffer).ok().filter(|n| *n > 0)?;
        head.extend_from_slice(&buffer[..n]);
        if head.len() > 16 * 1024 {
            return None;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(&str, &str)> = lines.filter_map(|l| l.split_once(':')).map(|(name, value)| (name.trim(), value.trim())).collect();
    let header = |name: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.to_string());
    Some(Request { method, target, host: header("host")?, origin: header("origin"), fetch_site: header("sec-fetch-site") })
}

/// The names this server answers under: the address it listens on and, on the two usual loopback addresses, `localhost`.
fn names(address: &std::net::SocketAddr) -> Vec<String> {
    let mut names = vec![address.to_string()];
    if address.ip() == std::net::Ipv4Addr::LOCALHOST || address.ip() == std::net::Ipv6Addr::LOCALHOST {
        names.push(format!("localhost:{}", address.port()));
    }
    names
}

fn handle(mut stream: TcpStream, names: &[String], wal: &Path, shared: &Mutex<Shared>) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
    let Some(Request { method, target, host, origin, fetch_site }) = request(&mut stream) else {
        return respond(&mut stream, "400 Bad Request", "text/plain; charset=utf-8", b"not a request this server answers\n");
    };
    // a page of another site that reaches this port through a name of its own is refused: the journal is shown under this
    // computer's own names only
    if !names.contains(&host.to_ascii_lowercase()) {
        return respond(&mut stream, "403 Forbidden", "text/plain; charset=utf-8", b"this server answers under the address it listens on only\n");
    }
    // and so is a request another site's page makes to this one, whatever name it uses: the browser says where a request comes
    // from, and one that is not this server's own page, or the reader's own navigation, gets no data and costs no work
    let foreign_site = fetch_site.as_deref().is_some_and(|site| !site.eq_ignore_ascii_case("same-origin") && !site.eq_ignore_ascii_case("none"));
    let foreign_origin = origin.as_deref().is_some_and(|o| !names.iter().any(|name| o.eq_ignore_ascii_case(&format!("http://{name}"))));
    if foreign_site || foreign_origin {
        return respond(&mut stream, "403 Forbidden", "text/plain; charset=utf-8", b"this server answers its own page only\n");
    }
    if method != "GET" {
        return respond(&mut stream, "405 Method Not Allowed", "text/plain; charset=utf-8", b"this server only reads: GET\n");
    }
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let number = |name: &str| query.split('&').find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == name).and_then(|(_, v)| v.parse::<u64>().ok()));
    let (epoch, model, status) = {
        let shared = locked(shared);
        (shared.epoch, shared.model.clone(), shared.status.clone())
    };
    let json = "application/json; charset=utf-8";
    match (path, model) {
        ("/", Some(model)) => respond(&mut stream, "200 OK", "text/html; charset=utf-8", model.page(epoch, &status.json()).as_bytes()),
        ("/", None) => respond(&mut stream, "200 OK", "text/html; charset=utf-8", waiting(wal, &status).as_bytes()),
        ("/status", _) => respond(&mut stream, "200 OK", json, format!("{{\"epoch\":{epoch},\"status\":{}}}\n", status.json()).as_bytes()),
        ("/data", Some(model)) => respond(&mut stream, "200 OK", json, model.whole().as_bytes()),
        ("/delta", Some(model)) => {
            let have = number("frames").unwrap_or(0) as usize;
            // a page of another reading, or one that holds more frames than were read, takes the data whole again
            let body = if number("epoch") != Some(epoch) || have == 0 || have > model.frames {
                format!("{{\"reset\":true,\"epoch\":{epoch}}}")
            } else {
                format!("{{\"epoch\":{epoch},\"delta\":{}}}", model.delta(have, &status.json()))
            };
            respond(&mut stream, "200 OK", json, body.as_bytes())
        }
        ("/data" | "/delta", None) => respond(&mut stream, "200 OK", json, format!("{{\"reset\":true,\"epoch\":{epoch}}}").as_bytes()),
        _ => respond(&mut stream, "404 Not Found", "text/plain; charset=utf-8", b"no such page: / is the journal\n"),
    }
}

/// `sbgk audit-watch --wal <run.wal> [--listen 127.0.0.1:7117] [--docs <folder>] [--note <text>] [--every-ms <n>]`: serves the
/// YuCe Live page of the journal on a loopback address and follows the journal for as long as the command runs. The journal may
/// not exist yet: the page waits for its first frame. `--docs` is the folder the documents were read from, to show each quote in
/// its line; `--note` is a sentence shown at the top of the page; `--every-ms` is how often the file is read (default 300).
/// It prints one JSON line with the address when it listens, and runs until it is stopped.
pub fn cmd_audit_watch(a: &Args) {
    let wal = PathBuf::from(a.req("wal"));
    let listen = a.get("listen").unwrap_or(DEFAULT_LISTEN).to_string();
    let docs = a.get("docs").map(PathBuf::from);
    let note = a.get("note").unwrap_or_default().to_string();
    let every = Duration::from_millis(a.num("every-ms", 300u64).clamp(20, 60_000));
    if let Some(folder) = docs.as_ref().filter(|d| !d.is_dir()) {
        fail(&format!("--docs {}: not a folder", folder.display()));
    }
    let addresses: Vec<_> = listen.to_socket_addrs().unwrap_or_else(|e| fail(&format!("cannot resolve --listen {listen}: {e}"))).collect();
    if addresses.is_empty() || addresses.iter().any(|a| !a.ip().is_loopback()) {
        fail(&format!("--listen {listen} is not a loopback address: the page of a journal is served on this computer only"));
    }
    let listener = TcpListener::bind(&addresses[..]).unwrap_or_else(|e| {
        fail(&format!("cannot listen on {listen}: {e}; --listen 127.0.0.1:0 takes any free port, and the line printed at the start names it"))
    });
    // the address the listener got, not the one asked for: a name can resolve to more than one, and port 0 to any
    let address = listener.local_addr().unwrap_or_else(|e| fail(&format!("cannot read the listening address: {e}")));
    let names = Arc::new(names(&address));
    let shared = Arc::new(Mutex::new(Shared { status: Status { mode: "waiting", ..Status::default() }, ..Shared::default() }));
    {
        let (wal, shared) = (wal.clone(), shared.clone());
        std::thread::spawn(move || follow(wal, docs, note, every, shared));
    }
    println!(
        "{}",
        json!({"status": "WATCHING", "url": format!("http://{address}/"), "wal": wal.display().to_string(),
        "note": "the page follows the journal and reads nothing else; stop the command to stop the page"})
    );
    let _ = std::io::stdout().flush();
    let busy = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if busy.fetch_add(1, Ordering::SeqCst) >= 64 {
            busy.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (wal, shared, names, busy) = (wal.clone(), shared.clone(), names.clone(), Busy(busy.clone()));
        std::thread::spawn(move || {
            // the count goes down when the thread ends, however it ends
            let _busy = busy;
            handle(stream, &names, &wal, &shared);
        });
    }
}

/// One of the threads that answer requests: its end, also by an error of the command itself, frees its place.
struct Busy(Arc<AtomicUsize>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_named_by_a_journal_is_read_only_inside_the_folder() {
        use super::super::docs_input::{file_inside, read_inside};
        let root = std::env::temp_dir().join(format!("sbgk_watch_docs_{}_{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("docs/sub")).unwrap();
        std::fs::write(root.join("docs/sub/a.md"), b"inside").unwrap();
        std::fs::write(root.join("outside.md"), b"outside").unwrap();
        let folder = root.join("docs");
        assert_eq!(std::fs::read(file_inside(&folder, "sub/a.md", 100).unwrap()).unwrap(), b"inside");
        assert_eq!(std::fs::read(file_inside(&folder, "sub\\a.md", 100).unwrap()).unwrap(), b"inside");
        let outside = root.join("outside.md").display().to_string();
        for path in ["../outside.md", "sub/../../outside.md", outside.as_str(), "/outside.md", "sub", "nothing.md", "", "."] {
            assert!(file_inside(&folder, path, 100).is_err(), "{path:?} is refused");
        }
        assert!(file_inside(&folder, "sub/a.md", 3).is_err(), "longer than the limit");
        assert_eq!(read_inside(&folder, "sub/a.md", 6).unwrap(), b"inside");
        assert!(read_inside(&folder, "sub/a.md", 5).is_err() && read_inside(&folder, "../outside.md", 100).is_err());
        #[cfg(windows)]
        for device in ["CON", "NUL", "sub/CON", "sub/a.md:stream", "\\\\.\\pipe\\x"] {
            assert!(file_inside(&folder, device, 100).is_err(), "{device:?} is refused");
        }
        #[cfg(not(windows))]
        assert!(file_inside(&folder, "/dev/zero", 100).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_server_answers_under_the_address_it_listens_on() {
        assert_eq!(names(&"127.0.0.1:7117".parse().unwrap()), ["127.0.0.1:7117", "localhost:7117"]);
        assert_eq!(names(&"[::1]:7117".parse().unwrap()), ["[::1]:7117", "localhost:7117"]);
        assert_eq!(names(&"127.0.0.2:80".parse().unwrap()), ["127.0.0.2:80"]);
    }

    #[test]
    fn the_template_has_the_places_a_watched_page_changes() {
        assert_eq!(TEMPLATE.matches(PLACE).count(), 1, "one place for the data");
        assert_eq!(TEMPLATE.matches(POLICY).count(), 1, "the policy a watched page widens by its own server");
        assert_eq!(TEMPLATE.matches("</body>").count(), 1);
        assert!(!CLIENT.contains("</script") && !CLIENT.contains(PLACE));
    }

    #[test]
    fn a_json_text_in_a_page_is_ascii_and_cannot_end_its_script() {
        let text = json!({"t": "a </script> \u{2028} \u{1F600} \u{e9}"}).to_string();
        let safe = ascii(&text);
        assert!(safe.is_ascii() && !safe.contains('<'));
        assert_eq!(serde_json::from_str::<Value>(&safe).unwrap(), serde_json::from_str::<Value>(&text).unwrap());
    }

    #[test]
    fn ids_of_the_export_are_read_as_make_page_reads_them() {
        assert_eq!(tail("urn:yuce:a%20run:agent:reader%3A1"), "reader:1");
        assert_eq!(frame_of(&json!("urn:yuce:r:frame:42")), 42);
        assert_eq!(utf8_ignore(b"ab\xffcd"), "abcd");
        let mut list = [Label('c', 10), Label('c', 2), Label('A', 3)];
        list.sort();
        assert_eq!(list.iter().map(Label::to_string).collect::<Vec<_>>(), ["A3", "c2", "c10"]);
    }
}
