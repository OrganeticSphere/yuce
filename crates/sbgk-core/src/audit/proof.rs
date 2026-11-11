//! Quittances of 0.2 (SPEC_V02_STEP5): one file that shows a record with every record it rests on, down to the quotes, and proves
//! that all of them were in the `/3` journal the kernel sealed at frame `n`, under a signed checkpoint of step 4. Whoever checks it
//! needs neither the journal nor a model. The journal format does not change: a quittance is cut from a journal and its checkpoint.
//!
//! What it proves, and what not: the records were written before the seal. Not that they stand now. With the status projection of
//! the seal inside (`with_status`), also that they stood at the seal. A signature is only the word of the key's holder (step 4).
//!
//! It ships with the open kernel from 0.2 on (the owner, 11.11.2026).

use super::persistence::{body_hash, header_hash, header_v3, lower_hex, AuditJournal, FrameFormat, FORMAT_V3, HEADER_KEYS_V3};
use super::sign::{self, NoteVerifier, OpenedNote, TrustedKey};
use super::state::{seal_hash, AuditState};
use super::trees;
use crate::error::{Code, KResult, KernelError};
use crate::hash::{sha256, sha256_parts, to_hex, Hash, ZERO_HASH};
use crate::jcs::to_jcs;
use crate::node::EvidenceNode;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// The format of a quittance file.
pub const FORMAT: &str = "yuce-proof/1";
const SEAL_FORMAT: &str = "r2r-seal/2";
const SEAL_KEYS: [&str; 8] = ["audit_root", "engine_root", "format", "log_root", "log_size", "projections", "run_id", "wal_head"];
const BODY_KEYS: [&str; 7] = ["actor", "audit_root", "command", "engine_root", "outcome", "request_hash", "submission_id"];

fn refuse(field: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field(field)
}

/// What a quittance carries beyond the records and their proofs (SPEC_V02_STEP5 sections 3 and 4).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProofOptions {
    /// The bytes of every quote, with the chunks and the chunk list of its document version: checked without the corpus.
    pub self_contained: bool,
    /// The whole status projection of the seal: whether the records stood at the seal.
    pub with_status: bool,
}

fn is_seal(payload: &Value) -> bool {
    payload["actor"] == "kernel" && payload["command"]["kind"] == "seal" && payload["outcome"]["kind"] == "value"
}

fn hexes(hashes: &[Hash]) -> Vec<String> {
    hashes.iter().map(|h| to_hex(h)).collect()
}

/// The bytes of lowercase hex text of any length; `None` for any other text.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes().chunks(2).map(|p| Some(digit(p[0])? << 4 | digit(p[1])?)).collect()
}

/// What the state at the seal gives a quittance: the records (by their place in the run) with their leaf values, the target, and
/// for the options the documents, the evidence nodes and the status rows.
struct Captured {
    records: Vec<(usize, Value)>,
    target: String,
    documents: Map<String, Value>,
    evidence: Map<String, Value>,
    status: Option<Vec<Value>>,
}

/// Every place `needle` occurs in `hay`, overlaps included.
fn occurrences(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return Vec::new();
    }
    hay.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i).collect()
}

fn capture(s: &AuditState, record: &str, opts: ProofOptions) -> KResult<Captured> {
    let count = s.record_count();
    let id_of = |i: usize| to_hex(&s.record_at(i).id.0);
    let index: HashMap<String, usize> = (0..count).map(|i| (id_of(i), i)).collect();
    // the id as the reading tools show it: whole, or its first hex digits, with or without the `@` of the short form
    let want = record.strip_prefix('@').unwrap_or(record).to_ascii_lowercase();
    if !want.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(refuse("record", format!("{record} is no record id: give the id or its short form, @ and 8 hex digits or more")));
    }
    let found: Vec<usize> = (0..count).filter(|&i| id_of(i).starts_with(&want)).collect();
    let target = match found[..] {
        [i] if want.len() >= 8 => i,
        [] => return Err(refuse("record", format!("no record {record} in the journal up to this seal (a record written after it needs a later seal)"))),
        _ => return Err(refuse("record", format!("{record} names more than one record or is shorter than 8 hex digits"))),
    };
    // the record and every record it rests on, through `based_on` and the ends of a relation, down to the observations
    let mut seen = BTreeSet::new();
    let mut stack = vec![target];
    while let Some(i) = stack.pop() {
        if !seen.insert(i) {
            continue;
        }
        let r = s.record_at(i);
        for g in r.based_on.iter().chain(r.ends.iter().flat_map(|(a, _, b)| [a, b])) {
            let j = index.get(&to_hex(&g.0)).ok_or_else(|| refuse("record", format!("a ground {} is no record of this run", to_hex(&g.0))))?;
            stack.push(*j);
        }
    }
    let (status, _, _) = s.projections();
    let stands: HashMap<&str, bool> = status.iter().filter_map(|row| Some((row[0].as_str()?, row[2] == true))).collect();
    for &i in &seen {
        let id = id_of(i);
        // a model's hypothesis is no claim of the run (SPEC_V02_STEP5 section 0; Codex review of 3fda096c, S5-01)
        if s.record_at(i).kind == super::RecordKind::Hypothesis {
            return Err(refuse("record", format!("record {id} is a hypothesis: a quittance carries none, as target or as ground")));
        }
        if stands.get(id.as_str()) != Some(&true) {
            return Err(refuse(
                "record",
                format!("record {id} does not stand at this seal: a quittance of it would hand out what fell, a withdrawn quote among it"),
            ));
        }
    }
    let mut out = Captured {
        records: seen.iter().map(|&i| (i, s.record_leaf_value_at(i))).collect(),
        target: id_of(target),
        documents: Map::new(),
        evidence: Map::new(),
        status: opts.with_status.then_some(status),
    };
    if opts.self_contained {
        for &i in &seen {
            let r = s.record_at(i);
            let Some((evidence, version, start, _)) = s.evidence_binding(&r.id) else { continue };
            add_quote(s, &id_of(i), &evidence, &version, start, &mut out)?;
        }
    }
    Ok(out)
}

/// The evidence node of one quote, its document's chunk list and the chunks it lies in, unless one of those chunks holds withdrawn
/// text: a self-contained quittance would hand that text out.
fn add_quote(s: &AuditState, id: &str, evidence: &Hash, version: &Hash, start: usize, out: &mut Captured) -> KResult<()> {
    let bytes =
        s.evidence_node_bytes(evidence).ok_or_else(|| refuse("record", format!("record {id}: the engine has no evidence node {}", to_hex(evidence))))?;
    let node = EvidenceNode::decode(&bytes).map_err(|e| refuse("record", format!("record {id}: evidence node: {}", e.0)))?;
    let doc = s.current_document(&node.doc_id).filter(|d| d.version_id == *version).ok_or_else(|| {
        refuse(
            "self_contained",
            format!(
                "record {id}: its quote is bound to a version of {} that is not the current one at this seal; a self-contained quittance carries quotes of a document's current version only, an inclusion quittance carries this one",
                node.doc_id
            ),
        )
    })?;
    let ends = |p: usize| doc.chunk_starts.get(p + 1).copied().unwrap_or(doc.bytes.len());
    let len = node.segs.len();
    let first = (0..=doc.chunk_hashes.len().saturating_sub(len))
        .find(|&p| {
            doc.chunk_starts[p] + node.segs[0].start as usize == start && node.segs.iter().enumerate().all(|(j, seg)| doc.chunk_hashes[p + j] == seg.chunk)
        })
        .ok_or_else(|| refuse("record", format!("record {id}: its quote is not where its binding says in {}", node.doc_id)))?;
    let (from, to) = (doc.chunk_starts[first], ends(first + len - 1));
    for text in s.withdrawn_of(&node.doc_id) {
        if occurrences(&doc.bytes, text).iter().any(|&o| o < to && o + text.len() > from) {
            return Err(refuse(
                "self_contained",
                format!("record {id}: a chunk of its quote holds withdrawn text of {}; cut an inclusion quittance, which carries no chunk", node.doc_id),
            ));
        }
    }
    let entry = out.documents.entry(to_hex(version)).or_insert_with(|| json!({"chunks": hexes(&doc.chunk_hashes), "pieces": {}}));
    for p in first..first + len {
        let piece = &doc.bytes[doc.chunk_starts[p]..ends(p)];
        if sha256(piece) != doc.chunk_hashes[p] {
            return Err(refuse("record", format!("record {id}: a chunk of {} does not have its hash", node.doc_id)));
        }
        entry["pieces"][to_hex(&doc.chunk_hashes[p])] = json!(sign::base64(piece));
    }
    out.evidence.insert(to_hex(evidence), json!(to_hex(&bytes)));
    Ok(())
}

/// A quittance of `record` (its full id or a unique prefix of at least 8 hex digits) at the seal of frame `seal`, the journal's last
/// seal when `None`, under `checkpoint`, the text of the signed checkpoint of that seal (SPEC_V02_STEP5 section 5). The journal is
/// checked whole first. Refused for a record written after the seal, for a record or ground that does not stand at it, and for a
/// self-contained quote that cannot be handed out. The quittance is checked by `check` before it is returned.
pub fn build(path: &Path, record: &str, seal: Option<usize>, checkpoint: &str, verifier_key: Option<&str>, opts: ProofOptions) -> KResult<Value> {
    let scan = AuditJournal::read(path)?;
    if scan.format != FrameFormat::V3 {
        return Err(refuse("wal", "a quittance is cut from a journal of 0.2"));
    }
    let seals: Vec<usize> = scan.payloads.iter().enumerate().filter(|(_, p)| is_seal(p)).map(|(k, _)| k).collect();
    let n = match seal {
        Some(n) if seals.contains(&n) => n,
        Some(n) => return Err(refuse("seal", format!("frame {n} is no seal of this journal; its seals are the frames {seals:?}"))),
        None => *seals.last().ok_or_else(|| refuse("seal", "the journal has no seal"))?,
    };
    let note = sign::open_note(checkpoint)?;
    let (origin, size, root) = sign::parse_checkpoint(&note.body)?;
    if size != n + 1 {
        return Err(refuse("checkpoint", format!("the checkpoint names {size} frames; the seal of frame {n} needs the one of {} frames", n + 1)));
    }
    sign::check_against_journal(path, &origin, size, &root)?;
    let mut counts = vec![0usize];
    let mut leaves: Vec<Vec<Hash>> = Vec::new();
    let mut captured = None;
    AuditState::verify_states(path, &mut |m, state, _| {
        if m > n + 1 {
            return;
        }
        let before = counts[counts.len() - 1];
        let now = state.record_count();
        leaves.push((before..now).map(|i| trees::record_leaf(&state.record_leaf_value_at(i))).collect());
        counts.push(now);
        if m == n + 1 {
            captured = Some(capture(state, record, opts));
        }
    })?;
    let cap = captured.ok_or_else(|| refuse("seal", "the journal ended before its seal"))??;
    let heads = &scan.heads[..=n];
    let header_of = |k: usize| -> KResult<Value> {
        let previous = if k == 0 { ZERO_HASH } else { heads[k - 1] };
        let header = header_v3(k as u64, &previous, &body_hash(&scan.payloads[k]), &scan.records_roots[k]);
        if header_hash(&header) != heads[k] {
            return Err(refuse("wal", format!("frame {k}: its header read back has another hash")));
        }
        Ok(header)
    };
    let mut frames = Map::new();
    let mut records = Vec::new();
    for (i, value) in &cap.records {
        let k = (0..=n).find(|&k| counts[k + 1] > *i).ok_or_else(|| refuse("record", "a record beyond the seal"))?;
        let j = i - counts[k];
        let leaf = trees::record_leaf(value);
        if leaves[k].get(j) != Some(&leaf) {
            return Err(refuse("record", format!("the leaf of record {} read back differs from the one frame {k} hashed", value["id"])));
        }
        records.push(json!({"value": value, "frame": k, "index": j, "path": hexes(&trees::records_path(&leaves[k], j))}));
        if !frames.contains_key(&k.to_string()) {
            frames.insert(k.to_string(), json!({"header": header_of(k)?, "leaves": leaves[k].len(), "path": hexes(&trees::log_path(heads, k))}));
        }
    }
    let mut proof = json!({"format": FORMAT, "mode": if opts.self_contained { "self-contained" } else { "inclusion" }, "target": cap.target,
        "checkpoint": checkpoint, "seal": {"header": header_of(n)?, "body": scan.payloads[n], "path": hexes(&trees::log_path(heads, n))},
        "frames": frames, "records": records});
    if let Some(key) = verifier_key {
        proof["verifier_key"] = json!(key.trim());
    }
    if opts.self_contained {
        proof["documents"] = Value::Object(cap.documents);
        proof["evidence"] = Value::Object(cap.evidence);
    }
    if let Some(status) = cap.status {
        proof["status"] = json!(status);
    }
    check(&proof)?;
    Ok(proof)
}

/// The seal frames of the journal at `path`, in order: where its checkpoints are.
pub fn seals_of(path: &Path) -> KResult<Vec<usize>> {
    Ok(AuditJournal::read(path)?.payloads.iter().enumerate().filter(|(_, p)| is_seal(p)).map(|(k, _)| k).collect())
}

/// The bytes of a quittance file: its JCS and one line end.
pub fn to_file(proof: &Value) -> Vec<u8> {
    let mut bytes = to_jcs(proof).into_bytes();
    bytes.push(b'\n');
    bytes
}

/// A quittance file read back: JSON in its canonical form (JCS) and one line end, nothing else.
pub fn parse(bytes: &[u8]) -> KResult<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| refuse("proof", format!("not JSON: {e}")))?;
    if to_file(&value) != bytes {
        return Err(refuse("proof", "a quittance is its canonical JSON (JCS) and one line end"));
    }
    Ok(value)
}

/// What `check` established of a quittance, before its signature and its anchor are weighed.
pub struct Checked {
    pub target: String,
    pub run_id: String,
    /// The frame of the seal; the checkpoint names the frames up to and with it.
    pub seal: usize,
    pub seal_hash: Hash,
    pub mode: String,
    pub records: usize,
    pub frames: usize,
    /// Quotes whose bytes were checked against their document version (self-contained mode).
    pub quotes_checked: usize,
    /// Whether each record stood at the seal, by id (with the status projection inside).
    pub standing: Option<BTreeMap<String, bool>>,
    pub note: OpenedNote,
}

fn object<'a>(v: &'a Value, what: &str, required: &[&str], optional: &[&str]) -> KResult<&'a Map<String, Value>> {
    let map = v.as_object().ok_or_else(|| refuse(what, format!("{what} is an object")))?;
    for k in map.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Err(refuse(what, format!("{what} has no key {k:?}")));
        }
    }
    if let Some(k) = required.iter().find(|k| !map.contains_key(**k)) {
        return Err(refuse(what, format!("{what} lacks {k:?}")));
    }
    Ok(map)
}

fn hash(v: &Value, what: &str) -> KResult<Hash> {
    lower_hex(v).ok_or_else(|| refuse(what, format!("{what} is 64 lowercase hex digits")))
}

fn path(v: &Value, what: &str) -> KResult<Vec<Hash>> {
    v.as_array().ok_or_else(|| refuse(what, format!("{what} is an array of hashes")))?.iter().map(|h| hash(h, what)).collect()
}

fn number(v: &Value, what: &str) -> KResult<usize> {
    v.as_u64().filter(|n| *n < (1 << 53)).map(|n| n as usize).ok_or_else(|| refuse(what, format!("{what} is a whole number")))
}

/// A `/3` frame header of frame `seq`: its exact keys and values. Returns the frame's hash, its previous and its records root.
fn frame_header(h: &Value, seq: usize, what: &str) -> KResult<(Hash, Hash, Hash)> {
    object(h, what, &HEADER_KEYS_V3, &[])?;
    let wal_op = if seq == 0 { "genesis" } else { "audit" };
    if h["format"] != FORMAT_V3 || number(&h["seq"], what)? != seq || h["wal_op"] != wal_op {
        return Err(refuse(what, format!("{what} is the header of frame {seq} of a /3 journal")));
    }
    hash(&h["body_hash"], what)?;
    Ok((header_hash(h), hash(&h["previous"], what)?, hash(&h["records_root"], what)?))
}

/// The checks of a quittance that need no key (SPEC_V02_STEP5 section 6, checks 1 and 3 to 8): its form, the seal frame and its
/// place under the checkpoint's root, every frame and record on its path, the grounds of every record, the quotes' bytes in the
/// self-contained mode and the status projection when it is inside. The first failure refuses.
pub fn check(proof: &Value) -> KResult<Checked> {
    let top =
        object(proof, "proof", &["checkpoint", "format", "frames", "mode", "records", "seal", "target"], &["documents", "evidence", "status", "verifier_key"])?;
    if top["format"] != FORMAT {
        return Err(refuse("proof", format!("not a quittance of format {FORMAT}")));
    }
    let mode = top["mode"].as_str().unwrap_or_default();
    let self_contained = match mode {
        "inclusion" => false,
        "self-contained" => true,
        _ => return Err(refuse("mode", "the mode is inclusion or self-contained")),
    };
    if top.contains_key("documents") != self_contained || top.contains_key("evidence") != self_contained {
        return Err(refuse("mode", "documents and evidence come with the self-contained mode, and only with it"));
    }
    if top.get("verifier_key").is_some_and(|k| !k.is_string()) {
        return Err(refuse("verifier_key", "the verifier key is text"));
    }
    let note = sign::open_note(top["checkpoint"].as_str().ok_or_else(|| refuse("checkpoint", "the checkpoint is text"))?)?;
    let (origin, size, root) = sign::parse_checkpoint(&note.body)?;
    if size < 2 {
        return Err(refuse("checkpoint", "a checkpoint of a seal names at least the genesis and the seal"));
    }
    let n = size - 1;

    // the seal frame, the last of the checkpoint
    let seal = object(&top["seal"], "seal", &["body", "header", "path"], &[])?;
    let (seal_frame, previous, _) = frame_header(&seal["header"], n, "seal header")?;
    let body = object(&seal["body"], "seal body", &BODY_KEYS, &[])?;
    if hash(&seal["header"]["body_hash"], "seal header")? != body_hash(&seal["body"]) {
        return Err(refuse("seal", "the seal frame's body does not have the body hash of its header"));
    }
    let command = object(&body["command"], "seal command", &["kind", "seal"], &[])?;
    if body["actor"] != "kernel" || command["kind"] != "seal" || body["submission_id"] != format!("seal-{n}") {
        return Err(refuse("seal", format!("frame {n} is a seal of the kernel, numbered seal-{n}")));
    }
    let p = &command["seal"];
    let pm = object(p, "seal P", &SEAL_KEYS, &[])?;
    object(&pm["projections"], "seal projections", &["dependencies", "status"], &[])?;
    let run_id = pm["run_id"].as_str().ok_or_else(|| refuse("seal", "the run id is text"))?.to_string();
    if pm["format"] != SEAL_FORMAT || number(&pm["log_size"], "seal P")? != n || hash(&pm["wal_head"], "seal P")? != previous {
        return Err(refuse("seal", format!("P is a seal of format {SEAL_FORMAT} of the {n} frames before it, the last of them its previous")));
    }
    for k in ["audit_root", "engine_root"] {
        hash(&pm[k], "seal P")?;
    }
    let sealed = seal_hash(p);
    if body["outcome"] != json!({"kind": "value", "result": {"seal": p, "seal_hash": to_hex(&sealed)}}) {
        return Err(refuse("seal", "the seal frame's outcome is its seal and the seal's hash"));
    }
    if origin != sign::origin(&run_id) {
        return Err(refuse("checkpoint", "the checkpoint's origin is not the run of its seal"));
    }
    let seal_path = path(&seal["path"], "seal path")?;
    if !trees::verify_log_path(&seal_frame, n, size, &seal_path, &root) {
        return Err(refuse("seal", "the seal frame is not the last frame under the checkpoint's root"));
    }
    if trees::log_prefix_root(&seal_path) != Some(hash(&pm["log_root"], "seal P")?) {
        return Err(refuse("seal", "the seal names another log of the frames before it than the checkpoint's root holds"));
    }

    // the frames of the records
    let frames = top["frames"].as_object().ok_or_else(|| refuse("frames", "frames is an object"))?;
    let mut roots: BTreeMap<usize, (Hash, usize)> = BTreeMap::new();
    for (key, frame) in frames {
        let k = key.parse::<usize>().ok().filter(|k| k.to_string() == *key && *k >= 1 && *k < n);
        let k = k.ok_or_else(|| refuse("frames", format!("frame {key:?}: a frame before the seal is named by its number")))?;
        let f = object(frame, "frame", &["header", "leaves", "path"], &[])?;
        let (h, _, records_root) = frame_header(&f["header"], k, "frame header")?;
        let leaves = number(&f["leaves"], "frame leaves")?;
        if leaves == 0 || !trees::verify_log_path(&h, k, size, &path(&f["path"], "frame path")?, &root) {
            return Err(refuse("frames", format!("frame {k} is not under the checkpoint's root with records")));
        }
        roots.insert(k, (records_root, leaves));
    }

    // the records on their paths
    let list = top["records"].as_array().filter(|l| !l.is_empty()).ok_or_else(|| refuse("records", "records is a non-empty array"))?;
    let mut by_id: BTreeMap<String, &Value> = BTreeMap::new();
    let mut places = BTreeSet::new();
    for r in list {
        let rm = object(r, "record", &["frame", "index", "path", "value"], &[])?;
        let (k, i) = (number(&rm["frame"], "record frame")?, number(&rm["index"], "record index")?);
        let (records_root, leaves) = *roots.get(&k).ok_or_else(|| refuse("records", format!("a record of frame {k}, which the quittance does not carry")))?;
        let leaf = trees::record_leaf(&rm["value"]);
        if !places.insert((k, i)) || !trees::verify_records_path(&leaf, i, leaves, &path(&rm["path"], "record path")?, &records_root) {
            return Err(refuse("records", format!("the record at {i} of frame {k} is not on its frame's records root")));
        }
        let id = hash(&rm["value"]["id"], "record id")?;
        if rm["value"]["kind"] == "hypothesis" {
            return Err(refuse("records", "a quittance carries no hypothesis of a model"));
        }
        if by_id.insert(to_hex(&id), &rm["value"]).is_some() {
            return Err(refuse("records", "a record is carried twice"));
        }
    }
    if places.iter().map(|(k, _)| *k).collect::<BTreeSet<_>>().len() != roots.len() {
        return Err(refuse("frames", "a frame no record of the quittance lies in"));
    }

    // the grounds of every record are in the quittance, with the bindings they have themselves, and all hang from the target
    let target = top["target"].as_str().unwrap_or_default().to_string();
    if !by_id.contains_key(&target) {
        return Err(refuse("target", "the target is a record of the quittance"));
    }
    let ids = |v: &Value, what: &str| -> KResult<Vec<String>> {
        let mut out = Vec::new();
        for g in v["based_on"].as_array().ok_or_else(|| refuse(what, "based_on is an array"))? {
            out.push(to_hex(&hash(g, what)?));
        }
        match &v["ends"] {
            Value::Null => {}
            Value::Array(e) if e.len() == 3 => out.extend([to_hex(&hash(&e[0], what)?), to_hex(&hash(&e[2], what)?)]),
            _ => return Err(refuse(what, "ends is null or [from, relation, to]")),
        }
        Ok(out)
    };
    let mut reached = BTreeSet::new();
    let mut stack = vec![target.clone()];
    while let Some(id) = stack.pop() {
        if !reached.insert(id.clone()) {
            continue;
        }
        let v = by_id[&id];
        for g in ids(v, "record")? {
            if !by_id.contains_key(&g) {
                return Err(refuse("records", format!("record {id} rests on {g}, which the quittance does not carry")));
            }
            stack.push(g);
        }
        let based_on = v["based_on"].as_array().map_or(0, Vec::len);
        match v.get("grounds") {
            None if based_on == 0 => {}
            Some(Value::Array(grounds)) if grounds.len() == based_on => {
                for (g, named) in grounds.iter().zip(v["based_on"].as_array().into_iter().flatten()) {
                    let ground = by_id.get(named.as_str().unwrap_or_default()).copied();
                    let binding = ground.and_then(|x| x.get("evidence"));
                    let want = match binding {
                        Some(b) => json!({"id": named, "evidence": b}),
                        None => json!({"id": named}),
                    };
                    if *g != want {
                        return Err(refuse("records", format!("record {id} names a ground with another binding than the ground has")));
                    }
                }
            }
            _ => return Err(refuse("records", format!("record {id}: its grounds are its based_on with their bindings"))),
        }
    }
    if reached.len() != by_id.len() {
        return Err(refuse("records", "a record the target does not rest on"));
    }

    let quotes_checked = if self_contained { check_quotes(top, &by_id)? } else { 0 };

    let standing = match top.get("status") {
        None => None,
        Some(rows) => {
            let rows = rows.as_array().ok_or_else(|| refuse("status", "status is the rows of the status projection"))?;
            let projection = sha256_parts(&[b"R2R-PROJ-STATUS/2\0", to_jcs(&json!(rows)).as_bytes()]);
            if projection != hash(&pm["projections"]["status"], "seal projections")? {
                return Err(refuse("status", "the status rows are not the projection the seal names"));
            }
            let mut standing = BTreeMap::new();
            for id in by_id.keys() {
                let row = rows.iter().find(|row| row[0] == id.as_str()).ok_or_else(|| refuse("status", format!("record {id} has no row")))?;
                standing.insert(id.clone(), row[2] == true);
            }
            Some(standing)
        }
    };

    Ok(Checked {
        target,
        run_id,
        seal: n,
        seal_hash: sealed,
        mode: mode.to_string(),
        records: by_id.len(),
        frames: roots.len(),
        quotes_checked,
        standing,
        note,
    })
}

/// The self-contained check of every quote (SPEC_V02_STEP5 section 6, check 7): the evidence node's bytes give its id and name the
/// record's document, the chunk list gives the version, the chunks give their hashes and the quote's bytes, which are the record's
/// quote. Nothing in `documents` or `evidence` goes unused.
fn check_quotes(top: &Map<String, Value>, by_id: &BTreeMap<String, &Value>) -> KResult<usize> {
    let documents = top["documents"].as_object().ok_or_else(|| refuse("documents", "documents is an object"))?;
    let evidence = top["evidence"].as_object().ok_or_else(|| refuse("evidence", "evidence is an object"))?;
    let (mut used_docs, mut used_pieces, mut used_nodes) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let mut checked = 0;
    for (id, v) in by_id {
        let Some(binding) = v.get("evidence") else { continue };
        let what = format!("quote of {id}");
        let b = object(binding, &what, &["id", "span", "version"], &[])?;
        let (node_id, version) = (hash(&b["id"], &what)?, hash(&b["version"], &what)?);
        let span = b["span"].as_array().filter(|s| s.len() == 2).ok_or_else(|| refuse(&what, "span is [start, end]"))?;
        let (start, end) = (number(&span[0], &what)?, number(&span[1], &what)?);
        let bytes = evidence.get(&to_hex(&node_id)).and_then(Value::as_str).and_then(unhex);
        let bytes = bytes.ok_or_else(|| refuse(&what, "its evidence node is in evidence, as lowercase hex"))?;
        let node = EvidenceNode::decode(&bytes).ok().filter(|n| n.encode() == bytes && sha256(&bytes) == node_id);
        let node = node.ok_or_else(|| refuse(&what, "the evidence node's bytes do not give its id"))?;
        if v["doc_id"] != node.doc_id.as_str() {
            return Err(refuse(&what, "the evidence node names another document than the record"));
        }
        let doc = object(documents.get(&to_hex(&version)).unwrap_or(&Value::Null), &what, &["chunks", "pieces"], &[])?;
        let chunks = path(&doc["chunks"], &what)?;
        if crate::arena::version_id_of(&chunks) != version || !node.has_contiguous_chunks(&chunks) {
            return Err(refuse(&what, "the chunk list is not the version's, or the quote's chunks are not in it in a row"));
        }
        let pieces = doc["pieces"].as_object().ok_or_else(|| refuse(&what, "pieces is an object"))?;
        let mut quote = Vec::with_capacity(node.quote_len as usize);
        let mut lens = HashMap::new();
        for seg in &node.segs {
            let piece = pieces.get(&to_hex(&seg.chunk)).and_then(Value::as_str).and_then(sign::unbase64);
            let piece = piece.filter(|p| sha256(p) == seg.chunk).ok_or_else(|| refuse(&what, "a chunk of the quote is missing or does not have its hash"))?;
            lens.insert(seg.chunk, piece.len());
            let slice = piece.get(seg.start as usize..seg.end as usize).ok_or_else(|| refuse(&what, "a segment lies outside its chunk"))?;
            quote.extend_from_slice(slice);
            used_pieces.insert((to_hex(&version), to_hex(&seg.chunk)));
        }
        if !node.has_valid_spans(|h| lens.get(h).copied())
            || quote.len() != node.quote_len as usize
            || sha256(&quote) != node.quote_hash
            || end.checked_sub(start) != Some(quote.len())
            || v["quote"] != String::from_utf8_lossy(&quote).as_ref()
        {
            return Err(refuse(&what, "the quote's bytes are not the ones the record and its evidence name"));
        }
        used_docs.insert(to_hex(&version));
        used_nodes.insert(to_hex(&node_id));
        checked += 1;
    }
    let pieces_carried: usize = documents.values().map(|d| d["pieces"].as_object().map_or(0, Map::len)).sum();
    if used_docs.len() != documents.len() || used_nodes.len() != evidence.len() || used_pieces.len() != pieces_carried {
        return Err(refuse("documents", "a document, chunk or evidence node no quote of the quittance uses"));
    }
    Ok(checked)
}

/// The whole check of a quittance (SPEC_V02_STEP5 section 6): `check`, then the checkpoint's signature against the trusted keys,
/// else against `key` or the quittance's own verifier key (which pins nothing), then the anchor. The answer says what is proved and
/// what is not; a refusal is an error.
pub fn verify(proof: &Value, trusted: &[TrustedKey], key: Option<&NoteVerifier>, anchored_at: Option<&str>, expect_seal: Option<&Hash>) -> KResult<Value> {
    let c = check(proof)?;
    let own = match proof.get("verifier_key").and_then(Value::as_str) {
        Some(text) => Some(NoteVerifier::parse(text)?),
        None => None,
    };
    let verdict = sign::signature_verdict(&c.note, trusted, key.or(own.as_ref()), anchored_at);
    if verdict.refused {
        return Err(refuse("checkpoint", format!("the checkpoint's signature: {}", verdict.status)));
    }
    let anchor = match expect_seal {
        Some(want) if *want == c.seal_hash => "the seal is the anchored one",
        Some(_) => return Err(refuse("expect_seal", "the seal is not the anchored one")),
        None => "the seal is not bound to an anchor",
    };
    let mut out = json!({"status": "PROOF_VALID", "target": c.target, "run_id": c.run_id, "mode": c.mode,
        "proves": format!("the target and the {} records it rests on were in the journal the kernel sealed at frame {}", c.records - 1, c.seal),
        "seal": {"frame": c.seal, "frames": c.seal + 1, "seal_hash": to_hex(&c.seal_hash)}, "records": c.records, "frames": c.frames,
        "signature": verdict.status, "key": verdict.key, "time": if anchored_at.is_some() { "anchored by the checker" } else { "time of signing not pinned" },
        "anchor": anchor});
    if c.mode == "self-contained" {
        out["quotes_checked_against_documents"] = json!(c.quotes_checked);
    }
    out["standing"] = match c.standing {
        Some(s) => json!({"at_seal": s, "note": "whether each record stood at the seal; not whether it stands now"}),
        None => json!("not checked: a quittance proves the records were written, not that they stand"),
    };
    Ok(out)
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
