//! `sbgk audit-cut` and `sbgk audit-observation`: a cut of several journals with the exports between them, and the observation
//! report over one sealed journal or over a cut (`verifier/spec/SPEC_CUT_AND_BUNDLE_v1.md`, `SPEC_OBSERVATION_REPORT_v1.md`).
//!
//! - `audit-cut export` makes a `yuce-export/1` file from one journal at one of its seals: the claims that stand there, or
//!   those named, each with the quotes and the claims it rests on, so that another party's agents can quote them byte for byte.
//! - `audit-cut manifest` makes the `yuce-cut/1` manifest of a bundle: a folder with one subfolder per journal
//!   (`<name>/run.wal`) and one file per export (`<name>.txt`). The deliveries are found in the journals, not typed. Whether
//!   the bundle passes is the verifier's to say.
//! - `audit-observation` writes the `yuce-observation-report/1` of one journal, or of a bundle with its manifest.
//!
//! Every journal is checked first as `audit-verify` checks it, up to the seal that ends its part. The check of a bundle as a
//! whole (levels B0 to B4) is the independent verifier's.

use super::audit_mcp::{not_over_inputs, refuse_locked_whole, write_aside};
use super::audit_stream::{json_lines, record_named};
use super::{fail, read, Args};
use sbgk_core::audit::cut::{self, Journal};
use sbgk_core::audit::observation;
use sbgk_core::audit::RecordId;
use sbgk_core::error::KernelError;
use sbgk_core::hash::{from_hex, sha256, to_hex, Hash};
use sbgk_core::jcs::to_jcs;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

const STEPS: &str = "export or manifest";
/// What an answer says of a journal that goes on after the seal its part ends with.
const FRAMES_AFTER: &str = "a journal holds frames after the seal its part ends with: they were not replayed, and nothing here is said of them";

/// Whether an object of a JSON text names a key twice, at any depth. The text is JSON: the caller has parsed it.
fn repeats_a_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    // the keys of each open object; `None` for an open array
    let mut open: Vec<Option<HashSet<String>>> = Vec::new();
    let (mut i, mut key_next) = (0, false);
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                open.push(Some(HashSet::new()));
                key_next = true;
            }
            b'[' => {
                open.push(None);
                key_next = false;
            }
            b'}' | b']' => {
                open.pop();
                key_next = false;
            }
            b',' => key_next = matches!(open.last(), Some(Some(_))),
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                if key_next {
                    let key: String = text.get(start..=i).and_then(|token| serde_json::from_str(token).ok()).unwrap_or_default();
                    if let Some(Some(keys)) = open.last_mut() {
                        if !keys.insert(key) {
                            return true;
                        }
                    }
                    key_next = false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// The files of a folder, at any depth; none when there is no such folder.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut folders = vec![dir.to_path_buf()];
    while let Some(dir) = folders.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                folders.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// The SHA-256 of every file of a documents folder: a document is known by its bytes, not by its file name.
fn documents_in(files: &[PathBuf]) -> BTreeSet<Hash> {
    files.iter().filter_map(|path| std::fs::read(path).ok()).map(|bytes| sha256(&bytes)).collect()
}

/// The documents folder beside a journal, as a bundle lays a journal out: `<folder of the journal>/docs`. A command that is
/// given the journal alone still writes over no file of it.
fn documents_beside(wal: &Path) -> Vec<PathBuf> {
    files_under(&wal.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new(".")).join("docs"))
}

/// How a command is told the seal that ends the part of a journal.
enum Named<'a> {
    Seal,
    At(&'a str),
}

impl Named<'_> {
    fn option(&self, seal: usize) -> String {
        match self {
            Named::Seal => format!("--seal {seal}"),
            Named::At(name) => format!("--at {name}={seal}"),
        }
    }
}

/// What a command that was told no seal says of a file `audit-verify` does not verify.
const WHOLE: &str = "With no seal named the whole file is the input, as audit-verify reads it";

/// With no seal named, a journal that ends in bytes that are no complete frame is refused as `audit-verify` refuses it: status
/// TORN_TAIL, exit 1 (Codex's review of c64809bb: the command answered from the complete frames and said nothing of the tail).
fn no_torn_tail(shown: &str, journal: &Journal, how: &Named) {
    let torn = journal.torn_tail_bytes();
    if torn > 0 {
        let name_it = journal.last_seal().map(|seal| format!(" Name the seal to take the part that ends with it: {}", how.option(seal))).unwrap_or_default();
        let message = format!("the journal ends in {torn} bytes that are no complete frame, usually from a crash. {WHOLE}.{name_it}");
        println!(
            "{}",
            json!({"status": "TORN_TAIL", "what": shown, "torn_tail_bytes": torn, "last_seal": journal.last_seal(),
                   "error": {"code": "BAD_FIELD", "field": "audit_wal", "message": message}})
        );
        std::process::exit(1)
    }
}

/// With no seal named, a frame after the last seal that the kernel refuses ends the command as it ends `audit-verify`.
fn rest_refused(shown: &str, seal: usize, frame: usize, error: &KernelError, how: &Named) -> ! {
    let message = format!(
        "frame {frame}, after the last seal of the journal, is refused: {}. {WHOLE}. Name the seal to take the part that ends with it: {}",
        error.message,
        how.option(seal)
    );
    println!("{}", json!({"status": "REFUSED", "what": shown, "last_seal": seal, "error": {"code": "BAD_FIELD", "field": "audit_wal", "message": message}}));
    std::process::exit(1)
}

/// The journals that hold frames after their part, each with their number; `None` when none does.
fn frames_after<'a>(parts: impl Iterator<Item = (&'a str, &'a cut::Part)>) -> Option<Value> {
    let after: serde_json::Map<String, Value> =
        parts.filter(|(_, part)| part.frames_after > 0).map(|(name, part)| (name.to_string(), json!(part.frames_after))).collect();
    (!after.is_empty()).then_some(Value::Object(after))
}

fn refused(what: &str, error: &KernelError) -> ! {
    println!("{}", json!({"status": "REFUSED", "what": what, "error": error.to_json()}));
    std::process::exit(1)
}

/// The journal of a file. With a seal named, only its part is read and validated: the frames up to that seal and the one
/// after it, as `closed` says (`Journal::read_part`). With none, the whole file is read and must be whole: its last seal is
/// then the one meant, and the caller replays the frames after it too (`Part::rest_replays`).
fn journal_at(path: &Path, part: Option<(usize, Option<bool>)>, how: &Named) -> Journal {
    let shown = path.display().to_string();
    refuse_locked_whole(&shown);
    let journal = match part {
        Some((seal, closed)) => Journal::read_part(path, seal, closed),
        None => Journal::read(path),
    }
    .unwrap_or_else(|e| refused(&shown, &e));
    if part.is_none() {
        no_torn_tail(&shown, &journal, how);
    }
    journal
}

fn frame_number(flag: &str, value: &str) -> usize {
    value.parse().unwrap_or_else(|_| fail(&format!("--{flag}: a frame number, not '{value}'")))
}

fn hash_arg(flag: &str, value: &str) -> Hash {
    from_hex(value).filter(|hash| to_hex(hash) == value).unwrap_or_else(|| fail(&format!("--{flag}: 64 lowercase hex digits")))
}

/// What is written, under a new name beside it first: never over a file it was made from.
fn write_out(out: &Path, bytes: &[u8], inputs: &[(PathBuf, &str)], what: &str) {
    not_over_inputs(&out.display().to_string(), out, inputs, what);
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", dir.display())));
    }
    write_aside(out, bytes).unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", out.display())));
}

pub fn cmd_audit_cut(a: &Args) {
    let step = a.pos(0, &format!("the step: {STEPS}"));
    match step.as_str() {
        "export" => export_step(a),
        "manifest" => manifest_step(a),
        other => fail(&format!("unknown step '{other}': {STEPS}")),
    }
}

/// `sbgk audit-cut export --wal <run.wal> --out <file> [--seal <n>] [--records <file>]`: the export of a journal at the seal of
/// frame `n` (its last seal by default), of the claims the file of `--records` names (a JSON array of record ids, or one a
/// line), or of every claim that stands at that seal. Exit 1 when refused: a record that is no claim, or does not stand there.
fn export_step(a: &Args) {
    let (wal, out) = (a.req("wal"), a.req("out"));
    let named = a.get("seal").map(|n| frame_number("seal", n));
    let journal = journal_at(Path::new(&wal), named.map(|n| (n, None)), &Named::Seal);
    let seal = match named {
        Some(n) => n,
        None => journal.last_seal().unwrap_or_else(|| fail(&format!("{wal} has no seal: an export names a seal"))),
    };
    let part = journal.part(seal, None, &BTreeSet::new()).unwrap_or_else(|e| refused(&wal, &e));
    let claims: Option<Vec<RecordId>> = a.get("records").map(|path| {
        let named = json_lines(path, "records");
        named.iter().map(|v| record_named(&part.state, v.as_str().unwrap_or_else(|| fail("--records: a file of record ids, each a JSON string")))).collect()
    });
    let export = part.export(seal, claims.as_deref()).unwrap_or_else(|e| refused(&wal, &e));
    let (run_id, frames_after) = (part.state.run_id().to_string(), part.frames_after);
    if named.is_none() {
        if let Err((frame, e)) = part.rest_replays() {
            rest_refused(&wal, seal, frame, &e, &Named::Seal);
        }
    }
    // The export is written over no file of its input: the journal, the list of its records (Codex's review of dd7f5b2f: --out
    // naming the file of --records replaced the list by the export), and the documents beside the journal (his review of
    // c64809bb: a document of a bundle was replaced the same way).
    let mut inputs = vec![(PathBuf::from(&wal), "the journal")];
    inputs.extend(a.get("records").map(|path| (PathBuf::from(path), "the list of its records")));
    inputs.extend(documents_beside(Path::new(&wal)).into_iter().map(|path| (path, "a document beside the journal")));
    write_out(Path::new(&out), &export.bytes, &inputs, "the export");
    println!(
        "{}",
        json!({"status": "EXPORT", "file": out, "run_id": run_id, "seal": {"log_size": export.seal, "seal_hash": to_hex(&export.seal_hash)},
               "records": export.records.len(), "record_ids": export.records.iter().map(|r| to_hex(&r.0)).collect::<Vec<_>>(),
               "bytes": export.bytes.len(), "sha256": to_hex(&sha256(&export.bytes)), "frames_after_the_seal": frames_after})
    );
}

/// The journals and the exports of a bundle folder a manifest is made of, with the files of its input: every subfolder that
/// holds a `run.wal`, with the documents in its `docs`, and every `.txt` file that begins as an export.
struct Bundle {
    journals: Vec<(String, Journal, Option<usize>)>,
    exports: Vec<(String, Vec<u8>)>,
    files: Vec<PathBuf>,
    /// The `.txt` files of the folder that are no export.
    skipped: Vec<String>,
}

fn read_bundle(folder: &Path, seals: &BTreeMap<String, usize>) -> Bundle {
    let mut bundle = Bundle { journals: Vec::new(), exports: Vec::new(), files: Vec::new(), skipped: Vec::new() };
    let (journal_names, export_names) = {
        {
            let entries = std::fs::read_dir(folder).unwrap_or_else(|e| fail(&format!("cannot read the bundle {}: {e}", folder.display())));
            let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            paths.sort();
            let (mut journals, mut exports) = (Vec::new(), Vec::new());
            for path in paths {
                let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else { continue };
                if path.join("run.wal").is_file() {
                    journals.push(name);
                } else if path.is_file() && path.extension().is_some_and(|x| x == "txt") {
                    let begins = std::fs::read(&path).is_ok_and(|bytes| bytes.starts_with(format!("{} ", cut::EXPORT_FORMAT).as_bytes()));
                    match (begins, path.file_stem().and_then(|s| s.to_str())) {
                        (true, Some(stem)) => exports.push(stem.to_string()),
                        _ => bundle.skipped.push(name),
                    }
                }
            }
            (journals, exports)
        }
    };
    // a name is a part of a path only once it is known to be a name
    if let Some(name) = journal_names.iter().chain(&export_names).find(|name| !cut::is_name(name)) {
        fail(&format!("{name:?} is no name of a journal or of an export: letters, digits, '.', '_' and '-', at most {} of them", cut::MAX_NAME));
    }
    if let Some(name) = seals.keys().find(|name| !journal_names.contains(name)) {
        fail(&format!("--at names {name}, which is no journal of the bundle"));
    }
    for name in journal_names {
        let path = folder.join(&name).join("run.wal");
        let journal = journal_at(&path, seals.get(&name).map(|n| (*n, None)), &Named::At(&name));
        bundle.journals.push((name.clone(), journal, seals.get(&name).copied()));
        bundle.files.push(path);
        // the documents of the journal are files of the bundle the manifest is of, though making it does not read them
        bundle.files.extend(files_under(&folder.join(&name).join("docs")));
    }
    for name in export_names {
        let path = folder.join(format!("{name}.txt"));
        bundle.exports.push((name, read(&path.display().to_string())));
        bundle.files.push(path);
    }
    bundle
}

/// `sbgk audit-cut manifest --bundle <folder> [--at <name>=<n>,...] [--previous-cut <hash>] [--out <file>]`: the manifest of the
/// cut of a bundle, written to `<folder>/cut.json` by default. Each journal is cut at its last seal, or at the seal of frame
/// `n` that `--at` names for it. Exit 1 when the cut is refused. A manifest says what the journals show; whether the bundle
/// passes is the independent verifier's to say, and this answer does not say it.
fn manifest_step(a: &Args) {
    let folder = PathBuf::from(a.req("bundle"));
    let mut seals = BTreeMap::new();
    for pair in a.get("at").into_iter().flat_map(|list| list.split(',')).map(str::trim).filter(|pair| !pair.is_empty()) {
        let (name, n) = pair.split_once('=').unwrap_or_else(|| fail("--at: <journal>=<frame of its seal>, several with commas between"));
        seals.insert(name.to_string(), frame_number("at", n));
    }
    let previous = a.get("previous-cut").map(|hash| hash_arg("previous-cut", hash));
    let out = a.get("out").map_or(folder.join("cut.json"), PathBuf::from);
    let bundle = read_bundle(&folder, &seals);
    if bundle.journals.is_empty() {
        fail(&format!("the bundle {} holds no journal: a journal is a subfolder with a run.wal", folder.display()));
    }
    let inputs: Vec<(PathBuf, &str)> = bundle.files.iter().map(|path| (path.clone(), "a file of the bundle")).collect();
    let made = cut::cut(bundle.journals, bundle.exports, previous).unwrap_or_else(|e| refused(&folder.display().to_string(), &e));
    let bytes = made.manifest_bytes();
    let after = frames_after(made.parts.iter().map(|(name, part)| (name.as_str(), part)));
    let mut answer = json!({"status": "CUT", "file": out.display().to_string(), "cut_hash": to_hex(&made.cut_hash), "manifest": made.manifest.clone()});
    // a journal whose seal was not named is read whole: the frames after the seal the cut chose replay too
    if let Err((name, seal, frame, e)) = made.rests_replay() {
        rest_refused(&folder.join(&name).join("run.wal").display().to_string(), seal, frame, &e, &Named::At(&name));
    }
    write_out(&out, &bytes, &inputs, "the manifest");
    if !bundle.skipped.is_empty() {
        answer["skipped"] = json!(bundle.skipped);
    }
    if let Some(after) = after {
        answer["frames_after_the_seal"] = after;
    }
    println!("{answer}");
}

/// `sbgk audit-observation --wal <run.wal> [--seal <n>] [--docs <folder>] [--out <file>]`, or `--bundle <folder> [--cut <file>]
/// [--out <file>]`: the observation report of one journal with its documents up to a seal (its last by default), or of the cut
/// of a bundle (`<folder>/cut.json` by default). The documents of the genesis record of a journal are asked for, in the folder
/// of `--docs` or in `<journal>/docs` of a bundle, each known by its bytes: without them the journal cannot be checked from
/// outside, and gets no report. With `--seal` only the frames up to that seal are read and validated. With `--out` the report is written there, in its canonical bytes, and the answer names it; without, the report is
/// the answer. A report is of a checked input (the specification, section 1). The manifest is read as it says, and the bundle
/// is asked what the check of a bundle asks, the documents of each genesis record in `<journal>/docs` among it: a cut that does
/// not pass is refused, exit 1, with the level it fails at. The failure itself is the verifier's to name.
pub fn cmd_audit_observation(a: &Args) {
    let (report, inputs, after) = match (a.get("wal"), a.get("bundle")) {
        (Some(wal), None) => {
            if a.get("cut").is_some() {
                fail("--cut goes with --bundle");
            }
            // the input is the journal with its documents, up to the seal: a close after the seal is no part of it (the
            // specification of the report, section 1)
            let named = a.get("seal").map(|n| frame_number("seal", n));
            let journal = journal_at(Path::new(wal), named.map(|n| (n, None)), &Named::Seal);
            let seal = match named {
                Some(n) => n,
                None => journal.last_seal().unwrap_or_else(|| fail(&format!("{wal} has no seal: the report is of a journal up to a seal"))),
            };
            let part = journal.part(seal, Some(false), &BTreeSet::new()).unwrap_or_else(|e| refused(wal, &e));
            // every file of --docs is read, and is a file of the input: the report is written over none of them
            let mut files = vec![PathBuf::from(wal)];
            let documents = a.get("docs").map(|dir| {
                if !Path::new(dir).is_dir() {
                    fail(&format!("--docs: {dir} is no folder"));
                }
                let supplied = files_under(Path::new(dir));
                let documents = documents_in(&supplied);
                files.extend(supplied);
                documents
            });
            files.extend(documents_beside(Path::new(wal)));
            if let Some(missing) = part.missing_document(documents.as_ref().unwrap_or(&BTreeSet::new())) {
                let how = if documents.is_some() { "is not in the folder of --docs" } else { "was not supplied: name the folder of its documents with --docs" };
                let message =
                    format!("the journal is no checked input of a report: the document {missing:?} of its genesis record {how}. Its quotes cannot be checked from outside without it");
                println!("{}", json!({"status": "REFUSED", "what": wal, "error": {"code": "BAD_FIELD", "field": "docs", "message": message}}));
                std::process::exit(1);
            }
            // a well-formed close right after the seal is no part of the input, and is not counted among the frames left out
            let left = part.frames_after - usize::from(journal.close_follows(seal));
            let (report, after) = (observation::of_journal(&part), (left > 0).then(|| json!({part.state.run_id(): left})));
            if named.is_none() {
                if let Err((frame, e)) = part.rest_replays() {
                    rest_refused(wal, seal, frame, &e, &Named::Seal);
                }
            }
            (report, files, after)
        }
        (None, Some(folder)) => {
            if a.get("seal").is_some() {
                fail("--seal goes with --wal: the manifest of a cut names the seal of each journal");
            }
            if a.get("docs").is_some() {
                fail("--docs goes with --wal: a bundle holds the documents of each journal in <journal>/docs");
            }
            let folder = PathBuf::from(folder);
            let file = a.get("cut").map_or(folder.join("cut.json"), PathBuf::from);
            let shown = file.display().to_string();
            // the file is one JSON object in UTF-8 without a repeated key at any depth (the specification of a cut, section 3): what
            // is none has no single value, and gets no report
            let no_manifest = |why: &str| -> ! {
                let message = format!("{shown} is no {} manifest: {why}", cut::CUT_FORMAT);
                println!("{}", json!({"status": "REFUSED", "what": shown, "error": {"code": "BAD_FIELD", "field": "cut", "message": message}}));
                std::process::exit(1)
            };
            let bytes = read(&shown);
            let given: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| no_manifest(&format!("it is not JSON: {e}")));
            if !given.is_object() || repeats_a_key(&String::from_utf8_lossy(&bytes)) {
                no_manifest("the file is one JSON object, without a key written twice");
            }
            // the names of the manifest are parts of paths only once its form has passed (level B0)
            let (journal_names, export_names) = cut::manifest_form(&given).unwrap_or_else(|e| refused(&shown, &e));
            let fails_at = |level: &str, why: String| -> ! {
                let message = format!("the cut does not pass the check of a bundle at level {level}: {why}");
                println!("{}", json!({"status": "REFUSED", "what": shown, "error": {"code": "BAD_FIELD", "field": "cut", "message": message}}));
                std::process::exit(1)
            };
            let mut files = vec![file.clone()];
            let mut journals = Vec::new();
            for (name, entry) in journal_names.into_iter().zip(given["journals"].as_array().into_iter().flatten()) {
                let path = folder.join(&name).join("run.wal");
                let supplied = files_under(&folder.join(&name).join("docs"));
                let documents = documents_in(&supplied);
                files.extend(supplied);
                if !path.is_file() {
                    fails_at("B1", format!("the journal {name} is not in the bundle"));
                }
                // the part the manifest names, and no frame after it: the form has passed, so both values are there
                let (seal, closed) = (usize::try_from(entry["log_size"].as_u64().unwrap_or(0)).unwrap_or(usize::MAX), entry["closed"].as_bool());
                refuse_locked_whole(&path.display().to_string());
                let journal = Journal::read_part(&path, seal, closed).unwrap_or_else(|e| fails_at("B1", format!("the journal {name}: {}", e.message)));
                journals.push((name, journal, documents));
                files.push(path);
            }
            let mut exports = Vec::new();
            for name in export_names {
                let path = folder.join(format!("{name}.txt"));
                let bytes = std::fs::read(&path).unwrap_or_else(|_| fails_at("B2", format!("the export {name} is not in the bundle")));
                exports.push((name, bytes));
                files.push(path);
            }
            let read = cut::read(&given, journals, exports).unwrap_or_else(|e| refused(&shown, &e));
            (observation::of_cut(&read), files, frames_after(read.parts.iter().map(|(name, part)| (name.as_str(), part))))
        }
        _ => fail("audit-observation takes --wal <run.wal> [--seal <n>] [--docs <folder>], or --bundle <folder> [--cut <file>]"),
    };
    match a.get("out") {
        None => {
            // the report is the whole answer: what was not read is said beside it
            if let Some(after) = after {
                eprintln!("{}", json!({"status": "note", "frames_after_the_seal": after, "note": FRAMES_AFTER}));
            }
            println!("{}", to_jcs(&report));
        }
        Some(out) => {
            let inputs: Vec<(PathBuf, &str)> = inputs.into_iter().map(|path| (path, "a file it was made from")).collect();
            let bytes = observation::report_bytes(&report);
            write_out(Path::new(out), &bytes, &inputs, "the report");
            let mut answer = json!({"status": "OBSERVATION_REPORT", "file": out, "report_hash": report["report_hash"], "cut_hash": report["cut_hash"],
                                    "journals": report["journals"], "claims": report["claims"].as_array().map_or(0, Vec::len),
                                    "debt": report["debt"]["total"], "bytes": bytes.len()});
            if let Some(after) = after {
                answer["frames_after_the_seal"] = after;
            }
            println!("{answer}");
        }
    }
}
