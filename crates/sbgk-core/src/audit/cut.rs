//! A cut of several journals at named seals (`yuce-cut/1`) and the exports between them (`yuce-export/1`), as
//! `verifier/spec/SPEC_CUT_AND_BUNDLE_v1.md` fixes them in its sections 2 and 3.
//!
//! This module makes both, deterministically: an export from one journal at one of its seals, and the manifest of a cut from
//! the journals and the exports of a bundle. A manifest is made only of what the journals themselves show: an export that is not
//! the export section 2 makes of its records is refused, and the deliveries are found, never typed: every document a journal
//! took in with the exact bytes of an export, by its genesis record or by a `put_document` frame of its own.
//!
//! The checks of a bundle (B0 to B4 of that specification), its verdict and its failures are the independent verifier's,
//! written without this code. `read` takes a manifest someone else wrote, for the observation report: it reads the manifest as
//! it says and asks of the bundle what those checks ask, since a report is of a checked input. It answers with the cut or with
//! the level it does not pass, and names no failure of a bundle.

use super::persistence::{lower_hex, AuditJournal, FrameFormat, JournalScan, Payloads};
use super::state::{seal_hash, AuditState};
use super::{RecordId, RecordKind};
use crate::error::{Code, KResult, KernelError};
use crate::hash::{sha256, sha256_parts, to_hex, Hash};
use crate::jcs::to_jcs;
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// The first word of an export, and the format a manifest names.
pub const EXPORT_FORMAT: &str = "yuce-export/1";
pub const CUT_FORMAT: &str = "yuce-cut/1";
/// The longest name of a journal or of an export in a cut.
pub const MAX_NAME: usize = 64;

fn refuse(field: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field(field)
}

/// Strings as a cut and a report sort them: by their UTF-16 code units, the order canonical JSON uses for object keys.
pub fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// A name of a journal or of an export: `[A-Za-z0-9._-]{1,64}`, and neither `.` nor `..`, which name no file of a bundle.
pub fn is_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) && name != "." && name != ".."
}

/// The escapes of an export (section 2.2): a backslash, a line feed and a carriage return, and nothing else.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

fn is_seal(body: &Value) -> bool {
    body["actor"] == "kernel" && body["command"]["kind"] == "seal" && body["outcome"]["kind"] == "value"
}

fn is_close(body: &Value) -> bool {
    body["command"]["kind"] == "close" && body["outcome"]["kind"] == "value"
}

/// A journal read once from its file, before any replay: its frames, and where its seals are.
pub struct Journal {
    scan: JournalScan,
    run_id: String,
    seals: Vec<(usize, Hash)>,
    /// The complete lines of the file after the frames read, when only its first frames were read (`read_part`).
    after: usize,
}

impl Journal {
    /// One bounded, read-only read of the file, as `audit-verify` reads it. Only a journal of the format with seals is taken.
    pub fn read(path: &Path) -> KResult<Journal> {
        Self::of(AuditJournal::read(path)?, 0)
    }

    /// The first frames of the file, up to the seal at frame `seal` and the frame right after it; the bytes after them are not
    /// validated. The check of a bundle reads the part of a journal as a file of its own (`SPEC_CUT_AND_BUNDLE_v1`, B1), so a
    /// damaged frame after the part does not take the part away (the review of 23e15cf3). `closed` is as in `part`: with
    /// `Some(false)` the frame after the seal is not read either, with `Some(true)` it must be whole, and with `None` it is
    /// read when it is whole and is no close when it is not.
    pub fn read_part(path: &Path, seal: usize, closed: Option<bool>) -> KResult<Journal> {
        let frames = seal.saturating_add(1);
        let (scan, after) = match closed {
            Some(false) => AuditJournal::read_prefix(path, frames, false)?,
            Some(true) => AuditJournal::read_prefix(path, frames.saturating_add(1), false)?,
            None => AuditJournal::read_prefix(path, frames, true)?,
        };
        Self::of(scan, after)
    }

    fn of(scan: JournalScan, after: usize) -> KResult<Journal> {
        if scan.format != FrameFormat::V3 {
            return Err(refuse("journal", "a journal of the 0.1 format has no seal: a cut and an export name a seal"));
        }
        let run_id = scan.payloads.first().and_then(|genesis| genesis["run_id"].as_str().map(str::to_string)).unwrap_or_default();
        let seals = scan.payloads.iter().enumerate().filter(|(_, body)| is_seal(body)).map(|(n, body)| (n, seal_hash(&body["command"]["seal"]))).collect();
        Ok(Journal { scan, run_id, seals, after })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The seals of the journal: the frame of each, which is also the number of frames it seals, and its hash.
    pub fn seals(&self) -> &[(usize, Hash)] {
        &self.seals
    }

    /// The bytes after the last complete frame of the file, when no writer held it: a torn tail, usually from a crash. A journal
    /// read up to a named seal (`read_part`) has none: the bytes after its part are outside what was read.
    pub fn torn_tail_bytes(&self) -> u64 {
        if self.scan.live {
            0
        } else {
            self.scan.bytes - self.scan.complete_bytes
        }
    }

    /// Whether the frame right after the seal of frame `seal` was read and is a close.
    pub fn close_follows(&self, seal: usize) -> bool {
        self.scan.payloads.len() > seal + 1 && is_close(&self.scan.payloads.get(seal + 1))
    }

    /// The frame of the journal's last seal.
    pub fn last_seal(&self) -> Option<usize> {
        self.seals.last().map(|(n, _)| *n)
    }

    /// The part of the journal that ends with the seal at frame `seal`, replayed and checked as `audit-verify` checks a
    /// journal. The frames after the part are not replayed. Whether each record stood is kept for the seals of `standing_at`
    /// too: an export is made at a seal of the part, not only at its last.
    ///
    /// `closed` says whether the close right after the seal belongs to the part. `None`: it does when it is there, as a
    /// command that makes a cut takes a journal. `Some`: as a manifest says (`SPEC_CUT_AND_BUNDLE_v1`, section 3 and B1.3):
    /// with `true` the close must be there, and with `false` the part ends with the seal though a close follows it in the file.
    pub fn part(&self, seal: usize, closed: Option<bool>, standing_at: &BTreeSet<usize>) -> KResult<Part> {
        let Some(&(_, hash)) = self.seals.iter().find(|(n, _)| *n == seal) else {
            return Err(refuse(
                "seal",
                format!("frame {seal} is no seal of this journal: its seals are at {:?}", self.seals.iter().map(|s| s.0).collect::<Vec<_>>()),
            ));
        };
        let follows = self.close_follows(seal);
        if closed == Some(true) && !follows {
            return Err(refuse("closed", format!("no close follows the seal of frame {seal}")));
        }
        let closed = closed.unwrap_or(follows);
        let frames = seal + 1 + usize::from(closed);
        let scan = JournalScan {
            format: self.scan.format,
            payloads: self.scan.payloads.prefix(frames),
            heads: self.scan.heads.iter().take(frames).copied().collect(),
            records_roots: self.scan.records_roots.iter().take(frames).copied().collect(),
            bytes: self.scan.bytes,
            complete_bytes: self.scan.complete_bytes,
            sha256: self.scan.sha256,
            live: self.scan.live,
            in_flight: self.scan.in_flight,
        };
        // the records after the first n frames, the versions of the documents of the genesis, and who stood at the seals asked for
        let mut counts = vec![0usize; frames + 1];
        let mut genesis_versions: Vec<(String, Hash)> = Vec::new();
        let mut standing: BTreeMap<usize, Vec<bool>> = BTreeMap::new();
        let (state, _) = AuditState::verify_scan(&scan, &mut |n, state, _| {
            counts[n] = state.record_count();
            if n == 1 {
                genesis_versions = state.document_versions();
            }
            if n == seal || standing_at.contains(&n) {
                standing.insert(n, state.standing());
            }
        })?;
        let mut accepted = Vec::with_capacity(state.record_count());
        let mut puts = Vec::new();
        let (mut rejected_submissions, mut late_submissions) = (0, 0);
        for n in 1..frames {
            let body = scan.payloads.get(n);
            for _ in counts[n]..counts[n + 1] {
                accepted.push((n, body["actor"].as_str().unwrap_or_default().to_string()));
            }
            let (command, outcome) = (&body["command"], &body["outcome"]);
            if outcome["kind"] != "value" {
                continue;
            }
            let put = |operation: &Value, result: &Value, in_batch: bool| {
                let version = lower_hex(&result["document_version"])?;
                let (doc_id, text) = (operation["doc_id"].as_str()?, operation["text"].as_str()?);
                Some(Put { frame: n, doc_id: doc_id.to_string(), sha256: sha256(text.as_bytes()), version, in_batch })
            };
            if command["kind"] == "put_document" {
                puts.extend(put(command, &outcome["result"], false));
            } else if command["kind"] == "batch" {
                if outcome["result"]["checkpointed"] == true {
                    let key = command["checkpoint"]["key"].as_str().unwrap_or_default();
                    rejected_submissions += usize::from(key.starts_with("task-repair:"));
                    late_submissions += usize::from(key.starts_with("task-conflict:"));
                }
                // the operations that ran are those with a result
                let results = outcome["result"]["results"].as_array().map(Vec::as_slice).unwrap_or_default();
                let operations = command["operations"].as_array().map(Vec::as_slice).unwrap_or_default();
                puts.extend(operations.iter().zip(results).filter(|(operation, _)| operation["kind"] == "put_document").filter_map(|(o, r)| put(o, r, true)));
            }
        }
        let genesis_body = scan.payloads.get(0);
        let versions: BTreeMap<String, Hash> = genesis_versions.into_iter().collect();
        let genesis = genesis_body["source_documents"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(doc, identity)| {
                Some(GenesisDocument { doc_id: doc.clone(), sha256: lower_hex(&identity["raw_sha256"])?, version: *versions.get(doc)? })
            })
            .collect();
        let positions = (0..state.record_count()).map(|i| (state.record_at(i).id, i)).collect();
        let seals = self.seals.iter().filter(|(n, _)| *n <= seal).copied().collect();
        let frames_after = self.scan.payloads.len() - frames + self.after;
        // the frames read and validated after the part, kept for a caller that named no seal (`Part::rest_replays`)
        let rest = (self.scan.payloads.len() > frames).then(|| Rest {
            payloads: self.scan.payloads.clone(),
            heads: self.scan.heads.clone(),
            records_roots: self.scan.records_roots.clone(),
            from: frames,
        });
        Ok(Part {
            state,
            log_size: seal,
            seal_hash: hash,
            wal_head: scan.heads[seal - 1],
            closed,
            frames_after,
            seals,
            accepted,
            positions,
            standing,
            genesis,
            puts,
            rejected_submissions,
            late_submissions,
            rest,
        })
    }
}

/// A document of a journal's genesis record: its name, the SHA-256 of its bytes and its version there.
pub struct GenesisDocument {
    pub doc_id: String,
    pub sha256: Hash,
    pub version: Hash,
}

/// A `put_document` that ran in a part: a frame of its own, or an operation of a batch that has a result.
pub struct Put {
    pub frame: usize,
    pub doc_id: String,
    pub sha256: Hash,
    pub version: Hash,
    pub in_batch: bool,
}

/// A journal's part in a cut: its frames `0 ..= log_size`, the seal at `log_size` its last (the close after it when `closed`),
/// and the state those frames make.
pub struct Part {
    pub state: AuditState,
    pub log_size: usize,
    pub seal_hash: Hash,
    /// The hash of frame `log_size - 1`: the head the seal names.
    pub wal_head: Hash,
    pub closed: bool,
    /// The complete frames the journal file holds after the part. They are not replayed: nothing is said of them.
    pub frames_after: usize,
    /// The seals of the part.
    pub seals: Vec<(usize, Hash)>,
    /// For each record, in record order: the frame that accepted it, and the actor of that frame.
    accepted: Vec<(usize, String)>,
    positions: HashMap<RecordId, usize>,
    /// Whether each record stood at a seal, by the frame of the seal.
    standing: BTreeMap<usize, Vec<bool>>,
    pub genesis: Vec<GenesisDocument>,
    pub puts: Vec<Put>,
    /// The frames of the part that record a refused answer and a late one: a batch with outcome `value` whose checkpoint has
    /// a key that starts `task-repair:` or `task-conflict:` and was written (`SPEC_OBSERVATION_REPORT_v1`, section 6).
    pub rejected_submissions: usize,
    pub late_submissions: usize,
    rest: Option<Rest>,
}

/// The frames of a journal file after a part of it: read and validated, not replayed.
struct Rest {
    payloads: Payloads,
    heads: Vec<Hash>,
    records_roots: Vec<Hash>,
    from: usize,
}

/// An export made from a part: its bytes, the records of its paragraphs in order, and the seal it names.
pub struct Export {
    pub bytes: Vec<u8>,
    pub records: Vec<RecordId>,
    pub seal: usize,
    pub seal_hash: Hash,
}

impl Part {
    /// The frames of the file after the part, replayed onto its state as `audit-verify` replays them; the part is used up. The
    /// error is the first frame the kernel refuses, with its number.
    ///
    /// A command that is told no seal takes the last seal of the file itself. The whole file is then its input, and it answers
    /// only where `audit-verify` verifies that file (Codex's review of c64809bb: the tail after the seal the kernel chose was
    /// neither checked nor named). With a seal named the frames after the part are outside the input, and this is not called.
    pub fn rest_replays(mut self) -> Result<(), (usize, KernelError)> {
        let Some(rest) = self.rest.take() else { return Ok(()) };
        for n in rest.from..rest.payloads.len() {
            self.state.replay_frame(n, &rest.payloads.get(n), &rest.heads[..n], rest.records_roots.get(n), true).map_err(|e| (n, e))?;
        }
        Ok(())
    }

    /// A document of the genesis record whose bytes are not among `documents`, the SHA-256 of every file supplied with the
    /// journal. The quotes of a journal are checked from outside against the documents themselves (level J3), so a journal
    /// that lacks one is no checked input, of a cut (`SPEC_CUT_AND_BUNDLE_v1`, B1.5) or of a report of its own
    /// (`SPEC_OBSERVATION_REPORT_v1`, section 1). A document that came by a `put_document` frame is in its frame.
    pub fn missing_document(&self, documents: &BTreeSet<Hash>) -> Option<&str> {
        self.genesis.iter().find(|d| !documents.contains(&d.sha256)).map(|d| d.doc_id.as_str())
    }

    /// The frame that accepted the record at `position` of the record order, and the actor of that frame.
    pub fn accepted_by(&self, position: usize) -> (usize, &str) {
        let (frame, actor) = &self.accepted[position];
        (*frame, actor)
    }

    pub fn position(&self, id: &RecordId) -> Option<usize> {
        self.positions.get(id).copied()
    }

    /// The paragraph of the claim at `position` (section 2.2): its id and text, then the claims and the quotes it rests on, in
    /// the order it names them, each once.
    fn paragraph(&self, position: usize) -> String {
        let record = self.state.record_at(position);
        let mut out = format!("Record {}: {}", to_hex(&record.id.0), escape(record.body["text"].as_str().unwrap_or_default()));
        let mut seen = BTreeSet::new();
        let grounds: Vec<usize> = record.based_on.iter().filter(|g| seen.insert(**g)).filter_map(|g| self.position(g)).collect();
        let of_kind = |kind: RecordKind| grounds.iter().map(|g| self.state.record_at(*g)).filter(move |g| g.kind == kind);
        let rests: Vec<String> = of_kind(RecordKind::Claim).map(|g| to_hex(&g.id.0)).collect();
        if !rests.is_empty() {
            out.push_str(" Rests on: ");
            out.push_str(&rests.join(", "));
        }
        let quotes: Vec<String> = of_kind(RecordKind::Observe)
            .map(|g| format!("[{}] \"{}\"", escape(g.doc_id.as_deref().unwrap_or_default()), escape(g.quote.as_deref().unwrap_or_default())))
            .collect();
        if !quotes.is_empty() {
            out.push_str(" Quotes: ");
            out.push_str(&quotes.join(" ; "));
        }
        out
    }

    /// The export of `claims` at the seal of frame `seal` of this part (section 2); without a list, of every claim that stands
    /// at that seal. The paragraphs come in record order whatever order the list has. A record that is no claim of the journal
    /// before that seal, that is named twice or that does not stand there is refused: an export carries standing claims only.
    pub fn export(&self, seal: usize, claims: Option<&[RecordId]>) -> KResult<Export> {
        let seal_hash = self.seals.iter().find(|(n, _)| *n == seal).map(|(_, hash)| *hash).ok_or_else(|| refuse("seal", "no seal of this part"))?;
        let standing = self.standing.get(&seal).ok_or_else(|| refuse("seal", "the part was not read at this seal"))?;
        let is_claim = |position: usize| self.state.record_at(position).kind == RecordKind::Claim;
        let positions: BTreeSet<usize> = match claims {
            None => (0..standing.len()).filter(|p| standing[*p] && is_claim(*p)).collect(),
            Some(ids) => {
                let mut out = BTreeSet::new();
                for id in ids {
                    let short = id.short();
                    let position = self.position(id).filter(|p| *p < standing.len());
                    let position = position.ok_or_else(|| refuse("record", format!("{short} is no record the journal accepted before that seal")))?;
                    if !is_claim(position) {
                        return Err(refuse("record", format!("{short} is no claim: an export carries claims")));
                    }
                    if !standing[position] {
                        return Err(refuse("record", format!("{short} does not stand at that seal: an export carries standing claims only")));
                    }
                    if !out.insert(position) {
                        return Err(refuse("record", format!("{short} is named twice: a record is exported at most once")));
                    }
                }
                out
            }
        };
        let mut lines = vec![format!("{EXPORT_FORMAT} run={} seal={} records={}", escape(self.state.run_id()), to_hex(&seal_hash), positions.len())];
        lines.extend(positions.iter().map(|p| self.paragraph(*p)));
        let records = positions.iter().map(|p| self.state.record_at(*p).id).collect();
        Ok(Export { bytes: (lines.join("\n\n") + "\n").into_bytes(), records, seal, seal_hash })
    }

    /// The quotes of the part bound to one version of one document, in record order: their bytes there and their records.
    fn quotes_of(&self, doc_id: &str, version: &Hash) -> Vec<(usize, usize, RecordId)> {
        (0..self.state.record_count())
            .map(|i| self.state.record_at(i))
            .filter(|r| r.kind == RecordKind::Observe && r.doc_id.as_deref() == Some(doc_id))
            .filter_map(|r| self.state.evidence_binding(&r.id).filter(|b| b.1 == *version).map(|b| (b.2, b.3, r.id)))
            .collect()
    }
}

/// The header of an export file and its paragraphs: where each lies in the file, and the record it names.
struct ParsedExport {
    run: String,
    seal_hash: Hash,
    paragraphs: Vec<(usize, usize, RecordId)>,
}

/// An export file read only as far as section 2.2 lets a reader go: its header, and of each paragraph the prefix `Record <id>: `.
/// The rest of a paragraph is never split: it is compared with the paragraph made from the record.
fn parse_export(name: &str, bytes: &[u8]) -> KResult<ParsedExport> {
    let no = |what: &str| refuse("export", format!("{name} is no {EXPORT_FORMAT} file: {what}"));
    let body = bytes.strip_suffix(b"\n").ok_or_else(|| no("it does not end with a line feed"))?;
    let mut pieces: Vec<(usize, &[u8])> = Vec::new();
    let mut at = 0;
    loop {
        match body[at..].windows(2).position(|w| w == b"\n\n") {
            Some(len) => {
                pieces.push((at, &body[at..at + len]));
                at += len + 2;
            }
            None => {
                pieces.push((at, &body[at..]));
                break;
            }
        }
    }
    let header = std::str::from_utf8(pieces[0].1).map_err(|_| no("its header is not UTF-8"))?;
    let rest = header.strip_prefix(EXPORT_FORMAT).and_then(|r| r.strip_prefix(" run=")).ok_or_else(|| no("its first line is not the header"))?;
    // read from the end: an escaped run id may hold a space or the words of the header
    let (rest, count) = rest.rsplit_once(" records=").ok_or_else(|| no("its header names no number of records"))?;
    let (run, seal) = rest.rsplit_once(" seal=").ok_or_else(|| no("its header names no seal"))?;
    let seal_hash = lower_hex(&json!(seal)).ok_or_else(|| no("the seal of its header is not 64 lowercase hex digits"))?;
    if count != (pieces.len() - 1).to_string() {
        return Err(no("the number of records in its header is not the number of its paragraphs"));
    }
    let mut paragraphs = Vec::new();
    for (start, piece) in &pieces[1..] {
        let id = piece.strip_prefix(b"Record ").filter(|p| p.len() >= 66 && &p[64..66] == b": ").and_then(|p| std::str::from_utf8(&p[..64]).ok());
        let id = id.and_then(|hex| lower_hex(&json!(hex))).ok_or_else(|| no("a paragraph does not begin with `Record <id>: `"))?;
        paragraphs.push((*start, start + piece.len(), RecordId(id)));
    }
    Ok(ParsedExport { run: run.to_string(), seal_hash, paragraphs })
}

/// An export of a cut: its name, its bytes, the journal it was made from and the seal it names.
pub struct CutExport {
    pub name: String,
    pub bytes: Vec<u8>,
    pub sha256: Hash,
    /// The place of its journal in the journals of the cut.
    pub journal: usize,
    pub seal_hash: Hash,
    /// Its paragraphs: the bytes of each in the file, and the record it names.
    pub paragraphs: Vec<(usize, usize, RecordId)>,
}

/// A delivery of a cut: the frame of a journal that brought an export in as a document, and the version it brought.
pub struct Delivery {
    pub export: usize,
    pub journal: usize,
    pub doc_id: String,
    pub frame: usize,
    pub version: Hash,
}

/// A quote of a receiving journal that lies, wholly or in part, inside a paragraph of a delivered export.
pub struct Across {
    pub delivery: usize,
    /// The record the paragraph names, in the journal the export was made from, and whether it stands there at the cut.
    pub record: RecordId,
    pub record_stands: bool,
    /// The observation of the receiving journal, and whether it stands there at the cut.
    pub observation: RecordId,
    pub observation_stands: bool,
}

/// A cut made from a bundle: its manifest and what the manifest was made of.
pub struct Cut {
    pub manifest: Value,
    pub cut_hash: Hash,
    /// The journals of the cut, by name in the order of the manifest, each with its part.
    pub parts: Vec<(String, Part)>,
    pub exports: Vec<CutExport>,
    pub deliveries: Vec<Delivery>,
    /// The parts whose seal the cut chose itself: the journals given without one.
    chosen: Vec<usize>,
}

/// `cut_hash = H("YUCE-CUT/1", JCS(manifest))` (section 3).
pub fn cut_hash(manifest: &Value) -> Hash {
    sha256_parts(&[b"YUCE-CUT/1\0", to_jcs(manifest).as_bytes()])
}

/// The cut of `journals` (each with its name and the frame of the seal that ends its part; without one, its last seal) and of
/// `exports` (each with its name and its bytes), in mode `observe`.
///
/// Refused: a name that is none or is given twice; a journal without the seal; an export that names no seal of a journal of the
/// cut at or before that journal's seal in the cut, or that is not, byte for byte, the export section 2 makes of the records it
/// names at that seal; and a batch that brought the exact bytes of an export into a journal, which no delivery can declare.
pub fn cut(journals: Vec<(String, Journal, Option<usize>)>, exports: Vec<(String, Vec<u8>)>, previous_cut: Option<Hash>) -> KResult<Cut> {
    let mut journals = journals;
    let mut exports = exports;
    journals.sort_by(|a, b| utf16_order(&a.0, &b.0));
    exports.sort_by(|a, b| utf16_order(&a.0, &b.0));
    let names = |what: &str, names: Vec<&String>| -> KResult<()> {
        for pair in names.windows(2) {
            if pair[0] == pair[1] {
                return Err(refuse(what, format!("the name {} is given twice", pair[0])));
            }
        }
        match names.iter().find(|name| !is_name(name)) {
            Some(name) => Err(refuse(what, format!("{name:?} is no name: letters, digits, '.', '_' and '-', at most {MAX_NAME} of them, and not '.' or '..'"))),
            None => Ok(()),
        }
    };
    names("journal", journals.iter().map(|j| &j.0).collect())?;
    names("export", exports.iter().map(|e| &e.0).collect())?;
    let mut seal_of = Vec::new();
    let mut chosen = Vec::new();
    for (j, (name, journal, seal)) in journals.iter().enumerate() {
        if seal.is_none() {
            // the cut takes the last seal of the file itself: the whole file is then the input
            if journal.torn_tail_bytes() > 0 {
                return Err(refuse(
                    "journal",
                    format!(
                        "the journal {name} ends in {} bytes that are no complete frame: with no seal named the whole file is the input",
                        journal.torn_tail_bytes()
                    ),
                ));
            }
            chosen.push(j);
        }
        let seal =
            seal.or(journal.last_seal()).ok_or_else(|| refuse("journal", format!("the journal {name} has no seal: a cut names a seal of each journal")))?;
        seal_of.push(seal);
    }
    // each export names its journal by the run id and a seal: found before any replay, so that one replay of a journal keeps
    // who stood at every seal its exports name
    let mut parsed = Vec::new();
    let mut standing_at: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); journals.len()];
    for (name, bytes) in &exports {
        let export = parse_export(name, bytes)?;
        let found: Vec<(usize, usize)> = journals
            .iter()
            .enumerate()
            .filter(|(_, (_, journal, _))| escape(journal.run_id()) == export.run)
            .filter_map(|(j, (_, journal, _))| journal.seals().iter().find(|(n, hash)| *hash == export.seal_hash && *n <= seal_of[j]).map(|(n, _)| (j, *n)))
            .collect();
        let &[(journal, seal)] = found.as_slice() else {
            let why = if found.is_empty() {
                "names no seal of a journal of the cut, at or before that journal's seal in the cut"
            } else {
                "names a seal that two journals of the cut have"
            };
            return Err(refuse("export", format!("the export {name} (run {}, seal {}) {why}", export.run, to_hex(&export.seal_hash))));
        };
        standing_at[journal].insert(seal);
        parsed.push((journal, seal, export));
    }
    let mut parts = Vec::new();
    for (j, (name, journal, _)) in journals.iter().enumerate() {
        let part = journal.part(seal_of[j], None, &standing_at[j]).map_err(|e| refuse("journal", format!("the journal {name}: {}", e.message)))?;
        parts.push((name.clone(), part));
    }
    let mut cut_exports = Vec::new();
    for ((name, bytes), (journal, seal, export)) in exports.into_iter().zip(parsed) {
        let ids: Vec<RecordId> = export.paragraphs.iter().map(|p| p.2).collect();
        let made = parts[journal].1.export(seal, Some(&ids)).map_err(|e| refuse("export", format!("the export {name}: {}", e.message)))?;
        if made.bytes != bytes {
            let why = if made.records != ids { "its paragraphs are not in record order" } else { "a paragraph is not the one made from its record" };
            return Err(refuse("export", format!("the export {name} is not the export made of these records at that seal: {why}")));
        }
        cut_exports.push(CutExport { name, sha256: sha256(&bytes), bytes, journal, seal_hash: export.seal_hash, paragraphs: export.paragraphs });
    }
    // the deliveries: every document a journal took in with the exact bytes of an export, the first export of those bytes
    let mut by_bytes: HashMap<Hash, usize> = HashMap::new();
    for (e, export) in cut_exports.iter().enumerate() {
        by_bytes.entry(export.sha256).or_insert(e);
    }
    let mut deliveries = Vec::new();
    for (journal, (name, part)) in parts.iter().enumerate() {
        for document in &part.genesis {
            if let Some(&export) = by_bytes.get(&document.sha256) {
                deliveries.push(Delivery { export, journal, doc_id: document.doc_id.clone(), frame: 0, version: document.version });
            }
        }
        for put in &part.puts {
            let Some(&export) = by_bytes.get(&put.sha256) else { continue };
            if put.in_batch {
                let message = format!(
                    "frame {} of the journal {name} is a batch that brings in the exact bytes of the export {}: a delivery is a put_document frame of its own, \
                     and no cut can declare this one",
                    put.frame, cut_exports[export].name
                );
                return Err(refuse("delivery", message));
            }
            deliveries.push(Delivery { export, journal, doc_id: put.doc_id.clone(), frame: put.frame, version: put.version });
        }
    }
    deliveries.sort_by(|a, b| utf16_order(&parts[a.journal].0, &parts[b.journal].0).then(a.frame.cmp(&b.frame)).then(utf16_order(&a.doc_id, &b.doc_id)));
    let manifest = json!({
        "format": CUT_FORMAT,
        "mode": "observe",
        "journals": parts.iter().map(|(name, part)| json!({"name": name, "run_id": part.state.run_id(), "rules_version": part.state.rules_version(),
            "seal_hash": to_hex(&part.seal_hash), "log_size": part.log_size, "wal_head": to_hex(&part.wal_head), "closed": part.closed})).collect::<Vec<_>>(),
        "exports": cut_exports.iter().map(|e| json!({"name": e.name, "journal": parts[e.journal].0, "seal_hash": to_hex(&e.seal_hash),
            "sha256": to_hex(&e.sha256), "records": e.paragraphs.len()})).collect::<Vec<_>>(),
        "deliveries": deliveries.iter().map(|d| json!({"export": cut_exports[d.export].name, "journal": parts[d.journal].0, "doc_id": d.doc_id,
            "frame": d.frame})).collect::<Vec<_>>(),
        "previous_cut": previous_cut.map(|hash| to_hex(&hash)),
    });
    Ok(Cut { cut_hash: cut_hash(&manifest), manifest, parts, exports: cut_exports, deliveries, chosen })
}

impl Cut {
    /// `Part::rest_replays` for every journal whose seal the cut chose itself; the cut is used up. The error names the journal,
    /// the seal the cut chose for it, the frame the kernel refuses and the refusal.
    pub fn rests_replay(self) -> Result<(), (String, usize, usize, KernelError)> {
        for (j, (name, part)) in self.parts.into_iter().enumerate() {
            if self.chosen.contains(&j) {
                let seal = part.log_size;
                part.rest_replays().map_err(|(frame, e)| (name, seal, frame, e))?;
            }
        }
        Ok(())
    }

    /// The bytes of the manifest file: canonical JSON and a line feed.
    pub fn manifest_bytes(&self) -> Vec<u8> {
        (to_jcs(&self.manifest) + "\n").into_bytes()
    }

    /// Every quote of a receiving journal that lies, wholly or in part, inside a paragraph of an export delivered to it, bound
    /// to the delivered version: in the order of the deliveries, then of the paragraphs, then of the records. Two spans overlap
    /// when each begins before the other ends; spans that only touch do not.
    pub fn across(&self) -> Vec<Across> {
        let mut out = Vec::new();
        for (d, delivery) in self.deliveries.iter().enumerate() {
            let export = &self.exports[delivery.export];
            let (source, receiver) = (&self.parts[export.journal].1, &self.parts[delivery.journal].1);
            let quotes = receiver.quotes_of(&delivery.doc_id, &delivery.version);
            for (start, end, record) in &export.paragraphs {
                let record_stands = source.state.is_grounded(record);
                for (_, _, observation) in quotes.iter().filter(|(a, z, _)| a < end && start < z) {
                    out.push(Across {
                        delivery: d,
                        record: *record,
                        record_stands,
                        observation: *observation,
                        observation_stands: receiver.state.is_grounded(observation),
                    });
                }
            }
        }
        out
    }

    /// The level of the bundle check the journals show this cut failing, among the two a made manifest does not hold by
    /// itself: `B3.3`, a delivered document name the journal had before the delivery or put again after it; `B4`, a quote
    /// of a receiving journal that still stands inside a paragraph whose record no longer stands in its own journal. The
    /// verdict on a bundle and the list of its failures are the independent verifier's alone: this answer only keeps a
    /// report from being made of a cut that does not pass, as the report is of a checked input.
    pub fn unmet_level(&self) -> Option<&'static str> {
        for delivery in &self.deliveries {
            let part = &self.parts[delivery.journal].1;
            let before = delivery.frame > 0
                && (part.genesis.iter().any(|d| d.doc_id == delivery.doc_id)
                    || part.puts.iter().any(|p| p.doc_id == delivery.doc_id && p.frame < delivery.frame));
            if before || part.puts.iter().any(|p| p.doc_id == delivery.doc_id && p.frame > delivery.frame) {
                return Some("B3.3");
            }
        }
        self.across().iter().any(|hit| !hit.record_stands && hit.observation_stands).then_some("B4")
    }
}

/// The refusal of a cut that does not pass the check of a bundle: the level, and in words what does not hold.
fn fails(level: &str, why: impl AsRef<str>) -> KernelError {
    refuse("cut", format!("the cut does not pass the check of a bundle at level {level}: {}", why.as_ref()))
}

/// Level B0: the form of a manifest (`SPEC_CUT_AND_BUNDLE_v1`, sections 3 and 5). Exactly the keys of section 3 with values of
/// the stated types, whole numbers below 2^53, names that are names, the lists sorted by UTF-16 code units, names unique,
/// deliveries that may coexist, every reference resolved, mode `observe`. Answers with the names of the journals and of the
/// exports, in the order of the manifest: a name is a part of a path of a bundle only once this check has passed.
pub fn manifest_form(manifest: &Value) -> KResult<(Vec<String>, Vec<String>)> {
    let no = |why: &str| fails("B0", why);
    let keys = |v: &Value, keys: &[&str]| v.as_object().is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)));
    let hash = |v: &Value| lower_hex(v).is_some();
    let name = |v: &Value| v.as_str().is_some_and(is_name);
    let number = |v: &Value| v.as_u64().is_some_and(|n| n < 1 << 53);
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    if !keys(manifest, &["format", "mode", "journals", "exports", "deliveries", "previous_cut"]) {
        return Err(no("a manifest has exactly the keys format, mode, journals, exports, deliveries and previous_cut"));
    }
    if manifest["format"] != CUT_FORMAT || manifest["mode"] != "observe" {
        return Err(no("the format is yuce-cut/1 and the mode is observe"));
    }
    if !(manifest["previous_cut"].is_null() || hash(&manifest["previous_cut"])) {
        return Err(no("previous_cut is null or a hash"));
    }
    let (Some(journals), Some(exports), Some(deliveries)) =
        (manifest["journals"].as_array(), manifest["exports"].as_array(), manifest["deliveries"].as_array())
    else {
        return Err(no("journals, exports and deliveries are lists"));
    };
    let journal_ok = |j: &Value| {
        keys(j, &["name", "run_id", "rules_version", "seal_hash", "log_size", "wal_head", "closed"])
            && name(&j["name"])
            && j["run_id"].is_string()
            && j["rules_version"].is_string()
            && hash(&j["seal_hash"])
            && number(&j["log_size"])
            && hash(&j["wal_head"])
            && j["closed"].is_boolean()
    };
    let export_ok = |e: &Value| {
        keys(e, &["name", "journal", "seal_hash", "sha256", "records"])
            && name(&e["name"])
            && name(&e["journal"])
            && hash(&e["seal_hash"])
            && hash(&e["sha256"])
            && number(&e["records"])
    };
    let delivery_ok = |d: &Value| {
        keys(d, &["export", "journal", "doc_id", "frame"])
            && name(&d["export"])
            && name(&d["journal"])
            && d["doc_id"].as_str().is_some_and(|doc| !doc.is_empty())
            && number(&d["frame"])
    };
    if !journals.iter().all(journal_ok) || !exports.iter().all(export_ok) || !deliveries.iter().all(delivery_ok) {
        return Err(no("an entry of journals, exports or deliveries has other keys or values than section 3 states"));
    }
    let journal_names: Vec<String> = journals.iter().map(|j| text(&j["name"])).collect();
    let export_names: Vec<String> = exports.iter().map(|e| text(&e["name"])).collect();
    for names in [&journal_names, &export_names] {
        if names.windows(2).any(|pair| utf16_order(&pair[0], &pair[1]) != Ordering::Less) {
            return Err(no("journals and exports are sorted by name, each name once"));
        }
    }
    let place = |d: &Value| (text(&d["journal"]), d["frame"].as_u64().unwrap_or(0), text(&d["doc_id"]));
    let order = |a: &Value, b: &Value| {
        let (a, b) = (place(a), place(b));
        utf16_order(&a.0, &b.0).then(a.1.cmp(&b.1)).then(utf16_order(&a.2, &b.2))
    };
    if deliveries.windows(2).any(|pair| order(&pair[0], &pair[1]) == Ordering::Greater) {
        return Err(no("deliveries are sorted by journal, frame and doc_id"));
    }
    // a genesis record holds several documents, one delivery each; a later frame is one put, so one delivery
    let mut seen = BTreeSet::new();
    for d in deliveries {
        let (journal, frame, doc) = place(d);
        if !seen.insert(if frame == 0 { (journal, 0, doc) } else { (journal, frame, String::new()) }) {
            return Err(no("two deliveries name the same document of a genesis record, or the same later frame"));
        }
    }
    let resolved = exports.iter().all(|e| journal_names.contains(&text(&e["journal"])))
        && deliveries.iter().all(|d| journal_names.contains(&text(&d["journal"])) && export_names.contains(&text(&d["export"])));
    if !resolved {
        return Err(no("an export or a delivery names a journal or an export the manifest does not list"));
    }
    Ok((journal_names, export_names))
}

/// The cut a given manifest describes, read as the manifest says: its journals at the seals and with the `closed` it names, its
/// exports from the journals it names, its deliveries at the frames it names. `journals` and `exports` are the files of the
/// bundle in the order of the manifest's lists, each journal with the SHA-256 of every file of its documents folder.
///
/// A report is of a checked input, so this asks what the check of a bundle asks (levels B0 to B4), no less and no more:
/// - B1: frame `log_size` is the seal named, with the head, the run id and the rules named; with `closed: true` the close
///   follows; the part replays (the frames after it are not read); and every document of its genesis record is in its folder,
///   as the independent verifier needs it to check the quotes;
/// - B2: each export has the bytes named, names a seal of the part of the journal named, and is the export section 2 makes of
///   its records there;
/// - B3: each delivery is the document of the genesis record, or the `put_document` frame of its own, that it names, with the
///   bytes of the export it names; no other document of a journal has the bytes of an export of the cut; no delivered name
///   existed before or is put again;
/// - B4: no quote of a receiving journal stands inside a paragraph whose record no longer stands in its own journal.
///
/// The refusal names the level and what does not hold. The verdict on a bundle and its failures are the independent verifier's.
pub fn read(manifest: &Value, journals: Vec<(String, Journal, BTreeSet<Hash>)>, exports: Vec<(String, Vec<u8>)>) -> KResult<Cut> {
    let (journal_names, export_names) = manifest_form(manifest)?;
    if journals.iter().map(|j| &j.0).ne(journal_names.iter()) || exports.iter().map(|e| &e.0).ne(export_names.iter()) {
        return Err(refuse("cut", "the journals and the exports read are not those the manifest lists, in its order"));
    }
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let place_of = |names: &[String], v: &Value| names.iter().position(|n| *n == text(v)).expect("a reference the form check resolved");
    let entries = |list: &str| manifest[list].as_array().cloned().unwrap_or_default();
    let (journal_entries, export_entries, delivery_entries) = (entries("journals"), entries("exports"), entries("deliveries"));
    // one replay of a journal keeps who stood at every seal an export of it names
    let mut standing_at: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); journals.len()];
    for entry in &export_entries {
        let j = place_of(&journal_names, &entry["journal"]);
        standing_at[j].extend(journals[j].1.seals().iter().filter(|(_, hash)| to_hex(hash) == text(&entry["seal_hash"])).map(|(n, _)| *n));
    }
    // B1
    let mut parts = Vec::new();
    for (j, ((name, journal, documents), entry)) in journals.iter().zip(&journal_entries).enumerate() {
        let b1 = |why: String| fails("B1", format!("the journal {name}: {why}"));
        let n = entry["log_size"].as_u64().unwrap_or(0) as usize;
        if !journal.seals().iter().any(|(k, hash)| *k == n && to_hex(hash) == text(&entry["seal_hash"])) {
            return Err(b1(format!("frame {n} is not the seal the manifest names")));
        }
        let part = journal.part(n, entry["closed"].as_bool(), &standing_at[j]).map_err(|e| b1(e.message))?;
        if to_hex(&part.wal_head) != text(&entry["wal_head"]) {
            return Err(b1("its head before the seal is not the wal_head the manifest names".into()));
        }
        if part.state.run_id() != text(&entry["run_id"]) || part.state.rules_version() != text(&entry["rules_version"]) {
            return Err(b1("its genesis record names another run id or other rules than the manifest".into()));
        }
        if let Some(missing) = part.missing_document(documents) {
            return Err(b1(format!(
                "the document {missing:?} of its genesis record is not in its documents folder: its quotes cannot be checked from outside"
            )));
        }
        parts.push((name.clone(), part));
    }
    // B2
    let mut cut_exports = Vec::new();
    for ((name, bytes), entry) in exports.into_iter().zip(&export_entries) {
        let b2 = |why: String| fails("B2", format!("the export {name}: {why}"));
        let journal = place_of(&journal_names, &entry["journal"]);
        let part = &parts[journal].1;
        let sha = sha256(&bytes);
        if to_hex(&sha) != text(&entry["sha256"]) {
            return Err(b2("its bytes do not have the SHA-256 the manifest names".into()));
        }
        let parsed = parse_export(&name, &bytes).map_err(|e| b2(e.message))?;
        if parsed.run != escape(part.state.run_id())
            || to_hex(&parsed.seal_hash) != text(&entry["seal_hash"])
            || Some(parsed.paragraphs.len() as u64) != entry["records"].as_u64()
        {
            return Err(b2("its header does not name the run of its journal, the seal and the number of records the manifest names".into()));
        }
        let Some(&(seal, _)) = part.seals.iter().find(|(_, hash)| *hash == parsed.seal_hash) else {
            return Err(b2(format!("it names no seal of the part of the journal {}", parts[journal].0)));
        };
        let ids: Vec<RecordId> = parsed.paragraphs.iter().map(|p| p.2).collect();
        let made = part.export(seal, Some(&ids)).map_err(|e| b2(e.message))?;
        if made.bytes != bytes {
            return Err(b2("it is not the export made of these records at that seal".into()));
        }
        cut_exports.push(CutExport { name, sha256: sha, bytes, journal, seal_hash: parsed.seal_hash, paragraphs: parsed.paragraphs });
    }
    // B3.1: each delivery is what it names
    let mut deliveries = Vec::new();
    for entry in &delivery_entries {
        let (export, journal) = (place_of(&export_names, &entry["export"]), place_of(&journal_names, &entry["journal"]));
        let (doc_id, frame) = (text(&entry["doc_id"]), entry["frame"].as_u64().unwrap_or(0) as usize);
        let (part, sha) = (&parts[journal].1, cut_exports[export].sha256);
        let version = if frame == 0 {
            part.genesis.iter().find(|d| d.doc_id == doc_id && d.sha256 == sha).map(|d| d.version)
        } else {
            part.puts.iter().find(|p| !p.in_batch && p.frame == frame && p.doc_id == doc_id && p.sha256 == sha).map(|p| p.version)
        };
        let Some(version) = version else {
            let why = format!(
                "frame {frame} of the journal {} does not bring the export {} in as the document {doc_id:?}",
                parts[journal].0, cut_exports[export].name
            );
            return Err(fails("B3.1", why));
        };
        deliveries.push(Delivery { export, journal, doc_id, frame, version });
    }
    // B3.2: every document with the exact bytes of an export of the cut is declared
    let of_an_export: BTreeSet<Hash> = cut_exports.iter().map(|e| e.sha256).collect();
    for (journal, (name, part)) in parts.iter().enumerate() {
        let genesis = part.genesis.iter().filter(|d| of_an_export.contains(&d.sha256)).map(|d| (0, d.doc_id.as_str()));
        let puts = part.puts.iter().filter(|p| of_an_export.contains(&p.sha256)).map(|p| (p.frame, p.doc_id.as_str()));
        for (frame, doc_id) in genesis.chain(puts) {
            let declared = deliveries.iter().any(|d| d.journal == journal && d.frame == frame && (frame > 0 || d.doc_id == doc_id));
            if !declared {
                return Err(fails(
                    "B3.2",
                    format!("frame {frame} of the journal {name} brings the bytes of an export in as the document {doc_id:?}, and no delivery declares it"),
                ));
            }
        }
    }
    let cut = Cut { cut_hash: cut_hash(manifest), manifest: manifest.clone(), parts, exports: cut_exports, deliveries, chosen: Vec::new() };
    match cut.unmet_level() {
        Some("B3.3") => Err(fails("B3.3", "a delivered document existed in its journal before the delivery, or is put again after it")),
        Some(level) => Err(fails(level, "a quote of a receiving journal stands inside a paragraph whose record no longer stands in its own journal")),
        None => Ok(cut),
    }
}

#[cfg(test)]
#[path = "cut_tests.rs"]
mod tests;
