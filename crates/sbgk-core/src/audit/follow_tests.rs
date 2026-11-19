//! Tests of the follower on journals the kernel writes: a journal read in parts gives what the same journal read whole gives.

use super::*;
use crate::audit::onto::AuditOntology;
use crate::audit::persistence::{self, body_hash, header_hash, header_v3};
use crate::audit::prov::{self, Tracker};
use crate::audit::state::GenesisSpec;
use crate::audit::{RecordId, Scope};
use crate::hash::{from_hex, to_hex};
use crate::jcs::to_jcs;
use serde_json::json;
use std::io::Write;

const DOC: &[u8] = b"The first line names the rule.\nThe second line names its exception.\n";
const EDITED: &[u8] = b"The first line names the rule.\nThe second line was rewritten.\n";

struct TempPath(PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp(name: &str) -> TempPath {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    TempPath(std::env::temp_dir().join(format!(
        "r2r_follow_{name}_{}_{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )))
}

fn submit(s: &mut AuditState, id: &str, lines: &[Value]) -> String {
    let scope = Scope { docs: vec!["d".into()], topic: Some("t".into()), ranges: Vec::new() };
    let r = s.submit_records_id(id, "worker", "w", &scope, lines);
    assert!(r.error.is_none(), "{:?}", r.error);
    to_hex(&r.accepted[0].0)
}

fn start(path: &Path) -> AuditState {
    let spec = GenesisSpec { questions: json!([]), settings: json!({"format": "fixture"}), operator_meta: None };
    AuditState::create_with(path, &AuditOntology::base(), &[("d".to_string(), DOC.to_vec())], "follow run", sha256(b"m"), &spec).unwrap()
}

/// A journal with two quotes, a claim on both, a seal, one quote withdrawn (the claim falls), the document edited and put back,
/// and a last seal. Returns its bytes.
fn journal(path: &Path) -> Vec<u8> {
    let mut s = start(path);
    let o1 =
        submit(&mut s, "a", &[json!({"kind": "observe", "local_id": "o1", "doc_id": "d", "exact_quote": "The first line names the rule.", "terms": ["t"]})]);
    submit(&mut s, "b", &[json!({"kind": "observe", "local_id": "o2", "doc_id": "d", "exact_quote": "The second line names its exception.", "terms": ["t"]})]);
    submit(
        &mut s,
        "c",
        &[json!({"kind": "claim", "local_id": "c1", "text": "The rule has an exception.", "subject": "rule", "stance": "reported", "based_on": ["o1", "o2"]})],
    );
    s.seal().unwrap();
    s.revoke_observation("owner", &RecordId(from_hex(&o1).unwrap())).unwrap();
    s.put_document("owner", "d", EDITED).unwrap();
    s.put_document("owner", "d", DOC).unwrap();
    s.seal().unwrap();
    drop(s);
    std::fs::read(path).unwrap()
}

fn append(path: &Path, bytes: &[u8]) {
    std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap().write_all(bytes).unwrap();
}

/// A follower with the export tracker beside it, as `audit-watch` runs them.
struct Watch {
    follower: Follower,
    tracker: Tracker,
}

impl Watch {
    fn new(path: &Path) -> Self {
        Self { follower: Follower::new(path), tracker: Tracker::new() }
    }

    fn step(&mut self) -> Result<Tail, Stop> {
        let tracker = &mut self.tracker;
        self.follower.advance(&mut |f| {
            tracker.frame(f.state, f.payload, f.head);
            true
        })
    }

    fn export(&self) -> String {
        self.tracker.document(self.follower.state().unwrap(), false).unwrap().text()
    }
}

#[test]
fn a_journal_read_in_parts_gives_the_export_of_the_same_frames_read_whole() {
    let (whole, growing) = (temp("whole"), temp("growing"));
    let bytes = journal(&whole.0);
    let frames = bytes.iter().filter(|b| **b == b'\n').count();
    let mut watch = Watch::new(&growing.0);
    assert!(matches!(watch.step(), Err(Stop::Unreadable(_))), "a journal that is not there yet is waited for");
    // the file grows by pieces that end inside frames: 700 bytes, then 1 byte, then 3000, and so on to the end
    let mut at = 0;
    let mut seen = 0;
    for piece in [700usize, 1, 3000, 17, 5000, 1, usize::MAX].into_iter().cycle() {
        let end = at + piece.min(bytes.len() - at);
        append(&growing.0, &bytes[at..end]);
        at = end;
        let complete = bytes[..at].iter().filter(|b| **b == b'\n').count();
        let tail_bytes = at - bytes[..at].iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let tail = watch.step().unwrap();
        assert_eq!((tail.frames, tail.new, tail.pending), (complete, complete - seen, tail_bytes as u64));
        assert!(!tail.writer && !tail.more, "no writer holds a file a test appends to, and a step reads to its end");
        seen = complete;
        if complete > 0 {
            assert_eq!(watch.export(), prov::export_at(&whole.0, Some(complete)).unwrap().text(), "at {complete} frames");
        }
        if at == bytes.len() {
            break;
        }
    }
    assert_eq!(seen, frames);
    assert_eq!(watch.export(), prov::export(&whole.0).unwrap().text());
    // nothing new: a step reads nothing and changes nothing
    assert_eq!(watch.step().unwrap(), Tail { frames, new: 0, writer: false, pending: 0, more: false });
    let (state, read) = AuditState::verify(&whole.0, &mut |_, _, _, _| {}).unwrap();
    let followed = watch.follower.state().unwrap();
    assert_eq!((followed.audit_root(), followed.engine_root(), watch.follower.head()), (state.audit_root(), state.engine_root(), Some(read.wal_head)));
}

#[test]
fn a_journal_its_writer_holds_is_read_to_its_last_complete_frame_and_on() {
    let path = temp("held");
    let mut s = start(&path.0);
    let mut watch = Watch::new(&path.0);
    assert_eq!(watch.step().unwrap(), Tail { frames: 1, new: 1, writer: true, pending: 0, more: false });
    submit(&mut s, "a", &[json!({"kind": "observe", "local_id": "o1", "doc_id": "d", "exact_quote": "The first line names the rule.", "terms": ["t"]})]);
    s.seal().unwrap();
    assert_eq!(watch.step().unwrap(), Tail { frames: 3, new: 2, writer: true, pending: 0, more: false });
    assert_eq!(watch.follower.state().unwrap().audit_root(), s.audit_root());
    drop(s);
    assert_eq!(watch.step().unwrap(), Tail { frames: 3, new: 0, writer: false, pending: 0, more: false });
    assert_eq!(watch.export(), prov::export(&path.0).unwrap().text());
}

#[test]
fn a_frame_that_fails_its_checks_stops_the_follower_at_the_frames_before_it() {
    let (whole, damaged) = (temp("sound"), temp("damaged"));
    let bytes = journal(&whole.0);
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    // frame 4 with one byte of its body changed: its hashes no longer hold
    let mut bad = lines[4].to_vec();
    let at = bad.windows(7).position(|w| w == b"\"actor\"").unwrap() + 9;
    bad[at] = if bad[at] == b'x' { b'y' } else { b'x' };
    append(&damaged.0, &lines[..4].concat());
    let mut watch = Watch::new(&damaged.0);
    assert_eq!(watch.step().unwrap().frames, 4);
    append(&damaged.0, &bad);
    append(&damaged.0, &lines[5..].concat());
    for _ in 0..2 {
        match watch.step() {
            Err(Stop::Broken { frame, error }) => assert!(frame == 4 && error.message.contains("frame 4"), "{frame} {}", error.message),
            other => panic!("expected a broken frame, got {other:?}"),
        }
    }
    assert_eq!(watch.follower.frames(), 4);
    assert_eq!(watch.export(), prov::export_at(&whole.0, Some(4)).unwrap().text());
}

#[test]
fn a_frame_whose_outcome_the_replay_does_not_give_leaves_the_state_of_the_frames_before_it() {
    let (whole, forged) = (temp("true"), temp("forged"));
    let bytes = journal(&whole.0);
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    // frame 3 (the claim) with another outcome and every hash made again: the chain holds, the replay does not give the outcome
    let mut frame: Value = serde_json::from_slice(lines[3]).unwrap();
    frame["body"]["outcome"]["result"]["forged"] = json!(true);
    let previous = from_hex(frame["header"]["previous"].as_str().unwrap()).unwrap();
    let root = from_hex(frame["header"]["records_root"].as_str().unwrap()).unwrap();
    let header = header_v3(3, &previous, &body_hash(&frame["body"]), &root);
    frame["hash"] = json!(to_hex(&header_hash(&header)));
    frame["header"] = header;
    append(&forged.0, &lines[..3].concat());
    append(&forged.0, format!("{}\n", to_jcs(&frame)).as_bytes());
    let mut watch = Watch::new(&forged.0);
    match watch.step() {
        Err(Stop::Broken { frame: 3, error }) => assert!(error.message.contains("diverged"), "{}", error.message),
        other => panic!("expected a broken frame 3, got {other:?}"),
    }
    // the state is the one of the first three frames, made again from the file, not one that holds a part of the forged frame
    let mut roots = Vec::new();
    AuditState::verify(&whole.0, &mut |n, audit_root, _, _| roots.push((n, audit_root))).unwrap();
    assert_eq!(watch.follower.frames(), 3);
    assert_eq!(Some(watch.follower.state().unwrap().audit_root()), roots.iter().find(|(n, _)| *n == 3).map(|(_, r)| *r));
    assert_eq!(watch.export(), prov::export_at(&whole.0, Some(3)).unwrap().text());
}

#[test]
fn a_step_its_caller_ends_is_taken_up_by_the_next_one() {
    let path = temp("stepped");
    let bytes = journal(&path.0);
    let frames = bytes.iter().filter(|b| **b == b'\n').count();
    let mut follower = Follower::new(&path.0);
    let mut tracker = Tracker::new();
    // two frames a step
    let mut steps = 0;
    loop {
        let mut taken = 0;
        let tail = follower
            .advance(&mut |f| {
                tracker.frame(f.state, f.payload, f.head);
                taken += 1;
                taken < 2
            })
            .unwrap();
        steps += 1;
        assert_eq!((tail.new, tail.frames), (taken, (steps * 2).min(frames)));
        assert_eq!(tracker.document(follower.state().unwrap(), false).unwrap().text(), prov::export_at(&path.0, Some(tail.frames)).unwrap().text());
        if !tail.more {
            break;
        }
        assert_eq!(tail.pending, 0);
    }
    assert_eq!((follower.frames(), steps), (frames, frames.div_ceil(2)));
}

#[test]
fn bytes_longer_than_any_frame_with_no_end_stop_the_follower_instead_of_being_asked_for_again() {
    let path = temp("endless");
    let bytes = journal(&path.0);
    let frames = bytes.iter().filter(|b| **b == b'\n').count();
    let mut watch = Watch::new(&path.0);
    assert_eq!(watch.step().unwrap().frames, frames);
    // after the frames: more bytes than the longest frame a journal holds and no newline, and more of the file behind them
    {
        let mut file = std::fs::OpenOptions::new().append(true).open(&path.0).unwrap();
        let block = vec![b'0'; 1024 * 1024];
        for _ in 0..(persistence::MAX_FRAME_BYTES / block.len() + 9) {
            file.write_all(&block).unwrap();
        }
    }
    // every step says so, at once: none answers that there is more to read
    for _ in 0..3 {
        match watch.step() {
            Err(Stop::Broken { frame, error }) => assert!(frame == frames && error.message.contains("unterminated"), "{frame} {}", error.message),
            other => panic!("expected a broken journal, got {other:?}"),
        }
    }
    // the frames before those bytes stand as read
    assert_eq!((watch.follower.frames(), watch.tracker.frames()), (frames, frames));
    assert!(watch.follower.state().is_some());
}

#[test]
fn a_follower_that_stopped_reads_no_more_than_the_end_of_the_last_frame_at_a_later_step() {
    let (whole, damaged) = (temp("stopped_sound"), temp("stopped"));
    let bytes = journal(&whole.0);
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let mut bad = lines[4].to_vec();
    let at = bad.windows(7).position(|w| w == b"\"actor\"").unwrap() + 9;
    bad[at] = if bad[at] == b'x' { b'y' } else { b'x' };
    append(&damaged.0, &lines[..4].concat());
    append(&damaged.0, &bad);
    let mut watch = Watch::new(&damaged.0);
    assert!(matches!(watch.step(), Err(Stop::Broken { frame: 4, .. })));
    // megabytes after the frame that failed, with no end of a frame and with frames: a later step asks for none of them
    append(&damaged.0, &vec![b'0'; 9 * 1024 * 1024]);
    append(&damaged.0, &lines[5..].concat());
    let before = watch.follower.read_bytes;
    for _ in 0..5 {
        assert!(matches!(watch.step(), Err(Stop::Broken { frame: 4, .. })));
    }
    assert!(watch.follower.read_bytes - before <= 5 * MARK_BYTES as u64, "{} bytes read by five steps", watch.follower.read_bytes - before);
    // and it still tells a file that became another one
    std::fs::write(&damaged.0, &bytes[..lines[0].len() + lines[1].len()]).unwrap();
    assert!(matches!(watch.step(), Err(Stop::Replaced(_))));
}

#[test]
fn a_follower_that_stopped_before_any_frame_tells_a_file_that_became_another_one() {
    let (whole, path) = (temp("start_whole"), temp("start"));
    let bytes = journal(&whole.0);
    // a file whose first line is no frame of a journal
    append(&path.0, b"{\"not\":\"a frame\"}\n");
    let mut watch = Watch::new(&path.0);
    assert!(matches!(watch.step(), Err(Stop::Broken { frame: 0, .. })));
    // what is written after that line changes nothing, and a later step reads the first bytes only
    append(&path.0, &vec![b'0'; 3 * 1024 * 1024]);
    let before = watch.follower.read_bytes;
    for _ in 0..5 {
        assert!(matches!(watch.step(), Err(Stop::Broken { frame: 0, .. })));
    }
    assert!(watch.follower.read_bytes - before <= 5 * MARK_BYTES as u64, "{} bytes read by five steps", watch.follower.read_bytes - before);
    assert!(watch.follower.state().is_none());
    // a journal put at that path is another file: a new follower reads it from its start
    std::fs::write(&path.0, &bytes).unwrap();
    assert!(matches!(watch.step(), Err(Stop::Replaced(_))));
    let mut again = Watch::new(&path.0);
    again.step().unwrap();
    assert_eq!(again.export(), prov::export(&whole.0).unwrap().text());
    // the same of a file shorter than the bytes kept, and of one that is empty
    let (short, empty) = (temp("start_short"), temp("start_empty"));
    for (file, now) in [(&short, &b"{}"[..]), (&empty, &b""[..])] {
        append(&file.0, b"{\"not\":\"a frame\"}\n");
        let mut watch = Watch::new(&file.0);
        assert!(matches!(watch.step(), Err(Stop::Broken { frame: 0, .. })));
        std::fs::write(&file.0, now).unwrap();
        assert!(matches!(watch.step(), Err(Stop::Replaced(_))));
    }
}

#[test]
fn a_frame_in_flight_is_read_once_however_many_steps_wait_for_its_end() {
    let (whole, growing) = (temp("flight_whole"), temp("flight"));
    // a journal whose second frame is longer than a megabyte: a document put with that much text
    let long = "A line of a long document that says nothing of the rule.\n".repeat(24_000);
    {
        let mut s = start(&whole.0);
        s.put_document("owner", "d", long.as_bytes()).unwrap();
        s.put_document("owner", "d", DOC).unwrap();
        s.seal().unwrap();
    }
    let bytes = std::fs::read(&whole.0).unwrap();
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let (first, frame) = (lines[0].len(), lines[1].len());
    assert!(frame > 1024 * 1024);
    append(&growing.0, lines[0]);
    let mut watch = Watch::new(&growing.0);
    assert_eq!(watch.step().unwrap().frames, 1);
    // a megabyte of the frame is written, and its writer stays silent
    let part = 1024 * 1024;
    append(&growing.0, &lines[1][..part]);
    assert_eq!(watch.step().unwrap(), Tail { frames: 1, new: 0, writer: false, pending: part as u64, more: false });
    let before = watch.follower.read_bytes;
    for _ in 0..5 {
        assert_eq!(watch.step().unwrap(), Tail { frames: 1, new: 0, writer: false, pending: part as u64, more: false });
    }
    let idle = watch.follower.read_bytes - before;
    assert!(idle <= 5 * 2 * MARK_BYTES as u64, "{idle} bytes read by five steps that found nothing new");
    // more of the frame: only what was written since is read
    let more = 100_000;
    append(&growing.0, &lines[1][part..part + more]);
    let before = watch.follower.read_bytes;
    assert_eq!(watch.step().unwrap().pending, (part + more) as u64);
    assert!(watch.follower.read_bytes - before <= (more + 2 * MARK_BYTES) as u64);
    // the end of the frame and the frames after it: the frame is read whole, and the journal is the one read whole
    append(&growing.0, &bytes[first + part + more..]);
    assert_eq!(watch.step().unwrap(), Tail { frames: lines.len(), new: lines.len() - 1, writer: false, pending: 0, more: false });
    assert_eq!(watch.export(), prov::export(&whole.0).unwrap().text());
}

#[test]
fn bytes_in_flight_that_became_others_are_read_from_the_frame_again() {
    let (whole, path) = (temp("torn_whole"), temp("torn"));
    let bytes = journal(&whole.0);
    let lines: Vec<&[u8]> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let read: usize = lines[..3].iter().map(|l| l.len()).sum();
    // three frames and a torn tail as long as the frames that will stand in its place
    append(&path.0, &bytes[..read]);
    append(&path.0, &vec![b'x'; bytes.len() - read]);
    let mut watch = Watch::new(&path.0);
    assert_eq!(watch.step().unwrap(), Tail { frames: 3, new: 3, writer: false, pending: (bytes.len() - read) as u64, more: false });
    // the tail is cut and the journal goes on: a file of the same length, whose frames end where the torn bytes ended
    std::fs::write(&path.0, &bytes).unwrap();
    assert_eq!(watch.step().unwrap(), Tail { frames: lines.len(), new: lines.len() - 3, writer: false, pending: 0, more: false });
    assert_eq!(watch.export(), prov::export(&whole.0).unwrap().text());
    // a tail that became shorter is read again too
    append(&path.0, b"torn tail");
    assert_eq!(watch.step().unwrap().pending, 9);
    std::fs::write(&path.0, &bytes).unwrap();
    assert_eq!(watch.step().unwrap(), Tail { frames: lines.len(), new: 0, writer: false, pending: 0, more: false });
}

#[test]
fn a_step_that_finds_nothing_new_reads_only_the_end_of_the_last_frame() {
    let path = temp("mark");
    let bytes = journal(&path.0);
    let mut watch = Watch::new(&path.0);
    let frames = watch.step().unwrap().frames;
    // the end of the last frame is what a step reads again: a byte changed there is another file
    let mut near = bytes.clone();
    let n = near.len();
    near[n - 20] ^= 1;
    std::fs::write(&path.0, &near).unwrap();
    assert!(matches!(watch.step(), Err(Stop::Replaced(_))));
    std::fs::write(&path.0, &bytes).unwrap();
    assert_eq!(watch.step().unwrap(), Tail { frames, new: 0, writer: false, pending: 0, more: false });
}

#[test]
fn a_file_that_became_another_journal_ends_the_follower() {
    let (first, path) = (temp("first"), temp("replaced"));
    let bytes = journal(&first.0);
    append(&path.0, &bytes);
    let mut watch = Watch::new(&path.0);
    assert_eq!(watch.step().unwrap().new, bytes.iter().filter(|b| **b == b'\n').count());
    // a shorter file
    std::fs::write(&path.0, &bytes[..bytes.len() / 2]).unwrap();
    assert!(matches!(watch.step(), Err(Stop::Replaced(_))));
    // a file as long, whose last frame is another
    let mut other = bytes.clone();
    let n = other.len();
    other[n - 20] ^= 1;
    std::fs::write(&path.0, &other).unwrap();
    assert!(matches!(watch.step(), Err(Stop::Replaced(_))));
    // a new follower reads the file that is there now from its start
    std::fs::write(&path.0, &bytes).unwrap();
    let mut again = Watch::new(&path.0);
    again.step().unwrap();
    assert_eq!(again.export(), prov::export(&first.0).unwrap().text());
}
