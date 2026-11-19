//! A reader that follows a journal while it grows (`sbgk audit-watch`): the journal is replayed from its genesis once, and after
//! that only the frames written since are read. Every frame gets the checks `audit-verify` gives it, in the same order: the
//! chain (`persistence::FrameChain`), then the semantic replay to the outcome and the roots the frame committed
//! (`AuditState::replay_genesis`, `replay_frame`). The journal is opened for reading only, never locked and never written; it
//! is read up to its last complete frame, as every reading tool reads a journal a server holds.
//!
//! The follower keeps the state after the last frame it read, the hashes of the frames, and the place in the file where the next
//! frame begins. It keeps no payload: `advance` hands each new frame to its caller once, with the state after it. A step reads a
//! bounded part of the file, and its caller can end it after any frame, so a long journal is caught up with in steps.

use super::persistence::{self, FrameChain, FrameFormat};
use super::state::AuditState;
use crate::error::{Code, KernelError};
use crate::hash::{sha256, Hash};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A frame the follower has just read: its number (the genesis is 0), the state after it, its payload and its hash.
pub struct Frame<'a> {
    pub number: usize,
    pub state: &'a AuditState,
    pub payload: &'a Value,
    pub head: Hash,
}

/// What a step along the journal found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tail {
    /// The frames read so far, the genesis included.
    pub frames: usize,
    /// How many of them this step read.
    pub new: usize,
    /// A writer held the journal at this step.
    pub writer: bool,
    /// The bytes after the last complete frame: a frame in flight while a writer holds the journal, a torn tail when none does.
    /// 0 while `more` is set.
    pub pending: u64,
    /// The step ended before the end of the file: the next step reads on at once.
    pub more: bool,
}

/// The bytes a step reads at once, when a frame is no longer than that.
const STEP_BYTES: u64 = 8 * 1024 * 1024;
/// How many bytes of the end of the frame read last a step reads again: enough to tell another file, little enough for a
/// step that finds nothing new to cost the same whatever the size of the last frame.
const MARK_BYTES: usize = 4096;

/// Why a step along the journal stopped.
#[derive(Debug)]
pub enum Stop {
    /// The file could not be read at this moment (it is not there yet, or a server of 0.2.0 or earlier locks it whole on
    /// Windows). Nothing was lost: a later step reads on.
    Unreadable(Box<KernelError>),
    /// The file is no longer the journal that was followed: it is shorter than the frames read, or the frame read last is not
    /// where it was. The follower is done; a new one reads the file from its start.
    Replaced(String),
    /// Frame `frame` does not pass the checks of the journal. The frames before it stand as read, and the follower reads no
    /// further: every later step says the same, until the file is another journal.
    Broken { frame: usize, error: Box<KernelError> },
}

/// See the module.
pub struct Follower {
    path: PathBuf,
    chain: FrameChain,
    heads: Vec<Hash>,
    state: Option<AuditState>,
    /// The bytes of the complete frames read.
    offset: u64,
    /// The end of the frame read last, its newline included: how many of its last bytes are kept in mind (at most `MARK_BYTES`)
    /// and their SHA-256. Each step reads them again: a file whose bytes there are others is no longer the journal followed.
    last: Option<(u64, Hash)>,
    /// The bytes after the last complete frame that a step read and found no end of a frame in: how many they are, and the mark
    /// of their end (as `last` is the mark of a frame). The next step reads on from there, not from the frame again.
    tail: Option<(u64, u64, Hash)>,
    broken: Option<(usize, KernelError)>,
    /// The first bytes of the file (at most `MARK_BYTES`), kept when the follower stopped before it read any frame: there is no
    /// end of a frame to read again then, and these bytes tell a file that became another one.
    start: Option<(u64, Hash)>,
    /// The bytes read from the file so far.
    #[cfg(test)]
    read_bytes: u64,
}

fn error(message: impl Into<String>) -> KernelError {
    KernelError::new(Code::BadField, message).field("audit_wal")
}

impl Follower {
    /// A follower of the journal at `path`, which may not exist yet. Nothing is read until the first `advance`.
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            chain: FrameChain::new(),
            heads: Vec::new(),
            state: None,
            offset: 0,
            last: None,
            tail: None,
            broken: None,
            start: None,
            #[cfg(test)]
            read_bytes: 0,
        }
    }

    /// The frames read so far, the genesis included.
    pub fn frames(&self) -> usize {
        self.heads.len()
    }

    /// The hash of the frame read last.
    pub fn head(&self) -> Option<Hash> {
        self.heads.last().copied()
    }

    /// The state after the frame read last; `None` before the genesis is read.
    pub fn state(&self) -> Option<&AuditState> {
        self.state.as_ref()
    }

    /// One step along the journal: reads bytes written since the last step, and checks and applies the complete frames among
    /// them, handing each to `visit` in the journal's order with the state after it. `visit` says whether to go on: after a
    /// `false` the step ends with that frame, and the next step takes the frames after it.
    pub fn advance(&mut self, visit: &mut dyn FnMut(&Frame) -> bool) -> Result<Tail, Stop> {
        let back = self.last.map_or(0, |(n, _)| n);
        let longest = persistence::MAX_FRAME_BYTES as u64 + 1;
        let mut limit = STEP_BYTES.min(longest);
        // a follower that stopped, or one that waits for the end of a frame in flight, reads the frames' end again and no more
        if self.broken.is_some() || self.tail.is_some() {
            if back > 0 {
                let read = self.read(self.offset - back, back)?;
                self.same(read.as_ref().map_or(&[][..], |r| r.bytes.as_slice()), read.is_some())?;
            } else if let Some((n, hash)) = self.start {
                let read = self.read(0, n)?;
                if !read.is_some_and(|r| r.bytes.len() as u64 == n && sha256(&r.bytes) == hash) {
                    return Err(Stop::Replaced("the first bytes of the file are no longer what they were".to_string()));
                }
            }
            if let Some((frame, error)) = &self.broken {
                return Err(Stop::Broken { frame: *frame, error: Box::new(error.clone()) });
            }
        }
        // the bytes after the last frame that held no end of a frame: a step reads on after them. Their own end is read again:
        // bytes that are no longer there, or are others, are read from the frame again, as bytes never seen
        if let Some((scanned, kept, mark)) = self.tail.take() {
            let read = self.read(self.offset + scanned - kept, kept + STEP_BYTES)?;
            if let Some(read) = read.filter(|r| r.bytes.len() as u64 >= kept && sha256(&r.bytes[..kept as usize]) == mark) {
                let new = &read.bytes[kept as usize..];
                if new.contains(&b'\n') {
                    // a frame ended: it is read whole, once
                    limit = (scanned + STEP_BYTES).min(longest);
                } else {
                    let pending = scanned + new.len() as u64;
                    if pending > persistence::MAX_FRAME_BYTES as u64 {
                        return Err(self.unterminated());
                    }
                    self.tail = Some(Self::mark(pending, &read.bytes));
                    if read.rest > 0 {
                        return Ok(Tail { frames: self.frames(), new: 0, writer: read.held, pending: 0, more: true });
                    }
                    let writer = read.held || persistence::writer_present(&self.path);
                    return Ok(Tail { frames: self.frames(), new: 0, writer, pending, more: false });
                }
            }
        }
        // a part of the file that holds the end of the frame read last and, after it, at least one whole frame when the file has
        // one. A part with no whole frame is read again larger, up to one byte more than the longest frame a journal holds: bytes
        // beyond that with no end of a frame are no frame, however many follow
        let (bytes, writer, rest) = loop {
            let Some(read) = self.read(self.offset - back, back + limit)? else {
                return Err(Stop::Replaced("the file is shorter than the frames already read".to_string()));
            };
            let whole = read.bytes.get(back as usize..).is_some_and(|fresh| fresh.contains(&b'\n'));
            if whole || read.rest == 0 || limit >= longest {
                break (read.bytes, read.held, read.rest);
            }
            limit = (limit * 8).min(longest);
        };
        let (known, fresh) = bytes.split_at((back as usize).min(bytes.len()));
        self.same(known, true)?;
        let complete = fresh.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        // more bytes than the longest frame and no end of a frame among them: the journal goes no further, whatever follows
        // (before the question of what is left to read: a step that asked for more here would ask for ever)
        if complete == 0 && fresh.len() > persistence::MAX_FRAME_BYTES {
            return Err(self.unterminated());
        }
        let before = self.frames();
        let mut at = 0;
        let mut go_on = true;
        while at < complete && go_on {
            let end = at + fresh[at..complete].iter().position(|b| *b == b'\n').expect("a complete frame ends in a newline");
            match self.apply(&fresh[at..end], visit) {
                Ok(more) => go_on = more,
                Err(error) => {
                    self.restore();
                    return Err(self.stop(error));
                }
            }
            self.offset += (end + 1 - at) as u64;
            let mark = &fresh[(end + 1).saturating_sub(MARK_BYTES).max(at)..=end];
            self.last = Some((mark.len() as u64, sha256(mark)));
            at = end + 1;
        }
        if at < complete || rest > 0 {
            return Ok(Tail { frames: self.frames(), new: self.frames() - before, writer, pending: 0, more: true });
        }
        let pending = (fresh.len() - complete) as u64;
        if pending > persistence::MAX_FRAME_BYTES as u64 {
            return Err(self.unterminated());
        }
        if pending > 0 {
            self.tail = Some(Self::mark(pending, &fresh[complete..]));
        }
        // bytes after the last complete frame are a frame in flight only while a writer holds the journal: one that took the
        // journal after the first question is asked for again, as `AuditJournal::read` asks
        let writer = writer || (pending > 0 && persistence::writer_present(&self.path));
        Ok(Tail { frames: self.frames(), new: self.frames() - before, writer, pending, more: false })
    }

    /// A part of the file from `from`, at most `limit` bytes; `None` when the file ends before `from`.
    fn read(&mut self, from: u64, limit: u64) -> Result<Option<persistence::TailRead>, Stop> {
        let read = persistence::read_tail(&self.path, from, limit).map_err(|e| Stop::Unreadable(Box::new(e)))?;
        #[cfg(test)]
        {
            self.read_bytes += read.as_ref().map_or(0, |r| r.bytes.len() as u64);
        }
        Ok(read)
    }

    /// Whether the bytes read where the frame read last ended are that frame's end.
    fn same(&self, known: &[u8], there: bool) -> Result<(), Stop> {
        if !there {
            return Err(Stop::Replaced("the file is shorter than the frames already read".to_string()));
        }
        if self.last.is_some_and(|(n, hash)| known.len() as u64 != n || sha256(known) != hash) {
            return Err(Stop::Replaced("the frame read last is no longer where it was".to_string()));
        }
        Ok(())
    }

    /// The mark of `pending` bytes with no end of a frame, of which `bytes` are the last ones read.
    fn mark(pending: u64, bytes: &[u8]) -> (u64, u64, Hash) {
        let kept = &bytes[bytes.len() - (MARK_BYTES as u64).min(pending).min(bytes.len() as u64) as usize..];
        (pending, kept.len() as u64, sha256(kept))
    }

    /// The stop at bytes longer than the longest frame with no end of a frame.
    fn unterminated(&mut self) -> Stop {
        self.stop(error("audit WAL unterminated frame exceeds 64 MiB"))
    }

    /// The follower stops at the frame after the ones it read, for `error`. One that read no frame keeps a mark of the file's
    /// first bytes, to read them again at each later step.
    fn stop(&mut self, error: KernelError) -> Stop {
        let frame = self.frames();
        if self.last.is_none() {
            self.start = self.read(0, MARK_BYTES as u64).ok().flatten().map(|r| (r.bytes.len() as u64, sha256(&r.bytes)));
        }
        self.broken = Some((frame, error.clone()));
        Stop::Broken { frame, error: Box::new(error) }
    }

    /// The checks of one frame and its step of the replay; what `visit` said of going on.
    fn apply(&mut self, line: &[u8], visit: &mut dyn FnMut(&Frame) -> bool) -> Result<bool, KernelError> {
        let (payload, head, records_root) = self.chain.frame(line)?;
        let v3 = self.chain.format == Some(FrameFormat::V3);
        let number = self.heads.len();
        match &mut self.state {
            None => self.state = Some(AuditState::replay_genesis(&payload, v3, records_root.as_ref())?),
            Some(state) => state.replay_frame(number, &payload, &self.heads, records_root.as_ref(), v3)?,
        }
        self.heads.push(head);
        Ok(visit(&Frame { number, state: self.state.as_ref().expect("a state after its frame"), payload: &payload, head }))
    }

    /// After a frame failed its checks: the state may hold a part of that frame, so the state after the frames that passed is
    /// made again from the file, by one replay of those frames. A file that no longer gives them leaves no state.
    fn restore(&mut self) {
        let (frames, offset) = (self.heads.len(), self.offset as usize);
        self.state = None;
        self.chain = FrameChain::new();
        let Ok(Some(read)) = self.read(0, self.offset) else { return };
        let bytes = read.bytes;
        if bytes.len() < offset {
            return;
        }
        let mut heads: Vec<Hash> = Vec::with_capacity(frames);
        let mut state: Option<AuditState> = None;
        for line in bytes[..offset].split(|b| *b == b'\n').take(frames) {
            let Ok((payload, head, records_root)) = self.chain.frame(line) else { return };
            let v3 = self.chain.format == Some(FrameFormat::V3);
            let step = match &mut state {
                None => AuditState::replay_genesis(&payload, v3, records_root.as_ref()).map(|s| state = Some(s)),
                Some(s) => s.replay_frame(heads.len(), &payload, &heads, records_root.as_ref(), v3),
            };
            if step.is_err() {
                return;
            }
            heads.push(head);
        }
        if heads == self.heads {
            self.state = state;
        }
    }
}

#[cfg(test)]
#[path = "follow_tests.rs"]
mod tests;
