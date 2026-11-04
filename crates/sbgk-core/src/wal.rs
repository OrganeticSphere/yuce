//! Append-only, hash-chained write-ahead log.
//!
//! Frame: `[u32 frame_len][u8 op][u64 seq][payload][h chain_hash]` where `frame_len` counts
//! the whole frame (including the length field and the trailing chain hash) and
//! `chain_hash = SHA256(prev_chain_hash || frame_bytes_without_chain_hash)`.
//!
//! The log is self-contained for structural replay: no source documents or ontology are
//! needed to reconstruct support under the current engine semantics, including ordered
//! anchor windows. It stores chunk hashes, not bytes: source-backed span bounds and quote
//! integrity additionally require the arena checks in `verify_container`.

use crate::codec::*;
use crate::engine::{CanonOp, Engine};
use crate::hash::{sha256, sha256_parts, Hash};
use crate::node::*;

pub const OP_GENESIS: u8 = 0;
pub const OP_BIND: u8 = 1;
pub const OP_ASSERT: u8 = 2;
pub const OP_DERIVE: u8 = 3;
pub const OP_REVOKE: u8 = 4;
pub const OP_DOCPUT: u8 = 5;

pub const FRAME_OVERHEAD: usize = 4 + 1 + 8 + 32;

/// Set on BIND / ASSERT frames the kernel emitted on its own (automatic re-binding after a document
/// update). Such frames repeat the current agent `seq`; agent frames advance it by exactly one.
pub const KERNEL_FLAG: u8 = 0x80;

pub fn chain_origin() -> Hash {
    sha256(b"SBGK-WAL-v1")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalError {
    /// The slice ends inside a frame; `valid_prefix` bytes form complete frames.
    Truncated {
        valid_prefix: usize,
    },
    BadLength {
        at: usize,
    },
    BadChain {
        frame: usize,
        at: usize,
    },
    BadOp {
        frame: usize,
        op: u8,
    },
    BadPayload {
        frame: usize,
        reason: String,
    },
    SeqRegression {
        frame: usize,
    },
    Engine {
        frame: usize,
        reason: String,
    },
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WalError {}

pub fn op_code(op: &CanonOp) -> u8 {
    match op {
        CanonOp::Genesis { .. } => OP_GENESIS,
        CanonOp::BindEvidence { .. } => OP_BIND,
        CanonOp::Assert { .. } => OP_ASSERT,
        CanonOp::Derive { .. } => OP_DERIVE,
        CanonOp::Revoke { .. } => OP_REVOKE,
        CanonOp::DocPut { .. } => OP_DOCPUT,
    }
}

pub fn encode_payload(op: &CanonOp) -> Vec<u8> {
    let mut out = Vec::new();
    match op {
        CanonOp::Genesis { ontology_hash, cdc } => {
            out.extend_from_slice(ontology_hash);
            put_u32(&mut out, cdc.0);
            put_u32(&mut out, cdc.1);
            put_u32(&mut out, cdc.2);
            put_u32(&mut out, cdc.3);
        }
        CanonOp::BindEvidence { doc_version, ev } => {
            out.extend_from_slice(doc_version);
            out.extend_from_slice(&ev.encode());
        }
        CanonOp::Assert { claim, evidence } => {
            out.extend_from_slice(&claim.encode());
            put_u16(&mut out, evidence.len() as u16);
            for e in evidence {
                out.extend_from_slice(e);
            }
        }
        CanonOp::Derive { claim, justs } => {
            out.extend_from_slice(&claim.encode());
            put_u16(&mut out, justs.len() as u16);
            for (rule, premises) in justs {
                put_str(&mut out, rule);
                put_u16(&mut out, premises.len() as u16);
                for p in premises {
                    out.extend_from_slice(p);
                }
            }
        }
        CanonOp::Revoke { evidence } => out.extend_from_slice(evidence),
        CanonOp::DocPut { doc_id, version, chunks } => {
            put_str(&mut out, doc_id);
            out.extend_from_slice(version);
            put_u32(&mut out, chunks.len() as u32);
            for c in chunks {
                out.extend_from_slice(c);
            }
        }
    }
    out
}

fn read_claim(rd: &mut Rd) -> Result<Claim, CodecError> {
    if rd.u8()? != KIND_CLAIM {
        return Err(CodecError("expected claim"));
    }
    Claim::decode_body(rd)
}

pub fn decode_payload(op: u8, payload: &[u8]) -> Result<CanonOp, CodecError> {
    let mut rd = Rd::new(payload);
    let out = match op {
        OP_GENESIS => {
            let ontology_hash = rd.hash()?;
            let cdc = (rd.u32()?, rd.u32()?, rd.u32()?, rd.u32()?);
            CanonOp::Genesis { ontology_hash, cdc }
        }
        OP_BIND => {
            let doc_version = rd.hash()?;
            if rd.u8()? != KIND_EVIDENCE {
                return Err(CodecError("expected evidence"));
            }
            let ev = EvidenceNode::decode_body(&mut rd)?;
            CanonOp::BindEvidence { doc_version, ev }
        }
        OP_ASSERT => {
            let claim = read_claim(&mut rd)?;
            let n = rd.u16()? as usize;
            let mut evidence = Vec::with_capacity(n);
            for _ in 0..n {
                evidence.push(rd.hash()?);
            }
            if evidence.is_empty() || evidence.windows(2).any(|w| w[0] >= w[1]) {
                return Err(CodecError("non-canonical evidence list"));
            }
            CanonOp::Assert { claim, evidence }
        }
        OP_DERIVE => {
            let claim = read_claim(&mut rd)?;
            let nj = rd.u16()? as usize;
            let mut justs = Vec::with_capacity(nj);
            for _ in 0..nj {
                let rule = rd.str()?;
                let np = rd.u16()? as usize;
                let mut ps = Vec::with_capacity(np);
                for _ in 0..np {
                    ps.push(rd.hash()?);
                }
                if ps.is_empty() || ps.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(CodecError("non-canonical premise list"));
                }
                justs.push((rule, ps));
            }
            if justs.is_empty() || justs.windows(2).any(|w| w[0] >= w[1]) {
                return Err(CodecError("non-canonical justification list"));
            }
            CanonOp::Derive { claim, justs }
        }
        OP_REVOKE => CanonOp::Revoke { evidence: rd.hash()? },
        OP_DOCPUT => {
            let doc_id = rd.str()?;
            let version = rd.hash()?;
            let n = rd.u32()? as usize;
            if n > rd.remaining() / 32 {
                return Err(CodecError("chunk count exceeds payload"));
            }
            let mut chunks = Vec::with_capacity(n);
            for _ in 0..n {
                chunks.push(rd.hash()?);
            }
            if crate::arena::version_id_of(&chunks) != version {
                return Err(CodecError("document version does not match its chunk list"));
            }
            CanonOp::DocPut { doc_id, version, chunks }
        }
        _ => return Err(CodecError("unknown op code")),
    };
    rd.expect_end()?;
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct Wal {
    pub bytes: Vec<u8>,
    pub chain: Hash,
    pub frame_ends: Vec<usize>,
    pub last_seq: u64,
}

impl Default for Wal {
    fn default() -> Self {
        Wal::new()
    }
}

impl Wal {
    pub fn new() -> Wal {
        Wal { bytes: Vec::new(), chain: chain_origin(), frame_ends: Vec::new(), last_seq: 0 }
    }

    /// Append one frame; returns the byte offset just after it. `kernel` marks kernel-generated
    /// BIND / ASSERT frames (re-binding); it must be false for every other frame.
    pub fn append(&mut self, seq: u64, op: &CanonOp, kernel: bool) -> usize {
        let payload = encode_payload(op);
        let total = FRAME_OVERHEAD + payload.len();
        let start = self.bytes.len();
        put_u32(&mut self.bytes, total as u32);
        self.bytes.push(op_code(op) | if kernel { KERNEL_FLAG } else { 0 });
        put_u64(&mut self.bytes, seq);
        self.bytes.extend_from_slice(&payload);
        let chain = sha256_parts(&[&self.chain, &self.bytes[start..]]);
        self.bytes.extend_from_slice(&chain);
        self.chain = chain;
        self.last_seq = seq;
        self.frame_ends.push(self.bytes.len());
        self.bytes.len()
    }
}

#[derive(Debug, Clone)]
pub struct FrameView<'a> {
    pub op: u8,
    pub seq: u64,
    pub payload: &'a [u8],
    pub chain: Hash,
    pub start: usize,
    pub end: usize,
}

/// Parse frame boundaries only (no chain verification).
pub fn parse_frames(wal: &[u8]) -> Result<Vec<FrameView<'_>>, WalError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < wal.len() {
        if wal.len() - pos < 4 {
            return Err(WalError::Truncated { valid_prefix: pos });
        }
        let len = u32::from_le_bytes(wal[pos..pos + 4].try_into().unwrap()) as usize;
        if len < FRAME_OVERHEAD {
            return Err(WalError::BadLength { at: pos });
        }
        if wal.len() - pos < len {
            return Err(WalError::Truncated { valid_prefix: pos });
        }
        let f = &wal[pos..pos + len];
        out.push(FrameView {
            op: f[4],
            seq: u64::from_le_bytes(f[5..13].try_into().unwrap()),
            payload: &f[13..len - 32],
            chain: f[len - 32..].try_into().unwrap(),
            start: pos,
            end: pos + len,
        });
        pos += len;
    }
    Ok(out)
}

/// Validate the operation byte and the sequence discipline of one frame; returns the next
/// `agent_seq`.
fn check_frame_discipline(i: usize, raw_op: u8, seq: u64, agent_seq: u64) -> Result<u64, WalError> {
    let base = raw_op & !KERNEL_FLAG;
    let flagged = raw_op & KERNEL_FLAG != 0;
    if base > OP_DOCPUT || (flagged && !matches!(base, OP_BIND | OP_ASSERT)) {
        return Err(WalError::BadOp { frame: i, op: raw_op });
    }
    let kernel = flagged || matches!(base, OP_GENESIS | OP_DOCPUT);
    if kernel {
        if seq != agent_seq {
            return Err(WalError::SeqRegression { frame: i });
        }
        Ok(agent_seq)
    } else {
        if seq != agent_seq + 1 {
            return Err(WalError::SeqRegression { frame: i });
        }
        Ok(seq)
    }
}

/// Verify the hash chain of a complete-frame byte slice. Returns the head chain hash.
pub fn verify_chain(wal: &[u8]) -> Result<(Hash, usize), WalError> {
    let frames = parse_frames(wal)?;
    let mut prev = chain_origin();
    let mut agent_seq = 0u64;
    for (i, f) in frames.iter().enumerate() {
        let want = sha256_parts(&[&prev, &wal[f.start..f.end - 32]]);
        if want != f.chain {
            return Err(WalError::BadChain { frame: i, at: f.start });
        }
        agent_seq = check_frame_discipline(i, f.op, f.seq, agent_seq)?;
        prev = f.chain;
    }
    Ok((prev, frames.len()))
}

#[derive(Debug)]
pub struct Reconstructed {
    pub engine: Engine,
    pub last_seq: u64,
    pub frames: usize,
    pub chain_head: Hash,
}

/// Rebuild a WAL byte prefix under the current engine semantics. Every frame's chain hash
/// is verified; anchor chunk order is checked to determine evidence status. Span bounds /
/// quote bytes need the source arena.
/// A prefix that ends mid-frame is reported as `Truncated`.
pub fn reconstruct_at_byte_offset(wal_prefix: &[u8]) -> Result<Reconstructed, WalError> {
    let frames = parse_frames(wal_prefix)?;
    let mut engine = Engine::new();
    let mut prev = chain_origin();
    let mut agent_seq = 0u64;
    for (i, f) in frames.iter().enumerate() {
        let want = sha256_parts(&[&prev, &wal_prefix[f.start..f.end - 32]]);
        if want != f.chain {
            return Err(WalError::BadChain { frame: i, at: f.start });
        }
        agent_seq = check_frame_discipline(i, f.op, f.seq, agent_seq)?;
        if i == 0 && f.op != OP_GENESIS || i > 0 && f.op == OP_GENESIS {
            return Err(WalError::BadOp { frame: i, op: f.op });
        }
        let op = decode_payload(f.op & !KERNEL_FLAG, f.payload).map_err(|e| WalError::BadPayload { frame: i, reason: e.0.to_string() })?;
        engine.apply(&op).map_err(|e| WalError::Engine { frame: i, reason: e.0 })?;
        prev = f.chain;
    }
    Ok(Reconstructed { engine, last_seq: agent_seq, frames: frames.len(), chain_head: prev })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Seg;

    fn sample_ops() -> Vec<CanonOp> {
        let ev = EvidenceNode { doc_id: "d".into(), quote_hash: [7; 32], quote_len: 3, segs: vec![Seg { chunk: [1; 32], start: 0, end: 3 }] };
        let claim = Claim { s: "a".into(), p: "p".into(), o: "x".into(), pol: Polarity::Pos, ctx: "c".into(), t_from: 0, t_to: 5 };
        vec![
            CanonOp::Genesis { ontology_hash: [9; 32], cdc: (1, 512, 1024, 2048) },
            CanonOp::DocPut { doc_id: "d".into(), version: crate::arena::version_id_of(&[[1; 32]]), chunks: vec![[1; 32]] },
            CanonOp::BindEvidence { doc_version: crate::arena::version_id_of(&[[1; 32]]), ev: ev.clone() },
            CanonOp::Assert { claim: claim.clone(), evidence: vec![ev.id()] },
            CanonOp::Revoke { evidence: ev.id() },
        ]
    }

    #[test]
    fn payload_roundtrip() {
        for op in sample_ops() {
            let p = encode_payload(&op);
            let back = decode_payload(op_code(&op), &p).unwrap();
            assert_eq!(encode_payload(&back), p);
        }
    }

    #[test]
    fn prefix_reconstruction_and_tamper_detection() {
        let mut wal = Wal::new();
        for (i, op) in sample_ops().iter().enumerate() {
            wal.append(if i < 2 { 0 } else { i as u64 - 1 }, op, false);
        }
        let full = reconstruct_at_byte_offset(&wal.bytes).unwrap();
        assert_eq!(full.frames, 5);
        let mid = reconstruct_at_byte_offset(&wal.bytes[..wal.frame_ends[3]]).unwrap();
        assert_eq!(mid.frames, 4);
        assert!(matches!(reconstruct_at_byte_offset(&wal.bytes[..wal.frame_ends[3] - 1]), Err(WalError::Truncated { .. })));
        for byte in 0..wal.bytes.len() {
            let mut bad = wal.bytes.clone();
            bad[byte] ^= 0x10;
            assert!(reconstruct_at_byte_offset(&bad).is_err(), "undetected flip at byte {byte}");
        }
    }
}
