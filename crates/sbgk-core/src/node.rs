//! Canonical node bytes. A node id is `SHA256(canonical_bytes)`; agent-local names never
//! reach this layer.
//!
//! Node kinds (first canonical byte):
//!   1 Evidence    `[1][str doc_id][h quote_hash][u32 quote_len][u8 nseg]{[h chunk][u32 start][u32 end]}*`
//!   2 Claim       `[2][str s][str p][str o][u8 polarity][str ctx][i64 t_from][i64 t_to]`
//!   3 Assertion   `[3][h claim][h evidence]`
//!   4 Derivation  `[4][str rule][h claim][u16 n][h premise]*n`   (premises sorted ascending)

use crate::codec::*;
use crate::hash::{sha256, Hash};

pub const KIND_EVIDENCE: u8 = 1;
pub const KIND_CLAIM: u8 = 2;
pub const KIND_ASSERTION: u8 = 3;
pub const KIND_DERIVATION: u8 = 4;

// Claim statuses.
pub const ST_UNSUPPORTED: u8 = 0;
pub const ST_SUPPORTED: u8 = 1;
pub const ST_CONFLICTING: u8 = 2;
// Evidence statuses.
pub const EV_ACTIVE: u8 = 0;
pub const EV_REVOKED: u8 = 1;
pub const EV_STALE: u8 = 2;
// Justification statuses.
pub const J_INACTIVE: u8 = 0;
pub const J_ACTIVE: u8 = 1;

pub fn status_name(kind: u8, status: u8) -> &'static str {
    match (kind, status) {
        (KIND_CLAIM, ST_SUPPORTED) => "SUPPORTED",
        (KIND_CLAIM, ST_CONFLICTING) => "CONFLICTING_SOURCES",
        (KIND_CLAIM, _) => "UNSUPPORTED",
        (KIND_EVIDENCE, EV_ACTIVE) => "ACTIVE",
        (KIND_EVIDENCE, EV_REVOKED) => "REVOKED",
        (KIND_EVIDENCE, _) => "STALE",
        (_, J_ACTIVE) => "ACTIVE",
        _ => "INACTIVE",
    }
}

pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_EVIDENCE => "evidence",
        KIND_CLAIM => "claim",
        KIND_ASSERTION => "assertion",
        KIND_DERIVATION => "derivation",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Polarity {
    Pos = 0,
    Neg = 1,
}

impl Polarity {
    pub fn as_str(self) -> &'static str {
        match self {
            Polarity::Pos => "POS",
            Polarity::Neg => "NEG",
        }
    }

    pub fn parse(s: &str) -> Option<Polarity> {
        match s {
            "POS" => Some(Polarity::Pos),
            "NEG" => Some(Polarity::Neg),
            _ => None,
        }
    }

    pub fn flip(self) -> Polarity {
        match self {
            Polarity::Pos => Polarity::Neg,
            Polarity::Neg => Polarity::Pos,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Claim {
    pub s: String,
    pub p: String,
    pub o: String,
    pub pol: Polarity,
    pub ctx: String,
    pub t_from: i64,
    pub t_to: i64,
}

impl Claim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.s.len() + self.p.len() + self.o.len() + self.ctx.len());
        out.push(KIND_CLAIM);
        put_str(&mut out, &self.s);
        put_str(&mut out, &self.p);
        put_str(&mut out, &self.o);
        out.push(self.pol as u8);
        put_str(&mut out, &self.ctx);
        put_i64(&mut out, self.t_from);
        put_i64(&mut out, self.t_to);
        out
    }

    pub fn decode_body(rd: &mut Rd) -> Result<Claim, CodecError> {
        let s = rd.str()?;
        let p = rd.str()?;
        let o = rd.str()?;
        let pol = match rd.u8()? {
            0 => Polarity::Pos,
            1 => Polarity::Neg,
            _ => return Err(CodecError("bad polarity")),
        };
        let ctx = rd.str()?;
        let t_from = rd.i64()?;
        let t_to = rd.i64()?;
        Ok(Claim { s, p, o, pol, ctx, t_from, t_to })
    }

    pub fn decode(bytes: &[u8]) -> Result<Claim, CodecError> {
        let mut rd = Rd::new(bytes);
        if rd.u8()? != KIND_CLAIM {
            return Err(CodecError("not a claim"));
        }
        let c = Claim::decode_body(&mut rd)?;
        rd.expect_end()?;
        Ok(c)
    }

    pub fn id(&self) -> Hash {
        sha256(&self.encode())
    }

    /// Conflict group key: claims sharing it with opposite polarity and overlapping
    /// intervals are in conflict.
    pub fn group_key(&self) -> (String, String, String, String) {
        (self.s.clone(), self.p.clone(), self.o.clone(), self.ctx.clone())
    }

    pub fn overlaps(&self, other: &Claim) -> bool {
        self.t_from < other.t_to && other.t_from < self.t_to
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seg {
    pub chunk: Hash,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvidenceNode {
    pub doc_id: String,
    pub quote_hash: Hash,
    pub quote_len: u32,
    pub segs: Vec<Seg>,
}

/// Most chunk segments one evidence node can span: the node encoding stores the count in one byte.
pub const MAX_EVIDENCE_SEGMENTS: usize = 255;

impl EvidenceNode {
    fn has_valid_span_lengths(&self) -> bool {
        !self.segs.is_empty()
            && self.segs.len() <= MAX_EVIDENCE_SEGMENTS
            && self.segs.iter().all(|s| s.start < s.end)
            && self.segs.iter().skip(1).all(|s| s.start == 0)
            && self.segs.iter().map(|s| u64::from(s.end - s.start)).sum::<u64>() == u64::from(self.quote_len)
    }

    /// Source-free continuity check shared by live operations and WAL replay. Match a
    /// window, not a subsequence or a set: repeated chunks must have enough occurrences,
    /// and a later occurrence may start the only valid window. Actual chunk lengths and
    /// quote bytes are checked separately by the source arena / container verifier.
    pub(crate) fn has_contiguous_chunks(&self, chunks: &[Hash]) -> bool {
        self.has_valid_span_lengths()
            && self.segs.len() <= chunks.len()
            && chunks.windows(self.segs.len()).any(|window| window.iter().zip(&self.segs).all(|(h, s)| *h == s.chunk))
    }

    /// A multi-chunk range is a suffix, zero or more full chunks, and a prefix.
    /// Historical evidence may use old chunks, but its spans must still describe one
    /// continuous range in that ordered chunk sequence.
    pub(crate) fn has_valid_spans(&self, chunk_len: impl Fn(&Hash) -> Option<usize>) -> bool {
        self.has_valid_span_lengths()
            && self
                .segs
                .iter()
                .enumerate()
                .all(|(i, s)| chunk_len(&s.chunk).is_some_and(|len| s.end as usize <= len && (i + 1 == self.segs.len() || s.end as usize == len)))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.doc_id.len() + self.segs.len() * 40);
        out.push(KIND_EVIDENCE);
        put_str(&mut out, &self.doc_id);
        out.extend_from_slice(&self.quote_hash);
        put_u32(&mut out, self.quote_len);
        debug_assert!(self.segs.len() <= MAX_EVIDENCE_SEGMENTS, "evidence spans {} segments", self.segs.len());
        out.push(self.segs.len() as u8);
        for s in &self.segs {
            out.extend_from_slice(&s.chunk);
            put_u32(&mut out, s.start);
            put_u32(&mut out, s.end);
        }
        out
    }

    pub fn decode_body(rd: &mut Rd) -> Result<EvidenceNode, CodecError> {
        let doc_id = rd.str()?;
        let quote_hash = rd.hash()?;
        let quote_len = rd.u32()?;
        let n = rd.u8()? as usize;
        let mut segs = Vec::with_capacity(n);
        for _ in 0..n {
            let chunk = rd.hash()?;
            let start = rd.u32()?;
            let end = rd.u32()?;
            segs.push(Seg { chunk, start, end });
        }
        Ok(EvidenceNode { doc_id, quote_hash, quote_len, segs })
    }

    pub fn decode(bytes: &[u8]) -> Result<EvidenceNode, CodecError> {
        let mut rd = Rd::new(bytes);
        if rd.u8()? != KIND_EVIDENCE {
            return Err(CodecError("not an evidence node"));
        }
        let e = EvidenceNode::decode_body(&mut rd)?;
        rd.expect_end()?;
        Ok(e)
    }

    pub fn id(&self) -> Hash {
        sha256(&self.encode())
    }
}

pub fn encode_assertion(claim: &Hash, evidence: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(KIND_ASSERTION);
    out.extend_from_slice(claim);
    out.extend_from_slice(evidence);
    out
}

pub fn encode_derivation(rule: &str, claim: &Hash, premises: &[Hash]) -> Vec<u8> {
    let mut sorted: Vec<Hash> = premises.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut out = Vec::with_capacity(40 + rule.len() + sorted.len() * 32);
    out.push(KIND_DERIVATION);
    put_str(&mut out, rule);
    out.extend_from_slice(claim);
    put_u16(&mut out, sorted.len() as u16);
    for p in &sorted {
        out.extend_from_slice(p);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Justification {
    Assertion { claim: Hash, evidence: Hash },
    Derivation { rule: String, claim: Hash, premises: Vec<Hash> },
}

impl Justification {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Justification::Assertion { claim, evidence } => encode_assertion(claim, evidence),
            Justification::Derivation { rule, claim, premises } => encode_derivation(rule, claim, premises),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Justification, CodecError> {
        let mut rd = Rd::new(bytes);
        match rd.u8()? {
            KIND_ASSERTION => {
                let claim = rd.hash()?;
                let evidence = rd.hash()?;
                rd.expect_end()?;
                Ok(Justification::Assertion { claim, evidence })
            }
            KIND_DERIVATION => {
                let rule = rd.str()?;
                let claim = rd.hash()?;
                let n = rd.u16()? as usize;
                let mut premises = Vec::with_capacity(n);
                for _ in 0..n {
                    premises.push(rd.hash()?);
                }
                rd.expect_end()?;
                Ok(Justification::Derivation { rule, claim, premises })
            }
            _ => Err(CodecError("not a justification")),
        }
    }

    pub fn id(&self) -> Hash {
        sha256(&self.encode())
    }

    pub fn claim(&self) -> &Hash {
        match self {
            Justification::Assertion { claim, .. } | Justification::Derivation { claim, .. } => claim,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_roundtrip_and_id_stable() {
        let c = Claim { s: "svc_auth".into(), p: "uses_api".into(), o: "v1".into(), pol: Polarity::Pos, ctx: "prod".into(), t_from: 100, t_to: 200 };
        let b = c.encode();
        assert_eq!(Claim::decode(&b).unwrap(), c);
        assert_eq!(c.id(), sha256(&b));
    }

    #[test]
    fn derivation_premises_are_canonically_sorted() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [9u8; 32];
        assert_eq!(encode_derivation("R@1", &c, &[a, b]), encode_derivation("R@1", &c, &[b, a]));
    }
}
