//! The `.sbgk` binary container.
//!
//! ```text
//! [Header 64 B] [Source Arena] [Merkle Node Table] [WAL] [Offset Index]
//!
//! Header   magic "SBGK\0\1" | u16 version | u32 arena_off | u32 node_table_off | u32 wal_off |
//!          u32 index_off | h state_merkle_root | u32 total_len | u32 reserved(=0)
//! Arena    u32 n | n × (h hash, u8 kind{0 chunk,1 ontology}, u32 off, u32 len) | data
//! Table    u32 n | 256 × h bucket_hash | n × record, records ordered by (rank, node_id)
//!          record = h id | u8 kind | u8 status | u32 rank | u32 payload_len | payload |
//!                   u16 adj_n | adj_n × h
//! WAL      hash-chained frames (see wal.rs)
//! Index    u32 n | 257 × u32 fanout | n × (h node_id, u32 rec_off)   sorted by node_id
//!          u32 m | m × (h sha256(entity), u32 start, u32 count) | u32 k | k × u32 rec_off
//! ```
//!
//! Every section is a pure function of the committed WAL, so `verify_container` rebuilds the
//! node table and the index from the log and compares them byte for byte.

use crate::arena::Arena;
use crate::cdc::CdcParams;
use crate::codec::*;
use crate::engine::{Engine, Record, Snapshot};
use crate::hash::{sha256, to_hex, Hash};
use crate::merkle::{root_from_buckets, BUCKETS};
use crate::node::*;
use crate::ontology::Ontology;
use crate::session::Session;
use crate::wal::*;
use std::collections::BTreeMap;

pub const MAGIC: [u8; 6] = *b"SBGK\x00\x01";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 64;
const ARENA_ENTRY: usize = 41;
const INDEX_ENTRY: usize = 36;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerError {
    pub kind: &'static str,
    pub detail: String,
}

impl ContainerError {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        ContainerError { kind, detail: detail.into() }
    }
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for ContainerError {}

impl From<CodecError> for ContainerError {
    fn from(e: CodecError) -> Self {
        ContainerError::new("malformed", e.0)
    }
}

type CResult<T> = Result<T, ContainerError>;

// ---------------------------------------------------------------------------- building

pub fn build_arena_section(arena: &Arena) -> Vec<u8> {
    let mut items: Vec<(Hash, u8, &[u8])> = Vec::new();
    for (h, b) in arena.all_chunks() {
        items.push((*h, 0, b.as_slice()));
    }
    for (h, b) in &arena.blobs {
        items.push((*h, 1, b.as_slice()));
    }
    items.sort_by_key(|a| a.0);
    let mut out = Vec::new();
    put_u32(&mut out, items.len() as u32);
    let mut off = 0u32;
    for (h, k, b) in &items {
        out.extend_from_slice(h);
        out.push(*k);
        put_u32(&mut out, off);
        put_u32(&mut out, b.len() as u32);
        off += b.len() as u32;
    }
    for (_, _, b) in &items {
        out.extend_from_slice(b);
    }
    out
}

fn write_record(out: &mut Vec<u8>, r: &Record) {
    out.extend_from_slice(&r.id);
    out.push(r.kind);
    out.push(r.status);
    put_u32(out, r.rank);
    put_u32(out, r.payload.len() as u32);
    out.extend_from_slice(&r.payload);
    put_u16(out, r.adj.len() as u16);
    for a in &r.adj {
        out.extend_from_slice(a);
    }
}

/// Build the node-table and the offset-index sections from a snapshot.
pub fn build_table_and_index(snap: &Snapshot) -> (Vec<u8>, Vec<u8>) {
    let mut table = Vec::new();
    put_u32(&mut table, snap.records.len() as u32);
    for b in &snap.bucket_hashes {
        table.extend_from_slice(b);
    }
    let mut offs: Vec<u32> = Vec::with_capacity(snap.records.len());
    for r in &snap.records {
        offs.push(table.len() as u32);
        write_record(&mut table, r);
    }

    let mut entries: Vec<(Hash, u32)> = snap.records.iter().zip(&offs).map(|(r, o)| (r.id, *o)).collect();
    entries.sort();
    let mut fanout = [0u32; 257];
    for (id, _) in &entries {
        fanout[id[0] as usize + 1] += 1;
    }
    for i in 0..256 {
        fanout[i + 1] += fanout[i];
    }

    let mut ent: BTreeMap<Hash, Vec<(Hash, u32)>> = BTreeMap::new();
    for (r, o) in snap.records.iter().zip(&offs) {
        if r.kind == KIND_CLAIM {
            if let Ok(c) = Claim::decode(&r.payload) {
                ent.entry(sha256(c.s.as_bytes())).or_default().push((r.id, *o));
                if c.o != c.s {
                    ent.entry(sha256(c.o.as_bytes())).or_default().push((r.id, *o));
                }
            }
        }
    }

    let mut index = Vec::new();
    put_u32(&mut index, entries.len() as u32);
    for f in &fanout {
        put_u32(&mut index, *f);
    }
    for (id, o) in &entries {
        index.extend_from_slice(id);
        put_u32(&mut index, *o);
    }
    put_u32(&mut index, ent.len() as u32);
    let mut flat: Vec<u32> = Vec::new();
    for (k, v) in ent.iter_mut() {
        v.sort();
        index.extend_from_slice(k);
        put_u32(&mut index, flat.len() as u32);
        put_u32(&mut index, v.len() as u32);
        flat.extend(v.iter().map(|x| x.1));
    }
    put_u32(&mut index, flat.len() as u32);
    for o in flat {
        put_u32(&mut index, o);
    }
    (table, index)
}

pub fn assemble(arena: &[u8], table: &[u8], wal: &[u8], index: &[u8], root: &Hash) -> Vec<u8> {
    let arena_off = HEADER_LEN;
    let table_off = arena_off + arena.len();
    let wal_off = table_off + table.len();
    let index_off = wal_off + wal.len();
    let total = index_off + index.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    put_u32(&mut out, arena_off as u32);
    put_u32(&mut out, table_off as u32);
    put_u32(&mut out, wal_off as u32);
    put_u32(&mut out, index_off as u32);
    out.extend_from_slice(root);
    put_u32(&mut out, total as u32);
    put_u32(&mut out, 0);
    debug_assert_eq!(out.len(), HEADER_LEN);
    out.extend_from_slice(arena);
    out.extend_from_slice(table);
    out.extend_from_slice(wal);
    out.extend_from_slice(index);
    out
}

pub fn build_container(s: &mut Session) -> Vec<u8> {
    let snap = s.engine.snapshot();
    let arena = build_arena_section(&s.arena);
    let (table, index) = build_table_and_index(&snap);
    assemble(&arena, &table, &s.wal.bytes, &index, &snap.root)
}

// ---------------------------------------------------------------------------- reading

#[derive(Debug, Clone, Copy)]
pub struct NodeRec<'a> {
    pub id: Hash,
    pub kind: u8,
    pub status: u8,
    pub rank: u32,
    pub payload: &'a [u8],
    pub adj: &'a [u8],
}

impl<'a> NodeRec<'a> {
    pub fn adj_ids(&self) -> impl Iterator<Item = Hash> + 'a {
        self.adj.as_chunks::<32>().0.iter().copied()
    }
}

/// Zero-copy view over a container buffer. Construction checks the header only; each accessor
/// bounds-checks what it touches.
#[derive(Clone, Copy)]
pub struct ContainerView<'a> {
    pub buf: &'a [u8],
    pub arena: &'a [u8],
    pub table: &'a [u8],
    pub wal: &'a [u8],
    pub index: &'a [u8],
    pub root: Hash,
}

impl<'a> ContainerView<'a> {
    pub fn parse(buf: &'a [u8]) -> CResult<Self> {
        if buf.len() < HEADER_LEN {
            return Err(ContainerError::new("truncated", "shorter than header"));
        }
        if buf[..6] != MAGIC {
            return Err(ContainerError::new("bad_magic", "not an SBGK container"));
        }
        let mut rd = Rd::new(&buf[6..HEADER_LEN]);
        let ver = rd.u16()?;
        if ver != FORMAT_VERSION {
            return Err(ContainerError::new("bad_version", format!("version {ver}")));
        }
        let a = rd.u32()? as usize;
        let t = rd.u32()? as usize;
        let w = rd.u32()? as usize;
        let i = rd.u32()? as usize;
        let root = rd.hash()?;
        let total = rd.u32()? as usize;
        let reserved = rd.u32()?;
        if reserved != 0 {
            return Err(ContainerError::new("reserved_nonzero", "reserved header bytes must be zero"));
        }
        if total != buf.len() {
            return Err(ContainerError::new("length_mismatch", format!("header says {total} bytes, buffer has {}", buf.len())));
        }
        if !(a == HEADER_LEN && a <= t && t <= w && w <= i && i <= total) {
            return Err(ContainerError::new("bad_offsets", "section offsets are not monotonic"));
        }
        Ok(ContainerView { buf, arena: &buf[a..t], table: &buf[t..w], wal: &buf[w..i], index: &buf[i..total], root })
    }

    pub fn node_count(&self) -> usize {
        self.table.get(..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    }

    pub fn bucket_hash(&self, b: usize) -> Option<Hash> {
        let s = 4 + b * 32;
        self.table.get(s..s + 32).map(|x| x.try_into().unwrap())
    }

    pub fn bucket_hashes(&self) -> Option<Vec<Hash>> {
        (0..BUCKETS).map(|b| self.bucket_hash(b)).collect()
    }

    fn index_n(&self) -> usize {
        self.index.get(..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    }

    fn fanout(&self, i: usize) -> Option<usize> {
        let s = 4 + i * 4;
        self.index.get(s..s + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    }

    fn index_base(&self) -> usize {
        4 + 257 * 4
    }

    fn index_entry(&self, i: usize) -> Option<(Hash, u32)> {
        let s = self.index_base() + i * INDEX_ENTRY;
        let e = self.index.get(s..s + INDEX_ENTRY)?;
        Some((e[..32].try_into().unwrap(), u32::from_le_bytes(e[32..36].try_into().unwrap())))
    }

    /// Entries of bucket `b` (all node ids whose first byte is `b`), in id order.
    pub fn bucket_entries(&self, b: usize) -> Vec<(Hash, u32)> {
        let (lo, hi) = match (self.fanout(b), self.fanout(b + 1)) {
            (Some(l), Some(h)) if l <= h && h <= self.index_n() => (l, h),
            _ => return Vec::new(),
        };
        (lo..hi).filter_map(|i| self.index_entry(i)).collect()
    }

    pub fn record_at(&self, off: u32) -> CResult<NodeRec<'a>> {
        let off = off as usize;
        if off < 4 + BUCKETS * 32 || off >= self.table.len() {
            return Err(ContainerError::new("bad_record_offset", format!("{off}")));
        }
        let mut rd = Rd { buf: self.table, pos: off };
        let id = rd.hash()?;
        let kind = rd.u8()?;
        let status = rd.u8()?;
        let rank = rd.u32()?;
        let plen = rd.u32()? as usize;
        let payload = rd.take(plen)?;
        let an = rd.u16()? as usize;
        let adj = rd.take(an * 32)?;
        Ok(NodeRec { id, kind, status, rank, payload, adj })
    }

    /// O(log N) lookup by node id directly in the byte index.
    pub fn find_node(&self, id: &Hash) -> Option<NodeRec<'a>> {
        let (mut lo, mut hi) = (self.fanout(id[0] as usize)?, self.fanout(id[0] as usize + 1)?);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (mid_id, off) = self.index_entry(mid)?;
            match mid_id.cmp(id) {
                std::cmp::Ordering::Equal => return self.record_at(off).ok(),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    fn entity_base(&self) -> usize {
        self.index_base() + self.index_n() * INDEX_ENTRY
    }

    /// Record offsets of every claim whose subject or object equals `entity` (exact string).
    pub fn entity_records(&self, entity: &str) -> Vec<u32> {
        let key = sha256(entity.as_bytes());
        let base = self.entity_base();
        let m = match self.index.get(base..base + 4) {
            Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
            None => return Vec::new(),
        };
        let ent = |i: usize| -> Option<(Hash, usize, usize)> {
            let s = base + 4 + i * 40;
            let e = self.index.get(s..s + 40)?;
            Some((
                e[..32].try_into().unwrap(),
                u32::from_le_bytes(e[32..36].try_into().unwrap()) as usize,
                u32::from_le_bytes(e[36..40].try_into().unwrap()) as usize,
            ))
        };
        let (mut lo, mut hi) = (0, m);
        let flat_base = base + 4 + m * 40 + 4;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (k, start, count) = match ent(mid) {
                Some(x) => x,
                None => return Vec::new(),
            };
            match k.cmp(&key) {
                std::cmp::Ordering::Equal => {
                    return (0..count)
                        .filter_map(|j| {
                            let s = flat_base + (start + j) * 4;
                            self.index.get(s..s + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                        })
                        .collect()
                }
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Vec::new()
    }

    fn arena_n(&self) -> usize {
        self.arena.get(..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    }

    fn arena_entry(&self, i: usize) -> Option<(Hash, u8, usize, usize)> {
        let s = 4 + i * ARENA_ENTRY;
        let e = self.arena.get(s..s + ARENA_ENTRY)?;
        Some((
            e[..32].try_into().unwrap(),
            e[32],
            u32::from_le_bytes(e[33..37].try_into().unwrap()) as usize,
            u32::from_le_bytes(e[37..41].try_into().unwrap()) as usize,
        ))
    }

    /// Content-addressed lookup of a chunk / blob in the arena section.
    pub fn arena_find(&self, hash: &Hash) -> Option<&'a [u8]> {
        let n = self.arena_n();
        let data_base = 4 + n * ARENA_ENTRY;
        let (mut lo, mut hi) = (0, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (h, _, off, len) = self.arena_entry(mid)?;
            match h.cmp(hash) {
                std::cmp::Ordering::Equal => return self.arena.get(data_base + off..data_base + off + len),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Sequential walk over all table records.
    pub fn records(&self) -> CResult<Vec<NodeRec<'a>>> {
        let n = self.node_count();
        let mut out = Vec::with_capacity(n);
        let mut pos = 4 + BUCKETS * 32;
        for _ in 0..n {
            let r = self.record_at(pos as u32)?;
            pos += 32 + 1 + 1 + 4 + 4 + r.payload.len() + 2 + r.adj.len();
            out.push(r);
        }
        Ok(out)
    }

    /// Reassemble the quote an evidence node points at, straight from arena bytes.
    pub fn quote_of(&self, ev: &EvidenceNode) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(ev.quote_len as usize);
        for s in &ev.segs {
            let c = self.arena_find(&s.chunk)?;
            out.extend_from_slice(c.get(s.start as usize..s.end as usize)?);
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------- merkle diff

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffKind {
    OnlyInA,
    OnlyInB,
    StatusChanged { a: u8, b: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    pub id: Hash,
    pub kind: u8,
    pub change: DiffKind,
}

#[derive(Debug, Clone)]
pub struct MerkleDiff {
    pub root_a: Hash,
    pub root_b: Hash,
    pub buckets_differing: usize,
    pub leaves_scanned: usize,
    pub entries: Vec<DiffEntry>,
}

/// Locate the exact diverging nodes of two containers. Only buckets whose 32-byte hashes
/// differ are opened; equal buckets (and everything under them) are never touched.
pub fn merkle_diff(bytes_a: &[u8], bytes_b: &[u8]) -> CResult<MerkleDiff> {
    let a = ContainerView::parse(bytes_a)?;
    let b = ContainerView::parse(bytes_b)?;
    let mut out = MerkleDiff { root_a: a.root, root_b: b.root, buckets_differing: 0, leaves_scanned: 0, entries: Vec::new() };
    if a.root == b.root {
        return Ok(out);
    }
    for bk in 0..BUCKETS {
        let (ha, hb) = (a.bucket_hash(bk), b.bucket_hash(bk));
        if ha.is_none() || hb.is_none() {
            return Err(ContainerError::new("truncated", "node table bucket hashes"));
        }
        if ha == hb {
            continue;
        }
        out.buckets_differing += 1;
        let ea = a.bucket_entries(bk);
        let eb = b.bucket_entries(bk);
        out.leaves_scanned += ea.len() + eb.len();
        let (mut i, mut j) = (0, 0);
        let status_kind = |v: &ContainerView, off: u32| -> CResult<(u8, u8)> {
            let r = v.record_at(off)?;
            Ok((r.kind, r.status))
        };
        while i < ea.len() || j < eb.len() {
            let ord = match (ea.get(i), eb.get(j)) {
                (Some(x), Some(y)) => x.0.cmp(&y.0),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => break,
            };
            match ord {
                std::cmp::Ordering::Less => {
                    let (k, _) = status_kind(&a, ea[i].1)?;
                    out.entries.push(DiffEntry { id: ea[i].0, kind: k, change: DiffKind::OnlyInA });
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    let (k, _) = status_kind(&b, eb[j].1)?;
                    out.entries.push(DiffEntry { id: eb[j].0, kind: k, change: DiffKind::OnlyInB });
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let (k, sa) = status_kind(&a, ea[i].1)?;
                    let (_, sb) = status_kind(&b, eb[j].1)?;
                    if sa != sb {
                        out.entries.push(DiffEntry { id: ea[i].0, kind: k, change: DiffKind::StatusChanged { a: sa, b: sb } });
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------- verification

#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub nodes: usize,
    pub frames: usize,
    pub chunks: usize,
    pub anchors_checked: usize,
}

fn parse_arena_entries(sec: &[u8]) -> CResult<Vec<(Hash, u8, &[u8])>> {
    let mut rd = Rd::new(sec);
    let n = rd.u32()? as usize;
    if n > sec.len() / ARENA_ENTRY {
        return Err(ContainerError::new("arena_malformed", "entry count exceeds section"));
    }
    let mut metas = Vec::with_capacity(n);
    for _ in 0..n {
        let h = rd.hash()?;
        let k = rd.u8()?;
        let off = rd.u32()? as usize;
        let len = rd.u32()? as usize;
        metas.push((h, k, off, len));
    }
    let data = &sec[rd.pos..];
    let mut out = Vec::with_capacity(n);
    let mut expect_off = 0usize;
    for (i, (h, k, off, len)) in metas.into_iter().enumerate() {
        if i > 0 && out.last().map(|x: &(Hash, u8, &[u8])| x.0 >= h).unwrap_or(false) {
            return Err(ContainerError::new("arena_unsorted", "arena entries must be strictly sorted by hash"));
        }
        if off != expect_off || off + len > data.len() {
            return Err(ContainerError::new("arena_layout", "arena data is not contiguous"));
        }
        expect_off += len;
        out.push((h, k, &data[off..off + len]));
    }
    if expect_off != data.len() {
        return Err(ContainerError::new("arena_layout", "unaccounted bytes in arena"));
    }
    Ok(out)
}

/// Full verification: structure, arena hashes, WAL chain, byte-exact rebuild of the node table
/// and index from the log, header root, and every evidence anchor against the arena bytes.
pub fn verify_container(buf: &[u8]) -> CResult<VerifyReport> {
    let v = ContainerView::parse(buf)?;
    let entries = parse_arena_entries(v.arena)?;
    let mut onto_blobs = 0;
    for (h, k, data) in &entries {
        if *k > 1 {
            return Err(ContainerError::new("arena_kind", "unknown arena entry kind"));
        }
        if *k == 1 {
            onto_blobs += 1;
        }
        if sha256(data) != *h {
            return Err(ContainerError::new("arena_hash_mismatch", format!("blob {} does not match its address", to_hex(&h[..8]))));
        }
    }
    if onto_blobs != 1 {
        return Err(ContainerError::new("arena_kind", "exactly one ontology blob is required"));
    }

    let rec = reconstruct_at_byte_offset(v.wal).map_err(|e| ContainerError::new("wal", format!("{e}")))?;
    let mut engine = rec.engine;
    let (onto_hash, _) = engine.genesis.ok_or_else(|| ContainerError::new("wal", "missing genesis frame"))?;
    if !entries.iter().any(|(h, k, _)| *k == 1 && *h == onto_hash) {
        return Err(ContainerError::new("ontology_missing", "ontology blob does not match genesis hash"));
    }

    let snap = engine.snapshot();
    let (table, index) = build_table_and_index(&snap);
    if v.table != table.as_slice() {
        return Err(ContainerError::new("node_table_mismatch", "node table differs from a rebuild from the WAL"));
    }
    if v.index != index.as_slice() {
        return Err(ContainerError::new("index_mismatch", "offset index differs from a rebuild from the WAL"));
    }
    if v.root != snap.root || root_from_buckets(&snap.bucket_hashes, &engine.genesis_meta()) != v.root {
        return Err(ContainerError::new("root_mismatch", "header state_merkle_root does not match the node table"));
    }

    // Anchors: every evidence node must still be backed by byte-identical arena data.
    let mut anchors = 0;
    for r in v.records()? {
        if r.kind == KIND_EVIDENCE {
            let ev = EvidenceNode::decode(r.payload)?;
            if !ev.has_valid_spans(|h| v.arena_find(h).map(|c| c.len())) {
                return Err(ContainerError::new("anchor_broken", "evidence spans do not form a continuous byte range"));
            }
            for s in &ev.segs {
                match v.arena_find(&s.chunk) {
                    Some(c) if sha256(c) == s.chunk => {}
                    _ => return Err(ContainerError::new("anchor_broken", format!("chunk {} missing or altered", to_hex(&s.chunk[..8])))),
                }
            }
            match v.quote_of(&ev) {
                Some(q) if q.len() == ev.quote_len as usize && sha256(&q) == ev.quote_hash => anchors += 1,
                _ => return Err(ContainerError::new("anchor_broken", "quote hash mismatch")),
            }
        }
    }
    // Every chunk a DocPut frame references must exist, and the declared chunking parameters
    // must reproduce exactly the committed chunk list.
    let params =
        CdcParams::from_tuple(engine.genesis.map(|g| g.1).unwrap_or((9, 0, 0, 0))).ok_or_else(|| ContainerError::new("genesis", "unknown chunking mode"))?;
    for f in parse_frames(v.wal).map_err(|e| ContainerError::new("wal", format!("{e}")))? {
        if f.op == OP_DOCPUT {
            if let Ok(crate::engine::CanonOp::DocPut { chunks, .. }) = decode_payload(f.op, f.payload) {
                let mut doc: Vec<u8> = Vec::new();
                for c in &chunks {
                    match v.arena_find(c) {
                        Some(b) => doc.extend_from_slice(b),
                        None => return Err(ContainerError::new("chunk_missing", format!("chunk {} referenced by log is absent", to_hex(&c[..8])))),
                    }
                }
                let again: Vec<Hash> = crate::cdc::chunk_ranges(&doc, &params).iter().map(|&(s, e)| sha256(&doc[s..e])).collect();
                if again != chunks {
                    return Err(ContainerError::new("chunking_mismatch", "committed chunk list is not what the declared chunker produces"));
                }
            }
        }
    }
    Ok(VerifyReport { nodes: snap.records.len(), frames: rec.frames, chunks: entries.len() - 1, anchors_checked: anchors })
}

// ---------------------------------------------------------------------------- reopen

/// Verify a container and resume a live session from it (local names are gone by design).
pub fn open_session(buf: &[u8]) -> CResult<Session> {
    verify_container(buf)?;
    let v = ContainerView::parse(buf)?;
    let entries = parse_arena_entries(v.arena)?;
    let rec = reconstruct_at_byte_offset(v.wal).map_err(|e| ContainerError::new("wal", format!("{e}")))?;
    let (onto_hash, cdc) = rec.engine.genesis.expect("verified");
    let onto_bytes = entries.iter().find(|(h, k, _)| *k == 1 && *h == onto_hash).map(|e| e.2).expect("verified");
    let ontology = Ontology::from_json_str(std::str::from_utf8(onto_bytes).map_err(|_| ContainerError::new("ontology", "not utf-8"))?)
        .map_err(|e| ContainerError::new("ontology", e.0))?;
    let params = CdcParams::from_tuple(cdc).ok_or_else(|| ContainerError::new("genesis", "unknown chunking mode"))?;
    let mut arena = Arena::new(params);
    for (h, k, data) in &entries {
        if *k == 0 {
            arena.insert_chunk_verified(*h, data);
        } else {
            arena.blobs.insert(*h, data.to_vec());
        }
    }
    let frames = parse_frames(v.wal).map_err(|e| ContainerError::new("wal", format!("{e}")))?;
    let mut latest: BTreeMap<String, Vec<Hash>> = BTreeMap::new();
    for f in &frames {
        if f.op == OP_DOCPUT {
            if let Ok(crate::engine::CanonOp::DocPut { doc_id, chunks, .. }) = decode_payload(f.op, f.payload) {
                latest.insert(doc_id, chunks);
            }
        }
    }
    for (d, chunks) in latest {
        if !arena.load_doc(&d, &chunks) {
            return Err(ContainerError::new("chunk_missing", "document chunk absent from arena"));
        }
    }
    let wal = Wal { bytes: v.wal.to_vec(), chain: rec.chain_head, frame_ends: frames.iter().map(|f| f.end).collect(), last_seq: rec.last_seq };
    Ok(Session::from_parts(ontology, arena, rec.engine, wal))
}

fn abs_offset(buf: &[u8], inner: &[u8]) -> usize {
    inner.as_ptr() as usize - buf.as_ptr() as usize
}

/// Absolute byte ranges of the five parts: header, arena, table, wal, index.
pub fn section_ranges(buf: &[u8]) -> CResult<[(&'static str, usize, usize); 5]> {
    let v = ContainerView::parse(buf)?;
    let (a, t, w, i) = (abs_offset(buf, v.arena), abs_offset(buf, v.table), abs_offset(buf, v.wal), abs_offset(buf, v.index));
    Ok([("header", 0, HEADER_LEN), ("arena", a, t), ("table", t, w), ("wal", w, i), ("index", i, buf.len())])
}

/// Absolute `(start, end)` byte range of every WAL frame.
pub fn wal_frame_ranges(buf: &[u8]) -> CResult<Vec<(usize, usize)>> {
    let v = ContainerView::parse(buf)?;
    let base = abs_offset(buf, v.wal);
    Ok(parse_frames(v.wal).map_err(|e| ContainerError::new("wal", format!("{e}")))?.iter().map(|f| (base + f.start, base + f.end)).collect())
}

/// `(hash, kind, absolute_start, len)` of every arena entry's data.
pub fn arena_layout(buf: &[u8]) -> CResult<Vec<(Hash, u8, usize, usize)>> {
    let v = ContainerView::parse(buf)?;
    Ok(parse_arena_entries(v.arena)?.into_iter().map(|(h, k, d)| (h, k, abs_offset(buf, d), d.len())).collect())
}

/// Engine state at an arbitrary WAL byte offset of a container.
pub fn reconstruct_container_at(buf: &[u8], wal_offset: usize) -> CResult<Engine> {
    let v = ContainerView::parse(buf)?;
    if wal_offset > v.wal.len() {
        return Err(ContainerError::new("offset", "beyond end of WAL"));
    }
    reconstruct_at_byte_offset(&v.wal[..wal_offset]).map(|r| r.engine).map_err(|e| ContainerError::new("wal", format!("{e}")))
}
