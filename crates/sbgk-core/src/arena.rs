//! Source Arena: immutable content-addressed chunks of source documents plus exact-quote
//! binding into `ByteAnchor`s.

use crate::cdc::{chunk_ranges, CdcParams};
use crate::hash::{sha256, sha256_parts, Hash};
use crate::node::{EvidenceNode, Seg};
use std::collections::{BTreeMap, HashMap, HashSet};

/// One exact occurrence of a quote inside a document (global offsets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub start: usize,
    pub end: usize,
}

/// Public view of the byte anchor from the specification. `segs[0]` is the
/// `(chunk_hash, local_span)` pair; a quote that straddles a chunk boundary carries more
/// than one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteAnchor {
    pub doc_id: String,
    pub doc_version_id: Hash,
    pub quote_hash: Hash,
    pub segs: Vec<Seg>,
}

#[derive(Debug, Clone)]
pub struct DocEntry {
    pub version_id: Hash,
    pub chunk_hashes: Vec<Hash>,
    /// Global start offset of every chunk (same length as `chunk_hashes`).
    pub chunk_starts: Vec<usize>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PutResult {
    pub version_id: Hash,
    pub chunk_hashes: Vec<Hash>,
    pub chunks_total: usize,
    pub chunks_new: usize,
    pub chunks_reused_from_prev: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Arena {
    pub params: CdcParams,
    chunks: HashMap<Hash, Vec<u8>>,
    docs: BTreeMap<String, DocEntry>,
    pub blobs: BTreeMap<Hash, Vec<u8>>,
}

pub fn version_id_of(chunks: &[Hash]) -> Hash {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(chunks.len() + 1);
    parts.push(b"SBGK-DOCVER-v1");
    for c in chunks {
        parts.push(c);
    }
    sha256_parts(&parts)
}

impl Arena {
    pub fn new(params: CdcParams) -> Self {
        Arena { params, chunks: HashMap::new(), docs: BTreeMap::new(), blobs: BTreeMap::new() }
    }

    pub fn put_document(&mut self, doc_id: &str, bytes: &[u8]) -> PutResult {
        let prev: HashSet<Hash> = self.docs.get(doc_id).map(|d| d.chunk_hashes.iter().copied().collect()).unwrap_or_default();
        let ranges = chunk_ranges(bytes, &self.params);
        let mut hashes = Vec::with_capacity(ranges.len());
        let mut starts = Vec::with_capacity(ranges.len());
        let mut new = 0;
        let mut reused = 0;
        for &(s, e) in &ranges {
            let slice = &bytes[s..e];
            let h = sha256(slice);
            if let std::collections::hash_map::Entry::Vacant(v) = self.chunks.entry(h) {
                v.insert(slice.to_vec());
                new += 1;
            }
            if prev.contains(&h) {
                reused += 1;
            }
            hashes.push(h);
            starts.push(s);
        }
        let version_id = version_id_of(&hashes);
        let res = PutResult { version_id, chunk_hashes: hashes.clone(), chunks_total: hashes.len(), chunks_new: new, chunks_reused_from_prev: reused };
        self.docs.insert(doc_id.to_string(), DocEntry { version_id, chunk_hashes: hashes, chunk_starts: starts, bytes: bytes.to_vec() });
        res
    }

    /// Re-create a document entry from an ordered chunk list (used when opening a container).
    pub fn load_doc(&mut self, doc_id: &str, chunk_hashes: &[Hash]) -> bool {
        let mut bytes = Vec::new();
        let mut starts = Vec::with_capacity(chunk_hashes.len());
        for h in chunk_hashes {
            match self.chunks.get(h) {
                Some(c) => {
                    starts.push(bytes.len());
                    bytes.extend_from_slice(c);
                }
                None => return false,
            }
        }
        self.docs
            .insert(doc_id.to_string(), DocEntry { version_id: version_id_of(chunk_hashes), chunk_hashes: chunk_hashes.to_vec(), chunk_starts: starts, bytes });
        true
    }

    /// Insert an already-hashed chunk (used when loading a container). Rejects mismatches.
    pub fn insert_chunk_verified(&mut self, hash: Hash, bytes: &[u8]) -> bool {
        if sha256(bytes) != hash {
            return false;
        }
        self.chunks.entry(hash).or_insert_with(|| bytes.to_vec());
        true
    }

    pub fn doc(&self, doc_id: &str) -> Option<&DocEntry> {
        self.docs.get(doc_id)
    }

    pub fn doc_ids(&self) -> impl Iterator<Item = &String> {
        self.docs.keys()
    }

    pub fn chunk(&self, h: &Hash) -> Option<&[u8]> {
        self.chunks.get(h).map(|v| v.as_slice())
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn all_chunks(&self) -> impl Iterator<Item = (&Hash, &Vec<u8>)> {
        self.chunks.iter()
    }

    /// Every byte-exact occurrence of `quote` in the current version of `doc_id`.
    pub fn find_occurrences(&self, doc_id: &str, quote: &[u8]) -> Option<Vec<Occurrence>> {
        let d = self.docs.get(doc_id)?;
        Some(find_all(&d.bytes, quote))
    }

    /// Build the byte anchor of a global span in the current version of a document.
    pub fn anchor_for_span(&self, doc_id: &str, start: usize, end: usize) -> Option<ByteAnchor> {
        let d = self.docs.get(doc_id)?;
        if start >= end || end > d.bytes.len() {
            return None;
        }
        let mut segs = Vec::new();
        for (i, &cs) in d.chunk_starts.iter().enumerate() {
            let ce = d.chunk_starts.get(i + 1).copied().unwrap_or(d.bytes.len());
            if ce <= start {
                continue;
            }
            if cs >= end {
                break;
            }
            let s = start.max(cs) - cs;
            let e = end.min(ce) - cs;
            segs.push(Seg { chunk: d.chunk_hashes[i], start: s as u32, end: e as u32 });
        }
        Some(ByteAnchor { doc_id: doc_id.to_string(), doc_version_id: d.version_id, quote_hash: sha256(&d.bytes[start..end]), segs })
    }

    pub fn evidence_node(anchor: &ByteAnchor, quote_len: usize) -> EvidenceNode {
        EvidenceNode { doc_id: anchor.doc_id.clone(), quote_hash: anchor.quote_hash, quote_len: quote_len as u32, segs: anchor.segs.clone() }
    }

    /// Re-read the quote bytes an evidence node points at (works for historical chunks).
    pub fn quote_bytes(&self, ev: &EvidenceNode) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(ev.quote_len as usize);
        for s in &ev.segs {
            let c = self.chunks.get(&s.chunk)?;
            if s.start > s.end || s.end as usize > c.len() {
                return None;
            }
            out.extend_from_slice(&c[s.start as usize..s.end as usize]);
        }
        Some(out)
    }

    /// Verify historical evidence bytes and span continuity. Whether the same ordered
    /// chunk window exists in the current document is checked by the engine.
    pub fn verify_evidence(&self, ev: &EvidenceNode) -> bool {
        if !ev.has_valid_spans(|h| self.chunk(h).map(|c| c.len())) {
            return false;
        }
        for s in &ev.segs {
            match self.chunks.get(&s.chunk) {
                Some(c) if sha256(c) == s.chunk => {}
                _ => return false,
            }
        }
        match self.quote_bytes(ev) {
            Some(q) => q.len() == ev.quote_len as usize && sha256(&q) == ev.quote_hash,
            None => false,
        }
    }

    /// Re-hash every stored chunk. Returns the keys whose bytes no longer match.
    pub fn corrupted_chunks(&self) -> Vec<Hash> {
        let mut bad: Vec<Hash> = self.chunks.iter().filter(|(h, b)| sha256(b) != **h).map(|(h, _)| *h).collect();
        bad.sort();
        bad
    }
}

/// Naive but allocation-free exact search (first-byte scan + compare).
pub fn find_all(hay: &[u8], needle: &[u8]) -> Vec<Occurrence> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > hay.len() {
        return out;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        match hay[i..=last_start].iter().position(|&b| b == first) {
            None => break,
            Some(off) => {
                let p = i + off;
                if &hay[p..p + needle.len()] == needle {
                    out.push(Occurrence { start: p, end: p + needle.len() });
                }
                i = p + 1;
            }
        }
    }
    out
}

fn trigrams(s: &[u8]) -> HashSet<u32> {
    let mut set = HashSet::new();
    if s.len() < 3 {
        return set;
    }
    for w in s.windows(3) {
        set.insert((w[0].to_ascii_lowercase() as u32) << 16 | (w[1].to_ascii_lowercase() as u32) << 8 | w[2].to_ascii_lowercase() as u32);
    }
    set
}

/// Nearest document segments (sentences / lines) to a non-matching quote, by byte-trigram
/// Jaccard similarity. Used only to build repair candidates, never to accept anything.
pub fn nearest_segments(doc: &[u8], quote: &[u8], limit: usize) -> Vec<(f64, usize, usize)> {
    let q = trigrams(quote);
    if q.is_empty() {
        return Vec::new();
    }
    let mut cands: Vec<(f64, usize, usize)> = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < doc.len() {
        let b = doc[i];
        let boundary = b == b'\n' || (b == b'.' && doc.get(i + 1).is_none_or(|n| *n == b' ' || *n == b'\n'));
        if boundary {
            let mut e = i + 1;
            while start < e && doc[start].is_ascii_whitespace() {
                start += 1;
            }
            if e > start {
                let seg = &doc[start..e];
                let t = trigrams(seg);
                let inter = q.intersection(&t).count() as f64;
                let uni = (q.len() + t.len()) as f64 - inter;
                if uni > 0.0 && inter > 0.0 {
                    cands.push((inter / uni, start, e));
                }
            }
            e = i + 1;
            start = e;
        }
        i += 1;
    }
    if start < doc.len() {
        let seg = &doc[start..];
        let t = trigrams(seg);
        let inter = q.intersection(&t).count() as f64;
        let uni = (q.len() + t.len()) as f64 - inter;
        if uni > 0.0 && inter > 0.0 {
            cands.push((inter / uni, start, doc.len()));
        }
    }
    cands.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));
    cands.truncate(limit);
    cands
}

/// Shortest superstring of occurrence `occ` (extended by whole UTF-8 characters, left and
/// right alternately) that occurs exactly once in `doc`.
pub fn unique_extension(doc: &[u8], occ: &Occurrence, max_extra: usize) -> Option<(usize, usize)> {
    let text = std::str::from_utf8(doc).ok()?;
    let (mut s, mut e) = (occ.start, occ.end);
    let mut extra = 0;
    let mut left = true;
    loop {
        if find_all(doc, &doc[s..e]).len() == 1 {
            return Some((s, e));
        }
        if extra >= max_extra {
            return None;
        }
        let can_left = s > 0;
        let can_right = e < doc.len();
        if !can_left && !can_right {
            return None;
        }
        let go_left = (left && can_left) || !can_right;
        if go_left {
            let mut ns = s - 1;
            while !text.is_char_boundary(ns) {
                ns -= 1;
            }
            extra += s - ns;
            s = ns;
        } else {
            let mut ne = e + 1;
            while !text.is_char_boundary(ne) {
                ne += 1;
            }
            extra += ne - e;
            e = ne;
        }
        left = !left;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> Vec<u8> {
        let mut s = String::new();
        for i in 0..400 {
            s.push_str(&format!("Clause {i}: the service svc_{i} shall use interface v{} in production.\n", i % 5));
        }
        s.into_bytes()
    }

    #[test]
    fn anchors_roundtrip_and_straddle() {
        let mut a = Arena::new(CdcParams::default());
        let doc = sample_doc();
        a.put_document("d", &doc);
        let q = b"Clause 7: the service svc_7 shall use interface v2 in production.";
        let occ = a.find_occurrences("d", q).unwrap();
        assert_eq!(occ.len(), 1);
        let anchor = a.anchor_for_span("d", occ[0].start, occ[0].end).unwrap();
        let ev = Arena::evidence_node(&anchor, q.len());
        assert!(a.verify_evidence(&ev));
        assert_eq!(a.quote_bytes(&ev).unwrap(), q.to_vec());
        // every span in the doc must be anchorable, including the ones crossing boundaries
        for k in (0..doc.len() - 50).step_by(397) {
            let an = a.anchor_for_span("d", k, k + 50).unwrap();
            let e = Arena::evidence_node(&an, 50);
            assert!(a.verify_evidence(&e));
        }
    }

    #[test]
    fn prefix_edit_preserves_most_chunks() {
        let mut a = Arena::new(CdcParams::default());
        let doc = sample_doc();
        let r1 = a.put_document("d", &doc);
        let mut edited = b"New preamble paragraph inserted at the very start of the policy text.\n".to_vec();
        edited.extend_from_slice(&doc);
        let r2 = a.put_document("d", &edited);
        assert!(r2.chunks_reused_from_prev as f64 / r1.chunks_total as f64 >= 0.9);
    }

    #[test]
    fn corruption_is_detected() {
        let mut a = Arena::new(CdcParams::default());
        a.put_document("d", &sample_doc());
        assert!(a.corrupted_chunks().is_empty());
        let h = *a.chunks.keys().next().unwrap();
        a.chunks.get_mut(&h).unwrap()[3] ^= 0x01;
        assert_eq!(a.corrupted_chunks(), vec![h]);
    }

    #[test]
    fn unique_extension_resolves_ambiguity() {
        let doc = b"alpha beta. gamma beta. delta.".to_vec();
        let occ = find_all(&doc, b"beta");
        assert_eq!(occ.len(), 2);
        let (s, e) = unique_extension(&doc, &occ[0], 32).unwrap();
        assert_eq!(find_all(&doc, &doc[s..e]).len(), 1);
    }
}
