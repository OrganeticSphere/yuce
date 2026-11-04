//! Bucketed Merkle commitment over `(node_id, status)` leaves.
//!
//! Leaves are partitioned by the first byte of `node_id` into 256 buckets, so the tree shape
//! depends only on the *set* of nodes, never on insertion order. A bucket hash covers its
//! leaves sorted by id; the root covers the 256 bucket hashes. Two states are compared by
//! first comparing 256 bucket hashes and only then walking the differing buckets.

use crate::hash::{sha256, Hash, ZERO_HASH};
use std::hash::{BuildHasherDefault, Hasher};

pub const BUCKETS: usize = 256;

/// Hash of one bucket: `SHA256(0x01 || (id || status)*)` over leaves sorted by id.
/// An empty bucket is the all-zero hash.
pub fn bucket_hash(sorted_leaves: &[(Hash, u8)]) -> Hash {
    if sorted_leaves.is_empty() {
        return ZERO_HASH;
    }
    let mut buf = Vec::with_capacity(1 + sorted_leaves.len() * 33);
    buf.push(0x01);
    for (id, st) in sorted_leaves {
        buf.extend_from_slice(id);
        buf.push(*st);
    }
    sha256(&buf)
}

/// Root over the 256 bucket hashes plus the immutable genesis commitment `meta`
/// (ontology hash and chunking parameters, empty before genesis), so that a container cannot be
/// re-labelled with a different ontology or chunker without changing its root.
pub fn root_from_buckets(buckets: &[Hash], meta: &[u8]) -> Hash {
    debug_assert_eq!(buckets.len(), BUCKETS);
    let mut buf = Vec::with_capacity(1 + BUCKETS * 32 + meta.len());
    buf.push(0x02);
    for b in buckets {
        buf.extend_from_slice(b);
    }
    buf.extend_from_slice(meta);
    sha256(&buf)
}

/// Hasher for keys that are already uniformly distributed 32-byte digests.
#[derive(Default)]
pub struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            self.0 ^= u64::from_le_bytes(bytes[..8].try_into().unwrap());
        } else {
            for b in bytes {
                self.0 = self.0.rotate_left(8) ^ (*b as u64);
            }
        }
    }
}

pub type IdBuild = BuildHasherDefault<IdHasher>;
pub type IdMap<V> = std::collections::HashMap<Hash, V, IdBuild>;
pub type IdSet = std::collections::HashSet<Hash, IdBuild>;

/// FxHash-style hasher for short non-digest keys (entity ids, predicates, labels, small tuples) in read-only indexes.
/// Nothing is ever ordered by such a map, so the hasher only affects speed.
#[derive(Default, Clone, Copy)]
pub struct FxHasher(u64);

impl FxHasher {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

impl Hasher for FxHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for w in words {
            self.add(u64::from_le_bytes(*w));
        }
        if !rest.is_empty() {
            let mut b = [0u8; 8];
            b[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_le_bytes(b) ^ ((rest.len() as u64) << 59));
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }

    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }

    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;
pub type FxMap<K, V> = std::collections::HashMap<K, V, FxBuild>;
pub type FxSet<K> = std::collections::HashSet<K, FxBuild>;
