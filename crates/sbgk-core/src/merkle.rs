//! Bucketed Merkle commitment over `(node_id, status)` leaves.
//!
//! Leaves are partitioned by the first byte of `node_id` into 256 buckets, so the tree shape
//! depends only on the *set* of nodes, never on insertion order. A bucket hash covers its
//! leaves sorted by id; the root covers the 256 bucket hashes. Two states are compared by
//! first comparing 256 bucket hashes and only then walking the differing buckets.

use crate::hash::{sha256, Hash, ZERO_HASH};
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};

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

/// `IdHasher` under a key drawn once per process, for tables of ids whose content an agent writes. A digest is uniform only until
/// someone searches: an agent can look for texts whose ids share their first bits, and in an unkeyed table those would all fall in
/// one bucket and slow every pass. Roots do not depend on it, as nothing reads such a table in order.
#[derive(Clone, Copy)]
pub struct KeyedIdBuild(u64);

impl Default for KeyedIdBuild {
    fn default() -> Self {
        static KEY: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        Self(*KEY.get_or_init(|| std::collections::hash_map::RandomState::new().hash_one(0u64) | 1))
    }
}

impl BuildHasher for KeyedIdBuild {
    type Hasher = KeyedIdHasher;

    fn build_hasher(&self) -> KeyedIdHasher {
        KeyedIdHasher { key: self.0, id: IdHasher::default() }
    }
}

pub struct KeyedIdHasher {
    key: u64,
    id: IdHasher,
}

impl Hasher for KeyedIdHasher {
    fn finish(&self) -> u64 {
        let mixed = self.id.finish().wrapping_mul(self.key);
        mixed ^ (mixed >> 32)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.id.write(bytes);
    }
}

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

#[cfg(test)]
mod keyed_tests {
    use super::*;

    /// Ids that an agent searched for so that their first bits agree: unkeyed they share one bucket, keyed they spread.
    #[test]
    fn ids_that_share_their_first_bits_spread_under_the_key() {
        let ids: Vec<[u8; 32]> = (0..1024u64)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(i << 24).to_le_bytes());
                id
            })
            .collect();
        let buckets = |hash: &dyn Fn(&[u8; 32]) -> u64| ids.iter().map(|id| hash(id) & 0xFFFF).collect::<std::collections::BTreeSet<_>>().len();
        let (plain, keyed) = (IdBuild::default(), KeyedIdBuild::default());
        assert_eq!(buckets(&|id| plain.hash_one(id)), 1, "the case this table is for");
        assert!(buckets(&|id| keyed.hash_one(id)) > 512);
    }
}
