//! The two binary hash trees of the `sbgk-session-log/3` journal (SPEC_V02_STEP2 sections 2 and 7).
//!
//! * The records tree of one frame: its leaves are the records the frame accepted, in the order it accepted them, each leaf the
//!   hash of the record with the bindings of all its grounds. It has string domains of its own.
//! * The log tree over the frame hashes, which a seal names: RFC 6962 bytes (`0x00` leaf, `0x01` node), so that a standard
//!   witness can follow it later.
//!
//! Both split as RFC 6962 does: the left subtree takes the largest power of two below the leaf count, which keeps an inclusion
//! path at `log n` hashes.

use crate::hash::{sha256, sha256_parts, Hash};
use crate::jcs::to_jcs;
use serde_json::Value;

const REC_LEAF: &[u8] = b"R2R-REC-LEAF/2\0";
const REC_NODE: &[u8] = b"R2R-REC-NODE/2\0";
const REC_EMPTY: &[u8] = b"R2R-REC-EMPTY/2\0";

/// The largest power of two strictly below `n` (`n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The leaf of one accepted record: `H("R2R-REC-LEAF/2", JCS(L))`.
pub fn record_leaf(value: &Value) -> Hash {
    sha256_parts(&[REC_LEAF, to_jcs(value).as_bytes()])
}

/// The root of a frame's records tree over leaf hashes in acceptance order; a frame that accepted no record has the empty root.
pub fn records_root(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => sha256_parts(&[REC_EMPTY]),
        [leaf] => *leaf,
        _ => {
            let k = split(leaves.len());
            sha256_parts(&[REC_NODE, &records_root(&leaves[..k]), &records_root(&leaves[k..])])
        }
    }
}

/// The inclusion path of leaf `index`, from the leaf's sibling up to the root's children.
pub fn records_path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    let mut path = Vec::new();
    path_into(leaves, index, &mut path, records_root);
    path
}

/// Whether `path` leads `leaf`, at `index` of a tree of `size` leaves, to `root`.
pub fn verify_records_path(leaf: &Hash, index: usize, size: usize, path: &[Hash], root: &Hash) -> bool {
    walk(leaf, index, size, path, &|l, r| sha256_parts(&[REC_NODE, l, r])) == Some(*root)
}

fn path_into(leaves: &[Hash], index: usize, path: &mut Vec<Hash>, root: fn(&[Hash]) -> Hash) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    if index < k {
        path_into(&leaves[..k], index, path, root);
        path.push(root(&leaves[k..]));
    } else {
        path_into(&leaves[k..], index - k, path, root);
        path.push(root(&leaves[..k]));
    }
}

/// Recompute a root from a leaf and its path (RFC 9162 section 2.1.3.2 in recursive form); `None` when the path has the wrong length.
fn walk(leaf: &Hash, index: usize, size: usize, path: &[Hash], node: &dyn Fn(&Hash, &Hash) -> Hash) -> Option<Hash> {
    if index >= size {
        return None;
    }
    if size == 1 {
        return path.is_empty().then_some(*leaf);
    }
    let (sibling, rest) = path.split_last()?;
    let k = split(size);
    if index < k {
        Some(node(&walk(leaf, index, k, rest, node)?, sibling))
    } else {
        Some(node(sibling, &walk(leaf, index - k, size - k, rest, node)?))
    }
}

/// The RFC 6962 leaf hash of one frame hash: `SHA256(0x00 || h)`.
pub fn log_leaf(frame_hash: &Hash) -> Hash {
    sha256_parts(&[&[0x00], frame_hash])
}

/// The RFC 6962 tree head over frame hashes `0..n` (`SHA256()` of nothing for an empty log).
pub fn log_root(frame_hashes: &[Hash]) -> Hash {
    fn head(leaves: &[Hash]) -> Hash {
        match leaves {
            [] => sha256(&[]),
            [leaf] => *leaf,
            _ => {
                let k = split(leaves.len());
                sha256_parts(&[&[0x01], &head(&leaves[..k]), &head(&leaves[k..])])
            }
        }
    }
    let leaves: Vec<Hash> = frame_hashes.iter().map(log_leaf).collect();
    head(&leaves)
}

/// The RFC 6962 inclusion path of frame `index` in a log of `frame_hashes.len()` frames.
pub fn log_path(frame_hashes: &[Hash], index: usize) -> Vec<Hash> {
    fn head(leaves: &[Hash]) -> Hash {
        match leaves {
            [] => sha256(&[]),
            [leaf] => *leaf,
            _ => {
                let k = split(leaves.len());
                sha256_parts(&[&[0x01], &head(&leaves[..k]), &head(&leaves[k..])])
            }
        }
    }
    let leaves: Vec<Hash> = frame_hashes.iter().map(log_leaf).collect();
    let mut path = Vec::new();
    path_into(&leaves, index, &mut path, head);
    path
}

/// Whether `path` leads frame hash `frame_hash`, at `index` of a log of `size` frames, to the tree head `root`.
pub fn verify_log_path(frame_hash: &Hash, index: usize, size: usize, path: &[Hash], root: &Hash) -> bool {
    walk(&log_leaf(frame_hash), index, size, path, &|l, r| sha256_parts(&[&[0x01], l, r])) == Some(*root)
}

/// The tree head over all frames but the last, from the inclusion path of the last frame (SPEC_V02_STEP5 section 6, check 4): that
/// path is the heads of the complete subtrees left of the last leaf, deepest first, and folded together they give the head of the
/// frames before it. A quittance binds the seal `P`, whose `log_root` names exactly those frames, to the signed head this way.
/// `None` for an empty path: a log of one frame has no frames before its last.
pub fn log_prefix_root(last_path: &[Hash]) -> Option<Hash> {
    let (first, rest) = last_path.split_first()?;
    Some(rest.iter().fold(*first, |right, left| sha256_parts(&[&[0x01], left, &right])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::from_hex;

    #[test]
    fn the_path_of_the_last_frame_folds_to_the_head_of_the_frames_before_it() {
        let l = leaves(41);
        assert_eq!(log_prefix_root(&log_path(&l[..1], 0)), None);
        for n in 2..=41 {
            let path = log_path(&l[..n], n - 1);
            assert_eq!(log_prefix_root(&path), Some(log_root(&l[..n - 1])), "{n} frames");
            assert!(verify_log_path(&l[n - 1], n - 1, n, &path, &log_root(&l[..n])));
        }
    }

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| sha256(format!("leaf {i}").as_bytes())).collect()
    }

    #[test]
    fn every_path_of_trees_up_to_seventeen_leaves_leads_to_its_root_and_no_other() {
        for n in 1..=17 {
            let l = leaves(n);
            let root = records_root(&l);
            let log = log_root(&l);
            for i in 0..n {
                let path = records_path(&l, i);
                assert!(verify_records_path(&l[i], i, n, &path, &root), "records n={n} i={i}");
                assert!(!verify_records_path(&l[(i + 1) % n], i, n, &path, &root) || n == 1, "records n={n} i={i}: another leaf");
                // a path of the wrong length for the size is refused (sizes with paths of equal shape bind through the seal)
                assert!(!verify_records_path(&l[i], i, 2 * n + 1, &path, &root), "records n={n} i={i}: a deeper size");
                let lp = log_path(&l, i);
                assert!(verify_log_path(&l[i], i, n, &lp, &log), "log n={n} i={i}");
                assert!(!verify_log_path(&l[i], i, n, &lp, &root), "log n={n} i={i}: the records root");
            }
            assert!(!verify_records_path(&l[0], n, n, &[], &root));
        }
    }

    #[test]
    fn the_two_trees_have_distinct_domains_and_the_empty_cases_are_fixed() {
        let l = leaves(5);
        assert_ne!(records_root(&l), log_root(&l));
        assert_eq!(records_root(&[]), sha256_parts(&[b"R2R-REC-EMPTY/2\0"]));
        // RFC 6962: the head of an empty log is the SHA-256 of nothing
        assert_eq!(log_root(&[]), from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap());
        assert_eq!(records_root(&l[..1]), l[0]);
        assert_eq!(log_root(&l[..1]), sha256_parts(&[&[0], &l[0]]));
    }

    #[test]
    fn a_log_of_three_frames_has_the_rfc_6962_shape() {
        let l = leaves(3);
        let (a, b, c) = (log_leaf(&l[0]), log_leaf(&l[1]), log_leaf(&l[2]));
        let ab = sha256_parts(&[&[1], &a, &b]);
        assert_eq!(log_root(&l), sha256_parts(&[&[1], &ab, &c]));
    }

    /// The vectors of an independent implementation of the specification (SBGK/SPEC_V02_STEP2, sections 0 and 2): a zero byte ends
    /// every domain, and the nodes hash raw 32-byte children.
    #[test]
    fn the_records_tree_matches_the_vectors_of_an_independent_implementation() {
        let hex = |h: Hash| crate::hash::to_hex(&h);
        assert_eq!(hex(records_root(&[])), "fe7c90ca2214e168f5ffe6cccb15729c3b8a03c403e48c406441cd589fdd8c41");
        let leaves: Vec<Hash> = (0..3).map(|n| record_leaf(&serde_json::json!({"n": n}))).collect();
        assert_eq!(hex(leaves[0]), "7c7593397600ae0f050d8e3b330563dd56b19c3aa3759764ba3515cc40659613");
        assert_eq!(hex(records_root(&leaves)), "a8f3c3f0dede6a44cbd15b72ecfcf9dda5c45d1a0df37b31793afb47f6c6ad08");
    }
}

/// The vectors another session computed from the text of SPEC_V02_STEP2 alone, without this code, for the independent verifier
/// `yuce-verify` (SBGK/VECTORS_INDEPENDENT_VERIFIER_20261110.json, V1, V2 and V4): the kernel's own functions must give them.
#[cfg(test)]
mod spec_text_vectors {
    use super::*;
    use crate::hash::{from_hex, sha256, to_hex};
    use serde_json::json;

    #[test]
    fn the_records_and_log_trees_give_the_vectors_written_from_the_spec_text() {
        assert_eq!(to_hex(&records_root(&[])), "fe7c90ca2214e168f5ffe6cccb15729c3b8a03c403e48c406441cd589fdd8c41");
        let leaves: Vec<Hash> = (0..3).map(|i| record_leaf(&json!({"id": format!("vector-{i}"), "kind": "observe"}))).collect();
        assert_eq!(
            leaves.iter().map(|l| to_hex(l)).collect::<Vec<_>>(),
            [
                "02cc8d3401b742e842f47e5eb86387d04c3e40caaaef6fefce763c6a14586b3a",
                "91541b96915cc39cdacd38e0437d9257a5d24f043ddc7d7fb5d97d75d70b7170",
                "7afb8d6308012bdd6bedebc2d8a2393af51a234827d9382f59a90f21f582cc24"
            ]
        );
        for (n, want) in [
            (1, "02cc8d3401b742e842f47e5eb86387d04c3e40caaaef6fefce763c6a14586b3a"),
            (2, "0e47cfc6c3aafdf12a6a75d3c0834a9c3d44105565ae9661225cf18b28f2c9f4"),
            (3, "9ffe7bd62d1a3077572650027a8a5ff2f0e4a9470a43e4c3a98d507fd151b94e"),
        ] {
            assert_eq!(to_hex(&records_root(&leaves[..n])), want, "{n} records");
        }
        let frames =
            [from_hex("09cdb29cc18bdc6fb6310d325d645bed02107f2e2e453be7b7854d8b0be587dc").unwrap(), sha256(b"vector-frame-1"), sha256(b"vector-frame-2")];
        assert_eq!(to_hex(&frames[1]), "b4bae464021d624403627580d82ca0648b01665e080bbe8c6d42f4e43fb56c1c");
        for (n, want) in [
            (1, "32afd763295e47fd58bb46c2586b435b862e2eddcb3647ae7d562bb8b52c2370"),
            (2, "3e318f3d65a78bf4f2f50a7f055fe8c937a69ac8838926dd71a0434ed1f460a2"),
            (3, "3e68089e94499e6df51727b8b615320676ff1e203d8b77551e28502e685da147"),
        ] {
            assert_eq!(to_hex(&log_root(&frames[..n])), want, "{n} frames");
        }
    }
}
