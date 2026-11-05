//! SHA-256 helpers and hex utilities. Everything content-addressed in SBGK uses these.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub const ZERO_HASH: Hash = [0u8; 32];

pub fn sha256(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_parts(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `sha256_parts` of parts that `write` hands over one by one, so that a long input never has to be put together first.
pub fn sha256_stream(write: impl FnOnce(&mut dyn FnMut(&[u8]))) -> Hash {
    let mut h = Sha256::new();
    write(&mut |part| h.update(part));
    h.finalize().into()
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Option<Hash> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 16-hex-char (64-bit) prefix used for compact ids in projections.
pub fn short(h: &Hash) -> String {
    to_hex(&h[..8])
}
