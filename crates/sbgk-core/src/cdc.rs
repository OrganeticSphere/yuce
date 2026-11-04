//! Content-defined chunking over a Gear rolling hash.
//!
//! Two deterministic chunkers share the same compile-time Gear table (fixed SplitMix64 seed, so
//! boundaries are identical on every machine and build):
//!
//! * [`CdcMode::FastCdc`]  - FastCDC with normalized chunking (min / avg / max). A cut depends on
//!   where the current chunk started, so after an edit the boundary sequence needs a few chunks
//!   to re-synchronise.
//! * [`CdcMode::LocalMax`] - a boundary is a byte whose Gear score is the strict maximum of the
//!   `+-avg/2` window around it. A cut depends only on the bytes within that window, so an edit can
//!   only move boundaries near the edit (immediate re-synchronisation). Chunks are at least
//!   `avg/2 + 1` bytes long (except at the document edges); `max` is enforced by forced cuts.

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdcMode {
    FastCdc = 0,
    LocalMax = 1,
}

impl CdcMode {
    pub fn from_u32(v: u32) -> Option<CdcMode> {
        match v {
            0 => Some(CdcMode::FastCdc),
            1 => Some(CdcMode::LocalMax),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> Option<CdcMode> {
        match s {
            "fastcdc" => Some(CdcMode::FastCdc),
            "localmax" => Some(CdcMode::LocalMax),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdcParams {
    pub mode: CdcMode,
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl Default for CdcParams {
    fn default() -> Self {
        CdcParams { mode: CdcMode::LocalMax, min: 512, avg: 1024, max: 2048 }
    }
}

impl CdcParams {
    pub fn to_tuple(self) -> (u32, u32, u32, u32) {
        (self.mode as u32, self.min as u32, self.avg as u32, self.max as u32)
    }

    pub fn from_tuple(t: (u32, u32, u32, u32)) -> Option<CdcParams> {
        Some(CdcParams { mode: CdcMode::from_u32(t.0)?, min: t.1 as usize, avg: t.2 as usize, max: t.3 as usize })
    }
}

const fn splitmix64(state: u64) -> (u64, u64) {
    let s = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (s, z ^ (z >> 31))
}

const fn make_gear() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut st = 0x5342_474B_4344_4301u64; // "SBGKCDC\x01"
    let mut i = 0;
    while i < 256 {
        let (ns, v) = splitmix64(st);
        st = ns;
        t[i] = v;
        i += 1;
    }
    t
}

static GEAR: [u64; 256] = make_gear();

fn top_mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else {
        !0u64 << (64 - bits.min(64))
    }
}

fn log2_floor(x: usize) -> u32 {
    usize::BITS - 1 - x.max(1).leading_zeros()
}

/// Length of the first chunk of `data`.
fn cut(data: &[u8], p: &CdcParams, mask_s: u64, mask_l: u64) -> usize {
    let n = data.len();
    if n <= p.min {
        return n;
    }
    let max = n.min(p.max);
    let norm = p.avg.min(max);
    let mut fp: u64 = 0;
    let mut i = p.min;
    while i < norm {
        fp = (fp << 1).wrapping_add(GEAR[data[i] as usize]);
        if fp & mask_s == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < max {
        fp = (fp << 1).wrapping_add(GEAR[data[i] as usize]);
        if fp & mask_l == 0 {
            return i + 1;
        }
        i += 1;
    }
    max
}

/// Split `data` into content-defined chunks; returns half-open `(start, end)` byte ranges
/// that tile `data` exactly.
pub fn chunk_ranges(data: &[u8], p: &CdcParams) -> Vec<(usize, usize)> {
    match p.mode {
        CdcMode::FastCdc => fastcdc_ranges(data, p),
        CdcMode::LocalMax => local_max_ranges(data, p),
    }
}

fn local_max_ranges(data: &[u8], p: &CdcParams) -> Vec<(usize, usize)> {
    let n = data.len();
    if n == 0 {
        return Vec::new();
    }
    let w = (p.avg / 2).max(1);
    let mut score = Vec::with_capacity(n);
    let mut fp = 0u64;
    for &b in data {
        fp = (fp << 1).wrapping_add(GEAR[b as usize]);
        score.push(fp);
    }
    // a beats b: larger score, ties resolved towards the earlier position
    let beats = |a: usize, b: usize| score[a] > score[b] || (score[a] == score[b] && a < b);
    let mut dq: VecDeque<usize> = VecDeque::new();
    let mut cuts: Vec<usize> = Vec::new();
    for r in 0..n + w {
        if r < n {
            while let Some(&b) = dq.back() {
                if beats(r, b) {
                    dq.pop_back();
                } else {
                    break;
                }
            }
            dq.push_back(r);
        }
        if r >= w {
            let c = r - w;
            if c < n {
                let lo = c.saturating_sub(w);
                while dq.front().is_some_and(|&f| f < lo) {
                    dq.pop_front();
                }
                if dq.front() == Some(&c) {
                    cuts.push(c + 1);
                }
            }
        }
    }
    if cuts.last() != Some(&n) {
        cuts.push(n);
    }
    let mut out = Vec::with_capacity(cuts.len());
    let mut start = 0;
    for cut in cuts {
        while cut - start > p.max {
            out.push((start, start + p.max));
            start += p.max;
        }
        if cut > start {
            out.push((start, cut));
            start = cut;
        }
    }
    out
}

fn fastcdc_ranges(data: &[u8], p: &CdcParams) -> Vec<(usize, usize)> {
    let bits = log2_floor(p.avg);
    let mask_s = top_mask(bits + 2);
    let mask_l = top_mask(bits.saturating_sub(2));
    let mut out = Vec::with_capacity(data.len() / p.avg.max(1) + 1);
    let mut pos = 0;
    while pos < data.len() {
        let len = cut(&data[pos..], p, mask_s, mask_l);
        out.push((pos, pos + len));
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_text(n: usize, seed: u64) -> Vec<u8> {
        let mut st = seed;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let (ns, r) = splitmix64(st);
            st = ns;
            v.push(b'a' + (r % 26) as u8);
            if r % 7 == 0 {
                v.push(b' ');
            }
        }
        v.truncate(n);
        v
    }

    fn both() -> [CdcParams; 2] {
        let d = CdcParams::default();
        [CdcParams { mode: CdcMode::FastCdc, ..d }, CdcParams { mode: CdcMode::LocalMax, ..d }]
    }

    #[test]
    fn tiles_exactly_and_respects_bounds() {
        let data = pseudo_text(60_000, 1);
        for p in both() {
            let ranges = chunk_ranges(&data, &p);
            let mut pos = 0;
            for (i, &(s, e)) in ranges.iter().enumerate() {
                assert_eq!(s, pos);
                assert!(e > s);
                assert!(e - s <= p.max);
                if i > 0 && i + 1 < ranges.len() {
                    let floor = if p.mode == CdcMode::FastCdc { p.min } else { p.avg / 2 + 1 };
                    assert!(e - s >= floor, "{:?} chunk {i} has {} bytes", p.mode, e - s);
                }
                pos = e;
            }
            assert_eq!(pos, data.len());
            let mean = data.len() as f64 / ranges.len() as f64;
            assert!(mean > 600.0 && mean < 1800.0, "{:?} mean chunk {mean}", p.mode);
        }
    }

    #[test]
    fn local_max_resynchronises_after_prefix_insertion() {
        let data = pseudo_text(40_000, 2);
        let mut edited = pseudo_text(700, 99);
        edited.extend_from_slice(&data);
        let p = CdcParams { mode: CdcMode::LocalMax, ..CdcParams::default() };
        let h = |d: &[u8]| chunk_ranges(d, &p).into_iter().map(|(s, e)| crate::hash::sha256(&d[s..e])).collect::<Vec<_>>();
        let a = h(&data);
        let b = h(&edited);
        let reused = a.iter().filter(|x| b.contains(x)).count();
        assert!(reused as f64 / a.len() as f64 >= 0.9, "reused {reused}/{}", a.len());
    }

    #[test]
    fn deterministic() {
        let data = pseudo_text(10_000, 3);
        for p in both() {
            assert_eq!(chunk_ranges(&data, &p), chunk_ranges(&data, &p));
        }
        assert!(chunk_ranges(&[], &CdcParams::default()).is_empty());
        assert_eq!(chunk_ranges(b"x", &CdcParams::default()), vec![(0, 1)]);
    }
}
