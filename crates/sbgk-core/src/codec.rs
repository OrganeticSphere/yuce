//! Tiny little-endian binary reader/writer used by every on-disk structure.

use crate::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub &'static str);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "codec error: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

pub struct Rd<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Rd<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Rd { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError("unexpected end of buffer"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn i64(&mut self) -> Result<i64, CodecError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn hash(&mut self) -> Result<Hash, CodecError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    /// u16 length-prefixed UTF-8 string.
    pub fn str(&mut self) -> Result<String, CodecError> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| CodecError("invalid utf-8"))
    }

    pub fn expect_end(&self) -> Result<(), CodecError> {
        if self.remaining() != 0 {
            Err(CodecError("trailing bytes"))
        } else {
            Ok(())
        }
    }
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_str(out: &mut Vec<u8>, s: &str) {
    assert!(s.len() <= u16::MAX as usize, "string too long for canonical encoding");
    put_u16(out, s.len() as u16);
    out.extend_from_slice(s.as_bytes());
}
