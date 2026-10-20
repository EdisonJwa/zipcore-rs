use crate::error::{Error, Result};
use std::io::{Read, Seek, SeekFrom};

/// Little-endian integer decoding from slices that the caller has already length-checked.
#[inline]
pub(crate) fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

#[inline]
pub(crate) fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
pub(crate) fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Read exactly `buf.len()` bytes starting at an absolute `offset`.
pub(crate) fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buf: &mut [u8],
) -> Result<()> {
    reader.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
    reader.read_exact(buf).map_err(Error::Io)
}

/// Total length of the stream, leaving the cursor where it was.
pub(crate) fn stream_len<R: Read + Seek>(reader: &mut R) -> Result<u64> {
    let saved = reader.stream_position().map_err(Error::Io)?;
    let end = reader.seek(SeekFrom::End(0)).map_err(Error::Io)?;
    reader.seek(SeekFrom::Start(saved)).map_err(Error::Io)?;
    Ok(end)
}

/// A cursor over an in-memory record that returns `Malformed` instead of panicking.
///
/// Every read is length-checked with `checked_add`, so a hostile length field can never
/// produce a slice index panic or an integer wrap.
pub(crate) struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::malformed("length overflow"))?;
        if end > self.data.len() {
            return Err(Error::malformed("truncated record"));
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

/// Return `true` if the four bytes at `offset` are `sig`.
///
/// Running off the end of the stream means "no signature here" and yields `Ok(false)`. Any
/// other failure is reported, so a genuine read error is never disguised as a malformed
/// archive.
pub(crate) fn signature_at<R: Read + Seek>(reader: &mut R, offset: u64, sig: u32) -> Result<bool> {
    let mut buf = [0u8; 4];
    reader.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(u32::from_le_bytes(buf) == sig),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_reader_reads_little_endian() {
        let mut r = SliceReader::new(&[0x01, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(r.u16().unwrap(), 1);
        assert_eq!(r.u32().unwrap(), 2);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn slice_reader_refuses_to_overrun() {
        let mut r = SliceReader::new(&[0u8; 3]);
        assert!(r.u32().is_err());
    }

    #[test]
    fn slice_reader_does_not_wrap_on_huge_length() {
        let mut r = SliceReader::new(&[0u8; 4]);
        // usize::MAX cannot be satisfied and must not overflow the internal position.
        assert!(r.take(usize::MAX).is_err());
    }
}
