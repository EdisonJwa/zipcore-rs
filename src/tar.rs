//! Writing tar streams, including `tar.zst`.
//!
//! Tar is a different format from ZIP, and `tar.zst` is a different thing again: it is a tar
//! stream **compressed as a whole**, whereas ZIP's zstd *method* compresses each member inside a
//! ZIP container. The two share only the codec.
//!
//! The writer needs nothing but [`Write`], because tar is a streaming format: every header carries
//! the size of the entry that follows, so there is nothing to seek back and patch. That also means
//! the size must be known before the data is written, which is why [`TarWriter::start_file`] asks
//! for it.
//!
//! Because it needs only `Write`, composing it with a compressor is free: put a zstd encoder
//! underneath and the result is a `tar.zst`. See [`TarWriter::new_zstd`].
//!
//! ```no_run
//! use zipcore::{TarEntryOptions, TarWriter};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut tar = TarWriter::new(std::fs::File::create("out.tar")?);
//! tar.add_file("notes.txt", b"hello", &TarEntryOptions::default())?;
//! tar.add_directory("sub", &TarEntryOptions::directory())?;
//! tar.finish()?;
//! # Ok(())
//! # }
//! ```

use crate::dos;
use crate::error::{Error, Result};
use std::io::Write;

/// Every tar record is this many bytes, and file data is padded up to it.
const BLOCK: usize = 512;
/// Two zero blocks terminate a tar stream.
const TRAILER: [u8; BLOCK * 2] = [0u8; BLOCK * 2];

/// Per-entry metadata.
#[derive(Debug, Clone)]
pub struct TarEntryOptions {
    /// Permission bits, without the file-type bits.
    pub mode: u32,
    /// Modification time in seconds since the Unix epoch.
    pub mtime: u64,
    pub uid: u32,
    pub gid: u32,
    /// Owner name, up to 31 bytes. Empty by default.
    pub uname: String,
    /// Group name, up to 31 bytes. Empty by default.
    pub gname: String,
}

impl Default for TarEntryOptions {
    fn default() -> Self {
        Self {
            mode: 0o644,
            mtime: dos::unix_now(),
            uid: 0,
            gid: 0,
            uname: String::new(),
            gname: String::new(),
        }
    }
}

impl TarEntryOptions {
    /// Options for a directory entry (mode `0755`).
    pub fn directory() -> Self {
        Self {
            mode: 0o755,
            ..Self::default()
        }
    }

    /// Set the permission bits.
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// Set the modification time, in seconds since the Unix epoch.
    pub fn with_mtime(mut self, mtime: u64) -> Self {
        self.mtime = mtime;
        self
    }
}

/// Builds a tar stream.
pub struct TarWriter<W: Write> {
    writer: W,
    finished: bool,
    /// Set when a dropped or explicitly finished entry was short, so `finish` cannot bless an
    /// archive whose contents are wrong.
    short_entry: Option<String>,
    /// Set when a write failed, so the writer cannot resume into a stream whose block structure
    /// is already broken.
    failed: Option<String>,
}

impl<W: Write> std::fmt::Debug for TarWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarWriter")
            .field("finished", &self.finished)
            .field("short_entry", &self.short_entry)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<W: Write> TarWriter<W> {
    /// Wrap a sink.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            finished: false,
            short_entry: None,
            failed: None,
        }
    }

    /// Add a regular file from a slice.
    pub fn add_file(&mut self, name: &str, data: &[u8], options: &TarEntryOptions) -> Result<()> {
        let mut entry = self.start_file(name, data.len() as u64, options)?;
        entry.write_all(data).map_err(Error::Io)?;
        entry.finish()
    }

    /// Add a directory entry. A trailing `/` is added if the caller omitted it.
    pub fn add_directory(&mut self, name: &str, options: &TarEntryOptions) -> Result<()> {
        let mut owned = name.to_string();
        if !owned.ends_with('/') {
            owned.push('/');
        }
        self.write_header(&owned, 0, b'5', options)?;
        Ok(())
    }

    /// Begin a regular file of exactly `size` bytes.
    ///
    /// The size has to be declared up front because a tar header precedes its data and cannot be
    /// patched on a stream. Write exactly `size` bytes and call [`TarEntry::finish`]; an entry
    /// dropped short is zero-filled to its declared size and poisons the writer, so the next
    /// header still lands on a block boundary but `finish` reports the damage.
    pub fn start_file(
        &mut self,
        name: &str,
        size: u64,
        options: &TarEntryOptions,
    ) -> Result<TarEntry<'_, W>> {
        self.write_header(name, size, b'0', options)?;
        Ok(TarEntry {
            tar: self,
            remaining: size,
            size,
            name: name.to_string(),
        })
    }

    /// Finish the archive and return the sink.
    pub fn finish(mut self) -> Result<W> {
        if let Some(detail) = self.failed.take() {
            return Err(Error::WriterFailed { detail });
        }
        if let Some(name) = self.short_entry.take() {
            return Err(Error::WriterFailed {
                detail: format!(
                    "entry `{name}` was dropped before all of its declared bytes were written, \
                     so the archive's contents are wrong"
                ),
            });
        }
        if !self.finished {
            self.writer.write_all(&TRAILER).map_err(Error::Io)?;
            self.writer.flush().map_err(Error::Io)?;
            self.finished = true;
        }
        Ok(self.writer)
    }

    /// Consume the writer and return the sink, without finishing the stream.
    ///
    /// Like [`ZipWriter::into_inner`](crate::ZipWriter::into_inner) this is an escape hatch that
    /// deliberately skips the "was anything short?" check, so a stream this writer considered
    /// wrong can still be recovered and inspected.
    pub fn into_inner(self) -> W {
        self.writer
    }

    fn write_header(
        &mut self,
        name: &str,
        size: u64,
        typeflag: u8,
        options: &TarEntryOptions,
    ) -> Result<()> {
        // A header that is half-written leaves the block structure unusable, so a failure here
        // poisons the writer rather than letting it append to a broken stream.
        if let Some(detail) = &self.failed {
            return Err(Error::WriterFailed {
                detail: detail.clone(),
            });
        }
        let header = build_header(name, size, typeflag, options)?;
        self.writer.write_all(&header).map_err(|error| {
            let detail = format!("writing the header for `{name}` failed: {error}");
            self.failed = Some(detail.clone());
            Error::Io(std::io::Error::new(error.kind(), detail))
        })
    }

    /// Write `count` zero bytes, poisoning the writer if that fails.
    fn write_zeros(&mut self, count: u64) -> Result<()> {
        let mut remaining = count;
        let zeros = [0u8; BLOCK];
        while remaining > 0 {
            let want = (remaining as usize).min(zeros.len());
            self.writer.write_all(&zeros[..want]).map_err(|error| {
                let detail = format!("zero-filling a short tar entry failed: {error}");
                self.failed = Some(detail.clone());
                Error::Io(std::io::Error::new(error.kind(), detail))
            })?;
            remaining -= want as u64;
        }
        Ok(())
    }
}

#[cfg(feature = "zstd")]
impl<W: Write> TarWriter<zstd::stream::write::Encoder<'static, W>> {
    /// Start a tar stream whose bytes are zstd-compressed as they are written.
    ///
    /// ```no_run
    /// use zipcore::{TarEntryOptions, TarWriter};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut tar = TarWriter::new_zstd(std::fs::File::create("out.tar.zst")?, 3)?;
    /// tar.add_file("notes.txt", b"hello", &TarEntryOptions::default())?;
    /// tar.finish_zstd()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_zstd(writer: W, level: i32) -> Result<Self> {
        let encoder = zstd::stream::write::Encoder::new(writer, level).map_err(Error::Io)?;
        Ok(TarWriter::new(encoder))
    }

    /// Finish the tar stream *and* the zstd frame, returning the sink.
    pub fn finish_zstd(self) -> Result<W> {
        let encoder = self.finish()?;
        encoder.finish().map_err(Error::Io)
    }
}

/// A handle for writing one entry's contents.
pub struct TarEntry<'a, W: Write> {
    tar: &'a mut TarWriter<W>,
    /// Bytes still to be written.
    remaining: u64,
    /// The declared size, which is what the trailing padding is computed from.
    size: u64,
    name: String,
}

impl<W: Write> std::fmt::Debug for TarEntry<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarEntry")
            .field("name", &self.name)
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl<W: Write> TarEntry<'_, W> {
    /// How many of the declared bytes are still to be written.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Close the entry, padding the payload out to a block boundary.
    ///
    /// Fails if fewer bytes were written than declared: the entry would otherwise silently carry
    /// the wrong contents. The omitted bytes are still zero-filled first, so the *next* header
    /// lands on a block boundary and the stream stays parseable — the data is wrong, but the
    /// container is not.
    pub fn finish(mut self) -> Result<()> {
        let padding = self.padding();
        if self.remaining != 0 {
            let name = self.name.clone();
            let outstanding = self.remaining;
            self.remaining = 0;
            // Fill the declared payload, then the tail padding: one continuous zero run.
            let fill = outstanding
                .checked_add(padding as u64)
                .ok_or_else(|| Error::malformed("tar entry padding overflow"))?;
            self.tar.write_zeros(fill)?;
            if self.tar.short_entry.is_none() {
                self.tar.short_entry = Some(name.clone());
            }
            return Err(Error::WriterFailed {
                detail: format!(
                    "entry `{name}` declared {outstanding} more bytes than were written, \
                     so it was zero-padded"
                ),
            });
        }
        self.tar.write_zeros(padding as u64)
    }

    /// Zeroes needed after the payload to reach a block boundary.
    fn padding(&self) -> usize {
        let remainder = (self.size % BLOCK as u64) as usize;
        (BLOCK - remainder) % BLOCK
    }
}

impl<W: Write> Write for TarEntry<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining) as usize;
        self.tar.writer.write_all(&buf[..want])?;
        self.remaining -= want as u64;
        Ok(want)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tar.writer.flush()
    }
}

impl<W: Write> Drop for TarEntry<'_, W> {
    fn drop(&mut self) {
        if self.remaining > 0 {
            // Pad the *declared* payload, not just the tail: writing only `padding` bytes would
            // leave the next header off a block boundary and desynchronise every later entry.
            let padding = self.padding();
            let outstanding = self.remaining;
            let fill = outstanding.saturating_add(padding as u64);
            let _ = self.tar.write_zeros(fill);
            self.remaining = 0;
            if self.tar.short_entry.is_none() {
                self.tar.short_entry = Some(self.name.clone());
            }
        }
    }
}

/// Build a 512-byte tar header.
fn build_header(
    name: &str,
    size: u64,
    typeflag: u8,
    options: &TarEntryOptions,
) -> Result<[u8; BLOCK]> {
    let (prefix, short_name) = split_name(name)?;
    if !short_name.is_ascii() || !prefix.is_ascii() {
        return Err(Error::Unsupported(
            "non-ASCII tar entry names need a PAX header, which this writer does not emit yet",
        ));
    }

    let mut header = [0u8; BLOCK];
    set_str(&mut header[0..100], &short_name)?;
    set_number(&mut header[100..108], options.mode as u64)?;
    set_number(&mut header[108..116], options.uid as u64)?;
    set_number(&mut header[116..124], options.gid as u64)?;
    set_number(&mut header[124..136], size)?;
    set_number(&mut header[136..148], options.mtime)?;
    // The checksum field is filled with spaces while the checksum itself is computed.
    header[148..156].copy_from_slice(b"        ");
    header[156] = typeflag;
    // linkname is left empty: this writer does not emit links yet.
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    set_str(&mut header[265..297], &options.uname)?;
    set_str(&mut header[297..329], &options.gname)?;
    set_str(&mut header[345..500], &prefix)?;

    let checksum: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
    let text = format!("{checksum:06o}");
    header[148..154].copy_from_slice(text.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    Ok(header)
}

/// Write a byte range as a NUL-terminated string, refusing anything that does not fit.
fn set_str(field: &mut [u8], value: &str) -> Result<()> {
    if value.len() > field.len() {
        return Err(Error::Unsupported(
            "a tar header field is too small for this value",
        ));
    }
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

/// Write a numeric field in octal, falling back to GNU base-256 for values that do not fit.
fn set_number(field: &mut [u8], value: u64) -> Result<()> {
    let digits = field.len() - 1; // room for a terminator
    let max_octal = if digits * 3 >= 64 {
        u64::MAX
    } else {
        (1u64 << (digits * 3)) - 1
    };

    if value <= max_octal {
        let text = format!("{value:0width$o}", width = digits);
        field[..digits].copy_from_slice(text.as_bytes());
        field[digits] = 0;
        return Ok(());
    }

    // GNU base-256: the high bit of the first byte marks the encoding, and the value is
    // right-justified big-endian behind it. Read by libarchive and GNU tar.
    if field.len() < 9 {
        return Err(Error::Unsupported(
            "value too large for a tar header field, even in base-256",
        ));
    }
    field.fill(0);
    field[0] = 0x80;
    let bytes = value.to_be_bytes();
    let start = field.len() - bytes.len();
    field[start..].copy_from_slice(&bytes);
    Ok(())
}

/// Split a path into the ustar `prefix` and `name` fields.
///
/// A name up to 100 bytes fits outright; longer ones are split at a `/` so that the prefix fits in
/// 155 bytes, which is what the ustar format is for. Beyond that the format needs a PAX or GNU
/// long-name entry, which this writer does not emit.
fn split_name(name: &str) -> Result<(String, String)> {
    if name.is_empty() {
        return Err(Error::Unsupported("tar entry names must not be empty"));
    }
    if name.len() <= 100 {
        return Ok((String::new(), name.to_string()));
    }
    for index in (1..name.len()).rev() {
        if name.as_bytes()[index] != b'/' {
            continue;
        }
        let prefix = &name[..index];
        let rest = &name[index + 1..];
        if !rest.is_empty() && prefix.len() <= 155 && rest.len() <= 100 {
            return Ok((prefix.to_string(), rest.to_string()));
        }
    }
    Err(Error::Unsupported(
        "tar entry name is longer than the ustar prefix field allows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_fit_in_the_name_field() {
        let (prefix, name) = split_name("docs/readme.txt").unwrap();
        assert_eq!(prefix, "");
        assert_eq!(name, "docs/readme.txt");
    }

    #[test]
    fn long_names_split_at_a_slash() {
        let long = format!("{}/{}", "a".repeat(120), "b".repeat(80));
        let (prefix, name) = split_name(&long).unwrap();
        assert_eq!(prefix.len(), 120);
        assert_eq!(name.len(), 80);
    }

    #[test]
    fn a_trailing_slash_is_kept_out_of_the_prefix_boundary() {
        let long = format!("{}/file.txt/", "d".repeat(150));
        let (prefix, name) = split_name(&long).unwrap();
        assert_eq!(name, "file.txt/");
        assert_eq!(prefix.len(), 150);
    }

    #[test]
    fn an_unsplittable_name_is_refused() {
        let impossible = "x".repeat(400);
        assert!(split_name(&impossible).is_err());
    }

    #[test]
    fn octal_fields_are_terminated() {
        let mut field = [0u8; 8];
        set_number(&mut field, 0o755).unwrap();
        assert_eq!(&field, b"0000755\0");
    }

    #[test]
    fn oversized_values_fall_back_to_base_256() {
        let mut field = [0u8; 12];
        // 8 GiB + 1 does not fit in 11 octal digits.
        let value = (8u64 << 30) + 1;
        set_number(&mut field, value).unwrap();
        assert_eq!(field[0], 0x80, "base-256 marker");
        assert_eq!(u64::from_be_bytes(field[4..12].try_into().unwrap()), value);
    }

    #[test]
    fn header_checksum_matches_a_hand_computed_ones() {
        let header = build_header("hello.txt", 5, b'0', &TarEntryOptions::default()).unwrap();
        assert_eq!(&header[0..9], b"hello.txt");
        assert_eq!(&header[257..262], b"ustar");

        // Recompute the checksum the way a reader does: spaces in place of the checksum field.
        let mut copy = header;
        copy[148..156].copy_from_slice(b"        ");
        let expected: u32 = copy.iter().map(|&b| u32::from(b)).sum();
        let recorded =
            u32::from_str_radix(std::str::from_utf8(&header[148..154]).unwrap(), 8).unwrap();
        assert_eq!(recorded, expected);
    }
}
