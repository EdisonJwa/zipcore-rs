//! ZIP archive creation.
//!
//! The writer works on a `Write + Seek` sink. Each entry's local file header is written with
//! placeholder checksum and size fields, the data is streamed straight through (compressed on
//! the fly), and the header is then seeked back to and patched with the real values. That
//! keeps memory use flat regardless of entry size and produces archives without data
//! descriptors, which is the most widely compatible shape.
//!
//! Because the sizes are only known after the data has been written, an entry that turns out
//! to be 4 GiB or larger needs its ZIP64 extra field to have been reserved before the data
//! went out. Supply [`FileOptions::size_hint`] for those entries; otherwise the writer reports
//! [`Error::Zip64Required`] rather than emitting a broken archive.

use crate::dos;
use crate::entry::{Compression, Entry};
use crate::error::{Error, Result};
use crate::spec::*;
use miniz_oxide::deflate::core::CompressorOxide;
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::deflate::CompressionLevel;
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Staging buffer for compressed output.
const OUT_BUF_SIZE: usize = 64 * 1024;

/// The largest value a 32-bit ZIP field can hold.
///
/// A field of exactly this value is the ZIP64 sentinel (`0xFFFFFFFF`), not a literal size, so
/// every comparison against it must treat the boundary as "needs ZIP64" ??see [`needs_zip64`].
const ZIP32_MAX: u64 = u32::MAX as u64;

/// Whether a value cannot be stored literally in a 32-bit field.
///
/// `>=` rather than `>`: `u32::MAX` is itself the sentinel, so a size of exactly 4 GiB ??1 must
/// go in the ZIP64 extra field or the reader will look for one that is not there.
fn needs_zip64(value: u64) -> bool {
    value >= ZIP32_MAX
}

/// Compression level used by [`FileOptions::default`].
pub const DEFAULT_COMPRESSION_LEVEL: u8 = 6;

/// Archive-level settings.
#[derive(Debug, Clone)]
pub struct WriteOptions {
    /// Compression used for entries that do not override it.
    pub compression: Compression,
    /// Deflate level, clamped to `0..=10`.
    pub compression_level: u8,
    /// Archive-level comment, written after the end of central directory record.
    pub comment: Option<String>,
    /// Whether member names that are unsafe to extract are permitted.
    ///
    /// Off by default. With it off, [`ZipWriter`] refuses to create an archive containing a
    /// name such as `../../etc/passwd`, because handing somebody an archive that extracts
    /// outside its destination directory is a defect regardless of intent. Turn it on only
    /// when deliberately producing such an archive.
    pub allow_unsafe_names: bool,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            compression: Compression::Deflate,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            comment: None,
            allow_unsafe_names: false,
        }
    }
}

/// Per-entry settings.
#[derive(Debug, Clone)]
pub struct FileOptions {
    /// Compression method for this entry.
    pub compression: Compression,
    /// Deflate level, clamped to `0..=10`.
    pub compression_level: u8,
    /// Unix `st_mode` recorded in the external attributes. When `None`, no Unix mode is
    /// recorded and extractors fall back to the DOS attribute byte.
    pub unix_mode: Option<u32>,
    /// Explicit `(DOS date, DOS time)`. Defaults to the current UTC time.
    pub dos_timestamp: Option<(u16, u16)>,
    /// Per-entry comment.
    pub comment: Option<String>,
    /// Uncompressed size of this entry, when known.
    ///
    /// Used to reserve ZIP64 fields before any data is written. Entries of 4 GiB or more
    /// written without a hint fail with [`Error::Zip64Required`].
    pub size_hint: Option<u64>,
}

impl Default for FileOptions {
    fn default() -> Self {
        Self {
            compression: Compression::Deflate,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            unix_mode: None,
            dos_timestamp: None,
            comment: None,
            size_hint: None,
        }
    }
}

impl FileOptions {
    /// Options for an uncompressed entry.
    pub fn stored() -> Self {
        Self {
            compression: Compression::Stored,
            ..Self::default()
        }
    }

    /// Options for a Deflate entry at `level` (clamped to `0..=10`).
    pub fn deflate(level: u8) -> Self {
        Self {
            compression: Compression::Deflate,
            compression_level: level,
            ..Self::default()
        }
    }

    /// Record a Unix `st_mode` for this entry.
    pub fn with_unix_mode(mut self, mode: u32) -> Self {
        self.unix_mode = Some(mode);
        self
    }

    /// Record an explicit `(DOS date, DOS time)` instead of the current time.
    pub fn with_dos_timestamp(mut self, date: u16, time: u16) -> Self {
        self.dos_timestamp = Some((date, time));
        self
    }

    /// Declare the uncompressed size, enabling ZIP64 reservation for large entries.
    pub fn with_size_hint(mut self, size: u64) -> Self {
        self.size_hint = Some(size);
        self
    }

    /// Attach a per-entry comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// A central directory record, built up once an entry is complete.
struct CentralRecord {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    dos_date: u16,
    dos_time: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    header_offset: u64,
    external_attrs: u32,
    comment: Vec<u8>,
    zip64_sizes: bool,
    zip64_offset: bool,
    /// Host and version byte, preserved verbatim when copying an entry.
    version_made_by: u16,
}

enum Encoder {
    Stored,
    Deflate(Box<CompressorOxide>),
    /// A codec that owns its own output buffer. The archive's sink is drained from that buffer
    /// after each write, so the codec never has to own the sink itself ??which is what would
    /// otherwise make the writer self-referential.
    #[cfg(feature = "zstd")]
    Zstd(Box<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

/// State for the entry currently being written.
struct EntryState {
    name: String,
    encoded_name: Vec<u8>,
    flags: u16,
    method: u16,
    dos_date: u16,
    dos_time: u16,
    comment: Vec<u8>,
    external_attrs: u32,
    header_offset: u64,
    zip64_sizes: bool,
    zip64_offset: bool,
    crc: crc32fast::Hasher,
    uncompressed: u64,
    compressed: u64,
    encoder: Encoder,
    out_buf: Vec<u8>,
}

/// Builds a ZIP archive.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::Write;
///
/// let file = std::fs::File::create("out.zip")?;
/// let mut writer = zipcore::ZipWriter::new(std::io::BufWriter::new(file));
///
/// writer.add_file("hello.txt", b"hello", &zipcore::FileOptions::default())?;
///
/// let mut entry = writer.start_file("streamed.txt", &zipcore::FileOptions::stored())?;
/// entry.write_all(b"written in pieces")?;
/// entry.finish()?;
///
/// writer.add_directory("empty-dir", &zipcore::FileOptions::default())?;
///
/// writer.finish()?;
/// # Ok(())
/// # }
/// ```
pub struct ZipWriter<W: Write + Seek> {
    writer: W,
    options: WriteOptions,
    records: Vec<CentralRecord>,
    current: Option<EntryState>,
    finished: bool,
    /// Set when a structured failure occurs, so `finish` reports the cause rather than the
    /// flattened `io::Error` that the `Write` trait forces on us.
    pending_error: Option<Error>,
}

impl<W: Write + Seek> std::fmt::Debug for ZipWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipWriter")
            .field("entries", &self.records.len())
            .field("in_progress", &self.current.is_some())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<W: Write + Seek> ZipWriter<W> {
    /// Create a writer with default options.
    pub fn new(writer: W) -> Self {
        Self::new_with_options(writer, WriteOptions::default())
    }

    /// Create a writer with explicit archive-level options.
    pub fn new_with_options(writer: W, options: WriteOptions) -> Self {
        Self {
            writer,
            options,
            records: Vec::new(),
            current: None,
            finished: false,
            pending_error: None,
        }
    }

    /// Begin a file entry and return a handle to write its contents.
    ///
    /// The returned handle must be dropped (or [`ZipWriterEntry::finish`]ed) before another
    /// entry can be started.
    pub fn start_file(
        &mut self,
        name: &str,
        options: &FileOptions,
    ) -> Result<ZipWriterEntry<'_, W>> {
        self.begin_entry(name, options, false)?;
        Ok(ZipWriterEntry { zip: self })
    }

    /// Write a whole file entry from a slice.
    pub fn add_file(&mut self, name: &str, data: &[u8], options: &FileOptions) -> Result<()> {
        let mut entry = self.start_file(name, options)?;
        if let Err(io_error) = entry.write_all(data) {
            // Report the latched cause, but leave the latch in place so that the writer stays
            // unusable rather than silently continuing with a broken archive.
            return Err(entry
                .zip
                .pending_error_copy()
                .unwrap_or(Error::Io(io_error)));
        }
        entry.finish()
    }

    /// Write a directory entry. A trailing `/` is added if the caller omitted it.
    ///
    /// Directory entries are optional: extractors reconstruct directories from member paths.
    pub fn add_directory(&mut self, name: &str, options: &FileOptions) -> Result<()> {
        self.begin_entry(name, options, true)?;
        self.end_entry()
    }

    /// Write an entry whose payload is already compressed, copying it verbatim.
    ///
    /// The name, method, CRC-32, sizes and attributes are taken from `entry` and written without
    /// inspecting the bytes, so an entry using a compression method this crate cannot decode ??    /// or one that is encrypted ??still copies faithfully. `payload` must yield exactly
    /// `entry.compressed_size()` bytes; a short source is reported rather than silently
    /// truncating the archive.
    ///
    /// Because the sizes are known up front, ZIP64 fields are chosen exactly and the local header
    /// needs no patching. That also means an entry past 4 GiB copies correctly *without* a size
    /// hint, unlike the streaming path.
    ///
    /// The data-descriptor flag is dropped: it describes how the source was written, and this
    /// writer always records real sizes in the local header.
    pub fn add_preserved<R: Read>(&mut self, entry: &Entry, payload: &mut R) -> Result<()> {
        if self.finished {
            return Err(Error::WriterFinished);
        }
        if self.pending_error.is_some() {
            return Err(Error::WriterFailed {
                detail: self.pending_error_detail(),
            });
        }
        // Validate the bytes actually being written, not just the decoded name.
        if !self.options.allow_unsafe_names {
            let raw_name = String::from_utf8_lossy(entry.name_raw());
            crate::path::safe_archive_name(&raw_name).map_err(|reason| Error::UnsafePath {
                entry: raw_name.into_owned(),
                reason,
            })?;
        }
        self.end_entry()?;

        let name = entry.name_raw();
        check_name_len(name)?;
        let comment = entry
            .comment()
            .map(|comment| comment.as_bytes().to_vec())
            .unwrap_or_default();
        if comment.len() > u16::MAX as usize {
            return Err(Error::malformed("entry comment too long"));
        }

        let compressed_size = entry.compressed_size();
        let uncompressed_size = entry.uncompressed_size();
        let flags = entry.flags & !FLAG_DATA_DESCRIPTOR;
        let (dos_date, dos_time) = entry.dos_timestamp();

        let header_offset = self.writer.stream_position().map_err(Error::Io)?;
        let zip64_sizes = needs_zip64(compressed_size) || needs_zip64(uncompressed_size);
        let zip64_offset = needs_zip64(header_offset);
        let extra_len = if zip64_sizes { 20usize } else { 0 };
        let version = if zip64_sizes || zip64_offset {
            45u16
        } else {
            20u16
        };
        let size_field = |value: u64| {
            if zip64_sizes {
                u32::MAX
            } else {
                value as u32
            }
        };

        let mut header = Vec::with_capacity(LOCAL_HEADER_LEN + name.len() + extra_len);
        header.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        header.extend_from_slice(&version.to_le_bytes());
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&entry.method().to_le_bytes());
        header.extend_from_slice(&dos_time.to_le_bytes());
        header.extend_from_slice(&dos_date.to_le_bytes());
        header.extend_from_slice(&entry.crc32().to_le_bytes());
        header.extend_from_slice(&size_field(compressed_size).to_le_bytes());
        header.extend_from_slice(&size_field(uncompressed_size).to_le_bytes());
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&(extra_len as u16).to_le_bytes());
        header.extend_from_slice(name);
        if zip64_sizes {
            header.extend_from_slice(&EXTRA_ZIP64.to_le_bytes());
            header.extend_from_slice(&16u16.to_le_bytes());
            header.extend_from_slice(&uncompressed_size.to_le_bytes());
            header.extend_from_slice(&compressed_size.to_le_bytes());
        }
        self.writer.write_all(&header).map_err(Error::Io)?;

        let mut copied = 0u64;
        let mut buffer = vec![0u8; 64 * 1024];
        while copied < compressed_size {
            let want = ((compressed_size - copied) as usize).min(buffer.len());
            let read = payload.read(&mut buffer[..want]).map_err(Error::Io)?;
            if read == 0 {
                let detail = format!(
                    "payload for `{}` ended after {copied} of {compressed_size} bytes",
                    entry.name()
                );
                // A half-written entry cannot be repaired, so the writer stops accepting work
                // rather than appending to an archive whose structure no longer adds up.
                self.pending_error = Some(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    detail.clone(),
                )));
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    detail,
                )));
            }
            self.writer.write_all(&buffer[..read]).map_err(Error::Io)?;
            copied += read as u64;
        }

        self.records.push(CentralRecord {
            name: name.to_vec(),
            flags,
            method: entry.method(),
            dos_date,
            dos_time,
            crc32: entry.crc32(),
            compressed_size,
            uncompressed_size,
            header_offset,
            external_attrs: entry.external_attrs,
            comment,
            zip64_sizes,
            zip64_offset,
            version_made_by: entry.version_made_by,
        });
        Ok(())
    }

    /// Copy every entry from `source` into this archive without recompressing.
    ///
    /// Returns the number of entries copied. Because the payloads are copied byte for byte, the
    /// compressed sizes in the result are identical to the source's ??nothing is inflated and
    /// nothing is deflated again.
    ///
    /// The archive-level comment is not copied; set [`WriteOptions::comment`] when constructing
    /// the writer if you want one.
    pub fn copy_from<R: Read + Seek>(&mut self, source: &mut crate::Archive<R>) -> Result<usize> {
        let count = source.len();
        for index in 0..count {
            let entry = source.entries()[index].clone();
            let mut payload = source.raw_reader(index)?;
            self.add_preserved(&entry, &mut payload)?;
        }
        Ok(count)
    }

    /// Finish the archive without consuming the writer.
    ///
    /// Unlike [`ZipWriter::finish`], a failure here leaves `self` intact, so
    /// [`ZipWriter::into_inner`] can still recover whatever was written. Use this when losing
    /// the sink on failure would be unacceptable.
    ///
    /// A failure also latches the writer: the central directory may be half-written, so a retry
    /// could otherwise emit an archive that claims fewer entries than were really written.
    pub fn finish_ref(&mut self) -> Result<()> {
        if let Some(error) = &self.pending_error {
            // Report the original cause every time rather than decaying to `WriterFinished`.
            return Err(Error::WriterFailed {
                detail: error.to_string(),
            });
        }
        if self.finished {
            return Err(Error::WriterFinished);
        }
        self.end_entry()?;
        if let Err(error) = self
            .write_central_directory()
            .and_then(|()| self.writer.flush().map_err(Error::Io))
        {
            // The central directory may be partially on the sink, so nothing more can be
            // appended: latch, and let `into_inner` recover the bytes written so far.
            let detail = error.to_string();
            self.pending_error = Some(copy_as_io_error(&error));
            return Err(Error::WriterFailed { detail });
        }
        self.finished = true;
        Ok(())
    }

    /// Finish the archive and hand back the sink.
    ///
    /// On failure the sink is dropped along with the writer; use [`ZipWriter::finish_ref`]
    /// followed by [`ZipWriter::into_inner`] when you need to keep it.
    pub fn finish(mut self) -> Result<W> {
        self.finish_ref()?;
        Ok(self.writer)
    }

    /// Consume the writer and return the sink, without finishing the archive.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Number of entries written so far, excluding one still in progress.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no entries have been written yet.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn begin_entry(&mut self, name: &str, options: &FileOptions, is_dir: bool) -> Result<()> {
        if self.finished {
            return Err(Error::WriterFinished);
        }
        if self.pending_error.is_some() {
            // Latched permanently: not cleared here, so every later operation reports it
            // instead of appending to an archive that is already inconsistent. `finish` takes
            // the original, structured error.
            return Err(Error::WriterFailed {
                detail: self.pending_error_detail(),
            });
        }
        if !self.options.allow_unsafe_names {
            crate::path::safe_archive_name(name).map_err(|reason| Error::UnsafePath {
                entry: name.to_string(),
                reason,
            })?;
        }
        // Defensive: the borrow checker prevents this in safe code.
        self.end_entry()?;

        let compression = options.compression;
        if !compression.is_writable() {
            let method = compression.method_id();
            let entry = name.to_string();
            // Distinguish "no such codec" from "we can decode it but not encode it", because the
            // second is a real limitation of this build rather than a malformed request.
            return Err(if compression.is_supported() {
                Error::CompressionNotWritable { entry, method }
            } else {
                Error::UnsupportedCompression { entry, method }
            });
        }
        // A directory has no contents, so it is always stored.
        let method = if is_dir {
            METHOD_STORED
        } else {
            compression.method_id()
        };

        let mut encoded_name = name.as_bytes().to_vec();
        if is_dir && !encoded_name.ends_with(b"/") {
            encoded_name.push(b'/');
        }
        if encoded_name.is_empty() {
            return Err(Error::malformed("entry name must not be empty"));
        }
        check_name_len(&encoded_name)?;
        let display_name = String::from_utf8_lossy(&encoded_name).into_owned();

        let mut flags = 0u16;
        if !encoded_name.is_ascii() {
            flags |= FLAG_UTF8;
        }

        let (dos_date, dos_time) = options.dos_timestamp.unwrap_or_else(dos::now);

        let comment = options
            .comment
            .as_ref()
            .map(|c| c.as_bytes().to_vec())
            .unwrap_or_default();
        if comment.len() > u16::MAX as usize {
            return Err(Error::malformed("entry comment too long"));
        }

        let header_offset = self.writer.stream_position().map_err(Error::Io)?;

        // Reserve the ZIP64 size fields only when the caller told us the entry is large
        // enough to need them; the offsets are known now, so decide those exactly.
        let zip64_sizes = options.size_hint.is_some_and(needs_zip64);
        let zip64_offset = needs_zip64(header_offset);
        let extra_len = if zip64_sizes { 4 + 16 } else { 0 };
        let version = if zip64_sizes || zip64_offset {
            45u16
        } else {
            20u16
        };

        let size_sentinel = if zip64_sizes { u32::MAX } else { 0 };
        let mut header = Vec::with_capacity(LOCAL_HEADER_LEN + encoded_name.len() + extra_len);
        header.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        header.extend_from_slice(&version.to_le_bytes());
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&dos_time.to_le_bytes());
        header.extend_from_slice(&dos_date.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // CRC-32, patched later
        header.extend_from_slice(&size_sentinel.to_le_bytes()); // compressed size
        header.extend_from_slice(&size_sentinel.to_le_bytes()); // uncompressed size
        header.extend_from_slice(&(encoded_name.len() as u16).to_le_bytes());
        header.extend_from_slice(&(extra_len as u16).to_le_bytes());
        header.extend_from_slice(&encoded_name);
        if zip64_sizes {
            // Reserved now, filled in once the sizes are known.
            header.extend_from_slice(&EXTRA_ZIP64.to_le_bytes());
            header.extend_from_slice(&16u16.to_le_bytes());
            header.extend_from_slice(&0u64.to_le_bytes());
            header.extend_from_slice(&0u64.to_le_bytes());
        }
        // A partially written local header leaves the sink in an unknown state, so a failure
        // here latches the writer: nothing can be appended to a header that is half out.
        if let Err(error) = self.writer.write_all(&header) {
            let detail = format!("writing the local header for `{display_name}` failed: {error}");
            self.pending_error = Some(Error::Io(io::Error::new(error.kind(), detail.clone())));
            return Err(Error::Io(io::Error::new(error.kind(), detail)));
        }
        let mut external_attrs: u32 = if is_dir { 0x10 } else { 0x20 };
        if let Some(mode) = options.unix_mode {
            external_attrs |= mode << 16;
        }

        let encoder = if is_dir || method == METHOD_STORED {
            Encoder::Stored
        } else {
            match compression {
                Compression::Deflate => Encoder::Deflate(new_compressor(options.compression_level)),
                #[cfg(feature = "zstd")]
                Compression::Zstd => {
                    let level = zstd_level(options.compression_level);
                    let encoder =
                        zstd::stream::write::Encoder::new(Vec::with_capacity(OUT_BUF_SIZE), level)
                            .map_err(Error::Io)?;
                    Encoder::Zstd(Box::new(encoder))
                }
                // `is_writable` rejected anything else before we got here.
                other => {
                    return Err(Error::UnsupportedCompression {
                        entry: display_name,
                        method: other.method_id(),
                    })
                }
            }
        };

        self.current = Some(EntryState {
            name: display_name,
            encoded_name,
            flags,
            method,
            dos_date,
            dos_time,
            comment,
            external_attrs,
            header_offset,
            zip64_sizes,
            zip64_offset,
            crc: crc32fast::Hasher::new(),
            uncompressed: 0,
            compressed: 0,
            encoder,
            out_buf: vec![0u8; OUT_BUF_SIZE],
        });
        Ok(())
    }

    fn entry_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(error) = self.latched_io_error() {
            return Err(error);
        }
        if self.finished {
            return Err(io::Error::from(Error::WriterFinished));
        }
        let mut state = match self.current.take() {
            Some(state) => state,
            None => return Err(io::Error::from(Error::NoEntryInProgress)),
        };
        // Take the state out while writing so the sink stays independently borrowable, then
        // put it back so the entry can still be closed deterministically.
        let result = self.pump(&mut state, buf);
        self.current = Some(state);
        match result {
            Ok(written) => Ok(written),
            Err(error) => {
                // A failed write leaves the entry's byte stream in an unknown state, so the
                // archive can no longer be completed. Latch the cause and refuse to continue,
                // rather than resuming into a structure that no longer adds up.
                if self.pending_error.is_none() {
                    self.pending_error =
                        Some(Error::Io(io::Error::new(error.kind(), error.to_string())));
                }
                Err(error)
            }
        }
    }

    fn pump(&mut self, state: &mut EntryState, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.zip64_overflow(state) {
            return Err(self.fail(error));
        }

        state.crc.update(buf);
        state.uncompressed += buf.len() as u64;

        if matches!(state.encoder, Encoder::Stored) {
            self.writer.write_all(buf)?;
            state.compressed += buf.len() as u64;
            return Ok(buf.len());
        }

        #[cfg(feature = "zstd")]
        if matches!(state.encoder, Encoder::Zstd(_)) {
            let produced = {
                let encoder = match &mut state.encoder {
                    Encoder::Zstd(encoder) => encoder,
                    _ => unreachable!("the branch above tested for a zstd encoder"),
                };
                encoder.write_all(buf)?;
                // Take whatever the codec has emitted so far and hand it to the real sink.
                std::mem::take(encoder.get_mut())
            };
            if !produced.is_empty() {
                self.writer.write_all(&produced)?;
                state.compressed += produced.len() as u64;
            }
            if let Some(error) = self.zip64_overflow(state) {
                return Err(self.fail(error));
            }
            return Ok(buf.len());
        }

        let mut remaining = buf;
        while !remaining.is_empty() {
            let (consumed, written, status) = {
                let compressor = match &mut state.encoder {
                    Encoder::Deflate(compressor) => compressor.as_mut(),
                    _ => unreachable!("only deflate entries reach this loop"),
                };
                let result = deflate(compressor, remaining, &mut state.out_buf, MZFlush::None);
                (result.bytes_consumed, result.bytes_written, result.status)
            };

            if written > 0 {
                self.writer.write_all(&state.out_buf[..written])?;
                state.compressed += written as u64;
            }

            if let Err(error) = status {
                if consumed == 0 && written == 0 {
                    return Err(self.fail(Error::Compression {
                        detail: format!("{error:?}"),
                    }));
                }
            }
            if consumed == 0 && written == 0 {
                // No progress with input still available means the compressor is stuck.
                return Err(self.fail(Error::Compression {
                    detail: "compressor made no progress".to_string(),
                }));
            }
            remaining = &remaining[consumed..];
        }

        if let Some(error) = self.zip64_overflow(state) {
            return Err(self.fail(error));
        }
        Ok(buf.len())
    }

    /// Flush the compressor and patch the entry's local header.
    ///
    /// Any failure latches the writer, because a partially written entry cannot be repaired.
    fn end_entry(&mut self) -> Result<()> {
        let result = self.end_entry_inner();
        if let Err(error) = &result {
            if self.pending_error.is_none() {
                self.pending_error = Some(copy_as_io_error(error));
            }
        }
        result
    }

    fn end_entry_inner(&mut self) -> Result<()> {
        let mut state = match self.current.take() {
            Some(state) => state,
            None => return Ok(()),
        };

        // Nothing can be recovered once the stream is inconsistent, so leave the header as it
        // is rather than patching nonsense into it.
        if self.pending_error.is_some() {
            return Ok(());
        }

        // Take the encoder out: finishing consumes it, and each kind finishes differently. The
        // placeholder is never read ??the entry is complete after this.
        match std::mem::replace(&mut state.encoder, Encoder::Stored) {
            Encoder::Stored => {}
            Encoder::Deflate(mut compressor) => loop {
                let (written, status) = {
                    let result = deflate(
                        compressor.as_mut(),
                        &[],
                        &mut state.out_buf,
                        MZFlush::Finish,
                    );
                    (result.bytes_written, result.status)
                };
                if written > 0 {
                    self.writer
                        .write_all(&state.out_buf[..written])
                        .map_err(Error::Io)?;
                    state.compressed += written as u64;
                }
                match status {
                    Ok(MZStatus::StreamEnd) => break,
                    Ok(_) if written > 0 => continue,
                    Ok(_) => {
                        return Err(Error::Compression {
                            detail: "compressor stalled while finishing".to_string(),
                        })
                    }
                    Err(error) => {
                        return Err(Error::Compression {
                            detail: format!("{error:?}"),
                        })
                    }
                }
            },
            #[cfg(feature = "zstd")]
            Encoder::Zstd(encoder) => {
                // Finishing the frame hands back everything still buffered, including the
                // frame's own trailing bytes.
                let tail = encoder.finish().map_err(Error::Io)?;
                if !tail.is_empty() {
                    self.writer.write_all(&tail).map_err(Error::Io)?;
                    state.compressed += tail.len() as u64;
                }
            }
        }

        if let Some(error) = self.zip64_overflow(&state) {
            return Err(error);
        }

        let crc32 = state.crc.clone().finalize();
        let data_end = self.writer.stream_position().map_err(Error::Io)?;

        // Patch the CRC-32 and sizes in the local file header.
        let mut patch = Vec::with_capacity(12);
        patch.extend_from_slice(&crc32.to_le_bytes());
        patch.extend_from_slice(&local_size(state.compressed, state.zip64_sizes).to_le_bytes());
        patch.extend_from_slice(&local_size(state.uncompressed, state.zip64_sizes).to_le_bytes());
        self.writer
            .seek(SeekFrom::Start(state.header_offset + 14))
            .map_err(Error::Io)?;
        self.writer.write_all(&patch).map_err(Error::Io)?;

        if state.zip64_sizes {
            // Fill in the ZIP64 extra field that `begin_entry` reserved.
            let extra =
                state.header_offset + LOCAL_HEADER_LEN as u64 + state.encoded_name.len() as u64;
            let mut sizes = [0u8; 16];
            sizes[..8].copy_from_slice(&state.uncompressed.to_le_bytes());
            sizes[8..].copy_from_slice(&state.compressed.to_le_bytes());
            self.writer
                .seek(SeekFrom::Start(extra + 4))
                .map_err(Error::Io)?;
            self.writer.write_all(&sizes).map_err(Error::Io)?;
        }

        self.writer
            .seek(SeekFrom::Start(data_end))
            .map_err(Error::Io)?;

        let made_by_version = if state.zip64_sizes || state.zip64_offset {
            45u16
        } else {
            20u16
        };
        self.records.push(CentralRecord {
            name: state.encoded_name,
            flags: state.flags,
            method: state.method,
            dos_date: state.dos_date,
            dos_time: state.dos_time,
            crc32,
            compressed_size: state.compressed,
            uncompressed_size: state.uncompressed,
            header_offset: state.header_offset,
            external_attrs: state.external_attrs,
            comment: state.comment,
            zip64_sizes: state.zip64_sizes,
            zip64_offset: state.zip64_offset,
            version_made_by: version_made_by(made_by_version),
        });
        Ok(())
    }

    fn write_central_directory(&mut self) -> Result<()> {
        // Validate everything that can be checked before anything is written, so the common
        // failure modes leave `records` untouched and the writer recoverable.
        let comment = self
            .options
            .comment
            .as_ref()
            .map(|c| c.as_bytes().to_vec())
            .unwrap_or_default();
        if comment.len() > u16::MAX as usize {
            return Err(Error::malformed("archive comment too long"));
        }

        // Take the records, but put them back if the sink refuses partway through: losing them
        // would let a retry emit an end-of-central-directory claiming zero entries.
        let records = std::mem::take(&mut self.records);
        let result = self.write_central_directory_inner(&records, &comment);
        if result.is_err() {
            self.records = records;
        }
        result
    }

    fn write_central_directory_inner(
        &mut self,
        records: &[CentralRecord],
        comment: &[u8],
    ) -> Result<()> {
        let cd_offset = self.writer.stream_position().map_err(Error::Io)?;
        let mut cd_size = 0u64;
        for record in records {
            cd_size += self.write_central_record(record)?;
        }
        let count = records.len() as u64;

        if count > u16::MAX as u64 || needs_zip64(cd_offset) || needs_zip64(cd_size) {
            let zip64_eocd_offset = self.writer.stream_position().map_err(Error::Io)?;

            let mut record = Vec::with_capacity(ZIP64_EOCD_MIN_LEN);
            record.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
            record.extend_from_slice(&44u64.to_le_bytes());
            record.extend_from_slice(&version_made_by(45).to_le_bytes());
            record.extend_from_slice(&45u16.to_le_bytes());
            record.extend_from_slice(&0u32.to_le_bytes()); // this disk
            record.extend_from_slice(&0u32.to_le_bytes()); // disk with central directory
            record.extend_from_slice(&count.to_le_bytes());
            record.extend_from_slice(&count.to_le_bytes());
            record.extend_from_slice(&cd_size.to_le_bytes());
            record.extend_from_slice(&cd_offset.to_le_bytes());
            self.writer.write_all(&record).map_err(Error::Io)?;

            let mut locator = Vec::with_capacity(ZIP64_LOCATOR_LEN);
            locator.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
            locator.extend_from_slice(&0u32.to_le_bytes());
            locator.extend_from_slice(&zip64_eocd_offset.to_le_bytes());
            locator.extend_from_slice(&1u32.to_le_bytes());
            self.writer.write_all(&locator).map_err(Error::Io)?;
        }

        let count16 = if count > u16::MAX as u64 {
            u16::MAX
        } else {
            count as u16
        };
        let size32 = if needs_zip64(cd_size) {
            u32::MAX
        } else {
            cd_size as u32
        };
        let offset32 = if needs_zip64(cd_offset) {
            u32::MAX
        } else {
            cd_offset as u32
        };

        let mut eocd = Vec::with_capacity(EOCD_LEN + comment.len());
        eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // this disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with central directory
        eocd.extend_from_slice(&count16.to_le_bytes());
        eocd.extend_from_slice(&count16.to_le_bytes());
        eocd.extend_from_slice(&size32.to_le_bytes());
        eocd.extend_from_slice(&offset32.to_le_bytes());
        eocd.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        eocd.extend_from_slice(comment);
        self.writer.write_all(&eocd).map_err(Error::Io)?;
        Ok(())
    }

    /// Returns the number of bytes written.
    fn write_central_record(&mut self, record: &CentralRecord) -> Result<u64> {
        let sizes_need_zip64 = record.zip64_sizes;
        let offset_needs_zip64 = record.zip64_offset;

        // Backstop: a size that overflowed 32 bits without a reserved ZIP64 field would
        // silently truncate, so refuse instead.
        if (!sizes_need_zip64
            && (needs_zip64(record.uncompressed_size) || needs_zip64(record.compressed_size)))
            || (!offset_needs_zip64 && needs_zip64(record.header_offset))
        {
            return Err(Error::Zip64Required {
                entry: String::from_utf8_lossy(&record.name).into_owned(),
            });
        }

        // The ZIP64 extra field carries only the values that are sentinels, in spec order:
        // uncompressed size, compressed size, then local header offset.
        let mut extra = Vec::new();
        let zip64_len = usize::from(sizes_need_zip64) * 16 + usize::from(offset_needs_zip64) * 8;
        if zip64_len > 0 {
            extra.extend_from_slice(&EXTRA_ZIP64.to_le_bytes());
            extra.extend_from_slice(&(zip64_len as u16).to_le_bytes());
            if sizes_need_zip64 {
                extra.extend_from_slice(&record.uncompressed_size.to_le_bytes());
                extra.extend_from_slice(&record.compressed_size.to_le_bytes());
            }
            if offset_needs_zip64 {
                extra.extend_from_slice(&record.header_offset.to_le_bytes());
            }
        }

        let version = if sizes_need_zip64 || offset_needs_zip64 {
            45u16
        } else {
            20u16
        };

        let mut out = Vec::with_capacity(
            CENTRAL_DIR_LEN + record.name.len() + extra.len() + record.comment.len(),
        );
        out.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        out.extend_from_slice(&record.version_made_by.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&record.flags.to_le_bytes());
        out.extend_from_slice(&record.method.to_le_bytes());
        out.extend_from_slice(&record.dos_time.to_le_bytes());
        out.extend_from_slice(&record.dos_date.to_le_bytes());
        out.extend_from_slice(&record.crc32.to_le_bytes());
        out.extend_from_slice(&local_size(record.compressed_size, sizes_need_zip64).to_le_bytes());
        out.extend_from_slice(
            &local_size(record.uncompressed_size, sizes_need_zip64).to_le_bytes(),
        );
        out.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&(record.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        out.extend_from_slice(&record.external_attrs.to_le_bytes());
        out.extend_from_slice(&local_size(record.header_offset, offset_needs_zip64).to_le_bytes());
        out.extend_from_slice(&record.name);
        out.extend_from_slice(&extra);
        out.extend_from_slice(&record.comment);

        self.writer.write_all(&out).map_err(Error::Io)?;
        Ok(out.len() as u64)
    }

    fn zip64_overflow(&self, state: &EntryState) -> Option<Error> {
        if !state.zip64_sizes && (needs_zip64(state.uncompressed) || needs_zip64(state.compressed))
        {
            Some(Error::Zip64Required {
                entry: state.name.clone(),
            })
        } else {
            None
        }
    }

    fn fail(&mut self, error: Error) -> io::Error {
        let message = error.to_string();
        self.pending_error = Some(error);
        io::Error::new(io::ErrorKind::Other, message)
    }

    fn pending_error_detail(&self) -> String {
        self.pending_error
            .as_ref()
            .map(|error| error.to_string())
            .unwrap_or_default()
    }

    /// The latched failure as an `io::Error`, without clearing it.
    fn latched_io_error(&self) -> Option<io::Error> {
        self.pending_error
            .as_ref()
            .map(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))
    }

    /// A copy of the latched failure, without clearing it.
    fn pending_error_copy(&self) -> Option<Error> {
        self.pending_error.as_ref().map(copy_as_io_error)
    }
}

/// Rebuild an [`Error`] as an [`Error::Io`] copy. `Error` is not `Clone` (it can hold an
/// `io::Error`), and a copy is what lets the latch survive being reported.
fn copy_as_io_error(error: &Error) -> Error {
    match error {
        Error::Io(source) => Error::Io(io::Error::new(source.kind(), source.to_string())),
        other => Error::Io(io::Error::new(io::ErrorKind::Other, other.to_string())),
    }
}

/// A handle for writing one entry's contents.
///
/// Dropping the handle finishes the entry, so a forgotten `finish` still produces a valid
/// archive; use [`ZipWriterEntry::finish`] when you want to observe the result.
pub struct ZipWriterEntry<'a, W: Write + Seek> {
    zip: &'a mut ZipWriter<W>,
}

impl<W: Write + Seek> std::fmt::Debug for ZipWriterEntry<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipWriterEntry")
            .field(
                "name",
                &self.zip.current.as_ref().map(|state| state.name.as_str()),
            )
            .finish_non_exhaustive()
    }
}

impl<W: Write + Seek> ZipWriterEntry<'_, W> {
    /// Close the entry, flushing the compressor and patching the local file header.
    pub fn finish(self) -> Result<()> {
        self.zip.end_entry()
    }
}

impl<W: Write + Seek> Write for ZipWriterEntry<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.zip.entry_write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.zip.writer.flush()
    }
}

impl<W: Write + Seek> Drop for ZipWriterEntry<'_, W> {
    fn drop(&mut self) {
        if let Err(error) = self.zip.end_entry() {
            self.zip.pending_error.get_or_insert(error);
        }
    }
}

/// Reject a name that does not fit the 16-bit length field.
///
/// The cast would otherwise truncate silently, and since the header's own `name_len` field then
/// disagrees with the bytes actually written, every reader would look for the payload at the
/// wrong offset — including this crate's.
fn check_name_len(name: &[u8]) -> Result<()> {
    if name.len() > u16::MAX as usize {
        return Err(Error::malformed(format!(
            "entry name is {} bytes, which does not fit the ZIP format's 16-bit name length",
            name.len()
        )));
    }
    Ok(())
}

/// A size field value, or the ZIP64 sentinel when the value is carried in the extra field.
fn local_size(value: u64, zip64: bool) -> u32 {
    if zip64 {
        u32::MAX
    } else {
        value as u32
    }
}

/// `version made by`: host system 3 (Unix) with the given version number.
fn version_made_by(version: u16) -> u16 {
    (u16::from(HOST_UNIX) << 8) | version
}

fn new_compressor(level: u8) -> Box<CompressorOxide> {
    let mut compressor =
        CompressorOxide::with_format_and_level(DataFormat::Raw, CompressionLevel::DefaultLevel);
    compressor.set_compression_level_raw(level.min(10));
    Box::new(compressor)
}

/// Map the deflate-style `compression_level` (0..=10) onto zstd's range.
///
/// The knob is documented as a deflate level and zstd's scale is different (1..=22), so it is
/// scaled rather than passed through ??"more" should still mean "more".
#[cfg(feature = "zstd")]
fn zstd_level(level: u8) -> i32 {
    let level = i32::from(level.min(10));
    (1 + level * 21 / 10).clamp(1, 22)
}
