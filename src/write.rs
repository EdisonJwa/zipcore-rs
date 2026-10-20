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
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Staging buffer for compressed output.
pub(crate) const OUT_BUF_SIZE: usize = 64 * 1024;

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
    /// Password used for entries whose [`FileOptions::encryption`] is set.
    ///
    /// Required when any entry is encrypted; writing one without it fails rather than falling
    /// back to an empty password.
    pub password: Option<Vec<u8>>,
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
            password: None,
            allow_unsafe_names: false,
        }
    }
}

/// How to encrypt an entry.
///
/// Both schemes are readable by other tools. They are not equally safe, and the difference is not
/// subtle:
///
/// | | `ZipCrypto` | `Aes256` |
/// |---|---|---|
/// | Dependencies | none | `aes-crypto` feature |
/// | Confidentiality | **broken** (known-plaintext attack) | sound |
/// | Authentication | none (CRC-32 only) | HMAC-SHA1 |
/// | Use for | reading legacy archives, compatibility | anything that matters |
///
/// `ZipCrypto` is offered because a great many old archives use it and refusing to read them is
/// unhelpful. It is *not* a way to protect data. Prefer [`Encryption::Aes256`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Encryption {
    /// Traditional PKWARE encryption. Insecure; for compatibility only.
    ZipCrypto,
    /// WinZip AES-256 (AE-2). Requires the `aes-crypto` feature.
    Aes256,
    /// WinZip AES-128 (AE-2). Requires the `aes-crypto` feature.
    Aes128,
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
    /// Encrypt this entry with the given scheme.
    ///
    /// `None` writes a plain entry. See [`Encryption`] for the trade-off between the two schemes.
    pub encryption: Option<Encryption>,
    /// Modification time in Unix seconds, written as an extended-timestamp (`0x5455`) field.
    ///
    /// When set, this is what readers that understand the field will report, and it keeps
    /// one-second resolution instead of DOS's two-second rounding. The DOS field is still
    /// written (derived from this value) so tools that ignore the extra field see approximately
    /// the right time.
    pub unix_mtime: Option<u64>,
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
            unix_mtime: None,
            encryption: None,
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
    /// Record a modification time in Unix seconds, written as an extended-timestamp field.
    ///
    /// Prefer this over [`FileOptions::with_dos_timestamp`]: DOS time cannot represent an
    /// arbitrary instant (two-second resolution, no timezone), so a round trip through it
    /// silently changes the value.
    pub fn with_unix_mtime(mut self, seconds: Option<u64>) -> Self {
        self.unix_mtime = seconds;
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
pub(crate) struct CentralRecord {
    pub(crate) name: Vec<u8>,
    pub(crate) flags: u16,
    pub(crate) method: u16,
    pub(crate) dos_date: u16,
    pub(crate) dos_time: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) header_offset: u64,
    pub(crate) external_attrs: u32,
    pub(crate) comment: Vec<u8>,
    pub(crate) zip64_sizes: bool,
    pub(crate) zip64_offset: bool,
    /// Host and version byte, preserved verbatim when copying an entry.
    pub(crate) version_made_by: u16,
    /// Unix modification time carried in the extended-timestamp extra field, if any.
    pub(crate) unix_mtime: Option<u64>,
    /// WinZip AES metadata: (vendor version, strength byte, real method). Written back into the
    /// `0x9901` extra field of the central record.
    pub(crate) aes: Option<(u16, u8, u16)>,
}

pub(crate) enum Encoder {
    Stored,
    /// miniz_oxide DEFLATE, the default backend.
    #[cfg_attr(feature = "deflate-zlib-rs", allow(dead_code))]
    Deflate(Box<CompressorOxide>),
    /// zlib-rs DEFLATE behind `flate2`, used when the `deflate-zlib-rs` feature is on.
    #[cfg(feature = "deflate-zlib-rs")]
    DeflateZlib(flate2::write::DeflateEncoder<Vec<u8>>),
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
    unix_mtime: Option<u64>,
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
    /// (vendor version, strength, real method) when the entry is WinZip AES encrypted.
    aes: Option<(u16, u8, u16)>,
    /// Set when the entry is encrypted. Payload bytes are accumulated here instead of going to the
    /// sink, because AES puts its authentication code *after* the data and the size fields must be
    /// known before the header can be patched.
    pending: Option<Pending>,
}

/// Encryption state for the entry currently being written.
struct Pending {
    scheme: Encryption,
    /// Compressed-but-not-yet-encrypted payload.
    payload: Vec<u8>,
}

/// Builds a ZIP archive.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::Write;
///
/// let file = std::fs::File::create("out.zip")?;
/// let mut writer = zipcore::ZipWriter::new(std::io::BufWriter::new(file))?;
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
    /// A compressor recycled from the previous entry.
    ///
    /// `CompressorOxide` owns a 32 KiB window plus Huffman tables, so allocating one per entry
    /// costs real time on archives with many small members. `reset` makes the allocation
    /// reusable, and this holds it between entries.
    spare_compressor: Option<Box<CompressorOxide>>,
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
    ///
    /// Fails if the sink already contains bytes: starting a fresh archive there would overwrite
    /// or orphan whatever is already written. Use [`ZipWriter::new_append`] to add entries to an
    /// existing archive instead.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(writer: W) -> Result<Self> {
        Self::new_with_options(writer, WriteOptions::default())
    }

    /// Create a writer with explicit archive-level options.
    ///
    /// Fails if the sink is not empty ??see [`ZipWriter::new`].
    pub fn new_with_options(mut writer: W, options: WriteOptions) -> Result<Self> {
        // Refuse to scribble over an existing archive. This used to be a `Self` and would
        // silently destroy everything already in the sink.
        let len = writer.seek(SeekFrom::End(0)).map_err(Error::Io)?;
        if len != 0 {
            return Err(Error::malformed(format!(
                "the sink already holds {len} bytes; use ZipWriter::new_append to add to an \
                 existing archive or truncate the sink first"
            )));
        }
        Ok(Self {
            writer,
            options,
            records: Vec::new(),
            current: None,
            finished: false,
            pending_error: None,
            spare_compressor: None,
        })
    }

    /// Create a writer that appends to the archive already in `writer`.
    ///
    /// The existing central directory is parsed and rewritten after the new entries, so the
    /// result is one archive containing the old entries followed by the new ones. The previous
    /// end-of-central-directory record and central directory are left in the bytes but are no
    /// longer referenced, which is what every other ZIP implementation does too.
    ///
    /// Fails if `writer` does not hold a readable archive, or if it is encrypted or uses a
    /// feature this crate cannot parse.
    pub fn new_append<R>(mut writer: W, mut source: R) -> Result<Self>
    where
        R: std::io::Read + Seek,
    {
        // Parse the source to recover its records, then re-serialise them at finish time.
        let archive = crate::Archive::new(&mut source)?;
        let mut records = Vec::with_capacity(archive.len());
        for entry in archive.entries() {
            records.push(central_record_from_entry(entry)?);
        }

        // Append at the point the old central directory started, so the orphaned records are
        // overwritten rather than accumulated on every append.
        let offset = archive.central_directory_offset();
        writer.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;

        Ok(Self {
            writer,
            options: WriteOptions::default(),
            records,
            current: None,
            finished: false,
            pending_error: None,
            spare_compressor: None,
        })
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

    /// Write a symbolic link entry whose content is `target`.
    ///
    /// The entry is recorded with the Unix `S_IFLNK` file type so extractors that understand it
    /// recreate a link instead of a regular file. [`Archive::extract_all`](crate::Archive::extract_all)
    /// deliberately refuses to materialise it, and reports it in
    /// [`ExtractReport::skipped_symlinks`](crate::ExtractReport::skipped_symlinks).
    ///
    /// This is a Unix-shaped entry: it sets the external attributes accordingly, which other
    /// platforms ignore. No compression is applied, matching what `zip -y` produces.
    pub fn add_symlink(&mut self, name: &str, target: &str, options: &FileOptions) -> Result<()> {
        if target.is_empty() {
            return Err(Error::malformed("a symbolic link needs a non-empty target"));
        }
        // Link targets are stored verbatim; refusing a NUL keeps the entry readable.
        if target.contains('\0') {
            return Err(Error::malformed(
                "a symbolic link target must not contain a NUL byte",
            ));
        }
        let options = FileOptions {
            compression: Compression::Stored,
            unix_mode: Some(options.unix_mode.unwrap_or(0o120_777)),
            ..options.clone()
        };
        self.add_file(name, target.as_bytes(), &options)
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
            unix_mtime: entry.unix_mtime,
            aes: entry
                .aes
                .map(|info| (info.vendor_version, info.strength, info.actual_method)),
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
        if options.encryption.is_some() {
            flags |= FLAG_ENCRYPTED;
        }
        // WinZip AES is announced by method 99 in the headers, with the real method moved into
        // the 0x9901 extra field. ZipCrypto keeps the real method in place.
        let is_aes = matches!(
            options.encryption,
            Some(Encryption::Aes256) | Some(Encryption::Aes128)
        );
        // The method actually used inside the payload; AES moves it into the extra field and puts
        // 99 in the header instead.
        let real_method = method;
        let method = if is_aes {
            crate::spec::METHOD_WINZIP_AES
        } else {
            method
        };

        // A recorded Unix mtime wins for the DOS field too, so tools that ignore the extended
        // field still show approximately the right time.
        let (dos_date, dos_time) = match (options.unix_mtime, options.dos_timestamp) {
            (Some(unix), _) => dos::from_unix_seconds(unix),
            (None, Some(explicit)) => explicit,
            (None, None) => dos::now(),
        };

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
        // An extended-timestamp field is 4 bytes of header plus a flags byte and one u32.
        let timestamp_extra_len = if options.unix_mtime.is_some() {
            4 + EXTRA_TIMESTAMP_MTIME_LEN
        } else {
            0
        };
        let aes_extra_len = if is_aes {
            4 + crate::spec::EXTRA_WINZIP_AES_LEN
        } else {
            0
        };
        let extra_len = element_extra_len(zip64_sizes) + timestamp_extra_len + aes_extra_len;
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
        if let Some(unix) = options.unix_mtime {
            header.extend_from_slice(&EXTRA_EXTENDED_TIMESTAMP.to_le_bytes());
            header.extend_from_slice(&(EXTRA_TIMESTAMP_MTIME_LEN as u16).to_le_bytes());
            header.push(EXTENDED_TIMESTAMP_FLAG_MTIME);
            header.extend_from_slice(&(unix as u32).to_le_bytes());
        }
        if is_aes {
            header.extend_from_slice(&crate::spec::EXTRA_WINZIP_AES.to_le_bytes());
            header.extend_from_slice(&(crate::spec::EXTRA_WINZIP_AES_LEN as u16).to_le_bytes());
            header.extend_from_slice(&2u16.to_le_bytes()); // vendor version: AE-2
            header.extend_from_slice(b"AE"); // vendor id
            header.push(if options.encryption == Some(Encryption::Aes128) {
                1
            } else {
                3
            });
            header.extend_from_slice(&real_method.to_le_bytes());
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
                Compression::Deflate => {
                    #[cfg(not(feature = "deflate-zlib-rs"))]
                    {
                        Encoder::Deflate(take_compressor(
                            &mut self.spare_compressor,
                            options.compression_level,
                        ))
                    }
                    #[cfg(feature = "deflate-zlib-rs")]
                    {
                        new_deflate_encoder(options.compression_level)
                    }
                }
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
            unix_mtime: options.unix_mtime,
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
            aes: if is_aes {
                Some((
                    2,
                    if options.encryption == Some(Encryption::Aes128) {
                        1
                    } else {
                        3
                    },
                    real_method,
                ))
            } else {
                None
            },
            pending: options.encryption.map(|scheme| Pending {
                scheme,
                payload: Vec::new(),
            }),
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

    /// Hand compressed payload bytes onward: buffered when the entry is encrypted, straight to the
    /// sink otherwise.
    fn emit(&mut self, state: &mut EntryState, data: &[u8]) -> io::Result<()> {
        match &mut state.pending {
            Some(pending) => {
                pending.payload.extend_from_slice(data);
                Ok(())
            }
            None => {
                self.writer.write_all(data)?;
                state.compressed += data.len() as u64;
                Ok(())
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
            self.emit(state, buf)?;
            return Ok(buf.len());
        }

        #[cfg(feature = "deflate-zlib-rs")]
        if matches!(state.encoder, Encoder::DeflateZlib(_)) {
            let produced = {
                let encoder = match &mut state.encoder {
                    Encoder::DeflateZlib(encoder) => encoder,
                    _ => unreachable!("the branch above tested for a zlib deflate encoder"),
                };
                encoder.write_all(buf)?;
                std::mem::take(encoder.get_mut())
            };
            if !produced.is_empty() {
                self.emit(state, &produced)?;
            }
            if let Some(error) = self.zip64_overflow(state) {
                return Err(self.fail(error));
            }
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
                self.emit(state, &produced)?;
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
                    _ => unreachable!("only miniz deflate entries reach this loop"),
                };
                let result = deflate(compressor, remaining, &mut state.out_buf, MZFlush::None);
                (result.bytes_consumed, result.bytes_written, result.status)
            };

            if written > 0 {
                let chunk = state.out_buf[..written].to_vec();
                self.emit(state, &chunk)?;
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
            Encoder::Deflate(mut compressor) => {
                loop {
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
                        let chunk = state.out_buf[..written].to_vec();
                        self.emit(&mut state, &chunk).map_err(Error::Io)?;
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
                }
                // Keep the finished compressor for the next entry instead of dropping its window.
                self.spare_compressor = Some(compressor);
            }
            #[cfg(feature = "deflate-zlib-rs")]
            Encoder::DeflateZlib(encoder) => {
                let tail = encoder.finish().map_err(Error::Io)?;
                if !tail.is_empty() {
                    self.emit(&mut state, &tail).map_err(Error::Io)?;
                }
            }
            #[cfg(feature = "zstd")]
            Encoder::Zstd(encoder) => {
                // Finishing the frame hands back everything still buffered, including the
                // frame's own trailing bytes.
                let tail = encoder.finish().map_err(Error::Io)?;
                if !tail.is_empty() {
                    self.emit(&mut state, &tail).map_err(Error::Io)?;
                }
            }
        }

        // Encrypt the buffered payload now that its size is known, then emit it in one piece.
        if let Some(pending) = state.pending.take() {
            let sealed = self.seal_entry(&state, pending)?;
            state.compressed = sealed.len() as u64;
            self.writer.write_all(&sealed).map_err(Error::Io)?;
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
            unix_mtime: state.unix_mtime,
            aes: state.aes,
        });
        Ok(())
    }

    /// Encrypt a finished compressed payload according to the entry's chosen scheme.
    ///
    /// Returns the exact bytes to write: for ZipCrypto the 12-byte header prepended to the
    /// ciphertext; for AES the salt, verifier, ciphertext and trailing HMAC.
    fn seal_entry(&self, state: &EntryState, pending: Pending) -> Result<Vec<u8>> {
        let password = match (pending.scheme, &self.options.password) {
            (_, Some(password)) => password.as_slice(),
            // An empty password would silently produce an archive the caller cannot open.
            (scheme, None) => {
                return Err(Error::malformed(format!(
                    "entry `{}` is marked for {:?} encryption but WriteOptions::password is unset",
                    state.name, scheme
                )))
            }
        };

        // The header carries the real CRC-32 unless the data descriptor flag is set, in which case
        // the high byte of the DOS time is used instead.
        let check = if state.flags & FLAG_DATA_DESCRIPTOR != 0 {
            crate::crypto::zipcrypto::CheckByte::DosTime(state.dos_time)
        } else {
            crate::crypto::zipcrypto::CheckByte::Crc(state.crc.clone().finalize())
        };

        match pending.scheme {
            Encryption::ZipCrypto => {
                let mut entropy = [0u8; crate::crypto::zipcrypto::HEADER_LEN - 1];
                fill_random(&mut entropy)?;
                Ok(crate::crypto::zipcrypto::encrypt(
                    password,
                    check,
                    &entropy,
                    &pending.payload,
                ))
            }
            Encryption::Aes256 | Encryption::Aes128 => {
                #[cfg(feature = "aes-crypto")]
                {
                    let strength = if pending.scheme == Encryption::Aes256 {
                        crate::crypto::aes::Strength::Bits256
                    } else {
                        crate::crypto::aes::Strength::Bits128
                    };
                    let mut salt = vec![0u8; strength.salt_len()];
                    fill_random(&mut salt)?;
                    crate::crypto::aes::encrypt(password, strength, &salt, &pending.payload)
                }
                #[cfg(not(feature = "aes-crypto"))]
                {
                    Err(Error::malformed(
                        "writing AES entries requires the `aes-crypto` feature",
                    ))
                }
            }
        }
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
    pub(crate) fn write_central_record(&mut self, record: &CentralRecord) -> Result<u64> {
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
        // The extended-timestamp field goes in the central record too, so a reader that only
        // looks at the directory still sees the precise time.
        if let Some((vendor_version, strength, real_method)) = record.aes {
            extra.extend_from_slice(&crate::spec::EXTRA_WINZIP_AES.to_le_bytes());
            extra.extend_from_slice(&(crate::spec::EXTRA_WINZIP_AES_LEN as u16).to_le_bytes());
            extra.extend_from_slice(&vendor_version.to_le_bytes());
            extra.extend_from_slice(b"AE");
            extra.push(strength);
            extra.extend_from_slice(&real_method.to_le_bytes());
        }
        if let Some(unix) = record.unix_mtime {
            extra.extend_from_slice(&EXTRA_EXTENDED_TIMESTAMP.to_le_bytes());
            extra.extend_from_slice(&(EXTRA_TIMESTAMP_MTIME_LEN as u16).to_le_bytes());
            extra.push(EXTENDED_TIMESTAMP_FLAG_MTIME);
            extra.extend_from_slice(&(unix as u32).to_le_bytes());
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

/// Rebuild the writer-side record for an entry read from an existing archive.
///
/// Used by [`ZipWriter::new_append`]: the container is re-emitted from the parsed central
/// directory, so the values must survive the round trip exactly ??including whether the original
/// used ZIP64 sentinels, since a record that carried one must keep carrying it.
fn central_record_from_entry(entry: &Entry) -> Result<CentralRecord> {
    let name = entry.name_raw().to_vec();
    check_name_len(&name)?;
    let comment = entry
        .comment()
        .map(|comment| comment.as_bytes().to_vec())
        .unwrap_or_default();
    if comment.len() > u16::MAX as usize {
        return Err(Error::malformed("entry comment too long"));
    }
    let (dos_date, dos_time) = entry.dos_timestamp();
    let compressed = entry.compressed_size();
    let uncompressed = entry.uncompressed_size();
    let offset = entry.header_offset();
    Ok(CentralRecord {
        name,
        flags: entry.flags() & !FLAG_DATA_DESCRIPTOR,
        method: entry.method(),
        dos_date,
        dos_time,
        crc32: entry.crc32(),
        compressed_size: compressed,
        uncompressed_size: uncompressed,
        header_offset: offset,
        external_attrs: entry.external_attrs(),
        comment,
        zip64_sizes: needs_zip64(compressed) || needs_zip64(uncompressed),
        zip64_offset: needs_zip64(offset),
        version_made_by: entry.version_made_by(),
        unix_mtime: entry.unix_mtime(),
        aes: entry
            .aes
            .map(|info| (info.vendor_version, info.strength, info.actual_method)),
    })
}

/// Reject a name that does not fit the 16-bit length field.
///
/// The cast would otherwise truncate silently, and since the header's own `name_len` field then
/// disagrees with the bytes actually written, every reader would look for the payload at the
/// wrong offset ??including this crate's.
pub(crate) fn check_name_len(name: &[u8]) -> Result<()> {
    if name.len() > u16::MAX as usize {
        return Err(Error::malformed(format!(
            "entry name is {} bytes, which does not fit the ZIP format's 16-bit name length",
            name.len()
        )));
    }
    Ok(())
}

/// Bytes the ZIP64 extended-information field occupies when the sizes need it.
///
/// Header (4) plus two 8-byte sizes. Kept as a function so the local header and the central
/// record cannot drift apart.
fn element_extra_len(zip64_sizes: bool) -> usize {
    if zip64_sizes {
        4 + 16
    } else {
        0
    }
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
pub(crate) fn version_made_by(version: u16) -> u16 {
    (u16::from(HOST_UNIX) << 8) | version
}

/// Fill `buf` with cryptographically secure random bytes.
///
/// Used for the ZipCrypto header and the WinZip AES salt. A weak source here would be a real
/// defect, so it comes from the OS rather than a userspace generator.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    // `getrandom` 0.2 spells this `getrandom`; 0.4 renamed it to `fill`. 0.2 is kept deliberately:
    // it is the newest release that does not require Rust 1.85, and the crate advertises 1.70.
    getrandom::getrandom(buf).map_err(|error| {
        Error::malformed(format!("the system random source is unavailable: {error}"))
    })
}

/// Drive the shared encoder once and return the bytes it produced.
///
/// Used by the streaming writer so that the DEFLATE backend selection (miniz_oxide or zlib-rs)
/// lives in exactly one place.
pub(crate) fn drive_encoder(
    encoder: &mut Encoder,
    out: &mut [u8],
    data: &[u8],
    finish: bool,
) -> Result<Vec<u8>> {
    let flush = if finish {
        MZFlush::Finish
    } else {
        MZFlush::None
    };
    match encoder {
        Encoder::Stored => Ok(data.to_vec()),
        #[cfg_attr(feature = "deflate-zlib-rs", allow(unreachable_patterns))]
        Encoder::Deflate(compressor) => {
            let mut produced = Vec::new();
            let mut remaining = data;
            loop {
                let result = deflate(compressor.as_mut(), remaining, out, flush);
                produced.extend_from_slice(&out[..result.bytes_written]);
                remaining = &remaining[result.bytes_consumed..];
                match result.status {
                    // Complete, or the 64 KiB output buffer filled: both mean "drain and call
                    // again", and the input position we track tells us when to stop.
                    Ok(MZStatus::StreamEnd) => break,
                    Ok(_) | Err(MZError::Buf) => {
                        if !finish && remaining.is_empty() {
                            break;
                        }
                        if result.bytes_written == 0 && result.bytes_consumed == 0 {
                            break;
                        }
                    }
                    Err(error) => {
                        return Err(Error::Compression {
                            detail: format!("{error:?}"),
                        })
                    }
                }
            }
            Ok(produced)
        }
        #[cfg(feature = "deflate-zlib-rs")]
        Encoder::DeflateZlib(encoder) => {
            if !data.is_empty() {
                encoder.write_all(data).map_err(Error::Io)?;
            }
            if finish {
                // `finish` consumes the encoder, but it is borrowed here; `try_finish` flushes and
                // writes the trailer while leaving the value in place, which is all we need.
                encoder.try_finish().map_err(Error::Io)?;
            }
            Ok(std::mem::take(encoder.get_mut()))
        }
        #[cfg(feature = "zstd")]
        Encoder::Zstd(encoder) => {
            if !data.is_empty() {
                encoder.write_all(data).map_err(Error::Io)?;
            }
            if finish {
                // Same borrow problem as the zlib arm: flush the frame in place instead of
                // consuming the encoder.
                encoder.do_finish().map_err(Error::Io)?;
            }
            Ok(std::mem::take(encoder.get_mut()))
        }
    }
}

/// Write the central directory, ZIP64 records and end-of-central-directory.
///
/// Shared by the seekable and streaming writers, which differ only in how entry headers are
/// produced. `cd_offset` is the byte position where the central directory begins.
pub(crate) fn write_archive_trailer<W: Write>(
    sink: &mut W,
    records: &[CentralRecord],
    comment: Option<Vec<u8>>,
    cd_offset: u64,
) -> Result<()> {
    let comment = comment.unwrap_or_default();
    if comment.len() > u16::MAX as usize {
        return Err(Error::malformed("archive comment too long"));
    }

    let mut cd = Vec::new();
    for record in records {
        write_central_record_into(&mut cd, record)?;
    }
    sink.write_all(&cd).map_err(Error::Io)?;
    let cd_size = cd.len() as u64;
    let count = records.len() as u64;

    let needs_zip64 = count > u16::MAX as u64 || needs_zip64(cd_offset) || needs_zip64(cd_size);
    if needs_zip64 {
        let zip64_eocd_offset = cd_offset + cd_size;
        let mut record = Vec::with_capacity(ZIP64_EOCD_MIN_LEN);
        record.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        record.extend_from_slice(&44u64.to_le_bytes());
        record.extend_from_slice(&version_made_by(45).to_le_bytes());
        record.extend_from_slice(&45u16.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes()); // this disk
        record.extend_from_slice(&0u32.to_le_bytes()); // disk with the central directory
        record.extend_from_slice(&count.to_le_bytes());
        record.extend_from_slice(&count.to_le_bytes());
        record.extend_from_slice(&cd_size.to_le_bytes());
        record.extend_from_slice(&cd_offset.to_le_bytes());
        sink.write_all(&record).map_err(Error::Io)?;

        let mut locator = Vec::with_capacity(crate::spec::ZIP64_LOCATOR_LEN);
        locator.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
        locator.extend_from_slice(&0u32.to_le_bytes()); // disk with the ZIP64 EOCD
        locator.extend_from_slice(&zip64_eocd_offset.to_le_bytes());
        locator.extend_from_slice(&1u32.to_le_bytes()); // total disks
        sink.write_all(&locator).map_err(Error::Io)?;
    }

    let mut eocd = Vec::with_capacity(EOCD_LEN + comment.len());
    eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes()); // this disk
    eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with the central directory
    let stored_count = if needs_zip64 { u16::MAX } else { count as u16 };
    eocd.extend_from_slice(&stored_count.to_le_bytes());
    eocd.extend_from_slice(&stored_count.to_le_bytes());
    eocd.extend_from_slice(&local_size(cd_size, needs_zip64).to_le_bytes());
    eocd.extend_from_slice(&local_size(cd_offset, needs_zip64).to_le_bytes());
    eocd.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    eocd.extend_from_slice(&comment);
    sink.write_all(&eocd).map_err(Error::Io)?;
    Ok(())
}

/// Serialise one central directory record into `out`.
fn write_central_record_into(out: &mut Vec<u8>, record: &CentralRecord) -> Result<()> {
    let sizes_need_zip64 = record.zip64_sizes;
    let offset_needs_zip64 = record.zip64_offset;
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
    out.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
    out.extend_from_slice(&record.version_made_by.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&record.flags.to_le_bytes());
    out.extend_from_slice(&record.method.to_le_bytes());
    out.extend_from_slice(&record.dos_time.to_le_bytes());
    out.extend_from_slice(&record.dos_date.to_le_bytes());
    out.extend_from_slice(&record.crc32.to_le_bytes());
    out.extend_from_slice(&local_size(record.compressed_size, sizes_need_zip64).to_le_bytes());
    out.extend_from_slice(&local_size(record.uncompressed_size, sizes_need_zip64).to_le_bytes());
    out.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    out.extend_from_slice(&(record.comment.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&record.external_attrs.to_le_bytes());
    out.extend_from_slice(&local_size(record.header_offset, offset_needs_zip64).to_le_bytes());
    out.extend_from_slice(&record.name);
    out.extend_from_slice(&extra);
    out.extend_from_slice(&record.comment);
    Ok(())
}

/// Build the DEFLATE encoder the active backend calls for.
#[cfg(feature = "deflate-zlib-rs")]
pub(crate) fn new_deflate_encoder(level: u8) -> Encoder {
    let level = level.min(10);
    Encoder::DeflateZlib(flate2::write::DeflateEncoder::new(
        Vec::with_capacity(OUT_BUF_SIZE),
        flate2::Compression::new(u32::from(level)),
    ))
}

/// Build the DEFLATE encoder the active backend calls for.
#[cfg(not(feature = "deflate-zlib-rs"))]
pub(crate) fn new_deflate_encoder(level: u8) -> Encoder {
    Encoder::Deflate(new_compressor(level))
}

#[cfg_attr(feature = "deflate-zlib-rs", allow(dead_code))]
fn new_compressor(level: u8) -> Box<CompressorOxide> {
    let mut compressor =
        CompressorOxide::with_format_and_level(DataFormat::Raw, CompressionLevel::DefaultLevel);
    compressor.set_compression_level_raw(level.min(10));
    Box::new(compressor)
}

/// Reset a recycled compressor for a new entry, or allocate one if none is spare.
///
/// A new DEFLATE stream must start from a clean window and fresh Huffman tables. `reset` restores
/// both without freeing and reallocating the 32 KiB window, which is the cost this avoids.
#[cfg_attr(feature = "deflate-zlib-rs", allow(dead_code))]
fn take_compressor(spare: &mut Option<Box<CompressorOxide>>, level: u8) -> Box<CompressorOxide> {
    match spare.take() {
        Some(mut compressor) => {
            compressor.reset();
            // `reset` restores the flags captured at construction, so the level is reapplied.
            compressor.set_compression_level_raw(level.min(10));
            compressor
        }
        None => new_compressor(level),
    }
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
