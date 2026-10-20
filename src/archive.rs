use crate::cp437::decode_name;
use crate::entry::AesInfo;
use crate::entry::Compression;
use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::multivolume::MultiVolumeReader;
use crate::read::ZipFile;
use crate::spec::*;
use crate::util::{le_u16, le_u32, le_u64, read_exact_at, signature_at, SliceReader};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Default ceiling on decompressed bytes per entry.
///
/// Also the ceiling re-applied by [`Archive::read_entry`] and [`Archive::extract_entry`] when a
/// caller has removed the limit, because those buffer or materialise the entry. Real
/// spreadsheet, document and archive members are far below this.
pub const MAX_IN_MEMORY_ENTRY: u64 = 1 << 30;

/// Knobs controlling how an archive is opened and how strictly it is verified.
#[derive(Debug, Clone)]
pub struct ReadOptions {
    /// Verify the CRC-32 of every entry that is read through to the end. Default `true`.
    pub verify_crc: bool,
    /// Verify that decompression produced exactly the declared number of bytes.
    /// Default `true`.
    pub verify_size: bool,
    /// Hard ceiling on decompressed bytes per entry. Defaults to [`MAX_IN_MEMORY_ENTRY`].
    ///
    /// This is the only bound that does not come from the archive itself, and therefore the
    /// only one that still holds when a header lies about its size. Use
    /// [`ReadOptions::unlimited`] for archives you trust.
    pub max_entry_size: Option<u64>,
    /// If a recorded offset does not point at a valid local file header, retry it shifted by
    /// the discrepancy between the recorded central directory offset and where the central
    /// directory actually is. Recovers archives with a prepended self-extractor stub.
    /// Default `true`.
    pub offset_correction: bool,
    /// Password used to decrypt encrypted entries.
    ///
    /// When `None`, an encrypted entry fails with [`Error::Encrypted`]. Traditional PKWARE
    /// encryption is supported without any feature flag; WinZip AES needs the `aes-crypto`
    /// feature.
    pub password: Option<Vec<u8>>,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            verify_crc: true,
            verify_size: true,
            // Safe by default: a hostile archive must not be able to drive unbounded work
            // merely by being read with default settings.
            max_entry_size: Some(MAX_IN_MEMORY_ENTRY),
            offset_correction: true,
            password: None,
        }
    }
}

impl ReadOptions {
    /// The defaults, with the per-entry size ceiling removed.
    pub fn unlimited() -> Self {
        Self {
            max_entry_size: None,
            ..Self::default()
        }
    }

    /// Replace the per-entry size ceiling, or remove it by passing `None`.
    pub fn with_max_entry_size(mut self, limit: Option<u64>) -> Self {
        self.max_entry_size = limit;
        self
    }

    /// Supply a password for encrypted entries.
    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }
}

/// Limits applied while extracting, for callers processing untrusted archives.
///
/// [`Archive::extract_all`] applies no limits; prefer
/// [`Archive::extract_all_with_limits`] when the archive is not trusted.
#[derive(Debug, Clone, Default)]
pub struct ExtractLimits {
    /// Maximum number of entries to write. `None` means unlimited.
    pub max_entries: Option<usize>,
    /// Maximum total number of decompressed bytes to write. `None` means unlimited.
    pub max_total_bytes: Option<u64>,
    /// What to do when an entry's target path already exists.
    ///
    /// Defaults to [`Overwrite::Replace`], matching ordinary unzip behaviour.
    pub overwrite: Overwrite,
}

/// What extraction does when the destination path already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Overwrite {
    /// Replace the existing file. The default.
    #[default]
    Replace,
    /// Refuse to touch it: extraction fails with [`Error::AlreadyExists`].
    Never,
    /// Leave the existing file alone and skip the entry, reporting it in
    /// [`ExtractReport::skipped_existing`].
    Skip,
}

impl ExtractReport {
    /// Paths that already existed and were left untouched under [`Overwrite::Skip`].
    pub fn skipped_existing_paths(&self) -> &[PathBuf] {
        &self.skipped_existing
    }
}

/// What an extraction actually did.
#[derive(Debug, Default, Clone)]
pub struct ExtractReport {
    /// Paths written, in archive order.
    pub written: Vec<PathBuf>,
    /// Names of symbolic link entries that were skipped rather than materialised.
    pub skipped_symlinks: Vec<String>,
    /// Paths left untouched because they already existed and the policy was [`Overwrite::Skip`].
    pub skipped_existing: Vec<PathBuf>,
    /// Total number of decompressed bytes actually written for those entries.
    ///
    /// This counts what reached the filesystem, not the size the archive declared, so a header
    /// that understates its size cannot make the total look smaller than it is.
    pub total_bytes: u64,
}

/// Restore an entry's permission bits, where the platform has them.
///
/// Only the permission bits are restored: honouring setuid or setgid out of an archive is a
/// privilege-escalation vector. A recorded mode of zero means nothing was recorded, and is
/// left alone so the umask-derived default stands rather than producing an unreadable file.
#[cfg(unix)]
fn apply_recorded_mode(path: &Path, entry: &Entry) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some(mode) = entry.unix_mode() else {
        return Ok(());
    };
    let permissions = mode & 0o777;
    if permissions == 0 {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(permissions)).map_err(Error::Io)
}

#[cfg(not(unix))]
fn apply_recorded_mode(_path: &Path, _entry: &Entry) -> Result<()> {
    Ok(())
}

/// A `Write` that counts what it forwards and refuses to exceed a budget.
///
/// Extraction limits have to be charged against bytes that were really produced, because a
/// header can claim any size it likes. Going through here means the archive's own numbers never
/// decide how much work is done.
struct BudgetedSink<'a, W: Write> {
    inner: &'a mut W,
    written: u64,
    /// Bytes still permitted and the overall limit, for the message.
    budget: Option<(u64, u64)>,
    entry: String,
    /// Set when the budget, not the sink or the codec, was the reason a write failed. `io::Error`
    /// cannot carry the structured `Error`, so it is recovered from here.
    limit_hit: Option<u64>,
}

impl<W: Write> Write for BudgetedSink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let allowed = match self.budget {
            Some((remaining, total)) => {
                if remaining == 0 {
                    self.limit_hit = Some(total);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        Error::LimitExceeded {
                            detail: format!("reached the {total}-byte limit at `{}`", self.entry),
                        }
                        .to_string(),
                    ));
                }
                (buf.len() as u64).min(remaining) as usize
            }
            None => buf.len(),
        };
        let n = self.inner.write(&buf[..allowed])?;
        self.written = self.written.saturating_add(n as u64);
        if let Some(budget) = &mut self.budget {
            budget.0 = budget.0.saturating_sub(n as u64);
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A unique temporary name beside `out_path`, used so a partially written entry never occupies
/// the real path.
fn temp_sibling(out_path: &Path, index: usize) -> PathBuf {
    let name = out_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "entry".to_string());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    out_path.with_file_name(format!(
        ".{name}.zipcore-{}-{index}-{unique}.part",
        std::process::id()
    ))
}

#[derive(Debug)]
struct Eocd {
    disk_number: u16,
    cd_start_disk: u16,
    entries_on_disk: u16,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
    comment: Vec<u8>,
}

/// A parsed, read-only view of a ZIP archive.
///
/// Constructing an `Archive` reads and validates the central directory; entry data is
/// decompressed lazily when an entry is opened.
pub struct Archive<R: Read + Seek> {
    reader: R,
    entries: Vec<Entry>,
    comment: Vec<u8>,
    zip64: bool,
    /// Added to every recorded offset. Non-zero only for archives with prepended data.
    base_offset: i64,
    options: ReadOptions,
    file_len: u64,
    /// Absolute offset at which the central directory starts, after any offset correction.
    /// `ZipWriter::new_append` seeks here so the old records are overwritten rather than
    /// accumulated.
    cd_offset: u64,
}

impl<R: Read + Seek> std::fmt::Debug for Archive<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written so that `R` does not have to be `Debug`.
        f.debug_struct("Archive")
            .field("entries", &self.entries.len())
            .field("zip64", &self.zip64)
            .field("base_offset", &self.base_offset)
            .field("file_len", &self.file_len)
            .finish_non_exhaustive()
    }
}

impl Archive<File> {
    /// Open an archive from a filesystem path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path).map_err(Error::Io)?;
        Archive::new(file)
    }
}

impl Archive<MultiVolumeReader> {
    /// Open an archive that was split across several volume files.
    ///
    /// The volumes must be given in order. This covers the ordinary split-file convention
    /// (`.zip.001`, `.zip.002`, ??, which is a plain byte split of one stream; see
    /// [`MultiVolumeReader`] for the naming caveat.
    pub fn open_volumes<I, P>(paths: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Archive::new(MultiVolumeReader::open(paths)?)
    }
}

impl<R: Read + Seek> Archive<R> {
    /// Parse an archive from any seekable reader.
    pub fn new(reader: R) -> Result<Self> {
        Self::new_with_options(reader, ReadOptions::default())
    }

    /// Parse an archive with explicit options.
    pub fn new_with_options(mut reader: R, options: ReadOptions) -> Result<Self> {
        let file_len = crate::util::stream_len(&mut reader)?;
        let (eocd, eocd_offset) = find_eocd(&mut reader, file_len)?;

        if eocd.disk_number != 0 || eocd.cd_start_disk != 0 {
            return Err(Error::Unsupported("spanned (multi-disk) archive"));
        }
        if eocd.entries_on_disk != eocd.total_entries {
            return Err(Error::Unsupported("spanned (multi-disk) archive"));
        }

        let mut zip64 = false;
        let mut cd_offset = eocd.cd_offset as u64;
        let mut cd_size = eocd.cd_size as u64;
        let mut total_entries = eocd.total_entries as u64;
        // Where the central directory ends: the ZIP64 EOCD record if present, else the EOCD.
        let mut cd_end = eocd_offset;

        if let Some(locator_offset) = eocd_offset.checked_sub(ZIP64_LOCATOR_LEN as u64) {
            if signature_at(&mut reader, locator_offset, ZIP64_LOCATOR_SIG)? {
                let mut locator = [0u8; ZIP64_LOCATOR_LEN];
                read_exact_at(&mut reader, locator_offset, &mut locator)?;
                let total_disks = le_u32(&locator[16..20]);
                if total_disks > 1 {
                    return Err(Error::Unsupported("spanned (multi-disk) archive"));
                }
                let zip64_eocd_offset = le_u64(&locator[8..16]);
                if zip64_eocd_offset
                    .checked_add(ZIP64_EOCD_MIN_LEN as u64)
                    .map_or(true, |end| end > file_len)
                {
                    return Err(Error::malformed("ZIP64 EOCD offset outside the file"));
                }
                let mut record = [0u8; ZIP64_EOCD_MIN_LEN];
                read_exact_at(&mut reader, zip64_eocd_offset, &mut record)?;
                if le_u32(&record[0..4]) != ZIP64_EOCD_SIG {
                    return Err(Error::malformed("bad ZIP64 EOCD signature"));
                }
                total_entries = le_u64(&record[32..40]);
                cd_size = le_u64(&record[40..48]);
                cd_offset = le_u64(&record[48..56]);
                cd_end = zip64_eocd_offset;
                zip64 = true;
            }
        }

        // An entry needs at least CENTRAL_DIR_LEN bytes, so a count larger than that cannot
        // be honest. This bounds every loop below by the real file size.
        if total_entries > file_len / CENTRAL_DIR_LEN as u64 + 1 {
            return Err(Error::malformed(
                "central directory entry count exceeds file size",
            ));
        }

        let derived_cd_offset = cd_end.saturating_sub(cd_size);
        let mut base_offset: i64 = 0;
        let mut effective_cd_offset = cd_offset;
        if total_entries > 0 && !signature_at(&mut reader, cd_offset, CENTRAL_DIR_SIG)? {
            if options.offset_correction
                && signature_at(&mut reader, derived_cd_offset, CENTRAL_DIR_SIG)?
            {
                effective_cd_offset = derived_cd_offset;
                // Both values come from the archive, so the difference is not guaranteed to fit
                // in an i64. Do the subtraction in i128 and refuse anything out of range rather
                // than overflowing ??this is reachable with a forged ZIP64 EOCD.
                base_offset = i64::try_from(derived_cd_offset as i128 - cd_offset as i128)
                    .map_err(|_| Error::malformed("offset correction out of range"))?;
            } else {
                return Err(Error::malformed(
                    "central directory not found at recorded offset",
                ));
            }
        }

        let entries =
            read_central_directory(&mut reader, effective_cd_offset, total_entries, file_len)?;

        Ok(Archive {
            reader,
            entries,
            comment: eocd.comment,
            zip64,
            base_offset,
            options,
            file_len,
            cd_offset: effective_cd_offset,
        })
    }

    /// Absolute offset at which this archive's central directory begins.
    ///
    /// This is where [`ZipWriter::new_append`](crate::ZipWriter::new_append) starts writing, so
    /// appending replaces the old directory instead of leaving it behind.
    pub fn central_directory_offset(&self) -> u64 {
        self.cd_offset
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the archive has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entry metadata, in central directory order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The archive-level comment, if any.
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Whether the archive used ZIP64 records.
    pub fn is_zip64(&self) -> bool {
        self.zip64
    }

    /// The options this archive was opened with.
    pub fn options(&self) -> &ReadOptions {
        &self.options
    }

    /// Index of the first entry whose decode name is exactly `name`.
    pub fn index_for_name(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.name == name)
    }

    /// Iterate over entry names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// Open the entry at `index` for streaming reads.
    pub fn by_index(&mut self, index: usize) -> Result<ZipFile<'_, R>> {
        self.by_index_with(index, self.options.clone())
    }

    /// Open the entry called `name` for streaming reads.
    ///
    /// If several entries share a name, the first is returned; use [`Archive::index_for_name`]
    /// together with [`Archive::by_index`] to reach the others.
    pub fn by_name(&mut self, name: &str) -> Result<ZipFile<'_, R>> {
        match self.index_for_name(name) {
            Some(index) => self.by_index(index),
            None => Err(Error::EntryNotFound {
                name: name.to_string(),
            }),
        }
    }

    /// A reader over the entry's *stored* bytes, without decompressing them.
    ///
    /// This is what makes a byte-faithful copy possible: the payload can be handed straight to
    /// [`ZipWriter::add_preserved`](crate::ZipWriter::add_preserved), including for entries whose
    /// compression method this crate cannot decode, and for encrypted entries, whose bytes are
    /// never inspected.
    ///
    /// Nothing is verified ??no CRC-32 and no size check ??because the bytes are not interpreted.
    pub fn raw_reader(&mut self, index: usize) -> Result<RawEntryReader<'_, R>> {
        let entry = match self.entries.get(index) {
            Some(entry) => entry.clone(),
            None => {
                return Err(Error::IndexOutOfRange {
                    index,
                    len: self.entries.len(),
                })
            }
        };
        let data_start = self.payload_extent(&entry)?;
        self.reader
            .seek(SeekFrom::Start(data_start))
            .map_err(Error::Io)?;
        Ok(RawEntryReader {
            reader: &mut self.reader,
            remaining: entry.compressed_size,
        })
    }

    fn by_index_with(&mut self, index: usize, options: ReadOptions) -> Result<ZipFile<'_, R>> {
        let entry = match self.entries.get(index) {
            Some(e) => e.clone(),
            None => {
                return Err(Error::IndexOutOfRange {
                    index,
                    len: self.entries.len(),
                })
            }
        };

        if entry.is_encrypted() {
            // Without a password there is nothing we can do; report it clearly rather than
            // letting the codec fail on ciphertext.
            if options.password.is_none() {
                return Err(Error::Encrypted { entry: entry.name });
            }
        } else if !entry.compression().is_supported() {
            // Read the Copy field before `name` is moved into the error.
            let method = entry.method();
            return Err(Error::UnsupportedCompression {
                entry: entry.name,
                method,
            });
        }

        // An encrypted entry announces method 99; the method actually used sits in its extra
        // field, and that is what decides whether this build can decode it.
        if entry.is_encrypted() {
            let real = entry
                .aes
                .map(|info| info.actual_method)
                .unwrap_or(entry.method());
            if !Compression::from_method(real).is_supported() {
                return Err(Error::UnsupportedCompression {
                    entry: entry.name,
                    method: real,
                });
            }
        }

        let data_start = self.payload_extent(&entry)?;

        ZipFile::new(&mut self.reader, entry, data_start, options)
    }

    /// Read an entire entry into memory.
    ///
    /// Applies [`MAX_IN_MEMORY_ENTRY`] when no explicit limit is configured, and never
    /// pre-allocates from the declared size.
    pub fn read_entry(&mut self, index: usize) -> Result<Vec<u8>> {
        let mut options = self.options.clone();
        if options.max_entry_size.is_none() {
            options.max_entry_size = Some(MAX_IN_MEMORY_ENTRY);
        }
        if let Some(entry) = self.entries.get(index) {
            if let Some(limit) = options.max_entry_size {
                if entry.uncompressed_size > limit {
                    return Err(Error::SizeLimitExceeded {
                        entry: entry.name.clone(),
                        limit,
                    });
                }
            }
        }

        let mut file = self.by_index_with(index, options)?;
        // Grow on demand rather than trusting the declared size.
        let hint = file.entry().uncompressed_size().min(1 << 20) as usize;
        let mut out = Vec::with_capacity(hint);
        if let Err(io_error) = std::io::copy(&mut file, &mut out) {
            // Prefer the structured terminal failure over the flattened io::Error.
            return Err(file.take_terminal_error().unwrap_or(Error::Io(io_error)));
        }
        Ok(out)
    }

    /// Extract one entry below `dest_dir`, creating parent directories as needed.
    ///
    /// The entry name is sanitised via [`Entry::safe_path`], so absolute names, drive-qualified
    /// names and `..` traversal are rejected rather than written. Symbolic link entries are
    /// refused: extracting a link is how zip-slip turns into arbitrary file overwrite.
    ///
    /// The payload is written to a temporary file in the destination directory and only renamed
    /// into place once its CRC-32 and size have verified, so a corrupt entry never leaves a
    /// complete-looking file behind.
    ///
    /// On Unix the recorded permission bits are restored after the contents are written,
    /// masked to `0o777` so an archive cannot install a setuid binary.
    pub fn extract_entry(&mut self, index: usize, dest_dir: &Path) -> Result<PathBuf> {
        self.extract_entry_with_budget(index, dest_dir, None, None)
            .map(|(path, _)| path)
    }

    /// The shared extraction body. `budget` caps how many bytes may be written; the returned
    /// count is what was actually written, never the size the archive declared.
    fn extract_entry_with_budget(
        &mut self,
        index: usize,
        dest_dir: &Path,
        budget: Option<(u64, u64)>,
        canonical_root: Option<&Path>,
    ) -> Result<(PathBuf, u64)> {
        let entry = match self.entries.get(index) {
            Some(e) => e.clone(),
            None => {
                return Err(Error::IndexOutOfRange {
                    index,
                    len: self.entries.len(),
                })
            }
        };
        let relative = entry.safe_path()?;
        let out_path = dest_dir.join(&relative);

        // A symlink entry is refused before the directory check: a name ending in `/` that also
        // carries S_IFLNK would otherwise be created as a directory, which is not what the
        // archive asked for and contradicts the guarantee that links are never materialised.
        if entry.is_symlink() {
            return Err(Error::Unsupported("symbolic link entry"));
        }
        if entry.is_dir() {
            let guarded = match canonical_root {
                Some(root) => self.guard_containment_against(root, dest_dir, &out_path)?,
                None => self.guard_containment(dest_dir, &out_path)?,
            };
            fs::create_dir_all(&guarded).map_err(Error::Io)?;
            apply_recorded_mode(&guarded, &entry)?;
            return Ok((guarded, 0));
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        // Re-check after the directories exist: a component may have been a pre-existing
        // junction or symlink pointing outside the destination.
        let out_path = match canonical_root {
            Some(root) => self.guard_containment_against(root, dest_dir, &out_path)?,
            None => self.guard_containment(dest_dir, &out_path)?,
        };

        let mut options = self.options.clone();
        if options.max_entry_size.is_none() {
            options.max_entry_size = Some(MAX_IN_MEMORY_ENTRY);
        }
        let mut source = self.by_index_with(index, options)?;

        // Write beside the destination and rename on success, so a failed entry leaves nothing
        // that looks like a complete file.
        let temp_path = temp_sibling(&out_path, index);
        let mut sink = File::create(&temp_path).map_err(Error::Io)?;
        let mut writer = BudgetedSink {
            inner: &mut sink,
            written: 0,
            budget,
            entry: entry.name.clone(),
            limit_hit: None,
        };
        // Streamed, so a large member never lands in memory.
        let copy_result = std::io::copy(&mut source, &mut writer);
        let written = writer.written;
        let limit_hit = writer.limit_hit;
        let flushed = sink.flush();
        drop(sink);

        if let Err(io_error) = copy_result {
            let _ = fs::remove_file(&temp_path);
            // The budget, not the archive, may be what stopped us; report that precisely.
            if let Some(limit) = limit_hit {
                return Err(Error::LimitExceeded {
                    detail: format!("reached the {limit}-byte limit at `{}`", entry.name()),
                });
            }
            return Err(source.take_terminal_error().unwrap_or(Error::Io(io_error)));
        }
        if let Err(error) = flushed {
            let _ = fs::remove_file(&temp_path);
            return Err(Error::Io(error));
        }
        // Verification runs at end of stream, so an error here means the payload is bad.
        if let Err(error) = source.verify_to_end() {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
        drop(source);

        if let Err(error) = fs::rename(&temp_path, &out_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(Error::Io(error));
        }
        apply_recorded_mode(&out_path, &entry)?;
        Ok((out_path, written))
    }

    /// Refuse a destination path that escapes `dest_dir` once the filesystem has resolved it.
    ///
    /// Name sanitisation cannot see a pre-existing junction or symlink inside the destination,
    /// so the containing directory is canonicalised and compared against the canonical
    /// destination root. The components after it are already known to be ordinary relative
    /// names, so this is enough to keep every write inside the tree.
    fn guard_containment(&self, dest_dir: &Path, out_path: &Path) -> Result<PathBuf> {
        let root = match fs::canonicalize(dest_dir) {
            Ok(root) => root,
            // Nothing exists yet: the caller is about to create it, and no reparenting can have
            // happened, so the join is safely inside.
            Err(_) => return Ok(out_path.to_path_buf()),
        };
        self.guard_containment_against(&root, dest_dir, out_path)
    }

    /// `guard_containment` with an already-canonicalised destination root.
    ///
    /// Extracting many entries canonicalises the same directory once per entry otherwise, which
    /// showed up as a measurable share of extraction time.
    fn guard_containment_against(
        &self,
        root: &Path,
        dest_dir: &Path,
        out_path: &Path,
    ) -> Result<PathBuf> {
        let parent = match out_path.parent() {
            Some(parent) => parent,
            None => return Ok(out_path.to_path_buf()),
        };
        let resolved = match fs::canonicalize(parent) {
            Ok(resolved) => resolved,
            // The parent does not exist yet; `create_dir_all` will create it under a path that
            // has already been checked, so nothing can redirect it.
            Err(_) => return Ok(out_path.to_path_buf()),
        };
        if !resolved.starts_with(root) {
            return Err(Error::UnsafePath {
                entry: out_path
                    .strip_prefix(dest_dir)
                    .unwrap_or(out_path)
                    .to_string_lossy()
                    .into_owned(),
                reason: "resolves outside the destination directory",
            });
        }
        Ok(out_path.to_path_buf())
    }

    /// Extract every entry below `dest_dir`.
    ///
    /// Symbolic link entries are skipped rather than materialised, and are reported in the
    /// result so nothing is dropped silently. No limits are applied: use
    /// [`Archive::extract_all_with_limits`] for archives you do not trust.
    pub fn extract_all(&mut self, dest_dir: &Path) -> Result<ExtractReport> {
        self.extract_all_with_limits(dest_dir, &ExtractLimits::default())
    }

    /// Extract every entry below `dest_dir`, stopping if `limits` are exceeded.
    ///
    /// Limits are enforced against the bytes actually written, not against the sizes the
    /// archive declares ??a header that understates its size cannot buy extra budget.
    pub fn extract_all_with_limits(
        &mut self,
        dest_dir: &Path,
        limits: &ExtractLimits,
    ) -> Result<ExtractReport> {
        let mut report = ExtractReport::default();
        // Canonicalise the destination once: doing it per entry was measurable.
        let canonical_root = fs::canonicalize(dest_dir).ok();
        for index in 0..self.entries.len() {
            let entry = self.entries[index].clone();
            if entry.is_symlink() {
                report.skipped_symlinks.push(entry.name().to_string());
                continue;
            }
            if let Some(max) = limits.max_entries {
                if report.written.len() >= max {
                    return Err(Error::LimitExceeded {
                        detail: format!("reached the {max}-entry limit at `{}`", entry.name()),
                    });
                }
            }
            // How many more bytes this entry may write before the total limit is reached.
            let budget = limits
                .max_total_bytes
                .map(|max| (max.saturating_sub(report.total_bytes), max));
            if matches!(budget, Some((0, _))) {
                return Err(Error::LimitExceeded {
                    detail: format!(
                        "reached the {}-byte limit at `{}`",
                        limits.max_total_bytes.unwrap_or(0),
                        entry.name()
                    ),
                });
            }
            // Apply the overwrite policy before doing any work for this entry.
            let target = dest_dir.join(entry.safe_path()?);
            if !entry.is_dir() && target.symlink_metadata().is_ok() {
                match limits.overwrite {
                    Overwrite::Replace => {}
                    Overwrite::Never => {
                        return Err(Error::AlreadyExists {
                            path: target.to_string_lossy().into_owned(),
                        })
                    }
                    Overwrite::Skip => {
                        report.skipped_existing.push(target);
                        continue;
                    }
                }
            }
            let (path, written) =
                self.extract_entry_with_budget(index, dest_dir, budget, canonical_root.as_deref())?;
            report.total_bytes = report.total_bytes.saturating_add(written);
            report.written.push(path);
        }
        Ok(report)
    }

    /// Validate an entry's local file header and return where its payload starts.
    ///
    /// The payload must lie inside the file. `compressed_size` comes from the central directory,
    /// which is authoritative even when the local header has been zeroed out.
    fn payload_extent(&mut self, entry: &Entry) -> Result<u64> {
        let header_offset = self.absolute_offset(entry.local_header_offset)?;
        let mut local = [0u8; LOCAL_HEADER_LEN];
        read_exact_at(&mut self.reader, header_offset, &mut local)?;
        if le_u32(&local[0..4]) != LOCAL_FILE_HEADER_SIG {
            return Err(Error::malformed(format!(
                "bad local file header signature at offset {header_offset}"
            )));
        }
        let name_len = le_u16(&local[26..28]) as u64;
        let extra_len = le_u16(&local[28..30]) as u64;
        let data_start = header_offset
            .checked_add(LOCAL_HEADER_LEN as u64)
            .and_then(|v| v.checked_add(name_len))
            .and_then(|v| v.checked_add(extra_len))
            .ok_or_else(|| Error::malformed("local header offset overflow"))?;

        let data_end = data_start
            .checked_add(entry.compressed_size)
            .ok_or_else(|| Error::malformed("compressed size overflow"))?;
        if data_end > self.file_len {
            return Err(Error::malformed("entry data extends past end of file"));
        }
        Ok(data_start)
    }

    /// Consume the archive and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    fn absolute_offset(&self, recorded: u64) -> Result<u64> {
        if recorded > self.file_len {
            return Err(Error::malformed("entry offset past end of file"));
        }
        // `recorded` is a 64-bit field from the central directory and `base_offset` is derived
        // from archive data, so the sum overflows for perfectly ordinary values. i128 keeps the
        // arithmetic exact and the result is range-checked before it is narrowed.
        let shifted = recorded as i128 + i128::from(self.base_offset);
        if shifted < 0 {
            return Err(Error::malformed("entry offset before start of file"));
        }
        u64::try_from(shifted).map_err(|_| Error::malformed("entry offset out of range"))
    }
}

/// A reader over one entry's stored bytes, produced by [`Archive::raw_reader`].
///
/// Nothing is decompressed or verified: the bytes are handed out exactly as they appear in the
/// archive. The reader seeks once when it is created and then reads sequentially, so copying an
/// entry costs no seek per chunk.
pub struct RawEntryReader<'a, R: Read + Seek> {
    reader: &'a mut R,
    remaining: u64,
}

impl<R: Read + Seek> std::fmt::Debug for RawEntryReader<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEntryReader")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> Read for RawEntryReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        // No seek: this reader holds the underlying reader exclusively, so nothing else can move
        // the cursor between calls.
        let want = (buf.len() as u64).min(self.remaining) as usize;
        let read = self.reader.read(&mut buf[..want])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// Locate the end of central directory record, scanning backwards.
///
/// Two passes: the first requires that the record's comment runs exactly to the end of the
/// file, which rejects the case where an archive comment happens to contain the signature.
/// The second pass relaxes that for archives with trailing bytes after the EOCD.
fn find_eocd<R: Read + Seek>(reader: &mut R, file_len: u64) -> Result<(Eocd, u64)> {
    if file_len < EOCD_LEN as u64 {
        return Err(Error::InvalidSignature);
    }
    let window = std::cmp::min(file_len, EOCD_MAX_SEARCH) as usize;
    let window_start = file_len - window as u64;
    let mut buf = vec![0u8; window];
    read_exact_at(reader, window_start, &mut buf)?;

    let sig = EOCD_SIG.to_le_bytes();
    let last = window - EOCD_LEN;

    for exact in [true, false] {
        for i in (0..=last).rev() {
            if buf[i..i + 4] != sig {
                continue;
            }
            let comment_len = le_u16(&buf[i + 20..]) as usize;
            let end = i + EOCD_LEN + comment_len;
            if end > window || (exact && end != window) {
                continue;
            }
            let record = Eocd {
                disk_number: le_u16(&buf[i + 4..]),
                cd_start_disk: le_u16(&buf[i + 6..]),
                entries_on_disk: le_u16(&buf[i + 8..]),
                total_entries: le_u16(&buf[i + 10..]),
                cd_size: le_u32(&buf[i + 12..]),
                cd_offset: le_u32(&buf[i + 16..]),
                comment: buf[i + EOCD_LEN..end].to_vec(),
            };
            return Ok((record, window_start + i as u64));
        }
    }

    Err(Error::InvalidSignature)
}

fn read_central_directory<R: Read + Seek>(
    reader: &mut R,
    cd_offset: u64,
    count: u64,
    file_len: u64,
) -> Result<Vec<Entry>> {
    // Bounded hint: the count itself has already been checked against the file size, but
    // avoid allocating megabytes up front for an archive we may reject immediately.
    let mut entries = Vec::with_capacity(count.min(4096) as usize);
    let mut pos = cd_offset;

    for _ in 0..count {
        let mut fixed = [0u8; CENTRAL_DIR_LEN];
        read_exact_at(reader, pos, &mut fixed).map_err(|error| {
            // A record that runs off the end of the file is a malformed archive, not an I/O
            // failure: the caller can act on "this archive is broken" but not on `UnexpectedEof`.
            match &error {
                Error::Io(io_error) if io_error.kind() == io::ErrorKind::UnexpectedEof => {
                    Error::malformed(format!(
                        "truncated central directory record at offset {pos}"
                    ))
                }
                _ => error,
            }
        })?;
        if le_u32(&fixed[0..4]) != CENTRAL_DIR_SIG {
            return Err(Error::malformed(format!(
                "bad central directory signature at offset {pos}"
            )));
        }
        let name_len = le_u16(&fixed[28..30]) as usize;
        let extra_len = le_u16(&fixed[30..32]) as usize;
        let comment_len = le_u16(&fixed[32..34]) as usize;
        let var_len = name_len + extra_len + comment_len;
        let var_start = pos + CENTRAL_DIR_LEN as u64;

        let mut var = vec![0u8; var_len];
        read_exact_at(reader, var_start, &mut var).map_err(|error| match &error {
            Error::Io(io_error) if io_error.kind() == io::ErrorKind::UnexpectedEof => {
                Error::malformed(format!(
                    "truncated central directory record at offset {pos}"
                ))
            }
            _ => error,
        })?;

        let name_raw = &var[..name_len];
        let extra = &var[name_len..name_len + extra_len];
        let comment_raw = &var[name_len + extra_len..];

        entries.push(parse_central_entry(&fixed, name_raw, extra, comment_raw)?);

        pos = var_start + var_len as u64;
        if pos > file_len {
            return Err(Error::malformed(
                "central directory extends past end of file",
            ));
        }
    }

    Ok(entries)
}

fn parse_central_entry(
    fixed: &[u8; CENTRAL_DIR_LEN],
    name_raw: &[u8],
    extra: &[u8],
    comment_raw: &[u8],
) -> Result<Entry> {
    let version_made_by = le_u16(&fixed[4..]);
    let flags = le_u16(&fixed[8..]);
    let method = le_u16(&fixed[10..]);
    let dos_time = le_u16(&fixed[12..]);
    let dos_date = le_u16(&fixed[14..]);
    let crc32 = le_u32(&fixed[16..]);
    let mut compressed_size = le_u32(&fixed[20..]) as u64;
    let mut uncompressed_size = le_u32(&fixed[24..]) as u64;
    let mut disk_start = le_u16(&fixed[34..]);
    let external_attrs = le_u32(&fixed[38..]);
    let mut local_header_offset = le_u32(&fixed[42..]) as u64;

    let need_zip64 = compressed_size == SENTINEL_U32 as u64
        || uncompressed_size == SENTINEL_U32 as u64
        || local_header_offset == SENTINEL_U32 as u64
        || disk_start == SENTINEL_U16;

    // The extended-timestamp field is independent of ZIP64, so scan for it unconditionally.
    let unix_mtime = parse_extended_timestamp(extra);
    // Likewise for WinZip AES: an entry using method 99 carries its real method in this field.
    let aes = parse_winzip_aes(extra);

    if need_zip64 {
        let mut found = false;
        let mut walker = SliceReader::new(extra);
        while walker.remaining() >= 4 {
            // Optional metadata: a truncated extra field ends the walk rather than failing
            // the whole archive. The ZIP64 case is re-checked below.
            let id = match walker.u16() {
                Ok(v) => v,
                Err(_) => break,
            };
            let size = match walker.u16() {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            let data = match walker.take(size) {
                Ok(d) => d,
                Err(_) => break,
            };
            if id != EXTRA_ZIP64 {
                continue;
            }
            // The ZIP64 field contains only the values that were sentinels, in this order.
            let mut z = SliceReader::new(data);
            if uncompressed_size == SENTINEL_U32 as u64 {
                uncompressed_size = z.u64()?;
            }
            if compressed_size == SENTINEL_U32 as u64 {
                compressed_size = z.u64()?;
            }
            if local_header_offset == SENTINEL_U32 as u64 {
                local_header_offset = z.u64()?;
            }
            if disk_start == SENTINEL_U16 {
                // A 64-bit disk number that does not fit in the 16-bit field would be read as a
                // local entry after truncation, so it is rejected rather than narrowed.
                disk_start = u16::try_from(z.u32()?).map_err(|_| {
                    Error::malformed("ZIP64 disk start number out of the 16-bit range")
                })?;
            }
            found = true;
            break;
        }
        if !found {
            return Err(Error::malformed(
                "ZIP64 sentinel present without a ZIP64 extra field",
            ));
        }
    }

    if disk_start != 0 {
        return Err(Error::Unsupported("spanned (multi-disk) archive"));
    }

    let utf8 = flags & FLAG_UTF8 != 0;
    let name = decode_name(name_raw, utf8);
    let comment = if comment_raw.is_empty() {
        None
    } else {
        Some(decode_name(comment_raw, utf8))
    };

    Ok(Entry {
        name,
        name_raw: name_raw.to_vec(),
        method,
        flags,
        crc32,
        compressed_size,
        uncompressed_size,
        local_header_offset,
        dos_time,
        dos_date,
        external_attrs,
        version_made_by,
        comment,
        unix_mtime,
        aes,
    })
}

/// Read the WinZip AES `0x9901` extra field.
///
/// Layout: version (2), vendor id (2, "AE"), strength (1), real compression method (2).
fn parse_winzip_aes(extra: &[u8]) -> Option<AesInfo> {
    let mut walker = SliceReader::new(extra);
    while walker.remaining() >= 4 {
        let id = walker.u16().ok()?;
        let size = walker.u16().ok()? as usize;
        let data = walker.take(size).ok()?;
        if id != EXTRA_WINZIP_AES {
            continue;
        }
        if data.len() < EXTRA_WINZIP_AES_LEN {
            return None;
        }
        // The vendor id must be "AE"; anything else is some other 99-method convention.
        if &data[2..4] != b"AE" {
            return None;
        }
        return Some(AesInfo {
            vendor_version: u16::from_le_bytes([data[0], data[1]]),
            strength: data[4],
            actual_method: u16::from_le_bytes([data[5], data[6]]),
        });
    }
    None
}

/// Pull the modification time out of an extended-timestamp (`0x5455`) extra field, if present.
///
/// Only the modification time is read: the field can also carry access and creation times, which
/// this crate does not model. A malformed field is ignored rather than failing the archive, since
/// it is metadata rather than structure.
fn parse_extended_timestamp(extra: &[u8]) -> Option<u64> {
    let mut walker = SliceReader::new(extra);
    while walker.remaining() >= 4 {
        let id = walker.u16().ok()?;
        let size = walker.u16().ok()? as usize;
        let data = walker.take(size).ok()?;
        if id != EXTRA_EXTENDED_TIMESTAMP {
            continue;
        }
        // layout: 1 byte of flags, then a 4-byte Unix time per flag bit that is set, in the
        // order mtime, atime, ctime.
        let flags = *data.first()?;
        if flags & EXTENDED_TIMESTAMP_FLAG_MTIME == 0 {
            return None;
        }
        let rest = data.get(1..)?;
        if rest.len() < 4 {
            return None;
        }
        return Some(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as u64);
    }
    None
}
