use std::fmt;
use std::io;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while reading or writing an archive.
///
/// The variants are deliberately specific: a reader that reports "invalid archive" for an
/// encrypted entry, a truncated file and a CRC mismatch gives the caller nothing to act on.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Wrapper around an underlying I/O failure.
    Io(io::Error),
    /// The end-of-central-directory record could not be located.
    InvalidSignature,
    /// The archive is structurally invalid. Carries a description of what was wrong, so that
    /// a failure in the field can be diagnosed without reproducing it.
    Malformed(String),
    /// A well-formed feature that this reader does not implement.
    Unsupported(&'static str),
    /// The entry is encrypted. We fail closed instead of returning gibberish.
    ///
    /// Only produced when no password was supplied; see [`Error::WrongPassword`].
    Encrypted { entry: String },
    /// A password was supplied but did not decrypt the entry.
    ///
    /// For traditional PKWARE encryption this is detected by the 12-byte header's check byte. For
    /// AES it is detected by the password verifier or, if that collides, by the authentication code.
    WrongPassword,
    /// A compression method that this build does not implement.
    UnsupportedCompression { entry: String, method: u16 },
    /// This build can read the method but cannot write it.
    ///
    /// Reachable once a decode-only codec lands; none is decode-only today.
    CompressionNotWritable { entry: String, method: u16 },
    /// The CRC-32 of the decompressed data does not match the central directory.
    CrcMismatch {
        entry: String,
        expected: u32,
        actual: u32,
    },
    /// The number of decompressed bytes does not match the declared size.
    SizeMismatch {
        entry: String,
        expected: u64,
        actual: u64,
    },
    /// Decompression would have exceeded the configured limit. See
    /// [`ReadOptions::max_entry_size`](crate::ReadOptions::max_entry_size).
    SizeLimitExceeded { entry: String, limit: u64 },
    /// No entry with the requested name exists.
    EntryNotFound { name: String },
    /// The requested index is not present in the archive.
    IndexOutOfRange { index: usize, len: usize },
    /// The entry name is not safe to use as a relative filesystem path.
    UnsafePath { entry: String, reason: &'static str },
    /// The destination path already exists and the extraction policy forbids replacing it.
    AlreadyExists { path: String },
    /// The entry grew past the 4 GiB limit and no ZIP64 field had been reserved for it.
    ///
    /// Set [`FileOptions::size_hint`](crate::FileOptions::size_hint) when writing an entry that
    /// large, so the writer can reserve the ZIP64 extra field before the data is written.
    Zip64Required { entry: String },
    /// The compressor rejected the data.
    Compression { detail: String },
    /// A configured limit was reached.
    LimitExceeded { detail: String },
    /// The writer has already been finished.
    WriterFinished,
    /// An earlier operation failed and left the writer unusable.
    ///
    /// Every later operation on that writer reports this instead of writing into an archive
    /// that is already inconsistent.
    WriterFailed { detail: String },
    /// No entry is in progress, so there is nothing to write to.
    NoEntryInProgress,
}

impl Error {
    pub(crate) fn malformed(msg: impl Into<String>) -> Self {
        Error::Malformed(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::InvalidSignature => write!(
                f,
                "not a ZIP archive: end of central directory record not found"
            ),
            Error::Malformed(msg) => write!(f, "malformed archive: {msg}"),
            Error::Unsupported(feature) => write!(f, "unsupported archive feature: {feature}"),
            Error::Encrypted { entry } => {
                write!(
                    f,
                    "entry `{entry}` is encrypted; supply a password to read it"
                )
            }
            Error::WrongPassword => {
                write!(f, "the password did not decrypt the entry")
            }
            Error::UnsupportedCompression { entry, method } => {
                let compression = crate::entry::Compression::from_method(*method);
                write!(
                    f,
                    "entry `{entry}` uses compression method {method} ({}), which this build \
                     does not support",
                    compression.name()
                )?;
                // Point at the feature that fixes it, but only when that feature exists.
                if let Some(feature) = compression.required_feature() {
                    write!(f, "; rebuild with the `{feature}` feature to enable it")?;
                }
                Ok(())
            }
            Error::CompressionNotWritable { entry, method } => write!(
                f,
                "entry `{entry}` uses compression method {method} ({}), which this build can \
                 read but not write",
                crate::entry::Compression::from_method(*method).name()
            ),
            Error::CrcMismatch {
                entry,
                expected,
                actual,
            } => write!(
                f,
                "CRC-32 mismatch for `{entry}`: expected {expected:#010x}, got {actual:#010x}"
            ),
            Error::SizeMismatch {
                entry,
                expected,
                actual,
            } => write!(
                f,
                "size mismatch for `{entry}`: expected {expected} bytes, got {actual}"
            ),
            Error::SizeLimitExceeded { entry, limit } => write!(
                f,
                "entry `{entry}` exceeds the configured size limit of {limit} bytes"
            ),
            Error::EntryNotFound { name } => write!(f, "no entry named `{name}`"),
            Error::IndexOutOfRange { index, len } => {
                write!(
                    f,
                    "entry index {index} out of range (archive has {len} entries)"
                )
            }
            Error::UnsafePath { entry, reason } => {
                write!(f, "entry `{entry}` is not safe to extract: {reason}")
            }
            Error::AlreadyExists { path } => {
                write!(
                    f,
                    "`{path}` already exists and extraction is set not to replace it"
                )
            }
            Error::Zip64Required { entry } => write!(
                f,
                "entry `{entry}` exceeds the 32-bit ZIP limit; set FileOptions::size_hint so the \
                 writer can reserve ZIP64 fields for it"
            ),
            Error::Compression { detail } => write!(f, "compression failed: {detail}"),
            Error::LimitExceeded { detail } => write!(f, "limit exceeded: {detail}"),
            Error::WriterFinished => write!(f, "the archive writer has already been finished"),
            Error::WriterFailed { detail } => write!(
                f,
                "the archive writer cannot continue after an earlier failure: {detail}"
            ),
            Error::NoEntryInProgress => {
                write!(f, "no entry is in progress; call start_file first")
            }
        }
    }
}

/// A coarse classification of [`Error`], for callers that need to branch on the *category* of a
/// failure rather than match every variant.
///
/// This exists because `Error` cannot be `Clone` or `PartialEq` — it wraps [`std::io::Error`],
/// which is neither. Comparing a `Kind` is the practical substitute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// The archive is structurally invalid or truncated: it was not, or is no longer, a ZIP.
    Malformed,
    /// The archive is well-formed but uses a feature this build cannot handle, such as a
    /// compression method whose feature is off. Rebuilding with that feature may help.
    Unsupported,
    /// A password was required (or was wrong).
    Password,
    /// A configured limit was reached: entry count, total bytes, or per-entry size.
    LimitExceeded,
    /// An integrity check failed: CRC-32 or the declared size did not match the data.
    IntegrityFailure,
    /// The caller asked for something that does not exist, such as an out-of-range index.
    NotFound,
    /// The writer refused because a previous write already failed.
    WriterFailed,
    /// A name was refused because extracting it would be unsafe.
    UnsafeName,
    /// The destination already exists and the overwrite policy forbade replacing it.
    AlreadyExists,
    /// An underlying I/O failure.
    Io,
}

impl Error {
    /// Classify this error.
    ///
    /// ```
    /// # use zipcore::{Archive, error::Kind};
    /// let error = Archive::new(std::io::Cursor::new(vec![0u8; 8])).unwrap_err();
    /// assert_eq!(error.kind(), Kind::Malformed);
    /// ```
    pub fn kind(&self) -> Kind {
        match self {
            Error::Io(_) => Kind::Io,
            Error::InvalidSignature | Error::Malformed(_) => Kind::Malformed,
            Error::UnsupportedCompression { .. }
            | Error::CompressionNotWritable { .. }
            | Error::Unsupported(_) => Kind::Unsupported,
            Error::Encrypted { .. } | Error::WrongPassword => Kind::Password,
            Error::LimitExceeded { .. }
            | Error::SizeLimitExceeded { .. }
            | Error::Zip64Required { .. } => Kind::LimitExceeded,
            Error::CrcMismatch { .. } | Error::SizeMismatch { .. } => Kind::IntegrityFailure,
            Error::IndexOutOfRange { .. } | Error::EntryNotFound { .. } => Kind::NotFound,
            Error::WriterFailed { .. } | Error::WriterFinished | Error::NoEntryInProgress => {
                Kind::WriterFailed
            }
            Error::UnsafePath { .. } => Kind::UnsafeName,
            Error::AlreadyExists { .. } => Kind::AlreadyExists,
            // `Compression` is the codec rejecting data, which is an integrity problem.
            Error::Compression { .. } => Kind::IntegrityFailure,
        }
    }

    /// Whether retrying with more capability (a feature, a password, a larger limit) could help.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self.kind(),
            Kind::Unsupported | Kind::Password | Kind::LimitExceeded | Kind::AlreadyExists
        )
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::EntryNotFound { .. } | Error::IndexOutOfRange { .. } => {
                io::Error::new(io::ErrorKind::NotFound, e.to_string())
            }
            Error::NoEntryInProgress
            | Error::WriterFinished
            | Error::WriterFailed { .. }
            | Error::CompressionNotWritable { .. }
            | Error::Zip64Required { .. } => io::Error::other(e.to_string()),
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}
