use crate::error::{Error, Result};
use crate::path::safe_relative_path;
use crate::spec::*;
use std::path::PathBuf;

/// The compression method an entry uses.
///
/// Every method id worth naming is named here, whether or not the current build can handle it, so
/// that an unsupported entry reports *which* method it wants rather than a bare number. Ask
/// [`Compression::is_supported`] whether this build can actually process it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compression {
    /// Method 0: the bytes are stored verbatim.
    Stored,
    /// Method 8: raw DEFLATE (RFC 1951).
    Deflate,
    /// Method 9: DEFLATE with a 64 KiB window and a 16-bit length extension.
    Deflate64,
    /// Method 12: bzip2.
    Bzip2,
    /// Method 14: LZMA.
    Lzma,
    /// Method 93: Zstandard.
    Zstd,
    /// Method 95: LZMA in an XZ container.
    Xz,
    /// Method 98: PPMd, variant I revision 1.
    Ppmd,
    /// Any other method id.
    Other(u16),
}

impl Compression {
    /// Classify a raw method id.
    pub fn from_method(method: u16) -> Self {
        match method {
            METHOD_STORED => Compression::Stored,
            METHOD_DEFLATE => Compression::Deflate,
            METHOD_DEFLATE64 => Compression::Deflate64,
            METHOD_BZIP2 => Compression::Bzip2,
            METHOD_LZMA => Compression::Lzma,
            METHOD_ZSTD => Compression::Zstd,
            METHOD_XZ => Compression::Xz,
            METHOD_PPMD => Compression::Ppmd,
            other => Compression::Other(other),
        }
    }

    /// The method id as it appears in the archive.
    pub fn method_id(self) -> u16 {
        match self {
            Compression::Stored => METHOD_STORED,
            Compression::Deflate => METHOD_DEFLATE,
            Compression::Deflate64 => METHOD_DEFLATE64,
            Compression::Bzip2 => METHOD_BZIP2,
            Compression::Lzma => METHOD_LZMA,
            Compression::Zstd => METHOD_ZSTD,
            Compression::Xz => METHOD_XZ,
            Compression::Ppmd => METHOD_PPMD,
            Compression::Other(id) => id,
        }
    }

    /// A short human-readable name, for messages.
    pub fn name(self) -> &'static str {
        match self {
            Compression::Stored => "stored",
            Compression::Deflate => "deflate",
            Compression::Deflate64 => "deflate64",
            Compression::Bzip2 => "bzip2",
            Compression::Lzma => "lzma",
            Compression::Zstd => "zstd",
            Compression::Xz => "xz",
            Compression::Ppmd => "ppmd",
            Compression::Other(_) => "unknown",
        }
    }

    /// Whether this build can decode the method.
    ///
    /// Methods that are named but unimplemented stay `false`, so a build never claims a
    /// capability it does not have.
    pub fn is_supported(self) -> bool {
        match self {
            Compression::Stored | Compression::Deflate => true,
            Compression::Zstd => cfg!(feature = "zstd"),
            Compression::Bzip2 => cfg!(feature = "bzip2"),
            Compression::Deflate64 => cfg!(feature = "deflate64"),
            Compression::Lzma => cfg!(feature = "lzma"),
            Compression::Ppmd => cfg!(feature = "ppmd"),
            // XZ (method 95) is not a ZIP method in practice, and `Other` is by definition
            // something this build has no decoder for.
            Compression::Xz | Compression::Other(_) => false,
        }
    }

    /// Whether this build can *write* the method.
    ///
    /// Kept separate from [`Compression::is_supported`] because a method can be worth decoding
    /// without being worth encoding. zstd is the one that is currently decode-only.
    pub fn is_writable(self) -> bool {
        match self {
            Compression::Stored | Compression::Deflate => true,
            Compression::Zstd => cfg!(feature = "zstd"),
            Compression::Deflate64
            | Compression::Bzip2
            | Compression::Lzma
            | Compression::Xz
            | Compression::Ppmd
            | Compression::Other(_) => false,
        }
    }

    /// The cargo feature that would teach this build to handle the method.
    ///
    /// Only names features that actually exist, so the hint in an error message is never a dead
    /// end. Each remaining codec adds its own name here as it lands.
    pub fn required_feature(self) -> Option<&'static str> {
        match self {
            Compression::Zstd => Some("zstd"),
            Compression::Bzip2 => Some("bzip2"),
            _ => None,
        }
    }
}

/// WinZip AES metadata carried by the `0x9901` extra field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AesInfo {
    /// AE-1 (1) or AE-2 (2). AE-2 omits the CRC-32 from the central directory.
    pub(crate) vendor_version: u16,
    /// Key strength byte: 1 = 128-bit, 2 = 192-bit, 3 = 256-bit.
    pub(crate) strength: u8,
    /// The compression method actually used inside the encrypted payload.
    pub(crate) actual_method: u16,
}

/// Metadata for one archive entry, taken from the central directory.
///
/// The central directory is authoritative: local file headers may be zeroed out by writers
/// that stream and patch sizes into a trailing data descriptor, so every value here comes
/// from the central directory record.
#[derive(Debug, Clone)]
pub struct Entry {
    pub(crate) name: String,
    pub(crate) name_raw: Vec<u8>,
    pub(crate) method: u16,
    pub(crate) flags: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) local_header_offset: u64,
    pub(crate) dos_time: u16,
    pub(crate) dos_date: u16,
    pub(crate) external_attrs: u32,
    pub(crate) version_made_by: u16,
    pub(crate) comment: Option<String>,
    /// WinZip AES metadata from the `0x9901` extra field, when the entry is AES encrypted.
    pub(crate) aes: Option<AesInfo>,
    /// Modification time from the extended-timestamp (`0x5455`) extra field, in Unix seconds.
    ///
    /// `None` when the archive recorded only a DOS timestamp, which has two-second resolution
    /// and no timezone.
    pub(crate) unix_mtime: Option<u64>,
}

impl Entry {
    /// The decoded entry name (UTF-8, or CP437 when the name is not UTF-8).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The entry name exactly as stored, before decoding.
    pub fn name_raw(&self) -> &[u8] {
        &self.name_raw
    }

    /// CRC-32 of the *decompressed* contents.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// Size of the entry as stored in the archive.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Size of the entry after decompression.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Offset of this entry's local file header from the start of the archive.
    pub fn header_offset(&self) -> u64 {
        self.local_header_offset
    }

    /// The compression method as a `Compression`.
    pub fn compression(&self) -> Compression {
        Compression::from_method(self.method)
    }

    /// Raw compression method id.
    pub fn method(&self) -> u16 {
        self.method
    }

    /// Whether the entry uses WinZip AES encryption (method 99 plus a `0x9901` extra field).
    pub fn is_aes(&self) -> bool {
        self.aes.is_some()
    }

    /// Whether the entry is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    /// Whether the entry carries a trailing data descriptor.
    pub fn has_data_descriptor(&self) -> bool {
        self.flags & FLAG_DATA_DESCRIPTOR != 0
    }

    /// The raw general-purpose bit flags.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// The raw external attributes field (Unix mode in the high 16 bits, DOS bits in the low).
    pub fn external_attrs(&self) -> u32 {
        self.external_attrs
    }

    /// The raw "version made by" field: host system in the high byte.
    pub fn version_made_by(&self) -> u16 {
        self.version_made_by
    }

    /// Last modification time as `(DOS date, DOS time)`.
    pub fn dos_timestamp(&self) -> (u16, u16) {
        (self.dos_date, self.dos_time)
    }

    /// Modification time in Unix seconds, from the extended-timestamp extra field.
    ///
    /// Returns `None` when the archive recorded only a DOS timestamp. Prefer this over
    /// [`Entry::dos_timestamp`] when it is available: DOS time has two-second resolution and no
    /// timezone, so it cannot round-trip an arbitrary instant.
    pub fn unix_mtime(&self) -> Option<u64> {
        self.unix_mtime
    }

    /// The Unix `st_mode` from the external attributes, if the archive was made on Unix.
    pub fn unix_mode(&self) -> Option<u32> {
        let host = (self.version_made_by >> 8) as u8;
        if host == HOST_UNIX {
            Some(self.external_attrs >> 16)
        } else {
            None
        }
    }

    /// Whether this entry represents a directory.
    pub fn is_dir(&self) -> bool {
        if self.name.ends_with('/') {
            return true;
        }
        match self.unix_mode() {
            Some(mode) => mode & S_IFMT == S_IFDIR,
            None => false,
        }
    }

    /// Whether this entry represents a symbolic link.
    ///
    /// The link target is the entry's contents. [`Entry::safe_path`] does not resolve links,
    /// and neither does this crate's extraction helper.
    pub fn is_symlink(&self) -> bool {
        match self.unix_mode() {
            Some(mode) => mode & S_IFMT == S_IFLNK,
            None => false,
        }
    }

    /// Optional entry comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// This entry's name as a relative path that is safe to join onto an extraction root.
    ///
    /// Returns [`Error::UnsafePath`] for absolute names, drive-qualified names, `..`
    /// traversal, NUL bytes, alternate data streams and Windows device names. Callers that
    /// write files must use this rather than [`Entry::name`].
    pub fn safe_path(&self) -> Result<PathBuf> {
        safe_relative_path(&self.name).map_err(|reason| Error::UnsafePath {
            entry: self.name.clone(),
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MADE_BY_UNIX: u16 = 0x031e;

    fn entry(name: &str, version_made_by: u16, external_attrs: u32) -> Entry {
        Entry {
            name: name.to_string(),
            name_raw: name.as_bytes().to_vec(),
            method: METHOD_STORED,
            flags: 0,
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            local_header_offset: 0,
            dos_time: 0,
            dos_date: 0,
            external_attrs,
            version_made_by,
            comment: None,
            unix_mtime: None,
            aes: None,
        }
    }

    #[test]
    fn directory_detected_from_a_trailing_slash() {
        assert!(entry("folder/", MADE_BY_UNIX, 0).is_dir());
        assert!(!entry("folder", MADE_BY_UNIX, 0).is_dir());
    }

    #[test]
    fn directory_detected_from_the_unix_mode() {
        let e = entry("folder", MADE_BY_UNIX, S_IFDIR << 16);
        assert!(e.is_dir());
        assert_eq!(e.unix_mode(), Some(S_IFDIR));
    }

    #[test]
    fn symlink_detected_from_the_unix_mode() {
        let e = entry("link", MADE_BY_UNIX, (S_IFLNK << 16) | 0o777);
        assert!(e.is_symlink());
        assert!(!e.is_dir());
    }

    #[test]
    fn unix_mode_is_absent_for_non_unix_hosts() {
        let e = entry("file.txt", 0x0014, 0o20);
        assert_eq!(e.unix_mode(), None);
        assert!(!e.is_symlink());
        assert!(!e.is_dir());
    }

    #[test]
    fn compression_maps_known_methods() {
        let mut e = entry("x", MADE_BY_UNIX, 0);
        assert_eq!(e.compression(), Compression::Stored);

        e.method = METHOD_DEFLATE;
        assert_eq!(e.compression(), Compression::Deflate);

        e.method = 99;
        assert_eq!(e.compression(), Compression::Other(99));
    }

    #[test]
    fn flags_are_reported() {
        let mut e = entry("x", MADE_BY_UNIX, 0);
        assert!(!e.is_encrypted());
        assert!(!e.has_data_descriptor());

        e.flags = FLAG_ENCRYPTED | FLAG_DATA_DESCRIPTOR;
        assert!(e.is_encrypted());
        assert!(e.has_data_descriptor());
    }

    #[test]
    fn safe_path_rejects_traversal_and_accepts_ordinary_names() {
        assert!(entry("../escape", MADE_BY_UNIX, 0).safe_path().is_err());
        assert!(entry("ok.txt", MADE_BY_UNIX, 0).safe_path().is_ok());
    }
}
