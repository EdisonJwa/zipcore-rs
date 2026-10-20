//! On-disk constants from the PKWARE APPNOTE (`.ZIP` file format specification).
//!
//! All multi-byte integers in a ZIP archive are little-endian.

/// Local file header signature: `PK\x03\x04`.
pub(crate) const LOCAL_FILE_HEADER_SIG: u32 = 0x0403_4b50;
/// Central directory file header signature: `PK\x01\x02`.
pub(crate) const CENTRAL_DIR_SIG: u32 = 0x0201_4b50;
/// End of central directory record signature: `PK\x05\x06`.
pub(crate) const EOCD_SIG: u32 = 0x0605_4b50;
/// ZIP64 end of central directory record signature: `PK\x06\x06`.
pub(crate) const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
/// ZIP64 end of central directory locator signature: `PK\x06\x07`.
pub(crate) const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
/// Optional data descriptor signature: `PK\x07\x08`.
#[allow(dead_code)]
pub(crate) const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;

/// Fixed sizes of the records we parse, in bytes.
pub(crate) const EOCD_LEN: usize = 22;
pub(crate) const ZIP64_LOCATOR_LEN: usize = 20;
pub(crate) const ZIP64_EOCD_MIN_LEN: usize = 56;
pub(crate) const CENTRAL_DIR_LEN: usize = 46;
pub(crate) const LOCAL_HEADER_LEN: usize = 30;

/// The EOCD record is followed by a comment of at most `u16::MAX` bytes, so a valid record
/// must start within this many bytes of the end of the file.
pub(crate) const EOCD_MAX_SEARCH: u64 = EOCD_LEN as u64 + u16::MAX as u64;

/// Extra field header ID for the ZIP64 extended information field.
pub(crate) const EXTRA_ZIP64: u16 = 0x0001;
/// Extra field header ID for the extended timestamp field (UT).
///
/// Carries real Unix seconds, so a timestamp survives at one-second resolution instead of the
/// two-second, 1980-era DOS granularity.
pub(crate) const EXTRA_EXTENDED_TIMESTAMP: u16 = 0x5455;
/// Length of an extended-timestamp field that carries only the modification time: a 1-byte flags
/// word plus one 4-byte Unix time.
pub(crate) const EXTRA_TIMESTAMP_MTIME_LEN: usize = 5;
/// Flags byte in the extended timestamp field: bit 0 is "modification time present".
pub(crate) const EXTENDED_TIMESTAMP_FLAG_MTIME: u8 = 0x01;

/// General purpose bit flags.
pub(crate) const FLAG_ENCRYPTED: u16 = 1 << 0;
pub(crate) const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
pub(crate) const FLAG_UTF8: u16 = 1 << 11;

/// Compression methods.
pub(crate) const METHOD_STORED: u16 = 0;
pub(crate) const METHOD_DEFLATE: u16 = 8;
pub(crate) const METHOD_DEFLATE64: u16 = 9;
pub(crate) const METHOD_BZIP2: u16 = 12;
pub(crate) const METHOD_LZMA: u16 = 14;
pub(crate) const METHOD_ZSTD: u16 = 93;
pub(crate) const METHOD_XZ: u16 = 95;
pub(crate) const METHOD_PPMD: u16 = 98;

/// Sentinel values that mean "the real value lives in the ZIP64 extra field".
pub(crate) const SENTINEL_U16: u16 = 0xffff;
pub(crate) const SENTINEL_U32: u32 = 0xffff_ffff;

/// Host system recorded in the high byte of "version made by".
pub(crate) const HOST_UNIX: u8 = 3;

/// `st_mode` file type bits, as stored in the high 16 bits of the external attributes.
pub(crate) const S_IFMT: u32 = 0o170000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFLNK: u32 = 0o120000;
