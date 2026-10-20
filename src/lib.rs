#![forbid(unsafe_code)]
//! A from-scratch, read-only ZIP archive reader.
//!
//! `zipcore` parses the ZIP container itself ??end of central directory record, ZIP64 records,
//! central directory, local file headers and data descriptors ??and decompresses **Stored** and
//! **Deflate** members in a streaming fashion. It exists because upstreaming a container parser
//! you control beats inheriting one you cannot.
//!
//! # Scope
//!
//! Implemented:
//!
//! * Stored (method 0) and Deflate (method 8) members, i.e. everything used by `.xlsx`, `.ods`,
//!   `.docx`, `.epub`, `.jar` and ordinary archives.
//! * ZIP64 sizes, offsets and entry counts.
//! * Streaming reads from any `Read + Seek` source, so a member never has to be held in memory.
//! * CRC-32 and declared-size verification.
//! * CP437 and UTF-8 entry name decoding, per general-purpose flag bit 11.
//! * Archives with a prepended self-extractor stub, via offset correction.
//!
//! Deliberately not implemented, and reported as an error rather than guessed at:
//!
//! * LZMA/XZ, PPMd and Deflate64.
//! * Bzip2 and Zstd in a build without their feature.
//! * The legacy shrink/implode/reduce methods.
//! * Multi-disk (spanned) archives.
//!
//! Encryption *is* supported: traditional PKWARE always, and WinZip AES behind the `aes-crypto`
//! feature. See [`ReadOptions::password`] and [`Encryption`].
//!
//! # Writing
//!
//! [`ZipWriter`] creates archives on any `Write + Seek` sink. Entry data is streamed through
//! the compressor straight to the sink, and each local file header is seeked back to and
//! patched once its CRC-32 and sizes are known, so memory use does not grow with entry size.
//!
//! ```no_run
//! use zipcore::{FileOptions, ZipWriter};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()))?;
//! writer.add_file("docs/readme.txt", b"hello", &FileOptions::default())?;
//! writer.add_file("stored.bin", b"raw bytes", &FileOptions::stored())?;
//! writer.add_directory("empty", &FileOptions::default())?;
//! let cursor = writer.finish()?;
//! # Ok(())
//! # }
//! ```
//!
//! Entries of 4 GiB or more must declare their size with [`FileOptions::size_hint`] so the
//! ZIP64 extra field can be reserved before the data is written; otherwise the writer reports
//! [`Error::Zip64Required`] rather than emitting a truncated header.
//!
//! # Robustness and hostile input
//!
//! This crate treats archives as untrusted:
//!
//! * No allocation is ever sized from a value in the archive. `Vec::with_capacity` is only
//!   ever called with a bounded hint, so a forged 64-bit size cannot cause an allocation
//!   failure. Set [`ReadOptions::max_entry_size`] to cap decompression outright.
//! * Every length field is range-checked with `checked_add` before use, and every offset is
//!   validated in wider arithmetic, so a malformed or forged record returns [`Error::Malformed`]
//!   instead of panicking. The crate is `#![forbid(unsafe_code)]`.
//! * Entry names are only converted to filesystem paths through [`Entry::safe_path`], which
//!   rejects absolute paths, drive-qualified paths, `..` traversal, alternate data streams and
//!   Windows device names ??including the trailing-space and trailing-dot spellings that Win32
//!   collapses onto them. Extracting a symbolic link entry is refused rather than followed.
//! * Extraction canonicalises the destination and refuses a write whose parent resolves outside
//!   it, so a pre-existing junction or symlink inside the destination cannot redirect a member.
//! * A structural inconsistency (declared size, CRC-32 or a bad signature) is an error, so
//!   corrupt data is never returned as if it were valid.
//!
//! # Example
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut archive = zipcore::Archive::open("book.xlsx")?;
//! println!("{} entries", archive.len());
//!
//! let mut sheet = archive.by_name("xl/worksheets/sheet1.xml")?;
//! let mut xml = String::new();
//! sheet.read_to_string(&mut xml)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod archive;
mod cp437;
mod crypto;
mod dos;
mod entry;
mod error;
mod multivolume;
mod path;
mod read;
mod spec;
mod tar;
mod util;
mod write;

pub use crate::archive::{
    Archive, ExtractLimits, ExtractReport, Overwrite, RawEntryReader, ReadOptions,
    MAX_IN_MEMORY_ENTRY,
};
pub use crate::entry::{Compression, Entry};
pub use crate::error::{Error, Result};
pub use crate::multivolume::MultiVolumeReader;
pub use crate::read::ZipFile;
pub use crate::tar::{TarEntry, TarEntryOptions, TarWriter};
pub use crate::write::{
    Encryption, FileOptions, WriteOptions, ZipWriter, ZipWriterEntry, DEFAULT_COMPRESSION_LEVEL,
};

/// Signature of the first four bytes of any non-empty ZIP archive.
pub const LOCAL_FILE_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
