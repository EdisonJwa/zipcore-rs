//! Streaming ZIP output for sinks that cannot seek.
//!
//! [`ZipWriter`](crate::ZipWriter) needs `Write + Seek` because it records each entry's CRC-32 and
//! sizes by seeking back to patch the local file header. That makes it unusable for a socket, a
//! pipe, or `stdout`.
//!
//! This module takes the other route the format allows: set general-purpose flag bit 3, leave the
//! local header's CRC-32 and sizes zeroed, and emit a **data descriptor** after the payload with
//! the real values. Every implementation written since the mid-1990s understands this — it is what
//! `zip -` and streaming archivers produce.
//!
//! Two consequences worth knowing:
//!
//! * An entry's metadata is not final until the entry ends, so the ZIP64 extra field cannot be
//!   reserved in advance. Entries at or past 4 GiB are **rejected** rather than truncated.
//! * Encryption is refused, because it needs the payload length before the descriptor is written.
//!
//! For a seekable sink prefer [`ZipWriter`](crate::ZipWriter): no data descriptors are needed and
//! the result is the more widely compatible layout.

use std::io::Write;

use crate::entry::Compression;
use crate::error::{Error, Result};
use crate::spec::{
    DATA_DESCRIPTOR_SIG, FLAG_DATA_DESCRIPTOR, FLAG_UTF8, LOCAL_FILE_HEADER_SIG, METHOD_DEFLATE,
    METHOD_STORED,
};
use crate::write::{
    check_name_len, new_deflate_encoder, write_archive_trailer, CentralRecord, Encoder,
    FileOptions, WriteOptions, OUT_BUF_SIZE,
};
use crate::{dos, spec};

/// Writes a ZIP archive to a sink that can only be written forwards.
///
/// ```no_run
/// use zipcore::stream::ZipStreamWriter;
/// use zipcore::FileOptions;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut writer = ZipStreamWriter::new(std::io::stdout())?;
/// writer.add_file("hello.txt", b"hi", &FileOptions::default())?;
/// writer.finish()?;
/// # Ok(())
/// # }
/// ```
pub struct ZipStreamWriter<W: Write> {
    sink: W,
    options: WriteOptions,
    records: Vec<CentralRecord>,
    /// Bytes written so far, tracked so entry offsets need no `seek`.
    position: u64,
    current: Option<Pending>,
    finished: bool,
}

impl<W: Write> std::fmt::Debug for ZipStreamWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipStreamWriter")
            .field("entries", &self.records.len())
            .field("position", &self.position)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// State for the entry currently being written.
struct Pending {
    encoded_name: Vec<u8>,
    flags: u16,
    method: u16,
    dos_date: u16,
    dos_time: u16,
    header_offset: u64,
    external_attrs: u32,
    encoder: Encoder,
    crc: crc32fast::Hasher,
    uncompressed: u64,
    compressed: u64,
    out_buf: Vec<u8>,
}

impl<W: Write> ZipStreamWriter<W> {
    /// Start an archive with default options.
    pub fn new(sink: W) -> Result<Self> {
        Self::new_with_options(sink, WriteOptions::default())
    }

    /// Start an archive with explicit options.
    pub fn new_with_options(sink: W, options: WriteOptions) -> Result<Self> {
        if options.password.is_some() {
            return Err(Error::malformed(
                "the streaming writer cannot encrypt: a data descriptor is written after the \
                 payload, but encryption needs the payload length first. Use ZipWriter for \
                 encrypted archives",
            ));
        }
        Ok(Self {
            sink,
            options,
            records: Vec::new(),
            position: 0,
            current: None,
            finished: false,
        })
    }

    /// Write a whole entry from a slice.
    pub fn add_file(&mut self, name: &str, data: &[u8], options: &FileOptions) -> Result<()> {
        let mut entry = self.start_file(name, options)?;
        entry.write_all(data).map_err(Error::Io)?;
        entry.finish()
    }

    /// Write a directory entry.
    pub fn add_directory(&mut self, name: &str, options: &FileOptions) -> Result<()> {
        let mut name = name.to_string();
        if !name.ends_with('/') {
            name.push('/');
        }
        self.add_file(
            &name,
            b"",
            &FileOptions {
                compression: Compression::Stored,
                ..options.clone()
            },
        )
    }

    /// Begin an entry whose payload will arrive in pieces.
    ///
    /// The returned writer must be finished (or dropped) before another entry starts.
    pub fn start_file(&mut self, name: &str, options: &FileOptions) -> Result<StreamEntry<'_, W>> {
        self.begin_entry(name, options)?;
        Ok(StreamEntry { zip: self })
    }

    /// Finish the archive, returning the sink.
    pub fn finish(mut self) -> Result<W> {
        self.finish_inner()?;
        self.sink.flush().map_err(Error::Io)?;
        Ok(self.sink)
    }

    /// Finish the archive, leaving the sink borrowed.
    pub fn finish_ref(&mut self) -> Result<()> {
        self.finish_inner()?;
        self.sink.flush().map_err(Error::Io)
    }

    fn finish_inner(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        let comment = self
            .options
            .comment
            .as_ref()
            .map(|text| text.as_bytes().to_vec());
        // The central directory starts exactly where the last entry ended.
        write_archive_trailer(&mut self.sink, &self.records, comment, self.position)?;
        self.finished = true;
        Ok(())
    }

    /// Emit a local header with flag bit 3 set and the sizes deferred to the descriptor.
    fn begin_entry(&mut self, name: &str, options: &FileOptions) -> Result<()> {
        if self.finished {
            return Err(Error::WriterFailed {
                detail: "the archive has already been finished".to_string(),
            });
        }
        if self.current.is_some() {
            return Err(Error::WriterFailed {
                detail: "an entry is still in progress".to_string(),
            });
        }
        if options.encryption.is_some() {
            return Err(Error::malformed(
                "the streaming writer cannot encrypt entries; use ZipWriter",
            ));
        }

        let encoded_name = name.as_bytes().to_vec();
        if encoded_name.is_empty() {
            return Err(Error::malformed("entry name must not be empty"));
        }
        check_name_len(&encoded_name)?;

        let method = match options.compression {
            Compression::Stored => METHOD_STORED,
            Compression::Deflate => METHOD_DEFLATE,
            other => {
                return Err(Error::UnsupportedCompression {
                    entry: name.to_string(),
                    method: other.method_id(),
                })
            }
        };

        let mut flags = FLAG_DATA_DESCRIPTOR;
        if !encoded_name.is_ascii() {
            flags |= FLAG_UTF8;
        }

        let (dos_date, dos_time) = match options.unix_mtime {
            Some(unix) => dos::from_unix_seconds(unix),
            None => options.dos_timestamp.unwrap_or_else(dos::now),
        };

        let mut header = Vec::with_capacity(30 + encoded_name.len());
        header.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        header.extend_from_slice(&20u16.to_le_bytes()); // version needed
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&dos_time.to_le_bytes());
        header.extend_from_slice(&dos_date.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // CRC-32 -> descriptor
        header.extend_from_slice(&0u32.to_le_bytes()); // compressed size -> descriptor
        header.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size -> descriptor
        header.extend_from_slice(&(encoded_name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes()); // no extra fields
        header.extend_from_slice(&encoded_name);

        let header_offset = self.position;
        self.emit(&header)?;

        let external_attrs = match options.unix_mode {
            Some(mode) => (mode << 16) | 0x20,
            None => 0x20,
        };

        self.current = Some(Pending {
            encoded_name,
            flags,
            method,
            dos_date,
            dos_time,
            header_offset,
            external_attrs,
            encoder: match method {
                METHOD_STORED => Encoder::Stored,
                _ => new_deflate_encoder(options.compression_level),
            },
            crc: crc32fast::Hasher::new(),
            uncompressed: 0,
            compressed: 0,
            out_buf: vec![0u8; OUT_BUF_SIZE],
        });
        Ok(())
    }

    /// Push payload bytes through the compressor.
    fn push(&mut self, data: &[u8]) -> Result<()> {
        let pending = self.current.as_mut().ok_or(Error::NoEntryInProgress)?;
        pending.crc.update(data);
        pending.uncompressed += data.len() as u64;

        let produced = encode(&mut pending.encoder, &mut pending.out_buf, data, false)?;
        let compressed = produced.len() as u64;
        pending.compressed += compressed;

        self.sink.write_all(&produced).map_err(Error::Io)?;
        self.position += compressed;
        Ok(())
    }

    /// Flush the compressor, write the data descriptor and record the entry.
    fn end_entry(&mut self) -> Result<()> {
        let mut pending = match self.current.take() {
            Some(pending) => pending,
            None => return Ok(()),
        };

        let tail = encode(&mut pending.encoder, &mut pending.out_buf, &[], true)?;
        pending.compressed += tail.len() as u64;
        self.sink.write_all(&tail).map_err(Error::Io)?;
        self.position += tail.len() as u64;

        if pending.compressed >= u32::MAX as u64 || pending.uncompressed >= u32::MAX as u64 {
            return Err(Error::Zip64Required {
                entry: String::from_utf8_lossy(&pending.encoded_name).into_owned(),
            });
        }

        let crc32 = pending.crc.clone().finalize();
        let mut descriptor = Vec::with_capacity(16);
        descriptor.extend_from_slice(&DATA_DESCRIPTOR_SIG.to_le_bytes());
        descriptor.extend_from_slice(&crc32.to_le_bytes());
        descriptor.extend_from_slice(&(pending.compressed as u32).to_le_bytes());
        descriptor.extend_from_slice(&(pending.uncompressed as u32).to_le_bytes());
        self.emit(&descriptor)?;

        self.records.push(CentralRecord {
            name: pending.encoded_name,
            flags: pending.flags,
            method: pending.method,
            dos_date: pending.dos_date,
            dos_time: pending.dos_time,
            crc32,
            compressed_size: pending.compressed,
            uncompressed_size: pending.uncompressed,
            header_offset: pending.header_offset,
            external_attrs: pending.external_attrs,
            comment: Vec::new(),
            zip64_sizes: false,
            zip64_offset: false,
            version_made_by: crate::write::version_made_by(spec::ZIP_VERSION_STREAMING),
            unix_mtime: None,
            aes: None,
        });
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<()> {
        self.sink.write_all(bytes).map_err(Error::Io)?;
        self.position += bytes.len() as u64;
        Ok(())
    }
}

/// Drive the shared encoder, returning the bytes it produced.
fn encode(encoder: &mut Encoder, out: &mut [u8], data: &[u8], finish: bool) -> Result<Vec<u8>> {
    crate::write::drive_encoder(encoder, out, data, finish)
}

/// A writer for one entry's payload.
pub struct StreamEntry<'a, W: Write> {
    zip: &'a mut ZipStreamWriter<W>,
}

impl<W: Write> StreamEntry<'_, W> {
    /// Close the entry, writing its data descriptor.
    pub fn finish(self) -> Result<()> {
        self.zip.end_entry()
    }
}

impl<W: Write> Write for StreamEntry<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.zip.push(buf) {
            Ok(()) => Ok(buf.len()),
            Err(Error::Io(error)) => Err(error),
            Err(error) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.zip.sink.flush()
    }
}

impl<W: Write> Drop for StreamEntry<'_, W> {
    fn drop(&mut self) {
        // Dropping without `finish` would leave a dangling entry; close it so the archive stays
        // structurally valid rather than silently losing the data descriptor.
        let _ = self.zip.end_entry();
    }
}
