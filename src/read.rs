use crate::entry::{Compression, Entry};
use crate::error::{Error, Result};
use crate::ReadOptions;
use miniz_oxide::inflate::core::{decompress as core_decompress, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;
use std::io::{self, Read, Seek, SeekFrom};

/// Size of the compressed-input staging buffer.
const IN_BUF_SIZE: usize = 64 * 1024;
/// Size of the decompression output buffer.
///
/// Must exceed the LZ77 window: the tail is retained across refills so that back-references
/// which reach behind the current chunk can still be resolved.
const OUT_BUF_SIZE: usize = 64 * 1024;
/// Maximum DEFLATE back-reference distance, and therefore how much decoded output has to be
/// kept as history when the output buffer is recycled.
const HISTORY_SIZE: usize = 32 * 1024;

/// A view of the archive reader limited to one entry's compressed payload.
///
/// Handed to a codec from another crate, which owns it while it decompresses. This is what makes
/// such a codec usable at all: a zstd or bzip2 decoder wants to own its input, and giving it a
/// bounded borrow of the archive means no payload ever has to be buffered whole.
#[cfg(any(feature = "zstd", feature = "bzip2"))]
struct Bounded<'a, R: Read + Seek> {
    reader: &'a mut R,
    remaining: u64,
}

#[cfg(any(feature = "zstd", feature = "bzip2"))]
impl<'a, R: Read + Seek> Bounded<'a, R> {
    fn new(reader: &'a mut R, remaining: u64) -> Self {
        Self { reader, remaining }
    }
}

#[cfg(any(feature = "zstd", feature = "bzip2"))]
impl<R: Read + Seek> Read for Bounded<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining) as usize;
        let read = self.reader.read(&mut buf[..want])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// What the caller is still permitted to receive.
///
/// Handed to the innermost loops so they can enforce the size limit and the declared size without
/// reaching back into the entry — which would tangle the borrows, since the loops already hold the
/// archive reader mutably.
struct Budget<'e> {
    entry: &'e str,
    produced: u64,
    /// Bytes still permitted by `ReadOptions::max_entry_size`.
    allowance: u64,
    /// The configured limit, for the error message.
    limit: u64,
    /// The declared uncompressed size, when the header states one.
    cap: Option<u64>,
}

impl Budget<'_> {
    /// How much of the declared size is still undelivered.
    fn cap_remaining(&self) -> u64 {
        self.cap
            .map_or(u64::MAX, |cap| cap.saturating_sub(self.produced))
    }

    fn limit_error(&self) -> Error {
        Error::SizeLimitExceeded {
            entry: self.entry.to_string(),
            limit: self.limit,
        }
    }
}

/// Build a budget from field borrows.
///
/// Deliberately a free function taking the fields it needs rather than a method on `ZipFile`:
/// a `&self` method would borrow the whole struct and collide with the `&mut` borrow of the
/// input state that the caller is about to take.
fn budget_for<'e>(
    entry: &'e str,
    options: &ReadOptions,
    produced: u64,
    declared: u64,
) -> Budget<'e> {
    Budget {
        entry,
        produced,
        allowance: match options.max_entry_size {
            Some(limit) => limit.saturating_sub(produced),
            None => u64::MAX,
        },
        limit: options.max_entry_size.unwrap_or(0),
        cap: if declared > 0 { Some(declared) } else { None },
    }
}

/// The incremental inflater, driven with our own buffers.
///
/// Everything is read through this rather than handing the archive to a codec, so a DEFLATE entry
/// costs a fixed amount of memory no matter what the headers claim.
struct DeflateInput<'a, R: Read + Seek> {
    reader: &'a mut R,
    data_start: u64,
    compressed: u64,
    consumed: u64,
    state: Box<DecompressorOxide>,
    in_buf: Vec<u8>,
    in_pos: usize,
    in_len: usize,
    in_eof: bool,
    /// Sliding output window: `out_buf[..out_write]` is valid decoded history and the space from
    /// `out_write` onwards is free.
    out_buf: Vec<u8>,
    out_write: usize,
    /// How much of the decoded output has already been handed to the caller.
    out_served: usize,
    stream_end: bool,
}

impl<'a, R: Read + Seek> DeflateInput<'a, R> {
    fn new(reader: &'a mut R, data_start: u64, compressed: u64) -> Self {
        Self {
            reader,
            data_start,
            compressed,
            consumed: 0,
            state: Box::<DecompressorOxide>::default(),
            in_buf: vec![0u8; IN_BUF_SIZE],
            in_pos: 0,
            in_len: 0,
            in_eof: false,
            out_buf: vec![0u8; OUT_BUF_SIZE],
            out_write: 0,
            out_served: 0,
            stream_end: false,
        }
    }

    /// Hand already-decoded bytes to the caller, enforcing the declared size and the limit.
    fn serve_pending(&mut self, buf: &mut [u8], budget: &Budget<'_>) -> Result<usize> {
        let pending = self.out_write - self.out_served;
        if budget.allowance == 0 && pending > 0 {
            return Err(budget.limit_error());
        }
        let n = (buf.len() as u64)
            .min(pending as u64)
            .min(budget.allowance)
            .min(budget.cap_remaining()) as usize;
        if n == 0 {
            return Ok(0);
        }
        buf[..n].copy_from_slice(&self.out_buf[self.out_served..self.out_served + n]);
        self.out_served += n;
        Ok(n)
    }

    fn read(&mut self, buf: &mut [u8], budget: &Budget<'_>) -> Result<usize> {
        // No compressed payload at all: there is nothing to inflate. Some writers store empty
        // members this way instead of emitting an empty DEFLATE stream.
        if self.compressed == 0 {
            self.stream_end = true;
            return Ok(0);
        }

        loop {
            // 1. Anything decoded but not yet handed out takes priority.
            if self.out_served < self.out_write {
                return self.serve_pending(buf, budget);
            }

            if self.stream_end {
                return Ok(0);
            }

            // 2. Nothing pending: recycle the output buffer, keeping the last window's worth of
            //    decoded data so back-references across the boundary still resolve.
            if self.out_write > HISTORY_SIZE {
                let keep = HISTORY_SIZE;
                self.out_buf
                    .copy_within(self.out_write - keep..self.out_write, 0);
                self.out_write = keep;
                self.out_served = keep;
            }

            if budget.cap_remaining() == 0 {
                // Every declared byte has been delivered.
                return Ok(0);
            }

            // 3. Refill the compressed input while any remains.
            if self.in_pos >= self.in_len && !self.in_eof {
                let remaining = self.compressed.saturating_sub(self.consumed);
                if remaining == 0 {
                    self.in_eof = true;
                } else {
                    let want = (IN_BUF_SIZE as u64).min(remaining) as usize;
                    self.reader
                        .seek(SeekFrom::Start(self.data_start + self.consumed))
                        .map_err(Error::Io)?;
                    // The payload range was bounds-checked when the entry was opened, so a short
                    // read here means the file shrank underneath us.
                    self.reader
                        .read_exact(&mut self.in_buf[..want])
                        .map_err(Error::Io)?;
                    self.consumed += want as u64;
                    self.in_len = want;
                    self.in_pos = 0;
                    self.in_eof = self.consumed >= self.compressed;
                }
            }

            // 4. Decompress with the output buffer as a non-wrapping window.
            let mut flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
            if !self.in_eof {
                flags |= inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;
            }
            let (status, in_consumed, out_consumed) = {
                let in_slice = &self.in_buf[self.in_pos..self.in_len];
                let out_write = self.out_write;
                core_decompress(
                    &mut self.state,
                    in_slice,
                    &mut self.out_buf,
                    out_write,
                    flags,
                )
            };
            self.in_pos += in_consumed;
            self.out_write += out_consumed;

            match status {
                TINFLStatus::Done => self.stream_end = true,
                // The output buffer filled up. It is served on the next iteration.
                TINFLStatus::HasMoreOutput => {}
                TINFLStatus::NeedsMoreInput => {
                    if self.in_eof {
                        // Input exhausted, decoder wants more: truncated. Size and CRC
                        // verification report the mismatch.
                        return Ok(0);
                    }
                }
                other => {
                    return Err(Error::Compression {
                        detail: format!("{other:?}"),
                    })
                }
            }

            if out_consumed > 0 {
                continue;
            }
            if self.stream_end {
                return Ok(0);
            }
            if self.in_pos >= self.in_len {
                if self.in_eof {
                    return Ok(0);
                }
                continue; // fetch the next input chunk
            }
            if in_consumed == 0 {
                return Err(Error::Compression {
                    detail: "decoder made no progress".to_string(),
                });
            }
        }
    }
}

/// Where an entry's decompressed bytes come from.
enum Input<'a, R: Read + Seek> {
    /// Copied straight out of the archive.
    Stored {
        reader: &'a mut R,
        data_start: u64,
        /// Payload length, already clamped by the declared size.
        payload: u64,
        read: u64,
        /// Where the reader is known to be positioned, so a sequential read needs one seek per
        /// entry rather than one per call.
        reader_pos: Option<u64>,
    },
    /// Inflated incrementally with our own buffers.
    Deflate(DeflateInput<'a, R>),
    /// A codec from another crate that owns a bounded view of the archive.
    Codec(Box<dyn Read + 'a>),
    /// Fully decoded plaintext for an encrypted entry.
    ///
    /// Encryption forces this shape: WinZip AES authenticates the entire payload with HMAC before
    /// any of it may be trusted, so the bytes have to be materialised before the first one is
    /// handed out. The size ceiling still applies, and decompression uses the bounded miniz
    /// entry points.
    Plain { data: Vec<u8>, pos: usize },
}

/// Read, decrypt, authenticate and decompress an encrypted entry into memory.
///
/// The whole payload has to be materialised because WinZip AES authenticates it with HMAC before
/// any plaintext may be trusted; releasing bytes progressively would mean handing out data that
/// could still turn out to be forged. Both schemes are also cheap enough that a second streaming
/// path would be more risk than it is worth.
fn decrypt_entry<R: Read + Seek>(
    reader: &mut R,
    entry: &Entry,
    data_start: u64,
    options: &ReadOptions,
) -> Result<Vec<u8>> {
    let password = match &options.password {
        Some(password) => password,
        None => {
            return Err(Error::Encrypted {
                entry: entry.name.clone(),
            })
        }
    };

    // A declared-size ceiling is applied before allocating anything.
    let ceiling = options.max_entry_size;

    reader
        .seek(SeekFrom::Start(data_start))
        .map_err(Error::Io)?;

    // The encrypted payload is the entry's compressed size; it cannot exceed the archive itself,
    // and `compressed_size` was validated against the file length when the directory was parsed.
    // The size was validated against the file length when the directory was parsed, and `read_exact`
    // fails cleanly if the archive is truncated under us.
    let mut sealed = vec![0u8; entry.compressed_size as usize];
    reader.read_exact(&mut sealed).map_err(Error::Io)?;

    let scheme = encryption_scheme(entry)?;
    #[allow(unreachable_patterns)]
    let plain = match scheme {
        crate::crypto::Scheme::ZipCrypto => {
            // The 12-byte header's check byte, then the payload.
            let check = if entry.flags() & crate::spec::FLAG_DATA_DESCRIPTOR != 0 {
                crate::crypto::zipcrypto::CheckByte::DosTime(entry.dos_timestamp().1)
            } else {
                crate::crypto::zipcrypto::CheckByte::Crc(entry.crc32())
            };
            if sealed.len() < crate::crypto::zipcrypto::HEADER_LEN {
                return Err(Error::malformed(
                    "encrypted entry is shorter than its header",
                ));
            }
            crate::crypto::zipcrypto::decrypt(password, check, &sealed)?
        }
        #[cfg(feature = "aes-crypto")]
        crate::crypto::Scheme::Aes(strength) => {
            crate::crypto::aes::decrypt(password, strength, &sealed)?
        }
        // Without the feature the entry is reported as needing it.
        #[allow(unreachable_patterns)]
        _ => unreachable!("AES without the feature is rejected by encryption_scheme"),
    };

    // Now decompress the plaintext according to the real method.
    let method = entry
        .aes
        .map(|info| info.actual_method)
        .unwrap_or_else(|| entry.method());
    let out = match Compression::from_method(method) {
        Compression::Stored => plain,
        Compression::Deflate => {
            let limit = ceiling.unwrap_or(u64::MAX);
            if plain.len() as u64 > limit.saturating_mul(1032) {
                // A DEFLATE stream cannot expand by more than ~1032x.
                return Err(Error::SizeLimitExceeded {
                    entry: entry.name.clone(),
                    limit,
                });
            }
            miniz_oxide::inflate::decompress_to_vec(&plain).map_err(|_| {
                Error::malformed("encrypted entry's payload is not a valid DEFLATE stream")
            })?
        }
        #[cfg(feature = "zstd")]
        Compression::Zstd => zstd::stream::decode_all(plain.as_slice()).map_err(Error::Io)?,
        #[cfg(feature = "bzip2")]
        Compression::Bzip2 => {
            let mut out = Vec::new();
            bzip2::read::BzDecoder::new(plain.as_slice())
                .read_to_end(&mut out)
                .map_err(Error::Io)?;
            out
        }
        other => {
            return Err(Error::UnsupportedCompression {
                entry: entry.name.clone(),
                method: other.method_id(),
            })
        }
    };

    if let Some(limit) = ceiling {
        if out.len() as u64 > limit {
            return Err(Error::SizeLimitExceeded {
                entry: entry.name.clone(),
                limit,
            });
        }
    }
    Ok(out)
}

/// Which encryption scheme an entry uses, or an error explaining what is missing.
fn encryption_scheme(entry: &Entry) -> Result<crate::crypto::Scheme> {
    if entry.method() == crate::spec::METHOD_WINZIP_AES || entry.aes.is_some() {
        #[cfg(feature = "aes-crypto")]
        {
            let strength = entry
                .aes
                .and_then(|info| crate::crypto::aes::Strength::from_byte(info.strength))
                .ok_or_else(|| {
                    Error::malformed("WinZip AES entry has a missing or invalid strength byte")
                })?;
            return Ok(crate::crypto::Scheme::Aes(strength));
        }
        #[cfg(not(feature = "aes-crypto"))]
        {
            return Err(Error::UnsupportedCompression {
                entry: entry.name.clone(),
                method: crate::spec::METHOD_WINZIP_AES,
            });
        }
    }
    Ok(crate::crypto::Scheme::ZipCrypto)
}

/// Build the decoder for a method handled by an external codec.
#[allow(unused_variables)]
fn build_codec<'a, R: Read + Seek>(
    reader: &'a mut R,
    entry: &Entry,
    data_start: u64,
    compression: Compression,
) -> Result<Box<dyn Read + 'a>> {
    match compression {
        #[cfg(feature = "zstd")]
        Compression::Zstd => {
            reader
                .seek(SeekFrom::Start(data_start))
                .map_err(Error::Io)?;
            let bounded = Bounded::new(reader, entry.compressed_size);
            let decoder = zstd::stream::read::Decoder::new(bounded).map_err(Error::Io)?;
            // Each ZIP member is exactly one zstd frame, so stopping at the frame boundary keeps
            // the decoder from reading bytes that belong to the next entry.
            Ok(Box::new(decoder.single_frame()))
        }
        #[cfg(feature = "bzip2")]
        Compression::Bzip2 => {
            reader
                .seek(SeekFrom::Start(data_start))
                .map_err(Error::Io)?;
            let bounded = Bounded::new(reader, entry.compressed_size);
            // A bzip2 member is a complete stream, so it ends where the stream says it does.
            Ok(Box::new(bzip2::read::BzDecoder::new(bounded)))
        }
        other => Err(Error::UnsupportedCompression {
            entry: entry.name.clone(),
            method: other.method_id(),
        }),
    }
}

/// A streaming reader over a single archive entry.
///
/// Implements [`Read`]. CRC-32 and size verification happen when the entry is read to the end; a
/// partial read is not verified. Use [`Archive::read_entry`](crate::Archive::read_entry) or
/// [`Read::read_to_end`] if you want verification to have run.
pub struct ZipFile<'a, R: Read + Seek> {
    entry: Entry,
    options: ReadOptions,
    input: Input<'a, R>,
    /// Total bytes handed to the caller.
    produced: u64,
    crc: crc32fast::Hasher,
    finished: bool,
    /// Set once the entry fails terminally. `Read` can only report `io::Error`, so the structured
    /// cause is kept here, and every later read repeats the failure instead of being downgraded to
    /// a clean end of stream.
    terminal_error: Option<Error>,
}

impl<R: Read + Seek> std::fmt::Debug for ZipFile<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written so that `R` does not have to be `Debug`.
        f.debug_struct("ZipFile")
            .field("name", &self.entry.name)
            .field("compressed_size", &self.entry.compressed_size)
            .field("uncompressed_size", &self.entry.uncompressed_size)
            .field("bytes_produced", &self.produced)
            .finish_non_exhaustive()
    }
}

impl<'a, R: Read + Seek> ZipFile<'a, R> {
    pub(crate) fn new(
        reader: &'a mut R,
        entry: Entry,
        data_start: u64,
        options: ReadOptions,
    ) -> Result<Self> {
        // An encrypted entry is fully decrypted (and, for AES, authenticated) before anything is
        // handed out, so it bypasses the streaming paths entirely.
        if entry.is_encrypted() {
            let data = decrypt_entry(reader, &entry, data_start, &options)?;
            return Ok(ZipFile {
                entry,
                options,
                input: Input::Plain { data, pos: 0 },
                produced: 0,
                crc: crc32fast::Hasher::new(),
                finished: false,
                terminal_error: None,
            });
        }

        let compression = entry.compression();
        let input = match compression {
            Compression::Stored => {
                // Clamping by the declared size as well means a header that disagrees with itself
                // cannot make us hand out more bytes than it claims.
                let cap = if entry.uncompressed_size > 0 {
                    entry.uncompressed_size
                } else {
                    u64::MAX
                };
                Input::Stored {
                    reader,
                    data_start,
                    payload: entry.compressed_size.min(cap),
                    read: 0,
                    reader_pos: None,
                }
            }
            Compression::Deflate => {
                Input::Deflate(DeflateInput::new(reader, data_start, entry.compressed_size))
            }
            // `Archive` rejects every method this build cannot handle before we get here, so a
            // failure is a bug rather than a caller error — but it is still reported, not panicked.
            other => Input::Codec(build_codec(reader, &entry, data_start, other)?),
        };

        Ok(ZipFile {
            entry,
            options,
            input,
            produced: 0,
            crc: crc32fast::Hasher::new(),
            finished: false,
            terminal_error: None,
        })
    }

    /// Metadata for the entry being read.
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    /// Number of decompressed bytes handed to the caller so far.
    pub fn bytes_produced(&self) -> u64 {
        self.produced
    }

    /// Record a terminal failure and express it as the `io::Error` that `Read` permits.
    fn fail(&mut self, error: Error) -> io::Error {
        let message = error.to_string();
        self.terminal_error = Some(error);
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    /// Re-raise the latched failure, so a failed entry stays failed.
    fn latched(&self) -> Option<io::Error> {
        self.terminal_error
            .as_ref()
            .map(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    /// Take the structured cause of a terminal failure, if one occurred.
    ///
    /// [`Read`] can only report [`io::Error`], so a CRC-32 mismatch, a size mismatch or a reached
    /// limit is surfaced as an `InvalidData` error. This recovers the specific [`Error`] behind it.
    pub fn take_terminal_error(&mut self) -> Option<Error> {
        self.terminal_error.take()
    }

    /// The structured terminal failure, if one occurred.
    pub fn terminal_error(&self) -> Option<&Error> {
        self.terminal_error.as_ref()
    }

    /// Run the CRC-32 and size checks now, without reading the rest of the entry.
    ///
    /// Verification normally happens when the stream ends. This lets a caller that already has
    /// every byte it wants (for example one that streamed the payload straight to a file) put the
    /// result on record before it keeps or discards the output.
    ///
    /// Fails if the entry has not been read to the end: a partial payload has not been verified
    /// and must not be reported as if it had been.
    pub fn verify_to_end(&mut self) -> Result<()> {
        if let Some(error) = self.terminal_error.as_ref() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, error.to_string()).into());
        }
        if !self.finished {
            // Drain the remainder so the CRC and size reflect the whole entry.
            let mut scratch = [0u8; 8 * 1024];
            loop {
                match self.read(&mut scratch) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(io_error) => {
                        return Err(self.terminal_error.take().unwrap_or(Error::Io(io_error)))
                    }
                }
            }
        }
        self.verify()
            .map_err(|io_error| self.terminal_error.take().unwrap_or(Error::Io(io_error)))
    }

    fn verification_failure(&self) -> Option<Error> {
        if self.options.verify_size {
            // Compared unconditionally. Treating a declared size of zero as "unknown" would let an
            // archive switch this check off simply by writing zero in that field.
            let expected = self.entry.uncompressed_size;
            if self.produced != expected {
                return Some(Error::SizeMismatch {
                    entry: self.entry.name.clone(),
                    expected,
                    actual: self.produced,
                });
            }
        }
        if self.options.verify_crc {
            let actual = self.crc.clone().finalize();
            // AE-2 (the WinZip AES convention) deliberately writes a zero CRC-32 because the
            // HMAC already authenticates the payload; checking it would reject every such entry.
            let crc_is_meaningful = !(self.entry.is_aes()
                && self.entry.aes.is_some_and(|info| info.vendor_version >= 2)
                && self.entry.crc32 == 0);
            if crc_is_meaningful && actual != self.entry.crc32 {
                return Some(Error::CrcMismatch {
                    entry: self.entry.name.clone(),
                    expected: self.entry.crc32,
                    actual,
                });
            }
        }
        None
    }

    fn verify(&mut self) -> io::Result<()> {
        match self.verification_failure() {
            None => Ok(()),
            Some(error) => Err(self.fail(error)),
        }
    }

    fn read_stored(&mut self, buf: &mut [u8]) -> Result<usize> {
        let budget = budget_for(
            self.entry.name.as_str(),
            &self.options,
            self.produced,
            self.entry.uncompressed_size,
        );
        let Input::Stored {
            reader,
            data_start,
            payload,
            read,
            reader_pos,
        } = &mut self.input
        else {
            unreachable!("read_stored called for a non-stored entry");
        };

        let remaining = payload.saturating_sub(*read);
        if remaining == 0 {
            return Ok(0);
        }
        if budget.allowance == 0 {
            return Err(budget.limit_error());
        }
        let want = (buf.len() as u64).min(remaining).min(budget.allowance) as usize;

        let target = *data_start + *read;
        // A stored entry is read strictly forwards, so only the first call needs to seek.
        if *reader_pos != Some(target) {
            reader.seek(SeekFrom::Start(target)).map_err(Error::Io)?;
        }
        let n = reader.read(&mut buf[..want]).map_err(Error::Io)?;
        *reader_pos = Some(target + n as u64);
        *read += n as u64;
        Ok(n)
    }

    fn read_deflate(&mut self, buf: &mut [u8]) -> Result<usize> {
        let budget = budget_for(
            self.entry.name.as_str(),
            &self.options,
            self.produced,
            self.entry.uncompressed_size,
        );
        match &mut self.input {
            Input::Deflate(state) => state.read(buf, &budget),
            _ => unreachable!("read_deflate called for a non-deflate entry"),
        }
    }

    fn read_codec(&mut self, buf: &mut [u8]) -> Result<usize> {
        let budget = budget_for(
            self.entry.name.as_str(),
            &self.options,
            self.produced,
            self.entry.uncompressed_size,
        );
        if budget.cap_remaining() == 0 {
            // Every declared byte has been delivered.
            return Ok(0);
        }
        if budget.allowance == 0 {
            return Err(budget.limit_error());
        }
        let want = (buf.len() as u64)
            .min(budget.allowance)
            .min(budget.cap_remaining()) as usize;

        match &mut self.input {
            // The codec reads through its bounded view of the archive, so the output is clamped
            // here rather than by the codec: nothing else bounds how much a hostile stream expands.
            Input::Codec(decoder) => decoder.read(&mut buf[..want]).map_err(Error::Io),
            _ => unreachable!("read_codec called for an entry with no codec"),
        }
    }

    fn read_plain(&mut self, buf: &mut [u8]) -> Result<usize> {
        let budget = budget_for(
            self.entry.name.as_str(),
            &self.options,
            self.produced,
            self.entry.uncompressed_size,
        );
        let Input::Plain { data, pos } = &mut self.input else {
            unreachable!("read_plain called for a non-plain entry");
        };
        let remaining = data.len().saturating_sub(*pos);
        if remaining == 0 {
            return Ok(0);
        }
        if budget.allowance == 0 {
            return Err(budget.limit_error());
        }
        let want = buf.len().min(remaining).min(budget.allowance as usize);
        buf[..want].copy_from_slice(&data[*pos..*pos + want]);
        *pos += want;
        Ok(want)
    }
}

impl<R: Read + Seek> Read for ZipFile<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A failed entry stays failed. Without this, the `finished` flag set when verification
        // fails would turn the next read into a clean end of stream, and a caller that retried
        // would see success on corrupt data.
        if let Some(error) = self.latched() {
            return Err(error);
        }
        if buf.is_empty() || self.finished {
            return Ok(0);
        }

        let stored = matches!(self.input, Input::Stored { .. });
        let deflate = matches!(self.input, Input::Deflate(_));
        let plain = matches!(self.input, Input::Plain { .. });
        let outcome = if stored {
            self.read_stored(buf)
        } else if deflate {
            self.read_deflate(buf)
        } else if plain {
            self.read_plain(buf)
        } else {
            self.read_codec(buf)
        };

        let n = match outcome {
            Ok(n) => n,
            Err(error) => return Err(self.fail(error)),
        };
        if n == 0 {
            self.finished = true;
            self.verify()?;
            return Ok(0);
        }
        self.crc.update(&buf[..n]);
        self.produced += n as u64;
        Ok(n)
    }
}
