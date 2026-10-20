# zipcore

**A ZIP reader and writer you can audit in an afternoon: no `unsafe`, three direct dependencies, and every failure a named error.**

[![Crates.io](https://img.shields.io/crates/v/zipcore.svg)](https://crates.io/crates/zipcore)
[![Downloads](https://img.shields.io/crates/d/zipcore.svg)](https://crates.io/crates/zipcore)
[![Documentation](https://docs.rs/zipcore/badge.svg)](https://docs.rs/zipcore)
[![CI](https://github.com/EdisonJwa/zipcore-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/EdisonJwa/zipcore-rs/actions/workflows/ci.yml)
[![dependencies](https://img.shields.io/badge/dependencies-3-brightgreen.svg)](#why-zipcore)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)](SECURITY.md)

`zipcore` implements the ZIP container from the PKWARE APPNOTE — local headers, central directory,
ZIP64 records, data descriptors, extra fields — plus the Stored and Deflate codecs, streaming in both
directions. It reads and writes `.zip`, `.xlsx`, `.docx`, `.epub` and `.jar`, reads split volumes, and
writes `tar` and `tar.zst`. It is built for the part of your program that parses bytes you did not
produce.

```rust
use std::io::Cursor;
use zipcore::{Archive, FileOptions, ZipWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read: metadata first, data only when asked for.
    let mut archive = Archive::open("book.xlsx")?;
    for entry in archive.entries() {
        println!("{} ({} bytes)", entry.name(), entry.uncompressed_size());
    }
    println!("first entry is {} bytes", archive.read_entry(0)?.len());

    // Write: Stored and Deflate, streamed through the codec.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("hello.txt", b"hello", &FileOptions::default())?;
    writer.add_directory("docs", &FileOptions::default())?;
    std::fs::write("out.zip", writer.finish()?.into_inner())?;
    Ok(())
}
```

## Why zipcore

**Three direct dependencies.** The default build depends on `miniz_oxide`, `crc32fast` and
`getrandom` — five crates after transitive resolution, all pure Rust, no C toolchain, no build script
that compiles anything. A ZIP parser reads attacker-controlled bytes, so its dependency tree is attack
surface; this one fits on one screen.

**No `unsafe`, enforced in CI.** `#![forbid(unsafe_code)]` on the crate, plus a workflow step that
greps `src/` for the keyword rather than trusting the attribute. For scale: `zip` 9.0.5 contains 27
`unsafe` occurrences across its 47 source files; this crate contains zero.

**Errors you can match on.** Every failure is a named variant, and `Error::kind()` groups them into
categories (`Malformed`, `Unsupported`, `Password`, `LimitExceeded`, `IntegrityFailure`, …) so a
caller decides what to do without string-matching. A corrupt archive is never returned as data, and a
failed extraction never leaves a partial file behind.

**Behaviour is specified and tested.** Every limit has a documented default, and every failure is a
named error variant rather than a number or a silent truncation. 251 tests plus 7 doctests cover the
`--all-features` build, a deterministic suite corrupts valid archives 5,500 ways and requires zero
panics, a `cargo-fuzz` target runs in CI, and encryption is checked against real 7-Zip 25.01 and
`pyzipper` 0.4.0 archives.

### Comparison with `zip` 9.0.5

| | zipcore | `zip` 9.0.5 |
| --- | --- | --- |
| Direct dependencies enabled by default | **3** | 17 of 25 declared |
| `unsafe` in `src/` | **0** | 27 occurrences |
| Archive comment / append / copy without recompressing | **yes** | yes |
| Codec breadth | Stored, Deflate, Zstd; decode Deflate64, LZMA, XZ, PPMd, Bzip2 | broader, including the legacy DOS methods |
| `tar.zst` writer | **yes** | no — ZIP only |
| Split volumes (`.zip.001`, `.zip.002`, …) | **yes** | no |
| Encryption | ZipCrypto + WinZip AES-128/192/256 read, 128/256 write | ZipCrypto + WinZip AES |

### When `zip` is the better choice

- **You need a decoder for everything.** `zip` ships more methods by default, including the legacy
  shrink/reduce/implode family, which this crate names in errors instead of decoding.
- **You need floppy-era spanning**, where one entry crosses disks. This crate reads split volumes —
  the `.zip.001` convention and 7-Zip's `-v` switch — and refuses true spans.
- **You want the widest possible field testing.** `zip` has years of production exposure this crate
  does not, and a much larger user base finding the edge cases first.

## Install

```
cargo add zipcore
```

Optional capability is opt-in, each feature a deliberate trade of dependency surface for a method:

| Feature | Adds | Enables |
| --- | --- | --- |
| `zstd` | 1 direct dep (`zstd`, builds C via `zstd-sys`) | read and write method 93, plus `tar.zst` |
| `bzip2` | 1 (`bzip2` with the pure-Rust `libbz2-rs-sys` backend) | read method 12 |
| `deflate-zlib-rs` | 1 (`flate2` with the `zlib-rs` backend, pure Rust) | ~2× faster Deflate compression |
| `aes-crypto` | 6 (`aes`, `ctr`, `hmac`, `sha1`, `pbkdf2`, `zeroize`) | WinZip AES-128/256, read and write |
| `deflate64` | 1 (`deflate64`, pure Rust) | read method 9 |
| `lzma` | 1 (`lzma-rs`, pure Rust) | read method 14 (LZMA) and 95 (XZ) |
| `ppmd` | 1 (`ppmd-rust`, pure Rust) | read method 98 |

Traditional PKWARE ("ZipCrypto") encryption needs no feature. A method the build cannot handle fails
with an error that names it and points at the feature:

```text
entry `data.bin` uses compression method 93 (zstd), which this build does not support;
rebuild with the `zstd` feature to enable it
```

**Compiler requirements.** Rust 1.85 or later for the default build; `deflate64` raises that to 1.87
and `aes-crypto` to 1.89. This floor is not a selling point — it is simply what the dependencies need
today, and it rises when they do. `scripts/msrv-check.ps1` builds one job per row so a dependency bump
cannot move it silently.

## Reading

Entry data is decompressed lazily and never has to be held in memory. Metadata comes from the central
directory; a streaming read verifies CRC-32 and declared size as it goes.

```rust
use std::io::Read;
use zipcore::{Archive, ReadOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = Archive::open("data.zip")?;
    println!("{} entries, ZIP64: {}", archive.len(), archive.is_zip64());

    // Metadata only: this decompresses nothing.
    for entry in archive.entries() {
        println!("{:<32} {:>10}", entry.name(), entry.uncompressed_size());
    }

    // Buffer one entry whole, bounded by `ReadOptions::max_entry_size` (default 1 GiB).
    let icon = archive.read_entry(0)?;

    // Or stream it. CRC-32 and size are checked at end of stream; the borrow is scoped so the
    // archive can be used again afterwards.
    let mut text = String::new();
    {
        let mut file = archive.by_name("docs/readme.md")?;
        file.read_to_string(&mut text)?;
    }

    // Per-open tuning, including decryption:
    let options = ReadOptions::default()
        .with_max_entry_size(Some(16 * 1024 * 1024))
        .with_password("correct horse battery staple");
    let _tuned = Archive::new_with_options(std::fs::File::open("data.zip")?, options)?;
    println!("{} bytes of text, {} of icon", text.len(), icon.len());
    Ok(())
}
```

`ReadOptions::unlimited()` removes the 1 GiB ceiling for archives you produced, and
`offset_correction` (on by default) recovers archives with a prepended self-extractor stub.

## Writing

`ZipWriter` needs a `Write + Seek` sink: it writes each local header with placeholder sizes, streams
the compressed payload, then seeks back and patches the real CRC-32 and sizes in. That produces
archives without data descriptors — the most widely compatible shape — and keeps memory flat.

```rust
use std::io::{Cursor, Write};
use zipcore::{FileOptions, ZipWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;

    writer.add_file("hello.txt", b"hello", &FileOptions::default())?;
    writer.add_file("raw.bin", &[0u8; 4096], &FileOptions::stored())?;

    // Metadata is per entry: Unix mode, exact-second mtime, comment, symlinks.
    let script = FileOptions::default()
        .with_unix_mode(0o100_755)
        .with_unix_mtime(Some(1_709_210_097));
    writer.add_file("script.sh", b"#!/bin/sh\n", &script)?;
    writer.add_symlink("latest", "releases/v2", &FileOptions::default())?;

    // Stream a payload in pieces instead of holding it in memory.
    let mut entry = writer.start_file("streamed.log", &FileOptions::deflate(9))?;
    for line in ["first\n", "second\n", "third\n"] {
        entry.write_all(line.as_bytes())?;
    }
    entry.finish()?;

    println!("{} bytes", writer.finish()?.into_inner().len());
    Ok(())
}
```

`ZipWriter::new` **refuses a sink that already holds bytes**, so an existing archive cannot be
silently destroyed. The rest of the writer API — appending, byte-faithful copying, and entries too
large for a 32-bit size field — works the same way:

```rust
use std::io::Cursor;
use zipcore::{Archive, FileOptions, ZipWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Append: parse the old central directory and rewrite it after the new entries.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("first.txt", b"one", &FileOptions::default())?;
    let existing = writer.finish()?.into_inner();
    let mut writer = ZipWriter::new_append(Cursor::new(existing.clone()), Cursor::new(existing))?;
    writer.add_file("second.txt", b"two", &FileOptions::default())?;
    let appended = writer.finish()?.into_inner();
    assert_eq!(Archive::new(Cursor::new(appended))?.len(), 2);

    // Re-wrap without recompressing: payloads are copied verbatim, so a 660 MB archive copies in
    // the time it takes to move the bytes. A preserved entry keeps its source's method, CRC-32 and
    // sizes, so one this crate cannot decode copies faithfully and stays undecodable.
    let mut source = Archive::open("in.zip")?;
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let copied = writer.copy_from(&mut source)?;
    println!("copied {copied} entries");

    // 4 GiB+: sizes are only known after the payload is written, but the ZIP64 extra field must be
    // reserved before it, so declare the size up front. Without a hint, an entry that grows past
    // 4 GiB fails with `Error::Zip64Required` rather than truncating its size field.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let big = FileOptions::default().with_size_hint(5 * 1024 * 1024 * 1024);
    writer.add_file("huge.bin", b"...", &big)?;
    let bytes = writer.finish()?.into_inner();
    // The local header reserved a 20-byte ZIP64 extended-information field.
    assert_eq!(u16::from_le_bytes([bytes[28], bytes[29]]), 20);
    Ok(())
}
```

## Encryption

**ZipCrypto** (traditional PKWARE) needs no feature and reads the large back-catalogue of old
encrypted archives. It is **not secure** — the keystream is recoverable from roughly a dozen bytes of
known plaintext — so use it for compatibility, never for confidentiality.

**WinZip AES** requires the `aes-crypto` feature and is what you want for actual secrecy. Entries are
written as AE-2: method 99, a `0x9901` extra field, and a zero CRC-32 because the HMAC authenticates
the payload. Payloads are decrypted and authenticated before any plaintext is returned, so a forged
entry fails instead of leaking unauthenticated data.

```rust
use std::io::Cursor;
use zipcore::{Archive, Encryption, FileOptions, ReadOptions, WriteOptions, ZipWriter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = b"correct horse battery staple".to_vec();

    // The archive-level password lives on `WriteOptions`; the scheme is chosen per entry.
    let options = WriteOptions { password: Some(password.clone()), ..WriteOptions::default() };
    let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options)?;
    let file = FileOptions { encryption: Some(Encryption::Aes256), ..FileOptions::default() };
    writer.add_file("secret.txt", b"classified", &file)?;
    let bytes = writer.finish()?.into_inner();

    let mut archive = Archive::new_with_options(
        Cursor::new(bytes),
        ReadOptions::default().with_password(password),
    )?;
    assert_eq!(archive.read_entry(0)?, b"classified");
    Ok(())
}
```

Passwords are `Vec<u8>`, not `String`: the formats encrypt raw bytes, and a password is not
necessarily UTF-8. A wrong password is `Error::WrongPassword` (`error::Kind::Password`), not a CRC
mismatch on garbage.

## Streaming to a sink that cannot seek

Sockets, pipes and `stdout` cannot be seeked, so `ZipWriter` does not apply. `ZipStreamWriter` takes
the other route the format allows: general-purpose flag bit 3, zeroed sizes in the local header, and a
data descriptor after each payload — the layout `zip -` and other streaming archivers produce.

```rust
use std::io::{Cursor, Write};
use zipcore::stream::ZipStreamWriter;
use zipcore::FileOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = ZipStreamWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("hello.txt", b"hi", &FileOptions::default())?;

    let mut entry = writer.start_file("log.txt", &FileOptions::default())?;
    entry.write_all(b"line one\n")?;
    entry.finish()?;

    println!("{} bytes, no seeks", writer.finish()?.into_inner().len());
    Ok(())
}
```

Two constraints follow from the format, not from this implementation: **entries at or past 4 GiB are
refused** (the ZIP64 field cannot be reserved for a size unknown until the descriptor is written),
and **encryption is refused** (it needs the payload length first). When the sink can seek, prefer
`ZipWriter`: no descriptors, and the more widely compatible layout.

## Extraction safety

Extraction is where an archive escapes its destination, so the guards are specific and on by default:

```rust
use zipcore::{Archive, AtomicWrite, ExtractLimits, Overwrite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = Archive::open("untrusted.zip")?;
    let limits = ExtractLimits {
        max_entries: Some(10_000),
        max_total_bytes: Some(256 * 1024 * 1024),
        overwrite: Overwrite::Never,
        atomic_write: AtomicWrite::Enabled,
    };
    let report = archive.extract_all_with_limits(std::path::Path::new("out"), &limits)?;
    println!("{} files, {} bytes", report.written.len(), report.total_bytes);
    println!("skipped symlinks: {:?}", report.skipped_symlinks);
    Ok(())
}
```

- **Names are sanitised before any path is built**: absolute paths, drive prefixes, `..` traversal,
  alternate data streams, and Windows device names in every spelling Win32 resolves — `CON`/`NUL`,
  `COM0`–`COM9`, `LPT0`–`LPT9`, `CONIN$`/`CONOUT$`/`CLOCK$`, and the superscript-digit variants.
- **Containment is checked on the filesystem, not just the string.** The destination is canonicalised
  and a write whose resolved target lands outside it is refused, which is what covers a pre-existing
  junction or file symlink already planted in the destination.
- **No partial files.** With `AtomicWrite::Enabled` (the default) each payload is written to a
  temporary sibling and renamed only after CRC-32 and size verify.
- **Symlinks are never materialised.** A symlink entry is refused (single extraction) or skipped and
  reported (bulk extraction), because writing one is how zip-slip becomes arbitrary overwrite.
- **Limits are charged against bytes actually produced**, never against what the header claims.

## Error handling

Failures are structured and classifiable without matching every variant:

```rust
use zipcore::error::Kind;
use zipcore::{Archive, Error};

fn classify(error: &Error) -> &'static str {
    match error.kind() {
        Kind::Malformed => "not a ZIP, or truncated",
        Kind::Unsupported => "needs a feature this build does not have",
        Kind::Password => "wrong or missing password",
        Kind::LimitExceeded => "hit a configured limit",
        Kind::IntegrityFailure => "CRC-32, size or codec rejected the data",
        Kind::NotFound => "no such entry",
        Kind::WriterFailed => "the writer was poisoned by an earlier failure",
        Kind::UnsafeName => "the entry name is unsafe to extract",
        Kind::AlreadyExists => "destination exists and overwrite was refused",
        _ => "i/o or other failure",
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let error = Archive::new(std::io::Cursor::new(vec![0u8; 32])).unwrap_err();
    assert_eq!(error.kind(), Kind::Malformed);
    assert!(!error.is_recoverable());
    println!("{error}: {}", classify(&error));
    Ok(())
}
```

`Error::is_recoverable()` answers whether more capability — a password, a feature, a bigger limit —
could make the same call succeed. `Error` itself is neither `Clone` nor `PartialEq` because it wraps
`io::Error`; branch on `Error::kind()` instead.

On the write side, **a failed write latches**: the writer stops accepting work and every later call
reports the original cause, so a partially written entry cannot be appended to a structure that no
longer adds up. `finish_ref()` then `into_inner()` recovers the sink when you need the bytes.

## Performance

Measured against `zip` 9.0.5 on the same machine, release build with `lto = true` and
`codegen-units = 1`, warmed up before timing. Variance across runs was within ±4%.

| Workload | zipcore | `zip` | Notes |
| --- | --- | --- | --- |
| Write, store-only (36.9 MiB) | 24.9 ms (1484 MiB/s) | 24.8 ms (1488 MiB/s) | container at parity |
| Read, store-only | 13.0 ms (2835 MiB/s) | 17.7 ms (2088 MiB/s) | **35% higher throughput** |
| Open + list 1000 entries | 124 µs | 167 µs | **26% faster** |
| `read_entry`, whole entry | 1.41 ms | 1.60 ms | **12% faster** |
| `by_name`, 1000 entries | 101 µs | 98 µs | parity |
| Write, Deflate L6 | 625 ms | 289 ms | the codec, not the container |
| Extract 500 small entries | 200 ms | 110 ms | see below |

**The Deflate gap is the compressor, not the container.** Forced onto `flate2`'s pure-Rust backend —
which *is* `miniz_oxide`, the codec used here — the two are indistinguishable (1.01×). `zip`'s
default pulls `zlib-rs`, roughly twice as fast at compressing. Enable `deflate-zlib-rs` to close the
gap on this side: on the same 36.9 MiB corpus, **625 ms → 293 ms (2.1×)**, archive size unchanged.
Decompression stays on `miniz_oxide`, which was already the faster of the two for inflate.

**Extraction pays for its guarantees.** Each entry costs a `rename` plus a containment
canonicalisation. `AtomicWrite::Disabled` skips the rename for archives you trust: **200 ms → 143 ms
(~30%)** on 500 small entries, at the cost of a partial file if one fails mid-write.

## Testing and verification

CI runs on every push: the default build, `zstd`, `bzip2`, `deflate-zlib-rs`, `aes-crypto` and all
four combined — plus clippy with `-D warnings`, `cargo fmt --check`, a docs build with warnings
denied, a check that every README example compiles, the `kitchen_sink` example run end to end, a grep
proving `src/` contains no `unsafe`, a default-dependency budget, one job per MSRV row, and a fuzz run.

| Check | Result |
| --- | --- |
| `cargo test --all-features` | 251 passed, 0 failed, plus 7 doctests |
| `cargo test` (default build) | 217 passed, 0 failed, plus 6 doctests |
| Deterministic mutation suite | 5,500 corruptions, 0 panics |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo doc --all-features` with `-D warnings` | clean |
| Rust 1.85 default build | builds clean |
| Python `zipfile` reading Stored/Deflate/ZipCrypto output | round-trips |
| 7-Zip 25.01 / `pyzipper` 0.4.0 reading our AES-256, and us reading theirs | both directions |

Interoperability is tested against real archives, not just this crate's own output — a scheme can be
internally consistent and still incompatible with every other implementation. The AE-2 zero-CRC rule
was found exactly that way. `scripts/check-all.ps1` runs locally what CI runs, with the same flags;
`scripts/test-on-linux.sh` runs the suite on a Unix host, where symlink and containment behaviour
differs from Windows.

## Known limitations

- **Decoding**: no shrink/reduce/implode (methods 1–6). They are recognised and named in errors.
- **Spanned archives** (an entry crossing disks) are refused; split volumes are supported.
- **Encoding**: Stored, Deflate, and Zstd behind its feature. Deflate64, LZMA, XZ, PPMd and Bzip2 are
  decode-only, because the archives that use them were written by other tools.
- **The tar writer emits plain ustar**: names up to 255 bytes split across `prefix`/`name`, ASCII
  only. Longer or non-ASCII names are refused rather than mangled — that needs PAX, which is not
  emitted. No links, xattrs or sparse files.
- **The 4 GiB write path is covered by fixtures**, not by an actual multi-gigabyte write.
- **Extraction is slower than `zip`** while `AtomicWrite::Enabled` (the default) is in use; that is
  the rename plus the containment check buying crash-tidiness and escape prevention.
- **AES entries are buffered in memory** while being authenticated, because plaintext is not released
  before the HMAC verifies. `max_entry_size` still bounds the decompressed result.

## Links and license

- API documentation: [docs.rs/zipcore](https://docs.rs/zipcore) ·
  changelog [CHANGELOG.md](CHANGELOG.md) · security policy [SECURITY.md](SECURITY.md) ·
  contributing [CONTRIBUTING.md](CONTRIBUTING.md)

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this
crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
