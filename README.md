# zipcore

**A small, auditable, `unsafe`-free ZIP implementation for Rust.**

Stored and Deflate, full ZIP64, CRC-32 verification, split volumes, encryption (legacy ZipCrypto
and WinZip AES), and a `tar.zst` writer — with **three direct dependencies** and an MSRV of
**1.70**.

[![Crates.io](https://img.shields.io/crates/v/zipcore.svg)](https://crates.io/crates/zipcore)
[![Documentation](https://docs.rs/zipcore/badge.svg)](https://docs.rs/zipcore)
[![MSRV](https://img.shields.io/badge/MSRV-1.70-blue.svg)](#minimum-supported-rust-version)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

```rust
let bytes = std::fs::read("book.xlsx")?;
let mut archive = zipcore::Archive::new(std::io::Cursor::new(bytes))?;
for name in archive.names() {
    println!("{name}");
}
let first = archive.read_entry(0)?;
```

```toml
cargo add zipcore
```

---

## What this is actually good for

Let me be straight about the competition, because it decides whether you should use this at all.

**If you want the most complete ZIP library, use [`zip`](https://crates.io/crates/zip).** It is
mature, has 300M downloads, and covers things this crate does not (AES-NI-accelerated paths, a
`Sync` writer, a wider method matrix in some builds). For most projects it is the right answer.

This crate is worth considering for a narrower set of reasons, and they are not all equally strong:

### Where it genuinely wins

**The dependency tree is small and auditable.** Three direct dependencies by default
(`miniz_oxide`, `crc32fast`, `getrandom`), all pure Rust, no C toolchain, no build script. `zip`
pulls 10+ by default, including a C build for zstd. A ZIP parser reads attacker-controlled bytes,
so its dependency tree *is* attack surface; this is the reason to care.

**There is no `unsafe`.** `#![forbid(unsafe_code)]`, enforced by a CI job rather than promised.
`zip` has 29 `unsafe` blocks. For code in the position of parsing hostile input, that difference
matters to some auditors.

**The MSRV is much lower.** 1.70 for the default build, where `zip` requires 1.88. If you are
pinned to an older toolchain, this crate works and `zip` does not.

**Behaviour is specified, not incidental.** Every limit has a documented default, every failure
mode is a named error variant, and the hostile-input posture is written down in
[SECURITY.md](SECURITY.md) and tested. Extraction refuses zip-slip names, refuses to write through
a pre-existing junction or symlink, never leaves a partial file behind by default, and never
returns corrupt data as valid.

### Where it is honest-but-weaker

**Feature coverage is close, but `zip` is still ahead.** This crate reads and writes Stored and
Deflate, reads Deflate64 (9), LZMA (14), XZ (95), PPMd (98), zstd (93) and bzip2 (12), writes zstd,
and does both legacy ZipCrypto and WinZip AES-128/192/256 in both directions. What it does *not*
do: legacy shrink/implode/reduce, truly spanned (multi-floppy) archives, and writing any of the
decode-only methods.

**Performance is a wash, and slightly behind on writing.** Store-only container work is at parity
or faster (reads 20–35% faster); Deflate compression is slower unless you enable
`deflate-zlib-rs`, because `zip` uses `zlib-rs` by default. Extraction is slower by default because
of the atomic-write guarantee, which you can turn off. See [Performance](#performance) for measured
numbers rather than adjectives.

**It is young.** 300M downloads versus a few hundred. No track record, one maintainer, a 0.x
version number that reserves the right to break.

### The honest summary

Choose `zip` unless you specifically need a small auditable dependency tree, no `unsafe`, or an
older compiler. Those are real constraints in supply-chain-sensitive, embedded, or long-term-support
contexts — and if you have one of them, this crate was built for you.

---

## What it does

- **Stored (0) and Deflate (8)** — the methods `.xlsx`, `.docx`, `.epub`, `.jar` and ordinary
  archives actually use.
- **ZIP64** — sizes, offsets and entry counts, in both directions.
- **CRC-32 and size verification**, with failures that stay failed instead of decaying into a
  clean end of stream.
- **CP437 and UTF-8** name decoding, per general-purpose flag bit 11.
- **Split volumes** — `archive.zip.001`, `.002`, … read as one archive.
- **Encryption** — legacy ZipCrypto (no extra dependencies) and WinZip AES-128/192/256.
- **Appending** — add entries to an existing archive.
- **Byte-faithful copying** between archives without decompressing.
- **A `ustar` tar writer**, including `tar.zst`.
- **Optional codecs** — zstd (93), bzip2 (12), Deflate64 (9), LZMA (14) and PPMd (98) for
  reading, plus a faster Deflate backend for writing.

## What is not supported

Reported as named errors, never guessed at or silently mis-decoded:

- Decoding the legacy shrink/reduce/implode methods (1-6). They are recognised and named in errors, but not decoded.
- Truly *spanned* archives (floppy-era, entry crosses volumes). Split volumes are supported.

---

## Performance

Measured against `zip` 9.0.5 on the same machine, release build, `lto = true`,
`codegen-units = 1`, warmed up before timing.

| Workload | zipcore | `zip` | Notes |
| --- | --- | --- | --- |
| Write, store-only (36.9 MiB) | 24.9 ms (1484 MiB/s) | 24.8 ms (1488 MiB/s) | container at parity |
| Read, store-only | 13.0 ms (2835 MiB/s) | 17.7 ms (2088 MiB/s) | **35% faster** |
| Open + list 1000 entries | 124 µs | 167 µs | **26% faster** |
| `read_entry`, whole entry | 1.41 ms | 1.60 ms | **12% faster** |
| Write, Deflate L6 | 625 ms | 289 ms | the codec, not the container — see below |
| `by_name`, 10 000-entry archive | 98 ns per lookup | linear scan | lazily built name index |
| Extract 500 small entries | 200 ms | 110 ms | see [Extraction speed](#extraction-speed-vs-crash-tidiness) |

**The Deflate gap is the compressor, not the container.** Forced onto `flate2`'s pure-Rust
backend — which *is* `miniz_oxide`, the codec used here — the two are indistinguishable (1.01×).
`zip`'s default pulls `zlib-rs`, roughly twice as fast at compressing. Enable the
`deflate-zlib-rs` feature to close it on this side.

### Faster Deflate, if you want it

```toml
zipcore = { version = "0.4", features = ["deflate-zlib-rs"] }
```

That pulls `flate2` with the `zlib-rs` backend (still pure Rust, no C toolchain). Measured on a
36.9 MiB corpus: **625 ms → 293 ms**, a **2.1× speedup**, archive size unchanged. Decompression
stays on `miniz_oxide`, which was already the faster of the two for inflate.

---

## Reading

```rust
use zipcore::Archive;

let mut archive = Archive::open("data.zip")?;
for entry in archive.entries() {
    println!("{} ({} bytes)", entry.name(), entry.uncompressed_size());
}
// Streams every entry to disk, verifying CRC-32 as it goes.
archive.extract_all(std::path::Path::new("out"))?;
```

Entry data is decompressed lazily and never has to be held in memory. For untrusted archives use
`extract_all_with_limits`:

```rust
use zipcore::{Archive, ExtractLimits, Overwrite};

let mut archive = Archive::open("untrusted.zip")?;
let limits = ExtractLimits {
    max_entries: Some(1_000),
    max_total_bytes: Some(64 * 1024 * 1024),
    overwrite: Overwrite::Never,
    ..ExtractLimits::default()
};
let report = archive.extract_all_with_limits(std::path::Path::new("out"), &limits)?;
println!("{} written", report.written.len());
```

### Extraction speed vs. crash-tidiness

By default each entry is written to a temporary file and renamed into place, so a failed entry
(bad CRC-32, a limit hit, an interrupted write) leaves **nothing** at the destination instead of a
truncated file that looks complete.

That `rename` is not free: on Windows it costs more than creating and writing a small file. For an
archive of many small entries it is most of the extraction time, so it is configurable:

```rust
use zipcore::{Archive, AtomicWrite, ExtractLimits};

let mut archive = Archive::open("many-small-files.zip")?;
let limits = ExtractLimits {
    atomic_write: AtomicWrite::Disabled,   // ~30% faster, but a failure can leave partial files
    ..ExtractLimits::default()
};
archive.extract_all_with_limits(std::path::Path::new("out"), &limits)?;
```

| Mode | 500 small entries | Guarantee |
| --- | --- | --- |
| `AtomicWrite::Enabled` (default) | ~200 ms | a failed entry leaves no file behind |
| `AtomicWrite::Disabled` | ~143 ms | an interrupted write can leave a partial file |

The default is the safe one, deliberately: correctness should not be what you get only when you
remember to ask.

### Hostile archives

The reader treats every archive as hostile input, and the guarantees are specific:

- **No `unsafe`**, so a malformed header cannot cause undefined behaviour.
- **Bounded work**: `max_entry_size` (default 1 GiB) caps decompression per entry, charged against
  bytes actually produced rather than bytes declared. No allocation is sized from an archive field.
- **No writes outside the destination**: names are sanitised (absolute paths, drive prefixes,
  `..`, alternate data streams, Windows device names including trailing-dot and trailing-space
  spellings), and extraction canonicalises the destination to refuse a write whose parent
  resolves outside it — which catches a pre-existing junction or symlink.
- **No partial files**: each entry is written to a temporary file and renamed only after it
  verifies.
- **No corrupt data returned as valid**: CRC-32 and size are checked, and a failed entry stays
  failed.

A time-boxed `cargo-fuzz` run against the reader is part of CI.

---

## Writing

```rust
use std::io::Cursor;
use zipcore::{FileOptions, ZipWriter};

let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
writer.add_file("hello.txt", b"hi", &FileOptions::default())?;
writer.add_directory("nested/", &FileOptions::default())?;
let bytes = writer.finish()?.into_inner();
```

`ZipWriter::new` refuses a sink that already holds bytes. Writing over an existing archive used to
destroy it silently; use `new_append` to add to one instead.

### Appending to an existing archive

```rust
use zipcore::{FileOptions, ZipWriter};

let existing = std::fs::read("existing.zip")?;
let mut writer = ZipWriter::new_append(
    std::io::Cursor::new(existing.clone()),
    std::io::Cursor::new(existing),
)?;
writer.add_file("added.txt", b"new entry", &FileOptions::default())?;
let out = writer.finish()?.into_inner();
```

The previous central directory is overwritten rather than left behind, so repeated appends grow
linearly in entry count.

### Streaming to a sink that cannot seek

`ZipWriter` patches each local header by seeking back, so it needs `Write + Seek`. For a socket, a
pipe or `stdout` — anything that can only be written forwards — use `ZipStreamWriter`, which emits
a **data descriptor** after each payload instead (general-purpose flag bit 3). That is the layout
`zip -` and other streaming archivers produce, and 7-Zip and Python's `zipfile` both read it.

```rust
use zipcore::stream::ZipStreamWriter;
use zipcore::FileOptions;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut writer = ZipStreamWriter::new(std::io::stdout())?;
writer.add_file("hello.txt", b"hi", &FileOptions::default())?;

// Payloads can also arrive in pieces.
let mut entry = writer.start_file("log.txt", &FileOptions::default())?;
std::io::Write::write_all(&mut entry, b"line one\n")?;
entry.finish()?;

writer.finish()?;
# Ok(())
# }
```

Two differences from `ZipWriter`, both structural rather than arbitrary:

- **Entries of 4 GiB or more are refused**, not truncated. The sizes are not known until the
  descriptor is written, so the ZIP64 extra field cannot be reserved in advance.
- **Encryption is refused.** It needs the payload length before the descriptor can be written.

When the sink can seek, prefer `ZipWriter`: no data descriptors are needed and the result is the
more widely compatible layout.

### Timestamps

`dos_timestamp` is the classic field, but it has two-second resolution and no timezone, so it
cannot round-trip an arbitrary instant. Use `with_unix_mtime` for exact Unix seconds:

```rust
use zipcore::FileOptions;

let options = FileOptions::default().with_unix_mtime(Some(1_709_210_097));
# let mut writer = zipcore::ZipWriter::new(std::io::Cursor::new(Vec::new()))?;
writer.add_file("t.txt", b"x", &options)?;
```

`Entry::unix_mtime()` returns those exact seconds, or `None` when only a DOS time was recorded.

### Symbolic links

```rust
use zipcore::FileOptions;

# let mut writer = zipcore::ZipWriter::new(std::io::Cursor::new(Vec::new()))?;
writer.add_symlink("latest", "releases/v2", &FileOptions::default())?;
```

`add_symlink` writes a link entry with the correct `S_IFLNK` mode. Extraction deliberately refuses
to materialise links and reports them in `ExtractReport::skipped_symlinks`.

### Entries of 4 GiB or more

Sizes are only known after the data is written, but the ZIP64 extra field must be reserved
*before* it. Declare large entries up front:

```rust
use zipcore::FileOptions;

let options = FileOptions::default().with_size_hint(5 * 1024 * 1024 * 1024);
# let mut writer = zipcore::ZipWriter::new(std::io::Cursor::new(Vec::new()))?;
writer.add_file("huge.bin", b"...", &options)?;
```

An entry that grows past 4 GiB without a hint fails with `Error::Zip64Required` rather than
emitting a header with a truncated size.

### Copying instead of rewriting

Re-wrapping an archive without touching its payloads costs no decompression at all, so a 660 MB
archive copies in the time it takes to move the bytes:

```rust
# let mut writer = zipcore::ZipWriter::new(std::io::Cursor::new(Vec::new()))?;
# let mut source = zipcore::Archive::new(std::io::Cursor::new(Vec::new()))?;
writer.copy_from(&mut source)?;      // every payload copied verbatim
# Ok::<(), Box<dyn std::error::Error>>(())
```

A preserved entry carries its source's compression method, CRC-32 and sizes unchanged, so an entry
this crate cannot decode copies fine and stays undecodable in the result — that is fidelity, not a
bug. Because the sizes are known before the header is written, a preserved entry past 4 GiB gets
correct ZIP64 fields without needing a size hint.

---

## Encryption

Two schemes, and the security difference between them is not small.

**ZipCrypto** (traditional PKWARE) needs no feature and reads the large back-catalogue of old
encrypted archives. It is **not secure**: the keystream is recoverable from about a dozen bytes of
known plaintext, and it has been breakable since 1996. Use it for compatibility, never for secrecy.

**WinZip AES** requires the `aes-crypto` feature and is what you want for actual confidentiality.

```toml
zipcore = { version = "0.4", features = ["aes-crypto"] }
```

Reading, once a password is supplied:

```rust
use zipcore::{Archive, ReadOptions};

let bytes = std::fs::read("encrypted.zip")?;
let options = ReadOptions::default().with_password("correct horse battery staple");
let mut archive = Archive::new_with_options(std::io::Cursor::new(bytes), options)?;
let plain = archive.read_entry(0)?;
```

Writing — set the password on `WriteOptions` and the scheme per entry:

```rust
use std::io::Cursor;
use zipcore::{Encryption, FileOptions, WriteOptions, ZipWriter};

let options = WriteOptions {
    password: Some(b"correct horse battery staple".to_vec()),
    ..WriteOptions::default()
};
let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options)?;
let file = FileOptions { encryption: Some(Encryption::Aes256), ..FileOptions::default() };
writer.add_file("secret.txt", b"payload", &file)?;
```

Details worth knowing:

- AES entries are stored as WinZip **AE-2**: method 99 with a `0x9901` extra field, and a zero
  CRC-32 because the HMAC authenticates the payload. Interoperates with 7-Zip, WinZip and
  `pyzipper`; the test suite round-trips against real archives from 7-Zip 25.01 and `pyzipper`
  0.4.0 in both directions.
- AES content is **decrypted and authenticated before any of it is returned**, so a corrupted or
  forged entry fails instead of leaking unauthenticated plaintext. The entry is therefore
  materialised in memory, subject to `max_entry_size`.
- Without `aes-crypto`, an AES entry is refused with an error naming method 99.
- Passwords are `Vec<u8>`, not `String`: the formats encrypt raw bytes, and a password is not
  necessarily UTF-8.

---

## Features

The default build has three direct dependencies, and every codec beyond Stored and Deflate sits
behind its own off-by-default feature. Opting in is a deliberate trade of dependency surface for
capability.

| Feature | Pulls in | Gives |
| --- | --- | --- |
| `zstd` | `zstd` → `zstd-safe` → `zstd-sys`, which builds C | reading *and* writing method 93, and `tar.zst` |
| `bzip2` | `bzip2` → `libbz2-rs-sys`, **pure Rust** | reading method 12 |
| `deflate-zlib-rs` | `flate2` + `zlib-rs`, both **pure Rust** | ~2× faster Deflate compression |
| `aes-crypto` | `aes`, `ctr`, `hmac`, `sha1`, `pbkdf2`, `zeroize` | WinZip AES-128/192/256, read and write |
| `deflate64` | `deflate64` (**pure Rust**) | reading method 9 |
| `lzma` | `lzma-rs` (**pure Rust**) | reading method 14 |
| `ppmd` | `ppmd-rust` (**pure Rust**) | reading method 98 |

The three decode-only methods are read-only on purpose: they are rare in the wild, the archives
that use them were written by other tools, and carrying an encoder for each would be code without
users.

Traditional PKWARE ("ZipCrypto") encryption needs no feature at all.

A method this build cannot handle fails with an error that names it, and points at the feature:

```text
entry `data.bin` uses compression method 93 (zstd), which this build does not support;
rebuild with the `zstd` feature to enable it
```

### Minimum supported Rust version

**1.70** for the default build. Enabling a feature raises the floor to what that feature's
dependencies need. Measured, not assumed:

| Build | MSRV |
| --- | --- |
| default (Stored + Deflate) | **1.70** |
| `+ deflate-zlib-rs` | 1.75 |
| `+ bzip2` | 1.85 |
| `+ zstd` | 1.85 |
| `+ ppmd` | 1.82 |
| `+ lzma` | 1.83 |
| `+ deflate64` | **1.87** |
| `+ aes-crypto` | **1.89** |

The AES floor is set by `aes 0.9.3`, which raised its own MSRV. `scripts/msrv-check.ps1` re-checks
every row against real toolchains and CI runs it, so a dependency raising its MSRV cannot silently
invalidate this table.

---

## Testing

255 tests across the feature configurations, plus doctests, including a deterministic mutation suite. CI runs the matrix on Linux, including
a dedicated job per MSRV row, clippy with `-D warnings`, rustfmt, a documentation build, a check
that every README example compiles, a check that no `unsafe` appears in `src/`, and a time-boxed
fuzz run.

Interoperability is tested against real archives, not just our own output:

- Archives written by 7-Zip 25.01 and `pyzipper` 0.4.0 are read back correctly (checked in).
- Our archives are verified readable by 7-Zip, `pyzipper` and Python's `zipfile`.

That matters because a scheme can be internally consistent and still incompatible with every other
implementation — the AE-2 zero-CRC rule was found exactly that way.

### Verified

| Environment | Result |
| --- | --- |
| Rust 1.95, all features | 255 tests pass |
| Rust 1.70 default build | builds clean |
| `cargo clippy --all-targets --all-features -D warnings` | clean |
| `cargo fmt --check` | clean |
| `cargo doc` with `-D warnings`, all features | clean |
| Python `zipfile` reading our Stored/Deflate output | round-trips |
| Python `zipfile` reading our ZipCrypto output | decrypts |
| 7-Zip 25.01 reading our ZipCrypto and AES-256 output | extracts correctly |
| `pyzipper` 0.4.0 reading our AES-256 output | decrypts |
| us reading 7-Zip ZipCrypto / AES-256, `pyzipper` AES-256 | extracts correctly |

## Known gaps

- A fresh compressor is allocated per entry, and a normally-written entry costs three seeks.
- The 4 GiB write path is covered by fixtures, not by an actual multi-gigabyte write.
- Extraction is slower than `zip` when `AtomicWrite::Enabled` (the default) is in use, because
  every entry pays a `rename` and the destination is canonicalised to refuse escaped writes.
  `AtomicWrite::Disabled` narrows the gap to ~1.3×.
- The tar writer emits plain `ustar` only: names beyond 255 bytes, non-ASCII names and
  out-of-range timestamps are refused rather than mangled. No links, xattrs or sparse files.
- `Error` is neither `Clone` nor `PartialEq`, which makes classifying errors in a caller awkward.

## Planned

Nothing from the original roadmap is outstanding: the non-seekable sink, XZ decode, LZMA,
Deflate64 and PPMd all landed. What remains are quality items rather than missing features, and
they are listed under [Known gaps](#known-gaps) instead of being presented as a plan.

## Examples

See [`examples/`](examples) for a listing CLI (`list.rs`), an archive creator (`create.rs`), a
re-wrapping copier (`copy.rs`) and a `tar.zst` packer (`pack_tar_zst.rs`).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
