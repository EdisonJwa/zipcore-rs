# zipcore-rs

A from-scratch ZIP archive **reader and writer** in Rust, with no dependencies beyond a DEFLATE
codec and a CRC-32 implementation.

It parses and emits the container itself ??end of central directory record, ZIP64 records,
central directory, local file headers ??and streams **Stored** and **Deflate** members in both
directions. It exists so the container handling is code you control, rather than something
inherited from a dependency whose release history you do not set.

## Why this exists

The upstream `zip` crate had every version up to and including `9.0.2` yanked in a single
security response, which broke fresh resolution of every crate that pins it ??`calamine`
included, since `calamine 0.36.1` depends on `zip = "8.6"`. A container implementation with a
small, stable dependency footprint removes that whole class of exposure.

The dependencies here are deliberately two, and both are mature and low-churn:

| Crate | Role |
| --- | --- |
| `miniz_oxide` | DEFLATE (raw inflate and deflate). Pure Rust ??no C toolchain, no build script. |
| `crc32fast` | CRC-32/ISO-HDLC verification. |

There is no `unsafe` code: the crate is `#![forbid(unsafe_code)]`.

## Supported

**Reading**

- Stored (method 0) and Deflate (method 8) members ??everything used by `.xlsx`, `.ods`,
  `.docx`, `.epub`, `.jar` and ordinary archives.
- ZIP64 sizes, offsets and entry counts, including resolving sentinels from the ZIP64 extended
  information extra field.
- Streaming reads from any `Read + Seek` source, so a member never has to be in memory.
- CRC-32 and declared-size verification.
- CP437 and UTF-8 name decoding, per general-purpose flag bit 11.
- Archives with a prepended self-extractor stub, via offset correction.
- Safe extraction: names sanitised via `Entry::safe_path()`, symbolic links refused, Unix
  permission bits restored (masked to `0o777`), and optional entry-count / total-byte limits.
- A lossless view of an entry's stored bytes (`Archive::raw_reader`), for copying without
  decompressing.
- Split archives: `Archive::open_volumes` presents `.zip.001`, `.zip.002`, ??as one seekable
  stream. Volumes are read in the order given ??there is no reordering magic.
- **Optional codecs behind off-by-default features**: zstd members (method 93, `zstd`) and bzip2
  (method 12, `bzip2`); see [Features](#features).

**Writing**

- Archives on any `Write + Seek` sink: Stored and Deflate entries, directories, per-entry and
  archive comments, Unix modes, and explicit or defaulted timestamps.
- Flat memory use. Data is compressed straight through to the sink and each local file header is
  seeked back to and patched once its CRC-32 and sizes are known, so nothing is buffered per
  entry and no data descriptors are needed.
- ZIP64 on the write side: sizes and offsets past 4 GiB, and archives with more than 65535
  entries.
- zstd entries (method 93) with `--features zstd`. The codec buffers its own output and the archive
  sink is drained from that buffer after each write, so the writer never has to become
  self-referential.
- Byte-faithful copying between archives. `ZipWriter::add_preserved` and `copy_from` move payloads
  across without inflating or deflating, so an entry using a method this crate cannot decode ??or
  one that is encrypted ??still copies intact, at its original compressed size.

**tar and tar.zst**

- `TarWriter` writes plain ustar streams: regular files, directories, modes, owners and mtimes, with
  names up to 255 bytes split across the ustar prefix and name fields. Data can be added whole or
  streamed a piece at a time via `start_file`.
- Because tar needs nothing but `Write`, it composes with a compressor for free:
  `TarWriter::new_zstd(writer, level)` writes a **`tar.zst`** ??the whole stream compressed at once.
  That is unrelated to ZIP's zstd *method*, which compresses each member inside a ZIP container;
  the two share only the codec.

## Not supported ??reported as errors, never guessed at

- **Encryption** (ZipCrypto and AES). Encrypted entries fail with `Error::Encrypted`; the reader
  never returns decrypted-looking garbage.
- LZMA, Deflate64 and PPMd ??and zstd or bzip2 in a build without their feature. These methods are
  *named*, not anonymous numbers, so an entry reports "method 14 (lzma)" rather than a bare id;
  `Compression::is_supported` says whether the current build can handle one.
- The legacy shrink / reduce / implode decoders.
- Truly spanned archives, where every header carries a disk number and an entry may cross volumes.
  Split volumes *are* supported (above); spanning was a floppy-era layout.
- Writing data descriptors. Local headers are patched by seeking back instead, which needs a
  seekable sink but produces the more widely compatible archive.
- Writing any method other than Stored, Deflate, and zstd when the feature is on. `is_writable`
  stays separate from `is_supported` so a decode-only codec is never offered to a caller producing
  an archive.

## Features

The default build has two dependencies, and every codec beyond Stored and Deflate sits behind its
own off-by-default feature ??opting in is a deliberate trade of dependency surface for a capability.

| Feature | Pulls in | Gives |
| --- | --- | --- |
| `zstd` | `zstd` ??`zstd-safe` ??`zstd-sys`, which builds C (plus `cc` and friends as build deps) | reading *and* writing method 93, and streaming zstd for `tar.zst` |
| `bzip2` | `bzip2` ??`libbz2-rs-sys`, **pure Rust** ??the crate's default C backend is switched off | reading method 12 |

```text
cargo build --features zstd
cargo test --features zstd
```

A method this build cannot handle fails with an error that names it, and ??where the feature exists
??points at it:

```text
entry `data.bin` uses compression method 93 (zstd), which this build does not support;
rebuild with the `zstd` feature to enable it
```

## Robustness against hostile archives

Archives are untrusted input, so:

- **Safe by default.** Every entry is capped at `ReadOptions::max_entry_size`, which defaults to
  1 GiB (`MAX_IN_MEMORY_ENTRY`) rather than being unlimited. That is the one bound which does not
  come from the archive, and therefore the one that still holds when a header lies. Opt out with
  `ReadOptions::unlimited()`.
- **No allocation is sized from the archive.** `Vec::with_capacity` is only ever given a bounded
  hint, so a forged 64-bit size field cannot cause a giant allocation.
- **Nothing panics on malformed input.** Every length field is range-checked with
  `checked_add` before use, so a truncated record yields `Error::Malformed`. Malformed errors
  carry the offset they were found at.
- **Entry names are sanitised before they become paths.** `Entry::safe_path()` rejects absolute
  paths, drive-qualified paths, `..` traversal, Windows alternate data streams, Windows device
  names (including the trailing-space and trailing-dot forms Win32 collapses onto them), trailing
  dots or spaces that would make two names collide, control characters and embedded NUL bytes.
  Extraction refuses symbolic link entries rather than following them, which is how zip-slip turns
  into arbitrary file overwrite. It also canonicalises the destination and refuses a write whose
  parent resolves outside it, so a pre-existing junction or symlink inside the destination cannot
  redirect a member.
- **Extraction is bounded and accountable.** `extract_all_with_limits` enforces entry-count and
  total-byte limits, and the returned `ExtractReport` lists what was written and which symbolic
  links were skipped, so nothing is dropped silently. The byte limit is charged against bytes
  actually written, not against the sizes the archive declares, so a header that understates its
  size cannot buy extra budget. Each entry is written to a temporary file and renamed into place
  only after its CRC-32 and size verify, so a corrupt member never leaves a complete-looking file
  behind.
- **Inconsistencies are errors, and they stay errors.** A bad signature, a CRC-32 mismatch, or a
  decompressed size differing from the declared one is reported rather than returned as valid.
  The size is compared even when the declared value is zero, so an archive cannot switch the
  check off by zeroing that field. Once an entry has failed, every later read repeats the error
  instead of decaying into a clean end of stream.

## Reading

```rust
use std::io::Read;

let mut archive = zipcore::Archive::open("book.xlsx")?;
println!("{} entries", archive.len());

for entry in archive.entries() {
    println!("{} ({} -> {} bytes)", entry.name(), entry.compressed_size(), entry.uncompressed_size());
}

let mut sheet = archive.by_name("xl/worksheets/sheet1.xml")?;
let mut xml = String::new();
sheet.read_to_string(&mut xml)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Entry data can also be read with a hard cap, or extracted safely below a directory:

```rust
use zipcore::ReadOptions;

let options = ReadOptions {
    max_entry_size: Some(64 * 1024 * 1024),
    ..ReadOptions::default()
};
let mut archive = zipcore::Archive::new_with_options(std::io::Cursor::new(bytes), options)?;
let xml = archive.read_entry(0)?;          // capped, streamed, CRC-verified
archive.extract_all(std::path::Path::new("out"))?;   // names sanitised, symlinks skipped
# Ok::<(), Box<dyn std::error::Error>>(())
```

Because `Read` can only report `io::Error`, a terminal failure arrives as `InvalidData`. Call
`ZipFile::take_terminal_error()` to recover the specific `Error` behind it ??`CrcMismatch`,
`SizeMismatch`, `SizeLimitExceeded` and so on. A failed entry stays failed: every later read
repeats the error rather than reporting a clean end of stream.

An open entry holds a mutable borrow of its archive until it is **dropped**, so finish one entry
(or scope the handle) before opening the next. That is stricter than a bare `&mut R` would be,
because a codec behind `Box<dyn Read>` has a dynamic destructor that the compiler has to assume
touches the borrow.

## Writing

```rust
use std::io::Write;
use zipcore::{FileOptions, ZipWriter};

let file = std::fs::File::create("out.zip")?;
let mut writer = ZipWriter::new(std::io::BufWriter::new(file));

// Whole-buffer convenience.
writer.add_file("docs/readme.txt", b"hello", &FileOptions::default())?;

// Uncompressed.
writer.add_file("raw.bin", b"unchanged bytes", &FileOptions::stored())?;

// Streamed, for data you do not hold in memory.
let mut entry = writer.start_file("streamed.txt", &FileOptions::deflate(9))?;
entry.write_all(b"written in pieces")?;
entry.finish()?;

writer.add_directory("empty", &FileOptions::default())?;

writer.finish()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`FileOptions` carries the per-entry knobs: compression method and level, Unix mode, timestamp,
comment, and size hint. `WriteOptions` carries the archive-level comment, the default compression,
and `allow_unsafe_names`.

**Names are validated on the way in.** Writing a member called `../../etc/passwd` is refused with
`Error::UnsafePath`, because producing an archive that extracts outside its destination directory
is a defect regardless of intent. `WriteOptions::allow_unsafe_names` opts out for the rare case
where such an archive is the goal.

Dropping a `ZipWriterEntry` without calling `finish()` still closes the entry, so a forgotten call
produces a valid archive rather than a corrupt one. Use `finish()` when you want to observe the
result.

**A failed write is latched.** If any write fails ??a compressor error, a ZIP64 overflow, or the
sink refusing bytes ??the writer stops accepting work and every later call reports the original
cause, rather than resuming into a structure that no longer adds up. Use `finish_ref()` followed
by `into_inner()` when you need the sink back after a failure; `finish()` consumes the writer and
is the convenient choice only when you do not.

### Copying instead of rewriting

```rust
use zipcore::{Archive, ZipWriter};

let mut source = Archive::open("in.zip")?;
let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
writer.copy_from(&mut source)?;      // every payload copied verbatim
let out = writer.finish()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Re-wrapping this way costs no decompression at all, so a 660 MB archive copies in the time it
takes to move the bytes rather than the time it takes to inflate and deflate them.

Two details worth knowing. A preserved entry carries its source's compression method, CRC-32 and
sizes unchanged, which means an entry this crate cannot decode copies fine and stays undecodable
in the result ??that is fidelity, not a bug. And because the sizes are known before the header is
written, a preserved entry past 4 GiB is written with correct ZIP64 fields without needing a size
hint; the data-descriptor flag is dropped, since this writer always records real sizes.

### Entries of 4 GiB or more

Sizes are only known after the data has been written, but the ZIP64 extra field has to be
reserved *before* it. Declare large entries up front:

```rust
use zipcore::FileOptions;

let options = FileOptions::default().with_size_hint(5 * 1024 * 1024 * 1024);
# let mut writer = zipcore::ZipWriter::new(std::io::Cursor::new(Vec::new()));
writer.add_file("huge.bin", b"...", &options)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

An entry that grows past 4 GiB without a hint fails with `Error::Zip64Required` rather than
emitting a header with a truncated size.

## Example CLI

```text
cargo run --example list -- book.xlsx
cargo run --example list -- book.xlsx --verify      # decompress and check every CRC
cargo run --example list -- book.zip --extract out/
cargo run --example create -- new.zip               # write a deterministic archive
cargo run --example copy -- in.zip out.zip          # re-wrap without recompressing
cargo run --example list -- split.zip.001 split.zip.002 --verify   # a split archive
```

## Testing

```text
cargo test
```

The suite is hermetic. Reader fixtures are archives built byte by byte in `tests/common/mod.rs`,
including deliberately hostile ones (bad CRCs, forged sizes, ZIP64 sentinels, `..` names,
truncated files). Writer tests parse the produced bytes directly as well as round-tripping them,
so a symmetric bug in the reader and writer cannot cancel itself out.

To validate against archives from real tools, point `ZIPCORE_ARCHIVES` at a list of them:

```text
ZIPCORE_ARCHIVES="one.zip;two.xlsx" cargo test --test real_world
```

`tests/regression_tests.rs` pins each defect found in review, and includes a deterministic
mutation sweep that truncates and flips bytes of a valid archive 600 ways and asserts the reader
never panics ??a stand-in for a fuzz target until one exists.

Outside the suite, the archive produced by `examples/create` is extracted with PowerShell's
`Expand-Archive`, with Info-ZIP `unzip -t` and with Python's `zipfile`, and compared byte for
byte; archives from real tools are read back and verified entry by entry. The `#[cfg(unix)]`
permission tests run on Linux, so verifying extraction on a Unix host needs WSL or CI rather than
a Windows run.

## Status

Version 0.1.0. Intentionally narrow: Stored and Deflate are the only methods, because they are
the only ones the target formats use. The issues raised in a production review have been fixed;
what follows is the honest remaining state.

### Verified

| Environment | Result |
| --- | --- |
| Windows 11, rustc 1.95 | 172 tests pass by default, 176 with `bzip2`, 181 with `zstd`, 185 with both (3 Unix-only compiled out); clippy clean in every configuration |
| WSL2 Ubuntu 24.04, rustc 1.99 | the same four configurations give 156 / 160 / 165 / 169, including the Unix permission-bit tests |
| MSRV, library | `cargo +1.70.0 check` on the default build is clean on 1.70.0 |
| MSRV, per feature | a feature raises the floor to whatever its codec needs, and Cargo enforces it rather than building something stale: `bzip2` needs 1.82 (`libbz2-rs-sys`), `zstd` needs 1.85 (`jobserver`) |
| Reader, real archives | 67,186 entries across 47 archives (7.2 GB) verify with **0 skipped** |
| Writer, independent oracles | accepted by Info-ZIP `unzip -t`, Python `zipfile.testzip()` and PowerShell `Expand-Archive`; extraction byte-identical to Python's |
| Raw copy | 46,169 entries / 660 MB copied with **0 payload mismatches** per Python's `zipfile`; a 553-entry archive copied with both extracted trees comparing equal |
| Split volumes | a 553-entry archive split into 3 parts reads back with a listing identical to the single-file listing; `unzip -t` on the re-concatenated stream is clean |
| bzip2 decoding | a Python `zipfile`-produced `ZIP_BZIP2` archive ??5 entries, including an empty one, a 100000-byte high-ratio one and a 300000??077-byte one ??extracts with all five files **byte-identical** to Python's own input. With the feature off the same archive fails with the actionable hint instead |
| Capability reporting | real Python-produced LZMA archives report `lzma` by name and are skipped, not failed |
| zstd | **Decoding:** a fixture whose frames come from libzstd decodes with CRC-32 and size verified. **Writing:** a method-93 entry produced by `ZipWriter` is read by Windows `tar.exe` (libarchive) and extracts to exactly the expected 6300 bytes, 0 diffs. Bogus payloads, a patched CRC and an over-cap expansion are rejected |
| tar.zst | a stream written by `TarWriter::new_zstd` is listed by Windows `tar.exe` (libarchive) with correct names, sizes, modes and mtimes, and both extracted files hash identical to the expected content |

The reader was also checked against archives produced by Python's `zipfile`, including the
data-descriptor form it writes to non-seekable streams.

### Planned, and what each item costs

A codec is not free: every one is a dependency that can itself be yanked or compromised, which is
the risk this crate exists to avoid. Each therefore belongs behind its own off-by-default feature,
so the default build stays at two dependencies.

| Feature | New dependencies | Notes |
| --- | --- | --- |
| lzma / xz decode | 1 direct (`lzma-rust2`, pure Rust) ??9 transitive if its `xz` feature is enabled | `LzmaReader` is an ordinary `Read`, so it fits the codec path already in place. Two obstacles stand in the way: every published version needs rustc 1.85, and the ZIP method-14 header declares a dictionary size, which needs an explicit ceiling first |
| deflate64 decode | 1 | pure Rust |
| ppmd decode | 1 | pure Rust |
| ZipCrypto | 1 | a broken cipher, worth decoding only for legacy archives |
| AES (AE-1/AE-2) | 7 | RustCrypto crates, all pre-1.0 and churn-prone |

LZMA is the one to watch: its dictionary size is declared *in the stream*, so a decoder that trusts
it can be made to allocate a great deal. That needs an explicit ceiling before it lands.

ZIP's zstd *method* and `tar.zst` are unrelated beyond sharing the codec: one compresses each
member inside a ZIP container, the other compresses a whole tar stream.

### Other known gaps

- No support for writing to a non-seekable sink (no data descriptors), so streaming to a socket
  or stdout is impossible.
- `by_name` is a linear scan, so reading N entries by name from a very large archive is O(N·M).
- A fresh `CompressorOxide` is allocated per entry, and a normally-written entry still costs three
  seeks (a raw copy needs none).
- The 4 GiB write path is covered by fixtures, not by an actual multi-gigabyte write.
- No CI configuration, so the checks above are manual and will rot.
- The tar writer emits plain ustar only: no PAX headers, so names beyond 255 bytes, non-ASCII names
  and out-of-range timestamps are refused rather than mangled. No links, xattrs or sparse files.
- The tar *reader* is experimental and lives in the test suite, not in the crate.
- `Error` is neither `Clone` nor `PartialEq`, which makes classifying errors in a caller awkward.
