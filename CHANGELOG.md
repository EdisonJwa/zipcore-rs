# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this crate is pre-1.0, the minor version is where breaking changes land.

## [0.10.0] - 2026-10-20

Documentation overhaul, community files, and two consistency fixes found by an external review
pass over the write path.

### Added

- **`ZipWriter::get_ref` and `get_mut`.** Reach the underlying sink while it is still owned by the
  writer, for progress counters, byte budgets, and inspecting an in-memory buffer mid-archive.
- **`examples/inspect.rs`** — list an archive's metadata, explain why a method is unreadable, and
  verify every entry's CRC, using `by_index`/`raw_reader` for data that should not be inflated.
- **Community files**: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
  issue and pull-request templates, `dependabot.yml`.

### Fixed

- **`add_preserved` now latches on a sink failure.** A failure writing the preserved entry's local
  header or copying its payload left the writer accepting new work, so `finish()` could succeed
  after a half-written entry. Every sibling operation already latched; this one did not. Found by
  review, pinned by `tests/latch_tests.rs`.
- **`CODE_REVIEW.md` removed from the repository.** It was an internal review record containing
  the local filesystem path and a catalogue of pre-fix vulnerabilities, and it had been public
  since the first commit. It is now gitignored alongside `ANALYSIS.md`.

### Changed

- **README rewritten** in the shape a widely used crate uses: badges, a one-paragraph statement of
  what it is for, the four properties that distinguish it, quick start, then per-topic sections
  with a compiling example each, and tables for features, performance and MSRV. All 12 code blocks
  are compiled by `scripts/check-readme-examples.py` in CI.

### Verified

- Review claims against the current tree, re-checked rather than assumed: the ZIP64 boundary
  comparisons, the central-directory record restoration on failure, tar short-entry padding, and
  the ZIP64 `disk_start` narrowing all turned out to be fixed already. The i64 offset casts the
  reader review flagged are gone. Documented here because "reviewed and found correct" is worth
  recording.

## [0.9.1] - 2026-10-20

### Security

- **Fixed a path-containment bypass on Unix.** A pre-existing *file symlink* at the destination
  path was followed by `File::create`, so with `AtomicWrite::Disabled` an archive could write
  through it to a file outside the extraction directory. The guard canonicalised only the parent
  directory, which is still inside the tree and therefore passed. It now canonicalises the full
  destination path as well.

  `AtomicWrite::Enabled` (the default) was not exploitable — `rename` replaces the symlink rather
  than following it — which is why this was invisible on Windows and in the default configuration.
  Found by CI running the test suite on Linux, after the equivalent Windows junction test passed.

- The regression test now covers both atomic modes, since only the non-default one exposed the bug.

### Fixed

- CI's `rust-cache` key contained commas for multi-feature matrix entries, which the action rejects.

## [0.9.0] - 2026-10-20

### Fixed

- **CI now passes.** It had failed on every push since it was added, because it sets
  `RUSTFLAGS=-D warnings` and local checks did not. `tests/method_codec_tests.rs` referenced
  feature-gated fixtures from configurations where they were unused, and README examples bind
  values for illustration, which `-D unused-variables` rejected. Both fixed.
- Added `scripts/check-all.ps1`, which runs exactly what CI runs with the same flags. Verifying
  under weaker settings than CI is what let six consecutive red builds look green locally.

### Added

- **`Error::kind()`** returning a new `error::Kind` enum, plus `Error::is_recoverable()`. `Error`
  cannot be `Clone` or `PartialEq` because it wraps `io::Error`, so this is the practical way for a
  caller to branch on the category of a failure.
- **`examples/kitchen_sink.rs`** — one runnable program covering every useful part of the API, run
  by CI so it cannot drift.
- Clippy and rustfmt are now part of the local verification script.

### Changed

- **README positioning rewritten again.** The previous version opened by recommending `zip` and
  listed our weaknesses before our strengths — wrong for a crate's own README. It now leads with
  what zipcore is for, and keeps the honest comparison as a short "when this is the wrong choice"
  section.

### Performance

- The DEFLATE compressor is recycled between entries instead of allocated per entry. A
  `CompressorOxide` owns a 32 KiB window and Huffman tables; `reset()` restores both without
  freeing. Output is byte-identical, which is asserted by a regression test.

## [0.8.0] - 2026-10-20

Review pass: security hardening, the last roadmap items, and a rewritten positioning.

### Security

- **LZMA dictionary size is now capped.** It is declared inside the stream, so an archive could
  ask for an arbitrarily large allocation from a tiny entry. Capped at 256 MiB, with the decoder's
  own memory limit set independently as a backstop. (No exploit was demonstrated — the decoder
  happened to tolerate the value — but an unbounded attacker-controlled size is a defect whether
  or not it is currently reachable.)
- **Windows device-name detection widened** to the spellings Win32 actually resolves: `COM0` and
  `LPT0`, the superscript digits (`com¹`), and the `$`-suffixed console handles `CONIN$`,
  `CONOUT$`, `CLOCK$`. The previous list was the classic 22 names and missed these.
- Added a regression test proving a **pre-existing junction cannot redirect a write** outside the
  extraction directory. The existing check already blocked it; nothing tested it.
- Added **mutation tests**: 5,500 deterministic corruptions of valid archives (including encrypted
  ones) with every reader path exercised, asserting no panic. Runs on stable, in under a second.

### Added

- **XZ (method 95) decoding**, completing the method matrix. Verified against a 7-Zip archive.

### Changed

- **README positioning rewritten.** The previous version led with being a reaction to a `zip`
  mass-yank that has since been resolved, and overstated the feature gap. It now states plainly
  when to use `zip` instead, separates genuine advantages (3 dependencies, no `unsafe`, 1.70 MSRV,
  specified behaviour) from honest weaknesses (narrower methods, slightly slower writes, young
  project), and recommends `zip` for most users.

## [0.7.0] - 2026-10-20

### Added

- **`stream::ZipStreamWriter`** — write an archive to a sink that cannot seek, such as a socket,
  a pipe or `stdout`. It sets general-purpose flag bit 3 and emits a **data descriptor** after each
  payload instead of patching the local header by seeking back, which is the layout `zip -` and
  other streaming archivers produce. Verified readable by 7-Zip 25.01 and Python's `zipfile`.
- `ZipStreamWriter::start_file` for payloads that arrive in pieces.
- The central-directory and trailer writing is now shared between both writers
  (`write_archive_trailer`), so the ZIP64 and EOCD logic exists once.

### Limitations, by construction

- Entries at or past 4 GiB are **rejected** rather than truncated: the sizes are unknown until the
  descriptor is written, so the ZIP64 extra field cannot be reserved in advance.
- Encryption is **refused**: it needs the payload length before the descriptor exists.
- Use `ZipWriter` when the sink can seek; no data descriptors are needed and the output is the
  more widely compatible layout.

## [0.6.0] - 2026-10-20

### Added

- **Decoding for Deflate64 (method 9), LZMA (method 14) and PPMd (method 98)**, each behind its
  own off-by-default feature. All are pure Rust and decode-only: they are rare in the wild, the
  archives using them were written by other tools, and an encoder for each would be code without
  users. The default build keeps its three direct dependencies.
- Verified against archives produced by 7-Zip 25.01 for all three methods, checked in as
  fixtures. The fixtures matter because a wrong decoder tends to produce *plausible* garbage
  rather than an error; the CRC-32 check is what makes the tests meaningful.
- `scripts/msrv-check.ps1` gained rows for the three new features.

### Notes

- ZIP's method 14 is not a `.lzma` file: APPNOTE 5.3.3 puts a 2-byte version, a 2-byte properties
  length and five bytes of LZMA properties before the raw stream. Reading it as a `.lzma`
  container fails with a confusing "distance beyond output size" error, which is what the
  implementation first did.
- PPMd carries a single 16-bit header describing order, memory and restore method — and no size
  field, so the declared uncompressed size is what bounds it.

## [0.5.0] - 2026-10-20

### Added

- **`ExtractLimits::atomic_write`** (`AtomicWrite::{Enabled,Disabled}`). Extraction still writes
  through a temporary file and renames by default, but the rename is now optional: on Windows it
  costs more than creating the file at all, which made it most of the extraction time for archives
  of many small entries. Measured **200 ms → 143 ms** for 500 small entries (~30%).
- `scripts/check-readme-examples.py` is now exercised by CI on every push.

### Changed

- **`by_name` / `index_for_name` are no longer a linear scan.** A name index is built once, lazily,
  on the first by-name lookup, so archives read only by index never pay for it. For a
  10,000-entry archive a lookup went from **16.6 us to 98 ns** (169x), and a miss from 3.8 us to
  ~7 ns.

### Fixed

- Nothing user-visible beyond the above; the 0.4.0 MSRV repair stands.

## [0.4.0] - 2026-10-20

### Fixed

- **The default build's MSRV is 1.70 again.** 0.3.0 made `getrandom 0.4` a required dependency for
  encryption salts; that crate needs Rust 1.85 *and* edition 2024, so the advertised 1.70 floor was
  fiction for the default build. It is now pinned to `getrandom 0.2` (MSRV 1.60).
- `deflate-zlib-rs = ["dep:flate2", "flate2/zlib-rs"]` used feature syntax that Cargo 1.70 cannot
  parse, which broke the old-toolchain build outright. Now `"flate2?/zlib-rs"`.
- README MSRV table corrected to measured values: `deflate-zlib-rs` needs 1.75 (not 1.70 as
  previously implied) and `aes-crypto` needs 1.89 (not 1.85), the latter set by `aes 0.9.3`.

### Added

- `scripts/msrv-check.ps1` — verifies every advertised MSRV row against real toolchains, and fails
  if a dependency raises a floor quietly.
- CI (`.github/workflows/ci.yml`): test matrix over six feature combinations, a job per MSRV row,
  clippy and rustfmt with `-D warnings`, docs build, a README-example compile check, a check that
  `src/` contains no `unsafe`, a default-dependency-budget check, and a time-boxed fuzz run.
- `fuzz/` with reader and writer round-trip targets.
- `scripts/check-readme-examples.py` — compiles every Rust block in the README.

### Changed

- README rewritten for readers arriving from crates.io: capabilities and limits first, measured
  performance table, MSRV table, and an honest comparison against `zip`.

### Performance

- Extraction is faster: `BudgetedSink` now implements `write_all`, so `io::copy` moves whole
  buffers instead of paying a bounds check and a `saturating_sub` per chunk. Measured 7–18%
  improvement on a 100-entry, 73.7 MiB archive (284.7 ms → 233–268 ms).

## [0.3.0] - 2026-10-20

### Added

- **Encryption, both schemes.**
  - **Traditional PKWARE ("ZipCrypto")** read and write, with **no new dependencies** — the key
    schedule's CRC-32 step was already available. It is documented as insecure, because it is.
  - **WinZip AES-128/192/256** (AE-2) read and write behind the `aes-crypto` feature: AES-CTR,
    PBKDF2-HMAC-SHA1 key derivation, and HMAC-SHA1 authentication verified *before* any plaintext
    is released.
  - `ReadOptions::with_password` / `ReadOptions::password`, `WriteOptions::password`, and
    `FileOptions::encryption` with the `Encryption` enum.
  - `Entry::is_aes`. The `0x9901` extra field is parsed and re-emitted.
- Interop test suite against real archives produced by 7-Zip 25.01 and pyzipper 0.4.0, in both
  directions: our output is readable by both, and theirs is read by us.

### Changed

- `Error::Encrypted` now means "no password was supplied" rather than "unsupported".
- Extraction of an encrypted entry is limited by `max_entry_size` on the decompressed result.

### Fixed

- A WinZip **AE-2** entry (zero CRC-32, as the specification requires) is no longer rejected by
  the CRC check. Every conforming AE-2 archive would otherwise have failed to read.

## [0.2.0] - 2026-10-20

### Added

- **`ZipWriter::new_append`** — append entries to an existing archive. The previous central
  directory is overwritten rather than accumulated, so repeated appends grow linearly.
- **`FileOptions::with_unix_mtime`** and **`Entry::unix_mtime`** — read and write the
  extended-timestamp (`0x5455`) extra field. Timestamps now round-trip to the second instead of
  being rounded to DOS's two-second grid. The DOS field is still written as a fallback.
- **`Overwrite`** policy for extraction (`Replace`, `Never`, `Skip`), set via
  `ExtractLimits::overwrite`, plus `ExtractReport::skipped_existing`.
- **`ZipWriter::add_symlink`** — write a symbolic link entry with the correct `S_IFLNK` mode.
- **`Archive::central_directory_offset`** — where the central directory begins, which is what
  `new_append` seeks to.
- **`Entry::flags`**, **`Entry::external_attrs`**, **`Entry::version_made_by`** — accessors for
  fields that previously required reconstructing them.
- **`deflate-zlib-rs` feature** — swaps the DEFLATE compressor to `flate2` + `zlib-rs`.
  Measured 2.1x faster compression than the default `miniz_oxide` backend on a 36.9 MiB corpus,
  with no change to archive size. Off by default so the two-dependency default build is intact.
- `SECURITY.md` with the threat model, and `[package.metadata.docs.rs]` so feature-gated APIs
  appear on docs.rs.

### Changed

- **`ZipWriter::new` and `ZipWriter::new_with_options` now return `Result`.** They refuse a sink
  that already holds bytes. Previously they accepted one and silently destroyed its contents by
  writing a new archive from offset 0. This is the one deliberate breaking change in this
  release.

  Upgrading from 0.1.0 is a one-line change per call site:

  ```rust
  // 0.1.0
  let mut writer = ZipWriter::new(sink);
  // 0.2.0
  let mut writer = ZipWriter::new(sink)?;          // or .expect("sink must be empty")
  let mut writer = ZipWriter::new_append(sink, source)?;  // to add to an existing archive
  ```

- Extraction canonicalises the destination once per `extract_all` instead of once per entry,
  which showed up as a measurable share of extraction time.

### Fixed

- Writing over an existing archive no longer discards it without warning.
- `extract_all` no longer re-resolves the destination root for every entry.

## [0.1.0] - 2026-10-19

First published release.

### Added

- Streaming ZIP reader and writer: Stored (method 0) and Deflate (method 8) in both directions.
- ZIP64 sizes, offsets and entry counts, in both directions.
- CRC-32 and declared-size verification, with terminal failures that stay failed.
- CP437 and UTF-8 entry-name decoding per general-purpose flag bit 11.
- Split-archive reading via `Archive::open_volumes` / `MultiVolumeReader`.
- Safe extraction with name sanitisation, symlink refusal, Unix mode restoration, and
  entry-count / total-byte limits.
- Byte-faithful copying between archives without recompressing (`add_preserved`, `copy_from`).
- Optional zstd (method 93, read and write) and bzip2 (method 12, read) behind off-by-default
  features.
- A ustar `TarWriter`, including `tar.zst` via `TarWriter::new_zstd`.

[0.10.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EdisonJwa/zipcore-rs/releases/tag/v0.1.0
