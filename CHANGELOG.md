# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this crate is pre-1.0, the minor version is where breaking changes land.

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

[0.3.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EdisonJwa/zipcore-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EdisonJwa/zipcore-rs/releases/tag/v0.1.0
