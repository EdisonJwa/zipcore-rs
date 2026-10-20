# Security Policy

`zipcore` parses bytes you did not produce. That is the threat model, and it shapes everything
below: the crate is built on the assumption that any archive handed to it may be crafted to make it
panic, hang, allocate without bound, write where it should not, or hand back corrupt data as valid.

## Supported versions

`zipcore` is pre-1.0. Security fixes land on the latest published minor version and ship as a new
patch release; older versions are yanked only when the defect is severe.

| Version | Supported |
| ------- | --------- |
| 0.10.x  | Yes       |
| ≤ 0.9.x | No        |

| Version | Note |
| ------- | ---- |
| 0.9.1 | Fixed a Unix path-containment bypass: a pre-existing file symlink at the destination was followed by `File::create`, letting `AtomicWrite::Disabled` write through it to a file outside the extraction directory. |
| 0.8.0 | Capped the LZMA dictionary size, widened Windows device-name detection, added mutation testing. |
| 0.10.0 | Removed an internal review document that had been public in the repository since the first commit. It contained no keys or credentials, but it did catalogue pre-fix defects and a local filesystem path. |

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private reporting: on the repository page, *Security* → *Advisories* →
*Report a vulnerability*. That opens a draft advisory visible only to maintainers.

Useful in a report:

- The archive bytes that trigger the problem, or a description precise enough to rebuild them. A
  hex dump, or a `zip`/Python snippet that constructs it, is ideal.
- The observed behaviour, and what you expected instead.
- Whether it reproduces in a debug build — arithmetic overflow and out-of-bounds indexing surface
  there as panics, and are usually silent in release.
- The `zipcore` version and the feature flags in use; several decoders are off by default, so a
  finding may depend on one being enabled.

You can expect an acknowledgement within a few days. This is a volunteer project, so please allow
reasonable time before disclosing publicly; a coordinated advisory and release will be prepared
together.

## Threat model

The guarantees this crate aims to hold, and how each is enforced:

1. **No panics on malformed input.** Every length and offset field is range-checked before use,
   and offset arithmetic is done in wider types than the field is stored in. The crate is
   `#![forbid(unsafe_code)]`, with a CI job that greps `src/` for `unsafe` rather than trusting the
   attribute. A deterministic mutation suite corrupts valid archives 5,500 ways and requires zero
   panics; it runs on stable as part of the normal test suite.

2. **No unbounded work from a header.** `ReadOptions::max_entry_size` caps decompressed bytes per
   entry and is on by default (1 GiB). The cap is charged against bytes actually produced, so a
   header that lies about its size cannot raise it. `max_total_bytes` caps the total written by
   extraction, also charged against bytes actually written. The end-of-central-directory scan is
   bounded by `EOCD_LEN + u16::MAX`, so a file cannot force an unbounded backwards scan.

3. **No unbounded allocation from a declared size.** No allocation is sized directly from an
   archive field. The LZMA dictionary size is the one such value that cannot be avoided — it is
   declared inside the stream — so it is capped at 256 MiB, with the decoder's own memory limit set
   independently as a backstop.

4. **No writes outside the extraction directory.** Entry names are sanitised: absolute paths,
   drive prefixes, `..`, alternate data streams, control characters, and Windows device names in
   every spelling the platform resolves (`CON`/`NUL`/`COM1`-`COM9`, `COM0`/`LPT0`, `CONIN$`/
   `CONOUT$`/`CLOCK$`, and the superscript-digit variants). Extraction then canonicalises **both**
   the containing directory and the full destination path, which is what catches a pre-existing
   junction or symlink inside the destination: the *name* is harmless and the redirect exists only
   on disk. Symlink entries are never materialised; they are reported in the extraction result
   instead of being silently dropped.

5. **No corrupt data returned as valid.** CRC-32 and the declared size are verified, and a failed
   entry stays failed — it does not decay into a clean end of stream on a later read. Extraction
   deletes the partial file on any failure and only renames into place after the payload verifies,
   so a failure never leaves a complete-looking file behind.

   `AtomicWrite::Disabled` skips the rename for speed. It still verifies and still deletes on a
   detected failure; what it gives up is crash-tidiness. If the process dies mid-entry, a partial
   file is left at the destination name, which cannot happen in the default mode.

6. **No silent data loss on write.** A failed write latches the writer, and every later call
   reports the original cause rather than continuing to append to a stream whose structure no
   longer adds up. Starting a fresh archive over a non-empty sink is refused, so an existing
   archive cannot be silently destroyed.

### Explicitly out of scope

- **ZipCrypto confidentiality.** Traditional PKWARE encryption is implemented for compatibility,
  and **it is broken**. Its keystream is recoverable from roughly a dozen bytes of known plaintext,
  and the 12-byte header leaks a one-byte check that narrows a password guess to 1-in-256. Reading
  such archives is fine; protecting data with them is not, and this crate will not describe it as
  secure. Use the `aes-crypto` feature.

- **Password lifetime in caller memory.** Derived AES key material is zeroised after use
  (`zeroize`), but the password itself is passed in as `&[u8]` and is owned by the caller, so the
  crate cannot clear it. If a password must not linger in memory, that is the caller's
  responsibility.

- **Bulk encrypted payloads are buffered.** An AES entry is decrypted and authenticated in memory
  before any plaintext is released — releasing unauthenticated plaintext would be worse. Its whole
  compressed size is therefore buffered. `max_entry_size` still bounds the decompressed result, but
  a very large encrypted entry is expensive in memory by construction.

- **Spoofing through name collisions.** Two entries whose decoded names map to one filesystem path
  (CP437 versus UTF-8) are not de-duplicated; extraction writes both and the last wins. This
  matches other implementations, but do not assume a one-to-one name mapping — or trust a listing
  to describe what extraction will produce.

- **Resource exhaustion through entry count.** Limits are per entry unless `max_total_bytes` is
  set. An archive with a million tiny entries will produce a million files. Reading or extracting a
  large untrusted archive without a total budget is the caller's responsibility.

- **Timing side channels in password verification.** The AES verifier and HMAC comparisons are
  constant-time, but archive parsing is not. This is not a defence against an attacker who can
  measure parse timing for a secret.

## Dependencies

The default build has three direct dependencies: `miniz_oxide` (pure-Rust DEFLATE), `crc32fast`
(CRC-32), and `getrandom` (OS randomness for encryption headers and salts). Five crates in total
after transitive resolution, all pure Rust, no C toolchain, no build script. A dependency budget
job in CI fails the build if that number grows.

Optional codecs and cryptography are off by default:

| Feature | Pulls in |
| ------- | -------- |
| `zstd` | `zstd` (C, via `zstd-sys`) |
| `bzip2` | `bzip2` (built on `libbz2-rs-sys`, pure Rust) |
| `deflate-zlib-rs` | `flate2` with the `zlib-rs` backend (pure Rust) |
| `lzma` | `lzma-rs` (also enables XZ decode) |
| `deflate64` | `deflate64` |
| `ppmd` | `ppmd-rust` |
| `aes-crypto` | `aes`, `ctr`, `hmac`, `sha1`, `pbkdf2`, `zeroize` |

`aes-crypto` pulls the RustCrypto stack. Those crates are mature and widely deployed but are
pre-1.0, so their minor releases can break; pin or audit accordingly. AES-CTR is used with a random
salt per entry (8/12/16 bytes by strength), which is what makes counter reuse impossible across
entries. The counter starts at 1 as WinZip requires, and the HMAC-SHA1 authentication tag covers the
whole ciphertext (the first 10 bytes of it are stored, per the WinZip AES specification).

## What is deliberately *not* claimed

Security documentation is only useful if it is honest about its edges:

- The mutation suite is a floor, not a proof. `cargo-fuzz` targets exist and run in CI for 60
  seconds per push; that is a smoke test, not exhaustive coverage.
- The ZIP64 write path is covered by fixtures and by entries that *declare* sizes past 4 GiB, not
  by writing 4 GiB of actual data. The offset arithmetic past 4 GiB is exercised with a sparse file
  on the reading side. A genuine multi-gigabyte write is not part of the test suite on any
  platform.
- No independent security audit has been performed. The crate has been reviewed internally and
  adversarially tested, which is not the same thing.
- The interop tests compare against 7-Zip 25.01, Python's `zipfile`, and `pyzipper` 0.4.0. A bug
  present in all four implementations would not be caught.
