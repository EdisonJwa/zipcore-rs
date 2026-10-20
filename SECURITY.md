# Security Policy

## Supported versions

`zipcore` is pre-1.0, so only the latest published minor version receives security fixes.
Fixes ship as a new patch release; older versions are yanked only if the defect is severe.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private reporting: on the repository page, *Security* → *Advisories* →
*Report a vulnerability*. That opens a draft advisory visible only to maintainers.

Useful in a report:

- The archive bytes that trigger the problem, or a description precise enough to rebuild them.
- The observed behaviour and what you expected.
- Whether it reproduces in a debug build (integer overflows surface there as panics).

You can expect an acknowledgement within a few days. This is a volunteer project, so please
allow reasonable time before disclosing publicly; a coordinated advisory and release will be
prepared together.

## Threat model

`zipcore` treats every archive as hostile input. The guarantees it aims to hold are:

1. **No panics on malformed input.** Length and offset fields are range-checked, offsets are
   validated in wider arithmetic than they are stored in, and the crate is
   `#![forbid(unsafe_code)]`.
2. **No unbounded work from a header.** `ReadOptions::max_entry_size` caps decompression per
   entry and is on by default (1 GiB); `max_total_bytes` caps the total written by extraction,
   charged against bytes actually produced rather than declared. No allocation is sized from an
   archive field.
3. **No writes outside the extraction directory.** Entry names are sanitised (absolute paths,
   drive prefixes, `..`, alternate data streams, Windows device names including trailing-dot
   and trailing-space spellings), and extraction canonicalises the destination to refuse a write
   whose parent resolves outside it — which also covers a pre-existing junction or symlink.
4. **No corrupt data returned as valid.** CRC-32 and declared size are verified; a failed entry
   stays failed rather than decaying into a clean end of stream. A failed extraction leaves no
   file behind, because the payload is written to a temporary and renamed only after it
   verifies.
5. **No silent data loss on write.** A failed write latches the writer and reports the original
   cause on every later call. Starting a fresh archive over a non-empty sink is refused.

### Explicitly out of scope

- **ZipCrypto confidentiality.** Traditional PKWARE encryption is implemented for
  compatibility, and **it is broken**. Its keystream is recoverable from roughly a dozen bytes of
  known plaintext, and the 12-byte header leaks a one-byte check that narrows a password guess to
  1-in-256. Reading such archives is fine; protecting data with them is not, and this crate will
  not describe it as secure. Use the `aes-crypto` feature instead.
- **Password handling.** Passwords are passed as `Vec<u8>` and are not zeroised after use, because
  the caller owns them. If a password must not linger in memory, the caller has to handle that.
- **Encrypted payload size.** An encrypted entry is decrypted and authenticated in memory before
  any plaintext is returned (AES requires this to avoid releasing unauthenticated data), so its
  whole compressed size is buffered. `max_entry_size` still bounds the decompressed result.
- **Spoofing through name collisions.** Two entries whose decoded names map to one filesystem
  path (CP437 versus UTF-8) are not de-duplicated; extraction writes both and the last wins.
  This matches other implementations, but do not assume a one-to-one name mapping.
- **Resource exhaustion via many small entries.** Limits are per entry unless
  `max_total_bytes` is set. Reading a large archive entry-by-entry in application code without
  a total budget is the caller's responsibility.

## Dependencies

The default build has three: `miniz_oxide` (pure-Rust DEFLATE), `crc32fast` (CRC-32) and
`getrandom` (OS randomness, used for encryption headers and salts). All are widely used and
low-churn. Optional codecs and cryptography (`zstd`, `bzip2`, `deflate-zlib-rs`, `aes-crypto`) are
off by default and each is documented in the README, including what it costs in dependency
surface.

`aes-crypto` pulls the RustCrypto stack (`aes`, `ctr`, `hmac`, `sha1`, `pbkdf2`, `zeroize`). Those
crates are mature and widely deployed but are pre-1.0, so their minor releases can break; pin or
audit accordingly. AES-CTR is used with a random 16-byte salt per entry, which is the property that
makes counter reuse impossible across entries.
