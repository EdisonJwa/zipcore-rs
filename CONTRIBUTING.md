# Contributing to zipcore

Thanks for taking the time to contribute. This document is deliberately concrete: every command
and feature name below exists in this repository, and the checks it lists are the ones CI actually
runs.

## Before you start

- **Security issues do not belong in a public issue.** Follow [`SECURITY.md`](SECURITY.md)
  instead — it uses GitHub's private advisory reporting.
- For anything larger than a bug fix, open an issue first so the design can be agreed before code
  is written. This crate is intentionally conservative about what it accepts: new public API is a
  long-term commitment, and a new dependency is a deliberate trade rather than a convenience.

## Getting set up

Requires a Rust toolchain. The default build has an MSRV of **1.70**; see
[MSRV policy](#msrv-policy) before using new language features.

```sh
git clone https://github.com/EdisonJwa/zipcore-rs
cd zipcore-rs
cargo build
cargo test
```

The default build covers Stored and Deflate only. Codecs beyond those live behind features:

```sh
cargo test --all-features
```

## Checks to run before pushing

Both of these must pass. CI enforces the same things, and a pull request whose checks fail will
not be merged.

**Windows (PowerShell 7):**

```pwsh
pwsh -File scripts/check-all.ps1          # everything
pwsh -File scripts/check-all.ps1 -Quick   # skip MSRV rows and the full feature matrix
```

`scripts/check-all.ps1` mirrors `.github/workflows/ci.yml` with the same `RUSTFLAGS=-D warnings`
and `RUSTDOCFLAGS=-D warnings`. It exists because verifying locally under weaker settings than CI
once let six consecutive red builds look green.

**Linux / macOS:**

```sh
./scripts/test-on-linux.sh
```

The test suite has platform-specific behaviour that Windows cannot exercise — path containment and
symlink handling in particular — so a change to extraction logic should be run on both.

The individual commands, if you would rather not use the scripts:

```sh
cargo test
cargo test --all-features
cargo test --doc --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc --no-deps --all-features        # with RUSTDOCFLAGS=-D warnings
```

CI additionally checks that no `unsafe` appears in `src/`, that every README example compiles
(`python3 scripts/check-readme-examples.py`), that the default build still has three direct
dependencies, and runs a time-boxed fuzz pass.

## Code style

- **rustfmt** is authoritative. Run `cargo fmt --all` before committing; CI runs
  `cargo fmt --all -- --check`.
- **Clippy with warnings denied** is authoritative. CI runs
  `cargo clippy --all-targets --all-features -- -D warnings`, and `RUSTFLAGS=-D warnings` applies
  to every other job as well, so an unused variable fails the build rather than accumulating.
- **No `unsafe`.** The crate is `#![forbid(unsafe_code)]` and CI greps `src/` for the keyword as a
  second, independent check. A contribution requiring `unsafe` will not be accepted.
- Comments explain **why**, not what. Where behaviour is non-obvious — a format quirk, a
  security-relevant check, a deliberate refusal — say what the alternative would have done wrong.

## Tests

- Every behaviour change needs a test. Bug fixes need a test that fails before the fix.
- **A security-relevant change must come with a regression test.** This is not negotiable: the
  threat model in [`SECURITY.md`](SECURITY.md) makes specific promises (no panics on malformed
  input, no writes outside the extraction directory, no unbounded work from a header, no silent
  data loss on write), and a fix without a test is a promise nobody is holding us to. Where the
  bug is platform-specific, cover both the platform that exposed it and the one that did not — the
  Unix path-containment fix is exactly this shape, because `AtomicWrite::Enabled` hid it.
- Where practical, verify against an **independent implementation** rather than only our own
  output. The suites check our archives with Python's `zipfile` and 7-Zip, and check that we read
  archives those tools wrote. A scheme can be internally consistent and still incompatible with
  everything else; the AE-2 zero-CRC rule was found that way.
- Tests for a known failure mode belong in the regression suites, not in an ad-hoc file.

## Feature matrix

Features are additive and off by default, so the default build stays small. Adding a feature means
adding a row to the CI matrix in `.github/workflows/ci.yml` and to `scripts/check-all.ps1`.

| Feature | Enables | MSRV |
| --- | --- | --- |
| *(default)* | Stored (0), Deflate (8) | 1.70 |
| `zstd` | method 93, reading and writing, plus `tar.zst` | 1.85 |
| `bzip2` | method 12, reading | 1.85 |
| `deflate-zlib-rs` | a faster Deflate backend (~2× compression) | 1.75 |
| `aes-crypto` | WinZip AES-128/192/256, read and write | 1.89 |
| `lzma` | methods 14 and 95 (LZMA and XZ), reading | 1.83 |
| `deflate64` | method 9, reading | 1.87 |
| `ppmd` | method 98, reading | 1.82 |

The decode-only methods are read-only on purpose: they are rare in the wild, the archives using
them were written by other tools, and carrying an encoder for each would be code without users.
Traditional PKWARE ("ZipCrypto") encryption needs no feature at all.

## MSRV policy

- **The default build supports Rust 1.70**, and that floor is a published promise, not an
  aspiration.
- Enabling a feature raises the floor to whatever that feature's dependencies need. The per-feature
  floors are in the table above and in the README's MSRV section.
- A change that raises the default MSRV is a breaking change for a patch release and needs
  discussion first.
- `scripts/msrv-check.ps1` re-checks every claimed floor in the table above against a real
  toolchain. CI's `msrv` job covers the default build plus `deflate-zlib-rs`, `zstd`, `bzip2` and
  `aes-crypto`; the script is the only place that also checks `ppmd`, `lzma` and `deflate64`, so
  run it locally when touching those. If you bump a dependency:
  `rustup toolchain install 1.70.0 1.85.1 1.89.0` and then `pwsh -File scripts/msrv-check.ps1`.
  A dependency raising its own MSRV is exactly how this promise broke silently once before.

## Adding a compression codec

The two halves are independent: a method can be worth decoding without being worth encoding.

**Decoding** — add the method id to `src/spec.rs`, add a `Compression` variant in `src/entry.rs`
(including `name()`, `is_supported()`, `required_feature()`, and `method_id()` if it is reversible),
then add an arm to `build_codec` in **`src/read.rs`** (search for `fn build_codec`). That function
returns `Box<dyn Read>`; wrap the entry's data in a `Bounded` reader so the decoder cannot read past
the declared compressed size, and seek to `data_start` first. Prefer `single_frame()`-style framing
where the codec offers it — each ZIP member is exactly one frame, and without it the decoder will
happily consume the next entry's bytes.

Also decide whether the method's declared sizes are trustworthy enough to pass to the decoder. The
LZMA arm is the reference: the dictionary size is declared *inside* the stream, so it is
attacker-controlled and is capped independently of the decoder's own memory limit. Do the same for
any codec with an attacker-controlled allocation.

**Encoding** — add an arm to the `Encoder` enum in **`src/write.rs`** (search for
`enum Encoder`) plus the matching arms in the write, finish, and patch paths, and set
`is_writable()` to true for the variant. If the codec owns its own output buffer, follow the zstd
arm: drain the buffer into the archive sink after each write rather than making the writer
self-referential.

**Both** — add the feature to `Cargo.toml` with `optional = true`, add a matrix row to
`.github/workflows/ci.yml` and `scripts/check-all.ps1`, add an MSRV row to `scripts/msrv-check.ps1`,
document it in the README's feature table, and add a `CHANGELOG.md` entry. Tests should include a
real archive produced by another tool, not only our own round-trip.

## Commit messages

- Subject line in the **imperative mood**, no trailing period: `Add LZMA decoding`,
  `Fix a Unix path-containment bypass`, not `Added` or `Fixes`.
- Keep the subject under ~72 characters. Use the body to explain **why** the change is needed and
  what the alternative would have done wrong — the diff already shows what changed.
- One logical change per commit. A formatting sweep does not belong in a behaviour fix.
- Reference the issue or advisory where one exists.

## Pull requests

Fill in the pull request template. In particular, a PR is not ready to merge until tests,
`clippy -D warnings`, `cargo fmt --check`, docs, and a `CHANGELOG.md` entry are all in place.

## License

By contributing, you agree that your contribution is dual licensed under the
[MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE) licenses, as described in the README's license
section, without additional terms or conditions.
