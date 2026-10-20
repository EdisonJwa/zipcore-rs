---
name: Feature request
about: Suggest a capability this crate does not have yet
title: ""
labels: enhancement
assignees: ""
---

## What do you want to do?

<!--
Describe the task, not the API. "Read an archive produced by X" is more useful than
"add a method to Archive", because it leaves room to find the smallest change that works.
-->

## Why is the current behaviour not enough?

<!-- What do you have to do today instead? Workaround, another crate, a preprocessing step? -->

## Is this in scope?

This crate is deliberately narrow, and some requests are already answered by design:

- **Compression methods.** Stored and Deflate work by default; zstd, bzip2, LZMA/XZ, Deflate64 and
  PPMd are behind features. The decode-only ones are read-only on purpose. Legacy DOS methods
  (shrink, reduce, implode) are named but not decoded in any build.
- **Encryption.** Traditional PKWARE ("ZipCrypto") works with no feature flag, and WinZip AES is
  behind `aes-crypto`. ZipCrypto is documented as broken for confidentiality — it exists for
  compatibility, not for protecting data.
- **New dependencies.** The default build has three direct dependencies and CI enforces that
  budget. A request that adds one needs an argument for why it cannot be avoided.
- **`unsafe`.** The crate is `#![forbid(unsafe_code)]`. A feature that requires it will not be
  accepted.
- **Out of scope for now:** multi-disk (spanned) archives on the write side, PAX/GNU long names and
  sparse files in the tar writer, and a `tar` reader in the crate itself.

If your request touches one of these, say why the existing position is wrong rather than only what
you need — that is the part that can actually change a decision.

## Suggested approach (optional)

<!-- If you have thought about the implementation, sketch it. Otherwise leave this out. -->

## Alternatives considered

<!-- Other crates, other designs, or doing nothing. -->

## Additional context

<!-- Links to format specifications or APPNOTE sections, sample archives, related issues. -->
