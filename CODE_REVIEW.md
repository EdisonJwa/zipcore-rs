# zipcore 0.1.0 — Code Review

> **Status: all findings below have been fixed.** Every critical, high and medium item was
> corrected and is now pinned by a regression test in `tests/regression_round2_tests.rs`
> (19 tests). The suite grew from 153 to 172 tests by default (185 with both features), and
> `cargo fmt --check` and `cargo clippy --all-targets --all-features` are clean. See
> **What was changed** at the end for the per-finding detail.

**Reviewed:** `C:\Users\admin\Downloads\zipcore` — 15 source files (~6,000 lines), 10 test
binaries, 4 examples.
**Baseline:** `cargo test` = 149 tests + 4 doc tests = 153, all green; `cargo clippy
--all-targets --all-features` silent; `cargo fmt --check` clean; builds under
`zstd`, `bzip2` and `zstd,bzip2`.

**Method.** Every finding below was reproduced by execution, not by reading. Hostile archives
were built byte by byte; writer output was cross-checked with Python 3.14 `zipfile`/`tarfile`,
libarchive (`bsdtar 3.8.9`) and 7-Zip as independent oracles. The ad-hoc reproduction harnesses
live in a local `review/` directory that is not part of this repository; the durable form of each
proof is the regression test named in **What was changed** at the end, which does ship. Where a
claim is inferred rather than executed, it says so.

**Verdict.** The design is sound and the hostile-input work is unusually good — the decompression
cap holds on all seven read paths, 20,000-iteration mutation fuzzing finds no panic outside the two
sites below, and the central/local byte layout matches APPNOTE exactly. But the "never panics" and
"writer never silently corrupts" guarantees have real holes: **2 critical, 4 high, 8 medium**.
The two criticals are both reachable from a single crafted archive.

---

## Critical

### C1 — `i64` overflow in offset correction (`src/archive.rs:246`)

```rust
base_offset = derived_cd_offset as i64 - cd_offset as i64;
```

`cd_offset` comes straight from the ZIP64 EOCD record and is never range-checked. A ZIP64 archive
declaring `cd_offset = 2^63` makes the subtraction overflow: **debug builds panic**, release builds
wrap silently and open the archive with a bogus `base_offset`. Measured trigger window is 32
consecutive values starting at `2^63` on a 94-byte fixture — not a single magic number, so a
patched constant would not close it.

Repro (regression test): `tests/regression_round2_tests.rs::c1_a_forged_zip64_cd_offset_is_an_error_not_a_panic`.

```rust
let base_offset: i64 = (derived_cd_offset as i128 - cd_offset as i128)
    .try_into()
    .map_err(|_| Error::malformed("offset correction out of range"))?;
```

### C2 — same class, second site (`src/archive.rs:547`)

```rust
let shifted = recorded as i64 + self.base_offset;
```

A ZIP64 entry's `local_header_offset` is also an arbitrary `u64`, so with a large positive
`base_offset` this overflows on **every** `by_index` / `raw_reader` — after the archive has already
parsed successfully. Confirmed by panic hook at `archive.rs:547`. Fixing line 246 alone leaves this
open. Use `recorded.checked_add_signed(self.base_offset)`.

---

## High

### H1 — `finish_ref` retry silently emits a zero-entry archive (`src/write.rs:854`)

`write_central_directory` does `std::mem::take(&mut self.records)` **before** any fallible step
(comment-too-long at `:869`, every sink write, and `flush` at `:438`). `finish_ref` latches only
`end_entry` failures, so the writer is left unlatched with `records` empty. Measured:

```
finish_ref #1 = Err(Io("one-shot sink failure"))
finish_ref #2 = Ok(())          <-- reports success
archive reopens with 0 entries  <-- caller wrote 1; payload still at offset 38
```

A flush-only failure — the ordinary `BufWriter` case — reproduces it, and so does the pure
validation route with no sink misbehaviour. Afterwards `add_file` still succeeds, so earlier entries
can be lost with no error anywhere. This directly contradicts the rustdoc at `src/write.rs:425`
("a failure here leaves self intact") and `README.md:221-225` ("every later call reports the
original cause"). Fix: validate the comment before the `take`, put `records` back on failure, and
latch a flush failure.

### H2 — tar short entry misaligns the stream (`src/tar.rs:241-257`, `src/tar.rs:282-292`)

`Drop` and explicit `finish` both pad by `padding()`, computed from the **declared** size, when
`remaining > 0`. For declared 1000 / written 500 that writes 24 bytes instead of 524, so the next
header lands at offset 1036 rather than a multiple of 512. When `declared % 512 == 0` the padding is
zero and nothing is written at all. Oracle results: `bsdtar` — *"Damaged tar archive (bad header
checksum)"*, exit 1, second entry unreachable; Python leaks the next header's bytes into the short
entry's payload. Worse, one variant leaves `len % 512 == 0`, so a structural assertion passes while
the content is wrong.

The rustdoc at `src/tar.rs:91` and `:135` claims the stream is "zero-padded to its declared size" — it is not. Fix: zero-fill `remaining` bytes, *then* write `padding`.

`TarWriter::finish` does correctly refuse via the `short_entry` poison flag, but `into_inner()`
(`src/tar.rs:170`) bypasses it and hands back a misaligned, unterminated stream with no error.

### H3 — one-byte hole at exactly 4 GiB-1 in ZIP64 detection (`src/write.rs:995`, `:933`, `:322`)

`0xFFFFFFFF` in a 32-bit size field **is** the ZIP64 sentinel, so a value of exactly `u32::MAX`
cannot be stored literally. `begin_entry:536` gets this right (`>=`) but the streaming guard
`:995`, the central-directory backstop `:933` and `add_preserved:322` all use `>`. Net effect: an
entry that reaches exactly `u32::MAX` with **no size hint** is neither reserved nor refused.

Executed: streamed exactly 4,294,967,295 bytes through `start_file` with no hint. The writer
accepted it and emitted `size = 0xFFFFFFFF`, `extra_len = 0`, `version = 20` — precisely the shape
this crate's own reader rejects with *"ZIP64 sentinel present without a ZIP64 extra field"*.
Python: `BadZipFile: Overlapped entries`; 7-Zip: `CRC Failed`.

Same root cause via `copy_from`: a **legal** source archive declaring `uncompressed_size` exactly
`u32::MAX` with a correct extra field is copied out as a bare sentinel, corrupting it. Fix: `>` — `>=` at `:995`, `:933` and `:322`, plus a regression test expecting `Zip64Required`.

(The `size_hint` path is correct — `size_hint == u32::MAX` does reserve ZIP64. Do not "fix" `:536`.)

### H4 — `u64` overflow in `extract_all`'s byte counter (`src/archive.rs:502`)

```rust
report.total_bytes += entry.uncompressed_size();
```

Two entries each declaring `u64::MAX` (an ordinary ZIP64 value) overflow the accumulator: debug
builds panic **inside the library**. Reachable with the public, documented
`ReadOptions { verify_size: false, verify_crc: false, .. }`; with verification on the entries fail
first, which is why this is High rather than Critical.
Repro (regression test): `tests/regression_round2_tests.rs::h4_extract_all_does_not_overflow_its_byte_counter`.
Fix: `saturating_add`, and account bytes actually written rather than declared.

---

## Medium

### M1 — tar writer has no sink-failure latch (`src/tar.rs`)
A one-shot failure writing a header leaves the writer usable: the next `add_file` succeeds and
`finish()` returns `Ok(())` on a stream whose first block has a bad checksum. `bsdtar`:
*"Unrecognized archive format"*; Python `tarfile`: `ReadError: bad checksum`. Unlike `ZipWriter`,
a corrupt stream here **is** blessed as success. Fix: a `failed` flag set in `write_header`.

### M2 — entry names longer than `u16::MAX` are silently truncated (`src/write.rs:556`, `:979`)
`name.len() as u16` is unchecked (comments *are* checked, names are not). A 70,000-byte name writes
`name_len = 4464`, so every reader looks for the payload at the wrong offset: Python
`BadZipFile: Corrupt extra field`, `bsdtar` `Extra data overflow`, own reader `Malformed`.
The patch-back arithmetic is correct (it uses the true length) — the defect is the cast. Reject
oversized names in `begin_entry`.

### M3 — Windows device names with a trailing space/dot bypass `safe_path` (`src/path.rs:49-55`)
`RESERVED` is matched against the stem before a `.`, but trailing spaces and dots are not stripped
even though Win32 ignores them. `"nul "`, `"con "`, `"com1 "` are accepted. Verified on this host:
`extract_entry` returns `Ok` for a path that does not exist — the payload is written to the NUL
device and discarded — and `"con "` silently creates/overwrites a file named `con`.
Fix: trim trailing `' '` and `'.'` per component before the check.

### M4 — ZIP64 `disk_start` cast truncates, so a spanned archive reads as local (`src/archive.rs:731`)
`disk_start = z.u32()? as u16` turns `0x1_0000` into `0`, so the `disk_start != 0` rejection
passes and the archive is accepted. Fix: `u16::try_from(...)` mapped to `Malformed`.

### M5 — a failed extraction leaves a corrupt file on disk (`src/archive.rs:454`)
`extract_entry` streams into `File::create(&out_path)` and returns `Err(CrcMismatch)` only at EOF,
so a complete-looking but unrecoverable file is left behind, byte-identical to the attacker's
payload. Fix: write to a temporary file in the destination and rename after verification, or unlink
on error.

### M6 — unverified bytes reach the caller before EOF (`src/read.rs:586`)
`crc.update` and `produced` advance before any verification, which only runs at EOF. A stored entry
declaring 0 bytes but carrying 50,000 hands all 50,000 to the caller, then reports `SizeMismatch`.
This is inherent to streaming and mostly documented ("a partial read is not verified"), but the
extraction consequence (M5) is not.

### M7 — `max_total_bytes` is charged against archive-declared sizes (`src/archive.rs:502`)
The limit counts what the header claims, not what is written. A header declaring 0 while expanding
to 2 MiB wrote **2 MiB to disk under a 1 KiB budget**. Counter it with a running total of bytes
actually written.

### M8 — a pre-existing junction/symlink inside the destination is followed
A directory reparse point in the destination is traversed by `create_dir_all`/`File::create`, so an
entry named `esc/evil.txt` lands outside the extraction root. Verified on this host with an
unelevated `mklink /J`: payload written to `outside\evil.txt`, `canonicalize()` shows containment
fails. Name sanitisation cannot catch this — it needs `openat`-style resolution or a
`canonicalize` containment check per component. Worth documenting as a limitation even if deferred.

---

## Low / Nit

- **L1** `trail.` and `trail ` are distinct names that Win32 collapses onto one file; `ExtractReport`
  lists 2 paths where 1 file exists (`src/path.rs`).
- **L2** CP437 `0x83` and UTF-8 `C3 A2` decode to the same `String`, so two entries extract to one
  path (`src/cp437.rs:49`). Keying extraction de-duplication on `name_raw` would fix it.
- **L3** `add_preserved` (`src/write.rs:366`, `:383`) and `begin_entry`'s first header write (`:566`)
  return errors **without latching**, contradicting "A failed write is latched". Harmless in
  practice — the orphaned local header is invisible to central-directory-driven readers, and I
  confirmed both zipcore and Python read the resulting archive correctly — but the contract is
  broken.
- **L4** `finish_ref` clears the latch with `pending_error.take()` (`:429`), so only the first call
  reports the cause; later calls say `WriterFinished`. `Error::WriterFailed`'s doc promises "every
  later operation reports this".
- **L5** A truncated central-directory record yields `Error::Io(UnexpectedEof)`, not
  `Error::Malformed` as the README asserts ("Every length field is range-checked ... a truncated
  record yields `Error::Malformed`"). The offset context is then missing too.
- **L6** `TarWriter::into_inner` bypasses the `short_entry` poison flag.
- **N1** `extract_entry` tests `is_dir()` before `is_symlink()`, so a `link/` entry carrying
  `S_IFLNK` is `create_dir_all`'d instead of refused — while `extract_all` skips it. The two entry
  points disagree, and "extracting a symbolic link entry is refused" is not quite true.
- **N2** Control characters (tab, newline, DEL) are accepted in written names.

---

## What is genuinely good

- **The decompression cap holds everywhere.** Tested on stored, deflate, zstd, bzip2, `read_entry`,
  streaming `io::copy`, `extract_all` and `raw_reader` for declared sizes 0, 1, 1024 and 2,000,000
  against 2 MiB real expansion — never more than the cap reached the caller or the disk.
  `ReadOptions::unlimited()` still re-applies `MAX_IN_MEMORY_ENTRY` in `read_entry`.
- **Panic resistance is real.** 2-, 4- and 8-byte field sweeps over every offset, 20,000 random
  havoc iterations, and 20,000 structured ZIP64 fuzz iterations found only C1/C2. Huge `var_len`,
  `u64::MAX` entry counts and `u64::MAX` `cd_size` are all rejected in microseconds with no
  allocation. Nothing is sized from a header.
- **No `unsafe`, and the borrow design is disciplined.** The `Budget` split, the
  `DeflateInput` non-wrapping window with retained history, and the terminal-error latch (a failed
  entry keeps failing) are all correct and well argued in comments.
- **Byte layout is spec-exact.** Every central-directory field offset and width matches APPNOTE;
  local-header patch-back is right (CRC at +14, ZIP64 extra at `header+30+name_len+4`, correct even
  with a corrupt length field); ZIP64 extra ordering is correct; all four
  {sizes, offset} × {needs ZIP64, not} version combinations are right; offset-only ZIP64 emits a
  12-byte extra with just the 8-byte offset; 65,535 entries stays classic and 65,536 emits an
  agreeing ZIP64 EOCD.
- **Writer output is accepted by independent tools.** Python `testzip()` clean, `bsdtar` lists and
  extracts correctly, entry CRCs and sizes agree.
- **The test suite is a real asset** — the hostile fixtures, the "feature off" tests, and the
  parser-not-just-round-trip writer tests are better than most crates ship.

## Documentation accuracy

The README is unusually honest — it already lists "no CI", the linear `by_name`, the per-entry
compressor allocation, and `Error` not being `Clone`/`PartialEq`. Four claims needed correcting,
and all four now match the code: the `finish_ref` recovery promise (H1), the tar "zero-padded to
its declared size" claim (H2), the "truncated record yields `Error::Malformed`" claim (L5), and
"extracting a symbolic link entry is refused" (N1). Test counts were refreshed to what the suite
actually runs.

---

## What was changed

All work is in `src/`, plus one new test file and doc corrections. No public API was removed;
two additions were made (`ZipFile::verify_to_end`, and `Error::WriterFailed` is now genuinely
used for latched writers).

### Correctness and safety

| Finding | Change |
| --- | --- |
| **C1** `archive.rs:246` | Baseline subtraction now runs in `i128` and is range-checked with `i64::try_from`, returning `Malformed("offset correction out of range")` instead of overflowing. |
| **C2** `archive.rs:547` | `absolute_offset` adds `recorded` to `base_offset` in `i128` and narrows with `u64::try_from`. Fixing C1 alone would have left this reachable. |
| **H1** `write.rs:854` | `write_central_directory` validates the archive comment *before* taking `records`, and restores them if the write fails. `finish_ref` now latches any failure (including `flush`) and reports the original cause on every later call rather than `WriterFinished`. |
| **H2** `tar.rs` | `TarEntry::finish` and `Drop` now zero-fill the *outstanding* declared bytes **plus** the tail padding, so the next header is always block-aligned. Verified with bsdtar: it previously failed with "Damaged tar archive" and now lists both entries with exit 0. |
| **H3** `write.rs:995,933,322` | All boundary comparisons now go through one `needs_zip64(value) -> value >= u32::MAX` helper. An entry of exactly `u32::MAX` now reserves the ZIP64 extra field (or is refused) instead of emitting a bare sentinel. |
| **H4** `archive.rs:502` | `report.total_bytes` uses `saturating_add`. |
| **M1** `tar.rs` | Added a `failed` flag set by `write_header`/`write_zeros`; `finish` refuses to terminate a stream whose structure is already broken. |
| **M2** `write.rs` | New `check_name_len` rejects names over `u16::MAX` in both `begin_entry` and `add_preserved`, before any header is written. |
| **M3/L1** `path.rs` | `safe_relative_path` trims trailing `.`/space the way Win32 does and rejects any component that changes under that trim (device aliases like `"nul "`, collisions like `"trail."`). |
| **M4** `archive.rs:731` | ZIP64 `disk_start` decoded with `u16::try_from`, so a value that would truncate is `Malformed`. |
| **M5** `archive.rs` | `extract_entry` writes to a temporary sibling and renames only after `verify_to_end` succeeds; on any failure the temporary is removed. |
| **M6** `read.rs` | New `ZipFile::verify_to_end()` lets a caller force verification after streaming; used by extraction. |
| **M7** `archive.rs` | Extraction limits are charged against bytes actually written: a `BudgetedSink` wraps the file and the `max_total_bytes` budget is passed down per entry. |
| **M8** `archive.rs` | New `guard_containment` canonicalises the destination and the write's parent and refuses a member whose parent resolves outside the root. Verified: a junction inside the destination now yields `UnsafePath` and nothing is written outside. |
| **N1** `archive.rs` | `extract_entry` checks `is_symlink()` *before* `is_dir()`, matching `extract_all`. |
| **L3** `write.rs` | `begin_entry`'s header write and `add_preserved`'s short-payload path now latch. |
| **L4** `write.rs` | `Error::WriterFailed` is now what a latched writer returns, so its doc comment is true. |
| **L5** `archive.rs` | Truncated central-directory reads are translated from `UnexpectedEof` into `Malformed` with the offset. |
| **N2** `path.rs` | Control characters (other than tab/newline) are rejected in both the extract and write directions. |

### Not changed, and why

- **L2** (CP437/UTF-8 decode collision) is documented behaviour of the name decoder, not a
  defect in the sanitiser; keying extraction on `name_raw` would be an API change. Left as-is.
- **L6** `TarWriter::into_inner` deliberately remains an escape hatch that skips the
  short-entry check, now with a doc comment that says so.
- **`add_preserved`'s orphaned local header** (L3's original observation) is harmless: the
  central directory is authoritative, and both `zipcore` and Python read such archives correctly.
  The latch was added for the contract, not because the archive was invalid.

### Verification

```
cargo test                                  172 passed, 0 failed
cargo test --features bzip2                 176 passed, 0 failed
cargo test --features zstd                  181 passed, 0 failed
cargo test --features zstd,bzip2            185 passed, 0 failed
cargo test --doc                              4 passed, 0 failed
cargo clippy --all-targets --all-features    clean
cargo fmt --check                            clean
```

External oracles re-run against the fixed writer: Python `zipfile.testzip()` returns `None` and
`bsdtar` lists every entry; a `tar` stream containing a short entry now lists both entries with
exit 0 where it previously reported "Damaged tar archive".
