//! Regression tests for issues found in review, plus a panic-freedom sweep.
//!
//! Each test here corresponds to a specific defect that was fixed; the name says which
//! behaviour must not come back.

mod common;

use common::*;
use std::io::{self, Cursor, Read, Write};
use zipcore::{Archive, Error, ExtractLimits, FileOptions, ReadOptions, WriteOptions, ZipWriter};

const SIG_CENTRAL: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

fn open(buf: Vec<u8>) -> Archive<Cursor<Vec<u8>>> {
    Archive::new(Cursor::new(buf)).expect("archive should open")
}

/// Every offset at which `needle` occurs in `haystack`.
fn find_all(haystack: &[u8], needle: [u8; 4]) -> Vec<usize> {
    haystack
        .windows(4)
        .enumerate()
        .filter(|(_, window)| *window == needle.as_slice())
        .map(|(index, _)| index)
        .collect()
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipcore-fix-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------------------
// Reader: a terminal failure must not decay into a clean end of stream
// ---------------------------------------------------------------------------------------

#[test]
fn a_failed_entry_keeps_failing_on_every_later_read() {
    let mut b = ZipBuilder::new();
    b.add_deflate_bad_crc("corrupt.txt", b"the real contents");
    let mut archive = open(b.finish());

    let mut file = archive.by_index(0).unwrap();
    let first = file.read_to_end(&mut Vec::new()).unwrap_err();
    assert_eq!(first.kind(), io::ErrorKind::InvalidData);
    assert!(matches!(
        file.terminal_error(),
        Some(Error::CrcMismatch { .. })
    ));

    // Before the fix, `finished` was set before verification, so these returned Ok(0) and the
    // corruption looked like a successful, empty read.
    for attempt in 0..3 {
        let error = file
            .read_to_end(&mut Vec::new())
            .expect_err("a failed entry must keep failing");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "attempt {attempt}"
        );
    }
}

#[test]
fn a_size_limit_failure_also_sticks() {
    let mut b = ZipBuilder::new();
    b.add_deflate("big.txt", &b"a".repeat(50_000)[..]);
    let buf = b.finish();

    let options = ReadOptions::default().with_max_entry_size(Some(512));
    let mut archive = Archive::new_with_options(Cursor::new(buf), options).unwrap();
    let mut file = archive.by_index(0).unwrap();

    assert!(file.read_to_end(&mut Vec::new()).is_err());
    assert!(matches!(
        file.terminal_error(),
        Some(Error::SizeLimitExceeded { .. })
    ));
    assert!(file.read_to_end(&mut Vec::new()).is_err());
}

// ---------------------------------------------------------------------------------------
// Reader: the declared size is checked even when it is zero
// ---------------------------------------------------------------------------------------

#[test]
fn a_declared_size_of_zero_no_longer_disables_the_size_check() {
    let mut b = ZipBuilder::new();
    b.add_deflate("liar.txt", b"definitely not empty");
    let mut buf = b.finish();

    // Zero the uncompressed size in the central directory, leaving the payload intact. This
    // used to be treated as "unknown", which switched verification off.
    let cd = find_all(&buf, SIG_CENTRAL)[0];
    buf[cd + 24..cd + 28].copy_from_slice(&0u32.to_le_bytes());

    let mut archive = open(buf);
    assert_eq!(archive.entries()[0].uncompressed_size(), 0);
    match archive.read_entry(0) {
        Err(Error::SizeMismatch { actual, .. }) => {
            assert_eq!(actual, b"definitely not empty".len() as u64);
        }
        other => panic!("expected SizeMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Reader: safe defaults
// ---------------------------------------------------------------------------------------

#[test]
fn the_default_read_options_cap_entry_size() {
    let options = ReadOptions::default();
    assert_eq!(options.max_entry_size, Some(zipcore::MAX_IN_MEMORY_ENTRY));
    assert!(options.verify_crc);
    assert!(options.verify_size);

    assert_eq!(ReadOptions::unlimited().max_entry_size, None);
    assert_eq!(
        ReadOptions::default()
            .with_max_entry_size(Some(7))
            .max_entry_size,
        Some(7)
    );
}

// ---------------------------------------------------------------------------------------
// Reader: malformed input is reported with enough context to act on
// ---------------------------------------------------------------------------------------

#[test]
fn malformed_errors_name_the_offset() {
    let mut b = ZipBuilder::new();
    b.add_stored("one.txt", b"first");
    b.add_stored("two.txt", b"second");
    let mut buf = b.finish();

    // Break the *second* central directory record, so the first-record probe still succeeds
    // and the failure happens inside the parse loop.
    let records = find_all(&buf, SIG_CENTRAL);
    assert_eq!(records.len(), 2);
    buf[records[1]] = 0;

    match Archive::new(Cursor::new(buf)) {
        Err(Error::Malformed(message)) => {
            assert!(
                message.contains("offset"),
                "message should name a location, was: {message}"
            );
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Extraction: limits and reporting
// ---------------------------------------------------------------------------------------

#[test]
fn extraction_reports_what_it_wrote() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.txt", b"aaaa");
    b.add_deflate("b.txt", b"bbbbbb");
    b.add_stored("c.txt", b"cc");
    let mut archive = open(b.finish());

    let dir = temp_dir("report");
    let report = archive.extract_all(&dir).unwrap();
    assert_eq!(report.written.len(), 3);
    assert_eq!(report.total_bytes, 4 + 6 + 2);
    assert!(report.skipped_symlinks.is_empty());
    assert!(dir.join("b.txt").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_entry_count_limit_is_enforced() {
    let mut b = ZipBuilder::new();
    for i in 0..5 {
        b.add_stored(&format!("f{i}.txt"), b"x");
    }
    let mut archive = open(b.finish());

    let dir = temp_dir("maxentries");
    let limits = ExtractLimits {
        max_entries: Some(2),
        ..ExtractLimits::default()
    };
    match archive.extract_all_with_limits(&dir, &limits) {
        Err(Error::LimitExceeded { detail }) => assert!(detail.contains("2-entry"), "{detail}"),
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
    // Exactly the permitted number were written before stopping.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_total_byte_limit_is_enforced() {
    let mut b = ZipBuilder::new();
    for i in 0..5 {
        b.add_stored(&format!("f{i}.txt"), &b"0123456789"[..]);
    }
    let mut archive = open(b.finish());

    let dir = temp_dir("maxbytes");
    let limits = ExtractLimits {
        max_total_bytes: Some(25),
        ..ExtractLimits::default()
    };
    match archive.extract_all_with_limits(&dir, &limits) {
        Err(Error::LimitExceeded { detail }) => assert!(detail.contains("25-byte"), "{detail}"),
        other => panic!("expected LimitExceeded, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// Writing: names, failure latch, sink recovery
// ---------------------------------------------------------------------------------------

#[test]
fn writing_an_unsafe_name_is_refused_by_default() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();

    let result = writer.add_file("../escape.txt", b"x", &FileOptions::stored());
    match result {
        Err(Error::UnsafePath { entry, reason }) => {
            assert_eq!(entry, "../escape.txt");
            assert_eq!(reason, "parent traversal");
        }
        other => panic!("expected UnsafePath, got {other:?}"),
    }

    // An absolute name is refused too.
    assert!(writer
        .add_file("/etc/passwd", b"x", &FileOptions::stored())
        .is_err());
}

#[test]
fn unsafe_names_can_be_enabled_explicitly() {
    let options = WriteOptions {
        allow_unsafe_names: true,
        ..WriteOptions::default()
    };
    let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options).unwrap();
    writer
        .add_file("../escape.txt", b"x", &FileOptions::stored())
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();

    // It round-trips, and the reader still refuses to turn it into a path.
    let archive = open(buf);
    assert_eq!(archive.entries()[0].name(), "../escape.txt");
    assert!(archive.entries()[0].safe_path().is_err());
}

/// A sink that rejects writes while `failures_left` is non-zero, once the write position has
/// reached `fail_at`.
///
/// A one-shot failure is what makes the writer's latch observable: without it, a later write
/// would silently succeed into an archive whose structure no longer adds up.
#[derive(Debug)]
struct FlakySink {
    inner: Cursor<Vec<u8>>,
    failures_left: usize,
    fail_at: u64,
}

impl Write for FlakySink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failures_left > 0 && self.inner.position() >= self.fail_at {
            self.failures_left -= 1;
            return Err(io::Error::other("sink write failed"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for FlakySink {
    fn seek(&mut self, pos: std::io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn a_failed_write_latches_and_the_cause_survives_to_finish() {
    let sink = FlakySink {
        inner: Cursor::new(Vec::new()),
        failures_left: 1,
        // The local header write starts at 0 and succeeds; the compressed payload write
        // starts at 30-odd and trips the sink.
        fail_at: 30,
    };
    let mut writer = ZipWriter::new(sink).unwrap();

    // The local header fits; a later data write trips the sink once.
    assert!(writer
        .add_file("big.bin", &vec![b'a'; 200_000], &FileOptions::deflate(1))
        .is_err());

    // The sink would accept bytes again now. Without the latch, this entry would be appended
    // to an archive whose structure no longer adds up.
    assert!(writer
        .add_file("another.bin", b"x", &FileOptions::stored())
        .is_err());

    // And finishing reports the original cause, not a generic "already finished".
    let error = writer.finish().unwrap_err();
    assert!(
        error.to_string().contains("sink write failed"),
        "finish reported: {error}"
    );
}

#[test]
fn finish_ref_leaves_the_sink_recoverable_after_a_failure() {
    let sink = FlakySink {
        inner: Cursor::new(Vec::new()),
        failures_left: 1,
        fail_at: 0,
    };
    let mut writer = ZipWriter::new(sink).unwrap();

    // The end of central directory record cannot be written.
    assert!(writer.finish_ref().is_err());

    // Unlike `finish`, the writer is still ours, so the sink can be reclaimed and reused.
    let mut recovered = writer.into_inner();
    recovered.write_all(b"still usable").unwrap();
    assert_eq!(recovered.inner.get_ref().as_slice(), b"still usable");
}

// ---------------------------------------------------------------------------------------
// Extraction: Unix permission bits (compiled and run on Unix hosts only)
// ---------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn extraction_restores_unix_permission_bits() {
    use std::os::unix::fs::PermissionsExt;

    let mut b = ZipBuilder::new();
    b.add_stored("run.sh", b"#!/bin/sh\n");
    let mut buf = b.finish();

    // Record mode 0100755 in the central directory's external attributes. The fixture builder
    // already declares host 3 (Unix), so `unix_mode()` will report it.
    let cd = find_all(&buf, SIG_CENTRAL)[0];
    buf[cd + 38..cd + 42].copy_from_slice(&(0o100_755u32 << 16).to_le_bytes());

    let mut archive = open(buf);
    let dir = temp_dir("unixmode");
    let path = archive.extract_entry(0, &dir).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "the recorded mode should be restored");

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn setuid_and_setgid_bits_are_not_restored() {
    use std::os::unix::fs::PermissionsExt;

    let mut b = ZipBuilder::new();
    b.add_stored("tool", b"binary");
    let mut buf = b.finish();

    // 0104755: setuid plus rwxr-xr-x. Honouring setuid out of an untrusted archive is a
    // privilege-escalation vector, so only the 0777 part may survive.
    let cd = find_all(&buf, SIG_CENTRAL)[0];
    buf[cd + 38..cd + 42].copy_from_slice(&(0o104_755u32 << 16).to_le_bytes());

    let mut archive = open(buf);
    let dir = temp_dir("setuid");
    let path = archive.extract_entry(0, &dir).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    assert_eq!(mode & 0o4000, 0, "setuid must be dropped");
    assert_eq!(mode & 0o2000, 0, "setgid must be dropped");

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_zero_recorded_mode_leaves_the_default_alone() {
    use std::os::unix::fs::PermissionsExt;

    // A Unix-host entry with no mode bits recorded must not be chmod'ed to 000.
    let mut b = ZipBuilder::new();
    b.add_stored("plain.txt", b"data");
    let mut archive = open(b.finish());

    let dir = temp_dir("zeromode");
    let path = archive.extract_entry(0, &dir).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert!(
        mode & 0o400 != 0,
        "owner must still be able to read it, got {mode:o}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// Panic-freedom sweep
// ---------------------------------------------------------------------------------------

#[test]
fn mutated_archives_never_panic() {
    // A stand-in for a fuzz target: deterministic mutations of a valid archive, asserting only
    // that the reader never panics. It may accept, reject or partially read ??never unwind.
    let mut b = ZipBuilder::new();
    b.add_deflate("text.txt", &b"hello world ".repeat(60)[..]);
    b.add_stored("bytes.bin", &b"stored content here"[..]);
    b.add_stored("empty.txt", b"");
    let original = b.finish();

    let mut parsed = 0usize;
    let mut bytes_read = 0usize;

    for seed in 0..600usize {
        let mut bytes = original.clone();

        let cut = (seed * 7) % bytes.len();
        bytes.truncate(bytes.len() - cut);
        if bytes.is_empty() {
            continue;
        }

        let index = (seed * 31) % bytes.len();
        bytes[index] ^= 0x5a;

        if seed % 3 == 0 {
            let index = (seed * 17) % bytes.len();
            bytes[index] = 0xff;
        }

        if let Ok(mut archive) = Archive::new(Cursor::new(bytes)) {
            parsed += 1;
            for index in 0..archive.len() {
                if let Ok(mut file) = archive.by_index(index) {
                    if let Ok(written) = io::copy(&mut file, &mut io::sink()) {
                        bytes_read += written as usize;
                    }
                }
            }
        }
    }

    // Not a correctness assertion: just evidence the sweep exercised something.
    assert!(parsed > 0, "no mutated archive was parseable at all");
    let _ = bytes_read;
}
