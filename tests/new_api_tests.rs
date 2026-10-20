//! Tests for the APIs added after the 0.1.0 public-readiness analysis.

mod common;

use std::io::Cursor;
use zipcore::{Archive, Error, ExtractLimits, FileOptions, ZipWriter};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("zipcore-new-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------------------------
// API-1: refuse to write over an existing archive
// ---------------------------------------------------------------------------------------

#[test]
fn api1_new_rejects_a_non_empty_sink() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("keep.txt", b"survive", &FileOptions::stored())
        .unwrap();
    let existing = w.finish().unwrap().into_inner();

    // Starting a fresh archive over those bytes must fail rather than destroy them.
    let err = ZipWriter::new(Cursor::new(existing.clone())).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("new_append"),
        "the error should point at the fix: {msg}"
    );
}

#[test]
fn api1_new_accepts_an_empty_sink() {
    assert!(ZipWriter::new(Cursor::new(Vec::new())).is_ok());
}

// ---------------------------------------------------------------------------------------
// API-2: append to an existing archive
// ---------------------------------------------------------------------------------------

#[test]
fn api2_append_adds_to_an_existing_archive() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("first.txt", b"one", &FileOptions::stored())
        .unwrap();
    let existing = w.finish().unwrap().into_inner();

    let cursor = Cursor::new(existing.clone());
    let mut appended = ZipWriter::new_append(cursor, Cursor::new(existing)).unwrap();
    appended
        .add_file("second.txt", b"two", &FileOptions::stored())
        .unwrap();
    let out = appended.finish().unwrap().into_inner();

    let mut a = Archive::new(Cursor::new(out)).unwrap();
    assert_eq!(a.len(), 2, "both entries must survive the append");
    assert_eq!(a.entries()[0].name(), "first.txt");
    assert_eq!(a.entries()[1].name(), "second.txt");
    assert_eq!(a.read_entry(0).unwrap(), b"one");
    assert_eq!(a.read_entry(1).unwrap(), b"two");
}

#[test]
fn api2_append_preserves_entry_metadata_and_payload_bytes() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    let opts = FileOptions::default()
        .with_unix_mode(0o100_755)
        .with_comment("kept")
        .with_dos_timestamp(((2020 - 1980) << 9) | (6 << 5) | 15, 9 << 11);
    w.add_file("script.sh", b"#!/bin/sh\n", &opts).unwrap();
    let existing = w.finish().unwrap().into_inner();
    let before = Archive::new(Cursor::new(existing.clone())).unwrap();
    let before_entry = before.entries()[0].clone();

    let mut appended =
        ZipWriter::new_append(Cursor::new(existing.clone()), Cursor::new(existing)).unwrap();
    appended
        .add_file("extra.bin", b"x", &FileOptions::stored())
        .unwrap();
    let out = appended.finish().unwrap().into_inner();

    let after = Archive::new(Cursor::new(out)).unwrap();
    let after_entry = &after.entries()[0];
    assert_eq!(after_entry.name(), before_entry.name());
    assert_eq!(after_entry.crc32(), before_entry.crc32());
    assert_eq!(after_entry.unix_mode(), before_entry.unix_mode());
    assert_eq!(after_entry.comment(), before_entry.comment());
    assert_eq!(after_entry.dos_timestamp(), before_entry.dos_timestamp());
}

#[test]
fn api2_append_does_not_grow_the_file_on_each_call() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("a.txt", b"aaaa", &FileOptions::stored())
        .unwrap();
    let mut bytes = w.finish().unwrap().into_inner();

    let mut sizes = Vec::new();
    for i in 0..5 {
        let mut ap =
            ZipWriter::new_append(Cursor::new(bytes.clone()), Cursor::new(bytes.clone())).unwrap();
        ap.add_file(&format!("n{i}.txt"), b"z", &FileOptions::stored())
            .unwrap();
        bytes = ap.finish().unwrap().into_inner();
        sizes.push(bytes.len());
        let a = Archive::new(Cursor::new(bytes.clone())).unwrap();
        assert_eq!(a.len(), i + 2, "each append adds exactly one entry");
    }
    // Because the old central directory is overwritten, growth is linear in entry count,
    // not quadratic in the number of appends.
    let growth_first = sizes[1] - sizes[0];
    let growth_last = sizes[4] - sizes[3];
    assert!(
        growth_last <= growth_first + 40,
        "per-append growth should stay flat, got {sizes:?}"
    );
}

#[test]
fn api2_append_reports_a_bad_source() {
    let bad = b"this is not a zip".to_vec();
    match ZipWriter::new_append(Cursor::new(Vec::new()), Cursor::new(bad)) {
        Err(Error::InvalidSignature) | Err(Error::Malformed(_)) => {}
        other => panic!("expected a parse error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// API-3: aggregate expansion budget
// ---------------------------------------------------------------------------------------

#[test]
fn api3_limits_cap_total_bytes_across_entries() {
    // Ten entries of 10 KiB each: individually small, collectively 100 KiB.
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    for i in 0..10 {
        w.add_file(
            &format!("f{i}.bin"),
            &vec![b'x'; 10 * 1024],
            &FileOptions::deflate(6),
        )
        .unwrap();
    }
    let buf = w.finish().unwrap().into_inner();

    let dir = temp_dir("api3");
    let mut a = Archive::new(Cursor::new(buf)).unwrap();
    let limits = ExtractLimits {
        max_entries: None,
        max_total_bytes: Some(25 * 1024),
        overwrite: zipcore::Overwrite::Replace,
        atomic_write: zipcore::AtomicWrite::Enabled,
    };
    let result = a.extract_all_with_limits(&dir, &limits);
    assert!(result.is_err(), "the aggregate budget must be enforced");
    let total: u64 = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.metadata().unwrap().len())
        .sum();
    assert!(
        total <= 25 * 1024,
        "wrote {total} bytes against a 25 KiB budget"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// API-4: extended timestamps (0x5455)
// ---------------------------------------------------------------------------------------

#[test]
fn api4_extended_timestamp_is_written_and_read_back_to_the_second() {
    // 2024-02-29 12:34:57 UTC ??an odd second that DOS cannot represent.
    let unix = 1_709_210_097u32; // 2024-02-29T12:34:57Z
    let opts = FileOptions::default().with_unix_mtime(Some(unix as u64));
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("t.txt", b"x", &opts).unwrap();
    let buf = w.finish().unwrap().into_inner();

    let a = Archive::new(Cursor::new(buf)).unwrap();
    assert_eq!(
        a.entries()[0].unix_mtime(),
        Some(unix as u64),
        "the exact second must survive, not DOS's 2-second rounding"
    );
}

#[test]
fn api4_dos_timestamp_is_still_the_fallback_when_no_extended_field_exists() {
    // Writer without an explicit mtime records DOS only; reading must not invent one.
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("t.txt", b"x", &FileOptions::stored()).unwrap();
    let buf = w.finish().unwrap().into_inner();
    let a = Archive::new(Cursor::new(buf)).unwrap();
    let _ = a.entries()[0].unix_mtime();
    assert_eq!(a.entries()[0].unix_mtime(), None);
}

// ---------------------------------------------------------------------------------------
// API-5: extraction overwrite policy
// ---------------------------------------------------------------------------------------

#[test]
fn api5_overwrite_policy_can_refuse_to_clobber() {
    let dir = temp_dir("api5");
    std::fs::write(dir.join("a.txt"), b"precious").unwrap();

    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("a.txt", b"from archive", &FileOptions::stored())
        .unwrap();
    let buf = w.finish().unwrap().into_inner();

    let mut a = Archive::new(Cursor::new(buf.clone())).unwrap();
    let limits = ExtractLimits {
        max_entries: None,
        max_total_bytes: None,
        overwrite: zipcore::Overwrite::Never,
        atomic_write: zipcore::AtomicWrite::Enabled,
    };
    let r = a.extract_all_with_limits(&dir, &limits);
    assert!(
        r.is_err(),
        "clobbering must be refused under Overwrite::Never"
    );
    assert_eq!(
        std::fs::read(dir.join("a.txt")).unwrap(),
        b"precious",
        "the pre-existing file must be untouched"
    );

    // The default still overwrites, as before.
    let mut a2 = Archive::new(Cursor::new(buf)).unwrap();
    a2.extract_all(&dir).unwrap();
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"from archive");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// API-6: add_symlink helper
// ---------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn api6_add_symlink_round_trips_as_a_symlink() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_symlink("link", "target/file.txt", &FileOptions::default())
        .unwrap();
    let buf = w.finish().unwrap().into_inner();
    let a = Archive::new(Cursor::new(buf)).unwrap();
    assert!(a.entries()[0].is_symlink());
    assert!(!a.entries()[0].is_dir());
    assert_eq!(
        a.entries()[0].unix_mode().map(|m| m & 0o170000),
        Some(0o120000)
    );
}

#[test]
fn api6_add_symlink_refuses_an_empty_target() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    assert!(w.add_symlink("link", "", &FileOptions::default()).is_err());
}

// ---------------------------------------------------------------------------------------
// API-7: atomic vs direct extraction
// ---------------------------------------------------------------------------------------

#[test]
fn api7_atomic_is_the_default() {
    assert_eq!(
        ExtractLimits::default().atomic_write,
        zipcore::AtomicWrite::Enabled,
        "the safe behaviour must be what you get without asking"
    );
}

#[test]
fn api7_direct_mode_still_writes_correct_content() {
    let dir = temp_dir("api7-direct");
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("a.txt", b"direct content", &FileOptions::stored())
        .unwrap();
    let buf = w.finish().unwrap().into_inner();

    let mut a = Archive::new(Cursor::new(buf)).unwrap();
    let limits = ExtractLimits {
        atomic_write: zipcore::AtomicWrite::Disabled,
        ..ExtractLimits::default()
    };
    a.extract_all_with_limits(&dir, &limits).unwrap();
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"direct content");
    // No stray temporary files either way.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files leaked: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn api7_atomic_mode_leaves_nothing_when_the_crc_fails() {
    // Corrupt the payload so the entry fails verification after it has been written out.
    let dir = temp_dir("api7-crc");
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file(
        "bad.bin",
        b"payload that will be corrupted",
        &FileOptions::stored(),
    )
    .unwrap();
    let mut buf = w.finish().unwrap().into_inner();

    // Flip a byte inside the stored payload (local header is 30 + name + extra).
    let name_len = "bad.bin".len();
    let payload_at = 30 + name_len;
    buf[payload_at] ^= 0xFF;

    let mut a = Archive::new(Cursor::new(buf)).unwrap();
    // Atomic mode: the failed entry must leave no file behind.
    let r = a.extract_all_with_limits(&dir, &ExtractLimits::default());
    assert!(r.is_err(), "corruption must be detected");
    let files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
    assert!(
        files.is_empty(),
        "atomic mode must leave nothing behind, found {files:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
