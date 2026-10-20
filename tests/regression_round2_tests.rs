//! Regression tests for the defects found in the full review.
//!
//! Each test names the finding it pins; the module is grouped the same way as the review report
//! so a future change that reintroduces one of them fails with a message that says which.

mod common;

use common::*;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use zipcore::{
    Archive, AtomicWrite, Error, ExtractLimits, FileOptions, ReadOptions, WriteOptions, ZipWriter,
};

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CD: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_Z64_EOCD: u32 = 0x0606_4b50;
const SIG_Z64_LOC: u32 = 0x0706_4b50;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipcore-rev-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn find_all(haystack: &[u8], needle: [u8; 4]) -> Vec<usize> {
    haystack
        .windows(4)
        .enumerate()
        .filter(|(_, window)| *window == needle.as_slice())
        .map(|(index, _)| index)
        .collect()
}

// ---------------------------------------------------------------------------------------
// C1 / C2: i64 overflow in the offset arithmetic
// ---------------------------------------------------------------------------------------

/// A ZIP64 archive whose ZIP64 EOCD declares an attacker-chosen `cd_offset`, with one real
/// central directory record placed so `cd_end - cd_size` lands exactly on it.
fn zip64_with_cd_offset(cd_offset: u64) -> Vec<u8> {
    let mut cd = Vec::new();
    cd.extend_from_slice(&SIG_CD.to_le_bytes());
    cd.extend_from_slice(&0x031eu16.to_le_bytes());
    cd.extend_from_slice(&45u16.to_le_bytes());
    for _ in 0..6 {
        cd.extend_from_slice(&0u16.to_le_bytes());
    }
    for _ in 0..3 {
        cd.extend_from_slice(&0u32.to_le_bytes());
    }
    cd.extend_from_slice(&1u16.to_le_bytes()); // name len
    cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
    cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
    cd.extend_from_slice(&0u16.to_le_bytes()); // disk
    cd.extend_from_slice(&0u16.to_le_bytes()); // internal
    cd.extend_from_slice(&0u32.to_le_bytes()); // external
    cd.extend_from_slice(&1u32.to_le_bytes()); // local header offset
    cd.push(b'x');

    let mut out = vec![0u8; 8];
    out.extend_from_slice(&cd);
    let cd_size = cd.len() as u64;
    let z64 = out.len() as u64;
    out.extend_from_slice(&SIG_Z64_EOCD.to_le_bytes());
    out.extend_from_slice(&44u64.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&SIG_Z64_LOC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&z64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0xffffu16.to_le_bytes());
    out.extend_from_slice(&0xffffu16.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn c1_a_forged_zip64_cd_offset_is_an_error_not_a_panic() {
    // 2^63 and the values around it used to overflow `derived as i64 - cd_offset as i64`.
    for offset in [1u64 << 63, (1u64 << 63) + 1, (1u64 << 63) + 31, u64::MAX] {
        let outcome = std::panic::catch_unwind(move || {
            Archive::new(Cursor::new(zip64_with_cd_offset(offset))).map(|_| ())
        });
        let result = outcome.unwrap_or_else(|_| panic!("panicked on cd_offset {offset}"));
        match result {
            Ok(()) => {}
            Err(Error::Malformed(_)) => {}
            Err(other) => panic!("expected a clean Malformed error, got {other:?}"),
        }
    }
}

#[test]
fn c2_absolute_offset_cannot_overflow() {
    // A base offset near i64::MAX plus a large recorded offset is the same class of bug in
    // `absolute_offset`; the archive must either open cleanly or fail as malformed.
    const D: u64 = 8;
    let mut cd = Vec::new();
    cd.extend_from_slice(&SIG_CD.to_le_bytes());
    cd.extend_from_slice(&0x031eu16.to_le_bytes());
    cd.extend_from_slice(&45u16.to_le_bytes());
    for _ in 0..6 {
        cd.extend_from_slice(&0u16.to_le_bytes());
    }
    for _ in 0..3 {
        cd.extend_from_slice(&0u32.to_le_bytes());
    }
    cd.extend_from_slice(&1u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&1u32.to_le_bytes()); // entry offset = 1
    cd.push(b'x');

    let mut out = vec![0u8; D as usize];
    out.extend_from_slice(&cd);
    let cd_size = cd.len() as u64;
    let z64 = out.len() as u64;
    out.extend_from_slice(&SIG_Z64_EOCD.to_le_bytes());
    out.extend_from_slice(&44u64.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    // (2^63 + D + 1) - (2^63 + D + 1) ... chosen so base_offset lands at i64::MAX without
    // overflowing the subtraction itself; only `recorded + base_offset` can overflow.
    out.extend_from_slice(&((1u64 << 63) + D + 1).to_le_bytes());
    out.extend_from_slice(&SIG_Z64_LOC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&z64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0xffffu16.to_le_bytes());
    out.extend_from_slice(&0xffffu16.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    let outcome = std::panic::catch_unwind(move || {
        let mut archive = Archive::new(Cursor::new(out))?;
        archive.by_index(0).map(|_| ())
    });
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!("panicked in the entry-offset arithmetic"),
    }
}

// ---------------------------------------------------------------------------------------
// H4 / M7: extraction accounting
// ---------------------------------------------------------------------------------------

/// Two entries each declaring `u64::MAX` uncompressed bytes, with a one-byte payload.
fn archive_with_huge_declared_sizes() -> Vec<u8> {
    let mut local_offsets = Vec::new();
    let mut out = Vec::new();
    for name in [b"a".as_slice(), b"b".as_slice()] {
        local_offsets.push(out.len() as u64);
        out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc32fast::hash(b"x").to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.push(b'x');
    }
    let cd_offset = out.len() as u64;
    let mut cd = Vec::new();
    for (name, offset) in [b"a".as_slice(), b"b".as_slice()]
        .iter()
        .zip(&local_offsets)
    {
        cd.extend_from_slice(&SIG_CD.to_le_bytes());
        cd.extend_from_slice(&0x031eu16.to_le_bytes());
        cd.extend_from_slice(&45u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&u32::MAX.to_le_bytes());
        cd.extend_from_slice(&u32::MAX.to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(4u16 + 16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        // Only the two sizes are sentinels, so the ZIP64 extra field carries exactly 16 bytes and
        // the offset stays a literal.
        cd.extend_from_slice(&(*offset as u32).to_le_bytes());
        cd.extend_from_slice(name);
        cd.extend_from_slice(&0x0001u16.to_le_bytes());
        cd.extend_from_slice(&16u16.to_le_bytes());
        cd.extend_from_slice(&u64::MAX.to_le_bytes()); // uncompressed
        cd.extend_from_slice(&1u64.to_le_bytes()); // compressed
    }
    let cd_size = cd.len() as u64;
    out.extend_from_slice(&cd);
    let z64 = out.len() as u64;
    out.extend_from_slice(&SIG_Z64_EOCD.to_le_bytes());
    out.extend_from_slice(&44u64.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&2u64.to_le_bytes());
    out.extend_from_slice(&2u64.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&SIG_Z64_LOC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&z64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0xffffu16.to_le_bytes());
    out.extend_from_slice(&0xffffu16.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn h4_extract_all_does_not_overflow_its_byte_counter() {
    let dir = temp_dir("h4");
    let options = ReadOptions {
        verify_size: false,
        verify_crc: false,
        ..ReadOptions::default()
    };
    let outcome = std::panic::catch_unwind(|| {
        let mut archive =
            Archive::new_with_options(Cursor::new(archive_with_huge_declared_sizes()), options)
                .unwrap();
        archive.extract_all(&dir)
    });
    let report = outcome.expect("the byte counter must not overflow");
    // The total counts what was written (1 byte each), not the declared u64::MAX.
    assert_eq!(report.unwrap().total_bytes, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m7_the_total_byte_limit_counts_bytes_actually_written() {
    // A deflate entry that declares 0 bytes but expands to 2 MiB.
    let content = vec![b'X'; 2 << 20];
    let payload = miniz_oxide::deflate::compress_to_vec(&content, 6);
    let crc = crc32fast::hash(&content);
    let name = b"bomb.txt";
    let mut out = Vec::new();
    out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // lies about the size
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&payload);
    let cd_offset = out.len() as u64;
    let mut cd = Vec::new();
    cd.extend_from_slice(&SIG_CD.to_le_bytes());
    cd.extend_from_slice(&0x031eu16.to_le_bytes());
    cd.extend_from_slice(&45u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&8u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(name);
    let cd_size = cd.len() as u64;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    let dir = temp_dir("m7");
    let mut archive =
        Archive::new_with_options(Cursor::new(out), ReadOptions::unlimited()).unwrap();
    let limits = ExtractLimits {
        max_entries: None,
        max_total_bytes: Some(1024),
        overwrite: zipcore::Overwrite::Replace,
        atomic_write: zipcore::AtomicWrite::Enabled,
    };
    let result = archive.extract_all_with_limits(&dir, &limits);
    let written: u64 = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.metadata().unwrap().len())
        .sum();
    // The cap is enforced against real output, so no more than 1 KiB lands on disk.
    assert!(
        written <= 1024,
        "wrote {written} bytes under a 1024-byte limit"
    );
    assert!(result.is_err(), "exceeding the limit must be reported");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// M5: no corrupt file is left behind
// ---------------------------------------------------------------------------------------

#[test]
fn m5_a_crc_failure_leaves_no_file_behind() {
    let mut b = ZipBuilder::new();
    b.add_deflate_bad_crc("report.txt", b"the real contents");
    let mut archive = Archive::new(Cursor::new(b.finish())).unwrap();

    let dir = temp_dir("m5");
    match archive.extract_entry(0, &dir) {
        Err(Error::CrcMismatch { .. }) => {}
        other => panic!("expected CrcMismatch, got {other:?}"),
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed extraction left {leftovers:?} behind"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// M5b / M8: containment
// ---------------------------------------------------------------------------------------

#[test]
fn m8_a_junction_in_the_destination_cannot_redirect_a_write() {
    let base = temp_dir("m8");
    let dest = base.join("dest");
    let outside = base.join("outside");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let link = dest.join("esc");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output();
    let created = matches!(&made, Ok(output) if output.status.success());
    if !created {
        // Creating a junction needs no elevation, but skip rather than fail on a host that
        // refuses it for another reason.
        let _ = std::fs::remove_dir_all(&base);
        return;
    }

    let mut b = ZipBuilder::new();
    b.add_stored("esc/evil.txt", b"ESCAPED");
    let mut archive = Archive::new(Cursor::new(b.finish())).unwrap();
    let result = archive.extract_entry(0, &dest);

    assert!(
        !outside.join("evil.txt").exists(),
        "the write followed a junction out of the destination"
    );
    assert!(
        matches!(result, Err(Error::UnsafePath { .. })),
        "expected UnsafePath, got {result:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

// ---------------------------------------------------------------------------------------
// M3 / L1: Windows-normalised names
// ---------------------------------------------------------------------------------------

#[test]
fn m3_device_names_with_trailing_space_or_dot_are_rejected() {
    let mut b = ZipBuilder::new();
    for name in ["nul ", "con ", "aux.", "com1 ", "lpt9.  ", "PRN."] {
        b.add_stored(name, b"x");
    }
    let archive = Archive::new(Cursor::new(b.finish())).unwrap();
    for entry in archive.entries() {
        assert!(
            entry.safe_path().is_err(),
            "`{}` should not be accepted as a path",
            entry.name()
        );
    }
}

#[test]
fn l1_names_that_collapse_on_windows_are_rejected() {
    let mut b = ZipBuilder::new();
    for name in ["trail.", "trail ", "trail..", "dir./file"] {
        b.add_stored(name, b"x");
    }
    let archive = Archive::new(Cursor::new(b.finish())).unwrap();
    for entry in archive.entries() {
        assert!(
            entry.safe_path().is_err(),
            "`{}` collapses onto another name on Windows",
            entry.name()
        );
    }
}

// ---------------------------------------------------------------------------------------
// R8 / N1: symlink handling is consistent
// ---------------------------------------------------------------------------------------

#[test]
fn n1_a_symlink_entry_with_a_trailing_slash_is_refused_not_created() {
    let mut b = ZipBuilder::new();
    b.add_stored("link/", b"target");
    let mut buf = b.finish();
    // Record S_IFLNK in the external attributes of the central record.
    let cd = find_all(&buf, SIG_CD.to_le_bytes())[0];
    buf[cd + 38..cd + 42].copy_from_slice(&(0o120_777u32 << 16).to_le_bytes());

    let mut archive = Archive::new(Cursor::new(buf)).unwrap();
    assert!(archive.entries()[0].is_symlink());

    let dir = temp_dir("n1");
    assert!(matches!(
        archive.extract_entry(0, &dir),
        Err(Error::Unsupported(_))
    ));
    assert!(!dir.join("link").exists(), "a symlink was materialised");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// L5: a truncated record is Malformed, not Io
// ---------------------------------------------------------------------------------------

#[test]
fn l5_a_truncated_central_directory_is_malformed() {
    let mut b = ZipBuilder::new();
    b.add_stored("file.txt", b"some contents here");
    let mut bytes = b.finish();

    let cd_pos = find_all(&bytes, SIG_CD.to_le_bytes())[0];
    bytes.truncate(cd_pos + 10);
    bytes.extend_from_slice(&SIG_EOCD.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&60u32.to_le_bytes());
    bytes.extend_from_slice(&(cd_pos as u32).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());

    match Archive::new(Cursor::new(bytes)) {
        Err(Error::Malformed(message)) => {
            assert!(
                message.contains("offset"),
                "message should name a location: {message}"
            );
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// M4: ZIP64 disk start
// ---------------------------------------------------------------------------------------

#[test]
fn m4_a_zip64_disk_start_that_does_not_fit_is_rejected() {
    // A ZIP64 extra field whose disk-start value is 0x1_0000: truncating it to a u16 would read
    // as 0 and make a spanned archive look local.
    let name = b"x";
    let mut cd = Vec::new();
    cd.extend_from_slice(&SIG_CD.to_le_bytes());
    cd.extend_from_slice(&0x031eu16.to_le_bytes());
    cd.extend_from_slice(&45u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&8u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0xffffu16.to_le_bytes()); // disk start sentinel
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(name);
    cd.extend_from_slice(&0x0001u16.to_le_bytes());
    cd.extend_from_slice(&4u16.to_le_bytes());
    cd.extend_from_slice(&0x0001_0000u32.to_le_bytes());
    let cd_size = cd.len() as u64;

    let mut out = cd;
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    match Archive::new(Cursor::new(out)) {
        Err(Error::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// H1: finish_ref must not lose entries on a retry
// ---------------------------------------------------------------------------------------

/// A sink that fails once, once its position reaches `fail_at`.
#[derive(Debug)]
struct FailOnceSink {
    inner: Cursor<Vec<u8>>,
    fail_at: u64,
    armed: bool,
}

impl Write for FailOnceSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.armed && self.inner.position() >= self.fail_at {
            self.armed = false;
            return Err(io::Error::other("one-shot sink failure"));
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for FailOnceSink {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn h1_a_retried_finish_ref_never_reports_success_with_fewer_entries() {
    let data = vec![b'q'; 5000];
    let cd_start = (30 + "kept.txt".len() + data.len()) as u64;

    let sink = FailOnceSink {
        inner: Cursor::new(Vec::new()),
        fail_at: cd_start,
        armed: true,
    };
    let mut writer = ZipWriter::new(sink).unwrap();
    writer
        .add_file("kept.txt", &data, &FileOptions::stored())
        .unwrap();

    let first = writer.finish_ref();
    assert!(first.is_err(), "the first finish must fail");

    // Whatever the retry returns, it must not produce an archive that silently claims zero
    // entries: either it reports the latched failure, or it succeeds with the entry intact.
    let second = writer.finish_ref();
    let bytes = writer.into_inner().inner.into_inner();
    if second.is_ok() {
        let archive = Archive::new(Cursor::new(bytes)).expect("a reported success must reopen");
        assert_eq!(
            archive.len(),
            1,
            "finish_ref reported success but lost the only entry"
        );
    }
}

#[test]
fn h1b_a_latched_writer_reports_the_original_cause_repeatedly() {
    // Fail while writing the central directory, so the writer is genuinely latched partway
    // through finishing rather than rejected at the first header.
    let sink = FailOnceSink {
        inner: Cursor::new(Vec::new()),
        fail_at: 400,
        armed: true,
    };
    let mut writer = ZipWriter::new(sink).unwrap();
    writer
        .add_file("x.bin", &vec![b'a'; 500], &FileOptions::stored())
        .unwrap();
    let first = writer.finish_ref().unwrap_err().to_string();
    assert!(
        first.contains("one-shot sink failure"),
        "the first failure should name its cause: {first}"
    );
    let second = writer.finish_ref().unwrap_err().to_string();
    assert!(
        second.contains("one-shot sink failure"),
        "the latched cause should survive into later calls: {second}"
    );
}

// ---------------------------------------------------------------------------------------
// H3: the u32::MAX boundary on the write side
// ---------------------------------------------------------------------------------------

#[test]
fn h3_a_size_hint_of_exactly_u32_max_reserves_zip64() {
    let options = FileOptions::default().with_size_hint(u32::MAX as u64);
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.add_file("big.bin", b"tiny", &options).unwrap();
    let buf = writer.finish().unwrap().into_inner();

    // Version 45 and a 20-byte ZIP64 extra field: the sentinel is only legal with them present.
    assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 45, "version needed");
    assert_eq!(
        u32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]),
        u32::MAX
    );
    assert_eq!(
        u32::from_le_bytes([buf[22], buf[23], buf[24], buf[25]]),
        u32::MAX
    );
    let extra_len = u16::from_le_bytes([buf[28], buf[29]]);
    assert_eq!(extra_len, 20, "ZIP64 extra field must be reserved");

    // And the archive this writer produced must be readable by the same crate.
    let mut archive = Archive::new(Cursor::new(buf)).unwrap();
    assert_eq!(archive.read_entry(0).unwrap(), b"tiny");
}

// ---------------------------------------------------------------------------------------
// M2: names that do not fit the 16-bit length field
// ---------------------------------------------------------------------------------------

#[test]
fn m2_a_name_longer_than_u16_max_is_refused() {
    let long = "n".repeat(70_000);
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    let error = writer
        .add_file(&long, b"payload", &FileOptions::stored())
        .expect_err("an over-long name must be refused");
    assert!(
        error.to_string().contains("16-bit"),
        "the message should explain the limit: {error}"
    );
    // The writer is not left wedged: a normal entry still works.
    writer
        .add_file("ok.txt", b"x", &FileOptions::stored())
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();
    let archive = Archive::new(Cursor::new(buf)).unwrap();
    assert_eq!(archive.len(), 1);
}

#[test]
fn m2b_a_comment_too_long_is_refused_before_anything_is_written() {
    let options = FileOptions::default().with_comment("c".repeat(70_000));
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    assert!(writer.add_file("x.txt", b"y", &options).is_err());
    writer
        .add_file("ok.txt", b"z", &FileOptions::stored())
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();
    let archive = Archive::new(Cursor::new(buf)).unwrap();
    assert_eq!(archive.len(), 1);
}

#[test]
fn l4_an_archive_comment_that_is_too_long_fails_without_losing_the_entries() {
    let options = WriteOptions {
        comment: Some("c".repeat(70_000)),
        ..WriteOptions::default()
    };
    let mut writer =
        ZipWriter::new_with_options(Cursor::new(Vec::new()), options).expect("empty sink");
    writer
        .add_file("kept.txt", b"hello", &FileOptions::stored())
        .unwrap();

    let error = writer.finish_ref().expect_err("the comment is too long");
    assert!(error.to_string().contains("comment too long"), "{error}");
    // The entries are still known to the writer rather than silently dropped.
    assert_eq!(writer.len(), 1);
}

// ---------------------------------------------------------------------------------------
// H2 / M1: tar stream alignment and failure latching
// ---------------------------------------------------------------------------------------

#[test]
fn h2_a_short_tar_entry_still_leaves_a_block_aligned_stream() {
    use zipcore::{TarEntryOptions, TarWriter};

    let mut buf: Vec<u8> = Vec::new();
    {
        let mut tar = TarWriter::new(&mut buf);
        {
            let mut entry = tar
                .start_file("short.bin", 1000, &TarEntryOptions::default())
                .unwrap();
            entry.write_all(&[b'A'; 500]).unwrap();
            // Dropped with 500 bytes outstanding: the old code padded only the tail, so the
            // next header landed off a block boundary.
        }
        tar.add_file("next.txt", b"hello", &TarEntryOptions::default())
            .unwrap();
        // The contents are wrong, so finishing must be refused even though the stream parses.
        assert!(
            tar.finish().is_err(),
            "a short entry must poison the writer"
        );
    }

    assert_eq!(
        buf.len() % 512,
        0,
        "a short entry must still leave a whole number of blocks"
    );
    let offset = buf
        .windows(8)
        .position(|window| window == b"next.txt")
        .expect("the entry after a short one must still be present");
    assert_eq!(
        offset % 512,
        0,
        "the next header must be block-aligned, was at {offset}"
    );
}

#[test]
fn m1_a_tar_sink_failure_poisons_the_writer() {
    use zipcore::{TarEntryOptions, TarWriter};

    /// A sink that fails once at a chosen position.
    struct FailingSink {
        inner: Cursor<Vec<u8>>,
        fail_at: u64,
        armed: bool,
    }
    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.armed && self.inner.position() >= self.fail_at {
                self.armed = false;
                return Err(io::Error::other("tar sink failure"));
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Seek for FailingSink {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    let sink = FailingSink {
        inner: Cursor::new(Vec::new()),
        // The first header (512 bytes) and its payload block land before this offset, so the
        // second entry's header is the write that trips.
        fail_at: 1024,
        armed: true,
    };
    let mut tar = TarWriter::new(sink);
    // The first header succeeds; the second trips the sink.
    tar.add_file("one.txt", b"first", &TarEntryOptions::default())
        .unwrap();
    assert!(
        tar.add_file("two.txt", b"second", &TarEntryOptions::default())
            .is_err(),
        "the sink failure must be reported"
    );
    // Because a header was half-written, the stream can no longer be trusted.
    assert!(
        tar.finish().is_err(),
        "a corrupt tar stream must not be blessed as success"
    );
}

/// A junction (Windows) or symlink (Unix) already sitting inside the destination must not let an
/// entry be written outside it. This is the attack name sanitisation cannot see: the *name* is
/// harmless, and the redirect only exists on disk.
#[test]
fn m8b_pre_existing_junction_cannot_redirect_a_write() {
    // Both policies matter. With `AtomicWrite::Enabled` the rename replaces a symlink rather than
    // following it, so the escape is masked; with `Disabled` the write goes straight through
    // `File::create`, which does follow it. CI caught this on Linux after Windows passed.
    for atomic in [AtomicWrite::Enabled, AtomicWrite::Disabled] {
        let base =
            std::env::temp_dir().join(format!("zc-junction-{}-{atomic:?}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("dest");
        let outside = base.join("outside");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim.txt");
        std::fs::write(&victim, b"ORIGINAL CONTENT").unwrap();

        // File symlinks need a privilege on Windows; directory junctions do not.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&victim, dest.join("pwned.txt")).unwrap();
        }
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(dest.join("sub"))
                .arg(&outside)
                .status()
                .unwrap();
            if !status.success() {
                let _ = std::fs::remove_dir_all(&base);
                continue;
            }
        }

        let mut w = ZipWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        #[cfg(unix)]
        w.add_file("pwned.txt", b"ATTACKER", &FileOptions::stored())
            .unwrap();
        #[cfg(windows)]
        w.add_file("sub/victim.txt", b"ATTACKER", &FileOptions::stored())
            .unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let mut archive = Archive::new(std::io::Cursor::new(bytes)).unwrap();
        let limits = ExtractLimits {
            atomic_write: atomic,
            ..ExtractLimits::default()
        };
        let error = archive
            .extract_all_with_limits(&dest, &limits)
            .expect_err("writing through a link must be refused");
        assert!(
            error.to_string().contains("outside the destination"),
            "the refusal should name the reason: {error}"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"ORIGINAL CONTENT",
            "the file outside the destination must be untouched ({atomic:?})"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
