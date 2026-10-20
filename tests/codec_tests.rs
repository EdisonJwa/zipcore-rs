//! Compression methods beyond Stored and Deflate.
//!
//! These tests deliberately cover *both* build configurations. With the feature off, a zstd entry
//! must be refused with an error that names the method and says which feature would fix it. With
//! the feature on, it must decode and verify like any other entry. A build that quietly claimed
//! support it does not have would pass one of these and fail the other.

mod common;

use common::*;
use std::io::Cursor;
use zipcore::{Archive, Compression, Error};

fn open(buf: Vec<u8>) -> Archive<Cursor<Vec<u8>>> {
    Archive::new(Cursor::new(buf)).expect("archive should open")
}

// ---------------------------------------------------------------------------------------
// Independent of the feature: the method is named either way
// ---------------------------------------------------------------------------------------

#[test]
fn a_zstd_entry_is_reported_as_zstd() {
    let mut b = ZipBuilder::new();
    b.add_zstd("data.bin", b"payload");
    let archive = open(b.finish());

    let compression = archive.entries()[0].compression();
    assert_eq!(compression, Compression::Zstd);
    assert_eq!(compression.name(), "zstd");
    assert_eq!(compression.method_id(), 93);
    assert_eq!(compression.required_feature(), Some("zstd"));
}

#[test]
fn the_capability_flags_track_the_feature() {
    // The whole point of these flags is that they never overstate the build.
    assert_eq!(Compression::Zstd.is_supported(), cfg!(feature = "zstd"));
    assert_eq!(Compression::Zstd.is_writable(), cfg!(feature = "zstd"));
    // Methods with no codec at all are never writable, feature or not.
    assert!(!Compression::Bzip2.is_writable());
    assert!(!Compression::Lzma.is_writable());
}

#[test]
fn stored_and_deflate_are_unaffected_by_the_codec_path() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.txt", b"stored");
    b.add_deflate("b.txt", &b"deflated ".repeat(100)[..]);
    let mut archive = open(b.finish());

    assert_eq!(archive.read_entry(0).unwrap(), b"stored");
    assert_eq!(archive.read_entry(1).unwrap(), b"deflated ".repeat(100));
}

// ---------------------------------------------------------------------------------------
// Feature off
// ---------------------------------------------------------------------------------------

#[cfg(not(feature = "zstd"))]
#[test]
fn without_the_feature_a_zstd_entry_is_refused_with_a_usable_message() {
    let mut b = ZipBuilder::new();
    b.add_zstd("data.bin", b"payload");
    let mut archive = open(b.finish());

    assert!(!Compression::Zstd.is_supported());
    let error = archive.by_index(0).unwrap_err();
    match &error {
        Error::UnsupportedCompression { method, entry } => {
            assert_eq!(*method, 93);
            assert_eq!(entry, "data.bin");
        }
        other => panic!("expected UnsupportedCompression, got {other:?}"),
    }

    // The caller should be told which method and which feature, not just a number.
    let message = error.to_string();
    assert!(message.contains("zstd"), "message was: {message}");
    assert!(message.contains("`zstd` feature"), "message was: {message}");
}

// ---------------------------------------------------------------------------------------
// bzip2 (method 12) — decode-only, and a real stream when present
// ---------------------------------------------------------------------------------------

#[test]
fn a_bzip2_entry_is_named_whether_or_not_it_decodes() {
    let mut b = ZipBuilder::new();
    b.add_bzip2("data.bz2", b"bzip2 payload");
    let mut archive = open(b.finish());

    let compression = archive.entries()[0].compression();
    assert_eq!(compression, Compression::Bzip2);
    assert_eq!(compression.name(), "bzip2");
    assert_eq!(compression.required_feature(), Some("bzip2"));
    assert_eq!(compression.is_supported(), cfg!(feature = "bzip2"));

    if cfg!(feature = "bzip2") {
        assert_eq!(archive.read_entry(0).unwrap(), b"bzip2 payload");
    } else {
        match archive.read_entry(0) {
            Err(Error::UnsupportedCompression { method, .. }) => assert_eq!(method, 12),
            other => panic!("expected UnsupportedCompression, got {other:?}"),
        }
        // The hint has to name a feature that actually exists.
        let message = archive.read_entry(0).unwrap_err().to_string();
        assert!(message.contains("bzip2"), "message was: {message}");
    }
}

#[cfg(feature = "bzip2")]
#[test]
fn a_real_bzip2_entry_decodes_and_verifies() {
    // The payload is a genuine bzip2 stream, so a mishandled end of stream or a short window shows
    // up as a CRC-32 or size mismatch instead of passing quietly.
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut b = ZipBuilder::new();
    b.add_bzip2("big.bz2", &content)
        .add_stored("plain.txt", b"stored alongside");
    let mut archive = open(b.finish());

    assert!(
        archive.entries()[0].compressed_size() < archive.entries()[0].uncompressed_size(),
        "the fixture should really be compressed"
    );
    assert_eq!(archive.read_entry(0).unwrap(), content);
    assert_eq!(archive.read_entry(1).unwrap(), b"stored alongside");
}

#[cfg(feature = "bzip2")]
#[test]
fn bzip2_streams_back_in_small_chunks() {
    use std::io::Read;

    let content = "bzip2 streamed ".repeat(4_000);
    let mut b = ZipBuilder::new();
    b.add_bzip2("stream.bz2", content.as_bytes());
    let mut archive = open(b.finish());

    let mut entry = archive.by_index(0).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 9];
    loop {
        let n = entry.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(out, content.as_bytes());
    assert!(entry.terminal_error().is_none());
}

#[cfg(feature = "bzip2")]
#[test]
fn a_bogus_bzip2_payload_fails_loudly() {
    let mut b = ZipBuilder::new();
    b.add_bogus_bzip2("bad.bz2", b"the real content");
    let mut archive = open(b.finish());

    // Garbage that is not a bzip2 stream must be an error, never content.
    assert!(archive.read_entry(0).is_err());
    let message = archive.read_entry(0).unwrap_err().to_string();
    assert!(
        !message.is_empty(),
        "a codec failure should still explain itself"
    );
}

#[cfg(feature = "bzip2")]
#[test]
fn writing_bzip2_is_refused_with_an_actionable_error() {
    use zipcore::{FileOptions, ZipWriter};

    // bzip2 is decode-only, and the writer must say so rather than silently storing or deflating.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let error = writer
        .start_file(
            "data.bz2",
            &FileOptions {
                compression: Compression::Bzip2,
                ..FileOptions::default()
            },
        )
        .unwrap_err();

    match &error {
        Error::CompressionNotWritable { method, entry } => {
            assert_eq!(*method, 12);
            assert_eq!(entry, "data.bz2");
        }
        other => panic!("expected CompressionNotWritable, got {other:?}"),
    }
    let message = error.to_string();
    assert!(
        message.contains("can read but not write"),
        "message was: {message}"
    );
}

// ---------------------------------------------------------------------------------------
// External interop
// ---------------------------------------------------------------------------------------

/// Write a zstd-method archive to a fixed path, so a third-party tool can be pointed at it.
///
/// Ignored by default, and deliberately so: nothing in this repo depends on an external
/// unzipper, but the strongest check available for a codec this crate did not write is a program
/// that did not write it either. Run it, then try the file with 7-Zip:
///
/// ```text
/// cargo test --features zstd -- --ignored emit_zstd_fixture
/// 7z t "$TMPDIR/zipcore-zstd-fixture.zip"
/// ```
#[cfg(feature = "zstd")]
#[test]
#[ignore = "writes a fixture for an external tool to check"]
fn emit_zstd_fixture() {
    use zipcore::{FileOptions, ZipWriter};

    // Written by this crate's own zstd encoder, so an external tool reading it checks the writer
    // as well as the reader.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_file(
            "hello.txt",
            &b"zstd from the writer ".repeat(300),
            &FileOptions {
                compression: Compression::Zstd,
                ..FileOptions::default()
            },
        )
        .unwrap();
    writer
        .add_file(
            "deflated.txt",
            &b"deflated ".repeat(50)[..],
            &FileOptions::default(),
        )
        .unwrap();
    writer
        .add_file(
            "stored.txt",
            b"stored, not compressed\n",
            &FileOptions::stored(),
        )
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();

    let path = std::env::temp_dir().join("zipcore-zstd-fixture.zip");
    std::fs::write(&path, &bytes).expect("fixture should be writable");
    eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());

    // Confirm this crate reads its own fixture back, so a failure later points at the tool.
    let mut archive = open(std::fs::read(&path).unwrap());
    assert_eq!(archive.len(), 3);
    assert_eq!(
        archive.read_entry(0).unwrap(),
        b"zstd from the writer ".repeat(300)
    );
    assert_eq!(archive.read_entry(1).unwrap(), b"deflated ".repeat(50));
    assert_eq!(archive.read_entry(2).unwrap(), b"stored, not compressed\n");
}

// ---------------------------------------------------------------------------------------
// Feature on
// ---------------------------------------------------------------------------------------

#[cfg(feature = "zstd")]
#[test]
fn with_the_feature_a_zstd_entry_decodes() {
    let content = "zstd payload ".repeat(500);
    let mut b = ZipBuilder::new();
    b.add_zstd("data.bin", content.as_bytes());
    let mut archive = open(b.finish());

    assert!(Compression::Zstd.is_supported());
    let entry = archive.entries()[0].clone();
    assert!(
        entry.compressed_size() < entry.uncompressed_size() / 4,
        "fixture should really be compressed: {} -> {}",
        entry.compressed_size(),
        entry.uncompressed_size()
    );
    // `read_entry` verifies the CRC-32 and the declared size, so a wrong payload cannot pass.
    assert_eq!(archive.read_entry(0).unwrap(), content.as_bytes());
}

#[cfg(feature = "zstd")]
#[test]
fn with_the_feature_a_zstd_entry_streams_in_small_chunks() {
    use std::io::Read;

    let content = "chunky zstd payload ".repeat(2_000);
    let mut b = ZipBuilder::new();
    b.add_zstd("data.bin", content.as_bytes());
    let mut archive = open(b.finish());

    let mut entry = archive.by_index(0).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 13];
    loop {
        let n = entry.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(out, content.as_bytes());
    assert!(entry.terminal_error().is_none());
}

#[cfg(feature = "zstd")]
#[test]
fn a_payload_that_is_not_a_zstd_frame_is_an_error_not_garbage() {
    use std::io::Read;

    let mut b = ZipBuilder::new();
    b.add_bogus_zstd("broken.bin", b"whatever this was meant to be");
    let mut archive = open(b.finish());

    let mut entry = archive.by_index(0).unwrap();
    assert!(entry.read_to_end(&mut Vec::new()).is_err());
    // And the failure is terminal, so a retry does not report a clean end of stream.
    assert!(entry.read_to_end(&mut Vec::new()).is_err());
}

#[cfg(feature = "zstd")]
#[test]
fn a_zstd_entry_whose_contents_do_not_match_its_crc_is_caught() {
    // A valid zstd frame, but the central directory records the CRC of different content.
    let mut b = ZipBuilder::new();
    b.add_zstd("wrong.bin", b"the real contents");
    let mut buf = b.finish();

    // Patch the recorded CRC in the central directory.
    let central = buf
        .windows(4)
        .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
        .expect("central directory");
    let bogus = 0x1234_5678u32;
    buf[central + 16..central + 20].copy_from_slice(&bogus.to_le_bytes());

    let mut archive = open(buf);
    match archive.read_entry(0) {
        Err(Error::CrcMismatch { .. }) => {}
        other => panic!("expected CrcMismatch, got {other:?}"),
    }
}

#[cfg(feature = "zstd")]
#[test]
fn a_highly_compressible_zstd_entry_is_capped_while_streaming() {
    use std::io::Read;
    use zipcore::ReadOptions;

    // The codec's own output is unbounded by the headers, so the reader has to be the thing that
    // stops it. A million bytes of one byte compresses to almost nothing.
    let mut b = ZipBuilder::new();
    b.add_zstd("bomb.bin", &vec![b'x'; 1_000_000]);
    let buf = b.finish();

    let options = ReadOptions::default().with_max_entry_size(Some(4096));
    let mut archive = Archive::new_with_options(Cursor::new(buf), options).unwrap();

    let mut entry = archive.by_index(0).unwrap();
    let mut sink = Vec::new();
    assert!(entry.read_to_end(&mut sink).is_err());
    assert!(
        sink.len() <= 4096,
        "nothing past the cap may be handed out, got {}",
        sink.len()
    );
    assert!(matches!(
        entry.terminal_error(),
        Some(Error::SizeLimitExceeded { .. })
    ));
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_entries_can_be_written_and_read_back() {
    use zipcore::{FileOptions, ZipWriter};

    let content = "zstd round trip ".repeat(2_000);
    let zstd = FileOptions {
        compression: Compression::Zstd,
        ..FileOptions::default()
    };

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_file("data.bin", content.as_bytes(), &zstd)
        .unwrap();
    writer
        .add_file("plain.txt", b"stored alongside", &FileOptions::stored())
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();

    let mut archive = open(bytes);
    let entry = archive.entries()[0].clone();
    assert_eq!(entry.compression(), Compression::Zstd);
    assert!(
        entry.compressed_size() < entry.uncompressed_size() / 4,
        "the written entry should really be compressed: {} -> {}",
        entry.compressed_size(),
        entry.uncompressed_size()
    );

    // Reading back verifies the CRC-32 and the declared size, so a wrong frame length or a
    // multi-frame stream would fail here rather than pass quietly.
    assert_eq!(archive.read_entry(0).unwrap(), content.as_bytes());
    assert_eq!(archive.read_entry(1).unwrap(), b"stored alongside");
}

#[cfg(feature = "zstd")]
#[test]
fn a_written_zstd_entry_streams_back_in_small_chunks() {
    use std::io::Read;
    use zipcore::{FileOptions, ZipWriter};

    let content = "chunky ".repeat(5_000);
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_file(
            "data.bin",
            content.as_bytes(),
            &FileOptions {
                compression: Compression::Zstd,
                ..FileOptions::default()
            },
        )
        .unwrap();
    let mut archive = open(writer.finish().unwrap().into_inner());

    let mut entry = archive.by_index(0).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 11];
    loop {
        let n = entry.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(out, content.as_bytes());
    assert!(entry.terminal_error().is_none());
}
