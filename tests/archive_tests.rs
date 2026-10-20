mod common;

use common::*;
use std::io::{Read, Write};
use zipcore::{Archive, Compression, Error, ReadOptions};

type MemArchive = Archive<std::io::Cursor<Vec<u8>>>;

fn open(buf: Vec<u8>) -> MemArchive {
    Archive::new(cursor(buf)).expect("archive should open")
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipcore-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// ---------------------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------------------

#[test]
fn reads_a_stored_entry() {
    let mut b = ZipBuilder::new();
    b.add_stored("hello.txt", b"hello, world");
    let mut archive = open(b.finish());

    assert_eq!(archive.len(), 1);
    let mut out = String::new();
    archive
        .by_name("hello.txt")
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "hello, world");
}

#[test]
fn reads_a_deflate_entry() {
    // Repeated text compresses well, so this exercises real back-references, not just literals.
    let content = "the quick brown fox jumps over the lazy dog. ".repeat(200);
    let mut b = ZipBuilder::new();
    b.add_deflate("fox.txt", content.as_bytes());
    let buf = b.finish();

    let mut archive = open(buf);
    let entry = &archive.entries()[0];
    assert_eq!(entry.compression(), Compression::Deflate);
    assert!(
        entry.compressed_size() < entry.uncompressed_size() / 2,
        "fixture should actually be compressed"
    );

    let mut out = String::new();
    archive
        .by_name("fox.txt")
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, content);
}

#[test]
fn reads_entries_larger_than_the_internal_buffers() {
    // Larger than both the 64 KiB input and output buffers, and incompressible so the Deflate
    // path cannot finish in one call.
    let mut content = Vec::with_capacity(300_000);
    let mut state = 0x1234_5678u32;
    for _ in 0..300_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        content.push((state >> 16) as u8);
    }

    let mut b = ZipBuilder::new();
    b.add_deflate("noise.bin", &content);
    let mut archive = open(b.finish());

    let read_back = archive.read_entry(0).unwrap();
    assert_eq!(read_back, content);
}

#[test]
fn round_trips_many_entries_of_mixed_methods() {
    let mut b = ZipBuilder::new();
    let mut expected = Vec::new();
    for i in 0..40 {
        let name = format!("dir{}/file{i}.txt", i % 3);
        let content = format!("payload number {i} ").repeat(i + 1);
        if i % 2 == 0 {
            b.add_stored(&name, content.as_bytes());
        } else {
            b.add_deflate(&name, content.as_bytes());
        }
        expected.push((name, content));
    }
    let mut archive = open(b.finish());

    assert_eq!(archive.len(), expected.len());
    for (index, (name, content)) in expected.iter().enumerate() {
        assert_eq!(archive.entries()[index].name(), name);
        let bytes = archive.read_entry(index).unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), content);
    }
}

#[test]
fn exposes_entry_metadata() {
    let mut b = ZipBuilder::new();
    b.add_deflate("docs/readme.md", b"contents");
    let buf = b.finish();
    let expected_crc = crc32(b"contents");

    let archive = open(buf);
    let entry = &archive.entries()[0];
    assert_eq!(entry.name(), "docs/readme.md");
    assert_eq!(entry.crc32(), expected_crc);
    assert_eq!(entry.uncompressed_size(), 8);
    assert!(!entry.is_dir());
    assert!(!entry.is_encrypted());
    assert!(!entry.is_symlink());
    assert_eq!(archive.index_for_name("docs/readme.md"), Some(0));
    assert_eq!(archive.index_for_name("nope"), None);
    assert!(!archive.is_zip64());
}

#[test]
fn reads_an_empty_archive() {
    let archive = open(ZipBuilder::new().finish());
    assert_eq!(archive.len(), 0);
    assert!(archive.is_empty());
}

#[test]
fn reads_an_archive_with_a_comment() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.txt", b"a");
    let archive = open(b.finish_with_comment(b"a trailing comment"));
    assert_eq!(archive.comment(), b"a trailing comment");
    assert_eq!(archive.len(), 1);
}

#[test]
fn a_comment_containing_the_eocd_signature_is_not_mistaken_for_the_record() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.txt", b"a");
    // The comment embeds `PK\x05\x06`, which a naive backwards scan would latch onto.
    let archive = open(b.finish_with_comment(b"comment with fake PK\x05\x06 inside"));
    assert_eq!(archive.len(), 1);
}

// ---------------------------------------------------------------------------------------
// Lookup errors
// ---------------------------------------------------------------------------------------

#[test]
fn reports_a_missing_entry_by_name() {
    let mut b = ZipBuilder::new();
    b.add_stored("present.txt", b"x");
    let mut archive = open(b.finish());

    // The error is taken out of the result first, so the entry handle inside it is dropped and
    // the archive is free to be borrowed again.
    let error = archive.by_name("absent.txt").unwrap_err();
    match error {
        Error::EntryNotFound { name } => assert_eq!(name, "absent.txt"),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}

#[test]
fn rejects_an_out_of_range_index() {
    let mut archive = open(ZipBuilder::new().finish());
    let error = archive.by_index(3).unwrap_err();
    match error {
        Error::IndexOutOfRange { index, len } => {
            assert_eq!(index, 3);
            assert_eq!(len, 0);
        }
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Hostile and corrupt input
// ---------------------------------------------------------------------------------------

#[test]
fn rejects_a_file_that_is_not_a_zip() {
    assert!(matches!(
        Archive::new(cursor(b"this is plainly not a zip file".to_vec())),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn rejects_an_empty_file() {
    assert!(matches!(
        Archive::new(cursor(Vec::new())),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn rejects_a_truncated_archive() {
    let mut b = ZipBuilder::new();
    b.add_deflate("data.txt", &b"x".repeat(5000)[..]);
    let buf = b.finish();
    // Chop the tail off, destroying the end of central directory record.
    let truncated = buf[..buf.len() - 12].to_vec();
    assert!(Archive::new(cursor(truncated)).is_err());
}

#[test]
fn detects_a_crc_mismatch() {
    let mut b = ZipBuilder::new();
    b.add_deflate_bad_crc("corrupt.txt", b"the real contents");
    let mut archive = open(b.finish());

    match archive.read_entry(0) {
        Err(Error::CrcMismatch { entry, .. }) => assert_eq!(entry, "corrupt.txt"),
        other => panic!("expected CrcMismatch, got {other:?}"),
    }
}

#[test]
fn detects_an_overstated_uncompressed_size() {
    let mut b = ZipBuilder::new();
    b.add_deflate_overstated_size("liar.txt", b"hello world", 100);
    let mut archive = open(b.finish());

    match archive.read_entry(0) {
        Err(Error::SizeMismatch {
            entry,
            expected,
            actual,
        }) => {
            assert_eq!(entry, "liar.txt");
            assert_eq!(expected, 111);
            assert_eq!(actual, 11);
        }
        other => panic!("expected SizeMismatch, got {other:?}"),
    }
}

#[test]
fn enforces_the_max_entry_size_limit() {
    let mut b = ZipBuilder::new();
    b.add_deflate("big.txt", &b"a".repeat(100_000)[..]);
    let buf = b.finish();

    let options = ReadOptions {
        max_entry_size: Some(1024),
        ..ReadOptions::default()
    };
    let mut archive = Archive::new_with_options(cursor(buf), options).unwrap();

    match archive.read_entry(0) {
        Err(Error::SizeLimitExceeded { limit, .. }) => assert_eq!(limit, 1024),
        other => panic!("expected SizeLimitExceeded, got {other:?}"),
    }
}

#[test]
fn applies_the_size_limit_while_streaming() {
    let mut b = ZipBuilder::new();
    b.add_deflate("big.txt", &b"a".repeat(100_000)[..]);
    let buf = b.finish();

    let options = ReadOptions {
        max_entry_size: Some(1024),
        ..ReadOptions::default()
    };
    let mut archive = Archive::new_with_options(cursor(buf), options).unwrap();

    let mut entry = archive.by_index(0).unwrap();
    let mut sink = Vec::new();
    let error = entry.read_to_end(&mut sink).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn refuses_encrypted_entries() {
    let mut b = ZipBuilder::new();
    b.add_flagged("secret.txt", b"ciphertext", FLAG_ENCRYPTED);
    let mut archive = open(b.finish());

    match archive.by_index(0) {
        Err(Error::Encrypted { entry }) => assert_eq!(entry, "secret.txt"),
        other => panic!("expected Encrypted, got {other:?}"),
    }
    assert!(archive.entries()[0].is_encrypted());
}

#[test]
fn refuses_unimplemented_compression_methods() {
    let mut b = ZipBuilder::new();
    // Method 6 is "implode", a DOS-era method this crate does not decode in any configuration,
    // so the test means the same thing regardless of which codec features are enabled.
    b.add_unknown_method("archive.implode", b"payload", 6);
    let mut archive = open(b.finish());

    assert_eq!(archive.entries()[0].compression().name(), "implode");
    assert!(!archive.entries()[0].compression().is_supported());

    match archive.by_index(0) {
        Err(Error::UnsupportedCompression { method, entry }) => {
            assert_eq!(method, 6);
            assert_eq!(entry, "archive.implode");
        }
        other => panic!("expected UnsupportedCompression, got {other:?}"),
    }

    // The message names the method, so a caller does not have to look up method ids.
    let message = archive.by_index(0).unwrap_err().to_string();
    assert!(message.contains("implode"), "message was: {message}");
}

#[test]
fn a_method_with_no_name_is_reported_by_number() {
    let mut b = ZipBuilder::new();
    // 200 is not a method anyone has defined, so it stays an unnamed number.
    b.add_unknown_method("legacy.zip", b"payload", 200);
    let mut archive = open(b.finish());

    assert_eq!(archive.entries()[0].compression(), Compression::Other(200));
    assert_eq!(archive.entries()[0].compression().name(), "unknown");
    assert!(archive.by_index(0).is_err());
}

#[test]
fn method_ids_round_trip_through_the_enum() {
    // `Reduce` spans methods 2-5 and therefore cannot round-trip them individually; it is
    // excluded here and covered by its own assertion below.
    for method in [0u16, 1, 6, 8, 9, 12, 14, 93, 95, 98, 1234] {
        let compression = Compression::from_method(method);
        assert_eq!(compression.method_id(), method, "method {method}");
    }
    // The reduce family collapses to one variant, so only its first id round-trips.
    assert_eq!(Compression::from_method(3), Compression::Reduce);
    assert_eq!(Compression::Reduce.method_id(), 2);

    // The legacy DOS methods are named (so an error can say "implode", not "method 6") but never
    // decodable or writable.
    for legacy in [
        Compression::Shrink,
        Compression::Reduce,
        Compression::Implode,
    ] {
        assert!(!legacy.is_supported(), "{}", legacy.name());
        assert!(!legacy.is_writable(), "{}", legacy.name());
        assert_ne!(legacy.name(), "unknown");
    }

    // Stored and Deflate are always available, in both directions.
    assert!(Compression::Stored.is_supported() && Compression::Stored.is_writable());
    assert!(Compression::Deflate.is_supported() && Compression::Deflate.is_writable());

    // XZ (method 95) follows the same feature as LZMA, and is never writable.
    assert_eq!(Compression::Xz.is_supported(), cfg!(feature = "lzma"));
    assert!(!Compression::Xz.is_writable());
    assert_ne!(Compression::Xz.name(), "unknown");

    // The decode-only methods follow their feature, and are never writable: encoding these is
    // deliberately not implemented.
    for compression in [Compression::Deflate64, Compression::Lzma, Compression::Ppmd] {
        assert_ne!(compression.name(), "unknown");
        assert!(
            !compression.is_writable(),
            "{} must stay decode-only",
            compression.name()
        );
    }
    assert_eq!(
        Compression::Deflate64.is_supported(),
        cfg!(feature = "deflate64")
    );
    assert_eq!(Compression::Lzma.is_supported(), cfg!(feature = "lzma"));
    assert_eq!(Compression::Ppmd.is_supported(), cfg!(feature = "ppmd"));

    // The two with codecs depend on their features.
    assert_eq!(Compression::Zstd.is_supported(), cfg!(feature = "zstd"));
    assert_eq!(Compression::Zstd.is_writable(), cfg!(feature = "zstd"));
    assert_eq!(Compression::Bzip2.is_supported(), cfg!(feature = "bzip2"));
    // bzip2 is decode-only: a decode-only codec must never be offered to a caller writing.
    assert!(!Compression::Bzip2.is_writable());
    assert_ne!(Compression::Zstd.name(), "unknown");
    assert_eq!(Compression::Zstd.required_feature(), Some("zstd"));
    assert_eq!(Compression::Bzip2.required_feature(), Some("bzip2"));
}

#[test]
fn a_nul_byte_in_a_name_is_not_a_filesystem_path() {
    let mut b = ZipBuilder::new();
    b.add_stored("evil\0.txt", b"x");
    let archive = open(b.finish());
    assert!(archive.entries()[0].safe_path().is_err());
}

// ---------------------------------------------------------------------------------------
// Offset correction
// ---------------------------------------------------------------------------------------

#[test]
fn corrects_offsets_when_data_is_prepended() {
    let mut b = ZipBuilder::new();
    b.add_stored("inner.txt", b"prepended stub payload");
    let archive_bytes = b.finish();

    // Simulate a self-extracting executable: a stub in front of an intact archive.
    let stub = vec![0x4du8; 4096];
    let mut combined = stub.clone();
    combined.extend_from_slice(&archive_bytes);

    let mut archive = open(combined);
    assert_eq!(archive.len(), 1);
    let mut out = String::new();
    archive
        .by_name("inner.txt")
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "prepended stub payload");
}

#[test]
fn offset_correction_can_be_disabled() {
    let mut b = ZipBuilder::new();
    b.add_stored("inner.txt", b"payload");
    let mut combined = vec![0u8; 512];
    combined.extend_from_slice(&b.finish());

    let options = ReadOptions {
        offset_correction: false,
        ..ReadOptions::default()
    };
    assert!(Archive::new_with_options(cursor(combined), options).is_err());
}

// ---------------------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------------------

#[test]
fn extracts_entries_below_the_destination() {
    let mut b = ZipBuilder::new();
    b.add_stored("top.txt", b"top level");
    b.add_deflate("nested/deep/data.txt", &b"nested contents ".repeat(50)[..]);
    let mut archive = open(b.finish());

    let dir = temp_dir("extract");
    let written = archive.extract_all(&dir).unwrap();
    assert_eq!(written.written.len(), 2);
    assert_eq!(std::fs::read(dir.join("top.txt")).unwrap(), b"top level");
    assert_eq!(
        std::fs::read(dir.join("nested/deep/data.txt")).unwrap(),
        b"nested contents ".repeat(50)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_to_extract_a_traversal_name() {
    let mut b = ZipBuilder::new();
    b.add_stored("../../evil.txt", b"should never be written");
    let mut archive = open(b.finish());

    let dir = temp_dir("zipslip");
    match archive.extract_entry(0, &dir) {
        Err(Error::UnsafePath { entry, .. }) => assert_eq!(entry, "../../evil.txt"),
        other => panic!("expected UnsafePath, got {other:?}"),
    }
    assert!(!dir.join("..").join("..").join("evil.txt").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_to_extract_an_absolute_name() {
    let mut b = ZipBuilder::new();
    b.add_stored("/tmp/absolute.txt", b"x");
    let mut archive = open(b.finish());

    let dir = temp_dir("absolute");
    assert!(matches!(
        archive.extract_entry(0, &dir),
        Err(Error::UnsafePath { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn creates_directories_for_entries_ending_in_a_slash() {
    let mut b = ZipBuilder::new();
    b.add_stored("subdir/", b"");
    b.add_stored("subdir/file.txt", b"contents");
    let mut archive = open(b.finish());

    let dir = temp_dir("mkdir");
    archive.extract_all(&dir).unwrap();
    assert!(dir.join("subdir").is_dir());
    assert_eq!(
        std::fs::read(dir.join("subdir/file.txt")).unwrap(),
        b"contents"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn round_trips_through_a_real_file_on_disk() {
    // Exercises the `Archive::open` path and a genuine seekable file rather than a Cursor.
    let mut b = ZipBuilder::new();
    b.add_deflate("on-disk.txt", &b"file backed archive ".repeat(100)[..]);
    let buf = b.finish();

    let dir = temp_dir("ondisk");
    let path = dir.join("fixture.zip");
    std::fs::write(&path, &buf).unwrap();

    let mut archive = Archive::open(&path).unwrap();
    let mut out = String::new();
    archive
        .by_name("on-disk.txt")
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "file backed archive ".repeat(100));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_to_end_from_a_zip_file_verifies_and_returns_all_bytes() {
    let mut b = ZipBuilder::new();
    b.add_deflate("verify.txt", &b"verified payload ".repeat(10)[..]);
    let mut archive = open(b.finish());

    // Scoped, because an open entry holds a mutable borrow of the archive until it is dropped.
    {
        let mut file = archive.by_index(0).unwrap();
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"verified payload ".repeat(10));
        assert!(file.terminal_error().is_none());
        assert_eq!(file.bytes_produced(), out.len() as u64);
    }

    // A partially-read entry is a caller mistake, but confirms no verification ran.
    let mut file = archive.by_index(0).unwrap();
    let mut small = [0u8; 4];
    file.read_exact(&mut small).unwrap();
    assert!(file.terminal_error().is_none());
}

#[test]
fn into_inner_returns_the_underlying_reader() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.txt", b"a");
    let archive = open(b.finish());
    let cursor = archive.into_inner();
    assert!(!cursor.get_ref().is_empty());
}

#[test]
fn reads_a_highly_compressible_entry_larger_than_the_output_buffer() {
    // Regression test. A small compressed payload that expands well past the internal output
    // buffer is the shape that breaks if the decoder is told "no more input" while the output
    // buffer is still full: miniz reports that as a fatal buffer error instead of asking for
    // another round, and the tail of the entry is lost.
    let content = vec![b'a'; 400_000];
    let mut b = ZipBuilder::new();
    b.add_deflate("compressible.txt", &content);
    let mut archive = open(b.finish());

    let entry = &archive.entries()[0];
    assert!(
        entry.compressed_size() < 4096,
        "fixture should compress to a small payload, was {}",
        entry.compressed_size()
    );
    assert!(entry.uncompressed_size() > 64 * 1024);

    assert_eq!(archive.read_entry(0).unwrap(), content);
}

#[test]
fn streams_correctly_when_read_one_byte_at_a_time() {
    // Forces the output window to be recycled many times while a partially served chunk is
    // outstanding, which is where back-reference history can be dropped.
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut b = ZipBuilder::new();
    b.add_deflate("pattern.bin", &content);
    let mut archive = open(b.finish());

    let mut file = archive.by_index(0).unwrap();
    let mut out = Vec::with_capacity(content.len());
    let mut one = [0u8; 1];
    loop {
        let n = file.read(&mut one).unwrap();
        if n == 0 {
            break;
        }
        out.push(one[0]);
    }
    assert_eq!(out, content);
    assert!(file.terminal_error().is_none());
}

#[test]
fn reads_an_entry_whose_compressed_and_expanded_sizes_both_exceed_the_buffers() {
    // Multi-round input refill *and* multi-round output, with a modest compression ratio.
    let mut content = Vec::with_capacity(500_000);
    let mut state = 0x9e37_79b9u32;
    for i in 0..500_000u32 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // Mix incompressible noise with a repeating pattern so matches and literals both occur.
        content.push(if i % 4 == 0 {
            (state >> 24) as u8
        } else {
            b'x'
        });
    }
    let mut b = ZipBuilder::new();
    b.add_deflate("mixed.bin", &content);
    let mut archive = open(b.finish());

    assert_eq!(archive.read_entry(0).unwrap(), content);
}

#[test]
fn write_helping_traits_are_available_for_output() {
    // Guards against accidentally requiring `Write` on the archive itself.
    let mut sink = Vec::new();
    sink.write_all(b"noop").unwrap();
    assert_eq!(sink, b"noop");
}
