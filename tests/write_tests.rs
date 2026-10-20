//! Tests for archive creation.
//!
//! Two kinds of check are used. Most tests round-trip through [`zipcore::Archive`], but a few
//! parse the produced bytes directly so that a symmetric bug in both the writer and the reader
//! cannot cancel itself out. The archive produced by `examples/create.rs` is additionally
//! checked against PowerShell's own unzipper outside this suite.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use zipcore::{Archive, Compression, Error, FileOptions, WriteOptions, ZipWriter};

const SIG_LOCAL: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const SIG_CENTRAL: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const SIG_EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

fn write_archive(entries: &[(&str, &[u8], FileOptions)]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data, options) in entries {
        writer.add_file(name, data, options).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn open(buf: Vec<u8>) -> Archive<Cursor<Vec<u8>>> {
    Archive::new(Cursor::new(buf)).expect("written archive should open")
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Locate the classic end of central directory record at the end of `buf`.
fn eocd(buf: &[u8]) -> (usize, u64, u64) {
    let base = buf.len() - 22;
    assert_eq!(&buf[base..base + 4], &SIG_EOCD, "EOCD signature");
    let count = le16(&buf[base + 10..]) as u64;
    let offset = le32(&buf[base + 16..]) as u64;
    (base, offset, count)
}

// ---------------------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------------------

#[test]
fn writes_and_reads_back_a_stored_entry() {
    let buf = write_archive(&[("hello.txt", b"hello, world", FileOptions::stored())]);
    let mut archive = open(buf);

    assert_eq!(archive.len(), 1);
    assert_eq!(archive.entries()[0].compression(), Compression::Stored);
    assert_eq!(archive.read_entry(0).unwrap(), b"hello, world");
}

#[test]
fn writes_and_reads_back_a_deflate_entry() {
    let content = "the quick brown fox jumps over the lazy dog. ".repeat(200);
    let buf = write_archive(&[("fox.txt", content.as_bytes(), FileOptions::default())]);
    let mut archive = open(buf);

    let entry = &archive.entries()[0];
    assert_eq!(entry.compression(), Compression::Deflate);
    assert_eq!(entry.uncompressed_size(), content.len() as u64);
    assert!(
        entry.compressed_size() < entry.uncompressed_size() / 2,
        "deflate should actually compress this fixture"
    );
    assert_eq!(archive.read_entry(0).unwrap(), content.as_bytes());
}

#[test]
fn round_trips_many_entries_of_mixed_methods() {
    let mut expected = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..40 {
        let name = format!("dir{}/file{i}.txt", i % 3);
        let content = format!("payload number {i} ").repeat(i + 1);
        let options = if i % 2 == 0 {
            FileOptions::stored()
        } else {
            FileOptions::default()
        };
        writer
            .add_file(&name, content.as_bytes(), &options)
            .unwrap();
        expected.push((name, content));
    }
    let buf = writer.finish().unwrap().into_inner();

    let mut archive = open(buf);
    assert_eq!(archive.len(), expected.len());
    for (index, (name, content)) in expected.iter().enumerate() {
        assert_eq!(archive.entries()[index].name(), name);
        assert_eq!(archive.read_entry(index).unwrap(), content.as_bytes());
    }
}

#[test]
fn round_trips_an_entry_larger_than_the_internal_buffers() {
    // Incompressible, larger than the 64 KiB staging buffer, so both the compressor and the
    // reader have to go around several times.
    let mut content = Vec::with_capacity(400_000);
    let mut state = 0x1357_9bdfu32;
    for _ in 0..400_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        content.push((state >> 16) as u8);
    }

    let buf = write_archive(&[("noise.bin", &content, FileOptions::default())]);
    let mut archive = open(buf);
    assert_eq!(archive.read_entry(0).unwrap(), content);
}

#[test]
fn round_trips_a_highly_compressible_large_entry() {
    let content = vec![b'z'; 500_000];
    let buf = write_archive(&[("compressible.txt", &content, FileOptions::default())]);
    let mut archive = open(buf);

    let entry = &archive.entries()[0];
    assert!(entry.compressed_size() < 4096);
    assert_eq!(archive.read_entry(0).unwrap(), content);
}

#[test]
fn round_trips_an_empty_file() {
    for options in [FileOptions::stored(), FileOptions::default()] {
        let buf = write_archive(&[("empty.txt", b"", options)]);
        let mut archive = open(buf);
        assert_eq!(archive.entries()[0].uncompressed_size(), 0);
        assert_eq!(archive.read_entry(0).unwrap(), b"");
    }
}

#[test]
fn streams_an_entry_written_in_small_pieces() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let mut entry = writer
        .start_file("pieces.txt", &FileOptions::default())
        .unwrap();
    let mut expected = Vec::new();
    for i in 0..1000u32 {
        let piece = format!("piece-{i};");
        entry.write_all(piece.as_bytes()).unwrap();
        expected.extend_from_slice(piece.as_bytes());
    }
    entry.finish().unwrap();
    let buf = writer.finish().unwrap().into_inner();

    let mut archive = open(buf);
    assert_eq!(archive.read_entry(0).unwrap(), expected);
}

#[test]
fn writing_in_one_byte_pieces_matches_one_big_write() {
    let content: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let mut entry = writer
        .start_file("drip.bin", &FileOptions::default())
        .unwrap();
    for byte in &content {
        entry.write_all(&[*byte]).unwrap();
    }
    entry.finish().unwrap();
    let drip = writer.finish().unwrap().into_inner();

    let whole = write_archive(&[("drip.bin", &content, FileOptions::default())]);

    // The compressed bytes should be identical: same data, same level, same order.
    let mut a = open(drip);
    let mut b = open(whole);
    assert_eq!(a.read_entry(0).unwrap(), content);
    assert_eq!(b.read_entry(0).unwrap(), content);
    assert_eq!(
        a.entries()[0].compressed_size(),
        b.entries()[0].compressed_size()
    );
}

// ---------------------------------------------------------------------------------------
// Direct byte-level checks, independent of the reader
// ---------------------------------------------------------------------------------------

#[test]
fn produced_bytes_are_a_well_formed_zip() {
    let data = b"hello world";
    let buf = write_archive(&[("greeting.txt", data, FileOptions::stored())]);

    // Local file header.
    assert_eq!(&buf[0..4], &SIG_LOCAL, "local header signature");
    assert_eq!(le16(&buf[6..]), 0, "no general purpose flags");
    assert_eq!(le16(&buf[8..]), 0, "stored method");
    assert_eq!(le32(&buf[14..]), crc32fast::hash(data), "local CRC-32");
    assert_eq!(
        le32(&buf[18..]) as usize,
        data.len(),
        "local compressed size"
    );
    let name_len = le16(&buf[26..]) as usize;
    assert_eq!(name_len, "greeting.txt".len());
    assert_eq!(le16(&buf[28..]), 0, "no extra field");
    let data_start = 30 + name_len;
    assert_eq!(&buf[data_start..data_start + data.len()], data);

    // End of central directory, and that it points at a real central directory.
    let (_, cd_offset, count) = eocd(&buf);
    assert_eq!(count, 1);
    let cd_offset = cd_offset as usize;
    assert_eq!(
        &buf[cd_offset..cd_offset + 4],
        &SIG_CENTRAL,
        "central header"
    );

    // The central directory's local header offset must point back at the local header.
    assert_eq!(le32(&buf[cd_offset + 42..]), 0);
    // ...and its CRC-32 must match the data too.
    assert_eq!(le32(&buf[cd_offset + 16..]), crc32fast::hash(data));

    // The archive must also be readable by our own reader, which re-derives all of the above.
    let mut archive = open(buf);
    assert_eq!(archive.read_entry(0).unwrap(), data);
}

#[test]
fn central_directory_offset_matches_where_it_actually_is() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_file("a.txt", &b"aaaa".repeat(1000)[..], &FileOptions::default())
        .unwrap();
    writer
        .add_file("b.txt", &b"bbbb".repeat(1000)[..], &FileOptions::default())
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();

    let (eocd_start, cd_offset, count) = eocd(&buf);
    assert_eq!(count, 2);
    // The central directory must end exactly where the EOCD begins.
    let cd_size = le32(&buf[eocd_start + 12..]) as usize;
    assert_eq!(
        cd_offset as usize + cd_size,
        eocd_start,
        "central directory must be contiguous with the EOCD"
    );
    assert_eq!(
        &buf[cd_offset as usize..cd_offset as usize + 4],
        &SIG_CENTRAL
    );
}

#[test]
fn deflate_entries_are_not_stored_verbatim() {
    let content = vec![b'q'; 10_000];
    let buf = write_archive(&[("run.txt", &content, FileOptions::default())]);

    // Find the payload and confirm it is not the raw input.
    let name_len = le16(&buf[26..]) as usize;
    let data_start = 30 + name_len;
    let compressed_size = le32(&buf[18..]) as usize;
    assert!(
        compressed_size < content.len(),
        "payload should be smaller than the input"
    );
    let payload = &buf[data_start..data_start + compressed_size];
    assert_ne!(
        payload,
        &content[..compressed_size],
        "payload must be compressed, not stored verbatim"
    );

    // The payload must not equal the input, so we really wrote compressed bytes.
    let mut archive = open(buf);
    assert_eq!(archive.read_entry(0).unwrap(), content);
    assert!(
        archive.entries()[0].compressed_size() < 200,
        "a run of one byte should compress to a handful of bytes"
    );
}

// ---------------------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------------------

#[test]
fn directory_entries_round_trip() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_directory("nested", &FileOptions::default())
        .unwrap();
    writer
        .add_file("nested/file.txt", b"contents", &FileOptions::default())
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();

    let mut archive = open(buf);
    assert_eq!(archive.len(), 2);
    let dir = &archive.entries()[0];
    assert!(dir.is_dir(), "name should have gained a trailing slash");
    assert_eq!(dir.name(), "nested/");
    assert_eq!(dir.uncompressed_size(), 0);
    // A directory is always stored, never deflated.
    assert_eq!(dir.compression(), Compression::Stored);

    assert_eq!(archive.read_entry(1).unwrap(), b"contents");
}

#[test]
fn an_archive_can_be_extracted_into_directories() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_file("top.txt", b"top", &FileOptions::default())
        .unwrap();
    writer
        .add_file(
            "deep/a/b/c.bin",
            &b"deep data".repeat(500)[..],
            &FileOptions::default(),
        )
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();

    let dir = std::env::temp_dir().join(format!("zipcore-write-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut archive = open(buf);
    archive.extract_all(&dir).unwrap();
    assert_eq!(std::fs::read(dir.join("top.txt")).unwrap(), b"top");
    assert_eq!(
        std::fs::read(dir.join("deep/a/b/c.bin")).unwrap(),
        b"deep data".repeat(500)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unix_mode_is_recorded_when_requested() {
    let options = FileOptions::default().with_unix_mode(0o100_755);
    let buf = write_archive(&[("script.sh", b"#!/bin/sh\n", options)]);
    let archive = open(buf);

    assert_eq!(archive.entries()[0].unix_mode(), Some(0o100_755));
}

#[test]
fn unix_mode_is_absent_when_not_requested() {
    let buf = write_archive(&[("plain.txt", b"x", FileOptions::default())]);
    let archive = open(buf);

    // We still declare a Unix host, but record no mode bits.
    assert_eq!(archive.entries()[0].unix_mode(), Some(0));
}

#[test]
fn explicit_dos_timestamps_round_trip() {
    let (date, time) = zipcore_dos_fixture();
    let options = FileOptions::default().with_dos_timestamp(date, time);
    let buf = write_archive(&[("dated.txt", b"x", options)]);
    let archive = open(buf);

    assert_eq!(archive.entries()[0].dos_timestamp(), (date, time));
}

/// 2024-02-29 12:34:56 encoded by hand.
fn zipcore_dos_fixture() -> (u16, u16) {
    let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
    let time = (12 << 11) | (34 << 5) | (56 / 2);
    (date, time)
}

#[test]
fn entry_and_archive_comments_round_trip() {
    let options = FileOptions::default().with_comment("entry comment");
    let mut writer = ZipWriter::new_with_options(
        Cursor::new(Vec::new()),
        WriteOptions {
            comment: Some("archive comment".to_string()),
            ..WriteOptions::default()
        },
    );
    writer.add_file("commented.txt", b"x", &options).unwrap();
    let buf = writer.finish().unwrap().into_inner();

    let archive = open(buf);
    assert_eq!(archive.comment(), b"archive comment");
    assert_eq!(archive.entries()[0].comment(), Some("entry comment"));
}

#[test]
fn non_ascii_names_are_flagged_and_round_trip() {
    let name = "unicode-\u{65e5}\u{672c}\u{8a9e}-caf\u{e9}.txt";
    let buf = write_archive(&[(name, b"contents", FileOptions::default())]);

    // The UTF-8 general purpose flag (bit 11) must be set.
    assert_ne!(le16(&buf[6..]) & (1 << 11), 0, "UTF-8 flag");

    let mut archive = open(buf);
    assert_eq!(archive.entries()[0].name(), name);
    assert_eq!(archive.read_entry(0).unwrap(), b"contents");
}

// ---------------------------------------------------------------------------------------
// ZIP64
// ---------------------------------------------------------------------------------------

#[test]
fn a_size_hint_reserves_zip64_fields_and_round_trips() {
    // Pretend the entry is 4 GiB so the writer reserves ZIP64 fields, then write a few bytes.
    let options = FileOptions::default().with_size_hint(u32::MAX as u64 + 1);
    let buf = write_archive(&[("big.txt", b"tiny payload", options)]);

    // Local header: version needed 45, sizes are sentinels, and a ZIP64 extra is present.
    assert_eq!(le16(&buf[4..]), 45, "local version needed");
    assert_eq!(le32(&buf[18..]), u32::MAX, "compressed size sentinel");
    assert_eq!(le32(&buf[22..]), u32::MAX, "uncompressed size sentinel");
    let name_len = le16(&buf[26..]) as usize;
    let extra_len = le16(&buf[28..]) as usize;
    assert_eq!(extra_len, 20, "ZIP64 extra field length");

    let extra = 30 + name_len;
    assert_eq!(le16(&buf[extra..]), 0x0001, "ZIP64 extra field id");
    assert_eq!(le16(&buf[extra + 2..]), 16, "ZIP64 extra field data length");
    assert_eq!(
        u64::from_le_bytes(buf[extra + 4..extra + 12].try_into().unwrap()) as usize,
        b"tiny payload".len(),
        "uncompressed size in the ZIP64 extra field"
    );

    // Our reader resolves the sentinels from the extra field.
    let mut archive = open(buf);
    let entry = &archive.entries()[0];
    assert_eq!(entry.uncompressed_size(), b"tiny payload".len() as u64);
    assert_eq!(archive.read_entry(0).unwrap(), b"tiny payload");
}

#[test]
fn more_than_65535_entries_produces_a_zip64_end_of_central_directory() {
    // 70_000 entries pushes the 16-bit entry count past its limit, which forces a ZIP64 EOCD
    // record and locator.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..70_000u32 {
        writer
            .add_file(&format!("f{i:06}"), b"", &FileOptions::stored())
            .unwrap();
    }
    let buf = writer.finish().unwrap().into_inner();

    // Classic EOCD carries the sentinel count, and the locator sits just before it.
    let base = buf.len() - 22;
    assert_eq!(&buf[base..base + 4], &SIG_EOCD);
    assert_eq!(le16(&buf[base + 10..]), u16::MAX, "sentinel entry count");
    let locator = base - 20;
    assert_eq!(
        &buf[locator..locator + 4],
        &[0x50, 0x4b, 0x06, 0x07],
        "locator"
    );

    let archive = open(buf);
    assert!(archive.is_zip64());
    assert_eq!(archive.len(), 70_000);
}

#[test]
fn a_small_archive_has_no_zip64_records() {
    let buf = write_archive(&[("small.txt", b"x", FileOptions::default())]);

    let archive = open(buf);
    assert!(!archive.is_zip64());
}

// ---------------------------------------------------------------------------------------
// Lifecycle and errors
// ---------------------------------------------------------------------------------------

#[test]
fn dropping_a_handle_finishes_the_entry() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    {
        let mut entry = writer
            .start_file("dropped.txt", &FileOptions::stored())
            .unwrap();
        entry.write_all(b"no explicit finish").unwrap();
        // `entry` is dropped here without calling finish().
    }
    writer
        .add_file("second.txt", b"second", &FileOptions::stored())
        .unwrap();
    let buf = writer.finish().unwrap().into_inner();

    let mut archive = open(buf);
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.read_entry(0).unwrap(), b"no explicit finish");
    assert_eq!(archive.read_entry(1).unwrap(), b"second");
}

#[test]
fn an_explicit_finish_is_not_double_counted() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    {
        let mut entry = writer
            .start_file("once.txt", &FileOptions::stored())
            .unwrap();
        entry.write_all(b"written once").unwrap();
        entry.finish().unwrap();
    }
    let buf = writer.finish().unwrap().into_inner();

    let mut archive = open(buf);
    assert_eq!(archive.len(), 1);
    assert_eq!(archive.read_entry(0).unwrap(), b"written once");
}

#[test]
fn an_unsupported_compression_method_is_rejected() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = FileOptions {
        compression: Compression::Other(12),
        ..FileOptions::default()
    };

    // Consuming the result drops the entry handle before we inspect the error.
    let error = writer
        .start_file("bad.bin", &options)
        .expect_err("expected an error");

    match error {
        Error::UnsupportedCompression { method, entry } => {
            assert_eq!(method, 12);
            assert_eq!(entry, "bad.bin");
        }
        other => panic!("expected UnsupportedCompression, got {other:?}"),
    }
}

#[test]
fn an_empty_name_is_rejected() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    assert!(writer.start_file("", &FileOptions::default()).is_err());
}

/// A sink that stops accepting bytes after a fixed budget, to exercise error propagation.
struct FailingSink {
    inner: Cursor<Vec<u8>>,
    budget: usize,
}

impl Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "sink is full"));
        }
        let take = buf.len().min(self.budget);
        self.budget -= take;
        self.inner.write(&buf[..take])
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

#[test]
fn a_failing_sink_surfaces_an_error_from_add_file() {
    let sink = FailingSink {
        inner: Cursor::new(Vec::new()),
        budget: 100,
    };
    let mut writer = ZipWriter::new(sink);

    let result = writer.add_file("large.bin", &vec![b'a'; 200_000], &FileOptions::default());
    assert!(
        result.is_err(),
        "exceeding the sink budget must be reported"
    );
}

#[test]
fn a_failing_sink_also_makes_finish_fail() {
    let sink = FailingSink {
        inner: Cursor::new(Vec::new()),
        budget: 0,
    };
    let mut writer = ZipWriter::new(sink);

    // The very first header write fails, so nothing is ever committed.
    assert!(writer
        .add_file("x.bin", b"data", &FileOptions::default())
        .is_err());
    // The end of central directory record cannot be written either.
    assert!(writer.finish().is_err());
}

#[test]
fn len_and_is_empty_track_entries() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    assert!(writer.is_empty());
    writer
        .add_file("a.txt", b"a", &FileOptions::stored())
        .unwrap();
    assert_eq!(writer.len(), 1);
    assert!(!writer.is_empty());
}

#[test]
fn compression_level_affects_the_output_size() {
    let content = b"abcdefghij".repeat(5000);
    let fast = write_archive(&[("c.txt", &content[..], FileOptions::deflate(1))]);
    let best = write_archive(&[("c.txt", &content[..], FileOptions::deflate(9))]);

    let fast_size = le32(&fast[18..]) as usize;
    let best_size = le32(&best[18..]) as usize;
    assert!(
        best_size <= fast_size,
        "level 9 ({best_size}) should not be worse than level 1 ({fast_size})"
    );

    // Both must still decode to the original content.
    for buf in [fast, best] {
        let mut archive = open(buf);
        assert_eq!(archive.read_entry(0).unwrap(), content);
    }
}

#[test]
fn a_buffered_file_sink_works() {
    // Exercises a real file plus a wrapping `BufWriter`, which is the realistic usage.
    let dir = std::env::temp_dir().join(format!("zipcore-sink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.zip");

    {
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = ZipWriter::new(std::io::BufWriter::new(file));
        writer
            .add_file("a.txt", b"buffered", &FileOptions::default())
            .unwrap();
        writer
            .add_file("b.bin", &b"xyz".repeat(20_000)[..], &FileOptions::default())
            .unwrap();
        writer.finish().unwrap();
    }

    let mut archive = Archive::open(&path).unwrap();
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.read_entry(0).unwrap(), b"buffered");
    assert_eq!(archive.read_entry(1).unwrap(), b"xyz".repeat(20_000));

    // The bytes on disk must be readable too.
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(&raw[0..4], &SIG_LOCAL);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rewind_after_writing_allows_reading_the_same_cursor() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_file("x.txt", b"seekable", &FileOptions::stored())
        .unwrap();
    let mut cursor = writer.finish().unwrap();

    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut archive = Archive::new(cursor).unwrap();
    let mut out = String::new();
    archive
        .by_name("x.txt")
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "seekable");
}
