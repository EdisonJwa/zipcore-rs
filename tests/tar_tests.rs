//! tar writing, and packing it with zstd.
//!
//! The parser below is written from the tar specification rather than from the writer's code, so a
//! mistake in the writer has to be mirrored in a second, independent implementation before these
//! tests pass. It also recomputes every header checksum, which is the part of tar most likely to be
//! got subtly wrong.

use std::io::{Cursor, Write};
use zipcore::{TarEntryOptions, TarWriter};

// ---------------------------------------------------------------------------------------
// An independent tar reader, for verification only
// ---------------------------------------------------------------------------------------

struct ParsedEntry {
    name: String,
    mode: u32,
    mtime: u64,
    size: u64,
    typeflag: u8,
    data: Vec<u8>,
}

fn field_str(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).to_string()
}

/// Decode an octal field, or GNU base-256 when the top bit is set.
fn field_num(field: &[u8]) -> u64 {
    if field[0] & 0x80 != 0 {
        let mut value = 0u64;
        for &byte in &field[1..] {
            value = (value << 8) | u64::from(byte);
        }
        return value;
    }
    u64::from_str_radix(field_str(field).trim(), 8).unwrap_or(0)
}

fn parse_tar(bytes: &[u8]) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();
    let mut position = 0usize;

    while position + 512 <= bytes.len() {
        let block = &bytes[position..position + 512];
        if block.iter().all(|&byte| byte == 0) {
            break; // the two zero blocks that end a stream
        }

        // Every header checksum is recomputed, so the writer cannot get away with a wrong one.
        let mut copy = [0u8; 512];
        copy.copy_from_slice(block);
        let recorded = field_num(&copy[148..156]);
        copy[148..156].copy_from_slice(b"        ");
        let expected: u64 = copy.iter().map(|&byte| u64::from(byte)).sum();
        assert_eq!(recorded, expected, "header checksum for a tar record");

        let name = field_str(&block[0..100]);
        let prefix = field_str(&block[345..500]);
        let full_name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };

        let size = field_num(&block[124..136]);
        let entry = ParsedEntry {
            name: full_name,
            mode: field_num(&block[100..108]) as u32,
            mtime: field_num(&block[136..148]),
            size,
            typeflag: block[156],
            data: Vec::new(),
        };
        position += 512;

        let payload = &bytes[position..position + size as usize];
        let mut entry = entry;
        entry.data = payload.to_vec();
        entries.push(entry);

        // Payloads are padded out to a whole number of blocks.
        let padded = size.div_ceil(512) * 512;
        position += padded as usize;
    }

    entries
}

fn options() -> TarEntryOptions {
    TarEntryOptions::default().with_mtime(1_700_000_000)
}

// ---------------------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------------------

#[test]
fn round_trips_files_and_a_directory() {
    // Sizes chosen around the 512-byte block boundary, where padding bugs live.
    let sizes = [0usize, 1, 511, 512, 513, 1024, 5000];
    let mut expected = Vec::new();
    let mut tar = TarWriter::new(Cursor::new(Vec::new()));

    tar.add_directory("sub", &TarEntryOptions::directory())
        .unwrap();
    for size in sizes {
        let name = format!("sub/file-{size}.bin");
        let data: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        tar.add_file(&name, &data, &options()).unwrap();
        expected.push((name, data));
    }
    let bytes = tar.finish().unwrap().into_inner();

    // A tar stream is always a whole number of blocks.
    assert_eq!(bytes.len() % 512, 0);
    // And it ends with two zero blocks.
    assert!(bytes[bytes.len() - 1024..].iter().all(|&byte| byte == 0));

    let parsed = parse_tar(&bytes);
    assert_eq!(parsed.len(), expected.len() + 1);

    let directory = &parsed[0];
    assert_eq!(directory.name, "sub/");
    assert_eq!(directory.typeflag, b'5');
    assert_eq!(directory.mode, 0o755);

    for (entry, (name, data)) in parsed[1..].iter().zip(&expected) {
        assert_eq!(&entry.name, name);
        assert_eq!(entry.size, data.len() as u64);
        assert_eq!(&entry.data, data);
        assert_eq!(entry.mode, 0o644);
        assert_eq!(entry.mtime, 1_700_000_000);
        assert_eq!(entry.typeflag, b'0');
    }
}

#[test]
fn long_names_use_the_ustar_prefix_field() {
    let long = format!("{}/deeper/still/file.txt", "a".repeat(120));
    assert!(long.len() > 100 && long.len() < 255);

    let mut tar = TarWriter::new(Cursor::new(Vec::new()));
    tar.add_file(&long, b"contents", &options()).unwrap();
    let bytes = tar.finish().unwrap().into_inner();

    // No separate long-name entry is emitted: the name is split across the two fields.
    let parsed = parse_tar(&bytes);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name, long);
    assert_eq!(parsed[0].data, b"contents");
}

#[test]
fn an_entry_written_in_pieces_matches_one_big_write() {
    let data: Vec<u8> = (0..3000u32).map(|index| (index % 253) as u8).collect();

    let mut whole = TarWriter::new(Cursor::new(Vec::new()));
    whole.add_file("data.bin", &data, &options()).unwrap();
    let whole = whole.finish().unwrap().into_inner();

    let mut pieces = TarWriter::new(Cursor::new(Vec::new()));
    {
        let mut entry = pieces
            .start_file("data.bin", data.len() as u64, &options())
            .unwrap();
        for chunk in data.chunks(97) {
            entry.write_all(chunk).unwrap();
        }
        entry.finish().unwrap();
    }
    let pieces = pieces.finish().unwrap().into_inner();

    assert_eq!(whole, pieces, "streaming should produce identical bytes");
}

#[test]
fn a_name_too_long_for_ustar_is_refused() {
    let mut tar = TarWriter::new(Cursor::new(Vec::new()));
    let impossible = "x".repeat(400);
    assert!(tar.add_file(&impossible, b"data", &options()).is_err());
}

#[test]
fn a_non_ascii_name_is_refused_rather_than_mangled() {
    let mut tar = TarWriter::new(Cursor::new(Vec::new()));
    // Without a PAX header there is no defined encoding for this, so it must not be written as if
    // it were ASCII.
    assert!(tar
        .add_file("\u{65e5}\u{672c}.txt", b"data", &options())
        .is_err());
}

// ---------------------------------------------------------------------------------------
// Misuse
// ---------------------------------------------------------------------------------------

#[test]
fn a_short_entry_poisons_the_writer() {
    let mut tar = TarWriter::new(Cursor::new(Vec::new()));
    {
        let mut entry = tar.start_file("short.bin", 100, &options()).unwrap();
        entry.write_all(b"only ten!!").unwrap();
        // Dropped with 90 bytes outstanding.
    }

    let error = tar.finish().unwrap_err();
    let message = error.to_string();
    // The archive stays structurally valid — the file is zero-padded — but the contents are wrong,
    // so this must be reported rather than quietly blessed.
    assert!(message.contains("short.bin"), "message was: {message}");
    assert!(
        message.contains("contents are wrong"),
        "message was: {message}"
    );
}

#[test]
fn writing_more_than_declared_stops_at_the_declared_size() {
    let mut tar = TarWriter::new(Cursor::new(Vec::new()));
    {
        let mut entry = tar.start_file("exact.bin", 4, &options()).unwrap();
        // `write` reports how much it took; a caller using `write_all` is not blocked, but the
        // entry never exceeds what the header promised.
        let taken = entry.write(&[1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(taken, 4);
        assert_eq!(entry.write(&[7]).unwrap(), 0);
        entry.finish().unwrap();
    }
    let bytes = tar.finish().unwrap().into_inner();
    let parsed = parse_tar(&bytes);
    assert_eq!(parsed[0].size, 4);
    assert_eq!(parsed[0].data, vec![1, 2, 3, 4]);
}

#[test]
fn an_empty_archive_is_just_the_trailer() {
    let tar = TarWriter::new(Cursor::new(Vec::new()));
    let bytes = tar.finish().unwrap().into_inner();
    assert_eq!(bytes.len(), 1024);
    assert!(bytes.iter().all(|&byte| byte == 0));
}

// ---------------------------------------------------------------------------------------
// tar.zst
// ---------------------------------------------------------------------------------------

#[cfg(feature = "zstd")]
#[test]
fn tar_zst_round_trips_through_the_zstd_codec() {
    let files: Vec<(String, Vec<u8>)> = (0..6)
        .map(|index| {
            (
                format!("dir{index}/file.bin"),
                vec![b'a' + index as u8; 1000 * (index + 1)],
            )
        })
        .collect();

    let mut tar = TarWriter::new_zstd(Cursor::new(Vec::new()), 3).unwrap();
    for (name, data) in &files {
        tar.add_file(name, data, &options()).unwrap();
    }
    let compressed = tar.finish_zstd().unwrap().into_inner();

    // The output must be a real zstd frame, so it decompresses with the codec itself.
    let plain = zstd::decode_all(&compressed[..]).expect("output should be a zstd frame");
    assert!(
        compressed.len() < plain.len(),
        "the fixture should compress: {} compressed vs {} plain",
        compressed.len(),
        plain.len()
    );

    let parsed = parse_tar(&plain);
    assert_eq!(parsed.len(), files.len());
    for (entry, (name, data)) in parsed.iter().zip(&files) {
        assert_eq!(&entry.name, name);
        assert_eq!(&entry.data, data);
    }
}

#[cfg(feature = "zstd")]
#[test]
fn tar_zst_output_is_readable_by_a_streaming_decoder() {
    use std::io::Read;

    // The whole point of zstd is that it can be decompressed as a stream, so verify it that way
    // rather than with a one-shot helper.
    let mut tar = TarWriter::new_zstd(Cursor::new(Vec::new()), 1).unwrap();
    tar.add_file("one.txt", b"first", &options()).unwrap();
    tar.add_file("two.txt", b"second", &options()).unwrap();
    let compressed = tar.finish_zstd().unwrap().into_inner();

    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed)).unwrap();
    let mut plain = Vec::new();
    decoder.read_to_end(&mut plain).unwrap();

    let parsed = parse_tar(&plain);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].data, b"first");
    assert_eq!(parsed[1].data, b"second");
}

/// Write a `tar.zst` to a fixed path so a third-party tool can be pointed at it.
///
/// ```text
/// cargo test --features zstd -- --ignored emit_tar_zst_fixture
/// tar -tf  "$TMPDIR/zipcore-fixture.tar.zst"
/// tar -xf  "$TMPDIR/zipcore-fixture.tar.zst" -C somewhere
/// ```
#[cfg(feature = "zstd")]
#[test]
#[ignore = "writes a fixture for an external tool to check"]
fn emit_tar_zst_fixture() {
    let mut tar = TarWriter::new_zstd(Cursor::new(Vec::new()), 3).unwrap();
    tar.add_file(
        "hello.txt",
        b"hello from a tar.zst written by zipcore\n",
        &options(),
    )
    .unwrap();
    tar.add_directory("nested", &TarEntryOptions::directory())
        .unwrap();
    tar.add_file(
        "nested/data.bin",
        &(0..5000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        &options(),
    )
    .unwrap();
    let bytes = tar.finish_zstd().unwrap().into_inner();

    let path = std::env::temp_dir().join("zipcore-fixture.tar.zst");
    std::fs::write(&path, &bytes).expect("fixture should be writable");
    eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
}
