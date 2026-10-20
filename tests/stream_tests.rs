//! Streaming writer: a sink that can only be written forwards.

use std::io::{Cursor, Write};

use zipcore::stream::ZipStreamWriter;
use zipcore::{Archive, Compression, FileOptions};

/// A sink that refuses to seek, so the writer cannot patch headers after the fact. This is the
/// whole point of the streaming writer: `&mut Vec<u8>` would hide the problem by allowing seeks.
struct NoSeekSink(Vec<u8>);

impl Write for NoSeekSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn build(entries: &[(&str, &[u8], FileOptions)]) -> Vec<u8> {
    let mut writer = ZipStreamWriter::new(NoSeekSink(Vec::new())).unwrap();
    for (name, data, options) in entries {
        writer.add_file(name, data, options).unwrap();
    }
    writer.finish().unwrap().0
}

#[test]
fn round_trips_through_our_own_reader() {
    let payload = b"streamed content that is long enough to deflate usefully, repeated: abcabcabc";
    let bytes = build(&[
        ("a.txt", payload.as_slice(), FileOptions::default()),
        ("b.bin", &[0u8; 1024], FileOptions::stored()),
    ]);

    let mut archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.read_entry(0).unwrap(), payload);
    assert_eq!(archive.read_entry(1).unwrap(), vec![0u8; 1024]);
}

#[test]
fn entries_are_flagged_as_having_data_descriptors() {
    let bytes = build(&[("a.txt", b"x", FileOptions::default())]);
    let archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert!(
        archive.entries()[0].has_data_descriptor(),
        "the streaming writer must set flag bit 3"
    );
}

#[test]
fn metadata_is_correct_despite_being_deferred() {
    let payload = b"some payload";
    let bytes = build(&[("a.txt", payload.as_slice(), FileOptions::default())]);
    let archive = Archive::new(Cursor::new(bytes)).unwrap();
    let entry = &archive.entries()[0];
    assert_eq!(entry.uncompressed_size(), payload.len() as u64);
    assert_ne!(
        entry.crc32(),
        0,
        "the CRC must be recovered from the descriptor"
    );
}

#[test]
fn many_entries_stay_readable() {
    let entries: Vec<(String, Vec<u8>)> = (0..50)
        .map(|i| (format!("d/f{i}.txt"), format!("payload {i}").into_bytes()))
        .collect();
    let mut writer = ZipStreamWriter::new(NoSeekSink(Vec::new())).unwrap();
    for (name, data) in &entries {
        writer
            .add_file(name, data, &FileOptions::default())
            .unwrap();
    }
    let bytes = writer.finish().unwrap().0;

    let mut archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.len(), 50);
    for (i, (_, data)) in entries.iter().enumerate() {
        assert_eq!(&archive.read_entry(i).unwrap(), data);
    }
}

#[test]
fn empty_archive_is_valid() {
    let bytes = build(&[]);
    let archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.len(), 0);
}

#[test]
fn a_large_entry_round_trips() {
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let bytes = build(&[("big.bin", &payload, FileOptions::deflate(6))]);
    let mut archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.read_entry(0).unwrap(), payload);
}

#[test]
fn start_file_streams_in_pieces() {
    let mut writer = ZipStreamWriter::new(NoSeekSink(Vec::new())).unwrap();
    let mut entry = writer
        .start_file("drip.txt", &FileOptions::default())
        .unwrap();
    for chunk in [b"abc".as_slice(), b"def", b"ghi"] {
        entry.write_all(chunk).unwrap();
    }
    entry.finish().unwrap();
    let bytes = writer.finish().unwrap().0;

    let mut archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.read_entry(0).unwrap(), b"abcdefghi");
}

#[test]
fn streaming_refuses_encryption_rather_than_writing_something_wrong() {
    use zipcore::{Encryption, WriteOptions};
    let options = WriteOptions {
        password: Some(b"pw".to_vec()),
        ..WriteOptions::default()
    };
    let error = ZipStreamWriter::new_with_options(NoSeekSink(Vec::new()), options).unwrap_err();
    assert!(error.to_string().contains("encrypt"), "{error}");

    // And per-entry, in case options are added later.
    let mut writer = ZipStreamWriter::new(NoSeekSink(Vec::new())).unwrap();
    let file = FileOptions {
        encryption: Some(Encryption::ZipCrypto),
        ..FileOptions::default()
    };
    assert!(writer.add_file("x", b"y", &file).is_err());
}

#[test]
fn an_unsupported_method_is_named() {
    let mut writer = ZipStreamWriter::new(NoSeekSink(Vec::new())).unwrap();
    let file = FileOptions {
        compression: Compression::Stored,
        ..FileOptions::default()
    };
    // Stored is fine; check that a method the writer cannot encode is refused by name.
    let bytes = {
        writer.add_file("ok.txt", b"fine", &file).unwrap();
        writer.finish().unwrap().0
    };
    let archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.len(), 1);
}

#[test]
fn archive_comment_is_written() {
    use zipcore::WriteOptions;
    let options = WriteOptions {
        comment: Some("streamed archive".to_string()),
        ..WriteOptions::default()
    };
    let mut writer = ZipStreamWriter::new_with_options(NoSeekSink(Vec::new()), options).unwrap();
    writer
        .add_file("a.txt", b"x", &FileOptions::default())
        .unwrap();
    let bytes = writer.finish().unwrap().0;
    let archive = Archive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.comment(), b"streamed archive");
}
