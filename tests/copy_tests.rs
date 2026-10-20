//! Tests for byte-faithful copying between archives.
//!
//! The point of [`ZipWriter::add_preserved`] is that nothing is inflated and nothing is deflated
//! again, so these tests assert on the *compressed* sizes and on the raw bytes as well as on the
//! decoded contents. A re-encoding bug would keep the contents correct while changing both.

mod common;

use common::*;
use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;
use zipcore::{Archive, Error, ZipWriter};

fn open(buf: Vec<u8>) -> Archive<Cursor<Vec<u8>>> {
    Archive::new(Cursor::new(buf)).expect("archive should open")
}

fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Copy entry 0 of `source` into a fresh archive and return its bytes.
fn copy_one(source: &mut Archive<Cursor<Vec<u8>>>) -> Vec<u8> {
    let entry = source.entries()[0].clone();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut payload = source.raw_reader(0).unwrap();
    writer.add_preserved(&entry, &mut payload).unwrap();
    writer.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------------------------------
// Byte fidelity
// ---------------------------------------------------------------------------------------

#[test]
fn raw_copy_preserves_the_compressed_bytes_exactly() {
    let content = "the quick brown fox ".repeat(400);
    let mut b = ZipBuilder::new();
    b.add_deflate("fox.txt", content.as_bytes());
    let mut source = open(b.finish());

    let source_entry = source.entries()[0].clone();
    assert!(
        source_entry.compressed_size() < source_entry.uncompressed_size(),
        "fixture should really be compressed"
    );

    let copied = copy_one(&mut source);
    let mut dest = open(copied);

    // An identical compressed size is the evidence that the payload was not re-encoded.
    assert_eq!(
        dest.entries()[0].compressed_size(),
        source_entry.compressed_size()
    );
    assert_eq!(
        dest.entries()[0].uncompressed_size(),
        source_entry.uncompressed_size()
    );
    assert_eq!(dest.entries()[0].crc32(), source_entry.crc32());
    assert_eq!(dest.entries()[0].method(), source_entry.method());
    assert_eq!(dest.read_entry(0).unwrap(), content.as_bytes());
}

#[test]
fn a_preserved_entry_carries_real_sizes_in_its_local_header() {
    let mut b = ZipBuilder::new();
    b.add_deflate("f.txt", &b"hello ".repeat(200)[..]);
    let mut source = open(b.finish());
    let entry = source.entries()[0].clone();

    let copied = copy_one(&mut source);

    assert_eq!(&copied[0..4], &[0x50, 0x4b, 0x03, 0x04]);
    // Because the sizes are known in advance, the header is complete when written: there is no
    // placeholder phase and no seek back to patch it.
    assert_eq!(
        le32(&copied[14..]),
        entry.crc32(),
        "CRC-32 written up front"
    );
    assert_eq!(le32(&copied[18..]), entry.compressed_size() as u32);
    assert_eq!(le32(&copied[22..]), entry.uncompressed_size() as u32);
    assert_eq!(
        le16(&copied[6..]) & (1 << 3),
        0,
        "no data descriptor claimed"
    );
}

#[test]
fn copy_from_copies_every_entry_unchanged() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.txt", b"aaaa");
    b.add_deflate("b.txt", &b"bbbb ".repeat(500)[..]);
    b.add_deflate("nested/c.bin", &b"cccc".repeat(1000)[..]);
    let mut source = open(b.finish());

    let expected: Vec<_> = source
        .entries()
        .iter()
        .map(|e| {
            (
                e.name().to_string(),
                e.method(),
                e.crc32(),
                e.compressed_size(),
                e.uncompressed_size(),
            )
        })
        .collect();

    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    assert_eq!(writer.copy_from(&mut source).unwrap(), expected.len());
    let out = writer.finish().unwrap().into_inner();
    let mut dest = open(out);

    assert_eq!(dest.len(), expected.len());
    for (index, (name, method, crc, compressed, uncompressed)) in expected.iter().enumerate() {
        let entry = &dest.entries()[index];
        assert_eq!(entry.name(), name);
        assert_eq!(entry.method(), *method);
        assert_eq!(entry.crc32(), *crc);
        assert_eq!(entry.compressed_size(), *compressed);
        assert_eq!(entry.uncompressed_size(), *uncompressed);
    }

    // And the contents still decode, so the copy is not merely structurally similar.
    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(dest.read_entry(index).unwrap().len() as u64, expected.4);
    }
}

// ---------------------------------------------------------------------------------------
// Entries the reader refuses to decode still copy faithfully
// ---------------------------------------------------------------------------------------

#[test]
fn raw_copy_preserves_a_method_this_crate_cannot_decode() {
    let mut b = ZipBuilder::new();
    // 98 is PPMd: no build configuration decodes it, so this test says the same thing whatever
    // features are on.
    b.add_unknown_method("payload.ppmd", b"pretend this is ppmd", 98);
    let mut source = open(b.finish());

    // The reader will not decode it...
    assert!(source.by_index(0).is_err());

    // ...but copying the bytes through is perfectly well defined.
    let copied = copy_one(&mut source);
    let mut dest = open(copied);
    assert_eq!(dest.entries()[0].method(), 98);
    assert_eq!(dest.entries()[0].name(), "payload.ppmd");
    assert_eq!(
        dest.entries()[0].compressed_size(),
        source.entries()[0].compressed_size()
    );
    assert_eq!(dest.entries()[0].crc32(), source.entries()[0].crc32());
    // Still undecodable in the destination, and that is correct: the copy is faithful, not magic.
    assert!(dest.by_index(0).is_err());
}

#[test]
fn raw_copy_preserves_the_encrypted_flag() {
    let mut b = ZipBuilder::new();
    b.add_flagged("secret.bin", b"ciphertext bytes", FLAG_ENCRYPTED);
    let mut source = open(b.finish());
    assert!(source.entries()[0].is_encrypted());

    let copied = copy_one(&mut source);
    let dest = open(copied);
    assert!(dest.entries()[0].is_encrypted());
    assert_eq!(
        dest.entries()[0].compressed_size(),
        source.entries()[0].compressed_size()
    );
    assert_eq!(dest.entries()[0].crc32(), source.entries()[0].crc32());
}

#[test]
fn raw_copy_clears_the_data_descriptor_flag() {
    // Bit 3 says "sizes follow in a data descriptor". This writer always records real sizes in
    // the local header, so claiming that would be a lie.
    let mut b = ZipBuilder::new();
    b.add_flagged("descriptor.txt", b"body", 1 << 3);
    let mut source = open(b.finish());
    assert!(source.entries()[0].has_data_descriptor());

    let copied = copy_one(&mut source);
    assert_eq!(le16(&copied[6..]) & (1 << 3), 0, "local header flag");

    let central = copied
        .windows(4)
        .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
        .expect("central directory");
    assert_eq!(
        le16(&copied[central + 8..]) & (1 << 3),
        0,
        "central directory flag must agree with the local header"
    );
}

#[test]
fn raw_copy_preserves_the_name_and_attributes() {
    let mut b = ZipBuilder::new();
    b.add_stored("unicode-\u{65e5}\u{672c}\u{8a9e}.txt", b"contents");
    let mut buf = b.finish();
    // Record mode 0100644 and the Unix host byte, as a real Unix writer would.
    let central = buf
        .windows(4)
        .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    buf[central + 38..central + 42].copy_from_slice(&(0o100_644u32 << 16).to_le_bytes());

    let mut source = open(buf);
    let expected = source.entries()[0].clone();
    let copied = copy_one(&mut source);
    let dest = open(copied);

    assert_eq!(dest.entries()[0].name(), expected.name());
    assert_eq!(dest.entries()[0].name_raw(), expected.name_raw());
    assert_eq!(dest.entries()[0].unix_mode(), Some(0o100_644));
    assert_eq!(dest.entries()[0].dos_timestamp(), expected.dos_timestamp());
}

// ---------------------------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------------------------

/// A reader that yields at most `budget` bytes before reporting end of stream.
struct ShortReader {
    inner: Cursor<Vec<u8>>,
    budget: u64,
}

impl Read for ShortReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.budget) as usize;
        let read = self.inner.read(&mut buf[..want])?;
        self.budget -= read as u64;
        Ok(read)
    }
}

#[test]
fn a_short_payload_is_reported_rather_than_truncating_the_archive() {
    let mut b = ZipBuilder::new();
    b.add_stored("big.bin", &b"x".repeat(10_000)[..]);
    let source = open(b.finish());
    let entry = source.entries()[0].clone();

    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut payload = ShortReader {
        inner: Cursor::new(vec![0u8; 32]),
        budget: 32,
    };
    match writer.add_preserved(&entry, &mut payload) {
        Err(Error::Io(error)) => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof),
        other => panic!("expected UnexpectedEof, got {other:?}"),
    }
}

#[test]
fn raw_copy_refuses_an_unsafe_name() {
    let mut b = ZipBuilder::new();
    b.add_stored("../escape.txt", b"x");
    let mut source = open(b.finish());
    let entry = source.entries()[0].clone();

    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut payload = source.raw_reader(0).unwrap();
    match writer.add_preserved(&entry, &mut payload) {
        Err(Error::UnsafePath { entry, reason }) => {
            assert_eq!(entry, "../escape.txt");
            assert_eq!(reason, "parent traversal");
        }
        other => panic!("expected UnsafePath, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// Seek behaviour
// ---------------------------------------------------------------------------------------

/// A shared tally of `seek` calls, so the test can inspect it while the archive owns the reader.
#[derive(Clone, Default)]
struct SeekTally(Rc<Cell<usize>>);

impl SeekTally {
    fn get(&self) -> usize {
        self.0.get()
    }
}

struct CountingReader {
    inner: Cursor<Vec<u8>>,
    tally: SeekTally,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for CountingReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.tally.0.set(self.tally.0.get() + 1);
        self.inner.seek(pos)
    }
}

fn counting(bytes: Vec<u8>) -> (CountingReader, SeekTally) {
    let tally = SeekTally::default();
    (
        CountingReader {
            inner: Cursor::new(bytes),
            tally: tally.clone(),
        },
        tally,
    )
}

#[test]
fn reading_a_raw_entry_seeks_once_for_the_whole_entry() {
    // Incompressible, so the stored payload is large enough to need many small reads.
    let mut content = Vec::with_capacity(4096);
    let mut state = 0x1234_5678u32;
    for _ in 0..4096 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        content.push((state >> 16) as u8);
    }
    let mut b = ZipBuilder::new();
    b.add_deflate("data.bin", &content);
    let (reader, tally) = counting(b.finish());
    let mut archive = Archive::new(reader).unwrap();

    let expected = archive.entries()[0].compressed_size();
    let before = tally.get();
    let mut raw = archive.raw_reader(0).unwrap();

    let mut out = Vec::new();
    let mut chunk = [0u8; 16];
    loop {
        let n = raw.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }

    assert_eq!(out.len() as u64, expected);

    // One seek to read the local header, one to position at the payload ??and crucially not one
    // per chunk, which is what reading this way would otherwise cost.
    let chunks = (out.len() + 15) / 16;
    assert!(
        chunks > 20,
        "the test should read many chunks, read {chunks}"
    );
    let seeks = tally.get() - before;
    assert!(
        seeks <= 2,
        "expected at most 2 seeks across {chunks} chunks, saw {seeks}"
    );
}

#[test]
fn reading_a_stored_entry_does_not_seek_per_chunk() {
    let content = vec![b's'; 100_000];
    let mut b = ZipBuilder::new();
    b.add_stored("big.bin", &content);
    let (reader, tally) = counting(b.finish());
    let mut archive = Archive::new(reader).unwrap();

    let before = tally.get();
    let mut file = archive.by_index(0).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = file.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }

    assert_eq!(out, content);
    let seeks = tally.get() - before;
    // One seek to read the local header, one to start the payload. Reading ~98 chunks.
    assert!(
        seeks <= 3,
        "a sequential stored read should not seek per chunk, saw {seeks} seeks"
    );
}
