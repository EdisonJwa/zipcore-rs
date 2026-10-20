mod common;

use common::*;
use std::io::Read;
use zipcore::Archive;

#[test]
fn reads_a_zip64_archive() {
    let mut b = ZipBuilder::new();
    b.add_stored_zip64("plain.txt", b"hello zip64");
    let mut archive = Archive::new(cursor(b.finish_zip64())).unwrap();

    assert!(archive.is_zip64());
    assert_eq!(archive.len(), 1);

    let entry = &archive.entries()[0];
    assert_eq!(entry.name(), "plain.txt");
    assert_eq!(entry.uncompressed_size(), 11);
    assert_eq!(entry.compressed_size(), 11);
    assert_eq!(entry.crc32(), crc32(b"hello zip64"));

    let mut out = String::new();
    archive
        .by_index(0)
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "hello zip64");
}

#[test]
fn zip64_sentinels_are_resolved_for_offsets_too() {
    // Two entries: the second has a non-zero local header offset, so the ZIP64 offset field
    // must be read from the extra data rather than defaulting to zero.
    let mut b = ZipBuilder::new();
    b.add_stored_zip64("first.txt", b"0000000000");
    b.add_stored_zip64("second.txt", b"1111111111");
    let mut archive = Archive::new(cursor(b.finish_zip64())).unwrap();

    assert_eq!(archive.len(), 2);
    let mut out = String::new();
    archive
        .by_name("second.txt")
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "1111111111");
}

#[test]
fn a_zip64_sentinel_without_the_extra_field_is_rejected() {
    // Hand-build a central directory entry claiming the 4 GiB sentinel but supplying no
    // ZIP64 extra field, which is contradictory and must not be silently accepted.
    let mut b = ZipBuilder::new();
    b.add_stored("liar.txt", b"data");
    let mut buf = b.finish();

    let cd = find(&buf, SIG_CENTRAL).expect("central directory");
    // uncompressed size lives at offset 24 of the central directory header.
    buf[cd + 24..cd + 28].copy_from_slice(&0xffff_ffffu32.to_le_bytes());

    match Archive::new(cursor(buf)) {
        Err(zipcore::Error::Malformed(message)) => {
            assert!(message.contains("ZIP64"), "unexpected message: {message}");
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

fn find(haystack: &[u8], needle: u32) -> Option<usize> {
    let bytes = needle.to_le_bytes();
    haystack
        .windows(4)
        .position(|window| window == bytes.as_slice())
}
