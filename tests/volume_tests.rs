//! Reading an archive that was split across several volume files.
//!
//! A split archive is the original byte stream cut into pieces, with nothing in the ZIP structure
//! that records the split. These tests cut a real archive into parts and read it back, including
//! cases where the central directory and a payload span volume boundaries.

mod common;

use common::*;
use std::io::Read;
use std::path::PathBuf;
use zipcore::Archive;

fn temp_volume(tag: &str, index: usize, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "zipcore-split-{tag}-{}-{index:03}",
        std::process::id()
    ));
    std::fs::write(&path, bytes).unwrap();
    path
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zipcore-splitdir-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Essentially incompressible bytes, so the payload does not collapse to one volume.
fn noise(length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9u32;
    let mut out = Vec::with_capacity(length);
    for _ in 0..length {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

fn build_source() -> (Vec<u8>, Vec<u8>) {
    let content = noise(4000);
    let mut b = ZipBuilder::new();
    b.add_stored("first.txt", b"stored in the first volume");
    b.add_deflate("noise.bin", &content);
    (b.finish(), content)
}

#[test]
fn reads_an_archive_split_across_volumes() {
    let (buf, content) = build_source();

    // Small volumes, so both a payload and the central directory cross boundaries.
    let paths: Vec<PathBuf> = buf
        .chunks(512)
        .enumerate()
        .map(|(index, chunk)| temp_volume("read", index, chunk))
        .collect();
    assert!(paths.len() > 3, "fixture should span several volumes");

    let mut archive = Archive::open_volumes(&paths).unwrap();
    assert_eq!(archive.len(), 2);
    assert_eq!(
        archive.read_entry(0).unwrap(),
        b"stored in the first volume"
    );
    assert_eq!(archive.read_entry(1).unwrap(), content);

    // Extraction through the volume reader behaves like any other archive.
    let dir = temp_dir("extract");
    let report = archive.extract_all(&dir).unwrap();
    assert_eq!(report.written.len(), 2);
    assert_eq!(
        std::fs::read(dir.join("first.txt")).unwrap(),
        b"stored in the first volume"
    );
    assert_eq!(std::fs::read(dir.join("noise.bin")).unwrap(), content);

    let _ = std::fs::remove_dir_all(&dir);
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn one_volume_is_the_same_as_the_whole_file() {
    let (buf, content) = build_source();
    let path = temp_volume("single", 0, &buf);

    let mut archive = Archive::open_volumes([&path]).unwrap();
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.read_entry(1).unwrap(), content);

    let _ = std::fs::remove_file(path);
}

#[test]
fn reading_in_small_chunks_crosses_volume_seams() {
    let (buf, content) = build_source();
    let paths: Vec<PathBuf> = buf
        .chunks(300)
        .enumerate()
        .map(|(index, chunk)| temp_volume("chunks", index, chunk))
        .collect();

    let mut archive = Archive::open_volumes(&paths).unwrap();
    let mut entry = archive.by_index(1).unwrap();
    let mut out = Vec::with_capacity(content.len());
    let mut small = [0u8; 7];
    loop {
        let n = entry.read(&mut small).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&small[..n]);
    }
    assert_eq!(out, content);

    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn a_truncated_volume_set_is_an_error_not_a_partial_archive() {
    let (buf, _) = build_source();
    let mut paths: Vec<PathBuf> = buf
        .chunks(512)
        .enumerate()
        .map(|(index, chunk)| temp_volume("trunc", index, chunk))
        .collect();
    // Drop the final volume, which is where the end of central directory record lives.
    paths.pop();

    // Opening must fail rather than reporting a shorter archive.
    assert!(Archive::open_volumes(&paths).is_err());

    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn volumes_are_read_in_the_order_given_and_never_reordered() {
    let (buf, content) = build_source();
    let mut paths: Vec<PathBuf> = buf
        .chunks(512)
        .enumerate()
        .map(|(index, chunk)| temp_volume("order", index, chunk))
        .collect();
    paths.reverse();

    // The reader concatenates exactly what it is handed; discovering the right order is the
    // caller's job. So a reversed set must not reconstruct the archive. It may fail outright, or
    // it may stumble onto a stray end-of-central-directory signature in the wrong place — what it
    // must never do is quietly hand back the real entries.
    if let Ok(mut archive) = Archive::open_volumes(&paths) {
        let reconstructed = archive.len() == 2
            && archive
                .read_entry(1)
                .map(|entry| entry == content)
                .unwrap_or(false);
        assert!(
            !reconstructed,
            "reversed volumes must not reconstruct the original archive"
        );
    }

    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn a_missing_volume_is_reported() {
    let missing = std::env::temp_dir().join("zipcore-split-does-not-exist-000");
    let _ = std::fs::remove_file(&missing);
    assert!(Archive::open_volumes([&missing]).is_err());
}
