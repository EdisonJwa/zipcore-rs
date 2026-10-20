//! Deterministic mutation testing: corrupt valid archives in thousands of ways and require that
//! nothing panics.
//!
//! `cargo-fuzz` explores this space far better, but it needs a nightly toolchain and a C++ build
//! of libFuzzer. This runs on stable in a fraction of a second, so it is part of the normal test
//! suite and CI. It is not a substitute for fuzzing; it is the floor.

use std::io::{Cursor, Read};
use zipcore::{Archive, FileOptions, ReadOptions, WriteOptions, ZipWriter};

/// Small deterministic PRNG, so a failure is reproducible from the seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// An archive exercising stored, deflated, directory and timestamped entries.
fn sample_archive() -> Vec<u8> {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("a.txt", b"alpha payload", &FileOptions::default())
        .unwrap();
    w.add_file("dir/b.bin", &[3u8; 400], &FileOptions::stored())
        .unwrap();
    let opts = FileOptions::default().with_unix_mtime(Some(1_700_000_000));
    w.add_file("c.txt", b"gamma", &opts).unwrap();
    w.finish().unwrap().into_inner()
}

/// Touch every reader path. Any panic fails the surrounding `catch_unwind`.
fn exercise(bytes: Vec<u8>) {
    let Ok(mut archive) = Archive::new(Cursor::new(bytes.clone())) else {
        return;
    };
    for entry in archive.entries() {
        let _ = entry.name();
        let _ = entry.uncompressed_size();
        let _ = entry.compressed_size();
        let _ = entry.crc32();
        let _ = entry.method();
        let _ = entry.is_encrypted();
        let _ = entry.is_dir();
        let _ = entry.is_symlink();
        let _ = entry.dos_timestamp();
        let _ = entry.unix_mtime();
        let _ = entry.safe_path();
    }
    let count = archive.len().min(8);
    for index in 0..count {
        if let Ok(mut file) = archive.by_index(index) {
            let mut sink = Vec::new();
            let _ = Read::take(&mut file, 1 << 20).read_to_end(&mut sink);
            let _ = file.take_terminal_error();
        }
    }
    // Run the encrypted paths too, with a password configured.
    let options = ReadOptions::default().with_password("not-the-password");
    if let Ok(mut archive) = Archive::new_with_options(Cursor::new(bytes), options) {
        let count = archive.len().min(4);
        for index in 0..count {
            let _ = archive.read_entry(index);
        }
    }
}

/// Corrupt headers, payloads and directory records, then truncate.
fn mutate_and_check(seed: u64, iterations: usize) {
    let base = sample_archive();
    let mut rng = Rng(seed);
    for _ in 0..iterations {
        let mut bytes = base.clone();
        for _ in 0..(1 + rng.below(6)) {
            // Bias half the mutations into the header regions, where the structure lives.
            let index = if rng.below(2) == 0 {
                rng.below(bytes.len())
            } else {
                rng.below(bytes.len().min(200))
            };
            bytes[index] = (rng.next() & 0xFF) as u8;
        }
        if rng.below(5) == 0 {
            let cut = rng.below(bytes.len());
            bytes.truncate(cut);
        }
        let payload = bytes.clone();
        // A panic here means a hostile archive could take down the caller.
        assert!(
            std::panic::catch_unwind(move || exercise(payload)).is_ok(),
            "reader panicked on a mutated archive (seed {seed})"
        );
    }
}

#[test]
fn mutations_do_not_panic() {
    mutate_and_check(0x5eed_1234_abcd_0001, 4000);
}

#[test]
fn mutations_of_an_encrypted_archive_do_not_panic() {
    let options = WriteOptions {
        password: Some(b"pw".to_vec()),
        ..WriteOptions::default()
    };
    let mut w = ZipWriter::new_with_options(Cursor::new(Vec::new()), options).unwrap();
    let file = FileOptions {
        encryption: Some(zipcore::Encryption::ZipCrypto),
        ..FileOptions::default()
    };
    w.add_file("secret.txt", b"classified payload", &file)
        .unwrap();
    let base = w.finish().unwrap().into_inner();

    let mut rng = Rng(0xc0ff_ee00_1234_5678);
    for _ in 0..1500 {
        let mut bytes = base.clone();
        for _ in 0..(1 + rng.below(4)) {
            let index = rng.below(bytes.len());
            bytes[index] = (rng.next() & 0xFF) as u8;
        }
        let payload = bytes.clone();
        assert!(
            std::panic::catch_unwind(move || {
                let options = ReadOptions::default().with_password("pw");
                if let Ok(mut archive) = Archive::new_with_options(Cursor::new(payload), options) {
                    let _ = archive.read_entry(0);
                }
            })
            .is_ok(),
            "encrypted reader panicked on a mutated archive"
        );
    }
}
