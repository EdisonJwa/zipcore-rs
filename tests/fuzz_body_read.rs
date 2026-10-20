//! Auto-generated from fuzz/fuzz_targets/read_archive.rs so the fuzz target's logic is type-checked and
//! run by the normal test suite, since libFuzzer needs a C++ toolchain to build.

use std::io::Cursor;
use zipcore::Archive;

fn body(data: &[u8]) {
    // Parse. Most inputs fail here, which is the point: the parser must reject them cleanly.
    let Ok(mut archive) = Archive::new(Cursor::new(data.to_vec())) else {
        return;
    };

    // Walk the metadata. Every accessor is exercised because a directory that parses can still
    // hold nonsense that a getter must not choke on.
    for entry in archive.entries() {
        let _ = entry.name();
        let _ = entry.uncompressed_size();
        let _ = entry.compressed_size();
        let _ = entry.crc32();
        let _ = entry.dos_timestamp();
        let _ = entry.unix_mtime();
        let _ = entry.method();
        let _ = entry.is_encrypted();
        let _ = entry.is_dir();
        let _ = entry.is_symlink();
        let _ = entry.unix_mode();
        // Path conversion is the zip-slip boundary; run it on every name.
        let _ = entry.safe_path();
    }

    // Then actually decode a bounded number of entries. The size ceiling keeps the fuzzer
    // exploring structure rather than decompression throughput.
    let len = archive.len().min(4);
    for index in 0..len {
        if let Ok(mut file) = archive.by_index(index) {
            // A read must either produce bytes or an error; it must never panic. Capped so a
            // bomb-shaped entry cannot exhaust memory inside the fuzzer.
            let mut sink = Vec::new();
            let _ = std::io::copy(&mut std::io::Read::take(&mut file, 1 << 20), &mut sink);
            let _ = file.take_terminal_error();
        }
    }
}

#[test]
fn fuzz_body_compiles_and_runs() {
    for seed in [b"".as_slice(), b"PK", b"PK", &[0u8; 64]] {
        body(seed);
    }
}
