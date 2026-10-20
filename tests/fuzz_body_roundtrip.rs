//! Auto-generated from fuzz/fuzz_targets/roundtrip.rs so the fuzz target's logic is type-checked and
//! run by the normal test suite, since libFuzzer needs a C++ toolchain to build.

use std::io::Cursor;
use zipcore::{Archive, FileOptions, WriteOptions, ZipWriter};

fn body(data: &[u8]) {
    // Split the input into a name, a payload and a compression choice.
    if data.len() < 2 {
        return;
    }
    let (meta, payload) = data.split_at(2);
    let stored = meta[0] & 1 == 0;
    let use_dir = meta[1] & 1 == 0;

    // Names come from the fuzz input, so they may contain path separators, NULs and UTF-8
    // fragments. The writer is expected to reject the unsafe ones rather than sanitise silently.
    let name = String::from_utf8_lossy(&meta[..1]).into_owned();

    let mut writer = match ZipWriter::new(Cursor::new(Vec::new())) {
        Ok(w) => w,
        Err(_) => return,
    };
    let options = if stored {
        FileOptions::stored()
    } else {
        FileOptions::deflate(6)
    };
    if use_dir {
        if writer.add_directory(&name, &options).is_err() {
            return;
        }
    } else if writer.add_file(&name, payload, &options).is_err() {
        return;
    }
    let Ok(finished) = writer.finish() else {
        return;
    };
    let bytes = finished.into_inner();

    // Whatever the writer produced must parse, and reading every entry must not panic.
    let Ok(mut archive) = Archive::new(Cursor::new(bytes)) else {
        panic!("the writer produced an archive the reader rejects");
    };
    for index in 0..archive.len() {
        if let Ok(mut file) = archive.by_index(index) {
            let mut sink = Vec::new();
            let _ = std::io::copy(&mut file, &mut sink);
            let _ = file.take_terminal_error();
        }
    }
    let _ = WriteOptions::default();
}

#[test]
fn fuzz_body_compiles_and_runs() {
    for seed in [b"".as_slice(), b"PK", b"PK", &[0u8; 64]] {
        body(seed);
    }
}
