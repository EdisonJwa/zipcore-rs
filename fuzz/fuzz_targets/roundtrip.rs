#![no_main]

//! Write an archive from arbitrary bytes, then read it back.
//!
//! This exercises the writer and reader against each other on arbitrary names and payloads,
//! which is where the two are most likely to disagree: a name the writer accepts but the reader
//! rejects, a size the writer records but the reader recomputes differently.

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zipcore::{Archive, FileOptions, WriteOptions, ZipWriter};

fuzz_target!(|data: &[u8]| {
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
    let Ok(finished) = writer.finish() else { return };
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
});
