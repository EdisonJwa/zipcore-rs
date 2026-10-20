//! Create a ZIP archive with `zipcore`.
//!
//! ```text
//! cargo run --example create -- out.zip
//! ```
//!
//! The contents are deterministic, so the resulting archive can be used as a fixture for
//! checking the writer against other tools.

use std::fs::File;
use std::io::BufWriter;
use std::process::ExitCode;
use zipcore::{FileOptions, ZipWriter};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: create <output.zip>".to_string())?;

    let file = File::create(&path).map_err(|e| format!("{path}: {e}"))?;
    let mut writer = ZipWriter::new(BufWriter::new(file)).unwrap();

    let entries: Vec<(String, Vec<u8>, FileOptions)> = vec![
        (
            "hello.txt".to_string(),
            b"hello from zipcore\n".to_vec(),
            FileOptions::default(),
        ),
        (
            "nested/deep/data.bin".to_string(),
            pseudo_random(200_000),
            FileOptions::deflate(6),
        ),
        (
            "compressible.txt".to_string(),
            vec![b'a'; 300_000],
            FileOptions::default(),
        ),
        (
            "stored.bin".to_string(),
            b"stored without compression".to_vec(),
            FileOptions::stored(),
        ),
        ("empty.txt".to_string(), Vec::new(), FileOptions::default()),
        ("empty-dir".to_string(), Vec::new(), FileOptions::default()),
        (
            "unicode-\u{c6e9}\u{c5b4}-caf\u{e9}.txt".to_string(),
            "non-ASCII name\n".as_bytes().to_vec(),
            FileOptions::default(),
        ),
        (
            "script.sh".to_string(),
            b"#!/bin/sh\necho hello\n".to_vec(),
            FileOptions::default()
                .with_unix_mode(0o100_755)
                .with_comment("mode 0755"),
        ),
    ];

    for (name, data, options) in &entries {
        if name == "empty-dir" {
            writer
                .add_directory(name, options)
                .map_err(|e| format!("{name}: {e}"))?;
            continue;
        }
        writer
            .add_file(name, data, options)
            .map_err(|e| format!("{name}: {e}"))?;
    }

    let sink = writer.finish().map_err(|e| format!("finish: {e}"))?;
    let length = sink
        .into_inner()
        .map_err(|e| format!("flush: {e}"))?
        .metadata()
        .map_err(|e| format!("stat: {e}"))?
        .len();

    println!("wrote {path} ({length} bytes)");

    // Read the archive back to confirm it is well formed.
    let mut archive = zipcore::Archive::open(&path).map_err(|e| format!("reopen: {e}"))?;
    println!("  {} entries", archive.len());
    for index in 0..archive.len() {
        let entry = archive.entries()[index].clone();
        let bytes = archive
            .read_entry(index)
            .map_err(|e| format!("verify {}: {e}", entry.name()))?;
        println!(
            "  {:>9} -> {:>9}  {}",
            entry.compressed_size(),
            entry.uncompressed_size(),
            entry.name()
        );
        assert_eq!(bytes.len() as u64, entry.uncompressed_size());
    }
    Ok(())
}

/// Deterministic, essentially incompressible bytes.
fn pseudo_random(length: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    let mut out = Vec::with_capacity(length);
    for _ in 0..length {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}
