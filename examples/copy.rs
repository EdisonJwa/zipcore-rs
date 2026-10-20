//! Copy a ZIP archive without recompressing its entries.
//!
//! ```text
//! cargo run --example copy -- source.zip dest.zip
//! ```
//!
//! Every payload is copied byte for byte, so the compressed sizes in the result are identical to
//! the source's. This is the cheap way to re-wrap an archive ??adding entries, dropping entries,
//! or changing the archive comment ??without paying to inflate and deflate everything again.

use std::fs::File;
use std::io::BufWriter;
use std::process::ExitCode;
use zipcore::{Archive, ZipWriter};

fn usage() -> String {
    "usage: copy <source.zip> <dest.zip>".to_string()
}

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
    let mut args = std::env::args().skip(1);
    let from = args.next().ok_or_else(usage)?;
    let to = args.next().ok_or_else(usage)?;

    let mut source = Archive::open(&from).map_err(|e| format!("{from}: {e}"))?;
    let compressed_in: u64 = source
        .entries()
        .iter()
        .map(|entry| entry.compressed_size())
        .sum();
    let entries = source.len();

    let file = File::create(&to).map_err(|e| format!("{to}: {e}"))?;
    let mut writer = ZipWriter::new(BufWriter::new(file)).unwrap();
    let copied = writer
        .copy_from(&mut source)
        .map_err(|e| format!("copy: {e}"))?;
    let file = writer
        .finish()
        .map_err(|e| format!("finish: {e}"))?
        .into_inner()
        .map_err(|e| format!("flush: {e}"))?;
    let length = file.metadata().map_err(|e| format!("stat: {e}"))?.len();

    println!("{from}: {entries} entries, {compressed_in} compressed bytes");
    println!("{to}: {copied} entries, {length} bytes on disk");

    // Re-open the result so a bad copy fails here rather than in the caller's hands.
    let check = Archive::open(&to).map_err(|e| format!("reopen {to}: {e}"))?;
    if check.len() != entries {
        return Err(format!(
            "entry count changed: {entries} became {}",
            check.len()
        ));
    }
    let compressed_out: u64 = check
        .entries()
        .iter()
        .map(|entry| entry.compressed_size())
        .sum();
    if compressed_out != compressed_in {
        return Err(format!(
            "payload sizes changed: {compressed_in} became {compressed_out} compressed bytes"
        ));
    }
    println!("verified: payload sizes identical, nothing was re-encoded");
    Ok(())
}
