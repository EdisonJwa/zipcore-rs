//! Inspect an archive without extracting it: metadata, integrity, and the raw bytes.
//!
//! ```text
//! cargo run --example inspect -- book.xlsx
//! cargo run --example inspect -- book.xlsx --verify
//! ```
//!
//! This is the "what is in here, and can I trust it?" example. It shows the metadata API and the
//! two ways to check an entry: `read_entry` (buffers the payload) and `by_index`/`raw_reader`
//! (streams it without inflating).

use std::io::{Read, Seek, SeekFrom};
use std::process::ExitCode;

use zipcore::{Archive, Compression, ReadOptions};

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
    let path = args.next().ok_or("usage: inspect <archive> [--verify]")?;
    let verify = args.any(|a| a == "--verify");

    let bytes = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
    let archive = Archive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("{path}: {e}"))?;

    // Archive-level facts.
    println!("{path}");
    println!("  entries          : {}", archive.len());
    println!("  is empty         : {}", archive.is_empty());
    println!("  uses ZIP64       : {}", archive.is_zip64());
    println!(
        "  central dir at   : {:#x}",
        archive.central_directory_offset()
    );
    println!("  archive comment  : {:?}", archive.comment());

    // Every entry, with the metadata worth showing.
    println!();
    println!(
        "{:>4}  {:<32} {:>10} {:>10}  {:<10} flags",
        "#", "name", "stored", "size", "method"
    );
    for index in 0..archive.len() {
        let entry = archive.entries()[index].clone();
        println!(
            "{index:>4}  {:<32} {:>10} {:>10}  {:<10} {}",
            truncate(entry.name(), 32),
            entry.compressed_size(),
            entry.uncompressed_size(),
            entry.compression().name(),
            describe_flags(&entry),
        );
        // Details that matter for extraction, shown only when true to keep the table readable.
        if entry.is_dir() {
            print!("        (directory)");
        }
        if entry.is_symlink() {
            print!("        (symlink)");
        }
        if entry.is_encrypted() {
            print!(
                "        (encrypted{})",
                if entry.is_aes() {
                    ", AES"
                } else {
                    ", ZipCrypto"
                }
            );
        }
        if entry.has_data_descriptor() {
            print!("        (data descriptor)");
        }
        if let Some(mtime) = entry.unix_mtime() {
            print!("        (mtime {mtime})");
        }
        // A mode of 0 means the archive recorded none, which is not worth showing.
        if let Some(mode) = entry.unix_mode().filter(|m| *m != 0) {
            print!("        (mode {mode:o})");
        }
        println!();

        // Why a method may be unreadable: the feature is off, or nothing decodes it.
        let method = entry.compression();
        if !method.is_supported() {
            println!(
                "        NOTE: {:<9} not readable by this build{}",
                method.name(),
                method
                    .required_feature()
                    .map(|f| format!(" (enable the `{f}` feature)"))
                    .unwrap_or_else(|| " (no decoder exists for it)".to_string())
            );
        }
    }

    if !verify {
        return Ok(());
    }

    // Verification: read every entry end to end and let the CRC/size checks run.
    println!();
    println!("verifying...");
    let options = ReadOptions::default();
    let mut archive = Archive::new_with_options(
        std::io::Cursor::new(std::fs::read(&path).map_err(|e| e.to_string())?),
        options,
    )
    .map_err(|e| e.to_string())?;

    let mut bad = 0;
    for index in 0..archive.len() {
        let entry = archive.entries()[index].clone();
        let name = entry.name().to_string();
        if entry.is_dir() {
            continue;
        }
        match archive.by_index(index) {
            Ok(mut entry) => {
                let mut sink = std::io::sink();
                match std::io::copy(&mut entry, &mut sink) {
                    Ok(n) => match entry.take_terminal_error() {
                        None => println!("  ok    {name} ({n} bytes)"),
                        Some(error) => {
                            bad += 1;
                            println!("  BAD   {name}: {error}");
                        }
                    },
                    Err(error) => {
                        bad += 1;
                        println!("  BAD   {name}: {error}");
                    }
                }
            }
            Err(error) => {
                bad += 1;
                println!("  SKIP  {name}: {error}");
            }
        }
    }

    if bad == 0 {
        println!("all entries verified");
        Ok(())
    } else {
        Err(format!("{bad} entries failed verification"))
    }
}

/// A compact description of what the general-purpose flags mean.
fn describe_flags(entry: &zipcore::Entry) -> String {
    let mut parts = Vec::new();
    if entry.is_encrypted() {
        parts.push("enc");
    }
    if entry.has_data_descriptor() {
        parts.push("desc");
    }
    if entry.name_raw().len() != entry.name().len() {
        parts.push("cp437");
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(",")
    }
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let tail: String = text
            .chars()
            .rev()
            .take(width.saturating_sub(3))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("...{tail}")
    }
}

/// Demonstrates the streaming readers that skip decompression entirely.
///
/// Reach for these when you only need the bytes as stored (copying between archives) or when
/// you want to decompress yourself.
#[allow(dead_code)]
fn raw_bytes_demo(path: &str) -> Result<(), String> {
    let mut archive = Archive::open(path).map_err(|e| e.to_string())?;
    let header_offset = archive.entries()[0].header_offset();
    let method_name = archive.entries()[0].compression().name();

    // 1. `raw_reader`: exactly `compressed_size` bytes, never inflated.
    let mut raw = archive.raw_reader(0).map_err(|e| e.to_string())?;
    let mut stored = Vec::new();
    raw.read_to_end(&mut stored).map_err(|e| e.to_string())?;
    println!(
        "raw entry 0: {} stored bytes ({})",
        stored.len(),
        method_name
    );

    // 2. `by_index`: decompressed, streaming, with a running byte count.
    let mut entry = archive.by_index(0).map_err(|e| e.to_string())?;
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = entry.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        println!("  produced {:>8} bytes so far", entry.bytes_produced());
    }
    entry.verify_to_end().map_err(|e| e.to_string())?;
    println!("read {total} decompressed bytes, CRC ok");

    // 3. Reading at an arbitrary point, e.g. to inspect a header inside the archive.
    println!("entry 0 local header at offset {header_offset:#x}");
    let mut probe = [0u8; 4];
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(header_offset))
        .map_err(|e| e.to_string())?;
    file.read_exact(&mut probe).map_err(|e| e.to_string())?;
    // The local file header signature is always PK\x03\x04.
    println!("signature at that offset: {:02x?}", probe);
    Ok(())
}

/// Naming every method this crate knows, readable or not.
#[allow(dead_code)]
fn method_names() {
    for raw in [0u16, 1, 6, 8, 9, 12, 14, 93, 95, 98, 200] {
        let method = Compression::from_method(raw);
        println!(
            "{raw:>3} -> {:<10} id={:<4} readable={:<5} writable={}",
            method.name(),
            method.method_id(),
            method.is_supported(),
            method.is_writable()
        );
    }
}
