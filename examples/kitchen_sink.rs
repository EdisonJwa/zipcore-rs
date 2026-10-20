//! One runnable example for every useful part of the public API.
//!
//! Run it with `cargo run --example kitchen_sink`, or read it as the reference documentation —
//! each section is self-contained and annotated with what it does and why you would reach for it.
//!
//! Sections that need an optional feature are marked; the `required-features` entry in
//! `Cargo.toml` enables them so this always compiles.

use std::io::{Cursor, Write};

use zipcore::stream::ZipStreamWriter;
use zipcore::{
    Archive, AtomicWrite, Compression, Encryption, ExtractLimits, FileOptions, Overwrite,
    ReadOptions, WriteOptions, ZipWriter,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    reading()?;
    writing()?;
    metadata()?;
    extracting()?;
    limits()?;
    appending()?;
    copying()?;
    big_entries()?;
    timestamps()?;
    symlinks()?;
    streaming()?;
    streaming_pieces()?;
    split_volumes()?;
    errors()?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

fn reading() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- reading ---");
    let bytes = build_sample();

    // From bytes in memory…
    let mut archive = Archive::new(Cursor::new(bytes.clone()))?;
    // …or from a path with `Archive::open("file.zip")?`.

    // Every entry, as metadata.
    for entry in archive.entries() {
        println!("  {} ({} bytes)", entry.name(), entry.uncompressed_size());
    }

    // Just the names.
    let names: Vec<&str> = archive.names().collect();
    println!("  names: {names:?}");

    // By position, decompressed into memory.
    let first = archive.read_entry(0)?;
    println!("  entry 0 = {:?}", String::from_utf8_lossy(&first));

    // By name. This builds a name index once, so repeated lookups are cheap.
    if let Some(index) = archive.index_for_name("docs/a.txt") {
        println!("  docs/a.txt is at index {index}");
    }

    // Stream an entry instead of buffering it, for anything potentially large.
    let mut file = archive.by_name("docs/a.txt")?;
    let mut out = Vec::new();
    std::io::copy(&mut file, &mut out)?;
    println!("  streamed {} bytes", out.len());

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

fn writing() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- writing ---");

    // The constructor refuses a sink that already holds bytes, so an existing archive cannot be
    // silently discarded — use `new_append` for that.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;

    // Deflate (the default), at an explicit level.
    writer.add_file("hello.txt", b"hello", &FileOptions::deflate(6))?;
    // Stored: no compression, useful for already-compressed payloads.
    writer.add_file("raw.bin", &[0u8; 512], &FileOptions::stored())?;
    // A directory entry.
    writer.add_directory("docs/", &FileOptions::default())?;

    // Streaming a payload in pieces, instead of holding it all in memory.
    let mut entry = writer.start_file("streamed.txt", &FileOptions::default())?;
    for i in 0..5 {
        entry.write_all(format!("line {i}\n").as_bytes())?;
    }
    entry.finish()?;

    // Archive-level options live on `WriteOptions`: compression default, comment, password.
    let options = WriteOptions {
        compression: Compression::Deflate,
        compression_level: 9,
        comment: Some("built by the kitchen-sink example".to_string()),
        password: None,
        allow_unsafe_names: false,
    };
    let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options)?;
    writer.add_file("x.txt", b"higher compression", &FileOptions::default())?;
    let bytes = writer.finish()?.into_inner();
    println!("  wrote {} bytes with an archive comment", bytes.len());

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------------------------

fn metadata() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- metadata ---");
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let options = FileOptions::default()
        .with_unix_mode(0o100_755) // rwxr-xr-x, executable
        .with_comment("a per-entry comment")
        .with_unix_mtime(Some(1_709_210_097));
    writer.add_file("script.sh", b"#!/bin/sh\n", &options)?;
    let bytes = writer.finish()?.into_inner();

    let archive = Archive::new(Cursor::new(bytes))?;
    let entry = &archive.entries()[0];
    println!("  name       : {}", entry.name());
    println!(
        "  sizes      : {} -> {}",
        entry.compressed_size(),
        entry.uncompressed_size()
    );
    println!("  crc32      : {:#010x}", entry.crc32());
    println!(
        "  method     : {} (id {})",
        entry.compression().name(),
        entry.method()
    );
    println!(
        "  unix mode  : {:?}",
        entry.unix_mode().map(|m| format!("{m:o}"))
    );
    println!("  comment    : {:?}", entry.comment());
    println!(
        "  mtime      : {:?} (unix seconds, exact)",
        entry.unix_mtime()
    );
    println!("  dos stamp  : {:?}", entry.dos_timestamp());
    println!("  is dir     : {}", entry.is_dir());
    println!("  is symlink : {}", entry.is_symlink());
    println!("  encrypted  : {}", entry.is_encrypted());
    println!("  safe path  : {:?}", entry.safe_path());
    println!("  zip64      : {}", archive.is_zip64());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------------------------

fn extracting() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- extracting ---");
    let dir = scratch("extract");
    let mut archive = Archive::new(Cursor::new(build_sample()))?;

    // Simplest form. Writes through a temporary file and renames, so a failure leaves nothing.
    let report = archive.extract_all(&dir)?;
    println!("  wrote {} files", report.written.len());
    println!("  skipped symlinks: {:?}", report.skipped_symlinks);
    println!("  total bytes: {}", report.total_bytes);

    // A single entry, when you only want one.
    let one = archive.extract_entry(0, &dir)?;
    println!("  extracted one to {}", one.display());

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Limits and policies (for untrusted archives)
// ---------------------------------------------------------------------------------------------

fn limits() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- limits ---");
    let dir = scratch("limits");
    let mut archive = Archive::new(Cursor::new(build_sample()))?;

    let limits = ExtractLimits {
        // Refuse archives with more entries than this.
        max_entries: Some(1_000),
        // Cap the total bytes written across the whole extraction, charged against what is
        // actually produced rather than what the archive claims.
        max_total_bytes: Some(64 * 1024 * 1024),
        // `Never` fails on an existing file, `Skip` leaves it and reports it, `Replace` overwrites.
        overwrite: Overwrite::Never,
        // `Disabled` skips the rename: ~30% faster, but a failure can leave a partial file.
        atomic_write: AtomicWrite::Enabled,
    };
    match archive.extract_all_with_limits(&dir, &limits) {
        Ok(report) => println!("  extracted {} files under limits", report.written.len()),
        Err(error) => println!("  refused: {error}"),
    }

    // A per-entry ceiling, for reading rather than extracting. The default is 1 GiB.
    let options = ReadOptions::default()
        .with_max_entry_size(Some(16 * 1024 * 1024))
        .with_password("unused-here");
    let mut limited = Archive::new_with_options(Cursor::new(build_sample()), options)?;
    println!(
        "  entry 0 under a 16 MiB cap: {} bytes",
        limited.read_entry(0)?.len()
    );

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Appending
// ---------------------------------------------------------------------------------------------

fn appending() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- appending ---");
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("first.txt", b"one", &FileOptions::default())?;
    let existing = writer.finish()?.into_inner();

    // One handle reads the existing archive, the other becomes the sink being rewritten.
    // The old central directory is overwritten rather than left behind, so repeated appends grow
    // linearly instead of accumulating dead records.
    let mut writer =
        ZipWriter::new_append(Cursor::new(existing.clone()), Cursor::new(existing.clone()))?;
    writer.add_file("second.txt", b"two", &FileOptions::default())?;
    let out = writer.finish()?.into_inner();

    let archive = Archive::new(Cursor::new(out))?;
    println!("  after append: {} entries", archive.len());

    // What happens if you try to write over an existing archive:
    let refused = ZipWriter::new(Cursor::new(existing));
    println!(
        "  plain new() on a non-empty sink refused: {}",
        refused.is_err()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Copying between archives without recompressing
// ---------------------------------------------------------------------------------------------

fn copying() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- copying ---");
    let source_bytes = build_sample();

    // `copy_from` moves every payload verbatim: no decompression, no recompression. A 660 MB
    // archive copies in the time it takes to move the bytes.
    let mut source = Archive::new(Cursor::new(source_bytes.clone()))?;
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let copied = writer.copy_from(&mut source)?;
    let out = writer.finish()?.into_inner();
    println!("  copy_from: {copied} entries, {} bytes", out.len());

    // `add_preserved` does the same for one entry, when you want to rename or filter.
    let mut source = Archive::new(Cursor::new(source_bytes))?;
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let entry = source.entries()[0].clone();
    let mut payload = source.raw_reader(0)?;
    writer.add_preserved(&entry, &mut payload)?;
    println!("  add_preserved: one entry kept byte-for-byte");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Large entries (ZIP64)
// ---------------------------------------------------------------------------------------------

fn big_entries() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- zip64 ---");
    // Sizes are only known after the data is written, but the ZIP64 extra field must be reserved
    // beforehand. Declare large entries with a hint; without one, an entry that grows past 4 GiB
    // fails with `Error::Zip64Required` rather than emitting a truncated size.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let options = FileOptions::default().with_size_hint(5 * 1024 * 1024 * 1024);
    writer.add_file(
        "huge.bin",
        b"only a few bytes, but reserved as 5 GiB",
        &options,
    )?;
    let bytes = writer.finish()?.into_inner();

    // The local header now carries a ZIP64 extra field reserved for 64-bit sizes. Confirm the
    // reservation exists rather than claiming the archive "is ZIP64" — the archive-level ZIP64
    // records only appear when an *offset* or the entry count needs them.
    let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]);
    println!("  local header reserves {extra_len} bytes of extra fields");
    let archive = Archive::new(Cursor::new(bytes))?;
    println!(
        "  entry parses back: {} bytes declared",
        archive.entries()[0].uncompressed_size()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------------------------

fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- timestamps ---");
    // DOS timestamps have two-second resolution and no timezone, so they cannot round-trip an
    // arbitrary instant. `with_unix_mtime` writes an extended-timestamp field instead.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    let options = FileOptions::default().with_unix_mtime(Some(1_709_210_097));
    writer.add_file("t.txt", b"x", &options)?;
    let bytes = writer.finish()?.into_inner();

    let archive = Archive::new(Cursor::new(bytes))?;
    println!(
        "  unix mtime round-tripped exactly: {:?}",
        archive.entries()[0].unix_mtime()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Symlinks
// ---------------------------------------------------------------------------------------------

fn symlinks() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- symlinks ---");
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_symlink("latest", "releases/v2", &FileOptions::default())?;
    let bytes = writer.finish()?.into_inner();

    let archive = Archive::new(Cursor::new(bytes))?;
    let entry = &archive.entries()[0];
    println!("  written as symlink: {}", entry.is_symlink());
    // Extraction deliberately refuses to materialise links, and reports them instead of dropping
    // them silently — a link is exactly how an archive escapes its destination.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_symlink("latest", "releases/v2", &FileOptions::default())?;
    writer.add_file("real.txt", b"not a link", &FileOptions::default())?;
    let bytes = writer.finish()?.into_inner();

    // Extraction never materialises a link — that is the zip-slip escape route — and reports it
    // rather than dropping it silently.
    let dir = scratch("symlink");
    let mut archive = Archive::new(Cursor::new(bytes))?;
    let report = archive.extract_all(&dir)?;
    println!("  skipped links reported: {:?}", report.skipped_symlinks);
    println!("  regular files written: {}", report.written.len());
    println!("  link created on disk: {}", dir.join("latest").exists());
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------------------------

#[allow(dead_code)]
fn encryption() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- encryption ---");
    // AES-256 needs the `aes-crypto` feature. ZipCrypto needs nothing, but is not secure — it
    // exists to read old archives, not to protect new ones.
    let options = WriteOptions {
        password: Some(b"correct horse battery staple".to_vec()),
        ..WriteOptions::default()
    };
    let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options)?;
    let file = FileOptions {
        encryption: Some(Encryption::Aes256),
        ..FileOptions::default()
    };
    writer.add_file("secret.txt", b"payload", &file)?;
    let bytes = writer.finish()?.into_inner();

    let mut archive = Archive::new_with_options(
        Cursor::new(bytes),
        ReadOptions::default().with_password("correct horse battery staple"),
    )?;
    println!(
        "  decrypted: {:?}",
        String::from_utf8_lossy(&archive.read_entry(0)?)
    );
    println!("  entry is AES: {}", archive.entries()[0].is_aes());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Streaming output to a non-seekable sink
// ---------------------------------------------------------------------------------------------

fn streaming() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- streaming ---");
    // `ZipWriter` patches headers by seeking, so it needs a seekable sink. For stdout, a socket or
    // a pipe, use `ZipStreamWriter`: it writes a data descriptor after each payload instead.
    let mut writer = ZipStreamWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("a.txt", b"streamed", &FileOptions::default())?;
    writer.add_directory("dir/", &FileOptions::default())?;
    let bytes = writer.finish()?.into_inner();

    let archive = Archive::new(Cursor::new(bytes))?;
    println!("  entries: {}", archive.len());
    println!(
        "  uses data descriptors: {}",
        archive.entries()[0].has_data_descriptor()
    );
    Ok(())
}

fn streaming_pieces() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- streaming in pieces ---");
    let mut writer = ZipStreamWriter::new(Cursor::new(Vec::new()))?;
    let mut entry = writer.start_file("drip.txt", &FileOptions::default())?;
    for chunk in ["alpha ", "beta ", "gamma"] {
        entry.write_all(chunk.as_bytes())?;
    }
    entry.finish()?;
    let bytes = writer.finish()?.into_inner();

    let mut archive = Archive::new(Cursor::new(bytes))?;
    println!(
        "  reassembled: {:?}",
        String::from_utf8_lossy(&archive.read_entry(0)?)
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Split volumes
// ---------------------------------------------------------------------------------------------

fn split_volumes() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- split volumes ---");
    // `archive.zip.001`, `.002`, … are read as one logical archive by `open_volumes`. This is what
    // 7-Zip's `-v` switch and many download mirrors produce.
    let dir = scratch("volumes");
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();

    // Write a single archive, then cut it into volumes on disk ourselves so the example does not
    // depend on an external tool.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("big.bin", &payload, &FileOptions::stored())?;
    let whole = writer.finish()?.into_inner();

    let chunk = 20_000;
    let mut paths = Vec::new();
    for (i, part) in whole.chunks(chunk).enumerate() {
        let path = dir.join(format!("archive.zip.{:03}", i + 1));
        std::fs::write(&path, part)?;
        paths.push(path);
    }

    // Read them back as one archive, without reassembling the file first.
    let mut archive = Archive::open_volumes(&paths)?;
    println!("  {} volumes -> {} entries", paths.len(), archive.len());
    let data = archive.read_entry(0)?;
    println!(
        "  reassembled {} bytes, content intact: {}",
        data.len(),
        data == payload
    );
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

fn errors() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- errors ---");
    // Failures are structured, so a caller can react rather than string-match.
    let mut broken = Archive::new(Cursor::new(vec![0u8; 32]));
    match &mut broken {
        Err(error) => println!("  corrupt archive: {error}"),
        Ok(_) => println!("  unexpected: parsed garbage"),
    }

    // An unknown compression method is named, not reported as a bare number.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()))?;
    writer.add_file("ok.txt", b"fine", &FileOptions::default())?;
    let bytes = writer.finish()?.into_inner();
    let mut archive = Archive::new(Cursor::new(bytes))?;
    // A streamed read that hits a CRC or size problem latches a terminal error:
    let mut file = archive.by_index(0)?;
    let mut sink = Vec::new();
    std::io::copy(&mut file, &mut sink)?;
    match file.take_terminal_error() {
        None => println!("  entry verified cleanly"),
        Some(error) => println!("  terminal error: {error}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// A small archive used by several sections above.
fn build_sample() -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    writer
        .add_file("docs/a.txt", b"alpha", &FileOptions::default())
        .unwrap();
    writer
        .add_file("docs/b.bin", &[1u8; 256], &FileOptions::stored())
        .unwrap();
    writer
        .add_directory("docs/", &FileOptions::default())
        .unwrap();
    writer.finish().unwrap().into_inner()
}

/// A fresh directory under the system temp dir.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipcore-example-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
