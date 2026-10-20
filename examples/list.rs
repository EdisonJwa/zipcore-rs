//! List, verify or extract the entries of a ZIP archive.
//!
//! ```text
//! cargo run --example list -- book.xlsx
//! cargo run --example list -- book.xlsx --verify
//! cargo run --example list -- book.zip --extract out/
//! cargo run --example list -- split.zip.001 split.zip.002 --verify
//! ```
//!
//! When several archive paths are given they are read as the volumes of a split archive, in the
//! order written.

use std::io;
use std::process::ExitCode;
use zipcore::{Archive, Compression};

fn usage() -> String {
    "usage: list <archive> [more volumes...] [--verify] [--extract <directory>]".to_string()
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Everything before the first `--` flag is an archive path; the rest are options.
    let split = args
        .iter()
        .position(|arg| arg.starts_with("--"))
        .unwrap_or(args.len());
    let (paths, rest) = args.split_at(split);

    let first = paths.first().ok_or_else(usage)?.clone();
    if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(usage());
    }

    if paths.len() == 1 {
        let archive = Archive::open(&first).map_err(|e| format!("{first}: {e}"))?;
        inspect(archive, &first, rest)
    } else {
        let archive = Archive::open_volumes(paths).map_err(|e| format!("{first}: {e}"))?;
        let label = format!("{first} (+{} more volumes)", paths.len() - 1);
        inspect(archive, &label, rest)
    }
}

fn inspect<R: io::Read + io::Seek>(
    mut archive: Archive<R>,
    label: &str,
    rest: &[String],
) -> Result<(), String> {
    println!(
        "{label}: {} entries{}",
        archive.len(),
        if archive.is_zip64() { " (ZIP64)" } else { "" }
    );

    if let Some(position) = rest.iter().position(|arg| arg == "--extract") {
        let directory = rest.get(position + 1).ok_or_else(usage)?;
        let report = archive
            .extract_all(std::path::Path::new(directory))
            .map_err(|e| format!("extract: {e}"))?;
        println!(
            "extracted {} entries ({} bytes) into {directory}",
            report.written.len(),
            report.total_bytes
        );
        if !report.skipped_symlinks.is_empty() {
            println!("skipped {} symbolic links", report.skipped_symlinks.len());
        }
        return Ok(());
    }

    // Snapshot the metadata so the archive can be borrowed mutably below.
    let rows: Vec<(String, Compression, u64, u64)> = archive
        .entries()
        .iter()
        .map(|e| {
            (
                e.name().to_string(),
                e.compression(),
                e.compressed_size(),
                e.uncompressed_size(),
            )
        })
        .collect();

    for (index, (name, compression, compressed, uncompressed)) in rows.iter().enumerate() {
        println!(
            "  {index:>5}  {:<9} {compressed:>10} -> {uncompressed:>10}  {name}",
            compression.name()
        );
    }

    if !rest.iter().any(|arg| arg == "--verify") {
        return Ok(());
    }

    let mut failures = 0usize;
    let mut skipped = 0usize;
    for (index, (name, compression, _, _)) in rows.iter().enumerate() {
        // A method this build has no codec for is reported, not counted as a failure.
        if !compression.is_supported() {
            eprintln!(
                "  SKIP {name}: {} is not supported by this build",
                compression.name()
            );
            skipped += 1;
            continue;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("  FAIL {name}: {error}");
                failures += 1;
                continue;
            }
        };
        if let Err(error) = io::copy(&mut entry, &mut io::sink()) {
            let detail = entry
                .take_terminal_error()
                .map(|v| v.to_string())
                .unwrap_or_else(|| error.to_string());
            eprintln!("  FAIL {name}: {detail}");
            failures += 1;
        }
    }

    if failures > 0 {
        return Err(format!("{failures} of {} entries failed", rows.len()));
    }
    if skipped > 0 {
        println!(
            "verified {} entries, all OK ({skipped} skipped)",
            rows.len() - skipped
        );
    } else {
        println!("verified {} entries, all OK", rows.len());
    }
    Ok(())
}
