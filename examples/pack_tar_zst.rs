//! Pack a `tar.zst` — a tar stream compressed with zstd.
//!
//! ```text
//! cargo run --features zstd --example pack_tar_zst -- out.tar.zst
//! cargo run --features zstd --example pack_tar_zst -- out.tar.zst some/directory
//! ```
//!
//! With no directory argument a small deterministic set of files is packed, which is useful as a
//! fixture: `tar -tf out.tar.zst` should list it, and `tar -xf` should reproduce it.
//!
//! This is a different thing from ZIP's zstd *method*: here the whole tar stream is compressed at
//! once, so nothing has to be seekable and no per-entry framing is involved.

use std::fs::{File, Metadata};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zipcore::{TarEntryOptions, TarWriter};

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
    let out = args
        .next()
        .ok_or_else(|| "usage: pack_tar_zst <out.tar.zst> [directory]".to_string())?;
    let source = args.next().map(PathBuf::from);

    let file = File::create(&out).map_err(|e| format!("{out}: {e}"))?;
    let mut tar =
        TarWriter::new_zstd(BufWriter::new(file), 3).map_err(|e| format!("{out}: {e}"))?;

    let count = match source {
        Some(directory) => pack_directory(&mut tar, &directory)?,
        None => pack_fixture(&mut tar)?,
    };

    let file = tar
        .finish_zstd()
        .map_err(|e| format!("finish: {e}"))?
        .into_inner()
        .map_err(|e| format!("flush: {e}"))?;
    let length = file.metadata().map_err(|e| format!("stat: {e}"))?.len();

    println!("wrote {out} ({length} bytes, {count} entries)");
    println!("check it with: tar -tvf {out}");
    Ok(())
}

/// Pack a small deterministic set, so the result can be checked against a known expectation.
fn pack_fixture(tar: &mut TarWriter<impl std::io::Write>) -> Result<usize, String> {
    let options = TarEntryOptions::default();
    tar.add_file("hello.txt", b"hello from a tar.zst\n", &options)
        .map_err(|e| format!("hello.txt: {e}"))?;
    tar.add_directory("nested", &TarEntryOptions::directory())
        .map_err(|e| format!("nested: {e}"))?;

    let mut pattern = Vec::with_capacity(8192);
    pattern.extend((0..8192u32).map(|index| (index % 251) as u8));
    tar.add_file("nested/data.bin", &pattern, &options)
        .map_err(|e| format!("nested/data.bin: {e}"))?;
    Ok(3)
}

/// Pack every file below `directory`, using streaming entries so nothing is held in memory.
fn pack_directory(
    tar: &mut TarWriter<impl std::io::Write>,
    directory: &Path,
) -> Result<usize, String> {
    let mut pending = vec![directory.to_path_buf()];
    let mut count = 0usize;

    while let Some(path) = pending.pop() {
        let metadata = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let name = relative_name(directory, &path)?;

        if metadata.is_dir() {
            if !name.is_empty() {
                tar.add_directory(&name, &TarEntryOptions::directory())
                    .map_err(|e| format!("{name}: {e}"))?;
                count += 1;
            }
            let children = std::fs::read_dir(&path).map_err(|e| format!("{name}: {e}"))?;
            for child in children {
                let child = child.map_err(|e| format!("{name}: {e}"))?;
                pending.push(child.path());
            }
            continue;
        }

        // Streaming: the size is taken from the filesystem, so the file is never read into memory.
        let size = metadata.len();
        let mut entry = tar
            .start_file(&name, size, &tar_options(&metadata))
            .map_err(|e| format!("{name}: {e}"))?;
        let mut source = File::open(&path).map_err(|e| format!("{name}: {e}"))?;
        std::io::copy(&mut source, &mut entry).map_err(|e| format!("{name}: {e}"))?;
        entry.finish().map_err(|e| format!("{name}: {e}"))?;
        count += 1;
    }

    Ok(count)
}

fn relative_name(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if relative.as_os_str().is_empty() {
        return Ok(String::new());
    }
    let mut name = relative.to_string_lossy().replace('\\', "/");
    if path.is_dir() {
        name.push('/');
    }
    Ok(name)
}

#[cfg(unix)]
fn tar_options(metadata: &Metadata) -> TarEntryOptions {
    use std::os::unix::fs::MetadataExt;
    TarEntryOptions::default()
        .with_mode(metadata.mode() & 0o7777)
        .with_mtime(metadata.mtime() as u64)
}

#[cfg(not(unix))]
fn tar_options(_metadata: &Metadata) -> TarEntryOptions {
    TarEntryOptions::default()
}
