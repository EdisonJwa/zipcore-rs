//! Validation against archives produced by real tools.
//!
//! Set `ZIPCORE_ARCHIVES` to a `;`-separated (`:`-separated on Unix) list of archive paths and
//! run `cargo test`. Every entry of every archive is decompressed and verified against the
//! CRC-32 and size recorded in its central directory. Without the variable the test is skipped,
//! so the suite stays hermetic by default.

use std::io;
use zipcore::{Archive, Compression};

#[test]
fn verifies_archives_named_by_the_environment() {
    let Some(list) = std::env::var_os("ZIPCORE_ARCHIVES") else {
        eprintln!("ZIPCORE_ARCHIVES is not set; skipping real-archive validation");
        return;
    };

    let mut archives_checked = 0usize;
    let mut entries_checked = 0usize;
    let mut entries_skipped = 0usize;

    for path in std::env::split_paths(&list) {
        let mut archive =
            Archive::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        archives_checked += 1;

        for index in 0..archive.len() {
            let entry = archive.entries()[index].clone();

            // Only the two methods this crate implements, and never encrypted members.
            if entry.is_encrypted()
                || !matches!(
                    entry.compression(),
                    Compression::Stored | Compression::Deflate
                )
            {
                entries_skipped += 1;
                continue;
            }

            let mut file = archive
                .by_index(index)
                .unwrap_or_else(|e| panic!("{}#{}: {e}", path.display(), entry.name()));

            if let Err(error) = io::copy(&mut file, &mut io::sink()) {
                let detail = file
                    .take_terminal_error()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| error.to_string());
                panic!("{}#{}: {detail}", path.display(), entry.name());
            }

            entries_checked += 1;
        }
    }

    assert!(archives_checked > 0, "no archives were checked");
    eprintln!(
        "verified {entries_checked} entries across {archives_checked} archives \
         ({entries_skipped} skipped)"
    );
}
