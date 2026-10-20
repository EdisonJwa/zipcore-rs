//! Reading archives that were split into several files.
//!
//! A split archive (`.zip.001`, `.zip.002`, … or `.z01`, `.z02`, `….zip`) is just the original
//! byte stream cut into pieces at arbitrary boundaries. Nothing in the ZIP structure records the
//! split, so reading one is only a matter of presenting the parts as a single seekable stream —
//! which is exactly what [`MultiVolumeReader`] does, without holding them in memory.
//!
//! This is deliberately *not* support for truly spanned archives, where each header carries a disk
//! number and an entry may begin on one volume and end on another. That layout belongs to the
//! floppy era and is vanishingly rare; the split-file convention above is what tools produce now.

use crate::error::{Error, Result};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

struct Part {
    path: PathBuf,
    file: File,
}

/// A `Read + Seek` view over several files that together hold one byte stream.
///
/// Construct it with [`MultiVolumeReader::open`], or use
/// [`Archive::open_volumes`](crate::Archive::open_volumes) to open an archive directly.
///
/// The caller supplies the volumes **in order**. Names with zero-padded numeric suffixes
/// (`part.001`, `part.002`, …) sort correctly as strings, so a plain lexicographic sort works
/// there; unpadded ones (`part.1`, `part.2`, …) do not, and would put `part.10` before `part.2`.
pub struct MultiVolumeReader {
    parts: Vec<Part>,
    /// Byte length of each part, in the same order.
    lengths: Vec<u64>,
    /// Offset in the combined stream at which each part begins.
    starts: Vec<u64>,
    total: u64,
    position: u64,
}

impl MultiVolumeReader {
    /// Open `paths` as one stream, in the order given.
    pub fn open<I, P>(paths: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut parts = Vec::new();
        let mut lengths = Vec::new();
        let mut starts = Vec::new();
        let mut total = 0u64;

        for path in paths {
            let path = path.as_ref().to_path_buf();
            let file = File::open(&path).map_err(Error::Io)?;
            let length = file.metadata().map_err(Error::Io)?.len();
            starts.push(total);
            total += length;
            lengths.push(length);
            parts.push(Part { path, file });
        }

        if parts.is_empty() {
            return Err(Error::malformed("no volumes were given"));
        }

        Ok(Self {
            parts,
            lengths,
            starts,
            total,
            position: 0,
        })
    }

    /// Combined length of every volume, in bytes.
    pub fn len(&self) -> u64 {
        self.total
    }

    /// Whether the volumes are empty.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// How many volumes make up the stream.
    pub fn volume_count(&self) -> usize {
        self.parts.len()
    }

    /// The path of the volume at `index`.
    pub fn volume_path(&self, index: usize) -> Option<&Path> {
        self.parts.get(index).map(|part| part.path.as_path())
    }

    /// Which volume holds `position`.
    fn index_for(&self, position: u64) -> usize {
        match self.starts.binary_search(&position) {
            Ok(index) => index,
            // `starts[0]` is always 0 and `position` is past the end only when the caller has
            // already been short-circuited, so the subtraction cannot underflow.
            Err(index) => index - 1,
        }
    }
}

impl std::fmt::Debug for MultiVolumeReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiVolumeReader")
            .field("volumes", &self.parts.len())
            .field("total", &self.total)
            .field("position", &self.position)
            .finish()
    }
}

impl Read for MultiVolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total {
            return Ok(0);
        }

        let mut filled = 0usize;
        // A single `read` spans volume boundaries, so callers see one continuous stream rather
        // than a short read at every seam.
        while filled < buf.len() && self.position < self.total {
            let index = self.index_for(self.position);
            let offset = self.position - self.starts[index];
            let available = (self.lengths[index] - offset) as usize;
            let want = (buf.len() - filled).min(available);

            self.parts[index].file.seek(SeekFrom::Start(offset))?;
            let read = self.parts[index]
                .file
                .read(&mut buf[filled..filled + want])?;
            if read == 0 {
                // A volume is shorter than its recorded length: treat it as end of stream rather
                // than spinning.
                break;
            }
            filled += read;
            self.position += read as u64;
        }
        Ok(filled)
    }
}

impl Seek for MultiVolumeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::End(offset) => self.total as i128 + offset as i128,
            SeekFrom::Current(offset) => self.position as i128 + offset as i128,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the first volume",
            ));
        }
        // Seeking past the end is allowed, as it is for a file; reads there return 0.
        self.position = target as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_part(tag: &str, index: usize, bytes: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("zipcore-vol-{tag}-{}-{index}", std::process::id()));
        let mut file = File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn reads_across_volume_boundaries() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let parts: Vec<PathBuf> = data
            .chunks(300)
            .enumerate()
            .map(|(index, chunk)| temp_part("across", index, chunk))
            .collect();

        let mut reader = MultiVolumeReader::open(&parts).unwrap();
        assert_eq!(reader.len(), data.len() as u64);
        assert_eq!(reader.volume_count(), 4);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);

        for path in parts {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn seeks_within_and_across_volumes() {
        // 256 bytes so the values do not wrap when cast, which keeps the expectations readable.
        let data: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let parts: Vec<PathBuf> = data
            .chunks(100)
            .enumerate()
            .map(|(index, chunk)| temp_part("seek", index, chunk))
            .collect();

        let mut reader = MultiVolumeReader::open(&parts).unwrap();
        assert_eq!(reader.volume_count(), 3);

        // Exactly on a seam, and one byte into the next volume.
        reader.seek(SeekFrom::Start(100)).unwrap();
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 100);

        // Relative seek backwards across a seam.
        reader.seek(SeekFrom::Current(-2)).unwrap();
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 99);

        // From the end.
        reader.seek(SeekFrom::End(-1)).unwrap();
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 255);

        // Seeking before the start is refused.
        assert!(reader.seek(SeekFrom::Start(0)).is_ok());
        assert!(reader.seek(SeekFrom::Current(-1)).is_err());

        // Reading past the end is empty, not an error.
        reader.seek(SeekFrom::Start(reader.len() + 10)).unwrap();
        assert_eq!(reader.read(&mut byte).unwrap(), 0);

        for path in parts {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn rejects_an_empty_volume_list() {
        let empty: Vec<PathBuf> = Vec::new();
        assert!(MultiVolumeReader::open(empty).is_err());
    }
}
