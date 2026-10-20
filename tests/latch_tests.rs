//! A sink that fails after a byte budget is exhausted, to exercise the writer's error latch.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

pub struct FailAt {
    inner: Cursor<Vec<u8>>,
    budget: usize,
}

impl FailAt {
    pub fn new(budget: usize) -> Self {
        Self {
            inner: Cursor::new(Vec::new()),
            budget,
        }
    }
    pub fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
    }
    pub fn bytes(&self) -> &[u8] {
        self.inner.get_ref()
    }
}

impl Write for FailAt {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Err(io::Error::other("sink budget exhausted"));
        }
        let n = buf.len().min(self.budget);
        self.budget -= n;
        self.inner.write(&buf[..n])
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for FailAt {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// A reader whose payload runs out before the declared size.
pub struct ShortReader(pub usize);

impl Read for ShortReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Ok(0);
        }
        let n = buf.len().min(self.0);
        self.0 -= n;
        buf[..n].fill(b'x');
        Ok(n)
    }
}

use zipcore::{Archive, Entry, Error, FileOptions, ZipWriter};

fn source_with_one_entry() -> (Entry, Vec<u8>) {
    let mut w = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    w.add_file("kept.txt", &[9u8; 4096], &FileOptions::stored())
        .unwrap();
    let bytes = w.finish().unwrap().into_inner();
    let archive = Archive::new(Cursor::new(bytes.clone())).unwrap();
    (archive.entries()[0].clone(), bytes)
}

/// A sink failure part-way through `add_preserved` must latch the writer, so every later call
/// reports the failure instead of appending to a stream whose structure no longer adds up.
#[test]
fn add_preserved_latches_a_sink_failure() {
    let (entry, _) = source_with_one_entry();
    // Enough room for the header, not the payload: the payload copy is where it trips.
    let mut writer = ZipWriter::new(FailAt::new(0)).unwrap();
    // Restore enough budget to accept the header, then exhaust it during the payload copy.
    writer.get_mut().set_budget(64 * 1024);
    writer.get_mut().set_budget(entry.name_raw().len() + 30);
    let mut payload = ShortReader(4096);
    let error = writer
        .add_preserved(&entry, &mut payload)
        .expect_err("the sink refuses the payload");
    assert!(
        matches!(error.kind(), zipcore::error::Kind::Io),
        "unexpected kind: {error}"
    );

    // The key property: no further work is accepted.
    let later = writer.add_file("after.txt", b"ok", &FileOptions::default());
    assert!(
        matches!(later, Err(Error::WriterFailed { .. })),
        "the writer must stay failed, got {later:?}"
    );
    assert!(matches!(writer.finish(), Err(Error::WriterFailed { .. })));
}

/// The same property for a payload that simply ends early.
#[test]
fn add_preserved_latches_a_short_payload() {
    let (entry, _) = source_with_one_entry();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut payload = ShortReader(100); // declared 4096
    writer
        .add_preserved(&entry, &mut payload)
        .expect_err("payload ends early");
    assert!(
        matches!(
            writer.add_file("after.txt", b"ok", &FileOptions::default()),
            Err(Error::WriterFailed { .. })
        ),
        "a truncated preserved entry must latch the writer"
    );
}
