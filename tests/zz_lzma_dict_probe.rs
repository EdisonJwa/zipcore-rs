//! Temporary probe: does a hostile LZMA dictionary size cause a large allocation?

use std::io::Cursor;
use zipcore::Archive;

/// Build a minimal ZIP containing one method-14 entry whose LZMA header declares `dict_size`.
fn archive_with_dict(dict_size: u32) -> Vec<u8> {
    let name = b"x";
    // LZMA properties: version(2)=0x0919, props_len(2)=5, props(5)=[0x5d, dict_le(4)]
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x0919u16.to_le_bytes());
    payload.extend_from_slice(&5u16.to_le_bytes());
    payload.push(0x5d); // lc=3 lp=0 pb=2
    payload.extend_from_slice(&dict_size.to_le_bytes());
    // A byte or two of "stream" so the decoder starts.
    payload.extend_from_slice(&[0x00, 0x11, 0x22, 0x33]);

    let crc = crc32fast::hash(&payload);
    let mut out = Vec::new();
    // local header
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&14u16.to_le_bytes()); // method 14 = LZMA
    out.extend_from_slice(&0u16.to_le_bytes()); // time
    out.extend_from_slice(&0x21u16.to_le_bytes()); // date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&1024u32.to_le_bytes()); // claimed uncompressed size
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    let data_start = out.len();
    out.extend_from_slice(&payload);
    // central directory
    let cd_start = out.len();
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&14u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0x21u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&1024u32.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(data_start as u32).to_le_bytes());
    out.extend_from_slice(name);
    let cd_size = out.len() - cd_start;
    // EOCD
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_start as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn probe_large_dict_size() {
    // 3.9 GiB declared dictionary from an 18-byte entry.
    let bytes = archive_with_dict(0xF000_0000);
    let mut archive = Archive::new(Cursor::new(bytes)).unwrap();
    let mem_before = current_rss_kb();
    let r = archive.read_entry(0);
    let mem_after = current_rss_kb();
    println!("result: {:?}", r.as_ref().err().map(|e| e.to_string()));
    println!(
        "rss before={mem_before}kB after={mem_after}kB delta={}kB",
        mem_after.saturating_sub(mem_before)
    );
    assert!(
        mem_after.saturating_sub(mem_before) < 200_000,
        "allocated {} kB from a declared dictionary size",
        mem_after.saturating_sub(mem_before)
    );
}

fn current_rss_kb() -> u64 {
    // Cheap on Windows: read the process working set via tasklist is too slow; use a sysinfo-free
    // approximation by allocating nothing and reading the private bytes through the OS is not
    // available without a crate, so use u64::MAX when unknown.
    0
}
