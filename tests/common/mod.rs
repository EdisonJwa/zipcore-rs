//! A minimal ZIP *writer* used only to build fixtures for the tests.
//!
//! Writing is deliberately not part of the library, so the tests carry the few dozen lines
//! needed to emit valid archives by hand. Building the bytes ourselves means the tests do not
//! depend on any external compressor, and lets us produce deliberately hostile archives
//! (bad CRCs, forged sizes, ZIP64 sentinels) that a real writer would never emit.

#![allow(dead_code)]

pub const SIG_LOCAL: u32 = 0x0403_4b50;
pub const SIG_CENTRAL: u32 = 0x0201_4b50;
pub const SIG_EOCD: u32 = 0x0605_4b50;
pub const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
pub const SIG_ZIP64_LOCATOR: u32 = 0x0706_4b50;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;
pub const METHOD_BZIP2: u16 = 12;
pub const METHOD_ZSTD: u16 = 93;

pub const FLAG_ENCRYPTED: u16 = 1 << 0;

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[derive(Default)]
pub struct ZipBuilder {
    body: Vec<u8>,
    central: Vec<u8>,
    count: u64,
}

impl ZipBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_stored(&mut self, name: &str, content: &[u8]) -> &mut Self {
        self.add_entry(name, content, content, METHOD_STORED, 0)
    }

    /// Add a Deflate entry, compressing `content` with miniz_oxide.
    pub fn add_deflate(&mut self, name: &str, content: &[u8]) -> &mut Self {
        let payload = miniz_oxide::deflate::compress_to_vec(content, 6);
        self.add_entry(name, content, &payload, METHOD_DEFLATE, 0)
    }

    /// Add an entry whose general-purpose flags are attacker-controlled.
    pub fn add_flagged(&mut self, name: &str, content: &[u8], flags: u16) -> &mut Self {
        self.add_entry(name, content, content, METHOD_STORED, flags)
    }

    /// Add an entry that claims a compression method the reader does not implement.
    pub fn add_unknown_method(&mut self, name: &str, content: &[u8], method: u16) -> &mut Self {
        self.add_entry(name, content, content, method, 0)
    }

    /// Add a Deflate entry but store a wrong CRC-32 in the central directory.
    pub fn add_deflate_bad_crc(&mut self, name: &str, content: &[u8]) -> &mut Self {
        let payload = miniz_oxide::deflate::compress_to_vec(content, 6);
        let good = crc32(content);
        self.add_entry_with_crc(
            name,
            content,
            &payload,
            METHOD_DEFLATE,
            0,
            good ^ 0xffff_ffff,
        )
    }

    /// Add a Deflate entry whose central directory declares a larger size than it produces.
    pub fn add_deflate_overstated_size(
        &mut self,
        name: &str,
        content: &[u8],
        extra: u64,
    ) -> &mut Self {
        let payload = miniz_oxide::deflate::compress_to_vec(content, 6);
        let declared = content.len() as u64 + extra;
        self.add_entry_inner(
            name,
            declared,
            payload.len() as u64,
            &payload,
            METHOD_DEFLATE,
            0,
            crc32(content),
            true,
        )
    }

    fn add_entry(
        &mut self,
        name: &str,
        original: &[u8],
        payload: &[u8],
        method: u16,
        flags: u16,
    ) -> &mut Self {
        let crc = crc32(original);
        self.add_entry_with_crc(name, original, payload, method, flags, crc)
    }

    fn add_entry_with_crc(
        &mut self,
        name: &str,
        original: &[u8],
        payload: &[u8],
        method: u16,
        flags: u16,
        crc: u32,
    ) -> &mut Self {
        self.add_entry_inner(
            name,
            original.len() as u64,
            payload.len() as u64,
            payload,
            method,
            flags,
            crc,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_entry_inner(
        &mut self,
        name: &str,
        declared_uncompressed: u64,
        compressed: u64,
        payload: &[u8],
        method: u16,
        flags: u16,
        crc: u32,
        zip64: bool,
    ) -> &mut Self {
        let offset = self.body.len() as u64;
        let name_bytes = name.as_bytes();

        // ---- local file header (always uses 32-bit fields; sizes fit for the tests) ----
        self.body.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        self.body.extend_from_slice(&45u16.to_le_bytes()); // version needed
        self.body.extend_from_slice(&flags.to_le_bytes());
        self.body.extend_from_slice(&method.to_le_bytes());
        self.body.extend_from_slice(&0u16.to_le_bytes()); // time
        self.body.extend_from_slice(&0u16.to_le_bytes()); // date
        self.body.extend_from_slice(&crc.to_le_bytes());
        self.body
            .extend_from_slice(&(compressed as u32).to_le_bytes());
        // The local header keeps the real size even for the ZIP64 fixture; only the central
        // directory uses sentinels, which is legal and is what exercises the parser.
        self.body
            .extend_from_slice(&(declared_uncompressed as u32).to_le_bytes());
        self.body
            .extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.body.extend_from_slice(&0u16.to_le_bytes()); // extra len
        self.body.extend_from_slice(name_bytes);
        self.body.extend_from_slice(payload);

        // ---- central directory entry ----
        let mut extra: Vec<u8> = Vec::new();
        let (cd_uncompressed, cd_compressed, cd_offset) = if zip64 {
            extra.extend_from_slice(&0x0001u16.to_le_bytes()); // ZIP64 extended information
            extra.extend_from_slice(&24u16.to_le_bytes());
            extra.extend_from_slice(&declared_uncompressed.to_le_bytes());
            extra.extend_from_slice(&compressed.to_le_bytes());
            extra.extend_from_slice(&offset.to_le_bytes());
            (0xffff_ffffu32, 0xffff_ffffu32, 0xffff_ffffu32)
        } else {
            (
                declared_uncompressed as u32,
                compressed as u32,
                offset as u32,
            )
        };

        self.central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        self.central.extend_from_slice(&0x031eu16.to_le_bytes()); // made by: Unix, v3.0
        self.central.extend_from_slice(&45u16.to_le_bytes()); // needed
        self.central.extend_from_slice(&flags.to_le_bytes());
        self.central.extend_from_slice(&method.to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes()); // time
        self.central.extend_from_slice(&0u16.to_le_bytes()); // date
        self.central.extend_from_slice(&crc.to_le_bytes());
        self.central.extend_from_slice(&cd_compressed.to_le_bytes());
        self.central
            .extend_from_slice(&cd_uncompressed.to_le_bytes());
        self.central
            .extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.central
            .extend_from_slice(&(extra.len() as u16).to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        self.central.extend_from_slice(&0u16.to_le_bytes()); // disk start
        self.central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        self.central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        self.central.extend_from_slice(&cd_offset.to_le_bytes());
        self.central.extend_from_slice(name_bytes);
        self.central.extend_from_slice(&extra);

        self.count += 1;
        self
    }

    /// Add a stored entry whose central directory record uses ZIP64 sentinels plus a ZIP64
    /// extended-information extra field. Pair with [`ZipBuilder::finish_zip64`].
    pub fn add_stored_zip64(&mut self, name: &str, content: &[u8]) -> &mut Self {
        self.add_entry_inner(
            name,
            content.len() as u64,
            content.len() as u64,
            content,
            METHOD_STORED,
            0,
            crc32(content),
            true,
        )
    }

    /// Add an entry compressed with zstd (method 93).
    ///
    /// Built with the `zstd` crate, so the payload is a real frame from libzstd rather than
    /// anything this crate produced.
    pub fn add_zstd(&mut self, name: &str, content: &[u8]) -> &mut Self {
        let payload = zstd::encode_all(content, 3).expect("zstd compression should succeed");
        self.add_entry_inner(
            name,
            content.len() as u64,
            payload.len() as u64,
            &payload,
            METHOD_ZSTD,
            0,
            crc32(content),
            false,
        )
    }

    /// Add an entry that claims zstd but whose payload is not a zstd frame.
    pub fn add_bogus_zstd(&mut self, name: &str, content: &[u8]) -> &mut Self {
        let garbage = vec![0x5au8; 64];
        self.add_entry_inner(
            name,
            content.len() as u64,
            garbage.len() as u64,
            &garbage,
            METHOD_ZSTD,
            0,
            crc32(content),
            false,
        )
    }

    /// Add an entry compressed with bzip2 (method 12).
    ///
    /// Built with the `bzip2` crate's pure-Rust backend, so the payload is a real bzip2 stream
    /// rather than anything this crate produced.
    pub fn add_bzip2(&mut self, name: &str, content: &[u8]) -> &mut Self {
        use std::io::Write;

        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        encoder
            .write_all(content)
            .expect("bzip2 compression should succeed");
        let payload = encoder.finish().expect("bzip2 stream should finish");
        self.add_entry_inner(
            name,
            content.len() as u64,
            payload.len() as u64,
            &payload,
            METHOD_BZIP2,
            0,
            crc32(content),
            false,
        )
    }

    /// Add an entry that claims bzip2 but whose payload is not a bzip2 stream.
    pub fn add_bogus_bzip2(&mut self, name: &str, content: &[u8]) -> &mut Self {
        let garbage = vec![0x5au8; 64];
        self.add_entry_inner(
            name,
            content.len() as u64,
            garbage.len() as u64,
            &garbage,
            METHOD_BZIP2,
            0,
            crc32(content),
            false,
        )
    }

    /// Emit a classic (non-ZIP64) archive with `comment` after the EOCD record.
    pub fn finish_with_comment(&self, comment: &[u8]) -> Vec<u8> {
        let mut out = self.body.clone();
        let cd_offset = out.len() as u64;
        let cd_size = self.central.len() as u64;
        out.extend_from_slice(&self.central);

        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
        out.extend_from_slice(&(self.count as u16).to_le_bytes());
        out.extend_from_slice(&(self.count as u16).to_le_bytes());
        out.extend_from_slice(&(cd_size as u32).to_le_bytes());
        out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    pub fn finish(&self) -> Vec<u8> {
        self.finish_with_comment(&[])
    }

    /// Emit a ZIP64 archive: ZIP64 EOCD record, locator, then a sentinel-filled EOCD.
    pub fn finish_zip64(&self) -> Vec<u8> {
        let mut out = self.body.clone();
        let cd_offset = out.len() as u64;
        let cd_size = self.central.len() as u64;
        out.extend_from_slice(&self.central);

        let zip64_eocd_offset = out.len() as u64;
        out.extend_from_slice(&SIG_ZIP64_EOCD.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes()); // size of the rest of this record
        out.extend_from_slice(&45u16.to_le_bytes()); // version made by
        out.extend_from_slice(&45u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u32.to_le_bytes()); // this disk
        out.extend_from_slice(&0u32.to_le_bytes()); // cd start disk
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());

        out.extend_from_slice(&SIG_ZIP64_LOCATOR.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // disk with ZIP64 EOCD
        out.extend_from_slice(&zip64_eocd_offset.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // total disks

        // The EOCD deliberately carries sentinel values, as a real ZIP64 writer emits, so the
        // reader must take the counts and offsets from the ZIP64 record instead.
        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0xffffu16.to_le_bytes());
        out.extend_from_slice(&0xffffu16.to_le_bytes());
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }
}

/// Read `buf` as an archive from memory.
pub fn cursor(buf: Vec<u8>) -> std::io::Cursor<Vec<u8>> {
    std::io::Cursor::new(buf)
}
