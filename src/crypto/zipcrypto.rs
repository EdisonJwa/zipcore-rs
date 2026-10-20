//! Traditional PKWARE encryption ("ZipCrypto").
//!
//! This is the weak, legacy scheme that `zip -e` and most 1990s-era tools produce. It is
//! implemented for **compatibility**, not for confidentiality: the keystream is generated from a
//! 96-bit state that is fully recoverable from about a dozen bytes of known plaintext, and the
//! 12-byte header's check byte leaks which of 256 possibilities is correct for any candidate
//! password. PKWARE's own specification has described it as obsolete for decades.
//!
//! Callers who need actual secrecy should use the `aes-crypto` feature.

use crate::error::{Error, Result};

/// Length of the encryption header that precedes the entry payload.
pub(crate) const HEADER_LEN: usize = 12;

/// CRC-32 step used by the key schedule.
///
/// The usual CRC-32 is defined with a pre- and post-inversion; ZipCrypto wants the bare reflected
/// table step, so `crc32fast` cannot be used directly here.
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                0xEDB8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

/// The three 32-bit key words, plus the derived keystream position.
///
/// Zeroised on drop: the state is enough to decrypt the rest of the entry, so leaving it in freed
/// memory would be careless even for a scheme this weak.
pub(crate) struct Keys {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl Drop for Keys {
    fn drop(&mut self) {
        // Best-effort scrub. This crate forbids `unsafe`, so a volatile write is not available and
        // the compiler is technically free to elide these stores. That is an acceptable trade: the
        // guarantee this crate actually makes is "no unsafe code", and callers needing a hard
        // scrubbing guarantee must handle key material outside this type.
        self.key0 = 0;
        self.key1 = 0;
        self.key2 = 0;
    }
}

impl Keys {
    pub(crate) fn new(password: &[u8]) -> Self {
        let mut keys = Keys {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        };
        for &byte in password {
            keys.update(byte);
        }
        keys
    }

    #[inline]
    fn crc32(key: u32, byte: u8) -> u32 {
        (key >> 8) ^ CRC_TABLE[((key ^ u32::from(byte)) & 0xFF) as usize]
    }

    #[inline]
    fn update(&mut self, byte: u8) {
        self.key0 = Self::crc32(self.key0, byte);
        self.key1 = self.key1.wrapping_add(self.key0 & 0xFF);
        self.key1 = self.key1.wrapping_mul(134_775_813).wrapping_add(1);
        self.key2 = Self::crc32(self.key2, (self.key1 >> 24) as u8);
    }

    /// The next keystream byte.
    #[inline]
    fn stream_byte(&self) -> u8 {
        let temp = self.key2 | 2;
        ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8
    }

    /// Decrypt one byte, advancing the key state with the recovered plaintext.
    #[inline]
    pub(crate) fn decrypt_byte(&mut self, cipher: u8) -> u8 {
        let plain = cipher ^ self.stream_byte();
        self.update(plain);
        plain
    }

    /// Encrypt one byte, advancing the key state with the plaintext.
    #[inline]
    pub(crate) fn encrypt_byte(&mut self, plain: u8) -> u8 {
        let cipher = plain ^ self.stream_byte();
        self.update(plain);
        cipher
    }
}

/// Validate the 12-byte header and return the initialised key state.
///
/// `check` is the value the header's final byte must equal: the high byte of the CRC-32, or the
/// high byte of the DOS time when bit 3 of the general-purpose flags is set (the CRC is unknown at
/// header-write time in that case).
pub(crate) fn open_header(password: &[u8], header: &[u8], check: u8) -> Result<Keys> {
    if header.len() < HEADER_LEN {
        return Err(Error::malformed(
            "encrypted entry has a truncated encryption header",
        ));
    }
    let mut keys = Keys::new(password);
    let mut last = 0u8;
    for &byte in header {
        last = keys.decrypt_byte(byte);
    }
    if last != check {
        return Err(Error::WrongPassword);
    }
    Ok(keys)
}

/// Where the check byte comes from for a given entry.
pub(crate) enum CheckByte {
    /// Bit 3 clear: the CRC-32 is in the local header, so its high byte is the check.
    Crc(u32),
    /// Bit 3 set: the CRC is not known yet, so the high byte of the DOS time is used instead.
    DosTime(u16),
}

impl CheckByte {
    fn value(&self) -> u8 {
        match self {
            // The header stores the real CRC-32; its most significant byte is the check.
            CheckByte::Crc(crc) => (crc >> 24) as u8,
            CheckByte::DosTime(time) => (time >> 8) as u8,
        }
    }
}

/// Decrypt a whole entry held in memory. Used by the reading path for small entries and by tests.
pub(crate) fn decrypt(password: &[u8], check: CheckByte, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN {
        return Err(Error::malformed(
            "encrypted entry is shorter than its header",
        ));
    }
    let (header, payload) = data.split_at(HEADER_LEN);
    let mut keys = open_header(password, header, check.value())?;
    Ok(payload
        .iter()
        .map(|&cipher| keys.decrypt_byte(cipher))
        .collect())
}

/// Encrypt a payload, returning the 12-byte header followed by the ciphertext.
///
/// `header_entropy` provides the 11 random bytes before the check byte; the caller owns the
/// randomness source so this module needs no RNG dependency.
pub(crate) fn encrypt(
    password: &[u8],
    check: CheckByte,
    header_entropy: &[u8; HEADER_LEN - 1],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut keys = Keys::new(password);
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len());

    // The header is encrypted too; the final plaintext byte is the check value.
    for &byte in header_entropy.iter() {
        out.push(keys.encrypt_byte(byte));
    }
    out.push(keys.encrypt_byte(check.value()));

    out.extend(plaintext.iter().map(|&plain| keys.encrypt_byte(plain)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real archive produced by 7-Zip 25.01 with `-mem=ZipCrypto -p"pw123"`.
    ///
    /// Payload is the 12-byte header followed by 26 ciphertext bytes; the entry's CRC-32 is
    /// `0xfda496c8` and the plaintext is a BOM-prefixed line.
    const SEVEN_ZIP_PAYLOAD: &[u8] = &[
        0x04, 0xc2, 0x8c, 0x5f, 0x49, 0xcb, 0x07, 0x6e, 0x5c, 0xce, 0xa9, 0x8b, 0xca, 0x4a, 0xe1,
        0xcd, 0x2b, 0x8e, 0x0a, 0xe0, 0x9f, 0x4e, 0x1a, 0xdd, 0xf7, 0xa5, 0xc8, 0xa8, 0xc3, 0xdc,
        0x85, 0x3e, 0xcc, 0xd7, 0x72, 0x72, 0x80, 0x80,
    ];

    #[test]
    fn decrypts_a_real_7zip_archive() {
        let plain = decrypt(b"pw123", CheckByte::Crc(0xfda4_96c8), SEVEN_ZIP_PAYLOAD).unwrap();
        assert_eq!(
            plain, b"\xEF\xBB\xBFhello encrypted world\r\n",
            "must match what 7-Zip and Python's zipfile both report"
        );
    }

    #[test]
    fn wrong_password_is_rejected_by_the_header_check() {
        let error = decrypt(b"wrong", CheckByte::Crc(0xfda4_96c8), SEVEN_ZIP_PAYLOAD).unwrap_err();
        assert!(matches!(error, Error::WrongPassword), "{error:?}");
    }

    #[test]
    fn round_trips() {
        let entropy = [0x11u8; HEADER_LEN - 1];
        let plain = b"the quick brown fox jumps over the lazy dog";
        let sealed = encrypt(b"secret", CheckByte::Crc(0x1234_5678), &entropy, plain);
        assert_eq!(sealed.len(), HEADER_LEN + plain.len());
        let back = decrypt(b"secret", CheckByte::Crc(0x1234_5678), &sealed).unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn dos_time_check_byte_is_used_when_the_crc_is_deferred() {
        // Bit 3 set: the reader validates against the high byte of the DOS time instead.
        let entropy = [0x5Au8; HEADER_LEN - 1];
        let sealed = encrypt(b"pw", CheckByte::DosTime(0xBC12), &entropy, b"abc");
        assert!(decrypt(b"pw", CheckByte::DosTime(0xBC12), &sealed).is_ok());
        // The CRC interpretation must not accidentally pass.
        assert!(decrypt(b"pw", CheckByte::Crc(0x0012_0000), &sealed).is_err());
    }

    #[test]
    fn a_truncated_header_is_an_error_not_a_panic() {
        assert!(decrypt(b"pw", CheckByte::Crc(0), &[0u8; 4]).is_err());
    }
}
