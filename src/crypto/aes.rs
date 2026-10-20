//! WinZip AES encryption (AE-1 and AE-2).
//!
//! Layout of an encrypted entry, per the WinZip AES specification:
//!
//! ```text
//! salt (8/12/16 bytes) | password verifier (2) | ciphertext (…) | HMAC-SHA1 tag (10)
//! ```
//!
//! Keys come from PBKDF2-HMAC-SHA1 over the password and salt, 1000 iterations, producing
//! `2 * key_len + 2` bytes: an encryption key, an authentication key, and the 2-byte verifier.
//! The payload is AES-CTR with a 128-bit little-endian counter starting at **1**, and the
//! authentication code is the first 10 bytes of HMAC-SHA1 over the ciphertext.
//!
//! AE-2 (what this crate writes) stores a zero CRC-32 in the central directory, because the HMAC
//! already authenticates the data and a redundant CRC would be a second thing to get wrong.

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit as MacKeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Length of the trailing authentication code.
pub(crate) const HMAC_LEN: usize = 10;

type HmacSha1 = Hmac<Sha1>;

/// Key strength of a WinZip AES entry, from the `0x9901` extra field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strength {
    /// AES-128.
    Bits128,
    /// AES-192.
    Bits192,
    /// AES-256.
    Bits256,
}

impl Strength {
    pub(crate) fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Strength::Bits128),
            2 => Some(Strength::Bits192),
            3 => Some(Strength::Bits256),
            _ => None,
        }
    }

    pub(crate) fn salt_len(self) -> usize {
        match self {
            Strength::Bits128 => 8,
            Strength::Bits192 => 12,
            Strength::Bits256 => 16,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Strength::Bits128 => 16,
            Strength::Bits192 => 24,
            Strength::Bits256 => 32,
        }
    }
}

/// Derive the encryption key, authentication key and password verifier.
fn derive(password: &[u8], salt: &[u8], strength: Strength) -> ([u8; 32], [u8; 32], [u8; 2]) {
    let key_len = strength.key_len();
    // 2 * key_len + 2 bytes of key material; the tail 2 bytes are the verifier.
    let mut material = [0u8; 32 * 2 + 2];
    let len = 2 * key_len + 2;
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut material[..len]);

    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    let mut verify = [0u8; 2];
    enc[..key_len].copy_from_slice(&material[..key_len]);
    mac[..key_len].copy_from_slice(&material[key_len..2 * key_len]);
    verify.copy_from_slice(&material[2 * key_len..len]);
    material.zeroize();
    (enc, mac, verify)
}

/// AES-CTR with the WinZip counter convention: 128-bit little-endian, starting at 1.
///
/// `aes`/`ctr` are keyed for a fixed size at compile time, so the three strengths are handled by
/// separate variants over a shared interface.
enum Cipher {
    Aes128(Box<ctr::Ctr128LE<aes::Aes128>>),
    Aes192(Box<ctr::Ctr128LE<aes::Aes192>>),
    Aes256(Box<ctr::Ctr128LE<aes::Aes256>>),
}

impl Cipher {
    fn new(strength: Strength, key: &[u8; 32]) -> Self {
        // Counter block: little-endian 128-bit, initial value 1. Setting byte 0 to 1 is the
        // little-endian encoding of that, since all higher bytes are zero.
        let mut block = [0u8; 16];
        block[0] = 1;
        match strength {
            Strength::Bits128 => {
                let k: [u8; 16] = key[..16].try_into().expect("16-byte key");
                Cipher::Aes128(Box::new(ctr::Ctr128LE::new(&k.into(), &block.into())))
            }
            Strength::Bits192 => {
                let k: [u8; 24] = key[..24].try_into().expect("24-byte key");
                Cipher::Aes192(Box::new(ctr::Ctr128LE::new(&k.into(), &block.into())))
            }
            Strength::Bits256 => {
                let k: [u8; 32] = key[..32].try_into().expect("32-byte key");
                Cipher::Aes256(Box::new(ctr::Ctr128LE::new(&k.into(), &block.into())))
            }
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Cipher::Aes128(c) => c.apply_keystream(data),
            Cipher::Aes192(c) => c.apply_keystream(data),
            Cipher::Aes256(c) => c.apply_keystream(data),
        }
    }
}

/// One-shot decryption of a complete AES-encrypted entry.
///
/// Verifies the password against the 2-byte verifier and the payload against the HMAC before
/// returning anything, so a caller never sees unauthenticated plaintext.
pub(crate) fn decrypt(password: &[u8], strength: Strength, data: &[u8]) -> Result<Vec<u8>> {
    let salt_len = strength.salt_len();
    let header_len = salt_len + 2;
    if data.len() < header_len + HMAC_LEN {
        return Err(Error::malformed(
            "AES entry is shorter than its salt and authentication code",
        ));
    }
    let salt = &data[..salt_len];
    let verifier = &data[salt_len..header_len];
    let ciphertext = &data[header_len..data.len() - HMAC_LEN];
    let tag = &data[data.len() - HMAC_LEN..];

    let (enc_key, mac_key, expected) = derive(password, salt, strength);
    if expected != verifier {
        return Err(Error::WrongPassword);
    }

    // Authenticate before decrypting: a forged or corrupted entry is rejected without the
    // plaintext ever reaching the caller.
    let mut mac = <HmacSha1 as MacKeyInit>::new_from_slice(&mac_key[..strength.key_len()])
        .map_err(|_| Error::malformed("invalid HMAC key length"))?;
    mac.update(ciphertext);
    let full = mac.finalize().into_bytes();
    // WinZip stores only the leading 10 bytes of the HMAC-SHA1 tag, so compare that prefix.
    // `verify_slice` expects the full length and would reject a truncated tag.
    if !constant_time_eq(&full[..HMAC_LEN], tag) {
        return Err(Error::malformed("AES authentication code does not match"));
    }

    let mut plain = ciphertext.to_vec();
    Cipher::new(strength, &enc_key).apply(&mut plain);
    Ok(plain)
}

/// Compare two equal-length byte slices without short-circuiting, so a timing signal cannot be
/// used to forge a tag byte by byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// One-shot encryption of a complete entry payload.
///
/// Returns the salt and verifier, the ciphertext, and the authentication code separately so the
/// writer can place them correctly around the (compressed) payload.
pub(crate) fn encrypt(
    password: &[u8],
    strength: Strength,
    salt: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    debug_assert_eq!(salt.len(), strength.salt_len());
    let (enc_key, mac_key, verifier) = derive(password, salt, strength);

    let mut out = Vec::with_capacity(salt.len() + 2 + plaintext.len() + HMAC_LEN);
    out.extend_from_slice(salt);
    out.extend_from_slice(&verifier);

    let mut ciphertext = plaintext.to_vec();
    Cipher::new(strength, &enc_key).apply(&mut ciphertext);

    let mut mac = <HmacSha1 as MacKeyInit>::new_from_slice(&mac_key[..strength.key_len()])
        .map_err(|_| Error::malformed("invalid HMAC key length"))?;
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag[..HMAC_LEN]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A WinZip AES-256 archive produced by pyzipper 0.4.0 (`WZ_AES`, 256-bit) with password
    /// `pw123`, containing `secret.txt` = "hello encrypted world", deflated.
    ///
    /// The salt/verifier/ciphertext/tag layout below is exactly what that writer emitted.
    const REF_PAYLOAD_HEX: &str = "58d88ff6b38ab8aee2f1cede6a4bf69e5bad\
de4716f6a2353aed1c6f19df577c4aec378b544e3131d3c8a92506ff580040126b";

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// The reference entry's payload decrypts to a raw DEFLATE stream which inflates to the text.
    #[test]
    fn decrypts_a_pyzipper_aes256_entry() {
        let payload = hex(&REF_PAYLOAD_HEX.replace('\n', ""));
        let plain = decrypt(b"pw123", Strength::Bits256, &payload).unwrap();
        let inflated = miniz_oxide::inflate::decompress_to_vec(&plain).unwrap();
        assert_eq!(inflated, b"hello encrypted world");
    }

    #[test]
    fn rejects_the_wrong_password() {
        let payload = hex(&REF_PAYLOAD_HEX.replace('\n', ""));
        let error = decrypt(b"nope", Strength::Bits256, &payload).unwrap_err();
        assert!(matches!(error, Error::WrongPassword), "{error:?}");
    }

    #[test]
    fn rejects_a_modified_ciphertext() {
        let mut payload = hex(&REF_PAYLOAD_HEX.replace('\n', ""));
        // Flip a bit in the middle of the ciphertext, leaving salt/verifier intact.
        let mid = payload.len() / 2;
        payload[mid] ^= 0x01;
        let error = decrypt(b"pw123", Strength::Bits256, &payload).unwrap_err();
        assert!(error.to_string().contains("authentication"), "{error}");
    }

    #[test]
    fn round_trips_all_strengths() {
        for strength in [Strength::Bits128, Strength::Bits192, Strength::Bits256] {
            let salt = vec![0xABu8; strength.salt_len()];
            let plain = b"attack at dawn, bring snacks".as_slice();
            let sealed = encrypt(b"pw", strength, &salt, plain).unwrap();
            assert_eq!(
                sealed.len(),
                strength.salt_len() + 2 + plain.len() + HMAC_LEN
            );
            assert_eq!(decrypt(b"pw", strength, &sealed).unwrap(), plain);
        }
    }

    #[test]
    fn a_truncated_entry_is_an_error_not_a_panic() {
        assert!(decrypt(b"pw", Strength::Bits256, &[0u8; 4]).is_err());
    }

    #[test]
    fn strength_bytes_match_the_spec() {
        // 1 = AES-128, 2 = AES-192, 3 = AES-256, per the WinZip AES extra field definition.
        assert_eq!(Strength::from_byte(1), Some(Strength::Bits128));
        assert_eq!(Strength::from_byte(2), Some(Strength::Bits192));
        assert_eq!(Strength::from_byte(3), Some(Strength::Bits256));
        assert_eq!(Strength::from_byte(0), None);
        assert_eq!(Strength::from_byte(4), None);
    }
}
