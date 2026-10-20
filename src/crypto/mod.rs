//! Entry encryption.
//!
//! Two schemes are supported, and they are not equivalent:
//!
//! * [`zipcrypto`] — traditional PKWARE encryption. **Not secure**; present for compatibility with
//!   legacy archives. Requires no dependencies.
//! * [`aes`] — WinZip AES (AE-1/AE-2): AES-CTR with HMAC-SHA1 authentication, behind the
//!   `aes-crypto` feature. Use this when confidentiality actually matters.
//!
//! Both expose the same [`CryptoStream`] shape so the reader and writer never special-case them.

pub(crate) mod zipcrypto;

#[cfg(feature = "aes-crypto")]
pub(crate) mod aes;

/// Which scheme an entry uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// Traditional PKWARE encryption.
    ZipCrypto,
    /// WinZip AES with the given key strength.
    #[cfg(feature = "aes-crypto")]
    Aes(aes::Strength),
}
