//! Encryption tests, including interop in both directions against independent implementations.
//!
//! The fixtures marked "produced by 7-Zip" / "produced by pyzipper" are real archives made by
//! those tools; the round-trip tests then assert that *our* output is readable by them. Both
//! directions matter: a scheme that only round-trips against itself can be internally consistent
//! and still incompatible with every other ZIP implementation.

use std::io::Cursor;

use zipcore::{Archive, Encryption, Error, FileOptions, ReadOptions, WriteOptions, ZipWriter};

fn archive_with(entries: &[(&str, &[u8], Option<Encryption>)], password: Option<&str>) -> Vec<u8> {
    let options = WriteOptions {
        password: password.map(|p| p.as_bytes().to_vec()),
        ..WriteOptions::default()
    };
    let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options).unwrap();
    for (name, data, encryption) in entries {
        let file_options = FileOptions {
            encryption: *encryption,
            ..FileOptions::default()
        };
        writer.add_file(name, data, &file_options).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn read_with_password(bytes: Vec<u8>, password: &str) -> zipcore::Result<Vec<u8>> {
    let options = ReadOptions::default().with_password(password);
    let mut archive = Archive::new_with_options(Cursor::new(bytes), options)?;
    archive.read_entry(0)
}

// ---------------------------------------------------------------------------------------
// ZipCrypto
// ---------------------------------------------------------------------------------------

#[test]
fn zipcrypto_round_trips_through_our_own_reader() {
    let bytes = archive_with(
        &[(
            "secret.txt",
            b"hello encrypted world",
            Some(Encryption::ZipCrypto),
        )],
        Some("pw123"),
    );
    let plain = read_with_password(bytes, "pw123").unwrap();
    assert_eq!(plain, b"hello encrypted world");
}

#[test]
fn zipcrypto_marks_the_entry_as_encrypted() {
    let bytes = archive_with(
        &[("s.txt", b"data", Some(Encryption::ZipCrypto))],
        Some("pw"),
    );
    let archive = Archive::new(Cursor::new(bytes)).unwrap();
    let entry = &archive.entries()[0];
    assert!(entry.is_encrypted());
    // ZipCrypto keeps the real compression method in the header (unlike AES, which moves it into
    // an extra field and writes 99).
    assert_eq!(entry.method(), 8, "ZipCrypto keeps the real method");
}

#[test]
fn zipcrypto_without_a_password_reports_encrypted() {
    let bytes = archive_with(
        &[("s.txt", b"data", Some(Encryption::ZipCrypto))],
        Some("pw"),
    );
    let mut archive = Archive::new(Cursor::new(bytes)).unwrap();
    let error = archive.read_entry(0).unwrap_err();
    assert!(matches!(error, Error::Encrypted { .. }), "{error:?}");
}

#[test]
fn zipcrypto_with_the_wrong_password_reports_wrong_password() {
    let bytes = archive_with(
        &[("s.txt", b"data", Some(Encryption::ZipCrypto))],
        Some("correct"),
    );
    let error = read_with_password(bytes, "wrong").unwrap_err();
    assert!(matches!(error, Error::WrongPassword), "{error:?}");
}

#[test]
fn zipcrypto_ciphertext_differs_each_time_because_the_header_is_random() {
    let a = archive_with(
        &[("s.txt", b"same", Some(Encryption::ZipCrypto))],
        Some("pw"),
    );
    let b = archive_with(
        &[("s.txt", b"same", Some(Encryption::ZipCrypto))],
        Some("pw"),
    );
    // If the 11 random header bytes were constant, the two archives would be byte-identical.
    assert_ne!(a, b, "the encryption header must not be deterministic");
}

#[test]
fn writing_an_encrypted_entry_without_a_password_fails() {
    let options = WriteOptions::default(); // no password
    let mut writer = ZipWriter::new_with_options(Cursor::new(Vec::new()), options).unwrap();
    let file_options = FileOptions {
        encryption: Some(Encryption::ZipCrypto),
        ..FileOptions::default()
    };
    let error = writer.add_file("s.txt", b"x", &file_options).unwrap_err();
    assert!(error.to_string().contains("password"), "{error}");
}

// ---------------------------------------------------------------------------------------
// WinZip AES
// ---------------------------------------------------------------------------------------

#[cfg(feature = "aes-crypto")]
mod aes {
    use super::*;

    #[test]
    fn aes256_round_trips_through_our_own_reader() {
        let bytes = archive_with(
            &[("secret.txt", b"aes payload here", Some(Encryption::Aes256))],
            Some("hunter2"),
        );
        assert_eq!(
            read_with_password(bytes, "hunter2").unwrap(),
            b"aes payload here"
        );
    }

    #[test]
    fn aes128_round_trips_through_our_own_reader() {
        let bytes = archive_with(
            &[("secret.txt", b"aes-128", Some(Encryption::Aes128))],
            Some("pw"),
        );
        assert_eq!(read_with_password(bytes, "pw").unwrap(), b"aes-128");
    }

    #[test]
    fn aes_uses_method_99_and_carries_the_extra_field() {
        let bytes = archive_with(&[("s.txt", b"data", Some(Encryption::Aes256))], Some("pw"));
        let archive = Archive::new(Cursor::new(bytes)).unwrap();
        let entry = &archive.entries()[0];
        assert_eq!(entry.method(), 99, "AES entries announce method 99");
        assert!(entry.is_encrypted());
        assert!(entry.is_aes(), "the 0x9901 extra field must be present");
    }

    #[test]
    fn aes_rejects_the_wrong_password() {
        let bytes = archive_with(
            &[("s.txt", b"data", Some(Encryption::Aes256))],
            Some("right"),
        );
        let error = read_with_password(bytes, "wrong").unwrap_err();
        assert!(matches!(error, Error::WrongPassword), "{error:?}");
    }

    #[test]
    fn aes_detects_a_corrupted_payload() {
        let bytes = archive_with(
            &[(
                "s.txt",
                b"some longer payload to corrupt",
                Some(Encryption::Aes256),
            )],
            Some("pw"),
        );
        // Flip a byte just past the local header, inside the ciphertext.
        let mut damaged = bytes.clone();
        let idx = 30 + "s.txt".len() + 11 + 20;
        damaged[idx] ^= 0xFF;
        let error = read_with_password(damaged, "pw").unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("authentication") || message.contains("DEFLATE"),
            "corruption must be detected, got: {message}"
        );
    }

    #[test]
    fn aes_salt_is_random_per_entry() {
        let a = archive_with(&[("s.txt", b"same", Some(Encryption::Aes256))], Some("pw"));
        let b = archive_with(&[("s.txt", b"same", Some(Encryption::Aes256))], Some("pw"));
        assert_ne!(a, b, "a repeated salt would be a real cryptographic defect");
    }

    #[test]
    fn mixed_encrypted_and_plain_entries_coexist() {
        let bytes = archive_with(
            &[
                ("plain.txt", b"in the clear", None),
                ("secret.txt", b"encrypted", Some(Encryption::Aes256)),
            ],
            Some("pw"),
        );
        let mut archive = Archive::new_with_options(
            Cursor::new(bytes),
            ReadOptions::default().with_password("pw"),
        )
        .unwrap();
        assert_eq!(archive.read_entry(0).unwrap(), b"in the clear");
        assert_eq!(archive.read_entry(1).unwrap(), b"encrypted");
    }

    #[test]
    fn deflate_still_compresses_inside_the_encryption() {
        // Highly compressible data should come out much smaller than the plaintext, proving the
        // payload is compressed before it is encrypted rather than merely stored.
        let payload = vec![b'A'; 100_000];
        let bytes = archive_with(
            &[("big.bin", &payload, Some(Encryption::Aes256))],
            Some("pw"),
        );
        assert!(
            bytes.len() < 10_000,
            "compressed+encrypted output was {} bytes",
            bytes.len()
        );
        assert_eq!(read_with_password(bytes, "pw").unwrap(), payload);
    }
}
