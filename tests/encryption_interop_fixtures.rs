//! Real encrypted archives produced by 7-Zip 25.01 and pyzipper 0.4.0.
//!
//! Regenerate with:
//!   7z a -tzip -p"pw123" -mem=ZipCrypto out.zip payload.txt
//!   7z a -tzip -p"pw123" -mem=AES256      out.zip payload.txt
//!   pyzipper.AESZipFile(..., encryption=pyzipper.WZ_AES, nbits=256)
//!
//! Payload is the text `interop check payload` (7-Zip adds a UTF-8 BOM and CRLF).

const SEVEN_ZIP_ZIPCRYPTO: &[u8] = &[
    80, 75, 3, 4, 20, 0, 1, 0, 0, 0, 77, 99, 84, 93, 143, 98, 87, 249, 38, 0, 0, 0, 26, 0, 0, 0,
    11, 0, 0, 0, 112, 97, 121, 108, 111, 97, 100, 46, 116, 120, 116, 105, 185, 195, 208, 73, 213,
    132, 215, 1, 199, 158, 160, 115, 176, 13, 89, 5, 175, 255, 137, 161, 208, 37, 219, 200, 83,
    140, 100, 228, 67, 79, 125, 221, 207, 184, 178, 231, 103, 80, 75, 1, 2, 63, 0, 20, 0, 1, 0, 0,
    0, 77, 99, 84, 93, 143, 98, 87, 249, 38, 0, 0, 0, 26, 0, 0, 0, 11, 0, 36, 0, 0, 0, 0, 0, 0, 0,
    32, 32, 0, 0, 0, 0, 0, 0, 112, 97, 121, 108, 111, 97, 100, 46, 116, 120, 116, 10, 0, 32, 0, 0,
    0, 0, 0, 1, 0, 24, 0, 196, 218, 77, 201, 66, 96, 221, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0, 93, 0, 0, 0, 79, 0, 0, 0, 0, 0,
];

const SEVEN_ZIP_AES256: &[u8] = &[
    80, 75, 3, 4, 51, 0, 1, 0, 99, 0, 77, 99, 84, 93, 0, 0, 0, 0, 54, 0, 0, 0, 26, 0, 0, 0, 11, 0,
    11, 0, 112, 97, 121, 108, 111, 97, 100, 46, 116, 120, 116, 1, 153, 7, 0, 2, 0, 65, 69, 3, 0, 0,
    123, 117, 123, 24, 190, 117, 127, 137, 211, 107, 46, 87, 239, 85, 35, 234, 94, 0, 240, 239, 82,
    219, 252, 131, 110, 55, 185, 44, 209, 59, 67, 208, 141, 166, 218, 133, 94, 80, 72, 129, 25,
    192, 26, 247, 155, 39, 39, 115, 136, 247, 170, 38, 64, 253, 80, 75, 1, 2, 63, 0, 51, 0, 1, 0,
    99, 0, 77, 99, 84, 93, 0, 0, 0, 0, 54, 0, 0, 0, 26, 0, 0, 0, 11, 0, 47, 0, 0, 0, 0, 0, 0, 0,
    32, 32, 0, 0, 0, 0, 0, 0, 112, 97, 121, 108, 111, 97, 100, 46, 116, 120, 116, 10, 0, 32, 0, 0,
    0, 0, 0, 1, 0, 24, 0, 196, 218, 77, 201, 66, 96, 221, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 153, 7, 0, 2, 0, 65, 69, 3, 0, 0, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0, 104, 0, 0,
    0, 106, 0, 0, 0, 0, 0,
];

const PYZIPPER_AES256: &[u8] = &[
    80, 75, 3, 4, 20, 0, 1, 0, 99, 0, 76, 99, 84, 93, 0, 0, 0, 0, 51, 0, 0, 0, 21, 0, 0, 0, 11, 0,
    11, 0, 112, 97, 121, 108, 111, 97, 100, 46, 116, 120, 116, 1, 153, 7, 0, 2, 0, 65, 69, 3, 8, 0,
    71, 215, 136, 189, 217, 124, 39, 56, 123, 83, 130, 93, 119, 45, 168, 175, 242, 92, 109, 17, 62,
    197, 121, 190, 190, 32, 7, 24, 203, 160, 205, 18, 175, 128, 181, 172, 29, 151, 124, 34, 98,
    170, 186, 219, 216, 243, 240, 131, 16, 5, 142, 80, 75, 1, 2, 20, 0, 20, 0, 1, 0, 99, 0, 76, 99,
    84, 93, 0, 0, 0, 0, 51, 0, 0, 0, 21, 0, 0, 0, 11, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0,
    0, 0, 0, 112, 97, 121, 108, 111, 97, 100, 46, 116, 120, 116, 1, 153, 7, 0, 2, 0, 65, 69, 3, 8,
    0, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0, 68, 0, 0, 0, 103, 0, 0, 0, 0, 0,
];

// ---------------------------------------------------------------------------------------
// Reading archives produced by other implementations
// ---------------------------------------------------------------------------------------

use std::io::Cursor;
use zipcore::{Archive, ReadOptions};

// AES interop requires the codec. Without `aes-crypto` the crate reports the entry as needing the
// feature, which is what `aes_entries_need_the_feature` below exercises.
fn read_foreign(bytes: &[u8]) -> String {
    let mut archive = Archive::new_with_options(
        Cursor::new(bytes.to_vec()),
        ReadOptions::default().with_password("pw123"),
    )
    .expect("the archive must parse");
    let data = archive.read_entry(0).expect("the entry must decrypt");
    String::from_utf8_lossy(&data)
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string()
}

#[test]
fn reads_a_7zip_zipcrypto_archive() {
    // 7-Zip writes the plaintext after a BOM and with CRLF line endings.
    assert_eq!(read_foreign(SEVEN_ZIP_ZIPCRYPTO), "interop check payload");
}

#[cfg(feature = "aes-crypto")]
#[test]
fn reads_a_7zip_aes256_archive() {
    assert_eq!(read_foreign(SEVEN_ZIP_AES256), "interop check payload");
}

#[cfg(feature = "aes-crypto")]
#[test]
fn reads_a_pyzipper_aes256_archive() {
    assert_eq!(read_foreign(PYZIPPER_AES256), "interop check payload");
}

#[test]
fn a_foreign_archive_needs_the_right_password() {
    let mut archive = Archive::new_with_options(
        Cursor::new(PYZIPPER_AES256.to_vec()),
        ReadOptions::default().with_password("wrong"),
    )
    .expect("parsing succeeds; only decryption fails");
    assert!(archive.read_entry(0).is_err());
}

#[cfg(feature = "aes-crypto")]
#[test]
fn an_ae2_entry_with_a_zero_crc_is_not_rejected() {
    // AE-2 stores CRC-32 = 0 on purpose. Treating that as a mismatch would reject every
    // WinZip AES archive in the wild, so the check is skipped for these entries.
    let mut archive = Archive::new_with_options(
        Cursor::new(SEVEN_ZIP_AES256.to_vec()),
        ReadOptions {
            verify_crc: true,
            ..ReadOptions::default().with_password("pw123")
        },
    )
    .unwrap();
    assert!(archive.entries()[0].crc32() == 0, "AE-2 writes a zero CRC");
    assert!(archive.read_entry(0).is_ok());
}

/// Without the feature, an AES entry must be refused with a message naming what to enable rather
/// than silently returning ciphertext or a confusing CRC error.
#[cfg(not(feature = "aes-crypto"))]
#[test]
fn aes_entries_need_the_feature() {
    let mut archive = Archive::new_with_options(
        Cursor::new(SEVEN_ZIP_AES256.to_vec()),
        ReadOptions::default().with_password("pw123"),
    )
    .expect("the archive still parses without the codec");
    let error = archive.read_entry(0).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("99") || message.contains("aes"),
        "the error should identify the unsupported method: {message}"
    );
}
