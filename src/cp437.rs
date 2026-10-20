//! Decoding of entry names in the legacy IBM code page 437.
//!
//! The ZIP format only guarantees ASCII in filenames. Names containing bytes >= 0x80 are
//! CP437 unless general-purpose flag bit 11 says they are UTF-8. Decoding as CP437 is worth
//! the table: it is what other tools show, so names match across implementations instead of
//! turning into replacement characters.

/// CP437 code points for bytes `0x80..=0xFF`.
///
/// Declared as a fixed-size array so the compiler rejects the file outright if the table is
/// not exactly 128 entries.
const HIGH: [char; 128] = [
    '\u{00C7}', '\u{00FC}', '\u{00E9}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E5}', '\u{00E7}',
    '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00EF}', '\u{00EE}', '\u{00EC}', '\u{00C4}', '\u{00C5}',
    '\u{00C9}', '\u{00E6}', '\u{00C6}', '\u{00F4}', '\u{00F6}', '\u{00F2}', '\u{00FB}', '\u{00F9}',
    '\u{00FF}', '\u{00D6}', '\u{00DC}', '\u{00A2}', '\u{00A3}', '\u{00A5}', '\u{20A7}', '\u{0192}',
    '\u{00E1}', '\u{00ED}', '\u{00F3}', '\u{00FA}', '\u{00F1}', '\u{00D1}', '\u{00AA}', '\u{00BA}',
    '\u{00BF}', '\u{2310}', '\u{00AC}', '\u{00BD}', '\u{00BC}', '\u{00A1}', '\u{00AB}', '\u{00BB}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{255C}', '\u{255B}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}', '\u{255E}', '\u{255F}',
    '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256C}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256B}',
    '\u{256A}', '\u{2518}', '\u{250C}', '\u{2588}', '\u{2584}', '\u{258C}', '\u{2590}', '\u{2580}',
    '\u{03B1}', '\u{00DF}', '\u{0393}', '\u{03C0}', '\u{03A3}', '\u{03C3}', '\u{00B5}', '\u{03C4}',
    '\u{03A6}', '\u{0398}', '\u{03A9}', '\u{03B4}', '\u{221E}', '\u{03C6}', '\u{03B5}', '\u{2229}',
    '\u{2261}', '\u{00B1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00F7}', '\u{2248}',
    '\u{00B0}', '\u{2219}', '\u{00B7}', '\u{221A}', '\u{207F}', '\u{00B2}', '\u{25A0}', '\u{00A0}',
];

pub(crate) fn decode_cp437(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                HIGH[(b - 0x80) as usize]
            }
        })
        .collect()
}

/// Decode an entry name.
///
/// `utf8_flagged` comes from general-purpose flag bit 11. A UTF-8-flagged name that is not
/// valid UTF-8 falls back to CP437 rather than lossy decoding, because a lossy decode can
/// silently turn two distinct entries into the same string.
pub(crate) fn decode_name(bytes: &[u8], utf8_flagged: bool) -> String {
    if utf8_flagged {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return s.to_string();
        }
    } else if bytes.is_ascii() {
        return bytes.iter().map(|&b| b as char).collect();
    } else if let Ok(s) = std::str::from_utf8(bytes) {
        // Not flagged, but valid UTF-8. Real-world writers omit the flag often enough that
        // honouring valid UTF-8 here matches what other tools display.
        return s.to_string();
    }
    decode_cp437(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_table_has_exactly_128_entries() {
        assert_eq!(HIGH.len(), 128);
    }

    #[test]
    fn ascii_passes_through() {
        assert_eq!(decode_cp437(b"readme.txt"), "readme.txt");
    }

    #[test]
    fn cp437_high_bytes_map_to_glyphs() {
        // 0x83 = 'â', 0x9B = '¢' in CP437.
        assert_eq!(decode_cp437(&[0x83, 0x9B]), "\u{00E2}\u{00A2}");
    }

    #[test]
    fn utf8_flag_is_honoured() {
        assert_eq!(decode_name("caf\u{e9}".as_bytes(), true), "caf\u{e9}");
    }

    #[test]
    fn invalid_utf8_flagged_name_falls_back_to_cp437() {
        assert_eq!(decode_name(&[0x83], true), "\u{00E2}");
    }
}
