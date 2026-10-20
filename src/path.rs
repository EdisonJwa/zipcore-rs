//! Entry-name sanitisation.
//!
//! This is the defence against the classic "zip slip" attack, where an archive contains an
//! entry such as `../../../../etc/cron.d/evil` or `C:\Windows\System32\evil.dll`. The library
//! never joins an entry name onto a path without running it through here first.

use std::path::PathBuf;

/// Windows device names that alias to a device regardless of extension.
///
/// `CON`, `PRN`, `AUX` and `NUL` are the classic four, and `CONIN$`/`CONOUT$` are the console
/// handles. `COM1`-`COM9` and `LPT1`-`LPT9` are the numbered ports; `COM0` and `LPT0` are also
/// reserved by Win32 even though they are rarely usable. The trailing `$` and the numbered forms
/// are matched without it, so a name like `CONIN$` cannot slip through as "not a device".
const RESERVED_STEMS: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
/// Console/clock handles that are devices only *with* their trailing `$`.
const RESERVED_DOLLAR: [&str; 3] = ["CONIN", "CONOUT", "CLOCK"];
const RESERVED_PORTS: [&str; 2] = ["COM", "LPT"];

/// Whether a filename stem names a Windows device.
///
/// DOS reserved `COM1`-`COM9` and `LPT1`-`LPT9`. Win32 additionally treats `COM0`, `LPT0`, the
/// superscript digits `¹²³` and a trailing `$` as part of the same namespace, which is how
/// `CONIN$` and `com¹` reach a device. Rejecting a slightly wider set than strictly necessary is
/// the safe direction here: the cost is refusing an exotic but harmless name.
fn is_windows_device_name(stem: &str) -> bool {
    // `$` only matters for the console handles: `CONIN$` is a device, `CONIN` is a file.
    let (core, had_dollar) = match stem.strip_suffix('$') {
        Some(rest) => (rest, true),
        None => (stem, false),
    };

    // Superscript digits map to the same device numbers as their ASCII forms.
    let normalized: String = core
        .chars()
        .map(|c| match c {
            '\u{00b9}' => '1',
            '\u{00b2}' => '2',
            '\u{00b3}' => '3',
            other => other.to_ascii_uppercase(),
        })
        .collect();

    // `.` and whitespace are stripped before this point by the caller, so compare directly.
    if RESERVED_STEMS
        .iter()
        .any(|reserved| normalized == *reserved)
    {
        return true;
    }

    // `CONIN$`, `CONOUT$` and `CLOCK$` are devices; the same names without `$` are ordinary files.
    if had_dollar
        && RESERVED_DOLLAR
            .iter()
            .any(|reserved| normalized == *reserved)
    {
        return true;
    }

    // Port names: a prefix from the list followed by exactly one digit.
    RESERVED_PORTS.iter().any(|prefix| {
        normalized
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.len() == 1 && rest.as_bytes()[0].is_ascii_digit())
    })
}

/// Strip the trailing dots and spaces that Win32 silently ignores.
///
/// `"nul "`, `"con."` and `"trail. "` all resolve to something other than a file with that name:
/// the first two are device aliases and the third collides with `trail`. The check has to see the
/// name the filesystem will use, not the bytes in the archive.
fn win32_trim(part: &str) -> &str {
    part.trim_end_matches(['.', ' '])
}

/// Convert an entry name into a relative path that is safe to join onto a destination
/// directory, or explain why it is not.
pub(crate) fn safe_relative_path(name: &str) -> Result<PathBuf, &'static str> {
    if name.is_empty() {
        return Err("empty name");
    }
    if name.contains('\0') {
        return Err("contains a NUL byte");
    }
    // Control characters other than tab/newline are never meaningful in a filename and are a
    // common way to smuggle a name past a human reviewing a listing.
    if name
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n')
    {
        return Err("contains a control character");
    }

    // Both separators are treated as separators: Windows accepts `\`, and hostile archives
    // rely on the other platform's reader not normalising it.
    let normalized = name.replace('\\', "/");

    if normalized.starts_with('/') {
        return Err("absolute path");
    }
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err("drive-qualified path");
    }

    let mut out = PathBuf::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err("parent traversal");
        }
        // `name:stream` is a Windows alternate data stream.
        if part.contains(':') {
            return Err("contains an alternate data stream separator");
        }
        // Judge the name Win32 will actually use, then reject if that is empty or dot-only:
        // `".. "` trims to `".."` and would otherwise walk upwards.
        let trimmed = win32_trim(part);
        if trimmed.is_empty() {
            return Err("name component is empty after ignoring trailing dots and spaces");
        }
        if trimmed == "." || trimmed == ".." {
            return Err("parent traversal");
        }
        // `trail.` and `trail ` resolve to the same file as `trail`, so a name that is not
        // already in its Win32-normalised form could silently overwrite a different entry.
        if trimmed.len() != part.len() {
            return Err("trailing dot or space would be ignored by Windows");
        }
        let stem = match trimmed.find('.') {
            Some(i) => &trimmed[..i],
            None => trimmed,
        };
        if is_windows_device_name(stem) {
            return Err("reserved device name");
        }
        out.push(part);
    }

    if out.as_os_str().is_empty() {
        return Err("empty name");
    }
    Ok(out)
}

/// Validate a name that is about to be *written* into an archive.
///
/// Deliberately narrower than [`safe_relative_path`]: it rejects the shapes that make an
/// archive dangerous for somebody else to extract — absolute paths, drive-qualified paths,
/// `..` traversal and NUL bytes — while still permitting names that are merely unusual on one
/// platform, such as a colon or a device name on Unix, which are legal filenames there.
pub(crate) fn safe_archive_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty name");
    }
    if name.contains('\0') {
        return Err("contains a NUL byte");
    }
    if name
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n')
    {
        return Err("contains a control character");
    }

    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err("absolute path");
    }
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err("drive-qualified path");
    }
    for part in normalized.split('/') {
        if part == ".." {
            return Err("parent traversal");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_relative_names() {
        assert_eq!(
            safe_relative_path("xl/worksheets/sheet1.xml").unwrap(),
            PathBuf::from("xl/worksheets/sheet1.xml")
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        assert!(safe_relative_path("../../etc/passwd").is_err());
        assert!(safe_relative_path("a/../../b").is_err());
    }

    #[test]
    fn rejects_backslash_traversal() {
        assert!(safe_relative_path(r"..\..\windows\system32").is_err());
    }

    #[test]
    fn rejects_absolute_names() {
        assert!(safe_relative_path("/etc/passwd").is_err());
        assert!(safe_relative_path(r"\windows\system32").is_err());
    }

    #[test]
    fn rejects_drive_qualified_and_ads_names() {
        assert!(safe_relative_path(r"C:\evil.dll").is_err());
        assert!(safe_relative_path("file.txt:stream").is_err());
    }

    #[test]
    fn rejects_reserved_device_names() {
        assert!(safe_relative_path("NUL").is_err());
        assert!(safe_relative_path("con.txt").is_err());
        assert!(safe_relative_path("console.txt").is_ok());
    }
}

#[cfg(test)]
mod device_name_tests {
    use super::*;

    /// Every spelling Win32 may resolve to a device must be refused.
    #[test]
    fn windows_device_spellings_are_all_rejected() {
        for name in [
            "CON",
            "con",
            "Con",
            "CON.txt",
            "con.tar.gz",
            "PRN",
            "AUX",
            "NUL",
            "nul.log",
            "COM1",
            "com9",
            "COM0",
            "LPT1",
            "lpt0",
            // `$`-suffixed console handles
            "CONIN$",
            "CONOUT$",
            "CLOCK$",
            "conin$",
            // superscript device digits
            "com\u{00b9}",
            "com\u{00b2}",
            "lpt\u{00b3}",
            // inside a directory
            "dir/NUL.txt",
        ] {
            assert!(
                safe_relative_path(name).is_err(),
                "{name:?} should be refused as a device name"
            );
        }
    }

    /// Ordinary names that merely start like a device must still work.
    #[test]
    fn similar_but_ordinary_names_are_allowed() {
        for name in [
            "console.log",
            "content.txt",
            "null.txt",
            "print.pdf",
            "COM10", // two digits: not the reserved namespace
            "common/x",
            "auxiliary.rs",
            "clock.rs",
            "nulify",
        ] {
            assert!(
                safe_relative_path(name).is_ok(),
                "{name:?} is an ordinary name and should be accepted"
            );
        }
    }
}
