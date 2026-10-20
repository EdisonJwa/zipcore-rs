//! Entry-name sanitisation.
//!
//! This is the defence against the classic "zip slip" attack, where an archive contains an
//! entry such as `../../../../etc/cron.d/evil` or `C:\Windows\System32\evil.dll`. The library
//! never joins an entry name onto a path without running it through here first.

use std::path::PathBuf;

/// Windows device names that alias to a device regardless of extension.
const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

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
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
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
