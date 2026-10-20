//! MS-DOS date/time encoding, as used in ZIP headers.
//!
//! DOS timestamps have two-second resolution and cannot represent anything before 1980 or
//! after 2107. There is no timezone database available without adding a dependency, so
//! timestamps are derived from UTC.

use std::time::{SystemTime, UNIX_EPOCH};

/// First year representable in a DOS timestamp.
pub(crate) const MIN_YEAR: i64 = 1980;
/// Last year representable in a DOS timestamp.
pub(crate) const MAX_YEAR: i64 = 2107;

/// The current time as `(DOS date, DOS time)`, in UTC.
pub(crate) fn now() -> (u16, u16) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => from_unix_seconds(elapsed.as_secs()),
        // Only reachable if the clock is set before the Unix epoch.
        Err(_) => from_unix_seconds(0),
    }
}

/// The current time as seconds since the Unix epoch, or 0 if the clock is set before it.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Convert a Unix timestamp in seconds (UTC) to `(DOS date, DOS time)`.
pub(crate) fn from_unix_seconds(seconds: u64) -> (u16, u16) {
    let days = (seconds / 86_400) as i64;
    let second_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);

    let year = year.clamp(MIN_YEAR, MAX_YEAR) as u16;
    let hour = (second_of_day / 3600) as u16;
    let minute = ((second_of_day % 3600) / 60) as u16;
    let second = (second_of_day % 60) as u16;

    // date: bits 0-4 day, 5-8 month, 9-15 years since 1980.
    let date = ((year - MIN_YEAR as u16) << 9) | (month as u16) << 5 | day as u16;
    // time: bits 0-4 seconds/2, 5-10 minutes, 11-15 hours.
    let time = (hour << 11) | (minute << 5) | (second / 2);
    (date, time)
}

/// Days since 1970-01-01 to a civil `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, which is exact for the whole `i64` range we care about.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (y + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_clamps_to_the_first_representable_year() {
        // 1970-01-01 cannot be represented, so it clamps to 1980-01-01 with a zero time:
        // ((1980 - 1980) << 9) | (1 << 5) | 1 == 0x0021.
        assert_eq!(from_unix_seconds(0), (0x0021, 0));
    }

    #[test]
    fn leap_day_is_encoded_correctly() {
        // 2024-02-29 is 19782 days after the epoch.
        let (date, time) = from_unix_seconds(19_782 * 86_400);
        assert_eq!(time, 0);
        assert_eq!(date, ((2024 - 1980) << 9) | (2 << 5) | 29);
    }

    #[test]
    fn time_of_day_is_encoded_correctly() {
        // 1980-01-01 at 12:34:56 -> seconds are halved by DOS encoding.
        let seconds = 12 * 3600 + 34 * 60 + 56;
        let (_, time) = from_unix_seconds(seconds);
        assert_eq!(time, (12 << 11) | (34 << 5) | (56 / 2));
    }

    #[test]
    fn civil_dates_match_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn now_is_within_the_representable_range() {
        let (date, _) = now();
        let year = (date >> 9) + 1980;
        assert!((MIN_YEAR as u16..=MAX_YEAR as u16).contains(&year));
    }
}
