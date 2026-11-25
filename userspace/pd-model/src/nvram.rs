//! The vendor's RAM configuration cache (`/tmp/nvram.cfg`): `key=value`
//! records, each ending in a NUL byte (a newline is accepted too). The first
//! record for a key wins.

/// The value bytes of the first `key=` record.
pub fn raw<'a>(cache: &'a [u8], key: &str) -> Option<&'a [u8]> {
    cache
        .split(|byte| *byte == 0 || *byte == b'\n')
        .find_map(|record| record.strip_prefix(key.as_bytes())?.strip_prefix(b"="))
}

/// The value, when it is UTF-8. Not trimmed.
pub fn field<'a>(cache: &'a [u8], key: &str) -> Option<&'a str> {
    raw(cache, key).and_then(|value| std::str::from_utf8(value).ok())
}

/// The value as trimmed text with any invalid UTF-8 replaced, or empty when
/// the key is missing.
pub fn text(cache: &[u8], key: &str) -> String {
    raw(cache, key)
        .map(|value| String::from_utf8_lossy(value).trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_record_for_a_key_wins_and_a_longer_key_is_not_it() {
        let cache = b"detection_enable=1\0detection_interval=3\0detection_enable=0\0";
        assert_eq!(field(cache, "detection_enable"), Some("1"));
        assert_eq!(field(cache, "detection_interval"), Some("3"));
        assert_eq!(field(b"a=1\nb=2\n", "b"), Some("2"));
        assert_eq!(field(b"detection_enable_x=0\0", "detection_enable"), None);
        assert_eq!(field(b"", "detection_enable"), None);
    }

    #[test]
    fn text_is_trimmed_and_lossy_and_field_is_neither() {
        let cache = b"band= 48 \0name=caf\xe9\0";
        assert_eq!(field(cache, "band"), Some(" 48 "));
        assert_eq!(text(cache, "band"), "48");
        assert_eq!(field(cache, "name"), None);
        assert_eq!(text(cache, "name"), "caf\u{fffd}");
        assert_eq!(text(cache, "missing"), "");
        assert_eq!(raw(cache, "name"), Some(&b"caf\xe9"[..]));
    }
}
