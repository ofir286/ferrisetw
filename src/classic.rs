//! Support for classic (EventlogClassic) ETW events.
//!
//! # Background
//!
//! Providers that advertise the `win:EventlogClassic` keyword (`0x0080000000000000`)
//! write events using the legacy [`ReportEvent()`] Win32 API. When these events are
//! delivered through ETW, they arrive with `EventDescriptor.Id == 0` and a custom
//! binary layout inside `UserData` — **not** the standard TDH-compatible property
//! layout used by manifest-based or TraceLogging providers.
//!
//! Because the raw `event_id` in the ETW header is always 0, kernel-level filtering
//! via `EventFilter::ByEventIds` will **not** match the real event ID. The real ID
//! (e.g. 7045 for "a service was installed") is embedded inside the binary payload.
//!
//! [`ReportEvent()`]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw
//!
//! # Binary payload format
//!
//! The `UserData` of a classic event contains the following fields, serialized
//! sequentially in little-endian byte order:
//!
//! | Offset   | Size              | Field                              |
//! |----------|-------------------|------------------------------------|
//! | 0        | 8 bytes           | `FILETIME` — time the event was created |
//! | 8        | 2 bytes           | `u16` — real Event ID (e.g. 7045)  |
//! | 10       | 2 bytes           | `u16` — qualifier (e.g. `0x4000`)  |
//! | 12       | 2 bytes           | `u16` — source name length in WCHARs (including null) |
//! | 14       | variable          | UTF-16LE null-terminated source name |
//! | ?        | 2 bytes           | `u16` — SID length in bytes         |
//! | ?        | variable          | raw SID bytes                       |
//! | ?        | 2 bytes           | `u16` — number of replacement strings |
//! | ?        | variable          | *N* null-terminated UTF-16LE strings (event data) |
//!
//! The structure is related to—but not identical to—the on-disk
//! [`EVENTLOGRECORD`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-eventlogrecord).
//! It omits the outer record header/footer and several fixed fields that are already
//! carried in the ETW `EVENT_HEADER`.
//!
//! # How this module works
//!
//! 1. **Detection** — When a provider is added to a trace, `ferrisetw` queries TDH
//!    for the provider's keyword definitions. If the provider advertises
//!    `win:EventlogClassic`, all its events are routed through the classic parsing path.
//!
//! 2. **Parsing** — [`parse_classic_user_data`] extracts the fixed header fields and
//!    the replacement strings from the raw `UserData`.
//!
//! 3. **TDH resolution** — The real event ID is used to query TDH for the event's
//!    schema (`TRACE_EVENT_INFO`), which provides the property names, channel name,
//!    and event message template.
//!
//! 4. **Re-encoding** — The replacement strings are re-encoded into a synthetic
//!    null-terminated UTF-16LE buffer by [`encode_strings_as_user_data`], so that
//!    the existing [`Parser`](crate::parser::Parser) can process them transparently.
//!
//! 5. **Metadata** — Classic-specific fields (SID, source name, channel, etc.) that
//!    are not part of the TDH property list are stored in [`ClassicMetadata`] and
//!    accessible via [`Schema::classic_metadata()`](crate::schema::Schema::classic_metadata).
//!    They can optionally be serialized by enabling
//!    [`EventSerializerOptions::include_classic_event_data`](crate::ser::EventSerializerOptions::include_classic_event_data).
//!
//! # Limitations
//!
//! * Classic events cannot be filtered by real event ID at the kernel level. Use
//!   [`Schema::event_id()`](crate::schema::Schema::event_id) in your callback to
//!   filter by real event ID after parsing.
//! * Metadata fields (SID, source name, time created) are not available through
//!   `Parser::try_parse()`. Use `Schema::classic_metadata()` instead.
//! * If the binary payload is malformed, parsing fails gracefully and falls back to
//!   normal TDH-based schema resolution (which will typically fail with "Element not
//!   found" for event ID 0).

use crate::native::sddl;

/// The `win:EventlogClassic` keyword value.
///
/// When this keyword bit is set in an event's `Keyword` field, the event uses the
/// classic Event Log binary format in its `UserData` buffer.
pub const EVENTLOG_CLASSIC_KEYWORD: u64 = 0x0080000000000000;

/// Metadata extracted from a classic (EventlogClassic) ETW event's binary payload and TDH.
///
/// Access this via [`Schema::classic_metadata()`](crate::schema::Schema::classic_metadata)
/// when the schema was resolved for a classic event.
#[derive(Debug, Clone)]
pub struct ClassicMetadata {
    /// FILETIME from the first 8 bytes of the binary payload.
    pub time_created: i64,
    /// The real event ID extracted from the payload (e.g. 7045).
    pub real_event_id: u16,
    /// Event qualifier (e.g. 0x4000 = 16384).
    pub qualifier: u16,
    /// Event source name (e.g. "Service Control Manager").
    pub source_name: String,
    /// SID as an SDDL string (e.g. "S-1-5-21-...").
    pub sid_string: String,
    /// Raw SID bytes.
    pub raw_sid: Vec<u8>,
    /// Channel name from TDH (e.g. "System").
    pub channel: String,
    /// Event message template from TDH.
    pub event_message: String,
}

#[cfg(feature = "serde")]
impl serde::Serialize for ClassicMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ClassicMetadata", 8)?;
        state.serialize_field("time_created", &self.time_created)?;
        state.serialize_field("real_event_id", &self.real_event_id)?;
        state.serialize_field("qualifier", &self.qualifier)?;
        state.serialize_field("source_name", &self.source_name)?;
        state.serialize_field("sid_string", &self.sid_string)?;
        let raw_sid_hex: String = self.raw_sid.iter().map(|b| format!("{:02x}", b)).collect();
        state.serialize_field("raw_sid", &raw_sid_hex)?;
        state.serialize_field("channel", &self.channel)?;
        state.serialize_field("event_message", &self.event_message)?;
        state.end()
    }
}

/// Errors that can occur when parsing a classic event's binary payload.
#[derive(Debug)]
pub enum ClassicParseError {
    /// The UserData buffer is too short to contain the expected fields.
    DataTooShort(String),
    /// A field value is invalid or inconsistent.
    InvalidField(String),
    /// TDH resolution for the real event ID failed.
    TdhResolutionFailed(crate::native::tdh::TdhNativeError),
    /// SID conversion to SDDL string failed.
    SddlError(crate::native::sddl::SddlNativeError),
}

impl std::fmt::Display for ClassicParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataTooShort(s) => write!(f, "data too short: {}", s),
            Self::InvalidField(s) => write!(f, "invalid field: {}", s),
            Self::TdhResolutionFailed(e) => write!(f, "TDH resolution failed: {}", e),
            Self::SddlError(e) => write!(f, "SDDL error: {}", e),
        }
    }
}

impl From<crate::native::tdh::TdhNativeError> for ClassicParseError {
    fn from(err: crate::native::tdh::TdhNativeError) -> Self {
        ClassicParseError::TdhResolutionFailed(err)
    }
}

impl From<crate::native::sddl::SddlNativeError> for ClassicParseError {
    fn from(err: crate::native::sddl::SddlNativeError) -> Self {
        ClassicParseError::SddlError(err)
    }
}

/// Intermediate parse result from the binary payload (before TDH resolution).
#[derive(Debug)]
pub(crate) struct RawClassicRecord {
    pub time_created: i64,
    pub real_event_id: u16,
    pub qualifier: u16,
    pub source_name: String,
    pub sid_bytes: Vec<u8>,
    pub strings: Vec<String>,
}

/// Read a little-endian `u16` from `data` at `*offset`.
/// Advances `*offset` by 2 bytes.
fn read_u16_le(data: &[u8], offset: &mut usize) -> Result<u16, ClassicParseError> {
    if *offset + 2 > data.len() {
        return Err(ClassicParseError::DataTooShort(format!(
            "need u16 at offset {}, have {} bytes remaining",
            *offset,
            data.len() - *offset
        )));
    }
    let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Ok(val)
}

/// Read a little-endian `i64` from `data` at `*offset`.
/// Advances `*offset` by 8 bytes.
fn read_i64_le(data: &[u8], offset: &mut usize) -> Result<i64, ClassicParseError> {
    if *offset + 8 > data.len() {
        return Err(ClassicParseError::DataTooShort(format!(
            "need i64 at offset {}, have {} bytes remaining",
            *offset,
            data.len() - *offset
        )));
    }
    let val = i64::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;
    Ok(val)
}

/// Read a null-terminated UTF-16LE (wide) string from `data` starting at `*offset`.
/// Advances `*offset` past the consumed bytes (including the null terminator).
fn read_null_terminated_wstring(data: &[u8], offset: &mut usize) -> String {
    let mut wchars: Vec<u16> = Vec::new();
    while *offset + 1 < data.len() {
        let wchar = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
        *offset += 2;
        if wchar == 0 {
            break;
        }
        wchars.push(wchar);
    }
    String::from_utf16_lossy(&wchars)
}

/// Read a UTF-16LE wide-char string of known length (in WCHARs, **including** the null
/// terminator) from `data` at `*offset`. Advances `*offset` past all `wchar_count * 2` bytes.
fn read_wstring_by_len(
    data: &[u8],
    offset: &mut usize,
    wchar_count: usize,
) -> Result<String, ClassicParseError> {
    let byte_count = wchar_count * 2;
    if *offset + byte_count > data.len() {
        return Err(ClassicParseError::DataTooShort(format!(
            "need {} bytes for wstring at offset {}, have {}",
            byte_count,
            *offset,
            data.len() - *offset
        )));
    }
    let slice = &data[*offset..*offset + byte_count];
    *offset += byte_count;

    let wchars: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    // Strip trailing null(s)
    let trimmed = match wchars.iter().position(|&c| c == 0) {
        Some(pos) => &wchars[..pos],
        None => &wchars,
    };
    Ok(String::from_utf16_lossy(trimmed))
}

/// Parse the classic Event Log record from raw `UserData` bytes.
///
/// Binary layout:
/// ```text
/// Offset   Size         Field
/// ------   ----------   ----------------------------------------
/// 0        8 bytes      FILETIME         TimeCreated
/// 8        2 bytes      u16              Real EventID  (e.g. 7045)
/// 10       2 bytes      u16              Qualifier     (e.g. 0x4000)
/// 12       2 bytes      u16              SourceName length (WCHARs incl. null)
/// 14       variable     wchar[]          SourceName    ("Service Control Manager\0")
/// ?        2 bytes      u16              SID length    (bytes)
/// ?        variable     bytes            SID
/// ?        2 bytes      u16              NumStrings
/// ?        variable     wchar[]...       N null-terminated wstrings (EventData)
/// ```
pub(crate) fn parse_classic_user_data(data: &[u8]) -> Result<RawClassicRecord, ClassicParseError> {
    let mut offset = 0;

    // --- FILETIME (8 bytes) ---
    let time_created = read_i64_le(data, &mut offset)?;

    // --- Real EventID (u16) ---
    let real_event_id = read_u16_le(data, &mut offset)?;

    // --- Qualifier (u16) ---
    let qualifier = read_u16_le(data, &mut offset)?;

    // --- SourceName length in WCHARs (including null terminator) ---
    let source_name_wchar_count = read_u16_le(data, &mut offset)? as usize;
    if source_name_wchar_count == 0 {
        return Err(ClassicParseError::InvalidField(
            "SourceName wchar count is zero".to_string(),
        ));
    }

    // --- SourceName wstring ---
    let source_name = read_wstring_by_len(data, &mut offset, source_name_wchar_count)?;

    // --- SID length in bytes ---
    let sid_byte_len = read_u16_le(data, &mut offset)? as usize;

    // --- SID bytes ---
    if offset + sid_byte_len > data.len() {
        return Err(ClassicParseError::DataTooShort(format!(
            "not enough data for SID at offset {}: need {}, have {}",
            offset,
            sid_byte_len,
            data.len() - offset
        )));
    }
    let sid_bytes = data[offset..offset + sid_byte_len].to_vec();
    offset += sid_byte_len;

    // --- NumStrings (u16) ---
    let num_strings = read_u16_le(data, &mut offset)? as usize;

    // --- N null-terminated wstrings ---
    let mut strings = Vec::with_capacity(num_strings);
    for i in 0..num_strings {
        if offset >= data.len() {
            return Err(ClassicParseError::DataTooShort(format!(
                "ran out of data reading string {} of {} at offset {}",
                i + 1,
                num_strings,
                offset
            )));
        }
        strings.push(read_null_terminated_wstring(data, &mut offset));
    }

    Ok(RawClassicRecord {
        time_created,
        real_event_id,
        qualifier,
        source_name,
        sid_bytes,
        strings,
    })
}

/// Re-encode a list of strings as null-terminated UTF-16LE bytes, matching the
/// TDH property layout for `InTypeUnicodeString` properties.
///
/// The resulting buffer can be fed to `Parser` as a synthetic `user_buffer` so that
/// the existing null-terminator-scanning logic in `find_property_size()` works unchanged.
pub(crate) fn encode_strings_as_user_data(strings: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for s in strings {
        for wchar in s.encode_utf16() {
            buf.extend_from_slice(&wchar.to_le_bytes());
        }
        // null terminator (two zero bytes for UTF-16LE)
        buf.extend_from_slice(&[0, 0]);
    }
    buf
}

/// Convert raw SID bytes to an SDDL string, or return a hex-encoded fallback.
pub(crate) fn sid_to_string(sid_bytes: &[u8]) -> String {
    if sid_bytes.is_empty() {
        return String::new();
    }
    match sddl::convert_sid_to_string(sid_bytes.as_ptr() as *const _) {
        Ok(s) => s,
        Err(_) => {
            // Fallback: hex-encode the raw SID bytes
            let mut hex = String::with_capacity(sid_bytes.len() * 2);
            for b in sid_bytes {
                hex.push_str(&format!("{:02x}", b));
            }
            hex
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal classic event payload from parts.
    ///
    /// Layout matches the binary format documented in [`parse_classic_user_data`].
    fn build_classic_payload(
        time_created: i64,
        real_event_id: u16,
        qualifier: u16,
        source_name: &str,
        sid_bytes: &[u8],
        strings: &[&str],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // FILETIME (8 bytes LE)
        buf.extend_from_slice(&time_created.to_le_bytes());
        // Real event ID
        buf.extend_from_slice(&real_event_id.to_le_bytes());
        // Qualifier
        buf.extend_from_slice(&qualifier.to_le_bytes());

        // Source name: encode to UTF-16LE with null terminator
        let source_wchars: Vec<u16> =
            source_name.encode_utf16().chain(std::iter::once(0)).collect();
        buf.extend_from_slice(&(source_wchars.len() as u16).to_le_bytes());
        for wchar in &source_wchars {
            buf.extend_from_slice(&wchar.to_le_bytes());
        }

        // SID length + bytes
        buf.extend_from_slice(&(sid_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(sid_bytes);

        // Num strings
        buf.extend_from_slice(&(strings.len() as u16).to_le_bytes());
        for s in strings {
            for wchar in s.encode_utf16() {
                buf.extend_from_slice(&wchar.to_le_bytes());
            }
            buf.extend_from_slice(&[0u8, 0]); // null terminator
        }

        buf
    }

    /// Helper: convert hex string to bytes.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- parse_classic_user_data tests ----

    #[test]
    fn parse_basic_event() {
        let time: i64 = 132_456_789_012_345_678;
        let event_id: u16 = 7045;
        let qualifier: u16 = 0x4000;
        let source = "Service Control Manager";
        let sid = &[1u8, 5, 0, 0, 0, 0, 0, 12, 1, 0, 0, 0, 0xDB, 0xA7, 0x5F, 0x40];
        let strings = &[
            "TestService",
            "C:\\test.exe",
            "user mode service",
            "demand start",
            "LocalSystem",
        ];

        let payload = build_classic_payload(time, event_id, qualifier, source, sid, strings);
        let result = parse_classic_user_data(&payload).expect("should parse successfully");

        assert_eq!(result.time_created, time);
        assert_eq!(result.real_event_id, event_id);
        assert_eq!(result.qualifier, qualifier);
        assert_eq!(result.source_name, source);
        assert_eq!(result.sid_bytes, sid);
        assert_eq!(result.strings.len(), 5);
        assert_eq!(result.strings[0], "TestService");
        assert_eq!(result.strings[1], "C:\\test.exe");
        assert_eq!(result.strings[2], "user mode service");
        assert_eq!(result.strings[3], "demand start");
        assert_eq!(result.strings[4], "LocalSystem");
    }

    #[test]
    fn parse_empty_sid() {
        let payload = build_classic_payload(0, 100, 0, "Src", &[], &["hello"]);
        let result = parse_classic_user_data(&payload).expect("should parse with empty SID");
        assert!(result.sid_bytes.is_empty());
        assert_eq!(result.strings, vec!["hello"]);
    }

    #[test]
    fn parse_no_strings() {
        let payload = build_classic_payload(0, 42, 0, "Provider", &[0xAA, 0xBB], &[]);
        let result = parse_classic_user_data(&payload).expect("should parse with no strings");
        assert_eq!(result.real_event_id, 42);
        assert!(result.strings.is_empty());
    }

    #[test]
    fn parse_unicode_source_name() {
        let payload = build_classic_payload(
            0,
            1,
            0,
            "\u{65E5}\u{672C}\u{8A9E}", // 日本語
            &[],
            &["\u{5024}1", "\u{5024}2"], // 値1, 値2
        );
        let result = parse_classic_user_data(&payload).expect("should parse Unicode source");
        assert_eq!(result.source_name, "\u{65E5}\u{672C}\u{8A9E}");
        assert_eq!(result.strings[0], "\u{5024}1");
        assert_eq!(result.strings[1], "\u{5024}2");
    }

    #[test]
    fn parse_truncated_header_fails() {
        let data = [0u8; 4]; // not enough for 8-byte FILETIME
        let result = parse_classic_user_data(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ClassicParseError::DataTooShort(_)));
    }

    #[test]
    fn parse_truncated_sid_fails() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0i64.to_le_bytes()); // time
        payload.extend_from_slice(&1u16.to_le_bytes()); // event id
        payload.extend_from_slice(&0u16.to_le_bytes()); // qualifier
        // source "A\0" => wchar count = 2
        payload.extend_from_slice(&2u16.to_le_bytes());
        for wchar in "A".encode_utf16() {
            payload.extend_from_slice(&wchar.to_le_bytes());
        }
        payload.extend_from_slice(&[0, 0]); // null terminator
        // SID length claims 100 bytes (more than remaining)
        payload.extend_from_slice(&100u16.to_le_bytes());

        let result = parse_classic_user_data(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn parse_zero_source_name_length_fails() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0i64.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes()); // source name wchar count = 0

        let result = parse_classic_user_data(&payload);
        assert!(result.is_err());
        match result.unwrap_err() {
            ClassicParseError::InvalidField(msg) => {
                assert!(msg.contains("SourceName wchar count is zero"), "msg: {}", msg);
            }
            other => panic!("Expected InvalidField, got {:?}", other),
        }
    }

    #[test]
    fn parse_real_captured_payload() {
        // Actual captured SCM event payload (event ID 7045, service installation).
        let hex = "1c6444c8c19ddc01851b004018005300650072007600690063006500\
                    200043006f006e00740072006f006c0020004d0061006e0061006700\
                    6500720000001c000105000000000\
                    00c01000000dba75f4052c41b468f6114ed4179a3f90500740065007\
                    3007400000043003a005c00500072006f006700720061006d0020004\
                    60069006c00650073005c0074006500730074002e006500780065000\
                    000750073006500720020006d006f006400650020007300650072007\
                    6006900630065000000640065006d0061006e006400200073007400\
                    61007200740000004c006f00630061006c00530079007300740065006\
                    d00000000000000";
        // Remove whitespace/newlines from hex string
        let hex_clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        let payload = hex_to_bytes(&hex_clean);

        let result = parse_classic_user_data(&payload).expect("should parse real payload");

        assert_eq!(result.real_event_id, 7045);
        assert_eq!(result.qualifier, 0x4000);
        assert_eq!(result.source_name, "Service Control Manager");
        assert_eq!(result.sid_bytes.len(), 28);
        assert_eq!(result.strings.len(), 5);
        assert_eq!(result.strings[0], "test");
        assert_eq!(result.strings[1], "C:\\Program Files\\test.exe");
        assert_eq!(result.strings[2], "user mode service");
        assert_eq!(result.strings[3], "demand start");
        assert_eq!(result.strings[4], "LocalSystem");
    }

    // ---- encode_strings_as_user_data tests ----

    #[test]
    fn encode_empty_list() {
        assert!(encode_strings_as_user_data(&[]).is_empty());
    }

    #[test]
    fn encode_single_string() {
        let result = encode_strings_as_user_data(&["hello".to_string()]);
        // "hello" = 5 WCHARs + 1 null = 12 bytes
        assert_eq!(result.len(), 12);

        let wchars: Vec<u16> = result
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(
            wchars,
            vec![b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0]
        );
    }

    #[test]
    fn encode_multiple_strings() {
        let strings = vec!["AB".to_string(), "C".to_string()];
        let result = encode_strings_as_user_data(&strings);
        // "AB\0" = 6 bytes, "C\0" = 4 bytes
        assert_eq!(result.len(), 10);

        let wchars: Vec<u16> = result
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(wchars, vec![b'A' as u16, b'B' as u16, 0, b'C' as u16, 0]);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = vec![
            "ServiceName".to_string(),
            "C:\\Program Files\\test.exe".to_string(),
            "user mode service".to_string(),
            "demand start".to_string(),
            "LocalSystem".to_string(),
        ];

        let encoded = encode_strings_as_user_data(&original);

        // Decode back using the same reader
        let mut decoded = Vec::new();
        let mut offset = 0;
        for _ in 0..original.len() {
            decoded.push(read_null_terminated_wstring(&encoded, &mut offset));
        }
        assert_eq!(original, decoded);
    }

    // ---- sid_to_string tests ----

    #[test]
    fn sid_empty_returns_empty() {
        assert_eq!(sid_to_string(&[]), "");
    }

    #[test]
    fn sid_well_known_local_system() {
        // S-1-5-18 (LocalSystem)
        let sid_bytes: Vec<u8> = vec![
            0x01, // Revision
            0x01, // SubAuthorityCount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (5)
            0x12, 0x00, 0x00, 0x00, // SubAuthority[0] = 18
        ];
        assert_eq!(sid_to_string(&sid_bytes), "S-1-5-18");
    }

    #[test]
    fn sid_invalid_falls_back_to_hex() {
        let bad_sid = vec![0xFF, 0xFE, 0xAB];
        assert_eq!(sid_to_string(&bad_sid), "fffeab");
    }
}
