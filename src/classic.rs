//! Support for classic (EventlogClassic) ETW events
//!
//! Providers using the `win:EventlogClassic` keyword emit events with `event_id == 0`
//! whose `UserData` contains a custom binary structure (not a TDH-compatible layout).
//! This module provides the binary parsing and re-encoding logic needed to make these
//! events work transparently through the existing [`Parser`](crate::parser::Parser) and
//! [`EventSerializer`](crate::ser::EventSerializer) pipelines.

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
