//! A way to cache and retrieve Schemas

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use windows::core::GUID;

use crate::classic::{self, ClassicMetadata, ClassicParseError};
use crate::native::etw_types::event_record::EventRecord;
use crate::native::tdh;
use crate::native::tdh::TraceEventInfo;
use crate::schema::{ClassicSchemaData, Schema};

/// Schema module errors
#[derive(Debug)]
pub enum SchemaError {
    /// Represents an internal [TdhNativeError]
    ///
    /// [TdhNativeError]: tdh::TdhNativeError
    TdhNativeError(tdh::TdhNativeError),
    /// Represents a classic event parsing error
    ClassicParseError(ClassicParseError),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::TdhNativeError(e) => write!(f, "TDH error: {}", e),
            SchemaError::ClassicParseError(e) => write!(f, "Classic parse error: {}", e),
        }
    }
}

impl From<tdh::TdhNativeError> for SchemaError {
    fn from(err: tdh::TdhNativeError) -> Self {
        SchemaError::TdhNativeError(err)
    }
}

impl From<ClassicParseError> for SchemaError {
    fn from(err: ClassicParseError) -> Self {
        SchemaError::ClassicParseError(err)
    }
}

pub(crate) type SchemaResult<T> = Result<T, SchemaError>;

/// A way to group events that share the same [`Schema`]
///
/// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor):
/// > For manifest-based ETW, the combination Provider.DecodeGuid + Event.Id + Event.Version should uniquely identify an event,
/// > i.e. all events with the same DecodeGuid, Id, and Version should have the same set of fields with no changes in field names, field types, or field ordering.
#[derive(Debug, Eq, PartialEq, Hash)]
struct SchemaKey {
    provider: GUID,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): A 16-bit number used to identify manifest-based events
    id: u16,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): An 8-bit number used to specify the version of a manifest-based event.
    // The version indicates a revision to the definition of an event with a particular Id.
    // All events with a given Id should have similar semantics, but a change in version
    // can be used to indicate a minor modification of the event details, e.g. a change to
    // the type of a field or the addition of a new field.
    version: u8,

    // TODO: not sure why these ones are required in a SchemaKey. If they are, document why.
    //       note that krabsetw also uses these fields (without an explanation)
    //       however, krabsetw's `schema::operator==` do not use them to compare schemas for equality.
    //       see https://github.com/microsoft/krabsetw/issues/195
    opcode: u8,
    level: u8,
    //
    // From MS documentation `evntprov.h`
    // For manifest-free events (i.e. TraceLogging), Event.Id and Event.Version are not useful
    // and should be ignored. Use Event name, level, keyword, and opcode for event filtering and
    // identification.
    //
    event_name: String,
}

impl SchemaKey {
    pub fn new(event: &EventRecord) -> Self {
        SchemaKey {
            provider: event.provider_id(),
            id: event.event_id(),
            opcode: event.opcode(),
            version: event.version(),
            level: event.level(),
            event_name: event.event_name(),
        }
    }
}

/// Represents a cache of Schemas already located
///
/// This cache is implemented as a [HashMap] where the key is a combination of the following elements
/// of an [Event Record](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
/// * EventHeader.ProviderId
/// * EventHeader.EventDescriptor.Id
/// * EventHeader.EventDescriptor.Opcode
/// * EventHeader.EventDescriptor.Version
/// * EventHeader.EventDescriptor.Level
///
/// Credits: [KrabsETW::schema_locator](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/schema_locator.hpp).
/// See also the code of `SchemaKey` for more info
pub struct SchemaLocator {
    schemas: Mutex<HashMap<SchemaKey, Arc<Schema>>>,
    /// Cache of `TraceEventInfo` for classic events, keyed by (provider_guid, real_event_id).
    /// The expensive TDH call is done at most once per event type.
    classic_tei_cache: Mutex<HashMap<(GUID, u16), Arc<TraceEventInfo>>>,
    /// Provider GUIDs known to emit classic (EventlogClassic) events.
    ///
    /// Populated at provider registration time by querying TDH for provider keywords
    /// (see [`Self::detect_and_register_classic_provider`]).
    /// Events from these providers are transparently parsed using the classic binary format.
    ///
    /// Uses `RwLock` because reads (`is_classic_provider`) happen on every event while
    /// writes (`register_classic_provider`) only happen during provider setup.
    classic_providers: RwLock<HashSet<GUID>>,
}

impl Default for SchemaLocator {
    fn default() -> Self {
        SchemaLocator {
            schemas: Mutex::new(HashMap::new()),
            classic_tei_cache: Mutex::new(HashMap::new()),
            classic_providers: RwLock::new(HashSet::new()),
        }
    }
}

impl std::fmt::Debug for SchemaLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaLocator")
            .field("len", &self.schemas.try_lock().map(|guard| guard.len()))
            .finish()
    }
}

impl SchemaLocator {
    pub(crate) fn new() -> Self {
        SchemaLocator {
            schemas: Mutex::new(HashMap::new()),
            classic_tei_cache: Mutex::new(HashMap::new()),
            classic_providers: RwLock::new(HashSet::new()),
        }
    }

    /// Register a provider GUID as a classic (EventlogClassic) provider.
    ///
    /// Events from this provider will be transparently parsed using the classic
    /// event binary format.  This is normally called automatically when a provider
    /// is enabled on a trace (via [`Self::detect_and_register_classic_provider`]),
    /// but it can also be called manually for providers that are consumed through
    /// other means (e.g. file traces).
    pub fn register_classic_provider(&self, guid: GUID) {
        self.classic_providers.write().unwrap().insert(guid);
    }

    /// Query TDH for a provider's keyword definitions and, if it advertises
    /// `win:EventlogClassic` (`0x0080000000000000`), register it as a classic provider.
    ///
    /// This is called automatically when a provider is added to a real-time trace.
    pub(crate) fn detect_and_register_classic_provider(&self, guid: &GUID) {
        if tdh::provider_has_classic_keyword(guid) {
            self.classic_providers.write().unwrap().insert(*guid);
        }
    }

    /// Returns `true` if the given provider GUID has been registered as a classic
    /// (EventlogClassic) provider.
    ///
    /// This can be useful when you want to check whether a provider uses the legacy
    /// event format before receiving any events from it. For most use cases, checking
    /// [`Schema::classic_metadata()`](crate::schema::Schema::classic_metadata) on a
    /// per-event basis is more convenient.
    pub fn is_classic_provider(&self, guid: &GUID) -> bool {
        self.classic_providers.read().unwrap().contains(guid)
    }

    /// Retrieve the Schema of an ETW Event
    ///
    /// For classic events (those from providers that advertise the
    /// `win:EventlogClassic` keyword), this method transparently parses the
    /// binary payload, resolves the real event ID via TDH, and returns a `Schema`
    /// whose synthetic user data buffer allows [`Parser`](crate::parser::Parser)
    /// and [`EventSerializer`](crate::ser::EventSerializer) to work normally.
    ///
    /// Classic-specific metadata (real event ID, SID, channel, etc.) is available via
    /// [`Schema::classic_metadata()`](crate::schema::Schema::classic_metadata).
    ///
    /// # Arguments
    /// * `event` - The [EventRecord] that's passed to the callback
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    /// };
    /// ```
    pub fn event_schema(&self, event: &EventRecord) -> SchemaResult<Arc<Schema>> {
        // Provider-level check: if this provider was detected (or manually registered)
        // as a classic EventLog provider, route through the classic parsing path.
        if self.is_classic_provider(&event.provider_id()) {
            match self.classic_event_schema(event) {
                Ok(schema) => return Ok(schema),
                Err(e) => {
                    // Classic parsing failed. Log a warning and fall back to
                    // normal TDH-based schema resolution so the event is not lost.
                    log::warn!(
                        "Classic event parsing failed for provider {:?}, event_id {}: {}. \
                         Falling back to normal schema resolution.",
                        event.provider_id(),
                        event.event_id(),
                        e,
                    );
                }
            }
        }

        let key = SchemaKey::new(event);

        let mut schemas = self.schemas.lock().unwrap();
        match schemas.get(&key) {
            Some(s) => Ok(Arc::clone(s)),
            None => {
                let tei = TraceEventInfo::build_from_event(event)?;
                let new_schema = Arc::from(Schema::new(tei));
                schemas.insert(key, Arc::clone(&new_schema));
                Ok(new_schema)
            }
        }
    }

    /// Internal: resolve a classic (EventlogClassic) event.
    ///
    /// 1. Parse the binary UserData to extract real_event_id, source_name, SID, strings.
    /// 2. Get or cache the `TraceEventInfo` for (provider_guid, real_event_id).
    /// 3. Re-encode the strings as a synthetic UserData buffer (null-terminated UTF-16LE).
    /// 4. Build `ClassicMetadata` with TDH-resolved channel and event message.
    /// 5. Return a fresh (non-cached) `Schema` with the shared TEI and per-event classic data.
    fn classic_event_schema(&self, event: &EventRecord) -> SchemaResult<Arc<Schema>> {
        // Step 1: Parse the binary payload
        let raw = classic::parse_classic_user_data(event.user_buffer())?;

        // Step 2: Get or cache TraceEventInfo for (provider_guid, real_event_id)
        let cache_key = (event.provider_id(), raw.real_event_id);
        let te_info = {
            let mut cache = self.classic_tei_cache.lock().unwrap();
            match cache.get(&cache_key) {
                Some(tei) => Arc::clone(tei),
                None => {
                    let tei = TraceEventInfo::build_from_event_with_id(
                        event,
                        raw.real_event_id,
                    ).map_err(ClassicParseError::from)?;
                    let tei = Arc::new(tei);
                    cache.insert(cache_key, Arc::clone(&tei));
                    tei
                }
            }
        };

        // Step 3: Re-encode the strings as a synthetic UserData buffer
        let synthetic_user_data = classic::encode_strings_as_user_data(&raw.strings);

        // Step 4: Build ClassicMetadata
        let sid_string = classic::sid_to_string(&raw.sid_bytes);
        let channel = te_info.channel_name();
        let event_message = te_info.event_message();

        let metadata = ClassicMetadata {
            time_created: raw.time_created,
            real_event_id: raw.real_event_id,
            qualifier: raw.qualifier,
            source_name: raw.source_name,
            sid_string,
            raw_sid: raw.sid_bytes,
            channel,
            event_message,
        };

        // Step 5: Build a fresh (non-cached) Schema with classic data
        let classic_data = ClassicSchemaData {
            metadata,
            synthetic_user_data,
        };
        let schema = Schema::new_classic(te_info, classic_data);
        Ok(Arc::new(schema))
    }
}
