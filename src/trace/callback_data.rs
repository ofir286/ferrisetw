use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use windows::Win32::System::Diagnostics::Etw;

use crate::native::etw_types::event_record::EventRecord;
use crate::provider::Provider;
use crate::schema_locator::SchemaLocator;
use crate::trace::RealTimeTraceTrait;
use crate::EtwCallback;

/// Data used by callbacks when the trace is running
// NOTE: this structure is accessed in an unsafe block in a separate thread (see the `trace_callback_thunk` function)
//       Thus, this struct must not be mutated (outside of interior mutability and/or using Mutex and other synchronization mechanisms) when the associated trace is running.
#[derive(Debug)]
pub enum CallbackData {
    RealTime(RealTimeCallbackData),
    FromFile(CallbackDataFromFile),
}

#[derive(Debug)]
pub struct RealTimeCallbackData {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    schema_locator: SchemaLocator,
    /// List of Providers associated with the Trace. This also owns the callback closures and their state
    providers: Vec<Provider>,
}

pub struct CallbackDataFromFile {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    schema_locator: SchemaLocator,
    /// This trace is reading from an ETL file, and has a single callback
    callback: RwLock<EtwCallback>,
}

impl CallbackData {
    pub fn on_event(&self, record: &EventRecord) {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.on_event(record),
            CallbackData::FromFile(f_cb) => f_cb.on_event(record),
        }
    }

    pub fn events_handled(&self) -> usize {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.events_handled(),
            CallbackData::FromFile(f_cb) => f_cb.events_handled(),
        }
    }
}

impl std::default::Default for RealTimeCallbackData {
    fn default() -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            providers: Vec::new(),
        }
    }
}

impl RealTimeCallbackData {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_provider(&mut self, provider: Provider) {
        // Auto-detect whether this provider emits classic EventLog events
        // by querying TDH for the win:EventlogClassic keyword at the provider level.
        self.schema_locator
            .detect_and_register_classic_provider(&provider.guid());

        // Warn if this classic provider has EventId filters, since classic events
        // always arrive with event_id == 0 in the ETW header. Kernel-level event ID
        // filtering will therefore never match the *real* event ID (which is embedded
        // in the binary payload and only resolved after parsing).
        if self.schema_locator.is_classic_provider(&provider.guid()) {
            use crate::provider::EventFilter;
            let has_event_id_filter = provider.filters().iter().any(|f| {
                matches!(f, EventFilter::ByEventIds(_))
            });
            if has_event_id_filter {
                log::warn!(
                    "Provider {:?} is a classic EventLog provider (win:EventlogClassic). \
                     Classic events always arrive with event_id == 0 in the ETW header, so \
                     kernel-level EventId filters will not match real event IDs. \
                     To filter by real event ID, remove the ByEventIds filter and check \
                     schema.event_id() in your callback instead.",
                    provider.guid()
                );
            }
        }

        self.providers.push(provider);
    }

    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    pub fn provider_flags<T: RealTimeTraceTrait>(&self) -> Etw::EVENT_TRACE_FLAG {
        Etw::EVENT_TRACE_FLAG(T::enable_flags(&self.providers))
    }

    /// Returns the OR of all kernel providers' group masks.
    /// Non-zero only when at least one provider uses TraceSetInformation (e.g. object_manager).
    pub fn provider_group_mask(&self) -> u32 {
        self.providers.iter().fold(0, |acc, p| acc | p.kernel_group_mask())
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);

        for prov in &self.providers {
            if prov.guid() == record.provider_id() {
                prov.on_event(record, &self.schema_locator);
            }
        }
    }
}

impl CallbackDataFromFile {
    pub fn new(callback: EtwCallback) -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            callback: RwLock::new(callback),
        }
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut cb) = self.callback.write() {
            cb(record, &self.schema_locator);
        }
    }
}

impl std::fmt::Debug for CallbackDataFromFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackDataFromFile")
            .field("events_handled", &self.events_handled)
            .field("schema_locator", &self.schema_locator)
            .finish()
    }
}
