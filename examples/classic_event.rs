//! Example: Subscribe to the Service Control Manager (SCM) ETW provider
//! and parse classic (EventlogClassic) events transparently.
//!
//! The SCM provider emits events with the `win:EventlogClassic` keyword,
//! which means `event_id == 0` and a custom binary payload. ferrisetw's
//! `event_schema()` handles these transparently — the same Parser and
//! EventSerializer APIs work without any special handling.
//!
//! Run with: `cargo run --example classic_event --features serde`
//! (requires Administrator privileges for ETW tracing)

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;
use std::time::Duration;

fn main() {
    env_logger::init();

    let callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
        // This SAME code works for both classic and modern events:
        match schema_locator.event_schema(record) {
            Ok(schema) => {
                println!("--- Event ---");
                println!("  Provider: {}", schema.provider_name());
                println!("  Task: {}", schema.task_name());
                println!("  Opcode: {}", schema.opcode_name());

                // Use Parser to extract properties — works transparently
                let parser = Parser::create(record, &schema);

                // For SCM event 7045 (service installed), try parsing known fields
                if let Ok(name) = parser.try_parse::<String>("ServiceName") {
                    println!("  ServiceName: {}", name);
                }
                if let Ok(path) = parser.try_parse::<String>("ImagePath") {
                    println!("  ImagePath: {}", path);
                }
                if let Ok(stype) = parser.try_parse::<String>("ServiceType") {
                    println!("  ServiceType: {}", stype);
                }
                if let Ok(start) = parser.try_parse::<String>("StartType") {
                    println!("  StartType: {}", start);
                }
                if let Ok(acct) = parser.try_parse::<String>("AccountName") {
                    println!("  AccountName: {}", acct);
                }

                // Optional: access classic-specific metadata
                if let Some(meta) = schema.classic_metadata() {
                    println!("  [Classic] Real EventID: {}", meta.real_event_id);
                    println!("  [Classic] Qualifier: {}", meta.qualifier);
                    println!("  [Classic] Source: {}", meta.source_name);
                    println!("  [Classic] Channel: {}", meta.channel);
                    println!("  [Classic] SID: {}", meta.sid_string);
                }

                // Serde path also works transparently:
                #[cfg(feature = "serde")]
                {
                    use ferrisetw::{EventSerializer, EventSerializerOptions};
                    // Enable include_classic_event_data to include SID, channel,
                    // source name, etc. in the JSON output for classic events.
                    let opts = EventSerializerOptions {
                        include_classic_event_data: true,
                        ..Default::default()
                    };
                    let ser = EventSerializer::new(record, &schema, opts);
                    match serde_json::to_string_pretty(&ser) {
                        Ok(json) => println!("  JSON:\n{}", json),
                        Err(e) => println!("  Serde error: {}", e),
                    }
                }
            }
            Err(err) => {
                eprintln!("Schema error for event_id={}: {:?}", record.event_id(), err);
            }
        }
    };

    // SCM provider GUID: {555908D1-A6D7-4695-8E1E-26931D2012F4}
    let scm_provider = Provider::by_guid(0x555908D1_A6D7_4695_8E1E_26931D2012F4u128)
        .add_callback(callback)
        .build();

    let (_trace, handle) = UserTrace::new()
        .named(String::from("FerrisEtwClassicExample"))
        .enable(scm_provider)
        .start()
        .unwrap();

    std::thread::spawn(move || {
        let status = UserTrace::process_from_handle(handle);
        println!("Trace ended with status {:?}", status);
    });

    println!("Listening for SCM events for 60 seconds...");
    println!("Try installing a service (e.g. `sc create test binPath= C:\\test.exe`) to trigger events.");
    std::thread::sleep(Duration::from_secs(60));
}
