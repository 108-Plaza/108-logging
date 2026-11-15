//! LOG-4 provided test: records from the `log` crate reach the reloadable subscriber,
//! and `log`'s own max level follows `LogHandle::set_filter`.
//!
//! This file is its own test binary (own process), because `init_reloadable` installs the
//! global subscriber and the global `log` logger, which can happen only once per process.
//! Do not edit, weaken or delete this test.

use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

struct Guard<'a>(std::sync::MutexGuard<'a, Vec<u8>>);

impl io::Write for Guard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Guard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Guard(self.0.lock().expect("lock test buffer"))
    }
}

impl Buf {
    fn take(&self) -> String {
        let mut guard = self.0.lock().expect("lock test buffer");
        String::from_utf8(std::mem::take(&mut *guard)).expect("valid utf-8 log")
    }
}

#[test]
fn log_crate_records_follow_the_runtime_filter() {
    std::env::remove_var("RUST_LOG");
    std::env::remove_var("LOG_FILTER");

    let buf = Buf::default();
    let handle = log108::init_reloadable(log108::Options {
        service: "bridge-test",
        writer: buf.clone(),
        json: true,
    });

    handle.set_filter("warn").expect("valid directives");
    assert_eq!(
        log::max_level(),
        log::LevelFilter::Warn,
        "log's max level must follow set_filter(\"warn\")"
    );
    log::debug!(target: "mqtt", "bridge-mqtt-debug");
    log::warn!(target: "mqtt", "bridge-mqtt-warn");
    let at_warn = buf.take();
    assert!(
        !at_warn.contains("bridge-mqtt-debug"),
        "a log::debug! on mqtt must not be written at warn, got: {at_warn}"
    );
    assert!(
        at_warn.contains("bridge-mqtt-warn"),
        "a log::warn! must reach the subscriber, got: {at_warn}"
    );

    handle
        .set_filter("warn,mqtt=debug")
        .expect("valid directives");
    assert!(
        log::max_level() >= log::LevelFilter::Debug,
        "log's max level must rise with set_filter(\"warn,mqtt=debug\"), got {:?}",
        log::max_level()
    );
    log::debug!(target: "mqtt", "bridge-mqtt-debug");
    log::debug!(target: "http", "bridge-http-debug");
    let raised = buf.take();
    assert!(
        raised.contains("bridge-mqtt-debug"),
        "a log::debug! on mqtt must be written after raising mqtt, got: {raised}"
    );
    assert!(
        !raised.contains("bridge-http-debug"),
        "a log::debug! on http must stay off, got: {raised}"
    );

    handle.set_filter("warn").expect("valid directives");
    assert_eq!(
        log::max_level(),
        log::LevelFilter::Warn,
        "log's max level must fall back with set_filter(\"warn\")"
    );
}
