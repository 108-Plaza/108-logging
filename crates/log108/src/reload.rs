//! Runtime log filter (LOG-3).
//!
//! Design: `docs/design/runtime-filter.md`. A service builds its subscriber with a
//! reloadable [`EnvFilter`] and keeps the returned [`LogHandle`], so an admin route can
//! raise or lower one subsystem (a `tracing` target) on a running process, for example
//! `warn,mqtt=debug`, with no restart.
//!
//! SKELETON: the bodies below are `todo!("LOG-3")`. The four tests at the bottom are the
//! provided tests from the design; they fail until the bodies are written. Do not edit,
//! weaken or delete them.

use std::fmt;
use std::sync::{Arc, RwLock};

use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::{reload, EnvFilter, Registry};

use crate::Options;

/// Why [`LogHandle::set_filter`] refused a new filter. The old filter stays in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// The directive string is not valid `EnvFilter` syntax.
    Parse(String),
    /// The subscriber this handle controlled is gone, or was never installed.
    Reload(String),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "invalid log filter directives: {msg}"),
            Self::Reload(msg) => write!(f, "log filter could not be reloaded: {msg}"),
        }
    }
}

impl std::error::Error for FilterError {}

/// Cloneable handle to a reloadable filter. Cheap to clone; every clone controls the same
/// subscriber.
#[derive(Clone)]
pub struct LogHandle {
    inner: reload::Handle<EnvFilter, Registry>,
    current: Arc<RwLock<String>>,
}

impl LogHandle {
    /// The directive string currently in force (what the last successful
    /// [`set_filter`](Self::set_filter), or the initial build, set).
    pub fn filter(&self) -> String {
        let _ = (&self.inner, &self.current);
        todo!("LOG-3")
    }

    /// Parses `directives` as `EnvFilter` directives and swaps the filter in.
    ///
    /// On `Err` nothing changes: the old filter stays in force and [`filter`](Self::filter)
    /// still returns the old string.
    pub fn set_filter(&self, directives: &str) -> Result<(), FilterError> {
        let _ = directives;
        todo!("LOG-3")
    }
}

/// Like [`crate::init_with`], but with a reloadable filter. Returns the handle.
///
/// Initial directives use the same precedence as today: `RUST_LOG` → `LOG_FILTER` → `info`.
/// If a global subscriber is already installed, nothing new is installed and the returned
/// handle controls nothing: its `set_filter` returns [`FilterError::Reload`].
pub fn init_reloadable<W, S>(options: Options<W, S>) -> LogHandle
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    S: AsRef<str>,
{
    let _ = options;
    todo!("LOG-3")
}

/// Testable form of [`init_reloadable`]: builds the same subscriber stack as
/// [`crate::build_subscriber_with_filter`] with the filter wrapped in a reload layer, and
/// installs nothing globally. Invalid `directives` fall back to `info`.
pub fn build_reloadable_subscriber<W>(
    service: &str,
    writer: W,
    json: bool,
    directives: &str,
) -> (Dispatch, LogHandle)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let _ = (service, writer, json, directives);
    todo!("LOG-3")
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

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

    // One callsite each, reused across reloads, so the tests prove the interest cache is
    // rebuilt (design, provided test 1).
    fn emit_mqtt_debug() {
        tracing::debug!(target: "mqtt", probe = "mqtt-debug", "mqtt probe");
    }

    fn emit_http_debug() {
        tracing::debug!(target: "http", probe = "http-debug", "http probe");
    }

    /// Design rows 1–3.
    #[test]
    fn reload_raises_one_target_without_restart() {
        let buf = Buf::default();
        let (dispatch, handle) = build_reloadable_subscriber("test-api", buf.clone(), true, "warn");

        tracing::dispatcher::with_default(&dispatch, || {
            emit_mqtt_debug();
            let before = buf.take();
            assert!(
                !before.contains("mqtt-debug"),
                "row 1: debug on mqtt must not be written at warn, got: {before}"
            );

            handle
                .set_filter("warn,mqtt=debug")
                .expect("valid directives are accepted");

            emit_mqtt_debug();
            let after = buf.take();
            assert!(
                after.contains("mqtt-debug"),
                "row 2: debug on mqtt must be written after raising mqtt, got: {after}"
            );

            emit_http_debug();
            let other = buf.take();
            assert!(
                !other.contains("http-debug"),
                "row 3: debug on http must stay off, got: {other}"
            );
        });
    }

    /// Design row 4.
    #[test]
    fn bad_directive_keeps_the_old_filter() {
        let buf = Buf::default();
        let (dispatch, handle) = build_reloadable_subscriber("test-api", buf.clone(), true, "warn");
        handle
            .set_filter("warn,mqtt=debug")
            .expect("valid directives are accepted");

        let err = handle
            .set_filter("warn,mqtt=nonsense[")
            .expect_err("invalid directives are refused");
        assert!(matches!(err, FilterError::Parse(_)), "got {err:?}");
        assert_eq!(handle.filter(), "warn,mqtt=debug");

        tracing::dispatcher::with_default(&dispatch, emit_mqtt_debug);
        let out = buf.take();
        assert!(
            out.contains("mqtt-debug"),
            "the old filter must still be in force after a refused reload, got: {out}"
        );
    }

    /// Design row 5.
    #[test]
    fn filter_reports_the_directives_in_force() {
        let (_dispatch, handle) =
            build_reloadable_subscriber("test-api", Buf::default(), true, "warn");
        assert_eq!(handle.filter(), "warn");
    }

    /// Design row 6.
    #[test]
    fn set_filter_after_the_subscriber_is_gone_is_a_reload_error() {
        let (dispatch, handle) =
            build_reloadable_subscriber("test-api", Buf::default(), true, "warn");
        drop(dispatch);

        let err = handle
            .set_filter("debug")
            .expect_err("a dead handle must refuse");
        assert!(matches!(err, FilterError::Reload(_)), "got {err:?}");
        assert_eq!(handle.filter(), "warn");
    }
}
