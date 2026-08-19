//! Progress reporting for long-running scans.
//!
//! [`pipeline::run_pipeline`](crate::pipeline::run_pipeline) can take minutes on a
//! `/24`. The CLI can live with that because every stage already logs through
//! `tracing`, but a GUI needs incremental results. [`ScanEvent`]s are emitted at
//! exactly the points the pipeline already logs, so the two stay in step.

use crate::model::{BackendKind, HopEdge, Host, HostGraph};
use std::net::IpAddr;
use tokio::sync::mpsc::UnboundedSender;

/// An incremental update from a running scan.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// A pipeline stage began. `total_stages` counts only stages that will
    /// actually run, so skipped backends never inflate a progress bar.
    StageStarted {
        kind: BackendKind,
        stage_index: usize,
        total_stages: usize,
    },
    /// A stage finished. `found` is the number of hosts it contributed.
    StageFinished {
        kind: BackendKind,
        elapsed_ms: u64,
        found: usize,
    },
    /// A stage was skipped, either by `--skip` or because its binary is missing.
    StageSkipped { kind: BackendKind, reason: String },
    /// A host was seen for the first time.
    HostDiscovered(Box<Host>),
    /// An already-known host gained detail (ports, OS, vendor, hostname).
    HostUpdated(Box<Host>),
    /// Per-host fan-out progress within a stage (nmap fingerprint, traceroute).
    HostProgress {
        kind: BackendKind,
        done: usize,
        total: usize,
    },
    /// A topology edge was discovered.
    EdgeDiscovered(HopEdge),
    /// The gateway was identified.
    GatewayIdentified(IpAddr),
    /// Something went wrong but the scan continued.
    Warning(String),
    /// The scan finished. Always the last event.
    Complete(Box<HostGraph>),
    /// The scan was cancelled before completing.
    Cancelled,
}

/// Sink for [`ScanEvent`]s.
///
/// [`Reporter::silent`] makes progress reporting free for callers that do not
/// want it (the CLI, and every existing test), so the pipeline can emit events
/// unconditionally without paying for them.
#[derive(Debug, Clone, Default)]
pub struct Reporter {
    tx: Option<UnboundedSender<ScanEvent>>,
}

impl Reporter {
    /// A reporter that drops everything sent to it.
    pub fn silent() -> Self {
        Self { tx: None }
    }

    /// A reporter that forwards to `tx`.
    pub fn new(tx: UnboundedSender<ScanEvent>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Sends an event. A closed receiver is not an error — the consumer simply
    /// stopped listening, which must never abort a scan.
    pub fn send(&self, event: ScanEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }

    /// True when events are actually going somewhere. Use to skip building
    /// payloads (cloning a `Host`) that would be discarded.
    pub fn is_active(&self) -> bool {
        self.tx.is_some()
    }

    pub fn warn(&self, msg: impl Into<String>) {
        self.send(ScanEvent::Warning(msg.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn silent_reporter_discards_events_without_panicking() {
        let r = Reporter::silent();
        assert!(!r.is_active());
        r.warn("dropped on the floor");
        r.send(ScanEvent::Cancelled);
    }

    #[test]
    fn active_reporter_forwards_events_in_order() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let r = Reporter::new(tx);
        assert!(r.is_active());

        r.send(ScanEvent::StageStarted {
            kind: BackendKind::Nmap,
            stage_index: 0,
            total_stages: 2,
        });
        r.warn("heads up");

        assert!(matches!(
            rx.try_recv().unwrap(),
            ScanEvent::StageStarted {
                kind: BackendKind::Nmap,
                ..
            }
        ));
        match rx.try_recv().unwrap() {
            ScanEvent::Warning(m) => assert_eq!(m, "heads up"),
            other => panic!("expected Warning, got {:?}", other),
        }
    }

    #[test]
    fn sending_after_the_receiver_drops_is_not_an_error() {
        let (tx, rx) = mpsc::unbounded_channel();
        let r = Reporter::new(tx);
        drop(rx);
        // A GUI closing mid-scan must not take the scan down with it.
        r.warn("nobody is listening");
    }
}
