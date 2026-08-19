//! Bridges the async pipeline to the synchronous UI thread.

use netmap::backends::ScanOptions;
use netmap::pipeline;
use netmap::progress::{Reporter, ScanEvent};
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A scan running on the background runtime.
pub struct RunningScan {
    /// Events drain from here on the UI thread, one non-blocking sweep per frame.
    pub events: std_mpsc::Receiver<ScanEvent>,
    pub cancel: CancellationToken,
    pub started: std::time::Instant,
}

impl RunningScan {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// Spawns a scan on `rt` and returns a handle the UI can poll.
///
/// The pipeline's tokio channel is forwarded onto a `std` channel because egui's
/// update loop is synchronous — it needs a receiver it can drain without an
/// async context.
pub fn spawn(
    rt: &tokio::runtime::Runtime,
    target: String,
    opts: ScanOptions,
    ctx: egui::Context,
) -> RunningScan {
    let (ui_tx, ui_rx) = std_mpsc::channel();
    let (pipe_tx, mut pipe_rx) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();

    let forward_target = target.clone();
    let scan_cancel = cancel.clone();

    rt.spawn(async move {
        // Forward events as they arrive, waking the UI for each one so progress
        // is visible immediately rather than at the next unrelated repaint.
        let forwarder = tokio::spawn(async move {
            while let Some(event) = pipe_rx.recv().await {
                if ui_tx.send(event).is_err() {
                    break; // Window closed; nothing left to draw.
                }
                ctx.request_repaint();
            }
            ctx.request_repaint();
        });

        let result = pipeline::run_pipeline_with_progress(
            &forward_target,
            &opts,
            Reporter::new(pipe_tx),
            scan_cancel,
        )
        .await;

        if let Err(e) = result {
            tracing::error!("scan failed: {e}");
        }
        let _ = forwarder.await;
    });

    RunningScan {
        events: ui_rx,
        cancel,
        started: std::time::Instant::now(),
    }
}
