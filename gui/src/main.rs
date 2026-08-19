//! netmap-gui — an interactive desktop front-end for netmap.
//!
//! All scanning logic lives in the `netmap` library; this crate only drives it
//! and draws the result. A scan runs on a background tokio runtime and streams
//! [`ScanEvent`](netmap::progress::ScanEvent)s back to the UI thread, so hosts
//! appear as they are found and the window never blocks.

mod app;
mod canvas;
mod export;
mod panels;
mod scan;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("netmap=info,warn")),
        )
        .with_target(false)
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("netmap"),
        ..Default::default()
    };

    eframe::run_native(
        "netmap",
        native_options,
        Box::new(|cc| Ok(Box::new(app::NetmapApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("failed to start the GUI: {e}"))
}
