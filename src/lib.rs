//! netmap — discover and render network topology maps.
//!
//! The crate is split so that everything except argument parsing and printing is
//! reusable. A scan produces a [`HostGraph`], which the renderer turns into text,
//! SVG, or (in `netmap-gui`) an interactive canvas:
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use netmap::{backends::ScanOptions, pipeline, renderer};
//!
//! let opts = ScanOptions::default();
//! let graph = pipeline::run_pipeline("192.168.1.0/24", &opts).await?;
//! print!("{}", renderer::render_tree(&graph));
//! # Ok(())
//! # }
//! ```

pub mod backends;
pub mod config;
pub mod layout;
pub mod model;
pub mod pipeline;
pub mod progress;
pub mod renderer;

pub use backends::{ScanBackend, ScanOptions, ScanResult};
pub use model::{BackendKind, DeviceRole, HopEdge, Host, HostGraph, Port, Protocol};
pub use pipeline::run_pipeline;
pub use progress::ScanEvent;
