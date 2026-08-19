//! Application state and the eframe update loop.

use crate::scan::{self, RunningScan};
use egui::{Pos2, Vec2};
use netmap::backends::ScanOptions;
use netmap::config::Config;
use netmap::layout::{layout_graph, Layout};
use netmap::model::{BackendKind, HostGraph};
use netmap::progress::ScanEvent;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// How many log lines to keep. Enough to explain a scan, bounded so a long run
/// cannot grow the process without limit.
const LOG_CAPACITY: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Scanning,
    Done,
    Cancelled,
}

/// Everything the UI needs to draw itself.
pub struct NetmapApp {
    // --- scan settings, mirroring the CLI flags ---
    pub target: String,
    pub sudo: bool,
    pub ports: String,
    pub timeout: u64,
    pub max_parallel: usize,
    pub show_off_target: bool,
    /// Per-backend enable switches, indexed to match [`BackendKind::ALL`].
    pub backends: [bool; 4],

    // --- results ---
    pub graph: HostGraph,
    pub layout: Layout,
    /// Positions the user has dragged, which override the computed layout.
    pub pinned: HashMap<IpAddr, Pos2>,
    pub selected: Option<IpAddr>,
    pub filter: String,

    // --- run state ---
    pub phase: Phase,
    pub stage: String,
    pub progress: Option<(usize, usize)>,
    pub log: VecDeque<String>,
    pub elapsed: Option<std::time::Duration>,

    // --- view transform ---
    pub pan: Vec2,
    pub zoom: f32,
    /// Set when the graph changes so the canvas re-fits on the next frame.
    pub needs_fit: bool,

    running: Option<RunningScan>,
    rt: tokio::runtime::Runtime,
}

impl NetmapApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Seed the form from the config file so the GUI and CLI agree on defaults.
        let cfg = Config::load().unwrap_or_default();
        let opts = cfg.to_scan_options().unwrap_or_default();

        let mut backends = [true; 4];
        for (i, kind) in BackendKind::ALL.iter().enumerate() {
            backends[i] = !opts.skip_backends.contains(kind);
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to start the tokio runtime");

        let mut app = Self {
            target: cfg.target.clone().unwrap_or_default(),
            sudo: opts.sudo,
            ports: opts.port_range.clone(),
            timeout: opts.timeout_secs,
            max_parallel: opts.max_parallel,
            show_off_target: opts.show_off_target,
            backends,
            graph: HostGraph::empty(),
            layout: Layout::default(),
            pinned: HashMap::new(),
            selected: None,
            filter: String::new(),
            phase: Phase::Idle,
            stage: String::new(),
            progress: None,
            log: VecDeque::new(),
            elapsed: None,
            pan: Vec2::ZERO,
            zoom: 1.0,
            needs_fit: true,
            running: None,
            rt,
        };
        app.push_log("Ready. Enter a target and press Scan.");
        app
    }

    pub fn is_scanning(&self) -> bool {
        self.phase == Phase::Scanning
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        if self.log.len() >= LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log.push_back(msg.into());
    }

    /// Builds [`ScanOptions`] from the form fields.
    pub fn scan_options(&self) -> ScanOptions {
        let skip = BackendKind::ALL
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.backends[*i])
            .map(|(_, k)| *k)
            .collect();

        ScanOptions {
            sudo: self.sudo,
            timeout_secs: self.timeout,
            port_range: self.ports.trim().to_string(),
            skip_backends: skip,
            max_parallel: self.max_parallel.max(1),
            // The GUI has a Cancel button, so a stage timeout would only add a
            // second, less predictable way for a scan to stop.
            stage_timeout_secs: 0,
            show_off_target: self.show_off_target,
        }
    }

    pub fn start_scan(&mut self, ctx: &egui::Context) {
        let target = self.target.trim().to_string();
        if target.is_empty() {
            self.push_log("Cannot scan: no target given.");
            return;
        }
        if self.is_scanning() {
            return;
        }

        self.graph = HostGraph::empty();
        self.layout = Layout::default();
        self.pinned.clear();
        self.selected = None;
        self.progress = None;
        self.elapsed = None;
        self.needs_fit = true;
        self.phase = Phase::Scanning;
        self.stage = "starting".into();
        self.push_log(format!("Scanning {target}"));

        if self.sudo {
            self.push_log(
                "sudo is enabled: if no password-less rule is configured, the privileged \
                 backends will fail silently. Consider `setcap cap_net_raw,cap_net_admin+eip`.",
            );
        }

        let opts = self.scan_options();
        self.running = Some(scan::spawn(&self.rt, target, opts, ctx.clone()));
    }

    pub fn cancel_scan(&mut self) {
        if let Some(run) = &self.running {
            run.cancel();
            self.push_log("Cancelling…");
        }
    }

    /// Drains every event that has arrived since the last frame.
    fn pump_events(&mut self) {
        let Some(run) = &self.running else { return };

        let mut events = Vec::new();
        while let Ok(event) = run.events.try_recv() {
            events.push(event);
        }
        let disconnected = matches!(
            run.events.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
        let started = run.started;

        let mut graph_changed = false;
        for event in events {
            match event {
                ScanEvent::StageStarted {
                    kind,
                    stage_index,
                    total_stages,
                } => {
                    self.stage = format!("{kind} ({}/{})", stage_index + 1, total_stages);
                    self.progress = None;
                    self.push_log(format!("stage {kind}: started"));
                }
                ScanEvent::StageFinished {
                    kind,
                    elapsed_ms,
                    found,
                } => {
                    self.progress = None;
                    self.push_log(format!("stage {kind}: {found} hosts in {elapsed_ms} ms"));
                }
                ScanEvent::StageSkipped { reason, .. } => {
                    self.push_log(format!("skipped {reason}"));
                }
                ScanEvent::HostDiscovered(host) | ScanEvent::HostUpdated(host) => {
                    self.graph.hosts.insert(host.ip, *host);
                    graph_changed = true;
                }
                ScanEvent::EdgeDiscovered(edge) => {
                    self.graph.edges.push(edge);
                    graph_changed = true;
                }
                ScanEvent::GatewayIdentified(ip) => {
                    self.graph.gateway = Some(ip);
                    graph_changed = true;
                    self.push_log(format!("gateway: {ip}"));
                }
                ScanEvent::HostProgress { done, total, .. } => {
                    self.progress = Some((done, total));
                }
                ScanEvent::Warning(msg) => self.push_log(format!("warning: {msg}")),
                ScanEvent::Complete(graph) => {
                    // The final graph is authoritative: it has been filtered,
                    // gateway-resolved and role-annotated, which the incremental
                    // events deliberately are not.
                    self.graph = *graph;
                    self.phase = Phase::Done;
                    self.elapsed = Some(started.elapsed());
                    self.progress = None;
                    self.stage = "complete".into();
                    graph_changed = true;
                    self.push_log(format!(
                        "Scan complete: {} hosts, {} edges",
                        self.graph.hosts.len(),
                        self.graph.edges.len()
                    ));
                }
                ScanEvent::Cancelled => {
                    self.phase = Phase::Cancelled;
                    self.elapsed = Some(started.elapsed());
                    self.progress = None;
                    self.stage = "cancelled".into();
                    self.push_log("Scan cancelled; showing partial results.");
                }
            }
        }

        if graph_changed {
            self.relayout();
        }

        // The channel closing is the only signal that a failed scan has ended.
        if disconnected && self.phase == Phase::Scanning {
            self.phase = Phase::Done;
            self.elapsed = Some(started.elapsed());
            self.stage = "finished".into();
        }
        if self.phase != Phase::Scanning {
            self.running = None;
        }
    }

    /// Recomputes positions, keeping any node the user has dragged where they put it.
    pub fn relayout(&mut self) {
        self.layout = layout_graph(&self.graph);
        self.pinned
            .retain(|ip, _| self.graph.hosts.contains_key(ip));
    }

    /// Hosts matching the filter box, in stable IP order.
    pub fn visible_hosts(&self) -> Vec<IpAddr> {
        let needle = self.filter.trim().to_lowercase();
        let mut ips: Vec<IpAddr> = self
            .graph
            .hosts
            .values()
            .filter(|h| {
                if needle.is_empty() {
                    return true;
                }
                h.ip.to_string().contains(&needle)
                    || h.hostname
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
                    || h.vendor
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
                    || h.role.to_string().to_lowercase().contains(&needle)
            })
            .map(|h| h.ip)
            .collect();
        ips.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0u8, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1u8, u128::from(*v6)),
        });
        ips
    }

    /// True when the scan produced a star topology rather than measuring one.
    /// Worth surfacing: the shape is inferred, not observed.
    pub fn topology_is_synthetic(&self) -> bool {
        let Some(gw) = self.graph.gateway else {
            return false;
        };
        !self.graph.edges.is_empty()
            && self
                .graph
                .edges
                .iter()
                .all(|e| e.from == gw && e.hop_index == 1)
            && self.graph.hosts.len() > 2
    }
}

impl eframe::App for NetmapApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.pump_events();

        // Panel order defines the layout: edges are claimed first, and the
        // canvas fills whatever rectangle is left.
        crate::panels::top_bar(self, ui);
        crate::panels::host_list(self, ui);
        crate::panels::details(self, ui);
        crate::canvas::show(self, ui);

        if self.is_scanning() {
            // Keep the spinner and elapsed time moving even between events.
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}
