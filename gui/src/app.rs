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
    /// Built on first use. Constructing a multi-threaded runtime costs real
    /// threads, and a test that only exercises state should not pay for one.
    rt: Option<tokio::runtime::Runtime>,
}

impl NetmapApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Seed the form from the config file so the GUI and CLI agree on defaults.
        Self::from_config(Config::load().unwrap_or_default())
    }

    /// Builds the app from an explicit config, with no eframe context required.
    ///
    /// `new` needs a `CreationContext` to satisfy eframe, but nothing in the app
    /// actually uses it — splitting it out is what lets tests construct a real
    /// app rather than a stand-in that could drift from the shipped one.
    pub fn from_config(cfg: Config) -> Self {
        let opts = cfg.to_scan_options().unwrap_or_default();

        let mut backends = [true; 4];
        for (i, kind) in BackendKind::ALL.iter().enumerate() {
            backends[i] = !opts.skip_backends.contains(kind);
        }

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
            rt: None,
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
        let rt = self.rt.get_or_insert_with(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to start the tokio runtime")
        });
        self.running = Some(scan::spawn(rt, target, opts, ctx.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use netmap::model::{HopEdge, Host, Port, Protocol};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn app() -> NetmapApp {
        NetmapApp::from_config(Config::default())
    }

    // --- form -> ScanOptions ---

    #[test]
    fn unchecked_backends_become_skip_entries() {
        let mut a = app();
        a.backends = [true, false, true, false]; // ip-neigh, arp-scan, nmap, traceroute

        let opts = a.scan_options();

        assert_eq!(
            opts.skip_backends,
            vec![BackendKind::ArpScan, BackendKind::Traceroute],
            "only the unchecked backends should be skipped"
        );
    }

    #[test]
    fn form_fields_map_onto_scan_options() {
        let mut a = app();
        a.sudo = true;
        a.ports = "  1-1024  ".into();
        a.timeout = 42;
        a.max_parallel = 7;
        a.show_off_target = true;

        let opts = a.scan_options();

        assert!(opts.sudo);
        assert_eq!(opts.port_range, "1-1024", "whitespace should be trimmed");
        assert_eq!(opts.timeout_secs, 42);
        assert_eq!(opts.max_parallel, 7);
        assert!(opts.show_off_target);
    }

    #[test]
    fn max_parallel_is_clamped_so_the_semaphore_cannot_deadlock() {
        let mut a = app();
        a.max_parallel = 0;
        assert_eq!(a.scan_options().max_parallel, 1);
    }

    #[test]
    fn the_gui_never_sets_a_stage_timeout() {
        // The GUI has an explicit Cancel button; a second, time-based way for a
        // scan to stop would only make its behaviour less predictable.
        assert_eq!(app().scan_options().stage_timeout_secs, 0);
    }

    #[test]
    fn config_file_values_seed_the_form() {
        let cfg = Config::parse(
            r#"
            target = "10.1.2.0/24"
            sudo = true
            timeout = 15
            max-parallel = 4
            skip = ["nmap"]
            "#,
        )
        .unwrap();

        let a = NetmapApp::from_config(cfg);

        assert_eq!(a.target, "10.1.2.0/24");
        assert!(a.sudo);
        assert_eq!(a.timeout, 15);
        assert_eq!(a.max_parallel, 4);
        assert_eq!(
            a.backends,
            [true, true, false, true],
            "a skipped backend should start unchecked"
        );
    }

    // --- host list filtering ---

    #[test]
    fn the_filter_matches_ip_hostname_vendor_and_role() {
        let mut a = app();
        let mut h1 = Host::new(ip("192.168.1.10"));
        h1.hostname = Some("fileserver".into());
        h1.vendor = Some("Ubiquiti Inc".into());
        h1.role = netmap::model::DeviceRole::Server;

        let mut h2 = Host::new(ip("192.168.1.99"));
        h2.role = netmap::model::DeviceRole::Workstation;

        a.graph.hosts.insert(h1.ip, h1);
        a.graph.hosts.insert(h2.ip, h2);

        assert_eq!(
            a.visible_hosts().len(),
            2,
            "an empty filter shows everything"
        );

        for needle in ["fileserver", "UBIQUITI", "server", ".10"] {
            a.filter = needle.into();
            let visible = a.visible_hosts();
            assert_eq!(
                visible,
                vec![ip("192.168.1.10")],
                "filter {:?} failed",
                needle
            );
        }

        a.filter = "nonexistent".into();
        assert!(a.visible_hosts().is_empty());
    }

    #[test]
    fn the_host_list_is_ordered_numerically_not_lexically() {
        let mut a = app();
        for addr in ["192.168.1.100", "192.168.1.9", "192.168.1.20"] {
            a.graph.hosts.insert(ip(addr), Host::new(ip(addr)));
        }

        assert_eq!(
            a.visible_hosts(),
            vec![ip("192.168.1.9"), ip("192.168.1.20"), ip("192.168.1.100")],
            "string ordering would put .100 before .20"
        );
    }

    // --- synthetic topology detection ---

    #[test]
    fn a_star_around_the_gateway_is_reported_as_inferred() {
        let mut a = app();
        let gw = ip("10.0.0.1");
        a.graph.gateway = Some(gw);
        for last in [2u8, 3, 4] {
            let h = ip(&format!("10.0.0.{last}"));
            a.graph.hosts.insert(h, Host::new(h));
            a.graph.edges.push(HopEdge {
                from: gw,
                to: h,
                hop_index: 1,
            });
        }
        a.graph.hosts.insert(gw, Host::new(gw));

        assert!(
            a.topology_is_synthetic(),
            "every edge is hop 1 from the gateway"
        );
    }

    #[test]
    fn a_measured_multi_hop_topology_is_not_flagged_as_inferred() {
        let mut a = app();
        let gw = ip("10.0.0.1");
        a.graph.gateway = Some(gw);
        for addr in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"] {
            a.graph.hosts.insert(ip(addr), Host::new(ip(addr)));
        }
        a.graph.edges.push(HopEdge {
            from: gw,
            to: ip("10.0.0.2"),
            hop_index: 1,
        });
        // A second hop means traceroute actually measured depth.
        a.graph.edges.push(HopEdge {
            from: ip("10.0.0.2"),
            to: ip("10.0.0.3"),
            hop_index: 2,
        });

        assert!(!a.topology_is_synthetic());
    }

    // --- event pump ---

    /// Drives `pump_events` with a scripted event stream, standing in for a
    /// running scan without touching the network.
    fn pump(a: &mut NetmapApp, events: Vec<ScanEvent>) {
        let (tx, rx) = std::sync::mpsc::channel();
        for e in events {
            tx.send(e).unwrap();
        }
        drop(tx);
        a.running = Some(crate::scan::RunningScan {
            events: rx,
            cancel: tokio_util::sync::CancellationToken::new(),
            started: std::time::Instant::now(),
        });
        a.phase = Phase::Scanning;
        a.pump_events();
    }

    #[test]
    fn discovered_hosts_appear_incrementally() {
        let mut a = app();
        pump(
            &mut a,
            vec![
                ScanEvent::HostDiscovered(Box::new(Host::new(ip("10.0.0.5")))),
                ScanEvent::HostDiscovered(Box::new(Host::new(ip("10.0.0.6")))),
            ],
        );

        assert_eq!(
            a.graph.hosts.len(),
            2,
            "hosts should land before Complete arrives"
        );
    }

    #[test]
    fn a_host_update_replaces_rather_than_duplicates() {
        let mut a = app();
        let mut updated = Host::new(ip("10.0.0.5"));
        updated.open_ports.push(Port {
            number: 22,
            protocol: Protocol::Tcp,
            service: Some("ssh".into()),
        });

        pump(
            &mut a,
            vec![
                ScanEvent::HostDiscovered(Box::new(Host::new(ip("10.0.0.5")))),
                ScanEvent::HostUpdated(Box::new(updated)),
            ],
        );

        assert_eq!(a.graph.hosts.len(), 1);
        assert_eq!(a.graph.hosts[&ip("10.0.0.5")].open_ports.len(), 1);
    }

    #[test]
    fn the_complete_event_replaces_the_incremental_graph() {
        // Only the final graph is CIDR-filtered, gateway-resolved and
        // role-annotated, so merging into it would resurrect filtered hosts.
        let mut a = app();
        let mut final_graph = HostGraph::empty();
        final_graph
            .hosts
            .insert(ip("10.0.0.9"), Host::new(ip("10.0.0.9")));

        pump(
            &mut a,
            vec![
                ScanEvent::HostDiscovered(Box::new(Host::new(ip("172.17.0.1")))),
                ScanEvent::Complete(Box::new(final_graph)),
            ],
        );

        assert_eq!(a.phase, Phase::Done);
        assert_eq!(a.graph.hosts.len(), 1);
        assert!(
            a.graph.hosts.contains_key(&ip("10.0.0.9")),
            "the off-target host should be gone, not merged back in"
        );
        assert!(
            a.elapsed.is_some(),
            "a finished scan should report its duration"
        );
    }

    #[test]
    fn cancellation_is_reported_without_claiming_completion() {
        let mut a = app();
        pump(&mut a, vec![ScanEvent::Cancelled]);

        assert_eq!(a.phase, Phase::Cancelled);
        assert!(a.elapsed.is_some());
        assert!(
            a.log.iter().any(|l| l.to_lowercase().contains("cancel")),
            "the user should be told the results are partial"
        );
    }

    #[test]
    fn warnings_reach_the_log() {
        let mut a = app();
        pump(
            &mut a,
            vec![ScanEvent::Warning("arp-scan needs root".into())],
        );
        assert!(a.log.iter().any(|l| l.contains("arp-scan needs root")));
    }

    #[test]
    fn per_host_progress_is_tracked_and_cleared_when_a_stage_ends() {
        let mut a = app();
        pump(
            &mut a,
            vec![ScanEvent::HostProgress {
                kind: BackendKind::Nmap,
                done: 3,
                total: 10,
            }],
        );
        assert_eq!(a.progress, Some((3, 10)));

        pump(
            &mut a,
            vec![ScanEvent::StageFinished {
                kind: BackendKind::Nmap,
                elapsed_ms: 120,
                found: 3,
            }],
        );
        assert_eq!(a.progress, None, "a finished stage should clear the bar");
    }

    #[test]
    fn a_scan_that_dies_without_a_final_event_still_leaves_scanning_state() {
        // The channel closing is the only signal that a failed scan has ended.
        let mut a = app();
        pump(&mut a, vec![]);

        assert_ne!(a.phase, Phase::Scanning, "the UI must not spin forever");
        assert!(a.running.is_none());
    }

    // --- misc state ---

    #[test]
    fn the_log_is_bounded() {
        let mut a = app();
        for i in 0..(LOG_CAPACITY + 50) {
            a.push_log(format!("line {i}"));
        }
        assert_eq!(
            a.log.len(),
            LOG_CAPACITY,
            "a long scan must not grow without limit"
        );
        assert!(
            a.log
                .back()
                .unwrap()
                .contains(&format!("line {}", LOG_CAPACITY + 49)),
            "the newest line should survive"
        );
    }

    #[test]
    fn relayout_forgets_pins_for_hosts_that_are_gone() {
        let mut a = app();
        a.graph
            .hosts
            .insert(ip("10.0.0.1"), Host::new(ip("10.0.0.1")));
        a.pinned.insert(ip("10.0.0.1"), egui::Pos2::new(1.0, 2.0));
        a.pinned.insert(ip("10.0.0.99"), egui::Pos2::new(3.0, 4.0));

        a.relayout();

        assert!(a.pinned.contains_key(&ip("10.0.0.1")));
        assert!(
            !a.pinned.contains_key(&ip("10.0.0.99")),
            "a pin for a vanished host would leak forever"
        );
    }

    #[test]
    fn scanning_with_an_empty_target_is_refused() {
        let mut a = app();
        a.target = "   ".into();
        let ctx = egui::Context::default();

        a.start_scan(&ctx);

        assert_eq!(
            a.phase,
            Phase::Idle,
            "an empty target must not start a scan"
        );
        assert!(a.log.iter().any(|l| l.contains("no target")));
    }
}
