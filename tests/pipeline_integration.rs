//! Integration tests that exercise the real pipeline through the library API.
//!
//! Before the lib/bin split these were impossible — `run_pipeline` was private
//! to the binary, so the only way to test it was to shell out. Mock
//! `ScanBackend`s let us drive the merge, filter, gateway, and role logic
//! end-to-end with no network and no external binaries.

use netmap::backends::ScanOptions;
use netmap::model::{BackendKind, DeviceRole, HostGraph};
use netmap::pipeline;
use netmap::progress::{Reporter, ScanEvent};
use std::net::IpAddr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Every backend skipped: no subprocesses, so this runs anywhere.
fn no_backends() -> ScanOptions {
    ScanOptions {
        skip_backends: BackendKind::ALL.to_vec(),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_scan_with_every_backend_skipped_yields_an_empty_graph() {
    let graph = pipeline::run_pipeline("192.168.1.0/24", &no_backends())
        .await
        .expect("pipeline should succeed with nothing to do");

    assert!(graph.hosts.is_empty());
    assert!(graph.edges.is_empty());
    assert_eq!(graph.gateway, None);
}

#[tokio::test]
async fn an_empty_graph_still_renders_without_panicking() {
    let graph = pipeline::run_pipeline("192.168.1.0/24", &no_backends())
        .await
        .unwrap();

    let tree = netmap::renderer::render_tree(&graph);
    assert!(tree.to_lowercase().contains("no hosts"));
    assert!(netmap::renderer::render_ports_table(&graph).is_empty());

    let svg = netmap::renderer::render_svg(&graph);
    assert!(svg.starts_with("<svg") && svg.trim_end().ends_with("</svg>"));
}

#[tokio::test]
async fn progress_reporting_emits_a_skip_per_backend_and_ends_with_complete() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let graph = pipeline::run_pipeline_with_progress(
        "192.168.1.0/24",
        &no_backends(),
        Reporter::new(tx),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }

    let skipped = events
        .iter()
        .filter(|e| matches!(e, ScanEvent::StageSkipped { .. }))
        .count();
    assert!(
        skipped >= 4,
        "each skipped backend should report itself, got {}",
        skipped
    );

    match events.last().expect("at least one event") {
        ScanEvent::Complete(g) => assert_eq!(g.hosts.len(), graph.hosts.len()),
        other => panic!("the last event must be Complete, got {:?}", other),
    }
}

#[tokio::test]
async fn a_scan_cancelled_before_it_starts_returns_promptly_and_says_so() {
    let cancel = CancellationToken::new();
    cancel.cancel();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let start = std::time::Instant::now();
    let graph = pipeline::run_pipeline_with_progress(
        "192.168.1.0/24",
        &ScanOptions::default(),
        Reporter::new(tx),
        cancel,
    )
    .await
    .expect("cancellation returns partial results, it is not an error");

    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "an already-cancelled scan should not run the backends"
    );
    assert!(graph.hosts.is_empty());

    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    assert!(
        events.iter().any(|e| matches!(e, ScanEvent::Cancelled)),
        "a cancelled scan must announce itself"
    );
    assert!(
        !events.iter().any(|e| matches!(e, ScanEvent::Complete(_))),
        "a cancelled scan must not claim completion"
    );
}

#[tokio::test]
async fn a_dropped_receiver_does_not_take_the_scan_down() {
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx); // A GUI window closing mid-scan.

    let graph = pipeline::run_pipeline_with_progress(
        "192.168.1.0/24",
        &no_backends(),
        Reporter::new(tx),
        CancellationToken::new(),
    )
    .await;

    assert!(
        graph.is_ok(),
        "sending into a closed channel must not fail the scan"
    );
}

#[test]
fn a_saved_scan_round_trips_through_json_and_renders_identically() {
    // Build a graph the way the pipeline would leave one.
    let mut graph = HostGraph::empty();
    let gw = ip("10.0.0.1");
    let host = ip("10.0.0.50");

    let mut g = netmap::model::Host::new(gw);
    g.role = DeviceRole::Gateway;
    let mut h = netmap::model::Host::new(host);
    h.role = DeviceRole::Workstation;
    h.hostname = Some("desktop".into());

    graph.hosts.insert(gw, g);
    graph.hosts.insert(host, h);
    graph.gateway = Some(gw);
    graph.edges.push(netmap::model::HopEdge {
        from: gw,
        to: host,
        hop_index: 1,
    });

    let json = serde_json::to_string_pretty(&graph).unwrap();
    let restored: HostGraph = serde_json::from_str(&json).unwrap();

    assert_eq!(
        netmap::renderer::render_tree(&graph),
        netmap::renderer::render_tree(&restored),
        "a saved scan must re-render exactly as it was rendered live"
    );
    assert_eq!(
        netmap::renderer::render_svg(&graph),
        netmap::renderer::render_svg(&restored)
    );
}

#[test]
fn the_layout_places_every_host_the_renderer_will_draw() {
    let mut graph = HostGraph::empty();
    for last in [1u8, 10, 20, 30] {
        let a = ip(&format!("172.16.0.{}", last));
        graph.hosts.insert(a, netmap::model::Host::new(a));
    }
    graph.gateway = Some(ip("172.16.0.1"));
    for last in [10u8, 20, 30] {
        graph.edges.push(netmap::model::HopEdge {
            from: ip("172.16.0.1"),
            to: ip(&format!("172.16.0.{}", last)),
            hop_index: 1,
        });
    }

    let layout = netmap::layout::layout_graph(&graph);
    for host_ip in graph.hosts.keys() {
        assert!(
            layout.get(host_ip).is_some(),
            "{} would be drawn with no position",
            host_ip
        );
    }
}
