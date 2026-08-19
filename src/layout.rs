//! Geometric layout for a [`HostGraph`].
//!
//! Both the SVG exporter and the GUI canvas need 2D coordinates for every host.
//! Computing them here means the layout math is written, tuned, and tested once.
//!
//! The algorithm is hierarchical rather than free-floating force-directed: BFS
//! layers from the gateway pin each node's *row*, and a repulsion pass spreads
//! nodes horizontally within their row. Rows carry real meaning here — they are
//! hop distance — so letting a force simulation shuffle them vertically would
//! throw away the most useful thing the scan learned.

use crate::model::{Host, HostGraph};
use crate::renderer::{bfs_layers, build_adjacency, sort_ips};
use std::collections::HashMap;
use std::net::IpAddr;

/// A point in layout space. Layout space is arbitrary units with the origin at
/// the top-left; callers scale it to pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pos {
    pub x: f32,
    pub y: f32,
}

/// Horizontal distance between adjacent nodes in the same row.
pub const NODE_SPACING_X: f32 = 160.0;
/// Vertical distance between hop layers.
pub const LAYER_SPACING_Y: f32 = 110.0;
/// Nodes closer than this repel each other during refinement.
const MIN_SEPARATION: f32 = 120.0;
const REFINE_ITERATIONS: usize = 60;

/// Computed positions plus the bounding box they occupy.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub positions: HashMap<IpAddr, Pos>,
    pub width: f32,
    pub height: f32,
}

impl Layout {
    pub fn get(&self, ip: &IpAddr) -> Option<Pos> {
        self.positions.get(ip).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }
}

/// Lays out every host in `graph`.
///
/// Deterministic: the same graph always produces the same coordinates, which is
/// what lets the SVG output be snapshot-tested and keeps the GUI from jittering
/// when a scan is re-run.
pub fn layout_graph(graph: &HostGraph) -> Layout {
    if graph.hosts.is_empty() {
        return Layout::default();
    }

    let adj = build_adjacency(&graph.edges);
    let root = pick_root(graph);

    // Rows come from hop distance where we know it.
    let (mut layers, visited) = match root {
        Some(r) => bfs_layers(r, &adj, &graph.hosts),
        None => (HashMap::new(), Default::default()),
    };

    // Hosts the BFS never reached (no traceroute edges) still need a row. Prefer
    // their measured hop_distance; otherwise park them one row below the graph.
    let max_layer = layers.values().copied().max().unwrap_or(0);
    let orphan_row = max_layer + 1;
    for (ip, host) in &graph.hosts {
        if !visited.contains(ip) {
            layers.insert(*ip, orphan_layer(host, orphan_row));
        }
    }

    // Group by row, ordered by IP so placement is stable across runs.
    let mut rows: HashMap<usize, Vec<IpAddr>> = HashMap::new();
    for (ip, layer) in &layers {
        rows.entry(*layer).or_default().push(*ip);
    }
    for ips in rows.values_mut() {
        sort_ips(ips);
    }

    let widest = rows.values().map(|r| r.len()).max().unwrap_or(1) as f32;
    let canvas_width = (widest.max(1.0)) * NODE_SPACING_X;

    // Initial placement: each row centred on the canvas.
    let mut positions: HashMap<IpAddr, Pos> = HashMap::new();
    let mut row_keys: Vec<usize> = rows.keys().copied().collect();
    row_keys.sort_unstable();
    for row in &row_keys {
        let ips = &rows[row];
        let span = (ips.len() as f32 - 1.0) * NODE_SPACING_X;
        let start_x = (canvas_width - span) / 2.0;
        for (i, ip) in ips.iter().enumerate() {
            positions.insert(
                *ip,
                Pos {
                    x: start_x + i as f32 * NODE_SPACING_X,
                    y: *row as f32 * LAYER_SPACING_Y,
                },
            );
        }
    }

    refine_horizontally(&mut positions, &rows, &row_keys, &adj);
    normalize(&mut positions)
}

/// The gateway anchors the diagram; without one, fall back to the lowest IP that
/// actually participates in an edge, and finally to the lowest IP overall.
fn pick_root(graph: &HostGraph) -> Option<IpAddr> {
    if let Some(gw) = graph.gateway {
        if graph.hosts.contains_key(&gw) {
            return Some(gw);
        }
    }
    let mut connected: Vec<IpAddr> = graph
        .edges
        .iter()
        .flat_map(|e| [e.from, e.to])
        .filter(|ip| graph.hosts.contains_key(ip))
        .collect();
    if !connected.is_empty() {
        connected.sort_unstable();
        connected.dedup();
        sort_ips(&mut connected);
        return connected.first().copied();
    }
    let mut all: Vec<IpAddr> = graph.hosts.keys().copied().collect();
    sort_ips(&mut all);
    all.first().copied()
}

fn orphan_layer(host: &Host, fallback: usize) -> usize {
    match host.hop_distance {
        Some(d) if d > 0 => d as usize,
        _ => fallback,
    }
}

/// Pulls each node toward the average x of its neighbours (so edges run close to
/// vertical) while pushing apart nodes that would otherwise overlap. Y is fixed,
/// so this can never reorder hop layers.
fn refine_horizontally(
    positions: &mut HashMap<IpAddr, Pos>,
    rows: &HashMap<usize, Vec<IpAddr>>,
    row_keys: &[usize],
    adj: &HashMap<IpAddr, std::collections::BTreeSet<IpAddr>>,
) {
    for _ in 0..REFINE_ITERATIONS {
        let snapshot: HashMap<IpAddr, f32> = positions.iter().map(|(ip, p)| (*ip, p.x)).collect();

        // Attraction: centre each node over its neighbours.
        for (ip, pos) in positions.iter_mut() {
            let Some(neighbours) = adj.get(ip) else {
                continue;
            };
            let xs: Vec<f32> = neighbours
                .iter()
                .filter_map(|n| snapshot.get(n))
                .copied()
                .collect();
            if xs.is_empty() {
                continue;
            }
            let target = xs.iter().sum::<f32>() / xs.len() as f32;
            pos.x += (target - pos.x) * 0.25;
        }

        // Separation: walk each row in x order and enforce a minimum gap.
        for row in row_keys {
            let mut ips = rows[row].clone();
            ips.sort_by(|a, b| {
                positions[a]
                    .x
                    .partial_cmp(&positions[b].x)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.cmp(b))
            });
            for i in 1..ips.len() {
                let prev_x = positions[&ips[i - 1]].x;
                let cur = positions.get_mut(&ips[i]).expect("ip came from this map");
                if cur.x - prev_x < MIN_SEPARATION {
                    cur.x = prev_x + MIN_SEPARATION;
                }
            }
        }
    }
}

/// Shifts everything so the bounding box starts at (0, 0), and reports its size.
fn normalize(positions: &mut HashMap<IpAddr, Pos>) -> Layout {
    let (mut min_x, mut min_y) = (f32::MAX, f32::MAX);
    let (mut max_x, mut max_y) = (f32::MIN, f32::MIN);
    for p in positions.values() {
        min_x = min_x.min(p.x);
        min_y = min_y.min(p.y);
        max_x = max_x.max(p.x);
        max_y = max_y.max(p.y);
    }
    for p in positions.values_mut() {
        p.x -= min_x;
        p.y -= min_y;
    }
    Layout {
        width: (max_x - min_x).max(1.0),
        height: (max_y - min_y).max(1.0),
        positions: std::mem::take(positions),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HopEdge, Host};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn graph_with(hosts: &[&str], edges: &[(&str, &str, u8)], gateway: Option<&str>) -> HostGraph {
        let mut g = HostGraph::empty();
        for h in hosts {
            g.hosts.insert(ip(h), Host::new(ip(h)));
        }
        for (f, t, idx) in edges {
            g.edges.push(HopEdge {
                from: ip(f),
                to: ip(t),
                hop_index: *idx,
            });
        }
        g.gateway = gateway.map(ip);
        g
    }

    #[test]
    fn empty_graph_lays_out_to_nothing() {
        let l = layout_graph(&HostGraph::empty());
        assert!(l.is_empty());
    }

    #[test]
    fn every_host_receives_a_position() {
        let g = graph_with(
            &["192.168.1.1", "192.168.1.10", "192.168.1.22"],
            &[("192.168.1.1", "192.168.1.10", 1)],
            Some("192.168.1.1"),
        );
        let l = layout_graph(&g);
        assert_eq!(l.positions.len(), 3, "orphans must still be placed");
        for h in g.hosts.keys() {
            assert!(l.get(h).is_some(), "{} has no position", h);
        }
    }

    #[test]
    fn hop_distance_becomes_vertical_order() {
        let g = graph_with(
            &["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            &[("10.0.0.1", "10.0.0.2", 1), ("10.0.0.2", "10.0.0.3", 2)],
            Some("10.0.0.1"),
        );
        let l = layout_graph(&g);
        let (a, b, c) = (
            l.get(&ip("10.0.0.1")).unwrap(),
            l.get(&ip("10.0.0.2")).unwrap(),
            l.get(&ip("10.0.0.3")).unwrap(),
        );
        assert!(a.y < b.y && b.y < c.y, "each hop should sit a row lower");
    }

    #[test]
    fn nodes_in_a_row_never_overlap() {
        let leaves: Vec<String> = (2..10).map(|i| format!("10.0.0.{}", i)).collect();
        let mut hosts = vec!["10.0.0.1".to_string()];
        hosts.extend(leaves.clone());
        let host_refs: Vec<&str> = hosts.iter().map(|s| s.as_str()).collect();
        let edge_owned: Vec<(String, String, u8)> = leaves
            .iter()
            .map(|l| ("10.0.0.1".to_string(), l.clone(), 1u8))
            .collect();
        let edge_refs: Vec<(&str, &str, u8)> = edge_owned
            .iter()
            .map(|(f, t, i)| (f.as_str(), t.as_str(), *i))
            .collect();

        let g = graph_with(&host_refs, &edge_refs, Some("10.0.0.1"));
        let l = layout_graph(&g);

        let mut xs: Vec<f32> = leaves.iter().map(|s| l.get(&ip(s)).unwrap().x).collect();
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        for w in xs.windows(2) {
            assert!(
                w[1] - w[0] >= MIN_SEPARATION - 0.5,
                "siblings {} and {} overlap",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn layout_is_deterministic() {
        let g = graph_with(
            &["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            &[("10.0.0.1", "10.0.0.2", 1), ("10.0.0.1", "10.0.0.3", 1)],
            Some("10.0.0.1"),
        );
        let a = layout_graph(&g);
        let b = layout_graph(&g);
        assert_eq!(
            a.positions, b.positions,
            "layout must not vary between runs"
        );
    }

    #[test]
    fn coordinates_are_normalized_to_the_origin() {
        let g = graph_with(
            &["10.0.0.1", "10.0.0.2"],
            &[("10.0.0.1", "10.0.0.2", 1)],
            Some("10.0.0.1"),
        );
        let l = layout_graph(&g);
        let min_x = l.positions.values().map(|p| p.x).fold(f32::MAX, f32::min);
        let min_y = l.positions.values().map(|p| p.y).fold(f32::MAX, f32::min);
        assert!(min_x.abs() < 0.01 && min_y.abs() < 0.01);
        assert!(l.width > 0.0 && l.height > 0.0);
    }

    #[test]
    fn a_graph_with_no_edges_still_places_every_host() {
        let g = graph_with(&["10.0.0.5", "10.0.0.6", "10.0.0.7"], &[], None);
        let l = layout_graph(&g);
        assert_eq!(l.positions.len(), 3);
    }
}
