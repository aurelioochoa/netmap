use crate::model::{Host, HostGraph, HopEdge};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// Render the HostGraph as a 2D ASCII topology map.
pub fn render_tree(graph: &HostGraph) -> String {
    if graph.hosts.is_empty() {
        return "(no hosts discovered)\n".to_string();
    }

    // Build undirected adjacency from edges
    let adj = build_adjacency(&graph.edges);

    // Determine root for BFS layering
    let root_ip = graph.gateway.or_else(|| {
        graph.hosts.keys().copied().next()
    });

    let root_ip = match root_ip {
        Some(ip) => ip,
        None => return "(no hosts discovered)\n".to_string(),
    };

    // BFS to assign layers
    let (layers, connected) = bfs_layers(root_ip, &adj, &graph.hosts);

    // Hosts not reached by BFS (no edges)
    let orphans: Vec<IpAddr> = graph.hosts.keys()
        .filter(|ip| !connected.contains(ip))
        .copied()
        .collect();

    // Build the 2D grid
    let mut grid_rows: Vec<Vec<IpAddr>> = Vec::new();

    // Add "Internet" virtual row if we have a gateway
    let has_internet_row = graph.gateway.is_some();

    if !layers.is_empty() {
        let max_layer = layers.values().copied().max().unwrap_or(0);
        for layer in 0..=max_layer {
            let mut row: Vec<IpAddr> = layers.iter()
                .filter(|(_, &l)| l == layer)
                .map(|(&ip, _)| ip)
                .collect();
            sort_ips(&mut row);
            grid_rows.push(row);
        }
    }

    // Render into a character canvas
    let mut output = String::new();

    if has_internet_row {
        // Find width of first row to center "Internet"
        let first_row_labels: Vec<String> = if !grid_rows.is_empty() {
            grid_rows[0].iter().map(|ip| node_label(graph, *ip)).collect()
        } else {
            vec![]
        };
        let first_row_width = row_width(&first_row_labels);
        let internet_label = "Internet";
        let pad = if first_row_width > internet_label.len() {
            (first_row_width - internet_label.len()) / 2
        } else {
            0
        };
        output.push_str(&" ".repeat(pad));
        output.push_str(internet_label);
        output.push('\n');

        // Vertical connector to gateway
        if !grid_rows.is_empty() {
            let gw_row_labels: Vec<String> = grid_rows[0].iter().map(|ip| node_label(graph, *ip)).collect();
            let gw_idx = grid_rows[0].iter().position(|&ip| ip == root_ip).unwrap_or(0);
            let gw_center = node_center_offset(&gw_row_labels, gw_idx);
            output.push_str(&" ".repeat(gw_center));
            output.push('|');
            output.push('\n');
        }
    }

    // Render each layer row
    for (row_idx, row) in grid_rows.iter().enumerate() {
        let labels: Vec<String> = row.iter().map(|ip| node_label(graph, *ip)).collect();

        // Print nodes connected with " - "
        let row_str = labels.join(" - ");
        // Center if narrower than previous rows
        output.push_str(&row_str);
        output.push('\n');

        // Vertical connectors to next row
        if row_idx + 1 < grid_rows.len() {
            let next_row = &grid_rows[row_idx + 1];
            let connector_line = build_vertical_connectors(row, &labels, next_row, &adj);
            if !connector_line.is_empty() {
                output.push_str(&connector_line);
                output.push('\n');
            }
        }
    }

    // Orphan hosts (no edges)
    if !orphans.is_empty() {
        if !grid_rows.is_empty() {
            output.push('\n');
        }
        let mut sorted_orphans = orphans;
        sort_ips(&mut sorted_orphans);
        for ip in &sorted_orphans {
            output.push_str(&node_label(graph, *ip));
            output.push('\n');
        }
    }

    output
}

fn build_adjacency(edges: &[HopEdge]) -> HashMap<IpAddr, BTreeSet<IpAddr>> {
    let mut adj: HashMap<IpAddr, BTreeSet<IpAddr>> = HashMap::new();
    for edge in edges {
        adj.entry(edge.from).or_default().insert(edge.to);
        adj.entry(edge.to).or_default().insert(edge.from);
    }
    adj
}

fn bfs_layers(
    root: IpAddr,
    adj: &HashMap<IpAddr, BTreeSet<IpAddr>>,
    hosts: &HashMap<IpAddr, Host>,
) -> (HashMap<IpAddr, usize>, HashSet<IpAddr>) {
    let mut layers: HashMap<IpAddr, usize> = HashMap::new();
    let mut visited: HashSet<IpAddr> = HashSet::new();
    let mut queue: VecDeque<(IpAddr, usize)> = VecDeque::new();

    // Only add root if it's in hosts
    if hosts.contains_key(&root) {
        layers.insert(root, 0);
        visited.insert(root);
        queue.push_back((root, 0));
    }

    while let Some((ip, layer)) = queue.pop_front() {
        if let Some(neighbors) = adj.get(&ip) {
            for &neighbor in neighbors {
                if !visited.contains(&neighbor) && hosts.contains_key(&neighbor) {
                    visited.insert(neighbor);
                    layers.insert(neighbor, layer + 1);
                    queue.push_back((neighbor, layer + 1));
                }
            }
        }
    }

    (layers, visited)
}

fn node_label(graph: &HostGraph, ip: IpAddr) -> String {
    if let Some(host) = graph.hosts.get(&ip) {
        let role_str = format!("{}", host.role);
        let mut label = role_str;

        if let Some(ref name) = host.hostname {
            label = format!("{} ({})", label, name);
        }

        // Append top 3 ports
        let port_strs: Vec<String> = host.open_ports.iter()
            .take(3)
            .map(|p| format!(":{}", p.number))
            .collect();
        if !port_strs.is_empty() {
            label = format!("{} {}", label, port_strs.join(" "));
        }

        label
    } else {
        format!("{}", ip)
    }
}

fn node_center_offset(labels: &[String], idx: usize) -> usize {
    let mut offset = 0;
    for (i, label) in labels.iter().enumerate() {
        if i == idx {
            return offset + label.len() / 2;
        }
        offset += label.len() + 3; // " - " separator
    }
    offset
}

fn row_width(labels: &[String]) -> usize {
    if labels.is_empty() {
        return 0;
    }
    let total_label_len: usize = labels.iter().map(|l| l.len()).sum();
    total_label_len + (labels.len() - 1) * 3 // " - " separators
}

fn build_vertical_connectors(
    current_row: &[IpAddr],
    current_labels: &[String],
    next_row: &[IpAddr],
    adj: &HashMap<IpAddr, BTreeSet<IpAddr>>,
) -> String {
    // Find which nodes in current_row connect to nodes in next_row
    let mut connector_positions: Vec<usize> = Vec::new();

    for (idx, &ip) in current_row.iter().enumerate() {
        if let Some(neighbors) = adj.get(&ip) {
            let connects_down = next_row.iter().any(|next_ip| neighbors.contains(next_ip));
            if connects_down {
                let center = node_center_offset(current_labels, idx);
                connector_positions.push(center);
            }
        }
    }

    if connector_positions.is_empty() {
        return String::new();
    }

    let max_pos = connector_positions.iter().copied().max().unwrap_or(0);
    let mut line = vec![' '; max_pos + 1];
    for pos in &connector_positions {
        if *pos < line.len() {
            line[*pos] = '|';
        }
    }

    line.iter().collect::<String>().trim_end().to_string()
}

fn sort_ips(ips: &mut Vec<IpAddr>) {
    ips.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Host, HostGraph, HopEdge, Port, Protocol, DeviceRole, BackendKind};
    use std::collections::HashMap;

    fn make_host(ip: &str, role: DeviceRole, hostname: Option<&str>, ports: Vec<u16>) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            mac: None,
            hostname: hostname.map(|s| s.to_string()),
            vendor: None,
            open_ports: ports.into_iter().map(|p| Port {
                number: p,
                protocol: Protocol::Tcp,
                service: None,
            }).collect(),
            os_guess: None,
            role,
            detected_by: vec![BackendKind::Nmap],
            hop_distance: None,
        }
    }

    #[test]
    fn test_render_empty_graph() {
        let graph = HostGraph::empty();
        let output = render_tree(&graph);
        assert_eq!(output, "(no hosts discovered)\n");
    }

    #[test]
    fn test_render_single_host() {
        let host = make_host("192.168.1.1", DeviceRole::Gateway, Some("router.local"), vec![]);
        let mut hosts = HashMap::new();
        hosts.insert(host.ip, host);

        let graph = HostGraph {
            hosts,
            edges: Vec::new(),
            gateway: Some("192.168.1.1".parse().unwrap()),
        };

        let output = render_tree(&graph);
        assert!(output.contains("Internet"));
        assert!(output.contains("router"));
        assert!(output.contains("router.local"));
    }

    #[test]
    fn test_render_linear_chain() {
        let gw = make_host("192.168.1.1", DeviceRole::Gateway, None, vec![]);
        let sw = make_host("192.168.1.2", DeviceRole::Switch, None, vec![]);
        let srv = make_host("192.168.1.10", DeviceRole::Server, Some("web"), vec![80]);

        let mut hosts = HashMap::new();
        hosts.insert(gw.ip, gw);
        hosts.insert(sw.ip, sw);
        hosts.insert(srv.ip, srv);

        let edges = vec![
            HopEdge { from: "192.168.1.1".parse().unwrap(), to: "192.168.1.2".parse().unwrap(), hop_index: 1 },
            HopEdge { from: "192.168.1.2".parse().unwrap(), to: "192.168.1.10".parse().unwrap(), hop_index: 2 },
        ];

        let graph = HostGraph {
            hosts,
            edges,
            gateway: Some("192.168.1.1".parse().unwrap()),
        };

        let output = render_tree(&graph);
        assert!(output.contains("Internet"));
        assert!(output.contains("router"));
        assert!(output.contains("switch"));
        assert!(output.contains("server"));
        assert!(output.contains("|"));
    }

    #[test]
    fn test_render_branching_topology() {
        let gw = make_host("192.168.1.1", DeviceRole::Gateway, None, vec![]);
        let srv = make_host("192.168.1.10", DeviceRole::Server, None, vec![80]);
        let pc = make_host("192.168.1.20", DeviceRole::Workstation, None, vec![]);

        let mut hosts = HashMap::new();
        hosts.insert(gw.ip, gw);
        hosts.insert(srv.ip, srv);
        hosts.insert(pc.ip, pc);

        let edges = vec![
            HopEdge { from: "192.168.1.1".parse().unwrap(), to: "192.168.1.10".parse().unwrap(), hop_index: 1 },
            HopEdge { from: "192.168.1.1".parse().unwrap(), to: "192.168.1.20".parse().unwrap(), hop_index: 1 },
        ];

        let graph = HostGraph {
            hosts,
            edges,
            gateway: Some("192.168.1.1".parse().unwrap()),
        };

        let output = render_tree(&graph);
        assert!(output.contains("router"));
        assert!(output.contains("server"));
        assert!(output.contains("workstation"));
        // Both children on same layer connected with " - "
        assert!(output.contains(" - "));
    }

    #[test]
    fn test_render_orphan_hosts() {
        let gw = make_host("192.168.1.1", DeviceRole::Gateway, None, vec![]);
        let orphan = make_host("10.0.0.5", DeviceRole::Unknown, Some("mystery"), vec![]);

        let mut hosts = HashMap::new();
        hosts.insert(gw.ip, gw);
        hosts.insert(orphan.ip, orphan);

        let graph = HostGraph {
            hosts,
            edges: Vec::new(),
            gateway: Some("192.168.1.1".parse().unwrap()),
        };

        let output = render_tree(&graph);
        // Gateway still renders
        assert!(output.contains("router"));
        // Orphan appears separately
        assert!(output.contains("unknown"));
        assert!(output.contains("mystery"));
    }

    #[test]
    fn test_render_full_diagram_snapshot() {
        // Build an extended topology:
        //
        //                        Internet
        //                            |
        //                         router
        //                            |
        //                         switch
        //                            |
        //       wap/switch - wap/switch (mesh-ap) - server :80 :443
        //           |               |
        //       wap/switch - workstation (tower) - workstation (desktop)
        //           |               |
        //       server :22 :8080 - workstation (laptop)
        //
        let router = make_host("192.168.1.1", DeviceRole::Gateway, None, vec![]);
        let switch = make_host("192.168.1.2", DeviceRole::Switch, None, vec![]);
        let wap1 = make_host("192.168.1.3", DeviceRole::WirelessAP, None, vec![]);
        let wap2 = make_host("192.168.1.4", DeviceRole::WirelessAP, None, vec![]);
        let wap3 = make_host("192.168.1.5", DeviceRole::WirelessAP, Some("mesh-ap"), vec![]);
        let server = make_host("192.168.1.10", DeviceRole::Server, None, vec![80, 443]);
        let pc_tower = make_host("192.168.1.15", DeviceRole::Workstation, Some("tower"), vec![]);
        let server2 = make_host("192.168.1.16", DeviceRole::Server, None, vec![22, 8080]);
        let pc_desktop = make_host("192.168.1.20", DeviceRole::Workstation, Some("desktop"), vec![]);
        let pc_laptop = make_host("192.168.1.21", DeviceRole::Workstation, Some("laptop"), vec![]);

        let mut hosts = HashMap::new();
        hosts.insert(router.ip, router);
        hosts.insert(switch.ip, switch);
        hosts.insert(wap1.ip, wap1);
        hosts.insert(wap2.ip, wap2);
        hosts.insert(wap3.ip, wap3);
        hosts.insert(server.ip, server);
        hosts.insert(pc_tower.ip, pc_tower);
        hosts.insert(server2.ip, server2);
        hosts.insert(pc_desktop.ip, pc_desktop);
        hosts.insert(pc_laptop.ip, pc_laptop);

        let edges = vec![
            // router -> switch
            HopEdge { from: "192.168.1.1".parse().unwrap(), to: "192.168.1.2".parse().unwrap(), hop_index: 1 },
            // switch -> wap1
            HopEdge { from: "192.168.1.2".parse().unwrap(), to: "192.168.1.3".parse().unwrap(), hop_index: 2 },
            // switch -> wap3 (mesh-ap)
            HopEdge { from: "192.168.1.2".parse().unwrap(), to: "192.168.1.5".parse().unwrap(), hop_index: 2 },
            // switch -> server
            HopEdge { from: "192.168.1.2".parse().unwrap(), to: "192.168.1.10".parse().unwrap(), hop_index: 2 },
            // wap1 -> wap2
            HopEdge { from: "192.168.1.3".parse().unwrap(), to: "192.168.1.4".parse().unwrap(), hop_index: 3 },
            // wap1 -> pc_desktop
            HopEdge { from: "192.168.1.3".parse().unwrap(), to: "192.168.1.20".parse().unwrap(), hop_index: 3 },
            // wap3 -> pc_tower (left of desktop)
            HopEdge { from: "192.168.1.5".parse().unwrap(), to: "192.168.1.15".parse().unwrap(), hop_index: 3 },
            // pc_tower -> server2 (down from tower)
            HopEdge { from: "192.168.1.15".parse().unwrap(), to: "192.168.1.16".parse().unwrap(), hop_index: 4 },
            // wap2 -> pc_laptop
            HopEdge { from: "192.168.1.4".parse().unwrap(), to: "192.168.1.21".parse().unwrap(), hop_index: 4 },
        ];

        let graph = HostGraph {
            hosts,
            edges,
            gateway: Some("192.168.1.1".parse().unwrap()),
        };

        let output = render_tree(&graph);
        let lines: Vec<&str> = output.lines().collect();

        // Print actual output for debugging
        eprintln!("--- Rendered diagram ---\n{}\n--- End ---", output);

        // Line 0: "Internet" header
        assert!(lines[0].trim() == "Internet", "Expected 'Internet', got: '{}'", lines[0]);

        // Line 1: vertical connector "|"
        assert!(lines[1].contains('|'), "Expected '|' connector, got: '{}'", lines[1]);

        // Line 2: router (layer 0)
        assert!(lines[2].contains("router"), "Expected 'router', got: '{}'", lines[2]);

        // Line 3: vertical connector
        assert!(lines[3].contains('|'), "Expected '|' connector, got: '{}'", lines[3]);

        // Line 4: switch (layer 1)
        assert!(lines[4].contains("switch"), "Expected 'switch', got: '{}'", lines[4]);

        // Line 5: vertical connector
        assert!(lines[5].contains('|'), "Expected '|' connector, got: '{}'", lines[5]);

        // Line 6: layer 2 — wap1, wap3 (mesh-ap), server — three nodes
        assert!(lines[6].contains("wap/switch"), "Expected 'wap/switch', got: '{}'", lines[6]);
        assert!(lines[6].contains("mesh-ap"), "Expected 'mesh-ap', got: '{}'", lines[6]);
        assert!(lines[6].contains("server"), "Expected 'server', got: '{}'", lines[6]);
        assert!(lines[6].contains(":80"), "Expected ':80', got: '{}'", lines[6]);

        // Line 7: vertical connectors (wap1 and wap3 connect down)
        assert!(lines[7].contains('|'), "Expected '|' connector, got: '{}'", lines[7]);

        // Line 8: layer 3 — wap2, tower, desktop — three nodes
        assert!(lines[8].contains("wap/switch"), "Expected 'wap/switch', got: '{}'", lines[8]);
        assert!(lines[8].contains("tower"), "Expected 'tower', got: '{}'", lines[8]);
        assert!(lines[8].contains("desktop"), "Expected 'desktop', got: '{}'", lines[8]);

        // Line 9: vertical connectors (wap2 and tower connect down)
        assert!(lines[9].contains('|'), "Expected '|' connector, got: '{}'", lines[9]);

        // Line 10: layer 4 — server2 and laptop
        assert!(lines[10].contains("server"), "Expected 'server', got: '{}'", lines[10]);
        assert!(lines[10].contains(":22"), "Expected ':22', got: '{}'", lines[10]);
        assert!(lines[10].contains("laptop"), "Expected 'laptop', got: '{}'", lines[10]);

        // Verify total structure: 11 lines
        assert!(lines.len() == 11, "Expected 11 lines, got {}: {:?}", lines.len(), lines);
    }

    #[test]
    fn test_render_no_edges_no_gateway() {
        let h1 = make_host("192.168.1.5", DeviceRole::Unknown, None, vec![]);
        let h2 = make_host("192.168.1.6", DeviceRole::Unknown, None, vec![]);

        let mut hosts = HashMap::new();
        hosts.insert(h1.ip, h1);
        hosts.insert(h2.ip, h2);

        let graph = HostGraph {
            hosts,
            edges: Vec::new(),
            gateway: None,
        };

        let output = render_tree(&graph);
        assert!(output.contains("unknown"));
        // No "Internet" header without gateway
        assert!(!output.contains("Internet"));
    }
}
