use crate::backends::arp_scan::ArpScanBackend;
use crate::backends::ip_neigh::IpNeighBackend;
use crate::backends::nmap::{self, NmapBackend};
use crate::backends::traceroute::{self, TracerouteBackend};
use crate::backends::{ScanBackend, ScanOptions, ScanResult, PartialHost};
use crate::model::{BackendKind, DeviceRole, HopEdge, Host, HostGraph};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Run the full scan pipeline and return a merged HostGraph.
pub async fn run_pipeline(target: &str, opts: &ScanOptions) -> Result<HostGraph> {
    let pipeline_start = Instant::now();
    let mut graph = HostGraph::empty();

    // Stage 1: ip neigh
    if opts.skip_backends.contains(&BackendKind::IpNeigh) {
        tracing::info!("stage ip-neigh: skipped (--skip)");
    } else {
        run_stage(&IpNeighBackend::new(), target, opts, &mut graph).await;
    }

    // Stage 2: arp-scan
    if opts.skip_backends.contains(&BackendKind::ArpScan) {
        tracing::info!("stage arp-scan: skipped (--skip)");
    } else {
        run_stage(&ArpScanBackend::new(), target, opts, &mut graph).await;
    }

    // Stage 3: nmap discovery
    if opts.skip_backends.contains(&BackendKind::Nmap) {
        tracing::info!("stage nmap-discovery: skipped (--skip)");
    } else {
        run_stage(&NmapBackend::new(), target, opts, &mut graph).await;
    }

    // Stage 4: nmap fingerprint (per host)
    if opts.skip_backends.contains(&BackendKind::Nmap) {
        tracing::info!("stage nmap-fingerprint: skipped (--skip)");
    } else if !NmapBackend::new().is_available() {
        tracing::warn!("stage nmap-fingerprint: nmap binary not found, skipping");
    } else {
        let ips: Vec<IpAddr> = graph.hosts.keys().copied().collect();
        if ips.is_empty() {
            tracing::info!("stage nmap-fingerprint: no hosts discovered yet, skipping");
        } else {
            let stage_start = Instant::now();
            tracing::info!(
                hosts = ips.len(),
                max_parallel = opts.max_parallel,
                "stage nmap-fingerprint: starting"
            );
            match nmap::run_nmap_fingerprint_all(&ips, opts).await {
                Ok(result) => {
                    let host_count = result.hosts.len();
                    merge_result(&mut graph, result, true);
                    tracing::info!(
                        fingerprinted = host_count,
                        elapsed_ms = stage_start.elapsed().as_millis() as u64,
                        "stage nmap-fingerprint: done"
                    );
                }
                Err(e) => tracing::warn!("stage nmap-fingerprint failed: {}", e),
            }
        }
    }

    // Stage 5: traceroute (per host)
    if opts.skip_backends.contains(&BackendKind::Traceroute) {
        tracing::info!("stage traceroute: skipped (--skip)");
    } else if !TracerouteBackend::new().is_available() {
        tracing::warn!("stage traceroute: traceroute binary not found, skipping");
    } else {
        let ips: Vec<IpAddr> = graph.hosts.keys().copied().collect();
        if ips.is_empty() {
            tracing::info!("stage traceroute: no hosts discovered, skipping");
        } else {
            let stage_start = Instant::now();
            tracing::info!(
                hosts = ips.len(),
                max_parallel = opts.max_parallel,
                "stage traceroute: starting"
            );
            match traceroute::run_traceroute_all(&ips, opts).await {
                Ok(result) => {
                    let edge_count = result.edges.len();
                    let host_count = result.hosts.len();
                    graph.edges.extend(result.edges.clone());
                    merge_result(&mut graph, result, false);
                    tracing::info!(
                        edges = edge_count,
                        hosts = host_count,
                        elapsed_ms = stage_start.elapsed().as_millis() as u64,
                        "stage traceroute: done"
                    );
                }
                Err(e) => tracing::warn!("stage traceroute failed: {}", e),
            }
        }
    }

    // Filter off-target hosts (docker bridge / IPv6 link-local / ULA leaked via
    // `ip neigh`) so they don't pollute the graph. Skipped when the target is
    // not a CIDR (bare IP or hostname) or when --show-off-target is set.
    if !opts.show_off_target {
        if let Some((network, prefix)) = parse_cidr(target) {
            apply_cidr_filter(&mut graph, network, prefix);
        }
    }

    // Detect gateway from edges
    graph.gateway = traceroute::detect_gateway(&graph.edges);
    if let Some(gw) = graph.gateway {
        tracing::info!(gateway = %gw, "gateway detected from edges");
    } else {
        tracing::debug!("no gateway detected from edges, trying CIDR fallback");
        // Fallback 1: when target is a CIDR, look for <network>.1
        if let Some((network, prefix)) = parse_cidr(target) {
            if let Some(candidate) = gateway_dot_one(network, prefix) {
                if graph.hosts.contains_key(&candidate) {
                    graph.gateway = Some(candidate);
                    tracing::info!(gateway = %candidate, "gateway inferred from target CIDR (.1 host)");
                }
            }
        }
    }

    // If no edges from traceroute but we now know a gateway, synthesize a star
    // topology so the renderer can produce a proper tree. Flagged in the log
    // so the user knows the layout isn't from real L2/L3 data.
    if graph.edges.is_empty() {
        if let Some(gw) = graph.gateway {
            let others: Vec<IpAddr> = graph.hosts.keys().copied().filter(|ip| *ip != gw).collect();
            for ip in &others {
                graph.edges.push(HopEdge { from: gw, to: *ip, hop_index: 1 });
            }
            if !others.is_empty() {
                tracing::info!(
                    gateway = %gw,
                    children = others.len(),
                    "star topology synthesized (traceroute produced no edges)"
                );
            }
        }
    }

    // Derive vendor from MAC OUI for hosts missing vendor
    for host in graph.hosts.values_mut() {
        if host.vendor.is_none() {
            if let Some(mac) = &host.mac {
                host.vendor = lookup_oui_vendor(mac);
            }
        }
    }

    // Infer roles (runs after gateway fallback + star synthesis so the gateway
    // host correctly gets DeviceRole::Gateway and peer_count is meaningful).
    infer_roles(&mut graph);

    tracing::info!(
        hosts = graph.hosts.len(),
        edges = graph.edges.len(),
        gateway = ?graph.gateway,
        total_ms = pipeline_start.elapsed().as_millis() as u64,
        "pipeline complete"
    );

    Ok(graph)
}

async fn run_stage(
    backend: &dyn ScanBackend,
    target: &str,
    opts: &ScanOptions,
    graph: &mut HostGraph,
) {
    let name = backend.name();
    if !backend.is_available() {
        tracing::warn!("stage {}: binary not found, skipping", name);
        return;
    }

    let stage_start = Instant::now();
    tracing::info!("stage {}: starting", name);

    match backend.scan(target, opts).await {
        Ok(result) => {
            let host_count = result.hosts.len();
            let edge_count = result.edges.len();
            merge_result(graph, result, false);
            tracing::info!(
                backend = %name,
                hosts = host_count,
                edges = edge_count,
                total_hosts = graph.hosts.len(),
                elapsed_ms = stage_start.elapsed().as_millis() as u64,
                "stage {}: done",
                name
            );
        }
        Err(e) => tracing::warn!(
            backend = %name,
            elapsed_ms = stage_start.elapsed().as_millis() as u64,
            "stage {} failed: {}",
            name,
            e
        ),
    }
}

pub fn merge_result(graph: &mut HostGraph, result: ScanResult, is_fingerprint: bool) {
    for partial in result.hosts {
        merge_partial_host(graph, partial, is_fingerprint);
    }
}

pub fn merge_partial_host(graph: &mut HostGraph, partial: PartialHost, is_fingerprint: bool) {
    let host = graph.hosts.entry(partial.ip).or_insert_with(|| Host::new(partial.ip));

    // MAC: prefer arp-scan over nmap
    if partial.mac.is_some() {
        let should_update = match (partial.detected_by, host.detected_by.first()) {
            (BackendKind::ArpScan, _) => true,
            (_, None) => true,
            (_, Some(&BackendKind::ArpScan)) => false,
            _ => host.mac.is_none(),
        };
        if should_update {
            host.mac = partial.mac;
        }
    }

    // Hostname: prefer nmap over ip neigh
    if partial.hostname.is_some() {
        let should_update = match (partial.detected_by, host.detected_by.first()) {
            (BackendKind::Nmap, _) => true,
            (_, None) => true,
            (_, Some(&BackendKind::Nmap)) => false,
            _ => host.hostname.is_none(),
        };
        if should_update {
            host.hostname = partial.hostname;
        }
    }

    // Vendor: prefer first non-None
    if partial.vendor.is_some() && host.vendor.is_none() {
        host.vendor = partial.vendor;
    }

    // Ports/OS: prefer nmap fingerprint
    if is_fingerprint || partial.detected_by == BackendKind::Nmap {
        if !partial.open_ports.is_empty() {
            host.open_ports = partial.open_ports;
        }
        if partial.os_guess.is_some() {
            host.os_guess = partial.os_guess;
        }
    }

    // Hop distance
    if partial.hop_distance.is_some() && host.hop_distance.is_none() {
        host.hop_distance = partial.hop_distance;
    }

    // detected_by: union
    if !host.detected_by.contains(&partial.detected_by) {
        host.detected_by.push(partial.detected_by);
    }
}

pub fn infer_roles(graph: &mut HostGraph) {
    let gateway_ip = graph.gateway;

    // Count how many distinct peers each IP connects to in edges
    let mut connection_count: HashMap<IpAddr, HashSet<IpAddr>> = HashMap::new();
    for edge in &graph.edges {
        connection_count.entry(edge.from).or_default().insert(edge.to);
        connection_count.entry(edge.to).or_default().insert(edge.from);
    }

    for host in graph.hosts.values_mut() {
        let peer_count = connection_count.get(&host.ip).map(|s| s.len()).unwrap_or(0);
        host.role = infer_single_role(host, gateway_ip, peer_count);
    }
}

pub fn infer_single_role(host: &Host, gateway_ip: Option<IpAddr>, peer_count: usize) -> DeviceRole {
    // Gateway check
    if let Some(gw) = gateway_ip {
        if host.ip == gw {
            return DeviceRole::Gateway;
        }
    }

    let port_numbers: HashSet<u16> = host.open_ports.iter().map(|p| p.number).collect();

    let server_ports: HashSet<u16> = [22, 25, 80, 443, 3306, 5432, 8080, 8443]
        .iter()
        .copied()
        .collect();
    let workstation_ports: HashSet<u16> = [139, 445, 3389].iter().copied().collect();

    // Switch/WAP: intermediate hop connecting multiple peers, no standard ports
    if peer_count >= 2 && port_numbers.is_disjoint(&server_ports) && port_numbers.is_disjoint(&workstation_ports) {
        if let Some(vendor) = &host.vendor {
            let v = vendor.to_lowercase();
            if is_wap_vendor(&v) {
                return DeviceRole::WirelessAP;
            }
            if is_switch_vendor(&v) {
                return DeviceRole::Switch;
            }
        }
        // No vendor match but high connectivity → switch
        if peer_count >= 3 {
            return DeviceRole::Switch;
        }
    }

    // Server: has server ports
    if !port_numbers.is_disjoint(&server_ports) {
        return DeviceRole::Server;
    }

    // Workstation: has workstation ports
    if !port_numbers.is_disjoint(&workstation_ports) {
        return DeviceRole::Workstation;
    }

    // IoT: detected by arp-scan, no standard server/workstation ports
    let detected_by_arp = host.detected_by.contains(&BackendKind::ArpScan);
    if detected_by_arp && port_numbers.is_disjoint(&server_ports) && port_numbers.is_disjoint(&workstation_ports) {
        if let Some(vendor) = &host.vendor {
            let v = vendor.to_lowercase();
            if is_iot_vendor(&v) {
                return DeviceRole::IoT;
            }
        }
        if port_numbers.is_empty() || port_numbers.is_disjoint(&server_ports) {
            return DeviceRole::IoT;
        }
    }

    DeviceRole::Unknown
}

fn is_iot_vendor(vendor_lower: &str) -> bool {
    const IOT_KEYWORDS: &[&str] = &[
        "philips", "hue", "sonos", "nest", "ring", "wyze", "tuya",
        "shelly", "tasmota", "espressif", "raspberry",
    ];
    IOT_KEYWORDS.iter().any(|kw| vendor_lower.contains(kw))
}

fn is_switch_vendor(vendor_lower: &str) -> bool {
    const SWITCH_KEYWORDS: &[&str] = &[
        "cisco", "netgear", "tp-link", "tplink", "d-link", "dlink",
        "juniper", "aruba", "hpe", "hewlett", "dell", "mikrotik",
        "zyxel", "linksys",
    ];
    SWITCH_KEYWORDS.iter().any(|kw| vendor_lower.contains(kw))
}

fn is_wap_vendor(vendor_lower: &str) -> bool {
    const WAP_KEYWORDS: &[&str] = &[
        "ubiquiti", "unifi", "ruckus", "meraki", "engenius",
        "cambium", "aruba", "eero", "google wifi", "mesh",
    ];
    WAP_KEYWORDS.iter().any(|kw| vendor_lower.contains(kw))
}

/// Parse a `<ip>/<prefix>` string (IPv4 or IPv6) into `(network_ip, prefix_len)`.
/// Returns `None` for bare IPs, hostnames, or malformed input.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip_s, prefix_s) = s.split_once('/')?;
    let ip: IpAddr = ip_s.parse().ok()?;
    let prefix: u8 = prefix_s.parse().ok()?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return None;
    }
    Some((ip, prefix))
}

/// Whether `ip` falls inside `network/prefix`. IPv4 and IPv6 are compared
/// strictly within their own family (a v4 address is never inside a v6 CIDR).
pub fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask: u32 = u32::MAX << (32 - prefix);
            (u32::from_be_bytes(a.octets()) & mask) == (u32::from_be_bytes(b.octets()) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask: u128 = u128::MAX << (128 - prefix);
            (u128::from_be_bytes(a.octets()) & mask) == (u128::from_be_bytes(b.octets()) & mask)
        }
        _ => false,
    }
}

/// Canonical network address for `network/prefix` (network bits zeroed on the
/// right). For `192.168.2.42/24` returns `192.168.2.0`.
pub fn canonical_network(network: IpAddr, prefix: u8) -> IpAddr {
    match network {
        IpAddr::V4(v4) => {
            if prefix == 0 {
                return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            }
            if prefix >= 32 {
                return IpAddr::V4(v4);
            }
            let mask: u32 = u32::MAX << (32 - prefix);
            IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(v4.octets()) & mask))
        }
        IpAddr::V6(v6) => {
            if prefix == 0 {
                return IpAddr::V6(Ipv6Addr::UNSPECIFIED);
            }
            if prefix >= 128 {
                return IpAddr::V6(v6);
            }
            let mask: u128 = u128::MAX << (128 - prefix);
            IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(v6.octets()) & mask))
        }
    }
}

/// Returns `<network>.1` for an IPv4 CIDR (e.g. `192.168.2.0/24` → `192.168.2.1`).
/// Returns `None` for IPv6, or when the host portion can't fit `.1`.
pub fn gateway_dot_one(network: IpAddr, prefix: u8) -> Option<IpAddr> {
    match canonical_network(network, prefix) {
        IpAddr::V4(net) => {
            if prefix >= 32 {
                return None; // /32 has no host part
            }
            let candidate = u32::from_be_bytes(net.octets()) | 1;
            Some(IpAddr::V4(Ipv4Addr::from(candidate)))
        }
        IpAddr::V6(_) => None,
    }
}

/// Drop every host whose IP is outside `network/prefix` (and any edges that
/// reference those hosts). Logs how many hosts were removed.
fn apply_cidr_filter(graph: &mut HostGraph, network: IpAddr, prefix: u8) {
    let before = graph.hosts.len();
    let off_target: Vec<IpAddr> = graph
        .hosts
        .keys()
        .copied()
        .filter(|ip| !ip_in_cidr(*ip, network, prefix))
        .collect();
    if off_target.is_empty() {
        return;
    }
    for ip in &off_target {
        graph.hosts.remove(ip);
    }
    graph
        .edges
        .retain(|e| ip_in_cidr(e.from, network, prefix) && ip_in_cidr(e.to, network, prefix));
    tracing::info!(
        removed = off_target.len(),
        before,
        after = graph.hosts.len(),
        network = %network,
        prefix,
        "filtered off-target hosts (use --show-off-target to keep them)"
    );
    for ip in &off_target {
        tracing::debug!(ip = %ip, "dropped off-target host");
    }
}

/// Simple OUI vendor lookup from MAC prefix.
pub fn lookup_oui_vendor(mac: &str) -> Option<String> {
    let prefix = mac
        .split(':')
        .take(3)
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase();

    match prefix.as_str() {
        "00:1A:2B" | "DC:A6:32" => Some("Raspberry Pi Foundation".to_string()),
        "B8:27:EB" => Some("Raspberry Pi Foundation".to_string()),
        "00:17:88" => Some("Philips Lighting BV".to_string()),
        "AC:CF:23" => Some("Espressif Inc.".to_string()),
        "3C:71:BF" | "24:0A:C4" | "30:AE:A4" => Some("Espressif Inc.".to_string()),
        "00:50:56" => Some("VMware, Inc.".to_string()),
        "08:00:27" => Some("Oracle VirtualBox".to_string()),
        "00:0C:29" => Some("VMware, Inc.".to_string()),
        "00:1C:42" => Some("Parallels".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Port, Protocol};

    #[test]
    fn test_merge_partial_hosts_by_ip() {
        let mut graph = HostGraph::empty();

        let p1 = PartialHost {
            ip: "192.168.1.10".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            hostname: Some("host-from-neigh".to_string()),
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            detected_by: BackendKind::IpNeigh,
            hop_distance: None,
        };

        let p2 = PartialHost {
            ip: "192.168.1.10".parse().unwrap(),
            mac: Some("11:22:33:44:55:66".to_string()),
            hostname: Some("host-from-nmap".to_string()),
            vendor: Some("TestVendor".to_string()),
            open_ports: vec![Port { number: 80, protocol: Protocol::Tcp, service: Some("http".to_string()) }],
            os_guess: Some("Linux".to_string()),
            detected_by: BackendKind::Nmap,
            hop_distance: None,
        };

        merge_partial_host(&mut graph, p1, false);
        merge_partial_host(&mut graph, p2, true);

        let host = graph.hosts.get(&"192.168.1.10".parse::<IpAddr>().unwrap()).unwrap();

        // Hostname: nmap preferred
        assert_eq!(host.hostname, Some("host-from-nmap".to_string()));
        // Vendor: first non-None wins
        assert_eq!(host.vendor, Some("TestVendor".to_string()));
        // Ports from fingerprint
        assert_eq!(host.open_ports.len(), 1);
        assert_eq!(host.open_ports[0].number, 80);
        // OS from fingerprint
        assert_eq!(host.os_guess, Some("Linux".to_string()));
        // detected_by union
        assert!(host.detected_by.contains(&BackendKind::IpNeigh));
        assert!(host.detected_by.contains(&BackendKind::Nmap));
    }

    #[test]
    fn test_merge_mac_preference_arp_scan() {
        let mut graph = HostGraph::empty();

        let p_nmap = PartialHost {
            ip: "192.168.1.5".parse().unwrap(),
            mac: Some("nmap:mac:00:00:00:00".to_string()),
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            detected_by: BackendKind::Nmap,
            hop_distance: None,
        };

        let p_arp = PartialHost {
            ip: "192.168.1.5".parse().unwrap(),
            mac: Some("arp:mac:11:11:11:11".to_string()),
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            detected_by: BackendKind::ArpScan,
            hop_distance: None,
        };

        merge_partial_host(&mut graph, p_nmap, false);
        merge_partial_host(&mut graph, p_arp, false);

        let host = graph.hosts.get(&"192.168.1.5".parse::<IpAddr>().unwrap()).unwrap();
        // arp-scan MAC should win
        assert_eq!(host.mac, Some("arp:mac:11:11:11:11".to_string()));
    }

    #[test]
    fn test_role_inference_gateway() {
        let host = Host {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::IpNeigh],
            hop_distance: Some(1),
        };
        let role = infer_single_role(&host, Some("192.168.1.1".parse().unwrap()), 0);
        assert_eq!(role, DeviceRole::Gateway);
    }

    #[test]
    fn test_role_inference_server() {
        let host = Host {
            ip: "192.168.1.10".parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: vec![
                Port { number: 80, protocol: Protocol::Tcp, service: Some("http".to_string()) },
                Port { number: 443, protocol: Protocol::Tcp, service: Some("https".to_string()) },
            ],
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::Nmap],
            hop_distance: None,
        };
        let role = infer_single_role(&host, None, 0);
        assert_eq!(role, DeviceRole::Server);
    }

    #[test]
    fn test_role_inference_workstation() {
        let host = Host {
            ip: "192.168.1.20".parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: vec![
                Port { number: 445, protocol: Protocol::Tcp, service: Some("microsoft-ds".to_string()) },
            ],
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::Nmap],
            hop_distance: None,
        };
        let role = infer_single_role(&host, None, 0);
        assert_eq!(role, DeviceRole::Workstation);
    }

    #[test]
    fn test_role_inference_iot() {
        let host = Host {
            ip: "192.168.1.50".parse().unwrap(),
            mac: Some("00:17:88:aa:bb:cc".to_string()),
            hostname: None,
            vendor: Some("Philips Lighting BV".to_string()),
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::ArpScan],
            hop_distance: None,
        };
        let role = infer_single_role(&host, None, 0);
        assert_eq!(role, DeviceRole::IoT);
    }

    #[test]
    fn test_role_inference_unknown() {
        let host = Host {
            ip: "192.168.1.99".parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::IpNeigh],
            hop_distance: None,
        };
        let role = infer_single_role(&host, None, 0);
        assert_eq!(role, DeviceRole::Unknown);
    }

    #[test]
    fn test_role_inference_switch() {
        let host = Host {
            ip: "192.168.1.2".parse().unwrap(),
            mac: Some("00:11:22:33:44:55".to_string()),
            hostname: None,
            vendor: Some("Cisco Systems".to_string()),
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::Traceroute],
            hop_distance: Some(1),
        };
        let role = infer_single_role(&host, None, 4);
        assert_eq!(role, DeviceRole::Switch);
    }

    #[test]
    fn test_role_inference_switch_high_connectivity() {
        let host = Host {
            ip: "192.168.1.3".parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::Traceroute],
            hop_distance: Some(1),
        };
        // peer_count >= 3 with no vendor → switch
        let role = infer_single_role(&host, None, 3);
        assert_eq!(role, DeviceRole::Switch);
    }

    #[test]
    fn test_role_inference_wap() {
        let host = Host {
            ip: "192.168.1.4".parse().unwrap(),
            mac: Some("00:11:22:33:44:55".to_string()),
            hostname: None,
            vendor: Some("Ubiquiti Networks".to_string()),
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: vec![BackendKind::Traceroute],
            hop_distance: Some(1),
        };
        let role = infer_single_role(&host, None, 2);
        assert_eq!(role, DeviceRole::WirelessAP);
    }

    #[test]
    fn test_gateway_detection_from_edges() {
        use crate::model::HopEdge;
        let edges = vec![
            HopEdge { from: "192.168.1.100".parse().unwrap(), to: "192.168.1.1".parse().unwrap(), hop_index: 1 },
            HopEdge { from: "192.168.1.200".parse().unwrap(), to: "192.168.1.1".parse().unwrap(), hop_index: 1 },
        ];
        let gw = crate::backends::traceroute::detect_gateway(&edges);
        assert_eq!(gw, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_lookup_oui_vendor() {
        assert_eq!(lookup_oui_vendor("B8:27:EB:11:22:33"), Some("Raspberry Pi Foundation".to_string()));
        assert_eq!(lookup_oui_vendor("00:17:88:aa:bb:cc"), Some("Philips Lighting BV".to_string()));
        assert!(lookup_oui_vendor("ff:ff:ff:ff:ff:ff").is_none());
    }

    // --- CIDR helpers ---

    #[test]
    fn test_parse_cidr_valid() {
        let (net, prefix) = parse_cidr("192.168.2.0/24").unwrap();
        assert_eq!(net, "192.168.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 24);

        let (net6, prefix6) = parse_cidr("fdde:8253:2f56::/48").unwrap();
        assert_eq!(net6, "fdde:8253:2f56::".parse::<IpAddr>().unwrap());
        assert_eq!(prefix6, 48);
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("192.168.2.1").is_none(), "bare IP is not a CIDR");
        assert!(parse_cidr("example.com").is_none());
        assert!(parse_cidr("192.168.2.0/33").is_none(), "prefix > 32 for v4");
        assert!(parse_cidr("::/129").is_none(), "prefix > 128 for v6");
    }

    #[test]
    fn test_ip_in_cidr_v4() {
        let net: IpAddr = "192.168.2.0".parse().unwrap();
        assert!(ip_in_cidr("192.168.2.1".parse().unwrap(), net, 24));
        assert!(ip_in_cidr("192.168.2.255".parse().unwrap(), net, 24));
        assert!(!ip_in_cidr("192.168.3.1".parse().unwrap(), net, 24));
        assert!(!ip_in_cidr("172.18.0.2".parse().unwrap(), net, 24));
        // /0 matches everything
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), net, 0));
    }

    #[test]
    fn test_ip_in_cidr_cross_family_is_false() {
        let v4_net: IpAddr = "192.168.2.0".parse().unwrap();
        let v6: IpAddr = "fe80::1".parse().unwrap();
        assert!(!ip_in_cidr(v6, v4_net, 24), "v6 address must not match v4 CIDR");
    }

    #[test]
    fn test_canonical_network_v4() {
        let net: IpAddr = "192.168.2.42".parse().unwrap();
        assert_eq!(canonical_network(net, 24), "192.168.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(canonical_network(net, 16), "192.168.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(canonical_network(net, 32), net);
        assert_eq!(canonical_network(net, 0), "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_gateway_dot_one() {
        let net: IpAddr = "192.168.2.0".parse().unwrap();
        assert_eq!(gateway_dot_one(net, 24), Some("192.168.2.1".parse().unwrap()));
        // Canonicalization: even if we pass a non-network address, we should still get .1
        let offset: IpAddr = "192.168.2.42".parse().unwrap();
        assert_eq!(gateway_dot_one(offset, 24), Some("192.168.2.1".parse().unwrap()));
        // /32 has no host portion
        assert_eq!(gateway_dot_one(net, 32), None);
        // IPv6 not supported yet
        let v6: IpAddr = "fdde::".parse().unwrap();
        assert_eq!(gateway_dot_one(v6, 64), None);
    }

    // --- Pipeline post-processing: CIDR filter + gateway fallback + star ---

    fn make_partial_host(ip: &str, kind: BackendKind) -> PartialHost {
        PartialHost {
            ip: ip.parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            detected_by: kind,
            hop_distance: None,
        }
    }

    fn graph_with_hosts(ips: &[&str]) -> HostGraph {
        let mut g = HostGraph::empty();
        for ip in ips {
            merge_partial_host(&mut g, make_partial_host(ip, BackendKind::IpNeigh), false);
        }
        g
    }

    #[test]
    fn test_cidr_filter_drops_off_target_hosts() {
        let mut g = graph_with_hosts(&[
            "192.168.2.1",
            "192.168.2.125",
            "172.18.0.2",
            "172.19.0.2",
        ]);
        // Include an edge that crosses the target boundary; it must go too.
        g.edges.push(HopEdge {
            from: "192.168.2.1".parse().unwrap(),
            to: "172.18.0.2".parse().unwrap(),
            hop_index: 1,
        });
        // And a valid in-CIDR edge that must survive.
        g.edges.push(HopEdge {
            from: "192.168.2.1".parse().unwrap(),
            to: "192.168.2.125".parse().unwrap(),
            hop_index: 1,
        });

        let (net, prefix) = parse_cidr("192.168.2.0/24").unwrap();
        apply_cidr_filter(&mut g, net, prefix);

        assert_eq!(g.hosts.len(), 2);
        assert!(g.hosts.contains_key(&"192.168.2.1".parse::<IpAddr>().unwrap()));
        assert!(g.hosts.contains_key(&"192.168.2.125".parse::<IpAddr>().unwrap()));
        assert!(!g.hosts.contains_key(&"172.18.0.2".parse::<IpAddr>().unwrap()));
        // Only the in-CIDR edge remains
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].to, "192.168.2.125".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_cidr_filter_no_op_when_all_in_range() {
        let mut g = graph_with_hosts(&["192.168.2.1", "192.168.2.2"]);
        let before_hosts = g.hosts.len();
        let (net, prefix) = parse_cidr("192.168.2.0/24").unwrap();
        apply_cidr_filter(&mut g, net, prefix);
        assert_eq!(g.hosts.len(), before_hosts);
    }

    #[test]
    fn test_gateway_fallback_finds_dot_one() {
        // Simulate the post-merge state: we have hosts, zero edges, and
        // detect_gateway therefore returns None. Manually reproduce the
        // fallback logic.
        let g = graph_with_hosts(&["192.168.2.1", "192.168.2.125", "192.168.2.200"]);
        let (net, prefix) = parse_cidr("192.168.2.0/24").unwrap();
        let candidate = gateway_dot_one(net, prefix).unwrap();
        assert!(g.hosts.contains_key(&candidate));
        assert_eq!(candidate, "192.168.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_gateway_fallback_absent_when_dot_one_missing() {
        // No .1 in the scanned hosts — fallback should yield nothing usable.
        let g = graph_with_hosts(&["192.168.2.5", "192.168.2.6"]);
        let (net, prefix) = parse_cidr("192.168.2.0/24").unwrap();
        let candidate = gateway_dot_one(net, prefix).unwrap();
        assert!(!g.hosts.contains_key(&candidate));
    }

    #[test]
    fn test_star_topology_synthesis_shape() {
        // Reproduce the pipeline's star synthesis against a fixed graph.
        let mut g = graph_with_hosts(&[
            "192.168.2.1",
            "192.168.2.100",
            "192.168.2.125",
            "192.168.2.200",
        ]);
        assert!(g.edges.is_empty());

        let gw: IpAddr = "192.168.2.1".parse().unwrap();
        g.gateway = Some(gw);

        // Inline the pipeline's star synthesis logic.
        if g.edges.is_empty() {
            if let Some(gateway) = g.gateway {
                let others: Vec<IpAddr> = g
                    .hosts
                    .keys()
                    .copied()
                    .filter(|ip| *ip != gateway)
                    .collect();
                for ip in &others {
                    g.edges.push(HopEdge {
                        from: gateway,
                        to: *ip,
                        hop_index: 1,
                    });
                }
            }
        }

        assert_eq!(g.edges.len(), 3, "3 non-gateway hosts → 3 synthetic edges");
        for edge in &g.edges {
            assert_eq!(edge.from, gw);
            assert_eq!(edge.hop_index, 1);
            assert!(g.hosts.contains_key(&edge.to));
            assert_ne!(edge.to, gw);
        }
    }
}
