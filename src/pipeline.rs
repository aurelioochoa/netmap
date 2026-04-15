use crate::backends::arp_scan::ArpScanBackend;
use crate::backends::ip_neigh::IpNeighBackend;
use crate::backends::nmap::{self, NmapBackend};
use crate::backends::traceroute::{self, TracerouteBackend};
use crate::backends::{ScanBackend, ScanOptions, ScanResult, PartialHost};
use crate::model::{BackendKind, DeviceRole, Host, HostGraph};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Run the full scan pipeline and return a merged HostGraph.
pub async fn run_pipeline(target: &str, opts: &ScanOptions) -> Result<HostGraph> {
    let mut graph = HostGraph::empty();

    // Stage 1: ip neigh
    if !opts.skip_backends.contains(&BackendKind::IpNeigh) {
        run_stage(&IpNeighBackend::new(), target, opts, &mut graph).await;
    }

    // Stage 2: arp-scan
    if !opts.skip_backends.contains(&BackendKind::ArpScan) {
        run_stage(&ArpScanBackend::new(), target, opts, &mut graph).await;
    }

    // Stage 3: nmap discovery
    if !opts.skip_backends.contains(&BackendKind::Nmap) {
        run_stage(&NmapBackend::new(), target, opts, &mut graph).await;
    }

    // Stage 4: nmap fingerprint (per host)
    if !opts.skip_backends.contains(&BackendKind::Nmap) {
        if NmapBackend::new().is_available() {
            let ips: Vec<IpAddr> = graph.hosts.keys().copied().collect();
            if !ips.is_empty() {
                match nmap::run_nmap_fingerprint_all(&ips, opts).await {
                    Ok(result) => merge_result(&mut graph, result, true),
                    Err(e) => tracing::warn!("nmap fingerprint stage failed: {}", e),
                }
            }
        }
    }

    // Stage 5: traceroute (per host)
    if !opts.skip_backends.contains(&BackendKind::Traceroute) {
        if TracerouteBackend::new().is_available() {
            let ips: Vec<IpAddr> = graph.hosts.keys().copied().collect();
            if !ips.is_empty() {
                match traceroute::run_traceroute_all(&ips, opts).await {
                    Ok(result) => {
                        graph.edges.extend(result.edges.clone());
                        merge_result(&mut graph, result, false);
                    }
                    Err(e) => tracing::warn!("traceroute stage failed: {}", e),
                }
            }
        }
    }

    // Detect gateway from edges
    graph.gateway = traceroute::detect_gateway(&graph.edges);

    // Derive vendor from MAC OUI for hosts missing vendor
    for host in graph.hosts.values_mut() {
        if host.vendor.is_none() {
            if let Some(mac) = &host.mac {
                host.vendor = lookup_oui_vendor(mac);
            }
        }
    }

    // Infer roles
    infer_roles(&mut graph);

    Ok(graph)
}

async fn run_stage(
    backend: &dyn ScanBackend,
    target: &str,
    opts: &ScanOptions,
    graph: &mut HostGraph,
) {
    if !backend.is_available() {
        tracing::warn!("{} is not available, skipping", backend.name());
        return;
    }

    match backend.scan(target, opts).await {
        Ok(result) => merge_result(graph, result, false),
        Err(e) => tracing::warn!("{} scan failed: {}", backend.name(), e),
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
}
