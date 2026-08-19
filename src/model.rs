use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostGraph {
    pub hosts: HashMap<IpAddr, Host>,
    pub edges: Vec<HopEdge>,
    pub gateway: Option<IpAddr>,
}

impl HostGraph {
    pub fn empty() -> Self {
        Self {
            hosts: HashMap::new(),
            edges: Vec::new(),
            gateway: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<Port>,
    pub os_guess: Option<String>,
    pub role: DeviceRole,
    pub detected_by: Vec<BackendKind>,
    pub hop_distance: Option<u8>,
}

impl Host {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os_guess: None,
            role: DeviceRole::Unknown,
            detected_by: Vec::new(),
            hop_distance: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopEdge {
    pub from: IpAddr,
    pub to: IpAddr,
    pub hop_index: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRole {
    Gateway,
    Switch,
    WirelessAP,
    Server,
    Workstation,
    IoT,
    Unknown,
}

impl fmt::Display for DeviceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceRole::Gateway => write!(f, "router"),
            DeviceRole::Switch => write!(f, "switch"),
            DeviceRole::WirelessAP => write!(f, "wap/switch"),
            DeviceRole::Server => write!(f, "server"),
            DeviceRole::Workstation => write!(f, "workstation"),
            DeviceRole::IoT => write!(f, "IoT"),
            DeviceRole::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    IpNeigh,
    ArpScan,
    Nmap,
    Traceroute,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendKind::IpNeigh => write!(f, "ip-neigh"),
            BackendKind::ArpScan => write!(f, "arp-scan"),
            BackendKind::Nmap => write!(f, "nmap"),
            BackendKind::Traceroute => write!(f, "traceroute"),
        }
    }
}

impl BackendKind {
    /// Every backend, in the order the pipeline runs them.
    pub const ALL: [BackendKind; 4] = [
        BackendKind::IpNeigh,
        BackendKind::ArpScan,
        BackendKind::Nmap,
        BackendKind::Traceroute,
    ];
}

/// Parses the names accepted by `--skip`. Hyphen, underscore, and bare spellings
/// are all accepted so `--skip ip-neigh`, `ip_neigh`, and `ipneigh` agree.
impl std::str::FromStr for BackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ip-neigh" | "ipneigh" | "ip_neigh" => Ok(BackendKind::IpNeigh),
            "arp-scan" | "arpscan" | "arp_scan" => Ok(BackendKind::ArpScan),
            "nmap" => Ok(BackendKind::Nmap),
            "traceroute" => Ok(BackendKind::Traceroute),
            other => Err(format!(
                "unknown backend '{}' (expected one of: ip-neigh, arp-scan, nmap, traceroute)",
                other
            )),
        }
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn backend_kind_parses_all_spellings() {
        for s in ["ip-neigh", "ip_neigh", "IPNEIGH"] {
            assert_eq!(BackendKind::from_str(s).unwrap(), BackendKind::IpNeigh);
        }
        for s in ["arp-scan", "arp_scan", "ArpScan"] {
            assert_eq!(BackendKind::from_str(s).unwrap(), BackendKind::ArpScan);
        }
        assert_eq!(BackendKind::from_str("nmap").unwrap(), BackendKind::Nmap);
        assert_eq!(
            BackendKind::from_str("traceroute").unwrap(),
            BackendKind::Traceroute
        );
    }

    #[test]
    fn backend_kind_rejects_unknown_and_names_the_alternatives() {
        let err = BackendKind::from_str("wireshark").unwrap_err();
        assert!(
            err.contains("wireshark"),
            "error should quote the bad input"
        );
        assert!(err.contains("arp-scan"), "error should list valid backends");
    }

    #[test]
    fn backend_kind_display_roundtrips_through_from_str() {
        for kind in BackendKind::ALL {
            assert_eq!(BackendKind::from_str(&kind.to_string()).unwrap(), kind);
        }
    }

    #[test]
    fn graph_survives_a_json_roundtrip() {
        let mut graph = HostGraph::empty();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let mut host = Host::new(ip);
        host.mac = Some("aa:bb:cc:dd:ee:ff".into());
        host.role = DeviceRole::Server;
        host.open_ports.push(Port {
            number: 443,
            protocol: Protocol::Tcp,
            service: Some("https".into()),
        });
        graph.hosts.insert(ip, host);
        graph.gateway = Some("192.168.1.1".parse().unwrap());
        graph.edges.push(HopEdge {
            from: "192.168.1.1".parse().unwrap(),
            to: ip,
            hop_index: 1,
        });

        let json = serde_json::to_string(&graph).unwrap();
        let back: HostGraph = serde_json::from_str(&json).unwrap();

        assert_eq!(back.hosts.len(), 1);
        assert_eq!(back.gateway, graph.gateway);
        assert_eq!(back.edges.len(), 1);
        let h = &back.hosts[&ip];
        assert_eq!(h.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(h.role, DeviceRole::Server);
        assert_eq!(h.open_ports[0].number, 443);
    }
}
