use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HopEdge {
    pub from: IpAddr,
    pub to: IpAddr,
    pub hop_index: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
