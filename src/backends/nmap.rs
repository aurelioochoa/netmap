use crate::model::{BackendKind, Port, Protocol};
use super::{needs_sudo, PartialHost, ScanBackend, ScanOptions, ScanResult};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::net::IpAddr;
use tokio::process::Command;
use tokio::task::JoinSet;

pub struct NmapBackend;

impl NmapBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanBackend for NmapBackend {
    fn name(&self) -> BackendKind {
        BackendKind::Nmap
    }

    fn is_available(&self) -> bool {
        which::which("nmap").is_ok()
    }

    async fn scan(&self, target: &str, opts: &ScanOptions) -> Result<ScanResult> {
        // Discovery scan
        let discovery = run_nmap_discovery(target, opts).await?;
        Ok(discovery)
    }
}

pub async fn run_nmap_discovery(target: &str, opts: &ScanOptions) -> Result<ScanResult> {
    let args = vec!["-sn", target, "-oX", "-"];
    let use_sudo = needs_sudo(opts);

    let output = if use_sudo {
        Command::new("sudo")
            .arg("nmap")
            .args(&args)
            .output()
            .await?
    } else {
        Command::new("nmap")
            .args(&args)
            .output()
            .await?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nmap_xml(&stdout, false)
}

pub async fn run_nmap_fingerprint_all(
    hosts: &[IpAddr],
    opts: &ScanOptions,
) -> Result<ScanResult> {
    let mut join_set = JoinSet::new();
    let mut all_hosts = Vec::new();

    // Process in batches to respect max_parallel
    for chunk in hosts.chunks(opts.max_parallel) {
        for &ip in chunk {
            let use_sudo = needs_sudo(opts);
            let port_range = opts.port_range.clone();
            let timeout = opts.timeout_secs;
            join_set.spawn(async move {
                run_nmap_fingerprint_single(ip, use_sudo, &port_range, timeout).await
            });
        }

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(scan_result)) => {
                    all_hosts.extend(scan_result.hosts);
                }
                Ok(Err(e)) => {
                    tracing::warn!("nmap fingerprint failed: {}", e);
                }
                Err(e) => {
                    tracing::warn!("nmap fingerprint task panicked: {}", e);
                }
            }
        }
    }

    Ok(ScanResult {
        hosts: all_hosts,
        edges: Vec::new(),
    })
}

async fn run_nmap_fingerprint_single(
    ip: IpAddr,
    sudo: bool,
    port_range: &str,
    _timeout: u64,
) -> Result<ScanResult> {
    let ip_str = ip.to_string();
    let mut args = vec!["-sV"];

    if sudo {
        args.push("-O");
    }

    if !port_range.is_empty() {
        args.push("-p");
        args.push(port_range);
    }

    args.push(&ip_str);
    args.push("-oX");
    args.push("-");

    let output = if sudo {
        Command::new("sudo")
            .arg("nmap")
            .args(&args)
            .output()
            .await?
    } else {
        Command::new("nmap")
            .args(&args)
            .output()
            .await?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nmap_xml(&stdout, true)
}

// --- XML parsing structs ---

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(default)]
    host: Vec<NmapHost>,
}

#[derive(Debug, Deserialize)]
struct NmapHost {
    #[serde(default)]
    address: Vec<NmapAddress>,
    #[serde(default)]
    hostnames: Option<NmapHostnames>,
    #[serde(default)]
    ports: Option<NmapPorts>,
    #[serde(default)]
    os: Option<NmapOs>,
}

#[derive(Debug, Deserialize)]
struct NmapAddress {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
    #[serde(rename = "@vendor", default)]
    vendor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmapHostnames {
    #[serde(default)]
    hostname: Vec<NmapHostname>,
}

#[derive(Debug, Deserialize)]
struct NmapHostname {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct NmapPorts {
    #[serde(default)]
    port: Vec<NmapPort>,
}

#[derive(Debug, Deserialize)]
struct NmapPort {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(default)]
    state: Option<NmapPortState>,
    #[serde(default)]
    service: Option<NmapService>,
}

#[derive(Debug, Deserialize)]
struct NmapPortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct NmapService {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct NmapOs {
    #[serde(default)]
    osmatch: Vec<NmapOsMatch>,
}

#[derive(Debug, Deserialize)]
struct NmapOsMatch {
    #[serde(rename = "@name")]
    name: String,
}

// --- Parse logic ---

pub fn parse_nmap_xml(xml: &str, fingerprint_mode: bool) -> Result<ScanResult> {
    let nmap_run: NmapRun = quick_xml::de::from_str(xml)
        .context("Failed to parse nmap XML output")?;

    let mut hosts = Vec::new();

    for host in &nmap_run.host {
        let mut ip: Option<IpAddr> = None;
        let mut mac: Option<String> = None;
        let mut vendor: Option<String> = None;

        for addr in &host.address {
            match addr.addrtype.as_str() {
                "ipv4" | "ipv6" => {
                    if ip.is_none() {
                        ip = addr.addr.parse().ok();
                    }
                }
                "mac" => {
                    mac = Some(addr.addr.clone());
                    if addr.vendor.is_some() {
                        vendor = addr.vendor.clone();
                    }
                }
                _ => {}
            }
        }

        let ip = match ip {
            Some(ip) => ip,
            None => continue,
        };

        let hostname = host
            .hostnames
            .as_ref()
            .and_then(|h| h.hostname.first())
            .map(|h| h.name.clone());

        let mut open_ports = Vec::new();
        let mut os_guess = None;

        if fingerprint_mode {
            if let Some(ports) = &host.ports {
                for port in &ports.port {
                    let is_open = port
                        .state
                        .as_ref()
                        .map(|s| s.state == "open")
                        .unwrap_or(false);

                    if !is_open {
                        continue;
                    }

                    let number: u16 = match port.portid.parse() {
                        Ok(n) => n,
                        Err(_) => continue,
                    };

                    let protocol = match port.protocol.as_str() {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        _ => Protocol::Tcp,
                    };

                    let service = port.service.as_ref().map(|s| s.name.clone());

                    open_ports.push(Port {
                        number,
                        protocol,
                        service,
                    });
                }
            }

            if let Some(os) = &host.os {
                os_guess = os.osmatch.first().map(|m| m.name.clone());
            }
        }

        hosts.push(PartialHost {
            ip,
            mac,
            hostname,
            vendor,
            open_ports,
            os_guess,
            detected_by: BackendKind::Nmap,
            hop_distance: None,
        });
    }

    Ok(ScanResult {
        hosts,
        edges: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVERY_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Netgear"/>
    <hostnames>
      <hostname name="router.local"/>
    </hostnames>
  </host>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="webserver"/>
    </hostnames>
  </host>
</nmaprun>"#;

    const FINGERPRINT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="webserver"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4"/>
    </os>
  </host>
</nmaprun>"#;

    #[test]
    fn test_parse_discovery_xml() {
        let result = parse_nmap_xml(DISCOVERY_XML, false).unwrap();
        assert_eq!(result.hosts.len(), 2);

        let h0 = &result.hosts[0];
        assert_eq!(h0.ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(h0.mac, Some("AA:BB:CC:DD:EE:FF".to_string()));
        assert_eq!(h0.vendor, Some("Netgear".to_string()));
        assert_eq!(h0.hostname, Some("router.local".to_string()));
        assert!(h0.open_ports.is_empty()); // discovery mode doesn't extract ports

        let h1 = &result.hosts[1];
        assert_eq!(h1.ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(h1.hostname, Some("webserver".to_string()));
    }

    #[test]
    fn test_parse_fingerprint_xml() {
        let result = parse_nmap_xml(FINGERPRINT_XML, true).unwrap();
        assert_eq!(result.hosts.len(), 1);

        let host = &result.hosts[0];
        assert_eq!(host.ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        // Only open ports
        assert_eq!(host.open_ports.len(), 3);
        assert_eq!(host.open_ports[0].number, 22);
        assert_eq!(host.open_ports[0].service, Some("ssh".to_string()));
        assert_eq!(host.open_ports[1].number, 80);
        assert_eq!(host.open_ports[2].number, 443);
        assert_eq!(host.os_guess, Some("Linux 5.4".to_string()));
    }

    #[test]
    fn test_parse_malformed_xml() {
        let result = parse_nmap_xml("not xml at all", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_nmaprun() {
        let xml = r#"<?xml version="1.0"?><nmaprun></nmaprun>"#;
        let result = parse_nmap_xml(xml, false).unwrap();
        assert!(result.hosts.is_empty());
    }
}
