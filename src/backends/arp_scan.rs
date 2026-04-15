use crate::model::BackendKind;
use super::{needs_sudo, PartialHost, ScanBackend, ScanOptions, ScanResult};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::process::Command;

pub struct ArpScanBackend;

impl ArpScanBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanBackend for ArpScanBackend {
    fn name(&self) -> BackendKind {
        BackendKind::ArpScan
    }

    fn is_available(&self) -> bool {
        which::which("arp-scan").is_ok()
    }

    async fn scan(&self, _target: &str, opts: &ScanOptions) -> Result<ScanResult> {
        let mut cmd = if needs_sudo(opts) {
            let mut c = Command::new("sudo");
            c.args(["arp-scan", "-l"]);
            c
        } else {
            let mut c = Command::new("arp-scan");
            c.arg("-l");
            c
        };

        let output = cmd.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let hosts = parse_arp_scan_output(&stdout);

        Ok(ScanResult {
            hosts,
            edges: Vec::new(),
        })
    }
}

pub fn parse_arp_scan_output(stdout: &str) -> Vec<PartialHost> {
    let mut hosts = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip header/footer lines (arp-scan prints informational lines)
        // Data lines start with an IP address
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }

        let ip: IpAddr = match parts[0].trim().parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        let mac = if parts.len() > 1 && parts[1].contains(':') {
            Some(parts[1].trim().to_string())
        } else {
            None
        };

        let vendor = if parts.len() > 2 {
            let v = parts[2].trim();
            if v.is_empty() { None } else { Some(v.to_string()) }
        } else {
            None
        };

        hosts.push(PartialHost {
            ip,
            mac,
            hostname: None,
            vendor,
            open_ports: Vec::new(),
            os_guess: None,
            detected_by: BackendKind::ArpScan,
            hop_distance: None,
        });
    }

    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_arp_scan_basic() {
        let output = "192.168.1.42\taa:bb:cc:dd:ee:ff\tApple, Inc.\n";
        let hosts = parse_arp_scan_output(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.42".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[0].mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(hosts[0].vendor, Some("Apple, Inc.".to_string()));
        assert_eq!(hosts[0].detected_by, BackendKind::ArpScan);
    }

    #[test]
    fn test_parse_arp_scan_multiple() {
        let output = "\
192.168.1.1\taa:bb:cc:dd:ee:ff\tNetgear
192.168.1.42\t11:22:33:44:55:66\tApple, Inc.
192.168.1.100\tde:ad:be:ef:00:01\t(Unknown)
";
        let hosts = parse_arp_scan_output(output);
        assert_eq!(hosts.len(), 3);
    }

    #[test]
    fn test_parse_arp_scan_header_footer_skipped() {
        let output = "\
Interface: eth0, type: EN10MB, MAC: 00:11:22:33:44:55, IPv4: 192.168.1.5
Starting arp-scan 1.10.0 with 256 hosts
192.168.1.1\taa:bb:cc:dd:ee:ff\tNetgear
192.168.1.42\t11:22:33:44:55:66\tApple, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan: 256 hosts scanned. 2 responded.
";
        let hosts = parse_arp_scan_output(output);
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_parse_arp_scan_empty() {
        let hosts = parse_arp_scan_output("");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_arp_scan_no_vendor() {
        let output = "192.168.1.42\taa:bb:cc:dd:ee:ff\t\n";
        let hosts = parse_arp_scan_output(output);
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].vendor.is_none());
    }
}
