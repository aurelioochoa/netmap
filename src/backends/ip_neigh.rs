use crate::model::BackendKind;
use super::{PartialHost, ScanBackend, ScanOptions, ScanResult};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::process::Command;

pub struct IpNeighBackend;

impl IpNeighBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanBackend for IpNeighBackend {
    fn name(&self) -> BackendKind {
        BackendKind::IpNeigh
    }

    fn is_available(&self) -> bool {
        if cfg!(target_os = "linux") {
            which::which("ip").is_ok()
        } else {
            which::which("arp").is_ok()
        }
    }

    async fn scan(&self, _target: &str, _opts: &ScanOptions) -> Result<ScanResult> {
        let output = if cfg!(target_os = "linux") {
            Command::new("ip")
                .args(["neigh", "show"])
                .output()
                .await?
        } else {
            Command::new("arp")
                .args(["-an"])
                .output()
                .await?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let hosts = parse_output(&stdout);

        Ok(ScanResult {
            hosts,
            edges: Vec::new(),
        })
    }
}

fn parse_output(stdout: &str) -> Vec<PartialHost> {
    let mut hosts = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(host) = parse_linux_line(line) {
            hosts.push(host);
        } else if let Some(host) = parse_macos_line(line) {
            hosts.push(host);
        }
    }

    hosts
}

fn parse_linux_line(line: &str) -> Option<PartialHost> {
    // Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }

    // Skip FAILED/INCOMPLETE entries
    let state = parts.last()?;
    if state.eq_ignore_ascii_case("FAILED") || state.eq_ignore_ascii_case("INCOMPLETE") {
        return None;
    }

    let ip: IpAddr = parts[0].parse().ok()?;

    // Find lladdr keyword and get the MAC after it
    let lladdr_pos = parts.iter().position(|&p| p == "lladdr")?;
    let mac = parts.get(lladdr_pos + 1).map(|s| s.to_string());

    Some(PartialHost {
        ip,
        mac,
        hostname: None,
        vendor: None,
        open_ports: Vec::new(),
        os_guess: None,
        detected_by: BackendKind::IpNeigh,
        hop_distance: None,
    })
}

fn parse_macos_line(line: &str) -> Option<PartialHost> {
    // Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    // Extract IP from parentheses
    let ip_str = parts[1].trim_start_matches('(').trim_end_matches(')');
    let ip: IpAddr = ip_str.parse().ok()?;

    // Skip incomplete entries
    if parts.len() > 3 && parts[3] == "incomplete" {
        return None;
    }

    let mac = if parts.len() > 3 && parts[3].contains(':') {
        Some(parts[3].to_string())
    } else {
        None
    };

    Some(PartialHost {
        ip,
        mac,
        hostname: None,
        vendor: None,
        open_ports: Vec::new(),
        os_guess: None,
        detected_by: BackendKind::IpNeigh,
        hop_distance: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_linux_reachable() {
        let line = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE";
        let host = parse_linux_line(line).unwrap();
        assert_eq!(host.ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(host.mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(host.detected_by, BackendKind::IpNeigh);
    }

    #[test]
    fn test_parse_linux_stale() {
        let line = "192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 STALE";
        let host = parse_linux_line(line).unwrap();
        assert_eq!(host.ip, "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(host.mac, Some("11:22:33:44:55:66".to_string()));
    }

    #[test]
    fn test_parse_linux_failed_skipped() {
        let line = "192.168.1.3 dev eth0 lladdr 00:00:00:00:00:00 FAILED";
        assert!(parse_linux_line(line).is_none());
    }

    #[test]
    fn test_parse_linux_incomplete_skipped() {
        let line = "192.168.1.4 dev eth0  INCOMPLETE";
        assert!(parse_linux_line(line).is_none());
    }

    #[test]
    fn test_parse_macos_line() {
        let line = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let host = parse_macos_line(line).unwrap();
        assert_eq!(host.ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(host.mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn test_parse_macos_incomplete_skipped() {
        let line = "? (192.168.1.5) at incomplete on en0";
        // "incomplete" in position 3 means no valid MAC
        let result = parse_macos_line(line);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_output_mixed() {
        let output = "\
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 STALE
192.168.1.3 dev eth0 lladdr 00:00:00:00:00:00 FAILED
";
        let hosts = parse_output(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[1].ip, "192.168.1.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_empty_output() {
        let hosts = parse_output("");
        assert!(hosts.is_empty());
    }
}
