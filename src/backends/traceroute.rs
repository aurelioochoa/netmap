use crate::model::{BackendKind, HopEdge};
use super::{PartialHost, ScanBackend, ScanOptions, ScanResult};
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use std::net::IpAddr;
use tokio::process::Command;
use tokio::task::JoinSet;

pub struct TracerouteBackend;

impl TracerouteBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanBackend for TracerouteBackend {
    fn name(&self) -> BackendKind {
        BackendKind::Traceroute
    }

    fn is_available(&self) -> bool {
        which::which("traceroute").is_ok()
    }

    async fn scan(&self, target: &str, _opts: &ScanOptions) -> Result<ScanResult> {
        let output = Command::new("traceroute")
            .args(["-n", target])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let target_ip: IpAddr = target.parse().unwrap_or("0.0.0.0".parse().unwrap());
        let (hosts, edges) = parse_traceroute_output(&stdout, target_ip);

        Ok(ScanResult { hosts, edges })
    }
}

pub async fn run_traceroute_all(
    targets: &[IpAddr],
    opts: &ScanOptions,
) -> Result<ScanResult> {
    let mut join_set = JoinSet::new();
    let mut all_hosts = Vec::new();
    let mut all_edges = Vec::new();

    for chunk in targets.chunks(opts.max_parallel) {
        for &ip in chunk {
            join_set.spawn(async move {
                let output = Command::new("traceroute")
                    .args(["-n", &ip.to_string()])
                    .output()
                    .await;
                (ip, output)
            });
        }

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((target_ip, Ok(output))) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let (hosts, edges) = parse_traceroute_output(&stdout, target_ip);
                    all_hosts.extend(hosts);
                    all_edges.extend(edges);
                }
                Ok((ip, Err(e))) => {
                    tracing::warn!("traceroute to {} failed: {}", ip, e);
                }
                Err(e) => {
                    tracing::warn!("traceroute task panicked: {}", e);
                }
            }
        }
    }

    Ok(ScanResult {
        hosts: all_hosts,
        edges: all_edges,
    })
}

pub fn parse_traceroute_output(
    stdout: &str,
    _target_ip: IpAddr,
) -> (Vec<PartialHost>, Vec<HopEdge>) {
    let re = Regex::new(r"^\s*(\d+)\s+([\d.]+)\s+").unwrap();
    let mut hosts = Vec::new();
    let mut edges = Vec::new();
    let mut prev_ip: Option<IpAddr> = None;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip header line (e.g., "traceroute to ...")
        if line.starts_with("traceroute") {
            continue;
        }

        // Skip lines with only asterisks (timeout hops) — break edge chain
        if line.contains("* * *") && !re.is_match(line) {
            prev_ip = None;
            continue;
        }

        if let Some(caps) = re.captures(line) {
            let hop_index: u8 = match caps[1].parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            let ip: IpAddr = match caps[2].parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            hosts.push(PartialHost {
                ip,
                mac: None,
                hostname: None,
                vendor: None,
                open_ports: Vec::new(),
                os_guess: None,
                detected_by: BackendKind::Traceroute,
                hop_distance: Some(hop_index),
            });

            if let Some(from) = prev_ip {
                edges.push(HopEdge {
                    from,
                    to: ip,
                    hop_index,
                });
            }

            prev_ip = Some(ip);
        }
    }

    (hosts, edges)
}

/// Detect gateway from edges: first IP appearing as hop 1 in >= 2 paths.
pub fn detect_gateway(all_edges: &[HopEdge]) -> Option<IpAddr> {
    use std::collections::HashMap;
    let mut hop1_counts: HashMap<IpAddr, usize> = HashMap::new();

    for edge in all_edges {
        if edge.hop_index == 1 {
            *hop1_counts.entry(edge.to).or_insert(0) += 1;
        }
    }

    hop1_counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .max_by_key(|(_, count)| *count)
        .map(|(ip, _)| ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_traceroute_normal() {
        let output = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.123 ms  1.456 ms
 2  10.0.0.1  5.678 ms  5.432 ms  5.789 ms
 3  8.8.8.8  10.123 ms  10.456 ms  10.789 ms
";
        let target: IpAddr = "8.8.8.8".parse().unwrap();
        let (hosts, edges) = parse_traceroute_output(output, target);

        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[0].hop_distance, Some(1));
        assert_eq!(hosts[1].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[2].ip, "8.8.8.8".parse::<IpAddr>().unwrap());

        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].from, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(edges[0].to, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(edges[1].from, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(edges[1].to, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_traceroute_with_stars() {
        let output = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max
 1  192.168.1.1  1.0 ms
 2  * * *
 3  8.8.8.8  10.0 ms
";
        let target: IpAddr = "8.8.8.8".parse().unwrap();
        let (hosts, edges) = parse_traceroute_output(output, target);

        assert_eq!(hosts.len(), 2); // hop 2 skipped
        assert_eq!(edges.len(), 0); // no consecutive pair through hop 2
    }

    #[test]
    fn test_parse_traceroute_single_hop() {
        let output = "\
traceroute to 192.168.1.1 (192.168.1.1), 30 hops max
 1  192.168.1.1  0.5 ms
";
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        let (hosts, edges) = parse_traceroute_output(output, target);

        assert_eq!(hosts.len(), 1);
        assert!(edges.is_empty());
    }

    #[test]
    fn test_parse_traceroute_empty() {
        let (hosts, edges) = parse_traceroute_output("", "0.0.0.0".parse().unwrap());
        assert!(hosts.is_empty());
        assert!(edges.is_empty());
    }

    #[test]
    fn test_detect_gateway_multiple_paths() {
        let edges = vec![
            HopEdge { from: "192.168.1.100".parse().unwrap(), to: "192.168.1.1".parse().unwrap(), hop_index: 1 },
            HopEdge { from: "192.168.1.1".parse().unwrap(), to: "10.0.0.1".parse().unwrap(), hop_index: 2 },
            HopEdge { from: "192.168.1.200".parse().unwrap(), to: "192.168.1.1".parse().unwrap(), hop_index: 1 },
            HopEdge { from: "192.168.1.1".parse().unwrap(), to: "10.0.0.2".parse().unwrap(), hop_index: 2 },
        ];

        let gw = detect_gateway(&edges);
        assert_eq!(gw, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_detect_gateway_single_path() {
        let edges = vec![
            HopEdge { from: "192.168.1.100".parse().unwrap(), to: "192.168.1.1".parse().unwrap(), hop_index: 1 },
        ];
        let gw = detect_gateway(&edges);
        assert!(gw.is_none()); // need >= 2 paths
    }
}
