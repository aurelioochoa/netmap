use super::{run_with_limits, PartialHost, ScanBackend, ScanOptions, ScanResult};
use crate::model::{BackendKind, HopEdge};
use crate::progress::{Reporter, ScanEvent};
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub struct TracerouteBackend;

impl TracerouteBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TracerouteBackend {
    fn default() -> Self {
        Self::new()
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

    async fn scan(
        &self,
        target: &str,
        opts: &ScanOptions,
        cancel: &CancellationToken,
    ) -> Result<ScanResult> {
        tracing::info!(cmd = %format!("traceroute -n {}", target), "traceroute: executing");
        let started = std::time::Instant::now();

        let mut cmd = Command::new("traceroute");
        cmd.args(["-n", target]);
        let output = run_with_limits(cmd, opts.stage_timeout_secs, cancel, "traceroute").await?;

        tracing::debug!(
            exit = ?output.status.code(),
            stdout_bytes = output.stdout.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "traceroute: command finished"
        );
        if !output.status.success() {
            tracing::warn!(
                "traceroute exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let (hosts, edges) = parse_traceroute_output(&stdout);
        tracing::info!(
            hosts = hosts.len(),
            edges = edges.len(),
            "traceroute: parsed output"
        );

        Ok(ScanResult { hosts, edges })
    }
}

/// Traces the path to every host, at most `opts.max_parallel` at a time.
///
/// Like the nmap fan-out, a semaphore replaces fixed batching so one
/// unreachable host cannot stall the hosts queued behind it.
pub async fn run_traceroute_all(
    targets: &[IpAddr],
    opts: &ScanOptions,
    reporter: &Reporter,
    cancel: &CancellationToken,
) -> Result<ScanResult> {
    let total = targets.len();
    let permits = Arc::new(Semaphore::new(opts.max_parallel.max(1)));
    let mut join_set = JoinSet::new();

    for &ip in targets {
        let permits = permits.clone();
        let cancel = cancel.clone();
        let timeout = opts.timeout_secs;

        join_set.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore is never closed");
            let started = std::time::Instant::now();
            if cancel.is_cancelled() {
                return (ip, Err(anyhow::anyhow!("cancelled")), 0u64);
            }

            tracing::info!(host = %ip, cmd = %format!("traceroute -n {}", ip), "traceroute: executing");
            let mut cmd = Command::new("traceroute");
            cmd.args(["-n", &ip.to_string()]);
            let output = run_with_limits(cmd, timeout, &cancel, &format!("traceroute to {}", ip)).await;

            (ip, output, started.elapsed().as_millis() as u64)
        });
    }

    let mut all_hosts = Vec::new();
    let mut all_edges = Vec::new();
    let mut completed: usize = 0;

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok((target_ip, Ok(output), elapsed_ms)) => {
                if !output.status.success() {
                    tracing::warn!(
                        host = %target_ip,
                        exit = ?output.status.code(),
                        elapsed_ms,
                        "traceroute exited non-zero: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                let (hosts, edges) = parse_traceroute_output(&stdout);
                tracing::info!(
                    host = %target_ip,
                    hops = hosts.len(),
                    edges = edges.len(),
                    elapsed_ms,
                    "traceroute: per-host done"
                );
                all_hosts.extend(hosts);
                all_edges.extend(edges);
            }
            Ok((ip, Err(e), elapsed_ms)) => {
                tracing::warn!(host = %ip, elapsed_ms, "traceroute failed: {}", e);
            }
            Err(e) => tracing::warn!("traceroute task panicked: {}", e),
        }
        completed += 1;
        reporter.send(ScanEvent::HostProgress {
            kind: BackendKind::Traceroute,
            done: completed,
            total,
        });

        if cancel.is_cancelled() {
            tracing::info!(
                completed,
                total,
                "traceroute: cancelled, aborting remaining hosts"
            );
            join_set.abort_all();
            break;
        }
    }

    Ok(ScanResult {
        hosts: all_hosts,
        edges: all_edges,
    })
}

/// Matches a traceroute hop line: `  3  192.168.1.1  1.234 ms ...`
fn hop_line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Infallible: the pattern is a literal, validated by the tests below.
    RE.get_or_init(|| Regex::new(r"^\s*(\d+)\s+([\d.]+)\s+").expect("hop-line pattern is valid"))
}

/// Parses `traceroute -n` output into hop hosts and the edges between them.
///
/// Every hop is derived from the text itself, so the destination address is not
/// needed here.
pub fn parse_traceroute_output(stdout: &str) -> (Vec<PartialHost>, Vec<HopEdge>) {
    let re = hop_line_regex();
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
        let (hosts, edges) = parse_traceroute_output(output);

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
        let (hosts, edges) = parse_traceroute_output(output);

        assert_eq!(hosts.len(), 2); // hop 2 skipped
        assert_eq!(edges.len(), 0); // no consecutive pair through hop 2
    }

    #[test]
    fn test_parse_traceroute_single_hop() {
        let output = "\
traceroute to 192.168.1.1 (192.168.1.1), 30 hops max
 1  192.168.1.1  0.5 ms
";
        let (hosts, edges) = parse_traceroute_output(output);

        assert_eq!(hosts.len(), 1);
        assert!(edges.is_empty());
    }

    #[test]
    fn test_parse_traceroute_empty() {
        let (hosts, edges) = parse_traceroute_output("");
        assert!(hosts.is_empty());
        assert!(edges.is_empty());
    }

    #[test]
    fn test_detect_gateway_multiple_paths() {
        let edges = vec![
            HopEdge {
                from: "192.168.1.100".parse().unwrap(),
                to: "192.168.1.1".parse().unwrap(),
                hop_index: 1,
            },
            HopEdge {
                from: "192.168.1.1".parse().unwrap(),
                to: "10.0.0.1".parse().unwrap(),
                hop_index: 2,
            },
            HopEdge {
                from: "192.168.1.200".parse().unwrap(),
                to: "192.168.1.1".parse().unwrap(),
                hop_index: 1,
            },
            HopEdge {
                from: "192.168.1.1".parse().unwrap(),
                to: "10.0.0.2".parse().unwrap(),
                hop_index: 2,
            },
        ];

        let gw = detect_gateway(&edges);
        assert_eq!(gw, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_detect_gateway_single_path() {
        let edges = vec![HopEdge {
            from: "192.168.1.100".parse().unwrap(),
            to: "192.168.1.1".parse().unwrap(),
            hop_index: 1,
        }];
        let gw = detect_gateway(&edges);
        assert!(gw.is_none()); // need >= 2 paths
    }
}
