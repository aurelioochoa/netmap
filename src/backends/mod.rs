pub mod arp_scan;
pub mod ip_neigh;
pub mod nmap;
pub mod traceroute;

use crate::model::{BackendKind, HopEdge, Port};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

/// Returns true only if `opts.sudo` is set AND the process is not already root.
pub fn needs_sudo(opts: &ScanOptions) -> bool {
    if !opts.sudo {
        return false;
    }
    // Skip sudo when already running as root (uid 0)
    !is_root()
}

#[cfg(unix)]
fn is_root() -> bool {
    rustix::process::getuid().is_root()
}

#[cfg(not(unix))]
fn is_root() -> bool {
    // No uid concept; let the caller's --sudo request stand.
    false
}

#[async_trait]
pub trait ScanBackend: Send + Sync {
    fn name(&self) -> BackendKind;
    fn is_available(&self) -> bool;

    /// Scans `target`. Implementations must abort promptly when `cancel` fires
    /// and must not leave child processes running behind them — route every
    /// subprocess through [`run_with_limits`].
    async fn scan(
        &self,
        target: &str,
        opts: &ScanOptions,
        cancel: &CancellationToken,
    ) -> Result<ScanResult>;
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub sudo: bool,
    /// Wall-clock budget for each per-host probe (nmap fingerprint, traceroute).
    /// `0` disables the limit. This is enforced by killing the child process,
    /// so it bounds hosts that nmap's own timing options do not.
    pub timeout_secs: u64,
    pub port_range: String,
    pub skip_backends: Vec<BackendKind>,
    pub max_parallel: usize,
    /// Wall-clock budget for a whole-target stage (`arp-scan`, `nmap -sn`).
    /// `0` disables the limit, which is the default: a discovery sweep across a
    /// `/24` legitimately runs for minutes, so borrowing the per-host budget
    /// here would abort healthy scans. Cancellation applies regardless.
    pub stage_timeout_secs: u64,
    /// When `target` is a CIDR, by default we drop hosts whose IPs fall outside
    /// of it (removes docker-bridge / IPv6 link-local noise leaked by ip-neigh).
    /// Setting this to `true` disables the filter so every discovered host appears.
    pub show_off_target: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            sudo: false,
            // `nmap -sV` against a single host commonly runs 30-90s; a tighter
            // default would abort service detection on healthy hosts.
            timeout_secs: 120,
            port_range: String::new(),
            skip_backends: Vec::new(),
            max_parallel: 10,
            stage_timeout_secs: 0,
            show_off_target: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub hosts: Vec<PartialHost>,
    pub edges: Vec<HopEdge>,
}

#[derive(Debug, Clone)]
pub struct PartialHost {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<Port>,
    pub os_guess: Option<String>,
    pub detected_by: BackendKind,
    pub hop_distance: Option<u8>,
}

/// Runs `cmd` to completion, giving up if `timeout_secs` elapses or `cancel` fires.
///
/// The child is spawned with `kill_on_drop`, so abandoning it on either path
/// actually terminates the process. Without this an `nmap` that hangs on a
/// filtered host would keep the whole scan waiting forever, and Ctrl-C would
/// leave orphaned scanners running.
///
/// `timeout_secs == 0` disables the timeout.
pub async fn run_with_limits(
    mut cmd: Command,
    timeout_secs: u64,
    cancel: &CancellationToken,
    what: &str,
) -> Result<Output> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true);

    let child = cmd.spawn()?;

    tokio::select! {
        biased;

        _ = cancel.cancelled() => {
            anyhow::bail!("{} cancelled", what)
        }
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)), if timeout_secs > 0 => {
            anyhow::bail!("{} timed out after {}s", what, timeout_secs)
        }
        result = child.wait_with_output() => {
            Ok(result?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_sudo_is_false_unless_requested() {
        let opts = ScanOptions::default();
        assert!(!needs_sudo(&opts), "default options must not invoke sudo");
    }

    #[test]
    fn needs_sudo_tracks_the_flag_and_the_current_uid() {
        let opts = ScanOptions {
            sudo: true,
            ..Default::default()
        };
        // Root already has the privileges, so sudo would be pointless there.
        assert_eq!(needs_sudo(&opts), !is_root());
    }

    #[tokio::test]
    async fn a_command_that_finishes_returns_its_output() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");
        let out = run_with_limits(cmd, 10, &CancellationToken::new(), "echo")
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("hello"));
    }

    #[tokio::test]
    async fn a_hanging_command_is_cut_off_by_the_timeout() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = std::time::Instant::now();
        let err = run_with_limits(cmd, 1, &CancellationToken::new(), "sleep")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "got: {}", err);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "should return promptly, took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn cancellation_aborts_a_running_command() {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token.cancel();
        });

        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = std::time::Instant::now();
        let err = run_with_limits(cmd, 0, &cancel, "sleep")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("cancelled"), "got: {}", err);
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    /// A whole-target stage (`arp-scan`, `nmap -sn`) is not per-host, so it is
    /// bounded only by cancellation. This is the regression guard for that: the
    /// four backends must route their subprocess through `run_with_limits`
    /// rather than calling `.output()` directly.
    /// The real regression guard for cancellable stages.
    ///
    /// The behaviour tests above prove `run_with_limits` works; this proves the
    /// backends actually go through it. A backend that calls `.output()`
    /// directly compiles and passes every other test, but silently reintroduces
    /// the bug where Ctrl-C leaves an `nmap` sweep running. Source-level because
    /// the alternative — executing each backend — depends on which scanner
    /// binaries happen to be installed.
    #[test]
    fn no_backend_bypasses_run_with_limits() {
        let sources = [
            ("arp_scan.rs", include_str!("arp_scan.rs")),
            ("ip_neigh.rs", include_str!("ip_neigh.rs")),
            ("nmap.rs", include_str!("nmap.rs")),
            ("traceroute.rs", include_str!("traceroute.rs")),
        ];

        for (name, src) in sources {
            // Ignore the `#[cfg(test)]` module: test helpers may spawn freely.
            let code = src.split("#[cfg(test)]").next().unwrap_or(src);
            assert!(
                !code.contains(".output()"),
                "{} calls .output() directly; every subprocess must go through \
                 run_with_limits so it honours the timeout and cancellation",
                name
            );
            assert!(
                code.contains("run_with_limits"),
                "{} spawns no bounded subprocess - did the helper get dropped?",
                name
            );
        }
    }

    #[tokio::test]
    async fn a_whole_target_stage_aborts_when_cancelled() {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token.cancel();
        });

        // stage_timeout_secs defaults to 0 (unlimited), so only the token can
        // end this — exactly the situation a /24 discovery sweep is in.
        let opts = ScanOptions::default();
        assert_eq!(
            opts.stage_timeout_secs, 0,
            "the default must stay unlimited"
        );

        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = std::time::Instant::now();
        let err = run_with_limits(cmd, opts.stage_timeout_secs, &cancel, "discovery")
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("cancelled"), "got: {}", err);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancellation should be prompt, took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn an_opt_in_stage_timeout_bounds_a_whole_target_stage() {
        let opts = ScanOptions {
            stage_timeout_secs: 1,
            ..Default::default()
        };
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let err = run_with_limits(
            cmd,
            opts.stage_timeout_secs,
            &CancellationToken::new(),
            "discovery",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("timed out"), "got: {}", err);
    }

    #[tokio::test]
    async fn an_already_cancelled_token_stops_the_command_immediately() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let err = run_with_limits(cmd, 0, &cancel, "sleep").await.unwrap_err();
        assert!(err.to_string().contains("cancelled"));
    }
}
