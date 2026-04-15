pub mod arp_scan;
pub mod ip_neigh;
pub mod nmap;
pub mod traceroute;

use crate::model::{BackendKind, HopEdge, Port};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;

/// Returns true only if `opts.sudo` is set AND the process is not already root.
pub fn needs_sudo(opts: &ScanOptions) -> bool {
    if !opts.sudo {
        return false;
    }
    // Skip sudo when already running as root (uid 0)
    unsafe { libc::getuid() != 0 }
}

#[async_trait]
pub trait ScanBackend: Send + Sync {
    fn name(&self) -> BackendKind;
    fn is_available(&self) -> bool;
    async fn scan(&self, target: &str, opts: &ScanOptions) -> Result<ScanResult>;
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub sudo: bool,
    pub timeout_secs: u64,
    pub port_range: String,
    pub skip_backends: Vec<BackendKind>,
    pub max_parallel: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            sudo: false,
            timeout_secs: 5,
            port_range: String::new(),
            skip_backends: Vec::new(),
            max_parallel: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub hosts: Vec<PartialHost>,
    pub edges: Vec<HopEdge>,
}

impl ScanResult {
    pub fn empty() -> Self {
        Self {
            hosts: Vec::new(),
            edges: Vec::new(),
        }
    }
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
