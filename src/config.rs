//! Optional configuration file.
//!
//! Precedence is **CLI flag > config file > built-in default**. Every field is
//! optional so a partial file is valid; anything absent falls through to the
//! next level down.
//!
//! Looked for at `$NETMAP_CONFIG`, else `~/.config/netmap/config.toml`
//! (`%APPDATA%\netmap\config.toml` on Windows).

use crate::backends::ScanOptions;
use crate::model::BackendKind;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The on-disk form of [`ScanOptions`], with every field optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Default target when none is given on the command line.
    pub target: Option<String>,
    pub sudo: Option<bool>,
    pub timeout: Option<u64>,
    pub ports: Option<String>,
    pub max_parallel: Option<usize>,
    /// Budget for a whole-target stage; 0 (the default) means unlimited.
    pub stage_timeout: Option<u64>,
    pub show_off_target: Option<bool>,
    /// Backends to skip by default, e.g. `skip = ["traceroute"]`.
    pub skip: Option<Vec<String>>,
}

impl Config {
    /// Loads the config file, or returns defaults when there isn't one.
    ///
    /// A *missing* file is normal and silent. A file that exists but is invalid
    /// is an error — silently ignoring a typo'd config is how you end up
    /// scanning with settings you didn't ask for.
    pub fn load() -> Result<Self> {
        match Self::path() {
            Some(p) if p.exists() => Self::from_file(&p),
            _ => Ok(Self::default()),
        }
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&raw).with_context(|| format!("parsing config file {}", path.display()))
    }

    pub fn parse(raw: &str) -> Result<Self> {
        Ok(toml::from_str(raw)?)
    }

    /// Where the config file is looked for, if a home directory exists.
    pub fn path() -> Option<PathBuf> {
        if let Ok(explicit) = std::env::var("NETMAP_CONFIG") {
            if !explicit.is_empty() {
                return Some(PathBuf::from(explicit));
            }
        }
        dirs::config_dir().map(|d| d.join("netmap").join("config.toml"))
    }

    /// Folds the file's values over [`ScanOptions::default`]. CLI flags are
    /// applied by the caller afterwards, so they win.
    pub fn to_scan_options(&self) -> Result<ScanOptions> {
        let d = ScanOptions::default();
        let skip = match &self.skip {
            Some(names) => names
                .iter()
                .map(|n| n.parse::<BackendKind>().map_err(anyhow::Error::msg))
                .collect::<Result<Vec<_>>>()
                .context("invalid entry in config `skip`")?,
            None => d.skip_backends,
        };
        Ok(ScanOptions {
            sudo: self.sudo.unwrap_or(d.sudo),
            timeout_secs: self.timeout.unwrap_or(d.timeout_secs),
            port_range: self.ports.clone().unwrap_or(d.port_range),
            skip_backends: skip,
            max_parallel: self.max_parallel.unwrap_or(d.max_parallel).max(1),
            stage_timeout_secs: self.stage_timeout.unwrap_or(d.stage_timeout_secs),
            show_off_target: self.show_off_target.unwrap_or(d.show_off_target),
        })
    }

    /// A commented starter file, written by `netmap config init`.
    pub fn template() -> &'static str {
        concat!(
            "# netmap configuration\n",
            "# Every key is optional; command-line flags override anything set here.\n\n",
            "# Default target when you run `netmap scan` with no argument.\n",
            "# target = \"192.168.1.0/24\"\n\n",
            "# Prepend sudo to backends that need root (arp-scan, nmap -O).\n",
            "# sudo = false\n\n",
            "# Per-host timeout in seconds.\n",
            "# timeout = 5\n\n",
            "# Port range passed to nmap, e.g. \"1-1024\". Empty means nmap's default.\n",
            "# ports = \"\"\n\n",
            "# How many hosts to probe concurrently.\n",
            "# max-parallel = 10\n\n",
            "# Budget for a whole-target stage (arp-scan, nmap -sn) in seconds.\n",
            "# 0 means unlimited; a /24 discovery sweep can legitimately take minutes.\n",
            "# stage-timeout = 0\n\n",
            "# Keep hosts whose IP falls outside the target CIDR.\n",
            "# show-off-target = false\n\n",
            "# Backends to skip: ip-neigh, arp-scan, nmap, traceroute\n",
            "# skip = [\"traceroute\"]\n",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_yields_plain_defaults() {
        let cfg = Config::parse("").unwrap();
        let opts = cfg.to_scan_options().unwrap();
        let d = ScanOptions::default();
        assert_eq!(opts.sudo, d.sudo);
        assert_eq!(opts.timeout_secs, d.timeout_secs);
        assert_eq!(opts.max_parallel, d.max_parallel);
        assert!(opts.skip_backends.is_empty());
    }

    #[test]
    fn values_from_the_file_override_defaults() {
        let cfg = Config::parse(
            r#"
            target = "10.0.0.0/24"
            sudo = true
            timeout = 30
            ports = "1-1024"
            max-parallel = 25
            show-off-target = true
            skip = ["traceroute", "arp_scan"]
            "#,
        )
        .unwrap();

        assert_eq!(cfg.target.as_deref(), Some("10.0.0.0/24"));
        let opts = cfg.to_scan_options().unwrap();
        assert!(opts.sudo);
        assert_eq!(opts.timeout_secs, 30);
        assert_eq!(opts.port_range, "1-1024");
        assert_eq!(opts.max_parallel, 25);
        assert!(opts.show_off_target);
        assert_eq!(
            opts.skip_backends,
            vec![BackendKind::Traceroute, BackendKind::ArpScan]
        );
    }

    #[test]
    fn a_partial_file_leaves_the_rest_at_defaults() {
        let opts = Config::parse("timeout = 99")
            .unwrap()
            .to_scan_options()
            .unwrap();
        assert_eq!(opts.timeout_secs, 99);
        assert_eq!(opts.max_parallel, ScanOptions::default().max_parallel);
        assert!(!opts.sudo);
    }

    #[test]
    fn an_unknown_key_is_an_error_rather_than_being_ignored() {
        let err = Config::parse("tiemout = 5").unwrap_err().to_string();
        assert!(
            err.contains("tiemout"),
            "error should name the bad key: {}",
            err
        );
    }

    #[test]
    fn an_unknown_backend_name_is_rejected_with_a_helpful_message() {
        let err = Config::parse(r#"skip = ["wireshark"]"#)
            .unwrap()
            .to_scan_options()
            .unwrap_err()
            .to_string();
        assert!(err.contains("skip"), "got: {}", err);
    }

    #[test]
    fn max_parallel_is_clamped_to_at_least_one() {
        let opts = Config::parse("max-parallel = 0")
            .unwrap()
            .to_scan_options()
            .unwrap();
        assert_eq!(opts.max_parallel, 1, "zero would deadlock the semaphore");
    }

    #[test]
    fn the_shipped_template_is_valid_and_parses_to_defaults() {
        let cfg = Config::parse(Config::template()).expect("template must parse");
        let opts = cfg.to_scan_options().unwrap();
        assert_eq!(opts.timeout_secs, ScanOptions::default().timeout_secs);
    }
}
