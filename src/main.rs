mod backends;
mod model;
mod pipeline;
mod renderer;

use anyhow::Result;
use clap::{Parser, Subcommand};
use model::BackendKind;
use backends::ScanOptions;

#[derive(Parser)]
#[command(name = "netmap", version, about = "Discover and render network topology maps")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a network target and display topology
    Scan {
        /// Target network or host (e.g., 192.168.1.0/24)
        target: String,

        /// Port range (e.g., "1-1024" or leave empty for nmap default)
        #[arg(long, default_value = "")]
        ports: String,

        /// Prepend sudo to backends that require it
        #[arg(long, default_value_t = false)]
        sudo: bool,

        /// Per-host timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,

        /// Save output to file (JSON or SVG based on extension)
        #[arg(long)]
        output: Option<String>,

        /// Print plain-text tree and exit (no TUI)
        #[arg(long, default_value_t = false)]
        no_tui: bool,

        /// Skip a backend (can be repeated): ip-neigh, arp-scan, nmap, traceroute
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
    },
}

fn parse_backend_kind(s: &str) -> Option<BackendKind> {
    match s.to_lowercase().as_str() {
        "ip-neigh" | "ipneigh" | "ip_neigh" => Some(BackendKind::IpNeigh),
        "arp-scan" | "arpscan" | "arp_scan" => Some(BackendKind::ArpScan),
        "nmap" => Some(BackendKind::Nmap),
        "traceroute" => Some(BackendKind::Traceroute),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            sudo,
            timeout,
            output,
            no_tui: _,
            skip,
        } => {
            let skip_backends: Vec<BackendKind> = skip
                .iter()
                .filter_map(|s| {
                    let kind = parse_backend_kind(s);
                    if kind.is_none() {
                        eprintln!("Warning: unknown backend '{}', ignoring", s);
                    }
                    kind
                })
                .collect();

            let opts = ScanOptions {
                sudo,
                timeout_secs: timeout,
                port_range: ports,
                skip_backends,
                max_parallel: 10,
            };

            let graph = pipeline::run_pipeline(&target, &opts).await?;
            let tree = renderer::render_tree(&graph);
            print!("{}", tree);

            // Phase 3: JSON/SVG output
            if let Some(path) = output {
                if path.ends_with(".json") {
                    let json = serde_json::to_string_pretty(&graph)?;
                    std::fs::write(&path, json)?;
                    eprintln!("Saved JSON to {}", path);
                } else if path.ends_with(".svg") {
                    eprintln!("SVG export not yet implemented (Phase 3)");
                } else {
                    eprintln!("Unknown output format: {}", path);
                }
            }
        }
    }

    Ok(())
}
