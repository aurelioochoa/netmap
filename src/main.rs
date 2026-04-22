mod backends;
mod model;
mod pipeline;
mod renderer;

use anyhow::Result;
use clap::{Parser, Subcommand};
use model::BackendKind;
use backends::ScanOptions;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "netmap", version, about = "Discover and render network topology maps")]
struct Cli {
    /// Increase log verbosity: -v for debug, -vv for trace
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

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

        /// Include hosts whose IP falls outside the target CIDR (docker bridge,
        /// IPv6 link-local, etc.). By default these are filtered out.
        #[arg(long, default_value_t = false)]
        show_off_target: bool,
    },
}

/// Initialize tracing so logs are visible by default.
/// Precedence: `RUST_LOG` env var > `-v/-vv` CLI flag > built-in default (`info`).
/// Logs are written to stderr so stdout stays clean for the rendered tree/JSON output.
fn init_tracing(verbose: u8) {
    let cli_default = match verbose {
        0 => "netmap=info,warn",
        1 => "netmap=debug,info",
        _ => "netmap=trace,debug",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cli_default));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
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
    let cli = Cli::parse();

    init_tracing(cli.verbose);

    match cli.command {
        Commands::Scan {
            target,
            ports,
            sudo,
            timeout,
            output,
            no_tui: _,
            skip,
            show_off_target,
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
                show_off_target,
            };

            tracing::info!(
                target = %target,
                sudo = opts.sudo,
                timeout_secs = opts.timeout_secs,
                port_range = %opts.port_range,
                max_parallel = opts.max_parallel,
                skip = ?opts.skip_backends,
                "netmap starting scan"
            );

            let graph = pipeline::run_pipeline(&target, &opts).await?;
            let tree = renderer::render_tree(&graph);
            print!("{}", tree);

            let ports_table = renderer::render_ports_table(&graph);
            if !ports_table.is_empty() {
                println!();
                print!("{}", ports_table);
            }

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
