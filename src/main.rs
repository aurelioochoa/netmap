use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use netmap::backends::ScanOptions;
use netmap::config::Config;
use netmap::model::{BackendKind, HostGraph};
use netmap::{pipeline, renderer};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "netmap",
    version,
    about = "Discover and render network topology maps",
    long_about = "Discover and render network topology maps.\n\n\
                  Combines ip-neigh, arp-scan, nmap and traceroute into a single host \
                  graph, infers device roles, and renders it as an ASCII diagram, JSON, \
                  or SVG. Settings may also be placed in a config file; run \
                  `netmap config path` to see where."
)]
struct Cli {
    /// Increase log verbosity: -v for debug, -vv for trace
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Suppress all log output (overrides -v and RUST_LOG)
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a network target and display its topology
    Scan(ScanArgs),

    /// Re-render a previously saved JSON scan without touching the network
    Render {
        /// Path to a JSON file written by `netmap scan --output`
        input: String,

        /// Write the re-rendered output here (.json or .svg); prints to stdout otherwise
        #[arg(long)]
        output: Option<String>,
    },

    /// Inspect or create the configuration file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the path netmap reads its config from
    Path,
    /// Write a commented starter config file
    Init {
        /// Overwrite an existing file
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Show the effective settings after merging the config file with defaults
    Show,
}

#[derive(Args)]
struct ScanArgs {
    /// Target network or host (e.g., 192.168.1.0/24). Falls back to `target` in the config file.
    target: Option<String>,

    /// Port range (e.g., "1-1024"); empty uses nmap's default set
    #[arg(long)]
    ports: Option<String>,

    /// Prepend sudo to backends that require it
    #[arg(long)]
    sudo: bool,

    /// Per-host probe timeout in seconds; 0 disables it [default: 120]
    #[arg(long)]
    timeout: Option<u64>,

    /// How many hosts to probe concurrently
    #[arg(long)]
    max_parallel: Option<usize>,

    /// Timeout for a whole-target stage (arp-scan, nmap -sn); 0 disables it [default: 0]
    #[arg(long)]
    stage_timeout: Option<u64>,

    /// Save output to a file; .json and .svg are both supported
    #[arg(long)]
    output: Option<String>,

    /// Skip a backend (repeatable): ip-neigh, arp-scan, nmap, traceroute
    #[arg(long, value_delimiter = ',')]
    skip: Vec<BackendKind>,

    /// Include hosts whose IP falls outside the target CIDR (docker bridge,
    /// IPv6 link-local, etc.). By default these are filtered out.
    #[arg(long)]
    show_off_target: bool,

    /// Deprecated: plain text is the only terminal mode, so this does nothing.
    #[arg(long, hide = true)]
    no_tui: bool,
}

impl ScanArgs {
    /// Applies CLI flags over the config file's values, which in turn sit over
    /// [`ScanOptions::default`]. A flag the user did not pass leaves the lower
    /// layer intact — which is why the optional flags are `Option<T>`.
    fn into_options(self, cfg: &Config) -> Result<(String, ScanOptions)> {
        let mut opts = cfg.to_scan_options()?;

        if self.sudo {
            opts.sudo = true;
        }
        if let Some(t) = self.timeout {
            opts.timeout_secs = t;
        }
        if let Some(p) = self.ports {
            opts.port_range = p;
        }
        if let Some(m) = self.max_parallel {
            opts.max_parallel = m.max(1);
        }
        if let Some(t) = self.stage_timeout {
            opts.stage_timeout_secs = t;
        }
        if self.show_off_target {
            opts.show_off_target = true;
        }
        if !self.skip.is_empty() {
            opts.skip_backends = self.skip;
        }

        let target = self
            .target
            .or_else(|| cfg.target.clone())
            .context("no target given: pass one (e.g. `netmap scan 192.168.1.0/24`) or set `target` in the config file")?;

        Ok((target, opts))
    }
}

/// Initialize tracing so logs are visible by default.
/// Precedence: `--quiet` > `RUST_LOG` env var > `-v/-vv` CLI flag > built-in default (`info`).
/// Logs are written to stderr so stdout stays clean for the rendered tree/JSON output.
fn init_tracing(verbose: u8, quiet: bool) {
    let filter = if quiet {
        EnvFilter::new("off")
    } else {
        let cli_default = match verbose {
            0 => "netmap=info,warn",
            1 => "netmap=debug,info",
            _ => "netmap=trace,debug",
        };
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cli_default))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Prints the ASCII tree and, when any host has open ports, the ports table.
fn print_graph(graph: &HostGraph) {
    print!("{}", renderer::render_tree(graph));

    let ports_table = renderer::render_ports_table(graph);
    if !ports_table.is_empty() {
        println!();
        print!("{}", ports_table);
    }
}

/// Writes `graph` to `path`, choosing the format from the file extension.
fn write_output(graph: &HostGraph, path: &str) -> Result<()> {
    if let Some(ext) = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
    {
        match ext.to_lowercase().as_str() {
            "json" => {
                let json = serde_json::to_string_pretty(graph)?;
                std::fs::write(path, json).with_context(|| format!("writing JSON to {}", path))?;
                tracing::info!(path, "saved JSON");
                return Ok(());
            }
            "svg" => {
                std::fs::write(path, renderer::render_svg(graph))
                    .with_context(|| format!("writing SVG to {}", path))?;
                tracing::info!(path, "saved SVG");
                return Ok(());
            }
            _ => {}
        }
    }
    anyhow::bail!(
        "unsupported output format for '{}' (expected .json or .svg)",
        path
    )
}

async fn cmd_scan(args: ScanArgs, cfg: &Config) -> Result<()> {
    if args.no_tui {
        tracing::warn!(
            "--no-tui is deprecated and does nothing; plain text is the only terminal mode"
        );
    }

    let output = args.output.clone();
    let (target, opts) = args.into_options(cfg)?;

    tracing::info!(
        target = %target,
        sudo = opts.sudo,
        timeout_secs = opts.timeout_secs,
        port_range = %opts.port_range,
        max_parallel = opts.max_parallel,
        skip = ?opts.skip_backends,
        "netmap starting scan"
    );

    // Ctrl-C cancels in-flight probes and kills their child processes, rather
    // than leaving orphaned nmap/traceroute processes behind.
    let cancel = CancellationToken::new();
    let signal_token = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("interrupt received, cancelling scan");
            signal_token.cancel();
        }
    });

    let graph = pipeline::run_pipeline_cancellable(&target, &opts, cancel.clone()).await?;

    print_graph(&graph);

    if let Some(path) = output {
        write_output(&graph, &path)?;
    }

    if cancel.is_cancelled() {
        // Partial results were still printed above; the exit code says they are partial.
        anyhow::bail!("scan cancelled before completion (results above are partial)");
    }

    Ok(())
}

fn cmd_render(input: &str, output: Option<String>) -> Result<()> {
    let raw =
        std::fs::read_to_string(input).with_context(|| format!("reading saved scan {}", input))?;
    let graph: HostGraph = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as a netmap JSON scan", input))?;

    match output {
        Some(path) => write_output(&graph, &path),
        None => {
            print_graph(&graph);
            Ok(())
        }
    }
}

fn cmd_config(action: ConfigAction, cfg: &Config) -> Result<()> {
    match action {
        ConfigAction::Path => {
            match Config::path() {
                Some(p) => {
                    let state = if p.exists() {
                        "exists"
                    } else {
                        "not created yet"
                    };
                    println!("{} ({})", p.display(), state);
                }
                None => println!("(no config directory available on this system)"),
            }
            Ok(())
        }
        ConfigAction::Init { force } => {
            let path = Config::path().context("no config directory available on this system")?;
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists (pass --force to overwrite)",
                    path.display()
                );
            }
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            std::fs::write(&path, Config::template())
                .with_context(|| format!("writing {}", path.display()))?;
            println!("Wrote starter config to {}", path.display());
            Ok(())
        }
        ConfigAction::Show => {
            let opts = cfg.to_scan_options()?;
            println!(
                "target:          {}",
                cfg.target.as_deref().unwrap_or("(none)")
            );
            println!("sudo:            {}", opts.sudo);
            println!("timeout:         {}s", opts.timeout_secs);
            println!(
                "ports:           {}",
                if opts.port_range.is_empty() {
                    "(nmap default)"
                } else {
                    &opts.port_range
                }
            );
            println!("max-parallel:    {}", opts.max_parallel);
            println!(
                "stage-timeout:   {}",
                if opts.stage_timeout_secs == 0 {
                    "(unlimited)".to_string()
                } else {
                    format!("{}s", opts.stage_timeout_secs)
                }
            );
            println!("show-off-target: {}", opts.show_off_target);
            println!(
                "skip:            {}",
                if opts.skip_backends.is_empty() {
                    "(none)".to_string()
                } else {
                    opts.skip_backends
                        .iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);

    // A broken config file should not be silently ignored, but it also should
    // not stop `netmap config path` from telling you which file to go fix.
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) if matches!(cli.command, Commands::Config { .. }) => {
            tracing::warn!(error = %e, "config file could not be loaded");
            Config::default()
        }
        Err(e) => return Err(e),
    };

    match cli.command {
        Commands::Scan(args) => cmd_scan(args, &cfg).await,
        Commands::Render { input, output } => cmd_render(&input, output),
        Commands::Config { action } => cmd_config(action, &cfg),
    }
}
