# netmap — Design Spec

**Date:** 2026-04-08  
**Status:** Approved  
**Language:** Rust  
**Location:** `/home/aurelio/Repos/netmap/`

---

## Context

`netmap` is a CLI tool that automatically discovers and renders a network topology map directly in the terminal. It combines multiple scanner backends (ip neigh, arp-scan, nmap, traceroute) into a unified host graph, then visualises it as an interactive TUI or plain-text tree.

The project is phased:
- **Phase 1** — Scanner pipeline + `--no-tui` plain-text output
- **Phase 2** — Interactive ratatui TUI
- **Phase 3** — JSON and SVG export

---

## Architecture

### Project Structure

```
netmap/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs              # clap CLI entry point
    ├── model.rs             # HostGraph, Host, Port, HopEdge, DeviceRole, BackendKind
    ├── pipeline.rs          # Orchestrates backends, merges PartialHost → Host
    ├── backends/
    │   ├── mod.rs           # ScanBackend trait, ScanOptions, ScanResult, PartialHost
    │   ├── ip_neigh.rs      # `ip neigh show` parser
    │   ├── arp_scan.rs      # `arp-scan -l` runner + parser
    │   ├── nmap.rs          # nmap XML parser (quick-xml + serde)
    │   └── traceroute.rs    # traceroute stdout parser → HopEdge list
    ├── tui/                 # Phase 2
    │   ├── mod.rs           # App struct, crossterm event loop, mpsc channel
    │   ├── topology.rs      # Topology tree widget (box-drawing characters)
    │   ├── detail.rs        # Host detail sidebar widget
    │   └── statusbar.rs     # Pipeline stage + host count + elapsed time
    ├── renderer/
    │   └── mod.rs           # Plain-text tree renderer (shared logic)
    └── output/              # Phase 3
        ├── json.rs          # serde_json export
        └── svg.rs           # Hand-built SVG string
```

---

## Data Model (`model.rs`)

```rust
pub struct HostGraph {
    pub hosts: HashMap<IpAddr, Host>,
    pub edges: Vec<HopEdge>,
    pub gateway: Option<IpAddr>,  // first common traceroute hop
}

pub struct Host {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,      // derived from MAC OUI prefix
    pub open_ports: Vec<Port>,
    pub os_guess: Option<String>,
    pub role: DeviceRole,
    pub detected_by: Vec<BackendKind>,
    pub hop_distance: Option<u8>,
}

pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub service: Option<String>,
}

pub struct HopEdge {
    pub from: IpAddr,
    pub to: IpAddr,
    pub hop_index: u8,
}

pub enum DeviceRole { Gateway, Server, Workstation, IoT, Unknown }
pub enum Protocol { Tcp, Udp }
pub enum BackendKind { IpNeigh, ArpScan, Nmap, Traceroute }
```

---

## Backend Trait (`backends/mod.rs`)

```rust
#[async_trait]
pub trait ScanBackend: Send + Sync {
    fn name(&self) -> BackendKind;
    fn is_available(&self) -> bool;  // uses `which::which()`, never panics
    async fn scan(&self, target: &str, opts: &ScanOptions) -> Result<ScanResult>;
}

pub struct ScanOptions {
    pub sudo: bool,
    pub timeout_secs: u64,
    pub port_range: String,       // e.g. "1-1024" or "top100"
    pub skip_backends: Vec<BackendKind>,
    pub max_parallel: usize,      // traceroute/nmap fingerprint concurrency cap
}

pub struct ScanResult {
    pub hosts: Vec<PartialHost>,  // sparse — only fields this backend knows
    pub edges: Vec<HopEdge>,      // non-empty only from traceroute
}

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
```

---

## Pipeline (`pipeline.rs`)

Sequential stage execution, each stage merges into `HostGraph` by IP:

1. **ip neigh** — reads `ip neigh show`, no subprocess needed. Zero cost. No sudo.
2. **arp-scan** — runs `arp-scan -l` (or `sudo arp-scan -l`). Adds MAC addresses.
3. **nmap discover** — runs `nmap -sn <target> -oX -`. Catches WAN-side hosts.
4. **nmap fingerprint** — runs `nmap -sV [-O] <host> -oX -` per host. Parallel via `JoinSet`, capped at `opts.max_parallel` (default 10).
5. **traceroute** — runs `traceroute -n <host>` per host. Parallel via `JoinSet`. Builds `HopEdge` list. Gateway = first IP appearing as hop 1 in ≥2 paths.

Unavailable backends (checked via `is_available()`) log a warning and return `ScanResult::empty()`.

**Merge rules:**
- MAC: prefer arp-scan over nmap
- Ports/OS: prefer nmap fingerprint
- Hostname: prefer nmap over ip neigh
- Vendor: derived from MAC OUI at merge time
- `detected_by`: union of all backends that saw the host

**Role inference** (applied after all merges):
- **Gateway** → IP matches `graph.gateway`
- **Server** → open ports ∩ {22, 25, 80, 443, 3306, 5432, 8080, 8443} non-empty
- **Workstation** → open ports ∩ {139, 445, 3389} non-empty, or no server/IoT ports
- **IoT** → detected by arp-scan, no standard server/workstation ports, OR OUI matches known IoT vendors
- **Unknown** → fallback

---

## Backends

### `ip_neigh.rs`
On Linux: runs `ip neigh show`, parses:
```
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
```
On macOS: falls back to `arp -an`, parses:
```
? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
```
`is_available()` checks for `ip` on Linux, `arp` on macOS (always true on both). Skips `FAILED`/`INCOMPLETE`/`incomplete` entries.

### `arp_scan.rs`
Runs `[sudo] arp-scan -l`, parses tab-separated output:
```
192.168.1.42    aa:bb:cc:dd:ee:ff    Apple, Inc.
```
Extracts IP + MAC + vendor.

### `nmap.rs`
Runs `nmap [args] -oX -` and deserialises XML using `quick-xml` + serde structs matching nmap's schema. Two modes:
- **Discovery** (`-sn`): extracts IPs + hostnames + MACs
- **Fingerprint** (`-sV -O` or `-sV`): extracts open ports + service names + OS guess

### `traceroute.rs`
Runs `traceroute -n <host>`, parses stdout with regex:
```
 1  192.168.1.1    1.2 ms  ...
 2  10.0.0.1       5.4 ms  ...
 3  * * *
```
`* * *` hops are skipped (no node). Returns `HopEdge` list: `(local_ip → hop1)`, `(hop1 → hop2)`, etc.

---

## Renderer (`renderer/mod.rs`)

Builds a tree string using box-drawing characters from the `HostGraph`. Used by both `--no-tui` mode and Phase 2 TUI topology widget.

```
[router] 192.168.1.1  (gateway)
├── [server] 192.168.1.10  nginx  :80 :443 :22
├── [workstation] 192.168.1.20  mypc
│   └── [unknown] 192.168.1.21
└── [IoT] 192.168.1.50  Philips Hue
```

Node format: `[role-icon] IP  hostname  top-3-ports`

---

## TUI (`tui/`) — Phase 2

**Layout:**
```
┌─────────────────────────────┬──────────────────────┐
│  Topology (main panel)      │  Host Detail         │
│                             │  IP: 192.168.1.10    │
│  [router] 192.168.1.1       │  MAC: aa:bb:cc:...   │
│  ├── [server] 192.168.1.10  │  Vendor: Apple       │
│  └── [workstation] ...      │  OS: Linux 5.x       │
│                             │  Ports: 22 80 443    │
│                             │  Detected by: nmap   │
├─────────────────────────────┴──────────────────────┤
│  Stage: traceroute  │  Hosts: 12  │  Elapsed: 14s  │
└──────────────────────────────────────────────────────┘
```

**Architecture:**
- Scan runs in background `tokio::task`, sends `HostGraph` snapshots via `mpsc::channel` after each pipeline stage
- `App` struct: `graph: HostGraph`, `selected: IpAddr`, `show_detail: bool`, `stage: PipelineStage`
- Event loop polls crossterm events + channel with `tokio::select!`

**Keyboard:**
- `↑↓` / `hjkl` — navigate nodes
- `Enter` — expand/collapse subtree
- `r` — re-run full scan
- `s` — toggle detail sidebar
- `q` / `Esc` — quit

**Colors:**
- Gateway/router → Yellow
- Server → Blue
- Workstation → Green
- IoT/Unknown → White
- Unreachable (timeout hop) → Dim Red

---

## CLI (`main.rs`)

```
netmap scan <target> [OPTIONS]
  --ports <range>        Port range (default: top100 via nmap default)
  --sudo                 Prepend sudo to backends that require it
  --timeout <sec>        Per-host timeout (default: 5)
  --output <file>        Save JSON or SVG on exit (extension determines format)
  --no-tui               Print plain-text tree and exit
  --skip <backend>       Skip a backend: ip-neigh | arp-scan | nmap | traceroute
```

---

## Output (`output/`) — Phase 3

**JSON** (`json.rs`): Serialise `HostGraph` with `serde_json`. Full fidelity.

**SVG** (`svg.rs`): Hand-built SVG string (no external crate). Hierarchical tree layout: gateway at top, hosts below, connected by `<line>` elements. Nodes are `<rect>` + `<text>`. Role-based fill colours match TUI theme.

---

## Installation & System Dependency Bootstrap

The install process must ensure all four backend tools are present before the binary is used. This is handled by `install.sh` at the repo root.

### Project layout addition

```
netmap/
├── install.sh             ← entrypoint: installs system deps + builds + links binary
├── scripts/
│   └── install_deps.sh   ← OS/package-manager detection + package installation
├── build.rs               ← emits cargo:warning= for any tool missing at compile time
```

### `install.sh` flow

1. Run `scripts/install_deps.sh` — installs system tools via detected package manager
2. Run `cargo build --release`
3. Symlink `target/release/netmap` → `/usr/local/bin/netmap`

### `scripts/install_deps.sh`

Detects OS and package manager, installs:

| Tool | Package |
|------|---------|
| `nmap` | `nmap` |
| `arp-scan` | `arp-scan` |
| `traceroute` | `traceroute` |
| `ip` (iproute2) | `iproute2` (Linux only) |

Detection order: `apt-get` → `dnf` → `yum` → `pacman` → `brew` (macOS).  
If `brew` is missing on macOS, exits with install instructions for Homebrew.  
On macOS: `traceroute` and `arp` are built-in; `iproute2` is skipped.

### `build.rs`

At `cargo build` time, uses `which::which()` to check for each tool and emits `cargo:warning=` messages for any that are missing — visible in `cargo build` output without failing the build.

### README install

```bash
git clone https://github.com/…/netmap
cd netmap
chmod +x install.sh
./install.sh      # installs system deps + builds + symlinks netmap to /usr/local/bin
netmap scan 192.168.1.0/24 --sudo
```

---

## Rust Dependencies (Cargo)

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
quick-xml = { version = "0.31", features = ["serialize"] }
ratatui = "0.28"
crossterm = "0.28"
regex = "1"
anyhow = "1"
which = "6"
tracing = "1"
tracing-subscriber = "1"
```

Cargo crates are downloaded automatically by `cargo build`. No manual steps required.

---

## Verification

**Phase 1:**
```bash
./install.sh
netmap scan 192.168.1.0/24 --no-tui --sudo
netmap scan 192.168.1.0/24 --no-tui --skip arp-scan --skip traceroute
netmap scan 192.168.1.1 --no-tui --timeout 3
```
Expected: tree printed to stdout, graceful warnings for missing backends.

**Phase 2:**
```bash
netmap scan 192.168.1.0/24 --sudo
```
Expected: TUI launches, topology renders, sidebar updates on node selection, status bar shows pipeline progress, `q` exits cleanly.

**Phase 3:**
```bash
netmap scan 192.168.1.0/24 --no-tui --output topology.json
netmap scan 192.168.1.0/24 --no-tui --output topology.svg
```
Expected: valid JSON file with full graph, valid SVG file opening in browser.
