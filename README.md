# netmap

A CLI tool that automatically discovers and renders a network topology map directly in the terminal.

Combines multiple scanner backends (ip neigh, arp-scan, nmap, traceroute) into a unified host graph, then visualises it as a plain-text tree.

## Quick Start

```bash
git clone https://github.com/…/netmap
cd netmap
chmod +x install.sh
./install.sh      # installs system deps + builds + symlinks netmap to /usr/local/bin
netmap scan 192.168.1.0/24 --sudo --no-tui
```

## Usage

```
netmap scan <target> [OPTIONS]
  --ports <range>        Port range (e.g., "1-1024")
  --sudo                 Prepend sudo to backends that require it
  --timeout <sec>        Per-host timeout (default: 5)
  --output <file>        Save JSON on exit (extension determines format)
  --no-tui               Print plain-text tree and exit
  --skip <backend>       Skip a backend: ip-neigh, arp-scan, nmap, traceroute
```

## Example Output

```
[router] 192.168.1.1  (gateway)
├── [server] 192.168.1.10  nginx  :80 :443 :22
├── [workstation] 192.168.1.20  mypc
└── [IoT] 192.168.1.50  Philips Hue
```

## Requirements

- Rust toolchain (cargo)
- nmap, arp-scan, traceroute, iproute2 (Linux) or arp (macOS)

The `install.sh` script handles system dependency installation automatically.

## License

MIT
