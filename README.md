# netmap

A CLI tool that automatically discovers and renders a 2D network topology map directly in the terminal.

Combines multiple scanner backends (ip neigh, arp-scan, nmap, traceroute) into a unified host graph, infers device roles (router, switch, wap/switch, server, workstation, IoT), and renders an ASCII topology diagram.

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
  --no-tui               Print plain-text topology and exit
  --skip <backend>       Skip a backend: ip-neigh, arp-scan, nmap, traceroute
```

## Example Output

```
Internet
   |
router
   |
switch
   |
wap/switch - wap/switch (mesh-ap) - server :80 :443
     |                 |
wap/switch - workstation (tower) - workstation (desktop)
     |                |
server :22 :8080 - workstation (laptop)
```

## Makefile

```bash
make build          # debug build
make release        # optimized build
make test           # run tests (shows rendered diagram)
make run            # scan default target (override: make run TARGET=10.0.0.0/24)
make lint           # clippy
make docker         # build Docker image
make docker-run     # run scan in Docker
make docker-test    # run tests in Docker
```

## Docker

```bash
docker compose up               # run a scan
docker compose build --no-cache # rebuild image
```

The container runs as root with `NET_RAW`/`NET_ADMIN` capabilities and `network_mode: host`.

## Requirements

- Rust toolchain (cargo)
- nmap, arp-scan, traceroute, iproute2 (Linux) or arp (macOS)

The `install.sh` script handles system dependency installation automatically.

## License

MIT
