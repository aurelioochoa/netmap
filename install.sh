#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Installing system dependencies..."
bash "$SCRIPT_DIR/scripts/install_deps.sh"

echo "==> Building netmap (release)..."
cd "$SCRIPT_DIR"
cargo build --release

echo "==> Symlinking netmap to /usr/local/bin..."
sudo ln -sf "$SCRIPT_DIR/target/release/netmap" /usr/local/bin/netmap

echo "==> Done! Run: netmap scan 192.168.1.0/24 --sudo --no-tui"
