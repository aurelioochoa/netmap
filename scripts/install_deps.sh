#!/usr/bin/env bash
set -euo pipefail

install_with_apt() {
    echo "  Using apt-get..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq nmap arp-scan traceroute iproute2
}

install_with_dnf() {
    echo "  Using dnf..."
    sudo dnf install -y nmap arp-scan traceroute iproute
}

install_with_yum() {
    echo "  Using yum..."
    sudo yum install -y nmap arp-scan traceroute iproute
}

install_with_pacman() {
    echo "  Using pacman..."
    sudo pacman -S --noconfirm nmap arp-scan traceroute iproute2
}

install_with_brew() {
    echo "  Using Homebrew..."
    brew install nmap arp-scan
    # traceroute and arp are built-in on macOS
}

OS="$(uname -s)"

case "$OS" in
    Linux)
        if command -v apt-get &>/dev/null; then
            install_with_apt
        elif command -v dnf &>/dev/null; then
            install_with_dnf
        elif command -v yum &>/dev/null; then
            install_with_yum
        elif command -v pacman &>/dev/null; then
            install_with_pacman
        else
            echo "ERROR: No supported package manager found (apt-get, dnf, yum, pacman)."
            echo "Please install manually: nmap, arp-scan, traceroute, iproute2"
            exit 1
        fi
        ;;
    Darwin)
        if command -v brew &>/dev/null; then
            install_with_brew
        else
            echo "ERROR: Homebrew not found."
            echo "Install Homebrew first: https://brew.sh"
            echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
        ;;
    *)
        echo "ERROR: Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "  System dependencies installed."
