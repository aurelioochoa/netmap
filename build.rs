fn main() {
    let tools = [
        ("nmap", "nmap"),
        ("arp-scan", "arp-scan"),
        ("traceroute", "traceroute"),
    ];

    for (name, bin) in &tools {
        if which::which(bin).is_err() {
            println!("cargo:warning={} not found in PATH. The '{}' backend will be unavailable at runtime.", bin, name);
        }
    }

    // ip (Linux) or arp (macOS)
    if cfg!(target_os = "linux") {
        if which::which("ip").is_err() {
            println!("cargo:warning=ip (iproute2) not found in PATH. The 'ip-neigh' backend will be unavailable.");
        }
    } else {
        if which::which("arp").is_err() {
            println!("cargo:warning=arp not found in PATH. The 'ip-neigh' backend will be unavailable.");
        }
    }
}
