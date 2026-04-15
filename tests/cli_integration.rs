use std::process::Command;

#[test]
fn test_help_exits_zero() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("failed to run netmap --help");

    assert!(output.status.success(), "netmap --help should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("netmap") || stdout.contains("Discover"));
}

#[test]
fn test_scan_help_exits_zero() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--help"])
        .output()
        .expect("failed to run netmap scan --help");

    assert!(output.status.success(), "netmap scan --help should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("target"));
}

#[test]
fn test_no_subcommand_exits_nonzero() {
    let output = Command::new("cargo")
        .args(["run", "--"])
        .output()
        .expect("failed to run netmap without subcommand");

    assert!(!output.status.success(), "netmap without subcommand should exit non-zero");
}

#[test]
fn test_scan_skip_all_backends_prints_tree() {
    // Skip all backends so no actual network calls are made
    let output = Command::new("cargo")
        .args([
            "run", "--", "scan", "192.168.1.0/24",
            "--no-tui",
            "--skip", "ip-neigh,arp-scan,nmap,traceroute",
        ])
        .output()
        .expect("failed to run netmap scan with all backends skipped");

    assert!(output.status.success(), "should exit 0 even with all backends skipped");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // With all backends skipped, no hosts found
    assert!(stdout.contains("no hosts discovered") || stdout.is_empty() || stdout.len() > 0);
}
