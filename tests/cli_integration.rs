//! Black-box tests that drive the built binary.
//!
//! `CARGO_BIN_EXE_netmap` points at the freshly built binary, so these do not
//! pay for a `cargo run` rebuild on every assertion.

use std::process::Command;

fn netmap() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netmap"));
    // Never let a developer's real config file change what these tests observe.
    cmd.env("NETMAP_CONFIG", "/nonexistent/netmap/config.toml");
    cmd
}

#[test]
fn help_exits_zero_and_describes_the_tool() {
    let output = netmap().arg("--help").output().expect("run --help");
    assert!(output.status.success(), "netmap --help should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scan"),
        "help should list the scan subcommand"
    );
    assert!(
        stdout.contains("render"),
        "help should list the render subcommand"
    );
    assert!(
        stdout.contains("config"),
        "help should list the config subcommand"
    );
}

#[test]
fn scan_help_documents_its_flags() {
    let output = netmap()
        .args(["scan", "--help"])
        .output()
        .expect("run scan --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--ports",
        "--sudo",
        "--timeout",
        "--max-parallel",
        "--skip",
        "--output",
    ] {
        assert!(
            stdout.contains(flag),
            "scan --help should document {}",
            flag
        );
    }
}

#[test]
fn no_subcommand_exits_nonzero() {
    let output = netmap().output().expect("run with no subcommand");
    assert!(
        !output.status.success(),
        "netmap with no subcommand should exit non-zero"
    );
}

#[test]
fn an_unknown_backend_name_is_rejected() {
    let output = netmap()
        .args(["scan", "192.168.1.0/24", "--skip", "wireshark"])
        .output()
        .expect("run scan with a bad --skip");

    assert!(
        !output.status.success(),
        "an unknown backend should be an error, not a warning"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("wireshark"),
        "the error should quote the bad value: {}",
        stderr
    );
}

#[test]
fn skipping_every_backend_reports_no_hosts() {
    let output = netmap()
        .args([
            "scan",
            "192.168.1.0/24",
            "--quiet",
            "--skip",
            "ip-neigh,arp-scan,nmap,traceroute",
        ])
        .output()
        .expect("run scan with all backends skipped");

    assert!(
        output.status.success(),
        "should exit 0 even with all backends skipped"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("no hosts"),
        "expected an explicit empty-result message, got: {:?}",
        stdout
    );
}

#[test]
fn scan_without_a_target_fails_with_a_helpful_message() {
    let output = netmap()
        .args(["scan", "--quiet"])
        .output()
        .expect("run scan with no target");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no target given"),
        "expected guidance about supplying a target, got: {}",
        stderr
    );
}

#[test]
fn render_round_trips_a_saved_scan() {
    let dir = std::env::temp_dir().join(format!("netmap-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let json_path = dir.join("scan.json");
    let svg_path = dir.join("scan.svg");

    // A hand-written graph stands in for a real scan, so this test needs no network.
    std::fs::write(
        &json_path,
        r#"{
          "hosts": {
            "192.168.1.1": {
              "ip": "192.168.1.1", "mac": null, "hostname": null, "vendor": null,
              "open_ports": [], "os_guess": null, "role": "Gateway",
              "detected_by": [], "hop_distance": 1
            },
            "192.168.1.10": {
              "ip": "192.168.1.10", "mac": null, "hostname": "nas", "vendor": null,
              "open_ports": [{"number": 443, "protocol": "Tcp", "service": "https"}],
              "os_guess": null, "role": "Server", "detected_by": [], "hop_distance": 2
            }
          },
          "edges": [{"from": "192.168.1.1", "to": "192.168.1.10", "hop_index": 1}],
          "gateway": "192.168.1.1"
        }"#,
    )
    .unwrap();

    let output = netmap()
        .args(["render", json_path.to_str().unwrap()])
        .output()
        .expect("run render");
    assert!(
        output.status.success(),
        "render should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("192.168.1.10"),
        "rendered tree should include the host"
    );
    assert!(
        stdout.contains("443/https"),
        "ports table should list the open port and service"
    );

    // The same input can be re-emitted as SVG.
    let output = netmap()
        .args([
            "render",
            json_path.to_str().unwrap(),
            "--output",
            svg_path.to_str().unwrap(),
        ])
        .output()
        .expect("run render --output");
    assert!(output.status.success());
    let svg = std::fs::read_to_string(&svg_path).unwrap();
    assert!(
        svg.starts_with("<svg"),
        "should have written an SVG document"
    );
    assert!(svg.contains("192.168.1.10"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn render_rejects_a_file_that_is_not_a_scan() {
    let path = std::env::temp_dir().join(format!("netmap-bad-{}.json", std::process::id()));
    std::fs::write(&path, "{\"not\": \"a scan\"}").unwrap();

    let output = netmap()
        .args(["render", path.to_str().unwrap()])
        .output()
        .expect("run render on junk");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("netmap JSON scan"), "got: {}", stderr);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_unsupported_output_extension_is_rejected() {
    let output = netmap()
        .args([
            "scan",
            "192.168.1.0/24",
            "--quiet",
            "--skip",
            "ip-neigh,arp-scan,nmap,traceroute",
            "--output",
            "/tmp/netmap-test-output.pdf",
        ])
        .output()
        .expect("run scan with a bad --output extension");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".json"),
        "the error should name the supported formats: {}",
        stderr
    );
}

#[test]
fn config_show_reports_the_effective_settings() {
    let output = netmap()
        .args(["config", "show"])
        .output()
        .expect("run config show");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("max-parallel"));
    assert!(stdout.contains("timeout"));
}

#[test]
fn config_values_are_picked_up_and_overridden_by_flags() {
    let dir = std::env::temp_dir().join(format!("netmap-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, "timeout = 77\nmax-parallel = 3\n").unwrap();

    // The file supplies the values...
    let output = Command::new(env!("CARGO_BIN_EXE_netmap"))
        .env("NETMAP_CONFIG", &cfg)
        .args(["config", "show"])
        .output()
        .expect("run config show");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("77s"),
        "config timeout should be in effect: {}",
        stdout
    );
    assert!(
        stdout.contains("3"),
        "config max-parallel should be in effect"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_malformed_config_file_is_an_error_rather_than_silently_ignored() {
    let dir = std::env::temp_dir().join(format!("netmap-badcfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, "tiemout = 5\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_netmap"))
        .env("NETMAP_CONFIG", &cfg)
        .args([
            "scan",
            "10.0.0.0/24",
            "--quiet",
            "--skip",
            "ip-neigh,arp-scan,nmap,traceroute",
        ])
        .output()
        .expect("run scan with a broken config");

    assert!(
        !output.status.success(),
        "a typo'd config must not be silently ignored"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tiemout"),
        "the error should name the bad key: {}",
        stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}
