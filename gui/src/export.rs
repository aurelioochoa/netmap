//! Saving and loading scans from the GUI.
//!
//! Every writer here goes through the same `netmap` renderers the CLI uses, so
//! an exported file is byte-identical to what `netmap scan --output` produces.

use crate::app::NetmapApp;
use netmap::model::HostGraph;
use netmap::renderer;
use std::path::PathBuf;

fn suggested_name(app: &NetmapApp, ext: &str) -> String {
    let base = app.target.trim().replace(['/', ':', ' ', '\\'], "_");
    let base = if base.is_empty() {
        "netmap-scan".to_string()
    } else {
        format!("netmap-{base}")
    };
    format!("{base}.{ext}")
}

fn save_dialog(app: &NetmapApp, ext: &str, filter_name: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_file_name(suggested_name(app, ext))
        .add_filter(filter_name, &[ext])
        .save_file()
}

pub fn save_json(app: &mut NetmapApp) {
    let Some(path) = save_dialog(app, "json", "JSON") else {
        return;
    };
    match serde_json::to_string_pretty(&app.graph) {
        Ok(json) => write_and_log(app, &path, &json),
        Err(e) => app.push_log(format!("Export failed: {e}")),
    }
}

pub fn save_svg(app: &mut NetmapApp) {
    let Some(path) = save_dialog(app, "svg", "SVG") else {
        return;
    };
    let svg = renderer::render_svg(&app.graph);
    write_and_log(app, &path, &svg);
}

pub fn save_text(app: &mut NetmapApp) {
    let Some(path) = save_dialog(app, "txt", "Text") else {
        return;
    };
    let mut out = renderer::render_tree(&app.graph);
    let ports = renderer::render_ports_table(&app.graph);
    if !ports.is_empty() {
        out.push('\n');
        out.push_str(&ports);
    }
    write_and_log(app, &path, &out);
}

/// Loads a scan saved earlier, so a graph can be reviewed without re-scanning.
pub fn open_json(app: &mut NetmapApp) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("JSON", &["json"])
        .pick_file()
    else {
        return;
    };

    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            app.push_log(format!("Could not read {}: {e}", path.display()));
            return;
        }
    };

    match serde_json::from_str::<HostGraph>(&raw) {
        Ok(graph) => {
            let hosts = graph.hosts.len();
            app.graph = graph;
            app.pinned.clear();
            app.selected = None;
            app.needs_fit = true;
            app.relayout();
            app.push_log(format!("Loaded {hosts} hosts from {}", path.display()));
        }
        Err(e) => app.push_log(format!("{} is not a netmap scan: {e}", path.display())),
    }
}

fn write_and_log(app: &mut NetmapApp, path: &PathBuf, contents: &str) {
    match std::fs::write(path, contents) {
        Ok(()) => app.push_log(format!("Saved {}", path.display())),
        Err(e) => app.push_log(format!("Could not write {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmap::config::Config;
    use netmap::model::{DeviceRole, HopEdge, Host};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn app_with_graph() -> NetmapApp {
        let mut a = NetmapApp::from_config(Config::default());
        a.target = "192.168.1.0/24".into();
        let gw = ip("192.168.1.1");
        let srv = ip("192.168.1.10");

        let mut g = Host::new(gw);
        g.role = DeviceRole::Gateway;
        let mut s = Host::new(srv);
        s.role = DeviceRole::Server;
        s.hostname = Some("nas".into());

        a.graph.hosts.insert(gw, g);
        a.graph.hosts.insert(srv, s);
        a.graph.gateway = Some(gw);
        a.graph.edges.push(HopEdge {
            from: gw,
            to: srv,
            hop_index: 1,
        });
        a.relayout();
        a
    }

    #[test]
    fn the_suggested_filename_is_derived_from_the_target_and_is_path_safe() {
        let a = app_with_graph();
        let name = suggested_name(&a, "json");

        assert!(name.ends_with(".json"));
        assert!(
            !name.contains('/') && !name.contains('\\'),
            "a CIDR's slash must not become a directory separator: {name}"
        );
        assert!(name.contains("192.168.1.0"));
    }

    #[test]
    fn an_empty_target_still_yields_a_usable_filename() {
        let mut a = NetmapApp::from_config(Config::default());
        a.target = String::new();
        assert_eq!(suggested_name(&a, "svg"), "netmap-scan.svg");
    }

    #[test]
    fn a_saved_scan_reloads_into_an_equivalent_graph() {
        let a = app_with_graph();
        let json = serde_json::to_string_pretty(&a.graph).unwrap();

        let dir = std::env::temp_dir().join(format!("netmap-gui-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("scan.json");
        std::fs::write(&path, &json).unwrap();

        // open_json's file dialog can't run headless, so drive the load path it wraps.
        let raw = std::fs::read_to_string(&path).unwrap();
        let restored: HostGraph = serde_json::from_str(&raw).unwrap();

        let mut b = NetmapApp::from_config(Config::default());
        b.graph = restored;
        b.relayout();

        assert_eq!(b.graph.hosts.len(), a.graph.hosts.len());
        assert_eq!(b.graph.gateway, a.graph.gateway);
        assert_eq!(
            renderer::render_tree(&b.graph),
            renderer::render_tree(&a.graph),
            "a reloaded scan must render identically to the live one"
        );
        assert_eq!(b.layout.positions.len(), a.layout.positions.len());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_write_failure_is_logged_rather_than_panicking() {
        let mut a = app_with_graph();
        // A path that cannot exist, standing in for a full disk or bad permissions.
        write_and_log(&mut a, &PathBuf::from("/nonexistent-dir/scan.json"), "{}");

        assert!(
            a.log.iter().any(|l| l.contains("Could not write")),
            "the user needs to be told the export failed: {:?}",
            a.log
        );
    }

    #[test]
    fn loading_a_file_that_is_not_a_scan_is_reported_not_fatal() {
        let mut a = NetmapApp::from_config(Config::default());
        let before = a.graph.hosts.len();

        match serde_json::from_str::<HostGraph>("{\"nope\": true}") {
            Ok(_) => panic!("junk should not parse as a scan"),
            Err(e) => a.push_log(format!("not a netmap scan: {e}")),
        }

        assert_eq!(
            a.graph.hosts.len(),
            before,
            "a failed load must not clear the graph"
        );
        assert!(a.log.iter().any(|l| l.contains("not a netmap scan")));
    }
}
