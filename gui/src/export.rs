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
