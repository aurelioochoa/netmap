//! The interactive topology view.
//!
//! Node positions come from [`netmap::layout`], the same engine the SVG exporter
//! uses, so what you see here is what you get in an exported file — except for
//! nodes the user has dragged, which are pinned in screen-independent layout
//! space and therefore survive pan and zoom.

use crate::app::{NetmapApp, Phase};
use egui::{Color32, FontId, Pos2, Rect, Sense, Stroke, Vec2};
use netmap::layout::Pos;
use netmap::model::{DeviceRole, Host};
use std::net::IpAddr;

const NODE_RADIUS: f32 = 20.0;
const MIN_ZOOM: f32 = 0.15;
const MAX_ZOOM: f32 = 4.0;

/// Role colours, matched to the SVG exporter so both outputs read the same.
pub fn role_color(role: DeviceRole) -> Color32 {
    match role {
        DeviceRole::Gateway => Color32::from_rgb(0xe0, 0x52, 0x52),
        DeviceRole::Switch => Color32::from_rgb(0xe0, 0x95, 0x2f),
        DeviceRole::WirelessAP => Color32::from_rgb(0x3a, 0xa3, 0xc9),
        DeviceRole::Server => Color32::from_rgb(0x4f, 0x9d, 0x5b),
        DeviceRole::Workstation => Color32::from_rgb(0x6b, 0x74, 0xd6),
        DeviceRole::IoT => Color32::from_rgb(0xa7, 0x63, 0xc4),
        DeviceRole::Unknown => Color32::from_rgb(0x8a, 0x8f, 0x98),
    }
}

/// Where a node sits in layout space, honouring any user drag.
fn layout_pos(app: &NetmapApp, ip: IpAddr) -> Option<Pos2> {
    if let Some(p) = app.pinned.get(&ip) {
        return Some(*p);
    }
    app.layout.get(&ip).map(|Pos { x, y }| Pos2::new(x, y))
}

pub fn show(app: &mut NetmapApp, ui: &mut egui::Ui) {
    egui::CentralPanel::default().show(ui, |ui| {
        let (response, painter) = ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
        let viewport = response.rect;

        painter.rect_filled(viewport, 0.0, ui.visuals().extreme_bg_color);

        if app.graph.hosts.is_empty() {
            let msg = match app.phase {
                Phase::Scanning => "Scanning…",
                Phase::Idle => "Enter a target above and press Scan",
                _ => "No hosts discovered",
            };
            painter.text(
                viewport.center(),
                egui::Align2::CENTER_CENTER,
                msg,
                FontId::proportional(15.0),
                ui.visuals().weak_text_color(),
            );
            return;
        }

        if app.needs_fit {
            fit_to_view(app, viewport);
            app.needs_fit = false;
        }

        handle_view_input(app, ui, &response, viewport);

        let to_screen = |p: Pos2| viewport.center() + (p.to_vec2() * app.zoom) + app.pan;
        let hit_radius = NODE_RADIUS * app.zoom;

        // --- edges, drawn first so nodes sit on top ---
        let edge_stroke = Stroke::new(
            (1.5 * app.zoom).clamp(0.6, 4.0),
            ui.visuals().weak_text_color().gamma_multiply(0.7),
        );
        for edge in &app.graph.edges {
            let (Some(a), Some(b)) = (layout_pos(app, edge.from), layout_pos(app, edge.to)) else {
                continue;
            };
            painter.line_segment([to_screen(a), to_screen(b)], edge_stroke);
        }

        // --- node interaction ---
        let ips: Vec<IpAddr> = app.layout.positions.keys().copied().collect();
        let pointer = response
            .interact_pointer_pos()
            .or_else(|| ui.ctx().pointer_latest_pos());

        let mut hovered: Option<IpAddr> = None;
        if let Some(cursor) = pointer {
            // Nearest node under the cursor, so overlapping nodes resolve predictably.
            let mut best: Option<(f32, IpAddr)> = None;
            for ip in &ips {
                let Some(p) = layout_pos(app, *ip) else {
                    continue;
                };
                let d = to_screen(p).distance(cursor);
                if d <= hit_radius && best.map(|(bd, _)| d < bd).unwrap_or(true) {
                    best = Some((d, *ip));
                }
            }
            hovered = best.map(|(_, ip)| ip);
        }

        if response.clicked() {
            // Clicking empty space clears the selection.
            app.selected = hovered;
        }

        // Dragging a node pins it; dragging the background pans the view.
        if response.dragged() {
            if let Some(ip) = app
                .selected
                .filter(|_| response.dragged_by(egui::PointerButton::Primary))
            {
                if hovered == Some(ip) || app.pinned.contains_key(&ip) {
                    let delta = response.drag_delta() / app.zoom;
                    let current = layout_pos(app, ip).unwrap_or(Pos2::ZERO);
                    app.pinned.insert(ip, current + delta);
                }
            }
        }

        // --- nodes ---
        let mut ordered = ips.clone();
        ordered.sort();
        for ip in ordered {
            let Some(p) = layout_pos(app, ip) else {
                continue;
            };
            let center = to_screen(p);
            if !viewport.expand(120.0).contains(center) {
                continue; // Off-screen; skip the text work entirely.
            }

            let host = app.graph.hosts.get(&ip);
            let role = host.map(|h| h.role).unwrap_or(DeviceRole::Unknown);
            let is_selected = app.selected == Some(ip);
            let is_hovered = hovered == Some(ip);

            let r = NODE_RADIUS * app.zoom;
            painter.circle_filled(center, r, role_color(role));

            if is_selected || is_hovered {
                painter.circle_stroke(
                    center,
                    r + 3.0,
                    Stroke::new(
                        if is_selected { 2.5 } else { 1.5 },
                        ui.visuals().strong_text_color(),
                    ),
                );
            }

            // Labels shrink with zoom, and vanish once they would be unreadable.
            let label_size = 12.0 * app.zoom;
            if label_size >= 7.0 {
                let text_color = ui.visuals().text_color();
                painter.text(
                    center + Vec2::new(0.0, r + 4.0),
                    egui::Align2::CENTER_TOP,
                    role.to_string(),
                    FontId::proportional(label_size),
                    text_color,
                );
                painter.text(
                    center + Vec2::new(0.0, r + 6.0 + label_size),
                    egui::Align2::CENTER_TOP,
                    ip.to_string(),
                    FontId::monospace(label_size * 0.85),
                    ui.visuals().weak_text_color(),
                );
                if let Some(h) = host {
                    if let Some(summary) = port_summary(h) {
                        painter.text(
                            center + Vec2::new(0.0, r + 8.0 + label_size * 2.0),
                            egui::Align2::CENTER_TOP,
                            summary,
                            FontId::monospace(label_size * 0.8),
                            role_color(DeviceRole::Server),
                        );
                    }
                }
            }
        }

        if let Some(ip) = hovered {
            if let Some(host) = app.graph.hosts.get(&ip) {
                let text = tooltip_text(host);
                response.clone().on_hover_text(text);
            }
        }

        draw_overlays(app, ui, viewport, &painter);
    });
}

fn port_summary(host: &Host) -> Option<String> {
    if host.open_ports.is_empty() {
        return None;
    }
    let mut nums: Vec<u16> = host.open_ports.iter().map(|p| p.number).collect();
    nums.sort_unstable();
    nums.dedup();
    let shown: Vec<String> = nums.iter().take(3).map(|n| format!(":{n}")).collect();
    let mut s = shown.join(" ");
    if nums.len() > 3 {
        s.push_str(&format!(" +{}", nums.len() - 3));
    }
    Some(s)
}

fn tooltip_text(host: &Host) -> String {
    let mut lines = vec![format!("{}  ({})", host.ip, host.role)];
    if let Some(n) = &host.hostname {
        lines.push(format!("host: {n}"));
    }
    if let Some(m) = &host.mac {
        lines.push(format!("mac:  {m}"));
    }
    if let Some(v) = &host.vendor {
        lines.push(format!("vendor: {v}"));
    }
    if let Some(o) = &host.os_guess {
        lines.push(format!("os: {o}"));
    }
    if !host.open_ports.is_empty() {
        let ports: Vec<String> = host
            .open_ports
            .iter()
            .map(|p| match &p.service {
                Some(s) if !s.is_empty() => format!("{}/{}", p.number, s),
                _ => p.number.to_string(),
            })
            .collect();
        lines.push(format!("ports: {}", ports.join(", ")));
    }
    lines.join("\n")
}

/// Pan with drag or scroll, zoom with ctrl+scroll or pinch, anchored on the cursor.
fn handle_view_input(
    app: &mut NetmapApp,
    ui: &egui::Ui,
    response: &egui::Response,
    viewport: Rect,
) {
    let dragging_node = response.dragged() && app.selected.is_some() && !app.pinned.is_empty();
    if response.dragged() && !dragging_node {
        app.pan += response.drag_delta();
    }

    if !response.hovered() {
        return;
    }

    let (scroll, zoom_delta, cursor) = ui.input(|i| {
        (
            i.smooth_scroll_delta,
            i.zoom_delta(),
            i.pointer.latest_pos(),
        )
    });

    if zoom_delta != 1.0 {
        let anchor = cursor.unwrap_or(viewport.center());
        let old = app.zoom;
        app.zoom = (app.zoom * zoom_delta).clamp(MIN_ZOOM, MAX_ZOOM);
        // Keep the point under the cursor fixed while zooming.
        let factor = app.zoom / old;
        let offset = anchor - viewport.center() - app.pan;
        app.pan -= offset * (factor - 1.0);
    } else if scroll != Vec2::ZERO {
        app.pan += scroll;
    }
}

/// Centres and scales the graph so the whole topology is visible.
pub fn fit_to_view(app: &mut NetmapApp, viewport: Rect) {
    if app.layout.is_empty() {
        return;
    }
    let margin = 90.0;
    let w = (viewport.width() - margin * 2.0).max(50.0);
    let h = (viewport.height() - margin * 2.0).max(50.0);
    let scale = (w / app.layout.width.max(1.0)).min(h / app.layout.height.max(1.0));

    app.zoom = scale.clamp(MIN_ZOOM, 1.0);
    // The layout's origin is its top-left, so shift its centre to the viewport's.
    app.pan = -Vec2::new(app.layout.width, app.layout.height) * 0.5 * app.zoom;
}

/// Legend, synthetic-topology notice, and the zoom controls.
fn draw_overlays(app: &NetmapApp, ui: &egui::Ui, viewport: Rect, painter: &egui::Painter) {
    let roles: Vec<DeviceRole> = [
        DeviceRole::Gateway,
        DeviceRole::Switch,
        DeviceRole::WirelessAP,
        DeviceRole::Server,
        DeviceRole::Workstation,
        DeviceRole::IoT,
        DeviceRole::Unknown,
    ]
    .into_iter()
    .filter(|r| app.graph.hosts.values().any(|h| h.role == *r))
    .collect();

    let mut y = viewport.top() + 12.0;
    let x = viewport.left() + 14.0;
    for role in roles {
        painter.circle_filled(Pos2::new(x, y + 5.0), 5.0, role_color(role));
        painter.text(
            Pos2::new(x + 12.0, y),
            egui::Align2::LEFT_TOP,
            role.to_string(),
            FontId::proportional(11.0),
            ui.visuals().weak_text_color(),
        );
        y += 16.0;
    }

    if app.topology_is_synthetic() {
        painter.text(
            Pos2::new(viewport.center().x, viewport.bottom() - 18.0),
            egui::Align2::CENTER_BOTTOM,
            "Topology inferred (traceroute produced no edges) — shape is a guess, not measured",
            FontId::proportional(11.0),
            ui.visuals().warn_fg_color,
        );
    }
}
