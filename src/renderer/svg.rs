//! SVG export.
//!
//! Shares [`crate::layout`] with the GUI canvas, so an exported diagram is
//! geometrically identical to what was on screen.

use crate::layout::{layout_graph, Pos};
use crate::model::{DeviceRole, Host, HostGraph};
use std::fmt::Write as _;

const PADDING: f32 = 60.0;
const NODE_RADIUS: f32 = 22.0;
const LEGEND_ROW_H: f32 = 22.0;

/// Colour per role. Chosen to stay distinguishable in both light and dark
/// viewers and under the common forms of colour-blindness — role is also always
/// spelled out in the label, so colour is never the only carrier of meaning.
fn role_color(role: DeviceRole) -> &'static str {
    match role {
        DeviceRole::Gateway => "#e05252",
        DeviceRole::Switch => "#e0952f",
        DeviceRole::WirelessAP => "#3aa3c9",
        DeviceRole::Server => "#4f9d5b",
        DeviceRole::Workstation => "#6b74d6",
        DeviceRole::IoT => "#a763c4",
        DeviceRole::Unknown => "#8a8f98",
    }
}

/// XML-escapes text destined for a text node or attribute value.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Up to three port numbers, then a count of the rest, so a host with 40 open
/// ports does not smother the diagram.
fn port_summary(host: &Host) -> Option<String> {
    if host.open_ports.is_empty() {
        return None;
    }
    let mut nums: Vec<u16> = host.open_ports.iter().map(|p| p.number).collect();
    nums.sort_unstable();
    nums.dedup();
    let shown: Vec<String> = nums.iter().take(3).map(|n| format!(":{}", n)).collect();
    let mut s = shown.join(" ");
    if nums.len() > 3 {
        let _ = write!(s, " +{}", nums.len() - 3);
    }
    Some(s)
}

/// Renders `graph` as a standalone SVG document.
///
/// Deterministic for a given graph, which is what makes it snapshot-testable.
pub fn render_svg(graph: &HostGraph) -> String {
    let layout = layout_graph(graph);

    if layout.is_empty() {
        return empty_svg();
    }

    // Roles actually present, in a stable order, for the legend.
    let mut roles: Vec<DeviceRole> = Vec::new();
    for role in [
        DeviceRole::Gateway,
        DeviceRole::Switch,
        DeviceRole::WirelessAP,
        DeviceRole::Server,
        DeviceRole::Workstation,
        DeviceRole::IoT,
        DeviceRole::Unknown,
    ] {
        if graph.hosts.values().any(|h| h.role == role) {
            roles.push(role);
        }
    }

    let legend_h = if roles.is_empty() {
        0.0
    } else {
        roles.len() as f32 * LEGEND_ROW_H + 20.0
    };
    let width = layout.width + PADDING * 2.0;
    let height = layout.height + PADDING * 2.0 + legend_h;
    let shift = |p: Pos| (p.x + PADDING, p.y + PADDING);

    let mut svg = String::with_capacity(4096);
    let _ = write!(
        svg,
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:.0} {h:.0}" width="{w:.0}" height="{h:.0}" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">
<title>netmap topology</title>
<style>
  .bg   {{ fill: #ffffff; }}
  .edge {{ stroke: #b4b8c0; stroke-width: 1.8; }}
  .lbl  {{ fill: #1b1f24; font-size: 12px; }}
  .sub  {{ fill: #656b73; font-size: 10px; }}
  .ring {{ stroke: #ffffff; stroke-width: 2; }}
  @media (prefers-color-scheme: dark) {{
    .bg   {{ fill: #0d1117; }}
    .edge {{ stroke: #3d444d; }}
    .lbl  {{ fill: #e6edf3; }}
    .sub  {{ fill: #9198a1; }}
    .ring {{ stroke: #0d1117; }}
  }}
</style>
<rect class="bg" width="100%" height="100%"/>
"#,
        w = width,
        h = height
    );

    // Edges first so nodes paint on top of them.
    svg.push_str("<g class=\"edges\">\n");
    for edge in &graph.edges {
        let (Some(a), Some(b)) = (layout.get(&edge.from), layout.get(&edge.to)) else {
            continue;
        };
        let (x1, y1) = shift(a);
        let (x2, y2) = shift(b);
        let _ = writeln!(
            svg,
            r#"  <line class="edge" x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}"/>"#,
            x1, y1, x2, y2
        );
    }
    svg.push_str("</g>\n");

    // Nodes in IP order so the document itself is stable, not just the geometry.
    let mut ips: Vec<std::net::IpAddr> = layout.positions.keys().copied().collect();
    crate::renderer::sort_ips(&mut ips);

    svg.push_str("<g class=\"nodes\">\n");
    for ip in ips {
        let Some(pos) = layout.get(&ip) else { continue };
        let (x, y) = shift(pos);
        let host = graph.hosts.get(&ip);
        let role = host.map(|h| h.role).unwrap_or(DeviceRole::Unknown);

        let _ = writeln!(
            svg,
            r#"  <circle class="ring" cx="{:.1}" cy="{:.1}" r="{:.1}" fill="{}"/>"#,
            x,
            y,
            NODE_RADIUS,
            role_color(role)
        );

        let _ = writeln!(
            svg,
            r#"  <text class="lbl" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
            x,
            y + NODE_RADIUS + 15.0,
            esc(&role.to_string())
        );
        let _ = writeln!(
            svg,
            r#"  <text class="sub" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
            x,
            y + NODE_RADIUS + 28.0,
            esc(&ip.to_string())
        );

        let mut extra_y = y + NODE_RADIUS + 40.0;
        if let Some(h) = host {
            if let Some(name) = &h.hostname {
                let _ = writeln!(
                    svg,
                    r#"  <text class="sub" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
                    x,
                    extra_y,
                    esc(name)
                );
                extra_y += 12.0;
            }
            if let Some(ports) = port_summary(h) {
                let _ = writeln!(
                    svg,
                    r#"  <text class="sub" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
                    x,
                    extra_y,
                    esc(&ports)
                );
            }
        }
    }
    svg.push_str("</g>\n");

    if !roles.is_empty() {
        let base_y = layout.height + PADDING * 2.0;
        svg.push_str("<g class=\"legend\">\n");
        for (i, role) in roles.iter().enumerate() {
            let y = base_y + i as f32 * LEGEND_ROW_H;
            let _ = writeln!(
                svg,
                r#"  <circle cx="{:.1}" cy="{:.1}" r="6" fill="{}"/>"#,
                PADDING,
                y,
                role_color(*role)
            );
            let _ = writeln!(
                svg,
                r#"  <text class="sub" x="{:.1}" y="{:.1}">{}</text>"#,
                PADDING + 14.0,
                y + 4.0,
                esc(&role.to_string())
            );
        }
        svg.push_str("</g>\n");
    }

    svg.push_str("</svg>\n");
    svg
}

fn empty_svg() -> String {
    r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 80" width="320" height="80" font-family="ui-monospace, monospace">
<title>netmap topology</title>
<rect width="100%" height="100%" fill="#ffffff"/>
<text x="160" y="44" text-anchor="middle" fill="#656b73" font-size="13">No hosts discovered</text>
</svg>
"##
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HopEdge, Host, Port, Protocol};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sample_graph() -> HostGraph {
        let mut g = HostGraph::empty();
        let gw = ip("192.168.1.1");
        let srv = ip("192.168.1.10");

        let mut g1 = Host::new(gw);
        g1.role = DeviceRole::Gateway;
        let mut s1 = Host::new(srv);
        s1.role = DeviceRole::Server;
        s1.hostname = Some("fileserver".into());
        s1.open_ports = vec![
            Port {
                number: 443,
                protocol: Protocol::Tcp,
                service: Some("https".into()),
            },
            Port {
                number: 80,
                protocol: Protocol::Tcp,
                service: Some("http".into()),
            },
        ];

        g.hosts.insert(gw, g1);
        g.hosts.insert(srv, s1);
        g.edges.push(HopEdge {
            from: gw,
            to: srv,
            hop_index: 1,
        });
        g.gateway = Some(gw);
        g
    }

    #[test]
    fn empty_graph_renders_a_valid_placeholder() {
        let svg = render_svg(&HostGraph::empty());
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.contains("No hosts discovered"));
    }

    #[test]
    fn output_is_well_formed_and_contains_every_host() {
        let svg = render_svg(&sample_graph());
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert_eq!(svg.matches("<circle class=\"ring\"").count(), 2);
        assert!(svg.contains("192.168.1.1"));
        assert!(svg.contains("192.168.1.10"));
        assert!(svg.contains("fileserver"));
    }

    #[test]
    fn edges_are_drawn_between_positioned_hosts() {
        let svg = render_svg(&sample_graph());
        assert_eq!(svg.matches("<line class=\"edge\"").count(), 1);
    }

    #[test]
    fn ports_are_summarized_and_truncated() {
        let mut h = Host::new(ip("10.0.0.2"));
        for n in [22u16, 80, 443, 8080, 9090] {
            h.open_ports.push(Port {
                number: n,
                protocol: Protocol::Tcp,
                service: None,
            });
        }
        let s = port_summary(&h).unwrap();
        assert_eq!(s, ":22 :80 :443 +2", "should show three ports then a count");
        assert!(port_summary(&Host::new(ip("10.0.0.3"))).is_none());
    }

    #[test]
    fn hostnames_are_xml_escaped() {
        let mut g = HostGraph::empty();
        let a = ip("10.0.0.9");
        let mut h = Host::new(a);
        h.hostname = Some("bad<&\"name".into());
        g.hosts.insert(a, h);

        let svg = render_svg(&g);
        assert!(svg.contains("bad&lt;&amp;&quot;name"));
        assert!(
            !svg.contains("bad<&\"name"),
            "raw markup must not leak through"
        );
    }

    #[test]
    fn a_legend_lists_only_the_roles_present() {
        let svg = render_svg(&sample_graph());
        assert!(svg.contains(r#"<g class="legend">"#));
        assert!(svg.contains(">router<"));
        assert!(svg.contains(">server<"));
        assert!(
            !svg.contains(">IoT<"),
            "absent roles should not be in the legend"
        );
    }

    #[test]
    fn rendering_is_deterministic() {
        let g = sample_graph();
        assert_eq!(render_svg(&g), render_svg(&g));
    }
}
