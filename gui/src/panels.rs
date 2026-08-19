//! Top bar, host list, and details/log panes.

use crate::app::{NetmapApp, Phase};
use crate::canvas::role_color;
use crate::export;
use egui::RichText;
use netmap::model::BackendKind;

pub fn top_bar(app: &mut NetmapApp, ui: &mut egui::Ui) {
    egui::Panel::top("top_bar").show(ui, |ui| {
        let ctx = ui.ctx().clone();
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("netmap").strong());
            ui.separator();

            ui.label("Target:");
            let target_box = ui.add(
                egui::TextEdit::singleline(&mut app.target)
                    .desired_width(180.0)
                    .hint_text("192.168.1.0/24"),
            );
            let submitted =
                target_box.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            let scanning = app.is_scanning();
            if scanning {
                if ui.button("Cancel").clicked() {
                    app.cancel_scan();
                }
                ui.spinner();
            } else if ui.button("Scan").clicked() || submitted {
                app.start_scan(&ctx);
            }

            ui.separator();
            ui.add_enabled_ui(!scanning, |ui| {
                ui.checkbox(&mut app.sudo, "sudo")
                    .on_hover_text("Run privileged backends via sudo (arp-scan, nmap -O)");

                ui.label("Ports:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.ports)
                        .desired_width(80.0)
                        .hint_text("1-1024"),
                );

                ui.label("Timeout:");
                ui.add(
                    egui::DragValue::new(&mut app.timeout)
                        .range(0..=3600)
                        .suffix("s"),
                )
                .on_hover_text("Per-host probe budget; 0 disables the limit");

                ui.label("Parallel:");
                ui.add(egui::DragValue::new(&mut app.max_parallel).range(1..=128));
            });

            ui.separator();
            ui.menu_button("Backends", |ui| {
                ui.set_min_width(160.0);
                for (i, kind) in BackendKind::ALL.iter().enumerate() {
                    ui.checkbox(&mut app.backends[i], kind.to_string());
                }
                ui.separator();
                ui.checkbox(&mut app.show_off_target, "Show off-target hosts")
                    .on_hover_text(
                        "Keep hosts outside the target CIDR (docker bridge, link-local)",
                    );
            });

            ui.menu_button("Export", |ui| {
                ui.set_min_width(150.0);
                let has_hosts = !app.graph.hosts.is_empty();
                ui.add_enabled_ui(has_hosts, |ui| {
                    if ui.button("Save as JSON…").clicked() {
                        export::save_json(app);
                        ui.close();
                    }
                    if ui.button("Save as SVG…").clicked() {
                        export::save_svg(app);
                        ui.close();
                    }
                    if ui.button("Save ASCII tree…").clicked() {
                        export::save_text(app);
                        ui.close();
                    }
                });
                ui.separator();
                if ui.button("Open saved scan…").clicked() {
                    export::open_json(app);
                    ui.close();
                }
            });

            if ui
                .button("Fit")
                .on_hover_text("Fit the whole topology in view")
                .clicked()
            {
                app.needs_fit = true;
            }

            // Status sits on the right, where it does not push the controls around.
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| match app.phase {
                    Phase::Scanning => {
                        let msg = match app.progress {
                            Some((done, total)) => format!("{} — {done}/{total}", app.stage),
                            None => app.stage.clone(),
                        };
                        ui.label(RichText::new(msg).weak());
                    }
                    Phase::Done | Phase::Cancelled => {
                        let secs = app.elapsed.map(|d| d.as_secs_f32()).unwrap_or(0.0);
                        let label = format!(
                            "{} host{}, {} edge{} in {:.1}s",
                            app.graph.hosts.len(),
                            if app.graph.hosts.len() == 1 { "" } else { "s" },
                            app.graph.edges.len(),
                            if app.graph.edges.len() == 1 { "" } else { "s" },
                            secs
                        );
                        if app.phase == Phase::Cancelled {
                            ui.label(
                                RichText::new(format!("cancelled — {label}"))
                                    .color(ui.visuals().warn_fg_color),
                            );
                        } else {
                            ui.label(RichText::new(label).weak());
                        }
                    }
                    Phase::Idle => {}
                },
            );
        });

        if let Some((done, total)) = app.progress {
            let frac = if total == 0 {
                0.0
            } else {
                done as f32 / total as f32
            };
            ui.add(egui::ProgressBar::new(frac).desired_height(3.0));
        }
        ui.add_space(3.0);
    });
}

pub fn host_list(app: &mut NetmapApp, ui: &mut egui::Ui) {
    egui::Panel::left("hosts")
        .resizable(true)
        .default_size(260.0)
        .show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Hosts ({})", app.graph.hosts.len())).strong());
            });
            ui.add(
                egui::TextEdit::singleline(&mut app.filter)
                    .desired_width(f32::INFINITY)
                    .hint_text("filter by ip, name, vendor, role"),
            );
            ui.separator();

            let visible = app.visible_hosts();
            if visible.is_empty() {
                ui.label(RichText::new("No matching hosts").weak());
                return;
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                for ip in visible {
                    let Some(host) = app.graph.hosts.get(&ip) else {
                        continue;
                    };
                    let selected = app.selected == Some(ip);

                    let label = match &host.hostname {
                        Some(n) => format!("{ip}  {n}"),
                        None => ip.to_string(),
                    };

                    ui.horizontal(|ui| {
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(9.0, 9.0), egui::Sense::hover());
                        ui.painter()
                            .circle_filled(rect.center(), 4.5, role_color(host.role));

                        if ui
                            .selectable_label(selected, RichText::new(label).monospace().size(11.5))
                            .clicked()
                        {
                            app.selected = Some(ip);
                        }
                    });
                }
            });
        });
}

pub fn details(app: &mut NetmapApp, ui: &mut egui::Ui) {
    egui::Panel::bottom("details")
        .resizable(true)
        .default_size(170.0)
        .show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Details").strong());
                if app.selected.is_some() && ui.small_button("clear").clicked() {
                    app.selected = None;
                }
            });
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                match app.selected.and_then(|ip| app.graph.hosts.get(&ip)) {
                    Some(host) => {
                        egui::Grid::new("host_details")
                            .num_columns(2)
                            .spacing([16.0, 4.0])
                            .show(ui, |ui| {
                                let mut row = |k: &str, v: String| {
                                    ui.label(RichText::new(k).weak());
                                    ui.label(RichText::new(v).monospace());
                                    ui.end_row();
                                };
                                row("IP", host.ip.to_string());
                                row("Role", host.role.to_string());
                                if let Some(n) = &host.hostname {
                                    row("Hostname", n.clone());
                                }
                                if let Some(m) = &host.mac {
                                    row("MAC", m.clone());
                                }
                                if let Some(v) = &host.vendor {
                                    row("Vendor", v.clone());
                                }
                                if let Some(o) = &host.os_guess {
                                    row("OS guess", o.clone());
                                }
                                if let Some(d) = host.hop_distance {
                                    row("Hops", d.to_string());
                                }
                                if !host.detected_by.is_empty() {
                                    row(
                                        "Detected by",
                                        host.detected_by
                                            .iter()
                                            .map(|b| b.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", "),
                                    );
                                }
                                if host.open_ports.is_empty() {
                                    row("Open ports", "(none found)".into());
                                } else {
                                    let ports = host
                                        .open_ports
                                        .iter()
                                        .map(|p| match &p.service {
                                            Some(s) if !s.is_empty() => {
                                                format!("{}/{}", p.number, s)
                                            }
                                            _ => p.number.to_string(),
                                        })
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    row("Open ports", ports);
                                }
                            });
                    }
                    None => {
                        ui.label(RichText::new("Select a host to see its details.").weak());
                        ui.add_space(6.0);
                        ui.label(RichText::new("Log").strong());
                        for line in app.log.iter().rev().take(60) {
                            ui.label(RichText::new(line).monospace().size(10.5).weak());
                        }
                    }
                }
            });
        });
}
