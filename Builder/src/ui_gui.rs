use std::time::Duration;

use egui::{Align, Color32, FontId, Layout, RichText, Rounding, ScrollArea, Stroke, Vec2};

use crate::{
    app::{App, InstallState, Phase},
    install::InstallStep,
    platform::CheckStatus,
    selftest::TestResult,
    wizard::{auto_find_installs, DbBackend, InstallMode, LogLevel, TargetOs},
};

// ── Colors ────────────────────────────────────────────────────────────────────

const ACCENT: Color32 = Color32::from_rgb(0, 190, 210);
const OK: Color32 = Color32::from_rgb(80, 210, 100);
const WARN: Color32 = Color32::from_rgb(220, 180, 50);
const ERR: Color32 = Color32::from_rgb(220, 80, 80);
const DIM: Color32 = Color32::from_rgb(140, 140, 140);
const SIDEBAR: Color32 = Color32::from_rgb(28, 32, 38);
const BG: Color32 = Color32::from_rgb(20, 23, 28);
const PANEL: Color32 = Color32::from_rgb(32, 36, 44);

// ── GuiApp ────────────────────────────────────────────────────────────────────

struct GuiApp {
    app: App,
}

impl GuiApp {
    fn new() -> Self {
        Self { app: App::new() }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.app.drain_progress();

        // Keep repainting during install/selftest so progress updates
        if matches!(self.app.phase, Phase::Installing | Phase::SelfTest) {
            ctx.request_repaint_after(Duration::from_millis(80));
        }

        // Close if quit requested
        if self.app.should_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        apply_style(ctx);

        // Custom frameless title bar — drag + macOS-style close button
        egui::TopBottomPanel::top("topbar")
            .exact_height(44.0)
            .frame(egui::Frame::none().fill(SIDEBAR))
            .show(ctx, |ui| {
                let rect = ui.max_rect();

                // Entire bar is draggable
                let drag = ui.interact(
                    rect,
                    ui.id().with("titlebar_drag"),
                    egui::Sense::click_and_drag(),
                );
                if drag.dragged() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }

                // Title painted centered (independent of button position)
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "KeyBase Builder",
                    FontId::proportional(16.0),
                    ACCENT,
                );

                // macOS-style red close dot — 22 px from left edge
                let close_c = egui::pos2(rect.left() + 22.0, rect.center().y);
                let close_r = egui::Rect::from_center_size(close_c, Vec2::splat(18.0));
                let close = ui.interact(close_r, ui.id().with("close_btn"), egui::Sense::click());

                let dot_clr = if close.hovered() {
                    Color32::from_rgb(200, 45, 35)
                } else {
                    Color32::from_rgb(255, 95, 87)
                };
                ui.painter().circle_filled(close_c, 7.0, dot_clr);
                if close.hovered() {
                    ui.painter().text(
                        close_c,
                        egui::Align2::CENTER_CENTER,
                        "×",
                        FontId::proportional(12.0),
                        Color32::from_rgb(100, 0, 0),
                    );
                }
                if close.clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

        // Bottom bar
        egui::TopBottomPanel::bottom("bottombar")
            .exact_height(54.0)
            .frame(
                egui::Frame::none()
                    .fill(SIDEBAR)
                    .inner_margin(egui::Margin::symmetric(16.0, 8.0)),
            )
            .show(ctx, |ui| {
                render_footer(ui, &mut self.app);
            });

        // Sidebar
        egui::SidePanel::left("sidebar")
            .exact_width(180.0)
            .frame(egui::Frame::none().fill(SIDEBAR))
            .show(ctx, |ui| {
                render_sidebar(ui, &self.app);
            });

        // Main content
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(20.0)),
            )
            .show(ctx, |ui| {
                render_body(ui, &mut self.app);
            });
    }
}

// ── Style ─────────────────────────────────────────────────────────────────────

fn apply_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(40, 46, 55);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(55, 62, 75);
    style.visuals.widgets.active.bg_fill = ACCENT;
    style.visuals.selection.bg_fill = ACCENT.linear_multiply(0.4);
    style.visuals.hyperlink_color = ACCENT;
    style.visuals.override_text_color = Some(Color32::from_rgb(220, 225, 235));
    ctx.set_style(style);
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

fn render_sidebar(ui: &mut egui::Ui, app: &App) {
    let phase_idx = phase_to_idx(app.phase);

    let steps = [
        (0, "Welcome"),
        (1, "System Check"),
        (2, "Configuration"),
        (3, "Confirm"),
        (4, "Installing"),
        (5, "Done"),
    ];

    ui.add_space(20.0);

    for (idx, name) in steps {
        let is_active = idx == phase_idx;
        let is_done = idx < phase_idx;

        let icon = if is_done {
            "✓"
        } else if is_active {
            "▶"
        } else {
            "○"
        };
        let (icon_color, text_color) = if is_done {
            (OK, DIM)
        } else if is_active {
            (ACCENT, Color32::WHITE)
        } else {
            (DIM, DIM)
        };

        let bg = if is_active {
            Color32::from_rgb(38, 44, 56)
        } else {
            Color32::TRANSPARENT
        };

        let resp = egui::Frame::none()
            .fill(bg)
            .inner_margin(egui::Margin {
                left: 12.0,
                right: 8.0,
                top: 6.0,
                bottom: 6.0,
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(icon).color(icon_color).size(14.0));
                    ui.add_space(6.0);
                    ui.label(RichText::new(name).color(text_color).size(13.0));
                });
            });
        let _ = resp;
    }

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(10.0);

    // Phase label
    let phase_label = match app.phase {
        Phase::Error => RichText::new("  Error").color(ERR).size(12.0),
        _ => RichText::new(format!("  Step {}/6", phase_idx + 1))
            .color(DIM)
            .size(12.0),
    };
    ui.label(phase_label);
}

fn phase_to_idx(phase: Phase) -> usize {
    match phase {
        Phase::Welcome => 0,
        Phase::SysCheck => 1,
        Phase::Wizard => 2,
        Phase::Confirm => 3,
        Phase::Installing | Phase::SelfTest => 4,
        Phase::Done | Phase::Error => 5,
    }
}

// ── Footer ────────────────────────────────────────────────────────────────────

fn render_footer(ui: &mut egui::Ui, app: &mut App) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        match app.phase {
            Phase::Welcome => {
                if primary_btn(ui, "Continue →") {
                    app.phase = Phase::SysCheck;
                    app.sysinfo = Some(crate::platform::SysInfo::detect());
                }
            }
            Phase::SysCheck => {
                let ok = app.sysinfo.as_ref().map(|s| s.python_ok).unwrap_or(false);
                ui.add_enabled_ui(ok, |ui| {
                    if primary_btn(ui, "Continue →") {
                        app.phase = Phase::Wizard;
                    }
                });
                ui.add_space(8.0);
                if secondary_btn(ui, "← Back") {
                    app.phase = Phase::Welcome;
                }
            }
            Phase::Wizard => {
                let ws = &app.wizard;
                let is_update = ws.install_mode == InstallMode::Update;
                let is_uninstall = ws.install_mode == InstallMode::Uninstall;
                let (ready, warn_msg) = if is_update {
                    let pwd_ok = !ws.sec_reset_pwd || ws.sec_new_pwd.len() >= 8;
                    let jwt_ok = !ws.sec_reset_jwt || ws.sec_new_jwt.len() >= 32;
                    let api_ok = !ws.sec_reset_api || ws.sec_new_api.len() >= 16;
                    let name_ok = !ws.sec_change_username || ws.sec_new_username.len() >= 3;
                    let prov_ok = !ws.prov_enabled || !ws.f_prov_token.buf.trim().is_empty();
                    let ok = pwd_ok && jwt_ok && api_ok && name_ok && prov_ok;
                    let warn = if !prov_ok {
                        "⚠ Provision token cannot be empty while provisioning is enabled"
                    } else {
                        "⚠ Fill enabled Security Operations"
                    };
                    (ok, warn)
                } else if is_uninstall {
                    (true, "")
                } else {
                    let ok = !ws.prov_enabled || !ws.f_prov_token.buf.trim().is_empty();
                    (
                        ok,
                        "⚠ Provision token cannot be empty while provisioning is enabled",
                    )
                };

                ui.add_enabled_ui(ready, |ui| {
                    if primary_btn(ui, "Review →") {
                        app.config = app.wizard.to_config();
                        app.phase = Phase::Confirm;
                    }
                });
                if !ready {
                    ui.add_space(6.0);
                    ui.label(RichText::new(warn_msg).color(ERR).size(11.0));
                }
                ui.add_space(8.0);
                if secondary_btn(ui, "← Back") {
                    app.phase = Phase::SysCheck;
                }
            }
            Phase::Confirm => {
                let is_uninstall = app.config.install_mode == InstallMode::Uninstall;
                if is_uninstall {
                    if primary_btn_colored(ui, "Uninstall", ERR) {
                        app.start_install();
                    }
                } else if primary_btn_colored(ui, "Install Now", OK) {
                    app.start_install();
                }
                ui.add_space(8.0);
                if secondary_btn(ui, "← Back") {
                    app.phase = Phase::Wizard;
                }
            }
            Phase::Installing | Phase::SelfTest => {
                ui.label(RichText::new("Please wait…").color(DIM).italics());
            }
            Phase::Done => {
                if primary_btn(ui, "Open Folder") {
                    app.open_output_folder_pub();
                }
                ui.add_space(8.0);
                if secondary_btn(ui, "Quit") {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            Phase::Error => {
                if primary_btn(ui, "← Back to Config") {
                    app.phase = Phase::Wizard;
                }
                ui.add_space(8.0);
                if secondary_btn(ui, "Quit") {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    });
}

fn primary_btn(ui: &mut egui::Ui, label: &str) -> bool {
    primary_btn_colored(ui, label, ACCENT)
}

fn primary_btn_colored(ui: &mut egui::Ui, label: &str, color: Color32) -> bool {
    let btn = egui::Button::new(RichText::new(label).color(Color32::BLACK).strong())
        .fill(color)
        .min_size(Vec2::new(120.0, 32.0));
    ui.add(btn).clicked()
}

fn secondary_btn(ui: &mut egui::Ui, label: &str) -> bool {
    let btn = egui::Button::new(RichText::new(label).color(DIM))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, DIM))
        .min_size(Vec2::new(90.0, 32.0));
    ui.add(btn).clicked()
}

// ── Body dispatch ─────────────────────────────────────────────────────────────

fn render_body(ui: &mut egui::Ui, app: &mut App) {
    match app.phase {
        Phase::Welcome => render_welcome(ui, app),
        Phase::SysCheck => render_syscheck(ui, app),
        Phase::Wizard => render_wizard(ui, app),
        Phase::Confirm => render_confirm(ui, app),
        Phase::Installing => render_installing(ui, &app.install),
        Phase::SelfTest => render_selftest(ui, app),
        Phase::Done => render_done(ui, app),
        Phase::Error => render_error(ui, app),
    }
}

// ── Welcome ───────────────────────────────────────────────────────────────────

fn render_welcome(ui: &mut egui::Ui, app: &App) {
    ui.vertical_centered(|ui| {
        ui.add_space(20.0);
        ui.label(RichText::new(
            "  ██╗  ██╗███████╗██╗   ██╗██████╗  █████╗ ███████╗███████╗\n  ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝\n  █████╔╝ █████╗   ╚████╔╝ ██████╔╝███████║███████╗█████╗  \n  ██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══██╗██╔══██║╚════██║██╔══╝  \n  ██║  ██╗███████╗   ██║   ██████╔╝██║  ██║███████║███████╗\n  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝",
        ).color(ACCENT).font(FontId::monospace(11.0)).strong());
        ui.add_space(24.0);

        let s = app.strings();
        ui.label(RichText::new(s.welcome_intro).size(15.0));
        ui.add_space(20.0);

        for step in s.welcome_steps {
            ui.horizontal(|ui| {
                ui.label(RichText::new("  ✓  ").color(OK).size(14.0));
                ui.label(RichText::new(*step).size(14.0));
            });
        }
        ui.add_space(24.0);
        ui.label(RichText::new("Press \"Continue\" to begin.").color(DIM).size(13.0));
    });
}

// ── System Check ──────────────────────────────────────────────────────────────

fn render_syscheck(ui: &mut egui::Ui, app: &App) {
    section_heading(ui, "System Requirements");
    ui.add_space(10.0);

    let Some(info) = &app.sysinfo else {
        ui.label(RichText::new("Detecting system…").color(DIM));
        return;
    };

    egui::Grid::new("syschecks")
        .num_columns(3)
        .spacing([16.0, 8.0])
        .show(ui, |ui| {
            for check in &info.checks() {
                let (icon, color) = match check.status {
                    CheckStatus::Ok => ("✓", OK),
                    CheckStatus::Warn => ("⚠", WARN),
                    CheckStatus::Fail => ("✗", ERR),
                };
                ui.label(RichText::new(icon).color(color).size(15.0));
                ui.label(RichText::new(&check.label).color(DIM));
                ui.label(
                    RichText::new(&check.value)
                        .color(match check.status {
                            CheckStatus::Ok => Color32::WHITE,
                            CheckStatus::Warn => WARN,
                            CheckStatus::Fail => ERR,
                        })
                        .strong(),
                );
                ui.end_row();
            }
        });

    ui.add_space(16.0);
    if info.required_ok() {
        ui.label(
            RichText::new("✓ All checks passed. Ready to proceed.")
                .color(OK)
                .size(14.0),
        );
    } else {
        ui.label(
            RichText::new("✗ Required dependencies are missing.")
                .color(ERR)
                .size(14.0),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("Install Python 3.10+ from https://python.org/downloads").color(DIM),
        );
    }
}

// ── Wizard / Configuration ────────────────────────────────────────────────────

fn render_wizard(ui: &mut egui::Ui, app: &mut App) {
    let ws = &mut app.wizard;
    let is_update = ws.install_mode == InstallMode::Update;
    let is_uninstall = ws.install_mode == InstallMode::Uninstall;
    let compact = is_update || is_uninstall;

    ScrollArea::vertical().show(ui, |ui| {
        ui.set_width(ui.available_width());

        // ── Installation ─────────────────────────────────────────────────────
        section_heading(ui, "Installation");

        // Install mode selector
        {
            if ws.dir_has_install.is_none() && !ws.f_output.buf.is_empty() {
                ws.dir_has_install = Some(has_existing_install(&ws.f_output.buf));
            }
            let detected = ws.dir_has_install;
            let fresh_label = if detected == Some(true) { "Fresh Reinstall" } else { "Fresh Install" };

            field_row(ui, "Mode", |ui| {
                if ui.selectable_label(ws.install_mode == InstallMode::Fresh, fresh_label).clicked() {
                    ws.install_mode = InstallMode::Fresh;
                }
                ui.add_space(6.0);
                let update_enabled = detected != Some(false);
                if ui.add_enabled(update_enabled, egui::SelectableLabel::new(
                    ws.install_mode == InstallMode::Update,
                    "Update",
                )).clicked() && update_enabled {
                    ws.install_mode = InstallMode::Update;
                    let found = auto_find_installs();
                    if let Some(p) = found.into_iter().next() {
                        ws.f_output.buf = p;
                        ws.dir_has_install = Some(true);
                    }
                }
                ui.add_space(6.0);
                if ui.add_enabled(update_enabled, egui::SelectableLabel::new(
                    ws.install_mode == InstallMode::Uninstall,
                    "Uninstall",
                )).clicked() && update_enabled {
                    ws.install_mode = InstallMode::Uninstall;
                    let found = auto_find_installs();
                    if let Some(p) = found.into_iter().next() {
                        ws.f_output.buf = p;
                        ws.dir_has_install = Some(true);
                    }
                }
                if !update_enabled {
                    ui.label(RichText::new("  (no install found)").color(DIM).size(11.0));
                }
            });
        }

        // Output dir
        ui.horizontal(|ui| {
            ui.set_height(28.0);
            ui.label(RichText::new("Directory").color(DIM).size(13.0));
            ui.add_space(8.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut ws.f_output.buf)
                    .desired_width(ui.available_width() - 180.0),
            );
            if resp.changed() {
                ws.dir_has_install = Some(has_existing_install(&ws.f_output.buf));
            }
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    ws.f_output.buf = path.to_string_lossy().into_owned();
                    ws.dir_has_install = Some(has_existing_install(&ws.f_output.buf));
                }
            }
            // Auto-find button only for Update/Uninstall
            if compact {
                ui.add_space(4.0);
                if ui.button("🔍 Auto-find").clicked() {
                    let found = auto_find_installs();
                    if let Some(p) = found.first() {
                        ws.f_output.buf = p.clone();
                        ws.dir_has_install = Some(true);
                    }
                }
            }
        });

        // ── Update mode: info banner + security ops ───────────────────────────
        if is_update {
            ui.add_space(8.0);
            egui::Frame::none()
                .fill(Color32::from_rgb(25, 40, 30))
                .inner_margin(egui::Margin::same(10.0))
                .rounding(Rounding::same(4.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🔒").size(18.0));
                        ui.add_space(6.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Config, .env, data and backups are preserved").color(OK).size(13.0).strong());
                            ui.label(RichText::new(
                                "Server files are replaced with the latest release. \
                                 Your config.yml and .env stay in place."
                            ).color(DIM).size(11.0));
                        });
                    });
                });

            section_heading(ui, "Security Operations");
            ui.label(RichText::new(
                "  Optionally reset or rotate credentials during this update."
            ).color(DIM).size(11.0));
            ui.add_space(6.0);

            sec_op_row(ui,
                "Reset Admin Password",
                "Generates a new admin password. Required on next login.",
                false,
                8,
                &mut ws.sec_reset_pwd,
                &mut ws.sec_new_pwd,
                &mut ws.sec_show_new_pwd,
            );
            sec_op_row(ui,
                "Rotate JWT Secret",
                "⚠  Invalidates ALL active sessions — every user will be logged out!",
                true,
                32,
                &mut ws.sec_reset_jwt,
                &mut ws.sec_new_jwt,
                &mut ws.sec_show_new_jwt,
            );
            sec_op_row(ui,
                "Rotate API Master Key",
                "⚠  Breaks all integrations using the current key until they update!",
                true,
                16,
                &mut ws.sec_reset_api,
                &mut ws.sec_new_api,
                &mut ws.sec_show_new_api,
            );

            ui.horizontal(|ui| {
                ui.set_height(26.0);
                ui.checkbox(&mut ws.sec_change_username,
                    RichText::new("Change Admin Username").size(13.0));
            });
            if ws.sec_change_username {
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    ui.label(RichText::new("New username:").color(DIM).size(13.0));
                    ui.add_space(8.0);
                    ui.add(egui::TextEdit::singleline(&mut ws.sec_new_username)
                        .desired_width(200.0)
                        .hint_text("e.g. admin"));
                    if ws.sec_new_username.len() < 3 && !ws.sec_new_username.is_empty() {
                        ui.label(RichText::new("min 3 chars").color(WARN).size(11.0));
                    }
                });
                ui.add_space(4.0);
            }
        }

        // ── Uninstall mode: warning banner ────────────────────────────────────
        if is_uninstall {
            ui.add_space(8.0);
            egui::Frame::none()
                .fill(Color32::from_rgb(50, 20, 20))
                .inner_margin(egui::Margin::same(10.0))
                .rounding(Rounding::same(4.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("⚠  Permanently removes the installation directory and all its contents.").color(ERR).size(13.0).strong());
                    ui.add_space(4.0);
                    ui.label(RichText::new("This includes the database, config, backups, and all server files.").color(DIM).size(11.0));
                    ui.label(RichText::new("Make a backup first if you need to preserve your data.").color(WARN).size(11.0));
                });
        }

        // ── All remaining sections only for Fresh install ─────────────────────
        if compact {
            return;
        }

        // ── Environment Files ─────────────────────────────────────────────────
        section_heading(ui, "Environment Files");
        ui.label(RichText::new(
            "  The builder creates full config.yml, .env and .env.example from the current server templates."
        ).color(DIM).size(11.0));
        ui.add_space(4.0);
        ui.label(RichText::new(
            "  Admin password hash and session secret are created on the first real admin setup."
        ).color(DIM).size(11.0));

        // ── Server ───────────────────────────────────────────────────────────
        section_heading(ui, "Server");
        field_row(ui, "Port", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_port.buf).desired_width(80.0));
        });
        field_row(ui, "Host (bind address)", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_host.buf).desired_width(160.0));
        });
        field_row(ui, "Workers", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_workers.buf).desired_width(60.0));
            ui.label(RichText::new("  parallel processes").color(DIM).size(12.0));
        });
        field_row(ui, "Log level", |ui| {
            let cur = LogLevel::all().get(ws.log_level_sel).map(|l| l.label()).unwrap_or("info");
            egui::ComboBox::from_id_salt("log_level").selected_text(cur).show_ui(ui, |ui| {
                for (i, level) in LogLevel::all().iter().enumerate() {
                    ui.selectable_value(&mut ws.log_level_sel, i, level.label());
                }
            });
        });

        // ── Database ─────────────────────────────────────────────────────────
        section_heading(ui, "Database");
        field_row(ui, "Backend", |ui| {
            let cur = DbBackend::all().get(ws.db_sel).map(|d| d.label()).unwrap_or("?");
            egui::ComboBox::from_id_salt("db_backend").selected_text(cur).show_ui(ui, |ui| {
                for (i, db) in DbBackend::all().iter().enumerate() {
                    ui.selectable_value(&mut ws.db_sel, i, db.label());
                }
            });
        });
        match ws.db_sel {
            0 => field_row(ui, "SQLite path", |ui| { ui.text_edit_singleline(&mut ws.f_sqlite.buf); }),
            1 => field_row(ui, "PostgreSQL URL", |ui| { ui.text_edit_singleline(&mut ws.f_pg_url.buf); }),
            _ => field_row(ui, "MySQL URL", |ui| { ui.text_edit_singleline(&mut ws.f_mysql_url.buf); }),
        }

        // ── Network ──────────────────────────────────────────────────────────
        section_heading(ui, "Network");
        toggle_row(ui, "Allow remote admin",  &mut ws.allow_remote_admin);
        toggle_row(ui, "Trust proxy headers", &mut ws.trust_proxy);
        toggle_row(ui, "Cloudflare mode",     &mut ws.cloudflare);
        field_row(ui, "API rate limit", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_rate.buf).desired_width(80.0));
            ui.label(RichText::new("  req/min").color(DIM).size(12.0));
        });

        // ── Provisioning ─────────────────────────────────────────────────────
        section_heading(ui, "Provisioning API");
        toggle_row(ui, "Enable provisioning API", &mut ws.prov_enabled);
        if ws.prov_enabled {
            secret_row(ui, "Provision token",
                "token for /provision endpoint",
                8,
                &mut ws.f_prov_token.buf,
                &mut ws.show_prov_token,
            );
        }

        // ── Target & Run Scripts ─────────────────────────────────────────────
        section_heading(ui, "Target OS & Run Scripts");
        let host_os = if cfg!(windows) { TargetOs::Windows } else { TargetOs::Linux };
        field_row(ui, "Target OS", |ui| {
            let cur = TargetOs::all().get(ws.target_os_sel).map(|t| t.label()).unwrap_or("?");
            egui::ComboBox::from_id_salt("target_os").selected_text(cur).show_ui(ui, |ui| {
                for (i, os) in TargetOs::all().iter().enumerate() {
                    ui.selectable_value(&mut ws.target_os_sel, i, os.label());
                }
            });
            let is_auto = TargetOs::all().get(ws.target_os_sel).copied() == Some(host_os);
            if is_auto {
                ui.label(RichText::new("✓ auto").color(OK).size(11.0));
            } else {
                let host_label = host_os.label();
                if ui.small_button("↺ Auto")
                    .on_hover_text(format!("Reset to host OS: {host_label}"))
                    .clicked()
                {
                    ws.target_os_sel = TargetOs::all()
                        .iter()
                        .position(|&t| t == host_os)
                        .unwrap_or(0);
                }
            }
        });
        let target_os = TargetOs::all().get(ws.target_os_sel).copied().unwrap_or_default();
        let scripts_hint = match target_os {
            TargetOs::Windows => "Generates: run.bat",
            TargetOs::Linux   => "Generates: run.sh",
            TargetOs::Both    => "Generates: run.bat + run.sh",
        };
        ui.add_space(2.0);
        ui.label(RichText::new(format!("  → {scripts_hint}")).color(DIM).size(12.0));

        // ── Backup ───────────────────────────────────────────────────────────
        section_heading(ui, "Backup");
        field_row(ui, "Interval (minutes)", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_backup_interval.buf).desired_width(70.0));
        });
        field_row(ui, "Keep last N backups", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_backup_keep.buf).desired_width(70.0));
        });

        // ── Session & Security ────────────────────────────────────────────────
        section_heading(ui, "Session");
        field_row(ui, "Session duration (hours)", |ui| {
            ui.add(egui::TextEdit::singleline(&mut ws.f_session_hours.buf).desired_width(70.0));
        });

        // ── Generated Files ───────────────────────────────────────────────────
        section_heading(ui, "Generated Files");
        toggle_row(ui, "Docker files (Dockerfile, compose)", &mut ws.gen_docker);
        toggle_row(ui, "NGINX reverse proxy config",        &mut ws.gen_nginx);
        if ws.gen_nginx {
            field_row(ui, "Domain / hostname", |ui| {
                ui.text_edit_singleline(&mut ws.f_domain.buf);
            });
        }
        toggle_row(ui, "systemd service unit", &mut ws.gen_systemd);
        toggle_row(ui, "Debug mode",           &mut ws.debug);
        toggle_row(ui, "Run self-test after install", &mut ws.selftest);
    });
}

// ── Secret field row with masking + Generate button ──────────────────────────

fn secret_row(
    ui: &mut egui::Ui,
    label: &str,
    hint: &str,
    min_len: usize,
    value: &mut String,
    show: &mut bool,
) {
    let ok = value.len() >= min_len;

    // Label row
    ui.horizontal(|ui| {
        ui.set_min_height(28.0);
        ui.label(RichText::new(label).color(DIM).size(13.0));
        ui.add_space(4.0);
        if ok {
            ui.label(
                RichText::new(format!("✓ {} chars", value.len()))
                    .color(OK)
                    .size(11.0),
            );
        } else if value.is_empty() {
            ui.label(RichText::new("required").color(ERR).size(11.0));
        } else {
            ui.label(
                RichText::new(format!("{}/{} chars", value.len(), min_len))
                    .color(WARN)
                    .size(11.0),
            );
        }
    });

    // Input row
    ui.horizontal(|ui| {
        ui.set_min_height(28.0);
        ui.add_space(12.0);

        // Masked text edit
        let te = egui::TextEdit::singleline(value)
            .password(!*show)
            .hint_text(hint)
            .desired_width(ui.available_width() - 160.0);
        ui.add(te);

        // Show / Hide
        let eye = if *show { "Hide" } else { "Show" };
        if ui.small_button(eye).clicked() {
            *show = !*show;
        }

        // Generate + auto-copy
        let gen_resp = ui.add(
            egui::Button::new(RichText::new("⟳ Generate").size(12.0))
                .fill(Color32::from_rgb(35, 50, 68))
                .min_size(Vec2::new(80.0, 22.0)),
        );
        if gen_resp.clicked() {
            let s = generate_secret(min_len.max(16));
            *value = s.clone();
            ui.output_mut(|o| o.copied_text = s);
        }
        gen_resp.on_hover_text("Generate random secret\nand copy to clipboard");
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn generate_secret(bytes: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    hex::encode((0..bytes).map(|_| rng.gen::<u8>()).collect::<Vec<_>>())
}

fn has_existing_install(path: &str) -> bool {
    let p = std::path::Path::new(path);
    p.join("config.yml").exists() || p.join(".venv").exists()
}

// ── Security operation row ────────────────────────────────────────────────────

fn sec_op_row(
    ui: &mut egui::Ui,
    label: &str,
    description: &str,
    is_critical: bool,
    min_len: usize,
    enabled: &mut bool,
    value: &mut String,
    show: &mut bool,
) {
    let desc_color = if is_critical { WARN } else { DIM };

    ui.horizontal(|ui| {
        ui.set_height(26.0);
        ui.checkbox(enabled, RichText::new(label).size(13.0).strong());
    });
    ui.horizontal(|ui| {
        ui.add_space(22.0);
        ui.label(RichText::new(description).color(desc_color).size(11.0));
    });

    if *enabled {
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.add_space(22.0);

            let te = egui::TextEdit::singleline(value)
                .password(!*show)
                .hint_text("generate or type…")
                .desired_width(ui.available_width() - 170.0);
            ui.add(te);

            let eye = if *show { "Hide" } else { "Show" };
            if ui.small_button(eye).clicked() {
                *show = !*show;
            }

            let gen_resp = ui.add(
                egui::Button::new(RichText::new("⟳ Generate").size(12.0))
                    .fill(Color32::from_rgb(35, 50, 68))
                    .min_size(Vec2::new(80.0, 22.0)),
            );
            if gen_resp.clicked() {
                let s = generate_secret(min_len.max(16));
                *value = s.clone();
                ui.output_mut(|o| o.copied_text = s);
            }
            gen_resp.on_hover_text("Generate & copy to clipboard");

            // Inline validation
            if !value.is_empty() {
                if value.len() >= min_len {
                    ui.label(RichText::new("✓").color(OK).size(14.0));
                } else {
                    ui.label(
                        RichText::new(format!("{}/{}", value.len(), min_len))
                            .color(WARN)
                            .size(11.0),
                    );
                }
            }
        });
        ui.add_space(2.0);
    }
    ui.add_space(6.0);
}

fn section_heading(ui: &mut egui::Ui, title: &str) {
    ui.add_space(14.0);
    ui.separator();
    ui.label(RichText::new(title).color(ACCENT).size(13.0).strong());
    ui.add_space(4.0);
}

fn field_row(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.set_height(28.0);
        ui.add(egui::Label::new(RichText::new(label).color(DIM).size(13.0)).wrap());
        ui.add_space(8.0);
        ui.with_layout(Layout::left_to_right(Align::Center), content);
    });
}

fn toggle_row(ui: &mut egui::Ui, label: &str, value: &mut bool) {
    ui.horizontal(|ui| {
        ui.set_height(26.0);
        ui.checkbox(value, RichText::new(label).size(13.0));
    });
}

// ── Confirm ───────────────────────────────────────────────────────────────────

fn render_confirm(ui: &mut egui::Ui, app: &App) {
    let is_uninstall = app.config.install_mode == InstallMode::Uninstall;

    if is_uninstall {
        section_heading(ui, "Confirm Uninstallation");
        ui.add_space(12.0);
        egui::Frame::none()
            .fill(Color32::from_rgb(50, 20, 20))
            .inner_margin(egui::Margin::same(14.0))
            .rounding(Rounding::same(6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("⚠  The following directory will be PERMANENTLY DELETED:").color(ERR).size(14.0).strong());
                ui.add_space(8.0);
                ui.label(RichText::new(&app.config.output_dir).color(Color32::WHITE).size(14.0).strong().font(FontId::monospace(13.0)));
                ui.add_space(8.0);
                ui.label(RichText::new("This includes the database, all keys, config, backups, and server files.").color(WARN).size(12.0));
                ui.label(RichText::new("This action cannot be undone.").color(ERR).size(12.0));
            });
        ui.add_space(12.0);
        ui.label(RichText::new("Click \"Uninstall\" to proceed, or ← Back to cancel.").color(DIM).size(13.0));
        return;
    }

    section_heading(ui, "Review Installation Settings");

    ScrollArea::vertical().show(ui, |ui| {
        let cfg = &app.config;
        let port = cfg.port_u16();

        egui::Grid::new("confirm_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                let row = |ui: &mut egui::Ui, k: &str, v: &str| {
                    ui.label(RichText::new(k).color(DIM).size(13.0));
                    ui.label(RichText::new(v).strong().size(13.0));
                    ui.end_row();
                };

                row(ui, "Output directory", &cfg.output_dir);
                row(ui, "Install mode", cfg.install_mode.label());
                row(ui, "Port", &cfg.port);
                row(ui, "Host", &cfg.host);
                row(ui, "Workers", &cfg.workers_u32().to_string());
                row(ui, "Log level", cfg.log_level.label());
                row(ui, "Database", cfg.db_backend.label());
                match cfg.db_backend {
                    DbBackend::Sqlite => row(ui, "  SQLite path", &cfg.sqlite_path),
                    DbBackend::Postgres => row(ui, "  PostgreSQL URL", &cfg.pg_url),
                    DbBackend::Mysql => row(ui, "  MySQL URL", &cfg.mysql_url),
                }
                row(
                    ui,
                    "Allow remote admin",
                    if cfg.allow_remote_admin { "Yes" } else { "No" },
                );
                row(
                    ui,
                    "Trust proxy",
                    if cfg.trust_proxy { "Yes" } else { "No" },
                );
                row(
                    ui,
                    "Cloudflare mode",
                    if cfg.cloudflare { "Yes" } else { "No" },
                );
                if !cfg.domain.is_empty() {
                    row(ui, "Domain", &cfg.domain);
                }
                row(ui, "API rate limit", &format!("{}/min", cfg.rate_limit));
                row(
                    ui,
                    "Provisioning API",
                    if cfg.prov_enabled {
                        "Enabled"
                    } else {
                        "Disabled"
                    },
                );
                row(ui, "Target OS", cfg.target_os.label());
                row(
                    ui,
                    "Backup interval",
                    &format!("{}m", cfg.backup_interval_u32()),
                );
                row(ui, "Backups to keep", &cfg.backup_keep_u32().to_string());
                row(ui, "Session hours", &cfg.session_hours_u32().to_string());
                row(
                    ui,
                    "Docker files",
                    if cfg.gen_docker { "Yes" } else { "No" },
                );
                row(ui, "NGINX config", if cfg.gen_nginx { "Yes" } else { "No" });
                row(
                    ui,
                    "systemd service",
                    if cfg.gen_systemd { "Yes" } else { "No" },
                );
                row(ui, "Self-test", if cfg.selftest { "Yes" } else { "No" });
                row(ui, "Debug mode", if cfg.debug { "Yes" } else { "No" });
            });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("Admin panel: http://{}:{}/admin", cfg.host, port)).color(ACCENT),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Click \"Install Now\" to begin installation.")
                .color(DIM)
                .size(13.0),
        );
    });
}

// ── Installing ────────────────────────────────────────────────────────────────

fn render_installing(ui: &mut egui::Ui, install: &InstallState) {
    let ratio = install.overall_progress() as f32;
    let pct = (ratio * 100.0) as u32;

    ui.label(
        RichText::new("Installing…")
            .color(ACCENT)
            .size(15.0)
            .strong(),
    );
    ui.add_space(12.0);

    // Overall progress bar
    ui.add(
        egui::ProgressBar::new(ratio)
            .text(format!("{}%", pct))
            .desired_width(f32::INFINITY)
            .animate(true),
    );
    ui.add_space(16.0);

    // Steps
    let steps: &[(InstallStep, &str)] = &[
        (InstallStep::Downloading, "Downloading Server-Portable.zip"),
        (InstallStep::Extracting, "Extracting files"),
        (InstallStep::Venv, "Creating Python environment"),
        (InstallStep::Pip, "Installing Python packages"),
        (InstallStep::Config, "Generating configuration"),
        (InstallStep::ExtraFiles, "Generating extra files"),
    ];

    for (step, label) in steps {
        let done = install.steps_done.contains(step);
        let active = install.step == Some(*step);

        let (icon, color) = if done {
            ("✓", OK)
        } else if active {
            ("▶", ACCENT)
        } else {
            ("○", DIM)
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new(icon).color(color).size(14.0));
            ui.label(
                RichText::new(*label)
                    .color(if active { Color32::WHITE } else { DIM })
                    .size(13.0),
            );

            // Show MB progress only for download
            if active && *step == InstallStep::Downloading && install.total > 0 {
                let done_mb = install.done as f32 / 1_048_576.0;
                let total_mb = install.total as f32 / 1_048_576.0;
                ui.label(
                    RichText::new(format!("  {:.1} / {:.1} MB", done_mb, total_mb))
                        .color(DIM)
                        .size(12.0),
                );
            }
        });
    }

    // Log tail
    ui.add_space(16.0);
    ui.separator();
    ui.add_space(6.0);

    let log_height = ui.available_height() - 8.0;
    let max_w = ui.available_width();
    ScrollArea::vertical()
        .id_salt("install_log")
        .stick_to_bottom(true)
        .max_height(log_height)
        .show(ui, |ui| {
            ui.set_max_width(max_w);
            for line in &install.log {
                ui.add(
                    egui::Label::new(RichText::new(line).color(DIM).font(FontId::monospace(11.0)))
                        .wrap(),
                );
            }
        });
}

// ── Self-Test ─────────────────────────────────────────────────────────────────

fn render_selftest(ui: &mut egui::Ui, app: &App) {
    ui.label(
        RichText::new("Running Self-Test…")
            .color(ACCENT)
            .size(15.0)
            .strong(),
    );
    ui.add_space(16.0);

    let max_w = ui.available_width();
    ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
        ui.set_max_width(max_w);
        for line in &app.test_log {
            ui.add(
                egui::Label::new(RichText::new(line).color(DIM).font(FontId::monospace(11.0)))
                    .wrap(),
            );
        }
    });
}

// ── Done ──────────────────────────────────────────────────────────────────────

fn render_done(ui: &mut egui::Ui, app: &App) {
    if app.config.install_mode == InstallMode::Uninstall {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("Uninstallation Complete").color(OK).size(20.0).strong());
            ui.add_space(16.0);
            ui.label(RichText::new(format!("✓  Removed: {}", app.config.output_dir)).color(OK).size(14.0));
            ui.add_space(8.0);
            ui.label(RichText::new("All server files, data, and config have been deleted.").color(DIM).size(13.0));
        });
        return;
    }

    let port = app.config.port_u16();
    let host = &app.config.host;

    ui.horizontal_top(|ui| {
        // Left column
        ui.vertical(|ui| {
            ui.set_width(ui.available_width() * 0.55);

            ui.label(
                RichText::new("Installation Complete")
                    .color(OK)
                    .size(18.0)
                    .strong(),
            );
            ui.add_space(12.0);

            success_row(ui, &format!("Installed to: {}", app.config.output_dir));
            success_row(ui, "Configuration generated");
            success_row(ui, "Python packages installed");

            if let Some(result) = &app.test_result {
                ui.add_space(4.0);
                match result {
                    TestResult::Pass => {
                        success_row(ui, "Self-test PASSED");
                    }
                    TestResult::Fail(e) => {
                        ui.label(RichText::new(format!("Self-test FAILED: {e}")).color(ERR));
                    }
                    TestResult::Skipped => {
                        ui.label(RichText::new("Self-test skipped").color(DIM));
                    }
                }
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);

            kv_row(ui, "Server URL", &format!("http://{}:{}", host, port));
            kv_row(
                ui,
                "Admin panel",
                &format!("http://{}:{}/admin", host, port),
            );

            if app.build_elapsed > 0.0 {
                kv_row(ui, "Build time", &format!("{:.1}s", app.build_elapsed));
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label(RichText::new("To start the server:").color(DIM).size(13.0));
            ui.add_space(4.0);

            if app.config.target_os.gen_bat() {
                ui.label(
                    RichText::new("  Windows:  run.bat")
                        .color(Color32::WHITE)
                        .font(FontId::monospace(12.0)),
                );
            }
            if app.config.target_os.gen_sh() {
                ui.label(
                    RichText::new("  Linux:    ./run.sh")
                        .color(Color32::WHITE)
                        .font(FontId::monospace(12.0)),
                );
            }

            ui.add_space(12.0);
            ui.label(
                RichText::new("On first run, create your admin account.")
                    .color(DIM)
                    .size(12.0),
            );
        });

        ui.separator();
        ui.add_space(16.0);

        // Right column — generated files
        ui.vertical(|ui| {
            ui.label(
                RichText::new("Generated files:")
                    .color(ACCENT)
                    .size(13.0)
                    .strong(),
            );
            ui.add_space(8.0);

            let base = [
                "config.yml",
                ".env",
                ".env.example",
                "README.md",
                "install.log",
            ];
            for f in &base {
                file_row(ui, f);
            }
            for f in &app.generated_files {
                if !base.contains(&f.as_str()) {
                    file_row(ui, f);
                }
            }
        });
    });
}

fn success_row(ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("  ✓  ").color(OK).size(14.0));
        ui.label(RichText::new(text).size(13.0));
    });
}

fn kv_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("  {:<14}", key))
                .color(DIM)
                .size(13.0),
        );
        ui.label(
            RichText::new(value)
                .color(Color32::WHITE)
                .strong()
                .size(13.0),
        );
    });
}

fn file_row(ui: &mut egui::Ui, name: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("  ✓  ").color(OK).size(13.0));
        ui.label(RichText::new(name).font(FontId::monospace(12.0)));
    });
}

// ── Error ─────────────────────────────────────────────────────────────────────

fn render_error(ui: &mut egui::Ui, app: &App) {
    ui.label(
        RichText::new("Installation Failed")
            .color(ERR)
            .size(18.0)
            .strong(),
    );
    ui.add_space(16.0);

    egui::Frame::none()
        .fill(Color32::from_rgb(50, 20, 20))
        .inner_margin(egui::Margin::same(12.0))
        .rounding(Rounding::same(6.0))
        .show(ui, |ui| {
            ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(&app.error_msg)
                            .color(Color32::from_rgb(255, 160, 160))
                            .font(FontId::monospace(12.0)),
                    )
                    .wrap(),
                );
            });
        });

    ui.add_space(16.0);
    if !app.install.log.is_empty() {
        ui.label(
            RichText::new("Recent log")
                .color(ACCENT)
                .size(13.0)
                .strong(),
        );
        ui.add_space(6.0);
        ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            for line in app
                .install
                .log
                .iter()
                .rev()
                .take(10)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                ui.add(
                    egui::Label::new(RichText::new(line).color(DIM).font(FontId::monospace(11.0)))
                        .wrap(),
                );
            }
        });
        ui.add_space(12.0);
    }
    ui.label(
        RichText::new("Check your settings and try again.")
            .color(DIM)
            .size(13.0),
    );
}

// ── Entry Point ───────────────────────────────────────────────────────────────

pub fn run() -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("KeyBase Builder")
            .with_inner_size([920.0, 660.0])
            .with_min_inner_size([920.0, 660.0])
            .with_max_inner_size([920.0, 660.0])
            .with_resizable(false)
            .with_decorations(false)
            .with_icon(egui::IconData::default()),
        ..Default::default()
    };
    eframe::run_native(
        "KeyBase Builder",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(GuiApp::new()))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}
