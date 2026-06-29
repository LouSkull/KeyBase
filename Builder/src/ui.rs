#![cfg_attr(windows, allow(dead_code, unused_imports))]

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Padding, Paragraph, Wrap},
    Frame,
};

use crate::{
    app::{App, Phase, TOTAL_STEPS},
    i18n::Strings,
    install::InstallStep,
    platform::CheckStatus,
    selftest::TestResult,
    wizard::{DbBackend, FieldId, InstallMode, LogLevel, TargetOs},
};

// ── Palette (dark / light) ────────────────────────────────────────────────────

#[allow(dead_code)]
struct Palette {
    accent: Color,
    ok: Color,
    warn: Color,
    err: Color,
    dim: Color,
    hi: Color,
    sel: Color,
    bg: Color,
}

const DARK: Palette = Palette {
    accent: Color::Cyan,
    ok: Color::Green,
    warn: Color::Yellow,
    err: Color::Red,
    dim: Color::DarkGray,
    hi: Color::White,
    sel: Color::Yellow,
    bg: Color::Reset,
};

const LIGHT: Palette = Palette {
    accent: Color::Blue,
    ok: Color::Green,
    warn: Color::Magenta,
    err: Color::Red,
    dim: Color::Gray,
    hi: Color::Black,
    sel: Color::Blue,
    bg: Color::Reset,
};

fn pal(app: &App) -> &'static Palette {
    if app.wizard.dark_theme {
        &DARK
    } else {
        &LIGHT
    }
}

// ── Widget helpers ─────────────────────────────────────────────────────────────

fn block_titled(title: &str, p: &Palette) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(p.accent))
        .title(Span::styled(
            format!(" {} ", title),
            Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::horizontal(1))
}

fn outer_block(s: &Strings, p: &Palette) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(p.accent))
        .title(Span::styled(
            format!(" {} ", s.title),
            Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        ))
}

// ── Main render ───────────────────────────────────────────────────────────────

pub fn render(f: &mut Frame, app: &App) {
    let p = pal(app);
    let s = app.strings();
    let area = f.area();

    let outer = outer_block(&s, p);
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .split(inner);

    render_header(f, app, &s, p, chunks[0]);
    render_body(f, app, &s, p, chunks[1]);
    render_footer(f, app, &s, p, chunks[2]);
}

// ── Header ────────────────────────────────────────────────────────────────────

fn render_header(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let phases = [
        "Welcome",
        "System Check",
        "Configuration",
        "Confirm",
        "Installing",
        "Self-Test",
        "Complete",
        "Error",
    ];
    let label = match app.phase {
        Phase::Welcome => phases[0],
        Phase::SysCheck => phases[1],
        Phase::Wizard => phases[2],
        Phase::Confirm => phases[3],
        Phase::Installing => phases[4],
        Phase::SelfTest => phases[5],
        Phase::Done => phases[6],
        Phase::Error => phases[7],
    };

    let widget = Paragraph::new(Line::from(vec![
        Span::styled(s.subtitle, Style::default().fg(p.dim)),
        Span::raw("   "),
        Span::styled(
            format!("[ {} ]", label),
            Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        ),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(widget, area);
}

// ── Footer ────────────────────────────────────────────────────────────────────

fn render_footer(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let ok = Style::default().fg(p.ok);
    let dim = Style::default().fg(p.dim);
    let warn = Style::default().fg(p.warn);

    let compact_mode = matches!(
        app.wizard.install_mode,
        InstallMode::Update | InstallMode::Uninstall
    );
    let active_secret = if app.phase == Phase::Wizard && !compact_mode {
        app.wizard
            .effective_fields()
            .get(app.wizard.field)
            .copied()
            .map(|fid| fid.is_secret())
            .unwrap_or(false)
    } else {
        false
    };

    let hints: Vec<Span> = match app.phase {
        Phase::Welcome => vec![
            Span::styled(s.press_enter, ok),
            Span::raw("   "),
            Span::styled(s.press_q, dim),
        ],
        Phase::SysCheck => vec![
            Span::styled(s.press_enter, ok),
            Span::raw("   "),
            Span::styled(s.press_back, dim),
        ],
        Phase::Wizard => {
            let mut hints = vec![
                Span::styled("[↑↓/Tab] Navigate", dim),
                Span::raw("   "),
                Span::styled("[←→] Change mode/edit", dim),
                Span::raw("   "),
                Span::styled("[PgDn] Next →", ok),
                Span::raw("   "),
                Span::styled("[Esc] Back", dim),
            ];
            if compact_mode {
                hints.push(Span::raw("   "));
                hints.push(Span::styled("[F8] Auto-find", ok));
            }
            if active_secret {
                hints.push(Span::raw("   "));
                hints.push(Span::styled("[F6] Generate", ok));
                hints.push(Span::raw("   "));
                hints.push(Span::styled("[F7] Show/Hide", dim));
            }
            hints
        }
        Phase::Confirm => {
            let action = if app.config.install_mode == InstallMode::Uninstall {
                Span::styled("[Y/Enter] UNINSTALL", warn)
            } else {
                Span::styled("[Y/Enter] Install", ok)
            };
            vec![
                action,
                Span::raw("   "),
                Span::styled("[N/Esc] Back", dim),
            ]
        }
        Phase::Done => {
            if app.config.install_mode == InstallMode::Uninstall {
                vec![Span::styled("[q] Quit", dim)]
            } else {
                vec![
                    Span::styled("[o] Open folder", ok),
                    Span::raw("   "),
                    Span::styled("[q] Quit", dim),
                ]
            }
        }
        Phase::Error => vec![
            Span::styled("[Enter] Back to config", Style::default().fg(p.warn)),
            Span::raw("   "),
            Span::styled("[q] Quit", dim),
        ],
        Phase::Installing | Phase::SelfTest => vec![Span::styled("Please wait…", dim)],
    };
    f.render_widget(
        Paragraph::new(Line::from(hints)).alignment(Alignment::Center),
        area,
    );
}

// ── Body dispatch ─────────────────────────────────────────────────────────────

fn render_body(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    match app.phase {
        Phase::Welcome => render_welcome(f, app, s, p, area),
        Phase::SysCheck => render_syscheck(f, app, s, p, area),
        Phase::Wizard => render_wizard(f, app, s, p, area),
        Phase::Confirm => render_confirm(f, app, s, p, area),
        Phase::Installing => render_installing(f, app, s, p, area),
        Phase::SelfTest => render_selftest(f, app, s, p, area),
        Phase::Done => render_done(f, app, s, p, area),
        Phase::Error => render_error(f, app, s, p, area),
    }
}

// ── Welcome ───────────────────────────────────────────────────────────────────

fn render_welcome(f: &mut Frame, _app: &App, s: &Strings, p: &Palette, area: Rect) {
    const LOGO: &str = concat!(
        "  ██╗  ██╗███████╗██╗   ██╗██████╗  █████╗ ███████╗███████╗\n",
        "  ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝\n",
        "  █████╔╝ █████╗   ╚████╔╝ ██████╔╝███████║███████╗█████╗  \n",
        "  ██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══██╗██╔══██║╚════██║██╔══╝  \n",
        "  ██║  ██╗███████╗   ██║   ██████╔╝██║  ██║███████║███████╗\n",
        "  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝"
    );

    let accent = Style::default().fg(p.accent).add_modifier(Modifier::BOLD);
    let base = Style::default().fg(p.hi);
    let ok = Style::default().fg(p.ok);

    let mut lines = vec![Line::raw("")];
    for l in LOGO.lines() {
        lines.push(Line::from(Span::styled(l, accent)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(s.welcome_intro, base)));
    lines.push(Line::raw(""));
    for step in s.welcome_steps {
        lines.push(Line::from(vec![
            Span::styled("  ✓ ", ok),
            Span::styled(*step, base),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(s.press_enter, ok)));

    f.render_widget(
        Paragraph::new(Text::from(lines))
            .alignment(Alignment::Center)
            .block(block_titled(s.title, p)),
        area,
    );
}

// ── System Check ──────────────────────────────────────────────────────────────

fn render_syscheck(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.syscheck_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(info) = &app.sysinfo else {
        f.render_widget(
            Paragraph::new("Detecting system…").style(Style::default().fg(p.dim)),
            inner,
        );
        return;
    };

    let checks = info.checks();
    let lw = checks.iter().map(|c| c.label.len()).max().unwrap_or(20) + 2;

    let mut items: Vec<ListItem> = checks
        .iter()
        .map(|c| {
            let (icon, sty) = match c.status {
                CheckStatus::Ok => ("  ✓  ", Style::default().fg(p.ok)),
                CheckStatus::Warn => ("  ⚠  ", Style::default().fg(p.warn)),
                CheckStatus::Fail => ("  ✗  ", Style::default().fg(p.err)),
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, sty),
                Span::styled(
                    format!("{:<w$}  ", c.label, w = lw),
                    Style::default().fg(p.dim),
                ),
                Span::styled(c.value.clone(), sty),
            ]))
        })
        .collect();

    items.push(ListItem::new(Line::raw("")));
    let status = if info.required_ok() {
        Line::from(Span::styled(s.syscheck_ok, Style::default().fg(p.ok)))
    } else {
        Line::from(Span::styled(s.syscheck_fail, Style::default().fg(p.err)))
    };
    items.push(ListItem::new(status));

    if !info.required_ok() {
        items.push(ListItem::new(Line::raw("")));
        items.push(ListItem::new(Line::from(vec![
            Span::styled("  Install Python 3.10+ from ", Style::default().fg(p.dim)),
            Span::styled(
                "https://python.org/downloads",
                Style::default().fg(p.accent),
            ),
        ])));
    }

    f.render_widget(List::new(items), inner);
}

// ── Wizard ────────────────────────────────────────────────────────────────────

/// Height (rows) per field row in the wizard.
const ROW_H: u16 = 1;

fn render_wizard(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.wizard_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let ws = &app.wizard;
    let is_compact = matches!(ws.install_mode, InstallMode::Update | InstallMode::Uninstall);

    // In compact mode split: top for fields, bottom for info panel
    let (field_area, info_area) = if is_compact && inner.height > 8 {
        let info_h: u16 = if ws.install_mode == InstallMode::Uninstall { 8 } else { 4 };
        let fields_h = inner.height.saturating_sub(info_h + 1);
        let chunks = Layout::vertical([
            Constraint::Length(fields_h),
            Constraint::Length(info_h),
        ])
        .split(inner);
        (chunks[0], Some(chunks[1]))
    } else {
        (inner, None)
    };

    let fields = ws.effective_fields();
    let total_fields = fields.len();
    let visible_rows = (field_area.height / ROW_H) as usize;

    let mut scroll = ws.scroll;
    {
        let active = ws.field;
        if active >= scroll + visible_rows {
            scroll = active + 1 - visible_rows;
        }
        if active < scroll {
            scroll = active;
        }
        scroll = scroll.min(total_fields.saturating_sub(visible_rows));
    }

    let visible = &fields[scroll..(scroll + visible_rows.min(total_fields - scroll))];
    let active_in_view = ws.field.saturating_sub(scroll);

    if total_fields > visible_rows {
        let scroll_info = format!(" {}/{} ", ws.field + 1, total_fields);
        let info_p = Paragraph::new(Span::styled(scroll_info, Style::default().fg(p.dim)))
            .alignment(Alignment::Right);
        let sr = Rect {
            x: field_area.x,
            y: field_area.y,
            width: field_area.width,
            height: 1,
        };
        f.render_widget(info_p, sr);
    }

    for (i, &fid) in visible.iter().enumerate() {
        let row = Rect {
            x: field_area.x,
            y: field_area.y + i as u16 * ROW_H,
            width: field_area.width,
            height: ROW_H,
        };
        if row.y >= field_area.y + field_area.height {
            break;
        }
        let is_active = i == active_in_view;
        render_wizard_field(f, app, s, p, fid, is_active, row);
    }

    // Cursor for active text field
    if let Some(&fid) = visible.get(active_in_view) {
        if fid.is_text() {
            let ti = ws.ti(fid);
            let label_w: u16 = 26;
            let row_y = field_area.y + active_in_view as u16 * ROW_H;
            let cur_x = field_area.x + 2 + label_w + ti.cursor as u16;
            if row_y < field_area.y + field_area.height && cur_x < field_area.x + field_area.width {
                f.set_cursor_position((cur_x, row_y));
            }
        }
    }

    // Info panel for Update / Uninstall
    if let Some(info_area) = info_area {
        render_wizard_info_panel(f, app, p, info_area);
    }
}

fn render_wizard_info_panel(f: &mut Frame, app: &App, p: &Palette, area: Rect) {
    let mode = app.wizard.install_mode;
    let ws = &app.wizard;

    let autofind_hint = match ws.autofind_count {
        None => Span::styled(" [F8] Auto-find install", Style::default().fg(p.accent)),
        Some(0) => Span::styled(" [F8] Not found — enter path manually", Style::default().fg(p.warn)),
        Some(n) => Span::styled(
            format!(" [F8] Found {} install(s) — re-scan", n),
            Style::default().fg(p.ok),
        ),
    };

    let lines: Vec<Line> = if mode == InstallMode::Uninstall {
        vec![
            Line::from(Span::styled(
                " ⚠  UNINSTALL — permanently removes all data:",
                Style::default().fg(p.err).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled("   • Database, all keys and licenses", Style::default().fg(p.dim))),
            Line::from(Span::styled("   • Config, .env, backups, Python environment", Style::default().fg(p.dim))),
            Line::raw(""),
            Line::from(autofind_hint),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                " UPDATE: code replaced, config/data/backups preserved",
                Style::default().fg(p.ok).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                " [F6] Generate secret  [F7] Show/Hide  [PgDn] Confirm",
                Style::default().fg(p.dim),
            )),
            Line::from(autofind_hint),
        ]
    };

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(p.dim));
    let block_inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        block_inner,
    );
}

fn render_wizard_field(
    f: &mut Frame,
    app: &App,
    s: &Strings,
    p: &Palette,
    fid: FieldId,
    active: bool,
    area: Rect,
) {
    let ws = &app.wizard;

    let label: &str = match fid {
        FieldId::Output => s.fld_output,
        FieldId::InstallMode => s.fld_mode,
        FieldId::Port => s.fld_port,
        FieldId::Host => s.fld_host,
        FieldId::Database => s.fld_db,
        FieldId::SqlitePath => s.fld_sqlite,
        FieldId::PgUrl => "PostgreSQL URL",
        FieldId::MysqlUrl => "MySQL URL",
        FieldId::AllowRemoteAdmin => "Allow remote admin",
        FieldId::TrustProxy => "Trust proxy headers",
        FieldId::Cloudflare => "Cloudflare mode",
        FieldId::Domain => "Domain / hostname",
        FieldId::RateLimit => "API rate limit (req/min)",
        FieldId::Provisioning => s.fld_prov,
        FieldId::ProvToken => s.fld_prov_token,
        FieldId::TargetOs => "Target OS",
        FieldId::Workers => "Server workers",
        FieldId::LogLevel => "Log level",
        FieldId::BackupInterval => "Backup interval (min)",
        FieldId::BackupKeep => "Backups to keep",
        FieldId::SessionHours => "Session duration (h)",
        FieldId::JwtSecret => "JWT Secret (min 32)",
        FieldId::AdminPassword => "Admin Password (min 8)",
        FieldId::ApiMasterKey => "API Master Key (min 16)",
        FieldId::Debug => "Debug mode",
        FieldId::GenDocker => "Generate Docker files",
        FieldId::GenNginx => "Generate NGINX config",
        FieldId::GenSystemd => "Generate systemd service",
        FieldId::SelfTest => "Run self-test after install",
        FieldId::Theme => "Theme",
        FieldId::SecResetPwd => "Reset Admin Password",
        FieldId::SecNewPwd => "  New password (min 8 chars)",
        FieldId::SecResetJwt => "Rotate Session Secret",
        FieldId::SecNewJwt => "  New secret (min 32 chars)",
        FieldId::SecResetApi => "Rotate API Master Key",
        FieldId::SecNewApi => "  New API key (min 16 chars)",
        FieldId::SecChangeUsername => "Change Admin Username",
        FieldId::SecNewUsername => "  New username (min 3 chars)",
    };

    let value: String = match fid {
        FieldId::Output => ws.f_output.buf.clone(),
        FieldId::InstallMode => ws.install_mode.label().into(),
        FieldId::Port => ws.f_port.buf.clone(),
        FieldId::Host => ws.f_host.buf.clone(),
        FieldId::Database => DbBackend::all()
            .get(ws.db_sel)
            .map(|d| d.label())
            .unwrap_or("?")
            .into(),
        FieldId::SqlitePath => ws.f_sqlite.buf.clone(),
        FieldId::PgUrl => ws.f_pg_url.buf.clone(),
        FieldId::MysqlUrl => ws.f_mysql_url.buf.clone(),
        FieldId::AllowRemoteAdmin => bool_label(ws.allow_remote_admin),
        FieldId::TrustProxy => bool_label(ws.trust_proxy),
        FieldId::Cloudflare => bool_label(ws.cloudflare),
        FieldId::Domain => ws.f_domain.buf.clone(),
        FieldId::RateLimit => ws.f_rate.buf.clone(),
        FieldId::Provisioning => bool_label(ws.prov_enabled),
        FieldId::ProvToken => secret_value(&ws.f_prov_token.buf, ws.show_prov_token),
        FieldId::TargetOs => TargetOs::all()
            .get(ws.target_os_sel)
            .map(|t| t.label())
            .unwrap_or("?")
            .into(),
        FieldId::Workers => ws.f_workers.buf.clone(),
        FieldId::LogLevel => LogLevel::all()
            .get(ws.log_level_sel)
            .map(|l| l.label())
            .unwrap_or("info")
            .into(),
        FieldId::BackupInterval => ws.f_backup_interval.buf.clone(),
        FieldId::BackupKeep => ws.f_backup_keep.buf.clone(),
        FieldId::SessionHours => ws.f_session_hours.buf.clone(),
        FieldId::JwtSecret => secret_value(&ws.f_jwt_secret.buf, ws.show_jwt),
        FieldId::AdminPassword => secret_value(&ws.f_admin_password.buf, ws.show_admin_pass),
        FieldId::ApiMasterKey => secret_value(&ws.f_api_master_key.buf, ws.show_api_key),
        FieldId::Debug => bool_label(ws.debug),
        FieldId::GenDocker => bool_label(ws.gen_docker),
        FieldId::GenNginx => bool_label(ws.gen_nginx),
        FieldId::GenSystemd => bool_label(ws.gen_systemd),
        FieldId::SelfTest => bool_label(ws.selftest),
        FieldId::Theme => {
            if ws.dark_theme {
                "Dark".into()
            } else {
                "Light".into()
            }
        }
        FieldId::SecResetPwd => bool_label(ws.sec_reset_pwd),
        FieldId::SecNewPwd => secret_value(&ws.f_sec_pwd.buf, ws.sec_show_new_pwd),
        FieldId::SecResetJwt => bool_label(ws.sec_reset_jwt),
        FieldId::SecNewJwt => secret_value(&ws.f_sec_jwt.buf, ws.sec_show_new_jwt),
        FieldId::SecResetApi => bool_label(ws.sec_reset_api),
        FieldId::SecNewApi => secret_value(&ws.f_sec_api.buf, ws.sec_show_new_api),
        FieldId::SecChangeUsername => bool_label(ws.sec_change_username),
        FieldId::SecNewUsername => ws.f_sec_username.buf.clone(),
    };

    // For sec op warn fields, show value in warn color when enabled
    let is_warn_field = matches!(
        fid,
        FieldId::SecResetJwt | FieldId::SecResetApi | FieldId::SecResetPwd | FieldId::SecChangeUsername
    );
    let value_enabled = matches!(
        fid,
        FieldId::SecResetJwt | FieldId::SecResetApi
    ) && value == "Yes";

    let label_sty = if active {
        Style::default().fg(p.sel).add_modifier(Modifier::BOLD)
    } else if is_warn_field {
        Style::default().fg(p.warn)
    } else {
        Style::default().fg(p.dim)
    };
    let value_sty = if value_enabled {
        Style::default().fg(p.warn).add_modifier(Modifier::BOLD)
    } else if active {
        Style::default().fg(p.hi).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(p.hi)
    };

    let prefix = if active { "▸ " } else { "  " };
    const LW: usize = 26;

    let cols = Layout::horizontal([
        Constraint::Length(2),
        Constraint::Length(LW as u16),
        Constraint::Min(0),
    ])
    .split(area);

    f.render_widget(Paragraph::new(prefix).style(label_sty), cols[0]);
    f.render_widget(
        Paragraph::new(format!("{:<LW$}", label)).style(label_sty),
        cols[1],
    );

    if fid.is_text() {
        f.render_widget(Paragraph::new(value).style(value_sty), cols[2]);
    } else {
        f.render_widget(
            Paragraph::new(format!("◀ {} ▶", value)).style(if active {
                Style::default().fg(p.sel)
            } else {
                Style::default().fg(p.hi)
            }),
            cols[2],
        );
    }
}

fn bool_label(b: bool) -> String {
    if b {
        "Yes".into()
    } else {
        "No".into()
    }
}

fn secret_value(value: &str, show: bool) -> String {
    if value.is_empty() {
        "<empty>".into()
    } else if show {
        value.to_string()
    } else {
        "*".repeat(value.chars().count())
    }
}

fn secret_status(value: &str, min_len: usize) -> String {
    if value.len() >= min_len {
        format!("set ({} chars)", value.len())
    } else if value.is_empty() {
        "missing".into()
    } else {
        format!("too short ({}/{})", value.len(), min_len)
    }
}

// ── Confirm ───────────────────────────────────────────────────────────────────

fn render_confirm(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.confirm_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let cfg = &app.config;
    let dim = Style::default().fg(p.dim);
    let hi = Style::default().fg(p.hi).add_modifier(Modifier::BOLD);

    // Uninstall: simplified confirm screen
    if cfg.install_mode == InstallMode::Uninstall {
        let lines = vec![
            Line::raw(""),
            Line::from(Span::styled(
                "  ⚠  CONFIRM UNINSTALLATION",
                Style::default().fg(p.err).add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Directory: ", dim),
                Span::styled(cfg.output_dir.clone(), hi),
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                "  ALL FILES WILL BE PERMANENTLY DELETED:",
                Style::default().fg(p.warn),
            )),
            Line::from(Span::styled("    • Database (all keys and licenses)", dim)),
            Line::from(Span::styled("    • Config, .env, backups", dim)),
            Line::from(Span::styled("    • Server files and Python environment", dim)),
            Line::raw(""),
            Line::from(Span::styled(
                "  [Y/Enter] Uninstall   [N/Esc] Cancel",
                Style::default().fg(p.warn).add_modifier(Modifier::BOLD),
            )),
        ];
        f.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }

    // Update: compact confirm showing what will happen
    if cfg.install_mode == InstallMode::Update {
        let kv = |k: &str, v: &str| -> Line {
            Line::from(vec![
                Span::styled(format!("  {:<28}", k), dim),
                Span::styled(v.to_string(), hi),
            ])
        };
        let mut lines = vec![
            Line::raw(""),
            Line::from(Span::styled("  CONFIRM UPDATE", hi)),
            Line::raw(""),
            kv("Directory", &cfg.output_dir),
            Line::raw(""),
            Line::from(Span::styled("  Will be replaced:", dim)),
            Line::from(Span::styled("    • Server code files", dim)),
            Line::from(Span::styled("    • Python packages (venv re-created)", dim)),
            Line::raw(""),
            Line::from(Span::styled("  Will be preserved:", Style::default().fg(p.ok))),
            Line::from(Span::styled("    • config.yml, .env, data/, backups/", Style::default().fg(p.ok))),
        ];
        let any_sec = cfg.sec_reset_pwd || cfg.sec_reset_jwt || cfg.sec_reset_api || cfg.sec_change_username;
        if any_sec {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled("  Security operations:", Style::default().fg(p.warn))));
            if cfg.sec_change_username { lines.push(Line::from(Span::styled(format!("    • Username → {}", cfg.sec_new_username), dim))); }
            if cfg.sec_reset_pwd      { lines.push(Line::from(Span::styled("    • Admin password will be reset", dim))); }
            if cfg.sec_reset_jwt      { lines.push(Line::from(Span::styled("    • Session secret rotated  ⚠ all users logged out", Style::default().fg(p.warn)))); }
            if cfg.sec_reset_api      { lines.push(Line::from(Span::styled("    • API master key rotated  ⚠ update all integrations", Style::default().fg(p.warn)))); }
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "  [Y/Enter] Update   [N/Esc] Cancel",
            Style::default().fg(p.ok).add_modifier(Modifier::BOLD),
        )));
        f.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }

    let kv = |k: &str, v: &str| -> Line {
        Line::from(vec![
            Span::styled(format!("  {:<26}", k), dim),
            Span::styled(v.to_string(), hi),
        ])
    };

    let mut lines = vec![
        Line::raw(""),
        Line::from(Span::styled(s.confirm_build, hi)),
        Line::raw(""),
    ];

    lines.push(kv("Output directory", &cfg.output_dir));
    lines.push(kv("Install mode", cfg.install_mode.label()));
    lines.push(kv("Port", &cfg.port));
    lines.push(kv("Host", &cfg.host));
    lines.push(kv("Database", cfg.db_backend.label()));
    match cfg.db_backend {
        crate::wizard::DbBackend::Sqlite => lines.push(kv("  SQLite path", &cfg.sqlite_path)),
        crate::wizard::DbBackend::Postgres => lines.push(kv("  PostgreSQL URL", &cfg.pg_url)),
        crate::wizard::DbBackend::Mysql => lines.push(kv("  MySQL URL", &cfg.mysql_url)),
    }
    lines.push(kv(
        "Allow remote admin",
        if cfg.allow_remote_admin { "Yes" } else { "No" },
    ));
    lines.push(kv(
        "Trust proxy headers",
        if cfg.trust_proxy { "Yes" } else { "No" },
    ));
    lines.push(kv(
        "Cloudflare mode",
        if cfg.cloudflare { "Yes" } else { "No" },
    ));
    if !cfg.domain.is_empty() {
        lines.push(kv("Domain", &cfg.domain));
    }
    lines.push(kv("API rate limit", &format!("{}/min", cfg.rate_limit)));
    lines.push(kv(
        "Provisioning API",
        if cfg.prov_enabled {
            "Enabled"
        } else {
            "Disabled"
        },
    ));
    if cfg.prov_enabled {
        lines.push(kv("  Provision token", &secret_status(&cfg.prov_token, 8)));
    }
    lines.push(kv(".env", "created from server example template"));
    lines.push(kv(
        "Generate Docker files",
        if cfg.gen_docker { "Yes" } else { "No" },
    ));
    lines.push(kv(
        "Generate NGINX config",
        if cfg.gen_nginx { "Yes" } else { "No" },
    ));
    lines.push(kv(
        "Generate systemd unit",
        if cfg.gen_systemd { "Yes" } else { "No" },
    ));
    lines.push(kv(
        "Self-test after install",
        if cfg.selftest { "Yes" } else { "No" },
    ));
    lines.push(kv("Debug mode", if cfg.debug { "Yes" } else { "No" }));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "  Source: latest GitHub release",
        dim,
    )));

    f.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        inner,
    );
}

// ── Installing ────────────────────────────────────────────────────────────────

fn render_installing(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.install_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // ── Uninstall progress ───────────────────────────────────────────────────
    if app.config.install_mode == InstallMode::Uninstall {
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

        let fully_done = app.install.steps_done.contains(&InstallStep::Extracting);
        let ratio = if fully_done {
            1.0
        } else if app.install.step == Some(InstallStep::Extracting) {
            if app.install.total > 0 {
                app.install.done as f64 / app.install.total as f64 * 0.5 + 0.5
            } else {
                0.5
            }
        } else {
            0.0
        };

        f.render_widget(
            Gauge::default()
                .gauge_style(Style::default().fg(p.err))
                .ratio(ratio)
                .label(format!("{:.0}%", ratio * 100.0)),
            chunks[0],
        );

        // Two pseudo-steps: Stop server / Remove files
        let stop_done = fully_done || app.install.done >= 1;
        let remove_done = fully_done;
        let removing_active = app.install.step == Some(InstallStep::Extracting) && app.install.done >= 1;
        let stopping_active = app.install.step == Some(InstallStep::Extracting) && app.install.done == 0;

        let step_items = vec![
            list_step_item(stop_done, stopping_active, "  Stopping server", p),
            list_step_item(remove_done, removing_active, "  Removing installation directory", p),
        ];
        f.render_widget(List::new(step_items), chunks[1]);

        render_log_tail(f, app, p, chunks[2]);
        return;
    }

    // ── Normal install progress ───────────────────────────────────────────────
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(TOTAL_STEPS as u16 + 1),
        Constraint::Min(0),
    ])
    .split(inner);

    let ratio = app.install.overall_progress();
    f.render_widget(
        Gauge::default()
            .gauge_style(Style::default().fg(p.accent))
            .ratio(ratio)
            .label(format!("{:.0}%", ratio * 100.0)),
        chunks[0],
    );

    let steps: &[(InstallStep, &str)] = &[
        (InstallStep::Downloading, s.install_downloading),
        (InstallStep::Extracting, s.install_extracting),
        (InstallStep::Venv, s.install_venv),
        (InstallStep::Pip, s.install_pip),
        (InstallStep::Config, s.install_config),
        (InstallStep::ExtraFiles, "Generating extra files"),
    ];

    let items: Vec<ListItem> = steps
        .iter()
        .map(|(step, label)| {
            let done = app.install.steps_done.contains(step);
            let active = app.install.step == Some(*step);
            let (icon, sty) = if done {
                ("  ✓  ", Style::default().fg(p.ok))
            } else if active {
                ("  ▶  ", Style::default().fg(p.sel).add_modifier(Modifier::BOLD))
            } else {
                ("  ○  ", Style::default().fg(p.dim))
            };
            let mb_info = if active && *step == InstallStep::Downloading && app.install.total > 0 {
                format!(
                    "  {:.1} / {:.1} MB",
                    app.install.done as f64 / 1_048_576.0,
                    app.install.total as f64 / 1_048_576.0
                )
            } else {
                String::new()
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, sty),
                Span::styled(*label, sty),
                Span::styled(mb_info, Style::default().fg(p.dim)),
            ]))
        })
        .collect();
    f.render_widget(List::new(items), chunks[1]);

    render_log_tail(f, app, p, chunks[2]);
}

fn list_step_item<'a>(done: bool, active: bool, label: &'a str, p: &Palette) -> ListItem<'a> {
    let (icon, sty) = if done {
        ("  ✓  ", Style::default().fg(p.ok))
    } else if active {
        ("  ▶  ", Style::default().fg(p.sel).add_modifier(Modifier::BOLD))
    } else {
        ("  ○  ", Style::default().fg(p.dim))
    };
    ListItem::new(Line::from(vec![
        Span::styled(icon, sty),
        Span::styled(label, sty),
    ]))
}

fn render_log_tail(f: &mut Frame, app: &App, p: &Palette, area: Rect) {
    let visible = area.height as usize;
    let log_items: Vec<ListItem> = app
        .install
        .log
        .iter()
        .rev()
        .take(visible)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|l| {
            ListItem::new(Line::from(Span::styled(
                l.clone(),
                Style::default().fg(p.dim),
            )))
        })
        .collect();
    f.render_widget(List::new(log_items), area);
}

// ── Self-Test ─────────────────────────────────────────────────────────────────

fn render_selftest(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.selftest_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            s.selftest_starting,
            Style::default().fg(p.dim),
        )),
        Line::raw(""),
    ];
    for l in &app.test_log {
        lines.push(Line::from(Span::styled(
            l.clone(),
            Style::default().fg(p.dim),
        )));
    }

    f.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        inner,
    );
}

// ── Done ──────────────────────────────────────────────────────────────────────

fn render_done(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.done_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Uninstall done: compact screen
    if app.config.install_mode == InstallMode::Uninstall {
        let lines = vec![
            Line::raw(""),
            Line::from(Span::styled(
                "  ✓  Uninstallation complete",
                Style::default().fg(p.ok).add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Removed: ", Style::default().fg(p.dim)),
                Span::styled(app.config.output_dir.clone(), Style::default().fg(p.hi)),
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                "  All server files, database, and configuration have been deleted.",
                Style::default().fg(p.dim),
            )),
        ];
        f.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }

    // Split: left = status+URLs, right = generated files
    let sides =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).split(inner);

    // ── Left ──────────────────────────────────────────────────────────────────
    let port = app.config.port_u16();
    let host = &app.config.host;

    let test_line = match &app.test_result {
        Some(TestResult::Pass) => Line::from(Span::styled(
            format!("  ✓ {}", s.selftest_pass),
            Style::default().fg(p.ok),
        )),
        Some(TestResult::Fail(e)) => Line::from(Span::styled(
            format!("  ✗ {} ({})", s.selftest_fail, e),
            Style::default().fg(p.err),
        )),
        Some(TestResult::Skipped) => Line::from(Span::styled(
            format!("  ·  {}", s.selftest_skip),
            Style::default().fg(p.dim),
        )),
        None => Line::raw(""),
    };

    let ok = Style::default().fg(p.ok);
    let dim = Style::default().fg(p.dim);
    let hi = Style::default().fg(p.hi).add_modifier(Modifier::BOLD);

    let mut left = vec![
        Line::raw(""),
        Line::from(Span::styled(
            format!("  ✓  Installed to: {}", app.config.output_dir),
            ok,
        )),
        Line::from(Span::styled("  ✓  Configuration generated", ok)),
        Line::from(Span::styled("  ✓  Python packages installed", ok)),
        test_line,
        Line::raw(""),
        Line::from(vec![
            Span::styled("  Server URL   ", dim),
            Span::styled(format!("http://{}:{}", host, port), hi),
        ]),
        Line::from(vec![
            Span::styled("  Admin panel  ", dim),
            Span::styled(format!("http://{}:{}/admin", host, port), hi),
        ]),
    ];

    if app.build_elapsed > 0.0 {
        left.push(Line::raw(""));
        left.push(Line::from(vec![
            Span::styled("  Build time   ", dim),
            Span::styled(
                format!("{:.1}s", app.build_elapsed),
                Style::default().fg(p.accent),
            ),
        ]));
    }

    left.push(Line::raw(""));
    if app.config.target_os.gen_bat() {
        left.push(Line::from(vec![
            Span::styled("  Windows:  ", dim),
            Span::styled("run.bat", ok),
        ]));
    }
    if app.config.target_os.gen_sh() {
        left.push(Line::from(vec![
            Span::styled("  Linux:    ", dim),
            Span::styled("./run.sh", ok),
        ]));
    }
    left.push(Line::raw(""));
    left.push(Line::from(Span::styled(
        "  First run: server will prompt you to create",
        dim,
    )));
    left.push(Line::from(Span::styled("  an admin account.", dim)));

    f.render_widget(
        Paragraph::new(Text::from(left)).wrap(Wrap { trim: false }),
        sides[0],
    );

    // ── Right: generated files ────────────────────────────────────────────────
    let mut right = vec![
        Line::raw(""),
        Line::from(Span::styled(
            "  Generated files:",
            Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
    ];
    let always = [
        "config.yml",
        ".env",
        ".env.example",
        "README.md",
        "install.log",
    ];
    for f_name in &always {
        right.push(Line::from(vec![
            Span::styled("  ✓ ", ok),
            Span::styled(*f_name, Style::default().fg(p.hi)),
        ]));
    }
    for f_name in &app.generated_files {
        if !always.contains(&f_name.as_str()) {
            right.push(Line::from(vec![
                Span::styled("  ✓ ", ok),
                Span::styled(f_name.clone(), Style::default().fg(p.hi)),
            ]));
        }
    }

    f.render_widget(
        Paragraph::new(Text::from(right)).wrap(Wrap { trim: false }),
        sides[1],
    );
}

// ── Error ─────────────────────────────────────────────────────────────────────

fn render_error(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.err_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let message_rows = app.error_msg.lines().count() as u16;
    let error_height = message_rows
        .saturating_add(6)
        .clamp(8, inner.height.saturating_sub(3).max(8));
    let chunks =
        Layout::vertical([Constraint::Length(error_height), Constraint::Min(0)]).split(inner);

    let mut lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            "  Installation failed:",
            Style::default().fg(p.err).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
    ];
    for line in app.error_msg.lines() {
        lines.push(Line::from(Span::styled(
            format!("  {line}"),
            Style::default().fg(p.hi),
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "  [Enter] go back and reconfigure",
        Style::default().fg(p.warn),
    )));
    f.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        chunks[0],
    );

    if !app.install.log.is_empty() {
        let visible = chunks[1].height.saturating_sub(1) as usize;
        let recent: Vec<ListItem> = app
            .install
            .log
            .iter()
            .rev()
            .take(visible)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|line| {
                ListItem::new(Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(p.dim),
                )))
            })
            .collect();
        f.render_widget(
            List::new(recent).block(block_titled("Recent log", p)),
            chunks[1],
        );
    }
}
