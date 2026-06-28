use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Padding, Paragraph, Wrap},
    Frame,
};

use crate::{
    app::{App, Phase, TOTAL_STEPS},
    i18n::{Lang, Strings},
    install::InstallStep,
    platform::CheckStatus,
    selftest::TestResult,
    wizard::{DbBackend, FieldId},
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
        Phase::Wizard => vec![
            Span::styled("[↑↓/Tab] Navigate", dim),
            Span::raw("   "),
            Span::styled("[←→] Change", dim),
            Span::raw("   "),
            Span::styled("[PgDn] Next →", ok),
            Span::raw("   "),
            Span::styled("[Esc] Back", dim),
        ],
        Phase::Confirm => vec![
            Span::styled("[Y/Enter] Install", ok),
            Span::raw("   "),
            Span::styled("[N/Esc] Back", dim),
        ],
        Phase::Done => vec![
            Span::styled("[o] Open folder", ok),
            Span::raw("   "),
            Span::styled("[q] Quit", dim),
        ],
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
    let fields = ws.effective_fields();
    let total_fields = fields.len();
    let visible_rows = (inner.height / ROW_H) as usize;

    // Compute scroll — we need a temp mutable copy just to call clamp_scroll
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

    // Scrollbar indicator
    if total_fields > visible_rows {
        let scroll_info = format!(" {}/{} ", ws.field + 1, total_fields);
        let info_p = Paragraph::new(Span::styled(scroll_info, Style::default().fg(p.dim)))
            .alignment(Alignment::Right);
        // Draw in top-right corner of inner area
        let sr = Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width,
            height: 1,
        };
        f.render_widget(info_p, sr);
    }

    for (i, &fid) in visible.iter().enumerate() {
        let row = Rect {
            x: inner.x,
            y: inner.y + i as u16 * ROW_H,
            width: inner.width,
            height: ROW_H,
        };
        if row.y >= inner.y + inner.height {
            break;
        }
        let is_active = i == active_in_view;
        render_wizard_field(f, app, s, p, fid, is_active, row);
    }

    // Set cursor for active text field
    if let Some(&fid) = visible.get(active_in_view) {
        if fid.is_text() {
            let ti = ws.ti(fid);
            let label_w: u16 = 26;
            let row_y = inner.y + active_in_view as u16 * ROW_H;
            let cur_x = inner.x + 2 + label_w + ti.cursor as u16;
            if row_y < inner.y + inner.height && cur_x < inner.x + inner.width {
                f.set_cursor_position((cur_x, row_y));
            }
        }
    }
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
        FieldId::Debug => "Debug mode",
        FieldId::GenDocker => "Generate Docker files",
        FieldId::GenNginx => "Generate NGINX config",
        FieldId::GenSystemd => "Generate systemd service",
        FieldId::SelfTest => "Run self-test after install",
        FieldId::Language => s.fld_lang,
        FieldId::Theme => "Theme",
    };

    let value: String = match fid {
        FieldId::Output => ws.f_output.buf.clone(),
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
        FieldId::ProvToken => ws.f_prov_token.buf.clone(),
        FieldId::Debug => bool_label(ws.debug),
        FieldId::GenDocker => bool_label(ws.gen_docker),
        FieldId::GenNginx => bool_label(ws.gen_nginx),
        FieldId::GenSystemd => bool_label(ws.gen_systemd),
        FieldId::SelfTest => bool_label(ws.selftest),
        FieldId::Language => Lang::all()
            .get(ws.lang_idx)
            .map(|l| l.label())
            .unwrap_or("English")
            .into(),
        FieldId::Theme => {
            if ws.dark_theme {
                "Dark".into()
            } else {
                "Light".into()
            }
        }
    };

    let label_sty = if active {
        Style::default().fg(p.sel).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(p.dim)
    };
    let value_sty = if active {
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

// ── Confirm ───────────────────────────────────────────────────────────────────

fn render_confirm(f: &mut Frame, app: &App, s: &Strings, p: &Palette, area: Rect) {
    let block = block_titled(s.confirm_title, p);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let cfg = &app.config;
    let dim = Style::default().fg(p.dim);
    let hi = Style::default().fg(p.hi).add_modifier(Modifier::BOLD);

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
        lines.push(kv("  Provision token", &cfg.prov_token));
    }
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

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(TOTAL_STEPS as u16 + 1),
        Constraint::Min(0),
    ])
    .split(inner);

    // Progress bar
    let ratio = app.install.overall_progress();
    f.render_widget(
        Gauge::default()
            .gauge_style(Style::default().fg(p.accent))
            .ratio(ratio)
            .label(format!("{:.0}%", ratio * 100.0)),
        chunks[0],
    );

    // Step list
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
                (
                    "  ▶  ",
                    Style::default().fg(p.sel).add_modifier(Modifier::BOLD),
                )
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

    // Log tail
    let log_area = chunks[2];
    let visible = log_area.height as usize;
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
    f.render_widget(List::new(log_items), log_area);
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
    left.push(Line::from(vec![
        Span::styled("  Windows:  ", dim),
        Span::styled("run.bat", ok),
    ]));
    left.push(Line::from(vec![
        Span::styled("  Linux:    ", dim),
        Span::styled("./run.sh", ok),
    ]));
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
    let always = ["config.yml", ".env", "README.md", "install.log"];
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

    let lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            "  Installation failed:",
            Style::default().fg(p.err).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            format!("  {}", app.error_msg),
            Style::default().fg(p.hi),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            "  [Enter] go back and reconfigure",
            Style::default().fg(p.warn),
        )),
    ];
    f.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        inner,
    );
}
