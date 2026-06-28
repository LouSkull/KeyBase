use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    net::TcpListener,
    path::Path,
    process::Command,
    sync::mpsc,
    thread,
    time::Duration,
};

use crate::{config_gen, wizard::BuildConfig};

const GITHUB_OWNER: &str = "LouSkull";
const GITHUB_REPO: &str = "KeyBase";
const RELEASE_API_URL: &str = "https://api.github.com/repos/LouSkull/KeyBase/releases/latest";
const RELEASE_ASSET_NAMES: &[&str] = &["Server-Portable.zip", "Server.zip"];

#[derive(Debug, Default, Clone)]
struct ExistingConfig {
    server_mode: String,
    server_port: Option<u16>,
    server_admin_port: Option<u16>,
    server_api_port: Option<u16>,
    database_backend: String,
}

/// Messages sent from install thread → UI.
pub enum InstallMsg {
    Progress {
        step: InstallStep,
        done: u64,
        total: u64,
    },
    Log(String),
    StepDone(InstallStep),
    GeneratedFile(String),
    Error(String),
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InstallStep {
    Downloading,
    Extracting,
    Venv,
    Pip,
    Config,
    ExtraFiles,
}

/// Spawn the install pipeline in a background thread.
pub fn spawn_install(
    cfg: BuildConfig,
    python: String,
) -> (thread::JoinHandle<()>, mpsc::Receiver<InstallMsg>) {
    let (tx, rx) = mpsc::channel::<InstallMsg>();
    let handle = thread::spawn(move || {
        if let Err(e) = run_install(&cfg, &python, &tx) {
            let _ = tx.send(InstallMsg::Error(format!("{e:#}")));
        } else {
            let _ = tx.send(InstallMsg::Done);
        }
    });
    (handle, rx)
}

fn run_install(cfg: &BuildConfig, python: &str, tx: &mpsc::Sender<InstallMsg>) -> Result<()> {
    let output_dir = cfg.output_path();
    let upgrade_mode = output_dir.join("config.yml").exists();
    let existing_config = if upgrade_mode {
        load_existing_config(&output_dir)
    } else {
        None
    };

    if upgrade_mode {
        log(tx, "Existing installation detected — update mode enabled.");
        log(
            tx,
            "Runtime config, secrets, backups, and data will be preserved.",
        );
    }

    // ── 1. Download ───────────────────────────────────────────────────────────
    let release_urls = resolve_release_urls();
    log(
        tx,
        format!(
            "Resolved {} release download candidate(s).",
            release_urls.len()
        ),
    );
    let zip_bytes = download_with_progress(&release_urls, tx)
        .context("Failed to download Server-Portable.zip")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Downloading));

    if upgrade_mode {
        if let Some(existing) = &existing_config {
            let ports = existing_listener_ports(existing, cfg.port_u16());
            log(tx, "Stopping the existing server before updating files…");
            stop_existing_server(&output_dir, &ports, tx)
                .context("Failed to stop the existing Key Base server")?;
        } else {
            log(tx, "Stopping the existing server before updating files…");
            stop_existing_server(&output_dir, &[cfg.port_u16()], tx)
                .context("Failed to stop the existing Key Base server")?;
        }
        cleanup_upgrade_dir(&output_dir).context("Failed to prepare the update directory")?;
    }

    // ── 2. Extract ────────────────────────────────────────────────────────────
    log(tx, format!("Extracting to {}", output_dir.display()));
    fs::create_dir_all(&output_dir).context("Cannot create output directory")?;
    extract_zip(&zip_bytes, &output_dir, tx).context("Failed to extract Server-Portable.zip")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Extracting));

    // ── 3. Python venv ────────────────────────────────────────────────────────
    log(tx, "Creating Python virtual environment…");
    progress(tx, InstallStep::Venv, 0, 1);
    let venv_dir = output_dir.join(".venv");
    run_cmd(
        python,
        &["-m", "venv", &venv_dir.to_string_lossy()],
        &output_dir,
    )
    .context("Failed to create Python venv")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Venv));

    // ── 4. pip install ────────────────────────────────────────────────────────
    log(tx, "Installing Python packages…");
    progress(tx, InstallStep::Pip, 0, 1);
    let pip = venv_python(&venv_dir);
    run_cmd(
        &pip,
        &["-m", "pip", "install", "--upgrade", "pip", "-q"],
        &output_dir,
    )
    .context("pip upgrade failed")?;
    run_cmd(
        &pip,
        &["-m", "pip", "install", "-r", "requirements.txt", "-q"],
        &output_dir,
    )
    .context("pip install requirements failed")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Pip));

    // ── 5. Config files ───────────────────────────────────────────────────────
    log(tx, "Generating configuration files…");
    progress(tx, InstallStep::Config, 0, 1);

    if !upgrade_mode || !output_dir.join("config.yml").exists() {
        config_gen::write_config(&output_dir, cfg).context("write config.yml")?;
        emit_file(tx, "config.yml");
    } else {
        log(tx, "Keeping the existing config.yml.");
    }

    if !upgrade_mode || !output_dir.join(".env").exists() {
        config_gen::write_env(&output_dir).context("write .env")?;
        emit_file(tx, ".env");
    } else {
        log(tx, "Keeping the existing .env.");
    }

    let _ = tx.send(InstallMsg::StepDone(InstallStep::Config));

    // ── 6. Extra files ────────────────────────────────────────────────────────
    log(tx, "Generating extra files…");
    progress(tx, InstallStep::ExtraFiles, 0, 1);

    if cfg.gen_docker {
        config_gen::write_docker(&output_dir, cfg).context("write Docker files")?;
        emit_file(tx, "Dockerfile");
        emit_file(tx, "docker-compose.yml");
        emit_file(tx, ".dockerignore");
    }
    if cfg.gen_nginx {
        config_gen::write_nginx(&output_dir, cfg).context("write nginx.conf")?;
        emit_file(tx, "nginx.conf");
    }
    if cfg.gen_systemd {
        config_gen::write_systemd(&output_dir, cfg).context("write keybase.service")?;
        emit_file(tx, "keybase.service");
    }

    config_gen::write_readme(&output_dir, cfg).context("write README.md")?;
    emit_file(tx, "README.md");

    if let Some(existing) = &existing_config {
        maybe_migrate_database(&output_dir, cfg, existing, &pip, tx)
            .context("database migration failed")?;
    }

    let _ = tx.send(InstallMsg::StepDone(InstallStep::ExtraFiles));

    Ok(())
}

fn load_existing_config(output_dir: &Path) -> Option<ExistingConfig> {
    let config_path = output_dir.join("config.yml");
    let raw = fs::read_to_string(config_path).ok()?;
    Some(ExistingConfig {
        server_mode: config_value(&raw, "server", "mode").unwrap_or_default(),
        server_port: config_value(&raw, "server", "port").and_then(|s| s.parse::<u16>().ok()),
        server_admin_port: config_value(&raw, "server", "admin_port")
            .and_then(|s| s.parse::<u16>().ok()),
        server_api_port: config_value(&raw, "server", "api_port")
            .and_then(|s| s.parse::<u16>().ok()),
        database_backend: config_value(&raw, "database", "backend").unwrap_or_default(),
    })
}

fn config_value(raw: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    let section_marker = format!("{section}:");
    for line in raw.lines() {
        let trimmed_end = line.trim_end();
        let trimmed = trimmed_end.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = trimmed_end.len().saturating_sub(trimmed.len());
        if indent == 0 {
            in_section = trimmed == section_marker;
            continue;
        }
        if !in_section || indent != 2 {
            continue;
        }
        let (found_key, value) = trimmed.split_once(':')?;
        if found_key.trim() != key {
            continue;
        }
        return Some(strip_yaml_quotes(value.trim()));
    }
    None
}

fn strip_yaml_quotes(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn existing_listener_ports(existing: &ExistingConfig, fallback_port: u16) -> Vec<u16> {
    let mut ports = Vec::new();
    let mode = existing.server_mode.trim().to_ascii_lowercase();
    if mode == "split" {
        if let Some(port) = existing.server_admin_port {
            ports.push(port);
        }
        if let Some(port) = existing.server_api_port {
            if !ports.contains(&port) {
                ports.push(port);
            }
        }
    } else if let Some(port) = existing.server_port {
        ports.push(port);
    }
    if ports.is_empty() {
        ports.push(fallback_port);
    }
    ports.retain(|port| *port > 0);
    ports
}

fn cleanup_upgrade_dir(output_dir: &Path) -> Result<()> {
    if !output_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches!(name.as_ref(), "config.yml" | ".env" | "data" | "backups") {
            continue;
        }
        remove_path(&entry.path())?;
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn stop_existing_server(
    output_dir: &Path,
    ports: &[u16],
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<()> {
    if let Some(pid) = read_pid_file(output_dir) {
        log(tx, format!("Stopping existing server process (PID {pid})…"));
        terminate_pid(pid);
        let _ = fs::remove_file(output_dir.join(".keybase.pid"));
    }
    terminate_keybase_processes();

    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();

    for port in &ports {
        if port_is_busy(*port) {
            log(tx, format!("Stopping listeners on port {port}…"));
            kill_listeners_on_port(*port)?;
        }
    }

    wait_for_ports_free(&ports, Duration::from_secs(15))?;
    Ok(())
}

fn terminate_keybase_processes() {
    #[cfg(windows)]
    {
        let script = "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'python.*-m\\s+keybase' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }";
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("pkill")
            .args(["-f", "python.*-m keybase"])
            .status();
    }
}

fn read_pid_file(output_dir: &Path) -> Option<u32> {
    let pid_path = output_dir.join(".keybase.pid");
    let raw = fs::read_to_string(pid_path).ok()?;
    raw.trim().parse::<u32>().ok()
}

fn terminate_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
    #[cfg(not(windows))]
    {
        let pid_str = pid.to_string();
        let _ = Command::new("kill").args(["-TERM", &pid_str]).status();
        std::thread::sleep(Duration::from_millis(500));
        let _ = Command::new("kill").args(["-KILL", &pid_str]).status();
    }
}

fn port_is_busy(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_err()
}

fn wait_for_ports_free(ports: &[u16], timeout: Duration) -> Result<()> {
    if ports.is_empty() {
        return Ok(());
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let busy = ports.iter().copied().find(|port| port_is_busy(*port));
        if busy.is_none() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let busy_ports: Vec<String> = ports
        .iter()
        .copied()
        .filter(|port| port_is_busy(*port))
        .map(|port| port.to_string())
        .collect();
    if busy_ports.is_empty() {
        Ok(())
    } else {
        bail!("Port(s) still in use after stop: {}", busy_ports.join(", "))
    }
}

fn kill_listeners_on_port(port: u16) -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output()
            .context("netstat failed")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let needle = format!(":{}", port);
        let mut pids = BTreeSet::new();
        for line in stdout.lines() {
            let upper = line.to_ascii_uppercase();
            if !line.contains(&needle) || !upper.contains("LISTENING") {
                continue;
            }
            if let Some(pid) = line
                .split_whitespace()
                .last()
                .and_then(|item| item.parse::<u32>().ok())
            {
                pids.insert(pid);
            }
        }
        for pid in pids {
            let _ = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .status();
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        let mut pids = BTreeSet::new();
        match Command::new("lsof")
            .args(["-ti", &format!("tcp:{port}")])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Ok(pid) = line.trim().parse::<u32>() {
                        pids.insert(pid);
                    }
                }
            }
            Err(_) => {
                let _ = Command::new("pkill")
                    .args(["-f", "python.*-m keybase"])
                    .status();
            }
        }
        for pid in pids {
            let pid_str = pid.to_string();
            let _ = Command::new("kill").args(["-TERM", &pid_str]).status();
            std::thread::sleep(Duration::from_millis(200));
            let _ = Command::new("kill").args(["-KILL", &pid_str]).status();
        }
        Ok(())
    }
}

fn database_backend_label(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" | "pgsql" => "postgresql",
        "mysql" | "mariadb" => "mysql",
        _ => "sqlite",
    }
}

fn target_backend_label(cfg: &BuildConfig) -> &'static str {
    match cfg.db_backend {
        crate::wizard::DbBackend::Sqlite => "sqlite",
        crate::wizard::DbBackend::Postgres => "postgresql",
        crate::wizard::DbBackend::Mysql => "mysql",
    }
}

fn maybe_migrate_database(
    output_dir: &Path,
    cfg: &BuildConfig,
    existing: &ExistingConfig,
    python: &str,
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<()> {
    let raw_from = existing.database_backend.trim();
    if raw_from.is_empty() {
        log(
            tx,
            "Could not determine the existing database backend — skipping automatic migration.",
        );
        return Ok(());
    }
    let from_backend = database_backend_label(raw_from);
    let to_backend = target_backend_label(cfg);
    if from_backend == to_backend {
        log(
            tx,
            "Database backend unchanged — schema migrations will run on startup.",
        );
        return Ok(());
    }

    log(
        tx,
        format!("Migrating database backend: {from_backend} → {to_backend}…"),
    );
    let mut args: Vec<String> = vec![
        "-m".into(),
        "keybase".into(),
        "db-migrate".into(),
        "--to-backend".into(),
        to_backend.into(),
    ];
    match cfg.db_backend {
        crate::wizard::DbBackend::Sqlite => {
            args.push("--to-sqlite-path".into());
            args.push(cfg.sqlite_path.clone());
        }
        crate::wizard::DbBackend::Postgres => {
            args.push("--to-url".into());
            args.push(cfg.pg_url.clone());
        }
        crate::wizard::DbBackend::Mysql => {
            args.push("--to-url".into());
            args.push(cfg.mysql_url.clone());
        }
    }
    args.push("--write-config".into());
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_cmd(python, &arg_refs, output_dir).context("database migration command failed")?;
    log(tx, "Database migration finished — config.yml updated.");
    Ok(())
}

// ── Download ──────────────────────────────────────────────────────────────────

fn resolve_release_urls() -> Vec<String> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("keybase-builder/0.1")
        .build()
    {
        Ok(client) => client,
        Err(_) => return fallback_release_urls(None),
    };

    let mut urls = Vec::new();
    let mut tag_name: Option<String> = None;

    if let Ok(resp) = client
        .get(RELEASE_API_URL)
        .header("Accept", "application/vnd.github+json")
        .send()
        .and_then(|resp| resp.error_for_status())
    {
        if let Ok(text) = resp.text() {
            tag_name = extract_json_string_field(&text, "tag_name")
                .map(|value| value.trim().trim_start_matches('v').to_string())
                .filter(|value| !value.is_empty());

            let mut preferred = Vec::new();
            let mut alternates = Vec::new();
            for url in extract_json_string_values(&text, "browser_download_url") {
                let filename = url_filename(&url);
                if filename.is_empty() {
                    continue;
                }
                if RELEASE_ASSET_NAMES
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(&filename))
                {
                    preferred.push(url);
                } else if filename.to_ascii_lowercase().ends_with(".zip") {
                    alternates.push(url);
                }
            }
            push_unique_many(&mut urls, preferred);
            push_unique_many(&mut urls, alternates);
        }
    }

    push_unique_many(&mut urls, fallback_release_urls(tag_name.as_deref()));
    urls
}

fn fallback_release_urls(tag_name: Option<&str>) -> Vec<String> {
    let mut urls = Vec::new();
    for asset in RELEASE_ASSET_NAMES {
        urls.push(format!(
            "https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest/download/{asset}"
        ));
        if let Some(tag) = tag_name {
            urls.push(format!(
                "https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/download/{tag}/{asset}"
            ));
        }
    }
    urls
}

fn extract_json_string_field(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = text.find(&pattern)? + pattern.len();
    parse_json_string(&text[start..]).map(|(value, _)| value)
}

fn extract_json_string_values(text: &str, key: &str) -> Vec<String> {
    let pattern = format!("\"{}\":\"", key);
    let mut values = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&pattern) {
        let after = &rest[start + pattern.len()..];
        if let Some((value, remaining)) = parse_json_string(after) {
            values.push(value);
            rest = remaining;
        } else {
            break;
        }
    }
    values
}

fn parse_json_string(input: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            return Some((out, &input[i + 1..]));
        }
        if b == b'\\' {
            i += 1;
            if i >= bytes.len() {
                break;
            }
            match bytes[i] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                _ => {}
            }
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    None
}

fn url_filename(url: &str) -> String {
    let tail = url.rsplit('/').next().unwrap_or("").trim();
    tail.trim_end_matches(['?', '#']).to_string()
}

fn push_unique_many(target: &mut Vec<String>, source: Vec<String>) {
    for url in source {
        if !target.iter().any(|existing| existing == &url) {
            target.push(url);
        }
    }
}

fn download_with_progress(urls: &[String], tx: &mpsc::Sender<InstallMsg>) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("keybase-builder/0.1")
        .build()?;

    let mut errors = Vec::new();
    for (idx, url) in urls.iter().enumerate() {
        log(tx, format!("Connecting to: {}", url));
        match download_single(&client, url, tx) {
            Ok(bytes) => return Ok(bytes),
            Err(err) => {
                errors.push(format!("candidate {}: {} ({err:#})", idx + 1, url));
            }
        }
    }

    bail!(
        "Unable to download Server-Portable.zip from any release candidate.\n{}",
        errors.join("\n")
    )
}

fn download_single(
    client: &reqwest::blocking::Client,
    url: &str,
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<Vec<u8>> {
    let mut resp = client.get(url).send()?.error_for_status()?;
    let total = resp.content_length().unwrap_or(0);
    let mut buf = if total > 0 {
        Vec::with_capacity(total as usize)
    } else {
        Vec::new()
    };
    let mut done: u64 = 0;
    let mut chunk = [0u8; 65536];

    loop {
        let n = resp.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        done += n as u64;
        let _ = tx.send(InstallMsg::Progress {
            step: InstallStep::Downloading,
            done,
            total,
        });
        // Log every ~512 KB
        if total > 0 && (done / (512 * 1024)) > ((done - n as u64) / (512 * 1024)) {
            log(
                tx,
                format!(
                    "  {:.1} / {:.1} MB  ({:.0}%)",
                    mb(done),
                    mb(total),
                    done as f64 / total as f64 * 100.0
                ),
            );
        }
    }
    log(tx, format!("Download complete — {:.1} MB", mb(done)));
    Ok(buf)
}

// ── Extract ───────────────────────────────────────────────────────────────────

fn extract_zip(data: &[u8], dest: &Path, tx: &mpsc::Sender<InstallMsg>) -> Result<()> {
    let cursor = io::Cursor::new(data);
    let mut arc = zip::ZipArchive::new(cursor).context("Not a valid ZIP archive")?;
    let total = arc.len() as u64;

    for i in 0..arc.len() {
        let mut file = arc.by_index(i)?;
        let raw_name = file.name().to_owned();

        // Strip leading "Server/" prefix (common in GitHub release zips)
        let rel = strip_prefix(&raw_name, &["Server/", "Server\\", "server/"]);
        if rel.is_empty() {
            continue;
        }

        let out_path = dest.join(&rel);
        // Guard against directory traversal
        if !out_path.starts_with(dest) {
            bail!("ZIP traversal attempt: {}", raw_name);
        }

        if file.is_dir() {
            fs::create_dir_all(&out_path)?;
        } else {
            if let Some(p) = out_path.parent() {
                fs::create_dir_all(p)?;
            }
            let mut out = fs::File::create(&out_path)?;
            io::copy(&mut file, &mut out)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    if mode & 0o111 != 0 {
                        let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode));
                    }
                }
            }
        }
        let _ = tx.send(InstallMsg::Progress {
            step: InstallStep::Extracting,
            done: i as u64 + 1,
            total,
        });
    }
    log(tx, format!("Extracted {} files", total));
    Ok(())
}

fn strip_prefix<'a>(s: &'a str, prefixes: &[&str]) -> &'a str {
    for p in prefixes {
        if let Some(rest) = s.strip_prefix(p) {
            return rest;
        }
    }
    s
}

// ── Process helpers ───────────────────────────────────────────────────────────

fn run_cmd(exe: &str, args: &[&str], cwd: &Path) -> Result<()> {
    let status = std::process::Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .status()?;
    if !status.success() {
        bail!("`{} {}` exited with {}", exe, args.join(" "), status);
    }
    Ok(())
}

fn venv_python(venv: &Path) -> String {
    if cfg!(windows) {
        venv.join("Scripts")
            .join("python.exe")
            .to_string_lossy()
            .to_string()
    } else {
        venv.join("bin")
            .join("python")
            .to_string_lossy()
            .to_string()
    }
}

// ── Message helpers ───────────────────────────────────────────────────────────

fn log(tx: &mpsc::Sender<InstallMsg>, msg: impl Into<String>) {
    let _ = tx.send(InstallMsg::Log(msg.into()));
}

fn progress(tx: &mpsc::Sender<InstallMsg>, step: InstallStep, done: u64, total: u64) {
    let _ = tx.send(InstallMsg::Progress { step, done, total });
}

fn emit_file(tx: &mpsc::Sender<InstallMsg>, name: &str) {
    let _ = tx.send(InstallMsg::GeneratedFile(name.to_string()));
}

fn mb(b: u64) -> f64 {
    b as f64 / 1_048_576.0
}
