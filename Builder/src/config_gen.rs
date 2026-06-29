use crate::wizard::{BuildConfig, DbBackend, TargetOs};
use anyhow::Result;
use std::{fs, path::Path};

const CONFIG_TEMPLATE: &str = include_str!("../assets/config.yml.example");
const ENV_TEMPLATE: &str = include_str!("../assets/.env.example");

// ── config.yml ────────────────────────────────────────────────────────────────

pub fn write_config(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let port = cfg.port_u16();
    let public_url = if cfg.domain.is_empty() {
        format!("http://{}:{}", cfg.host, port)
    } else {
        format!("https://{}", cfg.domain)
    };

    let mut yaml = CONFIG_TEMPLATE.replace("\r\n", "\n");

    yaml = replace_yaml_value(yaml, "server", "mode", "combined");
    yaml = replace_yaml_value(yaml, "server", "host", &cfg.host);
    yaml = replace_yaml_value(yaml, "server", "port", &port.to_string());
    yaml = replace_yaml_value(yaml, "server", "admin_host", &cfg.host);
    yaml = replace_yaml_value(yaml, "server", "admin_port", &port.to_string());
    yaml = replace_yaml_value(yaml, "server", "api_host", &cfg.host);
    yaml = replace_yaml_value(yaml, "server", "api_port", &port.to_string());
    yaml = replace_yaml_value(
        yaml,
        "server",
        "allow_remote_admin",
        yaml_bool(cfg.allow_remote_admin),
    );
    yaml = replace_yaml_value(
        yaml,
        "server",
        "trust_proxy_headers",
        yaml_bool(cfg.trust_proxy),
    );

    yaml = replace_yaml_value(yaml, "cloudflare", "enabled", yaml_bool(cfg.cloudflare));
    yaml = replace_yaml_value(
        yaml,
        "cloudflare",
        "require_https",
        yaml_bool(!cfg.domain.is_empty()),
    );

    yaml = replace_yaml_value(
        yaml,
        "security",
        "session_hours",
        &cfg.session_hours_u32().to_string(),
    );

    yaml = replace_yaml_value(
        yaml,
        "api",
        "verify_rate_limit_per_minute",
        &cfg.rate_limit_u32().to_string(),
    );
    yaml = replace_yaml_value(yaml, "api", "public_base_url", &yaml_string(&public_url));
    yaml = replace_yaml_value(yaml, "admin", "public_base_url", &yaml_string(&public_url));

    let (backend, url) = match cfg.db_backend {
        DbBackend::Sqlite => ("sqlite", String::new()),
        DbBackend::Postgres => ("postgresql", cfg.pg_url.clone()),
        DbBackend::Mysql => ("mysql", cfg.mysql_url.clone()),
    };
    yaml = replace_yaml_value(yaml, "database", "backend", backend);
    yaml = replace_yaml_value(yaml, "database", "url", &yaml_string(&url));
    yaml = replace_yaml_value(yaml, "database", "sqlite_path", &cfg.sqlite_path);

    yaml = replace_yaml_value(
        yaml,
        "backup",
        "interval_minutes",
        &cfg.backup_interval_u32().to_string(),
    );
    yaml = replace_yaml_value(
        yaml,
        "backup",
        "keep_last",
        &cfg.backup_keep_u32().to_string(),
    );

    yaml = replace_yaml_value(yaml, "provisioning", "enabled", yaml_bool(cfg.prov_enabled));
    yaml = replace_yaml_value(yaml, "provisioning", "shared_token", &cfg.prov_token);

    fs::write(dir.join("config.yml"), yaml)?;
    Ok(())
}

// ── .env.example ─────────────────────────────────────────────────────────────

pub fn write_env(dir: &Path, _cfg: &BuildConfig) -> Result<()> {
    let env_template = build_env_template();
    fs::write(dir.join(".env.example"), &env_template)?;

    let env_path = dir.join(".env");
    if !env_path.exists() {
        fs::write(env_path, env_template)?;
    }
    Ok(())
}

fn build_env_template() -> String {
    let mut env = ENV_TEMPLATE.replace("\r\n", "\n");
    if !env.ends_with('\n') {
        env.push('\n');
    }
    env
}

fn replace_yaml_value(mut yaml: String, section: &str, key: &str, value: &str) -> String {
    let section_marker = format!("{section}:");
    let mut in_section = false;
    let mut out = Vec::new();

    for line in yaml.lines() {
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len());

        if indent == 0 {
            in_section = trimmed == section_marker;
            out.push(line.to_string());
            continue;
        }

        if in_section && indent == 2 {
            if let Some((found_key, _)) = trimmed.split_once(':') {
                if found_key.trim() == key {
                    out.push(format!("  {key}: {value}"));
                    continue;
                }
            }
        }

        out.push(line.to_string());
    }

    yaml = out.join("\n");
    if !yaml.ends_with('\n') {
        yaml.push('\n');
    }
    yaml
}

fn yaml_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn yaml_string(value: &str) -> String {
    if value.is_empty() {
        "\"\"".into()
    } else if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '@'))
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off"
        )
    {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

// ── run.bat (Windows) ─────────────────────────────────────────────────────────

pub fn write_run_bat(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let port = cfg.port_u16();
    let workers = cfg.workers_u32();
    let bat = format!(
        "@echo off\r\n\
         title KeyBase Server\r\n\
         cd /d \"%~dp0\"\r\n\
         echo Starting KeyBase Server on port {port} ({workers} worker(s))...\r\n\
         echo Admin panel: http://{host}:{port}/admin\r\n\
         echo.\r\n\
         .venv\\Scripts\\python.exe -m keybase\r\n\
         if %errorlevel% neq 0 (\r\n\
             echo.\r\n\
             echo Server exited with code %errorlevel%\r\n\
             pause\r\n\
         )\r\n",
        port = port,
        workers = workers,
        host = cfg.host,
    );
    fs::write(dir.join("run.bat"), bat)?;
    Ok(())
}

// ── run.sh (Linux) ────────────────────────────────────────────────────────────

pub fn write_run_sh(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let port = cfg.port_u16();
    let workers = cfg.workers_u32();
    let sh = format!(
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\
         cd \"$(dirname \"$(readlink -f \"$0\")\")\"\n\
         echo \"Starting KeyBase Server on port {port} ({workers} worker(s))...\"\n\
         echo \"Admin panel: http://{host}:{port}/admin\"\n\
         exec .venv/bin/python -m keybase\n",
        port = port,
        workers = workers,
        host = cfg.host,
    );
    let path = dir.join("run.sh");
    fs::write(&path, sh)?;

    // Mark executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

// ── Dockerfile ────────────────────────────────────────────────────────────────

pub fn write_docker(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let port = cfg.port_u16();
    let workers = cfg.workers_u32();

    let dockerfile = format!(
        r#"FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# Copy server files
COPY . .

# Runtime directories
RUN mkdir -p data backups

EXPOSE {port}

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:{port}/')" || exit 1

ENV KEYBASE_WORKERS={workers}
CMD ["python", "-m", "keybase"]
"#,
        port = port,
        workers = workers,
    );

    let dockerignore = "\
.git\n\
.venv\nvenv\n\
__pycache__\n*.pyc\n*.pyo\n\
data/*\nbackups/*\n\
*.log\n.env\n\
target\n";

    let compose = format!(
        r#"services:
  keybase:
    build: .
    container_name: keybase
    restart: unless-stopped
    ports:
      - "{port}:{port}"
    volumes:
      - keybase_data:/app/data
      - keybase_backups:/app/backups
      - ./config.yml:/app/config.yml:ro
      - ./.env:/app/.env:ro
    environment:
      - PYTHONUNBUFFERED=1
    healthcheck:
      test: ["CMD", "python", "-c",
             "import urllib.request; urllib.request.urlopen('http://localhost:{port}/')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

volumes:
  keybase_data:
  keybase_backups:
"#,
        port = port,
    );

    fs::write(dir.join("Dockerfile"), dockerfile)?;
    fs::write(dir.join(".dockerignore"), dockerignore)?;
    fs::write(dir.join("docker-compose.yml"), compose)?;
    Ok(())
}

// ── NGINX config ──────────────────────────────────────────────────────────────

pub fn write_nginx(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let port = cfg.port_u16();
    let domain = if cfg.domain.is_empty() {
        "your-domain.com".to_string()
    } else {
        cfg.domain.clone()
    };

    let conf = format!(
        r#"# KeyBase — NGINX reverse proxy
# Place this file in /etc/nginx/sites-available/keybase
# Then: ln -s /etc/nginx/sites-available/keybase /etc/nginx/sites-enabled/
# And:  nginx -t && systemctl reload nginx

server {{
    listen 80;
    server_name {domain};

    # Redirect HTTP → HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    # TLS — replace with your certificate paths
    ssl_certificate     /etc/ssl/certs/{domain}.crt;
    ssl_certificate_key /etc/ssl/private/{domain}.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    client_max_body_size 10M;

    location / {{
        proxy_pass         http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }}
}}
"#,
        domain = domain,
        port = port,
    );

    fs::write(dir.join("nginx.conf"), conf)?;
    Ok(())
}

// ── systemd service ───────────────────────────────────────────────────────────

pub fn write_systemd(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let install_path = cfg.output_path().to_string_lossy().to_string();

    let service = format!(
        r#"[Unit]
Description=KeyBase License Key Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={path}
ExecStart={path}/.venv/bin/python -m keybase
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=keybase

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
"#,
        path = install_path,
    );

    fs::write(dir.join("keybase.service"), service)?;
    Ok(())
}

// ── README / Quick Start ──────────────────────────────────────────────────────

pub fn write_readme(dir: &Path, cfg: &BuildConfig) -> Result<()> {
    let port = cfg.port_u16();
    let host = &cfg.host;

    let run_section = match cfg.target_os {
        TargetOs::Windows => "### Windows\n```bat\nrun.bat\n```\n".to_string(),
        TargetOs::Linux => "### Linux\n```bash\n./run.sh\n```\n".to_string(),
        TargetOs::Both => {
            "### Windows\n```bat\nrun.bat\n```\n\n### Linux\n```bash\n./run.sh\n```\n".to_string()
        }
    };

    let run_files = match cfg.target_os {
        TargetOs::Windows => "| `run.bat` | Windows start script |\n".to_string(),
        TargetOs::Linux => "| `run.sh` | Linux start script |\n".to_string(),
        TargetOs::Both => {
            "| `run.bat` | Windows start script |\n| `run.sh` | Linux start script |\n".to_string()
        }
    };

    let docker_section = if cfg.gen_docker {
        format!(
            "\n## Docker\n\n```bash\ndocker compose up -d\n```\n\nServer: http://{host}:{port}\n",
            host = host,
            port = port
        )
    } else {
        String::new()
    };

    let nginx_section = if cfg.gen_nginx {
        "\n## NGINX\n\n```bash\nsudo cp nginx.conf /etc/nginx/sites-available/keybase\n\
         sudo ln -s /etc/nginx/sites-available/keybase /etc/nginx/sites-enabled/\n\
         nginx -t && sudo systemctl reload nginx\n```\n"
            .into()
    } else {
        String::new()
    };

    let systemd_section = if cfg.gen_systemd {
        "\n## systemd\n\n```bash\nsudo cp keybase.service /etc/systemd/system/\n\
         sudo systemctl daemon-reload\nsudo systemctl enable --now keybase\n```\n"
            .into()
    } else {
        String::new()
    };

    let readme = format!(
        r#"# KeyBase Server

Self-hosted license key management server.

## Quick Start

{run_section}
On first run, the server will ask you to create an admin account.

## URLs

| | URL |
|---|---|
| Admin panel | http://{host}:{port}/admin |
| API base    | http://{host}:{port}/api/v1 |
| Verify key  | POST http://{host}:{port}/api/v1/verify |
{docker_section}{nginx_section}{systemd_section}
## API Quick Reference

```http
POST /api/v1/verify
Content-Type: application/json

{{ "app_id": "default", "key": "XXXX-XXXX", "hwid": "...", "version": "1.0.0" }}
```

## Files

| File | Purpose |
|---|---|
| `config.yml` | Server configuration |
| `.env` | Runtime environment overrides and admin credentials |
| `.env.example` | Environment variable reference |
| `data/` | SQLite database and runtime data |
| `backups/` | Automatic backups |
{run_files}{docker_files}{nginx_files}{systemd_files}
"#,
        host = host,
        port = port,
        run_section = run_section,
        run_files = run_files,
        docker_section = docker_section,
        nginx_section = nginx_section,
        systemd_section = systemd_section,
        docker_files = if cfg.gen_docker {
            "| `Dockerfile` / `docker-compose.yml` | Docker deployment |\n"
        } else {
            ""
        },
        nginx_files = if cfg.gen_nginx {
            "| `nginx.conf` | NGINX reverse proxy config |\n"
        } else {
            ""
        },
        systemd_files = if cfg.gen_systemd {
            "| `keybase.service` | systemd service unit |\n"
        } else {
            ""
        },
    );

    fs::write(dir.join("README.md"), readme)?;
    Ok(())
}

// ── Install log ───────────────────────────────────────────────────────────────

pub fn save_install_log(dir: &Path, log: &[String], elapsed_secs: f64) -> Result<()> {
    use chrono::Local;
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut out =
        format!("KeyBase Builder — Install Log\nDate: {ts}\nDuration: {elapsed_secs:.1}s\n");
    out.push_str(&"─".repeat(60));
    out.push('\n');
    for line in log {
        out.push_str(line);
        out.push('\n');
    }
    fs::write(dir.join("install.log"), out)?;
    Ok(())
}
