use std::process::Command;

#[derive(Clone, Default)]
pub struct SysInfo {
    pub os_name: String,
    pub arch: String,
    pub python_path: Option<String>,
    pub python_version: Option<String>,
    pub pip_ok: bool,
    pub disk_free_mb: u64,
    pub python_ok: bool, // version >= 3.10
}

#[derive(Clone)]
pub struct CheckItem {
    pub label: String,
    pub value: String,
    pub status: CheckStatus,
}

#[derive(Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl SysInfo {
    pub fn detect() -> Self {
        let mut info = SysInfo {
            os_name: os_name(),
            arch: arch_name(),
            disk_free_mb: disk_free(),
            ..Default::default()
        };
        detect_python(&mut info);
        info
    }

    /// True only if everything required is present (Python ≥ 3.10).
    pub fn required_ok(&self) -> bool {
        self.python_ok && self.pip_ok
    }

    pub fn checks(&self) -> Vec<CheckItem> {
        let mut v = vec![];

        v.push(CheckItem {
            label: "Operating system".into(),
            value: self.os_name.clone(),
            status: CheckStatus::Ok,
        });

        v.push(CheckItem {
            label: "Architecture".into(),
            value: self.arch.clone(),
            status: CheckStatus::Ok,
        });

        v.push(CheckItem {
            label: "Python (≥ 3.10)".into(),
            value: self
                .python_version
                .clone()
                .unwrap_or_else(|| "not found".into()),
            status: if self.python_ok {
                CheckStatus::Ok
            } else if self.python_version.is_some() {
                CheckStatus::Fail
            } else {
                CheckStatus::Fail
            },
        });

        v.push(CheckItem {
            label: "pip".into(),
            value: if self.pip_ok {
                "available".into()
            } else {
                "not found".into()
            },
            status: if self.pip_ok {
                CheckStatus::Ok
            } else {
                CheckStatus::Fail
            },
        });

        let disk_status = if self.disk_free_mb > 500 {
            CheckStatus::Ok
        } else if self.disk_free_mb > 100 {
            CheckStatus::Warn
        } else {
            CheckStatus::Fail
        };
        v.push(CheckItem {
            label: "Free disk space".into(),
            value: format!("{:.1} GB", self.disk_free_mb as f64 / 1024.0),
            status: disk_status,
        });

        v
    }
}

// ── Detection helpers ─────────────────────────────────────────────────────────

fn os_name() -> String {
    #[cfg(target_os = "windows")]
    {
        format!("Windows {}", windows_version())
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(o) = std::fs::read_to_string("/etc/os-release") {
            for line in o.lines() {
                if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                    return rest.trim_matches('"').to_string();
                }
            }
        }
        "Linux".into()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        std::env::consts::OS.to_string()
    }
}

fn arch_name() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "x64".into(),
        "aarch64" => "ARM64".into(),
        a => a.to_string(),
    }
}

#[cfg(target_os = "windows")]
fn windows_version() -> String {
    let out = Command::new("cmd")
        .args(["/C", "ver"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    // "Microsoft Windows [Version 10.0.19045.4291]"
    if let Some(start) = out.find("Version ") {
        let rest = &out[start + 8..];
        if let Some(end) = rest.find(']') {
            return rest[..end].trim().to_string();
        }
    }
    out.trim().to_string()
}

fn detect_python(info: &mut SysInfo) {
    let candidates = if cfg!(windows) {
        vec!["python", "python3", "py"]
    } else {
        vec!["python3", "python"]
    };

    for candidate in candidates {
        if let Ok(path) = which::which(candidate) {
            let path_str = path.to_string_lossy().to_string();
            // Get version
            if let Ok(out) = Command::new(&path_str).arg("--version").output() {
                let raw = String::from_utf8_lossy(&out.stdout).to_string()
                    + &String::from_utf8_lossy(&out.stderr);
                // "Python 3.11.4"
                if let Some(ver) = raw.strip_prefix("Python ") {
                    let ver = ver.trim().to_string();
                    let ok = ver_at_least(&ver, 3, 10);
                    info.python_version = Some(ver);
                    info.python_path = Some(path_str.clone());
                    info.python_ok = ok;
                    // Check pip
                    info.pip_ok = Command::new(&path_str)
                        .args(["-m", "pip", "--version"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    return;
                }
            }
        }
    }
}

fn ver_at_least(ver: &str, major: u32, minor: u32) -> bool {
    let parts: Vec<u32> = ver.split('.').filter_map(|s| s.parse().ok()).collect();
    match (parts.first(), parts.get(1)) {
        (Some(&mj), Some(&mn)) => mj > major || (mj == major && mn >= minor),
        _ => false,
    }
}

fn disk_free() -> u64 {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell for simplicity
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-PSDrive C | Select-Object -ExpandProperty Free)",
            ])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        out.trim().parse::<u64>().unwrap_or(0) / 1024 / 1024
    }
    #[cfg(not(target_os = "windows"))]
    {
        let out = Command::new("df")
            .args(["-m", "/"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        out.lines()
            .nth(1)
            .and_then(|l| l.split_whitespace().nth(3))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    }
}
