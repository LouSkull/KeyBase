use std::{cmp::Ordering, collections::BTreeSet, process::Command};

#[cfg(windows)]
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Default)]
pub struct SysInfo {
    pub os_name: String,
    pub arch: String,
    pub python_path: Option<String>,
    pub python_version: Option<String>,
    pub pip_ok: bool,
    pub disk_free_mb: u64,
    pub elevated: bool,
    pub elevation_status: String,
    pub elevation_hint: String,
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
        let (elevated, elevation_status, elevation_hint) = detect_elevation();
        info.elevated = elevated;
        info.elevation_status = elevation_status;
        info.elevation_hint = elevation_hint;
        detect_python(&mut info);
        info
    }

    /// True only if everything required is present (Python ≥ 3.10).
    pub fn required_ok(&self) -> bool {
        self.python_ok && self.pip_ok && self.elevated
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

        v.push(CheckItem {
            label: "Privileges".into(),
            value: self.elevation_status.clone(),
            status: if self.elevated {
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

pub fn launch_elevation_error() -> Option<String> {
    if is_elevated() {
        return None;
    }

    Some(if cfg!(windows) {
        "Key Base Builder on Windows must be started with Administrator rights.\nRight-click the EXE and choose \"Run as administrator\".".into()
    } else {
        "Key Base Builder on Linux must be started with sudo/root privileges.\nExample: sudo ./keybase-builder-linux".into()
    })
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

fn detect_elevation() -> (bool, String, String) {
    let elevated = is_elevated();
    if cfg!(windows) {
        let status = if elevated {
            "running as Administrator"
        } else {
            "not elevated - restart with Run as administrator"
        };
        let hint = "Windows installs are blocked unless the builder is running as Administrator.";
        (elevated, status.into(), hint.into())
    } else {
        let status = if elevated {
            "running with sudo/root"
        } else {
            "not elevated - relaunch with sudo"
        };
        let hint = "Linux installs are blocked unless the builder is launched with sudo/root.";
        (elevated, status.into(), hint.into())
    }
}

fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows_is_elevated()
    }
    #[cfg(not(windows))]
    {
        unix_is_elevated()
    }
}

#[cfg(windows)]
fn windows_is_elevated() -> bool {
    let script = "[bool](([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))";
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn unix_is_elevated() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|uid| uid.trim().parse::<u32>().ok())
        == Some(0)
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

#[derive(Clone)]
struct PythonProbe {
    exe: String,
    version: String,
    version_key: (u32, u32, u32),
    pip_ok: bool,
}

fn detect_python(info: &mut SysInfo) {
    let mut best: Option<PythonProbe> = None;
    let mut seen = BTreeSet::new();

    for candidate in discover_python_candidates() {
        let key = candidate_key(&candidate);
        if !seen.insert(key) {
            continue;
        }

        if let Some(probe) = probe_python(&candidate) {
            if best
                .as_ref()
                .map(|current| python_probe_better(&probe, current))
                .unwrap_or(true)
            {
                best = Some(probe);
            }
        }
    }

    if let Some(best) = best {
        info.python_version = Some(best.version);
        info.python_path = Some(best.exe);
        info.python_ok = version_tuple_at_least(best.version_key, 3, 10);
        info.pip_ok = best.pip_ok;
    }
}

fn discover_python_candidates() -> Vec<String> {
    let mut out = Vec::new();

    let names: &[&str] = if cfg!(windows) {
        &["python", "python3", "py"]
    } else {
        &["python3", "python"]
    };

    for name in names {
        add_candidate(&mut out, name.to_string());
        if let Ok(path) = which::which(name) {
            add_candidate(&mut out, path.to_string_lossy().to_string());
        }
    }

    #[cfg(windows)]
    {
        for path in windows_launcher_python_paths() {
            add_candidate(&mut out, path);
        }
        for path in windows_common_python_paths() {
            add_candidate(&mut out, path);
        }
    }

    out
}

fn probe_python(exe: &str) -> Option<PythonProbe> {
    let out = Command::new(exe).arg("--version").output().ok()?;
    let raw =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let ver = raw.strip_prefix("Python ")?.trim().to_string();
    let version_key = parse_version_tuple(&ver)?;
    let pip_ok = pip_available(exe);

    Some(PythonProbe {
        exe: exe.to_string(),
        version: ver,
        version_key,
        pip_ok,
    })
}

fn python_probe_better(new: &PythonProbe, current: &PythonProbe) -> bool {
    match new.version_key.cmp(&current.version_key) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => new.pip_ok && !current.pip_ok,
    }
}

fn candidate_key(candidate: &str) -> String {
    if cfg!(windows) {
        candidate.to_ascii_lowercase()
    } else {
        candidate.to_string()
    }
}

fn add_candidate(list: &mut Vec<String>, candidate: String) {
    if candidate.trim().is_empty() {
        return;
    }
    if !list
        .iter()
        .any(|existing| candidate_key(existing) == candidate_key(&candidate))
    {
        list.push(candidate);
    }
}

fn parse_version_tuple(ver: &str) -> Option<(u32, u32, u32)> {
    let mut parts = ver.split('.');
    let major = parse_version_component(parts.next()?)?;
    let minor = parse_version_component(parts.next()?)?;
    let patch = parse_version_component(parts.next().unwrap_or("0")).unwrap_or(0);
    Some((major, minor, patch))
}

fn parse_version_component(part: &str) -> Option<u32> {
    let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn version_tuple_at_least(ver: (u32, u32, u32), major: u32, minor: u32) -> bool {
    ver.0 > major || (ver.0 == major && ver.1 >= minor)
}

#[cfg(windows)]
fn windows_launcher_python_paths() -> Vec<String> {
    let output = Command::new("py").args(["-0"]).output();
    let Ok(output) = output else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    let raw = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    let mut paths = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let spec = trimmed
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('*');
        if !spec.starts_with('-') {
            continue;
        }

        let launcher_out = Command::new("py")
            .args([spec, "-c", "import sys; print(sys.executable)"])
            .output();
        let Ok(launcher_out) = launcher_out else {
            continue;
        };
        if !launcher_out.status.success() {
            continue;
        }

        let candidate = String::from_utf8_lossy(&launcher_out.stdout)
            .trim()
            .trim_matches('"')
            .to_string();
        let candidate_lc = candidate.to_ascii_lowercase();
        if (candidate_lc.ends_with(r"\python.exe") || candidate_lc.ends_with(r"\python3.exe"))
            && Path::new(&candidate).is_file()
        {
            paths.push(candidate);
        }
    }

    paths
}

#[cfg(windows)]
fn windows_common_python_paths() -> Vec<String> {
    let mut roots = Vec::new();

    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local_app_data).join("Programs"));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        roots.push(PathBuf::from(program_files));
    }
    if let Some(program_files_x86) = std::env::var_os("ProgramFiles(x86)") {
        roots.push(PathBuf::from(program_files_x86));
    }
    if let Some(system_drive) = std::env::var_os("SystemDrive") {
        roots.push(PathBuf::from(format!(
            "{}\\",
            system_drive.to_string_lossy()
        )));
    }

    let mut out = Vec::new();
    for root in roots {
        collect_python_executables(&root, 0, &mut out);
    }
    out
}

#[cfg(windows)]
fn collect_python_executables(dir: &Path, depth: usize, out: &mut Vec<String>) {
    if depth > 4 {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if is_python_executable(&path) {
                out.push(path.to_string_lossy().to_string());
            }
            continue;
        }

        if !path.is_dir() {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if is_relevant_python_dir(&name) {
            collect_python_executables(&path, depth + 1, out);
        }
    }
}

#[cfg(windows)]
fn is_relevant_python_dir(name: &str) -> bool {
    name.contains("python")
        || name.contains("anaconda")
        || name.contains("miniconda")
        || name.contains("pypy")
        || name == "programs"
}

#[cfg(windows)]
fn is_python_executable(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(name.as_str(), "python.exe" | "python3.exe")
}

fn pip_available(python_path: &str) -> bool {
    let mut candidates: Vec<(String, Vec<&str>)> = vec![
        (python_path.to_string(), vec!["-m", "pip", "--version"]),
        ("python3".to_string(), vec!["-m", "pip", "--version"]),
        ("python".to_string(), vec!["-m", "pip", "--version"]),
        ("pip3".to_string(), vec!["--version"]),
        ("pip".to_string(), vec!["--version"]),
    ];
    if cfg!(windows) {
        candidates.insert(1, ("py".to_string(), vec!["-m", "pip", "--version"]));
    }

    for (exe, args) in candidates {
        if command_succeeds(&exe, &args) {
            return true;
        }
    }
    false
}

fn command_succeeds(exe: &str, args: &[&str]) -> bool {
    Command::new(exe)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
