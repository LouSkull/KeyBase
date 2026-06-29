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

use crate::{
    config_gen,
    wizard::{BuildConfig, InstallMode},
};

const GITHUB_OWNER: &str = "LouSkull";
const GITHUB_REPO: &str = "KeyBase";
const RELEASES_API_URL: &str = "https://api.github.com/repos/LouSkull/KeyBase/releases?per_page=1";
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

#[derive(Debug)]
struct DownloadedArchive {
    bytes: Vec<u8>,
    final_url: String,
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
    let upgrade_mode = matches!(cfg.install_mode, InstallMode::Update);
    let existing_config = if upgrade_mode && output_dir.join("config.yml").exists() {
        load_existing_config(&output_dir)
    } else {
        None
    };

    if upgrade_mode {
        log(tx, "Update mode selected.");
        if existing_config.is_some() {
            log(
                tx,
                "Runtime config, secrets, backups, and data will be preserved.",
            );
        } else {
            log(
                tx,
                "No existing installation metadata was found — update mode will start from a clean directory.",
            );
        }
    } else {
        log(tx, "Fresh install mode selected.");
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
    let downloaded = download_with_progress(&release_urls, tx)
        .context("Failed to download Server-Portable.zip")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Downloading));

    if upgrade_mode {
        if let Some(existing) = &existing_config {
            let ports = existing_listener_ports(existing, cfg.port_u16());
            log(tx, "Stopping the existing server before updating files…");
            stop_existing_server(&output_dir, &ports, tx)
                .context("Failed to stop the existing Key Base server")?;
        } else {
            log(
                tx,
                "Skipping server stop because no existing install was detected.",
            );
        }
        cleanup_directory(
            &output_dir,
            if existing_config.is_some() {
                &["config.yml", ".env", "data", "backups"]
            } else {
                &[]
            },
        )
        .context("Failed to prepare the update directory")?;
    } else if output_dir.exists() {
        log(
            tx,
            "Cleaning the output directory before creating a fresh build…",
        );
        cleanup_directory(&output_dir, &[]).context("Failed to prepare the output directory")?;
    }

    // ── 2. Extract ────────────────────────────────────────────────────────────
    log(tx, format!("Extracting to {}", output_dir.display()));
    fs::create_dir_all(&output_dir).context("Cannot create output directory")?;
    extract_zip(&downloaded.bytes, &output_dir, tx)
        .context("Failed to extract Server-Portable.zip")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Extracting));

    if let Some(release_version) = release_version_from_url(&downloaded.final_url) {
        if let Err(err) = sync_installed_version(&output_dir, &release_version) {
            log(
                tx,
                format!("Could not stamp installed server version to {release_version}: {err:#}"),
            );
        } else {
            log(
                tx,
                format!("Stamped installed server version to {release_version}."),
            );
        }
    }

    // ── 3. Python venv ────────────────────────────────────────────────────────
    log(tx, "Creating Python virtual environment…");
    progress(tx, InstallStep::Venv, 0, 1);
    let venv_dir = output_dir.join(".venv");
    create_python_venv(&output_dir, &venv_dir, python, tx)
        .context("Failed to create Python venv")?;
    let _ = tx.send(InstallMsg::StepDone(InstallStep::Venv));

    // ── 4. pip install ────────────────────────────────────────────────────────
    log(tx, "Installing Python packages…");
    progress(tx, InstallStep::Pip, 0, 1);
    let venv_py = venv_python(&venv_dir);
    install_python_packages(&output_dir, &venv_dir, python, tx)
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

    config_gen::write_env(&output_dir, cfg).context("write .env.example")?;
    emit_file(tx, ".env.example");

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

    if cfg.target_os.gen_bat() {
        config_gen::write_run_bat(&output_dir, cfg).context("write run.bat")?;
        emit_file(tx, "run.bat");
    }
    if cfg.target_os.gen_sh() {
        config_gen::write_run_sh(&output_dir, cfg).context("write run.sh")?;
        emit_file(tx, "run.sh");
    }

    config_gen::write_readme(&output_dir, cfg).context("write README.md")?;
    emit_file(tx, "README.md");

    if let Some(existing) = &existing_config {
        maybe_migrate_database(&output_dir, cfg, existing, &venv_py, tx)
            .context("database migration failed")?;
    }

    let _ = tx.send(InstallMsg::StepDone(InstallStep::ExtraFiles));

    Ok(())
}

fn install_python_packages(
    output_dir: &Path,
    venv_dir: &Path,
    bootstrap_python: &str,
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<()> {
    let venv_py = venv_python(venv_dir);

    if run_venv_pip_workflow(&venv_py, output_dir, tx).is_ok() {
        return Ok(());
    }

    log(
        tx,
        "pip inside the virtual environment failed. Trying ensurepip bootstrap…",
    );
    if let Err(err) = run_cmd(&venv_py, &["-m", "ensurepip", "--upgrade"], output_dir) {
        log(tx, format!("ensurepip did not help: {err:#}"));
    }

    if run_venv_pip_workflow(&venv_py, output_dir, tx).is_ok() {
        return Ok(());
    }

    log(
        tx,
        "Falling back to alternate pip launchers with --target into the virtual environment…",
    );
    let site_packages = venv_site_packages(&venv_py, output_dir)?;
    let mut errors = match install_requirements_with_external_pip(
        output_dir,
        &site_packages,
        bootstrap_python,
        tx,
    ) {
        Ok(()) => return Ok(()),
        Err(errors) => errors,
    };

    if try_install_linux_pip_package(output_dir, tx) {
        log(
            tx,
            "Python pip package install completed. Retrying external pip fallback…",
        );
        match install_requirements_with_external_pip(
            output_dir,
            &site_packages,
            bootstrap_python,
            tx,
        ) {
            Ok(()) => return Ok(()),
            Err(retry_errors) => {
                errors.extend(retry_errors);
            }
        }
    }

    bail!(
        "pip could not be prepared in the virtual environment.\n{}",
        errors.join("\n")
    )
}

fn install_requirements_with_external_pip(
    output_dir: &Path,
    site_packages: &str,
    bootstrap_python: &str,
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    for (exe, use_module) in pip_fallback_candidates(bootstrap_python) {
        let mut args = Vec::<String>::new();
        if use_module {
            args.extend(["-m", "pip"].iter().map(|s| s.to_string()));
        }
        args.extend(
            [
                "install",
                "--target",
                site_packages,
                "-r",
                "requirements.txt",
                "-q",
            ]
            .iter()
            .map(|s| s.to_string()),
        );

        let label = if use_module {
            format!("{exe} -m pip install --target {}", site_packages)
        } else {
            format!("{exe} install --target {}", site_packages)
        };
        log(tx, format!("Trying {}…", label));
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_cmd(&exe, &arg_refs, output_dir) {
            Ok(()) => {
                log(tx, format!("Package install succeeded via {}.", label));
                return Ok(());
            }
            Err(err) => {
                errors.push(format!("{label}: {err:#}"));
            }
        }
    }

    Err(errors)
}

fn create_python_venv(
    output_dir: &Path,
    venv_dir: &Path,
    python: &str,
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<()> {
    let venv_target = venv_dir.to_string_lossy().to_string();
    let primary_args = vec!["-m".to_string(), "venv".to_string(), venv_target.clone()];
    let primary_refs: Vec<&str> = primary_args.iter().map(String::as_str).collect();

    log(
        tx,
        format!("Creating venv with {} {}", python, primary_args.join(" ")),
    );
    match run_cmd(python, &primary_refs, output_dir) {
        Ok(()) => return Ok(()),
        Err(primary_err) => {
            let primary_text = format!("{primary_err:#}");
            log(tx, format!("Standard venv creation failed: {primary_text}"));

            if let Some(help) = linux_venv_help(python, output_dir, &primary_text) {
                log(tx, help);
            }

            if linux_missing_venv_support(&primary_text) {
                if try_create_venv_without_pip(output_dir, venv_dir, python, tx) {
                    return Ok(());
                }

                if try_install_user_virtualenv(python, output_dir, tx) {
                    log(
                        tx,
                        "User virtualenv install completed. Retrying virtualenv fallback…",
                    );
                } else {
                    log(tx, "Could not install virtualenv with user-level pip.");
                }

                if try_install_linux_venv_package(python, output_dir, tx) {
                    log(
                        tx,
                        "Linux venv package install completed. Retrying standard venv…",
                    );
                    match run_cmd(python, &primary_refs, output_dir) {
                        Ok(()) => return Ok(()),
                        Err(err) => log(
                            tx,
                            format!("Standard venv still failed after package install: {err:#}"),
                        ),
                    }
                }
            }

            log(tx, "Trying virtualenv fallback before giving up…");
            let mut errors = vec![format!(
                "{} {}: {primary_text}",
                python,
                primary_args.join(" ")
            )];

            for (exe, use_module) in virtualenv_fallback_candidates(python) {
                let args: Vec<String> = if use_module {
                    vec!["-m".into(), "virtualenv".into(), venv_target.clone()]
                } else {
                    vec![venv_target.clone()]
                };
                let label = if use_module {
                    format!("{exe} -m virtualenv {venv_target}")
                } else {
                    format!("{exe} {venv_target}")
                };
                log(tx, format!("Trying {label}"));
                let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
                match run_cmd(&exe, &arg_refs, output_dir) {
                    Ok(()) => {
                        log(tx, format!("Virtual environment created via {label}."));
                        return Ok(());
                    }
                    Err(err) => {
                        let err_text = format!("{err:#}");
                        log(tx, format!("{label} failed: {err_text}"));
                        errors.push(format!("{label}: {err_text}"));
                    }
                }
            }

            let mut message = String::from("Unable to create the Python virtual environment.");
            if let Some(help) = linux_venv_help(python, output_dir, &primary_text) {
                message.push_str("\n\n");
                message.push_str(&help);
            }
            message.push_str("\n\n");
            message.push_str(&errors.join("\n\n"));
            bail!(message);
        }
    }
}

fn try_create_venv_without_pip(
    output_dir: &Path,
    venv_dir: &Path,
    python: &str,
    tx: &mpsc::Sender<InstallMsg>,
) -> bool {
    if cfg!(windows) {
        return false;
    }

    let _ = fs::remove_dir_all(venv_dir);
    let venv_target = venv_dir.to_string_lossy().to_string();
    let args = ["-m", "venv", "--without-pip", &venv_target];
    log(
        tx,
        format!(
            "Trying venv without bundled pip: {} {}",
            python,
            args.join(" ")
        ),
    );

    match run_cmd(python, &args, output_dir) {
        Ok(()) => {
            log(
                tx,
                "Virtual environment created without pip. Dependencies will use external pip fallback.",
            );
            true
        }
        Err(err) => {
            log(tx, format!("venv --without-pip failed: {err:#}"));
            false
        }
    }
}

fn linux_missing_venv_support(failure: &str) -> bool {
    if cfg!(windows) {
        return false;
    }
    let lowered = failure.to_ascii_lowercase();
    lowered.contains("ensurepip is not available")
        || lowered.contains("no module named venv")
        || lowered.contains("the virtual environment was not created successfully")
        || lowered.contains("install the python3-venv package")
}

fn try_install_user_virtualenv(python: &str, cwd: &Path, tx: &mpsc::Sender<InstallMsg>) -> bool {
    if cfg!(windows) {
        return false;
    }

    log(
        tx,
        "Trying to install virtualenv with user-level pip as a no-sudo fallback…",
    );
    for (exe, use_module) in pip_fallback_candidates(python) {
        let args: Vec<&str> = if use_module {
            vec!["-m", "pip", "install", "--user", "virtualenv", "-q"]
        } else {
            vec!["install", "--user", "virtualenv", "-q"]
        };
        let label = if use_module {
            format!("{exe} -m pip install --user virtualenv")
        } else {
            format!("{exe} install --user virtualenv")
        };
        log(tx, format!("Trying {label}…"));
        match run_cmd(&exe, &args, cwd) {
            Ok(()) => {
                log(tx, format!("{label} succeeded."));
                return true;
            }
            Err(err) => {
                log(tx, format!("{label} failed: {err:#}"));
            }
        }
    }
    false
}

fn try_install_linux_venv_package(python: &str, cwd: &Path, tx: &mpsc::Sender<InstallMsg>) -> bool {
    if cfg!(windows) {
        return false;
    }

    let commands = linux_venv_install_commands(python, cwd);
    if commands.is_empty() {
        log(
            tx,
            "No supported Linux package manager detected for automatic venv repair.",
        );
        return false;
    }

    log(
        tx,
        "Trying automatic Linux venv package repair with non-interactive sudo/root…",
    );
    for command in commands {
        let pretty = command.pretty();
        log(tx, format!("Trying {pretty}"));
        match run_linux_admin_command(&command.exe, &command.args, cwd) {
            Ok(()) => {
                log(tx, format!("{pretty} succeeded."));
                return true;
            }
            Err(err) => {
                log(tx, format!("{pretty} failed: {err:#}"));
            }
        }
    }
    false
}

fn try_install_linux_pip_package(cwd: &Path, tx: &mpsc::Sender<InstallMsg>) -> bool {
    if cfg!(windows) {
        return false;
    }

    let commands = linux_pip_install_commands();
    if commands.is_empty() {
        log(
            tx,
            "No supported Linux package manager detected for automatic pip repair.",
        );
        return false;
    }

    log(
        tx,
        "Trying automatic Linux pip package repair with non-interactive sudo/root…",
    );
    for command in commands {
        let pretty = command.pretty();
        log(tx, format!("Trying {pretty}"));
        match run_linux_admin_command(&command.exe, &command.args, cwd) {
            Ok(()) => {
                log(tx, format!("{pretty} succeeded."));
                return true;
            }
            Err(err) => {
                log(tx, format!("{pretty} failed: {err:#}"));
            }
        }
    }
    false
}

#[derive(Clone)]
struct LinuxInstallCommand {
    exe: String,
    args: Vec<String>,
}

impl LinuxInstallCommand {
    fn new(exe: &str, args: &[String]) -> Self {
        Self {
            exe: exe.to_string(),
            args: args.to_vec(),
        }
    }

    fn pretty(&self) -> String {
        format!("{} {}", self.exe, self.args.join(" "))
    }
}

fn linux_venv_install_commands(python: &str, cwd: &Path) -> Vec<LinuxInstallCommand> {
    if cfg!(windows) {
        return Vec::new();
    }

    let version_pkg =
        python_major_minor(python, cwd).map(|version| format!("python{version}-venv"));
    let mut commands = Vec::new();

    if command_available("apt-get") {
        if let Some(pkg) = version_pkg {
            commands.push(LinuxInstallCommand::new(
                "apt-get",
                &["install".into(), "-y".into(), pkg],
            ));
        }
        commands.push(LinuxInstallCommand::new(
            "apt-get",
            &["install".into(), "-y".into(), "python3-venv".into()],
        ));
    } else if command_available("dnf") {
        commands.push(LinuxInstallCommand::new(
            "dnf",
            &[
                "install".into(),
                "-y".into(),
                "python3-virtualenv".into(),
                "python3-pip".into(),
            ],
        ));
    } else if command_available("yum") {
        commands.push(LinuxInstallCommand::new(
            "yum",
            &[
                "install".into(),
                "-y".into(),
                "python3-virtualenv".into(),
                "python3-pip".into(),
            ],
        ));
    } else if command_available("pacman") {
        commands.push(LinuxInstallCommand::new(
            "pacman",
            &[
                "-Sy".into(),
                "--noconfirm".into(),
                "python-virtualenv".into(),
                "python-pip".into(),
            ],
        ));
    } else if command_available("apk") {
        commands.push(LinuxInstallCommand::new(
            "apk",
            &["add".into(), "py3-virtualenv".into(), "py3-pip".into()],
        ));
    } else if command_available("zypper") {
        commands.push(LinuxInstallCommand::new(
            "zypper",
            &[
                "--non-interactive".into(),
                "install".into(),
                "python3-virtualenv".into(),
                "python3-pip".into(),
            ],
        ));
    }

    commands
}

fn linux_pip_install_commands() -> Vec<LinuxInstallCommand> {
    if cfg!(windows) {
        return Vec::new();
    }

    let mut commands = Vec::new();
    if command_available("apt-get") {
        commands.push(LinuxInstallCommand::new(
            "apt-get",
            &["install".into(), "-y".into(), "python3-pip".into()],
        ));
    } else if command_available("dnf") {
        commands.push(LinuxInstallCommand::new(
            "dnf",
            &["install".into(), "-y".into(), "python3-pip".into()],
        ));
    } else if command_available("yum") {
        commands.push(LinuxInstallCommand::new(
            "yum",
            &["install".into(), "-y".into(), "python3-pip".into()],
        ));
    } else if command_available("pacman") {
        commands.push(LinuxInstallCommand::new(
            "pacman",
            &["-Sy".into(), "--noconfirm".into(), "python-pip".into()],
        ));
    } else if command_available("apk") {
        commands.push(LinuxInstallCommand::new(
            "apk",
            &["add".into(), "py3-pip".into()],
        ));
    } else if command_available("zypper") {
        commands.push(LinuxInstallCommand::new(
            "zypper",
            &[
                "--non-interactive".into(),
                "install".into(),
                "python3-pip".into(),
            ],
        ));
    }

    commands
}

fn run_linux_admin_command(exe: &str, args: &[String], cwd: &Path) -> Result<()> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    if running_as_root() {
        return run_cmd(exe, &refs, cwd);
    }
    if !command_available("sudo") {
        bail!("sudo is not available and the builder is not running as root");
    }

    let mut sudo_args = vec!["-n".to_string(), exe.to_string()];
    sudo_args.extend(args.iter().cloned());
    let sudo_refs: Vec<&str> = sudo_args.iter().map(String::as_str).collect();
    run_cmd("sudo", &sudo_refs, cwd).context("sudo non-interactive command failed")
}

fn running_as_root() -> bool {
    if cfg!(windows) {
        return false;
    }
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|uid| uid.trim().parse::<u32>().ok())
        == Some(0)
}

fn command_available(exe: &str) -> bool {
    which::which(exe).is_ok()
}

fn run_venv_pip_workflow(venv_py: &str, cwd: &Path, tx: &mpsc::Sender<InstallMsg>) -> Result<()> {
    run_cmd_logged(
        tx,
        "Upgrading pip inside the virtual environment",
        venv_py,
        &["-m", "pip", "install", "--upgrade", "pip", "-q"],
        cwd,
    )?;
    run_cmd_logged(
        tx,
        "Installing requirements inside the virtual environment",
        venv_py,
        &["-m", "pip", "install", "-r", "requirements.txt", "-q"],
        cwd,
    )?;
    Ok(())
}

fn run_cmd_logged(
    tx: &mpsc::Sender<InstallMsg>,
    label: &str,
    exe: &str,
    args: &[&str],
    cwd: &Path,
) -> Result<()> {
    log(tx, format!("{label}: {exe} {}", args.join(" ")));
    run_cmd(exe, args, cwd).with_context(|| format!("{label} failed"))?;
    Ok(())
}

fn venv_site_packages(venv_python: &str, cwd: &Path) -> Result<String> {
    let output = Command::new(venv_python)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ])
        .current_dir(cwd)
        .output()
        .context("Failed to query virtual environment site-packages path")?;
    if !output.status.success() {
        bail!("Unable to determine virtual environment site-packages path");
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        bail!("Virtual environment site-packages path was empty");
    }
    Ok(path)
}

fn pip_fallback_candidates(bootstrap_python: &str) -> Vec<(String, bool)> {
    let mut items = vec![
        (bootstrap_python.to_string(), true),
        ("python3".to_string(), true),
        ("python".to_string(), true),
        ("pip3".to_string(), false),
        ("pip".to_string(), false),
    ];
    if cfg!(windows) {
        items.insert(1, ("py".to_string(), true));
    }
    let mut deduped = Vec::new();
    for item in items.drain(..) {
        if !deduped.iter().any(|(existing, _)| existing == &item.0) {
            deduped.push(item);
        }
    }
    deduped
}

fn virtualenv_fallback_candidates(bootstrap_python: &str) -> Vec<(String, bool)> {
    let mut items = vec![
        (bootstrap_python.to_string(), true),
        ("python3".to_string(), true),
        ("python".to_string(), true),
        ("virtualenv".to_string(), false),
    ];
    if cfg!(windows) {
        items.insert(1, ("py".to_string(), true));
    }
    let mut deduped = Vec::new();
    for item in items.drain(..) {
        if !deduped.iter().any(|(existing, _)| existing == &item.0) {
            deduped.push(item);
        }
    }
    deduped
}

fn linux_venv_help(python: &str, cwd: &Path, failure: &str) -> Option<String> {
    if cfg!(windows) {
        return None;
    }
    if !linux_missing_venv_support(failure) {
        return None;
    }

    let mut lines = vec![
        "This Linux system is missing Python virtual environment support.".to_string(),
        "The builder will try --without-pip, user-level virtualenv, and non-interactive distro repair automatically.".to_string(),
        "If that fails, run one of these commands and start the builder again:".to_string(),
        "Debian/Ubuntu: sudo apt-get install -y python3-venv".to_string(),
        "If pip is missing too: sudo apt-get install -y python3-pip".to_string(),
        "Alternative fallback: python3 -m pip install --user virtualenv".to_string(),
    ];
    if let Some(version) = python_major_minor(python, cwd) {
        let line =
            format!("Version-specific Debian/Ubuntu: sudo apt-get install -y python{version}-venv");
        lines.insert(3, line);
    }
    Some(lines.join("\n"))
}

fn python_major_minor(python: &str, cwd: &Path) -> Option<String> {
    let output = Command::new(python)
        .args([
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ])
        .current_dir(cwd)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
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

fn cleanup_directory(output_dir: &Path, keep: &[&str]) -> Result<()> {
    if !output_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if keep.iter().any(|wanted| wanted == &name.as_ref()) {
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

    if let Some((tag, release_urls)) = release_urls_from_api(&client, RELEASES_API_URL) {
        tag_name = tag_name.or(tag);
        push_unique_many(&mut urls, release_urls);
    }

    if urls.is_empty() {
        if let Some((tag, release_urls)) = release_urls_from_api(&client, RELEASE_API_URL) {
            tag_name = tag_name.or(tag);
            push_unique_many(&mut urls, release_urls);
        }
    }

    push_unique_many(&mut urls, fallback_release_urls(tag_name.as_deref()));
    urls
}

fn release_urls_from_api(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Option<(Option<String>, Vec<String>)> {
    let resp = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .ok()?
        .error_for_status()
        .ok()?;
    let text = resp.text().ok()?;
    let release = first_json_object_slice(&text).unwrap_or(text.as_str());
    let tag_name = extract_json_string_field(release, "tag_name")
        .or_else(|| extract_json_string_field(release, "name"))
        .map(|s| s.trim().trim_start_matches('v').to_string())
        .filter(|s| !s.is_empty());

    let mut preferred = Vec::new();
    let mut alternates = Vec::new();
    for url in extract_json_string_values(release, "browser_download_url") {
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

    let mut result = Vec::new();
    push_unique_many(&mut result, preferred);
    push_unique_many(&mut result, alternates);
    Some((tag_name, result))
}

fn first_json_object_slice(input: &str) -> Option<&str> {
    let start = input.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for (offset, ch) in input[start..].char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => escape = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = start + offset + ch.len_utf8();
                    return Some(&input[start..end]);
                }
            }
            _ => {}
        }
    }
    None
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

fn download_with_progress(
    urls: &[String],
    tx: &mpsc::Sender<InstallMsg>,
) -> Result<DownloadedArchive> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("keybase-builder/0.1")
        .build()?;

    let mut errors = Vec::new();
    for (idx, url) in urls.iter().enumerate() {
        log(tx, format!("Connecting to: {}", url));
        match download_single(&client, url, tx) {
            Ok(archive) => return Ok(archive),
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
) -> Result<DownloadedArchive> {
    let mut resp = client.get(url).send()?.error_for_status()?;
    let final_url = resp.url().to_string();
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
    Ok(DownloadedArchive {
        bytes: buf,
        final_url,
    })
}

fn release_version_from_url(url: &str) -> Option<String> {
    let needle = "/releases/download/";
    let start = url.find(needle)? + needle.len();
    let rest = &url[start..];
    let mut parts = rest.splitn(2, '/');
    let tag = parts.next()?.trim();
    if tag.is_empty() || tag.eq_ignore_ascii_case("latest") {
        return None;
    }
    Some(tag.trim_start_matches('v').to_string())
}

fn sync_installed_version(output_dir: &Path, version: &str) -> Result<()> {
    let init_path = output_dir.join("keybase").join("__init__.py");
    if !init_path.exists() {
        return Ok(());
    }

    let raw = fs::read_to_string(&init_path)
        .with_context(|| format!("failed to read {}", init_path.display()))?;
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in raw.lines() {
        if line.trim_start().starts_with("__version__") {
            lines.push(format!("__version__ = \"{}\"", version));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !replaced {
        bail!("package version line was not found");
    }

    let mut out = lines.join("\n");
    out.push('\n');
    fs::write(&init_path, out)
        .with_context(|| format!("failed to write {}", init_path.display()))?;
    Ok(())
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
    let output = std::process::Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("Failed to launch `{}`", exe))?;
    if !output.status.success() {
        let stdout = sanitize_command_output(&output.stdout);
        let stderr = sanitize_command_output(&output.stderr);
        let mut msg = format!(
            "`{} {}` exited with exit status: {}",
            exe,
            args.join(" "),
            output.status
        );
        if !stderr.is_empty() {
            msg.push_str("\n\nstderr:\n");
            msg.push_str(&stderr);
        }
        if !stdout.is_empty() {
            msg.push_str("\n\nstdout:\n");
            msg.push_str(&stdout);
        }
        bail!(msg);
    }
    Ok(())
}

fn sanitize_command_output(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).replace('\0', "");
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let max_chars = 4000usize;
    let mut out = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("\n… output truncated …");
            break;
        }
        out.push(ch);
    }
    out
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
