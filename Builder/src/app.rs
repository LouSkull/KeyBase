#![allow(dead_code)]
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{collections::VecDeque, sync::mpsc, thread, time::Instant};

use crate::{
    config_gen,
    i18n::{self, Lang, Strings},
    install::{self, InstallMsg, InstallStep},
    platform::SysInfo,
    selftest::{self, TestMsg, TestResult},
    wizard::{
        generate_secret, BuildConfig, DbBackend, FieldId, InstallMode, LogLevel, TargetOs,
        WizardState,
    },
};

// ── Phase ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Welcome,
    SysCheck,
    Wizard,
    Confirm,
    Installing,
    SelfTest,
    Done,
    Error,
}

// ── Install progress ──────────────────────────────────────────────────────────

pub const TOTAL_STEPS: usize = 6; // Download, Extract, Venv, Pip, Config, ExtraFiles

#[derive(Default)]
pub struct InstallState {
    pub step: Option<InstallStep>,
    pub done: u64,
    pub total: u64,
    pub steps_done: Vec<InstallStep>,
    pub log: VecDeque<String>,
}

impl InstallState {
    pub fn push_log(&mut self, s: String) {
        self.log.push_back(s);
        while self.log.len() > 300 {
            self.log.pop_front();
        }
    }

    pub fn overall_progress(&self) -> f64 {
        let completed = self.steps_done.len() as f64;
        let partial = if self.total > 0 {
            self.done as f64 / self.total as f64
        } else {
            0.0
        };
        ((completed + partial) / TOTAL_STEPS as f64).clamp(0.0, 1.0)
    }
}

// ── App ───────────────────────────────────────────────────────────────────────

pub struct App {
    pub phase: Phase,
    pub should_quit: bool,
    pub sysinfo: Option<SysInfo>,
    pub wizard: WizardState,
    pub config: BuildConfig,
    pub install: InstallState,
    pub test_log: VecDeque<String>,
    pub test_result: Option<TestResult>,
    pub error_msg: String,
    pub build_start: Option<Instant>,
    pub build_elapsed: f64, // seconds
    pub generated_files: Vec<String>,

    install_rx: Option<mpsc::Receiver<InstallMsg>>,
    test_rx: Option<mpsc::Receiver<TestMsg>>,
    _install_jh: Option<thread::JoinHandle<()>>,
    _test_jh: Option<thread::JoinHandle<()>>,
}

impl App {
    pub fn new() -> Self {
        let config = BuildConfig::default();
        let wizard = WizardState::from_config(&config);
        Self {
            phase: Phase::Welcome,
            should_quit: false,
            sysinfo: None,
            wizard,
            config,
            install: InstallState::default(),
            test_log: VecDeque::new(),
            test_result: None,
            error_msg: String::new(),
            build_start: None,
            build_elapsed: 0.0,
            generated_files: Vec::new(),
            install_rx: None,
            test_rx: None,
            _install_jh: None,
            _test_jh: None,
        }
    }

    pub fn lang(&self) -> Lang {
        Lang::En
    }

    pub fn strings(&self) -> Strings {
        i18n::strings(self.lang())
    }

    // ── Key handling ─────────────────────────────────────────────────────────

    pub fn handle_key(&mut self, key: KeyEvent) {
        match self.phase {
            Phase::Welcome => self.key_welcome(key),
            Phase::SysCheck => self.key_syscheck(key),
            Phase::Wizard => self.key_wizard(key),
            Phase::Confirm => self.key_confirm(key),
            Phase::Done => self.key_done(key),
            Phase::Error => self.key_error(key),
            Phase::Installing | Phase::SelfTest => {
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    self.should_quit = true;
                }
            }
        }
    }

    fn key_welcome(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.phase = Phase::SysCheck;
                self.sysinfo = Some(SysInfo::detect());
            }
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    fn key_syscheck(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if self.sysinfo.as_ref().map(|s| s.python_ok).unwrap_or(false) {
                    self.phase = Phase::Wizard;
                }
            }
            KeyCode::Esc => self.phase = Phase::Welcome,
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    fn key_wizard(&mut self, key: KeyEvent) {
        let fields = self.wizard.effective_fields();
        let n = fields.len();
        if n == 0 {
            return;
        }
        let fid = fields
            .get(self.wizard.field)
            .copied()
            .unwrap_or(FieldId::Output);

        match key.code {
            KeyCode::Esc if !fid.is_text() => self.phase = Phase::SysCheck,

            KeyCode::Down | KeyCode::Tab => {
                self.wizard.field = (self.wizard.field + 1) % n;
            }
            KeyCode::Up | KeyCode::BackTab => {
                self.wizard.field = (self.wizard.field + n - 1) % n;
            }

            KeyCode::Enter => {
                if fid.is_text() {
                    // Move to next field
                    self.wizard.field = (self.wizard.field + 1) % n;
                } else {
                    self.toggle_or_advance(fid, n);
                }
            }

            KeyCode::Left => {
                if fid.is_text() {
                    self.wizard.ti_mut(fid).move_left();
                } else {
                    self.selector_prev(fid);
                }
            }
            KeyCode::Right => {
                if fid.is_text() {
                    self.wizard.ti_mut(fid).move_right();
                } else {
                    self.selector_next(fid);
                }
            }

            KeyCode::Home => {
                if fid.is_text() {
                    self.wizard.ti_mut(fid).home();
                } else {
                    self.wizard.field = 0;
                }
            }
            KeyCode::End => {
                if fid.is_text() {
                    self.wizard.ti_mut(fid).end();
                } else {
                    self.wizard.field = n - 1;
                }
            }

            KeyCode::PageDown | KeyCode::F(5) => self.go_confirm(),

            KeyCode::F(6) if fid.can_generate() => {
                self.generate_field(fid);
            }
            KeyCode::F(7) if fid.is_secret() => {
                self.toggle_secret_visibility(fid);
            }

            KeyCode::Char(c) if fid.is_text() => {
                self.wizard.ti_mut(fid).handle_char(c);
            }
            KeyCode::Backspace if fid.is_text() => {
                self.wizard.ti_mut(fid).handle_backspace();
            }
            KeyCode::Delete if fid.is_text() => {
                self.wizard.ti_mut(fid).handle_delete();
            }

            KeyCode::Char('q') if !fid.is_text() => self.should_quit = true,
            _ => {}
        }
    }

    fn generate_field(&mut self, fid: FieldId) {
        let value = match fid {
            FieldId::ProvToken => format!("kb-prov-{}", generate_secret(16)),
            FieldId::JwtSecret => generate_secret(32),
            FieldId::AdminPassword => generate_secret(16),
            FieldId::ApiMasterKey => generate_secret(32),
            _ => return,
        };
        self.wizard.ti_mut(fid).set(value);
    }

    fn toggle_secret_visibility(&mut self, fid: FieldId) {
        match fid {
            FieldId::ProvToken => self.wizard.show_prov_token = !self.wizard.show_prov_token,
            FieldId::JwtSecret => self.wizard.show_jwt = !self.wizard.show_jwt,
            FieldId::AdminPassword => {
                self.wizard.show_admin_pass = !self.wizard.show_admin_pass;
            }
            FieldId::ApiMasterKey => self.wizard.show_api_key = !self.wizard.show_api_key,
            _ => {}
        }
    }

    fn toggle_or_advance(&mut self, fid: FieldId, _n: usize) {
        match fid {
            FieldId::InstallMode => {
                self.wizard.install_mode = match self.wizard.install_mode {
                    InstallMode::Fresh => InstallMode::Update,
                    InstallMode::Update => InstallMode::Fresh,
                };
            }
            FieldId::AllowRemoteAdmin => {
                self.wizard.allow_remote_admin = !self.wizard.allow_remote_admin
            }
            FieldId::TrustProxy => self.wizard.trust_proxy = !self.wizard.trust_proxy,
            FieldId::Cloudflare => self.wizard.cloudflare = !self.wizard.cloudflare,
            FieldId::Provisioning => self.wizard.prov_enabled = !self.wizard.prov_enabled,
            FieldId::Debug => self.wizard.debug = !self.wizard.debug,
            FieldId::GenDocker => self.wizard.gen_docker = !self.wizard.gen_docker,
            FieldId::GenNginx => self.wizard.gen_nginx = !self.wizard.gen_nginx,
            FieldId::GenSystemd => self.wizard.gen_systemd = !self.wizard.gen_systemd,
            FieldId::SelfTest => self.wizard.selftest = !self.wizard.selftest,
            _ => {}
        }
        // Advance unless toggling would shrink the field list and push us out of bounds
        let new_n = self.wizard.effective_fields().len();
        self.wizard.field = ((self.wizard.field + 1) % new_n).min(new_n.saturating_sub(1));
    }

    fn selector_prev(&mut self, fid: FieldId) {
        match fid {
            FieldId::InstallMode => {
                let l = InstallMode::all().len();
                self.wizard.install_mode = match self.wizard.install_mode {
                    InstallMode::Fresh => InstallMode::Update,
                    InstallMode::Update => InstallMode::Fresh,
                };
                debug_assert_eq!(l, 2);
            }
            FieldId::Database => {
                let l = DbBackend::all().len();
                self.wizard.db_sel = (self.wizard.db_sel + l - 1) % l;
            }
            FieldId::TargetOs => {
                let l = TargetOs::all().len();
                self.wizard.target_os_sel = (self.wizard.target_os_sel + l - 1) % l;
            }
            FieldId::LogLevel => {
                let l = LogLevel::all().len();
                self.wizard.log_level_sel = (self.wizard.log_level_sel + l - 1) % l;
            }
            fid => self.toggle_or_advance_no_move(fid),
        }
    }

    fn selector_next(&mut self, fid: FieldId) {
        match fid {
            FieldId::InstallMode => {
                let l = InstallMode::all().len();
                self.wizard.install_mode = match self.wizard.install_mode {
                    InstallMode::Fresh => InstallMode::Update,
                    InstallMode::Update => InstallMode::Fresh,
                };
                debug_assert_eq!(l, 2);
            }
            FieldId::Database => {
                let l = DbBackend::all().len();
                self.wizard.db_sel = (self.wizard.db_sel + 1) % l;
            }
            FieldId::TargetOs => {
                let l = TargetOs::all().len();
                self.wizard.target_os_sel = (self.wizard.target_os_sel + 1) % l;
            }
            FieldId::LogLevel => {
                let l = LogLevel::all().len();
                self.wizard.log_level_sel = (self.wizard.log_level_sel + 1) % l;
            }
            fid => self.toggle_or_advance_no_move(fid),
        }
    }

    fn toggle_or_advance_no_move(&mut self, fid: FieldId) {
        match fid {
            FieldId::InstallMode => {
                self.wizard.install_mode = match self.wizard.install_mode {
                    InstallMode::Fresh => InstallMode::Update,
                    InstallMode::Update => InstallMode::Fresh,
                }
            }
            FieldId::AllowRemoteAdmin => {
                self.wizard.allow_remote_admin = !self.wizard.allow_remote_admin
            }
            FieldId::TrustProxy => self.wizard.trust_proxy = !self.wizard.trust_proxy,
            FieldId::Cloudflare => self.wizard.cloudflare = !self.wizard.cloudflare,
            FieldId::Provisioning => self.wizard.prov_enabled = !self.wizard.prov_enabled,
            FieldId::Debug => self.wizard.debug = !self.wizard.debug,
            FieldId::GenDocker => self.wizard.gen_docker = !self.wizard.gen_docker,
            FieldId::GenNginx => self.wizard.gen_nginx = !self.wizard.gen_nginx,
            FieldId::GenSystemd => self.wizard.gen_systemd = !self.wizard.gen_systemd,
            FieldId::SelfTest => self.wizard.selftest = !self.wizard.selftest,
            _ => {}
        }
    }

    fn go_confirm(&mut self) {
        let cfg = self.wizard.to_config();
        if matches!(cfg.install_mode, InstallMode::Update)
            && !cfg.output_path().join("config.yml").exists()
        {
            self.error_msg =
                "Update mode did not find an existing config.yml. Switch to Fresh install or point the builder to a real existing server directory.".into();
            self.phase = Phase::Error;
            return;
        }
        if cfg.prov_enabled && cfg.prov_token.trim().is_empty() {
            self.error_msg =
                "Provisioning API is enabled, so the Provisioning token cannot be empty. Type one or press F6 to generate it.".into();
            self.phase = Phase::Error;
            return;
        }
        self.config = cfg;
        self.phase = Phase::Confirm;
    }

    fn key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => self.start_install(),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => self.phase = Phase::Wizard,
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    fn key_done(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('o') | KeyCode::Char('O') => self.open_output_folder(),
            _ => {}
        }
    }

    fn key_error(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Enter => self.phase = Phase::Wizard,
            _ => {}
        }
    }

    // ── Install ───────────────────────────────────────────────────────────────

    pub fn start_install(&mut self) {
        self.phase = Phase::Installing;
        self.install = InstallState::default();
        self.build_start = Some(Instant::now());

        let cfg = self.config.clone();
        let python = self
            .sysinfo
            .as_ref()
            .and_then(|s| s.python_path.clone())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    "py".into()
                } else {
                    "python3".into()
                }
            });
        let (jh, rx) = install::spawn_install(cfg, python);
        self._install_jh = Some(jh);
        self.install_rx = Some(rx);
    }

    fn start_selftest(&mut self) {
        self.phase = Phase::SelfTest;
        self.test_log.clear();
        self.test_result = None;

        let dir = self.config.output_path();
        let port = self.config.port_u16();
        let (jh, rx) = selftest::spawn_selftest(dir, port);
        self._test_jh = Some(jh);
        self.test_rx = Some(rx);
    }

    // ── Drain channels ────────────────────────────────────────────────────────

    pub fn drain_progress(&mut self) {
        self.drain_install();
        self.drain_test();
    }

    fn drain_install(&mut self) {
        let msgs: Vec<_> = if let Some(rx) = &self.install_rx {
            rx.try_iter().collect()
        } else {
            return;
        };

        for msg in msgs {
            match msg {
                InstallMsg::Log(s) => self.install.push_log(s),
                InstallMsg::Progress { step, done, total } => {
                    self.install.step = Some(step);
                    self.install.done = done;
                    self.install.total = total;
                }
                InstallMsg::StepDone(step) => {
                    self.install.steps_done.push(step);
                    self.install.step = None;
                    self.install.done = 0;
                    self.install.total = 0;
                }
                InstallMsg::GeneratedFile(f) => self.generated_files.push(f),
                InstallMsg::Error(e) => {
                    self.install_rx = None;
                    self.error_msg = e;
                    self.phase = Phase::Error;
                    return;
                }
                InstallMsg::Done => {
                    self.install_rx = None;
                    if let Some(t) = self.build_start {
                        self.build_elapsed = t.elapsed().as_secs_f64();
                    }
                    // Save log
                    let log: Vec<String> = self.install.log.iter().cloned().collect();
                    let dir = self.config.output_path();
                    let elapsed = self.build_elapsed;
                    let _ = config_gen::save_install_log(&dir, &log, elapsed);

                    if self.config.selftest {
                        self.start_selftest();
                    } else {
                        self.phase = Phase::Done;
                    }
                    return;
                }
            }
        }
    }

    fn drain_test(&mut self) {
        let msgs: Vec<_> = if let Some(rx) = &self.test_rx {
            rx.try_iter().collect()
        } else {
            return;
        };

        for msg in msgs {
            match msg {
                TestMsg::Log(s) => {
                    self.test_log.push_back(s);
                    while self.test_log.len() > 60 {
                        self.test_log.pop_front();
                    }
                }
                TestMsg::Done(r) => {
                    self.test_result = Some(r);
                    self.test_rx = None;
                    self.phase = Phase::Done;
                    return;
                }
            }
        }
    }

    // ── Misc ─────────────────────────────────────────────────────────────────

    pub fn print_summary(&self) {
        let port = self.config.port_u16();
        println!();
        println!("Installation complete: {}", self.config.output_dir);
        println!("Server URL:   http://{}:{}", self.config.host, port);
        println!("Admin panel:  http://{}:{}/admin", self.config.host, port);
        if self.build_elapsed > 0.0 {
            println!("Build time:   {:.1}s", self.build_elapsed);
        }
    }

    pub fn open_output_folder_pub(&self) {
        self.open_output_folder();
    }

    fn open_output_folder(&self) {
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("explorer")
                .arg(&self.config.output_dir)
                .spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open")
                .arg(&self.config.output_dir)
                .spawn();
        }
    }
}
