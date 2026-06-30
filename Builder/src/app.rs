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
        auto_find_installs, generate_secret, has_keybase_install, BuildConfig, DbBackend, FieldId,
        InstallMode, LogLevel, WizardState,
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
    pub cancel_requested: bool,
    pub install_cancelled: bool,

    install_rx: Option<mpsc::Receiver<InstallMsg>>,
    test_rx: Option<mpsc::Receiver<TestMsg>>,
    active_cancel: Option<install::CancelFlag>,
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
            cancel_requested: false,
            install_cancelled: false,
            install_rx: None,
            test_rx: None,
            active_cancel: None,
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
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if self.is_busy() {
                self.request_cancel();
            } else {
                self.should_quit = true;
            }
            return;
        }

        match self.phase {
            Phase::Welcome => self.key_welcome(key),
            Phase::SysCheck => self.key_syscheck(key),
            Phase::Wizard => self.key_wizard(key),
            Phase::Confirm => self.key_confirm(key),
            Phase::Done => self.key_done(key),
            Phase::Error => self.key_error(key),
            Phase::Installing | Phase::SelfTest => match key.code {
                KeyCode::Esc | KeyCode::Char('c') | KeyCode::Char('q') => {
                    self.request_cancel();
                }
                _ => {}
            },
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
                if self
                    .sysinfo
                    .as_ref()
                    .map(|s| s.required_ok())
                    .unwrap_or(false)
                {
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

            KeyCode::F(8) => {
                self.auto_populate_path_for_mode();
            }

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
            FieldId::JwtSecret | FieldId::SecNewJwt => generate_secret(32),
            FieldId::AdminPassword | FieldId::SecNewPwd => generate_secret(12),
            FieldId::ApiMasterKey | FieldId::SecNewApi => generate_secret(20),
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
            FieldId::SecNewPwd => self.wizard.sec_show_new_pwd = !self.wizard.sec_show_new_pwd,
            FieldId::SecNewJwt => self.wizard.sec_show_new_jwt = !self.wizard.sec_show_new_jwt,
            FieldId::SecNewApi => self.wizard.sec_show_new_api = !self.wizard.sec_show_new_api,
            _ => {}
        }
    }

    fn toggle_or_advance(&mut self, fid: FieldId, _n: usize) {
        match fid {
            FieldId::InstallMode => {
                self.wizard.install_mode = match self.wizard.install_mode {
                    InstallMode::Fresh => InstallMode::Update,
                    InstallMode::Update => InstallMode::Uninstall,
                    InstallMode::Uninstall => InstallMode::Fresh,
                };
                self.auto_populate_path_for_mode();
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
            FieldId::SecResetPwd => self.wizard.sec_reset_pwd = !self.wizard.sec_reset_pwd,
            FieldId::SecResetJwt => self.wizard.sec_reset_jwt = !self.wizard.sec_reset_jwt,
            FieldId::SecResetApi => self.wizard.sec_reset_api = !self.wizard.sec_reset_api,
            FieldId::SecChangeUsername => {
                self.wizard.sec_change_username = !self.wizard.sec_change_username
            }
            _ => {}
        }
        // Advance unless toggling would shrink the field list and push us out of bounds
        let new_n = self.wizard.effective_fields().len();
        self.wizard.field = ((self.wizard.field + 1) % new_n).min(new_n.saturating_sub(1));
    }

    fn selector_prev(&mut self, fid: FieldId) {
        match fid {
            FieldId::InstallMode => {
                let modes = InstallMode::all();
                let cur = modes
                    .iter()
                    .position(|&m| m == self.wizard.install_mode)
                    .unwrap_or(0);
                let prev = if cur == 0 { modes.len() - 1 } else { cur - 1 };
                self.wizard.install_mode = modes[prev];
                self.auto_populate_path_for_mode();
            }
            FieldId::Database => {
                let l = DbBackend::all().len();
                self.wizard.db_sel = (self.wizard.db_sel + l - 1) % l;
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
                let modes = InstallMode::all();
                let cur = modes
                    .iter()
                    .position(|&m| m == self.wizard.install_mode)
                    .unwrap_or(0);
                self.wizard.install_mode = modes[(cur + 1) % modes.len()];
                self.auto_populate_path_for_mode();
            }
            FieldId::Database => {
                let l = DbBackend::all().len();
                self.wizard.db_sel = (self.wizard.db_sel + 1) % l;
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
                let modes = InstallMode::all();
                let cur = modes
                    .iter()
                    .position(|&m| m == self.wizard.install_mode)
                    .unwrap_or(0);
                self.wizard.install_mode = modes[(cur + 1) % modes.len()];
                self.auto_populate_path_for_mode();
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
            FieldId::SecResetPwd => self.wizard.sec_reset_pwd = !self.wizard.sec_reset_pwd,
            FieldId::SecResetJwt => self.wizard.sec_reset_jwt = !self.wizard.sec_reset_jwt,
            FieldId::SecResetApi => self.wizard.sec_reset_api = !self.wizard.sec_reset_api,
            FieldId::SecChangeUsername => {
                self.wizard.sec_change_username = !self.wizard.sec_change_username
            }
            _ => {}
        }
    }

    fn auto_populate_path_for_mode(&mut self) {
        let found = auto_find_installs();
        self.wizard.autofind_count = Some(found.len());
        if let Some(path) = found.into_iter().next() {
            self.wizard.f_output.set(path);
            self.wizard.output_autofill_gen =
                self.wizard.output_autofill_gen.wrapping_add(1);
        } else if self.wizard.install_mode == InstallMode::Fresh
            && self.wizard.f_output.buf.is_empty()
        {
            // Suggest a platform-appropriate default install path
            let default = if cfg!(windows) {
                "C:\\KeyBase".to_string()
            } else {
                "/opt/keybase".to_string()
            };
            self.wizard.f_output.set(default);
            self.wizard.output_autofill_gen =
                self.wizard.output_autofill_gen.wrapping_add(1);
        }
    }

    fn go_confirm(&mut self) {
        let cfg = self.wizard.to_config();
        match cfg.install_mode {
            InstallMode::Update => {
                if !cfg.output_path().join("config.yml").exists() {
                    self.error_msg =
                        "Update mode did not find an existing config.yml. Point the builder to a real existing server directory.".into();
                    self.phase = Phase::Error;
                    return;
                }
                let ws = &self.wizard;
                if ws.sec_reset_pwd && ws.f_sec_pwd.buf.len() < 8 {
                    self.error_msg = "New admin password must be at least 8 characters. Press F6 to generate one.".into();
                    self.phase = Phase::Error;
                    return;
                }
                if ws.sec_reset_jwt && ws.f_sec_jwt.buf.len() < 32 {
                    self.error_msg = "New session secret must be at least 32 characters. Press F6 to generate one.".into();
                    self.phase = Phase::Error;
                    return;
                }
                if ws.sec_reset_api && ws.f_sec_api.buf.len() < 16 {
                    self.error_msg = "New API master key must be at least 16 characters. Press F6 to generate one.".into();
                    self.phase = Phase::Error;
                    return;
                }
                if ws.sec_change_username && ws.f_sec_username.buf.trim().len() < 3 {
                    self.error_msg = "New admin username must be at least 3 characters.".into();
                    self.phase = Phase::Error;
                    return;
                }
            }
            InstallMode::Uninstall => {
                if !has_keybase_install(&cfg.output_dir) {
                    self.error_msg =
                        "No KeyBase installation found at this path. Check the directory and try again.".into();
                    self.phase = Phase::Error;
                    return;
                }
            }
            InstallMode::Fresh => {
                if cfg.prov_enabled && cfg.prov_token.trim().is_empty() {
                    self.error_msg =
                        "Provisioning API is enabled, so the Provisioning token cannot be empty. Type one or press F6 to generate it.".into();
                    self.phase = Phase::Error;
                    return;
                }
            }
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
            KeyCode::Char('o') | KeyCode::Char('O') => {
                if self.config.output_path().exists() {
                    self.open_output_folder();
                }
            }
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

    // ── Install / Uninstall ───────────────────────────────────────────────────

    pub fn start_install(&mut self) {
        self.phase = Phase::Installing;
        self.install = InstallState::default();
        self.build_start = Some(Instant::now());
        self.build_elapsed = 0.0;
        self.generated_files.clear();
        self.test_log.clear();
        self.test_result = None;
        self.cancel_requested = false;
        self.install_cancelled = false;

        let mut cfg = self.config.clone();
        let cancel = install::new_cancel_flag();
        self.active_cancel = Some(cancel.clone());

        if matches!(cfg.install_mode, InstallMode::Uninstall) {
            cfg.selftest = false;
            let (jh, rx) = install::spawn_uninstall(cfg, cancel);
            self._install_jh = Some(jh);
            self.install_rx = Some(rx);
            return;
        }

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
        let (jh, rx) = install::spawn_install(cfg, python, cancel);
        self._install_jh = Some(jh);
        self.install_rx = Some(rx);
    }

    fn start_selftest(&mut self) {
        self.phase = Phase::SelfTest;
        self.test_log.clear();
        self.test_result = None;
        self.cancel_requested = false;

        let dir = self.config.output_path();
        let port = self.config.port_u16();
        let cancel = install::new_cancel_flag();
        self.active_cancel = Some(cancel.clone());
        let (jh, rx) = selftest::spawn_selftest(dir, port, cancel);
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
                InstallMsg::Cancelled => {
                    self.install_rx = None;
                    self.active_cancel = None;
                    self.cancel_requested = false;
                    self.install_cancelled = true;
                    if let Some(t) = self.build_start {
                        self.build_elapsed = t.elapsed().as_secs_f64();
                    }
                    self.persist_install_log();
                    self.phase = Phase::Done;
                    return;
                }
                InstallMsg::Error(e) => {
                    self.install_rx = None;
                    self.active_cancel = None;
                    self.cancel_requested = false;
                    self.error_msg = e;
                    self.phase = Phase::Error;
                    return;
                }
                InstallMsg::Done => {
                    self.install_rx = None;
                    self.active_cancel = None;
                    self.cancel_requested = false;
                    if let Some(t) = self.build_start {
                        self.build_elapsed = t.elapsed().as_secs_f64();
                    }
                    self.persist_install_log();

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
                    self.active_cancel = None;
                    self.cancel_requested = false;
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
        if self.install_cancelled {
            let action = if self.config.install_mode == InstallMode::Uninstall {
                "Uninstallation"
            } else {
                "Installation"
            };
            println!("{action} cancelled: {}", self.config.output_dir);
            if self.build_elapsed > 0.0 {
                println!("Elapsed:      {:.1}s", self.build_elapsed);
            }
            return;
        }
        if self.config.install_mode == InstallMode::Uninstall {
            println!("Uninstallation complete: {}", self.config.output_dir);
            if self.build_elapsed > 0.0 {
                println!("Elapsed:        {:.1}s", self.build_elapsed);
            }
            return;
        }
        println!("Installation complete: {}", self.config.output_dir);
        println!("Server URL:   http://{}:{}", self.config.host, port);
        println!("Admin panel:  http://{}:{}/admin", self.config.host, port);
        if self.test_result == Some(TestResult::Cancelled) {
            println!("Self-test:    cancelled");
        }
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

    pub fn is_busy(&self) -> bool {
        matches!(self.phase, Phase::Installing | Phase::SelfTest)
    }

    pub fn request_cancel(&mut self) {
        if self.cancel_requested {
            return;
        }
        let Some(flag) = &self.active_cancel else {
            return;
        };

        self.cancel_requested = true;
        install::request_cancel(flag);

        match self.phase {
            Phase::Installing => {
                let note = if self.config.install_mode == InstallMode::Uninstall {
                    "Cancellation requested - stopping uninstall and leaving remaining files in place."
                } else {
                    "Cancellation requested - stopping the install safely."
                };
                self.install.push_log(note.into());
            }
            Phase::SelfTest => {
                self.test_log
                    .push_back("Cancellation requested - stopping self-test.".into());
                while self.test_log.len() > 60 {
                    self.test_log.pop_front();
                }
            }
            _ => {}
        }
    }

    fn persist_install_log(&self) {
        let dir = self.config.output_path();
        if !dir.exists() {
            return;
        }
        let log: Vec<String> = self.install.log.iter().cloned().collect();
        let _ = config_gen::save_install_log(&dir, &log, self.build_elapsed);
    }
}
