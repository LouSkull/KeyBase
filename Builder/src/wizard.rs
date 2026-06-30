#![allow(dead_code)]
use std::path::PathBuf;

/// All user-configurable values collected during the wizard.
#[derive(Clone)]
pub struct BuildConfig {
    // Core
    pub output_dir: String,
    pub port: String,
    pub host: String,
    pub install_mode: InstallMode,
    // Database
    pub db_backend: DbBackend,
    pub sqlite_path: String,
    pub pg_url: String,
    pub mysql_url: String,
    // Network / proxy
    pub allow_remote_admin: bool,
    pub trust_proxy: bool,
    pub cloudflare: bool,
    pub domain: String,
    // API
    pub rate_limit: String,
    // Provisioning
    pub prov_enabled: bool,
    pub prov_token: String,
    // Runtime
    pub target_os: TargetOs,
    pub workers: String,
    pub log_level: LogLevel,
    // Backup
    pub backup_interval: String,
    pub backup_keep: String,
    // Security
    pub session_hours: String,
    // Secrets (required — written to .env.example)
    pub jwt_secret: String,
    pub admin_password: String,
    pub api_master_key: String,
    // Extras
    pub debug: bool,
    pub gen_docker: bool,
    pub gen_nginx: bool,
    pub gen_systemd: bool,
    // Wizard meta
    pub selftest: bool,
    pub dark_theme: bool,
    // Security operations (Update mode only)
    pub sec_reset_pwd: bool,
    pub sec_new_pwd: String,
    pub sec_reset_jwt: bool,
    pub sec_new_jwt: String,
    pub sec_reset_api: bool,
    pub sec_new_api: String,
    pub sec_change_username: bool,
    pub sec_new_username: String,
}

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum DbBackend {
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

impl DbBackend {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sqlite => "SQLite",
            Self::Postgres => "PostgreSQL",
            Self::Mysql => "MySQL / MariaDB",
        }
    }
    pub fn all() -> &'static [DbBackend] {
        &[DbBackend::Sqlite, DbBackend::Postgres, DbBackend::Mysql]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum InstallMode {
    #[default]
    Fresh,
    Update,
    Uninstall,
}

impl InstallMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Fresh => "Fresh install",
            Self::Update => "Update existing",
            Self::Uninstall => "Uninstall",
        }
    }
    pub fn all() -> &'static [InstallMode] {
        &[
            InstallMode::Fresh,
            InstallMode::Update,
            InstallMode::Uninstall,
        ]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetOs {
    #[default]
    Linux,
    Windows,
}

impl TargetOs {
    pub fn label(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::Windows => "Windows",
        }
    }
    pub fn gen_bat(self) -> bool {
        matches!(self, Self::Windows)
    }
    pub fn gen_sh(self) -> bool {
        matches!(self, Self::Linux)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Warning,
    Error,
}

impl LogLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
    pub fn all() -> &'static [LogLevel] {
        &[
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Warning,
            LogLevel::Error,
        ]
    }
}

// ── BuildConfig defaults ───────────────────────────────────────────────────────

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            output_dir: default_output_dir(),
            port: "8080".into(),
            host: "127.0.0.1".into(),
            install_mode: InstallMode::Fresh,
            db_backend: DbBackend::Sqlite,
            sqlite_path: "data/keybase.sqlite3".into(),
            pg_url: "postgresql://keybase:password@127.0.0.1:5432/keybase".into(),
            mysql_url: "mysql://keybase:password@127.0.0.1:3306/keybase".into(),
            allow_remote_admin: false,
            trust_proxy: false,
            cloudflare: false,
            domain: String::new(),
            rate_limit: "180".into(),
            prov_enabled: true,
            prov_token: random_token(),
            target_os: if cfg!(windows) {
                TargetOs::Windows
            } else {
                TargetOs::Linux
            },
            workers: "2".into(),
            log_level: LogLevel::Info,
            backup_interval: "60".into(),
            backup_keep: "24".into(),
            session_hours: "12".into(),
            jwt_secret: String::new(),
            admin_password: String::new(),
            api_master_key: String::new(),
            debug: false,
            gen_docker: true,
            gen_nginx: true,
            gen_systemd: cfg!(target_os = "linux"),
            selftest: true,
            dark_theme: true,
            sec_reset_pwd: false,
            sec_new_pwd: String::new(),
            sec_reset_jwt: false,
            sec_new_jwt: String::new(),
            sec_reset_api: false,
            sec_new_api: String::new(),
            sec_change_username: false,
            sec_new_username: String::new(),
        }
    }
}

impl BuildConfig {
    pub fn output_path(&self) -> PathBuf {
        PathBuf::from(&self.output_dir)
    }
    pub fn port_u16(&self) -> u16 {
        self.port.parse().unwrap_or(8080)
    }
    pub fn rate_limit_u32(&self) -> u32 {
        self.rate_limit.parse().unwrap_or(180)
    }
    pub fn workers_u32(&self) -> u32 {
        self.workers.parse::<u32>().unwrap_or(2).clamp(1, 32)
    }
    pub fn backup_interval_u32(&self) -> u32 {
        self.backup_interval.parse::<u32>().unwrap_or(60).max(1)
    }
    pub fn backup_keep_u32(&self) -> u32 {
        self.backup_keep.parse::<u32>().unwrap_or(24).max(1)
    }
    pub fn session_hours_u32(&self) -> u32 {
        self.session_hours.parse::<u32>().unwrap_or(12).max(1)
    }
    pub fn secrets_valid(&self) -> bool {
        self.jwt_secret.len() >= 32
            && self.admin_password.len() >= 8
            && self.api_master_key.len() >= 16
    }
}

// ── Text Input ────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct TextInput {
    pub buf: String,
    pub cursor: usize,
}

impl TextInput {
    pub fn new(s: &str) -> Self {
        Self {
            buf: s.to_string(),
            cursor: s.len(),
        }
    }

    pub fn handle_char(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        let bp = self.char_to_byte(self.cursor);
        self.buf.insert(bp, c);
        self.cursor += 1;
    }
    pub fn handle_backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let bp = self.char_to_byte(self.cursor);
        self.buf.remove(bp);
    }
    pub fn handle_delete(&mut self) {
        let len = self.buf.chars().count();
        if self.cursor >= len {
            return;
        }
        let bp = self.char_to_byte(self.cursor);
        self.buf.remove(bp);
    }
    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }
    pub fn move_right(&mut self) {
        let l = self.buf.chars().count();
        if self.cursor < l {
            self.cursor += 1;
        }
    }
    pub fn home(&mut self) {
        self.cursor = 0;
    }
    pub fn end(&mut self) {
        self.cursor = self.buf.chars().count();
    }
    pub fn set(&mut self, s: String) {
        self.buf = s;
        self.cursor = self.buf.chars().count();
    }

    fn char_to_byte(&self, ci: usize) -> usize {
        self.buf
            .char_indices()
            .nth(ci)
            .map(|(b, _)| b)
            .unwrap_or(self.buf.len())
    }
}

// ── Field IDs ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    // Core
    Output,
    InstallMode,
    Port,
    Host,
    // Database
    Database,
    SqlitePath,
    PgUrl,
    MysqlUrl,
    // Network
    AllowRemoteAdmin,
    TrustProxy,
    Cloudflare,
    Domain,
    // API
    RateLimit,
    // Provisioning
    Provisioning,
    ProvToken,
    // Runtime
    Workers,
    LogLevel,
    // Backup
    BackupInterval,
    BackupKeep,
    // Security
    SessionHours,
    JwtSecret,
    AdminPassword,
    ApiMasterKey,
    // Extras
    Debug,
    GenDocker,
    GenNginx,
    GenSystemd,
    // Wizard meta
    SelfTest,
    Theme,
    // Security operations (Update mode only)
    SecResetPwd,
    SecNewPwd,
    SecResetJwt,
    SecNewJwt,
    SecResetApi,
    SecNewApi,
    SecChangeUsername,
    SecNewUsername,
}

impl FieldId {
    pub fn is_text(self) -> bool {
        matches!(
            self,
            FieldId::Output
                | FieldId::Port
                | FieldId::Host
                | FieldId::SqlitePath
                | FieldId::PgUrl
                | FieldId::MysqlUrl
                | FieldId::Domain
                | FieldId::RateLimit
                | FieldId::ProvToken
                | FieldId::Workers
                | FieldId::BackupInterval
                | FieldId::BackupKeep
                | FieldId::SessionHours
                | FieldId::JwtSecret
                | FieldId::AdminPassword
                | FieldId::ApiMasterKey
                | FieldId::SecNewPwd
                | FieldId::SecNewJwt
                | FieldId::SecNewApi
                | FieldId::SecNewUsername
        )
    }

    pub fn is_secret(self) -> bool {
        matches!(
            self,
            FieldId::ProvToken
                | FieldId::JwtSecret
                | FieldId::AdminPassword
                | FieldId::ApiMasterKey
                | FieldId::SecNewPwd
                | FieldId::SecNewJwt
                | FieldId::SecNewApi
        )
    }

    pub fn can_generate(self) -> bool {
        self.is_secret()
    }
}

// ── Wizard State ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WizardState {
    pub field: usize,
    pub scroll: usize,

    // Text inputs
    pub f_output: TextInput,
    pub f_port: TextInput,
    pub f_host: TextInput,
    pub f_sqlite: TextInput,
    pub f_pg_url: TextInput,
    pub f_mysql_url: TextInput,
    pub f_domain: TextInput,
    pub f_rate: TextInput,
    pub f_prov_token: TextInput,
    pub f_workers: TextInput,
    pub f_backup_interval: TextInput,
    pub f_backup_keep: TextInput,
    pub f_session_hours: TextInput,
    pub f_jwt_secret: TextInput,
    pub f_admin_password: TextInput,
    pub f_api_master_key: TextInput,

    // Show/hide toggles for secret fields
    pub show_jwt: bool,
    pub show_admin_pass: bool,
    pub show_api_key: bool,
    pub show_prov_token: bool,

    // Detected existing install in output dir
    pub dir_has_install: Option<bool>,
    // Result of last auto-find scan: None=not run, Some(n)=found n installs
    pub autofind_count: Option<usize>,
    // Incremented each time output path is set programmatically; used as TextEdit ID salt
    // so egui drops its cached widget state and re-reads from buf immediately
    pub output_autofill_gen: u32,

    // Selectors / toggles
    pub install_mode: InstallMode,
    pub db_sel: usize,
    pub allow_remote_admin: bool,
    pub trust_proxy: bool,
    pub cloudflare: bool,
    pub prov_enabled: bool,
    pub log_level_sel: usize,
    pub debug: bool,
    pub gen_docker: bool,
    pub gen_nginx: bool,
    pub gen_systemd: bool,
    pub selftest: bool,
    pub dark_theme: bool,

    // Security operations (Update mode only — reset without reinstall)
    pub sec_reset_pwd: bool,
    pub f_sec_pwd: TextInput,
    pub sec_show_new_pwd: bool,
    pub sec_reset_jwt: bool,
    pub f_sec_jwt: TextInput,
    pub sec_show_new_jwt: bool,
    pub sec_reset_api: bool,
    pub f_sec_api: TextInput,
    pub sec_show_new_api: bool,
    pub sec_change_username: bool,
    pub f_sec_username: TextInput,
}

impl WizardState {
    pub fn from_config(c: &BuildConfig) -> Self {
        let log_level_sel = LogLevel::all()
            .iter()
            .position(|&l| l == c.log_level)
            .unwrap_or(0);
        Self {
            field: 0,
            scroll: 0,
            f_output: TextInput::new(&c.output_dir),
            f_port: TextInput::new(&c.port),
            f_host: TextInput::new(&c.host),
            f_sqlite: TextInput::new(&c.sqlite_path),
            f_pg_url: TextInput::new(&c.pg_url),
            f_mysql_url: TextInput::new(&c.mysql_url),
            f_domain: TextInput::new(&c.domain),
            f_rate: TextInput::new(&c.rate_limit),
            f_prov_token: TextInput::new(&c.prov_token),
            f_workers: TextInput::new(&c.workers),
            f_backup_interval: TextInput::new(&c.backup_interval),
            f_backup_keep: TextInput::new(&c.backup_keep),
            f_session_hours: TextInput::new(&c.session_hours),
            f_jwt_secret: TextInput::new(&c.jwt_secret),
            f_admin_password: TextInput::new(&c.admin_password),
            f_api_master_key: TextInput::new(&c.api_master_key),
            show_jwt: false,
            show_admin_pass: false,
            show_api_key: false,
            show_prov_token: false,
            dir_has_install: None,
            autofind_count: None,
            output_autofill_gen: 0,
            install_mode: c.install_mode,
            db_sel: c.db_backend as usize,
            allow_remote_admin: c.allow_remote_admin,
            trust_proxy: c.trust_proxy,
            cloudflare: c.cloudflare,
            prov_enabled: c.prov_enabled,
            log_level_sel,
            debug: c.debug,
            gen_docker: c.gen_docker,
            gen_nginx: c.gen_nginx,
            gen_systemd: c.gen_systemd,
            selftest: c.selftest,
            dark_theme: c.dark_theme,
            sec_reset_pwd: false,
            f_sec_pwd: TextInput::default(),
            sec_show_new_pwd: false,
            sec_reset_jwt: false,
            f_sec_jwt: TextInput::default(),
            sec_show_new_jwt: false,
            sec_reset_api: false,
            f_sec_api: TextInput::default(),
            sec_show_new_api: false,
            sec_change_username: false,
            f_sec_username: TextInput::default(),
        }
    }

    pub fn to_config(&self) -> BuildConfig {
        let (jwt_secret, admin_password, api_master_key) = if matches!(
            self.install_mode,
            InstallMode::Update | InstallMode::Uninstall
        ) {
            (String::new(), String::new(), String::new())
        } else {
            (
                self.f_jwt_secret.buf.clone(),
                self.f_admin_password.buf.clone(),
                self.f_api_master_key.buf.clone(),
            )
        };

        BuildConfig {
            output_dir: self.f_output.buf.clone(),
            port: self.f_port.buf.clone(),
            host: self.f_host.buf.clone(),
            install_mode: self.install_mode,
            db_backend: match self.db_sel {
                0 => DbBackend::Sqlite,
                1 => DbBackend::Postgres,
                _ => DbBackend::Mysql,
            },
            sqlite_path: self.f_sqlite.buf.clone(),
            pg_url: self.f_pg_url.buf.clone(),
            mysql_url: self.f_mysql_url.buf.clone(),
            allow_remote_admin: self.allow_remote_admin,
            trust_proxy: self.trust_proxy,
            cloudflare: self.cloudflare,
            domain: self.f_domain.buf.clone(),
            rate_limit: self.f_rate.buf.clone(),
            prov_enabled: self.prov_enabled,
            prov_token: self.f_prov_token.buf.clone(),
            target_os: if cfg!(windows) { TargetOs::Windows } else { TargetOs::Linux },
            workers: self.f_workers.buf.clone(),
            log_level: LogLevel::all()
                .get(self.log_level_sel)
                .copied()
                .unwrap_or_default(),
            backup_interval: self.f_backup_interval.buf.clone(),
            backup_keep: self.f_backup_keep.buf.clone(),
            session_hours: self.f_session_hours.buf.clone(),
            jwt_secret,
            admin_password,
            api_master_key,
            debug: self.debug,
            gen_docker: self.gen_docker,
            gen_nginx: self.gen_nginx,
            gen_systemd: self.gen_systemd,
            selftest: self.selftest,
            dark_theme: self.dark_theme,
            sec_reset_pwd: self.sec_reset_pwd,
            sec_new_pwd: self.f_sec_pwd.buf.clone(),
            sec_reset_jwt: self.sec_reset_jwt,
            sec_new_jwt: self.f_sec_jwt.buf.clone(),
            sec_reset_api: self.sec_reset_api,
            sec_new_api: self.f_sec_api.buf.clone(),
            sec_change_username: self.sec_change_username,
            sec_new_username: self.f_sec_username.buf.clone(),
        }
    }

    /// Full ordered list of visible fields (depends on current selections).
    pub fn effective_fields(&self) -> Vec<FieldId> {
        // Uninstall: only mode selector + path
        if self.install_mode == InstallMode::Uninstall {
            return vec![FieldId::InstallMode, FieldId::Output];
        }

        // Update: mode + path + optional security operations + generated files
        if self.install_mode == InstallMode::Update {
            let mut fields = vec![FieldId::InstallMode, FieldId::Output];
            fields.push(FieldId::SecResetPwd);
            if self.sec_reset_pwd {
                fields.push(FieldId::SecNewPwd);
            }
            fields.push(FieldId::SecResetJwt);
            if self.sec_reset_jwt {
                fields.push(FieldId::SecNewJwt);
            }
            fields.push(FieldId::SecResetApi);
            if self.sec_reset_api {
                fields.push(FieldId::SecNewApi);
            }
            fields.push(FieldId::SecChangeUsername);
            if self.sec_change_username {
                fields.push(FieldId::SecNewUsername);
            }
            fields.push(FieldId::GenDocker);
            fields.push(FieldId::GenNginx);
            if self.gen_nginx {
                fields.push(FieldId::Domain);
            }
            fields.push(FieldId::GenSystemd);
            fields.push(FieldId::SelfTest);
            return fields;
        }

        let mut v = vec![
            FieldId::Output,
            FieldId::InstallMode,
            FieldId::Port,
            FieldId::Host,
            FieldId::Database,
        ];
        match self.db_sel {
            0 => v.push(FieldId::SqlitePath),
            1 => v.push(FieldId::PgUrl),
            _ => v.push(FieldId::MysqlUrl),
        }
        v.push(FieldId::AllowRemoteAdmin);
        v.push(FieldId::TrustProxy);
        v.push(FieldId::Cloudflare);
        v.push(FieldId::RateLimit);
        v.push(FieldId::Provisioning);
        if self.prov_enabled {
            v.push(FieldId::ProvToken);
        }
        v.push(FieldId::Workers);
        v.push(FieldId::LogLevel);
        v.push(FieldId::BackupInterval);
        v.push(FieldId::BackupKeep);
        v.push(FieldId::SessionHours);
        v.push(FieldId::Debug);
        v.push(FieldId::GenDocker);
        v.push(FieldId::GenNginx);
        if self.gen_nginx {
            v.push(FieldId::Domain);
        }
        v.push(FieldId::GenSystemd);
        v.push(FieldId::SelfTest);
        v
    }

    pub fn ti_mut(&mut self, fid: FieldId) -> &mut TextInput {
        match fid {
            FieldId::Output => &mut self.f_output,
            FieldId::Port => &mut self.f_port,
            FieldId::Host => &mut self.f_host,
            FieldId::SqlitePath => &mut self.f_sqlite,
            FieldId::PgUrl => &mut self.f_pg_url,
            FieldId::MysqlUrl => &mut self.f_mysql_url,
            FieldId::Domain => &mut self.f_domain,
            FieldId::RateLimit => &mut self.f_rate,
            FieldId::ProvToken => &mut self.f_prov_token,
            FieldId::Workers => &mut self.f_workers,
            FieldId::BackupInterval => &mut self.f_backup_interval,
            FieldId::BackupKeep => &mut self.f_backup_keep,
            FieldId::SessionHours => &mut self.f_session_hours,
            FieldId::JwtSecret => &mut self.f_jwt_secret,
            FieldId::AdminPassword => &mut self.f_admin_password,
            FieldId::ApiMasterKey => &mut self.f_api_master_key,
            FieldId::SecNewPwd => &mut self.f_sec_pwd,
            FieldId::SecNewJwt => &mut self.f_sec_jwt,
            FieldId::SecNewApi => &mut self.f_sec_api,
            FieldId::SecNewUsername => &mut self.f_sec_username,
            _ => unreachable!("not a text field: {:?}", fid as u8),
        }
    }

    pub fn ti(&self, fid: FieldId) -> &TextInput {
        match fid {
            FieldId::Output => &self.f_output,
            FieldId::Port => &self.f_port,
            FieldId::Host => &self.f_host,
            FieldId::SqlitePath => &self.f_sqlite,
            FieldId::PgUrl => &self.f_pg_url,
            FieldId::MysqlUrl => &self.f_mysql_url,
            FieldId::Domain => &self.f_domain,
            FieldId::RateLimit => &self.f_rate,
            FieldId::ProvToken => &self.f_prov_token,
            FieldId::Workers => &self.f_workers,
            FieldId::BackupInterval => &self.f_backup_interval,
            FieldId::BackupKeep => &self.f_backup_keep,
            FieldId::SessionHours => &self.f_session_hours,
            FieldId::JwtSecret => &self.f_jwt_secret,
            FieldId::AdminPassword => &self.f_admin_password,
            FieldId::ApiMasterKey => &self.f_api_master_key,
            FieldId::SecNewPwd => &self.f_sec_pwd,
            FieldId::SecNewJwt => &self.f_sec_jwt,
            FieldId::SecNewApi => &self.f_sec_api,
            FieldId::SecNewUsername => &self.f_sec_username,
            _ => unreachable!("not a text field: {:?}", fid as u8),
        }
    }

    #[allow(dead_code)]
    pub fn clamp_scroll(&mut self, visible_rows: usize) {
        let n = self.effective_fields().len();
        if visible_rows == 0 || n == 0 {
            return;
        }
        if self.field >= self.scroll + visible_rows {
            self.scroll = self.field + 1 - visible_rows;
        }
        if self.field < self.scroll {
            self.scroll = self.field;
        }
        self.scroll = self.scroll.min(n.saturating_sub(visible_rows));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_output_dir() -> String {
    #[cfg(target_os = "windows")]
    {
        r"C:\KeyBase".into()
    }
    #[cfg(not(target_os = "windows"))]
    {
        dirs::home_dir()
            .map(|h| h.join("keybase").to_string_lossy().to_string())
            .unwrap_or_else(|| "/opt/keybase".into())
    }
}

pub fn generate_secret(bytes: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    hex::encode((0..bytes).map(|_| rng.gen::<u8>()).collect::<Vec<_>>())
}

fn random_token() -> String {
    format!("kb-prov-{}", generate_secret(16))
}

/// Returns true if path looks like a KeyBase server installation.
pub fn has_keybase_install(path: &str) -> bool {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return false;
    }
    // Strongest signal: the keybase Python package directory
    if p.join("keybase").is_dir() {
        return true;
    }
    // Builder-generated run scripts
    if p.join("run.sh").exists() || p.join("run.bat").exists() {
        return true;
    }
    // Config + venv present together
    if p.join("config.yml").exists() && p.join(".venv").is_dir() {
        return true;
    }
    // Looser: any one marker
    if p.join("config.yml").exists() || p.join(".venv").is_dir() {
        return true;
    }
    false
}

/// Scan common system locations and return paths that contain a KeyBase installation.
pub fn auto_find_installs() -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();

    #[cfg(windows)]
    {
        // All common drive letters
        for drive in &["C", "D", "E", "F", "G", "H"] {
            for name in &["KeyBase", "keybase", "key-base", "key_base"] {
                candidates.push(format!("{}:\\{}", drive, name));
            }
        }
        // User home locations
        if let Ok(user) = std::env::var("USERPROFILE") {
            for name in &["KeyBase", "keybase"] {
                candidates.push(format!("{}\\{}", user, name));
            }
            candidates.push(format!("{}\\Desktop\\KeyBase", user));
            candidates.push(format!("{}\\Documents\\KeyBase", user));
        }
        // Program Files
        for pf in &["C:\\Program Files", "C:\\Program Files (x86)"] {
            candidates.push(format!("{}\\KeyBase", pf));
        }
        // AppData
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(format!("{}\\KeyBase", local));
        }
        if let Ok(roaming) = std::env::var("APPDATA") {
            candidates.push(format!("{}\\KeyBase", roaming));
        }
        // Scan each drive root for keybase* subdirs
        for drive in &["C", "D", "E", "F"] {
            let root = format!("{}:\\", drive);
            if let Ok(entries) = std::fs::read_dir(&root) {
                for entry in entries.flatten() {
                    let name_lower = entry.file_name().to_string_lossy().to_lowercase();
                    if name_lower.contains("keybase") || name_lower == "key-base" {
                        if entry.path().is_dir() {
                            candidates.push(entry.path().to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home) = dirs::home_dir() {
            for name in &["keybase", "KeyBase", "key-base", ".keybase"] {
                candidates.push(home.join(name).to_string_lossy().into_owned());
            }
            candidates.push(
                home.join("apps")
                    .join("keybase")
                    .to_string_lossy()
                    .into_owned(),
            );
            candidates.push(
                home.join(".local")
                    .join("share")
                    .join("keybase")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        for prefix in &["/opt", "/srv", "/var/lib", "/usr/local", "/home"] {
            for name in &["keybase", "KeyBase", "key-base"] {
                candidates.push(format!("{}/{}", prefix, name));
            }
        }
        // Scan /home for per-user keybase dirs
        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    for name in &["keybase", "KeyBase"] {
                        let p = entry.path().join(name);
                        candidates.push(p.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    // Deduplicate, then filter
    candidates.dedup();
    candidates.retain(|p| has_keybase_install(p));
    candidates
}
