use std::path::PathBuf;

/// All user-configurable values collected during the wizard.
#[derive(Clone)]
pub struct BuildConfig {
    // Core
    pub output_dir: String,
    pub port: String,
    pub host: String,
    // Database
    pub db_backend: DbBackend,
    pub sqlite_path: String,
    pub pg_url: String,
    pub mysql_url: String,
    // Network / proxy
    pub allow_remote_admin: bool,
    pub trust_proxy: bool,
    pub cloudflare: bool,
    pub domain: String, // used by NGINX / SSL / docs
    // API
    pub rate_limit: String, // verify calls per minute
    // Provisioning
    pub prov_enabled: bool,
    pub prov_token: String,
    // Extras
    pub debug: bool,
    pub gen_docker: bool,
    pub gen_nginx: bool,
    pub gen_systemd: bool,
    // Wizard meta
    pub selftest: bool,
    pub lang_idx: usize,
    pub dark_theme: bool,
}

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

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            output_dir: default_output_dir(),
            port: "8080".into(),
            host: "127.0.0.1".into(),
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
            debug: false,
            gen_docker: true,
            gen_nginx: true,
            gen_systemd: cfg!(target_os = "linux"),
            selftest: true,
            lang_idx: 0,
            dark_theme: true,
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
}

// ── Text Input ───────────────────────────────────────────────────────────────

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
    // Extras
    Debug,
    GenDocker,
    GenNginx,
    GenSystemd,
    // Wizard meta
    SelfTest,
    Language,
    Theme,
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
        )
    }
}

// ── Wizard State ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WizardState {
    pub field: usize,
    pub scroll: usize, // top visible field index

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

    // Selectors / toggles
    pub db_sel: usize,
    pub allow_remote_admin: bool,
    pub trust_proxy: bool,
    pub cloudflare: bool,
    pub prov_enabled: bool,
    pub debug: bool,
    pub gen_docker: bool,
    pub gen_nginx: bool,
    pub gen_systemd: bool,
    pub selftest: bool,
    pub lang_idx: usize,
    pub dark_theme: bool,
}

impl WizardState {
    pub fn from_config(c: &BuildConfig) -> Self {
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
            db_sel: c.db_backend as usize,
            allow_remote_admin: c.allow_remote_admin,
            trust_proxy: c.trust_proxy,
            cloudflare: c.cloudflare,
            prov_enabled: c.prov_enabled,
            debug: c.debug,
            gen_docker: c.gen_docker,
            gen_nginx: c.gen_nginx,
            gen_systemd: c.gen_systemd,
            selftest: c.selftest,
            lang_idx: c.lang_idx,
            dark_theme: c.dark_theme,
        }
    }

    pub fn to_config(&self) -> BuildConfig {
        BuildConfig {
            output_dir: self.f_output.buf.clone(),
            port: self.f_port.buf.clone(),
            host: self.f_host.buf.clone(),
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
            debug: self.debug,
            gen_docker: self.gen_docker,
            gen_nginx: self.gen_nginx,
            gen_systemd: self.gen_systemd,
            selftest: self.selftest,
            lang_idx: self.lang_idx,
            dark_theme: self.dark_theme,
        }
    }

    /// Full ordered list of visible fields (depends on current selections).
    pub fn effective_fields(&self) -> Vec<FieldId> {
        let mut v = vec![
            FieldId::Output,
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
        v.push(FieldId::Debug);
        v.push(FieldId::GenDocker);
        v.push(FieldId::GenNginx);
        if self.gen_nginx {
            v.push(FieldId::Domain);
        }
        v.push(FieldId::GenSystemd);
        v.push(FieldId::SelfTest);
        v.push(FieldId::Language);
        v.push(FieldId::Theme);
        v
    }

    /// Mutable borrow of the TextInput for a given text field.
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
            _ => unreachable!("not a text field: {:?}", fid as u8),
        }
    }

    /// Shared borrow of the TextInput for a given text field.
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
            _ => unreachable!("not a text field: {:?}", fid as u8),
        }
    }

    /// Ensure scroll keeps active field visible given `visible_rows` rows.
    #[allow(dead_code)]
    pub fn clamp_scroll(&mut self, visible_rows: usize) {
        let n = self.effective_fields().len();
        if visible_rows == 0 || n == 0 {
            return;
        }
        // Scroll down if active field is below viewport
        if self.field >= self.scroll + visible_rows {
            self.scroll = self.field + 1 - visible_rows;
        }
        // Scroll up if active field is above viewport
        if self.field < self.scroll {
            self.scroll = self.field;
        }
        // Never scroll past end
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

fn random_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("kb-prov-{:x}", t ^ 0xdeadbeef_cafebabe_u128)
}
