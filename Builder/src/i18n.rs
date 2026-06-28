/// Supported UI languages.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    Ru,
    Es,
}

impl Lang {
    pub fn label(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Es => "Español",
        }
    }

    pub fn all() -> &'static [Lang] {
        &[Lang::En, Lang::Ru, Lang::Es]
    }
}

macro_rules! t {
    ($lang:expr, $en:literal, $ru:literal, $es:literal) => {
        match $lang {
            Lang::En => $en,
            Lang::Ru => $ru,
            Lang::Es => $es,
        }
    };
}

#[allow(dead_code)]
pub struct Strings {
    pub title: &'static str,
    pub subtitle: &'static str,
    pub welcome_intro: &'static str,
    pub welcome_steps: &'static [&'static str],
    pub press_enter: &'static str,
    pub press_q: &'static str,
    pub press_back: &'static str,
    pub syscheck_title: &'static str,
    pub syscheck_ok: &'static str,
    pub syscheck_warn: &'static str,
    pub syscheck_fail: &'static str,
    pub wizard_title: &'static str,
    pub fld_output: &'static str,
    pub fld_port: &'static str,
    pub fld_host: &'static str,
    pub fld_db: &'static str,
    pub fld_sqlite: &'static str,
    pub fld_lang: &'static str,
    pub fld_prov: &'static str,
    pub fld_prov_token: &'static str,
    pub confirm_title: &'static str,
    pub confirm_build: &'static str,
    pub install_title: &'static str,
    pub install_downloading: &'static str,
    pub install_extracting: &'static str,
    pub install_venv: &'static str,
    pub install_pip: &'static str,
    pub install_config: &'static str,
    pub selftest_title: &'static str,
    pub selftest_starting: &'static str,
    pub selftest_waiting: &'static str,
    pub selftest_pass: &'static str,
    pub selftest_fail: &'static str,
    pub selftest_skip: &'static str,
    pub done_title: &'static str,
    pub done_start_win: &'static str,
    pub done_start_lin: &'static str,
    pub done_open: &'static str,
    pub err_title: &'static str,
    pub nav_arrows: &'static str,
    pub nav_enter: &'static str,
    pub nav_next: &'static str,
    pub nav_edit: &'static str,
    pub nav_select: &'static str,
}

pub fn strings(lang: Lang) -> Strings {
    Strings {
        title: t!(
            lang,
            "KeyBase Builder",
            "KeyBase Установщик",
            "KeyBase Instalador"
        ),
        subtitle: t!(
            lang,
            "Self-hosted license key server — Setup Wizard",
            "Сервер лицензионных ключей — Мастер установки",
            "Servidor de claves — Asistente de instalación"
        ),
        welcome_intro: t!(
            lang,
            "This wizard will guide you through installing and configuring your KeyBase server.",
            "Мастер поможет вам установить и настроить сервер KeyBase.",
            "Este asistente le guiará para instalar y configurar su servidor KeyBase."
        ),
        welcome_steps: match lang {
            Lang::Ru => &[
                "Проверка системных требований",
                "Настройка параметров сервера",
                "Загрузка и установка",
                "Проверка работоспособности",
            ],
            Lang::Es => &[
                "Verificar requisitos del sistema",
                "Configurar el servidor",
                "Descargar e instalar",
                "Verificar funcionamiento",
            ],
            _ => &[
                "Check system requirements",
                "Configure server settings",
                "Download and install",
                "Verify everything works",
            ],
        },
        press_enter: t!(
            lang,
            "[Enter] Continue",
            "[Enter] Продолжить",
            "[Enter] Continuar"
        ),
        press_q: t!(lang, "[q] Quit", "[q] Выход", "[q] Salir"),
        press_back: t!(lang, "[Esc] Back", "[Esc] Назад", "[Esc] Atrás"),
        syscheck_title: t!(
            lang,
            "System Requirements",
            "Системные требования",
            "Requisitos del sistema"
        ),
        syscheck_ok: t!(
            lang,
            "All checks passed. Ready to proceed.",
            "Все проверки пройдены. Можно продолжить.",
            "Todas las verificaciones pasaron. Listo."
        ),
        syscheck_warn: t!(
            lang,
            "Some checks have warnings — you may still continue.",
            "Некоторые проверки выдали предупреждения — можно продолжить.",
            "Algunas verificaciones tienen advertencias — puede continuar."
        ),
        syscheck_fail: t!(
            lang,
            "Required dependencies are missing. Please install them first.",
            "Отсутствуют необходимые зависимости. Установите их перед продолжением.",
            "Faltan dependencias requeridas. Instálelas primero."
        ),
        wizard_title: t!(
            lang,
            "Server Configuration",
            "Настройка сервера",
            "Configuración del servidor"
        ),
        fld_output: t!(
            lang,
            "Output directory",
            "Папка установки",
            "Directorio de instalación"
        ),
        fld_port: t!(lang, "Port", "Порт", "Puerto"),
        fld_host: t!(
            lang,
            "Host (bind address)",
            "Хост (адрес привязки)",
            "Host (dirección de enlace)"
        ),
        fld_db: t!(lang, "Database", "База данных", "Base de datos"),
        fld_sqlite: t!(
            lang,
            "SQLite file path",
            "Путь к файлу SQLite",
            "Ruta del archivo SQLite"
        ),
        fld_lang: t!(lang, "Language", "Язык интерфейса", "Idioma de la interfaz"),
        fld_prov: t!(
            lang,
            "Enable provisioning API",
            "Включить API выдачи ключей",
            "Habilitar API de aprovisionamiento"
        ),
        fld_prov_token: t!(
            lang,
            "Provisioning token",
            "Токен выдачи ключей",
            "Token de aprovisionamiento"
        ),
        confirm_title: t!(
            lang,
            "Confirm Installation",
            "Подтверждение установки",
            "Confirmar instalación"
        ),
        confirm_build: t!(
            lang,
            "Build and install with these settings?",
            "Установить с этими параметрами?",
            "¿Instalar con esta configuración?"
        ),
        install_title: t!(lang, "Installing…", "Установка…", "Instalando…"),
        install_downloading: t!(
            lang,
            "Downloading Server-Portable.zip",
            "Загрузка Server-Portable.zip",
            "Descargando Server-Portable.zip"
        ),
        install_extracting: t!(
            lang,
            "Extracting files",
            "Извлечение файлов",
            "Extrayendo archivos"
        ),
        install_venv: t!(
            lang,
            "Creating Python environment",
            "Создание окружения Python",
            "Creando entorno Python"
        ),
        install_pip: t!(
            lang,
            "Installing Python packages",
            "Установка пакетов Python",
            "Instalando paquetes Python"
        ),
        install_config: t!(
            lang,
            "Generating configuration",
            "Генерация конфигурации",
            "Generando configuración"
        ),
        selftest_title: t!(
            lang,
            "Self-Test",
            "Проверка работоспособности",
            "Auto-prueba"
        ),
        selftest_starting: t!(
            lang,
            "Starting server…",
            "Запуск сервера…",
            "Iniciando servidor…"
        ),
        selftest_waiting: t!(
            lang,
            "Waiting for server to respond…",
            "Ожидание ответа сервера…",
            "Esperando respuesta del servidor…"
        ),
        selftest_pass: t!(
            lang,
            "Server responded — PASSED",
            "Сервер ответил — УСПЕХ",
            "El servidor respondió — APROBADO"
        ),
        selftest_fail: t!(
            lang,
            "Server did not respond — FAILED",
            "Сервер не ответил — ОШИБКА",
            "El servidor no respondió — FALLIDO"
        ),
        selftest_skip: t!(
            lang,
            "Self-test skipped.",
            "Проверка пропущена.",
            "Auto-prueba omitida."
        ),
        done_title: t!(
            lang,
            "Installation Complete",
            "Установка завершена",
            "Instalación completa"
        ),
        done_start_win: t!(
            lang,
            "To start the server:  run.bat",
            "Для запуска сервера:  run.bat",
            "Para iniciar:  run.bat"
        ),
        done_start_lin: t!(
            lang,
            "To start the server:  ./run.sh",
            "Для запуска сервера:  ./run.sh",
            "Para iniciar:  ./run.sh"
        ),
        done_open: t!(
            lang,
            "[o] Open folder",
            "[o] Открыть папку",
            "[o] Abrir carpeta"
        ),
        err_title: t!(lang, "Error", "Ошибка", "Error"),
        nav_arrows: t!(lang, "[↑↓] Navigate", "[↑↓] Навигация", "[↑↓] Navegar"),
        nav_enter: t!(
            lang,
            "[Enter] Confirm",
            "[Enter] Подтвердить",
            "[Enter] Confirmar"
        ),
        nav_next: t!(lang, "[Enter] Next", "[Enter] Далее", "[Enter] Siguiente"),
        nav_edit: t!(
            lang,
            "  type to edit",
            "  ввод для изменения",
            "  escriba para editar"
        ),
        nav_select: t!(lang, "[←→] Change", "[←→] Выбрать", "[←→] Cambiar"),
    }
}
