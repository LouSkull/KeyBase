#!/usr/bin/env python3
"""Core database, license, and HTML rendering logic for Key Base."""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import html
import ipaddress
import json
import os
import base64
import binascii
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from datetime import date, datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

from . import db, __version__ as PACKAGE_VERSION


APP_NAME = "Key Base"
VERSION = PACKAGE_VERSION
GITHUB_URL = "https://github.com/LouSkull/KeyBase"
GITHUB_REPO = "LouSkull/KeyBase"
GITHUB_RELEASES_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
# Keep this short so a deleted/latest-reverted release stops showing the
# update banner quickly, while still avoiding a GitHub hit on every render.
GITHUB_RELEASE_CACHE_SECONDS = 10
APP_AUTHOR = "DoxSense"
APP_CONTRIBUTORS: list[str] = []
APP_LICENSE = "MIT"
APP_WEBSITE = "https://github.com/LouSkull/KeyBase"
APP_DOCS_URL = ""
ROOT_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = Path(os.environ.get("KEYBASE_ENV_PATH", ROOT_DIR / ".env"))
PROCESS_LOG_MAX_LINES = 600
PROCESS_LOG_BUFFER: deque[str] = deque(maxlen=PROCESS_LOG_MAX_LINES)
PROCESS_LOG_LOCK = threading.Lock()
PROCESS_LOG_PARTIALS = {"stdout": "", "stderr": ""}
RUNTIME_CAPTURE_INSTALLED = False
BACKGROUND_SERVICES_STARTED = False
BACKUP_WORKER_STARTED = False
BACKUP_WORKER_THREAD: threading.Thread | None = None
WEBHOOK_WORKER_STARTED = False
WEBHOOK_WORKER_THREAD: threading.Thread | None = None
_WEBHOOK_WAKE = threading.Event()
EXPIRY_WORKER_STARTED = False
EXPIRY_WORKER_THREAD: threading.Thread | None = None
_WORKER_GENERATION: int = 0
CONFIG_WATCHER_STARTED: bool = False
CONFIG_WATCHER_THREAD: threading.Thread | None = None
_LAST_CONFIG_MTIME: float = 0.0
_LISTENER_RESTART_EVENT = threading.Event()
_LISTENER_RESTART_PENDING = threading.Event()  # debounce guard
BACKUP_LOCK = threading.Lock()
BACKUP_STATUS: dict[str, Any] = {
    "running": False,
    "last_started_at": "",
    "last_finished_at": "",
    "last_status": "idle",
    "last_message": "No backups yet.",
    "last_path": "",
}
PROCESS_CPU_SAMPLE_LOCK = threading.Lock()
PROCESS_CPU_SAMPLE: dict[str, float] = {
    "wall": time.perf_counter(),
    "proc": time.process_time(),
    "percent": 0.0,
}
SYSTEM_CPU_SAMPLE_LOCK = threading.Lock()
SYSTEM_CPU_SAMPLE: dict[str, float] = {"idle": 0.0, "kernel": 0.0, "user": 0.0, "percent": 0.0}
PROCESS_STORAGE_LOCK = threading.Lock()
PROCESS_STORAGE_CACHE: dict[str, Any] = {"at": 0.0, "bytes": 0, "detail": "Storage footprint unavailable."}
IP_REPUTATION_LOCK = threading.Lock()
IP_REPUTATION_CACHE: dict[str, dict[str, Any]] = {}
TOR_EXIT_CACHE: dict[str, Any] = {"at": 0.0, "nodes": set()}
TOR_EXIT_LOCK = threading.Lock()
GITHUB_RELEASE_LOCK = threading.Lock()
GITHUB_RELEASE_CACHE: dict[str, Any] = {"at": 0.0, "data": None}
PROTECTION_TIMING_LOCK = threading.Lock()
PROTECTION_TIMING: dict[str, deque[float]] = {}
PROTECTION_REASON_CODES = {
    "VM_DETECTED",
    "VPN_DETECTED",
    "PROXY_DETECTED",
    "TOR_DETECTED",
    "DEBUGGER_DETECTED",
}

# ---------------------------------------------------------------------------
# Localization
# ---------------------------------------------------------------------------
_LANG_CTX: contextvars.ContextVar[str] = contextvars.ContextVar("keybase_lang", default="en")


def set_lang(lang: str) -> None:
    _LANG_CTX.set(lang)


def get_lang() -> str:
    return _LANG_CTX.get()


def t(msgkey: str, **kw: Any) -> str:
    from .translations import TRANSLATIONS
    lang = get_lang()
    table = TRANSLATIONS.get(lang) or TRANSLATIONS["en"]
    text = table.get(msgkey) or TRANSLATIONS["en"].get(msgkey, msgkey)
    for k, v in kw.items():
        text = text.replace(f"{{{k}}}", str(v))
    return text


def _h(msgkey: str, **kw: Any) -> str:
    """Like t() but HTML-escapes the result."""
    return html.escape(t(msgkey, **kw))


def _ht(msgkey: str, **kw: Any) -> str:
    """Like t() — alias kept for readability in attribute contexts."""
    return html.escape(t(msgkey, **kw))


def _decode_env_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value


def _encode_env_value(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@+\-=]+", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def load_env_file() -> None:
    if not ENV_PATH.exists():
        return
    for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = _decode_env_value(value)


def update_env_values(values: dict[str, str]) -> None:
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    seen: set[str] = set()
    updated: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            updated.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in values:
            updated.append(f"{key}={_encode_env_value(values[key])}")
            seen.add(key)
        else:
            updated.append(line)
    for key, value in values.items():
        if key not in seen:
            updated.append(f"{key}={_encode_env_value(value)}")
    ENV_PATH.write_text("\n".join(updated).rstrip() + "\n", encoding="utf-8")
    for key, value in values.items():
        os.environ[key] = value


def ensure_env_file() -> None:
    if ENV_PATH.exists():
        return
    values: dict[str, str] = {}
    for key in ("KEYBASE_ADMIN_USER", "KEYBASE_ADMIN_PASSWORD_HASH", "KEYBASE_SESSION_SECRET"):
        if os.environ.get(key):
            values[key] = os.environ[key]
    if values:
        update_env_values(values)
    else:
        ENV_PATH.write_text("# Key Base admin credentials are written here after first setup.\n", encoding="utf-8")


def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", value or "")


def append_process_log(text: str, stream_name: str = "stdout") -> None:
    cleaned = _strip_ansi(str(text or "")).replace("\r\n", "\n").replace("\r", "\n")
    if not cleaned:
        return
    stream_key = "stderr" if stream_name == "stderr" else "stdout"
    with PROCESS_LOG_LOCK:
        combined = PROCESS_LOG_PARTIALS.get(stream_key, "") + cleaned
        lines = combined.split("\n")
        PROCESS_LOG_PARTIALS[stream_key] = lines.pop()
        for line in lines:
            line = line.rstrip()
            if line:
                PROCESS_LOG_BUFFER.append(line[:4000])


def runtime_note(message: str, source: str = "system") -> None:
    stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    append_process_log(f"{stamp} [{source}] {message}\n")


class _StreamMirror:
    def __init__(self, name: str, original: Any) -> None:
        self.name = name
        self.original = original
        self._local = threading.local()

    def write(self, data: Any) -> int:
        text = str(data or "")
        if not text:
            return 0
        if getattr(self._local, "busy", False):
            return self.original.write(text)
        self._local.busy = True
        try:
            written = self.original.write(text)
            append_process_log(text, self.name)
            return int(written or 0)
        finally:
            self._local.busy = False

    def flush(self) -> None:
        if hasattr(self.original, "flush"):
            self.original.flush()

    def isatty(self) -> bool:
        return bool(getattr(self.original, "isatty", lambda: False)())

    def fileno(self) -> int:
        if hasattr(self.original, "fileno"):
            return self.original.fileno()
        raise OSError("Underlying stream has no file descriptor")

    @property
    def encoding(self) -> str:
        return getattr(self.original, "encoding", "utf-8")


def ensure_runtime_stream_capture() -> None:
    global RUNTIME_CAPTURE_INSTALLED
    if RUNTIME_CAPTURE_INSTALLED:
        return
    if not isinstance(sys.stdout, _StreamMirror):
        sys.stdout = _StreamMirror("stdout", sys.stdout)
    if not isinstance(sys.stderr, _StreamMirror):
        sys.stderr = _StreamMirror("stderr", sys.stderr)
    RUNTIME_CAPTURE_INSTALLED = True
    runtime_note("Runtime console capture enabled", "runtime")


load_env_file()

CONFIG_PATH = Path(os.environ.get("KEYBASE_CONFIG_PATH", ROOT_DIR / "config.yml"))
DEFAULT_CONFIG: dict[str, Any] = {
    "server": {
        "mode": "combined",
        "host": "127.0.0.1",
        "port": 8080,
        "admin_host": "127.0.0.1",
        "admin_port": 8080,
        "api_host": "127.0.0.1",
        "api_port": 8080,
        "allow_remote_admin": False,
        "trust_proxy_headers": False,
    },
    "cloudflare": {
        "enabled": False,
        "country_header": "CF-IPCountry",
        "restore_visitor_ip": True,
        "require_https": True,
    },
    "security": {
        "session_hours": 12,
        "confirm_minutes": 15,
        "password_min_length": 6,
        "login_attempts_per_10m": 10,
        "register_attempts_per_hour": 8,
    },
    "api": {
        "verify_rate_limit_per_minute": 180,
        "geoip_timeout_seconds": 2,
        "allow_payload_ip_fallback": True,
        "accepted_ip_headers": [
            "CF-Connecting-IP",
            "True-Client-IP",
            "Fly-Client-IP",
            "X-Real-IP",
            "X-Client-IP",
            "X-Cluster-Client-IP",
            "X-Original-Forwarded-For",
            "X-Forwarded-For",
            "Forwarded",
        ],
        "accepted_country_headers": [
            "CF-IPCountry",
            "CloudFront-Viewer-Country",
            "X-Vercel-IP-Country",
            "Fastly-Geo-Country-Code",
            "X-GeoIP-Country",
            "X-Country-Code",
            "X-Geo-Country",
            "X-App-Country",
        ],
        "geoip_url": "",
        "public_base_url": "http://127.0.0.1:8080",
    },
    "admin": {
        "public_base_url": "http://127.0.0.1:8080",
    },
    "database": {
        "backend": "sqlite",
        "url": "",
        "sqlite_path": "data/keybase.sqlite3",
        "host": "127.0.0.1",
        "port": "",
        "name": "keybase",
        "user": "keybase",
        "password": "",
        "ssl_mode": "prefer",
        "connect_timeout_seconds": 10,
    },
    "backup": {
        "directory": "backups",
        "auto_enabled": True,
        "interval_minutes": 60,
        "keep_last": 24,
        "include_database": True,
        "include_config": True,
        "include_env": True,
    },
    "provisioning": {
        "enabled": False,
        "header_name": "X-KeyBase-Provision-Key",
        "shared_token": "change-this-provision-token",
        "rate_limit_per_minute": 30,
        "require_https": False,
        "default_prefix": "KB",
        "default_max_devices": 1,
        "default_duration_value": 30,
        "default_duration_unit": "days",
        "max_batch_size": 20,
    },
    "paths": {
        "data_dir": "data",
    },
    "public_ip": {
        "enabled": True,
        "cache_seconds": 300,
        "providers": [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://ipv4.icanhazip.com",
        ],
        "override": "",
    },
    "ui": {
        "update_banner_enabled": True,
    },
    "protection": {
        "mode": "warn",
        "anti_mode": "warn",
        "anti_vm": True,
        "anti_vpn": True,
        "anti_proxy": True,
        "anti_debug": True,
        "anti_tamper": True,
        "anti_sandbox": True,
        "ip_whitelist": [],
        "hwid_whitelist": [],
        "country_whitelist": [],
        "ip_reputation_url": "",
        "ip_reputation_token": "",
        "ip_reputation_timeout_seconds": 2,
        "ip_reputation_cache_seconds": 1800,
        "free_ip_intel": True,
        "tor_exit_list": True,
        "tor_exit_list_url": "https://check.torproject.org/torbulkexitlist",
        "request_window_seconds": 10,
        "too_fast_threshold": 20,
        "risk_threshold": 71,
        "signal_threshold": 2,
        "challenge_threshold": 41,
        "hard_challenge_threshold": 71,
        "block_threshold": 71,
        "risk_weights": {
            "vpn": 25,
            "proxy": 25,
            "datacenter_asn": 20,
            "tor": 40,
            "suspicious_ua": 10,
            "timezone_geo_mismatch": 15,
            "too_fast_requests": 20,
            "missing_js_fingerprint": 30,
            "headless_browser": 25,
            "automation_flags": 25,
            "vm_or_emulator": 30,
            "debugger": 40,
            "low_behavior_entropy": 15,
            "sandbox": 60,
            "tamper": 80,
        },
        "vm_keywords": [
            "vmware", "virtualbox", "vbox", "hyper-v", "kvm", "qemu", "xen", "parallels", "bhyve",
            "bochs", "seabios", "ovmf", "virtio", "vmmouse", "vmhgfs", "vmtools", "vmci", "vboxguest",
            "vboxsf", "hv_vmbus", "hv_utils", "qxl", "xenbus", "prl_fs", "00:05:69", "00:0c:29",
            "00:1c:14", "00:50:56", "08:00:27", "00:15:5d", "00:16:3e", "00:1c:42", "52:54:00",
            "mesa", "swiftshader", "llvmpipe", "virgl", "software rasterizer", "virtual gpu",
        ],
        "vpn_keywords": [
            "vpn", "wireguard", "openvpn", "private_relay", "privacy", "anonymous", "mullvad",
            "nordvpn", "expressvpn", "protonvpn", "surfshark", "windscribe", "tunnelbear",
        ],
        "proxy_keywords": [
            "proxy", "tor", "exit_node", "relay", "public_proxy", "socks", "residential_proxy",
            "transparent_proxy", "anonymous_proxy", "crawler", "bot", "headless", "webdriver",
            "puppeteer", "playwright", "selenium", "phantomjs",
        ],
        "suspicious_ua_keywords": [
            "curl", "wget", "python", "requests", "aiohttp", "scrapy", "httpclient", "go-http-client",
            "headless", "selenium", "playwright", "puppeteer", "phantomjs",
        ],
        "datacenter_keywords": [
            "datacenter", "hosting", "cloud", "colo", "amazon", "aws", "google cloud",
            "microsoft", "azure", "ovh", "hetzner", "digitalocean", "vultr", "linode", "akamai",
            "oracle", "leaseweb", "contabo", "m247", "datacamp", "choopa", "sharktech", "gcore",
            "alibaba", "tencent", "yandex", "cloudflare",
        ],
        "debug_keywords": [
            "debug", "debugger", "debugged", "x64dbg", "x32dbg", "ollydbg", "windbg", "ida",
            "ida64", "ghidra", "dnspy", "ilspy", "frida", "cheatengine", "cheat engine", "scylla",
        ],
        "tamper_keywords": [
            "tamper", "hook", "inject", "injection", "patched", "patch", "integrity_failed",
            "hash_mismatch", "memory_modified", "module_modified", "signature_mismatch",
        ],
        "sandbox_keywords": [
            "sandbox", "analysis_env", "automated_analysis", "cuckoo", "any.run", "anyrun",
            "hybrid-analysis", "joe sandbox", "tria.ge", "cape", "malware", "sample",
        ],
    },
    "subscriptions": {
        "levels": {},
    },
    "webhooks": {
        "timeout_seconds": 10,
        "max_retries": 3,
    },
}


def _strip_yaml_comment(value: str) -> str:
    quote = ""
    for index, ch in enumerate(value):
        if ch in {'"', "'"}:
            quote = "" if quote == ch else ch if not quote else quote
        if ch == "#" and not quote:
            return value[:index].rstrip()
    return value.strip()


def _parse_yaml_scalar(value: str) -> Any:
    value = _strip_yaml_comment(value)
    if not value:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return _decode_env_value(value)
    lower = value.lower()
    if lower in {"true", "yes", "on"}:
        return True
    if lower in {"false", "no", "off"}:
        return False
    if lower in {"null", "none", "~"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar(item.strip()) for item in inner.split(",")]
    try:
        return int(value)
    except ValueError:
        return value


def parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1] if stack else root
        if value.strip():
            parent[key] = _parse_yaml_scalar(value.strip())
        else:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
    return root


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if value is None:
        return "null"
    if isinstance(value, list):
        return "[" + ", ".join(_yaml_scalar(item) for item in value) + "]"
    return _encode_env_value(str(value))


def dump_simple_yaml(data: dict[str, Any], indent: int = 0) -> str:
    lines: list[str] = []
    prefix = " " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(dump_simple_yaml(value, indent + 2))
        else:
            lines.append(f"{prefix}{key}: {_yaml_scalar(value)}")
    return "\n".join(line for line in lines if line != "")


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key, value in base.items():
        if isinstance(value, dict):
            merged[key] = deep_merge(value, override.get(key, {}) if isinstance(override.get(key), dict) else {})
        else:
            merged[key] = override.get(key, value)
    for key, value in override.items():
        if key not in merged:
            merged[key] = value
    return merged


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(dump_simple_yaml(DEFAULT_CONFIG) + "\n", encoding="utf-8")
        return deep_merge(DEFAULT_CONFIG, {})
    loaded = parse_simple_yaml(CONFIG_PATH.read_text(encoding="utf-8"))
    return deep_merge(DEFAULT_CONFIG, loaded)


CONFIG = load_config()


def _default_sqlite_path() -> Path:
    data_dir_raw = Path(os.environ.get("KEYBASE_DATA_DIR") or config_str("paths.data_dir", "data"))
    data_dir = data_dir_raw if data_dir_raw.is_absolute() else ROOT_DIR / data_dir_raw
    return data_dir / "keybase.sqlite3"


def current_database_settings() -> db.DatabaseSettings:
    return db.settings_from_config(CONFIG, ROOT_DIR, _default_sqlite_path())


def database_restart_signature() -> tuple[Any, ...]:
    return db.database_signature(current_database_settings())


def _refresh_storage_globals() -> None:
    global DATA_DIR, DB_PATH, DB_SETTINGS, BACKUP_DIR
    data_dir_raw = Path(os.environ.get("KEYBASE_DATA_DIR") or config_str("paths.data_dir", "data"))
    DATA_DIR = data_dir_raw if data_dir_raw.is_absolute() else ROOT_DIR / data_dir_raw
    DB_SETTINGS = current_database_settings()
    DB_PATH = DB_SETTINGS.sqlite_file
    backup_raw = Path(config_str("backup.directory", "backups"))
    BACKUP_DIR = backup_raw if backup_raw.is_absolute() else ROOT_DIR / backup_raw


def reload_config() -> None:
    global CONFIG, SESSION_MAX_SECONDS, CONFIRM_WINDOW_SECONDS, PASSWORD_MIN_LENGTH, GEOIP_TIMEOUT_SECONDS
    CONFIG = load_config()
    _refresh_storage_globals()
    SESSION_MAX_SECONDS = config_int("security.session_hours", 12, 1, 24 * 30) * 60 * 60
    CONFIRM_WINDOW_SECONDS = config_int("security.confirm_minutes", 15, 1, 24 * 60) * 60
    PASSWORD_MIN_LENGTH = max(6, config_int("security.password_min_length", 6, 6, 256))
    GEOIP_TIMEOUT_SECONDS = config_int("api.geoip_timeout_seconds", 2, 1, 15)


def _normalize_subscription_levels(raw: Any) -> dict[int, str]:
    if not isinstance(raw, dict):
        return {}
    result: dict[int, str] = {}
    for k, v in raw.items():
        try:
            lvl_id = int(str(k))
        except (TypeError, ValueError):
            continue
        name = clean_text(v, 64)
        if lvl_id >= 1 and name:
            result[lvl_id] = name
    return dict(sorted(result.items()))


def subscription_levels_seed() -> dict[int, str]:
    seed = _normalize_subscription_levels(CONFIG.get("subscriptions", {}).get("levels", {}))
    return seed if seed else {1: "Default"}


def serialize_subscription_levels(levels: dict[int, str]) -> dict[str, str]:
    return {str(k): v for k, v in sorted(levels.items())}


def app_settings_seed(seed_levels: dict[int, str] | None = None) -> dict[str, Any]:
    return {"subscription_levels": serialize_subscription_levels(seed_levels or subscription_levels_seed())}


def subscription_levels(
    conn: sqlite3.Connection | None = None,
    app: sqlite3.Row | dict[str, Any] | str | None = None,
) -> dict[int, str]:
    if app is None:
        return subscription_levels_seed()
    row = None
    if isinstance(app, str):
        if conn is None:
            return subscription_levels_seed()
        row = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app,)).fetchone()
    else:
        row = app
    if not row:
        return subscription_levels_seed()
    levels = _normalize_subscription_levels(app_settings(row).get("subscription_levels"))
    return levels if levels else subscription_levels_seed()


def save_app_subscription_levels(conn: sqlite3.Connection, app_id: str, levels: dict[int, str]) -> None:
    row = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
    if not row:
        raise ValueError(f"Application not found: {app_id}")
    settings = app_settings(row)
    settings["subscription_levels"] = serialize_subscription_levels(levels)
    conn.execute(
        """
        UPDATE apps
        SET settings_json = ?, updated_at = ?
        WHERE app_id = ?
        """,
        (json.dumps(settings), utc_now(), app_id),
    )


def ensure_app_subscription_levels(conn: sqlite3.Connection) -> None:
    seeded = serialize_subscription_levels(subscription_levels_seed())
    for row in conn.execute("SELECT * FROM apps ORDER BY id").fetchall():
        settings = app_settings(row)
        if _normalize_subscription_levels(settings.get("subscription_levels")):
            continue
        settings["subscription_levels"] = dict(seeded)
        conn.execute(
            """
            UPDATE apps
            SET settings_json = ?, updated_at = ?
            WHERE app_id = ?
            """,
            (json.dumps(settings), utc_now(), row["app_id"]),
        )


def config_value(path: str, default: Any = None) -> Any:
    current: Any = CONFIG
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def config_str(path: str, default: str = "") -> str:
    value = config_value(path, default)
    return str(value if value is not None else default)


def config_int(path: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        value = int(config_value(path, default))
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def config_bool(path: str, default: bool = False) -> bool:
    value = config_value(path, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def config_list(path: str, default: list[str]) -> list[str]:
    value = config_value(path, default)
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [item.strip() for item in value.split(",") if item.strip()]
    return default


def config_choice(path: str, default: str, allowed: set[str]) -> str:
    value = config_str(path, default).strip().lower()
    return value if value in allowed else default


def server_mode() -> str:
    return config_choice("server.mode", "combined", {"combined", "split"})


def listener_targets() -> dict[str, dict[str, Any]]:
    combined_host = config_str("server.host", "127.0.0.1").strip() or "127.0.0.1"
    combined_port = config_int("server.port", 8080, 1, 65535)
    mode = server_mode()
    if mode == "split":
        admin_host = config_str("server.admin_host", combined_host).strip() or combined_host
        admin_port = config_int("server.admin_port", combined_port, 1, 65535)
        api_host = config_str("server.api_host", combined_host).strip() or combined_host
        api_port = config_int("server.api_port", 1488, 1, 65535)
        return {
            "mode": mode,
            "admin": {"host": admin_host, "port": admin_port},
            "api": {"host": api_host, "port": api_port},
        }
    return {
        "mode": "combined",
        "admin": {"host": combined_host, "port": combined_port},
        "api": {"host": combined_host, "port": combined_port},
    }


def config_text() -> str:
    if CONFIG_PATH.exists():
        return CONFIG_PATH.read_text(encoding="utf-8")
    return dump_simple_yaml(DEFAULT_CONFIG) + "\n"


def update_banner_enabled() -> bool:
    return config_bool("ui.update_banner_enabled", True)


def _strict_int(value: Any) -> int | None:
    raw = str(value or "").strip()
    if not raw or not re.fullmatch(r"-?\d+", raw):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _host_policy_error(label: str, value: Any) -> str:
    host = str(value or "").strip()
    if not host:
        return f"{label} cannot be empty."
    if len(host) > 255:
        return f"{label} is too long."
    if any(ch.isspace() for ch in host):
        return f"{label} cannot contain spaces."
    return ""


def _header_name_policy_error(label: str, value: Any) -> str:
    header = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{2,64}", header):
        return f"{label} must use only letters, numbers, and dashes."
    return ""


def _http_url_policy_error(label: str, value: Any) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return f"{label} must be a full http:// or https:// URL."
    return ""


def validate_duration_form(value: Any, unit: Any, field_name: str = "Duration") -> tuple[int | None, str]:
    unit_key = str(unit or "days").strip().lower()
    if unit_key not in {"hours", "days", "weeks", "months", "years", "lifetime"}:
        return None, f"{field_name} unit is invalid."
    if unit_key == "lifetime":
        return None, ""
    amount = _strict_int(value)
    if amount is None:
        return None, f"{field_name} value must be a whole number."
    if amount < 1 or amount > 36500:
        return None, f"{field_name} value must be between 1 and 36500."
    return min(amount * DURATION_UNITS.get(unit_key, DURATION_UNITS["days"]), DURATION_UNITS["years"] * 100), ""


def app_id_policy_error(value: Any) -> str:
    app_id = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", app_id):
        return "App ID must be 2-64 characters: letters, numbers, dot, dash, underscore."
    return ""


def app_name_policy_error(value: Any) -> str:
    name = clean_text(value, 80)
    if not name:
        return "Application name cannot be empty."
    return ""


def normalize_prefix(value: Any, fallback: str = "KB") -> str:
    return "".join(ch for ch in clean_text(value, 8).upper() if ch.isalnum())[:8] or fallback


def prefix_policy_error(value: Any, field_name: str = "Prefix") -> str:
    prefix = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{1,8}", prefix):
        return f"{field_name} must be 1-8 letters or numbers."
    return ""


def app_secret_policy_error(value: Any, *, required: bool = False) -> str:
    secret = str(value or "")
    if not secret:
        return "App secret is required." if required else ""
    if secret != secret.strip():
        return "App secret cannot start or end with spaces."
    if len(secret) < 8:
        return "App secret must be at least 8 characters."
    if len(secret) > 256:
        return "App secret must be 256 characters or less."
    if any(ord(ch) < 32 for ch in secret):
        return "App secret cannot contain control characters."
    return ""


def text_field_policy_error(
    value: Any,
    *,
    field_name: str,
    max_length: int,
    required: bool = False,
) -> str:
    raw = str(value or "")
    cleaned = clean_text(raw, max_length)
    if required and not cleaned:
        return f"{field_name} cannot be empty."
    if len(raw.strip()) > max_length:
        return f"{field_name} must be {max_length} characters or less."
    if any(ord(ch) < 32 for ch in raw):
        return f"{field_name} cannot contain control characters."
    return ""


def ban_value_policy_error(kind: str, value: Any) -> str:
    kind_key = str(kind or "").strip().lower()
    raw = clean_text(value, 128)
    if not raw:
        return "Ban value cannot be empty."
    if kind_key == "ip":
        try:
            if "/" in raw:
                network = ipaddress.ip_network(raw, strict=False)
                if network.version != 4:
                    return "IP ban must use IPv4 only."
            else:
                address = ipaddress.ip_address(raw)
                if address.version != 4:
                    return "IP ban must use IPv4 only."
        except ValueError:
            return "IP ban must be a valid IPv4 address or IPv4 CIDR range."
        return ""
    if kind_key == "hwid":
        if not looks_like_hwid(normalize_hwid(raw)):
            return "HWID ban looks too short or fake."
        return ""
    if kind_key == "country":
        if normalize_country(raw) not in COUNTRIES:
            return "Country ban must use a real 2-letter country code."
        return ""
    return "Ban kind is invalid."


def validate_config_map(merged: dict[str, Any]) -> str:
    mode = str(merged.get("server", {}).get("mode", "combined") or "").strip().lower()
    if mode not in {"combined", "split"}:
        return "server.mode must be combined or split."
    host_error = _host_policy_error("server.host", merged.get("server", {}).get("host", ""))
    if host_error:
        return host_error
    port = _strict_int(merged.get("server", {}).get("port", ""))
    if port is None or port < 1 or port > 65535:
        return "server.port must be between 1 and 65535."
    if mode == "split":
        admin_host = merged.get("server", {}).get("admin_host", "")
        api_host = merged.get("server", {}).get("api_host", "")
        for label, host_value in (("server.admin_host", admin_host), ("server.api_host", api_host)):
            error = _host_policy_error(label, host_value)
            if error:
                return error
        admin_port = _strict_int(merged.get("server", {}).get("admin_port", ""))
        api_port = _strict_int(merged.get("server", {}).get("api_port", ""))
        if admin_port is None or admin_port < 1 or admin_port > 65535:
            return "server.admin_port must be between 1 and 65535."
        if api_port is None or api_port < 1 or api_port > 65535:
            return "server.api_port must be between 1 and 65535."
        if str(admin_host).strip() == str(api_host).strip() and admin_port == api_port:
            return "Split mode requires admin and API listeners to use different host/port targets."
    else:
        combined_host = str(merged.get("server", {}).get("host", "")).strip()
        combined_port = port
        admin_host = str(merged.get("server", {}).get("admin_host", "")).strip()
        api_host = str(merged.get("server", {}).get("api_host", "")).strip()
        admin_port = _strict_int(merged.get("server", {}).get("admin_port", ""))
        api_port = _strict_int(merged.get("server", {}).get("api_port", ""))
        if admin_host and admin_host != combined_host:
            return "server.admin_host is used only in split mode. Set server.mode: split or keep it equal to server.host."
        if api_host and api_host != combined_host:
            return "server.api_host is used only in split mode. Set server.mode: split or keep it equal to server.host."
        if admin_port is not None and admin_port != combined_port:
            return "server.admin_port is used only in split mode. Set server.mode: split or keep it equal to server.port."
        if api_port is not None and api_port != combined_port:
            return "server.api_port is used only in split mode. Set server.mode: split or keep it equal to server.port."
    for label, url_value in (
        ("api.public_base_url", merged.get("api", {}).get("public_base_url", "")),
        ("admin.public_base_url", merged.get("admin", {}).get("public_base_url", "")),
    ):
        error = _http_url_policy_error(label, url_value)
        if error:
            return error
    database_config = merged.get("database", {})
    if not isinstance(database_config, dict):
        return "database must be a YAML mapping."
    try:
        backend = db.normalize_backend(database_config.get("backend", "sqlite"))
    except db.DatabaseConfigurationError as exc:
        return str(exc)
    db_url = str(database_config.get("url", "") or "").strip()
    if db_url:
        try:
            parsed = db._parse_url(db_url)
        except Exception as exc:
            return f"database.url is invalid: {exc}"
        backend = parsed["backend"]
    if backend == "sqlite":
        sqlite_path = clean_text(database_config.get("sqlite_path", ""), 260)
        if not sqlite_path:
            return "database.sqlite_path cannot be empty when database.backend is sqlite."
    else:
        host = clean_text(database_config.get("host", ""), 255)
        name = clean_text(database_config.get("name", ""), 120)
        user = clean_text(database_config.get("user", ""), 120)
        if not db_url and not host:
            return "database.host cannot be empty when using PostgreSQL or MySQL without database.url."
        if not db_url and not name:
            return "database.name cannot be empty when using PostgreSQL or MySQL without database.url."
        if not db_url and not user:
            return "database.user cannot be empty when using PostgreSQL or MySQL without database.url."
    db_port_raw = str(database_config.get("port", "") or "").strip()
    if db_port_raw:
        db_port = _strict_int(database_config.get("port"))
        if db_port is None or db_port < 1 or db_port > 65535:
            return "database.port must be between 1 and 65535."
    ssl_mode = str(database_config.get("ssl_mode", "prefer") or "").strip().lower()
    if ssl_mode not in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
        return "database.ssl_mode must be disable, allow, prefer, require, verify-ca, or verify-full."
    connect_timeout = _strict_int(database_config.get("connect_timeout_seconds", 10))
    if connect_timeout is None or connect_timeout < 1 or connect_timeout > 60:
        return "database.connect_timeout_seconds must be between 1 and 60."
    password_min = _strict_int(merged.get("security", {}).get("password_min_length", ""))
    if password_min is None or password_min < 6 or password_min > 256:
        return "security.password_min_length must be between 6 and 256."
    verify_rate = _strict_int(merged.get("api", {}).get("verify_rate_limit_per_minute", ""))
    if verify_rate is None or verify_rate < 1 or verify_rate > 100_000:
        return "api.verify_rate_limit_per_minute must be between 1 and 100000."
    geoip_timeout = _strict_int(merged.get("api", {}).get("geoip_timeout_seconds", ""))
    if geoip_timeout is None or geoip_timeout < 1 or geoip_timeout > 15:
        return "api.geoip_timeout_seconds must be between 1 and 15."
    if not isinstance(merged.get("api", {}).get("allow_payload_ip_fallback"), bool):
        return "api.allow_payload_ip_fallback must be true or false."
    accepted_ip_headers = merged.get("api", {}).get("accepted_ip_headers", [])
    if not isinstance(accepted_ip_headers, list) or not accepted_ip_headers:
        return "api.accepted_ip_headers must be a non-empty YAML list."
    for header in accepted_ip_headers:
        error = _header_name_policy_error("api.accepted_ip_headers", header)
        if error:
            return error
    accepted_headers = merged.get("api", {}).get("accepted_country_headers", [])
    if not isinstance(accepted_headers, list) or not accepted_headers:
        return "api.accepted_country_headers must be a non-empty YAML list."
    for header in accepted_headers:
        error = _header_name_policy_error("api.accepted_country_headers", header)
        if error:
            return error
    cloudflare_header_error = _header_name_policy_error("cloudflare.country_header", merged.get("cloudflare", {}).get("country_header", ""))
    if cloudflare_header_error:
        return cloudflare_header_error
    provisioning = merged.get("provisioning", {})
    enabled = str(provisioning.get("enabled", "")).strip().lower() in {"1", "true", "yes", "on"}
    header_error = _header_name_policy_error("provisioning.header_name", provisioning.get("header_name", ""))
    if header_error:
        return header_error
    env_provision_token = (os.environ.get("KEYBASE_PROVISION_TOKEN", "").strip()
                           or os.environ.get("KEYBASE_PROVISIONING_TOKEN", "").strip())
    if enabled and not str(provisioning.get("shared_token", "")).strip() and not env_provision_token:
        return "provisioning.shared_token cannot be empty when provisioning is enabled unless KEYBASE_PROVISION_TOKEN is set."
    prefix_error = prefix_policy_error(provisioning.get("default_prefix", "KB"), "provisioning.default_prefix")
    if prefix_error:
        return prefix_error
    default_devices = _strict_int(provisioning.get("default_max_devices", ""))
    if default_devices is None or default_devices < 1 or default_devices > 999:
        return "provisioning.default_max_devices must be between 1 and 999."
    max_batch = _strict_int(provisioning.get("max_batch_size", ""))
    if max_batch is None or max_batch < 1 or max_batch > 200:
        return "provisioning.max_batch_size must be between 1 and 200."
    _duration, duration_error = validate_duration_form(
        provisioning.get("default_duration_value", 30),
        provisioning.get("default_duration_unit", "days"),
        "provisioning.default_duration",
    )
    if duration_error:
        return duration_error
    rate = _strict_int(provisioning.get("rate_limit_per_minute", ""))
    if rate is None or rate < 1 or rate > 10_000:
        return "provisioning.rate_limit_per_minute must be between 1 and 10000."
    backup = merged.get("backup", {})
    backup_dir = clean_text(backup.get("directory", ""), 180)
    if not backup_dir:
        return "backup.directory cannot be empty."
    interval = _strict_int(backup.get("interval_minutes", ""))
    if interval is None or interval < 5 or interval > 10080:
        return "backup.interval_minutes must be between 5 and 10080."
    keep_last = _strict_int(backup.get("keep_last", ""))
    if keep_last is None or keep_last < 1 or keep_last > 500:
        return "backup.keep_last must be between 1 and 500."
    protection = merged.get("protection", {})
    mode_value = str(protection.get("mode", "warn") or "").strip().lower()
    if mode_value not in {"warn", "block", "restrict", "strict"}:
        return "protection.mode must be warn, block, restrict, or strict."
    anti_mode_value = str(protection.get("anti_mode", "warn") or "").strip().lower()
    if anti_mode_value not in {"off", "warn", "strict"}:
        return "protection.anti_mode must be off, warn, or strict."
    for bool_key in ("anti_vm", "anti_vpn", "anti_proxy", "anti_debug", "anti_tamper", "anti_sandbox"):
        if not isinstance(protection.get(bool_key), bool):
            return f"protection.{bool_key} must be true or false."
    for bool_key in ("free_ip_intel", "tor_exit_list"):
        if bool_key in protection and not isinstance(protection.get(bool_key), bool):
            return f"protection.{bool_key} must be true or false."
    for list_key in (
        "ip_whitelist",
        "hwid_whitelist",
        "country_whitelist",
        "vm_keywords",
        "vpn_keywords",
        "proxy_keywords",
        "suspicious_ua_keywords",
        "datacenter_keywords",
        "debug_keywords",
        "tamper_keywords",
        "sandbox_keywords",
    ):
        if not isinstance(protection.get(list_key, []), list):
            return f"protection.{list_key} must be a YAML list."
    for allowed_ip in protection.get("ip_whitelist", []):
        raw_ip = str(allowed_ip or "").strip()
        if not raw_ip:
            continue
        try:
            if "/" in raw_ip:
                ipaddress.ip_network(raw_ip, strict=False)
            else:
                ipaddress.ip_address(raw_ip)
        except ValueError:
            return "protection.ip_whitelist must contain valid IP addresses or CIDR ranges."
    for allowed_country in protection.get("country_whitelist", []):
        if normalize_country(str(allowed_country or "")) not in COUNTRIES:
            return "protection.country_whitelist must contain real 2-letter country codes."
    reputation_url = str(protection.get("ip_reputation_url", "") or "").strip()
    if reputation_url:
        reputation_error = _http_url_policy_error("protection.ip_reputation_url", reputation_url.replace("{ip}", "127.0.0.1"))
        if reputation_error:
            return reputation_error
    reputation_timeout = _strict_int(protection.get("ip_reputation_timeout_seconds", ""))
    if reputation_timeout is None or reputation_timeout < 1 or reputation_timeout > 15:
        return "protection.ip_reputation_timeout_seconds must be between 1 and 15."
    reputation_cache = _strict_int(protection.get("ip_reputation_cache_seconds", ""))
    if reputation_cache is None or reputation_cache < 0 or reputation_cache > 86400:
        return "protection.ip_reputation_cache_seconds must be between 0 and 86400."
    request_window = _strict_int(protection.get("request_window_seconds", DEFAULT_CONFIG["protection"]["request_window_seconds"]))
    if request_window is None or request_window < 1 or request_window > 300:
        return "protection.request_window_seconds must be between 1 and 300."
    too_fast = _strict_int(protection.get("too_fast_threshold", DEFAULT_CONFIG["protection"]["too_fast_threshold"]))
    if too_fast is None or too_fast < 2 or too_fast > 10000:
        return "protection.too_fast_threshold must be between 2 and 10000."
    risk_threshold = _strict_int(protection.get("risk_threshold", ""))
    if risk_threshold is None or risk_threshold < 1 or risk_threshold > 100:
        return "protection.risk_threshold must be between 1 and 100."
    for threshold_key in ("challenge_threshold", "hard_challenge_threshold", "block_threshold"):
        value = _strict_int(protection.get(threshold_key, DEFAULT_CONFIG["protection"][threshold_key]))
        if value is None or value < 0 or value > 100:
            return f"protection.{threshold_key} must be between 0 and 100."
    signal_threshold = _strict_int(protection.get("signal_threshold", ""))
    if signal_threshold is None or signal_threshold < 1 or signal_threshold > 10:
        return "protection.signal_threshold must be between 1 and 10."
    risk_weights = protection.get("risk_weights", DEFAULT_CONFIG["protection"]["risk_weights"])
    if not isinstance(risk_weights, dict):
        return "protection.risk_weights must be a YAML map."
    for weight_name, weight_value in risk_weights.items():
        parsed_weight = _strict_int(weight_value)
        if parsed_weight is None or parsed_weight < 0 or parsed_weight > 100:
            return f"protection.risk_weights.{weight_name} must be between 0 and 100."
    sub_levels = merged.get("subscriptions", {}).get("levels", {})
    if not isinstance(sub_levels, dict):
        return "subscriptions.levels must be a mapping of numeric IDs to level names."
    if len(sub_levels) > 20:
        return "subscriptions.levels cannot have more than 20 levels."
    seen_ids: set[int] = set()
    for k, v in sub_levels.items():
        try:
            lvl_id = int(str(k))
        except (ValueError, TypeError):
            return f"subscriptions.levels: key '{k}' is not a valid integer ID."
        if lvl_id < 1:
            return f"subscriptions.levels: level ID must be >= 1 (got {lvl_id})."
        if lvl_id in seen_ids:
            return f"subscriptions.levels: duplicate level ID {lvl_id}."
        seen_ids.add(lvl_id)
        name = str(v).strip()
        if not name:
            return f"subscriptions.levels: name for level {lvl_id} cannot be empty."
        if len(name) > 64:
            return f"subscriptions.levels: name for level {lvl_id} exceeds 64 characters."
    return ""


def save_config_text(text: str) -> tuple[bool, str, bool]:
    text = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > 50_000:
        return False, "Config is too large.", False
    parsed = parse_simple_yaml(text)
    merged = deep_merge(DEFAULT_CONFIG, parsed)
    config_error = validate_config_map(merged)
    if config_error:
        return False, config_error, False
    CONFIG_PATH.write_text(text.rstrip() + "\n", encoding="utf-8")
    runtime_note("Config updated — restarting services...", "config")
    _hot_apply("admin-save")
    _update_config_mtime()
    runtime_note("Restart successful", "config")
    return True, t("config_saved_ok"), False


ensure_env_file()
ensure_runtime_stream_capture()
ASSET_DIR = ROOT_DIR / "assets"
TEMPLATE_DIR = ROOT_DIR / "keybase" / "templates"
DATA_DIR = ROOT_DIR / "data"
DB_PATH: Path | None = None
DB_SETTINGS = current_database_settings()
BACKUP_DIR = ROOT_DIR / "backups"
_refresh_storage_globals()
ADMIN_USER = os.environ.get("KEYBASE_ADMIN_USER", "Admin").strip() or "Admin"

KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
COOKIE_NAME = "kb_admin"
CONFIRM_COOKIE_NAME = "kb_confirm"
CONFIRM_UI_COOKIE_NAME = "kb_confirm_until"
SESSION_MAX_SECONDS = config_int("security.session_hours", 12, 1, 24 * 30) * 60 * 60
CONFIRM_WINDOW_SECONDS = config_int("security.confirm_minutes", 15, 1, 24 * 60) * 60
PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PANIC_COOLDOWN_SECONDS = 1800  # 30 minutes minimum before dashboard unlock / disable
PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_MIN_LENGTH = max(6, config_int("security.password_min_length", 6, 6, 256))
PASSWORD_MAX_LENGTH = 256
KEY_STATUSES = {"active", "paused", "disabled", "revoked"}
APP_STATUSES = {"active", "paused", "disabled"}
KEY_STATUS_CHOICES = ("active", "paused", "disabled", "revoked")
APP_STATUS_CHOICES = ("active", "paused", "disabled")
BAN_KINDS = {"ip", "hwid", "country"}
DURATION_UNITS = {
    "hours": 60 * 60,
    "days": 24 * 60 * 60,
    "weeks": 7 * 24 * 60 * 60,
    "months": 30 * 24 * 60 * 60,
    "years": 365 * 24 * 60 * 60,
}
DURATION_LABELS = {
    "hours": "hours",
    "days": "days",
    "weeks": "weeks",
    "months": "months",
    "years": "years",
    "lifetime": "lifetime",
}
GEOIP_TIMEOUT_SECONDS = config_int("api.geoip_timeout_seconds", 2, 1, 15)
COUNTRY_LOOKUP_CACHE_TTL_SECONDS = 6 * 60 * 60
COUNTRY_LOOKUP_FAILURE_TTL_SECONDS = 60
_COUNTRY_LOOKUP_CACHE: dict[str, tuple[str, float]] = {}
_PUBLIC_IP_CACHE: dict[str, Any] = {"ip": "", "method": "", "ts": 0.0}
_PUBLIC_IP_LOCK = threading.Lock()
COUNTRIES = {
    "AR": "Argentina",
    "AT": "Austria",
    "AU": "Australia",
    "BE": "Belgium",
    "BR": "Brazil",
    "CA": "Canada",
    "CH": "Switzerland",
    "CL": "Chile",
    "CN": "China",
    "CO": "Colombia",
    "CZ": "Czechia",
    "DE": "Germany",
    "DK": "Denmark",
    "EE": "Estonia",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "GR": "Greece",
    "HK": "Hong Kong",
    "HU": "Hungary",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IL": "Israel",
    "IN": "India",
    "IT": "Italy",
    "JP": "Japan",
    "KR": "South Korea",
    "KZ": "Kazakhstan",
    "LT": "Lithuania",
    "LV": "Latvia",
    "MX": "Mexico",
    "MY": "Malaysia",
    "NL": "Netherlands",
    "NO": "Norway",
    "NZ": "New Zealand",
    "PH": "Philippines",
    "PL": "Poland",
    "PT": "Portugal",
    "RO": "Romania",
    "RS": "Serbia",
    "RU": "Russia",
    "SE": "Sweden",
    "SG": "Singapore",
    "TH": "Thailand",
    "TR": "Turkey",
    "UA": "Ukraine",
    "US": "United States",
    "VN": "Vietnam",
    "ZA": "South Africa",
}

COUNTRIES.update(
    {
        "AD": "Andorra",
        "AE": "United Arab Emirates",
        "AF": "Afghanistan",
        "AG": "Antigua and Barbuda",
        "AI": "Anguilla",
        "AL": "Albania",
        "AM": "Armenia",
        "AO": "Angola",
        "AQ": "Antarctica",
        "AS": "American Samoa",
        "AW": "Aruba",
        "AX": "Aland Islands",
        "AZ": "Azerbaijan",
        "BA": "Bosnia and Herzegovina",
        "BB": "Barbados",
        "BD": "Bangladesh",
        "BF": "Burkina Faso",
        "BG": "Bulgaria",
        "BH": "Bahrain",
        "BI": "Burundi",
        "BJ": "Benin",
        "BL": "Saint Barthelemy",
        "BM": "Bermuda",
        "BN": "Brunei Darussalam",
        "BO": "Bolivia",
        "BQ": "Bonaire, Sint Eustatius and Saba",
        "BS": "Bahamas",
        "BT": "Bhutan",
        "BV": "Bouvet Island",
        "BW": "Botswana",
        "BY": "Belarus",
        "BZ": "Belize",
        "CC": "Cocos Islands",
        "CD": "Congo, Democratic Republic",
        "CF": "Central African Republic",
        "CG": "Congo",
        "CI": "Cote d'Ivoire",
        "CK": "Cook Islands",
        "CM": "Cameroon",
        "CR": "Costa Rica",
        "CU": "Cuba",
        "CV": "Cabo Verde",
        "CW": "Curacao",
        "CX": "Christmas Island",
        "CY": "Cyprus",
        "DJ": "Djibouti",
        "DM": "Dominica",
        "DO": "Dominican Republic",
        "DZ": "Algeria",
        "EC": "Ecuador",
        "EG": "Egypt",
        "EH": "Western Sahara",
        "ER": "Eritrea",
        "ET": "Ethiopia",
        "FJ": "Fiji",
        "FK": "Falkland Islands",
        "FM": "Micronesia",
        "FO": "Faroe Islands",
        "GA": "Gabon",
        "GD": "Grenada",
        "GE": "Georgia",
        "GF": "French Guiana",
        "GG": "Guernsey",
        "GH": "Ghana",
        "GI": "Gibraltar",
        "GL": "Greenland",
        "GM": "Gambia",
        "GN": "Guinea",
        "GP": "Guadeloupe",
        "GQ": "Equatorial Guinea",
        "GS": "South Georgia and South Sandwich Islands",
        "GT": "Guatemala",
        "GU": "Guam",
        "GW": "Guinea-Bissau",
        "GY": "Guyana",
        "HM": "Heard Island and McDonald Islands",
        "HN": "Honduras",
        "HR": "Croatia",
        "HT": "Haiti",
        "IM": "Isle of Man",
        "IQ": "Iraq",
        "IR": "Iran",
        "IS": "Iceland",
        "JE": "Jersey",
        "JM": "Jamaica",
        "JO": "Jordan",
        "KE": "Kenya",
        "KG": "Kyrgyzstan",
        "KH": "Cambodia",
        "KI": "Kiribati",
        "KM": "Comoros",
        "KN": "Saint Kitts and Nevis",
        "KP": "North Korea",
        "KW": "Kuwait",
        "KY": "Cayman Islands",
        "LA": "Laos",
        "LB": "Lebanon",
        "LC": "Saint Lucia",
        "LI": "Liechtenstein",
        "LK": "Sri Lanka",
        "LR": "Liberia",
        "LS": "Lesotho",
        "LU": "Luxembourg",
        "LY": "Libya",
        "MA": "Morocco",
        "MC": "Monaco",
        "MD": "Moldova",
        "ME": "Montenegro",
        "MF": "Saint Martin",
        "MG": "Madagascar",
        "MH": "Marshall Islands",
        "MK": "North Macedonia",
        "ML": "Mali",
        "MM": "Myanmar",
        "MN": "Mongolia",
        "MO": "Macao",
        "MP": "Northern Mariana Islands",
        "MQ": "Martinique",
        "MR": "Mauritania",
        "MS": "Montserrat",
        "MT": "Malta",
        "MU": "Mauritius",
        "MV": "Maldives",
        "MW": "Malawi",
        "MZ": "Mozambique",
        "NA": "Namibia",
        "NC": "New Caledonia",
        "NE": "Niger",
        "NF": "Norfolk Island",
        "NG": "Nigeria",
        "NI": "Nicaragua",
        "NP": "Nepal",
        "NR": "Nauru",
        "NU": "Niue",
        "OM": "Oman",
        "PA": "Panama",
        "PE": "Peru",
        "PF": "French Polynesia",
        "PG": "Papua New Guinea",
        "PK": "Pakistan",
        "PM": "Saint Pierre and Miquelon",
        "PN": "Pitcairn",
        "PR": "Puerto Rico",
        "PS": "Palestine",
        "PY": "Paraguay",
        "QA": "Qatar",
        "RE": "Reunion",
        "RW": "Rwanda",
        "SA": "Saudi Arabia",
        "SB": "Solomon Islands",
        "SC": "Seychelles",
        "SD": "Sudan",
        "SH": "Saint Helena",
        "SI": "Slovenia",
        "SJ": "Svalbard and Jan Mayen",
        "SK": "Slovakia",
        "SL": "Sierra Leone",
        "SM": "San Marino",
        "SN": "Senegal",
        "SO": "Somalia",
        "SR": "Suriname",
        "SS": "South Sudan",
        "ST": "Sao Tome and Principe",
        "SV": "El Salvador",
        "SX": "Sint Maarten",
        "SY": "Syria",
        "SZ": "Eswatini",
        "TC": "Turks and Caicos Islands",
        "TD": "Chad",
        "TF": "French Southern Territories",
        "TG": "Togo",
        "TJ": "Tajikistan",
        "TK": "Tokelau",
        "TL": "Timor-Leste",
        "TM": "Turkmenistan",
        "TN": "Tunisia",
        "TO": "Tonga",
        "TT": "Trinidad and Tobago",
        "TV": "Tuvalu",
        "TW": "Taiwan",
        "TZ": "Tanzania",
        "UG": "Uganda",
        "UM": "United States Minor Outlying Islands",
        "UY": "Uruguay",
        "UZ": "Uzbekistan",
        "VA": "Holy See",
        "VC": "Saint Vincent and the Grenadines",
        "VE": "Venezuela",
        "VG": "Virgin Islands, British",
        "VI": "Virgin Islands, U.S.",
        "VU": "Vanuatu",
        "WF": "Wallis and Futuna",
        "WS": "Samoa",
        "XK": "Kosovo",
        "YE": "Yemen",
        "YT": "Mayotte",
        "ZM": "Zambia",
        "ZW": "Zimbabwe",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


API_RUNTIME_ENABLED = True
API_RUNTIME_STARTED_AT = utc_now()
API_RUNTIME_LOG: list[str] = [f"{API_RUNTIME_STARTED_AT} API runtime booted"]


def api_runtime_enabled() -> bool:
    return API_RUNTIME_ENABLED


def api_runtime_uptime() -> str:
    start = iso_datetime(API_RUNTIME_STARTED_AT)
    if start is None or not API_RUNTIME_ENABLED:
        return "stopped"
    seconds = max(0, int((datetime.now(timezone.utc) - start).total_seconds()))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {seconds}s"


def set_api_runtime_state(action: str, actor_ip: str = "") -> tuple[str, str]:
    global API_RUNTIME_ENABLED, API_RUNTIME_STARTED_AT
    action = (action or "").strip().lower()
    now = utc_now()
    if action == "start":
        if API_RUNTIME_ENABLED:
            status, message = "api_already_running", "API is already running"
        else:
            API_RUNTIME_ENABLED = True
            API_RUNTIME_STARTED_AT = now
            status, message = "api_started", "API runtime started"
    elif action == "stop":
        if not API_RUNTIME_ENABLED:
            status, message = "api_already_stopped", "API is already stopped"
        else:
            API_RUNTIME_ENABLED = False
            status, message = "api_stopped", "API runtime stopped. Verify endpoints now return 503."
    elif action == "restart":
        API_RUNTIME_ENABLED = True
        API_RUNTIME_STARTED_AT = now
        status, message = "api_restarted", "API runtime restarted"
    else:
        status, message = "api_action_rejected", "Unknown API runtime action"
    who = f" by {actor_ip}" if actor_ip else ""
    API_RUNTIME_LOG.append(f"{now} {status}{who}: {message}")
    del API_RUNTIME_LOG[:-30]
    runtime_note(f"{status}{who}: {message}", "api")
    return status, message


def api_runtime_log_text() -> str:
    return "\n".join(API_RUNTIME_LOG[-12:]) or "No runtime actions yet."


def runtime_console_text(limit: int = 180) -> str:
    with PROCESS_LOG_LOCK:
        lines = list(PROCESS_LOG_BUFFER)[-max(1, limit) :]
        for stream_name in ("stdout", "stderr"):
            partial = PROCESS_LOG_PARTIALS.get(stream_name, "").strip()
            if partial:
                lines.append(partial[:4000])
    operator_lines = API_RUNTIME_LOG[-16:]
    merged = operator_lines + lines
    return "\n".join(merged[-max(1, limit) :]) or "No runtime output yet."


def format_bytes(value: int | float) -> str:
    size = float(value or 0)
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return "0 B"


def system_memory_text() -> str:
    try:
        if os.name == "nt":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            used = stat.ullTotalPhys - stat.ullAvailPhys
            return f"{format_bytes(used)} used / {format_bytes(stat.ullTotalPhys)} total ({stat.dwMemoryLoad}%)"
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        total = pages * page_size
        return f"{format_bytes(total)} total"
    except (AttributeError, OSError, ValueError):
        return "unavailable"


def system_disk_text(root: Path | None = None) -> str:
    disk_root = root or (DATA_DIR if DATA_DIR.exists() else ROOT_DIR)
    try:
        disk = shutil.disk_usage(disk_root)
        return f"{format_bytes(disk.free)} free / {format_bytes(disk.total)} total"
    except OSError:
        return "unavailable"


def system_load_text() -> str:
    try:
        if os.name == "nt":
            import ctypes

            class FILETIME(ctypes.Structure):
                _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

            def _filetime_value(filetime: FILETIME) -> int:
                return (int(filetime.dwHighDateTime) << 32) | int(filetime.dwLowDateTime)

            idle = FILETIME()
            kernel = FILETIME()
            user = FILETIME()
            if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
                idle_value = _filetime_value(idle)
                kernel_value = _filetime_value(kernel)
                user_value = _filetime_value(user)
                with SYSTEM_CPU_SAMPLE_LOCK:
                    prev_idle = float(SYSTEM_CPU_SAMPLE.get("idle", 0.0))
                    prev_kernel = float(SYSTEM_CPU_SAMPLE.get("kernel", 0.0))
                    prev_user = float(SYSTEM_CPU_SAMPLE.get("user", 0.0))
                    percent = float(SYSTEM_CPU_SAMPLE.get("percent", 0.0))
                    if prev_kernel or prev_user:
                        idle_delta = max(0.0, idle_value - prev_idle)
                        kernel_delta = max(0.0, kernel_value - prev_kernel)
                        user_delta = max(0.0, user_value - prev_user)
                        total = kernel_delta + user_delta
                        if total > 0:
                            percent = max(0.0, min(100.0, ((total - idle_delta) / total) * 100.0))
                    SYSTEM_CPU_SAMPLE.update(
                        {"idle": float(idle_value), "kernel": float(kernel_value), "user": float(user_value), "percent": percent}
                    )
                return f"{percent:.1f}%"
        return ", ".join(f"{value:.2f}" for value in os.getloadavg())
    except (AttributeError, OSError):
        return "n/a on Windows"


def process_cpu_text() -> str:
    now_wall = time.perf_counter()
    now_proc = time.process_time()
    cores = max(os.cpu_count() or 1, 1)
    with PROCESS_CPU_SAMPLE_LOCK:
        prev_wall = float(PROCESS_CPU_SAMPLE.get("wall", now_wall))
        prev_proc = float(PROCESS_CPU_SAMPLE.get("proc", now_proc))
        percent = float(PROCESS_CPU_SAMPLE.get("percent", 0.0))
        wall_delta = now_wall - prev_wall
        proc_delta = now_proc - prev_proc
        if wall_delta > 0.05 and proc_delta >= 0:
            percent = max(0.0, min(100.0, (proc_delta / wall_delta) * 100.0 / cores))
        PROCESS_CPU_SAMPLE.update({"wall": now_wall, "proc": now_proc, "percent": percent})
    return f"{percent:.1f}%"


def process_memory_usage() -> tuple[int | None, int | None]:
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            counters = PROCESS_MEMORY_COUNTERS_EX()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            if psapi.GetProcessMemoryInfo(
                kernel32.GetCurrentProcess(),
                ctypes.byref(counters),
                counters.cb,
            ):
                return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)
        status_path = Path("/proc/self/status")
        if status_path.exists():
            rss = None
            peak = None
            for raw_line in status_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if raw_line.startswith("VmRSS:"):
                    parts = raw_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rss = int(parts[1]) * 1024
                elif raw_line.startswith("VmHWM:"):
                    parts = raw_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        peak = int(parts[1]) * 1024
            if rss is not None:
                return rss, peak
    except OSError:
        return None, None
    return None, None


def process_memory_text() -> tuple[str, str]:
    current, peak = process_memory_usage()
    if current is None:
        return "unavailable", "working set unavailable"
    detail = f"peak {format_bytes(peak)}" if peak else "current working set"
    return format_bytes(current), detail


def _path_size_bytes(path: Path) -> int:
    try:
        if not path.exists():
            return 0
        if path.is_file():
            return int(path.stat().st_size)
    except OSError:
        return 0
    total = 0
    try:
        for item in path.rglob("*"):
            try:
                if item.is_file():
                    total += int(item.stat().st_size)
            except OSError:
                continue
    except OSError:
        return 0
    return total


def keybase_storage_usage() -> tuple[int, str]:
    now = time.time()
    with PROCESS_STORAGE_LOCK:
        if now - float(PROCESS_STORAGE_CACHE.get("at", 0.0)) < 15:
            return int(PROCESS_STORAGE_CACHE.get("bytes", 0)), str(PROCESS_STORAGE_CACHE.get("detail", "Storage footprint unavailable."))
    parts: list[tuple[str, int]] = []
    seen: set[str] = set()
    for label, path in (
        ("data", DATA_DIR),
        ("backups", backup_directory()),
        ("config", CONFIG_PATH),
        ("env", ENV_PATH),
    ):
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        size = _path_size_bytes(path)
        if size:
            parts.append((label, size))
    total = sum(size for _label, size in parts)
    detail = ", ".join(f"{label} {format_bytes(size)}" for label, size in parts) or "No project data written yet."
    with PROCESS_STORAGE_LOCK:
        PROCESS_STORAGE_CACHE.update({"at": now, "bytes": total, "detail": detail})
    return total, detail


def backup_settings() -> dict[str, Any]:
    directory = clean_text(config_str("backup.directory", "backups"), 180) or "backups"
    return {
        "directory": directory,
        "auto_enabled": config_bool("backup.auto_enabled", True),
        "interval_minutes": config_int("backup.interval_minutes", 60, 5, 10080),
        "keep_last": config_int("backup.keep_last", 24, 1, 500),
        "include_database": config_bool("backup.include_database", True),
        "include_config": config_bool("backup.include_config", True),
        "include_env": config_bool("backup.include_env", True),
    }


def backup_directory() -> Path:
    configured = Path(backup_settings()["directory"])
    return configured if configured.is_absolute() else ROOT_DIR / configured


def backup_status() -> dict[str, Any]:
    settings = backup_settings()
    status = dict(BACKUP_STATUS)
    status["directory"] = str(backup_directory())
    status["auto_enabled"] = settings["auto_enabled"]
    status["interval_minutes"] = settings["interval_minutes"]
    status["keep_last"] = settings["keep_last"]
    return status


def backup_file_count() -> int:
    folder = backup_directory()
    if not folder.exists():
        return 0
    return sum(1 for _item in folder.glob("keybase-backup-*.zip"))


def list_backups(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    folder = backup_directory()
    if not folder.exists():
        return []
    rows: list[dict[str, Any]] = []
    limit = max(1, int(limit or 50))
    offset = max(0, int(offset or 0))
    files = sorted(folder.glob("keybase-backup-*.zip"), key=lambda path: path.stat().st_mtime, reverse=True)
    for item in files[offset : offset + limit]:
        metadata: dict[str, Any] = {}
        try:
            with zipfile.ZipFile(item) as archive:
                if "metadata.json" in archive.namelist():
                    metadata = json.loads(archive.read("metadata.json").decode("utf-8"))
        except (OSError, zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError):
            metadata = {}
        stat = item.stat()
        rows.append(
            {
                "name": item.name,
                "path": str(item),
                "size": format_bytes(stat.st_size),
                "size_bytes": stat.st_size,
                "created_at": metadata.get("created_at") or datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).replace(microsecond=0).isoformat(),
                "reason": metadata.get("reason") or "manual",
                "items": ", ".join(metadata.get("items", [])) or "archive",
            }
        )
    return rows


def cleanup_old_backups() -> None:
    keep_last = backup_settings()["keep_last"]
    backups = list_backups(limit=1000)
    for row in backups[keep_last:]:
        try:
            Path(row["path"]).unlink(missing_ok=True)
        except OSError:
            continue


def create_backup(reason: str = "manual", actor_ip: str = "") -> tuple[bool, str, str]:
    folder = backup_directory()
    settings = backup_settings()
    reason_clean = clean_text(reason, 32) or "manual"
    folder.mkdir(parents=True, exist_ok=True)
    created_at = utc_now()
    slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive_path = folder / f"keybase-backup-{slug}.zip"
    backup_note = f"{reason_clean} backup started"
    if actor_ip:
        backup_note += f" by {actor_ip}"
    runtime_note(backup_note, "backup")
    with BACKUP_LOCK:
        BACKUP_STATUS.update(
            {
                "running": True,
                "last_started_at": created_at,
                "last_status": "running",
                "last_message": "Backup in progress",
            }
        )
        temp_db_path: Path | None = None
        exported_db_bytes: bytes | None = None
        items: list[str] = []
        try:
            if settings["include_database"]:
                if DB_SETTINGS.backend == "sqlite" and DB_PATH and DB_PATH.exists():
                    temp_handle = tempfile.NamedTemporaryFile(prefix="keybase-backup-", suffix=".sqlite3", delete=False)
                    temp_handle.close()
                    temp_db_path = Path(temp_handle.name)
                    with sqlite3.connect(DB_PATH) as source_conn, sqlite3.connect(temp_db_path) as dest_conn:
                        source_conn.backup(dest_conn)
                    items.append("database")
                else:
                    exported_db_bytes = db.export_database_bytes(DB_SETTINGS)
                    items.append("database")
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                if temp_db_path and temp_db_path.exists():
                    archive.write(temp_db_path, arcname="data/keybase.sqlite3")
                elif exported_db_bytes:
                    archive.writestr("database-export.json", exported_db_bytes)
                if settings["include_config"] and CONFIG_PATH.exists():
                    archive.write(CONFIG_PATH, arcname="config.yml")
                    items.append("config")
                if settings["include_env"] and ENV_PATH.exists():
                    archive.write(ENV_PATH, arcname=".env")
                    items.append("env")
                metadata = {
                    "created_at": created_at,
                    "reason": reason_clean,
                    "actor_ip": actor_ip or "",
                    "items": items,
                    "version": VERSION,
                    "root": str(ROOT_DIR),
                    "database_backend": DB_SETTINGS.backend,
                }
                archive.writestr("metadata.json", json.dumps(metadata, indent=2))
            cleanup_old_backups()
            BACKUP_STATUS.update(
                {
                    "running": False,
                    "last_finished_at": utc_now(),
                    "last_status": "ok",
                    "last_message": f"Backup created: {archive_path.name}",
                    "last_path": str(archive_path),
                }
            )
            runtime_note(f"Backup created: {archive_path}", "backup")
            return True, f"Backup created: {archive_path.name}", str(archive_path)
        except Exception as exc:
            BACKUP_STATUS.update(
                {
                    "running": False,
                    "last_finished_at": utc_now(),
                    "last_status": "error",
                    "last_message": f"Backup failed: {exc}",
                }
            )
            runtime_note(f"Backup failed: {exc}", "backup")
            return False, f"Backup failed: {exc}", ""
        finally:
            if temp_db_path and temp_db_path.exists():
                try:
                    temp_db_path.unlink()
                except OSError:
                    pass


def delete_backup(name: str) -> tuple[bool, str]:
    clean_name = Path(str(name or "")).name
    if not clean_name.endswith(".zip") or clean_name != str(name or "").strip():
        return False, "Invalid backup name."
    target = (backup_directory() / clean_name).resolve()
    folder = backup_directory().resolve()
    if folder not in target.parents or not target.exists():
        return False, "Backup file not found."
    try:
        target.unlink()
        runtime_note(f"Backup deleted: {target.name}", "backup")
        return True, f"Backup deleted: {target.name}"
    except OSError as exc:
        return False, f"Could not delete backup: {exc}"


def _backup_worker_loop(gen: int) -> None:
    last_run = 0.0
    runtime_note("Backup worker online", "backup")
    while _WORKER_GENERATION == gen:
        try:
            settings = backup_settings()
            if settings["auto_enabled"]:
                now = time.time()
                interval = max(300, settings["interval_minutes"] * 60)
                if now - last_run >= interval:
                    ok, message, _path = create_backup("auto")
                    runtime_note(message, "backup")
                    last_run = time.time()
            else:
                last_run = time.time()
        except Exception as exc:
            runtime_note(f"Backup worker error: {exc}", "backup")
        for _ in range(30):
            if _WORKER_GENERATION != gen:
                return
            time.sleep(1)


def _sweep_expired_keys() -> int:
    """Store expires_at for duration-based keys that have expired but have no recorded expiry date.
    Fires key.expired webhooks for each such key. Returns count processed."""
    count = 0
    try:
        with db_connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM license_keys
                WHERE status = 'active'
                  AND expires_at IS NULL
                  AND duration_seconds IS NOT NULL
                  AND activated_at IS NOT NULL
                """,
            ).fetchall()
            for row in rows:
                activated_at = row_value(row, "activated_at")
                duration_seconds = positive_duration_seconds(row_value(row, "duration_seconds"))
                if not activated_at or not duration_seconds:
                    continue
                expires_at = expires_at_from_duration(activated_at, duration_seconds)
                if not expires_at or not is_expired(expires_at):
                    continue
                conn.execute(
                    "UPDATE license_keys SET expires_at = ? WHERE id = ?",
                    (expires_at, row["id"]),
                )
                enqueue_webhook(conn, "key.expired", row_value(row, "app_id"), {
                    "key": row_value(row, "key_text"),
                    "expired_at": expires_at,
                })
                count += 1
    except Exception as exc:
        runtime_note(f"Expiry sweep error: {exc}", "expiry")
    return count


def _expiry_worker_loop(gen: int) -> None:
    for _ in range(10):
        if _WORKER_GENERATION != gen:
            return
        time.sleep(1)
    runtime_note("Expiry worker online", "expiry")
    while _WORKER_GENERATION == gen:
        try:
            n = _sweep_expired_keys()
            if n:
                runtime_note(f"Expiry sweep: marked {n} expired key(s)", "expiry")
        except Exception as exc:
            runtime_note(f"Expiry worker error: {exc}", "expiry")
        for _ in range(300):
            if _WORKER_GENERATION != gen:
                return
            time.sleep(1)


def restart_background_services() -> None:
    """Gracefully retire current worker threads and spin up fresh ones."""
    global _WORKER_GENERATION
    global BACKGROUND_SERVICES_STARTED
    global BACKUP_WORKER_STARTED, WEBHOOK_WORKER_STARTED, EXPIRY_WORKER_STARTED
    global BACKUP_WORKER_THREAD, WEBHOOK_WORKER_THREAD, EXPIRY_WORKER_THREAD
    _WORKER_GENERATION += 1
    _WEBHOOK_WAKE.set()  # wake webhook worker so it notices the new generation immediately
    BACKGROUND_SERVICES_STARTED = False
    BACKUP_WORKER_STARTED = False
    WEBHOOK_WORKER_STARTED = False
    EXPIRY_WORKER_STARTED = False
    time.sleep(2.0)  # allow old threads to observe the generation change; workers check every 1 s
    ensure_background_services()


def _update_config_mtime() -> None:
    global _LAST_CONFIG_MTIME
    try:
        _LAST_CONFIG_MTIME = CONFIG_PATH.stat().st_mtime
    except Exception:
        pass


def schedule_listener_restart(delay: float = 1.5) -> None:
    """Signal the supervisor loop to restart listeners after a short delay.

    The delay allows the in-flight HTTP response (config save redirect) to finish
    before the server stops accepting connections on the old ports.
    Concurrent calls are debounced — only one restart fires per cycle.
    """
    if _LISTENER_RESTART_PENDING.is_set():
        return  # already scheduled; supervisor will pick it up
    _LISTENER_RESTART_PENDING.set()
    def _fire() -> None:
        time.sleep(delay)
        _LISTENER_RESTART_PENDING.clear()
        runtime_note("Restarting listeners for host/port change...", "config")
        _LISTENER_RESTART_EVENT.set()
    threading.Thread(target=_fire, daemon=True, name="keybase-listener-restart").start()


def _hot_apply(actor: str = "auto") -> None:
    """Apply already-validated config to all services without re-reading or re-validating."""
    old_listeners = listener_targets()
    reload_config()
    refresh_admin_credentials()
    set_api_runtime_state("restart", actor)
    restart_background_services()
    if old_listeners != listener_targets():
        schedule_listener_restart()


def apply_config_hot_reload(actor: str = "auto") -> tuple[bool, str]:
    """Read config.yml from disk, validate it, and if valid hot-apply to all services."""
    global _LAST_CONFIG_MTIME
    runtime_note("Config change detected — validating...", "config")
    try:
        text = CONFIG_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        msg = f"Config reload failed: cannot read file: {exc}"
        runtime_note(msg, "config")
        return False, msg
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > 50_000:
        msg = "Config reload rejected: file too large"
        runtime_note(msg, "config")
        return False, msg
    parsed = parse_simple_yaml(text)
    merged = deep_merge(DEFAULT_CONFIG, parsed)
    error = validate_config_map(merged)
    if error:
        msg = f"Config reload rejected — {error}"
        runtime_note(msg, "config")
        return False, msg
    runtime_note("Config valid — restarting services...", "config")
    _hot_apply(actor)
    _update_config_mtime()
    runtime_note("Restart successful", "config")
    return True, "Restart successful"


def _config_watcher_loop() -> None:
    global _LAST_CONFIG_MTIME
    try:
        _LAST_CONFIG_MTIME = CONFIG_PATH.stat().st_mtime
    except FileNotFoundError:
        _LAST_CONFIG_MTIME = 0.0
    runtime_note("Config watcher online", "config")
    while True:
        time.sleep(3)
        try:
            mtime = CONFIG_PATH.stat().st_mtime
            if mtime != _LAST_CONFIG_MTIME:
                _LAST_CONFIG_MTIME = mtime
                apply_config_hot_reload("file-watcher")
        except FileNotFoundError:
            pass
        except Exception as exc:
            runtime_note(f"Config watcher error: {exc}", "config")


def ensure_background_services() -> None:
    global BACKGROUND_SERVICES_STARTED, BACKUP_WORKER_STARTED, BACKUP_WORKER_THREAD
    global WEBHOOK_WORKER_STARTED, WEBHOOK_WORKER_THREAD
    global EXPIRY_WORKER_STARTED, EXPIRY_WORKER_THREAD
    global CONFIG_WATCHER_STARTED, CONFIG_WATCHER_THREAD
    ensure_runtime_stream_capture()
    if BACKGROUND_SERVICES_STARTED:
        return
    gen = _WORKER_GENERATION
    if not BACKUP_WORKER_STARTED:
        BACKUP_WORKER_THREAD = threading.Thread(target=_backup_worker_loop, args=(gen,), name="keybase-backups", daemon=True)
        BACKUP_WORKER_THREAD.start()
        BACKUP_WORKER_STARTED = True
    if not WEBHOOK_WORKER_STARTED:
        WEBHOOK_WORKER_THREAD = threading.Thread(target=_webhook_worker_loop, args=(gen,), name="keybase-webhooks", daemon=True)
        WEBHOOK_WORKER_THREAD.start()
        WEBHOOK_WORKER_STARTED = True
    if not EXPIRY_WORKER_STARTED:
        EXPIRY_WORKER_THREAD = threading.Thread(target=_expiry_worker_loop, args=(gen,), name="keybase-expiry", daemon=True)
        EXPIRY_WORKER_THREAD.start()
        EXPIRY_WORKER_STARTED = True
    if not CONFIG_WATCHER_STARTED:
        CONFIG_WATCHER_THREAD = threading.Thread(target=_config_watcher_loop, name="keybase-config-watcher", daemon=True)
        CONFIG_WATCHER_THREAD.start()
        CONFIG_WATCHER_STARTED = True
    BACKGROUND_SERVICES_STARTED = True


# ── Webhooks ─────────────────────────────────────────────────────────────────

WEBHOOK_EVENTS: list[str] = [
    "key.created",
    "key.extended",
    "key.activated",
    "key.hwid_reset",
    "key.expired",
]

_WEBHOOK_RETRY_DELAYS = [0, 60, 300, 1800]

# ── Webhook presets ───────────────────────────────────────────────────────────
# body_template: empty string → send native KeyBase JSON payload unchanged.
# {{var}} placeholders are replaced at dispatch time.
# Available vars: event, app_id, key, timestamp, delivery_id, hwid, reason,
#                 expires_at, new_expires_at, duration_seconds.
WEBHOOK_PRESETS: dict[str, dict[str, Any]] = {
    "keybase": {
        "label": "KeyBase Default",
        "desc": "Full signed JSON payload. Best for custom backends.",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": "",
    },
    "discord": {
        "label": "Discord",
        "desc": "Rich embed card to a Discord channel via Incoming Webhook.",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"content":null,"embeds":[{'
            '"title":"KeyBase · {{event}}",'
            '"description":"**Key:** `{{key}}`\\n**App:** `{{app_id}}`",'
            '"color":4886754,'
            '"fields":[{"name":"Event","value":"{{event}}","inline":true},'
            '{"name":"App","value":"{{app_id}}","inline":true}],'
            '"footer":{"text":"KeyBase Webhook"},'
            '"timestamp":"{{timestamp}}"'
            '}]}'
        ),
    },
    "slack": {
        "label": "Slack",
        "desc": "Block Kit message to a Slack Incoming Webhook URL.",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"blocks":[{'
            '"type":"section","text":{"type":"mrkdwn",'
            '"text":"*KeyBase* · `{{event}}`\\n*Key:* `{{key}}`  *App:* `{{app_id}}`"}'
            '},{"type":"context","elements":[{"type":"mrkdwn","text":"{{timestamp}}"}]}]}'
        ),
    },
    "telegram": {
        "label": "Telegram",
        "desc": "Message via Telegram Bot API. Set URL to: https://api.telegram.org/bot{TOKEN}/sendMessage",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"chat_id":"-100YOUR_CHAT_ID",'
            '"text":"🔑 *KeyBase* · `{{event}}`\\nKey: `{{key}}`\\nApp: `{{app_id}}`\\n{{timestamp}}",'
            '"parse_mode":"Markdown"}'
        ),
    },
    "ntfy": {
        "label": "ntfy.sh",
        "desc": "Push notification via ntfy.sh. Set URL to your topic, e.g. https://ntfy.sh/your-topic",
        "content_type": "text/plain",
        "extra_headers": {
            "Title": "KeyBase · {{event}}",
            "Priority": "default",
            "Tags": "key,keybase",
        },
        "body_template": "Key {{key}} • App {{app_id}} • {{timestamp}}",
    },
    "teams": {
        "label": "Microsoft Teams",
        "desc": "Adaptive Card via Teams Incoming Webhook connector.",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"@type":"MessageCard","@context":"https://schema.org/extensions",'
            '"themeColor":"4A90D9","summary":"KeyBase {{event}}",'
            '"sections":[{"activityTitle":"KeyBase · {{event}}",'
            '"activitySubtitle":"App: {{app_id}}",'
            '"facts":[{"name":"Key","value":"{{key}}"},'
            '{"name":"Event","value":"{{event}}"},'
            '{"name":"Time","value":"{{timestamp}}"}],"markdown":true}]}'
        ),
    },
    "gotify": {
        "label": "Gotify",
        "desc": "Push via self-hosted Gotify server. Set URL to https://gotify.example.com/message?token=YOUR_TOKEN",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"title":"KeyBase · {{event}}",'
            '"message":"Key: {{key}}\\nApp: {{app_id}}\\n{{timestamp}}",'
            '"priority":5}'
        ),
    },
    "pushover": {
        "label": "Pushover",
        "desc": "Push via Pushover API. URL: https://api.pushover.net/1/messages.json",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"token":"YOUR_APP_TOKEN","user":"YOUR_USER_KEY",'
            '"title":"KeyBase · {{event}}",'
            '"message":"Key: {{key}}\\nApp: {{app_id}}\\n{{timestamp}}"}'
        ),
    },
    "zapier": {
        "label": "Zapier / Make / n8n",
        "desc": "Generic flat JSON object — catches all fields for automation tools.",
        "content_type": "application/json",
        "extra_headers": {},
        "body_template": (
            '{"event":"{{event}}","key":"{{key}}","app_id":"{{app_id}}",'
            '"timestamp":"{{timestamp}}","delivery_id":"{{delivery_id}}",'
            '"hwid":"{{hwid}}","expires_at":"{{expires_at}}"}'
        ),
    },
}


def _wh_template_vars(payload_obj: dict[str, Any]) -> dict[str, str]:
    data = payload_obj.get("data") or {}
    return {
        "event": str(payload_obj.get("event", "")),
        "app_id": str(payload_obj.get("app_id") or ""),
        "timestamp": str(payload_obj.get("timestamp", "")),
        "delivery_id": str(payload_obj.get("delivery_id", "")),
        "key": str(data.get("key", "")),
        "hwid": str(data.get("hwid", "")),
        "reason": str(data.get("reason") or ""),
        "expires_at": str(data.get("expires_at") or ""),
        "new_expires_at": str(data.get("new_expires_at") or ""),
        "duration_seconds": str(data.get("duration_seconds") or ""),
    }


def _apply_wh_template(template: str, vars: dict[str, str]) -> str:
    result = template
    for k, v in vars.items():
        result = result.replace(f"{{{{{k}}}}}", v)
    return result


def _webhook_timeout() -> int:
    return max(3, min(60, int(CONFIG.get("webhooks", {}).get("timeout_seconds", 10))))


def _webhook_max_retries() -> int:
    return max(0, min(5, int(CONFIG.get("webhooks", {}).get("max_retries", 3))))


_WH_SSRF_PREFIXES = (
    "127.", "0.0.0.0", "0.", "10.", "100.64.", "100.65.", "100.66.", "100.67.",
    "100.68.", "100.69.", "100.7", "100.8", "100.9.", "100.10.", "100.11.",
    "100.12.", "100.13.", "100.14.", "100.15.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
    "192.168.", "169.254.", "198.18.", "198.19.", "240.", "255.",
)
_WH_SSRF_HOSTS = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost",
    "ip6-loopback", "broadcasthost",
})


def _endpoint_id_valid(endpoint_id: str) -> bool:
    """Return True if endpoint_id looks like a server-generated token_urlsafe value."""
    if not endpoint_id or len(endpoint_id) > 64:
        return False
    import re as _re
    return bool(_re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", endpoint_id))


def _webhook_url_error(url: str) -> str:
    url = url.strip()
    if not url:
        return t("wh_err_url_required")
    if len(url) > 512:
        return t("wh_err_url_too_long")
    if "\n" in url or "\r" in url:
        return t("wh_err_url_invalid")
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return t("wh_err_url_scheme")
        if not parsed.netloc:
            return t("wh_err_url_host")
        if parsed.username or parsed.password:
            return t("wh_err_url_credentials")
        host = parsed.hostname or ""
        host_lower = host.lower()
        if host_lower in _WH_SSRF_HOSTS:
            return t("wh_err_url_loopback")
        try:
            parsed_ip = ipaddress.ip_address(host_lower.strip("[]"))
            if not parsed_ip.is_global:
                return t("wh_err_url_loopback")
        except ValueError:
            pass
        for prefix in _WH_SSRF_PREFIXES:
            if host_lower.startswith(prefix):
                return t("wh_err_url_loopback")
        if host_lower.endswith(".internal") or host_lower.endswith(".local") or host_lower.endswith(".localhost"):
            return t("wh_err_url_loopback")
    except Exception:
        return t("wh_err_url_invalid")
    return ""


def _webhook_header_error(name: str, value: str) -> str:
    if "\n" in name or "\r" in name or "\x00" in name:
        return t("wh_err_header_injection")
    if "\n" in value or "\r" in value or "\x00" in value:
        return t("wh_err_header_injection")
    if len(name) > 128:
        return t("wh_err_header_name_long")
    if len(value) > 2048:
        return t("wh_err_header_value_long")
    return ""


def enqueue_webhook(
    conn: sqlite3.Connection,
    event_type: str,
    app_id: str | None,
    payload_data: dict[str, Any],
) -> None:
    """Queue a delivery for every enabled endpoint of the given app subscribed to event_type."""
    if not app_id:
        return
    try:
        endpoints = conn.execute(
            "SELECT * FROM webhook_endpoints WHERE enabled = 1 AND app_id = ?", (app_id,)
        ).fetchall()
    except Exception:
        return
    if not endpoints:
        return
    max_att = _webhook_max_retries() + 1
    now = utc_now()
    delivery_id = secrets.token_hex(10)
    payload_obj: dict[str, Any] = {
        "event": event_type,
        "timestamp": now,
        "delivery_id": delivery_id,
        "app_id": app_id,
        "data": payload_data,
    }
    payload_json = json.dumps(payload_obj, default=str, separators=(",", ":"))
    for ep in endpoints:
        try:
            ep_events: list[str] = json.loads(ep["events"] or '["*"]')
        except Exception:
            ep_events = ["*"]
        if "*" not in ep_events and event_type not in ep_events:
            continue
        try:
            conn.execute(
                """
                INSERT INTO webhook_deliveries
                    (endpoint_id, event_type, payload_json, status, attempt, max_attempts, next_retry_at, created_at)
                VALUES (?, ?, ?, 'pending', 0, ?, ?, ?)
                """,
                (ep["id"], event_type, payload_json, max_att, now, now),
            )
        except Exception as exc:
            runtime_note(f"Webhook enqueue error: {exc}", "webhooks")
    _WEBHOOK_WAKE.set()


def _dispatch_webhook(
    url: str, secret: str, payload_json: str, event_type: str, delivery_id: str,
    config_json: str = "{}",
) -> tuple[bool, int, str, str]:
    """POST payload to url. Returns (ok, http_status, resp_body[:500], error)."""
    try:
        cfg: dict[str, Any] = json.loads(config_json or "{}")
    except Exception:
        cfg = {}
    body_template: str = cfg.get("body_template", "") or ""
    content_type: str = cfg.get("content_type", "") or "application/json"
    extra_headers: dict[str, str] = cfg.get("extra_headers") or {}

    if body_template:
        try:
            payload_obj = json.loads(payload_json)
        except Exception:
            payload_obj = {}
        tvars = _wh_template_vars(payload_obj)
        # Apply template substitution in extra_headers values too
        resolved_extra = {k: _apply_wh_template(str(v), tvars) for k, v in extra_headers.items() if k}
        body_str = _apply_wh_template(body_template, tvars)
    else:
        resolved_extra = {k: str(v) for k, v in extra_headers.items() if k}
        body_str = payload_json

    body_bytes = body_str.encode("utf-8")
    sig = hmac_sha256(secret, body_str)
    headers: dict[str, str] = {
        "Content-Type": content_type,
        "User-Agent": f"KeyBase-Webhook/{VERSION}",
        "X-KeyBase-Event": event_type,
        "X-KeyBase-Signature": f"sha256={sig}",
        "X-KeyBase-Delivery": delivery_id,
    }
    headers.update(resolved_extra)
    req = urllib.request.Request(url, data=body_bytes, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_webhook_timeout()) as resp:
            body = resp.read(500).decode("utf-8", errors="replace")
            ok = 200 <= resp.status < 300
            return ok, resp.status, body, ""
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(500).decode("utf-8", errors="replace")
        except Exception:
            pass
        return False, exc.code, body, f"HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        return False, 0, "", str(exc.reason)
    except Exception as exc:
        return False, 0, "", str(exc)


def _webhook_worker_loop(gen: int) -> None:
    runtime_note("Webhook worker online", "webhooks")
    while _WORKER_GENERATION == gen:
        try:
            _process_webhook_queue()
        except Exception as exc:
            runtime_note(f"Webhook worker error: {exc}", "webhooks")
        _WEBHOOK_WAKE.wait(timeout=5)
        _WEBHOOK_WAKE.clear()


def _process_webhook_queue() -> None:
    now = utc_now()
    try:
        with db_connect() as conn:
            rows = conn.execute(
                """
                SELECT d.*, e.url, e.secret, e.config_json
                FROM webhook_deliveries d
                JOIN webhook_endpoints e ON e.id = d.endpoint_id
                WHERE d.status = 'pending' AND d.next_retry_at <= ?
                ORDER BY d.created_at ASC LIMIT 20
                """,
                (now,),
            ).fetchall()
            if not rows:
                return
            for row in rows:
                try:
                    obj = json.loads(row["payload_json"])
                    del_id = str(obj.get("delivery_id", row["id"]))
                except Exception:
                    del_id = str(row["id"])
                ok, http_st, resp_body, err = _dispatch_webhook(
                    row["url"], row["secret"], row["payload_json"], row["event_type"], del_id,
                    row["config_json"] or "{}",
                )
                attempt = int(row["attempt"]) + 1
                max_att = int(row["max_attempts"])
                delivered_at = utc_now()
                if ok:
                    conn.execute(
                        "UPDATE webhook_deliveries SET status='success', attempt=?, delivered_at=?, response_status=?, response_body=?, error='' WHERE id=?",
                        (attempt, delivered_at, http_st, resp_body[:500], row["id"]),
                    )
                    conn.execute(
                        "UPDATE webhook_endpoints SET last_triggered_at=?, last_status='success', last_response_status=? WHERE id=?",
                        (delivered_at, http_st, row["endpoint_id"]),
                    )
                    runtime_note(f"Webhook OK → {row['url']} [{http_st}]", "webhooks")
                else:
                    if attempt >= max_att:
                        conn.execute(
                            "UPDATE webhook_deliveries SET status='failed', attempt=?, response_status=?, response_body=?, error=? WHERE id=?",
                            (attempt, http_st or None, resp_body[:500], err[:300], row["id"]),
                        )
                        conn.execute(
                            "UPDATE webhook_endpoints SET last_triggered_at=?, last_status='failed', last_response_status=? WHERE id=?",
                            (delivered_at, http_st or None, row["endpoint_id"]),
                        )
                        runtime_note(f"Webhook FAILED (gave up) → {row['url']}: {err}", "webhooks")
                    else:
                        delay = _WEBHOOK_RETRY_DELAYS[attempt] if attempt < len(_WEBHOOK_RETRY_DELAYS) else 1800
                        next_retry = (datetime.now(timezone.utc) + timedelta(seconds=delay)).replace(microsecond=0).isoformat()
                        conn.execute(
                            "UPDATE webhook_deliveries SET status='pending', attempt=?, next_retry_at=?, response_status=?, response_body=?, error=? WHERE id=?",
                            (attempt, next_retry, http_st or None, resp_body[:500], err[:300], row["id"]),
                        )
                        conn.execute(
                            "UPDATE webhook_endpoints SET last_triggered_at=?, last_status='retrying', last_response_status=? WHERE id=?",
                            (delivered_at, http_st or None, row["endpoint_id"]),
                        )
                        runtime_note(f"Webhook retry in {delay}s → {row['url']}: {err}", "webhooks")
            conn.commit()
            # Prune delivered/failed entries older than 30 days
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).replace(microsecond=0).isoformat()
            conn.execute(
                "DELETE FROM webhook_deliveries WHERE created_at < ? AND status IN ('success', 'failed')",
                (cutoff,),
            )
            conn.commit()
    except Exception as exc:
        runtime_note(f"Webhook queue error: {exc}", "webhooks")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hmac_sha256(secret: str, payload: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_key(value: str) -> str:
    return value.strip().upper().replace(" ", "")


def normalize_hwid(value: str) -> str:
    return value.strip().lower()


def normalize_country(value: Any) -> str:
    raw = "" if value is None else str(value).strip().upper()
    if raw in {"", "NONE", "NULL", "UNKNOWN", "N/A"}:
        return ""
    if " - " in raw:
        raw = raw.split(" - ", 1)[0].strip()
    for code, name in COUNTRIES.items():
        if raw == name.upper():
            return code
    raw = "".join(ch for ch in raw if ch.isalpha())[:2]
    return raw if len(raw) == 2 else ""


def normalize_ip(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "," in raw:
        raw = raw.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def normalize_ipv4(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    if parsed.version == 4:
        return str(parsed)
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped:
        return str(mapped)
    if parsed.is_loopback:
        return "127.0.0.1"
    return ""


def first_ipv4(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    for part in raw.split(","):
        candidate = part.strip().strip('"').strip("'")
        if not candidate:
            continue
        if candidate.lower().startswith("for="):
            candidate = candidate.split("=", 1)[1].strip()
        candidate = candidate.split(";", 1)[0].strip().strip('"').strip("'")
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:].split("]", 1)[0].strip()
        elif candidate.count(":") == 1 and "." in candidate:
            host, _, port = candidate.rpartition(":")
            if host and port.isdigit():
                candidate = host.strip()
        normalized = normalize_ipv4(candidate)
        if normalized:
            return normalized
        match = re.search(r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)", candidate)
        if match:
            normalized = normalize_ipv4(match.group(1))
            if normalized:
                return normalized
    return ""


def ip_is_global(value: str | None) -> bool:
    normalized = normalize_ip(value)
    if not normalized:
        return False
    try:
        return ipaddress.ip_address(normalized).is_global
    except ValueError:
        return False


def ipv4_is_global(value: str | None) -> bool:
    normalized = normalize_ipv4(value)
    if not normalized:
        return False
    try:
        return ipaddress.ip_address(normalized).is_global
    except ValueError:
        return False


def request_trusts_forwarded_headers(connection_ip: str | None, headers: Any | None = None) -> bool:
    connection_str = str(connection_ip or "")
    return headers is not None and (
        is_loopback_ip(connection_str)
        or (trust_proxy_headers() and trusted_proxy_source(connection_str))
    )


def accepted_ip_header_names() -> list[str]:
    builtins = [
        "CF-Connecting-IP",
        "True-Client-IP",
        "Fly-Client-IP",
        "X-Real-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "X-Original-Forwarded-For",
        "X-Forwarded-For",
        "Forwarded",
    ]
    names: list[str] = []
    configured = config_list("api.accepted_ip_headers", builtins)
    for header in configured + builtins:
        clean = str(header or "").strip()
        if clean and clean not in names:
            names.append(clean)
    return names


def resolved_request_ip(
    connection_ip: str | None,
    headers: Any | None = None,
    payload_ip: str | None = None,
) -> tuple[str, str]:
    normalized_connection = normalize_ipv4(connection_ip)
    connection_str = str(connection_ip or "")

    # Loopback connections (127.x / ::1) can only originate from a local process,
    # so any X-Forwarded-For they carry must come from a local proxy — safe to trust
    # automatically, even when trust_proxy_headers is off in config.
    loopback = is_loopback_ip(connection_str)
    trust_headers = request_trusts_forwarded_headers(connection_str, headers)
    if trust_headers:
        for header in accepted_ip_header_names():
            raw = str(getattr(headers, "get", lambda *_args, **_kwargs: "")(header, "") or "")
            if not raw:
                continue
            normalized = first_ipv4(raw)
            if normalized:
                return normalized, f"header:{header}"

    if config_bool("api.allow_payload_ip_fallback", True):
        normalized_payload = normalize_ipv4(payload_ip)
        if normalized_payload and ipv4_is_global(normalized_payload) and not ipv4_is_global(normalized_connection):
            return normalized_payload, "payload:ip"
    if not ipv4_is_global(normalized_connection):
        public_ip_info = get_public_ip()
        public_ip = normalize_ipv4(str(public_ip_info.get("ip", "")))
        if public_ip and ipv4_is_global(public_ip):
            method = str(public_ip_info.get("method", "") or "External").strip() or "External"
            return public_ip, f"public_ip:{method}"
    if normalized_connection:
        return normalized_connection, "connection"
    if loopback:
        return "127.0.0.1", "connection"
    return "unknown", "connection"


def country_header_names() -> list[str]:
    names: list[str] = []
    preferred = config_str("cloudflare.country_header", "").strip()
    if preferred:
        names.append(preferred)
    builtins = [
        "CF-IPCountry",
        "CloudFront-Viewer-Country",
        "X-Vercel-IP-Country",
        "Fastly-Geo-Country-Code",
        "X-GeoIP-Country",
        "X-Country-Code",
        "X-Geo-Country",
        "X-App-Country",
    ]
    configured = config_list("api.accepted_country_headers", builtins)
    for header in configured + builtins:
        clean = str(header or "").strip()
        if clean and clean not in names:
            names.append(clean)
    return names


def public_ip_for_country(connection_ip: str, payload_ip: str | None = None) -> str:
    normalized_connection = normalize_ipv4(connection_ip)
    normalized_payload = normalize_ipv4(payload_ip)
    try:
        parsed = ipaddress.ip_address(normalized_connection)
        if parsed.is_global:
            return normalized_connection
    except ValueError:
        pass

    # Local development sees 127.0.0.1 as the connection IP, so allow a client-sent
    # public IP only as a country lookup hint. IP bans still use the real connection.
    try:
        parsed_payload = ipaddress.ip_address(normalized_payload)
        if parsed_payload.is_global:
            return normalized_payload
    except ValueError:
        pass
    return ""


def country_lookup_ip(
    connection_ip: str | None,
    resolved_ip: str | None = None,
    resolved_ip_source: str | None = None,
    payload_ip: str | None = None,
) -> str:
    normalized_resolved = normalize_ipv4(resolved_ip)
    source = str(resolved_ip_source or "")
    if normalized_resolved and not source.startswith("public_ip:"):
        try:
            if ipaddress.ip_address(normalized_resolved).is_global:
                return normalized_resolved
        except ValueError:
            pass
    return public_ip_for_country(str(connection_ip or ""), payload_ip)


def _cached_country_lookup(lookup_ip: str) -> str | None:
    cached = _COUNTRY_LOOKUP_CACHE.get(lookup_ip)
    if not cached:
        return None
    country, cached_at = cached
    ttl = COUNTRY_LOOKUP_CACHE_TTL_SECONDS if country else COUNTRY_LOOKUP_FAILURE_TTL_SECONDS
    if time.time() - cached_at <= ttl:
        return country
    _COUNTRY_LOOKUP_CACHE.pop(lookup_ip, None)
    return None


def _extract_country_from_geoip_data(data: Any, depth: int = 0) -> str:
    if depth > 3 or not isinstance(data, dict):
        return ""

    direct_keys = (
        "country",
        "country_code",
        "countryCode",
        "country_iso_code",
        "countryCodeIso2",
        "country_iso",
        "countryIsoCode",
        "iso_code",
        "isoCode",
        "iso2",
        "alpha2",
        "code",
    )
    for key in direct_keys:
        value = data.get(key)
        if isinstance(value, dict):
            continue
        country = normalize_country(value)
        if country:
            return country

    nested_keys = ("country", "location", "geo", "data", "result", "attributes", "details")
    for key in nested_keys:
        nested = data.get(key)
        if isinstance(nested, dict):
            country = _extract_country_from_geoip_data(nested, depth + 1)
            if country:
                return country
    return ""


def country_from_ip(ip: str) -> str:
    lookup_ip = normalize_ip(ip)
    if not lookup_ip:
        return ""
    try:
        if not ipaddress.ip_address(lookup_ip).is_global:
            return ""
    except ValueError:
        return ""
    cached_country = _cached_country_lookup(lookup_ip)
    if cached_country is not None:
        return cached_country

    urls = [
        os.environ.get("KEYBASE_GEOIP_URL", "").strip() or config_str("api.geoip_url", "").strip(),
        "https://ipwho.is/{ip}",
        "https://ipwhois.app/json/{ip}",
        "https://ipapi.co/{ip}/json/",
        "https://ipapi.co/{ip}/country/",
        "https://api.country.is/{ip}",
        "https://ipinfo.io/{ip}/country",
    ]
    for template in [url for url in urls if url]:
        url = template.replace("{ip}", lookup_ip)
        try:
            request = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=GEOIP_TIMEOUT_SECONDS) as response:
                text = response.read(2048).decode("utf-8", errors="ignore").strip()
        except (OSError, urllib.error.URLError, TimeoutError):
            continue
        country = ""
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            country = _extract_country_from_geoip_data(data)
        else:
            country = normalize_country(text)
        if country:
            _COUNTRY_LOOKUP_CACHE[lookup_ip] = (country, time.time())
            return country
    _COUNTRY_LOOKUP_CACHE[lookup_ip] = ("", time.time())
    return ""


def best_effort_country(country: Any = None, ip: str | None = None) -> str:
    normalized = normalize_country(country)
    if normalized:
        return normalized
    return country_from_ip(ip or "")


def resolved_request_country(
    connection_ip: str | None,
    headers: Any | None = None,
    resolved_ip: str | None = None,
    resolved_ip_source: str | None = None,
    payload_country: Any = None,
    payload_ip: str | None = None,
) -> tuple[str, str]:
    if request_trusts_forwarded_headers(connection_ip, headers):
        for header in country_header_names():
            raw = str(getattr(headers, "get", lambda *_args, **_kwargs: "")(header, "") or "")
            country = normalize_country(raw)
            if country:
                return country, f"header:{header}"

    lookup_ip = country_lookup_ip(connection_ip, resolved_ip, resolved_ip_source, payload_ip)
    payload_country_code = normalize_country(payload_country)

    if lookup_ip and payload_country_code and normalize_ipv4(payload_ip) == lookup_ip and not ipv4_is_global(connection_ip):
        geo_country = country_from_ip(lookup_ip)
        if geo_country:
            return geo_country, f"geoip:{lookup_ip}"
        return payload_country_code, "payload:country"

    if lookup_ip:
        geo_country = country_from_ip(lookup_ip)
        if geo_country:
            return geo_country, f"geoip:{lookup_ip}"

    if payload_country_code:
        return payload_country_code, "payload:country"
    return "", ""


def _fetch_public_ip_from_providers() -> tuple[str, str]:
    """Try each configured provider in order; return (ip, method) or ('', '')."""
    override = config_str("public_ip.override", "").strip()
    if override:
        try:
            addr = ipaddress.ip_address(override)
            if addr.version == 4:
                return override, "Manual Override"
        except ValueError:
            pass

    if not config_bool("public_ip.enabled", True):
        return "", "Disabled"

    default_providers = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    ]
    providers = config_list("public_ip.providers", default_providers)
    timeout = min(max(config_int("api.geoip_timeout_seconds", 2, 1, 15), 1), 5)

    for url in providers:
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        try:
            req = urllib.request.Request(str(url), headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=timeout) as resp:
                text = resp.read(64).decode("ascii", errors="ignore").strip()
            addr = ipaddress.ip_address(text)
            if addr.version == 4 and addr.is_global:
                return text, "External"
        except Exception:
            continue
    return "", ""


def get_public_ip() -> dict[str, Any]:
    """Return cached public IP info: {ip: str, method: str}. Never raises."""
    with _PUBLIC_IP_LOCK:
        cache_seconds = config_int("public_ip.cache_seconds", 300, 30, 3600)
        now = time.monotonic()
        if _PUBLIC_IP_CACHE["ts"] and (now - _PUBLIC_IP_CACHE["ts"]) < cache_seconds:
            return {"ip": _PUBLIC_IP_CACHE["ip"], "method": _PUBLIC_IP_CACHE["method"]}

    try:
        ip, method = _fetch_public_ip_from_providers()
    except Exception:
        ip, method = "", ""

    if not ip:
        try:
            listeners = listener_targets()
            bind_host = listeners["admin"]["host"]
            if bind_host and bind_host not in {"0.0.0.0", "::", ""}:
                ip, method = bind_host, "Local"
            else:
                ip, method = "Unavailable", "Unavailable"
        except Exception:
            ip, method = "Unavailable", "Unavailable"

    with _PUBLIC_IP_LOCK:
        _PUBLIC_IP_CACHE["ip"] = ip
        _PUBLIC_IP_CACHE["method"] = method
        _PUBLIC_IP_CACHE["ts"] = time.monotonic()

    return {"ip": ip, "method": method}


def normalize_app_id(value: str) -> str:
    app_id = value.strip().lower()
    return "".join(ch for ch in app_id if ch.isalnum() or ch in {"_", "-"})


def as_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def row_value(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def parse_expiry(value: str | None) -> date | datetime | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        if len(raw) == 10:
            return date.fromisoformat(raw)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def is_expired(value: str | None) -> bool:
    parsed = parse_expiry(value)
    if parsed is None:
        return False
    now = datetime.now(timezone.utc)
    if isinstance(parsed, datetime):
        return parsed < now
    return parsed < now.date()


def effective_key_status(row: sqlite3.Row) -> str:
    """Return the true display status for a key row, computing 'expired' from expires_at."""
    status = row_value(row, "status") or "disabled"
    if status not in KEY_STATUSES:
        status = "disabled"
    if status == "active":
        expires_at = row_value(row, "expires_at")
        if expires_at and is_expired(expires_at):
            return "expired"
        duration_seconds = positive_duration_seconds(row_value(row, "duration_seconds"))
        activated_at = row_value(row, "activated_at")
        if not expires_at and duration_seconds and activated_at:
            computed = expires_at_from_duration(activated_at, duration_seconds)
            if computed and is_expired(computed):
                return "expired"
    return status


def iso_datetime(value: str | None) -> datetime | None:
    parsed = parse_expiry(value)
    if parsed is None:
        return None
    if isinstance(parsed, datetime):
        return parsed.astimezone(timezone.utc)
    return datetime.combine(parsed, datetime.min.time(), tzinfo=timezone.utc)


def duration_seconds_from_form(value: Any, unit: Any, default_amount: int = 30) -> int | None:
    unit_key = str(unit or "days").strip().lower()
    if unit_key in {"lifetime", "never", "none"}:
        return None
    multiplier = DURATION_UNITS.get(unit_key, DURATION_UNITS["days"])
    amount = as_int(value, default_amount, minimum=1, maximum=36500)
    return min(amount * multiplier, DURATION_UNITS["years"] * 100)


def positive_duration_seconds(value: Any) -> int | None:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


def duration_parts(seconds: Any) -> tuple[int, str]:
    total = positive_duration_seconds(seconds)
    if not total:
        return 30, "days"
    for unit in ("years", "months", "weeks", "days", "hours"):
        multiplier = DURATION_UNITS[unit]
        if total % multiplier == 0:
            amount = total // multiplier
            if amount >= 1:
                return amount, unit
    return max(1, total // DURATION_UNITS["days"]), "days"


def format_duration(seconds: Any, legacy_expires_at: str | None = None) -> str:
    total = positive_duration_seconds(seconds)
    if not total:
        return "Fixed date" if legacy_expires_at else "Lifetime"
    amount, unit = duration_parts(total)
    return f"{amount} {DURATION_LABELS.get(unit, unit)}"


def duration_unit_options(selected_unit: str) -> str:
    options = []
    for value in ("hours", "days", "weeks", "months", "years", "lifetime"):
        selected = "selected" if selected_unit == value else ""
        label = "Lifetime" if value == "lifetime" else DURATION_LABELS[value].title()
        options.append(f'<option value="{value}" {selected}>{label}</option>')
    return "".join(options)


def expires_at_from_duration(start_at: str | None, seconds: Any) -> str | None:
    duration = positive_duration_seconds(seconds)
    start = iso_datetime(start_at)
    if not duration or start is None:
        return None
    return (start + timedelta(seconds=duration)).replace(microsecond=0).isoformat()


def key_expiry_display(row: sqlite3.Row) -> str:
    expires_at = row_value(row, "expires_at")
    if expires_at:
        return str(expires_at)
    if positive_duration_seconds(row_value(row, "duration_seconds")):
        return "After activation"
    return "Never"


def html_escape(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def clean_text(value: Any, max_length: int, *, strip: bool = True) -> str:
    text = str(value or "")
    if strip:
        text = text.strip()
    text = "".join(ch for ch in text if ord(ch) >= 32)
    return text[:max_length]


def template_text(relative_path: str) -> str:
    path = TEMPLATE_DIR / relative_path
    return path.read_text(encoding="utf-8")


def render_template(relative_path: str, **context: Any) -> str:
    safe_context = {key: str(value) for key, value in context.items()}
    return Template(template_text(relative_path)).safe_substitute(safe_context)


def make_license_key(prefix: str = "KB") -> str:
    clean_prefix = normalize_prefix(prefix)
    chunks = []
    for _ in range(4):
        chunks.append("".join(secrets.choice(KEY_ALPHABET) for _ in range(4)))
    return clean_prefix + "-" + "-".join(chunks)


def provisioning_enabled() -> bool:
    return config_bool("provisioning.enabled")


def provisioning_header_name() -> str:
    return config_str("provisioning.header_name", "X-KeyBase-Provision-Key").strip() or "X-KeyBase-Provision-Key"


def provisioning_shared_token() -> str:
    env_token = (os.environ.get("KEYBASE_PROVISION_TOKEN", "").strip()
                 or os.environ.get("KEYBASE_PROVISIONING_TOKEN", "").strip())
    return env_token or config_str("provisioning.shared_token", "").strip()


def provisioning_defaults() -> dict[str, Any]:
    duration_unit = config_choice("provisioning.default_duration_unit", "days", {"hours", "days", "weeks", "months", "years", "lifetime"})
    duration_value = config_int("provisioning.default_duration_value", 30, 1, 36500)
    return {
        "enabled": provisioning_enabled(),
        "header_name": provisioning_header_name(),
        "shared_token": provisioning_shared_token(),
        "require_https": config_bool("provisioning.require_https"),
        "rate_limit_per_minute": config_int("provisioning.rate_limit_per_minute", 30, 1, 10_000),
        "default_prefix": normalize_prefix(config_str("provisioning.default_prefix", "KB")),
        "default_max_devices": config_int("provisioning.default_max_devices", 1, 1, 999),
        "default_duration_value": duration_value,
        "default_duration_unit": duration_unit,
        "max_batch_size": config_int("provisioning.max_batch_size", 20, 1, 200),
    }


def build_batch_note(note: Any = "", order_id: Any = "", customer_id: Any = "") -> str | None:
    parts = []
    base_note = clean_text(note, 500)
    if base_note:
        parts.append(base_note)
    order_value = clean_text(order_id, 80)
    if order_value:
        parts.append(f"order:{order_value}")
    customer_value = clean_text(customer_id, 80)
    if customer_value:
        parts.append(f"customer:{customer_value}")
    combined = " | ".join(parts)
    return combined[:500] if combined else None


def create_license_key_batch(
    conn: sqlite3.Connection,
    *,
    app_id: str,
    count: int,
    prefix: str,
    max_devices: int,
    duration_seconds: int | None,
    note: str | None,
    actor_ip: str,
    subscription_level: int = 1,
    event_type: str = "admin",
    status: str = "key_created",
    message_prefix: str = "Key created",
) -> list[str]:
    created: list[str] = []
    safe_app_id = normalize_app_id(app_id) or "default"
    safe_prefix = normalize_prefix(prefix)
    duration_label = format_duration(duration_seconds)
    app_levels = subscription_levels(conn, safe_app_id)
    requested_level = max(1, int(subscription_level)) if subscription_level else 1
    safe_level = requested_level if requested_level in app_levels else 1
    for _ in range(count):
        inserted = False
        for _attempt in range(20):
            key_text = make_license_key(safe_prefix)
            try:
                conn.execute(
                    """
                    INSERT INTO license_keys(key_text, app_id, status, note, max_devices, expires_at, duration_seconds, activated_at, uses, created_at, subscription_level)
                    VALUES(?, ?, 'active', ?, ?, NULL, ?, NULL, 0, ?, ?)
                    """,
                    (key_text, safe_app_id, note, max_devices, duration_seconds, utc_now(), safe_level),
                )
                log_event(conn, event_type, safe_app_id, key_text, None, actor_ip, status, f"{message_prefix}: {duration_label} after first activation")
                enqueue_webhook(conn, "key.created", safe_app_id, {
                    "key": key_text,
                    "max_devices": max_devices,
                    "duration_seconds": duration_seconds,
                    "note": note,
                    "subscription_level": safe_level,
                    "subscription_name": app_levels.get(safe_level, "Default"),
                })
                created.append(key_text)
                inserted = True
                break
            except db.DatabaseIntegrityError:
                continue
        if not inserted:
            log_event(conn, event_type, safe_app_id, None, None, actor_ip, "key_create_failed", "Failed to generate a unique key after repeated attempts")
            break
    return created


ADMIN_PASSWORD_HASH = ""
ADMIN_CREDENTIAL_ID = ""
SESSION_SECRET = ""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def hash_admin_password(password: str, iterations: int = PASSWORD_HASH_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PASSWORD_HASH_SCHEME}${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password_hash(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations_raw, salt_raw, digest_raw = stored_hash.split("$", 3)
        iterations = int(iterations_raw)
        salt = _unb64(salt_raw)
        expected = _unb64(digest_raw)
    except (ValueError, TypeError, binascii.Error):
        return False
    if scheme != PASSWORD_HASH_SCHEME or iterations < 100_000:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def password_policy_error(username: str, password: str, repeated: str | None = None) -> str:
    if repeated is not None and password != repeated:
        return t("msg_passwords_no_match")
    if len(password) < PASSWORD_MIN_LENGTH:
        return t("msg_password_too_short", n=PASSWORD_MIN_LENGTH)
    if len(password) > PASSWORD_MAX_LENGTH:
        return t("msg_password_too_long", n=PASSWORD_MAX_LENGTH)
    if password != password.strip():
        return t("msg_password_spaces")
    if any(ord(ch) < 32 for ch in password):
        return t("msg_password_control_chars")
    if password.lower() in {"password", "adminadmin", "1234567890", "qwerty12345"}:
        return t("msg_password_common")
    if username and password.lower() == username.lower():
        return t("msg_password_username")
    classes = sum(
        bool(check(password))
        for check in (
            lambda value: re.search(r"[a-z]", value),
            lambda value: re.search(r"[A-Z]", value),
            lambda value: re.search(r"\d", value),
            lambda value: re.search(r"[^A-Za-z0-9]", value),
        )
    )
    if classes < 2:
        return t("msg_password_complexity")
    return ""


def username_policy_error(username: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return "Username must be 3-32 characters: letters, numbers, dot, dash, underscore."
    return ""


def set_admin_credentials(username: str, password_hash: str, session_secret: str) -> None:
    global ADMIN_USER, ADMIN_PASSWORD_HASH, ADMIN_CREDENTIAL_ID, SESSION_SECRET
    ADMIN_USER = username.strip() or "Admin"
    ADMIN_PASSWORD_HASH = password_hash.strip()
    SESSION_SECRET = session_secret.strip() or secrets.token_urlsafe(48)
    ADMIN_CREDENTIAL_ID = sha256_text(ADMIN_USER + "|" + ADMIN_PASSWORD_HASH) if ADMIN_PASSWORD_HASH else ""


def admin_configured() -> bool:
    return bool(ADMIN_USER and ADMIN_PASSWORD_HASH and SESSION_SECRET)


def refresh_admin_credentials() -> None:
    session_secret = os.environ.get("KEYBASE_SESSION_SECRET", "").strip()
    if not session_secret:
        session_secret = secrets.token_urlsafe(48)
        update_env_values({"KEYBASE_SESSION_SECRET": session_secret})
    set_admin_credentials(
        os.environ.get("KEYBASE_ADMIN_USER", "Admin").strip() or "Admin",
        os.environ.get("KEYBASE_ADMIN_PASSWORD_HASH", "").strip(),
        session_secret,
    )


def register_admin(username: str, password: str, repeated_password: str) -> tuple[bool, str]:
    username = username.strip()
    error = username_policy_error(username) or password_policy_error(username, password, repeated_password)
    if error:
        return False, error
    password_hash = hash_admin_password(password)
    session_secret = os.environ.get("KEYBASE_SESSION_SECRET", "").strip() or secrets.token_urlsafe(48)
    update_env_values(
        {
            "KEYBASE_ADMIN_USER": username,
            "KEYBASE_ADMIN_PASSWORD_HASH": password_hash,
            "KEYBASE_SESSION_SECRET": session_secret,
        }
    )
    set_admin_credentials(username, password_hash, session_secret)
    return True, "Admin account created."


def verify_admin_password(password: str) -> bool:
    return bool(admin_configured() and verify_password_hash(password, ADMIN_PASSWORD_HASH))


def change_admin_password(current_password: str, new_password: str, repeated_password: str) -> tuple[bool, str]:
    if not verify_admin_password(current_password):
        return False, "Current password is wrong."
    error = password_policy_error(ADMIN_USER, new_password, repeated_password)
    if error:
        return False, error
    password_hash = hash_admin_password(new_password)
    session_secret = secrets.token_urlsafe(48)
    update_env_values(
        {
            "KEYBASE_ADMIN_PASSWORD_HASH": password_hash,
            "KEYBASE_SESSION_SECRET": session_secret,
        }
    )
    set_admin_credentials(ADMIN_USER, password_hash, session_secret)
    return True, t("msg_password_changed")


refresh_admin_credentials()


def sign_session(payload: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_cookie() -> str:
    expires_at = int(datetime.now(timezone.utc).timestamp()) + SESSION_MAX_SECONDS
    nonce = secrets.token_urlsafe(12)
    payload = f"{ADMIN_CREDENTIAL_ID}:{expires_at}:{nonce}"
    sig = sign_session(payload)
    return payload + "." + sig


def verify_session_cookie(value: str) -> bool:
    if "." not in value or not admin_configured():
        return False
    payload, sig = value.rsplit(".", 1)
    if not hmac.compare_digest(sig, sign_session(payload)):
        return False
    parts = payload.split(":", 2)
    if len(parts) != 3:
        return False
    credential_id, expires_raw, _nonce = parts
    if not hmac.compare_digest(credential_id, ADMIN_CREDENTIAL_ID):
        return False
    try:
        return int(expires_raw) >= int(datetime.now(timezone.utc).timestamp())
    except ValueError:
        return False


def make_confirm_cookie() -> str:
    expires_at = int(datetime.now(timezone.utc).timestamp()) + CONFIRM_WINDOW_SECONDS
    payload = f"{ADMIN_CREDENTIAL_ID}:{expires_at}"
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return payload + "." + sig


def verify_confirm_cookie(value: str) -> bool:
    if "." not in value or ":" not in value:
        return False
    payload, sig = value.rsplit(".", 1)
    if not hmac.compare_digest(sig, hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()):
        return False
    credential_id, expires_raw = payload.split(":", 1)
    if not hmac.compare_digest(credential_id, ADMIN_CREDENTIAL_ID):
        return False
    try:
        return int(expires_raw) >= int(datetime.now(timezone.utc).timestamp())
    except ValueError:
        return False


def make_api_session_token(app_id: str, key_id: int, hwid: str, minutes: int) -> tuple[str, str]:
    expires_at = int(datetime.now(timezone.utc).timestamp()) + max(1, minutes) * 60
    payload = {
        "v": 1,
        "app": app_id,
        "kid": int(key_id),
        "hwid": sha256_text(normalize_hwid(hwid)),
        "exp": expires_at,
        "rnd": secrets.token_urlsafe(18),
    }
    payload_raw = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = hmac_sha256(SESSION_SECRET, payload_raw)
    expires_iso = datetime.fromtimestamp(expires_at, timezone.utc).replace(microsecond=0).isoformat()
    return f"kst1.{payload_raw}.{sig}", expires_iso


def parse_api_session_token(value: str) -> dict[str, Any] | None:
    try:
        prefix, payload_raw, sig = value.split(".", 2)
    except ValueError:
        return None
    if prefix != "kst1" or not SESSION_SECRET:
        return None
    if not hmac.compare_digest(sig, hmac_sha256(SESSION_SECRET, payload_raw)):
        return None
    try:
        payload = json.loads(_unb64(payload_raw).decode("utf-8"))
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            return None
    except (TypeError, ValueError):
        return None
    return payload


def api_session_token_valid(token: str, activation: sqlite3.Row | None, app_id: str, key_id: int, hwid: str) -> bool:
    if not token or not activation:
        return False
    payload = parse_api_session_token(token)
    if not payload:
        return False
    if payload.get("app") != app_id or int(payload.get("kid", -1)) != int(key_id):
        return False
    if payload.get("hwid") != sha256_text(normalize_hwid(hwid)):
        return False
    stored_hash = row_value(activation, "session_token_hash") or ""
    if not stored_hash or not hmac.compare_digest(stored_hash, sha256_text(token)):
        return False
    if is_expired(row_value(activation, "session_expires_at")):
        return False
    return True


def remote_admin_allowed() -> bool:
    return os.environ.get("KEYBASE_ALLOW_REMOTE_ADMIN", "").lower() in {"1", "true", "yes", "on"} or config_bool("server.allow_remote_admin")


def trust_proxy_headers() -> bool:
    return os.environ.get("KEYBASE_TRUST_PROXY", "").lower() in {"1", "true", "yes", "on"} or config_bool("server.trust_proxy_headers") or config_bool("cloudflare.enabled")


def trusted_proxy_list() -> list[str]:
    raw = os.environ.get("KEYBASE_PROXY_WHITELIST", "").strip() or os.environ.get("KEYBASE_TRUSTED_PROXY_IPS", "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def trusted_proxy_source(ip: str) -> bool:
    normalized_ip = normalize_ip(ip)
    whitelist = trusted_proxy_list()
    if not whitelist:
        return True
    if not normalized_ip:
        return False
    for allowed in whitelist:
        try:
            if "/" in allowed:
                if ipaddress.ip_address(normalized_ip) in ipaddress.ip_network(allowed, strict=False):
                    return True
            elif normalized_ip == normalize_ip(allowed):
                return True
        except ValueError:
            continue
    return False


def is_loopback_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value in {"localhost"}


def db_connect() -> db.ConnectionWrapper:
    return db.connect(DB_SETTINGS)


def table_columns(conn: db.ConnectionWrapper, table: str) -> set[str]:
    return db.table_columns(conn, table)


def table_sql(conn: db.ConnectionWrapper, table: str) -> str:
    return db.table_sql(conn, table)


def migrate_db(conn: db.ConnectionWrapper) -> None:
    db.ensure_latest_schema(conn, utc_now())


# ── Panic Mode ──────────────────────────────────────────────────────────────

def panic_mode_info() -> dict | None:
    try:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT created_at, value FROM system_flags WHERE flag = 'panic_mode'"
            ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    try:
        data = json.loads(row["value"] or "{}")
    except Exception:
        data = {}
    return {
        "activated_at": row["created_at"],
        "activated_by": data.get("activated_by", "unknown"),
        "ip": data.get("ip", ""),
    }


def is_panic_mode() -> bool:
    return panic_mode_info() is not None


def panic_cooldown_remaining() -> int:
    info = panic_mode_info()
    if not info:
        return 0
    try:
        activated = datetime.fromisoformat(info["activated_at"].replace("Z", "+00:00"))
        elapsed = (datetime.now(timezone.utc) - activated).total_seconds()
        remaining = PANIC_COOLDOWN_SECONDS - elapsed
        return max(0, int(remaining))
    except Exception:
        return 0


def enable_panic_mode(activated_by: str, ip: str) -> None:
    payload = json.dumps({"activated_by": activated_by, "ip": ip})
    with db_connect() as conn:
        conn.execute("DELETE FROM system_flags WHERE flag = 'panic_mode'")
        conn.execute(
            "INSERT INTO system_flags(flag, created_at, value) VALUES('panic_mode', ?, ?)",
            (utc_now(), payload),
        )
        log_event(conn, "admin", None, None, None, ip, "panic_mode_enabled",
                  f"Panic Mode enabled by {activated_by}")
        conn.commit()
    new_secret = secrets.token_urlsafe(48)
    os.environ["KEYBASE_SESSION_SECRET"] = new_secret
    update_env_values({"KEYBASE_SESSION_SECRET": new_secret})
    refresh_admin_credentials()


def disable_panic_mode(activated_by: str, ip: str) -> tuple[bool, str]:
    if not is_panic_mode():
        return False, t("panic_not_active")
    remaining = panic_cooldown_remaining()
    if remaining > 0:
        mins = remaining // 60
        secs = remaining % 60
        return False, t("panic_cooldown_remaining", mins=mins, secs=secs)
    with db_connect() as conn:
        conn.execute("DELETE FROM system_flags WHERE flag = 'panic_mode'")
        log_event(conn, "admin", None, None, None, ip, "panic_mode_disabled",
                  f"Panic Mode disabled by {activated_by}")
        conn.commit()
    return True, t("panic_disabled_toast")


def init_db() -> None:
    with db_connect() as conn:
        migrate_db(conn)
        if not conn.execute("SELECT 1 FROM system_flags WHERE flag = 'apps_seeded'").fetchone():
            if not conn.execute("SELECT 1 FROM apps LIMIT 1").fetchone():
                conn.execute(
                    """
                    INSERT INTO apps(app_id, name, secret_hash, require_secret, status, settings_json, created_at, updated_at)
                    VALUES('default', 'Default App', NULL, 0, 'active', ?, ?, ?)
                    """,
                    (json.dumps(app_settings_seed()), utc_now(), utc_now()),
                )
            conn.execute(
                "INSERT INTO system_flags(flag, created_at, value) VALUES('apps_seeded', ?, NULL)",
                (utc_now(),),
            )
        ensure_app_subscription_levels(conn)
        conn.commit()


def row_count(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    if not row:
        return 0
    if "COUNT(*)" in row:
        return int(row["COUNT(*)"] or 0)
    values = list(row.values())
    return int(values[0] or 0) if values else 0


def log_event(
    conn: sqlite3.Connection,
    event_type: str,
    app_id: str | None = None,
    key_text: str | None = None,
    hwid: str | None = None,
    ip: str | None = None,
    status: str | None = None,
    message: str | None = None,
    country: str | None = None,
) -> None:
    country = normalize_country(country)
    if not country and event_type in {"verify", "protection", "provision"}:
        country = country_from_ip(ip or "")
    conn.execute(
        """
        INSERT INTO events(event_type, app_id, key_text, hwid, ip, country, status, message, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_type, app_id, key_text, hwid, ip, country, status, message, utc_now()),
    )


def ip_matches_ban(ip: str, ban_value: str) -> bool:
    if not ip or not ban_value:
        return False
    if ip == ban_value:
        return True
    try:
        if "/" in ban_value:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(ban_value, strict=False)
    except ValueError:
        return False
    return False


def looks_like_license_key(value: str) -> bool:
    compact = value.replace("-", "")
    if len(compact) < 10:
        return False
    if any((not ch.isalnum()) and ch != "-" for ch in value):
        return False
    return len(set(compact)) >= 4


def looks_like_hwid(value: str) -> bool:
    compact = value.replace("-", "").replace("_", "")
    blocked = {"unknown", "none", "null", "test", "clienthwid", "client-hwid"}
    if value in blocked or compact in blocked:
        return False
    if len(compact) < 12:
        return False
    return len(set(compact)) >= 4


def too_many_recent_invalid_attempts(conn: sqlite3.Connection, ip: str) -> bool:
    if not ip:
        return False
    since = (datetime.now(timezone.utc) - timedelta(minutes=10)).replace(microsecond=0).isoformat()
    count = row_count(
        conn,
        """
        SELECT COUNT(*) FROM events
        WHERE ip = ?
          AND created_at >= ?
          AND status IN ('invalid', 'fake_key', 'missing_hwid', 'suspicious_hwid', 'missing_key')
        """,
        (ip, since),
    )
    return count >= 20


def find_ban(conn: sqlite3.Connection, kind: str, value: str, app_id: str | None) -> sqlite3.Row | None:
    if kind == "hwid":
        normalized = normalize_hwid(value)
    elif kind == "country":
        normalized = normalize_country(value)
    else:
        normalized = value.strip()
    scopes = [app_id, None] if app_id else [None]

    for scope in scopes:
        if kind in {"hwid", "country"}:
            kind_sql = kind
            if scope:
                row = conn.execute(
                    "SELECT * FROM bans WHERE kind = ? AND app_id = ? AND value = ?",
                    (kind_sql, scope, normalized),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM bans WHERE kind = ? AND app_id IS NULL AND value = ?",
                    (kind_sql, normalized),
                ).fetchone()
            if row:
                return row

        if kind == "ip":
            if scope:
                rows = conn.execute("SELECT * FROM bans WHERE kind = 'ip' AND app_id = ?", (scope,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM bans WHERE kind = 'ip' AND app_id IS NULL").fetchall()
            for row in rows:
                if ip_matches_ban(normalized, row["value"]):
                    return row
    return None


def verify_license(
    conn: sqlite3.Connection,
    key_text: str,
    app_id: str,
    hwid: str,
    ip: str,
    app_secret: str | None,
    country: str | None = None,
    timestamp: Any = None,
    nonce: str | None = None,
    signature: str | None = None,
    session_token: str | None = None,
    client_hash: str | None = None,
    client_flags: Any = None,
    build_id: str | None = None,
    version: str | None = None,
    protection_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key_text = normalize_key(key_text)
    app_id = normalize_app_id(app_id) or "default"
    hwid = normalize_hwid(hwid)
    country = normalize_country(country or "")
    nonce = clean_text(nonce or "", 128)
    signature = clean_text(signature or "", 256)
    session_token = clean_text(session_token or "", 2048)
    client_hash = clean_text(client_hash or "", 128).lower()
    build_id = clean_text(build_id or "", 80)
    version = clean_text(version or "", 64)
    flags = client_flags_list(client_flags)

    def reject(status: str, message: str, **extra: Any) -> dict[str, Any]:
        log_event(conn, "verify", app_id, key_text, hwid, ip, status, message, country=country)
        body: dict[str, Any] = {"ok": False, "status": status, "message": message, "country": country or None}
        body.update(extra)
        return body

    if not key_text:
        return reject("missing_key", "No key provided")
    if not hwid:
        return reject("missing_hwid", "No HWID provided")
    if too_many_recent_invalid_attempts(conn, ip):
        return reject("too_many_attempts", "Too many rejected attempts from this IP")
    if not looks_like_license_key(key_text):
        return reject("fake_key", "Key format looks invalid")
    if not looks_like_hwid(hwid):
        return reject("suspicious_hwid", "HWID format looks suspicious")

    app = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
    if not app:
        return reject("app_not_found", "Unknown app_id")

    if app["status"] == "paused":
        return reject("app_paused", "Application is paused")
    if app["status"] == "disabled":
        return reject("app_disabled", "Application is disabled")

    security = app_security_settings(app)
    requires_secret_for_security = bool(app["require_secret"] or security["require_signed_requests"] or security["require_session_token"])
    if requires_secret_for_security:
        provided_hash = sha256_text(app_secret or "")
        if not app["secret_hash"] or not hmac.compare_digest(provided_hash, app["secret_hash"]):
            return reject("bad_app_secret", "Bad app secret")

    signed_ok = False
    if security["require_signed_requests"] or security["require_session_token"]:
        if not timestamp or not nonce or not signature:
            return reject("signature_required", "Signed request headers are required")
        if not nonce_looks_safe(nonce):
            return reject("bad_nonce", "Nonce format is invalid")
        if not timestamp_within_skew(timestamp, int(security["max_clock_skew_seconds"])):
            return reject("stale_request", "Request timestamp is outside the allowed clock window")
        signed_ok = verify_request_signature(
            app_secret,
            signature,
            app_id,
            key_text,
            hwid,
            timestamp,
            nonce,
            version,
            client_hash,
            build_id,
        )
        if not signed_ok:
            return reject("bad_signature", "Request signature is invalid")
        if security["reject_replay"] and not remember_request_nonce(conn, app_id, key_text, hwid, nonce):
            return reject("replay_detected", "Request nonce was already used")

    risky_flags = {"debugger", "debugged", "tampered", "hooked", "patch", "patched", "integrity_failed", "hash_mismatch"}
    if security["block_debug_flags"] and risky_flags.intersection(flags):
        return reject("client_risk", "Client reported a protected runtime or integrity risk", client_flags=flags)
    if security["require_client_integrity"]:
        if not client_hash:
            return reject("missing_client_hash", "Client integrity hash is required")
        allowed_hashes = allowed_client_hashes(security)
        if allowed_hashes and client_hash not in allowed_hashes:
            return reject("client_integrity_failed", "Client hash is not allowed")
    if not version_at_least(version, str(security.get("min_client_version") or "")):
        return reject("client_version_blocked", "Client version is below the minimum allowed version")

    protection = evaluate_protection(ip, hwid, country, protection_payload, flags)
    if protection.get("reasons"):
        primary_reason = str(protection["reasons"][0])
        log_event(conn, "protection", app_id, key_text, hwid, ip, primary_reason, protection_message(protection), country=country)
        protection_body = {k: protection[k] for k in ("mode", "anti_mode", "reasons", "score", "signals", "evidence", "challenge", "action", "fingerprint_hash", "score_reasons", "ip_intel_sources") if k in protection}
        if protection.get("anti_mode") == "strict" and protection.get("action") == "block":
            return reject(
                primary_reason,
                "Client environment risk score was blocked by protection policy",
                reason_code=primary_reason,
                protection=protection_body,
            )

    ip_ban = find_ban(conn, "ip", ip, app_id)
    if ip_ban:
        scope = "global" if ip_ban["app_id"] is None else "application"
        return reject("banned_ip", ip_ban["reason"] or f"IP is banned by {scope} rule")

    hwid_ban = find_ban(conn, "hwid", hwid, app_id)
    if hwid_ban:
        scope = "global" if hwid_ban["app_id"] is None else "application"
        return reject("banned_hwid", hwid_ban["reason"] or f"HWID is banned by {scope} rule")

    if country:
        country_ban = find_ban(conn, "country", country, app_id)
        if country_ban:
            scope = "global" if country_ban["app_id"] is None else "application"
            return reject("banned_country", country_ban["reason"] or f"Country is banned by {scope} rule")

    key = conn.execute(
        "SELECT * FROM license_keys WHERE key_text = ? AND app_id = ?",
        (key_text, app_id),
    ).fetchone()
    if not key:
        return reject("invalid", "Key not found")

    if key["status"] != "active":
        messages = {
            "paused": "Key is paused",
            "disabled": "Key is disabled",
            "revoked": "Key is revoked",
        }
        status = key["status"] if key["status"] in KEY_STATUSES else "disabled"
        return reject(status, messages.get(status, "Key is not active"))

    if key["expires_at"] and is_expired(key["expires_at"]):
        enqueue_webhook(conn, "key.expired", app_id, {
            "key": key_text,
            "expired_at": key["expires_at"],
            "hwid": hwid,
        })
        return reject("expired", "Key is expired")

    activation = conn.execute(
        "SELECT * FROM activations WHERE key_id = ? AND hwid = ?",
        (key["id"], hwid),
    ).fetchone()
    device_count = row_count(conn, "SELECT COUNT(*) FROM activations WHERE key_id = ?", (key["id"],))

    session_valid = api_session_token_valid(session_token, activation, app_id, int(key["id"]), hwid)
    issue_session_token = False
    if security["require_session_token"]:
        if activation and not session_valid:
            if not signed_ok:
                return reject("session_required", "Valid session token is required")
            issue_session_token = True
        elif not activation:
            issue_session_token = True

    if not activation:
        max_devices = max(int(key["max_devices"]), 1)
        if device_count >= max_devices:
            return reject("device_limit", "Device limit reached", devices_used=device_count, max_devices=max_devices)
    else:
        current_ip = normalize_ip(ip)
        first_ip = normalize_ip(row_value(activation, "first_ip") or row_value(activation, "ip") or "")
        last_ip = normalize_ip(row_value(activation, "ip") or "")
        if security["bind_first_ip"] and first_ip and current_ip and current_ip != first_ip:
            return reject("ip_changed", "Device is bound to the first activation IP")
        if current_ip and last_ip and current_ip != last_ip:
            ip_change_count = as_int(row_value(activation, "ip_change_count"), 0, minimum=0, maximum=100000) + 1
            if ip_change_count > int(security["max_ip_changes"]):
                return reject("ip_change_limit", "Device changed IP too many times", ip_changes=ip_change_count)

    now = utc_now()
    activated_at = row_value(key, "activated_at") or None
    expires_at = key["expires_at"]
    duration_seconds = positive_duration_seconds(row_value(key, "duration_seconds"))
    if not activated_at:
        activated_at = now
    if duration_seconds and not expires_at:
        expires_at = expires_at_from_duration(activated_at, duration_seconds)

    if is_expired(expires_at):
        conn.execute(
            "UPDATE license_keys SET activated_at = ?, expires_at = ? WHERE id = ?",
            (activated_at, expires_at, key["id"]),
        )
        enqueue_webhook(conn, "key.expired", app_id, {
            "key": key_text,
            "expired_at": expires_at,
            "hwid": hwid,
        })
        return reject("expired", "Key is expired")

    if not activation:
        conn.execute(
            """
            INSERT INTO activations(key_id, hwid, ip, uses, first_seen_at, last_seen_at)
            VALUES(?, ?, ?, 1, ?, ?)
            """,
            (key["id"], hwid, ip, now, now),
        )
        device_count += 1
        activation = conn.execute(
            "SELECT * FROM activations WHERE key_id = ? AND hwid = ?",
            (key["id"], hwid),
        ).fetchone()
        enqueue_webhook(conn, "key.activated", app_id, {
            "key": key_text,
            "hwid": hwid,
            "ip": ip,
            "country": country or None,
            "devices_used": device_count,
            "max_devices": int(key["max_devices"]),
        })
    else:
        current_ip = normalize_ip(ip)
        last_ip = normalize_ip(row_value(activation, "ip") or "")
        ip_changed = bool(current_ip and last_ip and current_ip != last_ip)
        ip_change_sql = ", ip_change_count = ip_change_count + 1" if ip_changed else ""
        conn.execute(
            f"""
            UPDATE activations
            SET ip = ?, uses = uses + 1, last_seen_at = ?{ip_change_sql}
            WHERE id = ?
            """,
            (ip, now, activation["id"]),
        )

    response_session_token = None
    response_session_expires_at = None
    if security["require_session_token"] and (issue_session_token or not session_valid):
        response_session_token, response_session_expires_at = make_api_session_token(app_id, int(key["id"]), hwid, int(security["session_minutes"]))
        conn.execute(
            """
            UPDATE activations
            SET session_token_hash = ?, session_expires_at = ?
            WHERE key_id = ? AND hwid = ?
            """,
            (sha256_text(response_session_token), response_session_expires_at, key["id"], hwid),
        )

        conn.execute(
            """
            UPDATE activations
            SET first_ip = COALESCE(NULLIF(first_ip, ''), ?),
                country = COALESCE(NULLIF(?, ''), country),
                first_client_hash = COALESCE(NULLIF(first_client_hash, ''), NULLIF(?, '')),
                last_client_hash = NULLIF(?, ''),
                last_build_id = NULLIF(?, ''),
                last_security_flags = NULLIF(?, '')
        WHERE key_id = ? AND hwid = ?
        """,
        (ip, country, client_hash, client_hash, build_id, ",".join(flags), key["id"], hwid),
    )

    conn.execute(
        """
        UPDATE license_keys
        SET uses = uses + 1, last_seen_at = ?, activated_at = ?, expires_at = ?
        WHERE id = ?
        """,
        (now, activated_at, expires_at, key["id"]),
    )
    log_event(conn, "verify", app_id, key_text, hwid, ip, "valid", "Key accepted", country=country)

    key_sub_level = int(key["subscription_level"]) if row_value(key, "subscription_level") is not None else 1
    levels = subscription_levels(conn, app_id)
    result = {
        "ok": True,
        "status": "valid",
        "message": "Key accepted",
        "app_id": app_id,
        "key": key_text,
        "country": country or None,
        "expires_at": expires_at,
        "activated_at": activated_at,
        "duration_seconds": duration_seconds,
        "max_devices": int(key["max_devices"]),
        "devices_used": device_count,
        "subscription_level": key_sub_level,
        "subscription_name": levels.get(key_sub_level, "Default"),
        "server_time": utc_now(),
        "session_required": bool(security["require_session_token"]),
        "session_expires_at": response_session_expires_at or row_value(activation, "session_expires_at") if activation else response_session_expires_at,
    }
    if response_session_token:
        result["session_token"] = response_session_token
    if security["require_signed_requests"]:
        result["signed_request"] = True
    if protection.get("reasons"):
        result["protection"] = {k: protection[k] for k in ("mode", "anti_mode", "reasons", "score", "signals", "evidence", "challenge", "action", "fingerprint_hash", "score_reasons", "ip_intel_sources") if k in protection}
        result["reason_codes"] = protection.get("reasons", [])
        if protection.get("action") in {"warning", "block"}:
            result["protection_warning"] = True
        if protection.get("anti_mode") == "warn" and protection.get("action") == "block":
            result["would_block_in_strict"] = True
    return result


def app_href(app_id: str, tab: str = "overview") -> str:
    return f"/admin/app/{quote(app_id)}?tab={quote(tab)}"


def safe_return(value: str | None, fallback: str = "/admin") -> str:
    if value and value.startswith("/admin") and "://" not in value:
        return value
    return fallback


def status_badge(status: str) -> str:
    cls = {
        "active": "status-ok",
        "valid": "status-ok",
        "paused": "status-warn",
        "too_many_attempts": "status-warn",
        "signature_required": "status-warn",
        "stale_request": "status-warn",
        "session_required": "status-warn",
        "replay_detected": "status-bad",
        "bad_nonce": "status-bad",
        "bad_signature": "status-bad",
        "client_risk": "status-bad",
        "missing_client_hash": "status-warn",
        "client_integrity_failed": "status-bad",
        "client_version_blocked": "status-bad",
        "VM_DETECTED": "status-bad",
        "VPN_DETECTED": "status-bad",
        "PROXY_DETECTED": "status-bad",
        "DEBUGGER_DETECTED": "status-bad",
        "ip_changed": "status-bad",
        "ip_change_limit": "status-bad",
        "token_required": "status-warn",
        "token_locked": "status-warn",
        "token_rejected": "status-warn",
        "password_required": "status-warn",
        "password_rejected": "status-warn",
        "password_changed": "status-ok",
        "admin_registered": "status-ok",
        "config_saved": "status-ok",
        "config_rejected": "status-warn",
        "api_started": "status-ok",
        "api_restarted": "status-ok",
        "api_already_running": "status-warn",
        "api_already_stopped": "status-warn",
        "api_stopped": "status-bad",
        "api_action_rejected": "status-bad",
        "app_delete_blocked": "status-warn",
        "disabled": "status-bad",
        "revoked": "status-bad",
        "expired": "status-bad",
        "invalid": "status-bad",
        "fake_key": "status-bad",
        "suspicious_hwid": "status-bad",
        "banned_ip": "status-bad",
        "banned_hwid": "status-bad",
        "banned_country": "status-bad",
    }.get(status, "status-muted")
    return f'<span class="status {cls}">{html_escape(status or "unknown")}</span>'


def copy_chip(value: Any, label: str, sensitive: bool = False, compact: bool = True) -> str:
    text = str(value or "").strip()
    if not text:
        return '<span class="muted">-</span>'
    classes = ["copy-chip"]
    if sensitive:
        classes.append("is-blurred")
    if compact:
        classes.append("compact")
    class_attr = " ".join(classes)
    return (
        f'<button type="button" class="{class_attr}" data-copy-value="{html_escape(text)}" data-copy-label="{html_escape(label)}" '
        f'title="Click to copy {html_escape(label)}" aria-label="Copy {html_escape(label)}">'
        f'<span class="copy-chip-text">{html_escape(text)}</span>'
        f'<span class="copy-chip-hint">copy</span>'
        f'</button>'
    )


def secret_input(
    name: str,
    label: str,
    *,
    copy_label: str = "Application Secret",
    placeholder: str = "",
    value: str = "",
    input_id: str | None = None,
    minlength: int = 8,
    maxlength: int = 256,
    autocomplete: str = "new-password",
    disabled: bool = False,
) -> str:
    field_id = input_id or f"{name}-{secrets.token_hex(4)}"
    disabled_attr = " disabled" if disabled else ""
    value_attr = f' value="{html_escape(value)}"' if value else ""
    placeholder_attr = f' placeholder="{html_escape(placeholder)}"' if placeholder else ""
    return f"""
<label>{html_escape(label)}
  <div class="secret-field" data-secret-field>
    <input id="{html_escape(field_id)}" class="secret-field-input" type="password" name="{html_escape(name)}" minlength="{minlength}" maxlength="{maxlength}" autocomplete="{html_escape(autocomplete)}"{placeholder_attr}{value_attr}{disabled_attr} data-secret-input>
    <div class="secret-field-actions">
      <button type="button" class="secret-field-toggle" data-secret-toggle data-show-label="Show" data-hide-label="Hide"{disabled_attr}>Show</button>
      <button type="button" class="secret-field-copy" data-copy-source="#{html_escape(field_id)}" data-copy-label="{html_escape(copy_label)}"{disabled_attr}>Copy</button>
    </div>
  </div>
</label>
"""


def with_toast(location: str | None, message: str = "", level: str = "info") -> str:
    target = str(location or "/admin").strip() or "/admin"
    clean_message = clean_text(message, 240)
    if not clean_message:
        return target
    toast_level = str(level or "info").strip().lower()
    if toast_level not in {"success", "error", "warning", "info"}:
        toast_level = "info"
    parsed = urlparse(target)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params.setdefault("toast", []).append(clean_message)
    params.setdefault("toast_type", []).append(toast_level)
    query = urlencode(params, doseq=True)
    return parsed._replace(query=query).geturl()


def country_flag_icon(code: Any, compact: bool = False) -> str:
    normalized = normalize_country(code or "")
    known = normalized in COUNTRIES
    if known:
        title = f"{normalized} — {COUNTRIES[normalized]}"
        src = f"/assets/flags/{normalized}.svg"
    else:
        title = "Unknown country"
        src = "/assets/flags/_unknown.svg"
    classes = "country-flag compact" if compact else "country-flag"
    return (
        f'<span class="{classes}" title="{html_escape(title)}">'
        f'<img src="{src}" alt="{html_escape(normalized or "?")}" loading="lazy">'
        f"</span>"
    )


def country_badge(code: Any, include_name: bool = True, compact: bool = False) -> str:
    normalized = normalize_country(code or "")
    if normalized in COUNTRIES:
        name = COUNTRIES[normalized]
        icon = country_flag_icon(normalized, compact=compact)
        if include_name:
            return f'{icon}<span class="country-badge-name">{html_escape(name)}</span>'
        return f'{icon}<span class="country-badge-code">{html_escape(normalized)}</span>'
    icon = country_flag_icon("?", compact=compact)
    if include_name:
        return f'{icon}<span class="country-badge-name">Unknown country</span>'
    return f'{icon}<span class="country-badge-code">??</span>'


def country_picker_options() -> str:
    return "".join(
        f"""<button type="button" class="country-option" data-country-option data-code="{html_escape(code)}" data-name="{html_escape(name).lower()}" data-label="{html_escape(name)}">
  {country_badge(code)}
</button>"""
        for code, name in sorted(COUNTRIES.items(), key=lambda item: item[1])
    )


def ban_form_html(app_id: str | None, return_to: str, button_label: str) -> str:
    app_input = f'<input type="hidden" name="app_id" value="{html_escape(app_id)}">' if app_id else ""
    return f"""
<form class="toolbar ban-form" method="post" action="/admin/bans/create" data-ban-form>
  {app_input}
  <input type="hidden" name="return_to" value="{html_escape(return_to)}">
  <label>{t("ban_kind")}
    <select name="kind" data-ban-kind>
      <option value="ip">{t("ban_kind_ip")}</option>
      <option value="hwid">{t("ban_kind_hwid")}</option>
      <option value="country">{t("ban_kind_country")}</option>
    </select>
  </label>
  <label data-ban-value-field>{t("ban_value")}<input name="value" data-ban-value-input minlength="2" maxlength="128" placeholder="{_h('ban_value_placeholder')}" style="min-width:240px"></label>
  <div class="country-field" data-country-field hidden>
    <label>{t("ban_kind_country")}
      <button type="button" class="country-trigger" data-country-trigger><span class="country-code">--</span><span class="country-trigger-label" data-country-label>{t("ban_select_country")}</span></button>
    </label>
    <input type="hidden" name="value" data-country-hidden disabled>
    <div class="country-popover" data-country-popover hidden>
      <input data-country-search maxlength="48" placeholder="{_h('ban_search_country')}">
      <div class="country-menu" data-country-menu>{country_picker_options()}</div>
    </div>
  </div>
  <label>{t("ban_reason")}<input name="reason" maxlength="240" placeholder="{_h('form_reason_placeholder')}"></label>
  <button class="primary" type="submit">{icon_label("global-bans" if app_id is None else "bans", button_label)}</button>
</form>
"""


def ban_kind_badge(kind: str) -> str:
    labels = {"ip": "IP", "hwid": "HWID", "country": "CC"}
    safe_kind = kind if kind in labels else "ip"
    return f'<span class="kind-badge kind-{safe_kind}">{labels[safe_kind]}</span>'


def app_settings(row: sqlite3.Row) -> dict[str, Any]:
    try:
        parsed = json.loads(row["settings_json"] or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


APP_SECURITY_DEFAULTS: dict[str, Any] = {
    "require_signed_requests": False,
    "reject_replay": True,
    "max_clock_skew_seconds": 120,
    "require_session_token": False,
    "session_minutes": 60,
    "bind_first_ip": False,
    "max_ip_changes": 20,
    "require_client_integrity": False,
    "block_debug_flags": False,
    "allowed_client_hashes": "",
    "min_client_version": "",
}


def bool_setting(settings: dict[str, Any], key: str, default: bool = False) -> bool:
    value = settings.get(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def int_setting(settings: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    return as_int(settings.get(key, default), default, minimum=minimum, maximum=maximum)


def app_security_settings(row: sqlite3.Row) -> dict[str, Any]:
    raw = app_settings(row)
    settings = dict(APP_SECURITY_DEFAULTS)
    settings.update(raw)
    settings["require_signed_requests"] = bool_setting(settings, "require_signed_requests")
    settings["reject_replay"] = bool_setting(settings, "reject_replay", True)
    settings["require_session_token"] = bool_setting(settings, "require_session_token")
    settings["bind_first_ip"] = bool_setting(settings, "bind_first_ip")
    settings["require_client_integrity"] = bool_setting(settings, "require_client_integrity")
    settings["block_debug_flags"] = bool_setting(settings, "block_debug_flags")
    settings["max_clock_skew_seconds"] = int_setting(settings, "max_clock_skew_seconds", 120, 15, 3600)
    settings["session_minutes"] = int_setting(settings, "session_minutes", 60, 5, 1440)
    settings["max_ip_changes"] = int_setting(settings, "max_ip_changes", 20, 0, 10000)
    settings["allowed_client_hashes"] = clean_text(settings.get("allowed_client_hashes", ""), 4000)
    settings["min_client_version"] = clean_text(settings.get("min_client_version", ""), 32)
    return settings


def allowed_client_hashes(settings: dict[str, Any]) -> set[str]:
    raw = str(settings.get("allowed_client_hashes", "") or "")
    parts = re.split(r"[\s,;]+", raw)
    return {part.strip().lower() for part in parts if part.strip()}


def client_flags_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw_items = [str(item) for item in value]
    else:
        raw_items = re.split(r"[\s,;|]+", str(value or ""))
    seen: list[str] = []
    for item in raw_items:
        clean = re.sub(r"[^a-zA-Z0-9_.-]", "", item).lower()[:40]
        if clean and clean not in seen:
            seen.append(clean)
    return seen[:20]


def stable_payload_hash(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        raw = str(value or "")
    return sha256_text(raw)


def protection_settings() -> dict[str, Any]:
    default_weights = DEFAULT_CONFIG["protection"]["risk_weights"]
    configured_weights = CONFIG.get("protection", {}).get("risk_weights", default_weights)
    if not isinstance(configured_weights, dict):
        configured_weights = default_weights
    else:
        configured_weights = {**default_weights, **configured_weights}
    anti_mode = config_choice("protection.anti_mode", "warn", {"off", "warn", "strict"})
    return {
        "mode": anti_mode,
        "anti_mode": anti_mode,
        "legacy_mode": config_choice("protection.mode", "warn", {"warn", "block", "restrict", "strict"}),
        "anti_vm": config_bool("protection.anti_vm"),
        "anti_vpn": config_bool("protection.anti_vpn"),
        "anti_proxy": config_bool("protection.anti_proxy"),
        "anti_debug": config_bool("protection.anti_debug"),
        "anti_tamper": config_bool("protection.anti_tamper"),
        "anti_sandbox": config_bool("protection.anti_sandbox"),
        "ip_whitelist": config_list("protection.ip_whitelist", []),
        "hwid_whitelist": config_list("protection.hwid_whitelist", []),
        "country_whitelist": config_list("protection.country_whitelist", []),
        "ip_reputation_url": config_str("protection.ip_reputation_url", "").strip(),
        "ip_reputation_token": config_str("protection.ip_reputation_token", "").strip(),
        "ip_reputation_timeout_seconds": config_int("protection.ip_reputation_timeout_seconds", 2, 1, 15),
        "ip_reputation_cache_seconds": config_int("protection.ip_reputation_cache_seconds", 1800, 0, 86400),
        "free_ip_intel": config_bool("protection.free_ip_intel"),
        "tor_exit_list": config_bool("protection.tor_exit_list"),
        "tor_exit_list_url": config_str("protection.tor_exit_list_url", DEFAULT_CONFIG["protection"]["tor_exit_list_url"]).strip(),
        "request_window_seconds": config_int("protection.request_window_seconds", 10, 1, 300),
        "too_fast_threshold": config_int("protection.too_fast_threshold", 20, 2, 10000),
        "risk_threshold": config_int("protection.risk_threshold", 70, 1, 100),
        "signal_threshold": config_int("protection.signal_threshold", 2, 1, 10),
        "challenge_threshold": config_int("protection.challenge_threshold", 40, 0, 100),
        "hard_challenge_threshold": config_int("protection.hard_challenge_threshold", 71, 0, 100),
        "block_threshold": config_int("protection.block_threshold", 90, 0, 100),
        "risk_weights": {str(key): config_int(f"protection.risk_weights.{key}", int(value), 0, 100) for key, value in configured_weights.items()},
        "vm_keywords": config_list("protection.vm_keywords", DEFAULT_CONFIG["protection"]["vm_keywords"]),
        "vpn_keywords": config_list("protection.vpn_keywords", DEFAULT_CONFIG["protection"]["vpn_keywords"]),
        "proxy_keywords": config_list("protection.proxy_keywords", DEFAULT_CONFIG["protection"]["proxy_keywords"]),
        "suspicious_ua_keywords": config_list("protection.suspicious_ua_keywords", DEFAULT_CONFIG["protection"]["suspicious_ua_keywords"]),
        "datacenter_keywords": config_list("protection.datacenter_keywords", DEFAULT_CONFIG["protection"]["datacenter_keywords"]),
        "debug_keywords": config_list("protection.debug_keywords", DEFAULT_CONFIG["protection"]["debug_keywords"]),
        "tamper_keywords": config_list("protection.tamper_keywords", DEFAULT_CONFIG["protection"]["tamper_keywords"]),
        "sandbox_keywords": config_list("protection.sandbox_keywords", DEFAULT_CONFIG["protection"]["sandbox_keywords"]),
    }


def protection_any_module_enabled(settings: dict[str, Any] | None = None) -> bool:
    current = settings or protection_settings()
    if current.get("anti_mode") == "off":
        return False
    return any(bool(current.get(name)) for name in ("anti_vm", "anti_vpn", "anti_proxy", "anti_debug", "anti_tamper", "anti_sandbox"))


def protection_whitelisted(settings: dict[str, Any], ip: str, hwid: str, country: str) -> bool:
    normalized_ip = normalize_ip(ip)
    normalized_hwid = normalize_hwid(hwid)
    normalized_country = normalize_country(country)
    for allowed_ip in settings.get("ip_whitelist", []):
        if normalized_ip and ip_matches_ban(normalized_ip, str(allowed_ip)):
            return True
    allowed_hwids = {normalize_hwid(item) for item in settings.get("hwid_whitelist", []) if normalize_hwid(item)}
    if normalized_hwid and normalized_hwid in allowed_hwids:
        return True
    allowed_countries = {normalize_country(item) for item in settings.get("country_whitelist", []) if normalize_country(item)}
    return bool(normalized_country and normalized_country in allowed_countries)


def _protection_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "detected", "blocked", "high", "risk"}


def _protection_false(value: Any) -> bool:
    return str(value or "").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
        "none",
        "null",
        "clean",
        "clear",
        "safe",
        "residential",
        "mobile",
        "business",
        "isp",
    }


def _protection_signal_tokens(value: Any, prefix: str = "") -> list[str]:
    tokens: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            clean_key = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(key)).lower().strip("_")
            compound_key = f"{prefix}.{clean_key}" if prefix else clean_key
            if isinstance(item, (dict, list, tuple, set)):
                tokens.extend(_protection_signal_tokens(item, compound_key))
            elif _protection_false(item):
                continue
            elif _protection_bool(item):
                tokens.append(compound_key)
                if isinstance(item, str):
                    tokens.append(str(item).lower()[:80])
            elif isinstance(item, str) and item.strip():
                tokens.append(f"{compound_key}:{item.lower()[:80]}")
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            tokens.extend(_protection_signal_tokens(item, prefix))
    elif isinstance(value, str):
        tokens.extend(client_flags_list(value))
    return [token for token in tokens if token][:80]


def _protection_report(payload: Any, flags: list[str]) -> dict[str, Any]:
    report: dict[str, Any] = {}
    if isinstance(payload, dict):
        for key in (
            "protection",
            "security_report",
            "environment",
            "env",
            "anti_analysis",
            "network",
            "signals",
            "fingerprint",
            "browser_fingerprint",
            "behavior",
        ):
            value = payload.get(key)
            if isinstance(value, dict):
                if key in {"fingerprint", "browser_fingerprint", "behavior"}:
                    report[key] = value
                else:
                    report.update(value)
            elif value:
                report.setdefault("signals", value)
        for key in (
            "is_vm",
            "vm_detected",
            "is_sandbox",
            "sandbox_detected",
            "is_emulator",
            "emulator_detected",
            "is_debugger",
            "debugger_detected",
            "is_tampered",
            "tamper_detected",
            "is_hooked",
            "injection_detected",
            "is_vpn",
            "vpn_detected",
            "is_proxy",
            "proxy_detected",
            "is_tor",
            "tor_detected",
            "is_datacenter",
            "datacenter_detected",
            "asn",
            "asn_name",
            "asn_org",
            "asn_type",
            "organization",
            "org",
            "isp",
            "ip_type",
            "connection_type",
            "user_agent",
            "_user_agent",
            "risk_score",
            "fraud_score",
            "threat_score",
            "abuse_score",
            "mac_prefix",
            "mac_vendor",
            "bios_vendor",
            "bios_version",
            "bios_serial",
            "uefi_vendor",
            "system_manufacturer",
            "system_product",
            "cpu_vendor",
            "cpu_flags",
            "drivers",
            "devices",
            "processes",
            "modules",
            "loaded_modules",
            "hooks",
            "injected_modules",
            "fingerprint_hash",
            "canvas",
            "audio",
            "timezone",
            "language",
            "webgl_vendor",
            "webglVendor",
            "webgl_renderer",
            "webglRenderer",
            "hardware_concurrency",
            "hardwareConcurrency",
            "touch",
            "headless",
            "automation",
            "webdriver",
            "fonts",
            "screen",
            "behavior",
        ):
            if key in payload:
                report[key] = payload.get(key)
        fingerprint = report.get("fingerprint") or report.get("browser_fingerprint")
        if isinstance(fingerprint, dict):
            report["fingerprint_hash"] = str(fingerprint.get("hash") or fingerprint.get("fingerprint_hash") or stable_payload_hash(fingerprint))
            for source_key, target_key in (
                ("webglVendor", "webgl_vendor"),
                ("webglRenderer", "webgl_renderer"),
                ("hardwareConcurrency", "hardware_concurrency"),
            ):
                if source_key in fingerprint and target_key not in report:
                    report[target_key] = fingerprint.get(source_key)
            for direct_key in ("canvas", "audio", "timezone", "language", "touch", "headless", "automation", "webdriver", "fonts", "screen", "behavior"):
                if direct_key in fingerprint and direct_key not in report:
                    report[direct_key] = fingerprint.get(direct_key)
    if flags:
        report["client_flags"] = flags
    return report


def _cached_ip_reputation(ip: str, settings: dict[str, Any]) -> dict[str, Any]:
    url_template = str(settings.get("ip_reputation_url") or "").strip()
    normalized_ip = normalize_ip(ip)
    if not url_template or not normalized_ip:
        return {}
    cache_seconds = int(settings.get("ip_reputation_cache_seconds") or 0)
    cache_key = sha256_text(f"{url_template}|{normalized_ip}")
    now = time.time()
    with IP_REPUTATION_LOCK:
        cached = IP_REPUTATION_CACHE.get(cache_key)
        if cached and cache_seconds > 0 and now - float(cached.get("at", 0)) < cache_seconds:
            data = cached.get("data", {})
            return data if isinstance(data, dict) else {}
    token = str(settings.get("ip_reputation_token") or "").strip()
    url = url_template.replace("{ip}", quote(normalized_ip)).replace("{token}", quote(token))
    headers = {"User-Agent": f"{APP_NAME}/{VERSION}"}
    if token and "{token}" not in url_template:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=int(settings.get("ip_reputation_timeout_seconds") or 2)) as response:
            raw = response.read(65536).decode("utf-8", errors="ignore").strip()
        parsed = json.loads(raw) if raw.startswith(("{", "[")) else {"raw": raw}
        data = parsed if isinstance(parsed, dict) else {"items": parsed}
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        data = {"lookup_error": True}
    with IP_REPUTATION_LOCK:
        IP_REPUTATION_CACHE[cache_key] = {"at": now, "data": data}
        if len(IP_REPUTATION_CACHE) > 500:
            oldest = sorted(IP_REPUTATION_CACHE.items(), key=lambda item: float(item[1].get("at", 0)))[:100]
            for key, _ in oldest:
                IP_REPUTATION_CACHE.pop(key, None)
    return data


def _fetch_json_url(url: str, timeout: int) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(65536).decode("utf-8", errors="ignore").strip()
    parsed = json.loads(raw) if raw.startswith(("{", "[")) else {"raw": raw}
    return parsed if isinstance(parsed, dict) else {"items": parsed}


def _github_release_payload() -> dict[str, Any]:
    now = time.time()
    with GITHUB_RELEASE_LOCK:
        cached = GITHUB_RELEASE_CACHE.get("data")
        if isinstance(cached, dict) and now - float(GITHUB_RELEASE_CACHE.get("at", 0.0)) < GITHUB_RELEASE_CACHE_SECONDS:
            return cached if isinstance(cached, dict) else {}
    try:
        req = urllib.request.Request(
            GITHUB_RELEASES_API_URL,
            headers={
                "User-Agent": f"{APP_NAME}/{VERSION}",
                "Accept": "application/vnd.github+json",
            },
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=6) as response:
            raw = response.read(262144).decode("utf-8", errors="ignore").strip()
        parsed = json.loads(raw) if raw.startswith(("{", "[")) else {}
        data = parsed if isinstance(parsed, dict) else {}
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        data = {}
    with GITHUB_RELEASE_LOCK:
        GITHUB_RELEASE_CACHE["at"] = now
        GITHUB_RELEASE_CACHE["data"] = data
    return data


def current_installed_version() -> str:
    """Read the installed package version from disk so update checks do not need a restart."""
    init_path = Path(__file__).resolve().parent / "__init__.py"
    try:
        raw = init_path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", raw)
        if match:
            return match.group(1).strip()
    except OSError:
        pass
    pyproject_path = ROOT_DIR / "pyproject.toml"
    try:
        raw = pyproject_path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"(?m)^\s*version\s*=\s*['\"]([^'\"]+)['\"]", raw)
        if match:
            return match.group(1).strip()
    except OSError:
        pass
    return str(VERSION)


def github_release_update_info() -> dict[str, Any]:
    payload = _github_release_payload()
    current_version = current_installed_version()
    tag_name = str(payload.get("tag_name") or payload.get("name") or "").strip()
    latest_version = tag_name[1:] if tag_name.lower().startswith("v") else tag_name
    current_tuple = version_tuple(current_version)
    latest_tuple = version_tuple(latest_version)
    available = bool(current_tuple and latest_tuple and latest_tuple > current_tuple)
    banner_enabled = update_banner_enabled()
    published_at = str(payload.get("published_at") or payload.get("created_at") or "").strip()
    with GITHUB_RELEASE_LOCK:
        checked_at_ts = float(GITHUB_RELEASE_CACHE.get("at", 0.0))
    checked_at = datetime.fromtimestamp(checked_at_ts, timezone.utc).isoformat() if checked_at_ts else ""
    return {
        "available": available,
        "banner_enabled": banner_enabled,
        "current_version": current_version,
        "latest_version": latest_version,
        "release_name": str(payload.get("name") or latest_version or "").strip(),
        "published_at": published_at,
        "published_at_text": _format_release_timestamp(published_at),
        "checked_at": checked_at,
        "checked_at_text": _format_release_timestamp(checked_at),
        "body": str(payload.get("body") or "").strip(),
        "status": "available" if available else ("up_to_date" if latest_tuple and current_tuple else "unavailable"),
    }


def _merge_ip_intel(target: dict[str, Any], source: dict[str, Any]) -> None:
    if not source:
        return
    sources = target.setdefault("sources", [])
    if source.get("source") and source["source"] not in sources:
        sources.append(source["source"])
    for key in ("country", "asn", "asn_name", "asn_org", "organization", "org", "isp", "ip_type", "connection_type"):
        if source.get(key) and not target.get(key):
            target[key] = source[key]
    for key in ("is_vpn", "vpn_detected", "is_proxy", "proxy_detected", "is_tor", "tor_detected", "is_datacenter", "datacenter_detected"):
        target[key] = bool(target.get(key) or source.get(key))


def _ip_api_intel(ip: str, timeout: int) -> dict[str, Any]:
    fields = "status,countryCode,as,asname,isp,org,proxy,hosting,mobile,query"
    data = _fetch_json_url(f"http://ip-api.com/json/{quote(ip)}?fields={fields}", timeout)
    if data.get("status") != "success":
        return {}
    as_text = str(data.get("as") or "")
    return {
        "source": "ip-api",
        "country": data.get("countryCode") or "",
        "asn": as_text.split(" ", 1)[0] if as_text else "",
        "asn_name": data.get("asname") or "",
        "asn_org": data.get("asname") or data.get("org") or "",
        "organization": data.get("org") or "",
        "org": data.get("org") or "",
        "isp": data.get("isp") or "",
        "is_proxy": bool(data.get("proxy")),
        "proxy_detected": bool(data.get("proxy")),
        "is_datacenter": bool(data.get("hosting")),
        "datacenter_detected": bool(data.get("hosting")),
        "connection_type": "mobile" if data.get("mobile") else "",
    }


def _ipwhois_intel(ip: str, timeout: int) -> dict[str, Any]:
    data = _fetch_json_url(f"https://ipwho.is/{quote(ip)}", timeout)
    if data.get("success") is False:
        return {}
    security = data.get("security") if isinstance(data.get("security"), dict) else {}
    connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
    return {
        "source": "ipwho.is",
        "country": data.get("country_code") or "",
        "asn": connection.get("asn") or "",
        "asn_name": connection.get("org") or "",
        "asn_org": connection.get("org") or "",
        "organization": connection.get("org") or "",
        "org": connection.get("org") or "",
        "isp": connection.get("isp") or "",
        "is_vpn": bool(security.get("vpn")),
        "vpn_detected": bool(security.get("vpn")),
        "is_proxy": bool(security.get("proxy")),
        "proxy_detected": bool(security.get("proxy")),
        "is_tor": bool(security.get("tor")),
        "tor_detected": bool(security.get("tor")),
        "is_datacenter": bool(security.get("hosting")),
        "datacenter_detected": bool(security.get("hosting")),
        "security": security,
        "connection": connection,
    }


def _dbip_free_intel(ip: str, timeout: int) -> dict[str, Any]:
    data = _fetch_json_url(f"https://api.db-ip.com/v2/free/{quote(ip)}", timeout)
    if data.get("error"):
        return {}
    return {
        "source": "db-ip-free",
        "country": data.get("countryCode") or "",
    }


def _cymru_whois_intel(ip: str, timeout: int) -> dict[str, Any]:
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
            sock.sendall(f" -v {ip}\n".encode("ascii", errors="ignore"))
            raw = sock.recv(4096).decode("utf-8", errors="ignore")
    except OSError:
        return {}
    rows = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(rows) < 2 or "|" not in rows[1]:
        return {}
    parts = [part.strip() for part in rows[1].split("|")]
    return {
        "source": "cymru-whois",
        "asn": parts[0] if len(parts) > 0 else "",
        "country": parts[3] if len(parts) > 3 else "",
        "asn_org": parts[-1] if parts else "",
        "organization": parts[-1] if parts else "",
        "org": parts[-1] if parts else "",
    }


def _tor_exit_nodes(settings: dict[str, Any]) -> set[str]:
    if not settings.get("tor_exit_list"):
        return set()
    now = time.time()
    with TOR_EXIT_LOCK:
        nodes = TOR_EXIT_CACHE.get("nodes")
        if isinstance(nodes, set) and nodes and now - float(TOR_EXIT_CACHE.get("at", 0)) < int(settings.get("ip_reputation_cache_seconds") or 1800):
            return nodes
    url = str(settings.get("tor_exit_list_url") or DEFAULT_CONFIG["protection"]["tor_exit_list_url"])
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=int(settings.get("ip_reputation_timeout_seconds") or 2)) as response:
            raw = response.read(2_000_000).decode("utf-8", errors="ignore")
        parsed_nodes = {normalize_ip(line.strip()) for line in raw.splitlines()}
        parsed_nodes = {item for item in parsed_nodes if item}
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        parsed_nodes = set()
    with TOR_EXIT_LOCK:
        TOR_EXIT_CACHE["at"] = now
        TOR_EXIT_CACHE["nodes"] = parsed_nodes
    return parsed_nodes


def _request_timing_too_fast(ip: str, settings: dict[str, Any]) -> bool:
    normalized_ip = normalize_ip(ip)
    if not normalized_ip:
        return False
    window = int(settings.get("request_window_seconds") or 10)
    threshold = int(settings.get("too_fast_threshold") or 20)
    now = time.time()
    with PROTECTION_TIMING_LOCK:
        queue = PROTECTION_TIMING.get(normalized_ip)
        if queue is None:
            queue = deque(maxlen=max(threshold * 3, 64))
            PROTECTION_TIMING[normalized_ip] = queue
        queue.append(now)
        while queue and queue[0] < now - window:
            queue.popleft()
        if len(PROTECTION_TIMING) > 5000:
            stale = [key for key, value in PROTECTION_TIMING.items() if not value or value[-1] < now - max(window * 3, 60)]
            for key in stale[:1000]:
                PROTECTION_TIMING.pop(key, None)
        return len(queue) >= threshold


def _builtin_ip_intelligence(ip: str, settings: dict[str, Any]) -> dict[str, Any]:
    normalized_ip = normalize_ip(ip)
    if not settings.get("free_ip_intel") or not normalized_ip or not ip_is_global(normalized_ip):
        return {}
    cache_seconds = int(settings.get("ip_reputation_cache_seconds") or 1800)
    cache_key = sha256_text(f"builtin-ip-intel|{normalized_ip}")
    now = time.time()
    with IP_REPUTATION_LOCK:
        cached = IP_REPUTATION_CACHE.get(cache_key)
        if cached and cache_seconds > 0 and now - float(cached.get("at", 0)) < cache_seconds:
            data = cached.get("data", {})
            return data if isinstance(data, dict) else {}

    timeout = int(settings.get("ip_reputation_timeout_seconds") or 2)
    intel: dict[str, Any] = {"source": "builtin-free-ip-intel", "sources": []}
    for provider in (_ip_api_intel, _ipwhois_intel, _dbip_free_intel, _cymru_whois_intel):
        try:
            _merge_ip_intel(intel, provider(normalized_ip, timeout))
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
            continue

    if normalized_ip in _tor_exit_nodes(settings):
        intel["is_tor"] = True
        intel["tor_detected"] = True
        intel["is_proxy"] = True
        intel["proxy_detected"] = True

    org_blob = " ".join(str(intel.get(key) or "") for key in ("asn_name", "asn_org", "organization", "org", "isp")).lower()
    dc_hits = _keyword_hits(org_blob, settings.get("datacenter_keywords", []))
    if dc_hits:
        intel["is_datacenter"] = True
        intel["datacenter_detected"] = True
        intel["datacenter_evidence"] = dc_hits

    with IP_REPUTATION_LOCK:
        IP_REPUTATION_CACHE[cache_key] = {"at": now, "data": intel}
    return intel


def _reputation_tokens(data: dict[str, Any]) -> list[str]:
    tokens = _protection_signal_tokens(data)
    security = data.get("security") if isinstance(data, dict) else None
    if isinstance(security, dict):
        tokens.extend(_protection_signal_tokens(security, "security"))
    privacy = data.get("privacy") if isinstance(data, dict) else None
    if isinstance(privacy, dict):
        tokens.extend(_protection_signal_tokens(privacy, "privacy"))
    connection = data.get("connection") if isinstance(data, dict) else None
    if isinstance(connection, dict):
        tokens.extend(_protection_signal_tokens(connection, "connection"))
    asn = data.get("asn") if isinstance(data, dict) else None
    if isinstance(asn, dict):
        tokens.extend(_protection_signal_tokens(asn, "asn"))
    return tokens


def _keyword_hits(blob: str, keywords: list[str]) -> list[str]:
    hits: list[str] = []
    for keyword in keywords:
        clean = str(keyword or "").strip().lower()
        if not clean or clean in hits:
            continue
        if re.fullmatch(r"[a-z0-9_+-]{1,3}", clean):
            matched = bool(re.search(rf"(?<![a-z0-9_+-]){re.escape(clean)}(?![a-z0-9_+-])", blob))
        else:
            matched = clean in blob
        if matched:
            hits.append(clean)
    return hits[:12]


def _truthy_report(report: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(_protection_bool(report.get(key)) for key in keys)


def _max_score_from(value: Any, names: set[str]) -> int:
    best = 0
    if isinstance(value, dict):
        for key, item in value.items():
            clean_key = str(key or "").strip().lower()
            if clean_key in names:
                try:
                    best = max(best, int(float(item or 0)))
                except (TypeError, ValueError):
                    pass
            best = max(best, _max_score_from(item, names))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            best = max(best, _max_score_from(item, names))
    return best


def _risk_weight(settings: dict[str, Any], name: str) -> int:
    weights = settings.get("risk_weights", {})
    if isinstance(weights, dict):
        try:
            return max(0, min(100, int(weights.get(name, 0) or 0)))
        except (TypeError, ValueError):
            return 0
    return 0


def _fingerprint_present(report: dict[str, Any]) -> bool:
    fingerprint = report.get("fingerprint") or report.get("browser_fingerprint")
    if isinstance(fingerprint, dict) and fingerprint:
        return True
    return bool(report.get("fingerprint_hash") or report.get("canvas") or report.get("webgl_renderer") or report.get("webglRenderer"))


def _webgl_blob(report: dict[str, Any]) -> str:
    fingerprint = report.get("fingerprint") if isinstance(report.get("fingerprint"), dict) else {}
    parts = [
        report.get("webgl_vendor"),
        report.get("webglVendor"),
        report.get("webgl_renderer"),
        report.get("webglRenderer"),
    ]
    if isinstance(fingerprint, dict):
        parts.extend([fingerprint.get("webglVendor"), fingerprint.get("webglRenderer"), fingerprint.get("webgl_vendor"), fingerprint.get("webgl_renderer")])
    return " ".join(str(part or "") for part in parts).lower()


def _report_bool_any(report: dict[str, Any], keys: tuple[str, ...]) -> bool:
    fingerprint = report.get("fingerprint") if isinstance(report.get("fingerprint"), dict) else {}
    for key in keys:
        if _protection_bool(report.get(key)):
            return True
        if isinstance(fingerprint, dict) and _protection_bool(fingerprint.get(key)):
            return True
    return False


def _timezone_geo_mismatch(timezone_name: Any, country: str) -> bool:
    tz = str(timezone_name or "").strip()
    code = normalize_country(country)
    if not tz or not code:
        return False
    hints = {
        "US": ("America/", "Pacific/", "US/"),
        "CA": ("America/", "Canada/"),
        "BR": ("America/",),
        "MX": ("America/",),
        "GB": ("Europe/London",),
        "DE": ("Europe/",),
        "FR": ("Europe/",),
        "NL": ("Europe/",),
        "PL": ("Europe/",),
        "ES": ("Europe/",),
        "IT": ("Europe/",),
        "UA": ("Europe/",),
        "RU": ("Europe/", "Asia/"),
        "TR": ("Europe/", "Asia/"),
        "CN": ("Asia/",),
        "JP": ("Asia/",),
        "KR": ("Asia/",),
        "IN": ("Asia/",),
        "SG": ("Asia/",),
        "AU": ("Australia/",),
    }
    prefixes = hints.get(code)
    return bool(prefixes and not any(tz.startswith(prefix) for prefix in prefixes))


def _behavior_low_entropy(report: dict[str, Any]) -> bool:
    behavior = report.get("behavior")
    if not isinstance(behavior, dict):
        fingerprint = report.get("fingerprint")
        if isinstance(fingerprint, dict):
            behavior = fingerprint.get("behavior")
    if not isinstance(behavior, dict):
        return False
    dwell = as_int(behavior.get("dwellMs") or behavior.get("dwell_ms"), 0, minimum=0, maximum=86_400_000)
    moves = as_int(behavior.get("mouseMoves") or behavior.get("mouse_moves"), 0, minimum=0, maximum=1_000_000)
    clicks = as_int(behavior.get("clicks"), 0, minimum=0, maximum=1_000_000)
    try:
        entropy = float(behavior.get("mouseEntropy") or behavior.get("mouse_entropy") or 0)
    except (TypeError, ValueError):
        entropy = 0.0
    intervals = behavior.get("clickIntervals") or behavior.get("click_intervals") or []
    repetitive = False
    if isinstance(intervals, list) and len(intervals) >= 4:
        try:
            values = [float(item) for item in intervals[:20]]
            avg = sum(values) / len(values)
            variance = sum((item - avg) ** 2 for item in values) / len(values)
            repetitive = variance < 25
        except (TypeError, ValueError, ZeroDivisionError):
            repetitive = False
    return bool((dwell > 1500 and moves < 3 and clicks == 0) or (moves >= 3 and entropy < 0.15) or repetitive)


def _challenge_action(score: int, settings: dict[str, Any]) -> str:
    if score >= int(settings.get("block_threshold") or 90):
        return "block"
    if score >= int(settings.get("challenge_threshold") or 40):
        return "warning"
    return "allow"


def evaluate_protection(
    ip: str,
    hwid: str,
    country: str,
    payload: dict[str, Any] | None,
    flags: list[str],
) -> dict[str, Any]:
    settings = protection_settings()
    if not protection_any_module_enabled(settings):
        return {"enabled": False, "mode": settings["mode"], "anti_mode": settings["anti_mode"], "reasons": [], "signals": [], "score": 0, "action": "allow", "challenge": "allow"}
    if protection_whitelisted(settings, ip, hwid, country):
        return {"enabled": True, "mode": settings["mode"], "anti_mode": settings["anti_mode"], "whitelisted": True, "reasons": [], "signals": [], "score": 0, "action": "allow", "challenge": "allow"}

    report = _protection_report(payload or {}, flags)
    signals = _protection_signal_tokens(report)
    builtin_reputation = _builtin_ip_intelligence(ip, settings)
    reputation = _cached_ip_reputation(ip, settings)
    if builtin_reputation:
        reputation = {**builtin_reputation, **reputation, "builtin_ip_intel": builtin_reputation}
    if reputation:
        signals.extend(_reputation_tokens(reputation))
    if _request_timing_too_fast(ip, settings):
        report["too_fast_requests"] = True
        signals.append("too_fast_requests")

    blob = " ".join(sorted(set(signals))).lower()
    reasons: list[str] = []
    evidence: dict[str, list[str]] = {}
    score_reasons: list[str] = []

    def add_score(name: str, evidence_value: str | None = None) -> int:
        if name not in score_reasons:
            score_reasons.append(name)
        if evidence_value:
            evidence.setdefault("score_signals", [])
            if evidence_value not in evidence["score_signals"]:
                evidence["score_signals"].append(evidence_value)
        return _risk_weight(settings, name)

    vm_hits = _keyword_hits(blob, settings["vm_keywords"])
    vpn_hits = _keyword_hits(blob, settings["vpn_keywords"])
    proxy_hits = _keyword_hits(blob, settings["proxy_keywords"])
    ua_hits = _keyword_hits(str(report.get("user_agent") or report.get("_user_agent") or "").lower(), settings["suspicious_ua_keywords"])
    webgl_hits = _keyword_hits(_webgl_blob(report), settings["vm_keywords"])
    debug_hits = _keyword_hits(blob, settings["debug_keywords"])
    tamper_hits = _keyword_hits(blob, settings["tamper_keywords"])
    sandbox_hits = _keyword_hits(blob, settings["sandbox_keywords"])
    tor_detected = _truthy_report(report, ("is_tor", "tor_detected")) or bool(reputation.get("is_tor") or reputation.get("tor_detected")) or "tor" in proxy_hits
    dc_detected = _truthy_report(report, ("is_datacenter", "datacenter_detected")) or bool(reputation.get("is_datacenter") or reputation.get("datacenter_detected")) or bool(_keyword_hits(blob, settings["datacenter_keywords"]))

    if settings["anti_vm"] and (_truthy_report(report, ("is_vm", "vm_detected", "is_emulator", "emulator_detected")) or vm_hits or webgl_hits):
        reasons.append("VM_DETECTED")
        evidence["VM_DETECTED"] = (vm_hits + webgl_hits)[:6] or ["explicit_vm_signal"]
    sandbox_triggered = settings["anti_sandbox"] and (_truthy_report(report, ("is_sandbox", "sandbox_detected")) or bool(sandbox_hits))
    tamper_triggered = settings["anti_tamper"] and (_truthy_report(report, ("is_tampered", "tamper_detected", "is_hooked", "injection_detected")) or bool(tamper_hits))
    if settings["anti_debug"] and (_truthy_report(report, ("is_debugger", "debugger_detected")) or debug_hits):
        reasons.append("DEBUGGER_DETECTED")
        evidence["DEBUGGER_DETECTED"] = debug_hits or ["explicit_debug_signal"]
    if settings["anti_vpn"] and (_truthy_report(report, ("is_vpn", "vpn_detected")) or vpn_hits):
        reasons.append("VPN_DETECTED")
        evidence["VPN_DETECTED"] = vpn_hits or ["explicit_vpn_signal"]
    if settings["anti_proxy"] and (_truthy_report(report, ("is_proxy", "proxy_detected")) or proxy_hits or tor_detected):
        reasons.append("PROXY_DETECTED")
        evidence["PROXY_DETECTED"] = proxy_hits or ["explicit_proxy_signal"]
    if settings["anti_proxy"] and tor_detected:
        reasons.append("TOR_DETECTED")
        evidence["TOR_DETECTED"] = ["tor_exit_node"]

    external_score = 0
    for key in ("risk_score", "risk", "score", "fraud_score", "threat_score"):
        try:
            external_score = max(external_score, int(float(report.get(key, 0) or 0)))
        except (TypeError, ValueError):
            pass
        try:
            external_score = max(external_score, int(float(reputation.get(key, 0) or 0)))
        except (TypeError, ValueError):
            pass
    external_score = max(external_score, _max_score_from(report, {"risk_score", "risk", "score", "fraud_score", "threat_score", "abuse_score"}))
    external_score = max(external_score, _max_score_from(reputation, {"risk_score", "risk", "score", "fraud_score", "threat_score", "abuse_score"}))

    weighted_score = 0
    if "VM_DETECTED" in reasons:
        weighted_score += add_score("vm_or_emulator")
    if "VPN_DETECTED" in reasons:
        weighted_score += add_score("vpn")
    if "PROXY_DETECTED" in reasons:
        weighted_score += add_score("proxy")
    if "DEBUGGER_DETECTED" in reasons:
        weighted_score += add_score("debugger")
    if dc_detected:
        weighted_score += add_score("datacenter_asn", "datacenter_asn")
    if "TOR_DETECTED" in reasons:
        weighted_score += add_score("tor", "tor_exit_node")
    if ua_hits:
        weighted_score += add_score("suspicious_ua", f"user_agent:{','.join(ua_hits[:3])}")
    if _timezone_geo_mismatch(report.get("timezone"), country or str(reputation.get("country") or "")):
        weighted_score += add_score("timezone_geo_mismatch", "timezone_geo_mismatch")
    if _truthy_report(report, ("too_fast_requests",)):
        weighted_score += add_score("too_fast_requests", "too_fast_requests")
    if not _fingerprint_present(report):
        weighted_score += add_score("missing_js_fingerprint", "missing_js_fingerprint")
    if _report_bool_any(report, ("headless", "headless_browser", "is_headless")):
        weighted_score += add_score("headless_browser", "headless_browser")
    if _report_bool_any(report, ("automation", "webdriver", "webdriver_detected", "puppeteer", "playwright", "selenium")):
        weighted_score += add_score("automation_flags", "automation_flags")
    if webgl_hits and "VM_DETECTED" not in reasons:
        reasons.append("VM_DETECTED")
        evidence["VM_DETECTED"] = webgl_hits[:6]
    if webgl_hits and "vm_or_emulator" not in score_reasons:
        weighted_score += add_score("vm_or_emulator", f"webgl:{','.join(webgl_hits[:3])}")
    if _behavior_low_entropy(report):
        weighted_score += add_score("low_behavior_entropy", "low_behavior_entropy")
    if sandbox_triggered:
        weighted_score += add_score("sandbox", sandbox_hits[0] if sandbox_hits else "sandbox_signal")
    if tamper_triggered:
        weighted_score += add_score("tamper", tamper_hits[0] if tamper_hits else "tamper_signal")
    # Use local weighted signals for enforcement. Raw external scores are kept as evidence
    # only, because one noisy reputation response should not block a legitimate user.
    risk_score = min(100, weighted_score)
    if external_score:
        evidence.setdefault("score_signals", []).append(f"external_score:{min(100, external_score)}")

    action = _challenge_action(risk_score, settings)
    ordered = [code for code in ("TOR_DETECTED", "VM_DETECTED", "VPN_DETECTED", "PROXY_DETECTED", "DEBUGGER_DETECTED") if code in reasons]
    return {
        "enabled": True,
        "mode": settings["mode"],
        "anti_mode": settings["anti_mode"],
        "whitelisted": False,
        "reasons": ordered,
        "signals": sorted(set(signals))[:16],
        "evidence": {key: value[:6] for key, value in evidence.items()},
        "score": risk_score,
        "score_reasons": score_reasons[:12],
        "challenge": action,
        "action": action,
        "fingerprint_hash": str(report.get("fingerprint_hash") or ""),
        "ip_intel_sources": reputation.get("sources") if isinstance(reputation.get("sources"), list) else [],
        "reputation_error": bool(reputation.get("lookup_error")) if reputation else False,
    }


def protection_message(evaluation: dict[str, Any]) -> str:
    reasons = evaluation.get("reasons") or []
    mode = str(evaluation.get("mode") or "warn")
    score = int(evaluation.get("score") or 0)
    action = str(evaluation.get("action") or evaluation.get("challenge") or "allow")
    fp_hash = str(evaluation.get("fingerprint_hash") or "")
    suffix = f" score={score} action={action}"
    if fp_hash:
        suffix += f" fp={fp_hash[:16]}"
    return f"Protection {mode}: {', '.join(reasons)}{suffix}" if reasons else f"Protection {mode}: no suspicious signals{suffix}"


def request_signature_payload(
    app_id: str,
    key_text: str,
    hwid: str,
    timestamp: Any,
    nonce: str,
    version: str | None = None,
    client_hash: str | None = None,
    build_id: str | None = None,
) -> str:
    return "\n".join(
        [
            "kb-v1",
            normalize_app_id(app_id) or "default",
            normalize_key(key_text),
            normalize_hwid(hwid),
            str(timestamp or "").strip(),
            str(nonce or "").strip(),
            clean_text(version or "", 64),
            clean_text(client_hash or "", 128).lower(),
            clean_text(build_id or "", 80),
        ]
    )


def verify_request_signature(
    secret: str | None,
    signature: str | None,
    app_id: str,
    key_text: str,
    hwid: str,
    timestamp: Any,
    nonce: str,
    version: str | None = None,
    client_hash: str | None = None,
    build_id: str | None = None,
) -> bool:
    if not secret or not signature:
        return False
    expected = hmac_sha256(
        secret,
        request_signature_payload(app_id, key_text, hwid, timestamp, nonce, version, client_hash, build_id),
    )
    return hmac.compare_digest(expected.lower(), str(signature).strip().lower())


def timestamp_within_skew(timestamp: Any, max_skew_seconds: int) -> bool:
    try:
        value = int(str(timestamp).strip())
    except (TypeError, ValueError):
        return False
    now = int(datetime.now(timezone.utc).timestamp())
    return abs(now - value) <= max_skew_seconds


def nonce_looks_safe(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{12,96}", str(value or "").strip()))


def version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(value or ""))[:4]
    return tuple(int(part) for part in parts) if parts else tuple()


def version_at_least(version: str | None, minimum: str | None) -> bool:
    minimum_tuple = version_tuple(str(minimum or ""))
    if not minimum_tuple:
        return True
    current_tuple = version_tuple(str(version or ""))
    if not current_tuple:
        return False
    width = max(len(current_tuple), len(minimum_tuple))
    return current_tuple + (0,) * (width - len(current_tuple)) >= minimum_tuple + (0,) * (width - len(minimum_tuple))


def remember_request_nonce(conn: sqlite3.Connection, app_id: str, key_text: str, hwid: str, nonce: str, retention_minutes: int = 20) -> bool:
    since = (datetime.now(timezone.utc) - timedelta(minutes=max(1, retention_minutes))).replace(microsecond=0).isoformat()
    conn.execute("DELETE FROM request_nonces WHERE created_at < ?", (since,))
    try:
        conn.execute(
            """
            INSERT INTO request_nonces(app_id, key_text, hwid, nonce, created_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (normalize_app_id(app_id) or "default", normalize_key(key_text), normalize_hwid(hwid), nonce.strip(), utc_now()),
        )
        return True
    except db.DatabaseIntegrityError:
        return False


def app_default_prefix(row: sqlite3.Row) -> str:
    settings = app_settings(row)
    prefix = str(settings.get("default_prefix", "")).strip()
    return prefix or (row["app_id"][:6].upper() or "KB")


def confirm_password_field(label: str = "Admin password") -> str:
    return f'<label class="confirm-password-wrap">{html_escape(label)}<input type="password" name="confirm_password" autocomplete="current-password"></label>'


def app_secret_modal(row: sqlite3.Row, return_to: str, suffix: str = "") -> str:
    app_id = row["app_id"]
    modal_id = f"change-secret-{app_id}{suffix}"
    configured = t("yes") if row["secret_hash"] else t("no")
    required = t("yes") if row["require_secret"] else t("no")
    body = f"""
<form method="post" action="/admin/apps/update" data-danger-form {confirm_submit_attrs(t("secret_change_btn") + "?", t("secret_lockout_warning"), t("secret_change_btn"))}>
  <input type="hidden" name="app_id" value="{html_escape(app_id)}">
  <input type="hidden" name="return_to" value="{html_escape(return_to)}">
  <input type="hidden" name="secret_action" value="1">
  <div class="detail-grid">
    <div><span>{t("secret_configured")}</span><b>{html_escape(configured)}</b></div>
    <div><span>{t("secret_required_label")}</span><b>{html_escape(required)}</b></div>
    <div><span>{t("secret_scope")}</span><b>{html_escape(app_id)}</b></div>
  </div>
  <div class="form-grid">
    <label>{t("secret_require_label")}
      <select name="require_secret">
        <option value="0">{t("no")}</option>
        <option value="1" {"selected" if row["require_secret"] else ""}>{t("yes")}</option>
      </select>
    </label>
    <label>{t("secret_action")}
      <select name="secret_mode" data-secret-mode>
        <option value="keep">{t("secret_keep")}</option>
        <option value="replace">{t("secret_replace")}</option>
        <option value="clear">{t("secret_clear")}</option>
      </select>
    </label>
    <div data-secret-mode-group>{secret_input("secret", t("secret_new_label"), copy_label="Application Secret", placeholder=t("secret_new_placeholder"), input_id=f"app-secret-{app_id}{suffix}", disabled=True)}</div>
    {confirm_password_field(t("secret_admin_password"))}
  </div>
  <p class="password-confirmed-note">{t("form_password_confirmed")}</p>
  <p class="actions"><button class="danger" type="submit">{icon_label("change-secret", t("secret_change_btn"))}</button></p>
</form>
"""
    return modal(modal_id, f"{t('secret_panel_title')} — {app_id}", body, "wide")


def app_secret_panel(row: sqlite3.Row, return_to: str, suffix: str = "") -> str:
    app_id = row["app_id"]
    modal_id = f"change-secret-{app_id}{suffix}"
    configured = t("yes") if row["secret_hash"] else t("no")
    required = t("yes") if row["require_secret"] else t("no")
    return f"""
<section class="mini-section">
  <div class="panel-head">
    <div>
      <h3>{t("secret_panel_title")}</h3>
      <p class="muted">{t("secret_panel_subtitle", configured=html_escape(configured), required=html_escape(required))}</p>
    </div>
    <button type="button" {confirm_open_attrs(modal_id, t("secret_change_btn") + "?", t("secret_open_form_msg"), t("secret_change_btn"))}>{icon_label("change-secret", t("secret_change_btn"))}</button>
  </div>
</section>
{app_secret_modal(row, return_to, suffix)}
"""


def bool_select_options(enabled: bool) -> str:
    return f"""
<option value="0" {"selected" if not enabled else ""}>{t("no")}</option>
<option value="1" {"selected" if enabled else ""}>{t("yes")}</option>
"""


def app_security_fields(row: sqlite3.Row) -> str:
    settings = app_security_settings(row)
    return f"""
<section class="mini-section">
  <div class="panel-head">
    <div>
      <h3>{t("protection_title")}</h3>
      <p class="muted">{t("protection_subtitle")}</p>
    </div>
  </div>
  <div class="form-grid">
    <label>{t("protection_signed_req")}
      <select name="require_signed_requests">{bool_select_options(bool(settings["require_signed_requests"]))}</select>
    </label>
    <label>{t("protection_replay_nonce")}
      <select name="reject_replay">{bool_select_options(bool(settings["reject_replay"]))}</select>
    </label>
    <label>{t("protection_clock_skew")}<input type="number" name="max_clock_skew_seconds" min="15" max="3600" value="{html_escape(settings["max_clock_skew_seconds"])}"></label>
    <label>{t("protection_session_token")}
      <select name="require_session_token">{bool_select_options(bool(settings["require_session_token"]))}</select>
    </label>
    <label>{t("protection_session_lifetime")}<input type="number" name="session_minutes" min="5" max="1440" value="{html_escape(settings["session_minutes"])}"></label>
    <label>{t("protection_bind_ip")}
      <select name="bind_first_ip">{bool_select_options(bool(settings["bind_first_ip"]))}</select>
    </label>
    <label>{t("protection_max_ip_changes")}<input type="number" name="max_ip_changes" min="0" max="10000" value="{html_escape(settings["max_ip_changes"])}"></label>
    <label>{t("protection_integrity_hash")}
      <select name="require_client_integrity">{bool_select_options(bool(settings["require_client_integrity"]))}</select>
    </label>
    <label>{t("protection_block_debug")}
      <select name="block_debug_flags">{bool_select_options(bool(settings["block_debug_flags"]))}</select>
    </label>
    <label>{t("protection_min_version")}<input name="min_client_version" maxlength="32" value="{html_escape(settings["min_client_version"])}" placeholder="{_h('protection_min_version_placeholder')}"></label>
  </div>
  <label>{t("protection_allowed_hashes")}<textarea name="allowed_client_hashes" maxlength="4000" placeholder="{_h('protection_hashes_placeholder')}">{html_escape(settings["allowed_client_hashes"])}</textarea></label>
  <div class="notice">{t("protection_note")}</div>
</section>
"""


def confirm_open_attrs(target_modal: str, title: str, message: str, label: str = "Continue") -> str:
    return (
        f'data-confirm-open-modal="{html_escape(target_modal)}" '
        f'data-confirm-title="{html_escape(title)}" '
        f'data-confirm-message="{html_escape(message)}" '
        f'data-confirm-label="{html_escape(label)}"'
    )


def confirm_submit_attrs(title: str, message: str, label: str = "Continue") -> str:
    return (
        f'data-confirm-submit '
        f'data-confirm-title="{html_escape(title)}" '
        f'data-confirm-message="{html_escape(message)}" '
        f'data-confirm-label="{html_escape(label)}"'
    )


def dangerous_modal(
    modal_id: str,
    title: str,
    action: str,
    hidden_fields: dict[str, Any],
    submit_label: str,
    danger: bool = True,
    require_app_id: str | None = None,
    note: str = "",
) -> str:
    fields = "".join(f'<input type="hidden" name="{html_escape(name)}" value="{html_escape(value)}">' for name, value in hidden_fields.items())
    app_confirm = ""
    if require_app_id:
        app_confirm = f'<label>{t("form_type_app_id")}<input name="confirm_app_id" minlength="2" maxlength="64" pattern="[A-Za-z0-9_.-]{{2,64}}" placeholder="{html_escape(require_app_id)}" required></label>'
    body = f"""
<form method="post" action="{html_escape(action)}" data-danger-form>
  {fields}
  <p class="muted">{html_escape(note)}</p>
  <div class="form-grid">
    {app_confirm}
    <label>{t("form_reason")}<input name="reason" maxlength="240" placeholder="{_h("form_reason_placeholder")}"></label>
    {confirm_password_field(t("form_admin_password"))}
  </div>
  <p class="password-confirmed-note">{t("form_password_confirmed")}</p>
  <p class="actions"><button class="{'danger' if danger else 'primary'}" type="submit">{icon_label("delete" if danger else "save", submit_label)}</button></p>
</form>
"""
    return modal(modal_id, title, body, "wide")


def bulk_toolbar(endpoint: str, actions: list[str], export_url: str = "") -> str:
    _map: dict[str, tuple[str, str, str]] = {
        "delete":  ("delete",     "bulk_delete",  "danger"),
        "enable":  ("enable",     "bulk_enable",  ""),
        "disable": ("disable",    "bulk_disable", ""),
        "export":  ("export",     "bulk_export",  ""),
        "unban":   ("remove-ban", "bulk_unban",   ""),
    }
    btns = "".join(
        f'<button type="button" class="{cls}" data-bulk-action="{html_escape(a)}" hidden disabled>{icon_label(ic, t(lk))}</button>'
        for a in actions
        for ic, lk, cls in [_map.get(a, (a, a, ""))]
    )
    export_attr = f' data-bulk-export="{html_escape(export_url)}"' if export_url else ""
    selected_template = html_escape(t("bulk_selected_n", n="__count__"))
    confirm_template = html_escape(t("bulk_confirm_n", action="__action__", n="__count__"))
    export_template = html_escape(t("bulk_export_started_n", n="__count__"))
    return (
        f'<div class="bulk-bar" data-bulk-bar data-bulk-endpoint="{html_escape(endpoint)}"{export_attr} '
        f'data-bulk-done-label="{html_escape(t("bulk_done"))}" '
        f'data-bulk-selected-template="{selected_template}" '
        f'data-bulk-confirm-template="{confirm_template}" '
        f'data-bulk-export-template="{export_template}" '
        f'data-bulk-request-failed="{html_escape(t("bulk_request_failed"))}" '
        f'data-bulk-row-label="{html_escape(t("bulk_select_row"))}">'
        f'<button type="button" class="ghost" data-bulk-toggle>{icon_label("select", t("bulk_select"))}</button>'
        f'<span class="bulk-count" data-bulk-count hidden aria-live="polite"></span>'
        f'<button type="button" class="ghost" data-bulk-all hidden>{t("bulk_select_all")}</button>'
        f'<button type="button" class="ghost" data-bulk-clear hidden>{t("bulk_clear")}</button>'
        f'<span class="bulk-sep" aria-hidden="true" hidden></span>'
        f'{btns}'
        f'</div>'
    )


def bulk_confirm_modal(table_type: str) -> str:
    return modal(
        f"bulk-confirm-{html_escape(table_type)}",
        t("bulk_confirm_title"),
        f"""<p data-bulk-confirm-msg class="muted" style="min-height:1.4em"></p>
<div class="form-grid confirm-password-section" style="margin-top:12px">
  {confirm_password_field(t("form_admin_password"))}
</div>
<p class="password-confirmed-note">{t("form_password_confirmed")}</p>
<p class="actions" style="margin-top:14px">
  <button type="button" data-close-modal>{t("confirm_cancel")}</button>
  <button class="primary" type="button" data-bulk-confirm-ok>{t("bulk_confirm_ok")}</button>
</p>""",
    )


def app_delete_form(app_id: str, return_to: str, suffix: str = "") -> str:
    note = t("app_delete_note_default") if app_id == "default" else t("app_delete_note_normal")
    modal_id = f"delete-app-{app_id}{suffix}"
    confirm_attrs = confirm_open_attrs(
        modal_id,
        t("app_delete_title"),
        t("app_delete_open_msg", app_id=app_id),
        t("app_delete_open_label"),
    )
    return f"""
<div class="danger-zone">
  <h3>{t("danger_zone")}</h3>
  <p class="muted">{html_escape(note)}</p>
  <button class="danger" type="button" {confirm_attrs}>{icon_label("delete", t("app_delete_submit"))}</button>
</div>
{dangerous_modal(
    modal_id,
    t("app_delete_modal_title", app_id=app_id),
    "/admin/apps/delete",
    {"app_id": app_id, "return_to": return_to},
    t("app_delete_submit"),
    require_app_id=app_id,
    note=note,
)}
"""


def icon_svg(name: str) -> str:
    clean_name = "".join(ch for ch in name if ch.isalnum() or ch in {"-", "_"})
    icon_path = ASSET_DIR / "icons" / f"{clean_name}.svg"
    try:
        svg = icon_path.read_text(encoding="utf-8").strip()
        if svg.startswith("<svg"):
            return svg
    except OSError:
        pass
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14"/></svg>'


def icon_label(icon_name: str, label: str) -> str:
    return f'{icon_svg(icon_name)}<span>{html_escape(label)}</span>'


def modal(modal_id: str, title: str, body: str, size: str = "") -> str:
    close_label = _h("modal_close")
    return f"""
<div class="modal {html_escape(size)}" id="{html_escape(modal_id)}" hidden>
  <button class="modal-backdrop" type="button" data-close-modal aria-label="{close_label}"></button>
  <section class="modal-panel" role="dialog" aria-modal="true" aria-labelledby="{html_escape(modal_id)}-title">
    <header class="modal-head">
      <h3 id="{html_escape(modal_id)}-title">{html_escape(title)}</h3>
      <button class="icon-button" type="button" data-close-modal aria-label="{close_label}">x</button>
    </header>
    <div class="modal-body">{body}</div>
  </section>
</div>
"""


def confirmation_modal() -> str:
    body = f"""
<div class="danger-zone">
  <h3 id="confirm-action-heading">{t("confirm_heading")}</h3>
  <p class="muted" id="confirm-action-message">{t("confirm_message")}</p>
</div>
<p class="actions">
  <button type="button" data-close-modal>{t("confirm_cancel")}</button>
  <button class="danger" type="button" id="confirm-action-continue">{t("confirm_continue")}</button>
</p>
"""
    return modal("confirm-action", t("confirm_title"), body)


def _credits_section() -> str:
    contributors_html = ""
    if APP_CONTRIBUTORS:
        contr_list = ", ".join(html_escape(c) for c in APP_CONTRIBUTORS)
        contributors_html = f"<tr><td>{t('credits_contributors')}</td><td>{contr_list}</td></tr>"
    website_html = ""
    if APP_WEBSITE:
        url = html_escape(APP_WEBSITE)
        website_html = f'<tr><td>{t("credits_website")}</td><td><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td></tr>'
    docs_html = ""
    if APP_DOCS_URL:
        url = html_escape(APP_DOCS_URL)
        docs_html = f'<tr><td>{t("credits_docs")}</td><td><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td></tr>'
    github_url = html_escape(GITHUB_URL)
    return f"""
<section class="mini-section">
  <h3>{t("credits_title")}</h3>
  <table class="mini-table" style="margin:8px 0">
    <tr><th>{t("credits_field")}</th><th>{t("credits_value")}</th></tr>
    <tr><td>{t("credits_project")}</td><td><b>{html_escape(APP_NAME)}</b></td></tr>
    <tr><td>{t("credits_version")}</td><td><code>v{html_escape(VERSION)}</code></td></tr>
    <tr><td>{t("credits_author")}</td><td>{html_escape(APP_AUTHOR)}</td></tr>
    {contributors_html}
    <tr><td>{t("credits_license")}</td><td>{html_escape(APP_LICENSE)}</td></tr>
    {website_html}
    {docs_html}
  </table>
  <p class="actions" style="margin-top:8px">
    <a class="button" href="{github_url}" target="_blank" rel="noopener noreferrer">{icon_label("github", t("credits_github"))}</a>
  </p>
</section>
"""


def _format_release_timestamp(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return html_escape(value)
    return html_escape(parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


def _render_update_panel(release: dict[str, Any]) -> str:
    enabled = bool(release.get("banner_enabled"))
    available = bool(release.get("available"))
    hidden_attr = "" if (enabled and available) else " hidden"
    title = html_escape(t("dashboard_update_title"))
    subtitle = html_escape(t("dashboard_update_subtitle"))
    return f"""
<section class="release-banner" data-release-banner-root data-release-status-url="/admin/api/update-status" data-release-poll="30000" data-release-state="{html_escape(str(release.get("status") or "unavailable"))}" data-release-enabled="{1 if enabled else 0}"{hidden_attr}>
  <div class="release-banner-copy">
    <strong data-release-title>{title}</strong>
    <span data-release-text>{subtitle}</span>
  </div>
</section>
"""


def global_settings_modal() -> str:
    account_note = t("settings_account_note", path=str(ENV_PATH))
    cur_lang = get_lang()
    change_password_modal = modal(
        "change-admin-password",
        t("passwd_modal_title"),
        f"""
<form method="post" action="/admin/security/password" {confirm_submit_attrs(t("passwd_confirm_title"), t("passwd_confirm_msg"), t("passwd_confirm_label"))}>
  <input type="hidden" name="return_to" value="/admin">
  <p class="muted">{html_escape(account_note)}</p>
  <div class="form-grid">
    <label>{t("passwd_current")}<input type="password" name="current_password" maxlength="{PASSWORD_MAX_LENGTH}" autocomplete="current-password" required></label>
    <label>{t("passwd_new")}<input type="password" name="new_password" minlength="{PASSWORD_MIN_LENGTH}" maxlength="{PASSWORD_MAX_LENGTH}" autocomplete="new-password" required></label>
    <label>{t("passwd_repeat")}<input type="password" name="new_password_confirm" minlength="{PASSWORD_MIN_LENGTH}" maxlength="{PASSWORD_MAX_LENGTH}" autocomplete="new-password" required></label>
  </div>
  <p class="actions"><button class="danger" type="submit">{icon_label("change-secret", t("passwd_submit"))}</button></p>
</form>
""",
        "wide",
    )
    body = f"""
<div class="form-grid">
  <label>{t("settings_language")}
    <select id="lang-select">
      <option value="en"{'  selected' if cur_lang == 'en' else ''}>English</option>
      <option value="ru"{'  selected' if cur_lang == 'ru' else ''}>Русский</option>
      <option value="es"{'  selected' if cur_lang == 'es' else ''}>Español</option>
    </select>
  </label>
  <label>{t("settings_theme")}
    <select id="theme-select">
      <option value="classic">{t("settings_theme_classic")}</option>
      <option value="white">{t("settings_theme_white")}</option>
      <option value="dark">{t("settings_theme_dark")}</option>
    </select>
  </label>
</div>
<div class="notice">
  {t("settings_theme_note")} {t("settings_language_note")}
</div>
<section class="mini-section">
  <h3>{t("settings_admin_account")}</h3>
  <p class="muted">{t("settings_signed_in_as")} <b>{html_escape(ADMIN_USER)}</b>. {html_escape(account_note)}</p>
  <button type="button" data-open-modal="change-admin-password">{icon_label("change-secret", t("settings_change_password"))}</button>
</section>
<section class="mini-section panic-settings-section">
  <h3>{t("panic_settings_section")}</h3>
  <p class="muted">{t("panic_settings_desc")}</p>
  {'<p class="panic-active-note">' + t("panic_settings_active") + '</p>' if is_panic_mode() else ''}
  <a class="button {'danger' if is_panic_mode() else ''}" href="/admin/panic" data-close-modal>{icon_label("panic", t("panic_manage_btn"))}</a>
</section>
{_credits_section()}"""
    return modal("global-settings", t("settings_title"), body) + change_password_modal


def page_shell(title: str, body: str, active: str = "dashboard", app_nav: dict[str, Any] | None = None) -> str:
    sidebar_title = "Key Base"
    sidebar_subtitle = t("shell_license_control")
    active_key = active
    back_html = ""

    topbar_subtitle = t("shell_admin_console")

    if app_nav:
        app = app_nav["app"]
        current_tab = str(app_nav.get("tab", "overview"))
        app_id = str(app["app_id"])
        sidebar_title = str(app["name"])
        sidebar_subtitle = app_id
        topbar_subtitle = t("shell_app_console")
        active_key = current_tab
        nav_items = [
            ("overview", t("nav_overview"), app_href(app_id, "overview"), "overview"),
            ("keys", t("nav_keys"), app_href(app_id, "keys"), "license-key"),
            ("bans", t("nav_bans"), app_href(app_id, "bans"), "bans"),
            ("events", t("nav_events"), app_href(app_id, "events"), "events"),
            ("subscriptions", t("nav_subscriptions"), app_href(app_id, "subscriptions"), "subscription"),
            ("webhooks", t("nav_webhooks"), app_href(app_id, "webhooks"), "webhooks"),
            ("settings", t("nav_settings"), app_href(app_id, "settings"), "settings"),
        ]
        back_html = f'<a class="side-link side-back" href="/admin">{icon_label("back", t("nav_back_to_main"))}</a>'
    else:
        nav_items = [
            ("dashboard", t("nav_dashboard"), "/admin", "dashboard"),
            ("apps", t("nav_applications"), "/admin/apps", "apps"),
            ("global-bans", t("nav_global_bans"), "/admin/bans", "global-bans"),
            ("events", t("nav_audit_log"), "/admin/events", "audit-log"),
            ("protection", t("nav_protection"), "/admin/protection", "settings"),
            ("api", t("nav_api"), "/admin/api", "api-console"),
            ("config", t("nav_config"), "/admin/config", "settings"),
            ("backup", t("nav_backup"), "/admin/backup", "save"),
            ("docs", t("nav_faq"), "/admin/docs", "faq"),
            ("panic", t("panic_nav"), "/admin/panic", "panic"),
        ]
    nav_html = []
    for key, label, href, icon_name in nav_items:
        cls = "side-link active" if key == active_key else "side-link"
        if key == "panic" and is_panic_mode():
            cls += " side-link-panic"
        nav_html.append(f'<a class="{cls}" href="{href}">{icon_label(icon_name, label)}</a>')

    panic_banner = ""
    if is_panic_mode() and active != "panic":
        panic_banner = f'<div class="panic-topbanner">{icon_svg("panic")} {t("panic_banner_msg")} <a href="/admin/panic">{t("panic_banner_link")}</a></div>'
    release_banner = _render_update_panel(github_release_update_info())

    return render_template(
        "layouts/admin_shell.html",
        title=html_escape(title),
        app_name=html_escape(APP_NAME),
        sidebar_title=html_escape(sidebar_title),
        sidebar_subtitle=html_escape(sidebar_subtitle),
        nav_html="".join(nav_html),
        back_html=back_html,
        admin_user=html_escape(ADMIN_USER),
        topbar_subtitle=html_escape(topbar_subtitle),
        github_icon=icon_svg("github"),
        github_url=GITHUB_URL,
        control_icon=icon_svg("control-center"),
        logout_icon=icon_svg("logout"),
        logout_confirm=confirm_submit_attrs(t("shell_logout_confirm_title"), t("shell_logout_confirm_msg"), t("shell_logout_confirm_label")),
        shell_local_admin=html_escape(t("shell_local_admin")),
        shell_logout=html_escape(t("shell_logout")),
        shell_github_tooltip=html_escape(t("shell_github_tooltip")),
        shell_control_center_tooltip=html_escape(t("shell_control_center_tooltip")),
        body=panic_banner + release_banner + body,
        global_settings=global_settings_modal(),
        confirmation_modal=confirmation_modal(),
        confirm_ui_cookie_name=html_escape(CONFIRM_UI_COOKIE_NAME),
        admin_css=template_text("static/admin.css"),
        admin_js=template_text("static/admin.js"),
    )


_ERROR_CODE_KEYS: dict[int, tuple[str, str]] = {
    401: ("error_401_title", "error_401_desc"),
    403: ("error_403_title", "error_403_desc"),
    404: ("error_404_title", "error_404_desc"),
    500: ("error_500_title", "error_500_desc"),
    502: ("error_502_title", "error_502_desc"),
    503: ("error_503_title", "error_503_desc"),
}
_ERROR_CODE_ICONS: dict[int, str] = {
    401: "logout",
    403: "bans",
    404: "faq",
    500: "panic",
    502: "api-console",
    503: "panic",
}


def render_error_page(
    code: int,
    title: str | None = None,
    desc: str | None = None,
    *,
    show_back: bool = True,
) -> str:
    title_key, desc_key = _ERROR_CODE_KEYS.get(code, ("error_generic_title", "error_generic_desc"))
    error_title = title or t(title_key)
    error_desc = desc or t(desc_key)
    error_icon = icon_svg(_ERROR_CODE_ICONS.get(code, "panic"))
    back_btn = ""
    if show_back:
        back_btn = (
            f'<button class="button" id="err-back">'
            f"{html_escape(t('error_go_back'))}</button>"
        )
    return render_template(
        "layouts/error_page.html",
        error_code=str(code),
        error_title=html_escape(error_title),
        error_desc=html_escape(error_desc),
        error_icon=error_icon,
        back_button=back_btn,
        home_label=html_escape(t("error_home")),
        app_name=html_escape(APP_NAME),
        admin_css=template_text("static/admin.css"),
    )

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html_escape(title)} - {APP_NAME}</title>
  <script>
    (function () {{
      var theme = localStorage.getItem('keybase-theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'classic');
      document.documentElement.setAttribute('data-theme', theme);
    }})();
  </script>
  <style>
    [hidden] {{ display: none !important; }}
    :root {{
      --bg: #e7eaf0;
      --side: #182437;
      --side-soft: #22314a;
      --panel: #f8f9fb;
      --panel-2: #ffffff;
      --topbar: #f5f7fa;
      --input: #ffffff;
      --table-head: #edf1f6;
      --card-inner: #f7f9fc;
      --modal-backdrop: rgba(12, 22, 36, .45);
      --line: #b7c0cc;
      --line-soft: #d9dee7;
      --text: #18202b;
      --muted: #667284;
      --blue: #2463a6;
      --blue-2: #e8f1fb;
      --green: #146c43;
      --green-bg: #e5f4ec;
      --red: #9f2836;
      --red-bg: #f8e6e8;
      --yellow: #8a5a00;
      --yellow-bg: #fff4d8;
      --radius: 6px;
      --shadow: 0 10px 25px rgba(30, 42, 62, .12);
    }}
    html[data-theme="white"] {{
      --bg: #ffffff;
      --side: #121a28;
      --side-soft: #1d293b;
      --panel: #ffffff;
      --panel-2: #ffffff;
      --topbar: #ffffff;
      --input: #ffffff;
      --table-head: #f2f4f7;
      --card-inner: #f8fafc;
      --modal-backdrop: rgba(18, 26, 40, .42);
      --line: #c9d1dc;
      --line-soft: #e4e8ef;
      --text: #111827;
      --muted: #5b6677;
      --shadow: 0 10px 25px rgba(15, 23, 42, .08);
    }}
    html[data-theme="dark"] {{
      --bg: #0d131d;
      --side: #070b12;
      --side-soft: #121b2a;
      --panel: #151d2a;
      --panel-2: #101722;
      --topbar: #101722;
      --input: #0b111b;
      --table-head: #1d2938;
      --card-inner: #101722;
      --modal-backdrop: rgba(0, 0, 0, .68);
      --line: #344155;
      --line-soft: #253144;
      --text: #e7edf6;
      --muted: #99a6ba;
      --blue: #6aa7ff;
      --blue-2: #14253d;
      --green: #72d99d;
      --green-bg: #10281c;
      --red: #ff8d9a;
      --red-bg: #33141b;
      --yellow: #f2c35f;
      --yellow-bg: #342815;
      --shadow: 0 12px 34px rgba(0, 0, 0, .38);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      height: 100vh;
      overflow: hidden;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      font-size: 13px;
      line-height: 1.35;
    }}
    a {{ color: var(--blue); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    svg {{ width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }}
    .layout {{ display: grid; grid-template-columns: 224px minmax(0, 1fr); height: 100vh; overflow: hidden; }}
    .sidebar {{ height: 100vh; overflow: hidden; background: var(--side); color: #fff; padding: 14px 12px; display: flex; flex-direction: column; }}
    .sidebar nav {{ flex: 1; min-height: 0; overflow-y: auto; padding-right: 2px; }}
    .brand {{ display: flex; align-items: center; gap: 10px; padding: 4px 6px 18px; border-bottom: 1px solid rgba(255,255,255,.12); margin-bottom: 8px; }}
    .brand-wordmark {{ letter-spacing: .02em; }}
    .brand b {{ display: block; font-size: 15px; }}
    .brand span {{ display: block; color: #b8c5d8; font-size: 11px; }}
    .side-link {{ display: flex; align-items: center; gap: 9px; color: #dce6f4; padding: 9px 9px; border-radius: 5px; margin-bottom: 3px; }}
    .side-link:hover {{ background: var(--side-soft); text-decoration: none; }}
    .side-link.active {{ background: var(--blue-2); color: var(--text); }}
    .side-back {{ margin-top: 8px; border: 1px solid rgba(255,255,255,.12); }}
    .sidebar-footer {{ border-top: 1px solid rgba(255,255,255,.12); margin-top: 10px; padding-top: 10px; }}
    .user-card {{ display: flex; align-items: center; gap: 9px; padding: 7px 6px 2px; min-width: 0; }}
    .avatar {{ width: 34px; height: 34px; border-radius: 50%; object-fit: cover; border: 1px solid rgba(255,255,255,.35); background: #0d1623; flex: 0 0 auto; }}
    .user-card b, .user-card span {{ display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .user-card b {{ font-size: 13px; color: #fff; }}
    .user-card span {{ font-size: 11px; color: #b8c5d8; }}
    .main {{ min-width: 0; height: 100vh; overflow-y: auto; }}
    .topbar {{ height: 54px; display: flex; align-items: center; justify-content: space-between; padding: 0 18px; background: var(--topbar); border-bottom: 1px solid var(--line); }}
    .topbar-title b {{ display: block; font-size: 15px; }}
    .topbar-title span {{ color: var(--muted); font-size: 12px; }}
    .top-actions {{ display: flex; gap: 7px; align-items: center; }}
    .content {{ padding: 16px 18px 28px; max-width: 1360px; }}
    h1 {{ margin: 0 0 4px; font-size: 23px; letter-spacing: 0; }}
    h2 {{ margin: 0 0 10px; font-size: 17px; letter-spacing: 0; }}
    h3 {{ margin: 0; font-size: 15px; letter-spacing: 0; }}
    p {{ margin: 6px 0; }}
    .muted {{ color: var(--muted); }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 12px; margin-bottom: 12px; box-shadow: 0 1px 0 rgba(255,255,255,.8) inset; }}
    html[data-theme="dark"] .panel {{ box-shadow: none; }}
    .panel-head {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 10px; }}
    .panel-head p {{ margin: 2px 0 0; color: var(--muted); }}
    .stat-grid {{ display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr)); gap: 10px; }}
    .stat {{ background: var(--panel-2); border: 1px solid var(--line-soft); border-radius: var(--radius); padding: 10px; }}
    .stat b {{ display: block; font-size: 24px; line-height: 1; margin-bottom: 5px; }}
    .stat span {{ color: var(--muted); }}
    .app-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }}
    .app-card {{ background: var(--panel-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 11px; }}
    .app-card:hover {{ border-color: #7da5cf; box-shadow: var(--shadow); }}
    .app-card-title {{ display: flex; justify-content: space-between; align-items: start; gap: 8px; }}
    .app-meta {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; margin: 10px 0; }}
    .app-meta div {{ border: 1px solid var(--line-soft); background: var(--card-inner); border-radius: 4px; padding: 6px; }}
    .app-meta b {{ display: block; font-size: 16px; }}
    .toolbar {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: end; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel-2); border: 1px solid var(--line); }}
    th, td {{ border-bottom: 1px solid var(--line-soft); padding: 7px 8px; text-align: left; vertical-align: middle; }}
    th {{ background: var(--table-head); color: var(--text); font-size: 12px; }}
    tr:last-child td {{ border-bottom: 0; }}
    td form {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
    code {{ background: var(--card-inner); border: 1px solid var(--line); border-radius: 4px; padding: 1px 4px; }}
    pre {{ background: var(--card-inner); color: var(--text); border: 1px solid var(--line); border-radius: var(--radius); padding: 10px; overflow: auto; }}
    .copy-chip {{ max-width: 100%; border: 1px solid var(--line); border-radius: 4px; background: var(--card-inner); color: var(--text); padding: 2px 5px; min-height: 24px; display: inline-flex; align-items: center; gap: 6px; vertical-align: middle; cursor: copy; font-family: Consolas, "Courier New", monospace; line-height: 1.2; }}
    .copy-chip.compact {{ max-width: 470px; }}
    .copy-chip:hover, .copy-chip:focus {{ border-color: var(--blue); background: var(--blue-2); outline: none; }}
    .copy-chip-text {{ display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; transition: filter .18s ease, opacity .18s ease, transform .18s ease; }}
    .copy-chip.is-blurred .copy-chip-text {{ filter: blur(4px); opacity: .58; transform: scale(.985); }}
    .copy-chip.is-blurred:hover .copy-chip-text, .copy-chip.is-blurred:focus .copy-chip-text {{ filter: blur(0px); opacity: 1; transform: scale(1); }}
    .copy-chip-hint {{ color: var(--muted); font-family: Arial, Helvetica, sans-serif; font-size: 10px; text-transform: uppercase; letter-spacing: 0; opacity: .65; }}
    .copy-chip.copied {{ border-color: var(--green); color: var(--green); }}
    .copy-chip.copied .copy-chip-hint {{ color: var(--green); opacity: 1; }}
    input, select, textarea, button {{ font-family: Arial, Helvetica, sans-serif; font-size: 13px; }}
    input, select, textarea {{ width: 100%; min-width: 0; border: 1px solid var(--line); border-radius: 4px; padding: 6px 7px; background: var(--input); color: var(--text); }}
    textarea {{ min-height: 70px; resize: vertical; }}
    label {{ display: grid; gap: 4px; min-width: 0; color: var(--text); font-size: 12px; font-weight: 700; }}
    button, .button {{ border: 1px solid var(--line); border-radius: 4px; background: var(--table-head); color: var(--text); padding: 6px 10px; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; min-height: 30px; }}
    button:hover, .button:hover {{ background: var(--line-soft); text-decoration: none; }}
    .primary {{ background: var(--blue); border-color: #1c5188; color: #fff; }}
    .primary:hover {{ background: #1e568f; }}
    .danger {{ background: var(--red-bg); border-color: #c48b92; color: var(--red); }}
    .ghost {{ background: transparent; }}
    .icon-button {{ width: 32px; height: 32px; padding: 0; justify-content: center; }}
    .status {{ display: inline-flex; align-items: center; min-height: 22px; border-radius: 999px; border: 1px solid; padding: 2px 8px; font-size: 12px; font-weight: 700; }}
    .status-ok {{ background: var(--green-bg); color: var(--green); border-color: #9fd1b7; }}
    .status-warn {{ background: var(--yellow-bg); color: var(--yellow); border-color: #e5c56e; }}
    .status-bad {{ background: var(--red-bg); color: var(--red); border-color: #dea1a8; }}
    .status-muted {{ background: var(--table-head); color: var(--muted); border-color: var(--line); }}
    .kind-badge {{ display: inline-flex; min-width: 42px; justify-content: center; border: 1px solid var(--line); border-radius: 999px; padding: 2px 7px; font-weight: 700; font-size: 11px; background: var(--table-head); color: var(--text); }}
    .kind-country {{ background: var(--blue-2); color: var(--blue); }}
    .compact-token {{ width: 155px; min-width: 155px; max-width: 210px; }}
    .mini-section {{ border: 1px solid var(--line); background: var(--panel-2); border-radius: var(--radius); padding: 10px; margin: 10px 0; }}
    .form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
    .form-row {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: end; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 7px; align-items: center; }}
    .notice {{ background: var(--blue-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 9px; color: var(--text); margin: 9px 0; }}
    .split {{ display: grid; grid-template-columns: minmax(0, 1fr) 330px; gap: 12px; }}
    .mini-table th, .mini-table td {{ padding: 6px; font-size: 12px; }}
    .pagination {{ display: flex; flex-wrap: wrap; gap: 5px; align-items: center; margin-top: 10px; }}
    .page-link {{ border: 1px solid var(--line); background: var(--panel-2); color: var(--text); border-radius: 4px; padding: 5px 9px; }}
    .page-link.active {{ background: var(--blue); border-color: var(--blue); color: #fff; }}
    .page-gap {{ color: var(--muted); padding: 0 4px; }}
    .click-row {{ cursor: pointer; }}
    .click-row:hover td {{ background: var(--blue-2); }}
    .detail-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-bottom: 10px; }}
    .detail-grid div {{ background: var(--panel-2); border: 1px solid var(--line-soft); border-radius: 5px; padding: 8px; }}
    .detail-grid span {{ display: block; color: var(--muted); font-size: 11px; margin-bottom: 3px; }}
    .detail-grid b {{ word-break: break-word; }}
    .detail-section {{ margin-top: 10px; }}
    .doc-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .doc-list {{ margin: 8px 0 0 18px; padding: 0; }}
    .doc-list li {{ margin-bottom: 5px; }}
    .country-field {{ position: relative; min-width: 260px; }}
    .country-trigger {{ width: 100%; justify-content: flex-start; background: var(--input); }}
    .country-code {{ display: inline-flex; align-items: center; justify-content: center; min-width: 34px; height: 22px; border: 1px solid var(--line); border-radius: 4px; background: var(--blue-2); color: var(--blue); font-weight: 700; font-size: 11px; }}
    .country-popover {{ position: absolute; z-index: 20; top: calc(100% + 5px); left: 0; width: min(360px, 88vw); background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); padding: 8px; }}
    .country-menu {{ max-height: 176px; overflow-y: auto; display: grid; gap: 4px; margin-top: 6px; }}
    .country-option {{ width: 100%; justify-content: flex-start; background: var(--panel-2); }}
    .country-option[hidden] {{ display: none; }}
    .password-confirmed-note {{ display: none; color: var(--green); font-weight: 700; }}
    .password-confirmed .confirm-password-wrap {{ display: none; }}
    .password-confirmed .password-confirmed-note {{ display: block; }}
    .modal[hidden] {{ display: none !important; }}
    .modal {{ position: fixed; inset: 0; z-index: 50; display: grid; place-items: center; padding: 18px; }}
    .modal-backdrop, .modal-backdrop:hover {{ position: absolute; inset: 0; display: block; width: 100%; height: 100%; min-height: 0; padding: 0; border: 0; border-radius: 0; background: var(--modal-backdrop); }}
    .modal-panel {{ position: relative; width: min(660px, 96vw); max-height: 90vh; overflow: auto; background: var(--panel); color: var(--text); border: 1px solid var(--line); border-radius: 7px; box-shadow: 0 24px 80px rgba(0,0,0,.32); }}
    .modal.wide .modal-panel {{ width: min(860px, 96vw); }}
    .modal-head {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 10px 12px; background: var(--table-head); border-bottom: 1px solid var(--line); }}
    .modal-body {{ padding: 12px; }}
    .danger-zone {{ border: 1px solid #e3a1a9; background: var(--red-bg); border-radius: var(--radius); padding: 10px; margin-top: 10px; }}
    @media (max-width: 900px) {{
      body {{ height: auto; overflow: auto; }}
      .layout {{ grid-template-columns: 1fr; height: auto; overflow: visible; }}
      .sidebar {{ height: auto; overflow: visible; }}
      .sidebar nav {{ overflow: visible; }}
      .sidebar-footer {{ margin-top: 6px; }}
      .main {{ height: auto; overflow: visible; }}
      .stat-grid {{ grid-template-columns: repeat(2, minmax(130px, 1fr)); }}
      .split {{ grid-template-columns: 1fr; }}
      .doc-grid, .detail-grid {{ grid-template-columns: 1fr; }}
      .content {{ padding: 12px; }}
    }}
  </style>
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-wordmark"><b>{html_escape(sidebar_title)}</b><span>{html_escape(sidebar_subtitle)}</span></div>
    </div>
    <nav>{''.join(nav_html)}</nav>
    <div class="sidebar-footer">
      {back_html}
      <div class="user-card">
        <img class="avatar" src="/assets/default-avatar.png" alt="">
        <div><b>{html_escape(ADMIN_USER)}</b><span>Local administrator</span></div>
      </div>
    </div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div class="topbar-title"><b>{html_escape(title)}</b><span>{html_escape(topbar_subtitle)}</span></div>
      <div class="top-actions">
        <button class="icon-button" type="button" data-open-modal="global-settings" title="Control Center" aria-label="Control Center">{icon_svg("settings")}</button>
        <form method="post" action="/admin/logout" {confirm_submit_attrs("Logout?", "This will end the current admin session in this browser.", "Logout")}><button type="submit">Logout</button></form>
      </div>
    </header>
    <div class="content">{body}</div>
  </main>
</div>
{global_settings_modal()}
{confirmation_modal()}
<script>
var pendingConfirmAction = null;
function showConfirmAction(config) {{
  pendingConfirmAction = config;
  var modal = document.getElementById('confirm-action');
  var heading = document.getElementById('confirm-action-heading');
  var message = document.getElementById('confirm-action-message');
  var button = document.getElementById('confirm-action-continue');
  if (!modal || !button) return;
  if (heading) heading.textContent = config.title || 'Are you sure?';
  if (message) message.textContent = config.message || 'This action needs confirmation.';
  button.textContent = config.label || 'Continue';
  modal.hidden = false;
}}
document.addEventListener('click', function (event) {{
  var copyTarget = event.target.closest('[data-copy-value]');
  if (copyTarget) {{
    event.preventDefault();
    event.stopPropagation();
    var text = copyTarget.getAttribute('data-copy-value') || '';
    function markCopied() {{
      copyTarget.classList.add('copied');
      var hint = copyTarget.querySelector('.copy-chip-hint');
      var oldHint = hint ? hint.textContent : '';
      if (hint) hint.textContent = 'copied';
      window.setTimeout(function () {{
        copyTarget.classList.remove('copied');
        if (hint) hint.textContent = oldHint || 'copy';
      }}, 900);
    }}
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(markCopied).catch(markCopied);
    }} else {{
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {{ document.execCommand('copy'); }} catch (err) {{}}
      document.body.removeChild(textarea);
      markCopied();
    }}
    return;
  }}
  var confirmOpen = event.target.closest('[data-confirm-open-modal]');
  if (confirmOpen) {{
    event.preventDefault();
    event.stopPropagation();
    showConfirmAction({{
      kind: 'open',
      target: confirmOpen.getAttribute('data-confirm-open-modal'),
      title: confirmOpen.getAttribute('data-confirm-title'),
      message: confirmOpen.getAttribute('data-confirm-message'),
      label: confirmOpen.getAttribute('data-confirm-label')
    }});
    return;
  }}
  var open = event.target.closest('[data-open-modal]');
  if (open) {{
    var modal = document.getElementById(open.getAttribute('data-open-modal'));
    if (modal) modal.hidden = false;
  }}
  if (event.target.closest('[data-close-modal]')) {{
    event.target.closest('.modal').hidden = true;
  }}
}});
document.addEventListener('submit', function (event) {{
  var form = event.target.closest('form[data-confirm-submit]');
  if (!form) return;
  if (form.dataset.confirmed === '1') {{
    delete form.dataset.confirmed;
    return;
  }}
  event.preventDefault();
  showConfirmAction({{
    kind: 'submit',
    form: form,
    title: form.getAttribute('data-confirm-title'),
    message: form.getAttribute('data-confirm-message'),
    label: form.getAttribute('data-confirm-label')
  }});
}});
var confirmContinue = document.getElementById('confirm-action-continue');
if (confirmContinue) {{
  confirmContinue.addEventListener('click', function () {{
    var action = pendingConfirmAction;
    pendingConfirmAction = null;
    var confirmModal = document.getElementById('confirm-action');
    if (confirmModal) confirmModal.hidden = true;
    if (!action) return;
    if (action.kind === 'open') {{
      var targetModal = document.getElementById(action.target);
      if (targetModal) targetModal.hidden = false;
      return;
    }}
    if (action.kind === 'submit' && action.form) {{
      action.form.dataset.confirmed = '1';
      if (action.form.requestSubmit) action.form.requestSubmit();
      else action.form.submit();
    }}
  }});
}}
function applyTheme(theme) {{
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('keybase-theme', theme);
}}
var themeSelect = document.getElementById('theme-select');
if (themeSelect) {{
  themeSelect.value = localStorage.getItem('keybase-theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'classic');
  themeSelect.addEventListener('change', function () {{ applyTheme(themeSelect.value); }});
}}
function cookieValue(name) {{
  return document.cookie.split(';').map(function (item) {{ return item.trim(); }}).filter(function (item) {{ return item.indexOf(name + '=') === 0; }}).map(function (item) {{ return item.slice(name.length + 1); }})[0] || '';
}}
function passwordConfirmationActive() {{
  var until = parseInt(cookieValue('{CONFIRM_UI_COOKIE_NAME}'), 10);
  return !!until && until * 1000 > Date.now();
}}
function applyDangerPasswordState() {{
  var active = passwordConfirmationActive();
  document.querySelectorAll('[data-danger-form]').forEach(function (form) {{
    form.classList.toggle('password-confirmed', active);
    form.querySelectorAll('input[name="confirm_password"]').forEach(function (input) {{
      input.disabled = active;
      input.required = !active;
      if (active) input.value = '';
    }});
  }});
}}
function setupBanForm(form) {{
  var kind = form.querySelector('[data-ban-kind]');
  var valueField = form.querySelector('[data-ban-value-field]');
  var valueInput = form.querySelector('[data-ban-value-input]');
  var countryField = form.querySelector('[data-country-field]');
  var countryHidden = form.querySelector('[data-country-hidden]');
  var trigger = form.querySelector('[data-country-trigger]');
  var popover = form.querySelector('[data-country-popover]');
  var label = form.querySelector('[data-country-label]');
  var search = form.querySelector('[data-country-search]');
  function syncKind() {{
    var countryMode = kind.value === 'country';
    valueField.hidden = countryMode;
    valueInput.disabled = countryMode;
    countryField.hidden = !countryMode;
    countryHidden.disabled = !countryMode;
    if (!countryMode && popover) popover.hidden = true;
  }}
  function filterCountries() {{
    var needle = (search.value || '').trim().toLowerCase();
    form.querySelectorAll('[data-country-option]').forEach(function (button) {{
      var match = !needle || button.dataset.code.toLowerCase().indexOf(needle) >= 0 || button.dataset.name.indexOf(needle) >= 0;
      button.hidden = !match;
    }});
  }}
  kind.addEventListener('change', syncKind);
  trigger.addEventListener('click', function () {{
    popover.hidden = !popover.hidden;
    if (!popover.hidden) {{ search.focus(); filterCountries(); }}
  }});
  search.addEventListener('input', filterCountries);
  form.querySelectorAll('[data-country-option]').forEach(function (button) {{
    button.addEventListener('click', function () {{
      countryHidden.value = button.dataset.code;
      trigger.querySelector('.country-code').textContent = button.dataset.code;
      label.textContent = button.textContent.trim().replace(button.dataset.code, '').trim();
      popover.hidden = true;
    }});
  }});
  form.addEventListener('submit', function (event) {{
    if (kind.value === 'country' && !countryHidden.value) {{
      event.preventDefault();
      popover.hidden = false;
      search.focus();
    }}
  }});
  syncKind();
}}
document.querySelectorAll('[data-ban-form]').forEach(setupBanForm);
document.addEventListener('click', function (event) {{
  if (!event.target.closest('[data-country-field]')) {{
    document.querySelectorAll('[data-country-popover]').forEach(function (popover) {{ popover.hidden = true; }});
  }}
}});
applyDangerPasswordState();
document.addEventListener('keydown', function (event) {{
  if (event.key === 'Escape') {{
    document.querySelectorAll('.modal').forEach(function (modal) {{ modal.hidden = true; }});
  }}
}});
</script>
</body>
</html>"""


def setup_page(message: str = "") -> str:
    msg = f'<p class="status status-bad">{html_escape(message)}</p>' if message else ""
    return render_template(
        "pages/setup.html",
        app_name=html_escape(APP_NAME),
        message=msg,
        env_path=html_escape(str(ENV_PATH)),
        suggested_user=html_escape(ADMIN_USER),
        setup_title=html_escape(t("setup_title")),
        setup_subtitle=html_escape(t("setup_subtitle")),
        setup_username=html_escape(t("setup_username")),
        setup_password=html_escape(t("setup_password")),
        setup_repeat=html_escape(t("setup_repeat")),
        setup_submit=html_escape(t("setup_submit")),
        setup_credentials_note=html_escape(t("setup_credentials_note", path=str(ENV_PATH))),
        setup_tip1=html_escape(t("setup_tip1")),
        setup_tip2=html_escape(t("setup_tip2")),
        setup_tip3=html_escape(t("setup_tip3")),
    )


def login_page(message: str = "") -> str:
    if not admin_configured():
        return setup_page(message)
    msg = f'<p class="status status-bad">{html_escape(message)}</p>' if message else ""
    return render_template(
        "pages/login.html",
        app_name=html_escape(APP_NAME),
        message=msg,
        admin_user=html_escape(ADMIN_USER),
        session_hours=str(SESSION_MAX_SECONDS // 3600),
        login_admin_console=html_escape(t("login_admin_console")),
        login_password=html_escape(t("login_password")),
        login_submit=html_escape(t("login_submit")),
        login_session_note=html_escape(t("login_session_note", hours=SESSION_MAX_SECONDS // 3600)),
    )


def stat_card(label: str, value: Any, sensitive: bool = False) -> str:
    value_html = (
        f'<span class="stat-blur">{html_escape(str(value))}</span>'
        if sensitive
        else html_escape(str(value))
    )
    return f'<div class="stat"><b>{value_html}</b><span>{html_escape(label)}</span></div>'


def query_param(query: dict[str, list[str]] | None, name: str, default: str = "") -> str:
    if not query:
        return default
    value = query.get(name, [default])
    return value[0] if value else default


PAGINATION_DEFAULT_LIMIT = 25
PAGINATION_MAX_LIMIT = 100
PAGINATION_LIMIT_OPTIONS = (10, 25, 50, 100)


def page_state(
    query: dict[str, list[str]] | None,
    page_param: str = "page",
    per_page: int = PAGINATION_DEFAULT_LIMIT,
    limit_param: str = "limit",
    max_limit: int = PAGINATION_MAX_LIMIT,
) -> tuple[int, int, int]:
    page = as_int(query_param(query, page_param, "1"), 1, minimum=1)
    default_limit = max(1, min(int(per_page or PAGINATION_DEFAULT_LIMIT), max_limit))
    limit = as_int(query_param(query, limit_param, str(default_limit)), default_limit, minimum=1, maximum=max_limit)
    return page, limit, (page - 1) * limit


def pagination_bounds(total_items: int, page: int, per_page: int) -> tuple[int, int, int]:
    total = max(0, int(total_items or 0))
    limit = max(1, min(int(per_page or PAGINATION_DEFAULT_LIMIT), PAGINATION_MAX_LIMIT))
    total_pages = max((total + limit - 1) // limit, 1)
    current_page = min(max(1, int(page or 1)), total_pages)
    return current_page, total_pages, (current_page - 1) * limit


def pagination_window(current_page: int, total_pages: int) -> list[int | str]:
    if total_pages <= 1:
        return [1]
    candidates = {1, total_pages}
    for page in range(current_page - 2, current_page + 3):
        if 1 <= page <= total_pages:
            candidates.add(page)
    pages = sorted(candidates)
    window: list[int | str] = []
    previous = 0
    for page in pages:
        if previous and page - previous > 1:
            window.append("...")
        window.append(page)
        previous = page
    return window


def _pagination_clean_params(params: dict[str, Any] | None, exclude: set[str] | None = None) -> dict[str, Any]:
    exclude = exclude or set()
    clean: dict[str, Any] = {}
    for key, value in (params or {}).items():
        if key in exclude or value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        clean[key] = value
    return clean


def _pagination_hidden_inputs(params: dict[str, Any], exclude: set[str]) -> str:
    fields: list[str] = []
    for key, value in _pagination_clean_params(params, exclude).items():
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            if item is None or str(item) == "":
                continue
            fields.append(
                f'<input type="hidden" name="{html_escape(key)}" value="{html_escape(item)}">'
            )
    return "".join(fields)


def pagination_links(
    base_path: str,
    current_page: int,
    total_pages: int,
    params: dict[str, Any] | None = None,
    page_param: str = "page",
    limit_param: str = "limit",
    current_limit: int | None = None,
    total_items: int | None = None,
    show_page_size: bool = True,
    show_jump: bool = True,
) -> str:
    total_pages = max(1, int(total_pages or 1))
    current_page = min(max(1, int(current_page or 1)), total_pages)
    current_limit = as_int(
        current_limit if current_limit is not None else (params or {}).get(limit_param, PAGINATION_DEFAULT_LIMIT),
        PAGINATION_DEFAULT_LIMIT,
        minimum=1,
        maximum=PAGINATION_MAX_LIMIT,
    )
    parsed_base = urlparse(base_path)
    base_only = parsed_base.path or base_path.split("?", 1)[0]
    base_params = {key: values[-1] for key, values in parse_qs(parsed_base.query, keep_blank_values=True).items()}
    params = _pagination_clean_params({**base_params, **(params or {})}, {page_param, limit_param})

    if total_pages <= 1 and not show_page_size:
        return ""

    def href(page: int) -> str:
        next_params = dict(params)
        next_params[page_param] = page
        next_params[limit_param] = current_limit
        query = urlencode(next_params, doseq=True)
        return base_only + ("?" + query if query else "")

    parts: list[str] = []
    if total_pages > 1:
        prev_cls = "page-link page-edge" if current_page > 1 else "page-link page-edge disabled"
        next_cls = "page-link page-edge" if current_page < total_pages else "page-link page-edge disabled"
        if current_page > 1:
            parts.append(f'<a class="{prev_cls}" href="{href(current_page - 1)}">Previous</a>')
        else:
            parts.append(f'<span class="{prev_cls}" aria-disabled="true">Previous</span>')
        for item in pagination_window(current_page, total_pages):
            if item == "...":
                parts.append('<span class="page-gap">...</span>')
                continue
            page = int(item)
            cls = "page-link active" if page == current_page else "page-link"
            aria = ' aria-current="page"' if page == current_page else ""
            parts.append(f'<a class="{cls}" href="{href(page)}"{aria}>{page}</a>')
        if current_page < total_pages:
            parts.append(f'<a class="{next_cls}" href="{href(current_page + 1)}">Next</a>')
        else:
            parts.append(f'<span class="{next_cls}" aria-disabled="true">Next</span>')

    tools: list[str] = []
    if show_page_size:
        size_options = "".join(
            f'<option value="{size}" {"selected" if size == current_limit else ""}>{size}</option>'
            for size in PAGINATION_LIMIT_OPTIONS
        )
        tools.append(
            f"""<form class="pagination-size" method="get" action="{html_escape(base_only)}">
{_pagination_hidden_inputs(params, {page_param, limit_param})}
<input type="hidden" name="{html_escape(page_param)}" value="1">
<label>Rows<select name="{html_escape(limit_param)}" onchange="this.form.submit()">{size_options}</select></label>
<noscript><button type="submit">Apply</button></noscript>
</form>"""
        )
    if show_jump and total_pages > 1:
        tools.append(
            f"""<form class="pagination-jump" method="get" action="{html_escape(base_only)}">
{_pagination_hidden_inputs(params, {page_param, limit_param})}
<input type="hidden" name="{html_escape(limit_param)}" value="{html_escape(current_limit)}">
<label>Page<input name="{html_escape(page_param)}" type="number" min="1" max="{html_escape(total_pages)}" value="{html_escape(current_page)}"></label>
<button type="submit">Go</button>
</form>"""
        )
    total_attr = "" if total_items is None else f' data-total-items="{html_escape(total_items)}"'
    return (
        f'<div class="pagination" data-current-page="{html_escape(current_page)}" '
        f'data-total-pages="{html_escape(total_pages)}" data-items-per-page="{html_escape(current_limit)}"{total_attr}>'
        f'<div class="pagination-pages">{"".join(parts)}</div>'
        f'<div class="pagination-tools">{"".join(tools)}</div>'
        "</div>"
    )


def event_detail_modal(row: sqlite3.Row) -> str:
    scope = row["app_id"] or "Global"
    display_country = best_effort_country(row["country"], row["ip"])
    body = f"""
<div class="detail-grid">
  <div><span>{t("event_detail_id")}</span><b>#{html_escape(row["id"])}</b></div>
  <div><span>{t("event_detail_time")}</span><b>{html_escape(row["created_at"])}</b></div>
  <div><span>{t("event_detail_type")}</span><b>{html_escape(row["event_type"])}</b></div>
  <div><span>{t("event_detail_status")}</span><b>{html_escape(row["status"] or "info")}</b></div>
  <div><span>{t("event_detail_scope")}</span><b>{html_escape(scope)}</b></div>
  <div><span>{t("event_detail_country")}</span><b class="country-inline">{country_badge(display_country, compact=True)}</b></div>
  <div><span>{t("event_detail_ip")}</span><b>{copy_chip(row["ip"], "IP address", sensitive=True)}</b></div>
</div>
<div class="detail-section">
  <h3>{t("event_detail_license_ctx")}</h3>
  <table class="mini-table">
    <tr><th>{t("event_detail_key")}</th><td>{copy_chip(row["key_text"], "license key", sensitive=False, compact=False)}</td></tr>
    <tr><th>{t("event_detail_hwid")}</th><td>{copy_chip(row["hwid"], "HWID", sensitive=True, compact=False)}</td></tr>
    <tr><th>{t("event_detail_application")}</th><td>{html_escape(row["app_id"] or "-")}</td></tr>
  </table>
</div>
<div class="detail-section">
  <h3>{t("event_detail_message")}</h3>
  <pre>{html_escape(row["message"] or t("event_detail_no_message"))}</pre>
</div>
"""
    event_id = row["id"]

    return modal(
        f"event-details-{html_escape(event_id)}",
        t("event_detail_title", id=event_id),
        body,
        "wide"
    )


def render_events_table(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return f'<p class="muted">{t("events_empty")}</p>'
    tr = []
    modals = []
    for row in rows:
        display_country = best_effort_country(row["country"], row["ip"])
        tr.append(
            f"""<tr class="click-row" data-open-modal="event-details-{html_escape(row["id"])}" title="Open event details">
  <td>{html_escape(row["created_at"])}</td>
  <td>{html_escape(row["event_type"])}</td>
  <td>{html_escape(row["app_id"] or "-")}</td>
  <td>{copy_chip(row["key_text"], "license key")}</td>
  <td><span class="country-inline">{country_badge(display_country, include_name=False, compact=True)}</span></td>
  <td>{copy_chip(row["ip"], "IP address", sensitive=True)}</td>
  <td>{copy_chip(row["hwid"], "HWID", sensitive=True)}</td>
  <td>{status_badge(row["status"] or "info")}</td>
  <td>{html_escape(row["message"] or "")}</td>
</tr>"""
        )
        modals.append(event_detail_modal(row))
    return f"""<table>
<tr><th>{t("events_col_time")}</th><th>{t("events_col_event")}</th><th>{t("events_col_app")}</th><th>{t("events_col_key")}</th><th>{t("events_col_country")}</th><th>{t("events_col_ip")}</th><th>{t("events_col_hwid")}</th><th>{t("events_col_status")}</th><th>{t("events_col_message")}</th></tr>
{''.join(tr)}
</table>
{''.join(modals)}"""


def app_settings_modal(row: sqlite3.Row, return_to: str) -> str:
    app_id = row["app_id"]
    selected = {status: "selected" if row["status"] == status else "" for status in APP_STATUSES}
    prefix = app_default_prefix(row)
    body = f"""
<form method="post" action="/admin/apps/update">
  <input type="hidden" name="app_id" value="{html_escape(app_id)}">
  <input type="hidden" name="return_to" value="{html_escape(return_to)}">
  <div class="form-grid">
    <label>{t("app_settings_name")}<input name="name" value="{html_escape(row["name"])}" minlength="1" maxlength="80"></label>
    <label>{t("app_settings_status")}
      <select name="status">
        <option value="active" {selected["active"]}>{t("status_active")}</option>
        <option value="paused" {selected["paused"]}>{t("status_paused")}</option>
        <option value="disabled" {selected["disabled"]}>{t("status_disabled")}</option>
      </select>
    </label>
    <label>{t("app_settings_prefix")}<input name="default_prefix" value="{html_escape(prefix)}" minlength="1" maxlength="8" pattern="[A-Za-z0-9]{{1,8}}"></label>
  </div>
  {app_security_fields(row)}
  <div class="notice">{t("app_settings_pause_note")}</div>
  <p class="actions"><button class="primary" type="submit">{icon_label("save", t("app_settings_save"))}</button></p>
</form>
{app_secret_panel(row, return_to, "-modal")}
{app_delete_form(app_id, return_to, "-modal")}
"""
    return modal(f"app-settings-{html_escape(app_id)}", f"{t('app_settings_title')} - {app_id}", body, "wide")


def key_settings_modal(conn: sqlite3.Connection, row: sqlite3.Row, return_to: str) -> str:
    status = row["status"] if row["status"] in KEY_STATUSES else "disabled"
    selected = {item: "selected" if status == item else "" for item in KEY_STATUSES}
    duration_value, duration_unit = duration_parts(row_value(row, "duration_seconds"))
    if not positive_duration_seconds(row_value(row, "duration_seconds")):
        duration_unit = "lifetime" if not row_value(row, "expires_at") else "days"
    activation_note = t("key_settings_not_activated") if not row_value(row, "activated_at") else t("key_settings_activated_at", ts=row_value(row, "activated_at"))
    reset_modal_id = f"reset-key-{row['id']}"
    delete_modal_id = f"delete-key-{row['id']}"
    levels = subscription_levels(conn, row["app_id"])
    cur_level = int(row_value(row, "subscription_level") or 1)
    level_options = "".join(
        f'<option value="{lvl_id}" {"selected" if lvl_id == cur_level else ""}>{html_escape(name)}</option>'
        for lvl_id, name in sorted(levels.items())
    )
    sub_select = f"""
    <label>{t("key_settings_subscription")}
      <select name="subscription_level" {"disabled" if len(levels) == 1 else ""}>{level_options}</select>
    </label>"""
    body = f"""
<form method="post" action="/admin/keys/update">
  <input type="hidden" name="id" value="{html_escape(row["id"])}">
  <input type="hidden" name="return_to" value="{html_escape(return_to)}">
  <div class="form-grid">
    <label>{t("key_settings_status")}
      <select name="status">
        <option value="active" {selected["active"]}>{t("status_active")}</option>
        <option value="paused" {selected["paused"]}>{t("status_paused")}</option>
        <option value="disabled" {selected["disabled"]}>{t("status_disabled")}</option>
        <option value="revoked" {selected["revoked"]}>{t("status_revoked")}</option>
      </select>
    </label>
    <label>{t("key_settings_max_devices")}<input type="number" name="max_devices" min="1" max="999" value="{html_escape(row["max_devices"])}"></label>
    <label>{t("key_settings_valid_for")}<input type="number" name="duration_value" min="1" max="36500" value="{html_escape(duration_value)}" data-duration-value></label>
    <label>{t("key_settings_duration_unit")}
      <select name="duration_unit" data-duration-unit>{duration_unit_options(duration_unit)}</select>
    </label>
    <label>{t("key_settings_note_field")}<input name="note" value="{html_escape(row["note"] or "")}" maxlength="500"></label>
    {sub_select}
  </div>
  <div class="notice">{html_escape(activation_note)} {t("key_settings_current_expiry", expiry=html_escape(key_expiry_display(row)))}</div>
  <p class="actions"><button class="primary" type="submit">{icon_label("save", t("key_settings_save"))}</button></p>
</form>
<div class="danger-zone">
  <h3>{t("danger_zone")}</h3>
  <p class="muted">{t("key_settings_these_actions")}</p>
  <div class="actions">
    <button type="button" {confirm_open_attrs(reset_modal_id, t("key_reset_devices_title"), t("key_reset_devices_msg"), t("key_reset_devices_label"))}>{icon_label("reset-devices", t("key_reset_devices_submit"))}</button>
    <button class="danger" type="button" {confirm_open_attrs(delete_modal_id, t("key_delete_title"), t("key_delete_msg"), t("key_delete_label"))}>{icon_label("delete", t("key_delete_submit"))}</button>
  </div>
</div>
{dangerous_modal(reset_modal_id, t("key_reset_modal_title"), "/admin/keys/reset-devices", {"id": row["id"], "return_to": return_to}, t("key_reset_devices_submit"), danger=False, note=t("key_reset_modal_note"))}
{dangerous_modal(delete_modal_id, t("key_delete_modal_title"), "/admin/keys/delete", {"id": row["id"], "return_to": return_to}, t("key_delete_submit"), danger=True, note=t("key_delete_modal_note"))}
"""
    return modal(
        f"key-settings-{html_escape(row['id'])}",
        t("key_settings_title"),
        body,
        "wide"
    )


def create_keys_modal(conn: sqlite3.Connection, app_id: str, return_to: str, default_prefix: str) -> str:
    levels = subscription_levels(conn, app_id)
    level_options = "".join(
        f'<option value="{lvl_id}">{html_escape(name)}</option>'
        for lvl_id, name in sorted(levels.items())
    )
    sub_select = f"""
    <label>{t("create_keys_subscription")}
      <select name="subscription_level" {"disabled" if len(levels) == 1 else ""}>{level_options}</select>
    </label>"""
    body = f"""
<form method="post" action="/admin/keys/create">
  <input type="hidden" name="app_id" value="{html_escape(app_id)}">
  <input type="hidden" name="return_to" value="{html_escape(return_to)}">
  <div class="form-grid">
    <label>{t("create_keys_batch_size")}<input type="number" name="count" value="1" min="1" max="200"></label>
    <label>{t("create_keys_prefix")}<input name="prefix" value="{html_escape(default_prefix)}" minlength="1" maxlength="8" pattern="[A-Za-z0-9]{{1,8}}" placeholder="KB"></label>
    <label>{t("create_keys_max_devices")}<input type="number" name="max_devices" value="1" min="1" max="999"></label>
    <label>{t("create_keys_valid_for")}<input type="number" name="duration_value" value="30" min="1" max="36500" data-duration-value></label>
    <label>{t("create_keys_duration_unit")}
      <select name="duration_unit" data-duration-unit>{duration_unit_options("days")}</select>
    </label>
    <label>{t("create_keys_note_field")}<input name="note" maxlength="500" placeholder="{_h('create_keys_note_placeholder')}"></label>
    {sub_select}
  </div>
  <div class="notice">{t("create_keys_info")}</div>
  <p class="actions"><button class="primary" type="submit">{icon_label("create-key", t("create_keys_submit"))}</button></p>
</form>
"""
    return modal("create-keys", t("create_keys_title"), body, "wide")


def key_filter_form(app_id: str, q: str, status: str, device: str) -> str:
    status_options = [f'<option value="">{t("filter_all_statuses")}</option>']
    _status_display = {
        "active": t("status_active"),
        "paused": t("status_paused"),
        "disabled": t("status_disabled"),
        "revoked": t("status_revoked"),
    }
    for item in KEY_STATUS_CHOICES:
        selected = "selected" if status == item else ""
        status_options.append(f'<option value="{html_escape(item)}" {selected}>{html_escape(_status_display.get(item, item.title()))}</option>')
    device_options = [
        ("", t("filter_any_devices")),
        ("yes", t("filter_has_devices")),
        ("no", t("filter_no_devices")),
    ]
    device_html = "".join(
        f'<option value="{html_escape(value)}" {"selected" if device == value else ""}>{html_escape(label)}</option>'
        for value, label in device_options
    )
    return f"""
<form class="toolbar" method="get" action="/admin/app/{quote(app_id)}">
  <input type="hidden" name="tab" value="keys">
  <label>{t("filter_search")}
    <input name="q" value="{html_escape(q)}" placeholder="{_h('filter_search_keys_placeholder')}" style="min-width:260px">
  </label>
  <label>{t("filter_status")}
    <select name="status">{''.join(status_options)}</select>
  </label>
  <label>{t("filter_devices")}
    <select name="device">{device_html}</select>
  </label>
  <button class="primary" type="submit">{icon_label("filter", t("filter_apply"))}</button>
  <a class="button" href="{app_href(app_id, "keys")}">{icon_label("clear", t("filter_clear"))}</a>
</form>
"""


def ban_filter_form(app_id: str | None, q: str, kind: str) -> str:
    kind_options = [f'<option value="">{t("filter_all_statuses")}</option>']
    for value, label in (("ip", t("ban_kind_ip")), ("hwid", t("ban_kind_hwid")), ("country", t("ban_kind_country"))):
        selected = "selected" if kind == value else ""
        kind_options.append(f'<option value="{html_escape(value)}" {selected}>{html_escape(label)}</option>')
    if app_id:
        action = f"/admin/app/{quote(app_id)}"
        hidden = '<input type="hidden" name="tab" value="bans">'
        clear_href = app_href(app_id, "bans")
    else:
        action = "/admin/bans"
        hidden = ""
        clear_href = "/admin/bans"
    return f"""
<form class="toolbar" method="get" action="{action}">
  {hidden}
  <label>{t("filter_search")}
    <input name="q" value="{html_escape(q)}" placeholder="{_h('filter_search_bans_placeholder')}" style="min-width:280px">
  </label>
  <label>{t("ban_kind")}
    <select name="kind">{''.join(kind_options)}</select>
  </label>
  <button class="primary" type="submit">{icon_label("filter", t("filter_apply"))}</button>
  <a class="button" href="{clear_href}">{icon_label("clear", t("filter_clear"))}</a>
</form>
"""


def render_dashboard(conn: sqlite3.Connection, query: dict[str, list[str]] | None = None) -> str:
    today = datetime.now(timezone.utc).date().isoformat()
    pub_ip_info = get_public_ip()
    pub_ip = pub_ip_info["ip"]
    pub_ip_method = pub_ip_info["method"]
    apps_total = row_count(conn, "SELECT COUNT(*) FROM apps")
    app_page, app_per_page, app_offset = page_state(query, "apps_page", 3, "apps_limit")
    app_page, app_total_pages, app_offset = pagination_bounds(apps_total, app_page, app_per_page)
    apps = conn.execute(
        """
        SELECT app.*,
               (SELECT COUNT(*) FROM license_keys k WHERE k.app_id = app.app_id) AS key_count,
               (SELECT COUNT(*) FROM license_keys k WHERE k.app_id = app.app_id AND k.status = 'active') AS active_key_count,
               (SELECT COUNT(*) FROM events e WHERE e.app_id = app.app_id AND e.status = 'valid' AND substr(e.created_at, 1, 10) = ?) AS valid_today
        FROM apps app
        ORDER BY app.updated_at DESC, app.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (today, app_per_page, app_offset),
    ).fetchall()
    stats = [
        (t("stat_applications"), apps_total),
        (t("stat_active_apps"), row_count(conn, "SELECT COUNT(*) FROM apps WHERE status = 'active'")),
        (t("stat_license_keys"), row_count(conn, "SELECT COUNT(*) FROM license_keys")),
        (t("stat_active_keys"), row_count(conn, "SELECT COUNT(*) FROM license_keys WHERE status = 'active'")),
        (t("stat_devices"), row_count(conn, "SELECT COUNT(*) FROM activations")),
        (t("stat_global_bans"), row_count(conn, "SELECT COUNT(*) FROM bans WHERE app_id IS NULL")),
        (t("stat_app_bans"), row_count(conn, "SELECT COUNT(*) FROM bans WHERE app_id IS NOT NULL")),
        (t("stat_valid_today"), row_count(conn, "SELECT COUNT(*) FROM events WHERE status = 'valid' AND substr(created_at, 1, 10) = ?", (today,))),
        (t("stat_public_ip"), pub_ip),
        (t("stat_ip_source"), pub_ip_method),
    ]
    app_rows = []
    app_modals = []
    for row in apps:
        manage = app_href(row["app_id"], "overview")
        app_id_safe = html_escape(row["app_id"])
        app_rows.append(
            f"""<article class="app-row" data-row-link="{manage}" tabindex="0" role="link" aria-label="Open application {html_escape(row["name"])}">
  <div class="app-main">
    <h3>{html_escape(row["name"])}</h3>
    <code>{app_id_safe}</code>
  </div>
  <div class="app-row-status">{status_badge(row["status"])}</div>
  <div class="app-row-stat"><b>{html_escape(row["key_count"])}</b><span>{t("stat_keys")}</span></div>
  <div class="app-row-stat"><b>{html_escape(row["active_key_count"])}</b><span>{t("stat_active_keys_short")}</span></div>
  <div class="app-row-stat"><b>{html_escape(row["valid_today"])}</b><span>{t("stat_valid_today")}</span></div>
  <div class="row-actions app-actions">
    <a class="icon-action" href="{manage}" title="Open App" aria-label="Open App">{icon_svg("open-app")}</a>
    <button class="icon-action" type="button" data-open-modal="app-settings-{app_id_safe}" title="App Settings" aria-label="App Settings">{icon_svg("settings")}</button>
  </div>
</article>"""
        )
        app_modals.append(app_settings_modal(row, "/admin"))
    if not app_rows:
        app_rows.append(f'<p class="muted">{t("dashboard_no_apps")}</p>')

    recent = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 3").fetchall()
    ip_warning = ""
    if pub_ip_method in {"Unavailable", "Local", "Disabled"}:
        ip_warning = f'<div class="notice" style="margin-top:8px">{t("dashboard_ip_warning", method=html_escape(pub_ip_method))}</div>'
    body = f"""
<div class="panel">
  <div class="panel-head">
    <div><h1>{t("dashboard_title")}</h1><p>{t("dashboard_subtitle")}</p></div>
    <a class="button" href="/admin/bans">{icon_label("global-bans", t("dashboard_global_bans"))}</a>
  </div>
  <div class="stat-grid">{''.join(stat_card(label, value, sensitive=(label == t("stat_public_ip"))) for label, value in stats)}</div>
  {ip_warning}
</div>
<section class="panel">
  <div class="panel-head"><div><h2>{t("dashboard_apps_section")}</h2><p>{t("dashboard_apps_subtitle")}</p></div><a class="button" href="/admin/apps">{icon_label("manage-apps", t("dashboard_manage_apps"))}</a></div>
  <div class="app-list">{''.join(app_rows)}</div>
  {pagination_links("/admin", app_page, app_total_pages, page_param="apps_page", limit_param="apps_limit", current_limit=app_per_page, total_items=apps_total, show_page_size=False, show_jump=False)}
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("dashboard_recent_activity")}</h2><a class="button" href="/admin/events">{icon_label("audit-log", t("dashboard_open_audit"))}</a></div>
  {render_events_table(recent)}
</section>
{''.join(app_modals)}
"""
    return page_shell(t("dashboard_title"), body, "dashboard")


def render_apps(conn: sqlite3.Connection, query: dict[str, list[str]] | None = None) -> str:
    q = query_param(query, "q").strip()
    app_status = query_param(query, "status").strip().lower()
    app_status = app_status if app_status in APP_STATUSES else ""
    filters = []
    filter_params: list[Any] = []
    if q:
        like = f"%{q}%"
        filters.append("(app.app_id LIKE ? OR app.name LIKE ?)")
        filter_params.extend([like, like])
    if app_status:
        filters.append("app.status = ?")
        filter_params.append(app_status)
    where_sql = " WHERE " + " AND ".join(filters) if filters else ""
    page, per_page, offset = page_state(query, "page")
    total = row_count(conn, "SELECT COUNT(*) FROM apps app" + where_sql, tuple(filter_params))
    page, total_pages, offset = pagination_bounds(total, page, per_page)
    rows = conn.execute(
        f"""
        SELECT app.*,
               (SELECT COUNT(*) FROM license_keys k WHERE k.app_id = app.app_id) AS key_count,
               (SELECT COUNT(*) FROM bans b WHERE b.app_id = app.app_id) AS ban_count
        FROM apps app
        {where_sql}
        ORDER BY app.app_id
        LIMIT ? OFFSET ?
        """
        ,
        tuple(filter_params + [per_page, offset]),
    ).fetchall()
    tr = []
    modals = []
    for row in rows:
        app_id_safe = html_escape(row["app_id"])
        manage = app_href(row["app_id"])
        tr.append(
            f"""<tr class="click-row" data-row-link="{manage}" data-bulk-id="{app_id_safe}" tabindex="0" role="link" aria-label="Open application {html_escape(row["name"])}">
  <td><code>{app_id_safe}</code></td>
  <td>{html_escape(row["name"])}</td>
  <td>{status_badge(row["status"])}</td>
  <td>{"yes" if row["require_secret"] else "no"}</td>
  <td>{html_escape(row["key_count"])}</td>
  <td>{html_escape(row["ban_count"])}</td>
  <td>
    <div class="row-actions app-actions">
      <a class="icon-action" href="{manage}" title="Open App" aria-label="Open App">{icon_svg("open-app")}</a>
      <button class="icon-action" type="button" data-open-modal="app-settings-{app_id_safe}" title="App Settings" aria-label="App Settings">{icon_svg("settings")}</button>
    </div>
  </td>
</tr>"""
        )
        modals.append(app_settings_modal(row, "/admin/apps"))
    _app_status_display = {
        "active": t("status_active"),
        "paused": t("status_paused"),
        "disabled": t("status_disabled"),
    }
    _apps_bulk_bar = bulk_toolbar("/admin/apps/bulk", ["delete", "enable", "disable"]) if tr else ""
    table = f'<p class="muted">{t("apps_empty")}</p>' if not tr else (
        _apps_bulk_bar
        + f"""<table class="apps-table" data-bulk-table="apps">
<tr><th>{t("apps_col_app_id")}</th><th>{t("apps_col_name")}</th><th>{t("apps_col_status")}</th><th>{t("apps_col_secret")}</th><th>{t("apps_col_keys")}</th><th>{t("apps_col_bans")}</th><th>{t("apps_col_actions")}</th></tr>
{''.join(tr)}
</table>
{pagination_links("/admin/apps", page, total_pages, {"q": q, "status": app_status}, current_limit=per_page, total_items=total)}"""
        + bulk_confirm_modal("apps")
    )
    status_options = [f'<option value="">{t("filter_all_statuses")}</option>']
    for item in APP_STATUS_CHOICES:
        selected = "selected" if app_status == item else ""
        status_options.append(f'<option value="{html_escape(item)}" {selected}>{html_escape(_app_status_display.get(item, item.title()))}</option>')
    create_modal = modal(
        "create-app",
        t("apps_create_title"),
        f"""
<form method="post" action="/admin/apps/create">
  <div class="form-grid">
    <label>{t("apps_app_id_label")}<input name="app_id" minlength="2" maxlength="64" pattern="[A-Za-z0-9_.-]{{2,64}}" placeholder="{_h('apps_app_id_placeholder')}"></label>
    <label>{t("apps_name_label")}<input name="name" minlength="1" maxlength="80" placeholder="{_h('apps_name_placeholder')}"></label>
    {secret_input("secret", t("apps_secret_label"), copy_label="Application Secret", placeholder=t("apps_secret_placeholder"), input_id="create-app-secret")}
  </div>
  <p class="muted">{t("apps_create_note")}</p>
  <div class="actions"><button class="primary" type="submit">{icon_label("create-app", t("apps_create_submit"))}</button></div>
</form>
""",
    )
    body = f"""
<section class="panel">
  <div class="panel-head">
    <div><h1>{t("apps_title")}</h1><p>{t("apps_subtitle")}</p></div>
    <button class="icon-action primary-action" type="button" data-open-modal="create-app" title="{_h('apps_create_title')}" aria-label="{_h('apps_create_title')}">{icon_svg("create-app")}</button>
  </div>
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("apps_list_title")}</h2><p class="muted">{t("apps_list_subtitle")}</p></div>
  <form class="toolbar" method="get" action="/admin/apps">
    <label>{t("filter_search")}<input name="q" value="{html_escape(q)}" placeholder="{_h('filter_search_apps_placeholder')}" style="min-width:220px"></label>
    <label>{t("filter_status")}<select name="status">{''.join(status_options)}</select></label>
    <button class="primary" type="submit">{icon_label("filter", t("filter_apply"))}</button>
    <a class="button" href="/admin/apps">{icon_label("clear", t("filter_clear"))}</a>
  </form>
  {table}
</section>
{''.join(modals)}
{create_modal}
"""
    return page_shell(t("apps_title"), body, "apps")


def key_detail_modal(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    activations = conn.execute(
        "SELECT * FROM activations WHERE key_id = ? ORDER BY last_seen_at DESC LIMIT 25",
        (row["id"],),
    ).fetchall()
    activation_rows = []
    for activation in activations:
        activation_country = best_effort_country(row_value(activation, "country"), activation["ip"])
        activation_rows.append(
            f"""<tr>
  <td>{copy_chip(activation["ip"], "IP address", sensitive=True)}</td>
  <td><span class="country-inline">{country_badge(activation_country, include_name=False, compact=True)}</span></td>
  <td>{copy_chip(activation["hwid"], "HWID", sensitive=True, compact=False)}</td>
  <td>{html_escape(activation["uses"])}</td>
  <td>{html_escape(activation["first_seen_at"])}</td>
  <td>{html_escape(activation["last_seen_at"])}</td>
</tr>"""
        )
    activation_table = (
        f"""<table class="mini-table">
<tr><th>{t("key_detail_act_ip")}</th><th>{t("key_detail_act_country")}</th><th>{t("key_detail_act_hwid")}</th><th>{t("key_detail_act_uses")}</th><th>{t("key_detail_act_first")}</th><th>{t("key_detail_act_last")}</th></tr>
{''.join(activation_rows)}
</table>"""
        if activation_rows
        else f'<p class="muted">{t("key_detail_no_activations")}</p>'
    )
    levels = subscription_levels(conn, row["app_id"])
    key_sub_level = int(row_value(row, "subscription_level") or 1)
    key_sub_name = levels.get(key_sub_level, "Default")
    body = f"""
<div class="detail-grid">
  <div><span>{t("key_detail_key")}</span><b>{copy_chip(row["key_text"], "license key", compact=False)}</b></div>
  <div><span>{t("key_detail_status")}</span><b>{status_badge(effective_key_status(row))}</b></div>
  <div><span>{t("key_detail_devices")}</span><b>{html_escape(row["devices_used"])} / {html_escape(row["max_devices"])}</b></div>
  <div><span>{t("key_detail_uses")}</span><b>{html_escape(row["uses"])}</b></div>
  <div><span>{t("key_detail_subscription")}</span><b>{html_escape(key_sub_name)}</b></div>
  <div><span>{t("key_detail_duration")}</span><b>{html_escape(format_duration(row_value(row, "duration_seconds"), row["expires_at"]))}</b></div>
  <div><span>{t("key_detail_expires")}</span><b>{html_escape(key_expiry_display(row))}</b></div>
  <div><span>{t("key_detail_last_country")}</span><b class="country-inline">{country_badge(best_effort_country(row_value(row, "last_activation_country") or row_value(row, "last_country"), row_value(row, "last_ip")), compact=True)}</b></div>
  <div><span>{t("key_detail_activated")}</span><b>{html_escape(row_value(row, "activated_at") or t("key_not_activated"))}</b></div>
  <div><span>{t("key_detail_created")}</span><b>{html_escape(row["created_at"])}</b></div>
  <div><span>{t("key_detail_last_seen")}</span><b>{html_escape(row["last_seen_at"] or "-")}</b></div>
</div>
<div class="detail-section">
  <h3>{t("key_detail_note")}</h3>
  <pre>{html_escape(row["note"] or t("key_detail_no_note"))}</pre>
</div>
<div class="detail-section">
  <h3>{t("key_detail_activations")}</h3>
  {activation_table}
</div>
"""
    return modal(
        f"key-details-{html_escape(row['id'])}",
        t("key_detail_title", key=row["key_text"]),
        body,
        "wide"
    )


def render_keys_table(conn: sqlite3.Connection, rows: list[sqlite3.Row], return_to: str, show_app: bool = False) -> str:
    if not rows:
        return f'<p class="muted">{t("keys_empty")}</p>'
    level_cache: dict[str, dict[int, str]] = {}

    def levels_for(app_id: str) -> dict[int, str]:
        if app_id not in level_cache:
            level_cache[app_id] = subscription_levels(conn, app_id)
        return level_cache[app_id]

    show_sub_col = show_app or len(levels_for(str(rows[0]["app_id"]))) > 1
    tr = []
    modals = []
    for row in rows:
        levels = levels_for(str(row["app_id"]))
        sub_level = int(row_value(row, "subscription_level") or 1)
        sub_name = levels.get(sub_level, "Default")
        app_cell = f'<td><a href="{app_href(row["app_id"], "keys")}"><code>{html_escape(row["app_id"])}</code></a></td>' if show_app else ""
        sub_cell = f'<td>{html_escape(sub_name)}</td>' if show_sub_col else ""
        display_country = best_effort_country(row_value(row, "last_activation_country") or row_value(row, "last_country"), row["last_ip"])
        tr.append(
            f"""<tr class="click-row" data-open-modal="key-details-{html_escape(row["id"])}" data-bulk-id="{html_escape(row["id"])}" title="Open key details">
  <td>{copy_chip(row["key_text"], "license key")}</td>
  {app_cell}
  <td>{status_badge(effective_key_status(row))}</td>
  {sub_cell}<td>{html_escape(row["devices_used"])} / {html_escape(row["max_devices"])}</td>
  <td><span class="country-inline">{country_badge(display_country, include_name=False, compact=True)}</span></td>
  <td>{copy_chip(row["last_ip"], "IP address", sensitive=True)}</td>
  <td>{copy_chip(row["last_hwid"], "HWID", sensitive=True)}</td>
  <td>{html_escape(format_duration(row_value(row, "duration_seconds"), row["expires_at"]))}</td>
  <td>{html_escape(key_expiry_display(row))}</td>
  <td><button class="icon-button" type="button" data-open-modal="key-settings-{html_escape(row["id"])}" title="Key Settings" aria-label="Key Settings">{icon_svg("settings")}</button></td>
</tr>"""
        )
        modals.append(key_detail_modal(conn, row))
        modals.append(key_settings_modal(conn, row, return_to))
    app_header = f'<th>{t("filter_application")}</th>' if show_app else ""
    sub_header = f'<th>{t("keys_col_subscription")}</th>' if show_sub_col else ""
    return (
        bulk_toolbar("/admin/keys/bulk", ["delete", "enable", "disable", "export"], "/admin/keys/export")
        + f"""<table class="keys-table" data-bulk-table="keys">
<tr><th>{t("keys_col_key")}</th>{app_header}<th>{t("keys_col_status")}</th>{sub_header}<th>{t("keys_col_devices")}</th><th>{t("keys_col_country")}</th><th>{t("keys_col_last_ip")}</th><th>{t("keys_col_last_hwid")}</th><th>{t("keys_col_duration")}</th><th>{t("keys_col_expires")}</th><th>{t("keys_col_actions")}</th></tr>
{''.join(tr)}
</table>
{''.join(modals)}"""
        + bulk_confirm_modal("keys")
    )


def render_keys(conn: sqlite3.Connection, query: dict[str, list[str]] | None = None) -> str:
    q = query_param(query, "q").strip()
    key_status = query_param(query, "status").strip().lower()
    key_status = key_status if key_status in KEY_STATUSES else ""
    app_filter = query_param(query, "app").strip()
    device_filter = query_param(query, "device").strip().lower()
    device_filter = device_filter if device_filter in {"yes", "no"} else ""

    filters: list[str] = []
    filter_params: list[Any] = []
    if app_filter:
        filters.append("k.app_id = ?")
        filter_params.append(app_filter)
    if q:
        like = f"%{q}%"
        filters.append(
            """(
                k.key_text LIKE ?
                OR k.note LIKE ?
                OR k.app_id LIKE ?
                OR EXISTS (
                    SELECT 1 FROM activations a
                    WHERE a.key_id = k.id AND (a.hwid LIKE ? OR a.ip LIKE ? OR a.country LIKE ?)
                )
            )"""
        )
        filter_params.extend([like, like, like, like, like, like])
    if key_status:
        filters.append("k.status = ?")
        filter_params.append(key_status)
    if device_filter == "yes":
        filters.append("EXISTS (SELECT 1 FROM activations a WHERE a.key_id = k.id)")
    elif device_filter == "no":
        filters.append("NOT EXISTS (SELECT 1 FROM activations a WHERE a.key_id = k.id)")
    where_sql = " WHERE " + " AND ".join(filters) if filters else ""
    page, per_page, offset = page_state(query, "page")
    total = row_count(conn, "SELECT COUNT(*) FROM license_keys k" + where_sql, tuple(filter_params))
    page, total_pages, offset = pagination_bounds(total, page, per_page)
    rows = conn.execute(
        f"""
        SELECT k.*,
               (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id) AS devices_used,
               (SELECT a.ip FROM activations a WHERE a.key_id = k.id ORDER BY a.last_seen_at DESC LIMIT 1) AS last_ip,
               (SELECT a.hwid FROM activations a WHERE a.key_id = k.id ORDER BY a.last_seen_at DESC LIMIT 1) AS last_hwid,
               (
                   SELECT a.country
                   FROM activations a
                   WHERE a.key_id = k.id
                     AND NULLIF(a.country, '') IS NOT NULL
                   ORDER BY a.last_seen_at DESC
                   LIMIT 1
               ) AS last_activation_country,
               (
                   SELECT e.country
                   FROM events e
                   WHERE e.event_type = 'verify'
                     AND e.app_id = k.app_id
                     AND e.key_text = k.key_text
                     AND NULLIF(e.country, '') IS NOT NULL
                   ORDER BY e.id DESC
                   LIMIT 1
               ) AS last_country
        FROM license_keys k
        {where_sql}
        ORDER BY k.id DESC
        LIMIT ? OFFSET ?
        """,
        tuple(filter_params + [per_page, offset]),
    ).fetchall()

    apps = conn.execute("SELECT app_id, name FROM apps ORDER BY app_id").fetchall()
    app_options = [f'<option value="">{t("filter_all_applications")}</option>']
    for app in apps:
        selected = "selected" if app_filter == app["app_id"] else ""
        app_options.append(
            f'<option value="{html_escape(app["app_id"])}" {selected}>{html_escape(app["app_id"])} - {html_escape(app["name"])}</option>'
        )
    status_options = [f'<option value="">{t("filter_all_statuses")}</option>']
    _status_display = {
        "active": t("status_active"),
        "paused": t("status_paused"),
        "disabled": t("status_disabled"),
        "revoked": t("status_revoked"),
    }
    for item in KEY_STATUS_CHOICES:
        selected = "selected" if key_status == item else ""
        status_options.append(f'<option value="{html_escape(item)}" {selected}>{html_escape(_status_display.get(item, item.title()))}</option>')
    device_options = [
        ("", t("filter_any_devices")),
        ("yes", t("filter_has_devices")),
        ("no", t("filter_no_devices")),
    ]
    device_html = "".join(
        f'<option value="{html_escape(value)}" {"selected" if device_filter == value else ""}>{html_escape(label)}</option>'
        for value, label in device_options
    )
    start = 0 if total == 0 else offset + 1
    end = min(offset + per_page, total)
    key_params = {"q": q, "status": key_status, "app": app_filter, "device": device_filter}
    return_params = _pagination_clean_params({**key_params, "page": page, "limit": per_page})
    return_to = "/admin/keys" + ("?" + urlencode(return_params) if return_params else "")
    body = f"""
<section class="panel">
  <div class="panel-head">
    <div><h1>{t("nav_keys")}</h1><p>{t("app_console_keys_subtitle")}</p></div>
    <a class="button" href="/admin/apps">{icon_label("manage-apps", t("nav_applications"))}</a>
  </div>
  <form class="toolbar" method="get" action="/admin/keys">
    <label>{t("filter_search")}
      <input name="q" value="{html_escape(q)}" placeholder="{_h('filter_search_keys_placeholder')}" style="min-width:260px">
    </label>
    <label>{t("filter_application")}
      <select name="app">{''.join(app_options)}</select>
    </label>
    <label>{t("filter_status")}
      <select name="status">{''.join(status_options)}</select>
    </label>
    <label>{t("filter_devices")}
      <select name="device">{device_html}</select>
    </label>
    <button class="primary" type="submit">{icon_label("filter", t("filter_apply"))}</button>
    <a class="button" href="/admin/keys">{icon_label("clear", t("filter_clear"))}</a>
  </form>
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("nav_keys")}</h2><p class="muted">{t("audit_showing", start=html_escape(start), end=html_escape(end), total=html_escape(total))}</p></div>
  {render_keys_table(conn, rows, return_to, show_app=True)}
  {pagination_links("/admin/keys", page, total_pages, key_params, current_limit=per_page, total_items=total)}
</section>
"""
    return page_shell(t("nav_keys"), body, "keys")


def render_bans_table(rows: list[sqlite3.Row], return_to: str) -> str:
    if not rows:
        return f'<p class="muted">{t("bans_empty")}</p>'
    tr = []
    modals = []
    for row in rows:
        scope = "Global" if row["app_id"] is None else row["app_id"]
        value = row["value"]
        if row["kind"] == "country" and value in COUNTRIES:
            value_html = f'<span class="country-inline">{country_badge(value)}</span>'
        else:
            value_html = copy_chip(value, row["kind"], sensitive=row["kind"] in {"ip", "hwid"}, compact=False)
        modal_id = f"remove-ban-{row['id']}"
        tr.append(
            f"""<tr data-bulk-id="{html_escape(str(row['id']))}">
  <td>{html_escape(scope)}</td>
  <td>{ban_kind_badge(row["kind"])}</td>
  <td>{value_html}</td>
  <td>{html_escape(row["reason"] or "")}</td>
  <td>{html_escape(row["created_at"])}</td>
  <td>
    <button type="button" {confirm_open_attrs(modal_id, t("bans_remove_title"), t("bans_remove_msg"), t("bans_remove_label"))}>{icon_label("remove-ban", t("bans_remove_submit"))}</button>
  </td>
</tr>"""
        )
        modals.append(
            dangerous_modal(
                modal_id,
                t("bans_remove_modal"),
                "/admin/bans/delete",
                {"id": row["id"], "return_to": return_to},
                t("bans_remove_submit"),
                danger=False,
                note=f"Remove {row['kind']} ban {row['value']} from {scope}.",
            )
        )
    return (
        bulk_toolbar("/admin/bans/bulk", ["unban"])
        + f"""<table data-bulk-table="bans">
<tr><th>{t("bans_col_scope")}</th><th>{t("bans_col_kind")}</th><th>{t("bans_col_value")}</th><th>{t("bans_col_reason")}</th><th>{t("bans_col_created")}</th><th>{t("bans_col_action")}</th></tr>
{''.join(tr)}
</table>
{''.join(modals)}"""
        + bulk_confirm_modal("bans")
    )


def render_app_console(conn: sqlite3.Connection, app_id: str, tab: str, query: dict[str, list[str]] | None = None) -> str:
    app = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
    if not app:
        body = '<section class="panel"><h1>Application Not Found</h1><p class="muted">Return to the application list and choose another app.</p><p><a class="button" href="/admin/apps">Back to Applications</a></p></section>'
        return page_shell("Application Not Found", body, "apps")

    allowed_tabs = {"overview", "keys", "bans", "events", "subscriptions", "webhooks", "settings"}
    tab = tab if tab in allowed_tabs else "overview"
    return_to = app_href(app_id, tab)
    today = datetime.now(timezone.utc).date().isoformat()
    stats = [
        (t("stat_license_keys"), row_count(conn, "SELECT COUNT(*) FROM license_keys WHERE app_id = ?", (app_id,))),
        (t("stat_active_keys"), row_count(conn, "SELECT COUNT(*) FROM license_keys WHERE app_id = ? AND status = 'active'", (app_id,))),
        (t("stat_devices"), row_count(conn, "SELECT COUNT(*) FROM activations WHERE key_id IN (SELECT id FROM license_keys WHERE app_id = ?)", (app_id,))),
        (t("stat_app_bans"), row_count(conn, "SELECT COUNT(*) FROM bans WHERE app_id = ?", (app_id,))),
        (t("stat_valid_today"), row_count(conn, "SELECT COUNT(*) FROM events WHERE app_id = ? AND status = 'valid' AND substr(created_at, 1, 10) = ?", (app_id, today))),
        (t("stat_rejected_today"), row_count(conn, "SELECT COUNT(*) FROM events WHERE app_id = ? AND status <> 'valid' AND substr(created_at, 1, 10) = ?", (app_id, today))),
        (t("stat_total_events"), row_count(conn, "SELECT COUNT(*) FROM events WHERE app_id = ?", (app_id,))),
        (t("stat_secret_required"), t("app_console_yes") if app["require_secret"] else t("app_console_no")),
    ]
    head = f"""
<section class="panel">
  <div class="panel-head">
    <div>
      <h1>{html_escape(app["name"])}</h1>
      <p><code>{html_escape(app_id)}</code> {status_badge(app["status"])}</p>
    </div>
    <button type="button" data-open-modal="app-settings-{html_escape(app_id)}">{icon_label("settings", "App Settings")}</button>
  </div>
  <div class="stat-grid">{''.join(stat_card(label, value) for label, value in stats)}</div>
</section>
"""

    if tab == "overview":
        recent = conn.execute("SELECT * FROM events WHERE app_id = ? ORDER BY id DESC LIMIT 10", (app_id,)).fetchall()
        content = f"""
<section class="panel">
  <div class="panel-head"><h2>{t("app_console_recent_events")}</h2><a class="button" href="{app_href(app_id, "events")}">{icon_label("events", t("app_console_open_events"))}</a></div>
  {render_events_table(recent)}
</section>
"""
    elif tab == "keys":
        default_prefix = app_default_prefix(app)
        q = query_param(query, "q").strip()
        key_status = query_param(query, "status").strip().lower()
        key_status = key_status if key_status in KEY_STATUSES else ""
        device_filter = query_param(query, "device").strip().lower()
        device_filter = device_filter if device_filter in {"yes", "no"} else ""
        filters = ["k.app_id = ?"]
        filter_params: list[Any] = [app_id]
        if q:
            like = f"%{q}%"
            filters.append(
                """(
                    k.key_text LIKE ?
                    OR k.note LIKE ?
                    OR EXISTS (
                        SELECT 1 FROM activations a
                        WHERE a.key_id = k.id AND (a.hwid LIKE ? OR a.ip LIKE ?)
                    )
                )"""
            )
            filter_params.extend([like, like, like, like])
        if key_status:
            filters.append("k.status = ?")
            filter_params.append(key_status)
        if device_filter == "yes":
            filters.append("EXISTS (SELECT 1 FROM activations a WHERE a.key_id = k.id)")
        elif device_filter == "no":
            filters.append("NOT EXISTS (SELECT 1 FROM activations a WHERE a.key_id = k.id)")
        where_sql = " AND ".join(filters)
        page, per_page, offset = page_state(query)
        total = row_count(conn, "SELECT COUNT(*) FROM license_keys k WHERE " + where_sql, tuple(filter_params))
        page, total_pages, offset = pagination_bounds(total, page, per_page)
        rows = conn.execute(
            f"""
            SELECT k.*,
                   (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id) AS devices_used,
                   (SELECT a.ip FROM activations a WHERE a.key_id = k.id ORDER BY a.last_seen_at DESC LIMIT 1) AS last_ip,
                   (SELECT a.hwid FROM activations a WHERE a.key_id = k.id ORDER BY a.last_seen_at DESC LIMIT 1) AS last_hwid,
                   (
                       SELECT a.country
                       FROM activations a
                       WHERE a.key_id = k.id
                         AND NULLIF(a.country, '') IS NOT NULL
                       ORDER BY a.last_seen_at DESC
                       LIMIT 1
                   ) AS last_activation_country,
                   (
                       SELECT e.country
                       FROM events e
                       WHERE e.event_type = 'verify'
                         AND e.app_id = k.app_id
                         AND e.key_text = k.key_text
                         AND NULLIF(e.country, '') IS NOT NULL
                       ORDER BY e.id DESC
                       LIMIT 1
                   ) AS last_country
            FROM license_keys k
            WHERE {where_sql}
            ORDER BY k.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(filter_params + [per_page, offset]),
        ).fetchall()
        key_params = {"tab": "keys", "q": q, "status": key_status, "device": device_filter}
        content = f"""
<section class="panel">
  <div class="panel-head">
    <div><h2>{t("app_console_keys_title")}</h2><p class="muted">{t("app_console_keys_subtitle")}</p></div>
    <button class="primary" type="button" data-open-modal="create-keys">{icon_label("create-key", t("app_console_create_keys"))}</button>
  </div>
  {key_filter_form(app_id, q, key_status, device_filter)}
  {render_keys_table(conn, rows, return_to)}
  {pagination_links("/admin/app/" + quote(app_id), page, total_pages, key_params, current_limit=per_page, total_items=total)}
</section>
{create_keys_modal(conn, app_id, return_to, default_prefix)}
"""
    elif tab == "bans":
        q = query_param(query, "q").strip()
        ban_kind = query_param(query, "kind").strip().lower()
        ban_kind = ban_kind if ban_kind in BAN_KINDS else ""
        filters = ["app_id = ?"]
        filter_params: list[Any] = [app_id]
        if q:
            like = f"%{q}%"
            filters.append("(value LIKE ? OR reason LIKE ?)")
            filter_params.extend([like, like])
        if ban_kind:
            filters.append("kind = ?")
            filter_params.append(ban_kind)
        where_sql = " AND ".join(filters)
        page, per_page, offset = page_state(query)
        total = row_count(conn, "SELECT COUNT(*) FROM bans WHERE " + where_sql, tuple(filter_params))
        page, total_pages, offset = pagination_bounds(total, page, per_page)
        rows = conn.execute(
            "SELECT * FROM bans WHERE " + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(filter_params + [per_page, offset]),
        ).fetchall()
        ban_params = {"tab": "bans", "q": q, "kind": ban_kind}
        content = f"""
<section class="panel">
  <div class="panel-head"><div><h2>{t("app_console_bans_title")}</h2><p>{t("app_console_bans_subtitle", app_id=html_escape(app_id))}</p></div><a class="button" href="/admin/bans">{icon_label("global-bans", t("app_console_bans_global_link"))}</a></div>
  {ban_form_html(app_id, return_to, t("ban_add_app"))}
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("app_console_bans_section")}</h2><p class="muted">{t("app_console_bans_section_sub")}</p></div>
  {ban_filter_form(app_id, q, ban_kind)}
  {render_bans_table(rows, return_to)}
  {pagination_links("/admin/app/" + quote(app_id), page, total_pages, ban_params, current_limit=per_page, total_items=total)}
</section>
"""
    elif tab == "events":
        q = query_param(query, "q").strip()
        status = query_param(query, "status").strip()
        event_type = query_param(query, "event_type").strip()
        country = normalize_country(query_param(query, "country"))
        filters = ["app_id = ?"]
        filter_params: list[Any] = [app_id]
        if q:
            like = f"%{q}%"
            filters.append("(event_type LIKE ? OR key_text LIKE ? OR hwid LIKE ? OR ip LIKE ? OR country LIKE ? OR status LIKE ? OR message LIKE ?)")
            filter_params.extend([like, like, like, like, like, like, like])
        if status:
            filters.append("status = ?")
            filter_params.append(status)
        if event_type:
            filters.append("event_type = ?")
            filter_params.append(event_type)
        if country:
            filters.append("country = ?")
            filter_params.append(country)
        where_sql = " AND ".join(filters)
        page, per_page, offset = page_state(query)
        total = row_count(conn, "SELECT COUNT(*) FROM events WHERE " + where_sql, tuple(filter_params))
        page, total_pages, offset = pagination_bounds(total, page, per_page)
        rows = conn.execute(
            "SELECT * FROM events WHERE " + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(filter_params + [per_page, offset]),
        ).fetchall()
        status_rows = conn.execute(
            "SELECT DISTINCT status FROM events WHERE app_id = ? AND status IS NOT NULL AND status <> '' ORDER BY status",
            (app_id,),
        ).fetchall()
        status_options = [f'<option value="">{t("filter_all_statuses")}</option>']
        for row in status_rows:
            selected = "selected" if status == row["status"] else ""
            status_options.append(f'<option value="{html_escape(row["status"])}" {selected}>{html_escape(row["status"])}</option>')
        event_rows = conn.execute(
            "SELECT DISTINCT event_type FROM events WHERE app_id = ? AND event_type IS NOT NULL AND event_type <> '' ORDER BY event_type",
            (app_id,),
        ).fetchall()
        event_options = [f'<option value="">{t("filter_all_event_types")}</option>']
        for row in event_rows:
            selected = "selected" if event_type == row["event_type"] else ""
            event_options.append(f'<option value="{html_escape(row["event_type"])}" {selected}>{html_escape(row["event_type"])}</option>')
        event_params = {"tab": "events", "q": q, "status": status, "event_type": event_type, "country": country}
        content = f"""
<section class="panel">
  <div class="panel-head"><h2>{t("app_console_events_title")}</h2><p class="muted">{t("app_console_events_page", page=html_escape(page), total_pages=html_escape(total_pages))}</p></div>
  <form class="toolbar" method="get" action="/admin/app/{quote(app_id)}">
    <input type="hidden" name="tab" value="events">
    <label>{t("filter_search")}
      <input name="q" value="{html_escape(q)}" placeholder="{_h('filter_search_events_placeholder')}" style="min-width:260px">
    </label>
    <label>{t("filter_event")}
      <select name="event_type">{''.join(event_options)}</select>
    </label>
    <label>{t("filter_status")}
      <select name="status">{''.join(status_options)}</select>
    </label>
    <label>{t("events_col_country")}
      <input name="country" value="{html_escape(country)}" placeholder="{_h('filter_country_placeholder')}" style="width:80px">
    </label>
    <button class="primary" type="submit">{icon_label("filter", t("filter_apply"))}</button>
    <a class="button" href="{app_href(app_id, "events")}">{icon_label("clear", t("filter_clear"))}</a>
  </form>
  {render_events_table(rows)}
  {pagination_links("/admin/app/" + quote(app_id), page, total_pages, event_params, current_limit=per_page, total_items=total)}
</section>
"""
    elif tab == "subscriptions":
        content = _render_subscriptions_panels(conn, return_to, app_id, query=query)
    elif tab == "webhooks":
        content = _render_app_webhooks(conn, app_id, return_to, query)
    else:
        content = f"""
<section class="panel">
  <div class="panel-head"><div><h2>{t("app_console_settings_title")}</h2><p>{t("app_console_settings_sub")}</p></div></div>
  {app_settings_form(app, return_to)}
</section>
"""

    return page_shell(
        f"{app['name']} Console",
        head + content + app_settings_modal(app, return_to),
        "apps",
        {"app": app, "tab": tab},
    )


def app_settings_form(app: sqlite3.Row, return_to: str) -> str:
    selected = {status: "selected" if app["status"] == status else "" for status in APP_STATUSES}
    prefix = app_default_prefix(app)
    return f"""
<form method="post" action="/admin/apps/update">
  <input type="hidden" name="app_id" value="{html_escape(app["app_id"])}">
  <input type="hidden" name="return_to" value="{html_escape(return_to)}">
  <div class="form-grid">
    <label>{t("app_settings_name")}<input name="name" value="{html_escape(app["name"])}" minlength="1" maxlength="80"></label>
    <label>{t("app_settings_status")}
      <select name="status">
        <option value="active" {selected["active"]}>{t("status_active")}</option>
        <option value="paused" {selected["paused"]}>{t("status_paused")}</option>
        <option value="disabled" {selected["disabled"]}>{t("status_disabled")}</option>
      </select>
    </label>
    <label>{t("app_settings_prefix")}<input name="default_prefix" value="{html_escape(prefix)}" minlength="1" maxlength="8" pattern="[A-Za-z0-9]{{1,8}}"></label>
  </div>
  {app_security_fields(app)}
  <div class="notice">{t("app_settings_global_note")}</div>
  <p><button class="primary" type="submit">{icon_label("save", t("app_settings_save_short"))}</button></p>
</form>
{app_secret_panel(app, return_to, "-page")}
{app_delete_form(app["app_id"], return_to, "-page")}
"""


def render_global_bans(conn: sqlite3.Connection, query: dict[str, list[str]] | None = None) -> str:
    q = query_param(query, "q").strip()
    ban_kind = query_param(query, "kind").strip().lower()
    ban_kind = ban_kind if ban_kind in BAN_KINDS else ""
    filters = ["app_id IS NULL"]
    filter_params: list[Any] = []
    if q:
        like = f"%{q}%"
        filters.append("(value LIKE ? OR reason LIKE ?)")
        filter_params.extend([like, like])
    if ban_kind:
        filters.append("kind = ?")
        filter_params.append(ban_kind)
    where_sql = " AND ".join(filters)
    page, per_page, offset = page_state(query)
    total = row_count(conn, "SELECT COUNT(*) FROM bans WHERE " + where_sql, tuple(filter_params))
    page, total_pages, offset = pagination_bounds(total, page, per_page)
    rows = conn.execute(
        "SELECT * FROM bans WHERE " + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
        tuple(filter_params + [per_page, offset]),
    ).fetchall()
    ban_params = {"q": q, "kind": ban_kind}
    body = f"""
<section class="panel">
  <div class="panel-head"><div><h1>{t("global_bans_title")}</h1><p>{t("global_bans_subtitle")}</p></div></div>
  {ban_form_html(None, "/admin/bans", t("ban_add_global"))}
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("global_bans_rules_title")}</h2><p class="muted">{t("global_bans_rules_subtitle")}</p></div>
  {ban_filter_form(None, q, ban_kind)}
  {render_bans_table(rows, "/admin/bans")}
  {pagination_links("/admin/bans", page, total_pages, ban_params, current_limit=per_page, total_items=total)}
</section>
"""
    return page_shell(t("global_bans_title"), body, "global-bans")


def render_events(conn: sqlite3.Connection, query: dict[str, list[str]] | None = None) -> str:
    query = query or {}
    q = query.get("q", [""])[0].strip()
    status = query.get("status", [""])[0].strip()
    app_filter = query.get("app", [""])[0].strip()
    event_type = query.get("event_type", [""])[0].strip()
    country = normalize_country(query.get("country", [""])[0])
    page, per_page, offset = page_state(query)

    where = []
    params: list[Any] = []
    if q:
        like = f"%{q}%"
        where.append(
            "(event_type LIKE ? OR app_id LIKE ? OR key_text LIKE ? OR hwid LIKE ? OR ip LIKE ? OR country LIKE ? OR status LIKE ? OR message LIKE ?)"
        )
        params.extend([like, like, like, like, like, like, like, like])
    if status:
        where.append("status = ?")
        params.append(status)
    if app_filter:
        where.append("app_id = ?")
        params.append(app_filter)
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    if country:
        where.append("country = ?")
        params.append(country)

    where_sql = " WHERE " + " AND ".join(where) if where else ""
    total = row_count(conn, "SELECT COUNT(*) FROM events" + where_sql, tuple(params))
    page, total_pages, offset = pagination_bounds(total, page, per_page)
    rows = conn.execute(
        "SELECT * FROM events" + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
        tuple(params + [per_page, offset]),
    ).fetchall()

    apps = conn.execute("SELECT app_id, name FROM apps ORDER BY app_id").fetchall()
    app_options = [f'<option value="">{t("filter_all_applications")}</option>']
    for app in apps:
        selected = "selected" if app_filter == app["app_id"] else ""
        app_options.append(
            f'<option value="{html_escape(app["app_id"])}" {selected}>{html_escape(app["app_id"])} - {html_escape(app["name"])}</option>'
        )

    status_rows = conn.execute(
        "SELECT DISTINCT status FROM events WHERE status IS NOT NULL AND status <> '' ORDER BY status"
    ).fetchall()
    status_options = [f'<option value="">{t("filter_all_statuses")}</option>']
    for row in status_rows:
        selected = "selected" if status == row["status"] else ""
        status_options.append(f'<option value="{html_escape(row["status"])}" {selected}>{html_escape(row["status"])}</option>')

    event_rows = conn.execute(
        "SELECT DISTINCT event_type FROM events WHERE event_type IS NOT NULL AND event_type <> '' ORDER BY event_type"
    ).fetchall()
    event_options = [f'<option value="">{t("filter_all_event_types")}</option>']
    for row in event_rows:
        selected = "selected" if event_type == row["event_type"] else ""
        event_options.append(f'<option value="{html_escape(row["event_type"])}" {selected}>{html_escape(row["event_type"])}</option>')

    start = 0 if total == 0 else offset + 1
    end = min(offset + per_page, total)
    event_params = {"q": q, "status": status, "app": app_filter, "event_type": event_type, "country": country}
    body = f"""
<section class="panel">
  <div class="panel-head">
    <div><h1>{t("audit_title")}</h1><p>{t("audit_subtitle")}</p></div>
    <div class="muted">{t("audit_showing", start=html_escape(start), end=html_escape(end), total=html_escape(total))}</div>
  </div>
  <form class="toolbar" method="get" action="/admin/events">
    <label>{t("filter_search")}
      <input name="q" value="{html_escape(q)}" placeholder="{_h('filter_search_events_placeholder')}" style="min-width:260px">
    </label>
    <label>{t("filter_application")}
      <select name="app">{''.join(app_options)}</select>
    </label>
    <label>{t("filter_event")}
      <select name="event_type">{''.join(event_options)}</select>
    </label>
    <label>{t("filter_status")}
      <select name="status">{''.join(status_options)}</select>
    </label>
    <label>{t("events_col_country")}
      <input name="country" value="{html_escape(country)}" placeholder="{_h('filter_country_placeholder')}" style="width:80px">
    </label>
    <button class="primary" type="submit">{icon_label("filter", t("filter_apply"))}</button>
    <a class="button" href="/admin/events">{icon_label("clear", t("filter_clear"))}</a>
  </form>
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("audit_events_section")}</h2><p class="muted">{t("events_click_row")}</p></div>
  {render_events_table(rows)}
  {pagination_links("/admin/events", page, total_pages, event_params, current_limit=per_page, total_items=total)}
</section>
"""
    return page_shell(t("audit_title"), body, "events")


def _protection_mode_from_message(message: str) -> str:
    lowered = str(message or "").lower()
    if "protection block:" in lowered:
        return "block"
    if "protection restrict:" in lowered:
        return "restrict"
    if "protection strict:" in lowered:
        return "strict"
    if "protection warn:" in lowered:
        return "warn"
    return "event"


def render_protection_monitor(conn: sqlite3.Connection, query: dict[str, list[str]] | None = None) -> str:
    settings = protection_settings()
    q = query_param(query, "q")
    reason = query_param(query, "reason")
    page, per_page, offset = page_state(query)
    reason_codes = sorted(PROTECTION_REASON_CODES)
    where = ["event_type = 'protection'"]
    params: list[Any] = []
    if reason in reason_codes:
        where.append("status = ?")
        params.append(reason)
    if q:
        like = f"%{q}%"
        where.append("(key_text LIKE ? OR hwid LIKE ? OR ip LIKE ? OR country LIKE ? OR status LIKE ? OR message LIKE ?)")
        params.extend([like, like, like, like, like, like])
    where_sql = " WHERE " + " AND ".join(where)
    total = row_count(conn, "SELECT COUNT(*) FROM events" + where_sql, tuple(params))
    page, total_pages, offset = pagination_bounds(total, page, per_page)
    rows = conn.execute(
        "SELECT * FROM events" + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, per_page, offset),
    ).fetchall()
    counts = {
        "total": row_count(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'protection'"),
        "block": row_count(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'protection' AND (message LIKE 'Protection block:%' OR message LIKE '%action=block%')"),
        "restrict": row_count(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'protection' AND message LIKE 'Protection restrict:%'"),
        "warn": row_count(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'protection' AND message LIKE '%action=warning%'"),
    }
    reason_options = "".join(
        f'<option value="{html_escape(code)}" {"selected" if reason == code else ""}>{html_escape(code)}</option>'
        for code in reason_codes
    )
    module_rows = "".join(
        f"<tr><td><code>{html_escape(name)}</code></td><td>{status_badge('active' if settings[name] else 'disabled')}</td></tr>"
        for name in ("anti_vm", "anti_vpn", "anti_proxy", "anti_debug", "anti_tamper", "anti_sandbox")
    )
    rows_html = "".join(
        f"""
<tr>
  <td>{html_escape(row["created_at"])}</td>
  <td>{status_badge(row["status"] or "")}</td>
  <td>{html_escape(_protection_mode_from_message(row["message"] or ""))}</td>
  <td>{html_escape(row["app_id"] or "-")}</td>
  <td><code>{html_escape(row["key_text"] or "-")}</code></td>
  <td>{copy_chip(row["ip"] or "", "IP", sensitive=True)}</td>
  <td>{country_badge(best_effort_country(row["country"], row["ip"]), include_name=False, compact=True) if (row["country"] or row["ip"]) else '<span class="muted">-</span>'}</td>
  <td><code>{html_escape(row["hwid"] or "-")}</code></td>
  <td>{html_escape(row["message"] or "")}</td>
</tr>
"""
        for row in rows
    ) or '<tr><td colspan="9" class="muted">No protection events match this filter.</td></tr>'
    event_params = {"q": q, "reason": reason}
    body = f"""
<section class="panel">
  <div class="panel-head">
    <div>
      <span class="eyebrow">Protection Monitor</span>
      <h1>Anti-analysis & network protection</h1>
      <p>Score suspicious verification environments without blocking from one noisy signal.</p>
    </div>
    <div class="api-process-actions">
      <a class="button" href="/admin/config">{icon_label("settings", "Open Config")}</a>
      <a class="button" href="/admin/events?event_type=protection">{icon_label("audit-log", "Audit Log")}</a>
    </div>
  </div>
  <div class="stat-grid">
    {stat_card("Mode", settings["mode"])}
    {stat_card("Protection events", counts["total"])}
    {stat_card("Score blocks", counts["block"])}
    {stat_card("Score warnings", counts["warn"])}
    {stat_card("IP reputation", "configured" if settings["ip_reputation_url"] else "not set")}
    {stat_card("IP whitelist", len(settings["ip_whitelist"]))}
    {stat_card("HWID whitelist", len(settings["hwid_whitelist"]))}
  </div>
</section>
<section class="panel">
  <div class="doc-grid api-lower-grid">
    <div>
      <h2>Modules</h2>
      <table class="mini-table"><tr><th>Module</th><th>State</th></tr>{module_rows}</table>
    </div>
    <div>
      <h2>Policy</h2>
      <table class="mini-table">
        <tr><td>Anti mode</td><td><code>{html_escape(settings["anti_mode"])}</code></td></tr>
        <tr><td>Allow range</td><td><code>0-40</code></td></tr>
        <tr><td>Warning range</td><td><code>41-70</code></td></tr>
        <tr><td>Block range</td><td><code>71-100</code> only in <code>strict</code></td></tr>
        <tr><td>Country whitelist</td><td>{html_escape(", ".join(settings["country_whitelist"]) or "empty")}</td></tr>
        <tr><td>Reputation cache</td><td><code>{html_escape(settings["ip_reputation_cache_seconds"])}s</code></td></tr>
        <tr><td>Reason codes</td><td><code>VM_DETECTED</code>, <code>VPN_DETECTED</code>, <code>PROXY_DETECTED</code>, <code>DEBUGGER_DETECTED</code>, <code>TOR_DETECTED</code></td></tr>
      </table>
      <div class="notice">Default-safe setup is <code>anti_mode: warn</code>. Switch to <code>strict</code> only after reviewing events and whitelisting trusted users or networks.</div>
    </div>
  </div>
</section>
<section class="panel">
  <div class="panel-head"><div><h2>Flagged clients</h2><p class="muted">Showing page {html_escape(page)} of {html_escape(total_pages)}.</p></div></div>
  <form class="toolbar" method="get" action="/admin/protection">
    <label>Search<input name="q" value="{html_escape(q)}" placeholder="key, hwid, ip, country, reason" style="min-width:260px"></label>
    <label>Reason<select name="reason"><option value="">All reasons</option>{reason_options}</select></label>
    <button type="submit">{icon_label("filter", "Filter")}</button>
    <a class="button" href="/admin/protection">{icon_label("clear", "Clear")}</a>
  </form>
  <table>
    <tr><th>Time</th><th>Reason</th><th>Mode</th><th>App</th><th>Key</th><th>IP</th><th>Country</th><th>HWID</th><th>Message</th></tr>
    {rows_html}
  </table>
  {pagination_links("/admin/protection", page, total_pages, event_params, current_limit=per_page, total_items=total)}
</section>
"""
    return page_shell("Protection Monitor", body, "protection")


def api_runtime_snapshot() -> dict[str, Any]:
    listeners = listener_targets()
    mode = listeners["mode"]
    admin_listener = listeners["admin"]
    api_listener = listeners["api"]
    api_base = config_str("api.public_base_url", f"http://{api_listener['host']}:{api_listener['port']}")
    admin_base = config_str("admin.public_base_url", f"http://{admin_listener['host']}:{admin_listener['port']}")
    cloudflare_state = "enabled" if config_bool("cloudflare.enabled") else "disabled"
    provisioning = provisioning_defaults()
    provisioning_state = "enabled" if provisioning["enabled"] else "disabled"
    runtime_state = "running" if api_runtime_enabled() else "stopped"
    mode_explainer = (
        "combined = one listener serves both /admin and /api on the same host:port."
        if mode == "combined"
        else "split = admin and API are served by separate listeners inside the same process."
    )
    proxy_list_text = ", ".join(trusted_proxy_list()) or "not set"
    recent_events: list[dict[str, str]] = []
    total_verify = 0
    rejected_verify = 0
    try:
        with db_connect() as conn:
            rows = conn.execute(
                """
                SELECT created_at, app_id, status, message
                FROM events
                WHERE event_type = 'verify'
                ORDER BY id DESC
                LIMIT 10
                """
            ).fetchall()
            recent_events = [
                {
                    "created_at": str(row["created_at"] or ""),
                    "app_id": str(row["app_id"] or "-"),
                    "status": str(row["status"] or "info"),
                    "message": str(row["message"] or ""),
                }
                for row in rows
            ]
            total_verify = row_count(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'verify'")
            rejected_verify = row_count(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'verify' AND status != 'valid'")
    except db.DatabaseError:
        pass
    recent_events_text = "\n".join(
        f"{row['created_at']} [{row['app_id']}] {row['status']} - {row['message']}" for row in recent_events
    ) or "No verify events yet."
    process_memory_value, process_memory_detail = process_memory_text()
    process_storage_bytes, process_storage_detail = keybase_storage_usage()
    cpu_cores = os.cpu_count() or "unknown"
    load_text = system_load_text()
    pub_ip_info = get_public_ip()
    return {
        "runtime_state": runtime_state,
        "runtime_badge": status_badge("valid" if api_runtime_enabled() else "disabled"),
        "uptime": api_runtime_uptime(),
        "pid": os.getpid(),
        "mode": mode,
        "mode_explainer": mode_explainer,
        "admin_listener": f"{admin_listener['host']}:{admin_listener['port']}",
        "api_listener": f"{api_listener['host']}:{api_listener['port']}",
        "admin_base": admin_base,
        "api_base": api_base,
        "health_url": f"{api_base}/api/v1/health",
        "verify_url": f"{api_base}/api/v1/verify",
        "bind_host": admin_listener["host"] if mode == "combined" else f"admin={admin_listener['host']} api={api_listener['host']}",
        "bind_port": admin_listener["port"] if mode == "combined" else f"admin={admin_listener['port']} api={api_listener['port']}",
        "cloudflare_state": cloudflare_state,
        "provisioning_state": provisioning_state,
        "provision_header": provisioning["header_name"],
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_cores": cpu_cores,
        "memory": system_memory_text(),
        "disk": system_disk_text(),
        "load": load_text,
        "data_dir": str(DATA_DIR),
        "database": db.database_label(DB_SETTINGS),
        "config_path": str(CONFIG_PATH),
        "proxy_whitelist": proxy_list_text,
        "accepted_ip_headers": ", ".join(config_list("api.accepted_ip_headers", [])),
        "accepted_country_headers": ", ".join(config_list("api.accepted_country_headers", [])),
        "trust_proxy_headers": "yes" if trust_proxy_headers() else "no",
        "allow_payload_ip_fallback": "yes" if config_bool("api.allow_payload_ip_fallback", True) else "no",
        "geoip_url": config_str("api.geoip_url", "default fallback"),
        "public_ip": pub_ip_info["ip"],
        "public_ip_method": pub_ip_info["method"],
        "remote_admin": "yes" if remote_admin_allowed() else "no",
        "total_verify": total_verify,
        "rejected_verify": rejected_verify,
        "recent_events": recent_events,
        "recent_events_text": recent_events_text,
        "console_text": runtime_console_text(560),
        "system_cpu_label": t("api_stat_system_cpu"),
        "system_cpu": load_text,
        "system_cpu_detail": (
            t("api_stat_system_cpu_cores", n=cpu_cores)
            if os.name == "nt"
            else t("api_stat_system_cpu_load", n=cpu_cores)
        ),
        "system_memory_label": t("api_stat_system_memory"),
        "system_memory": system_memory_text(),
        "system_memory_detail": t("api_stat_system_memory_detail"),
        "system_storage_label": t("api_stat_system_disk"),
        "system_storage": system_disk_text(),
        "system_storage_detail": f"based on {DATA_DIR.drive or DATA_DIR.anchor or str(DATA_DIR)}",
        "system_threads_label": t("api_stat_cpu_cores"),
        "system_threads": str(cpu_cores),
        "system_threads_detail": t("api_stat_cpu_cores_detail"),
        "process_cpu_label": t("api_stat_api_cpu"),
        "process_cpu": process_cpu_text(),
        "process_cpu_detail": t("api_stat_api_cpu_detail", pid=os.getpid(), cores=cpu_cores),
        "process_memory_label": t("api_stat_api_memory"),
        "process_memory": process_memory_value,
        "process_memory_detail": process_memory_detail,
        "process_storage_label": t("api_stat_api_disk"),
        "process_storage": format_bytes(process_storage_bytes),
        "process_storage_detail": process_storage_detail,
        "process_threads_label": t("api_stat_api_threads"),
        "process_threads": str(threading.active_count()),
        "process_threads_detail": t("api_stat_api_threads_detail"),
        "last_refresh": utc_now(),
    }


def render_api_console() -> str:
    snapshot = api_runtime_snapshot()

    def side_card(title: str, key: str, detail: str = "", sensitive: bool = False) -> str:
        detail_html = f'<span class="api-side-card-detail">{html_escape(detail)}</span>' if detail else ""
        sensitive_attr = ' data-api-sensitive="1"' if sensitive else ""
        value_html = (
            f'<span class="stat-blur">{html_escape(snapshot[key])}</span>'
            if sensitive
            else html_escape(snapshot[key])
        )
        return f"""
<div class="api-side-card">
  <span>{html_escape(title)}</span>
  <b data-api-text="{html_escape(key)}"{sensitive_attr}>{value_html}</b>
  {detail_html}
</div>
"""

    def metric_card(process_prefix: str, system_prefix: str) -> str:
        return f"""
<div class="api-side-card api-side-card-metric">
  <span data-api-scope-label data-process-key="{process_prefix}_label" data-system-key="{system_prefix}_label">{html_escape(snapshot[f"{process_prefix}_label"])}</span>
  <b data-api-scope-value data-process-key="{process_prefix}" data-system-key="{system_prefix}">{html_escape(snapshot[process_prefix])}</b>
  <span class="api-side-card-detail" data-api-scope-detail data-process-key="{process_prefix}_detail" data-system-key="{system_prefix}_detail">{html_escape(snapshot[f"{process_prefix}_detail"])}</span>
</div>
"""

    body = f"""
<section class="api-hero" data-api-runtime-root data-api-runtime-url="/admin/api/runtime" data-api-scope="process">
  <section class="panel api-console-panel">
    <div class="api-console-head">
      <div>
        <span class="eyebrow">{t("api_runtime_control")}</span>
        <h1>{t("api_control_center")}</h1>
        <p>{t("api_subtitle")}</p>
        <div class="api-scope-toggle" role="tablist" aria-label="{_h('api_scope_label')}">
          <button class="api-scope-button active" type="button" data-api-scope-button data-scope="process">{t("api_scope_api")}</button>
          <button class="api-scope-button" type="button" data-api-scope-button data-scope="system">{t("api_scope_full")}</button>
        </div>
      </div>
      <div class="api-process-actions">
        <form method="post" action="/admin/api/process">
          <input type="hidden" name="return_to" value="/admin/api">
          <input type="hidden" name="action" value="start">
          <button class="primary" type="submit">{icon_label("api-console", t("api_btn_start"))}</button>
        </form>
        <form method="post" action="/admin/api/process" {confirm_submit_attrs(t("api_restart_title"), t("api_restart_msg"), t("api_restart_label"))}>
          <input type="hidden" name="return_to" value="/admin/api">
          <input type="hidden" name="action" value="restart">
          <button type="submit">{icon_label("reset-devices", t("api_btn_restart"))}</button>
        </form>
        <form method="post" action="/admin/api/process" {confirm_submit_attrs(t("api_stop_title"), t("api_stop_msg"), t("api_stop_label"))}>
          <input type="hidden" name="return_to" value="/admin/api">
          <input type="hidden" name="action" value="stop">
          <button class="danger" type="submit">{icon_label("delete", t("api_btn_stop"))}</button>
        </form>
      </div>
    </div>
    <div class="api-strip">
      <div class="api-strip-card"><span>{t("api_state")}</span><b data-api-text="runtime_state">{html_escape(snapshot["runtime_state"])}</b></div>
      <div class="api-strip-card"><span>{t("api_mode")}</span><b data-api-text="mode">{html_escape(snapshot["mode"])}</b></div>
      <div class="api-strip-card"><span>{t("api_uptime")}</span><b data-api-text="uptime">{html_escape(snapshot["uptime"])}</b></div>
      <div class="api-strip-card"><span>{t("api_verify_url")}</span><code data-api-text="verify_url">{html_escape(snapshot["verify_url"])}</code></div>
    </div>
    <pre class="console-box api-console-box" data-api-console>{html_escape(snapshot["console_text"])}</pre>
    <div class="api-console-footer">
      <div><span>{t("api_admin")}</span><code data-api-text="admin_listener">{html_escape(snapshot["admin_listener"])}</code></div>
      <div><span>{t("api_api")}</span><code data-api-text="api_listener">{html_escape(snapshot["api_listener"])}</code></div>
      <div><span>{t("api_health")}</span><code data-api-text="health_url">{html_escape(snapshot["health_url"])}</code></div>
      <div><span>{t("api_ip_headers")}</span><code data-api-text="accepted_ip_headers">{html_escape(snapshot["accepted_ip_headers"])}</code></div>
    </div>
  </section>
  <aside class="api-side-panel">
    {side_card(t("api_card_api_state"), "runtime_state", t("api_card_api_state_detail"))}
    {side_card(t("api_card_uptime"), "uptime", t("api_card_uptime_detail"))}
    {side_card(t("api_mode"), "mode", snapshot["mode_explainer"])}
    {side_card(t("api_card_verify_events"), "total_verify", t("api_card_verify_events_detail"))}
    {side_card(t("api_card_rejected"), "rejected_verify", t("api_card_rejected_detail"))}
    {metric_card("process_cpu", "system_cpu")}
    {metric_card("process_memory", "system_memory")}
    {metric_card("process_storage", "system_storage")}
    {metric_card("process_threads", "system_threads")}
    {side_card(t("api_card_public_ip"), "public_ip", snapshot["public_ip_method"], sensitive=True)}
    {side_card(t("api_card_proxy_trust"), "trust_proxy_headers", "payload IP fallback: " + snapshot["allow_payload_ip_fallback"])}
    {side_card(t("api_card_provisioning"), "provisioning_state", snapshot["provision_header"])}
  </aside>
</section>
<section class="panel">
  <div class="doc-grid api-lower-grid">
    <div>
      <div class="panel-head"><div><h2>{t("api_recent_activity")}</h2><p>{t("api_recent_subtitle")}</p></div></div>
      <pre class="api-activity-log" data-api-recent>{html_escape(snapshot["recent_events_text"])}</pre>
    </div>
    <div>
      <div class="panel-head"><div><h2>{t("api_proxy_title")}</h2><p>{t("api_proxy_subtitle")}</p></div></div>
      <table class="mini-table">
        <tr><th>{t("api_proxy_col_setting")}</th><th>{t("api_proxy_col_value")}</th></tr>
        <tr><td>{t("api_proxy_trust")}</td><td data-api-text="trust_proxy_headers">{html_escape(snapshot["trust_proxy_headers"])}</td></tr>
        <tr><td>{t("api_proxy_accepted_headers")}</td><td data-api-text="accepted_ip_headers">{html_escape(snapshot["accepted_ip_headers"])}</td></tr>
        <tr><td>{t("api_proxy_payload_fallback")}</td><td data-api-text="allow_payload_ip_fallback">{html_escape(snapshot["allow_payload_ip_fallback"])}</td></tr>
        <tr><td>{t("api_proxy_whitelist")}</td><td data-api-text="proxy_whitelist">{html_escape(snapshot["proxy_whitelist"])}</td></tr>
        <tr><td>{t("api_proxy_country_headers")}</td><td data-api-text="accepted_country_headers">{html_escape(snapshot["accepted_country_headers"])}</td></tr>
        <tr><td>{t("api_proxy_geoip")}</td><td><code data-api-text="geoip_url">{html_escape(snapshot["geoip_url"])}</code></td></tr>
        <tr><td>{t("api_proxy_remote_admin")}</td><td data-api-text="remote_admin">{html_escape(snapshot["remote_admin"])}</td></tr>
      </table>
    </div>
  </div>
</section>
"""
    return page_shell(t("api_title"), body, "api")


def render_panic_console() -> str:
    info = panic_mode_info()
    is_active = info is not None
    remaining = panic_cooldown_remaining() if is_active else 0
    mins = remaining // 60
    secs = remaining % 60
    cooldown_done = remaining == 0

    enable_modal = modal(
        "panic-enable-modal",
        t("panic_enable_confirm_title"),
        f"""<div class="notice panic-warning-box">
  <b>{t("panic_warning_label")}</b> {t("panic_enable_warning")}
</div>
<div class="form-grid" style="margin-top:14px">
  {confirm_password_field(t("panic_enable_confirm_label"))}
</div>
<p class="actions" style="margin-top:14px">
  <button type="button" data-close-modal>{t("confirm_cancel")}</button>
  <button class="danger" type="submit">{icon_label("panic", t("panic_enable_btn"))}</button>
</p>""",
        "wide",
    )

    disable_modal = modal(
        "panic-disable-modal",
        t("panic_disable_confirm_title"),
        f"""<p class="muted">{t("panic_disable_warning")}</p>
<div class="form-grid" style="margin-top:14px">
  {confirm_password_field(t("panic_disable_confirm_label"))}
</div>
<p class="actions" style="margin-top:14px">
  <button type="button" data-close-modal>{t("confirm_cancel")}</button>
  <button class="primary" type="submit">{icon_label("panic", t("panic_disable_btn"))}</button>
</p>""",
        "wide",
    ) if is_active else ""

    if is_active:
        status_badge_html = f'<span class="badge badge-danger">{t("panic_status_active")}</span>'
        api_status_html = f'<span class="badge badge-danger">{t("panic_api_blocked")}</span>'
        activated_at_html = html_escape(info["activated_at"])
        activated_by_html = html_escape(info["activated_by"])
        if cooldown_done:
            cooldown_html = f'<span class="badge badge-ok">{t("panic_cooldown_expired")}</span>'
            action_html = f"""
<form method="post" action="/admin/panic/disable" data-danger-form>
  <input type="hidden" name="return_to" value="/admin/panic">
  {confirm_password_field(t("panic_disable_confirm_label"))}
  <p class="password-confirmed-note">{t("form_password_confirmed")}</p>
  <p class="actions" style="margin-top:10px">
    <button class="primary" type="submit" {confirm_submit_attrs(t("panic_disable_confirm_title"), t("panic_disable_warning"), t("panic_disable_confirm_label"))}>{icon_label("panic", t("panic_disable_btn"))}</button>
  </p>
</form>"""
        else:
            cooldown_html = f'<span class="panic-countdown" data-panic-countdown="{remaining}">{t("panic_cooldown_remaining", mins=mins, secs=secs)}</span>'
            action_html = f'<p class="muted">{t("panic_cooldown_wait")}</p>'
    else:
        status_badge_html = f'<span class="badge badge-ok">{t("panic_status_inactive")}</span>'
        api_status_html = f'<span class="badge badge-ok">{t("panic_api_running")}</span>'
        activated_at_html = "—"
        activated_by_html = "—"
        cooldown_html = "—"
        action_html = f"""
<form method="post" action="/admin/panic/enable" data-danger-form>
  <input type="hidden" name="return_to" value="/admin/panic">
  {confirm_password_field(t("panic_enable_confirm_label"))}
  <p class="password-confirmed-note">{t("form_password_confirmed")}</p>
  <div class="notice panic-warning-box" style="margin-top:10px">
    <b>{t("panic_warning_label")}</b> {t("panic_enable_warning")}
  </div>
  <p class="actions" style="margin-top:10px">
    <button class="danger" type="submit" {confirm_submit_attrs(t("panic_enable_confirm_title"), t("panic_enable_warning"), t("panic_enable_confirm_label"))}>{icon_label("panic", t("panic_enable_btn"))}</button>
  </p>
</form>"""

    body = f"""
<section class="panel {'panic-panel-active' if is_active else ''}">
  <div class="panel-head">
    <div>
      <span class="eyebrow">{t("panic_eyebrow")}</span>
      <h1>{t("panic_heading")}</h1>
      <p>{t("panic_subtitle")}</p>
    </div>
  </div>
  <div class="stat-grid">
    <div class="stat-card"><span>{html_escape(t("panic_status"))}</span><b>{status_badge_html}</b></div>
    <div class="stat-card"><span>{html_escape(t("panic_api_status"))}</span><b>{api_status_html}</b></div>
    {stat_card(t("panic_activated_at"), activated_at_html)}
    {stat_card(t("panic_activated_by"), activated_by_html)}
  </div>
</section>
<section class="panel">
  <div class="doc-grid api-lower-grid">
    <div>
      <h2>{t("panic_cooldown_title")}</h2>
      <p>{cooldown_html}</p>
      <p class="muted">{t("panic_cooldown_desc")}</p>
    </div>
    <div>
      <h2>{'Disable Panic Mode' if is_active else t("panic_enable_btn")}</h2>
      {action_html}
    </div>
  </div>
</section>
{disable_modal}
"""
    return page_shell(t("panic_heading"), body, "panic")


def _render_subscriptions_panels(
    conn: sqlite3.Connection,
    return_to: str,
    app_id: str,
    query: dict[str, list[str]] | None = None,
) -> str:
    levels = subscription_levels(conn, app_id)
    only_level = len(levels) == 1
    level_items = sorted(levels.items())
    page, per_page, offset = page_state(query, "sub_page", PAGINATION_DEFAULT_LIMIT, "sub_limit")
    page, total_pages, offset = pagination_bounds(len(level_items), page, per_page)
    visible_levels = level_items[offset : offset + per_page]

    level_counts: dict[int, int] = {}
    for row in conn.execute(
        "SELECT subscription_level, COUNT(*) AS cnt FROM license_keys WHERE app_id = ? GROUP BY subscription_level",
        (app_id,),
    ).fetchall():
        level_counts[int(row["subscription_level"])] = int(row["cnt"])
    total_keys_with_level = sum(level_counts.values())

    tr_rows: list[str] = []
    remove_forms: list[str] = []
    for lvl_id, name in visible_levels:
        count = level_counts.get(lvl_id, 0)
        if only_level:
            action_cell = f'<span class="sub-default-lock" title="{_h("sub_err_last_level")}">{t("sub_last_level_label")}</span>'
        else:
            confirm_msg = t("sub_remove_confirm_note", name=html_escape(name), id=lvl_id)
            if count > 0:
                confirm_msg += " " + t("sub_remove_has_keys_warning", n=count)
            form_id = f"sub-remove-form-{lvl_id}"
            remove_forms.append(
                f'<form id="{form_id}" method="post" action="/admin/app/{quote(app_id)}/subscriptions/remove" '
                f'{confirm_submit_attrs(t("sub_remove_confirm_title"), confirm_msg, t("sub_settings_remove"))}>'
                f'<input type="hidden" name="level_id" value="{lvl_id}">'
                f'<input type="hidden" name="return_to" value="{html_escape(return_to)}"></form>'
            )
            action_cell = (
                f'<button class="danger small" type="submit" form="{form_id}">'
                f'{icon_label("delete", t("sub_settings_remove"))}</button>'
            )
        badge_cls = "sub-level-badge"
        tr_rows.append(
            f"""<tr>
  <td><span class="{badge_cls}">{html_escape(str(lvl_id))}</span></td>
  <td><b>{html_escape(name)}</b></td>
  <td>{html_escape(str(count))}</td>
  <td class="sub-action-cell">{action_cell}</td>
</tr>"""
        )

    table_html = f"""<table class="sub-levels-page-table">
<tr>
  <th style="width:60px">{t("sub_settings_col_id")}</th>
  <th>{t("sub_settings_col_name")}</th>
  <th style="width:80px">{t("sub_page_col_keys")}</th>
  <th style="width:120px">{t("sub_page_col_action")}</th>
</tr>
{"".join(tr_rows)}
</table>
{"".join(remove_forms)}
{pagination_links(
    "/admin/app/" + quote(app_id),
    page,
    total_pages,
    {"tab": "subscriptions"},
    page_param="sub_page",
    limit_param="sub_limit",
    current_limit=per_page,
    total_items=len(level_items),
)}"""

    scope_note = f'<div class="notice" style="margin-bottom:12px">{t("sub_page_scope_note")}</div>'

    return f"""
<section class="panel">
  <div class="panel-head">
    <div>
      <span class="eyebrow">{t("sub_page_eyebrow")}</span>
      <h2>{t("sub_page_title")}</h2>
      <p>{t("sub_page_subtitle")}</p>
    </div>
  </div>
  <div class="stat-grid">
    {stat_card(t("sub_page_stat_levels"), len(levels))}
    {stat_card(t("sub_page_stat_keys"), total_keys_with_level)}
  </div>
</section>
<section class="panel">
  <div class="panel-head">
    <div><h2>{t("sub_page_levels_title")}</h2><p class="muted">{t("sub_page_levels_subtitle_new")}</p></div>
  </div>
  {scope_note}
  {table_html}
</section>
<section class="panel">
  <div class="panel-head">
    <div><h2>{t("sub_page_add_title")}</h2><p class="muted">{t("sub_page_add_subtitle")}</p></div>
  </div>
  <form method="post" action="/admin/app/{quote(app_id)}/subscriptions/add" class="sub-add-form">
    <input type="hidden" name="return_to" value="{html_escape(return_to)}">
    <div class="sub-add-row">
      <label>
        {t("sub_page_id_label")}
        <input type="number" name="level_id" min="1" max="99" placeholder="2" required>
      </label>
      <label class="sub-name-label">
        {t("sub_page_name_label")}
        <input type="text" name="level_name" minlength="1" maxlength="64" placeholder="{_h("sub_page_name_placeholder")}" required>
      </label>
      <div class="sub-add-submit">
        <button class="primary" type="submit">{icon_label("create-key", t("sub_settings_add"))}</button>
      </div>
    </div>
    <p class="muted">{t("sub_page_add_note_new")}</p>
  </form>
</section>
"""


# ── Webhooks UI ───────────────────────────────────────────────────────────────

def _wh_event_label(ev: str) -> str:
    key = f"wh_ev_{ev.replace('.', '_')}"
    result = t(key)
    return ev if result == key else result


def _wh_config_modal(ep: sqlite3.Row, app_id: str) -> str:
    """Settings modal for a single webhook endpoint."""
    eid = ep["id"]
    page_base = f"/admin/app/{quote(app_id)}"
    base = f"{page_base}/webhooks"
    try:
        cfg: dict[str, Any] = json.loads(ep["config_json"] or "{}")
    except Exception:
        cfg = {}
    cur_preset = cfg.get("preset", "keybase")
    cur_ct = cfg.get("content_type", "application/json")
    cur_tmpl = cfg.get("body_template", "")
    cur_extra: dict[str, str] = cfg.get("extra_headers") or {}
    cur_headers_raw = "\n".join(f"{k}: {v}" for k, v in cur_extra.items())
    cur_url = ep["url"]

    # Build preset cards JS data
    presets_js = json.dumps({
        k: {
            "content_type": v["content_type"],
            "extra_headers": v.get("extra_headers") or {},
            "body_template": v["body_template"],
        }
        for k, v in WEBHOOK_PRESETS.items()
    }, separators=(",", ":"))

    preset_cards = "".join(
        f'<button type="button" class="wh-preset-card{"  wh-preset-active" if k == cur_preset else ""}" data-preset="{html_escape(k)}">'
        f'<span class="wh-preset-name">{html_escape(v["label"])}</span>'
        f'<span class="wh-preset-desc">{html_escape(v["desc"])}</span>'
        f'</button>'
        for k, v in WEBHOOK_PRESETS.items()
    )

    modal_id = f"wh-cfg-{eid}"
    modal_body = f"""
<form method="post" action="{base}/update" class="wh-cfg-form">
  <input type="hidden" name="endpoint_id" value="{html_escape(eid)}">
  <input type="hidden" name="preset" value="{html_escape(cur_preset)}" id="wh-preset-val-{html_escape(eid)}">
  <div class="wh-preset-grid">{preset_cards}</div>
  <div class="form-grid" style="margin-top:14px">
    <label style="grid-column:1/-1">{t("wh_url_label")}
      <input type="url" name="url" value="{html_escape(cur_url)}" required minlength="10" maxlength="512" data-url-field id="wh-url-{html_escape(eid)}">
    </label>
    <label>{t("wh_cfg_content_type")}
      <input type="text" name="content_type" value="{html_escape(cur_ct)}" maxlength="80" id="wh-ct-{html_escape(eid)}">
    </label>
    <label>{t("wh_desc_label")}
      <input type="text" name="description" value="{html_escape(ep['description'] or '')}" maxlength="200">
    </label>
  </div>
  <label style="display:block;margin-top:10px">{t("wh_cfg_extra_headers")}
    <textarea name="extra_headers_raw" rows="3" placeholder="Authorization: Bearer token&#10;X-Custom: value" id="wh-hdrs-{html_escape(eid)}" style="font-family:monospace;font-size:12px">{html_escape(cur_headers_raw)}</textarea>
  </label>
  <label style="display:block;margin-top:10px">{t("wh_cfg_body_template")}
    <textarea name="body_template" rows="7" placeholder="{html_escape(t("wh_cfg_body_placeholder"))}" id="wh-tmpl-{html_escape(eid)}" style="font-family:monospace;font-size:12px">{html_escape(cur_tmpl)}</textarea>
  </label>
  <p class="muted" style="font-size:11px;margin-top:6px">{t("wh_cfg_vars_hint")}</p>
  <div class="toolbar" style="margin-top:14px">
    <button type="submit" class="button primary-action">{icon_label("save", t("wh_cfg_save"))}</button>
  </div>
</form>
<script>
(function(){{
  var PRESETS={presets_js};
  var eid="{html_escape(eid)}";
  var cards=document.querySelectorAll('#{html_escape(modal_id)} .wh-preset-card');
  function applyPreset(key){{
    var p=PRESETS[key];if(!p)return;
    document.getElementById('wh-preset-val-'+eid).value=key;
    document.getElementById('wh-ct-'+eid).value=p.content_type||'';
    document.getElementById('wh-tmpl-'+eid).value=p.body_template||'';
    var hlines=Object.entries(p.extra_headers||{{}}).map(function(e){{return e[0]+': '+e[1];}}).join('\\n');
    document.getElementById('wh-hdrs-'+eid).value=hlines;
    cards.forEach(function(c){{c.classList.toggle('wh-preset-active',c.dataset.preset===key);}});
  }}
  cards.forEach(function(c){{c.addEventListener('click',function(){{applyPreset(c.dataset.preset);}});}});
}})();
</script>"""
    return modal(modal_id, t("wh_cfg_title"), modal_body)


def _render_app_webhooks(
    conn: sqlite3.Connection,
    app_id: str,
    return_to: str,
    query: dict[str, list[str]] | None = None,
) -> str:
    page_base = return_to or app_href(app_id, "webhooks")
    base = f"/admin/app/{quote(app_id)}/webhooks"
    endpoint_total = row_count(conn, "SELECT COUNT(*) FROM webhook_endpoints WHERE app_id = ?", (app_id,))
    ep_page, ep_per_page, ep_offset = page_state(query, "wh_page", PAGINATION_DEFAULT_LIMIT, "wh_limit")
    ep_page, ep_total_pages, ep_offset = pagination_bounds(endpoint_total, ep_page, ep_per_page)
    delivery_total = row_count(
        conn,
        "SELECT COUNT(*) FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id WHERE e.app_id = ?",
        (app_id,),
    )
    log_page, log_per_page, log_offset = page_state(query, "wh_log_page", PAGINATION_DEFAULT_LIMIT, "wh_log_limit")
    log_page, log_total_pages, log_offset = pagination_bounds(delivery_total, log_page, log_per_page)
    endpoints = conn.execute(
        "SELECT * FROM webhook_endpoints WHERE app_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (app_id, ep_per_page, ep_offset),
    ).fetchall()
    total_ok = row_count(conn, "SELECT COUNT(*) FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id WHERE e.app_id = ? AND d.status = 'success'", (app_id,))
    total_fail = row_count(conn, "SELECT COUNT(*) FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id WHERE e.app_id = ? AND d.status = 'failed'", (app_id,))
    total_pend = row_count(conn, "SELECT COUNT(*) FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id WHERE e.app_id = ? AND d.status = 'pending'", (app_id,))

    stats_html = f"""<div class="stat-grid wh-stat-grid">
  {stat_card(t("wh_stat_endpoints"), endpoint_total)}
  {stat_card(t("wh_stat_delivered"), total_ok)}
  {stat_card(t("wh_stat_failed"), total_fail)}
  {stat_card(t("wh_stat_pending"), total_pend)}
</div>"""

    # ── Endpoint list ──
    cfg_modals: list[str] = []
    if not endpoints:
        ep_html = f'<p class="muted wh-empty">{t("wh_no_endpoints")}</p>'
    else:
        rows = []
        for ep in endpoints:
            try:
                ep_evs: list[str] = json.loads(ep["events"] or '["*"]')
            except Exception:
                ep_evs = ["*"]
            try:
                ep_cfg: dict[str, Any] = json.loads(ep["config_json"] or "{}")
            except Exception:
                ep_cfg = {}
            preset_key = ep_cfg.get("preset", "keybase")
            preset_label = WEBHOOK_PRESETS.get(preset_key, WEBHOOK_PRESETS["keybase"])["label"]
            ev_badges = "".join(
                f'<span class="wh-ev-badge">{html_escape("ALL" if e == "*" else e)}</span>'
                for e in ep_evs
            )
            en = bool(ep["enabled"])
            st = ep["last_status"] or ""
            st_cls = {"success": "status status-ok", "failed": "status status-bad", "retrying": "status status-warn"}.get(st, "")
            st_html = f'<span class="{st_cls}">{html_escape(st)}</span>' if st_cls else ""
            en_cls = "status status-ok" if en else "status status-muted"
            en_lbl = t("wh_enabled") if en else t("wh_disabled")
            tog_action = "disable" if en else "enable"
            tog_label = t("wh_disable") if en else t("wh_enable")
            desc_html = f'<div class="wh-ep-desc muted">{html_escape(ep["description"])}</div>' if ep["description"] else ""
            modal_id = f"wh-cfg-{ep['id']}"
            rows.append(f"""<div class="wh-ep-row">
  <div class="wh-ep-main">
    <div class="wh-ep-url-row">
      <span class="{en_cls}">{en_lbl}</span>
      {st_html}
      <span class="wh-ev-badge wh-preset-badge">{html_escape(preset_label)}</span>
      <code class="wh-ep-url">{html_escape(ep["url"])}</code>
    </div>
    <div class="wh-ep-badges">{ev_badges}</div>
    {desc_html}
    <details class="wh-secret-details">
      <summary>{t("wh_show_secret")}</summary>
      <div class="wh-secret-box"><span class="muted">{t("wh_secret_label")}:</span> <code class="wh-secret-code">{html_escape(ep["secret"])}</code></div>
    </details>
  </div>
  <div class="wh-ep-actions">
    <button type="button" class="button small" data-open-modal="{modal_id}">{icon_label("settings", t("wh_cfg_btn"))}</button>
    <form method="post" action="{base}/test" style="display:contents">
      <input type="hidden" name="endpoint_id" value="{html_escape(ep["id"])}">
      <button class="button small">{t("wh_test_btn")}</button>
    </form>
    <form method="post" action="{base}/toggle" style="display:contents">
      <input type="hidden" name="endpoint_id" value="{html_escape(ep["id"])}">
      <input type="hidden" name="action" value="{tog_action}">
      <button class="button small">{tog_label}</button>
    </form>
    <form method="post" action="{base}/delete" style="display:contents" {confirm_submit_attrs(t("wh_del_confirm_title"), t("wh_del_confirm_msg", url=ep["url"]), t("wh_del_confirm_btn"))}>
      <input type="hidden" name="endpoint_id" value="{html_escape(ep["id"])}">
      <button class="button small wh-del-btn">{t("wh_delete_btn")}</button>
    </form>
  </div>
</div>""")
            cfg_modals.append(_wh_config_modal(ep, app_id))
        ep_html = "\n".join(rows)

    # ── Create form ──
    ev_checks = "".join(
        f'<label class="wh-ev-check"><input type="checkbox" name="ev_{html_escape(ev.replace(".", "_"))}" value="1" checked> {html_escape(_wh_event_label(ev))}</label>'
        for ev in WEBHOOK_EVENTS
    )
    create_form = f"""<section class="panel">
  <div class="panel-head"><h2>{t("wh_create_title")}</h2><p class="muted">{t("wh_create_desc")}</p></div>
  <form method="post" action="{base}/create">
    <div class="wh-create-fields">
      <label>{t("wh_url_label")}
        <input type="url" name="url" required minlength="10" maxlength="512" data-url-field placeholder="{html_escape(t("wh_url_placeholder"))}" class="wh-url-input">
      </label>
      <label>{t("wh_desc_label")}
        <input type="text" name="description" placeholder="{html_escape(t("wh_desc_placeholder"))}" maxlength="200">
      </label>
    </div>
    <div class="wh-events-row">
      <span class="wh-events-lbl">{t("wh_events_label")}</span>
      <div class="wh-ev-checks">{ev_checks}</div>
    </div>
    <div class="toolbar" style="margin-top:12px">
      <button type="submit" class="button primary-action">{icon_label("webhooks", t("wh_create_btn"))}</button>
    </div>
  </form>
</section>"""

    # ── Recent deliveries ──
    recent = conn.execute(
        """
        SELECT d.*, e.url FROM webhook_deliveries d
        JOIN webhook_endpoints e ON e.id = d.endpoint_id
        WHERE e.app_id = ?
        ORDER BY d.created_at DESC LIMIT ? OFFSET ?
        """,
        (app_id, log_per_page, log_offset),
    ).fetchall()
    if not recent:
        deliveries_html = f'<p class="muted wh-empty">{t("wh_no_deliveries")}</p>'
    else:
        drows = []
        for d in recent:
            st = d["status"]
            st_cls = {"success": "status status-ok", "failed": "status status-bad", "pending": "status status-warn", "retrying": "status status-warn"}.get(st, "status status-muted")
            code = str(d["response_status"]) if d["response_status"] else "—"
            err = html_escape((d["error"] or "")[:80])
            url_short = html_escape((d["url"] or "")[:55])
            drows.append(f"""<tr>
  <td>{html_escape(d["event_type"])}</td>
  <td><code style="font-size:11px">{url_short}</code></td>
  <td><span class="{st_cls}">{html_escape(st)}</span></td>
  <td>{code}</td>
  <td>{d["attempt"]}/{d["max_attempts"]}</td>
  <td class="muted" style="font-size:11px;max-width:200px">{err}</td>
  <td class="muted" style="font-size:11px">{(d["created_at"] or "")[:16]}</td>
</tr>""")
        deliveries_html = f"""<div class="table-wrap"><table class="wh-log-table">
<tr>
  <th>{t("wh_col_event")}</th><th>{t("wh_col_endpoint")}</th><th>{t("wh_col_status")}</th>
  <th>{t("wh_col_code")}</th><th>{t("wh_col_attempts")}</th><th>{t("wh_col_error")}</th><th>{t("wh_col_time")}</th>
</tr>
{"".join(drows)}
</table></div>"""

    endpoint_pagination = pagination_links(
        page_base,
        ep_page,
        ep_total_pages,
        {"tab": "webhooks", "wh_log_page": log_page, "wh_log_limit": log_per_page},
        page_param="wh_page",
        limit_param="wh_limit",
        current_limit=ep_per_page,
        total_items=endpoint_total,
    )
    delivery_pagination = pagination_links(
        page_base,
        log_page,
        log_total_pages,
        {"tab": "webhooks", "wh_page": ep_page, "wh_limit": ep_per_page},
        page_param="wh_log_page",
        limit_param="wh_log_limit",
        current_limit=log_per_page,
        total_items=delivery_total,
    )

    return f"""<section class="panel">
  <div class="panel-head">
    <div><h2>{t("wh_title")}</h2><p class="muted">{t("wh_subtitle")}</p></div>
  </div>
  {stats_html}
</section>
<section class="panel">
  <div class="panel-head"><h2>{t("wh_endpoints_title")}</h2><p class="muted">{t("wh_endpoints_desc")}</p></div>
  <div class="wh-ep-list">{ep_html}</div>
  {endpoint_pagination}
</section>
{create_form}
<section class="panel">
  <div class="panel-head"><h2>{t("wh_log_title")}</h2><p class="muted">{t("wh_log_desc")}</p></div>
  {deliveries_html}
  {delivery_pagination}
</section>
{"".join(cfg_modals)}"""


def render_config_console() -> str:
    listeners = listener_targets()
    admin_listener = listeners["admin"]
    api_listener = listeners["api"]
    provisioning = provisioning_defaults()
    backup = backup_settings()
    protection_cfg = protection_settings()
    current_config_text = config_text()
    proxy_example = """api:
  accepted_ip_headers: [CF-Connecting-IP, True-Client-IP, Fly-Client-IP, X-Real-IP, X-Forwarded-For, Forwarded]
  accepted_country_headers: [CF-IPCountry, CloudFront-Viewer-Country, X-Vercel-IP-Country]
  allow_payload_ip_fallback: true
  geoip_url: https://ipwho.is/{ip}
server:
  trust_proxy_headers: true"""
    split_example = """server:
  mode: split
  admin_host: 127.0.0.1
  admin_port: 8080
  api_host: 0.0.0.0
  api_port: 1488
admin:
  public_base_url: http://127.0.0.1:8080
api:
  public_base_url: https://licenses.example.com"""
    stats = [
        (t("config_stat_mode"), listeners["mode"]),
        (t("config_stat_admin"), f"{admin_listener['host']}:{admin_listener['port']}"),
        (t("config_stat_api"), f"{api_listener['host']}:{api_listener['port']}"),
        (t("config_stat_proxy"), t("yes") if trust_proxy_headers() else t("no")),
        (t("config_stat_provisioning"), t("backup_runtime_auto_on") if provisioning["enabled"] else t("backup_runtime_auto_off")),
        (t("config_stat_backup"), t("backup_runtime_auto_on") if backup["auto_enabled"] else t("backup_runtime_auto_off")),
        ("Protection", protection_cfg["mode"] if protection_any_module_enabled(protection_cfg) else "disabled"),
        (t("config_stat_geoip"), config_str("api.geoip_url", "default fallback")),
        (t("config_stat_password_min"), PASSWORD_MIN_LENGTH),
    ]
    jump_buttons = "".join(
        f'<button type="button" class="config-jump" data-config-jump="{html_escape(section)}">{html_escape(section)}</button>'
        for section in ("server", "admin", "api", "cloudflare", "security", "ui", "protection", "backup", "provisioning", "paths")
    )
    save_popup_modal = modal(
        "cfg-save-popup",
        t("config_save_confirm_title"),
        f"""<p class="muted">{t("config_save_confirm_msg")}</p>
<div class="form-grid" style="margin-top:12px">
  {confirm_password_field(t("form_admin_password"))}
</div>
<p class="actions" style="margin-top:14px">
  <button type="button" data-close-modal>{t("confirm_cancel")}</button>
  <button class="primary" type="button" id="cfg-save-confirm-btn">{icon_label("save", t("config_save"))}</button>
</p>""",
    )
    config_modal = modal(
        "config-editor-modal",
        t("config_workbench_title"),
        f"""
<form method="post" action="/admin/config/save" class="config-modal-form" data-config-save-form>
  <input type="hidden" name="return_to" value="/admin/config">
  <input type="hidden" name="confirm_password" data-cfg-pwd-hidden>
  <div class="config-editor-toolbar">
    <div class="config-jump-strip">{jump_buttons}</div>
    <div class="config-meta-strip">
      <span class="config-meta-pill" data-config-status>Live file</span>
      <span class="config-meta-pill" data-config-cursor>Ln 1, Col 1</span>
    </div>
  </div>
  <div class="config-editor-stage" data-config-editor-root>
    <div class="config-editor-gutter" data-config-gutter aria-hidden="true"></div>
    <div class="config-editor-surface">
      <pre class="config-editor-highlight" data-config-highlight aria-hidden="true"></pre>
      <textarea class="config-editor" name="config_text" data-config-input spellcheck="false" autocomplete="off" wrap="off">{html_escape(current_config_text)}</textarea>
    </div>
  </div>
  <div class="config-editor-footer">
    <div class="row-actions">
      <button type="button" data-config-reset>{icon_label("reset-devices", t("config_reset_unsaved"))}</button>
      <a class="button" href="/admin/backup">{icon_label("save", t("config_backup_center"))}</a>
      <a class="button" href="/admin/docs#config">{icon_label("faq", t("config_open_faq_btn"))}</a>
    </div>
    <button class="primary" type="button" data-config-save-btn>{icon_label("save", t("config_save"))}</button>
  </div>
</form>
""",
        "config-workbench-modal",
    )
    body = f"""
<section class="panel">
  <div class="panel-head">
    <div><h1>{t("config_title")}</h1><p>{t("config_subtitle")}</p></div>
    <div class="row-actions">
      <button class="primary" type="button" data-open-modal="config-editor-modal">{icon_label("settings", t("config_open_editor"))}</button>
      <a class="button" href="/admin/api">{icon_label("api-console", t("config_open_api"))}</a>
      <a class="button" href="/admin/backup">{icon_label("save", t("config_backup_center"))}</a>
      <a class="button" href="/admin/docs#config">{icon_label("faq", t("config_open_faq"))}</a>
    </div>
  </div>
  <div class="stat-grid">{''.join(stat_card(label, value) for label, value in stats)}</div>
</section>
<section class="panel">
  <div class="panel-head">
    <div><h2>{t("config_workbench_title")}</h2><p>{t("config_workbench_open")}</p></div>
    <button class="primary" type="button" data-open-modal="config-editor-modal">{icon_label("settings", t("config_workbench_open"))}</button>
  </div>
  <div class="doc-grid api-lower-grid">
    <div>
      <h3>What the popup gives you</h3>
      <ul class="doc-list">
        <li>Big focused modal instead of a stretched page textarea.</li>
        <li>Custom Key Base config syntax coloring for sections, keys, ports, URLs, booleans, and secrets.</li>
        <li>Line numbers, live cursor position, unsaved-change status, and section jump buttons.</li>
        <li><code>Tab</code> inserts spaces and <code>Ctrl+S</code> triggers save.</li>
      </ul>
    </div>
    <div>
      <h3>Fast sections</h3>
      <div class="config-jump-strip config-jump-static">{jump_buttons}</div>
      <p class="muted">Use these inside the popup to jump straight to the exact block you want without hunting through the whole file.</p>
    </div>
  </div>
</section>
<section class="panel">
  <div class="doc-grid api-lower-grid">
    <div>
      <h2>{t("config_what_belongs")}</h2>
      <ul class="doc-list">
        <li><code>server.*</code> controls combined vs split mode and every bind port.</li>
        <li><code>admin.public_base_url</code> and <code>api.public_base_url</code> define the public URLs shown in the panel and docs.</li>
        <li><code>api.accepted_ip_headers</code>, <code>api.allow_payload_ip_fallback</code>, and <code>api.geoip_url</code> control real-IP recovery.</li>
        <li><code>cloudflare.*</code> keeps HTTPS and country header behavior aligned with your reverse proxy.</li>
        <li><code>backup.*</code> controls auto backups, retention, and what each archive contains.</li>
        <li><code>provisioning.*</code> powers site-to-Key-Base key generation after a purchase.</li>
      </ul>
    </div>
    <div>
      <h2>{t("config_save_checklist")}</h2>
      <ul class="doc-list">
        <li>Keep <code>server.mode: combined</code> if admin and API should stay on one host:port.</li>
        <li>Use <code>server.mode: split</code> only when admin and API truly need different listeners.</li>
        <li>When a reverse proxy terminates TLS, set the public URLs to the real external HTTPS addresses.</li>
        <li>Whitelist only trusted proxy IPs in <code>.env</code> if you enable proxy header trust.</li>
        <li>After saving listener changes, restart from the API tab so the runtime picks up the new bind targets.</li>
      </ul>
    </div>
  </div>
</section>
<section class="panel">
  <div class="doc-grid api-lower-grid">
    <div>
      <h2>{t("config_proxy_example")}</h2>
      <pre>{html_escape(proxy_example)}</pre>
      <p class="muted">This keeps IPv4 recovery sane when requests arrive through Cloudflare, tunnels, or local reverse proxies.</p>
    </div>
    <div>
      <h2>{t("config_split_example")}</h2>
      <pre>{html_escape(split_example)}</pre>
      <p class="muted">Good when the admin panel should stay local but the verify API needs its own public port or domain.</p>
    </div>
  </div>
</section>
{save_popup_modal}
{config_modal}
"""
    return page_shell(t("config_title"), body, "config")


def render_backup_console(query: dict[str, list[str]] | None = None) -> str:
    settings = backup_settings()
    status = backup_status()
    total = backup_file_count()
    latest_rows = list_backups(limit=1)
    latest = latest_rows[0] if latest_rows else None
    page, per_page, offset = page_state(query)
    page, total_pages, offset = pagination_bounds(total, page, per_page)
    rows = list_backups(limit=per_page, offset=offset)
    rows_html = "".join(
        f"""
<tr data-bulk-id="{html_escape(row['name'])}">
  <td><code>{html_escape(row['name'])}</code></td>
  <td>{html_escape(row['created_at'])}</td>
  <td>{html_escape(row['reason'])}</td>
  <td>{html_escape(row['items'])}</td>
  <td>{html_escape(row['size'])}</td>
  <td>
    <form method="post" action="/admin/backup/delete" {confirm_submit_attrs(t("backup_delete_title"), t("backup_delete_msg", name=row['name']), t("backup_delete_label"))}>
      <input type="hidden" name="return_to" value="/admin/backup">
      <input type="hidden" name="name" value="{html_escape(row['name'])}">
      <button class="danger" type="submit">{icon_label("delete", t("backup_delete_btn"))}</button>
    </form>
  </td>
</tr>
"""
        for row in rows
    ) or f'<tr><td colspan="6" class="muted">{t("backup_empty")}</td></tr>'
    _backup_bulk_bar = bulk_toolbar("/admin/backup/bulk", ["delete"]) if rows else ""
    _backup_bulk_modal = bulk_confirm_modal("backups") if rows else ""
    body = f"""
<section class="panel">
  <div class="panel-head">
    <div>
      <span class="eyebrow">{t("backup_eyebrow")}</span>
      <h1>{t("backup_heading")}</h1>
      <p>{t("backup_subtitle")}</p>
    </div>
    <div class="api-process-actions">
      <form method="post" action="/admin/backup/create">
        <input type="hidden" name="return_to" value="/admin/backup">
        <input type="hidden" name="reason" value="manual">
        <button class="primary" type="submit">{icon_label("save", t("backup_create_now"))}</button>
      </form>
      <a class="button" href="/admin/docs#security">{icon_label("faq", t("backup_open_faq"))}</a>
    </div>
  </div>
  <div class="stat-grid">
    {stat_card(t("backup_stat_auto"), t("backup_runtime_auto_on") if settings["auto_enabled"] else t("backup_runtime_auto_off"))}
    {stat_card(t("backup_stat_interval"), f"{settings['interval_minutes']} min")}
    {stat_card(t("backup_stat_keep"), settings["keep_last"])}
    {stat_card(t("backup_stat_dir"), settings["directory"])}
    {stat_card(t("backup_stat_last_status"), status["last_status"])}
    {stat_card(t("backup_stat_last_archive"), latest["name"] if latest else t("backup_runtime_never"))}
    {stat_card(t("backup_stat_last_size"), latest["size"] if latest else "n/a")}
    {stat_card(t("backup_stat_worker"), t("backup_worker_running") if status["running"] else t("backup_worker_idle"))}
  </div>
</section>
<section class="panel">
  <div class="doc-grid api-lower-grid">
    <div>
      <h2>{t("backup_runtime_title")}</h2>
      <table class="mini-table">
        <tr><th>{t("backup_runtime_setting")}</th><th>{t("backup_runtime_value")}</th></tr>
        <tr><td>{t("backup_runtime_dir")}</td><td><code>{html_escape(status['directory'])}</code></td></tr>
        <tr><td>{t("backup_runtime_auto")}</td><td>{html_escape(t("backup_runtime_auto_on") if settings["auto_enabled"] else t("backup_runtime_auto_off"))}</td></tr>
        <tr><td>{t("backup_runtime_interval")}</td><td>{t("backup_runtime_interval_val", minutes=html_escape(settings["interval_minutes"]))}</td></tr>
        <tr><td>{t("backup_runtime_retention")}</td><td>{t("backup_runtime_retention_val", count=html_escape(settings["keep_last"]))}</td></tr>
        <tr><td>{t("backup_runtime_last_msg")}</td><td>{html_escape(status["last_message"])}</td></tr>
        <tr><td>{t("backup_runtime_last_started")}</td><td>{html_escape(status["last_started_at"] or t("backup_runtime_never"))}</td></tr>
        <tr><td>{t("backup_runtime_last_finished")}</td><td>{html_escape(status["last_finished_at"] or t("backup_runtime_never"))}</td></tr>
      </table>
    </div>
    <div>
      <h2>{t("backup_what_title")}</h2>
      <table class="mini-table">
        <tr><th>{t("backup_what_item")}</th><th>{t("backup_what_state")}</th></tr>
        <tr><td>{t("backup_what_db")}</td><td>{html_escape(t("yes") if settings["include_database"] else t("no"))}</td></tr>
        <tr><td>{t("backup_what_config")}</td><td>{html_escape(t("yes") if settings["include_config"] else t("no"))}</td></tr>
        <tr><td>{t("backup_what_env")}</td><td>{html_escape(t("yes") if settings["include_env"] else t("no"))}</td></tr>
        <tr><td>{t("backup_what_format")}</td><td><code>zip</code> with <code>metadata.json</code></td></tr>
      </table>
      <div class="notice">{t("backup_what_note")}</div>
    </div>
  </div>
</section>
<section class="panel">
  <div class="panel-head"><div><h2>{t("backup_archives_title")}</h2><p>{t("backup_archives_subtitle")}</p></div></div>
  {_backup_bulk_bar}
  <table{' data-bulk-table="backups"' if rows else ''}>
    <tr><th>{t("backup_col_name")}</th><th>{t("backup_col_created")}</th><th>{t("backup_col_reason")}</th><th>{t("backup_col_contents")}</th><th>{t("backup_col_size")}</th><th>{t("backup_col_actions")}</th></tr>
    {rows_html}
  </table>
  {pagination_links("/admin/backup", page, total_pages, current_limit=per_page, total_items=total)}
  {_backup_bulk_modal}
</section>
"""
    return page_shell(t("backup_title"), body, "backup")


def render_docs() -> str:
    backup = backup_settings()
    protection_cfg = protection_settings()
    provisioning = provisioning_defaults()
    listeners = listener_targets()
    api_listener = listeners["api"]
    admin_listener = listeners["admin"]
    api_port = str(api_listener["port"])
    api_base_url = "http://127.0.0.1:8080"
    admin_base_url = "http://127.0.0.1:8080"
    sample = {
        "app_id": "default",
        "key": "KB-AAAA-BBBB-CCCC-DDDD",
        "hwid": "b8d31d4ad7f62a6f1d2c4f6f9c9b1a88",
        "ip": "8.8.8.8",
        "country": "US",
        "version": "1.0.0",
    }
    success = {
        "ok": True,
        "status": "valid",
        "message": "Key accepted",
        "app_id": "default",
        "key": "KB-AAAA-BBBB-CCCC-DDDD",
        "country": "US",
        "expires_at": "2026-07-21T23:10:00+00:00",
        "activated_at": "2026-06-21T23:10:00+00:00",
        "duration_seconds": 2592000,
        "max_devices": 1,
        "devices_used": 1,
        "server_time": utc_now(),
    }
    failure = {
        "ok": False,
        "status": "device_limit",
        "message": "Device limit reached",
        "country": "US",
        "devices_used": 1,
        "max_devices": 1,
    }
    provisioning_success = {
        "ok": True,
        "status": "provisioned",
        "app_id": "default",
        "count": 1,
        "duration_seconds": 2592000,
        "duration_label": "30 days",
        "max_devices": 1,
        "note": "order-1001 | customer:user-42",
        "keys": ["KB-AAAA-BBBB-CCCC-DDDD"],
    }
    local_config = """server:
  host: 127.0.0.1
  port: 8080
  allow_remote_admin: false
  trust_proxy_headers: false
api:
  public_base_url: http://127.0.0.1:8080
admin:
  public_base_url: http://127.0.0.1:8080"""
    split_local_config = """server:
  mode: split
  admin_host: 127.0.0.1   # Admin panel + Admin API — local only
  admin_port: 8080
  api_host: 0.0.0.0        # Client API (verify) — public
  api_port: 1488
  allow_remote_admin: false
  trust_proxy_headers: false
api:
  public_base_url: https://api.example.com
admin:
  public_base_url: http://127.0.0.1:8080"""
    lan_config = """server:
  host: 0.0.0.0
  port: 8080
  allow_remote_admin: false
api:
  public_base_url: http://192.168.1.50:8080
admin:
  public_base_url: http://127.0.0.1:8080"""
    cloudflare_config = """server:
  host: 127.0.0.1
  port: 8080
  allow_remote_admin: false
  trust_proxy_headers: true
cloudflare:
  enabled: true
  country_header: CF-IPCountry
  restore_visitor_ip: true
  require_https: true
api:
  public_base_url: https://api.example.com
admin:
  public_base_url: https://admin.example.com"""
    split_cloudflare_config = """server:
  mode: split
  admin_host: 127.0.0.1
  admin_port: 8080
  api_host: 127.0.0.1
  api_port: 1488
  trust_proxy_headers: true
cloudflare:
  enabled: true
  country_header: CF-IPCountry
  restore_visitor_ip: true
  require_https: true
api:
  public_base_url: https://api.example.com
admin:
  public_base_url: http://127.0.0.1:8080"""
    proxy_config = """# nginx / caddy / cloudflared publishes HTTPS.
# Key Base stays private on localhost.
server:
  host: 127.0.0.1
  port: 8080
  trust_proxy_headers: true
api:
  public_base_url: https://licenses.example.com
admin:
  public_base_url: https://licenses.example.com"""
    provisioning_config = f"""provisioning:
  enabled: true
  header_name: {provisioning["header_name"]}
  shared_token: change-this-provision-token
  rate_limit_per_minute: {provisioning["rate_limit_per_minute"]}
  require_https: false
  default_prefix: {provisioning["default_prefix"]}
  default_max_devices: {provisioning["default_max_devices"]}
  default_duration_value: {provisioning["default_duration_value"]}
  default_duration_unit: {provisioning["default_duration_unit"]}
  max_batch_size: {provisioning["max_batch_size"]}"""
    protection_config = f"""protection:
  mode: warn           # warn, block, restrict, or strict — legacy field; anti_mode controls actual behavior
  anti_mode: {protection_cfg["anti_mode"]}      # off, warn, or strict
  anti_vm: {str(protection_cfg["anti_vm"]).lower()}
  anti_vpn: {str(protection_cfg["anti_vpn"]).lower()}
  anti_proxy: {str(protection_cfg["anti_proxy"]).lower()}
  anti_debug: {str(protection_cfg["anti_debug"]).lower()}
  anti_tamper: {str(protection_cfg["anti_tamper"]).lower()}
  anti_sandbox: {str(protection_cfg["anti_sandbox"]).lower()}
  free_ip_intel: {str(protection_cfg["free_ip_intel"]).lower()}
  tor_exit_list: {str(protection_cfg["tor_exit_list"]).lower()}
  tor_exit_list_url: {protection_cfg["tor_exit_list_url"]}
  ip_whitelist: []
  hwid_whitelist: []
  country_whitelist: []
  ip_reputation_url: ""
  ip_reputation_token: ""
  risk_threshold: {protection_cfg["risk_threshold"]}
  signal_threshold: {protection_cfg["signal_threshold"]}
  challenge_threshold: {protection_cfg["challenge_threshold"]}
  hard_challenge_threshold: {protection_cfg["hard_challenge_threshold"]}
  block_threshold: {protection_cfg["block_threshold"]}
  request_window_seconds: {protection_cfg["request_window_seconds"]}
  too_fast_threshold: {protection_cfg["too_fast_threshold"]}
  risk_weights:
    vpn: {protection_cfg["risk_weights"].get("vpn", 25)}
    proxy: {protection_cfg["risk_weights"].get("proxy", 25)}
    datacenter_asn: {protection_cfg["risk_weights"].get("datacenter_asn", 20)}
    tor: {protection_cfg["risk_weights"].get("tor", 40)}
    suspicious_ua: {protection_cfg["risk_weights"].get("suspicious_ua", 10)}
    timezone_geo_mismatch: {protection_cfg["risk_weights"].get("timezone_geo_mismatch", 15)}
    too_fast_requests: {protection_cfg["risk_weights"].get("too_fast_requests", 20)}
    missing_js_fingerprint: {protection_cfg["risk_weights"].get("missing_js_fingerprint", 30)}
    headless_browser: {protection_cfg["risk_weights"].get("headless_browser", 25)}
    automation_flags: {protection_cfg["risk_weights"].get("automation_flags", 25)}
    vm_or_emulator: {protection_cfg["risk_weights"].get("vm_or_emulator", 30)}
    debugger: {protection_cfg["risk_weights"].get("debugger", 40)}
    sandbox: {protection_cfg["risk_weights"].get("sandbox", 60)}
    tamper: {protection_cfg["risk_weights"].get("tamper", 80)}
  # Optional keyword lists: vm_keywords, vpn_keywords, proxy_keywords,
  # datacenter_keywords, debug_keywords, tamper_keywords, sandbox_keywords."""
    backup_yaml = f"""backup:
  directory: {backup['directory']}
  auto_enabled: {str(backup['auto_enabled']).lower()}
  interval_minutes: {backup['interval_minutes']}
  keep_last: {backup['keep_last']}
  include_database: {str(backup['include_database']).lower()}
  include_config: {str(backup['include_config']).lower()}
  include_env: {str(backup['include_env']).lower()}"""
    wh_timeout = config_int("webhooks.timeout_seconds", 10, 1, 120)
    wh_retries = config_int("webhooks.max_retries", 3, 0, 10)
    webhook_config = f"""webhooks:
  timeout_seconds: {wh_timeout}   # HTTP timeout per delivery attempt (seconds)
  max_retries: {wh_retries}        # Extra retries after initial fail (0 = one shot, max 10)
                            # Retry delays: 0s → 60s → 5m → 30m"""
    webhook_payload_example = json.dumps({
        "event": "key.created",
        "timestamp": utc_now(),
        "delivery_id": "a3f8c1d2e9b4",
        "app_id": "default",
        "key": "KB-AAAA-BBBB-CCCC-DDDD",
    }, indent=2)
    webhook_verify_python = """import hashlib
import hmac

def verify_signature(secret: str, payload_bytes: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header)

# In your handler (Flask example):
# payload = request.get_data()
# sig     = request.headers.get("X-KeyBase-Signature", "")
# ok      = verify_signature("your-endpoint-secret", payload, sig)"""
    webhook_verify_node = """const crypto = require("crypto");

function verifySignature(secret, payloadBuffer, header) {
  const expected = "sha256=" + crypto
    .createHmac("sha256", secret)
    .update(payloadBuffer)
    .digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(header)
  );
}

// Express example:
// app.post("/webhooks", express.raw({type:"*/*"}), (req, res) => {
//   const ok = verifySignature("your-secret", req.body,
//                              req.headers["x-keybase-signature"] || "");
//   if (!ok) return res.sendStatus(401);
//   const event = JSON.parse(req.body);
//   console.log(event.event, event.key);
//   res.sendStatus(200);
// });"""
    sub_levels_config = """subscriptions:
  levels:
    1: Default      # level ID 1–99, any name without special chars
    2: Premium
    3: Enterprise"""
    windows_commands = (
        r""".\run.bat
python -m keybase
Invoke-RestMethod __API__/api/v1/health
netstat -ano | findstr :__PORT__
taskkill /PID 1234 /F"""
        .replace("__API__", api_base_url)
        .replace("__PORT__", api_port)
    )
    linux_commands = (
        r"""sh ./run.sh
python3 -m keybase
curl -s __API__/api/v1/health
ss -ltnp | grep :__PORT__
kill -TERM 1234"""
        .replace("__API__", api_base_url)
        .replace("__PORT__", api_port)
    )
    config_check_commands = r"""python -c "import pathlib, py_compile, tempfile; py_compile.compile('keybase/core.py', cfile=str(pathlib.Path(tempfile.gettempdir()) / 'kb_core.pyc'), doraise=True); print('core ok')"
python -c "from keybase import core; print(core.config_str('server.host', '127.0.0.1'), core.config_int('server.port', 8080, 1, 65535))"
python -c "from keybase import core; print(core.server_mode(), core.listener_targets())"
python -c "from keybase import core; print(core.config_bool('cloudflare.enabled'), core.trust_proxy_headers())"
python -c "from keybase import core; print(core.provisioning_defaults())" """
    backup_windows = r"""New-Item -ItemType Directory -Force backups
Copy-Item data\keybase.sqlite3 backups\keybase.sqlite3.bak
Copy-Item .env backups\.env.bak
Copy-Item config.yml backups\config.yml.bak"""
    backup_linux = r"""mkdir -p backups
cp data/keybase.sqlite3 backups/keybase.sqlite3.bak
cp .env backups/.env.bak
cp config.yml backups/config.yml.bak"""
    firewall_windows = (
        r"""netsh advfirewall firewall add rule name="Key Base API __PORT__" dir=in action=allow protocol=TCP localport=__PORT__
netsh advfirewall firewall show rule name="Key Base API __PORT__"
netsh advfirewall firewall delete rule name="Key Base API __PORT__" """
        .replace("__PORT__", api_port)
    )
    firewall_linux = (
        r"""sudo ufw allow __PORT__/tcp
sudo ufw status
sudo ufw delete allow __PORT__/tcp"""
        .replace("__PORT__", api_port)
    )
    powershell_verify = (
        r"""$body = @{
  app_id = "default"
  key = "KB-AAAA-BBBB-CCCC-DDDD"
  hwid = "test-hwid-001"
  country = "US"
  version = "1.0.0"
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "__API__/api/v1/verify" `
  -Method Post `
  -ContentType "application/json" `
  -Headers @{"X-App-Secret"="optional-secret"} `
  -Body $body"""
        .replace("__API__", api_base_url)
    )
    nginx_example = (
        r"""server {
  listen 443 ssl http2;
  server_name licenses.example.com;

  location / {
    proxy_pass http://127.0.0.1:__PORT__;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}"""
        .replace("__PORT__", api_port)
    )
    caddy_example = (
        r"""licenses.example.com {
  reverse_proxy 127.0.0.1:__PORT__
}"""
        .replace("__PORT__", api_port)
    )
    systemd_example = r"""[Unit]
Description=Key Base
After=network.target

[Service]
WorkingDirectory=/opt/key-base
ExecStart=/usr/bin/python3 -m keybase
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target"""
    curl_example = (
        """curl -X POST __API__/api/v1/verify \\
  -H "Content-Type: application/json" \\
  -H "X-App-Secret: optional-secret" \\
  -H "CF-IPCountry: US" \\
  -d '{"app_id":"default","key":"KB-AAAA-BBBB-CCCC-DDDD","hwid":"b8d31d4ad7f62a6f1d2c4f6f9c9b1a88","country":"US","version":"1.0.0"}'"""
        .replace("__API__", api_base_url)
    )
    python_client = ("""import hashlib
import platform
import requests

API_URL = "__API__/api/v1/verify"

hwid = hashlib.sha256(
    (platform.node() + platform.system() + platform.processor()).encode()
).hexdigest()

payload = {
    "app_id": "default",
    "key": "KB-AAAA-BBBB-CCCC-DDDD",
    "hwid": hwid,
    "country": "US",
    "version": "1.0.0",
}

response = requests.post(
    API_URL,
    json=payload,
    headers={"X-App-Secret": "optional-secret"},
    timeout=10,
)
data = response.json()

if not data.get("ok"):
    raise SystemExit(f"License rejected: {data.get('status')}")

print("License OK", data.get("expires_at"))"""
        .replace("__API__", api_base_url)
    )
    signed_python_client = ("""import hashlib
import hmac
import platform
import secrets
import time
import requests

API_URL = "__API__/api/v1/verify"
APP_ID = "default"
APP_SECRET = "your-app-secret"
KEY = "KB-AAAA-BBBB-CCCC-DDDD"
VERSION = "1.0.0"
CLIENT_HASH = "sha256-of-your-client-binary"
BUILD_ID = "win-x64-100"
SESSION_TOKEN = ""

def hwid():
    raw = platform.node() + platform.system() + platform.processor()
    return hashlib.sha256(raw.encode()).hexdigest()

def sign(app_id, key, device_id, timestamp, nonce):
    payload = "\\n".join([
        "kb-v1",
        app_id.lower(),
        key.upper().replace(" ", ""),
        device_id.lower(),
        str(timestamp),
        nonce,
        VERSION,
        CLIENT_HASH.lower(),
        BUILD_ID,
    ])
    return hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

device_id = hwid()
timestamp = int(time.time())
nonce = secrets.token_urlsafe(24)

body = {
    "app_id": APP_ID,
    "key": KEY,
    "hwid": device_id,
    "version": VERSION,
    "client_hash": CLIENT_HASH,
    "build_id": BUILD_ID,
}

headers = {
    "Content-Type": "application/json",
    "X-App-Secret": APP_SECRET,
    "X-KeyBase-Timestamp": str(timestamp),
    "X-KeyBase-Nonce": nonce,
    "X-KeyBase-Signature": sign(APP_ID, KEY, device_id, timestamp, nonce),
}
if SESSION_TOKEN:
    headers["X-KeyBase-Session"] = SESSION_TOKEN

data = requests.post(API_URL, json=body, headers=headers, timeout=10).json()
if data.get("session_token"):
    SESSION_TOKEN = data["session_token"]
print(data["status"], data.get("message"))"""
        .replace("__API__", api_base_url)
    )
    provisioning_curl = f"""curl -X POST {api_base_url}/api/v1/provision \\
  -H "Content-Type: application/json" \\
  -H "{provisioning['header_name']}: change-this-provision-token" \\
  -d '{{"app_id":"default","count":1,"prefix":"{provisioning['default_prefix']}","max_devices":{provisioning['default_max_devices']},"duration_value":{provisioning['default_duration_value']},"duration_unit":"{provisioning['default_duration_unit']}","note":"order-1001","order_id":"1001","customer_id":"user-42"}}'"""
    api_tab_js = """<script>
(function() {
  var btns = [].slice.call(document.querySelectorAll('[data-api-docs-tab]'));
  var panels = [].slice.call(document.querySelectorAll('[data-api-docs-panel]'));
  if (!btns.length || !panels.length) return;

  function isKnownTab(tab) {
    for (var index = 0; index < btns.length; index += 1) {
      if (btns[index].dataset.apiDocsTab === tab) return true;
    }
    return false;
  }

  function setActiveTab(tab) {
    if (!isKnownTab(tab)) tab = btns[0].dataset.apiDocsTab;
    btns.forEach(function(btn) {
      var selected = btn.dataset.apiDocsTab === tab;
      btn.classList.toggle('active', selected);
      btn.setAttribute('aria-selected', selected ? 'true' : 'false');
    });
    panels.forEach(function(panel) {
      var visible = panel.dataset.apiDocsPanel === tab;
      panel.hidden = !visible;
      panel.setAttribute('aria-hidden', visible ? 'false' : 'true');
    });
    var apiSection = document.getElementById('api');
    if (apiSection) apiSection.dataset.apiDocsTab = tab;
    try {
      window.dispatchEvent(new CustomEvent('faq:api-tab-change', { detail: { tab: tab } }));
    } catch (err) {
      if (window.faqController && typeof window.faqController.setApiTab === 'function') {
        window.faqController.setApiTab(tab);
      }
    }
  }

  function currentTab() {
    for (var index = 0; index < panels.length; index += 1) {
      if (!panels[index].hidden && panels[index].dataset.apiDocsPanel) {
        return panels[index].dataset.apiDocsPanel;
      }
    }
    return btns[0].dataset.apiDocsTab;
  }

  btns.forEach(function(btn) {
    btn.addEventListener('click', function() {
      setActiveTab(this.dataset.apiDocsTab);
    });
  });

  setActiveTab(currentTab());
})();
</script>"""

    # ── Multi-language code examples (regular strings, not f-strings) ─────────
    ex_hwid_python = (
        "import hashlib, platform, uuid\n"
        "\n"
        "def get_hwid() -> str:\n"
        "    components = [\n"
        "        platform.node(),        # hostname\n"
        "        platform.system(),      # Windows / Linux / Darwin\n"
        "        platform.machine(),     # x86_64 / arm64\n"
        "        str(uuid.getnode()),    # MAC address as integer\n"
        "    ]\n"
        "    raw = '|'.join(c.strip() for c in components if c.strip())\n"
        "    return hashlib.sha256(raw.encode()).hexdigest()\n"
        "\n"
        "hwid = get_hwid()  # call once at startup and reuse"
    )
    ex_hwid_node = (
        "const crypto = require('crypto');\n"
        "const os = require('os');\n"
        "\n"
        "function getHWID() {\n"
        "    const parts = [\n"
        "        os.hostname(),\n"
        "        os.platform(),\n"
        "        os.arch(),\n"
        "        (os.cpus()[0] || {}).model || '',\n"
        "    ].filter(Boolean);\n"
        "    return crypto.createHash('sha256').update(parts.join('|')).digest('hex');\n"
        "}\n"
        "\n"
        "const hwid = getHWID(); // call once at startup and reuse"
    )
    ex_hwid_csharp = (
        "using System.Security.Cryptography;\n"
        "using System.Text;\n"
        "\n"
        "static string GetHWID()\n"
        "{\n"
        "    var parts = new[]\n"
        "    {\n"
        "        Environment.MachineName,\n"
        '        Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "",\n'
        "        Environment.OSVersion.Platform.ToString(),\n"
        "    };\n"
        "    var raw = string.Join(\"|\", parts.Where(p => p.Length > 0));\n"
        "    return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)))\n"
        "                  .ToLowerInvariant();\n"
        "}"
    )
    ex_hwid_go = (
        "package main\n"
        "\n"
        "import (\n"
        '    "crypto/sha256"\n'
        '    "fmt"\n'
        '    "os"\n'
        '    "runtime"\n'
        ")\n"
        "\n"
        "func getHWID() string {\n"
        "    hostname, _ := os.Hostname()\n"
        '    raw := fmt.Sprintf("%s|%s|%s", hostname, runtime.GOOS, runtime.GOARCH)\n'
        "    h := sha256.Sum256([]byte(raw))\n"
        '    return fmt.Sprintf("%x", h)\n'
        "}"
    )
    ex_hwid_php = (
        "function getHWID(): string {\n"
        "    $parts = [\n"
        "        gethostname(),     // machine name\n"
        "        php_uname('s'),    // OS name  (e.g. \"Windows NT\")\n"
        "        php_uname('m'),    // machine type (e.g. \"x86_64\")\n"
        "    ];\n"
        "    $raw = implode('|', array_filter($parts));\n"
        "    return hash('sha256', $raw);\n"
        "}"
    )
    _api = api_base_url
    _prov_hdr = provisioning["header_name"]
    ex_verify_node = (
        "const axios = require('axios');\n"
        "\n"
        f"const API_URL = '{_api}/api/v1/verify';\n"
        "const APP_ID  = 'default';\n"
        "const SECRET  = 'your-app-secret'; // empty string if no secret set\n"
        "\n"
        "async function verifyLicense(key, hwid, version = '1.0.0') {\n"
        "    const { data } = await axios.post(API_URL, {\n"
        "        app_id: APP_ID, key, hwid, version,\n"
        "    }, {\n"
        "        headers: { 'X-App-Secret': SECRET },\n"
        "        timeout: 10_000,\n"
        "    });\n"
        "\n"
        "    if (!data.ok) {\n"
        "        console.error('Rejected:', data.status, data.message);\n"
        "        throw new Error(data.status);\n"
        "    }\n"
        "    console.log('Accepted. Expires:', data.expires_at,\n"
        "                ' Level:', data.subscription_level);\n"
        "    return data;\n"
        "}"
    )
    ex_verify_csharp = (
        "using System.Net.Http;\n"
        "using System.Text;\n"
        "using System.Text.Json;\n"
        "\n"
        "static async Task<JsonElement> VerifyLicenseAsync(string key, string hwid)\n"
        "{\n"
        "    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };\n"
        '    http.DefaultRequestHeaders.Add("X-App-Secret", "your-app-secret");\n'
        "\n"
        "    var body = JsonSerializer.Serialize(new {\n"
        '        app_id  = "default",\n'
        "        key,\n"
        "        hwid,\n"
        '        version = "1.0.0",\n'
        "    });\n"
        "\n"
        "    var resp = await http.PostAsync(\n"
        f'        "{_api}/api/v1/verify",\n'
        '        new StringContent(body, Encoding.UTF8, "application/json")\n'
        "    );\n"
        "    resp.EnsureSuccessStatusCode();\n"
        "\n"
        "    using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());\n"
        "    var root = doc.RootElement.Clone();\n"
        '    if (!root.GetProperty("ok").GetBoolean())\n'
        '        throw new Exception($"License rejected: {root.GetProperty(\\"status\\").GetString()}");\n'
        "    return root;\n"
        "}"
    )
    ex_verify_php = (
        "function verifyLicense(string $key, string $hwid): array {\n"
        "    $payload = json_encode([\n"
        "        'app_id'  => 'default',\n"
        "        'key'     => $key,\n"
        "        'hwid'    => $hwid,\n"
        "        'version' => '1.0.0',\n"
        "    ]);\n"
        "\n"
        f"    $ch = curl_init('{_api}/api/v1/verify');\n"
        "    curl_setopt_array($ch, [\n"
        "        CURLOPT_POST           => true,\n"
        "        CURLOPT_POSTFIELDS     => $payload,\n"
        "        CURLOPT_RETURNTRANSFER => true,\n"
        "        CURLOPT_TIMEOUT        => 10,\n"
        "        CURLOPT_HTTPHEADER     => [\n"
        "            'Content-Type: application/json',\n"
        "            'X-App-Secret: your-app-secret',\n"
        "        ],\n"
        "    ]);\n"
        "\n"
        "    $response = curl_exec($ch);\n"
        "    $errno    = curl_errno($ch);\n"
        "    curl_close($ch);\n"
        "    if ($errno) throw new RuntimeException('cURL error: ' . curl_strerror($errno));\n"
        "\n"
        "    $data = json_decode($response, true);\n"
        "    if (!$data['ok'])\n"
        "        throw new RuntimeException('License rejected: ' . $data['status']);\n"
        "    return $data;\n"
        "}"
    )
    ex_verify_go = (
        "package main\n"
        "\n"
        "import (\n"
        '    "bytes"\n'
        '    "encoding/json"\n'
        '    "errors"\n'
        '    "net/http"\n'
        '    "time"\n'
        ")\n"
        "\n"
        "type VerifyRequest struct {\n"
        '    AppID   string `json:"app_id"`\n'
        '    Key     string `json:"key"`\n'
        '    HWID    string `json:"hwid"`\n'
        '    Version string `json:"version"`\n'
        "}\n"
        "\n"
        "type VerifyResponse struct {\n"
        '    OK                bool   `json:"ok"`\n'
        '    Status            string `json:"status"`\n'
        '    ExpiresAt         string `json:"expires_at"`\n'
        '    SubscriptionLevel int    `json:"subscription_level"`\n'
        "}\n"
        "\n"
        "func VerifyLicense(key, hwid string) (*VerifyResponse, error) {\n"
        '    req := VerifyRequest{AppID: "default", Key: key, HWID: hwid, Version: "1.0.0"}\n'
        "    body, _ := json.Marshal(req)\n"
        "\n"
        "    client := &http.Client{Timeout: 10 * time.Second}\n"
        f'    r, _ := http.NewRequest("POST", "{_api}/api/v1/verify", bytes.NewReader(body))\n'
        '    r.Header.Set("Content-Type", "application/json")\n'
        '    r.Header.Set("X-App-Secret", "your-app-secret")\n'
        "\n"
        "    resp, err := client.Do(r)\n"
        "    if err != nil { return nil, err }\n"
        "    defer resp.Body.Close()\n"
        "\n"
        "    var vr VerifyResponse\n"
        "    json.NewDecoder(resp.Body).Decode(&vr)\n"
        "    if !vr.OK { return nil, errors.New(\"license rejected: \" + vr.Status) }\n"
        "    return &vr, nil\n"
        "}"
    )
    ex_heartbeat_python = (
        "import threading, time, requests\n"
        "\n"
        f"API_URL = '{_api}/api/v1/verify'\n"
        "_last_ok: dict | None = None\n"
        "_GRACE_SECONDS = 3600  # allow 1 hour offline before hard-failing\n"
        "\n"
        "def _heartbeat_loop(key: str, hwid: str) -> None:\n"
        "    global _last_ok\n"
        "    while True:\n"
        "        try:\n"
        "            r = requests.post(API_URL, json={\n"
        '                "app_id": "default", "key": key,\n'
        '                "hwid": hwid, "version": "1.0.0",\n'
        "            }, headers={'X-App-Secret': 'your-secret'}, timeout=8)\n"
        "            data = r.json()\n"
        "            if data.get('ok'):\n"
        "                data['_ts'] = time.monotonic()\n"
        "                _last_ok = data\n"
        "            else:\n"
        "                on_rejected(data.get('status', 'unknown'))\n"
        "        except Exception:\n"
        "            if _last_ok:\n"
        "                age = time.monotonic() - _last_ok.get('_ts', 0)\n"
        "                if age > _GRACE_SECONDS:\n"
        "                    on_rejected('offline_grace_expired')\n"
        "        time.sleep(300)  # 5-minute heartbeat\n"
        "\n"
        "def start_heartbeat(key: str, hwid: str) -> None:\n"
        "    threading.Thread(target=_heartbeat_loop, args=(key, hwid),\n"
        "                     daemon=True).start()\n"
        "\n"
        "def on_rejected(status: str) -> None:\n"
        "    print(f'License invalid: {status}')\n"
        "    # disable feature gates, show dialog, or exit"
    )
    ex_subscription_usage = (
        "data = verify_license(key, hwid)\n"
        "level = data.get('subscription_level', 1)\n"
        "\n"
        "FEATURES = {\n"
        "    1: ['basic_scan', 'export_pdf'],\n"
        "    2: ['basic_scan', 'export_pdf', 'batch_mode', 'cloud_sync'],\n"
        "    3: ['basic_scan', 'export_pdf', 'batch_mode', 'cloud_sync',\n"
        "        'api_access', 'white_label'],\n"
        "}\n"
        "unlocked = FEATURES.get(level, FEATURES[1])\n"
        "\n"
        "if 'batch_mode' in unlocked:\n"
        "    run_batch()\n"
        "else:\n"
        "    show_upgrade_prompt(from_level=level, to_level=2)"
    )
    ex_retry_python = (
        "import time, requests\n"
        "\n"
        "def verify_with_retry(key: str, hwid: str, retries: int = 3) -> dict:\n"
        "    last_exc = None\n"
        "    for attempt in range(retries):\n"
        "        try:\n"
        f"            r = requests.post('{_api}/api/v1/verify',\n"
        "                json={'app_id': 'default', 'key': key, 'hwid': hwid},\n"
        "                headers={'X-App-Secret': 'your-secret'},\n"
        "                timeout=8)\n"
        "            r.raise_for_status()\n"
        "            data = r.json()\n"
        "            # A server-side rejection is a real answer — don't retry it\n"
        "            if not data.get('ok') and data.get('status') not in ('connection_error',):\n"
        "                return data\n"
        "            return data\n"
        "        except requests.RequestException as exc:\n"
        "            last_exc = exc\n"
        "            if attempt < retries - 1:\n"
        "                time.sleep(2 ** attempt)  # 1 s, 2 s, 4 s\n"
        "    raise RuntimeError(f'Verify failed after {retries} attempts: {last_exc}')"
    )
    ex_provision_node = (
        "const axios = require('axios');\n"
        "\n"
        f"const PROVISION_URL = '{_api}/api/v1/provision';\n"
        "const TOKEN = process.env.KEYBASE_PROVISION_TOKEN; // never hardcode!\n"
        "\n"
        "async function createKey(orderId, customerId, days = 30) {\n"
        "    const { data } = await axios.post(PROVISION_URL, {\n"
        "        app_id:         'default',\n"
        "        count:          1,\n"
        "        max_devices:    1,\n"
        "        duration_value: days,\n"
        "        duration_unit:  'days',\n"
        "        order_id:       String(orderId),\n"
        "        customer_id:    String(customerId),\n"
        "    }, {\n"
        "        headers: {\n"
        "            'Content-Type':      'application/json',\n"
        f"            '{_prov_hdr}': TOKEN,\n"
        "        },\n"
        "        timeout: 15_000,\n"
        "    });\n"
        "\n"
        "    if (!data.ok) throw new Error(`Provision failed: ${data.status}`);\n"
        "    return data.keys[0]; // the license key string\n"
        "}\n"
        "\n"
        "// In your payment webhook handler:\n"
        "// const key = await createKey(order.id, user.id, 30);\n"
        "// await sendEmail(user.email, key);"
    )
    ex_provision_php = (
        "function createKey(string $orderId, string $customerId, int $days = 30): string {\n"
        "    $payload = json_encode([\n"
        "        'app_id'         => 'default',\n"
        "        'count'          => 1,\n"
        "        'max_devices'    => 1,\n"
        "        'duration_value' => $days,\n"
        "        'duration_unit'  => 'days',\n"
        "        'order_id'       => $orderId,\n"
        "        'customer_id'    => $customerId,\n"
        "    ]);\n"
        "\n"
        f"    $ch = curl_init('{_api}/api/v1/provision');\n"
        "    curl_setopt_array($ch, [\n"
        "        CURLOPT_POST           => true,\n"
        "        CURLOPT_POSTFIELDS     => $payload,\n"
        "        CURLOPT_RETURNTRANSFER => true,\n"
        "        CURLOPT_TIMEOUT        => 15,\n"
        "        CURLOPT_HTTPHEADER     => [\n"
        "            'Content-Type: application/json',\n"
        f"            '{_prov_hdr}: ' . getenv('KEYBASE_PROVISION_TOKEN'),\n"
        "        ],\n"
        "    ]);\n"
        "\n"
        "    $response = curl_exec($ch);\n"
        "    curl_close($ch);\n"
        "    $data = json_decode($response, true);\n"
        "    if (!$data['ok']) throw new RuntimeException('Provision: ' . $data['status']);\n"
        "    return $data['keys'][0];\n"
        "}"
    )
    ex_provision_csharp = (
        "using System.Net.Http;\n"
        "using System.Text;\n"
        "using System.Text.Json;\n"
        "\n"
        "static async Task<string> CreateKeyAsync(string orderId, string customerId, int days = 30)\n"
        "{\n"
        "    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };\n"
        "    http.DefaultRequestHeaders.Add(\n"
        f'        "{_prov_hdr}",\n'
        '        Environment.GetEnvironmentVariable("KEYBASE_PROVISION_TOKEN")!);\n'
        "\n"
        "    var body = JsonSerializer.Serialize(new {\n"
        '        app_id         = "default",\n'
        "        count          = 1,\n"
        "        max_devices    = 1,\n"
        "        duration_value = days,\n"
        '        duration_unit  = "days",\n'
        "        order_id       = orderId,\n"
        "        customer_id    = customerId,\n"
        "    });\n"
        "\n"
        "    var resp = await http.PostAsync(\n"
        f'        "{_api}/api/v1/provision",\n'
        '        new StringContent(body, Encoding.UTF8, "application/json"));\n'
        "    resp.EnsureSuccessStatusCode();\n"
        "\n"
        "    using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());\n"
        "    var root = doc.RootElement.Clone();\n"
        '    if (!root.GetProperty("ok").GetBoolean())\n'
        '        throw new Exception("Provision failed: " + root.GetProperty("status").GetString());\n'
        '    return root.GetProperty("keys")[0].GetString()!;\n'
        "}"
    )
    ex_provision_go = (
        "package main\n"
        "\n"
        "import (\n"
        '    "bytes"; "encoding/json"; "errors"; "fmt"\n'
        '    "net/http"; "os"; "time"\n'
        ")\n"
        "\n"
        "type ProvReq struct {\n"
        '    AppID         string `json:"app_id"`\n'
        '    Count         int    `json:"count"`\n'
        '    MaxDevices    int    `json:"max_devices"`\n'
        '    DurationValue int    `json:"duration_value"`\n'
        '    DurationUnit  string `json:"duration_unit"`\n'
        '    OrderID       string `json:"order_id"`\n'
        '    CustomerID    string `json:"customer_id"`\n'
        "}\n"
        "type ProvResp struct {\n"
        '    OK     bool     `json:"ok"`\n'
        '    Keys   []string `json:"keys"`\n'
        '    Status string   `json:"status"`\n'
        "}\n"
        "\n"
        "func CreateKey(orderID, customerID string, days int) (string, error) {\n"
        '    body, _ := json.Marshal(ProvReq{AppID: "default", Count: 1,\n'
        "        MaxDevices: 1, DurationValue: days, DurationUnit: \"days\",\n"
        "        OrderID: orderID, CustomerID: customerID})\n"
        "\n"
        "    client := &http.Client{Timeout: 15 * time.Second}\n"
        f'    r, _ := http.NewRequest("POST", "{_api}/api/v1/provision",\n'
        "                            bytes.NewReader(body))\n"
        '    r.Header.Set("Content-Type", "application/json")\n'
        f'    r.Header.Set("{_prov_hdr}", os.Getenv("KEYBASE_PROVISION_TOKEN"))\n'
        "\n"
        "    resp, err := client.Do(r)\n"
        "    if err != nil { return \"\", err }\n"
        "    defer resp.Body.Close()\n"
        "\n"
        "    var pr ProvResp\n"
        "    json.NewDecoder(resp.Body).Decode(&pr)\n"
        "    if !pr.OK { return \"\", errors.New(\"provision: \" + pr.Status) }\n"
        "    return pr.Keys[0], nil\n"
        "}\n"
        "// Usage: key, err := CreateKey(orderID, userID, 30)"
    )
    ex_wh_verify_go = (
        "package main\n"
        "\n"
        "import (\n"
        '    "crypto/hmac"\n'
        '    "crypto/sha256"\n'
        '    "encoding/hex"\n'
        '    "io"\n'
        '    "net/http"\n'
        ")\n"
        "\n"
        "func verifySignature(secret string, body []byte, header string) bool {\n"
        "    mac := hmac.New(sha256.New, []byte(secret))\n"
        "    mac.Write(body)\n"
        '    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))\n'
        "    return hmac.Equal([]byte(expected), []byte(header))\n"
        "}\n"
        "\n"
        "func WebhookHandler(w http.ResponseWriter, r *http.Request) {\n"
        "    body, _ := io.ReadAll(r.Body)\n"
        '    sig := r.Header.Get("X-KeyBase-Signature")\n'
        '    if !verifySignature("your-endpoint-secret", body, sig) {\n'
        '        http.Error(w, "unauthorized", http.StatusUnauthorized)\n'
        "        return\n"
        "    }\n"
        "    // process event ...\n"
        "    w.WriteHeader(http.StatusOK)\n"
        "}"
    )
    ex_wh_verify_php = (
        "function verifyWebhookSignature(string $secret, string $body, string $header): bool {\n"
        "    $expected = 'sha256=' . hash_hmac('sha256', $body, $secret);\n"
        "    return hash_equals($expected, $header);\n"
        "}\n"
        "\n"
        "// In your webhook endpoint:\n"
        "$body   = file_get_contents('php://input');\n"
        "$header = $_SERVER['HTTP_X_KEYBASE_SIGNATURE'] ?? '';\n"
        "\n"
        "if (!verifyWebhookSignature('your-endpoint-secret', $body, $header)) {\n"
        "    http_response_code(401); exit('Unauthorized');\n"
        "}\n"
        "\n"
        "$event = json_decode($body, true);\n"
        "switch ($event['event']) {\n"
        "    case 'key.created':  /* send welcome email */  break;\n"
        "    case 'key.expired':  /* suspend user access */ break;\n"
        "    case 'key.activated': /* log new device */     break;\n"
        "}\n"
        "http_response_code(200);"
    )
    ex_wh_verify_csharp = (
        "[ApiController]\n"
        "public class WebhookController : ControllerBase\n"
        "{\n"
        '    [HttpPost("/webhooks/keybase")]\n'
        "    public async Task<IActionResult> Receive()\n"
        "    {\n"
        "        using var ms = new MemoryStream();\n"
        "        await Request.Body.CopyToAsync(ms);\n"
        "        var body = ms.ToArray();\n"
        "\n"
        '        var sig = Request.Headers["X-KeyBase-Signature"].ToString();\n'
        '        if (!VerifySignature("your-endpoint-secret", body, sig))\n'
        "            return Unauthorized();\n"
        "\n"
        "        var json = Encoding.UTF8.GetString(body);\n"
        "        // deserialize and handle event ...\n"
        "        return Ok();\n"
        "    }\n"
        "\n"
        "    private static bool VerifySignature(string secret, byte[] body, string header)\n"
        "    {\n"
        "        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));\n"
        "        var hash     = hmac.ComputeHash(body);\n"
        '        var expected = "sha256=" + Convert.ToHexString(hash).ToLowerInvariant();\n'
        "        return CryptographicOperations.FixedTimeEquals(\n"
        "            Encoding.ASCII.GetBytes(expected),\n"
        "            Encoding.ASCII.GetBytes(header));\n"
        "    }\n"
        "}"
    )
    ex_discord_setup = (
        "1. Open Discord → Server Settings → Integrations → Webhooks\n"
        "2. Click 'New Webhook', choose a channel, copy the URL.\n"
        "   Format: https://discord.com/api/webhooks/{ID}/{TOKEN}\n"
        "\n"
        "3. In KeyBase → App → Webhooks tab:\n"
        "   - Paste the Discord webhook URL as the Endpoint URL.\n"
        "   - Click Settings → choose the Discord preset.\n"
        "   - The body template is auto-filled with a rich embed.\n"
        "   - Save. Click 'Send test' — you should see a card in the channel.\n"
        "\n"
        "No custom headers are needed for Discord.\n"
        "Discord accepts the Content-Type: application/json the preset sets."
    )
    ex_ntfy_setup = (
        "ntfy.sh is a free, no-account push service (also self-hostable).\n"
        "\n"
        "1. Pick a topic name, e.g. 'keybase-myapp-alerts-xyz42'\n"
        "   (use a long random name — it acts as a secret).\n"
        "\n"
        "2. Endpoint URL: https://ntfy.sh/keybase-myapp-alerts-xyz42\n"
        "\n"
        "3. In KeyBase endpoint settings → ntfy.sh preset.\n"
        "   The preset sets:\n"
        "     Content-Type: text/plain\n"
        "     Custom headers:\n"
        "       Title: KeyBase · {{event}}   ← filled per event\n"
        "       Priority: default\n"
        "       Tags: key,keybase\n"
        "\n"
        "4. Subscribe on phone: install ntfy app → add topic by URL\n"
        "   Or in browser: https://ntfy.sh/keybase-myapp-alerts-xyz42\n"
        "\n"
        "Self-hosted ntfy: change URL to your own server, same preset works."
    )
    ex_telegram_setup = (
        "1. Open @BotFather → /newbot → copy the token\n"
        "   Token looks like: 7412345678:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "\n"
        "2. Get your chat_id:\n"
        "   a. Add the bot to a group or start a private chat.\n"
        "   b. Send any message to the bot.\n"
        "   c. Open in browser:\n"
        "      https://api.telegram.org/bot{YOUR_TOKEN}/getUpdates\n"
        "   d. Find 'chat':{'id': ...} in the response.\n"
        "      Groups have a negative ID, e.g. -1001234567890.\n"
        "\n"
        "3. Endpoint URL:\n"
        "   https://api.telegram.org/bot{YOUR_TOKEN}/sendMessage\n"
        "\n"
        "4. Choose the Telegram preset in endpoint settings.\n"
        "   Edit the body template and replace YOUR_CHAT_ID with your actual id.\n"
        "\n"
        "5. The preset uses parse_mode: 'Markdown' so *bold* and `code` render.\n"
        "   Test with the Send test button."
    )
    ex_slack_setup = (
        "Slack Incoming Webhook URL format:\n"
        "  https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/XXXXXXXX\n"
        "\n"
        "1. Go to https://api.slack.com/apps → Create New App → From scratch\n"
        "2. Incoming Webhooks → Activate → Add New Webhook to Workspace\n"
        "3. Choose a channel → Allow → copy the Webhook URL.\n"
        "\n"
        "4. In KeyBase endpoint settings:\n"
        "   - Paste the Slack URL as Endpoint URL.\n"
        "   - Choose the Slack preset.\n"
        "   - The preset uses Block Kit blocks[] format.\n"
        "   - No custom headers needed.\n"
        "   - Send test → you should see a formatted message in the channel."
    )
    ex_idempotency = (
        "Every delivery has a unique 'delivery_id' in the payload.\n"
        "Store it in your database and check before processing:\n"
        "\n"
        "import hashlib\n"
        "from functools import lru_cache\n"
        "\n"
        "def process_webhook(event: dict, db) -> None:\n"
        "    delivery_id = event.get('delivery_id')\n"
        "    if not delivery_id:\n"
        "        return\n"
        "    # Check idempotency — skip duplicate deliveries\n"
        "    if db.execute('SELECT 1 FROM processed_webhooks WHERE id = ?',\n"
        "                  (delivery_id,)).fetchone():\n"
        "        return  # already processed\n"
        "\n"
        "    # Do the real work\n"
        "    handle_event(event)\n"
        "\n"
        "    # Mark as processed\n"
        "    db.execute('INSERT INTO processed_webhooks (id) VALUES (?)', (delivery_id,))"
    )

    # ── copy-paste client snippet variables ───────────────────────────────────
    _api_is_https = _api.startswith("https://")
    _api_netloc = (_api.split("://", 1)[1] if "://" in _api else _api).split("/")[0]
    _api_cpp_host = _api_netloc.rsplit(":", 1)[0] if ":" in _api_netloc else _api_netloc
    try:
        _api_cpp_port = int(_api_netloc.rsplit(":", 1)[1]) if ":" in _api_netloc else (443 if _api_is_https else 80)
    except (ValueError, IndexError):
        _api_cpp_port = 8080
    _api_cpp_https_str = "true" if _api_is_https else "false"

    ex_snippet_python = """# keybase_license.py — drop this into your project root
# No extra dependencies — stdlib only.
import hashlib, json, platform, socket, threading, time, urllib.request, urllib.error, uuid

API_URL    = "__API__/api/v1/verify"
APP_ID     = "default"
APP_SECRET = ""      # X-App-Secret header — leave empty if not set in config
VERSION    = "1.0.0"
HEARTBEAT  = 300     # seconds between heartbeat checks
GRACE      = 3600    # seconds allowed offline before hard-fail

def _build_hwid():
    parts = [socket.gethostname(), platform.system(), platform.machine(), str(uuid.getnode())]
    return hashlib.sha256("|".join(p for p in parts if p).encode()).hexdigest()

HWID = _build_hwid()   # stable per-machine fingerprint, computed once at startup

def _post(key):
    body = json.dumps({"app_id": APP_ID, "key": key, "hwid": HWID, "version": VERSION})
    req  = urllib.request.Request(
        API_URL, body.encode(),
        {"Content-Type": "application/json", "X-App-Secret": APP_SECRET})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

_MSGS = {
    "not_found":      "Invalid license key.",
    "expired":        "License expired. Please renew.",
    "device_limit":   "Device limit reached. Contact support to reset devices.",
    "banned_key":     "Access denied.",
    "banned_hwid":    "Access denied.",
    "banned_ip":      "Access denied from this network.",
    "banned_country": "Not available in your region.",
    "paused":         "License suspended. Contact support.",
    "revoked":        "License permanently revoked.",
}

class LicenseError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status

def verify(key):
    data = _post(key)
    if not data.get("ok"):
        st = data.get("status", "unknown")
        raise LicenseError(st, _MSGS.get(st, "License check failed: " + st))
    return data

_last_ok, _lock = 0.0, threading.Lock()

def _hb_loop(key):
    global _last_ok
    while True:
        time.sleep(HEARTBEAT)
        try:
            d = _post(key)
            if d.get("ok"):
                with _lock: _last_ok = time.monotonic()
            else:
                _on_fail(d.get("status", "unknown")); return
        except Exception:
            with _lock: age = time.monotonic() - _last_ok
            if age > GRACE: _on_fail("offline_grace_expired"); return

def _on_fail(status):
    raise SystemExit("License invalid: " + status)

def start_heartbeat(key):
    global _last_ok
    _last_ok = time.monotonic()
    threading.Thread(target=_hb_loop, args=(key,), daemon=True).start()

if __name__ == "__main__":
    import sys
    key = input("Enter license key: ").strip()
    try:
        info = verify(key)
        print("OK  expires={}  level={}".format(
            info.get("expires_at", "lifetime"), info.get("subscription_level", 1)))
        start_heartbeat(key)
        input("Running — press Enter to exit.")
    except LicenseError as e:
        print("Error: " + str(e)); sys.exit(1)
    except Exception as e:
        print("Network error: " + str(e)); sys.exit(1)""".replace("__API__", _api)

    ex_snippet_csharp = """// KeyBaseLicense.cs — paste into your project (.NET 6+, no NuGet packages)
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

public static class KeyBaseLicense
{
    const string ApiUrl     = "__API__/api/v1/verify";
    const string AppId      = "default";
    const string AppSecret  = "";   // X-App-Secret — leave empty if not configured
    const string AppVersion = "1.0.0";
    static readonly TimeSpan Hb    = TimeSpan.FromMinutes(5);
    static readonly TimeSpan Grace = TimeSpan.FromHours(1);
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };
    static DateTime _lastOk = DateTime.MinValue;

    public static string Hwid()
    {
        var raw = string.Join("|",
            Environment.MachineName,
            Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "",
            Environment.OSVersion.Platform.ToString());
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLower();
    }

    public static async Task<JsonElement> VerifyAsync(string key)
    {
        var body = JsonSerializer.Serialize(
            new { app_id = AppId, key, hwid = Hwid(), version = AppVersion });
        using var req = new HttpRequestMessage(HttpMethod.Post, ApiUrl)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (AppSecret.Length > 0)
            req.Headers.Add("X-App-Secret", AppSecret);
        var res = await Http.SendAsync(req);
        res.EnsureSuccessStatusCode();
        using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync());
        var root = doc.RootElement.Clone();
        bool ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
        if (!ok)
        {
            var st = root.TryGetProperty("status", out var stEl)
                ? stEl.GetString() ?? "unknown" : "unknown";
            throw new LicenseException(st switch
            {
                "not_found"      => "Invalid license key.",
                "expired"        => "License expired. Please renew.",
                "device_limit"   => "Device limit reached. Contact support.",
                "banned_key"     => "Access denied.",
                "banned_hwid"    => "Access denied.",
                "banned_ip"      => "Access denied from this network.",
                "banned_country" => "Not available in your region.",
                "paused"         => "License suspended. Contact support.",
                "revoked"        => "License permanently revoked.",
                _                => $"License check failed ({st})."
            }, st);
        }
        _lastOk = DateTime.UtcNow;
        return root;
    }

    public static void StartHeartbeat(string key, Action<string>? onFail = null)
    {
        new Thread(async () => {
            while (true) {
                await Task.Delay(Hb);
                try { await VerifyAsync(key); }
                catch (LicenseException ex) { (onFail ?? Fail)(ex.Status); return; }
                catch { if (DateTime.UtcNow - _lastOk > Grace)
                    { (onFail ?? Fail)("offline_grace_expired"); return; } }
            }
        }) { IsBackground = true, Name = "keybase-hb" }.Start();
    }

    static void Fail(string st)
    { Console.Error.WriteLine("License invalid: " + st); Environment.Exit(1); }
}

public class LicenseException : Exception
{
    public string Status { get; }
    public LicenseException(string msg, string status) : base(msg) => Status = status;
}

/* Usage:
 *   var info = await KeyBaseLicense.VerifyAsync(licenseKey);
 *   Console.WriteLine("OK expires: " + info.GetProperty("expires_at"));
 *   KeyBaseLicense.StartHeartbeat(licenseKey);
 */""".replace("__API__", _api)

    ex_snippet_cpp = r"""// keybase_license.hpp — Windows only, no external dependencies
// Linker: winhttp.lib + bcrypt.lib  (both included in the Windows SDK)
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <stdexcept>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace keybase {

// ── Config ─── match these to your api.public_base_url in config.yml ─────────
const wchar_t* API_HOST  = L"__CPP_HOST__";
INTERNET_PORT  API_PORT  = __CPP_PORT__;
const wchar_t* API_PATH  = L"/api/v1/verify";
const bool     API_HTTPS = __CPP_HTTPS__;
const char*    APP_ID      = "default";
const char*    APP_SECRET  = "";   // X-App-Secret — leave empty if not configured
const char*    APP_VERSION = "1.0.0";

// ── HWID: stable MachineGuid from Windows registry ───────────────────────────
inline std::string hwid() {
    char buf[64] = {};
    DWORD sz = sizeof(buf);
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography", 0,
        KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
        RegQueryValueExA(hk, "MachineGuid", nullptr, nullptr, (LPBYTE)buf, &sz);
        RegCloseKey(hk);
    }
    if (strnlen(buf, sizeof(buf)) < 8) {
        DWORD len = sizeof(buf); GetComputerNameA(buf, &len);
    }
    BCRYPT_ALG_HANDLE alg;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    DWORD hashLen = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLen, sizeof(DWORD), &cb, 0);
    std::vector<BYTE> hash(hashLen);
    BCRYPT_HASH_HANDLE hh;
    BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(hh, (PBYTE)buf, (ULONG)strnlen(buf, sizeof(buf)), 0);
    BCryptFinishHash(hh, hash.data(), hashLen, 0);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(alg, 0);
    std::string hex;
    for (auto b : hash) { char h[3]; snprintf(h, 3, "%02x", b); hex += h; }
    return hex;
}

struct LicenseError : std::runtime_error {
    std::string status;
    LicenseError(const std::string& m, const std::string& s)
        : std::runtime_error(m), status(s) {}
};

inline std::string _post(const std::string& body, const std::string& xhdr = "") {
    HINTERNET ses = WinHttpOpen(L"KeyBase/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    HINTERNET con = WinHttpConnect(ses, API_HOST, API_PORT, 0);
    HINTERNET req = WinHttpOpenRequest(con, L"POST", API_PATH, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        API_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    std::string hdrs = "Content-Type: application/json\r\n" + xhdr;
    std::wstring wh(hdrs.begin(), hdrs.end());
    WinHttpSendRequest(req, wh.c_str(), (DWORD)wh.size(),
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(req, nullptr);
    std::string out; DWORD av = 0;
    while (WinHttpQueryDataAvailable(req, &av) && av) {
        std::vector<char> buf(av + 1); DWORD rd = 0;
        WinHttpReadData(req, buf.data(), av, &rd); out.append(buf.data(), rd);
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
    return out;
}

inline bool _jbool(const std::string& j, const char* k) {
    return j.find(std::string("\"") + k + "\":true") != std::string::npos;
}
inline std::string _jstr(const std::string& j, const char* k) {
    std::string pf = std::string("\"") + k + "\":\"";
    auto p = j.find(pf); if (p == std::string::npos) return "";
    p += pf.size(); auto e = j.find('"', p);
    return e == std::string::npos ? "" : j.substr(p, e - p);
}

// Returns expires_at string ("" = lifetime). Throws LicenseError on rejection.
inline std::string verify(const std::string& key) {
    auto h = hwid();
    std::string body =
        "{\"app_id\":\"" + std::string(APP_ID) + "\","
        "\"key\":\""     + key + "\","
        "\"hwid\":\""    + h + "\","
        "\"version\":\"" + APP_VERSION + "\"}";
    std::string xh;
    if (APP_SECRET[0]) xh = std::string("X-App-Secret: ") + APP_SECRET + "\r\n";
    auto resp = _post(body, xh);
    if (!_jbool(resp, "ok")) {
        auto st = _jstr(resp, "status");
        std::string msg;
        if      (st == "not_found")      msg = "Invalid license key.";
        else if (st == "expired")        msg = "License expired. Please renew.";
        else if (st == "device_limit")   msg = "Device limit reached. Contact support.";
        else if (st == "banned_key"  ||
                 st == "banned_hwid" ||
                 st == "banned_ip")      msg = "Access denied.";
        else if (st == "banned_country") msg = "Not available in your region.";
        else if (st == "paused")         msg = "License suspended.";
        else if (st == "revoked")        msg = "License permanently revoked.";
        else                             msg = "License check failed: " + st;
        throw LicenseError(msg, st);
    }
    return _jstr(resp, "expires_at");
}

// Call after verify() — re-checks on interval, exits process if rejected.
inline void start_heartbeat(const std::string& key,
    void(*on_fail)(const std::string&) = nullptr, DWORD iv = 300000)
{
    struct Ctx { std::string key; void(*on_fail)(const std::string&); DWORD iv; };
    auto* ctx = new Ctx{key, on_fail, iv};
    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* c = (Ctx*)p; DWORD since_ok = 0;
        while (true) {
            Sleep(c->iv);
            try { verify(c->key); since_ok = 0; }
            catch (const LicenseError& e) {
                if (c->on_fail) c->on_fail(e.status);
                else { MessageBoxA(nullptr,e.what(),"License Error",MB_ICONERROR); ExitProcess(1); }
                break;
            } catch (...) {
                since_ok += c->iv;
                if (since_ok > 3600000) {
                    if (c->on_fail) c->on_fail("offline_grace_expired"); break;
                }
            }
        }
        delete c; return 0;
    }, ctx, 0, nullptr);
}

} // namespace keybase

/* Usage:
 *   #include "keybase_license.hpp"
 *   try {
 *       auto exp = keybase::verify(key);
 *       keybase::start_heartbeat(key);
 *   } catch (const keybase::LicenseError& e) {
 *       MessageBoxA(nullptr, e.what(), "License Error", MB_ICONERROR);
 *       return 1;
 *   }
 */""".replace("__CPP_HOST__", _api_cpp_host).replace("__CPP_PORT__", str(_api_cpp_port)).replace("__CPP_HTTPS__", _api_cpp_https_str)

    ex_snippet_node = """// keybase_license.js — Node.js 14+, no external dependencies
'use strict';
const crypto = require('node:crypto');
const http   = require('node:http');
const https  = require('node:https');
const os     = require('node:os');

const API_URL     = '__API__/api/v1/verify';
const APP_ID      = 'default';
const APP_SECRET  = '';      // X-App-Secret header — leave empty if not configured
const APP_VERSION = '1.0.0';
const HEARTBEAT_MS = 300_000;    // 5 minutes
const GRACE_MS     = 3_600_000;  // 1 hour offline grace

function hwid() {
  const parts = [
    os.hostname(), os.platform(), os.arch(),
    (os.cpus()[0] || {}).model || '',
  ].filter(Boolean);
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

const HWID = hwid();

const MSGS = {
  not_found:      'Invalid license key.',
  expired:        'License expired. Please renew.',
  device_limit:   'Device limit reached. Contact support.',
  banned_key:     'Access denied.',
  banned_hwid:    'Access denied.',
  banned_ip:      'Access denied from this network.',
  banned_country: 'Not available in your region.',
  paused:         'License suspended. Contact support.',
  revoked:        'License permanently revoked.',
};

class LicenseError extends Error {
  constructor(status, msg) {
    super(msg); this.name = 'LicenseError'; this.status = status;
  }
}

function _post(key) {
  return new Promise((resolve, reject) => {
    const url  = new URL(API_URL);
    const body = JSON.stringify({ app_id: APP_ID, key, hwid: HWID, version: APP_VERSION });
    const lib  = url.protocol === 'https:' ? https : http;
    const req  = lib.request({
      hostname: url.hostname,
      port:     Number(url.port) || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...(APP_SECRET ? { 'X-App-Secret': APP_SECRET } : {}),
      },
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Bad JSON')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10_000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

async function verify(key) {
  const d = await _post(key);
  if (!d.ok) {
    const st = d.status || 'unknown';
    throw new LicenseError(st, MSGS[st] || 'License check failed: ' + st);
  }
  return d;
}

let _lastOkMs = 0;

function startHeartbeat(key, onFail) {
  _lastOkMs = Date.now();
  function tick() {
    _post(key).then((d) => {
      if (d.ok) { _lastOkMs = Date.now(); }
      else {
        const fn = onFail || function(s) { console.error('License invalid:', s); process.exit(1); };
        fn(d.status); return;
      }
      setTimeout(tick, HEARTBEAT_MS);
    }).catch(() => {
      if (Date.now() - _lastOkMs > GRACE_MS) {
        const fn = onFail || function(s) { console.error('License invalid:', s); process.exit(1); };
        fn('offline_grace_expired'); return;
      }
      setTimeout(tick, HEARTBEAT_MS);
    });
  }
  setTimeout(tick, HEARTBEAT_MS);
}

module.exports = { verify, startHeartbeat, hwid: () => HWID, LicenseError };

/* Usage:
 *   const { verify, startHeartbeat, LicenseError } = require('./keybase_license');
 *   try {
 *     const info = await verify(licenseKey);
 *     console.log('OK expires:', info.expires_at || 'lifetime');
 *     startHeartbeat(licenseKey);
 *   } catch (e) {
 *     if (e instanceof LicenseError) { console.error(e.message); process.exit(1); }
 *     throw e;
 *   }
 */""".replace("__API__", _api)

    ex_snippet_java = r"""// KeyBaseLicense.java — Java 17+, no external dependencies
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public final class KeyBaseLicense {

    static final String API_URL     = "__API__/api/v1/verify";
    static final String APP_ID      = "default";
    static final String APP_SECRET  = "";       // leave empty if not configured
    static final String APP_VERSION = "1.0.0";
    static final Duration TIMEOUT      = Duration.ofSeconds(10);
    static final Duration HEARTBEAT    = Duration.ofMinutes(5);
    static final Duration GRACE_PERIOD = Duration.ofHours(1);
    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    static final AtomicLong lastOkMs = new AtomicLong(0);

    private KeyBaseLicense() {}

    public static String hwid() {
        try {
            String raw = System.getenv().getOrDefault("COMPUTERNAME", "unknown")
                + "|" + System.getProperty("os.name") + "|" + System.getProperty("os.arch");
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { return "fallback"; }
    }

    public static class LicenseException extends RuntimeException {
        public final String status;
        LicenseException(String msg, String st) { super(msg); status = st; }
    }

    static String friendly(String st) {
        return switch (st) {
            case "not_found"      -> "Invalid license key.";
            case "expired"        -> "License expired. Please renew.";
            case "device_limit"   -> "Device limit reached. Contact support.";
            case "banned_key", "banned_hwid", "banned_ip" -> "Access denied.";
            case "banned_country" -> "Not available in your region.";
            case "paused"         -> "License suspended.";
            case "revoked"        -> "License permanently revoked.";
            default               -> "License check failed (" + st + ").";
        };
    }

    static String extract(String json, String key) {
        String k = "\"" + key + "\":\"";
        int i = json.indexOf(k); if (i < 0) return "";
        int s = i + k.length(), e = json.indexOf('"', s);
        return e < 0 ? "" : json.substring(s, e);
    }

    public static String verify(String key) {
        String body = String.format(
            "{\"app_id\":\"%s\",\"key\":\"%s\",\"hwid\":\"%s\",\"version\":\"%s\"}",
            APP_ID, key, hwid(), APP_VERSION);
        var req = HttpRequest.newBuilder().uri(URI.create(API_URL)).timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));
        if (!APP_SECRET.isEmpty()) req.header("X-App-Secret", APP_SECRET);
        try {
            var res = HTTP.send(req.build(), HttpResponse.BodyHandlers.ofString());
            var json = res.body();
            if (!json.contains("\"ok\":true")) {
                var st = extract(json, "status");
                throw new LicenseException(friendly(st.isEmpty() ? "unknown" : st), st);
            }
            lastOkMs.set(System.currentTimeMillis());
            return extract(json, "expires_at");   // "" = lifetime key
        } catch (LicenseException e) { throw e; }
        catch (Exception e) { throw new RuntimeException("Network error: " + e.getMessage(), e); }
    }

    public static void startHeartbeat(String key, Consumer<String> onFail) {
        var svc = Executors.newSingleThreadScheduledExecutor(r -> {
            var t = new Thread(r, "keybase-hb"); t.setDaemon(true); return t;
        });
        svc.scheduleAtFixedRate(() -> {
            try { verify(key); }
            catch (LicenseException e) { onFail.accept(e.status); svc.shutdown(); }
            catch (Exception e) {
                if (System.currentTimeMillis() - lastOkMs.get() > GRACE_PERIOD.toMillis()) {
                    onFail.accept("offline_grace_expired"); svc.shutdown();
                }
            }
        }, HEARTBEAT.toSeconds(), HEARTBEAT.toSeconds(), TimeUnit.SECONDS);
    }
}

/* Usage:
 *   try {
 *       String exp = KeyBaseLicense.verify(licenseKey);
 *       System.out.println("OK expires: " + (exp.isEmpty() ? "lifetime" : exp));
 *       KeyBaseLicense.startHeartbeat(licenseKey, st -> {
 *           JOptionPane.showMessageDialog(null, "License invalid: " + st);
 *           System.exit(1);
 *       });
 *   } catch (KeyBaseLicense.LicenseException e) {
 *       JOptionPane.showMessageDialog(null, e.getMessage());
 *       System.exit(1);
 *   }
 */""".replace("__API__", _api)

    ex_snippet_lua = """-- keybase_license.lua — Garry's Mod / DarkRP client-side
-- Place in lua/autorun/client/ or include() from your loader.
-- Uses the built-in HTTP() function — no extra libraries needed.

local API_URL     = "__API__/api/v1/verify"
local APP_ID      = "default"
local APP_SECRET  = ""        -- leave empty if not set in config
local APP_VERSION = "1.0.0"
local HEARTBEAT   = 300       -- seconds between heartbeat checks
local GRACE       = 3600      -- seconds offline before hard-fail

local MSGS = {
    not_found      = "Invalid license key.",
    expired        = "License expired.",
    device_limit   = "Device limit reached. Contact support.",
    banned_key     = "Access denied.",
    banned_hwid    = "Access denied.",
    banned_ip      = "Access denied from this network.",
    banned_country = "Not available in your region.",
    paused         = "License suspended.",
    revoked        = "License permanently revoked.",
}

local function get_hwid()
    local id64 = IsValid(LocalPlayer()) and LocalPlayer():SteamID64() or "0"
    local raw  = id64 .. "|" .. system.GetCountry() .. "|gmod"
    return (util.SHA256 or util.MD5)(raw)
end

local last_ok  = 0
local hb_timer = "kb_hb_" .. tostring(math.random(1000000))

local function raw_post(key, cb)
    HTTP({
        method  = "POST",
        url     = API_URL,
        body    = util.TableToJSON({
            app_id  = APP_ID,
            key     = key,
            hwid    = get_hwid(),
            version = APP_VERSION,
        }),
        type    = "application/json",
        headers = APP_SECRET ~= "" and { ["X-App-Secret"] = APP_SECRET } or {},
        success = function(_, body)
            cb(nil, util.JSONToTable(body) or {})
        end,
        failed  = function(err)
            cb(tostring(err), nil)
        end,
    })
end

local function verify(key, cb)
    raw_post(key, function(err, data)
        if err then cb("Network error: " .. err, nil); return end
        if not data.ok then
            local st  = data.status or "unknown"
            local msg = MSGS[st] or ("License rejected: " .. st)
            cb(msg, data); return
        end
        last_ok = CurTime()
        cb(nil, data)
    end)
end

local function start_heartbeat(key, on_fail)
    timer.Create(hb_timer, HEARTBEAT, 0, function()
        raw_post(key, function(err, data)
            if err then
                if CurTime() - last_ok > GRACE then
                    timer.Remove(hb_timer); on_fail("offline_grace_expired")
                end
                return
            end
            if not data.ok then
                timer.Remove(hb_timer); on_fail(data.status or "unknown"); return
            end
            last_ok = CurTime()
        end)
    end)
end

return { verify = verify, start_heartbeat = start_heartbeat }

--[[ Usage:
  local kb = include("keybase/keybase_license.lua")
  kb.verify(YOUR_LICENSE_KEY, function(err, data)
      if err then
          notification.AddLegacy(err, NOTIFY_ERROR, 5); return
      end
      local level = data.subscription_level or 1
      notification.AddLegacy("License OK! Level: " .. level, NOTIFY_GENERIC, 3)
      kb.start_heartbeat(YOUR_LICENSE_KEY, function(st)
          notification.AddLegacy("License lost: " .. st, NOTIFY_ERROR, 10)
      end)
  end)
--]]""".replace("__API__", _api)

    body = f"""
<section class="panel help-hero">
  <div class="help-hero-main">
    <span class="eyebrow">Key Base Help Center</span>
    <h1>FAQ & Setup Guide</h1>
    <p>Clear steps for config, API integration, Cloudflare, apps, keys, bans, security, and common errors.</p>
    <label class="help-search-label">Search FAQ<input data-faq-search placeholder="Search config, Cloudflare, country bans, keys, errors..."></label>
  </div>
  <div class="help-hero-actions">
    <a class="button primary" href="/admin/api">{icon_label("api-console", "API Console")}</a>
    <a class="button" href="#config">{icon_label("settings", "Config")}</a>
  </div>
</section>
<div class="help-layout">
  <aside class="panel help-toc">
    <h2>On This Page</h2>
    <a href="#quick-start">Quick Start</a>
    <a href="#config">Config</a>
    <a href="#api">API Integration</a>
    <a href="#api" data-api-docs-tab-link="client" onclick="document.querySelector('[data-api-docs-tab=client]').click()" style="padding-left:20px;font-size:12px;color:var(--muted)">↳ Client API</a>
    <a href="#api" data-api-docs-tab-link="server" onclick="document.querySelector('[data-api-docs-tab=server]').click()" style="padding-left:20px;font-size:12px;color:var(--muted)">↳ Server API</a>
    <a href="#apps-keys">Apps & Keys</a>
    <a href="#bans-geo">Bans & Geo</a>
    <a href="#webhooks">Webhooks</a>
    <a href="#security">Security</a>
    <a href="#troubleshooting">Troubleshooting</a>
  </aside>
  <main class="help-content">
    <p class="notice faq-empty" data-faq-empty hidden>No matching FAQ items. Try another word.</p>
    <section id="quick-start" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Quick Start</h2><p>Get the service running without guessing where things live.</p></div></div>
      <details class="faq-item" open data-faq-item>
        <summary>What do I do on the first run?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Start the server with <code>run.bat</code> on Windows or <code>sh ./run.sh</code> on Linux/macOS.</li>
            <li>Open <code>{html_escape(admin_base_url)}/admin</code>.</li>
            <li>Create the admin account. Username is saved once; future login asks only for the password.</li>
            <li>Create an app, open it, then create keys from the Keys tab.</li>
            <li>Put <code>/api/v1/verify</code> in your client.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Useful start and check commands</summary>
        <div class="faq-body">
          <div class="doc-grid">
            <div><h3>Windows PowerShell</h3><pre>{html_escape(windows_commands)}</pre></div>
            <div><h3>Linux / macOS shell</h3><pre>{html_escape(linux_commands)}</pre></div>
          </div>
          <p>Host and port are controlled by <code>config.yml</code> — change <code>server.host</code> and <code>server.port</code> there.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I know the server is alive?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open <code>{html_escape(api_base_url)}/api/v1/health</code>.</li>
            <li>If it returns JSON, the API process is alive.</li>
            <li>Open <code>{html_escape(admin_base_url)}/admin</code> for the admin panel.</li>
            <li>If the browser cannot connect, check the terminal logs and the port commands above.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Which setup path should I choose?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Goal</th><th>Recommended path</th></tr>
            <tr><td>Testing on one PC</td><td>Use local-only config, keep everything on <code>127.0.0.1</code>.</td></tr>
            <tr><td>Testing on home LAN</td><td>Bind API to <code>0.0.0.0</code>, keep admin local or VPN-only.</td></tr>
            <tr><td>Public API</td><td>Put HTTPS/CDN/reverse proxy in front, keep Key Base private behind it.</td></tr>
            <tr><td>Country bans</td><td>Use Cloudflare country headers or a trusted proxy/GeoIP source.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Which files matter?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>File</th><th>Purpose</th></tr>
            <tr><td><code>config.yml</code></td><td>Host, port, Cloudflare, proxy, API rate limits, session settings, data path.</td></tr>
            <tr><td><code>.env</code></td><td>Admin username, password hash, session secret. Keep private.</td></tr>
            <tr><td><code>data/keybase.sqlite3</code></td><td>Apps, keys, bans, activations, events.</td></tr>
            <tr><td><code>run.bat</code> / <code>run.sh</code></td><td>Cross-platform start scripts.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>When do I need to restart?</summary>
        <div class="faq-body">
          <p>Restart after changing bind host, port, data path, Cloudflare/proxy trust, or installed dependencies. UI-only theme changes and app/key/bans do not need restart.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What should I back up?</summary>
        <div class="faq-body">
          <p>Back up these three things together: <code>data/keybase.sqlite3</code>, <code>.env</code>, and <code>config.yml</code>. The database alone is not enough because admin auth and runtime config live outside it.</p>
        </div>
      </details>
    </section>
    <section id="config" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Config</h2><p>Use small focused snippets. Do not paste random full configs unless you know why.</p></div><a class="button" href="/admin/config">{icon_label("settings", "Open Config")}</a></div>
      <details class="faq-item" data-faq-item>
        <summary>What does each important config field do?</summary>
        <div class="faq-body">
          <table>
            <tr><th>Field</th><th>What it controls</th><th>Restart?</th></tr>
            <tr><td><code>server.mode</code></td><td><code>combined</code> means one listener serves admin + API together. <code>split</code> means one local admin listener and one separate API listener inside the same process.</td><td>Yes</td></tr>
            <tr><td><code>server.host</code></td><td>Address uvicorn binds to. Use <code>127.0.0.1</code> for private/local, <code>0.0.0.0</code> for LAN/public bind.</td><td>Yes</td></tr>
            <tr><td><code>server.port</code></td><td>Port for the built-in combined admin/API server.</td><td>Yes</td></tr>
            <tr><td><code>server.admin_host</code> / <code>server.admin_port</code></td><td>Admin bind used only in <code>split</code> mode. Good for keeping the panel local-only.</td><td>Yes</td></tr>
            <tr><td><code>server.api_host</code> / <code>server.api_port</code></td><td>API bind used only in <code>split</code> mode. Good when clients should hit a different port or interface.</td><td>Yes</td></tr>
            <tr><td><code>server.allow_remote_admin</code></td><td>Allows admin panel from non-local IPs. Keep false unless protected by VPN/proxy.</td><td>Yes</td></tr>
            <tr><td><code>server.trust_proxy_headers</code></td><td>Trusts proxy IP headers for real client IP. Enable only behind your proxy/CDN.</td><td>Yes</td></tr>
            <tr><td><code>cloudflare.enabled</code></td><td>Enables Cloudflare-style country/IP handling.</td><td>Yes</td></tr>
            <tr><td><code>api.accepted_ip_headers</code></td><td>Ordered header list for the real client IP when proxy trust is on. Good values: <code>CF-Connecting-IP</code>, <code>True-Client-IP</code>, <code>Fly-Client-IP</code>, <code>X-Real-IP</code>, <code>X-Forwarded-For</code>, <code>Forwarded</code>.</td><td>Yes</td></tr>
            <tr><td><code>api.allow_payload_ip_fallback</code></td><td>Allows JSON <code>ip</code> to become the effective ban/rate-limit IP when the connection itself is only local/proxy-private.</td><td>Yes</td></tr>
            <tr><td><code>api.public_base_url</code></td><td>Public URL clients should call. Used for docs/operator clarity.</td><td>No for docs, yes for deployment expectations</td></tr>
            <tr><td><code>protection.anti_mode</code></td><td><code>off</code> disables protection scoring, <code>warn</code> logs and returns warnings without blocking, and <code>strict</code> blocks only when combined risk score reaches 71+.</td><td>No</td></tr>
            <tr><td><code>protection.anti_vm</code> / <code>anti_vpn</code> / <code>anti_proxy</code> / <code>anti_debug</code></td><td>Enable individual protection modules. Keep warn mode until reviewed in Protection Monitor.</td><td>No</td></tr>
            <tr><td><code>backup.auto_enabled</code> / <code>backup.interval_minutes</code> / <code>backup.keep_last</code></td><td>Controls the automatic zip backup worker, its schedule, and how many archives stay on disk.</td><td>No for the page, new schedule applies live</td></tr>
            <tr><td><code>provisioning.enabled</code></td><td>Turns on the private server-to-server key creation endpoint for your website/backend.</td><td>Yes</td></tr>
            <tr><td><code>provisioning.shared_token</code></td><td>Secret header token your website must send to create new keys.</td><td>Yes</td></tr>
            <tr><td><code>security.password_min_length</code></td><td>Minimum admin password length. The app never allows below 6.</td><td>Yes</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I whitelist trusted proxy IPs from .env?</summary>
        <div class="faq-body">
          <p>Use this when you trust forwarded headers only from your own reverse proxy, tunnel, or Cloudflare connector machine.</p>
          <pre>KEYBASE_TRUST_PROXY=1
KEYBASE_PROXY_WHITELIST=127.0.0.1,10.0.0.0/8</pre>
          <p>If the whitelist is set, Key Base ignores forwarded IP/HTTPS headers unless the direct connection comes from one of those allowed proxy IPs or CIDR ranges.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What does mode: combined really mean?</summary>
        <div class="faq-body">
          <p><code>mode: combined</code> means there is one HTTP listener, one host, and one port. The admin panel and the client API both live there together.</p>
          <ol class="steps">
            <li>In the default local example both live on the same address — admin at <code>{html_escape(admin_base_url)}/admin</code>, API at <code>{html_escape(api_base_url)}/api/v1/verify</code>.</li>
            <li>This is the easiest mode for local testing and single-machine setups.</li>
          </ol>
          <p>Use this when you do not need to separate local admin traffic from client API traffic.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What does mode: split really mean?</summary>
        <div class="faq-body">
          <p><code>mode: split</code> opens two listeners in the same process. The key point: <b>admin API (provision/keys/bans) lives on the admin listener</b>, so it stays local automatically — no firewall rule needed to protect it.</p>
          <table class="mini-table">
            <tr><th>Listener</th><th>Routes served</th><th>Typical bind</th></tr>
            <tr><td>Admin (local)</td><td><code>/admin/*</code>, <code>/api/v1/provision</code>, <code>/api/v1/keys/*</code>, <code>/api/v1/bans/*</code></td><td><code>127.0.0.1:8080</code></td></tr>
            <tr><td>API (public)</td><td><code>/api/v1/verify</code>, <code>/api/v1/check</code>, <code>/api/v1/activate</code>, <code>/api/v1/health</code></td><td><code>0.0.0.0:1488</code></td></tr>
          </table>
          <ol class="steps">
            <li>Set <code>server.admin_host: 127.0.0.1</code> + <code>server.admin_port: 8080</code> — panel + admin API, local only.</li>
            <li>Set <code>server.api_host: 0.0.0.0</code> + <code>server.api_port: 1488</code> — client verify, public.</li>
            <li>Point <code>admin.public_base_url</code> to the admin address (browser access).</li>
            <li>Point <code>api.public_base_url</code> to the public API address (what clients call).</li>
          </ol>
          <pre>{html_escape(split_local_config)}</pre>
          <p>Your client app calls port 1488. Your backend server (for provisioning) calls port 8080 from localhost. End users can never reach the admin panel or admin API directly.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do separate admin/api ports work in practice?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Field</th><th>Who reaches it</th><th>What lives there</th></tr>
            <tr><td><code>admin_host: 127.0.0.1</code>, <code>admin_port: 8080</code></td><td>Same machine only</td><td>Admin panel + Admin API (provision, keys, bans)</td></tr>
            <tr><td><code>api_host: 0.0.0.0</code>, <code>api_port: 1488</code></td><td>Internet / LAN</td><td>Client verify, check, activate, health</td></tr>
          </table>
          <p>In this setup your backend server (website, bot) calls <code>http://127.0.0.1:8080/api/v1/provision</code> to create keys. End users' apps call <code>https://api.example.com/api/v1/verify</code>. The admin API is never reachable from outside the machine.</p>
          <p>If both listeners need to be remote (e.g. admin on a VPN address, API public), set both hosts to the appropriate bind address and protect the admin port with a firewall or VPN.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Safe config editing workflow</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open the API page from the sidebar.</li>
            <li>Click the config button and change only the block you need.</li>
            <li>Save with admin password confirmation.</li>
            <li>If you changed host, port, proxy, Cloudflare, security, or data path, restart the server.</li>
            <li>Open <code>/api/v1/health</code> and then test <code>/api/v1/verify</code>.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Commands to validate config.yml</summary>
        <div class="faq-body">
          <pre>{html_escape(config_check_commands)}</pre>
          <p>If the YAML command fails, fix indentation first. YAML uses spaces, not tabs, and nested fields must stay under the right parent block.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I choose host and port?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Value</th><th>Use it when</th></tr>
            <tr><td><code>host: 127.0.0.1</code></td><td>Only this machine or a local reverse proxy should reach the app.</td></tr>
            <tr><td><code>host: 0.0.0.0</code></td><td>Other machines need to connect directly through LAN/public network.</td></tr>
            <tr><td><code>port: 8080</code></td><td>Default easy local port.</td></tr>
            <tr><td><code>port: 80/443</code></td><td>Usually handled by nginx/Caddy/Cloudflare, not directly by Key Base.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What URL should my client use?</summary>
        <div class="faq-body">
          <p>A safe local example URL is <code>{html_escape(api_base_url)}/api/v1/verify</code>. If your clients reach a different address, set <code>api.public_base_url</code> to that LAN IP, HTTPS domain, or tunnel hostname.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Which config values should I touch first?</summary>
        <div class="faq-body">
          <table>
            <tr><th>Situation</th><th>Change</th><th>Do not forget</th></tr>
            <tr><td>Local dev</td><td><code>server.host: 127.0.0.1</code>, <code>server.port: 8080</code></td><td>Client URL uses localhost.</td></tr>
            <tr><td>Local admin + separate API port</td><td><code>server.mode: split</code>, <code>admin_port: 8080</code>, <code>api_port: 1488</code></td><td>Clients must call port 1488, not 8080.</td></tr>
            <tr><td>LAN testing</td><td><code>server.host: 0.0.0.0</code>, <code>api.public_base_url: http://192.168.1.50:8080</code></td><td>Open firewall only if trusted.</td></tr>
            <tr><td>Cloudflare tunnel</td><td><code>server.host: 127.0.0.1</code>, <code>cloudflare.enabled: true</code></td><td>Tunnel points to localhost app.</td></tr>
            <tr><td>Reverse proxy</td><td><code>server.trust_proxy_headers: true</code>, public URLs use HTTPS</td><td>Block direct public access to port 8080.</td></tr>
            <tr><td>More login security</td><td><code>security.session_hours</code>, <code>security.confirm_minutes</code>, <code>security.login_attempts_per_10m</code></td><td>Password minimum is never allowed below 6.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Do environment variables override config.yml?</summary>
        <div class="faq-body">
          <p>Real shell environment variables can override runtime values. The generated <code>.env</code> is for admin auth and secrets; normal host/port settings should live in <code>config.yml</code>.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Firewall commands for LAN testing</summary>
        <div class="faq-body">
          <div class="doc-grid">
            <div><h3>Windows</h3><pre>{html_escape(firewall_windows)}</pre></div>
            <div><h3>Linux ufw</h3><pre>{html_escape(firewall_linux)}</pre></div>
          </div>
          <p>Do not open the admin panel to the whole internet. For public use, expose only through HTTPS proxy/tunnel and keep admin protected.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Local-only setup</summary>
        <div class="faq-body">
          <p>Use this when Key Base runs only on your own PC and clients are local tests.</p>
          <pre>{html_escape(local_config)}</pre>
          <p><b>Result:</b> admin and API are reachable only from the same machine on <code>127.0.0.1:8080</code>.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>LAN setup</summary>
        <div class="faq-body">
          <p>Use this for devices on your network. Keep admin local unless you intentionally protect remote admin access.</p>
          <pre>{html_escape(lan_config)}</pre>
          <p><b>Important:</b> open firewall port <code>8080</code> only for trusted machines.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Cloudflare setup</summary>
        <div class="faq-body">
          <p>Cloudflare should terminate HTTPS and forward to your private Key Base process. This makes country bans reliable through <code>CF-IPCountry</code>.</p>
          <pre>{html_escape(cloudflare_config)}</pre>
          <ol class="steps">
            <li>Point DNS/proxy to your reverse proxy or tunnel.</li>
            <li>Keep Key Base bound to <code>127.0.0.1</code> when using a local tunnel/proxy.</li>
            <li>Enable <code>cloudflare.enabled</code> and <code>server.trust_proxy_headers</code>.</li>
            <li>Test one verify request and check Events for country/source.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Cloudflare with split mode</summary>
        <div class="faq-body">
          <p>Use this when the browser admin panel must stay local but the public API sits behind Cloudflare.</p>
          <pre>{html_escape(split_cloudflare_config)}</pre>
          <p>Cloudflare should hit the API listener, not your admin listener. Keep the admin listener private unless you also protect it separately.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Cloudflare Tunnel checklist</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Keep Key Base on <code>127.0.0.1:8080</code>.</li>
            <li>Point the tunnel service to <code>http://127.0.0.1:8080</code>.</li>
            <li>Set <code>api.public_base_url</code> to your HTTPS tunnel hostname.</li>
            <li>Enable <code>server.trust_proxy_headers</code> and <code>cloudflare.enabled</code>.</li>
            <li>Verify an app key and check Events for the real country value.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Reverse proxy setup</summary>
        <div class="faq-body">
          <p>Use this for nginx, Caddy, cloudflared, or any HTTPS gateway in front of the Python app.</p>
          <pre>{html_escape(proxy_config)}</pre>
          <p><b>Rule:</b> only enable <code>trust_proxy_headers</code> if untrusted clients cannot send headers directly to Key Base.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>nginx and Caddy examples</summary>
        <div class="faq-body">
          <div class="doc-grid">
            <div><h3>nginx</h3><pre>{html_escape(nginx_example)}</pre></div>
            <div><h3>Caddy</h3><pre>{html_escape(caddy_example)}</pre></div>
          </div>
          <p>After adding a proxy, set <code>api.public_base_url</code> and <code>admin.public_base_url</code> to the HTTPS domain users will actually open.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Linux systemd service example</summary>
        <div class="faq-body">
          <pre>{html_escape(systemd_example)}</pre>
          <ol class="steps">
            <li>Put the file at <code>/etc/systemd/system/keybase.service</code>.</li>
            <li>Run <code>sudo systemctl daemon-reload</code>.</li>
            <li>Run <code>sudo systemctl enable --now keybase</code>.</li>
            <li>Check logs with <code>sudo journalctl -u keybase -f</code>.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I enable site-to-site key creation?</summary>
        <div class="faq-body">
          <p>Enable the private provisioning endpoint when your website or backend should create a new key right after a payment or order.</p>
          <pre>{html_escape(provisioning_config)}</pre>
          <ol class="steps">
            <li>Set <code>provisioning.enabled: true</code>.</li>
            <li>Change <code>provisioning.shared_token</code> to a real private secret.</li>
            <li>Keep that token only on your website/backend, never in the public client.</li>
            <li>Call <code>/api/v1/provision</code> or <code>/api/v1/keys/provision</code> from your server after purchase.</li>
          </ol>
        </div>
      </details>
    </section>
    <section id="api" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>API Integration</h2><p>Client API is called by your app on end-user machines. Server API is called only by your backend.</p></div></div>
      <div class="api-docs-tab-bar" role="tablist" aria-label="API Integration tabs">
        <button class="api-docs-tab-btn active" id="api-docs-tab-client" type="button" data-api-docs-tab="client" role="tab" aria-selected="true">Client API</button>
        <button class="api-docs-tab-btn" id="api-docs-tab-server" type="button" data-api-docs-tab="server" role="tab" aria-selected="false">Server API</button>
      </div>

      <div class="api-docs-panel" data-api-docs-panel="client" role="tabpanel" aria-labelledby="api-docs-tab-client">
        <details class="faq-item" open data-faq-item>
          <summary>Client API overview — endpoints and when to call them</summary>
          <div class="faq-body">
            <p>These endpoints are called by your <b>licensed application running on the end-user's machine</b>. They do not require admin credentials. Never call provisioning or admin-only endpoints from client code.</p>
            <table class="mini-table">
              <tr><th>Method</th><th>Path</th><th>Purpose</th><th>Call when</th></tr>
              <tr><td>GET</td><td><code>/api/v1/health</code></td><td>Health check</td><td>Startup, before the first verify, to confirm the server is reachable.</td></tr>
              <tr><td>POST</td><td><code>/api/v1/verify</code></td><td>License verify + HWID bind</td><td>Startup activation and periodic heartbeat.</td></tr>
              <tr><td>POST</td><td><code>/api/v1/check</code></td><td>Alias for verify</td><td>Same as verify — use either name.</td></tr>
              <tr><td>POST</td><td><code>/api/v1/activate</code></td><td>Alias for verify</td><td>Same as verify — use either name.</td></tr>
            </table>
            <p class="muted" style="margin-top:8px">All three verify endpoints behave identically. Pick the name that matches your mental model.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Health check — GET /api/v1/health</summary>
          <div class="faq-body">
            <p>Call this before the first verify at startup to confirm the API server is alive. Returns JSON with server state and version.</p>
            <pre>curl {html_escape(api_base_url)}/api/v1/health</pre>
            <p>Typical response:</p>
            <pre>{{
  "ok": true,
  "status": "running",
  "version": "3.0.0",
  "uptime_seconds": 12345
}}</pre>
            <ul class="doc-list">
              <li>If this call fails (network error, non-200), the API process is not running or not reachable.</li>
              <li>Check the API console in the admin panel or the terminal for the API log output.</li>
              <li>With split mode, use the API port, not the admin port.</li>
            </ul>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Verify request — what to send (POST /api/v1/verify)</summary>
          <div class="faq-body">
            <p>The JSON body your client must POST:</p>
            <pre>{html_escape(json.dumps(sample, indent=2))}</pre>
            <table class="mini-table" style="margin-top:10px">
              <tr><th>Field</th><th>Type</th><th>Required</th><th>Notes</th></tr>
              <tr><td><code>app_id</code></td><td>string</td><td>Yes</td><td>Must match an Application created in the admin panel. Case-sensitive.</td></tr>
              <tr><td><code>key</code></td><td>string</td><td>Yes</td><td>Normalized to uppercase automatically. Spaces and dashes are stripped. Any case accepted.</td></tr>
              <tr><td><code>hwid</code></td><td>string</td><td>Strongly recommended</td><td>Stable per-machine fingerprint. Min 8 chars. Reject blank, "unknown", "test", "0000".</td></tr>
              <tr><td><code>country</code></td><td>string</td><td>Optional</td><td>ISO 3166-1 alpha-2 (e.g. "US", "DE"). Useful for local tests. In production, prefer CDN headers.</td></tr>
              <tr><td><code>version</code></td><td>string</td><td>Optional</td><td>Your client version string. Logged in Events for support and debugging.</td></tr>
              <tr><td><code>ip</code></td><td>string</td><td>Optional</td><td>Client's own public IP. Used for IP bans when <code>allow_payload_ip_fallback</code> is on and the connection is local.</td></tr>
              <tr><td><code>client_hash</code></td><td>string</td><td>Optional</td><td>SHA-256 of the client binary. Checked if integrity hash verification is enabled in App Settings.</td></tr>
              <tr><td><code>build_id</code></td><td>string</td><td>Optional</td><td>Build identifier, e.g. "win-x64-1.0.0". Logged for support.</td></tr>
              <tr><td><code>fingerprint</code></td><td>object</td><td>Recommended for browser clients</td><td>Browser fingerprint from <code>/api/v1/fingerprint.js</code>. Feeds WebGL, timezone, language, screen, hardware, audio, canvas, headless, and automation scoring.</td></tr>
              <tr><td><code>behavior</code></td><td>object</td><td>Optional</td><td>Mouse, click, dwell-time, and entropy signals. You can send it separately or inside <code>fingerprint.behavior</code>.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Verify response — every field explained</summary>
          <div class="faq-body">
            <div class="doc-grid">
              <div><h3>Accepted</h3><pre>{html_escape(json.dumps(success, indent=2))}</pre></div>
              <div><h3>Rejected</h3><pre>{html_escape(json.dumps(failure, indent=2))}</pre></div>
            </div>
            <table class="mini-table" style="margin-top:12px">
              <tr><th>Field</th><th>Type</th><th>When present</th><th>What it means</th></tr>
              <tr><td><code>ok</code></td><td>bool</td><td>Always</td><td><code>true</code> = allowed. <code>false</code> = denied. Always check this first.</td></tr>
              <tr><td><code>status</code></td><td>string</td><td>Always</td><td>Machine-readable result code. See status table below.</td></tr>
              <tr><td><code>message</code></td><td>string</td><td>Always</td><td>Human-readable explanation. Do not rely on exact wording — use <code>status</code> for logic.</td></tr>
              <tr><td><code>subscription_level</code></td><td>integer</td><td>When ok=true</td><td>Tier assigned to this key (e.g. 1=Basic, 2=Premium). Use to gate features.</td></tr>
              <tr><td><code>country</code></td><td>string</td><td>When resolved</td><td>ISO country code of the request origin as seen by the server. Use for display only.</td></tr>
              <tr><td><code>expires_at</code></td><td>string</td><td>When ok=true and not lifetime</td><td>ISO 8601 UTC expiry timestamp. Show to user or warn before expiry.</td></tr>
              <tr><td><code>activated_at</code></td><td>string</td><td>When activated</td><td>When the key was first activated (HWID binding).</td></tr>
              <tr><td><code>duration_seconds</code></td><td>integer</td><td>When has expiry</td><td>Total license duration in seconds.</td></tr>
              <tr><td><code>max_devices</code></td><td>integer</td><td>When ok=true</td><td>Maximum HWIDs this key can bind.</td></tr>
              <tr><td><code>devices_used</code></td><td>integer</td><td>When ok=true</td><td>Current number of bound HWIDs. Useful for "N of M devices used" display.</td></tr>
              <tr><td><code>server_time</code></td><td>string</td><td>Always</td><td>Current server UTC time. Compare with client clock to detect large skew.</td></tr>
              <tr><td><code>session_token</code></td><td>string</td><td>Signed requests only</td><td>Short-lived token returned on first valid signed activation. Re-send as <code>X-KeyBase-Session</code>.</td></tr>
              <tr><td><code>protection_warning</code></td><td>bool</td><td>Score 41+ or warn-mode would-block</td><td><code>true</code> when Protection Monitor saw elevated combined risk but verification was allowed.</td></tr>
              <tr><td><code>would_block_in_strict</code></td><td>bool</td><td>Warn mode only, score 71+</td><td><code>true</code> means this request would be rejected if <code>anti_mode</code> were <code>strict</code>.</td></tr>
              <tr><td><code>protection</code></td><td>object</td><td>When Protection Monitor is enabled</td><td>Risk score, reason codes, score action, score reasons, fingerprint hash, and IP intelligence source names.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>All status codes — what they mean and what to do</summary>
          <div class="faq-body">
            <table class="mini-table">
              <tr><th>Status</th><th>ok</th><th>Cause</th><th>Recommended action</th></tr>
              <tr><td><code>valid</code></td><td>true</td><td>Key accepted.</td><td>Allow access. Cache response for heartbeat.</td></tr>
              <tr><td><code>not_found</code></td><td>false</td><td>Key text does not exist or wrong <code>app_id</code>.</td><td>Show "invalid license key" message. Let user re-enter.</td></tr>
              <tr><td><code>expired</code></td><td>false</td><td>Key passed its expiry date.</td><td>Show "license expired" and link to renewal.</td></tr>
              <tr><td><code>device_limit</code></td><td>false</td><td>All HWID slots filled.</td><td>Tell user to contact support. Admin can reset devices.</td></tr>
              <tr><td><code>banned_key</code></td><td>false</td><td>This key text is banned.</td><td>Generic "access denied" — do not reveal it is banned.</td></tr>
              <tr><td><code>banned_hwid</code></td><td>false</td><td>This device fingerprint is banned.</td><td>Generic "access denied" — avoid revealing HWID was flagged.</td></tr>
              <tr><td><code>banned_ip</code></td><td>false</td><td>Request IP is banned.</td><td>Generic "access denied".</td></tr>
              <tr><td><code>banned_country</code></td><td>false</td><td>Country is geo-blocked.</td><td>Show "service not available in your region".</td></tr>
              <tr><td><code>paused</code></td><td>false</td><td>Admin paused the key temporarily.</td><td>"License temporarily suspended. Contact support."</td></tr>
              <tr><td><code>disabled</code></td><td>false</td><td>Admin disabled the key.</td><td>"License disabled. Contact support."</td></tr>
              <tr><td><code>revoked</code></td><td>false</td><td>Key permanently burned.</td><td>"License revoked." No renewal path.</td></tr>
              <tr><td><code>app_not_found</code></td><td>false</td><td><code>app_id</code> does not exist.</td><td>Developer error — check the app_id in your code.</td></tr>
              <tr><td><code>signature_invalid</code></td><td>false</td><td>Signed request HMAC mismatch.</td><td>Check signing logic, APP_SECRET, and field order.</td></tr>
              <tr><td><code>replay_detected</code></td><td>false</td><td>Nonce was already used.</td><td>Generate a fresh random nonce per request.</td></tr>
              <tr><td><code>clock_skew</code></td><td>false</td><td>Timestamp too far from server time.</td><td>Sync client clock. Max skew is usually 5 minutes.</td></tr>
              <tr><td><code>session_invalid</code></td><td>false</td><td>Session token expired or forged.</td><td>Re-run the full signed activation to get a fresh token.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>HWID generation — stable device fingerprint rules</summary>
          <div class="faq-body">
            <p>HWID must be a <b>stable, per-machine string</b> that does not change on reboot or normal app restart. It should identify the device, not the current launch.</p>
            <ul class="doc-list">
              <li>Use a stable OS/device identifier and hash it before sending.</li>
              <li>Minimum length is 8 characters. SHA-256 hex output is ideal.</li>
              <li>Never send blank, null, <code>unknown</code>, <code>test</code>, random UUID-per-run, or timestamps.</li>
              <li>For local testing, reuse one fixed test HWID so repeated runs do not burn extra device slots.</li>
              <li>Changing HWID means a new device slot. Reset devices from the admin panel only when intended.</li>
            </ul>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>HWID binding — exactly what happens on each call</summary>
          <div class="faq-body">
            <p>HWID binding is automatic through <code>/api/v1/verify</code>. There is no separate endpoint.</p>
            <table class="mini-table">
              <tr><th>Scenario</th><th>Result</th><th>Explanation</th></tr>
              <tr><td>First call from new device, slots available</td><td><code>valid</code> + HWID saved</td><td>The HWID is added to the key's device list. devices_used increases by 1.</td></tr>
              <tr><td>Repeat call from already-bound HWID</td><td><code>valid</code></td><td>Recognised device. No slot consumed.</td></tr>
              <tr><td>New device, all slots full</td><td><code>device_limit</code></td><td>HWID not saved. Admin must reset devices to allow a new bind.</td></tr>
              <tr><td>After admin resets devices</td><td><code>valid</code> + HWID saved fresh</td><td>All old bindings cleared, new binding starts from zero.</td></tr>
            </table>
            <p style="margin-top:8px">Design tip: set <code>max_devices = 1</code> for single-seat licenses. Set it higher (e.g. 3) for family or team plans. Let the verify response <code>devices_used</code> / <code>max_devices</code> drive your "N of M devices" UI. For local testing, reuse one stable test HWID per install so repeated runs do not burn extra slots.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Heartbeat pattern — keep license valid while the app runs</summary>
          <div class="faq-body">
            <p>Send a verify request in a background thread every 5–30 minutes while your app runs. This detects expiry, bans, and revocations without the user restarting.</p>
            <p><b>Offline grace period:</b> when the server is unreachable, allow the user to keep working for a limited time (e.g. 1–24 hours) using the last-known-good cached response. After the grace expires, re-verify before allowing further use.</p>
            <p><b>Recommended intervals:</b></p>
            <table class="mini-table">
              <tr><th>Product type</th><th>Interval</th><th>Grace period</th></tr>
              <tr><td>Security tool / loader</td><td>Every 5 minutes</td><td>0 hours (no offline allowed)</td></tr>
              <tr><td>SaaS desktop app</td><td>Every 15 minutes</td><td>1–4 hours</td></tr>
              <tr><td>Offline-capable tool</td><td>Every 30 minutes</td><td>24–72 hours</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Retry with back-off — handle network errors without spamming</summary>
          <div class="faq-body">
            <p>Network errors are different from license rejections. A rejection (<code>ok: false</code>) is a final answer — do not retry it. A network error means the server was unreachable — retry with exponential back-off.</p>
            <p>Recommended behavior: retry network failures after 2s, 5s, then 15s. Do not retry invalid, expired, banned, or device-limit responses.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Subscription levels — unlock feature tiers based on the key</summary>
          <div class="faq-body">
            <p>The verify response always includes <code>subscription_level</code> (integer). Map that number to your own feature flags in the application.</p>
            <p>Configure levels inside the selected application's <b>Subscriptions</b> tab. The numeric ID is permanent; only the display name can change. Use IDs 1–99.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>curl example — verify a key from the terminal</summary>
          <div class="faq-body"><pre>{html_escape(curl_example)}</pre></div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Signed request + session token — maximum hardening</summary>
          <div class="faq-body">
            <p>Enable <b>Require signed requests</b> and <b>Require session token</b> in App Settings for the strongest client-side protection.</p>
            <ul class="doc-list">
              <li>The client signs each request with HMAC-SHA256 using the App Secret.</li>
              <li>The server verifies the signature and rejects requests with invalid or replayed nonces.</li>
              <li>On first successful signed verify, the server returns a <code>session_token</code>.</li>
              <li>Re-send the token as <code>X-KeyBase-Session</code> on heartbeats to skip full re-signing.</li>
              <li>Note: the App Secret is still visible in the client binary if extracted — signing prevents replay attacks but does not prevent a sophisticated attacker from reading the secret.</li>
            </ul>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Client-side request headers — full reference</summary>
          <div class="faq-body">
            <table class="mini-table">
              <tr><th>Header</th><th>Required?</th><th>What it does</th></tr>
              <tr><td><code>Content-Type: application/json</code></td><td>Yes</td><td>Always. Server will not parse the body without it.</td></tr>
              <tr><td><code>X-App-Secret</code></td><td>If configured</td><td>Optional per-app secret. Enable "Require App Secret" in App Settings. Visible in client binary.</td></tr>
              <tr><td><code>X-KeyBase-Timestamp</code></td><td>Signed requests</td><td>Unix epoch seconds at request time. Used to detect replay and clock skew.</td></tr>
              <tr><td><code>X-KeyBase-Nonce</code></td><td>Signed requests</td><td>Unique random value per request. Never reuse — reuse triggers <code>replay_detected</code>.</td></tr>
              <tr><td><code>X-KeyBase-Signature</code></td><td>Signed requests</td><td>HMAC-SHA256 signature of the canonical request fields. See signing docs.</td></tr>
              <tr><td><code>X-KeyBase-Session</code></td><td>Session tokens</td><td>Returned token from prior signed activation. Replaces re-signing on heartbeats.</td></tr>
              <tr><td><code>X-Client-Hash</code></td><td>Integrity checks</td><td>SHA-256 hex of your client binary. Verified against allow-list in App Settings.</td></tr>
              <tr><td><code>X-Client-Flags</code></td><td>Optional</td><td>Comma-separated risk signals from the client (e.g. "debug,vm"). Feeds Protection Monitor.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Integration checklist — before you ship</summary>
          <div class="faq-body">
            <ul class="doc-list">
              <li>Generate HWID from multiple stable hardware identifiers — do not use hostname alone.</li>
              <li>Verify on startup before allowing any feature access.</li>
              <li>Start a heartbeat thread that re-verifies every 5–30 minutes.</li>
              <li>Handle <code>ok: false</code> gracefully — show a user-friendly message, log the status, exit or disable features.</li>
              <li>Handle network errors separately from license rejections — allow a configurable offline grace period.</li>
              <li>Never expose or log the App Secret in user-facing output.</li>
              <li>On update/reinstall, the HWID should remain stable — test that reinstalling does not reset the binding.</li>
              <li>Test all rejection statuses locally before launch: expired, device_limit, banned_key.</li>
            </ul>
          </div>
        </details>
      </div>

      <div class="api-docs-panel" data-api-docs-panel="server" hidden role="tabpanel" aria-labelledby="api-docs-tab-server">
        <details class="faq-item" open data-faq-item>
          <summary>Server API overview — all endpoints</summary>
          <div class="faq-body">
            <p>The Server API is called by <b>your own backend server or website</b> — never by end-user machines. All endpoints require the private provisioning token in the configured header.</p>
            <table class="mini-table">
              <tr><th>Method</th><th>Path</th><th>What it does</th></tr>
              <tr><td>GET</td><td><code>/api/v1/keys/info</code></td><td>Get key details, status, bound devices, IP history</td></tr>
              <tr><td>POST</td><td><code>/api/v1/provision</code></td><td>Create one or more keys (also: <code>/api/v1/keys/provision</code>)</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/extend</code></td><td>Change key duration / expiry date</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/suspend</code></td><td>Pause key (reversible)</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/resume</code></td><td>Un-pause a suspended key</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/revoke</code></td><td>Permanently revoke key (irreversible)</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/delete</code></td><td>Delete key from database entirely</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/reset-devices</code></td><td>Clear all HWID bindings so key can activate on new machines</td></tr>
              <tr><td>POST</td><td><code>/api/v1/keys/reset-ip</code></td><td>Clear IP history and IP drift counter</td></tr>
              <tr><td>POST</td><td><code>/api/v1/bans/add</code></td><td>Add IP / HWID / country ban (app-level or global)</td></tr>
              <tr><td>POST</td><td><code>/api/v1/bans/remove</code></td><td>Remove an existing ban by kind + value</td></tr>
            </table>
            <p style="margin-top:8px">All endpoints use the same provisioning token — no separate admin token needed. Enable provisioning in config.yml first.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Step 1 — enable provisioning in config.yml</summary>
          <div class="faq-body">
            <p>Provisioning is disabled by default. Enable it by adding this block to <code>config.yml</code> and restarting:</p>
            <pre>{html_escape(provisioning_config)}</pre>
            <table class="mini-table" style="margin-top:10px">
              <tr><th>Option</th><th>Default</th><th>What it controls</th></tr>
              <tr><td><code>enabled</code></td><td>false</td><td>Master switch. Must be true to accept provisioning requests.</td></tr>
              <tr><td><code>header_name</code></td><td>X-Provision-Token</td><td>The HTTP header your backend sends with the token.</td></tr>
              <tr><td><code>shared_token</code></td><td>—</td><td>The secret token value. Use a long random string (32+ chars).</td></tr>
              <tr><td><code>rate_limit_per_minute</code></td><td>10</td><td>Max provision requests per minute from any single IP.</td></tr>
              <tr><td><code>require_https</code></td><td>false</td><td>Reject plain HTTP provisioning requests. Enable in production.</td></tr>
              <tr><td><code>default_prefix</code></td><td>KB</td><td>Key prefix used when <code>prefix</code> is not specified in the request.</td></tr>
              <tr><td><code>default_max_devices</code></td><td>1</td><td>Per-key device limit when <code>max_devices</code> is not in the request.</td></tr>
              <tr><td><code>default_duration_value</code></td><td>30</td><td>Duration when not specified in the request.</td></tr>
              <tr><td><code>default_duration_unit</code></td><td>days</td><td>Unit for the default duration.</td></tr>
              <tr><td><code>max_batch_size</code></td><td>100</td><td>Maximum number of keys per single provision call.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Step 2 — provisioning request fields</summary>
          <div class="faq-body">
            <table class="mini-table">
              <tr><th>Field</th><th>Type</th><th>Required</th><th>Meaning</th></tr>
              <tr><td><code>app_id</code></td><td>string</td><td>Yes</td><td>Which application owns the new key(s). Must exist in admin.</td></tr>
              <tr><td><code>count</code></td><td>integer</td><td>No</td><td>How many keys to create. Default 1. Capped by <code>max_batch_size</code>.</td></tr>
              <tr><td><code>prefix</code></td><td>string</td><td>No</td><td>Key prefix, e.g. "PRO". Falls back to config default.</td></tr>
              <tr><td><code>max_devices</code></td><td>integer</td><td>No</td><td>HWID slots per key. Default from config.</td></tr>
              <tr><td><code>duration_value</code></td><td>integer</td><td>No</td><td>Duration number. Pair with <code>duration_unit</code>.</td></tr>
              <tr><td><code>duration_unit</code></td><td>string</td><td>No</td><td><code>days</code>, <code>weeks</code>, <code>months</code>, or <code>lifetime</code>.</td></tr>
              <tr><td><code>subscription_level</code></td><td>integer</td><td>No</td><td>Tier to assign (e.g. 2 for Premium). Returned in verify response.</td></tr>
              <tr><td><code>note</code></td><td>string</td><td>No</td><td>Internal note saved with the key. Max 500 chars.</td></tr>
              <tr><td><code>order_id</code></td><td>string</td><td>No</td><td>Your order/invoice reference. Appended to note, searchable in admin.</td></tr>
              <tr><td><code>customer_id</code></td><td>string</td><td>No</td><td>Your user/customer ID. Appended to note, searchable in admin.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Step 3 — provisioning response</summary>
          <div class="faq-body">
            <pre>{html_escape(json.dumps(provisioning_success, indent=2))}</pre>
            <table class="mini-table" style="margin-top:10px">
              <tr><th>Field</th><th>What it contains</th></tr>
              <tr><td><code>ok</code></td><td><code>true</code> when keys were created successfully.</td></tr>
              <tr><td><code>status</code></td><td><code>provisioned</code> on success. Error code on failure.</td></tr>
              <tr><td><code>keys</code></td><td>Array of key strings. Length equals <code>count</code> requested.</td></tr>
              <tr><td><code>count</code></td><td>Number of keys created.</td></tr>
              <tr><td><code>duration_label</code></td><td>Human label, e.g. "30 days" or "Lifetime".</td></tr>
              <tr><td><code>app_id</code></td><td>The application that owns the new keys.</td></tr>
            </table>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Authentication — how to send the token</summary>
          <div class="faq-body">
            <p>Every Server API request must include the provisioning token in the configured header. The header name is set by <code>provisioning.header_name</code> (default: <code>X-Provision-Token</code>).</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/... \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"..."}}'</pre>
            <p>Wrong or missing token returns <code>403 bad_provision_token</code>. The token is set in <code>provisioning.shared_token</code> in config.yml, or more safely via the <code>KEYBASE_PROVISION_TOKEN</code> environment variable.</p>
            <p><b>Split mode:</b> in <code>server.mode: split</code>, all Server API endpoints (<code>/api/v1/provision</code>, <code>/api/v1/keys/*</code>, <code>/api/v1/bans/*</code>) are served only on the <b>admin listener</b> (local port). Client verify (<code>/api/v1/verify</code>) stays on the public API listener. Your backend server must call the admin listener address, not the public API address.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>GET /api/v1/keys/info — get key details</summary>
          <div class="faq-body">
            <p>Returns full key state: status, expiry, devices, IP history, subscription level.</p>
            <pre>curl "{html_escape(api_base_url)}/api/v1/keys/info?key=KB-XXXX-XXXX&amp;app_id=default" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE"</pre>
            <p>Response includes: <code>status</code>, <code>expires_at</code>, <code>activated_at</code>, <code>devices_used</code>, <code>max_devices</code>, <code>subscription_level</code>, <code>note</code>, and a <code>devices</code> array with each bound HWID + IP.</p>
            <p>Returns <code>404 not_found</code> if the key does not exist in that app.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/provision — create keys</summary>
          <div class="faq-body">
            <p>Creates one or more license keys. Use after a successful payment or subscription activation.</p>
            <pre>{html_escape(provisioning_curl)}</pre>
            <p>Batch: set <code>count</code> to create multiple keys at once (max = <code>provisioning.max_batch_size</code>):</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/provision \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","count":50,"duration_value":30,"duration_unit":"days","subscription_level":2,"order_id":"ORDER-123"}}'</pre>
            <p>Response: <code>{{"ok":true,"keys":["KB-XXXX-XXXX"],"count":1,"duration_label":"30 days"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/extend — change duration or expiry</summary>
          <div class="faq-body">
            <p>Changes the key's duration. If the key is already activated, the new expiry is recalculated from activation date. If not yet activated, the new duration applies on first activation.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/extend \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX","duration_value":90,"duration_unit":"days"}}'</pre>
            <p>Units: <code>days</code>, <code>weeks</code>, <code>months</code>, <code>lifetime</code>. Fires a <code>key.extended</code> webhook with old and new expiry values.</p>
            <p>Response: <code>{{"ok":true,"status":"extended","expires_at":"2026-09-01T00:00:00Z","duration_label":"90 days"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/suspend — pause key (reversible)</summary>
          <div class="faq-body">
            <p>Sets key status to <code>paused</code>. Client verify returns <code>{{"ok":false,"status":"paused"}}</code>. Fully reversible with <code>/keys/resume</code>. Use for payment dispute / chargeback pending state.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/suspend \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX","reason":"payment disputed"}}'</pre>
            <p><code>reason</code> is optional, logged in events. Response: <code>{{"ok":true,"status":"suspended","key":"KB-XXXX-XXXX"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/resume — un-pause a suspended key</summary>
          <div class="faq-body">
            <p>Sets key status back to <code>active</code>. Use when a dispute is resolved or a temporary block is lifted.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/resume \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX"}}'</pre>
            <p>Response: <code>{{"ok":true,"status":"resumed","key":"KB-XXXX-XXXX"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/revoke — permanently revoke key</summary>
          <div class="faq-body">
            <p>Sets key status to <code>revoked</code>. Client verify returns <code>{{"ok":false,"status":"revoked"}}</code>. This is <b>irreversible via API</b> — only the admin panel can undo it. Use for fraud, ToS violation, chargeback confirmed.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/revoke \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX","reason":"chargeback confirmed"}}'</pre>
            <p>Response: <code>{{"ok":true,"status":"revoked","key":"KB-XXXX-XXXX"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/delete — permanently delete key</summary>
          <div class="faq-body">
            <p>Deletes the key record and all activation history from the database. <b>Irreversible.</b> Use only when you need to fully wipe a key (GDPR deletion, test cleanup).</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/delete \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX","reason":"GDPR delete request"}}'</pre>
            <p>Response: <code>{{"ok":true,"status":"deleted","key":"KB-XXXX-XXXX"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/reset-devices — clear all HWID bindings</summary>
          <div class="faq-body">
            <p>Removes all device bindings so the key can activate on a fresh machine. Use when a customer gets a new PC or reinstalls their OS and the device limit is hit.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/reset-devices \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX","reason":"customer got new PC"}}'</pre>
            <p>Fires a <code>key.hwid_reset</code> webhook. Response: <code>{{"ok":true,"status":"devices_reset","devices_removed":2}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/keys/reset-ip — clear IP binding history</summary>
          <div class="faq-body">
            <p>Clears <code>first_ip</code>, current <code>ip</code>, and <code>ip_change_count</code> on all activations for this key. Use when a customer's ISP changed their IP and the first-IP lock or drift limit is blocking them.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/keys/reset-ip \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","key":"KB-XXXX-XXXX"}}'</pre>
            <p>Response: <code>{{"ok":true,"status":"ip_reset","key":"KB-XXXX-XXXX"}}</code></p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/bans/add — add IP / HWID / country ban</summary>
          <div class="faq-body">
            <p>Creates a ban. <code>app_id</code> is optional — omit it for a global ban that affects all apps.</p>
            <table class="mini-table">
              <tr><th>kind</th><th>value format</th><th>example</th></tr>
              <tr><td><code>ip</code></td><td>IPv4 or CIDR</td><td><code>1.2.3.4</code> or <code>1.2.3.0/24</code></td></tr>
              <tr><td><code>hwid</code></td><td>Any HWID string</td><td><code>a1b2c3d4...</code></td></tr>
              <tr><td><code>country</code></td><td>ISO 3166-1 alpha-2</td><td><code>RU</code>, <code>CN</code></td></tr>
            </table>
            <pre># App-level IP ban
curl -X POST {html_escape(api_base_url)}/api/v1/bans/add \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","kind":"ip","value":"1.2.3.4","reason":"abuse"}}'

# Global HWID ban (no app_id = all apps)
curl -X POST {html_escape(api_base_url)}/api/v1/bans/add \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"kind":"hwid","value":"a1b2c3d4e5f6...","reason":"fraud"}}'</pre>
            <p>Response: <code>{{"ok":true,"status":"ban_created","kind":"ip","value":"1.2.3.4","scope":"default"}}</code></p>
            <p>Returns <code>409 already_exists</code> if the exact ban already exists.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>POST /api/v1/bans/remove — remove a ban</summary>
          <div class="faq-body">
            <p>Removes a ban by kind + value. Include <code>app_id</code> for app-level bans; omit for global bans.</p>
            <pre>curl -X POST {html_escape(api_base_url)}/api/v1/bans/remove \
  -H "Content-Type: application/json" \
  -H "{html_escape(provisioning['header_name'])}: YOUR_TOKEN_HERE" \
  -d '{{"app_id":"default","kind":"ip","value":"1.2.3.4"}}'</pre>
            <p>Response: <code>{{"ok":true,"status":"ban_removed","kind":"ip","value":"1.2.3.4","scope":"default"}}</code></p>
            <p>Returns <code>404 not_found</code> if no matching ban exists.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Idempotency — handle duplicate payment webhooks safely</summary>
          <div class="faq-body">
            <p>Payment providers (Stripe, PayPal, etc.) can fire the same event multiple times. Protect against duplicate key creation on your side:</p>
            <ol class="steps">
              <li>Save the <code>order_id</code> + returned key in your database when <code>/provision</code> succeeds.</li>
              <li>Before calling provision, check if that <code>order_id</code> already has a key.</li>
              <li>If yes, re-send the existing key — do not call provision again.</li>
            </ol>
            <p>Key Base does not deduplicate by <code>order_id</code> — duplicate calls would create duplicate keys. The check must be on your side.</p>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Token security — rules that must not be broken</summary>
          <div class="faq-body">
            <ul class="doc-list">
              <li>Never put the provisioning token in client code, browser JS, or mobile apps. It controls all key management operations.</li>
              <li>Store it in an environment variable or secrets manager. Never commit it to a repository.</li>
              <li>Use HTTPS in production — set <code>provisioning.require_https: true</code>.</li>
              <li>If the token is ever leaked, rotate <code>KEYBASE_PROVISION_TOKEN</code> or change <code>provisioning.shared_token</code> in config.yml and restart immediately.</li>
              <li>Keep <code>max_batch_size</code> low (10–100). A leaked token plus a high batch limit could create thousands of valid keys in one call.</li>
            </ul>
          </div>
        </details>
        <details class="faq-item" data-faq-item>
          <summary>Automation ideas — what you can build with the Server API</summary>
          <div class="faq-body">
            <table class="mini-table">
              <tr><th>Scenario</th><th>API calls</th></tr>
              <tr><td>New purchase → create key → email to customer</td><td><code>/provision</code></td></tr>
              <tr><td>Subscription renewed → extend existing key</td><td><code>/keys/info</code> → <code>/keys/extend</code></td></tr>
              <tr><td>Subscription cancelled → suspend key</td><td><code>/keys/suspend</code></td></tr>
              <tr><td>Reactivated subscription → resume key</td><td><code>/keys/resume</code></td></tr>
              <tr><td>Chargeback / fraud → revoke key + ban IP</td><td><code>/keys/revoke</code> + <code>/bans/add</code></td></tr>
              <tr><td>Customer new PC → reset device bindings</td><td><code>/keys/reset-devices</code></td></tr>
              <tr><td>Customer ISP changed → reset IP lock</td><td><code>/keys/reset-ip</code></td></tr>
              <tr><td>Support ticket → check key state</td><td><code>/keys/info</code></td></tr>
              <tr><td>GDPR deletion request → delete key</td><td><code>/keys/delete</code></td></tr>
              <tr><td>Abuse report → ban IP or HWID globally</td><td><code>/bans/add</code> (no app_id)</td></tr>
            </table>
          </div>
        </details>
      </div>

      {api_tab_js}
    </section>
    <section id="apps-keys" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Apps & Keys</h2><p>How to organize products and licenses.</p></div></div>
      <details class="faq-item" data-faq-item>
        <summary>How should I use Applications?</summary>
        <div class="faq-body"><p>Create one app per product, loader, game, or internal tool. App-local bans affect only that app. Global bans affect everything.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How does key duration work?</summary>
        <div class="faq-body"><p>Keys are created with a duration such as 30 days or lifetime. The countdown starts only after the first accepted activation, not when the key is created.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What are key statuses?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Status</th><th>Meaning</th></tr>
            <tr><td><code>active</code></td><td>Can verify normally.</td></tr>
            <tr><td><code>paused</code></td><td>Temporary stop.</td></tr>
            <tr><td><code>disabled</code></td><td>Stronger block, still reversible.</td></tr>
            <tr><td><code>revoked</code></td><td>License is burned/invalid.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>When should I reset devices?</summary>
        <div class="faq-body"><p>Reset Devices clears HWID activations for a key. Use it when a customer changed PC or you intentionally want the key to bind again.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Good key duration examples</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Plan</th><th>Duration</th><th>Why</th></tr>
            <tr><td>Trial</td><td>1-3 days</td><td>Short test access without manual cleanup.</td></tr>
            <tr><td>Week access</td><td>7 days</td><td>Simple rental/subscription style.</td></tr>
            <tr><td>Month access</td><td>30 days or 1 month</td><td>Most common license duration.</td></tr>
            <tr><td>Lifetime</td><td>lifetime</td><td>No expiration, still can be paused/revoked/banned.</td></tr>
          </table>
          <p>The timer starts on first valid activation. A created but unused key does not burn time.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What values should I search by in Keys?</summary>
        <div class="faq-body"><p>Search by full key, key note, last IP, last HWID, status, or device count. For support, start with the key, then open details to inspect activations and last seen info.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What fake checks are useful?</summary>
        <div class="faq-body">
          <ul class="doc-list">
            <li>Reject keys that are too short or do not match the generated prefix format.</li>
            <li>Reject empty, tiny, or placeholder HWIDs such as <code>unknown</code>, <code>test</code>, or <code>0000</code>.</li>
            <li>Rate-limit repeated invalid attempts from the same IP.</li>
            <li>Review Events for patterns before using global bans.</li>
          </ul>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Recommended hardening setup for a paid app</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Set an App Secret and make it required.</li>
            <li>Enable <b>Require signed requests</b> and <b>Reject replayed nonce</b>.</li>
            <li>Enable <b>Require session token</b> with a 30-120 minute lifetime.</li>
            <li>Keep <b>Max devices</b> low per key and reset devices only after support review.</li>
            <li>Enable <b>Require client integrity hash</b> and add known release hashes.</li>
            <li>Use Events to ban abusive HWIDs globally only after you confirm the pattern.</li>
          </ol>
          <p>Anti-debug and integrity checks in the client are useful signals, but the server-side signature, nonce, session, HWID, and ban checks are the real enforcement.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What are subscription levels and how do I use them?</summary>
        <div class="faq-body">
          <p>Subscription levels are optional named tiers (e.g. Default, Premium, Enterprise) that you can assign to keys. The level is stored as an integer ID and returned in the verify response so your client can unlock different feature sets.</p>
          <ol class="steps">
            <li>Open the target application, switch to its <b>Subscriptions</b> tab, and add your tiers — ID 1–99, any name without special characters.</li>
            <li>When creating or editing a key, choose a subscription level from the dropdown.</li>
            <li>The verify response includes <code>subscription_level</code> (integer) so your app can branch behavior.</li>
          </ol>
          <p>Levels are scoped per application. If you remove a level, existing keys in that application keep their numeric ID — they just no longer have a name attached.</p>
          <pre>{html_escape(sub_levels_config)}</pre>
          <p>The <code>subscriptions.levels</code> block in <code>config.yml</code> is optional and only used as the initial seed for each application. Use each application's <b>Subscriptions</b> tab to manage levels at runtime for that app.</p>
        </div>
      </details>
    </section>
    <section id="bans-geo" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Bans & Geo</h2><p>Country/IP/HWID behavior without mystery.</p></div></div>
      <details class="faq-item" data-faq-item>
        <summary>Global ban or app ban?</summary>
        <div class="faq-body"><p>Use Global Bans for abuse across every product. Use app bans when only one product should reject the IP, HWID, or country.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How does country blocking work?</summary>
        <div class="faq-body">
          <p>The server checks country in this order: trusted app country header, request JSON country, trusted proxy/CDN headers, then GeoIP lookup.</p>
          <p>For real deployment, prefer Cloudflare or another trusted proxy header. Client-sent country values are useful for tests but can be spoofed.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Why did banned_country not trigger?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open Events and click the verify log.</li>
            <li>Check country and country source.</li>
            <li>If country is empty, enable Cloudflare/proxy headers or set <code>api.geoip_url</code>.</li>
            <li>If country is present but not blocked, check whether the ban is global or app-local.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What IP is used for IP bans?</summary>
        <div class="faq-body">
          <p>Key Base resolves IP in this order:</p>
          <ol class="steps">
            <li>If <code>server.trust_proxy_headers</code> is enabled and the direct source IP is trusted by <code>KEYBASE_PROXY_WHITELIST</code>, it uses the first valid <b>IPv4</b> value from <code>api.accepted_ip_headers</code>.</li>
            <li>If the request still looks local/private like <code>127.0.0.1</code> and <code>api.allow_payload_ip_fallback</code> is enabled, Key Base can use JSON <code>ip</code> as the effective <b>IPv4</b> for bans and rate limits.</li>
            <li>Otherwise it keeps the direct socket IP.</li>
          </ol>
          <p>This means IP bans now work in both reverse-proxy setups and local client setups where the client first asks a public IP service and then sends that IP in JSON.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I test a country ban?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Add an app ban or global ban with kind <code>Country</code>.</li>
            <li>Pick a country from the country picker, for example <code>US</code>.</li>
            <li>Send a verify request with that country through trusted headers or JSON for local testing.</li>
            <li>Open Events and check for <code>banned_country</code>.</li>
          </ol>
          <p>For real public traffic, prefer Cloudflare <code>CF-IPCountry</code>. JSON country is not strong security because a client can lie.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Which ban type should I use?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Ban kind</th><th>Best use</th></tr>
            <tr><td>IP</td><td>Fast abuse stop, but weak against VPN/proxy changes.</td></tr>
            <tr><td>HWID</td><td>Blocks a known machine fingerprint. Stronger than IP for repeat abuse.</td></tr>
            <tr><td>Country</td><td>Region policy or abuse-heavy location block. Needs reliable country source.</td></tr>
          </table>
        </div>
      </details>
    </section>
    <section id="webhooks" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Webhooks</h2><p>Notify your server in real time when license events happen — per application.</p></div></div>
      <details class="faq-item" data-faq-item>
        <summary>What are webhooks and why use them?</summary>
        <div class="faq-body">
          <p>A webhook is an HTTP POST request Key Base sends to your server when a license event happens — key created, activated, expired, HWID reset, and more. Instead of polling the admin panel, your backend receives events instantly and can act: send an email, update a database, trigger provisioning, or push a notification.</p>
          <p>Webhooks are per-application — each app has its own <b>Webhooks</b> tab. This lets you route events to different backends per product.</p>
          <table class="mini-table">
            <tr><th>Event</th><th>When it fires</th></tr>
            <tr><td><code>key.created</code></td><td>A new key is created from the admin panel or provisioning API.</td></tr>
            <tr><td><code>key.extended</code></td><td>An existing key's expiry is changed via Edit Key.</td></tr>
            <tr><td><code>key.activated</code></td><td>A device activates a key for the first time (HWID binding).</td></tr>
            <tr><td><code>key.hwid_reset</code></td><td>An admin resets all device bindings for a key.</td></tr>
            <tr><td><code>key.expired</code></td><td>A key expires during a license verification check.</td></tr>
            <tr><td><code>test</code></td><td>Manual test delivery sent from the Webhooks tab.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I add a webhook endpoint?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open any <b>Application</b> and click the <b>Webhooks</b> tab.</li>
            <li>Paste your server's public HTTPS URL in the <b>Endpoint URL</b> field.</li>
            <li>Check the events you want, or leave all checked to receive everything.</li>
            <li>Click <b>Add Endpoint</b>. A signing secret is generated automatically.</li>
            <li>Click the <b>Settings</b> button on the endpoint row to choose a preset (Discord, Slack, ntfy, etc.) or write a custom body template.</li>
            <li>Copy the signing secret via <b>Show secret</b> and store it on your server — you will use it to verify incoming requests.</li>
            <li>Click <b>Send test</b> and watch the Delivery Log for the result.</li>
          </ol>
          <p>Each endpoint has its own secret and format config. Multiple endpoints per app are supported.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What does the POST body look like?</summary>
        <div class="faq-body">
          <p>Every delivery is a JSON POST with these headers:</p>
          <table class="mini-table">
            <tr><th>Header</th><th>Value</th></tr>
            <tr><td><code>Content-Type</code></td><td><code>application/json</code></td></tr>
            <tr><td><code>X-KeyBase-Event</code></td><td>Event name, e.g. <code>key.created</code></td></tr>
            <tr><td><code>X-KeyBase-Delivery</code></td><td>Unique delivery ID for this attempt</td></tr>
            <tr><td><code>X-KeyBase-Signature</code></td><td><code>sha256=&lt;hmac&gt;</code> — HMAC-SHA256 of the raw body using your endpoint secret</td></tr>
          </table>
          <p>Example body for <code>key.created</code>:</p>
          <pre>{html_escape(webhook_payload_example)}</pre>
          <p>Fields vary by event type. <code>key.*</code> events always include <code>app_id</code> and <code>key</code>. The test event includes <code>"test": true</code>.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I verify the signature?</summary>
        <div class="faq-body">
          <p>Always verify <code>X-KeyBase-Signature</code> before trusting the payload. Use the <b>raw request body bytes</b> — do not re-serialize the JSON.</p>
          <p>Compute <code>HMAC-SHA256(raw_body, endpoint_secret)</code>, compare it to the hex value after <code>sha256=</code>, and reject mismatches.</p>
          <p>Return HTTP <code>200</code> as fast as possible. Do heavy work asynchronously — Key Base waits only <code>webhooks.timeout_seconds</code> seconds before treating the delivery as failed.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How does retry logic work?</summary>
        <div class="faq-body">
          <p>When a delivery fails (timeout, non-2xx response, or network error), Key Base retries up to <code>webhooks.max_retries</code> times with exponential back-off:</p>
          <table class="mini-table">
            <tr><th>Attempt</th><th>Delay before retry</th></tr>
            <tr><td>1 (initial)</td><td>Immediate</td></tr>
            <tr><td>2</td><td>60 seconds</td></tr>
            <tr><td>3</td><td>5 minutes</td></tr>
            <tr><td>4</td><td>30 minutes</td></tr>
          </table>
          <p>After all attempts are exhausted the delivery is marked <code>failed</code>. You can see every attempt in the <b>Delivery Log</b> on the Webhooks page.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Webhook config options</summary>
        <div class="faq-body">
          <pre>{html_escape(webhook_config)}</pre>
          <p><code>timeout_seconds</code> is the per-attempt HTTP timeout. <code>max_retries</code> is the number of extra attempts after the initial failure (0 = try once and stop). Both values restart the background worker live when saved — no server restart needed.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>My endpoint is not receiving deliveries — checklist</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Check the <b>Delivery Log</b> on the Webhooks page — it shows the HTTP status code and any error for each attempt.</li>
            <li>Make sure the endpoint URL is publicly reachable. Key Base sends from the server process, so <code>localhost</code> or LAN IPs only work if both servers are on the same machine.</li>
            <li>Confirm the endpoint returns HTTP <code>2xx</code> quickly. Returning <code>4xx</code> or <code>5xx</code> counts as failure and triggers retries.</li>
            <li>Check that the endpoint is <b>Enabled</b> — the toggle on the endpoint row controls this.</li>
            <li>If HTTPS is involved, make sure the TLS certificate is valid. Self-signed certs are rejected by default.</li>
            <li>Use <b>Send test</b> to fire a test delivery and watch the Delivery Log for the result.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Can I subscribe to only some events?</summary>
        <div class="faq-body">
          <p>Yes. When creating an endpoint, check only the events you want. An endpoint configured with <code>*</code> (all events checked or none checked) receives everything including future new event types. If you check specific events, only those are delivered to that endpoint.</p>
          <p>You can add multiple endpoints with different event filters — for example one endpoint for billing events (<code>key.created</code>, <code>key.extended</code>) and another for security/monitoring (<code>key.activated</code>, <code>key.hwid_reset</code>, <code>key.expired</code>).</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Idempotency — handle duplicate deliveries safely</summary>
        <div class="faq-body">
          <p>Key Base retries failed deliveries. Your endpoint may receive the same event more than once. Use the <code>X-KeyBase-Delivery</code> header to deduplicate:</p>
          <p>Store processed delivery IDs in Redis or a database table. Expire old IDs after 24–72 hours to avoid unbounded growth. The <code>X-KeyBase-Delivery</code> value is the same for all retry attempts of a single delivery, so it is safe to use as the idempotency key.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Discord — forward license events to a channel</summary>
        <div class="faq-body">
          <p>Create a Discord webhook URL in your server's channel settings (Edit Channel → Integrations → Create Webhook). Paste the Discord URL as the endpoint URL. Choose the <b>Discord</b> preset in the Settings modal — Key Base will format the body as a Discord Embed automatically.</p>
          <pre>{html_escape(ex_discord_setup)}</pre>
          <p>The Discord preset sends a rich embed with event name, key, and timestamp. Use event filters to subscribe only to the events you want in that channel (e.g. only <code>key.created</code> for a #new-customers channel).</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Slack — send license events to a Slack channel</summary>
        <div class="faq-body">
          <p>Create a Slack Incoming Webhook at <code>api.slack.com/apps</code> → Your App → Incoming Webhooks. Paste the Slack URL as the endpoint URL. Choose the <b>Slack</b> preset in the Settings modal — Key Base formats the body as a Slack Block Kit message.</p>
          <pre>{html_escape(ex_slack_setup)}</pre>
          <p>The Slack preset sends a structured block message. You can further customize the body template in the Settings modal after choosing the preset as a starting point.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>ntfy — push notifications to phone or desktop</summary>
        <div class="faq-body">
          <p>ntfy is a free self-hostable push notification service (<code>ntfy.sh</code>). Paste your ntfy topic URL as the endpoint URL and choose the <b>ntfy</b> preset. Key Base sends a plain-text push notification when a license event happens.</p>
          <pre>{html_escape(ex_ntfy_setup)}</pre>
          <p>Install the ntfy app on Android or iOS and subscribe to your topic to receive instant phone push notifications on key activations, expiries, or HWID resets. Self-host ntfy on your own server if you need private topics.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Telegram — send license events to a bot or group</summary>
        <div class="faq-body">
          <p>Create a bot with @BotFather, get the bot token and your chat ID, then build the Telegram API URL manually. Choose the <b>Telegram</b> preset in Settings — it formats the body as a Telegram sendMessage call.</p>
          <pre>{html_escape(ex_telegram_setup)}</pre>
          <p>To find your chat ID, send the bot a message and then call <code>https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</code>. The <code>chat.id</code> field in the response is what you need. For groups, add the bot to the group first.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Custom body template — build any payload format</summary>
        <div class="faq-body">
          <p>In the endpoint Settings modal, write a custom body template using <code>{{variable}}</code> placeholders:</p>
          <table class="mini-table">
            <tr><th>Variable</th><th>Value</th></tr>
            <tr><td><code>{{event}}</code></td><td>Event name, e.g. <code>key.created</code></td></tr>
            <tr><td><code>{{key}}</code></td><td>The license key text</td></tr>
            <tr><td><code>{{app_id}}</code></td><td>Application ID</td></tr>
            <tr><td><code>{{hwid}}</code></td><td>Device fingerprint (when present)</td></tr>
            <tr><td><code>{{ip}}</code></td><td>Client IP address (when present)</td></tr>
            <tr><td><code>{{country}}</code></td><td>ISO country code (when present)</td></tr>
            <tr><td><code>{{timestamp}}</code></td><td>ISO 8601 UTC event time</td></tr>
          </table>
          <p>You can also set a custom <code>Content-Type</code> and extra headers (e.g. <code>Authorization: Bearer token</code>) in the Settings modal. Extra headers support <code>{{event}}</code> substitution too.</p>
        </div>
      </details>
    </section>
    <section id="security" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Security</h2><p>What is protected and what is only friction.</p></div></div>
      <details class="faq-item" data-faq-item>
        <summary>Where is the admin password stored?</summary>
        <div class="faq-body"><p>Only a salted PBKDF2 hash is stored in <code>.env</code>. Plain passwords are not saved.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do dangerous confirmations work?</summary>
        <div class="faq-body"><p>Delete/reset/config/secret actions ask for the admin password. After a correct confirmation, the browser gets a short confirmation cookie so you do not type it for every single action.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How does Protection Monitor work?</summary>
        <div class="faq-body">
          <p>Protection Monitor reviews client-provided environment signals and optional IP reputation results during license verification. Start in <code>anti_mode: warn</code> so legitimate users are not blocked while you tune rules and whitelists.</p>
          <p>The built-in risk engine combines free IP intelligence (<code>ip-api.com</code>, <code>ipwho.is</code>, DB-IP's free endpoint, Team Cymru ASN WHOIS, and the public Tor exit list), request timing, browser fingerprint data, WebGL/VM heuristics, and behavior entropy. Scores are normalized from 0 to 100 and mapped to <code>allow</code> (0-40), <code>warning</code> (41-70), or <code>block</code> (71-100 in strict mode only).</p>
          <p>Browser clients can load <code>/api/v1/fingerprint.js</code>, call <code>KeyBaseFingerprint.collect()</code>, and include the returned object as <code>fingerprint</code> in <code>POST /api/v1/verify</code>.</p>
          <pre>{html_escape(protection_config)}</pre>
          <table class="mini-table">
            <tr><th>Mode</th><th>Behavior</th></tr>
            <tr><td><code>off</code></td><td>Protection scoring is disabled.</td></tr>
            <tr><td><code>warn</code></td><td>Scores and logs signals, returns warning metadata for elevated scores, but does not block users.</td></tr>
            <tr><td><code>strict</code></td><td>Applies the score rules and rejects only combined risk scores of 71+.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Deployment hardening checklist</summary>
        <div class="faq-body">
          <ul class="doc-list">
            <li>Keep admin local, VPN-only, or behind a protected reverse proxy.</li>
            <li>Use HTTPS for public API traffic.</li>
            <li>Back up <code>data/keybase.sqlite3</code>, <code>.env</code>, and <code>config.yml</code>.</li>
            <li>Do not expose Key Base directly if you trust proxy headers.</li>
            <li>Remember client-side app secrets can be extracted.</li>
          </ul>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Backup commands</summary>
        <div class="faq-body">
          <p>The easiest path is the new <b>Backup</b> tab in the admin panel. It creates timestamped zip archives and also runs automatic backups on the schedule from <code>backup.*</code>.</p>
          <div class="doc-grid">
            <div><h3>Windows PowerShell</h3><pre>{html_escape(backup_windows)}</pre></div>
            <div><h3>Linux / macOS shell</h3><pre>{html_escape(backup_linux)}</pre></div>
          </div>
          <p>Back up all three together. Restoring only the database without <code>.env</code> can break admin login/session secrets.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How does the Backup tab work?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open <code>Backup</code> in the left sidebar.</li>
            <li>Press <code>Create Backup Now</code> to build a full zip archive immediately.</li>
            <li>Set <code>backup.auto_enabled</code>, <code>backup.interval_minutes</code>, and <code>backup.keep_last</code> in <code>config.yml</code> for automatic rotation.</li>
            <li>Each archive contains <code>config.yml</code>, <code>.env</code>, <code>data/keybase.sqlite3</code>, and <code>metadata.json</code> when those items are enabled.</li>
            <li>Delete old archives only after checking newer restore points exist.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Backup config example</summary>
        <div class="faq-body">
          <p>These are the same <code>backup.*</code> values the Backup page uses for the automatic worker and archive contents.</p>
          <pre>{html_escape(backup_yaml)}</pre>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I restore a backup?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Stop Key Base.</li>
            <li>Copy the chosen archive to a safe temporary folder and extract it.</li>
            <li>Restore <code>config.yml</code>, <code>.env</code>, and <code>data/keybase.sqlite3</code> together.</li>
            <li>Start Key Base and confirm login, apps, keys, and API health.</li>
          </ol>
          <p>Restoring only the database without the matching <code>.env</code> can break admin login and session cookies.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Security config fields</summary>
        <div class="faq-body">
          <table>
            <tr><th>Field</th><th>Recommended idea</th></tr>
            <tr><td><code>security.session_hours</code></td><td>How long admin login lasts. Use smaller values on shared machines.</td></tr>
            <tr><td><code>security.confirm_minutes</code></td><td>How long password confirmation is remembered for dangerous actions.</td></tr>
            <tr><td><code>security.password_min_length</code></td><td>Minimum password length. The app enforces at least 6 even if config is lower.</td></tr>
            <tr><td><code>security.login_attempts_per_10m</code></td><td>Limits brute force attempts against admin login.</td></tr>
            <tr><td><code>security.register_attempts_per_hour</code></td><td>Limits setup/register spam before the first admin account exists.</td></tr>
            <tr><td><code>backup.keep_last</code></td><td>Retention cap for automatic and manual backup archives.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What if I forgot the admin password?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Stop the server.</li>
            <li>Back up <code>.env</code>, <code>config.yml</code>, and <code>data/keybase.sqlite3</code>.</li>
            <li>Rename <code>.env</code> to <code>.env.old</code>.</li>
            <li>Start the server and register a new admin password.</li>
            <li>Keep the old <code>.env.old</code> until you confirm everything works.</li>
          </ol>
          <p>This requires filesystem access. If an attacker has that, the machine is already compromised, so protect the project folder.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>App Secret — what it is and what it protects</summary>
        <div class="faq-body">
          <p>The App Secret is an optional per-application string your client sends in the <code>X-App-Secret</code> header on every verify request. It is different from the provisioning token — it is a client-side value.</p>
          <table class="mini-table">
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Where set</td><td>App Settings → App Secret</td></tr>
            <tr><td>Where sent</td><td><code>X-App-Secret</code> request header</td></tr>
            <tr><td>What it protects</td><td>Prevents random internet traffic from hitting your verify endpoint; adds a shared "password" the client must know.</td></tr>
            <tr><td>What it does NOT protect</td><td>A sophisticated attacker can extract it from the client binary. It is a barrier, not encryption.</td></tr>
          </table>
          <p>For higher security, enable signed requests (HMAC-SHA256) instead. Signing is stronger because the secret is never sent directly — only the HMAC digest is.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What does warn vs strict mode in Protection Monitor mean for my users?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Mode</th><th>Score 0-40</th><th>Score 41-70</th><th>Score 71-100</th></tr>
            <tr><td><code>off</code></td><td>Verify succeeds.</td><td>Verify succeeds.</td><td>Verify succeeds.</td></tr>
            <tr><td><code>warn</code></td><td>Verify succeeds; event may be logged.</td><td>Verify succeeds with <code>protection_warning</code>.</td><td>Verify succeeds with <code>would_block_in_strict</code>.</td></tr>
            <tr><td><code>strict</code></td><td>Verify succeeds.</td><td>Verify succeeds with <code>protection_warning</code>.</td><td>Verify fails with the primary protection reason.</td></tr>
          </table>
          <p>A single VM, VPN, proxy, debugger, or datacenter signal is not enough to block by itself. Start with <code>anti_mode: warn</code> and move to <code>strict</code> only after you understand your user population's normal environment signals.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>IP drift and IP binding — first-IP locking explained</summary>
        <div class="faq-body">
          <p>If you enable first-IP binding for an app, the first IP that activates a key is saved. Later activations from a different IP are rejected with <code>ip_changed</code>. This is useful for single-user licenses where the user should always be on the same connection.</p>
          <p>IP drift limits allow a small number of IP changes before locking. Useful for users whose ISP changes their IP periodically.</p>
          <p><b>When NOT to use it:</b> mobile users, users behind CGNAT, and users who travel. Their IP changes legitimately. IP locking will lock out these users from their own license.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>What is the difference between a key ban and a key revoke?</summary>
        <div class="faq-body">
          <table class="mini-table">
            <tr><th>Action</th><th>Status</th><th>Reversible?</th><th>Use when</th></tr>
            <tr><td>Ban (via Bans tab)</td><td><code>banned_key</code></td><td>Yes</td><td>Temporarily block a specific key text. Can be un-banned.</td></tr>
            <tr><td>Pause</td><td><code>paused</code></td><td>Yes</td><td>Temporarily suspend key. User contacts support. Admin un-pauses.</td></tr>
            <tr><td>Disable</td><td><code>disabled</code></td><td>Yes</td><td>Stronger pause. Same response as paused.</td></tr>
            <tr><td>Revoke (via Edit Key)</td><td><code>revoked</code></td><td>No</td><td>Permanent blacklist. Chargeback, fraud, TOS violation.</td></tr>
          </table>
        </div>
      </details>
    </section>
    <section id="troubleshooting" class="panel faq-section" data-faq-section>
      <div class="panel-head"><div><h2>Troubleshooting</h2><p>Fast answers for common broken states.</p></div></div>
      <details class="faq-item" data-faq-item>
        <summary>Key says invalid / Key not found</summary>
        <div class="faq-body"><p>Check that the client sends the same <code>app_id</code> where the key was created, and that the key text has no hidden spaces.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>device_limit</summary>
        <div class="faq-body"><p>The key already reached its HWID limit. Open key settings and use Reset Devices if you intentionally want to rebind.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Config changed but nothing changed</summary>
        <div class="faq-body"><p>Restart the server after bind, port, or data path changes. Proxy header order, payload IP fallback, backup schedule, and most admin-side validation settings apply from config after save, but listener/socket changes still need restart. Also check that real environment variables are not overriding config values.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Everything shows 127.0.0.1 so IP bans do nothing</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>If you use Nginx, Cloudflare, or a tunnel, enable <code>server.trust_proxy_headers</code>.</li>
            <li>Add the proxy machine IP or CIDR to <code>KEYBASE_PROXY_WHITELIST</code>.</li>
            <li>Keep <code>api.accepted_ip_headers</code> in the right order, usually <code>CF-Connecting-IP</code>, <code>True-Client-IP</code>, <code>Fly-Client-IP</code>, <code>X-Real-IP</code>, <code>X-Forwarded-For</code>, then <code>Forwarded</code>.</li>
            <li>If your client talks to a local/tunneled server and still arrives as loopback, let the client fetch its own public <b>IPv4</b> and send JSON <code>ip</code>. Then keep <code>api.allow_payload_ip_fallback: true</code>.</li>
            <li>Test again and inspect <code>resolved_ip</code> plus <code>ip_source</code> in the verify response.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Port 8080 is already busy</summary>
        <div class="faq-body">
          <div class="doc-grid">
            <div><h3>Windows</h3><pre>netstat -ano | findstr :8080
taskkill /PID 1234 /F</pre></div>
            <div><h3>Linux / macOS</h3><pre>ss -ltnp | grep :8080
kill -TERM 1234</pre></div>
          </div>
          <p>Replace <code>1234</code> with the PID you actually see. Or change <code>server.port</code> in <code>config.yml</code> and restart.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Country ban still does not work</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Check Events and look at the country value on the verify log.</li>
            <li>If country is empty, your request is not providing a usable country source.</li>
            <li>If country is wrong behind Cloudflare, enable <code>cloudflare.enabled</code> and <code>server.trust_proxy_headers</code>.</li>
            <li>If direct users can reach port 8080, do not trust proxy headers yet. Close direct access first.</li>
            <li>For local testing, send <code>country</code> in JSON or <code>X-App-Country</code> header.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Admin page loads but old CSS/JS stays</summary>
        <div class="faq-body"><p>Hard refresh the browser with <code>Ctrl+F5</code>. The static files are local, so the most common cause is browser cache after CSS/JS edits.</p></div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Config.yml is broken and server will not start</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open <code>config.yml</code> in an editor that shows spaces.</li>
            <li>Remove tabs and fix indentation under <code>server:</code>, <code>api:</code>, <code>admin:</code>, <code>security:</code>, and <code>cloudflare:</code>.</li>
            <li>Compare against the examples in the Config section.</li>
            <li>Run the YAML validation command from <b>Commands to validate config.yml</b>.</li>
            <li>If needed, temporarily restore from <code>backups/config.yml.bak</code>.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Website provisioning request fails</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Make sure <code>provisioning.enabled</code> is set to <code>true</code>.</li>
            <li>Check that your backend sends the exact header name from <code>provisioning.header_name</code>.</li>
            <li>Check that the header value exactly matches <code>provisioning.shared_token</code>.</li>
            <li>If <code>provisioning.require_https</code> is true, send the request through HTTPS or a trusted HTTPS proxy.</li>
            <li>Check the Audit Log / Console for <code>provision_batch</code>, <code>bad_provision_token</code>, or <code>provisioning_disabled</code>.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Full status list</summary>
        <div class="faq-body">
          <table>
            <tr><th>Status</th><th>Meaning</th></tr>
            <tr><td><code>valid</code></td><td>Key accepted.</td></tr>
            <tr><td><code>invalid</code></td><td>Key not found for this app.</td></tr>
            <tr><td><code>fake_key</code></td><td>Key format is too short, malformed, or obviously synthetic.</td></tr>
            <tr><td><code>suspicious_hwid</code></td><td>HWID is too short or looks like a placeholder.</td></tr>
            <tr><td><code>too_many_attempts</code></td><td>This IP has too many rejected attempts.</td></tr>
            <tr><td><code>signature_required</code> / <code>bad_signature</code></td><td>Signed request mode is enabled and the request is missing or has a wrong HMAC.</td></tr>
            <tr><td><code>stale_request</code> / <code>bad_nonce</code> / <code>replay_detected</code></td><td>Timestamp or nonce protection rejected the request.</td></tr>
            <tr><td><code>session_required</code></td><td>The app expects a valid short server session token.</td></tr>
            <tr><td><code>missing_client_hash</code> / <code>client_integrity_failed</code></td><td>Client integrity hash is required or not on the allowed list.</td></tr>
            <tr><td><code>client_risk</code></td><td>The client sent a debugger/tamper/integrity-failed flag and the app blocks risk flags.</td></tr>
            <tr><td><code>VM_DETECTED</code> / <code>VPN_DETECTED</code> / <code>PROXY_DETECTED</code></td><td>Global protection policy detected a virtualized or suspicious network environment.</td></tr>
            <tr><td><code>DEBUGGER_DETECTED</code></td><td>Global protection policy detected debugger, tamper, sandbox, or related high-risk runtime signals.</td></tr>
            <tr><td><code>ip_changed</code> / <code>ip_change_limit</code></td><td>First-IP binding or IP drift limit rejected the device.</td></tr>
            <tr><td><code>expired</code></td><td>Key duration or fixed legacy date expired.</td></tr>
            <tr><td><code>paused</code> / <code>disabled</code> / <code>revoked</code></td><td>Key is blocked by its status.</td></tr>
            <tr><td><code>app_paused</code> / <code>app_disabled</code></td><td>The whole app is blocked.</td></tr>
            <tr><td><code>device_limit</code></td><td>Too many HWIDs used this key.</td></tr>
            <tr><td><code>banned_ip</code> / <code>banned_hwid</code> / <code>banned_country</code></td><td>A global or app ban matched.</td></tr>
            <tr><td><code>bad_app_secret</code></td><td>The app requires <code>X-App-Secret</code> and the value is wrong.</td></tr>
            <tr><td><code>api_stopped</code></td><td>The admin API gate is stopped from the API page.</td></tr>
            <tr><td><code>provisioning_disabled</code></td><td>The provisioning endpoint is off in <code>config.yml</code>.</td></tr>
            <tr><td><code>bad_provision_token</code></td><td>Your website/backend did not send the right private provisioning token header.</td></tr>
            <tr><td><code>https_required</code></td><td>Provisioning is configured to allow only HTTPS requests.</td></tr>
          </table>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>signature_invalid — signed request keeps failing</summary>
        <div class="faq-body">
          <p>This means the HMAC-SHA256 signature in <code>X-KeyBase-Signature</code> does not match what the server computed. Common causes:</p>
          <table class="mini-table">
            <tr><th>Cause</th><th>Fix</th></tr>
            <tr><td>Wrong APP_SECRET — using admin password instead of the app secret</td><td>Copy the App Secret from App Settings → Signing section.</td></tr>
            <tr><td>Signing over a different set of fields or in a different order</td><td>Match the exact canonical fields and order from the signing docs.</td></tr>
            <tr><td>Extra whitespace, newline, or encoding difference in the signed string</td><td>Use exact string concatenation. No trailing newline.</td></tr>
            <tr><td>Signing over the JSON body instead of canonical fields</td><td>The signature covers the canonical form, not the full JSON.</td></tr>
            <tr><td>Clock skew too large — server rejects before checking HMAC</td><td>Sync client clock. Skew limit is typically 5 minutes.</td></tr>
          </table>
          <p>Add a debug print of the exact string you are signing and compare it with what the server would compute using the same fields.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>too_many_attempts — rate limit hit</summary>
        <div class="faq-body">
          <p>The API rate-limit is per IP. This can happen legitimately during testing or maliciously during brute-force.</p>
          <ol class="steps">
            <li>Wait for the window to expire (usually 10 minutes) before retrying.</li>
            <li>If you are testing with curl in a loop, add a delay between requests.</li>
            <li>If clients behind NAT all share one IP, increase <code>api.rate_limit_per_10m</code> in config.</li>
            <li>If it is a real attack, add the attacker IP to bans via Admin → Global Bans.</li>
            <li>Check Events → filter by <code>too_many_attempts</code> to see which IP is hitting the limit.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>HWID changes after reinstall / update — device_limit or binding reset</summary>
        <div class="faq-body">
          <p>If your HWID generation uses values that change on reinstall (temp file path, installer-generated UUID, MAC address that resets in a VM), the old HWID slot remains used and the new HWID looks like a new device.</p>
          <table class="mini-table">
            <tr><th>HWID source</th><th>Stability</th></tr>
            <tr><td>Windows MachineGuid from registry</td><td>Stable until Windows reinstall</td></tr>
            <tr><td>Linux /etc/machine-id</td><td>Stable until distro reinstall</td></tr>
            <tr><td>macOS IOPlatformUUID</td><td>Very stable</td></tr>
            <tr><td>Disk volume serial / UUID</td><td>Stable unless disk reformatted</td></tr>
            <tr><td>Network MAC address</td><td>Unstable in VMs, changes with NIC swap</td></tr>
            <tr><td>Hostname alone</td><td>Unstable, easily spoofed</td></tr>
          </table>
          <p>Combine 2–3 stable sources and hash them together. Fallback gracefully if one source fails on a particular OS.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Webhook deliveries are failing — all show error in Delivery Log</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Click the failed delivery in the Delivery Log to see the HTTP status code and response body.</li>
            <li>If it shows "Connection refused" — the endpoint server is not running or the URL is wrong.</li>
            <li>If it shows "SSL certificate verify failed" — the TLS certificate on the endpoint is invalid or self-signed.</li>
            <li>If it shows "Read timeout" — the endpoint is not responding within <code>webhooks.timeout_seconds</code>. Respond 200 immediately and do work async.</li>
            <li>If it shows 4xx — check the URL path is correct and that you are not requiring extra auth headers.</li>
            <li>If it shows 5xx — your endpoint server has an error. Check its own logs.</li>
            <li>Use <b>Send test</b> with a simple echo endpoint (e.g. webhook.site) to confirm Key Base can send requests at all.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Server starts but API returns HTTP 500</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Check the terminal / server console for a Python traceback.</li>
            <li>A 500 almost always means an unhandled exception — the traceback tells you exactly what failed.</li>
            <li>Common causes: database is locked by another process, <code>data/</code> directory does not exist, SQLite file is corrupted, or a required config key is missing.</li>
            <li>Test with <code>python -c "import core; print('ok')"</code> to check for import errors.</li>
            <li>Test DB health: <code>sqlite3 data/keybase.sqlite3 "PRAGMA integrity_check;"</code> — should print <code>ok</code>.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Admin session keeps expiring too quickly</summary>
        <div class="faq-body">
          <p>By default the admin session expires after a configured number of hours (<code>security.session_hours</code>). If it expires too fast:</p>
          <ol class="steps">
            <li>Increase <code>security.session_hours</code> in <code>config.yml</code>.</li>
            <li>Check if the server was restarted — a restart invalidates all sessions because the session secret is regenerated. To keep sessions across restarts, set a fixed <code>security.session_secret</code> in config.</li>
            <li>If sessions expire immediately, check that your reverse proxy preserves the <code>Set-Cookie</code> header and does not strip it.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Python import error at startup</summary>
        <div class="faq-body">
          <p>If the server exits immediately with <code>ModuleNotFoundError</code>:</p>
          <ol class="steps">
            <li>Run <code>pip install -r requirements.txt</code> (or <code>pip3 install -r requirements.txt</code>) in the project directory.</li>
            <li>Make sure you are using the same Python venv or interpreter that matches the install.</li>
            <li>On Windows, run <code>run.bat</code> from the project folder, not from a different directory.</li>
            <li>If you just updated Python, re-install requirements in the new version's environment.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>How do I update Key Base?</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Open the Dashboard and watch the thin amber update strip at the top when a new release exists.</li>
            <li>Run Builder against the same install folder so it can download the newest <code>Server-Portable.zip</code> for you.</li>
            <li>Builder stops the running server, replaces the code files, keeps <code>config.yml</code>, <code>.env</code>, <code>data/</code>, and <code>backups/</code>, and runs database migration automatically if the backend changed.</li>
            <li>The strip re-checks release status automatically and disappears when the installed version is current or the release was removed.</li>
            <li>Start the server again with <code>run.bat</code> or <code>./run.sh</code>.</li>
          </ol>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Verify returns ok: true but key shows as expired in admin</summary>
        <div class="faq-body">
          <p>This can happen if the key's status in the database is <code>active</code> but <code>expires_at</code> is in the past and the expiry check runs asynchronously. The key shows "expired" in the UI because the display is calculated from the timestamp, but the verify result is cached or the expiry event has not fired yet.</p>
          <p>The fix: open the key in admin, check <code>expires_at</code>. If it is past, the next verify call will return <code>expired</code>. The UI and verify status will match from that point on. You can also manually set the status to <code>expired</code> from the Edit Key form.</p>
        </div>
      </details>
      <details class="faq-item" data-faq-item>
        <summary>Events page is empty — no activation events showing</summary>
        <div class="faq-body">
          <ol class="steps">
            <li>Events are written when a verify request is processed. If no verifications have happened, events will be empty.</li>
            <li>Send a test verify via curl (see API section for the curl example).</li>
            <li>Check that <code>app_id</code> in your verify request matches the app you are looking at in the panel.</li>
            <li>Refresh the Events page and check the filters — the time range or event type filter may be hiding entries.</li>
            <li>If events appear in the console but not the panel, check the database is writable: <code>ls -la data/</code> on Linux or check file permissions on Windows.</li>
          </ol>
        </div>
      </details>
    </section>
  </main>
</div>
"""
    return page_shell(t("faq_title"), body, "docs")


class KeyBaseHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{VERSION}"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stdout.write("%s - - [%s] %s\n" % (self._client_ip(), self.log_date_time_string(), fmt % args))

    def _client_ip_info(self, payload_ip: str | None = None) -> tuple[str, str]:
        return resolved_request_ip(self.client_address[0], getattr(self, "headers", None), payload_ip)

    def _client_ip(self, payload_ip: str | None = None) -> str:
        return self._client_ip_info(payload_ip)[0]

    def _client_country(self, data: dict[str, Any]) -> str:
        resolved_ip, resolved_source = self._client_ip_info(str(data.get("ip", "")))
        return resolved_request_country(
            self.client_address[0],
            getattr(self, "headers", None),
            resolved_ip,
            resolved_source,
            data.get("country"),
            str(data.get("ip", "")),
        )[0]

    def _read_body(self) -> bytes:
        length = as_int(self.headers.get("Content-Length"), 0, minimum=0, maximum=10_000_000)
        return self.rfile.read(length) if length else b""

    def _parse_body(self) -> dict[str, Any]:
        raw = self._read_body()
        if not raw:
            return {}
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type == "application/json":
            try:
                parsed = json.loads(raw.decode("utf-8"))
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        parsed_qs = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed_qs.items()}

    def _send(self, status: int, content: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def _send_text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _send_html(self, html_text: str, status: int = HTTPStatus.OK) -> None:
        self._send(status, html_text.encode("utf-8"), "text/html; charset=utf-8")

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _send_asset(self, request_path: str) -> None:
        name = unquote(request_path[len("/assets/") :])
        if not name or "/" in name or "\\" in name:
            self._send_text(HTTPStatus.NOT_FOUND, "Not found")
            return
        asset_path = ASSET_DIR / name
        if not asset_path.is_file():
            self._send_text(HTTPStatus.NOT_FOUND, "Not found")
            return
        suffix = asset_path.suffix.lower()
        content_type = "image/png" if suffix == ".png" else "image/svg+xml" if suffix == ".svg" else "application/javascript; charset=utf-8" if suffix == ".js" else "application/octet-stream"
        self._send(HTTPStatus.OK, asset_path.read_bytes(), content_type)

    def _redirect(self, location: str) -> None:
        self._send(HTTPStatus.SEE_OTHER, b"", "text/plain; charset=utf-8", {"Location": location})

    def _cookie_value(self) -> str:
        raw = self.headers.get("Cookie", "")
        for item in raw.split(";"):
            if "=" not in item:
                continue
            key, value = item.strip().split("=", 1)
            if key == COOKIE_NAME:
                return value
        return ""

    def _admin_allowed_from_ip(self) -> bool:
        return remote_admin_allowed() or is_loopback_ip(self.client_address[0])

    def _admin_authed(self) -> bool:
        if not admin_configured():
            return False
        cookie = self._cookie_value()
        return bool(cookie and verify_session_cookie(cookie))

    def _require_admin(self) -> bool:
        if not self._admin_allowed_from_ip():
            self._send_text(
                HTTPStatus.FORBIDDEN,
                "Remote admin is disabled. Set KEYBASE_ALLOW_REMOTE_ADMIN=1 if you really need it.",
            )
            return False
        if not admin_configured():
            self._send_html(setup_page(), HTTPStatus.OK)
            return False
        if self._admin_authed():
            return True
        self._send_html(login_page(), HTTPStatus.UNAUTHORIZED)
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/api/v1/fingerprint.js":
            self._send_asset("/assets/keybase-fingerprint.js")
            return

        if path.startswith("/assets/"):
            self._send_asset(path)
            return

        if path in {"/", "/health", "/api/v1/health"}:
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "name": APP_NAME,
                    "version": VERSION,
                    "api_enabled": api_runtime_enabled(),
                    "api_uptime": api_runtime_uptime(),
                },
            )
            return

        if path == "/admin/login":
            if not self._admin_allowed_from_ip():
                self._send_text(HTTPStatus.FORBIDDEN, "Remote admin is disabled.")
                return
            if not admin_configured():
                self._redirect("/admin/register")
                return
            self._send_html(login_page())
            return

        if path == "/admin/register":
            if not self._admin_allowed_from_ip():
                self._send_text(HTTPStatus.FORBIDDEN, "Remote admin is disabled.")
                return
            if admin_configured():
                self._redirect("/admin/login")
                return
            self._send_html(setup_page())
            return

        if path.startswith("/admin"):
            if not self._require_admin():
                return
            with db_connect() as conn:
                if path == "/admin":
                    self._send_html(render_dashboard(conn, query))
                elif path == "/admin/apps":
                    self._send_html(render_apps(conn, query))
                elif path == "/admin/keys":
                    self._send_html(render_keys(conn, query))
                elif path.startswith("/admin/app/"):
                    app_id = unquote(path[len("/admin/app/") :])
                    tab = query.get("tab", ["overview"])[0]
                    self._send_html(render_app_console(conn, app_id, tab, query))
                elif path == "/admin/bans":
                    self._send_html(render_global_bans(conn, query))
                elif path == "/admin/events":
                    self._send_html(render_events(conn, query))
                elif path == "/admin/protection":
                    self._send_html(render_protection_monitor(conn, query))
                elif path == "/admin/api":
                    self._send_html(render_api_console())
                elif path == "/admin/config":
                    self._send_html(render_config_console())
                elif path == "/admin/docs":
                    self._send_html(render_docs())
                else:
                    self._send_text(HTTPStatus.NOT_FOUND, "Not found")
            return

        self._send_text(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path in {"/api/v1/verify", "/api/v1/check", "/api/v1/activate"}:
            if not api_runtime_enabled():
                self._send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"ok": False, "status": "api_stopped", "message": "API runtime is stopped from the admin console"},
                )
                return
            data = self._parse_body()
            data["_user_agent"] = self.headers.get("User-Agent", "")
            with db_connect() as conn:
                result = verify_license(
                    conn,
                    str(data.get("key", "")),
                    str(data.get("app_id", "default")),
                    str(data.get("hwid", "")),
                    self._client_ip(str(data.get("ip", ""))),
                    self.headers.get("X-App-Secret"),
                    self._client_country(data),
                    self.headers.get("X-KeyBase-Timestamp") or data.get("timestamp"),
                    self.headers.get("X-KeyBase-Nonce") or data.get("nonce"),
                    self.headers.get("X-KeyBase-Signature") or data.get("signature"),
                    self.headers.get("X-KeyBase-Session") or data.get("session_token"),
                    self.headers.get("X-Client-Hash") or data.get("client_hash"),
                    self.headers.get("X-Client-Flags") or data.get("client_flags"),
                    self.headers.get("X-Build-Id") or data.get("build_id"),
                    str(data.get("version", "")),
                    data,
                )
                conn.commit()
            status = HTTPStatus.OK
            if result.get("status") == "bad_app_secret" or result.get("status") in PROTECTION_REASON_CODES:
                status = HTTPStatus.FORBIDDEN
            self._send_json(status, result)
            return

        if path == "/admin/login":
            if not self._admin_allowed_from_ip():
                self._send_text(HTTPStatus.FORBIDDEN, "Remote admin is disabled.")
                return
            data = self._parse_body()
            if not admin_configured():
                self._redirect("/admin/register")
                return
            if verify_admin_password(str(data.get("password", ""))):
                cookie = f"{COOKIE_NAME}={make_session_cookie()}; HttpOnly; SameSite=Strict; Path=/"
                self._send(HTTPStatus.SEE_OTHER, b"", "text/plain; charset=utf-8", {"Location": "/admin", "Set-Cookie": cookie})
            else:
                self._send_html(login_page("Wrong password"), HTTPStatus.UNAUTHORIZED)
            return

        if path == "/admin/register":
            if not self._admin_allowed_from_ip():
                self._send_text(HTTPStatus.FORBIDDEN, "Remote admin is disabled.")
                return
            if admin_configured():
                self._redirect("/admin/login")
                return
            data = self._parse_body()
            ok, message = register_admin(
                str(data.get("username", "")),
                str(data.get("password", "")),
                str(data.get("password_confirm", "")),
            )
            if ok:
                cookie = f"{COOKIE_NAME}={make_session_cookie()}; HttpOnly; SameSite=Strict; Path=/"
                self._send(HTTPStatus.SEE_OTHER, b"", "text/plain; charset=utf-8", {"Location": "/admin", "Set-Cookie": cookie})
            else:
                self._send_html(setup_page(message), HTTPStatus.BAD_REQUEST)
            return

        if path == "/admin/logout":
            cookie = f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            self._send(HTTPStatus.SEE_OTHER, b"", "text/plain; charset=utf-8", {"Location": "/admin/login", "Set-Cookie": cookie})
            return

        if path.startswith("/admin"):
            if not self._require_admin():
                return
            data = self._parse_body()
            return_to = safe_return(str(data.get("return_to", "")), "/admin")
            with db_connect() as conn:
                if path == "/admin/apps/create":
                    app_id = self._admin_create_app(conn, data)
                    conn.commit()
                    self._redirect(app_href(app_id) if app_id else "/admin/apps")
                elif path == "/admin/apps/update":
                    self._admin_update_app(conn, data)
                    conn.commit()
                    self._redirect(return_to)
                elif path == "/admin/apps/delete":
                    location = self._admin_delete_app(conn, data)
                    conn.commit()
                    self._redirect(location or return_to)
                elif path == "/admin/security/password":
                    rotated = self._admin_change_password(conn, data)
                    conn.commit()
                    if rotated:
                        cookie = f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                        self._send(
                            HTTPStatus.SEE_OTHER,
                            b"",
                            "text/plain; charset=utf-8",
                            {"Location": "/admin/login", "Set-Cookie": cookie},
                        )
                    else:
                        self._redirect(return_to)
                elif path == "/admin/keys/create":
                    self._admin_create_keys(conn, data)
                    conn.commit()
                    self._redirect(return_to if return_to != "/admin" else app_href(str(data.get("app_id", "default")), "keys"))
                elif path == "/admin/keys/update":
                    self._admin_update_key(conn, data)
                    conn.commit()
                    self._redirect(return_to)
                elif path == "/admin/keys/reset-devices":
                    self._admin_reset_key_devices(conn, data)
                    conn.commit()
                    self._redirect(return_to)
                elif path == "/admin/keys/delete":
                    self._admin_delete_key(conn, data)
                    conn.commit()
                    self._redirect(return_to)
                elif path == "/admin/bans/create":
                    self._admin_create_ban(conn, data)
                    conn.commit()
                    self._redirect(return_to)
                elif path == "/admin/bans/delete":
                    if self._confirm_password(conn, data, "Remove ban"):
                        conn.execute("DELETE FROM bans WHERE id = ?", (as_int(data.get("id"), 0),))
                        log_event(conn, "admin", None, None, None, self._client_ip(), "ban_removed", "Ban removed")
                    conn.commit()
                    self._redirect(return_to)
                elif path == "/admin/config/save":
                    if self._confirm_password(conn, data, "Update config"):
                        ok, message = save_config_text(str(data.get("config_text", "")))
                        log_event(conn, "admin", None, None, None, self._client_ip(), "config_saved" if ok else "config_rejected", message)
                    conn.commit()
                    self._redirect(return_to if return_to != "/admin" else "/admin/config")
                elif path == "/admin/api/process":
                    status, message = set_api_runtime_state(str(data.get("action", "status")), self._client_ip())
                    log_event(conn, "admin", None, None, None, self._client_ip(), status, message)
                    conn.commit()
                    self._redirect(return_to if return_to != "/admin" else "/admin/api")
                else:
                    self._send_text(HTTPStatus.NOT_FOUND, "Not found")
            return

        self._send_text(HTTPStatus.NOT_FOUND, "Not found")

    def _confirm_password(
        self,
        conn: sqlite3.Connection,
        data: dict[str, Any],
        action: str,
        app_id: str | None = None,
        key_text: str | None = None,
    ) -> bool:
        password = str(data.get("confirm_password", ""))
        if verify_admin_password(password):
            return True
        log_event(
            conn,
            "admin",
            app_id,
            key_text,
            None,
            self._client_ip(),
            "password_required",
            f"{action} blocked: admin password confirmation failed",
        )
        return False

    def _admin_change_password(self, conn: sqlite3.Connection, data: dict[str, Any]) -> bool:
        ok, message = change_admin_password(
            str(data.get("current_password", "")),
            str(data.get("new_password", "")),
            str(data.get("new_password_confirm", "")),
        )
        log_event(conn, "admin", None, None, None, self._client_ip(), "password_changed" if ok else "password_rejected", message)
        return ok

    def _admin_delete_app(self, conn: sqlite3.Connection, data: dict[str, Any]) -> str | None:
        app_id = str(data.get("app_id", "")).strip()
        confirm_app_id = normalize_app_id(str(data.get("confirm_app_id", "")))
        app = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app:
            return "/admin/apps"
        if confirm_app_id != app_id:
            log_event(conn, "admin", app_id, None, None, self._client_ip(), "app_delete_blocked", "App deletion blocked: app id confirmation mismatch")
            return app_href(app_id, "settings")
        if not self._confirm_password(conn, data, "Delete app", app_id):
            return app_href(app_id, "settings")
        conn.execute("DELETE FROM license_keys WHERE app_id = ?", (app_id,))
        conn.execute("DELETE FROM bans WHERE app_id = ?", (app_id,))
        conn.execute("DELETE FROM apps WHERE app_id = ?", (app_id,))
        log_event(conn, "admin", app_id, None, None, self._client_ip(), "app_deleted", f"Application {app_id} deleted")
        return "/admin/apps"

    def _admin_delete_key(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        key_id = as_int(data.get("id"), 0)
        key = conn.execute("SELECT * FROM license_keys WHERE id = ?", (key_id,)).fetchone()
        if not key:
            return
        if not self._confirm_password(conn, data, "Delete key", key["app_id"], key["key_text"]):
            return
        conn.execute("DELETE FROM license_keys WHERE id = ?", (key_id,))
        log_event(conn, "admin", key["app_id"], key["key_text"], None, self._client_ip(), "key_deleted", "Key deleted")

    def _admin_create_app(self, conn: sqlite3.Connection, data: dict[str, Any]) -> str | None:
        app_id = normalize_app_id(str(data.get("app_id", "")))
        name = str(data.get("name", "")).strip() or app_id
        secret = str(data.get("secret", "")).strip()
        if not app_id:
            return None
        if conn.execute("SELECT 1 FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            return None
        conn.execute(
            """
            INSERT INTO apps(app_id, name, secret_hash, require_secret, status, settings_json, created_at, updated_at)
            VALUES(?, ?, ?, ?, 'active', '{}', ?, ?)
            """,
            (app_id, name, sha256_text(secret) if secret else None, 1 if secret else 0, utc_now(), utc_now()),
        )
        log_event(conn, "admin", app_id, None, None, self._client_ip(), "app_created", f"App {app_id} created")
        return app_id

    def _admin_update_app(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        app_id = str(data.get("app_id", "")).strip()
        app = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app:
            return
        name = str(data.get("name", "")).strip() or app["name"]
        status = str(data.get("status", "active")).strip()
        status = status if status in APP_STATUSES else "active"
        if str(data.get("secret_action", "0")) == "1":
            if not self._confirm_password(conn, data, "Update app secret", app_id):
                return
            require_secret = 1 if str(data.get("require_secret", "0")) == "1" else 0
            secret_mode = str(data.get("secret_mode", "keep"))
            secret = str(data.get("secret", "")).strip()
            secret_hash = app["secret_hash"]
            if secret_mode == "replace" and secret:
                secret_hash = sha256_text(secret)
                require_secret = 1
            elif secret_mode == "clear":
                secret_hash = None
                require_secret = 0
            conn.execute(
                """
                UPDATE apps
                SET require_secret = ?, secret_hash = ?, updated_at = ?
                WHERE app_id = ?
                """,
                (require_secret, secret_hash, utc_now(), app_id),
            )
            log_event(conn, "admin", app_id, None, None, self._client_ip(), "app_secret_updated", "App secret settings updated")
            return
        settings = app_settings(app)
        settings["default_prefix"] = "".join(ch for ch in clean_text(data.get("default_prefix", ""), 8).upper() if ch.isalnum())
        for setting_name in (
            "require_signed_requests",
            "reject_replay",
            "require_session_token",
            "bind_first_ip",
            "require_client_integrity",
            "block_debug_flags",
        ):
            settings[setting_name] = str(data.get(setting_name, "0")) == "1"
        if settings["require_session_token"]:
            settings["require_signed_requests"] = True
            settings["reject_replay"] = True
        settings["max_clock_skew_seconds"] = as_int(data.get("max_clock_skew_seconds"), 120, minimum=15, maximum=3600)
        settings["session_minutes"] = as_int(data.get("session_minutes"), 60, minimum=5, maximum=1440)
        settings["max_ip_changes"] = as_int(data.get("max_ip_changes"), 20, minimum=0, maximum=10000)
        settings["allowed_client_hashes"] = clean_text(data.get("allowed_client_hashes", ""), 4000).lower()
        settings["min_client_version"] = clean_text(data.get("min_client_version", ""), 32)
        conn.execute(
            """
            UPDATE apps
            SET name = ?, status = ?, settings_json = ?, updated_at = ?
            WHERE app_id = ?
            """,
            (name, status, json.dumps(settings), utc_now(), app_id),
        )
        log_event(conn, "admin", app_id, None, None, self._client_ip(), "app_updated", "App settings updated")

    def _admin_create_keys(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        app_id = str(data.get("app_id", "default")).strip() or "default"
        if not conn.execute("SELECT id FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            return
        count = as_int(data.get("count"), 1, minimum=1, maximum=200)
        prefix = str(data.get("prefix", "KB")).strip() or "KB"
        max_devices = as_int(data.get("max_devices"), 1, minimum=1, maximum=999)
        duration_seconds = duration_seconds_from_form(data.get("duration_value"), data.get("duration_unit"))
        note = str(data.get("note", "")).strip() or None
        for _ in range(count):
            for _attempt in range(20):
                key_text = make_license_key(prefix)
                try:
                    conn.execute(
                        """
                        INSERT INTO license_keys(key_text, app_id, status, note, max_devices, expires_at, duration_seconds, activated_at, uses, created_at)
                        VALUES(?, ?, 'active', ?, ?, NULL, ?, NULL, 0, ?)
                        """,
                        (key_text, app_id, note, max_devices, duration_seconds, utc_now()),
                    )
                    log_event(conn, "admin", app_id, key_text, None, self._client_ip(), "key_created", f"Key created: {format_duration(duration_seconds)} after first activation")
                    break
                except db.DatabaseIntegrityError:
                    continue

    def _admin_update_key(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        key_id = as_int(data.get("id"), 0)
        key = conn.execute("SELECT * FROM license_keys WHERE id = ?", (key_id,)).fetchone()
        if not key:
            return
        if not self._confirm_password(conn, data, "Update key", key["app_id"], key["key_text"]):
            return
        status = str(data.get("status", "active")).strip()
        status = status if status in KEY_STATUSES else "disabled"
        max_devices = as_int(data.get("max_devices"), 1, minimum=1, maximum=999)
        duration_seconds = duration_seconds_from_form(data.get("duration_value"), data.get("duration_unit"))
        activated_at = row_value(key, "activated_at")
        expires_at = expires_at_from_duration(activated_at, duration_seconds) if activated_at else None
        note = str(data.get("note", "")).strip() or None
        conn.execute(
            """
            UPDATE license_keys
            SET status = ?, max_devices = ?, expires_at = ?, duration_seconds = ?, note = ?
            WHERE id = ?
            """,
            (status, max_devices, expires_at, duration_seconds, note, key_id),
        )
        log_event(conn, "admin", key["app_id"], key["key_text"], None, self._client_ip(), "key_updated", f"Key set to {status}, duration {format_duration(duration_seconds)}")

    def _admin_reset_key_devices(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        key_id = as_int(data.get("id"), 0)
        key = conn.execute("SELECT * FROM license_keys WHERE id = ?", (key_id,)).fetchone()
        if not key:
            return
        if not self._confirm_password(conn, data, "Reset key devices", key["app_id"], key["key_text"]):
            return
        conn.execute("DELETE FROM activations WHERE key_id = ?", (key_id,))
        log_event(conn, "admin", key["app_id"], key["key_text"], None, self._client_ip(), "devices_reset", "Key devices reset")

    def _admin_create_ban(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        app_id = str(data.get("app_id", "")).strip() or None
        if app_id and not conn.execute("SELECT id FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            return
        kind = str(data.get("kind", "ip")).strip().lower()
        if kind not in BAN_KINDS:
            kind = "ip"
        value = str(data.get("value", "")).strip()
        if kind == "hwid":
            value = normalize_hwid(value)
        elif kind == "country":
            value = normalize_country(value)
        reason = str(data.get("reason", "")).strip() or None
        if not value:
            return

        if app_id:
            exists = conn.execute(
                "SELECT id FROM bans WHERE app_id = ? AND kind = ? AND value = ?",
                (app_id, kind, value),
            ).fetchone()
        else:
            exists = conn.execute(
                "SELECT id FROM bans WHERE app_id IS NULL AND kind = ? AND value = ?",
                (kind, value),
            ).fetchone()
        if exists:
            return

        conn.execute(
            """
            INSERT INTO bans(app_id, kind, value, reason, created_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (app_id, kind, value, reason, utc_now()),
        )
        scope = "global" if app_id is None else app_id
        log_event(
            conn,
            "admin",
            app_id,
            None,
            value if kind == "hwid" else None,
            self._client_ip(),
            "ban_created",
            f"{kind} ban created in {scope}",
            country=value if kind == "country" else None,
        )


def main() -> None:
    from keybase.app import run

    run()


if __name__ == "__main__":
    main()
