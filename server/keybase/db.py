from __future__ import annotations

import importlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, unquote, urlparse


SUPPORTED_BACKENDS = {"sqlite", "postgresql", "mysql"}
BACKEND_ALIASES = {
    "sqlite3": "sqlite",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "psql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mysql",
}
SCHEMA_VERSION = 2
EXPORT_VERSION = 1
DATABASE_TABLES = (
    "apps",
    "license_keys",
    "activations",
    "bans",
    "events",
    "request_nonces",
    "system_flags",
    "webhook_endpoints",
    "webhook_deliveries",
)
DATABASE_IMPORT_CLEAR_ORDER = (
    "webhook_deliveries",
    "activations",
    "request_nonces",
    "events",
    "bans",
    "license_keys",
    "webhook_endpoints",
    "system_flags",
    "apps",
)
DATABASE_IMPORT_ORDER = (
    "apps",
    "license_keys",
    "activations",
    "bans",
    "events",
    "request_nonces",
    "system_flags",
    "webhook_endpoints",
    "webhook_deliveries",
)
DATABASE_TABLE_ORDER_BY = {
    "apps": "id",
    "license_keys": "id",
    "activations": "id",
    "bans": "id",
    "events": "id",
    "request_nonces": "id",
    "system_flags": "flag",
    "webhook_endpoints": "id",
    "webhook_deliveries": "id",
}
DATABASE_ID_TABLES = (
    "apps",
    "license_keys",
    "activations",
    "bans",
    "events",
    "request_nonces",
    "webhook_deliveries",
)


class DatabaseError(Exception):
    pass


class DatabaseConfigurationError(DatabaseError):
    pass


class DatabaseDriverUnavailableError(DatabaseError):
    pass


class DatabaseIntegrityError(DatabaseError):
    pass


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_backend(value: str) -> str:
    backend = str(value or "sqlite").strip().lower()
    backend = BACKEND_ALIASES.get(backend, backend)
    if backend not in SUPPORTED_BACKENDS:
        raise DatabaseConfigurationError(f"Unsupported database backend: {value}")
    return backend


def _env_or_default(name: str, default: Any = "") -> Any:
    return default if name not in {} else default


@dataclass(frozen=True)
class DatabaseSettings:
    backend: str
    url: str = ""
    sqlite_path: str = ""
    host: str = ""
    port: int | None = None
    name: str = ""
    user: str = ""
    password: str = ""
    ssl_mode: str = "prefer"
    connect_timeout_seconds: int = 10

    @property
    def sqlite_file(self) -> Path | None:
        return Path(self.sqlite_path) if self.backend == "sqlite" and self.sqlite_path else None

    def masked_dsn(self) -> str:
        if self.backend == "sqlite":
            return str(self.sqlite_file or "")
        user = self.user or "user"
        host = self.host or "localhost"
        port = f":{self.port}" if self.port else ""
        name = f"/{self.name}" if self.name else ""
        return f"{self.backend}://{user}@{host}{port}{name}"


class DBRow(dict[str, Any]):
    pass


def row_to_dict(row: Any, columns: Sequence[str]) -> DBRow:
    if row is None:
        return DBRow()
    if isinstance(row, DBRow):
        return row
    if isinstance(row, sqlite3.Row):
        return DBRow({key: row[key] for key in row.keys()})
    if isinstance(row, Mapping):
        return DBRow(dict(row))
    return DBRow({columns[index]: row[index] for index in range(len(columns))})


class CursorWrapper:
    def __init__(self, cursor: Any, backend: str) -> None:
        self._cursor = cursor
        self.backend = backend

    @property
    def rowcount(self) -> int:
        return int(getattr(self._cursor, "rowcount", -1))

    @property
    def lastrowid(self) -> Any:
        if hasattr(self._cursor, "lastrowid"):
            return getattr(self._cursor, "lastrowid")
        return None

    def _columns(self) -> list[str]:
        description = getattr(self._cursor, "description", None) or []
        return [str(item[0]) for item in description]

    def fetchone(self) -> DBRow | None:
        row = self._cursor.fetchone()
        if row is None:
            return None
        return row_to_dict(row, self._columns())

    def fetchall(self) -> list[DBRow]:
        columns = self._columns()
        return [row_to_dict(row, columns) for row in self._cursor.fetchall()]

    def close(self) -> None:
        if hasattr(self._cursor, "close"):
            self._cursor.close()


class ConnectionWrapper:
    def __init__(
        self,
        raw_connection: Any,
        settings: DatabaseSettings,
        placeholder: str,
        integrity_errors: tuple[type[BaseException], ...],
        general_errors: tuple[type[BaseException], ...],
    ) -> None:
        self._raw_connection = raw_connection
        self.settings = settings
        self.backend = settings.backend
        self.placeholder = placeholder
        self._integrity_errors = integrity_errors
        self._general_errors = general_errors

    def _translate(self, exc: Exception) -> DatabaseError:
        if isinstance(exc, self._integrity_errors):
            return DatabaseIntegrityError(str(exc))
        return DatabaseError(str(exc))

    def _prepare_sql(self, sql: str) -> str:
        if self.placeholder == "?":
            return sql
        return replace_qmark_placeholders(sql, self.placeholder)

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> CursorWrapper:
        prepared = self._prepare_sql(sql)
        values: Sequence[Any] = tuple(params or ())
        try:
            cursor = self._raw_connection.cursor()
            cursor.execute(prepared, values)
            return CursorWrapper(cursor, self.backend)
        except Exception as exc:
            raise self._translate(exc) from exc

    def executemany(self, sql: str, params_seq: Iterable[Sequence[Any]]) -> CursorWrapper:
        prepared = self._prepare_sql(sql)
        batch = [tuple(item) for item in params_seq]
        try:
            cursor = self._raw_connection.cursor()
            cursor.executemany(prepared, batch)
            return CursorWrapper(cursor, self.backend)
        except Exception as exc:
            raise self._translate(exc) from exc

    def executescript(self, script: str) -> None:
        for statement in split_sql_statements(script):
            if statement.strip():
                cursor = self.execute(statement)
                cursor.close()

    def commit(self) -> None:
        try:
            self._raw_connection.commit()
        except Exception as exc:
            raise self._translate(exc) from exc

    def rollback(self) -> None:
        try:
            self._raw_connection.rollback()
        except Exception as exc:
            raise self._translate(exc) from exc

    def close(self) -> None:
        try:
            self._raw_connection.close()
        except Exception as exc:
            raise self._translate(exc) from exc

    def __enter__(self) -> ConnectionWrapper:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()
        return False


def replace_qmark_placeholders(sql: str, placeholder: str) -> str:
    if placeholder == "?":
        return sql
    result: list[str] = []
    quote = ""
    index = 0
    in_line_comment = False
    in_block_comment = False
    while index < len(sql):
        char = sql[index]
        nxt = sql[index + 1] if index + 1 < len(sql) else ""
        if in_line_comment:
            result.append(char)
            if char == "\n":
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            result.append(char)
            if char == "*" and nxt == "/":
                result.append(nxt)
                index += 2
                in_block_comment = False
                continue
            index += 1
            continue
        if quote:
            result.append(char)
            if char == quote:
                if quote == "'" and nxt == "'":
                    result.append(nxt)
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if char == "-" and nxt == "-":
            result.append(char)
            result.append(nxt)
            index += 2
            in_line_comment = True
            continue
        if char == "/" and nxt == "*":
            result.append(char)
            result.append(nxt)
            index += 2
            in_block_comment = True
            continue
        if char in {"'", '"'}:
            quote = char
            result.append(char)
            index += 1
            continue
        if char == "?":
            result.append(placeholder)
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def split_sql_statements(script: str) -> list[str]:
    statements: list[str] = []
    chunk: list[str] = []
    quote = ""
    index = 0
    in_line_comment = False
    in_block_comment = False
    while index < len(script):
        char = script[index]
        nxt = script[index + 1] if index + 1 < len(script) else ""
        if in_line_comment:
            chunk.append(char)
            if char == "\n":
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            chunk.append(char)
            if char == "*" and nxt == "/":
                chunk.append(nxt)
                index += 2
                in_block_comment = False
                continue
            index += 1
            continue
        if quote:
            chunk.append(char)
            if char == quote:
                if quote == "'" and nxt == "'":
                    chunk.append(nxt)
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if char == "-" and nxt == "-":
            chunk.append(char)
            chunk.append(nxt)
            index += 2
            in_line_comment = True
            continue
        if char == "/" and nxt == "*":
            chunk.append(char)
            chunk.append(nxt)
            index += 2
            in_block_comment = True
            continue
        if char in {"'", '"'}:
            quote = char
            chunk.append(char)
            index += 1
            continue
        if char == ";":
            statement = "".join(chunk).strip()
            if statement:
                statements.append(statement)
            chunk = []
            index += 1
            continue
        chunk.append(char)
        index += 1
    tail = "".join(chunk).strip()
    if tail:
        statements.append(tail)
    return statements


def _parse_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    backend = normalize_backend(parsed.scheme)
    query = {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
    path = unquote(parsed.path or "")
    if backend == "sqlite":
        sqlite_path = path
        if sqlite_path.startswith("/") and len(sqlite_path) >= 3 and sqlite_path[2] == ":":
            sqlite_path = sqlite_path[1:]
        return {
            "backend": backend,
            "url": url,
            "sqlite_path": sqlite_path or unquote(parsed.netloc),
            "host": "",
            "port": None,
            "name": "",
            "user": "",
            "password": "",
            "ssl_mode": query.get("sslmode", query.get("ssl_mode", "prefer")),
        }
    return {
        "backend": backend,
        "url": url,
        "sqlite_path": "",
        "host": parsed.hostname or "",
        "port": parsed.port,
        "name": unquote(path.lstrip("/")),
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "ssl_mode": query.get("sslmode", query.get("ssl_mode", "prefer")),
    }


def settings_from_config(config: Mapping[str, Any], root_dir: Path, default_sqlite_path: Path) -> DatabaseSettings:
    db_config = config.get("database", {})
    if not isinstance(db_config, Mapping):
        db_config = {}
    raw_backend = str(db_config.get("backend", "sqlite") or "sqlite")
    backend = normalize_backend(raw_backend)
    url = str(db_config.get("url", "") or "").strip()
    parsed_url: dict[str, Any] = {}
    if url:
        parsed_url = _parse_url(url)
        backend = parsed_url["backend"]
    sqlite_path_raw = str(parsed_url.get("sqlite_path") or db_config.get("sqlite_path") or default_sqlite_path)
    sqlite_path = Path(sqlite_path_raw)
    if backend == "sqlite" and not sqlite_path.is_absolute():
        sqlite_path = root_dir / sqlite_path
    port_raw = parsed_url.get("port", db_config.get("port"))
    port = int(port_raw) if str(port_raw or "").strip() else None
    if port is None and backend == "postgresql":
        port = 5432
    if port is None and backend == "mysql":
        port = 3306
    timeout_raw = db_config.get("connect_timeout_seconds", 10)
    try:
        timeout = max(1, min(60, int(timeout_raw)))
    except (TypeError, ValueError):
        timeout = 10
    return DatabaseSettings(
        backend=backend,
        url=url,
        sqlite_path=str(sqlite_path),
        host=str(parsed_url.get("host") or db_config.get("host", "") or "").strip(),
        port=port,
        name=str(parsed_url.get("name") or db_config.get("name", "") or "").strip(),
        user=str(parsed_url.get("user") or db_config.get("user", "") or "").strip(),
        password=str(parsed_url.get("password") or db_config.get("password", "") or ""),
        ssl_mode=str(parsed_url.get("ssl_mode") or db_config.get("ssl_mode", "prefer") or "prefer").strip() or "prefer",
        connect_timeout_seconds=timeout,
    )


def settings_to_config(settings: DatabaseSettings, root_dir: Path) -> dict[str, Any]:
    sqlite_path = settings.sqlite_path
    try:
        sqlite_path = str(Path(sqlite_path).resolve().relative_to(root_dir.resolve()))
    except Exception:
        sqlite_path = settings.sqlite_path
    return {
        "backend": settings.backend,
        "url": settings.url,
        "sqlite_path": sqlite_path,
        "host": settings.host,
        "port": settings.port or "",
        "name": settings.name,
        "user": settings.user,
        "password": settings.password,
        "ssl_mode": settings.ssl_mode,
        "connect_timeout_seconds": settings.connect_timeout_seconds,
    }


def database_label(settings: DatabaseSettings) -> str:
    if settings.backend == "sqlite":
        return str(settings.sqlite_file or settings.sqlite_path)
    return settings.masked_dsn()


def database_signature(settings: DatabaseSettings) -> tuple[Any, ...]:
    return (
        settings.backend,
        settings.url,
        settings.sqlite_path,
        settings.host,
        settings.port,
        settings.name,
        settings.user,
        settings.ssl_mode,
    )


def _import_optional(name: str) -> Any | None:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        return None


def _connect_sqlite(settings: DatabaseSettings) -> ConnectionWrapper:
    sqlite_path = settings.sqlite_file
    if sqlite_path is None:
        raise DatabaseConfigurationError("SQLite backend requires database.sqlite_path")
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(sqlite_path, timeout=settings.connect_timeout_seconds)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA foreign_keys = ON")
    return ConnectionWrapper(raw, settings, "?", (sqlite3.IntegrityError,), (sqlite3.Error,))


def _connect_postgresql(settings: DatabaseSettings) -> ConnectionWrapper:
    psycopg = _import_optional("psycopg")
    if psycopg is not None:
        kwargs: dict[str, Any]
        if settings.url:
            kwargs = {"conninfo": settings.url}
        else:
            kwargs = {
                "host": settings.host,
                "port": settings.port,
                "dbname": settings.name,
                "user": settings.user,
                "password": settings.password,
                "connect_timeout": settings.connect_timeout_seconds,
                "sslmode": settings.ssl_mode,
            }
        raw = psycopg.connect(**kwargs)
        return ConnectionWrapper(raw, settings, "%s", (psycopg.IntegrityError,), (psycopg.Error,))
    psycopg2 = _import_optional("psycopg2")
    if psycopg2 is not None:
        if settings.url:
            raw = psycopg2.connect(settings.url, connect_timeout=settings.connect_timeout_seconds)
        else:
            raw = psycopg2.connect(
                host=settings.host,
                port=settings.port,
                dbname=settings.name,
                user=settings.user,
                password=settings.password,
                connect_timeout=settings.connect_timeout_seconds,
                sslmode=settings.ssl_mode,
            )
        return ConnectionWrapper(raw, settings, "%s", (psycopg2.IntegrityError,), (psycopg2.Error,))
    raise DatabaseDriverUnavailableError("PostgreSQL backend requires psycopg or psycopg2.")


def _connect_mysql(settings: DatabaseSettings) -> ConnectionWrapper:
    pymysql = _import_optional("pymysql")
    if pymysql is not None:
        if settings.url:
            parsed = _parse_url(settings.url)
            raw = pymysql.connect(
                host=parsed["host"],
                port=parsed["port"] or 3306,
                user=parsed["user"],
                password=parsed["password"],
                database=parsed["name"],
                connect_timeout=settings.connect_timeout_seconds,
                charset="utf8mb4",
                autocommit=False,
            )
        else:
            raw = pymysql.connect(
                host=settings.host,
                port=settings.port or 3306,
                user=settings.user,
                password=settings.password,
                database=settings.name,
                connect_timeout=settings.connect_timeout_seconds,
                charset="utf8mb4",
                autocommit=False,
            )
        return ConnectionWrapper(raw, settings, "%s", (pymysql.IntegrityError,), (pymysql.MySQLError,))
    mysql_connector = _import_optional("mysql.connector")
    if mysql_connector is not None:
        if settings.url:
            parsed = _parse_url(settings.url)
            raw = mysql_connector.connect(
                host=parsed["host"],
                port=parsed["port"] or 3306,
                user=parsed["user"],
                password=parsed["password"],
                database=parsed["name"],
                connection_timeout=settings.connect_timeout_seconds,
                autocommit=False,
            )
        else:
            raw = mysql_connector.connect(
                host=settings.host,
                port=settings.port or 3306,
                user=settings.user,
                password=settings.password,
                database=settings.name,
                connection_timeout=settings.connect_timeout_seconds,
                autocommit=False,
            )
        integrity = tuple(err for err in (getattr(mysql_connector, "IntegrityError", None),) if err)
        general = tuple(err for err in (getattr(mysql_connector, "Error", None), Exception) if err)
        return ConnectionWrapper(raw, settings, "%s", integrity or (Exception,), general)
    raise DatabaseDriverUnavailableError("MySQL backend requires pymysql or mysql-connector-python.")


def connect(settings: DatabaseSettings) -> ConnectionWrapper:
    backend = normalize_backend(settings.backend)
    if backend == "sqlite":
        return _connect_sqlite(settings)
    if backend == "postgresql":
        return _connect_postgresql(settings)
    if backend == "mysql":
        return _connect_mysql(settings)
    raise DatabaseConfigurationError(f"Unsupported database backend: {settings.backend}")


def identifier(name: str, backend: str) -> str:
    safe = str(name or "").strip()
    if not safe or not safe.replace("_", "").isalnum():
        raise DatabaseConfigurationError(f"Unsafe identifier: {name}")
    if backend == "mysql":
        return f"`{safe}`"
    return f'"{safe}"'


def table_exists(conn: ConnectionWrapper, table: str) -> bool:
    if conn.backend == "sqlite":
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        return row is not None
    if conn.backend == "postgresql":
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?",
            (table,),
        ).fetchone()
        return row is not None
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
        (table,),
    ).fetchone()
    return row is not None


def table_columns(conn: ConnectionWrapper, table: str) -> set[str]:
    if not table_exists(conn, table):
        return set()
    if conn.backend == "sqlite":
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if conn.backend == "postgresql":
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ?",
            (table,),
        ).fetchall()
        return {row["column_name"] for row in rows}
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?",
        (table,),
    ).fetchall()
    return {row["column_name"] for row in rows}


def table_sql(conn: ConnectionWrapper, table: str) -> str:
    if conn.backend == "sqlite":
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        return str((row or {}).get("sql", "") or "")
    if conn.backend == "postgresql":
        rows = conn.execute(
            """
            SELECT pg_get_constraintdef(c.oid) AS sql
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE t.relname = ? AND n.nspname = current_schema()
            """,
            (table,),
        ).fetchall()
        return "\n".join(str(row["sql"]) for row in rows if row.get("sql"))
    row = conn.execute(f"SHOW CREATE TABLE {identifier(table, conn.backend)}").fetchone()
    if not row:
        return ""
    for key in ("Create Table", "create table", "Create View"):
        if key in row:
            return str(row[key] or "")
    values = list(row.values())
    return str(values[-1] if values else "")


def add_column_if_missing(conn: ConnectionWrapper, table: str, column: str, definition: str) -> None:
    if column not in table_columns(conn, table):
        conn.execute(f"ALTER TABLE {identifier(table, conn.backend)} ADD COLUMN {definition}")


def schema_migration_table_statement(backend: str) -> str:
    if backend == "mysql":
        return """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version BIGINT PRIMARY KEY,
            applied_at VARCHAR(64) NOT NULL
        )
        """
    return """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version BIGINT PRIMARY KEY,
        applied_at VARCHAR(64) NOT NULL
    )
    """


def _id_column(backend: str) -> str:
    if backend == "sqlite":
        return "INTEGER PRIMARY KEY AUTOINCREMENT"
    if backend == "postgresql":
        return "BIGSERIAL PRIMARY KEY"
    return "BIGINT PRIMARY KEY AUTO_INCREMENT"


def schema_statements(backend: str) -> list[str]:
    pk = _id_column(backend)
    return [
        f"""
        CREATE TABLE IF NOT EXISTS apps (
            id {pk},
            app_id VARCHAR(64) NOT NULL UNIQUE,
            name VARCHAR(80) NOT NULL,
            secret_hash VARCHAR(128),
            require_secret INTEGER NOT NULL DEFAULT 0,
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            settings_json TEXT,
            created_at VARCHAR(64) NOT NULL,
            updated_at VARCHAR(64)
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS license_keys (
            id {pk},
            key_text VARCHAR(128) NOT NULL UNIQUE,
            app_id VARCHAR(64) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            note TEXT,
            max_devices INTEGER NOT NULL DEFAULT 1,
            expires_at VARCHAR(64),
            duration_seconds BIGINT,
            activated_at VARCHAR(64),
            subscription_level INTEGER NOT NULL DEFAULT 1,
            uses BIGINT NOT NULL DEFAULT 0,
            created_at VARCHAR(64) NOT NULL,
            last_seen_at VARCHAR(64)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_license_keys_app ON license_keys(app_id)",
        "CREATE INDEX IF NOT EXISTS idx_license_keys_status ON license_keys(status)",
        f"""
        CREATE TABLE IF NOT EXISTS activations (
            id {pk},
            key_id BIGINT NOT NULL,
            hwid VARCHAR(255) NOT NULL,
            ip VARCHAR(64),
            country VARCHAR(8),
            first_ip VARCHAR(64),
            ip_change_count INTEGER NOT NULL DEFAULT 0,
            session_token_hash VARCHAR(128),
            session_expires_at VARCHAR(64),
            first_client_hash VARCHAR(128),
            last_client_hash VARCHAR(128),
            last_build_id VARCHAR(255),
            last_security_flags TEXT,
            uses BIGINT NOT NULL DEFAULT 0,
            first_seen_at VARCHAR(64) NOT NULL,
            last_seen_at VARCHAR(64) NOT NULL,
            UNIQUE(key_id, hwid),
            FOREIGN KEY(key_id) REFERENCES license_keys(id) ON DELETE CASCADE
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_activations_hwid ON activations(hwid)",
        f"""
        CREATE TABLE IF NOT EXISTS bans (
            id {pk},
            app_id VARCHAR(64),
            kind VARCHAR(32) NOT NULL,
            value VARCHAR(255) NOT NULL,
            reason TEXT,
            created_at VARCHAR(64) NOT NULL
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS events (
            id {pk},
            event_type VARCHAR(64) NOT NULL,
            app_id VARCHAR(64),
            key_text VARCHAR(128),
            hwid VARCHAR(255),
            ip VARCHAR(64),
            country VARCHAR(8),
            status VARCHAR(64),
            message TEXT,
            created_at VARCHAR(64) NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_events_key_text ON events(key_text)",
        "CREATE INDEX IF NOT EXISTS idx_events_app_id ON events(app_id)",
        f"""
        CREATE TABLE IF NOT EXISTS request_nonces (
            id {pk},
            app_id VARCHAR(64) NOT NULL,
            key_text VARCHAR(128) NOT NULL,
            hwid VARCHAR(255) NOT NULL,
            nonce VARCHAR(255) NOT NULL,
            created_at VARCHAR(64) NOT NULL,
            UNIQUE(app_id, key_text, hwid, nonce)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_request_nonces_created_at ON request_nonces(created_at)",
        """
        CREATE TABLE IF NOT EXISTS system_flags (
            flag VARCHAR(64) PRIMARY KEY,
            created_at VARCHAR(64) NOT NULL,
            value TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS webhook_endpoints (
            id VARCHAR(64) PRIMARY KEY,
            app_id VARCHAR(64) NOT NULL,
            url TEXT NOT NULL,
            secret VARCHAR(128) NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            events TEXT NOT NULL,
            description TEXT,
            config_json TEXT,
            created_at VARCHAR(64) NOT NULL,
            last_triggered_at VARCHAR(64),
            last_status VARCHAR(64),
            last_response_status INTEGER
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id {pk},
            endpoint_id VARCHAR(64) NOT NULL,
            event_type VARCHAR(64) NOT NULL,
            payload_json TEXT NOT NULL,
            status VARCHAR(64) NOT NULL,
            attempt INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 4,
            next_retry_at VARCHAR(64),
            created_at VARCHAR(64) NOT NULL,
            delivered_at VARCHAR(64),
            response_status INTEGER,
            response_body TEXT,
            error TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_wh_deliveries_pending ON webhook_deliveries(status, next_retry_at)",
        "CREATE INDEX IF NOT EXISTS idx_wh_deliveries_endpoint ON webhook_deliveries(endpoint_id, created_at)",
    ]


def ensure_schema_migrations_table(conn: ConnectionWrapper) -> None:
    conn.execute(schema_migration_table_statement(conn.backend))


def get_applied_schema_versions(conn: ConnectionWrapper) -> set[int]:
    ensure_schema_migrations_table(conn)
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {int(row["version"]) for row in rows}


def record_schema_version(conn: ConnectionWrapper, version: int, applied_at: str) -> None:
    if conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (version,)).fetchone():
        conn.execute("UPDATE schema_migrations SET applied_at = ? WHERE version = ?", (applied_at, version))
    else:
        conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)", (version, applied_at))


def rebuild_bans_table_for_sqlite(conn: ConnectionWrapper) -> None:
    conn.execute("DROP TABLE IF EXISTS bans_old_migration")
    conn.execute("ALTER TABLE bans RENAME TO bans_old_migration")
    conn.execute(
        """
        CREATE TABLE bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id VARCHAR(64),
            kind VARCHAR(32) NOT NULL,
            value VARCHAR(255) NOT NULL,
            reason TEXT,
            created_at VARCHAR(64) NOT NULL
        )
        """
    )
    old_columns = table_columns(conn, "bans_old_migration")
    if "app_id" in old_columns:
        conn.execute(
            """
            INSERT INTO bans(id, app_id, kind, value, reason, created_at)
            SELECT id, app_id, kind, value, reason, created_at
            FROM bans_old_migration
            WHERE kind IN ('ip', 'hwid', 'country')
            """
        )
    else:
        conn.execute(
            """
            INSERT INTO bans(id, app_id, kind, value, reason, created_at)
            SELECT id, NULL, kind, value, reason, created_at
            FROM bans_old_migration
            WHERE kind IN ('ip', 'hwid', 'country')
            """
        )
    conn.execute("DROP TABLE bans_old_migration")


def apply_schema_v1(conn: ConnectionWrapper, applied_at: str) -> None:
    for statement in schema_statements(conn.backend):
        conn.execute(statement)
    app_columns = table_columns(conn, "apps")
    add_column_if_missing(conn, "apps", "status", "status VARCHAR(32) NOT NULL DEFAULT 'active'")
    add_column_if_missing(conn, "apps", "settings_json", "settings_json TEXT")
    add_column_if_missing(conn, "apps", "updated_at", "updated_at VARCHAR(64)")
    if app_columns:
        conn.execute("UPDATE apps SET status = 'active' WHERE status IS NULL OR status = ''")
        conn.execute("UPDATE apps SET settings_json = '{}' WHERE settings_json IS NULL OR settings_json = ''")
        conn.execute("UPDATE apps SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = ''")

    add_column_if_missing(conn, "license_keys", "duration_seconds", "duration_seconds BIGINT")
    add_column_if_missing(conn, "license_keys", "activated_at", "activated_at VARCHAR(64)")
    add_column_if_missing(conn, "license_keys", "subscription_level", "subscription_level INTEGER NOT NULL DEFAULT 1")

    ban_columns = table_columns(conn, "bans")
    if conn.backend == "sqlite":
        ban_sql = table_sql(conn, "bans").lower()
        if ban_columns and ("app_id" not in ban_columns or "'country'" not in ban_sql):
            rebuild_bans_table_for_sqlite(conn)
    elif ban_columns and "app_id" not in ban_columns:
        add_column_if_missing(conn, "bans", "app_id", "app_id VARCHAR(64)")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_scope ON bans(app_id, kind, value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_kind_value ON bans(kind, value)")

    add_column_if_missing(conn, "events", "country", "country VARCHAR(8)")

    activation_columns = table_columns(conn, "activations")
    if "first_ip" not in activation_columns:
        add_column_if_missing(conn, "activations", "first_ip", "first_ip VARCHAR(64)")
        conn.execute("UPDATE activations SET first_ip = ip WHERE first_ip IS NULL OR first_ip = ''")
    add_column_if_missing(conn, "activations", "ip_change_count", "ip_change_count INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(conn, "activations", "session_token_hash", "session_token_hash VARCHAR(128)")
    add_column_if_missing(conn, "activations", "session_expires_at", "session_expires_at VARCHAR(64)")
    add_column_if_missing(conn, "activations", "first_client_hash", "first_client_hash VARCHAR(128)")
    add_column_if_missing(conn, "activations", "last_client_hash", "last_client_hash VARCHAR(128)")
    add_column_if_missing(conn, "activations", "last_build_id", "last_build_id VARCHAR(255)")
    add_column_if_missing(conn, "activations", "last_security_flags", "last_security_flags TEXT")

    add_column_if_missing(conn, "system_flags", "value", "value TEXT")
    add_column_if_missing(conn, "webhook_endpoints", "app_id", "app_id VARCHAR(64) NOT NULL DEFAULT ''")
    add_column_if_missing(conn, "webhook_endpoints", "config_json", "config_json TEXT")
    conn.execute("UPDATE webhook_endpoints SET config_json = '{}' WHERE config_json IS NULL OR config_json = ''")
    record_schema_version(conn, 1, applied_at)


def apply_schema_v2(conn: ConnectionWrapper, applied_at: str) -> None:
    add_column_if_missing(conn, "activations", "country", "country VARCHAR(8)")

    rows = conn.execute(
        """
        SELECT a.id, a.ip, a.hwid, k.app_id, k.key_text
        FROM activations a
        JOIN license_keys k ON k.id = a.key_id
        WHERE a.country IS NULL OR a.country = ''
        """
    ).fetchall()
    for row in rows:
        match = conn.execute(
            """
            SELECT country
            FROM events
            WHERE event_type = 'verify'
              AND app_id = ?
              AND key_text = ?
              AND hwid = ?
              AND country IS NOT NULL
              AND country <> ''
            ORDER BY id DESC
            LIMIT 1
            """,
            (row["app_id"], row["key_text"], row["hwid"]),
        ).fetchone()
        if not match and row["ip"]:
            match = conn.execute(
                """
                SELECT country
                FROM events
                WHERE ip = ?
                  AND country IS NOT NULL
                  AND country <> ''
                ORDER BY id DESC
                LIMIT 1
                """,
                (row["ip"],),
            ).fetchone()
        if match and match["country"]:
            conn.execute("UPDATE activations SET country = ? WHERE id = ?", (match["country"], row["id"]))

    record_schema_version(conn, 2, applied_at)


def ensure_latest_schema(conn: ConnectionWrapper, applied_at: str) -> None:
    applied = get_applied_schema_versions(conn)
    if 1 not in applied or not table_exists(conn, "apps"):
        apply_schema_v1(conn, applied_at)
        applied = get_applied_schema_versions(conn)
    if 2 not in applied:
        apply_schema_v2(conn, applied_at)


def export_database(conn: ConnectionWrapper) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "format": "keybase-database-export",
        "version": EXPORT_VERSION,
        "backend": conn.backend,
        "tables": {},
    }
    for table in DATABASE_TABLES:
        if not table_exists(conn, table):
            payload["tables"][table] = []
            continue
        order_by = DATABASE_TABLE_ORDER_BY.get(table, "id")
        rows = conn.execute(f"SELECT * FROM {identifier(table, conn.backend)} ORDER BY {identifier(order_by, conn.backend)}").fetchall()
        payload["tables"][table] = [dict(row) for row in rows]
    return payload


def clear_database(conn: ConnectionWrapper) -> None:
    for table in DATABASE_IMPORT_CLEAR_ORDER:
        if table_exists(conn, table):
            conn.execute(f"DELETE FROM {identifier(table, conn.backend)}")


def import_database(conn: ConnectionWrapper, payload: Mapping[str, Any], clear_existing: bool = True) -> None:
    tables = payload.get("tables", {})
    if not isinstance(tables, Mapping):
        raise DatabaseError("Database import payload is missing tables.")
    if clear_existing:
        clear_database(conn)
    for table in DATABASE_IMPORT_ORDER:
        if not table_exists(conn, table):
            continue
        rows = tables.get(table, [])
        if not isinstance(rows, list) or not rows:
            continue
        columns = [str(col) for col in rows[0].keys()]
        sql = (
            f"INSERT INTO {identifier(table, conn.backend)} "
            f"({', '.join(identifier(col, conn.backend) for col in columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})"
        )
        conn.executemany(sql, [tuple(row.get(col) for col in columns) for row in rows if isinstance(row, Mapping)])
    sync_sequences(conn)


def sync_sequences(conn: ConnectionWrapper) -> None:
    if conn.backend == "sqlite":
        return
    if conn.backend == "postgresql":
        for table in DATABASE_ID_TABLES:
            if not table_exists(conn, table):
                continue
            conn.execute(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), COALESCE((SELECT MAX(id) FROM {identifier(table, conn.backend)}), 0) + 1, false)"
            )
        return
    for table in DATABASE_ID_TABLES:
        if not table_exists(conn, table):
            continue
        row = conn.execute(f"SELECT COALESCE(MAX(id), 0) AS max_id FROM {identifier(table, conn.backend)}").fetchone()
        next_id = int((row or {}).get("max_id", 0) or 0) + 1
        conn.execute(f"ALTER TABLE {identifier(table, conn.backend)} AUTO_INCREMENT = {next_id}")


def export_database_bytes(settings: DatabaseSettings) -> bytes:
    with connect(settings) as conn:
        ensure_latest_schema(conn, utc_now_text())
        payload = export_database(conn)
    return json.dumps(payload, indent=2).encode("utf-8")


def migrate_between_databases(source: DatabaseSettings, target: DatabaseSettings, applied_at: str) -> dict[str, Any]:
    with connect(source) as source_conn:
        ensure_latest_schema(source_conn, applied_at)
        export_payload = export_database(source_conn)
    with connect(target) as target_conn:
        ensure_latest_schema(target_conn, applied_at)
        import_database(target_conn, export_payload, clear_existing=True)
        target_conn.commit()
    counts: dict[str, int] = {}
    tables = export_payload.get("tables", {})
    if isinstance(tables, Mapping):
        for table, rows in tables.items():
            counts[str(table)] = len(rows) if isinstance(rows, list) else 0
    return {
        "source": database_label(source),
        "target": database_label(target),
        "tables": counts,
    }
