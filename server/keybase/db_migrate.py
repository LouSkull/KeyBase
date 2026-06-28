from __future__ import annotations

import argparse
import json
from typing import Any

from . import core, db


def _settings_from_args(prefix: str, args: argparse.Namespace, fallback: db.DatabaseSettings | None) -> db.DatabaseSettings:
    fragment = db.settings_to_config(fallback, core.ROOT_DIR) if fallback else {
        "backend": "sqlite",
        "url": "",
        "sqlite_path": str(core._default_sqlite_path()),
        "host": "",
        "port": "",
        "name": "",
        "user": "",
        "password": "",
        "ssl_mode": "prefer",
        "connect_timeout_seconds": 10,
    }
    for field in ("backend", "url", "sqlite_path", "host", "port", "name", "user", "password", "ssl_mode"):
        value = getattr(args, f"{prefix}_{field}")
        if value not in (None, ""):
            fragment[field] = value
    return db.settings_from_config({"database": fragment}, core.ROOT_DIR, core._default_sqlite_path())


def _write_target_config(settings: db.DatabaseSettings) -> None:
    loaded: dict[str, Any] = {}
    if core.CONFIG_PATH.exists():
        loaded = core.parse_simple_yaml(core.CONFIG_PATH.read_text(encoding="utf-8"))
    loaded["database"] = db.settings_to_config(settings, core.ROOT_DIR)
    merged = core.deep_merge(core.DEFAULT_CONFIG, loaded)
    merged["database"] = loaded["database"]
    core.CONFIG_PATH.write_text(core.dump_simple_yaml(merged).rstrip() + "\n", encoding="utf-8")
    core.reload_config()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Migrate Key Base data between database backends.")
    for prefix, label in (("from", "Source"), ("to", "Target")):
        group = parser.add_argument_group(f"{label} database")
        group.add_argument(f"--{prefix}-backend", choices=["sqlite", "postgresql", "postgres", "mysql", "mariadb"])
        group.add_argument(f"--{prefix}-url")
        group.add_argument(f"--{prefix}-sqlite-path")
        group.add_argument(f"--{prefix}-host")
        group.add_argument(f"--{prefix}-port", type=int)
        group.add_argument(f"--{prefix}-name")
        group.add_argument(f"--{prefix}-user")
        group.add_argument(f"--{prefix}-password")
        group.add_argument(f"--{prefix}-ssl-mode")
    parser.add_argument("--write-config", action="store_true", help="Write the target database settings into config.yml after a successful migration.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    core.reload_config()
    source = _settings_from_args("from", args, core.current_database_settings())
    target = _settings_from_args("to", args, None)
    if db.database_signature(source) == db.database_signature(target):
        parser.error("Source and target databases are identical.")
    summary = db.migrate_between_databases(source, target, core.utc_now())
    if args.write_config:
        _write_target_config(target)
    print(json.dumps(summary, indent=2))
    if args.write_config:
        print("config.yml updated with target database settings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
