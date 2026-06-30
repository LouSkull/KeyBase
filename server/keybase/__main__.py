"""Run Key Base with `python -m keybase`."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"db-migrate", "migrate-db"}:
        from .db_migrate import main as migrate_main

        return int(migrate_main(args[1:]) or 0)
    from .app import run

    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
