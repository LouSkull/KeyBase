# Key Base

Key Base is a self-hosted auth and license-key server with a built-in admin dashboard.

It is designed for managing applications, license keys, HWID/device binding, bans, backups, audit logs, webhooks, and API-based key provisioning from your own server.

## Features

- FastAPI-based license verification API
- Admin dashboard for apps, keys, bans, logs, backups, and webhooks
- License key activation, verification, suspension, revoke, delete, and device reset
- HWID/device binding with configurable max devices
- Application secrets and provisioning tokens
- Global and per-application bans by IP, HWID, and country
- Audit logs with IP and country visibility
- Bulk actions for management tables
- Server-side pagination with page size limits
- Backup creation, restore workflow, retention, and auto-backups
- Webhook delivery system with retries
- Risk-based protection for VPN, proxy, VM, debugger, and suspicious environments
- SQLite, PostgreSQL, and MySQL/MariaDB support

## Project Layout

```text
key-base/
  Server/        Main backend, dashboard, config, data, and run scripts
  Builder/       Builder-related project files
  Client-Test/   Sample/test client files
  test/          Test and scratch workspace
```

## Quick Start

### Windows

```bat
cd Server
run.bat
```

### Linux / macOS

```sh
cd Server
chmod +x run.sh
./run.sh
```

The server reads `Server/config.yml` and starts the admin/API runtime from that configuration.

## Configuration

Main config file:

```text
Server/config.yml
```

Important areas:

- `server` - host, port, mode
- `admin` - admin dashboard settings
- `api` - client API and proxy/IP handling
- `database` - SQLite/PostgreSQL/MySQL selection
- `backup` - backup directory, retention, auto backup
- `protection` - anti-VPN, anti-proxy, anti-VM, anti-debug risk settings

## Database Backends

Supported backends:

- SQLite
- PostgreSQL
- MySQL / MariaDB

Migration tooling is available in:

```text
Server/keybase/db_migrate.py
```

Always create a backup before migrating databases.

## Security Notes

- Do not expose the admin dashboard publicly unless you understand the risk.
- Use HTTPS or a trusted reverse proxy for public API traffic.
- Only trust proxy headers when clients cannot directly reach Key Base.
- Keep secrets, API tokens, provisioning tokens, and backups private.
- Start protection in `warn` mode before enabling strict blocking.

## Documentation

Open the dashboard FAQ/Documentation page for setup guides, API examples, Cloudflare/proxy notes, backup restore steps, and integration examples.

## Release Notes

See:

```text
RELEASE_NOTES.md
```

