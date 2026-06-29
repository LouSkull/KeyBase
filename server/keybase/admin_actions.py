"""Admin-side write actions shared by the web routes."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import core


class AdminActions:
    def __init__(self, client_ip: str, password_confirmed: bool = False) -> None:
        self.client_ip = client_ip
        self.password_confirmed = password_confirmed
        self.confirmed_this_request = False
        self.feedback: dict[str, str] | None = None

    def set_feedback(self, level: str, message: str) -> None:
        self.feedback = {"type": level, "message": core.clean_text(message, 240) or "Done."}

    def confirm_password(
        self,
        conn: sqlite3.Connection,
        data: dict[str, Any],
        action: str,
        app_id: str | None = None,
        key_text: str | None = None,
    ) -> bool:
        if self.password_confirmed:
            return True
        password = str(data.get("confirm_password", ""))
        if core.verify_admin_password(password):
            self.confirmed_this_request = True
            return True
        core.log_event(
            conn,
            "admin",
            app_id,
            key_text,
            None,
            self.client_ip,
            "password_required",
            f"{action} blocked: admin password confirmation failed",
        )
        self.set_feedback("warning", "Admin password confirmation failed.")
        return False

    def change_password(self, conn: sqlite3.Connection, data: dict[str, Any]) -> bool:
        ok, message = core.change_admin_password(
            str(data.get("current_password", "")),
            str(data.get("new_password", "")),
            str(data.get("new_password_confirm", "")),
        )
        status = "password_changed" if ok else "password_rejected"
        core.log_event(conn, "admin", None, None, None, self.client_ip, status, message)
        self.set_feedback("success" if ok else "error", message)
        return ok

    def create_app(self, conn: sqlite3.Connection, data: dict[str, Any]) -> str | None:
        raw_app_id = str(data.get("app_id", ""))
        app_id = core.normalize_app_id(raw_app_id)
        name = core.clean_text(data.get("name", ""), 80) or app_id
        secret = str(data.get("secret", ""))
        error = core.app_id_policy_error(raw_app_id) or core.app_name_policy_error(name) or core.app_secret_policy_error(secret)
        if error:
            core.log_event(conn, "admin", app_id or None, None, None, self.client_ip, "app_create_rejected", error)
            self.set_feedback("error", error)
            return None
        if conn.execute("SELECT 1 FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            message = "Application already exists."
            core.log_event(conn, "admin", app_id or None, None, None, self.client_ip, "app_create_rejected", message)
            self.set_feedback("warning", message)
            return None
        conn.execute(
            """
            INSERT INTO apps(app_id, name, secret_hash, require_secret, status, settings_json, created_at, updated_at)
            VALUES(?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                app_id,
                name,
                core.sha256_text(secret) if secret else None,
                1 if secret else 0,
                json.dumps(core.app_settings_seed()),
                core.utc_now(),
                core.utc_now(),
            ),
        )
        core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_created", f"App {app_id} created")
        self.set_feedback("success", "Application created.")
        return app_id

    def update_app(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        app_id = str(data.get("app_id", "")).strip()
        app = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app:
            self.set_feedback("warning", "Application not found.")
            return
        name = core.clean_text(data.get("name", ""), 80) or app["name"]
        name_error = core.app_name_policy_error(name)
        if name_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_update_rejected", name_error)
            self.set_feedback("error", name_error)
            return
        status = str(data.get("status", "active")).strip()
        status = status if status in core.APP_STATUSES else "active"
        if str(data.get("secret_action", "0")) == "1":
            if not self.confirm_password(conn, data, "Update app secret", app_id):
                return
            require_secret = 1 if str(data.get("require_secret", "0")) == "1" else 0
            secret_mode = str(data.get("secret_mode", "keep"))
            secret = str(data.get("secret", ""))
            secret_hash = app["secret_hash"]
            if secret_mode == "replace":
                secret_error = core.app_secret_policy_error(secret, required=True)
                if secret_error:
                    core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_secret_rejected", secret_error)
                    self.set_feedback("error", secret_error)
                    return
            if secret_mode == "replace" and secret:
                secret_hash = core.sha256_text(secret)
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
                (require_secret, secret_hash, core.utc_now(), app_id),
            )
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_secret_updated", "App secret settings updated")
            self.set_feedback("success", "Application secret updated.")
            return
        settings = core.app_settings(app)
        prefix_value = str(data.get("default_prefix", ""))
        prefix_error = core.prefix_policy_error(prefix_value, "Default key prefix")
        if prefix_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_update_rejected", prefix_error)
            self.set_feedback("error", prefix_error)
            return
        settings["default_prefix"] = core.normalize_prefix(prefix_value)
        for name in (
            "require_signed_requests",
            "reject_replay",
            "require_session_token",
            "bind_first_ip",
            "require_client_integrity",
            "block_debug_flags",
        ):
            settings[name] = str(data.get(name, "0")) == "1"
        if settings["require_session_token"]:
            settings["require_signed_requests"] = True
            settings["reject_replay"] = True
        settings["max_clock_skew_seconds"] = core.as_int(data.get("max_clock_skew_seconds"), 120, minimum=15, maximum=3600)
        settings["session_minutes"] = core.as_int(data.get("session_minutes"), 60, minimum=5, maximum=1440)
        settings["max_ip_changes"] = core.as_int(data.get("max_ip_changes"), 20, minimum=0, maximum=10000)
        settings["allowed_client_hashes"] = core.clean_text(data.get("allowed_client_hashes", ""), 4000).lower()
        settings["min_client_version"] = core.clean_text(data.get("min_client_version", ""), 32)
        conn.execute(
            """
            UPDATE apps
            SET name = ?, status = ?, settings_json = ?, updated_at = ?
            WHERE app_id = ?
            """,
            (name, status, json.dumps(settings), core.utc_now(), app_id),
        )
        core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_updated", "App settings updated")
        self.set_feedback("success", "Application settings updated.")

    def delete_app(self, conn: sqlite3.Connection, data: dict[str, Any]) -> str:
        app_id = str(data.get("app_id", "")).strip()
        confirm_app_id = core.normalize_app_id(str(data.get("confirm_app_id", "")))
        app = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app:
            self.set_feedback("warning", "Application not found.")
            return "/admin/apps"
        if confirm_app_id != app_id:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_delete_blocked", "App deletion blocked: app id confirmation mismatch")
            self.set_feedback("warning", "Application ID confirmation did not match.")
            return core.app_href(app_id, "settings")
        if not self.confirm_password(conn, data, "Delete app", app_id):
            return core.app_href(app_id, "settings")
        conn.execute("DELETE FROM license_keys WHERE app_id = ?", (app_id,))
        conn.execute("DELETE FROM bans WHERE app_id = ?", (app_id,))
        conn.execute("DELETE FROM apps WHERE app_id = ?", (app_id,))
        reason = core.clean_text(data.get("reason", ""), 240)
        message = f"Application {app_id} deleted" + (f": {reason}" if reason else "")
        core.log_event(conn, "admin", app_id, None, None, self.client_ip, "app_deleted", message)
        self.set_feedback("success", "Application deleted.")
        return "/admin/apps"

    def create_keys(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        app_id = str(data.get("app_id", "default")).strip() or "default"
        if not conn.execute("SELECT id FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            self.set_feedback("warning", "Application not found.")
            return
        count = core.as_int(data.get("count"), 1, minimum=1, maximum=200)
        prefix_raw = str(data.get("prefix", "KB"))
        prefix_error = core.prefix_policy_error(prefix_raw)
        if prefix_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "key_create_rejected", prefix_error)
            self.set_feedback("error", prefix_error)
            return
        max_devices = core.as_int(data.get("max_devices"), 1, minimum=1, maximum=999)
        duration_seconds, duration_error = core.validate_duration_form(data.get("duration_value"), data.get("duration_unit"))
        if duration_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "key_create_rejected", duration_error)
            self.set_feedback("error", duration_error)
            return
        note_error = core.text_field_policy_error(data.get("note", ""), field_name="Batch note", max_length=500)
        if note_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "key_create_rejected", note_error)
            self.set_feedback("error", note_error)
            return
        note = core.clean_text(data.get("note", ""), 500) or None
        levels = core.subscription_levels(conn, app_id)
        sub_level_raw = core.as_int(data.get("subscription_level"), 1, minimum=1, maximum=99)
        subscription_level = sub_level_raw if sub_level_raw in levels else 1
        core.create_license_key_batch(
            conn,
            app_id=app_id,
            count=count,
            prefix=prefix_raw,
            max_devices=max_devices,
            duration_seconds=duration_seconds,
            note=note,
            actor_ip=self.client_ip,
            subscription_level=subscription_level,
        )
        self.set_feedback("success", f"Created {count} key(s).")

    def update_key(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        key_id = core.as_int(data.get("id"), 0)
        key = conn.execute("SELECT * FROM license_keys WHERE id = ?", (key_id,)).fetchone()
        if not key:
            self.set_feedback("warning", "Key not found.")
            return
        status = str(data.get("status", "active")).strip()
        status = status if status in core.KEY_STATUSES else "disabled"
        max_devices = core.as_int(data.get("max_devices"), 1, minimum=1, maximum=999)
        duration_seconds, duration_error = core.validate_duration_form(data.get("duration_value"), data.get("duration_unit"))
        if duration_error:
            core.log_event(conn, "admin", key["app_id"], key["key_text"], None, self.client_ip, "key_update_rejected", duration_error)
            self.set_feedback("error", duration_error)
            return
        activated_at = core.row_value(key, "activated_at")
        expires_at = core.expires_at_from_duration(activated_at, duration_seconds) if activated_at else None
        note_error = core.text_field_policy_error(data.get("note", ""), field_name="Key note", max_length=500)
        if note_error:
            core.log_event(conn, "admin", key["app_id"], key["key_text"], None, self.client_ip, "key_update_rejected", note_error)
            self.set_feedback("error", note_error)
            return
        note = core.clean_text(data.get("note", ""), 500) or None
        levels = core.subscription_levels(conn, key["app_id"])
        sub_level_raw = core.as_int(data.get("subscription_level"), 1, minimum=1, maximum=99)
        subscription_level = sub_level_raw if sub_level_raw in levels else 1
        old_expires = core.row_value(key, "expires_at")
        conn.execute(
            """
            UPDATE license_keys
            SET status = ?, max_devices = ?, expires_at = ?, duration_seconds = ?, note = ?, subscription_level = ?
            WHERE id = ?
            """,
            (status, max_devices, expires_at, duration_seconds, note, subscription_level, key_id),
        )
        core.log_event(conn, "admin", key["app_id"], key["key_text"], None, self.client_ip, "key_updated", f"Key set to {status}, duration {core.format_duration(duration_seconds)}")
        if expires_at != old_expires:
            core.enqueue_webhook(conn, "key.extended", key["app_id"], {
                "key": key["key_text"],
                "old_expires_at": old_expires,
                "new_expires_at": expires_at,
                "duration_seconds": duration_seconds,
            })
        self.set_feedback("success", "Key updated.")

    def reset_key_devices(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        key_id = core.as_int(data.get("id"), 0)
        key = conn.execute("SELECT * FROM license_keys WHERE id = ?", (key_id,)).fetchone()
        if not key:
            self.set_feedback("warning", "Key not found.")
            return
        if not self.confirm_password(conn, data, "Reset key devices", key["app_id"], key["key_text"]):
            return
        conn.execute("DELETE FROM activations WHERE key_id = ?", (key_id,))
        reason = core.clean_text(data.get("reason", ""), 240)
        core.log_event(conn, "admin", key["app_id"], key["key_text"], None, self.client_ip, "devices_reset", "Key devices reset" + (f": {reason}" if reason else ""))
        core.enqueue_webhook(conn, "key.hwid_reset", key["app_id"], {
            "key": key["key_text"],
            "reason": reason or None,
        })
        self.set_feedback("success", "Key devices reset.")

    def delete_key(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        key_id = core.as_int(data.get("id"), 0)
        key = conn.execute("SELECT * FROM license_keys WHERE id = ?", (key_id,)).fetchone()
        if not key:
            self.set_feedback("warning", "Key not found.")
            return
        if not self.confirm_password(conn, data, "Delete key", key["app_id"], key["key_text"]):
            return
        conn.execute("DELETE FROM license_keys WHERE id = ?", (key_id,))
        reason = core.clean_text(data.get("reason", ""), 240)
        core.log_event(conn, "admin", key["app_id"], key["key_text"], None, self.client_ip, "key_deleted", "Key deleted" + (f": {reason}" if reason else ""))
        self.set_feedback("success", "Key deleted.")

    def create_ban(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        app_id = str(data.get("app_id", "")).strip() or None
        if app_id and not conn.execute("SELECT id FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            self.set_feedback("warning", "Application not found.")
            return
        kind = str(data.get("kind", "ip")).strip().lower()
        if kind not in core.BAN_KINDS:
            kind = "ip"
        value = core.clean_text(data.get("value", ""), 128)
        value_error = core.ban_value_policy_error(kind, value)
        if value_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "ban_rejected", value_error)
            self.set_feedback("error", value_error)
            return
        if kind == "hwid":
            value = core.normalize_hwid(value)
        elif kind == "country":
            value = core.normalize_country(value)
        reason_error = core.text_field_policy_error(data.get("reason", ""), field_name="Ban reason", max_length=240)
        if reason_error:
            core.log_event(conn, "admin", app_id, None, None, self.client_ip, "ban_rejected", reason_error)
            self.set_feedback("error", reason_error)
            return
        reason = core.clean_text(data.get("reason", ""), 240) or None

        if app_id:
            exists = conn.execute("SELECT id FROM bans WHERE app_id = ? AND kind = ? AND value = ?", (app_id, kind, value)).fetchone()
        else:
            exists = conn.execute("SELECT id FROM bans WHERE app_id IS NULL AND kind = ? AND value = ?", (kind, value)).fetchone()
        if exists:
            self.set_feedback("warning", "Ban already exists.")
            return

        conn.execute(
            "INSERT INTO bans(app_id, kind, value, reason, created_at) VALUES(?, ?, ?, ?, ?)",
            (app_id, kind, value, reason, core.utc_now()),
        )
        scope = "global" if app_id is None else app_id
        core.log_event(
            conn,
            "admin",
            app_id,
            None,
            value if kind == "hwid" else None,
            self.client_ip,
            "ban_created",
            f"{kind} ban created in {scope}",
            country=value if kind == "country" else None,
        )
        self.set_feedback("success", "Ban created.")

    def delete_ban(self, conn: sqlite3.Connection, data: dict[str, Any]) -> None:
        if not self.confirm_password(conn, data, "Remove ban"):
            return
        conn.execute("DELETE FROM bans WHERE id = ?", (core.as_int(data.get("id"), 0),))
        reason = core.clean_text(data.get("reason", ""), 240)
        core.log_event(conn, "admin", None, None, None, self.client_ip, "ban_removed", "Ban removed" + (f": {reason}" if reason else ""))
        self.set_feedback("success", "Ban removed.")

    # ── Bulk operations (password already verified at route level) ──────────

    def bulk_delete_keys(self, conn: sqlite3.Connection, ids: list[str]) -> tuple[int, str]:
        int_ids = [int(i) for i in ids[:500] if str(i).lstrip("-").isdigit() and int(i) > 0]
        if not int_ids:
            message = core.t("bulk_done_n", n=0)
            self.set_feedback("warning", message)
            return 0, message
        ph = ",".join("?" * len(int_ids))
        count = conn.execute(f"DELETE FROM license_keys WHERE id IN ({ph})", int_ids).rowcount
        core.log_event(conn, "admin", None, None, None, self.client_ip, "bulk_keys_deleted", f"{count} keys deleted")
        message = core.t("bulk_done_n", n=count)
        self.set_feedback("success" if count else "warning", message)
        return count, message

    def bulk_status_keys(self, conn: sqlite3.Connection, ids: list[str], status: str) -> tuple[int, str]:
        if status not in core.KEY_STATUSES:
            self.set_feedback("error", "Invalid status.")
            return 0, "Invalid status."
        int_ids = [int(i) for i in ids[:500] if str(i).lstrip("-").isdigit() and int(i) > 0]
        if not int_ids:
            message = core.t("bulk_done_n", n=0)
            self.set_feedback("warning", message)
            return 0, message
        now = core.utc_now()
        ph = ",".join("?" * len(int_ids))
        count = conn.execute(
            f"UPDATE license_keys SET status=?, updated_at=? WHERE id IN ({ph})",
            [status, now] + int_ids,
        ).rowcount
        core.log_event(conn, "admin", None, None, None, self.client_ip, "bulk_keys_status", f"{count} keys → {status}")
        message = core.t("bulk_done_n", n=count)
        self.set_feedback("success" if count else "warning", message)
        return count, message

    def bulk_delete_bans(self, conn: sqlite3.Connection, ids: list[str]) -> tuple[int, str]:
        int_ids = [int(i) for i in ids[:500] if str(i).lstrip("-").isdigit() and int(i) > 0]
        if not int_ids:
            message = core.t("bulk_done_n", n=0)
            self.set_feedback("warning", message)
            return 0, message
        ph = ",".join("?" * len(int_ids))
        count = conn.execute(f"DELETE FROM bans WHERE id IN ({ph})", int_ids).rowcount
        core.log_event(conn, "admin", None, None, None, self.client_ip, "bulk_bans_removed", f"{count} bans removed")
        message = core.t("bulk_done_n", n=count)
        self.set_feedback("success" if count else "warning", message)
        return count, message

    def bulk_delete_apps(self, conn: sqlite3.Connection, ids: list[str]) -> tuple[int, str]:
        safe = []
        protected: list[str] = []
        for raw in ids[:100]:
            app_id = str(raw or "").strip()
            if not app_id:
                continue
            if app_id == "default":
                protected.append(app_id)
                continue
            safe.append(app_id)
        count = 0
        for app_id in safe:
            if not conn.execute("SELECT app_id FROM apps WHERE app_id = ?", (app_id,)).fetchone():
                continue
            conn.execute("DELETE FROM license_keys WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM bans WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM apps WHERE app_id = ?", (app_id,))
            count += 1
        if count:
            core.log_event(conn, "admin", None, None, None, self.client_ip, "bulk_apps_deleted", f"{count} apps deleted")
        message = core.t("bulk_done_n", n=count)
        level = "success" if count else "warning"
        if protected:
            protected_message = core.t("bulk_apps_protected_skipped", items=", ".join(protected))
            message = protected_message if not count else f"{message} {protected_message}"
            level = "warning"
        self.set_feedback(level, message)
        return count, message

    def bulk_status_apps(self, conn: sqlite3.Connection, ids: list[str], status: str) -> tuple[int, str]:
        if status not in core.APP_STATUSES:
            self.set_feedback("error", "Invalid status.")
            return 0, "Invalid status."
        safe = [str(i) for i in ids[:100] if i]
        if not safe:
            message = core.t("bulk_done_n", n=0)
            self.set_feedback("warning", message)
            return 0, message
        now = core.utc_now()
        ph = ",".join("?" * len(safe))
        count = conn.execute(
            f"UPDATE apps SET status=?, updated_at=? WHERE app_id IN ({ph})",
            [status, now] + safe,
        ).rowcount
        core.log_event(conn, "admin", None, None, None, self.client_ip, "bulk_apps_status", f"{count} apps → {status}")
        message = core.t("bulk_done_n", n=count)
        self.set_feedback("success" if count else "warning", message)
        return count, message
