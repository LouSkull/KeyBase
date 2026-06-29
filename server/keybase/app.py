"""FastAPI application entrypoint for Key Base."""

from __future__ import annotations

import asyncio
import csv
import hmac
import io
import json
import os
import re
import sys
import threading
import time
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

if sys.platform.startswith("win") and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import core
from .admin_actions import AdminActions
from .rate_limit import admin_limiter, verify_limiter


def is_expected_disconnect_error(exc: BaseException) -> bool:
    if not sys.platform.startswith("win"):
        return False
    if isinstance(exc, (asyncio.CancelledError, ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "winerror", None) == 1236:
            return True
        if getattr(exc, "errno", None) in {10053, 10054, 1236}:
            return True
    return False


class VerifyRequest(BaseModel):
    app_id: str = "default"
    key: str = ""
    hwid: str = ""
    ip: str | None = None
    country: str | None = None
    version: str | None = None
    timestamp: int | str | None = None
    nonce: str | None = None
    signature: str | None = None
    session_token: str | None = None
    client_hash: str | None = None
    client_flags: str | list[str] | None = None
    build_id: str | None = None
    protection: dict[str, Any] | None = None
    fingerprint: dict[str, Any] | None = None
    browser_fingerprint: dict[str, Any] | None = None
    behavior: dict[str, Any] | None = None
    security_report: dict[str, Any] | None = None
    environment: dict[str, Any] | None = None
    signals: str | list[str] | None = None
    asn: str | int | None = None
    asn_name: str | None = None
    asn_org: str | None = None
    asn_type: str | None = None
    organization: str | None = None
    org: str | None = None
    isp: str | None = None
    ip_type: str | None = None
    connection_type: str | None = None
    risk_score: int | float | str | None = None
    fraud_score: int | float | str | None = None
    threat_score: int | float | str | None = None
    abuse_score: int | float | str | None = None
    is_vm: bool | None = None
    vm_detected: bool | None = None
    is_sandbox: bool | None = None
    sandbox_detected: bool | None = None
    is_emulator: bool | None = None
    emulator_detected: bool | None = None
    is_vpn: bool | None = None
    vpn_detected: bool | None = None
    is_proxy: bool | None = None
    proxy_detected: bool | None = None
    is_tor: bool | None = None
    tor_detected: bool | None = None
    is_datacenter: bool | None = None
    datacenter_detected: bool | None = None
    is_debugger: bool | None = None
    debugger_detected: bool | None = None
    is_tampered: bool | None = None
    tamper_detected: bool | None = None
    is_hooked: bool | None = None
    injection_detected: bool | None = None
    mac_prefix: str | None = None
    mac_vendor: str | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    bios_serial: str | None = None
    uefi_vendor: str | None = None
    system_manufacturer: str | None = None
    system_product: str | None = None
    cpu_vendor: str | None = None
    cpu_flags: str | list[str] | None = None
    drivers: str | list[str] | None = None
    devices: str | list[str] | None = None
    processes: str | list[str] | None = None
    modules: str | list[str] | None = None
    loaded_modules: str | list[str] | None = None
    hooks: str | list[str] | None = None
    injected_modules: str | list[str] | None = None


class ProvisionRequest(BaseModel):
    app_id: str = "default"
    count: int | str | None = 1
    prefix: str | None = None
    max_devices: int | str | None = None
    duration_value: int | str | None = None
    duration_unit: str | None = None
    note: str | None = None
    order_id: str | None = None
    customer_id: str | None = None
    subscription_level: int | str | None = 1


app = FastAPI(
    title="Key Base",
    version=core.VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/assets", StaticFiles(directory=core.ASSET_DIR), name="assets")


@app.on_event("startup")
async def startup() -> None:
    core.init_db()
    core.refresh_admin_credentials()
    core.ensure_background_services()
    core._sweep_expired_keys()
    if not core.admin_configured():
        print("Admin setup required: open /admin/register from the local machine.")


_PANIC_ADMIN_PASSTHROUGH = {
    "/admin/panic",
    "/admin/panic/enable",
    "/admin/panic/disable",
    "/admin/login",
    "/admin/logout",
    "/admin/register",
}


@app.middleware("http")
async def panic_guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and core.is_panic_mode():
        return JSONResponse(
            {"ok": False, "error": "maintenance", "message": "Service temporarily unavailable. Panic Mode is active."},
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            headers={"Retry-After": "1800"},
        )
    if path.startswith("/admin/") and core.is_panic_mode():
        if path not in _PANIC_ADMIN_PASSTHROUGH and not path.startswith("/admin/panic/"):
            return RedirectResponse("/admin/panic", status_code=HTTPStatus.SEE_OTHER)
    return await call_next(request)


@app.middleware("http")
async def set_language(request: Request, call_next):
    lang = request.cookies.get("keybase-lang", "en")
    core.set_lang(lang if lang in ("en", "ru", "es") else "en")
    return await call_next(request)


def _origin_from_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _request_origin(request: Request) -> str:
    host = request.headers.get("host") or request.url.netloc
    scheme = "https" if request_is_https(request) else request.url.scheme
    return f"{scheme.lower()}://{host.lower()}"


def _admin_allowed_origins(request: Request) -> set[str]:
    origins = {_request_origin(request)}
    configured = _origin_from_url(core.config_str("admin.public_base_url", ""))
    if configured:
        origins.add(configured)
    return origins


def _same_origin_admin_post(request: Request) -> bool:
    if not request.url.path.startswith("/admin") or request.method.upper() in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return True
    fetch_site = request.headers.get("sec-fetch-site", "").strip().lower()
    if fetch_site == "cross-site":
        return False
    allowed_origins = _admin_allowed_origins(request)
    origin = request.headers.get("origin", "").strip()
    if origin:
        normalized_origin = _origin_from_url(origin)
        if normalized_origin:
            return normalized_origin in allowed_origins
    referer = request.headers.get("referer", "").strip()
    if referer:
        normalized_referer = _origin_from_url(referer)
        if normalized_referer:
            return normalized_referer in allowed_origins
    if fetch_site and fetch_site not in {"same-origin", "same-site", "none"}:
        return False
    # Keep CLI/scripts/backwards compatibility when browsers omit Origin/Referer.
    return True


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    if not _same_origin_admin_post(request):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"ok": False, "status": "csrf_rejected", "message": "Cross-site admin request rejected."}, status_code=HTTPStatus.FORBIDDEN)
        return PlainTextResponse("Cross-site admin request rejected.", status_code=HTTPStatus.FORBIDDEN)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    if request_is_https(request):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith("/admin"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; base-uri 'none'; frame-ancestors 'none'")
    return response


_SENSITIVE_QUERY_KEYS = {
    "key",
    "license",
    "license_key",
    "token",
    "api_token",
    "provision_token",
    "secret",
    "app_secret",
    "password",
    "signature",
    "nonce",
    "session",
    "session_token",
    "x-app-secret",
    "x-keybase-signature",
}


def _redacted_target(request: Request) -> str:
    target = request.url.path
    if not request.query_params:
        return target
    pairs: list[str] = []
    for key, value in request.query_params.multi_items():
        safe_key = re.sub(r"[\r\n\t=&#]", "_", str(key))[:80]
        normalized = key.strip().lower().replace("-", "_")
        if normalized in _SENSITIVE_QUERY_KEYS or any(marker in normalized for marker in ("token", "secret", "password", "signature", "nonce")):
            value = "[redacted]"
        elif len(value) > 160:
            value = value[:157] + "..."
        safe_value = re.sub(r"[\r\n\t&]", " ", str(value))
        pairs.append(f"{safe_key}={safe_value}")
    return f"{target}?{'&'.join(pairs)}"


@app.middleware("http")
async def access_log(request: Request, call_next):
    started_at = time.perf_counter()
    response = None
    try:
        response = await call_next(request)
        return response
    except asyncio.CancelledError as exc:
        if is_expected_disconnect_error(exc):
            response = Response(status_code=499)
            core.runtime_note(f'client disconnected during {request.method} {request.url.path}', "http")
            return response
        raise
    except Exception as exc:
        if is_expected_disconnect_error(exc):
            response = Response(status_code=499)
            core.runtime_note(f'client disconnected during {request.method} {request.url.path}', "http")
            return response
        raise
    finally:
        try:
            ip, ip_source = client_ip_info(request)
            target = _redacted_target(request)
            status_code = getattr(response, "status_code", HTTPStatus.INTERNAL_SERVER_ERROR)
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
            source_suffix = f" [{ip_source}]" if ip_source and ip_source != "connection" else ""
            core.runtime_note(f'{ip}{source_suffix} "{request.method} {target}" {status_code} {elapsed_ms}ms', "http")
        except Exception:
            pass


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    if request.url.path.startswith("/api/"):
        msg = str(exc.detail) if exc.detail else "An error occurred."
        return JSONResponse(
            {"ok": False, "status": "error", "code": exc.status_code, "message": msg},
            status_code=exc.status_code,
        )
    _apply_lang(request)
    return HTMLResponse(core.render_error_page(exc.status_code), status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    if is_expected_disconnect_error(exc):
        core.runtime_note(f"client disconnected during {request.method} {request.url.path}", "http")
        if request.url.path.startswith("/api/"):
            return JSONResponse(
                {"ok": False, "status": "client_disconnected", "message": "Client disconnected before the response completed."},
                status_code=499,
            )
        return Response(status_code=499)
    import traceback as _tb
    core.runtime_note(
        f"500 on {request.method} {request.url.path}: {type(exc).__name__}: {exc}\n{_tb.format_exc()}",
        "error",
    )
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            {"ok": False, "status": "server_error", "message": "An internal server error occurred."},
            status_code=500,
        )
    _apply_lang(request)
    return HTMLResponse(core.render_error_page(500), status_code=500)


def client_ip_info(request: Request, payload_ip: str | None = None) -> tuple[str, str]:
    connection_ip = request.client.host if request.client else "unknown"
    return core.resolved_request_ip(connection_ip, request.headers, payload_ip)


def client_ip(request: Request, payload_ip: str | None = None) -> str:
    return client_ip_info(request, payload_ip)[0]


def client_country_info(
    request: Request,
    payload: dict[str, Any] | None = None,
    ip: str = "",
    ip_source: str = "",
) -> tuple[str, str]:
    payload = payload or {}
    connection_ip = request.client.host if request.client else "unknown"
    return core.resolved_request_country(
        connection_ip,
        request.headers,
        ip,
        ip_source,
        payload.get("country"),
        str(payload.get("ip", "")),
    )


def client_country(request: Request, payload: dict[str, Any] | None = None, ip: str = "", ip_source: str = "") -> str:
    country, _source = client_country_info(request, payload, ip, ip_source)
    return country


def request_is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    connection_ip = request.client.host if request.client else ""
    if core.trust_proxy_headers() and core.trusted_proxy_source(connection_ip):
        forwarded = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        if forwarded == "https":
            return True
        cf_visitor = request.headers.get("CF-Visitor", "")
        if '"scheme":"https"' in cf_visitor.replace(" ", "").lower():
            return True
    return False


def cookie_value(request: Request) -> str:
    return request.cookies.get(core.COOKIE_NAME, "")


def admin_allowed_from_ip(request: Request) -> bool:
    ip = request.client.host if request.client else ""
    return core.remote_admin_allowed() or core.is_loopback_ip(ip)


def _apply_lang(request: Request) -> None:
    lang = request.cookies.get("keybase-lang", "en")
    core.set_lang(lang if lang in ("en", "ru", "es") else "en")


def query_dict(request: Request) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        parsed.setdefault(key, []).append(value)
    return parsed


def admin_authed(request: Request) -> bool:
    if not core.admin_configured():
        return False
    cookie = cookie_value(request)
    return bool(cookie and core.verify_session_cookie(cookie))


def require_admin(request: Request) -> HTMLResponse | None:
    if not admin_allowed_from_ip(request):
        _apply_lang(request)
        return HTMLResponse(
            core.render_error_page(403, desc=core.t("error_403_remote_admin")),
            status_code=HTTPStatus.FORBIDDEN,
        )
    if not core.admin_configured():
        return HTMLResponse(core.setup_page(), status_code=HTTPStatus.OK)
    if admin_authed(request):
        return None
    return HTMLResponse(core.login_page(), status_code=HTTPStatus.UNAUTHORIZED)


async def form_data(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type == "application/x-www-form-urlencoded":
        raw = await request.body()
        parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}
    form = await request.form()
    return {key: str(value) for key, value in form.items()}


def redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=HTTPStatus.SEE_OTHER)


def redirect_with_feedback(location: str, feedback: dict[str, str] | None = None) -> RedirectResponse:
    if feedback:
        location = core.with_toast(location, feedback.get("message", ""), feedback.get("type", "info"))
    return redirect(location)


def danger_confirmed(request: Request) -> bool:
    return core.verify_confirm_cookie(request.cookies.get(core.CONFIRM_COOKIE_NAME, ""))


def admin_actions(request: Request) -> AdminActions:
    return AdminActions(client_ip(request), password_confirmed=danger_confirmed(request))


def secure_cookie(request: Request) -> bool:
    return request_is_https(request)


def admin_redirect(
    location: str,
    actions: AdminActions | None = None,
    feedback: dict[str, str] | None = None,
    request: Request | None = None,
) -> RedirectResponse:
    toast = feedback or (actions.feedback if actions else None)
    response = redirect_with_feedback(location, toast)
    cookie_secure = secure_cookie(request) if request is not None else False
    if actions and actions.confirmed_this_request:
        confirm_cookie = core.make_confirm_cookie()
        expires_at = confirm_cookie.split(":", 1)[1].split(".", 1)[0]
        response.set_cookie(
            core.CONFIRM_COOKIE_NAME,
            confirm_cookie,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=core.CONFIRM_WINDOW_SECONDS,
            secure=cookie_secure,
        )
        response.set_cookie(
            core.CONFIRM_UI_COOKIE_NAME,
            expires_at,
            httponly=False,
            samesite="strict",
            path="/",
            max_age=core.CONFIRM_WINDOW_SECONDS,
            secure=cookie_secure,
        )
    return response


def bulk_json_response(
    actions: AdminActions | None,
    ok: bool,
    count: int,
    message: str,
    *,
    level: str | None = None,
    status_code: int = HTTPStatus.OK,
) -> JSONResponse:
    toast_level = level or ("success" if ok else "error")
    response = JSONResponse({"ok": ok, "count": count, "message": message, "type": toast_level}, status_code=status_code)
    if actions and actions.confirmed_this_request:
        confirm_cookie = core.make_confirm_cookie()
        expires_at = confirm_cookie.split(":", 1)[1].split(".", 1)[0]
        response.set_cookie(
            core.CONFIRM_COOKIE_NAME,
            confirm_cookie,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=core.CONFIRM_WINDOW_SECONDS,
        )
        response.set_cookie(
            core.CONFIRM_UI_COOKIE_NAME,
            expires_at,
            httponly=False,
            samesite="strict",
            path="/",
            max_age=core.CONFIRM_WINDOW_SECONDS,
        )
    return response


@app.get("/", response_class=JSONResponse)
@app.get("/health", response_class=JSONResponse)
@app.get("/api/v1/health", response_class=JSONResponse)
async def health() -> JSONResponse:
    return JSONResponse({
        "ok": True,
        "name": core.APP_NAME,
        "version": core.VERSION,
        "api_enabled": core.api_runtime_enabled(),
        "api_uptime": core.api_runtime_uptime(),
    })


@app.get("/api/openapi.json", response_class=JSONResponse, include_in_schema=False)
async def openapi_schema(request: Request) -> JSONResponse:
    blocked = require_admin(request)
    if blocked:
        status = getattr(blocked, "status_code", HTTPStatus.FORBIDDEN)
        if status == HTTPStatus.OK:
            status = HTTPStatus.FORBIDDEN
        return JSONResponse({"ok": False, "status": "unauthorized", "message": "Admin authentication required."}, status_code=status)
    return JSONResponse(app.openapi())


@app.get("/api/v1/fingerprint.js", response_class=Response)
async def fingerprint_script() -> Response:
    script_path = core.ASSET_DIR / "keybase-fingerprint.js"
    try:
        body = script_path.read_text(encoding="utf-8")
    except OSError:
        return PlainTextResponse("fingerprint script unavailable", status_code=HTTPStatus.NOT_FOUND)
    return Response(body, media_type="application/javascript; charset=utf-8")


@app.post("/api/v1/verify", response_class=JSONResponse)
@app.post("/api/v1/check", response_class=JSONResponse)
@app.post("/api/v1/activate", response_class=JSONResponse)
async def verify(request: Request, payload: VerifyRequest) -> JSONResponse:
    ip, ip_source = client_ip_info(request, payload.ip)
    if not core.api_runtime_enabled():
        return JSONResponse(
            {"ok": False, "status": "api_stopped", "message": "API runtime is stopped from the admin console"},
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
        )
    if not verify_limiter.allow(f"verify:{ip}", limit=core.config_int("api.verify_rate_limit_per_minute", 180, 1, 100_000), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited", "message": "Too many requests"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    raw = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    raw["_user_agent"] = request.headers.get("User-Agent", "")
    country, country_source = client_country_info(request, raw, ip, ip_source)
    with core.db_connect() as conn:
        result = core.verify_license(
            conn,
            payload.key,
            payload.app_id,
            payload.hwid,
            ip,
            request.headers.get("X-App-Secret"),
            country,
            request.headers.get("X-KeyBase-Timestamp") or payload.timestamp,
            request.headers.get("X-KeyBase-Nonce") or payload.nonce,
            request.headers.get("X-KeyBase-Signature") or payload.signature,
            request.headers.get("X-KeyBase-Session") or payload.session_token,
            request.headers.get("X-Client-Hash") or payload.client_hash,
            request.headers.get("X-Client-Flags") or payload.client_flags,
            request.headers.get("X-Build-Id") or payload.build_id,
            payload.version,
            raw,
        )
        conn.commit()
    result["country_source"] = country_source or None
    result["resolved_ip"] = ip
    result["ip_source"] = ip_source
    status_code = HTTPStatus.FORBIDDEN if result.get("status") in {"bad_app_secret", "challenge_required"} or result.get("status") in core.PROTECTION_REASON_CODES else HTTPStatus.OK
    return JSONResponse(result, status_code=status_code)


@app.post("/api/v1/provision", response_class=JSONResponse)
@app.post("/api/v1/keys/provision", response_class=JSONResponse)
async def provision_key(request: Request, payload: ProvisionRequest) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited", "message": "Too many provisioning requests"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)

    raw = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    app_id_input = raw.get("app_id") or "default"
    app_id_error = core.app_id_policy_error(app_id_input)
    if app_id_error:
        return JSONResponse({"ok": False, "status": "bad_request", "message": app_id_error}, status_code=HTTPStatus.BAD_REQUEST)
    app_id = core.normalize_app_id(str(app_id_input)) or "default"

    count = core._strict_int(raw.get("count", 1))
    if count is None or count < 1 or count > int(defaults["max_batch_size"]):
        return JSONResponse(
            {"ok": False, "status": "bad_request", "message": f"count must be between 1 and {defaults['max_batch_size']}."},
            status_code=HTTPStatus.BAD_REQUEST,
        )
    prefix_value = raw.get("prefix") or defaults["default_prefix"]
    prefix_error = core.prefix_policy_error(prefix_value)
    if prefix_error:
        return JSONResponse({"ok": False, "status": "bad_request", "message": prefix_error}, status_code=HTTPStatus.BAD_REQUEST)
    max_devices_raw = raw.get("max_devices", defaults["default_max_devices"])
    max_devices = core._strict_int(max_devices_raw)
    if max_devices is None or max_devices < 1 or max_devices > 999:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "max_devices must be between 1 and 999."}, status_code=HTTPStatus.BAD_REQUEST)
    duration_seconds, duration_error = core.validate_duration_form(
        raw.get("duration_value", defaults["default_duration_value"]),
        raw.get("duration_unit", defaults["default_duration_unit"]),
        "Provisioning duration",
    )
    if duration_error:
        return JSONResponse({"ok": False, "status": "bad_request", "message": duration_error}, status_code=HTTPStatus.BAD_REQUEST)
    for field_name, field_value, max_length in (
        ("Provisioning note", raw.get("note", ""), 500),
        ("Order ID", raw.get("order_id", ""), 80),
        ("Customer ID", raw.get("customer_id", ""), 80),
    ):
        text_error = core.text_field_policy_error(field_value, field_name=field_name, max_length=max_length)
        if text_error:
            return JSONResponse({"ok": False, "status": "bad_request", "message": text_error}, status_code=HTTPStatus.BAD_REQUEST)
    note = core.build_batch_note(raw.get("note", ""), raw.get("order_id", ""), raw.get("customer_id", ""))
    sub_level_raw = core._strict_int(raw.get("subscription_level", 1))
    if sub_level_raw is None or sub_level_raw < 1:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "subscription_level must be a positive integer."}, status_code=HTTPStatus.BAD_REQUEST)

    with core.db_connect() as conn:
        app_row = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app_row:
            return JSONResponse({"ok": False, "status": "app_not_found", "message": "Unknown app_id"}, status_code=HTTPStatus.NOT_FOUND)
        levels = core.subscription_levels(conn, app_row)
        subscription_level = sub_level_raw if sub_level_raw in levels else 1
        keys = core.create_license_key_batch(
            conn,
            app_id=app_id,
            count=count,
            prefix=str(prefix_value),
            max_devices=max_devices,
            duration_seconds=duration_seconds,
            note=note,
            actor_ip=ip,
            subscription_level=subscription_level,
            event_type="provision",
            status="provisioned",
            message_prefix="Provisioned key",
        )
        core.log_event(conn, "provision", app_id, None, None, ip, "provision_batch", f"Provisioning API created {len(keys)} key(s)")
        conn.commit()
    return JSONResponse(
        {
            "ok": True,
            "status": "provisioned",
            "app_id": app_id,
            "count": len(keys),
            "duration_seconds": duration_seconds,
            "duration_label": core.format_duration(duration_seconds),
            "max_devices": max_devices,
            "subscription_level": subscription_level,
            "subscription_name": levels.get(subscription_level, "Default"),
            "note": note,
            "keys": keys,
        },
        status_code=HTTPStatus.CREATED,
    )


def _check_provision_auth(request: Request, defaults: dict) -> JSONResponse | None:
    if not core.api_runtime_enabled():
        return JSONResponse({"ok": False, "status": "api_stopped", "message": "API runtime is stopped"}, status_code=HTTPStatus.SERVICE_UNAVAILABLE)
    if not defaults["enabled"]:
        return JSONResponse({"ok": False, "status": "provisioning_disabled", "message": "Provisioning API is disabled in config.yml"}, status_code=HTTPStatus.NOT_FOUND)
    if defaults["require_https"] and not request_is_https(request):
        return JSONResponse({"ok": False, "status": "https_required", "message": "Provisioning API requires HTTPS"}, status_code=HTTPStatus.FORBIDDEN)
    ip = client_ip(request)
    if not verify_limiter.allow(f"provision-auth:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited", "message": "Too many provisioning authentication attempts"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    provided_token = request.headers.get(defaults["header_name"], "").strip()
    expected_token = str(defaults.get("shared_token") or "")
    if not provided_token or not expected_token or not hmac.compare_digest(provided_token, expected_token):
        return JSONResponse({"ok": False, "status": "bad_provision_token", "message": "Provisioning token is invalid"}, status_code=HTTPStatus.FORBIDDEN)
    return None


def _key_by_text(conn, key_text: str, app_id: str):
    return conn.execute(
        "SELECT * FROM license_keys WHERE key_text = ? AND app_id = ?",
        (key_text.strip().upper(), app_id.strip()),
    ).fetchone()


@app.get("/api/v1/keys/info", response_class=JSONResponse)
async def key_info(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited", "message": "Too many requests"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    key_text = request.query_params.get("key", "").strip().upper()
    app_id = request.query_params.get("app_id", "").strip()
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        page = core.as_int(request.query_params.get("page", "1"), 1, minimum=1)
        limit = core.as_int(
            request.query_params.get("limit", str(core.PAGINATION_DEFAULT_LIMIT)),
            core.PAGINATION_DEFAULT_LIMIT,
            minimum=1,
            maximum=core.PAGINATION_MAX_LIMIT,
        )
        total_devices = core.row_count(conn, "SELECT COUNT(*) FROM activations WHERE key_id = ?", (key["id"],))
        page, total_pages, offset = core.pagination_bounds(total_devices, page, limit)
        devices = conn.execute(
            """
            SELECT hwid, ip, country, first_ip, ip_change_count
            FROM activations
            WHERE key_id = ?
            ORDER BY last_seen_at DESC
            LIMIT ? OFFSET ?
            """,
            (key["id"], limit, offset),
        ).fetchall()
        return JSONResponse({
            "ok": True,
            "key": key["key_text"],
            "app_id": key["app_id"],
            "status": key["status"],
            "max_devices": key["max_devices"],
            "devices_used": total_devices,
            "expires_at": core.row_value(key, "expires_at"),
            "activated_at": core.row_value(key, "activated_at"),
            "duration_seconds": key["duration_seconds"],
            "subscription_level": key["subscription_level"] if "subscription_level" in key.keys() else 1,
            "note": core.row_value(key, "note"),
            "created_at": core.row_value(key, "created_at"),
            "pagination": {
                "total_items": total_devices,
                "total_pages": total_pages,
                "current_page": page,
                "items_per_page": limit,
            },
            "devices": [
                {
                    "hwid": d["hwid"],
                    "ip": d["ip"],
                    "country": core.best_effort_country(core.row_value(d, "country"), d["ip"]) or None,
                    "first_ip": d["first_ip"],
                    "ip_change_count": d["ip_change_count"],
                }
                for d in devices
            ],
        })


@app.post("/api/v1/keys/suspend", response_class=JSONResponse)
async def key_suspend(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    reason = core.clean_text(body.get("reason", ""), 240)
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        conn.execute("UPDATE license_keys SET status = 'paused' WHERE id = ?", (key["id"],))
        core.log_event(conn, "provision", app_id, key_text, None, ip, "key_suspended", "Key suspended via API" + (f": {reason}" if reason else ""))
        conn.commit()
    return JSONResponse({"ok": True, "status": "suspended", "key": key_text})


@app.post("/api/v1/keys/resume", response_class=JSONResponse)
async def key_resume(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        conn.execute("UPDATE license_keys SET status = 'active' WHERE id = ?", (key["id"],))
        core.log_event(conn, "provision", app_id, key_text, None, ip, "key_resumed", "Key resumed via API")
        conn.commit()
    return JSONResponse({"ok": True, "status": "resumed", "key": key_text})


@app.post("/api/v1/keys/revoke", response_class=JSONResponse)
async def key_revoke(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    reason = core.clean_text(body.get("reason", ""), 240)
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        conn.execute("UPDATE license_keys SET status = 'revoked' WHERE id = ?", (key["id"],))
        core.log_event(conn, "provision", app_id, key_text, None, ip, "key_revoked", "Key revoked via API" + (f": {reason}" if reason else ""))
        conn.commit()
    return JSONResponse({"ok": True, "status": "revoked", "key": key_text})


@app.post("/api/v1/keys/delete", response_class=JSONResponse)
async def key_delete(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    reason = core.clean_text(body.get("reason", ""), 240)
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        conn.execute("DELETE FROM license_keys WHERE id = ?", (key["id"],))
        core.log_event(conn, "provision", app_id, key_text, None, ip, "key_deleted", "Key deleted via API" + (f": {reason}" if reason else ""))
        conn.commit()
    return JSONResponse({"ok": True, "status": "deleted", "key": key_text})


@app.post("/api/v1/keys/extend", response_class=JSONResponse)
async def key_extend(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    duration_seconds, duration_error = core.validate_duration_form(body.get("duration_value"), body.get("duration_unit"))
    if duration_error:
        return JSONResponse({"ok": False, "status": "bad_request", "message": duration_error}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        activated_at = core.row_value(key, "activated_at")
        expires_at = core.expires_at_from_duration(activated_at, duration_seconds) if activated_at else None
        old_expires = core.row_value(key, "expires_at")
        conn.execute(
            "UPDATE license_keys SET duration_seconds = ?, expires_at = ? WHERE id = ?",
            (duration_seconds, expires_at, key["id"]),
        )
        core.log_event(conn, "provision", app_id, key_text, None, ip, "key_extended", f"Key extended to {core.format_duration(duration_seconds)} via API")
        core.enqueue_webhook(conn, "key.extended", app_id, {
            "key": key_text,
            "old_expires_at": old_expires,
            "new_expires_at": expires_at,
            "duration_seconds": duration_seconds,
        })
        conn.commit()
    return JSONResponse({
        "ok": True,
        "status": "extended",
        "key": key_text,
        "duration_seconds": duration_seconds,
        "duration_label": core.format_duration(duration_seconds),
        "expires_at": expires_at,
    })


@app.post("/api/v1/keys/reset-devices", response_class=JSONResponse)
async def key_reset_devices(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    reason = core.clean_text(body.get("reason", ""), 240)
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        deleted = conn.execute("DELETE FROM activations WHERE key_id = ?", (key["id"],)).rowcount
        core.log_event(conn, "provision", app_id, key_text, None, ip, "devices_reset", "Devices reset via API" + (f": {reason}" if reason else ""))
        core.enqueue_webhook(conn, "key.hwid_reset", app_id, {"key": key_text, "reason": reason or None})
        conn.commit()
    return JSONResponse({"ok": True, "status": "devices_reset", "key": key_text, "devices_removed": deleted})


@app.post("/api/v1/keys/reset-ip", response_class=JSONResponse)
async def key_reset_ip(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    key_text = str(body.get("key", "")).strip().upper()
    app_id = str(body.get("app_id", "")).strip()
    if not key_text or not app_id:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "key and app_id are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        key = _key_by_text(conn, key_text, app_id)
        if not key:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Key not found"}, status_code=HTTPStatus.NOT_FOUND)
        conn.execute(
            "UPDATE activations SET ip = NULL, first_ip = NULL, ip_change_count = 0 WHERE key_id = ?",
            (key["id"],),
        )
        core.log_event(conn, "provision", app_id, key_text, None, ip, "ip_reset", "IP history reset via API")
        conn.commit()
    return JSONResponse({"ok": True, "status": "ip_reset", "key": key_text})


@app.post("/api/v1/bans/add", response_class=JSONResponse)
async def ban_add(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    kind = str(body.get("kind", "ip")).strip().lower()
    if kind not in core.BAN_KINDS:
        return JSONResponse({"ok": False, "status": "bad_request", "message": f"kind must be one of: {', '.join(core.BAN_KINDS)}"}, status_code=HTTPStatus.BAD_REQUEST)
    value = core.clean_text(body.get("value", ""), 128)
    value_error = core.ban_value_policy_error(kind, value)
    if value_error:
        return JSONResponse({"ok": False, "status": "bad_request", "message": value_error}, status_code=HTTPStatus.BAD_REQUEST)
    if kind == "hwid":
        value = core.normalize_hwid(value)
    elif kind == "country":
        value = core.normalize_country(value)
    reason = core.clean_text(body.get("reason", ""), 240)
    app_id_raw = str(body.get("app_id", "")).strip() or None
    with core.db_connect() as conn:
        if app_id_raw and not conn.execute("SELECT id FROM apps WHERE app_id = ?", (app_id_raw,)).fetchone():
            return JSONResponse({"ok": False, "status": "app_not_found", "message": "Unknown app_id"}, status_code=HTTPStatus.NOT_FOUND)
        if app_id_raw:
            exists = conn.execute("SELECT id FROM bans WHERE app_id = ? AND kind = ? AND value = ?", (app_id_raw, kind, value)).fetchone()
        else:
            exists = conn.execute("SELECT id FROM bans WHERE app_id IS NULL AND kind = ? AND value = ?", (kind, value)).fetchone()
        if exists:
            return JSONResponse({"ok": False, "status": "already_exists", "message": "Ban already exists"}, status_code=HTTPStatus.CONFLICT)
        conn.execute(
            "INSERT INTO bans(app_id, kind, value, reason, created_at) VALUES(?, ?, ?, ?, ?)",
            (app_id_raw, kind, value, reason or None, core.utc_now()),
        )
        scope = "global" if app_id_raw is None else app_id_raw
        core.log_event(conn, "provision", app_id_raw, None, value if kind == "hwid" else None, ip, "ban_created", f"{kind} ban created in {scope} via API", country=value if kind == "country" else None)
        conn.commit()
    return JSONResponse({"ok": True, "status": "ban_created", "kind": kind, "value": value, "scope": scope})


@app.post("/api/v1/bans/remove", response_class=JSONResponse)
async def ban_remove(request: Request) -> JSONResponse:
    ip = client_ip(request)
    defaults = core.provisioning_defaults()
    err = _check_provision_auth(request, defaults)
    if err:
        return err
    if not verify_limiter.allow(f"provision:{ip}", limit=int(defaults["rate_limit_per_minute"]), window_seconds=60):
        return JSONResponse({"ok": False, "status": "rate_limited"}, status_code=HTTPStatus.TOO_MANY_REQUESTS)
    body = await request.json()
    kind = str(body.get("kind", "ip")).strip().lower()
    value = core.clean_text(body.get("value", ""), 128)
    if kind == "hwid":
        value = core.normalize_hwid(value)
    elif kind == "country":
        value = core.normalize_country(value)
    app_id_raw = str(body.get("app_id", "")).strip() or None
    if not kind or not value:
        return JSONResponse({"ok": False, "status": "bad_request", "message": "kind and value are required"}, status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        if app_id_raw:
            row = conn.execute("SELECT id FROM bans WHERE app_id = ? AND kind = ? AND value = ?", (app_id_raw, kind, value)).fetchone()
        else:
            row = conn.execute("SELECT id FROM bans WHERE app_id IS NULL AND kind = ? AND value = ?", (kind, value)).fetchone()
        if not row:
            return JSONResponse({"ok": False, "status": "not_found", "message": "Ban not found"}, status_code=HTTPStatus.NOT_FOUND)
        conn.execute("DELETE FROM bans WHERE id = ?", (row["id"],))
        scope = "global" if app_id_raw is None else app_id_raw
        core.log_event(conn, "provision", app_id_raw, None, None, ip, "ban_removed", f"{kind} ban removed from {scope} via API")
        conn.commit()
    return JSONResponse({"ok": True, "status": "ban_removed", "kind": kind, "value": value, "scope": scope})


@app.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not admin_allowed_from_ip(request):
        return PlainTextResponse("Remote admin is disabled.", status_code=HTTPStatus.FORBIDDEN)
    if not core.admin_configured():
        return redirect("/admin/register")
    return HTMLResponse(core.login_page())


@app.get("/admin/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if not admin_allowed_from_ip(request):
        return PlainTextResponse("Remote admin is disabled.", status_code=HTTPStatus.FORBIDDEN)
    if core.admin_configured():
        return redirect("/admin/login")
    return HTMLResponse(core.setup_page())


@app.post("/admin/register")
async def register(request: Request):
    if not admin_allowed_from_ip(request):
        return PlainTextResponse("Remote admin is disabled.", status_code=HTTPStatus.FORBIDDEN)
    if core.admin_configured():
        return redirect("/admin/login")
    ip = client_ip(request)
    if not admin_limiter.allow(f"register:{ip}", limit=core.config_int("security.register_attempts_per_hour", 8, 1, 1000), window_seconds=3600):
        return HTMLResponse(core.setup_page(core.t("msg_too_many_setup")), status_code=HTTPStatus.TOO_MANY_REQUESTS)
    data = await form_data(request)
    ok, message = core.register_admin(
        str(data.get("username", "")),
        str(data.get("password", "")),
        str(data.get("password_confirm", "")),
    )
    if not ok:
        return HTMLResponse(core.setup_page(message), status_code=HTTPStatus.BAD_REQUEST)
    with core.db_connect() as conn:
        core.log_event(conn, "admin", None, None, None, ip, "admin_registered", f"Admin account {core.ADMIN_USER} registered")
        conn.commit()
    response = redirect("/admin")
    response.set_cookie(
        core.COOKIE_NAME,
        core.make_session_cookie(),
        httponly=True,
        samesite="strict",
        path="/",
        max_age=core.SESSION_MAX_SECONDS,
        secure=secure_cookie(request),
    )
    return response


@app.post("/admin/login")
async def login(request: Request):
    if not admin_allowed_from_ip(request):
        return PlainTextResponse("Remote admin is disabled.", status_code=HTTPStatus.FORBIDDEN)
    if not core.admin_configured():
        return redirect("/admin/register")
    ip = client_ip(request)
    if not admin_limiter.allow(f"login:{ip}", limit=core.config_int("security.login_attempts_per_10m", 10, 1, 1000), window_seconds=600):
        return HTMLResponse(core.login_page(core.t("msg_too_many_login")), status_code=HTTPStatus.TOO_MANY_REQUESTS)
    data = await form_data(request)
    if core.verify_admin_password(str(data.get("password", ""))):
        response = redirect("/admin")
        response.set_cookie(
            core.COOKIE_NAME,
            core.make_session_cookie(),
            httponly=True,
            samesite="strict",
            path="/",
            max_age=core.SESSION_MAX_SECONDS,
            secure=secure_cookie(request),
        )
        return response
    with core.db_connect() as conn:
        core.log_event(conn, "admin", None, None, None, ip, "password_required", "Admin login failed")
        conn.commit()
    return HTMLResponse(core.login_page(core.t("msg_wrong_password")), status_code=HTTPStatus.UNAUTHORIZED)


@app.post("/admin/logout")
async def logout() -> RedirectResponse:
    response = redirect("/admin/login")
    response.delete_cookie(core.COOKIE_NAME, path="/")
    response.delete_cookie(core.CONFIRM_COOKIE_NAME, path="/")
    response.delete_cookie(core.CONFIRM_UI_COOKIE_NAME, path="/")
    return response


@app.get("/admin", response_class=HTMLResponse)
async def dashboard(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_dashboard(conn, query_dict(request)))


@app.get("/admin/apps", response_class=HTMLResponse)
async def apps_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_apps(conn, query_dict(request)))


@app.get("/admin/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_keys(conn, query_dict(request)))


@app.get("/admin/app/{app_id:path}", response_class=HTMLResponse)
async def app_console(app_id: str, request: Request, tab: str = "overview"):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_app_console(conn, unquote(app_id), tab, query_dict(request)))


@app.get("/admin/bans", response_class=HTMLResponse)
async def global_bans(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_global_bans(conn, query_dict(request)))


@app.get("/admin/events", response_class=HTMLResponse)
async def events_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_events(conn, query_dict(request)))


@app.get("/admin/protection", response_class=HTMLResponse)
async def protection_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    with core.db_connect() as conn:
        return HTMLResponse(core.render_protection_monitor(conn, query_dict(request)))


@app.get("/admin/api", response_class=HTMLResponse)
async def api_console(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return HTMLResponse(core.render_api_console())


@app.get("/admin/config", response_class=HTMLResponse)
async def config_console(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return HTMLResponse(core.render_config_console())


@app.get("/admin/api/runtime", response_class=JSONResponse)
async def api_runtime_data(request: Request):
    blocked = require_admin(request)
    if blocked:
        return JSONResponse({"ok": False, "message": "Unauthorized"}, status_code=getattr(blocked, "status_code", HTTPStatus.FORBIDDEN))
    return JSONResponse({"ok": True, **core.api_runtime_snapshot()})


@app.get("/admin/api/update-status", response_class=JSONResponse)
async def update_status(request: Request):
    blocked = require_admin(request)
    if blocked:
        return JSONResponse({"ok": False, "message": "Unauthorized"}, status_code=getattr(blocked, "status_code", HTTPStatus.FORBIDDEN))
    return JSONResponse(
        {"ok": True, **core.github_release_update_info()},
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@app.post("/admin/api/process")
async def api_process(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin/api")
    action = str(data.get("action", "status"))
    status, message = core.set_api_runtime_state(action, client_ip(request))
    with core.db_connect() as conn:
        core.log_event(conn, "admin", None, None, None, client_ip(request), status, message)
        conn.commit()
    level = "success"
    if status in {"api_already_running", "api_already_stopped"}:
        level = "warning"
    elif status in {"api_stopped", "api_action_rejected"}:
        level = "error"
    return redirect(core.with_toast(return_to, message, level))


@app.get("/admin/backup", response_class=HTMLResponse)
async def backup_console(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return HTMLResponse(core.render_backup_console(query_dict(request)))


@app.post("/admin/backup/create")
async def create_backup(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin/backup")
    ok, message, _path = core.create_backup(str(data.get("reason", "manual")), client_ip(request))
    with core.db_connect() as conn:
        core.log_event(conn, "admin", None, None, None, client_ip(request), "backup_created" if ok else "backup_failed", message)
        conn.commit()
    return redirect(core.with_toast(return_to, message, "success" if ok else "error"))


@app.post("/admin/backup/delete")
async def remove_backup(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin/backup")
    ok, message = core.delete_backup(str(data.get("name", "")))
    with core.db_connect() as conn:
        core.log_event(conn, "admin", None, None, None, client_ip(request), "backup_deleted" if ok else "backup_delete_failed", message)
        conn.commit()
    return redirect(core.with_toast(return_to, message, "success" if ok else "error"))


@app.get("/admin/docs", response_class=HTMLResponse)
async def docs_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return HTMLResponse(core.render_docs())


@app.post("/admin/config/save")
async def save_config(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin/config")
    actions = admin_actions(request)
    feedback = None
    with core.db_connect() as conn:
        if actions.confirm_password(conn, data, "Update config"):
            ok, message, needs_restart = core.save_config_text(str(data.get("config_text", "")))
            core.log_event(conn, "admin", None, None, None, client_ip(request), "config_saved" if ok else "config_rejected", message)
            fb_type = "error" if not ok else ("warning" if needs_restart else "success")
            feedback = {"type": fb_type, "message": message}
        conn.commit()
    if "application/json" in request.headers.get("accept", ""):
        if feedback:
            return bulk_json_response(actions, feedback["type"] != "error", 0, feedback["message"], level=feedback["type"])
        return bulk_json_response(actions, False, 0, "Password confirmation failed", level="error")
    return admin_redirect(return_to, actions, feedback)


@app.post("/admin/apps/create")
async def create_app(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    actions = admin_actions(request)
    with core.db_connect() as conn:
        app_id = actions.create_app(conn, data)
        conn.commit()
    return redirect_with_feedback(core.app_href(app_id) if app_id else "/admin/apps", actions.feedback)


@app.post("/admin/apps/update")
async def update_app(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.update_app(conn, data)
        conn.commit()
    return admin_redirect(return_to, actions)


@app.post("/admin/apps/delete")
async def delete_app(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    actions = admin_actions(request)
    with core.db_connect() as conn:
        location = actions.delete_app(conn, data)
        conn.commit()
    return admin_redirect(location, actions)


@app.post("/admin/security/password")
async def change_password(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        changed = actions.change_password(conn, data)
        conn.commit()
    if changed:
        response = redirect("/admin/login")
        response.delete_cookie(core.COOKIE_NAME, path="/")
        response.delete_cookie(core.CONFIRM_COOKIE_NAME, path="/")
        response.delete_cookie(core.CONFIRM_UI_COOKIE_NAME, path="/")
        return response
    return redirect_with_feedback(return_to, actions.feedback)


@app.post("/admin/keys/create")
async def create_keys(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.create_keys(conn, data)
        conn.commit()
    fallback = core.app_href(str(data.get("app_id", "default")), "keys")
    return redirect_with_feedback(return_to if return_to != "/admin" else fallback, actions.feedback)


@app.post("/admin/keys/update")
async def update_key(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.update_key(conn, data)
        conn.commit()
    return redirect_with_feedback(return_to, actions.feedback)


@app.post("/admin/keys/reset-devices")
async def reset_key_devices(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.reset_key_devices(conn, data)
        conn.commit()
    return admin_redirect(return_to, actions)


@app.post("/admin/keys/delete")
async def delete_key(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.delete_key(conn, data)
        conn.commit()
    return admin_redirect(return_to, actions)


@app.post("/admin/bans/create")
async def create_ban(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.create_ban(conn, data)
        conn.commit()
    return redirect_with_feedback(return_to, actions.feedback)


@app.post("/admin/bans/delete")
async def delete_ban(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        actions.delete_ban(conn, data)
        conn.commit()
    return admin_redirect(return_to, actions)


# ── Bulk endpoints ────────────────────────────────────────────────────────────

def _bulk_blocked(request: Request):
    blocked = require_admin(request)
    if blocked:
        return JSONResponse({"ok": False, "message": "Not authorized.", "count": 0}, status_code=403)
    return None


@app.post("/admin/keys/bulk")
async def bulk_keys(request: Request):
    err = _bulk_blocked(request)
    if err:
        return err
    data = await request.form()
    action = str(data.get("action", ""))
    ids = list(data.getlist("ids[]"))[:500]
    if not ids:
        return bulk_json_response(None, False, 0, core.t("bulk_no_items"), level="warning")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        if action == "delete":
            if not actions.confirm_password(conn, data, "Bulk delete keys"):
                conn.commit()
                fb = actions.feedback or {}
                return bulk_json_response(actions, False, 0, fb.get("message", "Password required."), level=fb.get("type", "warning"))
            count, msg = actions.bulk_delete_keys(conn, ids)
        elif action in ("enable", "disable"):
            count, msg = actions.bulk_status_keys(conn, ids, "active" if action == "enable" else "disabled")
        else:
            return bulk_json_response(actions, False, 0, core.t("bulk_unknown_action"))
        conn.commit()
    feedback = actions.feedback or {}
    return bulk_json_response(actions, count > 0, count, msg, level=feedback.get("type"))


@app.post("/admin/keys/export")
async def export_keys(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await request.form()
    ids = list(data.getlist("ids[]"))[:500]
    int_ids = [int(i) for i in ids if str(i).lstrip("-").isdigit() and int(i) > 0]
    with core.db_connect() as conn:
        if int_ids:
            ph = ",".join("?" * len(int_ids))
            rows = conn.execute(
                f"SELECT id, app_id, key_text, status, max_devices, uses, expires_at, created_at, note FROM license_keys WHERE id IN ({ph})",
                int_ids,
            ).fetchall()
        else:
            rows = []
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "app_id", "key_text", "status", "max_devices", "uses", "expires_at", "created_at", "note"])
    for r in rows:
        writer.writerow([r["id"], r["app_id"], r["key_text"], r["status"], r["max_devices"], r["uses"] or 0, r["expires_at"] or "", r["created_at"], r["note"] or ""])
    return Response(out.getvalue().encode("utf-8"), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=keys.csv"})


@app.post("/admin/bans/bulk")
async def bulk_bans(request: Request):
    err = _bulk_blocked(request)
    if err:
        return err
    data = await request.form()
    action = str(data.get("action", ""))
    ids = list(data.getlist("ids[]"))[:500]
    if not ids:
        return bulk_json_response(None, False, 0, core.t("bulk_no_items"), level="warning")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        if action in ("delete", "unban"):
            if not actions.confirm_password(conn, data, "Bulk remove bans"):
                conn.commit()
                fb = actions.feedback or {}
                return bulk_json_response(actions, False, 0, fb.get("message", "Password required."), level=fb.get("type", "warning"))
            count, msg = actions.bulk_delete_bans(conn, ids)
        else:
            return bulk_json_response(actions, False, 0, core.t("bulk_unknown_action"))
        conn.commit()
    feedback = actions.feedback or {}
    return bulk_json_response(actions, count > 0, count, msg, level=feedback.get("type"))


@app.post("/admin/apps/bulk")
async def bulk_apps_action(request: Request):
    err = _bulk_blocked(request)
    if err:
        return err
    data = await request.form()
    action = str(data.get("action", ""))
    ids = list(data.getlist("ids[]"))[:100]
    if not ids:
        return bulk_json_response(None, False, 0, core.t("bulk_no_items"), level="warning")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        if action == "delete":
            if not actions.confirm_password(conn, data, "Bulk delete apps"):
                conn.commit()
                fb = actions.feedback or {}
                return bulk_json_response(actions, False, 0, fb.get("message", "Password required."), level=fb.get("type", "warning"))
            count, msg = actions.bulk_delete_apps(conn, ids)
        elif action in ("enable", "disable", "pause"):
            status_map = {"enable": "active", "disable": "disabled", "pause": "paused"}
            count, msg = actions.bulk_status_apps(conn, ids, status_map[action])
        else:
            return bulk_json_response(actions, False, 0, core.t("bulk_unknown_action"))
        conn.commit()
    feedback = actions.feedback or {}
    return bulk_json_response(actions, count > 0, count, msg, level=feedback.get("type"))


@app.post("/admin/backup/bulk")
async def bulk_backup(request: Request):
    err = _bulk_blocked(request)
    if err:
        return err
    data = await request.form()
    action = str(data.get("action", ""))
    names = list(data.getlist("ids[]"))[:100]
    if not names or action != "delete":
        message = core.t("bulk_no_items") if not names else core.t("bulk_unknown_action")
        return bulk_json_response(None, False, 0, message, level="warning" if not names else "error")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        if not actions.confirm_password(conn, data, "Bulk delete backups"):
            conn.commit()
            fb = actions.feedback or {}
            return bulk_json_response(actions, False, 0, fb.get("message", "Password required."), level=fb.get("type", "warning"))
    count = 0
    for name in names:
        ok, _ = core.delete_backup(str(name))
        if ok:
            count += 1
    with core.db_connect() as conn:
        core.log_event(conn, "admin", None, None, None, client_ip(request), "bulk_backups_deleted", f"{count} backups deleted")
        conn.commit()
    actions.set_feedback("success" if count else "warning", core.t("bulk_done_n", n=count))
    feedback = actions.feedback or {}
    return bulk_json_response(actions, count > 0, count, feedback.get("message", core.t("bulk_done_n", n=count)), level=feedback.get("type"))


@app.get("/admin/panic")
async def panic_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return HTMLResponse(core.render_panic_console())


@app.post("/admin/panic/enable")
async def panic_enable(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin/panic")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        if not actions.confirm_password(conn, data, "Enable Panic Mode"):
            conn.commit()
    if actions.feedback and actions.feedback.get("type") == "error":
        return admin_redirect(return_to, actions)
    core.enable_panic_mode(core.ADMIN_USER, client_ip(request))
    response = redirect_with_feedback(
        "/admin/panic",
        {"type": "warning", "message": core.t("panic_enabled_toast")},
    )
    response.delete_cookie(core.COOKIE_NAME)
    response.delete_cookie(core.CONFIRM_COOKIE_NAME)
    return response


@app.post("/admin/panic/disable")
async def panic_disable(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), "/admin/panic")
    actions = admin_actions(request)
    with core.db_connect() as conn:
        if not actions.confirm_password(conn, data, "Disable Panic Mode"):
            conn.commit()
            return admin_redirect(return_to, actions)
        conn.commit()
    ok, msg = core.disable_panic_mode(core.ADMIN_USER, client_ip(request))
    fb_type = "success" if ok else "error"
    location = "/admin" if ok else return_to
    return admin_redirect(location, feedback={"type": fb_type, "message": msg})


@app.get("/admin/subscriptions")
async def subscriptions_page(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return redirect("/admin/apps")


@app.post("/admin/subscriptions/add")
async def subscriptions_add(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return redirect("/admin/apps")


@app.post("/admin/subscriptions/remove")
async def subscriptions_remove(request: Request):
    blocked = require_admin(request)
    if blocked:
        return blocked
    return redirect("/admin/apps")


@app.post("/admin/app/{app_id}/subscriptions/add")
async def app_subscriptions_add(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), core.app_href(app_id, "subscriptions"))
    level_id_raw = core._strict_int(data.get("level_id"))
    level_name = core.clean_text(str(data.get("level_name", "")).strip(), 64)
    if level_id_raw is None or level_id_raw < 1 or level_id_raw > 99:
        return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_bad_id")})
    if not level_name:
        return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_bad_name")})
    if not re.match(r'^[\w\s\-+\.]+$', level_name):
        return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_bad_name_chars")})
    with core.db_connect() as conn:
        app_row = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app_row:
            return admin_redirect("/admin/apps", feedback={"type": "error", "message": "Application not found."})
        levels = core.subscription_levels(conn, app_row)
        if len(levels) >= 20:
            return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_too_many")})
        if level_id_raw in levels:
            return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_duplicate_id", id=level_id_raw)})
        levels[level_id_raw] = level_name
        core.save_app_subscription_levels(conn, app_id, levels)
        conn.commit()
    return admin_redirect(return_to, feedback={"type": "success", "message": core.t("sub_settings_added", id=level_id_raw, name=level_name)})


@app.post("/admin/app/{app_id}/subscriptions/remove")
async def app_subscriptions_remove(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    data = await form_data(request)
    return_to = core.safe_return(str(data.get("return_to", "")), core.app_href(app_id, "subscriptions"))
    level_id_raw = core._strict_int(data.get("level_id"))
    if level_id_raw is None or level_id_raw < 1:
        return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_bad_id")})
    with core.db_connect() as conn:
        app_row = conn.execute("SELECT * FROM apps WHERE app_id = ?", (app_id,)).fetchone()
        if not app_row:
            return admin_redirect("/admin/apps", feedback={"type": "error", "message": "Application not found."})
        levels = core.subscription_levels(conn, app_row)
        if level_id_raw not in levels:
            return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_settings_not_found")})
        if len(levels) <= 1:
            return admin_redirect(return_to, feedback={"type": "error", "message": core.t("sub_err_last_level")})
        levels.pop(level_id_raw)
        core.save_app_subscription_levels(conn, app_id, levels)
        conn.commit()
    return admin_redirect(return_to, feedback={"type": "success", "message": core.t("sub_settings_removed", id=level_id_raw)})


# ── Per-app Webhooks ──────────────────────────────────────────────────────────

def _wh_return(app_id: str) -> str:
    return core.app_href(app_id, "webhooks")


@app.post("/admin/app/{app_id}/webhooks/create")
async def webhooks_create(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    rt = _wh_return(app_id)
    with core.db_connect() as conn:
        if not conn.execute("SELECT 1 FROM apps WHERE app_id = ?", (app_id,)).fetchone():
            return admin_redirect("/admin/apps", feedback={"type": "error", "message": core.t("wh_err_not_found")})
    data = await form_data(request)
    url = str(data.get("url", "")).strip()
    desc = core.clean_text(data.get("description", ""), 200)
    url_err = core._webhook_url_error(url)
    if url_err:
        return admin_redirect(rt, feedback={"type": "error", "message": url_err})
    events = [ev for ev in core.WEBHOOK_EVENTS if ev != "admin.registered" and data.get(f"ev_{ev.replace('.', '_')}")]
    if not events:
        events = ["*"]
    endpoint_id = core.secrets.token_urlsafe(16)
    secret = core.secrets.token_hex(32)
    now = core.utc_now()
    with core.db_connect() as conn:
        conn.execute(
            "INSERT INTO webhook_endpoints (id, app_id, url, secret, enabled, events, description, created_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            (endpoint_id, app_id, url, secret, json.dumps(events), desc or None, now),
        )
        core.log_event(conn, "admin", app_id, None, None, client_ip(request), "webhook_created", f"Endpoint created: {url}")
        conn.commit()
    return admin_redirect(rt, feedback={"type": "success", "message": core.t("wh_created_ok")})


@app.post("/admin/app/{app_id}/webhooks/delete")
async def webhooks_delete(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    rt = _wh_return(app_id)
    data = await form_data(request)
    endpoint_id = str(data.get("endpoint_id", ""))
    if not core._endpoint_id_valid(endpoint_id):
        return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
    with core.db_connect() as conn:
        ep = conn.execute("SELECT url FROM webhook_endpoints WHERE id = ? AND app_id = ?", (endpoint_id, app_id)).fetchone()
        if not ep:
            return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
        conn.execute("DELETE FROM webhook_endpoints WHERE id = ?", (endpoint_id,))
        conn.execute("DELETE FROM webhook_deliveries WHERE endpoint_id = ?", (endpoint_id,))
        core.log_event(conn, "admin", app_id, None, None, client_ip(request), "webhook_deleted", f"Endpoint deleted: {ep['url']}")
        conn.commit()
    return admin_redirect(rt, feedback={"type": "success", "message": core.t("wh_deleted_ok")})


@app.post("/admin/app/{app_id}/webhooks/toggle")
async def webhooks_toggle(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    rt = _wh_return(app_id)
    data = await form_data(request)
    endpoint_id = str(data.get("endpoint_id", ""))
    action = str(data.get("action", ""))
    if action not in ("enable", "disable") or not core._endpoint_id_valid(endpoint_id):
        return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
    enabled = 1 if action == "enable" else 0
    with core.db_connect() as conn:
        conn.execute("UPDATE webhook_endpoints SET enabled = ? WHERE id = ? AND app_id = ?", (enabled, endpoint_id, app_id))
        conn.commit()
    msg = core.t("wh_enabled_ok") if enabled else core.t("wh_disabled_ok")
    return admin_redirect(rt, feedback={"type": "success", "message": msg})


@app.post("/admin/app/{app_id}/webhooks/test")
async def webhooks_test(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    rt = _wh_return(app_id)
    data = await form_data(request)
    endpoint_id = str(data.get("endpoint_id", ""))
    if not core._endpoint_id_valid(endpoint_id):
        return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
    with core.db_connect() as conn:
        ep = conn.execute("SELECT * FROM webhook_endpoints WHERE id = ? AND app_id = ?", (endpoint_id, app_id)).fetchone()
        if not ep:
            return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
        now = core.utc_now()
        delivery_id = core.secrets.token_hex(10)
        payload = json.dumps({
            "event": "test",
            "timestamp": now,
            "delivery_id": delivery_id,
            "app_id": app_id,
            "test": True,
            "message": "This is a test delivery from KeyBase.",
        }, separators=(",", ":"))
        conn.execute(
            "INSERT INTO webhook_deliveries (endpoint_id, event_type, payload_json, status, attempt, max_attempts, next_retry_at, created_at) VALUES (?, 'test', ?, 'pending', 0, 1, ?, ?)",
            (endpoint_id, payload, now, now),
        )
        conn.commit()
    core._WEBHOOK_WAKE.set()
    return admin_redirect(rt, feedback={"type": "success", "message": core.t("wh_test_queued")})


@app.post("/admin/app/{app_id}/webhooks/update")
async def webhooks_update(request: Request, app_id: str):
    blocked = require_admin(request)
    if blocked:
        return blocked
    rt = _wh_return(app_id)
    data = await form_data(request)
    endpoint_id = str(data.get("endpoint_id", ""))
    if not core._endpoint_id_valid(endpoint_id):
        return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
    url = str(data.get("url", "")).strip()
    url_err = core._webhook_url_error(url)
    if url_err:
        return admin_redirect(rt, feedback={"type": "error", "message": url_err})
    desc = core.clean_text(data.get("description", ""), 200)
    preset = str(data.get("preset", "keybase"))
    if preset not in core.WEBHOOK_PRESETS:
        preset = "keybase"
    content_type = str(data.get("content_type", "application/json")).strip() or "application/json"
    if "\n" in content_type or "\r" in content_type or len(content_type) > 128:
        return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_content_type_invalid")})
    body_template = str(data.get("body_template", ""))
    if len(body_template.encode("utf-8")) > 32_768:
        return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_template_too_long")})
    extra_headers: dict[str, str] = {}
    for line in str(data.get("extra_headers_raw", "")).splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        header_err = core._webhook_header_error(k, v)
        if header_err:
            return admin_redirect(rt, feedback={"type": "error", "message": header_err})
        extra_headers[k] = v
        if len(extra_headers) > 20:
            return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_headers_too_many")})
    cfg = json.dumps({
        "preset": preset,
        "content_type": content_type,
        "extra_headers": extra_headers,
        "body_template": body_template,
    }, separators=(",", ":"))
    with core.db_connect() as conn:
        ep = conn.execute("SELECT id FROM webhook_endpoints WHERE id = ? AND app_id = ?", (endpoint_id, app_id)).fetchone()
        if not ep:
            return admin_redirect(rt, feedback={"type": "error", "message": core.t("wh_err_not_found")})
        conn.execute(
            "UPDATE webhook_endpoints SET url=?, description=?, config_json=? WHERE id=?",
            (url, desc or None, cfg, endpoint_id),
        )
        core.log_event(conn, "admin", app_id, None, None, client_ip(request), "webhook_updated", f"Endpoint updated: {url}")
        conn.commit()
    return admin_redirect(rt, feedback={"type": "success", "message": core.t("wh_cfg_saved")})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def catch_all_404(request: Request, path: str = "") -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            {"ok": False, "status": "not_found", "message": "Endpoint not found."},
            status_code=404,
        )
    _apply_lang(request)
    return HTMLResponse(core.render_error_page(404), status_code=404)


def run() -> None:
    core.init_db()
    core.refresh_admin_credentials()
    core.ensure_background_services()
    core._sweep_expired_keys()

    listeners = core.listener_targets()
    admin_target = listeners["admin"]
    api_target = listeners["api"]
    print(f"{core.APP_NAME} {core.VERSION}")
    print(f"Mode:  {listeners['mode']}")
    print(f"Admin: http://{admin_target['host']}:{admin_target['port']}/admin")
    if not core.admin_configured():
        print(f"Setup: http://{admin_target['host']}:{admin_target['port']}/admin/register")
    print(f"API:   http://{api_target['host']}:{api_target['port']}/api/v1/verify")
    if listeners["mode"] == "split":
        print(f"Admin API: http://{admin_target['host']}:{admin_target['port']}/api/v1/provision (local)")

    _ADMIN_API_PATHS: frozenset[str] = frozenset({
        "/api/openapi.json",
        "/api/v1/provision",
        "/api/v1/keys/provision",
        "/api/v1/keys/info",
        "/api/v1/keys/extend",
        "/api/v1/keys/suspend",
        "/api/v1/keys/resume",
        "/api/v1/keys/revoke",
        "/api/v1/keys/delete",
        "/api/v1/keys/reset-devices",
        "/api/v1/keys/reset-ip",
        "/api/v1/bans/add",
        "/api/v1/bans/remove",
    })

    class PathFilteredApp:
        def __init__(self, inner_app: Any, listener_role: str) -> None:
            self.inner_app = inner_app
            self.listener_role = listener_role

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope.get("type") != "http":
                await self.inner_app(scope, receive, send)
                return
            path = str(scope.get("path", "") or "")
            if self.listener_role == "admin":
                if path == "/" or path == "":
                    response = RedirectResponse("/admin", status_code=HTTPStatus.FOUND)
                    await response(scope, receive, send)
                    return
                allowed = (
                    path.startswith("/admin")
                    or path.startswith("/assets")
                    or path in _ADMIN_API_PATHS
                )
            else:
                allowed = (
                    path in {"/", "/health", "/api/v1/health"}
                    or path == "/api/v1/fingerprint.js"
                    or path.startswith("/api/v1/verify")
                    or path.startswith("/api/v1/check")
                    or path.startswith("/api/v1/activate")
                )
            if allowed:
                await self.inner_app(scope, receive, send)
                return
            if path.startswith("/api/"):
                response = JSONResponse({"ok": False, "status": "not_found", "message": "Endpoint not found on this listener."}, status_code=HTTPStatus.NOT_FOUND)
            else:
                response = HTMLResponse(core.render_error_page(404), status_code=HTTPStatus.NOT_FOUND)
            await response(scope, receive, send)

    def _make_server(asgi_app: Any, host: str, port: int) -> uvicorn.Server:
        return uvicorn.Server(
            uvicorn.Config(asgi_app, host=host, port=port, reload=False, access_log=False, lifespan="off", loop="asyncio")
        )

    active_servers: list[uvicorn.Server] = []
    active_threads: list[threading.Thread] = []

    def _start_servers() -> None:
        ls = core.listener_targets()
        adm = ls["admin"]
        api = ls["api"]
        if ls["mode"] == "combined":
            srv = _make_server(app, adm["host"], adm["port"])
            thr = threading.Thread(target=srv.run, name="keybase-combined", daemon=True)
            thr.start()
            active_servers[:] = [srv]
            active_threads[:] = [thr]
        else:
            api_srv = _make_server(PathFilteredApp(app, "api"), api["host"], api["port"])
            adm_srv = _make_server(PathFilteredApp(app, "admin"), adm["host"], adm["port"])
            api_thr = threading.Thread(target=api_srv.run, name="keybase-api", daemon=True)
            adm_thr = threading.Thread(target=adm_srv.run, name="keybase-admin", daemon=True)
            api_thr.start()
            adm_thr.start()
            active_servers[:] = [api_srv, adm_srv]
            active_threads[:] = [api_thr, adm_thr]

    def _stop_servers() -> None:
        for s in active_servers:
            s.should_exit = True
        for t in active_threads:
            t.join(timeout=10)
            if t.is_alive():
                core.runtime_note(f"Server thread '{t.name}' did not stop within 10 s — port may still be bound", "warn")

    core._LISTENER_RESTART_EVENT.clear()
    _start_servers()

    try:
        while True:
            triggered = core._LISTENER_RESTART_EVENT.wait(timeout=2)
            if triggered:
                core._LISTENER_RESTART_EVENT.clear()
                _stop_servers()
                ls = core.listener_targets()
                adm = ls["admin"]
                api = ls["api"]
                print(f"Listeners restarted — Admin: http://{adm['host']}:{adm['port']}/admin  API: http://{api['host']}:{api['port']}/api/v1/verify")
                _start_servers()
                continue
            dead = [t.name for t in active_threads if not t.is_alive()]
            if dead:
                core.runtime_note(f"Server thread(s) died unexpectedly: {', '.join(dead)} — shutting down", "warn")
                raise RuntimeError(f"Listener thread(s) died: {dead}")
    except KeyboardInterrupt:
        pass
    finally:
        _stop_servers()


if __name__ == "__main__":
    run()
