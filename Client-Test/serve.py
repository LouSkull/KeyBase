"""
KeyBase test panel proxy.

Serves index.html at / and proxies all /api/v1/* calls to the right backend:
  verify / activate / check  →  KB_API_URL   (client API)
  everything else            →  KB_ADMIN_URL  (admin API)

Usage:
    pip install flask requests
    KB_ADMIN_URL=http://127.0.0.1:8080 KB_API_URL=http://127.0.0.1:8080 python serve.py

Then open:  http://localhost:5000
Set the tester URL to:  http://localhost:5000
"""

import ipaddress
import os, secrets, hmac
from urllib.parse import urlparse, urlunparse
import requests
from flask import Flask, request, send_file, jsonify, make_response, session, render_template_string

# ── Config ────────────────────────────────────────────────────────
ADMIN_URL   = os.environ.get("KB_ADMIN_URL",   "http://127.0.0.1:8080")
API_URL     = os.environ.get("KB_API_URL",     "http://127.0.0.1:8080")
PROV_HEADER = os.environ.get("KB_PROV_HEADER", "X-KeyBase-Provision-Key")
PANEL_PASS  = os.environ.get("KB_PANEL_PASS",  "")
PORT        = int(os.environ.get("PORT", 5000))
ALLOW_DYNAMIC_TARGETS = os.environ.get("KB_ALLOW_DYNAMIC_TARGETS", "local").lower()

HERE    = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 12

# Client-facing endpoints → API_URL; everything else → ADMIN_URL
CLIENT_PATHS = {"/api/v1/verify", "/api/v1/activate", "/api/v1/check"}
TARGET_HEADER = "X-KeyBase-Target-Base"
FORWARD_HEADER_NAME = "X-KeyBase-Forward-Header-Name"
FORWARD_HEADER_VALUE = "X-KeyBase-Forward-Header-Value"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── Helpers ───────────────────────────────────────────────────────
def real_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[-1].strip() if fwd else (request.remote_addr or "")

def request_is_local():
    try:
        ip = ipaddress.ip_address(request.remote_addr or "")
        return ip.is_loopback
    except ValueError:
        return False

def dynamic_targets_allowed():
    if ALLOW_DYNAMIC_TARGETS in {"1", "true", "yes", "on"}:
        return True
    if ALLOW_DYNAMIC_TARGETS in {"0", "false", "no", "off"}:
        return False
    return request_is_local()

def clean_target_base(value):
    parsed = urlparse((value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an http(s) URL")
    clean_path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, clean_path, "", "", ""))

def select_target(default_target):
    requested = request.headers.get(TARGET_HEADER, "").strip()
    if not requested:
        return clean_target_base(default_target)
    if not dynamic_targets_allowed():
        return clean_target_base(default_target)
    return clean_target_base(requested)

def safe_header_name(value):
    value = (value or "").strip()
    if not value:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    return value if all(ch in allowed for ch in value) else ""

def forward(default_target):
    try:
        target = select_target(default_target)
    except ValueError as exc:
        return make_response(jsonify({"ok": False, "status": "bad_target", "message": str(exc)}), 400)

    headers = {"Content-Type": "application/json"}
    # Forward whichever provisioning header the browser UI is currently using.
    forward_name = safe_header_name(request.headers.get(FORWARD_HEADER_NAME)) or PROV_HEADER
    pv = request.headers.get(FORWARD_HEADER_VALUE) or request.headers.get(forward_name) or request.headers.get(PROV_HEADER)
    if pv:
        headers[forward_name] = pv

    path    = request.path
    is_client = path in CLIENT_PATHS

    body = None
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body = request.get_json(force=True) or {}
        except Exception:
            body = {}
        if is_client:
            body.setdefault("ip", real_ip())   # inject real IP for verify calls

    try:
        if request.method == "GET":
            r = requests.get(target + path, headers=headers,
                             params=request.args.to_dict(), timeout=TIMEOUT)
        else:
            r = requests.request(request.method, target + path,
                                 headers=headers, json=body, timeout=TIMEOUT)
        try:
            data = r.json()
        except ValueError:
            data = {"ok": False, "status": "bad_response", "raw": r.text[:400]}
        return make_response(jsonify(data), r.status_code)

    except requests.RequestException as e:
        return make_response(jsonify({"ok": False, "status": "connection_error",
                                      "message": str(e)}), 502)

# ── CORS ──────────────────────────────────────────────────────────
@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "*"
    r.headers["Access-Control-Allow-Methods"] = "*"
    return r

@app.route("/api/v1/<path:p>", methods=["OPTIONS"])
def preflight(p):
    return "", 204

# ── Panel password gate ───────────────────────────────────────────
@app.before_request
def gate():
    if not PANEL_PASS:
        return
    if request.path.startswith("/api/"):
        return
    if session.get("ok"):
        return
    if request.method == "POST":
        pw = request.form.get("pw", "")
        if hmac.compare_digest(pw, PANEL_PASS):
            session["ok"] = True
            return
    return render_template_string(LOGIN)

# ── Routes ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_file(os.path.join(HERE, "index.html"))

@app.route("/api/v1/<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(p):
    path = "/api/v1/" + p
    return forward(API_URL if path in CLIENT_PATHS else ADMIN_URL)

# ── Login page ────────────────────────────────────────────────────
LOGIN = """<!DOCTYPE html>
<html><head><meta charset=UTF-8><title>KeyBase</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:2rem;width:300px}
h2{font-size:15px;margin-bottom:1.2rem}
input{width:100%;background:#21262d;border:1px solid #30363d;border-radius:6px;padding:8px 11px;color:#e6edf3;font-size:13px;margin-bottom:.75rem}
input:focus{outline:none;border-color:#2f81f7}
button{width:100%;background:#39c5cf;color:#06202a;border:none;border-radius:6px;padding:9px;font-size:13px;font-weight:700;cursor:pointer}
</style></head>
<body><div class=box>
  <h2>🔑 KeyBase Tester</h2>
  <form method=post>
    <input name=pw type=password placeholder="Panel password" autofocus>
    <button>Enter</button>
  </form>
</div></body></html>"""

# ── Start ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n  KeyBase Tester")
    print(f"  ─────────────────────────────────")
    print(f"  Open:       http://localhost:{PORT}")
    print(f"  Set URL to: http://localhost:{PORT}")
    print(f"  Admin:      {ADMIN_URL}")
    print(f"  API:        {API_URL}")
    if PANEL_PASS:
        print(f"  Password:   set")
    print()
    app.run(host="0.0.0.0", port=PORT, debug=False)
