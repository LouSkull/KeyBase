"""
KeyBase test panel — Flask proxies all API calls server-side.
Testers only see this Flask server; the KeyBase server is never exposed directly.

Usage:
    pip install flask requests
    python serve.py

Then run ngrok in a second terminal:
    ngrok http 5000
"""

import os
import secrets
import hmac
import hashlib

import requests
from flask import Flask, request, render_template_string, session

# ── Config ────────────────────────────────────────────────────────
ADMIN_URL      = os.environ.get("KB_ADMIN_URL",  "")
API_URL        = os.environ.get("KB_API_URL",    "")
PROV_TOKEN     = os.environ.get("KB_PROV_TOKEN", "change-this-provision-token")
PROV_HEADER    = os.environ.get("KB_PROV_HEADER","X-KeyBase-Provision-Key")
PANEL_PASSWORD = os.environ.get("KB_PANEL_PASS", "")   # optional: lock the panel

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

TIMEOUT = 10  # seconds for keybase API calls

# ── Helpers ───────────────────────────────────────────────────────
def admin_headers():
    return {"Content-Type": "application/json", PROV_HEADER: PROV_TOKEN}

def api_headers():
    return {"Content-Type": "application/json"}

def client_ip():
    """IP of the tester's browser.
    Takes only the rightmost X-Forwarded-For entry (added by the last trusted hop,
    e.g. ngrok) to prevent callers from spoofing the IP sent to the KeyBase verify endpoint.
    Falls back to remote_addr when no forwarding header is present.
    """
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        # rightmost entry = added by the nearest trusted proxy (ngrok/nginx), not the client
        return fwd.split(",")[-1].strip()
    return request.remote_addr or ""

def tester_hwid():
    """Stable HWID per browser session."""
    if "hwid" not in session:
        session["hwid"] = hashlib.sha256(secrets.token_bytes(16)).hexdigest()
    return session["hwid"]

def call(method, base, path, **kwargs):
    try:
        r = getattr(requests, method)(base.rstrip("/") + path, timeout=TIMEOUT, **kwargs)
        return r.json()
    except requests.RequestException as e:
        return {"ok": False, "status": "connection_error", "message": str(e)}
    except ValueError:
        return {"ok": False, "status": "bad_response", "message": "Server returned non-JSON"}

def form(key, default=""):
    return request.form.get(key, default).strip()

# ── Panel password gate ───────────────────────────────────────────
@app.before_request
def check_panel_password():
    if not PANEL_PASSWORD:
        return
    if request.path == "/login":
        return
    if session.get("panel_authed"):
        return
    if request.method == "POST" and hmac.compare_digest(request.form.get("panel_password", ""), PANEL_PASSWORD):
        session["panel_authed"] = True
        return
    return render_template_string(LOGIN_HTML)

# ── Routes ───────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    return render_template_string(PAGE_HTML,
        result=None,
        op=None,
        hwid=tester_hwid(),
        detected_ip=client_ip(),
        admin_url=ADMIN_URL,
        api_url=API_URL,
    )

@app.route("/provision", methods=["POST"])
def provision():
    body = {
        "app_id":             form("app_id") or "default",
        "count":              int(form("count") or 1),
        "max_devices":        int(form("max_devices") or 1),
        "subscription_level": int(form("subscription_level") or 1),
    }
    prefix = form("prefix")
    if prefix:
        body["prefix"] = prefix
    dur_val  = form("duration_value")
    dur_unit = form("duration_unit")
    if dur_val and dur_unit:
        body["duration_value"] = int(dur_val)
        body["duration_unit"]  = dur_unit
    for k in ("note", "order_id", "customer_id"):
        v = form(k)
        if v:
            body[k] = v
    result = call("post", ADMIN_URL, "/api/v1/provision", json=body, headers=admin_headers())
    return render_result("Provision key", result)

@app.route("/verify", methods=["POST"])
def verify():
    path = form("endpoint") or "/api/v1/verify"
    hwid = form("hwid") or tester_hwid()
    body = {
        "app_id":  form("app_id") or "default",
        "key":     form("key"),
        "hwid":    hwid,
        "version": form("version") or "1.0.0",
        "ip":      client_ip(),
    }
    result = call("post", API_URL, path, json=body, headers=api_headers())
    return render_result(f"Verify ({path})", result)

@app.route("/keyinfo", methods=["POST"])
def keyinfo():
    app_id = form("app_id") or "default"
    key    = form("key")
    result = call("get", ADMIN_URL, f"/api/v1/keys/info",
                  params={"app_id": app_id, "key": key},
                  headers=admin_headers())
    return render_result("Key info", result)

@app.route("/keyaction", methods=["POST"])
def keyaction():
    action = form("action")
    paths  = {
        "suspend": "/api/v1/keys/suspend",
        "resume":  "/api/v1/keys/resume",
        "revoke":  "/api/v1/keys/revoke",
        "delete":  "/api/v1/keys/delete",
    }
    path = paths.get(action)
    if not path:
        return render_result("Error", {"ok": False, "message": "Unknown action"})
    body = {"app_id": form("app_id") or "default", "key": form("key")}
    reason = form("reason")
    if reason:
        body["reason"] = reason
    result = call("post", ADMIN_URL, path, json=body, headers=admin_headers())
    return render_result(f"Key {action}", result)

@app.route("/hwid/reset", methods=["POST"])
def reset_hwid():
    session.pop("hwid", None)
    from flask import redirect, url_for
    return redirect(url_for("index"))

def render_result(op, result):
    import json
    ok = result.get("ok", False) is not False
    return render_template_string(PAGE_HTML,
        result=json.dumps(result, indent=2, ensure_ascii=False),
        op=op,
        ok=ok,
        hwid=tester_hwid(),
        detected_ip=client_ip(),
        admin_url=ADMIN_URL,
        api_url=API_URL,
    )

# ── Templates ────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset=UTF-8><title>Login</title></head>
<body>
<h2>Panel password</h2>
<form method=post>
  <input name=panel_password type=password placeholder=Password>
  <button type=submit>Enter</button>
</form>
</body></html>"""

PAGE_HTML = """<!DOCTYPE html>
<html lang=en>
<head>
<meta charset=UTF-8>
<title>KeyBase API Test</title>
</head>
<body>
<h1>KeyBase API Test</h1>
<p>Admin: <code>{{ admin_url }}</code> &nbsp; API: <code>{{ api_url }}</code></p>

{% if result is not none %}
<fieldset>
  <legend>Result — {{ op }}</legend>
  <pre style="background:{{ '#efffef' if ok else '#fff2f2' }};padding:10px;white-space:pre-wrap;word-break:break-all">{{ result }}</pre>
  <a href="/">← Back</a>
</fieldset>
{% endif %}

<!-- ── Provision ── -->
<fieldset>
  <legend>Provision key</legend>
  <form method=post action=/provision>
    <table>
      <tr><td>app_id</td><td><input name=app_id value="default"></td></tr>
      <tr><td>count</td><td><input name=count value="1" type=number min=1 size=6></td></tr>
      <tr><td>max_devices</td><td><input name=max_devices value="1" type=number min=1 size=6></td></tr>
      <tr><td>subscription_level</td><td><input name=subscription_level value="1" type=number min=1 size=6></td></tr>
      <tr><td>prefix</td><td><input name=prefix placeholder="auto" size=12></td></tr>
      <tr><td>duration</td><td>
        <input name=duration_value type=number min=1 size=6 placeholder="blank=lifetime">
        <select name=duration_unit>
          <option value="">lifetime</option>
          <option>hours</option><option>days</option>
          <option>weeks</option><option>months</option><option>years</option>
        </select>
      </td></tr>
      <tr><td>note</td><td><input name=note size=40></td></tr>
      <tr><td>order_id</td><td><input name=order_id size=20></td></tr>
      <tr><td>customer_id</td><td><input name=customer_id size=20></td></tr>
    </table>
    <br><button type=submit>Provision</button>
  </form>
</fieldset>

<!-- ── Verify / Activate / Check ── -->
<fieldset>
  <legend>Verify / Activate / Check</legend>
  <p>Your IP detected: <code>{{ detected_ip or '(unknown)' }}</code> — sent automatically.</p>
  <form method=post action=/verify>
    <table>
      <tr><td>endpoint</td><td>
        <select name=endpoint>
          <option value=/api/v1/verify>verify</option>
          <option value=/api/v1/activate>activate</option>
          <option value=/api/v1/check>check</option>
        </select>
      </td></tr>
      <tr><td>app_id</td><td><input name=app_id value="default"></td></tr>
      <tr><td>key</td><td><input name=key size=45 placeholder="XXXX-XXXX-XXXX-XXXX"></td></tr>
      <tr><td>hwid</td><td><input name=hwid value="{{ hwid }}" size=70></td></tr>
      <tr><td>version</td><td><input name=version value="1.0.0" size=12></td></tr>
    </table>
    <br><button type=submit>Send</button>
  </form>
  <form method=post action=/hwid/reset style="display:inline;margin-top:6px">
    <button type=submit>Reset my HWID</button>
  </form>
</fieldset>

<!-- ── Key info ── -->
<fieldset>
  <legend>Key info</legend>
  <form method=post action=/keyinfo>
    <table>
      <tr><td>app_id</td><td><input name=app_id value="default"></td></tr>
      <tr><td>key</td><td><input name=key size=45></td></tr>
    </table>
    <br><button type=submit>Get info</button>
  </form>
</fieldset>

<!-- ── Suspend / Resume / Revoke / Delete ── -->
<fieldset>
  <legend>Suspend / Resume / Revoke / Delete</legend>
  <form method=post action=/keyaction>
    <table>
      <tr><td>app_id</td><td><input name=app_id value="default"></td></tr>
      <tr><td>key</td><td><input name=key size=45></td></tr>
      <tr><td>reason</td><td><input name=reason size=40 placeholder="optional"></td></tr>
      <tr><td>action</td><td>
        <button name=action value=suspend type=submit>Suspend</button>
        <button name=action value=resume type=submit>Resume</button>
        <button name=action value=revoke type=submit>Revoke</button>
        <button name=action value=delete type=submit>Delete</button>
      </td></tr>
    </table>
  </form>
</fieldset>

</body>
</html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Panel: http://localhost:{port}")
    print(f"KeyBase admin: {ADMIN_URL}")
    print(f"KeyBase API:   {API_URL}")
    if PANEL_PASSWORD:
        print("Panel password: set")
    app.run(host="0.0.0.0", port=port, debug=False)
