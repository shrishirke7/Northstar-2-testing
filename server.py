import json
import queue
import os
import re
import secrets
import hashlib
import hmac
import subprocess
import time
import uuid
import ipaddress
import threading
import unicodedata
import shutil
import tempfile
import base64
import socket
import ssl
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request as URLRequest, urlopen
from urllib.error import URLError, HTTPError
from cryptography.fernet import Fernet, InvalidToken

import psycopg
from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", ROOT / "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/backups"))
RESTORE_LOCK_PATH = Path("/tmp/northstar-restore-in-progress")
DEFAULT_CAMERA_PROFILES = [
    {"id": "unv_camera", "name": "UNV · Direct camera", "protocol": "rtsp", "port": 554,
     "mainPath": "/media/video1", "subPath": "/media/video2", "requiresChannel": False, "sourceType": "camera"},
    {"id": "unv_nvr", "name": "UNV · NVR channel", "protocol": "rtsp", "port": 554,
     "mainPath": "/unicast/c{channel}/s0/live", "subPath": "/unicast/c{channel}/s1/live", "requiresChannel": True, "sourceType": "nvr"},
    {"id": "hikvision", "name": "Hikvision · Camera/NVR", "protocol": "rtsp", "port": 10554,
     "mainPath": "/Streaming/Channels/{channelStream}", "subPath": "/Streaming/Channels/{channelStream}", "requiresChannel": True, "sourceType": "camera"},
    {"id": "dahua", "name": "Dahua · Camera/NVR", "protocol": "rtsp", "port": 554,
     "mainPath": "/cam/realmonitor?channel={channel}&subtype={streamIndex}", "subPath": "/cam/realmonitor?channel={channel}&subtype={streamIndex}", "requiresChannel": True, "sourceType": "camera"},
    {"id": "axis", "name": "Axis · Camera", "protocol": "rtsp", "port": 554,
     "mainPath": "/axis-media/media.amp", "subPath": "/axis-media/media.amp", "requiresChannel": False, "sourceType": "camera"},
    {"id": "custom_rtsp", "name": "Other brand · Custom RTSP", "protocol": "rtsp", "port": 554,
     "mainPath": "", "subPath": "", "requiresChannel": False, "sourceType": "camera"},
    {"id": "http_mjpeg", "name": "HTTP · Direct MJPEG/HLS", "protocol": "http", "port": 80,
     "mainPath": "", "subPath": "", "requiresChannel": False, "sourceType": "camera"},
    {"id": "https_mjpeg", "name": "HTTPS · Direct MJPEG/HLS", "protocol": "https", "port": 443,
     "mainPath": "", "subPath": "", "requiresChannel": False, "sourceType": "camera"},
]
LOGIN_MEDIA_DIR = UPLOAD_DIR / "login-branding"
LOGIN_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
PROFILE_MEDIA_DIR = UPLOAD_DIR / 'profiles'
PROFILE_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
FONT_UPLOAD_DIR = UPLOAD_DIR / "fonts"
FONT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
APP_SECRET = os.getenv("APP_SECRET", "")
if len(APP_SECRET) < 40:
    raise RuntimeError("APP_SECRET must be a randomly generated secret of at least 40 characters")

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SESSION_IDLE_MINUTES = max(5, int(os.getenv("SESSION_IDLE_MINUTES", "30")))
SESSION_MAX_HOURS = max(1, int(os.getenv("SESSION_MAX_HOURS", "8")))
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_REFRESH_EACH_REQUEST=False,
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=60 * 60 * SESSION_MAX_HOURS,
)


@app.before_request
def pause_api_during_restore():
    request.max_content_length = 1024 * 1024 * 1024 if request.path == "/api/backups/restore" else 64 * 1024 * 1024
    if request.path.startswith("/api/") and RESTORE_LOCK_PATH.exists():
        return jsonify(error="A backup restore is in progress. Please try again shortly."), 503
DATABASE_URL = os.environ["DATABASE_URL"]
RECOVERY_QUESTIONS = ("Favourite animal", "Favourite colour", "Favourite food")
RECOVERY_GENERIC_MESSAGE = "If the account and answers match, the password was reset. Try signing in."
RECOVERY_DUMMY_HASH = generate_password_hash("not-a-real-recovery-answer")
LOGIN_DUMMY_HASH = generate_password_hash("not-a-real-login-password")

# Module grants are stored on each local account. A missing grant keeps the
# account's pre-existing access for compatibility; an explicit empty mapping
# means that a newly configured account has no module access.
MODULE_IDS = (
    "overview", "assets", "data_center", "surveillance", "tickets",
    "visitors", "gatepass",
    "maintenance", "ageing", "parts", "users", "departments", "factories",
    "software", "network", "snmp", "notifications", "reports", "valuation", "billing",
)
MODULE_DATA_KEYS = {
    "overview": ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "invoices"),
    "assets": ("assets", "departments"),
    "data_center": ("assets", "camera_streams", "camera_profiles"),
    "surveillance": ("assets", "camera_streams", "camera_profiles"),
    "tickets": ("departments",),
    "visitors": ("departments", "manual_users"),
    "gatepass": ("departments", "manual_users"),
    "maintenance": ("assets", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "departments"),
    "ageing": ("assets", "maintenance"),
    "parts": ("assets", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "departments"),
    "users": ("manual_users", "departments"),
    "departments": ("departments", "assets", "manual_users", "maintenance", "parts_assignments"),
    "factories": ("departments", "assets", "manual_users"),
    "software": ("software", "assets", "departments", "manual_users"),
    "network": ("assets", "network_ranges", "network_scan", "scanner_heartbeat", "scanner_ip_status"),
    "snmp": ("assets",),
    "notifications": ("notifications",),
    "reports": ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "invoices", "vendors"),
    "valuation": ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "invoices"),
    "billing": ("invoices", "vendors", "departments", "manual_users"),
}
MODULE_API_PATHS = {
    "/api/invoices": "billing", "/api/tickets": "tickets",
    "/api/visitors": "visitors", "/api/gate-passes": "gatepass",
    "/api/camera-profiles": "surveillance", "/api/camera-streams": "surveillance",
    "/api/cctv-media-auth": "surveillance",
    "/api/network-scans": "network", "/api/network-scan": "network",
    "/api/network-map": "network",
    "/api/notifications": "notifications",
    "/api/snmp-metrics": "snmp", "/api/snmp-monitors": "snmp", "/api/admin/snmp-monitors": "snmp",
}


def module_permissions_for(profile):
    if profile.get("role") == "Administrator":
        return {module: "write" for module in MODULE_IDS}
    explicit = profile.get("module_permissions")
    if isinstance(explicit, dict):
        return {module: explicit.get(module, "none") if explicit.get(module) in ("none", "read", "write") else "none" for module in MODULE_IDS}
    if profile.get("role") == "Viewer":
        return {module: "read" for module in MODULE_IDS}
    if profile.get("role") == "IT Ticketing":
        return {module: ("write" if module == "tickets" else "none") for module in MODULE_IDS}
    # Legacy accounts were not assigned module grants. Preserve their current
    # access until an administrator explicitly configures the account.
    return {module: "write" for module in MODULE_IDS}


def module_access(profile, module, write=False):
    grant = module_permissions_for(profile).get(module, "none")
    return grant == "write" if write else grant in ("read", "write")


def _slug_desk_id(raw_val, fallback="it"):
    s = re.sub(r"[^a-z0-9-]+", "-", str(raw_val or "").strip().lower()).strip("-")[:40]
    return s or fallback


def allowed_complaint_desks_for(profile):
    if not isinstance(profile, dict) or profile.get("role") == "Administrator":
        return None
    raw = profile.get("allowed_complaint_desks")
    if not isinstance(raw, list):
        return None
    cleaned = []
    for item in raw:
        v = str(item or "").strip().lower()
        if v in ("*", "all"):
            return None
        slug = _slug_desk_id(v, fallback="")
        if slug and slug not in cleaned:
            cleaned.append(slug)
    return set(cleaned)


def ticket_desk_allowed(profile, desk_id):
    allowed = allowed_complaint_desks_for(profile)
    if allowed is None:
        return True
    return _slug_desk_id(desk_id, fallback="it") in allowed


def gate_scope_for(profile):
    if not isinstance(profile, dict) or profile.get("role") == "Administrator":
        return "all"
    sc = str(profile.get("gate_scope") or "dept").strip().lower()
    if sc in ("management", "security", "all"):
        return sc
    return "dept"


def is_gate_security_or_admin(profile):
    return isinstance(profile, dict) and (profile.get("role") == "Administrator" or gate_scope_for(profile) == "security")


def user_allowed_gate_depts(profile):
    out = set()
    if not isinstance(profile, dict):
        return out
    for val in (profile.get("dept"), profile.get("department")):
        s = str(val or "").strip().casefold()
        if s:
            out.add(s)
    g_depts = profile.get("gate_departments")
    if isinstance(g_depts, list):
        for item in g_depts:
            s = str(item or "").strip().casefold()
            if s:
                out.add(s)
    return out


def _dept_matches(allowed_set, target_dept):
    td = str(target_dept or "").strip().casefold()
    if not td or not allowed_set:
        return False
    if "*" in allowed_set or "all" in allowed_set or td in allowed_set:
        return True
    td_norm = re.sub(r"\b(dept|department)\b", "", td).strip()
    for a in allowed_set:
        a_norm = re.sub(r"\b(dept|department)\b", "", a).strip()
        if a_norm and td_norm and a_norm == td_norm:
            return True
    return False


def visitor_row_visible(row, profile, is_admin=False):
    if is_admin or gate_scope_for(profile) in ("all", "management", "security"):
        return True
    if not isinstance(profile, dict):
        return False
    uname = str(profile.get("username") or "").strip().casefold()
    pname = str(profile.get("name") or "").strip().casefold()
    r_host_u = str(row.get("hostUsername") or "").strip().casefold()
    r_host_n = str(row.get("hostName") or "").strip().casefold()
    if (uname and r_host_u and r_host_u == uname) or (pname and r_host_n and r_host_n == pname):
        return True
    return _dept_matches(user_allowed_gate_depts(profile), row.get("department"))


def gatepass_row_visible(row, profile, is_admin=False):
    if is_admin or gate_scope_for(profile) in ("all", "management", "security"):
        return True
    if not isinstance(profile, dict):
        return False
    uname = str(profile.get("username") or "").strip().casefold()
    pname = str(profile.get("name") or "").strip().casefold()
    r_for_u = str(row.get("forUsername") or "").strip().casefold()
    r_for_n = str(row.get("forName") or "").strip().casefold()
    if (uname and r_for_u and r_for_u == uname) or (pname and r_for_n and r_for_n == pname):
        return True
    explicit_depts = {str(x or "").strip().casefold() for x in (profile.get("gate_departments") or []) if str(x or "").strip()}
    return _dept_matches(explicit_depts, row.get("department"))


def data_key_module(key):
    if key == "assets": return "assets"
    if key == "departments": return "departments"
    if key == "manual_users": return "users"
    if key in ("factories_config",): return "factories"
    if key == "software": return "software"
    if key.startswith("parts_"): return "parts"
    if key == "maintenance": return "maintenance"
    if key in ("invoices", "vendors"): return "billing"
    if key.startswith("camera_"): return "surveillance"
    if key.startswith("network_") or key.startswith("scanner_"): return "network"
    if key == "notifications": return "notifications"
    for module, keys in MODULE_DATA_KEYS.items():
        if key in keys:
            return module
    return None


def db():
    return psycopg.connect(DATABASE_URL, connect_timeout=8)


def camera_secret_box():
    key = base64.urlsafe_b64encode(hashlib.sha256((APP_SECRET + "|camera-streams-v1").encode()).digest())
    return Fernet(key)


def snmp_secret_box():
    key = base64.urlsafe_b64encode(hashlib.sha256((APP_SECRET + "|snmp-monitors-v1").encode()).digest())
    return Fernet(key)


def go2rtc_request(method, path, params=None):
    from urllib.parse import urlencode
    base = os.getenv("GO2RTC_API", "http://go2rtc:1984").rstrip("/")
    url = base + path + (("?" + urlencode(params)) if params else "")
    req = URLRequest(url, method=method)
    with urlopen(req, timeout=8) as response:
        response.read(2048)


def normalize_recovery_answer(value):
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).casefold().split())


def recovery_answer_hashes(values):
    if not isinstance(values, list) or len(values) != len(RECOVERY_QUESTIONS):
        return None
    answers = [normalize_recovery_answer(value) for value in values]
    if any(len(answer) < 3 or len(answer) > 200 for answer in answers):
        return None
    return [generate_password_hash(answer) for answer in answers]


def matches_recovery_answer(stored_hash, answer):
    try:
        return check_password_hash(stored_hash, answer)
    except (ValueError, TypeError, AttributeError):
        return False


def init_db():
    with db() as conn:
        schema = (ROOT / "schema.sql").read_text(encoding="utf-8")
        for statement in schema.split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.execute("INSERT INTO app_state(key,value) VALUES('assets','[]'),('software','[]'),('departments','[]'),('maintenance','[]'),('parts_catalog','[]'),('parts_inventory','[]'),('parts_stock_entries','[]'),('parts_assignments','[]'),('invoices','[]'),('vendors','[]'),('manual_users','[]'),('camera_streams','[]'),('camera_profiles','[]'),('network_ranges','[]'),('network_scan','{}'),('scanner_heartbeat','{}'),('scanner_ip_status','{}'),('settings','{}'),('profile_preferences','{}'),('notifications','{\"rules\":[],\"queue\":[]}') ON CONFLICT(key) DO NOTHING")


def signed_in(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        profile = session.get("profile")
        sid = str(session.get("sid") or "").strip()
        if not profile or not sid:
            session.clear()
            return jsonify(error="sign_in_required"), 401
        username = str(profile.get("username", "")).casefold()
        with db() as conn:
            sess_row = conn.execute(
                "SELECT username, auth_version, last_seen_at, created_at FROM user_sessions WHERE sid=%s",
                (sid,),
            ).fetchone()
            if not sess_row or str(sess_row[0]).casefold() != username:
                session.clear()
                return jsonify(error="session_expired_sign_in_again"), 401
            now_utc = datetime.now(timezone.utc)
            last_seen = sess_row[2]
            created_at = sess_row[3]
            if ((now_utc - last_seen).total_seconds() > SESSION_IDLE_MINUTES * 60
                    or (now_utc - created_at).total_seconds() > SESSION_MAX_HOURS * 3600):
                conn.execute("DELETE FROM user_sessions WHERE sid=%s", (sid,))
                session.clear()
                return jsonify(error="session_expired_sign_in_again"), 401
            row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
            users = row[0] if row else []
            account = next((u for u in users if str(u.get("username", "")).casefold() == username), None)
            try:
                current_version = int(account.get("auth_version", 0)) if account else -1
                session_version = int(session.get("auth_version", 0))
            except (TypeError, ValueError):
                current_version, session_version = -1, 0
            if not account or not account.get("enabled", True) or current_version != session_version or int(sess_row[1]) != current_version:
                conn.execute("DELETE FROM user_sessions WHERE sid=%s", (sid,))
                session.clear()
                return jsonify(error="session_expired_sign_in_again"), 401
            if (now_utc - last_seen).total_seconds() >= 45:
                conn.execute("UPDATE user_sessions SET last_seen_at=now() WHERE sid=%s", (sid,))
        # Refresh grants from the current server-side account on every request,
        # so permission changes take effect immediately without stale sessions.
        if isinstance(account.get("module_permissions"), dict):
            session["profile"]["module_permissions"] = account["module_permissions"]
        else:
            session["profile"].pop("module_permissions", None)
        if isinstance(account.get("allowed_complaint_desks"), list):
            session["profile"]["allowed_complaint_desks"] = account["allowed_complaint_desks"]
        else:
            session["profile"].pop("allowed_complaint_desks", None)
        g_scope = str(account.get("gate_scope") or "dept").strip().lower()
        session["profile"]["gate_scope"] = g_scope if g_scope in ("dept", "management", "security") else "dept"
        g_depts = account.get("gate_departments")
        session["profile"]["gate_departments"] = [str(x).strip() for x in g_depts if str(x).strip()] if isinstance(g_depts, list) else []
        session["profile"]["role"] = account.get("role", "User")
        session["is_admin"] = session["profile"]["role"] == "Administrator"
        return fn(*args, **kwargs)
    return wrapper


def administrator(fn):
    @wraps(fn)
    @signed_in
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def ticket_manager(fn):
    @wraps(fn)
    @signed_in
    def wrapper(*args, **kwargs):
        # Ticket reads are allowed for read-only grants; the global request
        # guard still requires a write grant for mutations.
        if not session.get("is_admin") and not module_access(session.get("profile", {}), "tickets"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def check_api_origin():
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            abort(403)
        if request.headers.get("X-Requested-With") not in ("NorthstarIT", "ShreeIT"):
            abort(403)


@app.before_request
def enforce_module_access():
    profile = session.get("profile") or {}
    if not profile or session.get("is_admin") or not request.path.startswith("/api/"):
        return None
    path = request.path
    method = request.method
    if path.startswith(("/api/internal/", "/api/public/")) or path in (
        "/api/login", "/api/logout", "/api/profile", "/api/profile/preferences",
        "/api/tile-configs",
        "/api/account/password", "/api/account/profile-picture", "/api/account/recovery-answers",
        "/api/account/logout-all", "/api/data", "/api/live-alerts-feed", "/api/live-pulse",
        "/api/live-stream",
        "/api/notifications/silent", "/api/notifications/history", "/api/notifications/history/read",
        "/api/speedtest/ping", "/api/speedtest/download", "/api/speedtest/upload",
        "/api/network/speedtest", "/api/network/speedtest/run", "/api/network/speedtest/settings",
    ) or (path == "/api/notifications/sounds" and method == "GET") or path.startswith("/api/recovery/"):
        return None
    is_write = method in ("POST", "PUT", "PATCH", "DELETE")
    module = next((value for prefix, value in MODULE_API_PATHS.items() if path == prefix or path.startswith(prefix + "/")), None)
    if path.startswith("/api/admin/"):
        # Administration endpoints remain administrator-only.
        return jsonify(error="Administrator access is required."), 403
    if path == "/api/backups" or path.startswith("/api/backups/"):
        return jsonify(error="Administrator access is required."), 403
    if path.startswith("/api/invoices") and not is_write:
        if any(module_access(profile, m) for m in ("billing", "valuation", "departments", "reports")):
            return None
    if path.startswith(("/api/camera-streams", "/api/camera-profiles", "/api/cctv-media-auth")):
        if module_access(profile, "surveillance", write=is_write) or module_access(profile, "data_center", write=is_write):
            return None
    if path == "/api/snmp-metrics" and not is_write:
        if any(module_access(profile, m) for m in ("snmp", "overview", "network")):
            return None
    if module:
        if not module_access(profile, module, write=is_write):
            return jsonify(error=("This module is read-only for your account." if is_write and module_access(profile, module) else "You do not have access to this module.")), 403
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if request.path in ("/", "/setup", "/portal") or (request.path.startswith("/api/") and request.path not in ("/api/live-stream", "/api/public/live-stream")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/cctv-live.js")
def cctv_live_script():
    return send_from_directory(ROOT, "cctv-live.js")


@app.get("/manifest.json")
def pwa_manifest():
    response = send_from_directory(ROOT, "manifest.json", mimetype="application/manifest+json")
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/sw.js")
def pwa_service_worker():
    response = send_from_directory(ROOT, "sw.js", mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/apple-touch-icon.png")
def pwa_apple_touch_icon():
    return send_from_directory(ROOT, "apple-touch-icon.png", mimetype="image/png")


@app.get("/favicon.ico")
def pwa_favicon():
    return send_from_directory(ROOT, "favicon.ico", mimetype="image/x-icon")


@app.get("/static/icons/<path:filename>")
def pwa_static_icon(filename):
    clean = secure_filename(filename)
    mime = "image/svg+xml" if clean.endswith(".svg") else "image/png"
    return send_from_directory(ROOT / "static" / "icons", clean, mimetype=mime)


def _extract_der_cert_from_pem(pem_bytes):
    txt = pem_bytes.decode("ascii", errors="ignore")
    matches = re.findall(r"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----", txt)
    if not matches:
        return None
    # If fullchain PEM (leaf + Root CA), return the final Root CA certificate in the chain
    b64 = re.sub(r"\s+", "", matches[-1])
    try:
        return base64.b64decode(b64)
    except Exception:
        return None


def _fetch_server_ca_cert_der():
    # 1. Prefer dedicated Root CA public file, else extract Root CA from fullchain nginx.crt (never private keys)
    for cand in (
        Path("/app/secrets/ca.crt"),
        ROOT / "secrets" / "ca.crt",
        Path("/etc/nginx/certs/ca.crt"),
        Path("/app/secrets/nginx.crt"),
        ROOT / "secrets" / "nginx.crt",
        Path("/etc/nginx/certs/nginx.crt"),
    ):
        try:
            if cand.is_file() and cand.stat().st_size > 0:
                der = _extract_der_cert_from_pem(cand.read_bytes())
                if der:
                    return der
        except OSError:
            pass

    # 2. Fallback: read public TLS certificate from local Nginx/web proxy over TLS handshake
    ports = []
    host_hdr = str(request.headers.get("X-Forwarded-Host") or request.host or "").strip()
    if ":" in host_hdr:
        try:
            p = int(host_hdr.rsplit(":", 1)[1])
            if 1 <= p <= 65535:
                ports.append(p)
        except ValueError:
            pass
    for env_p in (os.getenv("HTTPS_PORT"), "8849", "8899", "443"):
        if env_p:
            try:
                p = int(env_p)
                if 1 <= p <= 65535 and p not in ports:
                    ports.append(p)
            except ValueError:
                pass

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req_host = host_hdr.split(":")[0].strip("[]")
    hosts = ["web", "127.0.0.1", "host.docker.internal"]
    try:
        if req_host:
            ip_obj = ipaddress.ip_address(req_host)
            if ip_obj.is_private and not ip_obj.is_multicast:
                hosts.append(req_host)
    except ValueError:
        pass
    for host in hosts:
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=1.5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=req_host or host) as ssock:
                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            return der
            except OSError:
                continue
    return None


def _serve_ca_cert_response():
    der = _fetch_server_ca_cert_der()
    if not der:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Shree IT Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Shree IT Asset Intelligence"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256())
            )
            der = cert.public_bytes(serialization.Encoding.DER)
        except Exception:
            pass
    if not der:
        return jsonify(error="No HTTPS server certificate could be located on this host."), 404
    path = (getattr(request, "path", "") or "").lower()
    fname = "swarnshilp-server-ca.crt" if "swarnshilp" in path else "shree-server-ca.crt"
    want_dl = request.args.get("download", "").lower() in ("1", "true", "yes")
    disp = f'attachment; filename="{fname}"' if want_dl else f'inline; filename="{fname}"'
    resp = Response(der, status=200, mimetype="application/x-x509-ca-cert")
    resp.headers["Content-Disposition"] = disp
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.get("/shree-ca.crt")
@app.get("/northstar-ca.crt")
@app.get("/swarnshilp-server-ca.crt")
@app.get("/shree-server-ca.crt")
@app.get("/ca.crt")
def pwa_ca_cert():
    return _serve_ca_cert_response()


@app.get("/api/public/ca-cert")
def public_ca_cert():
    return _serve_ca_cert_response()


@app.get("/")
def index():
    if not setup_complete():
        return redirect("/setup")
    resp = send_from_directory(ROOT, "index.html")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


def setup_complete():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    users = row[0] if row else []
    return any(u.get("enabled", True) and u.get("password_hash") and u.get("role") == "Administrator" for u in users)


@app.get("/setup")
def setup_page():
    if setup_complete():
        return redirect("/")
    resp = send_from_directory(ROOT, "setup.html")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/api/setup/status")
def setup_status():
    return jsonify(configured=setup_complete())


@app.post("/api/setup")
def initial_setup():
    body = request.get_json(silent=True) or {}
    company = str(body.get("company", "")).strip()[:120]
    full_name = str(body.get("full_name", "")).strip()[:120]
    username = str(body.get("username", "")).strip()[:80]
    password = str(body.get("password", ""))
    answer_hashes = recovery_answer_hashes(body.get("recovery_answers"))
    if not full_name or not re.fullmatch(r"[A-Za-z0-9._@-]{3,80}", username):
        return jsonify(error="Enter the administrator name and a valid username (3–80 letters, numbers, dots, underscores, @, or hyphens)."), 400
    if not password or len(password) > 1024:
        return jsonify(error="Enter a password."), 400
    if not answer_hashes:
        return jsonify(error="Answer all three recovery questions (3–200 characters each)."), 400
    with db() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('northstar-first-setup'))")
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        if any(u.get("enabled", True) and u.get("password_hash") and u.get("role") == "Administrator" for u in users):
            return jsonify(error="Setup is already complete. Sign in instead."), 409
        if any(str(u.get("username", "")).casefold() == username.casefold() for u in users):
            return jsonify(error="That username already exists."), 409
        users.append({"id":username,"username":username,"name":full_name,"email":"","site":"","dept":"","role":"Administrator","enabled":True,"source":"manual","password_hash":generate_password_hash(password),"auth_version":0,"recovery_answer_hashes":answer_hashes})
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
        settings_row=conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        settings=settings_row[0] if settings_row else {}
        branding=dict(settings.get("loginBranding", {}))
        site_name = str(body.get("site_name") or body.get("siteName") or "").strip()[:120]
        if company:
            branding['companyName'] = company
            settings.update(companyName=company, loginBranding=branding)
        if site_name:
            settings['siteName'] = site_name
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='settings'",(json.dumps(settings),))
    if site_name:
        def _delayed_apply(sn):
            time.sleep(1.5)
            try:
                _updater_ipc({"action": "set_network_config", "siteName": sn, "httpPort": int(os.getenv("HTTP_PORT") or 8848), "httpsPort": int(os.getenv("HTTPS_PORT") or 8849)}, timeout=30)
            except Exception:
                pass
        threading.Thread(target=_delayed_apply, args=(site_name,), daemon=True).start()
    return jsonify(ok=True, redirect="/"), 201


@app.get("/api/login-branding")
def get_login_branding():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    settings = row[0] if row else {}
    branding = settings.get("loginBranding", {})
    company_name = str(branding.get("companyName") or settings.get("companyName") or "").strip()
    if not company_name or company_name.casefold() in ("shree", "northstar", "northstar it", "it asset management"):
        company_name = "Swarnshilp"
    return jsonify({
        "companyName": company_name[:120],
        "tagline": str(branding.get("tagline") or "")[:180],
        "showTagline": branding.get("showTagline", True) is not False,
        "logoUrl": str(branding.get("logoUrl") or "")[:300],
        "slides": branding.get("slides", [])[:5] if isinstance(branding.get("slides", []), list) else [],
        "slideInterval": max(3, min(30, int(branding.get("slideInterval", 6) or 6))),
    })


@app.get("/profile-media/<path:filename>")
def profile_media(filename):
    if Path(filename).name != filename or Path(filename).suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
        abort(404)
    return send_from_directory(PROFILE_MEDIA_DIR, filename, max_age=3600)


@app.get("/api/cctv-media-auth")
@signed_in
def cctv_media_auth():
    if request.headers.get("X-Original-Method") not in ("POST", "GET"):
        abort(403)
    origin = request.headers.get("X-Original-Origin", "").rstrip("/")
    if origin != request.host_url.rstrip("/"):
        abort(403)
    return "", 204


def stored_camera_profiles():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='camera_profiles'").fetchone()
    profiles = row[0] if row else []
    return profiles if isinstance(profiles, list) and profiles else DEFAULT_CAMERA_PROFILES


def valid_camera_profile_path(value, allow_empty=False):
    path = str(value or "").strip()
    if not path and allow_empty:
        return ""
    if (not path.startswith("/") or path.startswith("//") or len(path) > 512
            or any(ord(ch) < 32 for ch in path)):
        return None
    tokens = set(re.findall(r"\{([^{}]+)\}", path))
    remainder = re.sub(r"\{[^{}]+\}", "", path)
    if ("{" in remainder or "}" in remainder
            or not tokens.issubset({"channel", "stream", "streamIndex", "channelStream"})):
        return None
    return path


@app.get("/api/camera-profiles")
@signed_in
def get_camera_profiles():
    return jsonify(items=stored_camera_profiles())


@app.put("/api/camera-profiles")
@app.put("/api/admin/camera-profiles")
@signed_in
def save_camera_profiles():
    body = request.get_json(force=True)
    profiles = body.get("items") if isinstance(body, dict) else None
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 50:
        return jsonify(error="Save between 1 and 50 camera profiles."), 400
    clean, ids = [], set()
    for item in profiles:
        if not isinstance(item, dict):
            return jsonify(error="Each camera profile must be an object."), 400
        profile_id = str(item.get("id", "")).strip().lower()[:40]
        name = str(item.get("name", "")).strip()[:80]
        protocol = str(item.get("protocol", "")).strip().lower()
        try:
            port = int(item.get("port", 0))
        except (ValueError, TypeError):
            port = 0
        if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", profile_id) or profile_id in ids
                or not name or protocol not in ("rtsp", "http", "https") or not 1 <= port <= 65535):
            return jsonify(error="Check each profile's unique ID, name, protocol and port."), 400
        main_path = valid_camera_profile_path(item.get("mainPath"), allow_empty=protocol in ("http", "https"))
        sub_path = valid_camera_profile_path(item.get("subPath"), allow_empty=True)
        if main_path is None or sub_path is None:
            return jsonify(error="Stream paths must start with / and can use {channel}, {stream}, {streamIndex}, or {channelStream}."), 400
        ids.add(profile_id)
        clean.append({"id": profile_id, "name": name, "protocol": protocol, "port": port,
                      "mainPath": main_path, "subPath": sub_path,
                      "requiresChannel": bool(item.get("requiresChannel")),
                      "sourceType": "nvr" if str(item.get("sourceType", "camera")).lower() == "nvr" else "camera"})
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('camera_profiles',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
                     (json.dumps(clean),))
    return jsonify(ok=True, items=clean)


@app.get("/api/camera-streams")
@signed_in
def get_camera_streams():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='camera_streams'").fetchone()
    items = row[0] if row else []
    # go2rtc streams are runtime entries. Recreate them from the encrypted
    # database after a container restart before returning the list to viewers.
    # Browser WebRTC cannot receive H.265 in common browsers. Route camera RTSP
    # through go2rtc's bundled FFmpeg H.264 transcoder for a compatible live feed.
    migrated = False
    for item in items:
        try:
            source = camera_secret_box().decrypt(item["encryptedSource"].encode()).decode()
            if not source.startswith("ffmpeg:"):
                source = f"ffmpeg:{source}#video=h264"
                item["encryptedSource"] = camera_secret_box().encrypt(source.encode()).decode()
                migrated = True
            go2rtc_request("PUT", "/api/streams", {"name": item["streamName"], "src": source})
            item["gatewayReady"] = True
        except (KeyError, ValueError, InvalidToken, URLError, HTTPError, TimeoutError, OSError):
            item["gatewayReady"] = False
    if migrated:
        with db() as conn:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='camera_streams'",
                         (json.dumps(items),))
    public = [{k: item.get(k, "") for k in ("assetTag", "room", "hub", "channel", "stream", "streamName", "sourceType", "profile", "profileId", "profileName", "protocol", "ip", "rtspReachable")}
              for item in items if isinstance(item, dict)]
    for item, safe in zip((x for x in items if isinstance(x, dict)), public):
        safe["gatewayReady"] = bool(item.get("gatewayReady"))
    return jsonify(items=public)


@app.post("/api/camera-streams")
@app.post("/api/admin/camera-streams")
@signed_in
def save_camera_stream():
    body = request.get_json(force=True)
    asset_tag = str(body.get("assetTag", "")).strip()[:80]
    room = str(body.get("room", "")).strip()[:100]
    hub = str(body.get("hub", "")).strip()[:100]
    source_type = str(body.get("sourceType", "nvr")).lower()
    legacy_profile = str(body.get("profile", "")).strip().lower()
    profile_id = str(body.get("profileId", "")).strip().lower()
    stream = str(body.get("stream", "main")).lower()
    username = str(body.get("username", "")).strip()[:128]
    password = str(body.get("password", ""))[:256]
    try:
        channel = int(body.get("channel", 1))
        port = int(body.get("port", 554))
        camera_ip = ipaddress.ip_address(str(body.get("ip", "")).strip())
    except (ValueError, TypeError):
        return jsonify(error="Enter a valid private camera/NVR IP, stream port, and channel."), 400
    if camera_ip.is_global or camera_ip.is_multicast or camera_ip.is_unspecified or camera_ip.is_loopback or camera_ip.is_link_local or camera_ip.is_reserved:
        return jsonify(error="Use the camera/NVR's private VLAN IP address."), 400
    if not asset_tag:
        return jsonify(error="Select a saved CCTV asset with an asset tag. Register this device as Surveillance → CCTV first."), 400
    if not room or not hub or not username or not password:
        return jsonify(error="Enter the hub, room, camera username, and camera password."), 400
    if stream not in ("main", "sub") or not 1 <= channel <= 256 or not 1 <= port <= 65535:
        return jsonify(error="Check the stream quality, channel number, and TCP port (1–65535)."), 400
    stream_path = str(body.get("streamPath", "")).strip()[:512]
    protocol = "rtsp"
    profile_name = ""
    profile_data = next((p for p in stored_camera_profiles() if p.get("id") == profile_id), None) if profile_id else None
    if profile_id and not profile_data:
        return jsonify(error="That camera profile no longer exists. Refresh and select a saved profile."), 400
    if profile_data:
        protocol = profile_data["protocol"]
        source_type = profile_data.get("sourceType", "camera")
        profile_name = profile_data["name"]
        port = int(body.get("port") or profile_data["port"])
        template = profile_data.get("mainPath" if stream == "main" else "subPath") or profile_data.get("mainPath", "")
        tokens = {"channel": str(channel), "stream": stream,
                  "streamIndex": "0" if stream == "main" else "1",
                  "channelStream": str(channel * 100 + (1 if stream == "main" else 2))}
        configured_path = re.sub(r"\{(channel|stream|streamIndex|channelStream)\}", lambda m: tokens[m.group(1)], template)
        stream_path = stream_path or configured_path
    elif legacy_profile:
        profile_name = legacy_profile.replace("_", " ").title()
        if legacy_profile == "unv_camera":
            source_type, protocol = "camera", "rtsp"
            stream_path = stream_path or f"/media/video{'1' if stream == 'main' else '2'}"
        elif legacy_profile == "unv_nvr":
            source_type, protocol = "nvr", "rtsp"
            stream_path = stream_path or f"/unicast/c{channel}/s{'0' if stream == 'main' else '1'}/live"
        elif legacy_profile == "hikvision":
            source_type, protocol = "camera", "rtsp"
            stream_path = stream_path or f"/Streaming/Channels/{channel}0{'1' if stream == 'main' else '2'}"
        elif legacy_profile == "dahua":
            source_type, protocol = "camera", "rtsp"
            stream_path = stream_path or f"/cam/realmonitor?channel={channel}&subtype={'0' if stream == 'main' else '1'}"
        elif legacy_profile == "axis":
            source_type, protocol = "camera", "rtsp"
            stream_path = stream_path or "/axis-media/media.amp"
        elif legacy_profile == "custom_rtsp":
            source_type, protocol = "camera", "rtsp"
        elif legacy_profile == "http_mjpeg":
            source_type, protocol = "camera", "http"
        elif legacy_profile == "https_mjpeg":
            source_type, protocol = "camera", "https"
        else:
            return jsonify(error="Choose a supported camera profile."), 400
    elif source_type in ("nvr", "camera"):
        profile_id = "unv_nvr" if source_type == "nvr" else "unv_camera"
        profile_name = "UNV · NVR channel" if source_type == "nvr" else "UNV · Direct camera"
        protocol = "rtsp"
        stream_path = (f"/unicast/c{channel}/s{'0' if stream == 'main' else '1'}/live" if source_type == "nvr"
                       else f"/media/video{'1' if stream == 'main' else '2'}")
    else:
        return jsonify(error="Choose a supported camera profile."), 400
    if (not stream_path.startswith("/") or stream_path.startswith("//")
            or any(ord(ch) < 32 for ch in stream_path)):
        return jsonify(error="Enter a valid stream path starting with /; use the camera's video endpoint, not its web login page."), 400
    rtsp_reachable = False
    try:
        with socket.create_connection((str(camera_ip), port), timeout=2):
            rtsp_reachable = True
    except OSError:
        pass
    with db() as conn:
        assets_row = conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone()
        items_row = conn.execute("SELECT value FROM app_state WHERE key='camera_streams' FOR UPDATE").fetchone()
        assets = assets_row[0] if assets_row else []
        if not any(str(a.get("tag", "")) == asset_tag and str(a.get("type", "")).casefold() == "surveillance"
                   and str(a.get("subtype", a.get("subCategory", "CCTV"))).casefold() == "cctv" for a in assets):
            return jsonify(error="Select a registered CCTV asset first."), 400
        items = items_row[0] if items_row else []
        if any(item.get("assetTag") == asset_tag for item in items):
            return jsonify(error="This CCTV asset already has a live-feed setup. Remove it before adding it again."), 409
        stream_name = "cam_" + hmac.new(APP_SECRET.encode(), asset_tag.encode(), hashlib.sha256).hexdigest()[:24]
        host = f"[{camera_ip.compressed}]" if camera_ip.version == 6 else camera_ip.compressed
        source = f"{protocol}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}{stream_path}"
        try:
            go2rtc_request("PUT", "/api/streams", {"name": stream_name, "src": source})
        except HTTPError as exc:
            # Keep the gateway response body private: it may echo the camera stream URL,
            # which contains the camera credentials. The status code is safe and
            # distinguishes a reachable API rejecting the request from a network failure.
            try:
                detail = exc.read(512).decode("utf-8", "replace").strip()
            except OSError:
                detail = ""
            detail = re.sub(r"(?i)(?:rtsp|https?)://[^\s\"'<>]+", "[stream URL redacted]", detail)[:400]
            message = f"The live-video gateway responded with HTTP {exc.code}."
            if detail:
                message += " " + detail
            return jsonify(error=message), 502
        except (URLError, TimeoutError, OSError):
            return jsonify(error="The app cannot reach the go2rtc API at go2rtc:1984. Check Docker service networking and confirm go2rtc is running."), 503
        item = {"assetTag": asset_tag, "room": room, "hub": hub, "channel": channel, "stream": stream,
                "sourceType": source_type, "profile": profile_id or legacy_profile or ("unv_nvr" if source_type == "nvr" else "unv_camera"),
                "profileId": profile_id, "profileName": profile_name,
                "protocol": protocol.upper(), "streamName": stream_name, "ip": camera_ip.compressed,
                "rtspReachable": rtsp_reachable,
                "encryptedSource": camera_secret_box().encrypt(source.encode()).decode()}
        items.append(item)
        conn.execute("INSERT INTO app_state(key,value) VALUES('camera_streams',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
                     (json.dumps(items),))
    return jsonify(ok=True, rtspReachable=rtsp_reachable, item={k: item[k] for k in ("assetTag", "room", "hub", "channel", "stream", "streamName", "sourceType", "profile", "profileId", "profileName", "protocol", "ip", "rtspReachable")}), 201


@app.delete("/api/camera-streams/<asset_tag>")
@app.delete("/api/admin/camera-streams/<asset_tag>")
@signed_in
def delete_camera_stream(asset_tag):
    asset_tag = str(asset_tag).strip()[:80]
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='camera_streams' FOR UPDATE").fetchone()
        items = row[0] if row else []
        item = next((entry for entry in items if entry.get("assetTag") == asset_tag), None)
        if not item:
            return jsonify(error="Live-feed setup was not found."), 404
        try:
            go2rtc_request("DELETE", "/api/streams", {"src": item["streamName"]})
        except (URLError, HTTPError, TimeoutError, OSError):
            return jsonify(error="Could not remove the stream from go2rtc. Keep this setup and retry when the gateway is online."), 503
        items = [entry for entry in items if entry.get("assetTag") != asset_tag]
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='camera_streams'", (json.dumps(items),))
    return jsonify(ok=True)

@app.get("/login-media/<path:filename>")
def login_media(filename):
    if Path(filename).name != filename or Path(filename).suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
        abort(404)
    return send_from_directory(LOGIN_MEDIA_DIR, filename, max_age=3600)


@app.post("/api/admin/fonts")
@administrator
def upload_custom_font():
    upload = request.files.get("font")
    if not upload or not upload.filename:
        return jsonify(error="Choose a font file to upload."), 400
    ext = Path(secure_filename(upload.filename)).suffix.lower()
    signatures = {
        ".woff2": (b"wOF2", "font/woff2", "woff2"),
        ".woff": (b"wOFF", "font/woff", "woff"),
        ".ttf": (b"\x00\x01\x00\x00", "font/ttf", "truetype"),
        ".otf": (b"OTTO", "font/otf", "opentype"),
    }
    if ext not in signatures:
        return jsonify(error="Use a WOFF2, WOFF, TTF, or OTF font file."), 400
    data = upload.stream.read(5 * 1024 * 1024 + 1)
    if not data or len(data) > 5 * 1024 * 1024:
        return jsonify(error="Font files must be no larger than 5 MB."), 400
    signature, _, _ = signatures[ext]
    if not data.startswith(signature):
        return jsonify(error="The file contents do not match the selected font type."), 400
    filename = uuid.uuid4().hex + ext
    (FONT_UPLOAD_DIR / filename).write_bytes(data)
    return jsonify(name=secure_filename(upload.filename)[:120] or "Custom font", url="/api/custom-fonts/" + filename, format=signatures[ext][2]), 201


@app.post("/api/admin/font-settings")
@administrator
def save_font_settings():
    body = request.get_json(silent=True) or {}
    family = str(body.get("uiFontFamily", "Manrope"))[:180]
    custom_fonts = body.get("customFonts", [])
    if not isinstance(custom_fonts, list) or len(custom_fonts) > 10:
        return jsonify(error="Choose up to 10 uploaded fonts."), 400
    cleaned = []
    for font in custom_fonts:
        if not isinstance(font, dict):
            continue
        url = str(font.get("url", ""))
        if not re.fullmatch(r"/api/custom-fonts/[a-f0-9]{32}\.(?:woff2|woff|ttf|otf)", url):
            return jsonify(error="A custom font reference is invalid."), 400
        cleaned.append({"name": str(font.get("name", "Custom font"))[:120], "url": url,
                        "format": str(font.get("format", "woff2"))[:12]})
    if family.startswith("custom:") and not any(family == "custom:" + font["url"] for font in cleaned):
        return jsonify(error="Select an uploaded font that is in the font list."), 400
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        settings = row[0] if row and isinstance(row[0], dict) else {}
        settings["uiFontFamily"] = family
        settings["customFonts"] = cleaned
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='settings'", (json.dumps(settings),))
    return jsonify(ok=True, uiFontFamily=family, customFonts=cleaned)


@app.get("/api/custom-fonts/<path:filename>")
def custom_font_file(filename):
    if Path(filename).name != filename or not re.fullmatch(r"[a-f0-9]{32}\.(?:woff2|woff|ttf|otf)", filename):
        abort(404)
    mime = {".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".otf": "font/otf"}[Path(filename).suffix]
    response = send_from_directory(FONT_UPLOAD_DIR, filename, mimetype=mime, max_age=3600)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def save_login_image(upload):
    if not upload or not upload.filename:
        return ""
    ext = Path(upload.filename).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp"):
        raise ValueError("Use PNG, JPG, or WebP images only")
    data = upload.stream.read(10 * 1024 * 1024 + 1)
    if not data or len(data) > 10 * 1024 * 1024:
        raise ValueError("Each sign-in image must be between 1 byte and 10 MB")
    valid = (ext == ".png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or (ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8\xff")) or (ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    if not valid:
        raise ValueError("The uploaded file does not match its image type")
    filename = f"{uuid.uuid4().hex}{ext}"
    (LOGIN_MEDIA_DIR / filename).write_bytes(data)
    return "/login-media/" + filename


@app.post("/api/admin/login-branding")
@administrator
def save_login_branding():
    try:
        company = str(request.form.get("companyName", "")).strip()[:120]
        tagline = str(request.form.get("tagline", "")).strip()[:180]
        show_tagline = str(request.form.get("showTagline", "true")).strip().lower() in ("true", "yes", "1")
        try:
            interval = max(3, min(30, int(request.form.get("slideInterval", "6"))))
            slides = json.loads(request.form.get("slides", "[]"))
        except (ValueError, TypeError, json.JSONDecodeError):
            return jsonify(error="Invalid slideshow settings"), 400
        if not isinstance(slides, list) or len(slides) > 5 or any(not isinstance(s, dict) or not re.fullmatch(r"/login-media/[a-f0-9]{32}\.(?:png|jpe?g|webp)", str(s.get("imageUrl", ""))) for s in slides):
            return jsonify(error="Add up to 5 valid slideshow images"), 400
        uploads = [image for image in request.files.getlist("slidesUpload") if image and image.filename]
        if len(slides) + len(uploads) > 5:
            return jsonify(error="The sign-in slideshow supports up to 5 images"), 400
        with db() as conn:
            current = (conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone() or ({},))[0]
            branding = dict(current.get("loginBranding", {}))
        new_logo = save_login_image(request.files.get("logo"))
        if new_logo:
            branding["logoUrl"] = new_logo
        for image in uploads:
            image_url = save_login_image(image)
            if image_url:
                slides.append({"imageUrl": image_url, "caption": tagline if show_tagline else ""})
        branding.update(companyName=company, tagline=tagline, showTagline=show_tagline, slides=slides, slideInterval=interval)
        current["companyName"] = company
        current["loginBranding"] = branding
        with db() as conn:
            conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(current),))
        return jsonify(ok=True, branding=branding)
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400


@app.get("/healthz")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False), 503


NETWORK_SCAN_LOCK = threading.Lock()
NETWORK_SCAN_STATE = {"status":"idle", "progress":0, "total":0, "results":[], "error":"", "started_at":"", "finished_at":""}


def _persist_network_scan(state, scan_id):
    with db() as conn:
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan' AND value->>'id'=%s", (json.dumps(state), scan_id))


@app.get("/api/network-scans")
@signed_in
def network_scans():
    with db() as conn:
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        saved = (conn.execute("SELECT value FROM app_state WHERE key='network_scan'").fetchone() or ({},))[0]
        heartbeat = (conn.execute("SELECT value FROM app_state WHERE key='scanner_heartbeat'").fetchone() or ({},))[0]
    with NETWORK_SCAN_LOCK:
        state = dict(NETWORK_SCAN_STATE)
    if saved:
        state = saved
    if state.get("status") == "running" and state.get("started_at"):
        try:
            started = datetime.fromisoformat(state["started_at"])
            if (datetime.now(timezone.utc) - started).total_seconds() > 1800:
                state.update(status="failed", error="Scan stopped unexpectedly; start a new scan.", finished_at=datetime.now(timezone.utc).isoformat())
                _persist_network_scan(state, state.get("id", ""))
        except (ValueError, TypeError):
            pass
    last_seen = heartbeat.get('last_seen', '')
    try:
        scanner_connected = bool(last_seen) and (datetime.now(timezone.utc) - datetime.fromisoformat(last_seen)).total_seconds() <= 20
    except (ValueError, TypeError):
        scanner_connected = False
    return jsonify(ranges=ranges, scan=state, scannerConnected=scanner_connected)


@app.put("/api/network-scan/ranges")
@app.put("/api/admin/network-scan/ranges")
@signed_in
def save_network_scan_ranges():
    body = request.get_json(force=True)
    raw = body.get("ranges", [])
    if not isinstance(raw, list) or len(raw) > 25000:
        return jsonify(error="Enter up to 25,000 private IPv4 CIDR ranges"), 400
    networks = []
    for value in raw:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            return jsonify(error=f"Invalid network range: {value}"), 400
        if network.version != 4 or not network.is_private or network.is_loopback or network.is_link_local or network.num_addresses > 256:
            return jsonify(error="Only private IPv4 ranges up to /24 can be scanned"), 400
        if network not in networks:
            networks.append(network)
    values = [str(n) for n in networks]
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_ranges',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(values),))
    return jsonify(ok=True, ranges=values)


@app.post("/api/network-scan")
@app.post("/api/admin/network-scan")
@signed_in
def start_network_scan():
    global NETWORK_SCAN_STATE
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone()
        raw = row[0] if row else []
    if not raw:
        return jsonify(error="Add the authorized private network ranges to scan first"), 400
    networks = [ipaddress.ip_network(value, strict=True) for value in raw]
    hosts_count = sum(n.num_addresses - (2 if n.prefixlen < 31 else 0) for n in networks)
    if hosts_count > 25000:
        return jsonify(error="Combined scan limit is 25,000 addresses. CIDR ranges can be /24 or smaller."), 400
    with db() as conn:
        current = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        prior = current[0] if current else {}
        if prior.get("status") == "running" and prior.get("started_at"):
            try:
                recent = (datetime.now(timezone.utc) - datetime.fromisoformat(prior["started_at"])).total_seconds() < 1800
            except (ValueError, TypeError):
                recent = False
            if recent:
                return jsonify(error="A network scan is already running"), 409
        scan_id = str(uuid.uuid4())
        NETWORK_SCAN_STATE = {"id":scan_id,"status":"queued","progress":0,"total":hosts_count,"results":[],"error":"","started_at":datetime.now(timezone.utc).isoformat(),"finished_at":""}
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_scan',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(NETWORK_SCAN_STATE),))
    return jsonify(ok=True, scan_id=scan_id, total=hosts_count), 202


def _scanner_authorized():
    supplied = request.headers.get("X-Northstar-Scanner", "")
    return bool(supplied) and secrets.compare_digest(supplied, APP_SECRET)


def _snmp_rows(conn):
    row = conn.execute("SELECT value FROM app_state WHERE key='snmp_monitors'").fetchone()
    value = row[0] if row else []
    return value if isinstance(value, list) else []


@app.get("/api/admin/snmp-monitors")
@app.get("/api/snmp-monitors")
@signed_in
def get_snmp_monitors():
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "snmp"):
        abort(403)
    with db() as conn:
        monitors = _snmp_rows(conn)
        samples_row = conn.execute("SELECT value FROM app_state WHERE key='snmp_samples'").fetchone()
    samples = samples_row[0] if samples_row else []
    clean = [{k: v for k, v in item.items() if k not in ("authSecret", "privacySecret")} | {
        "hasAuthSecret": bool(item.get("authSecret")), "hasPrivacySecret": bool(item.get("privacySecret"))
    } for item in monitors]
    return jsonify(items=clean, samples=samples if isinstance(samples, list) else [])


@app.put("/api/admin/snmp-monitors")
@app.put("/api/snmp-monitors")
@signed_in
def save_snmp_monitors():
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "snmp", write=True):
        abort(403)
    body = request.get_json(force=True)
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list) or len(items) > 100:
        return jsonify(error="Provide up to 100 SNMP monitor entries."), 400
    with db() as conn:
        old_rows = _snmp_rows(conn)
        old_by_id = {str(item.get("id")): item for item in old_rows if isinstance(item, dict)}
        clean, seen = [], set()
        for item in items:
            if not isinstance(item, dict):
                return jsonify(error="Each SNMP monitor must be an object."), 400
            monitor_id = str(item.get("id") or uuid.uuid4()).strip()[:40]
            name = str(item.get("name", "")).strip()[:80]
            host = str(item.get("host", "")).strip()
            try:
                ip = ipaddress.ip_address(host)
                port = int(item.get("port", 161))
                interval = int(item.get("pollSeconds", 60))
                interface_index = str(item.get("interfaceIndex", "")).strip()
            except (ValueError, TypeError):
                return jsonify(error="Use a valid IP address, port, polling interval and interface index."), 400
            if (not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", monitor_id) or monitor_id in seen
                    or not name or ip.version != 4 or not ip.is_private or ip.is_multicast or ip.is_loopback
                    or not 1 <= port <= 65535 or not 15 <= interval <= 600
                    or (interface_index and (not interface_index.isdigit() or len(interface_index) > 8))):
                return jsonify(error="Check the unique ID, name, private IPv4, port, 15–600 second interval and optional interface index."), 400
            seen.add(monitor_id)
            prior = old_by_id.get(monitor_id, {})
            auth_protocol = str(item.get("authProtocol", "SHA")).upper()
            privacy_protocol = str(item.get("privacyProtocol", "AES")).upper()
            username = str(item.get("username", "")).strip()[:40]
            auth_secret = str(item.get("authSecret", ""))
            privacy_secret = str(item.get("privacySecret", ""))
            if auth_protocol not in ("SHA", "SHA-256", "SHA-384", "SHA-512") or privacy_protocol not in ("AES", "AES-192", "AES-256"):
                return jsonify(error="Choose a supported SNMPv3 authentication and AES privacy algorithm."), 400
            if not username or len(username) > 40:
                return jsonify(error="Enter the SNMPv3 username."), 400
            if auth_secret:
                if len(auth_secret) < 8 or len(auth_secret) > 128:
                    return jsonify(error="SNMP authentication passphrases must be 8–128 characters."), 400
                auth_secret = snmp_secret_box().encrypt(auth_secret.encode()).decode()
            else:
                auth_secret = prior.get("authSecret", "")
            if privacy_secret:
                if len(privacy_secret) < 8 or len(privacy_secret) > 128:
                    return jsonify(error="SNMP privacy passphrases must be 8–128 characters."), 400
                privacy_secret = snmp_secret_box().encrypt(privacy_secret.encode()).decode()
            else:
                privacy_secret = prior.get("privacySecret", "")
            if not auth_secret or not privacy_secret:
                return jsonify(error="Enter both SNMPv3 passphrases when adding a monitor."), 400
            clean.append({"id": monitor_id, "name": name, "host": str(ip), "port": port,
                          "pollSeconds": interval, "interfaceIndex": interface_index,
                          "username": username, "authProtocol": auth_protocol,
                          "privacyProtocol": privacy_protocol, "authSecret": auth_secret,
                          "privacySecret": privacy_secret, "enabled": bool(item.get("enabled", True)),
                          "lastPollAt": prior.get("lastPollAt", ""),
                          "lastStatus": prior.get("lastStatus", "Not checked"),
                          "lastError": prior.get("lastError", ""),
                          "nextPollAt": prior.get("nextPollAt", "")})
        conn.execute("INSERT INTO app_state(key,value) VALUES('snmp_monitors',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(clean),))
    return jsonify(ok=True, items=[{k: v for k, v in item.items() if k not in ("authSecret", "privacySecret")} for item in clean])


@app.get("/api/snmp-metrics")
@signed_in
def get_snmp_metrics():
    with db() as conn:
        profiles = _snmp_rows(conn)
        row = conn.execute("SELECT value FROM app_state WHERE key='snmp_samples'").fetchone()
    samples = row[0] if row else []
    return jsonify(items=[{"id": p.get("id"), "name": p.get("name"), "host": p.get("host"),
                           "enabled": p.get("enabled", True), "lastPollAt": p.get("lastPollAt", ""),
                           "lastStatus": p.get("lastStatus", "Not checked"), "lastError": p.get("lastError", "")}
                          for p in profiles], samples=samples if isinstance(samples, list) else [])


@app.get("/api/internal/snmp-task")
def snmp_task():
    if not _scanner_authorized():
        abort(403)
    now = datetime.now(timezone.utc)
    tasks = []
    with db() as conn:
        monitors = _snmp_rows(conn)
        changed = False
        for item in monitors:
            if not item.get("enabled", True):
                continue
            try:
                due = not item.get("nextPollAt") or datetime.fromisoformat(item["nextPollAt"]) <= now
            except (ValueError, TypeError):
                due = True
            if not due:
                continue
            item["nextPollAt"] = (now + __import__("datetime").timedelta(seconds=int(item.get("pollSeconds", 60)))).isoformat()
            try:
                task = {k: v for k, v in item.items() if k not in ("authSecret", "privacySecret")}
                task["authSecret"] = snmp_secret_box().decrypt(item["authSecret"].encode()).decode()
                task["privacySecret"] = snmp_secret_box().decrypt(item["privacySecret"].encode()).decode()
                tasks.append(task)
            except (KeyError, InvalidToken, ValueError):
                item["lastStatus"] = "Configuration error"
                item["lastError"] = "Stored SNMP credentials could not be decrypted; re-save this profile."
                changed = True
        if changed or tasks:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='snmp_monitors'", (json.dumps(monitors),))
    if not tasks:
        return ("", 204)
    return jsonify(items=tasks)


@app.post("/api/internal/snmp-results")
def snmp_results():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True)
    profile_id = str(body.get("id", ""))[:40]
    status = "Online" if body.get("ok") else "Error"
    message = str(body.get("error", ""))[:180]
    raw_samples = body.get("samples", [])
    if not profile_id or not isinstance(raw_samples, list) or len(raw_samples) > 512:
        return jsonify(error="Invalid SNMP metrics result."), 400
    clean_samples = []
    at = datetime.now(timezone.utc).isoformat()
    for sample in raw_samples:
        try:
            index = int(sample.get("interfaceIndex"))
            rx = max(0.0, min(1e13, float(sample.get("rxBps", 0))))
            tx = max(0.0, min(1e13, float(sample.get("txBps", 0))))
            clean_samples.append({"monitorId": profile_id, "interfaceIndex": index,
                                  "interfaceName": str(sample.get("interfaceName", ""))[:80],
                                  "rxBps": rx, "txBps": tx, "at": at})
        except (ValueError, TypeError, AttributeError):
            continue
    with db() as conn:
        profiles = _snmp_rows(conn)
        profile = next((p for p in profiles if p.get("id") == profile_id), None)
        if not profile:
            return jsonify(error="SNMP monitor no longer exists."), 404
        profile.update(lastPollAt=at, lastStatus=status, lastError=message)
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='snmp_monitors'", (json.dumps(profiles),))
        row = conn.execute("SELECT value FROM app_state WHERE key='snmp_samples' FOR UPDATE").fetchone()
        samples = row[0] if row and isinstance(row[0], list) else []
        samples.extend(clean_samples)
        cutoff = datetime.now(timezone.utc).timestamp() - 86400
        retained = []
        for sample in samples:
            try:
                if datetime.fromisoformat(sample.get("at", "")).timestamp() >= cutoff:
                    retained.append(sample)
            except (ValueError, TypeError):
                continue
        conn.execute("INSERT INTO app_state(key,value) VALUES('snmp_samples',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(retained[-20000:]),))
    return jsonify(ok=True, accepted=len(clean_samples))


def _notification_channel_status():
    return {
        "email": bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_FROM")),
        "whatsapp": bool(os.getenv("WHATSAPP_ACCESS_TOKEN") and os.getenv("WHATSAPP_PHONE_NUMBER_ID")
                         and os.getenv("WHATSAPP_API_VERSION") and os.getenv("WHATSAPP_TEMPLATE_NAME")),
    }


def _queue_asset_status_notifications(conn, state, asset, previous, current, checked_at, users):
    if previous not in ("Online", "Offline") or previous == current:
        return
    asset_tag = str(asset.get("tag", ""))
    asset_type = str(asset.get("type", ""))
    event = current
    for rule in state.get("rules", []):
        if not isinstance(rule, dict) or not rule.get("enabled", True) or event not in rule.get("events", []):
            continue
        if rule.get("scope") == "device":
            if asset_tag not in rule.get("deviceTags", []):
                continue
        elif rule.get("category") != asset_type:
            continue
        recipient_names = {str(value).casefold() for value in rule.get("recipients", [])}
        recipients = [user for user in users if str(user.get("username") or user.get("id") or "").casefold() in recipient_names]
        for user in recipients:
            for channel in ("email", "whatsapp"):
                if not rule.get("channels", {}).get(channel):
                    continue
                destination = str(user.get("email", "") if channel == "email" else user.get("phone", user.get("phone_number", ""))).strip()
                if not destination or (channel == "whatsapp" and not rule.get("whatsappOptInConfirmed")):
                    continue
                state.setdefault("queue", []).append({
                    "id": str(uuid.uuid4()), "rule": str(rule.get("name", "Status alert"))[:100],
                    "asset": str(asset.get("name", asset_tag))[:160], "tag": asset_tag[:100],
                    "category": asset_type[:40], "factory": str(asset.get("site", ""))[:40],
                    "ip": str(asset.get("ipAddress", asset.get("ip_address", "")))[:45],
                    "status": current, "previous": previous, "checkedAt": checked_at,
                    "channel": channel, "recipient": str(user.get("name") or user.get("username") or "")[:120],
                    "destination": destination[:254], "state": "pending", "attempts": 0,
                    "createdAt": checked_at, "nextAttemptAt": checked_at, "error": ""
                })
    state["queue"] = state.get("queue", [])[-500:]


DEFAULT_SOUND_ALERTS = {
    "masterEnabled": True,
    "volume": 0.85,
    "desktopNotifications": False,
    "defaultNewTypeSilent": False,
    "events": {
        "ticket": {"enabled": True, "soundId": "builtin:ticket-chime"},
        "online": {"enabled": True, "soundId": "builtin:online-ping"},
        "offline": {"enabled": True, "soundId": "builtin:offline-beep"},
        "critical": {"enabled": True, "soundId": "builtin:critical-siren"},
    },
    "criticalCriteria": {
        "types": ["Server", "Network"],
        "subtypes": ["Firewall", "Router", "NVR"],
        "keywords": ["firewall", "server", "core switch", "dc-", "nvr"],
        "deviceTags": [],
        "alertOnOffline": True,
        "alertOnOnline": True,
    },
    "deviceRules": {},
}


def normalize_sound_state(state, username=None):
    raw = state if isinstance(state, dict) else {}
    saved_cfg = raw.get("soundAlerts") if isinstance(raw.get("soundAlerts"), dict) else {}
    if username:
        ukey = str(username or "").strip().casefold()
        user_map = raw.get("userSoundAlerts") if isinstance(raw.get("userSoundAlerts"), dict) else {}
        if ukey and isinstance(user_map.get(ukey), dict):
            saved_cfg = user_map[ukey]
    merged = json.loads(json.dumps(DEFAULT_SOUND_ALERTS))
    if "masterEnabled" in saved_cfg:
        merged["masterEnabled"] = bool(saved_cfg.get("masterEnabled"))
    if "volume" in saved_cfg:
        try:
            merged["volume"] = max(0.0, min(1.0, float(saved_cfg.get("volume", 0.85))))
        except (TypeError, ValueError):
            pass
    if "desktopNotifications" in saved_cfg:
        merged["desktopNotifications"] = bool(saved_cfg.get("desktopNotifications"))
    if "defaultNewTypeSilent" in saved_cfg:
        merged["defaultNewTypeSilent"] = bool(saved_cfg.get("defaultNewTypeSilent"))
    raw_events = saved_cfg.get("events") if isinstance(saved_cfg.get("events"), dict) else {}
    for ev_key in ("ticket", "online", "offline", "critical"):
        ev_val = raw_events.get(ev_key)
        if isinstance(ev_val, dict):
            if "enabled" in ev_val:
                merged["events"][ev_key]["enabled"] = bool(ev_val.get("enabled"))
            if isinstance(ev_val.get("soundId"), str) and ev_val.get("soundId").strip():
                merged["events"][ev_key]["soundId"] = ev_val.get("soundId").strip()[:120]
    raw_crit = saved_cfg.get("criticalCriteria") if isinstance(saved_cfg.get("criticalCriteria"), dict) else {}
    for list_key in ("types", "subtypes", "keywords", "deviceTags"):
        if isinstance(raw_crit.get(list_key), list):
            merged["criticalCriteria"][list_key] = [str(x).strip()[:80] for x in raw_crit[list_key] if str(x).strip()][:50]
    for bool_key in ("alertOnOffline", "alertOnOnline"):
        if bool_key in raw_crit:
            merged["criticalCriteria"][bool_key] = bool(raw_crit.get(bool_key))
    raw_dev_rules = saved_cfg.get("deviceRules") if isinstance(saved_cfg.get("deviceRules"), dict) else {}
    clean_dev_rules = {}
    for rk, rv in list(raw_dev_rules.items())[:120]:
        k_norm = str(rk or "").strip().lower()[:60]
        if not k_norm or not isinstance(rv, dict):
            continue
        clean_dev_rules[k_norm] = {
            "label": str(rv.get("label") or rk)[:80],
            "silent": bool(rv.get("silent", False)),
            "onlineSoundId": str(rv.get("onlineSoundId") or "inherit").strip()[:120] or "inherit",
            "offlineSoundId": str(rv.get("offlineSoundId") or "inherit").strip()[:120] or "inherit",
        }
    merged["deviceRules"] = clean_dev_rules
    lib = raw.get("soundLibrary") if isinstance(raw.get("soundLibrary"), list) else []
    clean_lib = []
    for item in lib[:12]:
        if not isinstance(item, dict):
            continue
        sid = str(item.get("id") or "").strip()[:80]
        sname = str(item.get("name") or "").strip()[:80]
        data_url = str(item.get("dataUrl") or "").strip()
        mime = str(item.get("mime") or item.get("mimeType") or "").strip()[:60]
        if sid and sname and data_url.startswith(("data:audio/", "data:video/webm", "data:video/mp4", "data:video/ogg", "data:application/ogg")) and len(data_url) <= 3_500_000:
            clean_lib.append({"id": sid, "name": sname, "mime": mime, "dataUrl": data_url, "size": int(item.get("size") or len(data_url))})
    return merged, clean_lib


@app.get("/api/notifications")
@app.get("/api/admin/notifications")
@signed_in
def get_notification_rules():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notifications'").fetchone()
        state = row[0] if row else {"rules": [], "queue": []}
        users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
        users = users_row[0] if users_row else []
        asset_row = conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone()
        assets = asset_row[0] if asset_row else []
    history = [{k: item.get(k) for k in ("id", "rule", "asset", "tag", "category", "status", "channel", "recipient", "state", "createdAt", "error")} for item in state.get("queue", [])[-100:]]
    username_key = str((session.get("profile") or {}).get("username") or "").strip().casefold()
    sound_alerts, sound_library = normalize_sound_state(state, username=username_key)
    return jsonify(rules=state.get("rules", []), history=history, channels=_notification_channel_status(),
                   soundAlerts=sound_alerts, soundLibrary=sound_library,
                   users=[{"username": u.get("username") or u.get("id", ""), "name": u.get("name") or u.get("username") or u.get("id", ""), "email": u.get("email", ""), "phone": u.get("phone") or u.get("phone_number", "")} for u in users],
                   assets=[{"tag": a.get("tag", ""), "name": a.get("name", ""), "type": a.get("type", ""), "subtype": a.get("subtype", ""), "site": a.get("site", "")} for a in assets])


@app.get("/api/notifications/sounds")
@signed_in
def get_notification_sounds():
    username_key = str((session.get("profile") or {}).get("username") or "").strip().casefold()
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notifications'").fetchone()
        state = row[0] if row else {}
    sound_alerts, sound_library = normalize_sound_state(state, username=username_key)
    return jsonify(soundAlerts=sound_alerts, soundLibrary=sound_library)


@app.put("/api/notifications/sounds")
@signed_in
def save_notification_sounds():
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "notifications", write=True):
        return jsonify(error="Write access on Notifications is required."), 403
    body = request.get_json(force=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid sound preferences payload."), 400
    raw_lib = body.get("soundLibrary")
    if isinstance(raw_lib, list):
        if len(raw_lib) > 12:
            return jsonify(error="Upload up to 12 custom ringtones."), 400
        for item in raw_lib:
            if not isinstance(item, dict):
                return jsonify(error="Each custom ringtone must be an object."), 400
            durl = str(item.get("dataUrl") or "")
            if not durl.startswith(("data:audio/", "data:video/webm", "data:video/mp4", "data:video/ogg", "data:application/ogg")):
                return jsonify(error="Only audio files (.mp3, .wav, .ogg, .m4a, .webm) are accepted as ringtones."), 400
            if len(durl) > 3_500_000:
                return jsonify(error="Each custom ringtone must be 2.5 MB or smaller."), 400
    username_key = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    sound_alerts, sound_library = normalize_sound_state({
        "soundAlerts": body.get("soundAlerts", {}),
        "soundLibrary": body.get("soundLibrary", []),
    })
    with db() as conn:
        current = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
        state = dict(current[0]) if current and isinstance(current[0], dict) else {"rules": [], "queue": []}
        user_sounds = dict(state.get("userSoundAlerts") or {}) if isinstance(state.get("userSoundAlerts"), dict) else {}
        user_sounds[username_key] = sound_alerts
        state["userSoundAlerts"] = user_sounds
        if session.get("is_admin") or not state.get("soundAlerts"):
            state["soundAlerts"] = sound_alerts
        if "soundLibrary" in body:
            state["soundLibrary"] = sound_library
        else:
            _, existing_lib = normalize_sound_state(state)
            state["soundLibrary"] = existing_lib
        conn.execute("INSERT INTO app_state(key,value) VALUES('notifications',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
        _pg_emit_notify(conn, "pulse", {"source": "sounds", "username": username_key})
    return jsonify(ok=True, soundAlerts=sound_alerts, soundLibrary=state["soundLibrary"])


def _pulse_versions(conn, include_internal=False):
    row = conn.execute("""
        SELECT
          COALESCE((SELECT extract(epoch FROM max(updated_at))::text FROM tickets), '0'),
          (SELECT count(*)::bigint FROM tickets),
          COALESCE((SELECT max(id) FROM ticket_events), 0),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='settings'), '0'),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='assets'), '0'),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='notifications'), '0'),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='notification_history'), '0'),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='network_map'), '0'),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='tile_configs'), '0'),
          COALESCE((SELECT extract(epoch FROM max(updated_at))::text FROM visitor_passes), '0'),
          (SELECT count(*)::bigint FROM visitor_passes),
          COALESCE((SELECT extract(epoch FROM max(updated_at))::text FROM material_gate_passes), '0'),
          (SELECT count(*)::bigint FROM material_gate_passes)
    """).fetchone()
    ticket_rev = f"{row[0]}:{row[1]}:{row[2]}"
    visitor_rev = f"{row[9]}:{row[10]}"
    gatepass_rev = f"{row[11]}:{row[12]}"
    out = {
        "ticketRev": ticket_rev,
        "visitorRev": visitor_rev,
        "gatepassRev": gatepass_rev,
        "settingsRev": str(row[3] or "0"),
        "serverTime": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if include_internal:
        out["assetsRev"] = str(row[4] or "0")
        out["notificationsRev"] = str(row[5] or "0")
        out["historyRev"] = str(row[6] or "0")
        out["mapRev"] = str(row[7] or "0")
        out["tileConfigsRev"] = str(row[8] or "0")
    return out


def _normalize_notif_history_doc(raw):
    doc = dict(raw) if isinstance(raw, dict) else {}
    events = [e for e in (doc.get("events") if isinstance(doc.get("events"), list) else []) if isinstance(e, dict)][:400]
    reads = doc.get("reads") if isinstance(doc.get("reads"), dict) else {}
    silent = doc.get("silent") if isinstance(doc.get("silent"), dict) else {}
    return {"events": events, "reads": reads, "silent": silent, "rev": int(doc.get("rev") or 0)}


_LIVE_STREAM_SUBSCRIBERS = set()
_LIVE_STREAM_LOCK = threading.Lock()
_MAX_SSE_PER_WORKER = 16
_PG_LISTENER_STARTED = False
_PG_LISTENER_LOCK = threading.Lock()


def _broadcast_live_stream_event(event_type="pulse", data=None):
    with _LIVE_STREAM_LOCK:
        if not _LIVE_STREAM_SUBSCRIBERS:
            return
        msg = {
            "type": str(event_type or "pulse"),
            "timestamp": time.time(),
            "data": data if isinstance(data, dict) else {},
        }
        dead = []
        for entry in list(_LIVE_STREAM_SUBSCRIBERS):
            q, is_public = entry
            try:
                if is_public:
                    # Never expose internal device alerts, IPs, or private metadata to public /portal stream
                    ev_kind = str(msg["data"].get("kind") or "")
                    if msg["type"] in ("ticket", "visitor", "gatepass") or (msg["type"] == "notification" and ev_kind in ("ticket", "material_request", "visitor", "gatepass")):
                        pub_type = msg["type"] if msg["type"] in ("ticket", "visitor", "gatepass") else ev_kind
                        pub_msg = {"type": pub_type, "timestamp": msg["timestamp"], "data": {"action": "refresh"}}
                        q.put_nowait(pub_msg)
                else:
                    q.put_nowait(msg)
            except Exception:
                dead.append(entry)
        for entry in dead:
            _LIVE_STREAM_SUBSCRIBERS.discard(entry)


def _pg_emit_notify(conn, event_type="pulse", data=None):
    payload_obj = {
        "type": str(event_type or "pulse")[:40],
        "timestamp": time.time(),
        "data": data if isinstance(data, dict) else {},
    }
    payload_str = json.dumps(payload_obj, separators=(",", ":"))
    if len(payload_str.encode("utf-8")) > 7500:
        d = payload_obj["data"]
        payload_obj["data"] = {
            k: d[k] for k in ("id", "eventKey", "kind", "level", "title", "factory",
                              "targetView", "targetTab", "targetId", "targetTag", "action", "ticketId")
            if k in d
        }
        payload_str = json.dumps(payload_obj, separators=(",", ":"))
    if conn is not None:
        try:
            conn.execute("SELECT pg_notify('northstar_live_events', %s)", (payload_str,))
            return
        except Exception:
            pass
    _broadcast_live_stream_event(event_type, payload_obj["data"])


def _pg_listener_loop():
    while True:
        try:
            with psycopg.connect(DATABASE_URL, autocommit=True, connect_timeout=8) as lconn:
                lconn.execute("LISTEN northstar_live_events")
                while True:
                    for notify in lconn.notifies(timeout=20.0):
                        if not notify or not notify.payload:
                            continue
                        try:
                            msg = json.loads(notify.payload)
                            _broadcast_live_stream_event(msg.get("type", "pulse"), msg.get("data"))
                        except Exception:
                            _broadcast_live_stream_event("pulse", {})
        except Exception:
            time.sleep(2.5)


def _ensure_pg_listener():
    global _PG_LISTENER_STARTED
    if _PG_LISTENER_STARTED:
        return
    with _PG_LISTENER_LOCK:
        if _PG_LISTENER_STARTED:
            return
        _PG_LISTENER_STARTED = True
        t = threading.Thread(target=_pg_listener_loop, name="northstar-pg-listener", daemon=True)
        t.start()


def _record_notification_event(conn, item):
    if not isinstance(item, dict):
        return None
    row = conn.execute("SELECT value FROM app_state WHERE key='notification_history' FOR UPDATE").fetchone()
    doc = _normalize_notif_history_doc(row[0] if row else {})
    ev_key = str(item.get("eventKey") or "").strip()[:160]
    if ev_key and any(str(x.get("eventKey") or "") == ev_key for x in doc["events"][:100]):
        return None
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ev = {
        "id": str(item.get("id") or ("nh-" + uuid.uuid4().hex[:12]))[:80],
        "eventKey": ev_key,
        "kind": str(item.get("kind") or "info")[:40],
        "level": str(item.get("level") or "info")[:20],
        "title": str(item.get("title") or "Notification")[:180],
        "body": str(item.get("body") or "")[:400],
        "factory": str(item.get("factory") or "")[:60],
        "targetView": str(item.get("targetView") or "")[:40],
        "targetTab": str(item.get("targetTab") or "")[:40],
        "targetId": str(item.get("targetId") or "")[:120],
        "targetTag": str(item.get("targetTag") or "")[:120],
        "targetIp": str(item.get("targetIp") or "")[:64],
        "deviceType": str(item.get("deviceType") or "")[:60],
        "deviceSubtype": str(item.get("deviceSubtype") or "")[:60],
        "transitionStatus": str(item.get("transitionStatus") or "")[:20],
        "complaintDesk": _slug_desk_id(item.get("complaintDesk") or "it", fallback="it")[:40],
        "targetDepartment": str(item.get("targetDepartment") or "")[:120],
        "targetUsername": str(item.get("targetUsername") or "")[:120],
        "targetHostName": str(item.get("targetHostName") or "")[:120],
        "createdAt": str(item.get("createdAt") or now_iso)[:40],
    }
    doc["events"] = [ev] + doc["events"]
    doc["events"] = doc["events"][:400]
    doc["rev"] = doc["rev"] + 1
    conn.execute(
        "INSERT INTO app_state(key,value) VALUES('notification_history',%s::jsonb) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
        (json.dumps(doc),),
    )
    _pg_emit_notify(conn, "notification", ev)
    if ev.get("kind") in ("ticket", "material_request"):
        _pg_emit_notify(conn, "ticket", {"action": "create", "ticketId": ev.get("targetId", ""), "kind": ev.get("kind")})
    return ev


def _is_critical_device_server(asset, notif_state):
    if not isinstance(asset, dict):
        return False
    sound_alerts, _ = normalize_sound_state(notif_state or {})
    crit = sound_alerts.get("criticalCriteria") or {}
    tag = str(asset.get("tag") or "").strip().lower()
    if tag and any(str(t or "").strip().lower() == tag for t in (crit.get("deviceTags") or [])):
        return True
    dev_type = str(asset.get("type") or "").strip().lower()
    dev_sub = str(asset.get("subtype") or "").strip().lower()
    if any(str(s or "").strip().lower() in dev_sub for s in (crit.get("subtypes") or []) if str(s or "").strip()):
        return True
    for t in (crit.get("types") or []):
        tv = str(t or "").strip().lower()
        if not tv:
            continue
        if dev_sub and tv in dev_sub:
            return True
        if tv == "network" and dev_type == "network" and dev_sub and not any(k in dev_sub for k in ("firewall", "router", "core switch")):
            continue
        if tv == dev_type or tv in dev_type:
            return True
    hay = " ".join(str(asset.get(k) or "") for k in ("name", "tag", "specs", "notes", "role", "subtype")).lower()
    return any(str(kw or "").strip().lower() in hay for kw in (crit.get("keywords") or []) if str(kw or "").strip())


def _record_asset_transition_notification(conn, notif_state, asset, new_status, checked_at):
    tag = str(asset.get("tag") or "").strip()
    name = str(asset.get("name") or tag or "Device").strip()
    ip = str(asset.get("ipAddress") or asset.get("ip_address") or "").strip()
    site = str(asset.get("site") or "").strip()
    dev_type = str(asset.get("type") or "Device").strip()
    sub = str(asset.get("subtype") or "").strip()
    st_low = str(new_status or "").strip().lower()
    is_crit = _is_critical_device_server(asset, notif_state)
    kind = "critical" if is_crit else ("offline" if st_low == "offline" else "online")
    level = ("critical" if st_low == "offline" else "ok") if is_crit else ("warn" if st_low == "offline" else "ok")
    title = f"CRITICAL DEVICE {st_low.upper()}: {name}" if is_crit else (f"Device Offline: {name}" if st_low == "offline" else f"Device Online: {name}")
    body = " · ".join(p for p in [dev_type + (f" ({sub})" if sub else ""), f"IP {ip}" if ip else "", site] if p)
    _record_notification_event(conn, {
        "eventKey": f"dev:{tag}:{st_low}:{checked_at}",
        "kind": kind,
        "level": level,
        "title": title,
        "body": body,
        "factory": site,
        "targetView": "assets",
        "targetTag": tag,
        "targetIp": ip,
        "deviceType": dev_type,
        "deviceSubtype": sub,
        "transitionStatus": st_low,
        "createdAt": checked_at,
    })


def _generate_sse_stream(is_public=False):
    _ensure_pg_listener()
    q = queue.Queue(maxsize=120)
    entry = (q, bool(is_public))
    with _LIVE_STREAM_LOCK:
        if len(_LIVE_STREAM_SUBSCRIBERS) >= _MAX_SSE_PER_WORKER:
            return
        _LIVE_STREAM_SUBSCRIBERS.add(entry)
    try:
        try:
            with db() as conn:
                pulse = _pulse_versions(conn, include_internal=(not is_public))
            yield f"retry: 3000\nevent: connected\ndata: {json.dumps(pulse)}\n\n"
        except Exception:
            yield "retry: 3000\nevent: connected\ndata: {}\n\n"
        while True:
            try:
                msg = q.get(timeout=20)
                ev_type = msg.get("type", "pulse")
                yield f"event: {ev_type}\ndata: {json.dumps(msg)}\n\n"
            except queue.Empty:
                yield f": heartbeat {int(time.time())}\n\n"
    except GeneratorExit:
        pass
    finally:
        with _LIVE_STREAM_LOCK:
            _LIVE_STREAM_SUBSCRIBERS.discard(entry)


@app.get("/api/live-stream")
@signed_in
def live_stream_sse():
    with _LIVE_STREAM_LOCK:
        if len(_LIVE_STREAM_SUBSCRIBERS) >= _MAX_SSE_PER_WORKER:
            return ("", 503)
    resp = Response(_generate_sse_stream(is_public=False), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers["Connection"] = "keep-alive"
    return resp


@app.get("/api/public/live-stream")
def public_live_stream_sse():
    with _LIVE_STREAM_LOCK:
        if len(_LIVE_STREAM_SUBSCRIBERS) >= _MAX_SSE_PER_WORKER:
            return ("", 503)
    resp = Response(_generate_sse_stream(is_public=True), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers["Connection"] = "keep-alive"
    return resp


@app.get("/api/live-pulse")
@signed_in
def live_pulse():
    with db() as conn:
        return jsonify(**_pulse_versions(conn, include_internal=True))


@app.get("/api/notifications/history")
@signed_in
def get_notification_history():
    username = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notification_history'").fetchone()
    doc = _normalize_notif_history_doc(row[0] if row else {})
    user_reads = doc["reads"].get(username) if isinstance(doc["reads"].get(username), dict) else {}
    read_ids = set(str(x) for x in (user_reads.get("readIds") or []))
    cleared_ids = set(str(x) for x in (user_reads.get("clearedIds") or []))
    read_all_before = str(user_reads.get("readAllBefore") or "")
    cleared_before = str(user_reads.get("clearedBefore") or "")
    silent_mode = bool(doc["silent"].get(username, False))

    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    can_tickets = is_adm or module_access(who, "tickets")
    can_visitors = is_adm or module_access(who, "visitors")
    can_gatepass = is_adm or module_access(who, "gatepass")
    can_devices = is_adm or any(module_access(who, m) for m in ("assets", "network", "notifications", "overview", "surveillance", "data_center"))
    visible = []
    unread_count = 0
    for ev in doc["events"]:
        ev_kind = str(ev.get("kind") or "")
        if ev_kind in ("ticket", "material_request"):
            if not can_tickets or not ticket_desk_allowed(who, ev.get("complaintDesk") or "it"):
                continue
        elif ev_kind == "visitor":
            if not can_visitors or not visitor_row_visible({
                "department": ev.get("targetDepartment") or "",
                "hostUsername": ev.get("targetUsername") or "",
                "hostName": ev.get("targetHostName") or "",
            }, who, is_adm):
                continue
        elif ev_kind == "gatepass":
            if not can_gatepass or not gatepass_row_visible({
                "department": ev.get("targetDepartment") or "",
                "forUsername": ev.get("targetUsername") or "",
                "forName": ev.get("targetHostName") or "",
            }, who, is_adm):
                continue
        elif ev_kind in ("online", "offline", "critical") or ev.get("targetTag"):
            if not can_devices:
                continue
        eid = str(ev.get("id") or "")
        created = str(ev.get("createdAt") or "")
        if eid in cleared_ids or (cleared_before and created and created <= cleared_before):
            continue
        is_read = (eid in read_ids) or bool(read_all_before and created and created <= read_all_before)
        item = {**ev, "read": is_read}
        visible.append(item)
        if not is_read:
            unread_count += 1
    return jsonify(events=visible, unreadCount=unread_count, silentMode=silent_mode, rev=doc["rev"])


@app.post("/api/notifications/history/read")
@signed_in
def mark_notification_history_read():
    username = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    body = request.get_json(silent=True) or {}
    mark_all = bool(body.get("all"))
    raw_ids = body.get("ids") if isinstance(body.get("ids"), list) else ([body.get("id")] if body.get("id") else [])
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notification_history' FOR UPDATE").fetchone()
        doc = _normalize_notif_history_doc(row[0] if row else {})
        ur = dict(doc["reads"].get(username) or {})
        if mark_all:
            ur["readAllBefore"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            ur["readIds"] = []
        else:
            existing = list(dict.fromkeys([str(x) for x in (ur.get("readIds") or [])] + [str(x) for x in raw_ids if x]))
            ur["readIds"] = existing[-400:]
        doc["reads"][username] = ur
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('notification_history',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(doc),),
        )
    return jsonify(ok=True)


@app.delete("/api/notifications/history")
@signed_in
def clear_notification_history():
    username = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    body = request.get_json(silent=True) or {}
    mode = str(body.get("mode") or "all").lower()
    raw_ids = body.get("ids") if isinstance(body.get("ids"), list) else ([body.get("id")] if body.get("id") else [])
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notification_history' FOR UPDATE").fetchone()
        doc = _normalize_notif_history_doc(row[0] if row else {})
        ur = dict(doc["reads"].get(username) or {})
        if raw_ids:
            cleared = list(dict.fromkeys([str(x) for x in (ur.get("clearedIds") or [])] + [str(x) for x in raw_ids if x]))
            ur["clearedIds"] = cleared[-400:]
        elif mode == "read":
            read_ids = set(str(x) for x in (ur.get("readIds") or []))
            read_all_before = str(ur.get("readAllBefore") or "")
            newly_cleared = [
                str(ev.get("id")) for ev in doc["events"]
                if str(ev.get("id")) in read_ids or (read_all_before and str(ev.get("createdAt") or "") <= read_all_before)
            ]
            cleared = list(dict.fromkeys([str(x) for x in (ur.get("clearedIds") or [])] + newly_cleared))
            ur["clearedIds"] = cleared[-400:]
        else:
            ur["clearedBefore"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            ur["clearedIds"] = []
        doc["reads"][username] = ur
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('notification_history',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(doc),),
        )
    return jsonify(ok=True)


@app.put("/api/notifications/silent")
@signed_in
def save_notification_silent_mode():
    username = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    body = request.get_json(silent=True) or {}
    silent = bool(body.get("silent"))
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notification_history' FOR UPDATE").fetchone()
        doc = _normalize_notif_history_doc(row[0] if row else {})
        doc["silent"][username] = silent
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('notification_history',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(doc),),
        )
        _pg_emit_notify(conn, "pulse", {"source": "silent", "silent": silent})
    return jsonify(ok=True, silentMode=silent)


@app.get("/api/public/live-pulse")
def public_live_pulse():
    with db() as conn:
        return jsonify(**_pulse_versions(conn, include_internal=False))


@app.get("/api/live-alerts-feed")
@signed_in
def live_alerts_feed():
    who = session["profile"]
    is_adm = bool(session.get("is_admin"))
    can_tickets = is_adm or module_access(who, "tickets")
    can_devices = is_adm or any(module_access(who, m) for m in ("assets", "network", "notifications", "overview", "surveillance", "data_center"))
    want_tickets = request.args.get("tickets", "1") != "0"
    want_devices = request.args.get("devices", "1") != "0"
    want_sounds = request.args.get("sounds", "0") == "1"
    out = {"latestTickets": [], "deviceStates": [], "serverTime": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with db() as conn:
        if want_sounds:
            notif_row = conn.execute("SELECT value FROM app_state WHERE key='notifications'").fetchone()
            sound_alerts, sound_library = normalize_sound_state(notif_row[0] if notif_row else {}, username=who.get("username"))
            out["soundAlerts"] = sound_alerts
            out["soundLibrary"] = sound_library
            out["includeSounds"] = bool(sound_library)
        if want_tickets and can_tickets:
            t_rows = conn.execute(
                "SELECT id,kind,display_name,department,factory,primary_category,sub_category,status,created_at,updated_at,complaint_desk FROM tickets ORDER BY created_at DESC LIMIT 80"
            ).fetchall()
            out["latestTickets"] = [
                {"id": r[0], "kind": r[1], "name": r[2], "dept": r[3], "site": r[4], "primary": r[5], "sub": r[6],
                 "status": r[7], "created": r[8].isoformat(timespec="seconds") if r[8] else "",
                 "updated": r[9].isoformat(timespec="seconds") if r[9] else "",
                 "complaintDesk": r[10] or "it"}
                for r in t_rows
                if ticket_desk_allowed(who, r[10] or "it")
            ][:40]
        if want_devices and can_devices:
            a_row = conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone()
            a_list = a_row[0] if a_row and isinstance(a_row[0], list) else []
            out["deviceStates"] = [
                {"tag": str(a.get("tag") or ""), "name": str(a.get("name") or ""), "type": str(a.get("type") or ""),
                 "subtype": str(a.get("subtype") or ""), "site": str(a.get("site") or ""),
                 "ipAddress": str(a.get("ipAddress") or a.get("ip_address") or ""),
                 "ipStatus": str(a.get("ipStatus") or a.get("status") or ""),
                 "ipCheckedAt": str(a.get("ipCheckedAt") or ""), "lastSeen": str(a.get("lastSeen") or a.get("seen") or "")}
                for a in a_list if isinstance(a, dict)
            ]
        out["pulse"] = _pulse_versions(conn, include_internal=True)
    return jsonify(**out)


@app.put("/api/notifications")
@app.put("/api/admin/notifications")
@signed_in
def save_notification_rules():
    body = request.get_json(force=True) or {}
    rules = body.get("rules")
    if not isinstance(rules, list) or len(rules) > 100:
        return jsonify(error="Provide up to 100 notification rules."), 400
    allowed_categories = {"Laptop", "Desktop", "Server", "Printer", "Network", "Mobile", "Tablet"}
    clean = []
    seen_ids = set()
    with db() as conn:
        user_rows = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
        configured_users = user_rows[0] if user_rows else []
        user_map = {str(u.get("username") or u.get("id") or "").casefold(): u for u in configured_users}
        valid_users = set(user_map)
        asset_rows = conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone()
        current_assets = asset_rows[0] if asset_rows else []
        valid_tags = {str(a.get("tag", "")) for a in current_assets}
        allowed_categories.update(str(a.get("type", "")) for a in current_assets if a.get("type"))
        for item in rules:
            if not isinstance(item, dict):
                return jsonify(error="Each rule must be an object."), 400
            rule_id = str(item.get("id") or uuid.uuid4())[:80]
            name = str(item.get("name", "")).strip()[:100]
            scope = item.get("scope")
            category = str(item.get("category", ""))
            tags = list(dict.fromkeys(str(x) for x in item.get("deviceTags", []) if str(x) in valid_tags))[:100]
            events = [x for x in (item.get("events") if isinstance(item.get("events"), list) else []) if x in ("Online", "Offline")]
            recipients = list(dict.fromkeys(str(x) for x in (item.get("recipients") if isinstance(item.get("recipients"), list) else []) if str(x).casefold() in valid_users))[:100]
            channels = item.get("channels") if isinstance(item.get("channels"), dict) else {}
            if not name or scope not in ("category", "device") or (scope == "category" and category not in allowed_categories) or (scope == "device" and not tags) or not events or not recipients or not (channels.get("email") or channels.get("whatsapp")):
                return jsonify(error="Every rule needs a name, scope, event, recipient and delivery channel."), 400
            selected_users = [user_map[username.casefold()] for username in recipients]
            if channels.get("email") and any(not str(user.get("email", "")).strip() for user in selected_users):
                return jsonify(error="Every selected recipient needs an email address to use email alerts."), 400
            if channels.get("whatsapp") and any(not 8 <= len(re.sub(r"\D", "", str(user.get("phone") or user.get("phone_number") or ""))) <= 15 for user in selected_users):
                return jsonify(error="Every selected WhatsApp recipient needs a valid phone number with country code."), 400
            if channels.get("whatsapp") and not item.get("whatsappOptInConfirmed"):
                return jsonify(error="Confirm WhatsApp recipients have opted in before enabling WhatsApp alerts."), 400
            if rule_id in seen_ids:
                return jsonify(error="Rule IDs must be unique."), 400
            seen_ids.add(rule_id)
            clean.append({"id": rule_id, "name": name, "enabled": bool(item.get("enabled", True)), "scope": scope,
                          "category": category if scope == "category" else "", "deviceTags": tags if scope == "device" else [],
                          "events": list(dict.fromkeys(events)), "recipients": recipients,
                          "channels": {"email": bool(channels.get("email")), "whatsapp": bool(channels.get("whatsapp"))},
                          "whatsappOptInConfirmed": bool(item.get("whatsappOptInConfirmed"))})
        current = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
        state = current[0] if current else {"rules": [], "queue": []}
        state["rules"] = clean
        conn.execute("INSERT INTO app_state(key,value) VALUES('notifications',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
    return jsonify(ok=True, rules=clean)


@app.get("/api/internal/notification-task")
def notification_task():
    if not _scanner_authorized():
        abort(403)
    now = datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
        state = row[0] if row else {"rules": [], "queue": []}
        channels = _notification_channel_status()
        for job in state.get("queue", []):
            if job.get("state") == "sending":
                try:
                    stale = (now - datetime.fromisoformat(job.get("claimedAt", ""))).total_seconds() > 180
                except (ValueError, TypeError):
                    stale = True
                if stale:
                    job["state"] = "pending"
            if job.get("state") != "pending" or not channels.get(job.get("channel")):
                continue
            try:
                due = datetime.fromisoformat(job.get("nextAttemptAt", "")) <= now
            except (ValueError, TypeError):
                due = True
            if due:
                job["state"] = "sending"
                job["claimedAt"] = now.isoformat()
                job["attempts"] = int(job.get("attempts", 0)) + 1
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='notifications'", (json.dumps(state),))
                return jsonify(job={k: job.get(k) for k in ("id", "asset", "tag", "category", "factory", "ip", "status", "previous", "checkedAt", "channel", "destination", "attempts")})
        return ("", 204)


@app.post("/api/internal/notification-result")
def notification_result():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True) or {}
    job_id = str(body.get("id", ""))
    ok = bool(body.get("ok"))
    error = str(body.get("error", ""))[:300]
    now = datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
        state = row[0] if row else {"rules": [], "queue": []}
        job = next((item for item in state.get("queue", []) if item.get("id") == job_id), None)
        if not job:
            return jsonify(error="Notification job not found"), 404
        job["state"] = "sent" if ok else ("pending" if int(job.get("attempts", 0)) < 3 else "failed")
        job["error"] = "" if ok else error
        if not ok and job["state"] == "pending":
            job["nextAttemptAt"] = (now + __import__("datetime").timedelta(seconds=30 * int(job.get("attempts", 1)))).isoformat()
        job["completedAt"] = now.isoformat() if ok or job["state"] == "failed" else ""
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='notifications'", (json.dumps(state),))
    return jsonify(ok=True)


@app.get("/api/internal/ip-status-task")
def scanner_ip_status_task():
    if not _scanner_authorized():
        abort(403)
    now = datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='scanner_ip_status' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        prior_time = state.get("finished_at") or state.get("started_at") or ""
        if prior_time:
            try:
                elapsed = (now - datetime.fromisoformat(prior_time)).total_seconds()
                # Recheck known inventory endpoints frequently; the scanner only
                # probes saved device IPs here (CIDR discovery is a separate task).
                if (not state.get("finished_at") and elapsed < 120) or (state.get("finished_at") and elapsed < 5):
                    return ("", 204)
            except (ValueError, TypeError):
                pass
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        if not ranges:
            return ("", 204)
        networks = [ipaddress.ip_network(value, strict=True) for value in ranges]
        inventory = (conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone() or ([],))[0]
        users = (conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone() or ([],))[0]
        targets = set()
        for item, fields, is_asset in ([(a, ("ipAddress", "ip_address"), True) for a in inventory]
                                       + [(u, ("ip_address", "ipAddress"), False) for u in users]):
            raw_values = [item.get(key) for key in fields if item.get(key)]
            if is_asset and isinstance(item.get("networkInterfaces"), list):
                for interface in item["networkInterfaces"]:
                    if isinstance(interface, dict):
                        raw_values.extend(interface.get(key) for key in ("ipAddress", "ip_address", "ip") if interface.get(key))
            for raw_ip in raw_values:
                try:
                    ip = ipaddress.ip_address(str(raw_ip).strip())
                except ValueError:
                    continue
                if ip.version == 4 and ip.is_private and any(ip in network for network in networks):
                    targets.add(str(ip))
        if not targets:
            return ("", 204)
        task_id = str(uuid.uuid4())
        state = {"id":task_id,"targets":sorted(targets, key=lambda value:tuple(int(part) for part in value.split("."))),"started_at":now.isoformat(),"finished_at":""}
        conn.execute("INSERT INTO app_state(key,value) VALUES('scanner_ip_status',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
    return jsonify(id=task_id, ips=state["targets"])


@app.post("/api/internal/ip-status-results")
def scanner_ip_status_results():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True)
    task_id = str(body.get("id", ""))
    responsive = set()
    rows = body.get("online", [])
    if not task_id or not isinstance(rows, list) or len(rows) > 25000:
        return jsonify(error="Invalid IP status result"), 400
    for value in rows:
        try:
            ip = ipaddress.ip_address(str(value))
            if ip.version == 4 and ip.is_private:
                responsive.add(str(ip))
        except ValueError:
            continue
    checked_at = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='scanner_ip_status' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        if state.get("id") != task_id or state.get("finished_at"):
            return jsonify(error="IP status task is no longer active"), 409
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        networks = [ipaddress.ip_network(value, strict=True) for value in ranges]
        target_set = set()
        for value in state.get("targets", []):
            try:
                ip = ipaddress.ip_address(value)
                if ip.version == 4 and ip.is_private and any(ip in network for network in networks):
                    target_set.add(str(ip))
            except ValueError:
                continue
        responsive.intersection_update(target_set)
        inventory_row = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
        inventory = inventory_row[0] if inventory_row else []
        users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = users_row[0] if users_row else []
        notifications_row = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
        notifications = notifications_row[0] if notifications_row else {"rules": [], "queue": []}
        queue_size_before = len(notifications.get("queue", []))
        assets_changed = users_changed = False
        for asset in inventory:
            interfaces = asset.get("networkInterfaces")
            if not isinstance(interfaces, list):
                interfaces = []
            checked_ips = set()
            for interface in interfaces:
                if not isinstance(interface, dict):
                    continue
                raw_ip = str(interface.get("ipAddress", interface.get("ip_address", interface.get("ip", "")))).strip()
                if raw_ip not in target_set:
                    continue
                interface["ipStatus"] = interface["status"] = "Online" if raw_ip in responsive else "Offline"
                interface["ipCheckedAt"] = checked_at
                checked_ips.add(raw_ip)
                if raw_ip in responsive:
                    interface["lastSeen"] = checked_at
            primary_ip = str(asset.get("ipAddress", asset.get("ip_address", ""))).strip()
            if primary_ip in target_set:
                checked_ips.add(primary_ip)
            if not checked_ips:
                continue
            previous_status = str(asset.get("ipStatus", asset.get("status", "")))
            is_online = bool(checked_ips & responsive)
            asset["status"] = asset["ipStatus"] = "Online" if is_online else "Offline"
            asset["ipCheckedAt"] = checked_at
            if is_online:
                asset["lastSeen"] = checked_at
            _queue_asset_status_notifications(conn, notifications, asset, previous_status, asset["status"], checked_at, users)
            if previous_status in ("Online", "Offline") and previous_status != asset["status"]:
                _record_asset_transition_notification(conn, notifications, asset, asset["status"], checked_at)
            assets_changed = True
        for user in users:
            raw_ip = str(user.get("ip_address", user.get("ipAddress", ""))).strip()
            if raw_ip not in target_set:
                continue
            user["ipStatus"] = "Online" if raw_ip in responsive else "Offline"
            user["ipCheckedAt"] = checked_at
            if raw_ip in responsive:
                user["lastSeen"] = checked_at
            users_changed = True
        if assets_changed:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='assets'", (json.dumps(inventory),))
            _pg_emit_notify(conn, "asset", {"online": len(responsive), "checked": len(target_set)})
        if users_changed:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
        state["finished_at"] = checked_at
        state["online_count"] = len(responsive)
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='scanner_ip_status'", (json.dumps(state),))
        if len(notifications.get("queue", [])) != queue_size_before:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='notifications'", (json.dumps(notifications),))
    return jsonify(ok=True, online=len(responsive), checked=len(target_set))


@app.post("/api/internal/scanner-heartbeat")
def scanner_heartbeat():
    if not _scanner_authorized():
        abort(403)
    state = {"last_seen": datetime.now(timezone.utc).isoformat()}
    site_name = ""
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('scanner_heartbeat',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
        srow = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
        if srow and isinstance(srow[0], dict):
            site_name = str(srow[0].get("siteName") or "").strip()
    if not site_name:
        site_name = str(os.getenv("SITE_NAME") or "").strip()
    return jsonify(ok=True, siteName=site_name)


@app.get("/api/internal/scanner-task")
def scanner_task():
    if not _scanner_authorized():
        abort(403)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        if ranges and state.get("status") in (None, "", "idle", "completed", "failed"):
            last_run = state.get("finished_at") or state.get("started_at") or ""
            try:
                due = not last_run or (datetime.now(timezone.utc) - datetime.fromisoformat(last_run)).total_seconds() >= 900
            except (ValueError, TypeError):
                due = True
            if due:
                hosts_count = sum(len(list(ipaddress.ip_network(value, strict=True).hosts())) for value in ranges)
                state = {"id":str(uuid.uuid4()),"status":"queued","progress":0,"total":hosts_count,"results":[],"error":"","started_at":datetime.now(timezone.utc).isoformat(),"finished_at":""}
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
        if state.get("status") != "queued":
            return ("", 204)
        state["status"] = "running"
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
    return jsonify(id=state.get("id"), ranges=ranges, total=state.get("total", 0))


@app.post("/api/internal/scanner-progress")
def scanner_progress():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True)
    scan_id = str(body.get("id", ""))
    status = body.get("status")
    if not scan_id or status not in ("running", "completed", "failed"):
        return jsonify(error="Invalid scanner progress update"), 400
    try:
        progress = max(0, min(25000, int(body.get("progress", 0))))
    except (ValueError, TypeError):
        return jsonify(error="Invalid scan progress"), 400
    results = body.get("results", [])
    if not isinstance(results, list) or len(results) > 25000:
        return jsonify(error="Invalid scan results"), 400
    clean = []
    for item in results:
        try:
            ip = ipaddress.ip_address(item.get("ip", ""))
            mac = str(item.get("mac", ""))[:32]
            if ip.version != 4 or not ip.is_private:
                continue
            raw_latency = item.get("latency_ms")
            latency = None if raw_latency is None else max(0, min(60000, int(raw_latency)))
            clean.append({"ip":str(ip), "mac":mac, "hostname":str(item.get("hostname", ""))[:255], "status":"Online", "latency_ms":latency, "last_seen":str(item.get("last_seen", ""))[:64]})
        except (ValueError, TypeError, AttributeError):
            continue
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        if state.get("id") != scan_id or state.get("status") not in ("queued", "running"):
            return jsonify(error="Scan task is no longer active"), 409
        state.update(status=status, progress=progress, results=clean)
        if body.get("error"):
            state["error"] = "Scanner agent failed. Check Ubuntu network access and ping permissions."
        if status in ("completed", "failed"):
            state["finished_at"] = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
        if status == "completed":
            ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
            networks = [ipaddress.ip_network(value, strict=True) for value in ranges]
            inventory_row = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
            inventory = inventory_row[0] if inventory_row else []
            users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
            users = users_row[0] if users_row else []
            online_ips = {item["ip"] for item in clean}
            checked_at = datetime.now(timezone.utc).isoformat()
            assets_changed = False
            users_changed = False
            for asset in inventory:
                try:
                    ip = ipaddress.ip_address(str(asset.get("ipAddress", asset.get("ip_address", ""))).strip())
                except ValueError:
                    continue
                if ip.version != 4 or not any(ip in network for network in networks):
                    continue
                asset["status"] = "Online" if str(ip) in online_ips else "Offline"
                asset["ipStatus"] = asset["status"]
                asset["ipCheckedAt"] = checked_at
                if str(ip) in online_ips:
                    asset["lastSeen"] = checked_at
                assets_changed = True
            for user in users:
                try:
                    ip = ipaddress.ip_address(str(user.get("ip_address", user.get("ipAddress", ""))).strip())
                except ValueError:
                    continue
                if ip.version != 4 or not any(ip in network for network in networks):
                    continue
                user["ipStatus"] = "Online" if str(ip) in online_ips else "Offline"
                user["ipCheckedAt"] = checked_at
                if str(ip) in online_ips:
                    user["lastSeen"] = checked_at
                users_changed = True
            if assets_changed:
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='assets'", (json.dumps(inventory),))
            if users_changed:
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password or len(username) > 120 or len(password) > 1024:
        return jsonify(error="Enter your username and password"), 400
    remote_ip = request.remote_addr or "127.0.0.1"
    with db() as conn:
        row = conn.execute("SELECT failures, blocked_until FROM login_attempts WHERE client_ip=%s", (remote_ip,)).fetchone()
        if row and row[1] and row[1] > datetime.now(timezone.utc):
            return jsonify(error="Too many attempts. Wait 15 minutes and try again."), 429
        local_state = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    local_users = local_state[0] if local_state else []
    local_user = next((u for u in local_users if str(u.get("username", "")).casefold() == username.casefold()), None)
    password_hash = local_user.get("password_hash") if local_user and local_user.get("enabled", True) else LOGIN_DUMMY_HASH
    if local_user and local_user.get("enabled", True) and local_user.get("password_hash"):
        try:
            valid_local = check_password_hash(local_user["password_hash"], password)
        except (ValueError, TypeError):
            valid_local = False
        if valid_local:
            profile = {"username": str(local_user["username"]).lower(), "name": local_user.get("name") or local_user["username"], "email": local_user.get("email", ""), "dept": local_user.get("dept", ""), "site": local_user.get("site", ""), "role": local_user.get("role", "User"), "profile_picture": local_user.get("profile_picture", ""), "groups": []}
            profile["module_permissions"] = local_user.get("module_permissions") if isinstance(local_user.get("module_permissions"), dict) else module_permissions_for(profile)
            if isinstance(local_user.get("allowed_complaint_desks"), list):
                profile["allowed_complaint_desks"] = local_user["allowed_complaint_desks"]
            g_sc = str(local_user.get("gate_scope") or "dept").strip().lower()
            profile["gate_scope"] = g_sc if g_sc in ("dept", "management", "security") else "dept"
            g_dp = local_user.get("gate_departments")
            profile["gate_departments"] = [str(x).strip() for x in g_dp if str(x).strip()] if isinstance(g_dp, list) else []
            sid = secrets.token_urlsafe(32)
            auth_ver = int(local_user.get("auth_version", 0) or 0)
            with db() as conn:
                conn.execute("DELETE FROM login_attempts WHERE client_ip=%s", (remote_ip,))
                conn.execute(
                    "DELETE FROM user_sessions WHERE last_seen_at < now() - make_interval(mins => %s) "
                    "OR created_at < now() - make_interval(hours => %s)",
                    (SESSION_IDLE_MINUTES, SESSION_MAX_HOURS),
                )
                conn.execute(
                    "INSERT INTO user_sessions(sid, username, auth_version, client_ip) VALUES(%s, %s, %s, %s)",
                    (sid, profile["username"], auth_ver, remote_ip),
                )
            session.clear()
            session.permanent = False
            session["sid"] = sid
            session["auth_version"] = auth_ver
            session["is_admin"] = profile["role"] == "Administrator"
            session["profile"] = {key: value for key, value in profile.items() if key != "groups"}
            return jsonify(profile=session["profile"], isAdmin=session["is_admin"])
    else:
        try:
            check_password_hash(password_hash, password)
        except (ValueError, TypeError):
            pass
    with db() as conn:
        conn.execute("INSERT INTO login_attempts(client_ip,failures,blocked_until) VALUES(%s,1,NULL) ON CONFLICT(client_ip) DO UPDATE SET failures=login_attempts.failures+1, blocked_until=CASE WHEN login_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END", (remote_ip,))
    return jsonify(error="Sign-in failed. Check your username and password."), 401


@app.post("/api/recovery/reset")
def recover_account_password():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()[:120]
    raw_answers = body.get("answers", [])
    new_password = str(body.get("new_password", ""))
    confirm_password = str(body.get("confirm_password", ""))
    if not username or not new_password or len(new_password) > 1024 or new_password != confirm_password:
        return jsonify(message=RECOVERY_GENERIC_MESSAGE), 200
    normalized = [normalize_recovery_answer(a) for a in raw_answers] if isinstance(raw_answers, list) else []
    if len(normalized) != len(RECOVERY_QUESTIONS) or any(len(a) < 3 or len(a) > 200 for a in normalized):
        normalized = ["invalid-answer"] * len(RECOVERY_QUESTIONS)
    remote_ip = request.remote_addr or "127.0.0.1"
    username_key = hmac.new(APP_SECRET.encode(), username.casefold().encode(), hashlib.sha256).hexdigest()
    with db() as conn:
        attempt = conn.execute(
            "SELECT failures,blocked_until FROM recovery_attempts WHERE client_ip=%s AND username_hash=%s",
            (remote_ip, username_key),
        ).fetchone()
        if attempt and attempt[1] and attempt[1] > datetime.now(timezone.utc):
            return jsonify(message="Too many recovery attempts. Wait 15 minutes and try again."), 429
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()
                        and u.get("enabled", True) and u.get("password_hash")), None)
        hashes = account.get("recovery_answer_hashes", []) if account else []
        usable_hashes = hashes if isinstance(hashes, list) and len(hashes) == len(RECOVERY_QUESTIONS) else [RECOVERY_DUMMY_HASH] * len(RECOVERY_QUESTIONS)
        checks = [matches_recovery_answer(stored, answer) for stored, answer in zip(usable_hashes, normalized)]
        valid = bool(account and len(hashes) == len(RECOVERY_QUESTIONS) and all(checks))
        if valid:
            account["password_hash"] = generate_password_hash(new_password)
            account["auth_version"] = int(account.get("auth_version", 0) or 0) + 1
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
            conn.execute("DELETE FROM user_sessions WHERE lower(username)=lower(%s)", (username,))
            conn.execute("DELETE FROM recovery_attempts WHERE client_ip=%s AND username_hash=%s", (remote_ip, username_key))
            conn.execute("DELETE FROM login_attempts WHERE client_ip=%s", (remote_ip,))
        else:
            conn.execute(
                "INSERT INTO recovery_attempts(client_ip,username_hash,failures,blocked_until) VALUES(%s,%s,1,NULL) "
                "ON CONFLICT(client_ip,username_hash) DO UPDATE SET failures=recovery_attempts.failures+1, "
                "blocked_until=CASE WHEN recovery_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END",
                (remote_ip, username_key),
            )
    return jsonify(message=RECOVERY_GENERIC_MESSAGE), 200


@app.post("/api/account/recovery-answers")
@signed_in
def update_recovery_answers():
    body = request.get_json(silent=True) or {}
    current_password = str(body.get("current_password", ""))
    hashes = recovery_answer_hashes(body.get("answers"))
    if not hashes:
        return jsonify(error="Answer all three recovery questions with 3–200 characters each."), 400
    username = session["profile"].get("username", "")
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account or not account.get("password_hash") or not check_password_hash(account["password_hash"], current_password):
            return jsonify(error="Current password is incorrect."), 400
        account["recovery_answer_hashes"] = hashes
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    return jsonify(ok=True, message="Recovery answers saved securely.")


@app.post("/api/logout")
def logout():
    sid = str(session.get("sid") or "").strip()
    if sid:
        try:
            with db() as conn:
                conn.execute("DELETE FROM user_sessions WHERE sid=%s", (sid,))
        except Exception:
            pass
    session.clear()
    resp = jsonify(ok=True)
    resp.delete_cookie(
        app.config.get("SESSION_COOKIE_NAME", "session"),
        path="/",
        httponly=True,
        samesite=app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        secure=app.config.get("SESSION_COOKIE_SECURE", True),
    )
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.post("/api/account/logout-all")
@signed_in
def logout_all_devices():
    username = str(session["profile"].get("username", ""))
    sid = str(session.get("sid") or "").strip()
    with db() as conn:
        conn.execute("DELETE FROM user_sessions WHERE lower(username)=lower(%s)", (username,))
    session.clear()
    resp = jsonify(ok=True, message="Signed out from all devices.")
    resp.delete_cookie(
        app.config.get("SESSION_COOKIE_NAME", "session"),
        path="/",
        httponly=True,
        samesite=app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        secure=app.config.get("SESSION_COOKIE_SECURE", True),
    )
    return resp


@app.get("/api/profile")
@signed_in
def profile():
    return jsonify(profile=session["profile"], isAdmin=session["is_admin"])


@app.get("/api/profile/preferences")
@signed_in
def get_profile_preferences():
    username = str(session["profile"].get("username", ""))
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='profile_preferences'").fetchone()
    preferences = row[0] if row and isinstance(row[0], dict) else {}
    return jsonify(preferences=preferences.get(username, {}))


@app.put("/api/profile/preferences")
@signed_in
def save_profile_preferences():
    payload = request.get_json(silent=True) or {}
    valid_views = {"dashboard", "assets", "datacenter", "tickets", "maintenance", "ageing",
                   "users", "departments", "factories", "valuation", "billing", "software",
                   "monitoring", "networkmap", "snmp", "notifications", "surveillance", "parts", "reports"}
    order = payload.get("order")
    hidden = payload.get("hidden", [])
    if (not isinstance(order, list) or not isinstance(hidden, list)
            or len(order) > len(valid_views) or len(hidden) > len(valid_views)
            or any(not isinstance(item, str) or item not in valid_views for item in order + hidden)):
        return jsonify(error="Invalid module preferences."), 400
    normalized_order = list(dict.fromkeys(order))
    normalized_order.extend(sorted(valid_views - set(normalized_order)))
    normalized = {"order": normalized_order, "hidden": list(dict.fromkeys(hidden))}
    username = str(session["profile"].get("username", ""))
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('profile_preferences','{}') ON CONFLICT(key) DO NOTHING")
        row = conn.execute("SELECT value FROM app_state WHERE key='profile_preferences' FOR UPDATE").fetchone()
        preferences = row[0] if row and isinstance(row[0], dict) else {}
        preferences[username] = normalized
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='profile_preferences'", (json.dumps(preferences),))
    return jsonify(ok=True, preferences=normalized)


@app.get("/portal")
def public_helpdesk_page():
    resp = send_from_directory(ROOT, "portal.html")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


DEFAULT_TICKET_CATEGORY_TREE = [
    {
        "id": "cat-network-hardware",
        "name": "Network / Hardware",
        "icon": "🖥️",
        "subcategories": [
            "Computer / Desktop", "Laptop", "Monitor / Screen", "Network Switch / Router",
            "Wi-Fi / Access Point", "LAN / Patch Cable", "Printer / Scanner",
            "CCTV / Surveillance", "Server / Storage", "UPS / Power", "Other Hardware",
        ],
    },
    {
        "id": "cat-erp-software",
        "name": "ERP / Software / Manufacturing",
        "icon": "📊",
        "subcategories": [
            "ERP Software", "Manufacturing System", "Digital Catalog",
            "Reports / Billing", "Operating System / Windows", "Email / Login / Outlook",
            "Software License", "Other Software",
        ],
    },
]
DEFAULT_MATERIAL_CATEGORIES = [
    "RAM", "SSD / Hard Drive", "Monitor / Screen", "Keyboard & Mouse",
    "SMPS / Power Supply", "Laptop / Desktop", "Network Switch / Cables",
    "Printer / Toner", "Accessories / Peripherals", "Other Material",
]


DEFAULT_COMPLAINT_DESKS = [
    {
        "id": "it",
        "name": "IT Department",
        "icon": "💻",
        "tokenPrefix": "IT",
        "allowMaterialRequest": True,
        "categories": DEFAULT_TICKET_CATEGORY_TREE,
        "materialCategories": DEFAULT_MATERIAL_CATEGORIES,
    },
    {
        "id": "plumber",
        "name": "Plumber",
        "icon": "🔧",
        "tokenPrefix": "PLM",
        "allowMaterialRequest": True,
        "categories": [
            {
                "id": "cat-plm-water",
                "name": "Water Supply / Pipeline",
                "icon": "🚰",
                "subcategories": ["Pipe Leakage", "Tap / Valve Repair", "Water Tank / Motor", "Low Water Pressure", "Other Plumbing"],
            },
            {
                "id": "cat-plm-drain",
                "name": "Drainage / Washroom",
                "icon": "🚿",
                "subcategories": ["Blocked Drain", "Flush / Cistern Issue", "Basin / Sink Leakage", "RO / Drinking Water"],
            },
        ],
        "materialCategories": ["Pipes & Fittings", "Taps & Valves", "Sealants & Adhesive", "Sanitary Hardware", "Other Plumbing Material"],
    },
    {
        "id": "electrician",
        "name": "Electrician",
        "icon": "⚡",
        "tokenPrefix": "ELC",
        "allowMaterialRequest": True,
        "categories": [
            {
                "id": "cat-elc-power",
                "name": "Power / Lighting",
                "icon": "💡",
                "subcategories": ["Tube Light / Bulb", "Power Socket / Switch", "MCB / DB Trip", "Fan / Exhaust", "Power Outage"],
            },
            {
                "id": "cat-elc-equip",
                "name": "Electrical Panel / AC / UPS",
                "icon": "🔌",
                "subcategories": ["Panel Wiring", "AC Electrical Point", "Inverter / Generator", "Earthing / Voltage"],
            },
        ],
        "materialCategories": ["Switches & Sockets", "MCB / Breakers", "LED Lights & Drivers", "Wires & Cables", "Other Electrical Material"],
    },
    {
        "id": "admin",
        "name": "Admin Dept",
        "icon": "🏢",
        "tokenPrefix": "ADM",
        "allowMaterialRequest": True,
        "categories": [
            {
                "id": "cat-adm-fac",
                "name": "Facility / Housekeeping",
                "icon": "🧹",
                "subcategories": ["Cleaning / Housekeeping", "Furniture / Chair / Desk", "Door / Lock / Glass", "AC Cooling / Vent", "Pest Control"],
            },
            {
                "id": "cat-adm-ops",
                "name": "Admin / Security / Canteen",
                "icon": "🪪",
                "subcategories": ["ID Card / Access Pass", "Canteen / Pantry", "Parking / Transport", "Stationery / Courier", "Other Admin Request"],
            },
        ],
        "materialCategories": ["Office Stationery", "Furniture / Fittings", "Housekeeping Supplies", "Security Badges", "Other Admin Material"],
    },
]


def _normalize_category_tree_items(raw_tree, default_tree, legacy_cats=None):
    clean_tree = []
    seen_names = set()
    if isinstance(raw_tree, list):
        for idx, item in enumerate(raw_tree[:40]):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()[:80]
            if not name or name.casefold() in seen_names:
                continue
            seen_names.add(name.casefold())
            icon = str(item.get("icon") or "🎫").strip()[:12] or "🎫"
            cid = str(item.get("id") or f"cat-{idx + 1}").strip()[:60]
            raw_subs = item.get("subcategories") if isinstance(item.get("subcategories"), list) else []
            subs = []
            seen_sub = set()
            for s in raw_subs[:60]:
                sname = str(s or "").strip()[:80]
                if sname and sname.casefold() not in seen_sub:
                    seen_sub.add(sname.casefold())
                    subs.append(sname)
            clean_tree.append({"id": cid, "name": name, "icon": icon, "subcategories": subs or ["Other"]})
    if not clean_tree:
        clean_tree = json.loads(json.dumps(default_tree))
        seen_names = {c["name"].casefold() for c in clean_tree}
        if isinstance(legacy_cats, list):
            for idx, cname in enumerate(legacy_cats[:40]):
                s = str(cname or "").strip()[:80]
                if s and s.casefold() not in seen_names:
                    seen_names.add(s.casefold())
                    clean_tree.append({"id": f"cat-custom-{idx + 1}", "name": s, "icon": "🎫", "subcategories": ["General Issue", "Other"]})
    return clean_tree


def _normalize_material_cats(raw_mat, default_mat):
    mat_cats = []
    if isinstance(raw_mat, list):
        seen_mat = set()
        for m in raw_mat[:60]:
            ms = str(m or "").strip()[:80]
            if ms and ms.casefold() not in seen_mat:
                seen_mat.add(ms.casefold())
                mat_cats.append(ms)
    return mat_cats or list(default_mat)


def normalize_ticketing_settings(settings_val):
    settings = settings_val if isinstance(settings_val, dict) else {}
    clean_tree = _normalize_category_tree_items(
        settings.get("ticketCategoryTree"),
        DEFAULT_TICKET_CATEGORY_TREE,
        settings.get("ticketCategories"),
    )
    mat_cats = _normalize_material_cats(settings.get("materialRequestCategories"), DEFAULT_MATERIAL_CATEGORIES)
    priority = str(settings.get("defaultTicketPriority") or "Normal").strip()
    if priority not in ("Normal", "Low", "High", "Urgent"):
        priority = "Normal"
    show_all_desks = bool(settings.get("showAllDesksOnPortal", False))

    raw_desks = settings.get("complaintDesks")
    clean_desks = []
    seen_desk_ids = set()
    used_prefixes = set()
    if isinstance(raw_desks, list) and len(raw_desks) > 0:
        for idx, dk in enumerate(raw_desks[:30]):
            if not isinstance(dk, dict):
                continue
            dname = str(dk.get("name") or "").strip()[:80]
            if not dname:
                continue
            did = _slug_desk_id(dk.get("id") or dname, fallback=f"desk-{idx + 1}")
            if did in seen_desk_ids:
                did = f"{did}-{idx + 1}"[:40]
            seen_desk_ids.add(did)
            raw_pref = re.sub(r"[^A-Z0-9]", "", str(dk.get("tokenPrefix") or "").strip().upper())[:5]
            if not raw_pref:
                raw_pref = re.sub(r"[^A-Z0-9]", "", dname.upper())[:3] or "TK"
            pref = raw_pref
            if pref in used_prefixes:
                pref = (raw_pref[:3] + str(idx + 1))[:5]
            used_prefixes.add(pref)
            icon = str(dk.get("icon") or "🎫").strip()[:12] or "🎫"
            cats = _normalize_category_tree_items(
                dk.get("categories") or dk.get("ticketCategoryTree"),
                [{"id": f"cat-{did}-1", "name": f"{dname} Issue", "icon": icon, "subcategories": ["General Issue", "Urgent Repair", "Other"]}],
            )
            dmats = _normalize_material_cats(
                dk.get("materialCategories"),
                [f"{dname} Material", "Other Material"],
            )
            clean_desks.append({
                "id": did,
                "name": dname,
                "icon": icon,
                "tokenPrefix": pref,
                "allowMaterialRequest": bool(dk.get("allowMaterialRequest", True)),
                "categories": cats,
                "materialCategories": dmats,
            })
    if not clean_desks:
        clean_desks = json.loads(json.dumps(DEFAULT_COMPLAINT_DESKS))

    # Sync IT (or first) desk categories when top-level ticketCategoryTree is explicitly edited without complaintDesks,
    # or vice versa keep top-level fields synced with 'it' desk for legacy consumers.
    it_desk = next((d for d in clean_desks if d["id"] == "it"), None)
    if it_desk:
        if "complaintDesks" in settings and isinstance(settings.get("complaintDesks"), list):
            clean_tree = json.loads(json.dumps(it_desk["categories"]))
            mat_cats = list(it_desk["materialCategories"])
        else:
            it_desk["categories"] = json.loads(json.dumps(clean_tree))
            it_desk["materialCategories"] = list(mat_cats)

    return {
        "ticketCategoryTree": clean_tree,
        "ticketCategories": [c["name"] for c in clean_tree],
        "materialRequestCategories": mat_cats,
        "defaultTicketPriority": priority,
        "complaintDesks": clean_desks,
        "showAllDesksOnPortal": show_all_desks,
    }


def issued_parts_map_from_conn(conn):
    row = conn.execute("SELECT value FROM app_state WHERE key='parts_assignments'").fetchone()
    rows = row[0] if row and isinstance(row[0], list) else []
    by_ticket = {}
    for a in rows:
        if not isinstance(a, dict):
            continue
        tid = str(a.get("ticketId") or a.get("materialRequestId") or "").strip()
        if not tid:
            continue
        by_ticket.setdefault(tid, []).append({
            "id": str(a.get("id") or ""),
            "partId": str(a.get("partId") or ""),
            "partName": str(a.get("partName") or ""),
            "sku": str(a.get("sku") or ""),
            "condition": str(a.get("condition") or "New"),
            "quantity": int(a.get("quantity") or 0),
            "returned": int(a.get("returned") or 0),
            "site": str(a.get("site") or ""),
            "dept": str(a.get("dept") or ""),
            "user": str(a.get("user") or ""),
            "date": str(a.get("date") or ""),
            "issuedBy": str(a.get("issuedBy") or ""),
            "notes": str(a.get("notes") or a.get("work") or ""),
        })
    return by_ticket


@app.get("/api/public/portal-options")
def public_portal_options():
    with db() as conn:
        rows = {key: (conn.execute("SELECT value FROM app_state WHERE key=%s", (key,)).fetchone() or ([],))[0]
                for key in ("manual_users", "departments", "settings")}
    users = rows["manual_users"] if isinstance(rows["manual_users"], list) else []
    departments = rows["departments"] if isinstance(rows["departments"], list) else []
    settings = rows["settings"] if isinstance(rows["settings"], dict) else {}
    ticketing_cfg = normalize_ticketing_settings(settings)
    factories = [{"code": str(f.get("code", "")).strip(), "name": str(f.get("name", "")).strip(), "description": str(f.get("description", "")).strip()}
                 for f in settings.get("factories", []) if isinstance(f, dict) and f.get("code")]
    for code in ("ARG", "ARB", "ARC", "ARF"):
        if not any(f["code"].casefold() == code.casefold() for f in factories):
            factories.append({"code": code, "name": code, "description": ""})
    depts = []
    for item in departments:
        if isinstance(item, list) and len(item) > 6:
            name, factory, kind = item[0], item[6] or item[1], item[8] if len(item) > 8 else "department"
        elif isinstance(item, dict):
            name, factory, kind = item.get("name", ""), item.get("factory", ""), item.get("kind", "department")
        else:
            continue
        if name and factory and kind != "subdepartment":
            depts.append({"name": str(name), "factory": str(factory)})
    employees = []
    for u in users:
        if not isinstance(u, dict) or not u.get("enabled", True) or str(u.get("active", "Active")).lower() == "inactive":
            continue
        name = str(u.get("name") or "").strip()
        dept = str(u.get("dept") or u.get("department") or "").strip()
        site = str(u.get("site") or "").strip()
        key = str(u.get("username") or u.get("id") or "").strip()
        if name and dept and site and key:
            public_key = hashlib.sha256((APP_SECRET + "|" + key.casefold() + "|" + dept.casefold() + "|" + site.casefold()).encode()).hexdigest()
            employees.append({"key": public_key, "name": name, "department": dept, "factory": site})
    company_name = str(settings.get("companyName") or settings.get("loginBranding", {}).get("companyName") or "").strip()
    if not company_name or company_name.casefold() in ("shree", "northstar", "northstar it", "it asset management"):
        company_name = "Swarnshilp"
    site_name = str(settings.get("siteName") or "").strip()
    return jsonify(factories=factories, departments=depts, employees=employees, companyName=company_name, siteName=site_name, **ticketing_cfg)


def repair_map_from_conn(conn):
    maint_row = conn.execute("SELECT value FROM app_state WHERE key='maintenance'").fetchone()
    maint_list = maint_row[0] if maint_row and isinstance(maint_row[0], list) else []
    repair_by_ticket = {}
    for m in maint_list:
        if isinstance(m, dict) and m.get("repairCase"):
            tid = str(m.get("ticketId") or m.get("ticket") or "").strip()
            if tid and tid not in repair_by_ticket:
                repair_by_ticket[tid] = {
                    "caseNo": str(m.get("caseNo") or m.get("id") or ""),
                    "stage": str(m.get("stage") or "Device in"),
                    "stageIndex": int(m.get("stageIndex") or 1),
                    "completedAt": str(m.get("completedAt") or ""),
                    "followUp": str(m.get("followUp") or ""),
                }
    return repair_by_ticket


@app.get("/api/public/tickets")
def public_ticket_list():
    kind = request.args.get("kind", "IT help desk")
    if kind not in ("IT help desk", "Material request", "all"):
        return jsonify(error="Choose IT help desk or Material request."), 400
    req_desk = str(request.args.get("desk") or "").strip().lower()
    with db() as conn:
        srow = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
        ticketing_cfg = normalize_ticketing_settings(srow[0] if srow else {})
        show_all_desks = bool(ticketing_cfg.get("showAllDesksOnPortal", False))
        desks = ticketing_cfg.get("complaintDesks") or []
        valid_ids = {d["id"] for d in desks}
        default_desk = desks[0]["id"] if desks else "it"
        if show_all_desks and (not req_desk or req_desk == "all"):
            desk_filter = None
        elif req_desk and req_desk in valid_ids:
            desk_filter = req_desk
        elif req_desk == "all" and not show_all_desks:
            desk_filter = default_desk
        else:
            desk_filter = default_desk if not show_all_desks else None

        clauses = []
        params = []
        if kind != "all":
            clauses.append("t.kind=%s")
            params.append(kind)
        if desk_filter is not None:
            clauses.append("COALESCE(NULLIF(t.complaint_desk,''),'it')=%s")
            params.append(desk_filter)
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(f"""
            SELECT t.id,t.kind,t.display_name,t.department,t.factory,t.primary_category,t.sub_category,
                   t.description,t.attachments,t.assigned_to,t.status,t.eta,t.note,t.created_at,t.updated_at,
                   COALESCE((SELECT min(e.created_at) FROM ticket_events e WHERE e.ticket_id=t.id
                             AND e.event_type='updated' AND e.detail ~ '(^|; )status: (Resolved|Closed)(;|$)'), t.updated_at),
                   t.material, COALESCE(NULLIF(t.complaint_desk,''),'it')
            FROM tickets t {where_sql} ORDER BY t.created_at DESC LIMIT 5000
        """, params).fetchall()
        repair_map = repair_map_from_conn(conn)
        issued_map = issued_parts_map_from_conn(conn)
    now = datetime.now(timezone.utc)
    result = []
    for r in rows:
        end = r[15] if r[10] in ("Resolved", "Closed") else now
        duration = max(0, int((end - r[13]).total_seconds() // 60))
        photos = []
        for item in (r[8] or []):
            name = Path(str(item.get("path", ""))).name
            if name and name == str(item.get("path", "")).split("/")[-1]:
                photos.append({"name": str(item.get("name") or name)[:160], "url": "/api/public/ticket-attachment?id=" + quote(r[0], safe="") + "&file=" + quote(name, safe="")})
        result.append({"id":r[0],"kind":r[1],"name":r[2],"department":r[3],"factory":r[4],"primary":r[5],"sub":r[6],
                       "description":r[7],"material":r[16] or "","photos":photos,"assigned":r[9],"status":r[10],
                       "eta":r[11].isoformat(timespec="minutes") if r[11] else "","note":r[12],
                       "created":r[13].isoformat(timespec="minutes"),"durationMinutes":duration,
                       "repair":repair_map.get(r[0]),"issuedParts":issued_map.get(r[0], []),
                       "complaintDesk":r[17] or "it"})
    return jsonify(tickets=result, showAllDesksOnPortal=show_all_desks, activeDesk=desk_filter or "all")


@app.get("/api/public/ticket-attachment")
def public_ticket_attachment():
    ticket_id = request.args.get("id", "")
    filename = request.args.get("file", "")
    if not ticket_id or Path(filename).name != filename:
        abort(404)
    with db() as conn:
        row = conn.execute("SELECT attachments FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
    if not row:
        abort(404)
    match = next((item for item in (row[0] or []) if Path(str(item.get("path", ""))).name == filename), None)
    if not match:
        abort(404)
    parts = Path(str(match.get("path", ""))).parts
    if len(parts) != 3 or parts[0] != "tickets" or Path(parts[2]).name != parts[2]:
        abort(404)
    return send_from_directory(UPLOAD_DIR / parts[0] / parts[1], parts[2], as_attachment=False)


def _next_ticket_id(conn, prefix="IT"):
    clean_pref = re.sub(r"[^A-Z0-9]", "", str(prefix or "IT").strip().upper())[:5] or "IT"
    token_date = datetime.now().strftime("%d-%m-%Y")
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{clean_pref}:{token_date}",))
    rows = conn.execute(
        "SELECT id FROM tickets WHERE id LIKE %s",
        (f"{clean_pref}%/{token_date}",),
    ).fetchall()
    max_seq = 0
    pat = re.compile(rf"^{re.escape(clean_pref)}(\d+)/")
    for (tid,) in rows:
        m = pat.match(str(tid or ""))
        if m:
            max_seq = max(max_seq, int(m.group(1)))
    return f"{clean_pref}{max_seq + 1:02d}/{token_date}", token_date


@app.post("/api/public/tickets")
def create_public_ticket():
    is_multipart = bool(request.content_type and "multipart/form-data" in request.content_type)
    body = request.form if is_multipart else (request.get_json(silent=True) or {})
    factory = str(body.get("factory", "")).strip()[:80]
    department = str(body.get("department", "")).strip()[:120]
    employee_key = str(body.get("employee", "")).strip()[:120]
    primary = str(body.get("primary", "IT help desk")).strip()[:80]
    sub = str(body.get("sub", "")).strip()[:80]
    description = str(body.get("description", "")).strip()[:5000]
    material = str(body.get("material", "")).strip()[:500]
    kind = "Material request" if body.get("kind") == "Material request" else "IT help desk"
    req_desk = _slug_desk_id(body.get("complaintDesk") or "it", fallback="it")
    if not all((factory, department, employee_key, description, sub)):
        return jsonify(error="Select your factory, department, name and issue category, then describe the issue."), 400
    files = [f for f in request.files.getlist("files") if f and f.filename] if is_multipart else []
    if len(files) > 5:
        return jsonify(error="Attach up to five screenshots."), 400
    for f in files:
        if f.mimetype not in ("image/png", "image/jpeg", "image/gif", "image/webp"):
            return jsonify(error="Only PNG, JPEG, GIF, or WebP image screenshots are accepted."), 400
    with db() as conn:
        recent = conn.execute("SELECT count(*) FROM tickets WHERE client_ip=%s AND username LIKE 'public-%%' AND created_at>now()-interval '10 minutes'", (request.remote_addr or "127.0.0.1",)).fetchone()[0]
        if recent >= 5:
            return jsonify(error="Too many requests from this network. Please try again in a few minutes."), 429
        state = {key: (conn.execute("SELECT value FROM app_state WHERE key=%s", (key,)).fetchone() or ([],))[0]
                 for key in ("manual_users", "departments", "settings")}
        ticketing_cfg = normalize_ticketing_settings(state["settings"])
        desks = ticketing_cfg.get("complaintDesks") or []
        desk_obj = next((d for d in desks if d["id"] == req_desk), None)
        if not desk_obj:
            return jsonify(error="The selected complaint department is no longer available. Refresh the portal."), 400
        if kind == "Material request" and not desk_obj.get("allowMaterialRequest", True):
            return jsonify(error=f"Material requests are not enabled for {desk_obj['name']}."), 400
        users = state["manual_users"] if isinstance(state["manual_users"], list) else []
        user = next((u for u in users if isinstance(u, dict)
                     and hashlib.sha256((APP_SECRET + "|" + str(u.get("username") or u.get("id") or "").casefold() + "|" + str(u.get("dept") or u.get("department") or "").casefold() + "|" + str(u.get("site") or "").casefold()).encode()).hexdigest() == employee_key
                     and str(u.get("dept") or u.get("department") or "").casefold() == department.casefold()
                     and str(u.get("site") or "").casefold() == factory.casefold()
                     and u.get("enabled", True) and str(u.get("active", "Active")).lower() != "inactive"), None)
        if not user:
            return jsonify(error="That employee is not active in the selected factory and department. Refresh the portal and choose again."), 400
        depts = state["departments"] if isinstance(state["departments"], list) else []
        dept_exists = any((str(d[0]).casefold() == department.casefold() and str((d[6] or d[1]) if len(d)>6 else "").casefold() == factory.casefold())
                          if isinstance(d, list) and len(d)>1 else
                          isinstance(d, dict) and str(d.get("name", "")).casefold() == department.casefold() and str(d.get("factory", "")).casefold() == factory.casefold()
                          for d in depts)
        custom_factories = (state["settings"] or {}).get("factories", []) if isinstance(state["settings"], dict) else []
        factory_exists = factory.upper() in {"ARG", "ARB", "ARC", "ARF"} or any(isinstance(f, dict) and str(f.get("code", "")).casefold() == factory.casefold() for f in custom_factories)
        if not dept_exists or not factory_exists:
            return jsonify(error="The selected factory or department is no longer available. Refresh the portal."), 400
        remote = request.remote_addr or "127.0.0.1"
        ticket_id, token_date = _next_ticket_id(conn, prefix=desk_obj.get("tokenPrefix", "IT"))
        tracking_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
        username = "public-" + token_hash[:24]
        saved = []
        if files:
            ticket_dir = UPLOAD_DIR / "tickets" / token_date
            ticket_dir.mkdir(parents=True, exist_ok=True)
            for f in files:
                ext = Path(secure_filename(f.filename)).suffix[:10]
                stored = f"{ticket_id.replace('/', '-')}-{uuid.uuid4().hex}{ext}"
                f.save(ticket_dir / stored)
                saved.append({"name": secure_filename(f.filename), "path": f"tickets/{token_date}/{stored}"})
        conn.execute("INSERT INTO tickets(id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,public_token_hash,complaint_desk) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)",
                     (ticket_id, kind, username, str(user.get("name") or "")[:120], department, factory, remote, primary, sub, description, material, json.dumps(saved), token_hash, desk_obj["id"]))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,'Public portal','created',%s)", (ticket_id, description[:500]))
        is_mr = (kind == "Material request")
        desk_label = desk_obj.get("name") or "IT"
        _record_notification_event(conn, {
            "eventKey": f"ticket:{ticket_id}",
            "kind": "material_request" if is_mr else "ticket",
            "level": "info",
            "title": f"{'New Material Request' if is_mr else f'New {desk_label} Ticket'}: {ticket_id}",
            "body": f"{str(user.get('name') or username)} · {sub or primary} ({factory or '-'})",
            "factory": factory,
            "targetView": "ticketing",
            "targetTab": "materials" if is_mr else "tickets",
            "targetId": ticket_id,
            "complaintDesk": desk_obj["id"],
        })
    return jsonify(id=ticket_id, tracking_token=tracking_token, complaintDesk=desk_obj["id"]), 201


@app.post("/api/public/tickets/status")
def get_public_ticket_status():
    tracking_token = str((request.get_json(silent=True) or {}).get("tracking_token", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", tracking_token):
        abort(404)
    token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute("SELECT id,status,eta,note,updated_at FROM tickets WHERE public_token_hash=%s", (token_hash,)).fetchone()
        repair = repair_map_from_conn(conn).get(row[0]) if row else None
        issued_parts = issued_parts_map_from_conn(conn).get(row[0], []) if row else []
    if not row:
        abort(404)
    return jsonify(id=row[0], status=row[1], eta=row[2].isoformat(timespec="minutes") if row[2] else "",
                   note=row[3], updated=row[4].isoformat(timespec="minutes") if row[4] else "",
                   repair=repair, issuedParts=issued_parts)


@app.post("/api/account/profile-picture")
@signed_in
def update_profile_picture():
    upload = request.files.get("picture")
    if not upload or not upload.filename:
        return jsonify(error="Choose a profile picture first."), 400
    ext = Path(upload.filename).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp"):
        return jsonify(error="Use a PNG, JPG, or WebP image."), 400
    data = upload.stream.read(2 * 1024 * 1024 + 1)
    valid = (ext == ".png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or (ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8\xff")) or (ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    if not data or len(data) > 2 * 1024 * 1024 or not valid:
        return jsonify(error="Use a valid image up to 2 MB."), 400
    username = session["profile"].get("username", "")
    filename = uuid.uuid4().hex + ext
    (PROFILE_MEDIA_DIR / filename).write_bytes(data)
    picture_url = "/profile-media/" + filename
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account:
            (PROFILE_MEDIA_DIR / filename).unlink(missing_ok=True)
            return jsonify(error="Local account was not found."), 404
        account["profile_picture"] = picture_url
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    session["profile"]["profile_picture"] = picture_url
    return jsonify(ok=True, profile_picture=picture_url)

@app.post("/api/account/password")
@signed_in
def change_account_password():
    body = request.get_json(force=True)
    current_password = str(body.get("current_password", ""))
    new_password = str(body.get("new_password", ""))
    confirm_password = str(body.get("confirm_password", ""))
    if not new_password or len(new_password) > 1024:
        return jsonify(error="Enter a new password"), 400
    if new_password != confirm_password:
        return jsonify(error="New password and confirmation do not match"), 400
    username = session["profile"].get("username", "")
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account or not account.get("password_hash"):
            return jsonify(error="Local account was not found."), 400
        if not check_password_hash(account["password_hash"], current_password):
            return jsonify(error="Current password is incorrect"), 400
        account["password_hash"] = generate_password_hash(new_password)
        account["auth_version"] = int(account.get("auth_version", 0) or 0) + 1
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
        cur_sid = str(session.get("sid") or "")
        if cur_sid:
            conn.execute("DELETE FROM user_sessions WHERE lower(username)=lower(%s) AND sid<>%s", (username, cur_sid))
            conn.execute("UPDATE user_sessions SET auth_version=%s, last_seen_at=now() WHERE sid=%s", (account["auth_version"], cur_sid))
        session["auth_version"] = account["auth_version"]
    return jsonify(ok=True, message="Password changed successfully")


@app.get("/api/data")
@signed_in
def get_data():
    who = session["profile"]
    with db() as conn:
        keys = ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "vendors", "manual_users", "settings", "camera_streams", "camera_profiles", "network_ranges", "network_scan", "scanner_heartbeat", "scanner_ip_status", "notifications")
        out = {k: (conn.execute("SELECT value FROM app_state WHERE key=%s", (k,)).fetchone() or ([],))[0] for k in keys}
        settings_val = out.get("settings") if isinstance(out.get("settings"), dict) else {}
        ticketing_cfg = normalize_ticketing_settings(settings_val)
        safe_factories = {k: settings_val[k] for k in ("factories", "factoryOrder", "removedFactoryCodes", "factoryTerm", "factoryTermPlural", "assetTypes", "assetSubcategories", "categoryTileHidden", "companyName") if k in settings_val}
        safe_factories.update(ticketing_cfg)
        if session.get("is_admin"):
            if isinstance(out.get("settings"), dict):
                out["settings"] = {**out["settings"], **ticketing_cfg}
            else:
                out["settings"] = dict(ticketing_cfg)
            out["users"] = [
                {k: v for k, v in u.items() if k not in ("password_hash", "recovery_answer_hashes")}
                | {"source": "manual", "hasRecoveryQuestions": bool(u.get("recovery_answer_hashes"))}
                for u in out.pop("manual_users", [])
            ]
            out["factories_config"] = safe_factories
        else:
            allowed = set()
            for module, grant in module_permissions_for(who).items():
                if grant in ("read", "write"):
                    allowed.update(MODULE_DATA_KEYS.get(module, ()))
            out = {key: value for key, value in out.items() if key in allowed}
            manuals = out.pop("manual_users", [])
            if "manual_users" in allowed:
                out["users"] = [
                    {k: v for k, v in u.items() if k not in ("password_hash", "recovery_answer_hashes", "module_permissions", "allowed_complaint_desks", "gate_scope", "gate_departments")}
                    | {"source": "manual", "hasRecoveryQuestions": bool(u.get("recovery_answer_hashes"))}
                    for u in manuals
                ]
            elif any(k in allowed for k in ("assets", "departments", "maintenance", "parts_inventory", "invoices", "software")) or module_access(who, "tickets") or module_access(who, "visitors") or module_access(who, "gatepass") or module_access(who, "notifications"):
                out["users"] = [{k: v for k, v in u.items() if k in ("username", "name", "email", "dept", "department", "subdept", "site", "role", "enabled", "active", "employment")} | {"source": "manual"} for u in manuals]
            else:
                out["users"] = [{k: v for k, v in who.items() if k in ("username", "name", "email", "dept", "department", "site", "role")}]
            out.pop("settings", None)
            out["factories_config"] = safe_factories
        return jsonify(**out)


@app.put("/api/data")
@signed_in
def save_data():
    body = request.get_json(force=True)
    if not isinstance(body, dict):
        return jsonify(error="Invalid data payload."), 400
    if not session.get("is_admin"):
        who = session["profile"]
        for key in body:
            if key == "settings":
                return jsonify(error="Administrator access is required for system settings."), 403
            module = data_key_module(key)
            if not module or not module_access(who, module, write=True):
                return jsonify(error="You do not have write access to the %s module." % (module or "requested")), 403
    with db() as conn:
        for key in ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "vendors", "manual_users", "settings"):
            if key in body:
                value = body[key]
                if key == "assets" and isinstance(value, list):
                    current = (conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone() or ([],))[0]
                    prior_by_tag = {str(a.get("tag", "")).casefold(): a for a in current}
                    reconciled = []
                    for item in value:
                        asset = dict(item)
                        prior = prior_by_tag.get(str(asset.get("tag", "")).casefold(), {})
                        interfaces = asset.get("networkInterfaces", [])
                        if not isinstance(interfaces, list) or len(interfaces) > 16:
                            return jsonify(error="Each asset can have up to 16 network interfaces."), 400
                        prior_interfaces = prior.get("networkInterfaces", [])
                        if not isinstance(prior_interfaces, list):
                            prior_interfaces = []
                        prior_by_interface = {}
                        for previous in prior_interfaces:
                            if isinstance(previous, dict):
                                identity = (str(previous.get("name", previous.get("interface", ""))).strip().casefold(),
                                            str(previous.get("ipAddress", previous.get("ip_address", previous.get("ip", "")))).strip())
                                prior_by_interface[identity] = previous
                        clean_interfaces = []
                        for interface in interfaces:
                            if not isinstance(interface, dict):
                                return jsonify(error="Network interface entries must be objects."), 400
                            name = str(interface.get("name", interface.get("interface", ""))).strip()[:80]
                            ip_value = str(interface.get("ipAddress", interface.get("ip_address", interface.get("ip", "")))).strip()
                            mac = str(interface.get("macAddress", interface.get("mac_address", ""))).strip()[:64]
                            if len(ip_value) > 45:
                                return jsonify(error="Network interface IP addresses are too long."), 400
                            if ip_value:
                                try:
                                    ipaddress.ip_address(ip_value)
                                except ValueError:
                                    return jsonify(error="Enter a valid IP address for each network interface."), 400
                            entry = {"name": name, "ipAddress": ip_value, "macAddress": mac}
                            previous = prior_by_interface.get((name.casefold(), ip_value))
                            if previous:
                                for field in ("status", "ipStatus", "ipCheckedAt", "lastSeen"):
                                    if field in previous:
                                        entry[field] = previous[field]
                            clean_interfaces.append(entry)
                        asset["networkInterfaces"] = clean_interfaces
                        old_ip = str(prior.get("ipAddress", prior.get("ip_address", ""))).strip()
                        new_ip = str(asset.get("ipAddress", asset.get("ip_address", ""))).strip()
                        old_ips = {old_ip} if old_ip else set()
                        new_ips = {new_ip} if new_ip else set()
                        old_ips.update(str(i.get("ipAddress", i.get("ip_address", i.get("ip", "")))).strip() for i in prior_interfaces if isinstance(i, dict))
                        new_ips.update(i["ipAddress"] for i in clean_interfaces if i["ipAddress"])
                        old_ips.discard("")
                        if prior and old_ips == new_ips:
                            for field in ("status", "ipStatus", "ipCheckedAt", "lastSeen"):
                                if field in prior:
                                    asset[field] = prior[field]
                        else:
                            asset["status"] = "Not checked"
                            asset["ipStatus"] = "Not checked"
                            asset["ipCheckedAt"] = ""
                        reconciled.append(asset)
                    value = reconciled
                if key == "manual_users":
                    current = (conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone() or ([],))[0]
                    existing = {str(u.get("username", "")).casefold(): u for u in current}
                    is_admin_actor = bool(session.get("is_admin"))
                    clean = []
                    for item in value:
                        user = dict(item)
                        username = str(user.get("username", "")).strip()
                        if not username:
                            continue
                        if not re.fullmatch(r"[A-Za-z0-9._@-]{3,80}", username):
                            return jsonify(error="Usernames must be 3–80 letters, numbers, dots, underscores, @, or hyphens."), 400
                        prior = existing.get(username.casefold(), {})
                        if not is_admin_actor:
                            if prior.get("role") == "Administrator" or user.get("role") == "Administrator":
                                if prior.get("role") == "Administrator":
                                    clean.append(prior)
                                    continue
                                return jsonify(error="Only an administrator can create or promote Administrator accounts."), 403
                            user.pop("password", None)
                            user.pop("recovery_answers", None)
                            if "module_permissions" in prior:
                                user["module_permissions"] = prior["module_permissions"]
                            else:
                                user.pop("module_permissions", None)
                            if "allowed_complaint_desks" in prior:
                                user["allowed_complaint_desks"] = prior["allowed_complaint_desks"]
                            else:
                                user.pop("allowed_complaint_desks", None)
                            if "gate_scope" in prior:
                                user["gate_scope"] = prior["gate_scope"]
                            else:
                                user.pop("gate_scope", None)
                            if "gate_departments" in prior:
                                user["gate_departments"] = prior["gate_departments"]
                            else:
                                user.pop("gate_departments", None)
                            user["role"] = prior.get("role", "User") if prior else "User"
                            user["enabled"] = prior.get("enabled", True) if prior else True
                        else:
                            raw_gscope = str(user.get("gate_scope") or "dept").strip().lower()
                            user["gate_scope"] = raw_gscope if raw_gscope in ("dept", "management", "security") else "dept"
                            raw_gdepts = user.get("gate_departments")
                            if isinstance(raw_gdepts, list):
                                user["gate_departments"] = [str(x).strip()[:120] for x in raw_gdepts[:60] if str(x).strip()]
                            else:
                                user["gate_departments"] = []
                            if "allowed_complaint_desks" in user:
                                raw_desks = user.get("allowed_complaint_desks")
                                if isinstance(raw_desks, list):
                                    clean_desks = []
                                    for dk in raw_desks[:40]:
                                        dks = str(dk or "").strip().lower()
                                        if dks in ("*", "all"):
                                            clean_desks = ["*"]
                                            break
                                        slug = _slug_desk_id(dks, fallback="")
                                        if slug and slug not in clean_desks:
                                            clean_desks.append(slug)
                                    user["allowed_complaint_desks"] = clean_desks
                                else:
                                    user.pop("allowed_complaint_desks", None)
                        old_ip = str(prior.get("ip_address", prior.get("ipAddress", ""))).strip()
                        new_ip = str(user.get("ip_address", user.get("ipAddress", ""))).strip()
                        if prior and old_ip == new_ip:
                            for field in ("ipStatus", "ipCheckedAt", "lastSeen"):
                                if field in prior:
                                    user[field] = prior[field]
                        elif new_ip:
                            user["ipStatus"] = "Not checked"
                            user["ipCheckedAt"] = ""
                        new_password = user.pop("password", "") if is_admin_actor else ""
                        user.pop("password_confirm", None)
                        user.pop("hasRecoveryQuestions", None)
                        rec_answers = user.pop("recovery_answers", None) if is_admin_actor else None
                        if rec_answers is not None and any(str(a or "").strip() for a in (rec_answers if isinstance(rec_answers, list) else [])):
                            rec_hashes = recovery_answer_hashes(rec_answers)
                            if not rec_hashes:
                                return jsonify(error="Answer all three recovery questions (3–200 characters each)."), 400
                            user["recovery_answer_hashes"] = rec_hashes
                        elif prior.get("recovery_answer_hashes"):
                            user["recovery_answer_hashes"] = prior["recovery_answer_hashes"]
                        pw_changed = False
                        if new_password:
                            if len(new_password) > 1024:
                                return jsonify(error="Password is too long."), 400
                            user["password_hash"] = generate_password_hash(new_password)
                            user["auth_version"] = int(prior.get("auth_version", 0) or 0) + 1
                            pw_changed = True
                        elif prior.get("password_hash"):
                            user["password_hash"] = prior["password_hash"]
                            user["auth_version"] = int(prior.get("auth_version", 0) or 0)
                        if "password_hash" not in user:
                            user["password_hash"] = ""
                        user["username"] = username
                        user["role"] = user.get("role") if user.get("role") in ("Administrator", "IT Ticketing", "Viewer") else "User"
                        user["enabled"] = user.get("enabled", True)
                        if pw_changed or not user["enabled"]:
                            conn.execute("DELETE FROM user_sessions WHERE lower(username)=lower(%s)", (username,))
                        clean.append(user)
                    if not any(u.get("enabled", True) and u.get("role") == "Administrator" and u.get("password_hash") for u in clean):
                        return jsonify(error="Keep at least one enabled Administrator account with a password."), 400
                    kept_names = {u["username"].casefold() for u in clean}
                    for old_uname in existing:
                        if old_uname not in kept_names:
                            conn.execute("DELETE FROM user_sessions WHERE lower(username)=lower(%s)", (old_uname,))
                    value = clean
                conn.execute("INSERT INTO app_state(key,value) VALUES(%s,%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (key, json.dumps(value)))
        if "factories_config" in body and isinstance(body["factories_config"], dict):
            s_row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
            settings_cur = dict(s_row[0]) if s_row and isinstance(s_row[0], dict) else {}
            for fk in ("factories", "factoryOrder", "removedFactoryCodes", "factoryTerm", "factoryTermPlural"):
                if fk in body["factories_config"]:
                    settings_cur[fk] = body["factories_config"][fk]
            conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(settings_cur),))
    return jsonify(ok=True)


def ticket_json(row):
    return {"id":row[0],"kind":row[1],"username":row[2],"name":row[3],"dept":row[4],"site":row[5],"ip":str(row[6] or ""),"primary":row[7],"sub":row[8],"description":row[9],"material":row[10],"files":row[11],"assigned":row[12],"status":row[13],"eta":row[14].isoformat(timespec="minutes") if row[14] else "","note":row[15],"updated":row[16].isoformat(timespec="minutes") if row[16] else "","complaintDesk":(row[17] if len(row) > 17 and row[17] else "it")}


TICKET_COLUMNS = "id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,assigned_to,status,eta,note,updated_at,COALESCE(NULLIF(complaint_desk,''),'it')"


INVOICE_UPLOAD_DIR = UPLOAD_DIR / "invoices"
INVOICE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
INVOICE_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".heic", ".heif", ".avif", ".tif", ".tiff", ".svg", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".pages", ".numbers", ".key"}


def invoice_rows(conn):
    row = conn.execute("SELECT value FROM app_state WHERE key='invoices'").fetchone()
    return row[0] if row and isinstance(row[0], list) else []


@app.get("/api/invoices")
@signed_in
def list_invoices():
    with db() as conn:
        rows = invoice_rows(conn)
    return jsonify(invoices=rows)


def save_invoice_request(invoice_id=None):
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "billing", write=True):
        abort(403)
    try:
        payload = json.loads(request.form.get("invoice", "{}"))
    except (TypeError, ValueError):
        return jsonify(error="Invoice details are invalid."), 400
    if not isinstance(payload, dict):
        return jsonify(error="Invoice details are invalid."), 400
    number = str(payload.get("number", "")).strip()[:100]
    if not number:
        return jsonify(error="Invoice number is required."), 400
    files = [f for f in request.files.getlist("files") if f and f.filename]
    if len(files) > 5:
        return jsonify(error="Attach up to five files per invoice."), 400
    attachments = []
    for upload in files:
        ext = Path(secure_filename(upload.filename)).suffix.lower()
        if ext not in INVOICE_EXTENSIONS:
            return jsonify(error="Use PDF, supported image, Office, OpenDocument, Apple iWork, RTF, CSV, or TXT attachments."), 400
        data = upload.stream.read(10 * 1024 * 1024 + 1)
        if not data or len(data) > 10 * 1024 * 1024:
            return jsonify(error="Each invoice file must be 10 MB or smaller."), 400
        if ext == ".pdf" and not data.startswith(b"%PDF-"):
            return jsonify(error="The PDF attachment is invalid."), 400
        if ext in (".jpg", ".jpeg") and not data.startswith(b"\xff\xd8\xff"):
            return jsonify(error="The JPEG attachment is invalid."), 400
        if ext == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return jsonify(error="The PNG attachment is invalid."), 400
        if ext == ".webp" and not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
            return jsonify(error="The WebP attachment is invalid."), 400
        safe_name = secure_filename(upload.filename)[:150] or ("attachment" + ext)
        attachments.append((safe_name, ext, data, upload.mimetype or "application/octet-stream"))
    with db() as conn:
        rows = invoice_rows(conn)
        old = next((r for r in rows if r.get("id") == invoice_id), None) if invoice_id else None
        if invoice_id and not old:
            abort(404)
        if old:
            old_files = list(old.get("attachments", []))
            if len(old_files) + len(attachments) > 5:
                return jsonify(error="An invoice can have up to five attachments in total."), 400
            record = {**old, **payload, "id": invoice_id, "attachments": old_files, "updatedAt": datetime.now(timezone.utc).isoformat()}
        else:
            record = {**payload, "id": "inv-" + uuid.uuid4().hex, "attachments": [], "createdAt": datetime.now(timezone.utc).isoformat()}
        folder = INVOICE_UPLOAD_DIR / record["id"]
        folder.mkdir(parents=True, exist_ok=True)
        for safe_name, ext, data, mime_type in attachments:
            stored = uuid.uuid4().hex + ext
            (folder / stored).write_bytes(data)
            record["attachments"].append({"name": safe_name, "file": stored, "size": len(data), "type": mime_type})
        if old:
            rows[rows.index(old)] = record
        else:
            rows.insert(0, record)
        conn.execute("INSERT INTO app_state(key,value) VALUES('invoices',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (json.dumps(rows),))
    return jsonify(invoice=record), 200 if old else 201


@app.post("/api/invoices")
@signed_in
def create_invoice():
    return save_invoice_request()


@app.put("/api/invoices/<invoice_id>")
@signed_in
def update_invoice(invoice_id):
    return save_invoice_request(invoice_id)


@app.get("/api/invoices/<invoice_id>/files/<filename>")
@signed_in
def invoice_attachment(invoice_id, filename):
    with db() as conn:
        record = next((r for r in invoice_rows(conn) if r.get("id") == invoice_id), None)
    if not record:
        abort(404)
    attachment = next((f for f in record.get("attachments", []) if f.get("file") == filename), None)
    if not attachment:
        abort(404)
    # Inline rendering is limited to formats browsers can safely preview. Keep
    # office, Apple and other uploaded documents as downloads, regardless of
    # a client supplied MIME type.
    inline_types = {
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".avif": "image/avif",
    }
    original_name = attachment.get("name", "invoice-attachment")
    inline_mime = inline_types.get(Path(original_name).suffix.lower())
    response = send_from_directory(
        INVOICE_UPLOAD_DIR / invoice_id,
        filename,
        as_attachment=inline_mime is None,
        download_name=original_name,
        mimetype=inline_mime,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.delete("/api/invoices/<invoice_id>")
@signed_in
def delete_invoice(invoice_id):
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "billing", write=True):
        abort(403)
    with db() as conn:
        rows = invoice_rows(conn)
        kept = [r for r in rows if r.get("id") != invoice_id]
        if len(kept) == len(rows):
            abort(404)
        conn.execute("INSERT INTO app_state(key,value) VALUES('invoices',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (json.dumps(kept),))
    shutil.rmtree(INVOICE_UPLOAD_DIR / invoice_id, ignore_errors=True)
    return jsonify(ok=True)


@app.get("/api/tickets")
@signed_in
def list_tickets():
    profile = session.get("profile", {})
    req_desk = str(request.args.get("desk") or "").strip().lower()
    with db() as conn:
        rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 1000").fetchall()
        repair_map = repair_map_from_conn(conn)
        issued_map = issued_parts_map_from_conn(conn)
    filtered = []
    for r in rows:
        desk_id = (r[17] if len(r) > 17 and r[17] else "it")
        if not session.get("is_admin") and not ticket_desk_allowed(profile, desk_id):
            continue
        if req_desk and req_desk != "all" and _slug_desk_id(desk_id, "it") != _slug_desk_id(req_desk, "it"):
            continue
        filtered.append({**ticket_json(r), "repair": repair_map.get(r[0]), "issuedParts": issued_map.get(r[0], [])})
    return jsonify(tickets=filtered)


@app.put("/api/tickets/settings")
@ticket_manager
def update_ticket_settings():
    profile = session.get("profile", {})
    unrestricted = allowed_complaint_desks_for(profile) is None
    if not session.get("is_admin") and not ((profile.get("role") == "IT Ticketing" and unrestricted) or module_access(profile, "settings", write=True)):
        return jsonify(error="Administrator or unrestricted ticketing manager access is required."), 403
    body = request.get_json(force=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid ticketing settings payload."), 400
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        settings_val = dict(row[0]) if row and isinstance(row[0], dict) else {}
        merged = dict(settings_val)
        for key in ("ticketCategoryTree", "ticketCategories", "materialRequestCategories", "defaultTicketPriority", "complaintDesks", "showAllDesksOnPortal"):
            if key in body:
                merged[key] = body[key]
        # Avoid stale top-level IT fields overriding explicit complaintDesks edit unless caller omitted complaintDesks
        if "complaintDesks" in body and "ticketCategoryTree" not in body:
            merged.pop("ticketCategoryTree", None)
        normalized = normalize_ticketing_settings(merged)
        settings_val.update(normalized)
        conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(settings_val),))
        _pg_emit_notify(conn, "pulse", {"source": "settings"})
    return jsonify(ok=True, settings=normalized)


@app.get("/api/tickets/parts-options")
@ticket_manager
def ticket_parts_options():
    profile = session.get("profile", {})
    can_view_cost = bool(session.get("is_admin") or module_access(profile, "parts") or module_access(profile, "valuation"))
    if not (session.get("is_admin") or profile.get("role") == "IT Ticketing" or module_access(profile, "parts")):
        return jsonify(error="Parts inventory access is not enabled for your account."), 403
    with db() as conn:
        inv_row = conn.execute("SELECT value FROM app_state WHERE key='parts_inventory'").fetchone()
        cat_row = conn.execute("SELECT value FROM app_state WHERE key='parts_catalog'").fetchone()
        asgn_row = conn.execute("SELECT value FROM app_state WHERE key='parts_assignments'").fetchone()
    inv = inv_row[0] if inv_row and isinstance(inv_row[0], list) else []
    if not can_view_cost:
        inv = [{k: v for k, v in item.items() if k != "unitCost"} for item in inv if isinstance(item, dict)]
    cat = cat_row[0] if cat_row and isinstance(cat_row[0], list) else []
    asgn = asgn_row[0] if asgn_row and isinstance(asgn_row[0], list) else []
    return jsonify(parts_inventory=inv, parts_catalog=cat, parts_assignments=asgn if can_view_cost else [])


@app.post("/api/tickets/<path:ticket_id>/issue-material")
@ticket_manager
def issue_material_for_ticket(ticket_id):
    profile = session.get("profile", {})
    if not (session.get("is_admin") or profile.get("role") == "IT Ticketing" or module_access(profile, "parts", write=True)):
        return jsonify(error="Ticketing backend or Parts write permission is required."), 403
    body = request.get_json(force=True) or {}
    part_id = str(body.get("partId") or "").strip()
    site = str(body.get("site") or "").strip()
    condition = str(body.get("condition") or "New").strip()
    dept = str(body.get("dept") or "").strip()[:120]
    user = str(body.get("user") or "").strip()[:120]
    notes = str(body.get("notes") or "").strip()[:400]
    new_status = str(body.get("status") or "Resolved").strip()
    if new_status not in ("In progress", "Resolved", "Closed"):
        new_status = "Resolved"
    try:
        qty = int(body.get("quantity") or 0)
    except (TypeError, ValueError):
        qty = 0
    if not part_id or qty < 1 or condition not in ("New", "RepairedRefurbished", "Repaired", "Refurbished", "Damaged"):
        return jsonify(error="Select a valid part, condition, and positive quantity."), 400
    actor = str(profile.get("name") or profile.get("username") or "IT")[:120]
    issue_date = datetime.now().strftime("%Y-%m-%d")
    with db() as conn:
        t_row = conn.execute("SELECT id,display_name,department,factory,material,sub_category,COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id=%s FOR UPDATE", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not session.get("is_admin") and not ticket_desk_allowed(profile, t_row[6]):
            return jsonify(error="You do not have access to this complaint department's tickets."), 403
        inv_row = conn.execute("SELECT value FROM app_state WHERE key='parts_inventory' FOR UPDATE").fetchone()
        asgn_row = conn.execute("SELECT value FROM app_state WHERE key='parts_assignments' FOR UPDATE").fetchone()
        inv_list = list(inv_row[0]) if inv_row and isinstance(inv_row[0], list) else []
        asgn_list = list(asgn_row[0]) if asgn_row and isinstance(asgn_row[0], list) else []
        part = next((p for p in inv_list if isinstance(p, dict) and str(p.get("id") or "") == part_id and (not site or str(p.get("site") or "") == site)), None)
        if not part:
            return jsonify(error="Selected part was not found at the chosen factory."), 404
        if condition == "New":
            avail = max(0, int(float(part.get("newQty") or 0)))
        elif condition == "RepairedRefurbished":
            avail = max(0, int(float(part.get("repairedQty") or 0))) + max(0, int(float(part.get("refurbishedQty") or 0)))
        elif condition == "Repaired":
            avail = max(0, int(float(part.get("repairedQty") or 0)))
        elif condition == "Refurbished":
            avail = max(0, int(float(part.get("refurbishedQty") or 0)))
        else:
            avail = max(0, int(float(part.get("damagedQty") or 0)))
        if avail < qty:
            return jsonify(error=f"Not enough stock in {condition}. Available: {avail}, Requested: {qty}."), 400
        rep_ded = 0
        ref_ded = 0
        cond_label = "Repaired / Refurbished" if condition == "RepairedRefurbished" else condition
        if condition == "RepairedRefurbished":
            rep_avail = max(0, int(float(part.get("repairedQty") or 0)))
            rep_ded = min(rep_avail, qty)
            ref_ded = qty - rep_ded
            part["repairedQty"] = rep_avail - rep_ded
            part["refurbishedQty"] = max(0, int(float(part.get("refurbishedQty") or 0)) - ref_ded)
        elif condition == "Repaired":
            part["repairedQty"] = max(0, int(float(part.get("repairedQty") or 0)) - qty)
        elif condition == "Refurbished":
            part["refurbishedQty"] = max(0, int(float(part.get("refurbishedQty") or 0)) - qty)
        elif condition == "Damaged":
            part["damagedQty"] = max(0, int(float(part.get("damagedQty") or 0)) - qty)
        else:
            part["newQty"] = max(0, int(float(part.get("newQty") or 0)) - qty)
        assign_id = f"assign-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:5]}"
        assignment = {
            "id": assign_id,
            "partId": part.get("id", ""),
            "productId": part.get("productId", ""),
            "partName": part.get("name", ""),
            "sku": part.get("sku", ""),
            "category": part.get("category", ""),
            "group": part.get("group", ""),
            "site": site or part.get("site", "") or t_row[3],
            "dept": dept or t_row[2],
            "user": user or t_row[1],
            "quantity": qty,
            "returned": 0,
            "condition": cond_label,
            "repairedDeducted": rep_ded,
            "refurbishedDeducted": ref_ded,
            "date": issue_date,
            "ticketId": ticket_id,
            "materialRequestId": ticket_id,
            "materialRequested": t_row[4] or t_row[5] or "",
            "issuedBy": actor,
            "unitCost": float(part.get("unitCost") or 0),
            "work": notes or f"Issued for Material Request {ticket_id}",
            "notes": notes or f"Issued for Material Request {ticket_id}",
        }
        asgn_list.insert(0, assignment)
        conn.execute("INSERT INTO app_state(key,value) VALUES('parts_inventory',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(inv_list),))
        conn.execute("INSERT INTO app_state(key,value) VALUES('parts_assignments',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(asgn_list),))
        ticket_note = f"Issued {qty} × {part.get('name', 'Part')} ({cond_label}) from {assignment['site']} Parts Inventory to {assignment['user']} on {issue_date}"
        if notes:
            ticket_note += f" · {notes}"
        conn.execute("UPDATE tickets SET status=%s, note=%s, assigned_to=CASE WHEN assigned_to='Unassigned' THEN %s ELSE assigned_to END, updated_at=now() WHERE id=%s",
                     (new_status, ticket_note[:1000], actor, ticket_id))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'material_issued',%s)", (ticket_id, actor, ticket_note[:1000]))
        _pg_emit_notify(conn, "ticket", {"action": "issue-material", "ticketId": ticket_id, "status": new_status})
        issued_list = issued_parts_map_from_conn(conn).get(ticket_id, [])
    return jsonify(ok=True, assignment=assignment, status=new_status, note=ticket_note, issuedParts=issued_list, parts_inventory=inv_list, parts_assignments=asgn_list)


@app.get("/api/tickets/<path:ticket_id>/attachments/<path:filename>")
@signed_in
def ticket_attachment(ticket_id, filename):
    profile = session.get("profile", {})
    with db() as conn:
        row = conn.execute("SELECT username,attachments,COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
    if not row:
        abort(404)
    if not session.get("is_admin") and not ticket_desk_allowed(profile, row[2]):
        abort(403)
    match = next((item for item in row[1] if Path(item.get("path", "")).name == filename), None)
    if not match:
        abort(404)
    return send_from_directory(UPLOAD_DIR / "tickets" / ticket_id.split("/")[-1], filename, as_attachment=False)


@app.post("/api/tickets")
@signed_in
def create_ticket():
    form = request.form
    description = form.get("description", "").strip()
    kind = form.get("kind", "IT help desk")
    primary = form.get("primary", "")
    sub = form.get("sub", "")
    if not description or not sub or kind not in ("IT help desk", "Material request"):
        return jsonify(error="Complete the issue description and category"), 400
    files = request.files.getlist("files")
    if len(files) > 5:
        return jsonify(error="Attach up to five screenshots"), 400
    profile = session["profile"]
    allowed_desks = allowed_complaint_desks_for(profile)
    req_desk_raw = form.get("complaintDesk")
    if req_desk_raw:
        req_desk = _slug_desk_id(req_desk_raw, fallback="it")
    elif allowed_desks is not None and len(allowed_desks) > 0:
        req_desk = sorted(allowed_desks)[0]
    else:
        req_desk = "it"
    if not session.get("is_admin") and not ticket_desk_allowed(profile, req_desk):
        return jsonify(error="You are not permitted to create tickets for this complaint department."), 403
    remote = request.remote_addr
    with db() as conn:
        srow = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
        ticketing_cfg = normalize_ticketing_settings(srow[0] if srow else {})
        desks = ticketing_cfg.get("complaintDesks") or []
        desk_obj = next((d for d in desks if d["id"] == req_desk), None) or (desks[0] if desks else {"id": req_desk, "name": "IT", "tokenPrefix": "IT"})
        ticket_id, token_date = _next_ticket_id(conn, prefix=desk_obj.get("tokenPrefix", "IT"))
        ticket_dir = UPLOAD_DIR / "tickets" / token_date
        ticket_dir.mkdir(parents=True, exist_ok=True)
        saved = []
        for f in files:
            if not f.filename:
                continue
            if f.mimetype not in ("image/png", "image/jpeg", "image/gif", "image/webp"):
                return jsonify(error="Only image attachments are accepted"), 400
            ext = Path(secure_filename(f.filename)).suffix[:10]
            stored = f"{ticket_id.replace('/', '-')}-{uuid.uuid4().hex}{ext}"
            f.save(ticket_dir / stored)
            saved.append({"name":secure_filename(f.filename),"path":f"tickets/{token_date}/{stored}"})
        conn.execute("INSERT INTO tickets(id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,complaint_desk) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)", (ticket_id,kind,profile["username"],profile["name"],profile.get("department", ""),profile.get("site", ""),remote,primary,sub,description,form.get("material", ""),json.dumps(saved),desk_obj["id"]))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'created',%s)", (ticket_id,profile["username"],description[:500]))
        is_mr = (kind == "Material request")
        desk_label = desk_obj.get("name") or "IT"
        _record_notification_event(conn, {
            "eventKey": f"ticket:{ticket_id}",
            "kind": "material_request" if is_mr else "ticket",
            "level": "info",
            "title": f"{'New Material Request' if is_mr else f'New {desk_label} Ticket'}: {ticket_id}",
            "body": f"{profile.get('name') or profile['username']} · {sub or primary} ({profile.get('site', '-')})",
            "factory": profile.get("site", ""),
            "targetView": "ticketing",
            "targetTab": "materials" if is_mr else "tickets",
            "targetId": ticket_id,
            "complaintDesk": desk_obj["id"],
        })
    return jsonify(id=ticket_id, complaintDesk=desk_obj["id"]), 201


@app.patch("/api/tickets/<path:ticket_id>")
@ticket_manager
def update_ticket(ticket_id):
    body = request.get_json(force=True)
    allowed = {"assigned":"assigned_to", "status":"status", "eta":"eta", "note":"note"}
    fields = [(allowed[k], (None if k == "eta" and v == "" else v)) for k,v in body.items() if k in allowed]
    if not fields:
        return jsonify(error="No supported fields to update"), 400
    if "status" in body and body["status"] not in ("Open", "In progress", "Resolved", "Closed"):
        return jsonify(error="Invalid status"), 400
    if "assigned" in body and len(str(body["assigned"])) > 160:
        return jsonify(error="Assignee name is too long."), 400
    if "eta" in body and body["eta"] not in (None, "") and len(str(body["eta"])) > 40:
        return jsonify(error="Invalid ETA."), 400
    assignments = ", ".join(f"{column}=%s" for column,_ in fields)
    profile = session.get("profile", {})
    with db() as conn:
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not session.get("is_admin") and not ticket_desk_allowed(profile, t_row[0]):
            return jsonify(error="You do not have access to this complaint department's tickets."), 403
        cur = conn.execute(f"UPDATE tickets SET {assignments}, updated_at=now() WHERE id=%s RETURNING id", [v for _,v in fields]+[ticket_id])
        if not cur.fetchone():
            abort(404)
        detail = "; ".join(f"{k}: {v}" for k,v in body.items() if k in allowed)[:1000]
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'updated',%s)", (ticket_id,session["profile"]["username"],detail))
        _pg_emit_notify(conn, "ticket", {"action": "update", "ticketId": ticket_id, "complaintDesk": t_row[0]})
    return jsonify(ok=True)


@app.post("/api/tickets/<path:ticket_id>/worklog")
@ticket_manager
def add_ticket_worklog(ticket_id):
    body = request.get_json(silent=True) or {}
    detail = str(body.get("detail", "")).strip()
    if not detail or len(detail) > 3000:
        return jsonify(error="Enter a work update (up to 3000 characters)."), 400
    profile = session.get("profile", {})
    actor = str(profile.get("name") or profile.get("username", "IT"))[:120]
    with db() as conn:
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not session.get("is_admin") and not ticket_desk_allowed(profile, t_row[0]):
            return jsonify(error="You do not have access to this complaint department's tickets."), 403
        row = conn.execute("UPDATE tickets SET note=%s,updated_at=now() WHERE id=%s RETURNING id", (detail, ticket_id)).fetchone()
        if not row:
            abort(404)
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'worklog',%s)", (ticket_id, actor, detail))
        _pg_emit_notify(conn, "ticket", {"action": "worklog", "ticketId": ticket_id, "complaintDesk": t_row[0]})
    return jsonify(ok=True)


@app.get("/api/tickets/<path:ticket_id>/worklog")
@ticket_manager
def list_ticket_worklog(ticket_id):
    profile = session.get("profile", {})
    with db() as conn:
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not session.get("is_admin") and not ticket_desk_allowed(profile, t_row[0]):
            abort(403)
        rows = conn.execute("SELECT actor,detail,created_at FROM ticket_events WHERE ticket_id=%s AND event_type IN ('created','updated','worklog') ORDER BY created_at DESC LIMIT 100", (ticket_id,)).fetchall()
    return jsonify(events=[{"actor":r[0],"detail":r[1],"created":r[2].isoformat(timespec="minutes")} for r in rows])


def _can_delete_tickets():
    profile = session.get("profile") or {}
    if session.get("is_admin") or profile.get("role") == "IT Ticketing":
        return True
    if module_access(profile, "tickets", write=True):
        return True
    return False


def _delete_tickets_tx(conn, raw_ids, profile=None, is_admin=False):
    ids = []
    seen = set()
    for x in (raw_ids or []):
        s = str(x or "").strip()[:120]
        if s and s not in seen:
            seen.add(s)
            ids.append(s)
    if not ids:
        return []
    rows = conn.execute("SELECT id, attachments, COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id = ANY(%s)", (ids,)).fetchall()
    if not is_admin and profile is not None:
        rows = [r for r in rows if ticket_desk_allowed(profile, r[2])]
    if not rows:
        return []
    deleted_ids = [r[0] for r in rows]
    tickets_root = (UPLOAD_DIR / "tickets").resolve()
    files_to_remove = []
    for _, atts, _ in rows:
        for item in (atts or []):
            rel = str(item.get("path", "") if isinstance(item, dict) else "").strip()
            if not rel:
                continue
            try:
                p = (UPLOAD_DIR / rel).resolve()
                if p != tickets_root and tickets_root in p.parents:
                    files_to_remove.append(p)
            except OSError:
                continue
    conn.execute("DELETE FROM tickets WHERE id = ANY(%s)", (deleted_ids,))
    for p in files_to_remove:
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
    if deleted_ids:
        _pg_emit_notify(conn, "ticket", {"action": "delete", "ids": deleted_ids})
    return deleted_ids


@app.delete("/api/tickets/<path:ticket_id>")
@ticket_manager
def delete_ticket(ticket_id):
    if not _can_delete_tickets():
        return jsonify(error="Ticketing backend or administrator access is required to delete tickets."), 403
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    with db() as conn:
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it') FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not is_adm and not ticket_desk_allowed(profile, t_row[0]):
            return jsonify(error="You do not have access to delete this complaint department's ticket."), 403
        deleted = _delete_tickets_tx(conn, [ticket_id], profile=profile, is_admin=is_adm)
    if not deleted:
        abort(404)
    return jsonify(ok=True, deletedIds=deleted, deleted=len(deleted))


@app.post("/api/tickets/bulk-delete")
@ticket_manager
def bulk_delete_tickets():
    if not _can_delete_tickets():
        return jsonify(error="Ticketing backend or administrator access is required to delete tickets."), 403
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") if isinstance(body, dict) else None
    if not isinstance(ids, list) or not ids or len(ids) > 500:
        return jsonify(error="Select between 1 and 500 tickets or material requests to delete."), 400
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    with db() as conn:
        deleted = _delete_tickets_tx(conn, ids, profile=profile, is_admin=is_adm)
    return jsonify(ok=True, deletedIds=deleted, deleted=len(deleted))


@app.get("/api/backups")
@administrator
def backup_list():
    path = Path(os.getenv("BACKUP_DIR", "/backups"))
    files = sorted(
        list(path.glob("northstar-*.tar.gz")) + list(path.glob("shree-*.tar.gz")),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    ) if path.exists() else []
    return jsonify(backups=[{"name":p.name,"size":p.stat().st_size,"created":datetime.fromtimestamp(p.stat().st_mtime,timezone.utc).isoformat()} for p in files[:100]])


@app.get("/api/backups/<path:name>")
@administrator
def download_backup(name):
    if not re.fullmatch(r"(?:northstar|shree)-(daily|weekly|monthly|manual)-[0-9T-]+\.tar\.gz", name):
        abort(404)
    return send_from_directory(os.getenv("BACKUP_DIR", "/backups"), name, as_attachment=True)


@app.post("/api/backups")
@administrator
def create_manual_backup():
    try:
        result = subprocess.run(["python", str(ROOT / "backup.py"), "manual"], capture_output=True, text=True, check=True, timeout=1800)
        return jsonify(name=result.stdout.strip())
    except subprocess.TimeoutExpired:
        return jsonify(error="Backup is taking longer than expected. Check server logs."), 504
    except subprocess.CalledProcessError as exc:
        app.logger.error("Manual backup failed: %s", exc.stderr[-1000:])
        return jsonify(error="Backup failed. Check server logs."), 500


@app.post("/api/backups/restore")
@administrator
def restore_uploaded_backup():
    upload = request.files.get("backup")
    if not upload or not upload.filename:
        return jsonify(error="Choose a Shree .tar.gz backup file."), 400
    if not upload.filename.lower().endswith((".tar.gz", ".tgz")):
        return jsonify(error="Only Shree .tar.gz backup files are supported."), 400

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="northstar-restore-") as temp_name:
        temp = Path(temp_name)
        archive = temp / "uploaded-backup.tar.gz"
        extracted = temp / "validated"
        upload.save(archive)

        try:
            validation = subprocess.run(
                ["python", str(ROOT / "restore_archive.py"), str(archive), str(extracted)],
                capture_output=True, text=True, check=True, timeout=1800,
            )
        except subprocess.CalledProcessError as exc:
            app.logger.warning("Uploaded backup rejected: %s", (exc.stderr or exc.stdout)[-1000:])
            return jsonify(error="Backup validation failed. Check that this is an intact Shree backup."), 400
        except subprocess.TimeoutExpired:
            return jsonify(error="Backup validation took too long. No data was restored."), 504

        try:
            lock_fd = os.open(RESTORE_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return jsonify(error="Another restore is already in progress."), 409

        safety_name = ""
        try:
            os.write(lock_fd, str(os.getpid()).encode("ascii"))
            os.close(lock_fd)
            safety = subprocess.run(
                ["python", str(ROOT / "backup.py"), "manual"],
                capture_output=True, text=True, check=True, timeout=1800,
            )
            safety_name = safety.stdout.strip()
            db_dump = extracted / "database.dump"
            subprocess.run(
                ["pg_restore", "--clean", "--if-exists", "--no-owner", "--single-transaction",
                 "--dbname", os.environ["DATABASE_URL"], str(db_dump)],
                capture_output=True, text=True, check=True, timeout=1800,
            )

            restored_uploads = extracted / "uploads"
            staging = UPLOAD_DIR.parent / (".uploads-restore-" + uuid.uuid4().hex)
            previous = UPLOAD_DIR.parent / (".uploads-before-restore-" + uuid.uuid4().hex)
            shutil.copytree(restored_uploads, staging)
            moved_previous = False
            try:
                if UPLOAD_DIR.exists():
                    os.replace(UPLOAD_DIR, previous)
                    moved_previous = True
                os.replace(staging, UPLOAD_DIR)
            except Exception:
                if moved_previous and previous.exists() and not UPLOAD_DIR.exists():
                    os.replace(previous, UPLOAD_DIR)
                raise
            if previous.exists():
                shutil.rmtree(previous)
            init_db()
            return jsonify(ok=True, safety_backup=safety_name,
                           message="Backup restored. Sign in again if the restored user accounts differ.")
        except subprocess.CalledProcessError as exc:
            app.logger.error("Uploaded backup restore failed: %s", (exc.stderr or exc.stdout)[-2000:])
            return jsonify(error="Restore failed. Check server logs; the pre-restore safety backup is " + (safety_name or "being created") + "."), 500
        except subprocess.TimeoutExpired:
            return jsonify(error="Restore took too long. Check server logs and the pre-restore safety backup."), 504
        except Exception:
            app.logger.exception("Uploaded backup restore failed unexpectedly")
            return jsonify(error="Restore failed. Check server logs and the pre-restore safety backup."), 500
        finally:
            try:
                os.close(lock_fd)
            except OSError:
                pass
            RESTORE_LOCK_PATH.unlink(missing_ok=True)


UPDATER_RUN_DIR = Path(os.getenv("NORTHSTAR_UPDATER_RUN", "/run/northstar-updater"))
UPDATER_SOCK_PATH = UPDATER_RUN_DIR / "updater.sock"
UPDATER_STATUS_PATH = UPDATER_RUN_DIR / "status.json"


def _updater_settings(conn):
    row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    cfg = row[0] if row and isinstance(row[0], dict) else {}
    repo_url = str(cfg.get("gitUpdateRepo") or "").strip()[:300]
    branch = str(cfg.get("gitUpdateBranch") or "main").strip()[:80] or "main"
    return repo_url, branch


def _updater_ipc(payload, timeout=180):
    if UPDATER_SOCK_PATH.exists():
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(str(UPDATER_SOCK_PATH))
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
            return json.loads(raw.decode("utf-8").strip() or "{}")
        finally:
            sock.close()
    if payload.get("action") == "status" and UPDATER_STATUS_PATH.exists():
        try:
            return json.loads(UPDATER_STATUS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "ok": False,
        "available": False,
        "state": "unavailable",
        "progress": 0,
        "step": "Host updater not connected",
        "error": "Run sudo bash update.sh once on the Ubuntu host to enable 1-click Git auto-updates.",
    }


@app.get("/api/admin/software-update/status")
@administrator
def software_update_status():
    with db() as conn:
        repo_url, branch = _updater_settings(conn)
    res = _updater_ipc({"action": "status"}, timeout=10)
    res.setdefault("available", bool(UPDATER_SOCK_PATH.exists() or res.get("state") in ("running", "completed")))
    res.setdefault("configRepoUrl", repo_url)
    res.setdefault("configBranch", branch)
    return jsonify(res)


@app.post("/api/admin/software-update/config")
@administrator
def software_update_config():
    body = request.get_json(silent=True) or {}
    repo_url = str(body.get("repoUrl") or "").strip()[:300]
    branch = str(body.get("branch") or "main").strip()[:80] or "main"
    if repo_url and not re.match(r"^https?://[^\s'\"]+$", repo_url):
        return jsonify(error="Use an HTTPS Git repository URL (for example https://github.com/user/repo.git)."), 400
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", branch):
        return jsonify(error="Branch name may contain only letters, numbers, dots, underscores, slashes, or hyphens."), 400
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        cfg = dict(row[0]) if row and isinstance(row[0], dict) else {}
        cfg["gitUpdateRepo"] = repo_url
        cfg["gitUpdateBranch"] = branch
        conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(cfg),))
    return jsonify(ok=True, repoUrl=repo_url, branch=branch)


_HOST_TOKEN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _normalize_site_names(raw):
    text = str(raw or "").strip()[:120]
    if not text:
        return ""
    tokens = []
    for part in re.split(r"[\s,]+", text):
        p = part.strip()
        if not p:
            continue
        if "://" in p:
            p = p.split("://", 1)[1]
        p = p.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].strip(".").lower()
        if not p:
            continue
        try:
            ipaddress.ip_address(p)
            return None
        except ValueError:
            pass
        if not _HOST_TOKEN_RE.match(p):
            return None
        tokens.append(p)
    return " ".join(dict.fromkeys(tokens))


@app.get("/api/admin/network-config")
@administrator
def admin_get_network_config():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    cfg = row[0] if row and isinstance(row[0], dict) else {}
    ipc_status = _updater_ipc({"action": "get_network_status"}, timeout=2) if UPDATER_SOCK_PATH.exists() else {}
    runtime = cfg.get("networkRuntime") if isinstance(cfg.get("networkRuntime"), dict) else {}
    return jsonify(
        ok=True,
        siteName=str(cfg.get("siteName") or ""),
        httpPort=int(cfg.get("httpPort") or os.getenv("HTTP_PORT") or 8848),
        httpsPort=int(cfg.get("httpsPort") or os.getenv("HTTPS_PORT") or 8849),
        updaterAvailable=bool(UPDATER_SOCK_PATH.exists()),
        serverLanIp=str(ipc_status.get("serverLanIp") or runtime.get("serverLanIp") or ""),
        hostNginxActive=bool(ipc_status.get("hostNginxActive", runtime.get("hostNginxActive", False))),
        hostNginxApplied=bool(ipc_status.get("hostNginxApplied", runtime.get("hostNginxApplied", False))),
        hostNginxDomains=ipc_status.get("hostNginxDomains", runtime.get("hostNginxDomains", [])),
        hostNginxCertType=str(ipc_status.get("hostNginxCertType") or runtime.get("hostNginxCertType") or ""),
        avahiActive=bool(ipc_status.get("avahiActive", runtime.get("avahiUpdated", False))),
    )


@app.post("/api/admin/network-config")
@administrator
def admin_save_network_config():
    body = request.get_json(silent=True) or {}
    raw_site = str(body.get("siteName") or "").strip()[:120]
    site_name = _normalize_site_names(raw_site)
    if site_name is None:
        return jsonify(error="Enter valid domain or LAN hostname(s), e.g. swarnshilp.local or it.yourcompany.com (without IP addresses or special symbols)."), 400
    try:
        http_port = int(body.get("httpPort") or 8848)
        https_port = int(body.get("httpsPort") or 8849)
    except (ValueError, TypeError):
        return jsonify(error="Port numbers must be valid numbers between 1 and 65535."), 400

    if not (1 <= http_port <= 65535 and 1 <= https_port <= 65535):
        return jsonify(error="Port numbers must be between 1 and 65535."), 400
    if http_port == https_port:
        return jsonify(error="HTTP port and HTTPS port must be different."), 400

    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        cfg = dict(row[0]) if row and isinstance(row[0], dict) else {}
        cfg["siteName"] = site_name
        cfg["httpPort"] = http_port
        cfg["httpsPort"] = https_port
        conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(cfg),))

    ipc_res = _updater_ipc({
        "action": "set_network_config",
        "siteName": site_name,
        "httpPort": http_port,
        "httpsPort": https_port,
    }, timeout=90) if UPDATER_SOCK_PATH.exists() else {}

    runtime = {
        "serverLanIp": str(ipc_res.get("serverLanIp") or ""),
        "hostNginxActive": bool(ipc_res.get("hostNginxActive")),
        "hostNginxApplied": bool(ipc_res.get("hostNginxApplied")),
        "hostNginxDomains": ipc_res.get("hostNginxDomains") or [],
        "hostNginxCertType": str(ipc_res.get("hostNginxCertType") or ""),
        "avahiUpdated": bool(ipc_res.get("avahiUpdated")),
    }

    if ipc_res.get("ok"):
        with db() as conn:
            row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
            cfg = dict(row[0]) if row and isinstance(row[0], dict) else {}
            cfg["networkRuntime"] = runtime
            conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(cfg),))

    return jsonify(
        ok=True,
        siteName=site_name,
        httpPort=http_port,
        httpsPort=https_port,
        updaterAvailable=bool(UPDATER_SOCK_PATH.exists()),
        dockerApplied=bool(ipc_res.get("ok")),
        dockerMessage=ipc_res.get("message") or ("Settings saved in database. LAN mDNS & LLMNR auto-discovery will activate within seconds; run sudo bash update.sh on Ubuntu to enable Port 80/443 Host Nginx multi-site integration." if not UPDATER_SOCK_PATH.exists() else "Network settings applied."),
        **runtime,
    )


@app.post("/api/admin/regenerate-ssl")
@administrator
def admin_regenerate_ssl():
    if not UPDATER_SOCK_PATH.exists():
        return jsonify(error="Host updater service is not running yet. Run sudo bash update.sh once on the Ubuntu server."), 503
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    cfg = row[0] if row and isinstance(row[0], dict) else {}
    site_name = str(cfg.get("siteName") or "").strip()[:120]
    res = _updater_ipc({"action": "regenerate_ssl", "siteName": site_name}, timeout=45)
    if not res.get("ok"):
        return jsonify(error=res.get("error") or "SSL certificate regeneration failed."), 400
    return jsonify(res)


def _find_android_apk():
    for cand in (UPLOAD_DIR / "shree-it.apk", ROOT / "static" / "downloads" / "shree-it.apk", ROOT / "shree-it.apk"):
        if cand.is_file() and cand.stat().st_size > 10000:
            return cand
    return None


@app.get("/api/public/apk-status")
def public_apk_status():
    apk = _find_android_apk()
    if not apk:
        return jsonify(available=False, sizeBytes=0, downloadUrl="")
    return jsonify(available=True, sizeBytes=apk.stat().st_size, downloadUrl="/download/shree-it.apk")


@app.get("/download/shree-it.apk")
def download_android_apk():
    apk = _find_android_apk()
    if not apk:
        return jsonify(error="Android APK is not compiled yet. Run sudo bash build-apk.sh on the server first."), 404
    resp = send_from_directory(apk.parent, apk.name, mimetype="application/vnd.android.package-archive")
    resp.headers["Content-Disposition"] = 'attachment; filename="Shree-IT.apk"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.post("/api/admin/software-update/check")
@administrator
def software_update_check():
    body = request.get_json(silent=True) or {}
    with db() as conn:
        saved_repo, saved_branch = _updater_settings(conn)
    repo_url = str(body.get("repoUrl") if body.get("repoUrl") is not None else saved_repo).strip()[:300]
    branch = str(body.get("branch") or saved_branch or "main").strip()[:80]
    if repo_url and not re.match(r"^https?://[^\s'\"]+$", repo_url):
        return jsonify(error="Use a valid HTTPS Git repository URL."), 400
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", branch):
        return jsonify(error="Enter a valid branch name."), 400
    if not UPDATER_SOCK_PATH.exists():
        return jsonify(error="Host auto-updater service is not running yet. Run sudo bash update.sh once on the Ubuntu server to install northstar-updater.service."), 503
    res = _updater_ipc({"action": "check", "repoUrl": repo_url, "branch": branch}, timeout=120)
    if res.get("error"):
        return jsonify(error=res["error"]), 400
    return jsonify(res)


@app.post("/api/admin/software-update/start")
@administrator
def software_update_start():
    body = request.get_json(silent=True) or {}
    with db() as conn:
        saved_repo, saved_branch = _updater_settings(conn)
    repo_url = str(body.get("repoUrl") if body.get("repoUrl") is not None else saved_repo).strip()[:300]
    branch = str(body.get("branch") or saved_branch or "main").strip()[:80]
    if repo_url and not re.match(r"^https?://[^\s'\"]+$", repo_url):
        return jsonify(error="Use a valid HTTPS Git repository URL."), 400
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", branch):
        return jsonify(error="Enter a valid branch name."), 400
    if not UPDATER_SOCK_PATH.exists():
        return jsonify(error="Host auto-updater service is not active yet. Run sudo bash update.sh once on the Ubuntu host to enable 1-click Git updates."), 503
    res = _updater_ipc({"action": "start", "repoUrl": repo_url, "branch": branch}, timeout=30)
    if res.get("error"):
        return jsonify(error=res["error"]), 400
    return jsonify(res)


SPEEDTEST_LIVE_PATH = Path(os.getenv("TMPDIR", "/tmp")) / "northstar-speedtest-live.json"
_SPEEDTEST_LOCK = threading.Lock()
_SPEEDTEST_SAMPLE_CHUNK = secrets.token_bytes(65536)
DEFAULT_SPEEDTEST_SETTINGS = {"unitMode": "auto", "testMode": "internet", "intervalSec": 0}


def _normalize_speedtest_doc(raw):
    doc = dict(raw) if isinstance(raw, dict) else {}
    s = dict(DEFAULT_SPEEDTEST_SETTINGS)
    raw_s = doc.get("settings") if isinstance(doc.get("settings"), dict) else {}
    if raw_s.get("unitMode") in ("auto", "kbps", "mbps", "gbps"):
        s["unitMode"] = raw_s["unitMode"]
    if raw_s.get("testMode") in ("internet", "lan"):
        s["testMode"] = raw_s["testMode"]
    try:
        iv = int(raw_s.get("intervalSec", 0))
        if iv in (0, 15, 30, 60, 300):
            s["intervalSec"] = iv
    except (TypeError, ValueError):
        pass
    hist = [h for h in (doc.get("history") if isinstance(doc.get("history"), list) else []) if isinstance(h, dict)][:50]
    return {"settings": s, "history": hist}


def _read_speedtest_live():
    try:
        if SPEEDTEST_LIVE_PATH.exists():
            return json.loads(SPEEDTEST_LIVE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"running": False, "phase": "idle", "downloadMbps": 0.0, "uploadMbps": 0.0, "pingMs": 0.0, "jitterMs": 0.0}


def _write_speedtest_live(payload):
    try:
        tmp = SPEEDTEST_LIVE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, SPEEDTEST_LIVE_PATH)
    except Exception:
        pass


def _run_internet_speedtest_worker(run_id):
    import http.client
    state = {
        "runId": run_id,
        "running": True,
        "phase": "ping",
        "mode": "internet",
        "pingMs": 0.0,
        "jitterMs": 0.0,
        "downloadMbps": 0.0,
        "uploadMbps": 0.0,
        "serverLabel": "Google / Cloudflare Edge",
        "startedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "error": "",
    }
    _write_speedtest_live(state)
    try:
        # 1. Latency & Jitter probe
        rtts = []
        probe_urls = ["https://www.google.com/generate_204", "https://speed.cloudflare.com/__down?bytes=0"]
        for i in range(5):
            for p_url in probe_urls:
                t0 = time.perf_counter()
                try:
                    req = URLRequest(p_url, headers={"User-Agent": "Shree-SpeedMonitor/1.0", "Cache-Control": "no-store"})
                    with urlopen(req, timeout=3.5) as resp:
                        resp.read(64)
                    rtts.append((time.perf_counter() - t0) * 1000.0)
                    break
                except Exception:
                    continue
        if not rtts:
            raise RuntimeError("Internet WAN unreachable from server container. Switch Test Mode to Server Link (LAN).")
        sorted_rtts = sorted(rtts)
        state["pingMs"] = round(sorted_rtts[len(sorted_rtts) // 2], 1)
        if len(rtts) > 1:
            deltas = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
            state["jitterMs"] = round(sum(deltas) / len(deltas), 1)

        # 2. Multi-stream Download probe (up to 4.2s)
        state["phase"] = "download"
        _write_speedtest_live(state)
        dl_bytes = 0
        dl_lock = threading.Lock()
        dl_stop = threading.Event()
        dl_t0 = time.perf_counter()

        def dl_worker():
            nonlocal dl_bytes
            try:
                req = URLRequest(
                    "https://speed.cloudflare.com/__down?bytes=25000000",
                    headers={"User-Agent": "Shree-SpeedMonitor/1.0", "Cache-Control": "no-store"},
                )
                with urlopen(req, timeout=6.0) as resp:
                    while not dl_stop.is_set():
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        with dl_lock:
                            dl_bytes += len(chunk)
                        if time.perf_counter() - dl_t0 >= 4.2:
                            break
            except Exception:
                pass

        dl_threads = [threading.Thread(target=dl_worker, daemon=True) for _ in range(2)]
        for t in dl_threads:
            t.start()
        while any(t.is_alive() for t in dl_threads):
            elapsed = max(0.08, time.perf_counter() - dl_t0)
            with dl_lock:
                cur_bytes = dl_bytes
            state["downloadMbps"] = round((cur_bytes * 8.0) / (elapsed * 1_000_000.0), 2)
            _write_speedtest_live(state)
            if elapsed >= 4.2 or (elapsed >= 2.5 and cur_bytes >= 32_000_000):
                dl_stop.set()
                break
            time.sleep(0.14)
        for t in dl_threads:
            t.join(timeout=1.0)
        dl_elapsed = max(0.1, time.perf_counter() - dl_t0)
        final_dl_mbps = round((dl_bytes * 8.0) / (dl_elapsed * 1_000_000.0), 2)
        state["downloadMbps"] = final_dl_mbps

        # 3. Multi-stream Streaming Upload probe via http.client chunk writes (up to 4.0s)
        state["phase"] = "upload"
        _write_speedtest_live(state)
        ul_bytes = 0
        ul_lock = threading.Lock()
        ul_stop = threading.Event()
        ul_t0 = time.perf_counter()
        payload_chunk = _SPEEDTEST_SAMPLE_CHUNK[:32768]
        total_per_req = 4 * 1024 * 1024

        def ul_worker():
            nonlocal ul_bytes
            try:
                while not ul_stop.is_set() and (time.perf_counter() - ul_t0) < 3.8:
                    conn_http = http.client.HTTPSConnection("speed.cloudflare.com", timeout=5.0)
                    try:
                        conn_http.putrequest("POST", "/__up")
                        conn_http.putheader("User-Agent", "Shree-SpeedMonitor/1.0")
                        conn_http.putheader("Content-Type", "application/octet-stream")
                        conn_http.putheader("Content-Length", str(total_per_req))
                        conn_http.endheaders()
                        sent = 0
                        while sent < total_per_req and not ul_stop.is_set() and (time.perf_counter() - ul_t0) < 4.0:
                            step = min(len(payload_chunk), total_per_req - sent)
                            conn_http.send(payload_chunk[:step])
                            sent += step
                            with ul_lock:
                                ul_bytes += step
                        try:
                            if sent == total_per_req:
                                conn_http.getresponse().read(64)
                        except Exception:
                            pass
                    finally:
                        try:
                            conn_http.close()
                        except Exception:
                            pass
            except Exception:
                pass

        ul_threads = [threading.Thread(target=ul_worker, daemon=True) for _ in range(2)]
        for t in ul_threads:
            t.start()
        while any(t.is_alive() for t in ul_threads):
            elapsed = max(0.08, time.perf_counter() - ul_t0)
            with ul_lock:
                cur_bytes = ul_bytes
            state["uploadMbps"] = round((cur_bytes * 8.0) / (elapsed * 1_000_000.0), 2)
            _write_speedtest_live(state)
            if elapsed >= 4.0:
                ul_stop.set()
                break
            time.sleep(0.14)
        for t in ul_threads:
            t.join(timeout=1.0)
        ul_elapsed = max(0.1, time.perf_counter() - ul_t0)
        final_ul_mbps = round((ul_bytes * 8.0) / (ul_elapsed * 1_000_000.0), 2)
        state["uploadMbps"] = final_ul_mbps

        completed = {
            "id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": "internet",
            "pingMs": state["pingMs"],
            "jitterMs": state["jitterMs"],
            "downloadMbps": final_dl_mbps,
            "uploadMbps": final_ul_mbps,
            "serverLabel": "Google / Cloudflare Edge",
            "status": "ok",
        }
        with db() as conn:
            row = conn.execute("SELECT value FROM app_state WHERE key='network_speedtest' FOR UPDATE").fetchone()
            doc = _normalize_speedtest_doc(row[0] if row else {})
            doc["history"] = ([completed] + doc["history"])[:50]
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES('network_speedtest',%s::jsonb) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
                (json.dumps(doc),),
            )
        state["running"] = False
        state["phase"] = "done"
        state["finishedAt"] = completed["timestamp"]
        _write_speedtest_live(state)
    except Exception as exc:
        state["running"] = False
        state["phase"] = "error"
        state["error"] = str(exc)[:240]
        _write_speedtest_live(state)


@app.get("/api/speedtest/ping")
@signed_in
def speedtest_ping():
    resp = jsonify(ok=True, serverTime=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/speedtest/download")
@signed_in
def speedtest_download():
    try:
        total = max(65536, min(32 * 1024 * 1024, int(request.args.get("bytes", 8 * 1024 * 1024))))
    except (TypeError, ValueError):
        total = 8 * 1024 * 1024

    def generate():
        sent = 0
        chunk_len = len(_SPEEDTEST_SAMPLE_CHUNK)
        while sent < total:
            n = min(chunk_len, total - sent)
            sent += n
            yield _SPEEDTEST_SAMPLE_CHUNK[:n]

    resp = Response(generate(), mimetype="application/octet-stream")
    resp.headers["Content-Length"] = str(total)
    resp.headers["Cache-Control"] = "no-store, no-transform"
    resp.headers["Content-Encoding"] = "identity"
    return resp


@app.post("/api/speedtest/upload")
@signed_in
def speedtest_upload():
    total = 0
    stream = request.stream
    while total < 40 * 1024 * 1024:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
    resp = jsonify(ok=True, bytes=total)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/network/speedtest")
@signed_in
def get_network_speedtest():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_speedtest'").fetchone()
    doc = _normalize_speedtest_doc(row[0] if row else {})
    live = _read_speedtest_live()
    latest = doc["history"][0] if doc["history"] else None
    return jsonify(settings=doc["settings"], live=live, latest=latest, history=doc["history"])


@app.put("/api/network/speedtest/settings")
@signed_in
def update_network_speedtest_settings():
    body = request.get_json(silent=True) or {}
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_speedtest' FOR UPDATE").fetchone()
        doc = _normalize_speedtest_doc(row[0] if row else {})
        merged = {**doc, "settings": {**doc["settings"], **body}}
        normalized = _normalize_speedtest_doc(merged)
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('network_speedtest',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(normalized),),
        )
    return jsonify(ok=True, settings=normalized["settings"])


@app.post("/api/network/speedtest/run")
@signed_in
def run_network_speedtest():
    body = request.get_json(silent=True) or {}
    client_result = body.get("clientResult") if isinstance(body.get("clientResult"), dict) else None
    if client_result:
        entry = {
            "id": "st-" + uuid.uuid4().hex[:10],
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": "lan" if client_result.get("mode") == "lan" else "internet",
            "pingMs": round(max(0.0, float(client_result.get("pingMs") or 0)), 1),
            "jitterMs": round(max(0.0, float(client_result.get("jitterMs") or 0)), 1),
            "downloadMbps": round(max(0.0, float(client_result.get("downloadMbps") or 0)), 2),
            "uploadMbps": round(max(0.0, float(client_result.get("uploadMbps") or 0)), 2),
            "serverLabel": str(client_result.get("serverLabel") or "Shree LAN Link")[:100],
            "status": "ok",
        }
        with db() as conn:
            row = conn.execute("SELECT value FROM app_state WHERE key='network_speedtest' FOR UPDATE").fetchone()
            doc = _normalize_speedtest_doc(row[0] if row else {})
            doc["history"] = ([entry] + doc["history"])[:50]
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES('network_speedtest',%s::jsonb) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
                (json.dumps(doc),),
            )
        return jsonify(ok=True, entry=entry, history=doc["history"])

    with _SPEEDTEST_LOCK:
        cur = _read_speedtest_live()
        if cur.get("running"):
            started = cur.get("startedAt") or ""
            stale = False
            try:
                stale = (datetime.now(timezone.utc) - datetime.fromisoformat(started)).total_seconds() > 25
            except Exception:
                stale = True
            if not stale:
                return jsonify(ok=True, started=False, live=cur)
        run_id = "st-" + uuid.uuid4().hex[:10]
        _write_speedtest_live({
            "runId": run_id, "running": True, "phase": "ping", "mode": "internet",
            "pingMs": 0.0, "jitterMs": 0.0, "downloadMbps": 0.0, "uploadMbps": 0.0,
            "startedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"), "error": "",
        })
        t = threading.Thread(target=_run_internet_speedtest_worker, args=(run_id,), daemon=True)
        t.start()
    return jsonify(ok=True, started=True, runId=run_id)


def _normalize_network_map_doc(raw):
    doc = dict(raw) if isinstance(raw, dict) else {}
    diagrams = doc.get("diagrams") if isinstance(doc.get("diagrams"), dict) else {}
    clean_diagrams = {}
    for fk, fd in list(diagrams.items())[:60]:
        fcode = str(fk or "").strip()[:60]
        if not fcode or not isinstance(fd, dict):
            continue
        floors = fd.get("floors") if isinstance(fd.get("floors"), list) else []
        clean_floors = []
        for idx, fl in enumerate(floors[:25]):
            if not isinstance(fl, dict):
                continue
            fid = str(fl.get("id") or f"fl-{idx + 1}")[:60]
            clean_floors.append({
                "id": fid,
                "name": str(fl.get("name") or f"Floor {idx + 1}")[:80],
                "level": int(fl.get("level") if isinstance(fl.get("level"), (int, float)) else idx),
                "visible": fl.get("visible", True) is not False,
                "width": max(600, min(4000, int(fl.get("width") or 1400))),
                "height": max(400, min(3000, int(fl.get("height") or 860))),
                "bgColor": str(fl.get("bgColor") or "#ffffff")[:40],
                "bgImage": str(fl.get("bgImage") or "")[:3_500_000],
                "bgOpacity": max(0.05, min(1.0, float(fl.get("bgOpacity") or 0.45))),
                "nodes": [n for n in (fl.get("nodes") if isinstance(fl.get("nodes"), list) else []) if isinstance(n, dict)][:500],
                "links": [l for l in (fl.get("links") if isinstance(fl.get("links"), list) else []) if isinstance(l, dict)][:1000],
                "shapes": [s for s in (fl.get("shapes") if isinstance(fl.get("shapes"), list) else []) if isinstance(s, dict)][:500],
                "strokes": [st for st in (fl.get("strokes") if isinstance(fl.get("strokes"), list) else []) if isinstance(st, dict)][:400],
            })
        clean_diagrams[fcode] = {
            "factory": fcode,
            "activeFloorId": str(fd.get("activeFloorId") or (clean_floors[0]["id"] if clean_floors else ""))[:60],
            "floors": clean_floors,
            "interFloorLinks": [l for l in (fd.get("interFloorLinks") if isinstance(fd.get("interFloorLinks"), list) else []) if isinstance(l, dict)][:400],
            "updatedAt": str(fd.get("updatedAt") or "")[:40],
        }
    return {
        "diagrams": clean_diagrams,
        "rev": int(doc.get("rev") or 1),
        "updatedAt": str(doc.get("updatedAt") or "")[:40],
    }


@app.get("/api/network-map")
@signed_in
def get_network_map():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_map'").fetchone()
    doc = _normalize_network_map_doc(row[0] if row else {})
    return jsonify(doc)


@app.put("/api/network-map")
@signed_in
def save_network_map():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid network map payload."), 400
    raw_len = len(json.dumps(body))
    if raw_len > 24 * 1024 * 1024:
        return jsonify(error="Network map payload exceeds 24 MB limit."), 400
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_map' FOR UPDATE").fetchone()
        existing = _normalize_network_map_doc(row[0] if row else {})
        doc = _normalize_network_map_doc(body)
        doc["rev"] = existing["rev"] + 1
        doc["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('network_map',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(doc),),
        )
    return jsonify(ok=True, rev=doc["rev"], updatedAt=doc["updatedAt"], diagrams=doc["diagrams"])


def _normalize_tile_node(raw, depth=0):
    if not isinstance(raw, dict) or depth > 4:
        return None
    subtiles = []
    if isinstance(raw.get("subtiles"), list):
        for st in raw["subtiles"][:150]:
            ns = _normalize_tile_node(st, depth + 1)
            if ns:
                subtiles.append(ns)
    return {
        "id": str(raw.get("id") or f"tile-{uuid.uuid4().hex[:8]}")[:80],
        "groupId": str(raw.get("groupId") or "grp-default")[:80],
        "domCountId": str(raw.get("domCountId") or "")[:60],
        "domFootId": str(raw.get("domFootId") or "")[:60],
        "title": str(raw.get("title") or "Untitled Tile")[:120],
        "icon": str(raw.get("icon") or "▦")[:16],
        "bg": str(raw.get("bg") or "#e7f6ee")[:40],
        "color": str(raw.get("color") or "#157a54")[:40],
        "status": str(raw.get("status") or "all")[:32],
        "type": str(raw.get("type") or "")[:60],
        "subtype": str(raw.get("subtype") or "")[:60],
        "site": str(raw.get("site") or "")[:60],
        "dept": str(raw.get("dept") or "")[:80],
        "keyword": str(raw.get("keyword") or "")[:80],
        "foot": str(raw.get("foot") or "")[:120],
        "visible": raw.get("visible") is not False,
        "subtiles": subtiles,
    }


def _normalize_tile_module_cfg(raw):
    if isinstance(raw, list):
        raw = {"groups": [{"id": "grp-default", "name": "Overview", "icon": "▦", "color": "#157a54", "collapsed": False}], "tiles": raw}
    if not isinstance(raw, dict):
        return None
    groups = []
    for g in (raw.get("groups") if isinstance(raw.get("groups"), list) else [])[:50]:
        if isinstance(g, dict) and g.get("id"):
            groups.append({
                "id": str(g.get("id"))[:80],
                "name": str(g.get("name") or "Group")[:80],
                "icon": str(g.get("icon") or "▦")[:16],
                "color": str(g.get("color") or "#157a54")[:40],
                "collapsed": bool(g.get("collapsed", False)),
            })
    tiles = []
    for t in (raw.get("tiles") if isinstance(raw.get("tiles"), list) else [])[:250]:
        nt = _normalize_tile_node(t, 0)
        if nt:
            tiles.append(nt)
    return {"groups": groups, "tiles": tiles}


def _normalize_tile_configs_doc(raw):
    doc = dict(raw) if isinstance(raw, dict) else {}
    out = {"rev": int(doc.get("rev") or 0), "updatedAt": str(doc.get("updatedAt") or "")}
    for mod in ("overview", "datacenter", "surveillance"):
        nm = _normalize_tile_module_cfg(doc.get(mod))
        if nm is not None:
            out[mod] = nm
    return out


@app.get("/api/tile-configs")
@signed_in
def get_tile_configs():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='tile_configs'").fetchone()
    return jsonify(_normalize_tile_configs_doc(row[0] if row else {}))


@app.put("/api/tile-configs")
@signed_in
def save_tile_configs():
    profile = session.get("profile") or {}
    if not session.get("is_admin") and str(profile.get("role", "")).lower() == "viewer":
        return jsonify(error="Viewer access is read-only."), 403
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid tile configuration payload."), 400
    if len(json.dumps(body)) > 4 * 1024 * 1024:
        return jsonify(error="Tile configuration exceeds 4 MB limit."), 400
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='tile_configs' FOR UPDATE").fetchone()
        existing = _normalize_tile_configs_doc(row[0] if row else {})
        incoming = _normalize_tile_configs_doc(body)
        for mod in ("overview", "datacenter", "surveillance"):
            if mod in incoming:
                existing[mod] = incoming[mod]
        existing["rev"] = int(existing.get("rev") or 0) + 1
        existing["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('tile_configs',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(existing),),
        )
        _pg_emit_notify(conn, "pulse", {"source": "tile_configs", "rev": existing["rev"]})
    return jsonify(ok=True, **existing)


# ======================== VISITOR PASS & MATERIAL GATE PASS ========================

VISITOR_STATUSES = ("Pending", "Approved", "Checked In", "Checked Out", "Rejected")
GATEPASS_STATUSES = ("Logged", "Verified", "Returned", "Dispatched")


def _next_gate_id(conn, table, prefix):
    clean_pref = re.sub(r"[^A-Z0-9]", "", str(prefix or "GP").strip().upper())[:6] or "GP"
    token_date = datetime.now().strftime("%d-%m-%Y")
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{table}:{clean_pref}:{token_date}",))
    rows = conn.execute(f"SELECT id FROM {table} WHERE id LIKE %s", (f"{clean_pref}%/{token_date}",)).fetchall()
    max_seq = 0
    pat = re.compile(rf"^{re.escape(clean_pref)}(\d+)/")
    for (gid,) in rows:
        m = pat.match(str(gid or ""))
        if m:
            max_seq = max(max_seq, int(m.group(1)))
    return f"{clean_pref}{max_seq + 1:02d}/{token_date}", datetime.now().strftime("%Y%m%d")


def _detect_valid_image_bytes(data):
    if not data or len(data) > 5 * 1024 * 1024:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    return None


def _save_gate_image(file_storage, data_url, category, entry_id, slot):
    raw = None
    if file_storage is not None and getattr(file_storage, "filename", ""):
        raw = file_storage.stream.read(5 * 1024 * 1024 + 1)
    elif isinstance(data_url, str) and data_url.startswith("data:image/") and ";base64," in data_url:
        try:
            b64_part = data_url.split(";base64,", 1)[1]
            raw = base64.b64decode(b64_part, validate=True)
        except Exception:
            return None, "Invalid captured image format."
    if raw is None:
        return "", None
    ext = _detect_valid_image_bytes(raw)
    if not ext:
        return None, f"{slot} photo must be a valid PNG, JPG, or WebP image under 5 MB."
    date_dir = datetime.now().strftime("%Y%m%d")
    target_dir = UPLOAD_DIR / category / date_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "-", str(entry_id))[:40]
    fname = f"{safe_id}-{slot}-{uuid.uuid4().hex[:12]}{ext}"
    (target_dir / fname).write_bytes(raw)
    return f"{category}/{date_dir}/{fname}", None


def _resolve_portal_employee(conn, factory, department, emp_key, fallback_name=""):
    row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    users = row[0] if row and isinstance(row[0], list) else []
    key_str = str(emp_key or "").strip()
    if key_str:
        matched = next((
            u for u in users if isinstance(u, dict)
            and hashlib.sha256((APP_SECRET + "|" + str(u.get("username") or u.get("id") or "").casefold() + "|" + str(u.get("dept") or u.get("department") or "").casefold() + "|" + str(u.get("site") or "").casefold()).encode()).hexdigest() == key_str
            and u.get("enabled", True) and str(u.get("active", "Active")).lower() != "inactive"
        ), None)
        if matched:
            return str(matched.get("username") or matched.get("id") or "").strip(), str(matched.get("name") or "").strip()
        # Allow direct username/name match for signed-in calls
        matched2 = next((
            u for u in users if isinstance(u, dict)
            and (str(u.get("username") or "").casefold() == key_str.casefold() or str(u.get("name") or "").casefold() == key_str.casefold())
            and (not factory or str(u.get("site") or "").casefold() == factory.casefold())
        ), None)
        if matched2:
            return str(matched2.get("username") or matched2.get("id") or "").strip(), str(matched2.get("name") or "").strip()
    return "", str(fallback_name or "").strip()[:120]


def _visitor_json(r, include_private=True, public_token=""):
    def _media_url(rel):
        if not rel:
            return ""
        if include_private:
            return "/api/gate-media/" + quote(rel, safe="/")
        if public_token:
            return "/api/public/gate-media/" + quote(rel, safe="/") + "?token=" + quote(public_token, safe="")
        return ""
    item = {
        "id": r[0], "factory": r[2], "visitorName": r[3],
        "purpose": r[6], "department": r[7], "hostUsername": r[8] if include_private else "",
        "hostName": r[9], "vehicleNo": r[10], "passNo": r[11], "visitorCount": int(r[12] or 1),
        "belongings": r[13], "status": r[16], "enteredBy": r[17], "approvedBy": r[18],
        "approvedAt": r[19].isoformat() if r[19] else "",
        "checkedInAt": r[20].isoformat() if r[20] else "",
        "checkedOutAt": r[21].isoformat() if r[21] else "",
        "decisionNote": r[22],
        "createdAt": r[23].isoformat() if r[23] else "",
        "updatedAt": r[24].isoformat() if r[24] else "",
        "idCardPhoto": _media_url(r[14]),
        "selfiePhoto": _media_url(r[15]),
    }
    if include_private:
        item["phone"] = r[4]
        item["address"] = r[5]
    elif public_token:
        item["phone"] = r[4]
        item["address"] = r[5]
    return item


def _gatepass_json(r, include_private=True, public_token=""):
    def _media_url(rel):
        if not rel:
            return ""
        if include_private:
            return "/api/gate-media/" + quote(rel, safe="/")
        if public_token:
            return "/api/public/gate-media/" + quote(rel, safe="/") + "?token=" + quote(public_token, safe="")
        return ""
    return {
        "id": r[0], "direction": r[2], "factory": r[3], "materialType": r[4], "materialName": r[5],
        "quantity": r[6], "unit": r[7], "returnable": bool(r[8]), "partyName": r[9],
        "challanNo": r[10], "vehicleNo": r[11], "remarks": r[12], "department": r[13],
        "forUsername": r[14] if include_private else "", "forName": r[15],
        "materialPhoto": _media_url(r[16]), "billPhoto": _media_url(r[17]),
        "status": r[18], "enteredBy": r[19], "verifiedBy": r[20],
        "verifiedAt": r[21].isoformat() if r[21] else "",
        "createdAt": r[22].isoformat() if r[22] else "",
        "updatedAt": r[23].isoformat() if r[23] else "",
    }


def _parse_dt_bound(raw_val):
    s = str(raw_val or "").strip()
    if not s:
        return None
    try:
        if len(s) == 10:
            return datetime.fromisoformat(s + "T00:00:00+00:00")
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _build_gate_where(args, alias=""):
    clauses = []
    params = []
    if args.get("factory") and args.get("factory") != "All sites":
        clauses.append(f"factory = %s")
        params.append(str(args.get("factory"))[:80])
    if args.get("department"):
        clauses.append(f"lower(department) = lower(%s)")
        params.append(str(args.get("department"))[:120])
    if args.get("status"):
        clauses.append(f"status = %s")
        params.append(str(args.get("status"))[:40])
    if args.get("direction") in ("IN", "OUT"):
        clauses.append(f"direction = %s")
        params.append(str(args.get("direction")))
    dt_from = _parse_dt_bound(args.get("from"))
    if dt_from is not None:
        clauses.append("created_at >= %s")
        params.append(dt_from)
    dt_to = _parse_dt_bound(args.get("to"))
    if dt_to is not None:
        clauses.append("created_at <= %s")
        params.append(dt_to)
    sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return sql, params


VISITOR_COLS = "id,tracking_token_hash,factory,visitor_name,phone,address,purpose,department,host_username,host_name,vehicle_no,pass_no,visitor_count,belongings,id_card_photo,selfie_photo,status,entered_by,approved_by,approved_at,checked_in_at,checked_out_at,decision_note,created_at,updated_at"
GATEPASS_COLS = "id,tracking_token_hash,direction,factory,material_type,material_name,quantity,unit,returnable,party_name,challan_no,vehicle_no,remarks,department,for_username,for_name,material_photo,bill_photo,status,entered_by,verified_by,verified_at,created_at,updated_at"


def _token_map_from_request():
    raw = request.headers.get("X-Gate-Tokens") or request.args.get("tokens") or ""
    if not raw or len(raw) > 8192:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {str(k)[:60]: str(v)[:100] for k, v in list(parsed.items())[:80] if v}
    except Exception:
        pass
    return {}


@app.get("/api/public/gate-media/<path:rel_path>")
def public_gate_media(rel_path):
    token = str(request.args.get("token") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{30,80}", token):
        abort(403)
    parts = Path(rel_path).parts
    if len(parts) != 3 or parts[0] not in ("visitors", "gatepass") or Path(parts[2]).name != parts[2]:
        abort(404)
    thash = hashlib.sha256(token.encode()).hexdigest()
    norm_rel = f"{parts[0]}/{parts[1]}/{parts[2]}"
    with db() as conn:
        if parts[0] == "visitors":
            row = conn.execute("SELECT 1 FROM visitor_passes WHERE tracking_token_hash=%s AND (id_card_photo=%s OR selfie_photo=%s)", (thash, norm_rel, norm_rel)).fetchone()
        else:
            row = conn.execute("SELECT 1 FROM material_gate_passes WHERE tracking_token_hash=%s AND (material_photo=%s OR bill_photo=%s)", (thash, norm_rel, norm_rel)).fetchone()
    if not row:
        abort(403)
    return send_from_directory(UPLOAD_DIR / parts[0] / parts[1], parts[2], as_attachment=False)


@app.get("/api/gate-media/<path:rel_path>")
@signed_in
def signed_in_gate_media(rel_path):
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    parts = Path(rel_path).parts
    if len(parts) != 3 or parts[0] not in ("visitors", "gatepass") or Path(parts[2]).name != parts[2]:
        abort(404)
    norm_rel = f"{parts[0]}/{parts[1]}/{parts[2]}"
    with db() as conn:
        if parts[0] == "visitors":
            if not is_adm and not module_access(who, "visitors"):
                abort(403)
            row = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id_card_photo=%s OR selfie_photo=%s", (norm_rel, norm_rel)).fetchone()
            if not row:
                abort(404)
            if not visitor_row_visible(_visitor_json(row), who, is_adm):
                abort(403)
        else:
            if not is_adm and not module_access(who, "gatepass"):
                abort(403)
            row = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE material_photo=%s OR bill_photo=%s", (norm_rel, norm_rel)).fetchone()
            if not row:
                abort(404)
            if not gatepass_row_visible(_gatepass_json(row), who, is_adm):
                abort(403)
    return send_from_directory(UPLOAD_DIR / parts[0] / parts[1], parts[2], as_attachment=False)


@app.get("/api/public/visitors")
def list_public_visitors():
    sql_where, params = _build_gate_where(request.args)
    q = str(request.args.get("q") or "").strip().lower()
    tok_map = _token_map_from_request()
    with db() as conn:
        rows = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes {sql_where} ORDER BY created_at DESC LIMIT 120", params).fetchall()
    out = []
    for r in rows:
        cand_tok = tok_map.get(r[0], "")
        matched_tok = cand_tok if (cand_tok and hashlib.sha256(cand_tok.encode()).hexdigest() == r[1]) else ""
        item = _visitor_json(r, include_private=False, public_token=matched_tok)
        if q and q not in " ".join([item["id"], item["visitorName"], item["department"], item["hostName"], item["purpose"], item["factory"], item["vehicleNo"]]).lower():
            continue
        out.append(item)
    return jsonify(visitors=out)


@app.post("/api/public/visitors")
def create_public_visitor():
    return _create_visitor_impl(is_public=True)


@app.post("/api/public/visitors/<path:visitor_id>/checkin-out")
def public_visitor_checkin_out(visitor_id):
    body = request.get_json(silent=True) or {}
    action = str(body.get("action") or "").strip().lower()
    guard = str(body.get("enteredBy") or "Security Gate").strip()[:80] or "Security Gate"
    if action not in ("checkin", "checkout"):
        return jsonify(error="Invalid gate action."), 400
    with db() as conn:
        row = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s FOR UPDATE", (visitor_id,)).fetchone()
        if not row:
            return jsonify(error="Visitor pass not found."), 404
        cur_status = row[16]
        if action == "checkin":
            if cur_status != "Approved":
                return jsonify(error="Host approval is required before Check-In."), 400
            conn.execute("UPDATE visitor_passes SET status='Checked In', checked_in_at=now(), updated_at=now(), entered_by=%s WHERE id=%s", (guard, visitor_id))
        else:
            if cur_status not in ("Approved", "Checked In"):
                return jsonify(error="Visitor must be checked in first."), 400
            conn.execute("UPDATE visitor_passes SET status='Checked Out', checked_out_at=now(), updated_at=now() WHERE id=%s", (visitor_id,))
        updated = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s", (visitor_id,)).fetchone()
        _pg_emit_notify(conn, "visitor", {"action": action, "id": visitor_id, "status": updated[16]})
    return jsonify(ok=True, visitor=_visitor_json(updated, include_private=False))


def _create_visitor_impl(is_public=True):
    is_multi = bool(request.content_type and "multipart/form-data" in request.content_type)
    body = request.form if is_multi else (request.get_json(silent=True) or {})
    factory = str(body.get("factory") or "").strip()[:80]
    visitor_name = str(body.get("visitorName") or "").strip()[:120]
    phone = str(body.get("phone") or "").strip()[:40]
    address = str(body.get("address") or "").strip()[:400]
    purpose = str(body.get("purpose") or "").strip()[:300]
    department = str(body.get("department") or "").strip()[:120]
    emp_key = str(body.get("employee") or body.get("hostUsername") or "").strip()[:140]
    host_manual = str(body.get("hostName") or "").strip()[:120]
    vehicle_no = str(body.get("vehicleNo") or "").strip()[:40]
    pass_no = str(body.get("passNo") or "").strip()[:40]
    belongings = str(body.get("belongings") or "").strip()[:240]
    entered_by = str(body.get("enteredBy") or ("Security Gate" if is_public else (session.get("profile") or {}).get("name") or "User")).strip()[:80]
    try:
        visitor_count = max(1, min(100, int(body.get("visitorCount") or 1)))
    except (TypeError, ValueError):
        visitor_count = 1
    if not visitor_name or not address or not purpose or not factory or not department:
        return jsonify(error="Fill Visitor Name, Address, Purpose, Factory, and Department."), 400
    tracking_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
    with db() as conn:
        if is_public:
            recent = conn.execute("SELECT count(*) FROM visitor_passes WHERE created_at > now() - interval '10 minutes'").fetchone()[0]
            if recent >= 60:
                return jsonify(error="Too many gate entries submitted in 10 minutes. Try shortly."), 429
        host_username, host_name = _resolve_portal_employee(conn, factory, department, emp_key, fallback_name=host_manual)
        if not host_name:
            host_name = department + " Desk"
        vid, _ = _next_gate_id(conn, "visitor_passes", "VIS")
        id_file = request.files.get("idCardPhoto") if is_multi else None
        sf_file = request.files.get("selfiePhoto") if is_multi else None
        id_rel, err1 = _save_gate_image(id_file, body.get("idCardDataUrl"), "visitors", vid, "id")
        if err1:
            return jsonify(error=err1), 400
        sf_rel, err2 = _save_gate_image(sf_file, body.get("selfieDataUrl"), "visitors", vid, "selfie")
        if err2:
            return jsonify(error=err2), 400
        conn.execute(
            "INSERT INTO visitor_passes(id,tracking_token_hash,factory,visitor_name,phone,address,purpose,department,host_username,host_name,vehicle_no,pass_no,visitor_count,belongings,id_card_photo,selfie_photo,status,entered_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Pending',%s)",
            (vid, token_hash, factory, visitor_name, phone, address, purpose, department, host_username, host_name, vehicle_no, pass_no, visitor_count, belongings, id_rel, sf_rel, entered_by),
        )
        _record_notification_event(conn, {
            "eventKey": f"visitor:{vid}",
            "kind": "visitor",
            "level": "info",
            "title": f"Visitor Waiting: {visitor_name} ({vid})",
            "body": f"{purpose} · Meet {host_name} ({department} · {factory})",
            "factory": factory,
            "targetView": "visitors",
            "targetId": vid,
            "targetDepartment": department,
            "targetUsername": host_username,
            "targetHostName": host_name,
        })
        _pg_emit_notify(conn, "visitor", {"action": "create", "id": vid, "department": department, "hostUsername": host_username})
        created = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s", (vid,)).fetchone()
    return jsonify(ok=True, id=vid, tracking_token=tracking_token, visitor=_visitor_json(created, include_private=not is_public, public_token=tracking_token if is_public else "")), 201


@app.get("/api/visitors")
@signed_in
def list_visitors():
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    if not is_adm and not module_access(who, "visitors"):
        abort(403)
    sql_where, params = _build_gate_where(request.args)
    q = str(request.args.get("q") or "").strip().lower()
    with db() as conn:
        rows = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes {sql_where} ORDER BY created_at DESC LIMIT 400", params).fetchall()
    out = []
    for r in rows:
        item = _visitor_json(r, include_private=True)
        if not visitor_row_visible(item, who, is_adm):
            continue
        if q and q not in " ".join([item["id"], item["visitorName"], item["phone"], item["address"], item["department"], item["hostName"], item["purpose"], item["factory"], item["vehicleNo"]]).lower():
            continue
        out.append(item)
    return jsonify(visitors=out, gateScope=gate_scope_for(who), canApprove=is_adm or module_access(who, "visitors", write=True))


@app.post("/api/visitors")
@signed_in
def create_visitor_signed_in():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "visitors", write=True):
        return jsonify(error="Write permission for Visitor Pass is required."), 403
    return _create_visitor_impl(is_public=False)


@app.post("/api/visitors/<path:visitor_id>/decision")
@signed_in
def decide_visitor(visitor_id):
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    if not is_adm and not module_access(who, "visitors", write=True):
        return jsonify(error="Write permission for Visitor Pass is required."), 403
    body = request.get_json(silent=True) or {}
    action = str(body.get("action") or "").strip().lower()
    note = str(body.get("note") or "").strip()[:300]
    if action not in ("approve", "reject", "checkin", "checkout"):
        return jsonify(error="Invalid action."), 400
    actor = str(who.get("name") or who.get("username") or "User")[:120]
    with db() as conn:
        row = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s FOR UPDATE", (visitor_id,)).fetchone()
        if not row:
            return jsonify(error="Visitor pass not found."), 404
        cur = _visitor_json(row, include_private=True)
        if not visitor_row_visible(cur, who, is_adm):
            return jsonify(error="You can only manage visitors for your department."), 403
        if action in ("approve", "reject"):
            new_st = "Approved" if action == "approve" else "Rejected"
            conn.execute("UPDATE visitor_passes SET status=%s, approved_by=%s, approved_at=now(), decision_note=%s, updated_at=now() WHERE id=%s", (new_st, actor, note, visitor_id))
            _record_notification_event(conn, {
                "eventKey": f"visitor:{visitor_id}:{new_st.lower()}",
                "kind": "visitor",
                "level": "ok" if action == "approve" else "warning",
                "title": f"Visitor {new_st}: {cur['visitorName']} ({visitor_id})",
                "body": f"{new_st} by {actor} · {cur['department']} ({cur['factory']})",
                "factory": cur["factory"],
                "targetView": "visitors",
                "targetId": visitor_id,
                "targetDepartment": cur["department"],
                "targetUsername": cur["hostUsername"],
                "targetHostName": cur["hostName"],
            })
        elif action == "checkin":
            if cur["status"] not in ("Approved", "Pending"):
                return jsonify(error="Cannot check in from current status."), 400
            if cur["status"] == "Pending" and not is_adm and gate_scope_for(who) != "security":
                conn.execute("UPDATE visitor_passes SET status='Checked In', approved_by=%s, approved_at=COALESCE(approved_at,now()), checked_in_at=now(), decision_note=%s, updated_at=now() WHERE id=%s", (actor, note or cur["decisionNote"], visitor_id))
            else:
                conn.execute("UPDATE visitor_passes SET status='Checked In', checked_in_at=now(), decision_note=COALESCE(NULLIF(%s,''), decision_note), updated_at=now() WHERE id=%s", (note, visitor_id))
        else:
            conn.execute("UPDATE visitor_passes SET status='Checked Out', checked_out_at=now(), updated_at=now() WHERE id=%s", (visitor_id,))
        updated = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s", (visitor_id,)).fetchone()
        _pg_emit_notify(conn, "visitor", {"action": action, "id": visitor_id, "status": updated[16]})
    return jsonify(ok=True, visitor=_visitor_json(updated, include_private=True))


@app.delete("/api/visitors/<path:visitor_id>")
@signed_in
def delete_visitor(visitor_id):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not is_gate_security_or_admin(who):
        return jsonify(error="Administrator or Security Incharge access required."), 403
    with db() as conn:
        row = conn.execute("DELETE FROM visitor_passes WHERE id=%s RETURNING id_card_photo, selfie_photo", (visitor_id,)).fetchone()
        if not row:
            abort(404)
        for rel in row:
            if rel:
                try:
                    p = (UPLOAD_DIR / rel).resolve()
                    if p.is_relative_to((UPLOAD_DIR / "visitors").resolve()):
                        p.unlink(missing_ok=True)
                except Exception:
                    pass
        _pg_emit_notify(conn, "visitor", {"action": "delete", "id": visitor_id})
    return jsonify(ok=True)


@app.get("/api/public/gate-passes")
def list_public_gate_passes():
    sql_where, params = _build_gate_where(request.args)
    q = str(request.args.get("q") or "").strip().lower()
    tok_map = _token_map_from_request()
    with db() as conn:
        rows = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes {sql_where} ORDER BY created_at DESC LIMIT 120", params).fetchall()
    out = []
    for r in rows:
        cand_tok = tok_map.get(r[0], "")
        matched_tok = cand_tok if (cand_tok and hashlib.sha256(cand_tok.encode()).hexdigest() == r[1]) else ""
        item = _gatepass_json(r, include_private=False, public_token=matched_tok)
        if q and q not in " ".join([item["id"], item["materialName"], item["materialType"], item["partyName"], item["challanNo"], item["department"], item["forName"], item["factory"], item["vehicleNo"]]).lower():
            continue
        out.append(item)
    return jsonify(passes=out)


@app.post("/api/public/gate-passes")
def create_public_gate_pass():
    return _create_gatepass_impl(is_public=True)


def _create_gatepass_impl(is_public=True):
    is_multi = bool(request.content_type and "multipart/form-data" in request.content_type)
    body = request.form if is_multi else (request.get_json(silent=True) or {})
    direction = "OUT" if str(body.get("direction") or "").strip().upper() == "OUT" else "IN"
    factory = str(body.get("factory") or "").strip()[:80]
    material_type = str(body.get("materialType") or "").strip()[:80]
    material_name = str(body.get("materialName") or "").strip()[:200]
    quantity = str(body.get("quantity") or "").strip()[:40]
    unit = str(body.get("unit") or "Pcs").strip()[:24] or "Pcs"
    returnable = str(body.get("returnable") or "").strip().lower() in ("1", "true", "yes", "on")
    party_name = str(body.get("partyName") or "").strip()[:140]
    challan_no = str(body.get("challanNo") or "").strip()[:80]
    vehicle_no = str(body.get("vehicleNo") or "").strip()[:40]
    remarks = str(body.get("remarks") or "").strip()[:400]
    department = str(body.get("department") or "").strip()[:120]
    emp_key = str(body.get("employee") or body.get("forUsername") or "").strip()[:140]
    for_manual = str(body.get("forName") or "").strip()[:120]
    entered_by = str(body.get("enteredBy") or ("Security Gate" if is_public else (session.get("profile") or {}).get("name") or "User")).strip()[:80]
    if not factory or not material_type or not material_name or not department:
        return jsonify(error="Select Factory, Material Type, Material Name, and Department."), 400
    tracking_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
    init_status = "Dispatched" if direction == "OUT" and not returnable else "Logged"
    with db() as conn:
        if is_public:
            recent = conn.execute("SELECT count(*) FROM material_gate_passes WHERE created_at > now() - interval '10 minutes'").fetchone()[0]
            if recent >= 60:
                return jsonify(error="Too many material entries submitted in 10 minutes."), 429
        for_username, for_name = _resolve_portal_employee(conn, factory, department, emp_key, fallback_name=for_manual)
        if not for_name:
            for_name = department + " Team"
        gid, _ = _next_gate_id(conn, "material_gate_passes", "MOUT" if direction == "OUT" else "MIN")
        mat_file = request.files.get("materialPhoto") if is_multi else None
        bill_file = request.files.get("billPhoto") if is_multi else None
        mat_rel, err1 = _save_gate_image(mat_file, body.get("materialDataUrl"), "gatepass", gid, "material")
        if err1:
            return jsonify(error=err1), 400
        bill_rel, err2 = _save_gate_image(bill_file, body.get("billDataUrl"), "gatepass", gid, "bill")
        if err2:
            return jsonify(error=err2), 400
        conn.execute(
            "INSERT INTO material_gate_passes(id,tracking_token_hash,direction,factory,material_type,material_name,quantity,unit,returnable,party_name,challan_no,vehicle_no,remarks,department,for_username,for_name,material_photo,bill_photo,status,entered_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (gid, token_hash, direction, factory, material_type, material_name, quantity, unit, returnable, party_name, challan_no, vehicle_no, remarks, department, for_username, for_name, mat_rel, bill_rel, init_status, entered_by),
        )
        dir_word = "Outward (OUT)" if direction == "OUT" else "Inward (IN)"
        _record_notification_event(conn, {
            "eventKey": f"gatepass:{gid}",
            "kind": "gatepass",
            "level": "info",
            "title": f"Material {dir_word}: {material_name} ({gid})",
            "body": f"For {for_name} ({department} · {factory}){' · Challan ' + challan_no if challan_no else ''}",
            "factory": factory,
            "targetView": "gatepass",
            "targetTab": direction,
            "targetId": gid,
            "targetDepartment": department,
            "targetUsername": for_username,
            "targetHostName": for_name,
        })
        _pg_emit_notify(conn, "gatepass", {"action": "create", "id": gid, "direction": direction, "forUsername": for_username})
        created = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s", (gid,)).fetchone()
    return jsonify(ok=True, id=gid, tracking_token=tracking_token, gatePass=_gatepass_json(created, include_private=not is_public, public_token=tracking_token if is_public else "")), 201


@app.get("/api/gate-passes")
@signed_in
def list_gate_passes():
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    if not is_adm and not module_access(who, "gatepass"):
        abort(403)
    sql_where, params = _build_gate_where(request.args)
    q = str(request.args.get("q") or "").strip().lower()
    with db() as conn:
        rows = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes {sql_where} ORDER BY created_at DESC LIMIT 500", params).fetchall()
    out = []
    for r in rows:
        item = _gatepass_json(r, include_private=True)
        if not gatepass_row_visible(item, who, is_adm):
            continue
        if q and q not in " ".join([item["id"], item["materialName"], item["materialType"], item["partyName"], item["challanNo"], item["department"], item["forName"], item["factory"], item["vehicleNo"], item["remarks"]]).lower():
            continue
        out.append(item)
    return jsonify(passes=out, gateScope=gate_scope_for(who), canWrite=is_adm or module_access(who, "gatepass", write=True))


@app.post("/api/gate-passes")
@signed_in
def create_gatepass_signed_in():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "gatepass", write=True):
        return jsonify(error="Write permission for Material Gate Pass is required."), 403
    return _create_gatepass_impl(is_public=False)


@app.post("/api/gate-passes/<path:pass_id>/status")
@signed_in
def update_gatepass_status(pass_id):
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    if not is_adm and not module_access(who, "gatepass", write=True):
        return jsonify(error="Write permission for Material Gate Pass is required."), 403
    body = request.get_json(silent=True) or {}
    new_st = str(body.get("status") or "Verified").strip()
    if new_st not in GATEPASS_STATUSES:
        return jsonify(error="Invalid status."), 400
    actor = str(who.get("name") or who.get("username") or "User")[:120]
    with db() as conn:
        row = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s FOR UPDATE", (pass_id,)).fetchone()
        if not row:
            return jsonify(error="Material gate pass not found."), 404
        cur = _gatepass_json(row, include_private=True)
        if not gatepass_row_visible(cur, who, is_adm):
            return jsonify(error="You can only update material entries assigned to you or your scope."), 403
        conn.execute("UPDATE material_gate_passes SET status=%s, verified_by=%s, verified_at=now(), updated_at=now() WHERE id=%s", (new_st, actor, pass_id))
        updated = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s", (pass_id,)).fetchone()
        _pg_emit_notify(conn, "gatepass", {"action": "status", "id": pass_id, "status": new_st})
    return jsonify(ok=True, gatePass=_gatepass_json(updated, include_private=True))


@app.delete("/api/gate-passes/<path:pass_id>")
@signed_in
def delete_gatepass(pass_id):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not is_gate_security_or_admin(who):
        return jsonify(error="Administrator or Security Incharge access required."), 403
    with db() as conn:
        row = conn.execute("DELETE FROM material_gate_passes WHERE id=%s RETURNING material_photo, bill_photo", (pass_id,)).fetchone()
        if not row:
            abort(404)
        for rel in row:
            if rel:
                try:
                    p = (UPLOAD_DIR / rel).resolve()
                    if p.is_relative_to((UPLOAD_DIR / "gatepass").resolve()):
                        p.unlink(missing_ok=True)
                except Exception:
                    pass
        _pg_emit_notify(conn, "gatepass", {"action": "delete", "id": pass_id})
    return jsonify(ok=True)


@app.errorhandler(413)
def too_large(_):
    limit = "1 GB" if request.path == "/api/backups/restore" else "64 MB"
    return jsonify(error=f"Request too large (maximum {limit})"), 413


init_db()
