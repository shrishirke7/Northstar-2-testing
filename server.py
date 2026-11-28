import json
import gzip
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
import smtplib
from email.message import EmailMessage
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None
import socket
import ssl
import math
import zipfile
import csv
import html
import io
import plistlib
import mimetypes
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request as URLRequest, urlopen
from urllib.error import URLError, HTTPError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import psycopg
from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", ROOT / "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
FIRMWARE_UPLOAD_DIR = UPLOAD_DIR / "firmware"
FIRMWARE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
VAULT_DOCS_DIR = UPLOAD_DIR / "vault_docs"
VAULT_DOCS_DIR.mkdir(parents=True, exist_ok=True)
MSG_UPLOAD_DIR = UPLOAD_DIR / "messages"
MSG_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
TASK_UPLOAD_DIR = UPLOAD_DIR / "tasks"
TASK_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
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
SESSION_IDLE_MINUTES = max(5, int(os.getenv("SESSION_IDLE_MINUTES", "480")))
SESSION_MAX_HOURS = max(1, int(os.getenv("SESSION_MAX_HOURS", "24")))
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
    request.max_content_length = 1024 * 1024 * 1024 if request.path == "/api/backups/restore" else (256 * 1024 * 1024 if request.path.startswith("/api/firmware-backups") else 64 * 1024 * 1024)
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
    "overview", "assets", "data_center", "surveillance", "tickets", "tasks",
    "visitors", "gatepass",
    "maintenance", "ageing", "parts", "users", "departments", "factories",
    "software", "firmware", "credentials", "network", "snmp", "notifications", "reports", "valuation", "billing",
)
MODULE_DATA_KEYS = {
    "overview": ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "invoices"),
    "assets": ("assets", "departments", "ip_mappings"),
    "data_center": ("assets", "camera_streams", "camera_profiles"),
    "surveillance": ("assets", "camera_streams", "camera_profiles"),
    "tickets": ("departments", "ip_mappings"),
    "tasks": ("departments", "manual_users"),
    "visitors": ("departments", "manual_users"),
    "gatepass": ("departments", "manual_users"),
    "maintenance": ("assets", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "departments"),
    "ageing": ("assets", "maintenance"),
    "parts": ("assets", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "departments"),
    "users": ("manual_users", "departments", "ip_mappings"),
    "departments": ("departments", "assets", "manual_users", "maintenance", "parts_assignments", "ip_mappings"),
    "factories": ("departments", "assets", "manual_users", "ip_mappings"),
    "software": ("software", "assets", "departments", "manual_users"),
    "firmware": ("assets", "departments", "software"),
    "credentials": ("assets", "departments"),
    "network": ("assets", "network_ranges", "network_scan", "scanner_heartbeat", "scanner_ip_status", "ip_mappings"),
    "snmp": ("assets",),
    "notifications": ("notifications",),
    "reports": ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "invoices", "vendors", "ip_mappings"),
    "valuation": ("assets", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "invoices"),
    "billing": ("invoices", "vendors", "departments", "manual_users"),
}
MODULE_API_PATHS = {
    "/api/invoices": "billing", "/api/tickets": "tickets", "/api/tasks": "tasks",
    "/api/assets": "assets",
    "/api/visitors": "visitors", "/api/gate-passes": "gatepass",
    "/api/firmware-backups": "firmware", "/api/vault": "credentials",
    "/api/camera-profiles": "surveillance", "/api/camera-streams": "surveillance",
    "/api/cctv-media-auth": "surveillance",
    "/api/network-scans": "network", "/api/network-scan": "network",
    "/api/network-map": "network",
    "/api/notifications": "notifications",
    "/api/snmp-metrics": "snmp", "/api/snmp-monitors": "snmp", "/api/admin/snmp-monitors": "snmp",
}

_VAULT_LOCK = threading.Lock()
_VAULT_SESSIONS = {}
_VAULT_BOOT_KEY_PATH = Path(tempfile.gettempdir()) / ".ns_vault_boot.key"


def _vault_boot_key():
    for _ in range(5):
        if _VAULT_BOOT_KEY_PATH.exists():
            raw = _VAULT_BOOT_KEY_PATH.read_bytes()
            if len(raw) == 32:
                return raw
        try:
            fd = os.open(str(_VAULT_BOOT_KEY_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            key = os.urandom(32)
            try:
                os.write(fd, key)
            finally:
                os.close(fd)
            return key
        except FileExistsError:
            time.sleep(0.02)
    return hashlib.sha256((APP_SECRET + "|fallback-boot").encode("utf-8")).digest()


def _vault_session_wrap_key():
    return hashlib.sha256(_vault_boot_key() + b"|" + APP_SECRET.encode("utf-8")).digest()


def _vault_purge_session(sid=None, username=None, conn=None):
    with _VAULT_LOCK:
        if sid is None and username is None:
            _VAULT_SESSIONS.clear()
        else:
            if sid:
                _VAULT_SESSIONS.pop(str(sid), None)
            if username:
                uname_low = str(username).strip().casefold()
                stale = [k for k, v in _VAULT_SESSIONS.items() if str(v.get("username", "")).strip().casefold() == uname_low]
                for k in stale:
                    _VAULT_SESSIONS.pop(k, None)
    try:
        def _run_del(c):
            if sid is None and username is None:
                c.execute("DELETE FROM vault_active_sessions")
            elif sid and username:
                c.execute("DELETE FROM vault_active_sessions WHERE sid=%s OR lower(username)=lower(%s)", (str(sid), str(username)))
            elif sid:
                c.execute("DELETE FROM vault_active_sessions WHERE sid=%s", (str(sid),))
            elif username:
                c.execute("DELETE FROM vault_active_sessions WHERE lower(username)=lower(%s)", (str(username),))
        if conn is not None:
            _run_del(conn)
        else:
            with db() as c:
                _run_del(c)
    except Exception:
        pass


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
    if key == "ip_mappings": return "assets"
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
        conn.execute("INSERT INTO app_state(key,value) VALUES('assets','[]'),('ip_mappings','[]'),('software','[]'),('departments','[]'),('maintenance','[]'),('parts_catalog','[]'),('parts_inventory','[]'),('parts_stock_entries','[]'),('parts_assignments','[]'),('invoices','[]'),('vendors','[]'),('manual_users','[]'),('camera_streams','[]'),('camera_profiles','[]'),('network_ranges','[]'),('network_scan','{}'),('scanner_heartbeat','{}'),('scanner_ip_status','{}'),('settings','{}'),('profile_preferences','{}'),('notifications','{\"rules\":[],\"queue\":[]}'),('workspace_tasks','{\"tasks\":[],\"rev\":0}') ON CONFLICT(key) DO NOTHING")


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
        if hasattr(session, "modified"):
            session.modified = True
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
    ) or (path == "/api/notifications/sounds" and method == "GET") or (path in ("/api/tickets/admin-presence", "/api/tickets/user-notifications", "/api/tickets/status-reminders") and method == "GET") or (path == "/api/tickets/status-reminders/me" and method in ("GET", "PUT")) or (path == "/api/tickets/status-reminders/check" and method in ("GET", "POST")) or (path == "/api/tickets" and method in ("GET", "POST")) or (path.startswith("/api/tickets/") and path.endswith("/return") and method == "POST") or (path.startswith("/api/tickets/") and (path.endswith("/worklog") or "/attachments/" in path) and method == "GET") or path == "/api/messages" or path.startswith("/api/messages/") or path.startswith("/api/recovery/"):
        return None
    is_write = method in ("POST", "PUT", "PATCH", "DELETE")
    module = next((value for prefix, value in MODULE_API_PATHS.items() if path == prefix or path.startswith(prefix + "/")), None)
    if path.startswith("/api/admin/"):
        # Administration endpoints remain administrator-only.
        return jsonify(error="Administrator access is required."), 403
    if path == "/api/backups" or path.startswith("/api/backups/"):
        return jsonify(error="Administrator access is required."), 403
    if path.startswith("/api/invoices") and not is_write:
        if any(module_access(profile, m) for m in ("billing", "valuation", "departments", "reports", "assets", "parts", "data_center", "surveillance", "overview")):
            return None
    if path.startswith("/api/invoices") and method in ("POST", "PUT"):
        if module_access(profile, "billing", write=True) or module_access(profile, "assets", write=True) or module_access(profile, "parts", write=True):
            return None
    if path.startswith("/api/assets/") and "/files/" in path and not is_write:
        if any(module_access(profile, m) for m in ("assets", "data_center", "surveillance", "overview", "maintenance", "billing", "reports")):
            return None
    if path.startswith("/api/parts/entries/") and "/files/" in path and not is_write:
        if any(module_access(profile, m) for m in ("parts", "billing", "valuation", "reports", "maintenance", "overview")):
            return None
    if path.startswith(("/api/camera-streams", "/api/camera-profiles", "/api/cctv-media-auth")):
        if module_access(profile, "surveillance", write=is_write) or module_access(profile, "data_center", write=is_write):
            return None
    if path == "/api/snmp-metrics" and not is_write:
        if any(module_access(profile, m) for m in ("snmp", "overview", "network")):
            return None
    if (
        path in (
            "/api/vault/unlock",
            "/api/vault/unlock-voice",
            "/api/vault/lock",
            "/api/vault/capture-alert",
            "/api/vault/config",
            "/api/vault/share-targets",
        )
        or (path.startswith("/api/vault/documents/") and path.endswith("/download"))
        or (request.method == "PUT" and (path.startswith("/api/vault/credentials/") or path.startswith("/api/vault/documents/")))
    ):
        if not module_access(profile, "credentials", write=False):
            return jsonify(error="You do not have access to this module."), 403
        return None
    if path == "/api/tasks/reminders/check" and method in ("GET", "POST"):
        if not module_access(profile, "tasks", write=False):
            return jsonify(error="You do not have access to this module."), 403
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
    try:
        ae = str(request.headers.get("Accept-Encoding") or "").lower()
        ct = str(getattr(response, "mimetype", "") or "").lower()
        compressible = ct in ("text/html", "application/json", "application/javascript", "text/javascript", "text/css", "image/svg+xml")
        if "gzip" in ae and getattr(response, "status_code", 200) == 200 and compressible and "Content-Encoding" not in response.headers:
            if getattr(response, "direct_passthrough", False):
                if request.path in ("/", "/index.html", "/portal", "/portal.html", "/cctv-live.js", "/sw.js", "/manifest.json"):
                    response.direct_passthrough = False
                else:
                    return response
            raw_body = response.get_data()
            if isinstance(raw_body, (bytes, bytearray)) and len(raw_body) >= 1024:
                gz_body = gzip.compress(raw_body, compresslevel=5)
                if len(gz_body) < len(raw_body):
                    response.set_data(gz_body)
                    response.headers["Content-Encoding"] = "gzip"
                    response.headers["Content-Length"] = str(len(gz_body))
                    vary = str(response.headers.get("Vary") or "")
                    if "accept-encoding" not in vary.lower():
                        response.headers["Vary"] = (vary + ", Accept-Encoding").strip(", ")
    except Exception:
        pass
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
            _pg_emit_notify(conn, "pulse", {"source": "settings"})
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


MAX_NETWORK_SCAN_HOSTS = 262144  # Supports /16 through /32 CIDRs (up to 4 x /16 networks combined)

_SRV_EMBEDDED_OUI = {
    "000c29": "VMware", "005056": "VMware", "000569": "VMware",
    "00155d": "Microsoft Hyper-V", "525400": "QEMU / KVM", "080027": "Oracle VirtualBox",
    "001b21": "Intel", "001e67": "Intel", "3c970e": "Intel", "8086f2": "Intel", "a4bf01": "Intel",
    "d4bed9": "Dell", "001422": "Dell", "180373": "Dell", "24b6fd": "Dell", "549f35": "Dell", "b083fe": "Dell", "f8bc12": "Dell", "00219b": "Dell",
    "001b78": "Hewlett Packard", "0025b3": "Hewlett Packard", "3c4a92": "Hewlett Packard Enterprise", "9457a5": "Hewlett Packard",
    "d4c9ef": "HP", "ec9a74": "HP", "0001e6": "HP", "00215a": "HP",
    "000b86": "Aruba / HPE", "204c03": "Aruba / HPE", "24de9a": "Aruba / HPE", "94b40f": "Aruba / HPE", "ac1702": "Aruba / HPE", "d8c7c8": "Aruba / HPE",
    "001122": "Cisco", "000e83": "Cisco", "001bd5": "Cisco", "0026cb": "Cisco", "68bc0c": "Cisco", "f4cfe2": "Cisco",
    "001a8c": "Sophos", "005018": "Sophos", "c84f86": "Sophos", "7c5a1c": "Sophos",
    "00090f": "Fortinet", "085b0e": "Fortinet", "704ca5": "Fortinet", "906cac": "Fortinet",
    "18e829": "Ubiquiti", "24a43c": "Ubiquiti", "44d9e7": "Ubiquiti", "7483c2": "Ubiquiti", "802aa8": "Ubiquiti", "b4fbe4": "Ubiquiti", "dc9fdb": "Ubiquiti", "fcecda": "Ubiquiti",
    "000c42": "MikroTik", "4c5e0c": "MikroTik", "64d154": "MikroTik", "d4ca6d": "MikroTik", "dc2c6e": "MikroTik", "b869f4": "MikroTik",
    "14cc20": "TP-Link", "50c7bf": "TP-Link", "60e327": "TP-Link", "98dac4": "TP-Link", "b0be76": "TP-Link", "c025e9": "TP-Link", "d807b6": "TP-Link", "e8de27": "TP-Link",
    "000d88": "D-Link", "1c7ee5": "D-Link", "28107b": "D-Link", "c8d3a3": "D-Link",
    "00095b": "Netgear", "204e7f": "Netgear", "a021b7": "Netgear", "c03f0e": "Netgear",
    "001132": "Synology", "0011d8": "Synology", "245ebe": "QNAP",
    "1868cb": "Hikvision", "2857be": "Hikvision", "4419b6": "Hikvision", "4cbd8f": "Hikvision", "54c415": "Hikvision", "8ce748": "Hikvision", "a41437": "Hikvision", "c056e3": "Hikvision", "c42f90": "Hikvision",
    "14a78b": "Dahua", "3cef8c": "Dahua", "4c11bf": "Dahua", "9002a9": "Dahua", "a0bd1d": "Dahua", "e0508b": "Dahua",
    "48ea63": "Uniview (UNV)", "6cf17e": "Uniview (UNV)", "c47905": "Uniview (UNV)",
    "00408c": "Axis", "accc8e": "Axis", "b8a44f": "Axis",
    "00105a": "Lenovo", "00215c": "Lenovo", "28d244": "Lenovo", "503eaa": "Lenovo", "98fa9b": "Lenovo", "c85b76": "Lenovo",
    "001e8c": "ASUS", "1c872c": "ASUS", "2c4d54": "ASUS", "38d547": "ASUS", "d850e6": "ASUS",
    "0013d4": "Realtek", "00e04c": "Realtek", "485b39": "Realtek", "52544c": "Realtek", "98e7f4": "Realtek",
    "001f81": "Canon", "000085": "Canon", "180cac": "Canon", "f48139": "Canon",
    "000048": "Epson", "0026ab": "Epson", "44d244": "Epson", "64eb8c": "Epson",
    "001ba9": "Brother", "008077": "Brother", "30055c": "Brother", "b42200": "Brother",
    "000074": "Ricoh", "002673": "Ricoh", "001599": "Samsung", "0000f0": "Samsung",
    "002590": "Supermicro", "0cc47a": "Supermicro", "3cecef": "Supermicro", "ac1f6b": "Supermicro",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi", "28cdc1": "Raspberry Pi",
    "000393": "Apple", "3c0754": "Apple", "a45e60": "Apple", "f01898": "Apple",
}
_SRV_OUI_CACHE = None


def _lookup_mac_vendor(mac):
    global _SRV_OUI_CACHE
    if _SRV_OUI_CACHE is None:
        cache = dict(_SRV_EMBEDDED_OUI)
        for p in ("/usr/share/ieee-data/oui.txt", "/usr/share/arp-scan/ieee-oui.txt", "/usr/share/misc/oui.txt"):
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            m1 = re.match(r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s*\(hex\)\s+(.+)$", line.strip())
                            if m1:
                                px = re.sub(r"[^0-9a-f]", "", m1.group(1).lower())
                                if len(px) == 6 and m1.group(2).strip():
                                    cache.setdefault(px, m1.group(2).strip()[:80])
                            else:
                                m2 = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line.strip())
                                if m2 and m2.group(2).strip():
                                    cache.setdefault(m2.group(1).lower(), m2.group(2).strip()[:80])
                except OSError:
                    pass
        _SRV_OUI_CACHE = cache
    cleaned = re.sub(r"[^0-9a-f]", "", str(mac or "").lower())
    return _SRV_OUI_CACHE.get(cleaned[:6], "") if len(cleaned) >= 6 else ""


def _network_usable_hosts(network):
    return network.num_addresses - (2 if network.prefixlen < 31 else 0)


def _suggest_vlan_cidrs(conn, saved_nets, host_subnets):
    suggested = []
    seen = set(saved_nets)
    cand_strs = list(host_subnets or [])
    for key in ("assets", "manual_users"):
        rows = (conn.execute("SELECT value FROM app_state WHERE key=%s", (key,)).fetchone() or ([],))[0]
        if not isinstance(rows, list):
            continue
        for item in rows:
            if not isinstance(item, dict):
                continue
            vals = [item.get("ipAddress"), item.get("ip_address")]
            for nif in (item.get("networkInterfaces") if isinstance(item.get("networkInterfaces"), list) else []):
                if isinstance(nif, dict):
                    vals.extend([nif.get("ipAddress"), nif.get("ip_address"), nif.get("ip")])
            for v in vals:
                s = str(v or "").strip()
                if s:
                    cand_strs.append(s)
    for raw in cand_strs:
        try:
            if "/" in raw:
                n = ipaddress.ip_network(raw, strict=False)
            else:
                ip = ipaddress.ip_address(raw)
                if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
                    continue
                n = ipaddress.ip_network(f"{ip}/24", strict=False)
            if n.version != 4 or not n.is_private or n.is_loopback or n.is_link_local:
                continue
            if not any(n.subnet_of(s) for s in seen):
                seen.add(n)
                suggested.append(str(n))
        except ValueError:
            continue
    suggested.sort(key=lambda x: tuple(int(p) for p in x.split("/")[0].split(".")))
    return suggested[:64]


@app.get("/api/network-scans")
@signed_in
def network_scans():
    with db() as conn:
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        saved = (conn.execute("SELECT value FROM app_state WHERE key='network_scan'").fetchone() or ({},))[0]
        heartbeat = (conn.execute("SELECT value FROM app_state WHERE key='scanner_heartbeat'").fetchone() or ({},))[0]
        col_row = (conn.execute("SELECT value FROM app_state WHERE key='network_collectors'").fetchone() or ({},))[0]
        col_cfg = col_row if isinstance(col_row, dict) else {}
        snmp_hosts = [str(m.get("host") or "").strip() for m in _snmp_rows(conn) if isinstance(m, dict) and m.get("host")]
        nets = _parse_authorized_networks(ranges)
        host_subnets = heartbeat.get("hostSubnets") if isinstance(heartbeat.get("hostSubnets"), list) else []
        suggested_ranges = _suggest_vlan_cidrs(conn, nets, host_subnets)
    with NETWORK_SCAN_LOCK:
        state = dict(NETWORK_SCAN_STATE)
    if saved:
        state = saved
    if state.get("status") == "running" and state.get("started_at"):
        try:
            started = datetime.fromisoformat(state["started_at"])
            if (datetime.now(timezone.utc) - started).total_seconds() > 3600:
                state.update(status="failed", error="Scan stopped unexpectedly; start a new scan.", finished_at=datetime.now(timezone.utc).isoformat())
                _persist_network_scan(state, state.get("id", ""))
        except (ValueError, TypeError):
            pass
    last_seen = heartbeat.get('last_seen', '')
    try:
        scanner_connected = bool(last_seen) and (datetime.now(timezone.utc) - datetime.fromisoformat(last_seen)).total_seconds() <= 30
    except (ValueError, TypeError):
        scanner_connected = False
    host_count = sum(_network_usable_hosts(n) for n in nets)
    return jsonify(
        ranges=ranges,
        hostCount=host_count,
        scan=state,
        scannerConnected=scanner_connected,
        hostSubnets=host_subnets,
        gateway=str(heartbeat.get("gateway") or ""),
        suggestedRanges=suggested_ranges,
        collectors={
            "collectorHosts": col_cfg.get("collectorHosts") if isinstance(col_cfg.get("collectorHosts"), list) else [],
            "snmpCommunity": str(col_cfg.get("snmpCommunity") or ""),
            "snmpV3Hosts": snmp_hosts,
        },
        serverNow=datetime.now(timezone.utc).isoformat(),
    )


@app.put("/api/network-scan/collectors")
@app.put("/api/admin/network-scan/collectors")
@signed_in
def save_network_scan_collectors():
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "network", write=True):
        abort(403)
    body = request.get_json(silent=True) or {}
    raw_hosts = body.get("collectorHosts") if isinstance(body.get("collectorHosts"), list) else []
    clean_hosts = []
    for raw_h in raw_hosts[:24]:
        txt = str(raw_h or "").strip()
        if not txt:
            continue
        try:
            ip = ipaddress.ip_address(txt)
        except ValueError:
            return jsonify(error=f"Invalid collector IPv4 address: {txt[:40]}"), 400
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
            return jsonify(error=f"Collector IP must be a private IPv4 address: {txt[:40]}"), 400
        if str(ip) not in clean_hosts:
            clean_hosts.append(str(ip))
    comm = str(body.get("snmpCommunity") or "").strip()[:64]
    if comm and not re.fullmatch(r"[A-Za-z0-9._@#$%^&+=!-]{1,64}", comm):
        return jsonify(error="SNMP community string contains unsupported characters."), 400
    cfg = {"collectorHosts": clean_hosts, "snmpCommunity": comm}
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_collectors',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(cfg),))
    return jsonify(ok=True, collectors=cfg)


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
        text = str(value).strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return jsonify(error=f"Invalid network range: {value}"), 400
        if network.version != 4 or not network.is_private or network.is_loopback or network.is_link_local or network.prefixlen < 16 or network.num_addresses > 65536:
            return jsonify(error="Only private IPv4 CIDR ranges from /16 to /32 (e.g. /24, /23, /22, /21, /20, /19, /18, /17, /16) can be saved"), 400
        if network not in networks:
            networks.append(network)
    hosts_count = sum(_network_usable_hosts(n) for n in networks)
    if hosts_count > MAX_NETWORK_SCAN_HOSTS:
        return jsonify(error=f"Combined address limit is {MAX_NETWORK_SCAN_HOSTS:,} hosts across saved CIDRs"), 400
    values = [str(n) for n in networks]
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_ranges',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(values),))
        # Reset cooldown so the host scanner immediately re-pings known devices in these saved ranges.
        conn.execute("INSERT INTO app_state(key,value) VALUES('scanner_ip_status',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps({}),))
        _pg_emit_notify(conn, "pulse", {"source": "network_ranges", "count": len(values)})
    return jsonify(ok=True, ranges=values, hostCount=hosts_count)


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
    networks = _parse_authorized_networks(raw)
    hosts_count = sum(_network_usable_hosts(n) for n in networks)
    if hosts_count > MAX_NETWORK_SCAN_HOSTS:
        return jsonify(error=f"Combined scan limit is {MAX_NETWORK_SCAN_HOSTS:,} addresses (supports /16 through /32 CIDRs)."), 400
    with db() as conn:
        current = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        prior = current[0] if current else {}
        if prior.get("status") == "running" and prior.get("started_at"):
            try:
                recent = (datetime.now(timezone.utc) - datetime.fromisoformat(prior["started_at"])).total_seconds() < 3600
            except (ValueError, TypeError):
                recent = False
            if recent:
                return jsonify(error="A network scan is already running"), 409
        scan_id = str(uuid.uuid4())
        NETWORK_SCAN_STATE = {"id":scan_id,"status":"queued","progress":0,"total":hosts_count,"results":[],"error":"","started_at":datetime.now(timezone.utc).isoformat(),"finished_at":""}
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_scan',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(NETWORK_SCAN_STATE),))
    return jsonify(ok=True, scan_id=scan_id, total=hosts_count), 202


@app.post("/api/network-scan/cancel")
@app.post("/api/admin/network-scan/cancel")
@signed_in
def cancel_network_scan():
    global NETWORK_SCAN_STATE
    if not session.get("is_admin") and not module_access(session.get("profile", {}), "network", write=True):
        abort(403)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        state = dict(row[0]) if row and isinstance(row[0], dict) else {}
        if state.get("status") in ("queued", "running"):
            state["status"] = "failed" if not state.get("results") else "completed"
            state["error"] = "Scan stopped by user."
            state["finished_at"] = datetime.now(timezone.utc).isoformat()
            NETWORK_SCAN_STATE = state
            conn.execute("INSERT INTO app_state(key,value) VALUES('network_scan',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
    return jsonify(ok=True, scan=state)


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
    user_rules_map = state.get("userRules") if isinstance(state.get("userRules"), dict) else None
    rules_iter = []
    if user_rules_map is not None:
        for owner_u, rlist in user_rules_map.items():
            if isinstance(rlist, list):
                for r in rlist:
                    if isinstance(r, dict):
                        rules_iter.append((str(owner_u or ""), r))
    else:
        for r in state.get("rules", []):
            if isinstance(r, dict):
                rules_iter.append(("", r))
    for owner_u, rule in rules_iter:
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
                    "ownerUsername": owner_u,
                    "recipientUsername": str(user.get("username") or user.get("id") or "").strip().casefold(),
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
        "visitor": {"enabled": True, "soundId": "builtin:ticket-chime"},
        "gatepass": {"enabled": True, "soundId": "builtin:double-tone"},
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
    "unrespondedAlarm": {
        "enabled": True,
        "thresholdMinutes": 15,
        "soundId": "builtin:urgent-call-ring",
        "repeatSeconds": 6,
    },
}


def normalize_sound_state(state, username=None, is_admin=True, can_manage_tickets=True):
    raw = state if isinstance(state, dict) else {}
    ukey = str(username or "").strip().casefold()
    has_saved_user_cfg = False
    if ukey:
        user_map = raw.get("userSoundAlerts") if isinstance(raw.get("userSoundAlerts"), dict) else {}
        if isinstance(user_map.get(ukey), dict):
            saved_cfg = user_map.get(ukey)
            has_saved_user_cfg = True
        else:
            saved_cfg = {}
    else:
        saved_cfg = raw.get("soundAlerts") if isinstance(raw.get("soundAlerts"), dict) else {}
    merged = json.loads(json.dumps(DEFAULT_SOUND_ALERTS))
    if not is_admin and not has_saved_user_cfg:
        merged["defaultNewTypeSilent"] = True
        for non_tk in ("visitor", "gatepass", "online", "offline", "critical"):
            merged["events"][non_tk]["enabled"] = False
        merged["events"]["ticket"]["enabled"] = True
        merged["unrespondedAlarm"]["enabled"] = bool(can_manage_tickets)
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
    raw_ua = saved_cfg.get("unrespondedAlarm") if isinstance(saved_cfg.get("unrespondedAlarm"), dict) else {}
    if raw_ua:
        if "enabled" in raw_ua:
            merged["unrespondedAlarm"]["enabled"] = bool(raw_ua.get("enabled"))
        try:
            if "thresholdMinutes" in raw_ua:
                merged["unrespondedAlarm"]["thresholdMinutes"] = max(1, min(1440, int(raw_ua.get("thresholdMinutes", 15))))
        except (TypeError, ValueError):
            pass
        if isinstance(raw_ua.get("soundId"), str) and raw_ua.get("soundId").strip():
            merged["unrespondedAlarm"]["soundId"] = raw_ua.get("soundId").strip()[:120]
        try:
            if "repeatSeconds" in raw_ua:
                merged["unrespondedAlarm"]["repeatSeconds"] = max(3, min(120, int(raw_ua.get("repeatSeconds", 6))))
        except (TypeError, ValueError):
            pass
    raw_events = saved_cfg.get("events") if isinstance(saved_cfg.get("events"), dict) else {}
    for ev_key in ("ticket", "visitor", "gatepass", "online", "offline", "critical"):
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
    user_libs = raw.get("userSoundLibraries") if isinstance(raw.get("userSoundLibraries"), dict) else {}
    if ukey and ukey in user_libs and isinstance(user_libs.get(ukey), list):
        lib = user_libs[ukey]
    elif ukey:
        used_ids = {v.get("soundId") for v in merged["events"].values() if isinstance(v, dict) and v.get("soundId")}
        for rv in clean_dev_rules.values():
            used_ids.add(rv.get("onlineSoundId"))
            used_ids.add(rv.get("offlineSoundId"))
        legacy_lib = raw.get("soundLibrary") if isinstance(raw.get("soundLibrary"), list) else []
        lib = [it for it in legacy_lib if isinstance(it, dict) and it.get("id") in used_ids] if used_ids else []
    else:
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
    username_key = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notifications'").fetchone()
        state = row[0] if row else {"rules": [], "queue": []}
        users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
        users = users_row[0] if users_row else []
        asset_row = conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone()
        assets = asset_row[0] if asset_row else []
    user_rules_map = state.get("userRules") if isinstance(state.get("userRules"), dict) else None
    if user_rules_map is not None:
        user_rules = user_rules_map.get(username_key, [])
    elif session.get("is_admin"):
        user_rules = state.get("rules", [])
    else:
        user_rules = []
    if not isinstance(user_rules, list):
        user_rules = []
    history = [
        {k: item.get(k) for k in ("id", "rule", "asset", "tag", "category", "status", "channel", "recipient", "state", "createdAt", "error")}
        for item in state.get("queue", [])[-200:]
        if isinstance(item, dict) and (
            str(item.get("ownerUsername") or "").casefold() == username_key
            or str(item.get("recipientUsername") or "").casefold() == username_key
            or (not item.get("ownerUsername") and session.get("is_admin"))
        )
    ][-100:]
    who_prof = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    can_tk_mgr = is_adm or who_prof.get("role") == "IT Ticketing" or module_access(who_prof, "tickets", write=True)
    sound_alerts, sound_library = normalize_sound_state(state, username=username_key, is_admin=is_adm, can_manage_tickets=can_tk_mgr)
    return jsonify(rules=user_rules, history=history, channels=_notification_channel_status(),
                   soundAlerts=sound_alerts, soundLibrary=sound_library, userScoped=True,
                   users=[{"username": u.get("username") or u.get("id", ""), "name": u.get("name") or u.get("username") or u.get("id", ""), "email": u.get("email", ""), "phone": u.get("phone") or u.get("phone_number", "")} for u in users],
                   assets=[{"tag": a.get("tag", ""), "name": a.get("name", ""), "type": a.get("type", ""), "subtype": a.get("subtype", ""), "site": a.get("site", "")} for a in assets])


@app.get("/api/notifications/sounds")
@signed_in
def get_notification_sounds():
    who_prof = session.get("profile") or {}
    username_key = str(who_prof.get("username") or "").strip().casefold()
    is_adm = bool(session.get("is_admin"))
    can_tk_mgr = is_adm or who_prof.get("role") == "IT Ticketing" or module_access(who_prof, "tickets", write=True)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='notifications'").fetchone()
        state = row[0] if row else {}
    sound_alerts, sound_library = normalize_sound_state(state, username=username_key, is_admin=is_adm, can_manage_tickets=can_tk_mgr)
    return jsonify(soundAlerts=sound_alerts, soundLibrary=sound_library, userScoped=True)


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
        user_libs = dict(state.get("userSoundLibraries") or {}) if isinstance(state.get("userSoundLibraries"), dict) else {}
        if "soundLibrary" in body:
            user_libs[username_key] = sound_library
            state["userSoundLibraries"] = user_libs
        _, out_lib = normalize_sound_state(state, username=username_key)
        conn.execute("INSERT INTO app_state(key,value) VALUES('notifications',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
        _pg_emit_notify(conn, "pulse", {"source": "sounds", "username": username_key})
    return jsonify(ok=True, soundAlerts=sound_alerts, soundLibrary=out_lib, userScoped=True)


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
          (SELECT count(*)::bigint FROM material_gate_passes),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='admin_presence'), '0'),
          COALESCE((SELECT extract(epoch FROM updated_at)::text FROM app_state WHERE key='ticket_user_notifications'), '0'),
          COALESCE((SELECT extract(epoch FROM max(updated_at))::text FROM helpdesk_threads), '0'),
          (SELECT count(*)::bigint FROM helpdesk_messages)
    """).fetchone()
    ticket_rev = f"{row[0]}:{row[1]}:{row[2]}:{row[13]}:{row[14]}"
    visitor_rev = f"{row[9]}:{row[10]}"
    gatepass_rev = f"{row[11]}:{row[12]}"
    messages_rev = f"{row[15] if len(row) > 15 else '0'}:{row[16] if len(row) > 16 else 0}"
    out = {
        "ticketRev": ticket_rev,
        "visitorRev": visitor_rev,
        "gatepassRev": gatepass_rev,
        "messagesRev": messages_rev,
        "settingsRev": str(row[3] or "0"),
        "presenceRev": str(row[13] or "0"),
        "ticketNotifRev": str(row[14] or "0"),
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
        "targetThreadId": str(item.get("targetThreadId") or "")[:120],
        "targetTag": str(item.get("targetTag") or "")[:120],
        "targetIp": str(item.get("targetIp") or "")[:64],
        "deviceType": str(item.get("deviceType") or "")[:60],
        "deviceSubtype": str(item.get("deviceSubtype") or "")[:60],
        "transitionStatus": str(item.get("transitionStatus") or "")[:20],
        "complaintDesk": _slug_desk_id(item.get("complaintDesk") or "it", fallback="it")[:40],
        "targetDepartment": str(item.get("targetDepartment") or "")[:120],
        "targetUsername": str(item.get("targetUsername") or "")[:120],
        "targetHostName": str(item.get("targetHostName") or "")[:120],
        "requesterName": str(item.get("requesterName") or "")[:120],
        "targetRole": str(item.get("targetRole") or "")[:24],
        "targetAssignee": str(item.get("targetAssignee") or "")[:120],
        "targetTicketId": str(item.get("targetTicketId") or "")[:120],
        "targetUsers": [str(u).strip().casefold() for u in (item.get("targetUsers") or []) if str(u).strip()][:60],
        "targetDepartments": [str(d).strip()[:120] for d in (item.get("targetDepartments") or []) if str(d).strip()][:30],
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
    uname_cf = str(who.get("username") or "").strip().casefold()
    dname_cf = str(who.get("name") or "").strip().casefold()
    can_tickets = is_adm or who.get("role") == "IT Ticketing" or module_access(who, "tickets", write=True) or (module_access(who, "tickets") and isinstance(who.get("allowed_complaint_desks"), list) and len(who.get("allowed_complaint_desks")) > 0)
    can_tasks = is_adm or module_access(who, "tasks")
    user_depts_set = {str(x or "").strip().casefold() for x in (who.get("dept"), who.get("department")) if str(x or "").strip()}
    can_visitors = is_adm or module_access(who, "visitors")
    can_gatepass = is_adm or module_access(who, "gatepass")
    can_devices = is_adm or module_access(who, "notifications")
    visible = []
    unread_count = 0
    for ev in doc["events"]:
        ev_kind = str(ev.get("kind") or "")
        if ev_kind in ("task", "task_reminder"):
            if not can_tasks:
                continue
            t_users = {str(u or "").strip().casefold() for u in (ev.get("targetUsers") or []) if str(u).strip()}
            for single_u in (ev.get("targetUsername"), ev.get("targetAssignee")):
                su = str(single_u or "").strip().casefold()
                if su:
                    t_users.add(su)
            t_depts = [str(d or "").strip() for d in (ev.get("targetDepartments") or []) if str(d).strip()]
            if ev.get("targetDepartment"):
                t_depts.append(str(ev.get("targetDepartment")).strip())
            in_users = bool(uname_cf and uname_cf in t_users)
            in_depts = any(_dept_matches(user_depts_set, td) for td in t_depts) if user_depts_set and t_depts else False
            if not in_users and not in_depts:
                continue
        elif ev_kind == "helpdesk_message":
            ev_user = str(ev.get("targetUsername") or "").strip().casefold()
            ev_req = str(ev.get("requesterName") or "").strip().casefold()
            ev_exp = str(ev.get("targetAssignee") or "").strip().casefold()
            t_role = str(ev.get("targetRole") or "").strip().lower()
            sec_id = str(ev.get("complaintDesk") or "it").strip().lower()
            is_own_ev = (uname_cf and ev_user and ev_user == uname_cf) or (dname_cf and ev_req and ev_req == dname_cf)
            if t_role == "requester":
                if not is_own_ev:
                    continue
            else:
                can_sec = _helpdesk_caller_can_staff_section(who, is_adm, sec_id)
                if not is_adm and not (uname_cf and ev_exp and ev_exp == uname_cf) and not can_sec:
                    continue
        elif ev_kind == "ticket_reminder":
            ev_user = str(ev.get("targetUsername") or "").strip().casefold()
            if not ev_user or ev_user != uname_cf:
                continue
        elif ev_kind in ("ticket", "material_request"):
            ev_user = str(ev.get("targetUsername") or "").strip().casefold()
            ev_req = str(ev.get("requesterName") or "").strip().casefold()
            t_role = str(ev.get("targetRole") or "").strip().lower()
            is_own_ev = (uname_cf and ev_user and ev_user == uname_cf) or (dname_cf and ev_req and ev_req == dname_cf)
            if t_role == "requester":
                if not is_own_ev:
                    continue
            elif not is_own_ev and (not can_tickets or not ticket_desk_allowed(who, ev.get("complaintDesk") or "it")):
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
    uname_cf = str(who.get("username") or "").strip().casefold()
    dname_cf = str(who.get("name") or "").strip().casefold()
    can_tickets = is_adm or who.get("role") == "IT Ticketing" or module_access(who, "tickets", write=True) or (module_access(who, "tickets") and isinstance(who.get("allowed_complaint_desks"), list) and len(who.get("allowed_complaint_desks")) > 0)
    can_tk_mgr = is_adm or who.get("role") == "IT Ticketing" or module_access(who, "tickets", write=True)
    can_devices = is_adm or module_access(who, "notifications")
    want_tickets = request.args.get("tickets", "1") != "0"
    want_devices = request.args.get("devices", "1") != "0"
    want_sounds = request.args.get("sounds", "0") == "1"
    out = {"latestTickets": [], "deviceStates": [], "serverTime": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with db() as conn:
        if want_sounds:
            notif_row = conn.execute("SELECT value FROM app_state WHERE key='notifications'").fetchone()
            sound_alerts, sound_library = normalize_sound_state(notif_row[0] if notif_row else {}, username=who.get("username"), is_admin=is_adm, can_manage_tickets=can_tk_mgr)
            out["soundAlerts"] = sound_alerts
            out["soundLibrary"] = sound_library
            out["includeSounds"] = bool(sound_library)
        if want_tickets:
            t_rows = conn.execute(
                "SELECT id,kind,display_name,department,factory,primary_category,sub_category,status,created_at,updated_at,COALESCE(NULLIF(complaint_desk,''),'it'),username,assigned_to FROM tickets ORDER BY created_at DESC LIMIT 80"
            ).fetchall()
            filtered_t = []
            for r in t_rows:
                t_uname = str(r[11] or "").strip().casefold()
                t_dname = str(r[2] or "").strip().casefold()
                is_owner = (uname_cf and t_uname == uname_cf) or (dname_cf and t_dname == dname_cf)
                if not is_owner and (not can_tickets or not ticket_desk_allowed(who, r[10] or "it")):
                    continue
                filtered_t.append({
                    "id": r[0], "kind": r[1], "name": r[2], "dept": r[3], "site": r[4], "primary": r[5], "sub": r[6],
                    "status": r[7], "assigned": r[12] or "Unassigned",
                    "created": r[8].isoformat(timespec="seconds") if r[8] else "",
                    "updated": r[9].isoformat(timespec="seconds") if r[9] else "",
                    "complaintDesk": r[10] or "it", "isOwn": is_owner,
                })
                if len(filtered_t) >= 40:
                    break
            out["latestTickets"] = filtered_t
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
        out["serverNow"] = datetime.now(timezone.utc).isoformat()
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
        username_key = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
        current = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
        state = dict(current[0]) if current and isinstance(current[0], dict) else {"rules": [], "queue": []}
        user_rules_map = dict(state.get("userRules") or {}) if isinstance(state.get("userRules"), dict) else {}
        if "userRules" not in state and isinstance(state.get("rules"), list) and state["rules"] and not session.get("is_admin"):
            pass
        for item in clean:
            item["ownerUsername"] = username_key
        user_rules_map[username_key] = clean
        state["userRules"] = user_rules_map
        state["rules"] = []
        conn.execute("INSERT INTO app_state(key,value) VALUES('notifications',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
        _pg_emit_notify(conn, "pulse", {"source": "notifications", "username": username_key})
    return jsonify(ok=True, rules=clean, userScoped=True)


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
        networks = _parse_authorized_networks(ranges)
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


def _parse_authorized_networks(raw_ranges):
    nets = []
    for value in (raw_ranges or []):
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.is_private and not net.is_loopback and not net.is_link_local:
            nets.append(net)
    return nets


def _apply_ip_status_to_records(conn, networks, responsive, checked_at, target_set=None):
    inventory_row = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
    inventory = inventory_row[0] if inventory_row else []
    users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
    users = users_row[0] if users_row else []
    notifications_row = conn.execute("SELECT value FROM app_state WHERE key='notifications' FOR UPDATE").fetchone()
    notifications = notifications_row[0] if notifications_row else {"rules": [], "queue": []}
    queue_size_before = len(notifications.get("queue", []))
    assets_changed = users_changed = False

    def in_scope(raw_ip_str):
        if target_set is not None:
            return raw_ip_str in target_set
        try:
            ip = ipaddress.ip_address(raw_ip_str)
        except ValueError:
            return False
        return ip.version == 4 and ip.is_private and any(ip in net for net in networks)

    for asset in inventory:
        interfaces = asset.get("networkInterfaces")
        if not isinstance(interfaces, list):
            interfaces = []
        checked_ips = set()
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            raw_ip = str(interface.get("ipAddress", interface.get("ip_address", interface.get("ip", "")))).strip()
            if not raw_ip or not in_scope(raw_ip):
                continue
            interface["ipStatus"] = interface["status"] = "Online" if raw_ip in responsive else "Offline"
            interface["ipCheckedAt"] = checked_at
            checked_ips.add(raw_ip)
            if raw_ip in responsive:
                interface["lastSeen"] = checked_at
        primary_ip = str(asset.get("ipAddress", asset.get("ip_address", ""))).strip()
        if primary_ip and in_scope(primary_ip):
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
        if not raw_ip or not in_scope(raw_ip):
            continue
        user["ipStatus"] = "Online" if raw_ip in responsive else "Offline"
        user["ipCheckedAt"] = checked_at
        if raw_ip in responsive:
            user["lastSeen"] = checked_at
        users_changed = True

    if assets_changed:
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='assets'", (json.dumps(inventory),))
        _pg_emit_notify(conn, "asset", {"online": len(responsive)})
    if users_changed:
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    if len(notifications.get("queue", [])) != queue_size_before:
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='notifications'", (json.dumps(notifications),))


@app.post("/api/internal/ip-status-results")
def scanner_ip_status_results():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True)
    task_id = str(body.get("id", ""))
    responsive = set()
    rows = body.get("online", [])
    if not task_id or not isinstance(rows, list) or len(rows) > MAX_NETWORK_SCAN_HOSTS:
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
        networks = _parse_authorized_networks(ranges)
        target_set = set()
        for value in state.get("targets", []):
            try:
                ip = ipaddress.ip_address(value)
                if ip.version == 4 and ip.is_private and any(ip in network for network in networks):
                    target_set.add(str(ip))
            except ValueError:
                continue
        responsive.intersection_update(target_set)
        _apply_ip_status_to_records(conn, networks, responsive, checked_at, target_set=target_set)
        state["finished_at"] = checked_at
        state["online_count"] = len(responsive)
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='scanner_ip_status'", (json.dumps(state),))
    return jsonify(ok=True, online=len(responsive), checked=len(target_set))


@app.post("/api/internal/scanner-heartbeat")
def scanner_heartbeat():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(silent=True) or {}
    clean_subnets = []
    for raw_sub in (body.get("hostSubnets") if isinstance(body.get("hostSubnets"), list) else [])[:32]:
        try:
            net = ipaddress.ip_network(str(raw_sub).strip(), strict=False)
            if net.version == 4 and net.is_private and not net.is_loopback and not net.is_link_local:
                s = str(net)
                if s not in clean_subnets:
                    clean_subnets.append(s)
        except ValueError:
            continue
    gw = ""
    raw_gw = str(body.get("gateway") or "").strip()
    if raw_gw:
        try:
            g_ip = ipaddress.ip_address(raw_gw)
            if g_ip.version == 4 and g_ip.is_private:
                gw = str(g_ip)
        except ValueError:
            gw = ""
    state = {"last_seen": datetime.now(timezone.utc).isoformat(), "hostSubnets": clean_subnets, "gateway": gw}
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
                networks = _parse_authorized_networks(ranges)
                hosts_count = sum(_network_usable_hosts(n) for n in networks)
                if 0 < hosts_count <= MAX_NETWORK_SCAN_HOSTS:
                    state = {"id":str(uuid.uuid4()),"status":"queued","progress":0,"total":hosts_count,"results":[],"error":"","started_at":datetime.now(timezone.utc).isoformat(),"finished_at":""}
                    conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
        if state.get("status") != "queued":
            return ("", 204)
        state["status"] = "running"
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
        col_row = (conn.execute("SELECT value FROM app_state WHERE key='network_collectors'").fetchone() or ({},))[0]
        col_cfg = col_row if isinstance(col_row, dict) else {}
        snmp_comm = str(col_cfg.get("snmpCommunity") or "").strip()
        arp_collectors = []
        seen_col_hosts = set()
        for ch in (col_cfg.get("collectorHosts") if isinstance(col_cfg.get("collectorHosts"), list) else []):
            ch_s = str(ch or "").strip()
            if ch_s and ch_s not in seen_col_hosts:
                seen_col_hosts.add(ch_s)
                arp_collectors.append({"host": ch_s, "version": "2c", "community": snmp_comm or "public", "port": 161})
        for sm in _snmp_rows(conn):
            if not isinstance(sm, dict) or not sm.get("host"):
                continue
            sh = str(sm["host"]).strip()
            if sm.get("username"):
                try:
                    auth_sec = snmp_secret_box().decrypt(str(sm.get("authSecret") or "").encode()).decode()
                    priv_sec = snmp_secret_box().decrypt(str(sm.get("privacySecret") or "").encode()).decode()
                except (KeyError, InvalidToken, ValueError, TypeError):
                    continue
                arp_collectors.append({
                    "host": sh,
                    "version": "3",
                    "port": int(sm.get("port") or 161),
                    "username": str(sm.get("username") or ""),
                    "authProtocol": str(sm.get("authProtocol") or "SHA"),
                    "authSecret": auth_sec,
                    "privacyProtocol": str(sm.get("privacyProtocol") or "AES"),
                    "privacySecret": priv_sec,
                    "community": snmp_comm or "public",
                })
            else:
                arp_collectors.append({
                    "host": sh,
                    "version": "2c",
                    "port": int(sm.get("port") or 161),
                    "community": snmp_comm or "public",
                })
    return jsonify(id=state.get("id"), ranges=ranges, total=state.get("total", 0), arpCollectors=arp_collectors, snmpCommunity=snmp_comm)


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
        progress = max(0, min(MAX_NETWORK_SCAN_HOSTS, int(body.get("progress", 0))))
    except (ValueError, TypeError):
        return jsonify(error="Invalid scan progress"), 400
    results = body.get("results", [])
    if not isinstance(results, list) or len(results) > MAX_NETWORK_SCAN_HOSTS:
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
            vendor = (str(item.get("vendor") or "").strip() or _lookup_mac_vendor(mac))[:120]
            clean.append({
                "ip": str(ip),
                "mac": mac,
                "vendor": vendor,
                "hostname": str(item.get("hostname", ""))[:255],
                "via": str(item.get("via", "ICMP"))[:32],
                "status": "Online",
                "latency_ms": latency,
                "last_seen": str(item.get("last_seen", ""))[:64],
            })
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
            networks = _parse_authorized_networks(ranges)
            online_ips = {item["ip"] for item in clean}
            checked_at = datetime.now(timezone.utc).isoformat()
            _apply_ip_status_to_records(conn, networks, online_ips, checked_at)
            by_ip = {item["ip"]: item for item in clean if item.get("mac") or item.get("vendor")}
            if by_ip:
                arow = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
                assets_list = arow[0] if arow and isinstance(arow[0], list) else []
                mac_updated = False
                for a in assets_list:
                    if not isinstance(a, dict):
                        continue
                    p_ip = str(a.get("ipAddress") or a.get("ip_address") or "").strip()
                    hit = by_ip.get(p_ip)
                    if hit:
                        if hit.get("mac") and not str(a.get("macAddress") or a.get("mac_address") or "").strip():
                            a["macAddress"] = hit["mac"]
                            mac_updated = True
                        if hit.get("vendor") and not str(a.get("manufacturer") or "").strip():
                            a["manufacturer"] = hit["vendor"]
                            mac_updated = True
                    for nif in (a.get("networkInterfaces") if isinstance(a.get("networkInterfaces"), list) else []):
                        if not isinstance(nif, dict):
                            continue
                        n_ip = str(nif.get("ipAddress") or nif.get("ip_address") or nif.get("ip") or "").strip()
                        n_hit = by_ip.get(n_ip)
                        if n_hit and n_hit.get("mac") and not str(nif.get("macAddress") or nif.get("mac_address") or "").strip():
                            nif["macAddress"] = n_hit["mac"]
                            mac_updated = True
                            if n_hit.get("vendor") and not str(a.get("manufacturer") or "").strip():
                                a["manufacturer"] = n_hit["vendor"]
                if mac_updated:
                    conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='assets'", (json.dumps(assets_list),))
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
        _vault_purge_session(sid=sid)
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
    _vault_purge_session(sid=sid, username=username)
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
    raw_user = str(session["profile"].get("username", "")).strip()
    ukey = raw_user.casefold()
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='profile_preferences'").fetchone()
    preferences = row[0] if row and isinstance(row[0], dict) else {}
    user_prefs = preferences.get(ukey) or (preferences.get(raw_user) if raw_user != ukey else None) or {}
    return jsonify(preferences=user_prefs, userScoped=True)


@app.put("/api/profile/preferences")
@signed_in
def save_profile_preferences():
    payload = request.get_json(silent=True) or {}
    valid_views = {
        "dashboard", "assets", "datacenter", "tickets", "ticketing", "visitors", "gatepass",
        "maintenance", "ageing", "users", "departments", "factories", "valuation", "billing",
        "software", "firmware", "credentials", "monitoring", "networkmap", "snmp",
        "notifications", "surveillance", "parts", "reports", "backups", "settings"
    }
    order = payload.get("order")
    hidden = payload.get("hidden", [])
    if (not isinstance(order, list) or not isinstance(hidden, list)
            or len(order) > len(valid_views) or len(hidden) > len(valid_views)
            or any(not isinstance(item, str) or item not in valid_views for item in order + hidden)):
        return jsonify(error="Invalid module preferences."), 400
    normalized_order = list(dict.fromkeys(order))
    normalized_order.extend(sorted(valid_views - set(normalized_order)))
    normalized = {"order": normalized_order, "hidden": list(dict.fromkeys(hidden))}
    raw_user = str(session["profile"].get("username", "")).strip()
    ukey = raw_user.casefold() or "_default"
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('profile_preferences','{}') ON CONFLICT(key) DO NOTHING")
        row = conn.execute("SELECT value FROM app_state WHERE key='profile_preferences' FOR UPDATE").fetchone()
        preferences = row[0] if row and isinstance(row[0], dict) else {}
        if raw_user and raw_user != ukey and raw_user in preferences:
            preferences.pop(raw_user, None)
        preferences[ukey] = normalized
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='profile_preferences'", (json.dumps(preferences),))
    return jsonify(ok=True, preferences=normalized, userScoped=True)


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


PORTAL_TILE_THEMES = ("emerald", "blue", "amber", "indigo", "teal", "rose", "cyan", "slate")
PORTAL_TILE_ACTIONS = (
    "complaint-desk",
    "support-all",
    "material-request",
    "visitor",
    "gatepass",
    "track-ticket",
    "custom-url",
)
_DEFAULT_DESK_TILE_STYLES = {
    "it": ("emerald", "IT Support"),
    "plumber": ("cyan", "Plumbing"),
    "electrician": ("amber", "Electrical"),
    "admin": ("indigo", "Facility / Admin"),
}


def _safe_portal_url(url_val):
    s = str(url_val or "").strip()[:300]
    if not s:
        return ""
    if (s.startswith("/") and not s.startswith("//")) or s.startswith("#"):
        return s
    low = s.casefold()
    if low.startswith(("http://", "https://")):
        return s
    return ""


def _default_tile_for_desk(desk, idx=0):
    did = str(desk.get("id") or "it").strip()[:40] or "it"
    palette = ("emerald", "cyan", "amber", "indigo", "teal", "blue", "rose")
    d_theme, d_sub = _DEFAULT_DESK_TILE_STYLES.get(did, (palette[idx % len(palette)], "Service Desk"))
    return {
        "id": f"desk:{did}",
        "action": "complaint-desk",
        "deskId": did,
        "requestKind": "",
        "gateDirection": "",
        "targetUrl": "",
        "openNewTab": False,
        "title": str(desk.get("name") or did)[:60],
        "subtitle": d_sub,
        "icon": str(desk.get("icon") or "🎫").strip()[:12] or "🎫",
        "theme": d_theme,
        "visible": True,
        "builtin": True,
    }


def _default_builtin_tiles(clean_desks, show_visitor=True, show_gatepass=True):
    tiles = [_default_tile_for_desk(dk, idx) for idx, dk in enumerate(clean_desks)]
    tiles.append({
        "id": "visitor",
        "action": "visitor",
        "deskId": "",
        "requestKind": "",
        "gateDirection": "",
        "targetUrl": "",
        "openNewTab": False,
        "title": "Visitor Pass",
        "subtitle": "Gate Entry",
        "icon": "🪪",
        "theme": "blue",
        "visible": bool(show_visitor),
        "builtin": True,
    })
    tiles.append({
        "id": "gatepass",
        "action": "gatepass",
        "deskId": "",
        "requestKind": "",
        "gateDirection": "",
        "targetUrl": "",
        "openNewTab": False,
        "title": "Material Gate",
        "subtitle": "IN / OUT",
        "icon": "📦",
        "theme": "amber",
        "visible": bool(show_gatepass),
        "builtin": True,
    })
    return tiles


def normalize_portal_config(settings_val, complaint_desks=None):
    settings = settings_val if isinstance(settings_val, dict) else {}
    raw = settings.get("portalConfig") if isinstance(settings.get("portalConfig"), dict) else {}
    desks = complaint_desks if isinstance(complaint_desks, list) and complaint_desks else list(DEFAULT_COMPLAINT_DESKS)
    valid_desk_ids = {str(d.get("id") or "") for d in desks if isinstance(d, dict) and d.get("id")}
    default_desk_id = desks[0].get("id", "it") if desks and isinstance(desks[0], dict) else "it"

    show_desks_as_tiles = bool(raw.get("showComplaintDesksAsTiles", True))
    auto_sync_desks = bool(raw.get("autoSyncComplaintDesks", True))
    show_visitor = bool(raw.get("showVisitorPass", True))
    show_gatepass = bool(raw.get("showMaterialGate", True))
    show_sec_pills = bool(raw.get("showSecondaryDeskPills", False))
    show_signin = bool(raw.get("showSignInButton", True))
    show_ticket_form = bool(raw.get("showTicketForm", True))
    show_mat_request = bool(raw.get("showMaterialRequest", True))
    show_attachments = bool(raw.get("showAttachments", True))
    show_tracking_panel = bool(raw.get("showTrackingPanel", True))
    show_live_queue = bool(raw.get("showLiveTicketQueue", True))
    show_visitor_queue = bool(raw.get("showVisitorQueue", True))
    show_material_queue = bool(raw.get("showMaterialQueue", True))
    show_live_toasts = bool(raw.get("showLiveToasts", True))
    eyebrow_text = str(raw.get("eyebrowText") or "").strip()[:120]
    heading_text = str(raw.get("headingText") or "").strip()[:140]
    subtitle_text = str(raw.get("subtitleText") or "").strip()[:260]
    default_tile_id = str(raw.get("defaultTileId") or "auto").strip()[:64] or "auto"

    raw_tiles = raw.get("tiles")
    clean_tiles = []
    seen_ids = set()
    if isinstance(raw_tiles, list) and len(raw_tiles) > 0:
        for idx, t in enumerate(raw_tiles[:40]):
            if not isinstance(t, dict):
                continue
            action = str(t.get("action") or "custom-url").strip()
            if action not in PORTAL_TILE_ACTIONS:
                continue
            tid = str(t.get("id") or f"tile-{idx + 1}").strip()[:64]
            tid = re.sub(r"[^a-zA-Z0-9_:-]+", "-", tid).strip("-") or f"tile-{idx + 1}"
            if tid in seen_ids:
                continue
            desk_id = str(t.get("deskId") or "").strip()[:40]
            if action == "complaint-desk":
                if not desk_id and tid.startswith("desk:"):
                    desk_id = tid.split(":", 1)[1]
                if desk_id not in valid_desk_ids:
                    if t.get("builtin") or tid.startswith("desk:"):
                        continue
                    desk_id = default_desk_id
            elif action == "material-request":
                if desk_id and desk_id not in valid_desk_ids:
                    desk_id = default_desk_id
            else:
                desk_id = ""
            req_kind = str(t.get("requestKind") or "").strip()
            if req_kind not in ("", "Issue", "Material request"):
                req_kind = ""
            gdir = str(t.get("gateDirection") or "").strip().upper()
            if gdir not in ("", "IN", "OUT"):
                gdir = ""
            target_url = _safe_portal_url(t.get("targetUrl")) if action == "custom-url" else ""
            title = str(t.get("title") or "").strip()[:60] or "Portal Module"
            subtitle = str(t.get("subtitle") or "").strip()[:40]
            icon = str(t.get("icon") or "🎫").strip()[:12] or "🎫"
            theme = str(t.get("theme") or "emerald").strip().lower()
            if theme not in PORTAL_TILE_THEMES:
                theme = "emerald"
            seen_ids.add(tid)
            clean_tiles.append({
                "id": tid,
                "action": action,
                "deskId": desk_id,
                "requestKind": req_kind,
                "gateDirection": gdir,
                "targetUrl": target_url,
                "openNewTab": bool(t.get("openNewTab", False)),
                "title": title,
                "subtitle": subtitle,
                "icon": icon,
                "theme": theme,
                "visible": bool(t.get("visible", True)),
                "builtin": bool(t.get("builtin", False)),
            })

    if not clean_tiles:
        clean_tiles = _default_builtin_tiles(desks, show_visitor, show_gatepass)
        seen_ids = {t["id"] for t in clean_tiles}
    else:
        if auto_sync_desks:
            missing_desk_tiles = []
            for idx, dk in enumerate(desks):
                did = str(dk.get("id") or "")
                has_tile = any(
                    (tl["id"] == f"desk:{did}") or (tl["action"] == "complaint-desk" and tl.get("deskId") == did)
                    for tl in clean_tiles
                )
                if did and not has_tile and f"desk:{did}" not in seen_ids:
                    dt = _default_tile_for_desk(dk, idx)
                    missing_desk_tiles.append(dt)
                    seen_ids.add(dt["id"])
            if missing_desk_tiles:
                insert_at = next((i for i, tl in enumerate(clean_tiles) if tl["action"] in ("visitor", "gatepass")), len(clean_tiles))
                clean_tiles[insert_at:insert_at] = missing_desk_tiles
        if "visitor" not in seen_ids and not any(tl["action"] == "visitor" for tl in clean_tiles):
            clean_tiles.append({
                "id": "visitor", "action": "visitor", "deskId": "", "requestKind": "", "gateDirection": "",
                "targetUrl": "", "openNewTab": False, "title": "Visitor Pass", "subtitle": "Gate Entry",
                "icon": "🪪", "theme": "blue", "visible": bool(show_visitor), "builtin": True,
            })
        if "gatepass" not in seen_ids and not any(tl["action"] == "gatepass" for tl in clean_tiles):
            clean_tiles.append({
                "id": "gatepass", "action": "gatepass", "deskId": "", "requestKind": "", "gateDirection": "",
                "targetUrl": "", "openNewTab": False, "title": "Material Gate", "subtitle": "IN / OUT",
                "icon": "📦", "theme": "amber", "visible": bool(show_gatepass), "builtin": True,
            })

    if "showVisitorPass" in raw:
        for tl in clean_tiles:
            if tl["id"] == "visitor":
                tl["visible"] = show_visitor
    elif any(tl["id"] == "visitor" for tl in clean_tiles):
        show_visitor = next(tl["visible"] for tl in clean_tiles if tl["id"] == "visitor")

    if "showMaterialGate" in raw:
        for tl in clean_tiles:
            if tl["id"] == "gatepass":
                tl["visible"] = show_gatepass
    elif any(tl["id"] == "gatepass" for tl in clean_tiles):
        show_gatepass = next(tl["visible"] for tl in clean_tiles if tl["id"] == "gatepass")

    return {
        "showComplaintDesksAsTiles": show_desks_as_tiles,
        "autoSyncComplaintDesks": auto_sync_desks,
        "showVisitorPass": show_visitor,
        "showMaterialGate": show_gatepass,
        "showSecondaryDeskPills": show_sec_pills,
        "showSignInButton": show_signin,
        "showTicketForm": show_ticket_form,
        "showMaterialRequest": show_mat_request,
        "showAttachments": show_attachments,
        "showTrackingPanel": show_tracking_panel,
        "showLiveTicketQueue": show_live_queue,
        "showVisitorQueue": show_visitor_queue,
        "showMaterialQueue": show_material_queue,
        "showLiveToasts": show_live_toasts,
        "eyebrowText": eyebrow_text,
        "headingText": heading_text,
        "subtitleText": subtitle_text,
        "defaultTileId": default_tile_id,
        "tiles": clean_tiles,
    }


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
        "portalConfig": normalize_portal_config(settings, clean_desks),
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


def _local_now_dt():
    tz_name = str(os.getenv("APP_TIMEZONE") or os.getenv("TZ") or "Asia/Kolkata").strip()
    if ZoneInfo is not None and tz_name:
        try:
            return datetime.now(ZoneInfo(tz_name))
        except Exception:
            pass
    return datetime.now().astimezone()


def _time_salutation(dt=None):
    d = dt or _local_now_dt()
    if 5 <= d.hour < 12:
        return "Good Morning"
    if 12 <= d.hour < 17:
        return "Good Afternoon"
    return "Good Evening"


def _clean_gender(val):
    g = str(val or "").strip().casefold()
    if g in ("male", "m", "mr", "sir"):
        return "Male"
    if g in ("female", "f", "ms", "mrs", "miss", "maam", "ma'am"):
        return "Female"
    return "Unspecified"


def _gender_honorific(gender):
    g = _clean_gender(gender)
    if g == "Male":
        return "Sir"
    if g == "Female":
        return "Ma'am"
    return "Sir/Ma'am"


def _format_eta_detail(eta_val):
    if not eta_val:
        return "", None
    now_local = _local_now_dt()
    dt_obj = None
    if isinstance(eta_val, datetime):
        dt_obj = eta_val
    else:
        raw = str(eta_val or "").strip()
        if raw:
            try:
                dt_obj = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                dt_obj = None
    if dt_obj is None:
        return str(eta_val or "")[:40], None
    if dt_obj.tzinfo is None:
        dt_local = dt_obj.replace(tzinfo=now_local.tzinfo)
    else:
        dt_local = dt_obj.astimezone(now_local.tzinfo)
    diff_min = int((dt_local - now_local).total_seconds() // 60)
    date_txt = dt_local.strftime("%d %b %Y, %I:%M %p")
    if diff_min > 0:
        if diff_min < 60:
            rel = f"in ~{diff_min} min{'s' if diff_min != 1 else ''}"
        else:
            hrs, rem = divmod(diff_min, 60)
            rel = f"in ~{hrs}h {rem}m" if rem else f"in ~{hrs} hr{'s' if hrs != 1 else ''}"
        return f"{date_txt} ({rel})", diff_min
    return date_txt, 0


def _clean_admin_presence_map(raw_map):
    if not isinstance(raw_map, dict):
        return {}
    now_utc = datetime.now(timezone.utc)
    valid_statuses = {"Available", "In work", "Away", "Offline"}
    cleaned = {}
    for raw_k, raw_v in raw_map.items():
        if not isinstance(raw_v, dict):
            continue
        ukey = str(raw_v.get("username") or raw_k or "").strip().casefold()[:80]
        if not ukey:
            continue
        status = str(raw_v.get("status") or "Available").strip()
        if status not in valid_statuses:
            status = "Available"
        current_task = str(raw_v.get("currentTask") or "").strip()[:240]
        try:
            eta_minutes = max(0, min(1440, int(raw_v.get("etaMinutes") or 0)))
        except (TypeError, ValueError):
            eta_minutes = 0
        busy_until = str(raw_v.get("busyUntil") or "").strip()[:48]
        eta_remaining = 0
        is_expired = False
        if status in ("In work", "Away") and busy_until:
            try:
                bdt = datetime.fromisoformat(busy_until.replace("Z", "+00:00"))
                if bdt.tzinfo is None:
                    bdt = bdt.replace(tzinfo=timezone.utc)
                sec_left = (bdt - now_utc).total_seconds()
                if sec_left > 0:
                    eta_remaining = max(1, int((sec_left + 59) // 60))
                else:
                    is_expired = True
            except ValueError:
                eta_remaining = eta_minutes
        elif status in ("In work", "Away"):
            eta_remaining = eta_minutes
        raw_desks = raw_v.get("desks") if isinstance(raw_v.get("desks"), list) else ["*"]
        clean_desks = [str(d).strip().lower()[:40] for d in raw_desks if str(d or "").strip()][:20] or ["*"]
        cleaned[ukey] = {
            "username": ukey,
            "name": str(raw_v.get("name") or ukey).strip()[:120] or ukey,
            "gender": _clean_gender(raw_v.get("gender")),
            "status": status,
            "currentTask": current_task,
            "etaMinutes": eta_minutes,
            "etaRemainingMin": eta_remaining,
            "busyUntil": busy_until,
            "isBusyExpired": is_expired,
            "desks": clean_desks,
            "updatedAt": str(raw_v.get("updatedAt") or "")[:48],
        }
    return cleaned


def _summarize_admin_availability(conn, desk_id="it", assigned_to=""):
    row = conn.execute("SELECT value FROM app_state WHERE key='admin_presence'").fetchone()
    pres_map = _clean_admin_presence_map(row[0] if row else {})
    entries = list(pres_map.values())
    desk_slug = _slug_desk_id(desk_id or "it", fallback="it")
    scoped = [p for p in entries if "*" in p["desks"] or desk_slug in p["desks"]]
    if not scoped:
        scoped = entries
    avail = [p for p in scoped if p["status"] == "Available"]
    busy = sorted([p for p in scoped if p["status"] == "In work"], key=lambda p: (p["etaRemainingMin"] or p["etaMinutes"] or 9999))
    away = sorted([p for p in scoped if p["status"] == "Away"], key=lambda p: (p["etaRemainingMin"] or p["etaMinutes"] or 9999))
    offline = [p for p in scoped if p["status"] == "Offline"]

    assigned_entry = None
    if assigned_to and assigned_to != "Unassigned":
        a_cf = str(assigned_to).strip().casefold()
        assigned_entry = next((p for p in entries if p["name"].casefold() == a_cf or p["username"] == a_cf), None)

    summary_sentence = ""
    busy_lead = busy[0] if busy else (away[0] if away else None)
    est_wait = (busy_lead["etaRemainingMin"] or busy_lead["etaMinutes"]) if busy_lead else 0

    if assigned_entry and assigned_entry["status"] in ("In work", "Away"):
        wmin = assigned_entry["etaRemainingMin"] or assigned_entry["etaMinutes"]
        wtxt = f" (~{wmin} min{'s' if wmin != 1 else ''} remaining)" if wmin > 0 else ""
        ttxt = f" — currently handling: \"{assigned_entry['currentTask']}\"" if assigned_entry["currentTask"] else ""
        summary_sentence = f"Currently, {assigned_entry['name']} is {assigned_entry['status'].lower()}{ttxt}{wtxt}."
    elif busy and not avail:
        lead = busy[0]
        wmin = lead["etaRemainingMin"] or lead["etaMinutes"]
        wtxt = f" (estimated completion: ~{wmin} min{'s' if wmin != 1 else ''})" if wmin > 0 else ""
        ttxt = f"\"{lead['currentTask']}\"" if lead["currentTask"] else "an ongoing support task"
        summary_sentence = f"Currently, {lead['name']} is occupied with {ttxt}{wtxt}. As soon as that task is completed, your ticket will be accepted immediately and resolved as quickly as possible."
    elif away and not avail:
        lead = away[0]
        wmin = lead["etaRemainingMin"] or lead["etaMinutes"]
        wtxt = f" (expected back in ~{wmin} min{'s' if wmin != 1 else ''})" if wmin > 0 else ""
        ttxt = f" ({lead['currentTask']})" if lead["currentTask"] else ""
        summary_sentence = f"Currently, our support engineer ({lead['name']}) is temporarily away{ttxt}{wtxt}. As soon as they return, your ticket will be picked up immediately and resolved promptly."
    elif avail:
        names = ", ".join(p["name"] for p in avail[:3])
        summary_sentence = f"Support engineer {names} is Available right now and will accept and begin working on your ticket shortly."
    elif offline:
        summary_sentence = "Our support team is currently offline/between shifts; your ticket is queued in priority order and will be accepted immediately once support comes online."
    else:
        summary_sentence = "Your request has been placed in the live queue and our support team will respond as soon as possible."

    return {
        "hasAvailable": bool(avail),
        "availableCount": len(avail),
        "busyCount": len(busy),
        "awayCount": len(away),
        "offlineCount": len(offline),
        "busyAdmin": busy_lead,
        "assignedPresence": assigned_entry,
        "estimatedWaitMin": est_wait,
        "summarySentence": summary_sentence,
        "admins": scoped,
    }


def _lookup_requester_contact(conn, username="", display_name="", explicit_gender=""):
    row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    users = row[0] if row and isinstance(row[0], list) else []
    u_cf = str(username or "").strip().casefold()
    n_cf = str(display_name or "").strip().casefold()
    matched = None
    for u in users:
        if not isinstance(u, dict):
            continue
        un = str(u.get("username") or u.get("id") or "").strip().casefold()
        nm = str(u.get("name") or "").strip().casefold()
        if (u_cf and not u_cf.startswith("public-") and un == u_cf) or (n_cf and nm == n_cf):
            matched = u
            break
    gender = _clean_gender(explicit_gender) if _clean_gender(explicit_gender) != "Unspecified" else _clean_gender((matched or {}).get("gender"))
    email = str((matched or {}).get("email") or "").strip()[:254]
    return {"gender": gender, "email": email, "name": str((matched or {}).get("name") or display_name or username or "User").strip()}


def _maybe_send_ticket_email(to_email, subject, body_text):
    smtp_host = str(os.getenv("SMTP_HOST") or "").strip()
    smtp_from = str(os.getenv("SMTP_FROM") or "").strip()
    if not smtp_host or not smtp_from or not to_email or "@" not in to_email:
        return False
    smtp_port = int(os.getenv("SMTP_PORT") or 587)
    smtp_user = str(os.getenv("SMTP_USER") or "").strip()
    smtp_pass = str(os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_PASS") or "").strip()
    use_ssl = str(os.getenv("SMTP_SSL") or "").strip().lower() in ("1", "true", "yes")
    use_tls = str(os.getenv("SMTP_TLS") or "true").strip().lower() not in ("0", "false", "no")

    def _send():
        try:
            msg = EmailMessage()
            msg["Subject"] = subject[:180]
            msg["From"] = smtp_from
            msg["To"] = to_email
            msg.set_content(body_text)
            if use_ssl:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as s:
                    if smtp_user and smtp_pass:
                        s.login(smtp_user, smtp_pass)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                    if use_tls:
                        s.starttls()
                    if smtp_user and smtp_pass:
                        s.login(smtp_user, smtp_pass)
                    s.send_message(msg)
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()
    return True


def _build_and_record_ticket_user_notification(conn, *, ticket_id, event_type, actor="", detail="", assigned_to=None, status=None, eta=None, note=None, explicit_gender=""):
    trow = conn.execute(
        "SELECT id,kind,username,display_name,department,factory,primary_category,sub_category,description,material,assigned_to,status,eta,note,public_token_hash,COALESCE(NULLIF(complaint_desk,''),'it'),COALESCE(NULLIF(requester_gender,''),'') FROM tickets WHERE id=%s",
        (ticket_id,),
    ).fetchone()
    if not trow:
        return None
    (tid, kind, uname, dname, dept, factory, primary, sub, desc, material, cur_assigned, cur_status, cur_eta, cur_note, pub_hash, desk_id, db_gender) = trow
    eff_assigned = cur_assigned if assigned_to is None else assigned_to
    eff_status = cur_status if status is None else status
    eff_eta = cur_eta if eta is None else eta
    eff_note = cur_note if note is None else note
    eff_gender = explicit_gender or db_gender

    contact = _lookup_requester_contact(conn, uname, dname, eff_gender)
    now_local = _local_now_dt()
    salutation = _time_salutation(now_local)
    honorific = _gender_honorific(contact["gender"])
    greeting_line = f"{salutation} {honorific}, Greetings of the day!"

    stage_map = {"Open": 1, "In progress": 2, "Resolved": 3, "Closed": 4}
    stage_idx = stage_map.get(eff_status, 1)
    eta_text, eta_wait_min = _format_eta_detail(eff_eta)
    eta_sentence = f" Detailed ETA: Expected resolution by {eta_text}." if eta_text else ""
    note_clean = str(eff_note or detail or "").strip()
    desc_short = (str(desc or "").strip()[:120] + ("..." if len(str(desc or "").strip()) > 120 else ""))
    issue_summary = " · ".join([x for x in (sub or primary, desc_short) if x])
    avail_info = _summarize_admin_availability(conn, desk_id=desk_id, assigned_to=eff_assigned)

    if event_type == "created":
        title = f"Ticket {tid} Registered (Stage 1: Open)"
        body = f"{greeting_line} Your {kind.lower()} #{tid} regarding \"{issue_summary}\" has been submitted and is currently in Stage 1 of 4 (Open). {avail_info['summarySentence']}"
    elif event_type == "assigned":
        title = f"Ticket {tid} Assigned to {eff_assigned}"
        live_ctx = ""
        ap = avail_info.get("assignedPresence")
        if ap and ap["status"] in ("In work", "Away"):
            rem = ap["etaRemainingMin"] or ap["etaMinutes"]
            live_ctx = f" (Note: {eff_assigned} is currently {ap['status'].lower()}" + (f" on \"{ap['currentTask']}\"" if ap["currentTask"] else "") + (f", free in ~{rem} mins" if rem else "") + " — will take up your task right after)"
        elif ap and ap["status"] == "Available":
            live_ctx = " (Currently Available to work on your issue)"
        body = f"{greeting_line} Your ticket #{tid} ({sub or primary}) has now been assigned to {eff_assigned}{live_ctx}. Current Stage: {eff_status} (Stage {stage_idx} of 4).{eta_sentence}"
    elif event_type == "status_change":
        if eff_status == "In progress":
            title = f"Ticket {tid} is now In Progress"
            body = f"{greeting_line} Your ticket #{tid} ({issue_summary}) has moved to Stage 2 of 4: In Progress. Assigned Engineer: {eff_assigned or 'Support Team'}.{eta_sentence}" + (f" Latest update: \"{note_clean}\"." if note_clean else "")
        elif eff_status in ("Resolved", "Closed"):
            title = f"Ticket {tid} {eff_status}"
            who_solved = actor or (eff_assigned if eff_assigned and eff_assigned != "Unassigned" else "our support team")
            work_part = f" Work completed: \"{note_clean}\"." if note_clean else ""
            body = (
                f"{greeting_line} We are pleased to inform you that your reported issue #{tid} regarding \"{issue_summary}\" has been {eff_status} by {who_solved}.{work_part} "
                f"If you encounter any new issue or face this same issue again in the future, please feel free to raise a new ticket anytime — we will be happy to assist you promptly!"
            )
        else:
            title = f"Ticket {tid} Updated to {eff_status}"
            body = f"{greeting_line} Your ticket #{tid} ({sub or primary}) status is now {eff_status} (Stage {stage_idx} of 4). {avail_info['summarySentence']}" + (f" Remark: \"{note_clean}\"." if note_clean else "")
    elif event_type == "worklog":
        title = f"Work Update on Ticket {tid}"
        body = f"{greeting_line} Work Update for your ticket #{tid} (Stage {stage_idx} of 4 · {eff_status}): {actor or 'Support Team'} logged — \"{detail}\". Assigned Engineer: {eff_assigned or 'Support Team'}.{eta_sentence}"
    elif event_type == "eta_updated":
        title = f"ETA Updated for Ticket {tid}"
        body = f"{greeting_line} Schedule / ETA update for ticket #{tid} (Stage: {eff_status}): {('Expected completion is ' + eta_text) if eta_text else 'ETA schedule cleared'}. Assigned Engineer: {eff_assigned or 'Support Team'}."
    elif event_type == "material_issued":
        title = f"Material Update for Request {tid}"
        done_invite = " Thank you! If you need additional items or face any issue again, feel free to raise a new ticket anytime." if eff_status in ("Resolved", "Closed") else ""
        body = f"{greeting_line} Update on your request #{tid} ({sub or primary}): {detail}. Current Stage: {eff_status} (Stage {stage_idx} of 4).{done_invite}"
    else:
        title = f"Update on Ticket {tid}"
        body = f"{greeting_line} Your ticket #{tid} has a new update ({eff_status}).{eta_sentence}"

    notif = {
        "id": f"unotif-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}",
        "ticketId": tid,
        "kind": kind,
        "complaintDesk": desk_id,
        "factory": factory,
        "department": dept,
        "requesterName": dname,
        "requesterUsername": uname,
        "requesterGender": contact["gender"],
        "trackingTokenHash": str(pub_hash or ""),
        "eventType": event_type,
        "stage": eff_status,
        "stageIndex": stage_idx,
        "salutation": salutation,
        "honorific": honorific,
        "greetingLine": greeting_line,
        "title": title,
        "message": body,
        "assignedTo": eff_assigned,
        "etaDisplay": eta_text,
        "etaWaitMinutes": eta_wait_min,
        "workDetail": str(detail or note_clean or "")[:600],
        "availabilityNotice": avail_info["summarySentence"],
        "busyAdmin": avail_info.get("busyAdmin"),
        "actor": str(actor or "")[:120],
        "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "createdDisplay": now_local.strftime("%d %b %Y, %I:%M %p"),
    }
    row = conn.execute("SELECT value FROM app_state WHERE key='ticket_user_notifications' FOR UPDATE").fetchone()
    items = list(row[0]) if row and isinstance(row[0], list) else []
    items.insert(0, notif)
    items = items[:400]
    conn.execute(
        "INSERT INTO app_state(key,value) VALUES('ticket_user_notifications',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
        (json.dumps(items),),
    )
    _pg_emit_notify(conn, "ticket", {"action": "user-notification", "ticketId": tid, "eventType": event_type, "stage": eff_status, "complaintDesk": desk_id})
    _sync_ticket_notif_to_helpdesk_tx(
        conn,
        raw_username=uname,
        requester_name=(dname or contact.get("name") or uname),
        dept=dept,
        factory=factory,
        gender=contact.get("gender") or "",
        section_id=desk_id,
        ticket_id=tid,
        assigned_to=eff_assigned,
        title=title,
        body=body,
        stage=eff_status,
        stage_index=stage_idx,
        eta_display=eta_text,
        event_type=event_type,
    )
    if contact.get("email"):
        _maybe_send_ticket_email(contact["email"], title, body)
    return {k: v for k, v in notif.items() if k != "trackingTokenHash"}


def _helpdesk_section_meta_list(conn):
    srow = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    cfg = normalize_ticketing_settings(srow[0] if srow else {})
    desks = cfg.get("complaintDesks") or []
    icon_map = {"it": "💻", "plumber": "🔧", "electrician": "⚡", "admin": "🏢"}
    color_map = {"it": "#059669", "plumber": "#0284c7", "electrician": "#d97706", "admin": "#7c3aed"}
    sections = []
    for d in desks:
        did = _slug_desk_id(d.get("id") or "it", "it")
        sections.append({
            "id": did,
            "label": str(d.get("name") or d.get("title") or did.title())[:60],
            "icon": icon_map.get(did, "🎫"),
            "color": color_map.get(did, "#0f766e"),
            "kind": "desk",
        })
    sections.append({"id": "visitor", "label": "Visitor Pass", "icon": "🪪", "color": "#0284c7", "kind": "visitor"})
    sections.append({"id": "gatepass", "label": "Material Entry", "icon": "📦", "color": "#b45309", "kind": "gatepass"})
    return sections


def _helpdesk_caller_can_staff_section(profile, is_admin, section_id):
    if is_admin:
        return True
    if not isinstance(profile, dict):
        return False
    sec = _slug_desk_id(section_id or "it", "it")
    if sec == "visitor":
        return module_access(profile, "visitors", write=True)
    if sec == "gatepass":
        return module_access(profile, "gatepass", write=True)
    return (profile.get("role") == "IT Ticketing" or module_access(profile, "tickets", write=True)) and ticket_desk_allowed(profile, sec)


def _user_can_staff_section(user_rec, section_id):
    if not isinstance(user_rec, dict) or not user_rec.get("active", True):
        return False
    role = str(user_rec.get("role") or "")
    if role == "Administrator":
        return True
    sec = _slug_desk_id(section_id or "it", "it")
    if sec == "visitor":
        return module_access(user_rec, "visitors", write=True) or module_access(user_rec, "visitors")
    if sec == "gatepass":
        return module_access(user_rec, "gatepass", write=True) or module_access(user_rec, "gatepass")
    return (role == "IT Ticketing" or module_access(user_rec, "tickets", write=True)) and ticket_desk_allowed(user_rec, sec)


def _helpdesk_section_experts(conn, section_id):
    urow = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    prow = conn.execute("SELECT value FROM app_state WHERE key='admin_presence'").fetchone()
    users = urow[0] if urow and isinstance(urow[0], list) else []
    pres = _clean_admin_presence_map(prow[0] if prow else {})
    sec = _slug_desk_id(section_id or "it", "it")
    out = []
    seen = set()
    for u in users:
        if not isinstance(u, dict) or not _user_can_staff_section(u, sec):
            continue
        uname = str(u.get("username") or "").strip().casefold()
        if not uname or uname in seen:
            continue
        seen.add(uname)
        p = pres.get(uname) or {}
        st = p.get("status") or "Available"
        out.append({
            "username": uname,
            "name": str(u.get("name") or uname)[:120],
            "role": str(u.get("role") or ""),
            "title": str(u.get("title") or u.get("dept") or "")[:80],
            "status": st,
            "currentTask": str(p.get("currentTask") or ""),
            "etaRemainingMin": int(p.get("etaRemainingMin") or 0),
        })
    rank = {"Available": 0, "In work": 1, "Away": 2, "Offline": 3}
    out.sort(key=lambda x: (rank.get(x["status"], 4), x["name"].casefold()))
    return out


def _resolve_ticket_requester_key(conn, raw_username="", raw_display_name=""):
    u = str(raw_username or "").strip().casefold()
    if u:
        return u
    contact = _lookup_requester_contact(conn, "", raw_display_name)
    if contact.get("username"):
        return str(contact["username"]).strip().casefold()
    slug = _slug_desk_id(raw_display_name or "guest", "guest")
    return f"portal:{slug}"


def _helpdesk_thread_id(section_id, requester_key):
    sec = _slug_desk_id(section_id or "it", "it")[:20]
    rk = str(requester_key or "guest").strip().casefold() or "guest"
    return f"hd-{sec}-{hashlib.sha1(rk.encode('utf-8')).hexdigest()[:12]}"


def _sync_ticket_notif_to_helpdesk_tx(
    conn, *, raw_username="", requester_name="", dept="", factory="", gender="",
    section_id="it", ticket_id="", assigned_to="", title="", body="", stage="Open",
    stage_index=1, eta_display="", event_type="updated",
):
    req_key = _resolve_ticket_requester_key(conn, raw_username, requester_name)
    sec = _slug_desk_id(section_id or "it", "it")
    tid_thread = _helpdesk_thread_id(sec, req_key)
    sections = _helpdesk_section_meta_list(conn)
    sec_label = next((s["label"] for s in sections if s["id"] == sec), sec.title())

    exp_name = str(assigned_to or "").strip()
    if exp_name == "Unassigned":
        exp_name = ""
    exp_uname = ""
    if exp_name:
        urow = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
        for u in (urow[0] if urow and isinstance(urow[0], list) else []):
            if str(u.get("name") or "").strip().casefold() == exp_name.casefold() or str(u.get("username") or "").strip().casefold() == exp_name.casefold():
                exp_uname = str(u.get("username") or "").strip().casefold()
                exp_name = str(u.get("name") or exp_uname)[:120]
                break

    preview = f"{title}: {body}"[:180]
    conn.execute(
        """
        INSERT INTO helpdesk_threads(
          id, requester_username, requester_name, requester_dept, requester_factory, requester_gender,
          section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name,
          mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff,
          deleted_by_admin, updated_at
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'bot',%s,now(),1,0,false,now())
        ON CONFLICT(id) DO UPDATE SET
          requester_name=CASE WHEN excluded.requester_name<>'' THEN excluded.requester_name ELSE helpdesk_threads.requester_name END,
          requester_dept=CASE WHEN excluded.requester_dept<>'' THEN excluded.requester_dept ELSE helpdesk_threads.requester_dept END,
          requester_factory=CASE WHEN excluded.requester_factory<>'' THEN excluded.requester_factory ELSE helpdesk_threads.requester_factory END,
          requester_gender=CASE WHEN excluded.requester_gender<>'' THEN excluded.requester_gender ELSE helpdesk_threads.requester_gender END,
          section_label=excluded.section_label,
          ticket_id=CASE WHEN excluded.ticket_id<>'' THEN excluded.ticket_id ELSE helpdesk_threads.ticket_id END,
          assigned_expert_username=CASE WHEN excluded.assigned_expert_username<>'' THEN excluded.assigned_expert_username ELSE helpdesk_threads.assigned_expert_username END,
          assigned_expert_name=CASE WHEN excluded.assigned_expert_name<>'' THEN excluded.assigned_expert_name ELSE helpdesk_threads.assigned_expert_name END,
          last_message_preview=excluded.last_message_preview,
          last_message_at=now(),
          unread_for_requester=helpdesk_threads.unread_for_requester + 1,
          deleted_by_admin=false,
          updated_at=now()
        """,
        (
            tid_thread, req_key, str(requester_name or req_key)[:120], str(dept or "")[:120],
            str(factory or "")[:80], str(gender or "")[:20], sec, sec_label,
            str(ticket_id or "")[:80], exp_uname, exp_name[:120], preview,
        ),
    )
    msg_id = "hdm-" + uuid.uuid4().hex[:14]
    meta = {
        "title": title, "stage": stage, "stageIndex": stage_index,
        "etaDisplay": eta_display, "eventType": event_type, "assignedTo": exp_name,
    }
    conn.execute(
        """
        INSERT INTO helpdesk_messages(
          id, thread_id, sender_username, sender_name, sender_role, tagged_ticket_id, body, meta
        ) VALUES(%s,%s,%s,%s,'system',%s,%s,%s::jsonb)
        """,
        (msg_id, tid_thread, "helpdesk-auto", f"{sec_label} Auto-Update", str(ticket_id or "")[:80], body[:3000], json.dumps(meta)),
    )
    _pg_emit_notify(conn, "helpdesk_message", {"threadId": tid_thread, "sectionId": sec, "ticketId": str(ticket_id or "")[:80]})
    return tid_thread


def _sanitize_public_user_notif(item):
    if not isinstance(item, dict):
        return None
    out = dict(item)
    out.pop("trackingTokenHash", None)
    out.pop("requesterUsername", None)
    ba = out.get("busyAdmin")
    if isinstance(ba, dict):
        out["busyAdmin"] = {k: ba[k] for k in ("name", "status", "currentTask", "etaMinutes", "etaRemainingMin", "busyUntil") if k in ba}
    return out


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
            employees.append({"key": public_key, "name": name, "department": dept, "factory": site, "gender": _clean_gender(u.get("gender"))})
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
    explicit_gender = _clean_gender(body.get("gender"))
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
        req_gender = explicit_gender if explicit_gender != "Unspecified" else _clean_gender(user.get("gender"))
        conn.execute("INSERT INTO tickets(id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,public_token_hash,complaint_desk,requester_gender) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",
                     (ticket_id, kind, username, str(user.get("name") or "")[:120], department, factory, remote, primary, sub, description, material, json.dumps(saved), token_hash, desk_obj["id"], req_gender))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,'Public portal','created',%s)", (ticket_id, description[:500]))
        is_mr = (kind == "Material request")
        desk_label = desk_obj.get("name") or "IT"
        welcome_notif = _build_and_record_ticket_user_notification(
            conn, ticket_id=ticket_id, event_type="created", actor="Support Portal", detail=description, explicit_gender=req_gender
        )
        req_key = _resolve_ticket_requester_key(conn, username, str(user.get("name") or ""))
        thr_id = _helpdesk_thread_id(desk_obj["id"], req_key)
        _record_notification_event(conn, {
            "eventKey": f"ticket:{ticket_id}",
            "kind": "material_request" if is_mr else "ticket",
            "level": "info",
            "title": f"{'New Material Request' if is_mr else f'New {desk_label} Ticket'}: {ticket_id}",
            "body": f"{str(user.get('name') or username)} · {sub or primary} ({factory or '-'})",
            "factory": factory,
            "targetView": "messages",
            "targetTab": desk_obj["id"],
            "targetId": thr_id,
            "targetThreadId": thr_id,
            "targetTicketId": ticket_id,
            "targetUsername": req_key[:80],
            "requesterName": str(user.get("name") or "")[:120],
            "complaintDesk": desk_obj["id"],
        })
    return jsonify(
        id=ticket_id,
        tracking_token=tracking_token,
        complaintDesk=desk_obj["id"],
        availabilityNotice=(welcome_notif or {}).get("availabilityNotice", ""),
        welcomeNotification=_sanitize_public_user_notif(welcome_notif),
    ), 201


@app.post("/api/public/tickets/status")
def get_public_ticket_status():
    tracking_token = str((request.get_json(silent=True) or {}).get("tracking_token", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", tracking_token):
        abort(404)
    token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute("SELECT id,status,eta,note,updated_at,COALESCE(NULLIF(complaint_desk,''),'it'),assigned_to FROM tickets WHERE public_token_hash=%s", (token_hash,)).fetchone()
        repair = repair_map_from_conn(conn).get(row[0]) if row else None
        issued_parts = issued_parts_map_from_conn(conn).get(row[0], []) if row else []
        notif_row = conn.execute("SELECT value FROM app_state WHERE key='ticket_user_notifications'").fetchone()
        raw_notifs = notif_row[0] if notif_row and isinstance(notif_row[0], list) else []
        ticket_notifs = [
            _sanitize_public_user_notif(n) for n in raw_notifs
            if isinstance(n, dict) and (n.get("ticketId") == (row[0] if row else None) or n.get("trackingTokenHash") == token_hash)
        ][:30]
        avail = _summarize_admin_availability(conn, desk_id=(row[5] if row else "it"), assigned_to=(row[6] if row else ""))
    if not row:
        abort(404)
    pub_admins = [{k: p[k] for k in ("name", "status", "currentTask", "etaMinutes", "etaRemainingMin", "busyUntil", "desks", "updatedAt")} for p in avail["admins"]]
    return jsonify(id=row[0], status=row[1], eta=row[2].isoformat(timespec="minutes") if row[2] else "",
                   note=row[3], updated=row[4].isoformat(timespec="minutes") if row[4] else "",
                   assigned=row[6], repair=repair, issuedParts=issued_parts,
                   notifications=ticket_notifs, availabilitySummary=avail["summarySentence"], adminPresence=pub_admins)


@app.get("/api/public/admin-presence")
def public_admin_presence():
    req_desk = str(request.args.get("desk") or "it").strip().lower()
    with db() as conn:
        avail = _summarize_admin_availability(conn, desk_id=req_desk)
    pub_admins = [{k: p[k] for k in ("name", "status", "currentTask", "etaMinutes", "etaRemainingMin", "busyUntil", "desks", "updatedAt")} for p in avail["admins"]]
    return jsonify(
        admins=pub_admins,
        hasAvailable=avail["hasAvailable"],
        availableCount=avail["availableCount"],
        busyCount=avail["busyCount"],
        awayCount=avail["awayCount"],
        offlineCount=avail["offlineCount"],
        estimatedWaitMin=avail["estimatedWaitMin"],
        summarySentence=avail["summarySentence"],
    )


@app.get("/api/public/ticket-notifications")
def public_ticket_notifications():
    tracking_token = str(request.args.get("tracking_token") or "").strip()
    raw_multi = str(request.args.get("tracking_tokens") or "").strip()
    ticket_id = str(request.args.get("ticket_id") or "").strip()
    tokens = []
    if tracking_token:
        tokens.append(tracking_token)
    if raw_multi:
        tokens.extend([x.strip() for x in raw_multi.split(",") if x.strip()])
    token_hashes = {
        hashlib.sha256(tk.encode()).hexdigest()
        for tk in tokens[:60]
        if re.fullmatch(r"[A-Za-z0-9_-]{40,60}", tk)
    }
    if not token_hashes:
        return jsonify(notifications=[])
    with db() as conn:
        nrow = conn.execute("SELECT value FROM app_state WHERE key='ticket_user_notifications'").fetchone()
        raw = nrow[0] if nrow and isinstance(nrow[0], list) else []
    out = []
    for n in raw:
        if not isinstance(n, dict):
            continue
        if n.get("trackingTokenHash") not in token_hashes:
            continue
        if ticket_id and str(n.get("ticketId") or "") != ticket_id:
            continue
        out.append(_sanitize_public_user_notif(n))
        if len(out) >= 60:
            break
    return jsonify(notifications=out)


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
        keys = ("assets", "ip_mappings", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "vendors", "manual_users", "settings", "camera_streams", "camera_profiles", "network_ranges", "network_scan", "scanner_heartbeat", "scanner_ip_status", "notifications")
        out = {k: (conn.execute("SELECT value FROM app_state WHERE key=%s", (k,)).fetchone() or ([],))[0] for k in keys}
        settings_val = out.get("settings") if isinstance(out.get("settings"), dict) else {}
        ticketing_cfg = normalize_ticketing_settings(settings_val)
        safe_factories = {k: settings_val[k] for k in ("factories", "factoryOrder", "removedFactoryCodes", "factoryTerm", "factoryTermPlural", "assetTypes", "assetSubcategories", "categoryTileHidden", "companyName", "moduleLabels") if k in settings_val}
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
                out["users"] = [{k: v for k, v in u.items() if k in ("username", "name", "email", "dept", "department", "subdept", "site", "role", "enabled", "active", "employment", "gender")} | {"source": "manual"} for u in manuals]
            else:
                out["users"] = [{k: v for k, v in who.items() if k in ("username", "name", "email", "dept", "department", "site", "role", "gender")}]
            out.pop("settings", None)
            out["factories_config"] = safe_factories
        out["serverNow"] = datetime.now(timezone.utc).isoformat()
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
            if key == "ip_mappings":
                if not (module_access(who, "assets", write=True) or module_access(who, "tickets", write=True)):
                    return jsonify(error="You do not have write access to Device / IP mappings."), 403
                continue
            module = data_key_module(key)
            if not module or not module_access(who, module, write=True):
                return jsonify(error="You do not have write access to the %s module." % (module or "requested")), 403
    with db() as conn:
        for key in ("assets", "ip_mappings", "software", "departments", "maintenance", "parts_catalog", "parts_inventory", "parts_stock_entries", "parts_assignments", "vendors", "manual_users", "settings"):
            if key in body:
                value = body[key]
                if key == "ip_mappings":
                    if not isinstance(value, list):
                        return jsonify(error="ip_mappings must be a list."), 400
                    clean_ips = []
                    seen_ips = set()
                    for item in value[:1000]:
                        if not isinstance(item, dict):
                            continue
                        ip_str = str(item.get("ip") or item.get("ipAddress") or "").strip()
                        if not ip_str:
                            continue
                        try:
                            ipaddress.ip_address(ip_str)
                        except ValueError:
                            return jsonify(error=f"Invalid mapped IP address: {ip_str[:45]}"), 400
                        ip_key = ip_str.casefold()
                        if ip_key in seen_ips:
                            continue
                        seen_ips.add(ip_key)
                        clean_ips.append({
                            "ip": ip_str,
                            "name": str(item.get("name") or item.get("owner") or "").strip()[:120],
                            "dept": str(item.get("dept") or item.get("department") or "").strip()[:120],
                            "site": str(item.get("site") or item.get("factory") or "").strip()[:64],
                            "assetTag": str(item.get("assetTag") or "").strip()[:80],
                            "assetName": str(item.get("assetName") or "").strip()[:160],
                            "source": str(item.get("source") or "manual").strip()[:40],
                            "updatedAt": str(item.get("updatedAt") or "").strip()[:64],
                        })
                    value = clean_ips
                if key == "assets" and isinstance(value, list):
                    current = (conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone() or ([],))[0]
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
                        asset["remoteApp"] = str(asset.get("remoteApp") or "").strip()[:80]
                        asset["remoteId"] = str(asset.get("remoteId") or "").strip()[:120]
                        asset["remotePassword"] = str(asset.get("remotePassword") or "")[:256]
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
                        user["gender"] = _clean_gender(user.get("gender") if "gender" in user else prior.get("gender"))
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
                elif key == "settings" and isinstance(value, dict):
                    s_cur_row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
                    s_cur = dict(s_cur_row[0]) if s_cur_row and isinstance(s_cur_row[0], dict) else {}
                    merged_s = dict(value)
                    for keep_k in ("portalConfig", "complaintDesks", "showAllDesksOnPortal", "loginBranding", "uiFontFamily", "customFonts", "moduleLabels"):
                        if keep_k not in merged_s and keep_k in s_cur:
                            merged_s[keep_k] = s_cur[keep_k]
                    if "moduleLabels" in merged_s:
                        raw_ml = merged_s.get("moduleLabels")
                        clean_ml = {}
                        if isinstance(raw_ml, dict):
                            for mk, mv in list(raw_ml.items())[:60]:
                                k_str = re.sub(r"[^a-zA-Z0-9_-]+", "", str(mk or ""))[:40]
                                v_str = re.sub(r"\s+", " ", str(mv or "")).strip()[:60]
                                if k_str and v_str:
                                    clean_ml[k_str] = v_str
                        merged_s["moduleLabels"] = clean_ml
                    # Never let stale client localStorage overwrite saved login slideshow/logo assets
                    cur_lb = s_cur.get("loginBranding")
                    if isinstance(cur_lb, dict) and (cur_lb.get("slides") or cur_lb.get("logoUrl")):
                        inc_lb = merged_s.get("loginBranding")
                        preserved_lb = dict(cur_lb)
                        if isinstance(inc_lb, dict) and inc_lb.get("companyName"):
                            preserved_lb["companyName"] = inc_lb["companyName"]
                        elif merged_s.get("companyName"):
                            preserved_lb["companyName"] = merged_s["companyName"]
                        merged_s["loginBranding"] = preserved_lb
                    t_norm = normalize_ticketing_settings(merged_s)
                    merged_s["portalConfig"] = t_norm["portalConfig"]
                    value = merged_s
                if key == "parts_stock_entries" and isinstance(value, list):
                    cur_row = conn.execute("SELECT value FROM app_state WHERE key='parts_stock_entries' FOR UPDATE").fetchone()
                    existing_entries = list(cur_row[0]) if cur_row and isinstance(cur_row[0], list) else []
                    existing_by_id = {str(r.get("id") or ""): r for r in existing_entries if isinstance(r, dict) and r.get("id")}
                    actor_prof = session.get("profile") or {}
                    actor_name_e = str(actor_prof.get("name") or actor_prof.get("username") or "User").strip()[:120]
                    actor_user_e = str(actor_prof.get("username") or "").strip()[:80]
                    now_entry_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    is_admin_e = bool(session.get("is_admin"))
                    if not is_admin_e:
                        incoming_ids = {str(x.get("id") or "") for x in value if isinstance(x, dict) and x.get("id")}
                        for eid, old_e in existing_by_id.items():
                            if old_e.get("locked") and eid not in incoming_ids:
                                return jsonify(error="Audit protection: Locked stock intake entries cannot be deleted. Contact an Administrator."), 403
                    reconciled_entries = []
                    for item in value:
                        if not isinstance(item, dict):
                            continue
                        rec_e = dict(item)
                        eid = str(rec_e.get("id") or "").strip()[:100]
                        old_e = existing_by_id.get(eid)
                        if old_e and old_e.get("locked") and not is_admin_e:
                            # Preserve immutable audit core of locked stock entries while permitting linkedInvoiceIds sync
                            preserved_e = dict(old_e)
                            new_inv_ids = rec_e.get("linkedInvoiceIds")
                            if isinstance(new_inv_ids, list):
                                merged_invs = list(dict.fromkeys([str(x) for x in (old_e.get("linkedInvoiceIds") or [])] + [str(x) for x in new_inv_ids if str(x).strip()]))
                                preserved_e["linkedInvoiceIds"] = merged_invs[:40]
                            for chk_k in ("site", "vendor", "date"):
                                if chk_k in rec_e and str(rec_e.get(chk_k) or "") != str(old_e.get(chk_k) or ""):
                                    return jsonify(error=f"Audit protection: Locked stock intake entry {eid} cannot be modified."), 403
                            for chk_num in ("unitCost", "newQty", "repairedQty", "refurbishedQty", "damagedQty"):
                                if chk_num in rec_e:
                                    try:
                                        if abs(float(rec_e.get(chk_num) or 0) - float(old_e.get(chk_num) or 0)) > 1e-6:
                                            return jsonify(error=f"Audit protection: Locked stock intake entry {eid} numbers cannot be modified."), 403
                                    except (TypeError, ValueError):
                                        return jsonify(error=f"Audit protection: Locked stock intake entry {eid} numbers cannot be modified."), 403
                            if isinstance(rec_e.get("items"), list) and isinstance(old_e.get("items"), list):
                                if len(rec_e["items"]) != len(old_e["items"]) or any(a != b for a, b in zip(rec_e["items"], old_e["items"])):
                                    return jsonify(error=f"Audit protection: Items on locked stock intake entry {eid} cannot be altered."), 403
                            reconciled_entries.append(preserved_e)
                            continue
                        if rec_e.get("type") == "multi-intake":
                            items_list = rec_e.get("items")
                            if not isinstance(items_list, list) or not items_list:
                                return jsonify(error="Stock intake entry must contain at least one part line."), 400
                            clean_items = []
                            for pi in items_list[:100]:
                                if not isinstance(pi, dict):
                                    return jsonify(error="Invalid part line inside stock intake entry."), 400
                                try:
                                    q_val = int(pi.get("quantity", 0))
                                    uc_val = float(pi.get("unitCost", 0) or 0)
                                except (TypeError, ValueError):
                                    return jsonify(error="Stock intake quantities and costs must be valid numbers."), 400
                                if q_val < 1 or uc_val < 0:
                                    return jsonify(error="Stock intake quantities must be at least 1 and costs cannot be negative."), 400
                                pi_clean = dict(pi)
                                pi_clean["quantity"] = q_val
                                pi_clean["unitCost"] = round(uc_val, 2)
                                clean_items.append(pi_clean)
                            rec_e["items"] = clean_items
                            if not old_e:
                                rec_e["createdBy"] = actor_name_e
                                rec_e["createdByUsername"] = actor_user_e
                                rec_e["createdAt"] = now_entry_iso
                            rec_e["locked"] = True
                        reconciled_entries.append(rec_e)
                    value = reconciled_entries
                conn.execute("INSERT INTO app_state(key,value) VALUES(%s,%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (key, json.dumps(value)))
                if key in ("settings", "ip_mappings"):
                    _pg_emit_notify(conn, "pulse", {"source": key})
        if "factories_config" in body and isinstance(body["factories_config"], dict):
            s_row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
            settings_cur = dict(s_row[0]) if s_row and isinstance(s_row[0], dict) else {}
            for fk in ("factories", "factoryOrder", "removedFactoryCodes", "factoryTerm", "factoryTermPlural"):
                if fk in body["factories_config"]:
                    settings_cur[fk] = body["factories_config"][fk]
            conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(settings_cur),))
            _pg_emit_notify(conn, "pulse", {"source": "settings"})
    return jsonify(ok=True)


def ticket_json(row):
    return {
        "id": row[0], "kind": row[1], "username": row[2], "name": row[3], "dept": row[4], "site": row[5],
        "ip": str(row[6] or ""), "primary": row[7], "sub": row[8], "description": row[9], "material": row[10],
        "files": row[11], "assigned": row[12], "status": row[13],
        "eta": row[14].isoformat(timespec="minutes") if row[14] else "",
        "note": row[15],
        "updated": row[16].isoformat(timespec="minutes") if row[16] else "",
        "complaintDesk": (row[17] if len(row) > 17 and row[17] else "it"),
        "created": (row[18].isoformat(timespec="minutes") if len(row) > 18 and row[18] else (row[16].isoformat(timespec="minutes") if row[16] else "")),
        "createdAt": (row[18].isoformat(timespec="seconds") if len(row) > 18 and row[18] else ""),
        "firstRespondedAt": (row[19].isoformat(timespec="seconds") if len(row) > 19 and row[19] else ""),
        "requesterGender": (row[20] if len(row) > 20 and row[20] else ""),
    }


TICKET_COLUMNS = "id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,assigned_to,status,eta,note,updated_at,COALESCE(NULLIF(complaint_desk,''),'it'),created_at,first_responded_at,COALESCE(NULLIF(requester_gender,''),'')"


INVOICE_UPLOAD_DIR = UPLOAD_DIR / "invoices"
INVOICE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ASSET_UPLOAD_DIR = UPLOAD_DIR / "assets"
ASSET_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PARTS_UPLOAD_DIR = UPLOAD_DIR / "parts"
PARTS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
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


def _invoice_audit_val(key, val):
    if key in ("subtotal", "gst", "total"):
        try:
            num = round(float(val or 0), 2)
            return f"₹{num:,.2f}".rstrip("0").rstrip(".")
        except (TypeError, ValueError):
            return str(val or "0")
    s = str(val or "").strip()
    return s if s else "—"


def _invoice_materials_summary(mats):
    if not isinstance(mats, list) or not mats:
        return "None"
    parts = []
    for m in mats[:25]:
        if isinstance(m, dict):
            desc = str(m.get("description") or "Item").strip()[:60]
            q = m.get("quantity", 1)
            up = m.get("unitPrice", 0)
            gr = m.get("gstRate", 0)
            parts.append(f"{desc} × {q} @ ₹{up} (+{gr}% GST)")
    return "; ".join(parts) if parts else "None"


def _compute_invoice_diff(old_rec, new_rec, added_files_names=None):
    fields = (
        ("number", "Invoice No."),
        ("date", "Invoice Date"),
        ("invoiceType", "Bill Type"),
        ("entryCategory", "Entry Type"),
        ("vendor", "Vendor / Supplier"),
        ("requestedFor", "Requested For"),
        ("factory", "Factory"),
        ("department", "Department"),
        ("user", "Assigned User"),
        ("status", "Payment Status"),
        ("assetTag", "Linked Asset"),
        ("partEntryId", "Linked Part Entry"),
        ("subtotal", "Subtotal"),
        ("gst", "GST"),
        ("total", "Total"),
        ("notes", "Notes"),
    )
    changes = []
    for fk, lbl in fields:
        old_s = _invoice_audit_val(fk, old_rec.get(fk))
        new_s = _invoice_audit_val(fk, new_rec.get(fk))
        if old_s != new_s:
            changes.append({"field": lbl, "from": old_s[:160], "to": new_s[:160]})
    old_m = _invoice_materials_summary(old_rec.get("materials"))
    new_m = _invoice_materials_summary(new_rec.get("materials"))
    if old_m != new_m:
        changes.append({"field": "Line Items", "from": old_m[:240], "to": new_m[:240]})
    if added_files_names:
        changes.append({
            "field": "Attachments Added",
            "from": f"{len(old_rec.get('attachments') or [])} file(s)",
            "to": ", ".join(added_files_names)[:200],
        })
    return changes


def save_invoice_request(invoice_id=None):
    profile_chk = session.get("profile", {})
    if not session.get("is_admin") and not module_access(profile_chk, "billing", write=True):
        # Allow asset and parts managers to create/link purchase invoices while adding assets or parts stock entries
        try:
            _p_preview = json.loads(request.form.get("invoice", "{}") or "{}")
        except (TypeError, ValueError):
            _p_preview = {}
        can_asset = isinstance(_p_preview, dict) and (_p_preview.get("assetTag") or _p_preview.get("assetTags")) and module_access(profile_chk, "assets", write=True)
        can_part = isinstance(_p_preview, dict) and (_p_preview.get("partEntryId") or _p_preview.get("partTags") or str(_p_preview.get("entryCategory") or "").strip().lower() == "part") and module_access(profile_chk, "parts", write=True)
        if not (can_asset or can_part):
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
    profile = session.get("profile") or {}
    actor_name = str(profile.get("name") or profile.get("username") or "User").strip()[:120]
    actor_user = str(profile.get("username") or "").strip()[:80]
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    clean_payload = {
        k: v for k, v in payload.items()
        if k not in ("createdBy", "createdByUsername", "createdAt", "updatedBy", "updatedByUsername", "updatedAt", "editHistory", "lastChanges")
    }
    with db() as conn:
        rows = invoice_rows(conn)
        old = next((r for r in rows if r.get("id") == invoice_id), None) if invoice_id else None
        if invoice_id and not old:
            abort(404)
        added_names = [a[0] for a in attachments]
        if old:
            old_files = list(old.get("attachments", []))
            if len(old_files) + len(attachments) > 5:
                return jsonify(error="An invoice can have up to five attachments in total."), 400
            changes = _compute_invoice_diff(old, clean_payload, added_names)
            prev_hist = list(old.get("editHistory") if isinstance(old.get("editHistory"), list) else [])
            summary = "; ".join(f"{c['field']}: {c['from']} -> {c['to']}" for c in changes[:8]) if changes else "Saved without field modifications"
            prev_hist.insert(0, {
                "action": "updated",
                "at": now_iso,
                "by": actor_name,
                "username": actor_user,
                "summary": summary[:600],
                "changes": changes,
            })
            record = {
                **old,
                **clean_payload,
                "id": invoice_id,
                "attachments": old_files,
                "createdBy": old.get("createdBy") or actor_name,
                "createdByUsername": old.get("createdByUsername") or actor_user,
                "createdAt": old.get("createdAt") or now_iso,
                "updatedBy": actor_name,
                "updatedByUsername": actor_user,
                "updatedAt": now_iso,
                "lastChanges": changes,
                "editHistory": prev_hist[:100],
            }
        else:
            init_changes = [{"field": "Total", "from": "—", "to": _invoice_audit_val("total", clean_payload.get("total"))}]
            if added_names:
                init_changes.append({"field": "Attachments", "from": "0", "to": ", ".join(added_names)[:200]})
            record = {
                **clean_payload,
                "id": "inv-" + uuid.uuid4().hex,
                "attachments": [],
                "createdBy": actor_name,
                "createdByUsername": actor_user,
                "createdAt": now_iso,
                "updatedBy": actor_name,
                "updatedByUsername": actor_user,
                "updatedAt": now_iso,
                "lastChanges": init_changes,
                "editHistory": [{
                    "action": "created",
                    "at": now_iso,
                    "by": actor_name,
                    "username": actor_user,
                    "summary": f"Created invoice {number} ({_invoice_audit_val('total', clean_payload.get('total'))})",
                    "changes": init_changes,
                }],
            }
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
        linked_part_id = str(record.get("partEntryId") or "").strip()
        if linked_part_id:
            pe_row = conn.execute("SELECT value FROM app_state WHERE key='parts_stock_entries' FOR UPDATE").fetchone()
            if pe_row and isinstance(pe_row[0], list):
                pe_list = list(pe_row[0])
                pe_target = next((pe for pe in pe_list if isinstance(pe, dict) and str(pe.get("id") or "").strip().lower() == linked_part_id.lower()), None)
                if pe_target is not None:
                    cur_ids = list(pe_target.get("linkedInvoiceIds") or [])
                    if str(record["id"]) not in cur_ids:
                        cur_ids.append(str(record["id"]))
                        pe_target["linkedInvoiceIds"] = cur_ids
                        conn.execute("INSERT INTO app_state(key,value) VALUES('parts_stock_entries',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()", (json.dumps(pe_list),))
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
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
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


def _safe_asset_dir_key(asset_tag):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(asset_tag or "").strip())[:80]
    return cleaned.strip("._") or "asset"


def _validate_media_upload(upload):
    ext = Path(secure_filename(upload.filename)).suffix.lower()
    if ext not in INVOICE_EXTENSIONS:
        raise ValueError("Unsupported file format.")
    data = upload.stream.read(10 * 1024 * 1024 + 1)
    if not data or len(data) > 10 * 1024 * 1024:
        raise ValueError("Each file must be 10 MB or smaller.")
    if ext == ".pdf" and not data.startswith(b"%PDF-"):
        raise ValueError("The PDF file is invalid.")
    if ext in (".jpg", ".jpeg") and not data.startswith(b"\xff\xd8\xff"):
        raise ValueError("The JPEG image is invalid.")
    if ext == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("The PNG image is invalid.")
    if ext == ".webp" and not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        raise ValueError("The WebP image is invalid.")
    safe_name = secure_filename(upload.filename)[:150] or ("asset-photo" + ext)
    return safe_name, ext, data, (upload.mimetype or "application/octet-stream")


@app.post("/api/assets/<path:asset_tag>/files")
@signed_in
def upload_asset_files(asset_tag):
    profile = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(profile, "assets", write=True):
        abort(403)
    files = [f for f in request.files.getlist("files") if f and f.filename]
    if not files:
        return jsonify(error="Select at least one image or file to upload."), 400
    if len(files) > 5:
        return jsonify(error="Upload up to 5 files per asset."), 400
    dir_key = _safe_asset_dir_key(asset_tag)
    validated = []
    try:
        for f in files:
            validated.append(_validate_media_upload(f))
    except ValueError as err:
        return jsonify(error=str(err)), 400

    with db() as conn:
        arow = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
        asset_list = list(arow[0]) if arow and isinstance(arow[0], list) else []
        target_asset = next((a for a in asset_list if isinstance(a, dict) and str(a.get("tag") or "").strip().lower() == str(asset_tag or "").strip().lower()), None)
        existing_photos = list(target_asset.get("photos") or []) if target_asset else []
        if len(existing_photos) + len(validated) > 5:
            return jsonify(error="Each asset can keep up to 5 photos/files total."), 400
        folder = (ASSET_UPLOAD_DIR / dir_key).resolve()
        if not folder.is_relative_to(ASSET_UPLOAD_DIR.resolve()):
            abort(400)
        folder.mkdir(parents=True, exist_ok=True)
        added = []
        for safe_name, ext, data, mime_type in validated:
            stored = uuid.uuid4().hex + ext
            (folder / stored).write_bytes(data)
            added.append({
                "name": safe_name,
                "file": stored,
                "size": len(data),
                "type": mime_type,
                "dirKey": dir_key,
                "uploadedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
        merged_photos = existing_photos + added
        if target_asset is not None:
            target_asset["photos"] = merged_photos
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES('assets',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()",
                (json.dumps(asset_list),),
            )
    return jsonify(ok=True, photos=merged_photos, added=added), 201


@app.get("/api/assets/<path:asset_tag>/files/<path:filename>")
@signed_in
def get_asset_file(asset_tag, filename):
    profile = session.get("profile") or {}
    if not session.get("is_admin") and not any(module_access(profile, m) for m in ("assets", "data_center", "surveillance", "overview", "maintenance", "billing", "reports")):
        abort(403)
    dir_key = _safe_asset_dir_key(asset_tag)
    base = (ASSET_UPLOAD_DIR / dir_key).resolve()
    clean_name = Path(filename).name
    target = (base / clean_name).resolve()
    if not base.is_relative_to(ASSET_UPLOAD_DIR.resolve()) or not target.is_relative_to(base) or not target.is_file():
        abort(404)
    inline_types = {
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".avif": "image/avif",
        ".svg": "image/svg+xml",
        ".tif": "image/tiff",
        ".tiff": "image/tiff",
        ".heic": "image/heic",
        ".heif": "image/heif",
    }
    ext = Path(clean_name).suffix.lower()
    inline_mime = inline_types.get(ext)
    response = send_from_directory(
        base,
        clean_name,
        as_attachment=inline_mime is None,
        download_name=clean_name,
        mimetype=inline_mime,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    if ext == ".svg":
        response.headers["Content-Security-Policy"] = "sandbox"
    return response


@app.delete("/api/assets/<path:asset_tag>/files/<path:filename>")
@signed_in
def delete_asset_file(asset_tag, filename):
    profile = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(profile, "assets", write=True):
        abort(403)
    dir_key = _safe_asset_dir_key(asset_tag)
    base = (ASSET_UPLOAD_DIR / dir_key).resolve()
    clean_name = Path(filename).name
    target = (base / clean_name).resolve()
    if not base.is_relative_to(ASSET_UPLOAD_DIR.resolve()) or not target.is_relative_to(base):
        abort(400)
    if target.is_file():
        target.unlink()
    remaining_photos = None
    with db() as conn:
        arow = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
        if arow and isinstance(arow[0], list):
            asset_list = list(arow[0])
            target_asset = next((a for a in asset_list if isinstance(a, dict) and str(a.get("tag") or "").strip().lower() == str(asset_tag or "").strip().lower()), None)
            if target_asset and isinstance(target_asset.get("photos"), list):
                target_asset["photos"] = [p for p in target_asset["photos"] if str(p.get("file") or "") != clean_name]
                remaining_photos = target_asset["photos"]
                conn.execute(
                    "INSERT INTO app_state(key,value) VALUES('assets',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()",
                    (json.dumps(asset_list),),
                )
    return jsonify(ok=True, photos=remaining_photos if remaining_photos is not None else [])


@app.post("/api/parts/entries/<path:entry_id>/files")
@signed_in
def upload_part_entry_files(entry_id):
    profile = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(profile, "parts", write=True):
        abort(403)
    files = [f for f in request.files.getlist("files") if f and f.filename]
    if not files:
        return jsonify(error="Select at least one image or file to upload."), 400
    if len(files) > 5:
        return jsonify(error="Upload up to 5 files per stock entry."), 400
    dir_key = _safe_asset_dir_key(entry_id)
    validated = []
    try:
        for f in files:
            validated.append(_validate_media_upload(f))
    except ValueError as err:
        return jsonify(error=str(err)), 400

    with db() as conn:
        erow = conn.execute("SELECT value FROM app_state WHERE key='parts_stock_entries' FOR UPDATE").fetchone()
        entry_list = list(erow[0]) if erow and isinstance(erow[0], list) else []
        target_entry = next((e for e in entry_list if isinstance(e, dict) and str(e.get("id") or "").strip().lower() == str(entry_id or "").strip().lower()), None)
        existing_photos = list(target_entry.get("photos") or []) if target_entry else []
        if len(existing_photos) + len(validated) > 5:
            return jsonify(error="Each stock entry can keep up to 5 photos/files total."), 400
        folder = (PARTS_UPLOAD_DIR / dir_key).resolve()
        if not folder.is_relative_to(PARTS_UPLOAD_DIR.resolve()):
            abort(400)
        folder.mkdir(parents=True, exist_ok=True)
        added = []
        for safe_name, ext, data, mime_type in validated:
            stored = uuid.uuid4().hex + ext
            (folder / stored).write_bytes(data)
            added.append({
                "name": safe_name,
                "file": stored,
                "size": len(data),
                "type": mime_type,
                "dirKey": dir_key,
                "uploadedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
        merged_photos = existing_photos + added
        if target_entry is not None:
            target_entry["photos"] = merged_photos
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES('parts_stock_entries',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()",
                (json.dumps(entry_list),),
            )
    return jsonify(ok=True, photos=merged_photos, added=added), 201


@app.get("/api/parts/entries/<path:entry_id>/files/<path:filename>")
@signed_in
def get_part_entry_file(entry_id, filename):
    profile = session.get("profile") or {}
    if not session.get("is_admin") and not any(module_access(profile, m) for m in ("parts", "billing", "valuation", "reports", "maintenance", "overview")):
        abort(403)
    dir_key = _safe_asset_dir_key(entry_id)
    base = (PARTS_UPLOAD_DIR / dir_key).resolve()
    clean_name = Path(filename).name
    target = (base / clean_name).resolve()
    if not base.is_relative_to(PARTS_UPLOAD_DIR.resolve()) or not target.is_relative_to(base) or not target.is_file():
        abort(404)
    inline_types = {
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".avif": "image/avif",
        ".svg": "image/svg+xml",
        ".tif": "image/tiff",
        ".tiff": "image/tiff",
        ".heic": "image/heic",
        ".heif": "image/heif",
    }
    ext = Path(clean_name).suffix.lower()
    inline_mime = inline_types.get(ext)
    response = send_from_directory(
        base,
        clean_name,
        as_attachment=inline_mime is None,
        download_name=clean_name,
        mimetype=inline_mime,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    if ext == ".svg":
        response.headers["Content-Security-Policy"] = "sandbox"
    return response


@app.delete("/api/parts/entries/<path:entry_id>/files/<path:filename>")
@signed_in
def delete_part_entry_file(entry_id, filename):
    profile = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(profile, "parts", write=True):
        abort(403)
    dir_key = _safe_asset_dir_key(entry_id)
    base = (PARTS_UPLOAD_DIR / dir_key).resolve()
    clean_name = Path(filename).name
    target = (base / clean_name).resolve()
    if not base.is_relative_to(PARTS_UPLOAD_DIR.resolve()) or not target.is_relative_to(base):
        abort(400)
    with db() as conn:
        erow = conn.execute("SELECT value FROM app_state WHERE key='parts_stock_entries' FOR UPDATE").fetchone()
        if erow and isinstance(erow[0], list):
            entry_list = list(erow[0])
            target_entry = next((e for e in entry_list if isinstance(e, dict) and str(e.get("id") or "").strip().lower() == str(entry_id or "").strip().lower()), None)
            if target_entry and target_entry.get("locked") and not session.get("is_admin"):
                return jsonify(error="Audit protection: Cannot delete proof files from a locked stock entry."), 403
            if target.is_file():
                target.unlink()
            remaining_photos = None
            if target_entry and isinstance(target_entry.get("photos"), list):
                target_entry["photos"] = [p for p in target_entry["photos"] if str(p.get("file") or "") != clean_name]
                remaining_photos = target_entry["photos"]
                conn.execute(
                    "INSERT INTO app_state(key,value) VALUES('parts_stock_entries',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()",
                    (json.dumps(entry_list),),
                )
            return jsonify(ok=True, photos=remaining_photos if remaining_photos is not None else [])
    if target.is_file():
        target.unlink()
    return jsonify(ok=True, photos=[])


def _load_ticket_reopen_map(conn):
    try:
        row = conn.execute("SELECT value FROM app_state WHERE key='ticket_reopen_meta'").fetchone()
        return dict(row[0]) if row and isinstance(row[0], dict) else {}
    except Exception:
        return {}


def _record_ticket_reopen_meta(conn, ticket_id, actor, reason, desk_id="it", prev_status="Closed"):
    tid = str(ticket_id or "").strip()
    if not tid:
        return {}
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        row = conn.execute("SELECT value FROM app_state WHERE key='ticket_reopen_meta' FOR UPDATE").fetchone()
        doc = dict(row[0]) if row and isinstance(row[0], dict) else {}
        cur = doc.get(tid) if isinstance(doc.get(tid), dict) else {}
        hist = list(cur.get("history") or [])
        hist.insert(0, {
            "at": now_iso,
            "by": str(actor or "User")[:120],
            "reason": str(reason or "")[:400],
            "fromStatus": str(prev_status or "Closed")[:40],
        })
        entry = {
            "reopenCount": int(cur.get("reopenCount") or 0) + 1,
            "lastReopenedAt": now_iso,
            "lastReopenedBy": str(actor or "User")[:120],
            "lastReason": str(reason or "")[:400],
            "desk": _slug_desk_id(desk_id or "it", fallback="it"),
            "history": hist[:25],
        }
        doc[tid] = entry
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('ticket_reopen_meta',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(doc),),
        )
        return entry
    except Exception:
        return {"reopenCount": 1, "lastReopenedAt": now_iso, "lastReopenedBy": str(actor or "User")[:120], "lastReason": str(reason or "")[:400]}


@app.get("/api/tickets")
@signed_in
def list_tickets():
    profile = session.get("profile", {})
    is_adm = bool(session.get("is_admin"))
    can_tickets = is_adm or module_access(profile, "tickets")
    uname_cf = str(profile.get("username") or "").strip().casefold()
    dname_cf = str(profile.get("name") or "").strip().casefold()
    req_desk = str(request.args.get("desk") or "").strip().lower()
    with db() as conn:
        rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 1000").fetchall()
        repair_map = repair_map_from_conn(conn)
        issued_map = issued_parts_map_from_conn(conn)
        reopen_map = _load_ticket_reopen_map(conn)
    filtered = []
    for r in rows:
        desk_id = (r[17] if len(r) > 17 and r[17] else "it")
        row_uname = str(r[2] or "").strip().casefold()
        row_dname = str(r[3] or "").strip().casefold()
        is_owner = (uname_cf and row_uname == uname_cf) or (dname_cf and row_dname == dname_cf)
        if not is_owner and (not can_tickets or not ticket_desk_allowed(profile, desk_id)):
            continue
        if req_desk and req_desk != "all" and _slug_desk_id(desk_id, "it") != _slug_desk_id(req_desk, "it"):
            continue
        rm = reopen_map.get(r[0]) if isinstance(reopen_map.get(r[0]), dict) else None
        reopen_cnt = int(rm.get("reopenCount") or 0) if rm else 0
        filtered.append({
            **ticket_json(r),
            "repair": repair_map.get(r[0]),
            "issuedParts": issued_map.get(r[0], []),
            "isOwn": is_owner,
            "isReopened": reopen_cnt > 0,
            "reopenCount": reopen_cnt,
            "reopenedAt": str(rm.get("lastReopenedAt") or "") if rm else "",
            "reopenedBy": str(rm.get("lastReopenedBy") or "") if rm else "",
            "reopenReason": str(rm.get("lastReason") or "") if rm else "",
            "reopenHistory": list(rm.get("history") or []) if rm else [],
        })
    return jsonify(tickets=filtered)


@app.post("/api/tickets/<path:ticket_id>/return")
@signed_in
def return_reopen_ticket(ticket_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    dname = str(profile.get("name") or "").strip().casefold()
    actor = str(profile.get("name") or uname or "User")[:120]
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "Issue recurred — returned by user").strip()[:400]
    if not reason:
        reason = "Issue recurred — returned by user"

    with db() as conn:
        t_row = conn.execute(
            "SELECT COALESCE(NULLIF(complaint_desk,''),'it'),assigned_to,status,eta,note,username,display_name,factory,kind FROM tickets WHERE id=%s FOR UPDATE",
            (ticket_id,),
        ).fetchone()
        if not t_row:
            return jsonify(error="Ticket not found."), 404
        desk_id = str(t_row[0] or "it")
        old_assigned = str(t_row[1] or "Unassigned")
        old_status = str(t_row[2] or "Open")
        t_user = str(t_row[5] or "")
        t_disp = str(t_row[6] or "")
        t_fac = str(t_row[7] or "")
        t_kind = str(t_row[8] or "")

        is_owner = (uname and t_user.strip().casefold() == uname) or (dname and t_disp.strip().casefold() == dname)
        is_staff = is_adm or profile.get("role") == "IT Ticketing" or (module_access(profile, "tickets", write=True) and ticket_desk_allowed(profile, desk_id))
        if not is_owner and not is_staff:
            return jsonify(error="Only the ticket requester or authorized department staff can return/reopen this ticket."), 403
        if old_status not in ("Closed", "Resolved"):
            return jsonify(error=f"Only Closed or Resolved tickets can be returned (current status: {old_status})."), 400

        note_txt = f"[Returned / Re-opened] {reason}"[:1000]
        conn.execute("UPDATE tickets SET status='Open', note=%s, updated_at=now() WHERE id=%s", (note_txt, ticket_id))
        conn.execute(
            "INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'reopened',%s)",
            (ticket_id, actor, f"Returned / Re-opened from {old_status}: {reason}"[:1000]),
        )
        reopen_meta = _record_ticket_reopen_meta(conn, ticket_id, actor, reason, desk_id=desk_id, prev_status=old_status)
        _on_ticket_status_changed(conn, ticket_id, "Open")
        notif = _build_and_record_ticket_user_notification(
            conn,
            ticket_id=ticket_id,
            event_type="status_change",
            actor=actor,
            assigned_to=old_assigned,
            status="Open",
            note=note_txt,
        )
        is_mr = (t_kind == "Material request")
        _record_notification_event(conn, {
            "eventKey": f"tkt-return:{ticket_id}:{reopen_meta.get('reopenCount', 1)}:{uuid.uuid4().hex[:6]}",
            "kind": "material_request" if is_mr else "ticket",
            "level": "warn",
            "title": f"↩ Returned / Re-opened #{reopen_meta.get('reopenCount', 1)} · {ticket_id}",
            "body": f"{actor} returned this ticket to Open: {reason}",
            "factory": t_fac,
            "targetView": "ticketing",
            "targetTab": "materials" if is_mr else "tickets",
            "targetId": ticket_id,
            "targetTicketId": ticket_id,
            "targetAssignee": old_assigned,
            "requesterName": t_disp,
            "complaintDesk": desk_id,
        })
        _pg_emit_notify(conn, "ticket", {"action": "return", "ticketId": ticket_id, "complaintDesk": desk_id, "reopenCount": reopen_meta.get("reopenCount", 1)})
    return jsonify(ok=True, ticketId=ticket_id, status="Open", reopenMeta=reopen_meta, notification=notif)


@app.get("/api/tickets/remote-directory")
@ticket_manager
def ticket_remote_directory():
    profile = session.get("profile", {})
    if not (session.get("is_admin") or profile.get("role") == "IT Ticketing" or module_access(profile, "tickets", write=True) or module_access(profile, "assets")):
        return jsonify(error="Ticketing manager or Assets access is required to view remote desktop credentials."), 403
    with db() as conn:
        arow = conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone()
    assets_list = arow[0] if arow and isinstance(arow[0], list) else []
    out = []
    for a in assets_list:
        if not isinstance(a, dict):
            continue
        r_app = str(a.get("remoteApp") or "").strip()
        r_id = str(a.get("remoteId") or "").strip()
        r_pw = str(a.get("remotePassword") or "")
        ip_val = str(a.get("ipAddress") or a.get("ip_address") or "").strip()
        if r_app or r_id or r_pw or ip_val:
            out.append({
                "tag": str(a.get("tag") or "")[:100],
                "name": str(a.get("name") or "")[:160],
                "type": str(a.get("type") or "")[:60],
                "subtype": str(a.get("subtype") or "")[:60],
                "owner": str(a.get("owner") or "")[:120],
                "dept": str(a.get("dept") or "")[:120],
                "site": str(a.get("site") or "")[:40],
                "ipAddress": ip_val[:45],
                "remoteApp": r_app[:80],
                "remoteId": r_id[:120],
                "remotePassword": r_pw[:256],
            })
    return jsonify(devices=out)


def _default_shortcuts_for_profile(profile):
    allowed = allowed_complaint_desks_for(profile)
    desks = set(allowed) if isinstance(allowed, set) else set()
    if desks == {"plumber"}:
        return ["Pipe / Tap Leakage", "Valve Replacement", "Drainage Blockage", "Pump / Motor Check", "Water Supply Check"]
    if desks == {"electrician"}:
        return ["Power / MCB Tripping", "Lighting Fault", "Panel / Wiring Work", "DG / UPS Check", "Machine Power Issue"]
    if desks == {"admin"}:
        return ["AC / HVAC Check", "Housekeeping Support", "Furniture Repair", "Security / Gate Check", "Facility Work"]
    return ["Fixing Printer", "Configuring Network Switch", "PC / Software Issue", "CCTV / NVR Check", "Server / Firewall Work"]


def _clean_task_shortcuts(raw):
    if not isinstance(raw, list):
        return []
    out = []
    seen = set()
    for item in raw[:20]:
        s = str(item or "").strip()[:60]
        if s and s.casefold() not in seen:
            seen.add(s.casefold())
            out.append(s)
    return out


@app.get("/api/tickets/admin-presence")
@signed_in
def get_admin_presence():
    profile = session.get("profile") or {}
    ukey = str(profile.get("username") or "").strip().casefold()
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='admin_presence'").fetchone()
        sc_row = conn.execute("SELECT value FROM app_state WHERE key='admin_presence_shortcuts'").fetchone()
    pres_map = _clean_admin_presence_map(row[0] if row else {})
    sc_map = sc_row[0] if sc_row and isinstance(sc_row[0], dict) else {}
    custom_sc = sc_map.get(ukey) if isinstance(sc_map.get(ukey), list) else None
    my_shortcuts = _clean_task_shortcuts(custom_sc) if custom_sc is not None else _default_shortcuts_for_profile(profile)
    entries = sorted(pres_map.values(), key=lambda p: ({"Available": 0, "In work": 1, "Away": 2, "Offline": 3}.get(p["status"], 4), p["name"].casefold()))
    my_entry = pres_map.get(ukey) or {
        "username": ukey,
        "name": str(profile.get("name") or ukey),
        "gender": _clean_gender(profile.get("gender")),
        "status": "Available",
        "currentTask": "",
        "etaMinutes": 0,
        "etaRemainingMin": 0,
        "busyUntil": "",
        "isBusyExpired": False,
        "desks": sorted(allowed_complaint_desks_for(profile)) if allowed_complaint_desks_for(profile) is not None else ["*"],
        "updatedAt": "",
    }
    return jsonify(presence=entries, myPresence=my_entry, myShortcuts=my_shortcuts, defaultShortcuts=_default_shortcuts_for_profile(profile))


@app.put("/api/tickets/admin-presence")
@ticket_manager
def update_admin_presence():
    profile = session.get("profile") or {}
    if not (session.get("is_admin") or profile.get("role") == "IT Ticketing" or module_access(profile, "tickets", write=True)):
        return jsonify(error="Ticket administrator or Ticketing write access is required."), 403
    body = request.get_json(silent=True) or {}
    ukey = str(profile.get("username") or "").strip().casefold()
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='admin_presence' FOR UPDATE").fetchone()
        pres_map = _clean_admin_presence_map(row[0] if row else {})
        sc_row = conn.execute("SELECT value FROM app_state WHERE key='admin_presence_shortcuts' FOR UPDATE").fetchone()
        sc_map = dict(sc_row[0]) if sc_row and isinstance(sc_row[0], dict) else {}

        if "taskShortcuts" in body:
            if body["taskShortcuts"] is None:
                sc_map.pop(ukey, None)
            else:
                sc_map[ukey] = _clean_task_shortcuts(body["taskShortcuts"])
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES('admin_presence_shortcuts',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
                (json.dumps(sc_map),),
            )

        prev_entry = pres_map.get(ukey) or {}
        if "status" in body or "currentTask" in body or "etaMinutes" in body:
            status = str(body.get("status") or prev_entry.get("status") or "Available").strip()
            if status not in ("Available", "In work", "Away", "Offline"):
                return jsonify(error="Status must be Available, In work, Away, or Offline."), 400
            current_task = str(body.get("currentTask") if "currentTask" in body else prev_entry.get("currentTask", "")).strip()[:240]
            try:
                eta_min = max(0, min(1440, int(body.get("etaMinutes") if "etaMinutes" in body else prev_entry.get("etaMinutes", 0))))
            except (TypeError, ValueError):
                return jsonify(error="ETA minutes must be a whole number."), 400
            if status in ("Available", "Offline") and "etaMinutes" not in body:
                eta_min = 0
            now_utc = datetime.now(timezone.utc)
            busy_until = (now_utc + timedelta(minutes=eta_min)).isoformat(timespec="seconds") if (status in ("In work", "Away") and eta_min > 0) else ""
            allowed_desks = allowed_complaint_desks_for(profile)
            desks_list = sorted(allowed_desks) if allowed_desks is not None else ["*"]
            contact = _lookup_requester_contact(conn, ukey, profile.get("name", ""))
            pres_map[ukey] = {
                "username": ukey,
                "name": str(profile.get("name") or ukey).strip()[:120] or ukey,
                "gender": contact["gender"],
                "status": status,
                "currentTask": "" if status == "Available" and not current_task else current_task,
                "etaMinutes": 0 if status == "Available" else eta_min,
                "busyUntil": "" if status == "Available" else busy_until,
                "desks": desks_list,
                "updatedAt": now_utc.isoformat(timespec="seconds"),
            }
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES('admin_presence',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
                (json.dumps(pres_map),),
            )
            _pg_emit_notify(conn, "ticket", {"action": "presence", "username": ukey, "status": status})

        clean_map = _clean_admin_presence_map(pres_map)
        custom_sc = sc_map.get(ukey) if isinstance(sc_map.get(ukey), list) else None
        my_shortcuts = _clean_task_shortcuts(custom_sc) if custom_sc is not None else _default_shortcuts_for_profile(profile)
    entries = sorted(clean_map.values(), key=lambda p: ({"Available": 0, "In work": 1, "Away": 2, "Offline": 3}.get(p["status"], 4), p["name"].casefold()))
    return jsonify(ok=True, presence=entries, myPresence=clean_map.get(ukey), myShortcuts=my_shortcuts, defaultShortcuts=_default_shortcuts_for_profile(profile))


@app.get("/api/tickets/user-notifications")
@signed_in
def list_ticket_user_notifications():
    profile = session.get("profile") or {}
    ticket_id = str(request.args.get("ticket_id") or "").strip()
    mine_only = str(request.args.get("mine") or "").strip() in ("1", "true", "yes")
    uname = str(profile.get("username") or "").strip().casefold()
    dname = str(profile.get("name") or "").strip().casefold()
    can_manage = bool(session.get("is_admin") or module_access(profile, "tickets"))
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='ticket_user_notifications'").fetchone()
    raw = row[0] if row and isinstance(row[0], list) else []
    out = []
    for n in raw:
        if not isinstance(n, dict):
            continue
        if ticket_id and str(n.get("ticketId") or "") != ticket_id:
            continue
        is_owner = (uname and str(n.get("requesterUsername") or "").casefold() == uname) or (dname and str(n.get("requesterName") or "").casefold() == dname)
        if not ticket_id and not is_owner:
            continue
        if mine_only and not is_owner:
            continue
        if not can_manage and not is_owner:
            continue
        if can_manage and not session.get("is_admin") and not ticket_desk_allowed(profile, n.get("complaintDesk") or "it") and not is_owner:
            continue
        clean = dict(n)
        clean.pop("trackingTokenHash", None)
        out.append(clean)
        if len(out) >= 100:
            break
    return jsonify(notifications=out)


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


@app.put("/api/admin/portal-config")
@administrator
def update_portal_config():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid portal configuration payload."), 400
    patch = body.get("portalConfig") if isinstance(body.get("portalConfig"), dict) else body
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        settings_val = dict(row[0]) if row and isinstance(row[0], dict) else {}
        cur_pc = settings_val.get("portalConfig") if isinstance(settings_val.get("portalConfig"), dict) else {}
        merged_pc = {**cur_pc, **patch}
        if isinstance(patch.get("tiles"), list):
            if "showVisitorPass" not in patch:
                for tl in patch["tiles"]:
                    if isinstance(tl, dict) and tl.get("id") == "visitor":
                        merged_pc["showVisitorPass"] = bool(tl.get("visible", True))
                        break
            if "showMaterialGate" not in patch:
                for tl in patch["tiles"]:
                    if isinstance(tl, dict) and tl.get("id") == "gatepass":
                        merged_pc["showMaterialGate"] = bool(tl.get("visible", True))
                        break
        settings_val["portalConfig"] = merged_pc
        normalized = normalize_ticketing_settings(settings_val)
        settings_val["portalConfig"] = normalized["portalConfig"]
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(settings_val),),
        )
        _pg_emit_notify(conn, "pulse", {"source": "settings"})
    return jsonify(ok=True, portalConfig=normalized["portalConfig"])


# =============================================================================
# DYNAMIC TICKET STATUS UPDATE REMINDERS (ORG / DESK / CATEGORY / PER-USER)
# =============================================================================
TICKET_REMINDER_STATUSES = ("Open", "In progress", "Resolved")

DEFAULT_TICKET_REMINDER_STATUSES = {
    "Open": {
        "enabled": True,
        "initialDelayMinutes": 60,
        "repeatEveryMinutes": 60,
        "maxReminders": 0,
        "message": "Please update status on {ticket_id} ({status}) — {category}: {summary}",
    },
    "In progress": {
        "enabled": True,
        "initialDelayMinutes": 60,
        "repeatEveryMinutes": 60,
        "maxReminders": 0,
        "message": "Please update progress / status on {ticket_id} ({status}) — {category}: {summary}",
    },
    "Resolved": {
        "enabled": True,
        "initialDelayMinutes": 60,
        "repeatEveryMinutes": 60,
        "maxReminders": 0,
        "message": "Please verify & close {ticket_id} ({status}) — {category}: {summary}",
    },
}


def _format_elapsed_duration(seconds):
    try:
        secs = max(0, int(round(float(seconds or 0))))
    except (TypeError, ValueError):
        secs = 0
    if secs < 5:
        return "under 1 min"
    if secs < 60:
        return f"{secs} sec" + ("" if secs == 1 else "s")
    mins_total = secs // 60
    if mins_total < 60:
        return f"{mins_total} min" + ("" if mins_total == 1 else "s")
    hrs_total = mins_total // 60
    rem_mins = mins_total % 60
    if hrs_total < 24:
        h_txt = f"{hrs_total} hr" + ("" if hrs_total == 1 else "s")
        return f"{h_txt} {rem_mins} min" + ("" if rem_mins == 1 else "s") if rem_mins else h_txt
    days = hrs_total // 24
    rem_hrs = hrs_total % 24
    d_txt = f"{days} day" + ("" if days == 1 else "s")
    if rem_hrs:
        h_txt = f"{rem_hrs} hr" + ("" if rem_hrs == 1 else "s")
        return f"{d_txt} {h_txt}"
    return d_txt


def _clamp_int(val, default, lo, hi):
    try:
        n = int(float(val))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _clean_username_list(raw):
    if not isinstance(raw, list):
        return []
    out = []
    seen = set()
    for item in raw[:60]:
        u = str(item or "").strip().casefold()[:80]
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _normalize_reminder_status_cfg(raw, fallback):
    src = raw if isinstance(raw, dict) else {}
    fb = fallback if isinstance(fallback, dict) else DEFAULT_TICKET_REMINDER_STATUSES["Open"]
    msg = str(src.get("message") if "message" in src else fb.get("message") or "").strip()[:240]
    if not msg:
        msg = str(fb.get("message") or "Please update status on {ticket_id} ({status})")[:240]
    return {
        "enabled": bool(src.get("enabled", fb.get("enabled", True))),
        "initialDelayMinutes": _clamp_int(
            src.get("initialDelayMinutes", fb.get("initialDelayMinutes", 60)),
            int(fb.get("initialDelayMinutes", 60)),
            1,
            10080,
        ),
        "repeatEveryMinutes": _clamp_int(
            src.get("repeatEveryMinutes", fb.get("repeatEveryMinutes", 60)),
            int(fb.get("repeatEveryMinutes", 60)),
            1,
            10080,
        ),
        "maxReminders": _clamp_int(
            src.get("maxReminders", fb.get("maxReminders", 0)),
            int(fb.get("maxReminders", 0)),
            0,
            200,
        ),
        "message": msg,
    }


def _normalize_reminder_statuses_map(raw, fallback_map=None):
    src = raw if isinstance(raw, dict) else {}
    fb = fallback_map if isinstance(fallback_map, dict) else DEFAULT_TICKET_REMINDER_STATUSES
    return {
        st: _normalize_reminder_status_cfg(src.get(st), fb.get(st, DEFAULT_TICKET_REMINDER_STATUSES[st]))
        for st in TICKET_REMINDER_STATUSES
    }


def _normalize_user_reminder_pref(raw, fallback_statuses=None):
    src = raw if isinstance(raw, dict) else {}
    scope = str(src.get("scope") or "desk").strip().lower()
    if scope not in ("assigned", "desk", "all"):
        scope = "desk"
    return {
        "enabled": bool(src.get("enabled", True)),
        "useCustom": bool(src.get("useCustom", False)),
        "scope": scope,
        "statuses": _normalize_reminder_statuses_map(src.get("statuses"), fallback_statuses or DEFAULT_TICKET_REMINDER_STATUSES),
        "updatedAt": str(src.get("updatedAt") or "")[:40],
    }


def normalize_ticket_status_reminders(raw):
    src = raw if isinstance(raw, dict) else {}
    raw_global = src.get("globalDefaults") if isinstance(src.get("globalDefaults"), dict) else {}
    global_statuses = _normalize_reminder_statuses_map(raw_global.get("statuses"), DEFAULT_TICKET_REMINDER_STATUSES)
    global_defaults = {
        "enabled": bool(raw_global.get("enabled", True)),
        "notifyAssignee": bool(raw_global.get("notifyAssignee", True)),
        "notifyDeskTeam": bool(raw_global.get("notifyDeskTeam", True)),
        "statuses": global_statuses,
    }

    raw_desks = src.get("deskRules") if isinstance(src.get("deskRules"), dict) else {}
    clean_desks = {}
    for dk, dv in list(raw_desks.items())[:40]:
        if not isinstance(dv, dict):
            continue
        did = _slug_desk_id(dk, fallback="")
        if not did:
            continue
        clean_desks[did] = {
            "enabled": bool(dv.get("enabled", True)),
            "overrideTiming": bool(dv.get("overrideTiming", False)),
            "notifyAssignee": bool(dv.get("notifyAssignee", global_defaults["notifyAssignee"])),
            "notifyDeskTeam": bool(dv.get("notifyDeskTeam", global_defaults["notifyDeskTeam"])),
            "extraRecipients": _clean_username_list(dv.get("extraRecipients") or dv.get("recipients")),
            "statuses": _normalize_reminder_statuses_map(dv.get("statuses"), global_statuses),
        }

    raw_cat_rules = src.get("categoryRules") if isinstance(src.get("categoryRules"), list) else []
    clean_cat_rules = []
    seen_ids = set()
    for idx, cr in enumerate(raw_cat_rules[:120]):
        if not isinstance(cr, dict):
            continue
        did = _slug_desk_id(cr.get("deskId") or "it", fallback="it")
        cid = str(cr.get("id") or f"tkr-{did}-{idx + 1}").strip()[:64]
        if cid in seen_ids:
            cid = f"{cid}-{idx + 1}"[:64]
        seen_ids.add(cid)
        pcat = str(cr.get("primaryCategory") or "").strip()[:120]
        scat = str(cr.get("subCategory") or "").strip()[:120]
        label = str(cr.get("label") or "").strip()[:120]
        clean_cat_rules.append({
            "id": cid,
            "deskId": did,
            "primaryCategory": pcat,
            "subCategory": scat,
            "label": label,
            "enabled": bool(cr.get("enabled", True)),
            "overrideTiming": bool(cr.get("overrideTiming", True)),
            "notifyAssignee": bool(cr.get("notifyAssignee", True)),
            "notifyDeskTeam": bool(cr.get("notifyDeskTeam", False)),
            "recipients": _clean_username_list(cr.get("recipients")),
            "statuses": _normalize_reminder_statuses_map(cr.get("statuses"), global_statuses),
        })

    raw_users = src.get("userOverrides") if isinstance(src.get("userOverrides"), dict) else {}
    clean_users = {}
    for uk, uv in list(raw_users.items())[:500]:
        u_cf = str(uk or "").strip().casefold()[:80]
        if not u_cf or not isinstance(uv, dict):
            continue
        clean_users[u_cf] = _normalize_user_reminder_pref(uv, global_statuses)

    return {
        "globalDefaults": global_defaults,
        "deskRules": clean_desks,
        "categoryRules": clean_cat_rules,
        "userOverrides": clean_users,
        "updatedAt": str(src.get("updatedAt") or "")[:40],
    }


def _normalize_reminder_state_doc(raw):
    src = raw if isinstance(raw, dict) else {}
    sent = src.get("sent") if isinstance(src.get("sent"), dict) else {}
    entered = src.get("statusEnteredAt") if isinstance(src.get("statusEnteredAt"), dict) else {}
    return {"sent": dict(sent), "statusEnteredAt": dict(entered)}


def _on_ticket_status_changed(conn, ticket_id, new_status):
    tid = str(ticket_id or "").strip()
    if not tid:
        return
    try:
        row = conn.execute("SELECT value FROM app_state WHERE key='ticket_reminder_state' FOR UPDATE").fetchone()
        st_doc = _normalize_reminder_state_doc(row[0] if row else {})
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        prefix = tid + "|"
        if new_status == "Closed":
            st_doc["statusEnteredAt"].pop(tid, None)
            st_doc["sent"] = {k: v for k, v in st_doc["sent"].items() if not str(k).startswith(prefix)}
        else:
            st_doc["statusEnteredAt"][tid] = {"status": str(new_status or "Open"), "at": now_iso}
            keep_prefix = f"{tid}|{new_status}|"
            st_doc["sent"] = {
                k: v for k, v in st_doc["sent"].items()
                if (not str(k).startswith(prefix)) or str(k).startswith(keep_prefix)
            }
        # Trim oldest entries if map ever grows very large
        if len(st_doc["sent"]) > 4000:
            items = sorted(st_doc["sent"].items(), key=lambda kv: str((kv[1] or {}).get("lastSentAt") or ""), reverse=True)[:3000]
            st_doc["sent"] = dict(items)
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('ticket_reminder_state',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(st_doc),),
        )
    except Exception:
        pass


def _parse_utc_dt(val):
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    s = str(val or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _resolve_ticket_reminder_rule(cfg, desk_id, primary_cat, sub_cat):
    gd = cfg["globalDefaults"]
    did = _slug_desk_id(desk_id or "it", fallback="it")
    p_cf = str(primary_cat or "").strip().casefold()
    s_cf = str(sub_cat or "").strip().casefold()

    eff = {
        "enabled": bool(gd.get("enabled", True)),
        "notifyAssignee": bool(gd.get("notifyAssignee", True)),
        "notifyDeskTeam": bool(gd.get("notifyDeskTeam", True)),
        "recipients": [],
        "statuses": json.loads(json.dumps(gd["statuses"])),
        "matchedRuleId": "",
        "matchedRuleLabel": "",
    }

    desk_rule = (cfg.get("deskRules") or {}).get(did)
    if isinstance(desk_rule, dict):
        eff["enabled"] = bool(desk_rule.get("enabled", True))
        eff["notifyAssignee"] = bool(desk_rule.get("notifyAssignee", eff["notifyAssignee"]))
        eff["notifyDeskTeam"] = bool(desk_rule.get("notifyDeskTeam", eff["notifyDeskTeam"]))
        eff["recipients"] = list(desk_rule.get("extraRecipients") or [])
        if desk_rule.get("overrideTiming"):
            eff["statuses"] = json.loads(json.dumps(desk_rule["statuses"]))

    best = None
    best_score = -1
    for cr in (cfg.get("categoryRules") or []):
        if _slug_desk_id(cr.get("deskId") or "it", fallback="it") != did:
            continue
        cr_p = str(cr.get("primaryCategory") or "").strip().casefold()
        cr_s = str(cr.get("subCategory") or "").strip().casefold()
        if cr_p and cr_p != p_cf:
            continue
        if cr_s and cr_s != s_cf:
            continue
        score = (2 if cr_p else 0) + (4 if cr_s else 0)
        if score > best_score:
            best_score = score
            best = cr

    if isinstance(best, dict):
        eff["enabled"] = bool(best.get("enabled", True))
        eff["notifyAssignee"] = bool(best.get("notifyAssignee", eff["notifyAssignee"]))
        eff["notifyDeskTeam"] = bool(best.get("notifyDeskTeam", eff["notifyDeskTeam"]))
        merged_recs = list(eff["recipients"])
        for u in (best.get("recipients") or []):
            if u not in merged_recs:
                merged_recs.append(u)
        eff["recipients"] = merged_recs
        if best.get("overrideTiming", True):
            eff["statuses"] = json.loads(json.dumps(best["statuses"]))
        eff["matchedRuleId"] = str(best.get("id") or "")
        eff["matchedRuleLabel"] = str(best.get("label") or best.get("subCategory") or best.get("primaryCategory") or "")

    return eff


def _user_is_active_staff(u):
    if not isinstance(u, dict):
        return False
    if u.get("active") is False:
        return False
    emp = str(u.get("employment") or "Active").strip().lower()
    return emp != "inactive"


def _resolve_ticket_reminder_recipients(ticket_info, rule, users, desk_name_map):
    desk_id = _slug_desk_id(ticket_info.get("complaintDesk") or "it", fallback="it")
    desk_name_cf = str(desk_name_map.get(desk_id) or desk_id).strip().casefold()
    assigned_raw = str(ticket_info.get("assigned") or "").strip()
    assigned_cf = assigned_raw.casefold() if assigned_raw and assigned_raw.lower() != "unassigned" else ""
    req_u_cf = str(ticket_info.get("username") or "").strip().casefold()

    active_users = [u for u in (users or []) if _user_is_active_staff(u) and str(u.get("username") or "").strip()]
    by_uname = {str(u.get("username") or "").strip().casefold(): u for u in active_users}

    recipients = {}  # uname_cf -> role tag ("assignee" | "explicit" | "desk")

    # 1. Assigned user currently working on the ticket
    assignee_uname = ""
    if assigned_cf:
        if assigned_cf in by_uname:
            assignee_uname = assigned_cf
        else:
            for u_cf, u in by_uname.items():
                if str(u.get("name") or "").strip().casefold() == assigned_cf or str(u.get("id") or "").strip().casefold() == assigned_cf:
                    assignee_uname = u_cf
                    break
        if assignee_uname and rule.get("notifyAssignee", True):
            recipients[assignee_uname] = "assignee"

    # 2. Explicit category/desk recipients
    for u_cf in (rule.get("recipients") or []):
        if u_cf in by_uname:
            recipients.setdefault(u_cf, "explicit")

    # 3. Department / desk team members
    if rule.get("notifyDeskTeam", True):
        for u_cf, u in by_uname.items():
            if u_cf == req_u_cf and u_cf != assignee_uname:
                # Avoid nagging a regular requester unless they are also desk staff
                pass
            role_val = str(u.get("role") or "")
            u_desks = u.get("allowed_complaint_desks")
            has_explicit_desks = isinstance(u_desks, list) and len(u_desks) > 0
            u_desk_slugs = {_slug_desk_id(x, fallback="") for x in (u_desks or []) if str(x or "").strip() and str(x).strip() != "*"}
            has_wildcard_desk = isinstance(u_desks, list) and any(str(x).strip() == "*" for x in u_desks)
            u_dept_cf = str(u.get("dept") or u.get("department") or "").strip().casefold()
            dept_matches = bool(u_dept_cf and (u_dept_cf == desk_id or u_dept_cf == desk_name_cf))

            is_team = False
            if has_explicit_desks:
                is_team = has_wildcard_desk or (desk_id in u_desk_slugs)
            elif role_val == "Administrator":
                is_team = True
            elif role_val == "IT Ticketing" and desk_id == "it":
                is_team = True
            elif module_access(u, "tickets", write=True) and ticket_desk_allowed(u, desk_id):
                is_team = True
            elif dept_matches and (module_access(u, "tickets") or role_val in ("IT Ticketing", "Technician", "Staff", "Manager")):
                is_team = True
            if is_team:
                recipients.setdefault(u_cf, "desk")

    return recipients, assignee_uname


def _format_reminder_message(template, ctx):
    tpl = str(template or "Please update status on {ticket_id} ({status}) — {summary}")
    for k, v in ctx.items():
        tpl = tpl.replace("{" + k + "}", str(v or ""))
    return tpl[:380]


def _evaluate_ticket_status_reminders(conn, caller_username_cf="", now_dt=None):
    now = now_dt or datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")

    cfg_row = conn.execute("SELECT value FROM app_state WHERE key='ticket_status_reminders'").fetchone()
    cfg = normalize_ticket_status_reminders(cfg_row[0] if cfg_row else {})

    st_row = conn.execute("SELECT value FROM app_state WHERE key='ticket_reminder_state' FOR UPDATE").fetchone()
    st_doc = _normalize_reminder_state_doc(st_row[0] if st_row else {})

    u_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    users = u_row[0] if u_row and isinstance(u_row[0], list) else []

    set_row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    t_settings = normalize_ticketing_settings(set_row[0] if set_row else {})
    desk_name_map = {d["id"]: d["name"] for d in (t_settings.get("complaintDesks") or [])}

    rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 1000").fetchall()
    tickets_active = [ticket_json(r) for r in rows if r and str(r[13] or "") in TICKET_REMINDER_STATUSES]

    state_dirty = False
    fired_total = []
    fired_for_caller = []

    for tk in tickets_active:
        tid = str(tk.get("id") or "").strip()
        status = str(tk.get("status") or "Open").strip()
        if not tid or status not in TICKET_REMINDER_STATUSES:
            continue
        desk_id = _slug_desk_id(tk.get("complaintDesk") or "it", fallback="it")
        primary = str(tk.get("primary") or "").strip()
        sub = str(tk.get("sub") or "").strip()

        rule = _resolve_ticket_reminder_rule(cfg, desk_id, primary, sub)
        if not rule.get("enabled", True):
            continue

        recipients, assignee_uname = _resolve_ticket_reminder_recipients(tk, rule, users, desk_name_map)
        if not recipients:
            continue

        # Also check any active user who opted into scope='all' with personal custom override and has desk access
        for u_cf, upref in (cfg.get("userOverrides") or {}).items():
            if u_cf in recipients or not upref.get("enabled", True):
                continue
            if upref.get("scope") == "all":
                u_obj = next((u for u in users if _user_is_active_staff(u) and str(u.get("username") or "").strip().casefold() == u_cf), None)
                if u_obj and (u_obj.get("role") == "Administrator" or (module_access(u_obj, "tickets") and ticket_desk_allowed(u_obj, desk_id))):
                    recipients[u_cf] = "desk"

        entered_info = st_doc["statusEnteredAt"].get(tid)
        if isinstance(entered_info, dict) and entered_info.get("status") == status:
            entered_dt = _parse_utc_dt(entered_info.get("at"))
        else:
            entered_dt = None
        if entered_dt is None:
            fallback_ts = tk.get("createdAt") or tk.get("created") if status == "Open" else (tk.get("updated") or tk.get("createdAt") or tk.get("created"))
            entered_dt = _parse_utc_dt(fallback_ts) or now

        elapsed_status_min = (now - entered_dt).total_seconds() / 60.0
        if elapsed_status_min < 0:
            elapsed_status_min = 0.0

        summary_txt = str(tk.get("description") or tk.get("material") or f"{primary} / {sub}").strip().replace("\n", " ")[:120]
        desk_label = desk_name_map.get(desk_id, desk_id.upper())
        is_mr = str(tk.get("kind") or "") == "Material request"

        for u_cf, rec_role in recipients.items():
            upref = (cfg.get("userOverrides") or {}).get(u_cf)
            st_cfg = dict(rule["statuses"][status])
            if isinstance(upref, dict):
                if not upref.get("enabled", True):
                    continue
                if upref.get("scope") == "assigned" and u_cf != assignee_uname:
                    continue
                if upref.get("useCustom"):
                    u_st = (upref.get("statuses") or {}).get(status)
                    if isinstance(u_st, dict):
                        st_cfg["enabled"] = bool(u_st.get("enabled", True))
                        st_cfg["initialDelayMinutes"] = int(u_st.get("initialDelayMinutes", st_cfg["initialDelayMinutes"]))
                        st_cfg["repeatEveryMinutes"] = int(u_st.get("repeatEveryMinutes", st_cfg["repeatEveryMinutes"]))
                        st_cfg["maxReminders"] = int(u_st.get("maxReminders", st_cfg["maxReminders"]))

            if not st_cfg.get("enabled", True):
                continue

            max_rem = int(st_cfg.get("maxReminders") or 0)
            init_min = max(1, int(st_cfg.get("initialDelayMinutes") or 60))
            rep_min = max(1, int(st_cfg.get("repeatEveryMinutes") or 60))

            skey = f"{tid}|{status}|{u_cf}"
            entry = st_doc["sent"].get(skey) if isinstance(st_doc["sent"].get(skey), dict) else {}
            sent_count = int(entry.get("count") or 0)
            if max_rem > 0 and sent_count >= max_rem:
                continue

            due = False
            if sent_count == 0:
                due = elapsed_status_min >= init_min
            else:
                last_dt = _parse_utc_dt(entry.get("lastSentAt"))
                if last_dt is None or ((now - last_dt).total_seconds() / 60.0) >= rep_min:
                    due = True

            if not due:
                continue

            new_count = sent_count + 1
            st_doc["sent"][skey] = {
                "ticketId": tid,
                "status": status,
                "recipient": u_cf,
                "count": new_count,
                "lastSentAt": now_iso,
            }
            state_dirty = True

            cat_txt = " · ".join(p for p in (primary, sub) if p) or desk_label
            body_txt = _format_reminder_message(
                st_cfg.get("message"),
                {
                    "ticket_id": tid,
                    "status": status,
                    "desk": desk_label,
                    "category": cat_txt,
                    "sub": sub,
                    "assignee": tk.get("assigned") or "Unassigned",
                    "requester": tk.get("name") or "",
                    "summary": summary_txt,
                    "count": new_count,
                },
            )
            title_txt = f"Status Update Reminder #{new_count} · {tid} ({status})"
            ev = _record_notification_event(conn, {
                "eventKey": f"tkr:{tid}:{status.lower().replace(' ', '_')}:{u_cf}:{new_count}",
                "kind": "ticket_reminder",
                "level": "warn",
                "title": title_txt,
                "body": body_txt,
                "factory": str(tk.get("site") or ""),
                "targetView": "ticketing",
                "targetTab": "materials" if is_mr else "tickets",
                "targetId": tid,
                "targetTicketId": tid,
                "targetRole": rec_role,
                "targetUsername": u_cf,
                "targetAssignee": str(tk.get("assigned") or ""),
                "requesterName": str(tk.get("name") or ""),
                "complaintDesk": desk_id,
                "createdAt": now_iso,
            })
            rec_item = {
                "id": ev.get("id") if isinstance(ev, dict) else f"tkr-{tid}-{new_count}",
                "ticketId": tid,
                "status": status,
                "desk": desk_id,
                "deskLabel": desk_label,
                "category": cat_txt,
                "recipient": u_cf,
                "recipientRole": rec_role,
                "count": new_count,
                "maxReminders": max_rem,
                "title": title_txt,
                "body": body_txt,
                "createdAt": now_iso,
            }
            fired_total.append(rec_item)
            if caller_username_cf and u_cf == caller_username_cf:
                fired_for_caller.append(rec_item)

    if state_dirty:
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('ticket_reminder_state',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(st_doc),),
        )

    return fired_for_caller, fired_total


def _can_edit_org_reminders(profile, is_adm):
    if is_adm or profile.get("role") == "IT Ticketing":
        return True
    return bool(module_access(profile, "tickets", write=True))


@app.get("/api/tickets/status-reminders")
@signed_in
def get_ticket_status_reminders():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname_cf = str(profile.get("username") or "").strip().casefold()
    can_edit_org = _can_edit_org_reminders(profile, is_adm)
    allowed_desks = allowed_complaint_desks_for(profile)
    with db() as conn:
        cfg_row = conn.execute("SELECT value FROM app_state WHERE key='ticket_status_reminders'").fetchone()
        set_row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
        u_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    cfg = normalize_ticket_status_reminders(cfg_row[0] if cfg_row else {})
    t_settings = normalize_ticketing_settings(set_row[0] if set_row else {})
    desks = t_settings.get("complaintDesks") or []
    users_raw = u_row[0] if u_row and isinstance(u_row[0], list) else []
    users_clean = [
        {
            "username": str(u.get("username") or "").strip(),
            "name": str(u.get("name") or u.get("username") or "").strip(),
            "dept": str(u.get("dept") or u.get("department") or "").strip(),
            "site": str(u.get("site") or "").strip(),
            "role": str(u.get("role") or "User").strip(),
            "allowed_complaint_desks": u.get("allowed_complaint_desks") if isinstance(u.get("allowed_complaint_desks"), list) else [],
        }
        for u in users_raw
        if _user_is_active_staff(u) and str(u.get("username") or "").strip()
    ]
    my_prefs = cfg["userOverrides"].get(uname_cf) or _normalize_user_reminder_pref({}, cfg["globalDefaults"]["statuses"])
    public_cfg = {
        "globalDefaults": cfg["globalDefaults"],
        "deskRules": cfg["deskRules"],
        "categoryRules": cfg["categoryRules"],
        "updatedAt": cfg["updatedAt"],
    }
    return jsonify(
        config=public_cfg,
        myPrefs=my_prefs,
        canEditOrg=can_edit_org,
        isAdmin=is_adm,
        allowedDesks=(sorted(allowed_desks) if isinstance(allowed_desks, set) else ["*"]),
        desks=desks,
        users=users_clean if can_edit_org else [],
    )


@app.put("/api/tickets/status-reminders")
@signed_in
def save_ticket_status_reminders_org():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    if not _can_edit_org_reminders(profile, is_adm):
        return jsonify(error="Ticketing write permission or Administrator access is required to edit department reminder rules."), 403
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid reminder configuration payload."), 400
    patch = body.get("config") if isinstance(body.get("config"), dict) else body
    allowed_desks = allowed_complaint_desks_for(profile)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='ticket_status_reminders' FOR UPDATE").fetchone()
        cur = normalize_ticket_status_reminders(row[0] if row else {})
        merged = json.loads(json.dumps(cur))
        if isinstance(patch.get("globalDefaults"), dict):
            if is_adm or allowed_desks is None:
                merged["globalDefaults"] = patch["globalDefaults"]
        if isinstance(patch.get("deskRules"), dict):
            if is_adm or allowed_desks is None:
                merged["deskRules"] = patch["deskRules"]
            else:
                for dk, dv in patch["deskRules"].items():
                    did = _slug_desk_id(dk, fallback="")
                    if did and did in allowed_desks:
                        merged["deskRules"][did] = dv
        if isinstance(patch.get("categoryRules"), list):
            if is_adm or allowed_desks is None:
                merged["categoryRules"] = patch["categoryRules"]
            else:
                kept = [r for r in merged["categoryRules"] if _slug_desk_id(r.get("deskId") or "it", "it") not in allowed_desks]
                incoming = [r for r in patch["categoryRules"] if isinstance(r, dict) and _slug_desk_id(r.get("deskId") or "it", "it") in allowed_desks]
                merged["categoryRules"] = kept + incoming
        merged["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        clean = normalize_ticket_status_reminders(merged)
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('ticket_status_reminders',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(clean),),
        )
        _pg_emit_notify(conn, "pulse", {"source": "ticket_status_reminders"})
    return jsonify(
        ok=True,
        config={
            "globalDefaults": clean["globalDefaults"],
            "deskRules": clean["deskRules"],
            "categoryRules": clean["categoryRules"],
            "updatedAt": clean["updatedAt"],
        },
    )


@app.route("/api/tickets/status-reminders/me", methods=["GET", "PUT"])
@signed_in
def ticket_status_reminders_me():
    profile = session.get("profile") or {}
    uname_cf = str(profile.get("username") or "").strip().casefold()
    if not uname_cf:
        return jsonify(error="Signed-in user account required."), 401
    if request.method == "GET":
        with db() as conn:
            row = conn.execute("SELECT value FROM app_state WHERE key='ticket_status_reminders'").fetchone()
        cfg = normalize_ticket_status_reminders(row[0] if row else {})
        my_prefs = cfg["userOverrides"].get(uname_cf) or _normalize_user_reminder_pref({}, cfg["globalDefaults"]["statuses"])
        return jsonify(ok=True, myPrefs=my_prefs)
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="Invalid personal reminder preferences."), 400
    patch = body.get("myPrefs") if isinstance(body.get("myPrefs"), dict) else body
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='ticket_status_reminders' FOR UPDATE").fetchone()
        cfg = normalize_ticket_status_reminders(row[0] if row else {})
        patch_clean = dict(patch)
        patch_clean["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cfg["userOverrides"][uname_cf] = _normalize_user_reminder_pref(patch_clean, cfg["globalDefaults"]["statuses"])
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('ticket_status_reminders',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(cfg),),
        )
    return jsonify(ok=True, myPrefs=cfg["userOverrides"][uname_cf])


@app.route("/api/tickets/status-reminders/check", methods=["GET", "POST"])
@signed_in
def check_ticket_status_reminders():
    profile = session.get("profile") or {}
    uname_cf = str(profile.get("username") or "").strip().casefold()
    with db() as conn:
        mine, total = _evaluate_ticket_status_reminders(conn, caller_username_cf=uname_cf)
    return jsonify(ok=True, reminders=mine, evaluatedCount=len(total), serverNow=datetime.now(timezone.utc).isoformat(timespec="seconds"))


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
        conn.execute("UPDATE tickets SET status=%s, note=%s, assigned_to=CASE WHEN assigned_to='Unassigned' THEN %s ELSE assigned_to END, first_responded_at=COALESCE(first_responded_at, now()), updated_at=now() WHERE id=%s",
                     (new_status, ticket_note[:1000], actor, ticket_id))
        _on_ticket_status_changed(conn, ticket_id, new_status)
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'material_issued',%s)", (ticket_id, actor, ticket_note[:1000]))
        mat_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="material_issued", actor=actor, detail=ticket_note[:500], status=new_status, note=ticket_note[:500])
        if mat_notif:
            req_key = _resolve_ticket_requester_key(conn, mat_notif.get("requesterUsername", ""), mat_notif.get("requesterName", ""))
            desk_m = mat_notif.get("complaintDesk") or t_row[6]
            thr_id = _helpdesk_thread_id(desk_m, req_key)
            _record_notification_event(conn, {
                "eventKey": f"ticket-mat:{ticket_id}:{mat_notif.get('id','')}",
                "kind": "material_request",
                "level": "ok" if new_status in ("Resolved", "Closed") else "info",
                "title": mat_notif.get("title") or f"Parts Issued · {ticket_id}",
                "body": mat_notif.get("message") or ticket_note[:360],
                "factory": t_row[3] or "",
                "targetView": "messages",
                "targetTab": desk_m,
                "targetId": thr_id,
                "targetThreadId": thr_id,
                "targetTicketId": ticket_id,
                "targetRole": "requester",
                "targetUsername": req_key[:80],
                "requesterName": str(t_row[1] or "")[:120],
                "complaintDesk": desk_m,
            })
        _pg_emit_notify(conn, "ticket", {"action": "issue-material", "ticketId": ticket_id, "status": new_status})
        issued_list = issued_parts_map_from_conn(conn).get(ticket_id, [])
        closed_meta = _build_ticket_closed_meta(conn, ticket_id, actor, t_row[6]) if new_status == "Closed" else None
    resp_data = dict(ok=True, assignment=assignment, status=new_status, note=ticket_note, issuedParts=issued_list, parts_inventory=inv_list, parts_assignments=asgn_list)
    if closed_meta:
        resp_data["closedMeta"] = closed_meta
    return jsonify(**resp_data)


@app.get("/api/tickets/<path:ticket_id>/attachments/<path:filename>")
@signed_in
def ticket_attachment(ticket_id, filename):
    profile = session.get("profile", {})
    uname_cf = str(profile.get("username") or "").strip().casefold()
    dname_cf = str(profile.get("name") or "").strip().casefold()
    with db() as conn:
        row = conn.execute("SELECT username,attachments,COALESCE(NULLIF(complaint_desk,''),'it'),display_name FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
    if not row:
        abort(404)
    is_owner = (uname_cf and str(row[0] or "").strip().casefold() == uname_cf) or (dname_cf and str(row[3] or "").strip().casefold() == dname_cf)
    if not is_owner and not session.get("is_admin") and not (module_access(profile, "tickets") and ticket_desk_allowed(profile, row[2])):
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
        explicit_gender = _clean_gender(form.get("gender"))
        contact = _lookup_requester_contact(conn, profile["username"], profile["name"], explicit_gender)
        conn.execute("INSERT INTO tickets(id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,complaint_desk,requester_gender) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)", (ticket_id,kind,profile["username"],profile["name"],profile.get("department", ""),profile.get("site", ""),remote,primary,sub,description,form.get("material", ""),json.dumps(saved),desk_obj["id"],contact["gender"]))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'created',%s)", (ticket_id,profile["username"],description[:500]))
        welcome_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="created", actor=profile["name"] or profile["username"], detail=description, explicit_gender=contact["gender"])
        is_mr = (kind == "Material request")
        desk_label = desk_obj.get("name") or "IT"
        req_key = _resolve_ticket_requester_key(conn, profile["username"], profile["name"])
        thr_id = _helpdesk_thread_id(desk_obj["id"], req_key)
        _record_notification_event(conn, {
            "eventKey": f"ticket:{ticket_id}",
            "kind": "material_request" if is_mr else "ticket",
            "level": "info",
            "title": f"{'New Material Request' if is_mr else f'New {desk_label} Ticket'}: {ticket_id}",
            "body": f"{profile.get('name') or profile['username']} · {sub or primary} ({profile.get('site', '-')})",
            "factory": profile.get("site", ""),
            "targetView": "messages",
            "targetTab": desk_obj["id"],
            "targetId": thr_id,
            "targetThreadId": thr_id,
            "targetTicketId": ticket_id,
            "targetUsername": req_key[:80],
            "requesterName": str(profile.get("name") or "")[:120],
            "complaintDesk": desk_obj["id"],
        })
    return jsonify(id=ticket_id, complaintDesk=desk_obj["id"], availabilityNotice=(welcome_notif or {}).get("availabilityNotice", ""), welcomeNotification=welcome_notif), 201


def _build_ticket_closed_meta(conn, ticket_id, actor, desk_id):
    now = datetime.now(timezone.utc)
    created_dt = None
    primary = ""
    sub = ""
    try:
        meta_row = conn.execute("SELECT created_at, primary_category, sub_category FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if meta_row:
            created_dt = _parse_utc_dt(meta_row[0])
            primary = str(meta_row[1] or "")
            sub = str(meta_row[2] or "")
    except Exception:
        pass
    elapsed_sec = max(1, int((now - created_dt).total_seconds())) if created_dt else 0
    return {
        "ticketId": str(ticket_id or ""),
        "actorName": str(actor or "Team Member")[:120],
        "desk": _slug_desk_id(desk_id or "it", fallback="it"),
        "primary": primary[:120],
        "sub": sub[:120],
        "durationSeconds": elapsed_sec,
        "durationText": _format_elapsed_duration(elapsed_sec) if elapsed_sec > 0 else "just now",
        "closedAt": now.isoformat(timespec="seconds"),
    }


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
    actor = str(profile.get("name") or profile.get("username") or "IT Support")[:120]
    closed_meta = None
    with db() as conn:
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it'),assigned_to,status,eta,note,username,display_name,factory,kind FROM tickets WHERE id=%s FOR UPDATE", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not session.get("is_admin") and not ticket_desk_allowed(profile, t_row[0]):
            return jsonify(error="You do not have access to this complaint department's tickets."), 403
        old_assigned, old_status, old_eta, old_note = t_row[1], t_row[2], (t_row[3].isoformat(timespec="minutes") if t_row[3] else ""), t_row[4]
        cur = conn.execute(f"UPDATE tickets SET {assignments}, first_responded_at=COALESCE(first_responded_at, now()), updated_at=now() WHERE id=%s RETURNING id,assigned_to,status,eta,note", [v for _,v in fields]+[ticket_id])
        u_row = cur.fetchone()
        if not u_row:
            abort(404)
        new_assigned, new_status, new_eta_dt, new_note = u_row[1], u_row[2], u_row[3], u_row[4]
        new_eta_str = new_eta_dt.isoformat(timespec="minutes") if new_eta_dt else ""
        detail = "; ".join(f"{k}: {v}" for k,v in body.items() if k in allowed)[:1000]
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'updated',%s)", (ticket_id,profile["username"],detail))
        if new_status != old_status:
            _on_ticket_status_changed(conn, ticket_id, new_status)
            if new_status == "Closed":
                closed_meta = _build_ticket_closed_meta(conn, ticket_id, actor, t_row[0])
        last_notif = None
        if "assigned" in body and str(new_assigned or "").strip() and new_assigned != old_assigned and new_assigned != "Unassigned":
            last_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="assigned", actor=actor, assigned_to=new_assigned, status=new_status, eta=new_eta_dt, note=new_note)
        if "status" in body and new_status != old_status:
            last_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="status_change", actor=actor, assigned_to=new_assigned, status=new_status, eta=new_eta_dt, note=new_note)
        elif "eta" in body and new_eta_str != old_eta:
            last_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="eta_updated", actor=actor, assigned_to=new_assigned, status=new_status, eta=new_eta_dt, note=new_note)
        elif "note" in body and new_note and new_note != old_note:
            last_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="worklog", actor=actor, detail=new_note, assigned_to=new_assigned, status=new_status, eta=new_eta_dt, note=new_note)
        if last_notif:
            t_user = t_row[5] if len(t_row) > 5 else ""
            t_disp = t_row[6] if len(t_row) > 6 else ""
            t_fac = t_row[7] if len(t_row) > 7 else ""
            t_kind = t_row[8] if len(t_row) > 8 else ""
            is_mr = (t_kind == "Material request")
            req_key = _resolve_ticket_requester_key(conn, t_user, t_disp)
            thr_id = _helpdesk_thread_id(t_row[0], req_key)
            _record_notification_event(conn, {
                "eventKey": f"ticket-upd:{ticket_id}:{last_notif.get('id','')}",
                "kind": "material_request" if is_mr else "ticket",
                "level": "ok" if new_status in ("Resolved", "Closed") else "info",
                "title": last_notif.get("title") or f"Ticket {ticket_id} Updated",
                "body": last_notif.get("message") or detail,
                "factory": t_fac or "",
                "targetView": "messages",
                "targetTab": t_row[0],
                "targetId": thr_id,
                "targetTicketId": ticket_id,
                "targetRole": "requester",
                "targetUsername": req_key[:80],
                "requesterName": str(t_disp or "")[:120],
                "complaintDesk": t_row[0],
            })
        _pg_emit_notify(conn, "ticket", {"action": "update", "ticketId": ticket_id, "complaintDesk": t_row[0]})
    resp_out = {"ok": True, "status": new_status}
    if closed_meta:
        resp_out["closedMeta"] = closed_meta
    return jsonify(**resp_out)


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
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it'),username,display_name,factory,kind FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        if not session.get("is_admin") and not ticket_desk_allowed(profile, t_row[0]):
            return jsonify(error="You do not have access to this complaint department's tickets."), 403
        row = conn.execute("UPDATE tickets SET note=%s, first_responded_at=COALESCE(first_responded_at, now()), updated_at=now() WHERE id=%s RETURNING id", (detail, ticket_id)).fetchone()
        if not row:
            abort(404)
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'worklog',%s)", (ticket_id, actor, detail))
        w_notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="worklog", actor=actor, detail=detail, note=detail)
        if w_notif:
            w_user = t_row[1] if len(t_row) > 1 else ""
            w_disp = t_row[2] if len(t_row) > 2 else ""
            w_fac = t_row[3] if len(t_row) > 3 else ""
            w_kind = t_row[4] if len(t_row) > 4 else ""
            is_mr = (w_kind == "Material request")
            req_key = _resolve_ticket_requester_key(conn, w_user, w_disp)
            thr_id = _helpdesk_thread_id(t_row[0], req_key)
            _record_notification_event(conn, {
                "eventKey": f"ticket-wl:{ticket_id}:{w_notif.get('id','')}",
                "kind": "material_request" if is_mr else "ticket",
                "level": "info",
                "title": w_notif.get("title") or f"Work Update: {ticket_id}",
                "body": w_notif.get("message") or detail,
                "factory": w_fac or "",
                "targetView": "messages",
                "targetTab": t_row[0],
                "targetId": thr_id,
                "targetTicketId": ticket_id,
                "targetRole": "requester",
                "targetUsername": req_key[:80],
                "requesterName": str(w_disp or "")[:120],
                "complaintDesk": t_row[0],
            })
        _pg_emit_notify(conn, "ticket", {"action": "worklog", "ticketId": ticket_id, "complaintDesk": t_row[0]})
    return jsonify(ok=True)


@app.get("/api/tickets/<path:ticket_id>/worklog")
@signed_in
def list_ticket_worklog(ticket_id):
    profile = session.get("profile", {})
    uname_cf = str(profile.get("username") or "").strip().casefold()
    dname_cf = str(profile.get("name") or "").strip().casefold()
    with db() as conn:
        t_row = conn.execute("SELECT COALESCE(NULLIF(complaint_desk,''),'it'),username,display_name FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
        if not t_row:
            abort(404)
        is_owner = (uname_cf and str(t_row[1] or "").strip().casefold() == uname_cf) or (dname_cf and str(t_row[2] or "").strip().casefold() == dname_cf)
        if not is_owner and not session.get("is_admin") and not (module_access(profile, "tickets") and ticket_desk_allowed(profile, t_row[0])):
            abort(403)
        rows = conn.execute("SELECT actor,detail,created_at FROM ticket_events WHERE ticket_id=%s AND event_type IN ('created','updated','worklog','reopened') ORDER BY created_at DESC LIMIT 100", (ticket_id,)).fetchall()
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


def _find_ios_ipa():
    for cand in (UPLOAD_DIR / "shree-it.ipa", ROOT / "static" / "downloads" / "shree-it.ipa", ROOT / "Shree-IT.ipa", ROOT / "shree-it.ipa"):
        if cand.is_file() and cand.stat().st_size > 10000:
            return cand
    return None


@app.get("/api/public/ios-status")
def public_ios_status():
    ipa = _find_ios_ipa()
    zip_proj = ROOT / "static" / "downloads" / "shree-ios-project.zip"
    return jsonify(
        ipaAvailable=bool(ipa),
        ipaSizeBytes=ipa.stat().st_size if ipa else 0,
        ipaDownloadUrl="/download/shree-it.ipa" if ipa else "",
        projectZipAvailable=zip_proj.is_file() or (ROOT / "ios-app").is_dir(),
        projectZipDownloadUrl="/download/shree-ios-project.zip",
    )


@app.get("/download/shree-it.ipa")
def download_ios_ipa():
    ipa = _find_ios_ipa()
    if not ipa:
        return jsonify(
            error="Compiled Apple .ipa binary requires macOS/Xcode or GitHub Actions (build-ipa.yml). Download /download/shree-ios-project.zip or open this site in iPhone/iPad Safari and tap Share -> Add to Home Screen."
        ), 404
    resp = send_from_directory(ipa.parent, ipa.name, mimetype="application/octet-stream")
    resp.headers["Content-Disposition"] = 'attachment; filename="Shree-IT-iOS-iPadOS.ipa"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.get("/download/shree-ios-project.zip")
def download_ios_project():
    pre = ROOT / "static" / "downloads" / "shree-ios-project.zip"
    if pre.is_file() and pre.stat().st_size > 1000:
        resp = send_from_directory(pre.parent, pre.name, mimetype="application/zip")
        resp.headers["Content-Disposition"] = 'attachment; filename="Shree-IT-iOS-iPadOS-Project.zip"'
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp
    ios_dir = ROOT / "ios-app"
    if not ios_dir.is_dir():
        return jsonify(error="iOS project bundle not found."), 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(ios_dir.rglob("*")):
            if p.is_file() and "/build/" not in str(p).replace("\\", "/"):
                rel = p.relative_to(ROOT).as_posix()
                zf.write(p, rel)
        wf = ROOT / ".github" / "workflows" / "build-ipa.yml"
        if wf.is_file():
            zf.write(wf, ".github/workflows/build-ipa.yml")
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = 'attachment; filename="Shree-IT-iOS-iPadOS-Project.zip"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


def _public_request_origin():
    proto = str(request.headers.get("X-Forwarded-Proto") or request.scheme or "https").split(",")[0].strip()
    host = str(request.headers.get("X-Forwarded-Host") or request.host or "localhost").split(",")[0].strip()
    return f"{proto}://{host}".rstrip("/")


@app.get("/download/shree-ios-app.mobileconfig")
def download_ios_mobileconfig():
    origin = _public_request_origin()
    target = str(request.args.get("target") or "").strip().lower()
    is_portal = target == "portal"
    target_url = f"{origin}/portal" if is_portal else f"{origin}/"
    app_label = "Shree Portal" if is_portal else "Shree IT"

    icon_bytes = b""
    for icand in (
        ROOT / "static" / "icons" / "apple-touch-icon-180.png",
        ROOT / "apple-touch-icon.png",
        ROOT / "static" / "icons" / "icon-192.png",
    ):
        if icand.is_file():
            try:
                icon_bytes = icand.read_bytes()
                break
            except OSError:
                pass

    webclip = {
        "FullScreen": True,
        "IgnoreManifestScope": False,
        "IsRemovable": True,
        "Label": app_label,
        "PayloadDescription": f"Opens {app_label} in full-screen Apple app mode.",
        "PayloadDisplayName": f"{app_label} Web App",
        "PayloadIdentifier": f"com.shree.itassets.webclip.{target or 'main'}",
        "PayloadOrganization": "Swarnshilp",
        "PayloadType": "com.apple.webClip.managed",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1,
        "Precomposed": True,
        "URL": target_url,
    }
    if icon_bytes:
        webclip["Icon"] = icon_bytes

    payloads = [webclip]
    if str(request.args.get("ca") or "") == "1":
        der = _fetch_server_ca_cert_der()
        if der:
            payloads.append({
                "PayloadCertificateFileName": "shree-server-ca.crt",
                "PayloadContent": der,
                "PayloadDescription": "Swarnshilp On-Premise Server Root CA",
                "PayloadDisplayName": "Shree Root CA",
                "PayloadIdentifier": "com.shree.itassets.rootca",
                "PayloadOrganization": "Swarnshilp",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": str(uuid.uuid4()).upper(),
                "PayloadVersion": 1,
            })

    profile = {
        "PayloadContent": payloads,
        "PayloadDescription": f"Direct 1-tap Home Screen App installer for {app_label} (iPhone & iPad).",
        "PayloadDisplayName": f"{app_label} App",
        "PayloadIdentifier": f"com.shree.itassets.profile.{target or 'main'}",
        "PayloadOrganization": "Swarnshilp",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1,
    }
    xml_bytes = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
    fname = "Swarnshilp-Portal-iOS.mobileconfig" if is_portal else "Shree-IT-iPhone-iPad.mobileconfig"
    resp = Response(xml_bytes, mimetype="application/x-apple-aspen-config")
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.get("/download/shree-ios-manifest.plist")
def download_ios_ota_manifest():
    origin = _public_request_origin()
    manifest = {
        "items": [
            {
                "assets": [
                    {"kind": "software-package", "url": f"{origin}/download/shree-it.ipa"},
                    {"kind": "display-image", "url": f"{origin}/static/icons/icon-192.png"},
                    {"kind": "full-size-image", "url": f"{origin}/static/icons/icon-512.png"},
                ],
                "metadata": {
                    "bundle-identifier": "com.shree.itassets",
                    "bundle-version": "1.0.7",
                    "kind": "software",
                    "title": "Shree IT",
                },
            }
        ]
    }
    xml_bytes = plistlib.dumps(manifest, fmt=plistlib.FMT_XML)
    resp = Response(xml_bytes, mimetype="application/xml")
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


def _normalize_overview_prefs(raw):
    p = raw if isinstance(raw, dict) else {}
    hidden_cats = [str(x).strip()[:80] for x in (p.get("hiddenCategories") if isinstance(p.get("hiddenCategories"), list) else []) if str(x).strip()][:100]
    hidden_subs = [str(x).strip()[:120] for x in (p.get("hiddenSubcategories") if isinstance(p.get("hiddenSubcategories"), list) else []) if str(x).strip()][:300]
    hidden_secs = [str(x).strip()[:80] for x in (p.get("hiddenSections") if isinstance(p.get("hiddenSections"), list) else []) if str(x).strip()][:50]
    return {
        "hiddenCategories": list(dict.fromkeys(hidden_cats)),
        "hiddenSubcategories": list(dict.fromkeys(hidden_subs)),
        "hiddenSections": list(dict.fromkeys(hidden_secs)),
    }


def _normalize_tile_configs_doc(raw):
    doc = dict(raw) if isinstance(raw, dict) else {}
    out = {"rev": int(doc.get("rev") or 0), "updatedAt": str(doc.get("updatedAt") or "")}
    for mod in ("overview", "datacenter", "surveillance"):
        nm = _normalize_tile_module_cfg(doc.get(mod))
        if nm is not None:
            out[mod] = nm
    if isinstance(doc.get("overviewPrefs"), dict):
        out["overviewPrefs"] = _normalize_overview_prefs(doc.get("overviewPrefs"))
    return out


@app.get("/api/tile-configs")
@signed_in
def get_tile_configs():
    username_key = str((session.get("profile") or {}).get("username") or "").strip().casefold() or "_default"
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='tile_configs'").fetchone()
    raw = row[0] if row and isinstance(row[0], dict) else {}
    users_map = raw.get("users") if isinstance(raw.get("users"), dict) else {}
    user_doc = users_map.get(username_key)
    if isinstance(user_doc, dict):
        out = _normalize_tile_configs_doc(user_doc)
    else:
        out = {"rev": int(raw.get("rev") or 0), "updatedAt": str(raw.get("updatedAt") or "")}
    out["userScoped"] = True
    return jsonify(out)


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
    username_key = str(profile.get("username") or "").strip().casefold() or "_default"
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='tile_configs' FOR UPDATE").fetchone()
        store = dict(row[0]) if row and isinstance(row[0], dict) else {}
        users_map = dict(store.get("users") or {}) if isinstance(store.get("users"), dict) else {}
        existing = _normalize_tile_configs_doc(users_map.get(username_key) or {})
        if body.get("resetDefaults"):
            for mod in ("overview", "datacenter", "surveillance"):
                if body.get("module") == mod:
                    existing.pop(mod, None)
            if body.get("module") in (None, "overview", "all"):
                existing.pop("overviewPrefs", None)
        else:
            incoming = _normalize_tile_configs_doc(body)
            for mod in ("overview", "datacenter", "surveillance"):
                if mod in incoming:
                    existing[mod] = incoming[mod]
            if "overviewPrefs" in incoming:
                existing["overviewPrefs"] = incoming["overviewPrefs"]
        existing["rev"] = int(existing.get("rev") or 0) + 1
        existing["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        users_map[username_key] = existing
        store["users"] = users_map
        store["rev"] = int(store.get("rev") or 0) + 1
        store["updatedAt"] = existing["updatedAt"]
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('tile_configs',%s::jsonb) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
            (json.dumps(store),),
        )
        _pg_emit_notify(conn, "pulse", {"source": "tile_configs", "username": username_key, "rev": existing["rev"]})
    return jsonify(ok=True, userScoped=True, **existing)


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


def _merge_photo_rels(legacy_rel, extra_json):
    out = []
    seen = set()
    extras = extra_json
    if isinstance(extras, str):
        try:
            extras = json.loads(extras)
        except Exception:
            extras = []
    for cand in ([legacy_rel] if legacy_rel else []) + (extras if isinstance(extras, list) else []):
        s = str(cand or "").strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _save_gate_image_batch(files_list, data_urls_val, single_data_url, category, entry_id, slot, max_count=12):
    items_data = []
    if isinstance(data_urls_val, str) and data_urls_val.strip().startswith("["):
        try:
            data_urls_val = json.loads(data_urls_val)
        except Exception:
            data_urls_val = []
    if isinstance(data_urls_val, list):
        for u in data_urls_val:
            if isinstance(u, str) and u.startswith("data:image/"):
                items_data.append(u)
    if not items_data and isinstance(single_data_url, str) and single_data_url.startswith("data:image/"):
        items_data.append(single_data_url)

    saved = []
    for f in (files_list or []):
        if f is None or not getattr(f, "filename", ""):
            continue
        if len(saved) >= max_count:
            break
        rel, err = _save_gate_image(f, None, category, entry_id, f"{slot}{len(saved) + 1}")
        if err:
            return None, err
        if rel:
            saved.append(rel)
    for du in items_data:
        if len(saved) >= max_count:
            break
        rel, err = _save_gate_image(None, du, category, entry_id, f"{slot}{len(saved) + 1}")
        if err:
            return None, err
        if rel:
            saved.append(rel)
    return saved, None


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
    id_rels = _merge_photo_rels(r[14], r[25] if len(r) > 25 else None)
    sf_rels = _merge_photo_rels(r[15], r[26] if len(r) > 26 else None)
    id_urls = [_media_url(u) for u in id_rels if _media_url(u)]
    sf_urls = [_media_url(u) for u in sf_rels if _media_url(u)]
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
        "idCardPhoto": id_urls[0] if id_urls else "",
        "idCardPhotos": id_urls,
        "selfiePhoto": sf_urls[0] if sf_urls else "",
        "selfiePhotos": sf_urls,
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
    exp_dt = r[24] if len(r) > 24 else None
    ret_dt = r[26] if len(r) > 26 else None
    is_ret = bool(r[8])
    is_overdue = bool(is_ret and r[18] != "Returned" and exp_dt and exp_dt <= datetime.now(timezone.utc))
    mat_rels = _merge_photo_rels(r[16], r[28] if len(r) > 28 else None)
    bill_rels = _merge_photo_rels(r[17], r[29] if len(r) > 29 else None)
    mat_urls = [_media_url(u) for u in mat_rels if _media_url(u)]
    bill_urls = [_media_url(u) for u in bill_rels if _media_url(u)]
    return {
        "id": r[0], "direction": r[2], "factory": r[3], "materialType": r[4], "materialName": r[5],
        "quantity": r[6], "unit": r[7], "returnable": is_ret, "partyName": r[9],
        "challanNo": r[10], "vehicleNo": r[11], "remarks": r[12], "department": r[13],
        "forUsername": r[14] if include_private else "", "forName": r[15],
        "materialPhoto": mat_urls[0] if mat_urls else "",
        "materialPhotos": mat_urls,
        "billPhoto": bill_urls[0] if bill_urls else "",
        "billPhotos": bill_urls,
        "status": r[18], "enteredBy": r[19], "verifiedBy": r[20],
        "verifiedAt": r[21].isoformat() if r[21] else "",
        "createdAt": r[22].isoformat() if r[22] else "",
        "updatedAt": r[23].isoformat() if r[23] else "",
        "expectedReturnAt": exp_dt.isoformat() if exp_dt else "",
        "expectedDays": int(r[25] or 0) if len(r) > 25 else 0,
        "returnedAt": ret_dt.isoformat() if ret_dt else "",
        "returnNote": str(r[27] or "") if len(r) > 27 else "",
        "isOverdue": is_overdue,
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
    d_arg = str(args.get("direction") or "").strip().upper()
    if d_arg in ("IN", "OUT"):
        clauses.append(f"direction = %s")
        params.append(d_arg)
    elif d_arg == "RETURNABLE" or str(args.get("returnable") or "").lower() in ("1", "true"):
        clauses.append("returnable = true")
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


VISITOR_COLS = "id,tracking_token_hash,factory,visitor_name,phone,address,purpose,department,host_username,host_name,vehicle_no,pass_no,visitor_count,belongings,id_card_photo,selfie_photo,status,entered_by,approved_by,approved_at,checked_in_at,checked_out_at,decision_note,created_at,updated_at,id_card_photos,selfie_photos"
GATEPASS_COLS = "id,tracking_token_hash,direction,factory,material_type,material_name,quantity,unit,returnable,party_name,challan_no,vehicle_no,remarks,department,for_username,for_name,material_photo,bill_photo,status,entered_by,verified_by,verified_at,created_at,updated_at,expected_return_at,expected_days,returned_at,return_note,material_photos,bill_photos"


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
    rel_json = json.dumps([norm_rel])
    with db() as conn:
        if parts[0] == "visitors":
            row = conn.execute(
                "SELECT 1 FROM visitor_passes WHERE tracking_token_hash=%s AND (id_card_photo=%s OR selfie_photo=%s OR id_card_photos @> %s::jsonb OR selfie_photos @> %s::jsonb)",
                (thash, norm_rel, norm_rel, rel_json, rel_json),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT 1 FROM material_gate_passes WHERE tracking_token_hash=%s AND (material_photo=%s OR bill_photo=%s OR material_photos @> %s::jsonb OR bill_photos @> %s::jsonb)",
                (thash, norm_rel, norm_rel, rel_json, rel_json),
            ).fetchone()
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
    rel_json = json.dumps([norm_rel])
    with db() as conn:
        if parts[0] == "visitors":
            if not is_adm and not module_access(who, "visitors"):
                abort(403)
            row = conn.execute(
                f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id_card_photo=%s OR selfie_photo=%s OR id_card_photos @> %s::jsonb OR selfie_photos @> %s::jsonb",
                (norm_rel, norm_rel, rel_json, rel_json),
            ).fetchone()
            if not row:
                abort(404)
            if not visitor_row_visible(_visitor_json(row), who, is_adm):
                abort(403)
        else:
            if not is_adm and not module_access(who, "gatepass"):
                abort(403)
            row = conn.execute(
                f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE material_photo=%s OR bill_photo=%s OR material_photos @> %s::jsonb OR bill_photos @> %s::jsonb",
                (norm_rel, norm_rel, rel_json, rel_json),
            ).fetchone()
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
        id_files = request.files.getlist("idCardPhoto") if is_multi else []
        sf_files = request.files.getlist("selfiePhoto") if is_multi else []
        id_rels, err1 = _save_gate_image_batch(id_files, body.get("idCardDataUrls"), body.get("idCardDataUrl"), "visitors", vid, "id")
        if err1:
            return jsonify(error=err1), 400
        sf_rels, err2 = _save_gate_image_batch(sf_files, body.get("selfieDataUrls"), body.get("selfieDataUrl"), "visitors", vid, "selfie")
        if err2:
            return jsonify(error=err2), 400
        id_rel = id_rels[0] if id_rels else ""
        sf_rel = sf_rels[0] if sf_rels else ""
        conn.execute(
            "INSERT INTO visitor_passes(id,tracking_token_hash,factory,visitor_name,phone,address,purpose,department,host_username,host_name,vehicle_no,pass_no,visitor_count,belongings,id_card_photo,selfie_photo,id_card_photos,selfie_photos,status,entered_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,'Pending',%s)",
            (vid, token_hash, factory, visitor_name, phone, address, purpose, department, host_username, host_name, vehicle_no, pass_no, visitor_count, belongings, id_rel, sf_rel, json.dumps(id_rels), json.dumps(sf_rels), entered_by),
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


def _append_visitor_photos_impl(visitor_id, is_public=False):
    body = request.get_json(silent=True) or {}
    if is_public:
        tok = str(body.get("token") or request.headers.get("X-Gate-Token") or "").strip()
        if not tok:
            return jsonify(error="Tracking token required to add photos to an existing visitor entry."), 403
        thash = hashlib.sha256(tok.encode()).hexdigest()
    else:
        who = session.get("profile") or {}
        is_adm = bool(session.get("is_admin"))
        if not is_adm and not module_access(who, "visitors", write=True):
            return jsonify(error="Write permission required for Visitor Pass."), 403
    with db() as conn:
        row = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s FOR UPDATE", (visitor_id,)).fetchone()
        if not row:
            abort(404)
        cur = _visitor_json(row)
        if is_public:
            if not row[1] or row[1] != thash:
                return jsonify(error="Invalid tracking token for this visitor entry."), 403
        elif not visitor_row_visible(cur, who, is_adm):
            return jsonify(error="You can only update visitors in your assigned department."), 403
        existing_id = _merge_photo_rels(row[14], row[25] if len(row) > 25 else None)
        existing_sf = _merge_photo_rels(row[15], row[26] if len(row) > 26 else None)
        new_id, err1 = _save_gate_image_batch(None, body.get("idCardDataUrls"), body.get("idCardDataUrl"), "visitors", visitor_id, f"id{len(existing_id)+1}_")
        if err1:
            return jsonify(error=err1), 400
        new_sf, err2 = _save_gate_image_batch(None, body.get("selfieDataUrls"), body.get("selfieDataUrl"), "visitors", visitor_id, f"selfie{len(existing_sf)+1}_")
        if err2:
            return jsonify(error=err2), 400
        merged_id = (existing_id + new_id)[:20]
        merged_sf = (existing_sf + new_sf)[:20]
        conn.execute(
            "UPDATE visitor_passes SET id_card_photo=%s, selfie_photo=%s, id_card_photos=%s::jsonb, selfie_photos=%s::jsonb, updated_at=now() WHERE id=%s",
            (merged_id[0] if merged_id else "", merged_sf[0] if merged_sf else "", json.dumps(merged_id), json.dumps(merged_sf), visitor_id),
        )
        updated = conn.execute(f"SELECT {VISITOR_COLS} FROM visitor_passes WHERE id=%s", (visitor_id,)).fetchone()
        _pg_emit_notify(conn, "visitor", {"action": "photos", "id": visitor_id})
    return jsonify(ok=True, visitor=_visitor_json(updated, include_private=not is_public, public_token=tok if is_public else ""))


@app.post("/api/public/visitors/<path:visitor_id>/photos")
def append_public_visitor_photos(visitor_id):
    return _append_visitor_photos_impl(visitor_id, is_public=True)


@app.post("/api/visitors/<path:visitor_id>/photos")
@signed_in
def append_visitor_photos(visitor_id):
    return _append_visitor_photos_impl(visitor_id, is_public=False)


@app.delete("/api/visitors/<path:visitor_id>")
@signed_in
def delete_visitor(visitor_id):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not is_gate_security_or_admin(who):
        return jsonify(error="Administrator or Security Incharge access required."), 403
    with db() as conn:
        row = conn.execute("DELETE FROM visitor_passes WHERE id=%s RETURNING id_card_photo, selfie_photo, id_card_photos, selfie_photos", (visitor_id,)).fetchone()
        if not row:
            abort(404)
        all_rels = _merge_photo_rels(row[0], row[2]) + _merge_photo_rels(row[1], row[3])
        for rel in all_rels:
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
    try:
        expected_days = max(0, min(3650, int(body.get("expectedDays") or 0))) if returnable else 0
    except (TypeError, ValueError):
        expected_days = 0
    expected_return_at = _parse_dt_bound(body.get("expectedReturnAt")) if returnable else None
    if returnable and expected_return_at is None and expected_days > 0:
        expected_return_at = datetime.now(timezone.utc) + timedelta(days=expected_days)
    elif returnable and expected_return_at is not None and expected_days == 0:
        delta_s = (expected_return_at - datetime.now(timezone.utc)).total_seconds()
        expected_days = max(1, int((delta_s + 86399) // 86400)) if delta_s > 0 else 1
    return_note = str(body.get("returnNote") or "").strip()[:300]
    with db() as conn:
        if is_public:
            recent = conn.execute("SELECT count(*) FROM material_gate_passes WHERE created_at > now() - interval '10 minutes'").fetchone()[0]
            if recent >= 60:
                return jsonify(error="Too many material entries submitted in 10 minutes."), 429
        for_username, for_name = _resolve_portal_employee(conn, factory, department, emp_key, fallback_name=for_manual)
        if not for_name:
            for_name = department + " Team"
        gid, _ = _next_gate_id(conn, "material_gate_passes", "MOUT" if direction == "OUT" else "MIN")
        mat_files = request.files.getlist("materialPhoto") if is_multi else []
        bill_files = request.files.getlist("billPhoto") if is_multi else []
        mat_rels, err1 = _save_gate_image_batch(mat_files, body.get("materialDataUrls"), body.get("materialDataUrl"), "gatepass", gid, "material")
        if err1:
            return jsonify(error=err1), 400
        bill_rels, err2 = _save_gate_image_batch(bill_files, body.get("billDataUrls"), body.get("billDataUrl"), "gatepass", gid, "bill")
        if err2:
            return jsonify(error=err2), 400
        mat_rel = mat_rels[0] if mat_rels else ""
        bill_rel = bill_rels[0] if bill_rels else ""
        conn.execute(
            "INSERT INTO material_gate_passes(id,tracking_token_hash,direction,factory,material_type,material_name,quantity,unit,returnable,party_name,challan_no,vehicle_no,remarks,department,for_username,for_name,material_photo,bill_photo,material_photos,bill_photos,status,entered_by,expected_return_at,expected_days,return_note) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s)",
            (gid, token_hash, direction, factory, material_type, material_name, quantity, unit, returnable, party_name, challan_no, vehicle_no, remarks, department, for_username, for_name, mat_rel, bill_rel, json.dumps(mat_rels), json.dumps(bill_rels), init_status, entered_by, expected_return_at, expected_days, return_note),
        )
        dir_word = "Outward (OUT)" if direction == "OUT" else "Inward (IN)"
        due_txt = f" · Return due: {expected_return_at.strftime('%d %b %Y')}" if (returnable and expected_return_at) else (" · 🔄 Returnable" if returnable else "")
        _record_notification_event(conn, {
            "eventKey": f"gatepass:{gid}",
            "kind": "gatepass",
            "level": "info",
            "title": f"Material {dir_word}: {material_name} ({gid})",
            "body": f"For {for_name} ({department} · {factory}){' · Challan ' + challan_no if challan_no else ''}{due_txt}",
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
    ret_note = str(body.get("returnNote") or "").strip()[:300]
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
        if new_st == "Returned":
            conn.execute("UPDATE material_gate_passes SET status=%s, verified_by=%s, verified_at=now(), returned_at=now(), return_note=COALESCE(NULLIF(%s,''), return_note), updated_at=now() WHERE id=%s", (new_st, actor, ret_note, pass_id))
            _record_notification_event(conn, {
                "eventKey": f"gatepass-ret:{pass_id}",
                "kind": "gatepass",
                "level": "ok",
                "title": f"Returnable Material Returned ({pass_id}): {cur['materialName']}",
                "body": f"Marked Returned by {actor} · {cur['forName']} ({cur['department']} · {cur['factory']})",
                "factory": cur["factory"],
                "targetView": "gatepass",
                "targetTab": "RETURNABLE",
                "targetId": pass_id,
                "targetDepartment": cur["department"],
                "targetUsername": cur["forUsername"],
                "targetHostName": cur["forName"],
            })
        else:
            conn.execute("UPDATE material_gate_passes SET status=%s, verified_by=%s, verified_at=now(), updated_at=now() WHERE id=%s", (new_st, actor, pass_id))
        updated = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s", (pass_id,)).fetchone()
        _pg_emit_notify(conn, "gatepass", {"action": "status", "id": pass_id, "status": new_st})
    return jsonify(ok=True, gatePass=_gatepass_json(updated, include_private=True))


@app.post("/api/public/gate-passes/<path:pass_id>/return")
def public_mark_gatepass_returned(pass_id):
    body = request.get_json(silent=True) or {}
    guard = str(body.get("enteredBy") or "Security Gate").strip()[:80] or "Security Gate"
    note = str(body.get("returnNote") or "").strip()[:300]
    with db() as conn:
        row = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s FOR UPDATE", (pass_id,)).fetchone()
        if not row:
            return jsonify(error="Material pass not found."), 404
        if not row[8]:
            return jsonify(error="Only returnable items can be marked returned from Gate."), 400
        conn.execute("UPDATE material_gate_passes SET status='Returned', verified_by=%s, verified_at=now(), returned_at=now(), return_note=%s, updated_at=now() WHERE id=%s", (guard, note, pass_id))
        updated = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s", (pass_id,)).fetchone()
        cur = _gatepass_json(updated, include_private=True)
        _record_notification_event(conn, {
            "eventKey": f"gatepass-ret:{pass_id}",
            "kind": "gatepass",
            "level": "ok",
            "title": f"Returnable Material Completed ({pass_id}): {cur['materialName']}",
            "body": f"{'Received back IN' if cur['direction']=='OUT' else 'Sent back OUT'} at Gate by {guard} · For {cur['forName']} ({cur['department']} · {cur['factory']})",
            "factory": cur["factory"],
            "targetView": "gatepass",
            "targetTab": "RETURNABLE",
            "targetId": pass_id,
            "targetDepartment": cur["department"],
            "targetUsername": cur["forUsername"],
            "targetHostName": cur["forName"],
        })
        _pg_emit_notify(conn, "gatepass", {"action": "returned", "id": pass_id})
    return jsonify(ok=True, gatePass=_gatepass_json(updated, include_private=False))


def process_returnable_gatepass_reminders(conn):
    got_lock = conn.execute("SELECT pg_try_advisory_xact_lock(hashtext('northstar:returnable-gatepass-due'))").fetchone()[0]
    if not got_lock:
        return 0
    rows = conn.execute(f"""
        SELECT {GATEPASS_COLS}, last_reminder_at
        FROM material_gate_passes
        WHERE returnable = true
          AND status <> 'Returned'
          AND expected_return_at IS NOT NULL
          AND expected_return_at <= now()
          AND (last_reminder_at IS NULL OR last_reminder_at::date < CURRENT_DATE)
        ORDER BY expected_return_at ASC
        LIMIT 80
    """).fetchall()
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sent = 0
    for row in rows:
        item = _gatepass_json(row[:28], include_private=True)
        gid = item["id"]
        dir_up = item["direction"]
        due_str = row[24].astimezone(timezone(timedelta(hours=5, minutes=30))).strftime("%d %b %Y, %I:%M %p") if row[24] else ""
        sent_str = row[22].astimezone(timezone(timedelta(hours=5, minutes=30))).strftime("%d %b %Y") if row[22] else ""
        if dir_up == "OUT":
            title = f"⏰ OVERDUE Returnable Material ({gid}): {item['materialName']}"
            body = f"Sent OUT ({item['partyName'] or 'External'}) on {sent_str} — expected BACK IN by {due_str}, NOT YET RETURNED! For {item['forName']} ({item['department']} · {item['factory']})"
        else:
            title = f"⏰ OVERDUE Returnable Dispatch ({gid}): {item['materialName']}"
            body = f"Came IN ({item['partyName'] or 'Vendor'}) on {sent_str} — expected BACK OUT by {due_str}, NOT YET DISPATCHED BACK! For {item['forName']} ({item['department']} · {item['factory']})"
        _record_notification_event(conn, {
            "eventKey": f"gatepass-due:{gid}:{today_key}",
            "kind": "gatepass",
            "level": "critical",
            "title": title[:180],
            "body": body[:400],
            "factory": item["factory"],
            "targetView": "gatepass",
            "targetTab": "RETURNABLE",
            "targetId": gid,
            "targetDepartment": item["department"],
            "targetUsername": item["forUsername"],
            "targetHostName": item["forName"],
        })
        conn.execute("UPDATE material_gate_passes SET last_reminder_at=now(), updated_at=now() WHERE id=%s", (gid,))
        sent += 1
    return sent


_RETURNABLE_SCHED_STARTED = False
_RETURNABLE_SCHED_LOCK = threading.Lock()


def _start_returnable_scheduler():
    global _RETURNABLE_SCHED_STARTED
    if _RETURNABLE_SCHED_STARTED:
        return
    with _RETURNABLE_SCHED_LOCK:
        if _RETURNABLE_SCHED_STARTED:
            return
        _RETURNABLE_SCHED_STARTED = True

        def _loop():
            time.sleep(8)
            while True:
                try:
                    with db() as conn:
                        process_returnable_gatepass_reminders(conn)
                except Exception:
                    pass
                try:
                    with db() as conn:
                        _evaluate_task_reminders(conn)
                except Exception:
                    pass
                time.sleep(60)

        t = threading.Thread(target=_loop, name="northstar-returnable-reminders", daemon=True)
        t.start()


def _append_gatepass_photos_impl(pass_id, is_public=False):
    body = request.get_json(silent=True) or {}
    if is_public:
        tok = str(body.get("token") or request.headers.get("X-Gate-Token") or "").strip()
        if not tok:
            return jsonify(error="Tracking token required to add photos to an existing gate pass."), 403
        thash = hashlib.sha256(tok.encode()).hexdigest()
    else:
        who = session.get("profile") or {}
        is_adm = bool(session.get("is_admin"))
        if not is_adm and not module_access(who, "gatepass", write=True):
            return jsonify(error="Write permission required for Material Gate Pass."), 403
    with db() as conn:
        row = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s FOR UPDATE", (pass_id,)).fetchone()
        if not row:
            abort(404)
        cur = _gatepass_json(row)
        if is_public:
            if not row[1] or row[1] != thash:
                return jsonify(error="Invalid tracking token for this gate pass."), 403
        elif not gatepass_row_visible(cur, who, is_adm):
            return jsonify(error="You can only update materials assigned to your account or gate scope."), 403
        existing_mat = _merge_photo_rels(row[16], row[28] if len(row) > 28 else None)
        existing_bill = _merge_photo_rels(row[17], row[29] if len(row) > 29 else None)
        new_mat, err1 = _save_gate_image_batch(None, body.get("materialDataUrls"), body.get("materialDataUrl"), "gatepass", pass_id, f"material{len(existing_mat)+1}_")
        if err1:
            return jsonify(error=err1), 400
        new_bill, err2 = _save_gate_image_batch(None, body.get("billDataUrls"), body.get("billDataUrl"), "gatepass", pass_id, f"bill{len(existing_bill)+1}_")
        if err2:
            return jsonify(error=err2), 400
        merged_mat = (existing_mat + new_mat)[:20]
        merged_bill = (existing_bill + new_bill)[:20]
        conn.execute(
            "UPDATE material_gate_passes SET material_photo=%s, bill_photo=%s, material_photos=%s::jsonb, bill_photos=%s::jsonb, updated_at=now() WHERE id=%s",
            (merged_mat[0] if merged_mat else "", merged_bill[0] if merged_bill else "", json.dumps(merged_mat), json.dumps(merged_bill), pass_id),
        )
        updated = conn.execute(f"SELECT {GATEPASS_COLS} FROM material_gate_passes WHERE id=%s", (pass_id,)).fetchone()
        _pg_emit_notify(conn, "gatepass", {"action": "photos", "id": pass_id})
    return jsonify(ok=True, gatePass=_gatepass_json(updated, include_private=not is_public, public_token=tok if is_public else ""))


@app.post("/api/public/gate-passes/<path:pass_id>/photos")
def append_public_gatepass_photos(pass_id):
    return _append_gatepass_photos_impl(pass_id, is_public=True)


@app.post("/api/gate-passes/<path:pass_id>/photos")
@signed_in
def append_gatepass_photos(pass_id):
    return _append_gatepass_photos_impl(pass_id, is_public=False)


@app.delete("/api/gate-passes/<path:pass_id>")
@signed_in
def delete_gatepass(pass_id):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not is_gate_security_or_admin(who):
        return jsonify(error="Administrator or Security Incharge access required."), 403
    with db() as conn:
        row = conn.execute("DELETE FROM material_gate_passes WHERE id=%s RETURNING material_photo, bill_photo, material_photos, bill_photos", (pass_id,)).fetchone()
        if not row:
            abort(404)
        all_rels = _merge_photo_rels(row[0], row[2]) + _merge_photo_rels(row[1], row[3])
        for rel in all_rels:
            if rel:
                try:
                    p = (UPLOAD_DIR / rel).resolve()
                    if p.is_relative_to((UPLOAD_DIR / "gatepass").resolve()):
                        p.unlink(missing_ok=True)
                except Exception:
                    pass
        _pg_emit_notify(conn, "gatepass", {"action": "delete", "id": pass_id})
    return jsonify(ok=True)


_VAULT_PBKDF2_ITERS = 480000
_VAULT_AAD_DEK = b"northstar-vault-dek-v1"
_VAULT_AAD_VOICE_TPL = b"northstar-vault-voice-tpl-v1"


def _vault_derive_kek(material_bytes, salt_b64):
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_VAULT_PBKDF2_ITERS,
    )
    return kdf.derive(material_bytes)


def _vault_aes_encrypt(key32, plaintext_bytes, aad):
    nonce = os.urandom(12)
    ct = AESGCM(key32).encrypt(nonce, plaintext_bytes, aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def _vault_aes_decrypt(key32, blob_b64, aad):
    raw = base64.b64decode(blob_b64)
    if len(raw) < 28:
        raise ValueError("Invalid ciphertext payload")
    return AESGCM(key32).decrypt(raw[:12], raw[12:], aad)


def _vault_pin_kw_kek(pin, keyword, salt_b64):
    return _vault_derive_kek(f"{pin}|{keyword}".encode("utf-8"), salt_b64)


def _vault_voice_kek(norm_phrase, salt_b64):
    return _vault_derive_kek(f"{APP_SECRET}|voice|{norm_phrase}".encode("utf-8"), salt_b64)


def _vault_voice_tpl_key(salt_b64):
    return _vault_derive_kek(f"{APP_SECRET}|voice-tpl|{salt_b64}".encode("utf-8"), salt_b64)


def _norm_voice_phrase(raw_phrase):
    cleaned = re.sub(r"[^a-z0-9]+", " ", str(raw_phrase or "").strip().lower()).strip()
    return re.sub(r"\s+", "", cleaned)


def _norm_vec(values, expected_len):
    if not isinstance(values, (list, tuple)) or len(values) != expected_len:
        return None
    out = []
    for x in values:
        try:
            v = float(x)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(v):
            return None
        out.append(v)
    norm = math.sqrt(sum(v * v for v in out))
    if norm <= 1e-9:
        return [0.0] * expected_len
    return [v / norm for v in out]


def _cosine_sim(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na <= 1e-9 or nb <= 1e-9:
        return 0.0
    return max(-1.0, min(1.0, sum(x * y for x, y in zip(a, b)) / (na * nb)))


def _pearson_sim(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    ma = sum(a) / len(a)
    mb = sum(b) / len(b)
    return _cosine_sim([x - ma for x in a], [y - mb for y in b])


def _extract_clean_voice_sig(raw):
    if not isinstance(raw, dict):
        return None
    try:
        voiced_ms = float(raw.get("voicedMs", 0))
        rms_mean = float(raw.get("rmsMean", 0))
        f0_median = float(raw.get("f0Median", 0))
        zcr_mean = float(raw.get("zcrMean", 0))
        centroid_mean = float(raw.get("centroidMean", 0))
    except (TypeError, ValueError):
        return None
    bands16 = _norm_vec(raw.get("bands16"), 16)
    energy_env12 = _norm_vec(raw.get("energyEnv12"), 12)
    pitch_env8 = _norm_vec(raw.get("pitchEnv8"), 8)
    if not bands16 or not energy_env12 or not pitch_env8:
        return None
    if not (math.isfinite(voiced_ms) and math.isfinite(rms_mean) and math.isfinite(f0_median)):
        return None
    return {
        "voicedMs": voiced_ms,
        "rmsMean": rms_mean,
        "f0Median": f0_median,
        "zcrMean": zcr_mean if math.isfinite(zcr_mean) else 0.0,
        "centroidMean": centroid_mean if math.isfinite(centroid_mean) else 0.0,
        "bands16": bands16,
        "energyEnv12": energy_env12,
        "pitchEnv8": pitch_env8,
    }


def _merge_voice_templates(samples):
    cleaned = [_extract_clean_voice_sig(s) for s in (samples or [])]
    cleaned = [c for c in cleaned if c and c["voicedMs"] >= 260 and c["rmsMean"] >= 0.006]
    if not cleaned:
        return None
    n = float(len(cleaned))
    bands = [sum(c["bands16"][i] for c in cleaned) / n for i in range(16)]
    env = [sum(c["energyEnv12"][i] for c in cleaned) / n for i in range(12)]
    p_env = [sum(c["pitchEnv8"][i] for c in cleaned) / n for i in range(8)]
    return {
        "voicedMs": sum(c["voicedMs"] for c in cleaned) / n,
        "rmsMean": sum(c["rmsMean"] for c in cleaned) / n,
        "f0Median": sum(c["f0Median"] for c in cleaned) / n,
        "zcrMean": sum(c["zcrMean"] for c in cleaned) / n,
        "centroidMean": sum(c["centroidMean"] for c in cleaned) / n,
        "bands16": _norm_vec(bands, 16),
        "energyEnv12": _norm_vec(env, 12),
        "pitchEnv8": _norm_vec(p_env, 8),
    }


def _compare_voice_signatures(tpl, cand):
    if not tpl or not cand or cand["voicedMs"] < 260 or cand["rmsMean"] < 0.006:
        return False, 0.0, {"reason": "audio_too_quiet_or_short"}
    bt = _norm_vec(tpl.get("bands16"), 16)
    bc = _norm_vec(cand.get("bands16"), 16)
    et = _norm_vec(tpl.get("energyEnv12"), 12)
    ec = _norm_vec(cand.get("energyEnv12"), 12)
    pt = _norm_vec(tpl.get("pitchEnv8"), 8)
    pc = _norm_vec(cand.get("pitchEnv8"), 8)
    if not (bt and bc and et and ec and pt and pc):
        return False, 0.0, {"reason": "invalid_feature_vector"}
    timbre_raw = _cosine_sim(bt, bc)
    timbre_shape = max(0.0, _pearson_sim(bt, bc))
    timbre_l1 = max(0.0, 1.0 - (sum(abs(x - y) for x, y in zip(bt, bc)) / 1.4))
    timbre_sim = 0.25 * timbre_raw + 0.45 * timbre_shape + 0.30 * timbre_l1
    energy_raw = _cosine_sim(et, ec)
    energy_shape = max(0.0, _pearson_sim(et, ec))
    energy_sim = 0.40 * energy_raw + 0.60 * energy_shape
    pitch_env_sim = max(0.0, _cosine_sim(pt, pc))
    f0_t = float(tpl.get("f0Median") or 0.0)
    f0_c = float(cand.get("f0Median") or 0.0)
    if f0_t >= 55.0 and f0_c >= 55.0:
        f0_err = abs(f0_t - f0_c) / max(f0_t, f0_c)
        f0_score = max(0.0, 1.0 - (f0_err / 0.22))
    else:
        f0_err = 0.0 if (f0_t < 55.0 and f0_c < 55.0) else 0.5
        f0_score = 0.7 if f0_err == 0.0 else 0.0
    rms_t = max(float(tpl.get("rmsMean") or 0.001), 0.001)
    rms_c = max(float(cand.get("rmsMean") or 0.001), 0.001)
    rms_ratio = min(rms_t, rms_c) / max(rms_t, rms_c)
    tune_score = 0.65 * f0_score + 0.35 * pitch_env_sim
    combined = (0.42 * timbre_sim) + (0.28 * energy_sim) + (0.22 * tune_score) + (0.08 * min(1.0, rms_ratio / 0.65))
    passed = (
        timbre_sim >= 0.80
        and energy_sim >= 0.76
        and f0_err <= 0.19
        and rms_ratio >= 0.25
        and combined >= 0.83
    )
    return passed, round(combined, 4), {
        "timbreSim": round(timbre_sim, 4),
        "energySim": round(energy_sim, 4),
        "pitchRatioErr": round(f0_err, 4),
        "tuneScore": round(tune_score, 4),
        "intensityRatio": round(rms_ratio, 4),
        "combined": round(combined, 4),
    }


_VAULT_SHARE_KEY_PATH = UPLOAD_DIR / ".ns_vault_share.key"
_VAULT_SHARE_KEY_CACHE = None


def _vault_ukey(username):
    return str(username or "").strip().casefold()[:120]


def _vault_current_ukey(who=None):
    w = who if isinstance(who, dict) else (session.get("profile") or {})
    return _vault_ukey(w.get("username") or session.get("user") or "")


def _vault_share_wrap_key():
    global _VAULT_SHARE_KEY_CACHE
    if _VAULT_SHARE_KEY_CACHE is not None:
        return _VAULT_SHARE_KEY_CACHE
    raw_bytes = None
    try:
        if _VAULT_SHARE_KEY_PATH.exists():
            b = _VAULT_SHARE_KEY_PATH.read_bytes()
            if len(b) == 32:
                raw_bytes = b
        if raw_bytes is None:
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            b = os.urandom(32)
            fd = os.open(str(_VAULT_SHARE_KEY_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, b)
            finally:
                os.close(fd)
            raw_bytes = b
    except FileExistsError:
        try:
            raw_bytes = _VAULT_SHARE_KEY_PATH.read_bytes()
        except Exception:
            raw_bytes = None
    except Exception:
        raw_bytes = None
    if not raw_bytes or len(raw_bytes) != 32:
        raw_bytes = hashlib.sha256((APP_SECRET + "|fallback-share-wrap").encode("utf-8")).digest()
    _VAULT_SHARE_KEY_CACHE = hashlib.sha256(raw_bytes + b"|ns-share-v1|" + APP_SECRET.encode("utf-8")).digest()
    return _VAULT_SHARE_KEY_CACHE


def _vault_user_lookup_map(conn):
    u_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    users = u_row[0] if u_row and isinstance(u_row[0], list) else []
    d_row = conn.execute("SELECT value FROM app_state WHERE key='departments'").fetchone()
    depts = d_row[0] if d_row and isinstance(d_row[0], list) else []
    by_ukey = {}
    for u in users:
        if isinstance(u, dict):
            uk = _vault_ukey(u.get("username"))
            if uk:
                by_ukey[uk] = u
    return by_ukey, users, depts


def _vault_user_dept_lower(by_ukey, ukey, who=None):
    u = by_ukey.get(_vault_ukey(ukey)) or (who if isinstance(who, dict) else {})
    return str(u.get("dept") or u.get("department") or "").strip().casefold()


def _vault_log_audit(conn, event_type, actor="", target="", detail="", owner_scope=""):
    scope = _vault_ukey(owner_scope or actor)
    try:
        ip = str(request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()[:64]
        conn.execute(
            "INSERT INTO vault_audit_logs(event_type, actor, target, detail, ip_address, owner_scope) VALUES(%s,%s,%s,%s,%s,%s)",
            (str(event_type)[:60], str(actor)[:120], str(target)[:160], str(detail)[:400], ip, scope),
        )
    except Exception:
        try:
            ip = str(request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()[:64]
            conn.execute(
                "INSERT INTO vault_audit_logs(event_type, actor, target, detail, ip_address) VALUES(%s,%s,%s,%s,%s)",
                (str(event_type)[:60], str(actor)[:120], str(target)[:160], str(detail)[:400], ip),
            )
        except Exception:
            pass


def _vault_migrate_legacy_if_needed(conn):
    try:
        cnt_row = conn.execute("SELECT count(*) FROM vault_user_security").fetchone()
        if cnt_row and int(cnt_row[0] or 0) > 0:
            return
        legacy = conn.execute("""
            SELECT id, initialized, pin_min_len, pin_max_len, pin_length,
                   pin_hash, keyword_hash, kdf_salt, wrapped_dek_pin_kw,
                   voice_enabled, voice_phrase_hash, voice_feature_enc, wrapped_dek_voice,
                   failed_attempts, max_attempts, permanently_locked, locked_at,
                   auto_lock_minutes, updated_at, updated_by, download_password_hash
            FROM vault_security_config WHERE id=1
        """).fetchone()
        if not legacy or not bool(legacy[1]):
            return
        by_ukey, users, _ = _vault_user_lookup_map(conn)
        hint = _vault_ukey(legacy[19])
        legacy_ukey = hint if hint in by_ukey else ""
        if not legacy_ukey and legacy[19]:
            hint_low = str(legacy[19]).strip().casefold()
            for uk, u in by_ukey.items():
                if str(u.get("name") or "").strip().casefold() == hint_low:
                    legacy_ukey = uk
                    break
        if not legacy_ukey:
            for u in users:
                if isinstance(u, dict) and u.get("enabled", True) and u.get("role") == "Administrator":
                    legacy_ukey = _vault_ukey(u.get("username"))
                    if legacy_ukey:
                        break
        if not legacy_ukey:
            legacy_ukey = _vault_current_ukey() or "admin"
        conn.execute(
            """
            INSERT INTO vault_user_security(
                username, initialized, pin_length, pin_hash, keyword_hash, kdf_salt,
                wrapped_dek_pin_kw, voice_enabled, voice_phrase_hash, voice_feature_enc,
                wrapped_dek_voice, download_password_hash, failed_attempts, max_attempts,
                permanently_locked, locked_at, auto_lock_minutes, updated_at, updated_by
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,COALESCE(%s,now()),%s)
            ON CONFLICT(username) DO NOTHING
            """,
            (
                legacy_ukey, bool(legacy[1]), int(legacy[4] or 4), str(legacy[5] or ""), str(legacy[6] or ""),
                str(legacy[7] or ""), str(legacy[8] or ""), bool(legacy[9]), str(legacy[10] or ""),
                str(legacy[11] or ""), str(legacy[12] or ""), str(legacy[20] or ""),
                int(legacy[13] or 0), max(3, int(legacy[14] or 5)), bool(legacy[15]),
                legacy[16], int(legacy[17] or 10), legacy[18], str(legacy[19] or legacy_ukey),
            ),
        )
        conn.execute("UPDATE vault_credentials SET owner_username=%s WHERE owner_username=''", (legacy_ukey,))
        conn.execute("UPDATE vault_documents SET owner_username=%s WHERE owner_username=''", (legacy_ukey,))
        conn.execute("UPDATE vault_doc_folders SET owner_username=%s WHERE owner_username=''", (legacy_ukey,))
    except Exception:
        pass


def _vault_ensure_config_row(conn, username_ukey=None):
    ukey = _vault_ukey(username_ukey) or _vault_current_ukey()
    if not ukey:
        ukey = "admin"
    _vault_migrate_legacy_if_needed(conn)
    conn.execute("INSERT INTO vault_user_security(username) VALUES(%s) ON CONFLICT(username) DO NOTHING", (ukey,))
    return conn.execute("""
        SELECT username, initialized, 4 AS pin_min_len, 8 AS pin_max_len, pin_length,
               pin_hash, keyword_hash, kdf_salt, wrapped_dek_pin_kw,
               voice_enabled, voice_phrase_hash, voice_feature_enc, wrapped_dek_voice,
               failed_attempts, max_attempts, permanently_locked, locked_at,
               auto_lock_minutes, updated_at, updated_by, download_password_hash
        FROM vault_user_security WHERE username=%s
    """, (ukey,)).fetchone()


def _vault_sess_aad(sid):
    return f"ns-vsess:{sid}".encode("utf-8")


def _vault_get_active_dek(sid, auto_lock_minutes=10, conn=None, expected_ukey=None):
    if not sid:
        return None, 0
    sid_str = str(sid)
    exp_u = _vault_ukey(expected_ukey) if expected_ukey is not None else _vault_current_ukey()
    ttl = max(60, min(7200, int(auto_lock_minutes or 10) * 60))

    def _lookup_and_refresh(c):
        c.execute("DELETE FROM vault_active_sessions WHERE expires_at <= now()")
        row = c.execute(
            "SELECT wrapped_dek, extract(epoch FROM (expires_at - now())), username FROM vault_active_sessions WHERE sid=%s AND expires_at > now()",
            (sid_str,),
        ).fetchone()
        if not row:
            with _VAULT_LOCK:
                _VAULT_SESSIONS.pop(sid_str, None)
            return None, 0
        sess_u = _vault_ukey(row[2] if len(row) > 2 else "")
        if exp_u and sess_u != exp_u:
            with _VAULT_LOCK:
                _VAULT_SESSIONS.pop(sid_str, None)
            return None, 0
        try:
            dek = _vault_aes_decrypt(_vault_session_wrap_key(), str(row[0]), _vault_sess_aad(sid_str))
        except Exception:
            c.execute("DELETE FROM vault_active_sessions WHERE sid=%s", (sid_str,))
            with _VAULT_LOCK:
                _VAULT_SESSIONS.pop(sid_str, None)
            return None, 0
        c.execute(
            "UPDATE vault_active_sessions SET expires_at=now() + (%s * interval '1 second') WHERE sid=%s",
            (ttl, sid_str),
        )
        with _VAULT_LOCK:
            _VAULT_SESSIONS[sid_str] = {"dek": dek, "expires_at": time.monotonic() + ttl, "username": sess_u}
        return dek, ttl

    try:
        if conn is not None:
            return _lookup_and_refresh(conn)
        with db() as c:
            return _lookup_and_refresh(c)
    except Exception:
        return None, 0


def _vault_set_active_dek(sid, username, dek_bytes, auto_lock_minutes=10, conn=None):
    sid_str = str(sid)
    ukey = _vault_ukey(username)
    ttl = max(60, min(7200, int(auto_lock_minutes or 10) * 60))
    wrapped = _vault_aes_encrypt(_vault_session_wrap_key(), dek_bytes, _vault_sess_aad(sid_str))

    def _upsert(c):
        c.execute("DELETE FROM vault_active_sessions WHERE expires_at <= now()")
        c.execute(
            """
            INSERT INTO vault_active_sessions(sid, username, wrapped_dek, expires_at)
            VALUES(%s, %s, %s, now() + (%s * interval '1 second'))
            ON CONFLICT(sid) DO UPDATE
            SET username=excluded.username, wrapped_dek=excluded.wrapped_dek, expires_at=excluded.expires_at
            """,
            (sid_str, ukey, wrapped, ttl),
        )

    if conn is not None:
        _upsert(conn)
    else:
        with db() as c:
            _upsert(c)
    with _VAULT_LOCK:
        _VAULT_SESSIONS[sid_str] = {"dek": dek_bytes, "username": ukey, "expires_at": time.monotonic() + ttl}
    return ttl


def _vault_record_failure(conn, owner_ukey, actor_display, reason_label):
    ukey = _vault_ukey(owner_ukey) or _vault_current_ukey()
    row = conn.execute(
        "SELECT failed_attempts, max_attempts FROM vault_user_security WHERE username=%s FOR UPDATE",
        (ukey,),
    ).fetchone()
    attempts = int(row[0] or 0) + 1 if row else 1
    max_att = max(3, int(row[1] or 5)) if row else 5
    tripped = attempts >= max_att
    conn.execute(
        """
        UPDATE vault_user_security
        SET failed_attempts=%s,
            permanently_locked=%s,
            locked_at=CASE WHEN %s THEN COALESCE(locked_at, now()) ELSE locked_at END,
            updated_at=now(),
            updated_by=%s
        WHERE username=%s
        """,
        (attempts, tripped, tripped, str(actor_display or ukey)[:120], ukey),
    )
    _vault_log_audit(conn, "vault_unlock_failed", actor_display, f"Attempt {attempts}/{max_att}", reason_label, owner_scope=ukey)
    if tripped:
        _vault_purge_session(sid=str(session.get("sid") or ""), username=ukey, conn=conn)
        _vault_log_audit(conn, "vault_self_locked", actor_display, f"{attempts} failures", reason_label, owner_scope=ukey)
        _record_notification_event(conn, {
            "eventKey": f"vault-self-lock:{ukey}:{int(time.time())}",
            "kind": "system",
            "level": "critical",
            "title": "🔐 SECURITY ALERT: Personal Credentials Vault Self-Locked",
            "body": f"Vault locked automatically after {attempts} failed unlock attempts ({reason_label}) for account {actor_display or ukey}. Administrator verification required.",
            "targetView": "credentials",
            "targetTab": "LOCKED",
            "targetUsername": ukey,
        })
    return attempts, max_att, tripped


def _vault_norm_shares(shared_users_raw, shared_depts_raw, owner_ukey=""):
    o_uk = _vault_ukey(owner_ukey)
    u_map = {}
    if isinstance(shared_users_raw, dict):
        for k, v in shared_users_raw.items():
            uk = _vault_ukey(k)
            perm = str(v or "").strip().lower()
            if uk and uk != o_uk and perm in ("read", "edit"):
                u_map[uk] = perm
    d_map = {}
    if isinstance(shared_depts_raw, dict):
        for k, v in shared_depts_raw.items():
            dk = str(k or "").strip().casefold()[:120]
            perm = str(v or "").strip().lower()
            if dk and perm in ("read", "edit"):
                d_map[dk] = perm
    return u_map, d_map


def _vault_item_access(owner_ukey, shared_users, shared_depts, my_ukey, my_dept_lower):
    o_uk = _vault_ukey(owner_ukey)
    me = _vault_ukey(my_ukey)
    if me and o_uk == me:
        return "owner"
    u_perm = (shared_users or {}).get(me) if isinstance(shared_users, dict) else None
    d_perm = (shared_depts or {}).get(my_dept_lower) if (isinstance(shared_depts, dict) and my_dept_lower) else None
    grants = [p for p in (u_perm, d_perm) if p in ("read", "edit")]
    if "edit" in grants:
        return "edit"
    if "read" in grants:
        return "read"
    return None


def _vault_resolve_item_key(user_dek, shared_item_key_enc, aad_prefix):
    if shared_item_key_enc:
        return _vault_aes_decrypt(_vault_share_wrap_key(), str(shared_item_key_enc), aad_prefix + b":skey")
    return user_dek


@app.get("/api/vault/status")
@signed_in
def get_vault_status():
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin") or who.get("role") == "Administrator")
    if not is_adm and not module_access(who, "credentials"):
        return jsonify(error="Credentials Vault access required."), 403
    my_ukey = _vault_current_ukey(who)
    sid = str(session.get("sid") or "")
    locked_users = []
    shared_count = 0
    with db() as conn:
        cfg = _vault_ensure_config_row(conn, my_ukey)
        auto_mins = int(cfg[17] or 10)
        dek, expires_sec = _vault_get_active_dek(sid, auto_mins, conn=conn, expected_ukey=my_ukey)
        if bool(cfg[15]):  # permanently_locked
            dek = None
            expires_sec = 0
            _vault_purge_session(sid=sid, conn=conn)
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        try:
            c_rows = conn.execute("SELECT owner_username, shared_users, shared_depts FROM vault_credentials").fetchall()
            d_rows = conn.execute("SELECT owner_username, shared_users, shared_depts FROM vault_documents").fetchall()
            for r in list(c_rows) + list(d_rows):
                if _vault_ukey(r[0]) != my_ukey and _vault_item_access(r[0], r[1], r[2], my_ukey, my_dept_low):
                    shared_count += 1
        except Exception:
            shared_count = 0
        if is_adm:
            try:
                l_rows = conn.execute("SELECT username, failed_attempts, locked_at FROM vault_user_security WHERE permanently_locked=true ORDER BY locked_at DESC NULLS LAST").fetchall()
                for lr in l_rows:
                    u_obj = by_ukey.get(_vault_ukey(lr[0])) or {}
                    locked_users.append({
                        "username": lr[0],
                        "name": u_obj.get("name") or lr[0],
                        "dept": u_obj.get("dept") or u_obj.get("department") or "",
                        "failedAttempts": int(lr[1] or 0),
                        "lockedAt": lr[2].isoformat() if lr[2] else "",
                    })
            except Exception:
                locked_users = []
    failed = int(cfg[13] or 0)
    max_att = max(3, int(cfg[14] or 5))
    return jsonify(
        ownerUsername=my_ukey,
        initialized=bool(cfg[1]),
        unlocked=dek is not None,
        expiresInSec=expires_sec,
        pinMinLen=4,
        pinMaxLen=8,
        pinLength=int(cfg[4] or 4),
        voiceEnabled=bool(cfg[9]),
        hasDownloadPassword=bool(cfg[20]),
        failedAttempts=failed,
        maxAttempts=max_att,
        remainingAttempts=max(0, max_att - failed),
        permanentlyLocked=bool(cfg[15]),
        lockedAt=cfg[16].isoformat() if cfg[16] else "",
        autoLockMinutes=auto_mins,
        canConfigure=True,
        canWrite=bool(is_adm or module_access(who, "credentials", write=True)),
        isAdmin=is_adm,
        sharedWithMeCount=shared_count,
        lockedUsers=locked_users,
        updatedAt=cfg[18].isoformat() if cfg[18] else "",
        updatedBy=cfg[19] or "",
    )


@app.post("/api/vault/config")
@signed_in
def save_vault_config():
    data = request.get_json(silent=True) or {}
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin") or who.get("role") == "Administrator")
    if not is_adm and not module_access(who, "credentials"):
        return jsonify(error="Credentials Vault access required."), 403
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    sid = str(session.get("sid") or "")
    pin = str(data.get("pin") or "").strip()
    keyword = str(data.get("keyword") or "").strip()
    try:
        auto_mins = max(1, min(120, int(data.get("autoLockMinutes", 10) or 10)))
    except (TypeError, ValueError):
        auto_mins = 10
    voice_enabled = bool(data.get("voiceEnabled", False))
    raw_phrase = str(data.get("voicePhrase") or "").strip()
    norm_phrase = _norm_voice_phrase(raw_phrase)
    voice_samples = data.get("voiceSamples")
    dl_pwd = str(data.get("downloadPassword") or "").strip()

    with db() as conn:
        cfg = _vault_ensure_config_row(conn, my_ukey)
        initialized = bool(cfg[1])
        if bool(cfg[15]):
            return jsonify(error="Your personal Vault is self-locked after 5 failed attempts. Ask Administrator to reset lockout first."), 423

        old_salt = str(cfg[7] or "")
        old_wrapped_pin = str(cfg[8] or "")
        old_voice_phrase_hash = str(cfg[10] or "")
        old_voice_feat_enc = str(cfg[11] or "")
        old_wrapped_voice = str(cfg[12] or "")
        old_dl_hash = str(cfg[20] or "")
        if dl_pwd:
            if len(dl_pwd) < 4 or len(dl_pwd) > 200:
                return jsonify(error="Document download password must be 4 to 200 characters."), 400
            new_dl_hash = generate_password_hash(dl_pwd)
        else:
            new_dl_hash = old_dl_hash

        if not initialized:
            if not re.fullmatch(r"\d{4,8}", pin):
                return jsonify(error="PIN must be strictly 4 to 8 numeric digits."), 400
            if len(keyword) < 3 or len(keyword) > 80:
                return jsonify(error="Secret keyword must be 3 to 80 characters."), 400
            dek = os.urandom(32)
            pin_len = len(pin)
            pin_hash = generate_password_hash(pin)
            kw_hash = generate_password_hash(keyword)
        else:
            dek, _ = _vault_get_active_dek(sid, int(cfg[17] or 10), conn=conn, expected_ukey=my_ukey)
            if dek is None:
                cur_pin = str(data.get("currentPin") or "").strip()
                cur_kw = str(data.get("currentKeyword") or "").strip()
                if not cur_pin or not cur_kw:
                    return jsonify(error="Unlock your Vault first or provide your current PIN and keyword to update settings."), 401
                try:
                    cur_kek = _vault_pin_kw_kek(cur_pin, cur_kw, old_salt)
                    dek = _vault_aes_decrypt(cur_kek, old_wrapped_pin, _VAULT_AAD_DEK)
                except Exception:
                    return jsonify(error="Current PIN or keyword did not match."), 401
            if pin:
                if not re.fullmatch(r"\d{4,8}", pin):
                    return jsonify(error="New PIN must be strictly 4 to 8 numeric digits."), 400
                pin_len = len(pin)
                pin_hash = generate_password_hash(pin)
            else:
                pin_len = int(cfg[4] or 4)
                pin_hash = str(cfg[5] or "")
            if keyword:
                if len(keyword) < 3 or len(keyword) > 80:
                    return jsonify(error="Secret keyword must be 3 to 80 characters."), 400
                kw_hash = generate_password_hash(keyword)
            else:
                kw_hash = str(cfg[6] or "")

        if not initialized or (pin and keyword) or not old_salt:
            new_salt = base64.b64encode(os.urandom(32)).decode("ascii")
        else:
            new_salt = old_salt

        if pin and keyword:
            wrapped_pin_kw = _vault_aes_encrypt(_vault_pin_kw_kek(pin, keyword, new_salt), dek, _VAULT_AAD_DEK)
        elif not initialized:
            return jsonify(error="Both PIN and Secret Keyword are required."), 400
        elif pin or keyword:
            return jsonify(error="Provide both new PIN and Secret Keyword together when rotating keys."), 400
        else:
            wrapped_pin_kw = old_wrapped_pin

        new_voice_phrase_hash = ""
        new_voice_feat_enc = ""
        new_wrapped_voice = ""
        if voice_enabled:
            if isinstance(voice_samples, list) and len(voice_samples) > 0:
                if len(norm_phrase) < 3 or len(norm_phrase) > 64:
                    return jsonify(error="Voice unlock phrase must be 3 to 64 letters/digits (e.g. blackpearl)."), 400
                merged_tpl = _merge_voice_templates(voice_samples)
                if not merged_tpl:
                    return jsonify(error="Voice recording was too quiet or short. Speak the phrase clearly and try again."), 400
                new_voice_phrase_hash = generate_password_hash(norm_phrase)
                new_voice_feat_enc = _vault_aes_encrypt(
                    _vault_voice_tpl_key(new_salt),
                    json.dumps(merged_tpl).encode("utf-8"),
                    _VAULT_AAD_VOICE_TPL,
                )
                new_wrapped_voice = _vault_aes_encrypt(_vault_voice_kek(norm_phrase, new_salt), dek, _VAULT_AAD_DEK)
            elif old_voice_phrase_hash and old_voice_feat_enc and old_wrapped_voice:
                if new_salt != old_salt:
                    return jsonify(error="Re-record your Voice Lock sample when rotating vault PIN & Keyword."), 400
                new_voice_phrase_hash = old_voice_phrase_hash
                new_voice_feat_enc = old_voice_feat_enc
                new_wrapped_voice = old_wrapped_voice
            else:
                return jsonify(error="Record at least one clear voice sample and enter your secret voice phrase."), 400

        conn.execute(
            """
            UPDATE vault_user_security
            SET initialized=true,
                pin_length=%s,
                pin_hash=%s,
                keyword_hash=%s,
                kdf_salt=%s,
                wrapped_dek_pin_kw=%s,
                voice_enabled=%s,
                voice_phrase_hash=%s,
                voice_feature_enc=%s,
                wrapped_dek_voice=%s,
                download_password_hash=%s,
                failed_attempts=0,
                permanently_locked=false,
                locked_at=NULL,
                auto_lock_minutes=%s,
                updated_at=now(),
                updated_by=%s
            WHERE username=%s
            """,
            (
                pin_len, pin_hash, kw_hash, new_salt, wrapped_pin_kw,
                voice_enabled, new_voice_phrase_hash, new_voice_feat_enc, new_wrapped_voice,
                new_dl_hash, auto_mins, actor, my_ukey,
            ),
        )
        _vault_log_audit(conn, "vault_user_initialized" if not initialized else "vault_config_updated", actor, f"PIN {pin_len}d · Voice={'On' if voice_enabled else 'Off'}", f"DownloadPwd={'Set' if bool(new_dl_hash) else 'Unset'}", owner_scope=my_ukey)
        ttl = _vault_set_active_dek(sid, my_ukey, dek, auto_mins, conn=conn)
    return jsonify(ok=True, ownerUsername=my_ukey, unlocked=True, expiresInSec=ttl, pinLength=pin_len, voiceEnabled=voice_enabled, hasDownloadPassword=bool(new_dl_hash), autoLockMinutes=auto_mins)


@app.post("/api/vault/unlock")
@signed_in
def unlock_vault_pin_keyword():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "credentials"):
        return jsonify(error="Credentials Vault access required."), 403
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pin") or "").strip()
    keyword = str(data.get("keyword") or "").strip()
    sid = str(session.get("sid") or "")
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("username") or who.get("name") or my_ukey or "User")

    with db() as conn:
        cfg = _vault_ensure_config_row(conn, my_ukey)
        if not bool(cfg[1]):
            return jsonify(error="Set up your personal Vault PIN & Secret Keyword first before unlocking."), 400
        if bool(cfg[15]):
            return jsonify(error="Your Vault is self-locked after 5 failed attempts. Administrator password reset required.", permanentlyLocked=True, remainingAttempts=0), 423
        auto_mins = int(cfg[17] or 10)
        dek = None
        if re.fullmatch(r"\d{4,8}", pin) and keyword:
            try:
                kek = _vault_pin_kw_kek(pin, keyword, str(cfg[7] or ""))
                dek = _vault_aes_decrypt(kek, str(cfg[8] or ""), _VAULT_AAD_DEK)
            except Exception:
                dek = None
        if dek is None:
            attempts, max_att, tripped = _vault_record_failure(conn, my_ukey, actor, "PIN/Keyword mismatch")
            rem = max(0, max_att - attempts)
            code = 423 if tripped else 401
            msg = (
                "5 failed attempts reached — Your Vault is now self-locked! Administrator password required to reset."
                if tripped
                else f"Invalid PIN or secret keyword. {rem} attempt(s) remaining before self-lock."
            )
            return jsonify(error=msg, failedAttempts=attempts, maxAttempts=max_att, remainingAttempts=rem, permanentlyLocked=tripped), code
        conn.execute("UPDATE vault_user_security SET failed_attempts=0, updated_at=now() WHERE username=%s", (my_ukey,))
        _vault_log_audit(conn, "vault_unlocked_pin", actor, "Personal Vault", "PIN + Secret Keyword verified", owner_scope=my_ukey)
        ttl = _vault_set_active_dek(sid, my_ukey, dek, auto_mins, conn=conn)
    return jsonify(ok=True, unlocked=True, expiresInSec=ttl)


@app.post("/api/vault/unlock-voice")
@signed_in
def unlock_vault_voice():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "credentials"):
        return jsonify(error="Credentials Vault access required."), 403
    data = request.get_json(silent=True) or {}
    norm_phrase = _norm_voice_phrase(data.get("phrase"))
    cand = _extract_clean_voice_sig(data.get("sample"))
    sid = str(session.get("sid") or "")
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("username") or who.get("name") or my_ukey or "User")

    with db() as conn:
        cfg = _vault_ensure_config_row(conn, my_ukey)
        if not bool(cfg[1]) or not bool(cfg[9]):
            return jsonify(error="Voice matching lock is not enabled on your personal Vault."), 400
        if bool(cfg[15]):
            return jsonify(error="Your Vault is self-locked after 5 failed attempts. Administrator password reset required.", permanentlyLocked=True, remainingAttempts=0), 423
        auto_mins = int(cfg[17] or 10)
        salt_b64 = str(cfg[7] or "")
        phrase_ok = bool(norm_phrase) and check_password_hash(str(cfg[10] or ""), norm_phrase)
        match_ok = False
        score = 0.0
        details = {}
        dek = None
        if phrase_ok and cand:
            try:
                tpl_bytes = _vault_aes_decrypt(_vault_voice_tpl_key(salt_b64), str(cfg[11] or ""), _VAULT_AAD_VOICE_TPL)
                tpl = json.loads(tpl_bytes.decode("utf-8"))
                match_ok, score, details = _compare_voice_signatures(tpl, cand)
                if match_ok:
                    dek = _vault_aes_decrypt(_vault_voice_kek(norm_phrase, salt_b64), str(cfg[12] or ""), _VAULT_AAD_DEK)
            except Exception:
                match_ok = False
                dek = None
        if dek is None:
            attempts, max_att, tripped = _vault_record_failure(conn, my_ukey, actor, "Voice signature/phrase mismatch")
            rem = max(0, max_att - attempts)
            code = 423 if tripped else 401
            reason = "Spoken secret phrase did not match." if not phrase_ok else "Voice tone, tune, or intensity did not match owner's voiceprint."
            msg = (
                "5 failed attempts reached — Your Vault is now self-locked! Administrator password required to reset."
                if tripped
                else f"{reason} {rem} attempt(s) remaining before self-lock."
            )
            return jsonify(error=msg, failedAttempts=attempts, maxAttempts=max_att, remainingAttempts=rem, permanentlyLocked=tripped, matchScore=score, matchDetails=details), code
        conn.execute("UPDATE vault_user_security SET failed_attempts=0, updated_at=now() WHERE username=%s", (my_ukey,))
        _vault_log_audit(conn, "vault_unlocked_voice", actor, "Personal Vault", f"Voice biometric match ({round(score*100,1)}%)", owner_scope=my_ukey)
        ttl = _vault_set_active_dek(sid, my_ukey, dek, auto_mins, conn=conn)
    return jsonify(ok=True, unlocked=True, expiresInSec=ttl, matchScore=score, matchDetails=details)


@app.post("/api/vault/lock")
@signed_in
def lock_vault_session():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("username") or who.get("name") or my_ukey or "User")
    sid = str(session.get("sid") or "")
    with db() as conn:
        _vault_purge_session(sid=sid, conn=conn)
        _vault_log_audit(conn, "vault_locked", actor, "Personal Vault", "Manual session lock", owner_scope=my_ukey)
    return jsonify(ok=True, unlocked=False)


@app.post("/api/vault/admin-reset-lock")
@administrator
def admin_reset_vault_lock():
    who = session.get("profile") or {}
    admin_ukey = _vault_current_ukey(who)
    data = request.get_json(silent=True) or {}
    target_ukey = _vault_ukey(data.get("targetUsername") or admin_ukey)
    admin_password = str(data.get("adminPassword") or "")
    wipe_and_reinit = bool(data.get("wipeAndReinit", False))
    if not admin_password:
        return jsonify(error="Administrator account password is required."), 400

    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if _vault_ukey(u.get("username")) == admin_ukey), None)
        if not account or account.get("role") != "Administrator" or not account.get("password_hash") or not check_password_hash(account["password_hash"], admin_password):
            return jsonify(error="Administrator account password is incorrect."), 401
        _vault_ensure_config_row(conn, target_ukey)
        if wipe_and_reinit:
            pin = str(data.get("pin") or "").strip()
            keyword = str(data.get("keyword") or "").strip()
            if not re.fullmatch(r"\d{4,8}", pin) or len(keyword) < 3 or len(keyword) > 80:
                return jsonify(error="Enter a valid 4–8 digit PIN and 3–80 character keyword to re-initialize the Vault."), 400
            dek = os.urandom(32)
            new_salt = base64.b64encode(os.urandom(32)).decode("ascii")
            wrapped_pin_kw = _vault_aes_encrypt(_vault_pin_kw_kek(pin, keyword, new_salt), dek, _VAULT_AAD_DEK)
            conn.execute("DELETE FROM vault_credentials WHERE owner_username=%s", (target_ukey,))
            deleted_docs = conn.execute("DELETE FROM vault_documents WHERE owner_username=%s RETURNING enc_rel_path", (target_ukey,)).fetchall()
            conn.execute("DELETE FROM vault_doc_folders WHERE owner_username=%s", (target_ukey,))
            for dr in deleted_docs:
                try:
                    p = (VAULT_DOCS_DIR / str(dr[0])).resolve()
                    if p.is_relative_to(VAULT_DOCS_DIR.resolve()):
                        p.unlink(missing_ok=True)
                except Exception:
                    pass
            conn.execute(
                """
                UPDATE vault_user_security
                SET initialized=true, pin_length=%s, pin_hash=%s, keyword_hash=%s,
                    kdf_salt=%s, wrapped_dek_pin_kw=%s, voice_enabled=false,
                    voice_phrase_hash='', voice_feature_enc='', wrapped_dek_voice='',
                    download_password_hash='', failed_attempts=0, permanently_locked=false, locked_at=NULL,
                    updated_at=now(), updated_by=%s
                WHERE username=%s
                """,
                (len(pin), generate_password_hash(pin), generate_password_hash(keyword), new_salt, wrapped_pin_kw, admin_ukey, target_ukey),
            )
            _vault_purge_session(username=target_ukey, conn=conn)
            _vault_log_audit(conn, "vault_wiped_reinit", admin_ukey, target_ukey, "Personal vault wipe & key reset after self-lock", owner_scope=target_ukey)
            return jsonify(ok=True, resetMode="wiped_reinit", targetUsername=target_ukey, permanentlyLocked=False)

        conn.execute(
            """
            UPDATE vault_user_security
            SET failed_attempts=0, permanently_locked=false, locked_at=NULL,
                updated_at=now(), updated_by=%s
            WHERE username=%s
            """,
            (admin_ukey, target_ukey),
        )
        _vault_log_audit(conn, "vault_lockout_cleared", admin_ukey, target_ukey, "Admin verified account password to clear 5-attempt lockout", owner_scope=target_ukey)
    return jsonify(ok=True, resetMode="lockout_cleared", targetUsername=target_ukey, permanentlyLocked=False)


def _vault_require_unlocked_dek(conn):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "credentials"):
        return None, (jsonify(error="Credentials Vault access required."), 403)
    my_ukey = _vault_current_ukey(who)
    cfg = _vault_ensure_config_row(conn, my_ukey)
    if not bool(cfg[1]):
        return None, (jsonify(error="vault_not_initialized"), 428)
    if bool(cfg[15]):
        _vault_purge_session(sid=str(session.get("sid") or ""), conn=conn)
        return None, (jsonify(error="vault_self_locked", permanentlyLocked=True), 423)
    dek, _ = _vault_get_active_dek(str(session.get("sid") or ""), int(cfg[17] or 10), conn=conn, expected_ukey=my_ukey)
    if dek is None:
        return None, (jsonify(error="vault_locked"), 423)
    return dek, None


def _vault_cred_aad(cred_id):
    return f"northstar-vault-cred-v1:{cred_id}".encode("utf-8")


@app.get("/api/vault/share-targets")
@signed_in
def list_vault_share_targets():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "credentials"):
        return jsonify(error="Credentials Vault access required."), 403
    my_ukey = _vault_current_ukey(who)
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, users, depts = _vault_user_lookup_map(conn)
    clean_users = []
    dept_counts = {}
    for u in users:
        if not isinstance(u, dict) or u.get("enabled") is False:
            continue
        if str(u.get("employment") or "Active").strip().lower() == "inactive":
            continue
        uk = _vault_ukey(u.get("username"))
        if not uk:
            continue
        dp = str(u.get("dept") or u.get("department") or "").strip()
        if dp:
            dept_counts[dp.casefold()] = dept_counts.get(dp.casefold(), 0) + 1
        if uk == my_ukey:
            continue
        clean_users.append({
            "username": uk,
            "name": str(u.get("name") or uk),
            "dept": dp,
            "site": str(u.get("site") or u.get("factory") or ""),
            "role": str(u.get("role") or "User"),
        })
    clean_users.sort(key=lambda x: (x["name"].lower(), x["username"]))
    seen_depts = set()
    clean_depts = []
    for d in depts:
        if isinstance(d, list) and d:
            dn = str(d[0] or "").strip()
            fac = str(d[6] if len(d) > 6 and d[6] else (d[1] if len(d) > 1 else "")).strip()
        elif isinstance(d, dict):
            dn = str(d.get("name") or "").strip()
            fac = str(d.get("factory") or d.get("site") or "").strip()
        else:
            continue
        if not dn:
            continue
        dk = dn.casefold()
        if dk in seen_depts:
            continue
        seen_depts.add(dk)
        clean_depts.append({"key": dk, "name": dn, "factory": fac, "userCount": int(dept_counts.get(dk, 0))})
    for u in users:
        if not isinstance(u, dict) or u.get("enabled") is False:
            continue
        dp = str(u.get("dept") or u.get("department") or "").strip()
        if dp and dp.casefold() not in seen_depts:
            dk = dp.casefold()
            seen_depts.add(dk)
            clean_depts.append({"key": dk, "name": dp, "factory": "", "userCount": int(dept_counts.get(dk, 0))})
    clean_depts.sort(key=lambda x: x["name"].lower())
    return jsonify(users=clean_users, departments=clean_depts)


@app.post("/api/vault/shares")
@signed_in
def update_vault_shares():
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin") or who.get("role") == "Administrator")
    if not is_adm and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    data = request.get_json(silent=True) or {}
    item_type = str(data.get("itemType") or "").strip().lower()
    if item_type not in ("credential", "document"):
        return jsonify(error="itemType must be credential or document."), 400
    raw_ids = data.get("itemIds")
    if not isinstance(raw_ids, list) or not raw_ids:
        return jsonify(error="Select at least one credential or document to share."), 400
    item_ids = [str(x).strip() for x in raw_ids if str(x).strip()][:500]
    mode = str(data.get("mode") or "replace").strip().lower()
    req_users, req_depts = _vault_norm_shares(data.get("sharedUsers"), data.get("sharedDepts"), owner_ukey=my_ukey)

    updated = 0
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        for iid in item_ids:
            if item_type == "credential":
                row = conn.execute(
                    "SELECT owner_username, ciphertext, shared_item_key_enc, shared_users, shared_depts, label FROM vault_credentials WHERE id=%s FOR UPDATE",
                    (iid,),
                ).fetchone()
                if not row:
                    continue
                if _vault_ukey(row[0]) != my_ukey:
                    return jsonify(error=f"Only the creator/owner can change sharing permissions on {row[5] or iid}."), 403
                cur_u = dict(row[3]) if isinstance(row[3], dict) else {}
                cur_d = dict(row[4]) if isinstance(row[4], dict) else {}
                if mode == "merge":
                    new_u, new_d = dict(cur_u), dict(cur_d)
                    new_u.update(req_users)
                    new_d.update(req_depts)
                else:
                    new_u, new_d = dict(req_users), dict(req_depts)
                new_u, new_d = _vault_norm_shares(new_u, new_d, owner_ukey=my_ukey)
                has_share = bool(new_u or new_d)
                cur_key = _vault_resolve_item_key(dek, row[2], _vault_cred_aad(iid))
                plain_ct = _vault_aes_decrypt(cur_key, row[1], _vault_cred_aad(iid))
                if has_share:
                    item_key = cur_key if row[2] else os.urandom(32)
                    new_ct = _vault_aes_encrypt(item_key, plain_ct, _vault_cred_aad(iid))
                    new_skey_enc = _vault_aes_encrypt(_vault_share_wrap_key(), item_key, _vault_cred_aad(iid) + b":skey") if not row[2] else row[2]
                else:
                    new_ct = _vault_aes_encrypt(dek, plain_ct, _vault_cred_aad(iid))
                    new_skey_enc = ""
                conn.execute(
                    """
                    UPDATE vault_credentials
                    SET ciphertext=%s, shared_item_key_enc=%s, shared_users=%s::jsonb, shared_depts=%s::jsonb, updated_at=now()
                    WHERE id=%s
                    """,
                    (new_ct, new_skey_enc, json.dumps(new_u), json.dumps(new_d), iid),
                )
                updated += 1
            else:
                row = conn.execute(
                    "SELECT owner_username, enc_rel_path, meta_ciphertext, shared_item_key_enc, shared_users, shared_depts, title FROM vault_documents WHERE id=%s FOR UPDATE",
                    (iid,),
                ).fetchone()
                if not row:
                    continue
                if _vault_ukey(row[0]) != my_ukey:
                    return jsonify(error=f"Only the creator/owner can share document {row[6] or iid}."), 403
                cur_u = dict(row[4]) if isinstance(row[4], dict) else {}
                cur_d = dict(row[5]) if isinstance(row[5], dict) else {}
                if mode == "merge":
                    new_u, new_d = dict(cur_u), dict(cur_d)
                    new_u.update(req_users)
                    new_d.update(req_depts)
                else:
                    new_u, new_d = dict(req_users), dict(req_depts)
                new_u, new_d = _vault_norm_shares(new_u, new_d, owner_ukey=my_ukey)
                has_share = bool(new_u or new_d)
                enc_path = (VAULT_DOCS_DIR / str(row[1])).resolve()
                if not enc_path.is_relative_to(VAULT_DOCS_DIR.resolve()) or not enc_path.is_file():
                    continue
                cur_key = _vault_resolve_item_key(dek, row[3], _vault_doc_aad(iid))
                raw_file = _vault_aes_decrypt(cur_key, enc_path.read_text(encoding="ascii"), _vault_doc_aad(iid))
                plain_meta = _vault_aes_decrypt(cur_key, row[2], _vault_doc_aad(iid + ":meta")) if row[2] else b"{}"
                if has_share:
                    item_key = cur_key if row[3] else os.urandom(32)
                    enc_path.write_text(_vault_aes_encrypt(item_key, raw_file, _vault_doc_aad(iid)), encoding="ascii")
                    new_meta_ct = _vault_aes_encrypt(item_key, plain_meta, _vault_doc_aad(iid + ":meta"))
                    new_skey_enc = _vault_aes_encrypt(_vault_share_wrap_key(), item_key, _vault_doc_aad(iid) + b":skey") if not row[3] else row[3]
                else:
                    enc_path.write_text(_vault_aes_encrypt(dek, raw_file, _vault_doc_aad(iid)), encoding="ascii")
                    new_meta_ct = _vault_aes_encrypt(dek, plain_meta, _vault_doc_aad(iid + ":meta"))
                    new_skey_enc = ""
                conn.execute(
                    """
                    UPDATE vault_documents
                    SET meta_ciphertext=%s, shared_item_key_enc=%s, shared_users=%s::jsonb, shared_depts=%s::jsonb, updated_at=now()
                    WHERE id=%s
                    """,
                    (new_meta_ct, new_skey_enc, json.dumps(new_u), json.dumps(new_d), iid),
                )
                updated += 1
        _vault_log_audit(
            conn,
            "vault_shares_updated",
            actor,
            f"{updated} {item_type}(s)",
            f"Users={len(req_users)} Depts={len(req_depts)} ({mode})",
            owner_scope=my_ukey,
        )
    return jsonify(ok=True, updated=updated)


@app.get("/api/vault/credentials")
@signed_in
def list_vault_credentials():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    q = str(request.args.get("q") or "").strip().lower()
    factory = str(request.args.get("factory") or "").strip()
    service_type = str(request.args.get("service_type") or "").strip()
    asset_tag = str(request.args.get("asset_tag") or "").strip()
    scope = str(request.args.get("scope") or "").strip().lower()
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        rows = conn.execute("""
            SELECT id, asset_tag, asset_name, device_type, factory, service_type,
                   host_url, port, label, ciphertext, created_by, updated_by,
                   rotated_at, created_at, updated_at, owner_username,
                   shared_item_key_enc, shared_users, shared_depts
            FROM vault_credentials
            ORDER BY updated_at DESC, created_at DESC
        """).fetchall()
    out = []
    for r in rows:
        cid = r[0]
        owner_u = _vault_ukey(r[15] or "")
        s_users = r[17] if isinstance(r[17], dict) else {}
        s_depts = r[18] if isinstance(r[18], dict) else {}
        access = _vault_item_access(owner_u, s_users, s_depts, my_ukey, my_dept_low)
        if not access:
            continue
        if scope == "shared" and access == "owner":
            continue
        if scope == "mine" and access != "owner":
            continue
        secret_obj = {}
        try:
            item_key = _vault_resolve_item_key(dek, r[16], _vault_cred_aad(cid))
            raw_json = _vault_aes_decrypt(item_key, r[9], _vault_cred_aad(cid))
            secret_obj = json.loads(raw_json.decode("utf-8"))
        except Exception:
            secret_obj = {"username": "", "password": "", "notes": "Decryption key mismatch"}
        owner_prof = by_ukey.get(owner_u) or {}
        owner_disp = str(owner_prof.get("name") or r[10] or owner_u)
        rec = {
            "id": cid,
            "assetTag": r[1] or "",
            "assetName": r[2] or "",
            "deviceType": r[3] or "",
            "factory": r[4] or "",
            "serviceType": r[5] or "Web GUI",
            "hostUrl": r[6] or "",
            "port": r[7] or "",
            "label": r[8] or "",
            "username": str(secret_obj.get("username") or ""),
            "password": str(secret_obj.get("password") or ""),
            "enableSecret": str(secret_obj.get("enableSecret") or ""),
            "snmpAuth": str(secret_obj.get("snmpAuth") or ""),
            "snmpPriv": str(secret_obj.get("snmpPriv") or ""),
            "apiToken": str(secret_obj.get("apiToken") or ""),
            "recoveryCodes": str(secret_obj.get("recoveryCodes") or ""),
            "notes": str(secret_obj.get("notes") or ""),
            "createdBy": r[10] or "",
            "updatedBy": r[11] or "",
            "ownerUsername": owner_u,
            "ownerName": owner_disp,
            "accessRole": access,
            "isSharedWithMe": access != "owner",
            "sharedBy": owner_disp if access != "owner" else "",
            "sharedUsers": s_users if access == "owner" else {},
            "sharedDepts": s_depts if access == "owner" else {},
            "shareCount": len(s_users) + len(s_depts),
            "canEdit": access in ("owner", "edit"),
            "canDelete": access == "owner",
            "canShare": access == "owner",
            "rotatedAt": r[12].isoformat() if r[12] else "",
            "createdAt": r[13].isoformat() if r[13] else "",
            "updatedAt": r[14].isoformat() if r[14] else "",
        }
        if factory and factory.lower() != "all" and rec["factory"].lower() != factory.lower():
            continue
        if service_type and service_type.lower() != "all" and rec["serviceType"].lower() != service_type.lower():
            continue
        if asset_tag and rec["assetTag"].lower() != asset_tag.lower():
            continue
        if q:
            hay = " ".join([
                rec["assetTag"], rec["assetName"], rec["deviceType"], rec["factory"],
                rec["serviceType"], rec["hostUrl"], rec["label"], rec["username"], rec["notes"], rec["ownerName"],
            ]).lower()
            if q not in hay:
                continue
        out.append(rec)
    return jsonify(items=out, total=len(out))


@app.post("/api/vault/credentials")
@signed_in
def create_vault_credential():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    data = request.get_json(silent=True) or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    label = str(data.get("label") or data.get("assetName") or data.get("hostUrl") or "").strip()[:160]
    if not label:
        return jsonify(error="Credential title / label or device name is required."), 400
    cid = f"CRD-{secrets.token_hex(4).upper()}"
    secret_payload = {
        "username": str(data.get("username") or "")[:200],
        "password": str(data.get("password") or "")[:500],
        "enableSecret": str(data.get("enableSecret") or "")[:300],
        "snmpAuth": str(data.get("snmpAuth") or "")[:300],
        "snmpPriv": str(data.get("snmpPriv") or "")[:300],
        "apiToken": str(data.get("apiToken") or "")[:2000],
        "recoveryCodes": str(data.get("recoveryCodes") or "")[:2000],
        "notes": str(data.get("notes") or "")[:4000],
    }
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        ct = _vault_aes_encrypt(dek, json.dumps(secret_payload).encode("utf-8"), _vault_cred_aad(cid))
        conn.execute(
            """
            INSERT INTO vault_credentials(
                id, asset_tag, asset_name, device_type, factory, service_type,
                host_url, port, label, ciphertext, created_by, updated_by, owner_username, rotated_at
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
            """,
            (
                cid,
                str(data.get("assetTag") or "")[:80],
                str(data.get("assetName") or "")[:160],
                str(data.get("deviceType") or "")[:80],
                str(data.get("factory") or "")[:120],
                str(data.get("serviceType") or "Web GUI")[:60],
                str(data.get("hostUrl") or "")[:240],
                str(data.get("port") or "")[:16],
                label,
                ct,
                actor,
                actor,
                my_ukey,
            ),
        )
        _vault_log_audit(conn, "credential_created", actor, label, cid, owner_scope=my_ukey)
    return jsonify(ok=True, id=cid), 201


@app.put("/api/vault/credentials/<path:cred_id>")
@signed_in
def update_vault_credential(cred_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    data = request.get_json(silent=True) or {}
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    label = str(data.get("label") or data.get("assetName") or data.get("hostUrl") or "").strip()[:160]
    if not label:
        return jsonify(error="Credential title / label is required."), 400
    secret_payload = {
        "username": str(data.get("username") or "")[:200],
        "password": str(data.get("password") or "")[:500],
        "enableSecret": str(data.get("enableSecret") or "")[:300],
        "snmpAuth": str(data.get("snmpAuth") or "")[:300],
        "snmpPriv": str(data.get("snmpPriv") or "")[:300],
        "apiToken": str(data.get("apiToken") or "")[:2000],
        "recoveryCodes": str(data.get("recoveryCodes") or "")[:2000],
        "notes": str(data.get("notes") or "")[:4000],
    }
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        cur_row = conn.execute(
            "SELECT owner_username, shared_item_key_enc, shared_users, shared_depts FROM vault_credentials WHERE id=%s FOR UPDATE",
            (cred_id,),
        ).fetchone()
        if not cur_row:
            abort(404)
        access = _vault_item_access(cur_row[0], cur_row[2], cur_row[3], my_ukey, my_dept_low)
        if access not in ("owner", "edit"):
            return jsonify(error="You only have Read permission on this shared credential."), 403
        item_key = _vault_resolve_item_key(dek, cur_row[1], _vault_cred_aad(cred_id))
        ct = _vault_aes_encrypt(item_key, json.dumps(secret_payload).encode("utf-8"), _vault_cred_aad(cred_id))
        conn.execute(
            """
            UPDATE vault_credentials
            SET asset_tag=%s, asset_name=%s, device_type=%s, factory=%s, service_type=%s,
                host_url=%s, port=%s, label=%s, ciphertext=%s, updated_by=%s,
                rotated_at=now(), updated_at=now()
            WHERE id=%s
            """,
            (
                str(data.get("assetTag") or "")[:80],
                str(data.get("assetName") or "")[:160],
                str(data.get("deviceType") or "")[:80],
                str(data.get("factory") or "")[:120],
                str(data.get("serviceType") or "Web GUI")[:60],
                str(data.get("hostUrl") or "")[:240],
                str(data.get("port") or "")[:16],
                label,
                ct,
                actor,
                cred_id,
            ),
        )
        _vault_log_audit(conn, "credential_updated", actor, label, cred_id, owner_scope=cur_row[0] or my_ukey)
    return jsonify(ok=True, id=cred_id)


@app.delete("/api/vault/credentials/<path:cred_id>")
@signed_in
def delete_vault_credential(cred_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        cur = conn.execute(
            "SELECT owner_username, label FROM vault_credentials WHERE id=%s",
            (cred_id,),
        ).fetchone()
        if not cur:
            abort(404)
        if _vault_ukey(cur[0]) != my_ukey:
            return jsonify(error="Only the creator/owner can delete this credential."), 403
        conn.execute("DELETE FROM vault_credentials WHERE id=%s", (cred_id,))
        _vault_log_audit(conn, "credential_deleted", actor, cur[1] or cred_id, cred_id, owner_scope=my_ukey)
    return jsonify(ok=True)


@app.post("/api/vault/credentials/bulk")
@signed_in
def bulk_create_vault_credentials():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    if not session.get("is_admin") and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    data = request.get_json(silent=True) or {}
    items = data.get("items")
    if not isinstance(items, list) or not items:
        return jsonify(error="Provide a non-empty list of credentials."), 400
    if len(items) > 2000:
        return jsonify(error="Maximum 2,000 credentials per batch import."), 400
    inserted = 0
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        for entry in items:
            if not isinstance(entry, dict):
                continue
            label = str(entry.get("label") or entry.get("assetName") or entry.get("hostUrl") or "").strip()[:160]
            if not label:
                continue
            cid = f"CRD-{secrets.token_hex(4).upper()}"
            secret_payload = {
                "username": str(entry.get("username") or "")[:200],
                "password": str(entry.get("password") or "")[:500],
                "enableSecret": str(entry.get("enableSecret") or "")[:300],
                "snmpAuth": str(entry.get("snmpAuth") or "")[:300],
                "snmpPriv": str(entry.get("snmpPriv") or "")[:300],
                "apiToken": str(entry.get("apiToken") or "")[:2000],
                "recoveryCodes": str(entry.get("recoveryCodes") or "")[:2000],
                "notes": str(entry.get("notes") or "")[:4000],
            }
            ct = _vault_aes_encrypt(dek, json.dumps(secret_payload).encode("utf-8"), _vault_cred_aad(cid))
            conn.execute(
                """
                INSERT INTO vault_credentials(
                    id, asset_tag, asset_name, device_type, factory, service_type,
                    host_url, port, label, ciphertext, created_by, updated_by, owner_username, rotated_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                """,
                (
                    cid,
                    str(entry.get("assetTag") or "")[:80],
                    str(entry.get("assetName") or "")[:160],
                    str(entry.get("deviceType") or "")[:80],
                    str(entry.get("factory") or "")[:120],
                    str(entry.get("serviceType") or "Web GUI")[:60],
                    str(entry.get("hostUrl") or "")[:240],
                    str(entry.get("port") or "")[:16],
                    label,
                    ct,
                    actor,
                    actor,
                    my_ukey,
                ),
            )
            inserted += 1
        _vault_log_audit(conn, "credential_bulk_import", actor, f"{inserted} device credentials", "Encrypted with AES-256-GCM", owner_scope=my_ukey)
    return jsonify(ok=True, imported=inserted), 201


@app.get("/api/vault/audit")
@signed_in
def list_vault_audit_logs():
    who = session.get("profile") or {}
    is_adm = bool(session.get("is_admin") or who.get("role") == "Administrator")
    my_ukey = _vault_current_ukey(who)
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        if is_adm:
            rows = conn.execute(
                "SELECT id, event_type, actor, target, detail, ip_address, created_at FROM vault_audit_logs ORDER BY id DESC LIMIT 150"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, event_type, actor, target, detail, ip_address, created_at FROM vault_audit_logs WHERE lower(owner_scope)=lower(%s) OR lower(actor)=lower(%s) ORDER BY id DESC LIMIT 150",
                (my_ukey, my_ukey),
            ).fetchall()
    return jsonify(items=[{
        "id": r[0], "eventType": r[1], "actor": r[2], "target": r[3],
        "detail": r[4], "ipAddress": r[5], "createdAt": r[6].isoformat() if r[6] else "",
    } for r in rows])


@app.post("/api/vault/capture-alert")
@signed_in
def log_vault_capture_alert():
    who = session.get("profile") or {}
    if not (session.get("is_admin") or module_access(who, "credentials", write=False)):
        return jsonify(error="Credentials Vault access required."), 403
    my_ukey = _vault_current_ukey(who)
    data = request.get_json(silent=True) or {}
    trigger = str(data.get("trigger") or "shortcut_or_blur")[:80]
    detail = str(data.get("detail") or "Screen capture attempt blocked by Vault Privacy Shield")[:300]
    actor = str(who.get("username") or session.get("user") or "unknown")[:120]
    with db() as conn:
        _vault_log_audit(conn, "screenshot_attempt_blocked", actor, trigger, detail, owner_scope=my_ukey)
    return jsonify(ok=True)


def _vault_doc_aad(doc_id):
    return f"northstar-vault-doc-v1:{doc_id}".encode("utf-8")


@app.get("/api/vault/folders")
@signed_in
def list_vault_folders():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        rows = conn.execute(
            "SELECT id, parent_id, name, color, icon, created_by, created_at, updated_at FROM vault_doc_folders WHERE lower(owner_username)=lower(%s) ORDER BY name ASC",
            (my_ukey,),
        ).fetchall()
        counts = dict(conn.execute("SELECT folder_id, count(*) FROM vault_documents WHERE lower(owner_username)=lower(%s) GROUP BY folder_id", (my_ukey,)).fetchall())
    return jsonify(items=[{
        "id": r[0], "parentId": r[1] or "", "name": r[2], "color": r[3] or "#157a54",
        "icon": r[4] or "📁", "createdBy": r[5] or "",
        "docCount": int(counts.get(r[0], 0)),
        "createdAt": r[6].isoformat() if r[6] else "",
        "updatedAt": r[7].isoformat() if r[7] else "",
    } for r in rows])


@app.post("/api/vault/folders")
@signed_in
def create_vault_folder():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    if not session.get("is_admin") and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()[:100]
    if not name:
        return jsonify(error="Folder name is required."), 400
    fid = f"VFLD-{secrets.token_hex(4).upper()}"
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        conn.execute(
            "INSERT INTO vault_doc_folders(id, parent_id, name, color, icon, created_by, owner_username) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (fid, str(data.get("parentId") or "")[:40], name, str(data.get("color") or "#157a54")[:24], str(data.get("icon") or "📁")[:16], actor, my_ukey),
        )
        _vault_log_audit(conn, "folder_created", actor, name, fid, owner_scope=my_ukey)
    return jsonify(ok=True, id=fid, name=name), 201


@app.put("/api/vault/folders/<path:folder_id>")
@signed_in
def update_vault_folder(folder_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    if not session.get("is_admin") and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()[:100]
    if not name:
        return jsonify(error="Folder name is required."), 400
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        cur = conn.execute(
            "UPDATE vault_doc_folders SET name=%s, color=%s, icon=%s, updated_at=now() WHERE id=%s AND lower(owner_username)=lower(%s)",
            (name, str(data.get("color") or "#157a54")[:24], str(data.get("icon") or "📁")[:16], folder_id, my_ukey),
        )
        if cur.rowcount == 0:
            abort(404)
        _vault_log_audit(conn, "folder_renamed", actor, name, folder_id, owner_scope=my_ukey)
    return jsonify(ok=True, id=folder_id)


@app.delete("/api/vault/folders/<path:folder_id>")
@signed_in
def delete_vault_folder(folder_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    if not session.get("is_admin") and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        conn.execute("UPDATE vault_documents SET folder_id='', updated_at=now() WHERE folder_id=%s AND lower(owner_username)=lower(%s)", (folder_id, my_ukey))
        cur = conn.execute("DELETE FROM vault_doc_folders WHERE id=%s AND lower(owner_username)=lower(%s) RETURNING name", (folder_id, my_ukey))
        row = cur.fetchone()
        if not row:
            abort(404)
        _vault_log_audit(conn, "folder_deleted", actor, row[0] or folder_id, "Documents moved to Root", owner_scope=my_ukey)
    return jsonify(ok=True)


@app.get("/api/vault/documents")
@signed_in
def list_vault_documents():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    folder_id = str(request.args.get("folder_id") or "").strip()
    q = str(request.args.get("q") or "").strip().lower()
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        rows = conn.execute(
            """
            SELECT id, folder_id, title, orig_filename, file_ext, mime_type,
                   file_size, sha256, enc_rel_path, meta_ciphertext, uploaded_by,
                   created_at, updated_at, owner_username, shared_item_key_enc,
                   shared_users, shared_depts
            FROM vault_documents
            ORDER BY updated_at DESC, created_at DESC
            """
        ).fetchall()
    out = []
    for r in rows:
        did = r[0]
        owner_u = _vault_ukey(r[13] or "")
        s_users = r[15] if isinstance(r[15], dict) else {}
        s_depts = r[16] if isinstance(r[16], dict) else {}
        access = _vault_item_access(owner_u, s_users, s_depts, my_ukey, my_dept_low)
        if not access:
            continue
        is_shared_me = access != "owner"
        if folder_id and folder_id != "ALL":
            if folder_id == "SHARED":
                if not is_shared_me:
                    continue
            elif folder_id == "ROOT":
                if is_shared_me or r[1]:
                    continue
            else:
                if is_shared_me or r[1] != folder_id:
                    continue
        notes = ""
        if r[9]:
            try:
                item_key = _vault_resolve_item_key(dek, r[14], _vault_doc_aad(did))
                m_obj = json.loads(_vault_aes_decrypt(item_key, r[9], _vault_doc_aad(did + ":meta")).decode("utf-8"))
                notes = str(m_obj.get("notes") or "")
            except Exception:
                notes = ""
        owner_prof = by_ukey.get(owner_u) or {}
        owner_disp = str(owner_prof.get("name") or r[10] or owner_u)
        item = {
            "id": did, "folderId": "" if is_shared_me else (r[1] or ""), "title": r[2], "origFilename": r[3],
            "fileExt": r[4] or "", "mimeType": r[5] or "", "fileSize": int(r[6] or 0),
            "sha256": r[7] or "", "notes": notes, "uploadedBy": r[10] or "",
            "ownerUsername": owner_u, "ownerName": owner_disp,
            "accessRole": access, "isSharedWithMe": is_shared_me,
            "sharedBy": owner_disp if is_shared_me else "",
            "sharedUsers": s_users if access == "owner" else {},
            "sharedDepts": s_depts if access == "owner" else {},
            "shareCount": len(s_users) + len(s_depts),
            "canEdit": access in ("owner", "edit"),
            "canDelete": access == "owner",
            "canShare": access == "owner",
            "createdAt": r[11].isoformat() if r[11] else "",
            "updatedAt": r[12].isoformat() if r[12] else "",
        }
        if q:
            hay = " ".join([item["title"], item["origFilename"], item["fileExt"], item["notes"], item["ownerName"]]).lower()
            if q not in hay:
                continue
        out.append(item)
    return jsonify(items=out, total=len(out))


@app.post("/api/vault/documents")
@signed_in
def upload_vault_document():
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    if not session.get("is_admin") and not module_access(who, "credentials", write=True):
        return jsonify(error="Write access on Credentials Vault is required."), 403
    f = request.files.get("file")
    if not f or not getattr(f, "filename", ""):
        return jsonify(error="Choose a secret document file to upload."), 400
    orig_name = Path(f.filename).name[:200]
    raw_bytes = f.read()
    if not raw_bytes:
        return jsonify(error="Uploaded file is empty."), 400
    ext = Path(orig_name).suffix.lower().lstrip(".")
    mime = f.mimetype or mimetypes.guess_type(orig_name)[0] or "application/octet-stream"
    title = str(request.form.get("title") or "").strip()[:160] or Path(orig_name).stem[:160]
    folder_id = str(request.form.get("folderId") or "").strip()[:40]
    notes = str(request.form.get("notes") or "")[:3000]
    doc_id = f"VDOC-{secrets.token_hex(4).upper()}"
    sha_hex = hashlib.sha256(raw_bytes).hexdigest()

    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        ct_file = _vault_aes_encrypt(dek, raw_bytes, _vault_doc_aad(doc_id))
        enc_name = f"{doc_id}.enc"
        (VAULT_DOCS_DIR / enc_name).write_text(ct_file, encoding="ascii")
        meta_ct = _vault_aes_encrypt(dek, json.dumps({"notes": notes}).encode("utf-8"), _vault_doc_aad(doc_id + ":meta"))
        conn.execute(
            """
            INSERT INTO vault_documents(
                id, folder_id, title, orig_filename, file_ext, mime_type,
                file_size, sha256, enc_rel_path, meta_ciphertext, uploaded_by, owner_username
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (doc_id, folder_id, title, orig_name, ext, mime[:120], len(raw_bytes), sha_hex, enc_name, meta_ct, actor, my_ukey),
        )
        _vault_log_audit(conn, "document_uploaded", actor, title, f"{orig_name} ({len(raw_bytes)} bytes) encrypted AES-256-GCM", owner_scope=my_ukey)
    return jsonify(ok=True, id=doc_id, sha256=sha_hex), 201


@app.put("/api/vault/documents/<path:doc_id>")
@signed_in
def update_vault_document(doc_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    if request.files or request.form:
        title = str(request.form.get("title") or "").strip()[:160]
        notes = str(request.form.get("notes") or "")[:3000]
        folder_id = request.form.get("folderId")
        f = request.files.get("file") if request.files else None
    else:
        data = request.get_json(silent=True) or {}
        title = str(data.get("title") or "").strip()[:160]
        notes = str(data.get("notes") or "")[:3000]
        folder_id = data.get("folderId")
        f = None
    if not title:
        return jsonify(error="Document title is required."), 400
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        row = conn.execute(
            "SELECT owner_username, folder_id, orig_filename, file_ext, mime_type, file_size, sha256, enc_rel_path, shared_item_key_enc, shared_users, shared_depts FROM vault_documents WHERE id=%s FOR UPDATE",
            (doc_id,),
        ).fetchone()
        if not row:
            abort(404)
        access = _vault_item_access(row[0], row[9], row[10], my_ukey, my_dept_low)
        if access not in ("owner", "edit"):
            return jsonify(error="You only have Read permission on this shared document."), 403
        item_key = _vault_resolve_item_key(dek, row[8], _vault_doc_aad(doc_id))
        orig_name, ext, mime, fsize, sha_hex = row[2], row[3], row[4], int(row[5] or 0), row[6]
        if f and getattr(f, "filename", ""):
            raw_bytes = f.read()
            if not raw_bytes:
                return jsonify(error="Replacement file cannot be empty."), 400
            orig_name = Path(f.filename).name[:200]
            ext = Path(orig_name).suffix.lower().lstrip(".")
            mime = (f.mimetype or mimetypes.guess_type(orig_name)[0] or "application/octet-stream")[:120]
            fsize = len(raw_bytes)
            sha_hex = hashlib.sha256(raw_bytes).hexdigest()
            enc_path = (VAULT_DOCS_DIR / str(row[7])).resolve()
            if enc_path.is_relative_to(VAULT_DOCS_DIR.resolve()):
                enc_path.write_text(_vault_aes_encrypt(item_key, raw_bytes, _vault_doc_aad(doc_id)), encoding="ascii")
        new_folder = (str(folder_id or "").strip()[:40] if (access == "owner" and folder_id is not None) else (row[1] or ""))
        new_meta_ct = _vault_aes_encrypt(item_key, json.dumps({"notes": notes}).encode("utf-8"), _vault_doc_aad(doc_id + ":meta"))
        conn.execute(
            """
            UPDATE vault_documents
            SET folder_id=%s, title=%s, orig_filename=%s, file_ext=%s, mime_type=%s,
                file_size=%s, sha256=%s, meta_ciphertext=%s, updated_at=now()
            WHERE id=%s
            """,
            (new_folder, title, orig_name, ext, mime, fsize, sha_hex, new_meta_ct, doc_id),
        )
        _vault_log_audit(conn, "document_updated", actor, title, doc_id, owner_scope=row[0] or my_ukey)
    return jsonify(ok=True, id=doc_id)


@app.delete("/api/vault/documents/<path:doc_id>")
@signed_in
def delete_vault_document(doc_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    with db() as conn:
        _, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        cur = conn.execute("SELECT owner_username, enc_rel_path, title FROM vault_documents WHERE id=%s", (doc_id,)).fetchone()
        if not cur:
            abort(404)
        if _vault_ukey(cur[0]) != my_ukey:
            return jsonify(error="Only the creator/owner can delete this document."), 403
        conn.execute("DELETE FROM vault_documents WHERE id=%s", (doc_id,))
        try:
            target = (VAULT_DOCS_DIR / str(cur[1])).resolve()
            if target.is_relative_to(VAULT_DOCS_DIR.resolve()):
                target.unlink(missing_ok=True)
        except Exception:
            pass
        _vault_log_audit(conn, "document_deleted", actor, cur[2] or doc_id, doc_id, owner_scope=my_ukey)
    return jsonify(ok=True)


def _col_letters_to_idx(ref_str):
    idx = 0
    for ch in ref_str:
        if ch.isalpha():
            idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
        else:
            break
    return max(0, idx - 1)


def _preview_office_xlsx(raw_bytes):
    sheets = []
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        shared = []
        if "xl/sharedStrings.xml" in zf.namelist():
            root_ss = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in root_ss.iter():
                if si.tag.endswith("}si") or si.tag == "si":
                    txt = "".join(t.text or "" for t in si.iter() if t.tag.endswith("}t") or t.tag == "t")
                    shared.append(txt)
        sheet_meta = []
        if "xl/workbook.xml" in zf.namelist():
            wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
            rels = {}
            if "xl/_rels/workbook.xml.rels" in zf.namelist():
                rr = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
                for rel in rr.iter():
                    if rel.tag.endswith("}Relationship") or rel.tag == "Relationship":
                        rid = rel.attrib.get("Id", "")
                        tgt = rel.attrib.get("Target", "").lstrip("/")
                        if not tgt.startswith("xl/"):
                            tgt = "xl/" + tgt
                        rels[rid] = tgt
            for sh in wb_root.iter():
                if sh.tag.endswith("}sheet") or sh.tag == "sheet":
                    nm = sh.attrib.get("name", f"Sheet {len(sheet_meta)+1}")
                    rid = next((v for k, v in sh.attrib.items() if k.endswith("}id") or k == "r:id"), "")
                    path = rels.get(rid) or f"xl/worksheets/sheet{len(sheet_meta)+1}.xml"
                    if path in zf.namelist():
                        sheet_meta.append((nm, path))
        if not sheet_meta:
            for nm in sorted(zf.namelist()):
                if nm.startswith("xl/worksheets/sheet") and nm.endswith(".xml"):
                    sheet_meta.append((Path(nm).stem, nm))
        for s_name, s_path in sheet_meta[:12]:
            s_root = ET.fromstring(zf.read(s_path))
            rows = []
            for row_el in s_root.iter():
                if not (row_el.tag.endswith("}row") or row_el.tag == "row"):
                    continue
                if len(rows) >= 500:
                    break
                cur = []
                for c_el in row_el:
                    if not (c_el.tag.endswith("}c") or c_el.tag == "c"):
                        continue
                    c_idx = _col_letters_to_idx(c_el.attrib.get("r", "")) if c_el.attrib.get("r") else len(cur)
                    while len(cur) <= c_idx:
                        cur.append("")
                    ctype = c_el.attrib.get("t", "")
                    val = ""
                    if ctype == "s":
                        v_el = next((x for x in c_el if x.tag.endswith("}v") or x.tag == "v"), None)
                        if v_el is not None and v_el.text and v_el.text.isdigit():
                            si_i = int(v_el.text)
                            val = shared[si_i] if 0 <= si_i < len(shared) else ""
                    elif ctype == "inlineStr":
                        val = "".join(t.text or "" for t in c_el.iter() if t.tag.endswith("}t") or t.tag == "t")
                    else:
                        v_el = next((x for x in c_el if x.tag.endswith("}v") or x.tag == "v"), None)
                        val = v_el.text if v_el is not None and v_el.text is not None else ""
                    cur[c_idx] = str(val)[:240]
                if any(cur):
                    rows.append(cur[:40])
            sheets.append({"name": s_name, "rows": rows})
    return {"kind": "sheets", "sheets": sheets}


def _preview_office_ods(raw_bytes):
    sheets = []
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        root = ET.fromstring(zf.read("content.xml"))
        for tbl in root.iter():
            if not (tbl.tag.endswith("}table") or tbl.tag == "table"):
                continue
            s_name = next((v for k, v in tbl.attrib.items() if k.endswith("}name") or k == "name"), f"Sheet {len(sheets)+1}")
            rows = []
            for r_el in tbl:
                if not (r_el.tag.endswith("}table-row") or r_el.tag == "table-row"):
                    continue
                if len(rows) >= 500:
                    break
                cur = []
                for c_el in r_el:
                    if not (c_el.tag.endswith("}table-cell") or c_el.tag == "table-cell"):
                        continue
                    rep = next((int(v) for k, v in c_el.attrib.items() if k.endswith("}number-columns-repeated") and str(v).isdigit()), 1)
                    rep = min(rep, 20)
                    txt = " ".join("".join(c_el.itertext()).split())[:240]
                    cur.extend([txt] * rep)
                while cur and not cur[-1]:
                    cur.pop()
                if any(cur):
                    rows.append(cur[:40])
            sheets.append({"name": s_name, "rows": rows})
            if len(sheets) >= 12:
                break
    return {"kind": "sheets", "sheets": sheets}


def _preview_office_docx(raw_bytes):
    blocks = []
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        doc_xml = zf.read("word/document.xml")
        root = ET.fromstring(doc_xml)
        body = next((el for el in root.iter() if el.tag.endswith("}body") or el.tag == "body"), root)
        for child in body:
            if child.tag.endswith("}p") or child.tag == "p":
                pstyle = ""
                is_list = False
                for el in child.iter():
                    if el.tag.endswith("}pStyle"):
                        pstyle = next((v for k, v in el.attrib.items() if k.endswith("}val")), "")
                    elif el.tag.endswith("}numPr"):
                        is_list = True
                runs_html = []
                for r in child:
                    if not (r.tag.endswith("}r") or r.tag == "r"):
                        continue
                    txt = "".join(t.text or "" for t in r.iter() if t.tag.endswith("}t") or t.tag == "t")
                    if not txt:
                        continue
                    esc_t = html.escape(txt)
                    bold = any(e.tag.endswith("}b") for e in r.iter())
                    italic = any(e.tag.endswith("}i") for e in r.iter())
                    if bold:
                        esc_t = f"<b>{esc_t}</b>"
                    if italic:
                        esc_t = f"<i>{esc_t}</i>"
                    runs_html.append(esc_t)
                line = "".join(runs_html).strip()
                if not line:
                    blocks.append("<p style='height:8px;margin:0'></p>")
                elif pstyle.lower().startswith("heading1") or pstyle.lower() == "title":
                    blocks.append(f"<h2 style='margin:14px 0 6px;color:#0f172a'>{line}</h2>")
                elif pstyle.lower().startswith("heading"):
                    blocks.append(f"<h3 style='margin:11px 0 5px;color:#145b40'>{line}</h3>")
                elif is_list:
                    blocks.append(f"<div style='padding-left:16px;margin:3px 0'>• {line}</div>")
                else:
                    blocks.append(f"<p style='margin:5px 0;line-height:1.55'>{line}</p>")
            elif child.tag.endswith("}tbl") or child.tag == "tbl":
                tr_html = []
                for tr in child:
                    if not tr.tag.endswith("}tr"):
                        continue
                    tds = []
                    for tc in tr:
                        if not tc.tag.endswith("}tc"):
                            continue
                        cell_txt = " ".join("".join(tc.itertext()).split())
                        tds.append(f"<td>{html.escape(cell_txt)}</td>")
                    if tds:
                        tr_html.append("<tr>" + "".join(tds) + "</tr>")
                if tr_html:
                    blocks.append("<table class='ns-vault-doc-tbl'>" + "".join(tr_html) + "</table>")
    return {"kind": "doc_html", "html": "".join(blocks) or "<p>Empty document.</p>"}


def _preview_office_odt(raw_bytes):
    blocks = []
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        root = ET.fromstring(zf.read("content.xml"))
        txt_body = next((el for el in root.iter() if el.tag.endswith("}text") or el.tag == "text"), root)
        for child in txt_body:
            tname = child.tag.split("}")[-1]
            if tname == "h":
                blocks.append(f"<h3 style='margin:12px 0 5px;color:#145b40'>{html.escape(''.join(child.itertext()))}</h3>")
            elif tname == "p":
                txt = "".join(child.itertext()).strip()
                blocks.append(f"<p style='margin:5px 0;line-height:1.55'>{html.escape(txt)}</p>" if txt else "<p style='height:8px;margin:0'></p>")
            elif tname == "list":
                for li in child:
                    txt = "".join(li.itertext()).strip()
                    if txt:
                        blocks.append(f"<div style='padding-left:16px;margin:3px 0'>• {html.escape(txt)}</div>")
            elif tname == "table":
                tr_html = []
                for tr in child:
                    if not tr.tag.endswith("}table-row"):
                        continue
                    tds = [f"<td>{html.escape(' '.join(''.join(tc.itertext()).split()))}</td>" for tc in tr if tc.tag.endswith("}table-cell")]
                    if tds:
                        tr_html.append("<tr>" + "".join(tds) + "</tr>")
                if tr_html:
                    blocks.append("<table class='ns-vault-doc-tbl'>" + "".join(tr_html) + "</table>")
    return {"kind": "doc_html", "html": "".join(blocks) or "<p>Empty OpenOffice document.</p>"}


def _preview_office_slides(raw_bytes, ext):
    slides = []
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        if ext == "pptx":
            names = [n for n in zf.namelist() if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)]
            names.sort(key=lambda x: int(re.search(r"(\d+)", Path(x).stem).group(1)))
            for idx, nm in enumerate(names[:50], 1):
                root = ET.fromstring(zf.read(nm))
                lines = []
                for p in root.iter():
                    if p.tag.endswith("}p"):
                        txt = "".join(t.text or "" for t in p.iter() if t.tag.endswith("}t")).strip()
                        if txt:
                            lines.append(txt)
                slides.append({"index": idx, "title": lines[0] if lines else f"Slide {idx}", "bullets": lines[1:] if len(lines) > 1 else []})
        else:
            root = ET.fromstring(zf.read("content.xml"))
            idx = 0
            for pg in root.iter():
                if pg.tag.endswith("}page"):
                    idx += 1
                    lines = [" ".join("".join(p.itertext()).split()) for p in pg.iter() if p.tag.endswith("}p")]
                    lines = [l for l in lines if l]
                    slides.append({"index": idx, "title": lines[0] if lines else f"Slide {idx}", "bullets": lines[1:] if len(lines) > 1 else []})
    return {"kind": "slides", "slides": slides}


def _vault_build_preview(raw_bytes, doc_id, ext, mime):
    ext_l = str(ext or "").lower().lstrip(".")
    if ext_l in ("png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"):
        if ext_l == "svg":
            return {"kind": "text", "text": raw_bytes[:200000].decode("utf-8", errors="replace")}
        m = mime if mime.startswith("image/") else f"image/{'jpeg' if ext_l == 'jpg' else ext_l}"
        return {"kind": "image", "mime": m, "dataUrl": f"data:{m};base64,{base64.b64encode(raw_bytes).decode('ascii')}"}
    if ext_l == "pdf":
        pdftoppm_bin = shutil.which("pdftoppm")
        if pdftoppm_bin:
            try:
                with tempfile.TemporaryDirectory() as td:
                    pdf_p = Path(td) / "in.pdf"
                    pdf_p.write_bytes(raw_bytes)
                    subprocess.run([pdftoppm_bin, "-png", "-r", "140", "-f", "1", "-l", "30", str(pdf_p), str(Path(td) / "page")], check=True, timeout=35)
                    pages = sorted(Path(td).glob("page-*.png"))
                    if pages:
                        return {
                            "kind": "pdf_pages",
                            "pages": [f"data:image/png;base64,{base64.b64encode(p.read_bytes()).decode('ascii')}" for p in pages],
                            "pageCount": len(pages),
                        }
            except Exception:
                pass
        return {"kind": "pdf_stream", "url": f"/api/vault/documents/{quote(doc_id)}/inline"}
    if ext_l in ("xlsx", "xlsm"):
        return _preview_office_xlsx(raw_bytes)
    if ext_l == "ods":
        return _preview_office_ods(raw_bytes)
    if ext_l in ("csv", "tsv"):
        delim = "\t" if ext_l == "tsv" else ","
        txt = raw_bytes[:1024 * 1024].decode("utf-8-sig", errors="replace")
        rows = list(csv.reader(io.StringIO(txt), delimiter=delim))[:600]
        return {"kind": "sheets", "sheets": [{"name": ext_l.upper(), "rows": [r[:40] for r in rows]}]}
    if ext_l == "docx":
        return _preview_office_docx(raw_bytes)
    if ext_l == "odt":
        return _preview_office_odt(raw_bytes)
    if ext_l in ("pptx", "odp"):
        return _preview_office_slides(raw_bytes, ext_l)
    if ext_l in ("txt", "log", "json", "xml", "yaml", "yml", "md", "ini", "cfg", "conf", "rsc", "pem", "crt", "key", "env", "sql", "py", "js", "html", "htm", "css", "sh", "bat", "ps1"):
        return {"kind": "text", "text": raw_bytes[:250000].decode("utf-8", errors="replace")}
    if ext_l in ("doc", "xls", "ppt", "rtf"):
        ascii_runs = re.findall(rb"[ -~\r\n\t]{6,}", raw_bytes[:512000])
        utf16_runs = re.findall(rb"(?:[ -~]\x00){5,}", raw_bytes[:512000])
        lines = [b.decode("ascii", errors="ignore").strip() for b in ascii_runs] + [b.decode("utf-16-le", errors="ignore").strip() for b in utf16_runs]
        if ext_l == "rtf":
            raw_t = raw_bytes[:300000].decode("latin-1", errors="ignore")
            raw_t = re.sub(r"\\[a-zA-Z]+\-?\d* ?|[{}]", "", raw_t)
            return {"kind": "text", "text": raw_t.strip()}
        joined = "\n".join(dict.fromkeys(l for l in lines if len(l) >= 6))
        return {"kind": "text", "text": joined[:120000] or "Legacy Office binary detected. Save as .docx/.xlsx/.odt for rich layout or Download with Download Password."}
    return {"kind": "binary", "message": f"Binary .{ext_l or 'file'} format stored safely with AES-256-GCM encryption. Use Password-Protected Download to retrieve the original file."}


@app.get("/api/vault/documents/<path:doc_id>/preview")
@signed_in
def preview_vault_document(doc_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        row = conn.execute(
            "SELECT id, title, orig_filename, file_ext, mime_type, enc_rel_path, owner_username, shared_item_key_enc, shared_users, shared_depts FROM vault_documents WHERE id=%s",
            (doc_id,),
        ).fetchone()
        if not row:
            abort(404)
        access = _vault_item_access(row[6], row[8], row[9], my_ukey, my_dept_low)
        if not access:
            return jsonify(error="You do not have access to this document."), 403
        enc_path = (VAULT_DOCS_DIR / row[5]).resolve()
        if not enc_path.is_relative_to(VAULT_DOCS_DIR.resolve()) or not enc_path.is_file():
            abort(404)
        item_key = _vault_resolve_item_key(dek, row[7], _vault_doc_aad(doc_id))
        raw_bytes = _vault_aes_decrypt(item_key, enc_path.read_text(encoding="ascii"), _vault_doc_aad(doc_id))
        _vault_log_audit(conn, "document_previewed", actor, row[1] or row[2], doc_id, owner_scope=row[6] or my_ukey)
    try:
        preview_obj = _vault_build_preview(raw_bytes, doc_id, row[3], row[4])
    except Exception as exc:
        preview_obj = {"kind": "binary", "message": f"Could not render inline preview ({exc}). Use Password-Protected Download."}
    watermark = f"{actor} · {who.get('username','')} · {request.headers.get('X-Forwarded-For') or request.remote_addr or ''} · {datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%d %b %Y %H:%M')}"
    return jsonify(id=row[0], title=row[1], origFilename=row[2], fileExt=row[3], watermark=watermark, preview=preview_obj)


@app.get("/api/vault/documents/<path:doc_id>/inline")
@signed_in
def inline_vault_document_pdf(doc_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        row = conn.execute(
            "SELECT orig_filename, mime_type, enc_rel_path, owner_username, shared_item_key_enc, shared_users, shared_depts FROM vault_documents WHERE id=%s",
            (doc_id,),
        ).fetchone()
        if not row:
            abort(404)
        if not _vault_item_access(row[3], row[5], row[6], my_ukey, my_dept_low):
            return jsonify(error="You do not have access to this document."), 403
        enc_path = (VAULT_DOCS_DIR / row[2]).resolve()
        if not enc_path.is_relative_to(VAULT_DOCS_DIR.resolve()) or not enc_path.is_file():
            abort(404)
        item_key = _vault_resolve_item_key(dek, row[4], _vault_doc_aad(doc_id))
        raw_bytes = _vault_aes_decrypt(item_key, enc_path.read_text(encoding="ascii"), _vault_doc_aad(doc_id))
    resp = Response(raw_bytes, mimetype=row[1] or "application/pdf")
    resp.headers["Content-Disposition"] = f'inline; filename="{secure_filename(row[0]) or "document.pdf"}"'
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.post("/api/vault/documents/<path:doc_id>/download")
@signed_in
def download_vault_document_protected(doc_id):
    who = session.get("profile") or {}
    my_ukey = _vault_current_ukey(who)
    actor = str(who.get("name") or who.get("username") or my_ukey or "User")[:120]
    data = request.get_json(silent=True) or {}
    dl_pwd = str(data.get("downloadPassword") or "")
    with db() as conn:
        dek, err = _vault_require_unlocked_dek(conn)
        if err:
            return err
        cfg = _vault_ensure_config_row(conn, my_ukey)
        dl_hash = str(cfg[20] or "")
        if not dl_hash:
            return jsonify(error="Set your Separate Document Download Password in My Vault Security first before downloading."), 428
        if not dl_pwd or not check_password_hash(dl_hash, dl_pwd):
            _vault_log_audit(conn, "doc_download_denied", actor, doc_id, "Incorrect Separate Download Password", owner_scope=my_ukey)
            return jsonify(error="Incorrect Document Download Password."), 401
        by_ukey, _, _ = _vault_user_lookup_map(conn)
        my_dept_low = _vault_user_dept_lower(by_ukey, my_ukey, who)
        row = conn.execute(
            "SELECT title, orig_filename, mime_type, enc_rel_path, owner_username, shared_item_key_enc, shared_users, shared_depts FROM vault_documents WHERE id=%s",
            (doc_id,),
        ).fetchone()
        if not row:
            abort(404)
        if not _vault_item_access(row[4], row[6], row[7], my_ukey, my_dept_low):
            return jsonify(error="You do not have access to this document."), 403
        enc_path = (VAULT_DOCS_DIR / row[3]).resolve()
        if not enc_path.is_relative_to(VAULT_DOCS_DIR.resolve()) or not enc_path.is_file():
            abort(404)
        item_key = _vault_resolve_item_key(dek, row[5], _vault_doc_aad(doc_id))
        raw_bytes = _vault_aes_decrypt(item_key, enc_path.read_text(encoding="ascii"), _vault_doc_aad(doc_id))
        _vault_log_audit(conn, "document_downloaded", actor, row[0] or row[1], row[1], owner_scope=row[4] or my_ukey)
    resp = Response(raw_bytes, mimetype=row[2] or "application/octet-stream")
    safe_dl = row[1].replace('"', "").replace("\r", "").replace("\n", "")
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_dl}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


def _save_firmware_upload(file_storage, item_id, slot):
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None
    orig_name = Path(file_storage.filename).name[:180]
    safe = secure_filename(orig_name) or f"{slot}.bin"
    raw = file_storage.read()
    if not raw:
        return None
    sha256_hex = hashlib.sha256(raw).hexdigest()
    folder = FIRMWARE_UPLOAD_DIR / re.sub(r"[^A-Za-z0-9_-]", "", item_id)
    folder.mkdir(parents=True, exist_ok=True)
    disk_name = f"{slot}_{secrets.token_hex(4)}_{safe}"
    target = folder / disk_name
    target.write_bytes(raw)
    rel = f"{folder.name}/{disk_name}"
    ext = Path(orig_name).suffix.lower().lstrip(".").upper() or "FILE"
    return rel, orig_name, len(raw), sha256_hex, ext


def _unlink_firmware_rel(rel_path):
    if not rel_path:
        return
    try:
        target = (FIRMWARE_UPLOAD_DIR / rel_path).resolve()
        if target.is_relative_to(FIRMWARE_UPLOAD_DIR.resolve()):
            target.unlink(missing_ok=True)
    except Exception:
        pass


def _firmware_row_json(r):
    cfg_rel = r[11] or ""
    fw_rel = r[16] or ""
    return {
        "id": r[0],
        "assetTag": r[1] or "",
        "assetName": r[2] or "",
        "deviceType": r[3] or "",
        "manufacturer": r[4] or "",
        "model": r[5] or "",
        "factory": r[6] or "",
        "recordKind": r[7] or "Config Backup",
        "firmwareVersion": r[8] or "",
        "previousVersion": r[9] or "",
        "releaseDate": r[10] or "",
        "configFileRel": cfg_rel,
        "configFileName": r[12] or "",
        "configFileSize": int(r[13] or 0),
        "configSha256": r[14] or "",
        "configFormat": r[15] or "",
        "configDownloadUrl": f"/api/firmware-backups/file/{quote(cfg_rel)}" if cfg_rel else "",
        "firmwareFileRel": fw_rel,
        "firmwareFileName": r[17] or "",
        "firmwareFileSize": int(r[18] or 0),
        "firmwareSha256": r[19] or "",
        "firmwareDownloadUrl": f"/api/firmware-backups/file/{quote(fw_rel)}" if fw_rel else "",
        "firmwareUrl": r[20] or "",
        "backupTakenAt": r[21] or "",
        "nextBackupDue": r[22] or "",
        "eolStatus": r[23] or "Supported",
        "restoreSteps": r[24] or "",
        "notes": r[25] or "",
        "uploadedBy": r[26] or "",
        "createdAt": r[27].isoformat() if r[27] else "",
        "updatedAt": r[28].isoformat() if r[28] else "",
    }


@app.get("/api/firmware-backups")
@signed_in
def list_firmware_backups():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "firmware"):
        return jsonify(error="Backups & Firmware access required."), 403
    q = str(request.args.get("q") or "").strip().lower()
    factory = str(request.args.get("factory") or "").strip()
    kind = str(request.args.get("record_kind") or "").strip()
    dtype = str(request.args.get("device_type") or "").strip()
    asset_tag = str(request.args.get("asset_tag") or "").strip()
    with db() as conn:
        rows = conn.execute("""
            SELECT id, asset_tag, asset_name, device_type, manufacturer, model, factory,
                   record_kind, firmware_version, previous_version, release_date,
                   config_file_rel, config_file_name, config_file_size, config_sha256, config_format,
                   firmware_file_rel, firmware_file_name, firmware_file_size, firmware_sha256,
                   firmware_url, backup_taken_at, next_backup_due, eol_status,
                   restore_steps, notes, uploaded_by, created_at, updated_at
            FROM device_firmware_backups
            ORDER BY updated_at DESC, created_at DESC
        """).fetchall()
    items = []
    for r in rows:
        item = _firmware_row_json(r)
        if factory and factory.lower() != "all" and item["factory"].lower() != factory.lower():
            continue
        if kind and kind.lower() != "all" and item["recordKind"].lower() != kind.lower():
            continue
        if dtype and dtype.lower() != "all" and item["deviceType"].lower() != dtype.lower():
            continue
        if asset_tag and item["assetTag"].lower() != asset_tag.lower():
            continue
        if q:
            hay = " ".join([
                item["id"], item["assetTag"], item["assetName"], item["deviceType"],
                item["manufacturer"], item["model"], item["factory"], item["firmwareVersion"],
                item["configFileName"], item["firmwareFileName"], item["notes"],
            ]).lower()
            if q not in hay:
                continue
        items.append(item)
    return jsonify(items=items, total=len(items))


@app.post("/api/firmware-backups")
@signed_in
def create_firmware_backup():
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "firmware", write=True):
        return jsonify(error="Write access on Backups & Firmware is required."), 403
    data = request.form if request.form else (request.get_json(silent=True) or {})
    actor = str(who.get("name") or who.get("username") or "User")[:120]
    asset_name = str(data.get("assetName") or "").strip()[:160]
    fw_ver = str(data.get("firmwareVersion") or "").strip()[:80]
    if not asset_name and not fw_ver and not request.files:
        return jsonify(error="Select a device or upload a backup / firmware file."), 400
    item_id = f"FWB-{secrets.token_hex(4).upper()}"
    cfg_saved = _save_firmware_upload(request.files.get("config_file"), item_id, "cfg")
    fw_saved = _save_firmware_upload(request.files.get("firmware_file"), item_id, "fw")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO device_firmware_backups(
                id, asset_tag, asset_name, device_type, manufacturer, model, factory,
                record_kind, firmware_version, previous_version, release_date,
                config_file_rel, config_file_name, config_file_size, config_sha256, config_format,
                firmware_file_rel, firmware_file_name, firmware_file_size, firmware_sha256,
                firmware_url, backup_taken_at, next_backup_due, eol_status,
                restore_steps, notes, uploaded_by
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                item_id,
                str(data.get("assetTag") or "")[:80],
                asset_name,
                str(data.get("deviceType") or "")[:80],
                str(data.get("manufacturer") or "")[:120],
                str(data.get("model") or "")[:120],
                str(data.get("factory") or "")[:120],
                str(data.get("recordKind") or "Config Backup")[:60],
                fw_ver,
                str(data.get("previousVersion") or "")[:80],
                str(data.get("releaseDate") or "")[:40],
                cfg_saved[0] if cfg_saved else "",
                cfg_saved[1] if cfg_saved else "",
                cfg_saved[2] if cfg_saved else 0,
                cfg_saved[3] if cfg_saved else "",
                (cfg_saved[4] if cfg_saved else str(data.get("configFormat") or ""))[:40],
                fw_saved[0] if fw_saved else "",
                fw_saved[1] if fw_saved else "",
                fw_saved[2] if fw_saved else 0,
                fw_saved[3] if fw_saved else "",
                str(data.get("firmwareUrl") or "")[:400],
                str(data.get("backupTakenAt") or "")[:40],
                str(data.get("nextBackupDue") or "")[:40],
                str(data.get("eolStatus") or "Supported")[:40],
                str(data.get("restoreSteps") or "")[:4000],
                str(data.get("notes") or "")[:4000],
                actor,
            ),
        )
    return jsonify(ok=True, id=item_id), 201


@app.put("/api/firmware-backups/<path:item_id>")
@signed_in
def update_firmware_backup(item_id):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "firmware", write=True):
        return jsonify(error="Write access on Backups & Firmware is required."), 403
    data = request.form if request.form else (request.get_json(silent=True) or {})
    actor = str(who.get("name") or who.get("username") or "User")[:120]
    cfg_new = _save_firmware_upload(request.files.get("config_file"), item_id, "cfg")
    fw_new = _save_firmware_upload(request.files.get("firmware_file"), item_id, "fw")
    clear_cfg = str(data.get("clearConfigFile") or "").lower() in ("1", "true", "yes")
    clear_fw = str(data.get("clearFirmwareFile") or "").lower() in ("1", "true", "yes")

    with db() as conn:
        prior = conn.execute(
            "SELECT config_file_rel, config_file_name, config_file_size, config_sha256, config_format, firmware_file_rel, firmware_file_name, firmware_file_size, firmware_sha256 FROM device_firmware_backups WHERE id=%s",
            (item_id,),
        ).fetchone()
        if not prior:
            abort(404)
        old_cfg_rel, old_fw_rel = prior[0], prior[5]
        if cfg_new:
            cfg_rel, cfg_name, cfg_size, cfg_sha, cfg_fmt = cfg_new
            _unlink_firmware_rel(old_cfg_rel)
        elif clear_cfg:
            cfg_rel, cfg_name, cfg_size, cfg_sha, cfg_fmt = "", "", 0, "", ""
            _unlink_firmware_rel(old_cfg_rel)
        else:
            cfg_rel, cfg_name, cfg_size, cfg_sha, cfg_fmt = prior[0], prior[1], prior[2], prior[3], prior[4]

        if fw_new:
            fw_rel, fw_name, fw_size, fw_sha, _ = fw_new
            _unlink_firmware_rel(old_fw_rel)
        elif clear_fw:
            fw_rel, fw_name, fw_size, fw_sha = "", "", 0, ""
            _unlink_firmware_rel(old_fw_rel)
        else:
            fw_rel, fw_name, fw_size, fw_sha = prior[5], prior[6], prior[7], prior[8]

        conn.execute(
            """
            UPDATE device_firmware_backups
            SET asset_tag=%s, asset_name=%s, device_type=%s, manufacturer=%s, model=%s, factory=%s,
                record_kind=%s, firmware_version=%s, previous_version=%s, release_date=%s,
                config_file_rel=%s, config_file_name=%s, config_file_size=%s, config_sha256=%s, config_format=%s,
                firmware_file_rel=%s, firmware_file_name=%s, firmware_file_size=%s, firmware_sha256=%s,
                firmware_url=%s, backup_taken_at=%s, next_backup_due=%s, eol_status=%s,
                restore_steps=%s, notes=%s, uploaded_by=%s, updated_at=now()
            WHERE id=%s
            """,
            (
                str(data.get("assetTag") or "")[:80],
                str(data.get("assetName") or "")[:160],
                str(data.get("deviceType") or "")[:80],
                str(data.get("manufacturer") or "")[:120],
                str(data.get("model") or "")[:120],
                str(data.get("factory") or "")[:120],
                str(data.get("recordKind") or "Config Backup")[:60],
                str(data.get("firmwareVersion") or "")[:80],
                str(data.get("previousVersion") or "")[:80],
                str(data.get("releaseDate") or "")[:40],
                cfg_rel, cfg_name, cfg_size, cfg_sha, cfg_fmt[:40],
                fw_rel, fw_name, fw_size, fw_sha,
                str(data.get("firmwareUrl") or "")[:400],
                str(data.get("backupTakenAt") or "")[:40],
                str(data.get("nextBackupDue") or "")[:40],
                str(data.get("eolStatus") or "Supported")[:40],
                str(data.get("restoreSteps") or "")[:4000],
                str(data.get("notes") or "")[:4000],
                actor,
                item_id,
            ),
        )
    return jsonify(ok=True, id=item_id)


@app.delete("/api/firmware-backups/<path:item_id>")
@signed_in
def delete_firmware_backup(item_id):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "firmware", write=True):
        return jsonify(error="Write access on Backups & Firmware is required."), 403
    with db() as conn:
        row = conn.execute(
            "DELETE FROM device_firmware_backups WHERE id=%s RETURNING config_file_rel, firmware_file_rel",
            (item_id,),
        ).fetchone()
        if not row:
            abort(404)
        _unlink_firmware_rel(row[0])
        _unlink_firmware_rel(row[1])
    return jsonify(ok=True)


@app.get("/api/firmware-backups/file/<path:rel_path>")
@signed_in
def download_firmware_backup_file(rel_path):
    who = session.get("profile") or {}
    if not session.get("is_admin") and not module_access(who, "firmware"):
        abort(403)
    base = FIRMWARE_UPLOAD_DIR.resolve()
    target = (base / rel_path).resolve()
    if not target.is_relative_to(base) or not target.is_file():
        abort(404)
    return send_from_directory(str(target.parent), target.name, as_attachment=True)


@app.errorhandler(413)
def too_large(_):
    if request.path == "/api/backups/restore":
        limit = "1 GB"
    elif request.path.startswith("/api/firmware-backups"):
        limit = "256 MB"
    else:
        limit = "64 MB"
    return jsonify(error=f"Request too large (maximum {limit})"), 413


# =============================================================================
# HELPDESK 1-TO-1 MESSAGES, SECTION CHANNELS & SMART AUTO-BOT
# =============================================================================

def _hd_thread_json(row):
    return {
        "id": row[0],
        "requesterUsername": row[1],
        "requesterName": row[2],
        "requesterDept": row[3],
        "requesterFactory": row[4],
        "requesterGender": row[5],
        "sectionId": row[6],
        "sectionLabel": row[7],
        "ticketId": row[8],
        "assignedExpertUsername": row[9],
        "assignedExpertName": row[10],
        "mode": row[11] or "bot",
        "lastMessagePreview": row[12],
        "lastMessageAt": row[13].isoformat(timespec="seconds") if row[13] else "",
        "unreadForRequester": int(row[14] or 0),
        "unreadForStaff": int(row[15] or 0),
        "updatedAt": row[16].isoformat(timespec="seconds") if len(row) > 16 and row[16] else "",
    }


def _hd_msg_json(row):
    return {
        "id": row[0],
        "threadId": row[1],
        "senderUsername": row[2],
        "senderName": row[3],
        "senderRole": row[4] or "user",
        "taggedTicketId": row[5] or "",
        "body": row[6] or "",
        "attachmentUrl": row[7] or "",
        "attachmentName": row[8] or "",
        "meta": row[9] if isinstance(row[9], dict) else {},
        "createdAt": row[10].isoformat(timespec="seconds") if row[10] else "",
        "createdDisplay": row[10].astimezone(_local_now_dt().tzinfo).strftime("%d %b %Y, %I:%M %p") if row[10] else "",
    }


def _hd_can_access_thread(profile, is_admin, thr):
    if is_admin:
        return True, True
    uname = str(profile.get("username") or "").strip().casefold()
    is_req = bool(uname and str(thr["requesterUsername"] or "").strip().casefold() == uname)
    is_staff = _helpdesk_caller_can_staff_section(profile, is_admin, thr["sectionId"])
    return (is_req or is_staff), is_staff


def _hd_save_attachment(file_storage):
    if not file_storage or not file_storage.filename:
        return "", ""
    ext = Path(file_storage.filename).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp"):
        raise ValueError("Use PNG, JPG, or WebP screenshots (up to 3 MB).")
    data = file_storage.stream.read(3 * 1024 * 1024 + 1)
    valid = (
        (ext == ".png" and data.startswith(b"\x89PNG\r\n\x1a\n"))
        or (ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8\xff"))
        or (ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    )
    if not data or len(data) > 3 * 1024 * 1024 or not valid:
        raise ValueError("Invalid or oversized screenshot image (max 3 MB).")
    safe_name = "msg-" + uuid.uuid4().hex + ext
    (MSG_UPLOAD_DIR / safe_name).write_bytes(data)
    return f"/api/messages/attachments/{safe_name}", secure_filename(file_storage.filename)[:120] or safe_name


def _hd_find_tagged_or_latest_ticket(conn, requester_username, requester_name, section_id, explicit_ticket_id="", text_body=""):
    explicit = str(explicit_ticket_id or "").strip()
    if not explicit and text_body:
        m = re.search(r"#?([A-Za-z]{1,6}\d{1,4}/\d{2}-\d{2}-\d{4})", text_body)
        if m:
            explicit = m.group(1).strip()
    if explicit:
        r = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets WHERE id=%s", (explicit,)).fetchone()
        if r:
            t = ticket_json(r)
            if t["username"].casefold() == requester_username.casefold() or t["complaintDesk"].casefold() == section_id.casefold():
                return t
    if section_id not in ("visitor", "gatepass"):
        rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 200").fetchall()
        for r in rows:
            t = ticket_json(r)
            own = (requester_username and t["username"].casefold() == requester_username.casefold()) or (requester_name and t["name"].casefold() == requester_name.casefold())
            if own and t["complaintDesk"].casefold() == section_id.casefold():
                return t
    return None


def _hd_build_bot_reply(conn, thr, user_text, tagged_ticket_id, bot_action="", req_expert=""):
    sec = str(thr.get("sectionId") or "it").lower()
    sec_label = str(thr.get("sectionLabel") or sec.title())
    req_uname = str(thr.get("requesterUsername") or "")
    req_name = str(thr.get("requesterName") or req_uname or "User")
    contact = _lookup_requester_contact(conn, req_uname, req_name, thr.get("requesterGender") or "")
    now_local = _local_now_dt()
    greeting = f"{_time_salutation(now_local)} {req_name.split()[0] if req_name else ''} {_gender_honorific(contact['gender'])}, Greetings of the day!"
    low = f"{user_text} {bot_action}".strip().lower()

    # Check Talk to Expert escalation intent
    if bot_action == "talk_to_expert" or any(kw in low for kw in ("talk to expert", "connect expert", "human", "agent", "speak with", "call me", "real person", "escalate", "expert se")):
        experts = _helpdesk_section_experts(conn, sec)
        chosen = None
        if req_expert:
            req_cf = str(req_expert).strip().casefold()
            chosen = next((e for e in experts if str(e["username"] or "").strip().casefold() == req_cf), None)
        if not chosen and thr.get("assignedExpertUsername"):
            thr_cf = str(thr["assignedExpertUsername"] or "").strip().casefold()
            chosen = next((e for e in experts if str(e["username"] or "").strip().casefold() == thr_cf), None)
        if not chosen and experts:
            chosen = experts[0]
        exp_uname = chosen["username"] if chosen else ""
        exp_name = chosen["name"] if chosen else f"{sec_label} Support"
        exp_status = f" ({chosen['status']}" + (f", ~{chosen['etaRemainingMin']}m left" if chosen and chosen.get("etaRemainingMin") else "") + ")" if chosen else ""
        conn.execute(
            "UPDATE helpdesk_threads SET mode='expert', assigned_expert_username=CASE WHEN %s<>'' THEN %s ELSE assigned_expert_username END, assigned_expert_name=CASE WHEN %s<>'' THEN %s ELSE assigned_expert_name END, updated_at=now() WHERE id=%s",
            (exp_uname, exp_uname, exp_name, exp_name, thr["id"]),
        )
        return {
            "reply": f"{greeting} I have connected your conversation directly to {exp_name}{exp_status} in the {sec_label} team and sent them an instant alert. Feel free to describe your issue or tag your #TicketID below — an expert will reply right here!",
            "switchedToExpert": True,
            "expertUsername": exp_uname,
            "expertName": exp_name,
            "taggedTicketId": tagged_ticket_id or thr.get("ticketId") or "",
        }

    # Visitor or Gate Pass section auto-assistant
    if sec == "visitor":
        vrows = conn.execute(
            "SELECT id, visitor_name, host_name, status, factory, department, created_at FROM visitor_passes WHERE lower(host_username)=lower(%s) OR lower(host_name)=lower(%s) ORDER BY created_at DESC LIMIT 5",
            (req_uname, req_name),
        ).fetchall()
        if vrows:
            v = vrows[0]
            return {
                "reply": f"{greeting} Your latest Visitor Pass ({v[0]}) for guest {v[1]} at {v[4]} ({v[5]}) is currently '{v[3]}'. Need gate desk coordination or approval help? Click '👨‍💻 Talk to Expert' anytime.",
                "switchedToExpert": False,
                "taggedTicketId": str(v[0]),
            }
        return {
            "reply": f"{greeting} Welcome to {sec_label} Support! Ask about any Visitor Pass or click '👨‍💻 Talk to Expert' to chat directly with Security/Front Desk.",
            "switchedToExpert": False,
            "taggedTicketId": tagged_ticket_id,
        }

    if sec == "gatepass":
        grows = conn.execute(
            "SELECT id, direction, material_name, status, factory, party_name, created_at FROM material_gate_passes WHERE lower(for_username)=lower(%s) OR lower(for_name)=lower(%s) ORDER BY created_at DESC LIMIT 5",
            (req_uname, req_name),
        ).fetchall()
        if grows:
            g = grows[0]
            return {
                "reply": f"{greeting} Your latest Material {g[1]} Pass ({g[0]}) for {g[2]} (Party: {g[5] or '-'}) at {g[4]} has status '{g[3]}'. Click '👨‍💻 Talk to Expert' to connect with Gate/Material Desk.",
                "switchedToExpert": False,
                "taggedTicketId": str(g[0]),
            }
        return {
            "reply": f"{greeting} Welcome to {sec_label} Support! Share a pass ID or click '👨‍💻 Talk to Expert' to talk directly to our Gate/Material team.",
            "switchedToExpert": False,
            "taggedTicketId": tagged_ticket_id,
        }

    # Helpdesk ticket lookup & intelligent reply
    t = _hd_find_tagged_or_latest_ticket(conn, req_uname, req_name, sec, tagged_ticket_id, user_text)
    avail = _summarize_admin_availability(conn, desk_id=sec, assigned_to=(t["assigned"] if t else ""))
    if t:
        tid = t["id"]
        st = t["status"] or "Open"
        stage_map = {"Open": "Stage 1 of 4 · Open", "In progress": "Stage 2 of 4 · In progress", "Resolved": "Stage 3 of 4 · Resolved", "Closed": "Stage 4 of 4 · Closed"}
        stage_lbl = stage_map.get(st, st)
        exp = t["assigned"] if t["assigned"] and t["assigned"] != "Unassigned" else "Desk Queue (Awaiting Assignment)"
        eta_txt, _ = _format_eta_detail(t["eta"]) if t.get("eta") else ("", 0)
        note_part = f' Latest Work Update: "{t["note"]}".' if t.get("note") else ""
        if any(k in low for k in ("reopen", "still", "not solved", "not resolved", "again")) or bot_action == "reopen":
            if st in ("Resolved", "Closed"):
                return {
                    "reply": f"{greeting} Ticket #{tid} is currently '{st}'. You can click the '🔁 Reopen Ticket' button right on ticket #{tid} to reopen it back to Open and alert {exp}, or click '👨‍💻 Talk to Expert' to chat live.",
                    "switchedToExpert": False,
                    "taggedTicketId": tid,
                    "canReopen": True,
                }
            return {
                "reply": f"{greeting} Ticket #{tid} is already active ({stage_lbl}) with {exp}. {avail['summarySentence']}{note_part} Need urgent help? Click '👨‍💻 Talk to Expert'.",
                "switchedToExpert": False,
                "taggedTicketId": tid,
            }
        if any(k in low for k in ("eta", "time", "when", "wait", "long", "kiti", "busy")):
            eta_msg = f"Expected completion is {eta_txt}." if eta_txt else "No fixed ETA timestamp has been locked yet."
            return {
                "reply": f"{greeting} ETA check for #{tid} ({stage_lbl}): Assigned to {exp}. {eta_msg} {avail['summarySentence']}{note_part} Want to speak directly or switch expert? Use the buttons above or click '👨‍💻 Talk to Expert'.",
                "switchedToExpert": False,
                "taggedTicketId": tid,
            }
        return {
            "reply": f"{greeting} Here is the live status of your {sec_label} ticket #{tid} ({t['primary']} · {t['sub']}): {stage_lbl}, Assigned to {exp}.{(' Expected ETA: ' + eta_txt + '.') if eta_txt else ''} {avail['summarySentence']}{note_part} You can tag another #TicketID or click '👨‍💻 Talk to Expert' for 1-to-1 live help.",
            "switchedToExpert": False,
            "taggedTicketId": tid,
        }

    return {
        "reply": f"{greeting} Welcome to {sec_label} Helpdesk! {avail['summarySentence']} You don't have a tagged ticket selected right now — pick a ticket using '🏷️ Tag Ticket', type your question, or click '👨‍💻 Talk to Expert' to connect directly with a specialist.",
        "switchedToExpert": False,
        "taggedTicketId": tagged_ticket_id,
    }


@app.get("/api/messages/bootstrap")
@signed_in
def messages_bootstrap():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    dname = str(profile.get("name") or "").strip().casefold()
    with db() as conn:
        sections = _helpdesk_section_meta_list(conn)
        for sec in sections:
            sec["experts"] = _helpdesk_section_experts(conn, sec["id"])
            sec["canStaff"] = _helpdesk_caller_can_staff_section(profile, is_adm, sec["id"])

        t_rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 400").fetchall()
        visible_tickets = []
        can_tickets = is_adm or module_access(profile, "tickets")
        for r in t_rows:
            t = ticket_json(r)
            is_own = (uname and t["username"].casefold() == uname) or (dname and t["name"].casefold() == dname)
            t["isOwn"] = is_own
            if is_own or (can_tickets and ticket_desk_allowed(profile, t["complaintDesk"])):
                visible_tickets.append(t)

        v_rows = conn.execute("SELECT id, visitor_name, host_name, host_username, status, factory, department FROM visitor_passes ORDER BY created_at DESC LIMIT 80").fetchall()
        can_vis = is_adm or module_access(profile, "visitors")
        visible_visitors = [
            {"id": v[0], "label": f"{v[0]} · {v[1]} ({v[3]})", "status": v[3], "factory": v[4], "dept": v[5]}
            for v in v_rows
            if can_vis or (uname and str(v[3] or "").casefold() == uname) or (dname and str(v[2] or "").casefold() == dname)
        ][:30]

        g_rows = conn.execute("SELECT id, direction, material_name, for_name, for_username, status, factory, department FROM material_gate_passes ORDER BY created_at DESC LIMIT 80").fetchall()
        can_gp = is_adm or module_access(profile, "gatepass")
        visible_gatepasses = [
            {"id": g[0], "label": f"{g[0]} · {g[1]} {g[2]} ({g[5]})", "status": g[5], "factory": g[6], "dept": g[7]}
            for g in g_rows
            if can_gp or (uname and str(g[4] or "").casefold() == uname) or (dname and str(g[3] or "").casefold() == dname)
        ][:30]

        thr_rows = conn.execute(
            "SELECT id, requester_username, requester_name, requester_dept, requester_factory, requester_gender, section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name, mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff, updated_at FROM helpdesk_threads WHERE deleted_by_admin=false ORDER BY last_message_at DESC LIMIT 400"
        ).fetchall()
        unread_total = 0
        for tr in thr_rows:
            t_obj = _hd_thread_json(tr)
            allowed, is_staff = _hd_can_access_thread(profile, is_adm, t_obj)
            if not allowed:
                continue
            is_own_t = (t_obj["requesterUsername"].casefold() == uname)
            unread_total += t_obj["unreadForRequester"] if is_own_t else t_obj["unreadForStaff"]

    return jsonify(
        sections=sections,
        me={
            "username": uname,
            "name": str(profile.get("name") or uname),
            "isAdmin": is_adm,
            "canDelete": is_adm,
            "role": str(profile.get("role") or "User"),
        },
        tickets=visible_tickets[:200],
        visitors=visible_visitors,
        gatepasses=visible_gatepasses,
        unreadTotal=unread_total,
    )


@app.get("/api/messages/threads")
@signed_in
def list_helpdesk_threads():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    sec_filter = str(request.args.get("section_id") or "").strip().lower()
    with db() as conn:
        sections = _helpdesk_section_meta_list(conn)
        valid_secs = {s["id"] for s in sections}
        if sec_filter and sec_filter not in ("all", "") and sec_filter in valid_secs:
            # Ensure caller always has their own 1-to-1 section thread ready to open
            my_tid = _helpdesk_thread_id(sec_filter, uname)
            sec_meta = next((s for s in sections if s["id"] == sec_filter), {"id": sec_filter, "label": sec_filter.title()})
            exps = _helpdesk_section_experts(conn, sec_filter)
            def_exp_u = exps[0]["username"] if exps else ""
            def_exp_n = exps[0]["name"] if exps else ""
            contact = _lookup_requester_contact(conn, uname, profile.get("name", ""))
            conn.execute(
                """
                INSERT INTO helpdesk_threads(
                  id, requester_username, requester_name, requester_dept, requester_factory, requester_gender,
                  section_id, section_label, assigned_expert_username, assigned_expert_name, mode,
                  last_message_preview, deleted_by_admin
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'bot','Ready to help — ask Bot or Talk to Expert',false)
                ON CONFLICT(id) DO UPDATE SET deleted_by_admin=false WHERE helpdesk_threads.deleted_by_admin=true
                """,
                (
                    my_tid, uname, str(profile.get("name") or uname)[:120],
                    str(profile.get("dept") or "")[:120], str(profile.get("site") or "")[:80],
                    contact["gender"], sec_filter, sec_meta["label"], def_exp_u, def_exp_n,
                ),
            )
        rows = conn.execute(
            "SELECT id, requester_username, requester_name, requester_dept, requester_factory, requester_gender, section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name, mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff, updated_at FROM helpdesk_threads WHERE deleted_by_admin=false ORDER BY last_message_at DESC LIMIT 400"
        ).fetchall()
    out = []
    for row in rows:
        thr = _hd_thread_json(row)
        if sec_filter and sec_filter != "all" and thr["sectionId"] != sec_filter:
            continue
        allowed, is_staff = _hd_can_access_thread(profile, is_adm, thr)
        if not allowed:
            continue
        is_own = (thr["requesterUsername"].casefold() == uname)
        thr["isOwn"] = is_own
        thr["isStaffView"] = bool(is_staff and not is_own)
        thr["unreadCount"] = thr["unreadForRequester"] if is_own else thr["unreadForStaff"]
        out.append(thr)
    return jsonify(threads=out)


@app.get("/api/messages/threads/<path:thread_id>")
@signed_in
def get_helpdesk_thread_detail(thread_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    with db() as conn:
        trow = conn.execute(
            "SELECT id, requester_username, requester_name, requester_dept, requester_factory, requester_gender, section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name, mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff, updated_at FROM helpdesk_threads WHERE id=%s AND deleted_by_admin=false",
            (thread_id,),
        ).fetchone()
        if not trow:
            return jsonify(error="Conversation thread not found."), 404
        thr = _hd_thread_json(trow)
        allowed, is_staff = _hd_can_access_thread(profile, is_adm, thr)
        if not allowed:
            return jsonify(error="Access denied: 1-to-1 conversations are private to the requester and assigned desk."), 403
        is_own = (thr["requesterUsername"].casefold() == uname)
        if is_own and thr["unreadForRequester"] > 0:
            conn.execute("UPDATE helpdesk_threads SET unread_for_requester=0 WHERE id=%s", (thread_id,))
            thr["unreadForRequester"] = 0
        elif not is_own and thr["unreadForStaff"] > 0:
            conn.execute("UPDATE helpdesk_threads SET unread_for_staff=0 WHERE id=%s", (thread_id,))
            thr["unreadForStaff"] = 0
        mrows = conn.execute(
            "SELECT id, thread_id, sender_username, sender_name, sender_role, tagged_ticket_id, body, attachment_url, attachment_name, meta, created_at FROM helpdesk_messages WHERE thread_id=%s ORDER BY created_at ASC LIMIT 300",
            (thread_id,),
        ).fetchall()
        experts = _helpdesk_section_experts(conn, thr["sectionId"])
        section_tickets = []
        if thr["sectionId"] not in ("visitor", "gatepass"):
            tlist = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 250").fetchall()
            for r in tlist:
                tj = ticket_json(r)
                if tj["complaintDesk"].casefold() == thr["sectionId"].casefold() and (
                    tj["username"].casefold() == thr["requesterUsername"].casefold()
                    or (thr["requesterName"] and tj["name"].casefold() == thr["requesterName"].casefold())
                ):
                    section_tickets.append(tj)
    thr["isOwn"] = is_own
    thr["isStaffView"] = bool(is_staff and not is_own)
    thr["unreadCount"] = 0
    return jsonify(
        thread=thr,
        messages=[_hd_msg_json(m) for m in mrows],
        experts=experts,
        sectionTickets=section_tickets,
        canDelete=is_adm,
    )


@app.post("/api/messages/send")
@signed_in
def send_helpdesk_message():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    uname_disp = str(profile.get("name") or uname)[:120]

    if request.content_type and "multipart/form-data" in request.content_type.lower():
        data = request.form
        up_file = request.files.get("attachment")
    else:
        data = request.get_json(silent=True) or {}
        up_file = None

    thread_id = str(data.get("threadId") or "").strip()
    section_id = _slug_desk_id(data.get("sectionId") or "it", "it")
    tagged_ticket_id = str(data.get("taggedTicketId") or "").strip()[:80]
    body_text = str(data.get("body") or "").strip()[:3000]
    bot_action = str(data.get("botAction") or "").strip()[:40]
    talk_to_expert = str(data.get("talkToExpert") or "").lower() in ("1", "true", "yes") or (data.get("talkToExpert") is True)
    req_expert = str(data.get("expertUsername") or "").strip().casefold()

    try:
        att_url, att_name = _hd_save_attachment(up_file) if up_file else ("", "")
    except ValueError as err:
        return jsonify(error=str(err)), 400

    if not body_text and not att_url and not talk_to_expert and not bot_action:
        return jsonify(error="Write a message or attach a screenshot first."), 400

    with db() as conn:
        sections = _helpdesk_section_meta_list(conn)
        if not thread_id:
            thread_id = _helpdesk_thread_id(section_id, uname)
            sec_meta = next((s for s in sections if s["id"] == section_id), {"id": section_id, "label": section_id.title()})
            contact = _lookup_requester_contact(conn, uname, uname_disp)
            exps = _helpdesk_section_experts(conn, section_id)
            chosen_exp = next((e for e in exps if e["username"] == req_expert), None) or (exps[0] if exps else None)
            conn.execute(
                """
                INSERT INTO helpdesk_threads(
                  id, requester_username, requester_name, requester_dept, requester_factory, requester_gender,
                  section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name,
                  mode, last_message_preview, deleted_by_admin
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'',false)
                ON CONFLICT(id) DO UPDATE SET
                  deleted_by_admin=false,
                  assigned_expert_username=CASE WHEN excluded.assigned_expert_username<>'' AND %s<>'' THEN excluded.assigned_expert_username ELSE helpdesk_threads.assigned_expert_username END,
                  assigned_expert_name=CASE WHEN excluded.assigned_expert_name<>'' AND %s<>'' THEN excluded.assigned_expert_name ELSE helpdesk_threads.assigned_expert_name END
                """,
                (
                    thread_id, uname, uname_disp, str(profile.get("dept") or "")[:120],
                    str(profile.get("site") or "")[:80], contact["gender"],
                    section_id, sec_meta["label"], tagged_ticket_id,
                    chosen_exp["username"] if chosen_exp else "",
                    chosen_exp["name"] if chosen_exp else "",
                    "expert" if talk_to_expert else "bot",
                    req_expert,
                    req_expert,
                ),
            )

        trow = conn.execute(
            "SELECT id, requester_username, requester_name, requester_dept, requester_factory, requester_gender, section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name, mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff, updated_at FROM helpdesk_threads WHERE id=%s FOR UPDATE",
            (thread_id,),
        ).fetchone()
        if not trow:
            return jsonify(error="Thread not found."), 404
        thr = _hd_thread_json(trow)
        allowed, is_staff = _hd_can_access_thread(profile, is_adm, thr)
        if not allowed:
            return jsonify(error="You cannot message inside another user's private helpdesk thread."), 403

        is_own = (thr["requesterUsername"].casefold() == uname)
        sender_role = "user" if is_own else "expert"
        if req_expert:
            exps = _helpdesk_section_experts(conn, thr["sectionId"])
            matched_e = next((e for e in exps if str(e["username"] or "").strip().casefold() == req_expert), None)
            if matched_e:
                thr["assignedExpertUsername"] = matched_e["username"]
                thr["assignedExpertName"] = matched_e["name"]
                conn.execute("UPDATE helpdesk_threads SET assigned_expert_username=%s, assigned_expert_name=%s WHERE id=%s", (matched_e["username"], matched_e["name"], thread_id))

        effective_text = body_text or ("Connected to Helpdesk Expert" if talk_to_expert else (f"[{bot_action}]" if bot_action else att_name))
        msg_id = "hdm-" + uuid.uuid4().hex[:14]
        conn.execute(
            """
            INSERT INTO helpdesk_messages(
              id, thread_id, sender_username, sender_name, sender_role, tagged_ticket_id, body, attachment_url, attachment_name
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (msg_id, thread_id, uname, uname_disp, sender_role, tagged_ticket_id, effective_text, att_url, att_name),
        )

        bot_msg_obj = None
        if sender_role == "expert":
            # Staff/Admin replying to requester -> format notification politely & notify ONLY requester
            contact = _lookup_requester_contact(conn, thr["requesterUsername"], thr["requesterName"], thr["requesterGender"])
            greeting = f"{_time_salutation(_local_now_dt())} {_gender_honorific(contact['gender'])}, Greetings of the day!"
            conn.execute(
                """
                UPDATE helpdesk_threads
                SET mode='expert', assigned_expert_username=%s, assigned_expert_name=%s,
                    ticket_id=CASE WHEN %s<>'' THEN %s ELSE ticket_id END,
                    last_message_preview=%s, last_message_at=now(),
                    unread_for_requester=unread_for_requester + 1, unread_for_staff=0, updated_at=now()
                WHERE id=%s
                """,
                (uname, uname_disp, tagged_ticket_id, tagged_ticket_id, f"{uname_disp}: {effective_text}"[:180], thread_id),
            )
            _record_notification_event(conn, {
                "eventKey": f"hd-msg:{msg_id}",
                "kind": "helpdesk_message",
                "level": "info",
                "title": f"💬 Reply from {uname_disp} ({thr['sectionLabel']})",
                "body": f"{greeting} {uname_disp}: {effective_text}"[:360],
                "factory": thr["requesterFactory"],
                "targetView": "messages",
                "targetTab": thr["sectionId"],
                "targetId": thread_id,
                "targetTicketId": tagged_ticket_id or thr["ticketId"],
                "targetRole": "requester",
                "targetUsername": thr["requesterUsername"][:80],
                "requesterName": thr["requesterName"][:120],
                "complaintDesk": thr["sectionId"],
            })
        else:
            # User sending message -> check Bot vs Talk-to-Expert mode
            use_expert = (thr["mode"] == "expert") and not bot_action and not talk_to_expert
            if not use_expert:
                eff_bot_action = "talk_to_expert" if (talk_to_expert and not bot_action) else bot_action
                bot_res = _hd_build_bot_reply(conn, thr, body_text, tagged_ticket_id, bot_action=eff_bot_action, req_expert=req_expert)
                bot_id = "hdm-" + uuid.uuid4().hex[:14]
                b_tag = bot_res.get("taggedTicketId") or tagged_ticket_id
                conn.execute(
                    """
                    INSERT INTO helpdesk_messages(
                      id, thread_id, sender_username, sender_name, sender_role, tagged_ticket_id, body, meta
                    ) VALUES(%s,%s,'helpdesk-bot',%s,'bot',%s,%s,%s::jsonb)
                    """,
                    (
                        bot_id, thread_id, f"{thr['sectionLabel']} Assistant", b_tag[:80],
                        bot_res["reply"][:3000], json.dumps({"canReopen": bool(bot_res.get("canReopen"))}),
                    ),
                )
                new_mode = "expert" if (bot_res.get("switchedToExpert") or thr["mode"] == "expert") else "bot"
                conn.execute(
                    """
                    UPDATE helpdesk_threads
                    SET mode=%s, ticket_id=CASE WHEN %s<>'' THEN %s ELSE ticket_id END,
                        last_message_preview=%s, last_message_at=now(),
                        unread_for_staff=CASE WHEN %s='expert' THEN unread_for_staff + 1 ELSE unread_for_staff END,
                        updated_at=now()
                    WHERE id=%s
                    """,
                    (new_mode, b_tag, b_tag, bot_res["reply"][:180], new_mode, thread_id),
                )
                if bot_res.get("switchedToExpert"):
                    _record_notification_event(conn, {
                        "eventKey": f"hd-esc:{msg_id}",
                        "kind": "helpdesk_message",
                        "level": "info",
                        "title": f"👨‍💻 Live Help Requested · {thr['requesterName']} ({thr['sectionLabel']})",
                        "body": f"{thr['requesterName']} requested Talk to Expert" + (f" ({b_tag})" if b_tag else "") + f": {effective_text}"[:240],
                        "factory": thr["requesterFactory"],
                        "targetView": "messages",
                        "targetTab": thr["sectionId"],
                        "targetId": thread_id,
                        "targetTicketId": b_tag,
                        "targetRole": "expert",
                        "targetAssignee": bot_res.get("expertUsername") or thr["assignedExpertUsername"],
                        "complaintDesk": thr["sectionId"],
                    })
                bot_msg_obj = {"id": bot_id, "body": bot_res["reply"], "switchedToExpert": bool(bot_res.get("switchedToExpert"))}
            else:
                conn.execute(
                    """
                    UPDATE helpdesk_threads
                    SET mode='expert', ticket_id=CASE WHEN %s<>'' THEN %s ELSE ticket_id END,
                        last_message_preview=%s, last_message_at=now(),
                        unread_for_staff=unread_for_staff + 1, unread_for_requester=0, updated_at=now()
                    WHERE id=%s
                    """,
                    (tagged_ticket_id, tagged_ticket_id, f"{uname_disp}: {effective_text}"[:180], thread_id),
                )
                _record_notification_event(conn, {
                    "eventKey": f"hd-usr:{msg_id}",
                    "kind": "helpdesk_message",
                    "level": "info",
                    "title": f"💬 {thr['requesterName']} ({thr['sectionLabel']})",
                    "body": (f"[{tagged_ticket_id}] " if tagged_ticket_id else "") + effective_text[:300],
                    "factory": thr["requesterFactory"],
                    "targetView": "messages",
                    "targetTab": thr["sectionId"],
                    "targetId": thread_id,
                    "targetTicketId": tagged_ticket_id or thr["ticketId"],
                    "targetRole": "expert",
                    "targetAssignee": thr["assignedExpertUsername"],
                    "complaintDesk": thr["sectionId"],
                })

        _pg_emit_notify(conn, "helpdesk_message", {"threadId": thread_id, "sectionId": thr["sectionId"]})
    return jsonify(ok=True, threadId=thread_id, messageId=msg_id, botReply=bot_msg_obj)


@app.post("/api/messages/threads/<path:thread_id>/mode")
@signed_in
def switch_helpdesk_thread_mode(thread_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    body = request.get_json(silent=True) or {}
    mode = "expert" if str(body.get("mode") or "").lower() == "expert" else "bot"
    with db() as conn:
        trow = conn.execute(
            "SELECT id, requester_username, requester_name, requester_dept, requester_factory, requester_gender, section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name, mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff, updated_at FROM helpdesk_threads WHERE id=%s AND deleted_by_admin=false",
            (thread_id,),
        ).fetchone()
        if not trow:
            return jsonify(error="Thread not found."), 404
        thr = _hd_thread_json(trow)
        allowed, _ = _hd_can_access_thread(profile, is_adm, thr)
        if not allowed:
            return jsonify(error="Access denied."), 403
        conn.execute("UPDATE helpdesk_threads SET mode=%s, updated_at=now() WHERE id=%s", (mode, thread_id))
        _pg_emit_notify(conn, "helpdesk_message", {"threadId": thread_id, "mode": mode})
    return jsonify(ok=True, threadId=thread_id, mode=mode)


@app.post("/api/messages/threads/<path:thread_id>/assign-expert")
@signed_in
def assign_helpdesk_thread_expert(thread_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    uname_disp = str(profile.get("name") or uname)[:120]
    body = request.get_json(silent=True) or {}
    expert_uname = str(body.get("expertUsername") or "").strip().casefold()
    ticket_id = str(body.get("ticketId") or "").strip()

    with db() as conn:
        trow = conn.execute(
            "SELECT id, requester_username, requester_name, requester_dept, requester_factory, requester_gender, section_id, section_label, ticket_id, assigned_expert_username, assigned_expert_name, mode, last_message_preview, last_message_at, unread_for_requester, unread_for_staff, updated_at FROM helpdesk_threads WHERE id=%s AND deleted_by_admin=false FOR UPDATE",
            (thread_id,),
        ).fetchone()
        if not trow:
            return jsonify(error="Thread not found."), 404
        thr = _hd_thread_json(trow)
        allowed, _ = _hd_can_access_thread(profile, is_adm, thr)
        if not allowed:
            return jsonify(error="Access denied."), 403

        experts = _helpdesk_section_experts(conn, thr["sectionId"])
        chosen = next((e for e in experts if e["username"] == expert_uname), None)
        if not chosen:
            return jsonify(error=f"Selected expert does not handle {thr['sectionLabel']}."), 400

        conn.execute(
            "UPDATE helpdesk_threads SET assigned_expert_username=%s, assigned_expert_name=%s, mode='expert', ticket_id=CASE WHEN %s<>'' THEN %s ELSE ticket_id END, updated_at=now() WHERE id=%s",
            (chosen["username"], chosen["name"], ticket_id, ticket_id, thread_id),
        )
        msg_text = f"{uname_disp} switched/assigned {chosen['name']} ({thr['sectionLabel']} · {chosen['status']}) for this conversation" + (f" and ticket #{ticket_id}." if ticket_id else ".")
        msg_id = "hdm-" + uuid.uuid4().hex[:14]
        conn.execute(
            "INSERT INTO helpdesk_messages(id, thread_id, sender_username, sender_name, sender_role, tagged_ticket_id, body) VALUES(%s,%s,%s,%s,'system',%s,%s)",
            (msg_id, thread_id, "helpdesk-auto", f"{thr['sectionLabel']} Routing", ticket_id, msg_text),
        )

        # If a specific ticket in the same section was selected, allow requester (own ticket) or staff to route it to that expert
        ticket_routed = False
        if ticket_id and thr["sectionId"] not in ("visitor", "gatepass"):
            tk = conn.execute("SELECT id, username, display_name, COALESCE(NULLIF(complaint_desk,''),'it'), status FROM tickets WHERE id=%s FOR UPDATE", (ticket_id,)).fetchone()
            if tk:
                is_tk_owner = (uname and str(tk[1] or "").casefold() == uname) or (str(profile.get("name") or "").casefold() == str(tk[2] or "").casefold())
                can_tk_staff = _helpdesk_caller_can_staff_section(profile, is_adm, tk[3])
                if is_tk_owner or can_tk_staff:
                    conn.execute("UPDATE tickets SET assigned_to=%s, updated_at=now() WHERE id=%s", (chosen["name"], ticket_id))
                    conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'updated',%s)", (ticket_id, uname_disp, f"assigned: {chosen['name']} (via Helpdesk Messages)"))
                    _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="assigned", actor=uname_disp, assigned_to=chosen["name"], status=tk[4])
                    ticket_routed = True

        _record_notification_event(conn, {
            "eventKey": f"hd-assign:{msg_id}",
            "kind": "helpdesk_message",
            "level": "info",
            "title": f"🔄 Assigned to {chosen['name']} ({thr['sectionLabel']})",
            "body": msg_text,
            "factory": thr["requesterFactory"],
            "targetView": "messages",
            "targetTab": thr["sectionId"],
            "targetId": thread_id,
            "targetTicketId": ticket_id or thr["ticketId"],
            "targetRole": "expert",
            "targetAssignee": chosen["username"],
            "complaintDesk": thr["sectionId"],
        })
        _pg_emit_notify(conn, "helpdesk_message", {"threadId": thread_id})
    return jsonify(ok=True, assignedExpert=chosen, ticketRouted=ticket_routed)


@app.post("/api/messages/tickets/<path:ticket_id>/reopen")
@signed_in
def reopen_ticket_from_messages(ticket_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip().casefold()
    dname = str(profile.get("name") or "").strip().casefold()
    actor = str(profile.get("name") or uname or "User")[:120]
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "Reopened from Helpdesk Messages").strip()[:400]

    with db() as conn:
        t_row = conn.execute("SELECT id, username, display_name, COALESCE(NULLIF(complaint_desk,''),'it'), status, assigned_to, factory FROM tickets WHERE id=%s FOR UPDATE", (ticket_id,)).fetchone()
        if not t_row:
            return jsonify(error="Ticket not found."), 404
        is_owner = (uname and str(t_row[1] or "").casefold() == uname) or (dname and str(t_row[2] or "").casefold() == dname)
        is_staff = _helpdesk_caller_can_staff_section(profile, is_adm, t_row[3])
        if not is_owner and not is_staff:
            return jsonify(error="Only the ticket requester or support desk staff can reopen this ticket."), 403
        conn.execute("UPDATE tickets SET status='Open', note=%s, updated_at=now() WHERE id=%s", (f"[Reopened] {reason}", ticket_id))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'updated',%s)", (ticket_id, actor, f"status: Open; reason: {reason}"))
        _record_ticket_reopen_meta(conn, ticket_id, actor, reason, desk_id=t_row[3], prev_status=t_row[4])
        _on_ticket_status_changed(conn, ticket_id, "Open")
        notif = _build_and_record_ticket_user_notification(conn, ticket_id=ticket_id, event_type="status_change", actor=actor, status="Open", note=f"Ticket reopened: {reason}")
        req_key = _resolve_ticket_requester_key(conn, t_row[1], t_row[2])
        thr_id = _helpdesk_thread_id(t_row[3], req_key)
        _record_notification_event(conn, {
            "eventKey": f"hd-reopen:{ticket_id}:{uuid.uuid4().hex[:8]}",
            "kind": "helpdesk_message",
            "level": "info",
            "title": f"🔁 Ticket {ticket_id} Reopened by {actor}",
            "body": f"Reason: {reason}",
            "factory": t_row[6] or "",
            "targetView": "messages",
            "targetTab": t_row[3],
            "targetId": thr_id,
            "targetTicketId": ticket_id,
            "targetRole": "expert",
            "complaintDesk": t_row[3],
        })
        _pg_emit_notify(conn, "ticket", {"action": "reopen", "ticketId": ticket_id, "complaintDesk": t_row[3]})
    return jsonify(ok=True, ticketId=ticket_id, status="Open", notification=notif)


@app.delete("/api/messages/item/<path:msg_id>")
@administrator
def admin_delete_helpdesk_message(msg_id):
    with db() as conn:
        row = conn.execute("DELETE FROM helpdesk_messages WHERE id=%s RETURNING thread_id", (msg_id,)).fetchone()
        if not row:
            return jsonify(error="Message not found."), 404
        thr_id = row[0]
        last = conn.execute("SELECT sender_name, body, created_at FROM helpdesk_messages WHERE thread_id=%s ORDER BY created_at DESC LIMIT 1", (thr_id,)).fetchone()
        preview = f"{last[0]}: {last[1]}"[:180] if last else "Conversation cleared by Administrator"
        conn.execute("UPDATE helpdesk_threads SET last_message_preview=%s, updated_at=now() WHERE id=%s", (preview, thr_id))
        _pg_emit_notify(conn, "helpdesk_message", {"threadId": thr_id, "deleted": True})
    return jsonify(ok=True, deletedId=msg_id, threadId=thr_id)


@app.delete("/api/messages/threads/<path:thread_id>")
@administrator
def admin_delete_helpdesk_thread(thread_id):
    with db() as conn:
        conn.execute("DELETE FROM helpdesk_messages WHERE thread_id=%s", (thread_id,))
        row = conn.execute("UPDATE helpdesk_threads SET deleted_by_admin=true, last_message_preview='', unread_for_requester=0, unread_for_staff=0, updated_at=now() WHERE id=%s RETURNING id", (thread_id,)).fetchone()
        if not row:
            return jsonify(error="Thread not found."), 404
        _pg_emit_notify(conn, "helpdesk_message", {"threadId": thread_id, "threadDeleted": True})
    return jsonify(ok=True, deletedThreadId=thread_id)


@app.get("/api/messages/attachments/<path:filename>")
@signed_in
def serve_helpdesk_attachment(filename):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    clean_name = Path(filename).name
    if not clean_name or clean_name != filename:
        abort(404)
    rel_url = f"/api/messages/attachments/{clean_name}"
    with db() as conn:
        row = conn.execute(
            "SELECT t.id, t.requester_username, t.section_id FROM helpdesk_messages m JOIN helpdesk_threads t ON t.id=m.thread_id WHERE m.attachment_url=%s LIMIT 1",
            (rel_url,),
        ).fetchone()
    if not row:
        abort(404)
    allowed, _ = _hd_can_access_thread(profile, is_adm, {"id": row[0], "requesterUsername": row[1], "sectionId": row[2]})
    if not allowed:
        abort(403)
    target = (MSG_UPLOAD_DIR / clean_name).resolve()
    if not target.is_relative_to(MSG_UPLOAD_DIR.resolve()) or not target.is_file():
        abort(404)
    return send_from_directory(str(MSG_UPLOAD_DIR), clean_name, as_attachment=False)


# ============================================================================
# WORKSPACE TASK'S MODULE — DAILY / WEEKLY / MONTHLY / TEAMWORK / DELEGATION
# ============================================================================
_TASK_CADENCES = ("daily", "weekly", "monthly")
_TASK_WORK_MODES = ("personal", "delegated", "department", "dept_to_dept")
_TASK_PRIORITIES = ("Urgent", "High", "Normal", "Low")
_TASK_ALLOWED_EXTS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".csv", ".txt", ".json", ".log", ".zip", ".7z", ".mp4", ".mov",
    ".odt", ".ods", ".odp", ".rtf",
}
_TASK_MAX_FILE_BYTES = 15 * 1024 * 1024
_TASK_MAX_ATTACHMENTS = 25


def _task_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _task_parse_dt(val):
    s = str(val or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _normalize_tasks_doc(raw):
    if isinstance(raw, dict):
        items = raw.get("tasks") if isinstance(raw.get("tasks"), list) else []
        rev = int(raw.get("rev") or 0)
        return {"tasks": [x for x in items if isinstance(x, dict)], "rev": rev}
    if isinstance(raw, list):
        return {"tasks": [x for x in raw if isinstance(x, dict)], "rev": 0}
    return {"tasks": [], "rev": 0}


def _load_tasks_doc(conn, for_update=False):
    sql = "SELECT value FROM app_state WHERE key='workspace_tasks'" + (" FOR UPDATE" if for_update else "")
    row = conn.execute(sql).fetchone()
    return _normalize_tasks_doc(row[0] if row else {})


def _save_tasks_doc(conn, doc):
    doc["rev"] = int(doc.get("rev") or 0) + 1
    conn.execute(
        "INSERT INTO app_state(key,value) VALUES('workspace_tasks',%s::jsonb) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
        (json.dumps(doc),),
    )
    return doc


def _task_people_and_depts(conn):
    u_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    d_row = conn.execute("SELECT value FROM app_state WHERE key='departments'").fetchone()
    raw_users = u_row[0] if u_row and isinstance(u_row[0], list) else []
    raw_depts = d_row[0] if d_row and isinstance(d_row[0], list) else []
    people = []
    seen_u = set()
    for u in raw_users:
        if not isinstance(u, dict) or not u.get("enabled", True):
            continue
        uname = str(u.get("username") or "").strip()
        if not uname:
            continue
        ucf = uname.casefold()
        if ucf in seen_u:
            continue
        seen_u.add(ucf)
        people.append({
            "username": uname,
            "name": str(u.get("name") or uname).strip()[:120],
            "dept": str(u.get("dept") or u.get("department") or "").strip()[:120],
            "site": str(u.get("site") or "").strip()[:60],
            "role": str(u.get("role") or "User").strip()[:60],
        })
    people.sort(key=lambda x: (x["name"].casefold(), x["username"].casefold()))
    depts = []
    seen_d = set()
    for d in raw_depts:
        dn = ""
        if isinstance(d, list) and d:
            dn = str(d[0] or "").strip()
        elif isinstance(d, dict):
            dn = str(d.get("name") or d.get("dept") or "").strip()
        elif isinstance(d, str):
            dn = d.strip()
        if dn and dn.casefold() not in seen_d:
            seen_d.add(dn.casefold())
            depts.append(dn[:120])
    for p in people:
        dn = p["dept"]
        if dn and dn.casefold() not in seen_d:
            seen_d.add(dn.casefold())
            depts.append(dn[:120])
    depts.sort(key=lambda x: x.casefold())
    return people, depts


def _task_resolve_person(people, raw_val):
    q = str(raw_val or "").strip().casefold()
    if not q:
        return None
    for p in people:
        if p["username"].casefold() == q:
            return p
    for p in people:
        if p["name"].casefold() == q:
            return p
    return None


def _task_rebuild_involved(task):
    inv = []
    seen = set()

    def _add(u):
        s = str(u or "").strip().casefold()
        if s and s not in seen:
            seen.add(s)
            inv.append(s)

    for k in ("creatorUsername", "assigneeUsername", "acceptedByUsername", "declinedByUsername", "completedByUsername"):
        _add(task.get(k))
    for step in (task.get("delegationChain") or []):
        if isinstance(step, dict):
            _add(step.get("fromUsername"))
            _add(step.get("toUsername"))
    for w in (task.get("watchers") or []):
        if isinstance(w, dict):
            _add(w.get("username"))
        elif isinstance(w, str):
            _add(w)
    for u in (task.get("involvedUsers") or []):
        _add(u)
    task["involvedUsers"] = inv
    return inv


def _task_user_dept_set(profile):
    out = set()
    if isinstance(profile, dict):
        for k in ("dept", "department"):
            v = str(profile.get(k) or "").strip().casefold()
            if v:
                out.add(v)
    return out


def _task_visible_to(task, profile, is_adm=False):
    if is_adm:
        return True
    if not isinstance(task, dict) or not isinstance(profile, dict):
        return False
    uname_cf = str(profile.get("username") or "").strip().casefold()
    if uname_cf:
        if uname_cf == str(task.get("creatorUsername") or "").strip().casefold():
            return True
        if uname_cf == str(task.get("assigneeUsername") or "").strip().casefold():
            return True
        inv = {str(u or "").strip().casefold() for u in (task.get("involvedUsers") or [])}
        if uname_cf in inv:
            return True
    u_depts = _task_user_dept_set(profile)
    if u_depts:
        for d in [task.get("targetDepartment"), task.get("sourceDepartment"), *(task.get("sharedDepartments") or [])]:
            if d and _dept_matches(u_depts, d):
                return True
    return False


def _task_is_overdue(task, now_dt=None):
    if not isinstance(task, dict):
        return False
    if str(task.get("status") or "") in ("Completed", "Declined"):
        return False
    ref_due = task.get("committedDueAt") or task.get("dueAt")
    dt = _task_parse_dt(ref_due)
    if not dt:
        return False
    now_dt = now_dt or datetime.now(timezone.utc)
    return dt < now_dt


def _task_add_timeline(task, action, actor_username, actor_name, detail):
    tl = list(task.get("timeline") or [])
    tl.append({
        "id": "tl-" + uuid.uuid4().hex[:10],
        "action": str(action or "update")[:40],
        "actorUsername": str(actor_username or "")[:80],
        "actorName": str(actor_name or actor_username or "System")[:120],
        "detail": str(detail or "")[:400],
        "at": _task_now_iso(),
    })
    task["timeline"] = tl[-80:]


def _task_notify(conn, task, title, body, event_key, level="info", kind="task", exclude_username="", extra_users=None, extra_depts=None):
    _task_rebuild_involved(task)
    ex_cf = str(exclude_username or "").strip().casefold()
    users_set = []
    seen_u = set()
    for u in list(task.get("involvedUsers") or []) + list(extra_users or []):
        ucf = str(u or "").strip().casefold()
        if ucf and ucf != ex_cf and ucf not in seen_u:
            seen_u.add(ucf)
            users_set.append(ucf)
    depts_set = []
    seen_d = set()
    for d in [task.get("targetDepartment"), task.get("sourceDepartment"), *(task.get("sharedDepartments") or []), *(extra_depts or [])]:
        ds = str(d or "").strip()
        if ds and ds.casefold() not in seen_d:
            seen_d.add(ds.casefold())
            depts_set.append(ds)
    ev = None
    if users_set or depts_set:
        ev = _record_notification_event(conn, {
            "eventKey": str(event_key or f"tsk:{task.get('id')}:{uuid.uuid4().hex[:8]}")[:160],
            "kind": kind,
            "level": level,
            "title": str(title or "Task Update")[:180],
            "body": str(body or "")[:400],
            "factory": str(task.get("creatorSite") or "")[:60],
            "targetView": "tasks",
            "targetTab": str(task.get("cadence") or "daily")[:40],
            "targetId": str(task.get("id") or "")[:120],
            "targetUsername": users_set[0] if len(users_set) == 1 else "",
            "targetAssignee": str(task.get("assigneeUsername") or "").strip().casefold(),
            "targetDepartment": str(task.get("targetDepartment") or "")[:120],
            "targetUsers": users_set,
            "targetDepartments": depts_set,
            "targetTicketId": str(task.get("linkedTicketId") or "")[:120],
        })
    _pg_emit_notify(conn, "task", {
        "taskId": str(task.get("id") or ""),
        "kind": kind,
        "status": str(task.get("status") or ""),
    })
    return ev


def _task_next_due_iso(due_val, cadence):
    dt = _task_parse_dt(due_val) or datetime.now(timezone.utc)
    if cadence == "daily":
        nxt = dt + timedelta(days=1)
    elif cadence == "weekly":
        nxt = dt + timedelta(days=7)
    else:
        nxt = dt + timedelta(days=30)
    return nxt.isoformat(timespec="minutes")


def _task_clean_checklist(raw_list):
    out = []
    if not isinstance(raw_list, list):
        return out
    for item in raw_list[:40]:
        if isinstance(item, str):
            txt = item.strip()[:240]
            if txt:
                out.append({"id": "chk-" + uuid.uuid4().hex[:8], "text": txt, "done": False})
        elif isinstance(item, dict):
            txt = str(item.get("text") or "").strip()[:240]
            if txt:
                cid = str(item.get("id") or ("chk-" + uuid.uuid4().hex[:8]))[:40]
                out.append({"id": cid, "text": txt, "done": bool(item.get("done"))})
    return out


def _evaluate_task_reminders(conn, caller_username_cf=None, force_task_id=None):
    doc = _load_tasks_doc(conn, for_update=True)
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat(timespec="seconds")
    caller_cf = str(caller_username_cf or "").strip().casefold()
    fired_all = []
    fired_caller = []
    dirty = False

    for task in doc["tasks"]:
        st = str(task.get("status") or "Pending")
        if st in ("Completed", "Declined"):
            continue
        try:
            interval = int(task.get("reminderIntervalMins") or 0)
        except (TypeError, ValueError):
            interval = 0
        if interval <= 0 and force_task_id != task.get("id"):
            continue
        ref_dt = _task_parse_dt(task.get("lastRemindedAt")) or _task_parse_dt(task.get("createdAt"))
        elapsed_mins = ((now_dt - ref_dt).total_seconds() / 60.0) if ref_dt else float(interval + 1)
        if force_task_id != task.get("id") and elapsed_mins < max(1, interval):
            continue

        overdue = _task_is_overdue(task, now_dt=now_dt)
        awaiting = str(task.get("acceptanceStatus") or "") == "pending"
        cadence_lbl = str(task.get("cadence") or "daily").capitalize()
        if overdue:
            title = f"⏰ Overdue {cadence_lbl} Task: {task.get('title', '')}"[:180]
            body = f"[{task.get('id')}] Pending completion (Due: {task.get('committedDueAt') or task.get('dueAt') or 'Now'}). Please update status."
            lvl = "warn"
        elif awaiting:
            title = f"📩 Action Required — Accept Task: {task.get('title', '')}"[:180]
            body = f"[{task.get('id')}] Assigned by {task.get('creatorName') or 'colleague'}. Please Accept (with ETA & plan), Decline, or Reassign."
            lvl = "warn"
        else:
            title = f"🔔 Pending {cadence_lbl} Task Reminder: {task.get('title', '')}"[:180]
            body = f"[{task.get('id')}] Status: {st} · Priority: {task.get('priority', 'Normal')}. Still pending — please update progress."
            lvl = "info"

        task["lastRemindedAt"] = now_iso
        dirty = True
        ev_key = f"task-rem:{task.get('id')}:{int(now_dt.timestamp() // 60)}"
        ev = _task_notify(conn, task, title, body, event_key=ev_key, level=lvl, kind="task_reminder", exclude_username="")
        if ev:
            fired_all.append(ev)
            if caller_cf and caller_cf in [str(u).casefold() for u in (ev.get("targetUsers") or [])]:
                fired_caller.append(ev)

    if dirty:
        _save_tasks_doc(conn, doc)
    return fired_caller, fired_all


def _task_summary_for(tasks_list, profile):
    uname_cf = str((profile or {}).get("username") or "").strip().casefold()
    u_depts = _task_user_dept_set(profile)
    now_dt = datetime.now(timezone.utc)
    s = {
        "total": len(tasks_list),
        "dailyPending": 0, "dailyCompleted": 0,
        "weeklyPending": 0, "weeklyCompleted": 0,
        "monthlyPending": 0, "monthlyCompleted": 0,
        "teamworkPending": 0, "teamworkCompleted": 0,
        "awaitingMyAccept": 0, "assignedToMePending": 0,
        "assignedByMePending": 0, "overdue": 0,
        "completed": 0, "pending": 0,
    }
    for t in tasks_list:
        st = str(t.get("status") or "Pending")
        is_done = (st == "Completed")
        cad = str(t.get("cadence") or "daily").lower()
        wm = str(t.get("workMode") or "personal").lower()
        if is_done:
            s["completed"] += 1
        elif st != "Declined":
            s["pending"] += 1
        if cad == "daily":
            s["dailyCompleted" if is_done else "dailyPending"] += 1
        elif cad == "weekly":
            s["weeklyCompleted" if is_done else "weeklyPending"] += 1
        elif cad == "monthly":
            s["monthlyCompleted" if is_done else "monthlyPending"] += 1
        if wm in ("department", "dept_to_dept"):
            s["teamworkCompleted" if is_done else "teamworkPending"] += 1
        if _task_is_overdue(t, now_dt=now_dt):
            s["overdue"] += 1
        asg_u = str(t.get("assigneeUsername") or "").strip().casefold()
        cr_u = str(t.get("creatorUsername") or "").strip().casefold()
        acc = str(t.get("acceptanceStatus") or "")
        is_my_dept_target = bool(not asg_u and t.get("targetDepartment") and _dept_matches(u_depts, t.get("targetDepartment")))
        if not is_done and st != "Declined":
            if acc == "pending" and ((uname_cf and asg_u == uname_cf) or is_my_dept_target):
                s["awaitingMyAccept"] += 1
            if (uname_cf and asg_u == uname_cf) or is_my_dept_target:
                s["assignedToMePending"] += 1
            if uname_cf and cr_u == uname_cf and (asg_u != uname_cf):
                s["assignedByMePending"] += 1
    return s


@app.get("/api/tasks")
@signed_in
def list_workspace_tasks():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    with db() as conn:
        doc = _load_tasks_doc(conn)
        people, depts = _task_people_and_depts(conn)
        # Lightweight recent tickets list for optional Ticket <-> Task linking
        recent_tickets = []
        try:
            t_rows = conn.execute(
                "SELECT id, display_name, department, factory, status, primary_category, description "
                "FROM tickets ORDER BY updated_at DESC LIMIT 80"
            ).fetchall()
            for r in t_rows:
                recent_tickets.append({
                    "id": str(r[0] or ""),
                    "name": str(r[1] or ""),
                    "dept": str(r[2] or ""),
                    "site": str(r[3] or ""),
                    "status": str(r[4] or ""),
                    "primary": str(r[5] or ""),
                    "summary": str(r[6] or "")[:120],
                })
        except Exception:
            recent_tickets = []

    visible = [t for t in doc["tasks"] if _task_visible_to(t, profile, is_adm)]
    visible.sort(key=lambda x: str(x.get("updatedAt") or x.get("createdAt") or ""), reverse=True)
    summary = _task_summary_for(visible, profile)
    can_write = is_adm or module_access(profile, "tasks", write=True)
    return jsonify(
        tasks=visible,
        summary=summary,
        people=people,
        departments=depts,
        tickets=recent_tickets,
        canWrite=can_write,
        me={
            "username": str(profile.get("username") or ""),
            "name": str(profile.get("name") or profile.get("username") or ""),
            "dept": str(profile.get("dept") or profile.get("department") or ""),
            "site": str(profile.get("site") or ""),
            "isAdmin": is_adm,
        },
        serverNow=_task_now_iso(),
    )


@app.post("/api/tasks")
@signed_in
def create_workspace_task():
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    body = request.get_json(silent=True) or {}
    title = str(body.get("title") or "").strip()[:200]
    if not title:
        return jsonify(error="Task title is required."), 400
    description = str(body.get("description") or "").strip()[:4000]
    cadence = str(body.get("cadence") or "daily").strip().lower()
    if cadence not in _TASK_CADENCES:
        cadence = "daily"
    work_mode = str(body.get("workMode") or "personal").strip().lower()
    if work_mode not in _TASK_WORK_MODES:
        work_mode = "personal"
    priority = str(body.get("priority") or "Normal").strip()
    if priority not in _TASK_PRIORITIES:
        priority = "Normal"
    due_at = str(body.get("dueAt") or "").strip()[:40]
    try:
        default_rem = 60 if cadence == "daily" else (240 if cadence == "weekly" else 1440)
        rem_raw = body.get("reminderIntervalMins")
        rem_mins = default_rem if rem_raw is None or rem_raw == "" else max(0, min(10080, int(rem_raw)))
    except (TypeError, ValueError):
        rem_mins = 60
    recurring = bool(body.get("recurring"))
    linked_ticket_id = str(body.get("linkedTicketId") or "").strip()[:80]
    checklist = _task_clean_checklist(body.get("checklist") or [])

    creator_u = str(profile.get("username") or "").strip()
    creator_u_cf = creator_u.casefold()
    creator_name = str(profile.get("name") or creator_u or "User").strip()[:120]
    creator_dept = str(profile.get("dept") or profile.get("department") or "").strip()[:120]
    creator_site = str(profile.get("site") or "").strip()[:60]

    with db() as conn:
        people, _depts = _task_people_and_depts(conn)
        doc = _load_tasks_doc(conn, for_update=True)

        req_asg = str(body.get("assigneeUsername") or "").strip()
        target_dept = str(body.get("targetDepartment") or "").strip()[:120]
        source_dept = str(body.get("sourceDepartment") or creator_dept).strip()[:120]

        asg_person = _task_resolve_person(people, req_asg) if req_asg else None
        if req_asg and not asg_person:
            return jsonify(error=f"Assignee '{req_asg}' was not found."), 400

        if work_mode == "personal":
            assignee_u = creator_u
            assignee_name = creator_name
            assignee_dept = creator_dept
            target_dept = ""
            source_dept = creator_dept
            acc_status = "self"
            status = "Pending"
        elif work_mode == "delegated":
            if not asg_person:
                return jsonify(error="Select a user to assign this task to."), 400
            assignee_u = asg_person["username"]
            assignee_name = asg_person["name"]
            assignee_dept = asg_person["dept"]
            if not target_dept:
                target_dept = assignee_dept
            if assignee_u.casefold() == creator_u_cf:
                acc_status = "self"
                status = "Pending"
            else:
                acc_status = "pending"
                status = "Awaiting Acceptance"
        elif work_mode == "department":
            if not target_dept:
                target_dept = creator_dept or (asg_person["dept"] if asg_person else "")
            if not target_dept:
                return jsonify(error="Select a department for this Team Work task."), 400
            assignee_u = asg_person["username"] if asg_person else ""
            assignee_name = asg_person["name"] if asg_person else ""
            assignee_dept = target_dept
            if assignee_u and assignee_u.casefold() == creator_u_cf:
                acc_status = "self"
                status = "Pending"
            else:
                acc_status = "pending"
                status = "Awaiting Acceptance"
        else:  # dept_to_dept
            if not target_dept:
                return jsonify(error="Select a target department for Department-to-Department handoff."), 400
            if not source_dept:
                source_dept = creator_dept or "Workspace"
            assignee_u = asg_person["username"] if asg_person else ""
            assignee_name = asg_person["name"] if asg_person else ""
            assignee_dept = target_dept
            acc_status = "pending"
            status = "Awaiting Acceptance"

        # Resolve optional watchers & shared departments
        watchers = []
        seen_w = set()
        for wu in (body.get("watcherUsernames") or []):
            wp = _task_resolve_person(people, wu)
            if wp and wp["username"].casefold() not in seen_w:
                seen_w.add(wp["username"].casefold())
                watchers.append({"username": wp["username"], "name": wp["name"], "dept": wp["dept"]})
        shared_depts = []
        seen_sd = set()
        for sd in (body.get("sharedDepartments") or []):
            s = str(sd or "").strip()[:120]
            if s and s.casefold() not in seen_sd:
                seen_sd.add(s.casefold())
                shared_depts.append(s)

        now_iso = _task_now_iso()
        task_id = "TSK-" + uuid.uuid4().hex[:8].upper()
        chain = []
        if acc_status == "pending":
            chain.append({
                "fromUsername": creator_u,
                "fromName": creator_name,
                "toUsername": assignee_u,
                "toName": assignee_name or (f"{target_dept} Dept" if target_dept else ""),
                "toDepartment": target_dept,
                "note": "Initial assignment",
                "at": now_iso,
            })

        task = {
            "id": task_id,
            "title": title,
            "description": description,
            "cadence": cadence,
            "workMode": work_mode,
            "priority": priority,
            "status": status,
            "acceptanceStatus": acc_status,
            "creatorUsername": creator_u,
            "creatorName": creator_name,
            "creatorDept": creator_dept,
            "creatorSite": creator_site,
            "assigneeUsername": assignee_u,
            "assigneeName": assignee_name,
            "assigneeDept": assignee_dept,
            "sourceDepartment": source_dept,
            "targetDepartment": target_dept,
            "watchers": watchers,
            "sharedDepartments": shared_depts,
            "involvedUsers": [],
            "delegationChain": chain,
            "dueAt": due_at,
            "committedDueAt": "",
            "acceptancePlan": "",
            "acceptedByUsername": "",
            "acceptedByName": "",
            "acceptedAt": "",
            "declineReason": "",
            "declinedByUsername": "",
            "declinedByName": "",
            "declinedAt": "",
            "reminderIntervalMins": rem_mins,
            "lastRemindedAt": "",
            "recurring": recurring,
            "parentTaskId": "",
            "spawnedNextId": "",
            "linkedTicketId": linked_ticket_id,
            "checklist": checklist,
            "attachments": [],
            "comments": [],
            "timeline": [],
            "completedAt": "",
            "completedByUsername": "",
            "completedByName": "",
            "completionNote": "",
            "createdAt": now_iso,
            "updatedAt": now_iso,
        }
        _task_rebuild_involved(task)
        target_desc = (
            f"{source_dept} → {target_dept} Dept" if work_mode == "dept_to_dept"
            else (f"{target_dept} Dept" + (f" ({assignee_name})" if assignee_name else "") if work_mode == "department"
                  else (assignee_name if assignee_u.casefold() != creator_u_cf else "Self"))
        )
        _task_add_timeline(task, "created", creator_u, creator_name, f"Created {cadence} task ({work_mode}) assigned to {target_desc}")
        doc["tasks"].insert(0, task)
        _save_tasks_doc(conn, doc)

        if acc_status == "pending" or watchers or shared_depts:
            _task_notify(
                conn, task,
                title=f"📋 New Task Assigned: {title}" if work_mode != "dept_to_dept" else f"🤝 Dept Handoff ({source_dept} → {target_dept}): {title}",
                body=f"{creator_name} assigned [{task_id}] ({cadence.capitalize()} · {priority}) to {target_desc}. Please accept with ETA & plan, decline, or reassign.",
                event_key=f"tsk-create:{task_id}",
                level="info",
                kind="task",
                exclude_username=creator_u_cf,
            )
        else:
            _pg_emit_notify(conn, "task", {"taskId": task_id, "action": "created"})

    return jsonify(ok=True, task=task), 201


@app.get("/api/tasks/<task_id>")
@signed_in
def get_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    with db() as conn:
        doc = _load_tasks_doc(conn)
    task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
    if not task:
        return jsonify(error="Task not found."), 404
    if not _task_visible_to(task, profile, is_adm):
        return jsonify(error="Access denied to this task."), 403
    return jsonify(ok=True, task=task)


@app.patch("/api/tasks/<task_id>")
@signed_in
def update_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]
    body = request.get_json(silent=True) or {}

    next_task = None
    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        old_status = str(task.get("status") or "Pending")
        changes = []
        if "title" in body:
            tval = str(body.get("title") or "").strip()[:200]
            if not tval:
                return jsonify(error="Task title cannot be empty."), 400
            if tval != task.get("title"):
                task["title"] = tval
                changes.append("title")
        if "description" in body:
            task["description"] = str(body.get("description") or "").strip()[:4000]
            changes.append("description")
        if "cadence" in body:
            cad = str(body.get("cadence") or "").strip().lower()
            if cad in _TASK_CADENCES:
                task["cadence"] = cad
                changes.append(f"cadence→{cad}")
        if "priority" in body:
            pr = str(body.get("priority") or "").strip()
            if pr in _TASK_PRIORITIES:
                task["priority"] = pr
                changes.append(f"priority→{pr}")
        if "dueAt" in body:
            task["dueAt"] = str(body.get("dueAt") or "").strip()[:40]
            changes.append("due date")
        if "committedDueAt" in body:
            task["committedDueAt"] = str(body.get("committedDueAt") or "").strip()[:40]
            changes.append("committed ETA")
        if "acceptancePlan" in body:
            task["acceptancePlan"] = str(body.get("acceptancePlan") or "").strip()[:2000]
        if "reminderIntervalMins" in body:
            try:
                task["reminderIntervalMins"] = max(0, min(10080, int(body.get("reminderIntervalMins") or 0)))
                changes.append("reminder schedule")
            except (TypeError, ValueError):
                pass
        if "recurring" in body:
            task["recurring"] = bool(body.get("recurring"))
        if "linkedTicketId" in body:
            task["linkedTicketId"] = str(body.get("linkedTicketId") or "").strip()[:80]
            changes.append("linked ticket")
        if "checklist" in body and isinstance(body.get("checklist"), list):
            task["checklist"] = _task_clean_checklist(body.get("checklist"))
            done_cnt = sum(1 for c in task["checklist"] if c.get("done"))
            changes.append(f"checklist ({done_cnt}/{len(task['checklist'])})")

        new_status = str(body.get("status") or "").strip()
        if new_status in ("Pending", "In progress", "Completed"):
            task["status"] = new_status
            if new_status == "Completed" and old_status != "Completed":
                task["completedAt"] = _task_now_iso()
                task["completedByUsername"] = uname
                task["completedByName"] = actor_name
                task["completionNote"] = str(body.get("completionNote") or "").strip()[:1000]
                if task.get("acceptanceStatus") == "pending":
                    task["acceptanceStatus"] = "accepted"
                changes.append("marked Completed")
            elif new_status != "Completed" and old_status == "Completed":
                task["completedAt"] = ""
                task["completedByUsername"] = ""
                task["completedByName"] = ""
                changes.append(f"reopened to {new_status}")
            elif new_status != old_status:
                changes.append(f"status→{new_status}")

        task["updatedAt"] = _task_now_iso()
        _task_rebuild_involved(task)
        if changes:
            _task_add_timeline(task, "updated", uname, actor_name, "Updated: " + ", ".join(changes))

        # Auto-spawn next cycle if recurring task was just completed
        if task.get("status") == "Completed" and old_status != "Completed" and task.get("recurring") and not task.get("spawnedNextId"):
            nxt_id = "TSK-" + uuid.uuid4().hex[:8].upper()
            now_iso = _task_now_iso()
            next_task = {
                **task,
                "id": nxt_id,
                "status": "Pending" if task.get("acceptanceStatus") == "self" else "Awaiting Acceptance",
                "acceptanceStatus": "self" if task.get("acceptanceStatus") == "self" else "pending",
                "dueAt": _task_next_due_iso(task.get("dueAt") or task.get("committedDueAt"), task.get("cadence", "daily")),
                "committedDueAt": "",
                "acceptancePlan": "",
                "acceptedByUsername": "",
                "acceptedByName": "",
                "acceptedAt": "",
                "declineReason": "",
                "declinedByUsername": "",
                "declinedByName": "",
                "declinedAt": "",
                "lastRemindedAt": "",
                "completedAt": "",
                "completedByUsername": "",
                "completedByName": "",
                "completionNote": "",
                "parentTaskId": task["id"],
                "spawnedNextId": "",
                "checklist": [{**c, "done": False} for c in (task.get("checklist") or [])],
                "attachments": [],
                "comments": [],
                "timeline": [],
                "createdAt": now_iso,
                "updatedAt": now_iso,
            }
            _task_add_timeline(next_task, "created", uname, actor_name, f"Auto-scheduled next {next_task['cadence']} cycle from {task['id']}")
            task["spawnedNextId"] = nxt_id
            doc["tasks"].insert(0, next_task)

        _save_tasks_doc(conn, doc)

        if task.get("status") == "Completed" and old_status != "Completed":
            _task_notify(
                conn, task,
                title=f"🎉 Task Completed: {task.get('title', '')}",
                body=f"{actor_name} completed [{task['id']}]." + (f" Note: {task.get('completionNote')}" if task.get("completionNote") else ""),
                event_key=f"tsk-done:{task['id']}:{uuid.uuid4().hex[:6]}",
                level="ok",
                kind="task",
                exclude_username=uname_cf,
            )
        elif changes:
            _task_notify(
                conn, task,
                title=f"✏️ Task Updated: {task.get('title', '')}",
                body=f"{actor_name} updated [{task['id']}] ({', '.join(changes)}).",
                event_key=f"tsk-upd:{task['id']}:{uuid.uuid4().hex[:6]}",
                level="info",
                kind="task",
                exclude_username=uname_cf,
            )

    return jsonify(ok=True, task=task, nextTask=next_task)


@app.delete("/api/tasks/<task_id>")
@signed_in
def delete_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname_cf = str(profile.get("username") or "").strip().casefold()
    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        idx = next((i for i, t in enumerate(doc["tasks"]) if str(t.get("id")) == str(task_id)), -1)
        if idx < 0:
            return jsonify(error="Task not found."), 404
        task = doc["tasks"][idx]
        if not is_adm and str(task.get("creatorUsername") or "").strip().casefold() != uname_cf:
            return jsonify(error="Only the task creator or an Administrator can delete this task."), 403
        for att in (task.get("attachments") or []):
            sname = Path(str(att.get("storedName") or "")).name
            if sname:
                try:
                    (TASK_UPLOAD_DIR / sname).unlink(missing_ok=True)
                except OSError:
                    pass
        doc["tasks"].pop(idx)
        _save_tasks_doc(conn, doc)
        _pg_emit_notify(conn, "task", {"taskId": task_id, "action": "deleted"})
    return jsonify(ok=True, deletedId=task_id)


@app.post("/api/tasks/<task_id>/accept")
@signed_in
def accept_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]
    actor_dept = str(profile.get("dept") or profile.get("department") or "").strip()[:120]
    body = request.get_json(silent=True) or {}

    committed_due = str(body.get("committedDueAt") or "").strip()[:40]
    plan = str(body.get("acceptancePlan") or "").strip()[:2000]
    if not committed_due:
        return jsonify(error="Please specify when this task will be completed (Planned Completion Date & Time)."), 400
    if len(plan) < 3:
        return jsonify(error="Please explain the action plan / how this task will be completed."), 400

    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        asg_cf = str(task.get("assigneeUsername") or "").strip().casefold()
        u_depts = _task_user_dept_set(profile)
        in_target_dept = bool(task.get("targetDepartment") and _dept_matches(u_depts, task.get("targetDepartment")))
        if not is_adm and asg_cf and asg_cf != uname_cf and not in_target_dept:
            return jsonify(error="Only the assigned user, target department member, or Administrator can accept this task."), 403

        now_iso = _task_now_iso()
        if not task.get("assigneeUsername"):
            task["assigneeUsername"] = uname
            task["assigneeName"] = actor_name
            if not task.get("assigneeDept"):
                task["assigneeDept"] = actor_dept or task.get("targetDepartment", "")
        task["acceptanceStatus"] = "accepted"
        task["status"] = "In progress"
        task["committedDueAt"] = committed_due
        task["acceptancePlan"] = plan
        task["acceptedByUsername"] = uname
        task["acceptedByName"] = actor_name
        task["acceptedAt"] = now_iso
        task["declineReason"] = ""
        task["updatedAt"] = now_iso
        _task_rebuild_involved(task)
        _task_add_timeline(task, "accepted", uname, actor_name, f"Accepted task · ETA: {committed_due} · Plan: {plan[:200]}")
        _save_tasks_doc(conn, doc)

        _task_notify(
            conn, task,
            title=f"✅ Task Accepted by {actor_name}: {task.get('title', '')}",
            body=f"[{task['id']}] Committed ETA: {committed_due} · Plan: {plan[:220]}",
            event_key=f"tsk-accept:{task['id']}:{uuid.uuid4().hex[:6]}",
            level="ok",
            kind="task",
            exclude_username=uname_cf,
        )
    return jsonify(ok=True, task=task)


@app.post("/api/tasks/<task_id>/decline")
@signed_in
def decline_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "").strip()[:1000]
    if len(reason) < 2:
        return jsonify(error="Please provide a reason for declining this task."), 400

    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        now_iso = _task_now_iso()
        task["acceptanceStatus"] = "declined"
        task["status"] = "Declined"
        task["declineReason"] = reason
        task["declinedByUsername"] = uname
        task["declinedByName"] = actor_name
        task["declinedAt"] = now_iso
        task["updatedAt"] = now_iso
        _task_rebuild_involved(task)
        _task_add_timeline(task, "declined", uname, actor_name, f"Declined task · Reason: {reason[:240]}")
        _save_tasks_doc(conn, doc)

        _task_notify(
            conn, task,
            title=f"❌ Task Declined by {actor_name}: {task.get('title', '')}",
            body=f"[{task['id']}] Reason: {reason[:260]}. You can reassign it to another person or department.",
            event_key=f"tsk-decline:{task['id']}:{uuid.uuid4().hex[:6]}",
            level="warn",
            kind="task",
            exclude_username=uname_cf,
        )
    return jsonify(ok=True, task=task)


@app.post("/api/tasks/<task_id>/reassign")
@signed_in
def reassign_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]
    body = request.get_json(silent=True) or {}
    to_user_raw = str(body.get("toUsername") or "").strip()
    to_dept = str(body.get("toDepartment") or "").strip()[:120]
    note = str(body.get("note") or "").strip()[:1000]
    if not to_user_raw and not to_dept:
        return jsonify(error="Select a new colleague or target department to reassign this task."), 400

    with db() as conn:
        people, _depts = _task_people_and_depts(conn)
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        target_person = _task_resolve_person(people, to_user_raw) if to_user_raw else None
        if to_user_raw and not target_person:
            return jsonify(error=f"User '{to_user_raw}' was not found."), 400

        prev_assignee_u = str(task.get("assigneeUsername") or "")
        new_u = target_person["username"] if target_person else ""
        new_name = target_person["name"] if target_person else ""
        new_dept = to_dept or (target_person["dept"] if target_person else task.get("targetDepartment", ""))

        now_iso = _task_now_iso()
        chain = list(task.get("delegationChain") or [])
        chain.append({
            "fromUsername": uname,
            "fromName": actor_name,
            "toUsername": new_u,
            "toName": new_name or (f"{new_dept} Dept" if new_dept else ""),
            "toDepartment": new_dept,
            "note": note or "Forwarded / Reassigned",
            "at": now_iso,
        })
        task["delegationChain"] = chain[-30:]
        task["assigneeUsername"] = new_u
        task["assigneeName"] = new_name
        task["assigneeDept"] = new_dept
        if to_dept:
            task["targetDepartment"] = to_dept
            if task.get("workMode") == "personal":
                task["workMode"] = "department"
        elif task.get("workMode") == "personal" and new_u.casefold() != uname_cf:
            task["workMode"] = "delegated"

        if new_u and new_u.casefold() == uname_cf:
            task["acceptanceStatus"] = "self"
            task["status"] = "Pending"
        else:
            task["acceptanceStatus"] = "pending"
            task["status"] = "Awaiting Acceptance"
        task["declineReason"] = ""
        task["updatedAt"] = now_iso
        # Keep previous assignee + actor + new assignee + creator in involvedUsers
        inv = list(task.get("involvedUsers") or [])
        for extra_u in (prev_assignee_u, uname, new_u):
            if extra_u:
                inv.append(extra_u)
        task["involvedUsers"] = inv
        _task_rebuild_involved(task)

        target_lbl = new_name + (f" ({new_dept})" if new_dept else "") if new_name else f"{new_dept} Dept"
        _task_add_timeline(task, "reassigned", uname, actor_name, f"Forwarded to {target_lbl}" + (f" · Note: {note[:200]}" if note else ""))
        _save_tasks_doc(conn, doc)

        _task_notify(
            conn, task,
            title=f"↪️ Task Forwarded to {target_lbl}: {task.get('title', '')}",
            body=f"{actor_name} reassigned [{task['id']}] to {target_lbl}." + (f" Note: {note[:200]}" if note else ""),
            event_key=f"tsk-reassign:{task['id']}:{uuid.uuid4().hex[:6]}",
            level="info",
            kind="task",
            exclude_username=uname_cf,
            extra_users=[prev_assignee_u, new_u],
            extra_depts=[new_dept] if new_dept else None,
        )
    return jsonify(ok=True, task=task)


@app.post("/api/tasks/<task_id>/share")
@signed_in
def share_workspace_task(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]
    body = request.get_json(silent=True) or {}
    raw_users = body.get("usernames") if isinstance(body.get("usernames"), list) else []
    raw_depts = body.get("departments") if isinstance(body.get("departments"), list) else []
    note = str(body.get("note") or "").strip()[:500]
    if not raw_users and not raw_depts:
        return jsonify(error="Choose at least one colleague or department to share with."), 400

    with db() as conn:
        people, _depts = _task_people_and_depts(conn)
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        watchers = list(task.get("watchers") or [])
        seen_w = {str(w.get("username") or "").casefold() for w in watchers if isinstance(w, dict)}
        added_names = []
        added_users = []
        for ru in raw_users:
            p = _task_resolve_person(people, ru)
            if p and p["username"].casefold() not in seen_w:
                seen_w.add(p["username"].casefold())
                watchers.append({"username": p["username"], "name": p["name"], "dept": p["dept"]})
                added_names.append(p["name"])
                added_users.append(p["username"])
        task["watchers"] = watchers

        shared_depts = list(task.get("sharedDepartments") or [])
        seen_sd = {str(d).casefold() for d in shared_depts}
        added_depts = []
        for rd in raw_depts:
            ds = str(rd or "").strip()[:120]
            if ds and ds.casefold() not in seen_sd:
                seen_sd.add(ds.casefold())
                shared_depts.append(ds)
                added_depts.append(ds)
                added_names.append(f"{ds} Dept")
        task["sharedDepartments"] = shared_depts
        task["updatedAt"] = _task_now_iso()
        _task_rebuild_involved(task)

        lbl = ", ".join(added_names) if added_names else "colleagues"
        _task_add_timeline(task, "shared", uname, actor_name, f"Shared task & attachments with {lbl}" + (f" · {note[:160]}" if note else ""))
        _save_tasks_doc(conn, doc)

        _task_notify(
            conn, task,
            title=f"📤 Task & Files Shared: {task.get('title', '')}",
            body=f"{actor_name} shared [{task['id']}] ({len(task.get('attachments') or [])} attachment(s)) with {lbl}." + (f" Note: {note[:180]}" if note else ""),
            event_key=f"tsk-share:{task['id']}:{uuid.uuid4().hex[:6]}",
            level="info",
            kind="task",
            exclude_username=uname_cf,
            extra_users=added_users,
            extra_depts=added_depts,
        )
    return jsonify(ok=True, task=task, addedNames=added_names)


@app.post("/api/tasks/<task_id>/comments")
@signed_in
def add_workspace_task_comment(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]
    body = request.get_json(silent=True) or {}
    text = str(body.get("text") or "").strip()[:2000]
    att_ids = [str(x)[:60] for x in (body.get("attachmentIds") or []) if str(x).strip()][:10]
    if not text and not att_ids:
        return jsonify(error="Enter a comment or attach a file."), 400

    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        comment = {
            "id": "cmt-" + uuid.uuid4().hex[:10],
            "authorUsername": uname,
            "authorName": actor_name,
            "text": text,
            "attachmentIds": att_ids,
            "createdAt": _task_now_iso(),
        }
        comments = list(task.get("comments") or [])
        comments.append(comment)
        task["comments"] = comments[-150:]
        task["updatedAt"] = _task_now_iso()
        _task_rebuild_involved(task)
        _task_add_timeline(task, "comment", uname, actor_name, f"Commented: {text[:180]}" if text else "Shared attachment in discussion")
        _save_tasks_doc(conn, doc)

        _task_notify(
            conn, task,
            title=f"💬 Comment on {task.get('title', '')}",
            body=f"{actor_name}: {text[:240]}" if text else f"{actor_name} shared a file on [{task['id']}].",
            event_key=f"tsk-cmt:{comment['id']}",
            level="info",
            kind="task",
            exclude_username=uname_cf,
        )
    return jsonify(ok=True, comment=comment, task=task), 201


@app.post("/api/tasks/<task_id>/attachments")
@signed_in
def upload_workspace_task_attachments(task_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname = str(profile.get("username") or "").strip()
    uname_cf = uname.casefold()
    actor_name = str(profile.get("name") or uname or "User").strip()[:120]

    files = request.files.getlist("files") + request.files.getlist("file")
    files = [f for f in files if f and getattr(f, "filename", "")]
    if not files:
        return jsonify(error="Choose or paste at least one file to upload."), 400

    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403

        existing = list(task.get("attachments") or [])
        if len(existing) + len(files) > _TASK_MAX_ATTACHMENTS:
            return jsonify(error=f"Maximum {_TASK_MAX_ATTACHMENTS} attachments allowed per task."), 400

        TASK_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        added = []
        for f in files[:10]:
            orig_name = Path(str(f.filename or "attachment")).name[:180]
            ext = Path(orig_name).suffix.lower()
            if not ext:
                guessed = mimetypes.guess_extension(str(f.mimetype or "")) or ".bin"
                ext = ".jpg" if guessed == ".jpe" else guessed
                orig_name = orig_name + ext
            if ext not in _TASK_ALLOWED_EXTS:
                return jsonify(error=f"File type '{ext}' is not supported."), 400
            raw_bytes = f.read(_TASK_MAX_FILE_BYTES + 1)
            if len(raw_bytes) > _TASK_MAX_FILE_BYTES:
                return jsonify(error=f"File '{orig_name}' exceeds 15 MB limit."), 400
            if not raw_bytes:
                continue
            att_id = "att-" + uuid.uuid4().hex[:10]
            safe_stem = secure_filename(Path(orig_name).stem)[:60] or "file"
            stored = f"{task_id}_{att_id}_{safe_stem}{ext}"
            (TASK_UPLOAD_DIR / stored).write_bytes(raw_bytes)
            mime = str(f.mimetype or mimetypes.guess_type(orig_name)[0] or "application/octet-stream")[:120]
            rec = {
                "id": att_id,
                "name": orig_name,
                "storedName": stored,
                "size": len(raw_bytes),
                "mime": mime,
                "url": f"/api/tasks/{task_id}/attachments/{att_id}",
                "uploadedBy": uname,
                "uploadedByName": actor_name,
                "uploadedAt": _task_now_iso(),
            }
            existing.append(rec)
            added.append(rec)

        if not added:
            return jsonify(error="Uploaded file was empty."), 400
        task["attachments"] = existing
        task["updatedAt"] = _task_now_iso()
        _task_rebuild_involved(task)
        _task_add_timeline(task, "attachment", uname, actor_name, f"Attached {len(added)} file(s): " + ", ".join(a["name"] for a in added[:3]))
        _save_tasks_doc(conn, doc)

        _task_notify(
            conn, task,
            title=f"📎 File Attached to {task.get('title', '')}",
            body=f"{actor_name} attached {', '.join(a['name'] for a in added[:3])} on [{task['id']}].",
            event_key=f"tsk-att:{added[0]['id']}",
            level="info",
            kind="task",
            exclude_username=uname_cf,
        )
    return jsonify(ok=True, attachments=added, task=task), 201


@app.get("/api/tasks/<task_id>/attachments/<att_id>")
@signed_in
def serve_workspace_task_attachment(task_id, att_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    with db() as conn:
        doc = _load_tasks_doc(conn)
    task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
    if not task:
        abort(404)
    if not _task_visible_to(task, profile, is_adm):
        abort(403)
    att = next((a for a in (task.get("attachments") or []) if str(a.get("id")) == str(att_id)), None)
    if not att:
        abort(404)
    clean_name = Path(str(att.get("storedName") or "")).name
    if not clean_name:
        abort(404)
    target = (TASK_UPLOAD_DIR / clean_name).resolve()
    if not target.is_relative_to(TASK_UPLOAD_DIR.resolve()) or not target.is_file():
        abort(404)
    as_dl = str(request.args.get("download") or "") in ("1", "true", "yes")
    return send_from_directory(str(TASK_UPLOAD_DIR), clean_name, as_attachment=as_dl, download_name=att.get("name") or clean_name)


@app.delete("/api/tasks/<task_id>/attachments/<att_id>")
@signed_in
def delete_workspace_task_attachment(task_id, att_id):
    profile = session.get("profile") or {}
    is_adm = bool(session.get("is_admin"))
    uname_cf = str(profile.get("username") or "").strip().casefold()
    with db() as conn:
        doc = _load_tasks_doc(conn, for_update=True)
        task = next((t for t in doc["tasks"] if str(t.get("id")) == str(task_id)), None)
        if not task:
            return jsonify(error="Task not found."), 404
        if not _task_visible_to(task, profile, is_adm):
            return jsonify(error="Access denied to this task."), 403
        atts = list(task.get("attachments") or [])
        idx = next((i for i, a in enumerate(atts) if str(a.get("id")) == str(att_id)), -1)
        if idx < 0:
            return jsonify(error="Attachment not found."), 404
        att = atts[idx]
        if not is_adm and uname_cf not in (str(att.get("uploadedBy") or "").casefold(), str(task.get("creatorUsername") or "").casefold()):
            return jsonify(error="Only the uploader, task creator, or Administrator can remove this attachment."), 403
        clean_name = Path(str(att.get("storedName") or "")).name
        if clean_name:
            try:
                (TASK_UPLOAD_DIR / clean_name).unlink(missing_ok=True)
            except OSError:
                pass
        atts.pop(idx)
        task["attachments"] = atts
        task["updatedAt"] = _task_now_iso()
        _save_tasks_doc(conn, doc)
    return jsonify(ok=True, task=task)


@app.route("/api/tasks/reminders/check", methods=["GET", "POST"])
@signed_in
def check_workspace_task_reminders():
    profile = session.get("profile") or {}
    uname_cf = str(profile.get("username") or "").strip().casefold()
    body = request.get_json(silent=True) or {}
    force_id = str(body.get("forceTaskId") or "").strip() if session.get("is_admin") else ""
    with db() as conn:
        mine, total = _evaluate_task_reminders(conn, caller_username_cf=uname_cf, force_task_id=force_id or None)
    return jsonify(ok=True, reminders=mine, firedCount=len(total), serverNow=_task_now_iso())


init_db()
_start_returnable_scheduler()
