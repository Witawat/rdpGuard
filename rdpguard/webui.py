"""Web UI + REST API (stdlib ล้วน, single page ภาษาไทย).

- เปิดเฉพาะ 127.0.0.1 (ค่าเริ่มต้น) — ระวังถ้าตั้งเป็น 0.0.0.0 ต้องตั้ง password
- ต้องล็อกอินด้วยรหัสจาก config (webui.password) — cookie session ง่าย ๆ
- กันการเดารหัสหน้า login: พลาด 5 ครั้ง ล็อก 5 นาที
- UI ฝั่ง static อยู่ในโฟลเดอร์ web/ (index.html, app.js, style.css)
"""

import ipaddress
import csv
import io
import json
import logging
import mimetypes
import os
import secrets
import sqlite3
import tempfile
import zipfile
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from . import config as config_mod

log = logging.getLogger("RDPGuard.webui")

_WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

_LOGIN_MAX_FAILS = 5
_LOGIN_LOCK_SECONDS = 300
_LOGIN_MAX_ENTRIES = 1000  # กัน DoS ด้วย IP ปลอมจำนวนมาก
_login_guard = {}  # ip -> {"fails": int, "locked_until": float} — per-IP (ไม่ล็อกทั้งระบบ)
_login_lock = threading.Lock()  # กัน read-modify-write ชนเมื่อโจมตี login พร้อมกันหลาย connection

_SESSION_MAX_AGE = 24 * 3600
_sessions = {}  # token -> expires (epoch)
_session_lock = threading.Lock()  # ThreadingHTTPServer เรียก handler หลาย thread พร้อมกัน


def _new_session():
    with _session_lock:
        _cleanup_sessions()
        token = secrets.token_urlsafe(32)
        _sessions[token] = time.time() + _SESSION_MAX_AGE
    return token


def _cleanup_sessions():
    now = time.time()
    for token in [t for t, exp in _sessions.items() if exp <= now]:
        _sessions.pop(token, None)


def _invalidate_all_sessions():
    with _session_lock:
        _sessions.clear()


_monitor = None
_cfg_lock = threading.Lock()

_SECRET_KEYS = {
    ("webui", "password"),
    ("notify", "telegram_bot_token"),
    ("notify", "telegram_chat_id"),
    ("notify", "smtp_password"),
    ("notify", "webhook_url"),
}

_BOOL_KEYS = {
    "enable", "auto_extend", "skip_local_ips", "escalate_to_permanent", "single_rule",
    "telegram_verify_ssl", "webhook_enable", "webhook_verify_ssl", "enable_commands",
}

_INT_RANGES = {
    ("general", "log_max_mb"): (1, 1024),
    ("general", "log_backups"): (0, 100),
    ("general", "event_retention_days"): (0, 3650),
    ("general", "history_retention_days"): (0, 3650),
    ("general", "audit_retention_days"): (0, 3650),
    ("monitor", "poll_interval_seconds"): (1, 3600),
    ("detection", "max_attempts"): (1, 100000),
    ("detection", "window_minutes"): (1, 100000),
    ("detection", "block_hours"): (0, 87600),
    ("detection", "active_session_grace_minutes"): (0, 100000),
    ("detection", "escalate_after_blocks"): (0, 100000),
    ("detection", "escalate_block_hours"): (0, 87600),
    ("detection", "escalation_window_days"): (1, 3650),
    ("detection", "accumulate_window_hours"): (0, 87600),
    ("detection", "accumulate_threshold"): (0, 100000),
    ("detection", "accumulate_block_hours"): (0, 87600),
    ("webui", "port"): (1, 65535),
    ("notify", "smtp_port"): (1, 65535),
    ("notify", "cooldown_seconds"): (0, 86400),
    ("notify", "confirm_timeout_seconds"): (5, 3600),
    ("notify", "rate_limit_per_minute"): (1, 600),
    ("notify", "poll_retry_min_seconds"): (1, 3600),
    ("notify", "poll_retry_max_seconds"): (1, 3600),
}


def _validate_setting(section, key, value):
    """ตรวจค่า config ก่อนเขียน เพื่อไม่ให้ค่าผิดทำให้ระบบ fallback เงียบ ๆ"""
    value = str(value).strip()
    if (section, key) in _SECRET_KEYS and value == "__CLEAR__":
        if (section, key) == ("webui", "password"):
            return "ห้ามล้างรหัสผ่าน Web UI — ตั้งรหัสใหม่แทน"
        return None
    if key in _BOOL_KEYS:
        if value.lower() not in ("true", "false"):
            return f"{section}.{key} ต้องเป็น true หรือ false"
    if (section, key) in _INT_RANGES:
        try:
            number = int(value)
        except ValueError:
            return f"{section}.{key} ต้องเป็นจำนวนเต็ม"
        low, high = _INT_RANGES[(section, key)]
        if number < low or number > high:
            return f"{section}.{key} ต้องอยู่ระหว่าง {low} ถึง {high}"
    if section == "firewall" and key == "profile" and value not in ("any", "domain", "private", "public"):
        return "firewall.profile ไม่ถูกต้อง"
    if section == "general" and key == "log_level" and value.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        return "general.log_level ไม่ถูกต้อง"
    if section == "notify" and key == "channel" and value.lower() not in ("both", "telegram", "email"):
        return "notify.channel ไม่ถูกต้อง"
    if section == "webui" and key == "password" and value and len(value) < 8:
        return "รหัสผ่าน Web UI ต้องยาวอย่างน้อย 8 ตัวอักษร"
    if section == "notify" and key == "webhook_url" and value and not value.lower().startswith(("http://", "https://")):
        return "notify.webhook_url ต้องขึ้นต้นด้วย http:// หรือ https://"
    if section == "notify" and key == "hostname" and value:
        import re as _re

        if not _re.fullmatch(r"[A-Za-z0-9_-]+", value):
            return "ชื่อเครื่องห้ามมีช่องว่างหรือ @ — ใช้ตัวอักษร ตัวเลข - หรือ _"
    return None


def _is_admin():
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _in_service():
    return os.environ.get("RDPGUARD_RUNNING_AS_SERVICE") == "1"


def _context_label():
    if _in_service():
        return "service"
    if _is_admin():
        return "standalone-admin"
    return "standalone"


def _setup_done():
    cfg = config_mod.load_config()
    return config_mod.get_bool(cfg, "general", "setup_done", False)


def _valid_ip_or_cidr(value):
    value = (value or "").strip()
    if not value:
        return False
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _json_error(handler, message, status=400):
    body = json.dumps({"ok": False, "error": message}, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _json_ok(handler, data=None, status=200, headers=None):
    body = json.dumps({"ok": True, "data": data or {}}, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)


def _fw_com_ok():
    """ตรวจว่า COM Windows Firewall เข้าถึงได้ไหม (enum สองสาม rule แรก)"""
    try:
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        try:
            fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
            count = 0
            for _rule in fw.Rules:
                count += 1
                if count >= 5:
                    break
            return True
        finally:
            pythoncom.CoUninitialize()
    except Exception:
        return False


def _health_data():
    from . import engines as engines_mod

    cfg = config_mod.load_config()
    try:
        eventlog_ok = engines_mod.channel_ok("Security")
    except Exception:
        eventlog_ok = False
    admin = _is_admin()
    service_ctx = _in_service()
    return {
        "is_admin": admin,
        "in_service": service_ctx,
        "can_add_rules": admin or service_ctx,
        "eventlog_ok": eventlog_ok,
        "firewall_com_ok": _fw_com_ok(),
        "engines": engines_mod.source_status(cfg),
        "monitor_running": bool(_monitor and _monitor.running),
    }


def _parse_qwinsta(out):
    """parse ผลลัพธ์ qwinsta/query session -> [{kind, user, id, state, start}]"""
    sessions = []
    for line in out.splitlines()[1:]:
        line = line.rstrip()
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0].lstrip(">")
        id_idx = None
        for i, p in enumerate(parts):
            if p.isdigit():
                id_idx = i
                break
        if id_idx is None:
            continue
        user = parts[1] if id_idx == 2 else (parts[1] if id_idx == 3 else "")
        sid = parts[id_idx]
        state = parts[id_idx + 1] if id_idx + 1 < len(parts) else ""
        stype = parts[id_idx + 2] if id_idx + 2 < len(parts) else ""
        kind = "rdp" if stype == "RDP-Tcp" else ("console" if name == "console" else "system" if name == "services" else (stype or name))
        sessions.append(
            {"kind": kind, "user": user, "id": sid, "state": state, "start": ""}
        )
    return sessions


# หมายเหตุ: เดิมมี fallback อ่าน session ผ่าน PowerShell CIM (Win32_LogonSession) —
# ถูกลบออกเพราะ Norton Behavioral Protection ฟลาก powershell.exe + embedded script
# (IDP.HELU.PSE...) — ตอนนี้ใช้ WTS API (win32ts) ตรง ๆ ซึ่งเป็น DLL call ใน process
# ตัวเอง ไม่มีการ spawn process ภายนอก


def _wts_sessions():
    """อ่าน session ผ่าน WTS API (win32ts) — ไม่ spawn process ภายนอก
    รองรับเครื่องที่ไม่มี qwinsta/query session (Win11 บางรุ่น)"""
    try:
        import win32ts
    except Exception:
        return []
    sessions = []
    try:
        for s in win32ts.WTSEnumerateSessions():
            try:
                if isinstance(s, dict):
                    sid = s["SessionId"]
                    name = s["WinStationName"]
                    state = s["State"]
                else:
                    sid = s.SessionId
                    name = s.WinStationName
                    state = s.State
                handle = win32ts.WTS_CURRENT_SERVER_HANDLE
                proto = win32ts.WTSQuerySessionInformation(handle, sid, win32ts.WTSClientProtocolType)
                user = win32ts.WTSQuerySessionInformation(handle, sid, win32ts.WTSUserName)
                if isinstance(user, bytes):
                    user = user.decode("utf-8", "ignore")
            except Exception:
                continue
            name_l = (name or "").lower()
            kind = (
                "rdp"
                if proto == win32ts.WTS_PROTOCOL_TYPE_RDP
                else "console"
                if name_l == "console"
                else "system"
                if name_l == "services"
                else (name_l or "session")
            )
            state_label = {
                win32ts.WTSActive: "Active",
                win32ts.WTSConnected: "Conn",
                win32ts.WTSDisconnected: "Disc",
                win32ts.WTSIdle: "Idle",
                win32ts.WTSListen: "Listen",
            }.get(state, str(state))
            sessions.append(
                {
                    "kind": kind,
                    "user": str(user or ""),
                    "id": str(sid),
                    "state": state_label,
                    "start": "",
                }
            )
    except Exception:
        log.debug("WTS อ่าน session ไม่ได้", exc_info=True)
    return sessions
class RDPGuardHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer ที่เงียบต่อการตัดการเชื่อมต่อจาก client (F5/ปิดแท็บ)"""

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, ConnectionError) or isinstance(exc, BrokenPipeError):
            log.debug("client ตัดการเชื่อมต่อ: %s (%s)", client_address, exc)
            return
        super().handle_error(request, client_address)


class RDPGuardHandler(BaseHTTPRequestHandler):
    server_version = f"RDPGuard/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.debug("http %s %s", self.address_string(), fmt % args)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, ConnectionError) or isinstance(exc, BrokenPipeError):
            log.debug("client ตัดการเชื่อมต่อ: %s (%s)", client_address, exc)
            return
        super().handle_error(request, client_address)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            return {}
        if length > 1024 * 1024:
            log.warning("body ใหญ่เกินกำหนด (%d bytes) — ปฏิเสธ", length)
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _check_origin(self):
        """กัน CSRF: ถ้ามี Origin/Referer ต้องตรงกับ Host (browser ส่งมาเสมอ;
        curl/CLI ไม่มี Origin → อนุญาต)"""
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        if not host:
            return False
        try:
            parsed = urllib.parse.urlparse(origin)
            return parsed.netloc == host
        except Exception:
            return False

    def _cookie_value(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1 :]
        return None

    def _authorized(self):
        token = self._cookie_value("rdpguard_session") or ""
        if not token:
            return False
        with _session_lock:
            expires = _sessions.get(token)
            if not expires or expires <= time.time():
                _sessions.pop(token, None)
                return False
            # sliding: ต่ออายุเมื่อเหลือน้อยกว่าครึ่งของ TTL (ไม่ touch ทุก request)
            if expires - time.time() < _SESSION_MAX_AGE / 2:
                _sessions[token] = time.time() + _SESSION_MAX_AGE
            return True

    def _require_auth(self):
        if not self._authorized():
            _json_error(self, "กรุณาล็อกอินก่อน", status=401)
            return False
        return True

    def _actor(self):
        return self.client_address[0] if self.client_address else "?"

    def _audit(self, action, target="", result="ok", detail=""):
        if not _monitor:
            return
        try:
            _monitor.db.add_audit(self._actor(), action, target, result, detail)
        except Exception:
            log.debug("บันทึก audit ไม่สำเร็จ", exc_info=True)

    def _send_static(self, rel_path):
        path = os.path.normpath(os.path.join(_WEB_DIR, rel_path))
        if not path.startswith(_WEB_DIR) or not os.path.isfile(path):
            _json_error(self, "not found", status=404)
            return
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- route ----

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send_static("index.html")
        elif path == "/app.js":
            self._send_static("app.js")
        elif path == "/style.css":
            self._send_static("style.css")
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        elif path == "/api/login-status":
            _json_ok(self, {"authorized": self._authorized(), "context": _context_label()})
        elif path == "/api/setup-status":
            _json_ok(self, {"setup_done": _setup_done()})
        elif path == "/api/service":
            self._handle_service_status()
        elif path == "/api/detection-state":
            self._handle_detection_state()
        elif path == "/api/log":
            self._handle_log(query)
        elif path == "/api/log/files":
            self._handle_log_files()
        elif path == "/api/log/download":
            self._handle_log_download(query)
        elif path == "/api/sessions":
            self._handle_sessions()
        elif path == "/api/overview":
            self._handle_overview()
        elif path == "/api/trends":
            self._handle_trends(query)
        elif path == "/api/events":
            self._handle_events(query)
        elif path == "/api/events/export":
            self._handle_events_export(query)
        elif path == "/api/blocked":
            self._handle_list_blocked()
        elif path == "/api/blocked/export":
            self._handle_blocked_export(query)
        elif path == "/api/whitelist":
            self._handle_list_whitelist()
        elif path == "/api/blacklist":
            self._handle_list_blacklist()
        elif path == "/api/settings":
            self._handle_get_settings()
        elif path == "/api/blocked-history":
            self._handle_blocked_history(query)
        elif path == "/api/blocked-history/export":
            self._handle_blocked_history_export(query)
        elif path == "/api/audit":
            self._handle_audit(query)
        elif path == "/api/audit/export":
            self._handle_audit_export(query)
        elif path == "/api/notify/status":
            self._handle_notify_status()
        elif path == "/api/telegram/status":
            self._handle_telegram_status()
        elif path == "/api/backup":
            self._handle_backup()
        else:
            _json_error(self, "ไม่พบเส้นทาง", status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if not self._check_origin():
            _json_error(self, "Origin ไม่ตรงกับ Host — ปฏิเสธ (กัน CSRF)", status=403)
            return
        if path == "/api/backup/restore":
            if self._require_auth():
                self._handle_restore()
            return
        body = self._read_body()
        if path == "/api/login":
            self._handle_login(body)
        elif path == "/api/logout":
            self._handle_logout()
        elif path == "/api/blocked":
            if self._require_auth():
                self._handle_block(body)
        elif path == "/api/blocked/bulk-unblock":
            if self._require_auth():
                self._handle_bulk_unblock(body)
        elif path == "/api/whitelist":
            if self._require_auth():
                self._handle_add_whitelist(body)
        elif path == "/api/blacklist":
            if self._require_auth():
                self._handle_add_blacklist(body)
        elif path == "/api/settings":
            if self._require_auth():
                self._handle_save_settings(body)
        elif path == "/api/setup/complete":
            if self._require_auth():
                self._handle_setup_complete()
        elif path == "/api/service/action":
            if self._require_auth():
                self._handle_service_action(body)
        elif path == "/api/toggle":
            if self._require_auth():
                self._handle_toggle(body)
        elif path == "/api/geoip":
            if self._require_auth():
                self._handle_geoip(body)
        elif path == "/api/health/test-firewall":
            if self._require_auth():
                self._handle_test_firewall()
        elif path == "/api/unblock-all":
            if self._require_auth():
                self._handle_unblock_all()
        elif path == "/api/self-test":
            if self._require_auth():
                self._handle_self_test()
        elif path == "/api/notify/test":
            if self._require_auth():
                self._handle_notify_test()
        elif path == "/api/backup":
            if self._require_auth():
                self._handle_backup()
        else:
            _json_error(self, "ไม่พบเส้นทาง", status=404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if not self._require_auth():
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "blocked":
            self._handle_unblock(urllib.parse.unquote(parts[2]))
        elif len(parts) == 3 and parts[0] == "api" and parts[1] == "whitelist":
            self._handle_remove_whitelist(urllib.parse.unquote(parts[2]))
        elif len(parts) == 3 and parts[0] == "api" and parts[1] == "blacklist":
            self._handle_remove_blacklist(urllib.parse.unquote(parts[2]))
        else:
            _json_error(self, "ไม่พบเส้นทาง", status=404)

    # ---- handlers ----

    def _handle_login(self, body):
        now = time.time()
        ip = self.client_address[0] if self.client_address else "?"
        with _login_lock:
            # ล้าง entry ที่หมดล็อกแล้ว ถ้าโตเกิน cap (กัน IP ปลอมเยอะ ๆ)
            if len(_login_guard) > _LOGIN_MAX_ENTRIES:
                for k in [k for k, v in _login_guard.items() if v["locked_until"] <= now]:
                    _login_guard.pop(k, None)
            entry = _login_guard.setdefault(ip, {"fails": 0, "locked_until": 0.0})
            if entry["locked_until"] > now:
                left = int(entry["locked_until"] - now)
                _json_error(self, f"พยายามมากเกินไป — รอ {left} วินาที", status=429)
                return
        cfg = config_mod.load_config()
        expected = config_mod.get(cfg, "webui", "password", "")
        given = str(body.get("password", ""))
        if expected and secrets.compare_digest(given, expected):
            token = _new_session()
            with _login_lock:
                entry = _login_guard.setdefault(ip, {"fails": 0, "locked_until": 0.0})
                entry["fails"] = 0
            self._audit("login", "webui", "ok")
            _json_ok(
                self,
                {"token": token},
                headers={
                    "Set-Cookie": (
                        f"rdpguard_session={token}; Path=/; Max-Age={_SESSION_MAX_AGE}; "
                        "HttpOnly; SameSite=Lax"
                    )
                },
            )
            return
        with _login_lock:
            entry = _login_guard.setdefault(ip, {"fails": 0, "locked_until": 0.0})
            entry["fails"] += 1
            if entry["fails"] >= _LOGIN_MAX_FAILS:
                entry["locked_until"] = now + _LOGIN_LOCK_SECONDS
                entry["fails"] = 0
                self._audit("login", "webui", "locked", "ครบจำนวนครั้งที่กำหนด")
                _json_error(self, "รหัสผิด 5 ครั้ง — ล็อกการพยายาม 5 นาที (เฉพาะ IP นี้)", status=429)
                return
        self._audit("login", "webui", "fail")
        _json_error(self, "รหัสไม่ถูกต้อง", status=401)

    def _handle_logout(self):
        token = self._cookie_value("rdpguard_session") or ""
        if token:
            with _session_lock:
                _sessions.pop(token, None)
        self._audit("logout", "webui")
        _json_ok(
            self,
            {"message": "ออกจากระบบแล้ว"},
            headers={
                "Set-Cookie": (
                    "rdpguard_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
                )
            },
        )

    def _handle_sessions(self):
        """Session ที่ใช้งานอยู่ — ดูว่าใคร remote เข้ามา (qwinsta -> query session -> WTS API)
        หมายเหตุ: ไม่ใช้ PowerShell (กัน Norton ฟลาก powershell.exe) — WTS เป็น DLL call ใน process"""
        if not self._require_auth():
            return
        import subprocess

        out = ""
        for cmd in (
            [r"C:\Windows\System32\qwinsta.exe"],
            ["qwinsta"],
            [r"C:\Windows\System32\query.exe", "session"],
        ):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                out = result.stdout or ""
            except Exception as exc:
                log.debug("session cmd %s ล้มเหลว: %s", cmd, exc)
            if out.strip():
                break
        sessions = _parse_qwinsta(out) if out.strip() else _wts_sessions()
        _json_ok(self, {"sessions": sessions})

    def _handle_overview(self):
        if not self._require_auth():
            return
        stats = _monitor.db.stats() if _monitor else {}
        cfg = config_mod.load_config()
        data = {
            "version": __version__,
            "context": _context_label(),
            "monitor_running": bool(_monitor and _monitor.running),
            "stats": stats,
            "health": _health_data(),
            "database": {
                "size": _monitor.db.file_size() if _monitor else 0,
            },
            "settings_summary": {
                "max_attempts": config_mod.get_int(cfg, "detection", "max_attempts", 5),
                "window_minutes": config_mod.get_int(cfg, "detection", "window_minutes", 10),
                "block_hours": config_mod.get_int(cfg, "detection", "block_hours", 24),
                "enable": config_mod.get_bool(cfg, "monitor", "enable", True),
            },
        }
        _json_ok(self, data)

    def _handle_trends(self, query):
        if not self._require_auth():
            return
        try:
            days = max(1, min(int(query.get("days", ["7"])[0]), 31))
        except ValueError:
            days = 7
        _json_ok(self, {"days": _monitor.db.daily_trends(days) if _monitor else []})

    def _handle_notify_test(self):
        """ส่งข้อความทดสอบผ่านช่องทางแจ้งเตือนที่ตั้งค่าไว้"""
        if _monitor and _monitor.notifier:
            notifier = _monitor.notifier
        else:
            from .notify import Notifier

            notifier = Notifier(config_mod.load_config(), start_worker=False)
        results = notifier.test()
        self._audit("notify-test", "notification", "ok", str(results)[:500])
        _json_ok(self, {"message": "ผลทดสอบแจ้งเตือน", "results": results})

    def _handle_notify_status(self):
        if not self._require_auth():
            return
        if _monitor and _monitor.notifier:
            status = _monitor.notifier.status()
        else:
            from .notify import Notifier

            status = Notifier(config_mod.load_config(), start_worker=False).status()
        _json_ok(self, status)

    def _handle_telegram_status(self):
        if not self._require_auth():
            return
        if _monitor and _monitor.tg:
            status = _monitor.tg.status()
        else:
            from .tgcmd import TelegramCommandBot

            status = TelegramCommandBot(None).status()
        _json_ok(self, status)

    def _handle_unblock_all(self):
        """ฉุกเฉิน: ปลดบล็อกทุก IP (ลบ rule firewall ทั้งหมดของ RDPGuard)"""
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        message = _monitor.unblock_all()
        self._audit("unblock-all", "all", "ok", message)
        _json_ok(self, {"message": message})

    def _handle_self_test(self):
        """Self-test ครบวงจร: เขียน event จำลอง (18456) ลง Application log จริง →
        engine อ่าน → detector บล็อก IP จำลอง → ตรวจ rule firewall → ปลดบล็อก + ทำความสะอาด"""
        import time

        import win32evtlog

        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        if not (_is_admin() or _in_service()):
            _json_error(
                self,
                "self-test ต้องรันด้วยสิทธิ์ admin (หรือ service) — เปิดโปรแกรมด้วย Run as administrator",
                status=403,
            )
            return
        cfg = config_mod.load_config()
        if not config_mod.get_bool(cfg, "monitor", "enable", True):
            _json_error(self, "การเฝ้าระวังถูกปิดอยู่ — เปิดก่อน (สวิตช์ในหน้า การตรวจจับ)")
            return
        if not config_mod.get_bool(cfg, "engines", "mssql", True):
            _json_error(self, "engine MSSQL ถูกปิดอยู่ — self-test ใช้ engine นี้ (เปิดในหน้า การตรวจจับ)")
            return

        max_attempts = config_mod.get_int(cfg, "detection", "max_attempts", 5)
        override = config_mod.get(cfg, "engines", "mssql_max_attempts", "").strip()
        if override:
            try:
                max_attempts = int(override)
            except ValueError:
                pass
        if max_attempts > 50:
            _json_error(self, f"max_attempts ({max_attempts}) สูงเกินไปสำหรับ self-test (ตั้ง ≤50 ก่อน)")
            return

        test_ip = "8.8.8.8"  # public IP ปลอดภัยสำหรับทดสอบ (rule เพิ่ม-ลบภายในไม่กี่วินาที)
        steps = []

        try:
            handle = win32evtlog.RegisterEventSource(None, "Application")
            try:
                for i in range(max_attempts):
                    msg = (
                        f"RDPGuard selftest {i}: Login failed for user 'selftest'. "
                        f"Reason: selftest. [CLIENT: {test_ip}]"
                    )
                    win32evtlog.ReportEvent(
                        handle,
                        win32evtlog.EVENTLOG_INFORMATION_TYPE,
                        0,
                        18456,
                        None,
                        [msg],
                        None,
                    )
            finally:
                win32evtlog.DeregisterEventSource(handle)
            steps.append(f"เขียน event จำลอง {max_attempts} รายการ (Event 18456) ลง Application log — OK")
        except Exception as exc:
            _json_error(self, f"เขียน event log ไม่สำเร็จ: {exc}")
            return

        blocked = False
        deadline = time.time() + 25
        while time.time() < deadline:
            if _monitor.db.is_blocked(test_ip):
                blocked = True
                break
            time.sleep(1)
        if not blocked:
            _monitor.db.delete_events_by_user("selftest")
            steps.append("เครื่องตรวจจับไม่เห็น/ไม่บล็อก IP จำลองภายใน 25 วิ — FAIL")
            _json_ok(
                self,
                {
                    "working": False,
                    "steps": steps,
                    "message": "self-test ล้มเหลว: engine ไม่บล็อก IP จำลอง (ดู log)",
                },
            )
            return
        steps.append(f"engine MSSQL อ่าน event → detector บล็อก {test_ip} อัตโนมัติ — OK")

        rule_ok = _monitor.fw.rule_exists(test_ip)
        steps.append(
            f"ตรวจ rule \"RDPGuard Block {test_ip}\" ใน Windows Firewall — "
            + ("OK" if rule_ok else "FAIL (rule ไม่เจอ)")
        )

        ok_unblock, msg_unblock = _monitor.manual_unblock(test_ip)
        _monitor.db.delete_events_by_user("selftest")
        _monitor.db.accumulate_reset(test_ip)
        steps.append(f"ปลดบล็อก + ลบ event ทดสอบ — {'OK' if ok_unblock else 'FAIL'}")

        working = rule_ok and ok_unblock
        _json_ok(
            self,
            {
                "working": working,
                "steps": steps,
                "message": (
                    "✅ self-test ผ่านครบวงจร: event log → ตรวจจับ → บล็อก → rule firewall → ปลดบล็อก ทำงานได้จริง"
                    if working
                    else "self-test มีบางขั้น FAIL (ดูขั้นตอน)"
                ),
            },
        )

    def _handle_test_firewall(self):
        """ทดสอบบล็อกจริง: เพิ่ม rule ทดสอบ (TEST-NET 203.0.113.254) แล้วลบทิ้งทันที"""
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        test_ip = "203.0.113.254"
        try:
            ok_add = _monitor.fw.add_block(test_ip)
            ok_remove = _monitor.fw.remove_block(test_ip)
        except Exception as exc:
            _json_ok(self, {"working": False, "message": f"ทดสอบล้มเหลว: {exc}"})
            return
        if ok_add and ok_remove:
            self._audit("firewall-test", test_ip, "ok", "เพิ่มและลบ rule ทดสอบ")
            _json_ok(
                self,
                {
                    "working": True,
                    "message": "Firewall ทำงานได้จริง — เพิ่ม + ลบ rule ทดสอบ (203.0.113.254) สำเร็จ",
                },
            )
        else:
            self._audit("firewall-test", test_ip, "fail", "เพิ่มหรือลบ rule ไม่สำเร็จ")
            _json_ok(
                self,
                {
                    "working": False,
                    "message": (
                        f"Firewall ยังใช้ไม่ได้ (add={'OK' if ok_add else 'FAIL'}, "
                        f"remove={'OK' if ok_remove else 'FAIL'}) — "
                        "ต้องรันด้วย admin; service รันเป็น SYSTEM จะทำได้"
                    ),
                },
            )

    def _handle_events(self, query):
        if not self._require_auth():
            return
        try:
            limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
        except ValueError:
            limit = 100
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
        except ValueError:
            offset = 0
        if not _monitor:
            _json_ok(self, {"events": [], "total": 0, "limit": limit, "offset": offset})
            return
        rows, total = _monitor.db.query_events(
            q=str(query.get("q", [""])[0])[:100].strip(),
            ip=str(query.get("ip", [""])[0])[:64].strip(),
            source=str(query.get("source", [""])[0])[:32].strip(),
            kind=str(query.get("kind", [""])[0])[:16].strip(),
            since=str(query.get("since", [""])[0])[:32].strip(),
            until=str(query.get("until", [""])[0])[:32].strip(),
            limit=limit,
            offset=offset,
        )
        _json_ok(self, {"events": rows, "total": total, "limit": limit, "offset": offset})

    @staticmethod
    def _csv_value(value):
        text = str(value if value is not None else "")
        if text.startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    def _send_csv(self, filename, headers, rows):
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([self._csv_value(value) for value in row])
        body = ("\ufeff" + output.getvalue()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_events_export(self, query):
        if not self._require_auth():
            return
        if not _monitor:
            self._send_csv("rdpguard-events.csv", ["เวลา", "ประเภท", "IP", "ผู้ใช้", "โดเมน", "LogonType", "แหล่ง"], [])
            return
        filters = {
            "q": str(query.get("q", [""])[0])[:100].strip(),
            "ip": str(query.get("ip", [""])[0])[:64].strip(),
            "source": str(query.get("source", [""])[0])[:32].strip(),
            "kind": str(query.get("kind", [""])[0])[:16].strip(),
            "since": str(query.get("since", [""])[0])[:32].strip(),
            "until": str(query.get("until", [""])[0])[:32].strip(),
        }
        rows = []
        offset = 0
        while len(rows) < 100000:
            page, total = _monitor.db.query_events(**filters, limit=500, offset=offset)
            rows.extend(page)
            offset += len(page)
            if not page or offset >= total:
                break
        self._send_csv(
            "rdpguard-events.csv",
            ["เวลา", "ประเภท", "IP", "ผู้ใช้", "โดเมน", "LogonType", "แหล่ง"],
            [(r.get("ts"), r.get("kind"), r.get("ip"), r.get("user"), r.get("domain"), r.get("logon_type"), r.get("source")) for r in rows[:100000]],
        )

    def _handle_blocked_export(self, query):
        if not self._require_auth():
            return
        rows = []
        if _monitor:
            q = str(query.get("q", [""])[0])[:100].strip()
            source = str(query.get("source", [""])[0])[:32].strip()
            offset = 0
            while len(rows) < 100000:
                page, total = _monitor.db.query_blocked(q=q, source=source, limit=500, offset=offset)
                rows.extend(page)
                offset += len(page)
                if not page or offset >= total:
                    break
        self._send_csv(
            "rdpguard-blocked.csv",
            ["IP", "เหตุผล", "ที่มา", "สร้างเมื่อ", "หมดอายุ", "Rule"],
            [(r.get("ip"), r.get("reason"), r.get("source"), r.get("created"), r.get("expires"), r.get("rule_name")) for r in rows[:100000]],
        )

    def _handle_audit_export(self, query):
        if not self._require_auth():
            return
        rows = []
        if _monitor:
            q = str(query.get("q", [""])[0])[:100].strip()
            action = str(query.get("action", [""])[0])[:32].strip()
            offset = 0
            while len(rows) < 100000:
                page, total = _monitor.db.query_audit(q=q, action=action, limit=500, offset=offset)
                rows.extend(page)
                offset += len(page)
                if not page or offset >= total:
                    break
        self._send_csv(
            "rdpguard-audit.csv",
            ["เวลา", "ผู้กระทำ", "การกระทำ", "เป้าหมาย", "ผลลัพธ์", "รายละเอียด"],
            [(r.get("ts"), r.get("actor"), r.get("action"), r.get("target"), r.get("result"), r.get("detail")) for r in rows[:100000]],
        )

    def _handle_list_blocked(self):
        if not self._require_auth():
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
            offset = max(0, int(query.get("offset", ["0"])[0]))
        except ValueError:
            limit, offset = 100, 0
        if not _monitor:
            _json_ok(self, {"blocked": [], "total": 0, "limit": limit, "offset": offset})
            return
        rows, total = _monitor.db.query_blocked(
            q=str(query.get("q", [""])[0])[:100].strip(),
            source=str(query.get("source", [""])[0])[:32].strip(),
            limit=limit,
            offset=offset,
        )
        _json_ok(self, {"blocked": rows, "total": total, "limit": limit, "offset": offset})

    def _handle_list_whitelist(self):
        if not self._require_auth():
            return
        _json_ok(self, {"whitelist": _monitor.db.list_whitelist() if _monitor else []})

    def _handle_list_blacklist(self):
        if not self._require_auth():
            return
        _json_ok(self, {"blacklist": _monitor.db.list_blacklist() if _monitor else []})

    def _handle_blocked_history(self, query):
        if not self._require_auth():
            return
        try:
            limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
            offset = max(0, int(query.get("offset", ["0"])[0]))
        except ValueError:
            limit, offset = 100, 0
        if not _monitor:
            _json_ok(self, {"history": [], "total": 0, "limit": limit, "offset": offset})
            return
        rows, total = _monitor.db.query_blocked_history(
            q=str(query.get("q", [""])[0])[:100].strip(),
            source=str(query.get("source", [""])[0])[:32].strip(),
            limit=limit,
            offset=offset,
        )
        _json_ok(self, {"history": rows, "total": total, "limit": limit, "offset": offset})

    def _handle_blocked_history_export(self, query):
        if not self._require_auth():
            return
        rows = []
        if _monitor:
            q = str(query.get("q", [""])[0])[:100].strip()
            source = str(query.get("source", [""])[0])[:32].strip()
            offset = 0
            while len(rows) < 100000:
                page, total = _monitor.db.query_blocked_history(q=q, source=source, limit=500, offset=offset)
                rows.extend(page)
                offset += len(page)
                if not page or offset >= total:
                    break
        self._send_csv(
            "rdpguard-blocked-history.csv",
            ["IP", "เหตุผล", "ที่มา", "สร้างเมื่อ", "หมดอายุ", "ปลดเมื่อ", "ปลดโดย"],
            [(r.get("ip"), r.get("reason"), r.get("source"), r.get("created"), r.get("expires"), r.get("unblocked_at"), r.get("unblocked_by")) for r in rows[:100000]],
        )

    def _handle_audit(self, query):
        if not self._require_auth():
            return
        try:
            limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
            offset = max(0, int(query.get("offset", ["0"])[0]))
        except ValueError:
            limit, offset = 100, 0
        if not _monitor:
            _json_ok(self, {"audit": [], "total": 0, "limit": limit, "offset": offset})
            return
        rows, total = _monitor.db.query_audit(
            q=str(query.get("q", [""])[0])[:100].strip(),
            action=str(query.get("action", [""])[0])[:32].strip(),
            limit=limit,
            offset=offset,
        )
        _json_ok(self, {"audit": rows, "total": total, "limit": limit, "offset": offset})

    def _handle_block(self, body):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ip = str(body.get("ip", "")).strip()
        if not _valid_ip_or_cidr(ip):
            _json_error(self, "รูปแบบ IP ไม่ถูกต้อง")
            return
        raw_hours = body.get("hours", 24)
        if raw_hours in (None, ""):
            hours = 24
        else:
            try:
                hours = int(raw_hours)
            except (TypeError, ValueError):
                _json_error(self, "จำนวนชั่วโมงต้องเป็นจำนวนเต็ม")
                return
        if hours < 0 or hours > 87600:
            _json_error(self, "จำนวนชั่วโมงต้องอยู่ระหว่าง 0 ถึง 87600")
            return
        ok, message = _monitor.manual_block(ip, hours)
        if ok:
            self._audit("block", ip, "ok", f"hours={hours}")
            _json_ok(self, {"message": message})
        else:
            self._audit("block", ip, "fail", message)
            _json_error(self, message)

    def _handle_bulk_unblock(self, body):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ips = body.get("ips", []) if isinstance(body, dict) else []
        if not isinstance(ips, list) or not ips or len(ips) > 200:
            _json_error(self, "ต้องส่ง ips เป็นรายการ 1-200 รายการ")
            return
        results = []
        for raw_ip in ips:
            ip = str(raw_ip).strip()
            if not _valid_ip_or_cidr(ip):
                results.append({"ip": ip, "ok": False, "message": "รูปแบบ IP ไม่ถูกต้อง"})
                continue
            ok, message = _monitor.manual_unblock(ip)
            results.append({"ip": ip, "ok": ok, "message": message})
        success = sum(1 for row in results if row["ok"])
        self._audit("bulk-unblock", f"{success}/{len(results)}", "ok", "ปลดบล็อกหลายรายการ")
        _json_ok(self, {"results": results, "success": success, "total": len(results)})

    def _handle_unblock(self, ip):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ok, message = _monitor.manual_unblock(ip)
        if ok:
            self._audit("unblock", ip, "ok", message)
            _json_ok(self, {"message": message})
        else:
            self._audit("unblock", ip, "fail", message)
            _json_error(self, message)

    def _handle_add_whitelist(self, body):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ip = str(body.get("ip", "")).strip()
        if not _valid_ip_or_cidr(ip):
            _json_error(self, "รูปแบบ IP ไม่ถูกต้อง")
            return
        if not _monitor.db.add_whitelist(ip, str(body.get("note", ""))):
            _json_error(self, "IP นี้อยู่ใน whitelist แล้ว")
            return
        self._audit("whitelist-add", ip, "ok", str(body.get("note", ""))[:200])
        # ถ้า IP ถูกบล็อกอยู่ -> ปลดทันที (whitelist = กันเด็ดขาด)
        if _monitor.db.is_blocked(ip):
            ok, message = _monitor.manual_unblock(ip)
            if not ok:
                self._audit("whitelist-add", ip, "fail", message)
                _json_error(self, f"เพิ่ม whitelist แล้ว แต่ {message}")
                return
            _json_ok(self, {"message": f"เพิ่ม {ip} ใน whitelist แล้ว — ปลดบล็อกให้ทันที"})
            return
        _json_ok(self, {"message": f"เพิ่ม {ip} ใน whitelist แล้ว — จะไม่ถูกบล็อกเด็ดขาด"})

    def _handle_remove_whitelist(self, ip):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        _monitor.db.remove_whitelist(ip)
        self._audit("whitelist-remove", ip)
        _json_ok(self, {"message": "ลบออกจาก whitelist แล้ว"})

    def _handle_add_blacklist(self, body):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ip = str(body.get("ip", "")).strip()
        if not _valid_ip_or_cidr(ip):
            _json_error(self, "รูปแบบ IP ไม่ถูกต้อง")
            return
        if not _monitor.db.add_blacklist(ip, str(body.get("note", ""))):
            _json_error(self, "IP นี้อยู่ใน blacklist แล้ว")
            return
        ok, message = _monitor.blacklist_block(ip)
        self._audit("blacklist-add", ip, "ok" if ok else "fail", message)
        _json_ok(self, {"message": message})

    def _handle_remove_blacklist(self, ip):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        _monitor.db.remove_blacklist(ip)
        # ถ้า IP ถูกบล็อกเพราะ blacklist -> ปลดให้ด้วย (ผู้ใช้เอาออก = อยากปลด)
        row = _monitor.db.is_blocked(ip)
        if row and row.get("source") == "blacklist":
            ok, message = _monitor.manual_unblock(ip)
            if not ok:
                self._audit("blacklist-remove", ip, "fail", message)
                _json_error(self, message)
                return
        self._audit("blacklist-remove", ip)
        _json_ok(self, {"message": "ลบออกจาก blacklist แล้ว"})

    def _handle_get_settings(self):
        if not self._require_auth():
            return
        cfg = config_mod.load_config()
        data = {}
        for section in cfg.sections():
            data[section] = dict(cfg.items(section))
        for section, key in _SECRET_KEYS:
            if section not in data:
                continue
            raw = data[section].pop(key, "")
            data[section][f"{key}_set"] = bool(str(raw).strip())
        _json_ok(self, data)

    def _handle_save_settings(self, body):
        allowed_sections = {"general", "monitor", "detection", "firewall", "webui", "engines", "notify"}
        allowed_keys = {
            "general": {
                "log_level", "log_max_mb", "log_backups", "event_retention_days",
                "history_retention_days", "audit_retention_days",
            },
            "monitor": {"enable", "poll_interval_seconds", "logon_types"},
            "detection": {
                "max_attempts",
                "window_minutes",
                "block_hours",
                "auto_extend",
                "skip_local_ips",
                "active_session_grace_minutes",
                "never_block_ips",
                "escalate_after_blocks",
                "escalate_block_hours",
                "escalate_to_permanent",
                "escalation_window_days",
                "accumulate_window_hours",
                "accumulate_threshold",
                "accumulate_block_hours",
            },
            "firewall": {"rule_prefix", "profile", "blocked_ports", "single_rule"},
            "webui": {"host", "port", "password"},
            "engines": {
                "openssh",
                "mssql",
                "iis",
                "mysql",
                "generic",
                "openssh_max_attempts",
                "mssql_max_attempts",
                "iis_max_attempts",
                "mysql_max_attempts",
                "generic_max_attempts",
                "iis_log_dir",
                "mysql_log_dir",
                "generic_logs",
            },
            "notify": {
                "enable",
                "channel",
                "hostname",
                "telegram_bot_token",
                "telegram_chat_id",
                "telegram_verify_ssl",
                "smtp_host",
                "smtp_port",
                "smtp_user",
                "smtp_password",
                "smtp_to",
                "cooldown_seconds",
                "webhook_enable",
                "webhook_url",
                "webhook_verify_ssl",
                "enable_commands",
                "confirm_timeout_seconds",
                "rate_limit_per_minute",
                "poll_retry_min_seconds",
                "poll_retry_max_seconds",
            },
        }
        if not isinstance(body, dict):
            body = {}
        with _cfg_lock:
            cfg = config_mod.load_config()
            old_password = config_mod.get(cfg, "webui", "password", "")
            changes = []
            try:
                for section, values in body.items():
                    section = str(section).lower()
                    if section not in allowed_sections or not isinstance(values, dict):
                        continue
                    for key, value in values.items():
                        if key not in allowed_keys[section]:
                            continue
                        value = str(value).strip()
                        if (section, key) in _SECRET_KEYS and not value:
                            continue
                        error = _validate_setting(section, key, value)
                        if error:
                            _json_error(self, error)
                            return
                        if (section, key) in _SECRET_KEYS and value == "__CLEAR__":
                            value = ""
                        cfg.set(section, key, value)
                        changes.append(f"{section}.{key}")
            except Exception as exc:
                _json_error(self, f"บันทึก config ไม่สำเร็จ: {exc}")
                return
            password_changed = False
            if "webui" in body and isinstance(body.get("webui"), dict):
                new_pw = str(body["webui"].get("password", "")).strip()
                if new_pw and new_pw != old_password:
                    password_changed = True
            try:
                config_mod.save_config(cfg)
            except Exception as exc:
                _json_error(self, f"เขียน config ไม่สำเร็จ: {exc}")
                return
        if password_changed:
            _invalidate_all_sessions()
        if _monitor:
            _monitor.reload()
        restart_keys = {
            "general.log_level", "general.log_max_mb", "general.log_backups",
            "general.event_retention_days", "general.history_retention_days", "general.audit_retention_days",
            "webui.host", "webui.port",
        }
        restart_required = sorted(set(changes) & restart_keys)
        self._audit("settings-save", ",".join(changes)[:500], "ok", "เปลี่ยนค่า config")
        _json_ok(
            self,
            {
                "message": "บันทึก config แล้ว — มีผลทันที",
                "changed": changes,
                "restart_required": restart_required,
            },
        )

    def _handle_setup_complete(self):
        with _cfg_lock:
            cfg = config_mod.load_config()
            cfg.set("general", "setup_done", "true")
            config_mod.save_config(cfg)
        if _monitor:
            _monitor.reload()
        _json_ok(self, {"message": "ตั้งค่าเสร็จสิ้น — เริ่มเฝ้าระวังแล้ว"})

    def _handle_detection_state(self):
        if not self._require_auth():
            return
        cfg = config_mod.load_config()
        engines = {}
        for name in ("openssh", "mssql", "iis", "mysql", "generic"):
            engines[name] = config_mod.get_bool(cfg, "engines", name, True)
        _json_ok(
            self,
            {
                "enable": config_mod.get_bool(cfg, "monitor", "enable", True),
                "engines": engines,
            },
        )

    def _handle_toggle(self, body):
        with _cfg_lock:
            cfg = config_mod.load_config()
            if body.get("engine"):
                name = str(body["engine"])
                if name not in ("openssh", "mssql", "iis", "mysql", "generic"):
                    _json_error(self, "engine ไม่รู้จัก")
                    return
                current = config_mod.get_bool(cfg, "engines", name, True)
                cfg.set("engines", name, "false" if current else "true")
                config_mod.save_config(cfg)
                result = {
                    "message": f"engine {name}: {'ปิด' if current else 'เปิด'} แล้ว",
                    "engine": name,
                    "enable": not current,
                }
            elif body.get("key") == "enable":
                current = config_mod.get_bool(cfg, "monitor", "enable", True)
                cfg.set("monitor", "enable", "false" if current else "true")
                config_mod.save_config(cfg)
                result = {
                    "message": f"การตรวจจับ: {'ปิด' if current else 'เปิด'} แล้ว",
                    "enable": not current,
                }
            else:
                _json_error(self, "ต้องระบุ engine หรือ key=enable")
                return
        if _monitor:
            _monitor.reload()
        _json_ok(self, result)

    def _handle_log(self, query):
        if not self._require_auth():
            return
        try:
            lines = max(1, min(int(query.get("lines", ["200"])[0]), 2000))
        except ValueError:
            lines = 200
        requested = os.path.basename(str(query.get("file", [""])[0]))
        candidates = self._log_candidates()
        log_file = candidates.get(requested, config_mod.LOG_FILE)
        content = []
        file_size = 0
        if os.path.isfile(log_file):
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    file_size = size
                    chunk = min(size, 64 * 1024)
                    f.seek(max(0, size - chunk))
                    data = f.read()
                content = data.splitlines()[-lines:]
            except Exception as exc:
                _json_error(self, f"อ่าน log ไม่ได้: {exc}")
                return
        _json_ok(self, {"lines": content, "file": log_file, "name": os.path.basename(log_file), "file_size": file_size})

    @staticmethod
    def _log_candidates():
        directory = os.path.dirname(config_mod.LOG_FILE)
        base = os.path.basename(config_mod.LOG_FILE)
        result = {base: config_mod.LOG_FILE}
        try:
            for name in os.listdir(directory):
                if not name.startswith(base + "."):
                    continue
                suffix = name[len(base) + 1 :]
                if suffix.isdigit():
                    result[name] = os.path.join(directory, name)
        except OSError:
            pass
        return dict(sorted(result.items(), key=lambda item: (item[0] != base, item[0])))

    def _handle_log_files(self):
        if not self._require_auth():
            return
        files = []
        for name, path in self._log_candidates().items():
            try:
                stat = os.stat(path)
            except OSError:
                continue
            files.append({"name": name, "size": stat.st_size, "mtime": stat.st_mtime})
        _json_ok(self, {"files": files})

    def _handle_log_download(self, query):
        if not self._require_auth():
            return
        name = os.path.basename(str(query.get("file", [os.path.basename(config_mod.LOG_FILE)])[0]))
        path = self._log_candidates().get(name)
        if not path or not os.path.isfile(path):
            _json_error(self, "ไม่พบไฟล์ log", status=404)
            return
        try:
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(path, "rb") as source:
                while True:
                    chunk = source.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception as exc:
            log.warning("ดาวน์โหลด log ไม่สำเร็จ: %s", exc)

    def _handle_backup(self):
        """ดาวน์โหลด backup แบบ zip โดยล้างค่าลับใน config ก่อนเสมอ"""
        if not self._require_auth():
            return
        temp_db = None
        db = _monitor.db if _monitor else None
        owned_db = False
        try:
            if db is None:
                from .database import Database

                db = Database()
                owned_db = True
            fd, temp_db = tempfile.mkstemp(prefix="rdpguard-backup-", suffix=".db")
            os.close(fd)
            db.backup_to(temp_db)
            cfg = config_mod.load_config()
            for section, key in _SECRET_KEYS:
                if cfg.has_option(section, key):
                    cfg.set(section, key, "")
            config_text = io.StringIO()
            cfg.write(config_text)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr("config.redacted.ini", config_text.getvalue())
                with open(temp_db, "rb") as source:
                    bundle.writestr("rdpguard.db", source.read())
                bundle.writestr("README.txt", "RDPGuard backup — config ถูกล้างค่าลับแล้ว\n")
            body = archive.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="rdpguard-backup.zip"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self._audit("backup", "database+config", "ok", "ดาวน์โหลด backup แบบล้างค่าลับ")
        except Exception as exc:
            log.exception("สร้าง backup ไม่สำเร็จ")
            _json_error(self, f"สร้าง backup ไม่สำเร็จ: {exc}")
        finally:
            if owned_db:
                db.close()
            if temp_db:
                try:
                    os.remove(temp_db)
                except OSError:
                    pass

    def _handle_restore(self):
        """รับเฉพาะฐานข้อมูลจาก backup ที่ตรวจ integrity แล้ว และรอ restart ก่อนใช้งาน"""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0 or length > 64 * 1024 * 1024:
            _json_error(self, "ไฟล์ backup ต้องมีขนาดไม่เกิน 64 MB")
            return
        raw = self.rfile.read(length)
        temp = config_mod.DB_FILE + ".restore.tmp"
        pending = config_mod.DB_FILE + ".restore"
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
                names = set(bundle.namelist())
                if "rdpguard.db" not in names or any(name.startswith("/") or ".." in name.split("/") for name in names):
                    _json_error(self, "ไฟล์ backup ไม่ถูกต้อง")
                    return
                db_bytes = bundle.read("rdpguard.db")
            if len(db_bytes) > 64 * 1024 * 1024:
                _json_error(self, "ฐานข้อมูลใน backup ใหญ่เกิน 64 MB")
                return
            with open(temp, "wb") as target:
                target.write(db_bytes)
            check = sqlite3.connect(temp)
            try:
                integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
                tables = {row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                check.close()
            if integrity != "ok" or "events" not in tables or "blocked" not in tables:
                _json_error(self, "ฐานข้อมูลใน backup ไม่ผ่านการตรวจสอบ")
                return
            os.replace(temp, pending)
            self._audit("restore", "database", "ok", "ตรวจสอบ backup แล้ว รอ restart")
            _json_ok(self, {"message": "รับ backup แล้ว — ปิดและเปิด RDPGuard ใหม่เพื่อใช้ฐานข้อมูลที่กู้คืน", "restart_required": True})
        except (zipfile.BadZipFile, KeyError) as exc:
            _json_error(self, f"อ่าน backup ไม่สำเร็จ: {exc}")
        except Exception as exc:
            log.exception("รับ restore ไม่สำเร็จ")
            _json_error(self, f"กู้คืน backup ไม่สำเร็จ: {exc}")
        finally:
            try:
                if os.path.isfile(temp):
                    os.remove(temp)
            except OSError:
                pass

    def _handle_geoip(self, body):
        ips = body.get("ips", [])
        if not isinstance(ips, list):
            _json_error(self, "ips ต้องเป็นรายการ")
            return
        # จำกัดต่อ request (throttle 0.35s/IP — batch ใหญ่ทำให้ request ค้างนาน)
        ips = [str(x).strip() for x in ips[:20]]
        from . import geoip as geoip_mod

        db = _monitor.db if _monitor else None
        results = geoip_mod.batch(ips, db=db)
        _json_ok(self, {"geoip": results})

    def _handle_service_status(self):
        if not self._require_auth():
            return
        try:
            from . import service as service_mod

            status = service_mod.service_status()
            data = {
                "installed": bool(status.get("installed", False)),
                "state": status.get("state", "unknown"),
                "running": status.get("state") == "running",
                "context": _context_label(),
                "is_admin": _is_admin(),
                "can_control": _is_admin() and not _in_service(),
            }
            if not data["installed"] and status.get("message"):
                data["message"] = status["message"]
            _json_ok(self, data)
        except Exception as exc:
            _json_error(self, f"ตรวจสถานะ service ไม่สำเร็จ: {exc}")

    def _handle_service_action(self, body):
        action = str(body.get("action", ""))
        if action not in ("install", "remove", "start", "stop", "restart"):
            _json_error(self, "action ไม่ถูกต้อง")
            return
        if _in_service():
            _json_error(
                self,
                "กำลังรันใน service อยู่ — ควบคุม service ได้จาก services.msc หรือ CLI เท่านั้น",
                status=403,
            )
            return
        if not _is_admin():
            _json_error(
                self,
                "ต้องรันด้วยสิทธิ์ administrator เพื่อควบคุม service "
                "(ให้คลิกขวาโปรแกรมแล้วเลือก Run as administrator)",
                status=403,
            )
            return
        try:
            from . import service as service_mod

            fn = {
                "install": service_mod.install_service,
                "remove": service_mod.remove_service,
                "start": service_mod.start_service,
                "stop": service_mod.stop_service,
                "restart": service_mod.restart_service,
            }[action]
            message = fn()
            self._audit("service-" + action, "RDPGuard", "ok", message)
            _json_ok(self, {"message": message})
        except Exception as exc:
            self._audit("service-" + action, "RDPGuard", "fail", str(exc))
            _json_error(self, f"คำสั่งล้มเหลว: {exc}")

    # ---- body helpers ----

    def send_response(self, code, message=None):
        super().send_response(code, message)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
        super().end_headers()


class WebUI:
    def __init__(self, host="127.0.0.1", port=8123, monitor=None):
        global _monitor
        _monitor = monitor
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self):
        self._server = RDPGuardHTTPServer((self.host, self.port), RDPGuardHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        log.info("Web UI เปิดที่ http://%s:%s", self.host, self.port)
        return self

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        log.info("Web UI หยุดทำงาน")

    def wait(self):
        if self._thread:
            self._thread.join()


def start_webui(host="127.0.0.1", port=8123, monitor=None, background=True):
    ui = WebUI(host=host, port=port, monitor=monitor).start()
    return ui
