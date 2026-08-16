"""Web UI + REST API (stdlib ล้วน, single page ภาษาไทย).

- เปิดเฉพาะ 127.0.0.1 (ค่าเริ่มต้น) — ระวังถ้าตั้งเป็น 0.0.0.0 ต้องตั้ง password
- ต้องล็อกอินด้วยรหัสจาก config (webui.password) — cookie session ง่าย ๆ
- กันการเดารหัสหน้า login: พลาด 5 ครั้ง ล็อก 5 นาที
- UI ฝั่ง static อยู่ในโฟลเดอร์ web/ (index.html, app.js, style.css)
"""

import ipaddress
import json
import logging
import mimetypes
import os
import secrets
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
_login_guard = {"fails": 0, "locked_until": 0.0}
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
            return True

    def _require_auth(self):
        if not self._authorized():
            _json_error(self, "กรุณาล็อกอินก่อน", status=401)
            return False
        return True

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
        elif path == "/api/sessions":
            self._handle_sessions()
        elif path == "/api/overview":
            self._handle_overview()
        elif path == "/api/events":
            self._handle_events(query)
        elif path == "/api/blocked":
            self._handle_list_blocked()
        elif path == "/api/whitelist":
            self._handle_list_whitelist()
        elif path == "/api/blacklist":
            self._handle_list_blacklist()
        elif path == "/api/settings":
            self._handle_get_settings()
        else:
            _json_error(self, "ไม่พบเส้นทาง", status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body()
        if path == "/api/login":
            self._handle_login(body)
        elif path == "/api/logout":
            self._handle_logout()
        elif path == "/api/blocked":
            if self._require_auth():
                self._handle_block(body)
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
        with _login_lock:
            if _login_guard["locked_until"] > now:
                left = int(_login_guard["locked_until"] - now)
                _json_error(self, f"พยายามมากเกินไป — รอ {left} วินาที", status=429)
                return
        cfg = config_mod.load_config()
        expected = config_mod.get(cfg, "webui", "password", "")
        given = str(body.get("password", ""))
        if expected and secrets.compare_digest(given, expected):
            token = _new_session()
            with _login_lock:
                _login_guard["fails"] = 0
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
            _login_guard["fails"] += 1
            if _login_guard["fails"] >= _LOGIN_MAX_FAILS:
                _login_guard["locked_until"] = now + _LOGIN_LOCK_SECONDS
                _login_guard["fails"] = 0
                _json_error(self, "รหัสผิด 5 ครั้ง — ล็อกการพยายาม 5 นาที", status=429)
                return
        _json_error(self, "รหัสไม่ถูกต้อง", status=401)

    def _handle_logout(self):
        token = self._cookie_value("rdpguard_session") or ""
        if token:
            with _session_lock:
                _sessions.pop(token, None)
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
            "settings_summary": {
                "max_attempts": config_mod.get_int(cfg, "detection", "max_attempts", 5),
                "window_minutes": config_mod.get_int(cfg, "detection", "window_minutes", 10),
                "block_hours": config_mod.get_int(cfg, "detection", "block_hours", 24),
                "enable": config_mod.get_bool(cfg, "monitor", "enable", True),
            },
        }
        _json_ok(self, data)

    def _handle_unblock_all(self):
        """ฉุกเฉิน: ปลดบล็อกทุก IP (ลบ rule firewall ทั้งหมดของ RDPGuard)"""
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        _json_ok(self, {"message": _monitor.unblock_all()})

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
            _json_ok(
                self,
                {
                    "working": True,
                    "message": "Firewall ทำงานได้จริง — เพิ่ม + ลบ rule ทดสอบ (203.0.113.254) สำเร็จ",
                },
            )
        else:
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
        _json_ok(self, {"events": _monitor.db.recent_events(limit) if _monitor else []})

    def _handle_list_blocked(self):
        if not self._require_auth():
            return
        _json_ok(self, {"blocked": _monitor.db.list_blocked() if _monitor else []})

    def _handle_list_whitelist(self):
        if not self._require_auth():
            return
        _json_ok(self, {"whitelist": _monitor.db.list_whitelist() if _monitor else []})

    def _handle_list_blacklist(self):
        if not self._require_auth():
            return
        _json_ok(self, {"blacklist": _monitor.db.list_blacklist() if _monitor else []})

    def _handle_block(self, body):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ip = str(body.get("ip", "")).strip()
        if not _valid_ip_or_cidr(ip):
            _json_error(self, "รูปแบบ IP ไม่ถูกต้อง")
            return
        try:
            hours = int(body.get("hours", 24) or 24)
        except ValueError:
            hours = 24
        ok, message = _monitor.manual_block(ip, hours)
        if ok:
            _json_ok(self, {"message": message})
        else:
            _json_error(self, message)

    def _handle_unblock(self, ip):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        ok, message = _monitor.manual_unblock(ip)
        if ok:
            _json_ok(self, {"message": message})
        else:
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
        # ถ้า IP ถูกบล็อกอยู่ -> ปลดทันที (whitelist = กันเด็ดขาด)
        if _monitor.db.is_blocked(ip):
            _monitor.manual_unblock(ip)
            _json_ok(self, {"message": f"เพิ่ม {ip} ใน whitelist แล้ว — ปลดบล็อกให้ทันที"})
            return
        _json_ok(self, {"message": f"เพิ่ม {ip} ใน whitelist แล้ว — จะไม่ถูกบล็อกเด็ดขาด"})

    def _handle_remove_whitelist(self, ip):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        _monitor.db.remove_whitelist(ip)
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
        _json_ok(self, {"message": message})

    def _handle_remove_blacklist(self, ip):
        if not _monitor:
            _json_error(self, "monitor ไม่ได้รัน")
            return
        _monitor.db.remove_blacklist(ip)
        # ถ้า IP ถูกบล็อกเพราะ blacklist -> ปลดให้ด้วย (ผู้ใช้เอาออก = อยากปลด)
        row = _monitor.db.is_blocked(ip)
        if row and row.get("source") == "blacklist":
            _monitor.manual_unblock(ip)
        _json_ok(self, {"message": "ลบออกจาก blacklist แล้ว"})

    def _handle_get_settings(self):
        if not self._require_auth():
            return
        cfg = config_mod.load_config()
        data = {}
        for section in cfg.sections():
            data[section] = dict(cfg.items(section))
        # ไม่ส่ง password ตัวจริงกลับ (UI ใช้ password_hidden แสดงสถานะเท่านั้น)
        data["webui"]["password_hidden"] = "***" if data["webui"].get("password") else ""
        del data["webui"]["password"]
        _json_ok(self, data)

    def _handle_save_settings(self, body):
        allowed_sections = {"monitor", "detection", "firewall", "webui", "engines"}
        allowed_keys = {
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
        }
        if not isinstance(body, dict):
            body = {}
        with _cfg_lock:
            cfg = config_mod.load_config()
            old_password = config_mod.get(cfg, "webui", "password", "")
            try:
                for section, values in body.items():
                    section = str(section).lower()
                    if section not in allowed_sections or not isinstance(values, dict):
                        continue
                    for key, value in values.items():
                        if key not in allowed_keys[section]:
                            continue
                        if section == "webui" and key == "password" and not str(value).strip():
                            continue
                        cfg.set(section, key, str(value).strip())
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
        _json_ok(self, {"message": "บันทึก config แล้ว — มีผลทันที"})

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
            lines = min(int(query.get("lines", ["200"])[0]), 2000)
        except ValueError:
            lines = 200
        log_file = config_mod.LOG_FILE
        content = []
        if os.path.isfile(log_file):
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    chunk = min(size, 64 * 1024)
                    f.seek(max(0, size - chunk))
                    data = f.read()
                content = data.splitlines()[-lines:]
            except Exception as exc:
                _json_error(self, f"อ่าน log ไม่ได้: {exc}")
                return
        _json_ok(self, {"lines": content, "file": log_file})

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
            _json_ok(self, {"message": message})
        except Exception as exc:
            _json_error(self, f"คำสั่งล้มเหลว: {exc}")

    # ---- body helpers ----

    def send_response(self, code, message=None):
        super().send_response(code, message)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
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
