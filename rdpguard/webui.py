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

_session_token = None
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


class RDPGuardHandler(BaseHTTPRequestHandler):
    server_version = f"RDPGuard/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.debug("http %s %s", self.address_string(), fmt % args)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            log.debug("client ตัดการเชื่อมต่อ: %s", client_address)
            return
        super().handle_error(request, client_address)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
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
        if _session_token is None:
            return False
        return secrets.compare_digest(self._cookie_value("rdpguard_session") or "", _session_token)

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
        if _login_guard["locked_until"] > now:
            left = int(_login_guard["locked_until"] - now)
            _json_error(self, f"พยายามมากเกินไป — รอ {left} วินาที", status=429)
            return
        cfg = config_mod.load_config()
        expected = config_mod.get(cfg, "webui", "password", "")
        given = str(body.get("password", ""))
        if expected and secrets.compare_digest(given, expected):
            global _session_token
            _session_token = secrets.token_urlsafe(32)
            _login_guard["fails"] = 0
            _json_ok(
                self,
                {"token": _session_token},
                headers={
                    "Set-Cookie": (
                        f"rdpguard_session={_session_token}; Path=/; "
                        "HttpOnly; SameSite=Lax"
                    )
                },
            )
            return
        _login_guard["fails"] += 1
        if _login_guard["fails"] >= _LOGIN_MAX_FAILS:
            _login_guard["locked_until"] = now + _LOGIN_LOCK_SECONDS
            _login_guard["fails"] = 0
            _json_error(self, "รหัสผิด 5 ครั้ง — ล็อกการพยายาม 5 นาที", status=429)
            return
        _json_error(self, "รหัสไม่ถูกต้อง", status=401)

    def _handle_logout(self):
        global _session_token
        _session_token = None
        _json_ok(
            self,
            {"message": "ออกจากระบบแล้ว"},
            headers={
                "Set-Cookie": (
                    "rdpguard_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
                )
            },
        )

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
            limit = min(int(query.get("limit", ["100"])[0]), 500)
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
        ok, message = _monitor.manual_unblock(ip)
        if ok:
            _json_ok(self, {"message": message})
        else:
            _json_error(self, message)

    def _handle_add_whitelist(self, body):
        ip = str(body.get("ip", "")).strip()
        if not _valid_ip_or_cidr(ip):
            _json_error(self, "รูปแบบ IP ไม่ถูกต้อง")
            return
        if not _monitor.db.add_whitelist(ip, str(body.get("note", ""))):
            _json_error(self, "IP นี้อยู่ใน whitelist แล้ว")
            return
        _json_ok(self, {"message": f"เพิ่ม {ip} ใน whitelist แล้ว"})

    def _handle_remove_whitelist(self, ip):
        _monitor.db.remove_whitelist(ip)
        _json_ok(self, {"message": "ลบออกจาก whitelist แล้ว"})

    def _handle_add_blacklist(self, body):
        ip = str(body.get("ip", "")).strip()
        if not _valid_ip_or_cidr(ip):
            _json_error(self, "รูปแบบ IP ไม่ถูกต้อง")
            return
        if not _monitor.db.add_blacklist(ip, str(body.get("note", ""))):
            _json_error(self, "IP นี้อยู่ใน blacklist แล้ว")
            return
        _json_ok(self, {"message": f"เพิ่ม {ip} ใน blacklist แล้ว"})

    def _handle_remove_blacklist(self, ip):
        _monitor.db.remove_blacklist(ip)
        _json_ok(self, {"message": "ลบออกจาก blacklist แล้ว"})

    def _handle_get_settings(self):
        if not self._require_auth():
            return
        cfg = config_mod.load_config()
        data = {}
        for section in cfg.sections():
            data[section] = dict(cfg.items(section))
        data["webui"]["password_hidden"] = "***" if data["webui"].get("password") else ""
        _json_ok(self, data)

    def _handle_save_settings(self, body):
        with _cfg_lock:
            cfg = config_mod.load_config()
            allowed_sections = {"monitor", "detection", "firewall", "webui", "engines"}
        allowed_keys = {
            "monitor": {"enable", "poll_interval_seconds", "logon_types"},
            "detection": {
                "max_attempts",
                "window_minutes",
                "block_hours",
                "auto_extend",
                "skip_local_ips",
            },
            "firewall": {"rule_prefix", "profile", "blocked_ports"},
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
        config_mod.save_config(cfg)
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
        ips = [str(x).strip() for x in ips[:200]]
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
        self._server = ThreadingHTTPServer((self.host, self.port), RDPGuardHandler)
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
