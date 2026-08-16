"""Brute-force detection engine.

หลักการ (เหมือน RDPGuard / fail2ban):
1. นับการล็อกอินล้มเหลว (Event 4625) ต่อ IP ภายในกรอบเวลา window
2. ครบ max_attempts → บล็อก IP ด้วย Windows Firewall ตามเวลา block_hours
3. IP ที่ถูกบล็อกแล้วยังโจมตีต่อ → ต่ออายุบล็อกอัตโนมัติ (ถ้าเปิด)
4. whitelist = ไม่บล็อกเด็ดขาด / blacklist = บล็อกทันทีแม้ครั้งเดียว
"""

import ipaddress
import logging
import socket
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

log = logging.getLogger("RDPGuard.detector")


def _now_utc():
    return datetime.now(timezone.utc)


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


ENGINE_LABELS = {
    "rdp": "RDP",
    "openssh": "OpenSSH",
    "mssql": "MSSQL",
    "iis": "IIS Web",
    "mysql": "MySQL",
}


def is_valid_ip(value):
    value = (value or "").strip()
    if not value or value in ("-", "0.0.0.0", "::", "::1"):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _own_ips():
    result = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            result.add(info[4][0])
    except Exception:
        pass
    return result


def is_local_ip(value):
    """True ถ้าเป็น loopback / เครื่องตัวเอง / วง LAN ส่วนตัว"""
    if value in _own_ips():
        return True
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


class BruteForceDetector:
    def __init__(self, db, fw, cfg=None, on_block=None):
        self.db = db
        self.fw = fw
        self.cfg = cfg
        self.on_block = on_block
        self._lock = threading.Lock()
        self._attempts = {}

    def reload(self, cfg):
        self.cfg = cfg

    def _config(self):
        from . import config as config_mod

        parser = self.cfg or config_mod.load_config()
        return parser

    def _logon_types(self):
        from . import config as config_mod

        raw = config_mod.get(self._config(), "monitor", "logon_types", "3,10").strip()
        if raw == "*":
            return None
        types = []
        for part in raw.split(","):
            try:
                types.append(int(part.strip()))
            except ValueError:
                pass
        return set(types)

    def _max_attempts(self, source):
        from . import config as config_mod

        parser = self._config()
        engine = source.split(":")[0]
        override = config_mod.get(parser, "engines", f"{engine}_max_attempts", "").strip()
        if override:
            try:
                return int(override)
            except ValueError:
                pass
        return config_mod.get_int(parser, "detection", "max_attempts", 5)

    def handle_event(self, item):
        """รับ event จาก engine — item: dict {kind, ip, user, source, ts, ...}"""
        kind = item.get("kind")
        if kind == "fail":
            self.handle_failed(item)
        elif kind == "success":
            self.handle_success(item)

    def handle_failed(self, item):
        parser = self._config()
        from . import config as config_mod

        if not config_mod.get_bool(parser, "monitor", "enable", True):
            return
        source = str(item.get("source") or "rdp")
        ip = item.get("ip", "-")
        if not is_valid_ip(ip):
            return
        if source == "rdp":
            types = self._logon_types()
            if types is not None and int(item.get("logon_type", 0)) not in types:
                return
        skip_local = config_mod.get_bool(parser, "detection", "skip_local_ips", True)
        if skip_local and is_local_ip(ip):
            return
        if self.db.is_whitelisted(ip):
            log.info("ข้าม IP %s (อยู่ใน whitelist)", ip)
            return
        if self.db.is_blocked(ip):
            self._maybe_extend(parser, ip)
            return
        if self._is_blacklisted(ip):
            log.info("IP %s อยู่ใน blacklist — บล็อกทันที", ip)
            self._do_block(parser, ip, "blacklist", source)
            return

        max_attempts = self._max_attempts(source)
        window_minutes = config_mod.get_int(parser, "detection", "window_minutes", 10)
        window = timedelta(minutes=window_minutes)
        key = (source, ip)

        with self._lock:
            buf = self._attempts.setdefault(key, deque())
            buf.append(_now_utc())
            while buf and buf[0] < _now_utc() - window:
                buf.popleft()
            count = len(buf)

        label = ENGINE_LABELS.get(source, source)
        log.info(
            "ล็อกอินล้มเหลว (%s) จาก %s (user=%s) — %d ครั้งใน %d นาที",
            label,
            ip,
            item.get("user", "-"),
            count,
            window_minutes,
        )
        if count < max_attempts:
            return
        self._do_block(parser, ip, "auto", source)

    def handle_success(self, item):
        ip = item.get("ip", "-")
        if not is_valid_ip(ip):
            return
        source = str(item.get("source") or "rdp")
        with self._lock:
            self._attempts.pop((source, ip), None)

    def _is_blacklisted(self, ip):
        return any(row["ip"] == ip for row in self.db.list_blacklist())

    def _maybe_extend(self, parser, ip):
        from . import config as config_mod

        if not config_mod.get_bool(parser, "detection", "auto_extend", True):
            return
        row = self.db.is_blocked(ip)
        if not row:
            return
        hours = config_mod.get_int(parser, "detection", "block_hours", 24)
        if hours <= 0:
            return
        new_expiry = _now_utc() + timedelta(hours=hours)
        self.db.extend_block(ip, _iso(new_expiry))
        log.info("ต่ออายุบล็อก IP %s (ยังโจมตีต่อ)", ip)

    def _do_block(self, parser, ip, source, engine="rdp"):
        from . import config as config_mod

        hours = config_mod.get_int(parser, "detection", "block_hours", 24)
        expires = _iso(_now_utc() + timedelta(hours=hours)) if hours > 0 else ""
        prefix = config_mod.get(parser, "firewall", "rule_prefix", "RDPGuard Block")
        ports = config_mod.get(parser, "firewall", "blocked_ports", "").strip()
        rule_name = f"{prefix} {ip}"

        if self.db.is_blocked(ip):
            self._maybe_extend(parser, ip)
            return
        self.fw.ports = [p.strip() for p in ports.split(",") if p.strip()] if ports else []
        ok = self.fw.add_block(ip)
        label = ENGINE_LABELS.get(engine, engine)
        reason = (
            f"ล็อกอิน {label} ล้มเหลวเกินกำหนด ({source})"
            + ("" if ok else " [FIREWALL ล้มเหลว — ตรวจสิทธิ์ admin]")
        )
        self.db.block_ip(ip, reason=reason, source=source, expires=expires, rule_name=rule_name)
        if ok:
            log.warning("บล็อก IP %s (%s) จนถึง %s", ip, label, expires or "ถาวร")
        else:
            log.error("ไม่สามารถเพิ่ม rule firewall สำหรับ IP %s", ip)
        if self.on_block:
            try:
                self.on_block(ip, source)
            except Exception:
                log.exception("on_block callback ล้มเหลว")
