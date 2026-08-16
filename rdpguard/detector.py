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


def is_valid_ip_or_cidr(value):
    """IP เดี่ยว หรือ CIDR (เช่น 192.168.1.0/24)"""
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
        if kind in ("fail", "success", "ntlm"):
            try:
                self.db.add_event(
                    kind,
                    ip=str(item.get("ip") or ""),
                    user=str(item.get("user") or ""),
                    domain=str(item.get("domain") or ""),
                    logon_type=int(item.get("logon_type") or 0),
                    source=str(item.get("source") or ""),
                )
            except Exception:
                log.exception("บันทึก event ล้มเหลว")
        if kind == "fail":
            self.handle_failed(item)
        elif kind == "success":
            self.handle_success(item)

    def _never_block(self, parser, ip):
        from . import config as config_mod

        for entry in config_mod.get_list(parser, "detection", "never_block_ips"):
            try:
                if entry == ip or (
                    "/" in entry
                    and ipaddress.ip_address(ip)
                    in ipaddress.ip_network(entry, strict=False)
                ):
                    return True
            except ValueError:
                continue
        return False

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
        if self.db.is_whitelisted(ip):
            log.info("ข้าม IP %s (อยู่ใน whitelist)", ip)
            return
        if self._never_block(parser, ip):
            log.info("ข้าม IP %s (อยู่ใน never_block_ips)", ip)
            return
        if self.db.is_blacklisted(ip):
            log.info("IP %s อยู่ใน blacklist — บล็อกทันที", ip)
            self._do_block(parser, ip, "blacklist", source)
            return
        skip_local = config_mod.get_bool(parser, "detection", "skip_local_ips", True)
        if skip_local and is_local_ip(ip):
            return
        if self.db.is_blocked(ip):
            self._maybe_extend(parser, ip)
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
            str(item.get("user", "-")).replace("\n", " "),
            count,
            window_minutes,
        )
        if count >= max_attempts:
            grace = config_mod.get_int(parser, "detection", "active_session_grace_minutes", 30)
            if grace > 0 and self.db.recent_success(ip, grace):
                log.warning(
                    "ข้ามการบล็อก IP %s — มี session ล็อกอินสำเร็จภายใน %d นาที (ป้องกันผู้ดูแลถูกล็อก)",
                    ip,
                    grace,
                )
                with self._lock:
                    self._attempts.pop(key, None)
                return
            self._do_block(parser, ip, "auto", source)
            return

        # ตัวนับสะสม: รันเฉพาะตอนที่ short-window ยังไม่บล็อก (กันเกณฑ์ทั้งคู่ชนกันใน event เดียว
        # → บล็อกทับ/ขยายซ้อนด้วย _maybe_extend)
        self._accumulate_bump(parser, ip, source)

    def _accumulate_bump(self, parser, ip, engine="rdp"):
        """ตัวนับสะสม: บวก 1 ต่อ IP (ข้าม engine) ภายใน accumulate_window_hours —
        ครบ accumulate_threshold → บล็อกด้วย accumulate_block_hours
        (กันกลยุทธ์ยิงสั้น ๆ แล้วหนี ที่ไม่ถึงเกณฑ์ window ระยะสั้น)"""
        from . import config as config_mod

        win = config_mod.get_int(parser, "detection", "accumulate_window_hours", 0)
        threshold = config_mod.get_int(parser, "detection", "accumulate_threshold", 0)
        if win <= 0 or threshold <= 0:
            return
        count = self.db.accumulate_add(ip)
        if count >= threshold:
            grace = config_mod.get_int(parser, "detection", "active_session_grace_minutes", 30)
            if grace > 0 and self.db.recent_success(ip, grace):
                self.db.accumulate_reset(ip)
                log.warning(
                    "ข้ามบล็อกสะสม IP %s (สะสม %d ครั้ง) — มี session ล็อกอินสำเร็จ ผู้ใช้จริงกลับมาแล้ว",
                    ip,
                    count,
                )
            else:
                self._do_block(parser, ip, "accumulate", engine)
        else:
            log.info(
                "ตัวนับสะสม: IP %s สะสม %d/%d ครั้งใน %d ชม.",
                ip,
                count,
                threshold,
                win,
            )

    def handle_success(self, item):
        ip = item.get("ip", "-")
        if not is_valid_ip(ip):
            return
        source = str(item.get("source") or "rdp")
        with self._lock:
            self._attempts.pop((source, ip), None)
        self.db.accumulate_reset(ip)
        row = self.db.is_blocked(ip)
        if row:
            ok = self.fw.remove_block(ip)
            self.db.unblock_ip(ip, by="auto-login")
            log.warning(
                "IP %s ล็อกอินสำเร็จ — ปลดบล็อกอัตโนมัติ (rule ลบ=%s)",
                ip,
                "OK" if ok else "FAIL",
            )

    def _maybe_extend(self, parser, ip):
        from . import config as config_mod

        if not config_mod.get_bool(parser, "detection", "auto_extend", True):
            return
        row = self.db.is_blocked(ip)
        if not row:
            return
        if row.get("source") == "accumulate":
            hours = config_mod.get_int(parser, "detection", "accumulate_block_hours", 6)
        else:
            hours = config_mod.get_int(parser, "detection", "block_hours", 24)
        if hours <= 0:
            return
        new_expiry = _now_utc() + timedelta(hours=hours)
        current = row.get("expires") or ""
        if not current:
            return  # บล็อกถาวร (expires ว่าง) — อย่าแตะ
        if current:
            try:
                cur = datetime.strptime(current, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                if cur > new_expiry:
                    return  # expires เดิมยาวกว่าอยู่แล้ว (เช่น escalate) — อย่าลดลง
            except ValueError:
                pass
        self.db.extend_block(ip, _iso(new_expiry))
        log.info("ต่ออายุบล็อก IP %s (ยังโจมตีต่อ)", ip)

    def _do_block(self, parser, ip, source, engine="rdp"):
        from . import config as config_mod

        prefix = config_mod.get(parser, "firewall", "rule_prefix", "RDPGuard Block")
        ports = config_mod.get(parser, "firewall", "blocked_ports", "").strip()
        rule_name = f"{prefix} {ip}"
        label = ENGINE_LABELS.get(engine, engine)

        if self.db.is_blocked(ip):
            self._maybe_extend(parser, ip)
            return

        if source == "accumulate":
            hours = config_mod.get_int(parser, "detection", "accumulate_block_hours", 6)
            expires = _iso(_now_utc() + timedelta(hours=hours)) if hours > 0 else ""
            reason = f"สะสมล็อกอิน {label} ล้มเหลวเกินกำหนด ({source}) — ยิงสั้น ๆ ซ้ำ"
        else:
            hours = config_mod.get_int(parser, "detection", "block_hours", 24)
            expires = _iso(_now_utc() + timedelta(hours=hours)) if hours > 0 else ""
            reason = f"ล็อกอิน {label} ล้มเหลวเกินกำหนด ({source})"

        if source == "auto":
            escalate_after = config_mod.get_int(parser, "detection", "escalate_after_blocks", 3)
            window_days = config_mod.get_int(parser, "detection", "escalation_window_days", 30)
            if escalate_after > 0 and window_days > 0:
                since = (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                prior = self.db.count_prior_blocks(ip, since)
                if prior >= escalate_after:
                    if config_mod.get_bool(parser, "detection", "escalate_to_permanent", False):
                        expires = ""
                        reason = (
                            f"ล็อกอิน {label} ล้มเหลวซ้ำ (ครั้งที่ {prior + 1}) — "
                            "ขาประจำ ขยายเป็นบล็อกถาวร"
                        )
                    else:
                        esc_hours = config_mod.get_int(parser, "detection", "escalate_block_hours", 168)
                        expires = _iso(_now_utc() + timedelta(hours=esc_hours)) if esc_hours > 0 else ""
                        reason = (
                            f"ล็อกอิน {label} ล้มเหลวซ้ำ (ครั้งที่ {prior + 1}) — "
                            f"ขยายบล็อกเป็น {esc_hours} ชม."
                        )

        ok = self.fw.add_block(ip, ports=[p.strip() for p in ports.split(",") if p.strip()] if ports else None)
        reason = reason + ("" if ok else " [FIREWALL ล้มเหลว — ตรวจสิทธิ์ admin]")
        self.db.block_ip(ip, reason=reason, source=source, expires=expires, rule_name=rule_name)
        with self._lock:
            self._attempts.pop((engine, ip), None)
        if ok:
            log.warning("บล็อก IP %s (%s) จนถึง %s", ip, label, expires or "ถาวร")
        else:
            log.error("ไม่สามารถเพิ่ม rule firewall สำหรับ IP %s", ip)
        if self.on_block:
            try:
                self.on_block(ip, source)
            except Exception:
                log.exception("on_block callback ล้มเหลว")
