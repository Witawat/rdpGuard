"""ตัวขับเคลื่อนหลัก: ประสาน multi-engine (engines.py) + detector + firewall cleanup.

- engine หลายตัว (rdp/openssh/mssql/iis/mysql/generic) → detector → บันทึก DB
- cleanup thread: ถอด rule firewall ที่หมดอายุ + ลบออกจากตาราง blocked
"""

import logging
import threading
from datetime import datetime, timedelta, timezone

from . import config as config_mod
from .database import Database
from .detector import BruteForceDetector, is_valid_ip, is_valid_ip_or_cidr
from .engines import ALL_ENGINES
from .firewall import FirewallManager

log = logging.getLogger("RDPGuard.monitor")


class Monitor:
    def __init__(self, cfg=None):
        self.cfg = cfg or config_mod.load_config()
        self.db = Database()
        prefix = config_mod.get(self.cfg, "firewall", "rule_prefix", "RDPGuard Block")
        profile = config_mod.get(self.cfg, "firewall", "profile", "any")
        self.fw = FirewallManager(rule_prefix=prefix, profile=profile)
        ports = config_mod.get(self.cfg, "firewall", "blocked_ports", "").strip()
        self.fw.ports = [p.strip() for p in ports.split(",") if p.strip()] if ports else []
        self.detector = BruteForceDetector(self.db, self.fw, cfg=self.cfg)
        self._engines = []
        self._stop = threading.Event()
        self._cleaner = None
        self.running = False

    def reload(self):
        self.cfg = config_mod.load_config()
        self.detector.reload(self.cfg)
        prefix = config_mod.get(self.cfg, "firewall", "rule_prefix", "RDPGuard Block")
        profile = config_mod.get(self.cfg, "firewall", "profile", "any")
        self.fw.rule_prefix = prefix
        self.fw.profile = profile
        self._restart_engines()
        log.info("โหลด config ใหม่เรียบร้อย")

    def start(self):
        self.running = True
        self._start_engines()
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()
        log.info("RDPGuard monitor เริ่มทำงาน")

    def stop(self):
        self.running = False
        self._stop_engines()
        self._stop.set()
        if self._cleaner:
            self._cleaner.join(timeout=10)
        log.info("RDPGuard monitor หยุดทำงาน")

    def _start_engines(self):
        poll = config_mod.get_int(self.cfg, "monitor", "poll_interval_seconds", 2)
        for engine_cls in ALL_ENGINES:
            try:
                engine = engine_cls(self.cfg, self.detector.handle_event, poll_interval=poll)
                if engine.enabled():
                    engine.start()
                    self._engines.append(engine)
            except Exception:
                log.exception("เริ่ม engine %s ไม่สำเร็จ", getattr(engine_cls, "name", "?"))

    def _stop_engines(self):
        for engine in self._engines:
            try:
                engine.stop()
            except Exception:
                log.exception("หยุด engine %s ไม่สำเร็จ", getattr(engine, "name", "?"))
        self._engines = []

    def _restart_engines(self):
        self._stop_engines()
        self._start_engines()

    def _cleanup_loop(self):
        while not self._stop.wait(60):
            try:
                self._cleanup_once()
            except Exception:
                log.exception("cleanup ล้มเหลว")

    def _cleanup_once(self):
        expired = self.db.expired_blocks()
        for row in expired:
            ip = row["ip"]
            if self.fw.remove_block(ip):
                self.db.unblock_ip(ip, by="expire")
                log.info("บล็อก IP %s หมดอายุ — ปลดบล็อกแล้ว", ip)
        # ฉุกเฉิน: ปลดบล็อก IP ที่อยู่ใน whitelist / never_block_ips (กันล็อกตัวเอง)
        for row in self.db.list_blocked():
            ip = row["ip"]
            if self.db.is_whitelisted(ip) or self.detector._never_block(self.cfg, ip):
                if self.fw.remove_block(ip):
                    self.db.unblock_ip(ip, by="whitelist")
                    log.warning("ปลดบล็อก IP %s (อยู่ใน whitelist/never_block_ips)", ip)

    def unblock_all(self):
        """ปลดบล็อกทั้งหมด (ฉุกเฉิน) — คืนจำนวนที่ปลด"""
        count = 0
        for row in self.db.list_blocked():
            ip = row["ip"]
            ok = self.fw.remove_block(ip)
            self.db.unblock_ip(ip, by="unblock-all")
            count += 1
            log.warning("unblock-all: ปลดบล็อก IP %s (rule ลบ=%s)", ip, "OK" if ok else "FAIL")
        return count

    def allow_ip(self, ip):
        """เพิ่ม whitelist + ปลดบล็อกถ้าถูกบล็อกอยู่ (ฉุกเฉิน)"""
        self.db.add_whitelist(ip, "allow (ฉุกเฉิน)")
        if self.db.is_blocked(ip):
            self.fw.remove_block(ip)
            self.db.unblock_ip(ip, by="allow")
            return True, f"เพิ่ม {ip} ใน whitelist และปลดบล็อกแล้ว"
        return True, f"เพิ่ม {ip} ใน whitelist แล้ว"

    def manual_block(self, ip, hours=24):
        """บล็อก IP ด้วยมือ (จาก Web UI / CLI) — รองรับ IP เดี่ยวหรือ CIDR"""
        if not is_valid_ip_or_cidr(ip):
            return False, "รูปแบบ IP/CIDR ไม่ถูกต้อง"
        if self.db.is_blocked(ip):
            return False, "IP นี้ถูกบล็อกอยู่แล้ว"
        expires = ""
        if hours and hours > 0:
            expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        ports = config_mod.get(self.cfg, "firewall", "blocked_ports", "").strip()
        ok = self.fw.add_block(
            ip, ports=[p.strip() for p in ports.split(",") if p.strip()] if ports else None
        )
        self.db.block_ip(
            ip,
            reason="บล็อกด้วยมือจากผู้ดูแล",
            source="manual",
            expires=expires,
            rule_name=self.fw._rule_name(ip),
        )
        if ok:
            log.warning("บล็อก IP %s ด้วยมือ (manual)", ip)
            return True, "บล็อกเรียบร้อย"
        return False, "เพิ่ม rule firewall ไม่สำเร็จ (ตรวจสิทธิ์ admin)"

    def manual_unblock(self, ip):
        row = self.db.is_blocked(ip)
        if not row:
            return False, "IP นี้ไม่ได้ถูกบล็อก"
        ok = self.fw.remove_block(ip)
        self.db.unblock_ip(ip, by="manual")
        if ok:
            log.info("ปลดบล็อก IP %s (manual)", ip)
            return True, "ปลดบล็อกเรียบร้อย"
        return False, "ลบ rule firewall ไม่สำเร็จ (ตรวจสิทธิ์ admin)"
