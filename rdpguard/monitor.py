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
        self._apply_fw_config()
        self.notifier = None
        self._init_notifier()
        self.tg = None
        self.detector = BruteForceDetector(self.db, self.fw, cfg=self.cfg, on_block=self._on_block)
        self._engines = []
        self._stop = threading.Event()
        self._cleaner = None
        self.running = False

    def _init_notifier(self):
        from .notify import Notifier

        self.notifier = Notifier(self.cfg)

    def _on_block(self, ip, source, reason="", expires=""):
        """detector บล็อก IP แล้ว — ส่งการแจ้งเตือน (ถ้าเปิด)"""
        try:
            if self.notifier:
                self.notifier.notify_block(ip, source, reason, expires)
        except Exception:
            log.exception("เรียก notifier ล้มเหลว")

    def _apply_fw_config(self):
        prefix = config_mod.get(self.cfg, "firewall", "rule_prefix", "RDPGuard Block")
        profile = config_mod.get(self.cfg, "firewall", "profile", "any")
        self.fw = FirewallManager(rule_prefix=prefix, profile=profile)
        ports = config_mod.get(self.cfg, "firewall", "blocked_ports", "").strip()
        self.fw.ports = [p.strip() for p in ports.split(",") if p.strip()] if ports else []
        self.fw.single_rule = config_mod.get_bool(self.cfg, "firewall", "single_rule", True)

    def reload(self):
        self.cfg = config_mod.load_config()
        self.detector.reload(self.cfg)
        self._apply_fw_config()
        if self.notifier:
            self.notifier.reload(self.cfg)
        if config_mod.get_bool(self.cfg, "notify", "enable_commands", False):
            if not (self.tg and self.tg.running()):
                self._start_tg()
        elif self.tg:
            self.tg.stop()
        self._restart_engines()
        log.info("โหลด config ใหม่เรียบร้อย")

    def start(self):
        self.running = True
        self._start_engines()
        self._start_tg()
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()
        log.info("RDPGuard monitor เริ่มทำงาน")

    def stop(self):
        self.running = False
        self._stop_engines()
        if self.tg:
            self.tg.stop()
        self._stop.set()
        if self._cleaner:
            self._cleaner.join(timeout=10)
        log.info("RDPGuard monitor หยุดทำงาน")

    def _start_tg(self):
        if not config_mod.get_bool(self.cfg, "notify", "enable_commands", False):
            return
        if not (self.notifier and self.notifier.configured()):
            log.warning("Telegram Command เปิดอยู่ แต่ Telegram ยังไม่ได้ตั้งค่า")
            return
        if not self.tg:
            from .tgcmd import TelegramCommandBot

            self.tg = TelegramCommandBot(self, cfg=self.cfg, notifier=self.notifier)
        self.tg.start()

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
        self.db.accumulate_cleanup(
            config_mod.get_int(self.cfg, "detection", "accumulate_window_hours", 0)
        )
        self.db.cleanup_geoip()
        removed = self.db.cleanup_retention(
            event_days=config_mod.get_int(self.cfg, "general", "event_retention_days", 90),
            history_days=config_mod.get_int(self.cfg, "general", "history_retention_days", 365),
            audit_days=config_mod.get_int(self.cfg, "general", "audit_retention_days", 365),
        )
        if any(removed.values()):
            log.info("ล้างข้อมูลตาม retention: %s", removed)
        expired = self.db.expired_blocks()
        for row in expired:
            ip = row["ip"]
            if self.fw.remove_block(ip):
                self.db.unblock_ip(ip, by="expire")
                log.info("บล็อก IP %s หมดอายุ — ปลดบล็อกแล้ว", ip)
        # refresh รายการ IP ใน single rule จาก firewall จริง ก่อน reconcile
        # (กัน _cache เก่าค้างเมื่อ firewall ถูกรีเซ็ต/แก้จากภายนอก → มองไม่เห็นว่า rule หาย)
        self.fw.sync()
        # ฉุกเฉิน: ปลดบล็อก IP ที่อยู่ใน whitelist / never_block_ips (กันล็อกตัวเอง)
        for row in self.db.list_blocked():
            ip = row["ip"]
            if self.db.is_whitelisted(ip) or self.detector._never_block(self.cfg, ip):
                if self.fw.remove_block(ip):
                    self.db.unblock_ip(ip, by="whitelist")
                    log.warning("ปลดบล็อก IP %s (อยู่ใน whitelist/never_block_ips)", ip)
                continue
            # firewall reconcile: DB บอก blocked แต่ rule ใน firewall หาย (ถูกลบ/รีเซ็ต) → สร้างกลับ
            if not self.fw.rule_exists(ip):
                ports = config_mod.get(self.cfg, "firewall", "blocked_ports", "").strip()
                ok = self.fw.add_block(
                    ip,
                    ports=[p.strip() for p in ports.split(",") if p.strip()] if ports else None,
                )
                log.warning(
                    "firewall reconcile: สร้าง rule กลับให้ %s (DB มีแต่ firewall ไม่มี) — %s",
                    ip,
                    "OK" if ok else "FAIL",
                )

    def unblock_all(self):
        """ปลดบล็อกทั้งหมด (ฉุกเฉิน) — คืนจำนวนที่ปลดสำเร็จ (DB ถูกลบเฉพาะที่ firewall ปลดได้จริง)"""
        count = 0
        failed = 0
        for row in self.db.list_blocked():
            ip = row["ip"]
            ok = self.fw.remove_block(ip)
            if ok:
                self.db.unblock_ip(ip, by="unblock-all")
                count += 1
                log.warning("unblock-all: ปลดบล็อก IP %s (rule ลบ=OK)", ip)
            else:
                failed += 1
                log.error(
                    "unblock-all: ลบ rule firewall ของ %s ไม่สำเร็จ — ยังอยู่ในตาราง blocked",
                    ip,
                )
        if failed:
            return f"{count} IP ปลดแล้ว แต่ {failed} IP ลบ rule ไม่สำเร็จ (ตรวจสิทธิ์ admin/service แล้วลองใหม่)"
        return f"ปลดบล็อกทั้งหมดแล้ว ({count} IP)"

    def allow_ip(self, ip):
        """เพิ่ม whitelist + ปลดบล็อกถ้าถูกบล็อกอยู่ (ฉุกเฉิน)"""
        self.db.add_whitelist(ip, "allow (ฉุกเฉิน)")
        if self.db.is_blocked(ip):
            if self.fw.remove_block(ip):
                self.db.unblock_ip(ip, by="allow")
                return True, f"เพิ่ม {ip} ใน whitelist และปลดบล็อกแล้ว"
            return False, f"เพิ่ม {ip} ใน whitelist แล้ว แต่ลบ Firewall rule ไม่สำเร็จ"
        return True, f"เพิ่ม {ip} ใน whitelist แล้ว"

    def blacklist_block(self, ip):
        """เพิ่ม blacklist แล้วบล็อก IP นั้นทันที (สร้าง rule firewall เลย ไม่รอให้โจมตี)"""
        if not is_valid_ip_or_cidr(ip):
            return False, "รูปแบบ IP/CIDR ไม่ถูกต้อง"
        if self.db.is_blocked(ip):
            return True, "IP นี้ถูกบล็อกอยู่แล้ว"
        hours = config_mod.get_int(self.cfg, "detection", "block_hours", 24)
        expires = ""
        if hours > 0:
            expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        ports = config_mod.get(self.cfg, "firewall", "blocked_ports", "").strip()
        ok = self.fw.add_block(
            ip, ports=[p.strip() for p in ports.split(",") if p.strip()] if ports else None
        )
        self.db.block_ip(
            ip,
            reason="IP อยู่ใน blacklist — บล็อกทันที",
            source="blacklist",
            expires=expires,
            rule_name=self.fw._rule_name(ip),
        )
        if ok:
            log.warning("blacklist: บล็อก IP %s ทันที (จนถึง %s)", ip, expires or "ถาวร")
            return True, "เพิ่ม blacklist + บล็อกทันทีแล้ว"
        log.error("blacklist: เพิ่ม rule firewall สำหรับ %s ล้มเหลว", ip)
        return False, "เพิ่ม blacklist แล้ว แต่สร้าง rule firewall ไม่ได้ (สิทธิ์ admin/service) — จะบล็อกให้เมื่อ IP นั้นพยายามโจมตี"

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
        if ok:
            self.db.unblock_ip(ip, by="manual")
            log.info("ปลดบล็อก IP %s (manual)", ip)
            return True, "ปลดบล็อกเรียบร้อย"
        return False, "ลบ rule firewall ไม่สำเร็จ (ตรวจสิทธิ์ admin)"
