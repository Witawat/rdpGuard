"""SQLite persistence: เหตุการณ์, IP ที่ถูกบล็อก, whitelist/blacklist, ประวัติ.

thread-safe ผ่าน lock ตัวเดียว (webui + monitor ใช้ร่วมกัน).
"""

import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from . import config as config_mod

log = logging.getLogger("RDPGuard.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    ip TEXT DEFAULT '',
    user TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    logon_type INTEGER DEFAULT 0
);CREATE TABLE IF NOT EXISTS blocked(
    ip TEXT PRIMARY KEY,
    reason TEXT DEFAULT '',
    source TEXT DEFAULT 'auto',
    created TEXT NOT NULL,
    expires TEXT DEFAULT '',
    rule_name TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS blocked_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT DEFAULT '',
    source TEXT DEFAULT 'auto',
    created TEXT NOT NULL,
    expires TEXT DEFAULT '',
    unblocked_at TEXT DEFAULT '',
    unblocked_by TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS whitelist(
    ip TEXT PRIMARY KEY,
    note TEXT DEFAULT '',
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blacklist(
    ip TEXT PRIMARY KEY,
    note TEXT DEFAULT '',
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS geoip_cache(
    ip TEXT PRIMARY KEY,
    code TEXT DEFAULT '',
    country TEXT DEFAULT '',
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accumulate(
    ip TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 1,
    first_ts TEXT NOT NULL,
    last_ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_blocked_history_created ON blocked_history(created);
CREATE INDEX IF NOT EXISTS idx_accumulate_last_ts ON accumulate(last_ts);
"""


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ip_matches(entry, ip):
    """match แบบ IP เดี่ยว หรือ CIDR (เช่น 192.168.1.0/24)"""
    entry = (entry or "").strip()
    if not entry:
        return False
    if entry == ip:
        return True
    if "/" in entry:
        try:
            import ipaddress

            return ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    return False


def _parse_iso(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


class Database:
    def __init__(self, db_file=None):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_file or config_mod.DB_FILE, check_same_thread=False)
        # WAL: เขียน-อ่านพร้อมกันจากหลาย thread (engine/webui/cleanup) ไม่ติด lock กัน
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate()

    def _migrate(self):
        with self._lock:
            cols = [row[1] for row in self._conn.execute("PRAGMA table_info(events)")]
            if "source" not in cols:
                self._conn.execute("ALTER TABLE events ADD COLUMN source TEXT DEFAULT ''")
                self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()

    def _execute(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in rows]

    def add_event(self, kind, ip="", user="", domain="", logon_type=0, source=""):
        self._execute(
            "INSERT INTO events(ts, kind, ip, user, domain, logon_type, source) VALUES(?,?,?,?,?,?,?)",
            (_now_iso(), kind, ip or "", user or "", domain or "", int(logon_type or 0), source or ""),
        )

    def delete_events_by_user(self, user):
        """ลบเหตุการณ์ที่มี user ระบุ (ใช้ล้างเหตุการณ์จาก self-test)"""
        self._execute("DELETE FROM events WHERE user=?", (user,))

    def recent_events(self, limit=100):
        return self._query(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (int(limit),)
        )

    def stats(self, since_hours=24):
        since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        failed = self._query(
            "SELECT COUNT(*) AS n FROM events WHERE kind='fail' AND ts >= ?", (since,)
        )[0]["n"]
        success = self._query(
            "SELECT COUNT(*) AS n FROM events WHERE kind='success' AND ts >= ?",
            (since,),
        )[0]["n"]
        active = self._query("SELECT COUNT(*) AS n FROM blocked")[0]["n"]
        history = self._query("SELECT COUNT(*) AS n FROM blocked_history")[0]["n"]
        manual = self._query(
            "SELECT COUNT(*) AS n FROM blocked WHERE source='manual'"
        )[0]["n"]
        return {
            "failed_24h": failed,
            "success_24h": success,
            "blocked_active": active,
            "blocked_total": history + active,
            "blocked_manual": manual,
        }

    def block_ip(self, ip, reason="", source="auto", expires=None, rule_name=""):
        now = _now_iso()
        if expires is None:
            expires = ""
        self._execute(
            "INSERT OR REPLACE INTO blocked(ip, reason, source, created, expires, rule_name) "
            "VALUES(?,?,?,?,?,?)",
            (ip, reason, source, now, expires, rule_name),
        )
        return True

    def extend_block(self, ip, expires):
        self._execute(
            "UPDATE blocked SET expires=? WHERE ip=?", (expires, ip)
        )

    def is_blocked(self, ip):
        rows = self._query("SELECT * FROM blocked WHERE ip=?", (ip,))
        return rows[0] if rows else None

    def list_blocked(self):
        return self._query("SELECT * FROM blocked ORDER BY created DESC")

    def expired_blocks(self):
        rows = self.list_blocked()
        result = []
        for row in rows:
            exp = _parse_iso(row.get("expires") or "")
            if exp and exp <= datetime.now(timezone.utc):
                result.append(row)
        return result

    def unblock_ip(self, ip, by="manual"):
        with self._lock:
            cur = self._conn.execute("SELECT * FROM blocked WHERE ip=?", (ip,))
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            self._conn.execute("DELETE FROM blocked WHERE ip=?", (ip,))
            self._conn.commit()
        if rows:
            row = dict(zip(cols, rows[0]))
            self._execute(
                "INSERT INTO blocked_history(ip, reason, source, created, expires, unblocked_at, unblocked_by) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    row["ip"],
                    row.get("reason", ""),
                    row.get("source", "auto"),
                    row.get("created", ""),
                    row.get("expires", ""),
                    _now_iso(),
                    by,
                ),
            )
            return row
        return None

    def is_whitelisted(self, ip):
        rows = self._query("SELECT ip FROM whitelist")
        return any(_ip_matches(row["ip"], ip) for row in rows)

    def is_blacklisted(self, ip):
        rows = self._query("SELECT ip FROM blacklist")
        return any(_ip_matches(row["ip"], ip) for row in rows)

    def recent_success(self, ip, minutes=30):
        """มีล็อกอินสำเร็จ (4624) จาก IP นี้ภายในกี่นาทีล่าสุดไหม"""
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        row = self._query(
            "SELECT COUNT(*) AS n FROM events WHERE kind='success' AND ip=? AND ts >= ?",
            (ip, since),
        )
        return row[0]["n"] > 0

    def count_prior_blocks(self, ip, since_iso):
        """จำนวนครั้งที่ IP นี้เคยโดนบล็อก (จากประวัติ blocked_history) ตั้งแต่ since_iso"""
        row = self._query(
            "SELECT COUNT(*) AS n FROM blocked_history WHERE ip=? AND created >= ?",
            (ip, since_iso),
        )
        return row[0]["n"]

    # ---- ตัวนับสะสม (ยิงสั้น ๆ แล้วหนี) ----

    def accumulate_add(self, ip):
        """เพิ่มตัวนับสะสมของ IP — คืนจำนวนรวมใหม่ (row เก่าที่เงียบเกิน window ลบโดย cleanup)"""
        now = _now_iso()
        with self._lock:
            row = self._conn.execute(
                "SELECT count, first_ts FROM accumulate WHERE ip=?", (ip,)
            ).fetchone()
            if row:
                new_count = row[0] + 1
                self._conn.execute(
                    "UPDATE accumulate SET count=?, last_ts=? WHERE ip=?",
                    (new_count, now, ip),
                )
            else:
                new_count = 1
                self._conn.execute(
                    "INSERT INTO accumulate(ip, count, first_ts, last_ts) VALUES(?,?,?,?)",
                    (ip, new_count, now, now),
                )
            self._conn.commit()
        return new_count

    def accumulate_reset(self, ip):
        """ล้างตัวนับสะสม (เช่น IP ล็อกอินสำเร็จ — ผู้ใช้จริงกลับมาแล้ว)"""
        self._execute("DELETE FROM accumulate WHERE ip=?", (ip,))

    def accumulate_cleanup(self, window_hours):
        """ลบตัวนับสะสมที่เงียบเกินกรอบเวลา (ชั่วโมง) — คืนจำนวนที่ลบ"""
        if window_hours <= 0:
            return 0
        since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cur = self._execute("DELETE FROM accumulate WHERE last_ts < ?", (since,))
        return cur.rowcount

    def add_whitelist(self, ip, note=""):
        try:
            self._execute(
                "INSERT INTO whitelist(ip, note, created) VALUES(?,?,?)",
                (ip, note, _now_iso()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_whitelist(self, ip):
        self._execute("DELETE FROM whitelist WHERE ip=?", (ip,))

    def list_whitelist(self):
        return self._query("SELECT * FROM whitelist ORDER BY created DESC")

    def add_blacklist(self, ip, note=""):
        try:
            self._execute(
                "INSERT INTO blacklist(ip, note, created) VALUES(?,?,?)",
                (ip, note, _now_iso()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_blacklist(self, ip):
        self._execute("DELETE FROM blacklist WHERE ip=?", (ip,))

    def list_blacklist(self):
        return self._query("SELECT * FROM blacklist ORDER BY created DESC")

    # ---- geoip cache ----

    def get_geoip(self, ip):
        rows = self._query("SELECT code, country FROM geoip_cache WHERE ip=?", (ip,))
        return (rows[0]["code"], rows[0]["country"]) if rows else None

    def set_geoip(self, ip, code, country):
        self._execute(
            "INSERT OR REPLACE INTO geoip_cache(ip, code, country, ts) VALUES(?,?,?,?)",
            (ip, code or "", country or "", _now_iso()),
        )

    def cleanup_geoip(self, max_age_days=30, max_rows=10000):
        """จำกัดขนาด geoip_cache: ลบ entry เก่าเกินกำหนด + ถ้าเกินจำนวนสูงสุด ลบของเก่าสุด"""
        since = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self._execute("DELETE FROM geoip_cache WHERE ts < ?", (since,))
        count = self._query("SELECT COUNT(*) AS n FROM geoip_cache")[0]["n"]
        if count > max_rows:
            excess = count - max_rows
            self._execute(
                "DELETE FROM geoip_cache WHERE rowid IN "
                "(SELECT rowid FROM geoip_cache ORDER BY ts ASC LIMIT ?)",
                (excess,),
            )
