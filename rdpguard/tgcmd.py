"""ควบคุม RDPGuard ผ่าน Telegram (Telegram Command Bot).

- worker 1 thread: getUpdates long-polling (offset-based, ไม่ต้องเปิดพอร์ต/HTTPS)
- รับคำสั่งจาก telegram_chat_id ที่ตั้งใน [notify] เท่านั้น
- /unblock-all ต้องยืนยัน /confirm ภายใน confirm_timeout_seconds
- rate limit: rate_limit_per_minute ต่อแชท
- ทุกคำสั่งบันทึก Audit Log (actor = telegram:<chat_id>)
"""

import json
import logging
import os
import random
import ssl
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("RDPGuard.tgcmd")

_HELP = """คำสั่งที่รองรับ (คำตอบทุกข้อขึ้นต้นด้วย [ชื่อเครื่อง]):
/where — ชื่อเครื่องนี้ + เวอร์ชัน
/status — สถานะระบบ
/block <ip> [ชั่วโมง] — บล็อก IP (0 = ถาวร)
/unblock <ip> — ปลดบล็อก
/unblock-all — ปลดบล็อกทุก IP (ต้องยืนยัน /confirm)
/allow <ip> — เพิ่ม whitelist + ปลดบล็อก
/blacklist <ip> — เพิ่ม blacklist + บล็อกทันที
/whitelist <ip> — เพิ่ม whitelist
/list blocked|white|black — ดูรายการล่าสุด
/events [n] — เหตุการณ์ล่าสุด (สูงสุด 20)
/log [บรรทัด] — ดู log ท้ายสุด (สูงสุด 50)
/ping — ตรวจ bot
/help — รายการคำสั่ง

ใช้หลายเครื่องกับ bot เดียว: ต่อท้าย @ชื่อเครื่อง เช่น /status @srv-a
เครื่องอื่นที่ไม่ใช่เป้า จะไม่ลงมือทำ — ส่งซ้ำจนกว่าคำตอบจะมาจากเครื่องที่ต้องการ
(คำสั่งที่ส่งไป จะตกที่เครื่องใดเครื่องหนึ่งแบบสุ่ม)"""


class TelegramCommandBot:
    def __init__(self, monitor, cfg=None, notifier=None):
        self.monitor = monitor
        self.cfg = cfg
        self.notifier = notifier
        self._stop = threading.Event()
        self._thread = None
        self._offset = 0
        self._confirm = {}  # chat_id -> expiry (epoch)
        self._rate = {}  # chat_id -> [timestamps]
        self._last_command = ""
        self._last_result = ""
        self._last_ts = 0.0
        self._lock = threading.Lock()

    # ---- config ----

    def _config(self):
        from . import config as config_mod

        return self.cfg or config_mod.load_config()

    # ---- lifecycle ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="tgcmd")
        self._thread.start()
        log.info("Telegram Command เริ่ม polling")

    def stop(self):
        self._stop.set()

    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def status(self):
        from . import config as config_mod

        cfg = self._config()
        return {
            "enabled": config_mod.get_bool(cfg, "notify", "enable_commands", False),
            "running": self.running(),
            "configured": bool(config_mod.get(cfg, "notify", "telegram_bot_token", "").strip()),
            "chat_id": config_mod.get(cfg, "notify", "telegram_chat_id", "").strip(),
            "last_command": self._last_command,
            "last_result": self._last_result,
            "last_ts": self._last_ts,
        }

    # ---- Telegram API ----

    def _api_base(self):
        from . import config as config_mod

        token = config_mod.get(self._config(), "notify", "telegram_bot_token", "").strip()
        return f"https://api.telegram.org/bot{token}"

    def _call(self, method, payload):
        from . import config as config_mod

        verify = config_mod.get_bool(self._config(), "notify", "telegram_verify_ssl", True)
        ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
        req = urllib.request.Request(
            self._api_base() + "/" + method,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))

    # ---- worker ----

    def _run(self):
        try:
            self._call("deleteWebhook", {})
        except Exception:
            log.debug("deleteWebhook ไม่สำเร็จ", exc_info=True)
        while not self._stop.wait(0):
            try:
                # staggered polling (หลายเครื่อง / bot เดียว): เช็คสิทธิ์ด้วย timeout
                # สั้นก่อน — ถ้าอีกเครื่องถือสิทธิ์รับคำสั่งอยู่ (HTTP 409) จะได้รู้ไว
                # แล้วรอสุ่มช่วง config เพื่อเปิดโอกาสให้อีกเครื่องรับคำสั่งบ้าง
                result = self._call("getUpdates", {"offset": self._offset, "timeout": 1})
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    wait = self._conflict_wait()
                    log.info("Telegram Command bot ถูกใช้ที่อื่น (409) — ลองใหม่ใน %.0f วิ", wait)
                    time.sleep(wait)
                    continue
                log.warning("Telegram Command polling error: %s", exc)
                time.sleep(5)
                continue
            except Exception as exc:
                log.warning("Telegram Command polling error: %s", exc)
                time.sleep(5)
                continue
            if not result.get("ok"):
                time.sleep(5)
                continue
            self._drain_updates(result)
            # ได้สิทธิ์แล้ว — รับคำสั่งแบบ timeout ยาว จนกว่าจะโดนแย่ง/error
            try:
                result = self._call("getUpdates", {"offset": self._offset, "timeout": 25})
                if result.get("ok"):
                    self._drain_updates(result)
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    wait = self._conflict_wait()
                    log.info("Telegram Command bot ถูกใช้ที่อื่น (409) — ลองใหม่ใน %.0f วิ", wait)
                    time.sleep(wait)
            except Exception as exc:
                log.warning("Telegram Command polling error: %s", exc)
                time.sleep(5)

    def _drain_updates(self, result):
        """ประมวลผลอัปเดตที่ได้จาก getUpdates — ขยับ offset และรับคำสั่ง"""
        for update in result.get("result", []):
            self._offset = max(self._offset, int(update.get("update_id", 0)) + 1)
            message = update.get("message") or {}
            text = str(message.get("text") or "").strip()
            chat = message.get("chat") or {}
            chat_id = str(chat.get("id") or "")
            if text.startswith("/"):
                self._handle_command(chat_id, text)

    def _conflict_wait(self):
        """รอสุ่มระหว่าง poll_retry_min/max_seconds ก่อนลอง poll ใหม่หลังเจอ 409"""
        from . import config as config_mod

        low = max(1, config_mod.get_int(self._config(), "notify", "poll_retry_min_seconds", 15))
        high = max(low, config_mod.get_int(self._config(), "notify", "poll_retry_max_seconds", 45))
        return random.uniform(low, high)

    # ---- auth / rate / confirm ----

    def _handle_command(self, chat_id, text):
        from . import config as config_mod

        cfg = self._config()
        expected = str(config_mod.get(cfg, "notify", "telegram_chat_id", "")).strip()
        if not expected or chat_id != expected:
            log.info(
                "Telegram Command จาก chat %s ถูกปฏิเสธ (ไม่ตรงกับ telegram_chat_id)", chat_id
            )
            return
        if not self._rate_ok(chat_id):
            self._reply(chat_id, "ส่งคำสั่งถี่เกินไป — ลองใหม่ในอีกสักครู่")
            return
        parts = text.split()
        command = parts[0].lower()
        args = parts[1:]
        target = self._extract_target(args, cfg)
        if target:
            self_name = config_mod.machine_name(cfg)
            if target.lower() != self_name.lower():
                self._reply(
                    chat_id,
                    f"นี่คือเครื่อง [{self_name}] — คำสั่งนี้ระบุ [{target}] เลยไม่ลงมือทำ",
                )
                return
        with self._lock:
            self._last_command = command
            self._last_ts = time.time()
        try:
            reply, action = self._dispatch(command, args, chat_id)
        except Exception as exc:
            log.exception("Telegram Command %s ล้มเหลว", command)
            reply, action = f"ทำงานไม่สำเร็จ: {exc}", command
        with self._lock:
            self._last_result = reply[:200]
        self._reply(chat_id, reply)
        if action:
            self._audit(chat_id, action, args)

    def _extract_target(self, args, cfg=None):
        """หา @ชื่อเครื่อง ใน args — คืนชื่อเป้า (None ถ้าไม่มี) และลบ @xxx ออกจาก args"""
        target = None
        keep = []
        for token in args:
            if token.startswith("@"):
                target = token[1:]
            else:
                keep.append(token)
        args[:] = keep
        return target

    def _audit(self, chat_id, action, args=()):
        if not self.monitor:
            return
        try:
            self.monitor.db.add_audit(
                f"telegram:{chat_id}", action, " ".join(args)[:200], "ok", ""
            )
        except Exception:
            log.debug("บันทึก audit ไม่สำเร็จ", exc_info=True)

    def _rate_ok(self, chat_id):
        from . import config as config_mod

        limit = max(1, config_mod.get_int(self._config(), "notify", "rate_limit_per_minute", 10))
        now = time.time()
        with self._lock:
            stamps = [t for t in self._rate.get(chat_id, []) if now - t < 60]
            if len(stamps) >= limit:
                self._rate[chat_id] = stamps
                return False
            stamps.append(now)
            self._rate[chat_id] = stamps
            return True

    def _set_confirm(self, chat_id):
        from . import config as config_mod

        timeout = max(
            5, config_mod.get_int(self._config(), "notify", "confirm_timeout_seconds", 60)
        )
        with self._lock:
            self._confirm[chat_id] = time.time() + timeout

    def _confirm_ok(self, chat_id):
        with self._lock:
            expiry = self._confirm.pop(chat_id, 0)
            return bool(expiry and time.time() < expiry)

    def _reply(self, chat_id, text):
        if not self.notifier:
            return
        try:
            from . import config as config_mod

            prefix = f"[{config_mod.machine_name(self._config())}] "
            self.notifier.send_reply(prefix + str(text))
        except Exception as exc:
            log.warning("ส่งคำตอบ Telegram ไม่สำเร็จ: %s", exc)

    # ---- dispatch ----

    def _dispatch(self, command, args, chat_id):
        if command == "/help":
            return _HELP, ""
        if command == "/ping":
            return self._cmd_ping(), ""
        if command == "/where":
            return self._cmd_where(), ""
        if command == "/status":
            return self._cmd_status(), ""
        if command == "/block":
            return self._cmd_block(args), "block"
        if command == "/unblock":
            return self._cmd_unblock(args), "unblock"
        if command == "/unblock-all":
            if self._confirm_ok(chat_id):
                return self._cmd_unblock_all(), "unblock-all"
            self._set_confirm(chat_id)
            return "ต้องการปลดบล็อกทุก IP ใช่ไหม? ตอบ /confirm ภายใน 60 วินาที", ""
        if command == "/confirm":
            if self._confirm_ok(chat_id):
                return self._cmd_unblock_all(), "unblock-all"
            return "ไม่มีคำสั่งที่รอการยืนยัน", ""
        if command == "/allow":
            return self._cmd_allow(args), "allow"
        if command == "/blacklist":
            return self._cmd_blacklist(args), "blacklist-add"
        if command == "/whitelist":
            return self._cmd_whitelist(args), "whitelist-add"
        if command == "/list":
            return self._cmd_list(args), ""
        if command == "/events":
            return self._cmd_events(args), ""
        if command == "/log":
            return self._cmd_log(args), ""
        return "ไม่รู้จักคำสั่ง — พิมพ์ /help", ""

    # ---- commands ----

    def _cmd_ping(self):
        from . import __version__

        return f"pong — RDPGuard v{__version__} ทำงาน"

    def _cmd_where(self):
        from . import __version__
        from . import config as config_mod

        return f"ชื่อเครื่อง: {config_mod.machine_name(self._config())} — RDPGuard v{__version__}"

    def _cmd_status(self):
        from . import __version__
        from . import config as config_mod

        monitor = self.monitor
        if not monitor:
            return "Monitor ไม่ได้รัน (โหมด web)"
        cfg = self._config()
        stats = monitor.db.stats()
        engines_ok, total = 0, 0
        try:
            from . import engines as engines_mod

            source = engines_mod.source_status(cfg)
            total = len(source)
            engines_ok = sum(1 for value in source.values() if value == "ok")
        except Exception:
            pass
        port = config_mod.get_int(cfg, "webui", "port", 8123)
        watch = "เปิด" if config_mod.get_bool(cfg, "monitor", "enable", True) else "ปิด"
        return "\n".join(
            [
                f"RDPGuard v{__version__} — เครื่อง [{config_mod.machine_name(cfg)}]",
                f"Monitor: {'กำลังรัน' if monitor.running else 'ไม่ได้รัน'} · เฝ้าระวัง: {watch}",
                f"Engine พร้อม: {engines_ok}/{total}",
                f"ล้มเหลว 24 ชม.: {stats['failed_24h']} · สำเร็จ: {stats['success_24h']}",
                f"บล็อกอยู่: {stats['blocked_active']} · รวม: {stats['blocked_total']}",
                f"Web UI: http://127.0.0.1:{port}",
            ]
        )

    def _cmd_block(self, args):
        if not args:
            return "ใช้งาน: /block <ip> [ชั่วโมง] (0 = ถาวร)"
        ip = args[0]
        try:
            hours = int(args[1]) if len(args) > 1 else 24
        except ValueError:
            return "ชั่วโมงต้องเป็นตัวเลข"
        if hours < 0 or hours > 87600:
            return "ชั่วโมงต้องอยู่ระหว่าง 0 ถึง 87600"
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        ok, message = self.monitor.manual_block(ip, hours)
        return ("OK: " if ok else "FAIL: ") + message

    def _cmd_unblock(self, args):
        if not args:
            return "ใช้งาน: /unblock <ip>"
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        ok, message = self.monitor.manual_unblock(args[0])
        return ("OK: " if ok else "FAIL: ") + message

    def _cmd_unblock_all(self):
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        return "OK: " + self.monitor.unblock_all()

    def _cmd_allow(self, args):
        if not args:
            return "ใช้งาน: /allow <ip>"
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        ok, message = self.monitor.allow_ip(args[0])
        return ("OK: " if ok else "FAIL: ") + message

    def _cmd_blacklist(self, args):
        from .detector import is_valid_ip_or_cidr

        if not args:
            return "ใช้งาน: /blacklist <ip>"
        ip = args[0]
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        if not is_valid_ip_or_cidr(ip):
            return "รูปแบบ IP/CIDR ไม่ถูกต้อง"
        if not self.monitor.db.add_blacklist(ip, "telegram"):
            return "IP นี้อยู่ใน blacklist แล้ว"
        ok, message = self.monitor.blacklist_block(ip)
        return ("OK: " if ok else "FAIL: ") + message

    def _cmd_whitelist(self, args):
        from .detector import is_valid_ip_or_cidr

        if not args:
            return "ใช้งาน: /whitelist <ip>"
        ip = args[0]
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        if not is_valid_ip_or_cidr(ip):
            return "รูปแบบ IP/CIDR ไม่ถูกต้อง"
        if not self.monitor.db.add_whitelist(ip, "telegram"):
            return "IP นี้อยู่ใน whitelist แล้ว"
        if self.monitor.db.is_blocked(ip):
            ok, message = self.monitor.manual_unblock(ip)
            if not ok:
                return "FAIL: " + message
            return f"OK: เพิ่ม {ip} ใน whitelist และปลดบล็อกแล้ว"
        return f"OK: เพิ่ม {ip} ใน whitelist แล้ว"

    def _cmd_list(self, args):
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        kind = (args[0] if args else "blocked").lower()
        if kind in ("blocked", "block"):
            rows = self.monitor.db.list_blocked()[:20]
            if not rows:
                return "ไม่มี IP ถูกบล็อก"
            return "\n".join(
                f"• {r['ip']} ({r['source']}) หมดอายุ: {r.get('expires') or 'ถาวร'}"
                for r in rows
            )
        if kind in ("white", "whitelist"):
            rows = self.monitor.db.list_whitelist()[:20]
            if not rows:
                return "ไม่มี whitelist"
            return "\n".join(f"• {r['ip']}" for r in rows)
        if kind in ("black", "blacklist"):
            rows = self.monitor.db.list_blacklist()[:20]
            if not rows:
                return "ไม่มี blacklist"
            return "\n".join(f"• {r['ip']}" for r in rows)
        return "ใช้งาน: /list blocked|white|black"

    def _cmd_events(self, args):
        if not self.monitor:
            return "Monitor ไม่ได้รัน"
        try:
            count = max(1, min(int(args[0]) if args else 5, 20))
        except ValueError:
            return "จำนวนต้องเป็นตัวเลข"
        rows, _total = self.monitor.db.query_events(limit=count)
        if not rows:
            return "ยังไม่มีเหตุการณ์"
        lines = []
        for row in rows:
            lines.append(
                f"{row['ts'][:19]} {row['kind']} {row.get('ip') or '-'} "
                f"{row.get('user') or '-'} ({row.get('source') or '-'})"
            )
        return "\n".join(lines)

    def _cmd_log(self, args):
        from . import config as config_mod

        try:
            count = max(1, min(int(args[0]) if args else 20, 50))
        except ValueError:
            return "จำนวนต้องเป็นตัวเลข"
        path = config_mod.LOG_FILE
        if not os.path.isfile(path):
            return "(ไม่มีไฟล์ log)"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as source:
                source.seek(0, os.SEEK_END)
                size = source.tell()
                chunk = min(size, 64 * 1024)
                source.seek(max(0, size - chunk))
                data = source.read()
            lines = data.splitlines()[-count:]
        except Exception as exc:
            return f"อ่าน log ไม่ได้: {exc}"
        return "\n".join(lines) or "(log ว่างเปล่า)"
