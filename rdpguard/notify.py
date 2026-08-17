"""แจ้งเตือนเมื่อบล็อก IP — Telegram bot + SMTP email.

- queue + worker thread (ไม่บล็อกการบล็อก)
- cooldown: กันสแปมตอนโจมตีหนัก — ข้อความที่เข้ามาระหว่าง cooldown ถูกรวมส่งเป็นชุดเดียว
- retry 2 ครั้ง (network ขัดข้อง)
"""

import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.request
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr

log = logging.getLogger("RDPGuard.notify")

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
_MAX_RETRY = 2


class Notifier:
    def __init__(self, cfg=None):
        self.cfg = cfg
        self._q = queue.Queue()
        self._last_sent = 0.0
        self._lock = threading.Lock()
        self._worker = threading.Thread(target=self._run, daemon=True, name="notify")
        self._worker.start()

    def reload(self, cfg):
        self.cfg = cfg

    # ---- config helpers ----

    def _cfg(self):
        from . import config as config_mod

        return self.cfg or config_mod.load_config()

    def _get(self, key, fallback=""):
        from . import config as config_mod

        return config_mod.get(self._cfg(), "notify", key, fallback)

    def enabled(self):
        from . import config as config_mod

        return config_mod.get_bool(self._cfg(), "notify", "enable", False)

    def _channels(self):
        """ช่องทางที่เลือก: both (ค่าเริ่มต้น) / telegram / email — คืน set"""
        from . import config as config_mod

        raw = config_mod.get(self._cfg(), "notify", "channel", "both").strip().lower()
        if raw == "telegram":
            return {"telegram"}
        if raw == "email":
            return {"email"}
        return {"telegram", "email"}

    def configured(self):
        """มีช่องทางใดช่องทางหนึ่งพร้อมใช้ไหม"""
        from . import config as config_mod

        cfg = self._cfg()
        tg_ok = bool(
            config_mod.get(cfg, "notify", "telegram_bot_token", "").strip()
            and config_mod.get(cfg, "notify", "telegram_chat_id", "").strip()
        )
        smtp_ok = bool(
            config_mod.get(cfg, "notify", "smtp_host", "").strip()
            and config_mod.get(cfg, "notify", "smtp_to", "").strip()
        )
        return tg_ok or smtp_ok

    # ---- public API ----

    def notify_block(self, ip, source, reason="", expires=""):
        """เรียกเมื่อบล็อก IP — เข้าคิว (worker รวม + ส่งตาม cooldown)"""
        if not self.enabled():
            return
        self._q.put({"ip": ip, "source": source, "reason": reason, "expires": expires})

    def test(self):
        """ส่งข้อความทดสอบตามช่องทางที่เลือก — คืนรายงาน {telegram, email}"""
        results = {}
        channels = self._channels()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        body = f"RDPGuard v{_version()} — ข้อความทดสอบจากระบบแจ้งเตือน ({now})"
        if "telegram" in channels:
            if self._get("telegram_bot_token").strip() and self._get("telegram_chat_id").strip():
                ok, err = self._send_telegram(body)
                results["telegram"] = "ok" if ok else f"ล้มเหลว: {err}"
            else:
                results["telegram"] = "ไม่ได้ตั้งค่า"
        else:
            results["telegram"] = "ไม่ได้เลือกช่องนี้"
        if "email" in channels:
            if self._get("smtp_host").strip() and self._get("smtp_to").strip():
                ok, err = self._send_email("RDPGuard — ทดสอบการแจ้งเตือน", body)
                results["email"] = "ok" if ok else f"ล้มเหลว: {err}"
            else:
                results["email"] = "ไม่ได้ตั้งค่า"
        else:
            results["email"] = "ไม่ได้เลือกช่องนี้"
        return results

    # ---- worker ----

    def _run(self):
        while True:
            item = self._q.get()
            batch = [item]
            while True:  # เก็บที่ค้างในคิวทั้งหมดมารวมเป็นชุดเดียว
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            wait = self._cooldown_left()
            if wait > 0:
                time.sleep(wait)
            try:
                self._send_batch(batch)
            except Exception:
                log.exception("ส่งการแจ้งเตือนล้มเหลว")

    def _cooldown_left(self):
        from . import config as config_mod

        cooldown = config_mod.get_int(self._cfg(), "notify", "cooldown_seconds", 60)
        if cooldown <= 0:
            return 0
        with self._lock:
            left = self._last_sent + cooldown - time.time()
            return max(0.0, left)

    def _mark_sent(self):
        with self._lock:
            self._last_sent = time.time()

    def _send_batch(self, batch):
        if len(batch) == 1:
            text = _format_block(batch[0])
        else:
            lines = [_format_block(b, numbered=True, idx=i + 1) for i, b in enumerate(batch)]
            text = f"RDPGuard: บล็อก IP รวม {len(batch)} รายการ\n\n" + "\n".join(lines)
        channels = self._channels()
        ok_tg = ok_mail = True
        err_tg = err_mail = ""
        if "telegram" in channels and self._get("telegram_bot_token").strip() and self._get("telegram_chat_id").strip():
            ok_tg, err_tg = self._send_telegram(text)
        if "email" in channels and self._get("smtp_host").strip() and self._get("smtp_to").strip():
            ok_mail, err_mail = self._send_email("RDPGuard — บล็อก IP", text)
        if not ok_tg:
            log.warning("Telegram ส่งไม่สำเร็จ: %s", err_tg)
        if not ok_mail:
            log.warning("Email ส่งไม่สำเร็จ: %s", err_mail)
        self._mark_sent()

    # ---- channels ----

    def _telegram_context(self):
        """SSL context สำหรับ Telegram API — ปิดตรวจสอบได้ถ้า proxy/AV intercept HTTPS"""
        from . import config as config_mod

        if config_mod.get_bool(self._cfg(), "notify", "telegram_verify_ssl", True):
            return ssl.create_default_context()
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        return ctx

    def _send_telegram(self, text):
        token = self._get("telegram_bot_token").strip()
        chat_id = self._get("telegram_chat_id").strip()
        payload = json.dumps(
            {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        ).encode("utf-8")
        last_err = ""
        for attempt in range(_MAX_RETRY):
            try:
                req = urllib.request.Request(
                    _TELEGRAM_API.format(token=token),
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10, context=self._telegram_context()) as resp:
                    data = json.loads(resp.read().decode("utf-8", "ignore"))
                if data.get("ok"):
                    return True, ""
                last_err = str(data.get("description", "unknown"))
            except Exception as exc:
                last_err = str(exc)
            time.sleep(2 * (attempt + 1))
        if "CERTIFICATE_VERIFY_FAILED" in last_err:
            last_err += (
                " — เครื่องมี proxy/โปรแกรมกันไวรัสที่ intercept HTTPS อยู่: ปิดตัวเลือก "
                '"ตรวจสอบ SSL" (telegram_verify_ssl) ในหน้า ตั้งค่า → แจ้งเตือน'
            )
        return False, last_err

    def _send_email(self, subject, body):
        host = self._get("smtp_host").strip()
        port = int(self._get("smtp_port") or 587)
        user = self._get("smtp_user").strip()
        password = self._get("smtp_password")
        to_addr = self._get("smtp_to").strip()
        from_addr = user or to_addr
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = formataddr(("RDPGuard", from_addr))
        msg["To"] = to_addr
        last_err = ""
        for attempt in range(_MAX_RETRY):
            try:
                smtp = smtplib.SMTP(host, port, timeout=15)
                try:
                    smtp.ehlo()
                    if port == 465:
                        # 465 = SMTPS ตรง (ใช้ SMTP_SSL)
                        raise OSError("use-ssl")
                    if smtp.has_extn("starttls"):
                        smtp.starttls()
                        smtp.ehlo()
                    if user:
                        smtp.login(user, password)
                    smtp.sendmail(from_addr, [to_addr], msg.as_string())
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                return True, ""
            except OSError as exc:
                if str(exc) == "use-ssl":
                    try:
                        smtp = smtplib.SMTP_SSL(host, port, timeout=15)
                        try:
                            smtp.login(user, password) if user else None
                            smtp.sendmail(from_addr, [to_addr], msg.as_string())
                        finally:
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                        return True, ""
                    except Exception as exc2:
                        last_err = str(exc2)
                else:
                    last_err = str(exc)
            except Exception as exc:
                last_err = str(exc)
            time.sleep(2 * (attempt + 1))
        return False, last_err


def _format_block(item, numbered=False, idx=0):
    from .detector import ENGINE_LABELS

    label = ENGINE_LABELS.get(str(item.get("source") or "rdp"), item.get("source") or "rdp")
    reason = str(item.get("reason") or "").strip()
    expires = str(item.get("expires") or "").strip()
    head = f"{idx}. " if numbered else ""
    line = f"{head}บล็อก IP {item.get('ip')} ({label})"
    if reason:
        line += f" — {reason}"
    if expires:
        line += f" — หมดอายุ {expires}"
    return line


def _version():
    from . import __version__

    return __version__
