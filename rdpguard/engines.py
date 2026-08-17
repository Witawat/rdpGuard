"""Multi-engine detection — เหมือน RDPGuard: ตรวจจับ brute-force หลายโปรโตคอล.

Engine ทั้งหมดส่ง item {kind, ip, user, source, ts} ให้ detector:
- rdp     : Security log — 4625 (failed, filter LogonType), 4624 (success), 4776 (info)
- openssh : OpenSSH/Operational channel — Event 4 (auth failure, มี IP ในข้อความ)
- mssql   : Application log — MSSQLSERVER Event 18456 (มี IP ในข้อความ)
- iis     : IIS W3C log — sc-status 401 = fail, 200 = success (HTTP Web Login / RD Web)
- mysql   : MySQL error log — "Access denied for user 'x'@'IP'"
- generic : ไฟล์ log ใด ๆ ตาม config (regex + {IP} placeholder)

ไฟล์ที่อ่านแบบ tail (IIS/MySQL/generic) ใช้ FileTailer: จำ offset ไว้ ตรวจ rotation
ผ่าน (size, ctime) — ไฟล์ใหม่ที่เจอหลัง start tail ตั้งแต่ต้น, ไฟล์เดิม tail จากท้าย.
"""

import glob
import ipaddress
import logging
import os
import re
import threading
import time

log = logging.getLogger("RDPGuard.engines")

IP_PATTERN = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,})"

ENGINE_LABELS = {
    "rdp": "RDP",
    "openssh": "OpenSSH",
    "mssql": "MSSQL",
    "iis": "IIS Web",
    "mysql": "MySQL",
}


def _cfg(cfg):
    from . import config as config_mod

    return config_mod


# ---------------------------------------------------------------- helpers


def _evt_message(evt):
    """ดึงข้อความเต็มของ event (ลอง FormatMessage ก่อน, fallback StringInserts)"""
    try:
        from win32evtlogutil import FormatMessage

        return FormatMessage(evt)
    except Exception:
        try:
            return " ".join(evt.StringInserts or [])
        except Exception:
            return ""


# ---- 4625/4624 layout ต่างกันตาม Windows เวอร์ชัน ----
# Win7/2008R2: ins[3]=LogonType, ins[5]=SourceNetworkAddress
# Win10/2016+: ins[4]=LogonType, ins[14]=SourceNetworkAddress (4625), ins[12] (4624)
# parser นี้จึงสแกนหาแบบ version-agnostic


def _find_logon_type(ins):
    for x in ins[:18]:
        try:
            v = int(x)
        except (TypeError, ValueError):
            continue
        if 2 <= v <= 13:
            return v
    return 0


def _find_ip(ins, preferred):
    for idx in preferred:
        if idx < len(ins):
            v = (ins[idx] or "").strip()
            if _looks_like_ip(v):
                return v
    for x in ins:
        if _looks_like_ip(x):
            return x
    return "-"


def _looks_like_ip(value):
    if not value or value in ("-", "0.0.0.0", "::", "::1"):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _pick_user(ins, idx_new, idx_old):
    """Win10 เอา TargetUserName (ins[6]/ins[7]) แต่ Win7 ตำแหน่งนั้นเป็นตัวเลข (พอร์ต)
    และข้ามค่าแบบ LogonId (0x...) / SID (S-1-...) ที่ไม่ใช่ชื่อจริง"""
    if idx_new < len(ins) and ins[idx_new] and not ins[idx_new].isdigit():
        v = ins[idx_new]
        if not v.lower().startswith("0x") and not v.startswith("S-1-"):
            return v
    return ins[idx_old] if idx_old < len(ins) else "-"


def _log_watch_loop(channel, handler, stop_event, poll_interval, source):
    """อ่าน event log channel ต่อเนื่อง — 1 thread ต่อ channel.

    วิธีอ่าน: เปิดครั้งแรกอ่านแบบ BACKWARDS 1 batch เพื่อหา RecordNumber ล่าสุด
    (วางตำแหน่งให้อยู่ท้าย log) จากนั้นอ่าน FORWARDS ต่อเนื่อง — event ใหม่
    เห็นภายใน 1-2 poll แม้ log จะใหญ่ (เดิมอ่าน backward ตลอด → ช้าเป็นนาที
    บน log ที่เต็มไปด้วย 4625).
    """
    import win32api
    import win32evtlog

    handle = None
    last_record = 0
    retry_wait = 5.0
    last_err_log = 0.0
    try:
        while not stop_event.is_set():
            try:
                if handle is None:
                    handle = win32evtlog.OpenEventLog(None, channel)
                    flags = (
                        win32evtlog.EVENTLOG_BACKWARDS_READ
                        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    )
                    for evt in win32evtlog.ReadEventLog(handle, flags, 0):
                        last_record = max(last_record, evt.RecordNumber)
                    continue

                flags = (
                    win32evtlog.EVENTLOG_FORWARDS_READ
                    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )
                while True:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break
                    for evt in events:
                        if evt.RecordNumber <= last_record:
                            continue
                        last_record = max(last_record, evt.RecordNumber)
                        try:
                            handler(evt)
                        except Exception:
                            log.exception("parse event (%s) ล้มเหลว", source)
            except win32api.error as exc:
                now = time.time()
                if now - last_err_log >= 60:
                    log.warning(
                        "อ่าน log '%s' ไม่ได้ (%s): %s — service รันเป็น SYSTEM จะอ่านได้",
                        channel,
                        source,
                        exc,
                    )
                    last_err_log = now
                if handle is not None:
                    try:
                        win32evtlog.CloseEventLog(handle)
                    except Exception:
                        pass
                    handle = None
                stop_event.wait(retry_wait)
                continue
            except Exception:
                log.exception("eventlog watcher (%s) error", source)
            stop_event.wait(poll_interval)
    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass


class FileTailer:
    """tail ไฟล์ log: จำ offset + ตรวจ rotation ผ่าน (size, ctime)"""

    def __init__(self, path, handler, tail_from_end=True):
        self.path = path
        self.handler = handler
        self.offset = None
        self.ctime = None
        self._last_line = None  # sentinel กันนับซ้ำเมื่อไฟล์ถูก truncate (copytruncate)
        self._init_offset = 0 if not tail_from_end else None

    def _stat(self):
        try:
            st = os.stat(self.path)
            return st.st_size, st.st_ctime
        except OSError:
            return None

    def poll(self):
        info = self._stat()
        if info is None:
            return
        size, ctime = info
        if self.ctime is not None and ctime != self.ctime:
            log.info("log '%s' ถูกหมุนเวียน — tail ตั้งแต่ต้น", self.path)
            self.offset = 0
        self.ctime = ctime
        if self.offset is None:
            self.offset = self._init_offset if self._init_offset is not None else size
        truncated = False
        if size < self.offset:
            self.offset = 0
            truncated = True
        if size == self.offset:
            return
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.offset)
                data = f.read()
                self.offset = f.tell()
        except OSError:
            return
        lines = data.splitlines()
        # ไฟล์โดน truncate (ขนาดลดลง — copytruncate/truncate) — ข้ามบรรทัดซ้ำกับ
        # บรรทัดสุดท้ายที่อ่านไปแล้ว (sentinel) กันนับเหตุการณ์เดิมซ้ำ
        if truncated and self._last_line is not None:
            skip = 0
            for line in lines:
                if line == self._last_line:
                    skip += 1
                else:
                    break
            if skip:
                log.info("log '%s' โดน truncate — ข้ามบรรทัดซ้ำ %d บรรทัด", self.path, skip)
                lines = lines[skip:]
        for line in lines:
            try:
                self.handler(line)
                self._last_line = line
            except Exception:
                log.exception("parse log line ล้มเหลว (%s)", self.path)


def _file_glob(candidate, default_pattern):
    """คืนรายการไฟล์ log: ถ้า candidate เป็นโฟลเดอร์/pattern ใช้ glob; ว่าง = default"""
    if not candidate:
        paths = glob.glob(default_pattern)
    elif os.path.isdir(candidate):
        paths = glob.glob(os.path.join(candidate, "**", "*.log"), recursive=True)
    else:
        paths = glob.glob(candidate)
    return sorted(paths)


# ---------------------------------------------------------------- engines


class BaseEngine:
    name = ""

    def __init__(self, cfg, callback, poll_interval=3.0):
        self.cfg = cfg
        self.callback = callback
        self.poll_interval = max(0.5, float(poll_interval))
        self._stop = threading.Event()
        self._thread = None

    def enabled(self, cfg=None):
        return True

    def _emit(self, kind, ip="", user="", **extra):
        item = {"kind": kind, "ip": ip, "user": user, "source": self.name, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        item.update(extra)
        try:
            self.callback(item)
        except Exception:
            log.exception("engine %s callback ล้มเหลว", self.name)

    def start(self):
        self._thread = threading.Thread(target=self._run, name=f"engine-{self.name}", daemon=True)
        self._thread.start()
        log.info("engine '%s' เริ่มทำงาน", self.name)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=8)

    def reload(self, cfg):
        self.cfg = cfg

    def _run(self):
        pass


class SecurityEngine(BaseEngine):
    """RDP + ทุก logon ที่ทิ้ง Event 4625 (FTP/IIS Windows-auth/MSSQL Windows-auth/OpenSSH แบบ Windows logon)"""

    name = "rdp"

    def enabled(self, cfg=None):
        return True

    def _run(self):
        poll = max(0.5, float(self._cfg_poll()))
        _log_watch_loop("Security", self._handle, self._stop, poll, self.name)

    def _cfg_poll(self):
        from . import config as config_mod

        return config_mod.get_int(self.cfg, "monitor", "poll_interval_seconds", 2)

    def _handle(self, evt):
        eid = evt.EventID & 0xFFFF
        ins = list(evt.StringInserts or [])
        if eid == 4625:
            self._emit(
                "fail",
                ip=_find_ip(ins, (14, 5)),
                user=_pick_user(ins, 6, 0),
                domain=_pick_user(ins, 7, 1),
                logon_type=_find_logon_type(ins),
                event_id=4625,
            )
        elif eid == 4624:
            logon_type = _find_logon_type(ins)
            if logon_type not in (3, 10):
                return  # ข้าม local/service logon (type 2/5 ฯลฯ) — สนใจแค่ remote (3=Network, 10=RDP)
            self._emit(
                "success",
                ip=_find_ip(ins, (12, 5)),
                user=_pick_user(ins, 6, 0),
                domain=_pick_user(ins, 7, 1),
                logon_type=logon_type,
                event_id=4624,
            )
        elif eid == 4776:
            self._emit("ntlm", user=ins[1] if len(ins) > 1 else "-", event_id=4776)


class OpenSSHEngine(BaseEngine):
    """OpenSSH/Operational channel — Event 4 (authentication failure)"""

    name = "openssh"

    def enabled(self, cfg=None):
        from . import config as config_mod

        return config_mod.get_bool(self.cfg if cfg is None else cfg, "engines", "openssh", True)

    def _run(self):
        _log_watch_loop("OpenSSH/Operational", self._handle, self._stop, self.poll_interval, self.name)

    def _handle(self, evt):
        if (evt.EventID & 0xFFFF) != 4:
            return
        msg = _evt_message(evt)
        m = re.search(r"from (" + IP_PATTERN + r")\s+port", msg)
        if not m:
            m = re.search(r"from (" + IP_PATTERN + r")", msg)
        if not m:
            return
        user = ""
        um = re.search(r"(?:for|by) (?:invalid user )?([^\s@]+)", msg)
        if um:
            user = um.group(1)
        self._emit("fail", ip=m.group(1), user=user, event_id=4)


class MSSQLEngine(BaseEngine):
    """Application log — MSSQLSERVER Event 18456 (login failed, มี CLIENT IP)"""

    name = "mssql"

    def enabled(self, cfg=None):
        from . import config as config_mod

        return config_mod.get_bool(self.cfg if cfg is None else cfg, "engines", "mssql", True)

    def _run(self):
        _log_watch_loop("Application", self._handle, self._stop, self.poll_interval, self.name)

    def _handle(self, evt):
        if (evt.EventID & 0xFFFF) != 18456:
            return
        msg = _evt_message(evt)
        m = re.search(r"CLIENT:\s*(" + IP_PATTERN + r")", msg, re.IGNORECASE)
        if not m:
            return
        user = ""
        um = re.search(r"Login failed for user '([^']*)'", msg, re.IGNORECASE)
        if um:
            user = um.group(1)
        self._emit("fail", ip=m.group(1), user=user, event_id=18456)


def _w3c_fields(line):
    """split W3C log แบบคำนึงถึง quote (cs(User-Agent) มีช่องว่างได้)"""
    fields = []
    buf = ""
    in_q = False
    for ch in line:
        if ch == '"':
            in_q = not in_q
            buf += ch
        elif ch in " \t" and not in_q:
            if buf:
                fields.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        fields.append(buf)
    return fields


class IISEngine(BaseEngine):
    """IIS W3C log (HTTP Web Login / RD Web forms): sc-status 401 = fail, 200 = success"""

    name = "iis"

    def __init__(self, cfg, callback, poll_interval=3.0):
        super().__init__(cfg, callback, poll_interval)
        self._tailers = []
        self._known = set()
        self._indices = {}

    def enabled(self, cfg=None):
        from . import config as config_mod

        return config_mod.get_bool(self.cfg if cfg is None else cfg, "engines", "iis", True)

    def _log_files(self):
        from . import config as config_mod

        candidate = config_mod.get(self.cfg, "engines", "iis_log_dir", "").strip()
        if candidate and os.path.isdir(candidate):
            return sorted(glob.glob(os.path.join(candidate, "**", "*.log"), recursive=True))
        return sorted(glob.glob(r"C:\inetpub\logs\LogFiles\**\*.log", recursive=True))

    def _run(self):
        while not self._stop.wait(self.poll_interval):
            try:
                self._refresh_tailers()
                for tailer in self._tailers:
                    tailer.poll()
            except Exception:
                log.exception("iis engine error")

    def _refresh_tailers(self):
        paths = self._log_files()
        for path in paths:
            if path not in self._known:
                self._known.add(path)
                tailer = FileTailer(path, lambda line, _p=path: self._handle_line(line, _p), tail_from_end=True)
                self._tailers.append(tailer)
                log.info("iis engine: เฝ้า %s", path)

    def _handle_line(self, line, path):
        line = line.strip()
        if line.startswith("#Fields:"):
            names = _w3c_fields(line[len("#Fields:") :].strip())
            self._indices[path] = {name: i for i, name in enumerate(names)}
            return
        if not line or line.startswith("#"):
            return
        f = _w3c_fields(line)
        idx = self._indices.get(path) or _DEFAULT_W3C_INDEX
        if len(f) <= max(idx.values()):
            return
        try:
            status = f[idx["sc-status"]]
        except (KeyError, IndexError):
            return
        ip = f[idx["c-ip"]] if idx.get("c-ip") is not None and idx["c-ip"] < len(f) else "-"
        user = f[idx["cs-username"]] if idx.get("cs-username") is not None and idx["cs-username"] < len(f) else ""
        if status == "401":
            self._emit("fail", ip=ip, user=user)
        elif status == "200":
            self._emit("success", ip=ip, user=user)


_DEFAULT_W3C_INDEX = {
    "date": 0,
    "time": 1,
    "s-ip": 2,
    "cs-method": 3,
    "cs-uri-stem": 4,
    "cs-uri-query": 5,
    "s-port": 6,
    "cs-username": 7,
    "c-ip": 8,
    "cs(User-Agent)": 9,
    "sc-status": 10,
    "sc-substatus": 11,
    "sc-win32-status": 12,
}


class MySQLEngine(BaseEngine):
    """MySQL error log — "Access denied for user 'x'@'IP'" """

    name = "mysql"

    def __init__(self, cfg, callback, poll_interval=3.0):
        super().__init__(cfg, callback, poll_interval)
        self._tailers = []
        self._known = set()

    def enabled(self, cfg=None):
        from . import config as config_mod

        return config_mod.get_bool(self.cfg if cfg is None else cfg, "engines", "mysql", True)

    def _run(self):
        while not self._stop.wait(self.poll_interval):
            try:
                self._refresh_tailers()
                for tailer in self._tailers:
                    tailer.poll()
            except Exception:
                log.exception("mysql engine error")

    def _refresh_tailers(self):
        from . import config as config_mod

        candidate = config_mod.get(self.cfg, "engines", "mysql_log_dir", "").strip()
        patterns = [r"C:\ProgramData\MySQL\*\Data\*.err"]
        if candidate:
            patterns.insert(0, candidate)
        paths = set()
        for p in patterns:
            paths.update(glob.glob(p))
        for path in sorted(paths):
            if path not in self._known:
                self._known.add(path)
                tailer = FileTailer(path, self._handle_line, tail_from_end=True)
                self._tailers.append(tailer)
                log.info("mysql engine: เฝ้า %s", path)

    def _handle_line(self, line):
        m = re.search(r"Access denied for user '[^']*'@'(" + IP_PATTERN + r")'", line)
        if not m:
            return
        user = ""
        um = re.search(r"for user '([^']*)'", line)
        if um:
            user = um.group(1)
        self._emit("fail", ip=m.group(1), user=user)


class GenericEngine(BaseEngine):
    """generic log regex: ชื่อ=path|regex (คั่น ;) — {IP} แทนตำแหน่ง IP"""

    name = "generic"

    def __init__(self, cfg, callback, poll_interval=3.0):
        super().__init__(cfg, callback, poll_interval)
        self._tailers = []
        self._seen = set()

    def enabled(self, cfg=None):
        from . import config as config_mod

        return config_mod.get_bool(self.cfg if cfg is None else cfg, "engines", "generic", True)

    def _entries(self):
        from . import config as config_mod

        raw = config_mod.get(self.cfg, "engines", "generic_logs", "").strip()
        entries = []
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            name, _, rest = part.partition("=")
            path, _, pattern = rest.partition("|")
            name = name.strip() or "generic"
            path = path.strip()
            pattern = pattern.strip()
            if not path or not pattern:
                log.warning("generic_logs รูปแบบผิด (ต้องเป็น ชื่อ=path|regex): %s", part)
                continue
            try:
                regex = re.compile(
                    re.sub(r"\{IP\}", lambda _m: "(?P<ip>" + IP_PATTERN + ")", pattern)
                )
            except re.error as exc:
                log.warning("generic_logs regex ผิด: %s (%s)", pattern, exc)
                continue
            entries.append((name, path, regex))
        return entries

    def _run(self):
        while not self._stop.wait(self.poll_interval):
            try:
                self._refresh_tailers()
                for tailer in self._tailers:
                    tailer.poll()
            except Exception:
                log.exception("generic engine error")

    def _refresh_tailers(self):
        entries = self._entries()
        active_paths = set()
        for name, path, regex in entries:
            active_paths.add(path)
            if path not in self._seen:
                self._seen.add(path)
                tailer = FileTailer(
                    path,
                    lambda line, _n=name, _r=regex: self._handle_line(line, _n, _r),
                    tail_from_end=True,
                )
                self._tailers.append(tailer)
                log.info("generic engine: เฝ้า %s (%s)", path, name)
        self._tailers = [t for t in self._tailers if t.path in active_paths]

    def _handle_line(self, line, name, regex):
        m = regex.search(line)
        if not m:
            return
        ip = m.group("ip") or ""
        user = ""
        if "user" in m.groupdict() and m.group("user"):
            user = m.group("user")
        self._emit("fail", ip=ip, user=user, engine_name=name)


ALL_ENGINES = [SecurityEngine, OpenSSHEngine, MSSQLEngine, IISEngine, MySQLEngine, GenericEngine]


# ---------------------------------------------------------------- สถานะแหล่งข้อมูล (สำหรับ Web UI)


def channel_ok(channel):
    """ตรวจว่าเปิด event log channel ได้ไหม (สิทธิ์/มี channel อยู่จริง)"""
    import win32evtlog

    handle = win32evtlog.OpenEventLog(None, channel)
    win32evtlog.CloseEventLog(handle)
    return True


def source_status(cfg):
    """คืนสถานะแหล่งข้อมูลของแต่ละ engine: ok / error / no-source / disabled"""
    from . import config as config_mod

    def enabled(key):
        return config_mod.get_bool(cfg, "engines", key, True)

    status = {}
    try:
        status["rdp"] = "ok" if channel_ok("Security") else "error"
    except Exception:
        status["rdp"] = "error"

    try:
        status["openssh"] = (
            "ok" if channel_ok("OpenSSH/Operational") else "no-source"
        ) if enabled("openssh") else "disabled"
    except Exception:
        status["openssh"] = "no-source" if enabled("openssh") else "disabled"
    status["mssql"] = (
        "ok" if channel_ok("Application") else "error"
    ) if enabled("mssql") else "disabled"

    if enabled("iis"):
        candidate = config_mod.get(cfg, "engines", "iis_log_dir", "").strip()
        paths = (
            sorted(glob.glob(os.path.join(candidate, "**", "*.log"), recursive=True))
            if candidate and os.path.isdir(candidate)
            else glob.glob(r"C:\inetpub\logs\LogFiles\**\*.log", recursive=True)
        )
        status["iis"] = "ok" if paths else "no-source"
    else:
        status["iis"] = "disabled"

    if enabled("mysql"):
        candidate = config_mod.get(cfg, "engines", "mysql_log_dir", "").strip()
        patterns = [r"C:\ProgramData\MySQL\*\Data\*.err"]
        if candidate:
            patterns.insert(0, candidate)
        found = any(glob.glob(p) for p in patterns)
        status["mysql"] = "ok" if found else "no-source"
    else:
        status["mysql"] = "disabled"

    if enabled("generic"):
        raw = config_mod.get(cfg, "engines", "generic_logs", "").strip()
        count = len([p for p in raw.split(";") if p.strip()])
        status["generic"] = "ok" if count else "no-source"
    else:
        status["generic"] = "disabled"
    return status
