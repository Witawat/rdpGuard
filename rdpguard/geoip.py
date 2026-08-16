"""GeoIP lookup: แสดงชื่อประเทศ + ธงของ IP ที่ถูกบล็อก/อนุญาต.

- ลำดับ: หน่วยความจำ → SQLite cache → ออนไลน์ (ipwho.is → ip-api.com fallback)
- ถ้าออฟไลน์/หาไม่เจอ คืน None (UI แสดง "-") — ไม่มีผลต่อการบล็อกแต่อย่างใด
- throttle การเรียกออนไลน์ (อย่างน้อย 0.35s/ครั้ง) กันโดน rate limit
"""

import ipaddress
import json
import logging
import threading
import time
import urllib.request

log = logging.getLogger("RDPGuard.geoip")

_mem = {}
_lock = threading.Lock()
_last_call = 0.0

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RDPGuard"


def _flag(code):
    if not code or len(code) != 2:
        return ""
    a = ord("A")
    return chr(0x1F1E6 + ord(code[0].upper()) - a) + chr(0x1F1E6 + ord(code[1].upper()) - a)


def _valid_ip(value):
    try:
        ipaddress.ip_address(value or "")
        return True
    except ValueError:
        return False


def _http_json(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def _throttle(min_interval=0.35):
    global _last_call
    while True:
        with _lock:
            now = time.time()
            if now - _last_call >= min_interval:
                _last_call = now
                return
        time.sleep(0.05)


def _lookup_online(ip):
    """ipwho.is ก่อน (https) — fallback ip-api.com (http)"""
    try:
        _throttle()
        data = _http_json(f"https://ipwho.is/{ip}")
        if data.get("success"):
            code = str(data.get("country_code") or "")
            country = str(data.get("country") or "")
            if code:
                return code, country
    except Exception as exc:
        log.debug("ipwho.is ล้มเหลว (%s) — ลอง ip-api.com", exc)
    try:
        _throttle()
        data = _http_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode")
        if data.get("status") == "success":
            return str(data.get("countryCode") or ""), str(data.get("country") or "")
    except Exception as exc:
        log.debug("ip-api.com ล้มเหลว: %s", exc)
    return None


def lookup(ip, db=None):
    """คืน {code, country, flag} หรือ None — db คือ Database (cache ระยะยาว)"""
    ip = (ip or "").strip()
    if not _valid_ip(ip):
        return None
    if ip in _mem:
        return _mem[ip]
    if db is not None:
        cached = db.get_geoip(ip)
        if cached and cached[0]:
            result = {"code": cached[0], "country": cached[1], "flag": _flag(cached[0])}
            _mem[ip] = result
            return result
    result = _lookup_online(ip)
    if result:
        code, country = result
        if db is not None and code:
            db.set_geoip(ip, code, country)
        data = {"code": code, "country": country, "flag": _flag(code)}
        _mem[ip] = data
        return data
    return None


def batch(ips, db=None):
    """lookup หลาย IP แบบ concurrent (thread pool) — คืน dict {ip: result}"""
    import concurrent.futures

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(lookup, ip, db): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = None
    return results
