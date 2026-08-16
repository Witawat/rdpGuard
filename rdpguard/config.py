"""การจัดการ config (INI แบบเดียวกับโครงการ Cloudflare DDNS).

ตำแหน่งข้อมูล (config.ini, rdpguard.db, rdpguard.log):
- โหมด exe (PyInstaller frozen): โฟลเดอร์เดียวกับ exe
- โหมด source (python run.py): %ProgramData%\\RDPGuard\\ (ถ้าเขียนไม่ได้ ใช้ ~/.rdpguard แทน)
- config สร้างอัตโนมัติตอนรันครั้งแรก ถ้า webui_password ว่างจะสุ่มให้ใหม่
"""

import configparser
import logging
import os
import secrets
import shutil
import sys

from . import __version__


def _writable_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        test_file = os.path.join(path, ".write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return True
    except Exception:
        return False


def _default_data_dir():
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        if _writable_dir(exe_dir):
            return exe_dir
    program_data = os.environ.get("ProgramData")
    candidate = os.path.join(program_data, "RDPGuard") if program_data else None
    if candidate and _writable_dir(candidate):
        return candidate
    fallback = os.path.join(os.path.expanduser("~"), ".rdpguard")
    _writable_dir(fallback)
    return fallback


def _migrate_legacy_data():
    """โหมด exe: ถ้ายังไม่มีข้อมูลข้าง exe แต่มีข้อมูลเก่าที่ %ProgramData%\\RDPGuard
    (จากเวอร์ชันก่อนหน้า) ให้คัดลอก config.ini + rdpguard.db มาไว้ข้าง exe"""
    if not getattr(sys, "frozen", False):
        return
    program_data = os.environ.get("ProgramData")
    legacy = os.path.join(program_data, "RDPGuard") if program_data else None
    if not legacy or os.path.normcase(legacy) == os.path.normcase(DATA_DIR):
        return
    for name in ("config.ini", "rdpguard.db"):
        src = os.path.join(legacy, name)
        dst = os.path.join(DATA_DIR, name)
        if os.path.isfile(src) and not os.path.exists(dst):
            try:
                shutil.copy2(src, dst)
                print(f"ย้ายข้อมูล {name} จาก {legacy} มาที่ {dst}")
            except Exception as exc:
                print(f"ย้าย {name} ไม่สำเร็จ: {exc}")


DATA_DIR = _default_data_dir()
CONFIG_FILE = os.path.join(DATA_DIR, "config.ini")
DB_FILE = os.path.join(DATA_DIR, "rdpguard.db")
LOG_FILE = os.path.join(DATA_DIR, "rdpguard.log")

_migrate_legacy_data()

DEFAULT_CONFIG = """\
[general]
; ระดับ log: DEBUG / INFO / WARNING / ERROR
log_level = INFO
; ตั้งค่าเสร็จแล้วหรือยัง (ระบบจัดการเอง — ผ่าน Setup Wizard ครั้งแรก)
setup_done = false

[monitor]
; เปิด/ปิดการเฝ้าระวังทั้งหมด
enable = true
; อ่าน Security event log ทุกกี่วินาที
poll_interval_seconds = 2
; ชนิด LogonType ที่นับเป็น "พยายามล็อกอิน RDP" (3=Network/NLA, 10=RemoteInteractive)
; ใช้ * เพื่อนับทุกชนิด
logon_types = 3,10

[detection]
; เจอล็อกอินผิดกี่ครั้ง (ภายใน window_minutes) ถึงจะบล็อก IP
max_attempts = 5
; กรอบเวลานับจำนวนครั้ง (นาที)
window_minutes = 10
; บล็อกนานเท่าไร (ชั่วโมง) - 0 = บล็อกถาวร
block_hours = 24
; ถ้า IP ที่ถูกบล็อกยังพยายามโจมตีต่อ ให้ต่ออายุการบล็อกอัตโนมัติ
auto_extend = true
; ข้าม IP ในวง LAN/loopback/เครื่องตัวเอง (กันบล็อกผู้ดูแลเอง)
skip_local_ips = true
; กันบล็อก IP ที่ล็อกอินสำเร็จภายในกี่นาทีที่ผ่านมา (ป้องกันบล็อกผู้ดูแลเอง
; ที่กำลังต่อ RDP อยู่) — 0 = ปิด
active_session_grace_minutes = 30
; รายการ IP/CIDR ที่ห้ามบล็อกเด็ดขาด (คั่น ,) — เหมือน whitelist แต่แก้ใน
; config ตรง ๆ ได้เมื่อฉุกเฉิน (เช่น ถูกล็อกตัวเอง)
never_block_ips =
; --- ขยายบล็อก IP ขาประจำ (repeat offender) ---
; IP ที่โดนบล็อกครบกี่ครั้ง (ภายใน escalation_window_days) ถึงจะขยายการบล็อก
; (เช่น โดนบล็อก 3 ครั้งแล้วยังกลับมาอีก -> ครั้งที่ 4 ขยายเป็น escalate_block_hours)
; 0 = ปิด (บล็อก-ปลดตามปกติตลอด)
escalate_after_blocks = 3
; ขยายเป็นกี่ชั่วโมง (ค่าเริ่มต้น 7 วัน = 168)
escalate_block_hours = 168
; ขยายเป็นบล็อกถาวรเลย (แทน escalate_block_hours) — ต้องปลดด้วยมือ
escalate_to_permanent = false
; กรอบเวลานับจำนวนครั้งที่โดนบล็อก (วัน)
escalation_window_days = 30
; --- ตัวนับสะสม (ไล่กลยุทธ์ "ยิงสั้น ๆ แล้วหนี") ---
; นับความล้มเหลวสะสมต่อ IP ภายในกรอบเวลายาว (ชั่วโมง) — แยกจาก window_minutes
; ที่รีเซ็ตทุกกรอบเวลา; 0 = ปิดตัวนับสะสม
accumulate_window_hours = 24
; ครบกี่ครั้ง (รวมภายในกรอบเวลานั้น) ถึงจะบล็อก — 0 = ปิด
accumulate_threshold = 8
; บล็อกนานเท่าไรสำหรับกรณีสะสม (ชั่วโมง) — ตั้งสั้นกว่า block_hours
; กันพลาดบล็อกผู้ใช้หลัง NAT/ISP shared; IP ขาประจำจะโดน escalate ต่อเอง
accumulate_block_hours = 6

[engines]
; Engine เพิ่มเติม (security/RDP เปิดถาวร) — เปิด/ปิดแต่ละตัวได้
openssh = true
mssql = true
iis = true
mysql = true
generic = true
; ขีดจำกัดเฉพาะ engine (ว่าง = ใช้ค่ากลาง max_attempts)
openssh_max_attempts =
mssql_max_attempts =
iis_max_attempts =
mysql_max_attempts =
generic_max_attempts =
; IIS W3C log (ว่าง = auto: C:\\inetpub\\logs\\LogFiles)
iis_log_dir =
; MySQL error log (ว่าง = auto: C:\\ProgramData\\MySQL\\*\\Data\\*.err)
mysql_log_dir =
; Generic: ไฟล์ log + regex ที่มี {IP} เป็นตัวแทน IP
; รูปแบบ: ชื่อ=path|regex  คั่นหลายรายการด้วย ;
; เช่น: mail=C:\\MailServer\\log.txt|Failed login from '{IP}'
generic_logs =

[firewall]
; คำนำหน้าชื่อ rule ใน Windows Firewall (เห็นใน wf.msc)
rule_prefix = RDPGuard Block
; profile: any / domain / private / public
profile = any
; จำกัดพอร์ตที่บล็อก (ว่าง = บล็อกทุกพอร์ตจาก IP นั้น) เช่น 3389,1433,22
blocked_ports =
; โหมด rule เดียวแบบ RDPGuard: rule เดียว (ชื่อ rule_prefix) แล้วเพิ่ม/ลบ IP
; ในรายการ RemoteAddresses ตาม IP ที่โจมตี — false = สร้าง rule แยกต่อ IP
single_rule = true

[webui]
; Web UI เปิดที่พอร์ต/โฮสต์ไหน (ค่าเริ่มต้น: เฉพาะเครื่องนี้)
host = 127.0.0.1
port = 8123
; รหัสผ่านหน้า Web UI (ว่าง = สุ่มให้อัตโนมัติตอนรันครั้งแรก)
password =
"""


def ensure_config():
    """สร้าง config.ini ถ้ายังไม่มี + เติม section/คีย์ที่ขาดด้วยค่าเริ่มต้น + สุ่ม password ถ้าว่าง"""
    if not os.path.exists(CONFIG_FILE):
        parser = configparser.ConfigParser()
        parser.read_string(DEFAULT_CONFIG)
        parser.set("webui", "password", secrets.token_urlsafe(12))
        save_config(parser)
        return load_config()

    parser = load_config()
    changed = False
    defaults = configparser.ConfigParser()
    defaults.read_string(DEFAULT_CONFIG)
    for section in defaults.sections():
        if not parser.has_section(section):
            parser.add_section(section)
            changed = True
        for key, value in defaults.items(section):
            if not parser.has_option(section, key):
                parser.set(section, key, value)
                changed = True
    if not get(parser, "webui", "password", "").strip():
        parser.set("webui", "password", secrets.token_urlsafe(12))
        changed = True
    if changed:
        save_config(parser)
    return parser


def load_config():
    parser = configparser.ConfigParser()
    parser.read(CONFIG_FILE, encoding="utf-8")
    return parser


def save_config(parser):
    tmp_file = CONFIG_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        parser.write(f)
    os.replace(tmp_file, CONFIG_FILE)


def get(parser, section, key, fallback=""):
    try:
        return parser.get(section, key, fallback=fallback)
    except Exception:
        return fallback


def get_int(parser, section, key, fallback=0):
    try:
        return parser.getint(section, key, fallback=fallback)
    except Exception:
        return fallback


def get_bool(parser, section, key, fallback=False):
    try:
        return parser.getboolean(section, key, fallback=fallback)
    except Exception:
        return fallback


def get_list(parser, section, key, fallback=None):
    raw = get(parser, section, key, "").strip()
    if not raw:
        return list(fallback or [])
    return [x.strip() for x in raw.split(",") if x.strip()]


def setup_logging(level_name="INFO"):
    from logging.handlers import RotatingFileHandler

    level = getattr(logging, str(level_name).upper(), logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        handlers.append(file_handler)
    except Exception:
        pass
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )
    logging.getLogger("RDPGuard").info("RDPGuard v%s", __version__)
