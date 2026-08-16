# AGENTS.md — RDPGuard

RDP brute-force protection สำหรับ Windows (Python) — ตรวจจับการล็อกอินล้มเหลวซ้ำ ๆ แล้วบล็อก IP ด้วย Windows Firewall

## คำสั่งหลัก

```powershell
python run.py run            # รัน foreground (monitor + web UI) — แนะนำ admin
python run.py web            # รันเฉพาะ web UI
python run.py status         # สถานะ service
python run.py block <ip> [ชม.] / unblock <ip> / unblock-all / allow <ip>
python run.py password       # ดู/รีเซ็ตรหัสผ่าน Web UI
install.bat                  # ติดตั้ง Windows Service (ขอ admin เอง)
python -m compileall -q rdpguard run.py   # ตรวจ syntax
python -m PyInstaller --noconfirm rdpguard.spec   # build exe -> dist\rdpguard.exe
```

## โครงสร้าง

- `rdpguard/config.py` — config INI; `DEFAULT_CONFIG` คือต้นฉบับค่าเริ่มต้น; `ensure_config()` เติม section/คีย์ที่ขาดให้อัตโนมัติ
- `rdpguard/database.py` — SQLite (events, blocked, blocked_history, whitelist, blacklist, geoip_cache)
- `rdpguard/engines.py` — multi-engine: rdp (Security 4625/4624), openssh (Event 4), mssql (18456), iis (W3C), mysql, generic (regex)
- `rdpguard/detector.py` — นับความถี่ต่อ (engine, IP), บล็อก, grace, escalation, auto-unblock
- `rdpguard/firewall.py` — HNetCfg COM + netsh fallback; `single_rule=true` (ค่าเริ่มต้น) = rule เดียว `RDPGuard Block` เก็บ IP ใน RemoteAddresses
- `rdpguard/monitor.py` — cleanup 60 วิ (หมดอายุ, whitelist reconcile, firewall reconcile)
- `rdpguard/webui.py` — web UI + REST API (stdlib http.server)
- `rdpguard/web/` — UI ภาษาไทย (index.html / app.js / style.css)
- `rdpguard/service.py` / `main.py` — Windows service / CLI

## กฎประจำโปรเจกต์

- **ภาษา**: docstring/UI/ข้อความ = ไทย · identifier/โค้ด = อังกฤษ
- **dependency**: pywin32 ตัวเดียว — ห้ามเพิ่มโดยไม่จำเป็น (web UI เป็น stdlib ล้วน)
- **bump เวอร์ชัน** ต้องทำครบ 3 จุด: `rdpguard/__init__.py` `__version__` + `?v=` ใน `rdpguard/web/index.html` + section ใหม่ใน `CHANGELOG.md`
- **data dir**: exe mode = โฟลเดอร์เดียวกับ exe · source mode = `%ProgramData%\RDPGuard\`
- **ห้าม commit**: `dist/config.ini`, `*.db`, `*.log`, `__pycache__` (gitignore แล้ว) — config/DB เป็นข้อมูลเฉพาะเครื่อง
- **UI แก้ CSS/JS แล้วต้อง rebuild exe** (static ถูก bundle ใน exe) — และ asset version ต้อง bump ไม่งั้น cache เก่าค้าง
- **release**: build exe → `gh release create <tag> --repo Witawat/rdpGuard --notes-file <ไฟล์> dist\rdpguard.exe` — แนบแค่ exe ตัวเดียว

## ทดสอบ

- ไม่มี test framework — ใช้สคริปต์ชั่วคราว: จุด `config_mod.DB_FILE` ไป tempfile แล้วเทสต์ logic ตรง ๆ (ดู `C:\Users\XSoFTz\AppData\Local\Temp\opencode\*.py` ที่เคยใช้)
- API ทดสอบผ่าน http://127.0.0.1:8123 (login → cookie `rdpguard_session`)
- **`POST /api/self-test`** = พิสูจน์ pipeline จริง (เขียน event 18456 → engine → บล็อก → ตรวจ rule → ปลด) — ต้อง admin/service
- ตรวจ firewall จริง: `rule_exists` ผ่าน COM (อ่านได้ไม่ต้อง admin)

## ข้อควรรู้บน Windows

- **firewall/event log ต้อง admin/SYSTEM** — เปิด elevated ด้วย `Start-Process -Verb RunAs` (มี UAC popup — บอก user ให้กด Yes)
- **rebuild exe ต้องไม่มี instance รันอยู่** (exe โดน lock) — ให้ user ปิดหน้าต่าง RDPGuard ก่อนทุกครั้ง
- 2 process `rdpguard.exe` = ปกติ (PyInstaller onefile: bootloader + child)
- `qwinsta`/`query session` ไม่มีใน Win11 บางรุ่น — sessions API fallback เป็น PowerShell CIM แล้ว
- Windows Firewall คืน RemoteAddresses เป็น `1.2.3.4/255.255.255.255` — ใช้ `_normalize_entry`/`_entry_contains` ใน firewall.py เสมอ
- เหตุการณ์ "หาย" จากตาราง = UI แสดงแค่ 80 ล่าสุด (ข้อมูลไม่ถูกลบ)
- exe (build ด้วย Python 3.11) รันได้ Windows 8.1+ — Win7 ต้อง build ด้วย Python 3.8

## แผนพัฒนา (ถัดไป)

- ตัวนับสะสม IP ที่พยายามแต่ยังไม่ถึงเกณฑ์ (ไล่กลยุทธ์ "ยิงสั้น ๆ แล้วหนี")
- แจ้งเตือน (email/webhook) เมื่อเจอบล็อก
