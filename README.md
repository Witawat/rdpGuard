# RDPGuard

RDP brute-force protection สำหรับ Windows Server / Windows Desktop — เขียนด้วย Python ภาษาไทย

ทำงานคล้าย [RDPGuard](https://rdpguard.com/) / fail2ban: เฝ้าดู Security event log ตรวจจับการลองล็อกอิน RDP ซ้ำ ๆ จาก IP เดียวกัน แล้ว **บล็อก IP ผู้โจมตีอัตโนมัติด้วย Windows Firewall** (ในตัว ไม่ต้องติดตั้งอะไรเพิ่ม) และปลดบล็อกให้เองเมื่อครบกำหนดเวลา

| รายการ | ค่า |
|---|---|
| เวอร์ชัน | 1.6.3 |
| ภาษา | Python 3.8+ |
| Windows | source: 7 SP1 / 8.1 / 10 / 11 + Server 2008 R2 SP1 ขึ้นไป · exe (build ด้วย Python 3.11): 8.1 / 10 / 11 + Server 2012 ขึ้นไป (ดู INSTALL.md) |
| Dependency | pywin32 อย่างเดียว (web UI ใช้ stdlib ล้วน) |
| Web UI | http://127.0.0.1:8123 (ภาษาไทย, เปลี่ยนพอร์ตได้) |

## คุณสมบัติ

- **ตรวจจับ brute-force หลายโปรโตคอล** (multi-engine แบบ RDPGuard):
  - **RDP / RD Web / Web Client** — Security log (Event 4625)
  - **OpenSSH (SSH)** — OpenSSH/Operational (Event 4)
  - **MSSQL** — Event 18456 (รองรับ SQL auth ด้วย)
  - **IIS / HTTP Web Login / RD Web forms** — IIS W3C log (HTTP 401)
  - **MySQL** — MySQL error log
  - **Generic** — ไฟล์ log ของโปรแกรมอื่น (MailEnable/SmarterMail/PBX/SIP ฯลฯ) ตั้ง regex เองได้ — [คู่มือการใช้งานอย่างละเอียด (GENERIC.md)](GENERIC.md)
- **นับความถี่ต่อ IP ต่อ engine** ภายในกรอบเวลา (ค่าเริ่มต้น 5 ครั้ง/10 นาที) — ตั้งขีดจำกัดแยกต่อ engine ได้
- **บล็อก IP อัตโนมัติ** — เพิ่ม IP เข้า Windows Firewall ผ่าน HNetCfg COM API (fallback ด้วย netsh) — ค่าเริ่มต้นใช้ rule เดียวชื่อ `RDPGuard Block` เก็บ IP ใน `RemoteAddresses` — **จำกัดเฉพาะพอร์ตได้** (เช่น 3389,1433,22) หรือบล็อกทุกพอร์ต
- **หมดอายุแล้วปลดเอง** — บล็อกชั่วคราว (ค่าเริ่มต้น 24 ชม.) ปลดบล็อกอัตโนมัติเมื่อหมดเวลา
- **ตัวนับสะสม (ยิงสั้น ๆ แล้วหนี)** — นับความล้มเหลวสะสมต่อ IP ภายในกรอบเวลายาว (ค่าเริ่มต้น 24 ชม.) — IP ที่ยิงทีละ 1-2 ครั้งไม่ถึงเกณฑ์ระยะสั้น แต่สะสมครบ (ค่าเริ่มต้น 8) โดนบล็อก (ค่าเริ่มต้น 6 ชม.) — ล็อกอินสำเร็จ = ล้างตัวนับให้อัตโนมัติ
- **ต่ออายุอัตโนมัติ** — IP ที่ถูกบล็อกแล้วยังโจมตีต่อ จะต่ออายุบล็อกให้ใหม่
- **ขยายบล็อก IP ขาประจำ** — โดนบล็อกซ้ำครบเกณฑ์ (ค่าเริ่มต้น 3 ครั้ง/30 วัน) → ขยายเป็น 7 วัน หรือบล็อกถาวร
- **Whitelist / Blacklist** — กัน IP ที่ไม่ควรบล็อก (เช่น IP สำนักงาน) / บล็อก IP ไม่พึงประสงค์ทันที
- **บล็อกด้วยมือ** — ผ่าน Web UI หรือ CLI
- **Web UI ภาษาไทย** — dashboard เรียลไทม์, เหตุการณ์ล่าสุด, จัดการ blocked/whitelist/blacklist, **ปุ่มควบคุม Windows Service (ติดตั้ง/เริ่ม/หยุด/รีสตาร์ท/ถอน)** จากหน้าเว็บ, ตั้งค่าโดยไม่ต้องแตะไฟล์ config, **Setup Wizard ตอนรันครั้งแรก**, ฟอนต์ปรับตามขนาดหน้าจออัตโนมัติ
- **รันเป็น Windows Service** — เริ่มอัตโนมัติตอน boot ทำงานแม้ไม่มีใครล็อกอิน (pywin32)
- **กันบล็อกตัวเอง** — ข้าม loopback / IP เครื่องตัวเอง / วง LAN ส่วนตัว (เปิดปิดได้)
- **CLI ครบ** — ติดตั้ง/ถอน/เริ่ม/หยุด service, บล็อก/ปลดบล็อก IP, ดูรีเซ็ตรหัสผ่าน
- **Build เป็น exe ได้** — ใช้ PyInstaller (build.bat) ไม่ต้องลง Python บนเครื่องเป้าหมาย
- **แจ้งเตือนเมื่อบล็อก IP** — Telegram และ/หรือ Email (SMTP) เลือกช่องทางได้ มี cooldown รวมข้อความและ retry แบบ background ไม่หน่วงการบล็อก
- **จัดการ Log** — หมุนไฟล์อัตโนมัติ (ค่าเริ่มต้น 5 MB/ไฟล์ + เก็บสำรอง 5 ไฟล์), เลือกดู 250/500/1000 บรรทัด และแสดงขนาดไฟล์ใน Web UI
- **ทำงานทนขึ้น** — กันรันซ้ำ, ป้องกัน CSRF, จำกัดการเดารหัสแยกต่อ IP, session sliding, SQLite WAL และจำกัดขนาด GeoIP cache

## เริ่มต้นเร็ว (Quick Start)

```bat
:: 1. ติดตั้ง dependency (ครั้งเดียว)
python -m pip install -r requirements.txt

:: 2. ติดตั้ง + เริ่ม service (ต้อง admin — ใช้ install.bat ดีที่สุด รันแล้วมันขอสิทธิ์ให้เอง)
install.bat

:: 3. ดูรหัสผ่าน Web UI แล้วเปิดเบราว์เซอร์
python run.py password
```
Web UI: http://127.0.0.1:8123

> วิธีติดตั้งแบบละเอียดทีละขั้น: [INSTALL.md](INSTALL.md)

## โครงสร้างโปรเจกต์

```
rdpGuard/
├── rdpguard/                # package หลัก
│   ├── main.py              # CLI entry (python -m rdpguard / run.py)
│   ├── service.py           # Windows Service (pywin32)
│   ├── monitor.py           # ตัวขับเคลื่อน: engines + detector + cleanup
│   ├── engines.py           # multi-engine (rdp/openssh/mssql/iis/mysql/generic)
│   ├── detector.py          # ตรวจจับ brute-force + ตัดสินใจบล็อก
│   ├── firewall.py          # Windows Firewall (COM + netsh fallback, จำกัดพอร์ตได้)
│   ├── database.py          # SQLite (events, blocked, accumulate, whitelist, blacklist, geoip)
│   ├── config.py            # อ่าน/เขียน config.ini
│   ├── notify.py            # แจ้งเตือน Telegram/Email แบบ worker thread
│   ├── webui.py             # Web UI + REST API (stdlib http.server)
│   └── web/                 # index.html, app.js, style.css (UI ภาษาไทย)
├── run.py                   # runner หลัก (entry ของ service + PyInstaller)
├── config.example.ini       # ตัวอย่าง config
├── assets/icon.ico          # icon ของโปรแกรม (โล่ + กุญแจ)
├── tools/make_icon.py       # สคริปต์สร้าง icon ใหม่ (Pillow, dev เท่านั้น)
├── install.bat              # ติดตั้ง service อัตโนมัติ (ขอ admin เอง)
├── uninstall.bat            # ถอน service
├── build.bat                # build exe ด้วย PyInstaller
├── rdpguard.spec            # PyInstaller spec (onefile + icon)
└── requirements.txt         # pywin32
```

ข้อมูล runtime (config.ini, rdpguard.db, rdpguard.log และไฟล์สำรอง log) เก็บไว้**ข้าง exe ถ้าเขียนได้** (โหมด exe) หรือ `%ProgramData%\RDPGuard\` (โหมด source; ถ้าเขียนไม่ได้ใช้ `~/.rdpguard`)

## เอกสารอื่น ๆ

| ไฟล์ | เนื้อหา |
|---|---|
| [INSTALL.md](INSTALL.md) | ติดตั้งทีละขั้น (Python, service, exe build, รองรับ Windows เวอร์ชันไหนบ้าง) |
| [USAGE.md](USAGE.md) | วิธีใช้ Web UI + CLI ทั้งหมด |
| [CONFIG.md](CONFIG.md) | อธิบาย config ทุกค่าพร้อมค่าเริ่มต้น |
| [GENERIC.md](GENERIC.md) | ตั้งค่า Generic log engine และเขียน regex |
| [API.md](API.md) | REST API สำหรับนักพัฒนา |
| [DESIGN.md](DESIGN.md) | design ของ Web UI |
| [CHANGELOG.md](CHANGELOG.md) | ประวัติเวอร์ชัน |
| [RELEASE_TEMPLATE.md](RELEASE_TEMPLATE.md) | รูปแบบ release notes สำหรับผู้ดูแลโปรเจกต์ |

## ข้อควรระวัง

- การบล็อก IP ต้องใช้สิทธิ์ admin — service รันเป็น LocalSystem มีสิทธิ์อยู่แล้ว แต่ตอนรันแบบ `python run.py run` ต้องเปิด terminal ด้วย Run as administrator
- Web UI ค่าเริ่มต้นเปิดเฉพาะ `127.0.0.1` — อย่าเปลี่ยนเป็น `0.0.0.0` โดยไม่ตั้งรหัสผ่าน (ดู [CONFIG.md](CONFIG.md))
- exe ที่ build ด้วย PyInstaller + UPX อาจถูกโปรแกรมกันไวรัสฟลาก — เพิ่มโฟลเดอร์ที่เก็บ exe ใน exclusion หากตรวจสอบแล้วว่าเป็นไฟล์จากโปรเจกต์นี้
- หาก Telegram ขึ้น `CERTIFICATE_VERIFY_FAILED` จาก proxy/โปรแกรมกันไวรัสที่ intercept HTTPS ให้ปิด **ตรวจสอบ SSL ของ Telegram** ในหน้า ตั้งค่า → แจ้งเตือน แล้วบันทึกค่า
- ระบบนี้บล็อก IP ระดับ firewall — ถ้าต้องการกันการเดารหัสขั้นอีกชั้น แนะนำใช้ NLA (Network Level Authentication) ร่วมด้วย
