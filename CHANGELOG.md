# Changelog

## 1.3.0 (2026-08-16)

- **พาเนล "สถานะระบบ"** — ตรวจส่วนประกอบสำคัญและแสดงผลตรงจริง: สิทธิ์ admin/SYSTEM, Security event log อ่านได้ไหม, Windows Firewall เข้าถึง/เพิ่ม rule ได้ไหม, monitor, สถานะแหล่งข้อมูลของทุก engine (ทำงานได้/มีปัญหา/ไม่พร้อม/ปิด)
- **ปุ่ม "ทดสอบบล็อกจริง (firewall)"** — เพิ่ม+ลบ rule ทดสอบ (203.0.113.254) จริง ๆ แล้วรายงานผล — รู้ทันทีว่าบล็อกได้จริงหรือไม่
- **pill หัวเว็บบอกความจริง** — "เฝ้าระวังบางส่วน (อ่าน log ไม่ได้)" แทนที่จะขึ้น "กำลังเฝ้าระวัง" หลอกตาเมื่ออ่าน log ไม่ได้
- กัน race condition การเขียน config พร้อมกัน (lock)

## 1.2.0 (2026-08-16)

- **พาเนล "การตรวจจับ"** ใน Web UI: สวิตช์เปิด/ปิดเฝ้าระวังทั้งหมด + chip เปิด/ปิดแต่ละ engine ทันที (RDP ถาวร)
- **พาเนล "Log การทำงาน"** ใน Web UI: ดู rdpguard.log ล่าสุด 250 บรรทัด (refresh อัตโนมัติ 5 วินาที)
- **คอลัมน์ "ประเทศ" + ธง** ในตาราง blocked/whitelist/blacklist (GeoIP: ipwho.is → ip-api.com, cache ใน SQLite — ออฟไลน์แสดง "-" ไม่มีผลต่อการบล็อก)
- config.ini เติม section/คีย์ที่ขาดด้วยค่าเริ่มต้นอัตโนมัติ (ค่าเริ่มต้นทั้งหมดเห็นใน config ได้)
- ข้อความ log ของ event watcher เปลี่ยนชื่อเป็น RDPGuard.engines + ลดความถี่ (1 ครั้ง/60 วินาที)
- API ใหม่: `/api/detection-state`, `/api/toggle`, `/api/log`, `/api/geoip`

## 1.1.0 (2026-08-16)

- **Multi-engine detection** (แบบ RDPGuard): เพิ่ม OpenSSH (Event 4), MSSQL (Event 18456 — ครอบคลุม SQL auth), IIS/HTTP Web Login (W3C log 401), MySQL (error log), Generic log engine (ตั้ง regex เอง ครอบคลุม MailEnable/SmarterMail/PBX/SIP)
- นับความถี่แยกต่อ (engine, IP) + ตั้งขีดจำกัดเฉพาะ engine ได้ (`<engine>_max_attempts`)
- rule บล็อกจำกัดพอร์ตได้ (`firewall.blocked_ports` เช่น 3389,1433,22) — ว่าง = บล็อกทุกพอร์ต
- ตารางเหตุการณ์เพิ่มคอลัมน์ "แหล่ง" ระบุช่องทางโจมตี (RDP/OpenSSH/MSSQL/IIS/MySQL)
- หน้า "ตั้งค่า" เพิ่มกลุ่ม Engine เพิ่มเติม + ช่องจำกัดพอร์ต
- รองรับ log rotation ของ IIS/MySQL/generic log (ตรวจ size+ctime)

## 1.0.0 (2026-08-16)

- เปิดตัวครั้งแรก
- ตรวจจับ brute-force ต่อ RDP: เฝ้าดู Security event log (Event 4625) แบบเรียลไทม์, นับความถี่ต่อ IP ภายในกรอบเวลา (ค่าเริ่มต้น 5 ครั้ง / 10 นาที)
- บล็อก IP อัตโนมัติด้วย Windows Firewall (HNetCfg COM API, fallback netsh) — ไม่พึ่งเครื่องมือภายนอก
- บล็อกชั่วคราวแล้วปลดเองอัตโนมัติเมื่อหมดเวลา (ค่าเริ่มต้น 24 ชม.) + ต่ออายุอัตโนมัติถ้ายังถูกโจมตี
- Whitelist / Blacklist (รองรับ CIDR) + บล็อกด้วยมือผ่าน Web UI / CLI
- Web UI ภาษาไทย (stdlib http.server): dashboard เรียลไทม์, เหตุการณ์, blocked/whitelist/blacklist, ตั้งค่า — พร้อมล็อกอิน + กันเดารหัส
- REST API ครบสำหรับนักพัฒนา
- Windows Service (pywin32) เริ่มอัตโนมัติตอน boot
- CLI: install / remove / start / stop / restart / status / run / web / block / unblock / password
- PyInstaller build เป็น exe ได้ (build.bat + rdpguard.spec)
- รองรับ Windows 7 SP1 ขึ้นไป / Python 3.8+
