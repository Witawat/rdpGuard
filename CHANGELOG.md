# Changelog

## 1.4.1 (2026-08-16)

- **ขยายบล็อก IP ขาประจำ (repeat offender)**: โดนบล็อกครบ `escalate_after_blocks` ครั้ง (ค่าเริ่มต้น 3 ครั้ง/30 วัน) แล้วกลับมาโจมตีอีก → ขยายเป็น `escalate_block_hours` (7 วัน) หรือถาวร (`escalate_to_permanent`) — ตั้งค่าได้ในหน้า ตั้งค่า (กลุ่ม การตรวจจับ)
- แก้บั๊ก: **blacklist ไม่มีผลกับ IP private/TEST-NET** (เช็คหลัง skip_local_ips) → ย้าย blacklist ขึ้นก่อน — คำสั่ง blacklist ของผู้ใช้มีผลเหนือกว่า auto-skip
- แก้บั๊ก: **auto_extend ทับระยะเวลาบล็อกที่ขยายแล้ว** (168 ชม. → ถูกขยายทับเป็น 24 ชม. ตอนยังโจมตีต่อ) และขยายบล็อกถาวร → `_maybe_extend` ไม่ลด expires เดิม + ไม่แตะบล็อกถาวร
- Web UI: เพิ่มช่องตั้งค่า escalate/never_block/grace ในหน้า ตั้งค่า + asset version bump

## 1.4.0 (2026-08-16)

### Self-test ครบวงจร (Web UI)
- ปุ่ม **"ทดสอบระบบทั้งหมด (self-test)"** ในพาเนลสถานะระบบ — พิสูจน์ pipeline ทั้งสายแบบเรียลไทม์: เขียน event จำลอง (18456) ลง Application log จริง → engine อ่าน → detector บล็อก IP ทดสอบ (8.8.8.8) → ตรวจ rule ใน Windows Firewall → ปลดบล็อก + ทำความสะอาด — แสดงผลทีละขั้นตอนบนหน้าเว็บ

### แก้บั๊กสำคัญ (code review รอบ 1)
- **RDP engine แตกบน Windows 10/2016+** — 4625/4624 layout ต่างจาก Win7 → parser ใหม่แบบ version-agnostic (หา LogonType + IP อัตโนมัติทั้งสอง layout) — ระบบหลักกลับมาทำงานบน Win10/11
- **MySQL/Generic engine ไม่เคยอ่าน log** — tailer ถูกสร้างใหม่ทุก poll → เก็บ tailer แบบถาวร + รองรับ rotation
- **`/api/overview` 500** บนเครื่องที่ไม่มี OpenSSH → กัน crash
- **อ่าน event log แบบช้า** (backward ตลอด) → สลับเป็น FORWARDS หลัง sync ครั้งแรก — event ใหม่เห็นทันทีแม้ log ใหญ่
- **ตารางเหตุการณ์/สถิติว่างเปล่า** — `db.add_event` ไม่เคยถูกเรียก → บันทึกทุก event แล้ว
- **CIDR ใน whitelist/blacklist ไม่ match** → match แบบ network containment
- **บล็อก CIDR ผ่าน UI/CLI ไม่ได้** → รองรับแล้ว
- IIS W3C parse `#Fields:` ต่อไฟล์ (ไม่ใช้ index ตายตัว)
- firewall ports ส่งผ่าน queue (กัน race ข้าม thread), ปิด handle ตอนจบ, rule_prefix มีผลทันที
- config เขียนแบบ atomic (temp + replace), log หมุนเวียน 5MB/5 ไฟล์, session per-token (หมดอายุ 24 ชม. + กัน logout ไขว้), body cap 1MB
- JS: clearInterval ไม่ซ้อนกัน, log-view ไม่ snap กลับล่างเมื่อเลื่อนเอง, CLI block กัน crash

### ระบบฉุกเฉิน (กันผู้ดูแลถูกล็อกตัวเอง)
- **active_session_grace_minutes** (30) — ไม่บล็อก IP ที่ล็อกอินสำเร็จล่าสุด (มี session จริง)
- **auto-unblock** — IP ถูกบล็อกแล้วแต่ล็อกอินผ่าน → ปลดบล็อก + ลบ rule ทันที
- **whitelist reconcile** — cleanup ปลดบล็อก IP ที่ไปอยู่ใน whitelist/never_block_ips
- **never_block_ips** ใน config (แก้ไฟล์ตรง ๆ ได้เมื่อฉุกเฉิน)
- CLI: `unblock-all` / `allow <ip>` — ใช้จาก console จริง/iDRAC/VM console ได้ ไม่ต้องพึ่ง RDP
- Web UI: ปุ่ม "ปลดบล็อกทั้งหมด (ฉุกเฉิน)" + พาเนลสถานะระบบมี "วิธีแก้ไข" ทุกจุด

### Backlog (ยังไม่แก้ — LOW)
session หมดอายุของ UI ยังไม่มี refresh token, geoip cache ไม่มี bound, login-guard เป็น global (DoS เฉพาะหน้า login), password ส่งกลับใน settings JSON, copytruncate rotation นับซ้ำ, ไม่มี single-instance guard

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
