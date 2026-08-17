# REST API

Web UI ของ RDPGuard เป็น REST API ง่าย ๆ (JSON) — เปิดเฉพาะ `127.0.0.1:8123` (ค่าเริ่มต้น)

- ทุก endpoint ต้องล็อกอินก่อน ยกเว้น `/api/login-status`, `/api/setup-status`, `/api/login` และ `/api/logout`
- ล็อกอินแล้วระบบจะให้ cookie `rdpguard_session` — ส่งติดตัวไปทุก request
- session มีอายุ 24 ชั่วโมง และต่ออายุอัตโนมัติเมื่อใช้งานต่อเนื่อง
- กันเดารหัสแยกตาม IP: พลาด 5 ครั้ง → ล็อก 5 นาที (จำกัดรายการ guard สูงสุด 1000 IP)
- POST ที่ส่ง `Origin` หรือ `Referer` ต้องตรงกับ `Host` เพื่อป้องกัน CSRF; curl ที่ไม่ส่ง header ดังกล่าวยังใช้ได้
- ตัวอย่างใช้ `curl` (Windows 10+ มีในตัว) — บันทึก cookie ลงไฟล์ `cookies.txt`

## ล็อกอิน

```bash
curl -s -c cookies.txt -X POST http://127.0.0.1:8123/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"password\":\"<รหัสผ่าน>\"}"
```

ต่อจากนั้นทุกคำสั่งเพิ่ม `-b cookies.txt`

## รูปแบบการตอบกลับ

```json
{ "ok": true,  "data": { ... } }
{ "ok": false, "error": "ข้อความผิดพลาด" }
```

## Endpoints

### GET /api/login-status
สถานะล็อกอิน + บริบทการรัน
```json
{ "ok": true, "data": { "authorized": true, "context": "service" } }
```
`context`: `service` (รันใน Windows Service) / `standalone-admin` / `standalone`

### POST /api/login
body: `{ "password": "..." }` → คืน `{ "token": "..." }` และ set cookie

### GET /api/setup-status
สถานะว่า Setup Wizard ทำเสร็จแล้วหรือยัง
```json
{ "ok": true, "data": { "setup_done": true } }
```

### POST /api/logout
ออกจากระบบ

### GET /api/overview
สถิติ + สถานะโดยรวม
```json
{
  "ok": true,
  "data": {
    "version": "1.7.0",
    "context": "service",
    "monitor_running": true,
    "stats": {
      "failed_24h": 128, "success_24h": 3,
      "blocked_active": 7, "blocked_total": 45, "blocked_manual": 1
    },
    "settings_summary": { "max_attempts": 5, "window_minutes": 10, "block_hours": 24, "enable": true }
  }
}
```

### GET /api/events?limit=100
เหตุการณ์ล่าสุด (max 500) เรียงใหม่สุดก่อน
```json
{ "ok": true, "data": { "events": [
  { "id": 1, "ts": "2026-08-16T05:00:00Z", "kind": "fail",
    "ip": "203.0.113.9", "user": "Administrator", "domain": "SERVER", "logon_type": 3,
    "source": "openssh" }
] } }
```
- `kind`: `fail` / `success` / `ntlm`
- `source`: engine ที่พบ — `rdp` / `openssh` / `mssql` / `iis` / `mysql` / `generic` (หรือ `generic:<ชื่อ>`)

### GET /api/blocked
```json
{ "ok": true, "data": { "blocked": [
  { "ip": "203.0.113.9", "reason": "ล็อกอิน RDP ล้มเหลวเกินกำหนด (auto)",
    "source": "auto", "created": "...", "expires": "...", "rule_name": "RDPGuard Block 203.0.113.9" }
] } }
```
`source`: `auto` / `manual` / `blacklist` / `accumulate` — `expires` ว่าง = ถาวร

### POST /api/blocked
บล็อกด้วยมือ — body: `{ "ip": "203.0.113.9", "hours": 24 }` (`hours` 0 = ถาวร, รองรับ CIDR)

### DELETE /api/blocked/{ip}
ปลดบล็อก (ip ต้อง URL-encode)

### GET /api/whitelist / GET /api/blacklist
```json
{ "ok": true, "data": { "whitelist": [ { "ip": "192.168.1.0/24", "note": "", "created": "..." } ] } }
```

### POST /api/whitelist / POST /api/blacklist
body: `{ "ip": "192.168.1.0/24", "note": "สำนักงาน" }` (รองรับ CIDR)

### DELETE /api/whitelist/{ip} / DELETE /api/blacklist/{ip}

### GET /api/settings
คืน config ปัจจุบันทั้งไฟล์ (ยกเว้นรหัสผ่านจริง — ใช้ `webui.password_hidden` แทน)
```json
{ "ok": true, "data": { "general": { "log_level": "INFO", "log_max_mb": "5", "event_retention_days": "90" }, "monitor": { ... }, "webui": { "password_set": true }, "notify": { "telegram_bot_token_set": true }, ... } }
```
ค่าลับจะไม่อยู่ใน response; ใช้คีย์ลงท้าย `_set` เพื่อตรวจว่าตั้งค่าแล้วหรือยัง

### GET /api/sessions
คืน session RDP/console/network ที่กำลังใช้งาน — พยายามใช้ `qwinsta`/`query session` และ fallback เป็น WTS API (`win32ts`)
```json
{ "ok": true, "data": { "sessions": [
  { "type": "rdp", "user": "Administrator", "session_id": "2", "state": "Active", "started": "..." }
] } }
```

### GET /api/service
สถานะ Windows Service + สิทธิ์ควบคุม
```json
{ "ok": true, "data": {
  "installed": true, "state": "running", "running": true,
  "context": "standalone", "is_admin": true, "can_control": true
} }
```
- `context`: `service` (รันใน service — ควบคุมไม่ได้) / `standalone-admin` / `standalone`
- `can_control` = มีสิทธิ์ admin และไม่ได้รันใน service

### POST /api/service/action
ควบคุม service — body: `{ "action": "install" | "remove" | "start" | "stop" | "restart" }`
- ต้องมีสิทธิ์ admin (คืน 403 ถ้าไม่มี) และต้องไม่ได้รันใน service เอง

### GET /api/detection-state
สถานะการตรวจจับ: `{ "enable": true, "engines": { "openssh": true, "mssql": true, "iis": true, "mysql": true, "generic": true } }`

### POST /api/toggle
เปิด/ปิดทันที — body: `{ "key": "enable" }` (เฝ้าระวังทั้งหมด) หรือ `{ "engine": "openssh" }` (engine ตัวเดียว: openssh/mssql/iis/mysql/generic)

### GET /api/log?lines=250
log ล่าสุด (รับค่า 1–2000; ค่าติดลบจะถูกปรับเป็น 1) — server อ่านเฉพาะ 64 KB ท้ายสุดของไฟล์ปัจจุบัน
```json
{ "ok": true, "data": { "lines": ["..."], "file": "C:\\...\\rdpguard.log", "file_size": 47942 } }
```

### GET /api/log/files
รายการไฟล์ `rdpguard.log` และไฟล์หมุนเวียนที่อนุญาตให้ดู

### GET /api/log/download?file=rdpguard.log.1
ดาวน์โหลดไฟล์ Log ที่อนุญาต — ไม่รับ path นอก data directory

### POST /api/geoip
หาประเทศของ IP — body: `{ "ips": ["8.8.8.8", ...] }` (ประมวลผลสูงสุด 20 IP ต่อครั้ง)
```json
{ "ok": true, "data": { "geoip": { "8.8.8.8": { "code": "US", "country": "United States", "flag": "🇺🇸" } } } }
```
ถ้าไม่มีข้อมูล (ออฟไลน์/IP ผิด) → `null`

### POST /api/health/test-firewall
ทดสอบบล็อกจริง: เพิ่ม + ลบ rule ทดสอบ (203.0.113.254 TEST-NET) แล้วรายงานผล
```json
{ "ok": true, "data": { "working": true, "message": "Firewall ทำงานได้จริง — ..." } }
```
`working: false` + เหตุผลเมื่อทำไม่ได้ (เช่น ไม่มีสิทธิ์ admin)

### POST /api/unblock-all
ฉุกเฉิน: ปลดบล็อกทุก IP ที่ RDPGuard บล็อกไว้ (ลบ rule firewall + ลบจากตาราง) — `{ "message": "ปลดบล็อกทั้งหมดแล้ว (N IP)" }`

### POST /api/self-test
ทดสอบระบบครบวงจร (ต้องรันด้วย admin/service) — เขียน event จำลองตาม `max_attempts` (ค่าเริ่มต้น 5, Event 18456, `CLIENT: 8.8.8.8`) ลง Application log จริง → รอ engine ตรวจจับ + บล็อก → ตรวจ rule firewall → ปลดบล็อก + ลบ event ทดสอบ
```json
{ "ok": true, "data": {
  "working": true,
  "steps": ["เขียน event จำลอง 5 รายการ ... OK", "engine MSSQL อ่าน event → detector บล็อก 8.8.8.8 — OK", "...", "ปลดบล็อก + ลบ event ทดสอบ — OK"],
  "message": "✅ self-test ผ่านครบวงจร: ..."
} }
```
- ใช้เวลาไม่เกินประมาณ 25 วินาที (รอ engine poll + บล็อก)
- ต้องเปิด engine `mssql` อยู่ และ `monitor.enable = true`

### POST /api/notify/test
ส่งข้อความทดสอบตามช่องทางที่เลือกใน `[notify]` — ทดสอบได้ทั้งโหมด monitor และ `python run.py web` โดยไม่ต้องเปิดการเฝ้าระวัง
```json
{ "ok": true, "data": { "message": "ผลทดสอบแจ้งเตือน", "results": { "telegram": "ok", "email": "ไม่ได้เลือกช่องนี้" } } }
```

### GET /api/notify/status
คืนสถานะการตั้งค่าและผลการส่งล่าสุด โดยไม่คืนข้อมูลลับ

### GET /api/trends?days=7
คืนจำนวน Events `fail`/`success` รายวัน (สูงสุด 31 วัน)

### GET /api/blocked-history?limit=100
ประวัติ IP ที่ถูกปลดบล็อก พร้อม `unblocked_at` และ `unblocked_by`

### GET /api/blocked-history/export
ส่งออกประวัติการบล็อกเป็น CSV

### GET /api/audit?limit=100
Audit Log จากการจัดการผ่าน Web UI

### GET /api/audit/export
ส่งออก Audit Log เป็น CSV

### POST /api/blocked/bulk-unblock
ปลดบล็อกหลายรายการ — body `{ "ips": ["203.0.113.9", "198.51.100.4"] }` สูงสุด 200 รายการ

### GET /api/events/export / GET /api/blocked/export
ส่งออก Events หรือรายการ Blocked เป็น CSV ตามตัวกรองเดียวกับ endpoint หลัก จำกัดสูงสุด 100,000 รายการ

### GET /api/backup
ดาวน์โหลด ZIP backup ที่ล้างค่าลับออกจาก config แล้ว

### POST /api/backup/restore
อัปโหลด ZIP backup ด้วย `Content-Type: application/zip`; ตรวจ SQLite integrity แล้วเก็บเป็นไฟล์รอ restart ไม่เขียนทับฐานข้อมูลที่กำลังใช้งาน

> `/api/overview` มีฟิลด์ `health` ด้วย: `{ is_admin, in_service, can_add_rules, eventlog_ok, firewall_com_ok, engines: {...}, monitor_running }` — ใช้ตรวจสถานะส่วนประกอบสำคัญ

### POST /api/settings
บันทึก config — รับเฉพาะ key ที่อนุญาตต่อ section (ดู [CONFIG.md](CONFIG.md)) แล้วมีผลทันที ไม่ต้อง restart ยกเว้น `webui.host`/`webui.port`, ค่า logging และ retention ใน `[general]` ที่ต้อง restart
```json
{ "detection": { "max_attempts": "8", "window_minutes": "15" } }
```

### POST /api/setup/complete
ทำเครื่องหมายว่า Setup Wizard เสร็จแล้ว — body `{}` และมีผลทันที

## ตัวอย่างใช้งานจริง

```bash
:: ล็อกอิน + บันทึก cookie
curl -s -c cookies.txt -X POST http://127.0.0.1:8123/api/login -H "Content-Type: application/json" -d "{\"password\":\"abc\"}"

:: ดูสถิติ
curl -s -b cookies.txt http://127.0.0.1:8123/api/overview

:: บล็อก IP 48 ชั่วโมง
curl -s -b cookies.txt -X POST http://127.0.0.1:8123/api/blocked -H "Content-Type: application/json" -d "{\"ip\":\"203.0.113.9\",\"hours\":48}"

:: ปลดบล็อก
curl -s -b cookies.txt -X DELETE http://127.0.0.1:8123/api/blocked/203.0.113.9
```

## HTTP status code

| Code | ความหมาย |
|---|---|
| 200 | สำเร็จ |
| 400 | ข้อมูลไม่ถูกต้อง (เช่น IP รูปแบบผิด) |
| 401 | ยังไม่ล็อกอิน / รหัสผิด |
| 403 | ไม่ผ่าน Origin/Referer หรือไม่มีสิทธิ์ควบคุม service/self-test |
| 404 | ไม่พบเส้นทาง |
| 429 | ล็อกอินพยายามเกินกำหนด (5 ครั้ง → รอ 5 นาที) |
