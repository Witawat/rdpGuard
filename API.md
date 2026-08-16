# REST API

Web UI ของ RDPGuard เป็น REST API ง่าย ๆ (JSON) — เปิดเฉพาะ `127.0.0.1:8123` (ค่าเริ่มต้น)

- ทุก endpoint ต้องล็อกอินก่อน ยกเว้น `/api/login-status` และ `/api/login`
- ล็อกอินแล้วระบบจะให้ cookie `rdpguard_session` — ส่งติดตัวไปทุก request
- กันเดารหัส: พลาด 5 ครั้ง → ล็อก 5 นาที
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

### POST /api/logout
ออกจากระบบ

### GET /api/overview
สถิติ + สถานะโดยรวม
```json
{
  "ok": true,
  "data": {
    "version": "1.0.0",
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
`source`: `auto` / `manual` / `blacklist` — `expires` ว่าง = ถาวร

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
คืน config ปัจจุบันทั้งไฟล์
```json
{ "ok": true, "data": { "general": { "log_level": "INFO" }, "monitor": { ... }, ... } }
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
log ล่าสุด (max 2000) — `{ "lines": ["..."], "file": "C:\\...\\rdpguard.log" }`

### POST /api/geoip
หาประเทศของ IP — body: `{ "ips": ["8.8.8.8", ...] }` (max 200 ต่อครั้ง)
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

> `/api/overview` มีฟิลด์ `health` ด้วย: `{ is_admin, in_service, can_add_rules, eventlog_ok, firewall_com_ok, engines: {...}, monitor_running }` — ใช้ตรวจสถานะส่วนประกอบสำคัญ

### POST /api/settings
บันทึก config — รับเฉพาะ key ที่อนุญาตต่อ section (ดู [CONFIG.md](CONFIG.md)) แล้วมีผลทันที ไม่ต้อง restart
```json
{ "detection": { "max_attempts": "8", "window_minutes": "15" } }
```

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
| 404 | ไม่พบเส้นทาง |
| 429 | ล็อกอินพยายามเกินกำหนด (5 ครั้ง → รอ 5 นาที) |
