# Roadmap v1.9.0

เอกสารแผนพัฒนาสำหรับเฟสถัดไปหลัง RDPGuard v1.8.0

## เป้าหมาย

เพิ่มความสามารถด้านการดูแลระบบและการวิเคราะห์ข้อมูล โดยเน้นสี่ส่วน:

- Service Watchdog ตรวจสุขภาพ Monitor, Event Log, Engine, Firewall และ Database
- ตัวเลือกความหนาแน่นของตารางบนจอใหญ่
- หน้ารายละเอียด IP แบบรวมศูนย์
- รายงานสรุปรายวันและรายสัปดาห์

แนวทาง UI ใช้ Product Dashboard สำหรับผู้ดูแลระบบ เน้นข้อมูลอ่านง่าย, สถานะมีข้อความกำกับ และรองรับ `prefers-reduced-motion` ตาม `PRODUCT.md` และ `DESIGN.md`

## เฟส 1: โครงสร้างกลาง

### งาน

- เพิ่ม Scheduler ใน `Monitor` โดยใช้ Worker เดียวร่วมกัน ไม่สร้าง Thread แยกหลายตัวโดยไม่จำเป็น
- เพิ่ม Health Snapshot กลางสำหรับ Monitor, Engine, Event Log, Firewall และ Database
- เพิ่ม Query สำหรับสรุป Events, IP, Engine และช่วงเวลา
- เพิ่มตาราง `report_runs` ป้องกันรายงานส่งซ้ำหลัง Service restart
- เพิ่ม Config section `[watchdog]` และ `[report]`
- เพิ่มระบบแจ้งเตือนเฉพาะตอนสถานะเปลี่ยน เพื่อลดการส่งซ้ำ

### ไฟล์หลัก

```text
rdpguard/monitor.py
rdpguard/database.py
rdpguard/config.py
rdpguard/notify.py
rdpguard/webui.py
```

## เฟส 2: Service Watchdog

### จุดตรวจ

- Monitor thread ยังทำงานอยู่หรือไม่
- Engine แต่ละตัวทำงานหรือหยุด
- Security Event Log อ่านได้หรือไม่
- Windows Firewall COM เข้าถึงได้หรือไม่
- โปรแกรมมีสิทธิ์เพิ่ม/ลบ Firewall Rule หรือไม่
- SQLite/WAL ยังเขียนได้หรือไม่
- พื้นที่ดิสก์เหลือน้อยผิดปกติหรือไม่

### พฤติกรรมแจ้งเตือน

- แจ้งเมื่อเปลี่ยนจากปกติเป็นผิดปกติ
- แจ้งเมื่อระบบกลับมาปกติ
- รอครบจำนวนครั้งก่อนแจ้ง เช่น 3 รอบ
- ใช้ cooldown ป้องกันแจ้งเตือนซ้ำ
- บันทึกเหตุการณ์ลง Audit Log และ `rdpguard.log`

### Config ที่แนะนำ

```ini
[watchdog]
enable = true
interval_seconds = 60
failure_threshold = 3
notify_recovery = true
cooldown_seconds = 900
```

### ข้อจำกัด

ถ้า Process หรือ Windows Service ตายทั้งตัว Watchdog ภายในจะส่งแจ้งเตือนไม่ได้ จึงควรตั้งค่า Windows Service Recovery ให้ Restart service อัตโนมัติแยกต่างหาก

### UI

เพิ่มพาเนล Watchdog แสดงสถานะรวม, เวลาตรวจล่าสุด, ส่วนที่ผิดปกติ, Error ล่าสุด, วิธีแก้ไข และเวลาที่กลับมาปกติ

## เฟส 3: ตัวเลือกความหนาแน่นตาราง

### แนวทาง

ใช้ค่าเฉพาะ Browser ผ่าน `localStorage` ไม่เก็บใน Config กลาง เพราะผู้ดูแลแต่ละคนอาจต้องการความหนาแน่นต่างกัน

ตัวเลือก:

- `comfortable`: อ่านง่าย เป็นค่าเริ่มต้น
- `compact`: แสดงข้อมูลต่อหน้ามากขึ้น

### สิ่งที่จะปรับ

- padding ของแถวตาราง
- ความสูงของแถว
- ขนาดตัวอักษร
- ระยะห่างระหว่างพาเนล
- ความสูงของ Log viewer
- ระยะห่างของปุ่มและตัวกรอง

### ข้อกำหนด

- แสดงตัวเลือกบนจอใหญ่
- จอมือถือคงขนาดที่อ่านง่าย
- ปุ่มต้องมีพื้นที่กดที่เพียงพอ
- รองรับ `prefers-reduced-motion`

ตำแหน่งที่เหมาะสม: Header → `Comfortable` / `Compact`

## เฟส 4: หน้ารายละเอียด IP

### API

เพิ่ม Endpoint หลัก:

```text
GET /api/ip/{ip}
```

ข้อมูลที่ควรคืน:

- IP และประเทศ
- สถานะ Blocked
- สถานะ Whitelist/Blacklist
- จำนวน Events ทั้งหมดและใน 24 ชั่วโมง
- เวลาที่พบครั้งแรกและล่าสุด
- จำนวน Fail/Success
- Engine ที่พบ
- ประวัติการบล็อก
- ตัวนับสะสม
- Firewall Rule ที่เกี่ยวข้อง

เพื่อไม่โหลด Events ทั้งฐานข้อมูล ให้แบ่งเป็น Endpoint ย่อย:

```text
GET /api/ip/{ip}/summary
GET /api/ip/{ip}/events?limit=100
GET /api/ip/{ip}/history?limit=100
```

### UI

เมื่อคลิก IP จาก Events หรือ Blocked ให้เปิด Detail Drawer ด้านข้างแทน Modal ใหญ่

แสดง Header ของ IP, ประเทศ, สถานะ, สรุปจำนวนครั้ง, Engine, Timeline, ประวัติ Block/Unblock และปุ่ม Block, Unblock, Allow, Blacklist และส่งออกข้อมูล

ต้องรองรับ IPv4, IPv6 และ CIDR พร้อม encode IP ใน URL อย่างถูกต้อง

## เฟส 5: รายงานรายวัน/รายสัปดาห์

### ข้อมูลในรายงาน

- จำนวนล็อกอินล้มเหลว
- จำนวนล็อกอินสำเร็จ
- จำนวน IP ไม่ซ้ำ
- จำนวน IP ที่ถูกบล็อก
- Top IP ที่โจมตี
- Top Engine
- ประเทศที่พบมากที่สุด
- IP ที่ยังถูกบล็อกอยู่
- Watchdog Incident
- สถานะระบบโดยรวม

### Config ที่แนะนำ

```ini
[report]
enable = false
daily_enable = true
daily_time = 08:00
weekly_enable = false
weekly_day = monday
weekly_time = 08:00
include_top_ips = true
include_top_engines = true
```

ใช้ช่องทางจาก `[notify]` เดิม ได้แก่ Telegram, Email และ Webhook

### API และ UI

เพิ่ม Endpoint:

```text
GET /api/reports/status
GET /api/reports/preview?period=daily
POST /api/reports/send-test
```

ใน Settings เพิ่มการเปิด/ปิดรายงาน, เวลา Daily Report, วันและเวลา Weekly Report, ข้อมูลที่จะรวม, ปุ่ม Preview, ปุ่มส่งทดสอบ และสถานะรายงานล่าสุด

### ความเสถียรและความปลอดภัย

- ปิดไว้เป็นค่าเริ่มต้น
- ส่งผ่าน Worker ไม่บล็อก Monitor
- ใช้ `report_runs` ป้องกันการส่งซ้ำ
- แบ่งข้อความ Telegram หากยาวเกินข้อจำกัด
- ส่งรายงานว่างเมื่อไม่มีข้อมูล เพื่อยืนยันว่า Scheduler ยังทำงาน
- ไม่ใส่ Token หรือ Password ในรายงาน

## ลำดับการทำงาน

1. ทำ Scheduler และ Health Snapshot
2. ทำ Service Watchdog
3. ทำ IP Detail API และ UI
4. ทำ Density Selector
5. ทำ Report Builder และ Report Scheduler
6. เชื่อม Settings, Status และ Notification
7. ทดสอบ Service, Notification และฐานข้อมูลขนาดใหญ่
8. อัปเดตเอกสารและ Release เป็น v1.8.0

## เกณฑ์ผ่าน

- Watchdog ไม่ส่งแจ้งเตือนซ้ำระหว่างปัญหาเดิม
- Service restart แล้วไม่ส่งรายงานซ้ำ
- IP Detail ไม่โหลด Events ทั้งฐานข้อมูล
- Compact Mode ไม่ทำให้ข้อมูลสำคัญถูกตัด
- รายงาน Daily/Weekly ใช้เวลาท้องถิ่นถูกต้อง
- Telegram, Email และ Webhook ส่งรายงานได้
- ไม่มี Secret ใน API, Log หรือรายงาน
- Desktop และ Mobile ไม่มีหน้าล้น
- `compileall`, `node --check`, Regression, Browser smoke และ Self-test ผ่าน
