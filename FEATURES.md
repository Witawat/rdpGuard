# ฟีเจอร์ RDPGuard

เอกสารนี้สรุปความสามารถของ RDPGuard รุ่น v1.7.0 แบ่งตามงานที่ผู้ดูแลระบบใช้จริง

## การตรวจจับ

- ตรวจจับ RDP จาก Windows Security Event Log: Event 4625, 4624 และ 4776
- ตรวจจับ OpenSSH จาก Event 4
- ตรวจจับ MSSQL จาก Event 18456
- ตรวจจับ IIS และ RD Web จาก W3C log
- ตรวจจับ MySQL จาก error log
- ตรวจจับโปรแกรมอื่นด้วย Generic Engine และ Python regex
- นับความถี่แยกตาม Engine และ IP
- รองรับการตั้งค่า LogonType ที่ต้องการนับ
- รองรับตัวนับสะสมสำหรับการโจมตีแบบยิงสั้น ๆ แล้วเปลี่ยน IP
- รองรับการขยายเวลาบล็อกสำหรับ IP ที่กลับมาโจมตีซ้ำ
- รองรับ active session grace เพื่อป้องกันบล็อกผู้ดูแลที่กำลังใช้งานจริง

## Windows Firewall

- บล็อก IP อัตโนมัติด้วย Windows Firewall
- ใช้ HNetCfg COM API และมี `netsh` เป็นทางสำรอง
- โหมด Rule เดียวเก็บ IP รวมใน `RemoteAddresses`
- รองรับโหมด Rule แยกต่อ IP
- จำกัดพอร์ตที่ต้องการบล็อกได้ เช่น 3389, 1433 และ 22
- ปลดบล็อกอัตโนมัติเมื่อหมดเวลา
- ต่ออายุการบล็อกเมื่อ IP เดิมยังโจมตีต่อ
- Reconcile Rule ที่ถูกลบหรือแก้จากภายนอก
- ปลดบล็อกฉุกเฉินทั้งหมดจาก Web UI หรือ CLI

## Whitelist และ Blacklist

- Whitelist รองรับ IP และ CIDR
- เพิ่ม Whitelist แล้วปลดบล็อกทันที
- IP ใน Whitelist จะไม่ถูกบล็อกอัตโนมัติ
- Blacklist รองรับ IP และ CIDR
- เพิ่ม Blacklist แล้วสร้าง Firewall Rule ทันที
- ลบ Blacklist แล้วปลดบล็อก Rule ที่เกิดจาก Blacklist
- ใส่หมายเหตุประกอบรายการได้

## การแจ้งเตือน

- แจ้งเตือนผ่าน Telegram Bot
- แจ้งเตือนผ่าน Email SMTP
- เลือก Telegram, Email หรือทั้งสองช่องทางได้
- รองรับ Webhook เสริมด้วย JSON รูปแบบ `{"text":"..."}`
- รวมหลายเหตุการณ์ตามค่า cooldown เพื่อลดการส่งถี่เกินไป
- ส่งผ่าน Worker Thread ไม่ทำให้การบล็อก IP ช้าลง
- Retry เมื่อเครือข่ายขัดข้อง
- มีปุ่มส่งข้อความทดสอบ
- แสดงผลการส่งล่าสุดและสถานะการตั้งค่า
- รองรับการปิด SSL verification สำหรับ Telegram/Webhook เมื่อมี HTTPS interception
- ทุกข้อความระบุ `[ชื่อเครื่อง]` — ตั้งชื่อเครื่องเองได้ (ว่าง = ชื่อเครื่องระบบ) เหมาะกับเฝ้าหลายเครื่อง

## ควบคุมผ่าน Telegram (Telegram Command)

- รับคำสั่งควบคุม RDPGuard ผ่าน Bot API แบบ long-polling ไม่ต้องเปิดพอร์ต/HTTPS
- รองรับ `/status`, `/where`, `/block`, `/unblock`, `/unblock-all`, `/allow`, `/blacklist`, `/whitelist`, `/list`, `/events`, `/log`, `/ping` และ `/help`
- รับคำสั่งจาก `telegram_chat_id` ที่ตั้งไว้เท่านั้น
- จำกัดคำสั่งต่อนาทีต่อแชท
- `/unblock-all` ต้องยืนยัน `/confirm` ภายในเวลาที่กำหนด
- บันทึกทุกคำสั่งลง Audit Log (actor = `telegram:<chat_id>`)
- ตรวจสอบสถานะได้จากหน้า ตั้งค่า และ `GET /api/telegram/status`
- **ใช้หลายเครื่องกับ bot เดียวได้** — ทุกคำตอบขึ้นต้นด้วย `[ชื่อเครื่อง]`, สั่งเครื่องเป้าหมายด้วย `@ชื่อเครื่อง` ต่อท้ายคำสั่ง (`/status @srv-a`), และมี `/where` ดูชื่อเครื่อง

## Web UI

- Dashboard แสดงจำนวนล็อกอินผิด, ล็อกอินสำเร็จ, IP ที่ถูกบล็อก และกฎปัจจุบัน
- แสดงแนวโน้ม Events ล้มเหลวและสำเร็จย้อนหลัง 7 วัน
- แสดงสถานะ Security Event Log, Firewall, สิทธิ์, Monitor และ Engine
- ปุ่มทดสอบ Firewall จริง
- ปุ่ม Self-test ครบวงจร Event Log → Engine → Detector → Firewall → Unblock
- ควบคุม Windows Service จากหน้าเว็บเมื่อมีสิทธิ์ Administrator
- แสดง Events พร้อมค้นหาและกรองตามข้อความ, Engine และประเภท
- แบ่งหน้า Events และ Blocked เพื่อลดการโหลดข้อมูลจำนวนมาก
- เลือก Blocked หลายรายการแล้วปลดบล็อกเป็นชุด
- ส่งออก Events และ Blocked เป็น CSV
- แสดงประเทศและธงของ IP ผ่าน GeoIP cache
- แสดงประวัติการบล็อกและ Audit Log
- ส่งออกประวัติและ Audit Log เป็น CSV
- แสดง Session RDP, Console และ Network ที่กำลังใช้งาน
- มี Setup Wizard สำหรับการตั้งค่าครั้งแรก

## Log และฐานข้อมูล

- Log หมุนเวียนอัตโนมัติตามขนาดไฟล์
- ค่าเริ่มต้น 5 MB ต่อไฟล์ และเก็บไฟล์สำรอง 5 ไฟล์
- Web UI อ่านเฉพาะ 64 KB ท้ายไฟล์ จึงไม่โหลด Log ทั้งไฟล์
- เลือกดู `rdpguard.log`, `.1`, `.2` และไฟล์หมุนเวียนอื่นได้
- ค้นหาข้อความใน Log และหยุดการ refresh ได้
- ดาวน์โหลด Log จาก Web UI
- SQLite ใช้ WAL และ `busy_timeout` รองรับการอ่าน/เขียนพร้อมกัน
- Retention สำหรับ Events, Blocked History และ Audit Log
- Backup ฐานข้อมูลและ Config แบบล้างค่าลับ
- ตรวจสอบ SQLite integrity ก่อนรับ Restore
- Restore ฐานข้อมูลหลัง restart เพื่อไม่เขียนทับฐานข้อมูลที่กำลังเปิด

## ความปลอดภัย

- Login ด้วย Session Cookie อายุ 24 ชั่วโมงและต่ออายุอัตโนมัติ
- จำกัดการเดารหัสแยกตาม IP
- ป้องกัน CSRF ด้วย Origin/Referer check
- ไม่ส่ง Web UI password, Telegram Token, SMTP password หรือ Webhook URL กลับใน API
- ช่องข้อมูลลับใช้ Password Input และเว้นว่างเพื่อคงค่าเดิม
- เพิ่ม Content Security Policy
- เพิ่ม `X-Content-Type-Options`, `X-Frame-Options` และ `Referrer-Policy`
- ป้องกันการรัน RDPGuard ซ้ำหลาย Instance
- Escape ข้อมูลใน HTML และป้องกัน CSV formula injection ตอนส่งออก

## CLI และการติดตั้ง

- ติดตั้ง, ถอน, เริ่ม, หยุด, Restart และตรวจสถานะ Windows Service
- รัน Foreground พร้อม Monitor และ Web UI
- รัน Web UI แยกสำหรับทดสอบ
- Block, Unblock, Unblock-all และ Allow IP/CIDR
- ดูหรือ Reset รหัสผ่าน Web UI
- Build เป็นไฟล์ exe เดียวด้วย PyInstaller
- ใช้ UPX ลดขนาด exe
- รองรับ Windows 8.1 ขึ้นไปสำหรับ exe ที่ build ด้วย Python 3.11
- รองรับ Windows 7 เมื่อ build ด้วย Python 3.8 ตามข้อกำหนดของ Python

## เฟสถัดไป

### เฟส 1: Final QA และ Release v1.7.0

- ทดสอบ Service จริงด้วยสิทธิ์ SYSTEM
- ทดสอบ Self-test ด้วยสิทธิ์ Administrator
- ทดสอบ Telegram, Email และ Webhook จริง
- ทดสอบ Backup และ Restore หลัง restart
- ตรวจประสิทธิภาพเมื่อ Events และ Blocked มีข้อมูลจำนวนมาก
- ตรวจ Secret ไม่หลุดใน API, Log และ Backup
- Commit, Push และสร้าง GitHub Release

### เฟส 2: การเชื่อมต่อและการดูแลขั้นสูง

- เพิ่มรูปแบบ Webhook สำเร็จรูปสำหรับ Discord และ Slack
- เพิ่มการตั้งค่า HTTPS หรือ Reverse Proxy สำหรับ Web UI ภายนอกเครื่อง
- เพิ่ม Restore Config แบบเลือกเฉพาะ Section
- เพิ่ม Audit Log แบบแบ่งหน้าและกรองตามช่วงเวลา

### เฟส 3: รายงานและการดูแลระบบ

- รายงานสรุปการโจมตีรายวันและรายสัปดาห์
- Backup แบบตั้งเวลาและเก็บหลายรุ่น
- แจ้งเตือนเมื่อ Firewall Rule ถูกลบหรือแก้จากภายนอก
- แจ้งเตือนเมื่ออ่าน Event Log หรือ Engine ไม่ได้
