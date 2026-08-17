# Changelog

## 1.9.0 (2026-08-17)

### ฟีเจอร์ใหม่

- **ระบุชื่อเครื่องใน Telegram** — ข้อความแจ้งเตือนทุกแบบ (บล็อกเดี่ยว, รวมชุด, ทดสอบ) ขึ้นต้นด้วย `[ชื่อเครื่อง]` — ตั้งเองได้ใน ตั้งค่า → แจ้งเตือน (ว่าง = ใช้ชื่อเครื่องระบบ)
- **Telegram Command รองรับหลายเครื่อง / bot เดียว** — ทุกคำตอบขึ้นต้นด้วย `[ชื่อเครื่อง]` รู้เสมอว่าคำตอบมาจากเครื่องไหน
- คำสั่งใหม่ `/where` — แสดงชื่อเครื่อง + เวอร์ชัน; `/status` แสดงชื่อเครื่องด้วย
- ระบุเครื่องเป้าหมายด้วย `@ชื่อเครื่อง` ต่อท้ายคำสั่ง เช่น `/status @srv-a` — เครื่องที่ไม่ใช่เป้าตอบปฏิเสธ ไม่ลงมือทำ (คำสั่งที่ส่งไปตกที่เครื่องใดเครื่องหนึ่งแบบสุ่ม — ส่งซ้ำจนกว่าคำตอบจะมาจากเครื่องที่ต้องการ)
- หน้า ตั้งค่า → แจ้งเตือน เพิ่มช่อง "ชื่อเครื่อง" (จำกัดอักขระ A-Za-z0-9_- ห้ามช่องว่าง/@)

### แก้บั๊กและความถูกต้อง

- ตรวจสอบค่าชื่อเครื่องฝั่ง server ก่อนบันทึก

## 1.8.0 (2026-08-17)

### ฟีเจอร์ใหม่

- **ควบคุม RDPGuard ผ่าน Telegram** — รับคำสั่งผ่าน Bot API (long-polling ไม่ต้องเปิดพอร์ต/HTTPS): `/status`, `/block`, `/unblock`, `/unblock-all`, `/allow`, `/blacklist`, `/whitelist`, `/list`, `/events`, `/log`, `/ping`, `/help`
- รับคำสั่งจาก `telegram_chat_id` ที่ตั้งไว้เท่านั้น, rate limit ต่อนาที, และ `/unblock-all` ต้องยืนยัน `/confirm`
- ทุกคำสั่งบันทึกลง Audit Log (actor = `telegram:<chat_id>`)
- หน้า ตั้งค่า → แจ้งเตือน เพิ่มกลุ่ม **Telegram Command** (เปิด/ปิด, timeout ยืนยัน, rate limit, สถานะ)
- เพิ่ม API `GET /api/telegram/status` สำหรับตรวจสอบสถานะ Telegram Command

### แก้บั๊กและความถูกต้อง

- Worker แยกจาก Monitor ไม่บล็อกการเฝ้าระวัง
- โหมด `web` หรือปิด `enable_commands` จะไม่รัน polling

## 1.7.0 (2026-08-17)

### ฟีเจอร์ใหม่

- **ความปลอดภัยของ Settings** — ไม่ส่ง Telegram Token, Chat ID, SMTP password, Webhook URL หรือ Web UI password กลับใน `/api/settings`; ช่องลับเป็น password input, เว้นว่างเพื่อคงค่าเดิม และมีปุ่มล้างค่าแยก
- **ค้นหาและส่งออกข้อมูล** — Events/Blocked/Blocked history/Audit Log มีตัวกรอง แบ่งหน้า และส่งออก CSV (ป้องกัน CSV formula injection)
- **Log viewer รุ่นใหม่** — เลือกไฟล์หมุนเวียน, ค้นหา, หยุด auto-refresh, ดาวน์โหลด และยังอ่านเฉพาะท้ายไฟล์ตามเดิม
- **ประวัติและ Audit Log** — เก็บการจัดการจาก Web UI และดูประวัติการปลดบล็อกได้
- **Retention ฐานข้อมูล** — ล้าง Events, Blocked history และ Audit Log เก่าตามจำนวนวันที่ตั้งค่าได้
- **แนวโน้มการโจมตี** — แสดง Events ล้มเหลว/สำเร็จรายวันย้อนหลัง 7 วัน
- **Webhook** — ส่งข้อความแจ้งเตือน JSON เพิ่มเติมจาก Telegram/Email
- **Backup/Restore** — ดาวน์โหลด backup แบบล้างค่าลับ และอัปโหลดฐานข้อมูลที่ตรวจ integrity แล้วเพื่อใช้หลัง restart
- **ตั้งค่า Log ใน Web UI** — ระดับ Log, ขนาดไฟล์, จำนวนไฟล์สำรอง และ retention พร้อมแจ้งค่าที่ต้อง restart

### แก้บั๊กและความถูกต้อง

- แก้ `hours=0` ใน API บล็อกด้วยมือให้เป็นบล็อกถาวรจริง ไม่ถูกแปลงเป็น 24 ชั่วโมง
- เพิ่ม validation ค่า config ฝั่ง server และไม่บันทึกบางส่วนเมื่อมีค่าผิด
- แก้ schema ฐานข้อมูลใหม่และ migration ฐานข้อมูลเก่าที่ไม่มีคอลัมน์ `events.source`
- แก้ manual/bulk unblock ไม่ลบรายการจาก DB หากลบ Firewall rule ไม่สำเร็จ
- แก้ `allow`/Whitelist ไม่รายงานสำเร็จหลอกเมื่อปลด Firewall rule ไม่ได้
- เพิ่ม security headers (`CSP`, `X-Frame-Options`, `Referrer-Policy`)
- ปรับหน้า UI ให้ไม่ล้นแนวนอนบนจอมือถือ

## 1.6.3 (2026-08-17)

- **แก้ Telegram error `CERTIFICATE_VERIFY_FAILED` (self-signed certificate)** — เกิดจาก proxy/โปรแกรมกันไวรัสที่ intercept HTTPS: เพิ่มตัวเลือก **"ตรวจสอบ SSL ของ Telegram"** (ตั้งค่า → แจ้งเตือน, config `telegram_verify_ssl`) — ปิดได้เมื่อขึ้น error นี้
- ข้อความ error ใหม่: ถ้าเจอ CERTIFICATE_VERIFY_FAILED จะแนะนำวิธีแก้ในข้อความเลย

## 1.6.2 (2026-08-17)

- **Log การทำงาน: ตั้งค่าได้ + แสดงข้อมูล** — dropdown เลือกจำนวนบรรทัด (250/500/1000) ในพาเนล Log + แสดงขนาดไฟล์ (KB/MB) ข้างชื่อไฟล์
- **ตั้งค่าการหมุนเวียน log ได้** — config `[general] log_max_mb` (ค่าเริ่มต้น 5 MB/ไฟล์) + `log_backups` (5 ไฟล์) — log ไม่โตเกินจำกัด; ระบบอ่านเฉพาะ 64KB ท้ายสุดของไฟล์ต่อ request (ไม่ค้างแม้ log เต็ม)
- แก้บั๊ก: `lines` ของ /api/log clamp 1-2000 (เดิม `-1` = ได้ทุกบรรทัดใน chunk)

## 1.6.1 (2026-08-17)

- **แจ้งเตือนเลือกช่องทางได้** — หน้า ตั้งค่า → แจ้งเตือน: dropdown "ช่องทางที่ใช้" (`both` ทั้งคู่ / `telegram` เท่านั้น / `email` เท่านั้น) — ระบบส่งเฉพาะช่องที่เลือก (ปุ่มทดสอบก็เคารพการเลือกด้วย)
- **แก้บั๊ก: บันทึกการตั้งค่าพังตั้งแต่ v1.5.3** — `settings-group` div มี `data-sec` (ใช้จัด layout) → save handler จับ div ด้วย → `el.value` undefined → TypeError กดบันทึกไม่ได้ — ตอนนี้ฟิลเตอร์เฉพาะ input/select แล้ว

## 1.6.0 (2026-08-17)

### ฟีเจอร์ใหม่

- **แจ้งเตือนเมื่อบล็อก IP (Telegram + Email)** — ตั้งค่าใน Web UI หน้า ตั้งค่า → "แจ้งเตือน (Telegram / Email)": Bot Token/Chat ID (จาก @BotFather) และ/หรือ SMTP (587 STARTTLS / 465 SSL) — ข้อความรวมหลาย IP ในรอบ `cooldown_seconds` (ค่าเริ่มต้น 60 วิ — กันสแปมตอนโจมตีหนัก) ส่งผ่าน worker thread แยก (ไม่หน่วงการบล็อก) + retry 2 ครั้ง — มีปุ่ม "ส่งข้อความทดสอบ" ในหน้า ตั้งค่า
- **single-instance guard** — รัน `run`/service ซ้ำ → เตือน "มี RDPGuard รันอยู่แล้ว" แทนการ bind พอร์ตชนเงียบ ๆ (Global mutex — ครอบทั้ง service และ standalone)
- **กัน CSRF** — POST ทุก request ตรวจ `Origin`/`Referer` ต้องตรงกับ Host (browser เก่า/iframe โจมตีไม่ได้; curl/CLI ไม่มี Origin ผ่านได้)

### ปรับปรุง / แก้บั๊ก

- **login-guard per-IP** (แทน global) — เดารหัสผิด 5 ครั้งล็อกเฉพาะ IP นั้น (เดิมล็อกทั้งระบบ — ใครก็ DoS หน้า login ได้) + จำกัด 1000 entries กัน IP ปลอม
- **UI session sliding** — ต่ออายุ session เมื่อเหลือ < ครึ่งของ 24 ชม. (ใช้งานต่อไม่หลุด)
- **GeoIP cache bound** — ลบ entry เก่ากว่า 30 วัน + จำกัด 10,000 แถว (DB) / 5,000 (RAM) — ไม่โตไม่รู้จบ
- **copytruncate กันนับซ้ำ** — ไฟล์ log ที่ถูก truncate (ขนาดลด) จะข้ามบรรทัดซ้ำกับบรรทัดสุดท้ายที่อ่านแล้ว (sentinel)
- **SQLite WAL mode** — เขียน/อ่านพร้อมกันจากหลาย thread ไม่ติด lock กัน (เครื่องโจมตีหนัก 4625 เยอะ) + busy_timeout

## 1.5.7 (2026-08-16)

- **exe เล็กลงด้วย UPX** — build.bat ดาวน์โหลด UPX (v5.2.0) ให้อัตโนมัติครั้งแรก (เก็บใน `tools\` — gitignore แล้ว) แล้วใช้บีบอัด DLLs ภายใน exe — ขนาดลดจาก 14.97 MB → **12.38 MB** (-17%) — `rdpguard.spec` ตั้ง `upx=True` ไว้แล้ว (เดิมไม่มี upx.exe เลยถูกข้ามไปเงียบ ๆ)
- หมายเหตุ: exe ที่ผ่าน UPX อาจถูก AV บางตัวฟลากง่ายขึ้น (packed executable) — ถ้าโดน ให้เพิ่ม exclude/รายงาน

## 1.5.6 (2026-08-16)

- **แก้ `uninstall.bat`**: ESC literal → `prompt $E` (กัน cmd parse พังข้ามเครื่อง เหมือน build.bat) — พร้อมเทสต์จริงครบ flow
- **`remove service` ไม่ traceback อีกต่อไป**: ตอน service ไม่ติดตั้ง → คืน "service ยังไม่ได้ติดตั้ง"; ตอนไม่มีสิทธิ์ → คืนคำแนะนำรัน admin (เดิม exception หลุด → uninstall.bat แสดง "[x] Failed" ผิด ๆ ทั้งที่ไม่มีอะไรต้องทำ)
- **console UTF-8**: `run.py` บังคับ stdout/stderr utf-8 — กัน UnicodeEncodeError (cp874/cp437) เวลาพิมพ์ข้อความที่มีอักขระพิเศษ

## 1.5.5 (2026-08-16)

- **พาเนล Session / Remote กลับมาทำงานครบทุกเครื่อง** — ลบ PowerShell CIM fallback (Norton Behavioral ฟลาก `powershell.exe` + embedded script base64 เป็น `IDP.HELU.PSE...` — pattern ที่ malware ใช้จริง) → เปลี่ยนเป็น **WTS API (win32ts)** ตรง ๆ แทน: เป็น DLL call ใน process ตัวเอง ไม่ spawn process ภายนอก — ใช้งานได้บนเครื่องที่ไม่มี `qwinsta` (Win11 บางรุ่น) และ Norton ไม่มีอะไรให้ฟลาก
- ลำดับอ่าน session: `qwinsta` → `query session` → `win32ts.WTSEnumerateSessions` (แสดง user/ชนิด session/สถานะ Active-Disc)

## 1.5.4 (2026-08-16)

### แก้บั๊ก (Bug fix round — code review ทั่วระบบ)

- **แก้ race ในโหมด single_rule** (firewall.py): `_cache` (รายการ IP ใน rule เดียว) ถูกแก้จากหลาย thread พร้อมกันโดยไม่มี lock → **lost update: IP หายจาก firewall ทั้งที่ DB บอก blocked** — เพิ่ม `_cache_lock` ครอบทุก add/remove/ตรวจ + `sync()` สำหรับ refresh จาก firewall จริง (reconcile ใช้ก่อนตรวจทุก 60 วิ — มองเห็น rule ที่ถูกรีเซ็ต/ลบจากภายนอกแล้วสร้างกลับ)
- **แก้ race ใน Web UI** (webui.py): `_sessions` + `_login_guard` แก้ข้าม thread ไม่มี lock → `RuntimeError: dictionary changed size during iteration` (500) และตัวนับกันเดารหัสพลาด — เพิ่ม `threading.Lock`
- **ความปลอดภัย**: `GET /api/settings` ไม่ส่ง `webui.password` ตัวจริงกลับอีกต่อไป (เหลือแค่ `password_hidden` แสดงสถานะ)
- **config lost update**: `save_config` ย้ายเข้า `_cfg_lock` (save settings + toggle พร้อมกันไม่ทับค่ากันอีก) + เขียนไฟล์ fail → แจ้งข้อความชัดเจน
- **blacklist เด็ดขาดขึ้น**: IP ใน blacklist ที่ล็อกอินสำเร็จจะ**ไม่ถูกปลดอัตโนมัติ** (ปลดด้วยมือเท่านั้น) — auto block ยังปลดตามปกติ
- **unblock-all ปลอดภัยขึ้น**: ลบจาก DB เฉพาะที่ firewall ปลดได้จริง — ตัวที่ลบ fail จะยังอยู่ในตาราง + แจ้งเตือน
- **monitor=None (โหมด `run.py web`)**: action handlers (block/unblock/whitelist/blacklist) คืน JSON error "monitor ไม่ได้รัน" แทน 500
- **GeoIP**: จำกัด batch ต่อ request (20 IP) — request เดิมค้าง ~70 วิ ลดเหลือ ~7 วิ + JS กันขอซ้ำ IP เดียวกันระหว่างรอ (in-flight)
- body JSON ที่ไม่ใช่ dict → จัดการเป็น `{}` (กัน 500) · `limit` ของ /api/events clamp 1-500 (กัน `LIMIT -1`)
- **UI**: badge "สะสม"/"หมดอายุ" มีสี · `init()` ลองใหม่เมื่อ server ยังไม่พร้อม · fetch มี timeout จริง (AbortController — self-test button ไม่ค้าง) · การ์ดสถิติไม่แสดง "undefined" ในโหมด web-only · sessions โหลดทันทีหลังล็อกอิน · polling (events/blocked/log) กัน response เก่ามาเขียนทับของใหม่

## 1.5.3 (2026-08-16)

- **Web UI หน้า ตั้งค่า**: จัดกลุ่มใหม่เป็น 2 คอลัมน์ — การเฝ้าระวัง / Windows Firewall / Web UI เรียงซ้อนกันฝั่งซ้าย, การตรวจจับ (กลุ่มยาว) อยู่ฝั่งขวากินความสูงเต็ม, Engine เพิ่มเติม เต็มแถวล่าง (จอแคบ <980px = เรียง 1 คอลัมน์ตามเดิม) + asset version bump

## 1.5.2 (2026-08-16)

- **Web UI หน้า ตั้งค่า**: ย้ายกลุ่ม "Web UI" ขึ้นมาแทนที่ตำแหน่งเดิมของกลุ่ม "Engine เพิ่มเติม" และทำให้กลุ่ม "Engine เพิ่มเติม" กินความกว้างเต็มพื้นที่ (editor generic_logs มีพื้นที่หายใจ ไม่เบียด 2 คอลัมน์) + asset version bump

## 1.5.1 (2026-08-16)

- **Web UI: ตัวแก้ไข generic_logs แบบกราฟิก** — หน้า ตั้งค่า → Engine เพิ่มเติม: เพิ่ม/ลบรายการไฟล์ log + regex ได้ทีละแถว (ชื่อ / path / regex แยกช่อง) — ระบบประกอบค่า `ชื่อ=path|regex` คั่น `;` ให้อัตโนมัติ ไม่ต้องนั่งพิมพ์ syntax เอง + เตือนเมื่อ regex มีอักขระที่ชนกับตัวคั่น (`|` `;` `=`) หรือยังไม่ครบ path/regex — ดูคู่มือเต็มใน GENERIC.md

## 1.5.0 (2026-08-16)

- **ตัวนับสะสม (ยิงสั้น ๆ แล้วหนี)**: นับความล้มเหลวสะสมต่อ IP ภายในกรอบเวลายาว (`accumulate_window_hours` ค่าเริ่มต้น 24 ชม.) — แยกจากตัวนับ window ระยะสั้นที่รีเซ็ตทุกกรอบ — IP ที่ยิงทีละ 1-2 ครั้งไม่ถึงเกณฑ์ short-window แต่สะสมครบ `accumulate_threshold` (ค่าเริ่มต้น 8) จะโดนบล็อกด้วย `accumulate_block_hours` (ค่าเริ่มต้น 6 ชม. — สั้นกว่าปกติ กันพลาดบล็อกผู้ใช้หลัง NAT/ISP shared)
- ตัวนับสะสมเคารพ whitelist/`never_block_ips`/grace 30 นาที (มี session ล็อกอินสำเร็จจริงไม่บล็อก + ล้างตัวนับทันที) — ล็อกอินสำเร็จ = ล้างตัวนับสะสมให้ IP นั้น
- ตัวนับสะสมรันเฉพาะเมื่อ short-window ยังไม่บล็อก (กันเกณฑ์ทั้งคู่ชนกันแล้ว expires ถูกทับ) — บล็อกสะสมที่ยังโจมตีต่อจะต่ออายุด้วย `accumulate_block_hours` (ไม่ใช่ `block_hours`)
- ตัวนับเก็บใน DB (ตาราง `accumulate`) — ไม่เสียสถิติตอน restart; cleanup ลบ entry ที่เงียบเกินกรอบเวลาทุก 60 วิ
- Web UI: ตั้งค่าได้ในหน้า ตั้งค่า → การตรวจจับ (3 ช่องใหม่) + badge "สะสม" ในตาราง IP ถูกบล็อก + asset version bump
- เอกสาร: **GENERIC.md ใหม่** — คู่มือ Generic engine ละเอียด (syntax/ตัวอย่าง regex จริง 9 โปรแกรม/วิธีทดสอบ regex/ข้อจำกัด delimiter/FAQ) + ลิงก์จาก README/CONFIG/USAGE

## 1.4.2 (2026-08-16)

- **โหมด rule เดียวแบบ RDPGuard** (`firewall.single_rule = true` ค่าเริ่มต้น) — Windows Firewall มี rule เดียวชื่อ `RDPGuard Block` แล้วเพิ่ม/ลบ IP ในรายการ RemoteAddresses ตาม IP ที่โจมตี (ไม่สร้าง rule ต่อ IP) — ตั้งค่าได้ที่หน้า ตั้งค่า → Windows Firewall
- ปลดบล็อก/หมดอายุ: ถอด IP ออกจากรายการ rule เดียว — ถ้ารายการว่าง ลบ rule ทิ้ง
- รองรับการล้าง rule แบบ per-IP เก่า (จากโหมดเดิม) อัตโนมัติ
- **firewall reconcile (self-heal)**: cleanup ตรวจทุก 60 วิ — DB บอก blocked แต่ rule ใน firewall หาย (ถูกลบ/รีเซ็ต) → สร้าง rule กลับให้อัตโนมัติ
- จัดการค่าที่ Windows Firewall คืนเป็น `1.2.3.4/255.255.255.255` (normalize เป็น /32/IP เปล่า + เช็ค CIDR membership)
- Web UI: คำเตือนเมื่อมี IP ถูกบล็อกเกิน 50/200 พร้อมคำแนะนำ (CIDR/ลด block_hours/ปลดล้าง) + เอกสาร "มี IP โดนบล็อกเยอะมาก (>50) ทำอย่างไร?"
- **Blacklist บล็อกทันทีที่เพิ่ม** (สร้าง rule firewall เลย ไม่ต้องรอให้ IP นั้นโจมตี) — ลบออกจาก blacklist = ปลดบล็อกให้อัตโนมัติ
- **Whitelist ปลดบล็อกทันทีที่เพิ่ม** (ถ้า IP ถูกบล็อกอยู่ — ไม่ต้องรอ reconcile 60 วิ) + ไม่ถูกบล็อกเด็ดขาด
- **พาเนล "Session / Remote ที่ใช้งานอยู่"** — ดูว่าใครล็อกอิน RDP/console/network อยู่ตอนนี้ (qwinsta → query session → PowerShell CIM fallback รองรับ Win7–11) — session RDP ที่ Active แสดง badge เตือน

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
