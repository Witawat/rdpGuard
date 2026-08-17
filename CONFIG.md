# การตั้งค่า (Config)

config เก็บที่:
- **โหมด exe**: โฟลเดอร์เดียวกับ `rdpguard.exe` ถ้าเขียนได้ (เช่น `C:\tools\rdpguard\config.ini`); ถ้าไม่ได้จะ fallback ไป `%ProgramData%\RDPGuard\` หรือ `~/.rdpguard`
- **โหมด source**: `%ProgramData%\RDPGuard\config.ini` (ถ้าเขียนไม่ได้ → `~/.rdpguard\`)

สร้างอัตโนมัติตอนรันครั้งแรก แก้ไขผ่าน Web UI (หน้า "ตั้งค่า") หรือแก้ไฟล์ตรง ๆ ได้

- ค่าการเฝ้าระวัง/ตรวจจับ/firewall/engine/แจ้งเตือนโหลดใหม่ทันทีหลังบันทึกผ่าน Web UI
- `webui.host`/`webui.port` และค่าการ logging ใน `[general]` ต้อง restart โปรแกรม/service จึงจะมีผล

ตัวอย่างเต็ม: [config.example.ini](config.example.ini)

## [general]

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `log_level` | `INFO` | ระดับ log: `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `log_max_mb` | `5` | ขนาดไฟล์ log สูงสุดต่อไฟล์ (MB) — เกินแล้วหมุนเป็น `rdpguard.log.1`, `.2`, ... |
| `log_backups` | `5` | เก็บไฟล์ log หมุนเวียนกี่ไฟล์ (รวมไฟล์ปัจจุบัน = 6 ไฟล์) |
| `setup_done` | `false` | ผ่าน Setup Wizard ครั้งแรกแล้วหรือยัง (ระบบจัดการเอง — ไม่ต้องแก้ด้วยมือ) |

> config.ini จะถูกเติม section/คีย์ที่ยังไม่มีด้วยค่าเริ่มต้นให้อัตโนมัติตอนรัน (ทุกค่าเริ่มต้นเห็นในไฟล์ config ได้) — ค่าที่ตั้งไว้แล้วจะไม่ถูกทับ

> ไฟล์ log เก่า/ใหญ่: ลบ `rdpguard.log.*` ข้าง exe (หรือ `%ProgramData%\RDPGuard`) ทิ้งได้เลยตอนโปรแกรมปิด — ระบบสร้างใหม่ให้เอง
> ค่า `log_level`, `log_max_mb` และ `log_backups` ยังปรับจากหน้า Web UI ไม่ได้ ต้องแก้ใน `config.ini` แล้ว restart โปรแกรม/service; ค่าเริ่มต้น 5 MB × (ไฟล์ปัจจุบัน + สำรอง 5 ไฟล์) จึงใช้พื้นที่ประมาณไม่เกิน 30 MB

## [monitor]

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `enable` | `true` | เปิด/ปิดการเฝ้าระวังทั้งหมด (ปิดแล้วไม่นับ/bl็อกใด ๆ แต่ Web UI ยังใช้ได้) |
| `poll_interval_seconds` | `2` | อ่าน Security event log ทุกกี่วินาที (ขั้นต่ำ 0.5) |
| `logon_types` | `3,10` | LogonType ที่นับเป็น "พยายามล็อกอิน RDP" — `3` = Network (NLA), `10` = RemoteInteractive ใช้ `*` เพื่อนับทุกชนิด |

## [detection]

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `max_attempts` | `5` | ล็อกอินผิดกี่ครั้ง (ภายใน `window_minutes`) ถึงจะบล็อก IP |
| `window_minutes` | `10` | กรอบเวลานับจำนวนครั้ง (นาที) — ครั้งเก่ากว่ากรอบเวลาจะไม่นับ |
| `block_hours` | `24` | บล็อกนานเท่าไร (ชั่วโมง) — `0` = บล็อกถาวร (ต้องปลดด้วยมือ) |
| `auto_extend` | `true` | ถ้า IP ที่ถูกบล็อกยังพยายามโจมตีต่อ ให้ต่ออายุบล็อกใหม่ (block_hours) อัตโนมัติ |
| `skip_local_ips` | `true` | ข้ามการนับ/บล็อก IP วง LAN ส่วนตัว (10.x, 172.16–31.x, 192.168.x), loopback, และ IP ของเครื่องตัวเอง — กันบล็อกผู้ดูแลเอง |
| `active_session_grace_minutes` | `30` | กันบล็อก IP ที่ล็อกอินสำเร็จภายใน X นาทีที่ผ่านมา (มี session จริงอยู่ — ผู้ดูแลที่กำลังต่อ RDP อยู่จะไม่โดนบล็อก) `0` = ปิด |
| `never_block_ips` | *(ว่าง)* | รายการ IP/CIDR ที่ห้ามบล็อกเด็ดขาด (คั่น `,`) — เหมือน whitelist แต่แก้ใน config ไฟล์ตรง ๆ ได้เมื่อฉุกเฉิน (ถูกล็อกตัวเอง) ระบบปลดบล็อก IP ในรายการนี้ให้อัตโนมัติทุก 60 วิ |
| `escalate_after_blocks` | `3` | **ขยายบล็อก IP ขาประจำ**: โดนบล็อกครบกี่ครั้ง (ภายใน `escalation_window_days`) ถึงขยาย — เช่น โดนบล็อก 3 ครั้งแล้วกลับมาอีก ครั้งที่ 4 ขยายเป็น `escalate_block_hours` `0` = ปิด |
| `escalate_block_hours` | `168` | ขยายเป็นกี่ชั่วโมง (ค่าเริ่มต้น 7 วัน) |
| `escalate_to_permanent` | `false` | ขยายเป็นบล็อกถาวรเลย (แทน `escalate_block_hours`) — ต้องปลดด้วยมือ |
| `escalation_window_days` | `30` | กรอบเวลานับจำนวนครั้งที่โดนบล็อก (วัน) |
| `accumulate_window_hours` | `24` | **ตัวนับสะสม (ยิงสั้น ๆ แล้วหนี)**: นับความล้มเหลวสะสมต่อ IP ภายในกรอบเวลายาว (ชั่วโมง) — แยกจาก `window_minutes` ที่รีเซ็ตทุกกรอบ `0` = ปิด |
| `accumulate_threshold` | `8` | ครบกี่ครั้ง (รวมภายใน `accumulate_window_hours`) ถึงจะบล็อก `0` = ปิด |
| `accumulate_block_hours` | `6` | บล็อกนานเท่าไรสำหรับกรณีสะสม (ชั่วโมง) — ตั้งสั้นกว่า `block_hours` กันพลาดบล็อกผู้ใช้หลัง NAT/ISP shared; IP ขาประจำจะโดน escalate ต่อเอง |

> หมายเหตุ: auto_extend (ต่ออายุบล็อก) จะ**ไม่ลด**ระยะเวลาบล็อกที่ขยายแล้ว และ**ไม่แตะ**บล็อกถาวร — IP ที่ถูกบล็อกจากตัวนับสะสม (source = `accumulate`) จะต่ออายุด้วย `accumulate_block_hours` (ไม่ใช่ `block_hours`)
>
> หมายเหตุ: ตัวนับสะสมเคารพ whitelist/`never_block_ips`/grace (`active_session_grace_minutes`) — IP ที่ล็อกอินสำเร็จจะถูก**ล้างตัวนับ**ทันที; counter เก็บใน DB และ cleanup ลบ entry ที่เงียบเกินกรอบเวลาอัตโนมัติ

## [engines]

Engine เพิ่มเติม (engine RDP/Security เปิดถาวร) — แต่ละตัวส่งเหตุการณ์ล้มเหลวต่อ IP เข้าเครื่องตรวจจับเดียวกัน (นับแยกต่อ engine)

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `openssh` | `true` | OpenSSH (SSH) — อ่านช่อง `OpenSSH/Operational` Event 4 |
| `mssql` | `true` | MSSQL — Application log Event **18456** (ครอบคลุม SQL auth ด้วย เพราะอ่านจากข้อความ event) |
| `iis` | `true` | IIS / HTTP Web Login / RD Web forms — อ่าน **W3C log** (sc-status 401 = ล้มเหลว, 200 = สำเร็จ) |
| `mysql` | `true` | MySQL — อ่าน **error log** (`Access denied for user 'x'@'IP'`) |
| `generic` | `true` | Generic log engine — อ่านไฟล์ log ตาม `generic_logs` |
| `openssh_max_attempts` ฯลฯ | *(ว่าง)* | ขีดจำกัดเฉพาะ engine (ว่าง = ใช้ค่ากลาง `detection.max_attempts`) — มี `mssql_max_attempts`, `iis_max_attempts`, `mysql_max_attempts`, `generic_max_attempts` |
| `iis_log_dir` | *(ว่าง)* | โฟลเดอร์ IIS log (ว่าง = auto: `C:\inetpub\logs\LogFiles`) |
| `mysql_log_dir` | *(ว่าง)* | โฟลเดอร์/pattern MySQL log (ว่าง = auto: `C:\ProgramData\MySQL\*\Data\*.err`) |
| `generic_logs` | *(ว่าง)* | รายการไฟล์ log + regex คั่นด้วย `;` รูปแบบ `ชื่อ=path|regex` — ใช้ `{IP}` แทนตำแหน่ง IP เช่น `mail=C:\MailServer\log.txt|Failed login from '{IP}'` (regex จริงได้ `{IP}` เป็น placeholder) — **[คู่มือเต็ม + ตัวอย่างโปรแกรมจริง: GENERIC.md](GENERIC.md)** |

> การอ่านไฟล์แบบ tail: ไฟล์ใหม่ที่เจอหลังเปิด engine จะอ่านตั้งแต่ต้น ไฟล์เดิมอ่านต่อจากท้าย (จำ offset) — รองรับ log rotation ผ่านการตรวจ (size, ctime)

## [firewall]

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `rule_prefix` | `RDPGuard Block` | คำนำหน้าชื่อ rule ใน Windows Firewall เช่น `RDPGuard Block 203.0.113.9` (ดูใน `wf.msc`) |
| `profile` | `any` | Profile ของ rule: `any` / `domain` / `private` / `public` — `any` ครอบคลุมทุก network profile |
| `blocked_ports` | *(ว่าง)* | จำกัดพอร์ตที่บล็อก เช่น `3389,1433,22` (ว่าง = บล็อกทุกพอร์ตจาก IP นั้น) — rule จะเป็น TCP + เฉพาะพอร์ตเหล่านี้ |
| `single_rule` | `true` | **โหมด rule เดียวแบบ RDPGuard** — rule เดียวชื่อ `rule_prefix` แล้วเพิ่ม/ลบ IP ในรายการ RemoteAddresses ตาม IP ที่โจมตี (ไม่สร้าง rule ต่อ IP — `wf.msc` สะอาด ไม่รกแม้ IP เยอะ) `false` = สร้าง rule แยกต่อ IP |

กลไกการบล็อก: ใช้ HNetCfg COM API (`FwPolicy2`) เป็นหลัก ถ้าล้มเหลวจะ fallback ไป `netsh advfirewall` เอง

## [webui]

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `host` | `127.0.0.1` | `127.0.0.1` = เฉพาะเครื่องนี้ (ปลอดภัยสุด) — `0.0.0.0` = เข้าจากเครื่องอื่นใน LAN ได้ |
| `port` | `8123` | พอร์ต Web UI |
| `password` | *(สุ่มอัตโนมัติ)* | รหัสผ่านหน้า Web UI — ดูได้ด้วย `python run.py password`, สุ่มใหม่ด้วย `python run.py password reset` |

> ⚠️ ถ้าตั้ง `host = 0.0.0.0` ต้องมี password ที่แข็งแรง และเปิดพอร์ต firewall เอง:
> `netsh advfirewall firewall add rule name="RDPGuard WebUI" dir=in action=allow protocol=TCP localport=8123`

## [notify]

แจ้งเตือนเมื่อบล็อก IP — ตั้งค่าได้ใน Web UI หน้า ตั้งค่า → "แจ้งเตือน (Telegram / Email)" (เปิด `enable` + ตั้งช่องทางอย่างน้อย 1 ช่อง แล้วกด "ส่งข้อความทดสอบ" ตรวจก่อนใช้จริง)

| คีย์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `enable` | `false` | เปิดการแจ้งเตือนเมื่อบล็อก IP |
| `channel` | `both` | ช่องทางที่ใช้: `both` (ทั้งคู่) / `telegram` / `email` |
| `telegram_bot_token` | *(ว่าง)* | Bot Token จาก @BotFather |
| `telegram_chat_id` | *(ว่าง)* | Chat ID ที่จะให้ส่งถึง (ตัวเลข หรือ @username) |
| `telegram_verify_ssl` | `true` | ตรวจสอบใบรับรอง SSL ของ Telegram API — ตั้ง `false` ถ้าเครื่องมี proxy/กันไวรัสที่ intercept HTTPS แล้วขึ้น `CERTIFICATE_VERIFY_FAILED` |
| `smtp_host` | *(ว่าง)* | SMTP server เช่น `smtp.gmail.com` / `smtp.office365.com` |
| `smtp_port` | `587` | `587` = STARTTLS (ส่วนใหญ่) / `465` = SMTPS ตรง |
| `smtp_user` / `smtp_password` | *(ว่าง)* | บัญชีผู้ส่ง (ว่างได้ถ้า server ไม่อนุญาต auth) |
| `smtp_to` | *(ว่าง)* | อีเมลผู้รับ |
| `cooldown_seconds` | `60` | ส่งอย่างน้อยทุกกี่วินาที — ข้อความระหว่างนั้นรวมเป็นชุดเดียว (`0` = ส่งทันทีทุกครั้ง; กันสแปมตอนโจมตีหนัก) |

> ข้อความแจ้งเตือน: `บล็อก IP <ip> (<engine>) — <เหตุผล> — หมดอายุ <เวลา>` — ส่งแบบไม่บล็อก (worker thread) + retry 2 ครั้ง; ส่งไม่สำเร็จ log ใน `rdpguard.log`
>
> หาก Telegram ขึ้น `CERTIFICATE_VERIFY_FAILED` ให้ปิด `telegram_verify_ssl` (หรือเอาเครื่องหมายติ๊ก **ตรวจสอบ SSL ของ Telegram** ใน Web UI) แล้วบันทึกค่า — ใช้เฉพาะเมื่อมี proxy/โปรแกรมกันไวรัส intercept HTTPS และควรใช้กับเครือข่ายที่เชื่อถือได้

## ค่าที่แนะนำตามสถานการณ์

| สถานการณ์ | คำแนะนำ |
|---|---|
| Server ถูกโจมตีหนักมาก (log เต็ม 4625) | `max_attempts = 3`, `window_minutes = 5` (บล็อกไว แต่เสี่ยง false positive) |
| RDP มีคนใช้จริงหลายคน | `max_attempts = 8–10`, `window_minutes = 15` (ลดการบล็อกผู้ใช้ที่พิมพ์รหัสผิดเป็นครั้งคราว) |
| ต้องการกันระยะยาว | `block_hours = 72` หรือ `0` (ถาวร) + `auto_extend = true` |
| Office ใช้ IP ปลายทางคงที่ | เพิ่ม IP นั้นใน **Whitelist** ผ่าน Web UI |
| เจอ "ยิงสั้น ๆ แล้วหนี" (IP แทบไม่ซ้ำ ทีละ 1-2 ครั้ง) | `accumulate_threshold = 5`, `accumulate_window_hours = 24` (สะสมครบ 5 ครั้ง/วัน โดนบล็อก 6 ชม.) — ถ้า network มี NAT/ISP shared เยอะ เก็บค่าเริ่มต้นไว้ |
