# Generic Log Engine — คู่มือใช้งานละเอียด

Generic engine คือช่องทางตรวจจับ **ไฟล์ log ของโปรแกรมอื่น ๆ** ที่ RDPGuard ไม่มี engine ให้
(เช่น MailEnable, SmarterMail, PBX/SIP — FreeSWITCH, Asterisk, 3CX, FTP server, Web server,
หรือเกม/ซอฟต์แวร์ใดก็ตามที่เขียน log การล็อกอินล้มเหลวพร้อม IP ลงไฟล์)

> สิ่งที่ engine อื่นทำได้ (นับ/bl็อก/ปลด/UI) — generic ก็ทำได้เหมือนกันหมด ต่างแค่แหล่งข้อมูล
> เป็น**ไฟล์ข้อความ**แทน event log/Windows API

## หลักการทำงาน

```
ไฟล์ log (ข้อความ)
      │  อ่านแบบ tail ทุก poll_interval_seconds (เริ่มจากท้ายไฟล์ — เห็นเฉพาะเหตุการณ์ใหม่)
      ▼
regex ที่คุณตั้งไว้ (เจอบรรทัดไหน match)
      │  {IP} ถูกแทนด้วย pattern IPv4/IPv6 อัตโนมัติ
      ▼
ส่งเข้าเครื่องตรวจจับ (เหมือน engine อื่น)
      ▼
ครบเกณฑ์ → บล็อก IP ด้วย Windows Firewall
```

- บรรทัดไหน match regex → นับเป็น **ล็อกอินล้มเหลว (fail)** 1 ครั้งจาก IP นั้น
- ครบ `max_attempts` (หรือ `generic_max_attempts` ที่ตั้งแยก) ภายใน `window_minutes` → บล็อก
- ตัวนับสะสม (ตั้งแต่ v1.5.0), escalate, auto_extend, whitelist/blacklist และการแจ้งเตือนทำงานตามปกติ
- **ไม่มี**การนับ success สำหรับ generic (engine นี้ส่งได้แค่ fail)

## เริ่มต้นด่วน (3 ขั้นตอน)

1. **เปิด engine** — ใน Web UI: หน้า ตั้งค่า → Engine เพิ่มเติม → ติ๊ก `Generic log engine` เป็น ON
   (หรือใน `config.ini`): `[engines] generic = true`
2. **ตั้งค่าไฟล์ + regex** — หน้า ตั้งค่า → Engine เพิ่มเติม → ช่อง `Generic: ชื่อ=path|regex (คั่น ;)`
3. **กด "บันทึกการตั้งค่า"** → ตรวจว่าใช้งานได้ (ดูหัวข้อ [วิธีตรวจว่าทำงาน](#วิธีตรวจว่าทำงาน))

> ตัวแก้ไขแบบกราฟิกจะประกอบค่า `ชื่อ=path|regex` ให้เองและเตือน delimiter ที่ใช้ไม่ได้ (`;`, `|`, `=`) — หลังบันทึก monitor จะโหลดรายการใหม่ทันที ไม่ต้อง restart

ตัวอย่างขั้นต่ำ (สมมติ MailEnable เขียน log ว่า `Login failed from 203.0.113.9`):

```ini
[engines]
generic_logs = mail=C:\MailEnable\Logging\SMTP\SMTP-160816.LOG|Login failed from {IP}
```

---

## รูปแบบการตั้งค่า (Syntax)

`generic_logs` = หลายรายการคั่นด้วย `;` แต่ละรายการ:

```
ชื่อ=path|regex
```

| ส่วน | ความหมาย | ตัวอย่าง |
|---|---|---|
| `ชื่อ` | ป้ายกำกับ — เห็นใน Web UI/เหตุการณ์ (ใช้ตัวอักษร/ตัวเลข/ขีด) | `mail`, `sip`, `ftp` |
| `path` | **เส้นทางไฟล์ log จริง** (ต้องเป็นไฟล์เดียว ไม่รองรับ wildcard) | `C:\MailEnable\Logging\SMTP\SMTP-160816.LOG` |
| `regex` | Python regex — บรรทัดไหน match = นับ 1 fail | `Login failed from {IP}` |

ตัวอย่าง 2 รายการ (mail + sip):

```ini
generic_logs = mail=C:\MailEnable\Logging\SMTP\SMTP-160816.LOG|Login failed from {IP};sip=C:\FreeSWITCH\log\freeswitch.log|failure in register.*from {IP}
```

### {IP} — ตัวแทนตำแหน่ง IP (จำเป็นต้องมี)

ทุก regex **ต้องมี `{IP}` หนึ่งตำแหน่ง** — engine จะแทนด้วย pattern ที่จับได้ทั้ง IPv4 และ IPv6:

```
{IP}  →  (?P<ip>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,}))
```

- `{IP}` ใส่ตรงตำแหน่งที่ IP ปรากฏในบรรทัด log
- ลองได้เลย เช่น log เขียน `failed from 203.0.113.9 port 5060` → regex `failed from {IP}`

### จับชื่อผู้ใช้ด้วย (?P<user>)

ถ้าอยากเห็นชื่อ user ใน Web UI/ตารางเหตุการณ์ ให้เพิ่ม named group `user`:

```regex
Login failed for user '(?P<user>[^']*)' from {IP}
```

- ถ้าไม่มี `(?P<user>)` → user แสดงเป็น `-`
- ห้ามตั้งชื่อ group อื่น (เช่น `(?P<ip>...)`) — `ip` สงวนไว้สำหรับ `{IP}`

### ⚠️ ข้อจำกัดของ delimiter (สำคัญมาก)

รายการใช้ `;` แยก และ `|` แยก path/regex — **ห้ามใช้ `;` `|` `=` ภายใน regex** เพราะจะถูกตัดเป็นคนละส่วน:

| อักขระ | ผลกระทบ |
|---|---|
| `;` | regex โดนตัด — ส่วนที่เกินจะกลายเป็นรายการใหม่ (error/warning) |
| `\|` หรือ `|` | regex โดนตัดที่ `|` ตัวแรก — ส่วนที่เหลือหาย |
| `=` | ถ้าอยู่ใน path → path โดนตัด |

**วิธีเลี่ยง** ถ้าต้องการ "หรือ" ใน regex:
- ใช้ character class แทน: `(?:a|b)` → `[ab]`, `(?:GET|POST)` → `[GP]ET` (ระวังความหมายเพี้ยน)
- ใช้ inline flag: `(?i)login failed` (ไม่สนใจตัวพิมพ์เล็กใหญ่)
- ใช้ capture ซ้อน: `invalid (?:password|pin)` — ใช้ได้เพราะไม่มี `|`

> regex ผิดจะไม่ทำให้โปรแกรมพัง — engine log warning `generic_logs regex ผิด: ...` แล้วข้ามรายการนั้น
> (ตรวจใน Web UI พาเนล Log หรือไฟล์ rdpguard.log)

---

## ตัวอย่างจริง (คัดจากโปรแกรมที่พบบ่อย)

> ตัวเลข IP ในตัวอย่างเป็นตัวอย่างสมมติ — ให้เทียบกับบรรทัดจริงใน log ของคุณ (โปรแกรมแต่ละเวอร์ชันรูปแบบอาจต่าง)

| โปรแกรม | บรรทัดใน log (โดยประมาณ) | regex |
|---|---|---|
| **MailEnable** (SMTP auth) | `08/16/26 17:01:02 AUTH LOGIN failed from 203.0.113.9 (authenticator failed)` | `AUTH LOGIN failed from {IP}` |
| **SmarterMail** | `2026-08-16 17:01:02 - IP 203.0.113.9: Invalid password for user 'admin'` | `IP {IP}: Invalid password for user '(?P<user>[^']*)'` |
| **FreeSWITCH** | `[ERR] sofia_reg.c:4417 failure in register for 1000@x - from 203.0.113.9:5060` | `failure in register.*from {IP}` |
| **Asterisk** (SIP) | `Registration from '1000' failed for '203.0.113.9:5060'` | `Registration from '[^']*' failed for '{IP}` |
| **3CX PBX** | `Login failed for user '1000' from IP 203.0.113.9` | `Login failed for user '[^']*' from IP {IP}` |
| **FileZilla Server** (FTP) | `(000100)16/08/2026 17:01:02 - (not logged in) (203.0.113.9)> 530 Login or password incorrect!` | `- \(not logged in\) \(({IP})\)> 530` |
| **ProFTPD** | `2026-08-16 17:01:02,203 203.0.113.9 - USER admin (Login failed)` | `{IP} - USER .* \(Login failed\)` |
| **nginx/apache** (HTTP 401) | `203.0.113.9 - - [16/Aug/2026:17:01:02 +0700] "GET / HTTP/1.0" 401 287` | `^({IP}) - - .*" 401 ` |
| **Windows Remote Web** (RD Web Access log) | `203.0.113.9 login attempt failed` | `login attempt failed` ต้องมี IP — ใช้ `{IP} .*login attempt failed` |

**ตัวอย่างชุดจริง (คัดลอกไปปรับได้):**

```ini
generic_logs =
    mail=C:\MailEnable\Logging\SMTP\SMTP.LOG|AUTH LOGIN failed from {IP};
    freeswitch=C:\FreeSWITCH\log\freeswitch.log|failure in register.*from {IP};
    ftp=D:\FileZilla Server\Logs\fzserver.log|\(not logged in\) \(({IP})\)> 530
```

> หมายเหตุ: ค่าในไฟล์จริงต้องอยู่บรรทัดเดียว (INI ไม่ support multiline) — ตัวอย่างแบ่งบรรทัดให้อ่านง่าย

---

## การทดสอบ regex ก่อนใส่จริง

ก่อนใส่ config ให้เทสต์กับบรรทัด log จริงด้วย Python (รันบนเครื่อง dev):

```python
# test_generic.py — เอา log บรรทัดจริง + regex มาใส่ แล้วรัน
import re

from rdpguard.engines import IP_PATTERN

line = "08/16/26 17:01:02 AUTH LOGIN failed from 203.0.113.9 (authenticator failed)"
pattern = re.sub(r"\{IP\}", lambda _m: "(?P<ip>" + IP_PATTERN + ")", r"AUTH LOGIN failed from {IP}")
m = re.search(pattern, line)
print("MATCH:", bool(m))
if m:
    print("IP  :", m.group("ip"))
```

- ได้ `MATCH: True` + IP ถูกต้อง → เอา regex ใส่ `generic_logs` ได้
- ได้ `MATCH: False` → ดูบรรทัดจริง (คัดลอกมาทั้งบรรทัด) แล้วปรับ regex

---

## วิธีตรวจว่าทำงาน

1. **Log**: หลังบันทึก config ควรเห็น (Web UI → พาเนล Log หรือ `rdpguard.log`):
   ```
   generic engine: เฝ้า C:\MailEnable\...\SMTP.LOG (mail)
   ```
2. **สถานะแหล่งข้อมูล**: Web UI → หน้า การตรวจจับ (หรือชิป Generic) — `ok` = ตั้งค่าเรียบร้อย, `no-source` = ยังไม่ได้ตั้ง `generic_logs`
3. **ตารางเหตุการณ์**: เจอ fail จากไฟล์นั้น → ปรากฏใน "เหตุการณ์ล่าสุด" แหล่ง = `Generic` ป้ายชื่อที่ตั้ง
4. **การบล็อก**: ครบเกณฑ์ → IP ขึ้นตาราง "IP ที่ถูกบล็อก" ป้าย `อัตโนมัติ` เหมือน engine อื่น

---

## ข้อจำกัด (ควรรู้)

- **อ่านแบบ tail จากท้ายไฟล์** — เห็นเฉพาะบรรทัดใหม่ที่เขียน**หลัง**เปิด/บันทึก config; เหตุการณ์เก่าที่ค้างอยู่ในไฟล์จะไม่ถูกนับ
- **ไฟล์ log หมุนเวียน (rotation)** — ตรวจอัตโนมัติผ่าน (ขนาด, ctime) — เจอไฟล์ใหม่/ถูกหมุน → อ่านตั้งแต่ต้น
- **ไฟล์ log ของ RDPGuard เอง** หมุนแยกต่างหากตาม `[general] log_max_mb`/`log_backups`; การหมุนของไฟล์ log ต้นทางที่ Generic อ่านจะตรวจจากขนาดและเวลาแก้ไข
- **path ต้องเป็นไฟล์เดียว** — ไม่รองรับ wildcard/โฟลเดอร์ (ถ้าต้องการหลายไฟล์ ใส่หลายรายการคั่น `;`)
- **encoding** — อ่านแบบ UTF-8 (ตัวอักษรที่ไม่รู้จักถูกข้าม) — log ที่เป็น ANSI/UTF-16 (เช่น บางโปรแกรม Windows) อาจอ่านไม่ออก
- **ไม่มี success event** — ตัวนับสะสม/grace ทำงานจาก event ของ engine อื่น (เช่น RDP) ได้ตามปกติ แต่ generic เองส่งได้แค่ fail
- **regex ตรวจแบบ search** — match ตรงไหนของบรรทัดก็ได้ (ไม่ต้อง match ทั้งบรรทัด) — ใช้ `^...$` เองถ้าต้องการ anchor

---

## Troubleshooting / FAQ

**Q: ตั้งแล้วไม่เห็นอะไรเลย**
- ดู log: ถ้ามี `generic_logs รูปแบบผิด` → syntax ผิด (เช็ค `;` `|` `=`) / ถ้ามี `regex ผิด` → regex compile ไม่ผ่าน
- ไฟล์เขียนบรรทัดใหม่จริงหรือเปล่า (tail เริ่มจากท้าย — เปิด config ทิ้งไว้ แล้วลองทำ fail จริงดู)
- `generic = true` เปิดหรือยัง? สถานะเป็น `no-source` ไหม?

**Q: regex ต้องมี {IP} เสมอไหม**
- ใช่ — engine นับ fail **ต่อ IP**; ไม่มี IP จะจับไม่ได้เลย (regex ที่ไม่มี `{IP}` ยัง compile ผ่านแต่จะ warning — ตั้งใจไม่ให้ทำงาน)

**Q: ใช้ regex ของ fail2ban ได้ไหม**
- ได้ — ส่วนใหญ่ใช้ได้เลย ถ้าไม่มี `;` `|` `=` ภายใน (มี → ปรับตามหัวข้อข้อจำกัด) และแทน IP ด้วย `{IP}` (fail2ban ใช้ `\`<HOST>\`` หรือ capture group)

**Q: อยากเห็น user ในตารางเหตุการณ์**
- เพิ่ม `(?P<user>...)` ใน regex (ดูหัวข้อ "จับชื่อผู้ใช้ด้วย (?P<user>)")

**Q: บล็อกช้า/เร็วเกินไป**
- ปรับ `generic_max_attempts` (จำนวนครั้ง) ใน config — ว่าง = ใช้ค่ากลาง `detection.max_attempts` (ค่าเริ่มต้น 5)
