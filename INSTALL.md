# การติดตั้ง (Install)

## 1. ข้อกำหนด

### Windows ที่รองรับ

| OS | โหมด source (python) | โหมด exe |
|---|---|---|
| Windows 7 SP1 / Server 2008 R2 SP1 | ✅ Python **3.8.10** (เวอร์ชันสุดท้ายที่รันบน Win7) | ⚠️ ต้อง build เองด้วย Python 3.8 + PyInstaller 5.x (exe ที่แจก build ด้วย Python 3.11 รันไม่ได้บน Win7) |
| Windows 8.1 / 10 / 11 | ✅ Python 3.8 – 3.12 | ✅ exe ปัจจุบัน (build ด้วย Python 3.11) |
| Windows Server 2012 / 2016 / 2019 / 2022 / 2025 | ✅ Python 3.8 – 3.12 | ✅ exe ปัจจุบัน |

> เหตุผล: Python 3.9+ ยกเลิกการสนับสนุน Windows 7 (PEP 11) — ส่วนประกอบที่ใช้ (HNetCfg COM, event log, netsh) มีครบตั้งแต่ Windows Vista/7 ทั้งสิ้น
>
> วิธี build exe สำหรับ Win7: ติดตั้ง Python 3.8.10 → `build.bat` (PyInstaller รุ่นที่เข้ากับ Python 3.8) → เอา `dist\rdpguard.exe` ไปใช้บน Win7

### Python

- **Python 3.8 – 3.12** (แนะนำ 3.11/3.12)
  - Python 3.8.10 คือเวอร์ชันสุดท้ายที่รันบน Windows 7 ได้ — ใช้ 3.8.10 ถ้าติดตั้งบน Win7
  - ดาวน์โหลด: https://www.python.org/downloads/windows/
  - ตอนติดตั้งอย่าลืมติ๊ก **"Add python.exe to PATH"**

> ไม่อยากลง Python บนเครื่องจริง? สร้าง exe ด้วย `build.bat` แล้วเอา `dist\rdpguard.exe` ไปรันบนเครื่องอื่นได้เลย (ดูหัวข้อ 5) — หมายเหตุ: exe ที่ build ด้วย Python 3.11 เริ่มต้นที่ Windows 8.1 ขึ้นไป

## 2. ตรวจสอบ Python

```bat
python --version
```

## 3. ติดตั้ง dependency

เปิด Command Prompt (หรือ PowerShell) ที่โฟลเดอร์โปรเจกต์:

```bat
python -m pip install -r requirements.txt
```

ติดตั้งแค่ pywin32 ตัวเดียว

## 4. ติดตั้ง Windows Service

### วิธีง่าย (แนะนำ): ใช้ install.bat

```bat
install.bat
```

- ดับเบิลคลิกหรือรันจาก command line ก็ได้
- ตัวสคริปต์จะขอสิทธิ์ administrator ให้เอง (UAC prompt)
- ทำ 3 ขั้น: ติดตั้ง dependency (ถ้ายัง) → ติดตั้ง service → เริ่ม service

### วิธีทำเองทีละขั้น (ต้อง admin)

เปิด Command Prompt **Run as administrator**:

```bat
python run.py install     :: ติดตั้ง service (ชื่อ "RDPGuard", เริ่มอัตโนมัติตอน boot)
python run.py start       :: เริ่ม service
python run.py status      :: ตรวจสถานะ ควรเห็น "running"
python run.py password    :: ดูรหัสผ่าน Web UI
```

- service ใช้ `pythonw.exe` (ไม่มีหน้าต่าง) + script `run.py`
- config/ฐานข้อมูล/log อยู่ที่ `%ProgramData%\RDPGuard\` (โหมด source) — สร้างให้อัตโนมัติตอนรันครั้งแรก

> โหมด exe (`dist\rdpguard.exe`): config/ฐานข้อมูล/log จะอยู่**โฟลเดอร์เดียวกับ exe ถ้าเขียนได้** แทน; ถ้าโฟลเดอร์ exe ป้องกันการเขียน ระบบจะใช้ data directory สำรองตาม [CONFIG.md](CONFIG.md)
> และถ้ามีข้อมูลเก่าอยู่ที่ `%ProgramData%\RDPGuard\` (จากโหมด source/เวอร์ชันก่อนหน้า)
> จะย้ายมาให้อัตโนมัติในรันครั้งแรก

### เปิด Web UI

เปิดเบราว์เซอร์ → `http://127.0.0.1:8123` → ใส่รหัสผ่านที่ได้จาก `python run.py password`

## 5. สร้าง exe (ไม่ต้องลง Python บนเครื่องเป้าหมาย)

```bat
build.bat build
```

- ติดตั้ง PyInstaller และดาวน์โหลด UPX ให้อัตโนมัติ แล้ว build เป็น **ไฟล์เดียว** `dist\rdpguard.exe` (มี icon ฝังอยู่แล้ว)
- ถ้าเรียก `build.bat` โดยไม่ใส่ argument จะมีเมนูให้เลือก build อย่างเดียว หรือ build แล้วติดตั้ง service ต่อทันที; ใช้ `build.bat install` เพื่อเลือกโหมดหลัง build แบบไม่โต้ตอบ
- หลัง build เสร็จ `install.bat` / `uninstall.bat` จะใช้ exe อัตโนมัติ
- เอาแค่ไฟล์ `dist\rdpguard.exe` ไปเครื่องอื่นได้เลย (ไม่ได้สร้าง folder หลายชั้น) แล้วรัน `rdpguard.exe install` ตามด้วย `rdpguard.exe start`

> โปรแกรมกันไวรัสบางตัวอาจฟลากไฟล์ที่สร้างด้วย PyInstaller + UPX เนื่องจากเป็น packed executable — ตรวจสอบไฟล์จากแหล่งที่เชื่อถือได้ก่อน แล้วเพิ่ม exclusion ให้โฟลเดอร์ที่เก็บ exe หากจำเป็น

### อัปเดต exe เดิม

1. หยุด RDPGuard หรือ Windows Service เดิมก่อน
2. สำรอง `config.ini` และ `rdpguard.db` ถ้าต้องการ
3. แทนที่ `rdpguard.exe` ด้วยไฟล์ใหม่ แล้วเริ่มโปรแกรม/service อีกครั้ง

ไฟล์ข้อมูลไม่ถูกลบระหว่างการอัปเดต และ exe จะใช้ข้อมูลที่อยู่ข้าง exe เป็นหลัก

## 6. ถอนการติดตั้ง

```bat
uninstall.bat
```
หรือ: `python run.py stop` → `python run.py remove`

ข้อมูลในโฟลเดอร์ข้อมูลของโหมดที่ใช้งาน (config, ฐานข้อมูล, log และไฟล์สำรอง log) จะไม่ถูกลบ — ลบโฟลเดอร์ทิ้งเองถ้าต้องการล้างทั้งหมด

## 7. ตรวจสอบหลังติดตั้ง

```bat
python run.py status
```
ควรเห็น `service ติดตั้งแล้ว — สถานะ: running`

ถ้า service ติดตั้งแล้วแต่สถานะไม่ใช่ running:

1. เปิด `services.msc` → หา **RDPGuard Service** → อ่านข้อความ error
2. ดู log: ตรวจตำแหน่งจาก Web UI พาเนล **Log การทำงาน** หรือ `%ProgramData%\RDPGuard\rdpguard.log` ในโหมด source
3. สาเหตุพบบ่อย: ติดตั้ง Python แบบ "just for me" (service มองไม่เห็น user profile) → ติดตั้ง Python แบบ **All Users** ใหม่ หรือใช้ exe build แทน
