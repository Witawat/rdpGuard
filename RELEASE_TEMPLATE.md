## 🚀 v{VERSION} — RDPGuard

**วันที่:** {DD/MM/YYYY} · **ขนาดไฟล์:** {X.X} MB

### ✨ ฟีเจอร์ใหม่
- {สั้น 1 บรรทัด เริ่มด้วยคำสำคัญ — ไม่มีให้เขียน "— (เน้นแก้บั๊ก ดู vX.Y.Z)"}

### 🔧 แก้บั๊ก
- {สั้น 1 บรรทัด}

### ⚠️ หมายเหตุ
- {breaking change / สิ่งที่ต้องทำก่อนอัปเดต — ไม่มีให้เขียน "— (ไม่มี)"}

### 📥 วิธีอัปเดต
**โหมด exe (ใช้ไฟล์เดียว):**
```
1. ปิด RDPGuard ตัวเก่า (ถ้ารันอยู่)
2. แทนที่ rdpguard.exe ด้วยตัวใหม่
3. ดับเบิลคลิก rdpguard.exe
```

**โหมด Windows Service (ติดตั้งด้วย install.bat):**
```
1. หยุด service: rdpguard.exe stop
2. แทนที่ rdpguard.exe ด้วยตัวใหม่
3. เริ่ม service: rdpguard.exe start
```
> config/ฐานข้อมูลอยู่ข้าง exe (หรือ `%ProgramData%\RDPGuard` โหมด source) — อัปเดต exe ไม่กระทบข้อมูล

### ✅ ตรวจสอบไฟล์
- SHA256: `{SHA256}`
- รายการเปลี่ยนแปลง: https://github.com/Witawat/rdpGuard/blob/master/CHANGELOG.md
- คู่มือ: CONFIG.md / GENERIC.md / INSTALL.md

---

## วิธีใช้ template นี้

1. คัดลอกเนื้อหานี้ ใส่ notes ไฟล์ชั่วคราว แล้วแทนที่ `{VERSION}`, `{DD/MM/YYYY}`, `{X.X}` (MB), `{SHA256}` + เขียน bullet สั้น ๆ ในแต่ละหมวด (ย่อจาก CHANGELOG — ไม่ copy ยาว)
2. **เขียนผ่านไฟล์ .md เสมอ** (ไม่ใช่ PowerShell heredoc — `$E`/`$(` โดน expand หายได้)
3. สร้าง release:
   ```powershell
   $hash = (Get-FileHash dist\rdpguard.exe -Algorithm SHA256).Hash
   gh release create v{VERSION} --repo Witawat/rdpGuard --title "RDPGuard v{VERSION}" --notes-file <ไฟล์.md> dist\rdpguard.exe
   gh release view v{VERSION} --repo Witawat/rdpGuard --json tagName,assets   # ตรวจสอบ (อย่าข้าม)
   ```
