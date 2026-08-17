"""RDPGuard - RDP brute-force protection for Windows (fail2ban style).

โมนิเตอร์ Security event log ตรวจจับการลองรหัสผ่าน RDP ซ้ำ ๆ
แล้วบล็อก IP ผู้โจมตีด้วย Windows Firewall (ในตัว ไม่ต้องติดตั้งเพิ่ม).
"""

__version__ = "1.9.1"
APP_NAME = "RDPGuard"
SERVICE_NAME = "RDPGuard"
SERVICE_DISPLAY_NAME = "RDPGuard Service"
