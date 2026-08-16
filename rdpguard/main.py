"""Entry point หลัก (CLI) — เรียกจาก: python -m rdpguard [คำสั่ง]

คำสั่ง:
    install          ติดตั้งเป็น Windows Service (ต้อง admin)
    remove           ถอนการติดตั้ง service
    start            เริ่ม service
    stop             หยุด service
    restart          restart service
    status           ดูสถานะ service
    run              รันแบบ foreground (monitor + web UI) — ใช้ทดสอบ
    web              รันเฉพาะ web UI (ไม่เฝ้าระวัง) — ใช้ทดสอบ
    block <ip> [ชม.] บล็อก IP ด้วยมือ (0 = ถาวร)
    unblock <ip>     ปลดบล็อก IP
    password         ดู/รีเซ็ตรหัสผ่าน Web UI (password reset)
    version          แสดงเวอร์ชัน
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from . import __version__


def _exe_label():
    return "rdpguard.exe" if getattr(sys, "frozen", False) else "python -m rdpguard"


def _print_help():
    cmd = _exe_label()
    print(f"RDPGuard v{__version__} — RDP brute-force protection")
    print()
    print(f"รัน {cmd} โดยไม่มีคำสั่ง = เริ่มเฝ้าระวัง + เปิด Web UI อัตโนมัติ")
    print()
    print("ใช้งาน:")
    print(f"  {cmd} install          # ติดตั้งเป็น Windows Service (ต้อง admin)")
    print(f"  {cmd} start            # เริ่ม service")
    print(f"  {cmd} stop             # หยุด service")
    print(f"  {cmd} restart          # restart service")
    print(f"  {cmd} status           # ดูสถานะ service")
    print(f"  {cmd} remove           # ถอน service")
    print(f"  {cmd} run              # รันแบบ foreground (monitor + web)")
    print(f"  {cmd} web              # รันเฉพาะ web UI")
    print(f"  {cmd} block 1.2.3.4 24 # บล็อก IP ด้วยมือ")
    print(f"  {cmd} unblock 1.2.3.4  # ปลดบล็อก IP")
    print(f"  {cmd} unblock-all     # ปลดบล็อกทุก IP (ฉุกเฉิน ถูกล็อกตัวเอง)")
    print(f"  {cmd} allow 1.2.3.4   # เพิ่ม whitelist + ปลดบล็อก (ฉุกเฉิน)")
    print(f"  {cmd} password         # ดูรหัสผ่าน Web UI")
    print(f"  {cmd} password reset   # สุ่มรหัสผ่านใหม่")
    print(f"  {cmd} version          # แสดงเวอร์ชัน")


def _cmd_service(op):
    from . import service as service_mod

    fn = {
        "install": service_mod.install_service,
        "remove": service_mod.remove_service,
        "start": service_mod.start_service,
        "stop": service_mod.stop_service,
        "restart": service_mod.restart_service,
    }[op]
    print(fn())


def _cmd_status():
    from . import service as service_mod

    status = service_mod.service_status()
    if status.get("installed"):
        print(f"service ติดตั้งแล้ว — สถานะ: {status['state']}")
        if status["state"] == "running":
            print("web UI: http://127.0.0.1:8123 (ตามที่ตั้งไว้ใน config)")
    else:
        print(status.get("message", "service ยังไม่ติดตั้ง"))


def _cmd_run(open_browser=False):
    from . import config as config_mod

    config_mod.ensure_config()
    cfg = config_mod.load_config()
    config_mod.setup_logging(config_mod.get(cfg, "general", "log_level", "INFO"))

    from .monitor import Monitor
    from .webui import start_webui

    monitor = Monitor()
    monitor.start()
    host = config_mod.get(cfg, "webui", "host", "127.0.0.1")
    port = config_mod.get_int(cfg, "webui", "port", 8123)
    password = config_mod.get(cfg, "webui", "password", "")
    ui = start_webui(host, port, monitor=monitor)
    url = f"http://{host}:{port}"
    print()
    print(f"Web UI: {url}")
    print(f"รหัสผ่าน: {password}")
    print("กด Ctrl+C เพื่อหยุด")
    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:
            pass
    try:
        ui.wait()
    except KeyboardInterrupt:
        pass
    finally:
        ui.stop()
        monitor.stop()
        monitor.db.close()
        print("หยุดแล้ว")


def _cmd_web(open_browser=True):
    from . import config as config_mod

    config_mod.ensure_config()
    cfg = config_mod.load_config()
    config_mod.setup_logging(config_mod.get(cfg, "general", "log_level", "INFO"))
    from .webui import start_webui

    host = config_mod.get(cfg, "webui", "host", "127.0.0.1")
    port = config_mod.get_int(cfg, "webui", "port", 8123)
    password = config_mod.get(cfg, "webui", "password", "")
    ui = start_webui(host, port, monitor=None)
    url = f"http://{host}:{port}"
    print()
    print(f"Web UI: {url}")
    print(f"รหัสผ่าน: {password}")
    print("กด Ctrl+C เพื่อหยุด")
    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:
            pass
    try:
        ui.wait()
    except KeyboardInterrupt:
        pass
    finally:
        ui.stop()
        print("หยุดแล้ว")


def _cmd_block(args):
    if not args:
        print("ใช้งาน: python -m rdpguard block <ip/cidr> [ชั่วโมง]")
        return
    ip = args[0]
    try:
        hours = int(args[1]) if len(args) > 1 else 24
    except ValueError:
        print("ชั่วโมงต้องเป็นตัวเลข")
        return
    from . import config as config_mod
    from .monitor import Monitor

    config_mod.ensure_config()
    monitor = Monitor()
    try:
        ok, message = monitor.manual_block(ip, hours)
        print(("OK: " if ok else "FAIL: ") + message)
    finally:
        monitor.db.close()


def _cmd_unblock(args):
    if not args:
        print("ใช้งาน: python -m rdpguard unblock <ip>")
        return
    ip = args[0]
    from . import config as config_mod
    from .monitor import Monitor

    config_mod.ensure_config()
    monitor = Monitor()
    try:
        ok, message = monitor.manual_unblock(ip)
        print(("OK: " if ok else "FAIL: ") + message)
    finally:
        monitor.db.close()


def _cmd_unblock_all():
    from . import config as config_mod
    from .monitor import Monitor

    config_mod.ensure_config()
    monitor = Monitor()
    try:
        print("OK: " + monitor.unblock_all())
    finally:
        monitor.db.close()


def _cmd_allow(args):
    if not args:
        print("ใช้งาน: python -m rdpguard allow <ip/cidr>")
        return
    ip = args[0]
    from . import config as config_mod
    from .monitor import Monitor

    config_mod.ensure_config()
    monitor = Monitor()
    try:
        ok, message = monitor.allow_ip(ip)
        print(("OK: " if ok else "FAIL: ") + message)
    finally:
        monitor.db.close()


def _cmd_password(args):
    from . import config as config_mod

    config_mod.ensure_config()
    cfg = config_mod.load_config()
    current = config_mod.get(cfg, "webui", "password", "")
    if args and args[0] == "reset":
        import secrets

        new_password = secrets.token_urlsafe(12)
        cfg.set("webui", "password", new_password)
        config_mod.save_config(cfg)
        print(f"รหัสผ่านใหม่: {new_password}")
        print(f"(บันทึกที่ {config_mod.CONFIG_FILE})")
    else:
        print(f"รหัสผ่าน Web UI: {current}")
        print(f"(config: {config_mod.CONFIG_FILE})")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(f"RDPGuard v{__version__} — เริ่มเฝ้าระวัง + เปิด Web UI...")
        _cmd_run(open_browser=True)
        return
    cmd = argv[0]
    rest = argv[1:]

    if cmd in ("install", "remove", "start", "stop", "restart"):
        _cmd_service(cmd)
    elif cmd == "status":
        _cmd_status()
    elif cmd == "run":
        _cmd_run()
    elif cmd == "web":
        _cmd_web()
    elif cmd == "block":
        _cmd_block(rest)
    elif cmd == "unblock":
        _cmd_unblock(rest)
    elif cmd == "unblock-all":
        _cmd_unblock_all()
    elif cmd == "allow":
        _cmd_allow(rest)
    elif cmd == "password":
        _cmd_password(rest)
    elif cmd == "version":
        print(f"RDPGuard v{__version__}")
    elif cmd == "help":
        _print_help()
    else:
        print(f"ไม่รู้จักคำสั่ง: {cmd}")
        _print_help()


if __name__ == "__main__":
    main()
