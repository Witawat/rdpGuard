"""Windows Service wrapper (pywin32) — ตาม pattern ของโครงการ Cloudflare DDNS.

- ติดตั้งด้วย pythonw.exe + main.py run-service (หรือตัว exe ถ้า PyInstaller frozen)
- รันเป็น service ระบบ: monitor + web UI ทำงานแม้ไม่มีใครล็อกอิน
"""

import logging
import os
import threading
import time

from . import SERVICE_DISPLAY_NAME, SERVICE_NAME

log = logging.getLogger("RDPGuard.service")

SERVICE_DESCRIPTION = (
    "RDPGuard: ตรวจจับการโจมตีแบบ brute-force ต่อ RDP "
    "และบล็อก IP ผู้โจมตีด้วย Windows Firewall"
)


def _make_service_class():
    """สร้างคลาส service แบบ lazy เพื่อให้ import ได้แม้ยังไม่มี pywin32."""
    try:
        import win32service
        import win32serviceutil
    except ImportError as exc:
        raise ImportError(
            "ไม่พบ pywin32 รัน 'python -m pip install pywin32' ก่อน"
        ) from exc

    class RDPGuardService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = threading.Event()
            self._monitor = None
            self._web = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()

        def SvcDoRun(self):
            import servicemanager

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            os.environ["RDPGUARD_RUNNING_AS_SERVICE"] = "1"

            from . import config as config_mod

            config_mod.ensure_config()
            config_mod.setup_logging(
                config_mod.get(config_mod.load_config(), "general", "log_level", "INFO")
            )
            log.info("service เริ่มทำงาน (%s)", SERVICE_NAME)

            from .monitor import Monitor

            self._monitor = Monitor()
            self._monitor.start()

            try:
                from . import webui as webui_mod

                cfg = config_mod.load_config()
                host = config_mod.get(cfg, "webui", "host", "127.0.0.1")
                port = config_mod.get_int(cfg, "webui", "port", 8123)
                self._web = webui_mod.start_webui(host, port, monitor=self._monitor)
            except Exception as exc:
                log.warning("เปิด Web UI ไม่ได้: %s", exc)

            self._stop_event.wait()
            try:
                if self._web:
                    self._web.stop()
            except Exception as exc:
                log.warning("หยุด Web UI ไม่ได้: %s", exc)
            try:
                self._monitor.stop()
                self._monitor.db.close()
            except Exception as exc:
                log.warning("หยุด monitor ไม่ได้: %s", exc)
            log.info("service หยุดทำงาน")

    return RDPGuardService


def run_service_entry():
    """entry ที่ Windows Service Control Manager เรียก (ผ่าน pythonw/exe)."""
    import servicemanager

    servicemanager.Initialize()
    cls = _make_service_class()
    if hasattr(servicemanager, "PrepareServiceHost"):
        servicemanager.PrepareServiceHost(cls)
    else:
        servicemanager.PrepareToHostSingle(cls)
    servicemanager.StartServiceCtrlDispatcher()


# ---- คำสั่งควบคุม service (เรียกจาก main.py) ----


def _service_util():
    import win32service
    import win32serviceutil

    return win32service, win32serviceutil


def install_service():
    """ลงทะเบียน service เข้า Windows (ต้องรันด้วยสิทธิ์ administrator)."""
    import sys

    win32service, win32serviceutil = _service_util()
    status = service_status()
    if status.get("installed"):
        try:
            win32serviceutil.StopService(SERVICE_NAME)
        except Exception:
            pass
        win32serviceutil.RemoveService(SERVICE_NAME)
    if getattr(sys, "frozen", False):
        exe = sys.executable
        exe_args = "run-service"
    else:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        run_script = os.path.join(project_root, "run.py")
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        exe = pythonw if os.path.isfile(pythonw) else sys.executable
        exe_args = f'"{run_script}" run-service'
    win32serviceutil.InstallService(
        exe,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        startType=win32service.SERVICE_AUTO_START,
        description=SERVICE_DESCRIPTION,
        exeArgs=exe_args,
    )
    return f"ติดตั้ง service '{SERVICE_NAME}' เรียบร้อย (เริ่มอัตโนมัติตอน boot)"


def remove_service():
    win32service, win32serviceutil = _service_util()
    try:
        win32serviceutil.StopService(SERVICE_NAME)
    except Exception:
        pass
    try:
        win32serviceutil.RemoveService(SERVICE_NAME)
    except Exception as exc:
        code = getattr(exc, "winerror", None)
        if code == 1060:  # service ไม่มีอยู่ — ไม่ใช่ความผิด
            return "service ยังไม่ได้ติดตั้ง — ไม่มีอะไรต้องลบ"
        if code == 5:  # Access denied
            return "ไม่มีสิทธิ์ลบ service - ต้องรันด้วย administrator (คลิกขวา > Run as administrator)"
        raise
    return f"ลบ service '{SERVICE_NAME}' เรียบร้อย"


def start_service():
    win32service, win32serviceutil = _service_util()
    win32serviceutil.StartService(SERVICE_NAME)
    return f"เริ่ม service '{SERVICE_NAME}' แล้ว"


def stop_service():
    win32service, win32serviceutil = _service_util()
    win32serviceutil.StopService(SERVICE_NAME)
    return f"หยุด service '{SERVICE_NAME}' แล้ว"


def restart_service():
    stop_service()
    start_service()
    return f"restart service '{SERVICE_NAME}' แล้ว"


def service_status():
    """คืน dict สถานะ service หรือ None ถ้ายังไม่ติดตั้ง"""
    try:
        win32service, _ = _service_util()
    except ImportError:
        return {"installed": False, "message": "pywin32 ยังไม่ติดตั้ง"}
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            handle = win32service.OpenService(
                scm, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS
            )
            try:
                status = win32service.QueryServiceStatus(handle)
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)
        states = {
            win32service.SERVICE_STOPPED: "stopped",
            win32service.SERVICE_START_PENDING: "starting",
            win32service.SERVICE_STOP_PENDING: "stopping",
            win32service.SERVICE_RUNNING: "running",
            win32service.SERVICE_CONTINUE_PENDING: "resuming",
            win32service.SERVICE_PAUSE_PENDING: "pausing",
            win32service.SERVICE_PAUSED: "paused",
        }
        return {"installed": True, "state": states.get(status[1], str(status[1]))}
    except Exception as exc:
        return {"installed": False, "message": f"ไม่พบ service: {exc}"}
