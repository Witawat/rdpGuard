# -*- mode: python ; coding: utf-8 -*-
# Onefile exe (เดียวกับโครงการ Cloudflare DDNS) — ใช้ icon จาก assets/icon.ico


a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=[],
    datas=[("rdpguard/web", "rdpguard/web")],
    hiddenimports=[
        "win32timezone",
        "win32com.client",
        "win32com.client.build",
        "pythoncom",
        "win32serviceutil",
        "win32service",
        "win32evtlog",
        "win32event",
        "servicemanager",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="rdpguard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=["assets/icon.ico"],
)
