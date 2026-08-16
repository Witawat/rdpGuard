"""Runner หลัก: ใช้เป็น entry ของ Windows Service และ PyInstaller.

- python run.py [คำสั่ง...]      -> เรียก CLI ปกติ (เดียวกับ python -m rdpguard)
- python run.py run-service      -> รันเป็น Windows Service (SCM เรียกผ่าน path นี้)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_service_entry():
    from rdpguard.service import run_service_entry as _entry

    _entry()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run-service":
        run_service_entry()
    else:
        from rdpguard.main import main

        main()
