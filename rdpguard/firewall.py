"""Windows Firewall integration — ใช้ firewall ในตัวของ Windows เท่านั้น.

- หลัก: HNetCfg COM API (FwPolicy2 / FWRule) — เร็ว ไม่ต้อง spawn process
- fallback: netsh advfirewall (กรณี COM ใช้ไม่ได้)
- COM ทั้งหมดทำงานบน worker thread ตัวเดียว (apartment คงที่) เพื่อไม่ให้
  เกิด cross-thread COM object release (ป้องกัน "Win32 exception occurred
  releasing IUnknown" noise)
- แต่ละ IP ที่ถูกบล็อกจะได้ rule คนละ rule (prefix + IP) ไว้ถอดออกได้ง่าย
"""

import logging
import queue
import subprocess
import threading

log = logging.getLogger("RDPGuard.firewall")

NET_FW_RULE_DIR_IN = 1
NET_FW_ACTION_BLOCK = 0
NET_FW_PROFILE2_ALL = 0x7FFFFFFF
INTERFACE_TYPES_ALL = "All"

_PROFILE_ARG = {"any": "any", "domain": "domain", "private": "private", "public": "public"}


class FirewallManager:
    def __init__(self, rule_prefix="RDPGuard Block", profile="any"):
        self.rule_prefix = rule_prefix
        self.profile = profile
        self.ports = []
        self._com_queue = queue.Queue()
        self._com_worker = threading.Thread(
            target=self._com_worker_loop, name="firewall-com", daemon=True
        )
        self._com_worker.start()

    def _rule_name(self, ip):
        return f"{self.rule_prefix} {ip}"

    def _com_worker_loop(self):
        import pythoncom

        pythoncom.CoInitialize()
        while True:
            fn, args, ret = self._com_queue.get()
            try:
                result = fn(*args)
                ret.put(("ok", result))
            except Exception as exc:
                ret.put(("err", exc))

    def _com_call(self, fn, *args):
        ret = queue.Queue()
        self._com_queue.put((fn, args, ret))
        status, result = ret.get(timeout=30)
        if status == "err":
            raise result
        return result

    def _netsh(self, args):
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall"] + args,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except Exception as exc:
            log.error("netsh ล้มเหลว: %s", exc)
            return False

    # ---- COM operations (รันบน worker thread) ----

    def _com_add_block(self, ip):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        name = self._rule_name(ip)
        for rule in fw.Rules:
            if rule.Name == name:
                if not rule.Enabled:
                    rule.Enabled = True
                return True
        rule = win32com.client.Dispatch("HNetCfg.FWRule")
        rule.Name = name
        rule.Description = f"RDPGuard: บล็อก IP {ip} จากการพยายามล็อกอิน"
        rule.Direction = NET_FW_RULE_DIR_IN
        rule.Action = NET_FW_ACTION_BLOCK
        rule.Enabled = True
        rule.InterfaceTypes = INTERFACE_TYPES_ALL
        rule.RemoteAddresses = ip
        rule.Profiles = NET_FW_PROFILE2_ALL
        if self.ports:
            rule.Protocol = 6  # TCP
            rule.LocalPorts = ",".join(str(p) for p in self.ports)
        fw.Rules.Add(rule)
        log.info("COM: บล็อก IP %s เรียบร้อย (ports=%s)", ip, ",".join(map(str, self.ports)) or "all")
        return True

    def _com_remove_block(self, ip):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        name = self._rule_name(ip)
        for rule in fw.Rules:
            if rule.Name == name:
                fw.Rules.Remove(name)
                log.info("COM: ปลดบล็อก IP %s เรียบร้อย", ip)
                return True
        return True

    def _com_rule_exists(self, ip):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        name = self._rule_name(ip)
        for rule in fw.Rules:
            if rule.Name == name:
                return bool(rule.Enabled)
        return False

    # ---- public API ----

    def add_block(self, ip):
        """เพิ่ม rule บล็อกขาเข้าจาก IP — คืน True เมื่อสำเร็จ (หรือ rule มีอยู่แล้ว)"""
        try:
            return self._com_call(self._com_add_block, ip)
        except Exception as exc:
            log.warning("COM firewall ล้มเหลว (%s) — ลอง netsh แทน", exc)
        return self._add_block_netsh(ip)

    def _add_block_netsh(self, ip):
        profile = _PROFILE_ARG.get(self.profile, "any")
        args = [
            "add",
            "rule",
            f"name={self._rule_name(ip)}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            f"profile={profile}",
            "enable=yes",
        ]
        if self.ports:
            args += ["protocol=TCP", "localport=" + ",".join(str(p) for p in self.ports)]
        ok = self._netsh(args)
        if ok:
            log.info("netsh: บล็อก IP %s เรียบร้อย (ports=%s)", ip, ",".join(map(str, self.ports)) or "all")
        else:
            log.error("netsh: บล็อก IP %s ล้มเหลว", ip)
        return ok

    def remove_block(self, ip):
        """ถอด rule บล็อกออก — คืน True เมื่อสำเร็จ (หรือไม่มี rule อยู่แล้ว)"""
        try:
            return self._com_call(self._com_remove_block, ip)
        except Exception as exc:
            log.warning("COM firewall ล้มเหลว (%s) — ลอง netsh แทน", exc)
        return self._remove_block_netsh(ip)

    def _remove_block_netsh(self, ip):
        ok = self._netsh(["delete", "rule", f"name={self._rule_name(ip)}"])
        if ok:
            log.info("netsh: ปลดบล็อก IP %s เรียบร้อย", ip)
        else:
            log.error("netsh: ปลดบล็อก IP %s ล้มเหลว", ip)
        return ok

    def rule_exists(self, ip):
        try:
            return self._com_call(self._com_rule_exists, ip)
        except Exception:
            return False
