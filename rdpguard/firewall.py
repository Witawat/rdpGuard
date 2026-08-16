"""Windows Firewall integration — ใช้ firewall ในตัวของ Windows เท่านั้น.

2 โหมด (ตั้งใน config [firewall] single_rule):
- single_rule = true  (แบบ RDPGuard จริง): rule เดียวชื่อ prefix
  แล้วเพิ่ม/ลบ IP ใน RemoteAddresses ของ rule นั้นตาม IP ที่โจมตี
- single_rule = false: 1 rule ต่อ 1 IP (RDPGuard Block <IP>)

- หลัก: HNetCfg COM API (FwPolicy2 / FWRule) — เร็ว ไม่ต้อง spawn process
- fallback: netsh advfirewall (กรณี COM ใช้ไม่ได้)
- COM ทั้งหมดทำงานบน worker thread ตัวเดียว (apartment คงที่)
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


def _normalize_entry(entry):
    """Windows คืน RemoteAddresses เป็น '1.2.3.4/255.255.255.255' — แปลง dotted
    netmask เป็น /prefix (/32 -> IP เปล่า) เพื่อเปรียบเทียบกับค่าที่เราใส่"""
    v = (entry or "").strip()
    if "/" in v:
        addr, _, mask = v.partition("/")
        parts = mask.split(".")
        if len(parts) == 4 and all(x.isdigit() for x in parts):
            bits = sum(bin(int(x)).count("1") for x in parts)
            return addr if bits == 32 else f"{addr}/{bits}"
    return v


def _entry_contains(entry, ip):
    """entry (IP เดี่ยว หรือ CIDR) ครอบคลุม ip หรือไม่"""
    if entry == ip:
        return True
    if "/" in entry:
        try:
            import ipaddress

            return ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    return False


class FirewallManager:
    def __init__(self, rule_prefix="RDPGuard Block", profile="any"):
        self.rule_prefix = rule_prefix
        self.profile = profile
        self.ports = []
        self.single_rule = False
        self._cache = None  # รายการ IP ใน single rule (sync จาก firewall จริง)
        self._com_queue = queue.Queue()
        self._com_worker = threading.Thread(
            target=self._com_worker_loop, name="firewall-com", daemon=True
        )
        self._com_worker.start()

    def _rule_name(self, ip):
        return self.rule_prefix if self.single_rule else f"{self.rule_prefix} {ip}"

    # ---- COM worker ----

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

    def _com_find_rule(self, fw, name):
        for rule in fw.Rules:
            if rule.Name == name:
                return rule
        return None

    def _com_add_block(self, ip, ports):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        name = self._rule_name(ip)
        rule = self._com_find_rule(fw, name)
        if rule is not None:
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
        if ports:
            rule.Protocol = 6  # TCP
            rule.LocalPorts = ",".join(str(p) for p in ports)
        fw.Rules.Add(rule)
        return True

    def _com_remove_block(self, ip):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        name = self._rule_name(ip)
        rule = self._com_find_rule(fw, name)
        if rule is not None:
            fw.Rules.Remove(name)
        return True

    def _com_rule_exists(self, ip):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rule = self._com_find_rule(fw, self._rule_name(ip))
        return rule is not None and bool(rule.Enabled)

    # ---- COM: single rule (รายการ IP ใน RemoteAddresses) ----

    def _com_get_ips(self):
        """อ่านรายการ IP ใน single rule — คืน list (ว่างถ้าไม่มี rule)"""
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rule = self._com_find_rule(fw, self.rule_prefix)
        if rule is None:
            return []
        raw = rule.RemoteAddresses or ""
        return [_normalize_entry(x) for x in raw.split(",") if x.strip()]

    def _com_set_ips(self, ips, ports):
        """สร้าง/อัปเดต single rule ให้มีรายการ IP ตามที่กำหนด"""
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rule = self._com_find_rule(fw, self.rule_prefix)
        if rule is not None:
            rule.RemoteAddresses = ",".join(ips)
            rule.Enabled = True
            return True
        rule = win32com.client.Dispatch("HNetCfg.FWRule")
        rule.Name = self.rule_prefix
        rule.Description = "RDPGuard: บล็อก IP ที่โจมตี (รายการอัตโนมัติ)"
        rule.Direction = NET_FW_RULE_DIR_IN
        rule.Action = NET_FW_ACTION_BLOCK
        rule.Enabled = True
        rule.InterfaceTypes = INTERFACE_TYPES_ALL
        rule.RemoteAddresses = ",".join(ips)
        rule.Profiles = NET_FW_PROFILE2_ALL
        if ports:
            rule.Protocol = 6
            rule.LocalPorts = ",".join(str(p) for p in ports)
        fw.Rules.Add(rule)
        return True

    def _com_delete_rule(self):
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rule = self._com_find_rule(fw, self.rule_prefix)
        if rule is not None:
            fw.Rules.Remove(self.rule_prefix)
        return True

    # ---- public API ----

    def _sync_cache(self):
        """โหลดรายการ IP ปัจจุบันของ single rule จาก firewall จริง"""
        try:
            self._cache = self._com_call(self._com_get_ips)
        except Exception as exc:
            log.warning("อ่าน single rule ไม่ได้ (%s) — ใช้ cache ว่าง", exc)
            self._cache = []

    def add_block(self, ip, ports=None):
        """เพิ่ม IP ในรายการบล็อก — ports: รายการพอร์ต (None/[] = ทุกพอร์ต)"""
        if ports is None:
            ports = list(self.ports)
        if self.single_rule:
            return self._add_block_single(ip, ports)
        try:
            return self._com_call(self._com_add_block, ip, list(ports))
        except Exception as exc:
            log.warning("COM firewall ล้มเหลว (%s) — ลอง netsh แทน", exc)
        return self._add_block_netsh(ip, ports)

    def _add_block_single(self, ip, ports):
        if self._cache is None:
            self._sync_cache()
        if any(_entry_contains(x, ip) for x in self._cache):
            return True
        new_list = self._cache + [ip]
        try:
            self._com_call(self._com_set_ips, new_list, list(ports))
            self._cache = new_list
            log.info("single rule: เพิ่ม %s (รวม %d IP)", ip, len(new_list))
            return True
        except Exception as exc:
            log.warning("COM ล้มเหลว (%s) — ลอง netsh แทน", exc)
        self._netsh(["delete", "rule", f"name={self.rule_prefix}"])
        args = [
            "add",
            "rule",
            f"name={self.rule_prefix}",
            "dir=in",
            "action=block",
            f"remoteip={','.join(new_list)}",
            f"profile={_PROFILE_ARG.get(self.profile, 'any')}",
            "enable=yes",
        ]
        if ports:
            args += ["protocol=TCP", "localport=" + ",".join(str(p) for p in ports)]
        ok = self._netsh(args)
        if ok:
            self._cache = new_list
        return ok

    def _add_block_netsh(self, ip, ports):
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
        if ports:
            args += ["protocol=TCP", "localport=" + ",".join(str(p) for p in ports)]
        ok = self._netsh(args)
        if ok:
            log.info("netsh: บล็อก IP %s เรียบร้อย (ports=%s)", ip, ",".join(map(str, ports)) or "all")
        else:
            log.error("netsh: บล็อก IP %s ล้มเหลว", ip)
        return ok

    def remove_block(self, ip):
        """ถอด IP ออกจากรายการบล็อก — คืน True เมื่อสำเร็จ (หรือไม่มีอยู่แล้ว)"""
        if self.single_rule:
            return self._remove_block_single(ip)
        try:
            return self._com_call(self._com_remove_block, ip)
        except Exception as exc:
            log.warning("COM firewall ล้มเหลว (%s) — ลอง netsh แทน", exc)
        return self._remove_block_netsh(ip)

    def _com_remove_legacy(self, ip):
        """ลบ rule แบบ per-IP เก่า (ชื่อ 'prefix ip') — ใช้ชื่อตรง ๆ เสมอ ไม่ผ่าน _rule_name"""
        import win32com.client

        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        name = f"{self.rule_prefix} {ip}"
        rule = self._com_find_rule(fw, name)
        if rule is not None:
            fw.Rules.Remove(name)
        return True

    def _remove_block_single(self, ip):
        # ล้าง rule แบบ per-IP เก่า (จากโหมดเดิม) ด้วย เผื่อเหลือค้าง
        try:
            self._com_call(self._com_remove_legacy, ip)
        except Exception:
            pass
        if self._cache is None:
            self._sync_cache()
        if not any(_entry_contains(x, ip) for x in self._cache):
            return True
        new_list = [x for x in self._cache if not _entry_contains(x, ip)]
        try:
            if not new_list:
                self._com_call(self._com_delete_rule)
                self._cache = []
                log.info("single rule: ลบ %s — rule ว่าง ถูกลบ", ip)
            else:
                self._com_call(self._com_set_ips, new_list, list(self.ports))
                self._cache = new_list
                log.info("single rule: ลบ %s (เหลือ %d IP)", ip, len(new_list))
            return True
        except Exception as exc:
            log.warning("COM ล้มเหลว (%s) — ลอง netsh แทน", exc)
        self._netsh(["delete", "rule", f"name={self.rule_prefix}"])
        if new_list:
            args = [
                "add",
                "rule",
                f"name={self.rule_prefix}",
                "dir=in",
                "action=block",
                f"remoteip={','.join(new_list)}",
                f"profile={_PROFILE_ARG.get(self.profile, 'any')}",
                "enable=yes",
            ]
            if self.ports:
                args += ["protocol=TCP", "localport=" + ",".join(str(p) for p in self.ports)]
            ok = self._netsh(args)
            if ok:
                self._cache = new_list
            return ok
        return True

    def _remove_block_netsh(self, ip):
        ok = self._netsh(["delete", "rule", f"name={self._rule_name(ip)}"])
        if ok:
            log.info("netsh: ปลดบล็อก IP %s เรียบร้อย", ip)
        else:
            log.error("netsh: ปลดบล็อก IP %s ล้มเหลว", ip)
        return ok

    def rule_exists(self, ip):
        """ตรวจว่า IP อยู่ในรายการบล็อก (firewall) หรือไม่"""
        if self.single_rule:
            if self._cache is None:
                self._sync_cache()
            return any(_entry_contains(x, ip) for x in self._cache)
        try:
            return self._com_call(self._com_rule_exists, ip)
        except Exception:
            return False
