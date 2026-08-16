"use strict";

const $ = (id) => document.getElementById(id);

function toast(message, type = "") {
  const wrap = $("toasts");
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = message;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...options,
  });
  let data = {};
  try {
    data = await res.json();
  } catch (e) {
    data = { ok: false, error: "ตอบกลับไม่ถูกต้อง" };
  }
  if (!res.ok && !data.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

const esc = (s) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

function fmtTs(ts) {
  if (!ts) return "-";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
  return isNaN(d) ? ts : d.toLocaleString("th-TH");
}

function typeBadge(kind) {
  const map = { fail: "ล้มเหลว", success: "สำเร็จ", ntlm: "NTLM" };
  return `<span class="badge ${kind}">${map[kind] || kind}</span>`;
}

function sourceBadge(source) {
  const map = { auto: "อัตโนมัติ", manual: "ด้วยมือ", blacklist: "blacklist", expire: "หมดอายุ" };
  return `<span class="badge ${source}">${map[source] || source}</span>`;
}

function engineBadge(source) {
  const map = { rdp: "RDP", openssh: "OpenSSH", mssql: "MSSQL", iis: "IIS Web", mysql: "MySQL" };
  const label = map[source] || source || "-";
  return `<span class="badge ntlm">${esc(label)}</span>`;
}

/* ---------- views ---------- */

async function init() {
  const status = await api("/api/login-status");
  if (status.data.authorized) {
    showApp();
  } else {
    showLogin();
  }
}

function showLogin() {
  $("login-view").style.display = "flex";
  $("app-view").style.display = "none";
  $("login-password").focus();
}

let appIntervals = [];

function showApp() {
  $("login-view").style.display = "none";
  $("app-view").style.display = "block";
  appIntervals.forEach(clearInterval);
  appIntervals = [];
  refreshOverview();
  refreshDetection();
  refreshService();
  refreshEvents();
  refreshBlocked();
  refreshLists();
  refreshSettings();
  refreshLog();
  appIntervals.push(setInterval(refreshOverview, 3000));
  appIntervals.push(setInterval(refreshEvents, 3000));
  appIntervals.push(setInterval(refreshBlocked, 5000));
  appIntervals.push(setInterval(refreshService, 10000));
  appIntervals.push(setInterval(refreshLog, 5000));
  checkSetup();
}

/* ---------- detection toggle ---------- */

async function refreshDetection() {
  try {
    const { data } = await api("/api/detection-state");
    const master = $("det-master");
    master.classList.toggle("on", data.enable);
    master.setAttribute("aria-checked", String(data.enable));
    document.querySelectorAll(".chip[data-engine]").forEach(chip => {
      const eng = chip.dataset.engine;
      const on = eng === "rdp" ? true : data.engines[eng] !== false;
      chip.classList.toggle("on", on);
      if (eng === "rdp") chip.classList.add("locked");
    });
  } catch (e) {}
}

$("det-master").addEventListener("click", async () => {
  try {
    const { data } = await api("/api/toggle", { method: "POST", body: JSON.stringify({ key: "enable" }) });
    toast(data.message, "ok");
    refreshDetection();
  } catch (e) { toast(e.message, "error"); }
});

document.addEventListener("click", async (e) => {
  const chip = e.target.closest(".chip[data-engine]");
  if (!chip || chip.classList.contains("locked")) return;
  try {
    const { data } = await api("/api/toggle", { method: "POST", body: JSON.stringify({ engine: chip.dataset.engine }) });
    toast(data.message, "ok");
    refreshDetection();
  } catch (err) { toast(err.message, "error"); }
});

/* ---------- geoip ---------- */

const geoCache = {};

async function fillCountry(rows, ipGetter, tdIndex, tableId) {
  const missing = [];
  for (const row of rows) {
    const ip = ipGetter(row);
    if (ip && !(ip in geoCache)) missing.push(ip);
  }
  let data = {};
  if (missing.length) {
    try {
      data = (await api("/api/geoip", { method: "POST", body: JSON.stringify({ ips: missing }) })).data.geoip || {};
    } catch (e) {}
    for (const [ip, info] of Object.entries(data)) geoCache[ip] = info || null;
  }
  rows.forEach((row) => {
    const ip = ipGetter(row);
    const cell = document.querySelector(`#${tableId} tr[data-ip="${CSS.escape(ip)}"] td:nth-child(${tdIndex})`);
    if (!cell) return;
    const info = geoCache[ip];
    if (info && info.flag) cell.innerHTML = `<span class="flag">${info.flag}</span> <span>${esc(info.country || info.code || "")}</span>`;
    else cell.textContent = "-";
  });
}

/* ---------- windows service ---------- */

async function refreshService() {
  try {
    const { data } = await api("/api/service");
    const pill = $("svc-pill");
    const pillText = $("svc-pill-text");
    if (!data.installed) {
      pill.className = "pill danger"; pillText.textContent = "ยังไม่ได้ติดตั้ง";
      $("svc-state").textContent = "";
    } else if (data.running) {
      pill.className = "pill ok"; pillText.textContent = "กำลังรัน";
      $("svc-state").textContent = "service RDPGuard ทำงานอยู่ — เฝ้าระวังตลอดเวลา";
    } else {
      pill.className = "pill warn"; pillText.textContent = "หยุดอยู่";
      $("svc-state").textContent = "service ติดตั้งแล้วแต่ยังไม่ได้เริ่ม";
    }

    const ctx = data.context === "service"
      ? "กำลังรันใน Windows Service — ควบคุมผ่าน services.msc หรือ CLI"
      : data.is_admin
        ? "รันแบบ standalone · มีสิทธิ์ admin (ควบคุม service ได้)"
        : "รันแบบ standalone · ไม่มีสิทธิ์ admin (ควบคุม service ต้องเปิดด้วย Run as administrator)";
    $("svc-ctx").textContent = ctx;

    const can = data.can_control;
    $("svc-install").disabled = !can || data.installed;
    $("svc-remove").disabled = !can || !data.installed;
    $("svc-start").disabled = !can || !data.installed || data.running;
    $("svc-stop").disabled = !can || !data.installed || !data.running;
    $("svc-restart").disabled = !can || !data.installed || !data.running;

    $("svc-note").textContent = can
      ? (data.installed ? "กดปุ่มเพื่อเริ่ม/หยุด/รีสตาร์ท service ได้เลย — ถอนได้ถ้าต้องการเลิกใช้" : "ยังไม่ติดตั้ง — กด \"ติดตั้ง\" เพื่อลง service (จะเริ่มอัตโนมัติตอนเปิดเครื่อง)")
      : "ปุ่มถูกปิดใช้งาน: " + (data.context === "service" ? "ระบบกำลังรันใน service อยู่" : "ต้องเปิดโปรแกรมด้วยสิทธิ์ administrator");
  } catch (e) {}
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[id^=svc-]");
  if (!btn || btn.id === "svc-pill" || btn.id === "svc-pill-text") return;
  const actionMap = {
    "svc-install": "install",
    "svc-remove": "remove",
    "svc-start": "start",
    "svc-stop": "stop",
    "svc-restart": "restart",
  };
  const action = actionMap[btn.id];
  if (!action) return;
  btn.disabled = true;
  try {
    const { data } = await api("/api/service/action", {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    toast(data.message, "ok");
    await refreshService();
  } catch (err) {
    toast(err.message, "error");
    btn.disabled = false;
  }
});

/* ---------- setup wizard ---------- */

const WIZARD_STEPS = ["ยินดีต้อนรับ", "การตรวจจับ", "Web UI", "พร้อมใช้งาน"];

async function checkSetup() {
  try {
    const { data } = await api("/api/setup-status");
    if (!data.setup_done) showWizard();
  } catch (e) {}
}

let wzIndex = 0;
let wzSettings = null;

function showWizard() {
  $("app-view").style.display = "none";
  $("wizard-view").style.display = "flex";
  wzIndex = 0;
  (async () => {
    try {
      wzSettings = (await api("/api/settings")).data;
    } catch (e) {}
    const d = wzSettings || {};
    $("wz-attempts").value = (d.detection && d.detection.max_attempts) || "5";
    $("wz-window").value = (d.detection && d.detection.window_minutes) || "10";
    $("wz-hours").value = (d.detection && d.detection.block_hours) || "24";
    $("wz-skip-local").checked = !d.detection || String(d.detection.skip_local_ips) !== "false";
    $("wz-host").value = (d.webui && d.webui.host) || "127.0.0.1";
    $("wz-port").value = (d.webui && d.webui.port) || "8123";
    $("wz-password").value = "";
    renderWizard();
  })();
}

function hideWizard() {
  $("wizard-view").style.display = "none";
  $("app-view").style.display = "block";
}

function renderWizard() {
  for (let i = 0; i < 4; i++) $("wz-step-" + i).style.display = i === wzIndex ? "" : "none";
  $("wz-title").textContent = "ตั้งค่าระบบครั้งแรก — " + WIZARD_STEPS[wzIndex];
  $("wz-prev").style.display = wzIndex === 0 ? "none" : "";
  $("wz-next").style.display = wzIndex < 3 ? "" : "none";
  $("wz-finish").style.display = wzIndex === 3 ? "" : "none";
  const dots = $("wz-dots");
  dots.innerHTML = "";
  for (let i = 0; i < 4; i++) {
    const d = document.createElement("span");
    d.className = "wz-dot" + (i <= wzIndex ? " active" : "");
    dots.appendChild(d);
  }
  if (wzIndex === 3) {
    $("wz-summary").innerHTML =
      `บล็อกเมื่อล้มเหลว <b>${esc($("wz-attempts").value)} ครั้ง</b> ใน <b>${esc($("wz-window").value)} นาที</b> ` +
      `→ บล็อก <b>${esc($("wz-hours").value)} ชั่วโมง</b><br>` +
      `Web UI: <span class="mono">http://${esc($("wz-host").value)}:${esc($("wz-port").value)}</span>` +
      (String($("wz-skip-local").checked) === "true" ? "" : " · <b>นับรวม IP ใน LAN</b>");
  }
}

$("wz-next").addEventListener("click", () => {
  if (wzIndex < 3) {
    wzIndex++;
    renderWizard();
  }
});
$("wz-prev").addEventListener("click", () => {
  if (wzIndex > 0) {
    wzIndex--;
    renderWizard();
  }
});
$("wz-skip").addEventListener("click", async () => {
  try {
    await api("/api/setup/complete", { method: "POST", body: "{}" });
  } catch (e) {}
  hideWizard();
  showApp();
});
$("wz-finish").addEventListener("click", async () => {
  const payload = { detection: {}, webui: {} };
  if ($("wz-attempts").value) payload.detection.max_attempts = $("wz-attempts").value;
  if ($("wz-window").value) payload.detection.window_minutes = $("wz-window").value;
  if ($("wz-hours").value) payload.detection.block_hours = $("wz-hours").value;
  payload.detection.skip_local_ips = $("wz-skip-local").checked ? "true" : "false";
  payload.webui.host = $("wz-host").value;
  payload.webui.port = $("wz-port").value;
  if ($("wz-password").value) payload.webui.password = $("wz-password").value;
  try {
    await api("/api/settings", { method: "POST", body: JSON.stringify(payload) });
    await api("/api/setup/complete", { method: "POST", body: "{}" });
    toast("ตั้งค่าเสร็จสิ้น — เริ่มเฝ้าระวังแล้ว", "ok");
    hideWizard();
    showApp();
  } catch (e) {
    toast(e.message, "error");
  }
});

/* ---------- login / logout ---------- */

$("login-btn").addEventListener("click", async () => {
  const error = $("login-error");
  error.textContent = "";
  try {
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: $("login-password").value }),
    });
    $("login-password").value = "";
    showApp();
  } catch (e) {
    error.textContent = e.message;
  }
});
$("login-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("login-btn").click();
});

$("logout-btn").addEventListener("click", async (e) => {
  e.preventDefault();
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } catch (e) {}
  showLogin();
});

/* ---------- overview ---------- */

async function refreshOverview() {
  try {
    const { data } = await api("/api/overview");
    $("stat-failed").textContent = data.stats.failed_24h;
    $("stat-success").textContent = data.stats.success_24h;
    $("stat-active").textContent = data.stats.blocked_active;
    $("stat-total").textContent = data.stats.blocked_total;
    $("stat-rule-desc").textContent =
      `max ${data.settings_summary.max_attempts} ครั้ง / ${data.settings_summary.window_minutes} นาที / ${data.settings_summary.block_hours} ชม.`;

    const pill = $("pill-monitor");
    const txt = $("pill-monitor-text");
    if (!data.settings_summary.enable) {
      pill.className = "pill warn"; txt.textContent = "เฝ้าระวังปิดอยู่";
    } else if (!data.health.eventlog_ok) {
      pill.className = "pill warn"; txt.textContent = "เฝ้าระวังบางส่วน (อ่าน log ไม่ได้)";
    } else if (data.monitor_running) {
      pill.className = "pill ok"; txt.textContent = "กำลังเฝ้าระวัง";
    } else {
      pill.className = "pill danger"; txt.textContent = "ไม่ทำงาน";
    }
    $("pill-context").textContent =
      data.context === "service" ? "รันใน Windows Service"
      : data.context === "standalone-admin" ? "รัน standalone (admin)"
      : "รัน standalone (ไม่มี admin)";
    $("pill-version").textContent = "v" + data.version;

    renderHealth(data.health);
  } catch (e) {
    if (e.message.includes("401") || e.message.includes("ล็อกอิน")) showLogin();
  }
}

/* ---------- system health ---------- */

function healthRow(name, status, detail, fix) {
  const tr = document.createElement("tr");
  const icon = status === "ok" ? '<span class="h-ok">&#10004;</span>'
    : status === "error" ? '<span class="h-err">&#10008;</span>'
    : status === "no-source" ? '<span class="h-mute">&#9675;</span>'
    : '<span class="h-mute">&#8855;</span>';
  const label = status === "ok" ? "ทำงานได้" : status === "error" ? "มีปัญหา" : status === "no-source" ? "ไม่พร้อมใช้งาน" : "ปิดอยู่";
  const fixHtml = fix
    ? `<div class="health-fix">วิธีแก้ไข: ${fix}</div>`
    : "";
  tr.innerHTML = `<td>${esc(name)}</td><td>${icon} <span class="h-${status === "ok" ? "ok" : status === "error" ? "err" : "mute"}">${label}</span></td><td>${esc(detail)}${fixHtml}</td>`;
  return tr;
}

function renderHealth(h) {
  if (!h) return;
  const tbody = $("health-tbody");
  tbody.innerHTML = "";
  tbody.appendChild(healthRow(
    "Security event log (แหล่งหลัก)",
    h.eventlog_ok ? "ok" : "error",
    h.eventlog_ok ? "อ่านได้ — เฝ้าระวัง RDP/FTP/MSSQL-Windows-auth ได้" : "อ่านไม่ได้ (สิทธิ์ไม่พอ)",
    h.eventlog_ok ? "" : "ติดตั้งเป็น service ด้วย install.bat (รันเป็น SYSTEM อ่านได้) หรือเปิดโปรแกรมด้วยสิทธิ์ administrator (คลิกขวา → Run as administrator)"
  ));
  tbody.appendChild(healthRow(
    "Windows Firewall (ตัวบล็อก)",
    h.firewall_com_ok ? (h.can_add_rules ? "ok" : "no-source") : "error",
    h.firewall_com_ok
      ? (h.can_add_rules ? "เข้าถึงได้ + มีสิทธิ์เพิ่ม rule — บล็อกได้จริง" : "เข้าถึงได้ แต่ไม่มีสิทธิ์เพิ่ม rule")
      : "เข้าถึง COM ไม่ได้",
    h.can_add_rules ? "" : "รันแบบ admin หรือติดตั้งเป็น service; ตรวจ service \"Windows Defender Firewall\" กำลังรัน (services.msc)"
  ));
  tbody.appendChild(healthRow(
    "สิทธิ์โปรแกรม",
    h.is_admin || h.in_service ? "ok" : "error",
    h.in_service ? "รันเป็น SYSTEM (สิทธิ์สูงสุด)" : h.is_admin ? "รันด้วย admin" : "รันแบบผู้ใช้ธรรมดา — บล็อกไม่ได้",
    h.is_admin || h.in_service ? "" : "ปิดโปรแกรม แล้วเปิดใหม่ด้วย Run as administrator หรือติดตั้งเป็น service (install.bat)"
  ));
  tbody.appendChild(healthRow(
    "Monitor / เฝ้าระวัง",
    h.monitor_running ? "ok" : "error",
    h.monitor_running ? "กำลังรัน (engines: " + Object.values(h.engines || {}).filter((v) => v === "ok").length + "/" + Object.keys(h.engines || {}).length + " แหล่งพร้อม)" : "monitor ไม่ได้รัน",
    h.monitor_running ? "" : "รันด้วยคำสั่ง run (python run.py run) หรือติดตั้งเป็น service"
  ));
  const engMap = { rdp: "RDP", openssh: "OpenSSH", mssql: "MSSQL", iis: "IIS Web", mysql: "MySQL", generic: "Generic" };
  const engFix = {
    rdp: "ต้องมีสิทธิ์อ่าน Security log — ดูแถวบนสุด",
    openssh: "ติดตั้ง OpenSSH Server (Windows Features) หรือปิด engine ถ้าไม่ใช้",
    mssql: "ติดตั้ง/เปิด MSSQL Server หรือปิด engine ถ้าไม่ใช้",
    iis: "ติดตั้ง IIS หรือตั้ง iis_log_dir ในหน้า ตั้งค่า",
    mysql: "ติดตั้ง MySQL หรือตั้ง mysql_log_dir ในหน้า ตั้งค่า",
    generic: "ตั้งค่า generic_logs (ชื่อ=path|regex) ในหน้า ตั้งค่า ดู CONFIG.md",
  };
  for (const [key, label] of Object.entries(engMap)) {
    const st = (h.engines || {})[key] || "disabled";
    const detail = st === "ok" ? "แหล่งข้อมูลพร้อม" : st === "error" ? "อ่านแหล่งข้อมูลไม่ได้" : st === "no-source" ? "ยังไม่พบแหล่งข้อมูล" : "ปิดใช้งาน (กด chip เปิดได้)";
    tbody.appendChild(healthRow(`Engine: ${label}`, st, detail, st === "ok" || st === "disabled" ? "" : engFix[key]));
  }
}

$("fw-test-btn").addEventListener("click", async () => {
  const btn = $("fw-test-btn");
  const msg = $("fw-test-msg");
  btn.disabled = true;
  msg.textContent = "กำลังทดสอบ...";
  try {
    const { data } = await api("/api/health/test-firewall", { method: "POST", body: "{}" });
    msg.textContent = data.message;
    toast(data.working ? "Firewall ทำงานได้จริง" : "Firewall ยังใช้ไม่ได้ — ดูรายละเอียด", data.working ? "ok" : "error");
  } catch (e) {
    msg.textContent = e.message;
    toast(e.message, "error");
  }
  btn.disabled = false;
  refreshOverview();
});

$("selftest-btn").addEventListener("click", async () => {
  const btn = $("selftest-btn");
  const list = $("selftest-steps");
  btn.disabled = true;
  list.innerHTML = '<li class="st-pending">กำลังทดสอบระบบทั้งหมด (ใช้เวลาประมาณ 15-30 วิ)...</li>';
  try {
    const { data } = await api("/api/self-test", { method: "POST", body: "{}", timeout: 60000 });
    list.innerHTML = "";
    (data.steps || []).forEach((step) => {
      const li = document.createElement("li");
      li.className = "st-" + (step.includes("FAIL") ? "fail" : "ok");
      li.textContent = step;
      list.appendChild(li);
    });
    toast(data.message, data.working ? "ok" : "error");
  } catch (e) {
    list.innerHTML = `<li class="st-fail">${esc(e.message)}</li>`;
    toast(e.message, "error");
  }
  btn.disabled = false;
  refreshOverview();
});

/* ---------- events ---------- */

async function refreshEvents() {
  try {
    const { data } = await api("/api/events?limit=80");
    const tbody = $("events-table").querySelector("tbody");
    tbody.innerHTML = "";
    $("events-count").textContent = `${data.events.length} เหตุการณ์ล่าสุด`;
    $("events-empty").style.display = data.events.length ? "none" : "";
    for (const ev of data.events) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono nw">${fmtTs(ev.ts)}</td>
        <td class="mono">${esc(ev.ip)}</td>
        <td>${esc(ev.user)}</td>
        <td>${esc(ev.domain)}</td>
        <td class="mono nw">${ev.logon_type || ""}</td>
        <td>${engineBadge(ev.source)}</td>
        <td>${typeBadge(ev.kind)}</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) {}
}

/* ---------- blocked ---------- */

async function refreshBlocked() {
  try {
    const { data } = await api("/api/blocked");
    const tbody = $("blocked-table").querySelector("tbody");
    tbody.innerHTML = "";
    $("blocked-empty").style.display = data.blocked.length ? "none" : "";
    data.blocked.forEach((b, i) => {
      const tr = document.createElement("tr");
      tr.dataset.ip = b.ip;
      const expires = b.expires ? fmtTs(b.expires) : "ถาวร";
      const ruleName = b.rule_name || "RDPGuard Block " + b.ip;
      tr.innerHTML = `
        <td class="mono">${esc(b.ip)}</td>
        <td class="geo">-</td>
        <td>${esc(b.reason)}</td>
        <td>${sourceBadge(b.source)}</td>
        <td class="mono nw">${fmtTs(b.created)}</td>
        <td class="mono nw">${expires}</td>
        <td>
          <button class="small check-cmd" data-ip="${esc(b.ip)}" data-rule="${esc(ruleName)}" title="คัดลอกคำสั่งตรวจสอบผ่าน cmd">ตรวจ cmd</button>
          <button class="small danger unblock" data-ip="${esc(b.ip)}">ปลดบล็อก</button>
        </td>`;
      tbody.appendChild(tr);
    });
    fillCountry(data.blocked, (r) => r.ip, 2, "blocked-table");
  } catch (e) {}
}

$("block-btn").addEventListener("click", async () => {
  const ip = $("block-ip").value.trim();
  if (!ip) return;
  try {
    const { data } = await api("/api/blocked", {
      method: "POST",
      body: JSON.stringify({ ip, hours: parseInt($("block-hours").value || "24", 10) }),
    });
    toast(data.message, "ok");
    $("block-ip").value = "";
    refreshBlocked();
  } catch (e) {
    toast(e.message, "error");
  }
});

$("unblock-all-btn").addEventListener("click", async () => {
  if (!confirm("ปลดบล็อกทุก IP ที่ถูกบล็อกไว้จริงหรือ? (ใช้เมื่อฉุกเฉิน)")) return;
  try {
    const { data } = await api("/api/unblock-all", { method: "POST", body: "{}" });
    toast(data.message, "ok");
    refreshBlocked();
  } catch (e) {
    toast(e.message, "error");
  }
});

document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".unblock");
  if (!btn) return;
  try {
    const { data } = await api("/api/blocked/" + encodeURIComponent(btn.dataset.ip), {
      method: "DELETE",
    });
    toast(data.message, "ok");
    refreshBlocked();
  } catch (err) {
    toast(err.message, "error");
  }
});

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".check-cmd");
  if (!btn) return;
  const ip = btn.dataset.ip;
  const rule = btn.dataset.rule;
  const cmds = [
    `REM 1) ตรวจว่า rule ถูกสร้างใน Windows Firewall (รัน cmd แบบ admin):`,
    `netsh advfirewall firewall show rule name="${rule}"`,
    `REM 2) ดูความพยายามล็อกอิน RDP ล้มเหลว (Event 4625) จาก IP นี้ (Security log):`,
    `wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:20 /rd:true /f:text | findstr /i "${ip}"`,
    `REM 3) ดู MSSQL ล็อกอินล้มเหลว (Event 18456, Application log):`,
    `wevtutil qe Application "/q:*[System[(EventID=18456)]]" /c:20 /rd:true /f:text | findstr /i "${ip}"`,
    `REM 4) ดู log ของ RDPGuard เอง:`,
    `type "%ProgramData%\\RDPGuard\\rdpguard.log" | findstr /i "${ip}"`,
  ].join("\r\n");
  navigator.clipboard.writeText(cmds).then(
    () => toast(`คัดลอกคำสั่งตรวจสอบ ${ip} แล้ว — วางใน Command Prompt (admin)`, "ok"),
    () => toast("คัดลอกไม่สำเร็จ", "error")
  );
});

/* ---------- whitelist / blacklist ---------- */

async function refreshLists() {
  try {
    const wl = (await api("/api/whitelist")).data.whitelist;
    const bl = (await api("/api/blacklist")).data.blacklist;
    const wlTbody = $("wl-table").querySelector("tbody");
    const blTbody = $("bl-table").querySelector("tbody");
    wlTbody.innerHTML = "";
    blTbody.innerHTML = "";
    $("wl-empty").style.display = wl.length ? "none" : "";
    $("bl-empty").style.display = bl.length ? "none" : "";
    wl.forEach((row) => {
      const tr = document.createElement("tr");
      tr.dataset.ip = row.ip;
      tr.innerHTML = `<td class="mono">${esc(row.ip)}</td><td class="geo">-</td><td>${esc(row.note)}</td>
        <td><button class="small danger wl-del" data-ip="${esc(row.ip)}">ลบ</button></td>`;
      wlTbody.appendChild(tr);
    });
    bl.forEach((row) => {
      const tr = document.createElement("tr");
      tr.dataset.ip = row.ip;
      tr.innerHTML = `<td class="mono">${esc(row.ip)}</td><td class="geo">-</td><td>${esc(row.note)}</td>
        <td><button class="small danger bl-del" data-ip="${esc(row.ip)}">ลบ</button></td>`;
      blTbody.appendChild(tr);
    });
    fillCountry(wl, (r) => r.ip, 2, "wl-table");
    fillCountry(bl, (r) => r.ip, 2, "bl-table");
  } catch (e) {}
}

async function addToList(which, inputId, path) {
  const ip = $(inputId).value.trim();
  if (!ip) return;
  try {
    const { data } = await api(path, {
      method: "POST",
      body: JSON.stringify({ ip, note: "" }),
    });
    toast(data.message, "ok");
    $(inputId).value = "";
    refreshLists();
  } catch (e) {
    toast(e.message, "error");
  }
}
$("wl-add").addEventListener("click", () => addToList("wl", "wl-ip", "/api/whitelist"));
$("bl-add").addEventListener("click", () => addToList("bl", "bl-ip", "/api/blacklist"));

document.addEventListener("click", async (e) => {
  const wlDel = e.target.closest(".wl-del");
  if (wlDel) {
    try {
      await api("/api/whitelist/" + encodeURIComponent(wlDel.dataset.ip), { method: "DELETE" });
      refreshLists();
    } catch (err) { toast(err.message, "error"); }
    return;
  }
  const blDel = e.target.closest(".bl-del");
  if (blDel) {
    try {
      await api("/api/blacklist/" + encodeURIComponent(blDel.dataset.ip), { method: "DELETE" });
      refreshLists();
    } catch (err) { toast(err.message, "error"); }
  }
});

/* ---------- log ---------- */

async function refreshLog() {
  try {
    const { data } = await api("/api/log?lines=250");
    const view = $("log-view");
    const nearBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 80;
    view.textContent = data.lines.length ? data.lines.join("\n") : "(log ว่างเปล่า)";
    if (nearBottom) view.scrollTop = view.scrollHeight;
    $("log-file-hint").textContent = data.file || "";
  } catch (e) {}
}

$("log-refresh").addEventListener("click", refreshLog);

/* ---------- settings ---------- */

const SETTINGS_UI = {
  monitor: {
    title: "การเฝ้าระวัง",
    fields: [
      { key: "enable", label: "เปิดการเฝ้าระวัง", type: "bool" },
      { key: "poll_interval_seconds", label: "อ่าน event log ทุก (วินาที)", type: "int" },
      { key: "logon_types", label: "LogonType ที่นับ (3,10 หรือ *)", type: "text" },
    ],
  },
  detection: {
    title: "การตรวจจับ",
    fields: [
      { key: "max_attempts", label: "จำนวนครั้งที่ล้มเหลว", type: "int" },
      { key: "window_minutes", label: "กรอบเวลา (นาที)", type: "int" },
      { key: "block_hours", label: "บล็อกนาน (ชั่วโมง, 0 = ถาวร)", type: "int" },
      { key: "auto_extend", label: "ต่ออายุบล็อกอัตโนมัติ", type: "bool" },
      { key: "skip_local_ips", label: "ข้าม IP ในวง LAN/เครื่องตัวเอง", type: "bool" },
      { key: "active_session_grace_minutes", label: "กันบล็อก IP ที่มี session จริง (นาที)", type: "int" },
      { key: "never_block_ips", label: "never_block_ips (IP/CIDR คั่น ,)", type: "text" },
      { key: "escalate_after_blocks", label: "ขยายบล็อกเมื่อโดนบล็อกครบกี่ครั้ง (0=ปิด)", type: "int" },
      { key: "escalate_block_hours", label: "ขยายเป็นกี่ชั่วโมง (ค่าเริ่มต้น 168)", type: "int" },
      { key: "escalate_to_permanent", label: "ขยายเป็นบล็อกถาวร (แทนชั่วโมง)", type: "bool" },
      { key: "escalation_window_days", label: "กรอบเวลานับครั้ง (วัน)", type: "int" },
    ],
  },
  firewall: {
    title: "Windows Firewall",
    fields: [
      { key: "rule_prefix", label: "คำนำหน้าชื่อ rule", type: "text" },
      { key: "profile", label: "Profile", type: "select", options: ["any", "domain", "private", "public"] },
      { key: "blocked_ports", label: "จำกัดพอร์ตที่บล็อก (ว่าง = ทุกพอร์ต)", type: "text" },
    ],
  },
  engines: {
    title: "Engine เพิ่มเติม (ตรวจจับโปรโตคอลอื่น)",
    fields: [
      { key: "openssh", label: "OpenSSH (SSH)", type: "bool" },
      { key: "mssql", label: "MSSQL (Event 18456)", type: "bool" },
      { key: "iis", label: "IIS / HTTP Web Login (W3C)", type: "bool" },
      { key: "mysql", label: "MySQL (error log)", type: "bool" },
      { key: "generic", label: "Generic log engine", type: "bool" },
      { key: "openssh_max_attempts", label: "OpenSSH: จำนวนครั้ง (ว่าง = ค่ากลาง)", type: "text" },
      { key: "mssql_max_attempts", label: "MSSQL: จำนวนครั้ง", type: "text" },
      { key: "iis_max_attempts", label: "IIS: จำนวนครั้ง", type: "text" },
      { key: "mysql_max_attempts", label: "MySQL: จำนวนครั้ง", type: "text" },
      { key: "generic_max_attempts", label: "Generic: จำนวนครั้ง", type: "text" },
      { key: "iis_log_dir", label: "โฟลเดอร์ IIS log (ว่าง = auto)", type: "text" },
      { key: "mysql_log_dir", label: "โฟลเดอร์ MySQL log (ว่าง = auto)", type: "text" },
      { key: "generic_logs", label: "Generic: ชื่อ=path|regex (คั่น ;)", type: "text" },
    ],
  },
  webui: {
    title: "Web UI",
    fields: [
      { key: "host", label: "Host (127.0.0.1 = เฉพาะเครื่องนี้)", type: "text" },
      { key: "port", label: "พอร์ต", type: "int" },
      { key: "password", label: "รหัสผ่าน (เว้นว่าง = สุ่มใหม่)", type: "text" },
    ],
  },
};

async function refreshSettings() {
  try {
    const { data } = await api("/api/settings");
    const grid = $("settings-grid");
    grid.innerHTML = "";
    window._settingsData = data;
    for (const [section, spec] of Object.entries(SETTINGS_UI)) {
      const group = document.createElement("div");
      group.className = "settings-group";
      group.innerHTML = `<h3>${spec.title}</h3>`;
      const values = data[section] || {};
      for (const f of spec.fields) {
        const field = document.createElement("div");
        field.className = "field";
        if (f.type === "bool") {
          field.innerHTML = `<label>${f.label}</label>
            <span class="check"><input type="checkbox" data-sec="${section}" data-key="${f.key}" ${String(values[f.key]) === "true" ? "checked" : ""}></span>`;
        } else if (f.type === "select") {
          const opts = f.options.map((o) => `<option ${values[f.key] === o ? "selected" : ""}>${o}</option>`).join("");
          field.innerHTML = `<label>${f.label}</label><select data-sec="${section}" data-key="${f.key}">${opts}</select>`;
        } else {
          field.innerHTML = `<label>${f.label}</label><input type="text" data-sec="${section}" data-key="${f.key}" value="${esc(values[f.key] ?? "")}">`;
        }
        group.appendChild(field);
      }
      grid.appendChild(group);
    }
  } catch (e) {}
}

$("settings-save").addEventListener("click", async () => {
  const payload = {};
  document.querySelectorAll("[data-sec]").forEach((el) => {
    const sec = el.dataset.sec;
    const key = el.dataset.key;
    if (!payload[sec]) payload[sec] = {};
    if (el.type === "checkbox") payload[sec][key] = el.checked ? "true" : "false";
    else payload[sec][key] = el.value.trim();
  });
  try {
    const { data } = await api("/api/settings", { method: "POST", body: JSON.stringify(payload) });
    toast(data.message, "ok");
    $("settings-msg").textContent = "บันทึกแล้ว " + new Date().toLocaleTimeString("th-TH");
    refreshSettings();
  } catch (e) {
    toast(e.message, "error");
  }
});

init();
