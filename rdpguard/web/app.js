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
  const { timeout, ...fetchOpts } = options;
  const ctrl = timeout ? new AbortController() : null;
  const timer = timeout ? setTimeout(() => ctrl.abort(), timeout) : null;
  let res;
  try {
    res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      signal: ctrl ? ctrl.signal : undefined,
      ...fetchOpts,
    });
  } catch (e) {
    throw new Error("server ไม่ตอบกลับ (timeout/ตัดการเชื่อมต่อ) — ลองอีกครั้ง");
  } finally {
    if (timer) clearTimeout(timer);
  }
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
  const map = { auto: "อัตโนมัติ", manual: "ด้วยมือ", blacklist: "blacklist", accumulate: "สะสม", expire: "หมดอายุ" };
  return `<span class="badge ${source}">${map[source] || source}</span>`;
}

function engineBadge(source) {
  const map = { rdp: "RDP", openssh: "OpenSSH", mssql: "MSSQL", iis: "IIS Web", mysql: "MySQL" };
  const label = map[source] || source || "-";
  return `<span class="badge ntlm">${esc(label)}</span>`;
}

/* ---------- views ---------- */

async function init() {
  try {
    const status = await api("/api/login-status");
    if (status.data.authorized) {
      showApp();
    } else {
      showLogin();
    }
  } catch (e) {
    // server ยังไม่พร้อม (กำลัง restart) — ลองใหม่เรื่อย ๆ
    setTimeout(init, 2000);
  }
}

function showLogin() {
  stopAppPolling();
  $("login-view").style.display = "flex";
  $("app-view").style.display = "none";
  $("login-password").focus();
}

let appIntervals = [];

function stopAppPolling() {
  appIntervals.forEach(clearInterval);
  appIntervals = [];
}

function showApp() {
  $("login-view").style.display = "none";
  $("app-view").style.display = "block";
  stopAppPolling();
  refreshOverview();
  refreshTrends();
  refreshDetection();
  refreshService();
  refreshEvents();
  refreshBlocked();
  refreshLists();
  refreshHistory();
  refreshAudit();
  refreshSettings();
  refreshLog();
  refreshSessions();
  appIntervals.push(setInterval(refreshOverview, 3000));
  appIntervals.push(setInterval(refreshTrends, 30000));
  appIntervals.push(setInterval(refreshEvents, 3000));
  appIntervals.push(setInterval(refreshBlocked, 5000));
  appIntervals.push(setInterval(refreshHistory, 10000));
  appIntervals.push(setInterval(refreshAudit, 10000));
  appIntervals.push(setInterval(refreshService, 10000));
  appIntervals.push(setInterval(refreshLog, 5000));
  appIntervals.push(setInterval(refreshSessions, 10000));
  checkSetup();
}

/* ---------- sessions (qwinsta) ---------- */

async function refreshSessions() {
  try {
    const { data } = await api("/api/sessions");
    const tbody = $("sessions-table").querySelector("tbody");
    tbody.innerHTML = "";
    $("sessions-empty").style.display = data.sessions.length ? "none" : "";
    const kindLabel = { rdp: "RDP (remote)", console: "Console (จอเครื่อง)", network: "Network (SMB/แชร์)", system: "System" };
    for (const s of data.sessions) {
      const isRdp = s.kind === "rdp";
      const active = s.state === "Active" || s.state === "Conn";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${esc(kindLabel[s.kind] || s.kind)}</td>
        <td>${esc(s.user || "-")}</td>
        <td class="mono nw">${esc(s.id)}</td>
        <td>${isRdp && active ? '<span class="badge danger">RDP ใช้งานอยู่!</span>' : active ? '<span class="badge success">Active</span>' : `<span class="badge ntlm">${esc(s.state || "-")}</span>`}</td>
        <td class="mono nw">${s.start ? esc(s.start) : ""}</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) {}
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
const geoInFlight = {};  // กันขอซ้ำ IP เดียวกันตอน request ก่อนยังไม่เสร็จ

async function fillCountry(rows, ipGetter, tdIndex, tableId) {
  const missing = [];
  for (const row of rows) {
    const ip = ipGetter(row);
    if (ip && !(ip in geoCache) && !geoInFlight[ip]) missing.push(ip);
  }
  if (missing.length) {
    missing.forEach((ip) => (geoInFlight[ip] = true));
    try {
      const { data } = await api("/api/geoip", { method: "POST", body: JSON.stringify({ ips: missing }) });
      for (const [ip, info] of Object.entries(data.geoip || {})) geoCache[ip] = info || null;
    } catch (e) {}
    missing.forEach((ip) => delete geoInFlight[ip]);
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
    const s = data.stats || {};
    $("stat-failed").textContent = s.failed_24h ?? 0;
    $("stat-success").textContent = s.success_24h ?? 0;
    $("stat-active").textContent = s.blocked_active ?? 0;
    $("stat-total").textContent = s.blocked_total ?? 0;
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
    const dbSize = data.database?.size || 0;
    $("database-hint").textContent = dbSize
      ? `ฐานข้อมูล ${(dbSize / 1048576).toFixed(1)} MB`
      : "";

    renderHealth(data.health);
  } catch (e) {
    if (e.message.includes("401") || e.message.includes("ล็อกอิน")) showLogin();
  }
}

async function refreshTrends() {
  try {
    const { data } = await api("/api/trends?days=7");
    const bars = $("trend-bars");
    const rows = data.days || [];
    const maximum = Math.max(1, ...rows.map((row) => Math.max(row.failed || 0, row.success || 0)));
    bars.innerHTML = rows.map((row) => {
      const failHeight = Math.max(2, Math.round(((row.failed || 0) / maximum) * 100));
      const okHeight = Math.max(2, Math.round(((row.success || 0) / maximum) * 100));
      return `<div class="trend-day"><div class="trend-columns"><span class="trend-bar fail" style="height:${failHeight}%" title="ล้มเหลว ${row.failed || 0}"></span><span class="trend-bar success" style="height:${okHeight}%" title="สำเร็จ ${row.success || 0}"></span></div><span>${esc(row.day.slice(5))}</span></div>`;
    }).join("") || '<span class="hint">ยังไม่มีข้อมูล</span>';
  } catch (e) {}
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

let _eventsSeq = 0;
let _eventsPage = 0;
const _eventsPageSize = 80;

function eventFilterQuery() {
  const params = new URLSearchParams({
    limit: String(_eventsPageSize),
    offset: String(_eventsPage * _eventsPageSize),
  });
  const q = $("events-q")?.value.trim();
  const source = $("events-source")?.value;
  const kind = $("events-kind")?.value;
  if (q) params.set("q", q);
  if (source) params.set("source", source);
  if (kind) params.set("kind", kind);
  return params;
}

async function refreshEvents() {
  const seq = ++_eventsSeq;
  try {
    const { data } = await api("/api/events?" + eventFilterQuery().toString());
    if (seq !== _eventsSeq) return;  // มี request ใหม่กว่าแล้ว — อย่าเขียนทับข้อมูลใหม่ด้วยของเก่า
    const tbody = $("events-table").querySelector("tbody");
    tbody.innerHTML = "";
    const total = data.total ?? data.events.length;
    const pages = Math.max(1, Math.ceil(total / _eventsPageSize));
    $("events-count").textContent = `${total} เหตุการณ์`;
    $("events-page").textContent = `หน้า ${_eventsPage + 1} / ${pages}`;
    $("events-prev").disabled = _eventsPage <= 0;
    $("events-next").disabled = _eventsPage + 1 >= pages;
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

function exportEvents() {
  const params = eventFilterQuery();
  params.delete("limit");
  params.delete("offset");
  window.location.href = "/api/events/export?" + params.toString();
}

$("events-prev").addEventListener("click", () => { if (_eventsPage > 0) { _eventsPage--; refreshEvents(); } });
$("events-next").addEventListener("click", () => { _eventsPage++; refreshEvents(); });
$("events-export").addEventListener("click", exportEvents);
$("events-clear").addEventListener("click", () => {
  $("events-q").value = "";
  $("events-source").value = "";
  $("events-kind").value = "";
  _eventsPage = 0;
  refreshEvents();
});
let _eventsFilterTimer = 0;
function scheduleEventsRefresh() {
  clearTimeout(_eventsFilterTimer);
  _eventsFilterTimer = setTimeout(() => { _eventsPage = 0; refreshEvents(); }, 250);
}
["events-q", "events-source", "events-kind"].forEach((id) => {
  $(id).addEventListener("input", scheduleEventsRefresh);
  $(id).addEventListener("change", scheduleEventsRefresh);
});

/* ---------- blocked ---------- */

let _blockedSeq = 0;
let _blockedPage = 0;
const _blockedPageSize = 100;

function blockedFilterQuery() {
  const params = new URLSearchParams({
    limit: String(_blockedPageSize),
    offset: String(_blockedPage * _blockedPageSize),
  });
  const q = $("blocked-q")?.value.trim();
  const source = $("blocked-source")?.value;
  if (q) params.set("q", q);
  if (source) params.set("source", source);
  return params;
}

async function refreshBlocked() {
  const seq = ++_blockedSeq;
  try {
    const { data } = await api("/api/blocked?" + blockedFilterQuery().toString());
    if (seq !== _blockedSeq) return;
    const tbody = $("blocked-table").querySelector("tbody");
    tbody.innerHTML = "";
    $("blocked-empty").style.display = data.blocked.length ? "none" : "";
    const warn = $("blocked-count-warn");
    if (warn) {
      const total = data.total ?? data.blocked.length;
      if (total > 200) {
        warn.style.display = "";
        warn.innerHTML = `<span class="h-err">&#9888;</span> มี IP ถูกบล็อก ${total} IP — จำนวนเยอะมาก แนะนำ: บล็อกแบบ CIDR (subnet), ลด block_hours, หรือปลดล้าง IP ที่ไม่จำเป็น`;
      } else if (total > 50) {
        warn.style.display = "";
        warn.innerHTML = `<span class="h-mute">&#9888;</span> มี IP ถูกบล็อก ${total} IP — ถ้า IP โจมตีมาจาก subnet เดียวกัน แนะนำบล็อกแบบ CIDR แทนราย IP`;
      } else {
        warn.style.display = "none";
      }
    }
    const pages = Math.max(1, Math.ceil((data.total ?? data.blocked.length) / _blockedPageSize));
    $("blocked-page").textContent = `หน้า ${_blockedPage + 1} / ${pages}`;
    $("blocked-prev").disabled = _blockedPage <= 0;
    $("blocked-next").disabled = _blockedPage + 1 >= pages;
    $("blocked-select-all").checked = false;
    data.blocked.forEach((b, i) => {
      const tr = document.createElement("tr");
      tr.dataset.ip = b.ip;
      const expires = b.expires ? fmtTs(b.expires) : "ถาวร";
      const ruleName = b.rule_name || "RDPGuard Block " + b.ip;
      tr.innerHTML = `
        <td><input type="checkbox" class="blocked-select" data-ip="${esc(b.ip)}"></td>
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
    updateBulkButton();
    fillCountry(data.blocked, (r) => r.ip, 3, "blocked-table");
  } catch (e) {}
}

function exportBlocked() {
  const params = blockedFilterQuery();
  params.delete("limit");
  params.delete("offset");
  window.location.href = "/api/blocked/export?" + params.toString();
}

function updateBulkButton() {
  const selected = document.querySelectorAll(".blocked-select:checked").length;
  const button = $("blocked-bulk-unblock");
  if (button) {
    button.disabled = selected === 0;
    button.textContent = selected ? `ปลดรายการที่เลือก (${selected})` : "ปลดรายการที่เลือก";
  }
}

$("blocked-prev").addEventListener("click", () => { if (_blockedPage > 0) { _blockedPage--; refreshBlocked(); } });
$("blocked-next").addEventListener("click", () => { _blockedPage++; refreshBlocked(); });
$("blocked-export").addEventListener("click", exportBlocked);
$("blocked-clear").addEventListener("click", () => {
  $("blocked-q").value = "";
  $("blocked-source").value = "";
  _blockedPage = 0;
  refreshBlocked();
});
let _blockedFilterTimer = 0;
function scheduleBlockedRefresh() {
  clearTimeout(_blockedFilterTimer);
  _blockedFilterTimer = setTimeout(() => { _blockedPage = 0; refreshBlocked(); }, 250);
}
["blocked-q", "blocked-source"].forEach((id) => {
  $(id).addEventListener("input", scheduleBlockedRefresh);
  $(id).addEventListener("change", scheduleBlockedRefresh);
});
$("blocked-select-all").addEventListener("change", (event) => {
  document.querySelectorAll(".blocked-select").forEach((input) => { input.checked = event.target.checked; });
  updateBulkButton();
});
document.addEventListener("change", (event) => {
  if (event.target.classList.contains("blocked-select")) updateBulkButton();
});
$("blocked-bulk-unblock").addEventListener("click", async () => {
  const ips = Array.from(document.querySelectorAll(".blocked-select:checked"), (input) => input.dataset.ip);
  if (!ips.length || !confirm(`ปลดบล็อก ${ips.length} รายการที่เลือกหรือไม่?`)) return;
  try {
    const { data } = await api("/api/blocked/bulk-unblock", { method: "POST", body: JSON.stringify({ ips }) });
    toast(`ปลดบล็อกสำเร็จ ${data.success}/${data.total} รายการ`, data.success === data.total ? "ok" : "");
    refreshBlocked();
  } catch (e) { toast(e.message, "error"); }
});

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

async function addToList(which, inputId, noteId, path) {
  const ip = $(inputId).value.trim();
  if (!ip) return;
  try {
    const { data } = await api(path, {
      method: "POST",
      body: JSON.stringify({ ip, note: $(noteId).value.trim().slice(0, 200) }),
    });
    toast(data.message, "ok");
    $(inputId).value = "";
    $(noteId).value = "";
    refreshLists();
  } catch (e) {
    toast(e.message, "error");
  }
}
$("wl-add").addEventListener("click", () => addToList("wl", "wl-ip", "wl-note", "/api/whitelist"));
$("bl-add").addEventListener("click", () => addToList("bl", "bl-ip", "bl-note", "/api/blacklist"));

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

/* ---------- history / audit ---------- */

async function refreshHistory() {
  try {
    const params = new URLSearchParams({ limit: "100" });
    const q = $("history-q")?.value.trim();
    const source = $("history-source")?.value;
    if (q) params.set("q", q);
    if (source) params.set("source", source);
    const { data } = await api("/api/blocked-history?" + params.toString());
    const tbody = $("history-table").querySelector("tbody");
    tbody.innerHTML = "";
    $("history-empty").style.display = data.history.length ? "none" : "";
    data.history.forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${esc(row.ip)}</td><td>${sourceBadge(row.source)}</td><td class="mono nw">${fmtTs(row.created)}</td><td class="mono nw">${fmtTs(row.unblocked_at)}</td><td>${esc(row.unblocked_by || "-")}</td>`;
      tbody.appendChild(tr);
    });
  } catch (e) {}
}

async function refreshAudit() {
  try {
    const params = new URLSearchParams({ limit: "100" });
    const q = $("audit-q")?.value.trim();
    if (q) params.set("q", q);
    const { data } = await api("/api/audit?" + params.toString());
    const tbody = $("audit-table").querySelector("tbody");
    tbody.innerHTML = "";
    $("audit-empty").style.display = data.audit.length ? "none" : "";
    data.audit.forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono nw">${fmtTs(row.ts)}</td><td>${esc(row.actor)}</td><td>${esc(row.action)}</td><td class="mono">${esc(row.target)}</td><td>${esc(row.result)}</td>`;
      tbody.appendChild(tr);
    });
  } catch (e) {}
}

$("history-export").addEventListener("click", () => {
  const params = new URLSearchParams();
  if ($("history-q").value.trim()) params.set("q", $("history-q").value.trim());
  if ($("history-source").value) params.set("source", $("history-source").value);
  window.location.href = "/api/blocked-history/export?" + params.toString();
});
$("audit-export").addEventListener("click", () => {
  const params = new URLSearchParams();
  if ($("audit-q").value.trim()) params.set("q", $("audit-q").value.trim());
  window.location.href = "/api/audit/export?" + params.toString();
});
["history-q", "history-source", "audit-q"].forEach((id) => {
  $(id).addEventListener("input", () => { id.startsWith("history") ? refreshHistory() : refreshAudit(); });
  $(id).addEventListener("change", () => { id.startsWith("history") ? refreshHistory() : refreshAudit(); });
});

/* ---------- log ---------- */

let _logSeq = 0;
let _logLines = [];
let _logFilesLoaded = false;

function renderLogLines() {
  const query = $("log-search")?.value.trim().toLowerCase() || "";
  const lines = query ? _logLines.filter((line) => line.toLowerCase().includes(query)) : _logLines;
  const view = $("log-view");
  const nearBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 80;
  view.textContent = lines.length ? lines.join("\n") : "(ไม่พบข้อความ)";
  if (nearBottom) view.scrollTop = view.scrollHeight;
  const count = $("log-count-hint");
  if (count) count.textContent = `${lines.length}/${_logLines.length} บรรทัด`;
}

async function refreshLogFiles() {
  if (_logFilesLoaded) return;
  try {
    const { data } = await api("/api/log/files");
    const select = $("log-file");
    select.innerHTML = "";
    (data.files || []).forEach((file) => {
      const option = document.createElement("option");
      option.value = file.name;
      option.textContent = file.name;
      select.appendChild(option);
    });
    _logFilesLoaded = true;
  } catch (e) {}
}

async function refreshLog() {
  if ($("log-pause")?.checked) return;
  const seq = ++_logSeq;
  try {
    await refreshLogFiles();
    const lines = $("log-lines") ? $("log-lines").value : 250;
    const file = $("log-file")?.value || "rdpguard.log";
    const { data } = await api(`/api/log?lines=${encodeURIComponent(lines)}&file=${encodeURIComponent(file)}`);
    if (seq !== _logSeq) return;
    _logLines = data.lines || [];
    $("log-file-hint").textContent = data.file || "";
    const sz = data.file_size || 0;
    $("log-size-hint").textContent = sz > 0
      ? (sz < 1048576 ? `(${Math.max(1, Math.round(sz / 1024))} KB)` : `(${(sz / 1048576).toFixed(1)} MB)`)
      : "";
    renderLogLines();
  } catch (e) {}
}

$("log-refresh").addEventListener("click", refreshLog);
$("log-lines").addEventListener("change", refreshLog);
$("log-file").addEventListener("change", refreshLog);
$("log-search").addEventListener("input", renderLogLines);
$("log-download").addEventListener("click", () => {
  const file = $("log-file").value || "rdpguard.log";
  window.location.href = "/api/log/download?file=" + encodeURIComponent(file);
});

/* ---------- settings ---------- */

const SETTINGS_UI = {
  general: {
    title: "Log และฐานข้อมูล",
    fields: [
      { key: "log_level", label: "ระดับ Log", type: "select", options: ["DEBUG", "INFO", "WARNING", "ERROR"], restart: true },
      { key: "log_max_mb", label: "ขนาด Log ต่อไฟล์ (MB)", type: "int", restart: true },
      { key: "log_backups", label: "จำนวนไฟล์ Log สำรอง", type: "int", restart: true },
      { key: "event_retention_days", label: "เก็บ Events (วัน, 0=ไม่ลบ)", type: "int", restart: true },
      { key: "history_retention_days", label: "เก็บประวัติ Blocked (วัน, 0=ไม่ลบ)", type: "int", restart: true },
      { key: "audit_retention_days", label: "เก็บ Audit Log (วัน, 0=ไม่ลบ)", type: "int", restart: true },
    ],
  },
  monitor: {
    title: "การเฝ้าระวัง",
    fields: [
      { key: "enable", label: "เปิดการเฝ้าระวัง", type: "bool" },
      { key: "poll_interval_seconds", label: "อ่าน event log ทุก (วินาที)", type: "int" },
      { key: "logon_types", label: "LogonType ที่นับ (3,10 หรือ *)", type: "text" },
    ],
  },
  firewall: {
    title: "Windows Firewall",
    fields: [
      { key: "single_rule", label: "ใช้ rule เดียวรวมทุก IP (แบบ RDPGuard)", type: "bool" },
      { key: "rule_prefix", label: "คำนำหน้าชื่อ rule", type: "text" },
      { key: "profile", label: "Profile", type: "select", options: ["any", "domain", "private", "public"] },
      { key: "blocked_ports", label: "จำกัดพอร์ตที่บล็อก (ว่าง = ทุกพอร์ต)", type: "text" },
    ],
  },
  webui: {
    title: "Web UI",
    fields: [
      { key: "host", label: "Host (127.0.0.1 = เฉพาะเครื่องนี้)", type: "text" },
      { key: "port", label: "พอร์ต", type: "int" },
      { key: "password", label: "รหัสผ่าน (เว้นว่าง = คงเดิม)", type: "secret" },
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
      { key: "accumulate_window_hours", label: "ตัวนับสะสม: กรอบเวลา (ชั่วโมง, 0=ปิด)", type: "int" },
      { key: "accumulate_threshold", label: "ตัวนับสะสม: ครบกี่ครั้งถึงบล็อก (0=ปิด)", type: "int" },
      { key: "accumulate_block_hours", label: "ตัวนับสะสม: บล็อกนาน (ชั่วโมง)", type: "int" },
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
      { key: "generic_logs", label: "Generic log engine: ไฟล์ + regex", type: "generic_logs" },
    ],
  },
  notify: {
    title: "แจ้งเตือน (Telegram / Email)",
    fields: [
      { key: "enable", label: "เปิดการแจ้งเตือนเมื่อบล็อก IP", type: "bool" },
      { key: "channel", label: "ช่องทางที่ใช้", type: "select", options: [{ v: "both", l: "ทั้งสองช่องทาง" }, { v: "telegram", l: "Telegram เท่านั้น" }, { v: "email", l: "Email เท่านั้น" }] },
      { key: "hostname", label: "ชื่อเครื่อง (ว่าง = ชื่อเครื่องระบบ — ใช้ระบุเป้าในคำสั่ง Telegram เช่น /status @ชื่อเครื่อง)", type: "text" },
      { key: "telegram_bot_token", label: "Telegram: Bot Token (จาก @BotFather)", type: "secret" },
      { key: "telegram_chat_id", label: "Telegram: Chat ID", type: "secret" },
      { key: "telegram_verify_ssl", label: "ตรวจสอบ SSL ของ Telegram (ปิดถ้า proxy/กันไวรัส intercept HTTPS แล้วขึ้น CERTIFICATE_VERIFY_FAILED)", type: "bool" },
      { key: "smtp_host", label: "SMTP: Host (เช่น smtp.gmail.com)", type: "text" },
      { key: "smtp_port", label: "SMTP: พอร์ต (587 = STARTTLS, 465 = SSL)", type: "int" },
      { key: "smtp_user", label: "SMTP: ผู้ใช้", type: "text" },
      { key: "smtp_password", label: "SMTP: รหัสผ่าน", type: "secret" },
      { key: "smtp_to", label: "SMTP: ผู้รับ", type: "text" },
      { key: "cooldown_seconds", label: "เว้นช่วงส่ง (วินาที, 0 = ส่งทันที)", type: "int" },
      { key: "webhook_enable", label: "เปิด Webhook เสริม", type: "bool" },
      { key: "webhook_url", label: "Webhook URL", type: "secret" },
      { key: "webhook_verify_ssl", label: "ตรวจสอบ SSL ของ Webhook", type: "bool" },
      { key: "enable_commands", label: "เปิดรับคำสั่งจาก Telegram (Telegram Command)", type: "bool" },
      { key: "confirm_timeout_seconds", label: "หมดเวลายืนยันคำสั่งอันตราย (วินาที)", type: "int" },
      { key: "rate_limit_per_minute", label: "จำกัดคำสั่งต่อนาที", type: "int" },
      { key: "poll_retry_min_seconds", label: "รอขั้นต่ำเมื่อ bot ติด 409 (หลายเครื่อง — วินาที)", type: "int" },
      { key: "poll_retry_max_seconds", label: "รอขั้นสูงเมื่อ bot ติด 409 (หลายเครื่อง — วินาที)", type: "int" },
      { key: "_telegram_cmd_status", label: "สถานะ Telegram Command", type: "tg_status" },
      { key: "_notify_test", label: "ทดสอบการแจ้งเตือน", type: "notify_test" },
      { key: "_notify_status", label: "สถานะการแจ้งเตือน", type: "notify_status" },
    ],
  },
};

function parseGenericLogs(value) {
  return String(value || "")
    .split(";")
    .map((part) => {
      const p = part.trim();
      if (!p) return null;
      const eq = p.indexOf("=");
      const name = (eq >= 0 ? p.slice(0, eq) : p).trim();
      const rest = eq >= 0 ? p.slice(eq + 1) : "";
      const bar = rest.indexOf("|");
      const path = (bar >= 0 ? rest.slice(0, bar) : rest).trim();
      const regex = bar >= 0 ? rest.slice(bar + 1).trim() : "";
      return { name, path, regex };
    })
    .filter(Boolean);
}

function renderGenericEditor(box, value) {
  const hidden = box.querySelector('input[type="hidden"]');
  const list = document.createElement("div");
  list.className = "gen-rows";
  box.appendChild(list);

  const validateRow = (row) => {
    const path = row.querySelector(".gen-path").value.trim();
    const regex = row.querySelector(".gen-regex").value.trim();
    const warns = [];
    if (regex && (regex.includes("|") || regex.includes(";")))
      warns.push("regex ห้ามมีอักขระ | หรือ ; (ตัวคั่น config)");
    if (path && path.includes("=")) warns.push("path ห้ามมี =");
    if (path && !regex) warns.push("ยังไม่ได้ใส่ regex");
    if (regex && !path) warns.push("ยังไม่ได้ใส่ path");
    const w = row.querySelector(".gen-warn");
    w.textContent = warns.join(" · ");
    row.classList.toggle("gen-invalid", warns.length > 0);
  };

  const sync = () => {
    const parts = [];
    Array.from(list.children).forEach((row) => {
      validateRow(row);
      const name = row.querySelector(".gen-name").value.trim();
      const path = row.querySelector(".gen-path").value.trim();
      const regex = row.querySelector(".gen-regex").value.trim();
      if (name || path || regex) parts.push(`${name || "generic"}=${path}|${regex}`);
    });
    hidden.value = parts.join(";");
  };

  const addRow = (entry) => {
    const row = document.createElement("div");
    row.className = "gen-row";
    row.innerHTML =
      `<input class="gen-name" placeholder="ชื่อ (เช่น mail)" value="${esc(entry?.name || "")}" title="ป้ายกำกับที่เห็นใน UI">` +
      `<input class="gen-path" placeholder="C:\\path\\ไฟล์.log" value="${esc(entry?.path || "")}" title="เส้นทางไฟล์ log จริง (ไฟล์เดียว)">` +
      `<input class="gen-regex" placeholder="regex — ต้องมี {IP} แทนตำแหน่ง IP" value="${esc(entry?.regex || "")}" title="Python regex เช่น AUTH LOGIN failed from {IP}">` +
      `<button type="button" class="gen-del" title="ลบรายการ">&times;</button>` +
      `<div class="gen-warn"></div>`;
    list.appendChild(row);
    row.querySelectorAll("input").forEach((inp) => inp.addEventListener("input", sync));
    row.querySelector(".gen-del").addEventListener("click", () => {
      row.remove();
      sync();
    });
    return row;
  };

  const entries = parseGenericLogs(value);
  (entries.length ? entries : [null]).forEach((e) => addRow(e));
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "gen-add";
  addBtn.textContent = "+ เพิ่มรายการ";
  addBtn.addEventListener("click", () => {
    addRow(null);
    sync();
  });
  box.appendChild(addBtn);
  sync();
}

async function refreshSettings() {
  try {
    const { data } = await api("/api/settings");
    const grid = $("settings-grid");
    grid.innerHTML = "";
    window._settingsData = data;
    for (const [section, spec] of Object.entries(SETTINGS_UI)) {
      const group = document.createElement("div");
      group.className = "settings-group";
      group.dataset.sec = section;
      group.innerHTML = `<h3>${spec.title}</h3>`;
      const values = data[section] || {};
      for (const f of spec.fields) {
        const field = document.createElement("div");
        field.className = "field";
        if (f.type === "bool") {
          field.innerHTML = `<label>${f.label}</label>
            <span class="check"><input type="checkbox" data-sec="${section}" data-key="${f.key}" ${String(values[f.key]) === "true" ? "checked" : ""}></span>`;
        } else if (f.type === "select") {
          const opts = f.options.map((o) => {
            const v = typeof o === "object" ? o.v : o;
            const l = typeof o === "object" ? o.l : o;
            return `<option value="${v}" ${String(values[f.key]) === String(v) ? "selected" : ""}>${l}</option>`;
          }).join("");
          field.innerHTML = `<label>${f.label}</label><select data-sec="${section}" data-key="${f.key}">${opts}</select>`;
        } else if (f.type === "secret") {
          field.innerHTML = `<label>${f.label}<span class="gen-hint">เว้นว่างเพื่อคงค่าเดิม</span></label>`;
          const wrap = document.createElement("div");
          wrap.className = "secret-input";
          const input = document.createElement("input");
          input.type = "password";
          input.autocomplete = "new-password";
          input.placeholder = String(values[`${f.key}_set`]) === "true" ? "ตั้งค่าแล้ว (เว้นว่างเพื่อคงเดิม)" : "ยังไม่ได้ตั้งค่า";
          input.dataset.sec = section;
          input.dataset.key = f.key;
          input.dataset.secret = "true";
          input.dataset.cleared = "false";
          const clear = document.createElement("button");
          clear.type = "button";
          clear.className = "small secret-clear";
          clear.textContent = "ล้าง";
          clear.addEventListener("click", () => {
            input.value = "";
            input.dataset.cleared = input.dataset.cleared === "true" ? "false" : "true";
            clear.classList.toggle("active", input.dataset.cleared === "true");
            clear.textContent = input.dataset.cleared === "true" ? "ยกเลิกการล้าง" : "ล้าง";
            markSettingsDirty();
          });
          wrap.appendChild(input);
          wrap.appendChild(clear);
          field.appendChild(wrap);
        } else if (f.type === "generic_logs") {
          field.innerHTML = `<label>${f.label}<span class="gen-hint">รายการละ ชื่อ=path|regex — คั่นหลายรายการด้วย ; ดูตัวอย่างใน GENERIC.md</span></label>`;
          const box = document.createElement("div");
          box.className = "gen-editor";
          box.innerHTML = `<input type="hidden" data-sec="${section}" data-key="${f.key}">`;
          field.appendChild(box);
          renderGenericEditor(box, values[f.key] || "");
        } else if (f.type === "notify_test") {
          field.innerHTML = `<label>${f.label}<span class="gen-hint">ต้องกด "บันทึกการตั้งค่า" ก่อน เพื่อให้ค่าที่ตั้งถูกโหลด</span></label>`;
          const box = document.createElement("div");
          box.className = "check";
          const btn = document.createElement("button");
          btn.type = "button";
          btn.textContent = "ส่งข้อความทดสอบ";
          const msg = document.createElement("span");
          msg.className = "gen-warn";
          msg.style.display = "none";
          btn.addEventListener("click", async () => {
            btn.disabled = true;
            msg.style.display = "";
            msg.style.color = "var(--muted)";
            msg.textContent = "กำลังส่ง...";
            try {
              const { data } = await api("/api/notify/test", { method: "POST", body: "{}", timeout: 60000 });
              const r = data.results || {};
              msg.style.color = "var(--ink-2)";
              msg.textContent = `Telegram: ${r.telegram || "-"} · Email: ${r.email || "-"} · Webhook: ${r.webhook || "-"}`;
            } catch (e) {
              msg.style.color = "var(--danger)";
              msg.textContent = e.message;
            }
            btn.disabled = false;
          });
          box.appendChild(btn);
          box.appendChild(msg);
          field.appendChild(box);
        } else if (f.type === "tg_status") {
          field.innerHTML = `<label>${f.label}<span class="gen-hint">คำสั่ง: /status /block /unblock /unblock-all /allow /blacklist /whitelist /list /events /log /ping /help</span></label>`;
          const node = document.createElement("span");
          node.className = "notify-status";
          node.dataset.tgStatus = "1";
          node.textContent = "กำลังโหลด...";
          field.appendChild(node);
          api("/api/telegram/status").then(({ data }) => {
            if (!node.isConnected) return;
            const parts = [data.enabled ? "เปิด" : "ปิด"];
            if (data.enabled) parts.push(data.running ? "polling ทำงาน" : "polling หยุด");
            if (data.last_command) parts.push("ล่าสุด: " + data.last_command + (data.last_result ? " → " + data.last_result.slice(0, 60) : ""));
            node.textContent = parts.join(" · ");
            node.className = "notify-status " + (data.enabled && data.running ? "ok" : "warn");
          }).catch(() => {
            if (node.isConnected) { node.textContent = "ตรวจสอบสถานะไม่ได้"; node.className = "notify-status warn"; }
          });
        } else if (f.type === "notify_status") {
          field.innerHTML = `<label>${f.label}</label><span class="notify-status" data-notify-status>กำลังโหลด...</span>`;
          api("/api/notify/status").then(({ data: status }) => {
            const node = field.querySelector("[data-notify-status]");
            if (!node) return;
            const last = Object.entries(status.last_result || {}).map(([key, value]) => `${key}: ${value}`).join(" · ");
            node.textContent = `${status.configured ? "ตั้งค่าแล้ว" : "ยังไม่พร้อม"}${last ? " · ล่าสุด: " + last : ""}`;
            node.className = "notify-status " + (status.configured ? "ok" : "warn");
          }).catch(() => {});
        } else {
          field.innerHTML = `<label>${f.label}</label><input type="text" data-sec="${section}" data-key="${f.key}" value="${esc(values[f.key] ?? "")}">`;
        }
        group.appendChild(field);
      }
      grid.appendChild(group);
    }
    window._settingsDirty = false;
    updateSettingsState();
  } catch (e) {}
}

function markSettingsDirty() {
  window._settingsDirty = true;
  updateSettingsState();
}

function updateSettingsState() {
  const msg = $("settings-dirty");
  if (msg) msg.textContent = window._settingsDirty ? "มีค่าที่ยังไม่ได้บันทึก" : "";
}

document.addEventListener("input", (event) => {
  if (event.target.matches("#settings-grid [data-sec][data-key]")) markSettingsDirty();
});
document.addEventListener("change", (event) => {
  if (event.target.matches("#settings-grid [data-sec][data-key]")) markSettingsDirty();
});

$("settings-save").addEventListener("click", async () => {
  const payload = {};
  document.querySelectorAll("[data-sec][data-key]").forEach((el) => {
    const sec = el.dataset.sec;
    const key = el.dataset.key;
    if (el.dataset.secret === "true" && !el.value.trim() && el.dataset.cleared !== "true") return;
    if (!payload[sec]) payload[sec] = {};
    if (el.type === "checkbox") payload[sec][key] = el.checked ? "true" : "false";
    else if (el.dataset.secret === "true" && el.dataset.cleared === "true") payload[sec][key] = "__CLEAR__";
    else payload[sec][key] = el.value.trim();
  });
  try {
    const { data } = await api("/api/settings", { method: "POST", body: JSON.stringify(payload) });
    const restart = data.restart_required?.length ? " ต้อง restart: " + data.restart_required.join(", ") : "";
    toast(data.message + restart, restart ? "" : "ok");
    $("settings-msg").textContent = "บันทึกแล้ว " + new Date().toLocaleTimeString("th-TH");
    refreshSettings();
  } catch (e) {
    toast(e.message, "error");
  }
});

$("backup-download").addEventListener("click", () => {
  window.location.href = "/api/backup";
});

$("backup-restore").addEventListener("click", () => $("backup-restore-file").click());
$("backup-restore-file").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  if (!confirm("กู้คืนฐานข้อมูลจากไฟล์นี้หรือไม่? โปรแกรมจะใช้ข้อมูลใหม่หลัง restart")) return;
  try {
    const response = await fetch("/api/backup/restore", {
      method: "POST",
      headers: { "Content-Type": "application/zip" },
      credentials: "same-origin",
      body: await file.arrayBuffer(),
    });
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || "กู้คืนไม่สำเร็จ");
    toast(data.data.message, "ok");
  } catch (e) {
    toast(e.message, "error");
  } finally {
    event.target.value = "";
  }
});

window.addEventListener("beforeunload", (event) => {
  if (!window._settingsDirty) return;
  event.preventDefault();
  event.returnValue = "มีการตั้งค่าที่ยังไม่ได้บันทึก";
});

init();
