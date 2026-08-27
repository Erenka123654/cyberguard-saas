/* CyberGuard frontend — API_BASE değeri config.js içinde tanımlı. */

const state = {
  token: localStorage.getItem("cg_token") || null,
  email: localStorage.getItem("cg_email") || "",
  org: localStorage.getItem("cg_org") || "",
  role: localStorage.getItem("cg_role") || "CUSTOMER",
  domains: [],
  scans: [],
  scanDetails: [], // en son tamamlanan taramaların tam bulgu listesi (son 5)
};

/* ---------- API yardımcı fonksiyonu ---------- */
async function api(path, { method = "GET", body, isBlob = false } = {}) {
  const headers = {};
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(API_BASE + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error("Sunucuya ulaşılamadı. API_BASE (config.js) doğru mu ve backend çalışıyor mu kontrol et.");
  }
  if (res.status === 401) {
    logout();
    throw new Error("Oturum süresi doldu, tekrar giriş yap.");
  }
  if (!res.ok) {
    let msg = "İstek başarısız oldu (" + res.status + ").";
    try {
      const j = await res.json();
      if (j.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch (e) {}
    throw new Error(msg);
  }
  if (isBlob) return res.blob();
  if (res.status === 204) return null;
  return res.json();
}

/* ---------- Toast ---------- */
let toastTimer;
function toast(msg, isError) {
  clearTimeout(toastTimer);
  let el = document.querySelector(".toast");
  if (!el) {
    el = document.createElement("div");
    el.className = "toast";
    document.body.appendChild(el);
  }
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = msg;
  toastTimer = setTimeout(() => el.remove(), 3500);
}

/* ---------- Auth ekranı ---------- */
const authscreen = document.getElementById("authscreen");
const appRoot = document.getElementById("appRoot");
let authMode = "login"; // veya "register"

const authTitle = document.getElementById("authTitle");
const authSubtitle = document.getElementById("authSubtitle");
const authRegisterFields = document.getElementById("authRegisterFields");
const authSubmit = document.getElementById("authSubmit");
const authError = document.getElementById("authError");
const authSwitchText = document.getElementById("authSwitchText");
const authSwitchLink = document.getElementById("authSwitchLink");

function setAuthMode(mode) {
  authMode = mode;
  authError.classList.add("hidden");
  if (mode === "login") {
    authTitle.textContent = "Sign in to CyberGuard";
    authSubtitle.textContent = "Enter your credentials to access your security dashboard.";
    authRegisterFields.classList.add("hidden");
    authSubmit.textContent = "Sign in";
    authSwitchText.textContent = "Don't have an account?";
    authSwitchLink.textContent = "Create one";
  } else {
    authTitle.textContent = "Create your CyberGuard account";
    authSubtitle.textContent = "Set up your organization to start scanning.";
    authRegisterFields.classList.remove("hidden");
    authSubmit.textContent = "Create account";
    authSwitchText.textContent = "Already have an account?";
    authSwitchLink.textContent = "Sign in";
  }
}
authSwitchLink.onclick = () => setAuthMode(authMode === "login" ? "register" : "login");

authSubmit.onclick = async () => {
  const email = document.getElementById("authEmail").value.trim();
  const password = document.getElementById("authPassword").value;
  const organization = document.getElementById("authOrg").value.trim();
  authError.classList.add("hidden");

  if (!email || !password || (authMode === "register" && !organization)) {
    authError.textContent = "Lütfen tüm alanları doldur.";
    authError.classList.remove("hidden");
    return;
  }

  authSubmit.disabled = true;
  authSubmit.textContent = authMode === "login" ? "Signing in…" : "Creating…";
  try {
    let data;
    if (authMode === "login") {
      data = await api("/api/auth/login", { method: "POST", body: { email, password } });
    } else {
      data = await api("/api/auth/register", {
        method: "POST",
        body: { email, password, organization },
      });
    }
    state.token = data.access_token;
    state.email = email;
    state.role = data.role || "CUSTOMER";
    if (authMode === "register") state.org = organization;
    localStorage.setItem("cg_token", state.token);
    localStorage.setItem("cg_email", state.email);
    localStorage.setItem("cg_role", state.role);
    if (state.org) localStorage.setItem("cg_org", state.org);
    await enterApp();
  } catch (e) {
    authError.textContent = e.message;
    authError.classList.remove("hidden");
  } finally {
    authSubmit.disabled = false;
    setAuthMode(authMode);
  }
};

function logout() {
  state.token = null;
  localStorage.removeItem("cg_token");
  authscreen.classList.remove("hidden");
  appRoot.classList.add("hidden");
}
document.getElementById("logoutBtn").onclick = logout;

/* ---------- Uygulamaya giriş ---------- */
async function enterApp() {
  authscreen.classList.add("hidden");
  appRoot.classList.remove("hidden");
  document.getElementById("orgName").textContent = state.org || "My Organization";
  document.getElementById("userEmail").textContent = state.email || "—";
  document.getElementById("userRole").textContent =
    state.role === "ADMIN" || state.role === "SUPER_ADMIN" ? "Administrator" : "Customer";
  document.getElementById("userInitials").textContent = (state.email || "??").slice(0, 2).toUpperCase();
  await loadAll();
}

async function loadAll() {
  try {
    [state.domains, state.scans] = await Promise.all([api("/api/domains"), api("/api/scans")]);
  } catch (e) {
    toast(e.message, true);
    return;
  }
  const recentCompleted = state.scans.filter((s) => s.status === "completed").slice(0, 5);
  state.scanDetails = (
    await Promise.all(recentCompleted.map((s) => api("/api/scans/" + s.id).catch(() => null)))
  ).filter(Boolean);

  renderDomains();
  renderScansPage();
  renderDashboard();
  renderFindings();
  renderReports();
  renderAdmin();
}

/* ---------- Yardımcılar ---------- */
function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString("tr-TR", { day: "2-digit", month: "short" }) +
    ", " + d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
}
function statusBadge(status) {
  if (status === "completed") return '<span class="badge green">Completed</span>';
  if (status === "running") return '<span class="badge yellow">Running</span>';
  return '<span class="badge yellow">' + status + "</span>";
}
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const SEV_CLASS = { CRITICAL: "crit", HIGH: "highbg", MEDIUM: "highbg", LOW: "highbg" };

/* ---------- Dashboard ---------- */
function renderDashboard() {
  const latest = state.scans[0];
  const scoreEl = document.getElementById("dashScore");
  const ring = document.getElementById("dashRing");
  const wordEl = document.getElementById("dashScoreWord");
  const descEl = document.getElementById("dashScoreDesc");
  const lastScanEl = document.getElementById("dashLastScan");

  if (latest && latest.score != null) {
    scoreEl.textContent = latest.score;
    ring.style.background = `conic-gradient(#3b82f6 0 ${latest.score}%, #1b283c ${latest.score}%)`;
    wordEl.textContent = latest.score >= 80 ? "Good" : latest.score >= 50 ? "Needs attention" : "Poor";
    descEl.textContent = latest.domain + " için son tarama sonucu.";
    lastScanEl.textContent = fmtDate(latest.completed_at || latest.started_at);
  } else {
    scoreEl.textContent = "–";
    ring.style.background = "#1b283c";
    wordEl.textContent = "—";
    descEl.textContent = "Henüz tamamlanmış tarama yok.";
    lastScanEl.textContent = "—";
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  state.scanDetails.forEach((d) => (d.findings || []).forEach((f) => {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }));
  document.getElementById("cntCritical").textContent = counts.CRITICAL;
  document.getElementById("cntHigh").textContent = counts.HIGH;
  document.getElementById("cntMedium").textContent = counts.MEDIUM;
  document.getElementById("cntLow").textContent = counts.LOW;

  const totalFindings = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  const notice = document.getElementById("dashNotice");
  if (totalFindings > 0) {
    notice.classList.remove("hidden");
    document.getElementById("dashNoticeText").textContent =
      totalFindings + " security finding" + (totalFindings > 1 ? "s" : "") + " require your attention";
  } else {
    notice.classList.add("hidden");
  }

  // Posture: son taramaların skor ortalamasını "secure" yüzdesi olarak kullan
  const scored = state.scans.filter((s) => s.score != null);
  const avg = scored.length ? Math.round(scored.reduce((a, s) => a + s.score, 0) / scored.length) : 0;
  document.getElementById("postureScore").textContent = (scored.length ? avg : "—") + "%";
  document.getElementById("postureBar").style.width = avg + "%";
  const critPct = totalFindings ? Math.round((counts.CRITICAL / totalFindings) * 100) : 0;
  const attnPct = totalFindings ? Math.round(((counts.HIGH + counts.MEDIUM) / totalFindings) * 100) : 0;
  const securePct = Math.max(0, 100 - critPct - attnPct);
  document.getElementById("postureSecure").textContent = securePct + "%";
  document.getElementById("postureAttention").textContent = attnPct + "%";
  document.getElementById("postureCritical").textContent = critPct + "%";

  // Basit çizgi grafik: son 8 tamamlanmış taramanın skoru
  const points = scored.slice(0, 8).reverse();
  const svg = document.getElementById("scoreChart");
  const dates = document.getElementById("scoreChartDates");
  if (points.length >= 2) {
    const w = 700, h = 250, step = w / (points.length - 1);
    const coords = points.map((s, i) => [Math.round(i * step), Math.round(h - (s.score / 100) * (h - 30) - 10)]);
    const line = coords.map((c) => c.join(" ")).join(" L ");
    const fillPath = `M ${line} L ${w} ${h} L 0 ${h} Z`;
    const curvePath = `M ${line}`;
    svg.innerHTML = `<path class="fill" d="${fillPath}"/><path class="curve" d="${curvePath}"/>`;
    dates.innerHTML = points.map((s) => `<span>${fmtDate(s.completed_at).split(",")[0]}</span>`).join("");
  } else {
    svg.innerHTML = "";
    dates.innerHTML = "<span>Grafik için en az 2 tamamlanmış tarama gerekli</span>";
  }

  const recent = state.scans.slice(0, 5);
  document.getElementById("dashRecentScans").innerHTML = recent.length
    ? recent
        .map(
          (s) =>
            `<tr><td><b>${s.domain}</b></td><td>${statusBadge(s.status)}</td><td>${
              s.score ?? "—"
            }</td><td>${s.findings_count ?? 0}</td><td>${fmtDate(s.completed_at || s.started_at)}</td></tr>`
        )
        .join("")
    : '<tr><td colspan="5" class="empty">Henüz tarama yok — "New Scan" ile başla.</td></tr>';

  document.getElementById("navDomainsCount").textContent = state.domains.length;
}

/* ---------- Domains ---------- */
function renderDomains() {
  const body = document.getElementById("domainsBody");
  body.innerHTML = state.domains.length
    ? state.domains
        .map(
          (d) => `<tr>
        <td><b>${d.domain}</b></td>
        <td>${d.authorized ? '<span class="badge green">● Authorized</span>' : '<span class="badge yellow">● Pending</span>'}</td>
        <td>${fmtDate(d.created_at)}</td>
        <td><button class="small" data-scan-domain="${d.id}">Scan</button></td>
      </tr>`
        )
        .join("")
    : '<tr><td colspan="4" class="empty">Henüz domain eklenmedi.</td></tr>';

  body.querySelectorAll("[data-scan-domain]").forEach((btn) => {
    btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = "…";
      try {
        await api("/api/scans", { method: "POST", body: { domain_id: Number(btn.dataset.scanDomain) } });
        toast("Tarama tamamlandı.");
        await loadAll();
      } catch (e) {
        toast(e.message, true);
        btn.disabled = false;
        btn.textContent = "Scan";
      }
    };
  });
}

/* ---------- Scans ---------- */
function renderScansPage() {
  const body = document.getElementById("scansBody");
  body.innerHTML = state.scans.length
    ? state.scans
        .map(
          (s) =>
            `<tr><td><b>${s.domain}</b></td><td>${statusBadge(s.status)}</td><td>${
              s.score ?? "—"
            }</td><td>${s.findings_count ?? 0}</td><td>${fmtDate(s.completed_at || s.started_at)}</td></tr>`
        )
        .join("")
    : '<tr><td colspan="5" class="empty">Henüz tarama yok.</td></tr>';

  document.getElementById("statTotalScans").textContent = state.scans.length;
  const scored = state.scans.filter((s) => s.score != null);
  document.getElementById("statAvgScore").textContent = scored.length
    ? (scored.reduce((a, s) => a + s.score, 0) / scored.length).toFixed(1)
    : "—";
  document.getElementById("statLastScan").textContent = state.scans.length
    ? fmtDate(state.scans[0].completed_at || state.scans[0].started_at)
    : "—";
}

/* ---------- Findings ---------- */
function renderFindings() {
  const el = document.getElementById("findingsBody");
  const rows = [];
  state.scanDetails.forEach((d) => {
    (d.findings || []).forEach((f) => rows.push({ ...f, domain: d.domain, when: d.completed_at }));
  });
  rows.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  document.getElementById("navFindingsCount").textContent = rows.length;

  el.innerHTML = rows.length
    ? rows
        .map(
          (f) => `<div class="finding card">
        <span class="severity ${SEV_CLASS[f.severity] || "highbg"}">${f.severity}</span>
        <div><h3>${f.title}</h3><p>${f.description || ""}</p><small>${f.domain} · ${fmtDate(f.when)}</small></div>
        <b>→</b>
      </div>`
        )
        .join("")
    : '<p class="empty">Harika — herhangi bir bulgu yok. Yeni bir tarama başlatarak kontrol edebilirsin.</p>';
}

/* ---------- Reports ---------- */
function renderReports() {
  const el = document.getElementById("reportsBody");
  const completed = state.scans.filter((s) => s.status === "completed");
  el.innerHTML = completed.length
    ? completed
        .map(
          (s) => `<div class="report card">
        <div class="pdf">PDF</div>
        <div><h3>${s.domain} — Security Assessment</h3><p>${fmtDate(s.completed_at)} · Score ${s.score ?? "—"}/100</p></div>
        <button class="small" data-download="${s.id}" data-domain="${s.domain}">Download</button>
      </div>`
        )
        .join("")
    : '<p class="empty">Henüz indirilebilir rapor yok.</p>';

  el.querySelectorAll("[data-download]").forEach((btn) => {
    btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = "…";
      try {
        const blob = await api("/api/reports/" + btn.dataset.download + ".pdf", { isBlob: true });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cyberguard-${btn.dataset.domain}-${btn.dataset.download}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } catch (e) {
        toast(e.message, true);
      } finally {
        btn.disabled = false;
        btn.textContent = "Download";
      }
    };
  });
}

/* ---------- Admin ---------- */
async function renderAdmin() {
  const el = document.getElementById("adminBody");
  try {
    const overview = await api("/api/admin/overview");
    el.innerHTML = `<div class="mini">
      <div class="card"><span>USERS</span><strong>${overview.users}</strong></div>
      <div class="card"><span>DOMAINS</span><strong>${overview.domains}</strong></div>
      <div class="card"><span>SCANS</span><strong>${overview.scans}</strong></div>
    </div>`;
  } catch (e) {
    el.innerHTML = '<p class="empty">Bu hesabın admin paneline erişimi yok (ADMIN/SUPER_ADMIN rolü gerekir).</p>';
  }
}

/* ---------- Settings (salt okunur — backend henüz desteklemiyor) ---------- */
function renderSettingsStatic() {
  document.getElementById("settingsOrg").value = state.org || "—";
  document.getElementById("settingsEmail").value = state.email || "—";
}

/* ---------- Yeni tarama modalı ---------- */
const modal = document.getElementById("modal");
document.querySelectorAll(".newscan").forEach((x) => (x.onclick = () => modal.classList.remove("hidden")));
document.querySelector(".close").onclick = () => modal.classList.add("hidden");
modal.onclick = (e) => {
  if (e.target === modal) modal.classList.add("hidden");
};

document.getElementById("start").onclick = async () => {
  const domainInput = document.getElementById("domain");
  const authorizedInput = document.getElementById("authorized");
  const statusEl = document.getElementById("status");
  const startBtn = document.getElementById("start");
  const domain = domainInput.value.trim();
  const authorized = authorizedInput.checked;

  if (!domain || !authorized) {
    statusEl.textContent = "Domain ve yetki onayı gereklidir.";
    return;
  }

  startBtn.disabled = true;
  statusEl.textContent = "Taranıyor…";
  try {
    let existing = state.domains.find((d) => d.domain === domain.toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, ""));
    let domainId;
    if (existing) {
      domainId = existing.id;
    } else {
      const added = await api("/api/domains", { method: "POST", body: { domain, authorized: true } });
      domainId = added.id;
    }
    await api("/api/scans", { method: "POST", body: { domain_id: domainId } });
    statusEl.textContent = "Tarama tamamlandı ✓";
    await loadAll();
    setTimeout(() => {
      modal.classList.add("hidden");
      domainInput.value = "";
      authorizedInput.checked = false;
      statusEl.textContent = "";
    }, 700);
  } catch (e) {
    statusEl.textContent = e.message;
  } finally {
    startBtn.disabled = false;
  }
};

/* ---------- Sayfa gezinme ---------- */
const pages = [...document.querySelectorAll(".page")];
const nav = [...document.querySelectorAll("nav a")];
const title = document.getElementById("title");
function showPage(id) {
  pages.forEach((p) => p.classList.toggle("hidden", p.id !== id));
  nav.forEach((n) => n.classList.toggle("active", n.dataset.page === id));
  title.textContent = id[0].toUpperCase() + id.slice(1);
  if (id === "settings") renderSettingsStatic();
  window.scrollTo(0, 0);
}
nav.forEach((n) => (n.onclick = () => showPage(n.dataset.page)));
document.querySelectorAll("[data-go]").forEach((x) => (x.onclick = () => showPage(x.dataset.go)));
document.querySelector(".mobile-menu").onclick = () => document.querySelector(".sidebar").classList.toggle("open");

/* ---------- Başlangıç ---------- */
(async function init() {
  if (state.token) {
    try {
      await enterApp();
    } catch (e) {
      logout();
    }
  } else {
    authscreen.classList.remove("hidden");
    appRoot.classList.add("hidden");
  }
})();
