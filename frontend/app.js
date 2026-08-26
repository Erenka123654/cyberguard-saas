const state = {
  token: localStorage.getItem("cg_token") || "",
  email: localStorage.getItem("cg_email") || "",
  role: localStorage.getItem("cg_role") || "CUSTOMER",
  org: localStorage.getItem("cg_org") || "",
  domains: [],
  scans: [],
  details: []
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  let res;
  try {
    res = await fetch(API_BASE + path, {
      ...options,
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
  } catch {
    throw new Error("API'ye ulaşılamadı. Cloudflare Worker ve API_BASE değerini kontrol edin.");
  }

  if (res.status === 401 && path !== "/api/auth/login" && path !== "/api/auth/register") {
    logout();
    throw new Error("Oturum geçersiz veya süresi dolmuş.");
  }

  if (!res.ok) {
    let message = `İstek başarısız (${res.status})`;
    try {
      const data = await res.json();
      if (data.error) message = data.error;
    } catch {}
    throw new Error(message);
  }

  if (options.blob) return res.blob();
  if (res.status === 204) return null;
  return res.json();
}

function showAuth(mode = "login") {
  $("authscreen").classList.remove("hidden");
  $("appRoot").classList.add("hidden");
  $("authRegisterFields").classList.toggle("hidden", mode !== "register");
  $("authTitle").textContent = mode === "login" ? "CyberGuard'a giriş yap" : "CyberGuard hesabı oluştur";
  $("authSubtitle").textContent = mode === "login"
    ? "Güvenlik paneline erişmek için bilgilerinizi girin."
    : "Organizasyonunuzu oluşturup taramaya başlayın.";
  $("authSubmit").textContent = mode === "login" ? "Giriş yap" : "Hesap oluştur";
  $("authSwitchLink").textContent = mode === "login" ? "Hesap oluştur" : "Giriş yap";
  $("authSwitchLink").dataset.mode = mode === "login" ? "register" : "login";
  $("authError").classList.add("hidden");
}

function logout() {
  state.token = "";
  localStorage.removeItem("cg_token");
  localStorage.removeItem("cg_email");
  localStorage.removeItem("cg_role");
  localStorage.removeItem("cg_org");
  showAuth("login");
}

$("authSwitchLink").onclick = () => showAuth($("authSwitchLink").dataset.mode || "register");
$("logoutBtn").onclick = logout;

$("authSubmit").onclick = async () => {
  const mode = $("authSwitchLink").dataset.mode === "login" ? "register" : "login";
  const email = $("authEmail").value.trim();
  const password = $("authPassword").value;
  const organization = $("authOrg").value.trim();

  if (!email || !password || (mode === "register" && !organization)) {
    $("authError").textContent = "Lütfen gerekli alanları doldurun.";
    $("authError").classList.remove("hidden");
    return;
  }

  $("authSubmit").disabled = true;
  try {
    const data = await api(`/api/auth/${mode}`, {
      method: "POST",
      body: mode === "login" ? { email, password } : { email, password, organization }
    });
    state.token = data.access_token;
    state.email = email;
    state.role = data.role || "CUSTOMER";
    state.org = data.organization || organization || "";
    localStorage.setItem("cg_token", state.token);
    localStorage.setItem("cg_email", state.email);
    localStorage.setItem("cg_role", state.role);
    localStorage.setItem("cg_org", state.org);
    await enterApp();
  } catch (e) {
    $("authError").textContent = e.message;
    $("authError").classList.remove("hidden");
  } finally {
    $("authSubmit").disabled = false;
  }
};

async function enterApp() {
  $("authscreen").classList.add("hidden");
  $("appRoot").classList.remove("hidden");
  $("userEmail").textContent = state.email;
  await loadAll();
}

async function loadAll() {
  try {
    [state.domains, state.scans] = await Promise.all([
      api("/api/domains"),
      api("/api/scans")
    ]);
    const recent = state.scans.slice(0, 5);
    state.details = (await Promise.all(
      recent.map(s => api(`/api/scans/${s.id}`).catch(() => null))
    )).filter(Boolean);
    render();
  } catch (e) {
    if (!state.token) return;
    alert(e.message);
  }
}

function fmtDate(v) {
  if (!v) return "—";
  return new Date(v).toLocaleString("tr-TR");
}

function badge(status) {
  const cls = status === "completed" ? "green" : status === "running" ? "yellow" : "red";
  return `<span class="badge ${cls}">${status}</span>`;
}

function render() {
  $("statDomains").textContent = state.domains.length;
  $("statScans").textContent = state.scans.length;
  const scored = state.scans.filter(s => s.score != null);
  $("statScore").textContent = scored.length
    ? Math.round(scored.reduce((a, s) => a + Number(s.score), 0) / scored.length)
    : "—";
  $("statFindings").textContent = state.scans.reduce((a, s) => a + Number(s.findings_count || 0), 0);

  $("scanTable").innerHTML = state.scans.slice(0, 8).map(s =>
    `<tr><td><b>${escapeHtml(s.domain)}</b></td><td>${badge(s.status)}</td><td>${s.score ?? "—"}</td><td>${s.findings_count ?? 0}</td><td>${fmtDate(s.completed_at || s.started_at)}</td></tr>`
  ).join("") || `<tr><td colspan="5">Henüz tarama yok.</td></tr>`;

  $("domainTable").innerHTML = state.domains.map(d =>
    `<tr><td><b>${escapeHtml(d.domain)}</b></td><td><span class="badge green">Authorized</span></td><td>${fmtDate(d.created_at)}</td><td><button class="ghost" onclick="scanDomain(${d.id})">Tara</button></td></tr>`
  ).join("") || `<tr><td colspan="4">Henüz domain eklenmedi.</td></tr>`;

  $("allScanTable").innerHTML = state.scans.map(s =>
    `<tr><td>${escapeHtml(s.domain)}</td><td>${badge(s.status)}</td><td>${s.score ?? "—"}</td><td>${s.findings_count ?? 0}</td><td>${fmtDate(s.completed_at || s.started_at)}</td><td><button class="ghost" onclick="downloadReport(${s.id})">PDF</button></td></tr>`
  ).join("") || `<tr><td colspan="6">Henüz tarama yok.</td></tr>`;

  const findings = state.details.flatMap(d => (d.findings || []).map(f => ({...f, domain: d.domain, scanId: d.id})));
  $("findingsList").innerHTML = findings.map(f =>
    `<article class="finding">
      <button class="download" onclick="downloadReport(${f.scanId})">PDF</button>
      <b>${escapeHtml(f.title)}</b>
      <small>${escapeHtml(f.domain)} · ${escapeHtml(f.severity)}</small>
      <p>${escapeHtml(f.description)}</p>
      <small><strong>Çözüm:</strong> ${escapeHtml(f.remediation)}</small>
    </article>`
  ).join("") || `<div class="card panel">Henüz güvenlik bulgusu yok.</div>`;

  renderAdmin();
}

async function addDomain() {
  const domain = $("domainInput").value.trim();
  const authorized = $("domainAuthorized").checked;
  if (!domain || !authorized) {
    alert("Domain ve yetkilendirme onayı gerekli.");
    return;
  }
  try {
    await api("/api/domains", { method: "POST", body: { domain, authorized } });
    $("domainInput").value = "";
    $("domainAuthorized").checked = false;
    await loadAll();
  } catch (e) { alert(e.message); }
}

async function scanDomain(id) {
  try {
    await api("/api/scans", { method: "POST", body: { domain_id: Number(id) } });
    await loadAll();
    showPage("scans");
  } catch (e) { alert(e.message); }
}

async function downloadReport(id) {
  try {
    const blob = await api(`/api/reports/${id}.pdf`, { blob: true });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberguard-${id}.pdf`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { alert(e.message); }
}

$("addDomain").onclick = addDomain;

function renderAdmin() {
  if (!["ADMIN", "SUPER_ADMIN"].includes(state.role)) {
    $("adminBox").innerHTML = `<div class="card panel">Admin yetkisi gerekli.</div>`;
    return;
  }
  api("/api/admin/overview").then(x => {
    $("adminBox").innerHTML = Object.entries(x).map(([k,v]) =>
      `<div class="stat"><span>${escapeHtml(k)}</span><strong>${v}</strong></div>`
    ).join("");
  }).catch(e => $("adminBox").innerHTML = `<div class="card panel">${escapeHtml(e.message)}</div>`);
}

function showPage(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
  document.querySelector(`#page-${name}`).classList.remove("hidden");
  document.querySelectorAll(".nav").forEach(b => b.classList.toggle("active", b.dataset.page === name));
}

document.querySelectorAll(".nav").forEach(btn => btn.onclick = () => showPage(btn.dataset.page));

function escapeHtml(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

(async function boot() {
  try {
    const h = await fetch(API_BASE + "/health");
    $("apiStatus").textContent = h.ok ? "Cloudflare API bağlantısı hazır." : "API health kontrolü başarısız.";
  } catch {
    $("apiStatus").textContent = "API'ye ulaşılamıyor.";
  }
  if (state.token) {
    try { await api("/api/auth/me"); await enterApp(); }
    catch { logout(); }
  } else {
    showAuth("login");
  }
})();
