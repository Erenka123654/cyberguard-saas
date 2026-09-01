/**
 * CyberGuard API - Cloudflare Worker (all-in-one, no external backend)
 *
 * Frontend -> Cloudflare Worker -> D1
 *
 * Bu dosya eskiden Railway'deki FastAPI backend'ine proxy yapıyordu.
 * Artık auth, domains, scans, reports, admin uçlarının hepsi burada,
 * D1 üzerinde çalışıyor. Railway/FastAPI'ye ihtiyaç yok.
 */

const ALLOWED_ORIGINS = [
  "https://erenka123654.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const HEADER_CHECKS = {
  "strict-transport-security": ["HIGH", 10],
  "content-security-policy": ["MEDIUM", 6],
  "x-content-type-options": ["LOW", 3],
  "x-frame-options": ["LOW", 3],
  "referrer-policy": ["LOW", 2],
};

/* ------------------------------------------------------------------ */
/* CORS                                                                */
/* ------------------------------------------------------------------ */

function corsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin),
    },
  });
}

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/* ------------------------------------------------------------------ */
/* Password hashing (PBKDF2-SHA256 via Web Crypto)                    */
/* ------------------------------------------------------------------ */

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuf(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return `pbkdf2$${iterations}$${bufToHex(salt)}$${bufToHex(bits)}`;
}

async function verifyPassword(password, stored) {
  const parts = (stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const salt = hexToBuf(parts[2]);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return bufToHex(bits) === parts[3];
}

/* ------------------------------------------------------------------ */
/* JWT (HS256 via Web Crypto)                                         */
/* ------------------------------------------------------------------ */

function b64url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecodeToBuf(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

async function signJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) throw new ApiError(401, "Invalid or expired token");
  const [header, body, sig] = parts;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("HMAC", key, b64urlDecodeToBuf(sig), new TextEncoder().encode(`${header}.${body}`));
  if (!valid) throw new ApiError(401, "Invalid or expired token");
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecodeToBuf(body)));
  if (payload.exp && Date.now() / 1000 > payload.exp) throw new ApiError(401, "Invalid or expired token");
  return payload;
}

function createToken(userId, role, secret) {
  return signJWT({ sub: String(userId), role, exp: Math.floor(Date.now() / 1000) + 12 * 3600 }, secret);
}

async function requireUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) throw new ApiError(401, "Authentication required");
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  return { id: parseInt(payload.sub, 10), role: payload.role };
}

/* ------------------------------------------------------------------ */
/* Rate limiting (D1-backed, per IP + action)                         */
/* ------------------------------------------------------------------ */

async function rateLimit(db, keyPrefix, ip, maxAttempts, windowSeconds) {
  const key = `${keyPrefix}:${ip || "unknown"}`;
  const now = Date.now();
  await db.prepare("DELETE FROM rate_limits WHERE key = ? AND created_at < ?").bind(key, now - windowSeconds * 1000).run();
  const row = await db.prepare("SELECT COUNT(*) AS n FROM rate_limits WHERE key = ?").bind(key).first();
  if ((row?.n || 0) >= maxAttempts) throw new ApiError(429, "Too many attempts. Please try again later.");
  await db.prepare("INSERT INTO rate_limits (key, created_at) VALUES (?, ?)").bind(key, now).run();
}

/* ------------------------------------------------------------------ */
/* DNS (over HTTPS) + SSRF guard + scanner                            */
/* ------------------------------------------------------------------ */

async function dohQuery(domain, type) {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
    });
    const data = await res.json();
    return (data.Answer || []).map((a) => a.data);
  } catch {
    return [];
  }
}

function isUnsafeIP(ip) {
  if (!ip) return false;
  if (ip.includes(":")) {
    const l = ip.toLowerCase();
    return l === "::1" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80");
  }
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(Number.isNaN)) return false;
  const [a, b] = p;
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

async function scanDomain(domain) {
  const dns = {};
  for (const type of ["A", "AAAA", "MX", "TXT", "NS"]) dns[type] = await dohQuery(domain, type);
  const ip = dns.A[0] || null;

  if (ip && isUnsafeIP(ip)) {
    return {
      domain, ip: null, http_status: null, dns,
      findings: [{
        severity: "CRITICAL", title: "Unsafe scan target",
        description: "This domain resolves to a private, loopback, or reserved IP address and cannot be scanned.",
        remediation: "Only public, internet-facing domains can be scanned.",
      }],
      score: 0,
    };
  }

  const findings = [];
  let status = null;
  let headers = {};
  try {
    let currentUrl = `https://${domain}`;
    let response = null;
    for (let hop = 0; hop < 6; hop++) {
      response = await fetch(currentUrl, { redirect: "manual" });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) break;
        currentUrl = new URL(location, currentUrl).toString();
        const hopIps = await dohQuery(new URL(currentUrl).hostname, "A");
        if (hopIps[0] && isUnsafeIP(hopIps[0])) {
          throw new Error("unsafe-redirect");
        }
        continue;
      }
      break;
    }
    status = response.status;
    response.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
  } catch (e) {
    if (e.message === "unsafe-redirect") {
      findings.push({ severity: "CRITICAL", title: "Unsafe redirect target", description: "Redirect pointed to a private/internal address.", remediation: "Scan blocked to prevent SSRF via redirect." });
    } else {
      findings.push({ severity: "HIGH", title: "HTTPS connection could not be verified", description: String(e.message || e), remediation: "Verify DNS, TLS and HTTPS availability." });
    }
  }

  for (const [key, [severity]] of Object.entries(HEADER_CHECKS)) {
    if (!headers[key]) {
      findings.push({ severity, title: `Missing ${key} header`, description: `${key} was not present in the HTTPS response.`, remediation: `Configure an appropriate ${key} policy.` });
    }
  }

  const weights = { CRITICAL: 25, HIGH: 10, MEDIUM: 6, LOW: 2 };
  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0));
  return { domain, ip, http_status: status, dns, findings, score };
}

/* ------------------------------------------------------------------ */
/* Minimal PDF writer (single page, Helvetica, no external library)   */
/* ------------------------------------------------------------------ */

function escapePdfText(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function buildReportPdf(domain, score, findings) {
  const lines = [`CyberGuard Security Assessment`, `Domain: ${domain}`, `Security Score: ${score}/100`, ``, `Findings`];
  for (const f of findings) lines.push(`[${f.severity}] ${f.title}`.slice(0, 105));

  let content = "";
  let y = 780;
  lines.forEach((line, i) => {
    const size = i === 0 ? 18 : i === 4 ? 13 : 10;
    content += `BT /F1 ${size} Tf 1 0 0 1 50 ${y} Tm (${escapePdfText(line)}) Tj ET\n`;
    y -= i === 0 ? 30 : 16;
  });

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${content.length} >>\nstream\n${content}endstream`,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets = [];
  objects.forEach((obj, idx) => {
    offsets.push(pdf.length);
    pdf += `${idx + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xrefStart = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.forEach((off) => (pdf += `${String(off).padStart(10, "0")} 00000 n \n`));
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return new TextEncoder().encode(pdf);
}

/* ------------------------------------------------------------------ */
/* Route handlers                                                     */
/* ------------------------------------------------------------------ */

async function handleRegister(request, env, origin) {
  const data = await request.json().catch(() => ({}));
  const email = String(data.email || "").trim().toLowerCase();
  const password = String(data.password || "");
  const organization = String(data.organization || "").trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(422, "Invalid email");
  if (password.length < 8) throw new ApiError(422, "Password must be at least 8 characters");
  if (organization.length < 2 || organization.length > 120) throw new ApiError(422, "Invalid organization name");

  await rateLimit(env.DB, "register", request.headers.get("CF-Connecting-IP"), 5, 60);

  const orgResult = await env.DB.prepare("INSERT INTO organizations (name) VALUES (?)").bind(organization).run();
  const orgId = orgResult.meta.last_row_id;

  try {
    const userResult = await env.DB.prepare(
      "INSERT INTO users (organization_id, email, password_hash, role) VALUES (?, ?, ?, 'CUSTOMER')"
    ).bind(orgId, email, await hashPassword(password)).run();
    const userId = userResult.meta.last_row_id;
    return json({ access_token: await createToken(userId, "CUSTOMER", env.JWT_SECRET), token_type: "bearer" }, 200, origin);
  } catch {
    throw new ApiError(400, "Email may already be registered.");
  }
}

async function handleLogin(request, env, origin) {
  const data = await request.json().catch(() => ({}));
  const email = String(data.email || "").trim().toLowerCase();
  const password = String(data.password || "");

  await rateLimit(env.DB, "login", request.headers.get("CF-Connecting-IP"), 8, 60);

  const row = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (!row || !(await verifyPassword(password, row.password_hash))) throw new ApiError(401, "Invalid email or password");

  return json({ access_token: await createToken(row.id, row.role, env.JWT_SECRET), token_type: "bearer", role: row.role }, 200, origin);
}

async function handleAddDomain(request, env, origin) {
  const user = await requireUser(request, env);
  const data = await request.json().catch(() => ({}));
  let domain = String(data.domain || "").trim().toLowerCase();
  if (domain.includes("://")) domain = new URL(domain).hostname;
  domain = domain.replace(/\/$/, "");

  if (!data.authorized) throw new ApiError(403, "Authorization confirmation is required.");
  if (!domain || domain.includes("/") || domain.includes(" ")) throw new ApiError(422, "Invalid domain");

  const org = await env.DB.prepare("SELECT organization_id FROM users WHERE id = ?").bind(user.id).first();
  const result = await env.DB.prepare("INSERT INTO domains (organization_id, domain, authorized) VALUES (?, ?, 1)").bind(org.organization_id, domain).run();

  return json({ message: "Domain added", domain, id: result.meta.last_row_id }, 200, origin);
}

async function handleDeleteDomain(request, env, origin, domainId) {
  const user = await requireUser(request, env);
  const org = await env.DB.prepare("SELECT organization_id FROM users WHERE id = ?").bind(user.id).first();

  const row = await env.DB.prepare("SELECT id FROM domains WHERE id = ? AND organization_id = ?").bind(domainId, org.organization_id).first();
  if (!row) throw new ApiError(404, "Domain not found");

  const scanIds = await env.DB.prepare("SELECT id FROM scans WHERE domain_id = ?").bind(domainId).all();
  for (const s of scanIds.results) {
    await env.DB.prepare("DELETE FROM scans WHERE id = ?").bind(s.id).run();
  }
  await env.DB.prepare("DELETE FROM domains WHERE id = ?").bind(domainId).run();

  return json({ message: "Domain deleted", id: domainId }, 200, origin);
}

async function handleListDomains(request, env, origin) {
  const user = await requireUser(request, env);
  const org = await env.DB.prepare("SELECT organization_id FROM users WHERE id = ?").bind(user.id).first();
  const { results } = await env.DB.prepare("SELECT id, domain, authorized, created_at FROM domains WHERE organization_id = ?").bind(org.organization_id).all();
  return json(results, 200, origin);
}

async function handleStartScan(request, env, origin) {
  const user = await requireUser(request, env);
  const data = await request.json().catch(() => ({}));
  const domainId = parseInt(data.domain_id, 10);

  const row = await env.DB.prepare(
    `SELECT d.id, d.domain FROM domains d JOIN users u ON u.organization_id = d.organization_id
     WHERE d.id = ? AND u.id = ? AND d.authorized = 1`
  ).bind(domainId, user.id).first();
  if (!row) throw new ApiError(404, "Authorized domain not found");

  const insert = await env.DB.prepare("INSERT INTO scans (domain_id, status, started_at) VALUES (?, 'running', ?)")
    .bind(row.id, new Date().toISOString()).run();
  const scanId = insert.meta.last_row_id;

  const result = await scanDomain(row.domain);

  await env.DB.prepare("UPDATE scans SET status='completed', score=?, findings_count=?, result_json=?, completed_at=? WHERE id=?")
    .bind(result.score, result.findings.length, JSON.stringify(result), new Date().toISOString(), scanId).run();

  return json({ scan_id: scanId, ...result }, 200, origin);
}

async function handleScanHistory(request, env, origin) {
  const user = await requireUser(request, env);
  const { results } = await env.DB.prepare(
    `SELECT s.id, d.domain, s.status, s.score, s.findings_count, s.started_at, s.completed_at
     FROM scans s JOIN domains d ON d.id = s.domain_id JOIN users u ON u.organization_id = d.organization_id
     WHERE u.id = ? ORDER BY s.id DESC`
  ).bind(user.id).all();
  return json(results, 200, origin);
}

async function handleScanDetail(request, env, origin, scanId) {
  const user = await requireUser(request, env);
  const row = await env.DB.prepare(
    `SELECT s.id, d.domain, s.status, s.score, s.findings_count, s.result_json, s.started_at, s.completed_at
     FROM scans s JOIN domains d ON d.id = s.domain_id JOIN users u ON u.organization_id = d.organization_id
     WHERE s.id = ? AND u.id = ?`
  ).bind(scanId, user.id).first();
  if (!row) throw new ApiError(404, "Scan not found");

  const result = JSON.parse(row.result_json || "{}");
  return json({
    id: row.id, domain: row.domain, status: row.status, score: row.score,
    findings_count: row.findings_count, started_at: row.started_at, completed_at: row.completed_at,
    findings: result.findings || [], dns: result.dns || {}, ip: result.ip, http_status: result.http_status,
  }, 200, origin);
}

async function handleReportPdf(request, env, scanId) {
  const user = await requireUser(request, env);
  const row = await env.DB.prepare(
    `SELECT s.*, d.domain FROM scans s JOIN domains d ON d.id = s.domain_id JOIN users u ON u.organization_id = d.organization_id
     WHERE s.id = ? AND u.id = ?`
  ).bind(scanId, user.id).first();
  if (!row) throw new ApiError(404, "Report not found");

  const data = JSON.parse(row.result_json || "{}");
  const pdfBytes = buildReportPdf(row.domain, row.score, data.findings || []);
  return new Response(pdfBytes, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="cyberguard-${scanId}.pdf"`,
      ...corsHeaders(request.headers.get("Origin") || ""),
    },
  });
}

async function handleAdminOverview(request, env, origin) {
  const user = await requireUser(request, env);
  if (!["ADMIN", "SUPER_ADMIN"].includes(user.role)) throw new ApiError(403, "Admin access required");

  const [users, domains, scans] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) AS n FROM users").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM domains").first(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM scans").first(),
  ]);
  return json({ users: users.n, domains: domains.n, scans: scans.n }, 200, origin);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (path === "/health") {
      return json({ status: "ok", service: "cyberguard-api", environment: env.ENVIRONMENT || "unknown" }, 200, origin);
    }
    if (path === "/") {
      return json({ status: "ok", service: "CyberGuard API", environment: env.ENVIRONMENT || "unknown", health: "/health" }, 200, origin);
    }
    if (!env.JWT_SECRET) {
      return json({ error: "JWT_SECRET is not configured" }, 500, origin);
    }

    try {
      if (path === "/api/auth/register" && method === "POST") return await handleRegister(request, env, origin);
      if (path === "/api/auth/login" && method === "POST") return await handleLogin(request, env, origin);
      if (path === "/api/domains" && method === "POST") return await handleAddDomain(request, env, origin);
      if (path === "/api/domains" && method === "GET") return await handleListDomains(request, env, origin);

      m = path.match(/^\/api\/domains\/(\d+)$/);
      if (m && method === "DELETE") return await handleDeleteDomain(request, env, origin, parseInt(m[1], 10));
      if (path === "/api/scans" && method === "POST") return await handleStartScan(request, env, origin);
      if (path === "/api/scans" && method === "GET") return await handleScanHistory(request, env, origin);

      let m = path.match(/^\/api\/scans\/(\d+)$/);
      if (m && method === "GET") return await handleScanDetail(request, env, origin, parseInt(m[1], 10));

      m = path.match(/^\/api\/reports\/(\d+)\.pdf$/);
      if (m && method === "GET") return await handleReportPdf(request, env, parseInt(m[1], 10));

      if (path === "/api/admin/overview" && method === "GET") return await handleAdminOverview(request, env, origin);
    } catch (err) {
      if (err instanceof ApiError) return json({ error: err.message }, err.status, origin);
      return json({ error: "Internal error", message: String(err.message || err) }, 500, origin);
    }

    return json({
      error: "Endpoint not found", path,
      available: ["/", "/health", "/api/auth/register", "/api/auth/login", "/api/domains", "/api/domains/:id", "/api/scans", "/api/scans/:id", "/api/reports/:id.pdf", "/api/admin/overview"],
    }, 404, origin);
  },
};
