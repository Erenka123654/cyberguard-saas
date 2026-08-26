/**
 * CyberGuard - Cloudflare-only API
 *
 * Frontend -> Cloudflare Worker -> D1
 *
 * No Railway, FastAPI, SQLite or external backend is required.
 */

const JWT_TTL_SECONDS = 12 * 60 * 60;
const PASSWORD_ITERATIONS = 120000;

const ALLOWED_ORIGINS = new Set([
  "https://erenka123654.github.io",
  "http://localhost:8788",
  "http://127.0.0.1:8788",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
]);

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function corsHeaders(origin) {
  const h = { ...SECURITY_HEADERS, Vary: "Origin" };
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  }
  h["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS";
  h["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
  h["Access-Control-Max-Age"] = "86400";
  return h;
}

function response(body, status = 200, origin = "", headers = {}) {
  return new Response(body, {
    status,
    headers: { ...corsHeaders(origin), ...headers },
  });
}

function json(data, status = 200, origin = "") {
  return response(JSON.stringify(data), status, origin, {
    "Content-Type": "application/json; charset=utf-8",
  });
}

function error(message, status = 400, origin = "") {
  return json({ error: message }, status, origin);
}

function b64url(bytes) {
  let binary = "";
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlText(text) {
  return b64url(new TextEncoder().encode(text));
}

function fromB64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function fromB64urlText(value) {
  return new TextDecoder().decode(fromB64url(value));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createToken(user, secret) {
  const header = b64urlText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64urlText(JSON.stringify({
    sub: String(user.id),
    role: user.role,
    org: user.organization_id,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + JWT_TTL_SECONDS,
  }));
  const data = `${header}.${payload}`;
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret),
    new TextEncoder().encode(data)
  );
  return `${data}.${b64url(sig)}`;
}

async function verifyToken(token, secret) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const [header, payload, signature] = parts;
  const valid = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(secret),
    fromB64url(signature),
    new TextEncoder().encode(`${header}.${payload}`)
  );
  if (!valid) throw new Error("Invalid token");
  const p = JSON.parse(fromB64urlText(payload));
  if (!p.exp || p.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }
  return p;
}

function randomBytes(size = 16) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function hashPassword(password, saltBytes = randomBytes(16)) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256",
    },
    key,
    256
  );
  return { salt: b64url(saltBytes), hash: b64url(new Uint8Array(bits)) };
}

async function verifyPassword(password, salt, expectedHash) {
  const saltBytes = fromB64url(salt);
  const result = await hashPassword(password, saltBytes);
  return timingSafeEqual(result.hash, expectedHash);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
}

async function bodyJson(request) {
  try {
    const data = await request.json();
    if (!data || typeof data !== "object") throw new Error();
    return data;
  } catch {
    throw new Error("Geçersiz JSON isteği");
  }
}

function normalizeDomain(value) {
  let raw = String(value || "").trim().toLowerCase();
  if (!raw) throw new Error("Domain gerekli");
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let u;
  try { u = new URL(raw); } catch { throw new Error("Geçersiz domain"); }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new Error("Sadece HTTP/HTTPS destekleniyor");
  }
  if (u.username || u.password || u.port) {
    throw new Error("Kimlik bilgisi veya özel port kullanılamaz");
  }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("..")) {
    throw new Error("Geçersiz hostname");
  }
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(host)
      && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)
      && !/^\[[0-9a-f:]+\]$/i.test(host)) {
    throw new Error("Geçersiz public domain");
  }
  return host;
}

function ipv4Parts(ip) {
  const p = ip.split(".").map(Number);
  return p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255) ? p : null;
}

function isPrivateIPv4(ip) {
  const p = ipv4Parts(ip);
  if (!p) return true;
  const [a,b] = p;
  return a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 0 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51) ||
    (a === 203 && b === 0) ||
    a >= 224;
}

function isPrivateIPv6(ip) {
  const s = ip.toLowerCase().replace(/^\[|\]$/g, "");
  return s === "::1" ||
    s === "::" ||
    s.startsWith("fc") ||
    s.startsWith("fd") ||
    s.startsWith("fe8") || s.startsWith("fe9") ||
    s.startsWith("fea") || s.startsWith("feb") ||
    s.startsWith("ff");
}

function isPrivateIp(ip) {
  return ip.includes(":") ? isPrivateIPv6(ip) : isPrivateIPv4(ip);
}

async function resolvePublicIps(host) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    if (isPrivateIPv4(host)) throw new Error("Özel/rezerve IP adresi taranamaz");
    return [host];
  }

  const ips = [];
  for (const type of ["A", "AAAA"]) {
    const dnsUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
    const r = await fetch(dnsUrl, {
      headers: { Accept: "application/dns-json" },
    });
    if (!r.ok) continue;
    const data = await r.json();
    for (const answer of data.Answer || []) {
      if (answer.type === 1 || answer.type === 28) ips.push(answer.data);
    }
  }
  if (!ips.length) throw new Error("Domain DNS ile çözümlenemedi");
  if (ips.some(isPrivateIp)) throw new Error("Domain özel/rezerve bir IP adresine çözülüyor");
  return ips;
}

async function validatePublicTarget(host) {
  const ips = await resolvePublicIps(host);
  if (!ips.length || ips.some(isPrivateIp)) {
    throw new Error("Güvenli olmayan tarama hedefi");
  }
  return ips;
}

async function safeFetchHttps(host) {
  let current = `https://${host}/`;
  let response = null;
  const visited = new Set();

  for (let hop = 0; hop < 6; hop++) {
    const u = new URL(current);
    if (u.protocol !== "https:") throw new Error("HTTPS zorunlu");
    const targetHost = u.hostname.toLowerCase();
    if (visited.has(targetHost)) throw new Error("Redirect döngüsü");
    visited.add(targetHost);
    await validatePublicTarget(targetHost);

    response = await fetch(current, {
      method: "GET",
      redirect: "manual",
      headers: {
        "User-Agent": "CyberGuard-Security-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
      },
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) break;
      const next = new URL(location, current);
      if (next.protocol !== "https:") throw new Error("HTTPS dışı redirect engellendi");
      current = next.toString();
      continue;
    }
    return response;
  }
  throw new Error("Çok fazla redirect");
}

function scoreFindings(findings) {
  const weights = { CRITICAL: 25, HIGH: 10, MEDIUM: 6, LOW: 2 };
  return Math.max(0, 100 - findings.reduce((n, f) => n + (weights[f.severity] || 0), 0));
}

async function scanDomain(domain) {
  const findings = [];
  let httpStatus = null;
  let ip = null;
  const dns = { A: [], AAAA: [] };

  try {
    const ips = await resolvePublicIps(domain);
    ip = ips[0] || null;
    dns.A = ips.filter(x => !x.includes(":"));
    dns.AAAA = ips.filter(x => x.includes(":"));
  } catch (e) {
    findings.push({
      severity: "CRITICAL",
      title: "Unsafe or unresolved scan target",
      description: e.message,
      remediation: "Use a public internet-facing domain with valid DNS records.",
    });
    return { domain, ip, http_status: null, dns, findings, score: 0 };
  }

  try {
    const r = await safeFetchHttps(domain);
    httpStatus = r.status;
    const headers = {};
    r.headers.forEach((v, k) => headers[k.toLowerCase()] = v);

    const checks = [
      ["strict-transport-security", "HIGH", 10, "HSTS header eksik", "HTTPS bağlantılarında HSTS kullanın."],
      ["content-security-policy", "MEDIUM", 6, "Content-Security-Policy header eksik", "Uygun bir CSP politikası tanımlayın."],
      ["x-content-type-options", "LOW", 3, "X-Content-Type-Options header eksik", "nosniff değerini ekleyin."],
      ["x-frame-options", "LOW", 3, "X-Frame-Options header eksik", "DENY veya SAMEORIGIN kullanın."],
      ["referrer-policy", "LOW", 2, "Referrer-Policy header eksik", "strict-origin-when-cross-origin gibi bir politika kullanın."],
      ["permissions-policy", "LOW", 2, "Permissions-Policy header eksik", "Gereksiz tarayıcı özelliklerini kısıtlayın."],
    ];

    for (const [key, severity, penalty, title, remediation] of checks) {
      if (!headers[key]) {
        findings.push({
          severity,
          title,
          description: `${key} response header bulunamadı.`,
          remediation,
        });
      }
    }

    if (r.url && !r.url.startsWith("https://")) {
      findings.push({
        severity: "HIGH",
        title: "HTTPS enforcement doğrulanamadı",
        description: "Son response HTTPS üzerinde değil.",
        remediation: "HTTP isteklerini HTTPS'e yönlendirin ve HSTS kullanın.",
      });
    }
  } catch (e) {
    findings.push({
      severity: "HIGH",
      title: "HTTPS connection could not be verified",
      description: e.message,
      remediation: "DNS, TLS ve HTTPS erişilebilirliğini kontrol edin.",
    });
  }

  return {
    domain,
    ip,
    http_status: httpStatus,
    dns,
    findings,
    score: scoreFindings(findings),
  };
}

function nowIso() {
  return new Date().toISOString();
}

async function requireUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) throw new Error("Authentication required");
  if (!env.JWT_SECRET) throw new Error("JWT_SECRET secret is not configured");
  return verifyToken(auth.slice(7), env.JWT_SECRET);
}

async function audit(env, userId, action, target) {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_logs(user_id, action, target, created_at) VALUES(?,?,?,?)"
    ).bind(userId, action, target || null, nowIso()).run();
  } catch {}
}

function pdfEscape(s) {
  return String(s || "")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)")
    .replace(/[^\x20-\x7E]/g, "?");
}

function makePdf(lines) {
  const clean = lines.map(pdfEscape);
  const streamLines = [
    "BT",
    "/F1 12 Tf",
    "50 790 Td",
    ...clean.flatMap((line, i) => [
      `(${line}) Tj`,
      "0 -18 Td",
    ]),
    "ET",
  ];
  const stream = streamLines.join("\n");
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objects.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new TextEncoder().encode(pdf);
}

async function handle(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin") || "";
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (request.method === "OPTIONS") {
    return response(null, 204, origin);
  }

  if (path === "/health" && request.method === "GET") {
    return json({
      status: "ok",
      service: "cyberguard-cloudflare",
      database: !!env.DB,
      environment: env.ENVIRONMENT || "production",
    }, 200, origin);
  }

  if (path === "/" && request.method === "GET") {
    return json({
      status: "ok",
      service: "CyberGuard API",
      platform: "Cloudflare Workers + D1",
      health: "/health",
    }, 200, origin);
  }

  if (!env.DB) return error("D1 binding 'DB' is not configured", 500, origin);

  if (path === "/api/auth/register" && request.method === "POST") {
    const data = await bodyJson(request);
    const email = String(data.email || "").trim().toLowerCase();
    const password = String(data.password || "");
    const organization = String(data.organization || "").trim();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return error("Geçerli bir e-posta adresi girin", 422, origin);
    }
    if (password.length < 8) return error("Şifre en az 8 karakter olmalı", 422, origin);
    if (organization.length < 2 || organization.length > 120) {
      return error("Organizasyon adı 2-120 karakter olmalı", 422, origin);
    }

    const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    if (exists) return error("Bu e-posta zaten kayıtlı", 409, origin);

    const org = await env.DB.prepare(
      "INSERT INTO organizations(name, created_at) VALUES(?,?) RETURNING id"
    ).bind(organization, nowIso()).first();

    const hp = await hashPassword(password);
    const role = env.ADMIN_EMAIL && env.ADMIN_EMAIL.toLowerCase() === email ? "ADMIN" : "CUSTOMER";

    const user = await env.DB.prepare(
      `INSERT INTO users(organization_id,email,password_salt,password_hash,role,created_at)
       VALUES(?,?,?,?,?,?) RETURNING id,organization_id,role`
    ).bind(org.id, email, hp.salt, hp.hash, role, nowIso()).first();

    await audit(env, user.id, "REGISTER", email);
    const token = await createToken(user, env.JWT_SECRET);
    return json({ access_token: token, token_type: "bearer", role, organization }, 201, origin);
  }

  if (path === "/api/auth/login" && request.method === "POST") {
    const data = await bodyJson(request);
    const email = String(data.email || "").trim().toLowerCase();
    const password = String(data.password || "");
    const user = await env.DB.prepare(
      `SELECT id,organization_id,email,password_salt,password_hash,role
       FROM users WHERE email=?`
    ).bind(email).first();

    if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
      return error("E-posta veya şifre hatalı", 401, origin);
    }

    const org = await env.DB.prepare(
      "SELECT name FROM organizations WHERE id=?"
    ).bind(user.organization_id).first();

    await audit(env, user.id, "LOGIN", email);
    const token = await createToken(user, env.JWT_SECRET);
    return json({
      access_token: token,
      token_type: "bearer",
      role: user.role,
      organization: org?.name || "",
    }, 200, origin);
  }

  if (path === "/api/auth/me" && request.method === "GET") {
    try {
      const user = await requireUser(request, env);
      const row = await env.DB.prepare(
        `SELECT u.id,u.email,u.role,o.name organization
         FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.id=?`
      ).bind(Number(user.sub)).first();
      if (!row) return error("User not found", 404, origin);
      return json(row, 200, origin);
    } catch (e) {
      return error(e.message, 401, origin);
    }
  }

  let user;
  try {
    user = await requireUser(request, env);
  } catch (e) {
    return error(e.message, 401, origin);
  }

  const userId = Number(user.sub);
  const orgId = Number(user.org);

  if (path === "/api/domains" && request.method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT id,domain,authorized,created_at FROM domains WHERE organization_id=? ORDER BY id DESC"
    ).bind(orgId).all();
    return json(rows.results || [], 200, origin);
  }

  if (path === "/api/domains" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data.authorized) return error("Authorization confirmation is required", 403, origin);
    let domain;
    try { domain = normalizeDomain(data.domain); }
    catch (e) { return error(e.message, 422, origin); }

    const existing = await env.DB.prepare(
      "SELECT id FROM domains WHERE organization_id=? AND domain=?"
    ).bind(orgId, domain).first();
    if (existing) return error("Domain already exists", 409, origin);

    const row = await env.DB.prepare(
      `INSERT INTO domains(organization_id,domain,authorized,created_at)
       VALUES(?,?,1,?) RETURNING id,domain,authorized,created_at`
    ).bind(orgId, domain, nowIso()).first();

    await audit(env, userId, "DOMAIN_ADD", domain);
    return json({ message: "Domain added", ...row }, 201, origin);
  }

  if (path === "/api/scans" && request.method === "GET") {
    const rows = await env.DB.prepare(
      `SELECT s.id,d.domain,s.status,s.score,s.findings_count,s.started_at,s.completed_at
       FROM scans s JOIN domains d ON d.id=s.domain_id
       WHERE d.organization_id=? ORDER BY s.id DESC`
    ).bind(orgId).all();
    return json(rows.results || [], 200, origin);
  }

  if (path === "/api/scans" && request.method === "POST") {
    const data = await bodyJson(request);
    const domainId = Number(data.domain_id);
    const domainRow = await env.DB.prepare(
      "SELECT id,domain FROM domains WHERE id=? AND organization_id=? AND authorized=1"
    ).bind(domainId, orgId).first();
    if (!domainRow) return error("Authorized domain not found", 404, origin);

    const started = nowIso();
    const scanRow = await env.DB.prepare(
      `INSERT INTO scans(domain_id,status,started_at,created_at)
       VALUES(?,?,?,?) RETURNING id`
    ).bind(domainId, "running", started, started).first();

    let result;
    try {
      result = await scanDomain(domainRow.domain);
    } catch (e) {
      result = {
        domain: domainRow.domain,
        ip: null,
        http_status: null,
        dns: {},
        findings: [{
          severity: "HIGH",
          title: "Scan failed",
          description: e.message,
          remediation: "Check DNS/TLS configuration and try again.",
        }],
        score: 0,
      };
    }

    const completed = nowIso();
    await env.DB.prepare(
      `UPDATE scans SET status='completed',score=?,findings_count=?,result_json=?,completed_at=?
       WHERE id=?`
    ).bind(
      result.score,
      result.findings.length,
      JSON.stringify(result),
      completed,
      scanRow.id
    ).run();

    await audit(env, userId, "SCAN", domainRow.domain);
    return json({ scan_id: scanRow.id, ...result }, 201, origin);
  }

  const scanMatch = path.match(/^\/api\/scans\/(\d+)$/);
  if (scanMatch && request.method === "GET") {
    const scanId = Number(scanMatch[1]);
    const row = await env.DB.prepare(
      `SELECT s.id,d.domain,s.status,s.score,s.findings_count,s.result_json,
              s.started_at,s.completed_at
       FROM scans s JOIN domains d ON d.id=s.domain_id
       WHERE s.id=? AND d.organization_id=?`
    ).bind(scanId, orgId).first();
    if (!row) return error("Scan not found", 404, origin);

    const result = JSON.parse(row.result_json || "{}");
    return json({
      id: row.id,
      domain: row.domain,
      status: row.status,
      score: row.score,
      findings_count: row.findings_count,
      started_at: row.started_at,
      completed_at: row.completed_at,
      findings: result.findings || [],
      dns: result.dns || {},
      ip: result.ip || null,
      http_status: result.http_status || null,
    }, 200, origin);
  }

  const reportMatch = path.match(/^\/api\/reports\/(\d+)\.pdf$/);
  if (reportMatch && request.method === "GET") {
    const scanId = Number(reportMatch[1]);
    const row = await env.DB.prepare(
      `SELECT s.id,s.score,s.findings_count,s.result_json,d.domain
       FROM scans s JOIN domains d ON d.id=s.domain_id
       WHERE s.id=? AND d.organization_id=?`
    ).bind(scanId, orgId).first();
    if (!row) return error("Report not found", 404, origin);

    const result = JSON.parse(row.result_json || "{}");
    const lines = [
      "CyberGuard Security Assessment",
      "",
      `Domain: ${row.domain}`,
      `Security Score: ${row.score ?? 0}/100`,
      `Findings: ${row.findings_count ?? 0}`,
      "",
      "Findings",
      ...(result.findings || []).map(f => `[${f.severity}] ${f.title}`),
      "",
      "Generated by CyberGuard - Cloudflare Edition",
    ];

    const pdf = makePdf(lines);
    return response(pdf, 200, origin, {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="cyberguard-${scanId}.pdf"`,
      "Content-Length": String(pdf.byteLength),
    });
  }

  if (path === "/api/admin/overview" && request.method === "GET") {
    if (!["ADMIN", "SUPER_ADMIN"].includes(user.role)) {
      return error("Admin access required", 403, origin);
    }
    const [users, domains, scans] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) n FROM users").first(),
      env.DB.prepare("SELECT COUNT(*) n FROM domains").first(),
      env.DB.prepare("SELECT COUNT(*) n FROM scans").first(),
    ]);
    return json({
      users: users?.n || 0,
      domains: domains?.n || 0,
      scans: scans?.n || 0,
    }, 200, origin);
  }

  return error("Endpoint not found", 404, origin);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (e) {
      const origin = request.headers.get("Origin") || "";
      return error(e?.message || "Internal server error", 500, origin);
    }
  },
};
