/**
 * CyberGuard API Gateway - Cloudflare Worker
 *
 * Frontend
 *    ↓
 * Cloudflare Worker
 *    ↓
 * Railway FastAPI
 */

const ALLOWED_ORIGINS = [
  "https://erenka123654.github.io",
  "https://cyberguard-saas-production.up.railway.app",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

function getCorsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : "https://erenka123654.github.io";

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods":
      "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...getCorsHeaders(origin),
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    /*
     * ---------------------------------------------------------
     * CORS PREFLIGHT
     * ---------------------------------------------------------
     */

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(origin),
      });
    }

    /*
     * ---------------------------------------------------------
     * HEALTH CHECK
     * ---------------------------------------------------------
     */

    if (url.pathname === "/health") {
      return json(
        {
          status: "ok",
          edge: true,
          service: "cyberguard-api-gateway",
          environment: env.ENVIRONMENT || "unknown",
        },
        200,
        origin
      );
    }

    /*
     * ---------------------------------------------------------
     * ROOT
     * ---------------------------------------------------------
     */

    if (url.pathname === "/") {
      return json(
        {
          status: "ok",
          service: "CyberGuard API Gateway",
          environment: env.ENVIRONMENT || "unknown",
          health: "/health",
        },
        200,
        origin
      );
    }

    /*
     * ---------------------------------------------------------
     * API ORIGIN KONTROLÜ
     * ---------------------------------------------------------
     */

    if (!env.API_ORIGIN) {
      return json(
        {
          error: "API_ORIGIN is not configured",
        },
        500,
        origin
      );
    }

    /*
     * ---------------------------------------------------------
     * SADECE /api/* İSTEKLERİNİ RAILWAY'E GÖNDER
     * ---------------------------------------------------------
     */

    if (url.pathname.startsWith("/api/")) {
      let apiOrigin;

      try {
        apiOrigin = new URL(env.API_ORIGIN);
      } catch {
        return json(
          {
            error: "Invalid API_ORIGIN configuration",
          },
          500,
          origin
        );
      }

      /*
       * Railway URL'sindeki olası son "/" karakterini temizle.
       */
      const target = new URL(
        url.pathname + url.search,
        apiOrigin.toString().replace(/\/$/, "") + "/"
      );

      /*
       * İstek header'larını kopyala.
       */
      const headers = new Headers(request.headers);

      /*
       * Worker bilgisini backend'e gönder.
       */
      headers.set("X-CyberGuard-Edge", "cloudflare-worker");

      /*
       * Host header'ını Railway'e zorla göndermiyoruz.
       * Cloudflare/Railway doğru Host'u kendisi oluşturacak.
       */
      headers.delete("Host");

      /*
       * Backend'in gerçek client IP'sini görebilmesi için.
       */
      const clientIP = request.headers.get("CF-Connecting-IP");

      if (clientIP) {
        headers.set("X-Real-IP", clientIP);
        headers.set("X-Forwarded-For", clientIP);
      }

      /*
       * Backend'e isteği gönder.
       */
      try {
        const response = await fetch(
          new Request(target.toString(), {
            method: request.method,
            headers,
            body:
              request.method === "GET" || request.method === "HEAD"
                ? undefined
                : request.body,
            redirect: "follow",
          })
        );

        /*
         * Backend response header'larını kopyala.
         */
        const responseHeaders = new Headers(response.headers);

        /*
         * CORS header'larını Worker seviyesinde garanti et.
         */
        const corsHeaders = getCorsHeaders(origin);

        for (const [key, value] of Object.entries(corsHeaders)) {
          responseHeaders.set(key, value);
        }

        /*
         * Edge bilgisini ekle.
         */
        responseHeaders.set(
          "X-CyberGuard-Edge",
          "cloudflare-worker"
        );

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      } catch (error) {
        return json(
          {
            error: "Backend connection failed",
            message: error instanceof Error
              ? error.message
              : "Unknown error",
          },
          502,
          origin
        );
      }
    }

    /*
     * ---------------------------------------------------------
     * BİLİNMEYEN ENDPOINT
     * ---------------------------------------------------------
     */

    return json(
      {
        error: "Endpoint not found",
        path: url.pathname,
        available: [
          "/",
          "/health",
          "/api/*",
        ],
      },
      404,
      origin
    );
  },
};
