# CyberGuard — Cloudflare Only

Bu sürüm Railway/FastAPI/SQLite bağımlılıklarını kaldırır.

## Mimari

- Frontend: Cloudflare Pages veya GitHub Pages
- API: Cloudflare Workers
- Database: Cloudflare D1
- Secrets: Cloudflare Worker Secrets
- PDF: Worker içinde oluşturulur
- Scanner: Worker içinde güvenli public-domain kontrolleri yapar

## 1. D1 oluştur

Cloudflare Dashboard → Workers & Pages → D1 → Create database

Database adı:

`cyberguard-db`

`database/schema.sql` dosyasını D1 Console'da çalıştır.

## 2. Worker binding

Workers → cyberguard-api → Settings → Bindings

D1 binding:

- Variable name: `DB`
- D1 database: `cyberguard-db`

## 3. Secrets

Worker → Settings → Variables and Secrets:

`JWT_SECRET` = uzun, rastgele bir gizli değer

Opsiyonel:

`ADMIN_EMAIL` = ilk admin hesabı olacak e-posta

Örnek üretim secret'ı:

`openssl rand -hex 32`

## 4. Worker deploy

`cloudflare/worker.js` dosyasını Worker'a yükle.

`cloudflare/wrangler.toml` içindeki `database_id` değerini kendi D1 ID'n ile değiştirirsen Wrangler ile de deploy edebilirsin.

## 5. Test

`https://cyberguard-api.erenkaraca2005.workers.dev/health`

Beklenen:

```json
{
  "status": "ok",
  "service": "cyberguard-cloudflare",
  "database": true,
  "environment": "production"
}
```

## 6. Frontend

`frontend/config.js` içindeki API adresi:

`https://cyberguard-api.erenkaraca2005.workers.dev`

Frontend'i Cloudflare Pages'e bağlayabilirsin.

## Önemli

- `backend/` klasörü bu sürümde intentionally kaldırılmıştır.
- `cyberguard.db`, `__pycache__` ve Railway yapılandırması kullanılmaz.
- Tarama yalnızca kullanıcının yetkili olduğunu onayladığı domainler için başlatılmalıdır.
- SSRF riskini azaltmak için özel/rezerve IP'ler ve HTTPS dışı redirectler engellenir.
