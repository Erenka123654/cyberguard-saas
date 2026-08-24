# Cloudflare deployment

```bash
npm install -g wrangler
wrangler login
wrangler d1 create cyberguard-db
wrangler d1 execute cyberguard-db --remote --file=../database/schema.sql
wrangler secret put API_ORIGIN
wrangler deploy
```

Use the public FastAPI URL as API_ORIGIN. Replace the D1 database ID in wrangler.toml.

The current backend uses SQLite locally so the project can be tested immediately. For full Cloudflare-native production, move the data access layer to Workers/D1 and keep scanning in a separate authorized scanner service.
