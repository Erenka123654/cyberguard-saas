# CyberGuard SaaS

Production-oriented SaaS foundation for authorized web security assessments.

Includes:
- Professional responsive dashboard
- User registration/login with JWT
- Customer organization model
- Cloudflare D1 schema
- Real scan history API
- Authorized domain validation
- DNS / HTTPS / HTTP security-header scanner
- PDF report endpoint
- Admin overview endpoints
- Cloudflare Worker API gateway
- Dockerized FastAPI backend

## Local API
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

API docs: http://127.0.0.1:8000/docs

## Cloudflare D1
```bash
wrangler d1 create cyberguard-db
wrangler d1 execute cyberguard-db --remote --file=database/schema.sql
```

Put the returned database ID into cloudflare/wrangler.toml.

Only scan systems you own or have explicit authorization to test.
