from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db import init_db
from app.routes.auth import router as auth_router
from app.routes.domains import router as domains_router
from app.routes.scans import router as scans_router
from app.routes.reports import router as reports_router
from app.routes.admin import router as admin_router

init_db()
app = FastAPI(title="CyberGuard SaaS API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(domains_router, prefix="/api/domains", tags=["domains"])
app.include_router(scans_router, prefix="/api/scans", tags=["scans"])
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
app.include_router(admin_router, prefix="/api/admin", tags=["admin"])

@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberguard-api"}
