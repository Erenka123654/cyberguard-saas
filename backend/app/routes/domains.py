from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from urllib.parse import urlparse
from app.db import get_conn
from app.security import current_user

router = APIRouter()

class DomainIn(BaseModel):
    domain: str
    authorized: bool = False

@router.post("")
def add_domain(data: DomainIn, user=Depends(current_user)):
    domain = data.domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or ""
    domain = domain.rstrip("/")
    if not data.authorized:
        raise HTTPException(403, "Authorization confirmation is required.")
    if not domain or "/" in domain or " " in domain:
        raise HTTPException(422, "Invalid domain")
    conn = get_conn()
    org = conn.execute("SELECT organization_id FROM users WHERE id=?", (user["id"],)).fetchone()
    conn.execute("INSERT INTO domains(organization_id,domain,authorized) VALUES(?,?,1)",
                 (org["organization_id"], domain))
    conn.commit(); conn.close()
    return {"message":"Domain added","domain":domain}

@router.get("")
def list_domains(user=Depends(current_user)):
    conn = get_conn()
    org = conn.execute("SELECT organization_id FROM users WHERE id=?", (user["id"],)).fetchone()
    rows = conn.execute("SELECT id,domain,authorized,created_at FROM domains WHERE organization_id=?",
                        (org["organization_id"],)).fetchall()
    conn.close()
    return [dict(x) for x in rows]
