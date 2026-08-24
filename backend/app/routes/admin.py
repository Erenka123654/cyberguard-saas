from fastapi import APIRouter, Depends, HTTPException
from app.db import get_conn
from app.security import current_user
router=APIRouter()

def admin_only(user):
    if user["role"] not in ("ADMIN","SUPER_ADMIN"):
        raise HTTPException(403,"Admin access required")

@router.get("/overview")
def overview(user=Depends(current_user)):
    admin_only(user)
    conn=get_conn()
    result={
      "users":conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
      "domains":conn.execute("SELECT COUNT(*) n FROM domains").fetchone()["n"],
      "scans":conn.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
    }
    conn.close()
    return result
