from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from app.db import get_conn
from app.security import hash_password, verify_password, create_token
from app.rate_limit import rate_limit

router = APIRouter()

class Register(BaseModel):
    email: str
    password: str = Field(min_length=8)
    organization: str = Field(min_length=2, max_length=120)

class Login(BaseModel):
    email: str
    password: str

@router.post("/register")
def register(data: Register, request: Request):
    rate_limit(request, "register", max_attempts=5, window_seconds=60)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO organizations(name) VALUES (?)", (data.organization,))
        org = cur.lastrowid
        cur.execute("INSERT INTO users(organization_id,email,password_hash,role) VALUES(?,?,?,?)",
                    (org, data.email.lower(), hash_password(data.password), "CUSTOMER"))
        conn.commit()
        return {"access_token": create_token(cur.lastrowid, "CUSTOMER"), "token_type":"bearer"}
    except Exception:
        conn.rollback()
        raise HTTPException(400, "Email may already be registered.")
    finally:
        conn.close()

@router.post("/login")
def login(data: Login, request: Request):
    rate_limit(request, "login", max_attempts=8, window_seconds=60)
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE email=?", (data.email.lower(),)).fetchone()
    conn.close()
    if not row or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    return {"access_token":create_token(row["id"],row["role"]),"token_type":"bearer","role":row["role"]}
