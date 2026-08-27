import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.db import get_conn
from app.security import current_user
from app.scanner import scan_domain

router = APIRouter()

class ScanIn(BaseModel):
    domain_id: int

@router.post("")
def start_scan(data: ScanIn, user=Depends(current_user)):
    conn = get_conn()
    row = conn.execute("""SELECT d.id,d.domain FROM domains d
      JOIN users u ON u.organization_id=d.organization_id
      WHERE d.id=? AND u.id=? AND d.authorized=1""",(data.domain_id,user["id"])).fetchone()
    if not row:
        conn.close(); raise HTTPException(404,"Authorized domain not found")
    cur = conn.execute("INSERT INTO scans(domain_id,status,started_at) VALUES(?,?,?)",
                       (row["id"],"running",datetime.now(timezone.utc).isoformat()))
    scan_id = cur.lastrowid; conn.commit()
    result = scan_domain(row["domain"])
    conn.execute("""UPDATE scans SET status='completed',score=?,findings_count=?,
                    result_json=?,completed_at=? WHERE id=?""",
                 (result["score"],len(result["findings"]),json.dumps(result),
                  datetime.now(timezone.utc).isoformat(),scan_id))
    conn.commit(); conn.close()
    return {"scan_id":scan_id,**result}

@router.get("")
def history(user=Depends(current_user)):
    conn = get_conn()
    rows = conn.execute("""SELECT s.id,d.domain,s.status,s.score,s.findings_count,
      s.started_at,s.completed_at FROM scans s JOIN domains d ON d.id=s.domain_id
      JOIN users u ON u.organization_id=d.organization_id WHERE u.id=? ORDER BY s.id DESC""",
      (user["id"],)).fetchall()
    conn.close()
    return [dict(x) for x in rows]

@router.get("/{scan_id}")
def scan_detail(scan_id: int, user=Depends(current_user)):
    conn = get_conn()
    row = conn.execute("""SELECT s.id,d.domain,s.status,s.score,s.findings_count,
      s.result_json,s.started_at,s.completed_at FROM scans s JOIN domains d ON d.id=s.domain_id
      JOIN users u ON u.organization_id=d.organization_id WHERE s.id=? AND u.id=?""",
      (scan_id, user["id"])).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Scan not found")
    result = json.loads(row["result_json"] or "{}")
    return {"id": row["id"], "domain": row["domain"], "status": row["status"],
            "score": row["score"], "findings_count": row["findings_count"],
            "started_at": row["started_at"], "completed_at": row["completed_at"],
            "findings": result.get("findings", []), "dns": result.get("dns", {}),
            "ip": result.get("ip"), "http_status": result.get("http_status")}
