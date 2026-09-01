import io, json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from app.db import get_conn
from app.security import current_user

router = APIRouter()

@router.get("/{scan_id}.pdf")
def pdf(scan_id:int,user=Depends(current_user)):
    conn=get_conn()
    row=conn.execute("""SELECT s.*,d.domain FROM scans s JOIN domains d ON d.id=s.domain_id
      JOIN users u ON u.organization_id=d.organization_id WHERE s.id=? AND u.id=?""",
      (scan_id,user["id"])).fetchone()
    conn.close()
    if not row: raise HTTPException(404,"Report not found")
    data=json.loads(row["result_json"] or "{}")
    buf=io.BytesIO(); c=canvas.Canvas(buf,pagesize=A4); w,h=A4
    c.setFont("Helvetica-Bold",20); c.drawString(50,h-60,"CyberGuard Security Assessment")
    c.setFont("Helvetica",11); c.drawString(50,h-90,f"Domain: {row['domain']}")
    c.drawString(50,h-110,f"Security Score: {row['score']}/100")
    y=h-155; c.setFont("Helvetica-Bold",13); c.drawString(50,y,"Findings"); y-=25
    c.setFont("Helvetica",9)
    for f in data.get("findings",[]):
        c.drawString(55,y,f"[{f['severity']}] {f['title']}"[:105]); y-=17
        if y<70: c.showPage(); y=h-60
    c.save(); buf.seek(0)
    return StreamingResponse(buf,media_type="application/pdf",
        headers={"Content-Disposition":f'attachment; filename="cyberguard-{scan_id}.pdf"'})
