import socket
import httpx
import dns.resolver

HEADERS = {
    "strict-transport-security": ("HIGH", 10),
    "content-security-policy": ("MEDIUM", 6),
    "x-content-type-options": ("LOW", 3),
    "x-frame-options": ("LOW", 3),
    "referrer-policy": ("LOW", 2),
}

def scan_domain(domain):
    findings, dns_data = [], {}
    for record in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            dns_data[record] = [str(x) for x in dns.resolver.resolve(domain, record, lifetime=3)]
        except Exception:
            dns_data[record] = []
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = None
    status, headers = None, {}
    try:
        with httpx.Client(timeout=8, follow_redirects=True) as client:
            r = client.get("https://" + domain)
            status = r.status_code
            headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception as exc:
        findings.append({"severity":"HIGH","title":"HTTPS connection could not be verified",
                         "description":str(exc),"remediation":"Verify DNS, TLS and HTTPS availability."})
    for key, (severity, penalty) in HEADERS.items():
        if key not in headers:
            findings.append({"severity":severity,"title":f"Missing {key} header",
                             "description":f"{key} was not present in the HTTPS response.",
                             "remediation":f"Configure an appropriate {key} policy."})
    weights = {"CRITICAL":25,"HIGH":10,"MEDIUM":6,"LOW":2}
    score = max(0, 100 - sum(weights.get(f["severity"],0) for f in findings))
    return {"domain":domain,"ip":ip,"http_status":status,"dns":dns_data,
            "findings":findings,"score":score}
