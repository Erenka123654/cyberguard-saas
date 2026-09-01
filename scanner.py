import ipaddress
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

class UnsafeTargetError(Exception):
    """Raised when a scan target resolves to a private/internal/reserved IP (SSRF guard)."""


def _assert_public_ip(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        raise UnsafeTargetError(f"Refusing to scan internal/reserved address {ip_str}")


def _safe_get(client: httpx.Client, url: str):
    """GET that re-validates the IP on every redirect hop, blocking SSRF via redirects/DNS rebinding."""
    current_url = url
    for _ in range(6):
        host = httpx.URL(current_url).host
        _assert_public_ip(socket.gethostbyname(host))
        r = client.get(current_url, follow_redirects=False)
        if r.is_redirect:
            current_url = str(r.headers.get("location"))
            if not current_url:
                return r
            continue
        return r
    raise UnsafeTargetError("Too many redirects")


def scan_domain(domain):
    findings, dns_data = [], {}
    for record in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            dns_data[record] = [str(x) for x in dns.resolver.resolve(domain, record, lifetime=3)]
        except Exception:
            dns_data[record] = []
    try:
        ip = socket.gethostbyname(domain)
        _assert_public_ip(ip)
    except UnsafeTargetError:
        return {"domain": domain, "ip": None, "http_status": None, "dns": dns_data,
                "findings": [{"severity": "CRITICAL", "title": "Unsafe scan target",
                               "description": "This domain resolves to a private, loopback, or reserved IP address and cannot be scanned.",
                               "remediation": "Only public, internet-facing domains can be scanned."}],
                "score": 0}
    except Exception:
        ip = None
    status, headers = None, {}
    try:
        with httpx.Client(timeout=8) as client:
            r = _safe_get(client, "https://" + domain)
            status = r.status_code
            headers = {k.lower(): v for k, v in r.headers.items()}
    except UnsafeTargetError as exc:
        findings.append({"severity":"CRITICAL","title":"Unsafe redirect target",
                         "description":str(exc),"remediation":"Scan blocked to prevent SSRF via redirect."})
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
