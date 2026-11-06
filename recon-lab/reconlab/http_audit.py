"""Lightweight HTTP security audit (headers, cookies, exposed paths)."""
from __future__ import annotations

import http.client
from urllib.parse import urlparse

from .findings import Finding

SECURITY_HEADERS = {
    "content-security-policy": ("medium", "Mitigates XSS and data injection"),
    "x-frame-options": ("low", "Prevents clickjacking"),
    "x-content-type-options": ("low", "Prevents MIME sniffing"),
    "referrer-policy": ("low", "Limits referrer leakage"),
    "permissions-policy": ("info", "Restricts browser feature access"),
    "strict-transport-security": ("medium", "Enforces HTTPS (only relevant over TLS)"),
}
COMMON_PATHS = ["/robots.txt", "/.git/HEAD", "/admin", "/backup.zip", "/server-status", "/.env"]


def _request(scheme: str, host: str, port: int, path: str, timeout: float = 4.0):
    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = cls(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "ReconLab/1.0 (educational)"})
        resp = conn.getresponse()
        raw = resp.getheaders()
        return resp.status, {k.lower(): v for k, v in raw}, raw, resp.read(2048)
    finally:
        conn.close()


def audit(url: str) -> tuple[list[Finding], dict]:
    u = urlparse(url if "://" in url else "http://" + url)
    scheme = u.scheme
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    target = f"{scheme}://{host}:{port}"
    findings: list[Finding] = []
    meta: dict = {"url": target, "paths": {}}

    status, headers, raw, _ = _request(scheme, host, port, u.path or "/")
    meta.update(status=status, headers=headers)

    for h, (sev, why) in SECURITY_HEADERS.items():
        if h == "strict-transport-security" and scheme != "https":
            continue
        if h not in headers:
            findings.append(Finding(f"Missing security header: {h}", sev, "web", target,
                                    why, f"Add the {h} response header."))
    if "server" in headers and any(c.isdigit() for c in headers["server"]):
        findings.append(Finding("Server version disclosure", "low", "web", target,
                                f"Server: {headers['server']}", "Suppress version details in the Server header."))
    if "x-powered-by" in headers:
        findings.append(Finding("Technology disclosure via X-Powered-By", "low", "web", target,
                                f"X-Powered-By: {headers['x-powered-by']}", "Remove the X-Powered-By header."))
    for k, v in raw:
        if k.lower() == "set-cookie":
            missing = [a for a in ("HttpOnly", "Secure", "SameSite") if a.lower() not in v.lower()]
            if scheme != "https" and "Secure" in missing:
                missing.remove("Secure")
            if missing:
                findings.append(Finding("Cookie missing security attributes", "medium", "web", target,
                                        f"{v.split('=')[0]} lacks: {', '.join(missing)}",
                                        "Set HttpOnly, Secure and SameSite on session cookies."))
    for p in COMMON_PATHS:
        try:
            st, _, _, body = _request(scheme, host, port, p)
        except OSError:
            continue
        meta["paths"][p] = st
        if st == 200:
            sev = "high" if p in ("/.git/HEAD", "/.env", "/backup.zip") else "low"
            findings.append(Finding(f"Exposed path: {p}", sev, "web", target,
                                    f"HTTP 200 for {p}: {body[:80]!r}",
                                    "Remove sensitive files from the web root or restrict access."))
    return findings, meta
