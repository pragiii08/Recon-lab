"""Threaded TCP-connect port scanner with banner grabbing (stdlib only)."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .findings import Finding

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb", 2121: "ftp (lab)", 2222: "ssh (lab)",
}
# port -> (severity, reason)
RISKY = {
    21: ("medium", "FTP transmits credentials in clear text"),
    23: ("high", "Telnet transmits everything in clear text"),
    445: ("medium", "SMB exposure increases lateral-movement risk"),
    3389: ("medium", "RDP is a common brute-force/ransomware entry point"),
    5900: ("medium", "VNC often has weak or no authentication"),
    6379: ("high", "Redis is frequently exposed without authentication"),
    27017: ("high", "MongoDB is frequently exposed without authentication"),
    2121: ("medium", "FTP transmits credentials in clear text"),
}
HTTP_PORTS = {80, 8000, 8080, 8443}
OLD_VERSION_HINTS = ["vsftpd 2.3.4", "openssh_5", "openssh_4", "apache/2.2", "proftpd 1.3.3"]


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be within 1-65535")
    return sorted(ports)


def _banner(sock: socket.socket, host: str, port: int) -> str:
    try:
        sock.settimeout(1.0)
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(512)
        return data.decode("latin-1", "replace").strip().replace("\r", "")[:200]
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float = 0.5) -> PortResult | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return PortResult(port, "open", SERVICES.get(port, "unknown"), _banner(s, host, port))
    except OSError:
        return None


def scan(host: str, ports: list[int], timeout: float = 0.5, workers: int = 100) -> list[PortResult]:
    workers = max(1, min(workers, 200))  # hard cap keeps the lab polite
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda p: scan_port(host, p, timeout), ports))
    return sorted((r for r in results if r), key=lambda r: r.port)


def analyse(host: str, results: list[PortResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        out.append(Finding(
            title=f"Open port {r.port}/tcp ({r.service})", severity="info", category="network",
            target=host, evidence=r.banner or "No banner returned",
            recommendation="Confirm the service is required; close or firewall it otherwise."))
        if r.port in RISKY:
            sev, why = RISKY[r.port]
            out.append(Finding(
                title=f"Risky service exposed: {r.service} on {r.port}", severity=sev, category="network",
                target=host, evidence=why,
                recommendation="Disable the service, restrict by firewall, or replace with an encrypted alternative."))
        low = r.banner.lower()
        for hint in OLD_VERSION_HINTS:
            if hint in low:
                out.append(Finding(
                    title=f"Outdated/vulnerable version banner on {r.port}", severity="high", category="network",
                    target=host, evidence=f"Banner: {r.banner}",
                    recommendation="Upgrade to a supported release and hide version banners where possible."))
                break
    return out
