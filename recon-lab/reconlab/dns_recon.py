"""Passive-style DNS / domain information gathering."""
from __future__ import annotations

import re
import shutil
import socket
import subprocess

from .findings import Finding

RECORD_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"}
_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def lookup(name: str) -> dict:
    if not _NAME.match(name):
        raise ValueError(f"Invalid hostname: {name!r}")
    data: dict = {"name": name, "addresses": [], "reverse": {}, "records": {}}
    try:
        infos = socket.getaddrinfo(name, None)
        data["addresses"] = sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return data
    for ip in data["addresses"]:
        try:
            data["reverse"][ip] = socket.gethostbyaddr(ip)[0]
        except OSError:
            data["reverse"][ip] = ""
    if shutil.which("dig"):
        for rtype in sorted(RECORD_TYPES):
            out = subprocess.run(["dig", "+short", rtype, name], capture_output=True,
                                 text=True, timeout=10, check=False).stdout
            vals = [l for l in out.splitlines() if l.strip()]
            if vals:
                data["records"][rtype] = vals
    return data


def analyse(data: dict) -> list[Finding]:
    f: list[Finding] = []
    name = data["name"]
    if not data["addresses"]:
        return [Finding("Name does not resolve", "info", "dns", name, "No A/AAAA records found",
                        "Verify the name is correct.")]
    f.append(Finding("DNS resolution", "info", "dns", name,
                     "Resolves to: " + ", ".join(data["addresses"]), "None - informational."))
    txt = " ".join(data["records"].get("TXT", []))
    if "MX" in data["records"] and "v=spf1" not in txt:
        f.append(Finding("Missing SPF record", "medium", "dns", name,
                         "Domain has MX records but no SPF TXT record",
                         "Publish an SPF record to reduce email spoofing."))
    return f
