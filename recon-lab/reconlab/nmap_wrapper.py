"""Optional Nmap integration. Runs nmap only against in-scope targets."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from .scope import Scope, ScopeError


def available() -> bool:
    return shutil.which("nmap") is not None


def run(target: str, ports: str, scope: Scope, timeout: int = 300) -> list[dict]:
    scope.check(target)
    if not available():
        raise ScopeError("nmap is not installed (sudo apt install nmap)")
    cmd = ["nmap", "-sV", "-Pn", "-p", ports, "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return parse_xml(proc.stdout)


def parse_xml(xml_text: str) -> list[dict]:
    rows = []
    root = ET.fromstring(xml_text)
    for port in root.iter("port"):
        state = port.find("state")
        svc = port.find("service")
        if state is None or state.get("state") != "open":
            continue
        rows.append({
            "port": int(port.get("portid")),
            "proto": port.get("protocol"),
            "service": svc.get("name") if svc is not None else "unknown",
            "product": (svc.get("product") or "") if svc is not None else "",
            "version": (svc.get("version") or "") if svc is not None else "",
        })
    return rows
