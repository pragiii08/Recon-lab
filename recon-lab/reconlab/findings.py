from __future__ import annotations

from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    title: str
    severity: str          # critical | high | medium | low | info
    category: str          # network | web | dns | config
    target: str
    evidence: str
    recommendation: str
    fid: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def number(findings: list[Finding]) -> list[Finding]:
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.target, f.title))
    for i, f in enumerate(findings, 1):
        f.fid = f"RL-{i:03d}"
    return findings
