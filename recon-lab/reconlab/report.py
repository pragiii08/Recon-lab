"""Report generation: Markdown + JSON."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .findings import Finding, SEVERITY_ORDER


def build(target: str, findings: list[Finding], data: dict, out_dir: str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = out / f"recon-{target.replace('/', '_').replace(':', '_')}-{stamp}"
    counts = Counter(f.severity for f in findings)

    md = [f"# Reconnaissance Report: {target}", "",
          f"- Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
          f"- Tool: ReconLab v{__version__} (authorised, in-scope testing only)", "",
          "## Executive summary", "", "| Severity | Count |", "|---|---|"]
    for sev in SEVERITY_ORDER:
        md.append(f"| {sev.capitalize()} | {counts.get(sev, 0)} |")
    md += ["", "## Findings", ""]
    for f in findings:
        md += [f"### {f.fid} [{f.severity.upper()}] {f.title}", "",
               f"- **Category:** {f.category}", f"- **Target:** {f.target}",
               f"- **Evidence:** {f.evidence}", f"- **Recommendation:** {f.recommendation}", ""]
    md += ["## Raw data", "", "```json", json.dumps(data, indent=2, default=str), "```", ""]

    md_path, js_path = Path(f"{base}.md"), Path(f"{base}.json")
    md_path.write_text("\n".join(md), encoding="utf-8")
    js_path.write_text(json.dumps({"target": target, "summary": dict(counts),
                                   "findings": [f.to_dict() for f in findings], "data": data},
                                  indent=2, default=str), encoding="utf-8")
    return md_path, js_path
