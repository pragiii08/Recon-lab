"""Command line interface: python -m reconlab <command>"""
from __future__ import annotations

import argparse
import sys

from . import __version__, dns_recon, http_audit, nmap_wrapper, portscan, report
from .findings import Finding, number
from .scope import Scope, ScopeError

BANNER = f"ReconLab v{__version__} - Controlled Reconnaissance Lab (authorised targets only)"


def _scope(args) -> Scope:
    return Scope(extra=args.allow or [])


def cmd_scan(args) -> int:
    scope = _scope(args)
    ips = scope.check(args.target)
    ports = portscan.parse_ports(args.ports)
    print(f"[*] {args.target} -> {', '.join(ips)}; scanning {len(ports)} ports")
    res = portscan.scan(ips[0], ports, args.timeout, args.workers)
    for r in res:
        print(f"  {r.port:>5}/tcp  open  {r.service:<12} {r.banner[:60]!r}")
    if not res:
        print("  no open ports found")
    return 0


def cmd_dns(args) -> int:
    data = dns_recon.lookup(args.name)
    print(f"[*] {args.name}: {', '.join(data['addresses']) or 'no records'}")
    for ip, ptr in data["reverse"].items():
        print(f"  PTR {ip} -> {ptr or '(none)'}")
    for rtype, vals in data["records"].items():
        print(f"  {rtype}: {'; '.join(vals)}")
    return 0


def cmd_http(args) -> int:
    from urllib.parse import urlparse
    u = urlparse(args.url if "://" in args.url else "http://" + args.url)
    _scope(args).check(u.hostname or "")
    findings, meta = http_audit.audit(args.url)
    for f in number(findings):
        print(f"  {f.fid} [{f.severity:<6}] {f.title}")
    print(f"[*] {len(findings)} findings (HTTP {meta['status']})")
    return 0


def cmd_nmap(args) -> int:
    rows = nmap_wrapper.run(args.target, args.ports, _scope(args))
    for r in rows:
        print(f"  {r['port']}/{r['proto']}  {r['service']}  {r['product']} {r['version']}".rstrip())
    return 0


def cmd_full(args) -> int:
    scope = _scope(args)
    ips = scope.check(args.target)
    findings: list[Finding] = []
    data: dict = {"resolved": ips}
    print(f"[1/3] DNS information for {args.target}")
    if not args.target.replace(".", "").isdigit() and ":" not in args.target:
        d = dns_recon.lookup(args.target)
        data["dns"] = d
        findings += dns_recon.analyse(d)
    print(f"[2/3] Port scan {ips[0]} ({args.ports})")
    res = portscan.scan(ips[0], portscan.parse_ports(args.ports), args.timeout, args.workers)
    data["ports"] = [r.__dict__ for r in res]
    findings += portscan.analyse(args.target, res)
    print("[3/3] HTTP audit of web ports")
    data["http"] = {}
    for r in res:
        if r.port in portscan.HTTP_PORTS:
            scheme = "https" if r.port in (443, 8443) else "http"
            try:
                f, meta = http_audit.audit(f"{scheme}://{ips[0]}:{r.port}")
                findings += f
                data["http"][str(r.port)] = meta
            except OSError as exc:
                print(f"  ! HTTP audit failed on {r.port}: {exc}")
    number(findings)
    md, js = report.build(args.target, findings, data, args.out)
    print(f"[+] {len(findings)} findings\n[+] Report: {md}\n[+] JSON:   {js}")
    return 0


def cmd_lab(args) -> int:
    from lab import target_server
    target_server.main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconlab", description=BANNER)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, ports=True):
        sp.add_argument("--allow", action="append", metavar="CIDR",
                        help="extra CIDR you are authorised to test (repeatable)")
        if ports:
            sp.add_argument("--ports", default="1-1024,2121,2222,3306,5432,6379,8000,8080,8443")
            sp.add_argument("--timeout", type=float, default=0.5)
            sp.add_argument("--workers", type=int, default=100)

    s = sub.add_parser("scan", help="TCP port scan + banner grab"); s.add_argument("target"); common(s); s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("dns", help="DNS/domain info (passive-style)"); s.add_argument("name"); s.set_defaults(fn=cmd_dns)
    s = sub.add_parser("http", help="HTTP security header/path audit"); s.add_argument("url"); common(s, False); s.set_defaults(fn=cmd_http)
    s = sub.add_parser("nmap", help="Run nmap -sV on an in-scope target"); s.add_argument("target"); s.add_argument("--ports", default="1-1024"); common(s, False); s.set_defaults(fn=cmd_nmap)
    s = sub.add_parser("full", help="DNS + scan + HTTP audit + report"); s.add_argument("target"); s.add_argument("--out", default="reports"); common(s); s.set_defaults(fn=cmd_full)
    s = sub.add_parser("lab", help="Start the local practice target"); s.set_defaults(fn=cmd_lab)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(BANNER)
    try:
        return args.fn(args)
    except (ScopeError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
