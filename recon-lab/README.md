# Controlled Reconnaissance Lab

Module 02 project: **Linux, Security Tools & Reconnaissance** (Day 6-10).
A safe, scope-enforced lab to *discover, analyse and document* security findings.

> **Legal / ethical use only.** Scan only systems you own or have written permission to test.
> ReconLab refuses any target outside loopback/private ranges unless you add `--allow <CIDR>`.

## Features
| Module objective | Where it lives |
|---|---|
| Linux fundamentals (files, permissions, users, processes) | `docs/01-linux-fundamentals.md`, `scripts/linux_basics_lab.sh` |
| Passive vs active recon, DNS/domain info | `docs/02-recon-methodology.md`, `reconlab/dns_recon.py` |
| Network enumeration (port scan, banners, Nmap) | `reconlab/portscan.py`, `reconlab/nmap_wrapper.py` |
| Nmap, Wireshark, Burp Suite, OWASP ZAP | `docs/03-tools-guide.md` |
| Controlled lab + documented findings | `lab/target_server.py`, `reconlab/report.py`, `reports/example/` |

## Quick start (Python 3.9+, no dependencies)
```bash
git clone <your-repo-url> recon-lab && cd recon-lab
python3 -m lab.target_server &            # terminal 1: local practice target (127.0.0.1 only)
python3 -m reconlab full 127.0.0.1 --ports 1-1024,2121,2222,8080
```
Reports land in `reports/` as Markdown + JSON.

## Commands
```text
python -m reconlab scan 127.0.0.1 --ports 1-1024,8080   # TCP connect scan + banners
python -m reconlab dns example.com                      # DNS / reverse / dig records
python -m reconlab http http://127.0.0.1:8080           # headers, cookies, exposed paths
python -m reconlab nmap 127.0.0.1 --ports 1-1024        # nmap -sV (needs nmap installed)
python -m reconlab full 127.0.0.1                       # everything + report
python -m reconlab lab                                  # start practice target
```

## Safety design
- Scope allow-list checked on **every resolved IP** before any packet is sent.
- Worker cap (200) and short timeouts; no exploitation, brute force or payloads.
- Practice target binds to `127.0.0.1` and serves static text only.

## Project layout
```text
reconlab/   scope, portscan, dns_recon, http_audit, nmap_wrapper, findings, report, cli
lab/        local deliberately-weak target
docs/       Linux basics, methodology, tools guide, lab exercises, report template
scripts/    linux_basics_lab.sh, run_lab.sh
tests/      unit + integration tests (python -m unittest discover -s tests)
reports/    example output
```

## Tests
```bash
make test
```

## Roadmap ideas
Subdomain wordlists (authorised domains), TLS checks, HTML reports, Docker target.

Licensed under MIT.
