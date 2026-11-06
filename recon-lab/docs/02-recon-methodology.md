# 02 - Reconnaissance Methodology

## Passive vs active
| | Passive | Active |
|---|---|---|
| Contact target? | No (public sources) | Yes (packets reach target) |
| Examples | WHOIS, DNS records, certificate transparency, search engines, public repos | Port scans, banner grabs, directory probing |
| Detectable | Practically no | Often logged / alerted |
| Authorisation | Generally fine | **Required** |

## DNS / domain information
Record types: A/AAAA (address), MX (mail), NS (nameservers), TXT (SPF/DKIM/verification), SOA, CNAME.
```bash
whois example.com; dig example.com ANY +noall +answer; dig +short MX example.com; dig -x 1.2.3.4
```
Look for: mail posture (SPF/DMARC), third-party hosting, forgotten hostnames.

## Network enumeration
1. Host discovery (`nmap -sn 192.168.56.0/24`)
2. Port discovery (`nmap -p- host`)
3. Service/version detection (`nmap -sV host`)
4. Web enumeration (headers, robots.txt, exposed paths)
5. Analyse -> rank by risk -> document

## Documenting findings
Every finding: **ID, title, severity, evidence, recommendation**. See `report-template.md`.
Severity guide: Critical (remote compromise) > High (clear exploitable weakness) > Medium (weak config)
> Low (hardening) > Info (observation).

## Rules of engagement checklist
- [ ] Written scope and permission
- [ ] Testing window agreed
- [ ] Rate limits respected
- [ ] No data exfiltration or DoS
- [ ] Findings stored securely
