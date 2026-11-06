# 04 - Lab Exercises (Day 6-10)

| Day | Focus | Task |
|---|---|---|
| 6 | Linux basics | Run `scripts/linux_basics_lab.sh`; explain every permission string |
| 7 | Passive recon | `python -m reconlab dns <domain you own>`; note MX/TXT/NS |
| 8 | Active recon | Start lab target; `scan`, `nmap`; map open ports to risks |
| 9 | Web tools | Capture with Wireshark; scan with ZAP; proxy with Burp |
| 10 | Reporting | `python -m reconlab full 127.0.0.1`; write executive summary using `report-template.md` |

Expected lab findings: outdated FTP/SSH banners, missing CSP/X-Frame-Options, `X-Powered-By` leak,
insecure cookie, exposed `/.git/HEAD`, `/admin`, `robots.txt` hints.
