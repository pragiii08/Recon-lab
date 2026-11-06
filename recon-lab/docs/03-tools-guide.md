# 03 - Essential Security Tools

## Nmap
```bash
nmap -sn 192.168.56.0/24            # host discovery
nmap -sV -p 1-1024 127.0.0.1        # service versions
nmap -sC -sV -oA scan1 target       # default scripts, save all formats
nmap -p- --min-rate 500 target      # all ports (lab only)
```
Flags: `-Pn` skip ping, `-sS` SYN (root), `-O` OS guess, `-oX` XML (parsed by ReconLab).

## Wireshark
1. Capture on `lo` (loopback) while running `python -m reconlab scan 127.0.0.1`.
2. Filters: `tcp.flags.syn==1 && tcp.flags.ack==0` (SYN probes), `http`, `ip.addr==127.0.0.1`, `tcp.port==2121`.
3. Follow > TCP Stream to see the banner exchange.
4. Observe: a connect scan = SYN, SYN/ACK, ACK, RST. Closed port = RST/ACK.
Exercise: count distinct destination ports in the capture (*Statistics > Conversations*).

## Burp Suite (Community)
1. Proxy tab -> browser proxy 127.0.0.1:8080 (**change lab port**: run Burp on 8081 or lab on another port).
2. Browse `http://127.0.0.1:8080`; inspect requests in *HTTP history*.
3. Send to Repeater, modify requests; compare with missing-header findings from ReconLab.
Only test the lab target or authorised apps.

## OWASP ZAP
1. Quick Start -> *Automated Scan* -> URL `http://127.0.0.1:8080`.
2. Use the *Spider* then *Passive scan*; review *Alerts* (missing headers, cookie flags).
3. Export report (HTML/MD) and compare with `reports/example/`.

## Cross-checking exercise
Run ReconLab, Nmap, and ZAP on the lab; record which tool found which issue in a table.
