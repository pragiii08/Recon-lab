# Reconnaissance Report: 127.0.0.1

- Generated: 2026-11-06T08:03:15+00:00
- Tool: ReconLab v1.0.0 (authorised, in-scope testing only)

## Executive summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 4 |
| Medium | 3 |
| Low | 7 |
| Info | 4 |

## Findings

### RL-001 [HIGH] Outdated/vulnerable version banner on 2121

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** Banner: 220 (vsFTPd 2.3.4) lab-sim
- **Recommendation:** Upgrade to a supported release and hide version banners where possible.

### RL-002 [HIGH] Outdated/vulnerable version banner on 2222

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** Banner: SSH-2.0-OpenSSH_5.3 lab-sim
- **Recommendation:** Upgrade to a supported release and hide version banners where possible.

### RL-003 [HIGH] Outdated/vulnerable version banner on 8080

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** Banner: HTTP/1.0 501 Unsupported method ('HEAD')
Server: Apache/2.2.8 (LabSim) 
Date: Fri, 06 Nov 2026 08:03:15 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 357
- **Recommendation:** Upgrade to a supported release and hide version banners where possible.

### RL-004 [HIGH] Exposed path: /.git/HEAD

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** HTTP 200 for /.git/HEAD: b'ref: refs/heads/main\n'
- **Recommendation:** Remove sensitive files from the web root or restrict access.

### RL-005 [MEDIUM] Risky service exposed: ftp (lab) on 2121

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** FTP transmits credentials in clear text
- **Recommendation:** Disable the service, restrict by firewall, or replace with an encrypted alternative.

### RL-006 [MEDIUM] Cookie missing security attributes

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** SESSIONID lacks: HttpOnly, SameSite
- **Recommendation:** Set HttpOnly, Secure and SameSite on session cookies.

### RL-007 [MEDIUM] Missing security header: content-security-policy

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** Mitigates XSS and data injection
- **Recommendation:** Add the content-security-policy response header.

### RL-008 [LOW] Exposed path: /admin

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** HTTP 200 for /admin: b'<h1>Admin login (simulated)</h1>'
- **Recommendation:** Remove sensitive files from the web root or restrict access.

### RL-009 [LOW] Exposed path: /robots.txt

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** HTTP 200 for /robots.txt: b'User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n'
- **Recommendation:** Remove sensitive files from the web root or restrict access.

### RL-010 [LOW] Missing security header: referrer-policy

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** Limits referrer leakage
- **Recommendation:** Add the referrer-policy response header.

### RL-011 [LOW] Missing security header: x-content-type-options

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** Prevents MIME sniffing
- **Recommendation:** Add the x-content-type-options response header.

### RL-012 [LOW] Missing security header: x-frame-options

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** Prevents clickjacking
- **Recommendation:** Add the x-frame-options response header.

### RL-013 [LOW] Server version disclosure

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** Server: Apache/2.2.8 (LabSim) 
- **Recommendation:** Suppress version details in the Server header.

### RL-014 [LOW] Technology disclosure via X-Powered-By

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** X-Powered-By: PHP/5.2.4
- **Recommendation:** Remove the X-Powered-By header.

### RL-015 [INFO] Open port 2121/tcp (ftp (lab))

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** 220 (vsFTPd 2.3.4) lab-sim
- **Recommendation:** Confirm the service is required; close or firewall it otherwise.

### RL-016 [INFO] Open port 2222/tcp (ssh (lab))

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** SSH-2.0-OpenSSH_5.3 lab-sim
- **Recommendation:** Confirm the service is required; close or firewall it otherwise.

### RL-017 [INFO] Open port 8080/tcp (http-alt)

- **Category:** network
- **Target:** 127.0.0.1
- **Evidence:** HTTP/1.0 501 Unsupported method ('HEAD')
Server: Apache/2.2.8 (LabSim) 
Date: Fri, 06 Nov 2026 08:03:15 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 357
- **Recommendation:** Confirm the service is required; close or firewall it otherwise.

### RL-018 [INFO] Missing security header: permissions-policy

- **Category:** web
- **Target:** http://127.0.0.1:8080
- **Evidence:** Restricts browser feature access
- **Recommendation:** Add the permissions-policy response header.

## Raw data

```json
{
  "resolved": [
    "127.0.0.1"
  ],
  "ports": [
    {
      "port": 2121,
      "state": "open",
      "service": "ftp (lab)",
      "banner": "220 (vsFTPd 2.3.4) lab-sim"
    },
    {
      "port": 2222,
      "state": "open",
      "service": "ssh (lab)",
      "banner": "SSH-2.0-OpenSSH_5.3 lab-sim"
    },
    {
      "port": 8080,
      "state": "open",
      "service": "http-alt",
      "banner": "HTTP/1.0 501 Unsupported method ('HEAD')\nServer: Apache/2.2.8 (LabSim) \nDate: Fri, 06 Nov 2026 08:03:15 GMT\nConnection: close\nContent-Type: text/html;charset=utf-8\nContent-Length: 357"
    }
  ],
  "http": {
    "8080": {
      "url": "http://127.0.0.1:8080",
      "paths": {
        "/robots.txt": 200,
        "/.git/HEAD": 200,
        "/admin": 200,
        "/backup.zip": 404,
        "/server-status": 404,
        "/.env": 404
      },
      "status": 200,
      "headers": {
        "server": "Apache/2.2.8 (LabSim) ",
        "date": "Fri, 06 Nov 2026 08:03:15 GMT",
        "content-type": "text/html",
        "x-powered-by": "PHP/5.2.4",
        "set-cookie": "SESSIONID=abc123; Path=/"
      }
    }
  }
}
```
