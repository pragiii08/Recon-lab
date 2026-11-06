# 01 - Linux Fundamentals for Security

## Files & directories
`/etc` config, `/var/log` logs, `/home` users, `/tmp` world-writable, `/proc` live process info.
```bash
pwd; ls -la; cd /var/log; find / -name "*.conf" 2>/dev/null | head
cat file; less file; head -n5 file; tail -f /var/log/syslog; grep -ri "failed" /var/log/auth.log
```

## Permissions
`-rwxr-x---` = owner rwx, group r-x, others none. Octal: r=4 w=2 x=1 -> `chmod 750 file`.
```bash
chmod 640 secret.txt; chown alice:dev secret.txt
find / -perm -4000 -type f 2>/dev/null     # SUID binaries (privilege-escalation review)
umask                                       # default permission mask
```
Security tip: least privilege - never `chmod 777`.

## Users & groups
```bash
id; whoami; groups; cat /etc/passwd; sudo -l
sudo useradd -m analyst; sudo usermod -aG sudo analyst; sudo passwd -l olduser
```
`/etc/shadow` holds password hashes (root-readable only).

## Processes
```bash
ps aux; top; htop; pstree -p; kill -15 PID; ss -tulpn; lsof -i
```

## Security basics
- Update: `sudo apt update && sudo apt upgrade`
- Firewall: `sudo ufw enable; sudo ufw allow 22/tcp`
- SSH hardening: key auth, `PermitRootLogin no`
- Logs: `journalctl -u ssh`, `last`, `lastb`
- Integrity: `sha256sum file`

Practice with `scripts/linux_basics_lab.sh`.
