#!/usr/bin/env bash
# Safe Linux fundamentals exercise: works only inside a temp sandbox directory.
set -euo pipefail
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
cd "$SANDBOX"

echo "== Files & directories =="; mkdir -p project/{src,logs}; touch project/src/app.py project/logs/app.log; ls -R project

echo; echo "== Permissions =="
echo "secret" > secret.txt
chmod 777 secret.txt; ls -l secret.txt; echo "^ too permissive"
chmod 600 secret.txt; ls -l secret.txt; echo "^ owner only"
stat -c '%A %a %U:%G %n' secret.txt

echo; echo "== Users & groups =="; id; echo "Login shells:"; grep -v nologin /etc/passwd | cut -d: -f1,7 | head -5

echo; echo "== Processes =="; ps -eo pid,user,comm --sort=-%mem | head -6
echo "Listening sockets:"; (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || true) | head -8

echo; echo "== Security checks =="
echo "SUID binaries (first 5):"; find /usr/bin -perm -4000 -type f 2>/dev/null | head -5 || true
echo "World-writable dirs in /tmp (sample):"; find /tmp -maxdepth 1 -perm -0002 2>/dev/null | head -3 || true
echo; echo "Done. Sandbox removed."
