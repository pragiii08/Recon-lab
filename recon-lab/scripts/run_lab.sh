#!/usr/bin/env bash
# Start the practice target, run a full recon, stop the target.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m lab.target_server >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
sleep 1
python3 -m reconlab full 127.0.0.1 --ports 1-1024,2121,2222,8080 --out reports
