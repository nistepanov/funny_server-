#!/usr/bin/env bash
# Quick Cloudflare tunnel in front of the local Xray WebSocket inbound.
# Quick tunnels get a fresh hostname on every start, so publish the current one
# to a file the operator can read instead of digging through the log.
set -euo pipefail

LOG='/var/log/cloudflared/quick.log'
HOST_FILE='/root/.cf-quick-host'

mkdir -p "$(dirname "$LOG")"
: > "$LOG"

cloudflared tunnel --url http://localhost:8080 --no-autoupdate >>"$LOG" 2>&1 &
tunnel_pid=$!

for _ in $(seq 1 30); do
    host=$(grep -oP 'https://\K[a-z0-9-]+\.trycloudflare\.com' "$LOG" | head -1 || true)
    if [ -n "$host" ]; then
        printf '%s' "$host" > "$HOST_FILE"
        break
    fi
    sleep 2
done

wait "$tunnel_pid"
