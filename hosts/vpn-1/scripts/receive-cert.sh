#!/usr/bin/env bash
# Accept a renewed certificate from the node that holds the DNS credentials.
#
# Only that node can answer the issuing challenge, and the credential stays
# there rather than being copied here. This end takes the result and nothing
# else: the key that calls it can run this and no other command.
set -euo pipefail

TLS_DIR='/etc/sing-box/tls'

tar xz -C "$TLS_DIR"
chmod 644 "$TLS_DIR/fullchain.pem"
chmod 600 "$TLS_DIR/privkey.pem"
systemctl restart sing-box
