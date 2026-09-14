#!/usr/bin/env bash
# Send the current certificate to the other node and reload it there.
#
# Both nodes answer to the same name, so both need the same certificate, but
# only this one holds the DNS credential that can renew it. Keeping issuing in
# one place means the credential lives in one place too.
set -euo pipefail

CERT_KEY='/root/.ssh/fleet-cert'
MIRROR_HOST="root@$(/usr/local/sbin/site_config.py mirror.address)"
LIVE_DIR="/etc/letsencrypt/live/$(/usr/local/sbin/site_config.py certificate_name)"
LOCAL_DIR='/etc/sing-box/tls'

install -m 644 "$LIVE_DIR/fullchain.pem" "$LOCAL_DIR/fullchain.pem"
install -m 600 "$LIVE_DIR/privkey.pem" "$LOCAL_DIR/privkey.pem"
systemctl restart sing-box

tar cz -C "$LIVE_DIR" -h fullchain.pem privkey.pem \
  | ssh -i "$CERT_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=20 "$MIRROR_HOST"
