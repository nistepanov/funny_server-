#!/usr/bin/env bash
# Push the pages and subscription to the other node.
#
# Delivery must survive losing this machine: without a mirror, a node that has
# just been blocked cannot tell its users where to go next. Only static content
# is copied — config issuing keeps its state here, so it stays single-homed.
#
# The geo databases are excluded: they are tens of megabytes and change perhaps
# twice a year, so shipping them on every run would cost more traffic than
# everything else combined. A weekly run with --geo carries them instead.
set -euo pipefail

MIRROR_KEY="$(/usr/local/sbin/site_config.py mirror.sync_key)"
MIRROR_HOST="root@$(/usr/local/sbin/site_config.py mirror.address)"
CONTENT_DIR='/var/www/sub'

if [[ "${1:-}" == '--geo' ]]; then
  tar_args=(cz ./rules)
else
  tar_args=(cz --exclude='files-*' --exclude='*.dat' .)
fi

cd "$CONTENT_DIR"
tar "${tar_args[@]}" \
  | ssh -i "$MIRROR_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=20 "$MIRROR_HOST"
