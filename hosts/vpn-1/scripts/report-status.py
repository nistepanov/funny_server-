#!/usr/bin/env python3
"""Report this host's state as JSON for the fleet status page.

Runs as a forced command over SSH, so the control host can collect without
holding shell access here.
"""
import json
import subprocess
from datetime import datetime, timezone

import site_config

UPLINK = 'ens3'
UNITS = ('xray', 'sing-box', 'cloudflared', 'cloudflared-sub',
         'sub-mirror', 'wg-quick@wg0')
FRESH_HANDSHAKE_SECONDS = 3600


def unit_state(unit):
    result = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
    return result.stdout.strip() or 'unknown'


def monthly_traffic_gb():
    try:
        output = subprocess.run(['vnstat', '--json', 'm', '-i', UPLINK],
                                capture_output=True, text=True, check=True).stdout
        months = json.loads(output)['interfaces'][0]['traffic']['month']
        today = datetime.now(timezone.utc)
        for entry in months:
            stamp = entry['date']
            if stamp['year'] == today.year and stamp['month'] == today.month:
                return round((entry['rx'] + entry['tx']) / 1e9, 1)
    except Exception:
        pass
    return None


def wireguard_peers(command, interface):
    """Peer totals plus how many handshook recently — the only sign of real use."""
    try:
        dump = subprocess.run([command, 'show', interface, 'dump'],
                              capture_output=True, text=True, check=True).stdout
    except Exception:
        return None
    now = datetime.now(timezone.utc).timestamp()
    total = active = 0
    for line in dump.splitlines()[1:]:
        fields = line.split('\t')
        if len(fields) < 5:
            continue
        total += 1
        stamp = int(fields[4] or 0)
        if stamp and now - stamp < FRESH_HANDSHAKE_SECONDS:
            active += 1
    return {'total': total, 'active': active}


def main():
    print(json.dumps({
        'host': 'vpn-1',
        'label': site_config.value('machine.label'),
        'address': site_config.value('machine.address'),
        'units': {unit: unit_state(unit) for unit in UNITS},
        'traffic_gb': monthly_traffic_gb(),
        'wireguard': wireguard_peers('wg', 'wg0'),
    }))


if __name__ == '__main__':
    main()
