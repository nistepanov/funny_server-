#!/usr/bin/env python3
"""Add one WireGuard peer and print its client config.

Called when the pool of prepared configs runs dry. The peer is written to the
server config and applied to the running interface in the same step, so a handed
out config works immediately rather than after the next restart.

Endpoints are names, never addresses: a replaced address is then a DNS edit
instead of a new file for everyone.
"""
import fcntl
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import site_config

SERVER_CONFIG = Path('/etc/wireguard/wg0.conf')
LOCK_PATH = Path('/var/lock/provision-peer.lock')
INTERFACE = 'wg0'
SUBNET_PREFIX = '10.49.0.'
ENDPOINT = site_config.value('wireguard_endpoint')
CLIENT_DNS = '172.18.67.174'
# Without this the client takes 1420, which overflows narrower paths — mobile
# networks especially. The tunnel then handshakes and carries no data, which
# reads as a block rather than a broken packet size.
CLIENT_MTU = 1200


def run(command, stdin=None):
    return subprocess.run(command, input=stdin, capture_output=True, text=True,
                          check=True).stdout.strip()


def next_free_address(config_text):
    taken = {int(n) for n in re.findall(rf'AllowedIPs\s*=\s*{re.escape(SUBNET_PREFIX)}(\d+)', config_text)}
    for candidate in range(2, 254):
        if candidate not in taken:
            return candidate
    raise SystemExit('subnet exhausted')


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'auto'
    if not re.fullmatch(r'[\w.-]{1,40}', name):
        raise SystemExit('bad name')

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        config_text = SERVER_CONFIG.read_text()
        host = next_free_address(config_text)
        private_key = run(['wg', 'genkey'])
        public_key = run(['wg', 'pubkey'], stdin=private_key + '\n')
        preshared_key = run(['wg', 'genpsk'])
        server_public = run(['wg', 'show', INTERFACE, 'public-key'])

        with SERVER_CONFIG.open('a') as handle:
            handle.write(f'\n[Peer]\n# {name}\nPublicKey = {public_key}\n'
                         f'PresharedKey = {preshared_key}\n'
                         f'AllowedIPs = {SUBNET_PREFIX}{host}/32\n')

        with tempfile.NamedTemporaryFile('w', delete=False) as psk_file:
            psk_file.write(preshared_key)
            psk_path = psk_file.name
        try:
            subprocess.run(['wg', 'set', INTERFACE, 'peer', public_key,
                            'preshared-key', psk_path,
                            'allowed-ips', f'{SUBNET_PREFIX}{host}/32'], check=True)
        finally:
            Path(psk_path).unlink(missing_ok=True)

        print(
            f'[Interface]\n'
            f'PrivateKey = {private_key}\n'
            f'Address = {SUBNET_PREFIX}{host}/32\n'
            f'DNS = {CLIENT_DNS}\n'
            f'MTU = {CLIENT_MTU}\n\n'
            f'[Peer]\n'
            f'PublicKey = {server_public}\n'
            f'PresharedKey = {preshared_key}\n'
            # No IPv6 on the tunnel, and wg-quick aborts the whole bring-up when
            # it cannot install the v6 route — the client is left with nothing.
            f'AllowedIPs = 0.0.0.0/0\n'
            f'Endpoint = {ENDPOINT}\n',
            end='')


if __name__ == '__main__':
    main()
