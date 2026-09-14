#!/usr/bin/env python3
"""Add one AmneziaWG peer and print its client config.

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
from pathlib import Path

import site_config

SERVER_CONFIG = Path('/etc/amnezia/amneziawg/awg0.conf')
CLIENT_DIR = Path('/etc/amnezia/amneziawg/clients')
LOCK_PATH = Path('/var/lock/provision-peer.lock')
INTERFACE = 'awg0'
SUBNET_PREFIX = '10.8.1.'
ENDPOINT = site_config.value('amneziawg_endpoint')
CLIENT_DNS = '1.1.1.1, 8.8.8.8'
# 1280 overflows the path on some links: wireguard-go then fails every data
# packet with EMSGSIZE while the handshake still succeeds, so the tunnel
# looks connected and carries nothing.
CLIENT_MTU = 1200
OBFUSCATION_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4')


def run(command, stdin=None):
    return subprocess.run(command, input=stdin, capture_output=True, text=True,
                          check=True).stdout.strip()


def next_free_address(config_text):
    taken = {int(n) for n in re.findall(rf'AllowedIPs\s*=\s*{re.escape(SUBNET_PREFIX)}(\d+)', config_text)}
    for candidate in range(2, 254):
        if candidate not in taken:
            return candidate
    raise SystemExit('subnet exhausted')


def obfuscation_settings(config_text):
    values = {}
    for key in OBFUSCATION_KEYS:
        match = re.search(rf'^{key}\s*=\s*(\S+)', config_text, re.MULTILINE)
        if match:
            values[key] = match.group(1)
    return values


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'auto'
    if not re.fullmatch(r'[\w.-]{1,40}', name):
        raise SystemExit('bad name')

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        config_text = SERVER_CONFIG.read_text()
        host = next_free_address(config_text)
        private_key = run(['awg', 'genkey'])
        public_key = run(['awg', 'pubkey'], stdin=private_key + '\n')
        server_public = run(['awg', 'show', INTERFACE, 'public-key'])

        with SERVER_CONFIG.open('a') as handle:
            handle.write(f'\n[Peer]\n# {name}\nPublicKey = {public_key}\n'
                         f'AllowedIPs = {SUBNET_PREFIX}{host}/32\n')

        subprocess.run(['awg', 'set', INTERFACE, 'peer', public_key,
                        'allowed-ips', f'{SUBNET_PREFIX}{host}/32'], check=True)

        settings = obfuscation_settings(config_text)
        obfuscation = '\n'.join(f'{key} = {value}' for key, value in settings.items())
        client_config = (
            f'[Interface]\n'
            f'Address = {SUBNET_PREFIX}{host}/32\n'
            f'DNS = {CLIENT_DNS}\n'
            f'PrivateKey = {private_key}\n'
            f'MTU = {CLIENT_MTU}\n'
            f'{obfuscation}\n\n'
            f'[Peer]\n'
            f'PublicKey = {server_public}\n'
            f'Endpoint = {ENDPOINT}\n'
            f'AllowedIPs = 0.0.0.0/0, ::/0\n'
            f'PersistentKeepalive = 25\n'
        )
        CLIENT_DIR.mkdir(parents=True, exist_ok=True)
        (CLIENT_DIR / f'{name}.conf').write_text(client_config)
        print(client_config, end='')


if __name__ == '__main__':
    main()
