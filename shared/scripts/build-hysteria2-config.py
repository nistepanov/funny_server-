#!/usr/bin/env python3
"""Render the server config for the Hysteria2 entry points.

It exists beside the TLS-shaped one because the two fail to different things.
One is a TCP connection that looks like an ordinary visit to a large website;
this one is UDP that looks like a browser fetching over HTTP/3. A filter tuned
to recognise the first has no reason to touch the second, so a bad week for one
is not automatically a bad week for both.

Anything arriving without the right password is handed to a real website rather
than refused, so a prober sees a site instead of a service that only answers
its own clients.

Each public address gets its own listener rather than one catching them all.
A socket that accepts on every address replies from whichever the routing table
prefers, so a client that wrote to the second address hears back from the
first and ignores the answer. Connectionless traffic gives the kernel nothing
to match the reply against, which is why this bites here and not on TCP.
"""
import json
import subprocess
from pathlib import Path

SECRETS_PATH = Path('/usr/local/etc/vpn-subscription/hysteria2.json')
CONFIG_PATH = Path('/etc/sing-box/config.json')
TLS_DIR = Path('/etc/sing-box/tls')
LISTEN_PORT = 443
MASQUERADE_SITE = 'https://www.samsung.com'


def public_addresses():
    """Every public address of the interface carrying the default route."""
    route = subprocess.run(['ip', '-json', 'route', 'show', 'default'],
                           capture_output=True, text=True, check=True)
    device = json.loads(route.stdout)[0]['dev']
    addresses = subprocess.run(
        ['ip', '-4', '-json', 'addr', 'show', 'scope', 'global', 'dev', device],
        capture_output=True, text=True, check=True)
    return [entry['local']
            for link in json.loads(addresses.stdout)
            for entry in link['addr_info']]


def inbound(address, secrets):
    return {
        'type': 'hysteria2',
        'tag': f'hysteria2-{address}',
        'listen': address,
        'listen_port': LISTEN_PORT,
        'users': [{'name': 'family', 'password': secrets['password']}],
        'obfs': {
            'type': 'salamander',
            'password': secrets['obfs_password'],
        },
        'masquerade': MASQUERADE_SITE,
        'tls': {
            'enabled': True,
            'server_name': secrets['sni'],
            'certificate_path': str(TLS_DIR / 'fullchain.pem'),
            'key_path': str(TLS_DIR / 'privkey.pem'),
        },
    }


def main():
    secrets = json.loads(SECRETS_PATH.read_text())
    addresses = public_addresses()
    config = {
        'log': {'level': 'warn', 'timestamp': True},
        'inbounds': [inbound(address=address, secrets=secrets)
                     for address in addresses],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
    }
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2) + '\n')
    CONFIG_PATH.chmod(0o600)
    print(f'wrote {CONFIG_PATH} listening on {", ".join(addresses)}')


if __name__ == '__main__':
    main()
