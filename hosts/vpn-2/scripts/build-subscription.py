#!/usr/bin/env python3
"""Render the node list into a base64 subscription clients can poll.

Clients hold one short link forever; swapping a burned address means editing
nodes.json and rerunning this, with nothing to redistribute.
"""
import base64
import json
import urllib.parse
from pathlib import Path

NODES_PATH = Path('/usr/local/etc/vpn-subscription/nodes.json')
TOKEN_PATH = Path('/usr/local/etc/vpn-subscription/token')
RESERVE_PATH = Path('/usr/local/etc/vpn-subscription/reserve.txt')
HYSTERIA2_PATH = Path('/usr/local/etc/vpn-subscription/hysteria2.json')
OUTPUT_DIR = Path('/var/www/sub')


def build_uri(uuid, node):
    query = {'encryption': 'none', 'type': 'tcp'}
    if node['kind'] == 'reality':
        query.update({
            'security': 'reality',
            'sni': node['sni'],
            'fp': 'firefox',
            'pbk': node['public_key'],
            'sid': node['short_id'],
            'flow': 'xtls-rprx-vision',
        })
    elif node['kind'] == 'xhttp':
        query.update({
            'type': 'xhttp',
            'security': 'tls',
            'sni': node['address'],
            'host': node['address'],
            'path': node['path'],
            'mode': 'packet-up',
            'fp': 'firefox',
        })
    else:
        query.update({
            'type': 'ws',
            'security': 'tls',
            'sni': node['address'],
            'host': node['address'],
            'path': node['path'],
            'fp': 'firefox',
        })
    fragment = urllib.parse.quote(node['name'])
    return f"vless://{uuid}@{node['address']}:{node['port']}?{urllib.parse.urlencode(query)}#{fragment}"


def build_hysteria2_uri(secrets, node):
    """The UDP entry points ship as their own list.

    Not every app that reads a plain list understands this protocol, and one
    line it cannot parse can cost the reader the whole list. Keeping them apart
    means an app that only speaks the older protocol never sees them.
    """
    query = {
        'sni': secrets['sni'],
        'obfs': 'salamander',
        'obfs-password': secrets['obfs_password'],
    }
    password = urllib.parse.quote(secrets['password'], safe='')
    fragment = urllib.parse.quote(node['name'])
    return (f"hy2://{password}@{node['address']}:{node['port']}"
            f"?{urllib.parse.urlencode(query)}#{fragment}")


def main():
    config = json.loads(NODES_PATH.read_text())
    config['nodes'] = [node for node in config['nodes'] if node.get('enabled', True)]
    own = [build_uri(config['uuid'], node) for node in config['nodes']
           if node['kind'] != 'hysteria2']
    # community configs lead while our own nodes are unproven from Russia
    mirrored = []
    if RESERVE_PATH.exists():
        mirrored = [line for line in RESERVE_PATH.read_text().splitlines() if line.strip()]
    uris = own + mirrored
    payload = base64.b64encode('\n'.join(uris).encode()).decode()

    token = TOKEN_PATH.read_text().strip()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / token).write_text(payload)
    hysteria2 = [node for node in config['nodes']
                 if node['kind'] == 'hysteria2']
    if hysteria2:
        secrets = json.loads(HYSTERIA2_PATH.read_text())
        links = [build_hysteria2_uri(secrets=secrets, node=node)
                 for node in hysteria2]
        (OUTPUT_DIR / f'{token}-hy2').write_text(
            base64.b64encode('\n'.join(links).encode()).decode())

    print(f'wrote {len(uris)} nodes and {len(hysteria2)} udp nodes')
    for uri in uris:
        print(' ', uri.split('#')[1])


if __name__ == '__main__':
    main()
