#!/usr/bin/env python3
"""Render a sing-box profile that keeps Russian traffic off the tunnel.

A plain vless:// subscription carries servers but no routing, so every byte
would take the long way round. This profile adds the rules: Russian domains and
addresses go straight out, everything else through whichever node is answering.

Rule sets are mirrored on this host — clients in Russia often cannot reach
GitHub, and a profile that silently fails to load its rules routes everything
through the tunnel again.
"""
import json
import urllib.parse
from pathlib import Path

import site_config

NODES_PATH = Path('/usr/local/etc/vpn-subscription/nodes.json')
TOKEN_PATH = Path('/usr/local/etc/vpn-subscription/token')
OUTPUT_DIR = Path('/var/www/sub')
RULES_BASE = 'https://' + site_config.value('page.primary') + '/rules'
RESERVE_PATH = Path('/usr/local/etc/vpn-subscription/reserve.txt')
HYSTERIA2_PATH = Path('/usr/local/etc/vpn-subscription/hysteria2.json')
RESERVE_GROUP = 'запасные (чужие серверы)'
PROBE_URL = 'https://www.gstatic.com/generate_204'
PROBE_INTERVAL = '10m'
PROBE_TOLERANCE = 50
# sing-box has no XHTTP transport, so those mirrored configs cannot come along
CONVERTIBLE_TRANSPORTS = ('tcp', 'grpc', 'ws', '')
RUSSIAN_RULE_SETS = ('geosite-category-ru', 'geosite-category-gov-ru', 'geoip-ru')


def hysteria2_outbound(node):
    secrets = json.loads(HYSTERIA2_PATH.read_text())
    return {
        'type': 'hysteria2',
        'tag': node['name'],
        'server': node['address'],
        'server_port': node['port'],
        'password': secrets['password'],
        'obfs': {'type': 'salamander', 'password': secrets['obfs_password']},
        'tls': {'enabled': True, 'server_name': secrets['sni']},
    }


def node_outbound(uuid, node):
    if node['kind'] == 'hysteria2':
        return hysteria2_outbound(node=node)
    outbound = {
        'type': 'vless',
        'tag': node['name'],
        'server': node['address'],
        'server_port': node['port'],
        'uuid': uuid,
        'tls': {
            'enabled': True,
            'utls': {'enabled': True, 'fingerprint': 'firefox'},
        },
    }
    if node['kind'] == 'reality':
        outbound['flow'] = 'xtls-rprx-vision'
        outbound['tls']['server_name'] = node['sni']
        outbound['tls']['reality'] = {
            'enabled': True,
            'public_key': node['public_key'],
            'short_id': node['short_id'],
        }
    else:
        outbound['tls']['server_name'] = node['address']
        outbound['transport'] = {
            'type': 'ws',
            'path': node['path'],
            'headers': {'Host': node['address']},
        }
    return outbound


def reserve_outbounds():
    """Convert mirrored community links into sing-box outbounds.

    They are the last resort when everything of ours is blocked, so leaving them
    out of this profile would make it strictly worse than the plain list.
    """
    if not RESERVE_PATH.exists():
        return []

    outbounds = []
    for line in RESERVE_PATH.read_text().splitlines():
        line = line.strip()
        if not line.startswith('vless://'):
            continue
        parsed = urllib.parse.urlparse(line)
        query = {key: value[0] for key, value in urllib.parse.parse_qs(parsed.query).items()}
        transport = query.get('type', 'tcp')
        if transport not in CONVERTIBLE_TRANSPORTS:
            continue
        if '@' not in parsed.netloc:
            continue

        credentials, _, authority = parsed.netloc.partition('@')
        host, _, port = authority.rpartition(':')
        if not port.isdigit():
            continue

        outbound = {
            'type': 'vless',
            'tag': urllib.parse.unquote(parsed.fragment) or f'резерв {len(outbounds) + 1}',
            'server': host,
            'server_port': int(port),
            'uuid': credentials,
        }

        security = query.get('security', 'none')
        if security in ('reality', 'tls'):
            tls = {
                'enabled': True,
                'server_name': query.get('sni', host),
                'utls': {'enabled': True, 'fingerprint': query.get('fp', 'chrome')},
            }
            if security == 'reality':
                tls['reality'] = {
                    'enabled': True,
                    'public_key': query.get('pbk', ''),
                    'short_id': query.get('sid', ''),
                }
                if not tls['reality']['public_key']:
                    continue
            outbound['tls'] = tls
            if query.get('flow'):
                outbound['flow'] = query['flow']

        if transport == 'grpc':
            outbound['transport'] = {'type': 'grpc',
                                     'service_name': query.get('serviceName', '')}
        elif transport == 'ws':
            outbound['transport'] = {'type': 'ws', 'path': query.get('path', '/'),
                                     'headers': {'Host': query.get('host', host)}}

        outbounds.append(outbound)
    return outbounds


def build_profile(config):
    uuid = config['uuid']
    nodes = config['nodes']
    reserve = reserve_outbounds()
    own_tags = [node['name'] for node in nodes]

    reserve_tags = [outbound['tag'] for outbound in reserve]
    # Strangers' machines enter the automatic choice as one candidate rather
    # than as a crowd. Excluding them entirely would strand everyone the moment
    # our own addresses go, which is the exact hour the fallback exists for;
    # listing each of them separately would let a lucky ping on any one of them
    # outvote every address we control.
    fallback_group = [{
        'type': 'urltest',
        'tag': RESERVE_GROUP,
        'outbounds': reserve_tags,
        'url': PROBE_URL,
        'interval': PROBE_INTERVAL,
        'tolerance': PROBE_TOLERANCE,
    }] if reserve_tags else []

    outbounds = [
        {
            'type': 'selector',
            'tag': 'proxy',
            'outbounds': ['auto', *own_tags,
                          *([RESERVE_GROUP] if reserve_tags else []),
                          *reserve_tags],
            'default': 'auto',
        },
        {
            'type': 'urltest',
            'tag': 'auto',
            'outbounds': [*own_tags,
                          *([RESERVE_GROUP] if reserve_tags else [])],
            'url': PROBE_URL,
            # Each round probes every node at once, so a short interval costs
            # battery and noise. The trade is how long a client can sit on a
            # node that died between rounds.
            'interval': PROBE_INTERVAL,
            'tolerance': PROBE_TOLERANCE,
        },
        *fallback_group,
        *[node_outbound(uuid, node) for node in nodes],
        *reserve,
        {'type': 'direct', 'tag': 'direct'},
    ]

    rule_sets = [
        {
            'type': 'remote',
            'tag': name,
            'format': 'binary',
            'url': f'{RULES_BASE}/{name}.srs',
            'download_detour': 'direct',
            'update_interval': '7d',
        }
        for name in RUSSIAN_RULE_SETS
    ]

    return {
        'log': {'level': 'warn'},
        'inbounds': [
            {
                'type': 'tun',
                'tag': 'tun-in',
                'address': ['172.19.0.1/30'],
                'auto_route': True,
                'strict_route': True,
                'stack': 'mixed',
            },
        ],
        'outbounds': outbounds,
        'route': {
            'rule_set': rule_sets,
            'rules': [
                {'action': 'sniff'},
                {'protocol': 'dns', 'action': 'hijack-dns'},
                {'ip_is_private': True, 'outbound': 'direct'},
                {'rule_set': list(RUSSIAN_RULE_SETS), 'outbound': 'direct'},
            ],
            'final': 'proxy',
            'auto_detect_interface': True,
        },
    }


def main():
    config = json.loads(NODES_PATH.read_text())
    config['nodes'] = [
        node for node in config['nodes']
        if node.get('enabled', True) and node['kind'] != 'xhttp'
    ]
    profile = build_profile(config)
    token = TOKEN_PATH.read_text().strip()
    target = OUTPUT_DIR / f'{token}.json'
    target.write_text(json.dumps(profile, ensure_ascii=False, indent=2))
    print(f'wrote {target} with {len(config["nodes"])} nodes')


if __name__ == '__main__':
    main()
