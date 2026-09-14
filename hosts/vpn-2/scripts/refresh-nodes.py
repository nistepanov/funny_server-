#!/usr/bin/env python3
"""Keep the subscription pointing at whatever still answers from Russia.

Nodes look healthy from the server side long after Russia stops routing to
them, so health is measured from Russian vantage points instead. Dead nodes are
dropped from the subscription rather than deleted, so they come back on their
own if a block is lifted.

Public community configs are mirrored as a last resort: they run on strangers'
machines, so they sit at the bottom and are labelled as such.
"""
import argparse
import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = Path('/usr/local/etc/vpn-subscription')
NODES_PATH = CONFIG_DIR / 'nodes.json'
RESERVE_PATH = CONFIG_DIR / 'reserve.txt'
LOG_PATH = Path('/var/log/refresh-nodes.log')

RU_NODES = ('ru1.node.check-host.net', 'ru2.node.check-host.net', 'ru3.node.check-host.net')
CHECK_HOST_API = 'https://check-host.net'
USER_AGENT = 'refresh-nodes/1.0'
RESULT_DELAY_SECONDS = 22
BETWEEN_CHECKS_SECONDS = 8

PUBLIC_SOURCE = ('https://raw.githubusercontent.com/igareck/'
                 'vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt')
# Only transports that still get through; ws is effectively dead in Russia.
USABLE_TRANSPORTS = ('xhttp', 'grpc', 'tcp')
RESERVE_LIMIT = 20
# Entry points reached through an edge network rather than their own address.
TUNNELLED_KINDS = ('cdn', 'xhttp')
# Entry points that never accept a connection, so nothing a vantage point can
# reach out and touch.
CONNECTIONLESS_KINDS = ('hysteria2',)
# Every machine also answers on the port it is administered through. Asked once
# an entry port has gone quiet, it tells an address the country has stopped
# routing from a service of ours that fell over behind one it still routes.
CONTROL_PORT = 22

def notify(text, key=None):
    """Alerting must never block the refresh itself."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'notify', '/usr/local/sbin/notify.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.send(text, key=key)
    except Exception:
        pass


BUILDERS = (
    '/usr/local/sbin/build-subscription.py',
    '/usr/local/sbin/build-singbox-profile.py',
)


def log(message):
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    line = f'{stamp} {message}'
    print(line)
    with LOG_PATH.open('a') as handle:
        handle.write(line + '\n')


def fetch(url):
    request = urllib.request.Request(url, headers={
        'Accept': 'application/json',
        'User-Agent': USER_AGENT,
    })
    with urllib.request.urlopen(request, timeout=40) as response:
        return response.read()


def vantage_verdicts(address, port):
    """What each Russian vantage point says about one address, or None."""
    target = urllib.parse.quote(f'{address}:{port}')
    nodes = ''.join(f'&node={node}' for node in RU_NODES)
    try:
        started = json.loads(fetch(f'{CHECK_HOST_API}/check-tcp?host={target}{nodes}'))
    except Exception as error:
        log(f'  probe start failed for {address}: {error}')
        return None
    request_id = started.get('request_id')
    if not request_id:
        log(f'  no request id for {address} (rate limited?)')
        return None

    time.sleep(RESULT_DELAY_SECONDS)
    try:
        results = json.loads(fetch(f'{CHECK_HOST_API}/check-result/{request_id}'))
    except Exception as error:
        log(f'  probe read failed for {address}: {error}')
        return None

    verdicts = {}
    for node, result in results.items():
        entry = result[0] if isinstance(result, list) and result else None
        verdicts[node.split('.')[0]] = isinstance(entry, dict) and 'time' in entry
    if not verdicts:
        return None
    log(f'  {address}:{port} -> ' + ' '.join(
        f'{name}={"ok" if ok else "fail"}' for name, ok in sorted(verdicts.items())))
    return verdicts


def probe_addresses(nodes):
    """One verdict per address, however many entry points sit on it.

    Entry points share machines, and a blocked address takes every one of them
    down together, so asking separately about each spends a scarce probe to
    learn something already known. What this cannot see is a filter that drops
    only connectionless traffic and passes the rest: the address keeps
    answering here while half of what it offers is unusable. Only a client
    inside the country can tell those apart.

    The reverse mistake is corrected afterwards, because it is cheap to catch
    and it has already cost us a working entry point for days.
    """
    verdicts = {}
    for node in nodes:
        address = node['address']
        if address in verdicts:
            continue
        if verdicts:
            time.sleep(BETWEEN_CHECKS_SECONDS)
        answers = vantage_verdicts(address, node['port'])
        verdicts[address] = None if answers is None else any(answers.values())
    return verdicts


def address_routes(address):
    """Whether the country still carries traffic to an address at all.

    A blacklisted address loses every port it has, the administrative one
    included, and that is what makes this question worth asking: an address
    that still answers somewhere is an address whose silence on one port
    belongs to whatever was listening there.
    """
    verdicts = vantage_verdicts(address, CONTROL_PORT)
    if not verdicts:
        return None
    return any(verdicts.values())


def decide(nodes, verdicts):
    """What this run concludes about each node, or None where it learnt nothing.

    An entry point that accepts no connections cannot be measured directly, so
    it borrows the verdict of its address — and where the port is shared it
    borrows from whatever else answers there. That is how a page falling over
    read as a blocked address and took a healthy UDP entry point off the
    subscription with it. Before believing that, the address is asked whether it
    is routed at all.
    """
    routed = {}
    for node in nodes:
        address = node['address']
        alive = verdicts.get(address)
        if alive and node['kind'] in TUNNELLED_KINDS:
            alive = tunnel_is_up(address)
        if alive is False and node['kind'] in CONNECTIONLESS_KINDS:
            if address not in routed:
                time.sleep(BETWEEN_CHECKS_SECONDS)
                routed[address] = address_routes(address)
                log(f'  {address}: entry port silent, address routed'
                    f' -> {routed[address]}')
            alive = routed[address]
        yield node, alive


def tunnel_is_up(hostname):
    """Whether anything is still behind an edge name.

    The edge answers on its own addresses, so a probe from Russia reports a
    healthy connection to a name with nothing left behind it. Asked directly,
    the edge admits it: a missing origin comes back as a server error of its
    own making.
    """
    request = urllib.request.Request(f'https://{hostname}/',
                                     headers={'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status < 500
    except urllib.error.HTTPError as error:
        return error.code < 500
    except Exception as error:
        log(f'  origin check failed for {hostname}: {error}')
        return None


def refresh_reserve():
    """Mirror a few community configs as an emergency fallback."""
    try:
        raw = fetch(PUBLIC_SOURCE).decode(errors='ignore').strip()
    except Exception as error:
        log(f'reserve: fetch failed ({error}); keeping previous list')
        return
    if 'vless://' not in raw:
        raw = base64.b64decode(raw + '=' * (-len(raw) % 4)).decode(errors='ignore')

    picked = []
    for line in raw.splitlines():
        if not line.startswith('vless://'):
            continue
        query = urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
        if query.get('type', [''])[0] not in USABLE_TRANSPORTS:
            continue
        base = line.split('#')[0]
        picked.append(f'{base}#{urllib.parse.quote(f"общий {len(picked) + 1} (чужой сервер)")}')
        if len(picked) >= RESERVE_LIMIT:
            break

    if picked:
        RESERVE_PATH.write_text('\n'.join(picked) + '\n')
        log(f'reserve: {len(picked)} configs mirrored')
    else:
        log('reserve: nothing usable found; keeping previous list')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--skip-reserve', action='store_true')
    parser.add_argument('--reserve-only', action='store_true')
    arguments = parser.parse_args()

    if arguments.reserve_only:
        refresh_reserve()
        for builder in BUILDERS:
            subprocess.run([builder], capture_output=True)
        return 0

    config = json.loads(NODES_PATH.read_text())
    log('probing own nodes from Russia')

    verdicts = probe_addresses(config['nodes'])

    changes = []
    for node, alive in decide(config['nodes'], verdicts):
        if alive is None:
            continue  # inconclusive: leave the node as it is
        was = node.get('enabled', True)
        if alive != was:
            changes.append(f'{node["name"]}: {"on" if alive else "OFF"}')
        node['enabled'] = alive

    if arguments.dry_run:
        log('dry-run: ' + (', '.join(changes) if changes else 'no changes'))
        return 0

    NODES_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2))
    if not arguments.skip_reserve:
        refresh_reserve()
    for builder in BUILDERS:
        subprocess.run([builder], capture_output=True)

    enabled = [n['name'] for n in config['nodes'] if n.get('enabled', True)]
    if changes:
        notify('Изменилось состояние точек: ' + ', '.join(changes)
               + f'. Работает {len(enabled)} из {len(config["nodes"])}.',
               key='node-change')
    if not enabled:
        notify('Ни одна своя точка не работает — люди сидят на публичных.',
               key='all-down')
    log(f'active nodes: {len(enabled)} ({", ".join(enabled) or "none"})'
        + (f' | changed: {", ".join(changes)}' if changes else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
