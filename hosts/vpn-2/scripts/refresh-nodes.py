#!/usr/bin/env python3
"""Find out which of our own nodes still answer from Russia, and what is wrong
with the rest.

Nodes look healthy from the server side long after Russia stops routing to
them, so health is measured from Russian vantage points instead. A failing node
stays in the subscription, moved to the end: the probes have been wrong before,
and a dropped node is lost to everyone for whom it still works.

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
# A page stopped by a filter only fails once its load times out.
PAGE_RESULT_DELAY_SECONDS = 40
BETWEEN_CHECKS_SECONDS = 8
# Every Russian network reaches these: a vantage point that cannot is broken itself.
# check-host limits checks per target, so the next one is used when it refuses.
REACHABLE_CONTROLS = ('ya.ru:443', 'yandex.ru:443', 'vk.com:443', 'mail.ru:443')
# Filtered Russian networks cannot load it: a vantage point that can sees past the filter.
FILTERED_CONTROL = 'https://www.youtube.com/'

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


def start_check(kind, target):
    """Ask every Russian vantage point to check a target; the request id, or None."""
    nodes = ''.join(f'&node={node}' for node in RU_NODES)
    query = urllib.parse.quote(target, safe='')
    try:
        started = json.loads(fetch(f'{CHECK_HOST_API}/check-{kind}?host={query}{nodes}'))
    except Exception as error:
        log(f'  probe start failed for {target}: {error}')
        return None
    request_id = started.get('request_id')
    if not request_id:
        log(f'  no request id for {target} (rate limited?)')
        return None
    return request_id


def read_check(target, request_id):
    """Each vantage point's answer, by short name; one still running has none yet."""
    if request_id is None:
        return {}
    try:
        results = json.loads(fetch(f'{CHECK_HOST_API}/check-result/{request_id}'))
    except Exception as error:
        log(f'  probe read failed for {target}: {error}')
        return {}
    return {node.split('.')[0]: result[0] for node, result in results.items()
            if isinstance(result, list) and result and result[0] is not None}


def connects(answer):
    return isinstance(answer, dict) and 'time' in answer


def loads(answer):
    return isinstance(answer, list) and bool(answer) and answer[0] == 1


def vantage_problem(name, reachable_target, reachable, filtered):
    """Why a vantage point's answers cannot be trusted, or None if they can."""
    if not connects(reachable.get(name)):
        return f'cannot reach {reachable_target}'
    if name not in filtered:
        return f'no answer about {FILTERED_CONTROL}'
    if loads(filtered[name]):
        return f'loads {FILTERED_CONTROL}, so it sees past the filter'
    return None


def start_reachable_check():
    """The first control target check-host accepts, with its request id."""
    for index, target in enumerate(REACHABLE_CONTROLS):
        if index:
            time.sleep(BETWEEN_CHECKS_SECONDS)
        request_id = start_check('tcp', target)
        if request_id is not None:
            return target, request_id
    return None, None


def trusted_vantages():
    """Short names of the vantage points that see what a filtered Russian network sees.

    None when check-host gave no control answers: that says nothing about the vantage points.
    """
    reachable_target, reachable_id = start_reachable_check()
    time.sleep(BETWEEN_CHECKS_SECONDS)
    filtered_id = start_check('http', FILTERED_CONTROL)
    if reachable_id is None or filtered_id is None:
        return None
    time.sleep(PAGE_RESULT_DELAY_SECONDS)
    reachable = read_check(reachable_target, reachable_id)
    filtered = read_check(FILTERED_CONTROL, filtered_id)
    if not reachable or not filtered:
        return None

    trusted = set()
    for node in RU_NODES:
        name = node.split('.')[0]
        problem = vantage_problem(name, reachable_target, reachable, filtered)
        if problem is None:
            trusted.add(name)
        else:
            log(f'  {name} ignored: {problem}')
    return trusted


def vantage_verdicts(address, port, trusted):
    """Whether each trusted vantage point connects to an address, or None if none said."""
    target = f'{address}:{port}'
    request_id = start_check('tcp', target)
    if request_id is None:
        return None
    time.sleep(RESULT_DELAY_SECONDS)
    verdicts = {name: connects(answer)
                for name, answer in read_check(target, request_id).items()
                if name in trusted}
    if not verdicts:
        return None
    log(f'  {target} -> ' + ' '.join(
        f'{name}={"ok" if ok else "fail"}' for name, ok in sorted(verdicts.items())))
    return verdicts


def probe_addresses(nodes, trusted):
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
        answers = vantage_verdicts(address, node['port'], trusted)
        verdicts[address] = None if answers is None else any(answers.values())
    return verdicts


def address_routes(address, trusted):
    """Whether the country still carries traffic to an address at all.

    A blacklisted address loses every port it has, the administrative one
    included, and that is what makes this question worth asking: an address
    that still answers somewhere is an address whose silence on one port
    belongs to whatever was listening there.
    """
    verdicts = vantage_verdicts(address, CONTROL_PORT, trusted)
    if not verdicts:
        return None
    return any(verdicts.values())


def decide(nodes, verdicts, trusted):
    """Each node this run could judge, with what is wrong with it, or None if nothing is.

    An entry point that accepts no connections borrows the verdict of its
    address, so a silent port there only counts once the address itself is silent.
    """
    routed = {}
    for node in nodes:
        address = node['address']
        alive = verdicts.get(address)
        if alive is None:
            continue
        if node['kind'] in TUNNELLED_KINDS:
            if not alive:
                yield node, f"Имя {address} не открывается из России"
                continue
            up = tunnel_is_up(address)
            if up is not None:
                yield node, None if up else f"За именем {address} нет туннеля — проверьте cloudflared"
            continue
        if alive:
            yield node, None
            continue
        if address not in routed:
            time.sleep(BETWEEN_CHECKS_SECONDS)
            routed[address] = address_routes(address, trusted)
            log(f'  {address}: entry port silent, address routed -> {routed[address]}')
        if routed[address] is False:
            yield node, f"Адрес {address} заблокирован в России целиком — нужен новый IP"
        elif node['kind'] in CONNECTIONLESS_KINDS:
            if routed[address]:
                yield node, None
        elif routed[address]:
            yield node, f"Адрес {address} виден из России, но точка на нём не отвечает — проверьте службу"
        else:
            yield node, f"Адрес {address} не отвечает из России"


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


def judge_nodes(nodes):
    """Record on each node what is wrong with it; what changed since the last run."""
    trusted = trusted_vantages()
    if trusted is None:
        log('check-host refused the control checks; leaving every node as it is')
        notify("check-host не дал проверить точки из России (лимит запросов). "
               "Точки оставлены как были.", key='probes-refused')
        return []
    if not trusted:
        log('no vantage point can be trusted; leaving every node as it is')
        notify("Проверка точек из России не работает: ни одному пробнику нельзя верить. "
               "Точки оставлены как были.", key='probes-untrusted')
        return []

    verdicts = probe_addresses(nodes, trusted)
    changes = []
    for node, fault in decide(nodes, verdicts, trusted):
        if fault != node.get('fault'):
            changes.append(f'{node["name"]}: {"ok" if fault is None else fault}')
        node['fault'] = fault
    return changes


def log_faults(nodes, changes):
    """Faults go to the log; the status page turns them into alerts."""
    faulty = [node for node in nodes if node.get('fault') is not None]
    for node in faulty:
        log(f'  {node["name"]}: {node["fault"]}')
    log(f'reachable nodes: {len(nodes) - len(faulty)} of {len(nodes)}'
        + (f' | changed: {"; ".join(changes)}' if changes else ''))


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
    changes = judge_nodes(config['nodes'])

    if arguments.dry_run:
        log('dry-run: ' + ('; '.join(changes) if changes else 'no changes'))
        return 0

    NODES_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2))
    if not arguments.skip_reserve:
        refresh_reserve()
    for builder in BUILDERS:
        subprocess.run([builder], capture_output=True)
    log_faults(config['nodes'], changes)
    return 0


if __name__ == '__main__':
    sys.exit(main())
