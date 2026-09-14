#!/usr/bin/env python3
"""Render a status page for the whole VPN fleet.

Nodes cannot answer "am I reachable from Russia" about themselves, so this
gathers what the probes found and what each machine reports, and states plainly
which routes clients can actually use right now.
"""
import html
import json
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import site_config

CONFIG_DIR = Path('/usr/local/etc/vpn-subscription')
NODES_PATH = CONFIG_DIR / 'nodes.json'
TOKEN_PATH = CONFIG_DIR / 'admin-token'
RESERVE_PATH = CONFIG_DIR / 'reserve.txt'
REFRESH_LOG = Path('/var/log/refresh-nodes.log')
ISSUED_PATH = Path('/var/lib/vpn-configs/issued.json')
ALERT_LOG = Path('/var/log/vpn-alerts.log')
PROBLEMS_PATH = Path('/var/lib/vpn-configs/problems-seen.json')
TOTAL_LIMIT = 40
OUTPUT_DIR = Path('/var/www/sub')

LOCAL_UNITS = ('xray', 'sing-box', 'cloudflared', 'cloudflared-sub',
               'sub-server', 'awg-quick@awg0')
# The two names the pages answer to, and the address behind each. The name that
# skips the edge network exists precisely for when the other one is unreachable,
# so a service being up is not enough: each door gets knocked on separately.
ENTRY_POINTS = ((site_config.value('page.primary'), None),
                (site_config.value('page.spare'), site_config.value('page.spare_address')))
ENTRY_TIMEOUT_SECONDS = 15
DIRECT_ADDRESS_PATH = CONFIG_DIR / 'direct-address'
# A unit name says what runs, never what breaks for whom when it stops. The
# page is read while something is already wrong, so each row names the way in
# that goes down with it, in the same words the instructions use.
UNIT_ROLES = {
    'xray': 'Способ 1 — прямые точки и через CDN',
    'sing-box': 'Способ 1 — запасная ссылка, Hysteria2 по UDP',
    'cloudflared': 'Туннель для точек входа через CDN',
    'cloudflared-sub': 'Туннель для страницы и подписки',
    'sub-server': 'Страница, подписка и выдача конфигов',
    'sub-mirror': 'Страница и подписка — копия, без выдачи',
    'wg-quick@wg0': 'Способ 2 — WireGuard',
    'awg-quick@awg0': 'Способ 3 — AmneziaWG',
}
# Both machines hand out peers, but not of the same kind, and the difference is
# the whole reason one survives blocks the other does not.
PEER_KINDS = {'awg-quick@awg0': 'AmneziaWG', 'wg-quick@wg0': 'WireGuard'}
REMOTE_HOSTS = ((site_config.value('mirror.address'), site_config.value('mirror.collector_key')),)
FRESH_HANDSHAKE_SECONDS = 3600
LOG_TAIL_LINES = 20


def notify(text, key=None):
    """Alerting must never stop the page from being written."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'notify', '/usr/local/sbin/notify.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.send(text, key=key)
    except Exception as error:
        print(f'notify failed: {error}')


def announce(problems):
    """Say it once when something breaks, and once when it comes back.

    This page is only opened by someone who already suspects trouble, so a
    fault that merely appears on it is a fault nobody hears about.

    A problem has to survive two runs before it is worth a message. One failed
    collection is almost always the network between the machines, and it clears
    itself before anyone could act on it.
    """
    try:
        state = json.loads(PROBLEMS_PATH.read_text())
    except Exception:
        state = {}
    current = set(problems)
    pending = set(state.get('pending', ()))
    announced = set(state.get('announced', ()))

    confirmed = current & pending
    for problem in sorted(confirmed - announced):
        notify(problem, key=problem)
    if announced and not current:
        notify("Всё снова работает.", key='recovered')

    PROBLEMS_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROBLEMS_PATH.write_text(json.dumps(
        {'pending': sorted(current),
         'announced': sorted(confirmed | (announced & current))},
        ensure_ascii=False))


def unit_state(unit):
    result = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
    return result.stdout.strip() or 'unknown'


def monthly_traffic_gb():
    try:
        output = subprocess.run(['vnstat', '--json', 'm'], capture_output=True, text=True, check=True).stdout
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


def issued_configs():
    """Who took client configs, and how close the shared link is to its cap."""
    try:
        state = json.loads(ISSUED_PATH.read_text())
    except Exception:
        return 0, []
    rows = []
    for protocol, visitors in state.items():
        for visitor, files in visitors.items():
            rows.append((protocol, visitor, len(files)))
    rows.sort(key=lambda row: -row[2])
    return sum(row[2] for row in rows), rows


def direct_entry():
    """The name this machine answers on without the edge network, if any."""
    address = DIRECT_ADDRESS_PATH.read_text().strip() if DIRECT_ADDRESS_PATH.exists() else ''
    if not address:
        return None
    return next((name for name, known in ENTRY_POINTS if known == address), address)


def collect_local():
    return {
        'host': 'vpn-2',
        'label': site_config.value('machine.label'),
        'address': site_config.value('machine.address'),
        'units': {unit: unit_state(unit) for unit in LOCAL_UNITS},
        'traffic_gb': monthly_traffic_gb(),
        'wireguard': wireguard_peers('awg', 'awg0'),
        'direct_entry': direct_entry(),
    }


def collect_remote(address, key_path):
    """Pull a peer machine's report over its forced-command SSH key."""
    try:
        output = subprocess.run(
            ['ssh', '-i', key_path, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
             '-o', 'StrictHostKeyChecking=no', f'root@{address}'],
            capture_output=True, text=True, timeout=40).stdout
        return json.loads(output)
    except Exception as error:
        return {'host': address, 'label': 'недоступен', 'address': address,
                'error': str(error)[:120], 'units': {}, 'traffic_gb': None, 'wireguard': None}


def entry_answers(name, address):
    """Whether a page entry point still speaks for itself.

    Knocking on the address rather than the name where one is known: a resolver
    that has not caught up says nothing about whether readers can get through.
    """
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection((address or name, 443),
                                       timeout=ENTRY_TIMEOUT_SECONDS)
        with context.wrap_socket(raw, server_hostname=name) as secure:
            secure.sendall(f'HEAD /help/ HTTP/1.1\r\nHost: {name}\r\n'
                           'Connection: close\r\n\r\n'.encode())
            status = secure.recv(64).decode('ascii', 'replace')
    except Exception:
        return False
    return ' 200 ' in status or ' 30' in status


def find_problems(nodes, machines):
    problems = []
    for node in nodes:
        if not node.get('enabled', True):
            problems.append(f'Точка «{node["name"]}» ({node["address"]}) не видна из России')
    for machine in machines:
        if machine.get('error'):
            problems.append(f'Машина {machine["host"]} не отвечает на сбор данных')
        for unit, state in machine.get('units', {}).items():
            if state != 'active':
                problems.append(f'{machine["host"]}: служба {unit} не работает ({state})')
    for name, address in ENTRY_POINTS:
        if not entry_answers(name, address):
            problems.append(f'Страница и подписка не открываются по адресу {name}')
    if not any(node.get('enabled', True) for node in nodes):
        problems.insert(0, 'Ни одна своя точка не работает — люди сидят на публичных')
    return problems


def machine_card(machine):
    units = machine.get('units', {})
    rows = []
    for unit, state in units.items():
        css = 'ok' if state == 'active' else 'bad'
        role = UNIT_ROLES.get(unit)
        role_html = f'<span class="role">{html.escape(role)}</span>' if role else ''
        rows.append(f'<tr><td class="unit mono">{html.escape(unit)}{role_html}</td>'
                    f'<td><span class="chip {css}">{html.escape(state)}</span></td></tr>')
    peers = machine.get('wireguard')
    if peers:
        css = 'ok' if peers['active'] else 'idle'
        kind = next((name for unit, name in PEER_KINDS.items() if unit in units),
                    'WireGuard')
        rows.append(f'<tr><td>пиры {html.escape(kind)}</td>'
                    f'<td><span class="chip {css}">'
                    f'{peers["active"]} из {peers["total"]} за час</span></td></tr>')
    entry = machine.get('direct_entry')
    if entry:
        rows.append(f'<tr><td>прямой вход мимо CDN</td>'
                    f'<td class="mono">{html.escape(entry)}</td></tr>')
    traffic = machine.get('traffic_gb')
    traffic_text = f'{traffic} ГБ' if traffic is not None else 'нет данных'
    rows.append(f'<tr><td>трафик за месяц</td><td class="mono">{traffic_text}</td></tr>')

    error = machine.get('error')
    banner = f'<div class="err">{html.escape(error)}</div>' if error else ''
    return (f'<div class="card"><div class="card-head">{html.escape(machine["host"])}'
            f'<span>{html.escape(machine["label"])} · {html.escape(machine["address"])}</span></div>'
            f'{banner}<table>{"".join(rows)}</table></div>')


def render(nodes, machines, reserve_count, problems, log_lines, issued_total, issued):
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    live = sum(1 for node in nodes if node.get('enabled', True))

    node_rows = ''.join(
        f'<tr><td>{html.escape(node["name"])}</td>'
        f'<td class="mono">{html.escape(node["address"])}:{node["port"]}</td>'
        f'<td class="mono">{html.escape(node["kind"])}</td>'
        f'<td><span class="chip {"ok" if node.get("enabled", True) else "bad"}">'
        f'{"работает" if node.get("enabled", True) else "заблокирован"}</span></td></tr>'
        for node in nodes)

    if problems:
        problem_html = ''.join(f'<li>{html.escape(p)}</li>' for p in problems)
        problems_block = f'<div class="alert"><b>Не работает</b><ul>{problem_html}</ul></div>'
    else:
        problems_block = '<div class="fine">Всё работает</div>'

    log_html = '\n'.join(f'<div class="line">{html.escape(l)}</div>' for l in log_lines)
    alerts = ALERT_LOG.read_text().splitlines()[-12:][::-1] if ALERT_LOG.exists() else []
    alert_html = '\n'.join(
        f'<div class="line">{html.escape(a)}</div>' for a in alerts) or 'пока тихо'
    issued_rows = ''.join(
        f'<tr><td class="mono">{html.escape(visitor)}</td>'
        f'<td class="mono">{html.escape(protocol)}</td>'
        f'<td>{count} шт</td></tr>'
        for protocol, visitor, count in issued) or '<tr><td>пока никто не забирал</td></tr>'

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>Состояние VPN</title>
<style>
:root {{ --bg:#f5f6f8; --card:#fff; --ink:#16181d; --muted:#5b6270; --line:#e0e4ea;
        --ok-bg:#e3f1e9; --ok:#1b7a4d; --bad-bg:#fae7e5; --bad:#b3261e;
        --idle-bg:#eceff4; --idle:#5b6270; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0f1217; --card:#171b22; --ink:#e6e9ef; --muted:#949cab; --line:#262c36;
          --ok-bg:#15271e; --ok:#4fb183; --bad-bg:#2b1917; --bad:#e8796f;
          --idle-bg:#1d222b; --idle:#949cab; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:24px 16px 64px; background:var(--bg); color:var(--ink);
       font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:860px; margin:0 auto; }}
h1 {{ font-size:22px; margin:0 0 4px; }}
.sub {{ color:var(--muted); font-size:13px; margin:0 0 24px; }}
h2 {{ font-size:13px; text-transform:uppercase; letter-spacing:.07em; color:var(--muted);
     margin:30px 0 10px; }}
.alert {{ background:var(--bad-bg); border:1px solid var(--bad); border-radius:8px;
         padding:14px 18px; margin-bottom:8px; }}
.alert b {{ color:var(--bad); display:block; margin-bottom:6px; }}
.alert ul {{ margin:0; padding-left:20px; font-size:14px; }}
.fine {{ background:var(--ok-bg); color:var(--ok); border-radius:8px; padding:14px 18px;
        font-weight:600; }}
.stats {{ display:flex; gap:10px; flex-wrap:wrap; margin:16px 0 0; }}
.stat {{ flex:1 1 150px; background:var(--card); border:1px solid var(--line);
        border-radius:8px; padding:14px 16px; }}
.stat b {{ display:block; font-size:20px; }}
.stat span {{ color:var(--muted); font-size:12px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
        overflow:hidden; margin-bottom:10px; }}
.card-head {{ padding:12px 14px; border-bottom:1px solid var(--line); font-weight:600; }}
.card-head span {{ display:block; font-weight:400; font-size:12px; color:var(--muted); }}
.err {{ padding:10px 14px; color:var(--bad); font-size:13px; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
td {{ padding:9px 14px; border-bottom:1px solid var(--line); }}
tr:last-child td {{ border-bottom:0; }}
.mono {{ font-family:ui-monospace,Menlo,monospace; font-size:13px; color:var(--muted); }}
.unit {{ color:var(--ink); }}
.role {{ display:block; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        font-size:12px; color:var(--muted); margin-top:2px; }}
.chip {{ display:inline-block; padding:2px 9px; border-radius:11px; font-size:12px; font-weight:600; }}
.chip.ok {{ background:var(--ok-bg); color:var(--ok); }}
.chip.bad {{ background:var(--bad-bg); color:var(--bad); }}
.chip.idle {{ background:var(--idle-bg); color:var(--idle); }}
.log {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
       padding:12px 14px; font-family:ui-monospace,Menlo,monospace; font-size:12px;
       color:var(--muted); overflow-x:auto; }}
.line {{ white-space:pre; }}
</style></head><body><div class="wrap">
<h1>Состояние VPN</h1>
<p class="sub">Обновлено {generated}. Страница перезагружается каждые 5 минут.</p>

{problems_block}

<div class="stats">
  <div class="stat"><b>{live} из {len(nodes)}</b><span>своих точек работает</span></div>
  <div class="stat"><b>{reserve_count}</b><span>публичных в резерве</span></div>
  <div class="stat"><b>{len(machines)}</b><span>машин в парке</span></div>
</div>

<h2>Машины</h2>
{''.join(machine_card(m) for m in machines)}

<h2>Выдано конфигов — {issued_total} из {TOTAL_LIMIT}</h2>
<div class="card"><table>{issued_rows}</table></div>

<h2>Точки в подписке</h2>
<div class="card"><table>{node_rows}</table></div>

<h2>Тревоги</h2>
<div class="log">{alert_html}</div>

<h2>Журнал проверок</h2>
<div class="log">{log_html or 'пока пусто'}</div>
</div></body></html>"""


def main():
    config = json.loads(NODES_PATH.read_text())
    nodes = config['nodes']
    machines = [collect_local()] + [collect_remote(a, k) for a, k in REMOTE_HOSTS]

    reserve_count = 0
    if RESERVE_PATH.exists():
        reserve_count = len([l for l in RESERVE_PATH.read_text().splitlines() if l.strip()])
    log_lines = REFRESH_LOG.read_text().splitlines()[-LOG_TAIL_LINES:][::-1] if REFRESH_LOG.exists() else []

    problems = find_problems(nodes, machines)
    announce(problems)
    issued_total, issued = issued_configs()
    page = render(nodes, machines, reserve_count, problems, log_lines,
                  issued_total, issued)
    token = TOKEN_PATH.read_text().strip()
    (OUTPUT_DIR / f'admin-{token}.html').write_text(page)
    print(f'problems: {len(problems)}')
    for problem in problems:
        print(f'  - {problem}')


if __name__ == '__main__':
    main()
