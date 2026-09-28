#!/usr/bin/env python3
"""Hand out a freshly generated client config, one link for everyone.

Every visitor gets their own peer rather than a file from a shared pool: nobody
receives someone else's keys, and the pool cannot run out. Repeat visits return
the same config, so a lost file costs nothing.

The per-visitor cap is the only thing standing between a link shared with family
and a link that has travelled further than intended.
"""
import fcntl
import json
import re
import subprocess
import sys
import time
from pathlib import Path

# These scripts import one another and are all installed side by side, so the
# directory has to be reachable however this file was loaded.
sys.path.insert(0, '/usr/local/sbin')

import site_config


def notify(text, key=None):
    """Alerting must never block handing out a config."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'notify', '/usr/local/sbin/notify.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.send(text, key=key)
    except Exception:
        pass

STATE_DIR = Path('/var/lib/vpn-configs')
STATE_PATH = STATE_DIR / 'issued.json'
LOCK_PATH = Path('/var/lock/issue-config.lock')
ISSUED_DIR = STATE_DIR / 'issued'

# A household shares one public address, so the per-visitor cap has to fit a
# family, not a person. The total cap is what actually bounds a leaked link.
PER_VISITOR_LIMIT = 4
# A soft threshold, not a wall: refusing a new family member is worse than
# issuing one more config. Crossing it raises an alert instead.
NOTIFY_AFTER = 40
# A wall after all, far above any real household, to bound a leaked link.
HARD_LIMIT = 200

PROTOCOLS = {
    'amnezia': {'command': ['/usr/local/sbin/provision-peer.py']},
    'algo': {'command': ['ssh', '-i', '/root/.ssh/fleet-provision',
                         '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                         '-o', 'ConnectTimeout=20',
                         f"root@{site_config.value('mirror.address')}"]},
}


def visitor_key(address):
    """Group by address; anything unparseable gets its own bucket."""
    return re.sub(r'[^\w.:-]', '_', address)[:64] or 'unknown'


def issue(protocol, address, want_new=False):
    if protocol not in PROTOCOLS:
        return None, 'unknown protocol'

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        state = json.loads(STATE_PATH.read_text()) if STATE_PATH.exists() else {}
        visitor = visitor_key(address)
        held = state.setdefault(protocol, {}).setdefault(visitor, [])

        if held and not want_new:
            path = ISSUED_DIR / protocol / held[-1]
            if path.exists():
                return path.read_text(), None

        # counted across protocols: a person needs one way in, not one of each
        held_anywhere = sum(len(group.get(visitor, []))
                            for group in state.values())
        if held_anywhere >= PER_VISITOR_LIMIT:
            return None, 'limit reached'

        issued_total = sum(len(files) for group in state.values()
                           for files in group.values())
        if issued_total >= HARD_LIMIT:
            notify(f'Выдача конфигов остановлена: {issued_total} штук, '
                   f'это выше потолка {HARD_LIMIT}. Похоже, ссылка утекла.',
                   key='hard-limit')
            return None, 'total limit reached'

        name = f'{visitor}-{len(held) + 1}'
        result = subprocess.run(
            [*PROTOCOLS[protocol]['command'], name] if protocol == 'amnezia'
            else PROTOCOLS[protocol]['command'],
            capture_output=True, text=True, timeout=60)
        if result.returncode != 0 or '[Interface]' not in result.stdout:
            return None, f'provision failed: {result.stderr[:120]}'

        filename = f'{name}.conf'
        target = ISSUED_DIR / protocol
        target.mkdir(parents=True, exist_ok=True)
        (target / filename).write_text(result.stdout)

        # every issue is reported: knowing who took what is the point
        line = (f'Выдан конфиг {protocol}: {visitor}, '
                f'{len(held) + 1}-й для этого адреса, {issued_total + 1} всего.')
        if issued_total + 1 > NOTIFY_AFTER:
            line += f' Это выше ожидаемых {NOTIFY_AFTER} — стоит проверить.'
        elif len(held) + 1 >= PER_VISITOR_LIMIT:
            line += ' Его предел исчерпан.'
        notify(line)

        held.append(filename)
        state[protocol][visitor] = held
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state, indent=1))
        return result.stdout, None


if __name__ == '__main__':
    import sys
    text, error = issue(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'cli')
    print(error or text, end='' if text else '\n')
