#!/usr/bin/env python3
"""Warn before a node's hosting runs out, and when one stops answering.

Neither provider exposes billing over its API, so renewal dates are kept here by
hand and refreshed after each payment. That makes them the weaker signal — a
date can silently go stale — so liveness is checked too: a node that stops
answering is the same emergency whether the cause is money or a block.
"""
import json
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

STATE_PATH = Path('/usr/local/etc/vpn-subscription/billing.json')
WARN_DAYS = (14, 7, 3, 1)


def notify(text, key=None):
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location('notify', '/usr/local/sbin/notify.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.send(text, key=key)
    except Exception as error:
        print(f'notify failed: {error}')
        return 'failed'


def node_answers(address, port=22):
    """A node that went unpaid stops answering, same as a blocked one."""
    result = subprocess.run(
        ['timeout', '8', 'bash', '-c', f'echo > /dev/tcp/{address}/{port}'],
        capture_output=True)
    return result.returncode == 0


def main():
    state = json.loads(STATE_PATH.read_text())
    today = date.today()

    for node in state['nodes']:
        name = node['name']
        renews = datetime.strptime(node['renews_on'], '%Y-%m-%d').date()
        days_left = (renews - today).days

        if days_left < 0:
            notify(f'{name} ({node["provider"]}): срок оплаты прошёл '
                   f'{abs(days_left)} дн. назад. Проверь баланс.',
                   key=f'billing-overdue-{name}')
        else:
            for threshold in WARN_DAYS:
                if days_left == threshold:
                    notify(f'{name} ({node["provider"]}): оплата через '
                           f'{days_left} дн., до {node["renews_on"]}.',
                           key=f'billing-{name}-{threshold}')
                    break

        alive = node_answers(node['check_address'])
        if not alive:
            notify(f'{name} не отвечает по адресу {node["check_address"]}. '
                   f'Это может быть блокировка или неоплата.',
                   key=f'unreachable-{name}')

        print(f'  {name:8} {node["provider"]:10} оплата через {days_left:4} дн. '
              f'({node["renews_on"]})  {"отвечает" if alive else "НЕ ОТВЕЧАЕТ"}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
