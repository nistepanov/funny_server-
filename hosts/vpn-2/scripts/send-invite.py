#!/usr/bin/env python3
"""Send the short version of the instructions to Telegram, ready to forward.

The page is the full answer, but a page is useless to someone who cannot open
it yet, and that is exactly the person being invited. This message carries
enough to get connected without the page: the links, the password, and which
app to install. It is built from the same tokens the page uses, so the two
cannot drift apart.

Link previews are turned off. A preview means the messenger fetches every
address in the message, and these addresses are the ones worth not handing to
a third party.
"""
import importlib.util
import sys
from pathlib import Path

import site_config

CONFIG_DIR = Path('/usr/local/etc/vpn-subscription')
NOTIFY_PATH = Path('/usr/local/sbin/notify.py')
# The name that goes through the edge network reads better and hides the
# machine, so it leads. The other one is the way back in when it is throttled.
PRIMARY_HOST = site_config.value('page.primary')
SPARE_HOST = site_config.value('page.spare')


def read(name):
    path = CONFIG_DIR / name
    return path.read_text().strip() if path.exists() else ''


def compose():
    token = read('token')
    password = read('page-password')
    base = f'https://{PRIMARY_HOST}'

    return f"""<b>ВПН — как подключиться</b>

<b>1. Поставьте приложение</b>
Android — <a href="https://play.google.com/store/apps/details?id=app.hiddify.com">Hiddify</a> \
или <a href="https://github.com/hiddify/hiddify-app/releases/latest">файл .apk</a>
iPhone — <a href="https://apps.apple.com/ru/app/id6472431552">Karing</a>
Компьютер — <a href="https://github.com/hiddify/hiddify-app/releases/latest">Hiddify</a>

<b>2. Скопируйте ссылку и добавьте её в приложении</b>
Кнопка «Добавить подписку» или «+».

Для Hiddify и Karing:
<code>{base}/{token}.json</code>

Для Happ, v2rayNG, Shadowrocket:
<code>{base}/{token}</code>

Всё. Сервер выбирается сам.

<b>Если не заработало</b>
Скачайте готовый файл и откройте его в приложении:
• <a href="{base}/get/algo">WireGuard</a> — приложение \
<a href="https://www.wireguard.com/install/">WireGuard</a>, есть везде
• <a href="{base}/get/amnezia">AmneziaWG</a> — приложение \
<a href="https://play.google.com/store/apps/details?id=org.amnezia.vpn">AmneziaVPN</a>, \
кроме iPhone

При скачивании спросят пароль: <code>{password}</code>

<b>Подробная страница</b>
{base}/help/
Не открывается — запасной адрес: https://{SPARE_HOST}/help/
Пароль тот же.

<b>Не пересылайте это сообщение дальше.</b> По ссылкам открывается доступ."""


def main():
    if not read('token') or not read('page-password'):
        print('missing token or password', file=sys.stderr)
        return 1
    spec = importlib.util.spec_from_file_location('notify', NOTIFY_PATH)
    notify = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(notify)
    print(notify.send(compose(), markup=True, preview=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
