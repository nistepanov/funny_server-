#!/usr/bin/env python3
"""Publish the WireGuard and AmneziaWG configs behind per-protocol links.

Endpoints are written as names, never addresses: a replaced address then means
one DNS edit instead of handing every person a new file. The files are served
over the tunnel so the pages stay reachable even when a node's own address is
blocked.
"""
import html
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import site_config

CONFIG_DIR = Path('/usr/local/etc/vpn-subscription')
OUTPUT_DIR = Path('/var/www/sub')
DOMAIN = 'https://' + site_config.value('page.primary')
AMNEZIAWG_HOST = site_config.value('amneziawg_endpoint').split(':')[0]
WIREGUARD_HOST = site_config.value('wireguard_endpoint').split(':')[0]

IPV4_PATTERN = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

PROTOCOLS = (
    {
        'slug': 'amnezia',
        'title': 'AmneziaWG',
        'app': 'AmneziaVPN',
        'app_url': 'https://amnezia.org/en/downloads',
        'source': Path('/etc/amnezia/amneziawg/clients'),
        'endpoint': AMNEZIAWG_HOST,
        'remote': None,
    },
    {
        'slug': 'algo',
        'title': 'WireGuard',
        'app': 'WireGuard',
        'app_url': 'https://www.wireguard.com/install/',
        'source': None,  # lives on the other machine, staged by the caller
        'staged': Path('/var/lib/vpn-configs/algo'),
        'endpoint': WIREGUARD_HOST,
        'remote': site_config.value('mirror.address'),
    },
)


def token_for(slug):
    path = CONFIG_DIR / f'{slug}-token'
    if not path.exists():
        import secrets
        path.write_text(secrets.token_hex(8))
        path.chmod(0o600)
    return path.read_text().strip()


def rewrite_endpoint(text, endpoint):
    """Swap any literal address in Endpoint for the stable name."""
    def replace(match):
        head, _, port = match.group(0).partition('=')
        port = port.strip().rsplit(':', 1)[-1]
        return f'Endpoint = {endpoint}:{port}'
    return re.sub(r'Endpoint\s*=\s*\S+', replace, text)


def publish(protocol):
    source = protocol.get('source') or protocol.get('staged')
    if not source or not source.is_dir():
        return None

    token = token_for(protocol['slug'])
    target = OUTPUT_DIR / f'files-{token}'
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)

    published = []
    for config in sorted(source.glob('*.conf')):
        text = rewrite_endpoint(config.read_text(), protocol['endpoint'])
        leftover = [a for a in IPV4_PATTERN.findall(text)
                    if not a.startswith(('10.', '172.', '192.168.'))]
        if leftover:
            print(f'  ВНИМАНИЕ: {config.name} всё ещё содержит адрес {leftover}')
        (target / config.name).write_text(text)
        published.append(config.stem)

    page = render_page(protocol, token, published)
    (OUTPUT_DIR / f'{protocol["slug"]}-{token}.html').write_text(page)
    return token, len(published)


def render_page(protocol, token, names):
    generated = datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')
    contact = site_config.value('contact')
    items = '\n'.join(
        f'<li><a href="{DOMAIN}/files-{token}/{html.escape(name)}.conf">'
        f'{html.escape(name)}</a></li>' for name in names)

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Конфиги {html.escape(protocol['title'])}</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --ink:#16181d; --muted:#5b6270;
        --line:#e2e6ec; --accent:#2b4c8c; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0f1217; --card:#171b22; --ink:#e6e9ef; --muted:#949cab;
          --line:#262c36; --accent:#90aaf0; }}
}}
body {{ margin:0; padding:28px 18px 72px; background:var(--bg); color:var(--ink);
       font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:620px; margin:0 auto; }}
h1 {{ font-size:24px; margin:0 0 6px; }}
.when {{ color:var(--muted); font-size:13px; margin:0 0 24px; }}
h2 {{ font-size:17px; margin:28px 0 10px; }}
p {{ margin:0 0 14px; }}
a {{ color:var(--accent); text-underline-offset:2px; }}
ul {{ list-style:none; padding:0; margin:0; }}
li {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
     margin-bottom:6px; }}
li a {{ display:block; padding:12px 16px; text-decoration:none; font-weight:600; }}
.note {{ color:var(--muted); font-size:14px; }}
</style></head><body><div class="wrap">
<h1>Конфиги {html.escape(protocol['title'])}</h1>
<p class="when">Обновлено {generated}</p>

<h2>Что нужно</h2>
<p>Приложение <a href="{protocol['app_url']}">{html.escape(protocol['app'])}</a>.
Скачайте свой файл ниже и откройте его в приложении.</p>

<h2>Файлы</h2>
<ul>
{items}
</ul>

<h2>Если перестало работать</h2>
<p>Выключите и включите подключение — этого хватает, когда мы меняем сервер.
Если не помогло, скачайте файл отсюда заново.
Совсем не работает — напишите <a href="https://t.me/{contact.lstrip('@')}">{contact}</a>.</p>

<p class="note">В файлах записано имя, а не адрес. Когда сервер переезжает,
файл остаётся прежним.</p>
</div></body></html>"""


def main():
    for protocol in PROTOCOLS:
        result = publish(protocol)
        if result:
            token, count = result
            print(f'{protocol["slug"]}: {count} конфигов, {DOMAIN}/{protocol["slug"]}-{token}.html')
        else:
            print(f'{protocol["slug"]}: источник недоступен')


if __name__ == '__main__':
    main()
