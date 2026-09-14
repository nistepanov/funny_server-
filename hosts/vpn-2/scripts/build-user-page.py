#!/usr/bin/env python3
"""Render the page family members open: the ways in, and what to do when one
stops working.

Carries no addresses of its own. Whoever holds the subscription link holds this
page too, and an address printed here is an address handed onward with it. The
one exception is the spare entry point: a reader who cannot reach the page has
no other way to learn where else to knock, so that name is printed in full.

Links are built in the browser from the address the reader arrived on. The page
answers to more than one name, and a link hard-coded to one of them would send
a reader who found the working name straight back to the broken one.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import site_config

CONFIG_DIR = Path('/usr/local/etc/vpn-subscription')
NODES_PATH = CONFIG_DIR / 'nodes.json'
RESERVE_PATH = CONFIG_DIR / 'reserve.txt'
OUTPUT_DIR = Path('/var/www/sub')
# Every name the page answers to. Whichever one the reader is not using is
# offered as the spare, so the two are never printed the wrong way round.
ENTRY_HOSTS = (site_config.value('page.primary'), site_config.value('page.spare'))


def read_token(name):
    path = CONFIG_DIR / name
    return path.read_text().strip() if path.exists() else None


def overall_state(nodes, reserve_count):
    live = sum(1 for node in nodes if node.get('enabled', True))
    if live >= 2:
        return 'ok', 'Всё работает'
    if live or reserve_count:
        return 'warn', 'Работает с перебоями'
    return 'bad', 'Не работает'


def render(state, headline, tokens):
    generated = datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')
    sub = tokens['sub']
    hosts = json.dumps(ENTRY_HOSTS)

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="600">
<title>Как подключиться</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --ink:#16181d; --muted:#5b6270; --line:#e2e6ec;
        --accent:#2b4c8c; --ok-bg:#e3f1e9; --ok:#1b7a4d;
        --warn-bg:#fbf0da; --warn:#8a6100; --bad-bg:#fae7e5; --bad:#b3261e; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0f1217; --card:#171b22; --ink:#e6e9ef; --muted:#949cab; --line:#262c36;
          --accent:#90aaf0; --ok-bg:#15271e; --ok:#4fb183;
          --warn-bg:#261e0d; --warn:#d3a63f; --bad-bg:#2b1917; --bad:#e8796f; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:28px 18px 72px; background:var(--bg); color:var(--ink);
       font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:660px; margin:0 auto; }}
h1 {{ font-size:26px; margin:0 0 18px; }}
h2 {{ font-size:19px; margin:0 0 10px; }}
h3 {{ font-size:15px; margin:18px 0 6px; }}
p {{ margin:0 0 12px; }}
a {{ color:var(--accent); text-underline-offset:2px; }}
.state {{ border-radius:10px; padding:15px 20px; font-weight:600; font-size:17px; }}
.state.ok {{ background:var(--ok-bg); color:var(--ok); }}
.state.warn {{ background:var(--warn-bg); color:var(--warn); }}
.state.bad {{ background:var(--bad-bg); color:var(--bad); }}
.when {{ color:var(--muted); font-size:13px; margin:8px 0 28px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
        padding:20px 22px; margin-bottom:14px; }}
.card.best {{ border-color:var(--accent); border-width:2px; }}
.tag {{ display:inline-block; background:var(--accent); color:#fff; font-size:11px;
       font-weight:700; letter-spacing:.05em; padding:3px 9px; border-radius:10px;
       margin-bottom:10px; }}
.tag.plain {{ background:var(--line); color:var(--muted); }}
.copy, .get {{ display:block; width:100%; text-align:left; border:1px solid var(--accent);
        border-radius:8px; padding:12px 15px; margin:8px 0; cursor:pointer;
        font-size:14px; word-break:break-all; text-decoration:none;
        background:var(--card); color:var(--accent); }}
.copy {{ font-family:ui-monospace,Menlo,monospace; font-size:13px; }}
.get {{ font-weight:600; }}
.copy:hover, .get:hover {{ background:var(--accent); color:#fff; }}
.copy.done {{ background:var(--ok-bg); color:var(--ok); border-color:var(--ok); }}
ol, ul {{ margin:0 0 12px; padding-left:22px; }}
li {{ margin-bottom:5px; }}
.note {{ color:var(--muted); font-size:14px; }}
.spare {{ background:var(--warn-bg); color:var(--warn); border-radius:10px;
         padding:14px 18px; font-size:15px; margin:26px 0; }}
.spare b {{ font-size:16px; }}
hr {{ border:0; border-top:1px solid var(--line); margin:30px 0 24px; }}
</style></head><body><div class="wrap">

<h1>Как подключиться</h1>
<div class="state {state}">{headline}</div>
<p class="when">Проверено {generated}</p>

<p>Способ 1 подходит почти всем и сам выбирает рабочий сервер.
Остальные — на случай, если он не пошёл.</p>

<div class="card best">
  <span class="tag">Способ 1 · основной</span>
  <h2>Подписка</h2>

  <h3>1. Поставьте приложение</h3>
  <p><b>Android:</b>
  <a href="https://play.google.com/store/apps/details?id=app.hiddify.com">Hiddify</a>
  или <a href="https://play.google.com/store/apps/details?id=com.happproxy">Happ</a>.
  Без Google Play —
  <a href="https://github.com/hiddify/hiddify-app/releases/latest">файл .apk</a>.<br>
  <b>iPhone:</b>
  <a href="https://apps.apple.com/ru/app/id6472431552">Karing</a> — бесплатный,
  есть в российском App Store.<br>
  <b>Компьютер:</b>
  <a href="https://github.com/hiddify/hiddify-app/releases/latest">Hiddify</a>
  для Windows, macOS и Linux.</p>
  <p class="note">Happ и Hiddify из российского App Store пропали. На iPhone
  берите Karing.</p>

  <h3>2. Добавьте ссылку</h3>
  <p>В приложении — «Добавить подписку» или «+». Нажмите на нужную ссылку,
  она скопируется.</p>

  <p><b>Hiddify, Karing, sing-box:</b></p>
  <button class="copy" data-path="/{sub}.json"></button>
  <p class="note">Больше настраивать нечего. Выбор сервера и обход российских
  сайтов уже внутри.</p>

  <p><b>Happ, v2rayNG, Shadowrocket:</b></p>
  <button class="copy" data-path="/{sub}"></button>
  <p class="note">В Happ нажмите спидометр рядом с названием подписки — он
  измерит серверы и подключится к быстрому. В v2rayNG и Shadowrocket через
  ВПН пойдёт весь трафик, и российские банки могут не открыться.</p>

  <p><b>Запасная ссылка на случай медленного мобильного интернета:</b></p>
  <button class="copy" data-path="/{sub}-hy2"></button>
  <p class="note">Для Hiddify, Karing и sing-box не нужна — эти серверы уже
  пришли первой ссылкой. Работает не у всех операторов.</p>
</div>

<div class="card">
  <span class="tag plain">Способ 2</span>
  <h2>WireGuard</h2>
  <p>Самый простой и быстрый. Блокируют его чаще остальных, но начать проще
  всего. Есть везде, включая российский App Store.</p>
  <p>Поставьте <a href="https://www.wireguard.com/install/">WireGuard</a>,
  затем скачайте файл и откройте его в приложении.</p>
  <a class="get" href="/get/algo">Скачать файл WireGuard</a>
  <p class="note">Файл выдаётся лично вам. Для второго устройства —
  <a href="/get/algo/new">скачать ещё один</a>.</p>
</div>

<div class="card">
  <span class="tag plain">Способ 3</span>
  <h2>AmneziaWG</h2>
  <p>Тот же WireGuard, но замаскированный. Медленнее, зато переживает
  блокировки, от которых способ 2 падает.</p>
  <p>Поставьте AmneziaVPN:
  <a href="https://play.google.com/store/apps/details?id=org.amnezia.vpn">Android</a>,
  <a href="https://github.com/amnezia-vpn/amnezia-client/releases/latest">компьютер</a>.
  На iPhone его в российском App Store нет.</p>
  <a class="get" href="/get/amnezia">Скачать файл AmneziaWG</a>
  <p class="note">Файл выдаётся лично вам. Для второго устройства —
  <a href="/get/amnezia/new">скачать ещё один</a>.</p>
</div>

<div class="spare">
  <b>Если эта страница перестанет открываться</b><br>
  Запасной адрес: <a class="other-host" href="#"></a><br>
  Ссылки на нём те же, пароль тот же. Сохраните адрес заранее.
</div>

<hr>

<h2>Если перестало работать</h2>
<ol>
  <li><b>Проверьте, что выбран режим «Auto».</b> Самая частая причина: выбран
      один сервер, он умер, а приложение так на нём и сидит.</li>
  <li><b>Обновите подписку</b> — круговая стрелка на профиле.</li>
  <li><b>Выключите и включите подключение.</b></li>
  <li><b>Смените сеть</b> — с домашней на мобильную или наоборот.</li>
  <li><b>Выберите вручную сервер со словом «через CDN».</b> Медленный, зато
      работает там, где остальные нет.</li>
  <li><b>Попробуйте способ 2 или 3.</b></li>
  <li>Не помогло — напишите тому, кто дал вам эту ссылку.</li>
</ol>

<h2>Названия серверов</h2>
<ul>
  <li><b>прямой</b> — быстрый, пробуйте первым.</li>
  <li><b>через CDN</b> — медленный, зато работает почти всегда.</li>
  <li><b>Hysteria2</b> — быстрый на мобильном, но не у всех операторов.</li>
  <li><b>общий</b> — чужой публичный сервер. Для банка и почты берите любой
      другой.</li>
</ul>

<h2>Если не работает вообще ничего</h2>
<p class="note">Чужие сервисы, к этой подписке отношения не имеют.</p>
<ul>
  <li><a href="https://warpgen.net/">warpgen.net</a> — бесплатный конфиг
      Cloudflare WARP, открывается приложением из способа 3.</li>
  <li><a href="https://vpn.maximkatz.com/">Светофор</a> — таблица, что сегодня
      работает у какого оператора.</li>
</ul>

<p class="note">Ссылки постоянные, серверы за ними меняются сами.
Страницу и ссылки не пересылайте: по ним открывается доступ.</p>
</div>
<script>
// Links follow the name the reader arrived on: the page answers to several
// names, and only the reader knows which of them still works where they are.
var entryHosts = {hosts};

document.querySelectorAll('.copy').forEach(function (button) {{
  var url = location.origin + button.dataset.path;
  button.textContent = url;
  button.addEventListener('click', function () {{
    var restore = function () {{
      button.textContent = 'Скопировано — вставьте в приложение';
      button.classList.add('done');
      setTimeout(function () {{
        button.textContent = url;
        button.classList.remove('done');
      }}, 2000);
    }};
    if (navigator.clipboard) {{
      navigator.clipboard.writeText(url).then(restore, restore);
    }} else {{
      var helper = document.createElement('textarea');
      helper.value = url;
      document.body.appendChild(helper);
      helper.select();
      document.execCommand('copy');
      helper.remove();
      restore();
    }}
  }});
}});

// Whichever name the reader is not on right now is the one worth writing down.
var spare = entryHosts.filter(function (host) {{
  return host !== location.hostname;
}})[0];
document.querySelectorAll('.other-host').forEach(function (link) {{
  if (!spare) {{ link.closest('.spare').remove(); return; }}
  link.href = 'https://' + spare + '/help/';
  link.textContent = spare;
}});
</script>
</body></html>"""


def main():
    config = json.loads(NODES_PATH.read_text())
    reserve_count = 0
    if RESERVE_PATH.exists():
        reserve_count = len([l for l in RESERVE_PATH.read_text().splitlines() if l.strip()])

    tokens = {'sub': read_token('token')}
    state, headline = overall_state(config['nodes'], reserve_count)

    target = OUTPUT_DIR / 'help'
    target.mkdir(exist_ok=True)
    (target / 'index.html').write_text(render(state, headline, tokens))
    print(f'user page: {state}')


if __name__ == '__main__':
    main()
