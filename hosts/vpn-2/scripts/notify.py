#!/usr/bin/env python3
"""Tell the operator when something needs attention.

Everything is written to the alert log first, so a missing or broken Telegram
token loses a message to the phone but never the record itself. The chat id is
discovered from the bot's own updates: it appears once the operator writes to
the bot, which they have to do anyway before it can reply.
"""
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CREDENTIALS = Path('/root/.vpn-credentials/telegram')
CHAT_ID_PATH = Path('/root/.vpn-credentials/telegram-chat-id')
ALERT_LOG = Path('/var/log/vpn-alerts.log')
SEEN_PATH = Path('/var/lib/vpn-configs/alerts-seen.json')
API = 'https://api.telegram.org/bot{token}/{method}'
QUIET_SECONDS = 6 * 3600


def read_token():
    if not CREDENTIALS.exists():
        return None
    for line in CREDENTIALS.read_text().splitlines():
        key, _, value = line.partition('=')
        if key.strip() == 'TELEGRAM_TOKEN' and value.strip():
            return value.strip()
    return None


def call(token, method, params):
    url = API.format(token=token, method=method)
    data = urllib.parse.urlencode(params).encode()
    with urllib.request.urlopen(url, data=data, timeout=20) as response:
        return json.load(response)


def resolve_chat_id(token):
    """The operator writes to the bot once; that message carries the chat id."""
    if CHAT_ID_PATH.exists():
        stored = CHAT_ID_PATH.read_text().strip()
        if stored:
            return stored
    try:
        updates = call(token, 'getUpdates', {'limit': 10})
    except Exception:
        return None
    for update in reversed(updates.get('result', [])):
        chat = (update.get('message') or {}).get('chat') or {}
        if chat.get('id'):
            CHAT_ID_PATH.write_text(str(chat['id']))
            CHAT_ID_PATH.chmod(0o600)
            return str(chat['id'])
    return None


def already_sent_recently(key):
    """Repeat alerts about the same thing are noise, not information."""
    now = datetime.now(timezone.utc).timestamp()
    try:
        seen = json.loads(SEEN_PATH.read_text())
    except Exception:
        seen = {}
    last = seen.get(key, 0)
    if now - last < QUIET_SECONDS:
        return True
    seen[key] = now
    SEEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    SEEN_PATH.write_text(json.dumps(seen))
    return False


def send(text, key=None, markup=False, preview=True):
    """Alerts are plain by default; only a message meant to be read as a
    document asks for markup, and only that one turns previews off."""
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    with ALERT_LOG.open('a') as log:
        log.write(f'{stamp} {text}\n')

    if key and already_sent_recently(key):
        return 'suppressed'

    token = read_token()
    if not token:
        return 'no token'
    chat_id = resolve_chat_id(token)
    if not chat_id:
        return 'no chat id: write any message to the bot first'
    params = {'chat_id': chat_id, 'text': text}
    if markup:
        params['parse_mode'] = 'HTML'
    if not preview:
        params['link_preview_options'] = json.dumps({'is_disabled': True})
    try:
        call(token, 'sendMessage', params)
        return 'sent'
    except Exception as error:
        return f'failed: {error}'


if __name__ == '__main__':
    print(send(' '.join(sys.argv[1:]) or 'test'))
