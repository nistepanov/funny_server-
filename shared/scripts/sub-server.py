#!/usr/bin/env python3
"""Serve the subscription, the pages and the client config files.

Two kinds of request arrive here and they cannot be protected the same way.
An app fetching its server list cannot be asked to log in, so those few paths
stay open and rely on being unguessable. Everything a person opens in a browser
sits behind a shared password instead: the page hands out the very link the
apps rely on, so a guessable address for it would undo the unguessable one.
The password also stops link previews — a messenger fetches every address
posted into a chat, and without it the page would be read by whoever runs the
messenger.

Config files are rate limited per visitor: the pages listing them are meant to
be shared with family, and a shared link eventually travels further than
intended. Someone who needs a second device asks for it; someone scraping the
whole directory stops after three.

There are two ways in. One arrives through the edge network, which is convenient
and hides the machine, but the country these readers live in has started
throttling that network, so the page it fronts opens only for people who already
have a working tunnel — exactly the people who do not need it. The other listens
straight on a public address of the machine. It is easier to block by address,
and it publishes that address, but it owes nothing to anyone else's network.
Neither is good enough alone.
"""
import base64
import functools
import hashlib
import hmac
import http.cookies
import http.server
import ssl
import sys
import json
import threading
import time
import urllib.parse
from datetime import timedelta
from pathlib import Path

# These scripts import one another and are all installed side by side, so the
# directory has to be reachable however this file was loaded.
sys.path.insert(0, '/usr/local/sbin')

import site_config

SERVE_DIR = '/var/www/sub'
PORT = 8081
STATE_PATH = Path('/var/lib/vpn-configs/download-counts.json')
CONFIG_LIMIT = 3
WINDOW_SECONDS = 24 * 3600
ROUTING_PATH = Path(SERVE_DIR) / 'rules/happ-routing.json'
TOKEN_PATH = Path('/usr/local/etc/vpn-subscription/token')
PASSWORD_PATH = Path('/usr/local/etc/vpn-subscription/page-password')
COOKIE_NAME = 'entry'
# Answering to more than one name means the password would otherwise be asked
# for again on each of them.
COOKIE_DOMAIN = site_config.value('page.cookie_domain')
# Handing out a peer keeps state, so it happens on one node. That node also
# answers to a name of its own, which is where the others send the visitor.
ISSUER_HOST = 'https://' + site_config.value('page.issuer')
COOKIE_MAX_AGE = int(timedelta(days=180).total_seconds())
OPEN_PREFIXES = ('/rules/',)
# What the saved file is called. The internal names mean nothing to the person
# who has to find the file again in their downloads folder.
CONFIG_FILENAMES = {'amnezia': 'amneziawg.conf', 'algo': 'wireguard.conf'}
GUESS_LIMIT = 10
GUESS_WINDOW = timedelta(hours=1).total_seconds()
# The public address this node answers on directly, when it answers directly
# at all. Absent on a node whose addresses are all spoken for.
DIRECT_ADDRESS_PATH = Path('/usr/local/etc/vpn-subscription/direct-address')
DIRECT_TLS_PORT = 443
DIRECT_PLAIN_PORT = 80
# Shared with the UDP entry point, which already renews it.
CERTIFICATE_PATH = Path('/etc/sing-box/tls/fullchain.pem')
PRIVATE_KEY_PATH = Path('/etc/sing-box/tls/privkey.pem')
# How long a connection may go quiet before it is dropped. Every listener here
# faces the open internet, where things connect and then say nothing for hours.
STALL_TIMEOUT = timedelta(seconds=15).total_seconds()

_lock = threading.Lock()
_guesses = {}


def load_state():
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {}


def save_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))


def register_download(client, name):
    """Count distinct configs per visitor; True while under the limit."""
    now = time.time()
    with _lock:
        state = load_state()
        entry = state.get(client, {})
        entry = {k: v for k, v in entry.items() if now - v < WINDOW_SECONDS}
        allowed = name in entry or len(entry) < CONFIG_LIMIT
        if allowed:
            entry[name] = now
        state[client] = entry
        state = {k: v for k, v in state.items() if v}
        save_state(state)
        return allowed, len(entry)


def routing_deeplink():
    """Hand the plain server list the same routing the profile format carries.

    A client reading a bare list has no way to know Russian sites belong off
    the tunnel, so it sends everything through: banking breaks and we pay for
    traffic that never needed us. Part of the client family accepts routing
    rules delivered beside the list, and this is how they arrive.
    """
    try:
        profile = json.loads(ROUTING_PATH.read_text())
    except Exception:
        return None
    packed = json.dumps(profile, separators=(',', ':')).encode()
    return 'happ://routing/onadd/' + base64.b64encode(packed).decode()


def read_token():
    try:
        return TOKEN_PATH.read_text().strip()
    except Exception:
        return None


def subscription_paths():
    token = read_token()
    return () if token is None else (f'/{token}', f'/{token}-hy2')


def open_paths():
    """The lists an app fetches by itself, which therefore cannot ask for a
    password. Their only protection is a name nobody can guess."""
    token = read_token()
    return () if token is None else (f'/{token}', f'/{token}-hy2',
                                     f'/{token}.json')


def page_password():
    try:
        return PASSWORD_PATH.read_text().strip() or None
    except Exception:
        return None


def entry_cookie(password):
    """What a browser that answered correctly carries afterwards.

    Derived from the password, so changing it turns every old cookie into a
    wrong one and nobody has to keep a list of who is still let in.
    """
    return hmac.new(password.encode(), b'vpn-page', hashlib.sha256).hexdigest()


def allow_guess(client):
    """Ten wrong answers an hour. A shared password is short enough to be
    worth guessing, and nothing else here notices someone trying."""
    now = time.time()
    with _lock:
        recent = [when for when in _guesses.get(client, ())
                  if now - when < GUESS_WINDOW]
        _guesses[client] = recent
        return len(recent) < GUESS_LIMIT


def record_guess(client):
    with _lock:
        _guesses.setdefault(client, []).append(time.time())


LOGIN_PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Пароль</title>
<style>
* {{ box-sizing:border-box; }}
body {{ margin:0; min-height:100vh; padding:20px; display:flex;
       align-items:center; justify-content:center; background:#f6f7f9;
       color:#16181d;
       font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
form {{ background:#fff; border:1px solid #e2e6ec; border-radius:12px;
       padding:26px; width:100%; max-width:340px; }}
h1 {{ font-size:18px; margin:0 0 14px; font-weight:600; }}
input, button {{ display:block; width:100%; padding:12px; font-size:16px;
                font-family:inherit; border-radius:8px; -webkit-appearance:none; }}
input {{ border:1px solid #c9d0da; background:#fff; color:inherit; }}
button {{ margin-top:10px; border:0; background:#2b4c8c; color:#fff;
         font-weight:600; cursor:pointer; }}
.bad {{ color:#b3261e; font-size:14px; margin:10px 0 0; }}
@media (prefers-color-scheme: dark) {{
  body {{ background:#0f1217; color:#e6e9ef; }}
  form {{ background:#171b22; border-color:#262c36; }}
  input {{ background:#0f1217; border-color:#39414f; color:#e6e9ef; }}
  button {{ background:#90aaf0; color:#0f1217; }}
}}
</style></head><body>
<form method="post">
<h1>Введите пароль</h1>
<input type="password" name="password" autofocus autocomplete="current-password">
<button type="submit">Войти</button>
{message}
</form></body></html>
"""


class SubscriptionHandler(http.server.SimpleHTTPRequestHandler):
    timeout = STALL_TIMEOUT

    def guess_type(self, path):
        if path.endswith('.html'):
            return 'text/html; charset=utf-8'
        if path.endswith('.json'):
            return 'application/json'
        if path.endswith(('.srs', '.dat')):
            return 'application/octet-stream'
        return 'text/plain; charset=utf-8'

    def serve_issued_config(self, protocol, want_new=False):
        """One link per protocol: every visitor gets their own generated peer.

        Issuing keeps state, so it lives on one host only. Where that state is
        absent this is a mirror, and saying so beats handing out a peer the
        real issuer has never heard of.
        """
        import importlib.util
        issuer = Path('/usr/local/sbin/issue-config.py')
        if not issuer.exists():
            self.send_response(302)
            self.send_header('Location', ISSUER_HOST + self.path)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        spec = importlib.util.spec_from_file_location('issue_config', issuer)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        client = self.visitor()
        text, error = module.issue(protocol, client, want_new)
        if error and 'limit' in error:
            self.log_message('"%s" 429 %s', self.path, error)
            body = 'Лимит конфигов для этого подключения исчерпан.\n'.encode()
            status, ctype = 429, 'text/plain; charset=utf-8'
        elif error:
            self.log_message('"%s" 500 %s', self.path, error)
            body = 'Не получилось выдать конфиг, попробуйте позже.\n'.encode()
            status, ctype = 500, 'text/plain; charset=utf-8'
        else:
            self.log_message('"%s" 200 issued', self.path)
            body = text.encode()
            status, ctype = 200, 'text/plain; charset=utf-8'

        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if status == 200:
            filename = CONFIG_FILENAMES.get(protocol, f'{protocol}.conf')
            self.send_header('Content-Disposition',
                             f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def visitor(self):
        """Who is asking, for counting and for rate limits.

        The edge network replaces the source address with its own and puts the
        real one in a header. Off that path the header is whatever the caller
        typed, so it is read only where something trustworthy wrote it.

        A connection dropped before it said anything has no headers at all, and
        it still has to be loggable.
        """
        headers = getattr(self, 'headers', None)
        if self.server.behind_edge and headers is not None:
            return headers.get('CF-Connecting-IP', self.client_address[0])
        return self.client_address[0]

    def path_is_open(self):
        path = self.path.split('?')[0]
        return path in open_paths() or path.startswith(OPEN_PREFIXES)

    def authorized(self):
        password = page_password()
        if password is None:
            return True
        jar = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
        carried = jar[COOKIE_NAME].value if COOKIE_NAME in jar else ''
        return hmac.compare_digest(carried, entry_cookie(password))

    def send_login_form(self, message='', status=200):
        body = LOGIN_PAGE.format(
            message=f'<p class="bad">{message}</p>' if message else '').encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'private, no-store')
        self.send_header('X-Robots-Tag', 'noindex')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_POST(self):
        client = self.visitor()
        if not allow_guess(client):
            self.log_message('"%s" 429 too-many-guesses', self.path)
            self.send_login_form(message="Слишком много попыток, подождите час.",
                                 status=429)
            return

        length = int(self.headers.get('Content-Length') or 0)
        form = urllib.parse.parse_qs(
            self.rfile.read(min(length, 4096)).decode('utf-8', 'replace'))
        given = (form.get('password') or [''])[0].strip()
        password = page_password()

        if password is None or not hmac.compare_digest(given, password):
            record_guess(client)
            self.log_message('"%s" 200 wrong-password', self.path)
            self.send_login_form(message="Неверный пароль.")
            return

        cookie = (f'{COOKIE_NAME}={entry_cookie(password)}; Max-Age='
                  f'{COOKIE_MAX_AGE}; Domain={COOKIE_DOMAIN}; Path=/; HttpOnly;'
                  ' Secure; SameSite=Lax')
        self.log_message('"%s" 303 signed-in', self.path)
        self.send_response(303)
        self.send_header('Location', self.path)
        self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_HEAD(self):
        if not self.path_is_open() and not self.authorized():
            self.send_login_form()
            return
        super().do_HEAD()

    def list_directory(self, path):
        """Never enumerate the tree.

        Both the subscription and the admin page are protected by nothing but
        an unguessable name, and the admin page carries the addresses we most
        need to keep unpublished. A listing hands out both.
        """
        self.send_error(404, 'Not Found')
        return None

    def end_headers(self):
        routing = getattr(self, 'routing_header', None)
        if routing is not None:
            self.send_header('routing', routing)
        super().end_headers()

    def do_GET(self):
        self.routing_header = None
        if not self.path_is_open() and not self.authorized():
            self.send_login_form()
            return
        if self.path.split('?')[0] in subscription_paths():
            self.routing_header = routing_deeplink()
        for protocol in ('amnezia', 'algo'):
            path = self.path.rstrip('/')
            if path == f'/get/{protocol}':
                self.serve_issued_config(protocol)
                return
            # a second device needs a second config, up to the per-visitor cap
            if path == f'/get/{protocol}/new':
                self.serve_issued_config(protocol, want_new=True)
                return
        if '/files-' in self.path and self.path.endswith('.conf'):
            client = self.visitor()
            name = self.path.rsplit('/', 1)[-1]
            allowed, taken = register_download(client, name)
            if not allowed:
                self.log_message('"%s" 429 limit-reached taken=%d', self.path, taken)
                contact = site_config.value('contact')
                body = (f'Уже скачано 3 конфига с этого адреса.\n'
                        f'Нужен ещё — напишите {contact}.\n').encode()
                self.send_response(429)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        super().do_GET()

    def log_message(self, fmt, *args):
        # A fetch recorded here proves the client reached us through Cloudflare,
        # which separates "never tried" from "path broken".
        client = self.visitor()
        agent = self.headers.get('User-Agent', '-')
        print(f'{client} {fmt % args} ua={agent}', flush=True)


class PageServer(http.server.ThreadingHTTPServer):
    """The same pages on every entry point, differing only in what is in front."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, behind_edge):
        self.behind_edge = behind_edge
        super().__init__(address, handler)

    def handle_error(self, request, client_address):
        """A connection that dies before it becomes a request is not news.

        Scanners reach a public address constantly and speak anything except
        what is expected there. Since the handshake now happens where requests
        are served, their failures surface here, and a stack trace for each
        would bury the lines worth reading.
        """
        error = sys.exc_info()[1]
        if isinstance(error, (ssl.SSLError, TimeoutError, ConnectionError)):
            print(f'{client_address[0]} dropped: {type(error).__name__}', flush=True)
            return
        super().handle_error(request, client_address)


class UpgradeHandler(http.server.BaseHTTPRequestHandler):
    """Send the plain port to the encrypted one.

    Nobody types a scheme, and browsers still try the plain port first for a
    name they have never seen. Answering nothing there looks like the machine
    is down; the password would also travel in the clear.
    """
    protocol_version = 'HTTP/1.1'
    timeout = STALL_TIMEOUT

    def do_GET(self):
        host = self.headers.get('Host', '').split(':')[0]
        if not host:
            self.send_error(400)
            return
        self.send_response(308)
        self.send_header('Location', f'https://{host}{self.path}')
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_HEAD = do_GET
    do_POST = do_GET

    def log_message(self, fmt, *args):
        pass


def direct_address():
    """The public address to answer on, or None on a node without a spare one."""
    if not DIRECT_ADDRESS_PATH.exists():
        return None
    address = DIRECT_ADDRESS_PATH.read_text().strip()
    return address or None


def serve_direct(address, handler):
    """Answer on a public address, without the edge network in between.

    The encrypted greeting is deliberately left for the thread that will serve
    the request. A listening socket told to negotiate on its own does it before
    handing the connection on, so the one thread that accepts connections
    spends its time talking to whoever knocked last — and someone who knocks
    and then says nothing keeps it there for good, while everybody else queues
    behind them until the kernel starts turning arrivals away. A public address
    is knocked on that way every day.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERTIFICATE_PATH, PRIVATE_KEY_PATH)

    secure = PageServer((address, DIRECT_TLS_PORT), handler, behind_edge=False)
    secure.socket = context.wrap_socket(secure.socket, server_side=True,
                                        do_handshake_on_connect=False)
    threading.Thread(target=secure.serve_forever, daemon=True).start()

    plain = PageServer((address, DIRECT_PLAIN_PORT), UpgradeHandler,
                       behind_edge=False)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    print(f'direct entry point on {address}', flush=True)


def main():
    handler = functools.partial(SubscriptionHandler, directory=SERVE_DIR)
    address = direct_address()
    if address is not None and CERTIFICATE_PATH.exists():
        serve_direct(address, handler)
    with PageServer(('127.0.0.1', PORT), handler, behind_edge=True) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
