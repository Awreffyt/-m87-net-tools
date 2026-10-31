#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# © 2026 M87 · 自有手写资产，未经授权禁止复制、转售或二次分发
"""
M87 本地服务（零依赖，只用 Python 标准库）

作用：
  1. 把 web/ 目录里的网页提供出来（http://127.0.0.1:8787）
  2. 代替浏览器去抓别的网站（/api/fetch），页面同源访问，没有跨域限制，也没有第三方代理
  3. 顺便返回状态码、响应头、重定向链，供「站点探测」使用

启动：双击 启动M87.bat（Windows）或 启动M87.command（Mac），
     也可以在终端里执行 python3 m87.py
"""

import gzip
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import webbrowser
import zlib
from http.cookiejar import Cookie, CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse
from urllib.request import (Request, build_opener, HTTPCookieProcessor,
                            HTTPRedirectHandler,
                            HTTPSHandler)

try:
    import brotli as _brotli
except Exception:
    _brotli = None

import aeslite

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(ROOT, 'web')
VERSION = '2.6'

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')

# 有些站只认特定 UA，主 UA 被 403/503 时换这一个再试
UA_ALT = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
          '(KHTML, like Gecko) Version/17.0 Safari/605.1.15')

BASE_HEADERS = {
    'User-Agent': UA,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate' + (', br' if _brotli is not None else ''),
    'Connection': 'close',
}

MAX_BYTES = 40 * 1024 * 1024
FETCH_TIMEOUT = 25
CHECK_TIMEOUT = 12


class _Tracker(HTTPRedirectHandler):
    """记录重定向链，方便前端展示跳转过程。"""

    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({'status': code, 'url': newurl})
        return HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


def _opener(jar=None):
    tracker = _Tracker()
    # 允许访问证书有问题的站点（抓取工具需要看得到内容，而不是直接报错）
    handler = HTTPSHandler(context=_ssl_context())
    cookied = HTTPCookieProcessor(jar if jar is not None else CookieJar())
    return build_opener(handler, tracker, cookied), tracker


# ---------------------------------------------------------------- 会话

# 每个域名一份 cookie 容器：过门禁拿到的 cookie 要留给同站的后续资源请求
_JARS = {}
_JARS_LOCK = threading.Lock()
_JAR_MAX = 300


def _jar_for(url):
    host = urlparse(url).hostname or ''
    with _JARS_LOCK:
        jar = _JARS.get(host)
        if jar is None:
            if len(_JARS) > _JAR_MAX:
                _JARS.clear()
            jar = CookieJar()
            _JARS[host] = jar
        return jar


def _decode_body(resp, raw, limit):
    """服务器若无视 identity 仍压缩了，这里补解，否则正文会变成乱码。"""
    enc = (resp.headers.get('Content-Encoding') or '').lower()
    if 'gzip' in enc:
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    elif 'deflate' in enc:
        try:
            raw = zlib.decompress(raw)
        except Exception:
            try:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except Exception:
                pass
    elif 'br' in enc and _brotli is not None:
        try:
            raw = _brotli.decompress(raw)
        except Exception:
            pass
    return raw[:limit]


# ---------------------------------------------------------------- JS Cookie 门禁

# 免费主机（wuaze / InfinityFree 等）常用这套：服务器先只发一段 slowAES 脚本，
# 浏览器算出一个 cookie 再跳回来，服务器校验通过才给真页面。
_CHALLENGE_KEYS = ('slowAES.decrypt', 'document.cookie', 'toNumbers(')


def unpack_packer(text):
    """还原 Dean Edwards packer：eval(function(p,a,c,k,e,d){...}(...))
       有些门禁会把脚本包一层 packer，不解开就认不到。"""
    if not text or 'function(p,a,c,k,e,d)' not in text:
        return text
    m = re.search(
        r"eval\(\s*function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)\s*\{[\s\S]*?\}"
        r"\s*\(\s*(['\"])((?:\\.|(?!\1).)*)\1\s*,\s*(\d+)\s*,\s*(\d+)\s*,"
        r"\s*(['\"])((?:\\.|(?!\5).)*)\5\.split\(\s*['\"]\|['\"]\s*\)\s*,\s*0\s*,\s*\{\s*\}\s*\)\s*\)",
        text)
    if not m:
        return text
    p = _js_str(m.group(1) + m.group(2) + m.group(1))
    try:
        a = int(m.group(3))
        c = int(m.group(4))
    except Exception:
        return text
    k = _js_str(m.group(5) + m.group(6) + m.group(5)).split('|')
    if not a or not c or not k:
        return text

    import string as _string
    digits = _string.digits + _string.ascii_lowercase

    def to_str(n):
        s = ''
        while n:
            r = n % a
            s = (chr(r + 29) if r > 35 else (digits[r] if r < len(digits) else '')) + s
            n //= a
        return s

    dict_map = {}
    keys = []
    for i in range(c):
        word = k[i] if i < len(k) else ''
        key = to_str(i)
        if word and word != key:
            dict_map[key] = word
            keys.append(key)
    if not keys:
        return p
    pattern = re.compile(r'\b(' + '|'.join(re.escape(k2) for k2 in keys) + r')\b')
    return pattern.sub(lambda m2: dict_map.get(m2.group(0), m2.group(0)), p)


def _js_str(s):
    """解析 JS 字符串字面量（含转义），不调用 eval。"""
    body = s[1:-1]
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '\\' and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == 'u' and i + 6 <= len(body):
                out.append(chr(int(body[i + 2:i + 6], 16)))
                i += 6
                continue
            if nxt == 'x' and i + 4 <= len(body):
                out.append(chr(int(body[i + 2:i + 4], 16)))
                i += 4
                continue
            if nxt in '01234567':
                j = i + 1
                octal = ''
                while j < len(body) and body[j] in '01234567' and len(octal) < 3:
                    octal += body[j]
                    j += 1
                out.append(chr(int(octal, 8) & 0xff))
                i = j
                continue
            mapping = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b',
                       'f': '\f', 'v': '\v', '0': '\0', "'": "'",
                       '"': '"', '`': '`', '\\': '\\', '/': '/'}
            out.append(mapping.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def solve_cookie_challenge(html, base_url):
    """识别门禁脚本，纯本地算出 cookie。返回 (名字, 值, 下一跳URL)，认不出返回 None。"""
    text = unpack_packer(html) if isinstance(html, str) else html
    if not all(k in text for k in _CHALLENGE_KEYS):
        return None
    nums = dict(re.findall(
        r'([A-Za-z_$][0-9A-Za-z_$]*)\s*=\s*toNumbers\(\s*["\']([0-9a-fA-F]+)["\']\s*\)', text))
    call = re.search(
        r'slowAES\.decrypt\(\s*([A-Za-z_$][0-9A-Za-z_$]*)\s*,\s*(\d+)\s*,\s*'
        r'([A-Za-z_$][0-9A-Za-z_$]*)\s*,\s*([A-Za-z_$][0-9A-Za-z_$]*)\s*\)', text)
    if not nums or not call:
        return None
    ct_name, mode, key_name, iv_name = call.groups()
    if mode != '2':  # 只处理 CBC
        return None
    if not all(k in nums for k in (ct_name, key_name, iv_name)):
        return None
    try:
        key = bytes.fromhex(nums[key_name])
        iv = bytes.fromhex(nums[iv_name])
        ct = bytes.fromhex(nums[ct_name])
        # slowAES 解密后不去填充，toHex 直接把整段字节转十六进制
        value = aeslite.cbc_decrypt(ct, key, iv, unpad=False).hex()
    except Exception:
        return None
    name_hit = re.search(r'document\.cookie\s*=\s*["\']([^"\'=;\s]+)=', text)
    name = name_hit.group(1) if name_hit else '__test'
    loc_hit = re.search(r'location\.href\s*=\s*["\']([^"\']+)["\']', text)
    nxt = urljoin(base_url, loc_hit.group(1)) if loc_hit else base_url
    return name, value, nxt


def _wall_reason(body):
    """Cloudflare 之类的人机验证页：服务端过不去，直接给一句人话。"""
    if len(body) > 40 * 1024:
        return ''
    text = body[:6000].decode('utf-8', 'ignore').lower()
    marks = ('just a moment', 'checking your browser', 'cf-challenge',
             '/cdn-cgi/challenge-platform', 'enable javascript and cookies')
    if any(m in text for m in marks):
        return ('该站启用了人机验证（Cloudflare 等），服务器过不去。'
                '用浏览器打开一次通过验证后再抓；仍然不行说明它专门拦非浏览器访问。')
    return ''


def _set_cookie(jar, url, name, value):
    host = urlparse(url).hostname or ''
    with _JARS_LOCK:
        jar.set_cookie(Cookie(
            0, name, value, None, False, host, False, False,
            '/', True, url.startswith('https'), None, True, None, None,
            {'HttpOnly': None}, False))



def _ssl_context():
    ctx = ssl.create_default_context()
    # 抓取工具要能看「证书有问题」的站点，不在这里中断
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _friendly(e):
    if isinstance(e, HTTPError):
        return 'HTTP %s' % e.code
    if isinstance(e, URLError):
        reason = getattr(e, 'reason', None)
        if isinstance(reason, socket.timeout):
            return '超时'
        text = str(reason or e)
        if 'Name or service not known' in text or 'nodename nor servname' in text:
            return '域名解析失败'
        if 'certificate' in text.lower() or 'ssl' in text.lower():
            return 'TLS 证书校验失败'
        if 'timed out' in text.lower():
            return '超时'
        if 'refused' in text.lower():
            return '目标拒绝连接'
        return text
    if isinstance(e, socket.timeout):
        return '超时'
    text = str(e)
    if 'certificate' in text.lower():
        return 'TLS 证书校验失败'
    return text or '未知错误'


def grab(url, limit=MAX_BYTES, timeout=FETCH_TIMEOUT, range_start=None):
    """服务端抓取：返回 (状态码, Content-Type, 正文bytes, 最终URL, 重定向链)
       range_start 不为 None 时带 Range 头，用于分片下大文件。"""
    jar = _jar_for(url)
    opener, tracker = _opener(jar)

    headers = dict(BASE_HEADERS)
    parts = urlparse(url)
    # 资源请求带上站内 Referer：不少站按防盗链规则直接拒绝裸请求
    if parts.path not in ('', '/'):
        headers['Referer'] = '%s://%s/' % (parts.scheme, parts.netloc)
    if range_start is not None:
        headers['Range'] = 'bytes=%d-' % range_start

    def _open(hdr, target=url):
        return opener.open(Request(target, headers=hdr), timeout=timeout)

    # 连接被重置/中途断开时重试一次（部分站的反爬会主动掐连接）
    last_err = None
    for attempt in range(2):
        try:
            try:
                resp = _open(headers)
            except HTTPError as e:
                # 有的站只认特定 UA：403/503 时换一个再来一次
                if e.code not in (403, 503):
                    raise
                alt = dict(headers)
                alt['User-Agent'] = UA_ALT
                resp = _open(alt)
            last_err = None
            break
        except (URLError, socket.error, ConnectionResetError) as e:
            text = str(getattr(e, 'reason', e) or e).lower()
            if attempt == 0 and any(k in text for k in ('reset', 'broken pipe', 'eof', 'connection')):
                last_err = e
                time.sleep(0.4)
                continue
            raise

    if last_err is not None:
        raise last_err

    body = _decode_body(resp, resp.read(limit), limit)
    status = resp.status
    ctype = resp.headers.get('Content-Type', '')
    final = resp.geturl()

    # 命中 JS Cookie 门禁时，本地算出 cookie 再请求一次（最多一次，避免死循环）
    if len(body) < 64 * 1024 and (b'toNumbers' in body or b'function(p,a,c,k,e,d)' in body):
        try:
            solved = solve_cookie_challenge(body.decode('utf-8', 'ignore'), final)
        except Exception:
            solved = None
        if solved:
            name, value, nxt = solved
            _set_cookie(jar, nxt, name, value)
            resp2 = _open(BASE_HEADERS, nxt)
            body = _decode_body(resp2, resp2.read(limit), limit)
            status = resp2.status
            ctype = resp2.headers.get('Content-Type', '')
            final = resp2.geturl()

    # meta refresh 自动跳转（urllib 只认 Location，不认 HTML 里的 meta）
    if 200 <= status < 400 and ctype and 'html' in ctype.lower():
        try:
            head = body[:8192].decode('utf-8', 'ignore')
            mm = re.search(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d+;?\s*url\s*=\s*([^"\'<>]+)', head, re.I)
            if not mm:
                mm = re.search(r'content\s*=\s*["\']?\d+;?\s*url\s*=\s*([^"\'<>]+)', head, re.I)
            if mm:
                nxt = urljoin(final, mm.group(1).strip().strip('"').strip("'"))
                try:
                    resp2 = _open(BASE_HEADERS, nxt)
                    body = _decode_body(resp2, resp2.read(limit), limit)
                    status = resp2.status
                    ctype = resp2.headers.get('Content-Type', '')
                    final = resp2.geturl()
                    tracker.chain.append({'status': 0, 'url': nxt})
                except Exception:
                    pass
        except Exception:
            pass

    return (status, ctype, body, final, tracker.chain)


def check(url, timeout=CHECK_TIMEOUT):
    """只探测：状态码 + 响应头 + 重定向链，正文只读一小段。"""
    started = time.time()
    opener, tracker = _opener()
    req = Request(url, headers=BASE_HEADERS)
    try:
        resp = opener.open(req, timeout=timeout)
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
        final = resp.geturl()
        try:
            resp.read(8192)
        except Exception:
            pass
        resp.close()
        return {
            'open': True,
            'status': status,
            'ms': int((time.time() - started) * 1000),
            'finalUrl': final,
            'contentType': headers.get('content-type', ''),
            'server': headers.get('server', ''),
            'headers': headers,
            'chain': tracker.chain,
        }
    except HTTPError as e:
        # 4xx/5xx 也说明「连上了」，只是状态码不好看
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()} if e.headers else {}
        return {
            'open': True,
            'status': e.code,
            'ms': int((time.time() - started) * 1000),
            'finalUrl': e.geturl(),
            'contentType': hdrs.get('content-type', ''),
            'server': hdrs.get('server', ''),
            'headers': hdrs,
            'chain': tracker.chain,
        }
    except Exception as e:
        return {
            'open': False,
            'ms': int((time.time() - started) * 1000),
            'error': _friendly(e),
        }


class Handler(BaseHTTPRequestHandler):
    server_version = 'M87Local/' + VERSION
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):  # 少打日志，只留错误
        pass

    # ---------------------------------------------------------------- 工具

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Expose-Headers', '*')

    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._cors()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _bytes(self, code, data, ctype, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype or 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self._cors()
        for key, value in (extra or {}).items():
            if value:
                self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    # ---------------------------------------------------------------- 路由

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == '/api/status':
            return self._json(200, {'ok': True, 'mode': 'm87-local', 'version': VERSION})
        if path == '/api/fetch':
            return self._api_fetch(query)
        if path == '/api/check':
            return self._api_check(query)
        if path.startswith('/api/'):
            return self._json(404, {'error': '未知接口：' + path})
        return self._static(path)

    # ---------------------------------------------------------------- 接口

    def _target(self, query):
        url = (query.get('url') or [''])[0]
        if not url:
            return None, '缺少 url 参数'
        if not url.lower().startswith(('http://', 'https://')):
            return None, 'url 必须以 http:// 或 https:// 开头'
        return url, None

    def _api_fetch(self, query):
        url, bad = self._target(query)
        if bad:
            return self._json(400, {'error': bad})
        binary = (query.get('bin') or ['0'])[0] == '1'
        range_start = None
        try:
            rs = (query.get('range') or [''])[0]
            if rs:
                range_start = max(0, int(rs))
        except (TypeError, ValueError):
            range_start = None
        try:
            status, ctype, body, final, chain = grab(url, range_start=range_start)
        except HTTPError as e:
            # 目标返回 4xx/5xx：正文通常仍有价值，原样回传
            try:
                body = e.read() or b''
                # 4xx/5xx 响应也可能被 gzip 压缩，必须解压否则前端拿到乱码
                body = _decode_body(e, body, MAX_BYTES)
            except Exception:
                body = b''
            fallback = 'application/octet-stream' if binary else 'text/plain; charset=utf-8'
            return self._bytes(200, body, (e.headers.get('Content-Type') if e.headers else '') or fallback, {
                'X-M87-Status': str(e.code),
                'X-M87-Final-Url': quote(e.geturl() or url, safe=':/?&=#%+'),
                'X-M87-Redirects': '0',
            })
        except Exception as e:
            return self._json(502, {'error': _friendly(e)})

        # 人机验证页给一句人话，别让用户以为是工具坏了
        wall = _wall_reason(body)
        if wall:
            return self._json(502, {'error': wall})

        fallback = 'application/octet-stream' if binary else 'text/plain; charset=utf-8'
        return self._bytes(200, body, ctype or fallback, {
            'X-M87-Status': str(status),
            'X-M87-Final-Url': quote(final or url, safe=':/?&=#%+'),
            'X-M87-Redirects': str(len(chain)),
        })

    def _api_check(self, query):
        url, bad = self._target(query)
        if bad:
            return self._json(400, {'open': False, 'error': bad})
        return self._json(200, check(url))

    # ---------------------------------------------------------------- 静态文件

    def _static(self, path):
        if path in ('', '/'):
            path = '/index.html'
        rel = unquote(path).lstrip('/')
        full = os.path.realpath(os.path.join(WEB, rel))
        if not full.startswith(os.path.realpath(WEB)) or not os.path.isfile(full):
            return self._json(404, {'error': '文件不存在：' + rel})

        if full.endswith('.html'):
            ctype = 'text/html; charset=utf-8'
        elif full.endswith('.js'):
            ctype = 'application/javascript; charset=utf-8'
        elif full.endswith('.css'):
            ctype = 'text/css; charset=utf-8'
        elif full.endswith('.json'):
            ctype = 'application/json; charset=utf-8'
        elif full.endswith('.svg'):
            ctype = 'image/svg+xml'
        elif full.endswith('.png'):
            ctype = 'image/png'
        elif full.endswith('.ico'):
            ctype = 'image/x-icon'
        else:
            ctype = 'application/octet-stream'

        try:
            with open(full, 'rb') as fh:
                data = fh.read()
        except OSError as e:
            return self._json(500, {'error': '读取失败：' + str(e)})

        return self._bytes(200, data, ctype, {'Cache-Control': 'no-store'})


def pick_port(start=8787, tries=8):
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    return None


def main():
    port = pick_port()
    if not port:
        print('端口 8787-8794 都被占用了，请关掉其他 M87 窗口后重试。')
        return 1

    url = 'http://127.0.0.1:%d/' % port
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True

    print('')
    print('  M87 本地服务已启动')
    print('  地址：%s' % url)
    print('  关闭窗口即停止。抓取过程中请不要关这个窗口。')
    print('')

    threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print('已停止。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
