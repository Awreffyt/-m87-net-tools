#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M87 本地服务（零依赖，只用 Python 标准库）

作用：
  1. 把 web/ 目录里的网页提供出来（http://127.0.0.1:8787）
  2. 代替浏览器去抓别的网站（/api/fetch），页面同源访问，没有跨域限制，也没有第三方代理
  3. 顺便返回状态码、响应头、重定向链，供「站点探测」使用

启动：双击 启动M87.bat（Windows）或 启动M87.command（Mac），
     也可以在终端里执行 python3 m87.py
"""

import json
import os
import socket
import ssl
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import (Request, build_opener, HTTPRedirectHandler,
                            HTTPSHandler)

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(ROOT, 'web')
VERSION = '2.5'

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')

BASE_HEADERS = {
    'User-Agent': UA,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'identity',
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


def _opener():
    tracker = _Tracker()
    # 允许访问证书有问题的站点（抓取工具需要看得到内容，而不是直接报错）
    handler = HTTPSHandler(context=_ssl_context())
    return build_opener(handler, tracker), tracker


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


def grab(url, limit=MAX_BYTES, timeout=FETCH_TIMEOUT):
    """服务端抓取：返回 (状态码, Content-Type, 正文bytes, 最终URL, 重定向链)"""
    opener, tracker = _opener()
    req = Request(url, headers=BASE_HEADERS)
    resp = opener.open(req, timeout=timeout)
    body = resp.read(limit)
    return (
        resp.status,
        resp.headers.get('Content-Type', ''),
        body,
        resp.geturl(),
        tracker.chain,
    )


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
        try:
            status, ctype, body, final, chain = grab(url)
        except HTTPError as e:
            # 目标返回 4xx/5xx：正文通常仍有价值，原样回传
            try:
                body = e.read() or b''
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
