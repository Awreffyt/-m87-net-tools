#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M87 取文中继（单文件，无常驻依赖）
GET /?url=<target>            -> 抓取并返回 HTML，自动过 slowAES 类 Cookie 门禁
GET /?url=<target>&bin=1      -> 原样返回二进制
所有响应带 CORS，可直接被网页 fetch。
"""
import base64
import json
import os
import re
import sys
import time
import urllib.parse

import requests
from Crypto.Cipher import AES
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
BUDGET = 25


def to_bytes(s):
    return bytes.fromhex(s)


def hex2bin(h):
    return bytes.fromhex(h)


def slowaes_solve(html):
    """从挑战页里取 key/iv/cipher，解出 __test 明文。返回 (name, value) 或 None"""
    if 'slowAES' not in html and 'toNumbers(' not in html:
        return None
    m = re.search(
        r'var\s+a\s*=\s*toNumbers\("([0-9a-fA-F]+)"\)\s*,\s*'
        r'b\s*=\s*toNumbers\("([0-9a-fA-F]+)"\)\s*,\s*'
        r'c\s*=\s*toNumbers\("([0-9a-fA-F]+)"\)', html)
    if not m:
        # 变体：页面直接把 cookie 明文写好（无加密），照抄即可
        md = re.search(r'document\.cookie\s*=\s*"([A-Za-z0-9_]+)=([^";]*)[^"]*"', html)
        if md:
            return md.group(1), md.group(2)
        return None
    key, iv, ct = hex2bin(m.group(1)), hex2bin(m.group(2)), hex2bin(m.group(3))
    try:
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        return None
    # 去 PKCS 填充
    if plain:
        n = plain[-1]
        if 0 < n <= 16 and plain.endswith(bytes([n]) * n):
            plain = plain[:-n]
    # 找到 document.cookie="NAME=" 的 cookie 名
    name = '__test'
    mc = re.search(r'document\.cookie\s*=\s*"([A-Za-z0-9_]+)=', html)
    if mc:
        name = mc.group(1)
    val = plain.hex()
    return name, val


def looks_gate(html):
    h = html[:8000]
    return ('slowAES' in h or 'toNumbers(' in h) and 'document.cookie' in h


def charset_from(headers, raw):
    ct = headers.get('content-type', '')
    m = re.search(r'charset=([\w-]+)', ct, re.I)
    if m:
        return m.group(1)
    m = re.search(rb'charset=["\']?([\w-]+)', raw[:2000], re.I)
    if m:
        return m.group(1).decode('ascii', 'ignore')
    return None


def fetch(url, as_bin=False):
    s = requests.Session()
    s.headers.update({'User-Agent': UA,
                      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'})
    t0 = time.time()
    r = s.get(url, timeout=15, allow_redirects=True)
    gate = 0
    # 最多两轮解门禁
    for _ in range(2):
        if r.encoding is None:
            pass
        try:
            text = r.content.decode('utf-8', 'replace')
        except Exception:
            text = ''
        sol = slowaes_solve(text)
        if not sol:
            break
        name, val = sol
        s.cookies.set(name, val, domain=urllib.parse.urlparse(r.url).hostname)
        r = s.get(url, timeout=15, allow_redirects=True)
        gate += 1
        if time.time() - t0 > BUDGET:
            break
    raw = r.content
    if as_bin:
        return {'status': r.status_code, 'body': raw, 'ctype': r.headers.get('content-type', 'application/octet-stream'),
                'gate': gate, 'final': r.url}
    cs = charset_from(r.headers, raw)
    try:
        text = raw.decode(cs or 'utf-8', 'replace')
    except Exception:
        text = raw.decode('utf-8', 'replace')
    if cs and cs.lower() in ('gbk', 'gb2312', 'gb18030'):
        text = raw.decode('gb18030', 'replace')
    return {'status': r.status_code, 'body': text.encode('utf-8'),
            'ctype': 'text/html; charset=utf-8', 'gate': gate, 'final': r.url}


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def _cors(self, extra=None):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,OPTIONS')
        self.send_header('Access-Control-Expose-Headers', 'X-M87-Gate,X-M87-Status,X-M87-Final')
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path not in ('/', '/fetch', '/m87'):
            self.send_response(404)
            self._cors()
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        q = urllib.parse.parse_qs(u.query)
        if (q.get('action') or [''])[0] == 'status':
            body = json.dumps({'ok': True, 'mode': 'm87-local', 'relay': 'python'}).encode()
            self.send_response(200)
            self._cors({'Content-Type': 'application/json; charset=utf-8'})
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        target = (q.get('url') or [''])[0]
        if not target and u.path != '/':
            target = urllib.parse.unquote(u.path[1:])
        if not target:
            body = json.dumps({'ok': False, 'error': 'missing url'}).encode()
            self.send_response(400)
            self._cors({'Content-Type': 'application/json'})
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not re.match(r'^https?://', target, re.I):
            target = 'http://' + target
        host = urllib.parse.urlparse(target).hostname or ''
        if host in ('127.0.0.1', 'localhost', '0.0.0.0') or host.startswith('192.168.') or host.startswith('10.'):
            if 'M87_ALLOW_LOCAL' not in os.environ:
                self.send_response(403)
                self._cors()
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        try:
            res = fetch(target, as_bin=(q.get('bin') or ['0'])[0] == '1')
        except Exception as e:
            body = json.dumps({'ok': False, 'error': str(e)[:200]}).encode()
            self.send_response(502)
            self._cors({'Content-Type': 'application/json'})
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = res['body']
        self.send_response(200)
        self._cors({'Content-Type': res['ctype'],
                    'X-M87-Gate': str(res['gate']),
                    'X-M87-Status': str(res['status']),
                    'X-M87-Final': urllib.parse.quote(res['final'], safe='')})
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print('relay on', port, flush=True)
    ThreadingHTTPServer(('0.0.0.0', port), H).serve_forever()
