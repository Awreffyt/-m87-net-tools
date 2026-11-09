#!/usr/bin/env python3
# 版权所有 (c) 2026 Awreffyt。保留所有权利。未经书面许可，禁止复制、修改、分发、反向工程。
"""定时快照：在 GitHub Actions 里跑，替浏览器过掉 Cookie 门禁。

浏览器受同源策略限制，解出来的门禁 Cookie 无法写进目标域，公共中继又不转发
Cookie，所以静态页面永远只能拿到 851 字节的挑战页。这里换个执行环境：Actions
有真实网络和 Cookie 容器，抓完把正文落成 JSON，网页版再回来读。

用法：维护 snapshots.txt，每行一个 URL，提交后自动生效。
"""
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'web', 'snapshots')
LIST = os.path.join(ROOT, 'snapshots.txt')


def slug(url):
    """FNV-1a 32 位，前端有同名实现，必须保持一致。"""
    h = 0x811C9DC5
    for b in url.encode('utf-8'):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return '%08x' % h


def norm(url):
    u = url.strip()
    for p in ('https://', 'http://'):
        if u.startswith(p):
            u = p + u[len(p):]
            break
    u = u.split('#')[0]
    while u.endswith('/') and len(u) > 8:
        u = u[:-1]
    return u


def main():
    if not os.path.exists(LIST):
        print('缺少 snapshots.txt')
        return 0
    sys.path.insert(0, ROOT)
    import m87  # 启动器把核心注入 globals，grab 可直接用

    urls = [norm(l) for l in open(LIST, encoding='utf-8')
            if l.strip() and not l.strip().startswith('#')]
    os.makedirs(OUT, exist_ok=True)
    ok = 0
    for url in urls:
        try:
            status, ctype, raw, enc, notes = m87.grab(url, timeout=45)
            body = raw.decode('utf-8', 'replace')
            blocked = ('slowAES' in body[:2000]) or ('/aes.js' in body[:2000])
            if blocked:
                print('BLOCKED', url, len(raw))
                continue
            doc = {
                'url': url,
                'status': status,
                'bytes': len(raw),
                'fetched_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'html': body,
            }
            path = os.path.join(OUT, slug(url) + '.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(doc, f, ensure_ascii=False)
            print('OK', url, len(raw), '->', os.path.relpath(path, ROOT))
            ok += 1
        except Exception as e:
            print('FAIL', url, type(e).__name__, e)
        time.sleep(1)
    print('完成 %d/%d' % (ok, len(urls)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
