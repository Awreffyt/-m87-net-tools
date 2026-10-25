"""轻量反爬与防护：UA 拦截、频率限制、扫描路径封锁、安全响应头。

目标是拦住常见的自动化抓取、漏洞扫描和目录探测，不引入任何外部依赖，
也不改变前端行为。全部逻辑集中在本文件，约 150 行。
"""

from __future__ import annotations

import re
import threading
import time
import urllib.parse
from collections import deque

from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import JSONResponse

# 自动化工具、脚本客户端、常见爬虫和扫描器的 UA 特征
BOT_UA = re.compile(
    r"(curl|wget|python-requests|python-urllib|aiohttp|httpx|scrapy|"
    r"httpclient|go-http-client|okhttp|java/|libwww|phantomjs|headlesschrome|"
    r"selenium|puppeteer|playwright|"
    r"(?:google|bing|baidu|yandex|ahrefs|semrush|mj12|dot|apple)bot|"
    r"\bbot\b|spider|crawler|scanner|nikto|sqlmap|masscan|nmap)",
    re.I,
)

# 后门、配置泄露和常见扫描入口，直接返回 404，不暴露任何信息
SCAN_PATHS = (
    "/.env", "/.git", "/.svn", "/.hg", "/.DS_Store",
    "/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php",
    "/phpmyadmin", "/pma", "/admin.php", "/config.php", "/db.php",
    "/backup", "/shell", "/cgi-bin", "/actuator", "/server-status",
    "/console", "/manager/html", "/.aws", "/.ssh",
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
}

CSP = (
    "default-src 'self'; img-src 'self' data: https: http:; "
    "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
    "connect-src 'self' ws: wss:; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)

# 普通接口每分钟 240 次，探测、提取、DNS 等耗时接口每分钟 20 次
DEFAULT_LIMIT = (240, 60)
HEAVY_LIMIT = (20, 60)
HEAVY_PREFIX = "/api/tools"

# 5 分钟内触发 3 次限制，封禁 10 分钟
STRIKE_LIMIT = 3
STRIKE_WINDOW = 300
BAN_SECONDS = 600

_lock = threading.Lock()
_hits: dict[str, deque] = {}
_strikes: dict[str, deque] = {}
_banned: dict[str, float] = {}
_last_clean = 0.0


def _client_ip(request: Request | WebSocket) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "-"


def _is_bot(ua: str) -> bool:
    return not ua or len(ua) < 12 or bool(BOT_UA.search(ua))


def apply_headers(response: Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    response.headers.setdefault("Content-Security-Policy", CSP)
    if "server" in response.headers:
        del response.headers["server"]


def _deny(status: int, message: str, extra: dict | None = None) -> JSONResponse:
    response = JSONResponse({"detail": message}, status_code=status, headers=extra)
    apply_headers(response)
    return response


def _clean(now: float) -> None:
    global _last_clean
    if now - _last_clean < 30:
        return
    _last_clean = now
    for store, window in ((_hits, 60), (_strikes, STRIKE_WINDOW)):
        for key in list(store):
            queue = store[key]
            while queue and now - queue[0] > window:
                queue.popleft()
            if not queue:
                store.pop(key, None)
    for ip, until in list(_banned.items()):
        if until <= now:
            _banned.pop(ip, None)


def check(request: Request) -> Response | None:
    """请求进入业务逻辑前的统一检查，命中任一规则就返回拒绝响应。"""
    path = request.url.path
    # 云平台健康检查专用路径，无条件放行（其 UA 常为空或非浏览器）
    if path == "/healthz":
        return None
    if path.startswith(SCAN_PATHS):
        return _deny(404, "Not Found")
    if _is_bot(request.headers.get("user-agent", "")):
        return _deny(403, "Forbidden")

    limit, window = HEAVY_LIMIT if path.startswith(HEAVY_PREFIX) else DEFAULT_LIMIT
    ip = _client_ip(request)
    now = time.time()
    key = f"{ip}|{limit}"

    with _lock:
        _clean(now)
        until = _banned.get(ip)
        if until and until > now:
            return _deny(429, "Too Many Requests", {"Retry-After": str(int(until - now) + 1)})

        hits = _hits.setdefault(key, deque())
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
            strikes = _strikes.setdefault(ip, deque())
            while strikes and now - strikes[0] > STRIKE_WINDOW:
                strikes.popleft()
            strikes.append(now)
            if len(strikes) >= STRIKE_LIMIT:
                _banned[ip] = now + BAN_SECONDS
                strikes.clear()
            return _deny(429, "Too Many Requests", {"Retry-After": str(window)})
        hits.append(now)
    return None


def allow_ws(websocket: WebSocket) -> bool:
    """WebSocket 只接受正常浏览器，并校验来源与主机一致。"""
    if _is_bot(websocket.headers.get("user-agent", "")):
        return False
    origin = websocket.headers.get("origin", "")
    if origin:
        host = urllib.parse.urlsplit(origin).netloc
        if host and host != websocket.headers.get("host", ""):
            return False
    return True


def install(app: FastAPI) -> None:
    @app.middleware("http")
    async def _guard(request: Request, call_next):
        blocked = check(request)
        if blocked is not None:
            return blocked
        response = await call_next(request)
        apply_headers(response)
        return response

    @app.get("/robots.txt", include_in_schema=False)
    async def robots() -> Response:
        return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        """云平台（Render 等）健康检查入口，不校验 UA、不计数。"""
        return JSONResponse({"ok": True})
