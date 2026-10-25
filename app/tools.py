"""网站工具箱后端：站点探测、资源提取、DNS 查询、资源打包。

设计要点：
* 所有外部请求都经由环境变量中的 HTTP(S)_PROXY（沙箱/容器内可直接用）
* 默认禁止访问内网/本机地址（SSRF 防护），可用 ALLOW_PRIVATE_TARGETS=1 关闭
* 不依赖任何第三方服务，前端只调用同源 /api/tools/*
"""

from __future__ import annotations

import concurrent.futures
import gzip
import io
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from datetime import datetime, timezone
from html.parser import HTMLParser

# 标准浏览器 UA，避免自定义标识被站点识别为爬虫
UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)
UA = UA_POOL[0]
TIMEOUT = 14
MAX_HTML_BYTES = 3 * 1024 * 1024
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_TARGETS", "0") == "1"

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS 强制加密传输", "high"),
    ("content-security-policy", "CSP 内容安全策略", "high"),
    ("x-content-type-options", "禁止 MIME 类型嗅探", "mid"),
    ("x-frame-options", "防点击劫持", "mid"),
    ("referrer-policy", "Referrer 泄露控制", "low"),
    ("permissions-policy", "浏览器特性权限控制", "low"),
    ("cross-origin-opener-policy", "跨源窗口隔离", "low"),
]

DOH_RESOLVERS = {
    "alidns": ("https://dns.alidns.com/resolve", "阿里 DNS (223.5.5.5)"),
    "cloudflare": ("https://cloudflare-dns.com/dns-query", "Cloudflare (1.1.1.1)"),
    "google": ("https://dns.google/resolve", "Google (8.8.8.8)"),
}
DNS_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    52: "TLSA", 65: "HTTPS", 257: "CAA",
}
ALL_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- 通用

def normalize_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ToolError("请输入网址")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ToolError("仅支持 http / https 网址")
    if not parsed.hostname:
        raise ToolError("网址格式不正确")
    return value


def _assert_public(url: str) -> None:
    """阻止访问内网 / 本机地址，避免 SSRF。

    只拦截「全部解析结果都是内网」的情况：CDN 域名常会混入保留段地址，
    只要存在一个公网地址就放行，避免误杀正常站点。
    """
    if ALLOW_PRIVATE:
        return
    host = urllib.parse.urlparse(url).hostname
    if not host:
        raise ToolError("网址缺少主机名")
    # 主机本身就是 IP 字面量时严格校验
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.is_private or literal.is_loopback or literal.is_link_local or literal.is_reserved:
            raise ToolError("出于安全考虑，禁止访问内网 / 本机地址")
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ToolError(f"域名解析失败：{host}") from exc
    has_public = False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            has_public = True
            break
    if not has_public:
        raise ToolError("出于安全考虑，禁止访问内网 / 本机地址")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


# 各类反爬 / 人机校验页的特征词
CHALLENGE_MARKERS = (
    "just a moment", "attention required", "checking your browser",
    "enable javascript and cookies", "cf-browser-verification",
    "challenge-platform", "cf_chl_opt", "ddos-guard", "sgcaptcha",
    "verify you are human", "are you a robot", "captcha",
    "访问异常", "人机验证", "请输入验证码", "请开启 javascript",
)


def _detect_challenge(html: str, headers: dict, status: int) -> str:
    """识别 Cloudflare 等反爬拦截页，返回拦截方描述；未命中返回空串。"""
    if not html:
        return ""
    server = str((headers or {}).get("server") or "").lower()
    low = html[:30000].lower()
    if (headers or {}).get("cf-mitigated"):
        return "Cloudflare 人机校验"
    if status in (202, 403, 429, 503):
        if "cloudflare" in server:
            return "Cloudflare 拦截"
        for marker in CHALLENGE_MARKERS:
            if marker in low:
                return "站点反爬校验"
    # 页面小得反常且含校验特征
    if len(html) < 8000:
        for marker in CHALLENGE_MARKERS:
            if marker in low:
                return "站点反爬校验"
    if status == 202 and len(html) < 8000:
        return "站点异步校验（HTTP 202）"
    return ""


def _decode_body(body: bytes, content_type: str) -> str:
    charset = None
    match = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    if match:
        charset = match.group(1)
    if not charset:
        head = body[:2048].decode("ascii", "ignore")
        match = re.search(r"<meta[^>]+charset=[\"']?([\w-]+)", head, re.I)
        if match:
            charset = match.group(1)
    try:
        return body.decode(charset or "utf-8", "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def http_get(url: str, max_bytes: int = MAX_HTML_BYTES, timeout: float = TIMEOUT,
             max_hops: int = 6, extra_headers: dict | None = None) -> dict:
    """抓取 URL，手动跟随跳转并记录完整跳转链。"""
    chain: list[dict] = []
    current = url
    started = time.time()
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        # 只声明 gzip / deflate，避免拿到无法解码的 br 响应
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    if extra_headers:
        headers.update(extra_headers)
    for _ in range(max_hops):
        _assert_public(current)
        req = urllib.request.Request(current, headers=headers)
        try:
            resp = _OPENER.open(req, timeout=timeout)
            status = resp.status
            headers = resp.headers
            body = resp.read(max_bytes)
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = exc.headers
            try:
                body = exc.read(max_bytes)
            except Exception:
                body = b""
        except Exception as exc:  # noqa: BLE001
            return {
                "url": current, "open": False, "status": None,
                "latency": round((time.time() - started) * 1000),
                "error": _short_error(exc), "redirectChain": chain,
                "finalUrl": current, "redirected": bool(chain),
                "headers": {}, "size": 0, "contentType": "", "isHtml": False,
            }

        # 处理 gzip / deflate 压缩响应
        encoding = (headers.get("Content-Encoding") or "").lower()
        if "gzip" in encoding:
            try:
                body = gzip.decompress(body)
            except OSError:
                pass
        elif "deflate" in encoding:
            try:
                body = zlib.decompress(body)
            except OSError:
                pass

        location = headers.get("Location")
        if status in (301, 302, 303, 307, 308) and location:
            target = urllib.parse.urljoin(current, location)
            chain.append({"from": current, "status": status, "to": target})
            current = target
            continue

        content_type = headers.get("Content-Type", "")
        text = _decode_body(body, content_type)
        is_html = "html" in content_type.lower() or text.lstrip()[:15].lower().startswith(("<!doctype html", "<html"))
        return {
            "url": url,
            "open": 200 <= status < 400,
            "status": status,
            "latency": round((time.time() - started) * 1000),
            "finalUrl": current,
            "redirected": bool(chain),
            "redirectChain": chain,
            "contentType": content_type,
            "isHtml": is_html,
            "size": len(body),
            "server": headers.get("Server", ""),
            "headers": {k.lower(): v for k, v in headers.items()},
            "text": text,
            "error": None,
        }
    return {
        "url": url, "open": False, "status": None, "finalUrl": current,
        "redirected": True, "redirectChain": chain,
        "latency": round((time.time() - started) * 1000),
        "error": "跳转次数过多", "headers": {}, "size": 0,
        "contentType": "", "isHtml": False,
    }


def _short_error(exc: Exception) -> str:
    text = str(exc)
    if isinstance(exc, socket.timeout) or "timed out" in text.lower():
        return "连接超时"
    if isinstance(exc, ssl.SSLError):
        return f"TLS 握手失败：{text}"
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, socket.timeout):
            return "连接超时"
        if isinstance(reason, socket.gaierror):
            return "域名解析失败"
        if isinstance(reason, ssl.SSLError):
            return f"TLS 握手失败：{reason}"
        if isinstance(reason, ConnectionRefusedError):
            return "连接被拒绝"
        return f"网络错误：{reason}"
    return f"{type(exc).__name__}: {text}"


# ---------------------------------------------------------------- TLS 证书

def _cert_name(items) -> str:
    if not items:
        return ""
    data = {key: value for group in items for key, value in group}
    return data.get("commonName") or data.get("organizationName") or ""


def tls_info(host: str, port: int = 443, timeout: float = 10) -> dict:
    """通过 HTTP CONNECT 代理（若配置）建立 TLS，读取证书信息。"""
    sock = None
    try:
        proxy = urllib.request.getproxies().get("https")
        if proxy:
            parsed = urllib.parse.urlparse(proxy if "://" in proxy else "http://" + proxy)
            sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout)
            request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
            sock.sendall(request)
            buffer = b""
            while b"\r\n\r\n" not in buffer and len(buffer) < 16384:
                chunk = sock.recv(2048)
                if not chunk:
                    raise OSError("代理隧道建立失败")
                buffer += chunk
            status_line = buffer.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if " 200" not in status_line:
                raise OSError(f"代理隧道建立失败：{status_line}")
        else:
            sock = socket.create_connection((host, port), timeout)

        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname=host)
        sock = None
        try:
            cert = tls_sock.getpeercert()
            version = tls_sock.version()
            cipher = tls_sock.cipher()
        finally:
            tls_sock.close()

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_left = (not_after - now).days
        sans = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
        issuer = _cert_name(cert.get("issuer"))
        subject = _cert_name(cert.get("subject"))
        return {
            "available": True,
            "issuer": issuer,
            "subject": subject,
            "validFrom": cert.get("notBefore"),
            "validTo": cert.get("notAfter"),
            "daysLeft": days_left,
            "expired": days_left < 0,
            "expiringSoon": 0 <= days_left < 21,
            "selfSigned": issuer == subject and bool(issuer),
            "san": sans[:20],
            "sanCount": len(sans),
            "version": version,
            "cipher": cipher[0] if cipher else "",
            "serial": cert.get("serialNumber", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": _short_error(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------- 站点探测

def _resolve_host(host: str) -> dict:
    started = time.time()
    ipv4: list[str] = []
    ipv6: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return {"resolved": False, "ips": [], "ipv4": [], "ipv6": [],
                "latency": round((time.time() - started) * 1000), "error": "域名解析失败"}
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        bucket = ipv4 if ip.version == 4 else ipv6
        if addr not in bucket:
            bucket.append(addr)
    return {
        "resolved": bool(ipv4 or ipv6),
        "ips": ipv4 + ipv6,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "latency": round((time.time() - started) * 1000),
    }


def _audit_headers(headers: dict) -> dict:
    items = []
    passed = 0
    for key, label, level in SECURITY_HEADERS:
        value = headers.get(key, "")
        present = bool(value)
        if present:
            passed += 1
        items.append({"key": key, "label": label, "level": level,
                      "present": present, "value": value[:300]})
    return {"items": items, "passed": passed, "total": len(items)}


def probe(raw_url: str) -> dict:
    normalized = normalize_url(raw_url)
    _assert_public(normalized)
    parsed = urllib.parse.urlparse(normalized)
    host = parsed.hostname
    if not host:
        raise ToolError("网址缺少主机名")
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    dns = _resolve_host(host)
    if not dns["resolved"]:
        raise ToolError(f"域名无法解析：{host}")

    http_result = https_result = None
    if port and port not in (80, 443):
        result = http_get(f"{parsed.scheme}://{host}:{port}{path}", max_bytes=512 * 1024)
        if parsed.scheme == "https":
            https_result = result
        else:
            http_result = result
    else:
        if parsed.scheme == "http":
            http_result = http_get(f"http://{host}{path}", max_bytes=512 * 1024)
            https_result = http_get(f"https://{host}{path}", max_bytes=512 * 1024)
        else:
            https_result = http_get(f"https://{host}{path}", max_bytes=512 * 1024)
            http_result = http_get(f"http://{host}{path}", max_bytes=512 * 1024)

    tls = tls_info(host, port or 443) if https_result and https_result.get("open") else {
        "available": False, "error": "HTTPS 不可用，跳过证书检测",
    }

    primary = https_result if (https_result and https_result.get("open")) else (http_result or {})
    headers = primary.get("headers", {}) if primary else {}
    security = _audit_headers(headers)
    for result in (http_result, https_result):
        if isinstance(result, dict):
            result.pop("text", None)

    score = 0
    hints: list[str] = []
    if dns["resolved"]:
        score += 20
    else:
        hints.append("域名无法解析，站点可能不存在或 DNS 配置有误。")
    https_open = bool(https_result and https_result.get("open"))
    http_open = bool(http_result and http_result.get("open"))
    if https_open:
        score += 25
    else:
        hints.append("HTTPS 访问失败，站点可能只支持 HTTP，存在安全风险。")
    if http_open:
        score += 5
    if https_open and tls.get("available") and not tls.get("expired"):
        score += 15
        if tls.get("daysLeft", 0) < 21:
            hints.append(f"TLS 证书将在 {tls.get('daysLeft')} 天后过期，请及时续期。")
        if tls.get("selfSigned"):
            hints.append("检测到自签名证书，浏览器会提示不安全。")
    elif https_open:
        hints.append("未能读取 TLS 证书信息。")
    for item in security["items"]:
        key = item["key"]
        if not item["present"]:
            if key in ("strict-transport-security", "content-security-policy"):
                hints.append(f"缺少 {item['label']} 响应头，建议补充。")
            continue
        if key == "strict-transport-security":
            score += 10
        elif key == "content-security-policy":
            score += 10
        elif key == "x-content-type-options":
            score += 5
        elif key in ("x-frame-options", "referrer-policy", "permissions-policy"):
            score += 2
    if http_open and https_open and not (http_result.get("redirectChain") or []):
        hints.append("HTTP 可以直接访问且未强制跳转 HTTPS，建议 301 重定向到 HTTPS。")
    score = max(0, min(score, 100))
    grade = "优秀" if score >= 90 else "良好" if score >= 75 else "一般" if score >= 60 else "待改进"

    if primary.get("isHtml") and not primary.get("error"):
        pass
    return {
        "target": host,
        "input": raw_url,
        "normalized": normalized,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dns": dns,
        "http": http_result,
        "https": https_result,
        "tls": tls,
        "security": security,
        "summary": {
            "reachable": http_open or https_open,
            "httpSupported": http_open,
            "httpsSupported": https_open,
            "isHtmlSite": bool(primary.get("isHtml")),
            "preferredProtocol": "https" if https_open else ("http" if http_open else "-"),
            "score": score,
            "grade": grade,
            "server": primary.get("server", ""),
            "finalUrl": primary.get("finalUrl", normalized),
        },
        "hints": hints,
    }


def probe_many(urls: list[str]) -> dict:
    urls = [u for u in urls if u.strip()][:12]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(probe, url): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"input": url, "error": _short_error(exc)})
    order = {url: i for i, url in enumerate(urls)}
    results.sort(key=lambda item: order.get(item.get("input", ""), 99))
    return {"results": results, "count": len(results)}


# ---------------------------------------------------------------- 资源提取

# 资源类扩展名（用于全文兜底扫描）
RES_EXT = (
    r"png|jpe?g|gif|webp|svg|bmp|ico|avif|"
    r"woff2?|ttf|otf|eot|"
    r"css|js|mjs|"
    r"mp4|webm|ogg|ogv|mp3|wav|m4a|m4v|flac|aac|mov|"
    r"pdf|zip|gz|rar|7z|json|xml|txt"
)
# 引号内的绝对 / 协议相对 URL
JS_RES_RE = re.compile(
    rf"""["'`]((?:https?:)?//[^"'`<>\\]+?\.(?:{RES_EXT})(?:\?[^"'`<>\\]*)?)["'`]""",
    re.I,
)
# 引号内的相对路径（/xxx, ./xxx, ../xxx）
JS_PATH_RE = re.compile(
    rf"""["'`]((?:/|\./|\.\./)[^"'`<>\\\s]+?\.(?:{RES_EXT})(?:\?[^"'`<>\\]*)?)["'`]""",
    re.I,
)
# 无引号包裹的绝对 URL（兜底扫描全文）
RAW_URL_RE = re.compile(
    rf"""https?://[^\s"'`<>()\\]+?\.(?:{RES_EXT})(?:\?[^\s"'`<>()\\]*)?""",
    re.I,
)


def _extract_js_urls(text: str) -> list[tuple[str, str]]:
    """从 JS / JSON 文本中提取可能的资源路径，返回 (地址, 来源标记)。"""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    if not text:
        return out
    for regex in (JS_RES_RE, JS_PATH_RE):
        for match in regex.finditer(text):
            raw = match.group(1)
            if raw in seen:
                continue
            seen.add(raw)
            lower = raw.lower()
            if re.search(r"\.(png|jpe?g|gif|webp|svg|bmp|ico|avif)(\?|$)", lower):
                out.append((raw, "js.image"))
            elif re.search(r"\.(woff2?|ttf|otf|eot)(\?|$)", lower):
                out.append((raw, "js.font"))
            elif re.search(r"\.css(\?|$)", lower):
                out.append((raw, "js.style"))
            elif re.search(r"\.m?js(\?|$)", lower):
                out.append((raw, "js.script"))
            elif re.search(r"\.(mp4|webm|ogv|m4v|mov)(\?|$)", lower):
                out.append((raw, "js.video"))
            elif re.search(r"\.(mp3|wav|m4a|flac|aac|ogg)(\?|$)", lower):
                out.append((raw, "js.audio"))
            else:
                out.append((raw, "js.url"))
    return out


def _extract_raw_urls(text: str) -> list[str]:
    """兜底：不看标签结构，直接扫全文里裸露的资源 URL。"""
    found: list[str] = []
    seen: set[str] = set()
    for match in RAW_URL_RE.finditer(text or ""):
        url = match.group(0)
        if url not in seen:
            seen.add(url)
            found.append(url)
    return found


class _Extract(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self._in_style = False
        self._in_script = False
        self.meta: dict[str, str] = {}
        self.base_href = ""
        self.canonical = ""
        self.images: list[tuple[str, str]] = []
        self.videos: list[tuple[str, str]] = []
        self.audios: list[tuple[str, str]] = []
        self.links: list[tuple[str, str]] = []
        self.scripts: list[tuple[str, str]] = []
        self.styles: list[tuple[str, str]] = []
        self.fonts: list[tuple[str, str]] = []
        self.iframes: list[tuple[str, str]] = []
        self.inline_js: list[str] = []
        self._js_buf: list[str] = []
        self._stack: list[str] = []

    # 懒加载 / 占位等常见资源属性
    _IMG_ATTRS = (
        "src", "data-src", "data-original", "data-lazy-src", "data-lazy",
        "data-url", "data-bg", "data-background", "data-background-image",
        "data-image", "data-thumb", "data-echo", "data-cfsrc", "data-poster",
        "data-full", "data-large", "data-original-src", "data-actualsrc",
    )
    _SRCSET_ATTRS = ("srcset", "data-srcset", "data-lazy-srcset")

    def handle_starttag(self, tag: str, attrs):
        data = {key.lower(): (value or "") for key, value in attrs}
        self._stack.append(tag)
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (data.get("property") or data.get("name") or data.get("itemprop") or "").lower()
            content = data.get("content", "")
            if key and content:
                self.meta[key] = content
            if data.get("charset"):
                self.meta.setdefault("charset", data["charset"])
            if key == "http-equiv" and data.get("charset"):
                self.meta.setdefault("charset", data["charset"])
            # 社交分享图的资源线索
            if key in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image",
                       "twitter:image:src", "image", "thumbnailurl"):
                if content:
                    self.images.append((content, f"meta.{key}"))
            elif key in ("og:video", "og:video:url", "og:video:secure_url", "twitter:player:stream"):
                if content:
                    self.videos.append((content, f"meta.{key}"))
            elif key in ("og:audio", "og:audio:url"):
                if content:
                    self.audios.append((content, f"meta.{key}"))
            elif key == "og:url" and content:
                self.links.append((content, "meta.og:url"))
        elif tag == "base":
            self.base_href = data.get("href", "")
        elif tag == "link":
            rel = data.get("rel", "").lower()
            href = data.get("href", "")
            as_type = data.get("as", "").lower()
            if not href:
                return
            if "stylesheet" in rel:
                self.styles.append((href, "stylesheet"))
            elif "icon" in rel or "apple-touch-icon" in rel or "mask-icon" in rel:
                self.images.append((href, "favicon"))
            elif "canonical" in rel:
                self.canonical = href
            elif "manifest" in rel:
                self.links.append((href, "link.manifest"))
            elif "modulepreload" in rel:
                self.scripts.append((href, "link.modulepreload"))
            elif "preload" in rel or "prefetch" in rel:
                if as_type == "image":
                    self.images.append((href, "preload"))
                elif as_type == "style":
                    self.styles.append((href, "preload"))
                elif as_type == "font":
                    self.fonts.append((href, "preload"))
                elif as_type == "script":
                    self.scripts.append((href, "preload"))
                elif as_type in ("video", "audio"):
                    (self.videos if as_type == "video" else self.audios).append((href, "preload"))
                elif re.search(r"\.(png|jpe?g|gif|webp|svg|avif)(\?|$)", href, re.I):
                    self.images.append((href, "preload"))
                elif re.search(r"\.m?js(\?|$)", href, re.I):
                    self.scripts.append((href, "preload"))
                elif re.search(r"\.css(\?|$)", href, re.I):
                    self.styles.append((href, "preload"))
            elif re.search(r"\.(woff2?|ttf|otf|eot)(\?|$)", href, re.I):
                self.fonts.append((href, "link"))
        elif tag in ("img", "input", "picture"):
            for attr in self._IMG_ATTRS:
                if data.get(attr):
                    self.images.append((data[attr], f"img.{attr}"))
            for attr in self._SRCSET_ATTRS:
                if data.get(attr):
                    for candidate in _parse_srcset(data[attr]):
                        self.images.append((candidate, f"img.{attr}"))
            _style_images(data.get("style", ""), self.images)
        elif tag == "source":
            parent = self._stack[-2] if len(self._stack) > 1 else ""
            if data.get("srcset"):
                for candidate in _parse_srcset(data["srcset"]):
                    (self.videos if parent == "video" else self.images).append((candidate, "source.srcset"))
            elif data.get("src"):
                kind = data.get("type", "")
                if parent == "video" or "video" in kind:
                    self.videos.append((data["src"], "source"))
                elif parent == "audio" or "audio" in kind:
                    self.audios.append((data["src"], "source"))
                elif re.search(r"\.(woff2?|ttf|otf)", data["src"], re.I):
                    self.fonts.append((data["src"], "source"))
        elif tag == "video":
            for attr in ("src", "data-src", "data-video"):
                if data.get(attr):
                    self.videos.append((data[attr], f"video.{attr}"))
            for attr in ("poster", "data-poster"):
                if data.get(attr):
                    self.images.append((data[attr], f"video.{attr}"))
            _style_images(data.get("style", ""), self.images)
        elif tag == "audio":
            for attr in ("src", "data-src"):
                if data.get(attr):
                    self.audios.append((data[attr], f"audio.{attr}"))
        elif tag == "script":
            self._in_script = True
            self._js_buf = []
            if data.get("src"):
                self.scripts.append((data["src"], "script.src"))
        elif tag == "iframe":
            if data.get("src") and not data["src"].startswith("about:"):
                self.iframes.append((data["src"], "iframe.src"))
            if data.get("data-src"):
                self.iframes.append((data["data-src"], "iframe.data-src"))
        elif tag == "a":
            href = data.get("href", "")
            if href:
                lower = href.lower()
                # 指向资源文件的链接也归类到对应类别
                if re.search(r"\.(png|jpe?g|gif|webp|svg|avif)(\?|$)", lower):
                    self.images.append((href, "a.href"))
                elif re.search(r"\.(mp4|webm|ogv|mov)(\?|$)", lower):
                    self.videos.append((href, "a.href"))
                elif re.search(r"\.(mp3|wav|m4a|flac|ogg)(\?|$)", lower):
                    self.audios.append((href, "a.href"))
                elif re.search(r"\.pdf(\?|$)", lower):
                    self.links.append((href, "a.pdf"))
                else:
                    self.links.append((href, "a.href"))
        elif tag in ("object", "embed"):
            src = data.get("data") or data.get("src")
            if src:
                self.iframes.append((src, f"{tag}.src"))
        elif tag == "form":
            if data.get("action") and data["action"].startswith(("http", "/")):
                self.links.append((data["action"], "form.action"))
        elif tag == "style":
            self._in_style = True
        # 任何元素上的内联背景图
        _style_images(data.get("style", ""), self.images)

    def handle_endtag(self, tag: str):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
            if self._js_buf:
                self.inline_js.append("".join(self._js_buf))
                self._js_buf = []
        elif tag == "style":
            self._in_style = False
        if self._stack:
            for index in range(len(self._stack) - 1, -1, -1):
                if self._stack[index] == tag:
                    del self._stack[index:]
                    break

    def handle_data(self, data: str):
        if self._in_title:
            self.title += data
        elif self._in_style:
            _style_images(data, self.images)
            for match in re.finditer(r"url\(\s*['\"]?([^'\")]+?\.(?:woff2?|ttf|otf|eot)[^'\")]*)[\"']?\s*\)", data, re.I):
                self.fonts.append((match.group(1), "css.font-face"))
            # CSS @import 引用的样式表
            for match in re.finditer(r"""@import\s+(?:url\()?\s*['"]([^'"]+)['"]""", data, re.I):
                self.styles.append((match.group(1), "css.import"))
        elif self._in_script:
            self._js_buf.append(data)

    def js_resources(self) -> list[tuple[str, str]]:
        """解析所有内联脚本，提取资源引用。"""
        out: list[tuple[str, str]] = []
        for chunk in self.inline_js:
            out.extend(_extract_js_urls(chunk))
        return out


def _parse_srcset(value: str) -> list[str]:
    out = []
    for part in value.split(","):
        url = part.strip().split(" ")[0]
        if url:
            out.append(url)
    return out


_JS_CAT_MAP = {
    "image": "images", "font": "fonts", "style": "styles",
    "script": "scripts", "video": "videos", "audio": "audios", "url": "links",
}


def _bucket_by_js(items: list[tuple[str, str]], buckets: dict[str, list]) -> None:
    """把 JS 里提取到的资源按类型放进对应分类桶。"""
    for raw, source in items:
        kind = source.split(".", 1)[1] if "." in source else "url"
        key = _JS_CAT_MAP.get(kind, "links")
        if key in buckets:
            buckets[key].append((raw, source))


def _bucket_raw_url(url: str, parser: "_Extract", source: str = "raw") -> None:
    """按扩展名把兜底扫描到的网址放进对应分类桶。"""
    lower = url.lower().split("?")[0]
    if re.search(r"\.(png|jpe?g|gif|webp|svg|bmp|ico|avif)$", lower):
        parser.images.append((url, source))
    elif re.search(r"\.(woff2?|ttf|otf|eot)$", lower):
        parser.fonts.append((url, source))
    elif re.search(r"\.css$", lower):
        parser.styles.append((url, source))
    elif re.search(r"\.m?js$", lower):
        parser.scripts.append((url, source))
    elif re.search(r"\.(mp4|webm|ogv|mov|m4v)$", lower):
        parser.videos.append((url, source))
    elif re.search(r"\.(mp3|wav|m4a|flac|aac|ogg)$", lower):
        parser.audios.append((url, source))
    else:
        parser.links.append((url, source))


def _style_images(style: str, bucket: list[tuple[str, str]]) -> None:
    if not style:
        return
    for match in re.finditer(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", style, re.I):
        bucket.append((match.group(1), "css.background"))


def _resolve(base: str, raw: str) -> str | None:
    value = (raw or "").strip().strip("\"'")
    if not value or value.startswith(("#", "data:", "javascript:", "mailto:", "tel:", "blob:", "about:")):
        return None
    try:
        absolute = urllib.parse.urljoin(base, value)
    except ValueError:
        return None
    if not absolute.startswith(("http://", "https://")):
        return None
    return absolute


def _filename(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    name = urllib.parse.unquote(path.rsplit("/", 1)[-1]) or "index"
    return name[:120]


def _collect(items: list[tuple[str, str]], base: str, limit: int = 800) -> list[dict]:
    seen = set()
    out = []
    for raw, source in items:
        resolved = _resolve(base, raw)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        out.append({
            "url": resolved,
            "filename": _filename(resolved),
            "host": urllib.parse.urlparse(resolved).hostname or "",
            "source": source,
        })
        if len(out) >= limit:
            break
    return out


def extract(raw_url: str, include_html: bool = True) -> dict:
    normalized = normalize_url(raw_url)
    fetched = _fetch_with_retry(normalized)
    if not fetched:
        raise ToolError("请求失败：目标站点无响应")
    if not fetched.get("open") or fetched.get("error"):
        raise ToolError(fetched.get("error") or f"请求失败（HTTP {fetched.get('status')}）")
    if not fetched.get("isHtml"):
        raise ToolError(f"目标不是 HTML 页面（Content-Type: {fetched.get('contentType') or '未知'}）")

    html = fetched.get("text", "")
    parser = _Extract()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        pass
    base = urllib.parse.urljoin(fetched.get("finalUrl") or normalized, parser.base_href or "")
    if parser.canonical:
        base = base or normalized

    # 内联脚本里藏着大量资源（SPA 站点几乎全在这里）
    inline = parser.js_resources()
    _bucket_by_js(inline, {
        "images": parser.images, "fonts": parser.fonts, "styles": parser.styles,
        "scripts": parser.scripts, "videos": parser.videos, "audios": parser.audios,
        "links": parser.links,
    })
    # 兜底：整页全文扫描裸露的资源 URL，补上任何标签/脚本解析漏掉的
    for url in _extract_raw_urls(html):
        _bucket_raw_url(url, parser, "raw.scan")

    groups = {
        "images": _collect(parser.images, base),
        "videos": _collect(parser.videos, base, 300),
        "audios": _collect(parser.audios, base, 200),
        "links": _collect(parser.links, base, 800),
        "scripts": _collect(parser.scripts, base, 300),
        "styles": _collect(parser.styles, base, 200),
        "fonts": _collect(parser.fonts, base, 200),
        "iframes": _collect(parser.iframes, base, 200),
    }
    counts = {key: len(value) for key, value in groups.items()}
    images = groups["images"]
    favicon = next((item["url"] for item in images if item["source"] == "favicon"), "")
    og_image = parser.meta.get("og:image") or parser.meta.get("twitter:image") or ""
    final_base = fetched.get("finalUrl") or normalized
    if og_image:
        resolved = _resolve(final_base, og_image)
        if resolved and resolved not in {item["url"] for item in images}:
            images.insert(0, {"url": resolved, "filename": _filename(resolved),
                              "host": urllib.parse.urlparse(resolved).hostname or "",
                              "source": "og:image"})

    result = {
        "page": {
            "input": raw_url,
            "url": final_base,
            "status": fetched.get("status"),
            "contentType": fetched.get("contentType"),
            "size": fetched.get("size"),
            "latency": fetched.get("latency"),
            "redirected": fetched.get("redirected"),
            "redirectChain": fetched.get("redirectChain"),
            "server": fetched.get("server", ""),
            "title": (parser.title or "").strip()[:300],
            "description": parser.meta.get("description", "")[:500],
            "keywords": parser.meta.get("keywords", "")[:300],
            "author": parser.meta.get("author", ""),
            "ogTitle": parser.meta.get("og_title", "") or parser.meta.get("og:title", ""),
            "ogImage": og_image,
            "canonical": _resolve(final_base, parser.canonical) if parser.canonical else "",
            "charset": parser.meta.get("charset", ""),
            "generator": parser.meta.get("generator", ""),
            "favicon": favicon,
        },
        "resources": groups,
        "counts": counts,
        "total": sum(counts.values()),
    }
    challenge = _detect_challenge(html, fetched.get("headers") or {}, fetched.get("status") or 0)
    if challenge:
        result["warning"] = (
            f"目标站点返回了{challenge}页面，HTTP {fetched.get('status')}，"
            f"真实 HTML 只有 {len(html)} 字节，静态抓取拿不到正文内容。"
            f"建议：换用站内其他入口地址、稍后重试，或改用「抓包分析」查看浏览器实际拿到的请求。"
        )
    if include_html:
        result["html"] = html[:1_200_000]
        result["htmlTruncated"] = len(html) > 1_200_000
    return result


# ---------------------------------------------------------------- 深度抓取（顺藤摸瓜）

CSS_URL_RE = re.compile(r"""url\(\s*(['"]?)([^)'"]+)\1\s*\)""", re.I)
NON_HTML_EXT = re.compile(
    r"\.(png|jpe?g|gif|webp|svg|bmp|ico|woff2?|ttf|otf|eot|css|js|"
    r"mp4|webm|ogg|mp3|wav|m4a|m4v|pdf|zip|gz|rar|7z|exe|apk|docx?|xlsx?|"
    r"pptx?|tar)(\?|$)",
    re.I,
)


def _extract_css_urls(text: str) -> list[tuple[str, str]]:
    """从 CSS 文本中提取所有 url() 引用，按扩展名粗分类。"""
    out: list[tuple[str, str]] = []
    for match in CSS_URL_RE.finditer(text or ""):
        raw = match.group(2).strip()
        if not raw or raw.startswith(("data:", "#", "//")):
            continue
        lower = raw.lower()
        if re.search(r"\.(woff2?|ttf|otf|eot)(\?|$)", lower):
            out.append((raw, "css.font"))
        elif re.search(r"\.(png|jpe?g|gif|webp|svg|bmp|ico)(\?|$)", lower):
            out.append((raw, "css.image"))
        else:
            out.append((raw, "css.url"))
    return out


def _fetch_with_retry(url: str, referer: str = "", max_bytes: int = MAX_HTML_BYTES) -> dict | None:
    """带 Referer 与 UA 轮换的重试抓取，用于应对简单反爬。"""
    extra = {"Referer": referer} if referer else {}
    for attempt in range(3):
        extra["User-Agent"] = random.choice(UA_POOL)
        result = http_get(url, max_bytes=max_bytes, extra_headers=extra)
        if result.get("open") and not result.get("error"):
            return result
        # 202 / 403 / 429 / 503 多半是触发反爬，换 UA 稍等再试
        if result.get("status") in (202, 403, 429, 503) and attempt < 2:
            time.sleep(0.6 + random.random() * 0.8)
            extra["Referer"] = referer or url
            continue
        return result
    return None


def _host_variants(host: str) -> set[str]:
    """生成同站主机名变体，兼容裸域与 www 前缀、大小写差异。"""
    if not host:
        return set()
    host = host.lower().strip()
    variants = {host}
    if host.startswith("www."):
        variants.add(host[4:])
    else:
        variants.add("www." + host)
    return variants


def deep_extract(raw_url: str, depth: int = 2, max_pages: int = 25) -> dict:
    """顺藤摸瓜：从入口页递归抓取同域内链，并对 CSS / JS 做二次资源挖掘。

    * depth: 递归深度，0 = 仅入口页，1 = 入口 + 一层子页，最大 4
    * max_pages: 最多抓取的 HTML 页面数，上限 80
    """
    depth = max(0, min(int(depth), 4))
    max_pages = max(1, min(int(max_pages), 80))
    normalized = normalize_url(raw_url)
    root_host = urllib.parse.urlparse(normalized).hostname
    if not root_host:
        raise ToolError("网址缺少主机名")
    # 允许的主机集合：入口域名 + www / 裸域变体，入口跳转后再补充实际域名
    allowed_hosts = _host_variants(root_host)

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(normalized, 0)]
    pages: list[dict] = []
    all_groups: dict[str, list[dict]] = {
        "images": [], "videos": [], "audios": [], "links": [],
        "scripts": [], "styles": [], "fonts": [], "iframes": [],
    }
    seen_resources: set[str] = set()
    css_seen: set[str] = set()
    js_seen: set[str] = set()
    challenge_note = ""

    def _merge(items: list[dict], category: str) -> None:
        for item in items:
            url = item["url"]
            if url in seen_resources:
                continue
            seen_resources.add(url)
            item["category"] = category
            all_groups[category].append(item)

    while queue and len(pages) < max_pages:
        url, level = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        fetched = _fetch_with_retry(url, referer=normalized)
        if not fetched:
            continue
        if not fetched.get("isHtml"):
            continue

        html = fetched.get("text", "")
        challenge = _detect_challenge(html, fetched.get("headers") or {}, fetched.get("status") or 0)
        if challenge and not challenge_note:
            challenge_note = challenge
        parser = _Extract()
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001
            pass
        base = urllib.parse.urljoin(fetched.get("finalUrl") or url, parser.base_href or "")

        final_url = fetched.get("finalUrl") or url
        final_host = urllib.parse.urlparse(final_url).hostname or ""
        if final_host:
            # 入口跳转后的真实域名也算同站，避免裸域跳 www 后内链全被过滤
            allowed_hosts.update(_host_variants(final_host))
        pages.append({
            "url": final_url,
            "title": (parser.title or "").strip()[:200],
            "status": fetched.get("status"),
            "size": fetched.get("size"),
            "depth": level,
        })

        # 收集本页八类资源
        # 内联脚本里藏着大量资源（SPA 站点几乎全在这里）
        _bucket_by_js(parser.js_resources(), {
            "images": parser.images, "fonts": parser.fonts, "styles": parser.styles,
            "scripts": parser.scripts, "videos": parser.videos, "audios": parser.audios,
            "links": parser.links,
        })
        # 兜底：整页全文扫描裸露的资源 URL
        for raw_url_found in _extract_raw_urls(html):
            _bucket_raw_url(raw_url_found, parser, "raw.scan")

        _merge(_collect(parser.images, base, limit=2000), "images")
        _merge(_collect(parser.videos, base, limit=500), "videos")
        _merge(_collect(parser.audios, base, limit=300), "audios")
        _merge(_collect(parser.links, base, limit=2000), "links")
        _merge(_collect(parser.scripts, base, limit=500), "scripts")
        _merge(_collect(parser.styles, base, limit=300), "styles")
        _merge(_collect(parser.fonts, base, limit=300), "fonts")
        _merge(_collect(parser.iframes, base, limit=200), "iframes")

        # 二次挖掘：抓取外部 CSS，提取 url() 中的图片 / 字体
        if level < depth:
            css_items = _collect(parser.styles, base, limit=16)
            for style in css_items:
                css_url = style["url"]
                if css_url in css_seen:
                    continue
                css_seen.add(css_url)
                try:
                    _assert_public(css_url)
                    css_fetched = _fetch_with_retry(css_url, referer=url, max_bytes=512 * 1024)
                    if css_fetched and css_fetched.get("open"):
                        css_text = css_fetched.get("text", "")
                        found = _extract_css_urls(css_text)
                        img_items = _collect([(r, s) for r, s in found if s == "css.image"], css_url, limit=400)
                        font_items = _collect([(r, s) for r, s in found if s == "css.font"], css_url, limit=200)
                        _merge(img_items, "images")
                        _merge(font_items, "fonts")
                except Exception:  # noqa: BLE001
                    continue
                time.sleep(0.08 + random.random() * 0.12)

        # 二次挖掘：抓取外部 JS，正则提取资源路径
        if level < depth:
            js_items = _collect(parser.scripts, base, limit=16)
            for script in js_items:
                js_url = script["url"]
                if js_url in js_seen:
                    continue
                js_seen.add(js_url)
                try:
                    _assert_public(js_url)
                    js_fetched = _fetch_with_retry(js_url, referer=url, max_bytes=1024 * 1024)
                    if js_fetched and js_fetched.get("open"):
                        js_text = js_fetched.get("text", "")
                        for raw, source in _extract_js_urls(js_text):
                            resolved = _resolve(js_url, raw)
                            if not resolved or resolved in seen_resources:
                                continue
                            seen_resources.add(resolved)
                            cat_key = source.split(".", 1)[1] if "." in source else "url"
                            cat_map = {
                                "image": "images", "font": "fonts", "style": "styles",
                                "script": "scripts", "video": "videos", "audio": "audios",
                            }
                            target = cat_map.get(cat_key, "links")
                            all_groups[target].append({
                                "url": resolved, "filename": _filename(resolved),
                                "host": urllib.parse.urlparse(resolved).hostname or "",
                                "source": source, "category": target,
                            })
                except Exception:  # noqa: BLE001
                    continue
                time.sleep(0.06 + random.random() * 0.1)

        # 顺藤摸瓜：同域内链入队（跳过非 HTML 资源）
        if level < depth:
            for link in _collect(parser.links, base, limit=400):
                link_url = link["url"]
                parsed = urllib.parse.urlparse(link_url)
                if (parsed.hostname or "").lower() not in allowed_hosts or link_url in visited:
                    continue
                if NON_HTML_EXT.search(parsed.path or ""):
                    continue
                queue.append((link_url, level + 1))
            time.sleep(0.12 + random.random() * 0.18)

    counts = {key: len(value) for key, value in all_groups.items()}
    result = {
        "page": {
            "input": raw_url,
            "url": normalized,
            "title": pages[0]["title"] if pages else "",
            "status": pages[0]["status"] if pages else None,
        },
        "pages": pages,
        "pageCount": len(pages),
        "resources": all_groups,
        "counts": counts,
        "total": sum(counts.values()),
        "html": "",
    }
    if challenge_note:
        result["warning"] = (
            f"抓取过程中遇到{challenge_note}页面，该页面的正文与静态资源无法获取。"
            f"建议换用站内其他入口地址，或改用「抓包分析」查看浏览器实际请求。"
        )
    return result


# ---------------------------------------------------------------- DNS

def _doh_query(name: str, rtype: str, resolver: str) -> list[dict]:
    if resolver not in DOH_RESOLVERS:
        raise ToolError(f"未知解析器：{resolver}")
    endpoint, _ = DOH_RESOLVERS[resolver]
    url = f"{endpoint}?name={urllib.parse.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read(1_000_000))
    except Exception as exc:  # noqa: BLE001
        raise ToolError(_short_error(exc)) from exc
    records = []
    for answer in data.get("Answer", []) or []:
        records.append({
            "type": DNS_TYPE_NAMES.get(answer.get("type"), str(answer.get("type"))),
            "name": (answer.get("name") or name).rstrip("."),
            "data": str(answer.get("data", "")),
            "ttl": answer.get("TTL", 0),
        })
    authority = []
    for authority_record in data.get("Authority", []) or []:
        authority.append({
            "type": DNS_TYPE_NAMES.get(authority_record.get("type"), ""),
            "name": (authority_record.get("name") or name).rstrip("."),
            "data": str(authority_record.get("data", "")),
            "ttl": authority_record.get("TTL", 0),
        })
    return records + ([] if records else authority)


def _system_query(name: str, rtype: str) -> list[dict]:
    if rtype not in ("A", "AAAA"):
        return []
    family = socket.AF_INET if rtype == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(name, None, family)
    except socket.gaierror:
        return []
    seen = set()
    out = []
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        out.append({"type": rtype, "name": name, "data": addr, "ttl": 0})
    return out


def dns_lookup(raw: str, rtype: str = "ALL", resolver: str = "alidns") -> dict:
    target = (raw or "").strip()
    if not target:
        raise ToolError("请输入域名或 IP")
    target = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not target or " " in target:
        raise ToolError("域名格式不正确")

    reverse = _is_ip(target)
    if reverse:
        name = _reverse_name(target)
        wanted = ["PTR"]
    else:
        name = target.rstrip(".")
        wanted = ALL_TYPES if rtype.upper() == "ALL" else [rtype.upper()]

    resolver = resolver if resolver in DOH_RESOLVERS or resolver == "system" else "cloudflare"
    started = time.time()
    records: list[dict] = []
    errors: list[str] = []

    def run(kind: str):
        if resolver == "system":
            return _system_query(name, kind)
        return _doh_query(name, kind, resolver)

    if resolver == "system" and reverse:
        try:
            host, _, _ = socket.gethostbyaddr(target)
            return {
                "input": raw, "domain": target, "type": "PTR",
                "resolver": "system", "resolverLabel": "系统解析器",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "queryMs": round((time.time() - started) * 1000),
                "records": [{"type": "PTR", "name": target, "data": host, "ttl": 0}],
                "summary": {"total": 1, "types": ["PTR"], "hasA": False, "hasAAAA": False,
                            "hasMX": False, "hasTXT": False, "hasNS": False},
                "errors": [],
            }
        except socket.herror:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(run, kind): kind for kind in wanted}
        for future in concurrent.futures.as_completed(futures):
            kind = futures[future]
            try:
                records.extend(future.result())
            except ToolError as exc:
                errors.append(f"{kind}: {exc}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{kind}: {_short_error(exc)}")

    fallback = ""
    if not records and resolver in DOH_RESOLVERS and resolver != "alidns" and not reverse:
        try:
            for kind in wanted:
                records.extend(_doh_query(name, kind, "alidns"))
            if records:
                fallback = f"{DOH_RESOLVERS[resolver][1]} 不可达，已自动回退到阿里 DNS"
                errors.append(fallback)
                resolver = "alidns"
        except ToolError as exc:
            errors.append(f"回退阿里 DNS 失败：{exc}")
    if resolver == "system" and rtype.upper() == "ALL":
        errors.append("系统解析器仅支持 A / AAAA 记录，如需其它类型请切换 DoH 解析器")

    order = {kind: index for index, kind in enumerate(wanted)}
    records.sort(key=lambda rec: (order.get(rec["type"], 99), rec["data"]))
    types = sorted({rec["type"] for rec in records})
    return {
        "input": raw,
        "domain": target,
        "type": "PTR" if reverse else rtype.upper(),
        "resolver": resolver,
        "resolverLabel": DOH_RESOLVERS[resolver][1] if resolver in DOH_RESOLVERS else "系统解析器",
        "fallback": fallback,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "queryMs": round((time.time() - started) * 1000),
        "records": records,
        "summary": {
            "total": len(records),
            "types": types,
            "hasA": "A" in types,
            "hasAAAA": "AAAA" in types,
            "hasMX": "MX" in types,
            "hasTXT": "TXT" in types,
            "hasNS": "NS" in types,
        },
        "errors": errors,
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _reverse_name(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    return ip.reverse_pointer


# ---------------------------------------------------------------- 资源打包

def package_resources(items: list[dict], filename: str = "resources") -> tuple[bytes, str]:
    items = items[:60]
    if not items:
        raise ToolError("没有可打包的资源")
    buffer = io.BytesIO()
    manifest = []
    total = 0
    used_names: set[str] = set()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, item in enumerate(items):
            url = item.get("url", "")
            category = item.get("category", "other")
            try:
                _assert_public(url)
                fetched = _fetch_binary(url)
                if fetched is None:
                    continue
                data, content_type = fetched
                if total + len(data) > 80 * 1024 * 1024:
                    manifest.append({"url": url, "skipped": "超过总大小限制"})
                    break
                total += len(data)
                name = _safe_name(item.get("filename") or _filename(url), index)
                base, dot, ext = name.rpartition(".")
                if not dot:
                    ext = _ext_from_type(content_type)
                    base = name
                candidate = f"{category}/{name}"
                counter = 1
                while candidate in used_names:
                    candidate = f"{category}/{base}_{counter}.{ext}" if ext else f"{category}/{base}_{counter}"
                    counter += 1
                used_names.add(candidate)
                archive.writestr(candidate, data)
                manifest.append({
                    "url": url, "file": candidate, "size": len(data),
                    "contentType": content_type,
                })
            except Exception as exc:  # noqa: BLE001
                manifest.append({"url": url, "skipped": _short_error(exc)})
        archive.writestr("manifest.json", json.dumps({
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "count": len([m for m in manifest if m.get("file")]),
            "totalBytes": total,
            "items": manifest,
        }, ensure_ascii=False, indent=2))
    safe = re.sub(r"[^\w\-\u4e00-\u9fa5]+", "_", filename or "resources").strip("_") or "resources"
    return buffer.getvalue(), f"{safe}.zip"


def _fetch_binary(url: str, max_bytes: int = 20 * 1024 * 1024) -> tuple[bytes, str] | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as resp:
        content_type = resp.headers.get("Content-Type", "")
        data = resp.read(max_bytes)
    return data, content_type


def _safe_name(name: str, index: int) -> str:
    name = urllib.parse.unquote(name or f"file_{index}")
    name = re.sub(r"[\\/:*?\"<>|]+", "_", name).strip(". ") or f"file_{index}"
    return name[:120]


def _ext_from_type(content_type: str) -> str:
    content_type = content_type.split(";")[0].strip().lower()
    mapping = {
        "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp",
        "image/svg+xml": "svg", "video/mp4": "mp4", "video/webm": "webm",
        "audio/mpeg": "mp3", "text/css": "css", "text/javascript": "js",
        "application/javascript": "js", "font/woff2": "woff2", "text/html": "html",
    }
    return mapping.get(content_type, "bin")
