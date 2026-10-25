"""显示过滤器：Wireshark 风格的表达式解析与求值。

支持示例：
    tcp
    ip.addr == 10.0.0.42
    tcp.port == 443 && !(tls.sni contains "example")
    http.request.method == "GET" || dns
    frame.len > 500 and ip.src == 192.168.1.10
"""

from __future__ import annotations

import re
from typing import Any, Callable

PROTO_NAMES = {
    "eth", "arp", "ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "dns",
    "http", "http2", "tls", "dhcp", "ssh", "ftp", "smtp", "ntp", "igmp", "vlan",
    "mdns", "llmnr", "mqtt", "redis", "memcached", "telnet", "mysql", "postgres",
    "ldap", "smb", "modbus", "stun", "snmp", "syslog", "tftp", "sip", "quic",
    "wireguard", "rtp",
}

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<op>==|!=|>=|<=|=~|>|<)"
    r"|(?P<paren>[()])"
    r"|(?P<logic>&&|\|\||!)"
    r"|(?P<kw>and|or|not|contains)\b"
    r'|(?P<str>"(?:[^"\\]|\\.)*")'
    r"|(?P<word>[A-Za-z0-9_.:/'*+-]+)"
    r")\s*"
)


class FilterError(Exception):
    pass


# ---------------------------------------------------------------- 词法

def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match or match.end() == pos:
            snippet = text[pos : pos + 12]
            raise FilterError(f"无法解析的位置：{snippet!r}")
        pos = match.end()
        if match.group("op"):
            tokens.append(("op", match.group("op")))
        elif match.group("paren"):
            tokens.append(("paren", match.group("paren")))
        elif match.group("logic"):
            tokens.append(("logic", match.group("logic")))
        elif match.group("kw"):
            tokens.append(("kw", match.group("kw")))
        elif match.group("str"):
            raw = match.group("str")[1:-1]
            tokens.append(("value", bytes(raw, "utf-8").decode("unicode_escape")))
        elif match.group("word"):
            tokens.append(("word", match.group("word")))
    if not tokens:
        raise FilterError("过滤器为空")
    return tokens


# ---------------------------------------------------------------- 语法

class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise FilterError("表达式意外结束")
        self.pos += 1
        return tok

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise FilterError(f"多余的内容：{self.peek()[1]!r}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while True:
            tok = self.peek()
            if tok and ((tok[0] == "logic" and tok[1] in ("||",)) or (tok[0] == "kw" and tok[1] == "or")):
                self.next()
                node = ("or", node, self.parse_and())
            else:
                return node

    def parse_and(self):
        node = self.parse_unary()
        while True:
            tok = self.peek()
            if tok and ((tok[0] == "logic" and tok[1] == "&&") or (tok[0] == "kw" and tok[1] == "and")):
                self.next()
                node = ("and", node, self.parse_unary())
            else:
                return node

    def parse_unary(self):
        tok = self.peek()
        if tok and ((tok[0] == "logic" and tok[1] == "!") or (tok[0] == "kw" and tok[1] == "not")):
            self.next()
            return ("not", self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        tok = self.next()
        if tok[0] == "paren" and tok[1] == "(":
            node = self.parse_or()
            close = self.next()
            if close != ("paren", ")"):
                raise FilterError("缺少右括号")
            return node
        if tok[0] not in ("word", "value"):
            raise FilterError(f"此处不能是 {tok[1]!r}")

        name = tok[1]
        nxt = self.peek()
        if nxt and nxt[0] == "op":
            op = self.next()[1]
            value_tok = self.next()
            if value_tok[0] not in ("value", "word"):
                raise FilterError(f"运算符 {op} 后缺少值")
            value = _coerce(value_tok[1])
            return ("cmp", name, op, value)
        if nxt and nxt[0] == "kw" and nxt[1] == "contains":
            self.next()
            value_tok = self.next()
            if value_tok[0] not in ("value", "word"):
                raise FilterError("contains 后缺少值")
            return ("cmp", name, "contains", str(value_tok[1]))
        return ("bare", name)


def _coerce(text: str) -> Any:
    try:
        return int(text, 10)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def compile_filter(text: str) -> Callable[[dict], bool] | None:
    """编译过滤器，返回可调用对象；空字符串返回 None（表示全部通过）。"""
    text = (text or "").strip()
    if not text:
        return None
    ast = _Parser(_tokenize(text)).parse()
    if not _validate(ast):
        raise FilterError("表达式中含有无法识别的字段")
    return lambda pkt: _eval(ast, pkt)


def _validate(node) -> bool:
    kind = node[0]
    if kind in ("and", "or"):
        return _validate(node[1]) and _validate(node[2])
    if kind == "not":
        return _validate(node[1])
    if kind == "cmp":
        return node[1] in FIELD_GETTERS or node[1] in PROTO_NAMES or node[1] in FIELD_ALIASES
    if kind == "bare":
        name = node[1]
        return name in PROTO_NAMES or name in FIELD_GETTERS or name in FIELD_ALIASES
    return False


# ---------------------------------------------------------------- 字段取值

def _field(fields: dict, key: str):
    return fields.get(key)


FIELD_ALIASES = {
    "ip.addr": ("ip.src", "ip.dst"),
    "ipv6.addr": ("ipv6.src", "ipv6.dst"),
    "tcp.port": ("tcp.srcport", "tcp.dstport"),
    "udp.port": ("udp.srcport", "udp.dstport"),
    "eth.addr": ("eth.src", "eth.dst"),
}

FIELD_GETTERS: dict[str, Callable[[dict], Any]] = {
    "frame.number": lambda p: p.get("num"),
    "frame.len": lambda p: p.get("len"),
    "frame.time": lambda p: p.get("ts"),
    "eth.src": lambda p: p.get("fields", {}).get("eth.src"),
    "eth.dst": lambda p: p.get("fields", {}).get("eth.dst"),
    "eth.type": lambda p: p.get("fields", {}).get("eth.type"),
    "vlan.id": lambda p: p.get("fields", {}).get("vlan.id"),
    "ip.src": lambda p: p.get("fields", {}).get("ip.src"),
    "ip.dst": lambda p: p.get("fields", {}).get("ip.dst"),
    "ip.proto": lambda p: p.get("fields", {}).get("ip.proto"),
    "ip.ttl": lambda p: p.get("fields", {}).get("ip.ttl"),
    "ip.len": lambda p: p.get("fields", {}).get("ip.len"),
    "ip.id": lambda p: p.get("fields", {}).get("ip.id"),
    "ipv6.src": lambda p: p.get("fields", {}).get("ipv6.src"),
    "ipv6.dst": lambda p: p.get("fields", {}).get("ipv6.dst"),
    "arp.op": lambda p: p.get("fields", {}).get("arp.op"),
    "arp.src.proto_ipv4": lambda p: p.get("fields", {}).get("arp.src.proto_ipv4"),
    "arp.dst.proto_ipv4": lambda p: p.get("fields", {}).get("arp.dst.proto_ipv4"),
    "tcp.srcport": lambda p: p.get("sport"),
    "tcp.dstport": lambda p: p.get("dport"),
    "tcp.seq": lambda p: p.get("fields", {}).get("tcp.seq"),
    "tcp.ack": lambda p: p.get("fields", {}).get("tcp.ack"),
    "tcp.window": lambda p: p.get("fields", {}).get("tcp.window"),
    "tcp.len": lambda p: p.get("fields", {}).get("tcp.len"),
    "tcp.flags.syn": lambda p: 1 if p.get("fields", {}).get("tcp.flags.syn") else 0,
    "tcp.flags.ack": lambda p: 1 if p.get("fields", {}).get("tcp.flags.ack") else 0,
    "tcp.flags.fin": lambda p: 1 if p.get("fields", {}).get("tcp.flags.fin") else 0,
    "tcp.flags.rst": lambda p: 1 if p.get("fields", {}).get("tcp.flags.rst") else 0,
    "tcp.flags.psh": lambda p: 1 if p.get("fields", {}).get("tcp.flags.psh") else 0,
    "tcp.stream": lambda p: p.get("fields", {}).get("tcp.stream"),
    "udp.srcport": lambda p: p.get("sport"),
    "udp.dstport": lambda p: p.get("dport"),
    "udp.length": lambda p: p.get("fields", {}).get("udp.length"),
    "icmp.type": lambda p: p.get("fields", {}).get("icmp.type"),
    "icmp.code": lambda p: p.get("fields", {}).get("icmp.code"),
    "dns.id": lambda p: p.get("fields", {}).get("dns.id"),
    "dns.qry.name": lambda p: p.get("fields", {}).get("dns.qry.name"),
    "dns.qry.type": lambda p: p.get("fields", {}).get("dns.qry.type"),
    "dns.flags.response": lambda p: p.get("fields", {}).get("dns.flags.response"),
    "dns.a": lambda p: p.get("fields", {}).get("dns.a"),
    "http.request.method": lambda p: p.get("fields", {}).get("http.request.method"),
    "http.request.uri": lambda p: p.get("fields", {}).get("http.request.uri"),
    "http.host": lambda p: p.get("fields", {}).get("http.host"),
    "http.response.code": lambda p: p.get("fields", {}).get("http.response.code"),
    "http.content_type": lambda p: p.get("fields", {}).get("http.content_type"),
    "http.user_agent": lambda p: p.get("fields", {}).get("http.user_agent"),
    "tls.sni": lambda p: p.get("fields", {}).get("tls.sni"),
    "tls.record.type": lambda p: p.get("fields", {}).get("tls.record.type"),
    "tls.handshake.type": lambda p: p.get("fields", {}).get("tls.handshake.type"),
    "tls.version": lambda p: p.get("fields", {}).get("tls.version"),
}

# 新增协议的字段，统一回填到 FIELD_GETTERS，写法保持简单
for _name in (
    "http2.frame.count", "http2.stream.id",
    "mqtt.type", "mqtt.type.name", "mqtt.topic", "mqtt.clientid", "mqtt.keepalive", "mqtt.qos",
    "redis.command", "redis.key",
    "memcached.command", "memcached.key",
    "ftp.command", "ftp.username", "ftp.filename", "ftp.reply_code",
    "telnet.negotiation.count",
    "mysql.command", "mysql.query", "mysql.server_version", "mysql.error_code",
    "pg.tag", "pg.query",
    "ldap.operation", "ldap.base_object", "ldap.message_id",
    "smb.version", "smb.command",
    "modbus.function_code", "modbus.unit_id", "modbus.transaction_id",
    "ntp.version", "ntp.mode", "ntp.stratum",
    "dhcp.type", "dhcp.type.name", "dhcp.hostname", "dhcp.ip.your",
    "tftp.filename", "tftp.opcode",
    "stun.type", "stun.length",
    "snmp.version", "snmp.pdu", "snmp.request_id",
    "syslog.severity", "syslog.facility",
    "sip.method", "sip.response.code", "sip.call_id",
    "wireguard.type", "wireguard.type.name",
    "rtp.payload_type", "rtp.ssrc",
    "quic.version",
):
    FIELD_GETTERS.setdefault(_name, lambda p, _key=_name: p.get("fields", {}).get(_key))



def _get(pkt: dict, name: str):
    if name in FIELD_ALIASES:
        values = [pkt.get("fields", {}).get(k) for k in FIELD_ALIASES[name]]
        values = [v for v in values if v is not None]
        return values or None
    getter = FIELD_GETTERS.get(name)
    return getter(pkt) if getter else pkt.get("fields", {}).get(name)


def _truthy(value) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, str, bytes, dict)):
        return len(value) > 0
    return bool(value)


def _compare(field_value, op: str, target) -> bool:
    if field_value is None:
        return False
    if isinstance(field_value, (list, tuple, set)):
        if op in ("==", "contains", "=~"):
            return any(_compare(v, op, target) for v in field_value)
        if op == "!=":
            return all(_compare(v, "!=", target) for v in field_value)
        field_value = max(field_value) if field_value else None
        if field_value is None:
            return False

    if op == "contains":
        return str(target).lower() in str(field_value).lower()
    if op == "=~":
        try:
            return re.search(str(target), str(field_value), re.IGNORECASE) is not None
        except re.error:
            raise FilterError(f"无效的正则表达式：{target}")

    if isinstance(target, (int, float)) and isinstance(field_value, (int, float)):
        left, right = field_value, target
    elif isinstance(target, (int, float)) and isinstance(field_value, str):
        try:
            left, right = float(field_value), float(target)
        except ValueError:
            left, right = str(field_value), str(target)
    else:
        left, right = str(field_value), str(target)

    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == ">":
        return left > right
    if op == "<":
        return left < right
    if op == ">=":
        return left >= right
    if op == "<=":
        return left <= right
    raise FilterError(f"不支持的运算符：{op}")


def _eval(node, pkt: dict) -> bool:
    kind = node[0]
    if kind == "and":
        return _eval(node[1], pkt) and _eval(node[2], pkt)
    if kind == "or":
        return _eval(node[1], pkt) or _eval(node[2], pkt)
    if kind == "not":
        return not _eval(node[1], pkt)
    if kind == "cmp":
        return _compare(_get(pkt, node[1]), node[2], node[3])
    if kind == "bare":
        name = node[1]
        if name in PROTO_NAMES:
            return name in pkt.get("layers", ())
        return _truthy(_get(pkt, name))
    return False


def check_filter(text: str) -> None:
    """仅校验语法，不保留编译结果。"""
    compile_filter(text)
