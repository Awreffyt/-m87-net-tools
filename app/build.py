"""演示流量生成：构造真实合法的以太网帧，导出的 pcap 可直接用 Wireshark 打开。"""

from __future__ import annotations

import random
import socket
import struct

CLIENT_MAC = bytes.fromhex("3c22fb1a2b3c")
GATEWAY_MAC = bytes.fromhex("001122334455")
REMOTE_MAC = bytes.fromhex("525400a1b2c3")
CLIENT_IP = "10.0.0.42"
GATEWAY_IP = "10.0.0.1"
DNS_IP = "8.8.8.8"
NTP_IP = "162.159.200.1"

DOMAINS = [
    "www.example.com", "api.github.com", "cdn.jsdelivr.net", "mail.google.com",
    "docs.python.org", "registry.npmjs.org", "news.ycombinator.com", "trae.ai",
]
REMOTE_HOSTS = {
    "www.example.com": "93.184.216.34",
    "api.github.com": "140.82.112.5",
    "cdn.jsdelivr.net": "104.16.85.20",
    "mail.google.com": "142.250.72.37",
    "docs.python.org": "151.101.64.223",
    "registry.npmjs.org": "104.16.24.34",
    "news.ycombinator.com": "209.216.230.240",
    "trae.ai": "104.18.32.7",
}

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# ---------------------------------------------------------------- 基础构件

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0, ttl: int = 64, df: bool = True) -> bytes:
    flags = 0x4000 if df else 0
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, flags, ttl, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    csum = _checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"",
        src_ip: str = CLIENT_IP, dst_ip: str = GATEWAY_IP, window: int = 64240,
        options: bytes = b"") -> bytes:
    doff = 5 + len(options) // 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                         doff << 4, flags, window, 0, 0) + options
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, 6, len(header) + len(payload)))
    csum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return header + payload


def udp(sport: int, dport: int, payload: bytes, src_ip: str = CLIENT_IP, dst_ip: str = DNS_IP) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, 17, length))
    csum = _checksum(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


def dns_query(tid: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return header + question + struct.pack("!HH", qtype, 1)


def dns_response(tid: int, name: str, address: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    rdata = socket.inet_aton(address) if qtype == 1 else socket.inet_pton(socket.AF_INET6, address)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata
    return header + question + struct.pack("!HH", qtype, 1) + answer


def tls_record(content_type: int, body: bytes, version: int = 0x0303) -> bytes:
    return bytes([content_type]) + struct.pack("!HH", version, len(body)) + body


def tls_client_hello(sni: str, rng: random.Random) -> bytes:
    name = sni.encode()
    sni_entry = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    sni_ext = struct.pack("!HH", 0, len(sni_entry)) + sni_entry
    alpn = b"\x02h2\x08http/1.1"
    alpn_ext = struct.pack("!HH", 16, len(alpn) + 2) + struct.pack("!H", len(alpn)) + alpn
    supported = struct.pack("!HH", 43, 3) + b"\x02\x03\x04"
    exts = sni_ext + alpn_ext + supported
    ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\x00\x9c"
    session_id = bytes(rng.getrandbits(8) for _ in range(32))
    body = (b"\x03\x03" + bytes(rng.getrandbits(8) for _ in range(32))
            + bytes([len(session_id)]) + session_id
            + struct.pack("!H", len(ciphers)) + ciphers
            + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return tls_record(22, handshake, 0x0301)


def tls_server_hello(rng: random.Random) -> bytes:
    body = (b"\x03\x03" + bytes(rng.getrandbits(8) for _ in range(32))
            + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack("!H", 0))
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return tls_record(22, handshake)


def http_request(host: str, path: str = "/", rng: random.Random | None = None) -> bytes:
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
        f"Accept: text/html,application/json;q=0.9,*/*;q=0.8\r\n"
        f"Accept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n"
    ).encode()


def http_response(rng: random.Random) -> bytes:
    body = (
        "<!doctype html><html><head><title>Example Domain</title>"
        "<meta charset=\"utf-8\"/></head><body><div><h1>Example Domain</h1>"
        "<p>This domain is for use in illustrative examples in documents.</p>"
        "</div></body></html>"
    )
    payload = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n"
        f"Content-Length: {len(body)}\r\nServer: nginx/1.24.0\r\n"
        "Cache-Control: max-age=604800\r\nConnection: keep-alive\r\n\r\n" + body
    )
    return payload.encode()


# ---------------------------------------------------------------- 扩展协议构件

def ber(tag: int, payload: bytes) -> bytes:
    length = len(payload)
    if length < 0x80:
        return bytes([tag, length]) + payload
    if length < 0x100:
        return bytes([tag, 0x81, length]) + payload
    return bytes([tag, 0x82]) + length.to_bytes(2, "big") + payload


def mqtt_remaining(length: int) -> bytes:
    out = []
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            return bytes(out)


def mqtt_connect(client_id: str, keepalive: int = 60) -> bytes:
    body = (b"\x00\x04MQTT\x04\x02" + struct.pack("!H", keepalive)
            + struct.pack("!H", len(client_id)) + client_id.encode())
    return bytes([0x10]) + mqtt_remaining(len(body)) + body


def mqtt_publish(topic: str, message: bytes) -> bytes:
    body = struct.pack("!H", len(topic)) + topic.encode() + message
    return bytes([0x30]) + mqtt_remaining(len(body)) + body


def mysql_handshake(server: str = "8.0.36") -> bytes:
    body = (b"\x0a" + server.encode() + b"\x00" + struct.pack("<I", 42)
            + b"\x00" * 20 + b"\x00" * 12)
    return len(body).to_bytes(3, "little") + b"\x00" + body


def mysql_query(sql: str, seq: int = 1) -> bytes:
    body = b"\x03" + sql.encode()
    return len(body).to_bytes(3, "little") + bytes([seq]) + body


def pg_query(sql: str) -> bytes:
    body = sql.encode() + b"\x00"
    return b"Q" + struct.pack("!I", 4 + len(body)) + body


def ldap_search(base: str, msgid: int = 1) -> bytes:
    search = ber(0x63, ber(0x04, base.encode()) + ber(0x0A, b"\x00")
                 + ber(0x02, b"\x00") + ber(0x02, b"\x00") + ber(0x01, b"\x00")
                 + ber(0x87, b""))
    return ber(0x30, ber(0x02, bytes([msgid])) + search)


def smb2_negotiate(msg_id: int = 1) -> bytes:
    smb = b"\xfeSMB" + struct.pack("<HHIHHIIQ", 64, 1, 0, 0, 1, 0, 0, msg_id)
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def dhcp_message(msg_type: int, xid: int, hostname: str, offered: str = "0.0.0.0",
                 op: int = 1, server_id: str | None = None) -> bytes:
    yiaddr = socket.inet_aton(offered) if offered != "0.0.0.0" else b"\x00" * 4
    siaddr = socket.inet_aton(server_id) if server_id else b"\x00" * 4
    header = (struct.pack("!BBBB", op, 1, 6, 0) + struct.pack("!I", xid)
              + struct.pack("!HH", 0, 0)
              + b"\x00" * 4 + yiaddr + siaddr + b"\x00" * 4
              + CLIENT_MAC + b"\x00" * 10
              + b"\x00" * 64 + b"\x00" * 128)
    options = b"\x35\x01" + bytes([msg_type])
    if hostname:
        options += b"\x0c" + bytes([len(hostname)]) + hostname.encode()
    if server_id:
        options += b"\x36\x04" + socket.inet_aton(server_id)
    options += b"\x33\x04" + struct.pack("!I", 3600) + b"\xff"
    return header + b"\x63\x82\x53\x63" + options


def stun_binding(rng: random.Random) -> bytes:
    return struct.pack("!HH", 1, 0) + b"\x21\x12\xa4\x42" + bytes(rng.getrandbits(8) for _ in range(12))


def snmp_get(community: str = "public") -> bytes:
    varbind = ber(0x30, ber(0x06, b"\x2b\x06\x01\x02\x01\x01\x03\x00") + ber(0x05, b""))
    pdu = ber(0xA0, ber(0x02, b"\x01") + ber(0x02, b"\x00") + ber(0x02, b"\x00")
              + ber(0x30, varbind))
    return ber(0x30, ber(0x02, b"\x01") + ber(0x04, community.encode()) + pdu)


def quic_initial(rng: random.Random) -> bytes:
    dcid = bytes(rng.getrandbits(8) for _ in range(8))
    return b"\xc0" + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid + b"\x00" + b"\x00" * 24


def rtp_packet(rng: random.Random) -> bytes:
    return (b"\x80\x60" + struct.pack("!HII", rng.randint(0, 0xFFFF),
            rng.randint(0, 0xFFFFFFFF), rng.randint(0, 0xFFFFFFFF)) + b"\x00\x01\x02\x03")


def wireguard_init(rng: random.Random) -> bytes:
    return b"\x01\x00\x00\x00" + bytes(rng.getrandbits(8) for _ in range(144))


# ---------------------------------------------------------------- 场景组合

def build_demo_batch(rng: random.Random, ident_start: int = 1) -> list[bytes]:
    """生成一批贴合真实网络的演示帧，覆盖全部已实现协议。"""
    frames: list[bytes] = []
    domain = rng.choice(DOMAINS)
    server_ip = REMOTE_HOSTS[domain]
    ident = ident_start
    client_port = rng.randint(49152, 65000)

    def next_ident() -> int:
        nonlocal ident
        ident += 1
        return ident

    def emit_ip(src_ip: str, dst_ip: str, proto: int, payload: bytes,
                dst_mac: bytes = GATEWAY_MAC, src_mac: bytes = CLIENT_MAC) -> None:
        frames.append(eth(dst_mac, src_mac, 0x0800, ipv4(src_ip, dst_ip, proto, payload, next_ident())))

    # 1. ARP 请求 / 应答
    arp_req = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + CLIENT_MAC + socket.inet_aton(CLIENT_IP) \
              + b"\x00" * 6 + socket.inet_aton(GATEWAY_IP)
    frames.append(eth(b"\xff" * 6, CLIENT_MAC, 0x0806, arp_req))
    arp_rep = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + GATEWAY_MAC + socket.inet_aton(GATEWAY_IP) \
              + CLIENT_MAC + socket.inet_aton(CLIENT_IP)
    frames.append(eth(CLIENT_MAC, GATEWAY_MAC, 0x0806, arp_rep))

    # 2. DNS 查询 / 响应
    tid = rng.randint(1, 0xFFFF)
    qname = domain
    emit_ip(CLIENT_IP, DNS_IP, 17, udp(client_port, 53, dns_query(tid, qname), CLIENT_IP, DNS_IP))
    emit_ip(DNS_IP, CLIENT_IP, 17, udp(53, client_port, dns_response(tid, qname, server_ip), DNS_IP, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)

    # 3. HTTPS (TLS 1.3)
    cisn = rng.randint(0, 0xFFFFFFF)
    sisn = rng.randint(0, 0xFFFFFFF)
    sport = rng.randint(49152, 65000)
    syn = tcp(sport, 443, cisn, 0, SYN, b"", CLIENT_IP, server_ip,
              options=struct.pack("!BBH", 2, 4, 1460) + struct.pack("!BBH", 4, 2, 0))
    emit_ip(CLIENT_IP, server_ip, 6, syn)
    synack = tcp(443, sport, sisn, cisn + 1, SYN | ACK, b"", server_ip, CLIENT_IP,
                 options=struct.pack("!BBH", 2, 4, 1380))
    emit_ip(server_ip, CLIENT_IP, 6, synack, dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, server_ip, 6, tcp(sport, 443, cisn + 1, sisn + 1, ACK, b"", CLIENT_IP, server_ip))

    hello = tls_client_hello(domain, rng)
    emit_ip(CLIENT_IP, server_ip, 6, tcp(sport, 443, cisn + 1, sisn + 1, PSH | ACK, hello, CLIENT_IP, server_ip))
    emit_ip(server_ip, CLIENT_IP, 6,
            tcp(443, sport, sisn + 1, cisn + 1 + len(hello), PSH | ACK, tls_server_hello(rng), server_ip, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    app_data = bytes(rng.getrandbits(8) for _ in range(rng.randint(120, 320)))
    emit_ip(server_ip, CLIENT_IP, 6,
            tcp(443, sport, sisn + 1 + 76, cisn + 1 + len(hello), PSH | ACK,
                tls_record(23, app_data), server_ip, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)

    # 4. HTTP 明文会话
    http_port = rng.randint(49152, 65000)
    cisn2 = rng.randint(0, 0xFFFFFFF)
    sisn2 = rng.randint(0, 0xFFFFFFF)
    host_ip = REMOTE_HOSTS[rng.choice(["www.example.com", "docs.python.org", "trae.ai"])]
    emit_ip(CLIENT_IP, host_ip, 6, tcp(http_port, 80, cisn2, 0, SYN, b"", CLIENT_IP, host_ip))
    emit_ip(host_ip, CLIENT_IP, 6, tcp(80, http_port, sisn2, cisn2 + 1, SYN | ACK, b"", host_ip, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, host_ip, 6, tcp(http_port, 80, cisn2 + 1, sisn2 + 1, ACK, b"", CLIENT_IP, host_ip))
    req = http_request(domain, "/" if rng.random() < 0.5 else "/index.html", rng)
    emit_ip(CLIENT_IP, host_ip, 6, tcp(http_port, 80, cisn2 + 1, sisn2 + 1, PSH | ACK, req, CLIENT_IP, host_ip),
            src_mac=CLIENT_MAC)
    resp = http_response(rng)
    emit_ip(host_ip, CLIENT_IP, 6,
            tcp(80, http_port, sisn2 + 1, cisn2 + 1 + len(req), PSH | ACK, resp, host_ip, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, host_ip, 6,
            tcp(http_port, 80, cisn2 + 1 + len(req), sisn2 + 1 + len(resp), ACK, b"", CLIENT_IP, host_ip))

    # 5. ICMP ping
    icmp_body = struct.pack("!BBHHH", 8, 0, 0, rng.randint(1, 0xFFFF), 1) + b"abcdefghijklmnopqrstuvwabcdefghi"
    icmp_csum = _checksum(icmp_body)
    icmp_body = icmp_body[:2] + struct.pack("!H", icmp_csum) + icmp_body[4:]
    ping_ip = "1.1.1.1"
    emit_ip(CLIENT_IP, ping_ip, 1, icmp_body)
    reply_body = struct.pack("!BBHHH", 0, 0, 0, struct.unpack("!H", icmp_body[4:6])[0], 1) + icmp_body[8:]
    reply_csum = _checksum(reply_body)
    reply_body = reply_body[:2] + struct.pack("!H", reply_csum) + reply_body[4:]
    emit_ip(ping_ip, CLIENT_IP, 1, reply_body, dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)

    # 6. NTP
    ntp_payload = b"\x1b" + b"\x00" * 47
    emit_ip(CLIENT_IP, NTP_IP, 17, udp(rng.randint(49152, 65000), 123, ntp_payload, CLIENT_IP, NTP_IP))

    # 7. 局域网基础协议：DHCP / mDNS / LLMNR
    xid = rng.randint(1, 0xFFFFFFFF)
    emit_ip("0.0.0.0", "255.255.255.255", 17,
            udp(68, 67, dhcp_message(1, xid, "trae-mac"), "0.0.0.0", "255.255.255.255"),
            dst_mac=b"\xff" * 6)
    emit_ip(GATEWAY_IP, "255.255.255.255", 17,
            udp(67, 68, dhcp_message(2, xid, "trae-mac", CLIENT_IP, op=2, server_id=GATEWAY_IP),
                GATEWAY_IP, "255.255.255.255"),
            dst_mac=b"\xff" * 6)
    emit_ip(CLIENT_IP, "224.0.0.251", 17,
            udp(5353, 5353, dns_query(rng.randint(1, 0xFFFF), "trae.local"), CLIENT_IP, "224.0.0.251"),
            dst_mac=bytes.fromhex("01005e0000fb"))
    emit_ip(CLIENT_IP, "224.0.0.252", 17,
            udp(5355, 5355, dns_query(rng.randint(1, 0xFFFF), "desktop-7f3a"), CLIENT_IP, "224.0.0.252"),
            dst_mac=bytes.fromhex("01005e0000fc"))

    # 8. 物联网与服务协议：MQTT / Redis / Memcached
    svc_port = rng.randint(49152, 65000)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(svc_port, 1883, 1, 1, PSH | ACK, mqtt_connect("sensor-gateway"), CLIENT_IP, GATEWAY_IP))
    emit_ip(GATEWAY_IP, CLIENT_IP, 6,
            tcp(1883, svc_port, 1, 1, PSH | ACK, b"\x20\x02\x00\x00", GATEWAY_IP, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(svc_port, 1883, 2, 1, PSH | ACK, mqtt_publish("sensors/temp", b"23.5"), CLIENT_IP, GATEWAY_IP))

    redis_port = rng.randint(49152, 65000)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(redis_port, 6379, 1, 1, PSH | ACK, b"*2\r\n$3\r\nGET\r\n$8\r\nsessions\r\n", CLIENT_IP, GATEWAY_IP))
    emit_ip(GATEWAY_IP, CLIENT_IP, 6,
            tcp(6379, redis_port, 1, 2, PSH | ACK, b"$2\r\nok\r\n", GATEWAY_IP, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)

    cache_port = rng.randint(49152, 65000)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(cache_port, 11211, 1, 1, PSH | ACK, b"get session:42\r\n", CLIENT_IP, GATEWAY_IP))

    # 9. 数据库与目录：MySQL / PostgreSQL / LDAP / SMB / Modbus
    db_port = rng.randint(49152, 65000)
    emit_ip(GATEWAY_IP, CLIENT_IP, 6,
            tcp(3306, db_port, 1, 1, PSH | ACK, mysql_handshake(), GATEWAY_IP, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(db_port, 3306, 2, 2, PSH | ACK, mysql_query("SELECT id, name FROM users LIMIT 10"),
                CLIENT_IP, GATEWAY_IP))

    pg_port = rng.randint(49152, 65000)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(pg_port, 5432, 1, 1, PSH | ACK, pg_query("SELECT now();"), CLIENT_IP, GATEWAY_IP))

    ldap_port = rng.randint(49152, 65000)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(ldap_port, 389, 1, 1, PSH | ACK, ldap_search("dc=example,dc=com"), CLIENT_IP, GATEWAY_IP))

    smb_port = rng.randint(49152, 65000)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(smb_port, 445, 1, 1, PSH | ACK, smb2_negotiate(), CLIENT_IP, GATEWAY_IP))

    plc_ip = "10.0.0.60"
    emit_ip(CLIENT_IP, plc_ip, 6,
            tcp(rng.randint(49152, 65000), 502, 1, 1, PSH | ACK,
                b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01", CLIENT_IP, plc_ip))

    # 10. 运维与实时通信：FTP / Telnet / STUN / SNMP / Syslog / TFTP / SIP
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(rng.randint(49152, 65000), 21, 1, 1, PSH | ACK, b"USER anonymous\r\n", CLIENT_IP, GATEWAY_IP))
    emit_ip(GATEWAY_IP, CLIENT_IP, 6,
            tcp(21, 51000, 1, 2, PSH | ACK, b"331 Please specify the password.\r\n", GATEWAY_IP, CLIENT_IP),
            dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(rng.randint(49152, 65000), 23, 1, 1, PSH | ACK,
                b"\xff\xfb\x01\xff\xfb\x03login: ", CLIENT_IP, GATEWAY_IP))
    emit_ip(CLIENT_IP, GATEWAY_IP, 17,
            udp(rng.randint(49152, 65000), 3478, stun_binding(rng), CLIENT_IP, GATEWAY_IP))
    emit_ip(CLIENT_IP, GATEWAY_IP, 17,
            udp(rng.randint(49152, 65000), 161, snmp_get(), CLIENT_IP, GATEWAY_IP))
    emit_ip(GATEWAY_IP, CLIENT_IP, 17,
            udp(514, 514, b"<134>Oct 25 10:12:03 gateway sshd[812]: Accepted password for admin",
                GATEWAY_IP, CLIENT_IP), dst_mac=CLIENT_MAC, src_mac=GATEWAY_MAC)
    emit_ip(CLIENT_IP, GATEWAY_IP, 17,
            udp(rng.randint(49152, 65000), 69, b"\x00\x01config.bin\x00octet\x00", CLIENT_IP, GATEWAY_IP))
    sip_message = (
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.42:5060\r\n"
        "From: <sip:alice@example.com>;tag=1a2b3c\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: 3c2f1e7a@10.0.0.42\r\n"
        "CSeq: 1 INVITE\r\n"
        "User-Agent: M87 Demo\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()
    emit_ip(CLIENT_IP, GATEWAY_IP, 17, udp(5060, 5060, sip_message, CLIENT_IP, GATEWAY_IP))

    # 11. 隧道与媒体：WireGuard / RTP / QUIC / HTTP2
    emit_ip(CLIENT_IP, GATEWAY_IP, 17,
            udp(rng.randint(49152, 65000), 51820, wireguard_init(rng), CLIENT_IP, GATEWAY_IP))
    emit_ip(CLIENT_IP, GATEWAY_IP, 17,
            udp(rng.randint(49152, 65000), 5004, rtp_packet(rng), CLIENT_IP, GATEWAY_IP))
    emit_ip(CLIENT_IP, GATEWAY_IP, 17,
            udp(rng.randint(49152, 65000), 443, quic_initial(rng), CLIENT_IP, GATEWAY_IP))

    h2_port = rng.randint(49152, 65000)
    h2_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    emit_ip(CLIENT_IP, GATEWAY_IP, 6,
            tcp(h2_port, 8443, 1, 1, PSH | ACK, h2_payload, CLIENT_IP, GATEWAY_IP))

    return frames
