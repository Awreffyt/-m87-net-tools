"""协议解码器：把链路层原始帧解析成 Wireshark 风格的结构化数据。

输出结构（每个数据包）：
{
  num, ts, len, caplen, src, dst, proto, color, info, layers(set),
  fields(dict), tree(list), sport, dport, data(bytes),
  tcp_key/tcp_dir/tcp_payload (仅 TCP)
}
其中 tree 节点的 range 表示字段在帧内的字节区间，用于前端高亮十六进制。
"""

from __future__ import annotations

import re
import socket
import struct
from datetime import datetime

ETHERTYPES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
    0x8100: "802.1Q VLAN", 0x88A8: "802.1ad", 0x8847: "MPLS",
}
IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
TCP_FLAG_BITS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]
DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 65: "HTTPS",
}
ICMP_TYPES = {
    0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench",
    5: "Redirect", 8: "Echo (ping) request", 9: "Router advertisement",
    10: "Router solicitation", 11: "Time-to-live exceeded", 12: "Parameter problem",
    13: "Timestamp request", 14: "Timestamp reply",
}
ICMPV6_TYPES = {
    1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded",
    128: "Echo (ping) request", 129: "Echo (ping) reply",
    133: "Router solicitation", 134: "Router advertisement",
    135: "Neighbor solicitation", 136: "Neighbor advertisement",
}

HTTP_PORTS = {80, 8080, 8000, 8888, 3128, 591, 8008}
TLS_PORTS = {443, 8443, 993, 995, 465, 636, 853}
SSH_PORTS = {22}
FTP_PORTS = {20, 21}
SMTP_PORTS = {25, 587}
NTP_PORTS = {123}
DHCP_PORTS = {67, 68}
DNS_PORTS = {53, 5353, 5355}

MQTT_PORTS = {1883, 8883}
REDIS_PORTS = {6379}
MEMCACHED_PORTS = {11211}
TELNET_PORTS = {23}
MYSQL_PORTS = {3306}
POSTGRES_PORTS = {5432}
LDAP_PORTS = {389}
SMB_PORTS = {445}
MODBUS_PORTS = {502}
STUN_PORTS = {3478, 3479}
SNMP_PORTS = {161, 162}
SYSLOG_PORTS = {514}
TFTP_PORTS = {69}
SIP_PORTS = {5060}
QUIC_PORTS = {443, 8443}
WIREGUARD_PORTS = {51820}
RTP_PORTS = {5004, 5005}

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _node(title: str, items=None, children=None) -> dict:
    return {"title": title, "items": items or [], "children": children or []}


def _it(name, value, rng=None) -> dict:
    return {"name": name, "value": value, "range": rng}


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _ip6(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except OSError:
        return raw.hex()


def _flags_text(value: int) -> str:
    names = [name for bit, name in TCP_FLAG_BITS if value & bit]
    return ", ".join(names) if names else ""


def _time_text(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")
    except (OverflowError, OSError, ValueError):
        return f"{ts:.6f}"


def decode_packet(data: bytes, num: int = 0, ts: float = 0.0, linktype: int = 1) -> dict:
    pkt = {
        "num": num, "ts": ts, "len": len(data), "caplen": len(data),
        "src": "", "dst": "", "proto": "UNKNOWN", "color": "other", "info": "",
        "layers": set(), "fields": {}, "tree": [], "data": data,
    }
    fields = pkt["fields"]
    nodes: list[dict] = []
    fields["frame.number"] = num
    fields["frame.len"] = len(data)
    fields["frame.time"] = ts

    try:
        if linktype == 1:
            _eth(data, 0, pkt, fields, nodes)
        elif linktype in (101, 12, 14, 228, 229):
            _ipv4(data, 0, pkt, fields, nodes)
        elif linktype == 113:
            _sll(data, 0, pkt, fields, nodes)
        else:
            pkt["proto"] = f"LINKTYPE_{linktype}"
            pkt["info"] = f"{len(data)} bytes"
    except Exception as exc:  # 畸形包不应影响整条抓包
        pkt["info"] = f"[Malformed] {exc}"
        pkt["color"] = "error"
        pkt["proto"] = "MALFORMED"

    if not pkt["src"]:
        pkt["src"] = "-"
    if not pkt["dst"]:
        pkt["dst"] = "-"
    if not pkt["info"]:
        pkt["info"] = f"{len(data)} bytes"
    pkt["tree"] = [
        _node(
            f"Frame {num}: {len(data)} bytes on wire ({len(data) * 8} bits)",
            [
                _it("Frame Number", num),
                _it("Arrival Time", _time_text(ts)),
                _it("Capture Length", len(data)),
                _it("Frame Length", len(data)),
                _it("Encapsulation", f"LINKTYPE_{linktype}"),
            ],
            nodes,
        )
    ]
    return pkt


# ---------------------------------------------------------------- 链路层

def _eth(data: bytes, off: int, pkt: dict, fields: dict, nodes: list) -> None:
    if len(data) < off + 14:
        raise ValueError("Ethernet 帧头不完整")
    dst, src = data[off : off + 6], data[off + 6 : off + 12]
    etype = struct.unpack("!H", data[off + 12 : off + 14])[0]
    nodes.append(
        _node(
            f"Ethernet II, Src: {_mac(src)}, Dst: {_mac(dst)}",
            [
                _it("Destination", _mac(dst), [off, off + 6]),
                _it("Source", _mac(src), [off + 6, off + 12]),
                _it("Type", ETHERTYPES.get(etype, f"0x{etype:04x}"), [off + 12, off + 14]),
            ],
        )
    )
    fields.update({"eth.src": _mac(src), "eth.dst": _mac(dst), "eth.type": etype})
    pkt["layers"].add("eth")
    pkt["src"], pkt["dst"] = _mac(src), _mac(dst)
    pkt["color"] = "arp" if etype == 0x0806 else "ip"
    off += 14

    while etype in (0x8100, 0x88A8):
        if len(data) < off + 6:
            raise ValueError("VLAN 标签不完整")
        tci = struct.unpack("!H", data[off : off + 2])[0]
        inner = struct.unpack("!H", data[off + 2 : off + 4])[0]
        vid = tci & 0x0FFF
        nodes.append(
            _node(
                f"IEEE 802.1Q Virtual LAN, PRI: {(tci >> 13) & 7}, DEI: {(tci >> 12) & 1}, ID: {vid}",
                [_it("Priority", (tci >> 13) & 7, [off, off + 1]), _it("VLAN ID", vid, [off + 2, off + 4])],
            )
        )
        fields["vlan.id"] = vid
        pkt["layers"].add("vlan")
        etype = inner
        off += 4

    if etype == 0x0800:
        _ipv4(data, off, pkt, fields, nodes)
    elif etype == 0x86DD:
        _ipv6(data, off, pkt, fields, nodes)
    elif etype == 0x0806:
        _arp(data, off, pkt, fields, nodes)
    else:
        pkt["proto"] = ETHERTYPES.get(etype, f"0x{etype:04x}")
        pkt["info"] = f"EtherType 0x{etype:04x}，{len(data) - off} bytes"
        pkt["color"] = "other"


def _sll(data: bytes, off: int, pkt: dict, fields: dict, nodes: list) -> None:
    if len(data) < off + 16:
        raise ValueError("SLL 头不完整")
    pkttype, arphrd, addrlen = struct.unpack("!HHH", data[off : off + 6])
    addr = data[off + 6 : off + 14]
    etype = struct.unpack("!H", data[off + 14 : off + 16])[0]
    nodes.append(
        _node(
            "Linux cooked capture",
            [
                _it("Packet type", pkttype),
                _it("Link-layer address", _mac(addr[:addrlen]) if addrlen else "-"),
                _it("Type", ETHERTYPES.get(etype, f"0x{etype:04x}")),
            ],
        )
    )
    fields["eth.type"] = etype
    off += 16
    if etype == 0x0800:
        _ipv4(data, off, pkt, fields, nodes)
    elif etype == 0x86DD:
        _ipv6(data, off, pkt, fields, nodes)
    elif etype == 0x0806:
        _arp(data, off, pkt, fields, nodes)


# ---------------------------------------------------------------- ARP

def _arp(data: bytes, off: int, pkt: dict, fields: dict, nodes: list) -> None:
    if len(data) < off + 28:
        raise ValueError("ARP 包不完整")
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[off : off + 8])
    smac = _mac(data[off + 8 : off + 8 + hlen])
    sip = _ip4(data[off + 8 + hlen : off + 12 + hlen])
    tmac = _mac(data[off + 12 + hlen : off + 12 + hlen + hlen])
    tip = _ip4(data[off + 12 + 2 * hlen : off + 16 + 2 * hlen])
    nodes.append(
        _node(
            f"Address Resolution Protocol ({'reply' if op == 2 else 'request' if op == 1 else op})",
            [
                _it("Hardware type", htype),
                _it("Protocol type", f"0x{ptype:04x}"),
                _it("Opcode", {1: "request (1)", 2: "reply (2)"}.get(op, op), [off + 6, off + 8]),
                _it("Sender MAC", smac, [off + 8, off + 14]),
                _it("Sender IP", sip, [off + 14, off + 18]),
                _it("Target MAC", tmac, [off + 18, off + 24]),
                _it("Target IP", tip, [off + 24, off + 28]),
            ],
        )
    )
    pkt["layers"].add("arp")
    pkt["proto"], pkt["color"] = "ARP", "arp"
    pkt["src"], pkt["dst"] = sip, tip
    fields.update({"arp.op": op, "arp.src.proto_ipv4": sip, "arp.dst.proto_ipv4": tip,
                   "arp.src.hw_mac": smac, "arp.dst.hw_mac": tmac})
    if op == 1:
        pkt["info"] = f"Who has {tip}? Tell {sip}"
    elif op == 2:
        pkt["info"] = f"{sip} is at {smac}"
    else:
        pkt["info"] = f"ARP opcode {op}"


# ---------------------------------------------------------------- IPv4 / IPv6

def _ipv4(data: bytes, off: int, pkt: dict, fields: dict, nodes: list) -> None:
    if len(data) < off + 20:
        raise ValueError("IPv4 头不完整")
    vihl = data[off]
    version, ihl = vihl >> 4, (vihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        raise ValueError("IPv4 头非法")
    total_len, ident, flags_frag = struct.unpack("!HHH", data[off + 2 : off + 8])
    ttl, proto = data[off + 8], data[off + 9]
    csum = struct.unpack("!H", data[off + 10 : off + 12])[0]
    src, dst = _ip4(data[off + 12 : off + 16]), _ip4(data[off + 16 : off + 20])
    flag_bits = (flags_frag >> 13) & 0x7
    frag_off = flags_frag & 0x1FFF
    flag_names = [n for b, n in ((0x4, "Reserved"), (0x2, "Don't fragment"), (0x1, "More fragments")) if flag_bits & b]

    nodes.append(
        _node(
            f"Internet Protocol Version 4, Src: {src}, Dst: {dst}",
            [
                _it("Version", version, [off, off + 1]),
                _it("Header Length", ihl, [off, off + 1]),
                _it("Total Length", total_len, [off + 2, off + 4]),
                _it("Identification", f"0x{ident:04x}", [off + 4, off + 6]),
                _it("Flags", ", ".join(flag_names) or "None", [off + 6, off + 7]),
                _it("Fragment Offset", frag_off),
                _it("Time to Live", ttl, [off + 8, off + 9]),
                _it("Protocol", IP_PROTOS.get(proto, f"{proto}"), [off + 9, off + 10]),
                _it("Header Checksum", f"0x{csum:04x}", [off + 10, off + 12]),
                _it("Source Address", src, [off + 12, off + 16]),
                _it("Destination Address", dst, [off + 16, off + 20]),
            ],
        )
    )
    pkt["layers"].update(("ip",))
    pkt["src"], pkt["dst"] = src, dst
    fields.update({"ip.src": src, "ip.dst": dst, "ip.proto": proto, "ip.ttl": ttl,
                   "ip.len": total_len, "ip.id": ident, "ip.flags.df": bool(flag_bits & 0x2)})
    pkt["color"] = "ip"
    l4 = off + ihl

    if frag_off != 0:
        pkt["proto"] = "IPv4"
        pkt["info"] = f"Fragmented IP protocol (fragment offset {frag_off})"
        return

    if proto == 6:
        _tcp(data, l4, pkt, fields, nodes, src, dst, 4)
    elif proto == 17:
        _udp(data, l4, pkt, fields, nodes, src, dst)
    elif proto == 1:
        _icmp(data, l4, pkt, fields, nodes)
    elif proto == 2:
        pkt["proto"], pkt["color"] = "IGMP", "ip"
        pkt["info"] = "IGMP"
        pkt["layers"].add("igmp")
    else:
        pkt["proto"] = IP_PROTOS.get(proto, f"IPv4/{proto}")
        pkt["info"] = f"{IP_PROTOS.get(proto, 'IP payload')}，{max(total_len - ihl, 0)} bytes"


def _ipv6(data: bytes, off: int, pkt: dict, fields: dict, nodes: list) -> None:
    if len(data) < off + 40:
        raise ValueError("IPv6 头不完整")
    first = struct.unpack("!I", data[off : off + 4])[0]
    version = first >> 28
    payload_len = struct.unpack("!H", data[off + 4 : off + 6])[0]
    next_header, hop = data[off + 6], data[off + 7]
    src, dst = _ip6(data[off + 8 : off + 24]), _ip6(data[off + 24 : off + 40])
    nodes.append(
        _node(
            f"Internet Protocol Version 6, Src: {src}, Dst: {dst}",
            [
                _it("Version", version),
                _it("Payload Length", payload_len, [off + 4, off + 6]),
                _it("Next Header", IP_PROTOS.get(next_header, next_header), [off + 6, off + 7]),
                _it("Hop Limit", hop, [off + 7, off + 8]),
                _it("Source Address", src, [off + 8, off + 24]),
                _it("Destination Address", dst, [off + 24, off + 40]),
            ],
        )
    )
    pkt["layers"].add("ipv6")
    pkt["src"], pkt["dst"] = src, dst
    fields.update({"ipv6.src": src, "ipv6.dst": dst, "ipv6.nxt": next_header, "ipv6.hlim": hop,
                   "ipv6.plen": payload_len})
    pkt["color"] = "ipv6"

    cursor, nxt = off + 40, next_header
    guard = 0
    while nxt in (0, 43, 60) and guard < 6 and len(data) >= cursor + 8:
        ext_len = (data[cursor + 1] + 1) * 8
        nxt = data[cursor]
        cursor += ext_len
        guard += 1
    if nxt == 44 and len(data) >= cursor + 8:
        nxt = data[cursor]
        cursor += 8

    if nxt == 6:
        _tcp(data, cursor, pkt, fields, nodes, src, dst, 6)
    elif nxt == 17:
        _udp(data, cursor, pkt, fields, nodes, src, dst)
    elif nxt == 58:
        _icmp(data, cursor, pkt, fields, nodes, ipv6=True)
    else:
        pkt["proto"] = "IPv6"
        pkt["info"] = f"IPv6 next header {nxt}，{payload_len} bytes"


# ---------------------------------------------------------------- TCP / UDP

def _tcp(data: bytes, off: int, pkt: dict, fields: dict, nodes: list,
         src: str, dst: str, ipver: int) -> None:
    if len(data) < off + 20:
        raise ValueError("TCP 头不完整")
    sport, dport = struct.unpack("!HH", data[off : off + 4])
    seq, ack = struct.unpack("!II", data[off + 4 : off + 12])
    doff = (data[off + 12] >> 4) * 4
    flag_byte = data[off + 13]
    window, csum = struct.unpack("!HH", data[off + 14 : off + 18])
    if doff < 20 or len(data) < off + doff:
        raise ValueError("TCP 头长度非法")
    payload = data[off + doff :]
    flags = [(name, bool(flag_byte & bit)) for bit, name in TCP_FLAG_BITS]

    options_text = []
    opt_off = off + 20
    while opt_off < off + doff:
        kind = data[opt_off]
        if kind == 0:
            break
        if kind == 1:
            opt_off += 1
            continue
        if opt_off + 1 >= off + doff:
            break
        olen = data[opt_off + 1]
        if olen < 2 or opt_off + olen > off + doff:
            break
        if kind == 2:
            mss = struct.unpack("!H", data[opt_off + 2 : opt_off + 4])[0]
            options_text.append(f"MSS={mss}")
        elif kind == 3:
            options_text.append(f"WS={data[opt_off + 2]}")
        elif kind == 4:
            options_text.append("SACK_PERM")
        elif kind == 8:
            tsval, tsecr = struct.unpack("!II", data[opt_off + 2 : opt_off + 10])
            options_text.append(f"TSval={tsval} TSecr={tsecr}")
        opt_off += olen

    items = [
        _it("Source Port", sport, [off, off + 2]),
        _it("Destination Port", dport, [off + 2, off + 4]),
        _it("Sequence Number", seq, [off + 4, off + 8]),
        _it("Acknowledgment Number", ack, [off + 8, off + 12]),
        _it("Header Length", doff, [off + 12, off + 13]),
        _it("Flags", f"0x{flag_byte:02x} ({_flags_text(flag_byte)})", [off + 13, off + 14]),
        _it("Window", window, [off + 14, off + 16]),
        _it("Checksum", f"0x{csum:04x}", [off + 16, off + 18]),
        _it("Payload Length", len(payload)),
    ]
    if options_text:
        items.append(_it("Options", ", ".join(options_text)))
    nodes.append(_node(f"Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {seq}, Ack: {ack}, Len: {len(payload)}", items))

    pkt["layers"].add("tcp")
    pkt["proto"], pkt["color"] = "TCP", "tcp"
    pkt["sport"], pkt["dport"] = sport, dport
    for name, on in flags:
        key = name.lower()
        fields[f"tcp.flags.{key}"] = on
    fields.update({
        "tcp.srcport": sport, "tcp.dstport": dport, "tcp.seq": seq, "tcp.ack": ack,
        "tcp.window": window, "tcp.len": len(payload), "tcp.flags": flag_byte,
    })

    fl = _flags_text(flag_byte)
    base_info = f"{sport} 到 {dport} [{fl or '-'}] Seq={seq} Ack={ack} Win={window} Len={len(payload)}"
    if options_text:
        base_info += " " + " ".join(options_text)
    pkt["info"] = base_info

    endpoints = tuple(sorted([(src, sport), (dst, dport)]))
    pkt["tcp_key"] = endpoints
    pkt["tcp_dir"] = "a2b" if (src, sport) == endpoints[0] else "b2a"
    pkt["tcp_payload"] = payload[:262144]

    if not payload:
        return

    handled = False
    if payload.startswith(HTTP2_PREFACE):
        handled = _http2(payload, pkt, fields, nodes)
    if not handled and (sport in HTTP_PORTS or dport in HTTP_PORTS or payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC") or payload[:5] == b"HTTP/"):
        handled = _http(payload, pkt, fields, nodes)
    if not handled and (sport in TLS_PORTS or dport in TLS_PORTS or payload[:2] == b"\x16\x03"):
        handled = _tls(payload, pkt, fields, nodes)
    if not handled and (sport in SSH_PORTS or dport in SSH_PORTS):
        if payload.startswith(b"SSH-"):
            banner = payload.split(b"\r\n")[0][:78].decode("utf-8", "replace")
            pkt["proto"], pkt["color"] = "SSH", "tcp"
            pkt["layers"].add("ssh")
            pkt["info"] = f"Server/Client Protocol: {banner}"
            nodes.append(_node("SSH Protocol", [_it("Identification", banner)]))
        else:
            pkt["layers"].add("ssh")
        handled = True
    if not handled and (sport in SMTP_PORTS or dport in SMTP_PORTS) and payload[:4] in (b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA"):
        line = payload.split(b"\r\n")[0][:100].decode("utf-8", "replace")
        pkt["proto"], pkt["color"] = "SMTP", "tcp"
        pkt["layers"].add("smtp")
        pkt["info"] = line
        nodes.append(_node("Simple Mail Transfer Protocol", [_it("Command", line)]))
        handled = True
    if handled:
        return

    if sport in MQTT_PORTS or dport in MQTT_PORTS:
        if _mqtt(payload, pkt, fields, nodes):
            return
    if sport in REDIS_PORTS or dport in REDIS_PORTS:
        if _redis(payload, pkt, fields, nodes):
            return
    if sport in MEMCACHED_PORTS or dport in MEMCACHED_PORTS:
        if _memcached(payload, pkt, fields, nodes):
            return
    if sport in FTP_PORTS or dport in FTP_PORTS:
        if _ftp(payload, pkt, fields, nodes):
            return
    if sport in TELNET_PORTS or dport in TELNET_PORTS:
        if _telnet(payload, pkt, fields, nodes):
            return
    if sport in MYSQL_PORTS or dport in MYSQL_PORTS:
        if _mysql(payload, pkt, fields, nodes):
            return
    if sport in POSTGRES_PORTS or dport in POSTGRES_PORTS:
        if _postgres(payload, pkt, fields, nodes):
            return
    if sport in LDAP_PORTS or dport in LDAP_PORTS:
        if _ldap(payload, pkt, fields, nodes):
            return
    if sport in SMB_PORTS or dport in SMB_PORTS:
        if _smb(payload, pkt, fields, nodes):
            return
    if sport in MODBUS_PORTS or dport in MODBUS_PORTS:
        if _modbus(payload, pkt, fields, nodes):
            return
    if _http2(payload, pkt, fields, nodes, require_preface=False):
        return


def _udp(data: bytes, off: int, pkt: dict, fields: dict, nodes: list, src: str, dst: str) -> None:
    if len(data) < off + 8:
        raise ValueError("UDP 头不完整")
    sport, dport, length, csum = struct.unpack("!HHHH", data[off : off + 8])
    payload = data[off + 8 : off + 8 + max(length - 8, 0)] if length >= 8 else data[off + 8 :]
    nodes.append(
        _node(
            f"User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}",
            [
                _it("Source Port", sport, [off, off + 2]),
                _it("Destination Port", dport, [off + 2, off + 4]),
                _it("Length", length, [off + 4, off + 6]),
                _it("Checksum", f"0x{csum:04x}", [off + 6, off + 8]),
                _it("Payload Length", len(payload)),
            ],
        )
    )
    pkt["layers"].add("udp")
    pkt["proto"], pkt["color"] = "UDP", "udp"
    pkt["sport"], pkt["dport"] = sport, dport
    fields.update({"udp.srcport": sport, "udp.dstport": dport, "udp.length": length})
    pkt["info"] = f"{sport} 到 {dport} Len={len(payload)}"

    if sport in DNS_PORTS or dport in DNS_PORTS:
        if _dns(payload, pkt, fields, nodes):
            return
    if sport in NTP_PORTS or dport in NTP_PORTS:
        if _ntp(payload, pkt, fields, nodes):
            return
    if sport in DHCP_PORTS or dport in DHCP_PORTS:
        if _dhcp(payload, pkt, fields, nodes):
            return
    if sport in TFTP_PORTS or dport in TFTP_PORTS:
        if _tftp(payload, pkt, fields, nodes):
            return
    if sport in STUN_PORTS or dport in STUN_PORTS:
        if _stun(payload, pkt, fields, nodes):
            return
    if sport in SNMP_PORTS or dport in SNMP_PORTS:
        if _snmp(payload, pkt, fields, nodes):
            return
    if sport in SYSLOG_PORTS or dport in SYSLOG_PORTS:
        if _syslog(payload, pkt, fields, nodes):
            return
    if sport in SIP_PORTS or dport in SIP_PORTS:
        if _sip(payload, pkt, fields, nodes):
            return
    if sport in WIREGUARD_PORTS or dport in WIREGUARD_PORTS:
        if _wireguard(payload, pkt, fields, nodes):
            return
    if sport in RTP_PORTS or dport in RTP_PORTS:
        if _rtp(payload, pkt, fields, nodes):
            return
    if sport in QUIC_PORTS or dport in QUIC_PORTS:
        if _quic(payload, pkt, fields, nodes):
            return
    if payload:
        preview = payload[:160].decode("utf-8", "replace").replace("\n", " ").replace("\r", " ")
        nodes.append(_node("Data", [_it("Payload", preview[:120])]))


# ---------------------------------------------------------------- ICMP

def _icmp(data: bytes, off: int, pkt: dict, fields: dict, nodes: list, ipv6: bool = False) -> None:
    if len(data) < off + 4:
        raise ValueError("ICMP 头不完整")
    icmp_type, code, csum = struct.unpack("!BBH", data[off : off + 4])
    table = ICMPV6_TYPES if ipv6 else ICMP_TYPES
    label = table.get(icmp_type, f"Type {icmp_type}")
    items = [
        _it("Type", f"{icmp_type} ({label})", [off, off + 1]),
        _it("Code", code, [off + 1, off + 2]),
        _it("Checksum", f"0x{csum:04x}", [off + 2, off + 4]),
    ]
    pkt["layers"].add("icmpv6" if ipv6 else "icmp")
    pkt["proto"], pkt["color"] = ("ICMPv6" if ipv6 else "ICMP"), "icmp"
    fields.update({"icmp.type": icmp_type, "icmp.code": code})
    info = label
    if icmp_type in (0, 8, 128, 129) and len(data) >= off + 8:
        ident, seq = struct.unpack("!HH", data[off + 4 : off + 8])
        items.extend([_it("Identifier", f"0x{ident:04x}", [off + 4, off + 6]),
                      _it("Sequence Number", seq, [off + 6, off + 8])])
        fields.update({"icmp.ident": ident, "icmp.seq": seq})
        info = f"{label} id=0x{ident:04x}, seq={seq}"
    nodes.append(_node(f"Internet Control Message Protocol{' v6' if ipv6 else ''}", items))
    pkt["info"] = info


# ---------------------------------------------------------------- DNS

def _dns(msg: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(msg) < 12:
        return False
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    qr = (flags >> 15) & 1
    rcode = flags & 0x0F
    opcode = (flags >> 11) & 0x0F
    offset = 12
    questions = []
    q_nodes = []
    try:
        for _ in range(qd):
            name, offset = _dns_name(msg, offset)
            qtype, qclass = struct.unpack("!HH", msg[offset : offset + 4])
            offset += 4
            questions.append((name, qtype))
            q_nodes.append(_node("Queries", [
                _it("Name", name), _it("Type", DNS_TYPES.get(qtype, qtype)),
                _it("Class", "IN" if qclass == 1 else qclass),
            ]))
        answer_nodes = []
        answers = []
        for _ in range(an):
            name, offset = _dns_name(msg, offset)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[offset : offset + 10])
            offset += 10
            rdata = msg[offset : offset + rdlen]
            offset += rdlen
            value = _dns_rdata(rtype, rdata)
            answers.append((rtype, value))
            answer_nodes.append(_node("Answers", [
                _it("Name", name), _it("Type", DNS_TYPES.get(rtype, rtype)),
                _it("TTL", ttl), _it("Data", value),
            ]))
    except (struct.error, ValueError):
        return False

    is_mdns = (pkt.get("sport") == 5353 or pkt.get("dport") == 5353)
    is_llmnr = (pkt.get("sport") == 5355 or pkt.get("dport") == 5355)
    proto_name = "LLMNR" if is_llmnr else "MDNS" if is_mdns else "DNS"
    pkt["proto"], pkt["color"] = proto_name, "dns"
    pkt["layers"].add("dns")
    if is_llmnr:
        pkt["layers"].add("llmnr")
    elif is_mdns:
        pkt["layers"].add("mdns")
    fields.update({
        "dns.id": tid, "dns.flags.response": qr, "dns.count.queries": qd,
        "dns.count.answers": an, "dns.qry.type": questions[0][1] if questions else 0,
        "dns.qry.name": questions[0][0] if questions else "",
    })
    if answers:
        fields["dns.a"] = [v for t, v in answers if t == 1]
        fields["dns.aaaa"] = [v for t, v in answers if t == 28]

    qname = questions[0][0] if questions else "?"
    qtype = DNS_TYPES.get(questions[0][1], questions[0][1]) if questions else "?"
    if qr:
        rcode_text = {0: "No error", 3: "No such name"}.get(rcode, f"rcode {rcode}")
        lead = "Standard query response" if opcode == 0 else f"Response opcode {opcode}"
        detail = ", ".join(v for _, v in answers[:4])
        pkt["info"] = f"{lead} 0x{tid:04x} {qtype} {qname}" + (f" {detail}" if detail else f" ({rcode_text})")
    else:
        pkt["info"] = f"Standard query 0x{tid:04x} {qtype} {qname}"

    nodes.append(
        _node(
            f"Domain Name System ({'response' if qr else 'query'})",
            [
                _it("Transaction ID", f"0x{tid:04x}", [0, 2]),
                _it("Flags", f"0x{flags:04x} ({'Response' if qr else 'Query'})", [2, 4]),
                _it("Questions", qd), _it("Answer RRs", an), _it("Additional RRs", ar),
            ],
            q_nodes + answer_nodes,
        )
    )
    return True


def _dns_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumps = 0
    cursor = offset
    end = offset
    while cursor < len(msg):
        length = msg[cursor]
        if length == 0:
            cursor += 1
            if jumps == 0:
                end = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(msg):
                raise ValueError("DNS 指针越界")
            pointer = ((length & 0x3F) << 8) | msg[cursor + 1]
            if jumps == 0:
                end = cursor + 2
            cursor = pointer
            jumps += 1
            if jumps > 20:
                raise ValueError("DNS 压缩指针循环")
            continue
        if cursor + 1 + length > len(msg):
            raise ValueError("DNS 标签越界")
        labels.append(msg[cursor + 1 : cursor + 1 + length].decode("utf-8", "replace"))
        cursor += 1 + length
        if jumps == 0:
            end = cursor
    return ".".join(labels), end


def _dns_rdata(rtype: int, rdata: bytes) -> str:
    if rtype == 1 and len(rdata) >= 4:
        return _ip4(rdata[:4])
    if rtype == 28 and len(rdata) >= 16:
        return _ip6(rdata[:16])
    if rtype in (2, 5, 12) and rdata:
        try:
            name, _ = _dns_name(rdata, 0)
            return name
        except ValueError:
            return rdata.hex()
    if rtype == 16:
        try:
            return rdata[1 : 1 + rdata[0]].decode("utf-8", "replace")
        except IndexError:
            return rdata.hex()
    return rdata.hex() if rdata else "-"


# ---------------------------------------------------------------- HTTP

def _http(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    text = payload.decode("utf-8", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines or not lines[0]:
        return False
    first = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    status = re.match(r"^(HTTP/\d(?:\.\d)?)\s+(\d{3})\s*(.*)$", first)
    request = re.match(r"^([A-Z]{3,7})\s+(\S+)\s+(HTTP/\d(?:\.\d)?)$", first)

    if status:
        version, code, reason = status.group(1), int(status.group(2)), status.group(3)
        pkt["proto"], pkt["color"] = "HTTP", "http"
        pkt["layers"].add("http")
        fields.update({
            "http.response.code": code, "http.host": headers.get("host", ""),
            "http.content_type": headers.get("content-type", ""),
            "http.response.line": first,
        })
        pkt["info"] = first[:120]
        children = [_node("Headers", [_it(k.title(), v) for k, v in headers.items()])] if headers else []
        if body:
            preview = body[:300].replace("\r", "").replace("\n", " ")
            children.append(_node(f"Body ({len(body)} bytes)", [_it("Preview", preview)]))
        nodes.append(_node("Hypertext Transfer Protocol", [
            _it("Version", version), _it("Status Code", code), _it("Reason Phrase", reason or "-"),
            _it("Content-Type", headers.get("content-type", "-")),
        ], children))
        return True

    if request:
        method, uri, version = request.group(1), request.group(2), request.group(3)
        pkt["proto"], pkt["color"] = "HTTP", "http"
        pkt["layers"].add("http")
        fields.update({
            "http.request.method": method, "http.request.uri": uri,
            "http.host": headers.get("host", ""), "http.user_agent": headers.get("user-agent", ""),
            "http.request.line": first,
        })
        pkt["info"] = first[:120]
        children = [_node("Headers", [_it(k.title(), v) for k, v in headers.items()])] if headers else []
        if body:
            children.append(_node(f"Body ({len(body)} bytes)", [_it("Preview", body[:300])]))
        nodes.append(_node("Hypertext Transfer Protocol", [
            _it("Method", method), _it("URI", uri), _it("Version", version),
            _it("Host", headers.get("host", "-")),
        ], children))
        return True
    return False


# ---------------------------------------------------------------- TLS

def _tls(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 5:
        return False
    content_type = payload[0]
    version = struct.unpack("!H", payload[1:3])[0]
    length = struct.unpack("!H", payload[3:5])[0]
    if content_type not in (20, 21, 22, 23):
        return False
    if not (0x0300 <= version <= 0x0304):
        return False

    version_text = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                    0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(version, f"0x{version:04x}")
    type_text = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}[content_type]
    pkt["proto"], pkt["color"] = "TLS", "tls"
    pkt["layers"].add("tls")
    fields.update({"tls.record.type": content_type, "tls.version": version_text,
                   "tls.record.length": length})

    info = type_text
    items = [
        _it("Content Type", f"{content_type} ({type_text})", [0, 1]),
        _it("Version", version_text, [1, 3]),
        _it("Length", length, [3, 5]),
    ]
    children = []

    if content_type == 22 and len(payload) >= 9:
        hs_type = payload[5]
        hs_len = int.from_bytes(payload[6:9], "big")
        hs_names = {1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
                    8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
                    13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
                    16: "Client Key Exchange", 20: "Finished"}
        hs_text = hs_names.get(hs_type, f"Handshake {hs_type}")
        info = hs_text
        items.append(_it("Handshake Type", f"{hs_type} ({hs_text})", [5, 6]))
        fields["tls.handshake.type"] = hs_type
        if hs_type == 1:
            sni = _tls_sni(payload[9 : 9 + hs_len])
            if sni:
                fields["tls.sni"] = sni
                info = f"Client Hello (SNI={sni})"
                children.append(_node("Server Name Indication", [_it("Server Name", sni)]))
        elif hs_type == 2 and len(payload) >= 43:
            children.append(_node("Server Random", [_it("Random", payload[11:43].hex())]))

    nodes.append(_node(f"Transport Layer Security ({version_text})", items, children))
    pkt["info"] = info
    return True


def _tls_sni(body: bytes) -> str | None:
    """从 Client Hello 中解析 SNI。"""
    try:
        pos = 2 + 32
        sid_len = body[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2 + cs_len
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return None
        ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", body[pos : pos + 4])
            pos += 4
            if ext_type == 0:
                data = body[pos : pos + ext_len]
                if len(data) < 5:
                    return None
                name_len = struct.unpack("!H", data[3:5])[0]
                return data[5 : 5 + name_len].decode("utf-8", "replace")
            pos += ext_len
        return None
    except (IndexError, struct.error):
        return None


# ---------------------------------------------------------------- HTTP/2

H2_FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION",
}
H2_SETTINGS = {
    1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
}
H2_ERRORS = {
    0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
    4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM",
    8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
    12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
}


def _http2_frame_detail(ftype: int, flags: int, sid: int, body: bytes) -> list:
    detail = []
    if ftype == 4 and len(body) >= 6:
        ident = struct.unpack("!H", body[:2])[0]
        detail.append((H2_SETTINGS.get(ident, f"Setting {ident}"), int.from_bytes(body[2:6], "big")))
    elif ftype == 6 and len(body) >= 8:
        detail.append(("Opaque Data", body[:8].hex()))
    elif ftype == 3 and len(body) >= 4:
        code = struct.unpack("!I", body[:4])[0]
        detail.append(("Error Code", H2_ERRORS.get(code, code)))
    elif ftype == 7 and len(body) >= 8:
        detail.append(("Last Stream ID", int.from_bytes(body[:4], "big") & 0x7FFFFFFF))
        code = struct.unpack("!I", body[4:8])[0]
        detail.append(("Error Code", H2_ERRORS.get(code, code)))
    elif ftype == 8 and len(body) >= 4:
        detail.append(("Window Increment", int.from_bytes(body[:4], "big") & 0x7FFFFFFF))
    elif ftype == 2 and len(body) >= 4:
        detail.append(("Stream Dependency", int.from_bytes(body[:4], "big") & 0x7FFFFFFF))
        detail.append(("Weight", (body[4] + 1) if len(body) > 4 else 1))
    elif ftype in (0, 1):
        detail.append(("END_STREAM", bool(flags & 0x01)))
        detail.append(("END_HEADERS", bool(flags & 0x04)))
    return detail


def _http2(payload: bytes, pkt: dict, fields: dict, nodes: list, require_preface: bool = True) -> bool:
    start = 0
    if payload.startswith(HTTP2_PREFACE):
        start = len(HTTP2_PREFACE)
    elif require_preface:
        return False

    frames = []
    pos, guard = start, 0
    while pos + 9 <= len(payload) and guard < 32:
        length = int.from_bytes(payload[pos : pos + 3], "big")
        ftype = payload[pos + 3]
        flags = payload[pos + 4]
        sid = int.from_bytes(payload[pos + 5 : pos + 9], "big") & 0x7FFFFFFF
        if ftype > 9 or length > 16777215:
            break
        if pos + 9 + length > len(payload):
            break
        frames.append((ftype, flags, sid, payload[pos + 9 : pos + 9 + length]))
        pos += 9 + length
        guard += 1

    if start == 0:
        if not frames or frames[0][0] not in (0, 1, 4):
            return False

    pkt["proto"], pkt["color"] = "HTTP2", "http"
    pkt["layers"].update(("http2", "http"))
    summary = [f"{H2_FRAME_TYPES.get(f[0], f[0])}({len(f[3])})" for f in frames]
    children = []
    if start:
        children.append(_node("Client Connection Preface", [_it("Preface", HTTP2_PREFACE.decode("ascii", "replace"))]))
    for ftype, flags, sid, body in frames[:8]:
        name = H2_FRAME_TYPES.get(ftype, str(ftype))
        detail = _http2_frame_detail(ftype, flags, sid, body)
        children.append(_node(
            f"{name} frame, Stream {sid}",
            [_it("Type", f"{ftype} ({name})"), _it("Flags", f"0x{flags:02x}"),
             _it("Stream ID", sid), _it("Length", len(body))],
            [_node("Details", [_it(k, v) for k, v in detail])] if detail else [],
        ))
    fields.update({
        "http2.preface": bool(start),
        "http2.frame.count": len(frames),
        "http2.first.frame.type": frames[0][0] if frames else -1,
        "http2.stream.id": frames[0][2] if frames else 0,
    })
    nodes.append(_node("HTTP/2", [
        _it("Frames", len(frames)),
        _it("Sequence", ", ".join(summary) if summary else "-"),
    ], children))
    pkt["info"] = "HTTP2 " + ", ".join(summary) if summary else "HTTP2 client preface"
    return True


# ---------------------------------------------------------------- MQTT

MQTT_TYPES = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
    6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
    11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
}
MQTT_QOS = {0: "最多一次", 1: "至少一次", 2: "仅一次"}
MQTT_CONNACK = {0: "Accepted", 1: "Bad protocol", 2: "Bad client id", 3: "Unavailable",
                4: "Bad credentials", 5: "Not authorized"}


def _mqtt_varint(data: bytes, pos: int) -> tuple[int, int]:
    mult, value = 1, 0
    for _ in range(4):
        if pos >= len(data):
            raise ValueError("MQTT 长度字段不完整")
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) * mult
        if not byte & 0x80:
            return value, pos
        mult *= 128
    raise ValueError("MQTT 长度字段非法")


def _mqtt_string(data: bytes, pos: int) -> tuple[str, int]:
    if pos + 2 > len(data):
        raise ValueError("MQTT 字符串不完整")
    length = struct.unpack("!H", data[pos : pos + 2])[0]
    if pos + 2 + length > len(data):
        raise ValueError("MQTT 字符串越界")
    return data[pos + 2 : pos + 2 + length].decode("utf-8", "replace"), pos + 2 + length


def _mqtt(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if not payload:
        return False
    ptype = payload[0] >> 4
    pflags = payload[0] & 0x0F
    if ptype not in MQTT_TYPES:
        return False
    try:
        remaining, body_off = _mqtt_varint(payload, 1)
    except ValueError:
        return False
    if body_off + remaining > len(payload):
        return False
    body = payload[body_off : body_off + remaining]
    name = MQTT_TYPES[ptype]
    detail = []
    info = name

    if ptype == 1:
        try:
            protocol, pos = _mqtt_string(body, 0)
            level, cflags = body[pos], body[pos + 1]
            keepalive = struct.unpack("!H", body[pos + 2 : pos + 4])[0]
            client_id, _ = _mqtt_string(body, pos + 4)
            detail = [("Protocol Name", protocol), ("Protocol Level", level),
                      ("Clean Session", bool(cflags & 0x02)), ("Keep Alive", keepalive),
                      ("Client ID", client_id or "-")]
            fields.update({"mqtt.protocol": protocol, "mqtt.clientid": client_id})
            info = f"CONNECT 客户端={client_id or '-'}"
        except (ValueError, IndexError, struct.error):
            pass
    elif ptype == 2 and len(body) >= 2:
        detail = [("Session Present", bool(body[0] & 0x01)),
                  ("Return Code", MQTT_CONNACK.get(body[1], body[1]))]
        info = f"CONNACK {MQTT_CONNACK.get(body[1], body[1])}"
    elif ptype == 3:
        qos = (pflags >> 1) & 0x03
        try:
            topic, pos = _mqtt_string(body, 0)
            detail = [("Topic", topic), ("QoS", f"{qos} ({MQTT_QOS.get(qos, '?')})"),
                      ("Retain", bool(pflags & 0x01)), ("Duplicate", bool(pflags & 0x08))]
            if qos:
                detail.append(("Packet ID", struct.unpack("!H", body[pos : pos + 2])[0]))
            fields.update({"mqtt.topic": topic, "mqtt.qos": qos})
            info = f"PUBLISH 主题={topic} qos={qos}"
        except (ValueError, IndexError, struct.error):
            pass
    elif ptype in (8, 10):
        try:
            pid = struct.unpack("!H", body[:2])[0]
            topic, _ = _mqtt_string(body, 2)
            detail = [("Packet ID", pid), ("Topic", topic)]
            fields["mqtt.topic"] = topic
            info = f"{name} 主题={topic}"
        except (ValueError, IndexError, struct.error):
            pass
    elif ptype in (4, 5, 6, 7) and len(body) >= 2:
        detail = [("Packet ID", struct.unpack("!H", body[:2])[0])]

    pkt["proto"], pkt["color"] = "MQTT", "mqtt"
    pkt["layers"].add("mqtt")
    fields.update({"mqtt.type": ptype, "mqtt.type.name": name, "mqtt.len": remaining})
    nodes.append(_node(
        f"MQTT {name}",
        [_it("Packet Type", f"{ptype} ({name})", [0, 1]),
         _it("Flags", f"0x{pflags:02x}", [0, 1]),
         _it("Remaining Length", remaining, [1, body_off])],
        [_node("Details", [_it(k, v) for k, v in detail])] if detail else [],
    ))
    pkt["info"] = info
    return True


# ---------------------------------------------------------------- Redis

REDIS_CMDS = {
    "GET", "SET", "DEL", "EXISTS", "EXPIRE", "TTL", "INCR", "DECR", "HGET", "HSET",
    "HDEL", "HGETALL", "LPUSH", "RPUSH", "LPOP", "RPOP", "LRANGE", "SADD", "SREM",
    "SMEMBERS", "ZADD", "ZRANGE", "PUBLISH", "SUBSCRIBE", "PING", "INFO", "AUTH",
    "SELECT", "KEYS", "SCAN", "MGET", "MSET", "CONFIG", "COMMAND", "CLIENT", "TYPE",
    "ECHO", "DBSIZE", "FLUSHALL", "FLUSHDB", "MULTI", "EXEC", "DISCARD", "WATCH",
}


def _redis(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if not payload or payload[0] not in b"+-:$*_,":
        return False
    sample = payload[:512]
    if any(b < 9 or (13 < b < 32) for b in sample):
        return False
    lines = [line for line in sample.decode("utf-8", "replace").split("\r\n") if line]
    if not lines:
        return False
    first = lines[0]
    command, args = "", []
    if first.startswith("*"):
        if len(lines) < 3 or not lines[1].startswith("$"):
            return False
        values = []
        index = 1
        while index + 1 < len(lines) and lines[index].startswith("$"):
            values.append(lines[index + 1])
            index += 2
        if not values:
            return False
        command, args = values[0], values[1:]
    elif first.startswith("$"):
        if len(lines) < 2:
            return False
        command = lines[1]
    elif first[:1] in ("+", "-", ":", ","):
        command = first[1:].strip()
    else:
        parts = first.split(" ")
        command, args = parts[0], parts[1:]
    if first[:1] not in ("+", "-", ":", ",", "$") and command.upper() not in REDIS_CMDS:
        return False

    pkt["proto"], pkt["color"] = "Redis", "redis"
    pkt["layers"].add("redis")
    preview = " ".join([command] + args)[:120]
    fields.update({"redis.command": command.upper(), "redis.args.count": len(args)})
    if args:
        fields["redis.key"] = args[0]
    nodes.append(_node(
        "Redis Protocol",
        [_it("Command", command.upper() or "-"),
         _it("Arguments", ", ".join(args[:8]) if args else "-"),
         _it("Preview", preview or "-")],
    ))
    pkt["info"] = preview or "Redis"
    return True


# ---------------------------------------------------------------- Memcached

MEMCACHED_CMDS = {
    "get", "gets", "gat", "gats", "set", "add", "replace", "append", "prepend",
    "cas", "delete", "incr", "decr", "touch", "stats", "version", "quit", "flush_all",
    "verbosity", "mg", "ms", "md", "ma", "me", "mn", "lru_crawler",
}


def _memcached(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if not payload or len(payload) > 8192:
        return False
    text = payload[:256].decode("utf-8", "replace")
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text):
        return False
    first = text.split("\r\n")[0]
    parts = first.split(" ")
    command = parts[0].lower()
    if command not in MEMCACHED_CMDS:
        return False
    args = parts[1:]

    pkt["proto"], pkt["color"] = "Memcached", "memcached"
    pkt["layers"].add("memcached")
    fields.update({"memcached.command": command, "memcached.args.count": len(args)})
    if command in ("get", "gets", "delete", "incr", "decr", "touch") and args:
        fields["memcached.key"] = args[0]
    if command in ("set", "add", "replace", "append", "prepend", "cas") and args:
        fields["memcached.key"] = args[0]
    nodes.append(_node(
        "Memcached Text Protocol",
        [_it("Command", command),
         _it("Arguments", ", ".join(args[:8]) if args else "-"),
         _it("Line", first[:120])],
    ))
    pkt["info"] = first[:120]
    return True


# ---------------------------------------------------------------- FTP / Telnet

FTP_CMDS = {
    "USER", "PASS", "ACCT", "CWD", "CDUP", "QUIT", "REIN", "PORT", "PASV", "TYPE",
    "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO",
    "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT",
    "HELP", "NOOP", "FEAT", "AUTH", "PBSZ", "PROT", "EPSV", "EPRT", "SIZE", "MDTM",
    "MLSD", "MLST", "OPTS",
}
FTP_REPLIES = {
    "220": "服务就绪", "221": "服务关闭", "226": "传输完成", "227": "进入被动模式",
    "230": "登录成功", "250": "请求成功", "331": "需要密码", "425": "无法打开数据连接",
    "421": "服务不可用", "530": "未登录", "550": "操作失败",
}


def _ftp(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if not payload or len(payload) > 8192:
        return False
    text = payload.decode("utf-8", "replace")
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text[:200]):
        return False
    line = text.split("\r\n")[0].strip()
    if not line:
        return False

    code = ""
    parts = line.split(" ")
    if len(line) >= 3 and line[:3].isdigit():
        code = line[:3]
        verb = FTP_REPLIES.get(code, "响应")
        info = f"{code} {verb}"
    else:
        verb = parts[0].upper()
        if verb not in FTP_CMDS:
            return False
        info = line

    pkt["proto"], pkt["color"] = "FTP", "ftp"
    pkt["layers"].add("ftp")
    fields.update({"ftp.command": verb, "ftp.reply_code": code})
    if verb == "USER" and len(parts) > 1:
        fields["ftp.username"] = parts[1]
        info = f"USER {parts[1]}"
    elif verb == "PASS":
        info = "PASS (已隐藏)"
    elif verb in ("RETR", "STOR") and len(parts) > 1:
        fields["ftp.filename"] = parts[1]
        info = f"{verb} {parts[1]}"
    nodes.append(_node(
        "File Transfer Protocol" if code else "File Transfer Protocol (command)",
        [_it("Code", code or "-"), _it("Command", verb), _it("Line", line[:120])],
    ))
    pkt["info"] = info
    return True


TELNET_OPTS = {
    0: "BINARY", 1: "ECHO", 3: "SUPPRESS-GO-AHEAD", 5: "STATUS", 24: "TERMINAL-TYPE",
    31: "NAWS", 32: "TERMINAL-SPEED", 33: "REMOTE-FLOW-CONTROL", 34: "LINEMODE",
    36: "ENVIRON", 39: "NEW-ENVIRON",
}
TELNET_CMDS = {
    236: "EOF", 237: "SUSP", 238: "ABORT", 239: "EOR", 240: "SE", 241: "NOP",
    242: "DM", 243: "BRK", 244: "IP", 245: "AO", 246: "AYT", 247: "EC", 248: "EL",
    249: "GA", 250: "SB", 251: "WILL", 252: "WONT", 253: "DO", 254: "DONT", 255: "IAC",
}


def _telnet(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if not payload or len(payload) > 8192:
        return False
    text = payload.decode("utf-8", "replace")
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    has_iac = 0xFF in payload
    if not has_iac and printable < len(text) * 0.85:
        return False

    negotiations = []
    plain = []
    pos = 0
    while pos < len(payload):
        byte = payload[pos]
        if byte != 0xFF:
            plain.append(chr(byte) if 32 <= byte < 127 else " ")
            pos += 1
            continue
        pos += 1
        if pos >= len(payload):
            break
        cmd = payload[pos]
        pos += 1
        if cmd == 0xFF:
            plain.append(" ")
            continue
        if cmd in (251, 252, 253, 254) and pos < len(payload):
            opt = payload[pos]
            pos += 1
            negotiations.append(f"{TELNET_CMDS.get(cmd, cmd)} {TELNET_OPTS.get(opt, opt)}")
        elif cmd == 250:
            while pos + 1 < len(payload) and not (payload[pos] == 0xFF and payload[pos + 1] == 240):
                pos += 1
            pos += 2
            negotiations.append("SB (子协商)")
        else:
            negotiations.append(TELNET_CMDS.get(cmd, f"CMD {cmd}"))

    pkt["proto"], pkt["color"] = "Telnet", "telnet"
    pkt["layers"].add("telnet")
    fields.update({"telnet.negotiation.count": len(negotiations)})
    nodes.append(_node(
        "Telnet",
        [_it("Negotiations", ", ".join(negotiations[:10]) if negotiations else "-"),
         _it("Text", "".join(plain).strip()[:100] or "-")],
    ))
    if negotiations:
        pkt["info"] = "Telnet " + ", ".join(negotiations[:4])
    else:
        pkt["info"] = "Telnet 数据 " + ("".join(plain).strip()[:60] or "-")
    return True


# ---------------------------------------------------------------- MySQL / PostgreSQL / LDAP / SMB / Modbus

MYSQL_CMDS = {
    0: "COM_SLEEP", 1: "COM_QUIT", 2: "COM_INIT_DB", 3: "COM_QUERY", 4: "COM_FIELD_LIST",
    5: "COM_CREATE_DB", 6: "COM_DROP_DB", 7: "COM_REFRESH", 8: "COM_SHUTDOWN",
    9: "COM_STATISTICS", 10: "COM_PROCESS_INFO", 11: "COM_CONNECT", 12: "COM_PROCESS_KILL",
    13: "COM_DEBUG", 14: "COM_PING", 15: "COM_TIME", 16: "COM_DELAYED_INSERT",
    17: "COM_CHANGE_USER", 18: "COM_BINLOG_DUMP", 19: "COM_TABLE_DUMP", 20: "COM_CONNECT_OUT",
    21: "COM_REGISTER_SLAVE", 22: "COM_STMT_PREPARE", 23: "COM_STMT_EXECUTE",
    24: "COM_STMT_SEND_LONG_DATA", 25: "COM_STMT_CLOSE", 26: "COM_STMT_RESET",
    27: "COM_SET_OPTION", 28: "COM_STMT_FETCH", 29: "COM_DAEMON", 30: "COM_BINLOG_DUMP_GTID",
    31: "COM_RESET_CONNECTION",
}


def _mysql(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 5:
        return False
    length = int.from_bytes(payload[:3], "little")
    seq = payload[3]
    if length == 0 or length > len(payload) - 4:
        return False
    body = payload[4 : 4 + length]
    if not body:
        return False

    detail = []
    info = "MySQL"
    first = body[0]
    if first == 0x0A and len(body) > 10:
        pos = 1
        end = body.find(b"\x00", pos)
        if end < 0:
            return False
        server_version = body[pos:end].decode("utf-8", "replace")
        thread_id = struct.unpack("<I", body[end + 1 : end + 5])[0] if len(body) >= end + 5 else 0
        detail = [("Protocol", 10), ("Server Version", server_version), ("Thread ID", thread_id)]
        fields.update({"mysql.server_version": server_version, "mysql.thread_id": thread_id})
        info = f"Handshake 服务器版本={server_version}"
    elif first == 0xFF and len(body) >= 3:
        code = struct.unpack("<H", body[1:3])[0]
        detail = [("Error Code", code), ("Message", body[3:80].decode("utf-8", "replace"))]
        fields["mysql.error_code"] = code
        info = f"Error {code}"
    elif first == 0x00:
        detail = [("Affected Rows", int.from_bytes(body[1:9], "little") if len(body) >= 9 else 0)]
        info = "OK"
    elif first == 0xFE:
        detail = [("EOF", True)]
        info = "EOF"
    elif first in MYSQL_CMDS:
        command = MYSQL_CMDS[first]
        query = body[1:200].decode("utf-8", "replace") if len(body) > 1 else ""
        detail = [("Command", f"{first} ({command})"), ("Statement", query[:120] or "-")]
        fields.update({"mysql.command": command})
        if query:
            fields["mysql.query"] = query
        info = f"{command} {query[:60]}"
    else:
        detail = [("Payload", body[:40].hex())]

    pkt["proto"], pkt["color"] = "MySQL", "mysql"
    pkt["layers"].add("mysql")
    fields.update({"mysql.packet.length": length, "mysql.seq": seq})
    nodes.append(_node(
        "MySQL Protocol",
        [_it("Packet Length", length), _it("Sequence ID", seq)],
        [_node("Details", [_it(k, v) for k, v in detail])] if detail else [],
    ))
    pkt["info"] = info
    return True


PG_TAGS = {
    "Q": "Simple Query", "P": "Parse", "B": "Bind", "E": "Execute", "D": "Describe",
    "C": "Close", "S": "Sync", "F": "Function Call", "X": "Terminate", "d": "Copy Data",
    "c": "Copy Done", "f": "Copy Fail", "H": "Flush", "p": "Password Message",
    "R": "Authentication", "N": "Notice Response", "Z": "Ready For Query",
    "T": "Row Description", "A": "Notification Response", "K": "Backend Key Data",
    "n": "No Data", "t": "Parameter Description", "1": "Parse Complete",
    "2": "Bind Complete", "3": "Close Complete", "s": "Portal Suspended",
    "V": "Function Call Response", "I": "Empty Query Response", "G": "Copy In Response",
    "W": "Copy Both Response", "J": "Negotiate Protocol Version",
}


def _postgres(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 5:
        return False
    startup_len = int.from_bytes(payload[:4], "big")
    tag = ""
    body = b""
    info = "PostgreSQL"
    if 8 <= startup_len <= len(payload) and payload[4:8] == b"\x00\x03\x00\x00":
        tag = "StartupMessage"
        detail = [("Protocol", "3.0"), ("Parameters", payload[8:startup_len].decode("utf-8", "replace").replace("\x00", " ").strip())]
        if payload[4:8] == b"\x00\x03\x00\x00":
            fields["pg.ssl_request"] = False
        info = "Startup Message"
    elif len(payload) >= 5 and 0 <= payload[0] <= 0x7F:
        letter = chr(payload[0])
        length = int.from_bytes(payload[1:5], "big")
        if letter not in PG_TAGS or length < 4 or length > len(payload) - 1:
            return False
        tag = PG_TAGS[letter]
        body = payload[5 : 1 + length]
        if letter == "Q":
            query = body.decode("utf-8", "replace").strip("\x00")
            fields["pg.query"] = query
            info = f"Query {query[:70]}"
        elif letter == "E":
            info = "Error Response"
        elif letter == "R":
            info = "Authentication"
        else:
            info = tag
        detail = [("Message Type", f"{letter} ({tag})"), ("Length", length)]
    else:
        return False

    pkt["proto"], pkt["color"] = "PostgreSQL", "postgres"
    pkt["layers"].add("postgres")
    fields.update({"pg.tag": tag})
    nodes.append(_node("PostgreSQL Protocol", [_it(k, v) for k, v in detail], []))
    pkt["info"] = info
    return True


def _ber_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("BER 长度缺失")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise ValueError("BER 长度非法")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _ber_int(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("BER 整数缺失")
    length, pos = _ber_length(data, pos + 1)
    if pos + length > len(data):
        raise ValueError("BER 整数越界")
    return int.from_bytes(data[pos : pos + length], "big"), pos + length


LDAP_OPS = {
    0x60: "BindRequest", 0x61: "BindResponse", 0x63: "SearchRequest",
    0x64: "SearchResultEntry", 0x65: "SearchResultDone", 0x67: "ModifyRequest",
    0x68: "ModifyResponse", 0x69: "AddRequest", 0x6A: "AddResponse",
    0x4B: "DeleteRequest", 0x6B: "DeleteResponse", 0x42: "UnbindRequest",
    0x50: "AbandonRequest", 0x77: "ExtendedRequest", 0x78: "ExtendedResponse",
}


def _ldap(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 8 or payload[0] != 0x30:
        return False
    try:
        total, pos = _ber_length(payload, 1)
        if pos + total > len(payload):
            return False
        msg_id, pos = _ber_int(payload, pos)
        if pos >= len(payload):
            return False
        op = payload[pos]
        if op not in LDAP_OPS:
            return False
        op_len, op_pos = _ber_length(payload, pos + 1)
    except ValueError:
        return False

    name = LDAP_OPS[op]
    base = ""
    scope = ""
    try:
        if op in (0x63, 0x64):
            base, cursor = _ber_string(payload, op_pos)
            scope = payload[cursor] if cursor < len(payload) else ""
    except ValueError:
        pass

    pkt["proto"], pkt["color"] = "LDAP", "ldap"
    pkt["layers"].add("ldap")
    fields.update({"ldap.message_id": msg_id, "ldap.operation": name})
    if base:
        fields["ldap.base_object"] = base
    nodes.append(_node(
        "Lightweight Directory Access Protocol",
        [_it("Message ID", msg_id), _it("Operation", name),
         _it("Base Object", base or "-"), _it("Length", op_len)],
    ))
    pkt["info"] = f"{name} msgid={msg_id}" + (f" base={base}" if base else "")
    return True


def _ber_string(data: bytes, pos: int) -> tuple[str, int]:
    if pos >= len(data) or data[pos] != 0x04:
        raise ValueError("BER 字符串缺失")
    length, pos = _ber_length(data, pos + 1)
    if pos + length > len(data):
        raise ValueError("BER 字符串越界")
    return data[pos : pos + length].decode("utf-8", "replace"), pos + length


SMB2_CMDS = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
    4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE",
    10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO", 14: "QUERY_DIRECTORY",
    15: "CHANGE_NOTIFY", 16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK",
}
SMB1_CMDS = {
    0x00: "CREATE_DIRECTORY", 0x01: "DELETE_DIRECTORY", 0x02: "OPEN", 0x03: "CREATE",
    0x04: "CLOSE", 0x05: "FLUSH", 0x06: "DELETE", 0x07: "RENAME", 0x08: "QUERY_INFORMATION",
    0x09: "SET_INFORMATION", 0x0A: "READ", 0x0B: "WRITE", 0x0C: "LOCK", 0x0D: "UNLOCK",
    0x0E: "CREATE_DIRECTORY", 0x20: "WRITE_ANDX", 0x24: "READ_ANDX", 0x25: "TRANSACTION",
    0x2E: "READ_ANDX", 0x2F: "WRITE_ANDX", 0x32: "TRANSACTION2", 0x71: "TREE_CONNECT",
    0x72: "TREE_DISCONNECT", 0x73: "NEGOTIATE", 0x74: "SESSION_SETUP",
}
NETBIOS_TYPES = {
    0x00: "Session Message", 0x81: "Session Request", 0x82: "Positive Session Response",
    0x83: "Negative Session Response", 0x84: "Retarget Session Response",
    0x85: "Session Keep Alive",
}


def _smb(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    data = payload
    nb = 0
    if len(data) >= 4 and data[0] in NETBIOS_TYPES:
        nb = data[0]
        data = data[4:]
    if len(data) >= 4 and data[:4] == b"\xffSMB":
        version = "SMB1"
        command = data[4] if len(data) > 4 else -1
        name = SMB1_CMDS.get(command, f"CMD {command}")
        status = struct.unpack("<I", data[5:9])[0] if len(data) >= 9 else 0
        info = f"SMB1 {name}"
    elif len(data) >= 4 and data[:4] == b"\xfeSMB":
        version = "SMB2"
        command = struct.unpack("<H", data[12:14])[0] if len(data) >= 14 else -1
        name = SMB2_CMDS.get(command, f"CMD {command}")
        status = struct.unpack("<I", data[8:12])[0] if len(data) >= 12 else 0
        info = f"SMB2 {name}"
    else:
        return False

    pkt["proto"], pkt["color"] = "SMB", "smb"
    pkt["layers"].add("smb")
    fields.update({"smb.version": version, "smb.command": name, "smb.nt_status": f"0x{status:08x}"})
    nodes.append(_node(
        "Server Message Block",
        [_it("Version", version),
         _it("NetBIOS Type", NETBIOS_TYPES.get(nb, "-") if nb else "-"),
         _it("Command", name),
         _it("NT Status", f"0x{status:08x}")],
    ))
    pkt["info"] = info
    return True


MODBUS_FC = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    7: "Read Exception Status", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 17: "Report Server ID", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers", 43: "Encapsulated Interface Transport",
}
MODBUS_EXC = {
    1: "非法功能", 2: "非法数据地址", 3: "非法数据值", 4: "从站设备故障",
    5: "确认", 6: "从站设备忙", 8: "存储奇偶校验错", 10: "网关路径不可用",
    11: "网关目标无响应",
}


def _modbus(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 8:
        return False
    tid, pid, length = struct.unpack("!HHH", payload[:6])
    if pid != 0 or length < 2 or length > len(payload) - 6:
        return False
    unit = payload[6]
    fc = payload[7]
    exception = fc & 0x80
    base_fc = fc & 0x7F
    if base_fc not in MODBUS_FC:
        return False
    name = MODBUS_FC[base_fc]
    if exception:
        code = payload[8] if len(payload) > 8 else 0
        info = f"异常响应 {MODBUS_EXC.get(code, code)}"
    else:
        info = name

    pkt["proto"], pkt["color"] = "Modbus", "modbus"
    pkt["layers"].add("modbus")
    fields.update({"modbus.transaction_id": tid, "modbus.unit_id": unit,
                   "modbus.function_code": base_fc})
    nodes.append(_node(
        "Modbus TCP",
        [_it("Transaction ID", tid), _it("Protocol ID", pid), _it("Length", length),
         _it("Unit ID", unit), _it("Function", f"{base_fc} ({name})"),
         _it("Exception", exception)],
    ))
    pkt["info"] = info
    return True


# ---------------------------------------------------------------- NTP / DHCP / TFTP

NTP_MODES = {0: "Reserved", 1: "Symmetric active", 2: "Symmetric passive", 3: "Client",
             4: "Server", 5: "Broadcast", 6: "Control", 7: "Private"}


def _ntp_time(value: int) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromtimestamp(value - 2208988800).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "-"


def _ntp(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 48:
        return False
    first = payload[0]
    leap, version, mode = (first >> 6) & 3, (first >> 3) & 7, first & 7
    if version < 1 or version > 4 or mode == 0:
        return False
    stratum, poll, precision = payload[1], payload[2], struct.unpack("!b", payload[3:4])[0]
    ref_id = payload[12:16]
    ref_text = _ip4(ref_id) if mode in (3, 4) else ref_id.hex()
    transmit = int.from_bytes(payload[40:44], "big")
    originate = int.from_bytes(payload[24:28], "big")
    mode_text = NTP_MODES.get(mode, str(mode))

    pkt["proto"], pkt["color"] = "NTP", "ntp"
    pkt["layers"].add("ntp")
    fields.update({"ntp.version": version, "ntp.mode": mode, "ntp.stratum": stratum})
    nodes.append(_node(
        "Network Time Protocol",
        [_it("Leap Indicator", leap), _it("Version", version),
         _it("Mode", f"{mode} ({mode_text})"), _it("Stratum", stratum),
         _it("Poll", poll), _it("Precision", precision),
         _it("Reference ID", ref_text), _it("Originate Time", _ntp_time(originate)),
         _it("Transmit Time", _ntp_time(transmit))],
    ))
    pkt["info"] = f"NTP {mode_text} v{version} stratum={stratum}"
    return True


DHCP_MAGIC = b"\x63\x82\x53\x63"
DHCP_OPTIONS = {
    1: "Subnet Mask", 3: "Router", 6: "DNS Servers", 12: "Host Name", 15: "Domain Name",
    28: "Broadcast Address", 43: "Vendor Specific", 50: "Requested IP", 51: "Lease Time",
    53: "Message Type", 54: "Server Identifier", 55: "Parameter Request List",
    58: "Renewal Time", 59: "Rebinding Time", 60: "Vendor Class",
    61: "Client Identifier", 81: "Client FQDN",
}
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
              6: "NAK", 7: "RELEASE", 8: "INFORM", 9: "FORCERENEW"}


def _dhcp(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 240 or payload[236:240] != DHCP_MAGIC:
        return False
    op, htype, hlen = payload[0], payload[1], payload[2]
    xid = struct.unpack("!I", payload[4:8])[0]
    ciaddr = _ip4(payload[12:16])
    yiaddr = _ip4(payload[16:20])
    siaddr = _ip4(payload[20:24])
    giaddr = _ip4(payload[24:28])
    client = _mac(payload[28 : 28 + hlen]) if 0 < hlen <= 16 else "-"

    options = {}
    pos = 240
    msg_type = 0
    while pos + 1 < len(payload):
        code = payload[pos]
        if code == 0:
            pos += 1
            continue
        if code == 255:
            break
        if pos + 1 >= len(payload):
            break
        length = payload[pos + 1]
        if pos + 2 + length > len(payload):
            break
        value = payload[pos + 2 : pos + 2 + length]
        options[code] = value
        if code == 53 and value:
            msg_type = value[0]
        pos += 2 + length

    type_text = DHCP_TYPES.get(msg_type, "DHCP")
    hostname = options.get(12, b"").decode("utf-8", "replace")
    requested = _ip4(options[50]) if 50 in options and len(options[50]) == 4 else ""
    detail = [
        ("Message Type", f"{msg_type} ({type_text})"), ("Transaction ID", f"0x{xid:08x}"),
        ("Client MAC", client), ("Client IP", ciaddr), ("Your IP", yiaddr),
        ("Server IP", siaddr), ("Gateway IP", giaddr), ("Host Name", hostname or "-"),
    ]
    if requested:
        detail.append(("Requested IP", requested))
    for code, label in ((1, "Subnet Mask"), (3, "Router"), (6, "DNS")):
        if code in options and len(options[code]) % 4 == 0:
            ips = [_ip4(options[code][i : i + 4]) for i in range(0, len(options[code]), 4)]
            detail.append((label, ", ".join(ips)))
    if 51 in options and len(options[51]) == 4:
        detail.append(("Lease Time", f"{int.from_bytes(options[51], 'big')} 秒"))

    pkt["proto"], pkt["color"] = "DHCP", "dhcp"
    pkt["layers"].add("dhcp")
    fields.update({"dhcp.type": msg_type, "dhcp.type.name": type_text,
                   "dhcp.hw.mac_addr": client, "dhcp.ip.your": yiaddr,
                   "dhcp.hostname": hostname})
    nodes.append(_node(f"Dynamic Host Configuration Protocol ({type_text})",
                       [_it(k, v) for k, v in detail]))
    pkt["info"] = f"DHCP {type_text} {client}" + (f" {hostname}" if hostname else "")
    return True


TFTP_OPS = {1: "Read Request", 2: "Write Request", 3: "Data", 4: "Acknowledgment",
            5: "Error", 6: "Option Acknowledgment"}


def _tftp(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 4:
        return False
    opcode = struct.unpack("!H", payload[:2])[0]
    if opcode not in TFTP_OPS:
        return False
    name = TFTP_OPS[opcode]
    detail = []
    info = f"TFTP {name}"
    if opcode in (1, 2):
        parts = payload[2:].split(b"\x00")
        filename = parts[0].decode("utf-8", "replace") if parts else ""
        mode = parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""
        options = [p.decode("utf-8", "replace") for p in parts[2:] if p]
        detail = [("Filename", filename), ("Mode", mode),
                  ("Options", ", ".join(options) if options else "-")]
        fields.update({"tftp.filename": filename, "tftp.mode": mode})
        info = f"{name} {filename}"
    elif opcode == 3 and len(payload) >= 4:
        detail = [("Block", struct.unpack("!H", payload[2:4])[0]),
                  ("Data Length", len(payload) - 4)]
    elif opcode == 4 and len(payload) >= 4:
        detail = [("Block", struct.unpack("!H", payload[2:4])[0])]
    elif opcode == 5 and len(payload) >= 4:
        code = struct.unpack("!H", payload[2:4])[0]
        detail = [("Error Code", code), ("Message", payload[4:120].decode("utf-8", "replace"))]
        info = f"Error {code}"

    pkt["proto"], pkt["color"] = "TFTP", "tftp"
    pkt["layers"].add("tftp")
    fields.update({"tftp.opcode": opcode})
    nodes.append(_node("Trivial File Transfer Protocol", [_it("Opcode", f"{opcode} ({name})")],
                       [_node("Details", [_it(k, v) for k, v in detail])] if detail else []))
    pkt["info"] = info
    return True


# ---------------------------------------------------------------- STUN / SNMP / Syslog / SIP

STUN_TYPES = {
    0x0001: "Binding Request", 0x0101: "Binding Response", 0x0111: "Binding Error",
    0x0003: "Allocate Request", 0x0103: "Allocate Response", 0x0004: "Refresh Request",
    0x0104: "Refresh Response", 0x0006: "Send Indication", 0x0008: "Data Indication",
    0x0009: "Create Permission Request", 0x0109: "Create Permission Response",
}
STUN_ATTRS = {
    0x0001: "MAPPED-ADDRESS", 0x0006: "USERNAME", 0x0008: "MESSAGE-INTEGRITY",
    0x0009: "ERROR-CODE", 0x000A: "UNKNOWN-ATTRIBUTES", 0x0014: "REALM",
    0x0015: "NONCE", 0x0019: "XOR-MAPPED-ADDRESS", 0x0020: "XOR-MAPPED-ADDRESS",
    0x8022: "SOFTWARE", 0x8028: "FINGERPRINT", 0x8029: "ICE-CONTROLLED",
    0x802A: "ICE-CONTROLLING",
}


def _stun(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 20 or payload[4:8] != b"\x21\x12\xa4\x42":
        return False
    mtype = struct.unpack("!H", payload[:2])[0]
    length = struct.unpack("!H", payload[2:4])[0]
    if length > len(payload) - 20:
        return False
    name = STUN_TYPES.get(mtype, f"0x{mtype:04x}")
    tid = payload[8:20].hex()
    attrs = []
    pos = 20
    end = 20 + length
    while pos + 4 <= end:
        atype, alen = struct.unpack("!HH", payload[pos : pos + 4])
        label = STUN_ATTRS.get(atype, f"0x{atype:04x}")
        attrs.append(f"{label}({alen})")
        pos += 4 + alen + (alen % 4)

    pkt["proto"], pkt["color"] = "STUN", "stun"
    pkt["layers"].add("stun")
    fields.update({"stun.type": name, "stun.length": length, "stun.transaction_id": tid})
    nodes.append(_node(
        "Session Traversal Utilities for NAT",
        [_it("Message Type", name), _it("Length", length), _it("Transaction ID", tid),
         _it("Attributes", ", ".join(attrs) if attrs else "-")],
    ))
    pkt["info"] = f"STUN {name}"
    return True


SNMP_PDUS = {
    0xA0: "GetRequest", 0xA1: "GetNextRequest", 0xA2: "Response", 0xA3: "SetRequest",
    0xA4: "Trap", 0xA5: "GetBulkRequest", 0xA6: "InformRequest", 0xA7: "TrapV2",
    0xA8: "Report",
}


def _snmp(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 12 or payload[0] != 0x30:
        return False
    try:
        total, pos = _ber_length(payload, 1)
        if pos + total > len(payload):
            return False
        version, pos = _ber_int(payload, pos)
        if version not in (0, 1, 3):
            return False
        if pos >= len(payload) or payload[pos] != 0x04:
            return False
        clen, pos = _ber_length(payload, pos + 1)
        if pos + clen > len(payload):
            return False
        community = payload[pos : pos + clen].decode("utf-8", "replace")
        pos += clen
        if pos >= len(payload) or payload[pos] not in SNMP_PDUS:
            return False
        pdu = payload[pos]
        pdu_len, pdu_pos = _ber_length(payload, pos + 1)
        req_id = 0
        if pdu_pos < len(payload) and payload[pdu_pos] == 0x02:
            req_id, _ = _ber_int(payload, pdu_pos)
    except ValueError:
        return False

    version_text = {0: "v1", 1: "v2c", 3: "v3"}.get(version, str(version))
    name = SNMP_PDUS[pdu]
    pkt["proto"], pkt["color"] = "SNMP", "snmp"
    pkt["layers"].add("snmp")
    fields.update({"snmp.version": version_text, "snmp.pdu": name,
                   "snmp.request_id": req_id})
    nodes.append(_node(
        "Simple Network Management Protocol",
        [_it("Version", version_text), _it("Community", community if version != 3 else "-"),
         _it("PDU Type", name), _it("Request ID", req_id), _it("Length", pdu_len)],
    ))
    pkt["info"] = f"SNMP {version_text} {name}" + (f" community={community}" if version != 3 else "")
    return True


SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog", 6: "lpr",
    7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp", 16: "local0",
    17: "local1", 18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}
SYSLOG_SEVERITY = {0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error", 4: "Warning",
                   5: "Notice", 6: "Informational", 7: "Debug"}


def _syslog(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 8 or payload[0:1] != b"<":
        return False
    end = payload.find(b">", 1)
    if end < 0 or end > 5:
        return False
    pri_text = payload[1:end].decode("ascii", "replace")
    if not pri_text.isdigit():
        return False
    pri = int(pri_text)
    facility, severity = pri >> 3, pri & 7
    message = payload[end + 1 :].decode("utf-8", "replace")

    pkt["proto"], pkt["color"] = "Syslog", "syslog"
    pkt["layers"].add("syslog")
    fields.update({"syslog.priority": pri, "syslog.facility": facility,
                   "syslog.severity": severity})
    nodes.append(_node(
        "Syslog",
        [_it("Priority", pri),
         _it("Facility", f"{facility} ({SYSLOG_FACILITIES.get(facility, '?')})"),
         _it("Severity", f"{severity} ({SYSLOG_SEVERITY.get(severity, '?')})"),
         _it("Message", message[:200] or "-")],
    ))
    pkt["info"] = f"Syslog {SYSLOG_SEVERITY.get(severity, severity)}: {message[:70]}"
    return True


SIP_METHODS = {"INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "SUBSCRIBE",
               "NOTIFY", "PUBLISH", "INFO", "PRACK", "MESSAGE", "REFER", "UPDATE"}


def _sip(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if not payload or len(payload) > 8192:
        return False
    text = payload.decode("utf-8", "replace")
    line = text.split("\r\n")[0].strip()
    if not line:
        return False
    reply = re.match(r"^SIP/2\.0\s+(\d{3})\s*(.*)$", line)
    request = re.match(r"^([A-Z]+)\s+(sip:[^\s]+)\s+SIP/2\.0$", line)
    if not reply and not (request and request.group(1) in SIP_METHODS):
        return False

    headers = {}
    for raw_line in text.split("\r\n")[1:]:
        if ":" in raw_line:
            key, _, value = raw_line.partition(":")
            headers[key.strip().lower()] = value.strip()

    pkt["proto"], pkt["color"] = "SIP", "sip"
    pkt["layers"].add("sip")
    if reply:
        method = f"{reply.group(1)} {reply.group(2)}".strip()
        fields.update({"sip.response.code": int(reply.group(1))})
    else:
        method = request.group(1)
        fields.update({"sip.method": method, "sip.uri": request.group(2)})
    fields.update({"sip.call_id": headers.get("call-id", ""),
                   "sip.from": headers.get("from", ""), "sip.to": headers.get("to", "")})
    nodes.append(_node(
        "Session Initiation Protocol",
        [_it("Start Line", line[:120]),
         _it("Call-ID", headers.get("call-id", "-")),
         _it("From", headers.get("from", "-")),
         _it("To", headers.get("to", "-")),
         _it("User-Agent", headers.get("user-agent", "-"))],
    ))
    pkt["info"] = f"SIP {method}"
    return True


# ---------------------------------------------------------------- WireGuard / RTP / QUIC

WIREGUARD_TYPES = {1: "Handshake Initiation", 2: "Handshake Response",
                   3: "Cookie Reply", 4: "Transport Data"}
WIREGUARD_SIZES = {1: 148, 2: 92, 3: 64}


def _wireguard(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 32:
        return False
    mtype = payload[0]
    if mtype not in WIREGUARD_TYPES:
        return False
    if mtype in WIREGUARD_SIZES and len(payload) != WIREGUARD_SIZES[mtype]:
        return False
    name = WIREGUARD_TYPES[mtype]
    detail = [("Message Type", f"{mtype} ({name})"), ("Length", len(payload))]
    if mtype == 4:
        detail.append(("Receiver Index", int.from_bytes(payload[4:8], "little")))
        detail.append(("Counter", int.from_bytes(payload[8:16], "little")))
        info = "WireGuard Transport Data"
    else:
        sender_index = int.from_bytes(payload[4:8], "little")
        detail.append(("Sender Index", sender_index))
        info = f"WireGuard {name}"

    pkt["proto"], pkt["color"] = "WireGuard", "wireguard"
    pkt["layers"].add("wireguard")
    fields.update({"wireguard.type": mtype, "wireguard.type.name": name})
    nodes.append(_node("WireGuard VPN", [_it(k, v) for k, v in detail]))
    pkt["info"] = info
    return True


def _rtp(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 12:
        return False
    first = payload[0]
    version = first >> 6
    if version != 2:
        return False
    padding, extension, csrc_count = (first >> 5) & 1, (first >> 4) & 1, first & 0x0F
    marker, payload_type = (payload[1] >> 7) & 1, payload[1] & 0x7F
    seq = struct.unpack("!H", payload[2:4])[0]
    timestamp = struct.unpack("!I", payload[4:8])[0]
    ssrc = struct.unpack("!I", payload[8:12])[0]
    header_len = 12 + csrc_count * 4
    if len(payload) < header_len:
        return False

    pkt["proto"], pkt["color"] = "RTP", "rtp"
    pkt["layers"].add("rtp")
    fields.update({"rtp.version": version, "rtp.payload_type": payload_type,
                   "rtp.seq": seq, "rtp.timestamp": timestamp, "rtp.ssrc": ssrc})
    nodes.append(_node(
        "Real-time Transport Protocol",
        [_it("Version", version), _it("Padding", padding), _it("Extension", extension),
         _it("CSRC Count", csrc_count), _it("Marker", marker),
         _it("Payload Type", payload_type), _it("Sequence", seq),
         _it("Timestamp", timestamp), _it("SSRC", ssrc)],
    ))
    pkt["info"] = f"RTP PT={payload_type} seq={seq} ts={timestamp} ssrc=0x{ssrc:08x}"
    return True


QUIC_VERSIONS = {
    0x00000001: "QUIC v1", 0x6B3343CF: "QUIC v2", 0xFF00001D: "draft-29",
    0xFF00001B: "draft-27", 0xFF00001C: "draft-28", 0xFF00001E: "draft-30",
}


def _quic(payload: bytes, pkt: dict, fields: dict, nodes: list) -> bool:
    if len(payload) < 7:
        return False
    first = payload[0]
    long_header = bool(first & 0x80)
    fixed = bool(first & 0x40)
    if not fixed:
        return False
    if long_header:
        version = struct.unpack("!I", payload[1:5])[0]
        version_text = QUIC_VERSIONS.get(version, f"0x{version:08x}")
        pos = 5
        dcid_len = payload[pos]
        pos += 1
        if dcid_len > 20 or pos + dcid_len + 1 > len(payload):
            return False
        dcid = payload[pos : pos + dcid_len].hex()
        pos += dcid_len
        scid_len = payload[pos]
        pos += 1
        if scid_len > 20 or pos + scid_len > len(payload):
            return False
        scid = payload[pos : pos + scid_len].hex()
        pkt_type = (first >> 4) & 0x03
        type_name = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get(pkt_type, str(pkt_type))
        detail = [("Version", version_text), ("Packet Type", type_name),
                  ("Destination CID", dcid or "-"), ("Source CID", scid or "-")]
        info = f"QUIC {type_name} {version_text}"
    else:
        dcid = payload[1:9].hex()
        detail = [("Packet Type", "1-RTT (short header)"), ("Destination CID", dcid or "-")]
        info = "QUIC 1-RTT"
        version = 0

    pkt["proto"], pkt["color"] = "QUIC", "quic"
    pkt["layers"].add("quic")
    fields.update({"quic.long_header": long_header, "quic.version": version})
    nodes.append(_node("QUIC (HTTP/3 transport)", [_it(k, v) for k, v in detail]))
    pkt["info"] = info
    return True
