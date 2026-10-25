"""pcap / pcapng 文件读写（纯标准库实现，无第三方依赖）。

导出的文件就是标准 pcap，可直接用 Wireshark / tcpdump 打开，
也可以用本工具的「导入」功能重新载入分析。
"""

from __future__ import annotations

import struct
from typing import BinaryIO, Iterable

MAGIC_USEC_LE = 0xA1B2C3D4
MAGIC_NSEC_LE = 0xA1B23C4D
MAGIC_PCAPNG = 0x0A0D0D0A


class PcapError(Exception):
    pass


# ---------------------------------------------------------------- 写入 pcap

def write_header(fh: BinaryIO, linktype: int = 1, snaplen: int = 262144) -> None:
    fh.write(struct.pack("<IHHiIII", MAGIC_USEC_LE, 2, 4, 0, 0, snaplen, linktype))


def write_record(
    fh: BinaryIO,
    ts: float,
    data: bytes,
    orig_len: int | None = None,
    caplen: int | None = None,
) -> None:
    sec = int(ts)
    usec = int(round((ts - sec) * 1_000_000))
    if usec >= 1_000_000:
        sec += 1
        usec = 0
    if usec < 0:
        usec = 0
    caplen = len(data) if caplen is None else caplen
    orig_len = caplen if orig_len is None else orig_len
    fh.write(struct.pack("<IIII", sec, usec, caplen, orig_len))
    fh.write(data)


def build_pcap(records: Iterable[tuple[float, bytes]], linktype: int = 1, snaplen: int = 262144) -> bytes:
    """把 (时间戳, 原始帧) 列表打包成 pcap 字节流。"""
    chunks = [struct.pack("<IHHiIII", MAGIC_USEC_LE, 2, 4, 0, 0, snaplen, linktype)]
    for ts, data in records:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec = 0
        chunks.append(struct.pack("<IIII", sec, usec, len(data), len(data)))
        chunks.append(data)
    return b"".join(chunks)


# ---------------------------------------------------------------- 读取 pcap

def sniff_linktype(head: bytes) -> int | None:
    """根据文件头判断 linktype；返回 None 表示不是可识别的抓包文件。"""
    if len(head) < 12:
        return None
    magic = struct.unpack("<I", head[:4])[0]
    if magic == MAGIC_PCAPNG:
        return _pcapng_first_linktype(head)
    if magic in (MAGIC_USEC_LE, MAGIC_NSEC_LE):
        # pcap 小端
        return struct.unpack("<I", head[20:24])[0]
    if struct.unpack(">I", head[:4])[0] in (MAGIC_USEC_LE, MAGIC_NSEC_LE):
        return struct.unpack(">I", head[20:24])[0]
    return None


def _pcapng_first_linktype(head: bytes) -> int | None:
    offset = 0
    while offset + 12 <= len(head):
        block_type, block_len = struct.unpack("<II", head[offset : offset + 8])
        if block_type == 1 and block_len >= 20:  # IDB
            return struct.unpack("<H", head[offset + 8 : offset + 10])[0]
        if block_len < 12:
            break
        offset += block_len
    return None


def read_capture(data: bytes) -> tuple[int, list[tuple[float, bytes]]]:
    """解析 pcap 或 pcapng 内容，返回 (linktype, [(ts, frame), ...])。"""
    if len(data) < 12:
        raise PcapError("文件太小，不是有效的抓包文件")
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MAGIC_PCAPNG:
        return _read_pcapng(data)
    if magic in (MAGIC_USEC_LE, MAGIC_NSEC_LE):
        return _read_pcap(data, "<")
    if struct.unpack(">I", data[:4])[0] in (MAGIC_USEC_LE, MAGIC_NSEC_LE):
        return _read_pcap(data, ">")
    raise PcapError("无法识别的文件格式（需要 .pcap 或 .pcapng）")


def _read_pcap(data: bytes, endian: str) -> tuple[int, list[tuple[float, bytes]]]:
    if len(data) < 24:
        raise PcapError("pcap 文件头不完整")
    _, vmaj, vmin, _, _, snaplen, linktype = struct.unpack(endian + "IHHiIII", data[:24])
    nano = struct.unpack(endian + "I", data[:4])[0] == MAGIC_NSEC_LE
    pos = 24
    out: list[tuple[float, bytes]] = []
    while pos + 16 <= len(data):
        sec, frac, caplen, _orig = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        if caplen > len(data) - pos:
            break
        frame = data[pos : pos + caplen]
        pos += caplen
        ts = sec + (frac / 1e9 if nano else frac / 1e6)
        out.append((ts, frame))
    return linktype, out


def _read_pcapng(data: bytes) -> tuple[int, list[tuple[float, bytes]]]:
    pos = 0
    interfaces: list[dict] = []
    out: list[tuple[float, bytes]] = []
    while pos + 12 <= len(data):
        block_type, block_len = struct.unpack("<II", data[pos : pos + 8])
        if block_len < 12 or pos + block_len > len(data):
            break
        body = data[pos + 8 : pos + block_len - 4]
        if block_type == 1:  # Interface Description Block
            linktype = struct.unpack("<H", body[:2])[0]
            snaplen = struct.unpack("<I", body[4:8])[0] if len(body) >= 8 else 0
            interfaces.append({"linktype": linktype, "snaplen": snaplen, "tsresol": 6})
        elif block_type == 6:  # Enhanced Packet Block
            if len(body) >= 20:
                iface_id, tsh, tsl, caplen, origlen = struct.unpack("<IIIII", body[:20])
                frame = body[20 : 20 + caplen]
                iface = interfaces[iface_id] if iface_id < len(interfaces) else {"linktype": 1, "tsresol": 6}
                ts = ((tsh << 32) | tsl) / (10 ** iface.get("tsresol", 6))
                out.append((ts, frame))
        elif block_type == 3:  # Simple Packet Block
            if len(body) >= 4:
                origlen = struct.unpack("<I", body[:4])[0]
                frame = body[4 : 4 + origlen]
                out.append((0.0, frame))
        elif block_type == 2:  # obsolete Packet Block
            if len(body) >= 20:
                iface_id, _drops, tsh, tsl, caplen, origlen = struct.unpack("<HHIIII", body[:20])
                frame = body[20 : 20 + caplen]
                out.append((((tsh << 32) | tsl) / 1e6, frame))
        pos += block_len
    linktype = interfaces[0]["linktype"] if interfaces else 1
    return linktype, out
