"""抓包会话管理：真实网卡抓包、演示流量、pcap 导入导出、统计与流重组。"""

from __future__ import annotations

import json
import os
import random
import socket
import struct
import threading
import time
import uuid

from . import build, decode, filters, pcapfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
SESSIONS_DIR = os.path.join(DATA_DIR, "sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

MAX_MEMORY_PACKETS = 200_000


# ---------------------------------------------------------------- 网卡信息

def _read(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return default


def _iface_ipv4(name: str) -> str | None:
    try:
        import fcntl
    except ImportError:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _iface_netmask(name: str) -> str | None:
    try:
        import fcntl
    except ImportError:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = fcntl.ioctl(sock.fileno(), 0x891B, struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def list_interfaces() -> list[dict]:
    """列出本机网卡及地址、状态、累计流量。"""
    try:
        names = sorted({name for _, name in socket.if_nameindex()})
    except OSError:
        names = []

    ipv6_map: dict[str, list[str]] = {}
    for line in _read("/proc/net/if_inet6").splitlines():
        parts = line.split()
        if len(parts) == 6:
            addr = ":".join(parts[0][i : i + 4] for i in range(0, 32, 4))
            try:
                addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(parts[0]))
            except OSError:
                pass
            ipv6_map.setdefault(parts[5], []).append(addr)

    result = []
    for name in names:
        stat_base = f"/sys/class/net/{name}/statistics"
        result.append({
            "name": name,
            "mac": _read(f"/sys/class/net/{name}/address", "-"),
            "state": _read(f"/sys/class/net/{name}/operstate", "unknown"),
            "ipv4": _iface_ipv4(name),
            "netmask": _iface_netmask(name),
            "ipv6": ipv6_map.get(name, []),
            "rxBytes": int(_read(f"{stat_base}/rx_bytes", "0") or 0),
            "txBytes": int(_read(f"{stat_base}/tx_bytes", "0") or 0),
            "rxPackets": int(_read(f"{stat_base}/rx_packets", "0") or 0),
            "txPackets": int(_read(f"{stat_base}/tx_packets", "0") or 0),
        })
    return result


# ---------------------------------------------------------------- 会话

class Session:
    def __init__(self, sid: str, name: str, interface: str = "demo", kind: str = "live",
                 linktype: int = 1, snaplen: int = 262144):
        self.id = sid
        self.name = name
        self.interface = interface
        self.kind = kind                 # live | demo | file
        self.linktype = linktype
        self.snaplen = snaplen
        self.status = "stopped" if kind == "file" else "idle"
        self.error: str | None = None
        self.created_at = time.time()
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.total = 0
        self.bytes_total = 0
        self.packets: list[dict] = []
        self.lock = threading.RLock()
        self.stop_evt = threading.Event()
        self.thread: threading.Thread | None = None
        self.path = os.path.join(SESSIONS_DIR, f"{sid}.pcap")
        self._fh = None
        self._stream_ids: dict[tuple, int] = {}
        self._filter_cache: tuple[str, object] | None = None

    # ------------------------------ 生命周期

    def start(self) -> None:
        with self.lock:
            if self.status in ("capturing", "starting"):
                return
            self.status = "starting"
            self.error = None
            self.created_at = self.created_at if self.total else time.time()
            self.started_at = time.time()
            self.stopped_at = None
            self.stop_evt.clear()
            self._fh = open(self.path, "wb")
            pcapfile.write_header(self._fh, self.linktype, self.snaplen)
        target = self._demo_loop if self.kind == "demo" else self._live_loop
        self.thread = threading.Thread(target=target, daemon=True, name=f"capture-{self.id}")
        self.thread.start()

    def stop(self) -> dict:
        self.stop_evt.set()
        thread = self.thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3)
        if self.status in ("starting", "capturing"):
            self._finish("stopped")
        return self.summary()

    def _finish(self, status: str) -> None:
        with self.lock:
            if self._fh is not None:
                try:
                    self._fh.flush()
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
            self.status = status
            self.stopped_at = time.time()
        _save_meta(self)

    def _set_status(self, status: str) -> None:
        with self.lock:
            if self.status not in ("stopped", "error"):
                self.status = status

    # ------------------------------ 抓包线程

    def _live_loop(self) -> None:
        sock = None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.interface, 0))
            try:  # 尽量开启混杂模式（需要权限，失败不影响）
                mreq = struct.pack("IHH8s", socket.if_nametoindex(self.interface), 1, 0, b"\x00" * 8)
                sock.setsockopt(263, 1, mreq)  # SOL_PACKET, PACKET_ADD_MEMBERSHIP
            except OSError:
                pass
            sock.settimeout(0.5)
            self._set_status("capturing")
            while not self.stop_evt.is_set():
                try:
                    data = sock.recv(self.snaplen)
                except socket.timeout:
                    continue
                if not data:
                    continue
                self.add_packet(data, time.time())
        except Exception as exc:
            self.error = _friendly_error(exc, self.interface)
            self._finish("error")
            return
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._finish("stopped")

    def _demo_loop(self) -> None:
        rng = random.Random()
        ident = random.randint(1, 500)
        self._set_status("capturing")
        try:
            while not self.stop_evt.is_set():
                frames = build.build_demo_batch(rng, ident)
                ident += 64
                for frame in frames:
                    if self.stop_evt.is_set():
                        break
                    self.add_packet(frame, time.time())
                    time.sleep(rng.uniform(0.02, 0.10))
                time.sleep(rng.uniform(0.2, 0.6))
        finally:
            self._finish("stopped")

    # ------------------------------ 收包

    def add_packet(self, data: bytes, ts: float) -> None:
        with self.lock:
            self.total += 1
            num = self.total
            try:
                pkt = decode.decode_packet(data, num, ts, self.linktype)
            except Exception as exc:  # 理论上不会发生，兜底保护
                pkt = {
                    "num": num, "ts": ts, "len": len(data), "caplen": len(data),
                    "src": "-", "dst": "-", "proto": "ERROR", "color": "error",
                    "info": f"解码失败: {exc}", "layers": set(), "fields": {},
                    "tree": [], "data": data,
                }
            stream = self._stream_id(pkt)
            if stream is not None:
                pkt["stream"] = stream
                pkt["fields"]["tcp.stream"] = stream
            self.bytes_total += len(data)
            if self._fh is not None:
                try:
                    pcapfile.write_record(self._fh, ts, data)
                except OSError as exc:
                    self.error = f"写入 pcap 失败: {exc}"
            if len(self.packets) < MAX_MEMORY_PACKETS:
                self.packets.append(pkt)

    def _stream_id(self, pkt: dict) -> int | None:
        key = pkt.get("tcp_key")
        if not key:
            return None
        sid = self._stream_ids.get(key)
        if sid is None:
            sid = len(self._stream_ids)
            self._stream_ids[key] = sid
        return sid

    # ------------------------------ 查询

    def summary(self) -> dict:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            size = 0
        duration = 0.0
        if self.started_at:
            duration = max((self.stopped_at or time.time()) - self.started_at, 0.0)
        return {
            "id": self.id,
            "name": self.name,
            "interface": self.interface,
            "kind": self.kind,
            "status": self.status,
            "createdAt": self.created_at,
            "startedAt": self.started_at,
            "stoppedAt": self.stopped_at,
            "packets": self.total,
            "bytes": self.bytes_total,
            "stored": len(self.packets),
            "duration": round(duration, 2),
            "error": self.error,
            "linktype": self.linktype,
            "fileSize": size,
        }

    def get_compiled_filter(self, text: str):
        if self._filter_cache and self._filter_cache[0] == text:
            return self._filter_cache[1]
        fn = filters.compile_filter(text)
        self._filter_cache = (text, fn)
        return fn

    def page(self, offset: int, limit: int, filter_text: str = "", tail: bool = False) -> dict:
        fn = self.get_compiled_filter(filter_text)
        with self.lock:
            snapshot = list(self.packets)
        if fn is None:
            matched = snapshot
        else:
            matched = [p for p in snapshot if fn(p)]
        total = len(matched)
        limit = min(max(limit, 1), 2000)
        offset = max(total - limit, 0) if tail else max(offset, 0)
        return {
            "total": total,
            "offset": offset,
            "packets": [_compact(p) for p in matched[offset : offset + limit]],
            "captured": self.total,
            "truncated": self.total > len(self.packets),
        }

    def since(self, last_num: int, filter_text: str = "", limit: int = 500) -> list[dict]:
        fn = self.get_compiled_filter(filter_text)
        with self.lock:
            fresh = [p for p in self.packets if p["num"] > last_num]
        out = []
        for pkt in fresh:
            if fn is not None and not fn(pkt):
                continue
            out.append(_compact(pkt))
            if len(out) >= limit:
                break
        return out

    def latest_num(self) -> int:
        with self.lock:
            return self.total

    def detail(self, num: int) -> dict | None:
        with self.lock:
            index = num - 1
            if index < 0 or index >= len(self.packets):
                return None
            pkt = self.packets[index]
            if pkt["num"] != num:
                for cand in self.packets:
                    if cand["num"] == num:
                        pkt = cand
                        break
                else:
                    return None
            payload = pkt.get("tcp_payload", b"")
            return {
                "num": pkt["num"],
                "ts": pkt["ts"],
                "len": pkt["len"],
                "src": pkt["src"],
                "dst": pkt["dst"],
                "proto": pkt["proto"],
                "color": pkt["color"],
                "info": pkt["info"],
                "tree": pkt["tree"],
                "fields": pkt["fields"],
                "data": bytes(pkt["data"]),
                "stream": pkt.get("stream"),
                "streamKey": list(pkt["tcp_key"]) if pkt.get("tcp_key") else None,
                "payloadPreview": payload[:4096].decode("latin-1", "replace"),
            }

    def export(self, filter_text: str = "") -> tuple[bytes, str]:
        fn = self.get_compiled_filter(filter_text)
        if fn is None and self.total == len(self.packets) and os.path.exists(self.path):
            with open(self.path, "rb") as fh:
                return fh.read(), f"{self.name}.pcap"
        records = []
        with self.lock:
            for pkt in self.packets:
                if fn is not None and not fn(pkt):
                    continue
                records.append((pkt["ts"], pkt["data"]))
        return pcapfile.build_pcap(records, self.linktype, self.snaplen), f"{self.name}.pcap"

    def stats(self) -> dict:
        with self.lock:
            snapshot = list(self.packets)
        if not snapshot:
            return {"total": 0, "bytes": 0, "duration": 0, "pps": 0,
                    "protocols": [], "talkers": [], "conversations": [],
                    "timeline": [], "streams": 0}
        total = len(snapshot)
        byte_total = sum(p["len"] for p in snapshot)
        tmin = snapshot[0]["ts"]
        tmax = snapshot[-1]["ts"]
        duration = max(tmax - tmin, 0.001)
        protocols: dict[str, dict] = {}
        talkers: dict[str, dict] = {}
        conversations: dict[tuple, dict] = {}
        for pkt in snapshot:
            proto = pkt["proto"]
            entry = protocols.setdefault(proto, {"name": proto, "count": 0, "bytes": 0, "color": pkt["color"]})
            entry["count"] += 1
            entry["bytes"] += pkt["len"]
            for addr in (pkt["src"], pkt["dst"]):
                if _is_ip(addr):
                    t = talkers.setdefault(addr, {"addr": addr, "packets": 0, "bytes": 0})
                    t["packets"] += 1
                    t["bytes"] += pkt["len"]
        with self.lock:
            stream_count = len(self._stream_ids)
        key_counts: dict[tuple, dict] = {}
        for pkt in snapshot:
            key = pkt.get("tcp_key")
            if not key:
                continue
            conv_key = tuple(key)
            conv = key_counts.setdefault(conv_key, {
                "endpointA": f"{key[0][0]}:{key[0][1]}",
                "endpointB": f"{key[1][0]}:{key[1][1]}",
                "proto": pkt["proto"], "packets": 0, "bytes": 0, "stream": pkt.get("stream"),
            })
            conv["packets"] += 1
            conv["bytes"] += pkt["len"]
        conversations = list(key_counts.values())

        bins = min(max(int(duration) + 1, 10), 120)
        width = duration / bins
        timeline = [{"t": tmin + i * width, "packets": 0, "bytes": 0} for i in range(bins)]
        for pkt in snapshot:
            idx = min(int((pkt["ts"] - tmin) / width), bins - 1)
            if idx < 0:
                idx = 0
            timeline[idx]["packets"] += 1
            timeline[idx]["bytes"] += pkt["len"]

        return {
            "total": total,
            "bytes": byte_total,
            "duration": round(duration, 3),
            "pps": round(total / duration, 1),
            "streams": stream_count,
            "protocols": sorted(protocols.values(), key=lambda x: -x["count"]),
            "talkers": sorted(talkers.values(), key=lambda x: -x["packets"])[:15],
            "conversations": sorted(conversations, key=lambda x: -x["packets"])[:15],
            "timeline": timeline,
        }

    def follow(self, num: int, max_bytes: int = 262144) -> dict | None:
        with self.lock:
            target = next((p for p in self.packets if p["num"] == num), None)
            if target is None or not target.get("tcp_key"):
                return None
            key = target["tcp_key"]
            same = [p for p in self.packets if p.get("tcp_key") == key]
        segments = []
        used = 0
        for pkt in same:
            payload = pkt.get("tcp_payload", b"")
            if not payload:
                continue
            if used + len(payload) > max_bytes:
                payload = payload[: max(max_bytes - used, 0)]
            if not payload:
                break
            used += len(payload)
            text = payload.decode("utf-8", "replace")
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
            segments.append({
                "num": pkt["num"],
                "dir": pkt.get("tcp_dir", "a2b"),
                "length": len(payload),
                "text": text if printable / max(len(text), 1) > 0.8 else payload.hex(),
                "bytes": payload,
            })
        return {"endpoints": [f"{key[0][0]}:{key[0][1]}", f"{key[1][0]}:{key[1][1]}"],
                "segments": segments}


def _friendly_error(exc: Exception, iface: str) -> str:
    text = str(exc)
    if isinstance(exc, PermissionError) or "Operation not permitted" in text:
        return f"没有抓包权限（需要 root 或 CAP_NET_RAW）：{text}"
    if isinstance(exc, OSError) and "No such device" in text:
        return f"网卡不存在：{iface}"
    return f"{type(exc).__name__}: {text}"


def _is_ip(addr: str) -> bool:
    if not addr:
        return False
    if addr.count(".") == 3 and all(part.isdigit() for part in addr.split(".")):
        return True
    return ":" in addr and addr != "-"


def _compact(pkt: dict) -> dict:
    return {
        "num": pkt["num"],
        "ts": pkt["ts"],
        "src": pkt["src"],
        "dst": pkt["dst"],
        "proto": pkt["proto"],
        "color": pkt["color"],
        "len": pkt["len"],
        "info": pkt["info"],
        "sport": pkt.get("sport"),
        "dport": pkt.get("dport"),
        "stream": pkt.get("stream"),
    }


# ---------------------------------------------------------------- 元数据

def _meta_path(sid: str) -> str:
    return os.path.join(SESSIONS_DIR, f"{sid}.json")


def _save_meta(session: Session) -> None:
    try:
        with open(_meta_path(session.id), "w", encoding="utf-8") as fh:
            json.dump({
                "id": session.id,
                "name": session.name,
                "interface": session.interface,
                "kind": session.kind,
                "createdAt": session.created_at,
                "linktype": session.linktype,
                "snaplen": session.snaplen,
            }, fh, ensure_ascii=False)
    except OSError:
        pass


# ---------------------------------------------------------------- 会话管理器

class SessionManager:
    def __init__(self):
        self.sessions: dict[str, Session] = {}
        self.lock = threading.RLock()

    def create(self, name: str, interface: str, kind: str = "live", linktype: int = 1,
               snaplen: int = 262144, auto_start: bool = True) -> Session:
        sid = uuid.uuid4().hex[:12]
        session = Session(sid, name, interface, kind, linktype, snaplen)
        _save_meta(session)
        with self.lock:
            self.sessions[sid] = session
        if auto_start:
            session.start()
        return session

    def get(self, sid: str) -> Session | None:
        return self.sessions.get(sid)

    def list(self) -> list[dict]:
        with self.lock:
            sessions = sorted(self.sessions.values(), key=lambda s: -s.created_at)
        return [s.summary() for s in sessions]

    def delete(self, sid: str) -> bool:
        session = self.sessions.pop(sid, None)
        if session is None:
            return False
        session.stop()
        for path in (session.path, _meta_path(sid)):
            try:
                os.remove(path)
            except OSError:
                pass
        return True

    def import_file(self, filename: str, data: bytes) -> Session:
        linktype = pcapfile.sniff_linktype(data[:64])
        if linktype is None:
            raise pcapfile.PcapError("无法识别的抓包文件格式")
        linktype, records = pcapfile.read_capture(data)
        sid = uuid.uuid4().hex[:12]
        name = os.path.basename(filename or "imported.pcap")
        session = Session(sid, name, interface="文件导入", kind="file", linktype=linktype)
        session.status = "stopped"
        session.started_at = records[0][0] if records else time.time()
        session.stopped_at = records[-1][0] if records else time.time()
        with open(session.path, "wb") as fh:
            pcapfile.write_header(fh, linktype, session.snaplen)
            fh.write(b"")
        for ts, frame in records[:MAX_MEMORY_PACKETS]:
            session.add_packet(frame, ts)
        # 保证磁盘文件完整（add_packet 时 _fh 为 None，这里整体落盘）
        with open(session.path, "wb") as fh:
            pcapfile.write_header(fh, linktype, session.snaplen)
            for pkt in session.packets:
                pcapfile.write_record(fh, pkt["ts"], pkt["data"])
        session.total = len(session.packets)
        session.bytes_total = sum(p["len"] for p in session.packets)
        _save_meta(session)
        with self.lock:
            self.sessions[sid] = session
        return session

    def load_existing(self) -> None:
        """启动时把磁盘上的 pcap 会话恢复出来。"""
        try:
            files = [f for f in os.listdir(SESSIONS_DIR) if f.endswith(".pcap")]
        except OSError:
            return
        for filename in sorted(files):
            sid = filename[:-5]
            path = os.path.join(SESSIONS_DIR, filename)
            if sid in self.sessions or os.path.getsize(path) == 0:
                continue
            try:
                with open(path, "rb") as fh:
                    data = fh.read(64 * 1024 * 1024)
                linktype, records = pcapfile.read_capture(data)
            except Exception:
                continue
            meta = {}
            try:
                with open(_meta_path(sid), "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, json.JSONDecodeError):
                pass
            session = Session(
                sid,
                meta.get("name", filename),
                meta.get("interface", "文件导入"),
                "file",
                meta.get("linktype", linktype),
                meta.get("snaplen", 262144),
            )
            session.status = "stopped"
            session.created_at = meta.get("createdAt", os.path.getmtime(path))
            session.started_at = records[0][0] if records else None
            session.stopped_at = records[-1][0] if records else None
            for ts, frame in records[:MAX_MEMORY_PACKETS]:
                session.add_packet(frame, ts)
            session.total = len(session.packets)
            session.bytes_total = sum(p["len"] for p in session.packets)
            self.sessions[sid] = session


manager = SessionManager()
