"""M87 后端入口：REST API + 实时 WebSocket + 静态前端。"""

from __future__ import annotations

import asyncio
import base64
import io
import os
import time
import urllib.parse

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import ai, capture, filters, guard, pcapfile, tools
from .capture import manager

BASE_DIR = capture.BASE_DIR
WEB_DIR = os.path.join(BASE_DIR, "web")
MAX_IMPORT_BYTES = 256 * 1024 * 1024

app = FastAPI(title="M87 网络抓包工具", version="1.1.0", docs_url=None, redoc_url=None)
guard.install(app)


class CreateSessionRequest(BaseModel):
    interface: str = "demo"
    name: str | None = None
    kind: str | None = None
    snaplen: int = 262144


class ProbeBatchRequest(BaseModel):
    urls: list[str]


class PackageRequest(BaseModel):
    items: list[dict]
    filename: str = "resources"


class DeepExtractRequest(BaseModel):
    url: str
    depth: int = 2
    max_pages: int = 25


@app.on_event("startup")
async def _startup() -> None:
    manager.load_existing()
    if not manager.sessions:
        manager.create("演示抓包 demo0", "demo", kind="demo", auto_start=True)


@app.get("/api/status")
async def api_status() -> dict:
    sessions = manager.list()
    return {
        "app": "M87",
        "version": "1.1.0",
        "privileged": hasattr(os, "geteuid") and os.geteuid() == 0,
        "sessions": len(sessions),
        "packets": sum(s["packets"] for s in sessions),
        "serverTime": time.time(),
        "platform": os.uname().sysname if hasattr(os, "uname") else "unknown",
    }


@app.get("/api/docs", include_in_schema=False)
async def api_docs() -> FileResponse:
    """离线 API 参考页，不依赖任何外部 CDN。"""
    return FileResponse(os.path.join(WEB_DIR, "api.html"))


@app.get("/api/interfaces")
async def api_interfaces() -> dict:
    return {"interfaces": capture.list_interfaces()}


@app.get("/api/sessions")
async def api_sessions() -> dict:
    return {"sessions": manager.list()}


@app.post("/api/sessions")
async def api_create_session(payload: CreateSessionRequest) -> dict:
    interface = payload.interface or "demo"
    kind = payload.kind or ("demo" if interface == "demo" else "live")
    if kind not in ("live", "demo"):
        raise HTTPException(400, "不支持的会话类型")
    if kind == "live":
        if not interface:
            raise HTTPException(400, "请选择网卡")
        try:
            available = {item["name"] for item in capture.list_interfaces()}
        except OSError:
            available = set()
        if available and interface not in available:
            raise HTTPException(400, f"网卡不存在：{interface}")
    name = payload.name or (
        "演示抓包" if kind == "demo" else f"{interface} 抓包"
    )
    snaplen = max(64, min(int(payload.snaplen or 262144), 262144))
    session = manager.create(name, interface, kind=kind, snaplen=snaplen, auto_start=True)
    if session.status == "error":
        return JSONResponse(status_code=500, content={"message": session.error, "session": session.summary()})
    return {"session": session.summary()}


@app.get("/api/sessions/{sid}")
async def api_session(sid: str) -> dict:
    session = _session_or_404(sid)
    return {"session": session.summary()}


@app.post("/api/sessions/{sid}/stop")
async def api_stop(sid: str) -> dict:
    session = _session_or_404(sid)
    return {"session": session.stop()}


@app.delete("/api/sessions/{sid}")
async def api_delete(sid: str) -> dict:
    if not manager.delete(sid):
        raise HTTPException(404, "会话不存在")
    return {"ok": True}


@app.get("/api/sessions/{sid}/packets")
async def api_packets(sid: str, offset: int = 0, limit: int = 500,
                      filter: str = Query("", alias="filter"), tail: bool = False) -> dict:
    session = _session_or_404(sid)
    try:
        return session.page(offset, limit, filter, tail)
    except filters.FilterError as exc:
        raise HTTPException(400, f"过滤器语法错误：{exc}") from exc


@app.get("/api/sessions/{sid}/packets/{num}")
async def api_packet_detail(sid: str, num: int) -> dict:
    session = _session_or_404(sid)
    detail = session.detail(num)
    if detail is None:
        raise HTTPException(404, "数据包不在内存中")
    detail["data"] = base64.b64encode(detail["data"]).decode("ascii")
    detail["payloadPreview"] = detail["payloadPreview"][:2000]
    return detail


@app.get("/api/sessions/{sid}/stats")
async def api_stats(sid: str) -> dict:
    return _session_or_404(sid).stats()


@app.get("/api/sessions/{sid}/follow/{num}")
async def api_follow(sid: str, num: int) -> dict:
    session = _session_or_404(sid)
    result = session.follow(num)
    if result is None:
        raise HTTPException(404, "该数据包不属于可重组的 TCP 流")
    for seg in result["segments"]:
        seg["text"] = seg["text"][:20000]
        seg.pop("bytes", None)
    return result


@app.get("/api/sessions/{sid}/export")
async def api_export(sid: str, filter: str = "") -> Response:
    session = _session_or_404(sid)
    try:
        content, filename = session.export(filter)
    except filters.FilterError as exc:
        raise HTTPException(400, f"过滤器语法错误：{exc}") from exc
    safe = urllib.parse.quote(filename)
    return Response(
        content=content,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f"attachment; filename=\"capture.pcap\"; filename*=UTF-8''{safe}",
            "X-Packet-Count": str(session.total),
        },
    )


@app.post("/api/import")
async def api_import(request: Request) -> dict:
    body = await request.body()
    if not body:
        raise HTTPException(400, "上传内容为空")
    if len(body) > MAX_IMPORT_BYTES:
        raise HTTPException(413, "文件过大（上限 256MB）")
    filename = urllib.parse.unquote(request.headers.get("x-filename", "imported.pcap"))
    try:
        session = manager.import_file(filename, body)
    except pcapfile.PcapError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"session": session.summary()}


@app.websocket("/ws/sessions/{sid}")
async def ws_packets(websocket: WebSocket, sid: str, since: int = 0, filter: str = "") -> None:
    if not guard.allow_ws(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    session = manager.get(sid)
    if session is None:
        await websocket.send_json({"type": "error", "message": "会话不存在"})
        await websocket.close()
        return
    try:
        session.get_compiled_filter(filter)
    except filters.FilterError as exc:
        await websocket.send_json({"type": "error", "message": f"过滤器语法错误：{exc}"})
        await websocket.close()
        return

    last = max(since, 0)
    idle = 0
    try:
        while True:
            await asyncio.sleep(0.12)
            fresh = session.since(last, filter, limit=800)
            if fresh:
                last = fresh[-1]["num"]
                idle = 0
                await websocket.send_json({"type": "packets", "packets": fresh})
                continue
            idle += 1
            if idle % 12 == 0:
                await websocket.send_json({
                    "type": "status", "status": session.status,
                    "captured": session.total, "error": session.error,
                })
            if session.status in ("stopped", "error") and idle >= 2:
                await websocket.send_json({
                    "type": "status", "status": session.status,
                    "captured": session.total, "error": session.error,
                })
                break
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass
    except Exception:
        pass


class AIAnalyzeRequest(BaseModel):
    sid: str
    num: int


@app.post("/api/ai/analyze")
async def api_ai_analyze(payload: AIAnalyzeRequest) -> dict:
    session = _session_or_404(payload.sid)
    detail = session.detail(payload.num)
    if detail is None:
        raise HTTPException(404, "数据包不在内存中")
    detail["payloadPreview"] = detail.get("payloadPreview", "")[:4096]
    result = await asyncio.to_thread(ai.analyze, detail)
    return {"analysis": result}


# ---------------------------------------------------------------- 网站工具箱

@app.get("/api/tools/probe")
async def api_tool_probe(url: str) -> dict:
    try:
        return await asyncio.to_thread(tools.probe, url)
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"{type(exc).__name__}: {exc}") from exc


@app.post("/api/tools/probe-batch")
async def api_tool_probe_batch(payload: ProbeBatchRequest) -> dict:
    try:
        return await asyncio.to_thread(tools.probe_many, payload.urls)
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/tools/extract")
async def api_tool_extract(url: str, html: bool = True) -> dict:
    try:
        return await asyncio.to_thread(tools.extract, url, html)
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"{type(exc).__name__}: {exc}") from exc


@app.post("/api/tools/deep-extract")
async def api_tool_deep_extract(payload: DeepExtractRequest) -> dict:
    """顺藤摸瓜：递归抓取同域内链，汇总所有页面的资源。"""
    try:
        return await asyncio.to_thread(
            tools.deep_extract, payload.url, payload.depth, payload.max_pages
        )
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"{type(exc).__name__}: {exc}") from exc


@app.get("/api/tools/dns")
async def api_tool_dns(url: str, type: str = "ALL", resolver: str = "alidns") -> dict:
    try:
        return await asyncio.to_thread(tools.dns_lookup, url, type, resolver)
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"{type(exc).__name__}: {exc}") from exc


@app.post("/api/tools/package")
async def api_tool_package(payload: PackageRequest) -> StreamingResponse:
    try:
        content, filename = await asyncio.to_thread(
            tools.package_resources, payload.items, payload.filename
        )
    except tools.ToolError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"{type(exc).__name__}: {exc}") from exc
    quoted = urllib.parse.quote(filename)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=\"resources.zip\"; filename*=UTF-8''{quoted}",
            "Content-Length": str(len(content)),
        },
    )


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


def _session_or_404(sid: str) -> capture.Session:
    session = manager.get(sid)
    if session is None:
        raise HTTPException(404, "会话不存在")
    return session
