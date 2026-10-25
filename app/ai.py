"""AI 辅助分析：把协议字段和载荷交给大模型做启发式解读。

注意：AI 不能破解 TLS/AES 等现代加密，只能做协议识别、编码解码、
弱加密猜测和可读信息提取。对 TLS 主体密文，AI 只会说明哪些是可见的
（握手、SNI、证书），哪些无法解密。
"""

from __future__ import annotations

import base64
import json
import os
import urllib.request
import urllib.error

BLOCKRUN_URL = "https://blockrun.ai/api/v1/chat/completions"
MODEL = "gpt-oss-20b"
TIMEOUT = 60
MAX_PAYLOAD_BYTES = 2048

SYSTEM_PROMPT = """你是网络协议分析专家。
严格遵守以下输出规则：
1. 直接输出最终结论，绝对不要包含思考过程、推理过程、"让我分析"、"we need"、"let's parse" 等内容
2. 第一行：一句话结论（协议类型 + 用途）
3. 然后用 1-3 个要点说明关键信息（命令、参数、token、域名等）
4. 如果载荷有可读文本，直接引用关键片段
5. 如果是 TLS/加密流量，说明可见部分（SNI、握手、证书）和不可见部分（应用数据密文）
6. 不要声称能破解 AES/TLS/RSA
7. 中文回答，控制在 200 字以内
8. 不要重复，不要逐字节解释"""


def _build_prompt(packet: dict) -> str:
    proto = packet.get("proto", "?")
    src = packet.get("src", "?")
    dst = packet.get("dst", "?")
    info = packet.get("info", "")
    fields = packet.get("fields", {}) or {}

    # 把关键字段列出来
    field_lines = []
    for key in sorted(fields.keys()):
        val = fields[key]
        if isinstance(val, (dict, list)):
            continue
        field_lines.append(f"{key}: {val}")
    field_str = "\n".join(field_lines) or "(无结构化字段)"

    # 取载荷 hex + 可读预览
    raw_data = packet.get("data", b"")
    if isinstance(raw_data, str):
        try:
            raw = base64.b64decode(raw_data)
        except Exception:
            raw = raw_data.encode("latin-1", "replace")
    else:
        raw = bytes(raw_data)
    payload_preview = packet.get("payloadPreview", "") or ""
    if raw:
        hex_str = raw[:MAX_PAYLOAD_BYTES].hex()
        try:
            text = raw[:MAX_PAYLOAD_BYTES].decode("latin-1", "replace")
        except Exception:
            text = payload_preview[:MAX_PAYLOAD_BYTES]
    else:
        hex_str = ""
        text = payload_preview[:MAX_PAYLOAD_BYTES]

    return (
        f"数据包信息：\n"
        f"协议: {proto}\n"
        f"源: {src}\n"
        f"目的: {dst}\n"
        f"摘要: {info}\n\n"
        f"已解析字段：\n{field_str}\n\n"
        f"载荷文本预览：\n{text[:1000]}\n\n"
        f"载荷 hex（前 {MAX_PAYLOAD_BYTES} 字节）：\n{hex_str[:4000]}\n"
    )


def analyze(packet: dict) -> str:
    """调用 BlockRun 免费 API 分析单个数据包。"""
    user_prompt = _build_prompt(packet)
    payload = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 512,
        "temperature": 0.2,
    }).encode("utf-8")

    req = urllib.request.Request(
        BLOCKRUN_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        return f"AI 接口错误（HTTP {exc.code}）：{detail}"
    except Exception as exc:  # noqa: BLE001
        return f"AI 分析失败：{type(exc).__name__}: {exc}"
