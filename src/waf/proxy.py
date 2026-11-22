# -*- coding: utf-8 -*-
"""反向代理与请求解析层。

职责：
1. 把客户端请求完整拆成请求行、头部、查询串、body、cookie 五个可注入面；
2. 交给检测引擎做归一化匹配与异常评分；
3. 命中则本地返回 403 拦截页，未命中则转发到上游并原样回写响应。

HTTP 是文本协议，但同一个参数可以藏在五种位置、三种 body 编码里。
如果 WAF 只检查 URL 查询串，那么把 Payload 放进 JSON body 或 cookie 就能绕过，
因此解析层必须先把所有位置穷举出来。
"""

import http.client
import json
import re
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qsl, urlsplit

from . import config
from .logger import get_logger
from .rules_engine import Engine

# 不参与检测的头，都是协议自身字段，检测它们只会增加误报。
# Cookie 头单独排除：cookie 已解析成键值对逐个检测，再检测原始头会重复计分，
# 实测会把 20 分放大到 40 分，影响阈值判断。
_SKIP_HEADERS = {
    "host", "content-length", "connection", "accept-encoding",
    "keep-alive", "transfer-encoding", "te", "upgrade", "cookie",
}

# 进程内单例：规则只加载一次，所有连接共享
_ENGINE = None


def get_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = Engine()
        print(f"[WAF] 规则加载完成，共 {len(_ENGINE.ruleset.all())} 条")
    return _ENGINE


class ReqContext:
    """一次 HTTP 请求的结构化表示。"""

    def __init__(self, method, raw_path, headers, body, client_ip, http_version):
        self.method = method
        self.raw_path = raw_path
        self.headers = headers            # 原样头名与值组成的列表，保留重复头
        self.body = body or b""
        self.client_ip = client_ip
        self.http_version = http_version

        parts = urlsplit(raw_path)
        self.path = parts.path or "/"
        self.query = parts.query
        self.query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        self.cookies = self._parse_cookies()

    # ---- 解析 ----
    def _header(self, name: str) -> str:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return ""

    def _parse_cookies(self):
        raw = self._header("cookie")
        if not raw:
            return {}
        # 先用标准库解析，它能处理带引号的值，再用人工切分兜底。
        # 实测：SimpleCookie 遇到 `id=1 union select 1,2` 这类含空格的非法值会
        # 静默返回空字典而不抛异常，只靠它会把攻击 Payload 整个漏掉。
        parsed = {}
        jar = SimpleCookie()
        try:
            jar.load(raw)
            parsed = {k: morsel.value for k, morsel in jar.items()}
        except Exception:
            parsed = {}
        for item in raw.split(";"):
            if "=" not in item:
                continue
            key, _, value = item.partition("=")
            key = key.strip()
            if key and key not in parsed:
                parsed[key] = value.strip().strip('"')
        return parsed

    def body_text(self) -> str:
        """把 body 解码成文本，非 UTF-8 时容错，不抛异常。"""
        if not self.body:
            return ""
        charset = "utf-8"
        match = re.search(r"charset=([\w-]+)", self._header("content-type"), re.I)
        if match:
            charset = match.group(1)
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def body_pairs(self):
        """按 Content-Type 解析 body，返回字段名与值组成的列表。"""
        ctype = self._header("content-type").lower()
        text = self.body_text()

        if "application/x-www-form-urlencoded" in ctype:
            return parse_qsl(text, keep_blank_values=True)

        if "application/json" in ctype:
            try:
                return list(_flatten_json(json.loads(text)))
            except (json.JSONDecodeError, TypeError):
                return [("$json_raw", text)]

        if "multipart/form-data" in ctype:
            return self._parse_multipart(ctype)

        # 兜底：把整个 body 当一个待检字段，覆盖 text/xml 等情况
        return [("$body_raw", text)] if text else []

    def _parse_multipart(self, ctype: str):
        """最小可用的 multipart 解析。

        不依赖第三方库：按 boundary 切分，取每个 part 的 name/filename 与内容。
        文件上传场景下，Payload 常藏在 filename 或文件内容里，因此两者都返回。
        """
        boundary = None
        for item in ctype.split(";"):
            item = item.strip()
            if item.startswith("boundary="):
                boundary = item[len("boundary="):].strip('"')
        if not boundary:
            return [("$body_raw", self.body_text())]

        separator = ("--" + boundary).encode()
        pairs = []
        for chunk in self.body.split(separator):
            chunk = chunk.strip(b"\r\n")
            if not chunk or chunk == b"--":
                continue
            head, _, data = chunk.partition(b"\r\n\r\n")
            head_text = head.decode("utf-8", "ignore")
            name_match = re.search(r'name="([^"]*)"', head_text)
            file_match = re.search(r'filename="([^"]*)"', head_text)
            if file_match:
                pairs.append((name_match.group(1) + ".filename" if name_match else "filename",
                              file_match.group(1)))
            if name_match:
                pairs.append((name_match.group(1), data.decode("utf-8", "replace")))
        return pairs

    def injection_points(self):
        """列出全部注入点，覆盖 url、body、header、cookie 四类位置。"""
        points = []
        for name, value in self.query_pairs:
            points.append(("url", name, value))
        for name, value in self.body_pairs():
            points.append(("body", name, value))
        for name, value in self.headers:
            if name.lower() in _SKIP_HEADERS:
                continue
            points.append(("header", name, value))
        for name, value in self.cookies.items():
            points.append(("cookie", name, value))
        self._extra_points = points
        return points

    def request_packet(self) -> dict:
        """还原请求包，写入日志。"""
        return {
            "request_line": f"{self.method} {self.raw_path} {self.http_version}",
            "headers": {k: v for k, v in self.headers},
            "body": self.body_text()[: config.LOG_BODY_PREVIEW],
        }


def _flatten_json(obj, prefix=""):
    """递归展开 JSON，把所有字符串值变成 (路径, 值)。"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _flatten_json(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _flatten_json(value, f"{prefix}[{index}]")
    elif isinstance(obj, str):
        yield prefix or "$json", obj
    elif obj is not None:
        yield prefix or "$json", str(obj)


class WafHandler(BaseHTTPRequestHandler):
    """所有 HTTP 方法的统一入口。"""

    protocol_version = "HTTP/1.1"
    server_version = "CourseWAF/1.0"

    # 让每个动词都走同一条处理链
    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    # ---- 主流程 ----
    def _handle(self):
        start = time.time()
        body = self._read_body()
        ctx = ReqContext(
            method=self.command,
            raw_path=self.path,
            headers=list(self.headers.items()),
            body=body,
            client_ip=self.client_address[0],
            http_version=self.request_version,
        )

        # WAF 自身的控制接口不检测、不转发
        if ctx.path.startswith("/__waf/"):
            self._serve_internal(ctx)
            return

        decision = get_engine().inspect(ctx)
        status = 403 if decision.action == "block" else 0

        if decision.action == "block":
            payload = self._deny_page(ctx, decision)
            self._send_bytes(403, "text/html; charset=utf-8", payload)
        else:
            status = self._forward(ctx)

        self._log(ctx, decision, status, start)

    # ---- 请求读取 ----
    def _read_body(self) -> bytes:
        """读取请求体，兼容 Content-Length 与 chunked 两种传输方式。"""
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            return self._read_chunked()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def _read_chunked(self) -> bytes:
        """解析 chunked 请求体。

        为什么必须支持：把 Payload 拆成多个 chunk 是公开的 WAF 绕过手法之一，
        如果这里不解包，检测层看到的永远是空 body。
        """
        chunks = []
        while True:
            line = self.rfile.readline(65536).strip()
            if not line:
                break
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline(65536)   # 读取结尾的空行
                break
            chunks.append(self.rfile.read(size))
            self.rfile.read(2)               # 每个 chunk 后的 CRLF
        return b"".join(chunks)

    # ---- 内建控制接口 ----
    def _serve_internal(self, ctx: ReqContext):
        logger = get_logger()
        if ctx.path == "/__waf/health":
            self._send_json(200, {
                "status": "ok",
                "mode": config.MODE,
                "upstream": f"{config.UPSTREAM_HOST}:{config.UPSTREAM_PORT}",
                "rules": len(get_engine().ruleset.all()),
            })
            return
        if ctx.path == "/__waf/api/stats":
            self._send_json(200, {
                "stats": logger.stats(),
                "rules_by_category": get_engine().ruleset.stats(),
            })
            return
        if ctx.path == "/__waf/api/logs":
            query = dict(ctx.query_pairs)
            try:
                limit = max(1, min(500, int(query.get("limit", "100"))))
            except ValueError:
                limit = 100
            self._send_json(200, {"items": logger.recent(limit)})
            return
        if ctx.path == "/__waf/console":
            from .console import render_console
            self._send_bytes(200, "text/html; charset=utf-8",
                             render_console().encode("utf-8"))
            return
        self._send_json(404, {"error": "unknown internal endpoint"})

    # ---- 转发 ----
    def _forward(self, ctx: ReqContext) -> int:
        target = ctx.path
        if ctx.query:
            target += "?" + ctx.query

        headers = {}
        for name, value in ctx.headers:
            if name.lower() in config.HOP_BY_HOP_HEADERS:
                continue
            if name.lower() in ("host", "content-length", "accept-encoding"):
                continue
            headers[name] = value
        headers["Host"] = f"{config.UPSTREAM_HOST}:{config.UPSTREAM_PORT}"
        headers["X-Forwarded-For"] = ctx.client_ip
        headers["Accept-Encoding"] = "identity"   # 不让上游压缩，保证响应体可原样读回

        conn = None
        try:
            conn = http.client.HTTPConnection(
                config.UPSTREAM_HOST, config.UPSTREAM_PORT,
                timeout=config.UPSTREAM_TIMEOUT,
            )
            conn.request(ctx.method, target, body=ctx.body or None, headers=headers)
            resp = conn.getresponse()
            data = resp.read()

            self.send_response(resp.status, resp.reason)
            for name, value in resp.getheaders():
                if name.lower() in config.HOP_BY_HOP_HEADERS | {"content-length"}:
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if ctx.method != "HEAD":
                self.wfile.write(data)
            return resp.status
        except Exception as exc:      # 上游不可达 / 超时
            self._send_bytes(502, "text/html; charset=utf-8",
                             self._error_page(502, f"上游服务不可达：{exc}"))
            return 502
        finally:
            if conn is not None:
                conn.close()

    # ---- 响应工具 ----
    def _send_bytes(self, status: int, content_type: str, payload: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_json(self, status: int, obj):
        self._send_bytes(status, "application/json; charset=utf-8",
                         json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _deny_page(self, ctx: ReqContext, decision) -> bytes:
        """403 拦截页：展示命中规则，便于定位命中原因。"""
        rows = "".join(
            f"<tr><td>{_esc(h.rule_id)}</td><td>{_esc(h.category)}/{_esc(h.subtype)}</td>"
            f"<td>{_esc(h.location)}.{_esc(h.field_name)}</td><td>{h.severity}</td>"
            f"<td>{_esc(h.layer)}</td><td><code>{_esc(h.payload[:120])}</code></td></tr>"
            for h in decision.hits
        )
        html_text = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>403 已被软 WAF 拦截</title>
<style>
 body{{font-family:system-ui,"Microsoft YaHei",sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:40px}}
 .card{{max-width:960px;margin:0 auto;background:#1e293b;border-radius:12px;padding:28px}}
 h1{{color:#f87171;margin:0 0 8px}} .meta{{color:#94a3b8;margin-bottom:18px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{border-bottom:1px solid #334155;padding:8px;text-align:left;vertical-align:top}}
 th{{color:#93c5fd}} code{{color:#fca5a5;word-break:break-all}}
</style></head><body><div class="card">
<h1>403 Forbidden</h1>
<div class="meta">请求已被 Web 应用防火墙拦截 ｜ 源 IP {_esc(ctx.client_ip)} ｜
累计评分 <b>{decision.score}</b> / 阈值 <b>{get_engine().threshold}</b> ｜ {_esc(decision.reason)}</div>
<table><thead><tr><th>规则ID</th><th>类别</th><th>位置</th><th>分值</th><th>命中层</th><th>原始 Payload</th></tr></thead>
<tbody>{rows}</tbody></table>
</div></body></html>"""
        return html_text.encode("utf-8")

    def _error_page(self, code: int, message: str) -> bytes:
        return (f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{code}</title>"
                f"</head><body><h1>{code}</h1><p>{_esc(message)}</p></body></html>").encode("utf-8")

    # ---- 日志 ----
    def _log(self, ctx: ReqContext, decision, status: int, start: float):
        entry = {
            "ip": ctx.client_ip,
            "method": ctx.method,
            "path": ctx.raw_path,
            "action": decision.action,
            "score": decision.score,
            "status": status,
            "elapsed_ms": round((time.time() - start) * 1000, 2),
            "hits": [hit.to_dict() for hit in decision.hits],
            "reason": decision.reason,
            "request": ctx.request_packet(),
        }
        get_logger().write(entry)

    def log_message(self, fmt, *args):
        """收敛默认控制台输出，避免每个请求刷屏。"""
        return


def _esc(text) -> str:
    """HTML 转义：拦截页展示攻击 Payload 时防止自身被 XSS。"""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
