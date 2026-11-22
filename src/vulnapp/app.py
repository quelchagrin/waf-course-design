# -*- coding: utf-8 -*-
"""本地零依赖漏洞靶场。

定位说明：
- 课程演示使用虚拟机中的 DVWA；
- 开发阶段每改一条规则都要验证，不能每次都开虚拟机，因此这里用 Python 标准库
  写一个"故意有漏洞"的极简应用，作为规则回归的固定靶场；
- 靶场的四个入口刻意覆盖 SQL 注入、XSS、命令注入、代码注入四类漏洞，且都能被
  参数直接控制，便于自动化测试脚本逐条断言。

仅用于课程设计教学演示，禁止部署到公网。
"""

import html
import platform
import sqlite3
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

_DB_LOCK = threading.Lock()
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
_DB.executemany("INSERT INTO users VALUES (?,?,?,?)", [
    (1, "admin", "admin123", "administrator"),
    (2, "alice", "alice@2024", "user"),
    (3, "bob", "bob_2024", "user"),
])
_DB.commit()

INDEX = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>课程设计靶场</title></head><body style="font-family:system-ui;padding:32px">
<h1>课程设计漏洞靶场</h1>
<p>用于软 WAF 规则回归，故意保留以下漏洞：</p>
<ul>
  <li><a href="/sqli?id=1">/sqli?id=1</a> — SQL 注入</li>
  <li><a href="/xss?q=hello">/xss?q=hello</a> — 反射型 XSS</li>
  <li><a href="/ping?host=127.0.0.1">/ping?host=127.0.0.1</a> — 命令注入</li>
  <li><a href="/upload">/upload</a> — 文件上传，用于 multipart 检测</li>
  <li>POST /calc，参数 expr — 代码注入，直接 eval</li>
</ul></body></html>"""

UPLOAD_FORM = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>上传</title></head><body style="font-family:system-ui;padding:32px">
<h2>文件上传</h2>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file"><button>上传</button>
</form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "VulnApp/1.0"

    def do_GET(self):
        parts = urlsplit(self.path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))

        if parts.path == "/":
            self._send(200, INDEX)
        elif parts.path == "/sqli":
            self._sqli(query.get("id", "1"))
        elif parts.path == "/xss":
            self._xss(query.get("q", ""))
        elif parts.path == "/ping":
            self._ping(query.get("host", "127.0.0.1"))
        elif parts.path == "/upload":
            self._send(200, UPLOAD_FORM)
        elif parts.path == "/health":
            self._send(200, "ok")
        else:
            self._send(404, "not found")

    def do_POST(self):
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if parts.path == "/calc":
            from urllib.parse import parse_qs
            form = parse_qs(body.decode("utf-8", "replace"))
            expr = (form.get("expr") or [""])[0]
            # 【故意漏洞】直接 eval 用户输入，用于演示"代码注入"
            try:
                result = eval(expr)      # noqa: S307 - 教学靶场，故意不安全
            except Exception as exc:
                result = f"error: {exc}"
            self._send(200, f"<p>计算结果：{html.escape(str(result))}</p>")
        elif parts.path == "/upload":
            self._send(200, "<p>上传已接收，未做校验</p>")
        else:
            self._send(404, "not found")

    def _sqli(self, user_input):
        # 【故意漏洞】字符串拼接 SQL
        sql = f"SELECT id, username, role FROM users WHERE id = {user_input}"
        try:
            with _DB_LOCK:
                rows = _DB.execute(sql).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"<p>SQL 错误：{html.escape(str(exc))}</p>", ctype="text/html")
            return
        table = "".join(
            f"<tr><td>{html.escape(str(r[0]))}</td><td>{html.escape(str(r[1]))}</td>"
            f"<td>{html.escape(str(r[2]))}</td></tr>" for r in rows
        )
        self._send(200, f"<table border=1>{table}</table>")

    def _xss(self, keyword):
        # 【故意漏洞】不转义直接回显
        self._send(200, f"<div>搜索结果：{keyword}</div>")

    def _ping(self, host):
        # 【故意漏洞】shell=True 拼接命令
        if platform.system() == "Windows":
            cmd = f"ping -n 1 {host}"
        else:
            cmd = f"ping -c 1 {host}"
        try:
            output = subprocess.run(cmd, shell=True, capture_output=True,
                                    timeout=5, text=True).stdout
        except subprocess.TimeoutExpired:
            output = "timeout"
        self._send(200, f"<pre>{html.escape(output[:2000])}</pre>")

    def _send(self, status, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


def make_server(host="127.0.0.1", port=8081) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> int:
    server = make_server()
    print(f"[靶场] 已启动 http://127.0.0.1:8081，仅本地教学使用")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
