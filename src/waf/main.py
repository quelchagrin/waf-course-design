# -*- coding: utf-8 -*-
"""WAF 进程入口。

用法：
    cd src
    python -m waf.main
    python -m waf.main --listen 8080 --upstream-host 127.0.0.1 --upstream-port 80
"""

import argparse
import sys
from http.server import ThreadingHTTPServer

from . import config
from .proxy import WafHandler, get_engine


def make_server(host: str = None, port: int = None) -> ThreadingHTTPServer:
    """创建 WAF 服务器，测试脚本直接复用，避免重复起进程。"""
    host = host or config.LISTEN_HOST
    port = port or config.LISTEN_PORT
    server = ThreadingHTTPServer((host, port), WafHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="课程设计软 WAF，反向代理模式")
    parser.add_argument("--listen", default=config.LISTEN_HOST)
    parser.add_argument("--port", type=int, default=config.LISTEN_PORT)
    parser.add_argument("--upstream-host", default=config.UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=config.UPSTREAM_PORT)
    parser.add_argument("--mode", choices=["off", "shadow", "block"], default=config.MODE)
    parser.add_argument("--threshold", type=int, default=config.THRESHOLD)
    args = parser.parse_args()

    # 命令行参数覆盖环境变量，方便演示现场临时切换
    config.UPSTREAM_HOST = args.upstream_host
    config.UPSTREAM_PORT = args.upstream_port
    config.MODE = args.mode
    config.THRESHOLD = args.threshold

    engine = get_engine()
    engine.threshold = args.threshold
    engine.ruleset.load()

    server = make_server(args.listen, args.port)
    print("=" * 62)
    print("  课程设计软 WAF 已启动，反向代理模式")
    print(f"  监听      : http://{args.listen}:{args.port}")
    print(f"  上游应用  : http://{args.upstream_host}:{args.upstream_port}")
    print(f"  检测模式  : {args.mode}    拦截阈值: {args.threshold}")
    print(f"  规则条数  : {len(engine.ruleset.all())}")
    print(f"  控制台    : http://{args.listen}:{args.port}/__waf/console")
    print("=" * 62)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[WAF] 收到中断，正在退出")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
