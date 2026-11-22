# -*- coding: utf-8 -*-
"""全局配置。

所有可调参数集中在这里，部署时统一修改即可。
全部参数都支持环境变量覆盖，所以同一份源码既能跑本地靶场，
也能指向 DVWA，不需要改代码。
默认拓扑：浏览器 -> WAF:8080 -> 上游:8081 或 DVWA:80。
"""

import os
from pathlib import Path

# ---- 路径 ----
BASE_DIR = Path(__file__).resolve().parent          # src/waf
PROJECT_DIR = BASE_DIR.parent.parent                # waf-course-design
RULES_DIR = BASE_DIR / "rules"
LOG_DIR = PROJECT_DIR / "logs"
DATA_DIR = PROJECT_DIR / "data"


def _env(name: str, default: str) -> str:
    """读取环境变量，未设置时返回默认值。"""
    value = os.environ.get(name)
    return default if value is None or value == "" else value


# ---- 监听与上游 ----
LISTEN_HOST = _env("WAF_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(_env("WAF_LISTEN_PORT", "8080"))

UPSTREAM_HOST = _env("WAF_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(_env("WAF_UPSTREAM_PORT", "8081"))

# ---- 检测策略 ----
# off    只透传，不检测，用于对比有无 WAF 的差异
# shadow 检测并记录，但一律放行，用于灰度观察误报
# block  检测并拦截，课程演示模式
MODE = _env("WAF_MODE", "block")

# 异常评分阈值：命中规则的 severity 累加，达到阈值判定为攻击。
# 参考 OWASP CRS 的异常评分思路，单条低危规则不拦截，
# 多条弱特征叠加才拦截，以降低误报。
THRESHOLD = int(_env("WAF_THRESHOLD", "5"))

# 规则热加载：规则文件修改时间变化后自动重新加载
HOT_RELOAD = _env("WAF_HOT_RELOAD", "1") == "1"
HOT_RELOAD_INTERVAL = float(_env("WAF_HOT_RELOAD_INTERVAL", "2.0"))

# ---- 日志 ----
LOG_FILE = Path(_env("WAF_LOG_FILE", str(LOG_DIR / "waf.jsonl")))
LOG_BODY_PREVIEW = int(_env("WAF_LOG_BODY_PREVIEW", "2048"))   # 日志中请求包预览字节数
RING_BUFFER_SIZE = int(_env("WAF_RING_BUFFER", "2000"))        # 控制台可回看条数

# ---- 代理行为 ----
UPSTREAM_TIMEOUT = float(_env("WAF_UPSTREAM_TIMEOUT", "10"))
# 转发时丢弃逐跳头，避免与上游的连接管理冲突
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
