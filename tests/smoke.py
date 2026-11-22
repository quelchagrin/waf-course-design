# -*- coding: utf-8 -*-
"""冒烟测试：验证「浏览器 -> WAF:8080 -> 靶场:8081」透传闭环。

运行：
    python tests/smoke.py
"""

import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulnapp import app as vulnapp          # noqa: E402
from waf import config as waf_config        # noqa: E402
from waf import main as waf_main            # noqa: E402

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name} {detail}")


def fetch(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:                # 连接失败等
        return 0, str(exc)


def main():
    waf_config.UPSTREAM_HOST = "127.0.0.1"
    waf_config.UPSTREAM_PORT = 8081

    target = vulnapp.make_server("127.0.0.1", 8081)
    waf = waf_main.make_server("127.0.0.1", 8080)

    threading.Thread(target=target.serve_forever, daemon=True).start()
    threading.Thread(target=waf.serve_forever, daemon=True).start()
    time.sleep(0.6)

    status, body = fetch("http://127.0.0.1:8080/__waf/health")
    check("WAF 健康检查", status == 200 and '"status": "ok"' in body, f"status={status}")

    status, body = fetch("http://127.0.0.1:8080/")
    check("首页透传", status == 200 and "课程设计漏洞靶场" in body, f"status={status}")

    status, body = fetch("http://127.0.0.1:8080/sqli?id=1")
    check("SQL 查询透传", status == 200 and "admin" in body, f"status={status}")

    status, body = fetch("http://127.0.0.1:8080/xss?q=hello")
    check("XSS 参数透传", status == 200 and "hello" in body, f"status={status}")

    status, body = fetch("http://127.0.0.1:8081/health")
    check("靶场直连正常", status == 200, f"status={status}")

    status, body = fetch("http://127.0.0.1:8080/__waf/api/logs?limit=10")
    check("日志接口可读", status == 200 and '"items"' in body, f"status={status}")

    waf.shutdown()
    target.shutdown()
    time.sleep(0.2)

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n冒烟结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
