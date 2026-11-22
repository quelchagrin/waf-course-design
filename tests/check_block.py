# -*- coding: utf-8 -*-
"""拦截链路校验：临时规则下验证 检测 -> 403 拦截页 -> 日志 -> 控制台。

与 smoke.py 的区别：smoke 验证透传链路，本脚本验证拦截链路，
用临时规则目录避免污染正式规则库，验证完自动清理。
"""

import json
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
    print(f"[{'PASS' if condition else 'FAIL'}] {name} {detail}")


def fetch(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, str(exc)


def main():
    # 临时规则目录建在工作区内，并先清空。
    # 不用 tempfile.mkdtemp，它创建的目录权限较严，子进程写入时容易失败。
    tmp_rules = ROOT / "data" / "tmp" / "rules-smoke"
    if tmp_rules.exists():
        import shutil
        shutil.rmtree(tmp_rules, ignore_errors=True)
    tmp_rules.mkdir(parents=True, exist_ok=True)
    (tmp_rules / "sqli.json").write_text(json.dumps({
        "category": "sqli",
        "rules": [{
            "id": "SQLI-UNION-SMOKE",
            "subtype": "union",
            "severity": 8,
            "pattern": r"union\s+select",
            "desc": "冒烟规则：UNION SELECT",
        }],
    }, ensure_ascii=False), encoding="utf-8")

    waf_config.RULES_DIR = tmp_rules
    waf_config.UPSTREAM_HOST = "127.0.0.1"
    waf_config.UPSTREAM_PORT = 8081

    target = vulnapp.make_server("127.0.0.1", 8081)
    waf = waf_main.make_server("127.0.0.1", 8080)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    threading.Thread(target=waf.serve_forever, daemon=True).start()
    time.sleep(0.6)

    # 1. 正常请求放行
    status, body = fetch("http://127.0.0.1:8080/sqli?id=1")
    check("正常请求放行", status == 200 and "admin" in body, f"status={status}")

    # 2. 攻击请求被拦截，位置为 URL 参数
    status, body = fetch("http://127.0.0.1:8080/sqli?id=1%20union%20select%201,2,3")
    check("UNION 注入被拦截", status == 403, f"status={status}")
    check("拦截页含命中规则", "SQLI-UNION-SMOKE" in body, "")

    # 3. 编码混淆仍能识别，这里用双重 URL 编码
    status, _ = fetch("http://127.0.0.1:8080/sqli?id=1%2520union%2520select")
    check("双重编码绕过被识别", status == 403, f"status={status}")

    # 4. 日志写入且含时间、源 IP、请求包
    status, body = fetch("http://127.0.0.1:8080/__waf/api/logs?limit=5")
    ok = status == 200
    entry = {}
    if ok:
        items = json.loads(body)["items"]
        blocked = [i for i in items if i["action"] == "block"]
        ok = bool(blocked)
        if blocked:
            entry = blocked[0]
    check("日志记录拦截事件", ok, "")
    if entry:
        check("日志含时间", bool(entry.get("time")), str(entry.get("time")))
        check("日志含源 IP", bool(entry.get("ip")), str(entry.get("ip")))
        check("日志含请求包", bool(entry.get("request", {}).get("request_line")),
              str(entry.get("request", {}).get("request_line")))

    # 5. 控制台页面可打开
    status, body = fetch("http://127.0.0.1:8080/__waf/console")
    check("控制台页面可访问", status == 200 and "实时拦截控制台" in body, f"status={status}")

    waf.shutdown()
    target.shutdown()
    time.sleep(0.2)

    import shutil
    shutil.rmtree(tmp_rules, ignore_errors=True)

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n拦截链路校验：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
