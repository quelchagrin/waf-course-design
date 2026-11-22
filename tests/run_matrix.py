# -*- coding: utf-8 -*-
"""测试矩阵执行器：把 tests/cases/*.json 里的用例逐条打给 WAF，汇总结果。

产出：
  results/matrix.json  每条用例的期望/实际/评分/命中规则
  results/matrix.md    便于查看的 Markdown 结果表
  results/summary.json 按类别、按位置的通过率统计

用法：
    python tests/run_matrix.py
"""

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulnapp import app as vulnapp          # noqa: E402
from waf import config as waf_config        # noqa: E402
from waf import main as waf_main            # noqa: E402

WAF_PORT = 8080
APP_PORT = 8081
RESULTS_DIR = ROOT / "results"


def send(case):
    """按用例描述构造并发送一次请求，返回状态码与响应体。"""
    method = case.get("method", "GET").upper()
    path = case["path"]
    url = f"http://127.0.0.1:{WAF_PORT}{path}"

    headers = dict(case.get("headers", {}))
    if case.get("cookie"):
        headers["Cookie"] = case["cookie"]
    data = None
    if case.get("body"):
        data = case["body"].encode("utf-8")
        headers.setdefault("Content-Type", case.get("content_type", "application/x-www-form-urlencoded"))

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, str(exc)


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def last_log():
    """取最近一条日志，用于还原本次请求的评分与命中规则。"""
    try:
        items = fetch_json(f"http://127.0.0.1:{WAF_PORT}/__waf/api/logs?limit=1")["items"]
        return items[-1] if items else {}
    except Exception:
        return {}


def load_cases():
    cases = []
    for path in sorted((ROOT / "tests" / "cases").glob("*.json")):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for case in data.get("cases", []):
            case.setdefault("category", data.get("category", path.stem))
            cases.append(case)
    return cases


def main():
    waf_config.UPSTREAM_HOST = "127.0.0.1"
    waf_config.UPSTREAM_PORT = APP_PORT
    waf_config.MODE = "block"
    waf_config.THRESHOLD = 5

    app_server = vulnapp.make_server("127.0.0.1", APP_PORT)
    waf_server = waf_main.make_server("127.0.0.1", WAF_PORT)
    threading.Thread(target=app_server.serve_forever, daemon=True).start()
    threading.Thread(target=waf_server.serve_forever, daemon=True).start()
    time.sleep(0.8)

    cases = load_cases()
    records = []
    for index, case in enumerate(cases, start=1):
        status, body = send(case)
        log = last_log()
        actual = "block" if status == 403 else "allow"
        # 上游 404/500 也属于"未被 WAF 拦截"，判定为 allow
        ok = actual == case["expect"]
        records.append({
            "no": index,
            "name": case["name"],
            "category": case["category"],
            "location": case.get("location", "url"),
            "expect": case["expect"],
            "actual": actual,
            "status": status,
            "ok": ok,
            "score": log.get("score", 0),
            "hits": [h["rule_id"] for h in log.get("hits", [])],
            "method": case.get("method", "GET"),
            "path": case["path"],
        })
        flag = "PASS" if ok else "FAIL"
        print(f"[{flag}] #{index:02d} {case['category']}/{case.get('location','url')} "
              f"{case['name']} 期望={case['expect']} 实际={actual} 评分={log.get('score',0)}")

    waf_server.shutdown()
    app_server.shutdown()
    time.sleep(0.2)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    total = len(records)
    passed = sum(1 for r in records if r["ok"])

    by_category = defaultdict(lambda: {"total": 0, "passed": 0})
    by_location = defaultdict(lambda: {"total": 0, "passed": 0})
    for record in records:
        for bucket, key in ((by_category, record["category"]), (by_location, record["location"])):
            bucket[key]["total"] += 1
            bucket[key]["passed"] += int(record["ok"])

    summary = {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total * 100, 2) if total else 0,
        "by_category": dict(by_category),
        "by_location": dict(by_location),
        "threshold": waf_config.THRESHOLD,
        "mode": waf_config.MODE,
    }

    (RESULTS_DIR / "matrix.json").write_text(
        json.dumps({"summary": summary, "records": records}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (RESULTS_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# 测试矩阵结果",
        "",
        f"- 用例总数：{total}，通过：{passed}，失败：{total - passed}，通过率：{summary['pass_rate']}%",
        f"- 拦截阈值：{waf_config.THRESHOLD}，模式：{waf_config.MODE}",
        "",
        "## 按漏洞类别",
        "",
        "| 类别 | 用例数 | 通过 | 通过率 |",
        "|---|---|---|---|",
    ]
    for category, stat in sorted(by_category.items()):
        rate = round(stat["passed"] / stat["total"] * 100, 1) if stat["total"] else 0
        lines.append(f"| {category} | {stat['total']} | {stat['passed']} | {rate}% |")
    lines += ["", "## 按 Payload 位置", "", "| 位置 | 用例数 | 通过 | 通过率 |", "|---|---|---|---|"]
    for location, stat in sorted(by_location.items()):
        rate = round(stat["passed"] / stat["total"] * 100, 1) if stat["total"] else 0
        lines.append(f"| {location} | {stat['total']} | {stat['passed']} | {rate}% |")
    lines += ["", "## 明细", "",
              "| # | 类别 | 位置 | 用例 | 期望 | 实际 | 评分 | 命中规则 | 结果 |",
              "|---|---|---|---|---|---|---|---|---|"]
    for record in records:
        lines.append(
            f"| {record['no']} | {record['category']} | {record['location']} | {record['name']} | "
            f"{record['expect']} | {record['actual']} | {record['score']} | "
            f"{', '.join(record['hits']) or '-'} | {'通过' if record['ok'] else '**失败**'} |")
    (RESULTS_DIR / "matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\n共 {total} 条，通过 {passed} 条，通过率 {summary['pass_rate']}%")
    print(f"结果已写入 {RESULTS_DIR}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
