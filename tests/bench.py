# -*- coding: utf-8 -*-
"""性能测试：量化 WAF 引入的延迟开销。

方法：对比「直连靶场」与「经过 WAF」两组请求的 P50/P95 延迟，
再测并发吞吐；攻击请求单独测一组，因为它在 WAF 本地就返回，
不消耗上游资源，延迟通常更低。

输出：results/bench.json + 控制台表格。
"""

import json
import statistics
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulnapp import app as vulnapp          # noqa: E402
from waf import config as waf_config        # noqa: E402
from waf import main as waf_main            # noqa: E402

APP_PORT = 8081
WAF_PORT = 8080
NORMAL_PATH = "/sqli?id=1"
ATTACK_PATH = "/sqli?id=1%20union%20select%201,2,3"
SEQUENTIAL_N = 200
CONCURRENCY = 16
CONCURRENT_PER_THREAD = 25


def fetch(url, timeout=10):
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            resp.read()
            status = resp.status
    except Exception:
        status = 0
    return (time.perf_counter() - start) * 1000, status


def percentile(values, ratio):
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * ratio))
    return round(ordered[index], 2)


def sequential_stats(url, count=SEQUENTIAL_N):
    fetch(url)                            # 预热，排除首次连接建立的影响
    samples = []
    statuses = set()
    for _ in range(count):
        elapsed, status = fetch(url)
        samples.append(elapsed)
        statuses.add(status)
    return {
        "url": url,
        "count": count,
        "status": sorted(statuses),
        "p50_ms": round(statistics.median(samples), 2),
        "p95_ms": percentile(samples, 0.95),
        "mean_ms": round(statistics.fmean(samples), 2),
        "max_ms": round(max(samples), 2),
    }


def concurrent_stats(url):
    """固定线程数并发打，统计每秒请求数。"""
    count = CONCURRENCY * CONCURRENT_PER_THREAD
    barrier = threading.Barrier(CONCURRENCY)

    def worker():
        barrier.wait()
        for _ in range(CONCURRENT_PER_THREAD):
            fetch(url)

    threads = [threading.Thread(target=worker) for _ in range(CONCURRENCY)]
    start = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    duration = time.perf_counter() - start
    return {
        "concurrency": CONCURRENCY,
        "requests": count,
        "duration_s": round(duration, 2),
        "throughput_rps": round(count / duration, 1),
    }


def main():
    waf_config.UPSTREAM_HOST = "127.0.0.1"
    waf_config.UPSTREAM_PORT = APP_PORT

    app_server = vulnapp.make_server("127.0.0.1", APP_PORT)
    waf_server = waf_main.make_server("127.0.0.1", WAF_PORT)
    threading.Thread(target=app_server.serve_forever, daemon=True).start()
    threading.Thread(target=waf_server.serve_forever, daemon=True).start()
    time.sleep(0.8)

    direct = f"http://127.0.0.1:{APP_PORT}{NORMAL_PATH}"
    through = f"http://127.0.0.1:{WAF_PORT}{NORMAL_PATH}"
    attack = f"http://127.0.0.1:{WAF_PORT}{ATTACK_PATH}"

    print("正在测试：直连靶场 ...")
    base = sequential_stats(direct)
    print("正在测试：经 WAF 放行 ...")
    via_waf = sequential_stats(through)
    print("正在测试：经 WAF 拦截 ...")
    blocked = sequential_stats(attack, count=100)

    print("正在测试：并发吞吐 ...")
    base_conc = concurrent_stats(direct)
    waf_conc = concurrent_stats(through)

    overhead = round(via_waf["p50_ms"] - base["p50_ms"], 2)
    result = {
        "environment": "Windows 11 + Python 3.12, 本地回环，单机",
        "direct_upstream": base,
        "through_waf_allow": via_waf,
        "through_waf_block": blocked,
        "overhead_p50_ms": overhead,
        "overhead_ratio": round(via_waf["p50_ms"] / base["p50_ms"], 2) if base["p50_ms"] else None,
        "direct_throughput": base_conc,
        "waf_throughput": waf_conc,
    }

    (ROOT / "results").mkdir(parents=True, exist_ok=True)
    (ROOT / "results" / "bench.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    waf_server.shutdown()
    app_server.shutdown()

    print("\n" + "=" * 66)
    print(f"{'场景':<22}{'P50(ms)':<10}{'P95(ms)':<10}{'平均(ms)':<10}")
    print("-" * 66)
    for label, stat in (("直连靶场", base), ("经 WAF 放行", via_waf), ("经 WAF 拦截", blocked)):
        print(f"{label:<22}{stat['p50_ms']:<10}{stat['p95_ms']:<10}{stat['mean_ms']:<10}")
    print("=" * 66)
    print(f"WAF 引入的 P50 延迟开销：+{overhead} ms，约为直连的 {result['overhead_ratio']} 倍")
    print(f"并发 {CONCURRENCY} 吞吐：直连 {base_conc['throughput_rps']} rps → "
          f"经 WAF {waf_conc['throughput_rps']} rps")
    print("结果已写入 results/bench.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
