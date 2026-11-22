# -*- coding: utf-8 -*-
"""规则引擎：规则加载、热加载、逐点匹配与异常评分。

设计取舍：
1. 单条规则只给分，不直接判定。select 出现在正文里可能是正常业务，
   而 union、select、from 同时命中，累计分越过阈值，才是高置信度攻击。
2. 参考 OWASP CRS 的异常评分思路，规则分级，总分达到阈值才拦截。
   好处是可以按业务调阈值，代价是需要标定。
3. 同一规则在 url、body、header、cookie 四个位置各计一次，
   避免把 Payload 挪到 header 就绕过。
"""

import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config, normalizer


@dataclass
class Hit:
    """一次规则命中。"""
    rule_id: str
    category: str
    subtype: str
    severity: int
    location: str          # url / body / header / cookie
    field_name: str        # 具体参数名或头名，如 id / User-Agent
    layer: str             # 在哪个归一化层级命中：raw / decoded / deep
    payload: str           # 原始值，截断后
    desc: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "subtype": self.subtype,
            "severity": self.severity,
            "location": self.location,
            "field": self.field_name,
            "layer": self.layer,
            "payload": self.payload,
            "desc": self.desc,
        }


@dataclass
class Decision:
    """一次请求的判定结果。"""
    action: str            # allow / block / shadow
    score: int
    hits: List[Hit] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "score": self.score,
            "hits": [h.to_dict() for h in self.hits],
            "reason": self.reason,
        }


class RuleSet:
    """规则集合：从 rules/*.json 加载，支持按文件 mtime 热加载。"""

    def __init__(self, rules_dir: Path):
        self.rules_dir = Path(rules_dir)
        self.rules: List[Dict[str, Any]] = []
        self._mtimes: Dict[str, float] = {}
        self._lock = threading.Lock()
        self.last_loaded = 0.0
        self.load()

    # ---- 加载 ----
    def _rule_files(self) -> List[Path]:
        return sorted(self.rules_dir.glob("*.json"))

    def load(self) -> int:
        """读取全部规则文件并编译正则。返回规则条数。"""
        files = self._rule_files()
        loaded: List[Dict[str, Any]] = []
        mtimes: Dict[str, float] = {}
        seen_ids = set()

        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                # 规则文件写坏时保留旧规则继续服务，这也是生产 WAF 的常见做法
                print(f"[WAF][规则告警] 跳过 {path.name}: {exc}")
                continue

            mtimes[str(path)] = path.stat().st_mtime
            default_category = data.get("category", path.stem)

            for raw in data.get("rules", []):
                rule = dict(raw)
                rule.setdefault("category", default_category)
                rule.setdefault("severity", 5)
                rule.setdefault("desc", "")
                rule.setdefault("subtype", "generic")
                rule["file"] = path.name

                rule_id = rule.get("id")
                if not rule_id or rule_id in seen_ids:
                    print(f"[WAF][规则告警] 规则 id 缺失或重复，已跳过: {rule_id!r}")
                    continue
                try:
                    rule["_re"] = re.compile(rule["pattern"], re.IGNORECASE)
                except re.error as exc:
                    print(f"[WAF][规则告警] 正则非法 {rule_id}: {exc}")
                    continue
                seen_ids.add(rule_id)
                loaded.append(rule)

        with self._lock:
            self.rules = loaded
            self._mtimes = mtimes
            self.last_loaded = time.time()
        return len(loaded)

    def maybe_reload(self) -> bool:
        """热加载：规则文件有增删改时自动重载，无需重启进程。"""
        if not config.HOT_RELOAD:
            return False
        try:
            current = {str(p): p.stat().st_mtime for p in self._rule_files()}
        except OSError:
            return False
        if current != self._mtimes:
            count = self.load()
            print(f"[WAF][热加载] 规则已重载，共 {count} 条")
            return True
        return False

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.rules)

    def stats(self) -> Dict[str, Dict[str, int]]:
        """按类别统计规则条数，用于规则分布展示。"""
        result: Dict[str, Dict[str, int]] = {}
        for rule in self.all():
            cat = rule["category"]
            sub = rule["subtype"]
            result.setdefault(cat, {})
            result[cat][sub] = result[cat].get(sub, 0) + 1
        return result


class Engine:
    """检测引擎：把请求上下文送进规则集，得到拦截决策。"""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.ruleset = RuleSet(rules_dir or config.RULES_DIR)
        self.threshold = config.THRESHOLD

    def inspect(self, ctx) -> Decision:
        """对请求的所有注入点做检测。

        返回 Decision：action 可能是 allow / block / shadow，
        具体由 config.MODE 与累计评分共同决定。
        """
        self.ruleset.maybe_reload()

        if config.MODE == "off":
            return Decision("allow", 0, [], "检测已关闭，WAF_MODE=off")

        hits: List[Hit] = []
        seen = set()          # 同一规则在同一位置同一字段只记一次，避免重复计分
        rules = self.ruleset.all()

        for location, field_name, value in ctx.injection_points():
            if not value:
                continue
            for layer, candidate in normalizer.candidates(value):
                if not candidate:
                    continue
                for rule in rules:
                    if rule["_re"].search(candidate) is None:
                        continue
                    key = (rule["id"], location, field_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(Hit(
                        rule_id=rule["id"],
                        category=rule["category"],
                        subtype=rule["subtype"],
                        severity=int(rule["severity"]),
                        location=location,
                        field_name=field_name,
                        layer=layer,
                        payload=value[:300],
                        desc=rule.get("desc", ""),
                    ))

        score = sum(hit.severity for hit in hits)
        if score >= self.threshold and hits:
            if config.MODE == "shadow":
                return Decision("shadow", score, hits,
                                f"评分 {score} >= 阈值 {self.threshold}，灰度模式仅记录")
            return Decision("block", score, hits,
                            f"评分 {score} >= 阈值 {self.threshold}")
        return Decision("allow", score, hits, "未达拦截阈值")
