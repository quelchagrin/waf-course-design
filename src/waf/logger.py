# -*- coding: utf-8 -*-
"""日志层：JSONL 落盘与内存环形缓冲。

每条拦截记录包含时间、源 IP、请求包，并附加命中规则、评分、
动作与响应状态，既用于事后审计，也供控制台实时读取。

设计说明：
- 采用 JSON Lines，一行一条，便于脚本统计规则命中率与拦截分布；
- 内存环形缓冲避免控制台频繁读盘，进程重启后清空，落盘日志不受影响。
"""

import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List

from . import config

_LOCK = threading.Lock()
_LOGGER = None


class Logger:
    """线程安全的日志写入器。"""

    def __init__(self, log_file: Path):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: deque = deque(maxlen=config.RING_BUFFER_SIZE)
        self._counters: Dict[str, int] = {
            "total": 0, "allowed": 0, "blocked": 0, "shadowed": 0,
        }

    def write(self, entry: Dict[str, Any]) -> None:
        """写入一条日志，并更新计数与环形缓冲。"""
        entry.setdefault("time", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        action = entry.get("action", "allow")
        line = json.dumps(entry, ensure_ascii=False)
        with _LOCK:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._buffer.append(entry)
            self._counters["total"] += 1
            if action == "block":
                self._counters["blocked"] += 1
            elif action == "shadow":
                self._counters["shadowed"] += 1
            else:
                self._counters["allowed"] += 1

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """返回最近的日志，新的在后，供控制台轮询。"""
        with _LOCK:
            items = list(self._buffer)
        return items[-limit:]

    def stats(self) -> Dict[str, int]:
        """返回累计计数，供控制台统计卡片使用。"""
        with _LOCK:
            return dict(self._counters)


def get_logger() -> Logger:
    """单例，整个进程共用一个日志器。"""
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = Logger(config.LOG_FILE)
    return _LOGGER
