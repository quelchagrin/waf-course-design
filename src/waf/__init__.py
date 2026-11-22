# -*- coding: utf-8 -*-
"""课程设计软 WAF 包。

模块划分：
- config.py        全局配置，包括监听端口、上游地址、模式、阈值、规则目录
- proxy.py         HTTP 反向代理与请求解析层
- normalizer.py    解码归一化层，对抗编码混淆
- rules_engine.py  规则加载、匹配与异常评分
- logger.py        JSONL 日志与内存环形缓冲
- console.py       可视化日志控制台
"""
