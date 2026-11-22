# -*- coding: utf-8 -*-
"""解码归一化层：把攻击者写的样子还原成语义等价的样子。

正则规则匹配的是字符串，而同一语义可以有无数种编码写法。
以 UNION SELECT 为例，下列写法等价：
    union select / UNION SELECT / un/**/ion sele/**/ct / %75nion%20select
    un&#105;on select / \\u0075nion select / Union%09Select
直接对原始字符串匹配会漏掉大部分写法，因此检测前先做多重解码、
去注释、空白归一、大小写折叠与全角转半角，再对结果匹配规则。
每次检测同时保留原文和不同归一化层级，既降低漏报，
也能说明原始 Payload 在第几层命中规则。

分层口径参考 OWASP CRS 的转换函数。
"""

import html
import re
import unicodedata
from typing import List, Tuple

# 多层 URL 编码最多解开几层，攻击者可能用 %2527 套两层
MAX_URL_ROUNDS = 3

# 字符转义：\uXXXX、\xNN、八进制
_RE_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_RE_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_RE_OCT_ESCAPE = re.compile(r"\\([0-7]{3})")

# SQL 注释：块注释、MySQL 版本注释、行注释
_RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_RE_LINE_COMMENT = re.compile(r"--[^\n]*")
_RE_HASH_COMMENT = re.compile(r"#[^\n]*")

# 连续空白，含 %09 %0a %0d 解码后的控制字符
_RE_WHITESPACE = re.compile(r"\s+")


def url_decode_multi(text: str, rounds: int = MAX_URL_ROUNDS) -> str:
    """反复做百分号解码，直到结果稳定或达到层数上限。

    单次 unquote 只解一层，攻击者常用双重编码绕过只解一层的检测器。
    """
    from urllib.parse import unquote

    current = text
    for _ in range(rounds):
        decoded = unquote(current, errors="ignore")
        if decoded == current:
            break
        current = decoded
    return current


def strip_comments(text: str) -> str:
    """去掉 SQL 注释。

    直接删除而不是替换为空格，因为 UN/**/ION 的语义就是 UNION，
    删掉注释才能还原关键字，换成空格反而把关键字切断。
    """
    text = _RE_BLOCK_COMMENT.sub("", text)
    text = _RE_LINE_COMMENT.sub(" ", text)
    return text


def decode_char_escapes(text: str) -> str:
    """还原 \\uXXXX / \\xNN / 八进制转义。"""
    def _u(m):
        return chr(int(m.group(1), 16))

    def _x(m):
        return chr(int(m.group(1), 16))

    def _o(m):
        return chr(int(m.group(1), 8))

    text = _RE_UNICODE_ESCAPE.sub(_u, text)
    text = _RE_HEX_ESCAPE.sub(_x, text)
    text = _RE_OCT_ESCAPE.sub(_o, text)
    return text


def collapse_whitespace(text: str) -> str:
    """把任意空白序列压成单个空格，消除用制表符/换行拆分关键字的绕过。"""
    return _RE_WHITESPACE.sub(" ", text).strip()


def fold_case(text: str) -> str:
    """大小写折叠，规则匹配统一走小写。"""
    return text.lower()


def to_halfwidth(text: str) -> str:
    """全角转半角，中文输入法下的全角关键字也能识别。"""
    return unicodedata.normalize("NFKC", text)


def candidates(value: str) -> List[Tuple[str, str]]:
    """产出一组候选串，供规则逐层匹配。

    返回层级标签与归一化结果。标签会写进日志，
    便于说明原始 Payload 在第几层命中规则。

    层级：
      raw     仅做大小写折叠，最快，但漏编码变形
      decoded URL 解码、HTML 实体、字符转义、全角转半角、去注释、空白归一
      deep    在上一步基础上再做一轮完整解码，应对二次编码
    """
    raw = value.replace("\x00", " ")
    yield "raw", fold_case(raw)

    step = url_decode_multi(raw)
    step = html.unescape(step)
    step = decode_char_escapes(step)
    step = to_halfwidth(step)
    step = strip_comments(step)
    step = collapse_whitespace(step)
    decoded = fold_case(step)
    yield "decoded", decoded

    # 二次编码：对归一化结果再解一轮，%2527 这类需要两轮
    deep = url_decode_multi(decoded)
    deep = html.unescape(deep)
    deep = decode_char_escapes(deep)
    deep = to_halfwidth(deep)
    deep = strip_comments(deep)
    deep = collapse_whitespace(deep)
    deep = fold_case(deep)
    if deep != decoded:
        yield "deep", deep
