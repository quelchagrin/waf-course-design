# 测试矩阵结果

- 用例总数：115，通过：115，失败：0，通过率：100.0%
- 拦截阈值：5，模式：block

## 按漏洞类别

| 类别 | 用例数 | 通过 | 通过率 |
|---|---|---|---|
| bypass | 18 | 18 | 100.0% |
| cmdi | 14 | 14 | 100.0% |
| codeinj | 8 | 8 | 100.0% |
| fp | 20 | 20 | 100.0% |
| normal | 12 | 12 | 100.0% |
| sqli | 21 | 21 | 100.0% |
| xss | 22 | 22 | 100.0% |

## 按 Payload 位置

| 位置 | 用例数 | 通过 | 通过率 |
|---|---|---|---|
| body | 13 | 13 | 100.0% |
| cookie | 4 | 4 | 100.0% |
| header | 8 | 8 | 100.0% |
| url | 90 | 90 | 100.0% |

## 明细

| # | 类别 | 位置 | 用例 | 期望 | 实际 | 评分 | 命中规则 | 结果 |
|---|---|---|---|---|---|---|---|---|
| 1 | bypass | url | 全 URL 编码 1' or 1=1 | block | block | 6 | SQLI-BOOL-001 | 通过 |
| 2 | bypass | url | 大小写交错 SeLeCt fRoM | block | block | 36 | SQLI-UNION-001, SQLI-UNION-002, SQLI-UNION-003, SQLI-UNION-004, SQLI-GEN-001 | 通过 |
| 3 | bypass | url | 注释穿插 Un/**/IoN | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 4 | bypass | url | MySQL 版本注释 /*!50000union*/ | block | block | 6 | SQLI-OBF-001 | 通过 |
| 5 | bypass | url | 制表符分隔 union%09select | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 6 | bypass | url | 换行分隔 union%0aselect | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 7 | bypass | url | 空字节截断 union%00select | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 8 | bypass | url | 全角字符 ｕｎｉｏｎ | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 9 | bypass | url | 参数污染 HPP 同名参数 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 10 | bypass | header | X-Forwarded-For 头注入 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 11 | bypass | body | 嵌套 JSON 深层注入 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 12 | bypass | url | XSS 十六进制实体 | block | block | 14 | XSS-CALL-001, XSS-SCRIPT-001 | 通过 |
| 13 | bypass | url | XSS 无引号事件处理 onerror=alert(1) | block | block | 25 | XSS-EVENT-001, XSS-EVENT-002, XSS-EVENT-003, XSS-CALL-001 | 通过 |
| 14 | bypass | url | XSS 反引号替代括号 | block | block | 31 | CMDI-SUB-002, XSS-EVENT-001, XSS-EVENT-002, XSS-EVENT-003, XSS-TAG-003 | 通过 |
| 15 | bypass | url | 命令注入 $IFS 无花括号 | block | block | 8 | CMDI-IFS-001 | 通过 |
| 16 | bypass | url | 命令注入 CRLF 换行 | block | block | 6 | CMDI-NL-001 | 通过 |
| 17 | bypass | url | 命令注入 引号+拼接 | block | block | 8 | CMDI-QUOTE-001 | 通过 |
| 18 | bypass | header | 代码注入 JNDI 嵌套变量绕过 | block | block | 7 | CODE-JAVA-005 | 通过 |
| 19 | cmdi | url | 分号分隔 whoami | block | block | 7 | CMDI-SEP-001 | 通过 |
| 20 | cmdi | url | 管道 |id | block | block | 7 | CMDI-SEP-001 | 通过 |
| 21 | cmdi | url | && 串联 cat | block | block | 7 | CMDI-SEP-002 | 通过 |
| 22 | cmdi | url | 命令替换 $(whoami) | block | block | 13 | CMDI-SUB-001, CMDI-SUB-003 | 通过 |
| 23 | cmdi | url | 反引号替换 `id` | block | block | 7 | CMDI-SUB-002 | 通过 |
| 24 | cmdi | url | 绕过1：${IFS} 代替空格 | block | block | 13 | CMDI-SUB-004, CMDI-IFS-001 | 通过 |
| 25 | cmdi | url | 绕过2：换行执行新命令 | block | block | 6 | CMDI-NL-001 | 通过 |
| 26 | cmdi | url | 绕过3：引号拼接 c'a't | block | block | 8 | CMDI-QUOTE-001 | 通过 |
| 27 | cmdi | url | 绕过4：base64 管道解码 | block | block | 7 | CMDI-B64-001 | 通过 |
| 28 | cmdi | url | 反弹 shell nc -e | block | block | 16 | CMDI-SEP-001, CMDI-REV-001 | 通过 |
| 29 | cmdi | url | 管道交给 sh 解释器 | block | block | 14 | CMDI-SEP-001, CMDI-PIPE-001 | 通过 |
| 30 | cmdi | url | PowerShell 执行 | block | block | 14 | CMDI-SEP-001, CMDI-PS-001 | 通过 |
| 31 | cmdi | url | 命令替换内嵌 curl | block | block | 19 | CMDI-SUB-001, CMDI-SUB-003, CMDI-DL-001 | 通过 |
| 32 | cmdi | url | 正常主机地址 | allow | allow | 0 | - | 通过 |
| 33 | codeinj | body | Python __import__ 执行 | block | block | 16 | CODE-PHP-002, CODE-PY-002 | 通过 |
| 34 | codeinj | body | Python eval | block | block | 22 | CODE-PHP-001, CODE-PY-001, XSS-CALL-002 | 通过 |
| 35 | codeinj | body | Python os.system | block | block | 15 | CODE-PHP-002, CODE-PY-003 | 通过 |
| 36 | codeinj | body | PHP system 写入 | block | block | 15 | CODE-PHP-002, CODE-PHP-007 | 通过 |
| 37 | codeinj | header | Log4j JNDI 注入 | block | block | 9 | CODE-JAVA-002 | 通过 |
| 38 | codeinj | body | Java Runtime 执行 | block | block | 31 | CODE-PHP-002, CODE-PY-001, CODE-JAVA-001, SQLI-GEN-004 | 通过 |
| 39 | codeinj | body | Python subprocess | block | block | 14 | CODE-PHP-002, CODE-PY-004 | 通过 |
| 40 | codeinj | body | 正常算式 1+1 | allow | allow | 0 | - | 通过 |
| 41 | fp | url | 商品名 select box | allow | allow | 0 | - | 通过 |
| 42 | fp | url | 地名 Union Station | allow | allow | 0 | - | 通过 |
| 43 | fp | url | 句子 I love javascript | allow | allow | 0 | - | 通过 |
| 44 | fp | url | 人名 O'Reilly | allow | allow | 0 | - | 通过 |
| 45 | fp | url | 英文引号对话 | allow | allow | 0 | - | 通过 |
| 46 | fp | url | 折扣 100% off | allow | allow | 0 | - | 通过 |
| 47 | fp | url | 竖线分隔 a|b | allow | allow | 0 | - | 通过 |
| 48 | fp | url | 日期 2019-01-01 | allow | allow | 0 | - | 通过 |
| 49 | fp | url | 短句 pass the salt & pepper | allow | allow | 0 | - | 通过 |
| 50 | fp | url | 邮箱地址 | allow | allow | 0 | - | 通过 |
| 51 | fp | url | 半角分号与冒号 | allow | allow | 0 | - | 通过 |
| 52 | fp | url | 算式 1+1=2 | allow | allow | 0 | - | 通过 |
| 53 | fp | url | 中文正文 | allow | allow | 0 | - | 通过 |
| 54 | fp | header | 请求追踪 ID | allow | allow | 0 | - | 通过 |
| 55 | fp | cookie | 正常 Cookie 主题与语言 | allow | allow | 0 | - | 通过 |
| 56 | fp | body | 正常 JSON 表单 | allow | allow | 0 | - | 通过 |
| 57 | fp | url | 文件路径参数 | allow | allow | 0 | - | 通过 |
| 58 | fp | url | 版本号字符串 | allow | allow | 0 | - | 通过 |
| 59 | fp | url | 含 and 的正常句子 | allow | allow | 0 | - | 通过 |
| 60 | fp | url | 含 or 的正常句子 | allow | allow | 0 | - | 通过 |
| 61 | normal | url | 首页 | allow | allow | 0 | - | 通过 |
| 62 | normal | url | 数字 ID 查询 | allow | allow | 0 | - | 通过 |
| 63 | normal | url | 普通搜索词 | allow | allow | 0 | - | 通过 |
| 64 | normal | url | 含单引号人名 O'Reilly | allow | allow | 0 | - | 通过 |
| 65 | normal | url | ping 本机 | allow | allow | 0 | - | 通过 |
| 66 | normal | url | DVWA 登录页 | allow | allow | 0 | - | 通过 |
| 67 | normal | body | DVWA 登录提交 | allow | allow | 0 | - | 通过 |
| 68 | normal | url | DVWA SQL 模块正常请求 | allow | allow | 0 | - | 通过 |
| 69 | normal | header | 浏览器 User-Agent | allow | allow | 0 | - | 通过 |
| 70 | normal | header | DVWA 站内 Referer | allow | allow | 0 | - | 通过 |
| 71 | normal | cookie | DVWA 会话 Cookie | allow | allow | 0 | - | 通过 |
| 72 | normal | url | 中文参数 | allow | allow | 0 | - | 通过 |
| 73 | sqli | url | UNION 基础注入 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 74 | sqli | url | UNION ALL 变体 | block | block | 15 | SQLI-UNION-001, SQLI-UNION-004 | 通过 |
| 75 | sqli | url | 注释拆关键字 un/**/ion | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 76 | sqli | url | 大小写混合 UnIoN | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 77 | sqli | url | 布尔 OR 1=1 | block | block | 11 | SQLI-BOOL-001, SQLI-BOOL-004 | 通过 |
| 78 | sqli | url | 布尔 AND 1=2 | block | block | 11 | SQLI-BOOL-002, SQLI-BOOL-004 | 通过 |
| 79 | sqli | url | 时间盲注 SLEEP | block | block | 7 | SQLI-TIME-001 | 通过 |
| 80 | sqli | url | 时间盲注 BENCHMARK | block | block | 7 | SQLI-TIME-002 | 通过 |
| 81 | sqli | url | 报错注入 EXTRACTVALUE | block | block | 11 | SQLI-ERR-001, SQLI-GEN-003 | 通过 |
| 82 | sqli | url | 报错注入 UPDATEXML | block | block | 11 | SQLI-ERR-002, SQLI-GEN-003 | 通过 |
| 83 | sqli | url | 报错注入 FLOOR(RAND) | block | block | 7 | SQLI-ERR-003 | 通过 |
| 84 | sqli | url | 堆叠查询 DROP TABLE | block | block | 8 | SQLI-STACK-001 | 通过 |
| 85 | sqli | url | 文件写入 INTO OUTFILE | block | block | 8 | SQLI-STACK-002 | 通过 |
| 86 | sqli | url | 系统表探测 information_schema | block | block | 43 | SQLI-UNION-001, SQLI-UNION-002, SQLI-UNION-003, SQLI-UNION-004, SQLI-GEN-001, SQLI-GEN-002 | 通过 |
| 87 | sqli | url | 双重 URL 编码 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 88 | sqli | body | body 表单参数注入 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 89 | sqli | body | body JSON 参数注入 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 90 | sqli | header | header 注入 User-Agent | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 91 | sqli | cookie | cookie 注入 | block | block | 22 | SQLI-UNION-001, SQLI-UNION-003, SQLI-UNION-004 | 通过 |
| 92 | sqli | url | 正常数字参数 | allow | allow | 0 | - | 通过 |
| 93 | sqli | url | 单个引号，不构成注入 | allow | allow | 0 | - | 通过 |
| 94 | xss | url | script 标签 | block | block | 20 | XSS-SCRIPT-001, XSS-SCRIPT-002, XSS-CALL-001 | 通过 |
| 95 | xss | url | img onerror 事件 | block | block | 25 | XSS-EVENT-001, XSS-EVENT-002, XSS-EVENT-003, XSS-CALL-001 | 通过 |
| 96 | xss | url | javascript 伪协议 | block | block | 13 | XSS-URI-001, XSS-CALL-001 | 通过 |
| 97 | xss | url | svg onload | block | block | 30 | XSS-EVENT-001, XSS-EVENT-002, XSS-EVENT-003, XSS-TAG-003, XSS-CALL-001 | 通过 |
| 98 | xss | url | iframe 注入 | block | block | 7 | XSS-TAG-001 | 通过 |
| 99 | xss | url | data:text/html | block | block | 7 | XSS-URI-003 | 通过 |
| 100 | xss | url | document.cookie 窃取 | block | block | 6 | XSS-DOM-001 | 通过 |
| 101 | xss | url | 外链脚本 src | block | block | 29 | XSS-SCRIPT-001, XSS-SCRIPT-002, XSS-SCRIPT-003, XSS-SCRIPT-004 | 通过 |
| 102 | xss | url | 大小写混淆 ScRiPt | block | block | 20 | XSS-SCRIPT-001, XSS-SCRIPT-002, XSS-CALL-001 | 通过 |
| 103 | xss | url | 双重 URL 编码 | block | block | 20 | XSS-SCRIPT-001, XSS-SCRIPT-002, XSS-CALL-001 | 通过 |
| 104 | xss | url | HTML 实体编码 | block | block | 20 | XSS-CALL-001, XSS-SCRIPT-001, XSS-SCRIPT-002 | 通过 |
| 105 | xss | body | body JSON 中的 XSS | block | block | 20 | XSS-SCRIPT-001, XSS-SCRIPT-002, XSS-CALL-001 | 通过 |
| 106 | xss | header | Referer 头注入 | block | block | 13 | XSS-URI-001, XSS-CALL-001 | 通过 |
| 107 | xss | cookie | cookie 中的 XSS | block | block | 20 | XSS-SCRIPT-001, XSS-SCRIPT-002, XSS-CALL-001 | 通过 |
| 108 | xss | url | body onload | block | block | 25 | XSS-EVENT-001, XSS-EVENT-002, XSS-EVENT-003, XSS-CALL-001 | 通过 |
| 109 | xss | url | a 标签 javascript 链接 | block | block | 13 | XSS-URI-001, XSS-CALL-001 | 通过 |
| 110 | xss | url | 裸 alert 调用 | block | block | 6 | XSS-CALL-001 | 通过 |
| 111 | xss | url | setTimeout 字符串执行 | block | block | 11 | XSS-EVENT-004, XSS-CALL-001 | 通过 |
| 112 | xss | url | meta refresh 伪协议 | block | block | 18 | XSS-URI-001, XSS-TAG-004, XSS-CALL-001 | 通过 |
| 113 | xss | url | fromCharCode 编码构造 | block | block | 6 | XSS-DOM-004 | 通过 |
| 114 | xss | url | 正常词 alert box | allow | allow | 0 | - | 通过 |
| 115 | xss | url | 正常词 javascript is fun | allow | allow | 0 | - | 通过 |
