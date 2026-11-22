# 虚拟机环境演示操作手册

适用环境：Windows 10 攻击机已安装 Python 3.11，靶机 Windows 7 上运行 phpStudy 与 DVWA。
WAF 部署在攻击机侧，浏览器经 127.0.0.1:8080 访问靶机。全过程不修改靶机配置，不安装额外软件。

---

## 一、调整 DVWA 安全级别

DVWA 若停留在 impossible 级别，靶场自身就会阻断全部攻击，演示时容易误判为 WAF 失效。

1. 在 Win10 打开浏览器，访问 `http://192.168.1.101/dvwa/login.php`
2. 使用账号 admin、密码 password 登录
3. 点击左侧菜单 DVWA Security
4. 下拉框选择 Low，点击 Submit
5. 页面提示 Security level is now low 即完成

---

## 二、部署 WAF 源码

在宿主机上项目位于 `D:\HarnessWorkSpace\waf-course-design\`。

**方式一：拖拽复制**

1. 在宿主机资源管理器中进入 `D:\HarnessWorkSpace\`
2. 选中 waf-course-design 文件夹
3. 拖入 VMware 中 Win10 的桌面，等待复制完成

**方式二：共享文件夹**

1. VMware 菜单 → 虚拟机 → 设置 → 选项 → 共享文件夹
2. 选择“总是启用”，添加 `D:\HarnessWorkSpace`，确定
3. 在 Win10 中访问 `\\vmware-host\Shared Folders\HarnessWorkSpace\waf-course-design`

复制完成后，在 Win10 上确认 `src\waf\rules` 目录下存在 sqli.json、xss.json、cmdi.json、
codeinj.json 四个文件。

---

## 三、启动 WAF

1. 在 Win10 按 Win + R，输入 cmd，回车
2. 依次执行：

```
cd %USERPROFILE%\Desktop\waf-course-design\src
python -m waf.main --upstream-host 192.168.1.101 --upstream-port 80 --port 8080
```

若项目不在桌面，把第一行路径改为实际位置；若提示 python 不是内部或外部命令，
改用 `py -3 -m waf.main ...`。

启动成功的标志是终端出现以下信息：

```
==============================================================
  课程设计软 WAF 已启动，反向代理模式
  监听      : http://127.0.0.1:8080
  上游应用  : http://192.168.1.101:80
  检测模式  : block    拦截阈值: 5
  规则条数  : 88
  控制台    : http://127.0.0.1:8080/__waf/console
==============================================================
```

该命令行窗口需保持运行，关闭即停止服务。

---

## 四、验证正常访问

1. 浏览器打开 `http://127.0.0.1:8080/dvwa/login.php`
2. 应出现 DVWA 登录页，使用 admin、password 可正常登录
3. 左侧菜单可正常展开

这一步说明 WAF 只做转发，不影响正常业务。

---

## 五、演示拦截

在浏览器依次访问以下地址，每个都应返回 403 拦截页：

**1. SQL 注入**

```
http://127.0.0.1:8080/dvwa/vulnerabilities/sqli/?id=1%27%20union%20select%201,2,3--&Submit=Submit
```

**2. XSS**

```
http://127.0.0.1:8080/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E
```

**3. 命令注入**

```
http://127.0.0.1:8080/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bwhoami&Submit=Submit
```

**4. 双重 URL 编码绕过**

```
http://127.0.0.1:8080/dvwa/vulnerabilities/sqli/?id=1%2520union%2520select%25201,2,3&Submit=Submit
```

拦截页会列出源 IP、累计评分、阈值、命中规则编号与原始 Payload。

---

## 六、查看实时控制台

浏览器打开：

```
http://127.0.0.1:8080/__waf/console
```

页面顶部显示请求总数、拦截数、放行数与灰度记录；下方表格按时间倒序展示每次请求的
源 IP、请求行、处置动作、评分与命中规则，并可展开查看完整请求包。

---

## 七、运行自动化演示脚本

另开一个 cmd 窗口，原窗口保持运行：

```
cd %USERPROFILE%\Desktop\waf-course-design
python tools\demo.py --waf http://127.0.0.1:8080
```

脚本会依次发送 SQL 注入、XSS、命令注入、代码注入、header 注入、cookie 注入六类 Payload，
并打印每条请求的状态码与命中规则。

---

## 八、常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| 提示 Address already in use | 8080 端口被占用 | 命令中 `--port 8080` 改为 `--port 8090`，浏览器地址同步修改 |
| 访问 127.0.0.1:8080 返回 502 | 靶机不可达 | 在 Win10 上执行 `ping 192.168.1.101` 确认连通，并确认 DVWA 地址未变 |
| 页面样式丢失或跳转异常 | 上游使用了绝对路径 | 记录具体 URL，检查代理转发路径 |
| 未出现拦截页而是直接进入 DVWA | 规则未加载 | 查看启动信息中的规则条数是否为 88，若为 0 检查 rules 目录 |
| 正常页面返回 403 | 规则误报 | 记录拦截页上的规则编号，调整该规则的子类型或分值 |


