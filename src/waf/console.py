# -*- coding: utf-8 -*-
"""可视化日志控制台。

实现方式：控制台页面由 WAF 自己提供，路径为 /__waf/console，
通过 fetch 轮询 /__waf/api/logs 与 /__waf/api/stats，不引入任何前端框架。
作用是不用 tail 日志文件就能实时看到谁、在什么位置、用什么 Payload、
命中了哪条规则、被如何处置。
"""

_CONSOLE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>课程设计软 WAF · 实时拦截控制台</title>
<style>
  :root{--bg:#0b1120;--panel:#111c33;--line:#233350;--text:#dbe6f5;--dim:#8aa0bf;--red:#f87171;--green:#4ade80;--blue:#60a5fa}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,"Microsoft YaHei",sans-serif}
  header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px}
  h1{font-size:18px;margin:0}
  .tag{font-size:12px;color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:2px 10px}
  .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:18px 24px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
  .card b{display:block;font-size:26px;margin-top:6px}
  .card span{font-size:12px;color:var(--dim)}
  main{padding:0 24px 40px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{border-bottom:1px solid var(--line);padding:8px 6px;text-align:left;vertical-align:top}
  th{color:var(--blue);font-weight:600;position:sticky;top:0;background:var(--bg)}
  .block{color:var(--red);font-weight:600}.allow{color:var(--green)}
  code{color:#fca5a5;word-break:break-all;font-size:12px}
  details summary{cursor:pointer;color:var(--dim);font-size:12px}
  pre{background:#0a1526;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12px;color:#c7d6ea}
</style>
</head>
<body>
<header>
  <h1>课程设计软 WAF · 实时拦截控制台</h1>
  <span class="tag" id="mode">模式加载中</span>
  <span class="tag" id="upstream">上游加载中</span>
  <span class="tag" id="rules">规则加载中</span>
  <span class="tag" id="clock"></span>
</header>

<section class="cards">
  <div class="card"><span>请求总数</span><b id="s-total">0</b></div>
  <div class="card"><span>已拦截</span><b id="s-blocked" class="block">0</b></div>
  <div class="card"><span>已放行</span><b id="s-allowed" class="allow">0</b></div>
  <div class="card"><span>灰度记录</span><b id="s-shadowed">0</b></div>
</section>

<main>
<table>
  <thead><tr><th>时间</th><th>源 IP</th><th>请求</th><th>动作</th><th>评分</th><th>命中规则 / 请求包</th></tr></thead>
  <tbody id="rows"><tr><td colspan="6" style="color:#8aa0bf">等待流量……</td></tr></tbody>
</table>
</main>

<script>
const LOG_API = '/__waf/api/logs?limit=100';
const STATS_API = '/__waf/api/stats';
const HEALTH_API = '/__waf/health';

function esc(s){return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

async function refresh(){
  try{
    const health = await (await fetch(HEALTH_API)).json();
    document.getElementById('mode').textContent = '模式 ' + health.mode;
    document.getElementById('upstream').textContent = '上游 ' + health.upstream;
    document.getElementById('rules').textContent = '规则 ' + health.rules + ' 条';
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();

    const stats = await (await fetch(STATS_API)).json();
    document.getElementById('s-total').textContent = stats.stats.total;
    document.getElementById('s-blocked').textContent = stats.stats.blocked;
    document.getElementById('s-allowed').textContent = stats.stats.allowed;
    document.getElementById('s-shadowed').textContent = stats.stats.shadowed;

    const logs = await (await fetch(LOG_API)).json();
    const rows = logs.items.slice().reverse().map(it => {
      const hits = (it.hits || []).map(h =>
        `<div><code>${esc(h.rule_id)}</code> ${esc(h.category)}/${esc(h.subtype)}
         · ${esc(h.location)}.${esc(h.field)} · +${h.severity} · ${esc(h.layer)}</div>
         <div><code>${esc(h.payload)}</code></div>`).join('');
      const packet = esc(JSON.stringify(it.request, null, 1));
      return `<tr>
        <td>${esc((it.time||'').replace('T',' '))}</td>
        <td>${esc(it.ip)}</td>
        <td>${esc(it.method)} <code>${esc(it.path)}</code></td>
        <td class="${it.action==='block'?'block':'allow'}">${esc(it.action)} / ${it.status||''}</td>
        <td>${it.score}</td>
        <td>${hits || '<span style="color:#8aa0bf">未命中</span>'}
          <details><summary>查看请求包</summary><pre>${packet}</pre></details></td>
      </tr>`;
    }).join('');
    document.getElementById('rows').innerHTML = rows || '<tr><td colspan="6" style="color:#8aa0bf">等待流量……</td></tr>';
  }catch(e){
    document.getElementById('clock').textContent = '控制台连接失败';
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


def render_console() -> str:
    """返回控制台页面 HTML。"""
    return _CONSOLE_HTML
