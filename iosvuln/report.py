"""Markdown / HTML / JSON report generation."""

from __future__ import annotations

import html
import json
import os
from collections import Counter, OrderedDict
from datetime import datetime
from typing import Any, Dict, List

from .models import Finding, Kext, Severity, sort_findings


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# Human-friendly labels / colors for each primitive class (used by MD + HTML).
CLASS_INFO: Dict[str, tuple] = {
    "DANGLING_POINTER": ("野指针 / UAF", "#d32f2f"),
    "DOUBLE_FREE": ("重复释放", "#c62828"),
    "NULL_DEREF": ("空指针解引用", "#e65100"),
    "OOB_READ": ("越界读", "#ef6c00"),
    "OOB_WRITE": ("越界写 / 内存破坏", "#d84315"),
    "MEMORY_CORRUPTION": ("内存破坏", "#b71c1c"),
    "INTEGER_OVERFLOW": ("整数溢出", "#f9a825"),
    "PRIVILEGE_ESCALATION": ("权限提升", "#6a1b9a"),
    "SANDBOX_ESCAPE": ("沙盒逃逸", "#4527a0"),
    "RCE": ("控制流劫持 / RCE", "#ad1457"),
    "RACE": ("竞态条件", "#00838f"),
    "UAF": ("释放后使用", "#c62828"),
    "INFO_LEAK": ("信息泄露", "#1565c0"),
    # arm64e PAC
    "PAC_BYPASS": ("PAC 绕过 / 签名剥离", "#880e4f"),
    "PAC_DOWNGRADE": ("PAC 降级 / 未启用", "#4a148c"),
    "PAC_SIGN_MISMATCH": ("PAC 密钥/验证失衡", "#6a1b9a"),
    # broadened static classes
    "FORMAT_STRING": ("格式化字符串", "#e65100"),
    "UNINITIALIZED": ("未初始化内存", "#1565c0"),
    "TOCTOU": ("TOCTOU / 双重取数", "#00695c"),
    "STACK_OVERFLOW": ("栈溢出风险", "#bf360c"),
    "TYPE_CONFUSION": ("类型混淆", "#311b92"),
    "OTHER": ("其他", "#555"),
}

SEV_COLOR = {
    "CRITICAL": "#b71c1c", "HIGH": "#d32f2f", "MEDIUM": "#f9a825",
    "LOW": "#2e7d32", "INFO": "#616161",
}


def _class_label(key: str) -> str:
    return CLASS_INFO.get(key, (key, "#555"))[0]


def _group_by_class(ordered: List[Finding]) -> "OrderedDict[str, List[Finding]]":
    groups: "OrderedDict[str, List[Finding]]" = OrderedDict()
    for finding in ordered:
        key = finding.vuln_class or "OTHER"
        groups.setdefault(key, []).append(finding)
    return groups


def render_markdown(
    findings: List[Finding],
    kexts: List[Kext],
    meta: Dict[str, Any],
) -> str:
    ordered = sort_findings(findings)
    sev_counts = Counter(f.severity.value for f in ordered)
    layer_counts = Counter(f.layer.value for f in ordered)
    groups = _group_by_class(ordered)

    # --- Executive summary + table of contents -----------------------------
    lines: List[str] = [
        "# iosvuln 漏洞分析报告",
        "",
        f"> 生成时间：{_timestamp()}",
        "",
        "## 摘要",
        "",
        f"共发现 **{len(ordered)}** 条疑似漏洞线索，涉及 **{len(groups)}** 类漏洞原语；"
        f"其中高危及以上 **{sev_counts.get('CRITICAL', 0) + sev_counts.get('HIGH', 0)}** 条。",
        "",
        "| 漏洞类别 | 数量 | 最高严重度 |",
        "| --- | ---: | --- |",
    ]
    for key, group in groups.items():
        top = group[0].severity.value
        lines.append(f"| {_class_label(key)} (`{key}`) | {len(group)} | {top} |")
    lines += [
        "",
        "**目录**",
        "",
        "- [0. 环境信息](#0-环境信息)",
        "- [0.1 可分析目标](#01-可分析目标)",
        "- [1. 流水线概览](#1-流水线概览)",
        "- [2. 结果统计](#2-结果统计)",
        "- [3. 疑似漏洞清单](#3-疑似漏洞清单)",
        "- [3.1 按原语归集的汇编位置](#31-按原语归集的汇编位置)",
        "- [4. 详细线索](#4-详细线索)",
        "- [5. Kext 清单](#5-kext-清单)",
        "",
        "## 1. 流水线概览",
        "",
        "| 项目 | 值 |",
        "| --- | --- |",
        f"| 目标 kext | `{meta.get('target', '')}` |",
        f"| 内核缓存 | `{meta.get('kernelcache', '')}` |",
        f"| 分析后端 | `{meta.get('backend', 'n/a')}` |",
        f"| 静态函数数 | {meta.get('function_count', 0)} |",
        f"| 依赖状态 | ipsw={meta.get('ipsw', 'missing')}, r2={meta.get('r2', 'missing')} |",
        "",
    ]
    env = meta.get("device", {}) or {}
    profile = env.get("profile", {}) or {}
    env_lines = [
        "## 0. 环境信息",
        "",
        "| 项目 | 值 |",
        "| --- | --- |",
        f"| 设备 | {env.get('name') or env.get('model') or '-'} |",
        f"| 产品 / 版本 | {env.get('product') or '-'} {env.get('version') or ''} |",
        f"| Build | {env.get('build') or '-'} |",
        f"| 架构 | {env.get('arch') or profile.get('arch') or '-'} |",
        f"| 内核 | {env.get('kernel') or '-'} |",
        f"| 信息来源 | {env.get('source') or '-'} |",
        f"| 版本推断 | major={profile.get('major_version', '-')}, PAC={profile.get('pointer_authentication')} |",
        f"| 长期存储 | {meta.get('home') or '-'} ({'已归档' if meta.get('archived') else '未归档'}) |",
        "",
    ]

    selected = meta.get("targets", []) or []
    available = meta.get("available_targets", []) or []
    selected_ids = {t.get("bundle_id") for t in selected}
    target_lines = [
        "## 0.1 可分析目标",
        "",
        f"已选 {len(selected)} 项；目录共 {len(available)} 项，可用 "
        f"{sum(1 for t in available if t.get('available'))} 项。",
        "",
        "| # | Bundle ID | 风险 | 可用 | 已选 | 说明 |",
        "| ---: | --- | --- | --- | --- | --- |",
    ]
    for index, target in enumerate(available, 1):
        target_lines.append(
            f"| {index} | `{target.get('bundle_id', '')}` | {target.get('risk', '')} | "
            f"{'yes' if target.get('available') else 'no'} | "
            f"{'YES' if target.get('bundle_id') in selected_ids else ''} | "
            f"{target.get('description', '')} |"
        )
    target_lines.append("")

    # Insert env (§0) and targets (§0.1) right after the title block, before
    # the summary/TOC that were built at the top of lines.
    lines = lines[:3] + [""] + env_lines + target_lines + lines[3:]

    warnings = meta.get("warnings", [])
    if warnings:
        lines += ["**注意事项**", ""]
        lines += [f"- {w}" for w in warnings]
        lines += [""]

    lines += [
        "## 2. 结果统计",
        "",
        "| 严重度 | 数量 |",
        "| --- | ---: |",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {sev_counts.get(sev, 0)} |")
    lines += [
        "",
        f"静态层 {layer_counts.get('static', 0)} 条，Hook 层 {layer_counts.get('hook', 0)} 条。",
        "",
        "## 3. 疑似漏洞清单",
        "",
    ]
    if not ordered:
        lines.append("未发现满足当前阈值的线索。可放宽 `--min-severity` 或补充 hook 观测日志。")
    else:
        lines += [
            "| ID | 原语 | 严重度 | 层级 | 标题 | 汇编位置 | 评分 |",
            "| --- | --- | --- | --- | --- | --- | ---: |",
        ]
        for f in ordered:
            loc = f.location.replace("|", "\\|")
            title = f.title.replace("|", "\\|")
            asm = f.assembly[0].replace("|", "\\|") if f.assembly else "-"
            lines.append(
                f"| `{f.id}` | {f.vuln_class or '-'} | {f.severity.value} | {f.layer.value} | "
                f"{title} | `{asm}` | {f.score:.0f} |"
            )

    # Group by vulnerability primitive so the assembly locations are the
    # primary output (no exploit/PoC content). ALL assembly lines are kept.
    lines += ["", "## 3.1 按原语归集的汇编位置", ""]
    if not groups:
        lines.append("无。")
    for vuln_class, group in groups.items():
        label = _class_label(vuln_class)
        lines += [
            f"### {label} (`{vuln_class}`) — {len(group)} 条",
            "",
            "| 函数 | 汇编地址 / 指令 | 严重度 | 置信度 |",
            "| --- | --- | --- | ---: |",
        ]
        for finding in group:
            symbol = (finding.symbol or finding.location).replace("|", "\\|")
            assembly = finding.assembly or ["-"]
            for index, asm in enumerate(assembly):
                safe_asm = asm.replace("|", "\\|")
                sym = symbol if index == 0 else ""
                sev = finding.severity.value if index == 0 else ""
                conf = f"{finding.confidence:.2f}" if index == 0 else ""
                lines.append(f"| `{sym}` | `{safe_asm}` | {sev} | {conf} |")
        lines.append("")

    lines += ["## 4. 详细线索", ""]
    for index, f in enumerate(ordered, 1):
        lines += [
            f"### {index}. [{f.severity.value}] {f.title}",
            "",
            f"- **ID**: `{f.id}`",
            f"- **层级 / 目标**: {f.layer.value} / `{f.target}`",
            f"- **位置**: `{f.location}`",
            f"- **评分 / 置信度**: {f.score:.0f} / {f.confidence:.2f}",
        ]
        if f.cwe:
            lines.append(f"- **分类**: {f.cwe}")
        if f.description:
            lines += ["", f.description]
        if f.assembly:
            lines += ["", "**汇编位置**", ""]
            lines += [f"- `{a}`" for a in f.assembly]
        if f.evidence:
            # Avoid duplicating the exact same lines shown as assembly.
            extra = [e for e in f.evidence if e not in f.assembly]
            if extra:
                lines += ["", "**证据**", ""]
                lines += [f"- `{e}`" for e in extra]
        if f.recommendation:
            lines += ["", f"**建议**: {f.recommendation}"]
        lines += [""]

    lines += [
        "## 5. Kext 清单",
        "",
        "| Bundle ID | 版本 | 目标 |",
        "| --- | --- | --- |",
    ]
    for k in kexts[:80]:
        mark = "是" if k.is_target else ""
        lines.append(f"| `{k.bundle_id}` | {k.version} | {mark} |")
    if len(kexts) > 80:
        lines.append(f"| ... | 其余 {len(kexts) - 80} 项 | |")

    lines += [
        "",
        "---",
        "",
        "本报告只标注漏洞原语类别与对应汇编地址，**不生成 PoC 或利用代码**。",
        "所有条目都是审计线索，需要人工复核数据流与可利用性；ElleKit 组件为提取式，不改写任何函数行为。",
        "",
    ]
    return "\n".join(lines)


def render_json(
    findings: List[Finding],
    kexts: List[Kext],
    meta: Dict[str, Any],
) -> str:
    payload = {
        "generated_at": _timestamp(),
        "meta": meta,
        "kexts": [k.to_dict() for k in kexts],
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_html(
    findings: List[Finding],
    kexts: List[Kext],
    meta: Dict[str, Any],
) -> str:
    """A self-contained, readable HTML report (no external assets)."""
    ordered = sort_findings(findings)
    groups = _group_by_class(ordered)
    sev_counts = Counter(f.severity.value for f in ordered)
    esc = html.escape

    env = meta.get("device", {}) or {}
    profile = env.get("profile", {}) or {}
    high = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)

    parts: List[str] = []
    add = parts.append
    add("<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>")
    add("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    add("<title>iosvuln 漏洞分析报告</title>")
    add("<style>")
    add("""
:root{--bg:#0f1115;--card:#1a1d24;--line:#2b303b;--fg:#e6e8ee;--muted:#9aa3b2;--accent:#4fc3f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:19px;margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
h3{font-size:16px;margin:20px 0 10px}
.meta{color:var(--muted);font-size:13px;margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:28px;font-weight:700}
.card .l{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;margin:10px 0;background:var(--card);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
code{font-family:"SFMono-Regular",Consolas,Menlo,monospace;font-size:12px;color:#b9d9ff;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff}
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;margin:12px 0;overflow:hidden}
.finding summary{padding:12px 14px;cursor:pointer;font-weight:600}
.finding .body{padding:0 14px 14px}
.kv{color:var(--muted);font-size:13px}
.asm{background:#0b0d11;border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin:8px 0;white-space:pre-wrap;word-break:break-all}
.rec{color:#ffd54f}
.toc a{color:var(--accent);text-decoration:none;margin-right:14px}
.note{color:var(--muted);border-top:1px solid var(--line);margin-top:36px;padding-top:16px;font-size:13px}
""")
    add("</style></head><body><div class='wrap'>")
    add(f"<h1>iosvuln 漏洞分析报告</h1>")
    add(f"<div class='meta'>生成时间 {esc(_timestamp())} · 目标 {esc(str(meta.get('target','')))}"
        f" · 后端 {esc(str(meta.get('backend','n/a')))}</div>")

    add("<div class='cards'>")
    for label, num in (("疑似漏洞", len(ordered)), ("漏洞类别", len(groups)),
                       ("高危及以上", high), ("静态函数", meta.get('function_count', 0))):
        add(f"<div class='card'><div class='n'>{num}</div><div class='l'>{label}</div></div>")
    add("</div>")

    add("<p class='toc'>")
    add("<a href='#env'>环境</a><a href='#stat'>统计</a><a href='#prim'>原语归集</a><a href='#detail'>详细线索</a>")
    add("</p>")

    add("<h2 id='env'>环境信息</h2><table>")
    env_rows = (
        ("设备", env.get('name') or env.get('model') or '-'),
        ("系统", f"{env.get('product','')} {env.get('version','')}".strip() or '-'),
        ("Build", env.get('build') or '-'),
        ("架构", env.get('arch') or profile.get('arch') or '-'),
        ("内核", env.get('kernel') or '-'),
        ("长期存储", meta.get('home') or '-'),
    )
    for k, v in env_rows:
        add(f"<tr><th>{esc(str(k))}</th><td>{esc(str(v))}</td></tr>")
    add("</table>")

    add("<h2 id='stat'>结果统计</h2><table><tr><th>严重度</th><th>数量</th></tr>")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        add(f"<tr><td><span class='badge' style='background:{SEV_COLOR[sev]}'>{sev}</span></td>"
            f"<td>{sev_counts.get(sev, 0)}</td></tr>")
    add("</table>")

    warnings = meta.get("warnings", []) or []
    if warnings:
        add("<h3>注意事项</h3><ul>")
        for w in warnings:
            add(f"<li>{esc(str(w))}</li>")
        add("</ul>")

    add("<h2 id='prim'>按原语归集的汇编位置</h2>")
    if not groups:
        add("<p>未发现满足阈值的线索。</p>")
    for key, group in groups.items():
        label, color = CLASS_INFO.get(key, (key, "#555"))
        add(f"<h3><span class='badge' style='background:{color}'>{esc(key)}</span> "
            f"{esc(label)} — {len(group)} 条</h3>")
        add("<table><tr><th>函数</th><th>汇编地址 / 指令</th><th>严重度</th><th>置信度</th></tr>")
        for f in group:
            sym = f.symbol or f.location
            for index, asm in enumerate(f.assembly or ["-"]):
                s = esc(sym) if index == 0 else ""
                sev = (
                    f"<span class='badge' style='background:{SEV_COLOR[f.severity.value]}'>"
                    f"{f.severity.value}</span>" if index == 0 else ""
                )
                conf = f"{f.confidence:.2f}" if index == 0 else ""
                add(f"<tr><td><code>{s}</code></td><td><code>{esc(asm)}</code></td>"
                    f"<td>{sev}</td><td>{conf}</td></tr>")
        add("</table>")

    add("<h2 id='detail'>详细线索</h2>")
    for index, f in enumerate(ordered, 1):
        color = SEV_COLOR[f.severity.value]
        add(f"<details class='finding' style='border-left-color:{color}'>")
        add(f"<summary>{index}. <span class='badge' style='background:{color}'>{f.severity.value}</span> "
            f"{esc(f.title)}</summary><div class='body'>")
        add(f"<div class='kv'>ID <code>{esc(f.id)}</code> · 层级 {esc(f.layer.value)} · "
            f"目标 <code>{esc(f.target)}</code> · 评分 {f.score:.0f} · 置信度 {f.confidence:.2f}</div>")
        add(f"<div class='kv'>位置 <code>{esc(f.location)}</code></div>")
        if f.cwe:
            add(f"<div class='kv'>分类 {esc(f.cwe)}</div>")
        if f.description:
            add(f"<p>{esc(f.description)}</p>")
        if f.assembly:
            add("<div class='asm'>" + "\n".join(esc(a) for a in f.assembly) + "</div>")
        if f.recommendation:
            add(f"<p class='rec'>建议：{esc(f.recommendation)}</p>")
        add("</div></details>")

    add("<p class='note'>本报告只标注漏洞原语类别与对应汇编地址，不生成 PoC 或利用代码。"
        "所有条目均为审计线索，需人工复核数据流与可利用性；ElleKit 组件为提取式，不改写任何函数行为。</p>")
    add("</div></body></html>")
    return "\n".join(parts)


def write_reports(
    out_dir: str,
    findings: List[Finding],
    kexts: List[Kext],
    meta: Dict[str, Any],
) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "markdown": os.path.join(out_dir, "report.md"),
        "html": os.path.join(out_dir, "report.html"),
        "json": os.path.join(out_dir, "report.json"),
    }
    with open(paths["markdown"], "w", encoding="utf-8") as handle:
        handle.write(render_markdown(findings, kexts, meta))
    with open(paths["html"], "w", encoding="utf-8") as handle:
        handle.write(render_html(findings, kexts, meta))
    with open(paths["json"], "w", encoding="utf-8") as handle:
        handle.write(render_json(findings, kexts, meta))
    return paths
