"""Markdown / JSON report generation."""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

from .models import Finding, Kext, Severity, sort_findings


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def render_markdown(
    findings: List[Finding],
    kexts: List[Kext],
    meta: Dict[str, Any],
) -> str:
    ordered = sort_findings(findings)
    sev_counts = Counter(f.severity.value for f in ordered)
    layer_counts = Counter(f.layer.value for f in ordered)
    lines: List[str] = [
        "# iosvuln 漏洞分析报告",
        "",
        f"> 生成时间：{_timestamp()}",
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

    header, rest = lines[:3], lines[3:]
    lines = header + env_lines + target_lines + rest

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
    # primary output, as requested (no exploit/PoC content).
    by_class: Dict[str, List[Finding]] = {}
    for finding in ordered:
        key = finding.vuln_class or "OTHER"
        by_class.setdefault(key, []).append(finding)
    lines += ["", "## 3.1 按原语归集的汇编位置", ""]
    if not by_class:
        lines.append("无。")
    for vuln_class, group in sorted(by_class.items()):
        lines += [f"### {vuln_class}", "", "| 函数 | 汇编地址 / 指令 | 置信度 |", "| --- | --- | ---: |"]
        for finding in group:
            for asm in (finding.assembly or ["-"])[:6]:
                safe_asm = asm.replace("|", "\\|")
                symbol = (finding.symbol or finding.location).replace("|", "\\|")
                lines.append(
                    f"| `{symbol}` | `{safe_asm}` | {finding.confidence:.2f} |"
                )
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
        if f.evidence:
            lines += ["", "**证据**", ""]
            lines += [f"- `{e}`" for e in f.evidence]
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


def write_reports(
    out_dir: str,
    findings: List[Finding],
    kexts: List[Kext],
    meta: Dict[str, Any],
) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "markdown": os.path.join(out_dir, "report.md"),
        "json": os.path.join(out_dir, "report.json"),
    }
    with open(paths["markdown"], "w", encoding="utf-8") as handle:
        handle.write(render_markdown(findings, kexts, meta))
    with open(paths["json"], "w", encoding="utf-8") as handle:
        handle.write(render_json(findings, kexts, meta))
    return paths
