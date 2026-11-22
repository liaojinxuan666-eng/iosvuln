"""ElleKit userspace hook layer: scaffold generation + log-to-finding bridge."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional

from .models import Finding, HookObservation, Layer, Severity
from .plugins import AnalysisContext, Plugin, register

TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "ellekit"
)
LOG_TAG = "[IOSVULN]"
KV_RE = re.compile(r"(\w+)=(\S+)")


def generate_tweak(workdir: str) -> str:
    """Copy the ElleKit/Theos observation tweak into the work directory."""
    dest = os.path.join(workdir, "ellekit")
    os.makedirs(dest, exist_ok=True)
    for name in ("Tweak.xm", "Makefile", "control", "iosvuln_extract.plist"):
        src = os.path.join(TEMPLATE_DIR, name)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(dest, name))
    readme = os.path.join(dest, "README.txt")
    with open(readme, "w", encoding="utf-8") as handle:
        handle.write(
            "EXTRACTIVE MODE: this tweak never modifies a function.\n"
            "It resolves IOSurface.framework symbols with MSFindSymbol and writes\n"
            "/var/mobile/iosvuln/extracted.json (address + raw instruction bytes).\n"
            "Build: THEOS_PACKAGE_SCHEME=rootless make package\n"
            "Pull the JSON with: scp root@localhost:/var/mobile/iosvuln/extracted.json .\n"
            "Then: iosvuln run --kext-dir <dir> --workdir <dir>\n"
        )
    return dest


def parse_syslog(text: str) -> List[HookObservation]:
    """Parse '[IOSVULN] FuncName key=value ...' lines into observations."""
    observations: List[HookObservation] = []
    for line in text.splitlines():
        if LOG_TAG not in line:
            continue
        body = line.split(LOG_TAG, 1)[1].strip()
        parts = body.split()
        if not parts:
            continue
        function = parts[0]
        args: Dict[str, Any] = {}
        for key, value in KV_RE.findall(body):
            if re.fullmatch(r"-?\d+", value):
                args[key] = int(value)
            elif re.fullmatch(r"0x[0-9a-fA-F]+", value):
                args[key] = int(value, 16)
            else:
                args[key] = value
        observations.append(
            HookObservation(
                function=function,
                pid=int(args.pop("pid", 0) or 0),
                process=str(args.pop("proc", "")),
                arguments=args,
            )
        )
    return observations


def load_observations(path: str) -> List[HookObservation]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_syslog(handle.read())


def load_extracted(path: str) -> List[HookObservation]:
    """Read the extractive tweak's JSON dump into observations."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (ValueError, OSError):
        return []
    result: List[HookObservation] = []
    for item in data.get("functions", []):
        result.append(
            HookObservation(
                function=str(item.get("name", "")),
                arguments={
                    "address": str(item.get("address", "")),
                    "bytes": str(item.get("bytes", "")),
                },
                note="extractive-hook",
            )
        )
    return result


def _obs_id(plugin: str, title: str, detail: str) -> str:
    raw = f"{plugin}|{title}|{detail}".encode("utf-8", "replace")
    return hashlib.md5(raw).hexdigest()[:10]


@register
class HookObservationPlugin(Plugin):
    name = "hook-observation"
    description = "归并 ElleKit 用户态观测日志，生成动态层线索"
    layer = "hook"

    def run(self, context: AnalysisContext) -> List[Finding]:
        observations: Iterable[HookObservation] = context.observations
        observations = list(observations)
        if not observations:
            return []
        findings: List[Finding] = []
        target = context.manifest.target

        extracted = [o for o in observations if o.note == "extractive-hook"]
        if extracted:
            assembly = [
                f"{o.arguments.get('address', '')}: {str(o.arguments.get('bytes', ''))[:64]}"
                for o in extracted
            ]
            findings.append(
                Finding(
                    id=_obs_id(self.name, "extracted-symbols", "all"),
                    title="[EXTRACT] 已导出函数地址与机器码",
                    severity=Severity.INFO,
                    layer=Layer.HOOK,
                    target=target,
                    description=(
                        f"提取式 tweak 导出 {len(extracted)} 个 IOSurface.framework 函数地址；"
                        "未改写任何函数行为。"
                    ),
                    location="IOSurface.framework",
                    evidence=assembly,
                    score=10.0,
                    confidence=1.0,
                    vuln_class="OTHER",
                    assembly=assembly,
                    symbol="IOSurface.framework",
                    recommendation="按汇编地址在反汇编器中定位，核对参数来源与边界检查。",
                    tags=["extractive-hook"],
                )
            )

        # 1) unusually large allocation requests
        for obs in observations:
            size = obs.arguments.get("allocSize")
            if isinstance(size, int) and size > 32 * 1024 * 1024:
                findings.append(
                    Finding(
                        id=_obs_id(self.name, "large-alloc", f"{obs.function}:{size}"),
                        title="用户态请求超大 surface 分配",
                        severity=Severity.HIGH if size > 256 * 1024 * 1024 else Severity.MEDIUM,
                        layer=Layer.HOOK,
                        target=target,
                        vuln_class="INTEGER_OVERFLOW",
                        symbol=obs.function,
                        description=(
                            f"{obs.function} 观测到 allocSize={size} 字节"
                            f"（pid={obs.pid}, 进程={obs.process}），可能触发内核侧整数溢出或内存压力。"
                        ),
                        location=obs.function,
                        evidence=[f"allocSize={size}", f"pid={obs.pid}"],
                        score=55.0 if size <= 256 * 1024 * 1024 else 72.0,
                        confidence=0.7,
                        cwe="CWE-190 Integer Overflow or Wraparound",
                        recommendation="复现该尺寸组合，检查内核中 size * bytesPerRow / elements 的计算。",
                        tags=["hook", "allocation"],
                    )
                )

        # 2) lock/unlock imbalance observed per process
        locks: Dict[int, Counter] = defaultdict(Counter)
        for obs in observations:
            if obs.function in ("IOSurfaceLock", "IOSurfaceUnlock"):
                locks[obs.pid][obs.function] += 1
        for pid, counter in locks.items():
            diff = counter["IOSurfaceLock"] - counter["IOSurfaceUnlock"]
            if diff > 2:
                findings.append(
                    Finding(
                        id=_obs_id(self.name, "lock-imbalance", str(pid)),
                        title="用户态观察到 Lock/Unlock 次数不平衡",
                        severity=Severity.MEDIUM,
                        layer=Layer.HOOK,
                        target=target,
                        vuln_class="RACE",
                        symbol="IOSurfaceLock/IOSurfaceUnlock",
                        description=(
                            f"pid={pid} 调用 Lock {counter['IOSurfaceLock']} 次、"
                            f"Unlock {counter['IOSurfaceUnlock']} 次；可能与异常路径或崩溃有关。"
                        ),
                        location="IOSurfaceLock/IOSurfaceUnlock",
                        evidence=[f"lock={counter['IOSurfaceLock']}", f"unlock={counter['IOSurfaceUnlock']}"],
                        score=45.0,
                        confidence=0.6,
                        cwe="CWE-667 Improper Locking",
                        recommendation="结合崩溃日志确认是否在持锁状态下释放 surface 对象。",
                        tags=["hook", "locking"],
                    )
                )

        # 3) repeated property writes -> fuzzing / race signal
        key_counts = Counter(
            (obs.function, str(obs.arguments.get("key", "")))
            for obs in observations
            if obs.function == "IOSurfaceSetValue"
        )
        for (function, key), count in key_counts.items():
            if count >= 8:
                findings.append(
                    Finding(
                        id=_obs_id(self.name, "repeated-prop", f"{key}:{count}"),
                        title="属性被高频重复写入",
                        severity=Severity.LOW,
                        layer=Layer.HOOK,
                        target=target,
                        vuln_class="RACE",
                        symbol=function,
                        description=f"{function} 对 key={key!r} 写入 {count} 次，疑似竞态测试或异常重试。",
                        location=function,
                        evidence=[f"key={key}", f"count={count}"],
                        score=28.0,
                        confidence=0.55,
                        cwe="CWE-362 Race Condition",
                        recommendation="在内核侧核对属性字典的并发读写保护。",
                        tags=["hook", "race"],
                    )
                )
        return findings
