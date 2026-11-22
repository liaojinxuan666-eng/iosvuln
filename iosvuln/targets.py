"""Analyzable target catalog and selection (single, many, indices, or all)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .models import Kext

# High-value kernel drivers / subsystems for primitive discovery.
CATALOG: List[Dict[str, str]] = [
    {
        "bundle_id": "com.apple.driver.IOSurface",
        "name": "IOSurface",
        "risk": "high",
        "description": "图像缓冲区：历史上 OOB / UAF / 提权高发面",
    },
    {
        "bundle_id": "com.apple.driver.AppleMobileFileIntegrity",
        "name": "AMFI",
        "risk": "high",
        "description": "代码签名与授权校验，沙盒逃逸/提权相关",
    },
    {
        "bundle_id": "com.apple.security.sandbox",
        "name": "Sandbox",
        "risk": "high",
        "description": "沙盒策略执行，沙盒逃逸面",
    },
    {
        "bundle_id": "com.apple.kernel.mach",
        "name": "Mach IPC",
        "risk": "high",
        "description": "Mach 端口与任务权限，提权/IPC 原语",
    },
    {
        "bundle_id": "com.apple.driver.IOKit",
        "name": "IOKit",
        "risk": "medium",
        "description": "外部方法与用户客户端入口",
    },
    {
        "bundle_id": "com.apple.driver.IOMobileFramebuffer",
        "name": "IOMobileFramebuffer",
        "risk": "medium",
        "description": "显示帧缓冲，内存映射相关",
    },
    {
        "bundle_id": "com.apple.driver.AppleHeapAllocators",
        "name": "AppleHeapAllocators",
        "risk": "medium",
        "description": "内核堆分配器，内存破坏相关",
    },
    {
        "bundle_id": "com.apple.driver.IOPlatformPluginFamily",
        "name": "IOPlatformPluginFamily",
        "risk": "low",
        "description": "电源/平台插件，IOKit 入口",
    },
    {
        "bundle_id": "com.apple.driver.AppleSEPKeyStore",
        "name": "AppleSEPKeyStore",
        "risk": "medium",
        "description": "安全隔区密钥存储，权限边界",
    },
    {
        "bundle_id": "com.apple.driver.IOUSBHostFamily",
        "name": "IOUSBHostFamily",
        "risk": "medium",
        "description": "USB 主机驱动，用户态可触达",
    },
]


@dataclass
class Target:
    bundle_id: str
    name: str = ""
    description: str = ""
    risk: str = ""
    available: bool = False
    path: str = ""
    catalog: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "bundle_id": self.bundle_id,
            "name": self.name,
            "description": self.description,
            "risk": self.risk,
            "available": self.available,
            "path": self.path,
            "catalog": self.catalog,
        }


def discover(kexts: Sequence[Kext], macho_files: Sequence[str] = ()) -> List[Target]:
    """Merge catalog entries with whatever the acquisition layer found."""
    by_id = {k.bundle_id.lower(): k for k in kexts}
    targets: List[Target] = []
    used: set = set()

    for entry in CATALOG:
        bundle_id = entry["bundle_id"]
        found = by_id.get(bundle_id.lower())
        targets.append(
            Target(
                bundle_id=bundle_id,
                name=entry["name"],
                description=entry["description"],
                risk=entry["risk"],
                available=bool(found) or _macho_match(macho_files, entry["name"]),
                path=found.path if found else _macho_path(macho_files, entry["name"]),
                catalog=True,
            )
        )
        used.add(bundle_id.lower())

    for kext in kexts:
        if kext.bundle_id.lower() in used:
            continue
        used.add(kext.bundle_id.lower())
        targets.append(
            Target(
                bundle_id=kext.bundle_id,
                name=kext.name or kext.bundle_id.rsplit(".", 1)[-1],
                description="从内核/目录发现的 kext",
                risk="low",
                available=True,
                path=kext.path,
                catalog=False,
            )
        )
    return targets


def select(
    specs: Sequence[str],
    discovered: Sequence[Target],
    max_targets: int = 12,
) -> List[Target]:
    """Resolve CLI target specs to concrete targets.

    Accepted specs:
      'all' / '*'          -> every available target (capped)
      'catalog' / 'auto'   -> catalog high+medium targets (capped)
      '1,3,5'              -> 1-based indices in the displayed list
      arbitrary string     -> bundle id / name / description substring
    """
    if not specs:
        specs = ["auto"]
    resolved: List[Target] = []
    seen: set = set()
    available = [t for t in discovered if t.available]

    def add(target: Target) -> None:
        key = target.bundle_id.lower()
        if key not in seen:
            seen.add(key)
            resolved.append(target)

    for spec in specs:
        raw = str(spec).strip()
        if not raw:
            continue
        lowered = raw.lower()
        if lowered in ("all", "*"):
            for target in available[:max_targets]:
                add(target)
            continue
        if lowered in ("auto", "catalog"):
            preferred = [t for t in available if t.catalog and t.risk in ("high", "medium")]
            for target in preferred[:max_targets]:
                add(target)
            continue
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if part.isdigit():
                index = int(part) - 1
                if 0 <= index < len(discovered):
                    target = discovered[index]
                    if target.available:
                        add(target)
                continue
            for target in discovered:
                haystack = " ".join(
                    (target.bundle_id, target.name, target.description)
                ).lower()
                if part.lower() in haystack and target.available:
                    add(target)
    return resolved[:max_targets]


def render_table(targets: Sequence[Target]) -> str:
    lines = [
        f"{'#':>3}  {'RISK':<7} {'AVAIL':<6} {'BUNDLE ID':<52} DESCRIPTION",
        "-" * 110,
    ]
    for index, target in enumerate(targets, 1):
        lines.append(
            f"{index:>3}  {target.risk:<7} "
            f"{'yes' if target.available else 'no':<6} "
            f"{target.bundle_id:<52} {target.description}"
        )
    return "\n".join(lines)


def _macho_match(files: Sequence[str], name: str) -> bool:
    return any(name.lower() in path.lower() for path in files)


def _macho_path(files: Sequence[str], name: str) -> str:
    for path in files:
        if name.lower() in path.lower():
            return path
    return ""
