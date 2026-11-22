"""Environment / device information gathering.

Priority: on-device collection.json > connected device (ipsw idev / SSH)
          > local analysis host. The result is used to adapt kernelcache
          paths, architecture assumptions and target profiling.
"""

from __future__ import annotations

import json
import os
import platform
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .config import Config
from .ipswwrap import check_dependencies, run

VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?")


@dataclass
class DeviceInfo:
    name: str = ""
    model: str = ""
    product: str = ""
    version: str = ""
    build: str = ""
    arch: str = ""
    kernel: str = ""
    hostname: str = ""
    source: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["profile"] = self.profile()
        return data

    def profile(self) -> Dict[str, Any]:
        """Derived hints used to adapt the analysis to this environment."""
        major = 0
        for value in (self.version, self.build):
            match = VERSION_RE.search(value or "")
            if match:
                major = int(match.group(1))
                break
        arch = self.arch or ("arm64e" if major >= 12 else "arm64")
        return {
            "major_version": major,
            "arch": arch,
            "pointer_authentication": major >= 12,
            "modern_kernelcache": major >= 12,
            "kernelcache_candidates": [
                "/System/Library/Caches/com.apple.kernelcaches/kernelcache",
                "/System/Library/Caches/com.apple.kernelcaches/kernelcache.release",
            ],
            "note": (
                "根据设备主版本推断，仅用于路径/架构提示"
                if major
                else "未取得系统版本，使用保守默认"
            ),
        }

    def summary(self) -> str:
        parts = [
            self.name or self.model or "unknown",
            f"iOS {self.version}" if self.version else "",
            f"build {self.build}" if self.build else "",
            self.arch,
            f"[{self.source}]" if self.source else "",
        ]
        return " ".join(p for p in parts if p)


def from_host() -> DeviceInfo:
    uname = platform.uname()
    info = DeviceInfo(
        name=uname.node,
        hostname=uname.node,
        kernel=uname.release,
        arch=uname.machine,
        source="analysis-host",
    )
    if hasattr(platform, "mac_ver"):
        mac = platform.mac_ver()
        if mac and mac[0]:
            info.product = "macOS"
            info.version = str(mac[0])
    return info


def from_collection(path: str) -> Optional[DeviceInfo]:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (ValueError, OSError):
        return None
    device = data.get("device") if isinstance(data, dict) else None
    if not isinstance(device, dict):
        return None
    return DeviceInfo(
        name=str(device.get("name", "")),
        model=str(device.get("model", "")),
        product=str(device.get("product", "")),
        version=str(device.get("version", "")),
        build=str(device.get("build", "")),
        arch=str(device.get("arch", "")),
        kernel=str(device.get("kernel", "")),
        hostname=str(device.get("hostname", "")),
        source="device-collection.json",
        raw=device,
    )


def from_device(cfg: Config, dep: Optional[Dict[str, Any]] = None) -> Optional[DeviceInfo]:
    dep = dep or check_dependencies(cfg)
    ipsw = dep.get("ipsw")
    host = cfg.ssh_host or "root@localhost"

    if ipsw:
        for argv in (
            [ipsw, "idev", "list", "--json"],
            [ipsw, "idev", "info", "--json"],
        ):
            result = run(argv, timeout=60)
            if not result.ok:
                continue
            try:
                payload = json.loads(result.stdout)
                item = payload[0] if isinstance(payload, list) and payload else payload
                if isinstance(item, dict):
                    return DeviceInfo(
                        name=str(item.get("name", item.get("deviceName", ""))),
                        model=str(item.get("model", item.get("productType", ""))),
                        version=str(item.get("version", item.get("osVersion", ""))),
                        build=str(item.get("build", item.get("buildVersion", ""))),
                        arch=str(item.get("arch", "")),
                        source="ipsw idev",
                        raw=item,
                    )
            except (ValueError, TypeError):
                continue

    script = (
        "sw_vers 2>/dev/null; "
        "sysctl -n hw.model 2>/dev/null; "
        "sysctl -n kern.osproductversion 2>/dev/null; "
        "sysctl -n kern.osversion 2>/dev/null; "
        "uname -m 2>/dev/null"
    )
    result = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, script], timeout=30)
    if result.ok and result.stdout.strip():
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        info = DeviceInfo(source=f"ssh {host}", raw={"lines": lines})
        for line in lines:
            if line.startswith("ProductName:"):
                info.product = line.split(":", 1)[1].strip()
            elif line.startswith("ProductVersion:"):
                info.version = line.split(":", 1)[1].strip()
            elif line.startswith("BuildVersion:"):
                info.build = line.split(":", 1)[1].strip()
            elif line.startswith("iPhone") or line.startswith("iPad"):
                info.model = line
            elif re.fullmatch(r"arm64e?", line):
                info.arch = line
            elif re.fullmatch(r"\d+[A-Z]\d+", line):
                info.build = info.build or line
        info.name = info.model
        return info
    return None


def gather(
    cfg: Config,
    dep: Optional[Dict[str, Any]] = None,
    collection_path: str = "",
) -> DeviceInfo:
    """Combine all available sources into one DeviceInfo."""
    base = from_host()
    device = None
    if cfg.device or cfg.device_path or cfg.ssh_host:
        device = from_device(cfg, dep)
    if device is None:
        device = from_collection(collection_path or os.path.join(cfg.workdir, "collection.json"))
    if device is None:
        return base
    # Fill gaps from the local host without overwriting device values.
    for field_name in ("name", "model", "product", "version", "build", "arch", "kernel", "hostname"):
        if not getattr(device, field_name):
            setattr(device, field_name, getattr(base, field_name, ""))
    device.raw["analysis_host"] = base.summary()
    return device
