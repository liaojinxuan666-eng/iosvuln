"""Acquisition layer: get a kernelcache / kext binaries from anywhere.

Supported inputs, in priority order:
  1. --kext-dir       : a directory of already-extracted kext Mach-O files
  2. --kernelcache    : an explicit path to a (decompressed) kernelcache
  3. --device         : pull from a connected jailbroken iOS device
  4. --ipsw           : extract from a full IPSW (legacy fallback)
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from .config import Config
from .ipswwrap import check_dependencies, run

DEVICE_KERNELCACHE_PATHS = [
    "/System/Library/Caches/com.apple.kernelcaches/kernelcache",
    "/System/Library/Caches/com.apple.kernelcaches/kernelcache.release",
    "/private/System/Library/Caches/com.apple.kernelcaches/kernelcache",
    "/var/MobileAsset/Assets/com_apple_MobileAsset_Kernelcache/kernelcache",
]


@dataclass
class AcquisitionResult:
    mode: str
    kernelcache: str = ""
    kext_dir: str = ""
    macho_files: List[str] = None  # type: ignore[assignment]
    commands: List[str] = None  # type: ignore[assignment]
    notes: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.macho_files is None:
            self.macho_files = []
        if self.commands is None:
            self.commands = []
        if self.notes is None:
            self.notes = []

    @property
    def ok(self) -> bool:
        return bool(self.kernelcache or self.macho_files)


class Acquisition:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dep = check_dependencies(cfg)
        os.makedirs(cfg.workdir, exist_ok=True)
        self.notes: List[str] = []
        self.commands: List[str] = []

    # ------------------------------------------------------------------ public
    def acquire(self) -> Optional[AcquisitionResult]:
        if self.cfg.kext_dir:
            return self.from_kext_dir(self.cfg.kext_dir)
        if self.cfg.kernelcache:
            return self.from_path(self.cfg.kernelcache)
        if self.cfg.device:
            return self.from_device()
        if self.cfg.ipsw_file:
            return self.from_ipsw(self.cfg.ipsw_file)
        return None

    # ----------------------------------------------------------------- helpers
    def from_path(self, path: str) -> Optional[AcquisitionResult]:
        path = os.path.abspath(os.path.expanduser(path))
        if os.path.isfile(path):
            return AcquisitionResult(mode="path", kernelcache=path, notes=[f"使用指定路径: {path}"])
        if os.path.isdir(path):
            candidates = _macho_files(path)
            if candidates:
                return AcquisitionResult(
                    mode="path", kext_dir=path, macho_files=candidates,
                    notes=[f"指定目录包含 {len(candidates)} 个 Mach-O"],
                )
        self.notes.append(f"路径不存在或不是文件/目录: {path}")
        return None

    def from_kext_dir(self, path: str) -> Optional[AcquisitionResult]:
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isdir(path):
            self.notes.append(f"kext 目录不存在: {path}")
            return None
        files = _macho_files(path)
        if not files:
            self.notes.append(f"kext 目录中没有 Mach-O: {path}")
            return None
        return AcquisitionResult(
            mode="kext-dir", kext_dir=path, macho_files=files,
            notes=[f"从目录读取 {len(files)} 个 kext Mach-O，跳过内核缓存解析"],
        )

    def from_device(self) -> Optional[AcquisitionResult]:
        """Pull the kernelcache from a connected jailbroken device."""
        remotes = [self.cfg.device_path] if self.cfg.device_path else list(DEVICE_KERNELCACHE_PATHS)
        out_dir = os.path.join(self.cfg.workdir, "from-device")
        os.makedirs(out_dir, exist_ok=True)
        ipsw = self.dep.get("ipsw")
        for remote in remotes:
            local = os.path.join(out_dir, os.path.basename(remote) or "kernelcache")
            if os.path.exists(local) and os.path.getsize(local) > 0:
                return AcquisitionResult(
                    mode="device", kernelcache=local,
                    notes=[f"复用已拉取的内核缓存: {local}"],
                )
            for argv in self._pull_commands(ipsw, remote, local):
                self.commands.append(" ".join(argv))
                result = run(argv, cwd=self.cfg.workdir, timeout=600)
                if result.ok and os.path.exists(local) and os.path.getsize(local) > 0:
                    self.notes.append(f"从设备拉取成功: {remote} -> {local}")
                    return AcquisitionResult(
                        mode="device", kernelcache=local,
                        commands=list(self.commands), notes=list(self.notes),
                    )
        self.notes.append(
            "设备拉取失败：请确认设备已越狱并连接，或显式使用 --kernelcache / --kext-dir 指定路径。"
        )
        return None

    def _pull_commands(self, ipsw: Optional[str], remote: str, local: str) -> List[List[str]]:
        commands: List[List[str]] = []
        if ipsw:
            commands += [
                [ipsw, "idev", "afc", "pull", remote, local],
                [ipsw, "idev", "pull", remote, local],
                [ipsw, "idev", "afc", "cp", remote, local],
            ]
        host = self.cfg.ssh_host or "root@localhost"
        commands.append(["scp", f"{host}:{remote}", local])
        return commands

    def from_ipsw(self, ipsw_file: str) -> Optional[AcquisitionResult]:
        # Delegate to the existing IpswTool so behaviour stays consistent.
        from .ipswwrap import IpswTool

        tool = IpswTool(self.cfg, self.dep)
        path = tool.extract_kernelcache(ipsw_file)
        if not path:
            self.notes.append("无法从 IPSW 提取 kernelcache")
            return None
        return AcquisitionResult(mode="ipsw", kernelcache=path, notes=["由 IPSW 提取 kernelcache"])


# Mach-O file magic (little-endian byte sequences at offset 0). ipsw exports
# kexts as bundle ids such as ``com.apple.iokit.IOSurface`` — a dotted name
# with no recognised extension — so extension-based filtering silently drops
# them. Sniffing the magic header is the only reliable test.
_MACHO_MAGICS = frozenset({
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64  (arm64/x86_64)
    b"\xfe\xed\xfa\xcf",  # MH_CIGAM_64
    b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit)
    b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit)
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
})


def _is_macho(path: str) -> bool:
    """True when the file starts with a Mach-O / FAT magic header."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return head in _MACHO_MAGICS


def _macho_files(root: str) -> List[str]:
    found: List[str] = []
    for path in glob.glob(os.path.join(root, "**", "*"), recursive=True):
        if not os.path.isfile(path):
            continue
        # Prefer magic sniffing; fall back to the old extension/name heuristic
        # for files we cannot open (so a transient permission error does not
        # silently drop a legitimate target).
        if _is_macho(path):
            found.append(path)
        elif path.endswith((".macho", ".dylib", ".bin", ".kext")):
            found.append(path)
    return sorted(found)[:200]
