"""ipsw orchestration layer: IPSW -> kernelcache -> decompressed -> kexts.

Every external command is probed at runtime; a missing binary never crashes the
pipeline. In demo mode the same interface is backed by checked-in JSON fixtures.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config import Config
from .models import Kext

BUNDLE_RE = re.compile(r"(?:com|org)\.apple\.[A-Za-z0-9._-]+")
VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)\b", re.IGNORECASE)


@dataclass
class CommandResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def run(argv: List[str], cwd: Optional[str] = None, timeout: int = 900) -> CommandResult:
    """Run a command, capturing text output without raising on failure."""
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "")
    except FileNotFoundError as exc:
        return CommandResult(argv, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        return CommandResult(argv, 124, exc.stdout or "", f"timeout after {timeout}s")


def check_dependencies(cfg: Config) -> Dict[str, Any]:
    ipsw = which(cfg.ipsw_path) if not os.path.isabs(cfg.ipsw_path) else (
        cfg.ipsw_path if os.path.exists(cfg.ipsw_path) else None
    )
    r2 = which(cfg.r2_path) if not os.path.isabs(cfg.r2_path) else (
        cfg.r2_path if os.path.exists(cfg.r2_path) else None
    )
    status: Dict[str, Any] = {
        "ipsw": ipsw,
        "r2": r2,
        "r2pipe": False,
    }
    if ipsw:
        res = run([ipsw, "version"], timeout=30)
        status["ipsw_version"] = (res.stdout or res.stderr).strip().splitlines()[:1]
    try:
        import r2pipe  # noqa: F401

        status["r2pipe"] = True
    except ImportError:
        pass
    return status


def _find_newest(pattern: str, root: str, exclude: List[str] = ()) -> Optional[str]:
    import glob

    matches = [p for p in glob.glob(os.path.join(root, pattern), recursive=True) if p not in exclude]
    if not matches:
        return None
    return max(matches, key=lambda p: os.path.getmtime(p))


def parse_kexts(text: str) -> List[Kext]:
    """Parse `ipsw kernel kexts` output (JSON or human-readable text)."""
    stripped = text.strip()
    result: List[Kext] = []
    if stripped.startswith(("[", "{")):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                data = data.get("kexts", data.get("k_exts", []))
            for item in data if isinstance(data, list) else []:
                if isinstance(item, str):
                    result.append(Kext(bundle_id=item))
                elif isinstance(item, dict):
                    bid = (
                        item.get("bundle_id")
                        or item.get("bundleID")
                        or item.get("id")
                        or item.get("name")
                        or ""
                    )
                    if bid:
                        result.append(
                            Kext(
                                bundle_id=str(bid),
                                name=str(item.get("name", "")),
                                version=str(item.get("version", "")),
                                path=str(item.get("path", "")),
                                size=int(item.get("size", 0) or 0),
                            )
                        )
            if result:
                return _dedup(result)
        except (ValueError, TypeError):
            pass  # fall through to text parsing

    seen = set()
    for line in stripped.splitlines():
        match = BUNDLE_RE.search(line)
        if not match:
            continue
        bid = match.group(0).rstrip(".")
        if bid in seen:
            continue
        seen.add(bid)
        version_match = VERSION_RE.search(line[match.end():]) or VERSION_RE.search(line)
        result.append(
            Kext(
                bundle_id=bid,
                name=bid.rsplit(".", 1)[-1],
                version=version_match.group(1) if version_match else "",
                path="",
            )
        )
    return _dedup(result)


def _dedup(kexts: List[Kext]) -> List[Kext]:
    seen: Dict[str, Kext] = {}
    for k in kexts:
        if k.bundle_id not in seen:
            seen[k.bundle_id] = k
    return list(seen.values())


class IpswTool:
    """Thin, defensive wrapper around the ipsw CLI."""

    def __init__(self, cfg: Config, dependency: Optional[Dict[str, Any]] = None):
        self.cfg = cfg
        self.dep = dependency if dependency is not None else check_dependencies(cfg)
        self.binary = self.dep.get("ipsw")
        self.log: List[CommandResult] = []
        os.makedirs(cfg.workdir, exist_ok=True)

    @property
    def available(self) -> bool:
        return self.binary is not None

    def _run(self, argv: List[str]) -> CommandResult:
        res = run(argv, cwd=self.cfg.workdir)
        self.log.append(res)
        return res

    def extract_kernelcache(self, ipsw_file: str) -> Optional[str]:
        if not self.available:
            return None
        ipsw_file = os.path.abspath(os.path.expanduser(ipsw_file))
        before = set(os.listdir(self.cfg.workdir))
        res = self._run([self.binary, "extract", "--kernel", ipsw_file])
        if not res.ok:
            return None
        after = set(os.listdir(self.cfg.workdir))
        for path in _find_newest_candidates(after - before, self.cfg.workdir, "kernelcache"):
            return path
        return _find_newest("kernelcache*", self.cfg.workdir)

    def decompress(self, kernelcache: str) -> Optional[str]:
        """Produce a decompressed Mach-O. Tries several ipsw spellings."""
        out_dir = os.path.join(self.cfg.workdir, "decompressed")
        os.makedirs(out_dir, exist_ok=True)
        existing = _find_newest("**/kernelcache.decompressed", self.cfg.workdir)
        if existing:
            return existing
        if not self.available:
            return None
        attempts = [
            [self.binary, "kernel", "decompress", kernelcache, "-o", out_dir],
            [self.binary, "kernel", "decomp", kernelcache, "-o", out_dir],
            [self.binary, "kernel", "extract", "--decompress", kernelcache, "-o", out_dir],
        ]
        for argv in attempts:
            res = self._run(argv)
            found = _find_newest("**/kernelcache.decompressed", out_dir) or _find_newest(
                "**/*decompressed*", out_dir
            )
            if res.ok and found:
                return found
        return None

    def list_kexts(self, kernelcache: str) -> List[Kext]:
        if not self.available:
            return []
        for argv in (
            [self.binary, "kernel", "kexts", kernelcache, "--json"],
            [self.binary, "kernel", "kexts", kernelcache],
        ):
            res = self._run(argv)
            if not res.ok:
                continue
            parsed = parse_kexts(res.stdout)
            if parsed:
                return parsed
        return []

    def extract_kext(self, kernelcache: str, bundle_id: str) -> Optional[str]:
        if not self.available:
            return None
        out_dir = os.path.join(self.cfg.workdir, "kexts", bundle_id.replace("/", "_"))
        os.makedirs(out_dir, exist_ok=True)
        res = self._run(
            [self.binary, "kernel", "extract", kernelcache, bundle_id, "-o", out_dir]
        )
        if not res.ok:
            return None
        machos = [
            os.path.join(root, f)
            for root, _dirs, files in os.walk(out_dir)
            for f in files
            if f.endswith((".macho", ".dylib", ".bin")) or f == bundle_id.rsplit(".", 1)[-1]
        ]
        return machos[0] if machos else out_dir

    def inventory(self, kernelcache: str, targets: List[str]) -> List[Kext]:
        """Full kext list, with target ones first and flagged."""
        all_kexts = self.list_kexts(kernelcache)
        for kext in all_kexts:
            kext.is_target = False
        selected = [k for k in all_kexts if _matches_any(k.bundle_id, targets)]
        for kext in selected:
            kext.is_target = True
        rest = [k for k in all_kexts if k not in selected]
        return selected + rest


def _matches_any(bundle_id: str, targets: List[str]) -> bool:
    lowered = bundle_id.lower()
    return any(t.lower() in lowered or lowered in t.lower() for t in targets if t)


def _find_newest_candidates(new_names: set, workdir: str, needle: str) -> List[str]:
    return sorted(
        (os.path.join(workdir, name) for name in new_names if needle.lower() in name.lower()),
        key=os.path.getmtime,
        reverse=True,
    )
