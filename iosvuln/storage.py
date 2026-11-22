"""Persistent home directory for iosvuln.

The analysis host keeps long-lived state under ``~/.iosvuln`` (overridable via
``IOSVULN_HOME`` or ``--home``). The on-device collector uses
``/var/mobile/iosvuln``. This module owns the layout so plugins and the CLI
have a stable place to save and rediscover data across runs.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

DEFAULT_HOME = "~/.iosvuln"
DEVICE_HOME = "/var/mobile/iosvuln"

SUBDIRS = (
    "collections",
    "cache",
    "cache/kexts",
    "reports",
    "tweaks",
    "logs",
)

# kind -> (subdirectory, filename prefix)
KINDS: Dict[str, tuple] = {
    "collection": ("collections", "collection"),
    "extracted": ("collections", "extracted"),
    "kernelcache": ("cache", "kernelcache"),
    "kext": ("cache/kexts", "kext"),
    "log": ("logs", "session"),
    "other": ("collections", "item"),
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "device_home": DEVICE_HOME,
    "targets": ["com.apple.driver.IOSurface"],
    "plugins": [
        "vuln-primitives", "taint-sink", "lock-balance",
        "api-risk", "surface-props", "hook-observation",
    ],
    "min_severity": "INFO",
    "max_targets": 12,
    "archive_reports": True,
}


def resolve_home(home: str = "") -> str:
    """Resolve the home path from an explicit value, env var, or default."""
    raw = home or os.environ.get("IOSVULN_HOME") or DEFAULT_HOME
    return os.path.abspath(os.path.expanduser(os.path.expandvars(raw)))


def _safe_label(text: str, fallback: str = "run", limit: int = 48) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(text)).strip("._")[:limit]
    return cleaned or fallback


@dataclass
class Home:
    """A filesystem-backed persistent store for iosvuln artifacts."""

    path: str = ""

    def __post_init__(self) -> None:
        self.path = resolve_home(self.path)

    # -------------------------------------------------------------- layout
    def subdir(self, name: str) -> str:
        return os.path.join(self.path, name)

    def ensure(self) -> str:
        for name in SUBDIRS:
            os.makedirs(self.subdir(name), exist_ok=True)
        config_path = self.subdir("config.json")
        if not os.path.exists(config_path):
            self.write_config(DEFAULT_CONFIG)
        return self.path

    def exists(self) -> bool:
        return os.path.isdir(self.path)

    @staticmethod
    def stamp() -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    # -------------------------------------------------------------- config
    def config_path(self) -> str:
        return self.subdir("config.json")

    def read_config(self) -> Dict[str, Any]:
        path = self.config_path()
        if not os.path.exists(path):
            return dict(DEFAULT_CONFIG)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return {**DEFAULT_CONFIG, **data} if isinstance(data, dict) else dict(DEFAULT_CONFIG)
        except (OSError, ValueError):
            return dict(DEFAULT_CONFIG)

    def write_config(self, data: Dict[str, Any]) -> str:
        path = self.config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        return path

    # -------------------------------------------------------------- import
    def import_file(self, src: str, kind: str = "other", name: str = "") -> str:
        """Copy an external file into the home with a timestamped name."""
        if not src or not os.path.exists(src):
            raise FileNotFoundError(src)
        sub, prefix = KINDS.get(kind, KINDS["other"])
        dest_dir = self.subdir(sub)
        os.makedirs(dest_dir, exist_ok=True)
        suffix = os.path.splitext(os.path.basename(src))[1]
        label = _safe_label(name or os.path.splitext(os.path.basename(src))[0])
        dest = os.path.join(dest_dir, f"{self.stamp()}-{prefix}-{label}{suffix}")
        shutil.copy2(src, dest)
        return dest

    def latest(self, kind: str) -> str:
        """Find the most recently modified file of a given kind in the home.

        Matches both timestamped imports (``20260101-000000-extracted-x.json``)
        and plain names placed by hand (``extracted.json``).
        """
        sub, prefix = KINDS.get(kind, KINDS["other"])
        dest_dir = self.subdir(sub)
        if not os.path.isdir(dest_dir):
            return ""
        candidates = [
            os.path.join(dest_dir, name)
            for name in os.listdir(dest_dir)
            if prefix.lower() in name.lower()
            and os.path.isfile(os.path.join(dest_dir, name))
        ]
        return max(candidates, key=os.path.getmtime) if candidates else ""

    # -------------------------------------------------------------- archive
    def archive_report(self, reports: Dict[str, str], label: str = "run") -> Dict[str, str]:
        """Snapshot a set of report files into a timestamped home subfolder."""
        folder = os.path.join(
            self.subdir("reports"), f"{self.stamp()}-{_safe_label(label)}"
        )
        os.makedirs(folder, exist_ok=True)
        saved: Dict[str, str] = {}
        for key, src in reports.items():
            if not src or not os.path.exists(src):
                continue
            dst = os.path.join(folder, os.path.basename(src))
            shutil.copy2(src, dst)
            saved[key] = dst
        return saved

    def save_tweak(self, src_dir: str) -> str:
        """Keep the latest generated ElleKit scaffold in the home."""
        if not src_dir or not os.path.isdir(src_dir):
            return ""
        dest = self.subdir("tweaks/ellekit")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        shutil.copytree(src_dir, dest)
        return dest

    def history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List archived reports, newest first."""
        rows: List[Dict[str, Any]] = []
        root = self.subdir("reports")
        if not os.path.isdir(root):
            return rows
        for folder in sorted(glob.glob(os.path.join(root, "*")), reverse=True)[:limit]:
            if not os.path.isdir(folder):
                continue
            files = sorted(os.path.basename(p) for p in glob.glob(os.path.join(folder, "*")))
            rows.append({"folder": folder, "name": os.path.basename(folder), "files": files})
        return rows

    def layout(self) -> str:
        lines = [self.path]
        for name in SUBDIRS:
            lines.append(f"  ├── {name:14} {self.subdir(name)}")
        lines.append(f"  └── {'config.json':14} {self.config_path()}")
        return "\n".join(lines)
