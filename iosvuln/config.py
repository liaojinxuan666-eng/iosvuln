"""Pipeline configuration."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


DEFAULT_TARGETS = [
    "com.apple.driver.IOSurface",
    "com.apple.driver.IOKit",
]


@dataclass
class Config:
    ipsw_path: str = "ipsw"
    r2_path: str = "r2"
    workdir: str = "iosvuln-out"
    kernelcache: str = ""
    ipsw_file: str = ""
    device: bool = False
    device_path: str = ""
    ssh_host: str = ""
    kext_dir: str = ""
    targets: List[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))
    plugins: List[str] = field(
        default_factory=lambda: [
            "vuln-primitives", "pointer-safety", "pac-security", "advanced-threats",
            "logic-flaws", "darwin-internals", "apple-silicon",
            "taint-sink", "lock-balance", "api-risk", "surface-props", "hook-observation",
        ]
    )
    min_severity: str = "INFO"
    observations: str = ""
    max_targets: int = 12
    interactive: bool = False
    demo: bool = False
    keep_artifacts: bool = True
    home: str = ""                 # persistent store; empty -> ~/.iosvuln or IOSVULN_HOME
    archive: bool = True           # snapshot reports into the persistent home

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        known = {k: v for k, v in data.items() if k in cls.__annotations__}
        cfg = cls(**known)
        if not cfg.workdir:
            cfg.workdir = "iosvuln-out"
        cfg.workdir = os.path.expanduser(os.path.expandvars(cfg.workdir))
        cfg.home = os.path.expanduser(os.path.expandvars(cfg.home)) if cfg.home else ""
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
