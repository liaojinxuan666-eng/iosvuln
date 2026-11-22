"""Shared data models for the iosvuln pipeline."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 20:
            return cls.LOW
        return cls.INFO


class Layer(str, Enum):
    STATIC = "static"
    HOOK = "hook"
    MANUAL = "manual"


class VulnClass(str, Enum):
    """Primitive classes the analyzer is allowed to report."""

    OOB_READ = "OOB_READ"
    OOB_WRITE = "OOB_WRITE"
    MEMORY_CORRUPTION = "MEMORY_CORRUPTION"
    UAF = "UAF"
    DANGLING_POINTER = "DANGLING_POINTER"      # 野指针：释放后仍被引用/外传
    DOUBLE_FREE = "DOUBLE_FREE"                # 重复释放
    NULL_DEREF = "NULL_DEREF"                  # 未校验的空指针解引用
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"
    RACE = "RACE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SANDBOX_ESCAPE = "SANDBOX_ESCAPE"
    RCE = "RCE"
    INFO_LEAK = "INFO_LEAK"
    OTHER = "OTHER"


@dataclass
class CallSite:
    """One call instruction with its concrete address."""

    address: str
    mnemonic: str = "bl"
    target: str = ""

    def render(self) -> str:
        return f"{self.address}: {self.mnemonic} {self.target}".strip()


@dataclass
class Kext:
    """One kernel extension from the ipsw kext inventory."""

    bundle_id: str
    name: str = ""
    version: str = ""
    path: str = ""
    size: int = 0
    arch: str = ""
    is_target: bool = False

    @property
    def is_interesting(self) -> bool:
        needle = self.bundle_id.lower()
        return any(
            keyword in needle
            for keyword in (
                "iosurface",
                "iokit",
                "driver",
                "security",
                "sandbox",
                "mach",
                "vnode",
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Function:
    """A function recovered from static analysis."""

    name: str
    address: str = ""
    size: int = 0
    calls: List[str] = field(default_factory=list)
    xrefs: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    complexity: int = 0
    call_sites: List[CallSite] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["call_sites"] = [site.render() for site in self.call_sites]
        return data


def _function_from_dict(data: Dict[str, Any]) -> Function:
    """Rebuild a Function, tolerating call_sites serialized as strings."""
    payload = dict(data)
    sites = payload.pop("call_sites", []) or []
    parsed: List[CallSite] = []
    for site in sites:
        if isinstance(site, dict):
            parsed.append(CallSite(**site))
        else:
            text = str(site)
            if ":" in text:
                addr, rest = text.split(":", 1)
                parts = rest.strip().split(None, 1)
                parsed.append(
                    CallSite(
                        address=addr.strip(),
                        mnemonic=parts[0] if parts else "bl",
                        target=parts[1] if len(parts) > 1 else "",
                    )
                )
    return Function(**payload, call_sites=parsed)


@dataclass
class AnalysisManifest:
    """Intermediate representation shared by every static-analysis backend.

    The r2 backend fills this from a Mach-O; the demo backend fills it from a
    checked-in fixture. Findings are always derived from this manifest so the
    heuristics stay backend-agnostic and unit-testable.
    """

    target: str
    source_file: str = ""
    arch: str = "arm64e"
    functions: List[Function] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def function_by_name(self, name: str) -> Optional[Function]:
        for fn in self.functions:
            if fn.name == name:
                return fn
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "source_file": self.source_file,
            "arch": self.arch,
            "functions": [f.to_dict() for f in self.functions],
            "imports": self.imports,
            "strings": self.strings,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "AnalysisManifest":
        data = json.loads(text)
        return cls(
            target=data["target"],
            source_file=data.get("source_file", ""),
            arch=data.get("arch", "arm64e"),
            functions=[_function_from_dict(f) for f in data.get("functions", [])],
            imports=list(data.get("imports", [])),
            strings=list(data.get("strings", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class Finding:
    """A suspected vulnerability, from either layer."""

    id: str
    title: str
    severity: Severity
    layer: Layer
    target: str
    description: str = ""
    location: str = ""
    evidence: List[str] = field(default_factory=list)
    score: float = 0.0
    confidence: float = 0.5
    cwe: str = ""
    vuln_class: str = ""
    assembly: List[str] = field(default_factory=list)
    symbol: str = ""
    recommendation: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["layer"] = self.layer.value
        return data


@dataclass
class HookObservation:
    """One userspace hook event relevant to a kernel driver."""

    function: str
    pid: int = 0
    process: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    note: str = ""


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Highest severity first, then score, then confidence."""
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, f.score, f.confidence),
        reverse=True,
    )
