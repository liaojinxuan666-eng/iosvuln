"""Minimal plugin registry used by both analysis layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type

from .models import AnalysisManifest, Finding, Kext


@dataclass
class AnalysisContext:
    """Everything a plugin may need during a pipeline run."""

    manifest: AnalysisManifest
    kext: Optional[Kext] = None
    workdir: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    observations: List[Any] = field(default_factory=list)


class Plugin:
    name: str = "base"
    description: str = ""
    layer: str = "static"

    def run(self, context: AnalysisContext) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError


_REGISTRY: Dict[str, Type[Plugin]] = {}


def register(cls: Type[Plugin]) -> Type[Plugin]:
    """Class decorator that makes a plugin discoverable by name."""
    if not cls.name or cls.name == "base":
        raise ValueError(f"plugin {cls!r} must define a unique name")
    if cls.name in _REGISTRY:
        raise ValueError(f"plugin already registered: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def get_plugin(name: str) -> Optional[Type[Plugin]]:
    return _REGISTRY.get(name)


def list_plugins() -> Dict[str, str]:
    return {name: cls.description for name, cls in sorted(_REGISTRY.items())}


def instantiate(name: str, **kwargs: Any) -> Plugin:
    cls = get_plugin(name)
    if cls is None:
        raise KeyError(f"unknown plugin: {name} (available: {', '.join(list_plugins())})")
    return cls(**kwargs)
