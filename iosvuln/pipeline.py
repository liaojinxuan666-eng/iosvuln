"""End-to-end pipeline orchestration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .acquire import Acquisition
from .config import Config
from .hook_layer import generate_tweak, load_extracted, load_observations
from .ipswwrap import IpswTool, check_dependencies, parse_kexts
from .models import AnalysisManifest, Finding, Kext, Layer, Severity, sort_findings
from .plugins import AnalysisContext, instantiate
from .r2_backend import R2Backend
from . import static_rules  # noqa: F401 - registers static plugins
from .report import write_reports

EXAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)


@dataclass
class PipelineResult:
    config: Config
    dependencies: Dict[str, Any]
    manifest: AnalysisManifest
    kexts: List[Kext] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    reports: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        parts = [f"{k}={v}" for k, v in sorted(counts.items())]
        return f"findings={len(self.findings)} ({', '.join(parts) if parts else 'none'})"


class Pipeline:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dep = check_dependencies(cfg)
        self.warnings: List[str] = []
        os.makedirs(cfg.workdir, exist_ok=True)

    # ------------------------------------------------------------------ helpers
    def _fixture(self, name: str) -> str:
        return os.path.join(EXAMPLES_DIR, name)

    def _load_demo_manifest(self) -> AnalysisManifest:
        with open(self._fixture("manifest_iosurface_demo.json"), "r", encoding="utf-8") as handle:
            manifest = AnalysisManifest.from_json(handle.read())
        manifest.target = self.cfg.targets[0] if self.cfg.targets else manifest.target
        return manifest

    def _load_demo_kexts(self) -> List[Kext]:
        with open(self._fixture("kexts_demo.json"), "r", encoding="utf-8") as handle:
            kexts = parse_kexts(handle.read())
        for kext in kexts:
            kext.is_target = any(
                t.lower() in kext.bundle_id.lower() for t in self.cfg.targets
            )
        return kexts

    def _load_demo_observations(self) -> List[Any]:
        if self.cfg.observations:
            return load_observations(self.cfg.observations)
        return load_observations(self._fixture("observations_demo.log"))

    # ---------------------------------------------------------------------- run
    def run(self) -> PipelineResult:
        if self.cfg.demo:
            result = self._run_demo()
        else:
            result = self._run_real()
        return result

    def _run_demo(self) -> PipelineResult:
        self.warnings.append("DEMO 模式：使用合成 fixture，不代表真实固件分析结果。")
        manifest = self._load_demo_manifest()
        kexts = self._load_demo_kexts()
        observations = self._load_demo_observations()
        artifacts = {"ellekit_tweak": generate_tweak(self.cfg.workdir)}
        return self._analyze(manifest, kexts, observations, artifacts, "demo-fixture", "")

    def _run_real(self) -> PipelineResult:
        artifacts: Dict[str, str] = {}
        acquisition = Acquisition(self.cfg)
        acquired = acquisition.acquire()
        self.warnings.extend(acquisition.notes)
        if acquired is None:
            self.warnings.append("未指定任何可用输入，改用 DEMO fixture。")
            return self._run_demo()
        if acquired.commands:
            artifacts["acquisition_commands"] = "\n".join(acquired.commands)

        ipsw = IpswTool(self.cfg, self.dep)
        kexts: List[Kext] = []
        source_cache = acquired.kernelcache
        target = self.cfg.targets[0] if self.cfg.targets else "unknown"
        macho = ""

        if acquired.macho_files:
            macho = _pick_macho(acquired.macho_files, self.cfg.targets)
            kexts = [
                Kext(bundle_id=os.path.basename(p), path=p, is_target=(p == macho))
                for p in acquired.macho_files
            ]
            if macho:
                target = os.path.basename(macho)
                artifacts["target_kext"] = macho
        else:
            if not ipsw.available or not source_cache:
                self.warnings.append("ipsw 不可用或没有内核缓存，静态层改用 DEMO fixture。")
            else:
                decompressed = ipsw.decompress(source_cache)
                artifacts["decompressed"] = decompressed or source_cache
                if not decompressed:
                    self.warnings.append("未能生成 kernelcache.decompressed，直接分析给定文件。")
                source_cache = decompressed or source_cache
                kexts = ipsw.inventory(source_cache, self.cfg.targets)
                target_kext = next((k for k in kexts if k.is_target), None)
                if target_kext:
                    target = target_kext.bundle_id
                    macho = ipsw.extract_kext(source_cache, target) or ""
                    artifacts["target_kext"] = macho
                if not kexts:
                    self.warnings.append("kext 清单为空。")

        r2 = R2Backend(self.cfg, self.dep)
        manifest = r2.build_manifest(target, macho) if macho else None
        if manifest is None:
            self.warnings.append("r2 不可用或分析失败，静态层使用 DEMO fixture。")
            manifest = self._load_demo_manifest()
            manifest.target = target
            backend = "demo-fixture (fallback)"
        else:
            backend = manifest.metadata.get("backend", "r2")

        observations = load_observations(self.cfg.observations) if self.cfg.observations else []
        extracted = load_extracted(os.path.join(self.cfg.workdir, "extracted.json"))
        if extracted and not observations:
            observations = extracted
            self.warnings.append("使用 ElleKit 提取式 hook 导出的符号地址作为动态线索。")
        artifacts["ellekit_tweak"] = generate_tweak(self.cfg.workdir)
        return self._analyze(manifest, kexts, observations, artifacts, backend, source_cache or "")

    def _analyze(
        self,
        manifest: AnalysisManifest,
        kexts: List[Kext],
        observations: List[Any],
        artifacts: Dict[str, str],
        backend: str,
        kernelcache: str,
    ) -> PipelineResult:
        context = AnalysisContext(
            manifest=manifest,
            kext=next((k for k in kexts if k.bundle_id == manifest.target), None),
            workdir=self.cfg.workdir,
            options={"min_severity": self.cfg.min_severity},
            observations=observations,
        )
        findings: List[Finding] = []
        for name in self.cfg.plugins:
            try:
                plugin = instantiate(name)
                if plugin.layer == Layer.HOOK.value and not observations:
                    continue
                findings.extend(plugin.run(context))
            except (KeyError, ValueError) as exc:
                self.warnings.append(f"插件 {name} 未执行: {exc}")

        seen = {f.id: f for f in findings}
        min_rank = Severity.INFO.rank
        try:
            min_rank = Severity(self.cfg.min_severity.upper()).rank
        except ValueError:
            self.warnings.append(f"未知最低严重度 {self.cfg.min_severity!r}，使用 INFO。")
        filtered = [f for f in sort_findings(seen.values()) if f.severity.rank >= min_rank]

        meta = {
            "target": manifest.target,
            "kernelcache": kernelcache or manifest.source_file,
            "backend": backend,
            "function_count": len(manifest.functions),
            "ipsw": self.dep.get("ipsw") or "missing",
            "r2": self.dep.get("r2") or ("r2pipe" if self.dep.get("r2pipe") else "missing"),
            "warnings": list(dict.fromkeys(self.warnings)),
            "observations": len(observations),
        }
        reports = write_reports(self.cfg.workdir, filtered, kexts, meta)
        artifacts.update(reports)
        artifacts["manifest"] = os.path.join(self.cfg.workdir, "manifest.json")
        with open(artifacts["manifest"], "w", encoding="utf-8") as handle:
            handle.write(manifest.to_json())

        return PipelineResult(
            config=self.cfg,
            dependencies=self.dep,
            manifest=manifest,
            kexts=kexts,
            findings=filtered,
            reports=reports,
            warnings=meta["warnings"],
            artifacts=artifacts,
        )


def _pick_macho(files: List[str], targets: List[str]) -> str:
    for target in targets:
        needle = target.rsplit(".", 1)[-1].lower()
        for path in files:
            if needle in os.path.basename(path).lower():
                return path
    return files[0] if files else ""
