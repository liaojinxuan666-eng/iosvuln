"""End-to-end pipeline orchestration (multi-target aware)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .acquire import Acquisition
from .config import Config
from .device_info import DeviceInfo, gather as gather_device
from .hook_layer import generate_tweak, load_extracted, load_observations
from .ipswwrap import IpswTool, check_dependencies, parse_kexts
from .models import AnalysisManifest, Finding, Kext, Layer, Severity, sort_findings
from .plugins import AnalysisContext, instantiate
from .r2_backend import R2Backend
from . import static_rules  # noqa: F401 - registers static plugins
from .report import write_reports
from .targets import Target, discover as discover_targets, select as select_targets

EXAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)


@dataclass
class PipelineResult:
    config: Config
    dependencies: Dict[str, Any]
    manifests: List[AnalysisManifest] = field(default_factory=list)
    device: Optional[DeviceInfo] = None
    targets: List[Target] = field(default_factory=list)
    selected: List[Target] = field(default_factory=list)
    kexts: List[Kext] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    reports: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)

    @property
    def manifest(self) -> Optional[AnalysisManifest]:
        return self.manifests[0] if self.manifests else None

    def summary(self) -> str:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        parts = [f"{k}={v}" for k, v in sorted(counts.items())]
        targets = ", ".join(t.name or t.bundle_id for t in self.selected)
        return (
            f"targets={len(self.selected)} [{targets}], findings={len(self.findings)} "
            f"({', '.join(parts) if parts else 'none'})"
        )


class Pipeline:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dep = check_dependencies(cfg)
        self.warnings: List[str] = []
        self.device = gather_device(cfg, self.dep)
        os.makedirs(cfg.workdir, exist_ok=True)

    # ------------------------------------------------------------------ helpers
    def _fixture(self, name: str) -> str:
        return os.path.join(EXAMPLES_DIR, name)

    def _load_demo_kexts(self) -> List[Kext]:
        with open(self._fixture("kexts_demo.json"), "r", encoding="utf-8") as handle:
            return parse_kexts(handle.read())

    def _demo_manifest_for(self, target: str) -> AnalysisManifest:
        with open(self._fixture("manifest_iosurface_demo.json"), "r", encoding="utf-8") as handle:
            manifest = AnalysisManifest.from_json(handle.read())
        manifest.target = target
        return manifest

    def _load_observations(self) -> List[Any]:
        if self.cfg.observations:
            return load_observations(self.cfg.observations)
        extracted = load_extracted(os.path.join(self.cfg.workdir, "extracted.json"))
        if extracted:
            return extracted
        return load_observations(self._fixture("observations_demo.log"))

    def _choose_targets(self, kexts: Sequence[Kext], macho_files: Sequence[str]) -> List[Target]:
        discovered = discover_targets(kexts, macho_files)
        if self.cfg.interactive:
            print("可分析目标：")
            from .targets import render_table

            print(render_table(discovered))
            try:
                answer = input("输入编号（逗号分隔）/ all / auto: ").strip()
                specs = [answer] if answer else list(self.cfg.targets)
            except EOFError:
                specs = list(self.cfg.targets)
        else:
            specs = list(self.cfg.targets)
        selected = select_targets(specs, discovered, max_targets=self.cfg.max_targets)
        if not selected:
            self.warnings.append("没有匹配到可分析目标，请运行 iosvuln targets 查看清单。")
        return selected

    # ---------------------------------------------------------------------- run
    def run(self) -> PipelineResult:
        return self._run_demo() if self.cfg.demo else self._run_real()

    def _run_demo(self) -> PipelineResult:
        self.warnings.append("DEMO 模式：使用合成 fixture，不代表真实固件分析结果。")
        kexts = self._load_demo_kexts()
        selected = self._choose_targets(kexts, ())
        manifests = [self._demo_manifest_for(t.bundle_id) for t in selected]
        if len(manifests) > 1:
            self.warnings.append("DEMO 多目标模式：所有目标共用同一份合成函数数据，仅目标名不同。")
        artifacts = {"ellekit_tweak": generate_tweak(self.cfg.workdir)}
        return self._finish(
            manifests, kexts, self._load_observations(), artifacts,
            "demo-fixture", "", selected,
        )

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
        macho_files = list(acquired.macho_files)

        if not macho_files and ipsw.available and source_cache:
            decompressed = ipsw.decompress(source_cache)
            artifacts["decompressed"] = decompressed or source_cache
            if not decompressed:
                self.warnings.append("未能生成 kernelcache.decompressed，直接分析给定文件。")
            source_cache = decompressed or source_cache
            kexts = ipsw.inventory(source_cache, self.cfg.targets)
            if not kexts:
                self.warnings.append("kext 清单为空，将只使用内置目标目录。")
        elif macho_files:
            kexts = [
                Kext(bundle_id=os.path.basename(p), path=p) for p in macho_files
            ]

        selected = self._choose_targets(kexts, macho_files)
        r2 = R2Backend(self.cfg, self.dep)
        manifests: List[AnalysisManifest] = []
        backend = "r2"

        for target in selected:
            macho = _macho_for_target(macho_files, target)
            if not macho and ipsw.available and source_cache:
                macho = ipsw.extract_kext(source_cache, target.bundle_id) or ""
            if macho:
                artifacts[f"target_kext_{target.name}"] = macho
            manifest = r2.build_manifest(target.bundle_id, macho) if macho else None
            if manifest is None:
                self.warnings.append(
                    f"{target.bundle_id}: r2 不可用或未提取到 Mach-O，使用 DEMO fixture 代替。"
                )
                manifest = self._demo_manifest_for(target.bundle_id)
                backend = "demo-fixture (fallback)"
            else:
                backend = manifest.metadata.get("backend", "r2")
            manifests.append(manifest)

        artifacts["ellekit_tweak"] = generate_tweak(self.cfg.workdir)
        return self._finish(
            manifests, kexts, self._load_observations(), artifacts,
            backend, source_cache or "", selected,
        )

    # ----------------------------------------------------------------- analysis
    def _finish(
        self,
        manifests: List[AnalysisManifest],
        kexts: List[Kext],
        observations: List[Any],
        artifacts: Dict[str, str],
        backend: str,
        kernelcache: str,
        selected: List[Target],
    ) -> PipelineResult:
        all_findings: List[Finding] = []
        for manifest in manifests:
            context = AnalysisContext(
                manifest=manifest,
                kext=next((k for k in kexts if k.bundle_id == manifest.target), None),
                workdir=self.cfg.workdir,
                options={"min_severity": self.cfg.min_severity},
                observations=observations,
            )
            for name in self.cfg.plugins:
                try:
                    plugin = instantiate(name)
                    if plugin.layer == Layer.HOOK.value and not observations:
                        continue
                    all_findings.extend(plugin.run(context))
                except (KeyError, ValueError) as exc:
                    self.warnings.append(f"插件 {name} 未执行: {exc}")

        seen = {f.id: f for f in all_findings}
        min_rank = Severity.INFO.rank
        try:
            min_rank = Severity(self.cfg.min_severity.upper()).rank
        except ValueError:
            self.warnings.append(f"未知最低严重度 {self.cfg.min_severity!r}，使用 INFO。")
        findings = [f for f in sort_findings(seen.values()) if f.severity.rank >= min_rank]

        discovered = discover_targets(kexts, ())
        meta = {
            "device": self.device.to_dict() if self.device else {},
            "targets": [t.to_dict() for t in selected],
            "available_targets": [t.to_dict() for t in discovered],
            "target": ", ".join(t.bundle_id for t in selected),
            "kernelcache": kernelcache or (manifests[0].source_file if manifests else ""),
            "backend": backend,
            "function_count": sum(len(m.functions) for m in manifests),
            "manifest_count": len(manifests),
            "ipsw": self.dep.get("ipsw") or "missing",
            "r2": self.dep.get("r2") or ("r2pipe" if self.dep.get("r2pipe") else "missing"),
            "warnings": list(dict.fromkeys(self.warnings)),
            "observations": len(observations),
        }
        reports = write_reports(self.cfg.workdir, findings, kexts, meta)
        artifacts.update(reports)
        artifacts["manifest"] = os.path.join(self.cfg.workdir, "manifest.json")
        manifest_payload = (
            [m.to_dict() for m in manifests] if len(manifests) != 1
            else manifests[0].to_json() if manifests else "[]"
        )
        with open(artifacts["manifest"], "w", encoding="utf-8") as handle:
            handle.write(
                manifest_payload if isinstance(manifest_payload, str)
                else json.dumps(manifest_payload, indent=2, ensure_ascii=False)
            )

        return PipelineResult(
            config=self.cfg,
            dependencies=self.dep,
            manifests=manifests,
            device=self.device,
            targets=discovered,
            selected=selected,
            kexts=kexts,
            findings=findings,
            reports=reports,
            warnings=meta["warnings"],
            artifacts=artifacts,
        )


def _macho_for_target(files: Sequence[str], target: Target) -> str:
    needles = [target.name.lower(), target.bundle_id.rsplit(".", 1)[-1].lower()]
    for needle in needles:
        for path in files:
            if needle and needle in os.path.basename(path).lower():
                return path
    return ""
