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
from .symbolicate import symbolicate_manifests
from . import static_rules  # noqa: F401 - registers static plugins
from .report import write_reports
from .targets import Target, discover as discover_targets, select as select_targets
from .storage import Home

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
    def __init__(self, cfg: Config, progress=None):
        self.cfg = cfg
        self.progress = progress
        self.dep = check_dependencies(cfg)
        self.warnings: List[str] = []
        self.observation_source: str = "unknown"  # none / collected / demo-fixture
        self.device = gather_device(cfg, self.dep)
        os.makedirs(cfg.workdir, exist_ok=True)
        self.home = Home(cfg.home)
        # Only materialize the persistent store when archiving is enabled.
        if cfg.archive:
            try:
                self.home.ensure()
            except OSError as exc:
                self.warnings.append(f"无法初始化长期存储目录 {self.home.path}: {exc}")

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
        # Search workdir first, then the persistent home's imported collections.
        for candidate in (
            os.path.join(self.cfg.workdir, "extracted.json"),
            self.home.latest("extracted") if self.cfg.archive else "",
        ):
            if candidate and os.path.exists(candidate):
                extracted = load_extracted(candidate)
                if extracted:
                    self.observation_source = "collected"
                    return extracted
        # DEMO mode only: fall back to the bundled synthetic observation log.
        # Real analysis must NEVER silently use demo data — it produces fake
        # hook-layer findings that look like genuine vulnerabilities.
        if self.cfg.demo:
            self.observation_source = "demo-fixture"
            return load_observations(self._fixture("observations_demo.log"))
        self.observation_source = "none"
        self.warnings.append(
            "未提供 --observations 且未找到采集日志：跳过 hook 观测层，"
            "不使用演示数据（避免生成假线索）。如需动态层线索，"
            "请用 iosvuln collect 采集后以 --observations 指定日志。"
        )
        return []

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
        else:
            available_count = sum(1 for t in discovered if t.available)
            if available_count > len(selected):
                self.warnings.append(
                    f"共发现 {available_count} 个可用目标，受 --max-targets={self.cfg.max_targets} "
                    f"限制只分析前 {len(selected)} 个（并非全部）。"
                )
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
            # A real run with no usable input must NEVER fall back to the demo
            # fixture — that silently fills the report with synthetic findings.
            self.warnings.append(
                "未找到任何可用输入（kernelcache/kext-dir/device/ipsw 均无效）："
                "本次为真实模式，不使用 DEMO 数据，报告漏洞线索为 0。"
                "请用 --kernelcache / --kext-dir 指定有效路径，或用 --from demo 显式体验演示数据。"
            )
            return self._finish(
                [], [], self._load_observations(), {}, "unavailable", "", []
            )
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
            # A --kext-dir pointing at ONE big file that looks like a full
            # kernelcache is not a single kext — it is the whole cache. Treat
            # it like --kernelcache: enumerate kexts with ipsw so each kext is
            # extracted and analysed on its own (small function sets, static
            # rules and symbolication actually land). Otherwise keep the old
            # "one Mach-O = one target" behaviour for genuine exported kexts.
            single = macho_files[0] if len(macho_files) == 1 else ""
            is_cache = bool(
                single
                and (
                    "kernelcache" in os.path.basename(single).lower()
                    or os.path.getsize(single) > 8 * 1024 * 1024
                )
            )
            if is_cache and ipsw.available:
                cache_kexts = ipsw.inventory(single, self.cfg.targets)
                if cache_kexts:
                    self.warnings.append(
                        f"检测到单个完整 kernelcache，已展开为 {len(cache_kexts)} 个 kext "
                        f"逐个分析（这是全量模式的正确路径）。"
                    )
                    kexts = cache_kexts
                    source_cache = single
                    macho_files = []  # force per-kext extraction below
                else:
                    self.warnings.append(
                        "kernelcache 未能列出 kext，退回到单 Mach-O 整体分析。"
                    )
                    kexts = [
                        Kext(bundle_id=os.path.basename(p), path=p) for p in macho_files
                    ]
            else:
                kexts = [
                    Kext(bundle_id=os.path.basename(p), path=p) for p in macho_files
                ]

        selected = self._choose_targets(kexts, macho_files)
        r2 = R2Backend(self.cfg, self.dep)
        manifests: List[AnalysisManifest] = []
        backend_counts: Dict[str, int] = {}

        for target in selected:
            macho = _macho_for_target(macho_files, target)
            if not macho and ipsw.available and source_cache:
                macho = ipsw.extract_kext(source_cache, target.bundle_id) or ""
            if macho:
                artifacts[f"target_kext_{target.name}"] = macho
            manifest = r2.build_manifest(target.bundle_id, macho) if macho else None
            if manifest is None:
                # NEVER substitute demo data for a real analysis — that is how
                # the same synthetic IOSurface fixture got replicated across
                # all targets and produced 396 fake findings (132 fake HIGH).
                reason = r2.last_error or "未提取到 Mach-O"
                self.warnings.append(
                    f"{target.bundle_id}: 分析失败（{reason}），已跳过该目标，"
                    "不使用 DEMO 数据代替。"
                )
                manifest = AnalysisManifest(
                    target=target.bundle_id,
                    source_file=macho or "",
                    metadata={"backend": "unavailable", "reason": reason},
                )
                backend_counts["unavailable"] = backend_counts.get("unavailable", 0) + 1
            else:
                name = manifest.metadata.get("backend", "r2")
                backend_counts[name] = backend_counts.get(name, 0) + 1
            manifests.append(manifest)

        backend = ", ".join(f"{k}:{v}" for k, v in sorted(backend_counts.items()))
        analyzed = len(selected) - backend_counts.get("unavailable", 0)
        if analyzed == 0 and selected:
            self.warnings.append(
                "所有目标均分析失败：没有真实数据可供分析，本次报告的漏洞线索为 0，"
                "这不代表固件安全。请按失败原因修复后重跑。"
            )

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
        # Symbolicate BEFORE the plugins run: most rules match on readable
        # symbol tokens (IOSurfaceLock, copyin, PAC mnemonics, ...), which are
        # invisible when r2 hands us mangled names.  Idempotent, so a manifest
        # that was already symbolicated is left untouched.
        if not getattr(self.cfg, "no_symbolicate", False):
            sym_stats = symbolicate_manifests(manifests)
            if sym_stats.get("cpp") or sym_stats.get("swift") or sym_stats.get("addresses_resolved"):
                self.warnings.append(
                    f"符号化: C++ {sym_stats.get('cpp', 0)} / Swift {sym_stats.get('swift', 0)} "
                    f"/ 地址解析 {sym_stats.get('addresses_resolved', 0)}"
                )
        else:
            sym_stats = {"disabled": True}

        all_findings: List[Finding] = []
        total_steps = max(1, len(manifests) * len(self.cfg.plugins))
        step = 0
        if self.progress:
            self.progress.start("分析插件")
        for manifest in manifests:
            context = AnalysisContext(
                manifest=manifest,
                kext=next((k for k in kexts if k.bundle_id == manifest.target), None),
                workdir=self.cfg.workdir,
                options={"min_severity": self.cfg.min_severity},
                observations=observations,
            )
            for name in self.cfg.plugins:
                step += 1
                try:
                    plugin = instantiate(name)
                    if plugin.layer == Layer.HOOK.value and not observations:
                        if self.progress:
                            self.progress.step(f"跳过 {name}", step, total_steps)
                        continue
                    all_findings.extend(plugin.run(context))
                except (KeyError, ValueError) as exc:
                    self.warnings.append(f"插件 {name} 未执行: {exc}")
                if self.progress:
                    self.progress.step(f"{manifest.target[:18]} · {name}",
                                       step, total_steps, len(all_findings))

        seen = {f.id: f for f in all_findings}
        # Cross-target de-duplication: when the same synthetic or repeated
        # finding surfaces under several targets, collapse it to one entry and
        # record how many targets it appeared in.  The key includes location
        # and score so genuinely distinct findings (different addresses) are
        # never merged away.
        merged: Dict[tuple, Finding] = {}
        dup_targets: Dict[tuple, set] = {}
        for f in seen.values():
            key = (f.title, f.symbol, f.location, f.vuln_class, round(f.score, 2))
            if key in merged:
                dup_targets[key].add(f.target)
            else:
                merged[key] = f
                dup_targets[key] = {f.target}
        for key, targets in dup_targets.items():
            if len(targets) > 1:
                merged[key].tags = list(merged[key].tags) + [
                    f"appeared_in_{len(targets)}_targets"
                ]
        min_rank = Severity.INFO.rank
        try:
            min_rank = Severity(self.cfg.min_severity.upper()).rank
        except ValueError:
            self.warnings.append(f"未知最低严重度 {self.cfg.min_severity!r}，使用 INFO。")
        findings = [f for f in sort_findings(merged.values()) if f.severity.rank >= min_rank]

        discovered = discover_targets(kexts, ())
        meta = {
            "device": self.device.to_dict() if self.device else {},
            "targets": [t.to_dict() for t in selected],
            "available_targets": [t.to_dict() for t in discovered],
            "target": ", ".join(t.bundle_id for t in selected),
            "kernelcache": kernelcache or (manifests[0].source_file if manifests else ""),
            "backend": backend,
            "function_count": sum(len(m.functions) for m in manifests),
            "identified_functions": sum(
                int(m.metadata.get("analyzed_functions", 0)) for m in manifests
            ),
            "manifest_count": len(manifests),
            "ipsw": self.dep.get("ipsw") or "missing",
            "r2": self.dep.get("r2") or ("r2pipe" if self.dep.get("r2pipe") else "missing"),
            "warnings": list(dict.fromkeys(self.warnings)),
            "observations": len(observations),
            "observation_source": self.observation_source,
            "home": self.home.path if self.cfg.archive else "",
            "archived": self.cfg.archive,
            "symbolication": sym_stats,
        }
        reports = write_reports(self.cfg.workdir, findings, kexts, meta)
        artifacts.update(reports)
        artifacts["manifest"] = os.path.join(self.cfg.workdir, "manifest.json")
        # Snapshot into the persistent home so results survive beyond the workdir.
        if self.cfg.archive:
            label = "-".join(t.name or t.bundle_id for t in selected)[:48] or "run"
            try:
                archived = self.home.archive_report(reports, label)
                if archived:
                    artifacts["archived_report_dir"] = os.path.dirname(
                        archived[next(iter(archived))]
                    )
                tweak_src = artifacts.get("ellekit_tweak", "")
                saved_tweak = self.home.save_tweak(tweak_src)
                if saved_tweak:
                    artifacts["archived_tweak"] = saved_tweak
            except OSError as exc:
                self.warnings.append(f"归档到长期存储失败: {exc}")
        manifest_payload = (
            [m.to_dict() for m in manifests] if len(manifests) != 1
            else manifests[0].to_json() if manifests else "[]"
        )
        with open(artifacts["manifest"], "w", encoding="utf-8") as handle:
            handle.write(
                manifest_payload if isinstance(manifest_payload, str)
                else json.dumps(manifest_payload, indent=2, ensure_ascii=False)
            )

        if self.progress:
            self.progress.finish("分析完成", len(findings))

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
