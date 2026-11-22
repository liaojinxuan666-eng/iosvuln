"""Command line interface for iosvuln."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .config import DEFAULT_TARGETS, Config
from .device_info import gather as gather_device
from .hook_layer import generate_tweak
from .ipswwrap import IpswTool, check_dependencies
from .pipeline import Pipeline, PipelineResult
from .plugins import list_plugins
from . import static_rules  # noqa: F401 - registers static plugins

DEFAULT_PLUGINS = [
    "vuln-primitives", "taint-sink", "lock-balance", "api-risk",
    "surface-props", "hook-observation",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iosvuln",
        description="iOS 内核驱动（kext）静态 + Hook 双层漏洞分析流水线",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="执行完整流水线")
    _add_run_args(run)
    run.add_argument("--demo", action="store_true", help="使用合成数据（无需 ipsw/r2）")

    demo = sub.add_parser("demo", help="等价于 run --demo")
    _add_run_args(demo)

    sub.add_parser("deps", help="检查 ipsw / r2 / r2pipe 可用性")
    sub.add_parser("plugins", help="列出已注册分析插件")

    info = sub.add_parser("info", help="探测设备/环境信息（名称、系统版本、架构）")
    _add_acquire_args(info)
    info.add_argument("--collection", default="", help="设备端 collection.json 路径")

    targets = sub.add_parser("targets", help="列出可分析目标并选择")
    _add_acquire_args(targets)
    targets.add_argument("--json", action="store_true")

    kexts = sub.add_parser("kexts", help="列出 kernelcache 中的 kext")
    kexts.add_argument("kernelcache")
    kexts.add_argument("--workdir", default="iosvuln-out")
    kexts.add_argument("--json", action="store_true")

    scaffold = sub.add_parser("hook-scaffold", help="生成 ElleKit 用户态 hook 工程")
    scaffold.add_argument("--workdir", default="iosvuln-out")

    home = sub.add_parser("home", help="显示长期存储目录结构")
    home.add_argument("--home", default="", help="覆盖长期存储目录（默认 ~/.iosvuln）")
    home.add_argument("--json", action="store_true")
    home.add_argument("--init", action="store_true", help="创建目录与默认配置")

    imp = sub.add_parser("import", help="把设备采集文件导入长期存储")
    imp.add_argument("file", help="要导入的文件路径")
    imp.add_argument("--kind", default="auto",
                     choices=["auto", "collection", "extracted", "kernelcache", "kext", "log", "other"],
                     help="数据类型；auto 时按文件名推断")
    imp.add_argument("--home", default="", help="覆盖长期存储目录")

    history = sub.add_parser("history", help="列出已归档的历史报告")
    history.add_argument("--home", default="", help="覆盖长期存储目录")
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--json", action="store_true")

    return parser


def _add_acquire_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kernelcache", default="", help="已提取的 kernelcache 路径")
    parser.add_argument("--kext-dir", default="", help="已导出的 kext Mach-O 目录")
    parser.add_argument("--device", action="store_true", help="从已连接的越狱设备拉取")
    parser.add_argument("--device-path", default="", help="设备上 kernelcache 的明确路径")
    parser.add_argument("--ssh-host", default="", help="设备 SSH 主机，默认 root@localhost")
    parser.add_argument("--workdir", default="iosvuln-out")


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ipsw", dest="ipsw_file", default="", help="本地 IPSW 路径（兼容旧流程）")
    parser.add_argument("--kernelcache", default="", help="已提取/解压的 kernelcache 路径")
    parser.add_argument("--device", action="store_true", help="从已连接的越狱设备拉取 kernelcache")
    parser.add_argument("--device-path", default="", help="设备上 kernelcache 的明确路径")
    parser.add_argument("--ssh-host", default="", help="设备 SSH 主机，默认 root@localhost")
    parser.add_argument("--kext-dir", default="", help="直接指定已导出的 kext Mach-O 目录")
    parser.add_argument("--workdir", default="iosvuln-out")
    parser.add_argument("--target", action="append", default=None, help="目标 kext bundle id，可重复")
    parser.add_argument("--plugin", action="append", default=None, help="启用的插件名，可重复")
    parser.add_argument("--observations", default="", help="由 hook 采集的 syslog 文件路径")
    parser.add_argument("--max-targets", type=int, default=12, help="全量分析时最多处理的目标数")
    parser.add_argument("--interactive", action="store_true", help="交互式选择可分析目标")
    parser.add_argument("--min-severity", default="INFO", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    parser.add_argument("--home", default="", help="长期存储目录（默认 ~/.iosvuln，可用 IOSVULN_HOME）")
    parser.add_argument("--no-archive", action="store_true", help="不把报告归档到长期存储目录")
    parser.add_argument("--quiet", action="store_true", help="只输出报告路径")


def _config_from_args(args: argparse.Namespace, demo: bool = False) -> Config:
    return Config(
        ipsw_file=getattr(args, "ipsw_file", "") or "",
        kernelcache=getattr(args, "kernelcache", "") or "",
        device=getattr(args, "device", False),
        device_path=getattr(args, "device_path", "") or "",
        ssh_host=getattr(args, "ssh_host", "") or "",
        kext_dir=getattr(args, "kext_dir", "") or "",
        workdir=getattr(args, "workdir", "iosvuln-out"),
        targets=getattr(args, "target", None) or list(DEFAULT_TARGETS),
        plugins=getattr(args, "plugin", None) or list(DEFAULT_PLUGINS),
        observations=getattr(args, "observations", "") or "",
        min_severity=getattr(args, "min_severity", "INFO"),
        max_targets=getattr(args, "max_targets", 12),
        interactive=getattr(args, "interactive", False),
        demo=demo or getattr(args, "demo", False),
        home=getattr(args, "home", "") or "",
        archive=not getattr(args, "no_archive", False),
    )


def _print_result(result: PipelineResult, quiet: bool = False) -> None:
    if not quiet:
        print("\n=== 流水线结果 ===")
        print(result.summary())
        if result.findings:
            print("\nTop findings:")
            for finding in result.findings[:8]:
                print(
                    f"  [{finding.severity.value:8}] {finding.layer.value:6} "
                    f"{finding.title} @ {finding.location} (score={finding.score:.0f})"
                )
        for warning in result.warnings:
            print(f"  ! {warning}")
    print("\n报告:")
    for name, path in result.reports.items():
        print(f"  {name}: {os.path.abspath(path)}")
    print(f"  manifest: {os.path.abspath(result.artifacts.get('manifest', ''))}")
    tweak = result.artifacts.get("ellekit_tweak")
    if tweak:
        print(f"  ellekit:  {os.path.abspath(tweak)}")
    archived = result.artifacts.get("archived_report_dir")
    if archived:
        print(f"  archived: {os.path.abspath(archived)}")
    from .storage import resolve_home

    print(f"  home:     {resolve_home(result.config.home)}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    command = args.command or "run"

    if command == "deps":
        status = check_dependencies(Config())
        print(json.dumps(status, indent=2, ensure_ascii=False, default=str))
        return 0

    if command == "plugins":
        for name, description in list_plugins().items():
            print(f"  {name:18} {description}")
        return 0

    if command == "info":
        cfg = _config_from_args(args)
        device = gather_device(cfg, check_dependencies(cfg), getattr(args, "collection", ""))
        print(device.summary())
        print(json.dumps(device.to_dict(), indent=2, ensure_ascii=False))
        return 0

    if command == "targets":
        cfg = _config_from_args(args)
        from .acquire import Acquisition
        from .models import Kext
        from .targets import discover as discover_targets, render_table

        acquired = Acquisition(cfg).acquire()
        kexts: List[Kext] = []
        macho_files: List[str] = []
        if acquired:
            macho_files = list(acquired.macho_files)
            kexts = [
                Kext(bundle_id=os.path.basename(p), path=p) for p in macho_files
            ]
            if not kexts and acquired.kernelcache:
                from .ipswwrap import IpswTool

                kexts = IpswTool(cfg).inventory(acquired.kernelcache, cfg.targets)
        found = discover_targets(kexts, macho_files)
        if args.json:
            print(json.dumps([t.to_dict() for t in found], indent=2, ensure_ascii=False))
        else:
            print(render_table(found))
            print("\n选择方式：--target 1,3 / --target all / --target auto / --interactive")
        return 0

    if command == "kexts":
        cfg = Config(workdir=args.workdir)
        tool = IpswTool(cfg)
        kexts = tool.list_kexts(args.kernelcache)
        if args.json:
            print(json.dumps([k.to_dict() for k in kexts], indent=2, ensure_ascii=False))
        else:
            for kext in kexts:
                print(f"{kext.bundle_id:55} {kext.version}")
        if not kexts:
            print("未找到 kext（检查 ipsw 是否安装、kernelcache 路径是否正确）", file=sys.stderr)
            return 1
        return 0

    if command == "hook-scaffold":
        path = generate_tweak(args.workdir)
        print(f"ElleKit tweak 工程已生成: {os.path.abspath(path)}")
        return 0

    if command == "home":
        from .storage import Home

        store = Home(getattr(args, "home", "") or "")
        if args.init:
            store.ensure()
            print(f"长期存储目录已初始化: {store.path}")
        if args.json:
            print(json.dumps({
                "path": store.path,
                "exists": store.exists(),
                "subdirs": {n: store.subdir(n) for n in
                            ("collections", "cache", "cache/kexts", "reports", "tweaks", "logs")},
                "config": store.config_path(),
            }, indent=2, ensure_ascii=False))
        else:
            print(store.layout())
        return 0

    if command == "import":
        from .storage import Home

        store = Home(getattr(args, "home", "") or "")
        store.ensure()
        kind = args.kind
        if kind == "auto":
            lower = os.path.basename(args.file).lower()
            if "extract" in lower:
                kind = "extracted"
            elif "collection" in lower:
                kind = "collection"
            elif "kernelcache" in lower or lower.endswith(".img4"):
                kind = "kernelcache"
            elif lower.endswith(".log"):
                kind = "log"
            else:
                kind = "other"
        try:
            dest = store.import_file(args.file, kind)
        except FileNotFoundError:
            print(f"文件不存在: {args.file}", file=sys.stderr)
            return 1
        print(f"已导入 [{kind}]: {dest}")
        return 0

    if command == "history":
        from .storage import Home

        store = Home(getattr(args, "home", "") or "")
        rows = store.history(limit=args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        elif not rows:
            print(f"尚无归档报告（长期存储: {store.path}）")
        else:
            print(f"长期存储: {store.path}")
            for row in rows:
                print(f"  {row['name']}: {', '.join(row['files'])}")
        return 0

    cfg = _config_from_args(args, demo=(command == "demo"))
    result = Pipeline(cfg).run()
    _print_result(result, quiet=getattr(args, "quiet", False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
