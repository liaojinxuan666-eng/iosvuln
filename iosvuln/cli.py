"""Command line interface for iosvuln."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .config import DEFAULT_TARGETS, Config
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

    kexts = sub.add_parser("kexts", help="列出 kernelcache 中的 kext")
    kexts.add_argument("kernelcache")
    kexts.add_argument("--workdir", default="iosvuln-out")
    kexts.add_argument("--json", action="store_true")

    scaffold = sub.add_parser("hook-scaffold", help="生成 ElleKit 用户态 hook 工程")
    scaffold.add_argument("--workdir", default="iosvuln-out")

    return parser


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
    parser.add_argument("--min-severity", default="INFO", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
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
        demo=demo or getattr(args, "demo", False),
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

    cfg = _config_from_args(args, demo=(command == "demo"))
    result = Pipeline(cfg).run()
    _print_result(result, quiet=getattr(args, "quiet", False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
