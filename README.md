# iosvuln

iOS 内核驱动（kext）**静态 + 提取式 Hook 双层分析流水线**。只标注**内存破坏 / OOB read / 提权原语 / 沙盒逃逸 / RCE 等漏洞类型对应的汇编地址**，**不生成 PoC 或利用代码**。

## 流程

```
0. 环境探测：iosvuln info
   设备名 / 系统版本 / Build / 架构 / 内核 → 用于适配路径与架构假设
1. 目标选择：iosvuln targets
   列出可分析 kext（编号、风险、是否可用）→ 单个 / 多个 / 全量
2. 采集输入（四选一，不再强制完整 IPSW）
   --kext-dir <dir> | --kernelcache <path> | --device | --ipsw <file>
3. ipsw kernel kexts / extract → Mach-O ；或直接用 --kext-dir
4. r2 / r2pipe → AnalysisManifest（含每条调用的汇编地址）
   ├─ vuln-primitives / taint-sink / lock-balance / api-risk / surface-props
   └─ 提取式 ElleKit tweak 导出的符号地址 + 机器码
5. report.md / report.json（按原语归集的汇编位置）
```

**提取式 Hook**：`Tweak.xm` 用 `MSFindSymbol` 解析 `IOSurface.framework` 符号，导出函数地址与前 96 字节机器码到 `/var/mobile/iosvuln/extracted.json`。**不安装 inline hook、不改写任何函数行为**。

## 安装

分析端（macOS / Linux）：

```bash
pip3 install -e .
pip3 install '.[r2]'      # 可选：r2pipe
```

设备端：用 **Sileo 安装** `packaging/dev.iosvuln.collect_0.1.1_iphoneos-arm64.deb`。它提供 `iosvuln-collect [路径]`，从系统缓存或指定路径采集 kernelcache/kext，并把**设备名、系统版本、Build、架构**写入 `/var/mobile/iosvuln/collection.json`。deb 内附提取式 tweak 源码，需你自己用 Theos 编译——沙箱没有 iOS SDK，**deb 不含已编译 dylib**。

**文档**：[安装指南 docs/INSTALL.md](docs/INSTALL.md) · [使用指南 docs/USAGE.md](docs/USAGE.md)

## 常用命令

```bash
# 0. 看环境（本地主机 / 已连接设备 / collection.json）
iosvuln info
iosvuln info --device --ssh-host root@localhost
iosvuln info --collection ./collection.json

# 1. 看可分析目标并选取
iosvuln targets --kernelcache ./kernelcache.decompressed
iosvuln targets --kext-dir ./exported-kexts --json
iosvuln run --target 1,3,5 --kernelcache ./kernelcache.decompressed
iosvuln run --target all --max-targets 12 --kernelcache ./kernelcache.decompressed
iosvuln run --interactive --device          # 交互式选择编号

# 2. 采集与分析
iosvuln-collect /System/Library/Caches/com.apple.kernelcaches/kernelcache   # 设备上
iosvuln run --kext-dir ./exported-kexts --workdir ./out
iosvuln run --device --device-path /System/Library/Caches/com.apple.kernelcaches/kernelcache
iosvuln run --kernelcache ./kernelcache.decompressed --min-severity MEDIUM
iosvuln demo --target all --workdir /tmp/iosvuln-demo

# 长期存储：持久保存采集数据、缓存与历史报告（默认 ~/.iosvuln）
iosvuln home --init
iosvuln import ./extracted.json
iosvuln history
iosvuln run --home /data/iosvuln --workdir ./out    # 指定长期目录
iosvuln run --no-archive --workdir ./out            # 关闭自动归档
```

`--target` 支持：`all`/`*`（全量，受 `--max-targets` 限制）、`auto`/`catalog`（内置目录中高风险目标）、`1,3,5`（`iosvuln targets` 显示的编号）、任意 bundle id / 名称子串。

## 输出

报告新增 **§0 环境信息**、**§0.1 可分析目标**（目录/可用/已选），以及 **§3.1 按原语归集的汇编位置**：

| 原语 | 含义 |
| --- | --- |
| `OOB_WRITE` / `MEMORY_CORRUPTION` | 用户输入源与 `memcpy` / `memmove` / `writeBytes` / 分配器共现 |
| `OOB_READ` | `copyout` / `readBytes` / `GetBaseAddress` 与 size/offset 共现 |
| `INTEGER_OVERFLOW` | 尺寸计算与分配/拷贝组合 |
| `PRIVILEGE_ESCALATION` | 外部方法、属性写入、`task_for_pid` 等内核能力入口 |
| `SANDBOX_ESCAPE` | mach port / task / VM 跨边界能力组合 |
| `RCE` | `blr`（函数指针）间接调用点 |
| `RACE` / `UAF` | 加解锁失衡，且伴随释放/引用计数操作 |

每条 finding 带 `assembly`（`地址: 指令 目标`）、`vuln_class`、`symbol`、证据和置信度。多目标时每条 finding 的 `target` 字段标明来源 kext。

## 插件与测试

内置：`vuln-primitives`、`taint-sink`、`lock-balance`、`api-risk`、`surface-props`、`hook-observation`。

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v   # 15 项
```

## 说明

- 静态规则是优先级排序工具，不替代人工逆向；所有条目需人工复核。
- 提取式 tweak 只导出用户态符号；内核 kext 内部靠 r2 静态分析，按地址关联。
- DEMO 多目标模式所有目标共用同一份合成函数数据（报告会明确警告）。
- 请仅在有权测试的设备与固件上使用。
