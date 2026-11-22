# iosvuln 使用指南

本文是面向使用者的完整操作手册。若你想了解内部架构与插件机制，见项目根目录的 [README.md](../README.md)。

iosvuln 对 iOS 内核驱动（kext）做**静态分析 + 提取式 Hook** 双层分析，只输出**漏洞类型 + 对应汇编地址**，不生成 PoC 或利用代码。

---

## 目录

1. [它能做什么 / 不能做什么](#1-它能做什么--不能做什么)
2. [安装](#2-安装)
3. [快速开始（无需真机）](#3-快速开始无需真机)
4. [标准工作流](#4-标准工作流)
5. [第一步：探测环境](#5-第一步探测环境)
6. [第二步：查看并选择目标](#6-第二步查看并选择目标)
7. [第三步：采集内核 / kext](#7-第三步采集内核--kext)
8. [第四步：运行分析](#8-第四步运行分析)
9. [第五步：解读报告](#9-第五步解读报告)
10. [设备端采集器详解](#10-设备端采集器详解)
11. [提取式 ElleKit tweak](#11-提取式-ellekit-tweak)
12. [长期存储目录](#12-长期存储目录)
13. [命令参考](#13-命令参考)
14. [常见问题](#14-常见问题)

---

## 1. 它能做什么 / 不能做什么

**能做的**

- 从 IPSW、已解压的 kernelcache、已导出的 kext 目录，或越狱设备直接获取分析输入。
- 列出可分析目标（内置 10 个高价值 kext 目录 + 从输入中发现的 kext），支持单个、多个、编号或全量分析。
- 用 radare2 提取函数、调用点、字符串与每条调用的汇编地址。
- 用启发式规则标注疑似漏洞原语及其汇编位置：OOB read/write、内存破坏、整数溢出、提权、沙盒逃逸、RCE、竞态、UAF。
- 通过提取式 tweak 导出用户态 `IOSurface.framework` 符号地址与机器码，离线关联到报告。

**不能做的（设计边界）**

- **不生成 PoC、exploit 或任何利用代码**——只指出“哪里可能有问题”。
- 静态规则是**优先级排序工具**，不等于漏洞确认，所有条目都需人工逆向复核。
- ElleKit 是**用户态**框架，**不能 hook 内核 kext 本身**；内核内部靠 r2 静态分析。
- 提取式 tweak **不安装 inline hook、不改写任何函数行为**，只读取符号地址与字节。

> 请仅在有权测试的设备与固件上使用。

---

## 2. 安装

完整的安装步骤（分析端依赖、Sileo 装 deb、Actions 构建、卸载）见专门的 **[安装指南 INSTALL.md](INSTALL.md)**。这里只列最简命令：

```bash
# 分析端
cd iosvuln && python3 -m pip install -e .
iosvuln deps                 # 检查 ipsw / r2 / r2pipe
iosvuln home --init          # 初始化长期存储目录 ~/.iosvuln

# 设备端：Sileo 安装 Release 里的两个 deb，然后
iosvuln-collect              # 在设备上采集
```

从 [Releases](https://github.com/liaojinxuan666-eng/iosvuln/releases) 下载 `collect` 与 `extract` 两个 deb，Sileo「安装本地文件」即可，均为 rootless 布局。

---

## 3. 快速开始（无需真机）

先用 DEMO 模式跑通全流程，确认工具工作正常：

```bash
iosvuln demo --workdir /tmp/iosvuln-demo
```

它会用内置的合成 IOSurface 数据跑完提取 → 静态分析 → 报告，输出：

```
report.md / report.json / manifest.json
```

查看结果：

```bash
head -40 /tmp/iosvuln-demo/report.md
```

全目标 DEMO：

```bash
iosvuln demo --target all --workdir /tmp/iosvuln-demo-all
```

> DEMO 多目标模式下所有目标共用同一份合成函数数据，报告会明确警告这一点。它只用于验证流程，不代表真实漏洞。

---

## 4. 标准工作流

```
┌─ 设备端 ─────────────────────────────┐
│  iosvuln-collect [路径]              │  → /var/mobile/iosvuln/collection.json
│  提取式 tweak（自动加载）             │  → /var/mobile/iosvuln/extracted.json
└──────────────────────────────────────┘
              │ 把这两个 json 拷到分析端
              ▼
┌─ 分析端 ─────────────────────────────┐
│  1. iosvuln info          探测环境    │
│  2. iosvuln targets       选择目标    │
│  3. 采集输入（四选一）                 │
│  4. iosvuln run           运行分析    │
│  5. 查看 report.md / report.json      │
└──────────────────────────────────────┘
```

采集输入四选一，优先级从高到低：

| 方式 | 参数 | 适用场景 |
| --- | --- | --- |
| 已导出 kext 目录 | `--kext-dir <dir>` | 已用 ipsw 分离出 Mach-O，最稳 |
| 指定 kernelcache | `--kernelcache <path>` | 本地已有解压后的 kernelcache |
| 从设备拉取 | `--device [--device-path <path>]` | 越狱设备已连接 |
| 完整 IPSW | `--ipsw <file>` | 兼容旧流程，工具会自行提取 |

---

## 5. 第一步：探测环境

获取设备名、系统版本、Build、架构、内核信息，用于适配不同固件：

```bash
# 本地分析主机
iosvuln info

# 读取设备端采集器写好的 collection.json
iosvuln info --collection ./collection.json

# 直接查询 SSH 连接的越狱设备
iosvuln info --device --ssh-host root@localhost
```

输出示例：

```
Device: iPhone (iPhone15,2), iOS 17.5 (21F90), arch=arm64e, PAC=yes
{
  "name": "iPhone",
  "version": "17.5",
  ...
}
```

其中会推断 `major_version`、架构、是否支持 PAC、kernelcache 候选路径，供后续分析使用。

---

## 6. 第二步：查看并选择目标

列出内置高价值目标与从输入中发现的 kext：

```bash
iosvuln targets --kernelcache ./kernelcache.decompressed
iosvuln targets --kext-dir ./exported-kexts
iosvuln targets --kext-dir ./exported-kexts --json
```

表格包含四列：`#` 编号、`RISK` 风险等级、`AVAIL` 是否可用、`BUNDLE ID` 与说明。`AVAIL=no` 表示当前输入里没找到该 kext，选它也不会产出结果。

内置目录包含 10 个目标（IOSurface、AMFI、Sandbox、Mach IPC、IOKit、IOMobileFramebuffer 等）。

选择目标用 `--target`，支持四种写法：

```bash
--target 1,3,5                          # 按 targets 显示的编号
--target all                            # 全部可用目标（受 --max-targets 限制，默认 12）
--target auto                           # 等价于 catalog：内置目录里 high+medium 项
--target com.apple.driver.IOSurface     # bundle id
--target IOSurface                      # 名称子串（大小写不敏感）
```

多个 `--target` 参数可重复使用；也支持逗号分隔。交互式选择：

```bash
iosvuln run --interactive --device
```

---

## 7. 第三步：采集内核 / kext

### 7.1 设备端采集

用 Sileo 装好采集器 deb 后，在设备上执行：

```bash
iosvuln-collect
```

不传参数时自动探测常见 kernelcache 路径：

- `/System/Library/Caches/com.apple.kernelcaches/kernelcache`
- `/System/Library/Caches/com.apple.kernelcaches/kernelcache.release`
- `/private/System/Library/Caches/com.apple.kernelcaches/kernelcache`
- `/var/MobileAsset/Assets/com_apple_MobileAsset_Kernelcache/kernelcache`

也可以指定路径或目录：

```bash
iosvuln-collect /System/Library/Caches/com.apple.kernelcaches/kernelcache
iosvuln-collect /path/to/exported-kexts
```

结果写到 `/var/mobile/iosvuln/collection.json`，内容包括设备信息、源文件路径、大小、SHA256、以及命中的可疑 kext 字符串（`IOSurface`、`task_for_pid`、`mach_msg` 等）。脚本**只读文件，不打补丁、不利用、不执行目标**。

把它拷到分析端：

```bash
scp root@localhost:/var/mobile/iosvuln/collection.json .
scp root@localhost:/var/mobile/iosvuln/kernelcache .
```

### 7.2 用 ipsw 从 IPSW 提取（可选）

```bash
ipsw extract --kernel iPhone16,2_18.0.ipsw
ipsw kernel kexts <kernelcache>
ipsw kernel extract com.apple.driver.IOSurface -o ./exported-kexts
```

之后用 `--kext-dir ./exported-kexts` 或 `--kernelcache <path>` 指向结果。

### 7.3 从设备直接拉取

```bash
iosvuln run --device
iosvuln run --device --device-path /System/Library/Caches/com.apple.kernelcaches/kernelcache
iosvuln run --device --ssh-host root@localhost
```

工具会依次尝试 `ipsw idev afc pull`、`ipsw idev pull`、`scp root@localhost:<path>`。**提示**：这些 `ipsw idev` 子命令在不同版本里可能不存在，此时用 `--kext-dir` 或 `--kernelcache` 最可靠。

---

## 8. 第四步：运行分析

```bash
# 分析指定 kext 目录，选 IOSurface
iosvuln run --kext-dir ./exported-kexts \
            --target com.apple.driver.IOSurface \
            --workdir ./out

# 多目标 + 只看中危以上
iosvuln run --kernelcache ./kernelcache.decompressed \
            --target 1,3,5 --min-severity MEDIUM --workdir ./out

# 全量分析，最多 12 个目标
iosvuln run --kernelcache ./kernelcache.decompressed \
            --target all --max-targets 12 --workdir ./out

# 合并提取式 tweak 导出的符号地址
iosvuln run --kext-dir ./exported-kexts \
            --observations ./extracted.json --workdir ./out
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--workdir <dir>` | 输出目录，默认 `iosvuln-out` |
| `--target <spec>` | 目标，可重复 / 逗号分隔，见上文 |
| `--plugin <name>` | 只启用指定插件，可重复 |
| `--min-severity <level>` | 过滤阈值：`INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `--observations <file>` | hook 采集的日志 / 提取式 JSON |
| `--interactive` | 交互式选择目标 |
| `--quiet` | 只打印报告路径 |

---

## 9. 第五步：解读报告

分析完成后，`--workdir` 目录里会有：

| 文件 | 内容 |
| --- | --- |
| `report.html` | **推荐**：自包含单文件，浏览器打开，彩色分类、可折叠详细线索 |
| `report.md` | Markdown 报告，含摘要表 + 目录 |
| `report.json` | 结构化结果，便于二次处理 |
| `manifest.json` | r2 提取的中间表示（函数、调用、字符串） |

报告结构：

- **摘要 + 目录**：按漏洞类别的数量与最高严重度一览，点击目录跳转。
- **§0 环境信息**：设备 / 系统版本 / 架构 / 内核。
- **§0.1 可分析目标**：目录、可用性、已选目标。
- **§1–2**：流水线概览与统计。
- **§3.1 按原语归集的汇编位置**：核心输出，按漏洞类型分章节，**汇编地址完整列出不截断**。
- **§4 详细线索**：每条 finding 的证据、评分、置信度、CWE 与人工复核建议。

漏洞类型对照：

| 类型 | 含义 |
| --- | --- |
| `DANGLING_POINTER` | **野指针 / UAF**：释放后再次访问（free→use 调用序列） |
| `DOUBLE_FREE` | **重复释放**：释放次数多于分配次数 |
| `NULL_DEREF` | 指针访问前无分配 / 外部来源 / 校验 |
| `OOB_WRITE` / `MEMORY_CORRUPTION` | 用户输入源与 `memcpy` / `memmove` / `writeBytes` / 分配器共现 |
| `OOB_READ` | `copyout` / `readBytes` / `GetBaseAddress` 与 size/offset 共现 |
| `INTEGER_OVERFLOW` | 尺寸计算与分配/拷贝组合 |
| `PRIVILEGE_ESCALATION` | 外部方法、属性写入、`task_for_pid` 等内核能力入口 |
| `SANDBOX_ESCAPE` | mach port / task / VM 跨边界能力组合 |
| `RCE` | `blr`（函数指针）间接调用点 |
| `RACE` / `UAF` | 加解锁失衡，且伴随释放 / 引用计数操作 |

每条 finding 带 `assembly`（`地址: 指令 目标`）、`vuln_class`、`symbol`、证据与置信度。多目标时 `target` 字段标明来源 kext。

**报告里的地址只是“值得优先看的位置”**，需要你用 r2 / IDA / 反编译器复核参数来源、边界检查与权限判断。报告明确声明不生成利用代码。

---

## 10. 设备端采集器详解

采集器由 deb 的 `postinst` 安装到 `/usr/bin/iosvuln-collect`，实际脚本在 `/usr/lib/iosvuln/collect.sh`。

输出 `collection.json` 字段：

```json
{
  "tool": "iosvuln-collector",
  "mode": "file",
  "source": "/System/Library/Caches/com.apple.kernelcaches/kernelcache",
  "device": {
    "product": "iPhone OS",
    "version": "17.5",
    "build": "21F90",
    "model": "iPhone15,2",
    "arch": "arm64e",
    "kernel": "Darwin",
    "hostname": "..."
  },
  "size": 12345678,
  "sha256": "...",
  "local_copy": "/var/mobile/iosvuln/kernelcache",
  "kext_hits": [ ... ]
}
```

`mode` 取值：`auto`（自动探测）、`file`（指定文件）、`dir`（指定目录）。

设备信息通过 `sw_vers`、`sysctl`、`uname`、`hostname` 获取，各命令都有 fallback，缺失时留空而不是失败。

---

## 11. 提取式 ElleKit tweak

安装 `dev.iosvuln.extract_0.1.1_iphoneos-arm64.deb` 后，tweak 会在进程启动时用 `MSFindSymbol(NULL, name)` 解析以下符号：

```
IOSurfaceCreate / SetValue / CopyValue / RemoveValue / Lock / Unlock
GetBaseAddress / GetAllocSize / CreateMachPort / LookupFromMachPort
IncrementUseCount / DecrementUseCount
```

对每个找到的符号，导出其**地址 + 前 96 字节机器码**到 `/var/mobile/iosvuln/extracted.json`：

```json
{
  "target": "IOSurface.framework",
  "mode": "extractive",
  "functions": [
    {
      "name": "IOSurfaceCreate",
      "address": "0x1a2b3c4d",
      "bytes": "ff0301d6...",
      "length": 96
    }
  ]
}
```

关键点：

- **不 hook、不改写任何函数行为**，只读取地址与字节。
- 加载所有进程（filter plist 为空 `Filter`），以便在任意 App 中解析符号。
- 拷贝到分析端后用 `--observations ./extracted.json` 合并进报告。

自行编译 tweak（如需修改源码）：

```bash
cd templates/ellekit
make package FINALPACKAGE=1
```

产物在 `packages/` 下，用 Sileo 安装即可。需要 Theos + iOS SDK（GitHub Actions 的 `build-release.yml` 已自动化这一过程）。

---

## 12. 长期存储目录

`--workdir` 是**单次分析的输出目录**，容易被清理或覆盖。工具另外维护一个**长期存储目录**（默认 `~/.iosvuln/`），用于跨次持久保存：

```
~/.iosvuln/
├── collections/     # 从设备导入的 collection.json / extracted.json
├── cache/           # kernelcache / kext 缓存（含 kexts/ 子目录）
├── reports/         # 每次分析的历史报告快照（按时间戳 + 目标命名）
├── tweaks/          # 最近一次生成的 ElleKit 工程
├── logs/            # 会话日志
└── config.json      # 默认目标、插件、严重度等偏好
```

**自动行为**：每次 `iosvuln run` / `demo` 成功后，会按时间戳把 `report.md` / `report.json` / `manifest.json` 快照到 `reports/`，并把生成的 tweak 工程存到 `tweaks/`。分析时若未在 `--workdir` 找到 `extracted.json`，会自动从长期存储里找最近导入的那份。

**管理命令**：

```bash
iosvuln home                    # 查看当前路径与目录结构
iosvuln home --init             # 显式创建目录与默认配置
iosvuln home --json             # JSON 格式查看

# 把设备采集文件导入长期存储（带时间戳，不覆盖原件）
iosvuln import ./collection.json
iosvuln import ./extracted.json
iosvuln import ./kernelcache
iosvuln import ./session.log --kind log

# 查看历史归档
iosvuln history
iosvuln history --limit 5 --json
```

**改路径**（三选一，优先级从高到低）：

```bash
iosvuln run --home /data/iosvuln ...   # 单次：--home 参数
export IOSVULN_HOME=/data/iosvuln      # 长期：环境变量（推荐写进 shell 配置）
iosvuln home --home /data/iosvuln --init
```

**关闭自动归档**：给 `run` / `demo` 加 `--no-archive`，报告只写 `--workdir`，不进长期存储。

> 设备端对应目录是 `/var/mobile/iosvuln/`。装了 `analyze` deb 后，手机端分析器会自动把 home 指向这里，与采集器、提取式 tweak **共用同一份完整目录、数据互通**；电脑端与手机端各自独立。详见 [INSTALL.md 的手机端分析端章节](INSTALL.md)。

---

## 13. 命令参考

```
iosvuln run            执行完整流水线（加 --demo 使用合成数据）
iosvuln demo           等价于 run --demo
iosvuln info           探测设备 / 环境信息
iosvuln targets        列出可分析目标
iosvuln kexts <cache>  列出 kernelcache 中的 kext
iosvuln hook-scaffold  生成 ElleKit tweak 工程源码
iosvuln home           查看/初始化长期存储目录（--init / --json）
iosvuln import <file>  导入采集文件到长期存储（--kind 指定类型）
iosvuln history        列出历史归档报告（--limit / --json）
iosvuln deps           检查 ipsw / r2 / r2pipe 可用性
iosvuln plugins        列出已注册分析插件
iosvuln --version      显示版本
```

`run` / `demo` 常用：`--home <dir>` 指定长期目录、`--no-archive` 关闭归档、`--no-progress` 关闭实时进度条与漏洞计数（默认开启，边分析边显示已发现的疑似漏洞数）。

分析完成后查看 HTML 报告：`open <workdir>/report.html`（macOS）或直接在浏览器/文件管理器打开。

设备端：

```
iosvuln-collect [路径]   采集 kernelcache / kext 与设备信息
```

---

## 14. 常见问题

**Q：`ipsw idev` 子命令不存在？**
不同版本 ipsw 的子命令不一样。直接用 `--kext-dir` 或 `--kernelcache` 指定本地文件最稳，设备端用采集器导出。

**Q：报告里全是 DEMO 数据？**
说明 `ipsw` / `r2` 缺失或没提供有效输入，工具自动降级了。运行 `iosvuln deps` 检查依赖。

**Q：`AVAIL=no` 的目标能分析吗？**
不能。它表示当前输入里没找到该 kext。请换用包含它的 kernelcache，或用 `--kext-dir` 指向导出的 Mach-O。

**Q：tweak 装了但没生成 `extracted.json`？**
确认设备已越狱且 ElleKit 生效、tweak 已启用；filter plist 为空表示加载所有进程。也可检查 `/var/mobile/iosvuln/` 目录权限。

**Q：为什么没有 PoC？**
这是设计选择。工具只标注疑似漏洞的汇编位置，是否可利用、如何触发由分析人员判断。

**Q：想加自己的分析规则？**
在 `iosvuln/static_rules.py` 里用 `@register` 装饰器新增插件类，然后用 `--plugin <name>` 启用。
