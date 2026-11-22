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
   ├─ vuln-primitives / pointer-safety / taint-sink / lock-balance / api-risk / surface-props
   └─ 提取式 ElleKit tweak 导出的符号地址 + 机器码
5. report.md / report.html / report.json（按原语归集的汇编位置，实时进度条）
```

**提取式 Hook**：`Tweak.xm` 用 `MSFindSymbol` 解析 `IOSurface.framework` 符号，导出函数地址与前 96 字节机器码到 `/var/mobile/iosvuln/extracted.json`。**不安装 inline hook、不改写任何函数行为**。

## 安装

分析端（macOS / Linux）：

```bash
pip3 install -e .
pip3 install '.[r2]'      # 可选：r2pipe
```

设备端（Sileo 安装，三个 deb）：

| deb | 作用 |
| --- | --- |
| `dev.iosvuln.analyze_0.1.1_iphoneos-arm64.deb` | **完整分析端**：整套 Python 引擎 + `iosvuln` 命令，手机本地即可跑全部分析 |
| `dev.iosvuln.collect_0.1.1_iphoneos-arm64.deb` | 采集器 `iosvuln-collect [路径]`，采集 kernelcache/kext + 设备信息 |
| `dev.iosvuln.extract_0.1.1_iphoneos-arm64.deb` | 提取式 tweak（已编译 dylib），导出 `IOSurface.framework` 符号地址与机器码 |

三者共用长期目录 `/var/mobile/iosvuln/`（collections/cache/reports/tweaks/logs/config.json），数据互通。

手机端依赖（均可从 **Procursus 源**用 Sileo 安装，截图已确认可用）：`python3`、`radare2`、`ipsw`。装了 `ipsw` 后手机端也能直接从 IPSW 提取内核；这些命令缺失时自动降级 DEMO。安装 `analyze` deb 会自动把 zsh 快捷命令写入 `~/.zshrc`（NewTerm 直接可用）：

```
iv   = iosvuln        ivs  = 扫描当前目录   ivd  = demo        ivi  = info
ivt  = targets        ivh  = home           ivim = import      ivl  = history
ivk <kernelcache>     = 直接扫描指定内核    ivall = 采集+扫描一条龙
```

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
iosvuln run --no-progress --workdir ./out           # 关闭进度条（默认显示）
```

`--target` 支持：`all`/`*`（全量，受 `--max-targets` 限制）、`auto`/`catalog`（内置目录中高风险目标）、`1,3,5`（`iosvuln targets` 显示的编号）、任意 bundle id / 名称子串。

## 输出

报告输出 **Markdown + HTML + JSON** 三种格式，含**摘要表、目录、按原语分类章节**，汇编位置**完整列出不截断**：

| 原语 | 含义 |
| --- | --- |
| `DANGLING_POINTER` | **野指针 / UAF**：释放后再次访问（基于 free→use 调用序列与地址） |
| `DOUBLE_FREE` | **重复释放**：释放次数多于分配次数 |
| `NULL_DEREF` | 指针访问前无分配/外部来源/校验 |
| `OOB_WRITE` / `MEMORY_CORRUPTION` | 用户输入源与 `memcpy` / `memmove` / `writeBytes` / 分配器共现 |
| `OOB_READ` | `copyout` / `readBytes` / `GetBaseAddress` 与 size/offset 共现 |
| `INTEGER_OVERFLOW` | 尺寸计算与分配/拷贝组合 |
| `PRIVILEGE_ESCALATION` | 外部方法、属性写入、`task_for_pid` 等内核能力入口 |
| `SANDBOX_ESCAPE` | mach port / task / VM 跨边界能力组合 |
| `RCE` | 认证/未认证间接调用点（`braa` / `blr`） |
| `RACE` / `UAF` | 加解锁失衡，且伴随释放/引用计数操作 |
| `PAC_BYPASS` | **arm64e**：`xpac` 签名剥离、未认证 `blr` 间接调用（函数指针未签名） |
| `PAC_DOWNGRADE` | **arm64e**：整个 kext 无 PAC 指令，疑似降级编译 / 未启用指针认证 |
| `PAC_SIGN_MISMATCH` | **arm64e**：A/B 密钥混用、签名后无验证 |
| `FORMAT_STRING` | 用户可控格式串（`sprintf` / `os_log` + `%s`/`%n`） |
| `UNINITIALIZED` | 分配后未经清零即 `copyout` 外传内核堆内容 |
| `TOCTOU` | 同一函数多次 `copyin`（double-fetch 检查-使用竞态） |
| `STACK_OVERFLOW` | `strcpy`/`sprintf`/`alloca` 无界栈操作与尺寸字段共现 |
| `TYPE_CONFUSION` | 对象强制转换缺少动态类型校验 |

每条 finding 带 `assembly`（`地址: 指令 目标`）、`vuln_class`、`symbol`、证据和置信度。多目标时每条 finding 的 `target` 字段标明来源 kext。`report.html` 是自包含的单文件，可直接用浏览器打开，详细线索可折叠。

### arm64e PAC 专项

r2 后端会额外采集 **PAC 指令**（认证分支 `braa`/`blraa`/`retaa`、签名 `pacia`、验证 `autia`、剥离 `xpaci`、BTI 等）到每个函数的 `pac_sites`，由 `pac-security` 插件据此判断绕过面。判断依据都是**可复核的指令证据**：

- 有 `xpaci`/`xpacd` → 签名被剥离，是绕过 PAC 的经典前置
- 有 `blr` 间接调用、全 kext 却无 `braa`/`blraa` 认证分支 → 函数指针未签名
- 全 kext 零 PAC 指令 → 疑似降级编译（PAC 未启用，利用门槛降低）
- A/B 密钥族混用、签名无验证 → 密钥空间误用

> 说明：PAC 静态检测定位的是**绕过面与降级迹象**，不如动态 PAC 违例那样确定，每条都标注置信度，需人工复核指针来源与签名约定。

## 插件与测试

内置：`vuln-primitives`、`pointer-safety`、`pac-security`、`advanced-threats`、`taint-sink`、`lock-balance`、`api-risk`、`surface-props`、`hook-observation`。

分析过程默认显示**实时进度条**，动态更新已发现的疑似漏洞数量；用 `--no-progress` 关闭。

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v   # 15 项
```

## 说明

- 静态规则是优先级排序工具，不替代人工逆向；所有条目需人工复核。
- 提取式 tweak 只导出用户态符号；内核 kext 内部靠 r2 静态分析，按地址关联。
- DEMO 多目标模式所有目标共用同一份合成函数数据（报告会明确警告）。
- 请仅在有权测试的设备与固件上使用。
