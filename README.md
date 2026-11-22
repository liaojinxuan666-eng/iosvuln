# iosvuln

iOS 内核驱动（kext）**静态 + 提取式 Hook 双层分析流水线**。只标注**内存破坏 / OOB read / 提权原语 / 沙盒逃逸 / RCE 等漏洞类型对应的汇编地址**，**不生成 PoC 或利用代码**。

## 设计

```
输入（四选一，不再强制完整 IPSW）
  1. --kext-dir <dir>      已导出的 kext Mach-O 目录
  2. --kernelcache <path>  指定路径的内核缓存
  3. --device              从已连接越狱设备拉取
  4. --ipsw <file>         兼容旧流程
        │
        ├─ ipsw kernel kexts / extract  → kext 清单 + Mach-O
        └─ r2 / r2pipe                   → AnalysisManifest（含每条调用的汇编地址）
                 ├─ vuln-primitives / taint-sink / lock-balance / api-risk / surface-props
                 └─ 提取式 ElleKit tweak 导出的符号地址 + 机器码
                        → report.md / report.json（按原语归集的汇编位置）
```

**提取式 Hook 的含义**：ElleKit 组件（`Tweak.x`）用 `MSFindSymbol` 解析 `IOSurface.framework` 符号，把函数地址与前 96 字节机器码写入 `/var/mobile/iosvuln/extracted.json`。它**不安装 inline hook、不改写任何函数行为**，只做"提取"。分析在离线侧完成。

## 安装与使用

分析端（macOS / Linux）：

```bash
pip3 install -e .
pip3 install '.[r2]'      # 可选：r2pipe
```

设备端：用 **Sileo 安装** `packaging/dev.iosvuln.collect_0.1.0_iphoneos-arm64.deb`。它是 rootless 采集器，提供 `iosvuln-collect [路径]`，从系统缓存路径或你指定的路径读取 kernelcache/kext，输出 `/var/mobile/iosvuln/collection.json`。deb 里同时附带提取式 tweak 源码（`Tweak.x`/`Makefile`/`control`），需你自己用 Theos 编译成 tweak.deb——当前 deb **不包含已编译的 dylib**（沙箱没有 iOS SDK）。

```bash
# 设备上
iosvuln-collect /System/Library/Caches/com.apple.kernelcaches/kernelcache
scp root@localhost:/var/mobile/iosvuln/collection.json .

# 分析端
iosvuln run --kext-dir ./exported-kexts --workdir ./out
iosvuln run --device --device-path /System/Library/Caches/com.apple.kernelcaches/kernelcache
iosvuln run --kernelcache ./kernelcache.decompressed --min-severity MEDIUM
iosvuln demo --workdir /tmp/iosvuln-demo      # 无依赖演示
```

`--device` 会依次尝试 `ipsw idev afc pull` / `ipsw idev pull` / `scp root@localhost:<path>`；也可以 `--ssh-host` 指定主机。

## 输出重点

报告新增 **§3.1 按原语归集的汇编位置**，例如：

| 原语 | 含义 |
| --- | --- |
| `OOB_WRITE` / `MEMORY_CORRUPTION` | 用户输入源与 `memcpy`/`memmove`/`writeBytes`/分配器共现 |
| `OOB_READ` | `copyout`/`readBytes`/`GetBaseAddress` 与 size/offset 共现 |
| `INTEGER_OVERFLOW` | 尺寸计算与分配/拷贝组合 |
| `PRIVILEGE_ESCALATION` | 外部方法、属性写入、`task_for_pid` 等内核能力入口 |
| `SANDBOX_ESCAPE` | mach port / task / VM 跨边界能力组合 |
| `RCE` | `blr`（函数指针）间接调用点 |
| `RACE` / `UAF` | 加解锁失衡，且伴随释放/引用计数操作 |

每条 finding 都带 `assembly`（`地址: 指令 目标`）、`vuln_class`、`symbol`、证据和置信度。报告明确声明不生成利用代码。

## 插件

```
vuln-primitives  按原语分类并输出汇编地址（核心）
taint-sink       输入源→危险操作共现
lock-balance     加解锁失衡
api-risk         高风险 API / 复杂控制流
surface-props    IOSurface 外部入口专项
hook-observation 提取式符号导出 + 用户态观测归并
```

自定义插件继承 `Plugin` 并用 `@register` 注册，见 README 前文或 `iosvuln/static_rules.py`。

## 测试

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## 说明

- 静态规则是优先级排序工具，不替代人工逆向；所有条目需人工复核。
- 提取式 tweak 只导出用户态符号；内核 kext 内部靠 r2 静态分析，二者按地址关联。
- 请仅在有权测试的设备与固件上使用。

## 结构

```
iosvuln/
├── iosvuln/            CLI、配置、模型、采集、ipsw/r2 后端、规则插件、报告
├── templates/ellekit/  提取式 Tweak.x + Theos 工程
├── packaging/deb/      Sileo 采集器 deb 源码；build_deb.sh 构建
├── examples/           demo fixtures（含汇编调用地址）
└── tests/              unittest
```
