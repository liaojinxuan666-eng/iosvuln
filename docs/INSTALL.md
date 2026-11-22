# iosvuln 安装指南

iosvuln 分两端：**分析端**（你的 Mac / Linux 电脑，跑 Python 工具）和**设备端**（越狱 iPhone，采集内核数据 + 提取式 tweak）。两端通过文件交换数据，无需一直连线。

本文只讲安装。功能用法见 [USAGE.md](USAGE.md)。

---

## 一、分析端安装（macOS / Linux）

### 1. 环境要求

- Python 3.11+
- 可选但推荐：`ipsw`（提取内核）、`radare2`（反汇编）

### 2. 安装工具

从仓库克隆并安装：

```bash
git clone https://github.com/liaojinxuan666-eng/iosvuln.git
cd iosvuln
python3 -m pip install -e .
```

这会把 `iosvuln` 命令装到当前 Python 环境。验证：

```bash
iosvuln --version
iosvuln deps        # 检查 ipsw / r2 / r2pipe 是否就绪
```

### 3. 可选依赖

```bash
# r2 后端：真实反汇编（否则工具自动降级到 DEMO 合成数据）
python3 -m pip install '.[r2]'

# ipsw：从 IPSW / 设备提取 kernelcache（blacktop/ipsw）
brew install blacktop/tap/ipsw          # macOS
# 或到 https://github.com/blacktop/ipsw/releases 下载对应平台二进制
```

`ipsw` 与 `r2` 不是必须的：缺失时工具会走内置合成数据，仍能跑通全流程（用 `iosvuln demo`）。

### 4. 初始化长期存储目录

工具会在 `~/.iosvuln/` 建立一个**长期存储目录**，用于持久保存采集数据、缓存、历史报告和 hook 工程。显式初始化：

```bash
iosvuln home --init
```

输出目录结构：

```
~/.iosvuln/
├── collections/     # 从设备导入的 collection.json / extracted.json
├── cache/           # kernelcache / kext 缓存
│   └── kexts/
├── reports/         # 每次分析的历史报告快照
├── tweaks/          # 最近一次生成的 ElleKit 工程
├── logs/            # 会话日志
└── config.json      # 默认目标、插件、严重度等偏好
```

想放到别处，用环境变量或参数：

```bash
export IOSVULN_HOME=/data/iosvuln      # 推荐：写进 shell 配置长期生效
iosvuln home --home /data/iosvuln --init
iosvuln run --home /data/iosvuln ...   # 单次覆盖
```

### 5. 卸载分析端

```bash
python3 -m pip uninstall iosvuln
# 长期数据需手动删除：rm -rf ~/.iosvuln（或你设置的 IOSVULN_HOME）
```

---

## 二、设备端安装（越狱 iPhone，Sileo）

### 1. 前提

- 已越狱（rootless，如 Dopamine）
- 已安装 Sileo
- 已安装 ElleKit（rootless 越狱通常默认带；提取式 tweak 依赖它提供 `MSFindSymbol`）

### 2. 下载 deb

到 [Releases](https://github.com/liaojinxuan666-eng/iosvuln/releases) 下载，共三个 deb：

| 文件 | 作用 | 是否必须 |
| --- | --- | --- |
| `dev.iosvuln.analyze_0.1.1_iphoneos-arm64.deb` | **完整分析端**：把整套 Python 引擎装到手机，提供 `iosvuln` 命令 | 想在手机上直接分析时装 |
| `dev.iosvuln.collect_0.1.1_iphoneos-arm64.deb` | 设备侧采集器 `iosvuln-collect` | 采集内核数据时装 |
| `dev.iosvuln.extract_0.1.1_iphoneos-arm64.deb` | 提取式 tweak（已编译 dylib），导出符号地址与机器码 | 想导出符号地址时装 |

> **`analyze` 是完整分析端**：装了它，iPhone 自己就能跑 `iosvuln run / demo / home / import / history` 等全部命令，不用再依赖电脑。它和 `collect`、`extract` 共用同一个长期目录 `/var/mobile/iosvuln/`，三者数据互通。

### 3. 用 Sileo 安装

1. 打开 Sileo → 底部「Sources」→ 右上「Edit」→ 「Add Source」可跳过（这里用本地包）。
2. Sileo → 右上搜索/菜单 → 「Install Local File」/「安装本地文件」。
3. 选中下载的 deb（可一次选多个），确认安装。
4. 安装完成后**重启 SpringBoard** 或重启设备，让 tweak 注入生效。
5. 若装了 `analyze`，**先装 Python 3**：Sileo 搜索并安装 `python3`（依赖已声明，通常会自动提示）。

> 三个包都是 rootless 布局，文件落在 `/var/jb/...`。`iosvuln` 与 `iosvuln-collect` 命令均已加入 PATH。

### 3.1 手机端完整分析端（analyze）

装好 `analyze` + `python3` 后，SSH 进手机即可跑**完整分析端**，用法与电脑端完全一致：

```bash
ssh root@localhost

iosvuln --version
iosvuln deps                    # 检查 python / r2；没有 r2 也能跑 demo
iosvuln home                    # 查看长期目录（自动指向 /var/mobile/iosvuln）
iosvuln demo --workdir /var/mobile/iosvuln-demo   # 无需网络，用内置数据跑通全流程
iosvuln info
iosvuln targets --kernelcache /path/to/kernelcache
iosvuln run --kernelcache /var/mobile/iosvuln/kernelcache \
            --target com.apple.driver.IOSurface \
            --workdir /var/mobile/iosvuln-run
iosvuln import /var/mobile/iosvuln/extracted.json
iosvuln history
```

**手机端长期目录**（安装时 `postinst` 自动建好，与电脑端结构一个不少）：

```
/var/mobile/iosvuln/
├── collections/     # 导入的 collection.json / extracted.json
├── cache/           # kernelcache / kext 缓存（含 kexts/ 子目录）
├── reports/         # 每次分析的历史报告快照
├── tweaks/          # 最近生成的 ElleKit 工程
├── logs/            # 会话日志
└── config.json      # 默认配置
```

手机端会自动把 home 指向 `/var/mobile/iosvuln`（由 `storage.py` 的 iOS 检测决定），因此分析端、采集器、提取式 tweak 三方数据落在同一处、自动互通。也可用 `IOSVULN_HOME` 覆盖。

**Procursus 依赖（推荐全装）**：这三样都能从 **Procursus 源**用 Sileo 直接安装，已实测可用：

- `python3` — 分析引擎运行时（analyze deb 已声明依赖）
- `radare2` — 真实反汇编；没装时自动降级 DEMO 合成数据
- `ipsw` — iOS 越狱包（Procursus 3.1.x），装了以后手机端也能直接从 IPSW 提取内核、列 kext

工具会自动探测 `/var/jb/usr/bin`、`/usr/bin` 等路径下的 `ipsw`/`r2`，无需手动配路径。装齐后手机端能力与电脑端一致：既能 `--ipsw` 从完整包提取，也能 `--kernelcache` / `--kext-dir` 分析已有数据。

**arm64e PAC 分析**：分析 A12+ 设备的 arm64e kext 时，r2 会采集 PAC 指令并由 `pac-security` 插件检测签名剥离（`xpac`）、未认证间接调用、PAC 降级与密钥失衡。这依赖真实反汇编（radare2），DEMO 模式用的是内置 PAC 合成指令演示流程；静态结果是绕过面定位，需人工复核。

**zsh 快捷命令**：`analyze` deb 安装时会自动向 `~/.zshrc` 写入一行 source，NewTerm 重开后即可用短命令：

```
iv                    = 无参数直接一站式扫描（auto）
ivs   = scan          ivf  = scan --full        ivd  = scan --from demo
ivz   = scan --preset fast                      ivp  = scan --preset pac
ivx   = scan --preset deep --full               ivi  = info
ivt   = targets       ivh  = home               ivim = import     ivl = history
ivk <kernelcache>     = 扫描指定内核            ivipsw <file> = 扫描 IPSW
ivall                 = 采集+扫描一条龙
```

例如手机上一条命令扫描内核：`ivk /var/mobile/iosvuln/kernelcache`，或 `ivf` 全量扫描、`iv` 自动扫描。进度条会实时显示已找到的疑似漏洞数，完成后报告自动归档到 `/var/mobile/iosvuln/reports/`。

### 4. 验证安装

SSH 进设备：

```bash
ssh root@localhost

# 采集器是否可用
which iosvuln-collect
iosvuln-collect

# 采集结果
cat /var/mobile/iosvuln/collection.json

# 若装了提取式 tweak，检查符号导出
cat /var/mobile/iosvuln/extracted.json
```

设备端的长期目录固定为 `/var/mobile/iosvuln/`，与电脑端的 `~/.iosvuln/` 对应但相互独立。

### 5. 把数据传回分析端

```bash
scp root@localhost:/var/mobile/iosvuln/collection.json ./collection.json
scp root@localhost:/var/mobile/iosvuln/extracted.json   ./extracted.json
scp root@localhost:/var/mobile/iosvuln/kernelcache      ./kernelcache
```

导入长期存储（可选，便于工具自动发现）：

```bash
iosvuln import ./collection.json
iosvuln import ./extracted.json
iosvuln import ./kernelcache
```

### 6. 卸载设备端

Sileo → Installed → 找到对应包 → Remove；或用命令：

```bash
dpkg -r dev.iosvuln.collect
dpkg -r dev.iosvuln.extract
dpkg -r dev.iosvuln.analyze
```

长期数据需手动删除：

```bash
rm -rf /var/mobile/iosvuln
```

---

## 三、GitHub Actions 自动构建 release（维护者）

`v0.1.x` 的 deb 由 `.github/workflows/build-release.yml` 在 macOS runner 上自动构建，无需本地 Theos：

```bash
# 手动触发（需仓库写权限的 token）
gh api repos/liaojinxuan666-eng/iosvuln/actions/workflows/build-release.yml/dispatches \
  -f ref=main -F 'inputs[tag]=v0.1.2'
```

工作流会：装 Theos + iOS SDK → 编译提取式 tweak → 打包采集器 deb → 压缩源码 → 发布到 Release。产物见 Release 页面。

本地重建采集器 deb（不需要 iOS SDK）：

```bash
bash packaging/build_deb.sh
# 输出 packaging/dev.iosvuln.collect_0.1.1_iphoneos-arm64.deb
```

本地编译 tweak 才需要 Theos + iOS SDK：

```bash
cd templates/ellekit
make package FINALPACKAGE=1
```

---

## 四、常见问题

**Q：`pip install -e .` 提示权限错误？**
用虚拟环境：`python3 -m venv .venv && source .venv/bin/activate`，再装。

**Q：`iosvuln deps` 显示 r2 缺失？**
按上文装 radare2 / r2pipe。缺失时工具仍可用 DEMO 模式，但没有真实反汇编。

**Q：Sileo 装 tweak 后没有 `extracted.json`？**
确认 ElleKit 生效、tweak 已启用，且进程重启过。提取式 tweak 的 filter 为空（加载所有进程），会在任意 App 启动时写文件。

**Q：长期存储目录在哪 / 怎么改？**
默认 `~/.iosvuln`，用 `IOSVULN_HOME` 环境变量或 `--home` 参数改。`iosvuln home` 可查看当前路径与结构。

**Q：采集器读不到 kernelcache？**
rootless 路径与真机不一致时，用 `iosvuln-collect <明确路径>` 指定，或参考 [USAGE.md](USAGE.md) 的设备采集章节。
