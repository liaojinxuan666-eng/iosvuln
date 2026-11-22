"""Static heuristics that turn an AnalysisManifest into ranked findings.

These are intentionally transparent, data-driven rules: every finding carries
the exact call/string evidence that triggered it, so a researcher can confirm
or discard it quickly. No rule claims to be a proof of exploitability.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Sequence, Tuple

from .models import AnalysisManifest, CallSite, Finding, Function, Layer, Severity
from .plugins import AnalysisContext, Plugin, register

# Kernel-side entry points where user-controlled data reaches a kext.
SOURCE_TOKENS = (
    "copyin", "copyout", "copyinstr", "externalmethod", "ioexternalmethodarguments",
    "ioconnectcall", "ioconnectset", "machmsg", "taskforpid", "currenttask",
    "withaddressrange", "getproperty", "setproperty", "setvalue", "getvalue",
    "iobuf", "request", "usermemory", "sharedmemory", "iomemorydescriptor",
)

# Dangerous operations whose arguments/size may be attacker-influenced.
SINK_TOKENS = (
    "memcpy", "memmove", "bcopy", "strcpy", "strncpy", "sprintf", "snprintf",
    "sscanf", "kalloc", "kfree", "osmalloc", "osfree", "iomalloc", "iofree",
    "kmemalloc", "writebytes", "readbytes", "setobject", "getobject", "copybytes",
)

LOCK_TOKENS = (
    "iolocklock", "recursivelocklock", "simplelocklock", "lckmtxlock",
    "mutexlock", "spinlocklock", "kspinlock", "rwlockwrlock", "semaphorewait",
)
UNLOCK_TOKENS = (
    "iolockunlock", "recursivelockunlock", "simplelockunlock", "lckmtxunlock",
    "mutexunlock", "spinlockunlock", "kspinunlock", "rwlockwrunlock", "semaphoresignal",
)

API_RISK_TOKENS = (
    "strcpy", "sprintf", "sscanf", "alloca", "vm_allocate", "vmallocate",
    "memcpy", "memmove", "bcopy", "kalloc", "iomalloc", "osmalloc",
)

SURFACE_FN_HINTS = (
    "setproperty", "getproperty", "initwithproperties", "externalmethod",
    "setvalue", "getvalue", "createbuffer", "allocatesurface", "mapmemory",
)

# Format-string sinks (functions whose first argument is a format string).
FORMAT_TOKENS = (
    "printf", "sprintf", "snprintf", "os_log", "os_log_with_type", "kprintf",
    "syslog", "fprintf", "asprintf", "vasprintf", "vprintf", "vsnprintf",
    "nslog", "log", "print",
)
# Uninitialized-memory reads that leak heap contents OUT to userspace.
# Only export-to-user sinks qualify here; plain alloc->memcpy is an internal
# operation and handled by the taint/OOB rules instead (avoids noise).
UNINIT_READ_TOKENS = (
    "copyout", "getbytes", "writebytes", "copybytes",
)
# Zeroing / initialization calls that legitimize a copy-out.
ZERO_TOKENS = ("memset", "bzero", "memsetpattern", "zero", "memclear")
# Two fetches of the same user buffer -> check/use race (double-fetch).
FETCH_TOKENS = ("copyin", "copyinstr", "copyfromuser", "vmread", "readuser")
# Cast / type-coercion APIs without an accompanying dynamic type check.
CAST_TOKENS = (
    "osdynamiccast", "osrequiredcast", "staticcast", "dynamiccast",
    "reinterpretcast", "getmetaclass", "osobject", "ismemberof",
)
# Bounds / validation calls that would legitimize a size/offset.
BOUND_TOKENS = (
    "checksize", "validate", "validaterange", "boundscheck", "clamp",
    "checklength", "verify", "inbounds", "range_check", "safecast",
)


def _norm(value: str) -> str:
    value = value.lower().replace("sym.imp.", "").replace("imp.", "")
    value = re.sub(r"[^a-z0-9_:]", "", value)
    return value.lstrip("_")


def _hits(names: Sequence[str], tokens: Sequence[str]) -> List[str]:
    normalized = [(name, _norm(name)) for name in names]
    found: List[str] = []
    for token in tokens:
        for original, norm in normalized:
            if token in norm and token not in found:
                found.append(token)
                break
    return found


def _assembly(fn: Function, tokens: Sequence[str] = (), limit: int = 6) -> List[str]:
    """Concrete assembly locations for a finding.

    With r2 we use real instruction offsets; fixtures without instruction data
    fall back to the function entry plus the call target name.
    """
    sites: List[CallSite] = list(fn.call_sites)
    if tokens:
        sites = [s for s in sites if any(t in _norm(s.target) for t in tokens)]
    if sites:
        return [s.render() for s in sites[:limit]]
    return [f"{fn.address}: bl {call}" for call in fn.calls[:limit] if fn.address]


def _id(plugin: str, manifest: AnalysisManifest, fn: Function, title: str) -> str:
    raw = f"{plugin}|{manifest.target}|{fn.name}|{title}".encode("utf-8", "replace")
    return hashlib.md5(raw).hexdigest()[:10]


def _base_kwargs(plugin: str, manifest: AnalysisManifest, fn: Function, title: str) -> Dict:
    return {
        "id": _id(plugin, manifest, fn, title),
        "title": title,
        "layer": Layer.STATIC,
        "target": manifest.target,
        "location": f"{fn.name} @ {fn.address}" if fn.address else fn.name,
    }


class _RulePlugin(Plugin):
    layer = "static"

    def run(self, context: AnalysisContext) -> List[Finding]:
        return self._scan(context.manifest)

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError


@register
class TaintSinkPlugin(_RulePlugin):
    name = "taint-sink"
    description = "用户态输入源与危险内存操作共现的函数（潜在校验缺失）"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        for fn in manifest.functions:
            # Only function-local calls count: using global imports/strings here
            # would flag every function in the binary (false positives).
            names = list(fn.calls)
            sources = _hits(names, SOURCE_TOKENS)
            sinks = _hits(names, SINK_TOKENS)
            if not sources or not sinks:
                continue
            score = 18.0 + 22.0 + min(12.0, 4.0 * (len(sinks) - 1))
            if any(h in _norm(fn.name) for h in SURFACE_FN_HINTS):
                score += 12.0
            if fn.complexity > 12:
                score += 8.0
            confidence = min(0.85, 0.45 + 0.1 * len(sources) + 0.08 * len(sinks))
            write_sinks = ("memcpy", "memmove", "bcopy", "writebytes", "copybytes")
            vuln_class = (
                "OOB_WRITE" if any(t in sinks for t in write_sinks) else "MEMORY_CORRUPTION"
            )
            if any(t in sinks for t in ("kalloc", "iomalloc", "osmalloc")) and len(sinks) > 1:
                vuln_class = "INTEGER_OVERFLOW"
            findings.append(
                Finding(
                    **_base_kwargs(self.name, manifest, fn, "用户输入与危险内存操作共现"),
                    severity=Severity.from_score(score),
                    vuln_class=vuln_class,
                    assembly=_assembly(fn, list(sources) + list(sinks)),
                    symbol=fn.name,
                    description=(
                        f"函数同时引用输入源 {sources} 与危险操作 {sinks}；"
                        "需人工核对长度/边界校验与引用计数是否完整。"
                    ),
                    evidence=[f"source: {s}" for s in sources] + [f"sink: {s}" for s in sinks],
                    score=round(score, 1),
                    confidence=round(confidence, 2),
                    cwe="CWE-20 Improper Input Validation",
                    recommendation="检查所有 size/offset 参数是否有上界校验，以及失败路径是否释放已分配对象。",
                    tags=list(dict.fromkeys(sources + sinks)),
                )
            )
        return findings


@register
class LockBalancePlugin(_RulePlugin):
    name = "lock-balance"
    description = "加解锁不配对的函数（潜在竞态或死锁）"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        for fn in manifest.functions:
            names = fn.calls
            locks = _hits(names, LOCK_TOKENS)
            unlocks = _hits(names, UNLOCK_TOKENS)
            if not locks and not unlocks:
                continue
            diff = abs(len(locks) - len(unlocks))
            if diff == 0:
                continue
            score = 20.0 + 20.0 * diff
            if any(h in _norm(fn.name) for h in SURFACE_FN_HINTS):
                score += 10.0
            findings.append(
                Finding(
                    **_base_kwargs(self.name, manifest, fn, "加解锁调用不配对"),
                    severity=Severity.from_score(score),
                    vuln_class="UAF" if _hits(fn.calls, ("kfree", "iofree", "release", "osfree")) else "RACE",
                    assembly=_assembly(fn, list(LOCK_TOKENS) + list(UNLOCK_TOKENS)),
                    symbol=fn.name,
                    description=(
                        f"观察到 {len(locks)} 个加锁、{len(unlocks)} 个解锁调用；"
                        "差异可能来自提前 return、异常分支或跨函数调用，需人工确认。"
                    ),
                    evidence=[f"lock: {x}" for x in locks] + [f"unlock: {x}" for x in unlocks],
                    score=round(score, 1),
                    confidence=0.55 if diff == 1 else 0.68,
                    cwe="CWE-667 Improper Locking",
                    recommendation="沿所有 return / error 分支确认锁状态，重点关注对象释放前的持锁窗口。",
                    tags=locks + unlocks,
                )
            )
        return findings


@register
class ApiRiskPlugin(_RulePlugin):
    name = "api-risk"
    description = "高风险 API 与异常复杂函数（优先审计入口）"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        suspicious_strings = [
            s for s in manifest.strings
            if any(w in s.lower() for w in ("size", "offset", "buffer", "property"))
        ]
        for fn in manifest.functions:
            risky = _hits(fn.calls, API_RISK_TOKENS)
            score = 0.0
            evidence: List[str] = []
            if risky:
                score += min(30.0, 8.0 * len(risky))
                evidence += [f"risky-api: {r}" for r in risky]
            if fn.complexity >= 18:
                score += 12.0
                evidence.append(f"high complexity: {fn.complexity}")
            local_suspicious = [
                s for s in suspicious_strings if s.lower() in _norm(fn.name)
            ]
            if local_suspicious:
                score += 6.0
                evidence += [f"string: {s}" for s in local_suspicious[:3]]
            if score < 12:
                continue
            findings.append(
                Finding(
                    **_base_kwargs(self.name, manifest, fn, "高风险 API / 复杂控制流"),
                    severity=Severity.from_score(score),
                    vuln_class="INTEGER_OVERFLOW" if fn.complexity >= 18 else "MEMORY_CORRUPTION",
                    assembly=_assembly(fn, risky),
                    symbol=fn.name,
                    description="该函数包含值得优先审计的 API 或复杂分支，属于静态优先级提示而非漏洞确认。",
                    evidence=evidence,
                    score=round(score, 1),
                    confidence=0.42,
                    cwe="CWE-119 Improper Restriction of Operations within the Bounds",
                    recommendation="先做符号化反编译，核对拷贝长度计算与整数溢出可能。",
                    tags=risky,
                )
            )
        return findings


@register
class SurfacePropsPlugin(_RulePlugin):
    name = "surface-props"
    description = "IOSurface 属性/外部方法入口专项审计提示"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        if "surface" not in manifest.target.lower():
            return []
        findings: List[Finding] = []
        for fn in manifest.functions:
            norm = _norm(fn.name)
            matched = [h for h in SURFACE_FN_HINTS if h in norm]
            if not matched:
                continue
            score = 30.0 + 6.0 * len(matched) + (8.0 if fn.complexity > 12 else 0.0)
            findings.append(
                Finding(
                    **_base_kwargs(self.name, manifest, fn, "IOSurface 外部入口需重点审计"),
                    severity=Severity.from_score(score),
                    vuln_class="PRIVILEGE_ESCALATION",
                    assembly=_assembly(fn, matched + list(fn.calls[:4])),
                    symbol=fn.name,
                    description=(
                        f"命中 IOSurface 属性/外部方法入口特征 {matched}。"
                        "历史上该类入口曾出现越界与使用后释放问题，建议优先做数据流追踪。"
                    ),
                    evidence=[f"entry-hint: {h}" for h in matched]
                    + [f"call: {c}" for c in fn.calls[:8]],
                    score=round(score, 1),
                    confidence=0.6,
                    cwe="CWE-20 Improper Input Validation",
                    recommendation="核对属性字典中 CFNumber/CFData 的类型与长度假设，以及 surface 对象的 retain/release 配对。",
                    tags=matched,
                )
            )
        return findings


@register
class VulnPrimitivesPlugin(_RulePlugin):
    name = "vuln-primitives"
    description = "按漏洞原语分类输出：OOB read/write、提权、沙盒逃逸、RCE（含汇编地址）"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        for fn in manifest.functions:
            calls = list(fn.calls)
            names = calls + [_norm(s) for s in fn.strings]

            # RCE / control-flow hijack surface: indirect call through register.
            indirect = [s for s in fn.call_sites if s.mnemonic.startswith("blr")]
            if not indirect:
                indirect = [s for s in fn.call_sites if "__indirect_call" in s.target]
            if indirect:
                findings.append(
                    self._make(
                        manifest, fn, "RCE", "间接调用（函数指针）",
                        "存在通过寄存器跳转的调用点，是控制流劫持面；需确认指针来源是否可被用户态影响。",
                        [s.render() for s in indirect[:6]],
                        68.0, 0.5, "函数指针表 / blr",
                    )
                )

            read_tokens = ("copyout", "readbytes", "getbaseaddress", "getvalue", "getproperty")
            reads = _hits(calls, read_tokens)
            size_hint = any(w in " ".join(fn.strings).lower() for w in ("size", "offset", "count", "length"))
            if reads and size_hint:
                findings.append(
                    self._make(
                        manifest, fn, "OOB_READ", "越界读原语候选",
                        f"读回用户态的路径 {reads} 与尺寸/偏移字符串共现，需核对长度是否被校验。",
                        _assembly(fn, reads),
                        56.0, 0.55, "读回/映射接口",
                    )
                )

            privesc_tokens = ("externalmethod", "taskforpid", "setproperty", "setvalue", "withaddressrange")
            privesc = _hits(calls, privesc_tokens)
            if privesc and ("surface" in manifest.target.lower() or "iokit" in manifest.target.lower()):
                findings.append(
                    self._make(
                        manifest, fn, "PRIVILEGE_ESCALATION", "内核能力暴露原语候选",
                        f"外部方法/属性写入入口 {privesc} 暴露内核能力，需核对调用者权限与参数校验。",
                        _assembly(fn, privesc),
                        60.0, 0.55, "IOKit 外部方法",
                    )
                )

            escape_tokens = ("machmsg", "machport", "taskforpid", "ioconnectmapmemory", "vmallocate", "hostport")
            escapes = _hits(names, escape_tokens)
            if len(escapes) >= 2:
                findings.append(
                    self._make(
                        manifest, fn, "SANDBOX_ESCAPE", "跨进程/沙盒边界原语候选",
                        f"命中跨边界能力 {escapes}，需核对 mach port 传递与 task 权限检查。",
                        _assembly(fn, escapes),
                        62.0, 0.5, "Mach/IPC 边界",
                    )
                )
        return findings

    def _make(
        self,
        manifest: AnalysisManifest,
        fn: Function,
        vuln_class: str,
        title: str,
        description: str,
        assembly: List[str],
        score: float,
        confidence: float,
        symbol: str,
    ) -> Finding:
        score += 8.0 if any(h in _norm(fn.name) for h in SURFACE_FN_HINTS) else 0.0
        return Finding(
            id=_id(self.name, manifest, fn, f"{vuln_class}:{title}"),
            title=f"[{vuln_class}] {title}",
            severity=Severity.from_score(score),
            layer=Layer.STATIC,
            target=manifest.target,
            description=description,
            location=f"{fn.name} @ {fn.address}" if fn.address else fn.name,
            evidence=assembly,
            score=round(score, 1),
            confidence=confidence,
            cwe={
                "OOB_READ": "CWE-125 Out-of-bounds Read",
                "PRIVILEGE_ESCALATION": "CWE-269 Improper Privilege Management",
                "SANDBOX_ESCAPE": "CWE-693 Protection Mechanism Failure",
                "RCE": "CWE-94 Improper Control of Code Generation",
            }.get(vuln_class, ""),
            vuln_class=vuln_class,
            assembly=assembly,
            symbol=symbol,
            recommendation="复核上述汇编地址处的参数来源、边界检查与权限判断；本报告不生成利用代码。",
            tags=[vuln_class],
        )


# --- Pointer-safety vocabulary ------------------------------------------------
# Deallocation / reference release.
FREE_TOKENS = (
    "kfree", "iofree", "osfree", "free", "vmdeallocate", "iodeletememoryentry",
    "release", "deleter", "destroy", "decrementusecount", "removeproperty",
)
# Allocation / creation (a fresh object can legitimize a later use).
ALLOC_TOKENS = (
    "kalloc", "iomalloc", "osmalloc", "malloc", "vmallocate", "alloc",
    "withaddressrange", "create", "copyin", "new", "initwithproperties",
)
# Operations that dereference / touch a buffer through a pointer.
PTR_USE_TOKENS = (
    "memcpy", "memmove", "bcopy", "writebytes", "readbytes", "copybytes",
    "getbaseaddress", "setvalue", "getvalue", "setobject", "getobject",
    "strcpy", "strncpy", "snprintf",
)
# Reference increments that balance a release.
RETAIN_TOKENS = ("retain", "incrementusecount", "get", "copy")


@register
class PointerSafetyPlugin(_RulePlugin):
    name = "pointer-safety"
    description = "野指针 / UAF / 重复释放：基于释放-使用调用序列（含汇编地址）"

    @staticmethod
    def _site_token(site: CallSite) -> str:
        return _norm(site.target) or _norm(site.mnemonic)

    @staticmethod
    def _first(site: CallSite, tokens: Sequence[str]) -> str:
        token = PointerSafetyPlugin._site_token(site)
        return next((t for t in tokens if t in token), "")

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        for fn in manifest.functions:
            # Ordered call stream from r2 (falls back to unordered fn.calls).
            sites = list(fn.call_sites)
            if not sites:
                names = list(fn.calls)
                frees = _hits(names, FREE_TOKENS)
                uses = _hits(names, PTR_USE_TOKENS)
                if frees and uses:
                    findings.append(
                        self._make(
                            manifest, fn,
                            "DANGLING_POINTER",
                            "释放与使用共现（无指令顺序，需人工确认）",
                            f"函数同时引用释放 {frees} 与指针访问 {uses}，但缺少指令级顺序；"
                            "按野指针/UAF 优先审计。",
                            _assembly(fn, list(frees) + list(uses)),
                            52.0, 0.45, "调用共现（无序）",
                        )
                    )
                continue

            events: List[tuple] = []  # (kind, token, site)
            for site in sites:
                kind = ""
                token = ""
                for k, toks in (
                    ("free", FREE_TOKENS), ("alloc", ALLOC_TOKENS),
                    ("use", PTR_USE_TOKENS), ("retain", RETAIN_TOKENS),
                ):
                    token = self._first(site, toks)
                    if token:
                        kind = k
                        break
                if kind:
                    events.append((kind, token, site))

            # 1) free followed by pointer use before a fresh allocation.
            live_freed: List[tuple] = []  # list of (token, site) awaiting use
            for kind, token, site in events:
                if kind == "free":
                    live_freed.append((token, site))
                elif kind == "alloc":
                    live_freed.clear()  # a fresh object legitimizes subsequent use
                elif kind == "use" and live_freed:
                    ftoken, fsite = live_freed[0]
                    evidence = [fsite.render(), site.render()]
                    findings.append(
                        self._make(
                            manifest, fn,
                            "DANGLING_POINTER",
                            f"释放后再次访问（野指针/UAF）：{ftoken} → {token}",
                            "在释放调用之后、重新分配之前出现指针访问，符合 use-after-free / "
                            "野指针模式；需人工确认是否为同一对象及其别名。",
                            evidence, 74.0, 0.62, f"{ftoken} → {token}",
                        )
                    )
                    live_freed.clear()

            # 2) two frees without an intervening allocation -> double free.
            frees = [e for e in events if e[0] == "free"]
            allocs = [e for e in events if e[0] == "alloc"]
            if len(frees) >= 2:
                # crude but effective for linear streams: >1 free and not enough allocs
                if len(frees) > len(allocs):
                    evidence = [e[2].render() for e in frees[:4]]
                    findings.append(
                        self._make(
                            manifest, fn,
                            "DOUBLE_FREE",
                            f"疑似重复释放：{len(frees)} 次 free / {len(allocs)} 次 alloc",
                            "释放次数多于分配次数，存在对同一指针重复释放的风险；"
                            "需人工确认各路径上的对象归属。",
                            evidence, 70.0, 0.58, "重复 free",
                        )
                    )

            # 3) pointer use with no allocation AND no external source that could
            #    legitimately own the buffer (copyin / mapping / external args).
            #    Otherwise getProperty(copyout+memcpy) would false-positive.
            has_external_buffer = bool(_hits(list(fn.calls), SOURCE_TOKENS))
            if (
                any(e[0] == "use" for e in events)
                and not any(e[0] == "alloc" for e in events)
                and not has_external_buffer
            ):
                first_use = next(e for e in events if e[0] == "use")
                findings.append(
                    self._make(
                        manifest, fn,
                        "NULL_DEREF",
                        f"指针访问前无分配/外部来源/校验：{first_use[1]}",
                        "函数内出现指针解引用类操作，但未见本地分配、外部缓冲来源或校验调用；"
                        "可能为未初始化/空指针，需人工确认。",
                        [first_use[2].render()], 46.0, 0.42, first_use[1],
                    )
                )
        return findings

    def _make(
        self, manifest: AnalysisManifest, fn: Function, vuln_class: str,
        title: str, description: str, assembly: List[str], score: float,
        confidence: float, symbol: str,
    ) -> Finding:
        if any(h in _norm(fn.name) for h in SURFACE_FN_HINTS):
            score += 6.0
        return Finding(
            id=_id(self.name, manifest, fn, f"{vuln_class}:{title}"),
            title=f"[{vuln_class}] {title}",
            severity=Severity.from_score(score),
            layer=Layer.STATIC,
            target=manifest.target,
            description=description,
            location=f"{fn.name} @ {fn.address}" if fn.address else fn.name,
            evidence=assembly,
            assembly=assembly,
            score=round(score, 1),
            confidence=confidence,
            cwe={
                "DANGLING_POINTER": "CWE-416 Use After Free",
                "DOUBLE_FREE": "CWE-415 Double Free",
                "NULL_DEREF": "CWE-476 NULL Pointer Dereference",
            }.get(vuln_class, ""),
            vuln_class=vuln_class,
            symbol=symbol,
            recommendation="复核该汇编地址处对象的生命周期与引用计数；本报告不生成利用代码。",
            tags=[vuln_class],
        )


# --- arm64e PAC (pointer authentication) --------------------------------------
# Indirect branches that carry authentication (verified at the branch).
PAC_AUTH_BRANCH = ("braa", "brab", "braaz", "brabz", "blraa", "blrab",
                   "blraaz", "blrabz", "bra", "blra")
# Instructions that strip or replace a signature (classic bypass primitive).
PAC_STRIP = ("xpaci", "xpacd")
# Signing vs. authentication families; the key/register family must match.
PAC_SIGN = ("pacia", "pacib", "paciza", "pacizb", "paciasp", "pacibsp",
            "paciaz", "pacibz", "pacia1716", "pacib1716")
PAC_AUTH = ("autia", "autib", "autiza", "autizb", "autiasp", "autibsp",
            "autiaz", "autibz", "autia1716", "autib1716")


def _pac_family(name: str) -> str:
    """Normalize a PAC mnemonic to its family token."""
    n = (name or "").lower().strip()
    for fam in PAC_STRIP + PAC_AUTH_BRANCH + PAC_SIGN + PAC_AUTH + ("bti", "btic"):
        if n == fam or n.startswith(fam + "."):
            return fam
    return ""


def _pac_key_family(fam: str) -> str:
    """Return 'A' / 'B' for keyed sign/auth ops, else ''."""
    if "1716" in fam:
        return "A" if "a1716" in fam else "B"
    if "ia" in fam and "pac" not in fam and "auti" not in fam:
        return ""
    if fam.startswith(("pacia", "autia", "paciza", "autiza", "paciasp", "autiasp")):
        return "A"
    if fam.startswith(("pacib", "autib", "pacizb", "autizb", "pacibsp", "autibsp")):
        return "B"
    if fam.startswith(("paciaz", "autiaz")):
        return "A"
    if fam.startswith(("pacibz", "autibz")):
        return "B"
    return ""


@register
class PacSecurityPlugin(_RulePlugin):
    name = "pac-security"
    description = "arm64e PAC 绕过面：签名剥离 / 未认证间接调用 / 签名验证失衡 / PAC 降级"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        arch = (manifest.arch or "").lower()
        if "arm64e" not in arch:
            return findings  # PAC rules only apply to arm64e slices

        all_pac: List[Tuple[Function, CallSite, str]] = []
        for fn in manifest.functions:
            for site in fn.pac_sites:
                fam = _pac_family(site.mnemonic)
                if fam:
                    all_pac.append((fn, site, fam))

        families = [fam for _, _, fam in all_pac]
        n_auth_branch = sum(1 for f in families if f in PAC_AUTH_BRANCH)
        n_strip = sum(1 for f in families if f in PAC_STRIP)
        n_sign = sum(1 for f in families if f in PAC_SIGN)
        n_verify = sum(1 for f in families if f in PAC_AUTH)

        # --- per-function findings -------------------------------------------
        for fn in manifest.functions:
            fn_pac = [(s, _pac_family(s.mnemonic)) for s in fn.pac_sites]
            fn_pac = [(s, f) for s, f in fn_pac if f]

            # 1) signature stripped before use -> bypass primitive.
            stripped = [(s, f) for s, f in fn_pac if f in PAC_STRIP]
            if stripped:
                evidence = [s.render() for s, _ in stripped[:6]]
                findings.append(
                    self._make(
                        manifest, fn, "PAC_BYPASS",
                        "指针认证签名被剥离（xpac）",
                        f"检测到 {len(stripped)} 条签名剥离指令（xpaci/xpacd）。"
                        "把认证指针转换为普通指针是绕过 PAC 的常见前置步骤；"
                        "需确认剥离后的指针是否用于间接调用或作为数据外传。",
                        evidence, 74.0, 0.68, "xpac → 普通指针",
                    )
                )

            # 2) register-indirect call with NO authenticated branch anywhere in
            #    the kext -> function pointer likely unsigned (classic bypass).
            indirect = [s for s in fn.call_sites if s.mnemonic.lower().startswith("blr")]
            fn_auth_branch = [s for s, f in fn_pac if f in PAC_AUTH_BRANCH]
            if indirect and not fn_auth_branch and n_auth_branch == 0:
                findings.append(
                    self._make(
                        manifest, fn, "PAC_BYPASS",
                        "未认证间接调用（函数指针未签名）",
                        f"函数含 {len(indirect)} 处 blr 间接调用，但整个 kext 未发现 "
                        "braa/blraa 等认证分支；若函数指针来自用户态或可写内存，"
                        "这是 arm64e 上典型的 PAC 绕过入口。",
                        [s.render() for s in indirect[:6]], 72.0, 0.6, "blr（无认证分支）",
                    )
                )

            # 3) signed with key A but verified with key B (or vice versa) in
            #    the same function -> authentication will always fail or be
            #    skipped, indicating a misuse of the PAC key space.
            keys_present = {
                _pac_key_family(f) for _, f in fn_pac
                if _pac_key_family(f) in ("A", "B")
            }
            if len(keys_present) == 2:
                ev = [s.render() for s, f in fn_pac if _pac_key_family(f)][:6]
                findings.append(
                    self._make(
                        manifest, fn, "PAC_SIGN_MISMATCH",
                        "同一函数内混用 A/B 两套 PAC 密钥",
                        "同一函数同时出现 A 密钥与 B 密钥的签名/验证指令；"
                        "跨密钥签名与验证无法相互认证，可能导致校验被绕过或逻辑错误，"
                        "需人工确认字段/指针的签名密钥约定。",
                        ev, 64.0, 0.55, "PAC key A/B 混用",
                    )
                )

        # --- manifest-level findings (whole kext) ----------------------------
        dummy = manifest.functions[0] if manifest.functions else Function(name=manifest.target)
        n_indirect = sum(
            1 for fn in manifest.functions
            for s in fn.call_sites if s.mnemonic.lower().startswith("blr")
        )
        if n_indirect > 0 and n_auth_branch == 0 and not all_pac:
            findings.append(
                self._make(
                    manifest, dummy, "PAC_DOWNGRADE",
                    "整个 kext 未启用 PAC（降级编译迹象）",
                    f"目标架构为 {manifest.arch}，共发现 {n_indirect} 处间接调用，"
                    "但未发现任何 PAC 签名、认证或认证分支指令，疑似未启用指针认证"
                    "（arm64e 降级编译或未使用 PAC）。此类二进制缺少指针完整性保护，"
                    "控制流劫持类漏洞的利用门槛显著降低。",
                    [f"{manifest.target}: 0 PAC instructions / {n_indirect} indirect calls"],
                    70.0, 0.62, "PAC 未启用",
                )
            )
        if n_sign > 0 and n_verify == 0:
            all_sign_sites = [s.render() for _, s, f in all_pac if f in PAC_SIGN][:6]
            findings.append(
                self._make(
                    manifest, dummy, "PAC_SIGN_MISMATCH",
                    "存在 PAC 签名但无对应验证指令",
                    f"全 kext 发现 {n_sign} 条签名指令、0 条认证指令；"
                    "签名后未验证意味着指针认证未形成闭环，需确认验证是否在调用方"
                    "或通过认证分支隐式完成。",
                    all_sign_sites or [f"{manifest.target}: {n_sign} sign / 0 auth"],
                    62.0, 0.55, "sign 无 auth",
                )
            )
        return findings

    def _make(
        self, manifest: AnalysisManifest, fn: Function, vuln_class: str,
        title: str, description: str, assembly: List[str], score: float,
        confidence: float, symbol: str,
    ) -> Finding:
        return Finding(
            id=_id(self.name, manifest, fn, f"{vuln_class}:{title}"),
            title=f"[{vuln_class}] {title}",
            severity=Severity.from_score(score),
            layer=Layer.STATIC,
            target=manifest.target,
            description=description,
            location=f"{fn.name} @ {fn.address}" if fn.address else fn.name,
            evidence=assembly,
            assembly=assembly,
            score=round(score, 1),
            confidence=confidence,
            cwe={
                "PAC_BYPASS": "CWE-693 Protection Mechanism Failure",
                "PAC_DOWNGRADE": "CWE-757 Selection of Less-Secure Algorithm",
                "PAC_SIGN_MISMATCH": "CWE-694 Use of Multiple Resources with Duplicate Identifier",
            }.get(vuln_class, ""),
            vuln_class=vuln_class,
            symbol=symbol,
            recommendation="核对指针的签名/验证密钥族与生命周期；本报告不生成利用代码。",
            tags=[vuln_class, "arm64e", "pac"],
        )


@register
class AdvancedThreatsPlugin(_RulePlugin):
    name = "advanced-threats"
    description = "扩展威胁面：格式化字符串 / 未初始化内存读 / TOCTOU / 栈缓冲 / 类型混淆 / 边界校验缺失"

    def _scan(self, manifest: AnalysisManifest) -> List[Finding]:
        findings: List[Finding] = []
        for fn in manifest.functions:
            names = list(fn.calls)
            norm_calls = [_norm(c) for c in names]
            norm_fn = _norm(fn.name)
            strings_lower = " ".join(fn.strings).lower()

            # 1) format string: user/source data + formatting sink + format
            #    specifiers in strings, with no explicit literal format guard.
            fmts = _hits(names, FORMAT_TOKENS)
            sources = _hits(names, SOURCE_TOKENS)
            has_specifier = any(
                token in strings_lower for token in ("%s", "%d", "%x", "%p", "%n", "%ld", "%lu")
            )
            if fmts and (sources or has_specifier):
                risky = [f for f in fmts if f in ("sprintf", "snprintf", "os_log", "kprintf", "printf", "syslog")]
                if risky:
                    ev = [s.render() for s in fn.call_sites
                          if any(f in _norm(s.target) for f in risky)][:6]
                    findings.append(self._make(
                        manifest, fn, "FORMAT_STRING",
                        f"用户可控格式串风险：{', '.join(risky)}",
                        "格式化函数与用户输入源/格式说明符共现；若格式串本身可被用户态控制，"
                        "可能导致信息泄露或内存写（%n）。需确认格式串是固定字面量还是外部传入。",
                        ev or [f"{fn.name}: fmt={risky}, sources={sources}"],
                        66.0, 0.55, "format-string",
                        "CWE-134 Use of Externally-Controlled Format String",
                    ))

            # 2) uninitialized memory read / copy-out: allocate + copy out with
            #    no memset/bzero in between -> heap contents may leak.
            allocs = _hits(names, ALLOC_TOKENS)
            outs = _hits(names, UNINIT_READ_TOKENS)
            zeroed = _hits(names, ZERO_TOKENS)
            if allocs and outs and not zeroed:
                findings.append(self._make(
                    manifest, fn, "UNINITIALIZED",
                    f"分配后未初始化即拷贝/外传：{', '.join(allocs)} → {', '.join(outs)}",
                    "函数分配内存后直接拷贝或回传用户态，未见清零/初始化调用；"
                    "可能泄露内核堆残留内容。需确认每个字节在写出前均已初始化。",
                    _assembly(fn, list(allocs) + list(outs)),
                    58.0, 0.5, "uninit-read",
                    "CWE-908 Use of Uninitialized Resource",
                ))

            # 3) TOCTOU / double-fetch: two or more user-buffer fetches and a
            #    check-like string present -> classic check/use race.
            fetches = [s for s in fn.call_sites
                       if any(f in _norm(s.target) for f in FETCH_TOKENS)]
            if len(fetches) >= 2:
                findings.append(self._make(
                    manifest, fn, "TOCTOU",
                    f"同一函数多次取数（double-fetch）：{len(fetches)} 次 copyin",
                    "函数内出现多次从用户态拷贝同一缓冲区，若校验与使用之间重复读取，"
                    "攻击者可在两次读取间修改内容（TOCTOU）。需确认是否只读取一次并本地缓存。",
                    [s.render() for s in fetches[:6]],
                    64.0, 0.58, "double-fetch",
                    "CWE-367 Time-of-check Time-of-use Race Condition",
                ))

            # 4) type confusion: object cast API with no member/type check.
            casts = _hits(names, CAST_TOKENS)
            checks = _hits(names, ("ismemberof", "getmetaclass", "checktype", "kindof", "iskindof"))
            if casts and not checks:
                findings.append(self._make(
                    manifest, fn, "TYPE_CONFUSION",
                    f"对象强制转换缺少类型校验：{', '.join(casts)}",
                    "函数进行对象类型转换，但未见动态类型/成员校验；"
                    "若对象来自用户可控的属性字典，可能触发类型混淆。",
                    _assembly(fn, list(casts)),
                    60.0, 0.5, "type-confusion",
                    "CWE-843 Access of Resource Using Incompatible Type",
                ))

            # 5) stack buffer risk: strcpy/sprintf with size-like strings and
            #    no stack protector hint (high complexity amplifies).
            # Only genuinely unbounded / stack-local ops qualify; memcpy has an
            # explicit length and belongs to the OOB class, not stack overflow.
            stack_sinks = _hits(names, ("strcpy", "sprintf", "alloca", "strcat", "vsprintf"))
            size_words = any(w in strings_lower for w in ("size", "len", "length", "width", "height"))
            if stack_sinks and size_words and fn.complexity >= 6:
                findings.append(self._make(
                    manifest, fn, "STACK_OVERFLOW",
                    f"栈上边界拷贝风险：{', '.join(stack_sinks)}",
                    "无界/受限字符串或栈分配函数与尺寸字段共现，且控制流较复杂；"
                    "需确认目标缓冲为堆分配或存在上界校验，避免栈溢出。",
                    _assembly(fn, list(stack_sinks)),
                    56.0, 0.46, "stack-buffer",
                    "CWE-121 Stack-based Buffer Overflow",
                ))
        return findings

    def _make(
        self, manifest: AnalysisManifest, fn: Function, vuln_class: str,
        title: str, description: str, assembly: List[str], score: float,
        confidence: float, symbol: str, cwe: str,
    ) -> Finding:
        if any(h in _norm(fn.name) for h in SURFACE_FN_HINTS):
            score += 6.0
        return Finding(
            id=_id(self.name, manifest, fn, f"{vuln_class}:{title}"),
            title=f"[{vuln_class}] {title}",
            severity=Severity.from_score(score),
            layer=Layer.STATIC,
            target=manifest.target,
            description=description,
            location=f"{fn.name} @ {fn.address}" if fn.address else fn.name,
            evidence=assembly,
            assembly=assembly,
            score=round(score, 1),
            confidence=confidence,
            cwe=cwe,
            vuln_class=vuln_class,
            symbol=symbol,
            recommendation="复核参数来源、边界与生命周期；本报告仅标注审计位置，不生成利用代码。",
            tags=[vuln_class],
        )
