"""radare2 backend: turn a Mach-O kext into an AnalysisManifest.

Uses r2pipe when available, otherwise shells out to `r2 -q -c ...`. The number
of functions inspected for call targets is bounded so a full kernelcache stays
usable on a laptop.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .models import AnalysisManifest, CallSite, Function
from .ipswwrap import check_dependencies

MAX_FUNCTIONS = int(os.environ.get("IOSVULN_MAX_FUNCTIONS", "400"))
INTERESTING_STRINGS = (
    "size", "property", "surface", "buffer", "alloc", "offset", "byte",
    "width", "height", "pixel", "key", "mach", "client", "heap",
)

# arm64e pointer-authentication instruction families. These are collected into
# Function.pac_sites (separate from ordinary calls) so PAC-specific rules can
# reason about signing/authentication balance and bypass surfaces.
PAC_FAMILIES = {
    # authenticated indirect branches / returns
    "braa", "brab", "braaz", "brabz", "blraa", "blrab", "blraaz", "blrabz",
    "retaa", "retab", "bra", "blra",
    # signing
    "pacia", "pacib", "paciza", "pacizb", "paciasp", "pacibsp", "paciaz",
    "pacibz", "pacia1716", "pacib1716",
    # authentication
    "autia", "autib", "autiza", "autizb", "autiasp", "autibsp", "autiaz",
    "autibz", "autia1716", "autib1716",
    # stripping / downgrade
    "xpaci", "xpacd", "bti", "btic", "btjz",
}


def _pac_family(mnemonic: str) -> str:
    """Return the matched PAC instruction family, or '' if not a PAC op."""
    m = (mnemonic or "").lower().lstrip()
    # r2 sometimes appends width/suffix like 'braa x8' already split into mnemonic
    for family in PAC_FAMILIES:
        if m == family or m.startswith(family + ".") or m.startswith(family + " "):
            return family
    return ""


def _jq(data: Any, *keys: str) -> Any:
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


class R2Backend:
    def __init__(self, cfg: Config, dependency: Optional[Dict[str, Any]] = None):
        self.cfg = cfg
        self.dep = dependency if dependency is not None else check_dependencies(cfg)
        self._r2pipe_mod = None
        if self.dep.get("r2pipe"):
            try:
                import r2pipe

                self._r2pipe_mod = r2pipe
            except ImportError:
                pass
        self.binary = self.dep.get("r2")

    @property
    def available(self) -> bool:
        return bool(self.binary or self._r2pipe_mod)

    def build_manifest(self, target: str, macho_path: str) -> Optional[AnalysisManifest]:
        if not self.available or not macho_path or not os.path.exists(macho_path):
            return None
        if self._r2pipe_mod:
            return self._with_r2pipe(target, macho_path)
        return self._with_subprocess(target, macho_path)

    # ------------------------------------------------------------------ r2pipe
    def _with_r2pipe(self, target: str, path: str) -> Optional[AnalysisManifest]:
        try:
            r2 = self._r2pipe_mod.open(path)
            r2.cmd("aa")
            funcs_raw = _as_list(r2.cmdj("aflj"))
            imports = self._imports_from_pipe(r2)
            strings = self._strings_from_pipe(r2)
            functions = []
            for item in funcs_raw[:MAX_FUNCTIONS]:
                functions.append(
                    self._function_from_raw(r2, item, include_calls=True)
                )
            r2.close()
            return AnalysisManifest(
                target=target,
                source_file=path,
                arch="arm64e",
                functions=functions,
                imports=imports,
                strings=strings,
                metadata={"backend": "r2pipe", "analyzed_functions": len(funcs_raw)},
            )
        except Exception:  # r2 crashes on some compressed/objc-heavy caches
            return None

    def _function_from_raw(self, r2: Any, item: Dict[str, Any], include_calls: bool) -> Function:
        name = str(item.get("name") or item.get("label") or "")
        addr = str(item.get("offset", ""))
        fn = Function(
            name=name,
            address=addr,
            size=int(item.get("size", 0) or 0),
        )
        if not include_calls or not addr:
            return fn
        try:
            pdf = r2.cmdj(f"pdfj @ {addr}") or {}
            calls, complexity, sites, pac_sites = _calls_from_pdf(pdf)
            fn.calls = calls
            fn.complexity = complexity
            fn.call_sites = sites
            fn.pac_sites = pac_sites
        except Exception:
            pass
        return fn

    def _imports_from_pipe(self, r2: Any) -> List[str]:
        try:
            return [
                str(x.get("name", ""))
                for x in _as_list(r2.cmdj("iij"))
                if x.get("name")
            ]
        except Exception:
            return []

    def _strings_from_pipe(self, r2: Any) -> List[str]:
        try:
            all_strings = _as_list(r2.cmdj("izzj"))
        except Exception:
            return []
        return [
            str(s.get("string", ""))
            for s in all_strings
            if any(word in str(s.get("string", "")).lower() for word in INTERESTING_STRINGS)
        ][:300]

    # --------------------------------------------------------------- subprocess
    def _with_subprocess(self, target: str, path: str) -> Optional[AnalysisManifest]:
        try:
            funcs_raw = self._cmd_json(path, "aflj")
            imports_raw = self._cmd_json(path, "iij")
            strings_raw = self._cmd_json(path, "izzj")
        except Exception:
            return None
        imports = [str(x.get("name", "")) for x in imports_raw if x.get("name")]
        strings = [
            str(s.get("string", ""))
            for s in strings_raw
            if any(w in str(s.get("string", "")).lower() for w in INTERESTING_STRINGS)
        ][:300]
        functions: List[Function] = []
        for item in funcs_raw[:MAX_FUNCTIONS]:
            fn = Function(
                name=str(item.get("name") or item.get("label") or ""),
                address=str(item.get("offset", "")),
                size=int(item.get("size", 0) or 0),
            )
            addr = fn.address
            if addr:
                pdf = self._cmd_json(path, f"pdfj @ {addr}")
                calls, complexity, sites, pac_sites = _calls_from_pdf(pdf)
                fn.calls = calls
                fn.complexity = complexity
                fn.call_sites = sites
                fn.pac_sites = pac_sites
            functions.append(fn)
        return AnalysisManifest(
            target=target,
            source_file=path,
            arch="arm64e",
            functions=functions,
            imports=imports,
            strings=strings,
            metadata={"backend": "r2-subprocess", "analyzed_functions": len(funcs_raw)},
        )

    def _cmd_json(self, path: str, command: str) -> List[Dict[str, Any]]:
        proc = subprocess.run(
            [self.binary, "-q", "-c", command, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=300,
            check=False,
        )
        try:
            data = json.loads(proc.stdout)
        except (ValueError, TypeError):
            return []
        return data if isinstance(data, list) else []


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    return []


def _calls_from_pdf(pdf: Any) -> Tuple[List[str], int, List[CallSite], List[CallSite]]:
    """Return (call targets, cyclomatic-ish complexity, call sites, PAC sites)."""
    ops = _as_list(pdf.get("ops")) if isinstance(pdf, dict) else []
    calls: List[str] = []
    sites: List[CallSite] = []
    pac_sites: List[CallSite] = []
    complexity = 1
    for op in ops:
        mnemonic = str(op.get("mnemonic", ""))
        offset = str(op.get("offset", ""))
        family = _pac_family(mnemonic)

        # Authenticated indirect branches (braa/blraa/...) are call-like: record
        # both as a PAC site and as an indirect call so RCE rules can see them.
        is_auth_branch = family in (
            "braa", "brab", "braaz", "brabz", "blraa", "blrab",
            "blraaz", "blrabz", "bra", "blra",
        )
        is_call = (
            op.get("type") in ("call", "cjmp")
            or mnemonic.startswith(("bl", "blr"))
            or is_auth_branch
        )
        is_indirect = mnemonic.startswith("blr") or is_auth_branch

        if family:
            pac_sites.append(
                CallSite(
                    address=offset,
                    mnemonic=mnemonic or family,
                    target=str(
                        _jq(op, "fwdto") or _jq(op, "inturn")
                        or op.get("comment") or ""
                    ),
                )
            )

        if is_call:
            called = (
                _jq(op, "fwdto")
                or _jq(op, "inturn")
                or _jq(op, "jump")
                or op.get("comment")
                or ("__indirect_call" if is_indirect else "")
            )
            if called:
                target = str(called)
                calls.append(target)
                sites.append(
                    CallSite(
                        address=offset,
                        mnemonic=mnemonic or ("braa" if is_auth_branch else "bl"),
                        target=target,
                    )
                )
        if op.get("type") == "cjmp" or mnemonic.startswith(("cb", "tb")):
            complexity += 1
    return list(dict.fromkeys(calls)), complexity, sites, pac_sites
