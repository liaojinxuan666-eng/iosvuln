"""Pure-Python symbolication for iosvuln.

Why pure Python: the tool ships as an iOS .deb and runs on the device, where
``c++filt`` / ``swift-demangle`` / ``llvm-cxxfilt`` are not available.  This
module therefore implements a best-effort Itanium C++ ABI demangler and a
heuristic Swift demangler, plus address -> nearest-symbol resolution from the
manifest's own function table.  No subprocess, no third-party package.

Design goals, in order:
  1. **Never throw** on a malformed symbol -- return the input unchanged.
  2. Feed readable names back into ``Function.name`` so the existing
     call-sequence rules (which match on readable tokens) actually fire on
     real firmware instead of only on the hand-written demo fixture.
  3. Be idempotent -- symbolicating an already-symbolicated manifest is a
     no-op, so the pipeline can call it unconditionally.

The C++ demangler is a recursive-descent parser for the common subset of the
Itanium ABI seen in XNU/IOKit (nested names, templates, cv-qualifiers, ctors /
dtors, operators, substitutions, local names, special names).  It is not a
complete ABI implementation; unsupported constructs degrade to a readable
approximation rather than an exception.

The Swift demangler is explicitly **heuristic**: Swift's mangling grammar is
large and versioned.  It decodes length-prefixed identifiers, the common
``S*`` builtin substitutions and simple function-type suffixes.  Treat its
output as a navigation aid, not a canonical signature.
"""

from __future__ import annotations

import bisect
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import AnalysisManifest, CallSite, Function

# How far past a function entry an address may be before we stop attributing
# it to that function.  Kernel functions are rarely >8 KiB; keeps false
# attributions low on stripped caches with sparse function starts.
DEFAULT_WINDOW = int(os.environ.get("IOSVULN_SYMBOL_WINDOW", "8192"), 0) or 8192

SYMBOLICATION_VERSION = 1

# ---------------------------------------------------------------- C++ ABI ---

# Itanium builtin type codes -> readable C/C++ spelling.
_BUILTIN: Dict[str, str] = {
    "v": "void", "w": "wchar_t", "b": "bool", "c": "char",
    "a": "signed char", "h": "unsigned char", "s": "short",
    "t": "unsigned short", "i": "int", "j": "unsigned int",
    "l": "long", "m": "unsigned long", "x": "long long",
    "y": "unsigned long long", "n": "__int128", "o": "unsigned __int128",
    "f": "float", "d": "double", "e": "long double", "g": "__float128",
    "z": "...",
}

# Two-character builtin types starting with 'D' / 'u'.
_BUILTIN2: Dict[str, str] = {
    "Dn": "std::nullptr_t", "Da": "auto", "Dc": "decltype(auto)",
    "Di": "char32_t", "Ds": "char16_t", "Du": "char8_t",
    "Dd": "decimal64", "De": "decimal128", "Df": "decimal32",
    "Db": "decimal64", "Dh": "decimal128", "DF": "fixed point",
    "u5": "__fp16", "u6": "__bf16",
}

# Operator names (source-name form, without the leading 'n' for unary forms
# where the ABI itself uses distinct codes).
_OPERATORS: Dict[str, str] = {
    "nw": "operator new", "nwa": "operator new[]",
    "dl": "operator delete", "dla": "operator delete[]",
    "aw": "operator co_await",
    "ps": "operator+", "ng": "operator-", "ad": "operator&",
    "de": "operator*", "co": "operator~", "nt": "operator!",
    "aS": "operator=", "pl": "operator+", "mi": "operator-",
    "ml": "operator*", "dv": "operator/", "rm": "operator%",
    "an": "operator&", "or": "operator|", "eo": "operator^",
    "pL": "operator+=", "mI": "operator-=", "mL": "operator*=",
    "dV": "operator/=", "rM": "operator%=", "aN": "operator&=",
    "oR": "operator|=", "eO": "operator^=", "ls": "operator<<",
    "rs": "operator>>", "lS": "operator<<=", "rS": "operator>>=",
    "eq": "operator==", "ne": "operator!=", "lt": "operator<",
    "gt": "operator>", "le": "operator<=", "ge": "operator>=",
    "ss": "operator<=>", "aa": "operator&&", "oo": "operator||",
    "pp": "operator++", "mm": "operator--", "cm": "operator,",
    "pm": "operator->*", "pt": "operator->", "cl": "operator()",
    "ix": "operator[]", "qu": "operator?:", "st": "operator sizeof",
    "sz": "operator sizeof", "at": "operator alignof",
    "az": "operator alignof", "cv": "operator cast",
    "li": "operator literal", "v": "operator",
}

# Standard-library substitutions that are predefined in the ABI.
_STD_SUBS: Dict[str, str] = {
    "St": "std", "Sa": "std::allocator", "Sb": "std::basic_string",
    "Ss": "std::string", "Si": "std::istream", "So": "std::ostream",
    "Sd": "std::iostream",
}

_SPECIAL_NAMES: Dict[str, str] = {
    "TV": "vtable for ", "TT": "VTT for ", "TI": "typeinfo for ",
    "TS": "typeinfo name for ", "TC": "construction vtable for ",
    "GV": "guard variable for ", "GR": "reference temporary for ",
    "Th": "non-virtual thunk to ", "Tv": "virtual thunk to ",
    "Tc": "covariant return thunk to ", "Tf": "function clone for ",
}

_CV_QUALS = {"r": "restrict", "V": "volatile", "K": "const"}


class _CppParser:
    """Recursive-descent parser for a practical subset of the Itanium ABI."""

    def __init__(self, mangled: str):
        self.s = mangled
        self.i = 0
        self.subs: List[str] = []
        self.failed = False

    # -- primitives ---------------------------------------------------------
    def eof(self) -> bool:
        return self.i >= len(self.s)

    def peek(self, offset: int = 0) -> str:
        pos = self.i + offset
        return self.s[pos] if pos < len(self.s) else ""

    def take(self) -> str:
        ch = self.peek()
        self.i += 1
        return ch

    def digits(self) -> str:
        start = self.i
        while self.peek().isdigit():
            self.i += 1
        return self.s[start:self.i]

    def fail(self) -> None:
        self.failed = True

    # -- grammar ------------------------------------------------------------
    def parse(self) -> str:
        # Accept the Mach-O extra underscore(s): __ZN... / _ZN...
        while self.peek() == "_":
            self.take()
        if self.take() != "Z":
            self.fail()
            return self.s
        return self.encoding()

    def encoding(self) -> str:
        # Special names (vtable/typeinfo/thunk/...) prefix the real name.
        special = ""
        if self.peek() == "T" and self.peek(1) in _SPECIAL_NAMES:
            code = self.s[self.i:self.i + 2]
            if code in _SPECIAL_NAMES:
                special = _SPECIAL_NAMES[code]
                self.i += 2
            # 'TC' carries an offset+class before the name; skip gracefully.
            if code == "TC":
                self.digits()
                while self.peek() in "hH":
                    self.take()
                    self.digits()
        elif self.peek() in ("L", "Z") and self.peek(1) == "Z" or self.peek() == "Z":
            # Internal-linkage marker (L) or local-name (Z) -- unwrap.
            while self.peek() == "L":
                self.take()

        name = self.name()
        if self.failed or not name:
            return special + (name or self.s)

        params = self.bare_function_types()
        if params is None:
            return special + name
        # A lone "void" means an empty parameter list.
        if params == ["void"]:
            params = []
        # 'const'/'volatile' qualifiers on a member function are appended by
        # parse_nested_name() to the name itself (e.g. "Foo::bar() const");
        # move them after the parameter list where readers expect them.
        quals = ""
        for q in (" const", " volatile", " restrict"):
            if name.endswith(q):
                name = name[:-len(q)]
                quals += q
        return f"{special}{name}({', '.join(params)}){quals}"

    def name(self) -> str:
        c = self.peek()
        if c == "N":
            return self.nested_name()
        if c == "Z":
            return self.local_name()
        if c == "S":
            return self.substitution()
        if c == "L":
            self.take()
            return self.name()
        return self.unqualified_name()

    def nested_name(self) -> str:
        self.take()  # 'N'
        cv = ""
        while self.peek() in _CV_QUALS:
            cv += " " + _CV_QUALS[self.take()]
        # NOTE: do NOT consume a leading digit sequence here.  In the Itanium
        # ABI a nested-name starts directly with a <prefix>/<unqualified-name>;
        # a leading decimal is the length prefix of the first source-name
        # (e.g. "3Foo").  Consuming it corrupts every subsequent component.
        # Ref-qualifiers (R/O) and vendor qualifiers are separate productions
        # and are rare in XNU symbols, so we leave them unhandled rather than
        # risk eating a source-name length.
        parts: List[str] = []
        while not self.eof() and self.peek() != "E":
            before = self.i
            if self.peek() == "S":
                sub = self.substitution()
                if sub:
                    parts.append(sub)
            elif self.peek() == "I":
                args = self.template_args()
                if parts:
                    parts[-1] += args
            elif self.peek() == "T":
                parts.append(self.template_param())
            else:
                parts.append(self.unqualified_name())
            # Record every completed prefix as a substitution candidate.
            if self.i != before and parts:
                joined = "::".join(parts)
                if joined not in self.subs:
                    self.subs.append(joined)
            if self.i == before:
                self.fail()
                break
        if self.peek() == "E":
            self.take()
        joined = "::".join(p for p in parts if p)
        return joined + cv

    def local_name(self) -> str:
        self.take()  # 'Z'
        outer = self.name()
        if self.peek() == "E":
            self.take()
        inner = ""
        if not self.eof():
            if self.peek() == "s":
                self.take()  # 's' string entity marker
                inner = self.source_name()
            else:
                inner = self.unqualified_name()
        return f"{outer}::{inner}" if inner else outer

    def unqualified_name(self) -> str:
        c = self.peek()
        if c.isdigit():
            return self.source_name()
        if c == "C":
            self.take()
            self.take()  # C1 / C2 / C3 / C4 / C5
            return "<constructor>"
        if c == "D" and self.peek(1) in "012345":
            self.take()
            self.take()
            return "<destructor>"
        if c == "U":
            # unnamed type name: Ut <number> _ ; also lambda 'Ul ... E'
            if self.peek(1) in "lt":
                self.take()
                kind = self.take()
                if kind == "t":
                    self.digits()
                    if self.peek() == "_":
                        self.take()
                    return "{unnamed type}"
                # lambda: gather until E
                depth = 0
                while not self.eof():
                    ch = self.take()
                    if ch == "E":
                        depth -= 1
                        if depth <= 0:
                            break
                    elif ch in ("I", "U"):
                        depth += 1
                return "{lambda}"
        # Operator names: try 3, then 2 characters.
        for width in (3, 2):
            op = self.s[self.i:self.i + width]
            if op in _OPERATORS:
                self.i += width
                if op == "cv":
                    return f"operator {self.type()}"
                if op == "li":
                    self.source_name()
                return _OPERATORS[op]
        self.take()
        return c

    def source_name(self) -> str:
        length = self.digits()
        if not length:
            self.fail()
            return ""
        try:
            n = int(length)
        except ValueError:
            self.fail()
            return ""
        # Anonymous namespaces use a zero-length source name with a discriminator.
        end = self.i + n
        name = self.s[self.i:end]
        self.i = end
        # Encode constructor/destructor placeholders based on the enclosing
        # class name -- done in nested_name() post-processing below.
        return name or "{anonymous}"

    def template_param(self) -> str:
        self.take()  # 'T'
        if self.peek() == "_":
            self.take()
            return "T0"
        if self.peek().isdigit():
            idx = int(self.digits())
            if self.peek() == "_":
                self.take()
            return f"T{idx + 1}"
        return "T?"

    def template_args(self) -> str:
        self.take()  # 'I'
        args: List[str] = []
        while not self.eof() and self.peek() != "E":
            before = self.i
            if self.peek() == "X":
                self.take()
                self.expression()
                if self.peek() == "E":
                    self.take()
                args.append("{expr}")
            elif self.peek() == "J":
                self.take()
                pack: List[str] = []
                while not self.eof() and self.peek() != "E":
                    pack.append(self.type())
                if self.peek() == "E":
                    self.take()
                args.append(", ".join(pack))
            else:
                args.append(self.type())
            if self.i == before:
                self.fail()
                break
        if self.peek() == "E":
            self.take()
        return "<" + ", ".join(args) + ">"

    def substitution(self) -> str:
        self.take()  # 'S'
        c = self.peek()
        if c == "_":
            self.take()
            return self.subs[0] if self.subs else "S_"
        if c.isdigit() or c in "abcdefghijklmnopqrstuvwxyz":
            # Base-36 sequence id terminated by '_'.
            token = ""
            while not self.eof() and self.peek() != "_":
                token += self.take()
            if self.peek() == "_":
                self.take()
            try:
                # ABI seq-id: 0 -> subs[1], 1 -> subs[2], ..., A -> subs[11]
                value = int(token, 36)
                idx = value + 1
                if 0 <= idx < len(self.subs):
                    return self.subs[idx]
            except ValueError:
                pass
            return f"S{token}_"
        # Predefined std:: substitution (St / Sa / Ss / ...).
        code = "S" + c
        if code in _STD_SUBS:
            self.take()
            return _STD_SUBS[code]
        self.fail()
        return "S?"

    def type(self) -> str:
        cv: List[str] = []
        while self.peek() in _CV_QUALS:
            cv.append(_CV_QUALS[self.take()])
        if self.eof():
            self.fail()
            return "?"
        c = self.peek()
        # Two-character builtin codes first.
        two = self.s[self.i:self.i + 2]
        if two in _BUILTIN2:
            self.i += 2
            result = _BUILTIN2[two]
        elif c in _BUILTIN:
            self.take()
            result = _BUILTIN[c]
        elif c == "D" and two not in _BUILTIN2:
            self.take()
            if self.peek() == "p":
                self.take()
                result = "..."
            elif self.peek() == "t":
                self.take()
                self.type()
                while not self.eof() and self.peek() != "E":
                    self.type()
                if self.peek() == "E":
                    self.take()
                result = "decltype(...)"
            else:
                result = "D?"
        elif c == "P":
            self.take()
            result = self.type() + "*"
        elif c == "R":
            self.take()
            result = self.type() + "&"
        elif c == "O":
            self.take()
            result = self.type() + "&&"
        elif c == "C" and self.peek(1) in "12345":
            # complex<T>
            self.take()
            self.take()
            result = "complex<" + self.type() + ">"
        elif c == "G":
            self.take()
            result = "imaginary<" + self.type() + ">"
        elif c == "U" and self.peek(1) in "123456789":
            self.take()
            vendor = self.source_name()
            result = f"{vendor} " + self.type()
        elif c == "A":
            self.take()
            dims = self.digits()
            if self.peek() == "_":
                self.take()
            result = self.type()
            result = f"{result}[{dims}]" if dims else f"{result}[]"
        elif c == "M":
            self.take()
            cls = self.type()
            result = f"{cls}::*" + self.type()
        elif c == "F":
            self.take()
            ret = self.type()
            params: List[str] = []
            while not self.eof() and self.peek() != "E":
                params.append(self.type())
            if self.peek() == "E":
                self.take()
            result = f"{ret} ({', '.join(params)})"
        elif c == "T":
            result = self.template_param()
        elif c == "S":
            result = self.substitution()
        elif c == "N":
            result = self.nested_name()
        elif c == "Z":
            result = self.local_name()
        elif c.isdigit():
            result = self.source_name()
        elif c == "u":
            self.take()
            result = self.type()
        else:
            self.take()
            result = c
        # Keep CV qualifiers in canonical-ish order (const volatile restrict).
        if cv:
            result = " ".join(cv) + " " + result
        # Non-builtin, non-substitution types become substitution candidates.
        if c not in _BUILTIN and c not in ("S", "T") and two not in _BUILTIN2:
            if result and result not in self.subs:
                self.subs.append(result)
        return result

    def expression(self) -> str:
        c = self.peek()
        if c.isdigit():
            return self.source_name()
        if c == "L":
            self.take()
            t = self.type()
            while not self.eof() and self.peek() != "E":
                self.take()
            if self.peek() == "E":
                self.take()
            return f"({t})...literal"
        if c == "T":
            return self.template_param()
        return self.type()

    def bare_function_types(self) -> Optional[List[str]]:
        params: List[str] = []
        while not self.eof():
            before = self.i
            params.append(self.type())
            if self.i == before:
                self.fail()
                break
        if self.failed:
            return None
        return params


def _demangle_cpp(name: str) -> Tuple[str, bool]:
    """Return (readable, changed).  Never raises."""
    stripped = name
    for prefix in ("sym.imp.", "imp.", "sym.", "reloc."):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    if not re.match(r"^_+Z", stripped):
        return name, False
    try:
        parser = _CppParser(stripped)
        out = parser.parse()
        if parser.failed or not out or out == stripped:
            return name, False
        # Sanity: a correct parse must consume the entire mangled string.  If
        # bytes are left over the length prefixes were wrong/corrupt and the
        # output would be a mangled-looking chain of single letters -- worse
        # than returning the original.  Bail out in that case.
        if parser.i != len(stripped):
            return name, False
        # Resolve ctor/dtor placeholders using the enclosing class name.
        m = re.search(r"([A-Za-z_][\w:<>, ]*)::<(constructor|destructor)>", out)
        if m:
            cls = m.group(1).split("::")[-1].strip()
            replacement = cls if m.group(2) == "constructor" else "~" + cls
            out = out[:m.start()] + cls + "::" + replacement + out[m.end():]
        out = re.sub(r"\s+", " ", out).strip()
        return out, True
    except Exception:  # noqa: BLE001 - demangler must be total
        return name, False


# --------------------------------------------------------------- Swift -----

# Common Swift builtin / stdlib substitutions.  These are stable across Swift
# 4/5 mangling for the mostly-used types.
_SWIFT_SUBS: Dict[str, str] = {
    "Si": "Swift.Int", "Ss": "Swift.String", "Sb": "Swift.Bool",
    "Sd": "Swift.Double", "Sf": "Swift.Float", "Su": "Swift.UInt",
    "Sg": "Swift.Optional", "Sq": "Swift.Optional", "SS": "Swift.String",
    "Sa": "Swift.Array", "SD": "Swift.Dictionary", "Sd": "Swift.Double",
    "Sh": "Swift.Set", "Sc": "Swift.Character", "St": "Swift.Substring",
    "Sz": "Swift.Never", "S5UUID": "Foundation.UUID",
}

_SWIFT_CTX_KINDS = {
    "C": "class", "V": "struct", "O": "enum", "P": "protocol",
    "E": "extension", "F": "func", "f": "func", "A": "typealias",
    "G": "generic", "I": "init", "y": "", "Y": "",
}


def _swift_length_name(s: str, i: int) -> Tuple[str, int]:
    start = i
    while i < len(s) and s[i].isdigit():
        i += 1
    if i == start:
        return "", start
    try:
        n = int(s[start:i])
        end = i + n
        if end <= len(s):
            return s[i:end], end
    except ValueError:
        pass
    return "", start


def _demangle_swift(name: str) -> Tuple[str, bool]:
    """Heuristic Swift demangler.  Returns (readable, changed)."""
    stripped = name
    for prefix in ("sym.imp.", "imp.", "sym."):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    stripped = stripped.lstrip("_")
    if not stripped.startswith("$s") and not stripped.startswith("$S"):
        return name, False
    body = stripped[2:]
    if not body:
        return name, False
    try:
        parts: List[str] = []
        i = 0
        segment_kind = ""
        while i < len(body):
            c = body[i]
            if c.isdigit():
                ident, ni = _swift_length_name(body, i)
                if ident:
                    parts.append(ident)
                    i = ni
                    continue
                i += 1
            elif c == "S":
                two = body[i:i + 2]
                if two in _SWIFT_SUBS:
                    parts.append(_SWIFT_SUBS[two])
                    i += 2
                elif i + 2 < len(body) and body[i + 1].isdigit():
                    ident, ni = _swift_length_name(body, i + 1)
                    if ident:
                        parts.append("Swift." + ident)
                        i = ni
                    else:
                        i += 1
                elif c in _SWIFT_CTX_KINDS:
                    segment_kind = _SWIFT_CTX_KINDS[c]
                    i += 1
                else:
                    i += 1
            elif c in _SWIFT_CTX_KINDS:
                segment_kind = _SWIFT_CTX_KINDS[c]
                i += 1
            elif c in "yY":
                # empty tuple / function arrow separators
                i += 1
            elif c in "Rr":
                i += 1  # throws / rethrows markers
            elif c in "Qq":
                i += 1  # archetype / ownership markers
            else:
                i += 1
        if not parts:
            return name, False
        # De-duplicate consecutive identical components (common in $s forms).
        dedup: List[str] = []
        for p in parts:
            if not dedup or dedup[-1] != p:
                dedup.append(p)
        result = ".".join(dedup)
        if segment_kind and segment_kind not in result:
            result = f"{result} /* {segment_kind} */"
        return result, True
    except Exception:  # noqa: BLE001
        return name, False


# ------------------------------------------------------------ public API ----

def demangle(name: str) -> Tuple[str, str]:
    """Demangle one symbol.

    Returns ``(readable_name, kind)`` where kind is one of ``cpp``, ``swift``,
    ``objc`` or ``plain``.  ``readable_name`` equals the input when nothing
    could be decoded, so this function is always safe to call.
    """
    if not name:
        return name, "plain"
    text = str(name)
    # Objective-C method names are already readable.
    if re.match(r"^[+-]\[", text):
        return text, "objc"
    out, changed = _demangle_cpp(text)
    if changed:
        return out, "cpp"
    out, changed = _demangle_swift(text)
    if changed:
        return out, "swift"
    return text, "plain"


def _parse_address(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for prefix in ("sym.", "imp."):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if text.lower().startswith("0x"):
        body = text[2:]
        if not body or not re.fullmatch(r"[0-9a-fA-F]+", body):
            return None
        return int(body, 16)
    if re.fullmatch(r"[0-9a-fA-F]{6,16}", text):
        # Bare hex address (r2 pdf offsets are usually 0x-prefixed, but some
        # plugins emit bare strings).  Require >=6 digits to avoid swallowing
        # decimal offsets like "4012".
        return int(text, 16)
    if text.isdigit():
        return int(text, 10)
    return None


@dataclass
class AddressTable:
    """Sorted function entries used for nearest-symbol lookup."""

    addresses: List[int] = field(default_factory=list)
    names: List[str] = field(default_factory=list)

    def add(self, address: Any, name: str) -> None:
        addr = _parse_address(address)
        if addr is None or not name:
            return
        self.addresses.append(addr)
        self.names.append(name)

    def resolve(self, address: Any, window: int = DEFAULT_WINDOW) -> Optional[str]:
        addr = _parse_address(address)
        if addr is None or not self.addresses:
            return None
        if self.addresses != sorted(self.addresses):
            order = sorted(range(len(self.addresses)), key=self.addresses.__getitem__)
            self.addresses = [self.addresses[i] for i in order]
            self.names = [self.names[i] for i in order]
        idx = bisect.bisect_right(self.addresses, addr) - 1
        if idx < 0:
            return None
        delta = addr - self.addresses[idx]
        if delta > window:
            return None
        name = self.names[idx]
        return f"{name}+0x{delta:x}" if delta else name

    @classmethod
    def from_functions(cls, functions: Sequence[Function]) -> "AddressTable":
        table = cls()
        for fn in functions:
            table.add(fn.address, fn.name)
        return table

    @classmethod
    def from_manifest(cls, manifest: AnalysisManifest) -> "AddressTable":
        """Prefer the manifest's full address index over the analyzed subset.

        Entries in ``address_index`` are demangled on the fly so resolved call
        targets read as ``IOSurface::foo+0x8`` rather than a mangled spelling.
        Deeply-analyzed functions are merged in as a fallback.
        """
        table = cls()
        seen: set = set()
        for entry in manifest.address_index:
            addr = _parse_address(entry.get("address"))
            name = str(entry.get("name", ""))
            if addr is None or not name:
                continue
            readable, _ = demangle(name)
            table.add(addr, readable)
            seen.add(addr)
        for fn in manifest.functions:
            addr = _parse_address(fn.address)
            if addr is None or addr in seen:
                continue
            table.add(addr, fn.name)
        return table


@dataclass
class SymbolicationStats:
    functions: int = 0
    cpp: int = 0
    swift: int = 0
    objc: int = 0
    targets_demangled: int = 0
    addresses_resolved: int = 0
    calls_demangled: int = 0
    already: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _symbolicate_site(site: CallSite, table: AddressTable, stats: SymbolicationStats,
                      window: int) -> None:
    target = site.target
    if not target:
        return
    addr = _parse_address(target)
    if addr is not None:
        resolved = table.resolve(target, window=window)
        if resolved and resolved != target:
            site.raw_target = target
            site.target = resolved
            stats.addresses_resolved += 1
        return
    readable, kind = demangle(target)
    if readable != target:
        site.raw_target = target
        site.target = readable
        stats.targets_demangled += 1


def symbolicate_manifest(manifest: AnalysisManifest, window: int = DEFAULT_WINDOW) -> SymbolicationStats:
    """Symbolicate a manifest in place and return what changed.

    Idempotent: if ``metadata['symbolicated']`` is already set, returns a stats
    object with ``already=True`` and leaves the manifest untouched.
    """
    stats = SymbolicationStats()
    if manifest.metadata.get("symbolicated"):
        stats.already = True
        return stats

    # Pass 1: demangle every function NAME first.  Doing this before address
    # resolution is essential -- the address table must map to the readable
    # names, otherwise resolved call sites would display mangled spellings
    # like "__ZN9IOSurface11setPropertyE+0x8".
    for fn in manifest.functions:
        stats.functions += 1
        original = fn.name
        readable, kind = demangle(original)
        if readable != original:
            fn.mangled = original
            fn.name = readable
            fn.symbol_source = kind
            if kind == "cpp":
                stats.cpp += 1
            elif kind == "swift":
                stats.swift += 1
        elif kind == "objc" and not fn.symbol_source:
            fn.symbol_source = "objc"
            stats.objc += 1

    # Build the address table from the full index (demangled on the fly), so
    # bare call targets resolve even when the callee was not disassembled.
    table = AddressTable.from_manifest(manifest)

    # Pass 2: resolve call sites, PAC sites, xrefs and plain call-name lists.
    for fn in manifest.functions:
        for site in fn.call_sites:
            _symbolicate_site(site, table, stats, window)
        for site in fn.pac_sites:
            _symbolicate_site(site, table, stats, window)

        new_calls: List[str] = []
        for call in fn.calls:
            readable, _ = demangle(call)
            if readable != call:
                stats.calls_demangled += 1
            if readable not in new_calls:
                new_calls.append(readable)
        fn.calls = new_calls

        new_xrefs: List[str] = []
        for xref in fn.xrefs:
            resolved = table.resolve(xref, window=window)
            if resolved and resolved != xref:
                stats.addresses_resolved += 1
                value = resolved
            else:
                value, _ = demangle(xref)
            if value not in new_xrefs:
                new_xrefs.append(value)
        fn.xrefs = new_xrefs

    manifest.metadata["symbolicated"] = True
    manifest.metadata["symbolication_version"] = SYMBOLICATION_VERSION
    manifest.metadata["symbolication"] = stats.to_dict()
    return stats


def symbolicate_manifests(manifests: Sequence[AnalysisManifest],
                          window: int = DEFAULT_WINDOW) -> Dict[str, Any]:
    """Symbolicate several manifests; aggregate stats into a summary dict."""
    aggregate = SymbolicationStats()
    for manifest in manifests:
        s = symbolicate_manifest(manifest, window=window)
        if s.already:
            aggregate.already = True
            continue
        aggregate.functions += s.functions
        aggregate.cpp += s.cpp
        aggregate.swift += s.swift
        aggregate.objc += s.objc
        aggregate.targets_demangled += s.targets_demangled
        aggregate.addresses_resolved += s.addresses_resolved
        aggregate.calls_demangled += s.calls_demangled
    return aggregate.to_dict()
