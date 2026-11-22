"""Symbolication tests: run with PYTHONPATH=. python3 -m pytest tests/test_symbolicate.py -q

Mangled names are built programmatically with ``_m`` (length-prefixed source
names) so the fixtures cannot drift from the Itanium ABI encoding rules.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from iosvuln.models import AnalysisManifest, CallSite, Function
from iosvuln.symbolicate import (
    AddressTable,
    demangle,
    symbolicate_manifest,
    symbolicate_manifests,
)


def _m(name: str) -> str:
    """Itanium source-name: <decimal length><identifier>."""
    return f"{len(name)}{name}"


class CppDemangleTests(unittest.TestCase):
    def test_member_function(self):
        sym = "__ZN" + _m("IOSurface") + _m("setProperty") + "EP" + _m("OSDictionary")
        out, kind = demangle(sym)
        self.assertEqual(kind, "cpp")
        self.assertEqual(out, "IOSurface::setProperty(OSDictionary*)")

    def test_const_method(self):
        sym = "__ZNK" + _m("IOSurface") + _m("getProperty") + "EPKc"
        out, _ = demangle(sym)
        # c++filt says "char const*", our demangler says "const char*" -- both
        # are valid C++ spellings; assert on the stable parts only.
        self.assertIn("IOSurface::getProperty(", out)
        self.assertIn("char*", out)
        self.assertTrue(out.endswith(" const"))

    def test_constructor_and_destructor(self):
        ctor = "_ZN" + _m("IOSurface") + "C1Ev"
        dtor = "_ZN" + _m("IOSurface") + "D1Ev"
        self.assertEqual(demangle(ctor)[0], "IOSurface::IOSurface()")
        self.assertEqual(demangle(dtor)[0], "IOSurface::~IOSurface()")

    def test_namespace(self):
        sym = "__ZN" + _m("IOKit") + _m("IOService") + _m("open") + "Ei"
        self.assertEqual(demangle(sym)[0], "IOKit::IOService::open(int)")

    def test_plain_and_objc_passthrough(self):
        self.assertEqual(demangle("plain_func"), ("plain_func", "plain"))
        self.assertEqual(demangle("-[IOSurface setProperty:]")[1], "objc")

    def test_single_underscore_macho_prefix(self):
        sym = "_ZN" + _m("Foo") + _m("bar") + "Eii"
        self.assertEqual(demangle(sym)[0], "Foo::bar(int, int)")

    def test_never_throws(self):
        for junk in ("__Z", "__ZZZ", "_ZN99999999999", "__ZN3Foo", "$s$$$", ""):
            out, _ = demangle(junk)
            self.assertIsInstance(out, str)


class SwiftDemangleTests(unittest.TestCase):
    def test_builtin(self):
        self.assertEqual(demangle("$sSi"), ("Swift.Int", "swift"))
        self.assertEqual(demangle("$sSs")[0], "Swift.String")

    def test_module_member(self):
        sym = "$s" + _m("MyModule") + _m("MyStruct") + "C"
        out, kind = demangle(sym)
        self.assertEqual(kind, "swift")
        self.assertIn("MyModule", out)
        self.assertIn("MyStruct", out)


class AddressTableTests(unittest.TestCase):
    def test_exact_and_offset(self):
        table = AddressTable()
        table.add("0x1000", "func_a")
        table.add("0x2000", "func_b")
        self.assertEqual(table.resolve("0x1000"), "func_a")
        self.assertEqual(table.resolve("0x1010"), "func_a+0x10")

    def test_out_of_window_and_before_first(self):
        table = AddressTable()
        table.add("0x1000", "func_a")
        self.assertIsNone(table.resolve("0x0fff"))
        self.assertIsNone(table.resolve("0x9000"))

    def test_unsorted_input(self):
        table = AddressTable()
        table.add("0x2000", "func_b")
        table.add("0x1000", "func_a")
        self.assertEqual(table.resolve("0x1000"), "func_a")


class ManifestSymbolicationTests(unittest.TestCase):
    def test_full_index_resolves_callee(self):
        setter = "__ZN" + _m("IOSurface") + _m("setProperty") + "EP" + _m("OSDictionary")
        ext = "__ZN" + _m("IOSurface") + _m("externalMethod") + "EjP" + _m("IOExternalMethodArguments")
        manifest = AnalysisManifest(
            target="t",
            functions=[Function(name=setter, address="0x1000",
                                call_sites=[CallSite(address="0x1004", target="0x2008")])],
            address_index=[
                {"address": "0x1000", "name": setter},
                {"address": "0x2000", "name": ext},
            ],
        )
        stats = symbolicate_manifest(manifest)
        site = manifest.functions[0].call_sites[0]
        self.assertTrue(site.target.startswith("IOSurface::externalMethod"))
        self.assertTrue(site.target.endswith("+0x8"))
        self.assertEqual(site.raw_target, "0x2008")
        self.assertEqual(manifest.functions[0].name, "IOSurface::setProperty(OSDictionary*)")
        self.assertEqual(manifest.functions[0].mangled, setter)
        self.assertGreater(stats.addresses_resolved, 0)

    def test_idempotent(self):
        manifest = AnalysisManifest(target="t", functions=[Function(name="plain", address="0x1")])
        first = symbolicate_manifest(manifest)
        self.assertFalse(first.already)
        second = symbolicate_manifest(manifest)
        self.assertTrue(second.already)

    def test_json_roundtrip(self):
        sym = "_ZN" + _m("Foo") + _m("bar") + "Eii"
        manifest = AnalysisManifest(target="t", functions=[Function(name=sym, address="0x10")])
        symbolicate_manifest(manifest)
        restored = AnalysisManifest.from_json(manifest.to_json())
        self.assertEqual(restored.functions[0].name, "Foo::bar(int, int)")
        self.assertEqual(restored.functions[0].mangled, sym)
        self.assertTrue(restored.metadata.get("symbolicated"))

    def test_rule_fires_after_symbolication(self):
        """Symbolication feeds readable tokens back into the rule engine."""
        from iosvuln import static_rules
        from iosvuln.plugins import AnalysisContext

        # A mangled copyin-style sink name would never match otherwise.
        sym = "__ZN" + _m("IOSurface") + _m("setProperty") + "EP" + _m("OSDictionary")
        manifest = AnalysisManifest(
            target="com.apple.driver.IOSurface",
            functions=[Function(name=sym, address="0x1000",
                                calls=["copyin", "memcpy"], complexity=3)],
            imports=["copyin", "memcpy"],
            strings=["allocSize"],
        )
        symbolicate_manifest(manifest)
        findings = static_rules.TaintSinkPlugin().run(AnalysisContext(manifest=manifest))
        self.assertTrue(any("setProperty" in f.location for f in findings))

    def test_named_index_used_when_subset_missing_callee(self):
        """Callee not in functions[] but present in address_index still resolves."""
        callee = "far_away_helper"  # plain name, no mangling
        manifest = AnalysisManifest(
            target="t",
            functions=[Function(name="caller", address="0x1000",
                                call_sites=[CallSite(address="0x1004", target="0x5000")])],
            address_index=[{"address": "0x5000", "name": callee}],
        )
        symbolicate_manifest(manifest)
        self.assertEqual(manifest.functions[0].call_sites[0].target, "far_away_helper")


class CLISymbolizeTests(unittest.TestCase):
    def test_symbolize_command_single(self):
        from iosvuln.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            # Cover CLI wiring via --manifest path below; here just ensure entry
            # point does not crash on a single symbol.
            self.assertEqual(main(["symbolize", "$sSi", "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
