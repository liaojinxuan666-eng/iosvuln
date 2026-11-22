"""Tests for analysis-quality fixes: no fake hook data + value-ranked deep analysis."""
import os
import tempfile
import unittest

from iosvuln.acquire import _macho_files, _is_macho
from iosvuln.config import Config
from iosvuln.ipswwrap import IpswTool, _has_macho_magic
from iosvuln.models import Severity
from iosvuln.pipeline import Pipeline
from iosvuln.r2_backend import _prioritize, _symbol_score
from iosvuln import report as report_mod


class HookDataSourceTests(unittest.TestCase):
    def test_real_mode_without_observations_skips_hook(self):
        """Real analysis must not silently inject demo observations."""
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            cfg = Config(demo=False, workdir=td, archive=False, home=os.path.join(td, "home"))
            p = Pipeline(cfg)
            obs = p._load_observations()
            self.assertEqual(obs, [])
            self.assertEqual(p.observation_source, "none")
            self.assertTrue(any("跳过 hook" in w for w in p.warnings))

    def test_demo_mode_uses_fixture(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            cfg = Config(demo=True, workdir=td, archive=False, home=os.path.join(td, "home"))
            p = Pipeline(cfg)
            obs = p._load_observations()
            self.assertGreater(len(obs), 0)
            self.assertEqual(p.observation_source, "demo-fixture")


class RankedDeepAnalysisTests(unittest.TestCase):
    def test_high_value_symbols_ranked_first(self):
        funcs = [
            {"name": "sub_1000", "offset": "0x1000"},
            {"name": "stub_helper", "offset": "0x1010"},
            {"name": "__ZN9IOSurface14externalMethodEj", "offset": "0x2000"},
            {"name": "_copyin", "offset": "0x2100"},
            {"name": "_IOSurfaceLock", "offset": "0x2200"},
        ]
        sel = _prioritize(funcs, 3)
        names = [f["name"] for f in sel]
        self.assertIn("__ZN9IOSurface14externalMethodEj", names)
        self.assertIn("_copyin", names)
        self.assertIn("_IOSurfaceLock", names)
        self.assertNotIn("sub_1000", names)

    def test_score_values(self):
        self.assertGreater(_symbol_score("__ZN9IOSurface14externalMethodEj"), 0)
        self.assertGreater(_symbol_score("_copyin"), _symbol_score("sub_1234"))
        self.assertEqual(_symbol_score("sub_1234"), 0)

    def test_no_ranking_when_under_budget(self):
        funcs = [{"name": "a"}, {"name": "b"}]
        self.assertEqual(_prioritize(funcs, 400), funcs)


class ReportSourceLabelTests(unittest.TestCase):
    def _markdown(self, source):
        meta = {
            "observation_source": source,
            "observations": 5 if source != "none" else 0,
            "symbolication": {},
        }
        return report_mod.render_markdown([], [], meta)

    def test_demo_label(self):
        self.assertIn("演示数据", self._markdown("demo-fixture"))

    def test_collected_label(self):
        self.assertIn("真实采集日志", self._markdown("collected"))

    def test_none_label(self):
        self.assertIn("未提供", self._markdown("none"))


class NoFakeDataTests(unittest.TestCase):
    """The 396-finding / 132-fake-HIGH incident must never recur."""

    def test_no_input_never_uses_demo(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Config(
                demo=False, workdir=td, archive=False,
                home=os.path.join(td, "home"),
                kernelcache="/nonexistent/kernelcache",
                targets=["all"], max_targets=3,
                plugins=["vuln-primitives"],
            )
            result = Pipeline(cfg).run()
            self.assertEqual(len(result.findings), 0)
            self.assertTrue(any("不使用 DEMO" in w for w in result.warnings))

    def test_demo_mode_still_works(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Config(demo=True, workdir=td, archive=False,
                         home=os.path.join(td, "home"))
            result = Pipeline(cfg).run()
            self.assertGreater(len(result.findings), 0)


class MachOSniffTests(unittest.TestCase):
    def test_dotted_kext_name_detected_by_magic(self):
        with tempfile.TemporaryDirectory() as td:
            kext = os.path.join(td, "com.apple.iokit.IOSurface")
            with open(kext, "wb") as f:
                f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 20)
            with open(os.path.join(td, "info.plist"), "wb") as f:
                f.write(b"<?xml?>")
            found = _macho_files(td)
            self.assertTrue(any("IOSurface" in x for x in found))
            self.assertFalse(any("plist" in x for x in found))
            self.assertTrue(_is_macho(kext))

    def test_extract_failure_returns_none(self):
        cfg = Config(workdir="/tmp/iv-x", ipsw_path="/nonexistent/ipsw")
        tool = IpswTool(cfg)
        self.assertIsNone(tool.extract_kext("/x", "com.apple.foo"))

    def test_has_macho_magic(self):
        with tempfile.TemporaryDirectory() as td:
            m = os.path.join(td, "kext")
            with open(m, "wb") as f:
                f.write(b"\xca\xfe\xba\xbe" + b"\x00" * 20)
            self.assertTrue(_has_macho_magic(m))


if __name__ == "__main__":
    unittest.main()
