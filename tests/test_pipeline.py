"""Run with: PYTHONPATH=. python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from iosvuln.config import Config
from iosvuln.hook_layer import generate_tweak, parse_syslog
from iosvuln.ipswwrap import parse_kexts
from iosvuln.models import AnalysisManifest, Function, Layer
from iosvuln.pipeline import Pipeline
from iosvuln import static_rules  # noqa: F401

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


class KextParsingTests(unittest.TestCase):
    def test_text_output(self):
        text = (
            "com.apple.driver.IOSurface (1.0.0)\n"
            "com.apple.security.sandbox 1.0.0 /System/Library/Extensions\n"
            "garbage line\n"
        )
        kexts = parse_kexts(text)
        self.assertEqual(len(kexts), 2)
        self.assertEqual(kexts[0].bundle_id, "com.apple.driver.IOSurface")
        self.assertEqual(kexts[0].version, "1.0.0")

    def test_json_output(self):
        payload = [{"bundle_id": "com.apple.driver.X", "version": "2.1"}]
        kexts = parse_kexts(json.dumps(payload))
        self.assertEqual(kexts[0].bundle_id, "com.apple.driver.X")


class HookParsingTests(unittest.TestCase):
    def test_syslog(self):
        log = (
            "[IOSVULN] IOSurfaceCreate pid=42 proc=Demo id=7\n"
            "[IOSVULN] IOSurfaceGetBaseAddress pid=42 allocSize=402653184\n"
            "unrelated line\n"
        )
        observations = parse_syslog(log)
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0].function, "IOSurfaceCreate")
        self.assertEqual(observations[0].pid, 42)
        self.assertEqual(observations[1].arguments["allocSize"], 402653184)


class StaticRuleTests(unittest.TestCase):
    def test_no_global_false_positive(self):
        manifest = AnalysisManifest(
            target="com.apple.driver.IOSurface",
            functions=[Function(name="only_logs", calls=["os_log"])],
            imports=["copyin", "memcpy"],
            strings=["allocSize"],
        )
        findings = static_rules.TaintSinkPlugin().run(_context(manifest))
        self.assertEqual(findings, [])

    def test_taint_sink_detected(self):
        with open(os.path.join(EXAMPLES, "manifest_iosurface_demo.json"), encoding="utf-8") as fh:
            manifest = AnalysisManifest.from_json(fh.read())
        findings = static_rules.TaintSinkPlugin().run(_context(manifest))
        self.assertTrue(any("setProperty" in f.location for f in findings))


class PipelineTests(unittest.TestCase):
    def test_demo_pipeline(self):
        with tempfile.TemporaryDirectory() as workdir:
            cfg = Config(workdir=workdir, demo=True)
            result = Pipeline(cfg).run()
            self.assertTrue(result.findings)
            self.assertTrue(all(f.layer in (Layer.STATIC, Layer.HOOK) for f in result.findings))
            self.assertTrue(os.path.exists(result.reports["markdown"]))
            self.assertTrue(os.path.exists(result.reports["json"]))
            self.assertTrue(os.path.exists(result.artifacts["ellekit_tweak"]))
            with open(result.reports["json"], encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(len(data["findings"]), len(result.findings))

    def test_min_severity_filter(self):
        with tempfile.TemporaryDirectory() as workdir:
            cfg = Config(workdir=workdir, demo=True, min_severity="HIGH")
            result = Pipeline(cfg).run()
            self.assertTrue(result.findings)
            self.assertTrue(all(f.severity.value in ("HIGH", "CRITICAL") for f in result.findings))

    def test_generate_tweak(self):
        with tempfile.TemporaryDirectory() as workdir:
            path = generate_tweak(workdir)
            self.assertTrue(os.path.exists(os.path.join(path, "Tweak.x")))


def _context(manifest, **kwargs):
    from iosvuln.plugins import AnalysisContext

    return AnalysisContext(manifest=manifest, **kwargs)


if __name__ == "__main__":
    unittest.main()


class NewFeatureTests(unittest.TestCase):
    def test_vuln_primitives_with_assembly(self):
        with open(os.path.join(EXAMPLES, "manifest_iosurface_demo.json"), encoding="utf-8") as fh:
            manifest = AnalysisManifest.from_json(fh.read())
        findings = static_rules.VulnPrimitivesPlugin().run(_context(manifest))
        classes = {f.vuln_class for f in findings}
        self.assertIn("RCE", classes)
        self.assertIn("PRIVILEGE_ESCALATION", classes)
        self.assertIn("OOB_READ", classes)
        self.assertTrue(all(f.assembly for f in findings))

    def test_extractive_hook_dump(self):
        from iosvuln.hook_layer import HookObservationPlugin, load_extracted

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "extracted.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "target": "IOSurface.framework",
                        "functions": [
                            {
                                "name": "IOSurfaceCreate",
                                "address": "0x1a2b3c4d",
                                "bytes": "ff0301d6",
                            }
                        ],
                    },
                    fh,
                )
            observations = load_extracted(path)
            self.assertEqual(len(observations), 1)
            findings = HookObservationPlugin().run(
                _context(AnalysisManifest(target="com.apple.driver.IOSurface"), observations=observations)
            )
            self.assertTrue(any("0x1a2b3c4d" in a for f in findings for a in f.assembly))

    def test_acquisition_from_path(self):
        from iosvuln.acquire import Acquisition

        with tempfile.TemporaryDirectory() as tmp:
            kernelcache = os.path.join(tmp, "kernelcache.decompressed")
            with open(kernelcache, "wb") as fh:
                fh.write(b"mach-o-placeholder")
            acquired = Acquisition(Config(workdir=tmp, kernelcache=kernelcache)).acquire()
            self.assertEqual(acquired.mode, "path")
            self.assertEqual(acquired.kernelcache, kernelcache)

    def test_report_has_assembly_section(self):
        with tempfile.TemporaryDirectory() as workdir:
            result = Pipeline(Config(workdir=workdir, demo=True)).run()
            with open(result.reports["markdown"], encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("## 3.1 按原语归集的汇编位置", text)
            self.assertIn("blr x8", text)


