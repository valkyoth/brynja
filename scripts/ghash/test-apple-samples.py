"""Offline replay and target-attribution controls for Apple PMI sampling."""
import contextlib
import io
from pathlib import Path
import runpy
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

C = runpy.run_path(str(Path(__file__).with_name("check-apple-samples.py")))
OBS = Path(__file__).resolve().parents[2] / "assurance/ghash-observations"
EXE = Path("/test/public-fixture")
EVENT = "INST_BRANCH"
PINS = {
    "1.100.0-INST_BRANCH.samples.json": "91d7d6abb36258430b10c9e2ff5e57580f1ad287d5f3d40a8ffd73d95c78c5f9",
    "1.100.0-L1D_CACHE_MISS_LD.samples.json": "080d76fdfa825c4705e9d99c47d50c6235a79838ef66c239e0ffaa22e2625f48",
    "1.90.0-INST_BRANCH.samples.json": "e77d89a34369de2c49fd30f6351f7bc7ac52b389cea2ef4b9b14d003b9498c68",
    "1.90.0-L1D_CACHE_MISS_LD.samples.json": "28af3bb540adfc69e24e4b3107d9afd24379c4e49f86d78ce39279375f2d9d93",
}
TOC = """<trace-toc><run><info><target><process type="launched" name="public-fixture" pid="20"
return-exit-status="0" termination-reason="exit(0)" /></target></info>
<processes><process pid="20" path="/test/public-fixture" /></processes><data>
<table schema="counters-profile" target-pid="SINGLE" pmi-event='"INST_BRANCH"'
pmi-threshold="65536" trigger="pmi" /></data></run></trace-toc>"""
ROWS = """<export><node><schema>
<col><mnemonic>time</mnemonic></col><col><mnemonic>process</mnemonic></col>
<col><mnemonic>weight</mnemonic></col></schema>
<row><sample-time>6</sample-time><process id="p"><pid>20</pid></process>
<pmc-event id="w">65536</pmc-event></row>
<row><sample-time>7</sample-time><process ref="p"/><pmc-event ref="w"/></row>
<row><sample-time>8</sample-time><process><pid>21</pid></process><pmc-event ref="w"/></row>
</node></export>"""


class AppleSamples(unittest.TestCase):
    def test_first_records(self):
        dest = OBS / "samples-apple-m2-pro"
        with patch("subprocess.Popen", side_effect=AssertionError("offline replay")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            C["replay"](OBS / "throughput-apple-m2-pro", dest)
        self.assertEqual(len(output.getvalue().splitlines()), 4)
        for filename, digest in PINS.items():
            self.assertEqual(C["digest"](dest / filename), digest)

    def test_attributes_samples_to_target_pid_only(self):
        parse = lambda raw: C["checked_rows"](ET.fromstring(TOC), ET.fromstring(raw), EVENT, EXE)
        self.assertEqual(parse(ROWS), [6, 7])
        self.assertEqual(parse(ROWS.replace("<pid>20", "<pid>21")), [])
        with self.assertRaisesRegex(ValueError, "sample schema"):
            parse("<export><node/></export>")
        with self.assertRaisesRegex(ValueError, "sample weight"):
            parse(ROWS.replace(">65536<", ">128<"))

    def test_wrong_event_binary_or_failed_target_is_not_evidence(self):
        for before, after in (("INST_BRANCH", "CYCLES"), ("65536", "4096"), ("SINGLE", "ALL"),
                              ("exit(0)", "timeout"), ("/test/public-fixture", "/other/public-fixture")):
            with self.assertRaises(ValueError):
                C["checked_rows"](ET.fromstring(TOC.replace(before, after)), ET.fromstring(ROWS), EVENT, EXE)


if __name__ == "__main__":
    unittest.main()
