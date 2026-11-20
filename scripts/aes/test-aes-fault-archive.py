#!/usr/bin/env python3
"""Keep the unfinished AES fault prototype out of ordinary crate packages."""
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
RESEARCH = ROOT / "research/aes-fault-integrity"


class FaultArchiveBoundaryTests(unittest.TestCase):
    def test_sources_live_outside_published_crate_roots(self):
        self.assertTrue((RESEARCH / "crypto/fault_integrity/mod.rs").is_file())
        self.assertTrue((RESEARCH / "core/fault_comparison_workbench/mod.rs").is_file())
        self.assertFalse((ROOT / "crates/brynja-crypto/src/aes/fault_integrity.rs").exists())
        self.assertFalse((ROOT / "crates/brynja-crypto/src/aes/fault_integrity").exists())
        self.assertFalse((ROOT / "crates/brynja-core/src/fault_comparison_workbench.rs").exists())
        self.assertFalse((ROOT / "crates/brynja-core/src/fault_comparison_workbench").exists())

    def test_research_bridge_requires_explicit_non_feature_cfg(self):
        crypto = (ROOT / "crates/brynja-crypto/src/aes.rs").read_text(encoding="utf-8")
        core = (ROOT / "crates/brynja-core/src/lib.rs").read_text(encoding="utf-8")
        portable = (ROOT / "crates/brynja-crypto/src/aes/portable.rs").read_text(
            encoding="utf-8")
        self.assertIn("#[cfg(all(brynja_fault_profile_research, any(test, brynja_fault_profile_build)))]", crypto)
        self.assertIn("#[cfg(all(brynja_fault_primitives, brynja_fault_profile_research))]", core)
        self.assertIn("#[cfg(all(test, brynja_fault_evidence, brynja_fault_profile_research))]", portable)
        for manifest in ("crates/brynja-crypto/Cargo.toml", "crates/brynja-core/Cargo.toml"):
            self.assertNotIn("brynja_fault_profile_research", (ROOT / manifest).read_text(
                encoding="utf-8"))

    def test_actual_package_lists_exclude_prototype(self):
        for crate in ("brynja-core", "brynja-crypto"):
            package = subprocess.run(
                ["cargo", "package", "--list", "--allow-dirty", "--locked",
                 "--offline", "-p", crate], cwd=ROOT, capture_output=True,
                text=True, check=True, timeout=30)
            self.assertTrue(package.stdout.strip(), crate)
            self.assertFalse(any("fault_integrity" in line or
                                 "fault_comparison_workbench" in line or
                                 "field_fault_fixture" in line or
                                 line.startswith("research/")
                                 for line in package.stdout.splitlines()), crate)

    def test_deferred_slot_cannot_claim_a_release(self):
        plan = (ROOT / "docs/RELEASE_PLAN.md").read_text(encoding="utf-8")
        section = plan.split("### v0.27.7 - AES Fault-Integrity Research Archive", 1)[1]
        section = section.split("### v0.28.0 - GHASH", 1)[0]
        self.assertIn("Status: deferred research; no release or tag planned", section)
        self.assertIn("No tag or crates.io publication", section)


if __name__ == "__main__":
    unittest.main()
