#!/usr/bin/env python3
"""Focused facade catalog, negative-probe and graph regressions; no crypto rerun."""
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "hmac_facade_check", Path(__file__).with_name("check-hmac-facade.py"))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
api = checks.api


class FacadeTests(unittest.TestCase):
    def test_additive_leaf_cannot_enable_any_facade_opt_in(self):
        doc = {"packages": [{"id": "c", "name": "brynja-crypto"}],
               "resolve": {"nodes": [{"id": "c", "features": []}]}}
        checks.facade_isolation(doc)
        doc["resolve"]["nodes"][0]["features"] = ["default"]
        checks.facade_isolation(doc)
        for feature in (*checks.FEATURES, "cpu", "general-sha512-t"):
            doc["resolve"]["nodes"][0]["features"] = ["default", feature]
            with self.assertRaisesRegex(ValueError, "silently enabled"):
                checks.facade_isolation(doc)

    def test_current_archive_population_adds_hmac_once_without_mutating_catalog(self):
        declared = api.packaging.PACKAGING_PACKAGES
        without_hmac = tuple(row for row in declared if row[0] != api.archives.HMAC[0])
        # Older catalogs omit HMAC; current isolated package workspaces need it
        # even when disabled. Both inputs must resolve to the same exact set.
        current = api.archives.specifications(api.packaging)
        for seed in (without_hmac, declared):
            fake = SimpleNamespace(PACKAGING_PACKAGES=seed)
            resolved = api.archives.specifications(fake)
            self.assertEqual(set(resolved), set(current))
            self.assertEqual(len(resolved), len(without_hmac) + 1)
            self.assertEqual(len({name for name, *_ in resolved}), len(resolved))
            self.assertIn(api.archives.HMAC, resolved)
            self.assertEqual(fake.PACKAGING_PACKAGES, seed)
        self.assertEqual(api.packaging.PACKAGING_PACKAGES, declared)
        manifest = api.tomllib.loads((checks.ROOT / "crates/brynja/Cargo.toml").read_text())
        self.assertEqual(dict((name, version) for name, version, _ in current)["brynja"],
                         manifest["package"]["version"])
        fake = SimpleNamespace(PACKAGING_PACKAGES=current)
        self.assertEqual(api.archives.specifications(fake), current)
        fake.PACKAGING_PACKAGES += (current[0],)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            api.archives.specifications(fake)
        with patch.object(api.archives.tomllib, "loads",
                          return_value={"package": {"name": "substitute", "version": "0.0.0"}}):
            with self.assertRaisesRegex(ValueError, "identity"):
                api.archives.specifications(api.packaging)

    def test_forwarding_and_probes_cover_both_routes(self):
        for feature, leaf in zip(checks.FEATURES, ("hardened-execution", "runtime-execution")):
            self.assertEqual(api.policy.LEAVES[feature], ("brynja-mac-hmac", leaf))
            self.assertEqual(api.policy.FEATURES["brynja"][feature], ["brynja-crypto/" + feature])
            self.assertEqual(api.policy.FEATURES["brynja-crypto"][feature],
                             ["cpu", "brynja-mac-hmac/" + leaf])
            self.assertTrue(api.cases.PROBES[feature].startswith("hmac::execution::"))

    def test_probes_do_not_silently_skip_or_use_leaf_namespace(self):
        for package in ("brynja", "brynja-crypto"):
            seen = []
            def source(_consumer, name, text):
                self.assertEqual(name, package)
                self.assertTrue(text.startswith("use api::hmac::*;"))
                seen.append(text)
            with patch.object(api, "source", side_effect=source), patch.object(api, "run"), \
                    patch.object(checks.hmac_acceptance, "diagnostic_rejection") as rejection, \
                    redirect_stdout(io.StringIO()):
                checks.negatives(["cargo"], Path("/unused"), {}, package)
            self.assertEqual(len(seen), 118)
            self.assertEqual(rejection.call_count, 118)

    def test_missing_hmac_feature_and_protocol_cpu_are_rejected(self):
        feature = "hmac-runtime-execution"
        document = {"packages": [
            {"id": name, "name": name, "source": None}
            for name in ("brynja-crypto", "brynja-crypto-cpu", "brynja-mac-hmac")],
            "resolve": {"nodes": [
                {"id": "brynja-crypto", "features": [feature]},
                {"id": "brynja-crypto-cpu", "features": []},
                {"id": "brynja-mac-hmac", "features": ["runtime-execution"]}]}}
        api.graph(document, [feature])
        with self.assertRaisesRegex(ValueError, "CPU"):
            api.adversarial.protocol_graph(document)
        document["resolve"]["nodes"][-1]["features"] = []
        with self.assertRaisesRegex(ValueError, "missing resolved leaf feature"):
            api.graph(document, [feature])


if __name__ == "__main__":
    unittest.main()
