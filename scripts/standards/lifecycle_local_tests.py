"""Local-first authority monitoring regression tests; no network needed."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import lifecycle_local as local
import lifecycle_model as model
import lifecycle_network as network
import standards_lib as standards


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="brynja-authority-local-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = b"reviewed normative document bytes"
        register = model.load_json(model.REGISTER)
        self.row = copy.deepcopy(next(r for r in register["authorities"] if r["id"].startswith("itu:")))
        self.row["content_sha256"] = standards.sha256(self.data)
        self.register = {"authorities": [self.row], "schema": 1}
        self.policy = model.read_policy()
        source = local.source_path(self.root, self.row)
        source.parent.mkdir(parents=True)
        source.write_bytes(self.data)
        local.prepare(self.register, self.policy, self.root)

    def observer(self, response):
        def fetch(_url, _maximum):
            if isinstance(response, Exception):
                raise response
            return response
        return local.LocalObserver(self.register, self.policy, self.root, fetch)

    def observe(self, response):
        observer = self.observer(response)
        observations = network.content_observations(self.register, self.policy, observer.fetch)
        with patch.object(model, "load_json", return_value={"unresolved_observations": []}):
            result = observer.annotate(network.artifact(self.register, observations, "2026-09-15"))
        return result

    def test_available_unchanged_is_fresh(self):
        result = self.observe(self.data)
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(local.permits_freshness(result))
        self.assertEqual(result["offline_documents"], [])

    def test_available_changed_never_uses_cache(self):
        result = self.observe(b"updated document")
        self.assertEqual(result["observations"][0]["state"], "changed")
        self.assertFalse(local.permits_release(result))
        self.assertEqual(result["offline_documents"], [])
        self.assertEqual(local.cache_path(self.root, self.row).read_bytes(), self.data)

    def test_outages_use_local_but_cannot_claim_freshness(self):
        errors = [TimeoutError("timeout"), ConnectionResetError("reset"), socket.gaierror("DNS")]
        errors += [urllib.error.HTTPError(self.row["content_url"], code, "outage", {}, None)
                   for code in (408, 429, 500, 502, 503, 504)]
        errors += [urllib.error.URLError(TimeoutError("timeout"))]
        for error in errors:
            with self.subTest(error=error):
                result = self.observe(error)
                self.assertTrue(local.permits_release(result))
                self.assertFalse(local.permits_freshness(result))
                self.assertEqual(result["result"], "PASS WITH VERIFIED LOCAL DOCUMENTS")
                self.assertEqual(result["offline_documents"][0]["remote_freshness"], "unverified")
                self.assertEqual(result["offline_documents"][0]["local_sha256"], self.row["content_sha256"])

    def test_non_outages_are_not_downgraded(self):
        errors = [model.LifecycleError("redirect-rejected"), model.LifecycleError("oversized"),
                  model.LifecycleError("malformed"), ssl.SSLError("certificate rejected"),
                  urllib.error.URLError(ssl.SSLError("certificate rejected"))]
        errors += [urllib.error.HTTPError(self.row["content_url"], code, "rejected", {}, None)
                   for code in (301, 400, 401, 403, 404, 410)]
        for error in errors:
            with self.subTest(error=error):
                result = self.observe(error)
                self.assertFalse(local.permits_release(result))
                self.assertEqual(result["offline_documents"], [])

    def test_missing_or_corrupt_cache_rejects_even_when_online(self):
        path = local.cache_path(self.root, self.row)
        for value in (b"corrupt", b""):
            path.write_bytes(value)
            with self.assertRaises((RuntimeError, model.LifecycleError)):
                self.observer(self.data)
        path.unlink()
        with self.assertRaises(model.LifecycleError):
            self.observer(self.data)

    def test_prepare_does_not_repair_or_repin_corrupt_bytes(self):
        path = local.cache_path(self.root, self.row)
        path.write_bytes(b"wrong")
        with self.assertRaises(RuntimeError):
            local.prepare(self.register, self.policy, self.root)
        self.assertEqual(path.read_bytes(), b"wrong")
        path.unlink()
        local.source_path(self.root, self.row).write_bytes(b"new source")
        with self.assertRaises(RuntimeError):
            local.prepare(self.register, self.policy, self.root)
        self.assertFalse(path.exists())

    def test_symlinked_cache_and_parent_reject(self):
        path = local.cache_path(self.root, self.row)
        path.unlink()
        try:
            path.symlink_to(local.source_path(self.root, self.row))
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(model.LifecycleError, "symlinked"):
            self.observer(self.data)
        path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to(local.source_path(self.root, self.row).parent, target_is_directory=True)
        with self.assertRaisesRegex(model.LifecycleError, "symlinked"):
            self.observer(self.data)

    def test_bounds_and_duplicate_identity_reject(self):
        self.policy["monitor"]["document_max_bytes"] = 3
        with self.assertRaisesRegex(model.LifecycleError, "oversized"):
            self.observer(self.data)
        self.policy = model.read_policy()
        self.register["authorities"].append(copy.deepcopy(self.row))
        with self.assertRaisesRegex(model.LifecycleError, "ambiguous"):
            self.observer(self.data)

    def test_unrelated_metadata_outage_stays_blocked(self):
        observer = self.observer(TimeoutError("offline"))
        with self.assertRaises(TimeoutError):
            observer.fetch(self.row["landing_url"], 1024)
        observer.fetch(self.row["content_url"], 1024)
        changed = model.observation(self.row, "changed", "landing metadata changed")
        with patch.object(model, "load_json", return_value={"unresolved_observations": []}):
            result = observer.annotate(network.artifact(self.register, [changed], "2026-09-15"))
        self.assertFalse(local.permits_release(result))

    def test_prior_unresolved_review_is_retained(self):
        observation = model.observation(self.row, "changed", "previous change")
        previous = model.retain_unresolved([], [observation])
        observer = self.observer(TimeoutError("offline"))
        observer.fetch(self.row["content_url"], 1024)
        with patch.object(model, "load_json", return_value={"unresolved_observations": previous}):
            result = observer.annotate(network.artifact(self.register, [], "2026-09-15"))
        self.assertFalse(local.permits_release(result))
        self.assertEqual(result["unresolved_observations"], previous)

    def test_all_source_paths_are_bounded(self):
        for identifier, expected in (("rfc:1321", "rfc/rfc1321.txt"),
                                     ("iana:tls-parameters", "standards/snapshots/iana/tls-parameters.xml"),
                                     ("nist:sample.pdf", "references/local/sample.pdf")):
            self.assertEqual(local.source_path(self.root, {"id": identifier}), self.root / expected)
        for identifier in ("rfc:../x", "iana:../x", "nist:../../x.pdf", "itu:/x.pdf", "other:x"):
            with self.assertRaises(model.LifecycleError):
                local.source_path(self.root, {"id": identifier})
        with self.assertRaises(model.LifecycleError):
            local.cache_path(self.root, {"content_sha256": "../bad"})

    def test_cli_records_offline_without_upgrading_freshness(self):
        path = model.ROOT / "scripts/standards/observe-authority-lifecycle.py"
        spec = importlib.util.spec_from_file_location("local_observer_cli", path)
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        observer = self.observer(TimeoutError("offline"))
        observer.fetch(self.row["content_url"], 1024)
        output = self.root / "observation.json"
        argv = [str(path), "--artifact", str(output), "--allow-verified-local"]
        with patch("sys.argv", argv), patch.object(local, "LocalObserver", return_value=observer), \
                patch.object(network, "observe", return_value=[]), \
                patch.object(network, "write_existing_json") as freshness, patch("sys.stdout", io.StringIO()):
            self.assertEqual(cli.main(), 0)
            freshness.assert_not_called()
            self.assertEqual(json.loads(output.read_text())["result"], "PASS WITH VERIFIED LOCAL DOCUMENTS")
            output.unlink()
            argv.append("--write-freshness")
            with self.assertRaisesRegex(model.LifecycleError, "offline"):
                cli.main()
            freshness.assert_not_called()

    def test_release_opt_in_does_not_change_scheduled_monitor(self):
        gate = (model.ROOT / "scripts/tag_gate.sh").read_text()
        prepare = "python3 scripts/standards/prepare-authority-cache.py"
        observe = "python3 scripts/standards/observe-authority-lifecycle.py --allow-verified-local"
        self.assertEqual(gate.count(prepare), 1)
        self.assertEqual(gate.count(observe), 1)
        self.assertLess(gate.index(prepare), gate.index(observe))
        workflow = (model.ROOT / ".github/workflows/standards-lifecycle.yml").read_text()
        self.assertNotIn("--allow-verified-local", workflow)
        ignore = (model.ROOT / ".gitignore").read_text().splitlines()
        self.assertIn("/references/local/*", ignore)


def test():
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalTests))
    if not result.wasSuccessful():
        raise AssertionError("local authority regression tests failed")


if __name__ == "__main__":
    test()
