"""Negative controls for archive evidence (no Cargo processes needed)."""
import importlib.util
import hashlib
from pathlib import Path
import shutil
from subprocess import CompletedProcess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gcm_archives", Path(__file__).with_name("check-packaged-api.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
spec = importlib.util.spec_from_file_location("combined", Path(__file__).with_name("check-portable-acceptance.py"))
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)


class ArchiveTests(unittest.TestCase):
    def test_replay_rejects_a_consumer_that_ignores_the_verify_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "rows"
            data.write_text("seal\t00\nopen\t00\nreject\t01\n")
            for missed in ("open", "reject"):
                with self.subTest(missed=missed):
                    def consumer(cmd, *, input=None, **kwargs):
                        if input is None:
                            return CompletedProcess(cmd, 0, "generate=1 verify=1 reject=1", "")
                        ignored = {"open": "reject\t00\n", "reject": "open\t01\n"}[missed]
                        if input == ignored:
                            return CompletedProcess(cmd, 0, "", "")
                        return CompletedProcess(cmd, 1, "", "GMAC case 1 failed")
                    with patch.object(combined.pkg.cargo_environment, "check") as guard, \
                         patch.object(combined.subprocess, "run", side_effect=consumer) as runs, \
                         self.assertRaisesRegex(ValueError, f"wrong {missed} expectation"):
                        combined.replay(["cargo"], data.parent, {}, [], "nist", data,
                                        "generate=1 verify=1 reject=1")
                    self.assertEqual(guard.call_count, runs.call_count)

    def test_wrong_expectations_preserve_inputs_and_layout(self):
        plain = {"reject": "open", "seal": "seal", "open": "reject"}
        extra = {"open-disjoint": "reject-disjoint", "seal-in-place": "seal-in-place",
                 "reject-disjoint": "open-disjoint"}
        for example, labels in (("nist", plain), ("gcmvs", plain | extra)):
            rows = [kind + "\t1234\t\t0a\n" for kind in labels]
            got = dict(combined.wrong_expectations([rows[0], *rows], example))
            self.assertEqual(got, {kind: new + "\t1234\t\t" + ("1a" if kind.startswith("seal") else "0a") + "\n"
                                   for kind, new in labels.items()})
            with self.assertRaisesRegex(ValueError, "missing differential controls"):
                list(combined.wrong_expectations(rows[:-1], example))

    def test_empty_graph_is_not_portable_evidence(self):
        with self.assertRaisesRegex(ValueError, "missing archive"):
            runner.check_graph({"resolve": {"root": None, "nodes": []}, "packages": []},
                               Path("/unused"), {}, "brynja")

    def test_frozen_inventory_requires_each_exact_file_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example").write_bytes(b"public fixture")
            checksum = hashlib.sha256(b"public fixture").hexdigest()
            line = checksum + "  example\n"
            with patch.multiple(combined, ROOT=root, FIXTURE=root, INPUTS={"example"}):
                for inventory in ("", line * 2, line.replace("example", "extra"), "0" * 64 + line[64:]):
                    (root / "SHA256SUMS").write_text(inventory)
                    with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                        combined.frozen()
                (root / "SHA256SUMS").write_text(line)
                combined.frozen()

    def test_combined_registry_binds_frozen_inputs_and_requires_full_replay(self):
        registry = tomllib.loads((runner.ROOT / "verification/checks.toml").read_text())
        check, = (c for c in registry["checks"] if
                  (c["component"], c["id"]) == ("gmac", "packaged-portable-acceptance"))
        self.assertEqual(check["command"], ["python3", "scripts/aes-gcm/check-portable-acceptance.py"])
        paths = {Path(p) for g in check["inputs"] for p in registry["groups"][g].get("paths", [])}
        for name in combined.INPUTS | {check["command"][1], "assurance/aead-portable-acceptance/SHA256SUMS"}:
            self.assertTrue(any(Path(name).is_relative_to(p) for p in paths), name)
        self.assertEqual(check["success"]["contains"], ["PORTABLE_AEAD_ARCHIVES_COMPLETE"])

    def test_fixture_change_fails_even_if_the_number_of_examples_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "fixture"
            for directory in ("src", "tests"):
                shutil.copytree(runner.FIXTURE / directory, fixture / directory)
            data = fixture / "tests/nist-worked.txt"
            data.write_bytes(data.read_bytes().replace(b"3247184b", b"3247184a", 1))
            with patch.object(runner, "FIXTURE", fixture), self.assertRaisesRegex(ValueError, "NIST fixture"):
                runner.prepare(root, "brynja-crypto", {"brynja-crypto": "0.2.0"})

    def test_archive_registration_covers_every_packaged_crate_and_helper(self):
        registry = tomllib.loads((runner.ROOT / "verification/checks.toml").read_text())
        check, = (c for c in registry["checks"] if
                  (c["component"], c["id"]) == ("aes_gcm", "packaged-public-api"))
        self.assertEqual(check["command"], ["python3", "scripts/aes-gcm/check-packaged-api.py"])
        paths = {p for group in check["inputs"] for p in registry["groups"][group].get("paths", [])}
        required = {f"crates/{name}" for name in runner.pkg.MODERN}
        self.assertTrue(required | {check["command"][1], "scripts/ghash/check-packaged-api.py",
                        "scripts/hkdf/check-hkdf-public-api.py", "scripts/repository/facade_cargo_environment.py",
                        "assurance/aes-gcm-consumer/tests", "assurance/aes-gcm-consumer/src"} <= paths)
        self.assertEqual(check["success"]["contains"], ["AES_GCM_ARCHIVE_COMPLETE"])


if __name__ == "__main__":
    unittest.main()
