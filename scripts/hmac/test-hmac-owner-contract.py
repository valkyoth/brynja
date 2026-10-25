#!/usr/bin/env python3
"""Composed registration regressions; emitted-code tests remain separate."""
import copy
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/cryptography"))
import api_profile_model as model
import hmac_owner_contract as contract
import secret_owner_compiler as direct
from legacy_hmac_owner_tests import LegacyOwnerTests


class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.policy = model.read_policy()
        self.surfaces = model.read_surfaces()
        self.owner = next(row for row in self.policy["registered-secret-owner"]
                          if row["id"] == contract.ID)
        self.directory = tempfile.TemporaryDirectory(prefix="brynja-hmac-owner-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in (contract.LEAF + "engine.rs", contract.LEAF + "algorithms.rs", "scripts/checks.sh"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)

    def validate(self):
        contract.validate(self.root, self.owner, self.policy["registered-secret-owner"])

    def mutate(self, name, before, after):
        path = self.root / name
        original = path.read_text()
        self.assertEqual(original.count(before), 1)
        path.write_text(original.replace(before, after))
        try:
            with self.assertRaises((ValueError, contract.rust.RustContractError)):
                self.validate()
        finally:
            path.write_text(original)

    def test_registered_but_not_qualified_or_direct_destructor(self):
        self.validate()
        register = model.build_register(self.policy, self.surfaces)
        owner = next(row for row in register["registered_secret_owners"] if row["id"] == contract.ID)
        self.assertEqual(owner["qualification"], contract.RECORD["qualification"])
        self.assertNotIn("sanitization_symbol", owner)
        self.assertNotIn("cleanup_callers", owner)
        self.assertNotIn(contract.ID, direct.contracts.REGISTERED_OWNER_CONTRACTS)
        direct.compiler_inventory()  # Original direct-owner population still validates.
        self.assertNotIn("planned.algorithm.hmac", {row["id"] for row in register["planned_secret_owners"]})
        self.assertIn(b"not native release qualification", model.render_coverage(register))

    def test_record_fields_cannot_disappear_expand_or_change(self):
        original = copy.deepcopy(self.owner)
        for name, value in original.items():
            for mode in ("remove", "replace"):
                with self.subTest(name=name, mode=mode):
                    self.owner.clear()
                    self.owner.update(copy.deepcopy(original))
                    if mode == "remove":
                        del self.owner[name]
                    else:
                        self.owner[name] = [] if isinstance(value, list) else "forged"
                    with self.assertRaisesRegex(ValueError, "canonical record changed"):
                        self.validate()
        self.owner.clear()
        self.owner.update(original, sanitization_symbol=contract.LEAF + "scratch.rs#Scratch::drop")
        with self.assertRaisesRegex(ValueError, "canonical record changed"):
            self.validate()

    def test_scratch_and_facade_are_not_the_engine(self):
        for symbol in (contract.LEAF + "scratch.rs#Scratch", "crates/brynja-strict/src/hmac.rs#Session"):
            self.owner["symbol"] = symbol
            with self.assertRaisesRegex(ValueError, "canonical record changed"):
                self.validate()

    def test_missing_composed_and_delegated_owners_reject(self):
        for identity in (contract.ID, *contract.RECORD["delegated_owners"]):
            policy = copy.deepcopy(self.policy)
            policy["registered-secret-owner"] = [row for row in policy["registered-secret-owner"]
                                                 if row["id"] != identity]
            with self.subTest(identity=identity), self.assertRaisesRegex(
                    model.ProfileError, "composed secret-owner inventory|delegated clearing owner"):
                model.build_register(policy, self.surfaces)

    def test_surface_disposition_cannot_contradict_the_registered_owner(self):
        row = next(row for row in self.surfaces["surfaces"] if row["id"] == "algorithm.hmac")
        self.assertEqual(row["code_target"], contract.LEAF + "lib.rs#Hmac")
        self.assertEqual(row["test_target"], "crates/brynja-mac-hmac/tests/vectors.rs#rfc4231_case1")
        for disposition in ("future-work", "caller-owned", "legacy-only"):
            row["disposition"] = disposition
            self.policy["schema"]["surface_register_sha256"] = model.sha256(model.json_bytes(self.surfaces))
            with self.subTest(disposition=disposition), self.assertRaisesRegex(
                    model.ProfileError, "lacks an implemented secret capability"):
                model.build_register(self.policy, self.surfaces)

    def test_all_bound_checks_are_raw_pinned_not_only_the_registration(self):
        pins = {row["path"] for row in self.policy["reviewed-source"]}
        for command in contract.CHECKS:
            self.assertIn(command.split()[1], pins)
        for tree in contract.SOURCE_TREES:
            self.assertTrue((ROOT / tree).is_dir(), tree)
            self.assertTrue(any(path.startswith(tree + "/") for path in pins), tree)

    def test_owned_types_sealing_and_fabricated_drop_reject(self):
        name = contract.LEAF + "engine.rs"
        for field in ("inner", "outer"):
            self.mutate(name, field + ": A::State,", field + ": core::mem::ManuallyDrop<A::State>,")
            self.mutate(name, field + ": A::State,", "// " + field + ": A::State,")
        self.mutate(name, "    tag_bytes: usize,\n}", "    tag_bytes: u64,\n}")
        self.mutate(name, "impl<A: Algorithm> Engine<A> {",
                    "impl<A: Algorithm> Drop for Engine<A> {}\nimpl<A: Algorithm> Engine<A> {")
        self.mutate(contract.LEAF + "algorithms.rs", "pub(crate) mod sealed", "pub mod sealed")
        self.mutate(contract.LEAF + "algorithms.rs", "pub trait Algorithm: sealed::Hash",
                    "pub trait Algorithm: OtherHash")

    def test_all_eleven_existing_compiler_commands_are_required(self):
        self.assertEqual(len(contract.CHECKS), 11)
        for command in contract.CHECKS:
            for replacement in ("# " + command, "echo " + command, command + "\n" + command):
                with self.subTest(command=command):
                    self.mutate("scripts/checks.sh", command + "\n", replacement + "\n")

    def test_raw_review_pins_cover_each_hmac_input(self):
        pins = {row["path"] for row in self.policy["reviewed-source"]}
        self.assertLessEqual(contract.reviewed_paths(), pins)
        required = (contract.LEAF + "engine.rs", "scripts/cryptography/hmac_owner_contract.py",
                    "scripts/cryptography/api_profile_render.py",
                    "scripts/hmac/hmac_hosted_loans.py", "scripts/hmac/test-hmac-owner-contract.py")
        read = Path.read_bytes
        for name in required:
            original = (ROOT / name).read_bytes()
            def changed(path, name=name, original=original):
                return original.replace(b"\n", b"\r\n") if path == ROOT / name else read(path)
            with self.subTest(name=name), mock.patch.object(Path, "read_bytes", changed):
                with self.assertRaisesRegex(model.ProfileError, "reviewed secret-state source changed"):
                    model.build_register(self.policy, self.surfaces)

    def test_new_code_is_not_exempt_from_inventory(self):
        before = contract.reviewed_paths(self.root)
        for name in ("scripts/hmac/new_helper.py", contract.LEAF + "new_owner.rs",
                     "assurance/hmac-engine-cleanup/src/new_consumer.rs"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// synthetic inventory probe\n")
            self.assertIn(name, contract.reviewed_paths(self.root) - before)


if __name__ == "__main__":
    unittest.main()
