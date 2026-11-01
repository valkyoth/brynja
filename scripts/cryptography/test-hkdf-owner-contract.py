#!/usr/bin/env python3
"""Positive and broken-source controls for the bounded HKDF owner inventory."""
import copy
from pathlib import Path
import tempfile
import tomllib
import unittest

import hkdf_owner_contract as contract

ROOT = Path(__file__).resolve().parents[2]


class OwnerContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for path in (contract.MODERN, contract.LEGACY, "verification/checks.toml"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / path).read_text())
        self.owner = {"id": contract.ID, **copy.deepcopy(contract.RECORD)}
        policy = tomllib.loads((ROOT / "security/cryptographic-api-profile-policy.toml").read_text())
        self.current = policy["current-secret-owner"]
        self.registered = policy["registered-secret-owner"]

    def validate(self):
        contract.validate(self.root, self.owner, self.registered, self.current)

    def mutate(self, path, old, new):
        file = self.root / path
        source = file.read_text()
        self.assertIn(old, source)
        file.write_text(source.replace(old, new))

    def test_current_contract(self):
        self.validate()

    def test_reject_qualification_promotion(self):
        self.owner["qualification"] = "complete"
        with self.assertRaisesRegex(ValueError, "canonical record"):
            self.validate()

    def test_reject_missing_core_owner(self):
        self.current = [c for c in self.current if c["id"] != "core.owned-secret-region"]
        with self.assertRaisesRegex(ValueError, "delegated clearing"):
            self.validate()

    def test_reject_missing_hmac_owner(self):
        self.registered = [c for c in self.registered if c["id"] != "registered.algorithm.hmac"]
        with self.assertRaisesRegex(ValueError, "delegated clearing"):
            self.validate()

    def test_reject_nonclearing_modern_field(self):
        self.mutate(contract.MODERN, "region: OwnedSecretRegion<'a>", "region: &'a mut [u8]")
        with self.assertRaisesRegex(ValueError, "exact clearing region"):
            self.validate()

    def test_reject_nonclearing_legacy_output(self):
        self.mutate(contract.LEGACY, "Option<OwnedSecretRegion<'a>>", "Option<&'a mut [u8]>")
        with self.assertRaisesRegex(ValueError, "exact clearing region"):
            self.validate()

    def test_reject_invented_destructor(self):
        self.mutate(contract.MODERN, "pub struct DerivedKey", "impl Drop for Prk {}\npub struct DerivedKey")
        with self.assertRaisesRegex(ValueError, "direct destructor"):
            self.validate()

    def test_reject_replaced_compiler_command(self):
        self.mutate("verification/checks.toml", '"scripts/hkdf/check-hkdf-owner-cleanup.py", "modern"',
                    '"scripts/hkdf/check-hkdf-owner-cleanup.py", "legacy"')
        with self.assertRaisesRegex(ValueError, "missing or replaced"):
            self.validate()

    def test_reject_replaced_operation_command(self):
        self.mutate("verification/checks.toml", '"scripts/hkdf/check-hkdf-operation-cleanup.py", "modern"',
                    '"scripts/hkdf/check-hkdf-operation-cleanup.py", "legacy"')
        with self.assertRaisesRegex(ValueError, "missing or replaced"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
