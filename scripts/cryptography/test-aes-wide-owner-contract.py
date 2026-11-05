#!/usr/bin/env python3
"""Mutation controls for the development-only wide AES owner inventory."""
from copy import deepcopy
from pathlib import Path
import tempfile
import tomllib
import unittest
import aes_wide_owner_contract as contract

ROOT = Path(__file__).resolve().parents[2]


class WideOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in (contract.SOURCE, contract.PORTABLE, contract.LAYOUT, 'verification/checks.toml'):
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((ROOT / path).read_text())
        policy = tomllib.loads((ROOT / 'security/cryptographic-api-profile-policy.toml').read_text())
        self.current = policy['current-secret-owner']
        self.owners = [{'id': name, **deepcopy(row)} for name, row in contract.RECORDS.items()]

    def validate(self):
        for owner in self.owners:
            contract.validate(self.root, owner, self.current)

    def test_current(self):
        self.validate()

    def test_reject_claim_promotion(self):
        self.owners[1]['compiler_scope'] = 'qualified'
        with self.assertRaisesRegex(ValueError, 'canonical scoped record'):
            self.validate()

    def test_reject_missing_core_owner(self):
        self.current = []
        with self.assertRaisesRegex(ValueError, 'delegated core owner'):
            self.validate()

    def test_reject_source_mutations(self):
        for path, old, new in (
            (contract.SOURCE, '    14\n', '    12\n'),
            (contract.SOURCE, 'local: PhantomData<*mut ()>', 'local: PhantomData<()>'),
            (contract.SOURCE, 'let _ = self.region.clear();', 'let _ = self.region.expose();'),
            (contract.SOURCE, '_authority: PublicCiphertext', '_authority: ()'),
            (contract.SOURCE, 'SecretRegionInitialization::begin(output)?', 'broken(output)?'),
            (contract.SOURCE, 'SecretRegionInitialization::begin(storage)?', 'broken(storage)?'),
            (contract.LAYOUT, '(32, 240, 14)', '(32, 240, 12)'),
            (contract.PORTABLE, 'layout::prior_word_index(offset, K, i)', 'layout::prior_word_index(offset, 4, i)'),
            (contract.PORTABLE, 'Scratch::<4>::new()', '[0; 4]'),
            (contract.PORTABLE, 'K == 32 && position == 16', 'K == 32 && position == 12'),
        ):
            with self.subTest(old=old):
                file = self.root / path
                original = file.read_text()
                self.assertIn(old, original)
                file.write_text(original.replace(old, new))
                with self.assertRaises(ValueError):
                    self.validate()
                file.write_text(original)

    def test_reject_compiler_binding_replacement(self):
        file = self.root / 'verification/checks.toml'
        original = file.read_text()
        for old, new in (
            ('id = "owner-dispatch"', 'id = "unrelated-dispatch"'),
            ('"scripts/aes/check-aes-owner-cleanup.py"', '"scripts/unrelated.py"'),
            ('id = "wide-operation-cleanup"', 'id = "unrelated-operation"'),
            ('"scripts/aes/check-aes-wide-operation-cleanup.py"', '"scripts/unrelated.py"'),
            ('category = "compiler"', 'category = "portable"'),
            ('platform = "linux-x86_64"', 'platform = "other"'),
        ):
            with self.subTest(old=old):
                self.assertIn(old, original)
                file.write_text(original.replace(old, new))
                with self.assertRaisesRegex(ValueError, 'compiler binding'):
                    self.validate()
        file.write_text(original)


if __name__ == '__main__':
    unittest.main()
