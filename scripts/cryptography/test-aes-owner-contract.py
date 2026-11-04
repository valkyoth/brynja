#!/usr/bin/env python3
"""Synthetic mutations of the scoped AES development owner; no crypto runs."""
import copy
from pathlib import Path
import tempfile
import tomllib
import unittest

import aes_owner_contract as contract
import rust_source_contract as rust

ROOT = Path(__file__).resolve().parents[2]


class OwnerContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for path in (contract.SOURCE, contract.PORTABLE, 'verification/checks.toml'):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / path).read_text())
        policy = tomllib.loads((ROOT / 'security/cryptographic-api-profile-policy.toml').read_text())
        self.owner = copy.deepcopy(policy['development-secret-owner'][0])
        self.current = policy['current-secret-owner']

    def validate(self):
        contract.validate(self.root, self.owner, self.current)

    def mutate(self, path, old, new):
        file = self.root / path
        source = file.read_text()
        self.assertIn(old, source)
        file.write_text(source.replace(old, new))

    def test_current_contract(self):
        self.validate()

    def test_fixed_array_signature_has_a_real_body(self):
        body = contract.callable_body(self.root, contract.SOURCE, 'Aes128Key', 'transform')
        self.assertIn('Scratch::<176>::new()', body)

    def test_reject_missing_or_disabled_operation(self):
        self.mutate(contract.SOURCE, 'pub fn encrypt_block_public(', '#[cfg(test)]\npub fn encrypt_block_public(')
        with self.assertRaises(rust.RustContractError):
            self.validate()

    def test_reject_qualification_or_family_promotion(self):
        for field, value in [('qualification', 'complete'), ('variant', 'AES'), ('rounds', 14),
                             ('key_bytes', 32), ('excluded_scope', []), ('lifecycle_scope', ['all'])]:
            original = self.owner[field]
            self.owner[field] = value
            with self.assertRaisesRegex(ValueError, 'canonical scoped record'):
                self.validate()
            self.owner[field] = original

    def test_reject_declassification_or_failure_downgrade(self):
        self.owner['operations'][3]['failure'] = 'may-partially-write'
        with self.assertRaisesRegex(ValueError, 'canonical scoped record'):
            self.validate()

    def test_reject_missing_core_owner(self):
        self.current = [c for c in self.current if c['id'] != 'core.owned-secret-region']
        with self.assertRaisesRegex(ValueError, 'delegated core owner'):
            self.validate()

    def test_reject_nonclearing_field(self):
        self.mutate(contract.SOURCE, "region: OwnedSecretRegion<'a>", "region: &'a mut [u8]")
        with self.assertRaisesRegex(ValueError, 'exact clearing region'):
            self.validate()

    def test_reject_thread_movable_marker(self):
        self.mutate(contract.SOURCE, 'local: PhantomData<*mut ()>', 'local: PhantomData<()>')
        with self.assertRaisesRegex(ValueError, 'local marker'):
            self.validate()

    def test_reject_extra_secret_field(self):
        self.mutate(contract.SOURCE, 'pub struct Aes128Key<\'a> {', 'pub struct Aes128Key<\'a> {\n retained_key: [u8; 16],')
        with self.assertRaises(rust.RustContractError):
            self.validate()

    def test_reject_invented_destructor(self):
        self.mutate(contract.SOURCE, 'mod portable;', 'mod portable;\nimpl Drop for Aes128Key {}')
        with self.assertRaisesRegex(ValueError, 'direct owner destructor'):
            self.validate()

    def test_reject_missing_explicit_clear(self):
        self.mutate(contract.SOURCE, 'let _ = self.region.clear();', 'core::mem::forget(self.region);')
        with self.assertRaisesRegex(ValueError, 'explicit clear delegation'):
            self.validate()

    def test_reject_scratch_clear_only_in_comment(self):
        self.mutate(contract.SOURCE, 'let _ = clear_owned_region(&mut self.0);', '// let _ = clear_owned_region(&mut self.0);')
        with self.assertRaisesRegex(ValueError, 'mandatory scratch clearing'):
            self.validate()

    def test_reject_test_only_scratch_clear(self):
        self.mutate(contract.SOURCE, 'let _ = clear_owned_region(&mut self.0);', '#[cfg(test)]\nlet _ = clear_owned_region(&mut self.0);')
        with self.assertRaisesRegex(ValueError, 'mandatory scratch clearing'):
            self.validate()

    def test_reject_unguarded_operation_schedule(self):
        self.mutate(contract.SOURCE, 'Scratch::<176>::new()', 'Ordinary::<176>::new()')
        with self.assertRaisesRegex(ValueError, 'operation scratch guards'):
            self.validate()

    def test_reject_unguarded_expansion_word(self):
        self.mutate(contract.PORTABLE, 'Scratch::<4>::new()', 'Ordinary::<4>::new()')
        with self.assertRaisesRegex(ValueError, 'helper scratch guard'):
            self.validate()

    def test_reject_round_count_drift(self):
        self.mutate(contract.PORTABLE, 'for round in 1..10', 'for round in 1..9')
        with self.assertRaisesRegex(ValueError, 'round bounds'):
            self.validate()

    def test_reject_public_acknowledgement_field(self):
        self.mutate(contract.SOURCE, '_private: (),', 'pub _private: (),')
        with self.assertRaisesRegex(ValueError, 'authority is no longer private'):
            self.validate()

    def test_reject_fixed_width_drift(self):
        self.mutate(contract.SOURCE, 'KEY_BYTES: usize = 16;', 'KEY_BYTES: usize = 32;')
        with self.assertRaisesRegex(ValueError, 'fixed AES-128 width'):
            self.validate()

    def test_reject_replaced_compiler_driver(self):
        self.mutate('verification/checks.toml', '["python3", "scripts/aes/check-aes-operation-cleanup.py"]', '["true"]')
        with self.assertRaisesRegex(ValueError, 'binding missing or replaced'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
