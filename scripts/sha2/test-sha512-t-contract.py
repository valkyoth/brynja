#!/usr/bin/env python3
"""Exhaustive descriptor model and fail-closed admission regressions."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sha512_t_contract as policy


class ContractTests(unittest.TestCase):
    def test_complete_u16_domain(self):
        accepted = 0
        for t in range(65536):
            if t == 0 or t == 384 or t >= 512:
                with self.assertRaises(ValueError):
                    policy.descriptor(t)
                continue
            accepted += 1
            label, width, mask = policy.descriptor(t)
            self.assertEqual(label[:8], b"SHA-512/")
            self.assertFalse(label[8:].startswith(b"0"))
            self.assertEqual(int(label[8:]), t)
            self.assertLessEqual(len(label), 11)
            self.assertGreaterEqual(len(label), 9)
            self.assertEqual(width, len(range(0, t, 8)))
            active = t % 8 or 8
            expected_mask = sum(1 << bit for bit in range(8 - active, 8))
            self.assertEqual(mask, expected_mask)
        self.assertEqual(accepted, 510)

    def test_invalid_python_types_do_not_mint_parameters(self):
        for value in (True, False, 1.0, "224", b"224", None, -1, 2**100):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.descriptor(value)

    def test_named_and_nonbyte_boundaries(self):
        self.assertEqual(policy.descriptor(224), (b"SHA-512/224", 28, 255))
        self.assertEqual(policy.descriptor(256), (b"SHA-512/256", 32, 255))
        self.assertEqual(policy.descriptor(1), (b"SHA-512/1", 1, 128))
        self.assertEqual(policy.descriptor(511), (b"SHA-512/511", 64, 254))

    def test_semantic_mutations(self):
        contract = policy.validate()
        for changed in (dict(contract, implemented=True), {k: v for k, v in contract.items() if k != "profiles"}):
            with self.assertRaises(ValueError):
                policy.validate_model(changed)
        mutations = [("parameters", key, value) for key, value in (
            ("minimum", 8), ("maximum", 512), ("excluded", []),
            ("count", 509), ("label_prefix", "SHA512/"),
            ("label_decimal", "zero-padded"), ("iv_mask", "0"),
            ("unused_bits", "high-zero"), ("output_order", "lsb-first"),
            ("approved_named_values", [224, 256, 511]), ("general_approval", True),
            ("minimum", True))]
        mutations += [("operations", key, "0.24.24") for key in contract["operations"]]
        mutations += [("authority", "distribution", "redistributable"),
                      ("authority", "sha256", "0" * 64)]
        for section, key, value in mutations:
            changed = copy.deepcopy(contract)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                policy.validate_model(changed)
        for key in ("default_enabled", "facade_export", "cpu_admitted", "fips_validated", "independently_verified"):
            changed = copy.deepcopy(contract)
            changed[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.validate_model(changed)

    def test_bound_contract_and_gate_mutations(self):
        original = policy.read
        for path in policy.BOUND:
            def changed(root, name, selected=path):
                data = original(root, name)
                return data + b"\nchanged\n" if name == selected else data
            with self.subTest(path=path), patch.object(policy, "read", changed), self.assertRaises(ValueError):
                policy.validate()
        for script in policy.BOUND[3:]:
            def missing(root, name, selected=script):
                data = original(root, name)
                return data.replace(f"python3 {selected}".encode(), b"# omitted") if name == "scripts/checks.sh" else data
            with patch.object(policy, "read", missing), self.assertRaises(ValueError):
                policy.validate()

    def test_bounded_read_and_crlf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_bytes(b"a\r\nb\r\n")
            self.assertEqual(policy.read(root, "input"), b"a\nb\n")
            with patch.object(policy, "LIMIT", 3), self.assertRaises(ValueError):
                policy.read(root, "input")
            with self.assertRaises(ValueError):
                policy.read(root, "absent")

    def test_profile_and_requirement_binding(self):
        original = policy.read
        cases = (
            ("requirements/domains/cryptography.toml", 'owner = "0.24.26"', 'owner = "0.24.25"'),
            ("security/cryptographic-api-profile-policy.toml", '"algorithm.sha512-t" = "0.24.26"', '"algorithm.sha512-t" = "0.24.24"'),
            ("security/cryptographic-api-profile-policy.toml", '"no-std", "cancellation"', '"no-std"'),
        )
        for path, old, new in cases:
            self.assertIn(old.encode(), original(policy.ROOT, path))
            def changed(root, name):
                data = original(root, name)
                return data.replace(old.encode(), new.encode(), 1) if name == path else data
            with self.subTest(path=path, old=old), patch.object(policy, "read", changed), self.assertRaises(ValueError):
                policy.validate()


def main() -> int:
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
