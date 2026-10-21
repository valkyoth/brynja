#!/usr/bin/env python3
"""Source-level inventory regressions; not a substitute for compiler tests."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import hmac_inventory as inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="brynja-hmac-inventory-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        paths = {target.split("#")[0] for target in inventory.OWNERS}
        paths |= {inventory.LEAF + name for name in (
            "lib.rs", "bits.rs", "algorithms.rs", "scratch.rs", "engine.rs", "execution/retained.rs")}
        paths |= {"crates/" + package + "/Cargo.toml" for _, package, _, _ in inventory.PROFILES}
        paths |= {name for _, name in inventory.EVIDENCE}
        paths.add("standards/protocol-surfaces.json")
        paths.add("security/cryptographic-api-profile-policy.toml")
        for name in paths:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(inventory.ROOT / name, target)

    def mutate(self, name, before, after):
        path = self.root / name
        original = path.read_text()
        self.assertEqual(original.count(before), 1)
        path.write_text(original.replace(before, after))
        try:
            with self.assertRaises((ValueError, inventory.rust.RustContractError)):
                inventory.validate(self.root)
        finally:
            path.write_text(original)

    def test_current_inventory_and_pending_claims(self):
        inventory.validate(self.root)
        text = inventory.render()
        self.assertEqual(len(inventory.OWNERS), 15)
        self.assertEqual(len(inventory.PROFILES), 10)
        for phrase in ("not compiler-qualified", "not dump exclusion",
                       "strict::hmac", "383 parameters", "direct-destructor model",
                       "768 campaigns", "not constant-time"):
            self.assertIn(phrase, text)
        for pending in inventory.PENDING:
            self.assertIn(pending, text)

    def test_every_named_owner_rejects_added_storage(self):
        for target in inventory.OWNERS:
            name, symbol = target.split("#")
            with self.subTest(target=target):
                path = self.root / name
                original = path.read_text()
                # Locate the exact declaration; do not mutate a doc example.
                start = original.index("struct " + symbol)
                opening = original.index("{", start)
                path.write_text(original[:opening + 1] + "\n    untracked: [u8; 32],"
                                + original[opening + 1:])
                try:
                    with self.assertRaises(inventory.rust.RustContractError):
                        inventory.validate(self.root)
                finally:
                    path.write_text(original)

    def test_methods_and_algorithms_cannot_disappear_or_expand(self):
        self.mutate(inventory.LEAF + "lib.rs", "pub fn cancel(", "pub fn reset(")
        self.mutate(inventory.LEAF + "bits.rs", "pub fn verify_bits(", "pub fn verify_any(")
        path = self.root / (inventory.LEAF + "algorithms.rs")
        original = path.read_text()
        path.write_text(original + "\nalgorithm!(Extra, Hidden, 64, 32, map, Bits);\n")
        with self.assertRaisesRegex(ValueError, "algorithm population"):
            inventory.validate(self.root)
        path.write_text(original)

    def test_scratch_size_cleanup_and_retained_storage(self):
        self.mutate(inventory.LEAF + "scratch.rs",
                    "let _ = clear_owned_region(&mut self.0);",
                    "// let _ = clear_owned_region(&mut self.0);\n")
        self.mutate(inventory.LEAF + "engine.rs", "Scratch::<144>", "Scratch::<145>")
        self.mutate(inventory.LEAF + "execution/retained.rs", "(Option<T>);", "(T);")
        for directory in ("strict_hmac", "macos_resident/hmac"):
            self.mutate(inventory.HOST + directory + "/mod.rs", "self.storage.clear();",
                        "// self.storage.clear();")

    def test_missing_features_and_default_on_reject(self):
        self.mutate("crates/brynja-mac-hmac/Cargo.toml", "default = []",
                    'default = ["hardened-execution"]')
        self.mutate("crates/brynja-mac-hmac/Cargo.toml", "runtime-execution =",
                    "lost-runtime-execution =")

    def test_missing_and_symlinked_inputs_reject(self):
        name = inventory.LEAF + "engine.rs"
        path = self.root / name
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(ValueError):
            inventory.validate(self.root)
        path.symlink_to(inventory.ROOT / name)
        with self.assertRaises(ValueError):
            inventory.validate(self.root)
        path.unlink()
        path.write_bytes(original)
        (self.root / inventory.EVIDENCE[0][1]).unlink()
        with self.assertRaisesRegex(ValueError, "missing check"):
            inventory.validate(self.root)

    def test_global_registration_is_not_silently_dropped(self):
        path = self.root / "standards/protocol-surfaces.json"
        document = json.loads(path.read_text())
        for row in document["surfaces"]:
            if row["id"] == "algorithm.hmac":
                row["disposition"] = "future-work"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "implementation inventory"):
            inventory.validate(self.root)

    def test_global_registration_cannot_claim_qualification(self):
        self.mutate("security/cryptographic-api-profile-policy.toml",
                    'qualification = "native-release-reconciliation-and-independent-review-pending"',
                    'qualification = "fully-qualified"')

    def test_comments_cannot_supply_a_missing_method(self):
        self.mutate(inventory.LEAF + "lib.rs", "pub fn cancel(self) {}",
                    "// pub fn cancel(self) {}\n")

    def test_normative_links_cannot_disappear(self):
        path = self.root / "standards/protocol-surfaces.json"
        document = json.loads(path.read_text())
        for row in document["surfaces"]:
            if row["id"] == "algorithm.hmac":
                row["normative_sources"] = ["rfc:2104"]
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "requirement sources"):
            inventory.validate(self.root)


if __name__ == "__main__":
    unittest.main()
