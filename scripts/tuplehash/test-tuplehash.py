#!/usr/bin/env python3
"""Reject representative regressions across the TupleHash boundary."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import tuplehash_policy


ROOT = Path(__file__).resolve().parents[2]


def reject(label: str, path: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-tuplehash-{label}-") as directory:
        root = Path(directory)
        for source in tuplehash_policy.FILES:
            target = root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, target)
        reviewed = Path("scripts/tuplehash/tuplehash_reviewed_hashes.py")
        target = root / reviewed
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / reviewed, target)
        subject = root / path
        text = subject.read_text(encoding="utf-8")
        if old not in text:
            raise RuntimeError(f"broken TupleHash fixture: {label}")
        subject.write_text(text.replace(old, new, 1), encoding="utf-8")
        try:
            tuplehash_policy.validate(root)
        except tuplehash_policy.TupleHashPolicyError:
            return
        raise RuntimeError(f"TupleHash policy accepted regression: {label}")


def main() -> int:
    tuplehash_policy.validate(ROOT)
    reject("std", Path("crates/brynja-hash-tuple/src/lib.rs"), "#![no_std]", "extern crate std;")
    reject("unsafe", Path("crates/brynja-hash-tuple/src/output.rs"), "use brynja_hash_sha3", "unsafe fn bypass() {}\nuse brynja_hash_sha3")
    reject("domain", Path("crates/brynja-hash-tuple/src/backend.rs"), 'b"TupleHash"', 'b"RawHash"')
    reject("item-prefix", Path("crates/brynja-hash-tuple/src/core_state.rs"), "left_encode_u128(bits)", "right_encode_u128(bits)")
    reject("fixed-trailer", Path("crates/brynja-hash-tuple/src/core_state.rs"), "right_encode_u128(output_bits)", "left_encode_u128(output_bits)")
    reject("abandon", Path("crates/brynja-hash-tuple/src/item.rs"), "self.core.abandon_item();", "core::hint::black_box(&mut self.core);")
    reject("cleanup", Path("crates/brynja-hash-tuple/src/core_state.rs"), "clear_owned_region(&mut self.pending)", "core::hint::black_box(&mut self.pending)")
    reject("official", Path("crates/brynja-hash-tuple/tests/official_vectors.rs"), "C5D8786C1AFB9B82", "D5D8786C1AFB9B82")
    reject("differential", Path("scripts/checks.sh"), "python3 scripts/tuplehash/check-tuplehash-differential.py", "true # removed")
    reject("miri", Path("scripts/zeroization/check-zeroization-miri.sh"), "-p brynja-hash-tuple", "-p missing-tuplehash")
    reject("sanitizer", Path("scripts/zeroization/check-zeroization-sanitizer.sh"), "-p brynja-hash-tuple", "-p missing-tuplehash")
    reject("facade-bit-xof", Path("crates/brynja-crypto/src/lib.rs"), "tuple_hash_xof128_bits", "removed_bit_xof")
    reject("dependency", Path("crates/brynja-hash-tuple/Cargo.toml"), "brynja-hash-sha3 = { workspace = true }", 'foreign = "1"')
    print("TupleHash policy rejects thirteen encoding, lifecycle, cleanup, API, test, and dependency regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
