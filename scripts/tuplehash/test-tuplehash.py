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
    reject("item-prefix", Path("crates/brynja-hash-tuple/src/core_state.rs"), "prefix.left(bits)", "prefix.right(bits)")
    reject("borrowed-fragment", Path("crates/brynja-hash-tuple/src/core_state.rs"), "byte: &u8, valid: u8", "byte: u8, valid: u8")
    reject("fragment-insertion", Path("crates/brynja-hash-tuple/src/core_state.rs"), "brynja_core::xor_secret_byte_bits(pending, byte, position, 1, used)", "Ok::<(), brynja_core::SecretBitRangeError>(())")
    reject("fixed-trailer", Path("crates/brynja-hash-tuple/src/core_state.rs"), "suffix.right(output_bits)", "suffix.left(output_bits)")
    reject("reader-borrow", Path("crates/brynja-hash-tuple/src/backend.rs"), "backend: &'a mut Backend", "backend: Backend")
    reject("in-place-transition", Path("crates/brynja-hash-tuple/src/backend.rs"), "state.enter_squeezing_in_place(tail)?", "state.finalize_xof_erasing_source()?")
    reject("reader-erasure", Path("crates/brynja-hash-tuple/src/backend.rs"), "squeeze_final_bits_secret_in_place", "squeeze_final_bits_secret")
    reject("reader-drop", Path("crates/brynja-hash-tuple/src/backend.rs"), "self.backend.wipe();", "core::hint::black_box(&mut self.backend);")
    reject("core-in-place", Path("crates/brynja-hash-tuple/src/core_state.rs"), "self.backend.finalize_in_place(None)?", "self.backend.finalize(None)?")
    reject("fixed-borrow", Path("crates/brynja-hash-tuple/src/fixed.rs"), "pub fn finalize(&mut self", "pub fn finalize(mut self")
    reject("xof-borrow", Path("crates/brynja-hash-tuple/src/xof.rs"), "pub fn finalize_xof(&mut self)", "pub fn finalize_xof(mut self)")
    reject("codegen-owner-copy", Path("scripts/tuplehash/check-tuplehash-codegen.sh"), "reject_secret_copy", "accept_secret_copy")
    reject("codegen-matcher-self-test", Path("scripts/tuplehash/check-tuplehash-codegen.sh"), "self_test_secret_copy_matcher", "skip_secret_copy_matcher_test")
    reject("codegen-any-memcpy", Path("scripts/tuplehash/check-tuplehash-codegen.sh"), "reject_any_memcpy", "allow_any_memcpy")
    reject("codegen-encoding-borrow", Path("scripts/tuplehash/check-tuplehash-codegen.sh"), "borrowed encoding writer result", "omitted encoding writer check")
    reject("codegen-external", Path("scripts/tuplehash/check-tuplehash-codegen.sh"), "assurance/tuplehash-public-api/Cargo.toml", "assurance/missing/Cargo.toml")
    reject("open-latch", Path("crates/brynja-hash-tuple/src/core_state.rs"), "self.failed = [1];", "self.failed = [0];")
    reject("complete-latch", Path("crates/brynja-hash-tuple/src/item.rs"), "self.core.complete_item()?;", "self.core.check_item_fragment(0)?;")
    reject("remaining-owner", Path("crates/brynja-hash-tuple/src/core_state.rs"), "clear_owned_region(&mut self.remaining)", "core::hint::black_box(&mut self.remaining)")
    reject("remaining-staging", Path("crates/brynja-hash-tuple/src/core_state.rs"), "write_u128(&mut self.remaining, bits)", "self.remaining.copy_from_slice(&bits.to_le_bytes())")
    reject("encoded-length", Path("crates/brynja-hash-tuple/src/secret_encoding.rs"), "clear_owned_region(&mut self.bytes)", "core::hint::black_box(&mut self.bytes)")
    reject("partial-owner", Path("crates/brynja-hash-tuple/src/core_state.rs"), "Fips202BitString::new(&self.pending, valid)", "Fips202BitString::new(&[self.pending[0]], valid)")
    reject("production-proof", Path("crates/brynja-hash-tuple/src/lib.rs"), "checked_remaining_after(remaining, fragment)", "remaining.checked_sub(fragment).ok_or(TupleHashError::MessageTooLong)")
    reject("abandon", Path("crates/brynja-hash-tuple/src/item.rs"), "self.core.abandon_item();", "core::hint::black_box(&mut self.core);")
    reject("cleanup", Path("crates/brynja-hash-tuple/src/core_state.rs"), "clear_owned_region(&mut self.pending)", "core::hint::black_box(&mut self.pending)")
    reject("finalized-item-count", Path("crates/brynja-hash-tuple/tests/api.rs"), "assert_eq!(whole.item_count(), 0);", "assert_eq!(whole.item_count(), 1);")
    reject("official", Path("crates/brynja-hash-tuple/tests/official_vectors.rs"), "C5D8786C1AFB9B82", "D5D8786C1AFB9B82")
    reject("differential", Path("scripts/checks.sh"), "python3 scripts/tuplehash/check-tuplehash-differential.py", "true # removed")
    reject("miri", Path("scripts/zeroization/check-zeroization-miri.sh"), "-p brynja-hash-tuple", "-p missing-tuplehash")
    reject("miri-latch", Path("scripts/zeroization/check-zeroization-miri.sh"), "forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch", "missing_latch_test")
    reject("sanitizer", Path("scripts/zeroization/check-zeroization-sanitizer.sh"), "-p brynja-hash-tuple", "-p missing-tuplehash")
    reject("sanitizer-latch", Path("scripts/zeroization/check-zeroization-sanitizer.sh"), "forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch", "missing_latch_test")
    reject("facade-bit-xof", Path("crates/brynja-crypto/src/lib.rs"), "tuple_hash_xof128_bits", "removed_bit_xof")
    reject("dependency", Path("crates/brynja-hash-tuple/Cargo.toml"), "brynja-hash-sha3 = { workspace = true }", 'foreign = "1"')
    encoding = (ROOT / "crates/brynja-hash-tuple/src/secret_encoding.rs").read_text()
    # Exercise the semantic rule itself, independent of source hash rejection.
    for old, new in (
        ("fn left(&mut self,", "fn left(self,"),
        ("fn right(&mut self,", "fn right(self,"),
        ("self.reset();", ""),
        ("if !(2..=17).contains(&length)", "if length > 17"),
        ("Result<(), TupleHashError>", "Result<Self, TupleHashError>"),
    ):
        if old not in encoding:
            raise RuntimeError("missing borrowed encoding mutation target")
        try:
            tuplehash_policy.validate_encoding(encoding.replace(old, new, 1))
        except tuplehash_policy.TupleHashPolicyError:
            continue
        raise RuntimeError("accepted borrowed encoding regression: " + old)
    print("TupleHash policy rejects forty-two encoding, lifecycle, cleanup, API, proof, dynamic-analysis, code-generation, test, and dependency regressions")
    loaded = {path: tuplehash_policy.read(ROOT, path) for path in tuplehash_policy.FILES}
    mutations = [(tuplehash_policy.CRATE / 'src' / name, token)
                 for name, tokens in tuplehash_policy.SCOPED_TOKENS.items() for token in tokens]
    mutations += [(tuplehash_policy.CRATE / 'src/hardened_in_place/core_state.rs', f'clear_owned_region(&mut self.{field})')
                  for field in ('pending', 'used', 'items', 'remaining', 'input_bits', 'phase', 'staging')]
    for path, token in mutations:
        if token not in loaded[path]:
            raise RuntimeError('missing scoped mutation target: ' + token)
        mutant = dict(loaded)
        mutant[path] = loaded[path].replace(token, 'REMOVED')
        try:
            tuplehash_policy.validate_scoped(mutant)
        except tuplehash_policy.TupleHashPolicyError:
            continue
        raise RuntimeError('accepted scoped ownership/encoding regression: ' + token)
    print(f'Scoped TupleHash policy rejects {len(mutations)} semantic regressions')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
