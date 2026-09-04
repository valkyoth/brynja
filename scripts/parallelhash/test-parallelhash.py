#!/usr/bin/env python3
"""Reject representative ParallelHash boundary regressions."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import parallelhash_policy


ROOT = Path(__file__).resolve().parents[2]


def reject(label: str, path: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-parallelhash-{label}-") as directory:
        root = Path(directory)
        for source in parallelhash_policy.FILES:
            target = root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, target)
        hashes = Path("scripts/parallelhash/parallelhash_reviewed_hashes.py")
        target = root / hashes
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / hashes, target)
        subject = root / path
        text = subject.read_text(encoding="utf-8")
        if old not in text:
            raise RuntimeError(f"broken ParallelHash fixture: {label}")
        subject.write_text(text.replace(old, new, 1), encoding="utf-8")
        try:
            parallelhash_policy.validate(root)
        except parallelhash_policy.ParallelHashPolicyError:
            return
        raise RuntimeError(f"ParallelHash policy accepted regression: {label}")


def main() -> int:
    parallelhash_policy.validate(ROOT)
    reject("std", Path("crates/brynja-hash-parallel/src/lib.rs"), "#![no_std]", "extern crate std;")
    reject("unsafe", Path("crates/brynja-hash-parallel/src/backend.rs"), "use brynja_hash_sha3", "unsafe fn bypass() {}\nuse brynja_hash_sha3")
    reject("domain", Path("crates/brynja-hash-parallel/src/backend.rs"), 'b"ParallelHash"', 'b"RawHash"')
    reject("block-encoding", Path("crates/brynja-hash-parallel/src/core_state.rs"), "left_encode_u128", "right_encode_u128")
    reject("leaf-order", Path("crates/brynja-hash-parallel/src/scheduled.rs"), "ParallelHashError::LeafOrder", "ParallelHashError::StateConsumed")
    reject("plan-identity", Path("crates/brynja-hash-parallel/src/scheduled.rs"), "core::ptr::eq(identity, self.identity)", "core::ptr::eq(identity, identity)")
    reject("cleanup", Path("crates/brynja-hash-parallel/src/core_state.rs"), "clear_owned_region", "core::hint::black_box")
    reject("executor-bound", Path("crates/brynja-hash-parallel-std/src/worker.rs"), "try_reserve_exact", "reserve_exact")
    reject("executor-cleanup", Path("crates/brynja-hash-parallel-std/src/worker.rs"), "clear_owned_region(leaf)", "core::hint::black_box(leaf)")
    reject("executor-spawn", Path("crates/brynja-hash-parallel-std/src/worker.rs"), "thread::Builder::new().spawn_scoped", "scope.spawn")
    reject("executor-work-limit", Path("crates/brynja-hash-parallel-std/src/worker.rs"), "let slots = leaves.min(workers)", "let slots = leaves")
    reject("executor-operation-gate", Path("crates/brynja-hash-parallel-std/src/lib.rs"), "let _operation = self.enter_operation()?;", "let _operation = Ok::<(), ParallelHashExecutorError>(())?;")
    reject("official", Path("crates/brynja-hash-parallel/tests/official_vectors.rs"), "all_six_official_fixed_examples_match", "removed_official_examples")
    reject("differential", Path("scripts/checks.sh"), "scripts/parallelhash/check-parallelhash-differential.py", "removed-parallelhash-differential")
    reject("miri", Path("scripts/zeroization/check-zeroization-miri.sh"), "-p brynja-hash-parallel", "-p missing-parallelhash")
    reject("sanitizer", Path("scripts/zeroization/check-zeroization-sanitizer.sh"), "-p brynja-hash-parallel-std", "-p missing-parallelhash-std")
    reject("proof", Path("scripts/assurance/check-kani.sh"), "cargo kani -p brynja-hash-parallel", "cargo kani -p missing-parallelhash")
    reject("dependency", Path("crates/brynja-hash-parallel/Cargo.toml"), "brynja-hash-sha3 = { workspace = true }", 'foreign = "1"')
    print("ParallelHash policy rejects eighteen domain, encoding, lifecycle, cleanup, scheduling, evidence, test, and dependency regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
