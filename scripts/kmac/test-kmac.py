#!/usr/bin/env python3
"""Reject representative regressions across the reviewed KMAC boundary."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import kmac_policy


ROOT = Path(__file__).resolve().parents[2]


def reject(label: str, path: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-kmac-{label}-") as directory:
        root = Path(directory)
        for source in kmac_policy.FILES:
            target = root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, target)
        reviewed = Path("scripts/kmac/kmac_reviewed_hashes.py")
        reviewed_target = root / reviewed
        reviewed_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / reviewed, reviewed_target)
        subject = root / path
        text = subject.read_text(encoding="utf-8")
        if old not in text:
            raise RuntimeError(f"broken KMAC fixture: {label}")
        subject.write_text(text.replace(old, new, 1), encoding="utf-8")
        try:
            kmac_policy.validate(root)
        except kmac_policy.KmacPolicyError:
            return
        raise RuntimeError(f"KMAC policy accepted regression: {label}")


def main() -> int:
    kmac_policy.validate(ROOT)
    reject("std", Path("crates/brynja-mac-kmac/src/lib.rs"), "#![no_std]", "extern crate std;")
    reject("unsafe", Path("crates/brynja-mac-kmac/src/output.rs"), "use brynja_core", "unsafe fn bypass() {}\nuse brynja_core")
    reject("domain-name", Path("crates/brynja-mac-kmac/src/backend.rs"), "b\"KMAC\"", "b\"RAW\"")
    reject("key-clear", Path("crates/brynja-mac-kmac/src/packer.rs"), "clear_owned_region(&mut self.pending)", "core::hint::black_box(&mut self.pending)")
    reject("key-length-clear", Path("crates/brynja-mac-kmac/src/packer.rs"), "clear_owned_region(&mut self.emitted)", "core::hint::black_box(&mut self.emitted)")
    reject("nested-owner-clear", Path("crates/brynja-mac-kmac/src/core_state.rs"), "drop(self.state.take())", "core::hint::black_box(self.state.take())")
    reject("constant-time", Path("crates/brynja-mac-kmac/src/output.rs"), "ct_eq", "ordinary_eq")
    reject("official-vector", Path("crates/brynja-mac-kmac/tests/official_vectors.rs"), "E5780B0D3EA6F7D3", "F5780B0D3EA6F7D3")
    reject("differential", Path("scripts/checks.sh"), "python3 scripts/kmac/check-kmac-differential.py", "true")
    reject("miri", Path("scripts/zeroization/check-zeroization-miri.sh"), "-p brynja-mac-kmac", "-p missing-kmac")
    reject(
        "sanitizer-targets",
        Path("scripts/zeroization/check-zeroization-sanitizer.sh"),
        "-p brynja-mac-kmac \\\n    --tests",
        "-p brynja-mac-kmac \\\n    --lib",
    )
    reject("dependency", Path("crates/brynja-mac-kmac/Cargo.toml"), "brynja-hash-sha3 = { workspace = true }", "foreign = \"1\"")
    print("KMAC policy rejects twelve ownership, algorithm, test, and dependency regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
