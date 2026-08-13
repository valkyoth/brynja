#!/usr/bin/env python3
"""Broken-fixture tests for the v0.20.0 DER-reader policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import der_reader_policy as policy


ROOT = Path(__file__).resolve().parents[1]


def replace(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(label: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-der-reader-") as temporary:
        root = Path(temporary)
        for relative in (*policy.SOURCES, policy.MANIFEST, policy.PACKAGE_POLICY):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        mutation(root)
        try:
            policy.validate(root)
        except policy.DerReaderPolicyError:
            return
        raise AssertionError(f"DER-reader fixture accepted: {label}")


def main() -> int:
    reject("unsafe", lambda root: replace(root, policy.READER, "pub fn next_event", "pub unsafe fn next_event"))
    reject("ffi", lambda root: replace(root, policy.DER, "mod tag;", 'extern "C" {}\nmod tag;'))
    reject("std", lambda root: replace(root, policy.ERROR, "pub enum", "use std::vec::Vec;\npub enum"))
    reject("alloc", lambda root: replace(root, policy.ERROR, "pub enum", "use alloc::vec::Vec;\npub enum"))
    reject("dynamic bytes", lambda root: replace(root, policy.ERROR, "pub enum", "type Dynamic = Vec<u8>;\npub enum"))
    reject("provider", lambda root: replace(root, policy.ERROR, "pub enum", "struct Provider;\npub enum"))
    reject("socket", lambda root: replace(root, policy.ERROR, "pub enum", "struct Socket;\npub enum"))
    reject("verification", lambda root: replace(root, policy.ERROR, "pub enum", "fn verify_signature() {}\npub enum"))
    reject("global state", lambda root: replace(root, policy.ERROR, "pub enum", "static mut STATE: u8 = 0;\npub enum"))
    reject("input limit", lambda root: replace(root, policy.LIMITS, "input_bytes: usize", "input_size: usize"))
    reject("depth limit", lambda root: replace(root, policy.LIMITS, "depth: usize", "nesting: usize"))
    reject("node limit", lambda root: replace(root, policy.LIMITS, "nodes: usize", "values: usize"))
    reject("child limit", lambda root: replace(root, policy.LIMITS, "children: usize", "child_count: usize"))
    reject("identifier limit", lambda root: replace(root, policy.LIMITS, "identifier_octets: usize", "identifier_bytes: usize"))
    reject("length limit", lambda root: replace(root, policy.LIMITS, "length_octets: usize", "length_bytes: usize"))
    reject("value limit", lambda root: replace(root, policy.LIMITS, "value_bytes: usize", "contents: usize"))
    reject("work limit", lambda root: replace(root, policy.LIMITS, "work: usize", "effort: usize"))
    reject("public limits", lambda root: replace(root, policy.LIMITS, "input_bytes: usize", "pub input_bytes: usize"))
    reject("recursive traversal", lambda root: replace(root, policy.READER, "pub fn next_event(&mut self)", "fn recursive(&mut self) { let _ = self.next_event(); }\npub fn next_event(&mut self)"))
    reject("unbounded stack", lambda root: replace(root, policy.READER, "frames: [Frame; STACK]", "frames: Vec<Frame>"))
    reject("indefinite length", lambda root: replace(root, policy.READER, "DerError::IndefiniteLength", "DerError::Truncated"))
    reject("nonminimal length", lambda root: replace(root, policy.READER, "DerError::NonMinimalLength", "DerError::Truncated"))
    reject("nonminimal tag", lambda root: replace(root, policy.READER, "DerError::NonMinimalTag", "DerError::Truncated"))
    reject("boundary", lambda root: replace(root, policy.READER, "DerError::BoundaryViolation", "DerError::Truncated"))
    reject("header boundary", lambda root: replace(root, policy.READER, "if position >= boundary", "if position > boundary"))
    reject("platform length", lambda root: replace(root, policy.READER, "count > core::mem::size_of::<usize>()", "count == usize::MAX"))
    reject("short long-form", lambda root: replace(root, policy.READER, "length < 128", "length < 1"))
    reject("payload error", lambda root: replace(root, policy.ERROR, "Truncated,", "Truncated { offset: usize },"))
    reject("dependency", lambda root: replace(root, policy.MANIFEST, "brynja-core = { workspace = true }", "brynja-core = { workspace = true }\nbrynja-crypto = { workspace = true }"))
    reject("package class", lambda root: replace(root, policy.PACKAGE_POLICY, '[packages.brynja-pki]\nclass = "modern-shared"', '[packages.brynja-pki]\nclass = "modern-engine"'))
    reject("oversized source", lambda root: (root / policy.READER).write_text((root / policy.READER).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.TAG, "Canonical DER tag identity", "DER tag identity"))
    reject("implementation claim", lambda root: replace(root, policy.LIB, "BOUNDED_DER_READER_IMPLEMENTED: bool = true", "BOUNDED_DER_READER_IMPLEMENTED: bool = false"))
    print("DER-reader policy rejects thirty-three allocation, recursion, canonicality, bound, package, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
