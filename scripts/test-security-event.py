#!/usr/bin/env python3
"""Broken-fixture tests for the v0.18.1 security-event policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import security_event_policy as policy


ROOT = Path(__file__).resolve().parents[1]


def replace(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(label: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-security-event-") as temporary:
        root = Path(temporary)
        for relative in (*policy.SOURCES, policy.LIB):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        mutation(root)
        try:
            policy.validate(root)
        except policy.SecurityEventPolicyError:
            return
        raise AssertionError(f"security-event fixture accepted: {label}")


def main() -> int:
    reject("unsafe", lambda root: replace(root, policy.QUEUE, "pub fn pop", "unsafe pub fn pop"))
    reject("ffi", lambda root: replace(root, policy.MODULE, "mod event;", 'extern "C" {}\nmod event;'))
    reject("std", lambda root: replace(root, policy.RECORD, "use crate", "use std::vec::Vec;\nuse crate"))
    reject("alloc", lambda root: replace(root, policy.RECORD, "use crate", "use alloc::vec::Vec;\nuse crate"))
    reject("string", lambda root: replace(root, policy.EVENT, "kind: SecurityEventKind", "message: String,\n    kind: SecurityEventKind"))
    reject("bytes", lambda root: replace(root, policy.EVENT, "kind: SecurityEventKind", "payload: [u8; 32],\n    kind: SecurityEventKind"))
    reject("alert", lambda root: replace(root, policy.EVENT, "use crate::{", "use crate::Alert;\nuse crate::{"))
    reject("provider handle", lambda root: replace(root, policy.EVENT, "use crate::{", "use crate::ProviderHandle;\nuse crate::{"))
    reject("authoritative resolution", lambda root: replace(root, policy.EVENT, "use crate::{", "use crate::SecurityResolution;\nuse crate::{"))
    reject("mutable authority", lambda root: replace(root, policy.EVENT, "impl SecurityEvent {", "fn alter(_: &mut SecurityAuthority) {}\nimpl SecurityEvent {"))
    reject("callback", lambda root: replace(root, policy.QUEUE, "impl<const CAPACITY", "fn callback(_: impl FnMut()) {}\nimpl<const CAPACITY"))
    reject("public fields", lambda root: replace(root, policy.EVENT, "kind: SecurityEventKind", "pub kind: SecurityEventKind"))
    reject("public constructor", lambda root: replace(root, policy.EVENT, "const fn outcome", "pub const fn outcome"))
    reject("generation id", lambda root: replace(root, policy.EVENT, "kind: SecurityEventKind", "generation: u64,\n    kind: SecurityEventKind"))
    reject("timestamp fields", lambda root: replace(root, policy.RECORD, "event: SecurityEvent", "pub event: SecurityEvent"))
    reject("queue fields", lambda root: replace(root, policy.QUEUE, "head: usize", "pub head: usize"))
    reject("wrapping drops", lambda root: replace(root, policy.QUEUE, "self.count.checked_add(1)", "self.count.wrapping_add(1)"))
    reject("lost saturation", lambda root: replace(root, policy.QUEUE, "None => self.saturated = true", "None => {}"))
    reject("unbounded source", lambda root: (root / policy.EVENT).write_text((root / policy.EVENT).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.EVENT, "Closed class", "Closed category"))
    reject("module export", lambda root: replace(root, policy.LIB, "pub mod security_event;", "mod security_event;"))
    reject("completion flag", lambda root: replace(root, policy.LIB, "SECURITY_EVENT_SCHEMA_IMPLEMENTED: bool = true", "SECURITY_EVENT_SCHEMA_IMPLEMENTED: bool = false"))
    print("security-event policy rejects twenty-two authority, payload, queue, timestamp, boundary, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

