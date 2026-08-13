#!/usr/bin/env python3
"""Validate the reviewed v0.18.1 observational security-event schema."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


MODULE = Path("crates/brynja-core/src/security_event.rs")
EVENT = Path("crates/brynja-core/src/security_event/event.rs")
RECORD = Path("crates/brynja-core/src/security_event/record.rs")
QUEUE = Path("crates/brynja-core/src/security_event/queue.rs")
LIB = Path("crates/brynja-core/src/lib.rs")
SOURCES = (MODULE, EVENT, RECORD, QUEUE)
EXPECTED_SHA256 = {
    MODULE: "6ac55444550481d170c0f7ffe95cb1e2384082a848f15a7c56a58db15381df00",
    EVENT: "3cbe6824df95ab13e78e314e3c955dd3baacc0af75e722f9a75152a272924490",
    RECORD: "775967f0c9f9227f78584aacb41f873bda8a2b01a0ee40886ba18bf6f8fa3443",
    QUEUE: "af6a4058dbfc23f1c74da6f977e29da362ca769aac9aa6ae4b9f096e7e6c6d67",
}


class SecurityEventPolicyError(RuntimeError):
    """The reviewed observational event boundary differs from policy."""


def fail(message: str) -> None:
    raise SecurityEventPolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"security-event source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"security-event source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def require(code: str, token: str, label: str) -> None:
    if token not in code:
        fail(f"{label} drift: {token}")


def validate_structure(root: Path, sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "String",
        "Vec<",
        "Box<",
        "[u8",
        "Alert",
        "ProviderHandle",
        "SecurityResolution",
        "SecurityReceipt",
        "&mut SecurityAuthority",
        "FnMut",
        "dyn ",
        "static mut",
        "Atomic",
        "thread_local",
    ):
        if forbidden in all_code:
            fail(f"security-event schema crossed forbidden boundary: {forbidden}")

    event = sources[EVENT][1]
    for required in (
        "pub enum SecurityEventKind",
        "Pending,",
        "Accepted,",
        "Approved,",
        "NonApproved,",
        "Rejected,",
        "Canceled,",
        "Failed,",
        "Terminal,",
        "pub struct SecurityEvent",
        "kind: SecurityEventKind",
        "decision: Option<SecurityDecisionKind>",
        "disposition: Option<SecurityDisposition>",
        "terminal: Option<SecurityTerminal>",
        "pub const fn from_pending",
        "pub const fn from_accepted",
        "pub const fn from_approved",
        "pub const fn from_non_approved",
        "pub const fn from_rejected",
        "pub const fn from_canceled",
        "pub const fn from_failed",
        "pub const fn from_snapshot",
        "SecurityAuthorityState::Ready => None",
        "SecurityAuthorityState::Pending(decision)",
        "SecurityAuthorityState::AwaitingCommit",
        "SecurityAuthorityState::Terminal",
    ):
        require(event, required, "security-event mapping")
    if re.search(r"pub\s+(?:kind|decision|disposition|terminal):", event):
        fail("security-event construction fields became public")
    if re.search(r"pub (?:const )?fn (?:new|outcome)\(", event):
        fail("security-event gained an unbound public constructor")
    if "generation" in event:
        fail("security-event gained a stable generation identifier")

    record = sources[RECORD][1]
    for required in (
        "pub enum SecurityEventTimestamp",
        "Untimestamped,",
        "Wall(WallTime)",
        "Monotonic(MonotonicInstant)",
        "pub struct SecurityEventRecord",
        "pub const fn untimestamped",
        "pub fn enrich(",
        "SecurityEventTimestampError::AlreadyTimestamped",
        "SecurityEventTimestampError::UntimestampedInput",
    ):
        require(record, required, "security-event timestamp")
    if re.search(r"pub\s+(?:event|timestamp):", record):
        fail("security-event record fields became public")

    queue = sources[QUEUE][1]
    for required in (
        "pub enum SecurityEventPush",
        "Stored,",
        "Dropped,",
        "pub struct SecurityEventDropCount",
        "self.count.checked_add(1)",
        "None => self.saturated = true",
        "pub const fn is_saturated",
        "pub struct SecurityEventQueue<const CAPACITY: usize>",
        "entries: [Option<SecurityEventRecord>; CAPACITY]",
        "pub fn push(&mut self, record: SecurityEventRecord)",
        "if self.len == CAPACITY",
        "self.dropped.record()",
        "pub fn pop(&mut self)",
        "self.entries.get(self.head).copied().flatten()",
        "pub const fn snapshot(&self)",
    ):
        require(queue, required, "bounded security-event queue")
    if re.search(r"pub\s+(?:entries|head|len|dropped):", queue):
        fail("security-event queue state became public")
    if "wrapping_add" in queue:
        fail("security-event loss accounting can wrap")

    library = (root / LIB).read_text(encoding="utf-8")
    for required in (
        "pub mod security_event;",
        "SecurityEventQueue",
        "pub const SECURITY_EVENT_SCHEMA_IMPLEMENTED: bool = true;",
    ):
        require(library, required, "security-event public boundary")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"security-event reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(root, sources)
    validate_hashes(sources)
