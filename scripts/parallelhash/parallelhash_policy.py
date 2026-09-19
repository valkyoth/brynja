#!/usr/bin/env python3
"""Validate the complete ParallelHash/ParallelHashXOF boundary."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import parallelhash_reviewed_hashes

PORTABLE = Path("crates/brynja-hash-parallel")
STD = Path("crates/brynja-hash-parallel-std")
SOURCES = tuple(PORTABLE / "src" / name for name in (
    "backend.rs", "core_state.rs", "error.rs", "fixed.rs", "lib.rs",
    "output.rs", "scheduled.rs", "xof.rs", "secret_encoding.rs",
    "secret_encoding/tests.rs", "backend/tests.rs",
    "hardened_in_place.rs", "hardened_in_place/backend.rs", "hardened_in_place/core_state.rs",
    "hardened_in_place/fixed.rs", "hardened_in_place/tests.rs", "hardened_in_place/core_state/tests.rs",
    "hardened_in_place/reader.rs", "hardened_in_place/reader/tests.rs",
    "hardened_in_place/xof.rs", "hardened_in_place/xof/tests.rs",
    "hardened_in_place/accelerated.rs", "hardened_in_place/accelerated/backend.rs", "hardened_in_place/accelerated/fixed.rs",
    "hardened_in_place/accelerated/xof.rs",
    "hardened_in_place/scheduled.rs", "hardened_in_place/scheduled/tests.rs",
    "hardened_in_place/scheduled_core.rs", "hardened_in_place/scheduled_core/tests.rs",
    "hardened_in_place/accelerated/scheduled.rs", "hardened_in_place/accelerated/scheduled_leaf.rs",
    "hardened_in_place/accelerated/scheduled_backend.rs",
))
STD_SOURCES = tuple(STD / "src" / name for name in (
    "lib.rs", "worker.rs", "in_place.rs", "scoped_worker.rs", "scoped_worker/tests.rs",
))
EXECUTION = tuple(PORTABLE / "src/execution" / name for name in (
    "batch.rs", "batch/tests.rs", "collector/batch.rs",
    "batch/transfer.rs", "batch/transfer/tests.rs",
    "batch/scoped.rs", "batch/scoped/tests.rs", "batch/scoped/tests/handoff.rs",
    "stream/batch.rs", "stream/batch/output.rs", "stream/batch/tests.rs", "stream/batch/failures.rs",
    "backend.rs", "binding.rs", "collector.rs", "collector/tests.rs", "encoding.rs", "mod.rs",
    "ownership.rs", "plan.rs", "stream.rs", "stream_output.rs", "stream/tests.rs",
))
STD_EXECUTION = tuple(STD / "src/execution" / name for name in (
    "mod.rs", "selection.rs", "worker.rs", "tests.rs", "worker/tests.rs",
    "batch.rs", "batch/selection.rs", "batch/worker.rs", "batch/tests.rs", "batch/worker/tests.rs",
    "batch/worker/tests/coordinator_unwind.rs",
    "batch/in_place.rs", "batch/in_place/tests.rs", "batch/in_place/worker.rs",
    "batch/in_place/worker/tests.rs", "batch/in_place/worker/tests/order.rs",
    "in_place.rs", "in_place/tests.rs", "in_place/worker.rs", "in_place/worker/tests.rs",
))
TESTS = (
    PORTABLE / "tests/api.rs", PORTABLE / "tests/official_vectors.rs",
    STD / "tests/executor.rs",
    STD / "tests/scoped.rs",
    STD / "tests/scoped_execution.rs",
    PORTABLE / "tests/execution.rs", PORTABLE / "tests/execution_vectors/mod.rs",
    PORTABLE / "tests/execution_stream.rs",
    STD / "tests/execution.rs",
    PORTABLE / "tests/scoped_accelerated.rs",
    PORTABLE / "tests/scoped_accelerated/xof.rs", PORTABLE / "tests/scoped_accelerated/xof_lifecycle.rs",
    PORTABLE / "tests/scoped_scheduled.rs",
    PORTABLE / "tests/scoped_accelerated/scheduled.rs", PORTABLE / "tests/scoped_accelerated/scheduled_lifecycle.rs",
)
MANIFESTS = (PORTABLE / "Cargo.toml", STD / "Cargo.toml")
PUBLIC = (
    Path("assurance/parallelhash-public-api/Cargo.toml"),
    Path("assurance/parallelhash-public-api/src/lib.rs"),
    Path("assurance/parallelhash-std-public-api/Cargo.toml"),
    Path("assurance/parallelhash-std-public-api/src/lib.rs"),
)
DIFFERENTIAL = (
    Path("assurance/parallelhash-differential/Cargo.toml"),
    Path("assurance/parallelhash-differential/src/main.rs"),
    Path("scripts/parallelhash/check-parallelhash-differential.py"),
    Path("assurance/parallelhash-differential/src/execution.rs"),
    Path("assurance/parallelhash-differential/src/lib.rs"),
    PORTABLE / "README.md", STD / "README.md",
    Path("scripts/parallelhash/check-parallelhash-execution-differential.py"),
    Path("scripts/parallelhash/check-parallelhash-execution-package.py"),
    Path("scripts/parallelhash/check-parallelhash-execution-codegen.py"),
    Path("scripts/parallelhash/parallelhash_cleanup.py"),
    Path("scripts/parallelhash/parallelhash_execution_native.py"),
    Path("scripts/parallelhash/capture-parallelhash-execution-native.py"),
    Path("scripts/parallelhash/check-parallelhash-execution-native.py"),
    Path("scripts/parallelhash/test-parallelhash-execution-native.py"),
    Path("scripts/parallelhash/test-parallelhash-batch.py"),
    Path("assurance/parallelhash-differential/src/scoped.rs"),
    Path("assurance/parallelhash-differential/tests/scoped.rs"),
    Path("assurance/parallelhash-differential/src/scoped_accelerated.rs"),
    Path("assurance/parallelhash-differential/src/scoped_scheduled.rs"),
    Path("assurance/parallelhash-differential/src/scoped_scheduled_accelerated.rs"),
    Path("assurance/parallelhash-differential/src/scoped_threaded.rs"),
    Path("assurance/parallelhash-differential/src/scoped_execution.rs"),
    Path("assurance/parallelhash-batch-oracle/src/scoped.rs"),
    Path("assurance/parallelhash-batch-oracle/src/main.rs"),
)
SUPPORT = (
    Path("crates/brynja-crypto/src/lib.rs"), Path("crates/brynja/src/lib.rs"),
    Path("package-policy.toml"), Path("scripts/checks.sh"),
    Path("scripts/zeroization/check-zeroization-miri.sh"),
    Path("scripts/zeroization/check-zeroization-sanitizer.sh"),
    Path("scripts/assurance/check-kani.sh"),
)
OWNER_INVENTORY = Path("docs/parallelhash-execution.md")
FILES = (*SOURCES, *STD_SOURCES, *EXECUTION, *STD_EXECUTION, *TESTS, *MANIFESTS, *PUBLIC, *DIFFERENTIAL, *SUPPORT, OWNER_INVENTORY)
HASHED = (*SOURCES, *STD_SOURCES, *EXECUTION, *STD_EXECUTION, *TESTS, *MANIFESTS, *PUBLIC, *DIFFERENTIAL)
HASHES = {Path(path): digest for path, digest in parallelhash_reviewed_hashes.REVIEWED_HASHES.items()}

class ParallelHashPolicyError(RuntimeError):
    """The reviewed ParallelHash boundary differs from policy."""

def fail(message: str) -> None:
    raise ParallelHashPolicyError(message)

def read(root: Path, path: Path) -> str:
    subject = root / path
    if not subject.is_file() or subject.is_symlink():
        fail(f"ParallelHash boundary must be a regular file: {path}")
    text = subject.read_text(encoding="utf-8")
    if path.suffix in {".rs", ".py"} and len(text.splitlines()) > 500:
        fail(f"ParallelHash boundary exceeds 500 lines: {path}")
    return text

def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")

BORROWED_TOKENS = {
    "execution/batch/scoped.rs": (
        "struct Output<'out>(&'out mut [[u8; 64]; CAPACITY])", "impl Drop for Output<'_>",
        "clear_owned_region(self.0.as_flattened_mut())", "clear_owned_region(output.0.as_flattened_mut())",
        "struct Scratch<'a>(&'a mut Workspace)", "self.0.clear()", "let scratch = Scratch(workspace)",
        "executor.kernel()?", "self.plan.job(index).map_err(plan_error)?.batch_input()",
        "executor.digest_secret(&inputs, destinations,", "destination.copy_from_slice(source)",
        "report.accelerated_slots & !active != 0", "executor.quarantine()",
        "!core::ptr::eq(plan, self.plan)", "merge(Err(ParallelHashError::LeafIdentity), &[])",
        "merge(index, &bytes[..$width])?", "Output<'out>", "PhantomData<Cell<()>>",
    ),
    "hardened_in_place/accelerated/scheduled.rs": (
        "sponge: api::$storage<'authority>, count: Count, stage: [u8;168]",
        "api::$storage::new(session)?", "self.sponge.report()", "let guard = CountGuard(count)",
        "let scratch = Block(scratch)", "Scheduled { state, scratch: &mut *scratch.0 }",
        "impl for<'scope> FnOnce($collector<'scope, 'plan, 'input, 'authority>) -> R",
        'sponge.with_bits(byte_string(b"ParallelHash")?', "plan.block_size(), plan.leaf_count()",
        "self.inner.merge(self.plan.checked_index(&result), result.expose())",
        "pub fn merge(&mut self, result: crate::$result<'plan, '_>)",
        "self.inner.public(output, valid)", "self.inner.secret(output, valid)", "Output::new(self.inner.xof()?)",
    ),
    "hardened_in_place/accelerated/scheduled_leaf.rs": (
        "sponge: api::$storage<'authority>", "api::$storage::new(session)?", "self.sponge.report()",
        "clear_owned_region(output)", "job.execute_with(output,", "state.finalize_bits_xof(input)?.squeeze_secret(output)",
    ),
    "hardened_in_place/accelerated/scheduled_backend.rs": (
        "self.state.update(&[])", "self.state.update(input)", "self.check()?",
        "Output::new(self.state.finalize_xof()?, self.scratch)", "clear_owned_region(output)", "Err(Error::StateConsumed)",
    ),
    "hardened_in_place/scheduled.rs": (
        "sponge: api::$storage, count: Count", "let guard = CountGuard(&mut self.count);",
        "impl for<'scope> FnOnce($collector<'scope, 'plan, 'input>) -> R",
        'self.sponge.with_bits(byte_string(b"ParallelHash")?', "plan.block_size(), plan.leaf_count()",
        "plan: &'plan crate::$plan<'input>", "self.inner.merge(self.plan.checked_index(&result), result.expose())",
        "pub fn merge(&mut self, result: crate::$result<'plan, '_>)",
        "self.inner.public(output, valid)", "self.inner.secret(output, valid)", "Output::new(self.inner.xof()?)",
    ),
    "hardened_in_place/scheduled_core.rs": (
        "count: &'scope mut Count", "state: Option<S>", "merged: [u8; 16]", "clear_owned_region(&mut self.merged)",
        "impl Drop for CountGuard<'_>", "self.0.wipe()", "self.count.wipe()", "self.state = None",
        "if !self.complete {", "self.collector.cancel()", "guard.collector.root()?.check()?",
        "index != read(&guard.collector.count.merged) || index >= guard.collector.expected",
        "index.checked_add(1)", "write(&mut guard.collector.count.merged, next)?",
        "read(&self.count.merged) != self.expected", "suffix.right(self.expected)?", "suffix.right(bits)?",
        "prefix.left(u128::try_from(block)", "clear_owned_region(output)", "self.finish(0)",
    ),
    "hardened_in_place/accelerated/xof.rs": (
        "inner: fixed::$fixed_workspace<'authority>", "inner: fixed::$fixed_state<'scope, 'authority>",
        "fixed::$fixed_workspace::new(root, leaf)?", "self.inner.root_report()", "self.inner.leaf_report()",
        "impl for<'scope> FnOnce($state<'scope, 'authority>) -> R",
        "self.inner.with(block, customization,", "self.inner.with_bits(block, customization,",
        "self.inner.with_scratch(block, customization, scratch,", "self.inner.with_bits_and_scratch(block, customization, scratch,",
        "self.inner.core.finish_xof(tail)?",
        "inner: Output<BackendOutput<api::$backend_reader<'scope, 'authority>, &'scope mut [u8]>>",
        "self.inner.public(output)", "self.inner.secret(output)", "self.inner.final_public(output, valid)",
        "self.inner.final_secret(output, valid)", "ParallelHashPublicDeclassification", "pub fn cancel(self)",
    ),
    "hardened_in_place/accelerated/fixed.rs": (
        "sponge: api::$storage<'authority>", "leaf: api::$leaf<'authority>", "metadata: Metadata", "stage: [u8;168]",
        "pub fn new(root: KeccakSession<'authority>, leaf: KeccakSession<'authority>)",
        "api::$storage::new(root)?", "api::$leaf::new(leaf)?",
        "impl for<'scope> FnOnce($state<'scope, 'authority>) -> R", "let cleanup = Guard(metadata);",
        "let scratch = Block(scratch);", "let block = Block(block);",
        'sponge.with_bits(byte_string(b"ParallelHash")?', "Backend { state, leaf, scratch: &mut *scratch.0 }",
        "self.core.public(tail, output, valid)", "self.core.secret(tail, output, valid)",
    ),
    "hardened_in_place/accelerated/backend.rs": (
        "self.state.update(&[])?", "self.leaf.with(|state| state.cancel())?", "self.check()?",
        "self.state.update(input)", "self.state.finalize_xof()?", "output.get_mut(..$size)",
        ".with(|state| state.finalize_bits_xof(input)?.squeeze_secret(bytes))?",
        "squeeze_final_bits_public(\n                        output,\n                        self.scratch,", "squeeze_final_bits_secret(output, valid)",
    ),
    "hardened_in_place/xof.rs": (
        "inner: fixed::$fixed_workspace", "inner: fixed::$fixed_state<'scope>",
        "impl for<'scope> FnOnce($state<'scope>) -> R", "self.inner.with_bits(block, customization,",
        "self.inner.core.finish_xof(tail)?", "inner: Output<api::$backend_reader<'scope>>",
        "self.inner.public(output)", "self.inner.secret(output)", "self.inner.final_public(output, valid)",
        "self.inner.final_secret(output, valid)", "ParallelHashPublicDeclassification", "pub fn cancel(self)",
    ),
    "hardened_in_place/reader.rs": (
        "reader: Option<R>", "reader: &'borrow mut Option<R>", "impl<R: Reader> Drop for Operation",
        "if !self.complete {", "*self.reader = None;", "guard.complete = true;",
        "clear_owned_region(output)", "self.reader.take().ok_or(Error::StateConsumed)?",
        "Fips202Output::new(output, valid)", "read_public(output)?", "read_secret(output)?",
        "#[cfg(test)]\nmod tests;",
    ),
    "hardened_in_place/fixed.rs": (
        "sponge: api::$storage, metadata: Metadata", "pub fn new() -> Self",
        "impl for<'scope> FnOnce($state<'scope>) -> R", "let metadata = Guard(&mut self.metadata);",
        "let block = Block(block);", 'self.sponge.with_bits(byte_string(b"ParallelHash")?',
        "Core::new(state, &mut *metadata.0, &mut *block.0)?",
        "self.core.public(tail, output, valid)", "self.core.secret(tail, output, valid)",
        "pub fn finalize_bits_secret<'out>(self,", "ParallelHashPublicDeclassification", "pub fn cancel(self)",
    ),
    "hardened_in_place/core_state.rs": (
        "state: Option<S>", "metadata: &'scope mut Metadata", "block: &'scope mut [u8]",
        "clear_owned_region(&mut self.used)", "clear_owned_region(&mut self.leaves)", "clear_owned_region(&mut self.leaf)",
        "impl Drop for Guard<'_>", "impl Drop for Block<'_>", "self.state = None;", "if !self.complete {",
        "self.core.cancel();", "operation.complete = true;", "prefix.left(", "suffix.right(read(&self.metadata.leaves))?",
        "suffix.right(output_bits)?", "state.leaf(bits, &mut self.metadata.leaf)?", "update(secret.expose())?",
        "operation.core.root()?.check()?", "self.root()?.check()?",
        "clear_owned_region(output)", "Fips202Output::new(output, valid)", "self.state.take().ok_or(Error::StateConsumed)?.finish()",
        "self.flush(tail.valid_bits_in_last_byte())", "u128::try_from(full)",
        "pub(super) fn finish_xof(mut self,", "self.finish(tail, 0)",
    ),
    "hardened_in_place/backend.rs": (
        "impl<'scope> State for api::$state<'scope>", "self.finalize_xof()",
        "crate::backend::$leaf(input,", "Fips202Output::new(output, valid)",
        "Sha3PublicDeclassification::acknowledge()",
    ),
    "secret_encoding.rs": (
        "pub(crate) const fn empty() -> Self", "pub(crate) fn left(&mut self,", "pub(crate) fn right(&mut self,",
        "clear_owned_region(storage)", "clear_owned_region(length)", "!(2..=17).contains(&count)",
        "clear_owned_region(&mut self.bytes)", "clear_owned_region(&mut self.length)",
        "let marker = if left { 0 } else { width }", ".checked_add(usize::from(left))",
    ),
    "core_state.rs": ("let mut prefix = Encoded::empty();", "prefix.left(block_size)?", "suffix.right(self.leaf_count())?", "suffix.right(output_bits)?"),
    "scheduled.rs": ("let mut prefix = Encoded::empty();", "prefix.left(block)?", "suffix.right(self.expected)?", "suffix.right(output_bits)?",
        "pub(crate) fn checked_index", "!core::ptr::eq(identity, &self.identity)",
        "count != self.leaves", "block != self.block_size", "pub(crate) fn execute_with",
        "operation(self.input, output)", "identity: self.identity"),
    "execution/encoding.rs": ("pub(super) const fn empty() -> Self", "pub(super) fn left(&mut self,", "pub(super) fn right(&mut self,",
        "crate::secret_encoding::write(&mut self.bytes, &mut self.length, value, true)",
        "crate::secret_encoding::write(&mut self.bytes, &mut self.length, value, false)",
        "crate::secret_encoding::bytes(&self.bytes, &self.length)",
        "clear_owned_region(&mut self.bytes)", "clear_owned_region(&mut self.length)"),
    "execution/collector.rs": ("prefix.left(block)?", "suffix.right(root.merged_leaves())?", "suffix.right(output_bits)?"),
    "backend.rs": ("hardened_in_place::Shake128Workspace::new()", "hardened_in_place::Shake256Workspace::new()",
        "workspace.with(|state| state.finalize_bits_xof(input)?.squeeze_secret(output))"),
}

SCOPED_THREAD_TOKENS = {
    "execution/batch/in_place.rs": ("let scratch = Scratch(scratch)", "let _gate = self.inner.base.gate()?",
        "clear_owned_region(output)", "output.copy_from_slice(secret.expose())", "root.merge_batch(leaves)",
        "Selection::new(self.inner.base.config.root)?", "plan.leaf_count() > self.inner.base.config.max_leaves",
        "accelerated::$workspace::new(session).map_err(crypto)?", "#[cfg(test)]\nmod tests;"),
    "execution/batch/in_place/worker.rs": ("struct GroupSlots(Vec<[[u8; 64]; leaf::CAPACITY]>)",
        "try_reserve_exact(length)", "clear_owned_region(slot.as_flattened_mut())", "self.clear()",
        "GroupSlots::new(width)?", "thread::scope(|scope|", "match handle.join()", "if failure.is_none()",
        "Selection::new(executor.inner.base.config.leaves)?", "leaf::Workspace::new()",
        "leaf::Control::new(executor.inner.budget, &mut cancel)", "merge(leaves).map_err(crypto)",
        "failure.map_or(Ok(work), Err)", "#[cfg(test)]\nmod tests;"),
    "in_place.rs": ("let _gate = self.enter_operation()?", "crate::scoped_worker::admit(",
        "workspace.with_bits(plan, customization, |mut root|", "|leaf| root.merge(leaf)",
        "crate::worker::ensure_live(cancellation)?", "Ok(operation(root))",
        "impl for<'scope> FnOnce(api::$collector<'scope, 'plan, 'input>) -> R"),
    "scoped_worker.rs": ("struct Slots<const N: usize>(pub(crate) Vec<[u8; N]>)", "try_reserve_exact(length)",
        "clear_owned_region(slot)", "self.clear()", "Slots::<$width>::new(leaves.min(workers))",
        "base.checked_add(count)", "base.checked_add(offset)", "if leaves > limit",
        "thread::scope(|scope|", "try_reserve_exact(batch.len())", "match handle.join()",
        "if failure.is_none()", "ensure_live(cancel)?", "let result = job.execute(destination)?",
        "failure.map_or(Ok(()), Err)", "#[cfg(test)]\nmod tests;"),
    "execution/in_place.rs": ("let scratch = Scratch(scratch)", "let _gate = self.inner.gate()?",
        "clear_owned_region(output)", "output.copy_from_slice(secret.expose())", "live(cancellation)?",
        "Selection::new(self.inner.config.root)?", "plan.leaf_count() > self.inner.config.max_leaves",
        ".with_bits(&plan, request.customization, |mut root|", "|leaf| root.merge(leaf)",
        "accelerated::$workspace::new(session).map_err(crypto)?", "Mode::Require(None) => Err(Error::Unavailable)",
        ".squeeze_final_bits_secret(output, valid)", "root.finalize_secret_bits(output, valid)"),
    "execution/in_place/worker.rs": ("Slots::<$width>::new(leaves.min(config.workers))", "if failure.is_none()",
        "Selection::new(preference)?", "let result = $leaf(job, destination, &owner)?", "match handle.join()",
        "accelerated.checked_add(used)", ".checked_add(u128::from(used))", "merge(leaf).map_err(crypto)?",
        "workspace.execute(job, output).map_err(crypto)?", "Mode::Require(None) => Err(Error::Unavailable)",
        "clear_owned_region(output)", "live(cancellation)?", "failure.map_or(Ok(accelerated), Err)"),
}

def validate_scoped_threads(loaded):
    for name, tokens in SCOPED_THREAD_TOKENS.items():
        for token in tokens:
            require(loaded[STD / "src" / name], token, "scoped thread ownership")

def validate_borrowed(loaded: dict) -> None:
    for name, tokens in BORROWED_TOKENS.items():
        code = loaded[PORTABLE / "src" / name]
        for token in tokens:
            require(code, token, "borrowed ParallelHash framing/leaf storage")
    for name in ("core_state.rs", "scheduled.rs", "execution/collector.rs"):
        code = loaded[PORTABLE / "src" / name]
        for forbidden in ("Encoded::new(", "left_encode_u128(", "right_encode_u128("):
            if forbidden in code:
                fail("ParallelHash populated integer owner return: " + name)

def validate(root: Path) -> None:
    expected_sources = {root / path for path in (*SOURCES, *EXECUTION)}
    if set((root / PORTABLE / "src").rglob("*.rs")) != expected_sources:
        fail("portable ParallelHash source inventory changed")
    expected_std_sources = {root / path for path in (*STD_SOURCES, *STD_EXECUTION)}
    if set((root / STD / "src").rglob("*.rs")) != expected_std_sources:
        fail("std ParallelHash source inventory changed")
    loaded = {path: read(root, path) for path in FILES}
    for owner in ("`backend::State`", "`Collector` metadata", "`Stream` workspace and metadata",
                  "`Encoded`", "`Leaf` / worker output", "`Clear` / output staging",
                  "`Reader` / `StreamReader`", "std `worker::Storage`"):
        require(loaded[OWNER_INVENTORY], owner, "execution secret-region inventory")
    require(loaded[STD / "src/execution/worker/tests.rs"],
            "storage_clear_visits_every_byte_of_every_live_slot", "std slot clearing test")
    if set(HASHES) != set(HASHED):
        fail("ParallelHash reviewed hash inventory changed")

    # This out-of-line, test-only module uses host allocation/unwind probes.
    require(loaded[PORTABLE / "src/execution/batch.rs"],
            "#[cfg(test)]\nmod tests;", "batch tests remain test-only")
    for module in ("tests", "failures"):
        require(loaded[PORTABLE / "src/execution/stream/batch.rs"],
                f"#[cfg(test)]\nmod {module};", "stream batch tests remain test-only")
    test_only = {PORTABLE / "src/execution" / name for name in (
        "batch/tests.rs", "batch/scoped/tests.rs", "batch/scoped/tests/handoff.rs",
        "stream/batch/tests.rs", "stream/batch/failures.rs")}
    require(loaded[PORTABLE / "src/execution/batch/scoped.rs"],
            "#[cfg(test)]\nmod tests;", "scoped batch host tests remain test-only")
    require(loaded[PORTABLE / "src/execution/batch/scoped/tests.rs"],
            "mod handoff;", "scoped batch threaded regression reachable")
    require(loaded[PORTABLE / "src/hardened_in_place/reader.rs"],
            "#[cfg(test)]\nmod tests;", "scoped reader unwind tests remain test-only")
    test_only.add(PORTABLE / "src/hardened_in_place/reader/tests.rs")
    production = "\n".join(loaded[path] for path in (*SOURCES, *EXECUTION) if path not in test_only)
    for forbidden in (
        "unsafe", 'extern "C"', "std::", "alloc::", "Vec<", "Box<",
        "static mut", "Atomic", "thread_local", "core::arch", "asm!",
    ):
        if forbidden in production:
            fail(f"portable ParallelHash crossed forbidden boundary: {forbidden}")
    library = loaded[PORTABLE / "src/lib.rs"]
    for token in (
        "#![no_std]", "PARALLEL_HASH_IMPLEMENTED: bool = true",
        "pub fn parallel_hash128", "pub fn parallel_hash256",
        "pub fn parallel_hash_xof128", "pub fn parallel_hash_xof256",
        "#[kani::proof]",
    ):
        require(library, token, "portable API")
    backend = loaded[PORTABLE / "src/backend.rs"]
    for token in (
        'b"ParallelHash"', "HardenedCshake128", "HardenedCshake256",
        "LEAF_128_BYTES", "LEAF_256_BYTES", "impl Drop for BackendReader",
    ):
        require(backend, token, "SP 800-185 backend")
    core = loaded[PORTABLE / "src/core_state.rs"]
    for token in (
        "prefix.left(block_size)?", "suffix.right(self.leaf_count())?", "suffix.right(output_bits)?", "clear_owned_region",
        "checked_add", "finalize_input", "impl Drop for ParallelCore",
    ):
        require(core, token, "sequential lifecycle")
    validate_borrowed(loaded)
    validate_scoped_threads(loaded)
    scheduled = loaded[PORTABLE / "src/scheduled.rs"]
    for token in (
        "ParallelHash128Plan", "ParallelHash256Plan",
        "pub fn execute", "pub fn merge", "ParallelHashError::LeafOrder",
        "ParallelHashError::LeafIdentity", "core::ptr::eq(identity, self.identity)",
        "identity: &'plan PlanIdentity", "clear_owned_region(&mut self.merged)",
        "impl Drop for $collector",
    ):
        require(scheduled, token, "scheduled ownership")
    fixed = loaded[PORTABLE / "src/fixed.rs"]
    xof = loaded[PORTABLE / "src/xof.rs"]
    for name in ("ParallelHash128", "ParallelHash256", "HardenedParallelHash128", "HardenedParallelHash256"):
        require(fixed, name, "fixed identities")
    for name in ("ParallelHashXof128", "ParallelHashXof256", "HardenedParallelHashXof128", "HardenedParallelHashXof256"):
        require(xof, name, "XOF identities")

    portable_manifest = tomllib.loads(loaded[MANIFESTS[0]])
    if portable_manifest.get("features") != {
        "default": [],
        "hardened-batch-execution": ["hardened-execution", "brynja-hash-sha3/hardened-batch-execution"],
        "hardened-execution": ["brynja-hash-sha3/hardened-execution"],
        "runtime-execution": ["hardened-execution", "brynja-hash-sha3/runtime-execution"],
    }:
        fail("portable feature boundary changed")
    if portable_manifest.get("dev-dependencies") != {
        "brynja-crypto-cpu": {"workspace": True, "features": ["hardened-execution"]},
        "brynja-crypto-cpu-std": {"workspace": True, "features": ["runtime-execution"]},
    }:
        fail("execution test-only authority dependencies changed")
    if portable_manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-sha3": {"workspace": True},
    }:
        fail("portable dependency boundary changed")
    std_manifest = tomllib.loads(loaded[MANIFESTS[1]])
    if std_manifest.get("features") != {
        "default": [],
        "runtime-execution": ["brynja-hash-parallel/runtime-execution", "dep:brynja-crypto-cpu-std", "dep:brynja-crypto-cpu"],
        "runtime-batch-execution": ["runtime-execution", "brynja-hash-parallel/hardened-batch-execution", "brynja-crypto-cpu-std/keccak-hardened-batch", "brynja-crypto-cpu/keccak-hardened-batch"],
    }:
        fail("std execution must remain explicitly opt-in")
    if std_manifest.get("dependencies") != {
        "brynja-core": {"workspace": True},
        "brynja-hash-parallel": {"workspace": True},
        "brynja-crypto-cpu-std": {"workspace": True, "optional": True, "features": ["runtime-execution"]},
        "brynja-crypto-cpu": {"workspace": True, "optional": True, "features": ["hardened-execution"]},
    }:
        fail("std executor dependency boundary changed")
    std_source = "\n".join(loaded[path] for path in STD_SOURCES)
    for token in (
        "pub struct ParallelHashExecutor", "try_reserve_exact",
        "thread::scope", "thread::Builder::new().spawn_scoped",
        "trait ThreadSpawner", "CancellationToken", "WorkerPanicked",
        "max_leaves", "WorkLimitExceeded", "let slots = leaves.min(workers)",
        "operation_gate: Mutex<()>", "TryLockError::WouldBlock",
        "TryLockError::Poisoned", "fn enter_operation",
        "struct LeafStorage", "clear_owned_region(leaf)", "join_worker(handle)",
        "failure.map_or(Ok(()), Err)",
        "pub fn parallel_hash128_bits", "pub fn parallel_hash256_bits",
        "pub fn parallel_hash_xof128_bits", "pub fn parallel_hash_xof256_bits",
    ):
        require(std_source, token, "native executor")
    std_library = loaded[STD / "src/lib.rs"]
    if std_library.count("let _operation = self.enter_operation()?;") != 8:
        fail("every native executor operation must hold the shared operation permit")
    for token in (
        "all_public_operations_reject_concurrent_use_without_waiting",
        "poisoned_operation_gate_fails_closed",
    ):
        require(std_library, token, "executor operation-permit tests")
    for forbidden in ("HardenedCshake", "Keccak", "core::arch", 'extern "C"'):
        if forbidden in std_source:
            fail(f"std adapter contains cryptographic or native backend code: {forbidden}")

    official = loaded[PORTABLE / "tests/official_vectors.rs"]
    for token in (
        "all_six_official_fixed_examples_match",
        "all_six_official_xof_examples_match",
        "check128", "check256", "check_xof128", "check_xof256",
    ):
        require(official, token, "official NIST examples")
    api = loaded[PORTABLE / "tests/api.rs"]
    for token in (
        "streamed_scheduled_and_one_shot_are_identical",
        "empty_input_has_zero_leaves_and_b_one_is_valid",
        "reordered_leaf_permanently_fails_closed",
        "equal_shape_cross_plan_result_permanently_fails_closed",
        "arbitrary_bit_input_and_output_partition_are_stable",
        "hardened_output_and_workspace_clear_on_drop",
    ):
        require(api, token, "portable adversarial acceptance")
    executor_tests = loaded[STD / "tests/executor.rs"]
    for token in (
        "worker_counts_match_portable_fixed_and_xof",
        "arbitrary_bit_executor_matches_portable_fixed_and_xof",
        "cancellation_is_fail_closed_and_preserves_output",
        "zero_and_exceeded_leaf_budgets_fail_before_output",
    ):
        require(executor_tests, token, "executor acceptance")
    for path, token in (
        (PUBLIC[1], "leaf_crypto_main_scheduled_and_hardened_apis_are_operational"),
        (PUBLIC[3], "external_native_executor_is_operational"),
        (DIFFERENTIAL[2], "for index in range(64)"),
        (SUPPORT[0], "PARALLEL_HASH_IMPLEMENTED: bool = true"),
        (SUPPORT[1], "four ParallelHash identities"),
        (SUPPORT[3], "scripts/parallelhash/check-parallelhash-differential.py"),
        (SUPPORT[4], "run_miri -p brynja-hash-parallel --tests"),
        (SUPPORT[5], "-p brynja-hash-parallel-std"),
        (SUPPORT[6], "cargo kani -p brynja-hash-parallel"),
    ):
        require(loaded[path], token, "ParallelHash evidence closure")
    for command in (
        "python3 scripts/parallelhash/check-parallelhash-execution-differential.py",
        "python3 scripts/parallelhash/check-parallelhash-execution-package.py",
        "cargo test --locked --offline --manifest-path assurance/parallelhash-differential/Cargo.toml --features execution --doc",
        "python3 scripts/parallelhash/check-parallelhash-execution-codegen.py --toolchain 1.90.0",
        "python3 scripts/parallelhash/check-parallelhash-execution-codegen.py --toolchain 1.98.1",
        "cargo clippy --locked --offline --manifest-path assurance/parallelhash-differential/Cargo.toml --all-features --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks",
    ):
        require(loaded[SUPPORT[3]], command, "execution repository gate")
    for command in (
        "run_miri -p brynja-hash-parallel --features hardened-execution --lib execution",
        "run_miri -p brynja-hash-parallel --features hardened-execution --test execution",
        "run_miri -p brynja-hash-parallel --features hardened-execution --test execution_stream",
        "run_miri -p brynja-hash-parallel-std --features runtime-execution --lib execution",
    ):
        require(loaded[SUPPORT[4]], command, "execution Miri gate")
    sanitizer = " ".join(loaded[SUPPORT[5]].replace("\\\n", " ").split())
    for package in ("brynja-hash-parallel", "brynja-hash-parallel-std"):
        require(sanitizer, f"-p {package} --features runtime-execution --tests", "execution ASan gate")
    for path, digest in HASHES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != digest:
            fail(f"ParallelHash reviewed source changed: {path}")
