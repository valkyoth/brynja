# Fixed-frame enclave depth experiment

Status: **native execution pending; not strict qualification**.
No production Rust, cryptographic implementation or release gate is changed.
Windows strict support remains unsupported.

This separate synthetic image extends the [guarded OS-stack window](windows-enclave-window-guard-results.md).
It retains the original sixteen-page locking, complete payload clearing/readback,
and boundary-restoration protocol. It does not modify the earlier probe images.

`window_depth_x64.asm` descends through fixed 4096-byte frames with a saved RBP
and return address: exactly 4112 bytes between adjacent payload-frame pointers.
Each allocation is preceded by `__chkstk`. Before allocation, optional admission
requires the prospective frame to leave four pages (16384 bytes) above the low
payload boundary. The first frame that would cross this budget returns a distinct
rejection, without allocating that frame. This reserve is an experimental number,
not a proven bound for arbitrary Rust or Windows exception machinery.

The C helper records admitted-frame counts and addresses, validates the exact
descent, and either returns normally or raises one exact synthetic exception at
the final leaf/budget rejection. The enclosing C handler must catch that exact
exception after unwinding the assembly frames; unrelated exceptions continue
searching. A crash, timeout, missing clear or incomplete record fails the runner.
An unchecked mode and compiled skipped-admission image provide negative controls.
Their failure cannot establish that overflow was caught or that cleanup occurred.

Ten local orchestration tests cover depth accounting, minimum retained headroom,
early/late rejection, exact exception outcomes, residency/clear protocol reuse,
malformed records, subprocess failures, teardown and source ordering. They are
mock-based regressions, not native stack evidence. Native compilation, unwind
inspection, repeated shallow/deep/at-budget execution, failure controls and
artifact review are still required.

Even successful fixed-frame tests would not qualify arbitrary recursion,
variable-sized allocations, compiler/runtime scratch, asynchronous exceptions,
Rust panics, register erasure or dump exclusion of a complete worker. These remain
separate from this public-marker-only experiment.
