# Brynja v0.24.50

Status: in progress; Windows strict protected-profile design and qualification.
The previous v0.24.49 signed tag is the implementation baseline. This release
selects no crates.io publication and changes no supporting crate versions.

The scope is operational Windows x86-64 and AArch64 protected storage and
worker stacks for the existing strict cryptographic APIs, preserving explicit
opt-in SIMD/hardware acceleration and fail-closed resource acquisition.
See the [platform design and open proof obligations](../docs/windows-strict-profile.md).

Windows strict sessions remain unsupported today. This candidate does not
claim implementation completion, native qualification or a passed pentest.
The milestone requires failure/rollback and cleanup tests, packaged consumers,
Windows ABI/register inspection and native evidence for each claimed platform,
followed by the existing exceptional pentest/retest and release checks.
No release-gate policy is being changed.

An isolated synthetic Windows mapping probe passed its first native Windows
Server 2025 x86-64 run, alongside all 15 portable regression tests. It
checks allocation/guard geometry, page locking, WER registration and cleanup,
with portable failure-injection regressions. Its output is explicitly not
strict qualification; crash-dump exclusion and worker-stack protection remain
unverified. No production Rust behavior or dependency is changed by this probe.
