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

A separate, explicitly approved local-crash-dump experiment is prepared with
synthetic control mappings, bounded address-based dump parsing and cleanup of
its own application-specific configuration. Parser and orchestration regressions
pass locally and on Windows. Two native runs found that the full local crash
dump still includes all bytes of the WER-registered synthetic mapping. This
candidate protection mechanism is therefore insufficient for claiming local
dump exclusion; Windows strict constructors remain unsupported. Temporary test
configuration and raw dumps were removed, with cleanup independently checked.
Worker-stack review also tracks OS-owned fiber register state, which a stack-only
wipe would not cover. No weaker deployment contract has been substituted.

The follow-up AWE physical-memory experiment also found all 8 KiB of its
synthetic payload in full local dumps on two native runs. Allocation, normal
clearing/release and all 39 probe tests passed; dump exclusion did not. The
temporary Lock Pages account right was removed and exact prior rights restored;
a fresh-token negative test rejected the unprivileged AWE path. The observation
is recorded without claiming Windows strict qualification. Production behavior
and release gates remain unchanged.

A read-only enclave capability probe now records negative results without
confusing OS API availability with qualification. Its eight regression tests
pass on Windows, including parsing the real embedded PowerShell query. The
current EC2 host reports no VBS/SGX enclave support. The separate enclave design
review identifies required operation/secret-output API changes, residency and
worker cleanup questions, signing requirements and the host prerequisite.
No enclave runtime, dependency or weaker Windows profile has been introduced.
