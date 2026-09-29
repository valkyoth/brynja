# Native fixed-frame stack-depth results

Status: **bounded synthetic observations, not Windows strict qualification**.
No production crypto, Rust API, release-gate or Linux guarantee changed.
Windows strict constructors remain unsupported.

Source: `59b732d7bf830b7cc157502cc7a82d505c3ad950`, 2026-09-29.
The [separate depth image](windows-enclave-window-depth-design.md) ran on the
existing Azure x86-64 development host: AMD EPYC 9V45, Windows Server 2025
10.0.26100.33438, VBS/HVCI running, Secure Boot off, vTPM available and test
signing enabled. Tools were Python 3.13.15, MSVC directory 14.44.35207,
linker 14.44.35229.0 and SDK directory 10.0.26100.0. These are observed identities,
not a supported production baseline or a full SDK servicing-version claim.

## Native outcomes

Each successful mode ran three calls through one enclave, including repeated
boundary restoration and lock/clear/unlock. The sixteen payload pages were
observed valid and locked before body admission and after complete zero readback.
The fixed recursion consumed exactly 4112 bytes between admitted frame pointers.

| Control | Observed result |
| --- | --- |
| Requested depth 0, 4 and 8, normal and exact-exception modes | Respectively 1, 5 and 9 frames complete; normal leaves or exact caught exception; full payload clearing and cleanup |
| Requested depth 32 with admission, normal and exact-exception modes | 11 frames admitted; next frame rejected before allocation; no final leaf reached; ordinary rejection or exact caught exception; full payload clearing and cleanup |
| Unchecked depth 4, normal and exact-exception modes | Five frames complete; paired controls establish shallow execution without admission |
| Compiled skipped-admission image, depth 4, both modes | Same shallow control succeeds; mutant is loadable and executable |
| Missing-clear image, depth 4 | Runner rejects exact execution/cleanup outcome; no success record |
| Deliberately wrong leaf/rejection expectations | Both rejected; requested work completion cannot be confused with budget rejection |
| Unchecked depth 32 and compiled skipped-admission depth 32 | Both child processes terminate with `0xc0000005`; no success JSON, no recovery or clearing claim |

The [bounded rejection](../assurance/windows-protection-observations/window-depth-32-59b732d7.json)
and [exception at rejection](../assurance/windows-protection-observations/window-depth-32-unwind-59b732d7.json)
records each show 20224 bytes between the lowest admitted frame and payload low,
and 20176 bytes between the rejection helper's local marker and payload low.
Allocating the next frame would violate the configured 16384-byte reserve.
These addresses do **not** measure the deepest internal exception-dispatch frame.
Successful unwinding proves this exact synthetic case, not a universal headroom bound.

All [seventeen process outcomes](../assurance/windows-protection-observations/window-depth-run-exits-59b732d7.json)
match the control expectations: twelve successful observation records (36 calls)
and five rejected/error records. The two exhaustion failures are retained as
[unchecked](../assurance/windows-protection-observations/window-depth-unchecked-exhaustion-59b732d7.err)
and [compiled mutant](../assurance/windows-protection-observations/window-depth-mutant-exhaustion-59b732d7.err).
We did not capture their faulting instruction/address; an access-violation exit
alone does not identify which guard or runtime operation faulted. In particular,
these failures are not evidence of graceful stack-overflow recovery.

## Build, review and retained artifacts

The [native build and tests](../assurance/windows-protection-observations/window-depth-build-59b732d7.txt)
passed `/W4 /WX` for all three images. Ten depth, ten guard and fourteen handshake
regression tests passed locally and natively. Their mocked API cases are not
additional native measurements.

The [first-party emitted frames and unwind metadata](../assurance/windows-protection-observations/window-depth-frames-59b732d7.txt)
retain the preallocation admission branch, `__chkstk`, 4096-byte reservation,
recursive call, leaf/rejection paths and RBP-based unwind description. The outer
frame retains full clearing/readback before the finish callback and boundary
restoration before return. The native caught-exception runs exercise recursive
unwinding in addition to this emitted-code inspection.

All fifteen source hashes in all twelve records match the capture commit. Signed
image hashes match the downloaded binaries:

- Normal: `c66d53f457f9ae8320de9bbc144ea180ec62b143faf33ef856d5f58ade6d3125`.
- Missing clear: `12f8acafa18efa5cbd9da9848233b1ccedd23c4207c357b90609ac0642564faa`.
- Skipped admission: `07c29b4656dc98e4f53c2174f96237c8c133d41f61450bfb2f7b4aa3f8d3370a`.

Raw archive SHA-256 (identical remotely and after download):
`db44010d260bac0447aa05f5c4471a705244976de04422142f89152aaab20482`.
Raw disassembly SHA-256:
`fa167e760c035857d4c53adde90feee029d0ade044eb463b819324c58c86807d`.
Full raw artifacts, signed binaries, objects and helpers remain in the ignored
local `release-reports/` backup, outside Cargo target directories. Committed text
normalizes CRLF/trailing whitespace; only first-party assembly is reproduced.

All three signing commands returned compatibility-warning exit 2, and the wrapper
failed explicitly. The warning was reviewed before development-only execution;
it was not counted as a clean production signing pass. An ephemeral non-exportable
machine-store key was removed with its certificate; no trust root was installed.
The [final cleanup](../assurance/windows-protection-observations/window-depth-cleanup-59b732d7.json)
records zero probe processes and zero temporary signing certificates. No crash
dump was requested or downloaded.

## What remains

The subsequent [fixed Rust worker experiment](windows-enclave-rust-worker-results.md)
now establishes a narrow public-only ABI step, separately from depth unwinding.
This experiment supports explicit frame-budget rejection before consuming the
reserved margin, not recovery after exhaustion. Production work still requires
a bounded real call graph, Rust ABI/panic integration, complete worker/TLS and
register ownership, concurrency, exact-layout dump testing, production signing
and separately supported platform/compiler baselines. Host residency cooperation
remains trusted. A four-page reserve cannot simply be applied to arbitrary Rust
callbacks, variable frames or asynchronous runtime behavior.
