# Optional Arm DIT — v0.27.3 development

The owner selected optional scoped support, with an explicit fail-closed option
for applications that require it. No HSM, military profile or new release gate
is introduced. Portable AES and non-AES APIs retain their behavior.

## Caller policy

The hosted adapter's existing `Authority::new` now uses `DitPolicy::IfAvailable`.
Linux/macOS Arm system feature detection admits DIT independently of AES/PMULL/
NEON. AES-capable CPUs without DIT remain usable under that policy.

Applications can require it explicitly:

```rust,ignore
use brynja_crypto_cpu_std::aes::{Authority, DitPolicy, Kernel, Mode};
let authority = Authority::new_with_dit(Kernel::ArmAes, Mode::Require, DitPolicy::Require)?;
assert!(authority.dit_enabled());
let kernel = authority.kernel_authority()?;
// Borrow the kernel authority to construct a clearing AES execution key owner.
```

`DitPolicy::Require` rejects portable mode, missing DIT and non-Arm routes.
With `Mode::Prefer` it disables portable fallback: the application receives an
error, not a weaker execution route. `dit_enabled()` observes the configured
kernel scope, not the caller's instantaneous PSTATE or owner health. Check
`kernel_authority()`/session health before execution as before.

Static/no_std callers use `Authority::new_with_dit`. DIT availability there comes
only from the compiled `+dit` target feature, with the usual deployment-wide ISA
obligation. The policy is re-exported by `brynja_crypto::aes::execution` and hence
the facade. Platform authors have a separately unsafe `from_platform_with_dit`
boundary; a safe caller cannot turn an arbitrary boolean into CPU authorization.
The old unsafe `from_platform` does not assume DIT support.

## Scope and limits

After admission and before every Arm expansion or block kernel, a private guard
saves PSTATE.DIT, enables it and verifies readback. It restores the saved value
on normal return, error and unwinding, including nested scopes. Startup KATs use
the same dispatch. Failed enabling prevents entry; startup becomes quarantined,
and a selected operation failure revokes the owner without fallback.

The system register is `S3_3_C4_C2_5`, bit 24. Memory-clobbering asm boundaries and
ISB surround state changes; no `nomem`, `readonly` or `pure` declaration permits
memory work to float across them. Abort, process termination and hostile signal
handlers are not recoverable unwinds. The platform must preserve the admitted
ISA and PSTATE across scheduling and must not resume an operation with DIT
altered by a signal handler.

This scopes the expansion/round kernel instruction sequences, not the complete
application, clearing-owner wrapper or protocol. DIT does not equalize addresses,
erase spills, prevent power/EM leakage, detect physical faults or certify constant
time. See the [Arm architectural clarification, D23813](https://documentation-service.arm.com/static/690b6d106f7db8243c22d513%3Ftoken=)
and [Rust feature detection](https://doc.rust-lang.org/std_detect/macro.is_aarch64_feature_detected.html).

## Verification and remaining qualification

Unit models cover optional/required admission, rejected enable, both prior bit
states, nested scopes, error and unwind restoration. The native test independently
reads PSTATE around startup, all three key widths and both directions, nested
scopes, unwind and quarantine. It emits a distinct unavailable marker if hardware
cannot exercise the path; that marker is never accepted as a DIT execution pass.

Linux Neoverse-V2 and Apple ARM executed that test with Rust 1.90.0 and 1.99.1.
The hosted tests verify detection, required admission and optional selection.
The registered `aes-dit` checks retain model tests and QEMU DIT-on plus Cortex-A53
DIT-unavailable checks on both compilers. Emulation is functional coverage only.

The source change invalidates earlier linked-code and timing observations for
these dispatch paths. They remain historical evidence, not DIT qualification.
Updated final-linked scope review and any new shared-address timing experiment
remain required before claiming the changed production paths are qualified.

### Bounded linked-session review, 2026-11-12

`scripts/aes/check-aes-dit-linked.py` replays a manually inspected, fail-closed
review of the two Linux ARM hosted release consumers. It is an optional review
tool, not a new publication gate. The binary identities, normalized instruction
and encoding hashes, and mutation counts are retained in
[`dit-fixture-review-20261112.json`](../../assurance/aes-native-observations/v0.27.3/dit-fixture-review-20261112.json).

For each compiler the review binds nine full Session bodies (expand, encrypt,
decrypt for all three widths) to six independently checked raw kernels. Within
an operation, all widths have the same normalized caller body, but each call is
bound to the correct width-specific kernel. Encrypt/decrypt differ only in the
public direction argument. Local branches retain their encoded displacement;
only independently bound external call relocations are normalized.

Rust 1.90.0 saves prior DIT in a callee-saved register, enables bit 24, executes
ISB and verifies readback before calling the kernel. Enable failure restores
the saved state and quarantines without entering the kernel. A separate public
enabled flag selects restoration after normal return and on the emitted unwind
landing pad. Rust 1.99.1 separates the DIT-on and DIT-off call paths; successful
DIT-on calls restore the saved register and execute ISB immediately afterward.
Its inspected raw-kernel calls have no emitted unwind landing pad. Admission,
generation, quarantine and direction branches use public metadata, not key/block
values. Expansion's post-operation admission checks occur after restoration.

The checker rejected 5,640 altered instruction/byte cases for 1.90.0 and 4,980
for 1.99.1. Tests also reject wrong readback bit, branch direction, register and
destination. `_Unwind_Resume` is pinned as a trusted runtime boundary; its bytes
are not a semantic review of libunwind. This review does **not** cover exception
table dispatch, startup, owner cleanup, Apple machine code, the timing fixture,
or whole-program/spill erasure. Earlier broader linked policies are not silently
refreshed by these observations.

### DIT-required timing fixture correctness

The timing runner now accepts `--require-dit` with `--controls --value-controls`
on ARM. A baseline-compiled probe must detect AES, PMULL, NEON and DIT before
specialized tests execute. The fixture then compiles with `+aes,+neon,+dit`,
requires `DitPolicy::Require`, and checks `dit_enabled()` before emitting its
authority marker. Identity records bind that policy, the generated authority
source, probe source, flags, package archives and executable. Unsupported hosts
fail; no DIT-off fallback is used for a DIT-required observation.
The baseline probe was also cross-compiled with both Rust endpoints and checked
under QEMU: `max` admitted it, while `cortex-a53` exited with code 2 and no success
marker. This is a capability-branch test, not native timing evidence.

On the Apple builder, both the direct and facade routes passed with Rust 1.90.0
and 1.99.1: eight fixture tests and 936 independent OpenSSL comparisons per
configuration. The record above includes all four identities and log hashes;
full logs and binaries are retained locally under
`target/aes-dit-mac-fixtures-20261112/`. An initial attempt used the older Mac
source copy and failed to compile the missing `DitPolicy` re-export. The full
current source bundle was then transferred; no measurement was attempted in
either case.

### Retained Linux timing binaries and native preflight

The replacement Linux ARM builder has no Rust toolchain. The runner therefore
now supports explicit `--qemu-aarch64` preparation on Linux x86_64: build a
self-contained `aarch64-unknown-linux-musl` executable with the pinned compiler
and `rust-lld`, then run correctness tests under QEMU `max`. This mode requires
DIT and shared-address controls and rejects observations before packaging.
The lower-level preflight helper independently rejects emulated observations.
The baseline capability-probe executable is retained alongside the specialized
binary, so it can be run before transferring trust from emulation to a real host.
This is cross compilation, not a native GNU/Linux build or native timing result.

Both Rust 1.90.0 and 1.99.1 direct-route builds passed eight fixture tests and
936 OpenSSL comparisons under QEMU. Those **same executable bytes** then passed
the baseline DIT probe and all four native preflights on Neoverse-V2 at
`13.49.18.65`: another 936 comparisons per compiler. Executable and probe hashes
were checked remotely before and after the preflights. No `measure` command ran.
An initial local orchestration attempt rejected the OpenSSL environment before
any remote execution; its setup failure is retained, not a timing attempt.

The [preparation record](../../assurance/aes-native-observations/v0.27.3/dit-timing-preparation-20261112.json)
binds these identities, seven native command logs per compiler and the exact
raw-kernel review of the two Linux and two previously retained direct Apple
timing binaries. Each Linux binary matched all six round/expansion templates
and rejected 1,305 instruction/encoding mutations. Each Apple binary matched
all six complete Mach-O function extents. These checks cover raw kernels only,
not their whole callers or timers. Full generated assembly is retained as
`dit-review.asm` next to each executable; the record contains its hash.

The cross-preparation changes passed the 44-test timing-tool suite and the
969-test verification-registry suite. Regression tests forbid emulated
observations, require DIT for cross preparation and check the baseline probe's
closed QEMU runner and linker arguments.

### Bounded timing caller review

This is a bounded manual inspection of the **retained musl timing binaries**,
separate from the hosted-session checker above. Addresses are hexadecimal and
apply only to the executable hashes in the preparation record.

| Compiler / selected cached path | Observed timer and operation boundaries |
| --- | --- |
| 1.90.0 / AES-192 decrypt | Constructor call `22634c` precedes the start clock at `226370`. Direction-one call `2264ec` reaches secret wrapper `22a9d8`; output clearing at `2265a0` is inside the four-operation loop bounded at `22670c`. Elapsed call `226b14` precedes schedule clearing `226b3c`. |
| 1.90.0 / AES-256 public | Constructor `227be4` precedes clock `227c08`. Public metadata and 240-byte schedule checks precede block staging `227e90`. DIT readback at `227ef8` must have bit 24 before raw AES call `227fd8`; restoration/ISB follow immediately. Public copy and scratch clearing are timed; elapsed call `2283e8` precedes schedule clearing `228410`. |
| 1.99.1 / AES-192 decrypt | Constructor `226fa0` precedes cached timer call `226fec`. Timer `2233f0` starts at `22341c`, calls secret wrapper `22a364` with direction one at `223600`, clears returned output at `2236b8`, and stops at `223ad4`. Schedule clearing `22709c` is after return. |
| 1.99.1 / AES-256 public | Timer `22453c` starts at `224568`; public metadata and schedule checks precede staging `224700`. Save/enable/ISB/readback at `22484c..224860` guard raw AES call `22492c`; restoration/ISB at `224930..224934` precede output copy and scratch clearing. Four-operation loop bound is `224904`; stop clock is `224c20`. |

The complete inspected AES-192 secret wrappers (`22a9d8..22ac0c` on MSRV,
`22a364..22a598` on current) first clear the destination, check public owner
metadata, stage the block, enable/read back DIT, call the width-specific kernel,
restore prior DIT, copy the result and clear scratch. Failed enable restores
prior DIT and takes a clearing/quarantine exit without calling AES. Public
direction selects encryption or decryption. The copy/clear helpers at
`229e88/229e9c` and `2299e4/2299fc` use lengths and offsets rather than
content-derived addresses or branches. Successful measuring paths skip
hexadecimal formatting; error formatting is not a successful retained sample.

In the current Linux driver's inspected pair traversal, both shared-control
calls use `sp + 448` for the key and that address plus 32 for the block. Copy
stores at `2259ec/225a14` and `225b08/225b30` precede trial calls
`225a54/225b78`; neither call passes a class argument into the trial. The
separate controls still use class-indexed 48-byte slots intentionally. Distinct
call sites and prior execution history remain possible context effects even
with shared input addresses: the negative control is not optional.

The corresponding Apple retained-binary inspection is now complete for these
selected cached paths (not all 39 complete campaign callers):

| Compiler / selected cached path | Observed timer and operation boundaries |
| --- | --- |
| 1.90.0 / AES-192 decrypt | Constructor `1000051cc` precedes clock `1000051f0`. Direction-one secret call `100005378` reaches `100009e8c`; output clear `10000543c` is inside the loop bounded at `1000055b4`. Elapsed call `100005a7c` precedes schedule clear `100005aa4`. |
| 1.90.0 / AES-256 public | Constructor `100006c68` precedes clock `100006c8c`. Staging `100006f2c`, DIT save/enable/readback `100006f84..100006f98`, raw call `100007080`, restoration/ISB, copy `100007094` and scratch clear `1000070a0` are timed. Elapsed `100007550` precedes schedule clear `100007578`. |
| 1.99.1 / AES-192 decrypt | Constructor `100005d7c` precedes timer call `100005dc8`; schedule clear `100005e78` follows return. Timer starts at `100002324`, calls secret wrapper `100008ff4` at `1000024e0` with direction one, clears output at `100002598`, and stops at `1000029c0`. |
| 1.99.1 / AES-256 public | Timer `10000341c` starts at `100003448`; block staging `1000035b8` precedes DIT save/enable/readback `100003710..100003724`. Raw call `1000037f0` is followed by restoration/ISB, public copy `100003804` and scratch clear `100003810`. Stop clock is `100003ae4`. |

Complete Apple secret wrappers `100009e8c..10000a0c0` (MSRV) and
`100008ff4..100009228` (current) have the same clear/check/stage/DIT/kernel/
restore/copy/clear ordering. Readback failure restores and quarantines without
calling AES. Copy/clear helpers at `10000933c/100009350` and
`100008674/10000868c` branch and address by lengths/offsets, not data contents.
Measuring paths skip hexadecimal formatting. Runtime clock and public-mode
string-comparison calls remain trusted boundaries, not a runtime-library audit.

The remaining shared-driver call sites were also inspected. All use one
`sp + 448` common key buffer and its offset-32 block buffer, copy before the
trial, and do not pass the class to the trial:

| Binary | First key/block copies → trial | Second key/block copies → trial |
| --- | --- | --- |
| Linux MSRV | `2231d4/223200` → `223230` | `2232e4/223310` → `223344` |
| Apple MSRV | `100001d38/100001d64` → `100001d9c` | `100001e48/100001e74` → `100001eb0` |
| Apple current | `100004814/100004840` → `100004884` | `100004930/10000495c` → `1000049a8` |

This completes the stated bounded review, not a whole-program audit,
unwind-runtime qualification, spill-erasure claim or constant-time proof.
No content-derived branches were identified in the inspected successful paths.
DIT covers raw operations, not all surrounding loads, copies or cleanup.
Distinct call sites/history remain: the shared-identical control is required.

**Remaining:** freeze the finite experiment's declaration, then collect and
retain every shared-address and diagnostic arm. No new timing samples were
collected for these preparation/review records.
