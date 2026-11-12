# Apple retained static AES startup review — v0.27.3 development

This is a bounded review of the eight **static-admission** executables from the
[Apple startup capture](../../assurance/aes-native-observations/v0.27.3/apple-startup-capture-20261111.json).
It does not approve the hosted detector or platform lifetime guarantees.
The source is the recorded development working tree, not a clean tagged release.

## Replay and identity

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-static-startup \
  --compiler 1.99.1 --panic abort --admission static
```

Identity checking precedes parsing. Missing/conflicting configuration, hosted
admission, unexpected symbols, dependencies or bytes fail without success JSON.
The [review record](../../assurance/aes-native-observations/v0.27.3/apple-static-startup-review-20261111.json)
binds capture/source identities, reviewer hashes, function extents, immutable
references, comparison imports and rejection-control totals. It is an
unauthenticated local observation, not certification evidence. Original capture
records remain unchanged and still say machine review was not performed during
capture. Earlier reviewer hashes are historical identities, not rewritten to
match this updated checker.

## Instructions reviewed

[`aes_apple_startup_static.py`](../../scripts/aes/aes_apple_startup_static.py)
constructs explicit instruction templates from the inspected startup bodies:
196 instructions on Rust 1.90.0 and 193 on 1.99.1. Direct/facade consumers and
abort/unwind share the respective compiler template. Mach-O symbols and
`LC_FUNCTION_STARTS` bound complete functions; disassembler text is not trusted.

The wrong-architecture branch precedes every expansion, comparison and round
call. Enum representations follow the safe Rust API: MSRV tests bit zero;
the current compiler tests zero. This is not arbitrary-corruption tolerance.
The admitted path:

1. Initializes each 176/208/240-byte schedule and supplies sequential public
   keys of 16/24/32 bytes to the width-matched expansion kernel.
2. Compares each complete schedule to the fixed expected schedule with lengths
   176/208/240, retaining all three comparison results.
3. Uses the **fixed expected schedules**, independently of computed expansion,
   for three encryptions starting from known plaintext and three decryptions
   starting from independent known ciphertexts. Direction operands are zero/one.
4. Compares both 64-bit halves of all six answers to fixed expected values.
   Conditional comparisons propagate failure through the entire chain. OR of
   all schedule-comparison results must also be zero.
5. Stores generation 2 and health 1 only when all checks agree; otherwise health
   is 2 (quarantined). A separate discriminant distinguishes an admitted owner
   from pre-admission rejection.

All twelve call destinations bind to the reviewed six expansion/round kernels
or the comparison import in the same executable. Every kernel body is rechecked.
MSRV additionally copies public startup bytes into result padding; this neither
introduces key material nor establishes a general clearing guarantee.

Reference data comes from the existing fixed
[`startup-arm-reference.json`](../../scripts/aes/startup-arm-reference.json),
not from values learned from the executable. ADRP/address/vector-load encodings
must identify the expected bytes in a uniquely mapped non-writable segment.
Registers, opcodes, lengths and local branches remain exact. A relocation to an
equivalent immutable copy of a constant is deliberately allowed; it is not a
cryptographic error. Repeated schedule-address uses must remain consistent.

## System comparison trust boundary

Apple links schedule comparison to **`memcmp` in `/usr/lib/libSystem.B.dylib`**,
not the locally reviewed ELF `bcmp`/`memcmp` bodies used by the Linux runner.
The import checker now accepts only an explicitly requested unwind or `memcmp`
symbol. For `memcmp` it checks the strong undefined ordinal-one symbol,
two-level namespace, library identity, indirect slot, stub instructions,
lazy pointer, lazy binding record and per-symbol helper.

This binds the call to the declared system function; it does **not** inspect the
loaded system implementation, dyld common dispatcher, runtime interposition or
memory corruption. Correct libc/dyld behavior is an explicit assumption. These
comparisons process public self-test data; no secret-comparison timing claim is
made. Earlier caller/unwind reviews still replay successfully with the default
unwind binding unchanged.

## Results and limits

All eight static startup bodies, 48 AES kernel bodies and eight comparison
bindings pass. Offline controls reject **6,224 code-byte complements** (XOR
`0xff` at each startup byte) and **5,824 referenced-constant bit flips** (bit zero
at each distinct referenced byte). No altered executable was run.

Eight new startup tests cover both compiler layouts, profiles, all call targets,
comparison lengths, direction/result/health checks, constants, symbols, extent,
dependencies and CLI failures, including 1,556 synthetic code-byte complements
and 1,456 constant-bit flips. A separate new import test checks `memcmp` binding,
rejects interchange with unwind and mutates its stub/pointer/helper/record.
All **906 integrated tooling tests** pass. The previous 16-binary caller chain
also passes a fresh normal replay; its original records were not rewritten.

At the offline-review stage, executed corrupted-answer controls were unfinished;
the subsequent native campaign is recorded below. Hosted startup, feature
detection, lifetime admission and other call sites remain separate.
No production Rust or publication gate changed. No new timing runs
were needed, and earlier timing alarms remain recorded. This review does
not establish physical fault resistance, power/EM protection or spill erasure.

## Native quarantine controls

The [native control runner](../../scripts/aes/check-aes-apple-startup-controls.py)
requires Darwin ARM64 and an exact trusted capture hash. It rejects ambient
loader-injection variables, replays the static startup review and executes the
original healthy fixture before creating private disposable copies. The original
binary is never patched. An unchanged, re-signed positive copy must also pass
before any negative controls run.

Apple requires modified executables to be re-signed. These ad-hoc signatures
are temporary test machinery, not release identities. Native `codesign` shrinks
the terminal signature relative to the linker's signature, updating its length
and the enclosing `__LINKEDIT` file size. Both sizes must agree with the actual
file end; runtime tables must precede the signature. The runner permits only
these two size fields and the signature payload to change. The signature offset,
VM layout, permissions, all other metadata, code and constants stay identical.
Each copy must pass `codesign --verify --strict` before execution.

The population is **628 per executable**: bit zero in each of the 624 expanded-
schedule bytes, plus one byte in each of the four plaintext/ciphertext inputs.
Each copy gets its own inode and must exit successfully with the exact quarantine
marker and no stderr. A crash, timeout, healthy result or missing marker fails;
the fixture requires generation 2, quarantined health and a rejected session.
Cases are logged incrementally with unsigned/signed hashes. A final report
requires all 628 unique cases and unchanged original-binary/signing-tool hashes.
Temporary executables are removed; case logs remain available.

Seven local runner tests cover mutation population, byte changes, signature
boundaries and resizing, runtime-table overlap, wrong host/profile/hash,
injected environment, timeout/output failures and the mocked full workflow.
Mocks are not native evidence. The first native pilot stopped before negative
execution because its initial signature policy incorrectly required unchanged
file length. Inspection established the two size changes above; the amended
policy has explicit positive and negative regression coverage. This tooling
adjustment changes neither AES nor its startup logic.

All **eight native static configurations pass** on Apple M2 Pro, macOS 27.2.1
(26B131): Rust 1.90.0/1.99.1, direct/facade, abort/unwind. Each original and each
unchanged re-signed positive copy stays healthy; **5,024 corrupted-answer
executions quarantine correctly**. The
[native record](../../assurance/aes-native-observations/v0.27.3/apple-static-startup-controls-20261111.json)
binds source/capture identities, tool and binary hashes, case logs, the retained
archive and the initial rejected signing pilot. Local replay validates all
eight original hashes, complete static reviews, mutation identities and exact
markers against the fixed reference bytes. This is unauthenticated observation,
not certification or a new verification-runner current pass.

All seven runner tests pass on Linux and the Mac; all **913 integrated tooling
tests** pass locally. The Mac test run also exposed its symlinked temporary-root
spelling: tests now canonicalize their own created fixture directory, while an
explicit negative test retains rejection of symlinked caller inputs. No
production path policy was relaxed. Release-plan, documentation-link and diff
checks pass. Hosted startup/detection and platform lifetime admission remain
separate work. This campaign does not establish physical fault resistance.
