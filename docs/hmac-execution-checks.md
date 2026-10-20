# HMAC execution composition checks

These checks exercise the HMAC layer around existing accelerated hash owners.
They are author-operated development tests, not independent native review,
compiler-erasure qualification or approval of a new CPU authority.
Production constructors and backend policy are not weakened for testing.

## Private admission and lifecycle witness

The [archive acceptance](../scripts/hmac/check-hmac-package.py) runs the
[execution fault harness](../scripts/hmac/hmac_execution_faults.py) against a
private copy of the extracted HMAC crate. Its real `execution::Hmac`, `Engine`,
`Adapter` and `Retained` implementations run unchanged. Only that copy receives
a test-only `Source::Synthetic` and a sealed test backend. Ordinary backend
entry points panic if the composition attempts portable fallback.

Six tests run in debug and release. The main campaign injects 2,784 individual
errors/unwinds across all six kernel **labels**, empty/block-sized/long keys,
and byte/bit public output, secret output, verification and cancellation.
Labels check preservation of selected identity; synthetic owners execute
**no CPU instructions**. Each fault must occur at the intended boundary.

The witnesses require:

- All two or three empty hash owners admitted before the first backend
  update/finalization.
  A failed later admission drops every earlier owner.
- No additional admission after absorption starts, no implicit adapter
  constructor and no portable fallback.
- Every terminal operation drops all created owners. A terminal update also
  rejects subsequent operations without entering the backend again.
- Atomic message-length rejection preserves both owners and permits reuse.
- Invalid algorithm/tag policy reaches no admission; wrong output length
  reaches no finalizer. Public destinations remain unchanged, while admitted
  secret destinations clear on error, including already-terminal streams.

Eleven compiled mutations remove admission, change the long-key boundary,
turn a fallible admission into a panic, leak cancellation, bypass terminal
output clearing, retain failed state, reject recoverable length errors or
delay policy validation. Each mutation must fail an executed test between
passing original/restored runs. Compile failures, crashes and ignored tests
are not accepted as detected behavioral regressions.

The synthetic owner's drop counter proves dispatch/lifetime behavior only.
Its byte filling is **not** compiler-resistant erasure evidence. Real hash
owners, real adapter output cleanup and their instruction boundaries retain
their separate tests and premises. The witness observes backend calls, not
arbitrary input-byte reads; source review separately establishes that the
constructor admits the owners before entering the engine.

## Explicit hosted native checks

On an admitted AArch64 Linux or Apple Silicon Mac host:

```sh
python3 scripts/hmac/check-hmac-hosted-native.py --kernel sha256 --kernel sha512 --kernel keccak
```

Only request routes that the host supports. There is no skip-on-unavailability
success. The safe production hosted constructor establishes authority; the
test runner does not inject detection, affinity guarantees or target features.
Generic x86 hosted authority remains deliberately unavailable: CPUID alone
does not establish the project's scheduler/migration contract. Separate
static SHA-NI/AVX2 checks are not reclassified as hosted runtime evidence.

For each requested route, the driver explicitly executes the otherwise ignored
integration test in debug and release. It checks two SHA-224/256, six
SHA-512-family (including general 129/511-bit), or four SHA-3 identities under
both `Require` and `Prefer`. Outputs are compared to portable HMAC; correct and
modified candidates, truncation,
invalid policy/destination, wrong algorithm, quarantine and terminal stream
behavior are exercised.

Five private production-source mutations turn portable selection into an
error, turn readiness or initialization errors into `None`, discard a
successfully selected HMAC or ignore tag policy. The native tests must reject
each compiled mutation and pass again after restoration. Exact test and
identity populations are required; a PASS marker with a failed subprocess
does not pass.

The portable reference is a same-library control, not an independent oracle.
This test does not substantiate hosted/protected worker-frame cleanup, timing,
dedicated x86 SHA-512 execution, OS snapshot protection or whole-frame erasure.
Those boundaries remain in the [development inventory](hmac-development-inventory.md).

## Driver regressions

`python3 scripts/hmac/test-hmac-acceptance.py` also verifies private hook
placement, unchanged composition files, exact populations, source restoration
and rejection of missing markers, compilation errors, crashes, surviving
mutants, ignored tests and unsupported native hosts. These driver regressions
use mocked subprocess results; the archive/native campaigns above run real
compiled binaries.
