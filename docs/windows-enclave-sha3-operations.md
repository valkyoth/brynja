# Saved scalar SHA-3 owner operation review

This implementation-author review extends the
[lifecycle review](windows-enclave-sha3-lifecycle.md) for the saved
`sha3/mod.rs::open` development image. It covers nine owner operations and their
actual receiver, not all transitive sponge/prefix callees or whole-image
qualification. Production code, the saved image and release-gate policy are
unchanged. This is not an independent retest or a new native enclave campaign.

The [observation](../assurance/windows-protection-observations/sha3-operations-review-20261005.json)
records identical parsed Linux/Windows reports, source identities and scope.
The [review specification](../assurance/windows-protection-observations/sha3-operations-20261005.json)
pins complete bodies, relocations, frames and dispatch data. Inspected assembly
sequences provide additional regression checks; they are not a general symbolic
proof. Twenty-three further callees have object/image identity bindings only:
their internal semantics remain separate work.

## Admission and private compiler preconditions

The receiver copies a bounded header into enclave-owned storage before decoding.
It checks protocol version, nonzero sequence, bounded input/output lengths,
last-bit range, terminal flag and operation-specific fields before dispatch.
All nine owner destinations and the earlier cancellation path are bound to
the same saved image. The receiver's two adjacent tables have separate dispatch
bases; their actual linked destinations are checked against COFF relocations.

Owner methods require the appropriate phase and next nonzero sequence. Private
optimized callees do not necessarily repeat every source-level check: the
saved LLVM IR restricts final-bit parameters to `[0,9)` and the export sequence
to nonzero values. In particular, the machine export increment needs that
nonzero precondition to reject rollover. The reviewed receiver enforces these
conditions. These private bodies are not advertised as standalone safe entry
points for arbitrary machine-ABI arguments or corrupted Rust enum tags.

## Setup, consumption and retained output

Begin admits eight algorithm identities and publishes the newly constructed
state after success. Update bounds each fragment to 1,024 bytes. Streamed setup
admits only the two cSHAKE identities; public prefix-length accumulation checks
carry before use. Setup completion requires the complete phase, no remaining
declared input, no pending packed byte, matching emitted/expected counters and
a present workspace before publishing a usable state.

Completion from SetupRetained finalizes the exact retained fragment and clears
the old output before entering Squeezing. Ordinary completion enters Streaming.
Finalization validates canonical low-bit-first input; fixed hashes retain their
exact digest width, while XOFs enter Squeezing. All four fixed widths are bound
in the finish table and the two rehash constant tables.

Rehash uses a new state and a 1,024-byte staging region. It clears the prior
retained output and replaces the old state only after computation succeeds.
Its staging region is cleared on returned success and failure. Squeeze likewise
uses bounded staging; nonterminal output must be byte-aligned, terminal output
discards the reader, and publication records the exact retained width/last-bit
shape. Error paths reach the reviewed state destructor and output clearer,
leaving the owner quarantined.

Public export checks identity and exact retained shape before the fixed OS copy
adapter. Copy failure quarantines; success clears the retained bytes and either
resumes the XOF reader or clears the owner to Empty. This does not claim rollback
of bytes already transferred to the public destination by the OS seam.

## Copies, stack and unresolved boundaries

The compiler creates multiple state/setup copies in these functions. Clearing
the active owner alone does not erase earlier copies: enclosing protected-window
and owner-page reclamation remain mandatory. The setup frame also saves XMM6;
that saved caller value is not described as separately erased by the owner.

With `H` the protected window's high address, the selected owner setup frame
reaches `H-7600` and setup completion reaches `H-7024`. The reviewer checks the
recorded copied-state/staging slots fit their frames and protected window.
These are selected frames, **not maximum whole-image depth**. Deeper constructors,
finalizers, sponge/prefix routines and their call frames remain unqualified here.
`__chkstk` and `__umodti3` are explicitly recorded runtime boundaries, not silently
treated as reviewed cryptographic helpers. Arbitrary OS exceptions and
instrumented builds are outside this normal-return review.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-operations.py
python3 scripts/cryptography/windows_enclave_sha3_operations.py \
  release-reports/windows-local-20261004 --mutate
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Ten focused tests pass on Linux and Windows, including semantic-sequence
removal, compiler preconditions, actual incoming/outgoing connections,
readonly table closure, frame changes and geometry limits. Each host rejects
10,191 actual body-byte mutations and 160 table-byte mutations. These mutations
detect review drift, not algorithmic correctness. Parsed reports are identical
and retained outside Cargo target directories under
`release-reports/windows-worker-review-20261005/offline/`.

The ordinary Linux component campaign also passes seven component tests, one
placement test, ten compiled mutation rejections, 628 cSHAKE, 76 NIST and 96
hashlib cases, 512 retained-rehash cases and streamed setup. Remaining worker,
runtime and retest work is tracked in the [checklist](windows-v02450-remaining.md).
The subsequent [state review](windows-enclave-sha3-state.md) extends this work
through construction and fixed-output consumption; deeper helper semantics
remain separate obligations.
