<p align="center">
  <b>Security-first, dependency-free, no_std TLS in Rust.</b><br>
  Built in small audited releases with strict modern/legacy protocol isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja Rust TLS crate overview">
  </a>
</p>

# brynja-core

`brynja-core 0.7.0` adds Brynja's allocation-free v0.10 abstract secret
lifetime and destruction-duty contract to the transactional cursors,
caller-owned workspace, and value domains from earlier milestones.

Every arithmetic operation is checked independently of build profile.
Sequence and epoch exhaustion cannot wrap or reuse zero. Budget checks return
the existing typed, limit-value-free exhaustion result without mutating the
budget. Every resource limit is supplied exactly once through a named builder
method; duplicate and incomplete assignments fail with a typed domain-specific
error. Numeric values and budget types intentionally implement neither `Debug`
nor `Display`; the fixed, valueless `NumericError` enum implements `Debug` for
safe diagnostics. `ReadCursor` borrows caller input, advances only after an
exact checked range is available, returns borrowed slices and array references,
and consumes itself when `finish` checks for trailing data. It is not clonable
or formattable, and its value-free errors reveal no input, offset, requested
length, or available length. `WriteCursor` exclusively borrows caller output
and preflights complete single-slice, multi-part, and repeated-byte operations
before changing any byte. Failure preserves the complete buffer and position;
exact completion consumes the cursor. `Workspace` safe-splits one exact-size
caller buffer into named secret, plaintext, transcript, certificate, and output
arenas. Sealed zero-sized domain markers prevent the five simultaneous handles
from being swapped. Complete monotonic allocations track used, remaining,
high-water, and successful non-empty allocation count; rejection preserves both
bytes and telemetry. Allocated bytes retain their caller contents and must be
initialized completely before any read. `SecretDomain` is only a storage
classification, and `CertificateDomain` is not private-key storage. Sensitive
use remains prohibited until the v0.11 proven destruction primitive exists.

`SecretInitialization` is an affine write-acknowledgment state: only exact
complete initialization can produce the non-clonable, non-formattable abstract
`SecretState`. Every partial-init exit, live drop, explicit obsolescence, or
replacement invokes configured local-memory, external-store, accelerator,
cache, and DMA duties. Every configured duty is attempted; any failed duty
produces a terminal failure. Explicit transitions return that failure. Because
`Drop` cannot return it, `SecretDestructor::handle_drop_failure` must make it
durable or initiate a platform fail-stop response before returning; returning
is itself a security assertion that silent continuation is impossible under
the operating contract. The state contains no secret bytes and exposes no
read operation. A destructor completion token is a security assertion by its
caller, not proof of erasure, and this crate intentionally supplies no
production local-memory destructor before v0.11.0. This is not integer
encoding, TLS framing, a
protocol parser, a TLS state machine, cryptography, PKI, a provider, secret
ownership or destruction, or a production-ready transport.

## Protocol Verification Status

The alert, failure, numeric, budget, cursor, workspace, arena, and abstract
secret-lifecycle domains have not been independently reviewed. Project tests,
CI, Kani, Miri, fuzzing, and pentesting do not by themselves constitute
independent protocol verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-core` | Alert, failure, numeric, budget, cursor, workspace/arena, and abstract secret-lifecycle domains | ❌ Not verified |

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.10"
```

The `0.7.0` package is selected for publication with Brynja v0.10.0. The
repository-owner pentest and remediation retest passed; green hosted release
checks remain required under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
