# Retained SHA-256 ownership bridge

Status: **isolated research component**, now linked by the separate
[native retained-worker fixture](windows-enclave-retained-worker-results.md).
It is not a shipping API or production Windows qualification.
Windows strict constructors, Linux behavior and release gates remain unchanged.

[`retained_digest.rs`](../assurance/windows-enclave-probe/retained_digest.rs)
connects the existing first-party in-place hardened SHA-256 workspace to the
retained-result lifecycle model. The owner borrows its destination for its entire
lifetime. Workspace and intermediate output belong to a shorter worker scope;
the retained result can be consumed after that scope has ended.

Hashing uses `finalize_secret`, never the public-finalization API. While the
intermediate secret-output owner is live, its bytes are copied into the retained
slot. Dropping that owner clears the intermediate; a separate staging guard also
clears the caller-supplied staging region on all returns and recoverable unwind.
This is an additional owned intermediate, not a zero-copy claim. Native placement
must put both that intermediate and the workspace inside the protected worker,
and the retained destination in the independently resident allocation.

The owner has no `expose` method and inherits the slot's non-Send/Sync/Copy/Clone/
Debug restrictions. Public export remains explicit and terminal. Failed export
quarantines; malformed tokens/public flags consume the ready result; a busy fill
cannot overwrite it. Tokens remain public routing metadata, not authentication.
The copy closure is a trusted test seam, not an application callback API. A native
adapter must replace it with a fixed OS copy-out or in-enclave operation.

## Verification

```text
python3 scripts/cryptography/test-windows-enclave-retained-digest.py
python3 scripts/cryptography/windows_enclave_retained_build.py <persistent-build-directory>
```

Four Rust tests pass at O0/O2, including twenty independent Python `hashlib`
vectors and retention after staging/workspace scope exit. They cover busy
rejection, cancellation, reuse, stale tokens, abandonment, explicit public
acknowledgment, copy failure, copy unwind, quarantine and closure. Staging and
retained destination clearing are checked separately.

Four compiled lifecycle regressions are rejected at both levels: omitted clearing,
reused generation, ignored token and implicit public export. An additional O2
digest-copy corruption mutant fails the independent oracle. A positive downstream
consumer compiles and ten negative consumers reject ownership traits, direct
storage mutation, escaped storage lifetime, private slot access, secret exposure
and an escaped export borrow. The first downstream check caught an incorrectly
named transitive fixture rlib; the builder naming was corrected and all checks
rerun successfully.

The five isolated library variants also cross-compile for Windows x86-64 MSVC
with Rust 1.98.1, warnings denied and panic=abort. The build record binds compiler,
commands, source hashes and resulting archives outside Cargo's `target/` tree.
Cross-compilation is not native execution or protected-placement evidence.

## Next boundary

The [placement component](windows-enclave-retained-placement-design.md) now tests
checked in-page construction, exclusive ownership, destruction order and full-page
clearing, including strict-provenance Miri execution. The separate native fixture
now exercises that connection using public vectors.

The [native allocation probe](windows-enclave-persistent-slot-results.md) already
tests residency across worker returns, guards and erase-before-release. The
retained-worker fixture adds placement of this owner and destruction before
full-allocation clearing and unlock/free. The next host adapter must preserve
those ownership/lifetime boundaries and retain the actual enclave instance;
a saved token alone is insufficient.

The native fixture covers digest retention, replay, cancellation, close with an
unconsumed result and failed-copy quarantine. Affine host-handle abandonment and
uncertain-completion campaigns remain pending; the fixture's internal token is
not a host-owned result capability.
