# HKDF public API usability acceptance (0.26.1)

From the repository root, run:

```sh
python3 scripts/hkdf/check-hkdf-public-api.py
```

This checks both consumers against **unpacked `.crate` archives**, not checkout
source paths. It does not upload anything, install tools, access the network or
change release approval. Rust 1.90.0 and 1.99.1 and their
`thumbv7em-none-eabi` targets must already be installed. No Cargo registry cache
is needed for this first-party packaged graph. Provision tools explicitly before running the offline
command; missing prerequisites fail rather than skip checks.

The runner creates temporary packages with `cargo package --no-verify`, then
tests the consumers against those packages. The flag avoids Cargo's separate
default package build: it does **not** bypass the subsequent consumer builds,
tests or compiler rejection checks. First-party dependency patches point only
to unpacked archives. A graph check rejects checkout fallback and any legacy
dependency in the modern consumer. Temporary consumers have their own profiles;
these are downstream debug/release builds, not the repository's optimized
erasure qualification profile.

Packaging runs in a private workspace containing only the selected first-party
crate closure, preserving the repository's inherited metadata, lints and
profiles. Every crate in this closure has an explicit Cargo `include` list;
the runner accepts only the reviewed manifest/license/README/Rust-source forms
(plus Rust tests for the two HKDF implementation crates). It copies only those
inputs, rejects symlinked inputs and checks the unpacked archive's file set and
source bytes, including `Cargo.toml.orig`, against the checkout. Cargo-generated
normalized manifests, lockfiles and VCS metadata are treated separately; this
is source-content parity, not byte-identical archive or release-provenance proof.
Untracked source matching an explicit include remains eligible, just as it is
for Cargo publication; a committed release candidate must still be clean.
Git ignore rules are not used as a surrogate for package selection. Unknown or
missing include policies fail closed and require an explicit runner review.

The runner uses an empty private Cargo home and an environment
allowlist, not the user's Cargo configuration or cache. Cargo target runners,
wrappers, flags, profile overrides, loader hooks and temporary-directory
overrides are not inherited. Working-directory ancestor and private-home Cargo
configs (including dangling symlinks) are rejected before each Cargo invocation.
The temporary workspace lives under the repository's owned `target` directory;
group/world-writable ancestors are rejected. Installed tools, PATH, the rustup
toolchain store and repository commands remain trusted local inputs. This is
configuration isolation, not an OS sandbox for an untrusted repository.

## Scope

- `assurance/hkdf-public-api` depends only on the modern `brynja` facade with
  default features disabled. SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and
  SHA-512/256 are selected explicitly through public types.
- `assurance/legacy-hkdf-public-api` depends separately on
  `brynja-legacy-hkdf` and supplies `LegacyUse::acknowledge()`. It cannot be used
  as a modern TLS derivation provider.
- Both library fixtures are `no_std`, forbid unsafe code and use fixed-size
  caller buffers, with no allocator. Host tests use the normal Rust test
  harness, and `std` only inside the test module for consumer-unwind and
  redacted-Debug checks.
- All seven RFC 5869 cases compare both PRK and output. Additional checks cover
  every admitted SHA-2 identity, frozen block-255 answers, empty output,
  one-byte and partial-block output, maximum output and over-limit requests,
  absent/empty/zero salt, PRK import, irregular borrowed subslices, explicit
  clearing and Drop during normal completion and consumer unwind.
- Multipart `info` is compared with contiguous input at every split of a
  129-byte input, with empty lists/parts, one-byte parts, reordered/repeated
  parts and output-block boundaries. RFC answers and block-255 answers also
  exercise multipart expansion. Both APIs use the same production expansion
  engine; agreement alone is not an independent cryptographic oracle.
- TLS examples exercise `key`, `iv`, `finished` and `derived` framing on
  SHA-256/SHA-384, compare both public label helpers with explicitly encoded
  raw Expand input, and check length binding and label/context limits. These
  are framing examples, not a TLS key schedule or transcript validation.
  Published [RFC 8448 section 3](https://www.rfc-editor.org/rfc/rfc8448#section-3)
  early/derived-secret values and [RFC 9001 Appendix A.1](https://www.rfc-editor.org/rfc/rfc9001#appendix-A.1)
  initial/client/server secrets, keys, IVs and header-protection keys are checked
  through both public label helpers, with clearing and canary checks.

The output bound is `255 * HashLen` bytes. Pre-admission errors preserve the
destination unchanged; they do not return partial derived output. Accepted
output owners clear their borrowed region on Drop or explicit `clear()`.
The public API exposes no way to inject an internal HMAC failure. Internal
partial-output rollback and scratch cleanup remain covered by the separate
`hkdf/fault-cleanup` and `legacy_hkdf/fault-cleanup` checks; the downstream
fixture does not claim to reproduce that internal fault injection.

Negative compiler probes require a nearby successful control and an exact
Rust diagnostic sequence at consumer source spans (one error per probe, except
the two required supertrait rejections for sealed admission). They reject cross-hash PRK
substitution, overlapping label/output borrows, private label encoder access,
implicit modern SHA-1 selection, missing legacy acknowledgement and a legacy
TLS-label helper. They also reject downstream algorithm implementation,
Send/Sync/Copy/Clone/Debug for both PRK and output owners, using either owner
after clear, multipart info/output overlap, and output outliving its buffer.
There are 19 modern and 16 legacy
probes per compiler. A dependency build failure or arbitrary compile failure is
not accepted as proof. Fixture assertion failures expose only a generic API or
contract error, not PRK/output bytes. All inputs are synthetic public test data.

## Matrix, targets and verification records

The default command runs debug/release tests and compiler probes on both
endpoint compilers, plus compile-only Cortex-M checks. For all 14 supported
host compilers from Rust 1.90.0 through 1.99.1:

```sh
scripts/ci/check-rust-version-matrix.sh --hkdf-public-api
```

This selection still compiles bare-metal only at the two endpoints. It does
not silently install missing intermediate compilers or run other components.
`--family modern` or `--family legacy` narrows either command. The existing
explicit bare-metal campaign also includes both checkout fixtures.

To record scoped observations using the local verifier:

```sh
brynja-verify run hkdf packaged-public-api
brynja-verify run legacy_hkdf packaged-public-api
brynja-verify run hkdf public-api-matrix
brynja-verify run legacy_hkdf public-api-matrix
```

Package checks are in category `package`; the full host checks are in `matrix`.
These overlap intentionally: use exact IDs to choose endpoints or the full
matrix. Registration alone is not a pass. GitHub runs the endpoint acceptance,
fixture formatting/lint and runner regressions in a dedicated job; it does not
launch dynamic analysis, proofs, timing or the full host matrix implicitly.

## Explicit dynamic verification

The downstream checkout fixtures also have ASan/LeakSanitizer registrations for
their complete suites (five modern tests and four legacy tests). Focused Miri
registrations execute the exact `tests::ownership` test in each fixture and
`tests::tls` in the modern fixture. Ownership includes import/admission errors,
irregular borrowed storage, explicit clearing and Drop during consumer unwind.
The ownership cases include multipart input, empty parts, and input/list storage
going out of scope before the returned output owner. Internal Miri fault cases
also inject errors and unwinds at individual part boundaries.
Miri does not run the expensive maximum-output loops in these fixtures.

```sh
brynja-verify run hkdf asan-public-api
brynja-verify run legacy_hkdf asan-public-api
brynja-verify run hkdf miri-public-api-ownership
brynja-verify run hkdf miri-public-api-tls
brynja-verify run legacy_hkdf miri-public-api-ownership
```

These require the existing `nightly-2026-09-11` toolchain, Miri setup and Linux
x86-64 environment. Missing tools fail; no installation is implicit. The
registrations bind the instrumentation flags, fixture and dependency inputs,
exact test counts and successful completion. The separate registry regression
test rejects weakened instrumentation and incorrect test populations.

Use `run COMPONENT --all --category asan` or `--category miri` to rerun both the
existing implementation checks and these downstream checks. Dynamic checks use
checkout dependencies, not unpacked archives; do not conflate them with the
separate packaged-consumer checks above. Results remain local observations,
not signed certification or a publication prerequisite imposed by the runner.

The fixture is downstream usability evidence, not independent cryptographic
review, constant-time certification, full compiler erasure qualification or
target runtime testing. The limits in `docs/VERIFICATION_STATUS.md` and
`docs/security-controls.md` still apply. Legacy SHA-1 remains compatibility-only.
The user requires a pentest before the final gate, including this development
milestone. No crates.io publication is requested by this acceptance milestone.

## Pre-remediation local verification pass — 2026-11-03

Both packaged consumers passed again across all 14 supported host compilers,
with debug/release tests, diagnostic-checked negative controls and endpoint
Cortex-M builds. All six registered HKDF ASan/LSan checks and seven registered
Miri checks were executed successfully, including the five new downstream
registrations above. Scoped timestamps, fingerprints and logs are retained in
`verification/results.json`; no historical result was promoted to a fresh run.

The 13 packaged-runner tests, 169 registry tests, 50 verifier Rust tests,
catalog tests, fixture formatting/Clippy, and the current finite local check
commands passed. The first registry run exposed a test-loader omission for
the included Miri tool group; the loader was corrected and all 169 tests rerun
successfully. Workspace and standalone verifier RustSec scans, dependency
policy and the committed SBOM check passed as well.

This validates the working-tree acceptance work, not a committed 0.26.1 release
candidate. Release metadata and the finite release plan still identify 0.26.0;
their 0.26.1 preparation, commit and exact-candidate GitHub/CodeQL results remain
pending. That earlier pass changed no production implementation and made no tag
or upload. It predates the remediation below and does not approve those changes.

## Candidate pentest disposition — 2026-11-03

The submitted Daybreak/Claude reports reviewed an uncommitted candidate.
`HEAD` and `v0.26.0` both identified
`df290dad14b744845d43289ca06c7b8ec23ca44d`; an empty committed range is not
approval of 0.26.1. Claude explicitly excluded the generated results diff.

1. **Medium, packaged-runner isolation:** accepted. The direct Python entrypoint
   inherited open-ended Cargo overrides and used a shared temporary ancestor.
   It now uses the private workspace/home/allowlist and configuration checks
   described above. The Rust `brynja-verify` runner already clears the environment;
   inventing prefix rules in the unrelated historical `run-verification.py`
   would not fix the direct entrypoint. Both entrypoints use the corrected script.
   Regression tests cover override stripping, config poisoning/dangling links,
   subprocess refusal, private location, inherited workspace settings and scope.
2. **Low, external TLS vectors:** accepted as an interoperability evidence gap,
   not a demonstrated derivation defect. Published TLS/QUIC trace values now
   supplement self-consistency tests; both public label helpers are exercised.
3. **Low, public compiler-contract coverage:** accepted. Diagnostic-checked
   packaged probes now exercise admission, trait restrictions and lifetimes,
   with positive controls on every tested compiler. Unexpected/missing/extra
   diagnostics, dependency-span errors and failed positive controls cannot pass.
4. **Low, label Debug exposure:** accepted. Production `Tls13Label::Debug` now
   reports lengths only. Equal-length different contents must format identically
   in normal and alternate Debug modes. Copy remains: it copies shared borrows,
   not secret ownership. The caller's storage/clearing responsibility is explicit.
5. **Informational, completeness:** RFC 5869 Extract/Expand, separate imported
   PRKs, all six admitted SHA-2 identities, caller-buffer clearing and TLS framing
   are implemented. Multipart `info` was identified as a worthwhile ergonomic
   extension for bounded/no-allocator protocol code; the user subsequently
   authorized its implementation in this milestone (see below). Contiguous
   input alone was not an interoperability defect.
   Thread-transferable secret owners would change the established ownership
   boundary and are not silently introduced. Same-worker/local-task usage is now
   documented. Per-block HMAC re-keying is a documented performance cost; caching
   state needs separate lifecycle/fault/zeroization review, not an untested
   optimization. TLS transcript/key-schedule integration remains separate work:
   the handshake crate explicitly reports `IMPLEMENTED = false`, so it currently
   contains no competing ad-hoc derivation implementation. The fixture's byte/
   block-boundary comment was corrected.

These dispositions do not establish full protocol support, independent timing
qualification or production certification. A committed-candidate retest and
final release checks remain separate from this local remediation.

### Remediation validation

- `brynja-verify run hkdf --needed` reran all 22 affected modern registrations:
  packaged endpoints and the 14-compiler matrix, three ASan/LSan and four Miri
  checks, portable/optimized tests, compiler/ownership checks, no_std target,
  four bounded Kani harnesses and the limited host timing screen all passed.
- `brynja-verify run legacy_hkdf --needed` reran the two changed package/matrix
  registrations and the shared-input bounds-proof registration. All 19 legacy
  registrations are current passes; unchanged scopes retain their prior run
  dates, not fabricated new executions.
- Direct packaged acceptance for both families on 1.99.1 passed with deliberately
  poisoned Cargo home, wrapper, runner, flags, profile and temporary-directory
  environment overrides. The real builds used the isolated environment.
- All 18 packaged-runner unit tests and 169 registry tests passed. The existing
  facade package-control regressions also passed, including its configuration
  isolation cases. Fixture formatting and Clippy with warnings denied passed on
  1.99.1; modern fixture tests and lint also passed on the 1.90.0 MSRV.
- Every command in the finite 18-check CI selection passed after correcting the
  release-plan's required milestone wording. The CI wrapper's final clean-tree
  check correctly refused overall approval because this candidate is still
  uncommitted. This is command-level validation, not a clean-candidate final gate.

The temporary `PENTEST.md` was removed after recording these dispositions and
validation results. No commit, tag, push or publication was performed.

## Multipart info extension

Both modern `Prk` and isolated legacy `Sha1Prk` now provide
`expand_parts(&[&[u8]], destination)`. Existing `expand` delegates with one part;
its output, admission and cleanup contracts are unchanged. For example:

```rust,ignore
let parts: [&[u8]; 3] = [b"application-v1", b"/", b"encryption-key"];
let key = prk.expand_parts(&parts, &mut output)?;
// Use key.expose() within the intended secret boundary; Drop clears output.
```

This is plain ordered byte concatenation, not tuple encoding or automatic
domain separation. Callers supply protocol framing and bound input size and
part count, including empty parts. No concatenation buffer or allocator is
required, and the output owner borrows only its destination. Input copies and
storage remain the caller's clearing responsibility. No streaming output,
cached HMAC state or thread-transferable ownership is introduced.

TLS label helpers are unchanged. Full TLS transcript/key-schedule integration
remains at the planned v0.109.0 milestone; this extension does not implement it.

### Multipart validation — 2026-11-03

- Scoped `--needed` runs completed 21 modern and 18 legacy registrations.
  All 22 modern and 19 legacy registrations are now current passes. The two
  unchanged bounded-proof scopes retain their earlier successful executions;
  no new multipart proof or historical-result promotion is claimed.
- Both packaged matrices passed on all 14 host compilers, with debug/release
  suites (five modern/four legacy tests), 19 modern/16 legacy diagnostic probes,
  and Cortex-M compilation on both endpoints. No upload was performed.
- All six ASan/LSan and seven Miri registrations passed, including multipart
  borrowing and injected errors/unwinds after individual parts and earlier
  output blocks. All six modern identities and legacy SHA-1 also passed native
  and optimized fault tests. The maximum-output tests still compare independent
  frozen block-255 answers; multipart RFC tests retain the published answers.
- Operation-scratch checks passed all four compiler/panic configurations per
  family, with 24 modern/three legacy consumers and 180/25 rejected cleanup
  mutations per build. Public-owner checks also passed. The existing bounded
  timing screens reported no alarms; these are not multipart side-channel
  certification or independent qualification.
- All 18 packaged-runner regressions, 169 registry tests, both packages' tests
  and doctests with all features, and fixture Clippy with warnings denied on
  Rust 1.90.0/1.99.1 passed. Formatting and diff checks passed. All 18 finite CI
  check commands passed, including source-review policy and downgrade controls.
  This is command-level validation, not a clean-candidate final release gate.

Validation caught stale compiler-population expectations, two test-input style
warnings, and the deliberately fail-closed reviewed-source fingerprint check.
The expectations and four reviewed-file fingerprints were updated after review
and testing; no ownership requirement or qualification claim was relaxed. One
matrix attempt was deliberately interrupted before editing the lint-affected
fixtures; its later complete execution passed and the interrupted attempt
remains recorded. Logs, timestamps and fingerprints are in the local verifier.

This working tree is not committed or release-approved. Candidate preparation,
commit, the user's pentest retest and final gate/GitHub checks remain pending.

## Follow-up pentest disposition — 2026-11-03

The latest report confirms the previous remediations and multipart expansion,
and corrects the earlier suggestion that the verifier's environment denylist
was its only isolation boundary. It reports one new Low finding, accepted here:
copying whole crate directories into a non-Git workspace allowed unintended
files into archives for crates without explicit include lists.

The 12 affected crate manifests now have explicit include lists, preserving
their existing source, documentation, licenses and HKDF test files. The other
crates in the tested dependency closure already had explicit includes. Only
declared package inputs are copied, and every unpacked archive must match the
selected source files and bytes before any downstream test is accepted. This
avoids tracked-only copying, which would incorrectly omit ignored/untracked
files that Cargo deliberately admits through an explicit `include` pattern.
No cryptographic production implementation or public API was changed for this
finding, and no publication was performed.

Regression coverage includes real Git/private-workspace Cargo archive parity
with synthetic `notes.key`, `PENTEST.md` and ignored-but-explicitly-included Rust
source; rejected missing/unknown include policies and symlinks; added, removed
or altered archive members and original manifests; and a real family run that
must stop on an injected extra archive member before building its consumer.

The informational multipart-vector suggestion is addressed by asserting the
multipart result directly against each published RFC 5869 answer in both
fixtures, in addition to the existing contiguous comparison. The symbol-match
observation requires no change: exact consumer selection, cycle rejection and
compiler cleanup mutation checks remain in force. Personal/ancestor Cargo
configuration remains intentionally rejected as already documented above.

### Follow-up validation

- All 25 packaged-runner tests passed, including real archive parity and the
  injected-extra-member failure before consumer execution. All 169 verification
  registry tests passed.
- The modern and legacy packaged endpoints and full 14-compiler matrices passed
  with archive file/content validation enabled, direct multipart RFC assertions,
  diagnostic rejection controls and endpoint no_std Cortex-M compilation.
- Scoped `--needed` reran five modern and four legacy affected registrations:
  package/matrix checks and the downstream ASan/Miri checks. All 22 modern and
  19 legacy observations remain current passes; unchanged implementation,
  compiler, proof and dynamic scopes retain their previous execution dates.
- Fixture Clippy with warnings denied, formatting and diff-integrity checks
  passed. All 18 finite CI check commands passed after the release inventory
  correctly classified nine previously unchanged package entries as
  metadata-only. No version or publication selection changed. This does not
  constitute a clean committed-candidate release gate.

The temporary `PENTEST.md` was deleted after preserving this disposition and
validation record. Repository changes remain uncommitted; no tag, push or
publication was performed. The normal committed-candidate retest and final
gate remain pending.
