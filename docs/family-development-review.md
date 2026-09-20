# End-of-milestone hardening and acceleration review

Run this inexpensive **development checklist** for every new or extended family,
at design time and again before calling its implementation milestone complete:

```sh
python3 scripts/release/check-family-completeness.py --version 0.25.0 --closing-version 0.25.2
```

It reports missing decisions and lists existing follow-up milestones. No record
means **review needed**, never an automatic pass. It does not run Cargo, Miri,
Kani, sanitizers, network checks, or a release gate. It does not change tagging,
publication, approval, CPU admission, evidence reuse, or the existing planner.
Run it manually as part of development handoff; it is deliberately not wired
into CI or the release gate. Its regression tests are equally inexpensive:

```sh
python3 scripts/release/test-family-completeness.py
```

## Review, do not infer completion from a feature name

The seventeen required dispositions cover:

- Public API completeness, portable correctness and extracted-package usability.
- Owned secret memory, kernel registers, compiler spills and caller transfers.
- Success, errors, cancellation, revocation, unwind, Drop and abort limitations.
- Constant-time behavior and sensitive length/shape metadata.
- Dedicated x86 and Arm instructions, other targets, single-state SIMD,
  independent-message SIMD and useful bounded threading.
- Optional dispatch, real platform authority, quarantine and portable fallback.
- Linux, macOS and Windows ABI/runtime evidence, and measured performance.

For **each relevant identity, ordinary/hardened profile and backend**, describe
the coverage and gaps in the reason/evidence entries. A row must not say merely
"SIMD done" when only the ordinary path exists. Inherited primitive acceleration
must be exercised through the new caller, with secret ownership preserved.
Hardware absence in our current machines is not proof that an instruction does
not exist. Neither a filename scan nor this checklist can discover all useful
algorithms/instructions or prove correct hardening; the reviewer must inspect
the implementation and authoritative architecture material as appropriate.

In particular, do not repeat the v0.24.49 boundary mistake: owned-memory cleanup
does not establish register/spill cleanup, kernel cleanup does not establish
caller/framing/transfer cleanup, and a no-marker diagnostic does not prove
complete erasure. Record the precise supported guarantee, unsupported targets,
and abort/interruption/platform-storage exclusions. Preserve caller ABI state.
Native Windows evidence is distinct from Linux, cross-compilation and emulation.

## Recording decisions

Generate an **unreviewed** template; creating it is not an approval:

```sh
mkdir -p target
python3 scripts/release/check-family-completeness.py --version 0.25.0 --closing-version 0.25.2 --template > target/hmac-family-review.json
```

Fill in reviewer, scope, and every decision. Each decision has:

- `status`: `needs-review`, `reviewed`, `inherited`, `not-applicable`, or `planned`.
- `reason`: identities/profiles/backends covered, technical rationale, limitations
  and unresolved work. `reviewed` means a documented disposition, **not secure**.
- `evidence`: repository-relative file paths mapped to SHA-256 digests. Use
  reviewed implementation reports, exact test results, platform/ABI records and
  explicit limitations; a test script alone is not evidence that it passed.
  Obtain file digests with `sha256sum path/to/file`. All references are checked.
- `follow_up`: null except for planned work; either a later existing milestone
  in the same minor no later than closure, or null to request a new milestone.
  A planned milestone must also bind `docs/RELEASE_PLAN.md` in `evidence`; the
  reviewer must verify that its actual deliverables cover the missing work.

```sh
python3 scripts/release/check-family-completeness.py --version 0.25.0 --closing-version 0.25.2 --review target/hmac-family-review.json
```

Use `--json` for a machine-readable report. Exit 0 means **review recorded**,
2 means follow-up/review/evidence remains, and 1 means invalid or stale input.
Planned work always remains outstanding; attaching a future version does not
make it implemented. A non-applicable or inherited decision requires evidence
and rationale just like a reviewed implementation. This is a trusted maintainer
review record, not authenticated third-party approval or security certification.

Keep a completed record in the family's documentation/evidence directory when
ready. The record binds current/closing roadmap sections and a conservative
workspace Rust/manifests/configuration fingerprint, including dirty and
untracked non-ignored sources and shared code. Documentation-only changes do
not invalidate that implementation fingerprint, but changes to cited evidence
do. This fingerprint is not a full compiler/dependency evidence closure and
does not replace any existing verifier. An invalidated checklist calls for
reviewing the changed decisions, **not automatically rerunning expensive tests**.
Reuse existing verification when the existing planner permits it; do not simply
refresh hashes to conceal stale evidence.

## When another patch is needed

For HMAC, first examine the already planned `0.25.1` and `0.25.2` work. It may
inherit appropriate hash acceleration, but still needs its own keyed setup,
verification, cleanup, failure, package and backend-routing evidence. Do not
assume that ordinary public-data hash acceleration is usable for secret HMAC.

If a useful promised profile does not fit those milestones, report the gap,
add review-sized numbered patches and move family acceptance after them using
the existing roadmap process. Keep prerequisite ordering and final-minor
publication scheduling consistent. The tool intentionally does not renumber
versions or create speculative implementation commitments automatically.
RISC-V native qualification can remain explicitly post-1.0 as planned; record
that limitation without presenting it as completed native support.
