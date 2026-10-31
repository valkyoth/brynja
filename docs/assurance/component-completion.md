# Implement, verify, record, close, and move on

This is the owner-approved development policy for v0.25.3 onward. It replaces
automatic evidence-renewal requirements in routine releases. It applies to
tools, infrastructure and documentation as well as cryptographic components.

## A finite completion target

Before implementing a component, agree its behavior, necessary integrations,
and finite checks. Use existing tests, proofs and evidence mechanisms. When
those checks pass and blocking findings are resolved, close the component.
Do not add more campaigns or acceptance requirements just to increase
confidence after completion.

Adding AES does not reopen MD5. Calling a completed component normally requires
testing the new integration, not repeating the dependency's qualification.
Read its API/contract as needed; that is not a verification campaign. Avoid
incidental changes to completed code, shared build settings or toolchains.

## A named reason is required to reopen work

Reopen only for an implementation change; a relevant dependency, generated
input or effective build-setting change; changed test/proof meaning or a
checker defect; a concrete bug/regression; or an explicit owner request.

Before expensive work, name:

1. The changed input or concrete finding.
2. The previously established property it affects.
3. The smallest checks that address that impact.

Run those checks, record their actual results and close the work again. A new
commit, version, unrelated dependency, reporting change or workflow arrangement
does not itself reopen a component. Do not audit every completed component to
prove that unrelated work did not affect it.

## Tooling problems are not automatic reasons to repeat computation

Distinguish invalid evidence from a gate that cannot match valid evidence.
Fix and test receipt-format, classification or reporting problems at their own
scope. Do not rerun completed computations merely to satisfy bookkeeping.
Python/workflow changes are assessed by meaning: changed assertions, oracles,
selection or assumptions matter; a log-format change alone does not invalidate
the implementation's result.

Preserve original evidence, provenance, failures and incomplete attempts.
Never fabricate a result, call an old result a new execution, or suppress a
meaningful failure. Reuse compatible successes and resume missing work. Do not
repeat an identical successful deterministic check without a concrete reason.

## Three separate responsibilities

- **Component work:** implement its agreed scope, verify, record, close.
- **Evidence tracker:** inspect or explicitly run registered assessments. Its
  report is neither certification nor an automatic release blocker.
- **Release:** clean pentest/retest, finite final checks, push the candidate,
  green GitHub, then publish that candidate without restarting verification.

A full campaign requires an explicitly requested milestone. Neither adding a
component nor publishing to crates.io implies one. Known relevant defects and
required functional checks still must be addressed; separation does not turn
failures into passes.

See the [runner guide](brynja-verify.md) and
[release handoff](../release/scoped-release.md). Historical assurance documents
and captures retain their original scope and limitations.
