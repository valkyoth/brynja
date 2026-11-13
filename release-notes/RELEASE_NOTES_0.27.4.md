# v0.27.4 candidate — RISC-V scalar AES development

Internal candidate; no crates.io publication is selected. Owner pentest/retest,
the existing finite final gate and exact-commit green GitHub/CodeQL remain
pending. These notes do not authorize a tag or claim release approval.

## Scope

The candidate adds RV64 Zkne/Zknd AES-128/192/256 expansion, encryption and
decryption behind an explicit evidence-only build cfg. Both scalar extensions
are required. Ordinary static and hosted routes remain unadmitted, including
when compiler target features are present. No vector-crypto implementation or
new public key owner is added; raw AES remains opt-in and is not a mode or
authenticated encryption protocol.

The [development record](../docs/assurance/aes-riscv-development.md) gives
reproduction commands and scope: packaged direct/facade QEMU consumers, NIST
KAT/MCT/MMT, independent host OpenSSL answers, guarded buffer tests, error/unwind
and authority misuse checks, no_std builds and paired API probes on Rust 1.90.0
and 1.99.1. The [linked review](../docs/assurance/aes-riscv-linked.md) binds
selected instruction bodies and dependencies, including scratch clearing,
session checks, startup, constructors and public/secret output boundaries.

## Limits and release process

The offered native host lacks the AES extensions. QEMU is functional evidence,
not native timing/performance, physical-fault or power/EM qualification.
Bounded linked-code reviews do not establish whole-program constant time,
external runtime correctness or complete register/compiler-spill erasure.
Existing timing limitations and future hardware/fault-profile milestones remain
explicit; no native acceptance is inherited from another architecture.

The facade and consumer pins advance to 0.27.4; supporting-crate versions remain
unchanged under the internal train policy. No dependency is added. The same
30-check finite final gate is retained. Expensive verification campaigns remain
separately selected, not implicit publication requirements. Version-only edits
can invalidate scoped fingerprints: previous runs retain their actual snapshots
and must not be relabelled as new executions.
