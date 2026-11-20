# AES fault-integrity research prototype

This is an unfinished, **non-production** research snapshot. It is not a
fault-resistant AES implementation, a supported API, a release gate, or a
claim of physical-fault protection. Ordinary Brynja AES and the external-key
provider do not depend on it.

The prototype's AES composition lives in `crypto/fault_integrity/`, and its
comparison experiments live in `core/fault_comparison_workbench/`. These files
are outside published crate packages. The production source trees contain only
small, explicitly gated research bridges; no Cargo feature enables them.

From the repository checkout, its functional unit tests can be run with:

```sh
RUSTFLAGS='--cfg brynja_fault_profile_research --cfg brynja_fault_primitives' \
  cargo test --locked -p brynja-crypto --features hazmat-aes-block --lib
```

The extra `brynja_fault_evidence` cfg enables source-level corruption fixtures
for research tests. It changes test code generation and must not be treated as
evidence about an ordinary build. The scripts named `check-aes-fault-*` under
`scripts/aes/` and the records under `assurance/aes-fault-*` are historical
development observations. Many native scripts require the exact previously
pinned test ELFs; a rebuild does not inherit those observations.

The [design](../../docs/assurance/aes-fault-profile-design.md) and
[review log](../../docs/assurance/aes-fault-profile-review.md) explain the
bounded model, accepted outcome-leakage residual, and open work. The current
inventory still marks every source and bypass family open. Do not expose this
prototype as a public API or use it to protect real keys.
