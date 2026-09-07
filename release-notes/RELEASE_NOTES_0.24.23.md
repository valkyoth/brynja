# Brynja 0.24.23 Release Notes

Status: implementation candidate; follow-up local verification passed; owner retest pending

## Scope

- Close the SHA-1/MD5 public contract using the byte-identical v0.24.20 fixture,
  plus bounded ordinary/hardened MD5 batches and optional host fallback APIs.
- Add a downstream no_std/optional-host fixture with 160 frozen batch/mask
  comparisons, failure atomicity, secret-output destruction, recoverable unwind
  and ordinary-build rejection of all four unadmitted CPU candidates.
- Bind native reuse to the unchanged complete source closures. Retain MD5's
  committed original captures. SHA-1's private raw captures are unavailable;
  retain only their historical signed review, without claiming fresh raw
  authentication, new native execution or backend admission.
- Record separate machine-readable implementation, collision-security,
  independent-review, FIPS, modern/default and execution-admission claims.
- Add one shared explicit public-checkpoint register. v0.25.2 and v0.30.2
  replace the planned .0 publication stops; later fifth-minor series use their
  registered closing patches. All ordinary intermediate versions still receive
  signed tags. Historical published tags stay fixed; later-added patches do not
  silently shift a checkpoint. Exceptional security releases remain available.

No production Rust implementation changes. The facade advances to 0.24.23;
all support versions and the exact sanitization 2.1.0 dependency remain unchanged.
This is an internal milestone with **zero crates selected for publication**.
The next cumulative publication/pentest covers `(v0.20.0, v0.25.2]`.

## Verification

The new downstream debug/release consumer and strict Clippy pass locally.
Final-acceptance mutations reject frozen/source/capture drift, omitted checks
and overstated claims. Checkpoint tests cover historical boundaries, early .0
publication rejection, explicit exceptions, missing/malformed entries, complete
cumulative ranges and the shared plan/publisher classification.

Completed locally:

- Complete `scripts/checks.sh`: workspace tests, strict Clippy, documentation,
  package acceptance, source/mutation policies and emitted-code checks.
- All twelve registered Rust lanes from 1.90.0 through 1.98.1 and all three
  bare-metal targets, including the new no_std/optional-host consumer.
- Focused Miri: the complete legacy downstream group and smoke on the nine
  unchanged owner groups. All 29 registered Kani harnesses passed separately.
- AddressSanitizer, including the new fixture. Leak detection was disabled
  because this environment's ptrace restrictions prevent LeakSanitizer.
- Supplemental AArch64 SHA-1/MD5 forced-path QEMU correctness; this does not
  authorize acceleration or replace native evidence.
- Thirty-three final-acceptance mutations plus input-path/read-boundary regressions;
  34 release-policy tests; full roadmap/readiness and semantic Miri regressions.
- Current tooling/admission checks, RustSec audit, cargo-deny and SBOM checks;
  publisher check/dry run confirms zero crates selected.

The previous v0.24.22 full Miri campaigns remain bound to their unchanged
production source and verifier, not relabelled as fresh full runs. SHA-1's
review-hash filename now receives the same tested digest-only classification
as other inventories; changing its coverage keys still selects its full group.

## Limits and release flow

The supplied follow-up assessment contained three Low/informational observations,
not active exploits. The public-vector fixture now uses first-party fixed-width
comparison and tests every mismatch position; a neighboring destructor unwind
test supplements callback panic coverage. The Python reader bounds its actual
read and explicitly requires a trusted, non-concurrently-mutated checkout.
The permanent report records all dispositions; owner retest remains pending.
No production Rust or external dependency changed. The fixture adds an explicit
edge to the same `brynja-core` version it already used transitively.

SHA-1 and MD5 remain collision-broken, isolated and unsuitable for new security
designs. Ordinary states must not own secrets. Hardened state cleanup does not
erase caller/compiler copies, registers/spills, caches, dumps, swap or DMA, and
cannot run after forget, abort or forced termination. No independent review,
FIPS validation or military/classified deployment approval is claimed.

All instruction candidates stay unadmitted. Neither QEMU nor historical native
observations establish migration safety or hardened SIMD cleanup. RISC-V legacy
acceleration and MD5 AVX-512 remain unimplemented and explicitly unsupported.

Complete local checks, obtain the owner pentest, commit its disposition, then
wait for green GitHub/CodeQL and explicit owner permission before tagging.
