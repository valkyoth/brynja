# Brynja v0.24.49

Development candidate: dedicated x86 SHA-512 execution, awaiting owner retest
and register-residual disposition. Not ready for release or final evidence collection yet.
No crates are selected for publication.

- Extend scoped storage to all six named SHA-2 identities, with exact-IV reset,
  byte/bit input and typed secret output. Update failures clear and terminate
  the scoped state. General SHA-512/t now has a parameter-bound scoped workspace,
  typed secret output and all-parameter oracle coverage. Six named execution
  workspaces and a parameter-bound general-t execution workspace now retain
  the engine and CPU scratch in place with existing
  static/hosted authority. Other accelerated scoped APIs remain pending;
  no whole-register/spill guarantee is claimed.
- Add `brynja_hash_sha3::hardened_in_place` for scoped SHA3-224/256/384/512,
  SHAKE128/256 and cSHAKE128/256 workspaces. Handles and readers borrow the active
  owner; finalization does not move that
  owner. Independent scope cleanup covers forgotten handles and recoverable
  unwind. Existing by-value APIs remain unchanged. See the
  [in-place contract](../docs/hardened-in-place.md); wider rollout and complete
  framing/register/spill qualification are still pending, not release-qualified.
- Add four scoped fixed-output SHA-3 execution workspaces with explicit existing
  static/hosted sessions, in-workspace output staging and no owner moves through
  finalization. Authority/revocation behavior is unchanged. Scoped accelerated
  SHAKE/cSHAKE readers remain pending.
- Add an isolated first-party SHA512/AVX2/AVX intrinsic kernel and exact static/raw
  runtime identity, with real startup KAT and irreversible quarantine.
- Connect all ordinary SHA-512-family APIs, including every general-t identity;
  add distinct owner-backed hardened compression without ordinary scratch reuse.
- Preserve generic portable defaults, AVX2 batch routes and the hosted x86
  migration restriction. SHA-NI or AVX-512 alone never authorizes this kernel.
- Record Intel SDE development correctness separately from absent native CPU
  qualification. Keep Rust 1.90 support and no additional dependencies.
- Address pentest instruction-entry, checked-domain, quarantine-reporting and
  automated-coverage findings with private permits, fallible helpers, compiled
  fault probes, explicit ignored tests and a separate path-filtered SDE job.
  Register remnants remain outside the owned-memory clearing guarantee.

See the [API and acceptance status](../docs/x86-sha512-execution.md).
Both compiler endpoints pass development instruction, owner-cleanup and SDE
checks; packaged consumers, five compiled kernel mutants, ten cleanup/identity
mutants and startup/route probes pass. Generic CPU Miri and emulated ASan/LSan
also pass; neither establishes native instruction qualification. Shared assurance
metadata, full workspace tests/doctests, Clippy, documentation and dependency
isolation checks pass. The owner retest/disposition, final source-bound evidence and
release verification remain pending. No release-gate or evidence-reuse policy
changes.
