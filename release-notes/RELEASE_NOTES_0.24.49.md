# Brynja v0.24.49

Development candidate: dedicated x86 SHA-512 execution. Not ready for release,
pentest or native collection yet. No crates are selected for publication.

- Add an isolated first-party SHA512/AVX2/AVX intrinsic kernel and exact static/raw
  runtime identity, with real startup KAT and irreversible quarantine.
- Connect all ordinary SHA-512-family APIs, including every general-t identity;
  add distinct owner-backed hardened compression without ordinary scratch reuse.
- Preserve generic portable defaults, AVX2 batch routes and the hosted x86
  migration restriction. SHA-NI or AVX-512 alone never authorizes this kernel.
- Record Intel SDE development correctness separately from absent native CPU
  qualification. Keep Rust 1.90 support and no additional dependencies.

See the [API and acceptance status](../docs/x86-sha512-execution.md).
Both compiler endpoints pass development instruction, owner-cleanup and SDE
checks; packaged consumers, five compiled kernel mutants, ten cleanup/identity
mutants and startup/route probes pass. Generic CPU Miri and emulated ASan/LSan
also pass; neither establishes native instruction qualification. Shared assurance
integration, remaining scoped checks and the exceptional pentest remain
pending. No release-gate or evidence-reuse policy changes.
