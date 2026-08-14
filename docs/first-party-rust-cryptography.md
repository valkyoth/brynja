# First-Party Rust Cryptography Policy

Status: enforced golden rule

## Golden Rule

Every cryptographic primitive, construction, key operation, protocol
cryptographic operation, CPU backend, and FIPS cryptographic-module service
shipped by Brynja is implemented from first-party Rust source owned and
reviewed by this project.

Brynja never satisfies that implementation duty by wrapping, linking,
vendoring, calling, or delegating to a foreign cryptographic implementation.
This prohibition includes C, C++, Objective-C, native archives or shared
libraries, OpenSSL, LibreSSL, BoringSSL, AWS-LC, mbedTLS, wolfCrypt, SymCrypt,
and any equivalent external software cryptographic module. A wrapper around
such a module is not a Brynja implementation.

The rule is permanent. Performance, platform support, interoperability,
certification cost, schedule pressure, or convenience cannot weaken it. No
roadmap milestone or release is authorized to reverse it; a project that
replaces Brynja cryptography with a foreign implementation is no longer Brynja
as defined by this policy. An ordinary dependency update, feature, adapter,
provider, build script, or FIPS milestone cannot create an exception.

## Enforced Build Boundary

Repository checks reject foreign source and native binary artifacts in
Brynja-owned package trees, package build scripts, Cargo native-link metadata,
build dependencies, Rust foreign-ABI declarations, and native-library link
attributes. The unsafe inventory independently rejects unapproved low-level
code and FFI. Cargo metadata, lockfile, SBOM, package archives, and admission
checks reject an unreviewed dependency or build edge.

Architecture intrinsics and inline assembly written inside Rust source are not
foreign modules. They remain forbidden by default and may be admitted only as
small, hashed, first-party `brynja-crypto-cpu` implementation symbols after the
primitive- and architecture-specific unsafe, emitted-code, native-hardware,
side-channel, differential, KAT, and audit gates in the release plan. External
assembly files, prebuilt objects, and vendor libraries remain prohibited.
Version 0.13.2 reserved that package and eight symbol identities. Versions
0.22.1 and 0.22.2 implement exact unadmitted x86 SHA, AArch64 SHA2, and RV64
Zknh symbols under separately hash-bound low-level exceptions; no ordinary or
FIPS activation follows from implementation alone.

Caller-provided entropy, external keys, accelerators, or HSMs are outside the
Brynja implementation and claim boundary. They can satisfy an explicit
application provider port only where policy permits; they never become a
Brynja cryptographic implementation, default backend, independent-verification
claim, or Brynja FIPS validation claim.

## Optional Ecosystem Adapters

Future `brynja-rustls` and `brynja-tokio` packages are downstream companion
adapters that applications must select directly. Neither can be a dependency,
feature, re-export, default, or all-features edge of `brynja`, a protocol
engine, a scalar or CPU cryptography package, or `brynja-fips-module`.

Those adapters necessarily depend on the pure-Rust ecosystem API they
implement. This is a narrow integration exception to the core workspace's
third-party dependency prohibition, not an exception to the golden rule:

- `brynja-rustls` uses rustls with default providers disabled and constructs a
  custom provider entirely from Brynja implementations. It must never enable
  rustls's AWS-LC, ring, or `fips` features, delegate a missing operation to a
  built-in provider, or present ordinary Brynja as FIPS validated.
- `brynja-tokio` implements Tokio asynchronous I/O around Brynja's complete TLS
  engine. It does not implement a raw AEAD-over-stream protocol and does not
  depend on `tokio-rustls` or another TLS implementation.

Each adapter owns a separately locked dependency graph, minimal feature
allowlist, latest-version review, advisory review, SBOM, package audit, and
native-code closure check. No adapter dependency is admitted to the main
Brynja lockfile or package graph.

## FIPS Boundary

`brynja-fips-module` contains only the exact first-party Rust cryptographic
implementations and separately admitted first-party Rust CPU symbols frozen
into its validation artifact. It never uses the rustls `fips` feature,
AWS-LC, OpenSSL, a system cryptographic service, or another validated module as
its implementation.

Rust ownership does not itself establish FIPS validation. A FIPS claim exists
only for the exact issued certificate, source and binary identity, approved
services, dispatch table, build inputs, caveats, and listed operational
environments. Ecosystem adapters remain outside that module boundary. Any
future adapter-level approved-operation claim requires its own numbered review
and must consume the certificate-bound module service without changing or
misrepresenting it.
