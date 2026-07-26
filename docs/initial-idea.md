Worked for 1m 47s

“Internal” did not mean private, closed-source, or unavailable to users. It meant an implementation detail inside the public Brynja repository that users are not expected to depend on directly.

Your original plan’s workspace-plus-facade model is sound; the main question is which workspace members should become independently published crates.

1. Public source versus crates.io packages

These are separate decisions:

Public repository: All Brynja source code is visible on GitHub.
Rust crate/package: A compilable package containing a Cargo.toml.
Published crates.io package: A package users can add as a dependency.
Public API: Types and functions for which you promise compatibility.

You can have a completely public repository like:

brynja/
├── crates/
│   ├── brynja/
│   ├── brynja-core/
│   ├── brynja-crypto/
│   ├── brynja-pki/
│   └── brynja-tls/
├── fuzz/
├── tools/
├── test-support/
└── proofs/

without publishing every directory to crates.io.

2. What I meant by internal crates

I used “internal crates” for components such as:

brynja-wire
brynja-secret
brynja-math
brynja-crypto-soft
brynja-crypto-arch
brynja-asn1
brynja-test-support

However, for your project, I would revise that wording and reduce the number of actual internal crates.

A crates.io package cannot normally depend on an unpublished path-only runtime dependency. If brynja depends on brynja-wire as a separate package, then brynja-wire generally also needs to be published with a version, or its code needs to be incorporated into one of the published packages. Local-only development dependencies and tools are a different case.

Therefore, I recommend making most of those internal modules, not separate crates:

brynja-core/
└── src/
    ├── wire/
    ├── buffer/
    ├── secret/
    ├── error/
    ├── state/
    └── provider/
brynja-crypto/
└── src/
    ├── math/
    ├── hash/
    ├── mac/
    ├── aead/
    ├── rsa/
    ├── ecc/
    ├── portable/
    └── arch/
brynja-pki/
└── src/
    ├── asn1/
    ├── der/
    ├── pem/
    ├── x509/
    ├── path/
    └── revocation/

These modules are still completely public source. They simply do not create dozens of tiny crates.io packages.

3. Recommended crates.io structure
Main production packages

These should be published:

brynja
brynja-core
brynja-crypto
brynja-pki
brynja-tls
brynja-tls12
brynja-tls13
brynja-tls13-handshake
brynja-quic-tls
brynja-platform
brynja-dtls

The main brynja package is the convenient facade:

[dependencies]
brynja = "1"

Internally it could depend on:

brynja-core
brynja-crypto
brynja-pki
brynja-tls

Users could also depend directly on brynja-crypto or brynja-pki when they need those components independently.

Repository-only packages

These can remain unpublished:

brynja-test-support
brynja-fuzz
brynja-interop-runner
brynja-vector-generator
brynja-xtask
brynja-proof-harness

They can still be public and used by contributors, CI, pentesters, and auditors.

4. What “legacy protocols remain separate” means

It means separation at four levels:

Separate crates.io package
Separate Rust API
Separate configuration and state
Separate runtime connection path

For example:

brynja-legacy-ssl3
brynja-legacy-ssl2
brynja-legacy-tls10
brynja-legacy-tls11
brynja-legacy-wtls
brynja-legacy-pct
brynja-legacy-snp

Someone needing SSL 3.0 could write:

[dependencies]
brynja = "2"
brynja-legacy-ssl3 = "2"

Then:

use brynja::tls13::Client as ModernClient;
use brynja_legacy_ssl3::Client as LegacySsl3Client;

Both are public Brynja crates. They simply cannot be confused with one another.

5. Would SSL 3.0 be enabled through the main brynja crate?

Under my strictest recommendation: no.

The user would explicitly add:

brynja-legacy-ssl3 = "2"

rather than:

brynja = { version = "2", features = ["ssl3"] }

This is intentional. Cargo features are additive, and when multiple dependencies enable features on the same package, Cargo ordinarily builds the union of those features. Cargo specifically recommends splitting functionality into separate packages when feature combinations represent conflicting behavior or boundaries that should not be silently merged.

Suppose an application uses:

my-application
├── brynja
└── old-device-library
    └── brynja feature "ssl3"

The application could end up compiling brynja with SSL 3.0 even though the application author never selected it directly. That would not necessarily make the modern TLS client negotiate SSL 3.0, but it makes the dependency graph and security claim less obvious.

With a separate package, the graph clearly shows:

my-application
├── brynja
└── brynja-legacy-ssl3

There is no ambiguity about legacy code being present.

6. The ergonomic compromise: brynja-legacy

A good compromise would be to publish a second facade:

brynja              # Modern production facade
brynja-legacy   # Explicit legacy facade

A user could then write:

[dependencies]
brynja = { version = "2", features = ["tls13", "tls12"] }

brynja-legacy = {
    version = "2",
    default-features = false,
    features = ["ssl3"]
}

The legacy facade would internally select the relevant package:

[features]
ssl3 = ["dep:brynja-legacy-ssl3"]
ssl2 = ["dep:brynja-legacy-ssl2"]
tls10 = ["dep:brynja-legacy-tls10"]
tls11 = ["dep:brynja-legacy-tls11"]
wtls = ["dep:brynja-legacy-wtls"]
pct = ["dep:brynja-legacy-pct"]
snp = ["dep:brynja-legacy-snp"]

Then users get a convenient unified namespace:

use brynja::tls13::Client;
use brynja_legacy::ssl3::Client as Ssl3Client;

I think this gives you the best balance:

brynja
└── Modern, production-safe protocols

brynja-legacy
├── TLS 1.1
├── TLS 1.0
├── SSL 3.0
├── SSL 2.0
├── WTLS
├── PCT
└── SNP

Everything remains public and available on crates.io, but a normal cargo add brynja never introduces legacy protocols.

7. Could the main crate still offer legacy features?

Technically, yes:

[dependencies]
brynja = {
    version = "2",
    default-features = false,
    features = ["tls13", "legacy-ssl3"]
}

And Brynja could implement:

[dependencies]
brynja-legacy-ssl3 = { version = "2", optional = true }

[features]
legacy-ssl3 = ["dep:brynja-legacy-ssl3"]

with:

#[cfg(feature = "legacy-ssl3")]
pub mod legacy {
    pub use brynja_legacy_ssl3 as ssl3;
}

That is possible and would not automatically make the normal TLS engine negotiate SSL 3.0, provided the APIs remain completely separate.

However, I would still prefer brynja-legacy because:

cargo add brynja has an unambiguous modern-security meaning.
--all-features on brynja does not pull in every broken protocol.
Transitive dependencies cannot enable SSL code inside the modern facade.
Modern documentation remains focused.
Security scanners can identify legacy use from package names.
Dependency policies can reject brynja-legacy-ssl3 without rejecting modern Brynja.
Future audits can certify the modern package without including SSL.
Removing or changing a legacy protocol does not disturb the modern facade.
8. Separate does not mean the user cannot combine them

A migration tool can deliberately use both:

[dependencies]
brynja = { version = "2", features = ["tls13"] }
brynja-legacy = {
    version = "2",
    default-features = false,
    features = ["ssl3"]
}

For example:

let modern_listener = brynja::tls13::Server::new(modern_config);

let old_device_listener =
    brynja_legacy::ssl3::Server::new(legacy_config);

But this must be prohibited:

// Do not design this API.
let config = BrynjaConfig::builder()
    .minimum_version(ProtocolVersion::Ssl3)
    .maximum_version(ProtocolVersion::Tls13)
    .build();

That creates one negotiable range from SSL 3.0 through TLS 1.3, which is exactly the boundary we want to avoid.

Instead:

let modern = brynja::tls::ServerConfig::tls13(...);

let legacy =
    brynja_legacy::ssl3::ServerConfig::new(
        LegacyAuthority::for_controlled_interop(...)
    );

There should be:

No shared version enum.
No shared negotiation builder.
No shared session cache.
No shared ticket keys.
No fallback from one engine to another.
No “try modern, then try SSL 3.0” convenience method.
9. My final recommendation

Use this arrangement:

Published modern crates
├── brynja
├── brynja-core
├── brynja-crypto
├── brynja-pki
├── brynja-tls
├── brynja-tls12
├── brynja-tls13
├── brynja-tls13-handshake
├── brynja-quic-tls
├── brynja-dtls
└── brynja-platform

Published legacy facade
└── brynja-legacy

Published legacy implementation crates
├── brynja-legacy-tls11
├── brynja-legacy-tls10
├── brynja-legacy-ssl3
├── brynja-legacy-ssl2
├── brynja-legacy-wtls
├── brynja-legacy-pct
└── brynja-legacy-snp

Public but unpublished repository packages
├── brynja-research-ssl1
├── brynja-test-support
├── brynja-fuzz
├── brynja-interop
├── brynja-xtask
└── brynja-proofs

So the answer to your main question is:

Yes, users can absolutely use SSL 3.0 when they genuinely need it. But I would make them opt in through brynja-legacy-ssl3 or brynja-legacy, rather than enabling SSL 3.0 as an ordinary feature of the main modern brynja package.

10. Final package-lifecycle refinement

The modern `brynja-tls` package should remain an evergreen facade and one-pass
version router rather than becoming synonymous with TLS 1.3. Version-specific
implementations live in `brynja-tls12`, `brynja-tls13`, and
`brynja-tls13-handshake`; a future TLS generation receives a new package and an
independent implementation and audit line.

An older TLS generation does not become legacy merely because a successor
exists. If standards or cryptographic evidence later require retirement, a
dedicated release removes it from every modern dependency and negotiation path.
Only then may controlled interoperability continue through a newly isolated
`brynja-legacy-tls1N` package. The former modern crate is deprecated and
never forwards silently into legacy code.
