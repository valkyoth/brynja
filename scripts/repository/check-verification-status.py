#!/usr/bin/env python3
"""Fail closed when README independent-review status is absent or overstated."""

from __future__ import annotations

import re
import sys
from pathlib import Path


HEADING = "## Cryptography Verification Status"
ROOT_READMES = (Path("README.md"), Path("crates/brynja/README.md"))
ROOT_ROWS = (
    "| SHA-2 | ✅ Fully implemented | `brynja-hash-sha2` | ❌ Not independently verified |",
    "| SHA-3/SHAKE | ✅ Fully implemented | `brynja-hash-sha3` | ❌ Not independently verified |",
    "| TupleHash/TupleHashXOF | ✅ Fully implemented | `brynja-hash-tuple` | ❌ Not independently verified |",
    "| SP 800-185 family | 🚧 In progress — encodings, cSHAKE, KMAC, and TupleHash complete; ParallelHash pending | `brynja-hash-sha3`, `brynja-mac-kmac`, `brynja-hash-tuple` | ❌ Not independently verified |",
    "| KMAC/KMACXOF | ✅ Fully implemented | `brynja-mac-kmac` | ❌ Not independently verified |",
    "| SHA-1 | 🗓 Planned — v0.24.18–v0.24.23 | `brynja-legacy-sha1` | ❌ Not independently verified |",
    "| MD5 | 🗓 Planned — v0.24.19–v0.24.23 | `brynja-legacy-md5` | ❌ Not independently verified |",
    "| TLS and DTLS record-envelope parsing and encoding | ✅ Implemented | `brynja-protocol` | ❌ Not independently verified |",
    "| Bounded DER framing and admitted canonical ASN.1 values | ✅ Implemented | `brynja-pki` | ❌ Not independently verified |",
    "| Fixed-width constant-time operations and secret-region lifecycle | ✅ Implemented | `brynja-core` | ❌ Not independently verified |",
    "| Fixed-size secret ownership and explicit sanitization adapter | ✅ Implemented | `brynja-core`, `brynja-sanitization` | ❌ Not independently verified |",
    "| FIPS 140-3 cryptographic module | ❌ Not implemented | Future `brynja-fips-module`, `brynja-fips` | ❌ Not FIPS validated |",
)
COMPONENT_DOCUMENT = Path("docs/VERIFICATION_STATUS.md")
COMPONENT_ROWS = (
    "| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, FIPS-aware state, and mandatory security-outcome contracts | ❌ Not verified |",
    "| `brynja-hash-sha2` | All six fully implemented FIPS 180-4 ordinary and hardened byte-oriented and canonical arbitrary-bit SHA-2 algorithms with forced optional ordinary CPU candidate APIs, compiler-resistant cleanup evidence, and combined package-external acceptance | ❌ Not verified |",
    "| `brynja-hash-sha3` | All six fully implemented FIPS 202 ordinary/hardened byte and arbitrary-bit functions plus complete SP 800-185 encodings and cSHAKE128/cSHAKE256 ordinary/hardened byte and arbitrary-bit APIs; hardened owners classify public versus typed-secret output | ❌ Not verified |",
    "| `brynja-mac-kmac` | Complete KMAC128/KMAC256 and KMACXOF128/KMACXOF256 with strength-only default APIs, feature-gated exact conformance, hardened in-place source clearing, typed output, and constant-time tag verification | ❌ Not independently verified |",
    "| `brynja-hash-tuple` | Complete TupleHash128/TupleHash256 and TupleHashXOF128/TupleHashXOF256 with structural whole or exact-length streamed items, arbitrary-bit inputs and outputs, and ordinary or hardened ownership | ❌ Not independently verified |",
    "| Future `brynja-mac-*` | Other reusable MACs | ❌ Not implemented or verified |",
    "| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |",
    "| `brynja-crypto-cpu` | Five SHA-2 plus x86_64 AVX2 and AArch64 SHA3 Keccak candidates implemented but unadmitted; x86 SHA-512 and RISC-V Keccak are explicit scalar-only decisions | ❌ Not independently verified; native admission evidence incomplete |",
    "| `brynja-crypto-cpu-std` | Implemented opt-in SHA-2 host detection/reporting, opportunistic scalar fallback and fail-closed required modes; RISC-V auto-detection disabled | ❌ Not independently verified; accelerated candidates remain unadmitted |",
    "| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |",
    "| `brynja-protocol` | Shared TLS and DTLS record-envelope parsing and encoding | ❌ Not verified |",
    "| `brynja-tls` | Modern TLS version routing and policy | ❌ Not verified |",
    "| `brynja-tls12` | TLS 1.2 record and handshake engine | ❌ Not verified |",
    "| `brynja-tls13` / `brynja-tls13-handshake` | TLS 1.3 record and handshake engine | ❌ Not verified |",
    "| `brynja-quic-tls` | QUIC/TLS handshake integration | ❌ Not verified |",
    "| `brynja-dtls` | DTLS record and handshake engines | ❌ Not verified |",
    "| Future `brynja-openpgp-core` / `brynja-openpgp-armor` / `brynja-openpgp` | RFC 9580 packet, armor, certificate, key, signature, encryption, compression, and message processing | ❌ Not implemented or verified |",
    "| Future `brynja-openpgp-legacy` | Explicitly isolated deprecated OpenPGP read, decrypt, or verify compatibility | ❌ Not implemented or verified |",
    "| Future `brynja-legacy-sha1` | Complete isolated SHA-1 implementation for explicit legacy compatibility | ❌ Not implemented or verified |",
    "| Future `brynja-legacy-md5` | Complete isolated MD5 implementation for explicit legacy compatibility | ❌ Not implemented or verified |",
    "| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |",
    "| `brynja-legacy` / `brynja-legacy-*` | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP obsolete-protocol boundaries | ❌ Not verified |",
    "| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |",
    "| Future `brynja-fips-module` / `brynja-fips` | FIPS 140-3 cryptographic module and policy boundary | ❌ Not FIPS validated |",
)
SCOPED_ROWS = {
    Path("crates/brynja-core/README.md"): "| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, FIPS-aware state, and mandatory security-outcome contracts | ❌ Not verified |",
    Path("crates/brynja-crypto/README.md"): "| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |",
    Path("crates/brynja-crypto-cpu/README.md"): "| x86_64 SHA-256 candidate | SHA-extension compression | ❌ Implemented but unadmitted and not independently verified |",
    Path("crates/brynja-crypto-cpu-std/README.md"): "| SHA-256 host detection and dispatch | x86_64 SHA and AArch64 NEON/SHA2 selection, explicit scalar fallback, and no automatic RISC-V activation | ❌ Implemented; accelerated candidates remain unadmitted and not independently verified |",
    Path("crates/brynja-hash-sha2/README.md"): "| SHA-2 (all six identities, ordinary and hardened byte and arbitrary-bit APIs) | ✅ Fully implemented | ❌ Not independently verified |",
    Path("crates/brynja-hash-sha3/README.md"): "| Complete SHA-3/SHAKE family, including final combined acceptance | ✅ Fully implemented | ❌ Not independently verified |",
    Path("crates/brynja-mac-kmac/README.md"): "| KMAC128 | ✅ Implemented | ❌ Not independently verified |",
    Path("crates/brynja-hash-tuple/README.md"): "| TupleHash / TupleHashXOF | ✅ Fully implemented | ❌ No | ❌ No |",
    Path("crates/brynja-pki/README.md"): "| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |",
    Path("crates/brynja-tls/README.md"): "| `brynja-tls` | Modern TLS version routing and policy | ❌ Not verified |",
    Path("crates/brynja-tls12/README.md"): "| `brynja-tls12` | TLS 1.2 record and handshake engine | ❌ Not verified |",
    Path("crates/brynja-tls13/README.md"): "| `brynja-tls13` | TLS 1.3 stream record and protocol engine | ❌ Not verified |",
    Path("crates/brynja-tls13-handshake/README.md"): "| `brynja-tls13-handshake` | Record-independent TLS 1.3 handshake engine | ❌ Not verified |",
    Path("crates/brynja-quic-tls/README.md"): "| `brynja-quic-tls` | QUIC/TLS handshake integration | ❌ Not verified |",
    Path("crates/brynja-dtls/README.md"): "| `brynja-dtls` | DTLS record and handshake engines | ❌ Not verified |",
    Path("crates/brynja-sanitization/README.md"): "| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |",
    Path("crates/brynja-legacy/README.md"): "| `brynja-legacy` | Opt-in obsolete-protocol facade and isolation boundary | ❌ Not verified |",
    Path("crates/brynja-legacy-pct/README.md"): "| `brynja-legacy-pct` | PCT controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-legacy-snp/README.md"): "| `brynja-legacy-snp` | SNP controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-legacy-ssl2/README.md"): "| `brynja-legacy-ssl2` | SSL 2.0 controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-legacy-ssl3/README.md"): "| `brynja-legacy-ssl3` | SSL 3.0 controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-legacy-tls10/README.md"): "| `brynja-legacy-tls10` | TLS 1.0 controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-legacy-tls11/README.md"): "| `brynja-legacy-tls11` | TLS 1.1 controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-legacy-wtls/README.md"): "| `brynja-legacy-wtls` | WTLS controlled-interoperability engine | ❌ Not verified |",
    Path("crates/brynja-research-ssl1/README.md"): "| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |",
}
SUPPORT_NOTES = (
    Path("crates/brynja-hash-core/README.md"),
    Path("crates/brynja-interop/README.md"),
    Path("crates/brynja-proofs/README.md"),
    Path("crates/brynja-test-support/README.md"),
)
VERIFIED = re.compile(
    r"^✅ Independently verified by [^[]+ — \[[^]]+\]\([^)]+\)$"
)


class VerificationStatusError(RuntimeError):
    """A verification-status document is missing or makes an unsafe claim."""


def section_from(text: str) -> str:
    if text.count(HEADING) != 1:
        raise VerificationStatusError("verification-status heading must occur once")
    section = text.split(HEADING, 1)[1]
    return section.split("\n## ", 1)[0]


def validate_checkmarks(section: str) -> None:
    for line in section.splitlines():
        if not line.startswith("|") or "✅" not in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) not in (3, 4):
            raise VerificationStatusError("status tables must have three or four columns")
        if "✅" in cells[0]:
            raise VerificationStatusError("✅ is forbidden in the capability name")
        if "✅" in cells[1] and cells[1] not in (
            "✅ Implemented",
            "✅ Fully implemented",
        ):
            raise VerificationStatusError(
                "implemented ✅ must be exactly: ✅ Implemented or ✅ Fully implemented"
            )
        if len(cells) == 4 and "✅" in cells[2]:
            raise VerificationStatusError("✅ is forbidden in the owning-crate column")
        if "✅" in cells[-1] and not VERIFIED.fullmatch(cells[-1]):
            raise VerificationStatusError(
                "✅ requires a named independent reviewer and linked evidence"
            )


def validate_document(path: Path, text: str, required_rows: tuple[str, ...]) -> None:
    try:
        section = section_from(text)
        prose = " ".join(section.split())
        for phrase in (
            "named independent reviewer",
            "tests",
            "CI",
            "Kani",
            "Miri",
            "fuzzing",
            "pentest",
            "independent",
        ):
            if phrase not in prose:
                raise VerificationStatusError(f"missing disclaimer phrase: {phrase}")
        if path in ROOT_READMES:
            for phrase in (
                "concrete public capabilities",
                "complete public API",
                "does not mean independently verified",
                "component verification status",
                "FIPS validation is a separate official claim",
                "no FIPS 140-3 validation",
                "certificate-bound operational-environment claim",
            ):
                if phrase not in prose:
                    raise VerificationStatusError(
                        f"missing FIPS disclaimer phrase: {phrase}"
                    )
        for row in required_rows:
            if row not in section:
                raise VerificationStatusError(f"missing required status row: {row}")
        validate_checkmarks(section)
    except VerificationStatusError as error:
        raise VerificationStatusError(f"{path}: {error}") from error


def validate_component_document(path: Path, text: str) -> None:
    try:
        prose = " ".join(text.split())
        for phrase in (
            "crate-level assurance inventory",
            "does not claim",
            "consumer-usable cryptographic capability",
            "named independent reviewer",
            "no FIPS 140-3 validation",
        ):
            if phrase not in prose:
                raise VerificationStatusError(
                    f"missing component-inventory phrase: {phrase}"
                )
        completion = (
            "combined v0.24.11 cross-family acceptance has passed. Both "
            "expanded families are therefore **Fully implemented**"
        )
        if completion not in prose:
            raise VerificationStatusError(
                "missing completed SHA-2/SHA-3 cross-family acceptance status"
            )
        for stale in (
            "combined cross-backend acceptance remains pending through v0.24.11",
            "both expanded families therefore remain **In progress**",
        ):
            if stale in prose:
                raise VerificationStatusError(
                    f"stale SHA-2/SHA-3 acceptance status: {stale}"
                )
        for row in COMPONENT_ROWS:
            if row not in text:
                raise VerificationStatusError(
                    f"missing component-inventory row: {row}"
                )
        validate_checkmarks(text)
    except VerificationStatusError as error:
        raise VerificationStatusError(f"{path}: {error}") from error


def validate_support_document(path: Path, text: str) -> None:
    try:
        section = section_from(text)
        prose = " ".join(section.split())
        for phrase in (
            "does not implement cryptographic or protocol code",
            "named independent reviewer",
            "linked review evidence",
        ):
            if phrase not in prose:
                raise VerificationStatusError(f"missing support note: {phrase}")
        validate_checkmarks(section)
    except VerificationStatusError as error:
        raise VerificationStatusError(f"{path}: {error}") from error


def validate_readme_split(root_readme: bytes, crate_readme: bytes) -> None:
    if root_readme == crate_readme:
        raise VerificationStatusError(
            "GitHub and crates.io READMEs must remain purpose-specific"
        )
    crate_lines = len(crate_readme.splitlines())
    if crate_lines > 200:
        raise VerificationStatusError(
            f"crates.io README exceeds compact 200-line ceiling: {crate_lines}"
        )


def check(root: Path) -> None:
    for path in ROOT_READMES:
        validate_document(path, (root / path).read_text(encoding="utf-8"), ROOT_ROWS)
    validate_component_document(
        COMPONENT_DOCUMENT,
        (root / COMPONENT_DOCUMENT).read_text(encoding="utf-8"),
    )
    for path, row in SCOPED_ROWS.items():
        validate_document(path, (root / path).read_text(encoding="utf-8"), (row,))
    for path in SUPPORT_NOTES:
        validate_support_document(path, (root / path).read_text(encoding="utf-8"))
    validate_readme_split(
        (root / ROOT_READMES[0]).read_bytes(),
        (root / ROOT_READMES[1]).read_bytes(),
    )


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(".")
    if len(sys.argv) > 2:
        print("usage: check-verification-status.py [repository-root]", file=sys.stderr)
        return 2
    try:
        check(root)
    except (OSError, VerificationStatusError) as error:
        print(error, file=sys.stderr)
        return 1
    print("cryptography verification status: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
