#!/usr/bin/env python3
"""Fail closed when README independent-review status is absent or overstated."""

from __future__ import annotations

import re
import sys
from pathlib import Path


HEADING = "## Cryptography Verification Status"
ROOT_READMES = (Path("README.md"), Path("crates/brynja/README.md"))
ROOT_ROWS = (
    "| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, and FIPS-aware state contracts | ❌ Not verified |",
    "| Future `brynja-hash-*` / `brynja-mac-*` | Reusable hashes, XOFs, and MACs | ❌ Not implemented or verified |",
    "| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |",
    "| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |",
    "| `brynja-tls` | Modern TLS version routing and policy | ❌ Not verified |",
    "| `brynja-tls12` | TLS 1.2 record and handshake engine | ❌ Not verified |",
    "| `brynja-tls13` / `brynja-tls13-handshake` | TLS 1.3 record and handshake engine | ❌ Not verified |",
    "| `brynja-quic-tls` | QUIC/TLS handshake integration | ❌ Not verified |",
    "| `brynja-dtls` | DTLS record and handshake engines | ❌ Not verified |",
    "| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |",
    "| `brynja-legacy` / `brynja-legacy-*` | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP obsolete-protocol boundaries | ❌ Not verified |",
    "| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |",
    "| Future `brynja-fips-module` / `brynja-fips` | FIPS 140-3 cryptographic module and policy boundary | ❌ Not FIPS validated |",
)
SCOPED_ROWS = {
    Path("crates/brynja-core/README.md"): "| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, and FIPS-aware state contracts | ❌ Not verified |",
    Path("crates/brynja-crypto/README.md"): "| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |",
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
        if len(cells) != 3 or not VERIFIED.fullmatch(cells[2]):
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


def check(root: Path) -> None:
    for path in ROOT_READMES:
        validate_document(path, (root / path).read_text(encoding="utf-8"), ROOT_ROWS)
    for path, row in SCOPED_ROWS.items():
        validate_document(path, (root / path).read_text(encoding="utf-8"), (row,))
    for path in SUPPORT_NOTES:
        validate_support_document(path, (root / path).read_text(encoding="utf-8"))
    if (root / ROOT_READMES[0]).read_bytes() != (root / ROOT_READMES[1]).read_bytes():
        raise VerificationStatusError("root and brynja crate READMEs differ")


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
