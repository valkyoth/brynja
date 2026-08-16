#!/usr/bin/env python3
"""Exercise positive and broken first-party Rust cryptography fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path

import first_party_rust_crypto


def fixture(root: Path) -> Path:
    package = root / "crates/example"
    source = package / "src"
    source.mkdir(parents=True)
    (package / "Cargo.toml").write_text(
        '[package]\nname = "example"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (source / "lib.rs").write_text("#![no_std]\npub fn owned() {}\n", encoding="utf-8")
    return package


def reject(root: Path, expected: str) -> None:
    try:
        first_party_rust_crypto.validate(root)
    except first_party_rust_crypto.FirstPartyRustCryptoError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"first-party Rust policy accepted {expected}")


def test_case(name: str, mutation, expected: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-rust-{name}-") as temporary:
        root = Path(temporary)
        package = fixture(root)
        mutation(package)
        reject(root, expected)


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-rust-good-") as temporary:
        root = Path(temporary)
        fixture(root)
        first_party_rust_crypto.validate(root)

    test_case("c-source", lambda package: (package / "crypto.c").write_text("", encoding="utf-8"), "foreign source")
    test_case("archive", lambda package: (package / "vendor.a").write_bytes(b"archive"), "native binary")
    test_case("build-script", lambda package: (package / "build.rs").write_text("fn main() {}\n", encoding="utf-8"), "build script")
    test_case(
        "build-dependency",
        lambda package: (package / "Cargo.toml").write_text(
            '[package]\nname = "example"\nversion = "0.1.0"\n[build-dependencies]\ncc = "1"\n',
            encoding="utf-8",
        ),
        "build dependencies",
    )
    test_case(
        "custom-build",
        lambda package: (package / "Cargo.toml").write_text(
            '[package]\nname = "example"\nversion = "0.1.0"\nbuild = "native.rs"\n',
            encoding="utf-8",
        ),
        "custom build target",
    )
    test_case(
        "links",
        lambda package: (package / "Cargo.toml").write_text(
            '[package]\nname = "example"\nversion = "0.1.0"\nlinks = "crypto"\n',
            encoding="utf-8",
        ),
        "native link identity",
    )
    test_case(
        "foreign-abi",
        lambda package: (package / "src/lib.rs").write_text(
            '#![no_std]\nunsafe extern "C" { fn crypto(); }\n', encoding="utf-8"
        ),
        "foreign ABI",
    )
    test_case(
        "link-attribute",
        lambda package: (package / "src/lib.rs").write_text(
            '#![no_std]\n#[link(name = "crypto")] mod native {}\n',
            encoding="utf-8",
        ),
        "native link attribute",
    )
    test_case(
        "native-include",
        lambda package: (package / "src/lib.rs").write_text(
            '#![no_std]\nconst BLOB: &[u8] = include_bytes!("vendor.o");\n',
            encoding="utf-8",
        ),
        "included native binary",
    )


if __name__ == "__main__":
    test()
    print("first-party Rust cryptography policy rejects nine native-code regressions")
