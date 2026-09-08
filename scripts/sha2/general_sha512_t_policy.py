"""v0.24.25 public parameter/IV/digest boundary, not a general message hasher."""
from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import sha512_t_contract as contract

ROOT = contract.ROOT
REVIEW = "scripts/sha2/general-sha512-t-reviewed.toml"
PREFIX = "crates/brynja-hash-sha2/src/general/"
PRODUCTION = tuple(PREFIX + name for name in ("mod.rs", "parameter.rs", "iv.rs", "digest.rs"))
BOUND = PRODUCTION + (
    "crates/brynja-hash-sha2/tests/general.rs",
    "crates/brynja-hash-sha2/tests/vectors/general-sha512-t-iv.txt",
    "crates/brynja-hash-sha2/src/compress64.rs",
    "assurance/general-sha512-t/Cargo.toml",
    "assurance/general-sha512-t/Cargo.lock",
    "assurance/general-sha512-t/src/lib.rs",
    "scripts/sha2/sha512_t_iv_oracle.py",
    "scripts/sha2/general_sha512_t_policy.py",
    "scripts/sha2/check-general-sha512-t.py",
    "scripts/sha2/test-general-sha512-t.py",
)


def read(root: Path, name: str) -> str:
    return contract.read(root, name).decode("utf-8")


def validate(root: Path = ROOT, *, hashes: bool = True) -> None:
    sources = {name: read(root, name) for name in PRODUCTION}
    actual = {str(p.relative_to(root)) for p in (root / PREFIX).rglob("*.rs")}
    if actual != set(PRODUCTION):
        raise ValueError("general source inventory changed")
    for name, text in sources.items():
        if len(text.splitlines()) > 500:
            raise ValueError("general source exceeds 500 lines")
        code = "\n".join(line.split("//")[0] for line in text.splitlines())
        for token in ("unsafe", 'extern "C"', "alloc::", "std::", "unwrap()", "expect(",
                      "panic!", "static mut", "target_feature", "asm!", "brynja_crypto_cpu"):
            if token in code:
                raise ValueError(f"general public-only boundary crossed: {name}: {token}")
    manifest = tomllib.loads(read(root, "crates/brynja-hash-sha2/Cargo.toml"))
    if manifest["features"] != {"default": [], "cpu": ["dep:brynja-crypto-cpu"], "general-sha512-t": []}:
        raise ValueError("general feature must be explicit and dependency-free")
    library = read(root, "crates/brynja-hash-sha2/src/lib.rs")
    for token in ('#[cfg(feature = "general-sha512-t")]\nmod general;',
                  '#[cfg(feature = "general-sha512-t")]\npub use general::{Sha512TBits, Sha512TDigest, Sha512TError};'):
        if token not in library:
            raise ValueError("general exports escaped feature gate")
    for path in ("crates/brynja-crypto/src/lib.rs", "crates/brynja/src/lib.rs"):
        if "Sha512TBits" in read(root, path) or "general-sha512-t" in read(root, path):
            raise ValueError("general capability was implicitly reexported")
    gates = read(root, "scripts/checks.sh").splitlines()
    for name in ("check-general-sha512-t.py", "test-general-sha512-t.py"):
        if f"python3 scripts/sha2/{name}" not in gates:
            raise ValueError("general gate is absent")
    for path in ("scripts/zeroization/check-zeroization-miri.sh", "scripts/zeroization/check-zeroization-sanitizer.sh"):
        if "-p brynja-hash-sha2 --features general-sha512-t --test general" not in read(root, path):
            raise ValueError("general dynamic-analysis coverage is absent")
    if hashes:
        reviewed = tomllib.loads(read(root, REVIEW))
        if set(reviewed) != {"files"} or set(reviewed["files"]) != set(BOUND):
            raise ValueError("general review inventory differs")
        for path in BOUND:
            actual_hash = hashlib.sha256(contract.read(root, path)).hexdigest()
            if actual_hash != reviewed["files"][path]:
                raise ValueError(f"general review drift: {path}")


def write_review() -> None:
    validate(hashes=False)
    lines = ["# v0.24.25 public descriptor and IV implementation review.", "[files]"]
    for path in BOUND:
        lines.append(f'"{path}" = "{hashlib.sha256(contract.read(ROOT, path)).hexdigest()}"')
    (ROOT / REVIEW).write_text("\n".join(lines) + "\n", encoding="utf-8")
