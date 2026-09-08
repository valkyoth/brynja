"""Reviewed non-authorizing inventory for v0.24.30; trusted checkout tooling."""
from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = "security/acceleration-availability.toml"
REVIEW = "security/acceleration-availability-reviewed.json"
FIXTURE = "assurance/acceleration-contract"
CHECKS = "scripts/checks.sh"
CLIPPY_COMMAND = f"cargo clippy --locked --offline --manifest-path {FIXTURE}/Cargo.toml --all-targets -- -D warnings"
OWNERS = (
    "brynja-crypto-cpu", "brynja-crypto-cpu-std", "brynja-legacy-sha1",
    "brynja-legacy-sha1-std", "brynja-legacy-md5", "brynja-legacy-md5-std",
)
BOUND = (
    CHECKS,
    POLICY, "security/cpu-backend-admissions.toml", "docs/acceleration-availability.md",
    "security/sha1-cpu-admissions.toml", "security/md5-cpu-admissions.toml",
    "scripts/cpu/acceleration_availability.py",
    "scripts/cpu/check-acceleration-availability.py",
    "scripts/cpu/test-acceleration-availability.py",
)


def read(root: Path, name: str) -> bytes:
    """Bound individual reads; not a hostile-filesystem containment promise."""
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or symlinked availability input: {name}")
    with path.open("rb") as stream:
        data = stream.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError(f"oversized availability input: {name}")
    return data.replace(b"\r\n", b"\n")


def paths(root: Path) -> list[str]:
    result = set(BOUND)
    result.update(f"{FIXTURE}/{name}" for name in ("Cargo.toml", "Cargo.lock"))
    result.update(str(p.relative_to(root)) for p in (root / FIXTURE / "src").rglob("*.rs"))
    for owner in OWNERS:
        result.add(f"crates/{owner}/Cargo.toml")
        result.update(str(p.relative_to(root)) for p in (root / "crates" / owner / "src").rglob("*.rs"))
    for owner in ("brynja-hash-sha2", "brynja-hash-sha3", "brynja-mac-kmac",
                  "brynja-hash-tuple", "brynja-hash-parallel", "brynja-hash-parallel-std"):
        result.add(f"crates/{owner}/Cargo.toml")
    return sorted(name.replace("\\", "/") for name in result)


def snapshot(root: Path) -> dict:
    return {name: hashlib.sha256(read(root, name)).hexdigest() for name in paths(root)}


def check_gate(root: Path) -> None:
    """Require the reviewed literal commands, not a whole-workspace substitute.

    This is a structural check for the linear repository driver, not a shell
    interpreter. The driver's full contents are also bound by the review hash.
    """
    commands = {
        " ".join(line.split())
        for line in read(root, CHECKS).decode().replace("\\\n", " ").splitlines()
    }
    required = (
        f"cargo test --locked --offline --manifest-path {FIXTURE}/Cargo.toml",
        CLIPPY_COMMAND,
    )
    if not all(command in commands for command in required):
        raise ValueError("acceleration fixture requires dedicated test and strict all-target Clippy gates")


def check_inventory(policy: dict, root: Path) -> None:
    check_gate(root)
    for key, value in {
        "schema": 1, "milestone": "0.24.30", "state": "contract-only-zero-activations",
        "default_mode": "Portable", "modes": ["Portable", "Prefer", "Require"],
        "independent_review_required_for_ordinary_use": False,
        "fips_certificate_required_for_ordinary_use": False,
        "evidence_cfg_is_public_availability": False, "cargo_feature_is_cpu_authority": False,
        "safe_boolean_is_cpu_authority": False, "hidden_fallback": False,
        "midstream_loss": "terminal-for-prefer-and-require", "kat_failure": "quarantine-no-fallback",
    }.items():
        if type(policy.get(key)) is not type(value) or policy[key] != value:
            raise ValueError(f"availability contract changed: {key}")
    kernels = policy["kernels"]
    ids = [k["id"] for k in kernels]
    if len(ids) != 11 or len(set(ids)) != 11:
        raise ValueError("incomplete or duplicate implemented kernel inventory")
    for kernel in kernels:
        for field in ("ordinary_operational", "hardened_operational", "independent_review", "fips_validated"):
            if kernel[field] is not False:
                raise ValueError(f"premature claim: {kernel['id']} {field}")
        source = read(root, kernel["source"]).decode()
        if f"fn {kernel['symbol']}(" not in source:
            raise ValueError("kernel implementation symbol missing")
        for feature in kernel["compiler_features"]:
            owner_sources = "\n".join(
                read(root, str(p.relative_to(root)).replace("\\", "/")).decode()
                for p in (root / "crates" / kernel["owner"] / "src").rglob("*.rs")
            )
            if feature not in owner_sources:
                raise ValueError("kernel compiler feature missing")
    families = policy["families"]
    algorithms = [a for f in families for a in f["algorithms"]]
    if len(families) != 9 or len(algorithms) != 29 or len(set(algorithms)) != 29:
        raise ValueError("incomplete family/algorithm inventory")
    for family in families:
        if family["public_operational"] is not False or not set(family["kernels"]) <= set(ids):
            raise ValueError("premature family claim or unknown kernel")
    manifest = tomllib.loads(read(root, f"{FIXTURE}/Cargo.toml").decode())
    if manifest["package"]["publish"] is not False or any(k in manifest for k in (
            "dependencies", "build-dependencies", "dev-dependencies")):
        raise ValueError("contract fixture must remain unpublished and dependency-free")


def validate(root: Path = ROOT) -> None:
    policy = tomllib.loads(read(root, POLICY).decode())
    check_inventory(policy, root)
    reviewed = json.loads(read(root, REVIEW))
    expected = {"schema": 1, "milestone": "0.24.30", "sha256": snapshot(root)}
    if json.dumps(reviewed, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("availability contract/source closure changed; reopen review")


def write_review() -> None:
    """Maintainer-only regeneration; not evidence or permission to execute."""
    check_inventory(tomllib.loads(read(ROOT, POLICY).decode()), ROOT)
    (ROOT / REVIEW).write_text(json.dumps(
        {"schema": 1, "milestone": "0.24.30", "sha256": snapshot(ROOT)}, indent=2,
    ) + "\n", encoding="utf-8")
