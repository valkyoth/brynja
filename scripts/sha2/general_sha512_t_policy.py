"""General SHA-512/t default-off ordinary/hardened ownership boundary."""
from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import sha512_t_contract as contract

ROOT = contract.ROOT
REVIEW = "scripts/sha2/general-sha512-t-reviewed.toml"
PREFIX = "crates/brynja-hash-sha2/src/general/"
PRODUCTION = tuple(PREFIX + name for name in ("mod.rs", "parameter.rs", "iv.rs", "digest.rs", "ordinary.rs", "hardened.rs", "secret.rs", "one_shot.rs", "cpu.rs"))
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
    "scripts/sha2/sha512_t_digest_oracle.py",
    "crates/brynja-hash-sha2/tests/general_hash.rs",
    "crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt",
    "crates/brynja-hash-sha2/src/hardened/owner.rs",
    "crates/brynja-hash-sha2/src/hardened/mod.rs",
    "crates/brynja-hash-sha2/src/hardened/tests.rs",
    "scripts/sha2/sha2_hardened.py",
    "scripts/sha2/test-sha2-hardened.py",
    "crates/brynja-hash-sha2/src/hardened/state64.rs",
    "crates/brynja-hash-sha2/src/hardened/compress64.rs",
    "crates/brynja-hash-sha2/src/sha512_state.rs",
    PREFIX + "hardened/tests.rs",
    "scripts/sha2/general_sha512_t_cleanup.py",
    "scripts/sha2/general_sha512_t_lifecycle.py",
    "crates/brynja-hash-sha2/tests/general_hash/lifecycle.rs",
    "docs/sha512-t-lifecycle.md",
    "assurance/general-sha512-t/src/acceptance.rs",
    "assurance/general-sha512-t/src/boundaries.rs",
    "assurance/general-sha512-t/src/corpus.rs",
    "assurance/general-sha512-t/src/main.rs",
    "scripts/sha2/general_sha512_t_acceptance.py",
    "docs/sha512-t-public-acceptance.md",
    "docs/sha512-t-final-evidence.md",
    "requirements/sha512-t-final.toml",
    "assurance/general-sha512-t/src/resources.rs",
    "assurance/general-sha512-t/profile.rs",
    "assurance/general-sha512-t/work_probe.rs",
    "scripts/sha2/general_sha512_t_work.py",
    "scripts/sha2/general_sha512_t_final.py",
    "scripts/sha2/general_sha512_t_cpu.py",
    "scripts/sha2/capture-general-sha512-t-native.py",
    "scripts/sha2/test-general-sha512-t-cpu.py",
    "scripts/sha2/check-sha256-cpu-qemu.sh",
    "assurance/general-sha512-t-cpu/Cargo.toml",
    "assurance/general-sha512-t-cpu/Cargo.lock",
    "assurance/general-sha512-t-cpu/src/lib.rs",
    "assurance/general-sha512-t-cpu/src/main.rs",
    "docs/sha512-t-cpu-evidence.md",
)


def read(root: Path, name: str) -> str:
    return contract.read(root, name).decode("utf-8")


def validate(root: Path = ROOT, *, hashes: bool = True) -> None:
    sources = {name: read(root, name) for name in PRODUCTION}
    actual = {str(p.relative_to(root)) for p in (root / PREFIX).rglob("*.rs")}
    if actual != set(PRODUCTION) | {PREFIX + "hardened/tests.rs"}:
        raise ValueError("general source inventory changed")
    for name, text in sources.items():
        if len(text.splitlines()) > 500:
            raise ValueError("general source exceeds 500 lines")
        code = "\n".join(line.split("//")[0] for line in text.splitlines())
        for token in ("unsafe", 'extern "C"', "alloc::", "std::", "unwrap()", "expect(",
                      "panic!", "static mut", "target_feature", "asm!"):
            if token in code:
                raise ValueError(f"general public-only boundary crossed: {name}: {token}")
        if name != PREFIX + "cpu.rs" and ("brynja_crypto_cpu" in code or "Sha512BackendSession" in code):
            raise ValueError("CPU dependency escaped ordinary CPU wrapper")
    cpu = sources[PREFIX + "cpu.rs"]
    if "impl Hardened" in cpu or "HardenedSha2Owner" in cpu:
        raise ValueError("hardened acceleration is not qualified")
    for token in (".update_with_backend(input, backend)", ".finalize_with_backend(backend)",
                  ".finalize_bits_with_backend(input, backend)", "map_err(Sha512TAcceleratedError::Backend)"):
        if token not in cpu:
            raise ValueError("explicit CPU route/failure boundary missing")
    if '#[cfg(feature = "cpu")]\nmod cpu;' not in sources[PREFIX + "mod.rs"]:
        raise ValueError("CPU wrapper escaped optional feature")
    manifest = tomllib.loads(read(root, "crates/brynja-hash-sha2/Cargo.toml"))
    if manifest["features"] != {"default": [], "cpu": ["dep:brynja-crypto-cpu"], "general-sha512-t": [],
                               "static-execution": ["cpu", "brynja-crypto-cpu/static-execution"],
                               "runtime-execution": ["static-execution", "brynja-crypto-cpu/runtime-execution"]}:
        raise ValueError("general feature must be explicit and dependency-free")
    library = read(root, "crates/brynja-hash-sha2/src/lib.rs")
    if '#[cfg(all(feature = "general-sha512-t", feature = "cpu"))]\npub use general::{' not in library:
        raise ValueError("CPU public exports escaped dual feature gate")
    for token in ('#[cfg(feature = "general-sha512-t")]\nmod general;',
                  '#[cfg(feature = "general-sha512-t")]\npub use general::{Sha512TBits, Sha512TDigest, Sha512TError};'):
        if token not in library:
            raise ValueError("general exports escaped feature gate")
    for path in ("crates/brynja-crypto/src/lib.rs", "crates/brynja/src/lib.rs"):
        if "Sha512TBits" in read(root, path) or "general-sha512-t" in read(root, path):
            raise ValueError("general capability was implicitly reexported")
    gates = read(root, "scripts/checks.sh").splitlines()
    for path, token in (
        ("scripts/sha2/check-general-sha512-t.py", "    final.run()"),
        ("scripts/sha2/test-general-sha512-t.py", "        work.run(mutations=True)"),
        ("assurance/general-sha512-t/profile.rs", "brynja_general_sha512_t_consumer::resources::check()"),
        ("scripts/zeroization/check-zeroization-sanitizer.sh", "--manifest-path assurance/general-sha512-t/Cargo.toml"),
        ("scripts/zeroization/check-zeroization-sanitizer.sh", "--bin general-sha512-t-profile --target x86_64-unknown-linux-gnu"),
        ("scripts/sha2/check-sha256-cpu-qemu.sh", "python3 scripts/sha2/general_sha512_t_cpu.py"),
        ("scripts/checks.sh", "python3 scripts/sha2/test-general-sha512-t-cpu.py"),
    ):
        if token not in read(root, path):
            raise ValueError("final work/resource evidence is absent")
    for name in ("check-general-sha512-t.py", "test-general-sha512-t.py"):
        if f"python3 scripts/sha2/{name}" not in gates:
            raise ValueError("general gate is absent")
    for path in ("scripts/zeroization/check-zeroization-miri.sh", "scripts/zeroization/check-zeroization-sanitizer.sh"):
        if "-p brynja-hash-sha2 --features general-sha512-t --test general" not in read(root, path):
            raise ValueError("general dynamic-analysis coverage is absent")
        if "--test general_hash" not in read(root, path):
            raise ValueError("general hashing dynamic-analysis coverage is absent")
    if "        dynamic_lifecycle_" not in read(root, "scripts/zeroization/check-zeroization-miri.sh"):
        raise ValueError("general lifecycle Miri coverage is absent")
    if "lifecycle.run()" not in read(root, "scripts/sha2/check-general-sha512-t.py"):
        raise ValueError("general destructor probe is absent")
    for path, token in (
        ("scripts/sha2/check-general-sha512-t.py", "    acceptance.run()"),
        ("scripts/sha2/test-general-sha512-t.py", "        acceptance.run(regressions=True)"),
        ("scripts/zeroization/check-zeroization-miri.sh", "    run_miri --manifest-path assurance/general-sha512-t/Cargo.toml --lib"),
        ("scripts/ci/check-rust-version-matrix.sh", 'cargo "+$toolchain" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml'),
        ("scripts/assurance/check-bare-metal.sh", 'cargo check --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml --lib --target "$target"'),
    ):
        if token not in read(root, path):
            raise ValueError("packaged general acceptance gate is absent")
    for path in (PREFIX + "hardened.rs", PREFIX + "secret.rs", PREFIX + "one_shot.rs"):
        if "from_bytes(" in read(root, path):
            raise ValueError("secret paths must not use public importer")
    hard = sources[PREFIX + "hardened.rs"]
    if "owner: HardenedSha2Owner" not in hard or "SecretRegionInitialization" not in hard:
        raise ValueError("mandatory hardened/output owner missing")
    # On the reviewed source, public digest construction has exactly three
    # callers: ordinary output and the two explicit declassification boundaries.
    # In particular, finish_secret and one-shot secret routes must not stage one.
    public_finish = hard.partition("    fn finish_public(")[2].partition("    pub(super) fn finish_secret")[0]
    secret = sources[PREFIX + "secret.rs"]
    declassification = secret.partition("    pub fn declassify(")[2].partition("// This guard")[0]
    if (hard.count("Sha512TDigest::computed(") != 1
            or public_finish.count("Sha512TDigest::computed(") != 1
            or secret.count("Sha512TDigest::computed(") != 1
            or declassification.count("Sha512TDigest::computed(") != 1
            or "Sha512TDigest::computed(" in sources[PREFIX + "one_shot.rs"]):
        raise ValueError("public digest staging escaped explicit declassification")
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
    lines = ["# v0.24.29 general hashing scalar and unadmitted CPU integration review.", "[files]"]
    for path in BOUND:
        lines.append(f'"{path}" = "{hashlib.sha256(contract.read(ROOT, path)).hexdigest()}"')
    (ROOT / REVIEW).write_text("\n".join(lines) + "\n", encoding="utf-8")
