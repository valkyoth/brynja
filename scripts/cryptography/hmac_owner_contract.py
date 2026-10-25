"""HMAC's composed owner: field destruction/consuming handoff, not a fake wipe.

This inventory binds the existing emitted-code checks; it is not a receipt,
independent review, native qualification, or a whole-frame erasure proof.
"""
from pathlib import Path
import re

import rust_source_contract as rust
import legacy_hmac_owner_contract as compatibility

ROOT = Path(__file__).resolve().parents[2]
ID = "registered.algorithm.hmac"
LEAF = "crates/brynja-mac-hmac/src/"
CHECKS = [
    "python3 scripts/hmac/" + checker + suffix
    for checker, targets in (
        ("check-hmac-cleanup.py", (None, "aarch64-unknown-linux-gnu")),
        ("check-hmac-engine-cleanup.py", (None, "aarch64-unknown-linux-gnu")),
        ("check-hmac-execution-cleanup.py", (None, "aarch64-unknown-linux-gnu")),
        ("check-hmac-static-cleanup.py", (None, "aarch64-unknown-linux-gnu")),
        ("check-hmac-hosted-cleanup.py", (None, "aarch64-unknown-linux-gnu", "aarch64-apple-darwin")),
    )
    for suffix in ("" if target is None else " --target " + target for target in targets)
]
RECORD = {
    "capability": "algorithm.hmac",
    "symbol": LEAF + "engine.rs#Engine",
    "fields": ["inner:owned-secret-hash-state", "outer:owned-secret-hash-state",
               "tag_bytes:public-preselected-policy"],
    "temporaries": ["pad:Scratch<144>", "normalized:Scratch<64>",
                    "inner_digest:Scratch<64>", "tag:Scratch<64>",
                    "difference:Scratch<1>", "borrowed-input:caller-owned-copy-risk"],
    "cleanup_model": "transitive-owned-fields-and-consuming-handoffs",
    "delegated_owners": ["registered.algorithm.sha2", "registered.algorithm.sha512-t",
                         "registered.algorithm.sha3-shake"],
    "cleanup_bindings": [LEAF + "engine.rs#Engine::finish",
                         LEAF + "algorithms.rs#Hash", LEAF + "general.rs#Sha512T",
                         LEAF + "execution/adapter.rs#Adapter",
                         LEAF + "scratch.rs#Scratch::drop",
                         "crates/brynja-core/src/secret_memory.rs#OwnedSecretRegion"],
    "compiler_checks": CHECKS,
    "compiler_scope": "bounded-owned-storage-and-dispatch-not-whole-frame-erasure",
    "qualification": "native-release-reconciliation-and-independent-review-pending",
    "evidence": ["crates/brynja-mac-hmac/tests/vectors.rs",
                 "crates/brynja-mac-hmac/tests/lifecycle.rs",
                 "scripts/hmac/check-hmac-package.py", "scripts/hmac/check-hmac-protected.py",
                 "scripts/hmac/check-hmac-strict.py", "scripts/hmac/check-hmac-inventory.py",
                 "scripts/hmac/test-hmac-owner-contract.py",
                 *dict.fromkeys(command.split()[1] for command in CHECKS)],
    "storage": "transitive-fixed-owners-with-separate-protected-or-resident-hosted-profiles",
    "output_classification": "typed-secret-owned",
    "partial_failure_policy": "clear-complete-secret-destination",
    "compatibility_profiles": [compatibility.RECORD],
}

# Enumerate current files, not just known filenames, so an added implementation
# or checker cannot escape the raw-byte review inventory. Data/results/README
# changes are not code. Shared hash/kernel/resource premises remain separately
# checked by the delegated owner contracts and the HMAC emitted-code drivers.
SOURCE_TREES = (
    "crates/brynja-mac-hmac/src", "scripts/hmac",
    "crates/brynja-crypto-cpu-std/src/strict_hmac",
    "crates/brynja-crypto-cpu-std/src/macos_resident/hmac",
    "assurance/hmac-cleanup", "assurance/hmac-engine-cleanup",
    "assurance/hmac-execution-cleanup", "assurance/hmac-hosted-cleanup",
)


def reviewed_paths(root=ROOT):
    paths = {"scripts/cryptography/hmac_owner_contract.py",
             "crates/brynja-mac-hmac/Cargo.toml",
             "crates/brynja-crypto-cpu-std/src/execution/hmac.rs",
             "scripts/repository/facade_cargo_environment.py"}
    paths.update(RECORD["evidence"])
    for tree in SOURCE_TREES:
        paths.update(str(path.relative_to(root)) for path in (root / tree).rglob("*")
                     if path.is_file() and path.suffix in {".rs", ".py", ".toml", ".lock"}
                     and "target" not in path.relative_to(root / tree).parts)
    return paths | compatibility.reviewed_paths(root)


def validate(root, owner, registered):
    def require(condition, message):
        if not condition:
            raise ValueError("HMAC composed-owner contract: " + message)

    require(owner == {"id": ID, **RECORD}, "canonical record changed")
    require(set(RECORD["delegated_owners"]) <= {row.get("id") for row in registered},
            "delegated clearing owner absent")
    rust.validate_type(root, RECORD["symbol"], {"inner", "outer", "tag_bytes"})
    engine = rust.scrub((root / (LEAF + "engine.rs")).read_text())
    require(re.search(r"struct\s+Engine<A:\s*Algorithm>\s*\{\s*inner:\s*A::State,\s*"
                      r"outer:\s*A::State,\s*tag_bytes:\s*usize,\s*\}", engine),
            "Engine must own both sealed hash states")
    require(not re.search(r"\bDrop\s+for\s+Engine\b", engine),
            "direct destructor is not this composed contract")
    algorithm = rust.scrub((root / (LEAF + "algorithms.rs")).read_text())
    require(re.search(r"pub\(crate\)\s+mod\s+sealed\b", algorithm)
            and re.search(r"pub\s+trait\s+Algorithm:\s*sealed::Hash\b", algorithm),
            "hash-state admission must remain sealed")
    # Availability of exact executable checks is not proof that they ran. The
    # normal CI/release runner executes them; existing source-bound receipts
    # retain their own reuse rules. No new sweep or receipt is manufactured here.
    commands = (root / "scripts/checks.sh").read_text().splitlines()
    require(all(commands.count(command) == 1 for command in CHECKS),
            "compiler check missing, duplicated or replaced in checks.sh")
