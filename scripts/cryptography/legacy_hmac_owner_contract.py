"""Compatibility owner inventory, not execution evidence or new approval.

HMAC keeps one semantic capability. This separate composition belongs to its
explicit legacy profile, never to the modern or strict facade's algorithm set.
The listed compiler drivers still need scoped release scheduling/reconciliation.
"""
from pathlib import Path
import re

import rust_source_contract as rust

ROOT = Path(__file__).resolve().parents[2]
LEAF = "crates/brynja-legacy-hmac/"
HOST = "crates/brynja-legacy-hmac-std/"
FIXTURES = ("cleanup", "engine-cleanup", "execution-cleanup", "md5-cleanup", "hosted-cleanup")
CHECKS = ["python3 scripts/legacy-hmac/check-legacy-hmac-" + name + ".py"
          for name in FIXTURES]
RECORD = {
    "id": "legacy-sha1-md5",
    "milestone": "0.25.1",
    "admission": "explicit-LegacyUse-not-policy-approval",
    "symbol": LEAF + "src/engine.rs#Engine",
    "fields": ["inner:owned-secret-hash-state", "outer:owned-secret-hash-state",
               "tag_bytes:public-preselected-policy"],
    "temporaries": ["pad:Scratch<64>", "normalized:Scratch<20>",
                    "inner_digest:Scratch<20>", "tag:Scratch<20>", "difference:Scratch<1>",
                    "batch-pads:Rows<64>", "batch-digests:Rows<16>",
                    "caller-input-and-lengths:outside-owned-storage"],
    "delegated_owners": ["registered.algorithm.sha1", "registered.algorithm.md5"],
    "cleanup_model": "transitive-owned-fields-and-consuming-handoffs",
    "cleanup_bindings": [LEAF + "src/engine.rs#Engine::finish",
                         LEAF + "src/scratch.rs#Scratch::drop",
                         LEAF + "src/execution/adapter.rs#Sha1Adapter",
                         LEAF + "src/execution/retained.rs#Retained",
                         LEAF + "src/md5_batch/engine.rs#Rows::drop",
                         LEAF + "src/md5_batch/engine.rs#Operation::drop",
                         LEAF + "src/output.rs#SecretTag",
                         LEAF + "src/md5_batch/output.rs#SecretTags"],
    "routes": [
        {"id": "portable", "symbol": LEAF + "src/lib.rs#Hmac",
         "storage": "transitive-fixed-owned-memory-not-residency", "selection": "default"},
        {"id": "sha1-execution", "symbol": LEAF + "src/execution/mod.rs#Sha1Hmac",
         "storage": "borrowed-hardened-workspace", "selection": "pre-admitted-authority-no-failure-fallback"},
        {"id": "md5-batch", "symbol": LEAF + "src/md5_batch/mod.rs#Md5Batch",
         "storage": "borrowed-hardened-workspace-and-owned-rows", "selection": "full-AVX2-or-NEON-group-no-failure-fallback"},
        *({"id": directory, "symbol": HOST + "src/" + directory + "/mod.rs#Session",
           "storage": storage, "selection": "explicit-feature-unsupported-target-errors",
           "compiled_owners": [HOST + "src/" + directory + "/sha1_compiled.rs#Sha1CompiledSession",
                               HOST + "src/" + directory + "/md5_compiled.rs#Md5BatchSession"],
           "cleanup_bindings": [HOST + "src/" + directory + "/mod.rs#Buffers::drop",
                                HOST + "src/" + directory + "/mod.rs#Output::drop",
                                HOST + "src/" + directory + "/md5_compiled/types.rs#Md5BatchOutput"]}
          for directory, storage in (("strict_execution", "Linux-protected-mappings-and-worker-stack"),
                                     ("macos_resident", "Apple-Silicon-resident-mappings-and-worker-stack-not-dump-exclusion"))),
    ],
    "compiler_checks": CHECKS,
    "compiler_scope": "bounded-owned-storage-and-dispatch-not-whole-frame-erasure",
    "qualification": "scoped-release-reconciliation-and-independent-review-pending",
    "output_classification": "typed-secret-owned-or-explicit-public-declassification",
    "partial_failure_policy": "clear-complete-secret-destination",
    "limitations": ["legacy-only-not-new-protocol-or-FIPS-approval",
                    "public-lengths-batch-shape-and-work",
                    "caller-copies-registers-OS-state-and-fatal-termination-outside-guarantee",
                    "build-wide-CPU-feature-and-deployment-authority-required-for-acceleration"],
    "evidence": ["docs/legacy-hmac-hosted-qualification.md",
                 LEAF + "tests/contracts.rs", LEAF + "tests/rfc2202.rs", LEAF + "tests/md5_batch.rs",
                 "scripts/legacy-hmac/check-legacy-hmac-package.py",
                 "scripts/legacy-hmac/check-legacy-hmac-hosted-package.py",
                 "scripts/cryptography/legacy_hmac_owner_tests.py",
                 *[command.split()[1] for command in CHECKS]],
}
SOURCE_TREES = (LEAF.rstrip('/'), HOST.rstrip('/'), "scripts/legacy-hmac",
                *("assurance/legacy-hmac-" + name for name in (*FIXTURES, "timing")))


def reviewed_paths(root=ROOT):
    paths = {"scripts/cryptography/legacy_hmac_owner_contract.py",
             "scripts/cryptography/legacy_hmac_owner_tests.py"}
    paths.update(RECORD["evidence"])
    for tree in SOURCE_TREES:
        paths.update(str(path.relative_to(root)) for path in (root / tree).rglob("*")
                     if path.is_file() and path.suffix in {".rs", ".py", ".toml", ".lock"}
                     and "target" not in path.relative_to(root / tree).parts)
    return paths


def targets():
    result = [RECORD["symbol"], *RECORD["cleanup_bindings"], *RECORD["evidence"]]
    for route in RECORD["routes"]:
        result.extend([route["symbol"], *route.get("compiled_owners", []),
                       *route.get("cleanup_bindings", [])])
    return result


def validate(root, profiles, registered):
    def require(condition, message):
        if not condition:
            raise ValueError("legacy HMAC owner contract: " + message)

    require(profiles == [RECORD], "canonical compatibility profile changed")
    require(set(RECORD["delegated_owners"]) <= {row.get("id") for row in registered},
            "delegated clearing owner absent")
    rust.validate_type(root, RECORD["symbol"], {"inner", "outer", "tag_bytes"})
    engine = rust.scrub((root / LEAF / "src/engine.rs").read_text())
    require(re.search(r"struct\s+Engine<A:\s*Algorithm>\s*\{\s*inner:\s*A::State,\s*"
                      r"outer:\s*A::State,\s*tag_bytes:\s*usize,\s*\}", engine),
            "Engine must own both sealed legacy hash states")
    require(not re.search(r"\bDrop\s+for\s+Engine\b", engine), "not a direct-destructor contract")
    algorithms = rust.scrub((root / LEAF / "src/algorithms.rs").read_text())
    require(re.search(r"pub\(crate\)\s+mod\s+sealed\b", algorithms)
            and re.search(r"pub\s+trait\s+Algorithm:\s*sealed::Hash\b", algorithms),
            "legacy hash-state admission must remain sealed")
    for target in targets():
        path, _, symbol = target.partition('#')
        file = root / path
        require(file.is_file() and not file.is_symlink(), "missing/aliased owner or evidence: " + path)
        if symbol:
            require(re.search(r'\b' + re.escape(symbol.rsplit('::', 1)[-1]) + r'\b',
                              rust.scrub(file.read_text())), "missing owner/cleanup symbol: " + target)
