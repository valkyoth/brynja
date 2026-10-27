"""Development HMAC composition inventory, not compiler or release qualification."""
from pathlib import Path
import json
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "scripts/cryptography"))
import rust_source_contract as rust

LEAF = "crates/brynja-mac-hmac/src/"
HOST = "crates/brynja-crypto-cpu-std/src/"
DOC = "docs/hmac-development-inventory.md"

# Explicit expectations: adding an owner/field requires reviewing its lifetime.
# Test-only fault fields are included, not silently discarded by the parser.
OWNERS = {
    LEAF + "lib.rs#Hmac": (
        {"engine", "_local"}, "Affine engine; transitive hash-owner destruction."),
    LEAF + "engine.rs#Engine": (
        {"inner", "outer", "tag_bytes"},
        "Two secret-bearing hash owners; public preselected tag width. Rust field drop, not a custom wipe."),
    LEAF + "output.rs#SecretTag": (
        {"region", "algorithm"}, "OwnedSecretRegion clears the borrowed destination on drop."),
    LEAF + "output.rs#Tag": (
        {"bytes", "algorithm"}, "Explicit public output; intentionally not an erasing owner."),
    LEAF + "execution/mod.rs#Hmac": (
        {"engine", "kernel", "_local"}, "Retained engine borrows authority; failures cannot select fallback."),
    LEAF + "execution/retained.rs#Guard": (
        {"slot", "preserve"}, "Error/unwind drops retained state unless the outcome preserves it."),
}
for directory, storage in (
        ("strict_hmac", "GNU/Linux protected stack and buffers"),
        ("macos_resident/hmac", "Apple Silicon resident mappings; no dump-exclusion claim")):
    OWNERS[HOST + directory + "/mod.rs#Session"] = (
        {"stack", "staging", "output", "policy", "bits", "limits", "_algorithm", "fault"},
        storage + "; keyed states are constructed on the joined worker.")
    OWNERS[HOST + directory + "/mod.rs#Output"] = (
        {"storage", "bits", "_algorithm"}, "Exclusive clearing loan; session reuse also clears forgotten output.")
    OWNERS[HOST + directory + "/mod.rs#Buffers"] = (
        {"output", "staging", "keep"}, "Operation guard always clears staging; keeps output only after success.")
    OWNERS[HOST + directory + "/compiled.rs#CompiledSession"] = (
        {"inner", "kernel", "quarantined"}, "Explicit kernel; terminal health latch; inherits scalar resource lifetime.")

ALGORITHMS = (
    "Sha224", "Sha256", "Sha384", "Sha512", "Sha512_224", "Sha512_256",
    "Sha3_224", "Sha3_256", "Sha3_384", "Sha3_512",
)
OPERATIONS = {
    "lib.rs": {"validate_tag_policy", "authenticate", "new", "with_tag_length", "update",
               "finalize_tag", "finalize_secret", "verify", "cancel"},
    "bits.rs": {"authenticate_bits", "finalize_bits_tag", "finalize_bits_secret", "verify_bits"},
}
PROFILES = (
    ("Portable", "brynja-mac-hmac", None, "No CPU authority or protected-memory promise."),
    ("Static", "brynja-mac-hmac", "hardened-execution", "Borrowed explicit CPU authority."),
    ("Runtime", "brynja-mac-hmac", "runtime-execution", "Borrowed runtime authority, never implicit fallback."),
    ("Hosted", "brynja-crypto-cpu-std", "hmac-execution", "Portable selection occurs before reading keys."),
    ("Linux scalar", "brynja-crypto-cpu-std", "strict-hmac", "Protected complete requests; also curated by the strict facade."),
    ("Linux compiled", "brynja-crypto-cpu-std", "strict-hmac-acceleration", "Explicit kernel, protected worker."),
    ("Mac scalar", "brynja-crypto-cpu-std", "macos-resident-hmac", "Residency only, not dump exclusion."),
    ("Mac compiled", "brynja-crypto-cpu-std", "macos-resident-hmac-acceleration", "Explicit Arm kernel, resident worker."),
    ("Strict facade scalar", "brynja-strict", None, "Mandatory protected HMAC; unsupported platforms reject."),
    ("Strict facade compiled", "brynja-strict", "acceleration", "Facade-owned opt-in, explicit kernel; no portable/resident fallback."),
)
EVIDENCE = (
    ("48 host consumers and 48 public-loan probes; reconciled scalar/compiled constructors and consuming callees, retained storage, input/output provenance, checkpoints, joined transactions, public verification results, loan construction/declassification and mapping/buffer clearing; full qualification pending", "scripts/hmac/check-hmac-hosted-cleanup.py"),
    ("RFC 2104 construction and RFC 4231 known answers", "crates/brynja-mac-hmac/tests/vectors.rs"),
    ("Byte differential controls", "scripts/hmac/check-hmac-differential.py"),
    ("Canonical final-bit messages", "scripts/hmac/check-hmac-bit-differential.py"),
    ("All 383 admitted general SHA-512/t parameters", "scripts/hmac/check-hmac-general-differential.py"),
    ("Affine lifecycle and output errors", "crates/brynja-mac-hmac/tests/lifecycle.rs"),
    ("Synthetic composition errors/unwind", "scripts/hmac/hmac_faults.py"),
    ("Real extracted archives, negative probes and mutants", "scripts/hmac/check-hmac-package.py"),
    ("Protected/resident consumer tests and mutants", "scripts/hmac/check-hmac-protected.py"),
    ("Curated facade feature and package contracts", "scripts/hmac/check-hmac-facade.py"),
    ("Strict facade archives, default-off acceleration and ownership/trait isolation", "scripts/hmac/check-hmac-strict.py"),
    ("Bounded verifier scope and population", "scripts/hmac/test-hmac-verification.py"),
    ("Five scratch probes, optimized normal/error/unwind clearing only", "scripts/hmac/check-hmac-cleanup.py"),
    ("24 cancellation/update, 84 scratch, 72 finalizer and 12 constructor graphs; dispatch only", "scripts/hmac/check-hmac-engine-cleanup.py"),
    ("24 accelerated owner, 96 scratch, 72 finalizer and 24 constructor consumers; dispatch only", "scripts/hmac/check-hmac-execution-cleanup.py"),
    ("Static-only feature graph, 24 retained, 72 finalizer and 12 constructor consumers; dispatch only", "scripts/hmac/check-hmac-static-cleanup.py"),
    ("Real portable and explicitly selected native adapter handoffs", "assurance/hmac-faults/adapter_tests.rs"),
    ("Private accelerated composition admission/error/unwind witnesses", "assurance/hmac-faults/execution_cases.rs"),
    ("Explicit AArch64 hosted native selection and fallback mutations", "scripts/hmac/check-hmac-hosted-native.py"),
    ("Explicit native SHA-256 worker-start recovery and compiled regressions", "scripts/hmac/check-hmac-launch.py"),
    ("Dedicated x86 SHA-512 composition under explicit SDE; emulated, never native or timing qualification", "scripts/hmac/check-hmac-x86-sha512.py"),
    ("Explicit portable/static/runtime and protected/resident scalar/compiled paired timing screens; compiled preflight controls, not a constant-time proof", "scripts/hmac/check-hmac-timing.py"),
)
PENDING = (
    "Independent assessment of the bounded portable/static/runtime and hosted compiler checks; completed graph linkage is not whole-frame erasure or independent qualification.",
    "Final native receipt reconciliation and assessment of remaining cache/branch limits; the completed explicit-route paired screens are not constant-time proofs.",
    "Dedicated x86 SHA-512 has explicit HMAC SDE functional coverage, not native-silicon or timing qualification.",
    "Final affected release checks after the supplied pentest/retest; see docs/hmac-review-handoff.md for exact reviewer scope rather than restarting completed compiler slices.",
)


def require(condition, message):
    if not condition:
        raise ValueError("HMAC development inventory: " + message)


def source(root, name):
    path = root / name
    require(path.is_file() and not path.is_symlink(), "missing/nonregular input " + name)
    return rust.scrub(path.read_text())


def validate(root=ROOT):
    for target, (fields, _) in OWNERS.items():
        source(root, target.split("#")[0])
        rust.validate_type(root, target, fields)
    for file, expected in OPERATIONS.items():
        actual = re.findall(r"\bpub\s+fn\s+(\w+)", source(root, LEAF + file))
        require(len(actual) == len(expected) and set(actual) == expected,
                "portable operation population changed: " + file)
    actual = re.findall(r"\balgorithm!\s*\(\s*(\w+)", source(root, LEAF + "algorithms.rs"))
    require(tuple(actual) == ALGORITHMS, "named algorithm population changed")
    # Tuple scratch storage is outside validate_type's named-field parser.
    scratch = source(root, LEAF + "scratch.rs")
    require(re.search(r"struct Scratch<const N: usize>\(pub\(crate\) \[u8; N\]\);", scratch),
            "scratch storage changed")
    body = rust.validate_callable(root, LEAF + "scratch.rs#Scratch::drop")
    require("clear_owned_region(&mut self.0)" in body, "scratch clearing call absent")
    uses = re.findall(r"let mut (\w+) = Scratch::<(\d+)>::new\(\);",
                      source(root, LEAF + "engine.rs"))
    require(uses == [("pad", "144"), ("normalized", "64"), ("inner_digest", "64"),
                     ("tag", "64"), ("difference", "1")], "scratch population changed")
    require(re.search(r"struct Retained<T>\(Option<T>\);",
                      source(root, LEAF + "execution/retained.rs")),
            "retained storage changed")
    for directory in ("strict_hmac", "macos_resident/hmac"):
        name = HOST + directory + "/mod.rs#"
        body = rust.validate_callable(root, name + "Buffers::drop")
        require("self.staging.clear();" in body and "self.output.clear();" in body,
                "buffer clearing call absent")
        body = rust.validate_callable(root, name + "Output::drop")
        require("self.storage.clear();" in body, "output clearing call absent")
    for _, package, feature, _ in PROFILES:
        manifest = tomllib.loads((root / "crates" / package / "Cargo.toml").read_text())
        require(not manifest["features"]["default"], "HMAC profile became default-on")
        require(feature is None or feature in manifest["features"], "profile feature absent")
    for _, name in EVIDENCE:
        require((root / name).is_file() and not (root / name).is_symlink(), "missing check " + name)
    # Implementation registration is not qualification or independent review.
    surfaces = json.loads((root / "standards/protocol-surfaces.json").read_text())
    rows = [row for row in surfaces["surfaces"] if row["id"] == "algorithm.hmac"]
    require(len(rows) == 1 and rows[0]["owner"] == "0.25.0"
            and rows[0]["disposition"] == "implemented",
            "global HMAC implementation inventory drifted")
    policy = tomllib.loads((root / "security/cryptographic-api-profile-policy.toml").read_text())
    from hmac_owner_contract import ID, RECORD
    owners = [row for row in policy["registered-secret-owner"] if row["id"] == ID]
    require(owners == [{"id": ID, **RECORD}], "global composed-owner registration drifted")
    require(set(rows[0]["normative_sources"]) == {"rfc:2104", "rfc:4231"},
            "HMAC requirement sources changed")


def render():
    lines = [
        "# HMAC development composition inventory", "",
        "Generated by `python3 scripts/hmac/check-hmac-inventory.py --write`.", "",
        "Development inventory only: **not compiler-qualified, independently reviewed or release-ready**.",
        "Source checks detect declaration/operation drift; they do not prove control flow,",
        "compiler erasure or execution. Existing hash qualification does not qualify HMAC.", "",
        "## Profiles", "",
        "| Profile | Package feature | Boundary |", "| --- | --- | --- |",
    ]
    for name, package, feature, boundary in PROFILES:
        lines.append(f"| {name} | `{package}` / `{feature or 'none'}` | {boundary} |")
    lines += ["", "Modern facades expose curated HMAC types; `brynja-strict::hmac` exposes protected sessions.",
              "The strict namespace excludes portable keyed states and the low-level hash trait;",
              "its acceleration exports require the facade's own opt-in even under feature unification.",
              "No HMAC Windows enclave or independent-message SIMD batch API is implemented.", "",
              "## Owners and outputs", "", "| Source type | Exact declared fields | Lifetime |",
              "| --- | --- | --- |"]
    for target, (fields, note) in OWNERS.items():
        file, symbol = target.split("#")
        lines.append(f"| [{symbol}](../{file}) | {', '.join(f'`{f}`' for f in sorted(fields))} | {note} |")
    lines += ["", "`Scratch<N>` owns `[u8; N]` and calls `clear_owned_region` on drop.",
              "Its uses include the 144-byte key pad, 64-byte normalization/inner/tag",
              "buffers and one-byte comparison accumulator. The execution `Retained<T>`",
              "owns an optional engine; its guard drops that engine on terminal failure.",
              "Hash states and output regions retain their own transitive clearing owners.", "",
              "## Inputs, tag policy and public observations", "",
              "Keys are byte strings; empty keys are mathematically accepted, not secure.",
              "Streaming prefixes are bytes. Final bits use distinct SHA-2 high-bit and",
              "FIPS 202 low-bit canonical input types. General SHA-512/t admits",
              "128..511 except 384 (383 parameters), preserving exact inner/full-tag bits.",
              "Truncation selects whole bytes of at least 128 bits before processing;",
              "candidate length never chooses the policy. No fractional keys or arbitrary",
              "bit truncation are implemented. Public lengths, resource limits, selected",
              "routes, rejection and the explicitly released verification result are observable.",
              "Public output errors preserve the destination; secret-output errors clear it.", "",
              "Caller inputs/copies, compiler-created copies, interruption state, fatal",
              "termination and privileged snapshots are outside owned-memory cleanup.",
              "Mac residency must not be described as Linux dump exclusion.", "",
              "## Requirement-to-check links", "",
              "RFC identifiers below are traceability, not a claim of a fresh standards review.",
              "Links identify executable checks, not proof that a current run passed.", ""]
    lines += [f"- {requirement}: [check](../{path})." for requirement, path in EVIDENCE]
    lines += ["", "## Reconciled development work", "",
              "The portable/static/runtime constructor, retained-state, suffix/comparison and",
              "error/unwind graphs are implemented and checked. Hosted graph linkage also",
              "covers constructors, workers, consuming callees, checkpoints, joined result",
              "transactions and public output loans. The hosted cross-check at `cba6ffa1`",
              "covered Rust 1.90.0/1.99.1, Linux x86/Arm and Apple Arm, abort/unwind:",
              "twelve compiler profiles, 48 consumers, 48 loan probes and 24 executors.",
              "These are bounded emitted-code checks with the documented hash/core/OS",
              "premises, not whole-frame erasure or an independent security review.", "",
              "The timing work at `f7affddf` reconciled 17 retained native observations:",
              "six Linux/AMD and eleven Apple Silicon records, 768 campaigns, no alarm",
              "at the configured threshold. Mac captures used that clean commit; local",
              "captures used its final pre-commit source bytes and were hash-reconciled,",
              "not labelled clean-commit captures. The raw samples remain outside crate",
              "archives. No-alarm is not constant-time, cache/branch or runner-attestation",
              "proof. Dedicated x86 SHA-512 was not executed on native silicon.", "",
              "The strict facade forwards these existing protected implementations; it",
              "does not add a new worker or change the cryptographic implementation.",
              "Its separate package tests cover the consumer surface and feature graph.",
              "The global owner inventory now registers the transitive Engine inner/outer",
              "fields and consuming handoffs, rather than a synthetic direct-destructor model.",
              "Its compiler-check links bind the existing eleven pipeline commands. This",
              "registration is neither an execution receipt nor independent qualification;",
              "the original emitted-code checks and source-bound evidence remain necessary."]
    lines += ["", "## Still pending", ""]
    lines += ["- " + pending for pending in PENDING]
    return "\n".join(lines) + "\n"
