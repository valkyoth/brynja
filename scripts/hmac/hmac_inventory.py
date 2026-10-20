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
    LEAF + "output.rs#Verification": (
        {"choice"}, "Only the final comparison decision is explicitly declassified."),
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
    "lib.rs": {"authenticate", "new", "with_tag_length", "update",
               "finalize_tag", "finalize_secret", "verify", "cancel"},
    "bits.rs": {"authenticate_bits", "finalize_bits_tag", "finalize_bits_secret", "verify_bits"},
}
PROFILES = (
    ("Portable", "brynja-mac-hmac", None, "No CPU authority or protected-memory promise."),
    ("Static", "brynja-mac-hmac", "hardened-execution", "Borrowed explicit CPU authority."),
    ("Runtime", "brynja-mac-hmac", "runtime-execution", "Borrowed runtime authority, never implicit fallback."),
    ("Hosted", "brynja-crypto-cpu-std", "hmac-execution", "Portable selection occurs before reading keys."),
    ("Linux scalar", "brynja-crypto-cpu-std", "strict-hmac", "Protected complete requests; not the strict facade."),
    ("Linux compiled", "brynja-crypto-cpu-std", "strict-hmac-acceleration", "Explicit kernel, protected worker."),
    ("Mac scalar", "brynja-crypto-cpu-std", "macos-resident-hmac", "Residency only, not dump exclusion."),
    ("Mac compiled", "brynja-crypto-cpu-std", "macos-resident-hmac-acceleration", "Explicit Arm kernel, resident worker."),
)
EVIDENCE = (
    ("RFC 2104 construction and RFC 4231 known answers", "crates/brynja-mac-hmac/tests/vectors.rs"),
    ("Byte differential controls", "scripts/hmac/check-hmac-differential.py"),
    ("Canonical final-bit messages", "scripts/hmac/check-hmac-bit-differential.py"),
    ("All 383 admitted general SHA-512/t parameters", "scripts/hmac/check-hmac-general-differential.py"),
    ("Affine lifecycle and output errors", "crates/brynja-mac-hmac/tests/lifecycle.rs"),
    ("Synthetic composition errors/unwind", "scripts/hmac/hmac_faults.py"),
    ("Real extracted archives, negative probes and mutants", "scripts/hmac/check-hmac-package.py"),
    ("Protected/resident consumer tests and mutants", "scripts/hmac/check-hmac-protected.py"),
    ("Curated facade feature and package contracts", "scripts/hmac/check-hmac-facade.py"),
    ("Bounded verifier scope and population", "scripts/hmac/test-hmac-verification.py"),
)
PENDING = (
    "HMAC-specific optimized caller/scratch cleanup and stack qualification.",
    "HMAC-specific timing campaigns; equal-length comparison structure alone is not a timing proof.",
    "Remaining native route qualification, including dedicated x86 SHA-512.",
    "Independent pentest and final source-bound release evidence.",
    "Promote the global API/requirement register only after its compiler-owner contract is satisfied.",
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
    # This register deliberately does not promote the global assurance state.
    surfaces = json.loads((root / "standards/protocol-surfaces.json").read_text())
    rows = [row for row in surfaces["surfaces"] if row["id"] == "algorithm.hmac"]
    require(len(rows) == 1 and rows[0]["owner"] == "0.25.0"
            and rows[0]["disposition"] == "future-work",
            "global HMAC completion requires separate qualification review")
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
    lines += ["", "Modern facades expose curated HMAC types; `brynja-strict` does not yet expose HMAC.",
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
    lines += ["", "## Still pending", ""]
    lines += ["- " + pending for pending in PENDING]
    return "\n".join(lines) + "\n"
