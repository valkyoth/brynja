"""Bounded admission model; not a SHA-512/t implementation or digest oracle."""
from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = "requirements/sha512-t-contract.toml"
DOC = "docs/sha512-t-contract.md"
REVIEW = "scripts/sha2/sha512-t-contract-reviewed.toml"
BOUND = (CONTRACT, DOC, "scripts/sha2/sha512_t_contract.py",
         "scripts/sha2/check-sha512-t-contract.py",
         "scripts/sha2/test-sha512-t-contract.py")
LIMIT = 4 * 1024 * 1024
AUTHORITY_SHA = "0455b406d89648d20cbde375561e19c245b9815e894164c2670772e3d54deb82"


def read(root: Path, name: str) -> bytes:
    """Trusted, quiescent checkout only; not a hostile-filesystem sandbox."""
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or symlinked contract input: {name}")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError(f"oversized contract input: {name}")
    return data.replace(b"\r\n", b"\n")


def descriptor(t: int) -> tuple[bytes, int, int]:
    """Public parameter model: ASCII label, byte width, last-byte keep mask."""
    if type(t) is not int or not 1 <= t < 512 or t == 384:
        raise ValueError("invalid general SHA-512/t parameter")
    return f"SHA-512/{t}".encode("ascii"), (t + 7) // 8, 255 << (-t % 8) & 255


def validate_model(contract: dict) -> None:
    expected_keys = {
        "schema", "milestone", "state", "owner", "feature", "default_enabled",
        "facade_export", "independently_verified", "fips_validated", "cpu_admitted",
        "documentation", "authority", "parameters", "profiles", "operations", "evidence", "lifecycle",
    }
    if set(contract) != expected_keys:
        raise ValueError("unknown or missing contract fields")
    expected_parameters = {
        "minimum": 1, "maximum": 511, "excluded": [384], "count": 510,
        "input_integer_bits": 16, "label_prefix": "SHA-512/",
        "label_decimal": "shortest-ascii-no-leading-zero",
        "iv_mask": "a5a5a5a5a5a5a5a5", "output_order": "msb-first",
        "unused_bits": "low-zero", "approved_named_values": [224, 256],
        "general_approval": False,
    }
    # JSON serialization preserves bool versus integer distinctions.
    if json.dumps(contract.get("parameters"), sort_keys=True) != json.dumps(expected_parameters, sort_keys=True):
        raise ValueError("parameter contract changed")
    for key, value in {
        "schema": 1, "milestone": "0.24.29", "state": "final-evidence-and-ordinary-cpu-integration",
        "owner": "brynja-hash-sha2", "feature": "general-sha512-t",
        "documentation": DOC, "default_enabled": False,
        "facade_export": False, "independently_verified": False,
        "fips_validated": False, "cpu_admitted": False,
    }.items():
        if type(contract.get(key)) is not type(value) or contract[key] != value:
            raise ValueError(f"contract identity or claim changed: {key}")
    expected_operations = {name: "0.24.26" for name in (
        "ordinary_state", "ordinary_finish", "ordinary_one_shot",
        "hardened_state", "hardened_public_finish", "hardened_secret_finish",
        "hardened_one_shot", "secret_output_access", "cancel")}
    expected_operations.update(parameter="0.24.25", public_digest="0.24.25")
    expected_operations.update(ordinary_cpu_update="0.24.29", ordinary_cpu_finish="0.24.29", ordinary_cpu_one_shot="0.24.29")
    if contract.get("operations") != expected_operations:
        raise ValueError("incomplete operation matrix")
    expected_lifecycle = {
        "documentation": "docs/sha512-t-lifecycle.md",
        "borrowed_rejection": "preserve-all-1170-owned-bytes",
        "consuming_exit": "drop-on-success-error-cancel-recoverable-unwind",
        "destination": "exact-width-affine-owner-clear-entire-region",
        "declassification": "explicit-consuming-public-copy-clears-original",
        "public_metadata": ["t", "iv", "iv-label", "message-length", "phase"],
        "borrowed_input": "caller-owned-never-cleared",
        "transient_values": "no-register-spill-or-compiler-copy-erasure-claim",
        "regions": dict(chaining_state=64, partial_input=128, message_length=16,
                        phase=2, message_schedule=640, block_copy=128,
                        padding_block=128, output_staging=64),
    }
    if json.dumps(contract.get("lifecycle"), sort_keys=True) != json.dumps(expected_lifecycle, sort_keys=True):
        raise ValueError("secret lifecycle inventory or disposition changed")
    authority = contract["authority"]
    if set(authority) != {"id", "edition", "reviewed", "url", "sha256", "sections", "distribution", "errata"}:
        raise ValueError("unknown or missing authority fields")
    if (authority["id"] != "nist:NIST.FIPS.180-4.pdf"
            or authority["sha256"] != AUTHORITY_SHA
            or authority["distribution"] != "local-only"
            or authority["edition"] != "August 2015"):
        raise ValueError("authority admission changed")


def validate(root: Path = ROOT) -> dict:
    review = tomllib.loads(read(root, REVIEW).decode())
    if set(review) != {"files"} or set(review["files"]) != set(BOUND):
        raise ValueError("incomplete contract review inventory")
    for path in BOUND:
        if hashlib.sha256(read(root, path)).hexdigest() != review["files"][path]:
            raise ValueError(f"contract review drift: {path}")
    contract = tomllib.loads(read(root, CONTRACT).decode())
    validate_model(contract)
    ledger = json.loads(read(root, "standards/source-ledger.json"))
    records = [item for item in ledger["local_authorities"]
               if item["filename"] == "NIST.FIPS.180-4.pdf"]
    if len(records) != 1 or records[0]["sha256"] != AUTHORITY_SHA:
        raise ValueError("authority is not bound to the source ledger")
    if records[0]["url"] != contract["authority"]["url"]:
        raise ValueError("authority URL differs from ledger")
    checks = read(root, "scripts/checks.sh").decode().splitlines()
    for script in BOUND[3:]:
        if f"python3 {script}" not in checks:
            raise ValueError("contract gate is not invoked")
    claims = tomllib.loads(read(root, "requirements/authority-claims.toml").decode())
    rights = [entry for entry in claims["local_right"]
              if entry["authority"] == contract["authority"]["id"]]
    if len(rights) != 1 or rights[0]["distribution"] != "local-only":
        raise ValueError("source distribution policy changed")
    requirements = tomllib.loads(read(root, "requirements/domains/cryptography.toml").decode())
    rows = [entry for entry in requirements["requirement"]
            if entry["id"] == "BRY-REQ-CRYPTO-0020"]
    if (len(rows) != 1 or rows[0]["lifecycle"] != "implemented"
            or rows[0]["owner"] != "0.24.26"
            or rows[0]["decision_ids"] != ["algorithm.sha512-t"]
            or rows[0]["sources"] != [{"id": contract["authority"]["id"], "authority_role": "current"}]):
        raise ValueError("general hashing requirement misclassified or missing")
    api = tomllib.loads(read(root, "security/cryptographic-api-profile-policy.toml").decode())
    profile = api["profile"]["general-sha512-t"]
    if (not {"cancellation", "ownership", "byte-input", "bit-input", "fixed-output"} <= set(profile["required"])
            or not {"provider", "hosted-adapter"} <= set(profile["forbidden"])
            or profile["optional_isolated"] != ["backend"]
            or api["secret-owner-overrides"].get("algorithm.sha512-t") != "0.24.26"):
        raise ValueError("general SHA-512/t profile differs from contract")
    return contract


def write_review() -> None:
    validate_model(tomllib.loads(read(ROOT, CONTRACT).decode()))
    lines = ["# Reviewed general SHA-512/t API contract; final family closure pending.", "[files]"]
    for path in BOUND:
        lines.append(f'"{path}" = "{hashlib.sha256(read(ROOT, path)).hexdigest()}"')
    (ROOT / REVIEW).write_text("\n".join(lines) + "\n", encoding="utf-8")
