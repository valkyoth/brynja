"""Check the migrated catalogue's inventory, ordering and API scope contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REGISTER = Path(__file__).resolve().parents[2] / "docs/CATALOGUE_SCOPE_REGISTER.json"
MIGRATED_MAPPING_SHA256 = "24caacccbd46be819911f127d709225d9d1a4d546216f8bc8b95b504142986a5"
DOMAINS = {"utility", "research-utility", "crypto", "research", "legacy",
           "mac", "mac-legacy", "password", "field", "perceptual", "source-research"}
PREREQUISITES = {
    "Skein": "0.251.4", "MDC": "0.59.2", "scrypt": "0.77.3",
    "EksBlowfish and bcrypt": "0.66.1", "Poly1305-AES": "0.31.3",
    "CMAC extension profiles": "0.217.1", "HMAC catalogue adapters": "0.25.2",
    "UMAC": "0.27.5", "VMAC": "0.27.5", "PMAC": "0.27.5",
}
FAMILY_EDGES = {"BLAKE2 tree profiles": "BLAKE2s", "BLAKE2X": "BLAKE2s",
                "KangarooTwelve": "TurboSHAKE", "scrypt": "Salsa20 core for scrypt",
                "FSB": "Whirlpool"}


def validate(entries, register=None):
    data = json.loads(REGISTER.read_text(encoding="utf-8")) if register is None else register
    if data["schema"] != 1 or len(data["inventory"]) != 104 or len(data["families"]) != 93:
        raise ValueError("catalogue migration inventory count changed without review")
    inventory = data["inventory"]
    if [r["id"] for r in inventory] != list(range(104)):
        raise ValueError("catalogue inventory is missing, duplicated or reordered")
    if any(not r["item"] or not r["owners"] for r in inventory):
        raise ValueError("catalogue inventory lost its identity or owner")
    if len({r["item"] for r in inventory}) != 104:
        raise ValueError("duplicate migrated inventory name")
    identity = hashlib.sha256(json.dumps([r["item"] for r in inventory],
        ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    if identity != data["inventory_identity_sha256"]:
        raise ValueError("inherited catalogue identities changed without review")
    mapping = hashlib.sha256(json.dumps(inventory, sort_keys=True,
        ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    if mapping != MIGRATED_MAPPING_SHA256:
        raise ValueError("reviewed inventory-to-owner mapping changed")
    positions = {v.removeprefix("v"): i for i, (v, _, _) in enumerate(entries)}
    scopes = {v.removeprefix("v"): (t, s) for v, t, s in entries}
    families = {f["name"]: f for f in data["families"]}
    if len(families) != 93:
        raise ValueError("duplicate catalogue family")
    allowed = set(families) | set(data["reuse"]) | {"standards lifecycle"}
    if any(set(r["owners"]) - allowed for r in inventory):
        raise ValueError("inventory refers to an unknown owner")
    if any(v not in positions for v in data["reuse"].values()):
        raise ValueError("catalogue reuse points to absent implementation")
    if data["reuse"]["SHA-512/t"] != "0.24.29":
        raise ValueError("SHA-512/t reuse must point to IV-generation closure")
    if data["lifecycle_versions"] != ["0.250.4", "0.348.1"]:
        raise ValueError("catalogue standards update closure drift")
    if not data["post_1_0_exception"].startswith("RISC-V native/community qualification only;"):
        raise ValueError("catalogue silently deferred non-RISC-V scope")
    records = list(data["spine"])
    for family in families.values():
        for key in ("variants", "package", "domain", "authority", "api_contract", "verification_focus", "requires"):
            if not family[key]:
                raise ValueError(f"catalogue family lost {key}")
        if len(set(family["variants"])) != len(family["variants"]):
            raise ValueError("duplicate catalogue variant")
        domain = family["domain"]
        if domain not in DOMAINS:
            raise ValueError("unknown catalogue semantic domain")
        package = family["package"]
        if domain.startswith("research") or domain in ("field", "source-research"):
            if not package.startswith("brynja-research-"):
                raise ValueError("research catalogue owner escaped package isolation")
        if domain in ("legacy", "mac-legacy") and not package.startswith("brynja-legacy-"):
            raise ValueError("legacy catalogue owner escaped package isolation")
        milestones = family["milestones"]
        stages = [m["stage"] for m in milestones]
        required = ["admission", "implementation", "portable-acceptance", "final-acceptance"]
        if domain != "source-research":
            required.insert(2, "lifecycle")
        if any(s not in stages for s in required):
            raise ValueError("catalogue family lost required API/evidence stage")
        if [stages.index(s) for s in required] != sorted(stages.index(s) for s in required):
            raise ValueError("catalogue API acceptance follows evidence or lacks prerequisite")
        if stages[0] != "admission" or stages[-1] != "final-acceptance":
            raise ValueError("catalogue family boundary drift")
        if "backend" in stages and not stages.index("portable-acceptance") < stages.index("backend") < stages.index("final-acceptance"):
            raise ValueError("catalogue backend precedes real public acceptance")
        actual = [positions.get(m["version"], -1) for m in milestones]
        if -1 in actual or actual != sorted(set(actual)):
            raise ValueError("catalogue milestones absent or reordered")
        for prerequisite in family["requires"]:
            if prerequisite not in positions or positions[prerequisite] >= actual[0]:
                raise ValueError("catalogue consumer precedes its accepted prerequisite")
        prerequisite = PREREQUISITES.get(family["name"])
        if prerequisite and prerequisite not in family["requires"]:
            raise ValueError("catalogue lost its exact reusable primitive prerequisite")
        predecessor = FAMILY_EDGES.get(family["name"])
        if predecessor and families[predecessor]["milestones"][-1]["version"] not in family["requires"]:
            raise ValueError("catalogue lost its accepted family prerequisite")
        if actual[-1] >= positions.get("0.346.0", -1):
            raise ValueError("catalogue implementation follows integrated closure")
        admission_scope = scopes[milestones[0]["version"]][1]
        if "freeze every " + "; ".join(family["variants"]) + " profile" not in admission_scope:
            raise ValueError("catalogue variant list differs from its full admission scope")
        implementation_scopes = [scopes[m["version"]][1] for m in milestones if m["stage"] == "implementation"]
        if not any(family["api_contract"] in scope for scope in implementation_scopes):
            raise ValueError("catalogue public API contract is not owned by implementation")
        records.extend(milestones)
    record_versions = [r["version"] for r in records]
    if len(record_versions) != len(set(record_versions)):
        raise ValueError("duplicate catalogue milestone ownership")
    expected = {v for v in positions if v.startswith("0.") and 250 <= int(v.split(".")[1]) <= 350}
    if set(record_versions) != expected:
        raise ValueError("catalogue spine has missing or unowned milestones")
    for record in records:
        title, scope = scopes.get(record["version"], (None, ""))
        if title != record["title"] or hashlib.sha256(scope.encode()).hexdigest() != record["scope_sha256"]:
            raise ValueError("catalogue plan scope differs from reviewed API register")
    for a, b in (("0.348.1", "0.476.0"), ("0.350.0", "0.476.0"),
                 ("0.476.1", "0.477.0"), ("0.477.0", "0.478.0"),
                 ("0.478.0", "0.479.0"), ("0.479.0", "0.480.0"),
                 ("0.480.0", "1.0.0-rc.1")):
        if a not in positions or b not in positions or positions[a] >= positions[b]:
            raise ValueError("final production gate precedes expanded scope")
