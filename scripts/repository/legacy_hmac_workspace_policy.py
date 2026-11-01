"""Exact opt-in legacy composition features, never modern facade forwarding."""

SHARED_HMAC_CONSUMERS = ("brynja-legacy-hkdf", "brynja-legacy-hmac-std")


def validate_shared_hmac_pin(workspace, consumers):
    expected = {"path": "crates/brynja-legacy-hmac", "version": "=0.1.0",
                "default-features": False}
    if workspace.get("workspace", {}).get("dependencies", {}).get("brynja-legacy-hmac") != expected:
        raise ValueError("legacy HMAC requires one exact no-default workspace pin")
    for name in SHARED_HMAC_CONSUMERS:
        if consumers.get(name, {}).get("dependencies", {}).get("brynja-legacy-hmac") != {"workspace": True}:
            raise ValueError(name + " must inherit the legacy HMAC workspace pin without overrides")

FEATURES = {
    "default": [],
    "sha1-execution": ["brynja-legacy-sha1/hardened-execution"],
    "md5-batch": ["brynja-legacy-md5/hardened-execution"],
}

FEATURE_SETS = {
    "brynja-legacy-hmac": FEATURES,
    "brynja-legacy-hmac-std": {
        "default": [],
        "strict-execution": ["dep:brynja-crypto-cpu-std", "brynja-crypto-cpu-std/protected-memory"],
        "macos-resident": ["dep:brynja-crypto-cpu-std", "brynja-crypto-cpu-std/macos-resident"],
        "strict-sha1-acceleration": ["strict-execution", "brynja-legacy-hmac/sha1-execution"],
        "macos-resident-sha1-acceleration": ["macos-resident", "brynja-legacy-hmac/sha1-execution"],
        "strict-md5-batch": ["strict-execution", "brynja-legacy-hmac/md5-batch"],
        "macos-resident-md5-batch": ["macos-resident", "brynja-legacy-hmac/md5-batch"],
    },
}


def no_defaults(package, dependency):
    """Legacy cryptographic/provider dependencies never unify defaults implicitly."""
    return dependency in {
        "brynja-legacy-hkdf": {"brynja-legacy-hmac"},
        "brynja-legacy-hmac": {"brynja-legacy-sha1", "brynja-legacy-md5"},
        "brynja-legacy-hmac-std": {"brynja-legacy-hmac", "brynja-crypto-cpu-std"},
    }.get(package, set())
