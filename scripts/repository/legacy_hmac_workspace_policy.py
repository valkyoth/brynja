"""Exact opt-in legacy composition features, never modern facade forwarding."""

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
    },
}


def no_defaults(package, dependency):
    """Legacy cryptographic/provider dependencies never unify defaults implicitly."""
    return dependency in {
        "brynja-legacy-hmac": {"brynja-legacy-sha1", "brynja-legacy-md5"},
        "brynja-legacy-hmac-std": {"brynja-legacy-hmac", "brynja-crypto-cpu-std"},
    }.get(package, set())
