"""HMAC archive footprint policy; it does not authorize publication."""
from pathlib import PurePosixPath

REQUIRED = frozenset({
    "Cargo.toml", "Cargo.toml.orig", "LICENSE-APACHE", "LICENSE-MIT", "README.md",
    "src/lib.rs", "src/algorithms.rs", "src/engine.rs", "src/output.rs", "src/scratch.rs",
})
OPTIONAL = frozenset({"Cargo.lock", ".cargo_vcs_info.json"})


def validate_members(members):
    names = list(members)
    if len(names) != len(set(names)):
        raise ValueError("duplicate HMAC package entry")
    for name in names:
        path = PurePosixPath(name)
        if str(path) != name or path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("noncanonical HMAC package entry")
    actual = set(names)
    if REQUIRED - actual or actual - REQUIRED - OPTIONAL:
        raise ValueError("HMAC archive must contain only reviewed runtime sources and package metadata")
