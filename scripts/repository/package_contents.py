"""Check Cargo archive listings; repository tests remain separate from downloads.

Migrated crates retain all src Rust modules (including cfg(test) modules).
Unpublished test-support packages are not silently trimmed by this check.
This checks content, not publication approval.
"""
from pathlib import Path, PurePosixPath
import sys
import tomllib

REQUIRED = {"Cargo.toml", "LICENSE-APACHE", "LICENSE-MIT", "README.md", "src/lib.rs"}
METADATA = (REQUIRED - {"src/lib.rs"}) | {"Cargo.lock", "Cargo.toml.orig", ".cargo_vcs_info.json"}
SOURCE_INCLUDE = ["Cargo.toml", "LICENSE-APACHE", "LICENSE-MIT", "README.md", "src/**/*.rs"]
MIGRATED = {
    "brynja-core", "brynja-crypto-cpu-std", "brynja-pki", "brynja-protocol",
    "brynja-sanitization", "brynja-hash-sha2", "brynja-hash-sha3",
    "brynja-mac-kmac", "brynja-mac-hmac", "brynja-hash-tuple",
    "brynja-legacy-sha1", "brynja-legacy-sha1-std", "brynja-legacy-md5",
    "brynja-legacy-md5-std", "brynja-hash-parallel", "brynja-hash-parallel-std",
}
HOSTED = {"brynja-crypto-cpu-std", "brynja-legacy-sha1-std",
          "brynja-legacy-md5-std", "brynja-hash-parallel-std"}
REPOSITORY_ONLY = {"rfc", "references", "security", "assurance", "release-reports"}


def require(condition, message):
    if not condition:
        raise ValueError("package contents: " + message)


def validate(package, members, sources=()):
    members = list(members)
    require(len(members) == len(set(members)), "duplicate archive member")
    require(REQUIRED <= set(members), "required metadata or library missing")
    if package.get("publish") is not False:
        require(not any(name.startswith("tests/") for name in members),
                "standalone tests belong in the repository, not published archives")
    for name in members:
        path = PurePosixPath(name)
        require(name and not path.is_absolute() and ".." not in path.parts
                and "\\" not in name and path.as_posix() == name,
                "non-canonical archive path: " + name)
        require(not REPOSITORY_ONLY.intersection(path.parts), "repository-only material: " + name)
    if package["name"] in MIGRATED:
        require(package.get("include") == SOURCE_INCLUDE and "exclude" not in package,
                "source/metadata allowlist changed")
        require(all(name in METADATA or (name.startswith("src/") and name.endswith(".rs"))
                    for name in members), "standalone fixture or non-source member in lean archive")
        require(set(sources) <= set(members), "Rust source missing from archive")


def check(manifest, members):
    package = tomllib.loads(manifest.read_text())["package"]
    sources = [path.relative_to(manifest.parent).as_posix()
               for path in (manifest.parent / "src").rglob("*.rs")]
    validate(package, members, sources)


if __name__ == "__main__":
    check(Path(sys.argv[1]), sys.stdin.read().splitlines())
