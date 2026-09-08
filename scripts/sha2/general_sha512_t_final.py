"""Final scalar-only work/performance evidence, never an admission certificate."""
import hashlib
import itertools
import json
import re
import subprocess
import tempfile
from pathlib import Path

import general_sha512_t_work as work

ROOT = work.ROOT
DECLARATION = "requirements/sha512-t-final.toml"
DOCUMENT = "docs/sha512-t-final-evidence.md"
ROW = re.compile(r"t=(\d+) bytes=(\d+) pattern=(\d+) samples=9 operations=8 ordinary_median_ns=(\d+) hardened_median_ns=(\d+)")
FOOTERS = (
    "General SHA-512/t performance profile: PASS; rows=50; scalar-only",
    "includes IV derivation, checking and cleanup; not a constant-time proof",
)
EXPECTED = list(itertools.product((1, 9, 224, 256, 511), (0, 111, 112, 1024, 16384), (0, 255)))


def parse_profile(text):
    lines = text.splitlines()
    if len(lines) != 52 or tuple(lines[-2:]) != FOOTERS:
        raise ValueError("incomplete or overstated final performance output")
    rows = []
    for expected, line in zip(EXPECTED, lines[:-2], strict=True):
        match = ROW.fullmatch(line)
        if match is None:
            raise ValueError("invalid performance row")
        t, length, pattern, ordinary, hardened = map(int, match.groups())
        if (t, length, pattern) != expected or not (0 < ordinary < 10**15 and 0 < hardened < 10**15):
            raise ValueError("performance inventory or duration out of bounds")
        rows.append(dict(t=t, bytes=length, pattern=pattern, ordinary_ns=ordinary, hardened_ns=hardened))
    return rows


def fingerprint():
    # Exact complete Rust dependency source closure, not only top-level APIs.
    paths = set()
    for name in ("brynja-core", "brynja-hash-core", "brynja-hash-sha2"):
        crate = ROOT / "crates" / name
        paths.update((crate / "src").rglob("*.rs"))
        paths.add(crate / "Cargo.toml")
    paths.update((work.FIXTURE / "src").rglob("*.rs"))
    paths.update(work.FIXTURE / name for name in ("Cargo.toml", "Cargo.lock", "profile.rs", "work_probe.rs"))
    paths.update((ROOT / "scripts/sha2").glob("*.py"))
    paths.update(ROOT / name for name in (DECLARATION, DOCUMENT, "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"))
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            for path in sorted(paths)}


def validate_declaration():
    import tomllib
    data = tomllib.loads((ROOT / DECLARATION).read_text())
    expected = dict(schema=1, milestone="0.24.29", implementation="portable-with-unadmitted-ordinary-cpu",
                    native_disposition="required-after-fresh-pentest",
                    independent_review=False, fips_validated=False, cpu_admitted=False,
                    pentest="required-before-completion", parameters=510, oracle_cases=4590,
                    work_cases_per_profile=12240, work_profiles=["debug", "release"],
                    performance_rows=50, ordinary_object_max=256, hardened_object_max=1200,
                    public_digest_max=72, secret_digest_max=32,
                    object_limits_are_stack_limits=False, timing_proof=False,
                    resource_check="assurance/general-sha512-t/src/resources.rs",
                    work_probe="assurance/general-sha512-t/work_probe.rs",
                    profile="assurance/general-sha512-t/profile.rs")
    if json.dumps(data, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("final declaration inventory or claim changed")


def write_artifact(path, evidence):
    # Trusted quiescent checkout, but do not follow an accidental output symlink
    # or leave a truncated success record if writing is interrupted.
    path.parent.mkdir(exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("final artifact destination must not be a symlink")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run():
    validate_declaration()
    before = fingerprint()
    work.run()
    command = ["cargo", "run", "--locked", "--offline", "--release", "--manifest-path",
               "assurance/general-sha512-t/Cargo.toml", "--bin", "general-sha512-t-profile"]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=240)
    if result.returncode:
        raise ValueError(f"final profile failed: {result.stdout}\n{result.stderr}")
    rows = parse_profile(result.stdout)
    compiler = subprocess.check_output(["rustc", "-vV"], cwd=ROOT, text=True)
    if fingerprint() != before:
        raise ValueError("final evidence source changed while capturing")
    evidence = dict(schema=1, milestone="0.24.29", source_sha256=before, compiler=compiler,
                    implementation="portable-only", performance=rows,
                    work_cases_per_profile=12240, work_profiles=["debug", "release"],
                    independent_review=False, fips_validated=False, cpu_admitted=False,
                    timing_proof=False, total_stack_bound=False)
    path = ROOT / "target/general-sha512-t-final.json"
    write_artifact(path, evidence)
    print("General SHA-512/t final scalar work/resource/profile evidence: PASS; 50 performance rows")
    print("Local exact-source artifact: target/general-sha512-t-final.json; no native/timing/FIPS approval")


if __name__ == "__main__":
    run()
