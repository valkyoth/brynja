"""Run frozen no_std consumer against packaged sources in an offline empty cache.

Trusted, quiescent checkout tooling, not a sandbox for hostile Rust/build scripts.
The existing archive extractor and closure builder are reused; Cargo resolution
must reach only the three first-party portable dependencies, never the facade.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import sha2_public_api as packages
import sha512_t_digest_oracle as oracle

ROOT = packages.ROOT
FIXTURE = ROOT / "assurance/general-sha512-t"
EXPECTED_GRAPH = {"brynja-general-sha512-t-consumer", "brynja-hash-sha2", "brynja-hash-core", "brynja-core"}
SUCCESS = "parameters: 510; independent cases: 4590"


def execute(command, cwd, env, *, data=None):
    return subprocess.run(command, cwd=cwd, env=env, input=data, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)


def require_success(result):
    if result.returncode != 0:
        raise ValueError(f"consumer failed:\n{result.stdout}\n{result.stderr}")


def prepare(destination):
    roots = packages.package_roots(destination)
    fixture = destination / "consumer"
    shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns("target", "Cargo.lock"))
    manifest = fixture / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace('path = "../../crates/brynja-hash-sha2", ', ''), encoding="utf-8")
    config = fixture / ".cargo"
    config.mkdir()
    # Include optional CPU in the local registry patches for Cargo's resolution
    # of the manifest, but reject it in the actually enabled dependency graph.
    names = ("brynja-core", "brynja-hash-core", "brynja-hash-sha2", "brynja-crypto-cpu")
    (config / "config.toml").write_text("[patch.crates-io]\n" + "\n".join(
        f'{name} = {{ path = "{roots[name].as_posix()}" }}' for name in names) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["CARGO_HOME"] = str(destination / "consumer-empty-cargo-home")
    env["CARGO_TARGET_DIR"] = str(destination / "consumer-target")
    require_success(execute(["cargo", "generate-lockfile", "--offline"], fixture, env))
    metadata = execute(["cargo", "metadata", "--locked", "--offline", "--format-version", "1"], fixture, env)
    require_success(metadata)
    graph = json.loads(metadata.stdout)
    active = {n["id"] for n in graph["resolve"]["nodes"]}
    resolved = [p for p in graph["packages"] if p["id"] in active]
    if {p["name"] for p in resolved} != EXPECTED_GRAPH:
        raise ValueError("consumer gained an external, facade or CPU dependency")
    for package in resolved:
        if package["source"] is not None or not Path(package["manifest_path"]).resolve().is_relative_to(destination.resolve()):
            raise ValueError("consumer escaped extracted package closure")
    return fixture, env, roots


def run(*, regressions=False):
    corpus = oracle.CORPUS.read_text(encoding="utf-8")
    if corpus.encode() != oracle.render():
        raise ValueError("public acceptance corpus differs from independent oracle")
    with tempfile.TemporaryDirectory(prefix="brynja-general-package-") as directory:
        fixture, env, roots = prepare(Path(directory))
        require_success(execute(["cargo", "test", "--locked", "--offline"], fixture, env))
        for mode in ([], ["--release"]):
            command = ["cargo", "run", "--locked", "--offline", *mode]
            good = execute(command, fixture, env, data=corpus)
            require_success(good)
            if SUCCESS not in good.stdout:
                raise ValueError("acceptance success inventory omitted")
            if regressions:
                rows = corpus.splitlines(keepends=True)
                # Every negative run must fail inside the built consumer, not
                # from compilation, cargo resolution, or a missing executable.
                invalid = ("", "".join(rows[:-1]), corpus + rows[-1],
                           rows[1] + rows[0] + "".join(rows[2:]),
                           corpus.replace("1 0 - 80", "1 0 - 00", 1),
                           "1 0 - zz\n", "1 18446744073709551616 - 00\n")
                for data in invalid:
                    result = execute(command, fixture, env, data=data)
                    if result.returncode == 0 or "acceptance failed:" not in result.stderr:
                        raise ValueError("malformed/corrupted corpus was not rejected by executable")
        if regressions:
            compile_fail(fixture, env)
            mutants(fixture, env, roots, corpus)
    print("General SHA-512/t extracted-package acceptance: PASS (4590 independent cases, all 510 t)")


def compile_fail(fixture, env):
    library = fixture / "src/lib.rs"
    original = library.read_text()
    prefix = '\nfn forbidden(p: brynja_hash_sha2::Sha512TBits) { use brynja_hash_sha2::*; '
    cases = (
        ("let h = Sha512T::new(p); let _ = h.finalize(); let _ = h.finalize();", "E0382"),
        ("let h = HardenedSha512T::new(p); h.cancel(); h.cancel();", "E0382"),
        ("let h = HardenedSha512T::new(p); let _ = h.clone();", "E0599"),
        ("let mut out = [0; 64]; if let Ok(secret) = hardened_sha512_t_secret(p, b\"a\", &mut out) { let _ = secret.clone(); }", "E0599"),
        ("let _: Sha512_224Digest = sha512_t(p, b\"a\").unwrap();", "E0308"),
    )
    try:
        for source, error in cases:
            library.write_text(original + prefix + source + " }\n", encoding="utf-8")
            result = execute(["cargo", "check", "--lib", "--locked", "--offline"], fixture, env)
            if result.returncode == 0 or f"error[{error}]" not in result.stderr:
                raise ValueError(f"ownership/type negative missed intended diagnostic: {result.stderr}")
    finally:
        library.write_text(original, encoding="utf-8")


def mutants(fixture, env, roots, corpus):
    changes = (
        ("ordinary.rs", "Sha512State::new(parameter.initial_words())", "Sha512State::new([0; 8])"),
        ("hardened.rs", "HardenedSha2Owner::new64(parameter.initial_words())", "HardenedSha2Owner::new64([0; 8])"),
        ("secret.rs", "Sha512TDigest::computed(self.parameter, self.region.expose())", "let value = Sha512TDigest::computed(self.parameter, self.region.expose()); core::mem::forget(self); value"),
    )
    for name, before, after in changes:
        path = roots["brynja-hash-sha2"] / "src/general" / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError("packaged mutation site drifted")
        try:
            path.write_text(original.replace(before, after), encoding="utf-8")
            for mode in ([], ["--release"]):
                result = execute(["cargo", "run", "--locked", "--offline", *mode], fixture, env, data=corpus)
                if result.returncode == 0 or "acceptance failed:" not in result.stderr:
                    raise ValueError(f"compiled package mutant not caught: {name}\n{result.stderr}")
        finally:
            path.write_text(original, encoding="utf-8")
