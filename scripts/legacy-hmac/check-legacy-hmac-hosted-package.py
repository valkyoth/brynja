#!/usr/bin/env python3
"""Bounded extracted Linux protected / Apple resident legacy HMAC acceptance."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import tomllib
from unittest.mock import patch

import legacy_hmac_hosted_acceptance as policy
import legacy_hmac_hosted_sha1 as compiled
from legacy_hmac_acceptance import NAMES, require

spec = importlib.util.spec_from_file_location("legacy_package", Path(__file__).with_name("check-legacy-hmac-package.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
ARCHIVES = (*NAMES, policy.HOST, "brynja-crypto-cpu", "brynja-crypto-cpu-std",
            "brynja-hash-sha2", "brynja-hash-sha3", "brynja-mac-kmac",
            "brynja-mac-hmac", "brynja-hash-tuple")
PRELUDE = 'use brynja_legacy_hmac_std::strict_execution::*;\n'
POSITIVE = 'pub fn check(s: &mut Session<Sha1>) -> Result<(), Error> { drop(s.authenticate(b"key",b"message")?); Ok(()) }'


def package_workspace(destination):
    workspace = ORIGINAL_WORKSPACE(destination)
    path = workspace / "Cargo.toml"
    text = path.read_text()
    before = 'brynja-crypto-cpu-std = { path = "crates/brynja-crypto-cpu-std", version = "=0.1.1" }'
    require(text.count(before) == 1, "host provider workspace default binding")
    path.write_text(text.replace(before, before[:-2] + ', default-features = false }'))
    return workspace


ORIGINAL_WORKSPACE = api.packaging.isolated_package_workspace


def negatives(consumer, env, resident=False, accelerated=False):
    prelude = PRELUDE.replace("strict_execution", "macos_resident") if resident else PRELUDE
    source = consumer / "src/lib.rs"
    command = ["cargo", "check", "--offline", "--locked", "--lib", "--features",
               "brynja-legacy-hmac-std/strict-execution,brynja-legacy-hmac-std/macos-resident"]
    cases = []
    for identity in ("Sha1", "Md5"):
        for owner in (f"Session<{identity}>", f"Output<'static, {identity}>"):
            for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
                cases.append((f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{owner}>();}}', "E0277"))
    cases.extend([
        ('fn probe(o:Output<Sha1>)->Output<Md5>{o}', "E0308"),
        ('fn probe(s:&mut Session<Sha1>)->Result<(),Error>{let a=s.authenticate(b"k",b"a")?; let b=s.authenticate(b"k",b"b")?; let _=(a.expose(),b.expose());Ok(())}', "E0499"),
        ('fn probe(l:Limits){let _=Session::<Sha1>::new(TagPolicy::Full,l);}', "E0061"),
        ('use brynja_legacy_hmac_std::strict_execution::ProtectedStack;', "E0603"),
        ('use brynja_legacy_hmac_std::strict_execution::Sha256;', "E0432"),
        ('fn probe(o:Output<Sha1>, b:&mut[u8]){let _=o.declassify(b);}', "E0061"),
    ])
    # Compile both profiles together: rejection must survive Cargo feature unification.
    for origin, target in (("strict_execution", "macos_resident"), ("macos_resident", "strict_execution")):
        cases.append((f'fn convert(s:brynja_legacy_hmac_std::{origin}::Session<Sha1>) -> '
                      f'brynja_legacy_hmac_std::{target}::Session<Sha1>{{s}}', "E0308"))
    if accelerated:
        command[-1] += ",brynja-legacy-hmac-std/strict-sha1-acceleration,brynja-legacy-hmac-std/macos-resident-sha1-acceleration"
        cases.extend(compiled.negatives())
    try:
        source.write_text(prelude + POSITIVE)
        api.run(command, consumer, env)
        for body, code in cases:
            if resident and not body.startswith("fn convert("):
                body = body.replace("strict_execution", "macos_resident").replace("ProtectedStack", "ResidentStack")
            source.write_text(prelude + body)
            api.cargo_environment.check(consumer, env)
            result = subprocess.run(command, cwd=consumer, env=env, capture_output=True, text=True, timeout=90, check=False)
            diagnostic = "lifetime may not live long enough" if code == "LIFETIME" else f"error[{code}]"
            require(result.returncode == 101 and diagnostic in result.stderr,
                    "hosted compiled negative: " + code + "\n" + result.stderr[-1800:])
    finally:
        source.write_text(prelude + POSITIVE)
    api.run(command, consumer, env)
    print(f"Hosted legacy HMAC ownership/classification negatives: {len(cases)} rejected", flush=True)


def mutations(roots, env, resident=False):
    module = "macos_resident" if resident else "strict_execution"
    feature = "macos-resident" if resident else "strict-execution"
    root = roots[policy.HOST]
    path = root / f"src/{module}/mod.rs"
    original = path.read_text()
    test = module + "::tests::native::"
    cases = [
        ("self.output.clear();", "", "output_loan_forget_errors_and_explicit_release"),
        ("self.staging.clear();", "", "output_loan_forget_errors_and_explicit_release"),
        ("self.storage.clear();", "", "output_loan_forget_errors_and_explicit_release"),
        ("if !self.keep {", "if false {", "every_worker_checkpoint_and_post_write_failure_clear_and_reuse"),
        ("types::validate(self.limits, &request, candidate, self.bytes)?;", "", "output_loan_forget_errors_and_explicit_release"),
    ]
    for before, after, selected in cases:
        require(before in original, "hosted mutation anchor")
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ["--release"]):
                command = ["cargo", "test", "--offline", "--features", feature, *profile, "--lib", test + selected]
                api.run(command + ["--no-run"], root, env)
                api.cargo_environment.check(root, env)
                result = subprocess.run(command + ["--", "--exact"], cwd=root, env=env,
                                        text=True, capture_output=True, timeout=180, check=False)
                require(result.returncode == 101 and "test result: FAILED. 0 passed; 1 failed;" in result.stdout,
                        "hosted mutant must fail its assertion, not compilation: " + before + "\n" + result.stdout[-1500:] + result.stderr[-1000:])
        finally:
            path.write_text(original)
    print(f"Hosted legacy HMAC compiled cleanup mutants: {len(cases)*2} rejected", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resident", action="store_true", help="explicit native macOS resident profile, NOT dump exclusion")
    parser.add_argument("--sha1-native", action="store_true", help="explicit compiled SHA-1; requires real native hardware")
    args = parser.parse_args()
    resident, accelerated = args.resident, args.sha1_native
    if resident:
        require(platform.system() == "Darwin" and platform.machine() == "arm64", "requires native Apple Silicon")
    else:
        require(platform.system() == "Linux" and platform.machine() in ("x86_64", "aarch64")
                and platform.libc_ver()[0] == "glibc", "requires native protected GNU/Linux host")
    feature = "macos-resident" if resident else "strict-execution"
    if accelerated:
        feature = "macos-resident-sha1-acceleration" if resident else "strict-sha1-acceleration"
        import legacy_hmac_native
        target_features = legacy_hmac_native.features()
    specifications = tuple((name, tomllib.loads((api.ROOT / "crates" / name / "Cargo.toml").read_text())["package"]["version"],
                            ("src/lib.rs",)) for name in ARCHIVES)
    with api.cargo_environment.private_directory(api.ROOT) as temporary:
        directory = Path(temporary)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO_", "RUST", "BRYNJA_"))}
        env.update(CARGO_HOME=str(directory / "cargo-home"), CARGO_TARGET_DIR=str(directory / "consumer-target"))
        if accelerated:
            env["RUSTFLAGS"] = "-C target-feature=" + target_features
        api.cargo_environment.check(api.ROOT, env)
        with patch.object(api.packaging, "PACKAGING_PACKAGES", specifications), \
             patch.object(api.packaging, "isolated_package_workspace", package_workspace), patch.dict(os.environ, env, clear=True):
            roots = api.packaging.package_roots(directory)
        root = roots[policy.HOST]
        policy.members(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
        size = (directory / "target/package/brynja-legacy-hmac-std-0.1.0.crate").stat().st_size
        print(f"Hosted legacy HMAC source-only archive: {size} bytes", flush=True)
        consumer = directory / "consumer"
        (consumer / "src").mkdir(parents=True)
        patches = ''.join(f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
        manifest = ('[workspace]\n[package]\nname="legacy-hosted-external"\nversion="0.0.0"\nedition="2024"\n'
                    '[dependencies]\nbrynja-legacy-hmac-std={version="=0.1.0",default-features=false,features=["' + feature + '"]}\n'
                    '[patch.crates-io]\n' + patches)
        (consumer / "Cargo.toml").write_text(manifest)
        (consumer / "src/lib.rs").write_text((PRELUDE.replace("strict_execution", "macos_resident") if resident else PRELUDE) + POSITIVE)
        api.run(["cargo", "generate-lockfile", "--offline"], consumer, env)
        graph = json.loads(api.run(["cargo", "metadata", "--offline", "--locked", "--format-version=1"], consumer, env))
        policy.graph(graph, roots, consumer, resident, accelerated)
        # Test the actual archived private implementation and its native fault
        # hooks too; patch only its external dependency resolution, never code.
        for path in roots.values():
            manifest = path / "Cargo.toml"
            manifest.write_text(manifest.read_text() + "\n[workspace]\n[patch.crates-io]\n" + patches)
        for profile in ([], ["--release"]):
            result = api.run(["cargo", "test", "--offline", "--features", feature, *profile, "--lib"], root, env)
            policy.runtime(result, 10 if accelerated else 6)
            api.run(["cargo", "test", "--offline", "--features", feature, *profile, "--doc"], root, env)
        negatives(consumer, env, resident, accelerated)
        mutations(roots, env, resident)
        if accelerated:
            compiled.mutations(api, roots[policy.HOST], env, resident)
        policy.runtime(api.run(["cargo", "test", "--offline", "--features", feature, "--lib"], root, env), 10 if accelerated else 6)
    print(f"Legacy HMAC {feature} extracted-package acceptance: PASS; author checks, qualification pending", flush=True)


if __name__ == "__main__":
    main()
