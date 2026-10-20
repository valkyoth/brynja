#!/usr/bin/env python3
"""Linux protected HMAC: real extracted consumers and executed cleanup mutants."""
import importlib.util
from pathlib import Path
import shutil
import sys

import hmac_verifiers as verifier
from hmac_acceptance import diagnostic_rejection

ROOT = verifier.ROOT
spec = importlib.util.spec_from_file_location(
    "hmac_hosted_packaging", ROOT / "scripts/cpu/check-hosted-execution.py")
sys.path.append(str(ROOT / "scripts/cpu"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def population(result, count):
    if f"test result: ok. {count} passed; 0 failed; 0 ignored;" not in result.stdout:
        raise ValueError("protected HMAC acceptance population changed")


def negatives(consumer, env):
    source = consumer / "src/lib.rs"
    prefix = "use brynja_crypto_cpu_std::strict_hmac::*;\n"
    positive = '''pub fn p(s: &mut Session<Sha256>) -> Result<Output<'_, Sha256>, Error> {
    s.authenticate(b"key", b"message")
}
'''
    source.write_text(prefix + positive)
    command = ["cargo", "check", "--offline", "--lib", "--message-format=json"]
    host.run(command, consumer, env)
    cases = []
    for algorithm in ("Sha256", "Sha512T<129>"):
        for owner in (f"Session<{algorithm}>", f"Output<'static, {algorithm}>"):
            for trait in ("Send", "Sync", "Clone", "Copy", "core::fmt::Debug"):
                cases.append((f"fn bound<T: {trait}>() {{}} pub fn p() {{bound::<{owner}>();}}", "E0277"))
    cases.extend([
        (positive.replace("s: &mut Session<Sha256>", "mut s: Session<Sha256>").replace(
            "Output<'_, Sha256>", "Output<'static, Sha256>"), "E0515"),
        (positive.replace("Output<'_, Sha256>", "Output<'_, Sha224>"), "E0308"),
        ('''pub fn p(s: &mut Session<Sha256>) -> Result<(), Error> {
            let first = s.authenticate(b"key", b"a")?;
            let second = s.authenticate(b"key", b"b")?;
            assert_eq!(first.expose(), second.expose()); Ok(())
        }''', "E0499"),
        ("pub fn p(s: Session<Sha256>) { let _ = s.stack; }", "E0616"),
    ])
    for code, diagnostic in cases:
        source.write_text(prefix + code)
        result = host.run(command, consumer, env, success=False)
        diagnostic_rejection(result, diagnostic)
    # Absence of the opt-in feature must prevent importing the entire surface.
    source.write_text(prefix + positive)
    manifest = consumer / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace(', features = ["strict-hmac"]', ''))
    diagnostic_rejection(host.run(command, consumer, env, success=False), "E0432")
    print(f"Protected HMAC packaged ownership/API: {len(cases) + 1} rejected probes")


def mutants(workspace, env):
    directory = workspace / "crates/brynja-crypto-cpu-std/src/strict_hmac"
    cases = [
        ("mod.rs", "if !self.keep {", "if false {",
         "cancellation_unwind_and_post_write_failure_clear_and_reuse"),
        ("worker.rs", "state.update(part).map_err(Error::Mac)?;", "let _ = part;",
         "all_identities_match_portable_and_storage_is_protected"),
        ("worker.rs", ".expose_public(),", ".expose_public() || true,",
         "all_identities_match_portable_and_storage_is_protected"),
        ("types.rs", "if bits > limits.max_message_bits {", "if false {",
         "budgets_and_partial_tag_comparison_fail_closed"),
    ]
    for name, before, after, test in cases:
        path = directory / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError("protected HMAC mutant anchor drift")
        command = ["cargo", "test", "--offline", "-p", host.HOST,
                   "--features", "strict-hmac", "--lib",
                   "strict_hmac::tests::native::" + test]
        try:
            path.write_text(original.replace(before, after))
            host.run([*command, "--no-run"], workspace, env)
            result = host.run(command, workspace, env, success=False)
            if "test result: FAILED. 0 passed; 1 failed; 0 ignored;" not in result.stdout:
                raise ValueError("protected HMAC mutant did not fail its behavioral test")
        finally:
            path.write_text(original)
    print(f"Protected HMAC: {len(cases)} compiled behavioral mutants rejected")


def main():
    if sys.platform != "linux":
        raise ValueError("protected HMAC native acceptance requires supported GNU/Linux")
    with verifier.cargo_environment.private_directory(ROOT) as raw:
        root = Path(raw)
        env = verifier.environment(root)
        shutil.copyfile(ROOT / "rust-toolchain.toml", root / "rust-toolchain.toml")
        workspace = host.isolated(root)
        for profile in ([], ["--release"]):
            population(host.run(["cargo", "test", "--offline", "-p", host.HOST, "--features",
                                 "strict-hmac", "--lib", "strict_hmac", *profile], workspace, env), 6)
        consumer = host.package_consumer(root, workspace, env)
        manifest = consumer / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace(
            'features = ["runtime-execution"]', 'features = ["strict-hmac"]').replace(
            '[dependencies]\n', '[dependencies]\nbrynja-mac-hmac = {version="=0.1.0", default-features=false}\n'))
        # Remove the old runtime fixture source, not any archive runtime source.
        (consumer / "src/lib.rs").write_text("")
        (consumer / "src/main.rs").write_text("fn main() {}")
        (consumer / "tests").mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "assurance/hmac-protected/acceptance.rs", consumer / "tests/protected.rs")
        for profile in ([], ["--release"]):
            population(host.run(["cargo", "test", "--offline", "--test", "protected", *profile],
                                consumer, env), 3)
        negatives(consumer, env)
        mutants(workspace, env)
    print("Protected scalar HMAC packaged acceptance: PASS; author tests, qualification pending")


if __name__ == "__main__":
    main()
