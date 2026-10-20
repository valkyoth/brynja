"""Compiled protected HMAC probes; native execution is explicitly selected."""
import platform
import shutil
from hmac_acceptance import ALGORITHMS, diagnostic_rejection


def negatives(host, consumer, env):
    manifest = consumer / "Cargo.toml"
    original = manifest.read_text()
    enabled = original.replace('brynja-crypto-cpu-std = {',
                               'brynja-crypto-cpu-std = {features=["strict-hmac-acceleration"], ')
    if enabled == original:
        raise ValueError("compiled HMAC package dependency missing")
    manifest.write_text(enabled)
    source = consumer / "src/lib.rs"
    prefix = "use brynja_crypto_cpu_std::strict_hmac::*;\n"
    command = ["cargo", "check", "--offline", "--lib", "--message-format=json"]
    positive = '''pub fn p(s: &mut CompiledSession<Sha256>) -> Result<Output<'_, Sha256>, Error> {
    s.authenticate(b"key", b"message")
}'''
    source.write_text(prefix + positive + "\n".join(
        f"pub fn c{i}(k: Kernel, l: Limits) -> Result<CompiledSession<{a}>, Error> "
        "{CompiledSession::new(TagPolicy::Full, k, l)}"
        for i, a in enumerate(ALGORITHMS)))
    host.run(command, consumer, env)
    cases = []
    for algorithm in ("Sha256", "Sha512T<129>"):
        for trait in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
            cases.append((f"fn bound<T:{trait}>() {{}} pub fn p() {{bound::<CompiledSession<{algorithm}>>();}}", "E0277"))
    cases += [
        (positive.replace("s: &mut CompiledSession<Sha256>", "mut s: CompiledSession<Sha256>")
         .replace("Output<'_, Sha256>", "Output<'static, Sha256>"), "E0515"),
        (positive.replace("Output<'_, Sha256>", "Output<'_, Sha224>"), "E0308"),
        ('''pub fn p(s: &mut CompiledSession<Sha256>) -> Result<(), Error> {
            let out = s.authenticate(b"key", b"message")?;
            s.quarantine(); let _ = out.expose(); Ok(())
        }''', "E0499"),
        ("pub fn p(s: CompiledSession<Sha256>) { let _ = s.inner; }", "E0616"),
    ]
    for code, diagnostic in cases:
        source.write_text(prefix + code)
        diagnostic_rejection(host.run(command, consumer, env, success=False), diagnostic)
    manifest.write_text(original.replace('brynja-crypto-cpu-std = {',
                                        'brynja-crypto-cpu-std = {features=["strict-hmac"], '))
    source.write_text("use brynja_crypto_cpu_std::strict_hmac::{CompiledSession, Sha256, Output, Error};\n" + positive)
    diagnostic_rejection(host.run(command, consumer, env, success=False), "E0432")
    manifest.write_text(original)
    source.write_text("")
    print(f"Protected compiled HMAC package: 12 positive identities, {len(cases) + 1} rejected probes")


def native_environment(env, kernel):
    arch = platform.machine()
    features = {
        "x86_64": {"sha256": "+sha,+sse2", "sha512": "+sha512,+avx2,+avx", "keccak": "+avx2"},
        "aarch64": {"sha256": "+neon,+sha2", "sha512": "+neon,+sha3", "keccak": "+neon,+sha3"},
    }
    if arch not in features or kernel not in features[arch]:
        raise ValueError("unsupported protected HMAC native selection")
    result = dict(env)
    result["RUSTFLAGS"] = "-C target-feature=" + features[arch][kernel]
    result["BRYNJA_HMAC_PROTECTED_KERNEL"] = kernel
    return result


def native(host, root, workspace, consumer, env, kernel, population):
    env = native_environment(env, kernel)
    command = ["cargo", "test", "--offline", "-p", host.HOST,
               "--features", "strict-hmac-acceleration", "--lib",
               "strict_hmac::compiled::tests::native::" + kernel + "_route"]
    for profile in ([], ["--release"]):
        population(host.run([*command, *profile, "--", "--ignored", "--exact"], workspace, env), 1)
    manifest = consumer / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace(
        'brynja-crypto-cpu-std = {', 'brynja-crypto-cpu-std = {features=["strict-hmac-acceleration"], '))
    shutil.copyfile(root / "assurance/hmac-protected/compiled.rs", consumer / "tests/compiled.rs")
    for profile in ([], ["--release"]):
        population(host.run(["cargo", "test", "--offline", "--test", "compiled", *profile],
                            consumer, env), 1)
    mutants(host, workspace, env, command)
    print(f"Protected compiled HMAC native/package/mutation acceptance: PASS; {kernel}; author testing only")


def mutants(host, workspace, env, command):
    directory = workspace / "crates/brynja-crypto-cpu-std/src/strict_hmac"
    cases = [
        ("compiled.rs", "self.quarantined = true;", "self.quarantined = false;"),
        ("compiled/worker.rs", "state.update(part).map_err(Error::Mac)?;", "let _ = part;"),
        ("compiled/worker.rs", ".expose_public(),", ".expose_public() || true,"),
        ("mod.rs", "if !self.keep {", "if false {"),
    ]
    for name, before, after in cases:
        source = directory / name
        original = source.read_text()
        expected = 2 if name == "compiled.rs" else 1
        if original.count(before) != expected:
            raise ValueError("compiled protected HMAC mutant anchor drift")
        try:
            source.write_text(original.replace(before, after))
            host.run([*command, "--no-run"], workspace, env)
            result = host.run([*command, "--", "--ignored", "--exact"], workspace, env, success=False)
            if "test result: FAILED. 0 passed; 1 failed; 0 ignored;" not in result.stdout:
                raise ValueError("compiled HMAC mutant did not fail its executed test")
        finally:
            source.write_text(original)
