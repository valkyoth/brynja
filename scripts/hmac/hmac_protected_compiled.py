"""Compiled protected HMAC probes; native execution is explicitly selected."""
import platform
from hmac_acceptance import ALGORITHMS, diagnostic_rejection
from hmac_owner_profile import PROTECTED, RESIDENT


def negatives(host, consumer, env, owner=PROTECTED):
    manifest = consumer / "Cargo.toml"
    original = manifest.read_text()
    enabled = original.replace('brynja-crypto-cpu-std = {',
                               f'brynja-crypto-cpu-std = {{features=["{owner.feature}-acceleration"], ')
    if enabled == original:
        raise ValueError("compiled HMAC package dependency missing")
    manifest.write_text(enabled)
    source = consumer / "src/lib.rs"
    prefix = f"use brynja_crypto_cpu_std::{owner.module}::*;\n"
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
                                        f'brynja-crypto-cpu-std = {{features=["{owner.feature}"], '))
    source.write_text(f"use brynja_crypto_cpu_std::{owner.module}::" +
                     "{CompiledSession, Sha256, Output, Error};\n" + positive)
    diagnostic_rejection(host.run(command, consumer, env, success=False), "E0432")
    manifest.write_text(original)
    source.write_text("")
    print(f"{owner.label} compiled HMAC package: 12 positive identities, {len(cases) + 1} rejected probes")


def native_environment(env, kernel, owner=PROTECTED):
    owner.require_host()
    arch = platform.machine()
    if owner == RESIDENT:
        arch = "aarch64"
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


def preentry(host, workspace, env, kernel, population, owner=PROTECTED):
    """Actually execute the ignored SHA-256 startup/forgotten-loan regression."""
    if kernel != "sha256":
        return
    module = ("macos_resident::resource::darwin::tests" if owner == RESIDENT
              else "protected_memory::platform::thread::tests")
    test = module + "::hmac_preentry_failures_preserve_session"
    for profile in ([], ["--release"]):
        command = ["cargo", "test", "--offline", "-p", host.HOST, "--features",
                   owner.feature + "-acceleration", "--lib", *profile,
                   test, "--", "--ignored", "--exact"]
        population(host.run(command, workspace, env), 1)
    print(f"{owner.label} HMAC native startup failures: debug/release PASS")


def native(host, root, workspace, consumer, env, kernel, population, owner=PROTECTED):
    env = native_environment(env, kernel, owner)
    preentry(host, workspace, env, kernel, population, owner)
    command = ["cargo", "test", "--offline", "-p", host.HOST,
               "--features", owner.feature + "-acceleration", "--lib",
               owner.module + "::compiled::tests::native::" + kernel + "_route"]
    for profile in ([], ["--release"]):
        population(host.run([*command, *profile, "--", "--ignored", "--exact"], workspace, env), 1)
    manifest = consumer / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace(
        'brynja-crypto-cpu-std = {', f'brynja-crypto-cpu-std = {{features=["{owner.feature}-acceleration"], '))
    (consumer / "tests/compiled.rs").write_text(owner.source(
        (root / "assurance/hmac-protected/compiled.rs").read_text()))
    for profile in ([], ["--release"]):
        population(host.run(["cargo", "test", "--offline", "--test", "compiled", *profile],
                            consumer, env), 1)
    mutants(host, workspace, env, command, owner)
    print(f"{owner.label} compiled HMAC native/package/mutation acceptance: PASS; {kernel}; author testing only")


def mutants(host, workspace, env, command, owner=PROTECTED):
    directory = workspace / "crates/brynja-crypto-cpu-std/src" / owner.directory
    cases = [
        ("compiled.rs", "self.quarantined = true;", "self.quarantined = false;"),
        ("compiled/worker.rs", "state.update(part).map_err(Error::Mac)?;", "let _ = part;"),
        ("compiled/worker.rs", "Err(brynja_mac_hmac::Error::Mismatch) => false,", "Err(brynja_mac_hmac::Error::Mismatch) => true,"),
        ("compiled.rs", "Some(false) => Err(Error::Mismatch),", "Some(false) => Ok(()),"),
        ("mod.rs", "if !self.keep {", "if false {"),
    ]
    for name, before, after in cases:
        source = directory / name
        original = source.read_text()
        expected = 2 if before == "self.quarantined = true;" else 1
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
