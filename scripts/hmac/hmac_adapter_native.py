"""Real extracted native adapters, explicit host route, no public test hooks."""
import platform
import shutil

from hmac_faults import ROOT, accepted, rejected, replace_once, result

FEATURES = {
    "x86_64": {"sha256": "+sha,+sse2", "sha512": "+sha512,+avx,+avx2", "keccak": "+avx2"},
    "aarch64": {"sha256": "+neon,+sha2", "sha512": "+neon,+sha3", "keccak": "+neon,+sha3"},
}


def check(roots, directory, environment, kernel):
    arch = {"arm64": "aarch64"}.get(platform.machine(), platform.machine())
    if arch not in FEATURES or kernel not in FEATURES[arch]:
        raise ValueError("unsupported HMAC adapter native route")
    # Detection inside a target-feature-enabled binary can fold to true.
    # A separate dependency-free generic rustc probe must execute first.
    probe = directory / "hmac-host-probe"
    compiled = result(["rustc", "+1.99.1", "--edition=2024", "-C", "target-cpu=generic",
                       str(ROOT / "assurance/hmac-faults/host_probe.rs"), "-o", str(probe)],
                      directory, environment)
    if compiled.returncode:
        raise ValueError("HMAC generic feature probe failed to compile: " + compiled.stderr[-2000:])
    observed = result([str(probe), kernel], directory, environment)
    if observed.returncode or observed.stdout.splitlines() != ["HMAC_HOST_FEATURES: " + kernel]:
        raise ValueError("HMAC generic host instruction preflight failed")
    # lifecycle() already made this private archive copy, including its exact
    # extracted manifest, path patches and real retained-owner unit tests.
    prepared = directory / "execution-faults"
    if not (prepared / "Cargo.toml").is_file():
        raise ValueError("missing private extracted native fixture")
    fixture = directory / ("native-adapter-" + kernel)
    shutil.copytree(prepared, fixture)
    library = fixture / "src/lib.rs"
    library.write_text(library.read_text() + "\n#[cfg(test)] mod adapter_tests;\n")
    execution = fixture / "src/execution/mod.rs"
    execution.write_text(execution.read_text() + "\n#[cfg(test)] mod native_adapter_tests;\n")
    for name, destination in (("adapter_tests.rs", "src/adapter_tests.rs"),
                              ("native_adapter_tests.rs", "src/execution/native_adapter_tests.rs")):
        shutil.copyfile(ROOT / "assurance/hmac-faults" / name, fixture / destination)
    env = dict(environment)
    env["RUSTFLAGS"] = "-C target-feature=" + FEATURES[arch][kernel]
    env["BRYNJA_HMAC_ADAPTER_KERNEL"] = kernel
    command = ["cargo", "test", "--offline", "--locked", "--features", "hardened-execution",
               "--lib", "execution::native_adapter_tests::real_native_adapter_handoffs"]
    marker = "HMAC_NATIVE_ADAPTER_HANDOFF: " + kernel + " " + str(
        {"sha256": 24, "sha512": 72, "keccak": 48}[kernel])

    def baseline(profile):
        run = result([*command, *profile, "--", "--exact", "--nocapture"], fixture, env)
        accepted(run, 1)
        if marker not in run.stdout.splitlines():
            raise ValueError("missing native adapter handoff population")

    for profile in ([], ["--release"]):
        baseline(profile)
    path = fixture / "src/execution/backends.rs"
    original = path.read_text()
    anchors = ["consume(($digest)(&result))"]
    if kernel == "sha512":
        anchors.append("consume(result.digest.as_bytes())")
    for before in anchors:
        mutations = (
            f"let callback = {before};\ncore::mem::forget(result);\ncallback",
            f"let _ = {before};\nOk(())",
            f"let result = core::mem::ManuallyDrop::new(result);\nlet callback = {before};\n"
            "drop(core::mem::ManuallyDrop::into_inner(result));\ncallback",
        )
        for after in mutations:
            try:
                path.write_text(replace_once(original, before, after))
                rejected(result([*command, "--release", "--", "--exact"], fixture, env))
            finally:
                path.write_text(original)
            baseline(["--release"])
    print(f"HMAC native adapter handoff: {arch} {kernel}; debug/release; "
          f"{len(anchors) * 3} compiled output-owner/callback mutants rejected")
