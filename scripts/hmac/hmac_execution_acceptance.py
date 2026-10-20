"""Extracted static-execution API checks, without claiming hardware execution."""
import json
from pathlib import Path
import shutil
from hmac_acceptance import ALGORITHMS, diagnostic_rejection
from hmac_faults import result, accepted, rejected, replace_once

ROOT = Path(__file__).resolve().parents[2]


def lifecycle(roots, directory, environment):
    """Compile real retained-owner logic and kill behavioral cleanup mutants."""
    fixture = directory / "execution-faults"
    shutil.copytree(roots["brynja-mac-hmac"], fixture)
    shutil.copyfile(ROOT / "crates/brynja-mac-hmac/src/execution/tests.rs",
                    fixture / "src/execution/tests.rs")
    manifest = fixture / "Cargo.toml"
    manifest.write_text(manifest.read_text() + "\n[workspace]\n[patch.crates-io]\n"
                        + "".join(f"{name}={{path={json.dumps(str(path))}}}\n"
                                  for name, path in roots.items() if name != "brynja-mac-hmac"))
    run = result(["cargo", "generate-lockfile", "--offline"], fixture, environment)
    if run.returncode:
        raise ValueError(run.stderr)
    base = ["cargo", "test", "--offline", "--locked", "--features", "hardened-execution", "--lib"]
    for profile in ([], ["--release"]):
        accepted(result([*base, *profile, "execution::tests"], fixture, environment), 4)
    # Cargo's normalized archive must retain the inherited workspace prohibition.
    library = fixture / "src/lib.rs"
    original_library = library.read_text()
    try:
        library.write_text(original_library + """
/// Deliberate extracted-archive lint rejection probe.
pub fn unsafe_policy_probe() -> u8 { unsafe { core::ptr::read(&1) } }
""")
        diagnostic_rejection(result(
            ["cargo", "check", "--offline", "--locked", "--lib", "--message-format=json"],
            fixture, environment), "unsafe_code")
    finally:
        library.write_text(original_library)
    cases = [
        ("retained.rs", "guard.preserve = matches!(result, Ok(()) | Err(Error::MessageTooLong));",
         "guard.preserve = true;", "failure_drops_both_owners_and_is_terminal"),
        ("retained.rs", "preserve: false,", "preserve: true,",
         "unwind_drops_both_owners_and_is_terminal"),
        ("retained.rs", "Ok(()) | Err(Error::MessageTooLong)", "Ok(())",
         "atomic_length_rejection_preserves_both_owners"),
        ("backends.rs", "// Unlike SHA-2's atomic length preflight,",
         "sha3::Error::LengthOverflow => Error::MessageTooLong,\n        // Unlike SHA-2's atomic length preflight,",
         "sha3_overflow_is_terminal_not_atomic_length_rejection"),
    ]
    for filename, before, after, test in cases:
        path = fixture / "src/execution" / filename
        original = path.read_text()
        command = [*base, "--release", "execution::tests::" + test, "--", "--exact"]
        accepted(result(command, fixture, environment), 1)
        try:
            path.write_text(replace_once(original, before, after))
            rejected(result(command, fixture, environment))
        finally:
            path.write_text(original)
        accepted(result(command, fixture, environment), 1)
    print("HMAC retained execution: 4 debug/release lifecycle tests; 4 compiled mutants rejected")


def check(consumer, environment, roots, *, runtime=False):
    source = consumer / "src/lib.rs"
    manifest = consumer / "Cargo.toml"
    original_source, original_manifest = source.read_text(), manifest.read_text()
    feature = "runtime-execution" if runtime else "hardened-execution"
    enabled = original_manifest.replace(
        'brynja-mac-hmac={version="=0.1.0", default-features=false}',
        'brynja-mac-hmac={version="=0.1.0", default-features=false, features=["' + feature + '"]}')
    if enabled == original_manifest:
        raise ValueError("missing extracted HMAC dependency")
    prefix = '#![no_std]\nuse brynja_mac_hmac::{*, execution::{Hmac as CpuHmac, Authority}};\n'
    command = ["cargo", "check", "--offline", "--locked", "--lib", "--message-format=json"]
    try:
        manifest.write_text(enabled)
        run = result(["cargo", "generate-lockfile", "--offline"], consumer, environment)
        if run.returncode:
            raise ValueError(run.stderr)
        run = result(["cargo", "metadata", "--offline", "--locked", "--format-version", "1"],
                     consumer, environment)
        if run.returncode:
            raise ValueError(run.stderr)
        graph = json.loads(run.stdout)
        if {p["name"] for p in graph["packages"]} != set(roots) | {"hmac-external"}:
            raise ValueError("unexpected accelerated HMAC dependency closure")
        for package in graph["packages"]:
            location = consumer if package["name"] == "hmac-external" else roots[package["name"]]
            if package["source"] is not None or Path(package["manifest_path"]).resolve() != location / "Cargo.toml":
                raise ValueError("accelerated HMAC dependency escaped extracted archives")
        positive = "\n".join(
            f"pub fn p{index}<'a>(owner: &'a Authority, key: &[u8]) -> Result<CpuHmac<'a, {a}>, Error> "
            "{CpuHmac::from_static(owner, key)}"
            for index, a in enumerate(ALGORITHMS))
        positive += "\npub fn tag<'o>(mac: CpuHmac<Sha256>, out: &'o mut [u8]) -> Result<Tag<'o, Sha256>, Error> {mac.finalize_tag(out)}"
        if runtime:
            positive += "\n".join(
                f"pub fn r{index}<'a>(owner: &'a execution::RuntimeAuthority, key: &[u8]) -> Result<CpuHmac<'a, {a}>, Error> "
                "{CpuHmac::from_runtime(owner, key)}"
                for index, a in enumerate(ALGORITHMS))
        source.write_text(prefix + positive)
        run = result(command, consumer, environment)
        if run.returncode:
            raise ValueError("accelerated API positive probe failed: " + run.stderr)
        cases = []
        for algorithm in ALGORITHMS:
            for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
                cases.append((f"fn bound<T: {bound}>() {{}} pub fn p() {{bound::<CpuHmac<'static, {algorithm}>>();}}", "E0277"))
        cases.extend([
            ("pub fn p(owner: Authority) -> Result<CpuHmac<'static, Sha256>, Error> {CpuHmac::from_static(&owner, b\"key\")}", "E0515"),
            ("pub fn p(mut mac: CpuHmac<Sha256>) {mac.cancel(); let _ = mac.update(b\"late\");}", "E0382"),
            ("pub fn p(mac: CpuHmac<Sha256>) {mac.report();}", "E0599"),
            ("pub fn p(mac: CpuHmac<Sha256>) {mac.check_additional_bits(1);}", "E0599"),
            ("pub fn p() {let _ = CpuHmac::<Sha256>::new(b\"key\");}", "E0599"),
            ("pub fn p<'a>(mac: CpuHmac<Sha256>, out: &'a mut [u8]) -> Result<Tag<'a, Sha224>, Error> {mac.finalize_tag(out)}", "E0308"),
        ])
        if runtime:
            cases.extend([
                ("pub fn p(owner: execution::RuntimeAuthority) -> Result<CpuHmac<'static, Sha256>, Error> {CpuHmac::from_runtime(&owner, b\"key\")}", "E0515"),
                ("pub fn p(owner: Authority) {let _ = CpuHmac::<Sha256>::from_runtime(&owner, b\"key\");}", "E0308"),
            ])
        for code, diagnostic in cases:
            source.write_text(prefix + code)
            diagnostic_rejection(result(command, consumer, environment), diagnostic)
    finally:
        source.write_text(original_source)
        manifest.write_text(original_manifest)
    print(f"HMAC packaged {feature} API: {len(ALGORITHMS)} positive identities; {len(cases)} rejected probes")
