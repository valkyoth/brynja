#!/usr/bin/env python3
"""Explicit native hosted HMAC errors/fallback checks; not compiler qualification."""
import argparse
import importlib.util
from pathlib import Path
import platform
import sys

import hmac_verifiers as verifier
from hmac_faults import accepted, rejected, replace_once, result

ROOT = verifier.ROOT
sys.path.append(str(ROOT / "scripts/cpu"))
spec = importlib.util.spec_from_file_location(
    "hmac_native_host_packaging", ROOT / "scripts/cpu/check-hosted-execution.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

MUTANTS = (
    ("None => Ok(HmacSelection::Portable(PortableHmac::new(tag_bytes)?)),",
     "None => Err(HmacError::Mac(brynja_mac_hmac::Error::ExecutionFailed)),",
     "portable_selection_does_not_process_keys"),
    ("let _ = owner\n                    .session()\n                    .map_err(|error| HmacError::Hosted(Error::Kernel(error)))?;",
     "if owner.session().is_err() { return Ok(HmacSelection::Portable(PortableHmac::new(tag_bytes)?)); }", "native_hosted_all_identities"),
    ("                .map_err(HmacError::Mac)?;", ".ok();\n                if mac.is_none() { return Ok(HmacSelection::Portable(PortableHmac::new(tag_bytes)?)); }\n"
     "                let mac = mac.unwrap();", "native_hosted_all_identities"),
    ("Ok(HmacSelection::Accelerated(mac))", "let _: Hmac<'a, A> = mac; Ok(HmacSelection::Portable(PortableHmac::new(tag_bytes)?))", "native_hosted_all_identities"),
    ("Some(length) => Hmac::from_runtime_with_tag_length(owner, key, length),",
     "Some(_) => Hmac::from_runtime(owner, key),", "native_hosted_all_identities"),
    ("brynja_mac_hmac::validate_tag_policy::<A>(tag_bytes).map_err(HmacError::Mac)?;", "// omitted algorithm/tag admission",
     "portable_selection_does_not_process_keys"),
    ("tag_bytes,\n            _algorithm: PhantomData", "tag_bytes: None,\n            _algorithm: PhantomData",
     "portable_selection_does_not_process_keys"),
    ("Some(length) => brynja_mac_hmac::Hmac::with_tag_length(key, length),",
     "Some(_) => brynja_mac_hmac::Hmac::new(key),", "portable_selection_does_not_process_keys"),
)


def check(workspace, env, kernel):
    if platform.machine() not in ("arm64", "aarch64") or sys.platform not in ("linux", "darwin"):
        raise ValueError("native hosted HMAC requires an admitted AArch64 Linux/Mac host")
    env = dict(env, BRYNJA_HMAC_HOSTED_KERNEL=kernel)
    command = ["cargo", "test", "--offline", "-p", host.HOST, "--features",
               "hmac-execution", "--test", "hmac"]
    marker = f"HMAC_NATIVE_HOSTED: {kernel} " + str(
        {"sha256": 2, "sha512": 6, "keccak": 4}[kernel]) + " identities; Require and Prefer"

    def run(test, profile, baseline=True):
        args = [*command, *profile, test, "--", "--exact"]
        if test == "native_hosted_all_identities":
            args += ["--ignored", "--nocapture"]
        observed = result(args, workspace, env)
        if baseline:
            accepted(observed, 1)
            if test == "native_hosted_all_identities" and marker not in observed.stdout.splitlines():
                raise ValueError("missing hosted native identity population")
        else:
            rejected(observed)

    for profile in ([], ["--release"]):
        run("portable_selection_does_not_process_keys", profile)
        run("native_hosted_all_identities", profile)
    path = workspace / "crates" / host.HOST / "src/execution/hmac.rs"
    original = path.read_text()
    for before, after, test in MUTANTS:
        run(test, ["--release"])
        try:
            path.write_text(replace_once(original, before, after))
            run(test, ["--release"], baseline=False)
        finally:
            path.write_text(original)
        run(test, ["--release"])
    print(f"HMAC hosted native: {kernel}; debug/release; both selection modes; "
          "8 compiled fallback/policy mutants rejected; not independent qualification", flush=True)


def check_portable_policy(workspace, env):
    """Exercise portable selection and metadata-only Linux/Mac policy adapters."""
    root = workspace / "crates" / host.HOST
    features = "hmac-execution,strict-hmac,macos-resident-hmac"
    base = ["cargo", "test", "--offline", "-p", host.HOST, "--features", features]
    portable = ["--test", "hmac", "portable_policy_matches_leaf_for_all_algorithms_and_boundaries", "--", "--exact"]
    cases = [(root / "src/execution/hmac.rs", before, after, portable)
             for before, after, _test in MUTANTS[5:]]
    for module in ("strict_hmac", "macos_resident/hmac"):
        test = module.replace("/", "::") + "::tests::metadata_admission_and_exact_tag_policy"
        path = root / "src" / module / "types.rs"
        for before, after in (("Self::Bytes(bytes) => Some(bytes)", "Self::Bytes(_bytes) => None"),
                              ("brynja_mac_hmac::Error::TagLength => Error::InvalidTagPolicy",
                               "brynja_mac_hmac::Error::TagLength => Error::Mac(brynja_mac_hmac::Error::TagLength)")):
            cases.append((path, before, after, ["--lib", test, "--", "--exact"]))
    for path, before, after, test in cases:
        original = path.read_text()
        for profile in ([], ["--release"]):
            accepted(result([*base, *profile, *test], workspace, env), 1)
        command = [*base, "--release", *test]
        try:
            path.write_text(replace_once(original, before, after))
            rejected(result(command, workspace, env))
        finally:
            path.write_text(original)
        accepted(result(command, workspace, env), 1)
    print("HMAC portable policy: debug/release; 7 compiled selection/Linux/Mac metadata mutants rejected; NOT native execution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", choices=("sha256", "sha512", "keccak"), action="append")
    parser.add_argument("--portable-policy", action="store_true", help="metadata-only checks; no native-execution claim")
    args = parser.parse_args()
    if bool(args.kernel) == args.portable_policy:
        parser.error("choose native --kernel or --portable-policy, not both")
    if args.kernel and len(args.kernel) != len(set(args.kernel)):
        parser.error("duplicate native kernel")
    with verifier.cargo_environment.private_directory(ROOT) as raw:
        root = Path(raw)
        env = verifier.environment(root)
        workspace = host.isolated(root)
        if args.portable_policy:
            check_portable_policy(workspace, env)
        for kernel in args.kernel or []:
            check(workspace, env, kernel)


if __name__ == "__main__":
    main()
