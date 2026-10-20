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
    ("None => Ok(None),", "None => Err(HmacError::Mac(brynja_mac_hmac::Error::ExecutionFailed)),",
     "portable_selection_does_not_process_keys"),
    ("let _ = owner\n                    .session()\n                    .map_err(|error| HmacError::Hosted(Error::Kernel(error)))?;",
     "if owner.session().is_err() { return Ok(None); }", "native_hosted_all_identities"),
    (".map_err(HmacError::Mac)?;", ".ok();\n                if mac.is_none() { return Ok(None); }\n"
     "                let mac = mac.unwrap();", "native_hosted_all_identities"),
    ("Ok(Some(mac))", "let _: Hmac<'a, A> = mac; Ok(None)", "native_hosted_all_identities"),
    ("Some(length) => Hmac::from_runtime_with_tag_length(owner, key, length),",
     "Some(_) => Hmac::from_runtime(owner, key),", "native_hosted_all_identities"),
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
          "5 compiled fallback/policy mutants rejected; not independent qualification", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", choices=("sha256", "sha512", "keccak"), action="append", required=True)
    args = parser.parse_args()
    if len(args.kernel) != len(set(args.kernel)):
        parser.error("duplicate native kernel")
    with verifier.cargo_environment.private_directory(ROOT) as raw:
        root = Path(raw)
        env = verifier.environment(root)
        workspace = host.isolated(root)
        for kernel in args.kernel:
            check(workspace, env, kernel)


if __name__ == "__main__":
    main()
