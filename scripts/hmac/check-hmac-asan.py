#!/usr/bin/env python3
"""Portable HMAC memory checking with mandatory, fatal leak detection."""
from pathlib import Path
import platform
import sys

import hmac_verifiers as verifier


def main():
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise ValueError("HMAC sanitizer lane currently requires Linux x86-64")
    pin = verifier.tool("rust-sanitizers")
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env["RUSTFLAGS"] = "-Zsanitizer=address"
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:exitcode=1"
        env["LSAN_OPTIONS"] = "exitcode=23"
        for target, count in (("bounded", 13), ("vectors", 7), ("lifecycle", 11), ("bits", 12), ("general", 5)):
            output = verifier.run(["cargo", "+" + pin["execution_toolchain"], "test", "--locked", "--offline",
                                   "-p", "brynja-mac-hmac", "--test", target,
                                   "--target", "x86_64-unknown-linux-gnu"], env)
            if f"test result: ok. {count} passed; 0 failed; 0 ignored;" not in output:
                raise ValueError("HMAC sanitizer test population changed: " + target)
            print(output)
        output = verifier.run(["cargo", "+" + pin["execution_toolchain"], "test", "--locked", "--offline",
                               "-p", "brynja-mac-hmac", "--features", "hardened-execution",
                               "--lib", "execution::tests", "--target", "x86_64-unknown-linux-gnu"], env)
        if "test result: ok. 4 passed; 0 failed; 0 ignored;" not in output:
            raise ValueError("HMAC sanitizer execution lifecycle population changed")
        print(output)
        output = verifier.run(["cargo", "+" + pin["execution_toolchain"], "test", "--locked", "--offline",
                               "-p", "brynja-crypto-cpu-std", "--features", "hmac-execution",
                               "--test", "hmac", "--target", "x86_64-unknown-linux-gnu"], env)
        if "test result: ok. 2 passed; 0 failed; 1 ignored;" not in output:
            raise ValueError("HMAC sanitizer hosted selection population changed")
        print(output)
        print("Portable HMAC ASan/LSan: PASS; leak detection forced; no hardware qualification claim")
        output = verifier.run(["cargo", "+" + pin["execution_toolchain"], "test", "--locked", "--offline",
                               "-p", "brynja-crypto-cpu-std", "--features", "strict-hmac",
                               "--lib", "strict_hmac::tests::metadata_admission_and_exact_tag_policy",
                               "--target", "x86_64-unknown-linux-gnu"], env)
        if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in output:
            raise ValueError("protected HMAC sanitizer metadata population changed")
        print(output)
        print("Protected HMAC public-policy ASan: PASS; protected native execution not inferred")


if __name__ == "__main__":
    main()
