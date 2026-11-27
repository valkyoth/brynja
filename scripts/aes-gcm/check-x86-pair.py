"""Private composition and opt-in downstream paired owners on stable Linux x86-64."""
import os
from pathlib import Path
import platform
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/repository"))
import facade_cargo_environment as workspace

PROBE = ROOT / "assurance/aes-kernel-candidate/probe.rs"
PREFIX = "aes_gcm::portable::tests::x86_pair::"
CASES = ("aes128", "aes192", "aes256", "hash_failure_at_either_stage_burns_nonce_without_commit")


def main():
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("requires a stable Linux x86-64 ISA; no emulated success")
    validate = runpy.run_path(str(ROOT / "scripts/aes/check-aes-static.py"))["validate_tests"]
    env = {k: os.environ[k] for k in ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME") if k in os.environ}
    env.setdefault("CARGO_HOME", str(Path.home() / ".cargo"))
    env.update(RUSTUP_AUTO_INSTALL="0", CARGO_NET_OFFLINE="true")
    workspace.check(ROOT, env)
    with workspace.private_directory(ROOT) as temp:
        probe = Path(temp) / "probe"
        for version in ("1.90.0", "1.100.0"):
            subprocess.run(["rustc", "+" + version, "--edition=2024", str(PROBE), "-o", probe],
                           cwd=ROOT, env=env, timeout=60, check=True)
            if subprocess.check_output([probe], cwd=ROOT, env=env, text=True, timeout=10).splitlines() != ["AES_STATIC_HOST_BUNDLE_PASS"]:
                raise ValueError("missing baseline AES host probe")
            # Only AES/SSE2 are statically enabled. GHASH independently requires
            # runtime PCLMUL admission and a passing KAT, with no fallback.
            cmd = ["cargo", "+" + version, "test", "--locked", "--offline", "--release",
                   "--target", "x86_64-unknown-linux-gnu", "--target-dir", str(Path(temp) / "target"),
                   "-p", "brynja-crypto", "--no-default-features", "--features",
                   "aes-gcm,gmac,aes-static-execution,ghash-runtime-execution", "--lib", PREFIX]
            output = subprocess.check_output(cmd, cwd=ROOT, env=dict(env, RUSTFLAGS="-Ctarget-feature=+aes,+sse2"),
                                             text=True, timeout=300)
            validate(output, len(CASES), ["test " + PREFIX + name + " ... ok" for name in CASES])
            public = cmd[:cmd.index("--features")] + ["--features", "aes-gcm-execution,gmac-execution"]
            lifetime = "aes_gcm::portable::paired::tests::"
            interrupted = "aes_gcm::interruptions::tests::"
            for flags, args, names in (
                ("-Ctarget-feature=-aes", ["--test", "aead_pair"], ["unavailable_before_key_import"]),
                ("-Ctarget-feature=+aes,+sse2", ["--test", "aead_pair"],
                 ["native::aes128", "native::aes192", "native::aes256"]),
                ("-Ctarget-feature=+aes,+sse2", ["--lib", lifetime],
                 [lifetime + name for name in ("postcheck_precedes_commit", "unwind_retires_pair",
                                                "frames_use_the_admitted_multiplier")]),
                ("-Ctarget-feature=+aes,+sse2", ["--lib", interrupted],
                 [interrupted + width + "::" + name for width in ("aes128", "aes192", "aes256")
                  for name in ("import", "messages", "authentication_only")]),
            ):
                output = subprocess.check_output(public + args, cwd=ROOT, env=dict(env, RUSTFLAGS=flags),
                                                 text=True, timeout=300)
                validate(output, len(names), ["test " + name + " ... ok" for name in names])
            # This test moved out of the composition crate. Run the generic
            # leaf on the host; an absent multiplier must not count as evidence.
            case = "ghash::interrupted_pair_update_clears_live_frame"
            leaf = cmd[:cmd.index("-p")] + ["-p", "brynja-universal-hash-ghash",
                    "--no-default-features", "--features", "__mode-execution",
                    "--lib", "--", "--exact", case, "--nocapture"]
            output = subprocess.check_output(leaf, cwd=ROOT, env=env, text=True, timeout=300)
            validate(output, 1, ["test " + case + " ... ok", "GHASH_PAIRED_LIVE_CLEANUP_COMPLETE"])
            print(f"{version}: staged native error and unwind sweeps passed", flush=True)
            print(f"{version}: required AES-NI and PCLMUL composition passed", flush=True)
    print("GCM_X86_PAIR_DEVELOPMENT_COMPLETE")


if __name__ == "__main__":
    main()
