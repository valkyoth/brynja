"""Exercise the portable path consumer; no registry publication or hardware runs."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "assurance/aes-gcm-consumer/Cargo.toml"


def check(toolchain, route, action, flags, target_dir, marker=None):
    args = ["cargo", f"+{toolchain}", action, "--locked", "--offline",
            "--manifest-path", MANIFEST, "--no-default-features", "--features", route,
            "--target-dir", target_dir, *flags]
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode or (marker and marker not in result.stdout):
        raise SystemExit(f"{toolchain} {route} {action} {flags} failed:\n"
                         f"{result.stderr[-3000:]}\n{result.stdout[-1000:]}")


def main():
    with tempfile.TemporaryDirectory(prefix="brynja-gcm-consumer-") as target:
        for compiler in ("1.90.0", "1.100.0"):
            for route in ("direct", "facade"):
                check(compiler, route, "test", ["--release", "--lib"], target,
                      "2 passed; 0 failed; 0 ignored;")
                check(compiler, route, "test", ["--doc"], target,
                      "6 passed; 0 failed; 0 ignored;")
                check(compiler, route, "check", ["--lib", "--target", "thumbv7em-none-eabi"], target)
                print(f"{compiler} {route}: host + borrow/visibility checks; Cortex-M compile")
    print("AES_GCM_PUBLIC_CONSUMER_COMPLETE")


if __name__ == "__main__":
    main()
