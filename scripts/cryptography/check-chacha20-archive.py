"""Exercise the direct, default-off ChaCha20 API outside the workspace."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("archive", ROOT / "scripts/aes-gcm/check-packaged-api.py")
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)
pkg = archive.pkg


def oracle_corpus(env):
    """Only public deterministic fixtures. Never ask OpenSSL to wrap the IETF counter."""
    rows = bytearray()
    count = 0
    openssl = shutil.which("openssl", path=env["PATH"])
    if not openssl:
        raise ValueError("the optional comparison requires the OpenSSL CLI")
    print(subprocess.check_output([openssl, "version"], env=env, text=True, timeout=10).strip(),
          flush=True)
    for seed in (0, 1):
        for counter in (0, 1, 255, 65535, 16777215, 0x80000000, 0xfffffffe, 0xffffffff):
            for size in (0, 1, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257,
                         1023, 1024, 1025, 4095, 4096, 4097, 16384):
                if size > ((1 << 32) - counter) * 64:
                    continue
                header = struct.pack("<IH", counter, size)
                sample = hashlib.shake_256(b"brynja chacha20 differential v1" + bytes([seed])
                                           + header).digest(44 + size)
                key, nonce, plain = sample[:32], sample[32:44], sample[44:]
                # Raw ChaCha takes four little-endian state words. These bytes
                # match RFC 8439 while word 12 does not wrap. Exhaustion policy
                # is checked separately, never inferred from OpenSSL.
                answer = subprocess.run([openssl, "enc", "-chacha20", "-K", key.hex(), "-iv",
                                         (header[:4] + nonce).hex()], input=plain, env=env,
                                        capture_output=True, check=True, timeout=10).stdout
                if len(answer) != size:
                    raise ValueError("wrong oracle output length")
                rows.extend(header + sample + answer)
                count += 1
    if count != 302:
        raise ValueError("unexpected oracle population")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--differential", action="store_true",
                        help="compare against OpenSSL instead of running the package smoke suite")
    differential = parser.parse_args().differential
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError("remove ambient toolchain, target or compiler overrides")
    with pkg.cargo_environment.private_directory(ROOT) as temp:
        root = Path(temp)
        env = pkg.isolated_env(root)
        endpoints = archive.archives.ENDPOINTS
        versions = pkg.package_archives(root, pkg.MODERN, endpoints[-1], env)
        consumer = root / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "tests").mkdir()
        version = versions["brynja-crypto"]
        source = root / "unpacked" / ("brynja-crypto-" + version)
        shutil.copyfile(source / "tests/chacha20.rs", consumer / "tests/vectors.rs")
        shutil.copytree(source / "tests/chacha20", consumer / "tests/chacha20")
        shutil.copyfile(ROOT / "assurance/chacha20-consumer/lib.rs", consumer / "src/lib.rs")
        (consumer / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="stream-consumer"\nversion="0.0.0"\nedition="2024"\n'
            '[features]\nstream=["brynja-crypto/hazmat-chacha20"]\n[dependencies]\n'
            f'brynja-crypto={{version="={version}",default-features=false}}\n[patch.crates-io]\n'
            + "".join(f'{p}={{path="../unpacked/{p}-{v}"}}\n' for p, v in versions.items()))
        pkg.run(["cargo", "+" + endpoints[0], "generate-lockfile", "--offline"], consumer, env)
        if differential:
            shutil.copyfile(ROOT / "assurance/chacha20-consumer/differential.rs",
                            consumer / "tests/differential.rs")
            (consumer / "tests/public-corpus.bin").write_bytes(oracle_corpus(env))
        for compiler in endpoints:
            cargo = ["cargo", "+" + compiler]
            flags = ["--locked", "--offline", "--features", "stream"]
            info = pkg.run(cargo + ["metadata", "--format-version", "1", *flags], consumer, env)
            archive.check_graph(json.loads(info.stdout), consumer, versions, "brynja-crypto",
                                features=("hazmat-chacha20",))
            if differential:
                result = pkg.run(cargo + ["test", "--release", "--test", "differential", *flags],
                                 consumer, env)
                if not archive.archives.exact_suite(result.stdout, 2):
                    raise ValueError("incomplete oracle replay or negative control")
                print(f"{compiler}: 302 OpenSSL comparisons and altered-answer control passed",
                      flush=True)
                continue
            for selection, count in [(["--test", "vectors"], 4), (["--lib"], 1)]:
                result = pkg.run(cargo + ["test", "--release", *selection, *flags], consumer, env)
                if not archive.archives.exact_suite(result.stdout, count):
                    raise ValueError(f"incomplete archive suite: {selection}")
            pkg.run(cargo + ["check", "--lib", "--target", "thumbv7em-none-eabi", *flags], consumer, env)
            negative = pkg.cargo_result(cargo + ["check", "--lib", "--locked", "--offline",
                                        "--message-format=json"], consumer, env, timeout=120)
            if not pkg.diagnostic_matches(negative, "E0432", filename="src/lib.rs"):
                raise ValueError("unexpected result without the raw-stream feature")
            probe = consumer / "src/bin/overlap.rs"
            probe.parent.mkdir(exist_ok=True)
            probe.write_text("use brynja_crypto::chacha20::ChaCha20;\n"
                             "fn main() { let mut a = [0u8; 8];\n"
                             "let mut s = ChaCha20::new(&[0;32], [0;12], 0);\n"
                             "let _ = s.apply_keystream(&a[..7], &mut a[1..]); }\n")
            overlap = pkg.cargo_result(cargo + ["check", "--bin", "overlap",
                                      "--message-format=json", *flags], consumer, env, timeout=120)
            if not pkg.diagnostic_matches(overlap, "E0502", filename="src/bin/overlap.rs"):
                raise ValueError("partial overlap did not fail for the expected borrow conflict")
            # Cargo builds binary targets for integration tests. Do not leave the
            # intentionally invalid target in the next compiler's positive suite.
            probe.unlink()
            print(f"{compiler}: RFC and stream boundaries, Cortex-M compile, default-off import passed",
                  flush=True)
    print("CHACHA20_DIFFERENTIAL_COMPLETE" if differential else "CHACHA20_ARCHIVE_COMPLETE")


if __name__ == "__main__":
    main()
