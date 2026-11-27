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


def replay(root, env, versions, compiler, dependency, differential, *, simd=None):
    leaf = dependency == "brynja-cipher-chacha"
    namespace = "brynja_cipher_chacha" if leaf else "brynja_crypto::chacha20"
    consumer = root / (dependency + "-" + compiler + ("-" + simd if simd else ""))
    feature = "chacha20-" + simd if simd else "hazmat-chacha20"
    cross = ["--target", "aarch64-unknown-linux-musl"] if simd == "neon" else []
    if cross:
        env = dict(env, CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="rust-lld",
                   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="qemu-aarch64 -cpu cortex-a53")
    (consumer / "src").mkdir(parents=True)
    (consumer / "tests").mkdir()
    source = root / "unpacked" / ("brynja-crypto-" + versions["brynja-crypto"])

    def fixture(original, dest):
        # Compile the same reviewed test against each path; only change its import.
        data = original.read_text()
        if data.count("use brynja_crypto::chacha20::") != 1:
            raise ValueError("unexpected fixture import")
        data = data.replace("use brynja_crypto::chacha20::", f"use {namespace}::")
        if simd:
            data = data.replace("ChaCha20", "ChaCha20" + {"sse2": "Sse2", "neon": "Neon"}[simd])
        (consumer / dest).write_text(data)

    fixture(source / "tests/chacha20.rs", "tests/vectors.rs")
    shutil.copytree(source / "tests/chacha20", consumer / "tests/chacha20")
    fixture(ROOT / "assurance/chacha20-consumer/lib.rs", "src/lib.rs")
    (consumer / "Cargo.toml").write_text(
        '[workspace]\n[package]\nname="stream-consumer"\nversion="0.0.0"\nedition="2024"\n'
        f'[features]\nstream=["{dependency}/{feature}"]\n[dependencies]\n'
        f'{dependency}={{version="={versions[dependency]}",default-features=false}}\n[patch.crates-io]\n'
        + "".join(f'{p}={{path="../unpacked/{p}-{v}"}}\n' for p, v in versions.items()))
    cargo = ["cargo", "+" + compiler]
    pkg.run(cargo + ["generate-lockfile", "--offline"], consumer, env)
    flags = ["--locked", "--offline", "--features", "stream"]
    platform = ["--filter-platform", cross[1]] if cross else []
    info = pkg.run(cargo + ["metadata", "--format-version", "1", *platform, *flags], consumer, env)
    meta = json.loads(info.stdout)
    if simd:
        packages = {p["id"]: p for p in meta["packages"]}
        actual = {}
        for node in meta["resolve"]["nodes"]:
            p = packages[node["id"]]
            if node["id"] != meta["resolve"]["root"]:
                target = root / "unpacked" / (p["name"] + "-" + versions[p["name"]]) / "Cargo.toml"
                if Path(p["manifest_path"]) != target:
                    raise ValueError("native consumer did not use the packaged source")
            actual[p["name"]] = (set(node["features"]), {packages[d["pkg"]]["name"] for d in node["deps"]})
        if actual != {
            "stream-consumer": ({"stream"}, {dependency}),
            dependency: ({feature, "hazmat-chacha20"}, {"brynja-core", "brynja-crypto-cpu"}),
            "brynja-core": ({"default"}, set()),
            "brynja-crypto-cpu": ({"default", feature}, set()),
        }:
            raise ValueError(f"unexpected native package graph: {actual}")
        # These negatives keep the portable stream enabled: only SIMD authority is absent.
        for denied in ([*cross, "--features", dependency + "/hazmat-chacha20"], ["--target", "thumbv7em-none-eabi", "--features", "stream"]):
            negative = pkg.cargo_result(cargo + ["check", "--lib", "--locked", "--offline", "--message-format=json",
                                        *denied], consumer, env, timeout=120)
            if not pkg.diagnostic_matches(negative, "E0432", filename="src/lib.rs"):
                raise ValueError(f"{simd} owner was not excluded as expected")
    else:
        archive.check_graph(meta, consumer, versions, dependency, features=("hazmat-chacha20",))
    if differential is not None:
        fixture(ROOT / "assurance/chacha20-consumer/differential.rs", "tests/differential.rs")
        (consumer / "tests/public-corpus.bin").write_bytes(differential)
        result = pkg.run(cargo + ["test", "--release", "--test", "differential", *cross, *flags], consumer, env)
        if not archive.archives.exact_suite(result.stdout, 2):
            raise ValueError("incomplete oracle replay or negative control")
        return
    for selection, count in [(["--test", "vectors"], 5), (["--lib"], 1)]:
        result = pkg.run(cargo + ["test", "--release", *selection, *flags], consumer, env)
        if not archive.archives.exact_suite(result.stdout, count):
            raise ValueError(f"incomplete archive suite: {selection}")
    pkg.run(cargo + ["check", "--lib", "--target", "thumbv7em-none-eabi", *flags], consumer, env)
    negative = pkg.cargo_result(cargo + ["check", "--lib", "--locked", "--offline",
                                "--message-format=json"], consumer, env, timeout=120)
    if not pkg.diagnostic_matches(negative, "E0432", filename="src/lib.rs"):
        raise ValueError("unexpected result without the raw-stream feature")
    probe = consumer / "src/bin/overlap.rs"
    probe.parent.mkdir()
    probe.write_text(f"use {namespace}::ChaCha20;\n"
                     "fn main() { let mut a = [0u8; 8];\n"
                     "let mut s = ChaCha20::new(&[0;32], [0;12], 0);\n"
                     "let _ = s.apply_keystream(&a[..7], &mut a[1..]); }\n")
    overlap = pkg.cargo_result(cargo + ["check", "--bin", "overlap", "--message-format=json",
                               *flags], consumer, env, timeout=120)
    if not pkg.diagnostic_matches(overlap, "E0502", filename="src/bin/overlap.rs"):
        raise ValueError("partial overlap did not fail for the expected borrow conflict")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    routes = parser.add_mutually_exclusive_group()
    routes.add_argument("--differential", action="store_true",
                        help="compare against OpenSSL instead of running the package smoke suite")
    routes.add_argument("--sse2-differential", action="store_true",
                        help="compare the packaged explicit x86-64 SSE2 owner against OpenSSL")
    routes.add_argument("--neon-qemu-differential", action="store_true",
                        help="compare the packaged AArch64 NEON owner under Linux QEMU against OpenSSL")
    args = parser.parse_args()
    simd = "neon" if args.neon_qemu_differential else "sse2" if args.sse2_differential else None
    differential = args.differential or simd is not None
    if any(k in os.environ for k in pkg.REJECT_ENV):
        raise ValueError("remove ambient toolchain, target or compiler overrides")
    with pkg.cargo_environment.private_directory(ROOT) as temp:
        root = Path(temp)
        env = pkg.isolated_env(root)
        endpoints = archive.archives.ENDPOINTS
        versions = pkg.package_archives(root, pkg.MODERN, endpoints[-1], env)
        corpus = oracle_corpus(env) if differential else None
        for compiler in endpoints:
            if simd:
                replay(root, env, versions, compiler, "brynja-cipher-chacha", corpus, simd=simd)
                route = "NEON (Linux QEMU)" if simd == "neon" else "SSE2"
                print(f"{compiler}: archived {route} owner: oracle and feature controls passed", flush=True)
                continue
            for dependency in ("brynja-cipher-chacha", "brynja-crypto"):
                replay(root, env, versions, compiler, dependency, corpus)
            summary = ("302 OpenSSL comparisons and altered-answer control" if differential else
                       "RFC and stream boundaries, Cortex-M compile, default-off import")
            print(f"{compiler}: leaf and compatibility routes: {summary} passed", flush=True)
    print("CHACHA20_NEON_QEMU_DIFFERENTIAL_COMPLETE" if args.neon_qemu_differential else
          "CHACHA20_SSE2_DIFFERENTIAL_COMPLETE" if args.sse2_differential else
          "CHACHA20_DIFFERENTIAL_COMPLETE" if differential else "CHACHA20_ARCHIVE_COMPLETE")


if __name__ == "__main__":
    main()
