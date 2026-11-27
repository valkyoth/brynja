"""Installed consumer and compile-contract checks; no installed user files."""
import subprocess


def signatures(pkg, cargo, consumer, env, flags, cross, owner):
    probe = consumer / "src/bin/contract.rs"
    probe.parent.mkdir(exist_ok=True)
    prefix = f"use {owner} as Stream;\nfn main() {{}}\n"
    template = ("fn exercise(key: &[u8; 32], nonce: [u8; 12], counter: u32, data: &mut [u8; 9]) {\n"
                "let mut stream = Stream::new(key, nonce, counter);\n"
                "let _ = stream.apply_keystream_in_place(data);\n}\n")
    check = cargo + ["check", "--bin", "contract", *cross, *flags, "--message-format=json"]
    probe.write_text(prefix + template)
    pkg.run(check, consumer, env)
    for before, after, error in (
            ("[u8; 12]", "[u8; 8]", "E0308"), ("[u8; 12]", "[u8; 24]", "E0308"),
            ("counter: u32", "counter: u64", "E0308"),
            ("stream.apply_keystream_in_place(data)",
             "stream.apply_keystream(&data[..8], &mut data[1..])", "E0502")):
        probe.write_text(prefix + template.replace(before, after))
        result = pkg.cargo_result(check, consumer, env, timeout=120)
        if not pkg.diagnostic_matches(result, error, filename="src/bin/contract.rs"):
            raise ValueError(f"wrong result for {after} on {owner}")


def installed(pkg, cargo, consumer, env, flags, cross, simd, corpus):
    prefix = consumer / "install"
    pkg.run(cargo + ["install", "--path", ".", "--bin", "stream-consumer",
                     "--root", str(prefix), *cross, *flags], consumer, env)
    binary = prefix / "bin/stream-consumer"
    symbols = pkg.run(["llvm-nm", "--defined-only", "--demangle", str(binary)], consumer, env).stdout
    kernels = {isa for isa in ("sse2", "neon")
               if f"chacha20_{isa}::packed_rounds" in symbols}
    if kernels != ({simd} if simd else set()):
        raise ValueError(f"unexpected linked ChaCha20 kernels: {kernels}")
    run = (["qemu-aarch64", "-cpu", "cortex-a53"] if cross else []) + [str(binary)]
    path = consumer / "public-corpus.bin"
    path.write_bytes(corpus)
    if pkg.run(run + [str(path)], consumer, env).stdout.splitlines() != [
            "PASS 302 " + (simd or "scalar")]:
        raise ValueError("unexpected installed owner or corpus population")
    wrong = bytearray(corpus)
    wrong[-1] ^= 1
    path.write_bytes(wrong)
    result = subprocess.run(run + [str(path)], cwd=consumer, env=env,
                            capture_output=True, text=True, timeout=120)
    if (result.returncode, result.stdout, result.stderr.strip()) != (2, "", "ciphertext differs"):
        raise ValueError("installed consumer missed altered ciphertext")
