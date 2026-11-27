"""Installed consumer and compile-contract checks; no installed user files."""
import re
import struct
import subprocess


def signatures(pkg, cargo, consumer, env, flags, cross, owner):
    probe = consumer / "src/bin/contract.rs"
    probe.parent.mkdir(exist_ok=True)
    prefix = f"use {owner} as Stream;\nfn main() {{}}\n"
    template = ("fn exercise(key: &[u8; 32], nonce: [u8; 12], counter: u32, data: &mut [u8; 9]) {\n"
                "let mut stream = Stream::new(key, nonce, counter);\n"
                "let _ = stream.apply_keystream_in_place(data);\n}\n")
    check = cargo + ["check", "--bin", "contract", *cross, *flags, "--message-format=json"]
    # This path is ours only if we created it; never replace a pre-existing probe.
    with probe.open("x") as handle:
        handle.write(prefix + template)
    try:
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
    finally:
        probe.unlink()


def ciphertext_controls(corpus):
    """Offsets into expected answers only: one full four-block group and the final scalar block."""
    offset, group, final = 0, None, None
    while offset < len(corpus):
        if len(corpus) - offset < 50:  # counter, length, key, IETF nonce
            raise ValueError("truncated oracle header")
        counter, size = struct.unpack_from("<IH", corpus, offset)
        answer = offset + 50 + size
        offset = answer + size
        if offset > len(corpus) or size > ((1 << 32) - counter) * 64:
            raise ValueError("invalid oracle record")
        if group is None and size >= 256:
            group = answer
        if counter == 0xffffffff and size == 64:
            final = offset - 1
    if group is None or final is None:
        raise ValueError("missing full-group or final-block oracle control")
    return group, final


def installed(pkg, cargo, consumer, env, flags, cross, simd, corpus):
    prefix = consumer / "install"
    pkg.run(cargo + ["install", "--path", ".", "--bin", "stream-consumer",
                     "--root", str(prefix), *cross, *flags], consumer, env)
    binary = prefix / "bin/stream-consumer"
    symbols = pkg.run(["llvm-nm", "--defined-only", "--demangle", str(binary)], consumer, env).stdout
    if not re.search(r"^[0-9a-fA-F]+\s+T\s+main$", symbols, re.MULTILINE):
        raise ValueError("expected an unstripped installed consumer with a main text symbol")
    # Rust 1.90 includes the demangled hash suffix; 1.100 need not.
    kernels = set(re.findall(r"^[0-9a-fA-F]+\s+[tT]\s+brynja_crypto_cpu::chacha20_(sse2|neon)"
                             r"::packed_rounds(?:::h[0-9a-f]{16})?$", symbols, re.MULTILINE))
    if kernels != ({simd} if simd else set()):
        raise ValueError(f"unexpected linked ChaCha20 kernels: {kernels}")
    run = (["qemu-aarch64", "-cpu", "cortex-a53"] if cross else []) + [str(binary)]
    path = consumer / "public-corpus.bin"
    path.write_bytes(corpus)
    if pkg.run(run + [str(path)], consumer, env).stdout.splitlines() != [
            "PASS 302 " + (simd or "scalar")]:
        raise ValueError("unexpected installed owner or corpus population")
    for pos in ciphertext_controls(corpus):
        wrong = bytearray(corpus)
        wrong[pos] ^= 1
        path.write_bytes(wrong)
        result = subprocess.run(run + [str(path)], cwd=consumer, env=env,
                                capture_output=True, text=True, timeout=120)
        if (result.returncode, result.stdout, result.stderr.strip()) != (2, "", "ciphertext differs"):
            raise ValueError("installed consumer missed altered ciphertext")
