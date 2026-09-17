#!/usr/bin/env python3
"""Validate Brynja's exact, hash-bound unsafe implementation inventory."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ALLOWED = {
    Path("crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs"): ("fb571bcee4762b16fdae5012c7d15894a319c711500955d4c3a3d9134119b4aa", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs"): ("d913dd21b13d95ec2341b4bae3b738c5021c501cc6afaf4310f73c181d1736a8", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_sha/secret.rs"): ("f8afc16ed5a53259391a9a32a87b3127a9d0556ce634a3cb2ac415a87d7f5adb", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret256.rs"): ("2ee599b4176cd3c278335dddc2292a8b65eb5094ca5c80a7993d3d9c0c038c9f", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"): ("b790074aa3774d785a87bf3abca850540f3ab5c798c43aaf3ce29bdde4b38e66", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs"): ("8febc7fc79bb5813590293d8b17bc5d9f1bcb56f17dba55c844f28dd89bcf96e", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_sha512.rs"): ("9530acc46f67ba8f50f009bb2e837c2732b3f88cb80ba7847acf7229fce5d12c", 5, 1, 5),
    Path("crates/brynja-crypto-cpu-std/src/sha256_hardened_batch/platform.rs"): ("6784643cde62181da1f6133b9fb629087963fe0785e2020996d2f0ac665e4afb", 1, 0, 1),
    Path("crates/brynja-crypto-cpu-std/src/sha512_hardened_batch/platform.rs"): ("6784643cde62181da1f6133b9fb629087963fe0785e2020996d2f0ac665e4afb", 1, 0, 1),
    Path("crates/brynja-crypto-cpu-std/src/keccak_hardened_batch/platform.rs"): ("6784643cde62181da1f6133b9fb629087963fe0785e2020996d2f0ac665e4afb", 1, 0, 1),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/platform.rs"): ("aaceb66eb54d19f782b876ae626a39f134e67da6f3515e37f90ada2fb95cc0c9", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/x86.rs"): ("d52961eda7dd32f156c09e2ed5f49db29739e6442717529115e57a9eba4363a4", 3, 3, 3),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/arm.rs"): ("0e97b81b379216d5d8d7b49ebb1fd088d0dec5208f102e37bb4952503ff56e3c", 3, 3, 3),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/platform.rs"): ("24dea1b5fd00a72b980ea8d0b89851b0654823a4009722e0995096e3beb5700c", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86.rs"): ("bc58dbd74a1566b9ded419357bf3568b7fe6fc98a7f2f87321bdae5b7fd5dd1d", 3, 3, 3),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm.rs"): ("c4d1785547c3a5887e9667f03d87e2ed2ee8fe5e3d21d550b522aa63a36e9c3d", 3, 3, 3),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/platform.rs"): ("24dea1b5fd00a72b980ea8d0b89851b0654823a4009722e0995096e3beb5700c", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86.rs"): ("98351e5d38a6c9520fa24242fd488c9143e6b98135b21eee10d01bd8dd3b16b6", 3, 3, 3),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm.rs"): ("c445575508e419205b22eb8a29c560eb82bcad1a2ad6b0d58bf0b5c35a9b70d8", 3, 3, 3),
    Path("crates/brynja-crypto-cpu/src/keccak_batch/platform.rs"): ("e77387ad44d2470852b11262fc11784809fc9b8e09ac1a0bfe2751f5157ff7e9", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/keccak_batch/x86.rs"): ("cef6c1433caf37131fc0afb6844985c2e9ee73ed375e31eab23ad1402148edba", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/keccak_batch/arm.rs"): ("2191fb9338fcb49f7869c8f5243fd1c2f4bb1cafd8b9acd704b7dcaf04195b4d", 1, 1, 1),
    Path("crates/brynja-crypto-cpu-std/src/keccak_batch/platform.rs"): ("8865e11ca3156c3bd8ec918aa144f7eb27d9046a7b9fd5c0e71553e95bc5a2b9", 1, 0, 1),
    Path("crates/brynja-crypto-cpu/src/sha512_batch/platform.rs"): ("0fddd6e9a4f0856e5515eee16b9a7e1b1a11f1be3431fc89848b338adb6255c6", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/sha512_batch/x86.rs"): ("ca1e537b146856aff863eb9ee00c248c550af3b29c9cae3eb8fecb75646e3803", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha512_batch/arm.rs"): ("dcd014bf4be3708a283bda015516fde1b685cf1046b28686f11c498ed151754c", 1, 1, 1),
    Path("crates/brynja-crypto-cpu-std/src/sha512_batch/platform.rs"): ("8865e11ca3156c3bd8ec918aa144f7eb27d9046a7b9fd5c0e71553e95bc5a2b9", 1, 0, 1),
    Path("crates/brynja-crypto-cpu/src/sha256_batch/platform.rs"): ("8b41c22d5d2ec836f68e599c8966d15ae583b783469004621339f4960c6ab415", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/sha256_batch/x86.rs"): ("d286878c8180cac08828556ff1ba3e1da4d33527d9a09364ebd3125296c0d3c0", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha256_batch/arm.rs"): ("42cce4243621807a453db7fb48876487ea39ee2c1749f2f8e54dba7d0e63ec51", 1, 1, 1),
    Path("crates/brynja-crypto-cpu-std/src/sha256_batch/platform.rs"): ("8865e11ca3156c3bd8ec918aa144f7eb27d9046a7b9fd5c0e71553e95bc5a2b9", 1, 0, 1),
    Path("crates/brynja-legacy-md5/src/cpu/secret.rs"): ("1fd19b0d4167991ae1cb93ec209807350e334a3a85b3204124f013f05afbddb8", 2, 1, 2),
    Path("crates/brynja-legacy-md5/src/cpu/x86_secret.rs"): ("187318346e149c418554708552aec2d0f3d09dabbb68987c8e50289b1eccddfa", 3, 3, 3),
    Path("crates/brynja-legacy-md5/src/cpu/arm_secret.rs"): ("210447e40e6d20cdc75554e185adc8cdc9280f2bb3d4e2dbb5ec43bb115bbf40", 3, 3, 3),
    Path("crates/brynja-legacy-md5-std/src/hardened_execution/platform.rs"): ("552ae73fb7389f0450e637f6c3e7d3b6b57b904694084eeb71e7fa860df34832", 1, 0, 1),
    Path("crates/brynja-legacy-sha1/src/cpu/secret.rs"): ("135ab0dae0b9fbaf8dc147bf55ccf7e167c667ee675b980679ced331a3d6464e", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/runtime_execution/mod.rs"): (
        "19939961ef4e56f06df2154c7a5bde59f5e2d8289a044a858032ea1ab3e6d8d0", 0, 1, 0,
    ),
    Path("crates/brynja-crypto-cpu-std/src/execution/platform.rs"): (
        "777c14162432b633fc9ce13e4bd8ef397eb6258c9abf2d38a9cf0a04e44e2b19", 1, 0, 1,
    ),
    Path("crates/brynja-legacy-md5/src/cpu/session.rs"): ("96c89bc6bf0cb9a2f0fb7b3be0c6a608a30eba9627a13233ca90f3f8548f3c5f", 4, 2, 4),
    Path("crates/brynja-legacy-md5-std/src/execution/platform.rs"): ("351571ad239d08b806f9e966aac9633cdc785407526afe66433d08bb1e327b55", 1, 0, 1),
    Path("crates/brynja-legacy-md5/src/cpu/x86_avx2_md5.rs"): ("ed6bc494e363fc24256b835b5d4ee52b0785f4d46028a5bdb7ca8446d597ea8e", 1, 1, 1),
    Path("crates/brynja-legacy-md5/src/cpu/aarch64_neon_md5.rs"): ("95266c29fe1ce486477bf32d5276dc8f241cb3d57c1ce2dedfe8d8f335199651", 1, 1, 1),
    Path("crates/brynja-legacy-sha1/src/cpu/session.rs"): ("543c1ee7cec6d33c86c67b3dd06011e60417fbbc0cc6e1664fbc6cad39fbad77", 3, 2, 3),
    Path("crates/brynja-legacy-sha1-std/src/execution/platform.rs"): ("229f0b76150b65dffcea7e51f4e98d085622ee8356f8cd79d54ca51e18c2eea3", 2, 0, 2),
    Path("crates/brynja-legacy-sha1/src/cpu/x86_sha1.rs"): ("118c68887b4b3e60998108c8fb31da574c4dda3eff93b59fe4c0913d12368d2e", 6, 2, 6),
    Path("crates/brynja-legacy-sha1/src/cpu/aarch64_sha1.rs"): ("674c69df80e8a7a8ae09eebb0fc107dd48083c4c1a9135965cdffb9feb137591", 8, 2, 8),
    Path("crates/brynja-core/src/secret_memory_volatile.rs"): (
        "b056f1b562b4d1507305c8b79d1c53d63dfc842cf59992dbc9df30e65f051217",
        1,
        0,
        1,
    ),
    Path("crates/brynja-crypto-cpu/src/sha256.rs"): (
        "31e899058bbb2b2c5d5e43908fcf5a5e61862fa2f3f5a5df73eb1e6f1c63dd44", 0, 2, 0,
    ),
    Path("crates/brynja-crypto-cpu/src/x86_sha.rs"): (
        "4d5f8e820fb177f43b79de2ba887e2c8d43f555263782d759a129c81e47c655a", 3, 1, 3,
    ),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2.rs"): (
        "e9869ccd9e6bb2795a1ee753be0d1b6833009e507d84d904494f591964c3dc2f", 10, 2, 10,
    ),
    Path("crates/brynja-crypto-cpu/src/riscv64_zknh.rs"): (
        "4666c10486046cdd5a7caf8c99dc1c87b41c4f4ae4aa697a966067b89b38c619", 8, 2, 8,
    ),
    Path("crates/brynja-crypto-cpu/src/keccak.rs"): (
        "57f019950ad5b38da3da620be36b3026e91d7aeee262bd1b5861ba7fe48c804a", 0, 1, 0,
    ),
    Path("crates/brynja-crypto-cpu/src/x86_avx2_keccak.rs"): (
        "2322536da8ae0417973475c8ed702a39ec3759986f13ff7218f993bc0dd9bf23", 4, 1, 4,
    ),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak.rs"): (
        "c4fc0d66df46a06af27219d60d36b3f19fd7dae4ac8ed022c9b221ec9af16a27", 4, 1, 4,
    ),
    Path("crates/brynja-crypto-cpu-std/src/runtime_detection.rs"): (
        "f80399ec92f54a4a7deaf5588e729908a1f730549f30de5bdfdc826c6cb31de5", 1, 0, 1,
    ),
}
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_ITEM = re.compile(r'\bunsafe\s+(?:extern\s+"[^"]+"\s+)?(?:fn|impl|trait)\b')
UNSAFE_ALLOW = "allow(unsafe_code)"
FORBIDDEN_IDENTIFIER = re.compile(
    r"\b(?:unsafe|unsafe_code|asm|global_asm|llvm_asm|naked_asm|include|path)\b"
)
FOREIGN_ABI = re.compile(r'\bextern\s*(?:/\*.*?\*/\s*)?"', re.DOTALL)


class UnsafePolicyError(RuntimeError):
    """The unsafe inventory differs from the approved reviewed exceptions."""


def fail(message: str) -> None:
    raise UnsafePolicyError(message)


def validate(root: Path) -> None:
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    if cargo.count('unsafe_code = "deny"') != 1 or 'unsafe_code = "forbid"' in cargo:
        fail("workspace unsafe lint must be deny for the isolated module exception")

    sources = sorted((root / "crates").glob("**/*.rs"))
    if not sources:
        fail("unsafe policy found no Rust source inventory")
    allowed_paths = {root / relative for relative in ALLOWED}
    if not allowed_paths.issubset(sources):
        fail("an approved unsafe module is missing")

    for path in sources:
        crates_root = root / "crates"
        relative_source = path.relative_to(crates_root)
        current = crates_root
        parent_is_symlink = False
        for component in relative_source.parts[:-1]:
            current /= component
            parent_is_symlink = parent_is_symlink or current.is_symlink()
        if not path.is_file() or path.is_symlink() or parent_is_symlink:
            fail(f"Rust source must be a regular non-symlink file: {path}")
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(root)
        if path in allowed_paths:
            relative = path.relative_to(root)
            expected_hash, blocks, items, proofs = ALLOWED[relative]
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected_hash:
                fail("approved unsafe module changed; reopen security review")
            validate_allowed(relative, text, blocks, items, proofs)
        elif FORBIDDEN_IDENTIFIER.search(text) is not None or FOREIGN_ABI.search(text) is not None:
            fail(f"unapproved low-level or code-inclusion token: {relative}")

    library = (root / "crates/brynja-core/src/lib.rs").read_text(encoding="utf-8")
    if library.count("mod secret_memory_volatile;") != 1:
        fail("volatile-store module must remain private and declared exactly once")
    if "pub mod secret_memory_volatile" in library:
        fail("volatile-store implementation module became public")


def validate_allowed(
    relative: Path,
    text: str,
    expected_blocks: int,
    expected_items: int,
    expected_proofs: int,
) -> None:
    if text.count(UNSAFE_ALLOW) != 1:
        fail("approved module must contain one exact unsafe-code allowance")
    if len(UNSAFE_BLOCK.findall(text)) != expected_blocks:
        fail(f"approved unsafe-block inventory changed: {relative}")
    if len(UNSAFE_ITEM.findall(text)) != expected_items:
        fail(f"approved unsafe-item inventory changed: {relative}")
    if text.count("// SAFETY:") != expected_proofs:
        fail(f"approved local safety-proof inventory changed: {relative}")
    if relative == Path("crates/brynja-core/src/secret_memory_volatile.rs"):
        if text.count("core::ptr::write_volatile") != 1:
            fail("approved module must use exactly one volatile-store call site")
        if "core::ptr::from_mut(byte)" not in text:
            fail("volatile pointer must derive from each live exclusive byte reference")
        if "compiler_fence(Ordering::SeqCst)" not in text:
            fail("volatile loop must retain its final compiler barrier")
    elif relative in {
        Path("crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/x86_sha/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret256.rs"),
        Path("crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs"),
    }:
        # Exact source hashes bind the reviewed instruction stream. This narrow
        # structural check does not admit assembly in any other kernel module.
        keccak = relative.parent.name in {'x86_avx2_keccak', 'aarch64_sha3_keccak'}
        function, width = ('permute', 576) if keccak else ('compress', 704)
        required = (f'pub unsafe extern "C" fn {function}(', '#[inline(never)]',
                    '#[target_feature', f'scratch: &mut [u8; {width}]',
                    'BRYNJA_SECRET_BEGIN', 'BRYNJA_REGISTER_ERASE',
                    'BRYNJA_SECRET_END', 'options(nostack)')
        if any(text.count(token) != 1 for token in required) or text.count('asm!(') != 1:
            fail("register boundary lost its exact opaque assembly contract")
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail("register boundary weakened clobbers or memory effects")
    elif relative.name in {
        "x86_sha.rs", "x86_sha512.rs", "aarch64_sha2.rs", "riscv64_zknh.rs", "x86_sha1.rs", "aarch64_sha1.rs",
        "x86_avx2_keccak.rs", "aarch64_sha3_keccak.rs", "x86_avx2_md5.rs", "aarch64_neon_md5.rs",
    }:
        if "#[target_feature" not in text or "core::arch" not in text:
            fail(f"CPU kernel lost its intrinsic boundary: {relative}")
        if relative.name == "riscv64_zknh.rs":
            if text.count("asm!(") != 6 or "global_asm!(" in text:
                fail("RISC-V kernel inline-assembly inventory drifted")
        elif re.search(r'extern\s+"C"|\basm\s*!|\bglobal_asm\s*!', text):
            fail(f"CPU kernel introduced native linkage or assembly: {relative}")
    elif relative.name == "runtime_detection.rs":
        if "is_x86_feature_detected!" not in text or "from_runtime_detection" not in text:
            fail("runtime detector lost its reviewed attestation boundary")
    elif relative == Path("crates/brynja-crypto-cpu/src/runtime_execution/mod.rs"):
        if "pub unsafe fn from_platform(kernel: Kernel)" not in text or "EVERY CPU" not in text:
            fail("runtime owner lost its lifetime-wide platform obligation")
    elif relative == Path("crates/brynja-crypto-cpu-std/src/execution/platform.rs"):
        if "availability(kernel).map_err" not in text or "KernelAuthority::from_platform(kernel)" not in text:
            fail("hosted permit lost its private platform recheck")
