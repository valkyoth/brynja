#!/usr/bin/env python3
"""Validate Brynja's exact, hash-bound unsafe implementation inventory."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ALLOWED = {
    Path("crates/brynja-legacy-sha1/src/compress/native.rs"): ("f785162fdf3c5ada9847cc5796db0b7a870d289707587c9d698d78a6d6355ad3", 3, 1, 3),
    Path("crates/brynja-legacy-md5/src/compress/native.rs"): ("33adb9934e5b3c42ba112263a963266b8391d3b4e58fc7b94b27341df66ce33d", 3, 1, 3),
    Path("crates/brynja-legacy-md5/src/cpu/transfer.rs"): ("086352bda68dd5908f397079dcaf8b30f75501510a993d00143d473db4c8d481", 6, 1, 6),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/transfer.rs"): ("b1293ffcbfe51b26b49bc17dfd861e917f151c8d73356e7902e3277efeec42d4", 6, 1, 6),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/transfer.rs"): ("1b87c3f35bde0f59fe65f54b2c14a1d93369d9c03fe6f20a7e336f7d7992ac1f", 6, 1, 6),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/transfer.rs"): ("d8e07cce1e24149d37874f3dd9828e587fbdf8ae61dd91bcf9b602ecbf914d5d", 6, 1, 6),
    Path("crates/brynja-legacy-md5/src/cpu/x86_secret/kernel.rs"): ("c008b23798ed127c95607d333f633b845e2383752768588023ae5dfbb4f33dd8", 1, 1, 1),
    Path("crates/brynja-legacy-md5/src/cpu/arm_secret/kernel.rs"): ("3134097267beea2f7d2c97abaf8d3fb721a870b38581a4e8dbc0245c4194515c", 1, 1, 1),
    Path("crates/brynja-legacy-sha1/src/cpu/x86_sha1/secret.rs"): ("b7625787a8d512fc0f4129c002997e32b088e3dff52cc84c6c57a0decb75eab0", 1, 1, 1),
    Path("crates/brynja-legacy-sha1/src/cpu/aarch64_sha1/secret.rs"): ("663c0964503b0063e0a4031133e4c633e33ca386d04eb19199840410aae2799e", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/x86/secret.rs"): ("11cd76232a6e59720835bb8bf1b977608c59ba7465a107c8f1dc1f27711d8146", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/arm/secret.rs"): ("db9a59d97c9ffbf81b0572a8e9cce770dbc89a409c22db4c6d85fb65f3f92ba8", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86/secret.rs"): ("bb03ef422bf0e6fb505e39f75364384683e696f8ef8c50ed6f3b683f20470c2b", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm/secret.rs"): ("807a94ee4f3f8d73c1c945e8899121f6f3635a9ef438f2eb309477f4d5b550c5", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86/secret.rs"): ("1c9dfe716a169deb9d8a2670eb485b74d393888898904ba5a092aa1cefcbd852", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm/secret.rs"): ("f29271f331283b937532ab931894679d4ee6a1a4049dfbff687c389ff5dfb946", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs"): ("59efd87d9c1fc577f2eb1c39a626849262919783909195ea4e0459ae4641d67e", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs"): ("5e01c5624d8783c742f8d5e04cd6f276bbb158d80fe10160c1d17b715aa36949", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_sha/secret.rs"): ("f8afc16ed5a53259391a9a32a87b3127a9d0556ce634a3cb2ac415a87d7f5adb", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret256.rs"): ("2ee599b4176cd3c278335dddc2292a8b65eb5094ca5c80a7993d3d9c0c038c9f", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"): ("b790074aa3774d785a87bf3abca850540f3ab5c798c43aaf3ce29bdde4b38e66", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs"): ("8febc7fc79bb5813590293d8b17bc5d9f1bcb56f17dba55c844f28dd89bcf96e", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/x86_sha512.rs"): ("9530acc46f67ba8f50f009bb2e837c2732b3f88cb80ba7847acf7229fce5d12c", 5, 1, 5),
    Path("crates/brynja-crypto-cpu-std/src/sha256_hardened_batch/platform.rs"): ("6784643cde62181da1f6133b9fb629087963fe0785e2020996d2f0ac665e4afb", 1, 0, 1),
    Path("crates/brynja-crypto-cpu-std/src/sha512_hardened_batch/platform.rs"): ("6784643cde62181da1f6133b9fb629087963fe0785e2020996d2f0ac665e4afb", 1, 0, 1),
    Path("crates/brynja-crypto-cpu-std/src/keccak_hardened_batch/platform.rs"): ("6784643cde62181da1f6133b9fb629087963fe0785e2020996d2f0ac665e4afb", 1, 0, 1),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/platform.rs"): ("aaceb66eb54d19f782b876ae626a39f134e67da6f3515e37f90ada2fb95cc0c9", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/x86.rs"): ("c86f9e8e991b198c5771f92d96fc994a74cfcd1ad3499ddc2c524e90a9c36c1d", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/arm.rs"): ("bea57ebfa2d29bc3ecea4c466314c4d020a12e7ed56d5512b9050396947deb08", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/platform.rs"): ("24dea1b5fd00a72b980ea8d0b89851b0654823a4009722e0995096e3beb5700c", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86.rs"): ("29925113a8a38b4ece7b722ad6fa9de3b893a43a4cddf59e28ddd2985a6e4213", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm.rs"): ("be48362dfd6aef45fc4b4cb7fbeb953cf739126b89c8926c0e8f2cfd34c6f8bf", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/platform.rs"): ("24dea1b5fd00a72b980ea8d0b89851b0654823a4009722e0995096e3beb5700c", 2, 1, 2),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86.rs"): ("37f291ed1e6527f61f12000837d606cd3d814b9325d79594ee6f73b138806110", 1, 1, 1),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm.rs"): ("77a97032b2bb929533dc6ba098c94a120ad0e5b770a2c25f0868547f196dd8de", 1, 1, 1),
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
    Path("crates/brynja-legacy-md5/src/cpu/x86_secret.rs"): ("03ba73e4d293fb3b8d3095f68220927dd48a4dd2102858791e1c74885e8346f3", 1, 1, 1),
    Path("crates/brynja-legacy-md5/src/cpu/arm_secret.rs"): ("6e6d7883d222b9ec2b4211b5c2a4d5a0902ec33d8c4348c97d714a4c4ea33a71", 1, 1, 1),
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
    Path("crates/brynja-legacy-sha1/src/cpu/x86_sha1.rs"): ("885555cbbddbfa704599e2d3c30493e2a39496cee6032d9262891e0a212c8d07", 2, 2, 2),
    Path("crates/brynja-legacy-sha1/src/cpu/aarch64_sha1.rs"): ("89e4b91af4adf587828396a612e8d3c1f14a8160176edbb58a5f1d49ae882f4e", 4, 2, 4),
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
        "25820050594a2f20027667c4f5ed53b8194d516d94e8c80b19a7f72516d5b1bf", 4, 1, 4,
    ),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak.rs"): (
        "c4ac153bcf66d98f015e796151aa4ea68d6abe2330f418fef84d2b1dc63ea56f", 4, 1, 4,
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
    elif relative in {Path("crates/brynja-legacy-md5/src/compress/native.rs"),
                      Path("crates/brynja-legacy-sha1/src/compress/native.rs")}:
        sha1 = relative.parts[1] == 'brynja-legacy-sha1'
        required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                    'state: &mut [u8; 16]', 'block: &[u8; 64]', 'constants: &[u32; 64]',
                    'shifts: &[u32; 16]', '"cmp r14d, 64"', '"cmp w10, #64"')
        if sha1:
            required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                        'state: &mut [u8; 20]', 'block: &[u8; 64]', 'schedule: &mut [u8; 320]',
                        '"cmp r14d, 320"', '"cmp x11, #320"',
                        '"mov dword ptr [{schedule} + r14], 0"', '"str wzr, [{schedule}, x11]"')
        if any(token not in text for token in required):
            fail("scalar compressor lost its fixed operands, ABI, bound or schedule wipe")
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_SCALAR_BEGIN',
                'BRYNJA_SCALAR_ERASE', 'BRYNJA_SCALAR_END', 'options(nostack)')):
            fail("scalar compressor lost an opaque architecture boundary")
        wipes = tuple(f'"xor {reg}, {reg}"' for reg in ('eax', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d', 'r14d'))
        wipes += tuple(f'"mov x{i}, xzr"' for i in range(4, 13 if sha1 else 12))
        if any(token not in text for token in wipes):
            fail("scalar compressor register erasure disappeared")
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly|target_feature)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail("scalar compressor changed memory/clobber or baseline ISA contract")
    elif relative in {
        Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/transfer.rs"),
        Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/transfer.rs"),
        Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/transfer.rs"),
        Path("crates/brynja-legacy-md5/src/cpu/transfer.rs"),
    }:
        required = ('pub(super) unsafe extern "C" fn transpose<const WORDS: usize, const PACK: bool>',
                    '#[inline(never)]', 'assert!(WORDS == 8 || WORDS == 16)')
        if relative.parent.name == 'keccak_hardened_batch':
            required = ('pub(super) unsafe extern "C" fn transpose<const PACK: bool>',
                        '#[inline(never)]', '"cmp r8, 25"', '"cmp x6, #25"')
        md5 = relative == Path("crates/brynja-legacy-md5/src/cpu/transfer.rs")
        if md5:
            required = (required[0], required[1], 'assert!(WORDS == 4 || WORDS == 16 || (WORDS == 32 && PACK))')
        if any(text.count(token) != 1 for token in required):
            fail("transfer boundary lost its checked word domain or non-inlining contract")
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_TRANSFER_BEGIN',
                'BRYNJA_TRANSFER_ERASE', 'BRYNJA_TRANSFER_END', 'options(nostack)')):
            fail("transfer lost its two opaque architecture boundaries")
        lanes = 8 if relative.parent.name == 'sha256_hardened_batch' else 4
        if (text.count('if lane >= 8') != 3 if md5 else text.count(f'width.min({lanes})') != 4):
            fail("safe transfer entry lost its fixed lane bound")
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail("transfer boundary weakened clobbers or memory effects")
    elif relative in {
        Path("crates/brynja-legacy-md5/src/cpu/x86_secret/kernel.rs"),
        Path("crates/brynja-legacy-md5/src/cpu/arm_secret/kernel.rs"),
        Path("crates/brynja-legacy-sha1/src/cpu/x86_sha1/secret.rs"),
        Path("crates/brynja-legacy-sha1/src/cpu/aarch64_sha1/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/x86/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/arm/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86/secret.rs"),
        Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm/secret.rs"),
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
        if relative.parent.parent.name == 'sha256_hardened_batch':
            width = 2752
        if relative.parent.parent.name == 'sha512_hardened_batch':
            width = 3264
        if relative.parent.parent.name == 'keccak_hardened_batch':
            function, width = 'permute', 1920
        if relative.parent.name in {'x86_secret', 'arm_secret'}:
            width = 864
        required = (f'pub unsafe extern "C" fn {function}(', '#[inline(never)]',
                    '#[target_feature', f'scratch: &mut [u8; {width}]',
                    'BRYNJA_SECRET_BEGIN', 'BRYNJA_REGISTER_ERASE',
                    'BRYNJA_SECRET_END', 'options(nostack)')
        if relative.parent.name in {'x86_sha1', 'aarch64_sha1'}:
            required = tuple(token for token in required if not token.startswith('scratch:'))
            required += ('state: &mut [u8; 20]', 'block: &[u8; 64]', 'schedule: &mut [u8; 320]')
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
