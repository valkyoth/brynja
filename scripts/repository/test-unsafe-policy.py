#!/usr/bin/env python3
"""Exercise positive and broken unsafe-policy inventories."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import unsafe_policy


ROOT = Path(__file__).resolve().parents[2]


def fixture(root: Path) -> None:
    source = root / "crates/brynja-core/src"
    source.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace.lints.rust]\nunsafe_code = "deny"\n', encoding="utf-8"
    )
    (source / "lib.rs").write_text(
        "mod secret_memory_volatile;\npub mod safe {}\n", encoding="utf-8"
    )
    for relative in unsafe_policy.ALLOWED:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def require_rejection(root: Path, expected: str) -> None:
    try:
        unsafe_policy.validate(root)
    except unsafe_policy.UnsafePolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"unsafe policy accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-unsafe-") as temporary:
        root = Path(temporary)
        fixture(root)
        unsafe_policy.validate(root)

        (root / "Cargo.toml").write_text(
            '[workspace.lints.rust]\nunsafe_code = "forbid"\n', encoding="utf-8"
        )
        require_rejection(root, "workspace unsafe lint")
        fixture(root)

        extra = root / "crates/brynja-core/src/extra.rs"
        extra.write_text(
            "#[allow(unsafe_code)] fn escaped() { unsafe {} }\n", encoding="utf-8"
        )
        require_rejection(root, "unapproved low-level")
        extra.unlink()

        extra.write_text(
            """#![deny(unsafe_code)]
#[expect(unsafe_code)]
unsafe extern    "C" {
    pub safe fn unreviewed_native_entry();
}
pub fn reachable_from_safe_rust() { unreviewed_native_entry(); }
""",
            encoding="utf-8",
        )
        require_rejection(root, "unapproved low-level")
        extra.unlink()

        extra.write_text(
            "pub fn escaped() { core::arch::asm \n ! (\"nop\"); }\n",
            encoding="utf-8",
        )
        require_rejection(root, "unapproved low-level")
        extra.unlink()

        extra.write_text('include ! ("generated.inc");\n', encoding="utf-8")
        require_rejection(root, "code-inclusion")
        extra.unlink()

        extra.write_text(
            '#[path = "/tmp/unreviewed.rs"] mod unreviewed;\n',
            encoding="utf-8",
        )
        require_rejection(root, "code-inclusion")
        extra.unlink()

        extra.write_text(
            """#![deny(unsafe_code)]
#[expect /* comment-separated control */ (unsafe_code)]
mod injected {
    core::arch::global_asm /* comment-separated control */ !("ret");
}
""",
            encoding="utf-8",
        )
        require_rejection(root, "unapproved low-level")
        extra.unlink()

        extra.write_text(
            '#[cfg_attr(all(), path = "/tmp/unreviewed.rs")] mod escaped;\n',
            encoding="utf-8",
        )
        require_rejection(root, "code-inclusion")
        extra.unlink()

        extra.write_text(
            '#[path /* comment-separated control */ = "/tmp/unreviewed.rs"] '
            "mod escaped;\n",
            encoding="utf-8",
        )
        require_rejection(root, "code-inclusion")
        extra.unlink()

        extra.write_text(
            'include /* comment-separated control */ !("unreviewed.inc");\n',
            encoding="utf-8",
        )
        require_rejection(root, "code-inclusion")
        extra.unlink()

        allowed = root / "crates/brynja-core/src/secret_memory_volatile.rs"
        allowed.write_text(
            allowed.read_text(encoding="utf-8").replace(
                "unsafe { core::ptr::write_volatile(destination, 0_u8) };",
                "unsafe {\n"
                "            core::ptr::write_volatile(destination, 0_u8);\n"
                "            core::ptr::write_volatile(destination, 0_u8);\n"
                "        }",
            ),
            encoding="utf-8",
        )
        require_rejection(root, "approved unsafe module changed")


def register_boundaries() -> None:
    for relative in (Path('crates/brynja-legacy-md5/src/cpu/x86_secret/kernel.rs'),
                     Path('crates/brynja-legacy-md5/src/cpu/arm_secret/kernel.rs'),
                     Path('crates/brynja-legacy-sha1/src/cpu/x86_sha1/secret.rs'),
                     Path('crates/brynja-legacy-sha1/src/cpu/aarch64_sha1/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/keccak_hardened_batch/x86/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/keccak_hardened_batch/arm/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/x86_sha512/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs'),
                     Path('crates/brynja-crypto-cpu/src/x86_sha/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/aarch64_sha2/secret256.rs'),
                     Path('crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86/secret.rs'),
                     Path('crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm/secret.rs')):
        source = (ROOT / relative).read_text()
        _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
        unsafe_policy.validate_allowed(relative, source, blocks, items, proofs)
        for before, after in (
            ('unsafe extern "C" fn', 'extern "C" fn'),
            ('#[inline(never)]', '#[inline(always)]'),
            ('BRYNJA_REGISTER_ERASE', 'REMOVED'),
            ('out(', 'lateout('),
            ('options(nostack)', 'options(nostack, nomem)'),
            ('options(nostack)', 'options(nostack, readonly)'),
        ):
            assert before in source
            try:
                unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
            except unsafe_policy.UnsafePolicyError:
                pass
            else:
                raise AssertionError('accepted opaque-register-boundary regression: ' + before)


def transfer_boundaries(family, lanes):
    relative = Path(f'crates/brynja-crypto-cpu/src/{family}_hardened_batch/transfer.rs')
    if family == 'md5':
        relative = Path('crates/brynja-legacy-md5/src/cpu/transfer.rs')
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    unsafe_policy.validate_allowed(relative, source, blocks, items, proofs)
    domain = ('"cmp r8, 25"', '"cmp r8, 24"') if family == 'keccak' else ('WORDS == 8 || WORDS == 16', 'WORDS <= 64')
    bound = (f'width.min({lanes})', 'width')
    if family == 'md5':
        domain = ('WORDS == 4 || WORDS == 16 || (WORDS == 32 && PACK)', 'WORDS <= 64')
        bound = ('if lane >= 8', 'if lane > 8')
    for before, after in (
        ('unsafe extern "C" fn', 'extern "C" fn'),
        ('#[inline(never)]', '#[inline(always)]'),
        domain,
        bound,
        ('BRYNJA_TRANSFER_BEGIN', 'REMOVED'),
        ('BRYNJA_TRANSFER_ERASE', 'REMOVED'),
        ('BRYNJA_TRANSFER_END', 'REMOVED'),
        ('out(', 'lateout('),
        ('options(nostack)', 'options(nostack, nomem)'),
        ('options(nostack)', 'options(nostack, readonly)'),
    ):
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            pass
        else:
            raise AssertionError('accepted transfer boundary regression: ' + before)


def scalar_boundary(family):
    relative = Path(f'crates/brynja-legacy-{family}/src/compress/native.rs')
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    unsafe_policy.validate_allowed(relative, source, blocks, items, proofs)
    mutations = [('unsafe extern "C" fn', 'extern "C" fn'),
                 ('#[inline(never)]', '#[inline(always)]'),
                 ('block: &[u8; 64]', 'block: &[u8; 63]'),
                 ('BRYNJA_SCALAR_BEGIN', 'REMOVED'),
                 ('BRYNJA_SCALAR_ERASE', 'REMOVED'),
                 ('BRYNJA_SCALAR_END', 'REMOVED'),
                 ('out(', 'lateout('),
                 ('options(nostack)', 'options(nostack, nomem)'),
                 ('options(nostack)', 'options(nostack, readonly)')]
    mutations += ([('"cmp r14d, 320"', '"cmp r14d, 316"'),
                   ('"cmp x11, #320"', '"cmp x11, #316"'),
                   ('schedule: &mut [u8; 320]', 'schedule: &mut [u8; 316]'),
                   ('"mov dword ptr [{schedule} + r14], 0"', '"nop"'),
                   ('"str wzr, [{schedule}, x11]"', '"nop"')]
                  if family == 'sha1' else [('"cmp r14d, 64"', '"cmp r14d, 63"'),
                                            ('"cmp w10, #64"', '"cmp w10, #63"')])
    mutations += [(f'"xor {r}, {r}"', '"nop"') for r in ('eax', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d', 'r14d')]
    mutations += [(f'"mov x{i}, xzr"', '"nop"') for i in range(4, 13 if family == 'sha1' else 12)]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            pass
        else:
            raise AssertionError('accepted scalar boundary regression: '+before)
    print(f'Scalar {family} boundary rejects {len(mutations)} ABI, memory, bound and wipe regressions')


if __name__ == "__main__":
    test()
    register_boundaries()
    transfer_boundaries('sha256', 8)
    transfer_boundaries('sha512', 4)
    transfer_boundaries('keccak', 4)
    transfer_boundaries('md5', 8)
    scalar_boundary('md5')
    scalar_boundary('sha1')
    print("unsafe policy rejects eleven exception-boundary regressions")
    print("opaque register boundaries reject ninety-six unsafe-ABI, clobber and memory-effect regressions")
    print("opaque transfer boundaries reject forty ABI, bounds, clobber and memory-effect regressions")
