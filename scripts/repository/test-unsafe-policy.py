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
        "mod secret_memory_difference;\nmod secret_memory_volatile;\nmod secret_memory_transfer;\nmod secret_memory_mask;\nmod secret_memory_xor;\nmod secret_memory_predicate;\npub mod safe {}\n", encoding="utf-8"
    )
    shutil.copyfile(ROOT / 'crates/brynja-core/src/secret_memory.rs', source / 'secret_memory.rs')
    hash_root = root / 'crates/brynja-hash-core/src'
    hash_root.mkdir(parents=True, exist_ok=True)
    for name in ('lib.rs', 'bit_string.rs'):
        shutil.copyfile(ROOT / 'crates/brynja-hash-core/src' / name, hash_root / name)
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


def secret_copy_boundary():
    relative = Path('crates/brynja-core/src/secret_memory_transfer.rs')
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    mutations = [('unsafe extern "C" fn', 'extern "C" fn'),
                 ('#[inline(never)]', '#[inline(always)]'),
                 ('if destination.len() != input.len()', 'if false'),
                 ('return Err(SecretMemoryError::InsufficientCapacity);', 'return Ok(());'),
                 ('input.len())', 'destination.len())'),
                 ('"cmp rdx, 8"', '"cmp rdx, 7"'),
                 ('"cmp x6, #8"', '"cmp x6, #7"'),
                 ('"test rdx, rdx"', '"nop"'), ('"cbz x6, 5f"', '"nop"'),
                 ('BRYNJA_COPY_BEGIN', 'REMOVED'), ('BRYNJA_COPY_ERASE', 'REMOVED'),
                 ('BRYNJA_COPY_END', 'REMOVED'), ('out(', 'lateout('),
                 ('options(nostack)', 'options(nostack, nomem)'),
                 ('options(nostack)', 'options(nostack, readonly)'),
                 ('not(any(miri, kani))', 'not(miri)'),
                 ('target_endian = "little"', 'target_endian = "big"'),
                 ('*output = *byte;', '*output = 0;')]
    mutations += [(f'"xor {r}, {r}"', '"nop"') for r in ('eax', 'ecx', 'edx')]
    mutations += [(f'"mov x{i}, xzr"', '"nop"') for i in range(4, 7)]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            pass
        else:
            raise AssertionError('accepted secret transfer regression: '+before)
    with tempfile.TemporaryDirectory(prefix='brynja-secret-transfer-policy-') as temporary:
        root = Path(temporary)
        fixture(root)
        writer = root / 'crates/brynja-core/src/secret_memory.rs'
        writer.write_text(writer.read_text().replace('crate::secret_memory_transfer::copy(destination, input)?;', ''))
        require_rejection(root, 'initialization lost its checked transfer')
    print(f'Secret transfer rejects {len(mutations)} ABI/bound/wipe/model regressions and a writer bypass')


def scalar_boundary(family):
    relative = Path(f'crates/brynja-legacy-{family}/src/compress/native.rs')
    if family == 'sha256':
        relative = Path('crates/brynja-hash-sha2/src/hardened/compress32/native.rs')
    if family == 'sha512':
        relative = Path('crates/brynja-hash-sha2/src/hardened/compress64/native.rs')
    if family == 'keccak':
        relative = Path('crates/brynja-hash-sha3/src/hardened/permutation/native.rs')
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
    if family in ('sha256', 'sha512'):
        mutations = [(a.replace('64]', '128]'), b.replace('63]', '127]')) for a, b in mutations]
    if family == 'keccak':
        mutations = [(a.replace('block: &[u8; 64]', 'state: &mut [u8; 200]'),
                      b.replace('block: &[u8; 63]', 'state: &mut [u8; 199]')) for a, b in mutations]
        mutations += [('"cmp r10d, 192"', '"cmp r10d, 184"'),
                      ('"cmp x8, #192"', '"cmp x8, #184"'),
                      ('"cmp r11d, 200"', '"cmp r11d, 192"'),
                      ('"cmp x7, #200"', '"cmp x7, #192"'),
                      ('"cmp r11d, 40"', '"cmp r11d, 32"'),
                      ('"cmp x7, #40"', '"cmp x7, #32"'),
                      ('constants: &[u64; 24]', 'constants: &[u64; 23]')]
        for region, size in (('columns', 40), ('theta', 40), ('rearranged', 200)):
            mutations += [(f'{region}: &mut [u8; {size}]', f'{region}: &mut [u8; {size-1}]'),
                          (f'"mov qword ptr [{{{region}}} + r11], 0"', '"nop"'),
                          (f'"str xzr, [{{{region}}}, x7]"', '"nop"')]
    elif family == 'sha512':
        mutations += [('"and r11d, 127"', '"and r11d, 63"'),
                      ('"and x10, x9, #127"', '"and x10, x9, #63"'),
                      ('"cmp r10d, 640"', '"cmp r10d, 632"'),
                      ('"cmp x9, #640"', '"cmp x9, #632"'),
                      ('scratch: &mut [u8; 640]', 'scratch: &mut [u8; 632]'),
                      ('constants: &[u64; 80]', 'constants: &[u64; 79]'),
                      ('"mov qword ptr [{scratch} + r10], 0"', '"nop"'),
                      ('"str xzr, [{scratch}, x9]"', '"nop"')]
    elif family == 'sha256':
        mutations += [('"cmp r10d, 256"', '"cmp r10d, 252"'),
                      ('"cmp x9, #256"', '"cmp x9, #252"'),
                      ('"cmp r10d, 640"', '"cmp r10d, 636"'),
                      ('"cmp x9, #640"', '"cmp x9, #636"'),
                      ('scratch: &mut [u8; 640]', 'scratch: &mut [u8; 636]'),
                      ('"mov dword ptr [{scratch} + r10], 0"', '"nop"'),
                      ('"str wzr, [{scratch}, x9]"', '"nop"')]
    else:
        mutations += ([('"cmp r14d, 320"', '"cmp r14d, 316"'),
                   ('"cmp x11, #320"', '"cmp x11, #316"'),
                   ('schedule: &mut [u8; 320]', 'schedule: &mut [u8; 316]'),
                   ('"mov dword ptr [{schedule} + r14], 0"', '"nop"'),
                   ('"str wzr, [{schedule}, x11]"', '"nop"')]
                  if family == 'sha1' else [('"cmp r14d, 64"', '"cmp r14d, 63"'),
                                            ('"cmp w10, #64"', '"cmp w10, #63"')])
    registers = ('eax', 'ecx', 'edx', 'r8d', 'r10d') if family == 'sha256' else ('eax', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d', 'r14d')
    if family == 'sha512':
        registers = registers[:-1]
    if family == 'keccak':
        registers = ('eax', 'ecx', 'edx', 'r10d', 'r11d')
    mutations += [(f'"xor {r}, {r}"', '"nop"') for r in registers]
    last = 13 if family == 'sha1' else 11 if family in ('sha256', 'keccak') else 12
    mutations += [(f'"mov x{i}, xzr"', '"nop"') for i in range(4, last)]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            pass
        else:
            raise AssertionError('accepted scalar boundary regression: '+before)
    print(f'Scalar {family} boundary rejects {len(mutations)} ABI, memory, bound and wipe regressions')


def secret_mask_boundary():
    relative = Path('crates/brynja-core/src/secret_memory_mask.rs')
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    mutations = [
        ('byte: *mut u8', 'byte: *mut u64'),
        ('"movzx eax, byte ptr [{byte}]"', '"mov eax, [{byte}]"'),
        ('"ldrb w4, [{byte}]"', '"ldr w4, [{byte}]"'),
        ('"and al, {keep}"', '"nop"'), ('"or al, {set}"', '"nop"'),
        ('"and w4, w4, {keep:w}"', '"nop"'), ('"orr w4, w4, {set:w}"', '"nop"'),
        ('"xor eax, eax"', '"nop"'), ('"mov x4, xzr"', '"nop"'),
        ('out("rax") _', 'lateout("rax") _'),
        ('out("x4") _', 'lateout("x4") _'),
        ('options(nostack)', 'options(nostack, nomem)'),
        ('not(any(miri, kani))', 'not(kani)'),
        ('*byte = (*byte & keep) | set;', '*byte = set;'),
    ]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            continue
        raise AssertionError('accepted secret byte-mask regression: ' + before)
    with tempfile.TemporaryDirectory(prefix='brynja-secret-mask-policy-') as temporary:
        root = Path(temporary)
        fixture(root)
        writer = root / 'crates/brynja-core/src/secret_memory.rs'
        original = writer.read_text()
        writer.write_text(original.replace('crate::secret_memory_mask::apply(byte, keep, set);', ''))
        require_rejection(root, 'masking lost its boundary')
        writer.write_text(original)
        library = root / 'crates/brynja-core/src/lib.rs'
        library.write_text(library.read_text().replace('mod secret_memory_mask;', 'pub mod secret_memory_mask;'))
        require_rejection(root, 'secret-mask module must remain private')
    print(f'Secret mask rejects {len(mutations)} byte-bound, operation, wipe, clobber and model regressions plus wrapper/visibility bypasses')


def secret_xor_boundary():
    relative = Path('crates/brynja-core/src/secret_memory_xor.rs')
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    mutations = [
        ('count == 0 || right > remaining || left > remaining', 'false'),
        ('8_u8.checked_sub(count)', '8_u8.checked_sub(0)'),
        ('u8::MAX', '0_u8'),
        ('"movzx eax, byte ptr [{source}]"', '"mov eax, dword ptr [{source}]"'),
        ('"ldrb w5, [{source}]"', '"ldr w5, [{source}]"'),
        ('"xor byte ptr [{destination}], al"', '"mov byte ptr [{destination}], al"'),
        ('"eor w6, w6, w5"', '"orr w6, w6, w5"'),
        *[(token, '"nop"') for token in ('"shr eax, cl"', '"shl eax, cl"',
          '"and eax, {mask:e}"', '"lsr w5, w5, {right:w}"', '"lsl w5, w5, {left:w}"',
          '"and w5, w5, {mask:w}"', '"xor eax, eax"', '"xor ecx, ecx"',
          '"mov x5, xzr"', '"mov x6, xzr"', '"cmp xzr, xzr"')],
        *[(f'out("{reg}") _', f'lateout("{reg}") _') for reg in ('rax', 'rcx', 'x5', 'x6')],
        ('options(nostack)', 'options(nostack, nomem)'),
        ('not(any(miri, kani))', 'not(kani)'),
        ('*destination ^=', '*destination ='),
    ]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            continue
        raise AssertionError('accepted secret XOR regression: ' + before)
    with tempfile.TemporaryDirectory(prefix='brynja-secret-xor-policy-') as temporary:
        root = Path(temporary)
        fixture(root)
        writer = root / 'crates/brynja-core/src/secret_memory.rs'
        original = writer.read_text()
        writer.write_text(original.replace('crate::secret_memory_xor::apply(', 'other::apply('))
        require_rejection(root, 'xor lost its boundary')
        writer.write_text(original)
        library = root / 'crates/brynja-core/src/lib.rs'
        library.write_text(library.read_text().replace('mod secret_memory_xor;', 'pub mod secret_memory_xor;'))
        require_rejection(root, 'secret-xor module must remain private')
    print(f'Secret XOR rejects {len(mutations)} bounds/shift/memory/wipe/model regressions plus wrapper/visibility bypasses')


def secret_difference_boundary():
    relative = Path('crates/brynja-core/src/secret_memory_difference.rs')
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    mutations = [(token, '"nop"') for token in ('"xor eax, eax"', '"mov x4, xzr"', '"mov x5, xzr"', '"cmp xzr, xzr"', '"xor al, byte ptr [{right}]"', '"or byte ptr [{difference}], al"', '"eor w4, w4, w5"', '"orr w4, w4, w5"')]
    mutations += [('"ldrb w4, [{left}]"', '"ldr w4, [{left}]"'), ('"movzx eax, byte ptr [{left}]"', '"mov eax, dword ptr [{left}]"'), ('not(any(miri, kani))', 'not(kani)'), ('*difference |=', '*difference ^='), ('options(nostack)', 'options(nostack, pure)'), ('out("rax")', 'lateout("rax")'), ('out("x4")', 'lateout("x4")')]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            continue
        raise AssertionError('accepted secret difference regression: ' + before)
    print(f'Secret difference rejects {len(mutations)} computation/bounds/wipe/model regressions')


def secret_predicate_boundary(crate='brynja-core'):
    relative = Path('crates') / crate / 'src/secret_memory_predicate.rs'
    source = (ROOT / relative).read_text()
    _, blocks, items, proofs = unsafe_policy.ALLOWED[relative]
    mutations = [
        ('byte: *const u8', 'byte: *const u64'),
        ('"movzx r10d, byte ptr [{byte}]"', '"mov r10d, [{byte}]"'),
        ('"ldrb w4, [{byte}]"', '"ldr w4, [{byte}]"'),
        *[(token, '"nop"') for token in ('"and r10d, {mask:e}"',
          '"sete {result:l}"', '"movzx {result:e}, {result:l}"', '"xor r10d, r10d"',
          '"and w4, w4, {mask:w}"', '"cmp w4, #0"', '"cset {result:w}, eq"',
          '"mov x4, xzr"', '"cmp xzr, xzr"')],
        ('result = out(reg) result', 'result = lateout(reg) result'),
        ('out("r10") _', 'lateout("r10") _'),
        ('out("x4") _', 'lateout("x4") _'),
        ('options(nostack)', 'options(nostack, preserves_flags)'),
        ('not(any(miri, kani))', 'not(kani)'),
        ('*byte & mask == 0', '*byte == 0'),
    ]
    for before, after in mutations:
        assert before in source
        try:
            unsafe_policy.validate_allowed(relative, source.replace(before, after), blocks, items, proofs)
        except unsafe_policy.UnsafePolicyError:
            continue
        raise AssertionError('accepted secret predicate regression: ' + before)
    with tempfile.TemporaryDirectory(prefix='brynja-secret-predicate-policy-') as temporary:
        root = Path(temporary)
        fixture(root)
        writer = root / 'crates/brynja-core/src/secret_memory.rs'
        original = writer.read_text()
        writer.write_text(original.replace('crate::secret_memory_predicate::apply(byte, mask)', 'false'))
        require_rejection(root, 'predicate lost its boundary')
        writer.write_text(original)
        library = root / 'crates/brynja-core/src/lib.rs'
        library.write_text(library.read_text().replace('mod secret_memory_predicate;', 'pub mod secret_memory_predicate;'))
        require_rejection(root, 'secret-predicate module must remain private')
        fixture(root)
        bits = root / 'crates/brynja-hash-core/src/bit_string.rs'
        original = bits.read_text()
        bits.write_text(original.replace('crate::secret_memory_predicate::apply(byte, unused_mask)', 'true'))
        require_rejection(root, 'hash bit validation lost its borrowed predicate boundary')
        bits.write_text(original)
        library = root / 'crates/brynja-hash-core/src/lib.rs'
        library.write_text(library.read_text().replace('mod secret_memory_predicate;', 'pub mod secret_memory_predicate;'))
        require_rejection(root, 'hash predicate module must remain private')
    print(f'Secret predicate rejects {len(mutations)} byte/result/wipe/flags/model regressions plus wrapper/visibility bypasses')


if __name__ == "__main__":
    test()
    register_boundaries()
    transfer_boundaries('sha256', 8)
    transfer_boundaries('sha512', 4)
    transfer_boundaries('keccak', 4)
    transfer_boundaries('md5', 8)
    scalar_boundary('md5')
    scalar_boundary('sha1')
    scalar_boundary('sha256')
    scalar_boundary('sha512')
    scalar_boundary('keccak')
    secret_copy_boundary()
    secret_mask_boundary()
    secret_xor_boundary()
    secret_difference_boundary()
    secret_predicate_boundary()
    secret_predicate_boundary('brynja-hash-core')
    print("unsafe policy rejects eleven exception-boundary regressions")
    print("opaque register boundaries reject ninety-six unsafe-ABI, clobber and memory-effect regressions")
    print("opaque transfer boundaries reject forty ABI, bounds, clobber and memory-effect regressions")
