#!/usr/bin/env python3
"""Validate Brynja's exact, hash-bound unsafe implementation inventory."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from unsafe_inventory import ALLOWED, CORE_RESEARCH_DIR, CORE_RESEARCH_HASHES, PATH_ATTRIBUTE, SOURCE_IMPORTERS

UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_ITEM = re.compile(r'\bunsafe\s+(?:extern\s+"[^"]+"\s+)?(?:fn|impl|trait)\b')
UNSAFE_ALLOW = "allow(unsafe_code)"
FORBIDDEN_IDENTIFIER = re.compile(
    r"\b(?:unsafe|unsafe_code|asm|global_asm|llvm_asm|naked_asm|include|path)\b"
)
FOREIGN_ABI = re.compile(r'\bextern\s*(?:/\*.*?\*/\s*)?"', re.DOTALL)

# The scanner is deliberately conservative; do not ignore all comments, or
# all occurrences of "path" (attributes can be split across lines).
_DIFFERENTIAL_LINES = frozenset({
    'path::{Path, PathBuf},', 'let path =',
    'if !path.is_absolute() || !path.is_file() {', 'Ok(path.canonicalize()?)',
})
BENIGN_LINES = {
    Path('crates/brynja-crypto/tests/aes128_differential.rs'): _DIFFERENTIAL_LINES,
    Path('crates/brynja-crypto/tests/aes_wide_differential.rs'): _DIFFERENTIAL_LINES,
    Path('crates/brynja-crypto/src/aes_gcm/interruptions.rs'): {
        'path: &[Step],', 'for n in 1..=path.len() {',
        'let prefix = path.get(..n).ok_or("invalid test prefix")?;',
        'for (seal, candidate, path) in [', 'sweep(path, |prefix, unwind| {',
    },
    Path('crates/brynja-crypto/src/aes.rs'): {
        '// Repository-only research snapshot. This path is outside the published crate',
    },
    Path('crates/brynja-crypto/src/aes_gcm/portable/x86_pair_tests.rs'): {
        '// Published empty-message answer: the 96-bit fast path hashes only the message.',
    },
    Path('crates/brynja-crypto/src/chacha20.rs'): {
        '//! Raw RFC 8439 stream cipher. This compatibility path re-exports the standalone',
    },
    Path('crates/brynja-crypto/src/hkdf/derive.rs'): {
        '// Keep the bounded Miri-selected fault test on the multipart path too.',
    },
    Path('crates/brynja-crypto/src/hkdf/parameters.rs'): {
        '/// slices of one allocation are allowed. No unsafe aliasing workaround exists.',
    },
}

class UnsafePolicyError(RuntimeError):
    """The unsafe inventory differs from the approved reviewed exceptions."""


def fail(message: str) -> None:
    raise UnsafePolicyError(message)


def check_import_targets(root: Path, relative: Path, text: str) -> None:
    for name in PATH_ATTRIBUTE.findall(text):
        target = root / relative.parent / name
        if (not target.is_file() or target.is_symlink() or
                any(parent.is_symlink() for parent in target.parents if parent.is_relative_to(root))):
            fail(f"missing or symlinked reviewed module target: {relative}: {name}")
        resolved = target.resolve()
        if not any(resolved.is_relative_to(root.resolve() / tree) for tree in
                   ("crates", "research/aes-fault-integrity")):
            fail(f"reviewed module target outside source trees: {relative}: {name}")
        if resolved == root.resolve() / CORE_RESEARCH_DIR / "mod.rs":
            directory = resolved.parent
            files = {}
            for child in directory.rglob("*"):
                if child.is_symlink():
                    fail(f"symlink in core research module: {child}")
                if child.is_dir():
                    continue
                if not child.is_file():
                    fail(f"non-regular core research module input: {child}")
                files[child.relative_to(directory).as_posix()] = child
            if files.keys() != CORE_RESEARCH_HASHES.keys():
                fail("core research module inventory changed; reopen security review")
            for entry, child in files.items():
                if hashlib.sha256(child.read_bytes()).hexdigest() != CORE_RESEARCH_HASHES[entry]:
                    fail(f"core research module changed; reopen security review: {entry}")


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
        data = path.read_bytes()
        text = data.decode("utf-8")
        relative = path.relative_to(root)
        if path in allowed_paths:
            expected_hash, blocks, items, proofs = ALLOWED[relative]
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected_hash:
                fail(f"approved unsafe module changed; reopen security review: {relative}")
            validate_allowed(relative, text, blocks, items, proofs)
            check_import_targets(root, relative, text)
            continue
        if relative in SOURCE_IMPORTERS and PATH_ATTRIBUTE.search(text):
            if hashlib.sha256(data).hexdigest() != SOURCE_IMPORTERS[relative]:
                fail(f"reviewed source-import context changed: {relative}")
            check_import_targets(root, relative, text)
            text = PATH_ATTRIBUTE.sub('', text)
        benign = BENIGN_LINES.get(relative, ())
        scanned = '\n'.join(line for line in text.split('\n') if line.strip() not in benign)
        scanned = re.sub(r'(?m)^#!\[forbid\(unsafe_code\)\]$', '', scanned.replace('std::path::', ''))
        if FORBIDDEN_IDENTIFIER.search(scanned) or FOREIGN_ABI.search(text):
            fail(f"unapproved low-level or code-inclusion token: {relative}")

    library = (root / "crates/brynja-core/src/lib.rs").read_text(encoding="utf-8")
    if library.count("mod secret_memory_volatile;") != 1:
        fail("volatile-store module must remain private and declared exactly once")
    if "pub mod secret_memory_volatile" in library:
        fail("volatile-store implementation module became public")
    if library.count('mod secret_memory_transfer;') != 1 or 'pub mod secret_memory_transfer' in library:
        fail('secret-transfer module must remain private and declared once')
    writer = (root / 'crates/brynja-core/src/secret_memory.rs').read_text()
    if library.count('mod secret_memory_difference;') != 1 or 'pub mod secret_memory_difference' in library:
        fail('secret difference must remain private')
    if writer.count('crate::secret_memory_difference::accumulate(difference, left, right);') != 1:
        fail('secret difference lost its borrowed boundary')
    if writer.count('crate::secret_memory_transfer::copy(destination, input)?;') != 1:
        fail('secret initialization lost its checked transfer boundary')
    if library.count('mod secret_memory_mask;') != 1 or 'pub mod secret_memory_mask' in library:
        fail('secret-mask module must remain private and declared once')
    if library.count('mod secret_memory_predicate;') != 1 or 'pub mod secret_memory_predicate' in library:
        fail('secret-predicate module must remain private and declared once')
    if writer.count('crate::secret_memory_predicate::apply(byte, mask)') != 1:
        fail('borrowed secret predicate lost its boundary')
    hash_root = root / 'crates/brynja-hash-core/src'
    hash_library = (hash_root / 'lib.rs').read_text()
    if hash_library.count('mod secret_memory_predicate;') != 1 or 'pub mod secret_memory_predicate' in hash_library:
        fail('hash predicate module must remain private and declared once')
    if (hash_root / 'bit_string.rs').read_text().count('crate::secret_memory_predicate::apply(byte, unused_mask)') != 1:
        fail('hash bit validation lost its borrowed predicate boundary')
    if (hash_root / 'secret_memory_predicate.rs').read_bytes() != (root / 'crates/brynja-core/src/secret_memory_predicate.rs').read_bytes():
        fail('private borrowed predicate implementations drifted')
    if writer.count('crate::secret_memory_mask::apply(byte, keep, set);') != 1:
        fail('borrowed secret-byte masking lost its boundary')
    if library.count('mod secret_memory_xor;') != 1 or 'pub mod secret_memory_xor' in library:
        fail('secret-xor module must remain private and declared once')
    if re.sub(r'\s+', '', writer).count('crate::secret_memory_xor::apply(destination,source,source_offset,count,destination_offset,)') != 1:
        fail('borrowed secret-byte xor lost its boundary')


def validate_allowed(
    relative: Path,
    text: str,
    expected_blocks: int,
    expected_items: int,
    expected_proofs: int,
) -> None:
    allowances = {
        Path('crates/brynja-crypto-cpu/src/aes/mod.rs'): 4,
        Path('crates/brynja-crypto-cpu/src/aes/dit.rs'): 3,
        Path('crates/brynja-crypto-cpu/src/ghash_admission.rs'): 0,
    }.get(relative, 1)
    if text.count(UNSAFE_ALLOW) != allowances:
        fail(f"approved module unsafe-code allowance count changed: {relative}")
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
    elif relative == Path('crates/brynja-core/src/secret_memory_difference.rs'):
        required = ('pub(crate) unsafe extern "C" fn accumulate_byte(', '#[inline(never)]',
                    'core::ptr::from_mut(difference)', 'core::ptr::from_ref(left)', 'core::ptr::from_ref(right)',
                    '"movzx eax, byte ptr [{left}]"', '"xor al, byte ptr [{right}]"', '"or byte ptr [{difference}], al"', '"xor eax, eax"',
                    '"ldrb w4, [{left}]"', '"ldrb w5, [{right}]"', '"eor w4, w4, w5"',
                    '"ldrb w5, [{difference}]"', '"orr w4, w4, w5"', '"strb w4, [{difference}]"',
                    '"mov x4, xzr"', '"mov x5, xzr"', '"cmp xzr, xzr"', 'out("rax") _', 'out("x4") _', 'out("x5") _')
        if any(token not in text for token in required):
            fail('secret difference lost byte bounds, computation or cleanup')
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_DIFFERENCE_BEGIN', 'BRYNJA_DIFFERENCE_ERASE', 'BRYNJA_DIFFERENCE_END', 'options(nostack)')):
            fail('secret difference lost an opaque boundary')
        normalized = re.sub(r'\s+', '', text)
        condition = 'all(not(any(miri,kani)),any(target_arch="x86_64",all(target_arch="aarch64",target_endian="little")))'
        if normalized.count('#[cfg('+condition+')]') != 2 or normalized.count('#[cfg(not('+condition+'))]') != 1 or '*difference|=*left^*right;' not in normalized:
            fail('secret difference native/model separation changed')
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly|target_feature|preserves_flags)\b', re.sub(r'//[^\n]*', '', text)):
            fail('secret difference changed memory/clobber or baseline ISA contract')
    elif relative in (Path('crates/brynja-core/src/secret_memory_predicate.rs'),
                      Path('crates/brynja-hash-core/src/secret_memory_predicate.rs')):
        required = ('pub(crate) unsafe extern "C" fn mask_is_zero(byte: *const u8, mask: u8) -> u32',
                    '#[inline(never)]', 'mask_is_zero(core::ptr::from_ref(byte), mask) == 1',
                    '"movzx r10d, byte ptr [{byte}]"', '"and r10d, {mask:e}"',
                    '"sete {result:l}"', '"movzx {result:e}, {result:l}"', '"xor r10d, r10d"',
                    '"ldrb w4, [{byte}]"', '"and w4, w4, {mask:w}"', '"cmp w4, #0"',
                    '"cset {result:w}, eq"', '"mov x4, xzr"', '"cmp xzr, xzr"',
                    'out("r10") _', 'out("x4") _')
        if any(token not in text for token in required):
            fail('secret predicate lost byte bounds, normalization or cleanup')
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_PREDICATE_BEGIN',
                'BRYNJA_PREDICATE_ERASE', 'BRYNJA_PREDICATE_END', 'options(nostack)',
                'result = out(reg) result')):
            fail('secret predicate lost an opaque architecture boundary')
        normalized = re.sub(r'\s+', '', text)
        condition = 'all(not(any(miri,kani)),any(target_arch="x86_64",all(target_arch="aarch64",target_endian="little")))'
        if normalized.count('#[cfg('+condition+')]') != 2 or normalized.count('#[cfg(not('+condition+'))]') != 1:
            fail('secret predicate native/model separation changed')
        if '*byte&mask==0' not in normalized:
            fail('secret predicate safe model disappeared')
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly|target_feature|preserves_flags)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail('secret predicate changed memory/clobber or baseline ISA contract')
    elif relative == Path('crates/brynja-core/src/secret_memory_xor.rs'):
        required = ('pub(crate) unsafe extern "C" fn xor_bits(', '#[inline(never)]',
                    '8_u8.checked_sub(count).ok_or(SecretBitRangeError)?',
                    'count == 0 || right > remaining || left > remaining',
                    'core::ptr::from_mut(destination)', 'core::ptr::from_ref(source)',
                    '"movzx eax, byte ptr [{source}]"', '"mov ecx, {right:e}"', '"shr eax, cl"',
                    '"and eax, {mask:e}"', '"mov ecx, {left:e}"', '"shl eax, cl"',
                    '"xor byte ptr [{destination}], al"', '"xor eax, eax"', '"xor ecx, ecx"',
                    '"ldrb w5, [{source}]"', '"lsr w5, w5, {right:w}"', '"and w5, w5, {mask:w}"',
                    '"lsl w5, w5, {left:w}"', '"ldrb w6, [{destination}]"', '"eor w6, w6, w5"',
                    '"strb w6, [{destination}]"', '"mov x5, xzr"', '"mov x6, xzr"', '"cmp xzr, xzr"',
                    'out("rax") _', 'out("rcx") _', 'out("x5") _', 'out("x6") _')
        if any(token not in text for token in required):
            fail('secret xor lost bounds, computation or cleanup')
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_XOR_BEGIN',
                'BRYNJA_XOR_ERASE', 'BRYNJA_XOR_END', 'options(nostack)')):
            fail('secret xor lost an opaque architecture boundary')
        normalized = re.sub(r'\s+', '', text)
        condition = 'all(not(any(miri,kani)),any(target_arch="x86_64",all(target_arch="aarch64",target_endian="little")))'
        if normalized.count('#[cfg('+condition+')]') != 2 or normalized.count('#[cfg(not('+condition+'))]') != 1:
            fail('secret xor native/model separation changed')
        if '*destination^=(source.checked_shr(u32::from(right)).ok_or(SecretBitRangeError)?&mask).checked_shl(u32::from(left)).ok_or(SecretBitRangeError)?;' not in normalized:
            fail('secret xor safe model disappeared')
        if 'letmask=u8::MAX.checked_shr(u32::from(remaining)).ok_or(SecretBitRangeError)?;' not in normalized:
            fail('secret xor public mask changed')
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly|target_feature)\b', re.sub(r'//[^\n]*', '', text)):
            fail('secret xor changed memory/clobber or baseline ISA contract')
    elif relative == Path('crates/brynja-core/src/secret_memory_mask.rs'):
        required = ('pub(crate) unsafe extern "C" fn mask_byte(byte: *mut u8, keep: u8, set: u8)',
                    '#[inline(never)]', 'mask_byte(core::ptr::from_mut(byte), keep, set)',
                    '"movzx eax, byte ptr [{byte}]"', '"and al, {keep}"', '"or al, {set}"',
                    '"mov byte ptr [{byte}], al"', '"xor eax, eax"',
                    '"ldrb w4, [{byte}]"', '"and w4, w4, {keep:w}"', '"orr w4, w4, {set:w}"',
                    '"strb w4, [{byte}]"', '"mov x4, xzr"', '"cmp xzr, xzr"',
                    'out("rax") _', 'out("x4") _')
        if any(token not in text for token in required):
            fail('secret mask lost byte bounds, computation or cleanup')
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_MASK_BEGIN',
                'BRYNJA_MASK_ERASE', 'BRYNJA_MASK_END', 'options(nostack)')):
            fail('secret mask lost an opaque architecture boundary')
        normalized = re.sub(r'\s+', '', text)
        condition = 'all(not(any(miri,kani)),any(target_arch="x86_64",all(target_arch="aarch64",target_endian="little")))'
        if normalized.count('#[cfg('+condition+')]') != 2 or normalized.count('#[cfg(not('+condition+'))]') != 1:
            fail('secret mask native/model target separation changed')
        if '*byte=(*byte&keep)|set;' not in normalized:
            fail('secret mask safe model disappeared')
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly|target_feature)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail('secret mask changed memory/clobber or baseline ISA contract')
    elif relative == Path('crates/brynja-core/src/secret_memory_transfer.rs'):
        required = ('pub(crate) unsafe extern "C" fn copy_bytes(destination: *mut u8, source: *const u8, length: usize)',
                    '#[inline(never)]', 'if destination.len() != input.len()',
                    'return Err(SecretMemoryError::InsufficientCapacity);',
                    'copy_bytes(destination.as_mut_ptr(), input.as_ptr(), input.len())',
                    '"cmp rdx, 8"', '"cmp x6, #8"', '"test rdx, rdx"', '"cbz x6, 5f"',
                    '"mov rax, [{source} + rcx]"', '"ldr x4, [{source}, x5]"')
        if any(token not in text for token in required):
            fail('secret transfer lost ABI, checked length, empty guard or word bound')
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_COPY_BEGIN',
                'BRYNJA_COPY_ERASE', 'BRYNJA_COPY_END', 'options(nostack)')):
            fail('secret transfer lost an opaque architecture boundary')
        for token in tuple(f'"xor {r}, {r}"' for r in ('eax', 'ecx', 'edx')) + tuple(f'"mov x{i}, xzr"' for i in range(4, 7)):
            if token not in text:
                fail('secret transfer register erasure disappeared')
        normalized = re.sub(r'\s+', '', text)
        condition = 'all(not(any(miri,kani)),any(target_arch="x86_64",all(target_arch="aarch64",target_endian="little")))'
        if normalized.count('#[cfg('+condition+')]') != 2 or normalized.count('#[cfg(not('+condition+'))]') != 1:
            fail('secret transfer native/model target separation changed')
        if 'for(output,byte)indestination.iter_mut().zip(input.iter()){*output=*byte;}' not in normalized:
            fail('secret transfer safe model disappeared')
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly|target_feature)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail('secret transfer changed memory/clobber or baseline ISA contract')
    elif relative in {Path("crates/brynja-legacy-md5/src/compress/native.rs"),
                      Path("crates/brynja-legacy-sha1/src/compress/native.rs"),
                      Path("crates/brynja-hash-sha2/src/hardened/compress32/native.rs"),
                      Path("crates/brynja-hash-sha2/src/hardened/compress64/native.rs"),
                      Path("crates/brynja-hash-sha3/src/hardened/permutation/native.rs")}:
        sha1 = relative.parts[1] == 'brynja-legacy-sha1'
        sha256 = relative.parent.name == 'compress32'
        sha512 = relative.parent.name == 'compress64'
        keccak = relative.parent.name == 'permutation'
        required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                    'state: &mut [u8; 16]', 'block: &[u8; 64]', 'constants: &[u32; 64]',
                    'shifts: &[u32; 16]', '"cmp r14d, 64"', '"cmp w10, #64"')
        if sha1:
            required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                        'state: &mut [u8; 20]', 'block: &[u8; 64]', 'schedule: &mut [u8; 320]',
                        '"cmp r14d, 320"', '"cmp x11, #320"',
                        '"mov dword ptr [{schedule} + r14], 0"', '"str wzr, [{schedule}, x11]"')
        if sha256:
            required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                        'state: &mut [u8; 64]', 'block: &[u8; 128]', 'scratch: &mut [u8; 640]',
                        'constants: &[u32; 64]', '"cmp r10d, 256"', '"cmp x9, #256"',
                        '"cmp r10d, 640"', '"cmp x9, #640"',
                        '"mov dword ptr [{scratch} + r10], 0"', '"str wzr, [{scratch}, x9]"')
        if sha512:
            required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                        'state: &mut [u8; 64]', 'block: &[u8; 128]', 'scratch: &mut [u8; 640]',
                        'constants: &[u64; 80]', '"and r11d, 127"', '"and x10, x9, #127"',
                        '"cmp r10d, 640"', '"cmp x9, #640"',
                        '"mov qword ptr [{scratch} + r10], 0"', '"str xzr, [{scratch}, x9]"')
        if keccak:
            required = ('pub(super) unsafe extern "C" fn scalar(', '#[inline(never)]',
                        'state: &mut [u8; 200]', 'columns: &mut [u8; 40]',
                        'theta: &mut [u8; 40]', 'rearranged: &mut [u8; 200]', 'constants: &[u64; 24]',
                        '"cmp r10d, 192"', '"cmp x8, #192"',
                        '"cmp r11d, 200"', '"cmp x7, #200"',
                        '"cmp r11d, 40"', '"cmp x7, #40"')
            for region in ('columns', 'theta', 'rearranged'):
                required += (f'"mov qword ptr [{{{region}}} + r11], 0"',
                             f'"str xzr, [{{{region}}}, x7]"')
        if any(token not in text for token in required):
            fail("scalar compressor lost its fixed operands, ABI, bound or schedule wipe")
        if any(text.count(token) != 2 for token in ('asm!(', 'BRYNJA_SCALAR_BEGIN',
                'BRYNJA_SCALAR_ERASE', 'BRYNJA_SCALAR_END', 'options(nostack)')):
            fail("scalar compressor lost an opaque architecture boundary")
        wipes = tuple(f'"xor {reg}, {reg}"' for reg in ('eax', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d', 'r14d'))
        wipes += tuple(f'"mov x{i}, xzr"' for i in range(4, 13 if sha1 else 12))
        if sha256:
            wipes = tuple(f'"xor {r}, {r}"' for r in ('eax', 'ecx', 'edx', 'r8d', 'r10d'))
            wipes += tuple(f'"mov x{i}, xzr"' for i in range(4, 11))
        if sha512:
            wipes = tuple(f'"xor {r}, {r}"' for r in ('eax', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d'))
            wipes += tuple(f'"mov x{i}, xzr"' for i in range(4, 12))
        if keccak:
            wipes = tuple(f'"xor {r}, {r}"' for r in ('eax', 'ecx', 'edx', 'r10d', 'r11d'))
            wipes += tuple(f'"mov x{i}, xzr"' for i in range(4, 11))
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
        if 'out("ymm0")' in text:
            code = re.sub(r'//[^\n]*', '', text)
            if (code.count('"vzeroupper"') != 1
                    or not re.search(r'"vzeroupper",\s*"# BRYNJA_SECRET_END"', code)
                    or any(code.count(f'out("ymm{i}")') != 1 for i in range(16))):
                fail("AVX boundary lost return transition cleanup or complete clobbers")
        if re.search(r'\b(?:lateout|inlateout|global_asm|pure|nomem|readonly)\b',
                     re.sub(r'//[^\n]*', '', text)):
            fail("register boundary weakened clobbers or memory effects")
    elif relative.name in {
        "x86_sha.rs", "x86_sha512.rs", "aarch64_sha2.rs", "riscv64_zknh.rs", "x86_sha1.rs", "aarch64_sha1.rs",
        "x86_avx2_keccak.rs", "aarch64_sha3_keccak.rs", "x86_avx2_md5.rs", "aarch64_neon_md5.rs", "chacha20_sse2.rs", "chacha20_neon.rs",
    }:
        if "#[target_feature" not in text or "core::arch" not in text:
            fail(f"CPU kernel lost its intrinsic boundary: {relative}")
        if relative.name == "riscv64_zknh.rs":
            if text.count("asm!(") != 6 or "global_asm!(" in text:
                fail("RISC-V kernel inline-assembly inventory drifted")
            for boundary in ('compress_zknh(', 'expanded(', 'compress_zknh512('):
                if text.count('#[target_feature(enable = "zknh")]\nunsafe fn ' + boundary) != 1:
                    fail("RISC-V kernel lost a Zknh feature boundary")
            if ('let schedule = unsafe { expanded(block) };' not in text or
                    any(text.count(f'asm!("{op} {{output}}, {{input}}"') != 1 for op in
                        ('sha256sig0', 'sha256sig1', 'sha256sum0', 'sha256sum1', 'sha512sum0', 'sha512sum1'))):
                fail("RISC-V kernel schedule or instruction inventory drifted")
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
