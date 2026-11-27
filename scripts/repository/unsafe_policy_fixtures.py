"""Positive fixtures and source-import regression controls for the unsafe policy."""

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
        "use std::path::Path;\nmod secret_memory_difference;\nmod secret_memory_volatile;\nmod secret_memory_transfer;\nmod secret_memory_mask;\nmod secret_memory_xor;\nmod secret_memory_predicate;\npub mod safe {}\n", encoding="utf-8"
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
        copy_import_targets(root, relative)


def copy_import_targets(root: Path, relative: Path) -> None:
    for name in unsafe_policy.PATH_ATTRIBUTE.findall((ROOT / relative).read_text()):
        real = (ROOT / relative.parent / name).resolve()
        target = root / real.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(real, target)


def reconciled_inventory():
    with tempfile.TemporaryDirectory(prefix='brynja-policy-imports-') as temporary:
        root = Path(temporary)
        fixture(root)
        for relative in unsafe_policy.SOURCE_IMPORTERS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)
            copy_import_targets(root, relative)
        unsafe_policy.validate(root)
        importer = root / 'crates/brynja-crypto/src/aes.rs'
        original = importer.read_text()
        for changed in (
            original.replace('brynja_fault_profile_research', 'not(kani)'),
            original.replace('/fault_integrity/mod.rs', '/other/mod.rs'),
            original + '\n#[allow(unsafe_code)]\nfn extra() {}\n',
        ):
            assert changed != original
            importer.write_text(changed)
            require_rejection(root, 'source-import context changed')
        importer.write_text(original)
        target = root / 'research/aes-fault-integrity/crypto/fault_integrity/mod.rs'
        target.unlink()
        require_rejection(root, 'missing or symlinked')
        target.symlink_to(importer)
        require_rejection(root, 'missing or symlinked')
        target.unlink()
        copy_import_targets(root, importer.relative_to(root))

        extra = root / 'crates/brynja-crypto/src/aes_gcm/interruptions.rs'
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text('        path: &[Step],\n#[path="unreviewed.rs"] mod other;\n')
        require_rejection(root, 'code-inclusion')
        extra.unlink()
        kernel = root / 'crates/brynja-crypto-cpu/src/aes/mod.rs'
        kernel.write_text(kernel.read_text() + '\n')
        require_rejection(root, 'approved unsafe module changed')
    relative = Path('crates/brynja-crypto-cpu/src/riscv64_zknh.rs')
    source = (ROOT / relative).read_text()
    for before, after in (
        ('#[target_feature(enable = "zknh")]\nunsafe fn expanded', 'unsafe fn expanded'),
        ('asm!("sha256sig0 ', 'asm!("sha256sig1 '),
    ):
        changed = source.replace(before, after)
        assert changed != source
        try:
            unsafe_policy.validate_allowed(relative, changed, *unsafe_policy.ALLOWED[relative][1:])
        except unsafe_policy.UnsafePolicyError as error:
            assert 'RISC-V kernel' in str(error)
        else:
            raise AssertionError('RISC-V kernel boundary regression accepted')
    print('Reconciled inventory rejects edited guards, redirects, missing/symlink targets, kernel and opcode drift')


def require_rejection(root: Path, expected: str) -> None:
    try:
        unsafe_policy.validate(root)
    except unsafe_policy.UnsafePolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"unsafe policy accepted {expected}")
